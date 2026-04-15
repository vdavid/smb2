# Client -- high-level SMB2 API

Entry point for most users. `SmbClient` wraps `Connection` + `Session` and provides convenience methods for file operations.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `SmbClient`, `ClientConfig`, `connect()` shorthand |
| `connection.rs` | `Connection` -- credit tracking, message sequencing, signing, encryption, compound send/receive |
| `session.rs` | `Session::setup()` -- NTLM auth, key derivation, signing/encryption activation |
| `tree.rs` | `Tree` -- share connection, file CRUD, compound and pipelined I/O |
| `stream.rs` | `FileDownload` / `FileUpload` / `FileWriter` -- streaming I/O with progress |
| `watcher.rs` | `Watcher` -- directory change notifications via CHANGE_NOTIFY long-poll |
| `pipeline.rs` | `Pipeline` / `Op` / `OpResult` -- batched concurrent operations (the core feature) |
| `shares.rs` | Share enumeration via IPC$ + srvsvc RPC |
| `dfs.rs` | DFS referral IOCTL helper, `DfsResolver` with TTL-based referral cache |

## Layering

```
SmbClient  (owns Connection + Session, stores credentials for reconnect)
  Connection  (TCP transport, credits, message IDs, signing, encryption)
    Session   (NTLM auth, key derivation -- setup mutates Connection)
      Tree    (share-level ops, borrows &mut Connection for each call)
  extra_connections  (HashMap<String, ConnectionEntry> for DFS cross-server)
  dfs_resolver       (DfsResolver with TTL-based referral cache)
```

All `Tree` methods take `&mut Connection` as a parameter. `SmbClient` convenience methods use `connection_for_tree(tree)` to route through the correct connection (primary or DFS extra connection) based on the tree's `server` field.

## Connection and credits

- Connection starts with 1 credit (from negotiate). Requests 256 credits in every message.
- Multi-credit requests (reads/writes > 64 KB) consume `ceil(payload_size / 65536)` credits and use that many consecutive `MessageId` values. Gaps in `MessageId` sequences cause the server to drop the connection.
- Credits flow back from responses via `CreditResponse` header field. The connection tracks available credits and blocks if exhausted.
- `STATUS_PENDING` interim responses carry credits but the request isn't done -- keep waiting.

## Compound requests

`send_compound` packs multiple operations into a single transport frame. Each sub-request is 8-byte aligned, linked via `NextCommand`. Subsequent related operations use `FileId::SENTINEL` (the server substitutes the real handle from the first CREATE).

- **Read compound**: CREATE + READ + CLOSE (3 ops, 1 round-trip). Default for `read_file`.
- **Write compound**: CREATE + WRITE + FLUSH + CLOSE (4 ops, 1 round-trip). Default for `write_file`.
- **Delete compound**: CREATE (DELETE_ON_CLOSE) + CLOSE (2 ops, 1 round-trip). Default for `delete_file` / `delete_directory`.
- **Rename compound**: CREATE + SET_INFO + CLOSE (3 ops, 1 round-trip). Default for `rename`.
- **Stat compound**: CREATE + QUERY_INFO (basic) + QUERY_INFO (standard) + CLOSE (4 ops, 1 round-trip). Default for `stat`.
- If CREATE succeeds but a later op fails, the client issues a standalone CLOSE to avoid leaking the handle.

## Batch operations

`delete_files`, `rename_files`, and `stat_files` send all compound requests before waiting for any responses, minimizing total round-trips for multi-file operations. The pattern:

1. **Send all**: build and send N independent compound chains (one per file)
2. **Receive all**: collect N compound responses, parse each independently
3. **Cleanup**: issue standalone CLOSEs for any compound where CREATE succeeded but a later op failed

Partial failures are independent -- if 3 of 50 files fail, the other 47 still succeed. Each method returns `Vec<Result<T>>` in the same order as the input.

No credit windowing yet -- the server's initial 256-credit grant supports ~128 deletes, ~85 renames, or ~64 stats in a single batch. Enough for typical file manager use.

## DFS (Distributed File System) resolution

Reactive DFS resolution with multi-target failover. When a convenience method gets `STATUS_PATH_NOT_COVERED` (mapped to `ErrorKind::DfsReferral`), it:

1. Calls `handle_dfs_redirect()` which resolves the referral via `DfsResolver` (cache or IOCTL)
2. Tries each target in the referral response (multi-target failover)
3. Creates a new connection + session for cross-server targets via `ensure_connection()`
4. Tree-connects to the target share via `ensure_tree()`
5. Updates the caller's `&mut Tree` in-place to point to the new server/share
6. Retries the operation with the resolved remaining path

**Key design decisions:**
- Convenience methods take `&mut Tree` (not `&Tree`) so DFS can update the tree in-place
- `disconnect_share` stays as `&Tree` (no redirect on teardown)
- Streaming methods (`download`, `upload`, `watch`) keep `&Tree` because they return handles that borrow the tree for their lifetime
- Batch methods (`delete_files`, `rename_files`, `stat_files`) don't retry per-file; the caller should trigger one single-file operation first to resolve the redirect
- `dfs_enabled` flag on `ClientConfig` (default `true`) gates all DFS resolution
- Borrow checker requires inlining the connection lookup in `handle_dfs_redirect` to avoid double `&mut self` borrows

## Pipelined I/O

For large files, `read_file_pipelined` / `write_file_pipelined` send multiple READ/WRITE requests without waiting for responses, bounded by available credits. Chunk size is `min(512 KB, max_read_size)` with up to 32 in-flight requests. This is the core performance feature -- without it, throughput is ~10x worse.

FileWriter provides push-based pipelined writes. The consumer pushes chunks at their own pace via `write_chunk`, with the sliding window handling backpressure. Complement to FileDownload (read streaming).

## Session setup flow

1. Send NTLM NEGOTIATE in SESSION_SETUP
2. Receive STATUS_MORE_PROCESSING_REQUIRED with challenge, update preauth hash
3. Send NTLM AUTHENTICATE in SESSION_SETUP, update preauth hash with request only
4. Receive STATUS_SUCCESS (do NOT include in preauth hash)
5. Derive signing/encryption keys via SP800-108 KDF
6. Activate signing on the connection
7. If session or share requires encryption, activate encryption (TRANSFORM_HEADER wrapping with AEAD)

## Encryption

Encryption is activated when the session flags include `ENCRYPT_DATA` or a share has `SMB2_SHAREFLAG_ENCRYPT_DATA`. When active:
- Outgoing messages are wrapped in TRANSFORM_HEADER (protocol ID 0xFD) with a monotonic nonce
- Incoming messages with 0xFD are decrypted before processing
- Signing is skipped (AEAD provides authentication)
- Compound chains are encrypted as one unit (pitfall #9)

Tree-level encryption: `connect_share()` checks the share's encrypt flag and activates encryption on the connection if needed, even if the session didn't require it.

## Reconnection

`SmbClient::reconnect()` creates a fresh TCP connection, re-negotiates, and re-authenticates using stored credentials. All previous `Tree` handles and `FileId` values are invalidated. The caller must `connect_share` again.

## Key decisions

- **`&mut Connection` instead of `Arc<Mutex<Connection>>`**: Forces sequential access at compile time. The pipeline module handles concurrency differently (split transport halves).
- **Compound reads as default**: One round-trip for small files. Saves 2 RTTs vs sequential CREATE/READ/CLOSE.
- **512 KB pipeline chunks**: Balances between too many small requests (overhead) and too few large ones (credit starvation). Gives ~20 chunks per 10 MB file.
- **Password stored in `SmbClient`**: Enables reconnect without re-prompting. Not encrypted in memory. Drop when done.

## Gotchas

- **Preauth hash excludes the final success response**: Only STATUS_MORE_PROCESSING_REQUIRED responses are hashed. Including the success response produces wrong keys. (MS-SMB2 3.2.5.3.1)
- **Oplock break notifications arrive with MessageId 0xFFFFFFFFFFFFFFFF**: `receive_response` / `receive_compound` must detect and skip these unsolicited messages.
- **STATUS_PENDING loop**: CHANGE_NOTIFY and other long-poll operations get STATUS_PENDING first. Must loop until a non-pending response arrives. The pending response still carries valid credit grants.
- **Signing and encryption are mutually exclusive on the wire**: When encrypting, zero the signature field (AEAD provides integrity). On receive, skip signature verification if decryption succeeded.
- **Compound encryption wraps the entire chain**: One TRANSFORM_HEADER for all sub-requests concatenated, not per sub-request.
- **Share-level encryption**: If a share has `SMB2_SHAREFLAG_ENCRYPT_DATA`, encryption is activated even if the session didn't require it.
- **FileDownload/FileUpload can leak handles on drop**: Rust has no async drop. If not consumed fully, the file handle leaks. The types log a warning.
- **FileWriter can leak handles on drop**: Same as FileDownload/FileUpload. Rust has no async drop. If not consumed via `finish()`, the file handle leaks. The type logs a warning.
- **DFS paths must include server\share prefix**: When `SMB2_FLAGS_DFS_OPERATIONS` is set, the server expects the path to start with `server\share\` (MS-SMB2 3.2.4.3). `Tree::format_path()` handles this automatically for DFS shares. Without the prefix, Samba strips the first two path components, leading to wrong file opens.
- **DFS redirect changes the tree in-place**: After a DFS redirect, `tree.server`, `tree.share_name`, and `tree.tree_id` all change. Subsequent operations on the same tree use the target server directly -- they must use target-relative paths, not the original DFS paths.
- **tree.server stores addr:port**: The `server` field on `Tree` stores the full `addr:port` string (not just hostname) so `connection_for_tree` can distinguish servers that share the same hostname but use different ports.
