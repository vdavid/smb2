# Client -- high-level SMB2 API

Entry point for most users. `SmbClient` wraps `Connection` + `Session` and provides convenience methods for file operations.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `SmbClient`, `ClientConfig`, `connect()` shorthand |
| `connection.rs` | `Connection` -- credit tracking, message sequencing, signing, encryption, `execute` / `execute_compound` |
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

`Connection::execute_compound(&[CompoundOp])` packs multiple operations into a single transport frame. Each sub-request is 8-byte aligned, linked via `NextCommand`. Subsequent related operations use `FileId::SENTINEL` (the server substitutes the real handle from the first CREATE).

- **Read compound**: CREATE + READ + CLOSE (3 ops, 1 round-trip). Default for `read_file`.
- **Write compound**: CREATE + WRITE + FLUSH + CLOSE (4 ops, 1 round-trip). Default for `write_file`.
- **Delete compound**: CREATE (DELETE_ON_CLOSE) + CLOSE (2 ops, 1 round-trip). Default for `delete_file` / `delete_directory`.
- **Rename compound**: CREATE + SET_INFO + CLOSE (3 ops, 1 round-trip). Default for `rename`.
- **Stat compound**: CREATE + QUERY_INFO (basic) + QUERY_INFO (standard) + CLOSE (4 ops, 1 round-trip). Default for `stat`.
- **Fs-info compound**: CREATE + QUERY_INFO (FileFsFullSizeInformation) + CLOSE (3 ops, 1 round-trip). Default for `fs_info`.
- If CREATE succeeds but a later op fails, the client issues a standalone CLOSE to avoid leaking the handle.

### Receiving compound responses

`execute_compound` returns `Result<Vec<Result<Frame>>>`. The outer `Result` is "did the compound hit the wire"; the inner one is per-sub-op (waiter-level: session expired, signature verify, connection dropped mid-await). Sub-op protocol status codes (`STATUS_OBJECT_NAME_NOT_FOUND` etc.) ride in the inner frame's `header.status`, not the inner `Result`. Per MS-SMB2 3.3.4.1.3 the server MAY split the compound response across multiple transport frames (Samba, QNAP, Windows Server in some cases); the receiver task routes each sub-response by `MessageId` so the per-waiter `oneshot::Receiver`s resolve independently and `execute_compound` reassembles the result vector in submission order.

Most callers use a small `all_or_first_err` helper (see `tree.rs`) that propagates the first inner `Err` as the outer `Err` (matching the pre-Phase-3 shortcircuit behavior) and hands back a `Vec<Frame>` indexable per sub-op. Tolerating partial failure (for example, CREATE ok, READ fails → issue standalone CLOSE with the create's returned `FileId`) keeps the individual inner `Result`s.

## Batch operations

`delete_files`, `rename_files`, and `stat_files` issue one `execute_compound` per file. Partial failures are independent — if 3 of 50 files fail, the other 47 still succeed. Each method returns `Vec<Result<T>>` in the same order as the input.

Decision/Why — sequential execute vs parallel: pre-Phase-3 these methods did "phase 1 send all compounds, phase 2 receive all" for wire-level pipelining. With the new API a caller can re-create that shape by spawning `tokio::spawn` tasks over `conn.clone()`s, each calling `execute_compound`. For cmdr's "delete 50 files" flows the sequential-compound cost is small (one round-trip per file) so we chose simplicity. If a workload needs the extra parallelism later, the refactor is local to each batch method.

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

For large files, `read_file_pipelined` / `write_file_pipelined` issue multiple `execute_with_credits` calls concurrently on cloned connections via `futures_util::stream::FuturesUnordered`. The sliding window stays at 32 in-flight requests, credits are checked per launch via `conn.credits()`. Chunk size is `min(512 KB, max_read_size)`. This is the core performance feature -- without it, throughput is ~10x worse.

`FileWriter` keeps an owned `FuturesUnordered<BoxedWriteFut>` field — `launch_wire_chunk` pushes a boxed `execute_with_credits` future, `drain_one` awaits `in_flight.next()`, and the public `write_chunk` / `finish` / `abort` drive that state machine.

FileWriter provides push-based pipelined writes. The consumer pushes chunks at their own pace via `write_chunk`, with the sliding window handling backpressure. Complement to FileDownload (read streaming).

FileWriter has two terminal operations:
- `finish()` — send all buffered data, drain in-flight WRITEs, FLUSH (fsync on the server), CLOSE. Use on normal completion.
- `abort()` — discard unsent data, drain in-flight WRITEs to keep credits/message-ids in sync, skip FLUSH, best-effort CLOSE. Use on cancellation or error paths where the partial remote file is going to be deleted anyway — `abort()` saves the fsync round-trip. The caller is responsible for deleting the partial remote file.

Both consume `self` so write-after-close/abort is a compile error. `Drop` logs a debug warning if neither was called (handle leaks).

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

## Connection internals: receiver task + `oneshot` routing

`Connection::execute` / `execute_compound` is the primary API. A background receiver task (spawned per `Connection` at `from_transport`) owns the transport's read half and routes each sub-frame to a per-request `oneshot::Sender` by `MessageId`.

- `Connection` is `Clone` and holds just `Arc<Inner>`. `Inner` owns `waiters: Mutex<HashMap<MessageId, oneshot::Sender<Result<Frame>>>>`, `credits: AtomicU32`, `next_message_id: AtomicU64`, the transport send half (via `Arc<dyn TransportSend>`), the receiver task's `JoinHandle`, and crypto state. All state is behind atomics or short-critical-section `std::sync::Mutex`.
- `execute(command, body, tree_id)` allocates a `MessageId` (`AtomicU64::fetch_add(credit_charge)`), registers a `oneshot::Sender` in `waiters` atomically under the waiters lock (re-checks `disconnected` there to rule out a TOCTOU where the receiver task has already shut down and drained the map), packs the frame, signs/encrypts/compresses as needed, and writes through `TransportSend::send`. Then it awaits the local `oneshot::Receiver`. Returns `Result<Frame { header, body, raw }>`.
- `execute_compound(&[CompoundOp])` does the same per sub-op, building one compound transport frame with `NextCommand` offsets, then awaits each per-sub-op receiver sequentially. Each receiver resolves independently (the receiver task splits the server's response by `NextCommand` and routes each sub-response by its `MessageId`). The outer `Result` is "did the compound hit the wire"; the inner `Vec<Result<Frame>>` has one entry per sub-op.
- **Cancellation-by-drop is safe by construction.** If a caller's future is aborted (`tokio::spawn` + `JoinHandle::abort()` is the common path in consumers), the locally-owned `oneshot::Receiver` drops; the receiver task's `Sender::send` then fails silently when the late frame arrives; the frame is discarded. Credits are still applied in the receiver task so dropped-caller frames don't starve throughput.
- **Transport drop** fans `Err(Disconnected)` to every pending `oneshot::Sender` and sets `disconnected=true` under the waiters lock. Subsequent `execute` / `execute_compound` sees `disconnected=true` and returns `Err(Disconnected)` without inserting (no leaked waiters).

Gotcha/Why — pre-Phase-3 `send_request` / `receive_response` split API was removed in Phase 3 Stage A.3. The test-mode `set_orphan_filter_enabled(false)` escape hatch is gone too; tests that build mocks without going through `setup_connection` call `mock.enable_auto_rewrite_msg_id()` instead, which rewrites each queued response's zero-msg_id to match the next pending sent msg_id in FIFO order.

Full design in [docs/specs/connection-actor.md](../../docs/specs/connection-actor.md).

## Key decisions

- **`execute` / `execute_compound` take `&self`**: `Connection: Clone` supports concurrent ops per connection — clone freely across tasks, the receiver task multiplexes responses by `MessageId`. `Tree::*` methods still take `&mut Connection` because session-setup mutators (`activate_signing`, `set_session_id`) keep `&mut self`; Tree code calls both, so `&mut` at that layer is the least-churn choice.
- **Sender work stays on the caller thread, only the receiver is a task**: The send path already uses an internal Mutex on the transport write half for ordering; adding a second task just to drive sends would add latency without correctness gain. The receiver bug (orphan/dropped-caller frames corrupting the wire) only existed on the receive side, so only the receive side needed a task.
- **Compound reads as default**: One round-trip for small files. Saves 2 RTTs vs sequential CREATE/READ/CLOSE.
- **512 KB pipeline chunks**: Balances between too many small requests (overhead) and too few large ones (credit starvation). Gives ~20 chunks per 10 MB file.
- **Password stored in `SmbClient`**: Enables reconnect without re-prompting. Not encrypted in memory. Drop when done.

## Gotchas

- **Preauth hash excludes the final success response**: Only STATUS_MORE_PROCESSING_REQUIRED responses are hashed. Including the success response produces wrong keys. (MS-SMB2 3.2.5.3.1)
- **Oplock break notifications arrive with MessageId 0xFFFFFFFFFFFFFFFF**: The receiver task detects these and skips them without invoking a waiter lookup.
- **Register-waiter must be atomic with `disconnected` check**: The waiters lock covers both reading `disconnected` and inserting the `oneshot::Sender`. If the check and insert were racy, a receiver-task failure mid-send could leave an orphan `Sender` in the map that never gets routed — caller would hang on `rx.await` forever. Same goes for `fan_error_to_waiters`: it sets `disconnected=true` UNDER the same waiters lock before draining, so new sends strictly either succeed-and-get-drained or fail at the insert check.
- **Silent frame discard on decrypt/decompress/malformed header**: The receiver task currently `log+continue`s on these — if a legitimate response's frame was corrupted, the matching waiter hangs forever (the msg_id isn't recoverable for decrypt failures). This is a known hole; Phase 3 should decide between "tear down the connection" (safer) and "log and continue" (today). See code-review note in `docs/specs/connection-actor.md` § Risks and non-risks.
- **STATUS_PENDING loop**: CHANGE_NOTIFY and other long-poll operations get STATUS_PENDING first. The receiver task keeps the waiter registered on PENDING and does NOT forward the interim response. Credits from PENDING are still applied so the caller's `conn.credits()` reflects them.
- **STATUS_PENDING loop**: CHANGE_NOTIFY and other long-poll operations get STATUS_PENDING first. Must loop until a non-pending response arrives. The pending response still carries valid credit grants.
- **Signing and encryption are mutually exclusive on the wire**: When encrypting, zero the signature field (AEAD provides integrity). On receive, skip signature verification if decryption succeeded.
- **Compound encryption wraps the entire chain**: One TRANSFORM_HEADER for all sub-requests concatenated, not per sub-request.
- **Share-level encryption**: If a share has `SMB2_SHAREFLAG_ENCRYPT_DATA`, encryption is activated even if the session didn't require it.
- **FileDownload/FileUpload can leak handles on drop**: Rust has no async drop. If not consumed fully, the file handle leaks. The types log a warning.
- **FileWriter can leak handles on drop**: Same as FileDownload/FileUpload. Rust has no async drop. If not consumed via `finish()` or `abort()`, the file handle leaks. The type logs a debug warning.
- **DFS paths must include server\share prefix**: When `SMB2_FLAGS_DFS_OPERATIONS` is set, the server expects the path to start with `server\share\` (MS-SMB2 3.2.4.3). `Tree::format_path()` handles this automatically for DFS shares. Without the prefix, Samba strips the first two path components, leading to wrong file opens.
- **DFS redirect changes the tree in-place**: After a DFS redirect, `tree.server`, `tree.share_name`, and `tree.tree_id` all change. Subsequent operations on the same tree use the target server directly -- they must use target-relative paths, not the original DFS paths.
- **tree.server stores addr:port**: The `server` field on `Tree` stores the full `addr:port` string (not just hostname) so `connection_for_tree` can distinguish servers that share the same hostname but use different ports.
- **Servers MAY split compound responses**: MS-SMB2 section 3.3.4.1.3 says the server SHOULD compound responses but is not required to. Samba (and QNAP firmware built on it) is known to split compound chains into separate frames in some scenarios; Windows Server does too under certain conditions. Compound-using methods (`read_file_compound`, `write_file_compound`, `fs_info`, `stat`, `rename`, `delete_file`, batch `*_files`) call `Connection::receive_compound_expected(n)` instead of `receive_compound()`, which transparently gathers additional frames if the server splits. Logged at DEBUG, not WARN -- it's a spec edge case, not a problem.
