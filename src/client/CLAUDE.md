# Client -- high-level SMB2 API

Entry point for most users. `SmbClient` wraps `Connection` + `Session` and provides convenience methods for file operations.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `SmbClient`, `ClientConfig`, `connect()` shorthand |
| `connection.rs` | `Connection` -- credit tracking, message sequencing, signing, encryption, compound send/receive |
| `session.rs` | `Session::setup()` -- NTLM auth, key derivation, signing/encryption activation |
| `tree.rs` | `Tree` -- share connection, file CRUD, compound and pipelined I/O |
| `stream.rs` | `FileDownload` / `FileUpload` -- streaming I/O with progress |
| `watcher.rs` | `Watcher` -- directory change notifications via CHANGE_NOTIFY long-poll |
| `pipeline.rs` | `Pipeline` / `Op` / `OpResult` -- batched concurrent operations (the core feature) |
| `shares.rs` | Share enumeration via IPC$ + srvsvc RPC |

## Layering

```
SmbClient  (owns Connection + Session, stores credentials for reconnect)
  Connection  (TCP transport, credits, message IDs, signing, encryption)
    Session   (NTLM auth, key derivation -- setup mutates Connection)
      Tree    (share-level ops, borrows &mut Connection for each call)
```

All `Tree` methods take `&mut Connection` as a parameter. `SmbClient` convenience methods thread this through automatically.

## Connection and credits

- Connection starts with 1 credit (from negotiate). Requests 256 credits in every message.
- Multi-credit requests (reads/writes > 64 KB) consume `ceil(payload_size / 65536)` credits and use that many consecutive `MessageId` values. Gaps in `MessageId` sequences cause the server to drop the connection.
- Credits flow back from responses via `CreditResponse` header field. The connection tracks available credits and blocks if exhausted.
- `STATUS_PENDING` interim responses carry credits but the request isn't done -- keep waiting.

## Compound requests

`send_compound` packs multiple operations into a single transport frame. Each sub-request is 8-byte aligned, linked via `NextCommand`. Subsequent related operations use `FileId::SENTINEL` (the server substitutes the real handle from the first CREATE).

- **Read compound**: CREATE + READ + CLOSE (3 ops, 1 round-trip). Default for `read_file`.
- **Write compound**: CREATE + WRITE + FLUSH + CLOSE (4 ops, 1 round-trip). Default for `write_file`.
- If CREATE succeeds but a later op fails, the client issues a standalone CLOSE to avoid leaking the handle.

## Pipelined I/O

For large files, `read_file_pipelined` / `write_file_pipelined` send multiple READ/WRITE requests without waiting for responses, bounded by available credits. Chunk size is `min(512 KB, max_read_size)` with up to 32 in-flight requests. This is the core performance feature -- without it, throughput is ~10x worse.

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
