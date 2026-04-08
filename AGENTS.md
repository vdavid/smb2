# smb2

Pure-Rust SMB2/3 client library with pipelined I/O. No C dependencies, no FFI. Single crate, async, runtime-agnostic.

## Quick commands

| Command                | Description                                          |
|------------------------|------------------------------------------------------|
| `just`                 | Fast checks: format, lint, test, doc (~2s)           |
| `just check-live`      | Fast checks + integration tests on real servers (~6s)|
| `just fix`             | Auto-fix formatting and clippy warnings              |
| `just check-all`       | Include MSRV check, security audit, and license check|
| `cargo test`           | Run unit tests (mock transport, no server needed)    |

## Project structure

```
src/
  lib.rs                  # Public API exports
  error.rs                # Error types, NTSTATUS mapping

  pack/                   # Binary serialization (cursor-based)
    mod.rs                # ReadCursor, WriteCursor, primitives
    guid.rs               # GUID pack/unpack (mixed-endian)
    filetime.rs           # Windows FILETIME <-> SystemTime

  types/                  # Newtypes and common data structures
    mod.rs                # SessionId, TreeId, FileId, MessageId, CreditCharge
    flags.rs              # Bitflag types (Capabilities, SecurityMode, etc.)
    status.rs             # NtStatus enum (from MS-ERREF)

  msg/                    # Wire format message structs
    mod.rs                # Command enum, Header, ErrorResponse
    header.rs             # SMB2 packet header (sync + async variants)
    negotiate.rs          # NegotiateRequest/Response, negotiate contexts
    session_setup.rs      # SessionSetupRequest/Response
    logoff.rs             # LogoffRequest/Response
    tree_connect.rs       # TreeConnectRequest/Response
    tree_disconnect.rs    # TreeDisconnectRequest/Response
    create.rs             # CreateRequest/Response, create contexts
    close.rs              # CloseRequest/Response
    flush.rs              # FlushRequest/Response
    read.rs               # ReadRequest/Response
    write.rs              # WriteRequest/Response
    lock.rs               # LockRequest/Response
    ioctl.rs              # IoctlRequest/Response
    query_directory.rs    # QueryDirectoryRequest/Response
    change_notify.rs      # ChangeNotifyRequest/Response
    query_info.rs         # QueryInfoRequest/Response
    set_info.rs           # SetInfoRequest/Response
    echo.rs               # EchoRequest/Response
    cancel.rs             # CancelRequest
    oplock_break.rs       # OplockBreakNotification/Acknowledgment
    transform.rs          # TransformHeader (encryption), CompressionTransformHeader

  transport/              # Transport abstraction
    mod.rs                # Transport trait (split send/receive)
    tcp.rs                # Direct TCP (port 445)
    mock.rs               # Mock transport for testing

  crypto/                 # Signing, encryption, key derivation
    mod.rs
    signing.rs            # HMAC-SHA256, AES-CMAC, AES-GMAC
    encryption.rs         # AES-128/256-CCM, AES-128/256-GCM
    kdf.rs                # SP800-108 key derivation

  auth/                   # Authentication
    mod.rs                # Auth trait
    ntlm.rs              # NTLM authentication (from MS-NLMP)

  rpc/                    # Named pipe RPC (MS-RPCE / NDR)
    mod.rs                # RPC PDU types, NDR encoding/decoding
    srvsvc.rs             # NetShareEnumAll — list shares on a server

  client/                 # High-level client API
    mod.rs                # SmbClient (entry point)
    connection.rs         # Connection state, credit management, response demux
    session.rs            # Session (authenticated context)
    tree.rs               # TreeConnect (share access)
    file.rs               # Single-file convenience methods
    pipeline.rs           # Unified operation pipeline
    directory.rs          # Directory listing helpers
    shares.rs             # Share enumeration (IPC$ + srvsvc RPC)

tests/
  pack_roundtrip.rs       # Property-based tests for pack/unpack
  msg_wire_format.rs      # Test messages against known byte sequences
  protocol_flow.rs        # Negotiate -> session -> tree -> file flows (mock)
  integration.rs          # Tests against real Samba server (Docker, ignored)

examples/
  list_shares.rs          # Connect and enumerate shares
  list_directory.rs       # List files in a directory
  read_file.rs            # Read a file from a share
  write_file.rs           # Write a file to a share
```

## Architecture

```
client:: (SmbClient, Tree, Pipeline)   <-- What users interact with
  |
msg:: (wire format pack/unpack)        <-- Protocol messages
  |
transport:: (Transport trait)
  |
tcp::TcpTransport  or  mock::MockTransport
```

**Entry points:** `SmbClient::connect()` for high-level use (handles negotiate + session setup + reconnection), or `Connection::connect()` + `Session::setup()` for low-level control

**Key types:** `SessionId(u64)`, `TreeId(u32)`, `FileId { persistent: u64, volatile: u64 }`, `MessageId(u64)`, `CreditCharge(u16)`

**Layers:**
1. **Client API** (`client/`): High-level operations (connect, read file, list directory). Wraps the pipeline.
2. **Protocol logic** (`client/connection.rs`, `client/pipeline.rs`): Credit management, message sequencing, response demux, compounding. The pipeline is the core feature.
3. **Wire format** (`msg/`, `pack/`): Serialize/deserialize SMB2 messages. Hand-rolled, no proc macros.
4. **Transport** (`transport/`): Send/receive raw bytes over TCP. Split into send/receive halves to avoid deadlocks in the pipeline's `select!` loop.

## Pipeline design

The pipeline is the reason this library exists. Without pipelining, SMB downloads are ~10x slower than native OS implementations.

**How it works:**
- Caller pushes `Op` requests into a channel (`tx`)
- A driver task expands ops into SMB2 messages, sends as many as credits allow
- Responses arrive asynchronously, get matched by `MessageId`, results stream back via `rx`
- Large files get chunked at `MaxReadSize`/`MaxWriteSize` and reassembled
- Credits flow back from responses, sliding the window forward

**Key constraint:** Only ONE task reads from the transport. Multiple pipelines on the same connection share a single receive task that demultiplexes by `MessageId`.

## Key design decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Binary serialization | Hand-rolled `ReadCursor`/`WriteCursor` | Full control, debuggable, no proc-macro dep |
| Async strategy | `dyn Transport` + `async_trait` | Simpler public API than generics |
| ID types | Newtypes (`SessionId(u64)`, etc.) | Zero-cost compile-time safety |
| Error handling | Rich context + `is_retryable()` + NTSTATUS | mtp-rs style |
| Transport trait | Split send/receive | Avoids deadlock in pipeline's `select!` loop |
| Single crate | No workspace | Like mtp-rs, keeps things simple |
| I/O performance | Pipelined reads/writes as core feature | Not an optimization, the reason the lib exists |
| Testing | TDD with mock transport | Spec-driven tests first |
| Primary reference | MS-SMB2 spec (~80%) | smb-rs as sanity check (~15%), mtp-rs as architecture template (~5%) |

## Known protocol pitfalls

These are the top issues that WILL cause bugs if not handled correctly. Read the spec sections before implementing.

1. **Preauthentication integrity hash (SMB 3.1.1):** Key derivation requires hashing raw bytes of NEGOTIATE and SESSION_SETUP messages. Must capture wire bytes before parsing. Wrong hash = wrong keys = first signed message fails. (Spec 3.2.5.2, 3.2.5.3.1)

2. **Compound partial failure:** When CREATE fails in a compound, the server cascades errors to all subsequent ops. If CREATE succeeds but READ fails, CLOSE also fails, and the client MUST issue a standalone CLOSE to avoid leaking the file handle. (Spec 3.3.5.2.7.2)

3. **Consecutive MessageIds for multi-credit requests:** A request consuming N credits MUST use N consecutive MessageIds. Can't use IDs with gaps. Server terminates connection on violation. (Spec 3.2.4.1.5, 3.3.5.2.3)

4. **Signing/encryption ordering:** When encrypting, zero the Signature field (AEAD provides auth). On receive, if decryption succeeded, skip signature verification. Build message -> sign OR zero signature -> encrypt. (Spec 3.2.4.1.1)

5. **TCP framing is big-endian:** Transport header is 1 byte (must be 0x00) + 3 bytes length in big-endian (network byte order). Everything else in SMB is little-endian. (Spec 2.1)

6. **STATUS_PENDING interim responses:** Carry credits in CreditResponse, but the request is NOT done. Store the AsyncId, keep waiting for the final response. Don't remove from in-flight. (Spec 3.3.4.3)

7. **CANCEL has two modes:** Before interim response, use original MessageId. After STATUS_PENDING (have AsyncId), set `SMB2_FLAGS_ASYNC_COMMAND` and use AsyncId. CANCEL doesn't consume credits. (Spec 3.2.4.24)

8. **Session reauthentication:** On STATUS_NETWORK_SESSION_EXPIRED, reauthenticate with same SessionId. MUST NOT regenerate SessionKey. Preserve existing signing/encryption keys. (Spec 3.2.5.1.6, 3.2.5.3.2)

9. **Compound encryption wraps the entire chain:** One TRANSFORM_HEADER for the whole compound, not per sub-request. Sign each sub-request individually (or zero signatures if encrypting), then concatenate, then encrypt. (Spec 3.1.4.3)

10. **STATUS_BUFFER_OVERFLOW is a WARNING, not an error:** Returns valid partial data. Don't discard the response body. Client may retry with a larger buffer. (Spec 3.3.4.4)

11. **Oplock/lease break notifications:** Arrive with MessageId 0xFFFFFFFFFFFFFFFF. Need an `OpenTable: FileId -> (SessionId, TreeId)` to construct a valid ack. Lease breaks arrive with SessionId=0, TreeId=0, look up by LeaseKey. (Spec 3.2.5.19.1)

12. **NTLM MIC:** Modern servers include `MsvAvTimestamp` in the challenge, triggering MIC validation. Must retain raw bytes of NEGOTIATE, CHALLENGE, and AUTHENTICATE for MIC computation. (MS-NLMP)

## Testing approach

- **Unit tests:** `cargo test` — uses mock transport, no server needed
- **Property tests:** `cargo test` includes proptest for pack/unpack roundtrips
- **Integration tests:** `cargo test --test integration -- --ignored` — requires Docker Samba
- **Wire format tests:** Known byte sequences from spec and Wireshark captures

## Code style

Run `just check` before committing. This runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, and `cargo doc --no-deps`.

- `#![forbid(unsafe_code)]` — no unsafe
- `#![warn(missing_docs)]` — doc comments for public APIs
- Hand-rolled pack/unpack, no proc macros for wire format
- Newtypes for all protocol IDs
- `thiserror` for error types

## Logging

The crate uses `log` (a facade) for structured logging. The application picks the backend (for example, `env_logger`, `tracing`).

**Log levels:**

| Level   | Use for                                                                      | Examples                                                  |
|---------|-----------------------------------------------------------------------------|-----------------------------------------------------------|
| `info`  | Major lifecycle events users care about                                      | Connected, negotiated dialect, session established, tree connected/disconnected |
| `debug` | Protocol details useful for debugging                                        | Negotiate params, session setup rounds, signing activation, credit changes, each request/response |
| `trace` | Very verbose, byte-level                                                     | Raw message sizes, signature bytes (first 4), nonce values, preauth hash updates, TCP framing, individual directory entries |
| `warn`  | Unexpected but recoverable                                                   | Signature verification skipped, credit starvation, retryable errors |
| `error` | Should not happen during normal operation                                    | Protocol violations, decryption/signature failures, connection drops |

**How to enable:**

```sh
RUST_LOG=smb2=debug cargo test --test integration -- --ignored
```

**Security rule:** Never log passwords, session keys, signing keys, or full signatures. At most log key lengths and the first four bytes of signatures for correlation.

**Backend note:** `log` is a facade. This crate does NOT depend on any specific backend. Applications using smb2 pick their own (for example, `env_logger`). The `env_logger` dev-dependency is only used in integration tests.

## Spec files

Agents MUST read the actual spec files, not work from memory. Protocol specs are dense and full of edge cases that are easy to get wrong.

- Implementation plan: `docs/specs/implementation-plan.md`
- MS-SMB2 spec: `related-repos/openspecs/skills/windows-protocols/MS-SMB2/MS-SMB2.md`
- MS-ERREF (NTSTATUS codes): `related-repos/openspecs/skills/windows-protocols/MS-ERREF/MS-ERREF.md`
- MS-DTYP (data types): `related-repos/openspecs/skills/windows-protocols/MS-DTYP/MS-DTYP.md`
- MS-FSCC (file system codes): `related-repos/openspecs/skills/windows-protocols/MS-FSCC/MS-FSCC.md`
- MS-NLMP (NTLM auth): `related-repos/openspecs/skills/windows-protocols/MS-NLMP/MS-NLMP.md`
- smb-rs reference impl: `related-repos/smb-rs/`
- mtp-rs architecture template: `../mtp-rs/`

## References

- [MS-SMB2 spec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/) — primary reference
- [mtp-rs](https://github.com/vdavid/mtp-rs) — architecture template
- [smb-rs](https://github.com/oll3/smb-rs) — reference implementation (sanity check only)
