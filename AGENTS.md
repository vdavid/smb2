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
    srvsvc.rs             # NetShareEnumAll (list shares on a server)

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

## Protocol pitfalls (all handled)

These were identified during three adversarial review rounds and have all been addressed. They're documented here so you understand the reasoning behind certain code patterns.

1. **Preauth hash excludes success response** ✅ -- The final SESSION_SETUP response (STATUS_SUCCESS) is NOT included in the preauth hash. Including it produces wrong keys. See `session.rs`.
2. **Compound partial failure** ✅ -- Standalone CLOSE issued when CREATE succeeds but a later op fails. See `tree.rs` compound methods.
3. **Consecutive MessageIds** ✅ -- `send_request_with_credits()` advances MessageId by CreditCharge. See `connection.rs`.
4. **Signing/encryption mutual exclusion** ✅ -- When encrypting, Signature is zeroed, AEAD provides auth. See `connection.rs` send/receive paths.
5. **TCP framing is big-endian** ✅ -- 0x00 + 3-byte BE length. Only big-endian thing in SMB. See `transport/tcp.rs`.
6. **STATUS_PENDING loop** ✅ -- `receive_response()` loops past interim responses, extracting credits. See `connection.rs`.
7. **CANCEL two modes** ✅ -- `send_cancel()` handles sync (MessageId) and async (AsyncId + flag). See `connection.rs`.
8. **Session expiry** ✅ -- `receive_response()` detects STATUS_NETWORK_SESSION_EXPIRED, returns `Error::SessionExpired`. Caller reconnects. See `connection.rs`.
9. **Compound encryption wraps entire chain** ✅ -- One TRANSFORM_HEADER for concatenated compound. See `connection.rs` `send_compound()`.
10. **STATUS_BUFFER_OVERFLOW** ✅ -- Accepted as partial success in QueryInfo responses via `is_success_or_partial()`. See `tree.rs`.
11. **Oplock break notifications** ✅ -- Detected by MessageId 0xFFFF..., logged, skipped. See `connection.rs` receive loop.
12. **NTLM MIC** ✅ -- Computed when MsvAvTimestamp present, using retained raw bytes. See `auth/ntlm.rs`.

## Testing

See `tests/CLAUDE.md` for the full testing guide. Quick reference:

- `cargo test` — unit tests (~555), no server needed
- `just check` — fmt + clippy + tests + doc
- `cargo test --test integration -- --ignored` — real NAS/Pi tests (needs `.env`)
- `just test-docker` — Docker container tests (needs Docker)

## Module docs (CLAUDE.md files)

Each module has a colocated `CLAUDE.md` with architecture, decisions, and gotchas. These are auto-discovered by Claude Code.

**Before modifying a module:** Read its CLAUDE.md.
**After modifying a module:** Update its CLAUDE.md if you changed architecture, added decisions, or discovered new gotchas. Keep them current.

```
src/client/CLAUDE.md    # SmbClient, Connection, compound, pipelining
src/crypto/CLAUDE.md    # Signing, encryption, KDF, preauth hash
src/msg/CLAUDE.md       # Wire format, Pack/Unpack, offsets, compounds
src/transport/CLAUDE.md # Split send/receive, TCP framing, MockTransport
src/auth/CLAUDE.md      # NTLM, MIC, session key derivation
src/rpc/CLAUDE.md       # RPC-over-pipes, NDR, share enumeration
src/pack/CLAUDE.md      # Cursors, GUID, FileTime, MAX_UNPACK_BUFFER
src/types/CLAUDE.md     # Newtypes, enums, bitflags, NtStatus
tests/CLAUDE.md         # Test categories, how to run, writing new tests
```

## Code style

Run `just check` before committing. This runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, and `cargo doc --no-deps`.

- `#![forbid(unsafe_code)]`: no unsafe
- `#![warn(missing_docs)]`: doc comments for public APIs
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

- [MS-SMB2 spec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/): primary reference
- [mtp-rs](https://github.com/vdavid/mtp-rs): architecture template
- [smb-rs](https://github.com/oll3/smb-rs): reference implementation, sanity check only
