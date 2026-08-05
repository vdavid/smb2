# smb2

Pure-Rust SMB2/3 client library with pipelined I/O. No C dependencies, no FFI. Single crate, async, runtime-agnostic.

## Quick commands

- `just`: Fast checks: format, lint, test, doc (~2s)
- `just check-live`: Fast checks + integration tests on real servers (~6s)
- `just fix`: Auto-fix formatting and clippy warnings
- `just check-all`: Include MSRV check, security audit, and license check
- `just test-consumer`: Consumer integration tests (needs Docker, ~30s)
- `cargo test`: Run unit tests (mock transport, no server needed)
- `just fuzz <target> [duration]`: Fuzz a single parse entry point (nightly, cargo-fuzz)
- `just fuzz-seeds`: Regenerate the committed `fuzz/corpus/` seeds

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
    create_context.rs     # Create-context codec + DH2Q/DH2C (durable handles v2) + QFid
    close.rs              # CloseRequest/Response
    copychunk.rs          # Server-side copy structures (SRV_COPYCHUNK_COPY/RESPONSE, RESUME_KEY)
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
    dfs.rs                # DFS referral request/response wire format

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

  testing/                # Consumer test harness (feature-gated: `testing`)
    mod.rs                # TestServers API, embedded Docker infrastructure
    fixtures/consumer/    # Consumer Docker fixtures, embedded via include_str! (shipped in the crate)
    CLAUDE.md

  fuzzing.rs              # Parse entry points exposed under the `fuzzing` feature (used by `fuzz/`)

  client/                 # High-level client API
    mod.rs                # SmbClient (entry point)
    connection.rs         # Connection state, response demux, response deadline
    credits.rs            # Connection-wide credit budget, send-side gate
    session.rs            # Session (authenticated context)
    tree.rs               # TreeConnect (share access)
    file.rs               # Single-file convenience methods
    pipeline.rs           # Unified operation pipeline
    directory.rs          # Directory listing helpers
    shares.rs             # Share enumeration (IPC$ + srvsvc RPC)
    dfs.rs                # DFS referral IOCTL, DfsResolver with TTL cache
    copy.rs               # Server-side copy API (FSCTL_SRV_COPYCHUNK): resume-key + copychunk, batched convenience
    durable.rs            # Durable handles: open, reclaim, and the two proofs that make a resume safe
    fault_injection_tests.rs # Hostile-but-plausible servers: one that goes silent, one that goes away and comes back

tests/
  pack_roundtrip.rs       # Property-based tests for pack/unpack
  msg_wire_format.rs      # Test messages against known byte sequences
  protocol_flow.rs        # Negotiate -> session -> tree -> file flows (mock)
  integration.rs          # Tests against real NAS/Pi (#[ignore])
  docker_integration.rs   # Tests against Docker Samba containers (#[ignore])
  consumer_integration.rs # Tests against consumer Docker containers (#[ignore])
  docker/                 # Docker infrastructure for smb2's own integration tests
    internal/             # Internal-suite containers (consumer fixtures live in src/testing/fixtures/)

examples/
  list_shares.rs          # Connect and enumerate shares
  list_directory.rs       # List files in a directory
  read_file.rs            # Read a file from a share
  write_file.rs           # Write a file to a share
  write_storm.rs          # Concurrent bulk-copy stress/diagnostic driver (see its header for the knobs)

fuzz/
  Cargo.toml              # Separate crate (nightly + libfuzzer-sys)
  fuzz_targets/*.rs       # One fuzz target per parse entry point
  corpus/<target>/seed_*.bin  # Committed seeds, generated by `tests/fuzz_seeds.rs`
```

## Kerberos status

Tested end-to-end against Windows Server 2022 with AD DS (2026-04-09). Full flow works: AS exchange, TGS exchange,
AP-REQ in SPNEGO, SMB SESSION_SETUP, file read/write. See `tests/CLAUDE.md` for AWS access details and
`src/auth/CLAUDE.md` for design decisions discovered during testing.

## Quality bar

Each change must be solid AND elegant. Safe for family photos and company docs. No races, no code smells, no missing
docs. Agents must update CLAUDE.md files when modifying modules.

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

**Entry points:** `SmbClient::connect()` for high-level use (handles negotiate + session setup + reconnection), or
`Connection::connect()` + `Session::setup()` for low-level control

**Key types:** `SessionId(u64)`, `TreeId(u32)`, `FileId { persistent: u64, volatile: u64 }`, `MessageId(u64)`,
`CreditCharge(u16)`

**Layers:**

1. **Client API** (`client/`): High-level operations (connect, read file, list directory). Wraps the pipeline.
2. **Protocol logic** (`client/connection.rs`, `client/pipeline.rs`): Credit management, message sequencing, response
   demux, compounding. The pipeline is the core feature.
3. **Wire format** (`msg/`, `pack/`): Serialize/deserialize SMB2 messages. Hand-rolled, no proc macros.
4. **Transport** (`transport/`): Send/receive raw bytes over TCP. Split into send/receive halves to avoid deadlocks in
   the pipeline's `select!` loop.

## Pipeline design

The pipeline is the reason this library exists. Without pipelining, SMB downloads are ~10x slower than native OS
implementations.

**How it works:**

- Caller pushes `Op` requests into a channel (`tx`)
- A driver task expands ops into SMB2 messages, sends as many as credits allow
- Responses arrive asynchronously, get matched by `MessageId`, results stream back via `rx`
- Large files get chunked at `MaxReadSize`/`MaxWriteSize` and reassembled
- Credits flow back from responses, sliding the window forward

**Key constraint:** Only ONE task reads from the transport. Every `Connection` spawns a single receiver task on
construction that owns the read half, demultiplexes each incoming frame to the matching request's
`oneshot::Sender<Frame>` (keyed by `MessageId`), and handles decrypt/decompress/sign-verify/credits/PENDING-loop/
oplock-break/session-expiry centrally. Dropping a caller's future drops its `oneshot::Receiver`; the receiver task
discards the late-arriving response silently. See `docs/specs/connection-actor.md` for the full design and
`src/client/CLAUDE.md` § "Connection internals: receiver task + `oneshot` routing" for the architectural sketch.

## Key design decisions

| Decision             | Choice                                     | Why                                                                  |
|----------------------|--------------------------------------------|----------------------------------------------------------------------|
| Binary serialization | Hand-rolled `ReadCursor`/`WriteCursor`     | Full control, debuggable, no proc-macro dep                          |
| Async strategy       | `dyn Transport` + `async_trait`            | Simpler public API than generics                                     |
| ID types             | Newtypes (`SessionId(u64)`, etc.)          | Zero-cost compile-time safety                                        |
| Error handling       | Rich context + `is_retryable()` + NTSTATUS | mtp-rs style                                                         |
| Transport trait      | Split send/receive                         | Avoids deadlock in pipeline's `select!` loop                         |
| Single crate         | No workspace                               | Like mtp-rs, keeps things simple                                     |
| I/O performance      | Pipelined reads/writes as core feature     | Not an optimization, the reason the lib exists                       |
| Batch operations     | Send-all-then-receive-all for multi-file ops | No new infra needed -- N `send_compound` + N `receive_compound`    |
| Testing              | TDD with mock transport                    | Spec-driven tests first                                              |
| Primary reference    | MS-SMB2 spec (~80%)                        | smb-rs as sanity check (~15%), mtp-rs as architecture template (~5%) |

## Protocol pitfalls (all handled)

Cross-module protocol concerns that span multiple files. Each is handled, but documented here so you understand
non-obvious code patterns. Module-specific gotchas go in the relevant `CLAUDE.md`; cross-cutting ones go here. If you
discover a new pitfall that involves 2+ modules, add it to this list.

1. **Preauth hash excludes success response** ✅ -- The final SESSION_SETUP response (STATUS_SUCCESS) is NOT included in
   the preauth hash. Including it produces wrong keys. See `session.rs`.
2. **Compound partial failure** ✅ -- Standalone CLOSE issued when CREATE succeeds but a later op fails. See `tree.rs`
   compound methods.
3. **Consecutive MessageIds** ✅ -- `send_request_with_credits()` advances MessageId by CreditCharge. See
   `connection.rs`.
4. **Signing/encryption mutual exclusion** ✅ -- When encrypting, Signature is zeroed, AEAD provides auth. See
   `connection.rs` send/receive paths.
5. **TCP framing is big-endian** ✅ -- 0x00 + 3-byte BE length. Only big-endian thing in SMB. See `transport/tcp.rs`.
6. **STATUS_PENDING loop** ✅ -- `receive_response()` loops past interim responses, extracting credits. See
   `connection.rs`.
7. **CANCEL two modes, and a nonce bit that makes or breaks both** ✅ -- `send_cancel()` handles sync (MessageId) and async (AsyncId + flag); a request the server has answered with an interim STATUS_PENDING has an AsyncId and can ONLY be cancelled by it (MS-SMB2 § 3.2.4.24), which is why `Waiter` records it and `OutstandingRequest` exposes it. Under AES-GMAC the signature nonce carries a "this is a CANCEL" bit (§ 3.1.4.1) on both the sign and the verify path; without it a GMAC-negotiating server refuses the cancel, and since a cancel has no success response the client sees nothing and believes it let go of a request the server still holds. Spans `client/connection.rs` + `crypto/signing.rs`; see `crypto/CLAUDE.md`.
8. **Session expiry** ✅ -- `receive_response()` detects STATUS_NETWORK_SESSION_EXPIRED, returns `Error::SessionExpired`.
   Caller reconnects. See `connection.rs`.
9. **Compound encryption wraps entire chain** ✅ -- One TRANSFORM_HEADER for concatenated compound. See `connection.rs`
   `send_compound()`.
10. **STATUS_BUFFER_OVERFLOW** ✅ -- Accepted as partial success in QueryInfo responses via `is_success_or_partial()`.
    See `tree.rs`.
11. **Oplock break notifications** ✅ -- Detected by MessageId 0xFFFF..., logged, skipped. See `connection.rs` receive
    loop.
12. **NTLM MIC** ✅ -- Computed when MsvAvTimestamp present, using retained raw bytes. See `auth/ntlm.rs`.
13. **Server may split compound responses** ✅ -- MS-SMB2 3.3.4.1.3: the server SHOULD compound responses but MAY send them as separate frames (Samba/QNAP do this in some cases). Compound-using methods call `Connection::receive_compound_expected(n)`, which gathers additional frames transparently. See `connection.rs` + `tree.rs`.
14. **Credits are spent on send, not on receipt** ✅ -- `client/credits.rs` reserves a request's `CreditCharge` before its bytes reach the wire; only a `CreditResponse` grant puts credits back. Charging on the response instead leaves every in-flight request invisible, so concurrent pipelined streams over one connection each spend the same budget and blow past the server's window. MS-SMB2 § 3.3.1.1 lets a server drop such a client; a QNAP TS-464 instead stopped answering while TCP stayed `ESTABLISHED` (2026-07-31, reproduced twice). A short send parks on a bounded wait and surfaces `Error::CreditStarvation` rather than hanging. Spans `client/credits.rs` + `client/connection.rs` + the pipelined loops in `client/tree.rs` and `client/stream.rs`.
15. **A silent server must not hang a caller** ✅ -- `Connection::await_response` gives up after 30 s without a sign of life. The clock measures silence, not elapsed time: it starts when the frame reaches the wire (`mark_sent`) and interim `STATUS_PENDING` frames refresh `Waiter.last_activity` (MS-SMB2 § 3.2.5.1.5), so an acknowledged operation is never cut short however long it runs — that refresh is the whole reason the deadline can be this short. Long-poll CHANGE_NOTIFY is exempt. See `client/CLAUDE.md` § Response deadline.
16. **Getting ONTO the wire is bounded, not just getting a reply** ✅ -- A dedicated writer task (`client/connection.rs`
    `writer_loop`) owns the transport's write half; callers hand over whole frames through an `mpsc` queue and never
    touch the socket. Every other deadline in this crate starts once the server has been asked, so a socket that stopped
    accepting writes while TCP stayed `ESTABLISHED` was invisible to all of them: a 2026-08-01 Cmdr wedge sat frozen 40
    minutes with ~700 requests registered as in-flight and zero bytes sent, and neither the response deadline nor the
    credit bound could fire because both live downstream of the send. The writer task times each frame out
    (`Error::SendTimeout`, 20 s default) and tears the connection down, because a write abandoned partway leaves half a
    frame on the wire. Handing over whole frames also removes a second hazard: a caller cancelled between
    `TcpTransport::send`'s length-header write and its body write used to desynchronize the stream permanently, and
    consumers cancel routinely. Spans `client/connection.rs` + `transport/tcp.rs`.
17. **Waiters deregister on drop** ✅ -- `register_waiter` returns a `WaiterGuard` whose `Drop` removes the map entry, so
    an aborted caller (the common `tokio::spawn` + `abort()` shape) leaves nothing behind. Previously only the response
    deadline ever removed a waiter, which inflated `outstanding_requests()` with long-dead requests and made
    `reserve_credits`' "is anything outstanding that could bring a grant back?" check permanently true, so real
    starvation waited out the full deadline instead of failing fast. A bounded ring of abandoned MessageIds keeps
    `responses_late_after_drop` distinguishable from `responses_stray`. See `client/connection.rs`.
18. **Share-enum responses split two ways** ✅ -- A srvsvc `NetShareEnum` reply can arrive as multiple DCE/RPC fragments (MS-RPCE 2.2.2.6, `PFC_LAST_FRAG` only on the last) and/or as `STATUS_BUFFER_OVERFLOW` pipe reads (MS-SMB2 3.3.5.10) when it exceeds one read buffer. `client::shares::read_pipe_message` follows the overflow chain; `rpc_bind_and_request` loops `rpc::parse_response_fragment` until the last fragment, then NDR-decodes the joined stub. Treating either as a hard error (the old behavior) truncated or failed listings on servers that chunk large replies. Spans `rpc/` + `client/shares.rs`.
19. **A deadline cannot tell slow from dead; ECHO can** ✅ -- A response deadline has to be sized for the slowest thing a healthy server does without a word, which makes it a poor detector of a dead one: too short and a large write to a loaded spinning-disk NAS is killed, too long and a dead session freezes a transfer. SMB2 ECHO (MS-SMB2 § 2.2.28) touches no share, handle, or disk, so an answer means the server is processing requests, full stop. **The keepalive tells the response deadline whether the server is alive; an alive server gets more time.** That is all of it: `client/connection.rs` `keepalive_loop` probes a connection that has gone quiet with work outstanding (5 s, on by default, `Connection::set_keepalive`), and a request on a connection it has just proven alive gets 6× the deadline before being abandoned. ❌ A missed probe is never a verdict -- it withholds the extension and nothing more -- because a real NAS drops probes precisely when it is busy writing, which is exactly when a transfer is running (QNAP TS-464 under write load, 2026-08-02). It measures *silence*, so a busy connection never probes and an idle one is not probed either. Two more traps it is designed around: a probe that cannot get a credit is skipped and never counted against the server, and getting the probe onto the wire stays the send deadline's problem. What still declares a session dead is `Connection::await_response`, and only when BOTH hold: a request ran out of its full deadline AND the connection put nothing at all on the wire meanwhile (`Error::ServerUnresponsive`, every waiter told at once so `reconnect_if_needed` has something to revive). CHANGE_NOTIFY is exempt from the *request's* deadline but bounded by the connection's silence the same way, since nothing else can tell a `Watcher` its session died -- which means `Watcher::next_events` has to finish through `await_response` like everything else; a bare `WaiterGuard::recv()` is unbounded and skipped the whole mechanism (measured 2026-08-02: 90.3 s of silence, 17 consecutive unanswered probes, watcher none the wiser). Spans `client/connection.rs` + `client/credits.rs`; see `client/CLAUDE.md` § Liveness.
20. **A dead connection comes back under the handles that outlived it** ✅ -- `FileWriter`, `FileReader`, `Watcher`, and every pipelined task own a `Connection` clone, so a reconnect that minted a *new* `Connection` would leave all of them permanently dead and make the consumer rebuild the world. `Connection::reconnect_if_needed` swaps the transport in place under the shared `Arc<Inner>` and erases every scrap of the dead session (credits, message ids, signing keys, negotiated sizes, tree ids), then rebuilds all four background tasks -- three of which exit for good on `disconnected`, so a revival that only replaced the socket would come back with no keepalive and no stale-request warning, silently. One dial serves a whole pipeline's worth of callers. Every bound lives in `ReconnectPolicy`: the wall-clock budget wraps the ENTIRE revival (a per-attempt timeout multiplies by the attempt count, and an attempt that parks forever never reaches the second one), and a failed revival's verdict stands for a cooldown so 32 callers don't each pay the budget. ❌ `execute` never reconnects on your behalf: re-issuing an arbitrary request against a new session is a data-safety call only the layer that knows the operation's semantics can make. Spans `client/connection.rs` + `client/mod.rs` + `client/credits.rs`; see `client/CLAUDE.md` § Reconnection.
21. **A reclaimed durable handle is proven, never assumed** ✅ -- Writing into the wrong file is far worse than a failed transfer, so `Tree::reclaim_durable_handle` needs two independent proofs: the `CreateGuid` the server matched (MS-SMB2 § 3.3.5.9.12), and a compounded `QUERY_INFO` saying which file the handle points at, read at open and again after the reclaim. Either one missing means the handle is closed and the transfer restarts. SMB 2.1's v1 durable handles are deliberately unimplemented (server-allocated `FileId` only, nothing the client contributed). Two findings a mock could never have surfaced, both verified against Samba 4.20.6 on 2026-08-02: a reclaim carrying any other create context is rejected outright (so the identity check cannot ride on the `QFid` context), and `FileIdInformation` (class 59) is answered `STATUS_INVALID_INFO_CLASS` (so it uses class 6 plus `FileFsVolumeInformation`). The batch oplock durability requires bills other clients ~35 s per unanswered break, so breaks are acknowledged. Spans `msg/create_context.rs` + `client/durable.rs` + `client/connection.rs`; see `client/CLAUDE.md` § Durable handles.

22. **A long poll can die on its own, and only a cycle can heal it** ✅ -- Every liveness verdict in this crate is about the CONNECTION (`quiet_for`, the ECHO probes, `unresponsive_for`, and the long-poll bound built on them), so a server that keeps answering everything while it has quietly forgotten one CHANGE_NOTIFY reads as perfectly healthy by all of them. A QNAP TS-464 held two subscriptions for 6,186 s that way while `fs_info` on the same connection round-tripped in 4 ms (2026-08-03). ❌ There is nothing here to detect: a forgotten subscription and an untouched directory are the same observation, so any heuristic that "notices" one also kills healthy watches. What fixes it is refusing to trust a single subscription indefinitely — `Connection::set_long_poll_refresh` (10 min, on by default) retires each one and issues a replacement, first so the wire is never unarmed, then CANCELling the retired ones with the `AsyncId` the server assigned (MS-SMB2 § 3.2.4.24; a cancel without it matches nothing and the server keeps the subscription). Counted as `long_poll_refreshes`, which is a handover count and never a fault count. Spans `client/connection.rs` + `client/watcher.rs`; see `client/CLAUDE.md` § The long-poll refresh cycle.

## Testing

See `tests/CLAUDE.md` for the full testing guide. Quick reference:

- `cargo test` — unit tests (~1,000), no server needed
- `just check` — fmt + clippy + tests + doc
- `cargo test --test integration -- --ignored` — real NAS/Pi tests (needs `.env`)
- `just test-docker` — Docker container tests (needs Docker, ~28s locally)
- `just test-consumer` — Consumer integration tests (needs Docker, ~30s locally)

### Docker test containers

15 Samba containers in `tests/docker/internal/`, exercising the full protocol stack:

| Container             | Port  | What it tests                                 |
|-----------------------|-------|-----------------------------------------------|
| smb-guest             | 10445 | Guest access, basic operations                |
| smb-auth              | 10446 | NTLM authentication                           |
| smb-signing           | 10447 | Mandatory signing (server rejects unsigned)   |
| smb-readonly          | 10448 | Write/delete return clean NTSTATUS errors     |
| smb-ancient           | 10449 | SMB1 only, clean protocol rejection           |
| smb-flaky             | 10450 | 5s up / 5s down, reconnect behavior           |
| smb-slow              | 10451 | 200ms latency, pipelining under delay         |
| smb-encryption        | 10452 | Mandatory encryption (AES-128-GCM, SMB 3.1.1) |
| smb-50shares          | 10453 | 50 shares, RPC enumeration at scale           |
| smb-manyshares        | 10458 | 200 long-comment shares, multi-fragment srvsvc reassembly |
| smb-maxreadsize       | 10454 | 64 KB max read/write, chunking edge cases     |
| smb-encryption-aes128 | 10455 | Mandatory encryption (AES-128-CCM, SMB 3.0.2) |
| smb-weirdnames        | 10459 | Names carrying SMB2-illegal characters, seeded as the exact private-use bytes macOS writes |
| smb-dfs-root          | 10456 | DFS namespace root with msdfs link            |
| smb-dfs-target        | 10457 | DFS target server with actual files            |

### Consumer test containers

14 Samba containers embedded in the crate under `src/testing/fixtures/consumer/`, used by apps that depend on smb2 to test their SMB integration. Exposed via the `smb2::testing` module (requires `testing` feature flag). They live in `src/` (not `tests/`) because the published crate embeds them via `include_str!`.

| Container              | Port  | What it tests                                 |
|------------------------|-------|-----------------------------------------------|
| smb-consumer-guest     | 10480 | Guest access, basic operations                |
| smb-consumer-auth      | 10481 | Login flow                                    |
| smb-consumer-both      | 10482 | Mixed auth: guest + authenticated shares      |
| smb-consumer-50shares  | 10483 | Share list UI, scrolling, search              |
| smb-consumer-unicode   | 10484 | CJK, emoji, accented chars                    |
| smb-consumer-longnames | 10485 | 200+ char filenames                           |
| smb-consumer-deepnest  | 10486 | 50-level deep tree                            |
| smb-consumer-manyfiles | 10487 | 10k+ files in one dir                         |
| smb-consumer-readonly  | 10488 | Read-only share, write errors                 |
| smb-consumer-windows   | 10489 | Windows-like server string                    |
| smb-consumer-synology  | 10490 | Synology-like server string + TimeMachine     |
| smb-consumer-linux     | 10491 | Default Linux Samba server                    |
| smb-consumer-flaky     | 10492 | Error recovery UI, reconnect handling         |
| smb-consumer-slow      | 10493 | Loading spinners, progress bars, timeouts     |
| smb-consumer-maxreadsize | 10494 | Streaming-fallback chunking (64 KB max read/write) |

### Tested hardware

Integration tests (`tests/integration.rs`) run against real hardware:

- QNAP TS-464 NAS (SMB 3.1.1, NTLM auth, AES-GMAC signing)
- Raspberry Pi 4 Model B (SMB 3.1.1, guest access). ⚠️ Its Samba 4.9.5 crashes on compound writes; that is a server bug,
  not ours. See `docs/notes/samba-4.9-compound-write-crash.md` before diagnosing a dead connection against it.

How much silence a real one of each tolerates before a watch is given up on, and the `SIGSTOP` recipe that
measures it deterministically: `docs/notes/watcher-silence-tolerance.md`.

## Module docs (CLAUDE.md files)

Each module has a colocated `CLAUDE.md` with architecture, decisions, and gotchas. These are auto-discovered by Claude
Code.

**Before modifying a module:** Read its CLAUDE.md.
**After modifying a module:** Update its CLAUDE.md if you changed architecture, added decisions, or discovered new
gotchas. Keep them current.

```
src/testing/CLAUDE.md   # Consumer test harness, TestServers API, embedded Docker infra
src/client/CLAUDE.md    # SmbClient, Connection, compound, pipelining
src/crypto/CLAUDE.md    # Signing, encryption, KDF, preauth hash
src/msg/CLAUDE.md       # Wire format, Pack/Unpack, offsets, compounds
src/transport/CLAUDE.md # Split send/receive, TCP framing, MockTransport
src/auth/CLAUDE.md      # NTLM, MIC, session key derivation
src/rpc/CLAUDE.md       # RPC-over-pipes, NDR, share enumeration
src/pack/CLAUDE.md      # Cursors, GUID, FileTime, MAX_UNPACK_BUFFER
src/types/CLAUDE.md     # Newtypes, enums, bitflags, NtStatus
tests/CLAUDE.md         # Test categories, how to run, writing new tests, AWS access for Kerberos testing
```

## Code style

Run `just check` before committing. This first updates the stable toolchain (`rustup update stable`, soft-failing
offline) so local clippy matches CI's always-latest stable, then runs `cargo fmt --check`,
`cargo clippy -- -D warnings`, `cargo test`, and `cargo doc --no-deps`.

- `#![forbid(unsafe_code)]`: no unsafe
- `#![warn(missing_docs)]`: doc comments for public APIs
- Hand-rolled pack/unpack, no proc macros for wire format
- Newtypes for all protocol IDs
- `thiserror` for error types

## Diagnostics

`SmbClient::diagnostics()` and `Connection::diagnostics()` return an in-process snapshot of the client's state plus 26
`AtomicU64` counters per connection (`requests_sent`, `wire_bytes_*`, the disjoint routing partition `responses_*`,
`status_pending_loops`, `signature_failures`, `credit_waits` / `credit_starvations` / `response_timeouts`,
`keepalive_probes_sent` / `keepalive_probes_skipped` / `keepalive_failures` / `response_deadline_extensions`,
`long_poll_refreshes`, `reconnect_attempts` / `reconnects_succeeded` / `reconnects_failed`, etc.) and three client-level counters (`reconnects`,
`dfs_referrals_resolved`, `dfs_cache_hits`). Eventually consistent, survives connection teardown, and now survives a
reconnect too (which revives the connection in place rather than replacing it), so the numbers describe the whole life
of the link. `OutstandingRequest::sent_age` says which side of the wire a request is on: `None` means
it is still queued for the transport, so the server has not been asked and nothing about the server follows from it. `OutstandingRequest::async_id` is what a `Connection::send_cancel` for that request has to carry. `Display` impl for terminal output; optional `serde` feature for JSON.

Spec: [`docs/specs/diagnostics-plan.md`](docs/specs/diagnostics-plan.md). Quick smoke test:

```sh
SMB2_PASS=secret cargo run --example diagnostics
SMB2_PASS=secret cargo run --example diagnostics --features serde -- --json
```

## Logging

The crate uses `log` (a facade) for structured logging. The application picks the backend (for example, `env_logger`,
`tracing`).

**The volume rule (read this before adding any log line):** no site at `debug` or above may fire at a rate
proportional to the number of frames on the wire. A consumer runs its own code at `debug`, and a library that spends
that budget on protocol plumbing makes `debug` useless for the person who owns the application. If a line's rate
tracks request volume, it belongs at `trace`, where anyone who wants a packet-by-packet trace can turn it on.

Two follow-on rules fall out of it:

- **One `debug` line per consumer-visible operation, not two.** Where a code path logs both "starting X" and "X done",
  the "starting" line is `trace` and the "done" line (the one carrying the result: bytes, count, throughput) is
  `debug`. Reaching for both at `debug` doubles the volume and adds nothing.
- **`info` gets one line per protocol milestone, and nothing else.** Never announce an intent that the very next line
  confirms, and never log a per-file operation at `info`: a consumer deleting 5,000 files would get 5,000 `info` lines.

**Log levels:**

- `info`: connection and session milestones only. Connected, negotiated dialect, session established, tree
  connected/disconnected, reconnect succeeded, durable handle reclaimed. There are ~11 `info` sites in the whole crate,
  and four of them fire per connect. Keep it that way.
- `debug`: what changed the connection's capabilities (negotiate params, signing/encryption activation, credit
  starvation and recovery), the mutations a consumer asked for (write, rename, delete, mkdir), one summary per
  multi-round-trip transfer (bytes and MB/s), and anomalies (orphan frames, non-fatal compound sub-request failures,
  handles that may leak, long-poll refreshes).
- `trace`: everything that happens once per request or per response. Dispatch, interim `STATUS_PENDING` responses,
  cancels, per-message signing, success routing, TCP framing. Also the read path (`stat`, `fs_info`, single-round-trip
  reads, opening a handle), because reads change nothing and are what a polling consumer does constantly, plus
  byte-level detail: raw message sizes, signature bytes (first four), nonce values, preauth hash updates, individual
  directory entries, Kerberos and NTLM key and ciphertext lengths.
- `warn`: unexpected but recoverable. Signature verification skipped, credit starvation, retryable errors.
- `error`: shouldn't happen during normal operation. Protocol violations, decryption and signature failures,
  connection drops.

An idle connection is the test case that matters: keepalive `ECHO`s and long-polling `CHANGE_NOTIFY`s must produce
nothing at `debug` when they're working.

**How to enable:**

```sh
RUST_LOG=smb2=debug cargo test --test integration -- --ignored
```

**Security rule:** Never log passwords, session keys, signing keys, or full signatures. At most log key lengths and the
first four bytes of signatures for correlation.

**Backend note:** `log` is a facade. This crate does NOT depend on any specific backend. Applications using smb2 pick
their own (for example, `env_logger`). The `env_logger` dev-dependency is only used in integration tests.

## Spec files

Agents MUST read the actual spec files, not work from memory. Protocol specs are dense and full of edge cases that are
easy to get wrong.

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
- [docs/releasing.md](docs/releasing.md) — how to publish a new version to crates.io
