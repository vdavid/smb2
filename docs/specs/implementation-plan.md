# smb2-rs implementation plan

Pure-Rust SMB2/3 client library. No C dependencies, no FFI. Modeled after
[mtp-rs](https://github.com/vdavid/mtp-rs) in architecture and style.

## Decisions made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Fork vs. rewrite | **Rewrite** | smb-rs has almost no tests, architectural mismatch with our style, license (MIT-only vs our MIT OR Apache-2.0) |
| Binary serialization | **Hand-rolled pack/unpack** with cursor-based reader | Full control, more debuggable, no proc-macro dependency. Cursor approach keeps it compact. |
| Async strategy | **Option B: `dyn Transport` + `async_trait`** | Simpler public API than generics. Drop `async_trait` when `async_fn_in_dyn_trait` stabilizes in Rust. |
| ID types | **Newtypes** | `SessionId(u64)`, `TreeId(u32)`, `FileId { persistent: u64, volatile: u64 }` etc. Zero-cost, compile-time safety. |
| Error handling | **Combined approach** | mtp-rs style (rich context, `is_retryable()`) + comprehensive NTSTATUS coverage from spec |
| Transport trait | **Single trait, simple** | Framing as a separate concern, not baked into the trait |
| Testing | **TDD** | Spec-driven tests first for wire format; mock transport for protocol logic; Docker Samba for integration |
| License | **MIT OR Apache-2.0** | Standard Rust ecosystem dual license |
| Primary reference | **MS-SMB2 spec** (~80%) | smb-rs as sanity check (~15%), mtp-rs as architecture template (~5%) |
| I/O performance | **Pipelined reads/writes as a core feature** | Credit-window-based sliding window; use server's `MaxReadSize`/`MaxWriteSize`. Not an optimization — it's the reason this lib exists. |

## Crate structure

Single crate (like mtp-rs), not a workspace of many crates (unlike smb-rs).
Features gate optional functionality.

```
smb2/
  src/
    lib.rs                  # Public API exports
    error.rs                # Error types, NTSTATUS mapping

    pack/                   # Binary serialization (copy+extend from mtp-rs)
      mod.rs                # ReadCursor, WriteCursor, primitives
      guid.rs               # GUID pack/unpack
      filetime.rs           # Windows FILETIME <-> SystemTime

    types/                  # Newtypes and common data structures
      mod.rs                # SessionId, TreeId, FileId, MessageId, CreditCharge
      flags.rs              # Bitflag types (Capabilities, SecurityMode, etc.)
      status.rs             # NtStatus enum (from MS-ERREF)
      security.rs           # SID, ACL types (from MS-DTYP)

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
      mod.rs                # Transport trait
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
      connection.rs         # Connection state, credit management, response demux, OpenTable
      session.rs            # Session (authenticated context)
      tree.rs               # TreeConnect (share access)
      file.rs               # Single-file convenience methods (wraps pipeline)
      pipeline.rs           # Unified operation pipeline (reads, writes, deletes, stats, listings)
      directory.rs          # Directory listing helpers
      shares.rs             # Share enumeration (IPC$ + srvsvc RPC)

  tests/
    pack_roundtrip.rs       # Property-based tests for pack/unpack
    msg_wire_format.rs      # Test messages against known byte sequences
    protocol_flow.rs        # Test negotiate -> session -> tree -> file flows with mock transport
    integration.rs          # Tests against real Samba server (Docker, ignored by default)

  examples/
    list_shares.rs          # Connect and enumerate shares
    read_file.rs            # Read a file from a share
    write_file.rs           # Write a file to a share
    watch_directory.rs      # Monitor directory changes
```

## Phases

### Phase 0: Project scaffold

Set up the Cargo project, CI, linting, and dev tooling.

**Deliverables:**
- `Cargo.toml` with metadata, dependencies, features
- `justfile` (like mtp-rs)
- `rustfmt.toml`, `clippy.toml`, `deny.toml`
- `.gitignore`
- `AGENTS.md`
- `LICENSE-MIT`, `LICENSE-APACHE`
- Empty `src/lib.rs` that compiles
- GitHub Actions CI (fmt, clippy, test, deny)

**Dependencies (initial):**
- `futures` + `async-trait` (async)
- `thiserror` (errors)
- `num_enum` (enum conversions)
- `bytes` (byte handling)
- `tokio` (dev-dependency only, for running async tests)
- `proptest` (dev-dependency, property testing)

**No agents needed, just setup.**

---

### Phase 1: Pack/unpack foundation + types

TDD: write tests first, then the implementation.

**1a. Pack/unpack primitives** (copy+adapt from mtp-rs)
- `ReadCursor` struct: wraps `&[u8]` with offset tracking
  - `read_u8()`, `read_u16_le()`, `read_u32_le()`, `read_u64_le()`, `read_u128_le()`
  - `read_bytes(n)`, `read_utf16_le(len)`, `skip(n)`, `remaining()`, `position()`
- `WriteCursor` struct: wraps `Vec<u8>` with write tracking
  - `write_u8()`, `write_u16_le()`, `write_u32_le()`, `write_u64_le()`, `write_u128_le()`
  - `write_bytes()`, `write_utf16_le()`, `write_zeros(n)`, `align_to(n)`
  - `position()`, `set_u16_le_at(pos)`, `set_u32_le_at(pos)` (for backpatching offsets)
- `Pack` and `Unpack` traits
- GUID pack/unpack (mixed-endian, as per MS-DTYP)
- FILETIME pack/unpack (100-ns intervals since 1601-01-01)

**Tests:**
- Roundtrip tests for every primitive
- Property tests: `pack(unpack(x)) == x` for all types
- GUID known-value test from spec
- FILETIME known-value tests

**1b. Newtype IDs and flags**
- `SessionId(u64)`, `MessageId(u64)`, `TreeId(u32)`, `CreditCharge(u16)`
- `FileId { persistent: u64, volatile: u64 }` (128-bit, two parts)
- `Command` enum (from spec section 2.2.1.2)
- `NtStatus` enum (from MS-ERREF, top ~100 codes used by SMB)
- `Capabilities`, `SecurityMode`, `ShareFlags`, etc. as bitflag types
- `Dialect` enum: `Smb2_0_2`, `Smb2_1`, `Smb3_0`, `Smb3_0_2`, `Smb3_1_1`

**Tests:**
- Each newtype has a Display impl test
- Each enum has a roundtrip test via num_enum
- Bitflag types have combination tests

**Parallelizable:** 1a and 1b are independent, can run as separate agents.

---

### Phase 2: Wire format messages (the big one)

TDD: for each message type, write a test with known bytes from the spec
(section 2.2 has byte-level field tables), then implement Pack/Unpack.

**2a. Header** (must be first, everything depends on it)
- SMB2 packet header (64 bytes)
- Sync variant: `Reserved(u32)` + `TreeId(u32)`
- Async variant: `AsyncId(u64)`
- `ErrorResponse` with optional error data

**Tests:**
- Parse a known negotiate response header from a Wireshark capture
- Roundtrip test
- Verify magic bytes `0xFE 'S' 'M' 'B'`

**2b. Core messages** (can parallelize across agents, one per message type)

Each message struct needs:
- `impl Unpack` (parse from bytes)
- `impl Pack` (serialize to bytes)
- Unit test with known byte sequence from spec
- Roundtrip property test

**Priority order** (matches the protocol flow):

| Priority | Message | Spec section | Complexity | Notes |
|----------|---------|-------------|------------|-------|
| P0 | Negotiate | 2.2.3/2.2.4 | High | Negotiate contexts make this complex |
| P0 | SessionSetup | 2.2.5/2.2.6 | Medium | Variable-length security buffer |
| P0 | TreeConnect | 2.2.9/2.2.10 | Low | Simple |
| P0 | Create | 2.2.13/2.2.14 | High | Many create contexts |
| P0 | Close | 2.2.15/2.2.16 | Low | Simple |
| P0 | Read | 2.2.19/2.2.20 | Medium | Large data buffer |
| P0 | Write | 2.2.21/2.2.22 | Medium | Large data buffer |
| P1 | Logoff | 2.2.7/2.2.8 | Low | Trivial |
| P1 | TreeDisconnect | 2.2.11/2.2.12 | Low | Trivial |
| P1 | QueryDirectory | 2.2.33/2.2.34 | Medium | File info classes |
| P1 | QueryInfo | 2.2.37/2.2.38 | Medium | Multiple info types |
| P1 | SetInfo | 2.2.39/2.2.40 | Medium | Multiple info types |
| P2 | Flush | 2.2.17/2.2.18 | Low | Simple |
| P2 | Lock | 2.2.26/2.2.27 | Low | Byte-range locks |
| P2 | Echo | 2.2.28/2.2.29 | Low | Trivial |
| P2 | Cancel | 2.2.30 | Low | Request only |
| P1 | Ioctl | 2.2.31/2.2.32 | High | FSCTL_PIPE_TRANSCEIVE needed for share enumeration; other sub-commands can wait |
| P1 | ChangeNotify | 2.2.35/2.2.36 | Medium | Needed for Cmdr live directory updates |
| P2 | OplockBreak | 2.2.23-25 | Medium | Multiple variants |
| P3 | Transform | 2.2.41/2.2.42 | Medium | Encryption/compression wrappers |

**Parallelization strategy:** After 2a (header), agents can work on message types
independently. Group by priority. Each agent gets:
- The relevant spec section (from the markdown spec)
- The corresponding smb-rs code as reference
- The pack/unpack module from Phase 1
- A template showing what a completed message type looks like (first one we do manually becomes the template)

---

### Phase 3: Error types

**3a. NtStatus comprehensive mapping**
- Extend the basic enum from Phase 1b with all SMB-relevant status codes
- `Display` impl with human-readable messages
- `is_error()`, `is_warning()`, `is_info()` helpers (based on severity bits)
- **STATUS_BUFFER_OVERFLOW (0x80000005) is a WARNING, not an error.**
  It's returned with valid partial data in QUERY_INFO, IOCTL, and
  named pipe reads (spec section 3.3.4.4). The response processing
  path must still parse the response body when this status is returned.
  For QUERY_INFO, the client may retry with a larger buffer. The
  pipeline should surface this as a partial result or auto-retry, not
  discard the response data.

**3b. Error enum**
- `Error::Protocol { status: NtStatus, command: Command }` — what the server said
- `Error::Transport(io::Error)` — connection-level failure
- `Error::Auth(String)` — authentication failure
- `Error::InvalidData { message: String }` — malformed response
- `Error::Timeout` — operation timed out
- `Error::Disconnected` — connection lost
- `Error::DfsReferralRequired { path: String }` — server returned
  STATUS_PATH_NOT_COVERED, meaning the path is on a different server
  via DFS. Gives the caller enough info to follow up (or display a
  helpful message). Full DFS follow-through deferred to post-1.0.
- `Error::SessionExpired` — STATUS_NETWORK_SESSION_EXPIRED (internal
  use, pipeline handles transparently via reauthentication; surfaced
  only if reauthentication fails)
- `is_retryable()`, `status()` helpers

**Tests:**
- NtStatus severity classification tests
- Error display format tests

---

### Phase 4: Transport + mock

**4a. Transport trait — split read/write**

The pipeline's `tokio::select!` loop needs to send requests while
simultaneously awaiting responses. A single `&self` trait with one
mutex over a TcpStream would deadlock (send blocks on mutex held by
receive). Solution: split into separate send/receive traits or use
split halves internally.

```rust
#[async_trait]
pub trait TransportSend: Send + Sync {
    async fn send(&self, data: &[u8]) -> Result<(), Error>;
}

#[async_trait]
pub trait TransportReceive: Send + Sync {
    /// Receive one complete SMB2 transport frame.
    /// The implementation handles length-prefix framing.
    /// The returned buffer may contain multiple compounded responses
    /// (linked by NextCommand) — the caller must split them.
    async fn receive(&self) -> Result<Vec<u8>, Error>;
}

pub trait Transport: TransportSend + TransportReceive {}
```

TCP implementation uses `tokio::io::split()` or `Arc<Mutex<ReadHalf>>`
+ `Arc<Mutex<WriteHalf>>` so send and receive never contend.

**4b. TCP transport** (Direct TCP, port 445)
- **TCP framing** (spec section 2.1): The header is NOT a simple u32.
  It is 1 byte that MUST be 0x00, followed by 3 bytes of length in
  big-endian (network byte order). This is important because SMB
  messages are generally little-endian — the transport framing is the
  exception. Validate the first byte is 0x00 on receive.
- **Partial reads:** TCP is a stream protocol. Under load (the exact
  scenario pipelining creates), a single `read()` commonly returns
  fewer bytes than requested. The `receive()` implementation MUST use
  `AsyncReadExt::read_exact()` (which loops internally) for both the
  4-byte header and the payload. Never assume a single read returns a
  complete frame.
- **Maximum frame size check:** After reading the 3-byte length, validate
  it against a sane ceiling (for example, 16 MB) before allocating the buffer.
  This prevents denial-of-service from corrupt length fields or
  malicious servers.
- Split into independent read/write halves (no deadlock in select!)
- Connect, send, receive, close
- Timeout handling

**4c. Mock transport**
- Queue of canned responses
- Records sent messages for assertions
- Supports scripted multi-step conversations (negotiate -> session -> tree -> ...)

**Tests:**
- Mock transport: queue response, send request, verify received
- TCP transport: integration test against Docker Samba (ignored by default)
- Framing: test 0x00 + 3-byte big-endian length encoding/decoding
- Framing: reject frame where first byte is not 0x00
- Framing: reject frame with length exceeding max (16 MB ceiling)
- Framing: partial TCP reads (simulate with mock stream that delivers
  one byte at a time) → still assembles correctly

---

### Phase 5: Crypto

**5a. Signing** — three distinct code paths:
- HMAC-SHA256 truncated to 16 bytes (SMB 2.0.2, 2.1)
- AES-128-CMAC (SMB 3.0, 3.0.2)
- AES-256-GMAC (SMB 3.1.1, when negotiated via SMB2_SIGNING_CAPABILITIES)
  — uses a **12-byte nonce** built from the MessageId (spec section
  3.1.4.1): first 8 bytes = MessageId (little-endian), next 4 bytes
  have bit 0 = 0 (client), bit 1 = 1 if CANCEL request, remaining
  30 bits = 0. This is NOT the same as the encryption nonce (which is
  a counter). The CANCEL bit must be set correctly or the server
  rejects the signature.
- **Signing/encryption are mutually exclusive per-message** (spec
  section 3.2.4.1.1): When encrypting, zero the Signature field in the
  SMB2 header — AEAD provides authentication instead. On receive: if
  decryption succeeds (AEAD validated), skip signature verification
  (spec section 3.2.5.1.3). The send path order is: build message →
  if not encrypting, sign it; if encrypting, zero signature → encrypt.
  Receive path: if encrypted, decrypt (AEAD handles auth) → skip
  signature check; if not encrypted, verify signature.

**5b. Encryption**
- AES-128-CCM (SMB 3.0+)
- AES-128-GCM (SMB 3.0+)
- AES-256-CCM (SMB 3.1.1)
- AES-256-GCM (SMB 3.1.1)
- **Nonce management:** The TRANSFORM_HEADER nonce MUST NOT be reused
  within a session (spec section 2.2.41). Use a monotonically increasing
  per-session counter (u64), not random nonces. AES-GCM is
  catastrophically broken by nonce reuse (attacker recovers auth key).
  For AES-CCM: 8-byte counter + 3 zero bytes (11-byte nonce). For
  AES-GCM: 8-byte counter + 4 zero bytes (12-byte nonce). Reset
  counter on session re-key (new key = safe to restart counter).

**5c. Key derivation**
- SP800-108 KDF in counter mode
- Session key -> signing key, encryption key, decryption key
- **Preauthentication integrity hash (SMB 3.1.1, CRITICAL):**
  SMB 3.1.1 binds the negotiate and session-setup exchanges together
  cryptographically. Without this, key derivation produces WRONG keys
  and the first signed/encrypted message fails. Modern servers (Windows
  Server 2016+, recent Samba) default to 3.1.1.

  Implementation (spec sections 3.2.5.2, 3.2.5.3.1):
  1. Initialize `Connection.PreauthIntegrityHashValue` = 64 zero bytes
  2. Hash(zeros || raw_negotiate_request_bytes) → hash1
  3. Hash(hash1 || raw_negotiate_response_bytes) → hash2 =
     Connection.PreauthIntegrityHashValue
  4. For session setup: Session.PreauthIntegrityHashValue starts from
     Connection.PreauthIntegrityHashValue
  5. Hash(session_hash || raw_session_setup_request_bytes) → updated
  6. Hash(updated || raw_session_setup_response_bytes) → updated
  7. Repeat steps 5-6 for each SESSION_SETUP round-trip
  8. Feed final Session.PreauthIntegrityHashValue into KDF as context
     when deriving SigningKey, EncryptionKey, DecryptionKey

  This requires capturing RAW bytes of NEGOTIATE and SESSION_SETUP
  messages before parsing — the hash is over the wire bytes, not
  reconstructed from parsed structs. The hash algorithm is negotiated
  in the PREAUTH_INTEGRITY_CAPABILITIES negotiate context (currently
  only SHA-512 is defined).

**Tests:**
- Known-answer tests from spec appendix or from Wireshark captures
- Roundtrip: encrypt then decrypt
- Verify signature, then tamper, verify rejection

**5d. Compression**
- LZ4 via `lz4_flex` (pure Rust, zero deps)
- Negotiate compression support in NEGOTIATE contexts
  (SMB2_COMPRESSION_CAPABILITIES)
- Compress outgoing messages in COMPRESSION_TRANSFORM_HEADER
- Decompress incoming messages before processing
- Only unchained compression (chained is rarely used, defer)

**Tests:**
- Roundtrip: compress then decompress
- Negotiate compression capability, verify it's used
- Large message compression reduces wire size

**Dependencies added:** `hmac`, `sha2`, `aes`, `aes-gcm`, `ccm`, `cmac`, `lz4_flex`

---

### Phase 6: Authentication

**6a. NTLM** (from MS-NLMP)
- NtlmNegotiate message
- NtlmChallenge message parsing
- NtlmAuthenticate message construction
- NTLMv2 hash computation
- Session key derivation
- **MIC (Message Integrity Code):** Modern servers (Windows Server
  2008+, recent Samba) include MsvAvTimestamp in the challenge
  TargetInfo, which triggers MIC validation. The client MUST:
  (1) check for MsvAvTimestamp in the challenge TargetInfo,
  (2) if present, set MsvAvFlags to 0x00000002 in the authenticate
  message's TargetInfo,
  (3) compute MIC = HMAC_MD5(ExportedSessionKey, concatenation of
  raw bytes of NEGOTIATE || CHALLENGE || AUTHENTICATE messages),
  (4) write it into the 16-byte MIC field at offset 72 of the
  AUTHENTICATE_MESSAGE.
  Without MIC, authentication fails against modern servers. The
  implementation must retain raw bytes of NEGOTIATE and CHALLENGE
  messages for MIC computation (similar to the preauth hash
  requirement — raw bytes matter, not parsed structs).

**Tests:**
- Known-answer tests from MS-NLMP appendix (it has test vectors!)
- Full NTLM exchange against mock transport
- MIC computation test with known values
- Test against server with MsvAvTimestamp (the common case)

**Note:** Kerberos deferred to a later phase. NTLM gets us connected to
any Samba server and most Windows servers.

---

### Phase 7: Client protocol logic

This is where the state machines from spec section 3.2 come together.
TDD with mock transport: script the expected byte exchanges.

**7a. Connection + credit engine**
- Establish TCP connection
- Send Negotiate, process response
- **Dialect validation:** Verify that `DialectRevision` in the response
  matches one of the dialects the client offered. If not, disconnect
  immediately — this prevents man-in-the-middle dialect downgrade
  attacks (spec section 3.2.5.2).
- **DialectRevision 0x02FF handling:** Older servers may respond with
  the wildcard dialect 0x02FF (spec section 3.2.4.2.1), meaning "I
  support SMB2 but you need to send a proper SMB2 NEGOTIATE." If
  received, issue a second NEGOTIATE with MessageId=1 and the actual
  desired dialects. Alternatively, fail fast with a clear error if we
  decide not to support pre-Windows 8 servers. Either way, don't leave
  0x02FF unhandled.
- Store negotiated dialect, capabilities, server GUID, **MaxReadSize,
  MaxWriteSize, MaxTransactSize**
- **Store raw NEGOTIATE request/response bytes** for preauthentication
  integrity hashing (required for SMB 3.1.1, see Phase 7b).
- Validate MaxReadSize/MaxWriteSize/MaxTransactSize >= 65536, disconnect
  if below (spec section 3.2.5.2 SHOULD)
- Credit management (request/grant tracking) — this is the foundation
  for pipelining, so it needs to be right from day one
- **Interim response handling:** When the server processes a request
  asynchronously, it sends a STATUS_PENDING interim response that
  carries credits in CreditResponse. The final async response has
  CreditResponse=0 (spec section 3.3.4.3). The credit engine MUST
  extract credits from interim responses. Do NOT remove the request
  from in_flight on an interim response — store the AsyncId and keep
  waiting for the final response.
- **Credit request strategy:** On each request, set CreditRequest to
  `max(credits_consumed, desired_window_size)` to grow the credit pool
  toward our target pipeline depth. Without this, we may never get
  enough credits for effective pipelining.
- **Credit starvation timeout:** If the server grants zero credits for
  a configurable period (default: 30s), fail pending operations with
  a timeout error. Send ECHO requests periodically as keepalive that
  also replenishes credits.
- Message ID sequencing — see SequenceWindow below
- **Message multiplexer (connection-level, not per-pipeline):** The
  spec supports multiple tree connects on one connection. If a user
  opens two shares, each gets its own pipeline, but they share one TCP
  connection. There must be a single receive task per connection that
  demultiplexes responses by MessageId to the correct pipeline. Options:
  (a) connection-level driver task dispatches responses to per-share
  pipeline channels, or (b) shared `in_flight` map at the connection
  level with per-request oneshot channels. The key constraint: only ONE
  task can call `receive()` on the transport — multiple pipelines
  cannot race on the same socket.
- **Connection health:** Send ECHO keepalives every N seconds (default:
  60s). If no response within timeout, consider connection dead and
  fail all pending operations.
- **Per-request timeouts:** Each in-flight request has a deadline. On
  timeout, send CANCEL for the request, remove from in_flight, report
  error, reclaim credits. **CANCEL has two modes** (spec section
  3.2.4.24): (1) before an interim response, use the original
  MessageId; (2) after STATUS_PENDING has been received (AsyncId is
  stored on the PendingOp), set `SMB2_FLAGS_ASYNC_COMMAND` in the
  header and use the AsyncId. The MessageId in the CANCEL header must
  match the original request in both cases.

**SequenceWindow and consecutive MessageId allocation:**
Multi-credit requests (SMB 2.1+) MUST use N consecutive MessageIds
starting from the first one (spec section 3.2.4.1.5). The server
validates the entire range falls within its CommandSequenceWindow. If
the client's window has gaps (for example, IDs 5,6 are available but 7 is
in-flight, then 8,9 are available), a request needing 4 consecutive IDs
cannot use {5,6,8,9} — it must wait for a contiguous range.

Implementation: use a sorted set or bitmap of available MessageIds.
`allocate(n: u16) -> Option<MessageId>` finds the first contiguous
range of N IDs, or returns None (caller must wait/queue). This is more
complex than a simple counter but required for correctness — the server
SHOULD terminate the connection if non-consecutive IDs are used (spec
section 3.3.5.2.3).

**7b. Session**
- SESSION_SETUP exchange (NTLM auth)
- Session key establishment
- Signing activation
- Encryption activation (if negotiated)
- **Session reauthentication:** When the server returns
  STATUS_NETWORK_SESSION_EXPIRED (spec section 3.2.5.1.6), the client
  MUST transparently reauthenticate and retry the failed request. The
  pipeline driver must: (1) pause dispatching new requests, (2) perform
  SESSION_SETUP with the same SessionId — set Flags to 0 (NOT
  `SMB2_SESSION_FLAG_BINDING`, that's for multi-channel binding on a
  *different* connection), set PreviousSessionId to 0 (spec section
  3.2.4.2.3.1), (3) **preserve existing Session.SessionKey and all
  derived signing/encryption keys** — the spec (section 3.2.5.3.2)
  explicitly says "The client MUST NOT regenerate Session.SessionKey",
  (4) the SESSION_SETUP is multi-round-trip (NTLM challenge/response),
  so loop: send SESSION_SETUP, if STATUS_MORE_PROCESSING_REQUIRED
  process the GSS token and send another, repeat until STATUS_SUCCESS
  or error, (5) for SMB 3.1.1, update Session.PreauthIntegrityHashValue
  for each SESSION_SETUP round-trip during reauth (spec section 3.2.5.3
  applies hash updates to all session setup exchanges), (6) retry the
  failed request, (7) resume normal dispatch. If reauthentication fails,
  fail all pending operations and tear down. This is critical for
  long-running transfers in Cmdr — sessions can expire after a
  server-configured timeout.

**7c. Tree connect**
- TREE_CONNECT to a share path — the Buffer must contain the full
  UNC path in UTF-16LE: `\\server\share` (spec section 3.2.4.2.4).
  The `connect_share("Documents")` API should internally construct
  `\\{Connection.ServerName}\Documents` and encode as UTF-16LE.
  Sending just the bare share name produces STATUS_BAD_NETWORK_NAME.
- Store tree ID, share capabilities, `IsDfsShare` (from
  `SMB2_SHAREFLAG_DFS` in response), `EncryptData` (from
  `SMB2_SHAREFLAG_ENCRYPT_DATA`)

**7d. Unified operation pipeline** (core feature, not an optimization)

This is the reason this library exists. Benchmarks show that without
pipelining, even with 1MB chunks, large downloads are 10x slower than
native macOS SMB. The `smb` crate sends one read, waits for the
response, then sends the next — leaving the TCP pipe idle most of
the time.

**Design: channel-based pipeline for all operation types.**

The caller pushes requests into one end, results stream out the other.
No need to know the total count upfront — keep feeding requests as they
arise (user scrolls, opens folders, selects files to copy). One unified
pipeline handles reads, writes, deletes, stats, and directory listings.

```rust
// Open a pipeline on a share
let (tx, rx) = share.open_pipeline();

// Producer side — keep feeding, from anywhere, any time
tx.request(Op::ReadFile("a.txt")).await;
tx.request(Op::WriteFile("b.txt", data)).await;
tx.request(Op::Delete("c.txt")).await;
tx.request(Op::List("projects/")).await;
tx.request(Op::Stat("d.txt")).await;

// ...later, user selects more files...
tx.request(Op::ReadFile("e.txt")).await;

// Consumer side — results stream back as they complete
while let Some(result) = rx.next().await {
    match result {
        OpResult::FileData(path, bytes) => ...,
        OpResult::Written(path, bytes_written) => ...,
        OpResult::Deleted(path) => ...,
        OpResult::DirEntries(path, entries) => ...,
        OpResult::Stat(path, info) => ...,
        OpResult::Error(path, err) => ...,
    }
}

// Drop tx to signal "no more requests" — pipeline drains gracefully
```

The simple one-shot API wraps this internally:
```rust
// Convenience — opens pipeline, pushes one request, collects result
let data = share.read_file("report.pdf").await?;
```

**How the pipeline works internally:**

The server tells us everything we need during NEGOTIATE:
- `MaxReadSize` / `MaxWriteSize`: typically 1–8 MB (use this, not 64KB)
- Credits granted: how many outstanding requests we can have

**CreditCharge calculation** (spec section 3.2.4.1.5, SMB 2.1+):
- Formula: `(max(SendPayloadSize, ExpectedResponsePayloadSize) - 1) / 65536 + 1`
- READ: use MaxReadSize for expected response → `ceil(read_size / 64KB)`
- WRITE: use write data size for send payload → `ceil(write_size / 64KB)`
- QUERY_DIRECTORY: use MaxTransactSize (not MaxReadSize!) for expected
  response → `ceil(MaxTransactSize / 64KB)`
- QUERY_INFO, SET_INFO, CHANGE_NOTIFY: also use MaxTransactSize
- IOCTL: use max of input/output buffer sizes
- All other commands (CREATE, CLOSE, LOGOFF, etc.): CreditCharge = 1
- Zero-byte reads: handle explicitly, use CreditCharge = 1. The formula
  `(0 - 1) / 65536 + 1` would underflow in unsigned arithmetic.
- **CANCEL is special:** does NOT consume a credit or allocate a new
  MessageId. It reuses the MessageId of the request being canceled
  (spec section 3.2.4.24). Must be special-cased in credit/sequencing.

Example: 128 credits, 1MB reads = 16 credits each = 8 concurrent reads.

**Path normalization:**
All file paths in Op requests are normalized before going on the wire:
(1) convert `/` to `\` (SMB uses backslash, spec section 2.2.13),
(2) strip leading `\` (paths are relative to tree connect root),
(3) collapse `\\` sequences, (4) reject illegal characters (`:`, `*`,
`?`, `"`, `<`, `>`, `|`). Encode the normalized path as UTF-16LE into
the CREATE request Buffer. The API accepts forward slashes for
convenience (natural for Rust callers on Unix) but converts internally.

The pipeline loop:
1. Drain incoming requests from `tx` channel
2. For each request, normalize the path, then expand into SMB operations:
   - `ReadFile("a.txt")` for small files → compound(CREATE + READ + CLOSE)
   - `ReadFile("big.iso")` for large files → CREATE, then N × READ
     (chunked at MaxReadSize), then CLOSE
   - `Delete("c.txt")` → compound(CREATE with DELETE_ON_CLOSE + CLOSE)
   - `List("dir/")` → CREATE (open dir handle), then N × QUERY_DIRECTORY
     (loop until STATUS_NO_MORE_FILES, streaming batches to `rx`), then
     CLOSE. **Cannot** compound CREATE+QUERY_DIRECTORY+CLOSE because
     pagination requires keeping the handle open across multiple requests.
3. Send as many operations as credits allow (fill the window)
4. As each response arrives:
   - **First: split compound responses.** A single transport frame may
     contain multiple SMB2 responses linked by NextCommand in the header.
     Split them into individual responses before processing. (Spec
     section 3.2.5.1.9.) Never assume responses mirror the request
     structure — unrelated compound responses may arrive as individual
     messages (spec section 3.2.4.1.4).
   - Match to request by MessageId
   - **Check for unsolicited messages:** MessageId 0xFFFFFFFFFFFFFFFF
     is an oplock/lease break notification. To send a valid ack, we need
     the correct SessionId and TreeId for the file handle (spec section
     3.2.5.19.1). Maintain an `OpenTable: FileId → (SessionId, TreeId)`
     mapping, populated on CREATE response and removed on CLOSE. Look up
     the FileId from the break notification to construct the ack. If the
     client doesn't want caching, ack with `SMB2_OPLOCK_LEVEL_NONE`
     (spec allows downgrading). For lease breaks (SMB 2.1+), the break
     arrives with SessionId=0 and TreeId=0 — look up by LeaseKey instead.
   - **Check for STATUS_PENDING:** Extract credits, store AsyncId, keep
     waiting for the final response. Do NOT remove from in_flight.
   - Replenish credits from response
   - For large-file reads: buffer chunks, deliver in order (reorder buffer)
   - For directory listings: deliver each QUERY_DIRECTORY batch as a
     `DirEntryBatch` result, queue the next QUERY_DIRECTORY if not
     STATUS_NO_MORE_FILES
   - For completed operations: send result to `rx`
   - Send the next queued operation (slide the window forward)

**Compounding** (spec section 3.2.4.1.4):
- Chain related requests in one message (CREATE+READ+CLOSE)
- `NextCommand` offset in header links chained requests
- Server processes them in order, returns compounded response
- Related compounds: subsequent requests use sentinel FileId
  `{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}` meaning "use the FileId
  from the previous response" (spec section 2.2.13)
- Batch size is limited by BOTH credit budget AND total wire size.
  Each compound group (CREATE+READ+CLOSE) has header overhead (~200
  bytes per sub-request), so realistic limit is ~20-40 compound groups
  per transport send, not 128.

**Compound NextCommand offset calculation** (spec section 2.2.1):
NextCommand is the offset from the beginning of the CURRENT SMB2
header to the beginning of the NEXT SMB2 header. Calculation:
`NextCommand = header_size(64) + body_size + padding_to_8_byte_boundary`.
The last sub-request in the chain sets NextCommand = 0. Body size
varies per command (CREATE has variable-length filename and create
contexts, each with their own padding). Off-by-one errors here cause
the server to reject the entire compound with STATUS_INVALID_PARAMETER.
Use `WriteCursor.align_to(8)` from Phase 1a, then backpatch the
NextCommand field with `set_u32_le_at()`.

On receive: validate that `current_offset + NextCommand` is 8-byte
aligned and within buffer bounds. If not, disconnect (spec section
3.2.5.1.3: "If each response in the compounded chain, except the
first one, does not start at an 8-byte aligned boundary, the client
MUST disconnect the connection"). Add specific test cases for
variable-length compound messages (CREATE with a long filename
followed by READ).

**Compound + encryption interaction** (spec section 3.1.4.3):
Encryption wraps the ENTIRE compound chain in one TRANSFORM_HEADER,
not individual sub-requests. The correct send path order is:
1. Build each sub-request
2. Pad each (except last) to 8-byte alignment
3. Set NextCommand offsets
4. **Sign each sub-request individually** (including padding bytes!)
   — or if encrypting, zero all Signature fields instead
5. Concatenate into one compound blob
6. Compress (optional, if negotiated)
7. Wrap in TRANSFORM_HEADER and encrypt the whole blob

On receive:
1. Decrypt the entire blob (AEAD validates authenticity)
2. Decompress if compressed
3. Split compound responses by NextCommand
4. Process each response individually (skip signature verification
   since AEAD already authenticated)

This ordering is critical. Encrypting individual sub-requests or
splitting before decrypting will cause protocol failures.

**Compound partial failure handling:**
When a compound related request fails (for example, CREATE fails with
STATUS_OBJECT_NAME_NOT_FOUND), the server cascades the error to all
subsequent operations in the compound (spec section 3.3.5.2.7.2).
The pipeline must:
- Track compound groups as single logical units, not individual ops
- Report one error per compound, not one per sub-operation
- If CREATE succeeds but READ fails (for example, STATUS_INSUFFICIENT_RESOURCES),
  CLOSE will also fail in the compound. The client MUST then issue a
  separate standalone CLOSE to clean up the leaked file handle. This
  cleanup CLOSE cannot be part of the failed compound.

**Large file chunking within the pipeline:**
- Large reads/writes are split into MaxReadSize/MaxWriteSize chunks
- These chunks compete for credit window space alongside other operations
- Reorder buffer (`BTreeMap<offset, Bytes>`) reassembles chunks for
  streaming delivery to the caller
- **Concurrency limit for large transfers:** Limit the number of
  simultaneously active large-file transfers (default: 4-8). When more
  are requested, queue them internally and start when a current transfer
  completes. Without this, 500 concurrent large-file reads (user drags
  a folder in Cmdr) would create 500 reorder buffers, each potentially
  holding several MB of out-of-order data. Total memory:
  `active_transfers * MaxReadSize * pipeline_depth`. With a limit of 8
  and 1MB reads and 8-deep pipeline, worst case is ~64 MB — manageable.
- **File size changes during read:** The file can change between CREATE
  and subsequent READs. A READ beyond EOF returns STATUS_END_OF_FILE.
  Treat this as "last chunk" — deliver what was received and report
  FileComplete with the actual bytes read. The reorder buffer must
  handle the expected chunk count changing mid-transfer.
- **Compound READ size limits:** When READ is part of a compound, the
  total compound response size is limited by the transport. Use
  `min(MaxReadSize, transport_max - overhead)` for the READ size in
  compounds, not just MaxReadSize.

**What we don't need to guess:**
| Parameter | Source | Guessing? |
|-----------|--------|-----------|
| Chunk size | `MaxReadSize` / `MaxWriteSize` from NEGOTIATE response | No — spec says MUST NOT exceed this |
| Max concurrent requests | Credits granted by server in each response | No |
| When to back off | `STATUS_INSUFFICIENT_RESOURCES` or reduced credit grants | No |

**Server-specific chunk size adaptation:**
The server declares its limits during NEGOTIATE. A Raspberry Pi running
Samba might advertise MaxReadSize=65536 (64KB), while a QNAP NAS might
advertise MaxReadSize=8388608 (8MB). We MUST respect this — the spec
says "the client MUST split the read into separate read operations no
larger than Connection.MaxReadSize." Sending a 1MB read to a server
that advertised 64KB may cause it to drop the connection (observed on
Pi hardware). This is a protocol compliance issue, not a performance
tuning knob.

We always use exactly the server's advertised MaxReadSize as our chunk
size. No configuration needed, no guessing, no hardcoded defaults. The
protocol handles it.

**Error handling in the pipeline:**
- If one operation fails: report error for that operation via `rx`,
  continue processing other operations (don't stop the whole pipeline)
- If a large-file read fails mid-stream: mark the transfer as canceled
  but keep processing arriving responses for that transfer (discard
  data, free credits). Don't rely on CANCEL preventing responses —
  it's best-effort. Bound the reorder buffer size to prevent memory
  leaks from chunks that arrive for canceled transfers.
- If the server grants fewer credits: shrink the window dynamically
- If `tx` is dropped: stop accepting new requests, drain in-flight
  operations, **close any open file handles** held by in-progress
  chunked transfers or directory listings (issue standalone CLOSE for
  each), then close `rx` when done. Without this, file handles leak
  on the server until session timeout, potentially blocking other
  clients.
- **Graceful shutdown sequence** (spec sections 3.2.4.22, 3.2.4.23):
  The caller (`SmbClient` or `Tree`) is responsible for issuing
  TREE_DISCONNECT and LOGOFF after the pipeline drains. `SmbClient`'s
  `Drop` impl should issue LOGOFF best-effort (with a short timeout).
  Correct order: close files → tree disconnect → logoff → close
  transport.
- If `rx` is dropped (consumer gone): abort the driver. Use `try_send`
  on the results channel — if it fails (channel closed), stop the
  pipeline. Otherwise the driver becomes an orphan task leaking memory.
- If the connection drops unexpectedly: iterate over ALL remaining
  in-flight requests and report errors for each one via `rx` before
  exiting. Don't let the `rx` stream just end silently.

**Backpressure:**
The results channel (`rx`) should be bounded. If the caller stops
consuming results, the driver must not block on `results.send()` — use
`try_send` and if the channel is full, pause accepting new work from
`tx` (don't pause processing responses though, since that replenishes
credits and prevents protocol-level stalls).

**Implementation shape:**
```rust
// client/pipeline.rs (~400-600 lines)
// tx is tokio::mpsc::Sender<Op> which is Clone + Send.
// Multiple tasks can push operations concurrently by cloning tx.
// Each Op is an atomic unit — the driver expands it internally
// (single consumer on the channel, so no locking needed in enqueue).
pub struct Pipeline {
    tx: mpsc::Sender<Op>,
    rx: mpsc::Receiver<OpResult>,
}

// Internal driver — runs as a spawned task
struct PipelineDriver {
    conn: Arc<Connection>,
    requests: mpsc::Receiver<Op>,
    results: mpsc::Sender<OpResult>,
    credit_window: CreditWindow,
    in_flight: HashMap<MessageId, PendingOp>,
    // For large-file reassembly
    chunked_transfers: HashMap<FileId, ChunkedTransfer>,
}

impl PipelineDriver {
    async fn run(mut self) {
        loop {
            // Use `biased` to prioritize responses over new requests.
            // Responses replenish credits — starving them causes the
            // pipeline to stall. New requests can always wait one tick.
            tokio::select! {
                biased;

                // Response from server — always process first
                result = self.conn.receive() => {
                    match result {
                        Ok(frame) => {
                            // Split compound responses by NextCommand,
                            // then handle each individually.
                            for response in split_compound(frame) {
                                self.handle_response(response).await;
                            }
                            self.fill_window().await;
                        }
                        Err(e) => {
                            // Connection lost: report errors for ALL
                            // in-flight requests, then exit.
                            self.fail_all_in_flight(e).await;
                            break;
                        }
                    }
                }

                // New request from caller
                Some(op) = self.requests.recv() => {
                    self.enqueue(op);
                    self.fill_window().await;
                }

                // Both channels closed — done
                else => break,
            }
        }
    }
}
```

**Tests:**
- Mock: 5 pipelined reads, responses in order → results in order
- Mock: 5 pipelined reads, responses reversed → results still correct
- Mock: mixed ops (read + delete + list) → each result delivered correctly
- Mock: large file chunked across 5 reads → stream delivers in order
- Mock: operation #3 fails → error for that op, others continue
- Mock: server grants only 2 credits → window stays at 2
- Mock: server reduces credits mid-stream → window shrinks
- Mock: tx dropped mid-stream → pipeline drains and closes
- Mock: 100 small file reads → compounded into minimal round-trips
- Mock: request timeout → error reported, credits reclaimed
- Mock: ECHO keepalive sent after idle period
- Mock: connection drops mid-pipeline → all in-flight ops get errors
- Mock: STATUS_PENDING interim response → credits extracted, final
  response handled correctly
- Mock: rx dropped → driver detects and stops
- Mock: compound CREATE+READ+CLOSE where READ fails → standalone CLOSE
  issued to clean up handle
- Mock: multi-credit request waits for consecutive MessageId range
- Mock: CANCEL reuses original MessageId, doesn't consume credit
- Mock: oplock break notification (MessageId 0xFFFF...) → acknowledged
- Mock: directory with 1000 files → multiple QUERY_DIRECTORY pages,
  each delivered as DirEntryBatch, handle kept open until done
- Mock: zero-byte file read → handled without underflow
- Mock: file shrinks during read → STATUS_END_OF_FILE on chunk treated
  as last chunk, partial data delivered
- Mock: unrelated compound responses arrive as separate transport
  frames (not mirroring request compound structure) → handled correctly
- Mock: STATUS_NETWORK_SESSION_EXPIRED → pipeline pauses, reauthenticates,
  retries failed request, resumes
- Mock: session reauthentication fails → all pending ops get errors
- Mock: encryption nonce increments monotonically, never repeats
- Mock: encrypted compound → one TRANSFORM_HEADER wraps entire chain,
  signatures zeroed inside
- Mock: compound signing includes 8-byte alignment padding in hash
- Mock: DialectRevision 0x02FF → either second negotiate or clear error
- Mock: dialect downgrade (server picks dialect we didn't offer) → disconnect
- Mock: partial TCP frame delivery → receive still assembles correctly
- Mock: preauthentication integrity hash feeds into key derivation
  for SMB 3.1.1 → signing/encryption work after session setup
- Mock: 50 concurrent large-file reads → only 8 active, rest queued
- Mock: CANCEL after STATUS_PENDING → uses AsyncId + async flag
- Mock: tx dropped with open chunked transfers → CLOSE issued for
  each open handle before pipeline exits
- Mock: STATUS_PATH_NOT_COVERED → DfsReferralRequired error with path
- Mock: reauthentication preserves existing session keys (does NOT
  re-derive), multi-round-trip (challenge/response loop)
- Mock: NTLM MIC computed correctly when MsvAvTimestamp present in
  challenge TargetInfo
- Mock: oplock break ack uses correct SessionId/TreeId from OpenTable
- Mock: TREE_CONNECT sends UNC path `\\server\share` in UTF-16LE,
  not bare share name
- Mock: forward-slash paths normalized to backslash before wire
- Mock: illegal path characters rejected
- Mock: AES-GMAC signing nonce built from MessageId (not counter),
  CANCEL bit set correctly
- Mock: STATUS_BUFFER_OVERFLOW response body is parsed (not discarded)
- Mock: compound NextCommand offsets are 8-byte aligned, last is 0
- Mock: compound response with misaligned NextCommand → disconnect
- Mock: two pipelines on two shares on one connection → responses
  routed to correct pipeline by MessageId
- Property test: random response ordering always produces correct output

**7e. Progress reporting and streaming results**

All operations report progress through the `rx` stream as they happen:

- **Large file transfers:** Each chunk completion is a progress event.
  With 8 × 1MB in flight, Cmdr gets an update every ~1MB.
- **Small file batches:** Each completed file is a result on `rx`.
  "Copied 47 of 256 files" falls out naturally.
- **Directory listings:** Streamed incrementally as batches arrive.
  QUERY_DIRECTORY returns paginated responses (server fills up to
  MaxTransactSize per response, then client sends follow-ups until
  STATUS_NO_MORE_FILES). Each page is surfaced immediately:

```rust
OpResult::DirEntryBatch {
    path: "photos/",
    entries: vec![...],  // ~200 entries per batch
    is_last: false,      // more pages coming
}
```

- **Multiple concurrent listings:** 10 × `Op::List` in the pipeline
  produces interleaved batches, each tagged with its path. The pipeline
  tracks which directories still need follow-up QUERY_DIRECTORY requests
  and interleaves them with all other operations in the credit window.

**7f. Convenience file operations** (wrap the pipeline)
- `read_file(path)` -> bytes
- `write_file(path, data)` -> bytes_written
- `delete(path)`
- `stat(path)` -> FileInfo (timestamps, size, attributes)
- `rename(from, to)` -> () (SET_INFO with FileRenameInformation)
- `set_timestamps(path, created, modified, accessed)` -> ()
- `truncate(path, size)` -> () (SET_INFO with FileEndOfFileInformation)
- `flush(path)` -> ()
- `fs_info()` -> FsInfo (total space, free space, sector size)
- `server_copy(src, dst)` -> () (FSCTL_SRV_COPYCHUNK, same-share only)

**Client-level configuration** (`ClientConfig`):
- `min_dialect` / `max_dialect`: restrict negotiated SMB version range
- `signing`: Required, Allowed, or Disabled
- `encryption`: Required, Allowed, or Disabled
- `allow_unsigned_guest_access`: skip signing for guest/anonymous
  (required for many Samba NAS setups)
- `connect_timeout`, `request_timeout`: configurable timeouts
- `auto_reconnect`: enable automatic reconnection on network failure
  (default: true, see Phase 7i)

**7g. Directory operations** (also wrap the pipeline)
- `list(path, pattern)` -> stream of directory entries (paginated)
- `create_directory(path)`
- `watch(path, recursive)` -> stream of change notifications
  (CHANGE_NOTIFY, important for Cmdr's live directory updates)

**7h. Share enumeration** (required for Cmdr)

Cmdr uses SMB for two things: server discovery (mDNS, not our concern)
and share enumeration (listing shares on a known server). The `smb`
crate provides `list_shares()` which internally does IPC$ + srvsvc RPC.
We need to replicate this.

**How it works:**
1. TREE_CONNECT to `IPC$` (the inter-process communication share)
2. CREATE on `\pipe\srvsvc` (open the Server Service named pipe)
3. IOCTL with `FSCTL_PIPE_TRANSCEIVE` — send an NDR-encoded
   `NetShareEnumAll` RPC request, receive NDR-encoded response
4. Parse the response into a list of `ShareInfo` (name, type, comment)
5. CLOSE the pipe handle
6. TREE_DISCONNECT from `IPC$`

**What we need to build:**
- `rpc/mod.rs`: RPC PDU types (bind, bind_ack, request, response),
  NDR base encoding/decoding (~200 lines)
- `rpc/srvsvc.rs`: `NetShareEnumAll` request/response NDR encoding,
  `ShareInfo1` struct (name, type, comment) (~150 lines)
- `client/shares.rs`: High-level `client.list_shares()` method that
  orchestrates the IPC$ flow above (~100 lines)

**Share filtering** (matching Cmdr's current behavior):
- Only return disk shares (type 0x00000000 = STYPE_DISKTREE)
- Skip IPC$ shares, printer shares, and admin shares ending with `$`
- Return share name and comment

**High-level API:**
```rust
let client = SmbClient::connect("192.168.1.100", "user", "pass").await?;

// List shares (connects to IPC$, does RPC, disconnects)
let shares = client.list_shares().await?;
for share in &shares {
    println!("{}: {}", share.name, share.comment);
}

// Then connect to a specific share
let share = client.connect_share(&shares[0].name).await?;
```

**Auth flow** (matching Cmdr's current pattern):
- Try guest access first (empty password)
- If `STATUS_ACCESS_DENIED`, try provided credentials
- Return specific error if auth is required

**Tests:**
- Mock: IPC$ → srvsvc → NetShareEnumAll round-trip
- Mock: guest access succeeds → shares returned
- Mock: guest access denied → retry with credentials → shares returned
- Mock: admin shares ($) filtered out
- Mock: NDR encoding/decoding roundtrip for ShareInfo1
- Integration: list shares on Docker Samba (ignored by default)

**7i. Reconnection and durable handles**

Cmdr runs on laptops. Wi-Fi drops, sleep/wake cycles, and network
switches are routine. The library must handle these gracefully.

**Three levels of reconnection support:**

1. **`client.reconnect()`** — explicit manual reconnection. Re-does
   NEGOTIATE + SESSION_SETUP + TREE_CONNECT for all previously
   connected shares. All previous file handles are invalidated
   (server-side state is gone). Caller must re-open files.

2. **Auto-reconnect** — when a connection drop is detected (transport
   error, ECHO timeout), automatically attempt reconnection with
   configurable backoff (default: 1s, 2s, 4s, 8s, max 30s). Enabled
   by `ClientConfig::auto_reconnect` (default: true). During
   reconnection, new pipeline ops queue up. Once reconnected, queued
   ops proceed. In-flight ops at the time of disconnect get errors.

3. **Durable handles (SMB 3.0+)** — request durable handles on CREATE
   (via `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` create context). When
   the connection drops and reconnects, re-open files using
   `SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2` with the stored
   `CreateGuid`. The server preserves the open's state (locks, byte
   ranges, cached data). This makes large transfers survive transient
   network hiccups without restarting from scratch.

**Implementation:**
- Connection state machine: `Connected` → `Disconnected` → `Reconnecting` → `Connected`
- Pipeline driver detects disconnect (transport error or ECHO timeout),
  transitions to `Reconnecting`, starts reconnect loop
- During `Reconnecting`: queue new ops, drain in-flight with errors
  (unless durable handles are in play)
- On successful reconnect: re-issue TREE_CONNECT for all shares,
  re-open durable handles, resume pipeline
- On reconnect failure after max retries: fail all pending ops, report
  `Error::Disconnected`

**Tests:**
- Mock: connection drops → auto-reconnect → ops resume
- Mock: connection drops → reconnect fails after retries → all ops error
- Mock: manual `client.reconnect()` → new session, new tree connects
- Mock: durable handle survives reconnect (CREATE with durable context,
  disconnect, reconnect, re-open with reconnect context)
- Mock: non-durable handle invalidated after reconnect → error on use
- Mock: ops queued during reconnection → execute after reconnect

**Tests per sub-phase:**
- Script full conversation in mock transport
- Verify correct request bytes sent
- Verify state transitions (session ID stored, signing enabled, etc.)
- Error paths: server rejects auth, share not found, access denied

---

### Phase 8: High-level API

The user-facing API. Two tiers: simple one-shot methods and the
pipeline for power users.

```rust
let client = SmbClient::connect("192.168.1.1", Credentials::ntlm("user", "pass")).await?;

// --- Share enumeration (IPC$ + srvsvc RPC) ---

let shares = client.list_shares().await?;
for s in &shares {
    println!("{}: {}", s.name, s.comment);
}

let share = client.connect_share(&shares[0].name).await?;

// --- Simple API (one-shot, wraps pipeline internally) ---

let data = share.read_file("report.pdf").await?;
share.write_file("output.txt", b"hello").await?;
share.delete("old.txt").await?;
let entries = share.list_directory("projects/").await?;
let info = share.stat("report.pdf").await?;

// --- Pipeline API (open-ended, for Cmdr and power users) ---

let (tx, rx) = share.open_pipeline();

// Feed requests as they arise — no need to know count upfront
tx.request(Op::ReadFile("a.txt")).await;
tx.request(Op::ReadFile("b.txt")).await;
tx.request(Op::List("subdir/")).await;

// Later, user selects more files...
tx.request(Op::ReadFile("c.txt")).await;
tx.request(Op::Delete("temp.log")).await;

// Results stream back as they complete — partial results for everything
while let Some(result) = rx.next().await {
    match result {
        // Large file: multiple FileChunk results, then FileComplete
        OpResult::FileChunk { path, offset, data } => update_progress_bar(offset),
        OpResult::FileComplete { path, total_bytes } => ...,

        // Small file: one shot
        OpResult::FileData { path, data } => ...,

        // Directory: incremental batches
        OpResult::DirEntryBatch { path, entries, is_last } => render_entries(entries),

        OpResult::Written { path, bytes_written } => ...,
        OpResult::Deleted { path } => ...,
        OpResult::Stat { path, info } => ...,
        OpResult::Error { path, err } => ...,
    }
}
// Drop tx → pipeline drains gracefully
```

**Tests:**
- End-to-end simple API with mock transport
- End-to-end pipeline with mock transport (mixed ops, streaming)
- Integration tests against Docker Samba
- Benchmark: pipeline vs sequential for N small files

---

### Phase 9: Polish and ship

- Examples (list_shares, read_file, write_file, watch_directory)
- README with quick start
- API docs (`cargo doc`)
- `docs/architecture.md`, `docs/protocol.md`
- Publish to crates.io as `smb2`

---

## Docker Samba setup for integration tests

```yaml
# docker-compose.yml
services:
  samba:
    image: dperson/samba
    ports:
      - "10445:445"
    environment:
      - USER=testuser;testpass
      - SHARE=testshare;/share;yes;no;no;testuser
    volumes:
      - ./test-data:/share
```

Integration tests connect to `localhost:10445`. Ignored by default,
run with `cargo test --test integration -- --ignored`.

---

## Agent parallelization strategy

### What can run in parallel

**Phase 1:** 1a (pack/unpack) and 1b (types) are independent.

**Phase 2:** After header (2a), all message types are independent.
Group into batches of 3-4 agents:
- Batch 1: Negotiate, SessionSetup, TreeConnect, Create
- Batch 2: Close, Read, Write, QueryDirectory
- Batch 3: Logoff, TreeDisconnect, QueryInfo, SetInfo
- Batch 4: Flush, Lock, Echo, Cancel, Ioctl
- Batch 5: ChangeNotify, OplockBreak, Transform

**Phase 3-6:** Mostly sequential (each builds on the previous), but:
- Phase 3 (errors) can start alongside Phase 2
- Phase 5a (signing), 5b (encryption), 5c (KDF) are independent
- Phase 6 (auth) depends on Phase 5c

**Phase 7:** Sequential (each sub-phase depends on the previous).

### What each agent needs in its prompt

1. The relevant spec section(s) from the markdown spec
2. The pack/unpack module code (from Phase 1)
3. A completed message type as a template (from early Phase 2)
4. The corresponding smb-rs code as reference
5. Clear instruction: "Write the test first, then the implementation"

### Agent model selection

- **Opus**: All code-writing agents
- **Sonnet/Haiku**: Research agents (reading specs, finding test vectors)

---

## Resolved questions

1. **Crate name:** **`smb2`**. Clear (SMB2/3 protocol), short, available
   on crates.io. `smb` is taken by smb-rs and would be confusing since
   we don't support SMB1.
2. **MSRV:** **1.85** (matching mtp-rs). No compelling Rust features
   worth raising it for.
3. **Kerberos:** **Defer to post-1.0.** NTLM covers home NAS setups
   (Pi, QNAP, Synology, most Samba). Kerberos is needed for enterprise
   Active Directory environments that disable NTLM. Add when enterprise
   users ask.
4. **Server implementation:** **Out of scope.** Client library only.
5. **QUIC/RDMA transports:** **Defer to post-1.0.** QUIC is for Azure
   Files / Windows Server 2022+ over internet. RDMA is datacenter-only.
   Neither helps Cmdr.
6. **Compression:** **Include in v1.** LZ4 via `lz4_flex` (pure Rust,
   zero dependencies, ~15K lines). ~200 lines to negotiate in
   NEGOTIATE contexts and compress/decompress in the TRANSFORM_HEADER
   path. LZNT1 deferred (rarely used, LZ4 is the modern choice).
7. **Named pipes / RPC:** **RESOLVED: Include in Phase 7h.** Required
   for Cmdr's share enumeration. IOCTL promoted to P1 for
   `FSCTL_PIPE_TRANSCEIVE`. Added `rpc/` module and `client/shares.rs`.
8. **DFS support:** **Defer full follow-through to post-1.0.** Returns
   `Error::DfsReferralRequired` with the path for v1. Enterprise users
   can follow referrals manually. Automatic DFS resolution
   (FSCTL_DFS_GET_REFERRALS + reconnect) is ~500-800 lines and needed
   mainly in Windows domain environments.
9. **DialectRevision 0x02FF:** **Support.** Issue a second NEGOTIATE
   with MessageId=1 when 0x02FF is received. Handles older servers
   (pre-Windows 8) gracefully.
10. **Reconnection:** **Full support in Phase 7i.** `client.reconnect()`
    for manual reconnection, auto-reconnect with configurable backoff
    (default: enabled), and durable handles (SMB 3.0+) to survive
    transient network hiccups without restarting transfers.

---

## Spec versioning and agent instructions

**Pinned spec versions:** All implementation work uses the spec files
checked into `related-repos/openspecs/`. These are from ~2026-02,
which is recent enough — SMB2/3 is a mature protocol and revisions at
this point are minor clarifications, not structural changes.

**Agent prompts MUST include the actual spec text**, not rely on
training data. For each agent:
- Extract the relevant section(s) from the markdown spec file
- Paste the spec text directly into the agent prompt
- Agents should never implement from memory — their training data
  likely contains older spec versions with subtle differences

**Pre-ship spec diff (Phase 9):** Before publishing, download the
latest spec versions and diff against our pinned versions. Review any
changes for impact on our implementation. This catches any corrections
or clarifications published during development.

---

## Reference material locations

| Resource | Path |
|----------|------|
| MS-SMB2 spec | `related-repos/openspecs/skills/windows-protocols/MS-SMB2/MS-SMB2.md` |
| MS-ERREF spec | `related-repos/openspecs/skills/windows-protocols/MS-ERREF/MS-ERREF.md` |
| MS-DTYP spec | `related-repos/openspecs/skills/windows-protocols/MS-DTYP/MS-DTYP.md` |
| MS-FSCC spec | `related-repos/openspecs/skills/windows-protocols/MS-FSCC/MS-FSCC.md` |
| MS-NLMP spec | `related-repos/openspecs/skills/windows-protocols/MS-NLMP/MS-NLMP.md` |
| MS-RPCE spec (RPC) | `related-repos/openspecs/skills/windows-protocols/MS-RPCE/MS-RPCE.md` |
| MS-SRVS spec (srvsvc) | `related-repos/openspecs/skills/windows-protocols/MS-SRVS/MS-SRVS.md` |
| smb-rs reference | `related-repos/smb-rs/` |
| mtp-rs reference | `../mtp-rs/` |
