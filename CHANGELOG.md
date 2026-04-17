# Changelog

All notable changes to smb2 will be documented in this file.

The format is based on [keep a changelog](https://keepachangelog.com/en/1.1.0/), and we use
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Connection::receive_compound_expected(n)` -- gathers exactly `n` compound sub-responses, transparently
  reading additional transport frames when the server splits the chain. All compound-using methods
  (`read_file_compound`, `write_file_compound`, `fs_info`, `stat`, `rename`, `delete_file`/`delete_directory`,
  and the batch `delete_files`/`rename_files`/`stat_files`) now use it.

### Fixed

- Compound requests no longer error with `invalid_data: expected N compound responses, got M` when the
  server sends responses as separate frames instead of one compounded frame. Per MS-SMB2 3.3.4.1.3 the
  server SHOULD compound but MAY split, and Samba (including QNAP NAS firmware built on Samba) splits
  in some scenarios. Hit in the wild via `fs_info` against a QNAP NAS.

## [0.7.0] - 2026-04-15

### Added

- `FileWriter` — push-based streaming write API with pipelined I/O. Consumer drives the loop, pushing chunks via
  `write_chunk()` with automatic backpressure (sliding window, credit-aware). Complement to `FileDownload` for reads.
  Created via `SmbClient::create_file_writer()`.
- 13 new Docker integration tests: basic, large (5 MB), empty, single byte, overwrite, equivalence with
  `write_file_pipelined`, binary data integrity, 64 KB max-write-size, signing, encryption, read-only rejection,
  100 MB stress (guest), 100 MB stress (200ms latency)
- 10 new unit tests for `FileWriter` pipelining, backpressure, chunk splitting, error handling

## [0.6.0] - 2026-04-15

### Added

- `write_file_streamed` — write files from a streaming callback source with pipelined I/O, bounded memory usage
  (sliding window, not full file), automatic chunk splitting at `MaxWriteSize`, works with signing and encryption
  ([f5ade78](https://github.com/vdavid/smb2/commit/f5ade78))
- 14 new tests: 3 unit (basic, empty, callback error), 9 Docker integration (guest, small, large 10 MB, empty, early
  stop, 64 KB max-write-size, mandatory signing, mandatory encryption, read-only rejection), 2 NAS integration
  (write + verify, performance comparison vs `write_file_pipelined`)

### Fixed

- Bumped `rand` 0.9.2 → 0.9.4 (RUSTSEC-2026-0097)

## [0.5.0] - 2026-04-10

### Added

- DFS (Distributed File System) support — resolve `\\domain\dfs-namespace\path` transparently, follow referrals across
  servers, multi-target failover, TTL-based referral cache
  ([d353490](https://github.com/vdavid/smb2/commit/d353490),
  [bfd8557](https://github.com/vdavid/smb2/commit/bfd8557),
  [03c4c2a](https://github.com/vdavid/smb2/commit/03c4c2a),
  [87a7d78](https://github.com/vdavid/smb2/commit/87a7d78))
- Compound delete (1 RTT instead of 2), compound rename (1 RTT instead of 3), compound stat (1 RTT instead of 4)
  ([33938591](https://github.com/vdavid/smb2/commit/33938591),
  [5e0f7a5](https://github.com/vdavid/smb2/commit/5e0f7a5),
  [4dc8fb8](https://github.com/vdavid/smb2/commit/4dc8fb8))
- `read_file_with_progress` for pipelined reads with progress callback and cancellation
  ([37e3370](https://github.com/vdavid/smb2/commit/37e3370))
- Batch operations — `delete_files`, `rename_files`, `stat_files` send all compound requests before waiting for
  responses, partial failures are independent ([afe4395](https://github.com/vdavid/smb2/commit/afe4395))
- DFS wire format types: `ReqGetDfsReferral`, `RespGetDfsReferral` with V2/V3/V4 referral entries
  ([e9e5bf9](https://github.com/vdavid/smb2/commit/e9e5bf9))
- Auto-set `SMB2_FLAGS_DFS_OPERATIONS` based on tree capabilities
  ([f254e96](https://github.com/vdavid/smb2/commit/f254e96))
- Connection pool for DFS cross-server routing, `ClientConfig.dfs_enabled` and `dfs_target_overrides`
  ([03c4c2a](https://github.com/vdavid/smb2/commit/03c4c2a),
  [edcf730](https://github.com/vdavid/smb2/commit/edcf730))
- Docker DFS test containers (smb-dfs-root:10456, smb-dfs-target:10457) with 4 integration tests
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))

### Fixed

- IOCTL `InputOffset` double-counted `Header::SIZE`, causing `STATUS_INVALID_PARAMETER` on DFS referral requests
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))
- DFS paths missing `server\share` prefix in `Tree::format_path`
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))
- Cross-server routing matched hostname-only instead of addr:port
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))

## [0.4.0] - 2026-04-09

### Added

- Kerberos authentication — full AS + TGS + AP-REQ flow with pre-auth, tested end-to-end against Windows Server 2022
  with Active Directory Domain Services
  ([9b40b00](https://github.com/vdavid/smb2/commit/9b40b00))
- Kerberos credential cache (ccache) support — read MIT Kerberos ccache files (v3 and v4) for password-less auth from
  `kinit` tickets, `Session::setup_kerberos_from_ccache()`
  ([2344f15](https://github.com/vdavid/smb2/commit/2344f15))
- AP-REP mutual authentication — server sub-session key extraction for cryptographic server identity proof
  ([b966d2c](https://github.com/vdavid/smb2/commit/b966d2c))
- SPNEGO token wrapping — hand-rolled ASN.1/DER encoding for NegTokenInit/NegTokenResp (RFC 4178 / MS-SPNG), no external
  ASN.1 dependency ([c27c88f](https://github.com/vdavid/smb2/commit/c27c88f))
- Kerberos crypto: AES-CTS (RFC 3962), RC4-HMAC (RFC 4757), PBKDF2 string-to-key, n-fold, HMAC-SHA1-96 checksums
  ([e23b851](https://github.com/vdavid/smb2/commit/e23b851))
- Kerberos ASN.1 messages: AS-REQ, TGS-REQ, AP-REQ, Authenticator, KDC-REP parsing — all hand-rolled DER
  ([97b57a5](https://github.com/vdavid/smb2/commit/97b57a5))
- KDC client: UDP primary with TCP fallback on `KRB_ERR_RESPONSE_TOO_BIG`, exponential backoff retries
  ([97b57a5](https://github.com/vdavid/smb2/commit/97b57a5))
- `Session::setup_kerberos()` and `Session::setup_kerberos_from_ccache()` public API
  ([3a63337](https://github.com/vdavid/smb2/commit/3a63337),
  [2344f15](https://github.com/vdavid/smb2/commit/2344f15))
- Support for AES-256, AES-128, and RC4-HMAC encryption types, with AES-256 preferred
  ([01ad252](https://github.com/vdavid/smb2/commit/01ad252))

### Fixed

- KDC-REP field tags: pvno is `[0]` not `[1]` per RFC 4120
  ([3a63337](https://github.com/vdavid/smb2/commit/3a63337))
- AES-CTS key derivation: Ki constant is 0x55 (encrypt/decrypt integrity), not 0x99 (standalone checksum)
  ([661a245](https://github.com/vdavid/smb2/commit/661a245))
- TGS-REQ AP-REQ Authenticator was missing body checksum over KDC-REQ-BODY (RFC 4120 section 7.2.2, key usage 6)
  ([661a245](https://github.com/vdavid/smb2/commit/661a245))

### Key implementation details

Hard-won lessons from testing against Windows AD (documented in `src/auth/CLAUDE.md`):

- MS Kerberos OID (`1.2.840.48018.1.2.2`) required as primary SPNEGO mechanism for Windows
- Key usage 11 (not 7) for AP-REQ Authenticator encryption in SPNEGO exchanges
- GSS-API wrapping of AP-REQ inside SPNEGO mechToken
- Raw ticket byte pass-through (re-encoding corrupts the encrypted ticket)
- Session key etype detection from TGS-REP (may differ from ticket encryption type)

## [0.3.0] - 2026-04-08

### Added

- Compound requests — CREATE+READ+CLOSE (3-way) and CREATE+WRITE+FLUSH+CLOSE (4-way) as single transport frames,
  reducing round-trips from 3-4 to 1 per file operation
  ([a9293b6](https://github.com/vdavid/smb2/commit/a9293b6),
  [cb022bc](https://github.com/vdavid/smb2/commit/cb022bc))
- `read_file()` and `write_file()` auto-select compound (small) or pipelined (large) — callers don't choose
  ([25b2f68](https://github.com/vdavid/smb2/commit/25b2f68),
  [cb022bc](https://github.com/vdavid/smb2/commit/cb022bc))
- Streaming upload with `FileUpload` — compound for small files, chunked for large, same caller API either way
  ([8b2283a](https://github.com/vdavid/smb2/commit/8b2283a))
- Streaming download with `FileDownload`, progress reporting with `ControlFlow`-based cancellation
  ([c11f5f3](https://github.com/vdavid/smb2/commit/c11f5f3))
- Sliding window pipeline — each response immediately triggers the next chunk, keeping the TCP pipe full
  ([dd36181](https://github.com/vdavid/smb2/commit/dd36181))
- SMB 3.x encryption wired into client layer — TRANSFORM_HEADER wrapping, sign-then-compress-then-encrypt send path,
  AES-128/256-CCM/GCM ([101d22d](https://github.com/vdavid/smb2/commit/101d22d))
- LZ4 compression wired into connection layer — negotiated during handshake, applied per-message when it reduces size
  ([e2921f9](https://github.com/vdavid/smb2/commit/e2921f9))
- File watching via `CHANGE_NOTIFY` — `Watcher` struct with `next_events()` long-poll, recursive watching support
  ([75b281d](https://github.com/vdavid/smb2/commit/75b281d))
- Disk space query (`fs_info`) via compound CREATE+QUERY_INFO+CLOSE
  ([6d3a05c](https://github.com/vdavid/smb2/commit/6d3a05c))
- `ErrorKind` for high-level error classification — `NotFound`, `AccessDenied`, `ConnectionLost`, etc. instead of raw
  NTSTATUS codes ([58aead2](https://github.com/vdavid/smb2/commit/58aead2))
- Oplock break notification handling — detected by MessageId `0xFFFF...`, logged and skipped without crashing
  ([371b984](https://github.com/vdavid/smb2/commit/371b984))
- `STATUS_BUFFER_OVERFLOW` accepted as partial success in QueryInfo responses
  ([4122d16](https://github.com/vdavid/smb2/commit/4122d16))
- CANCEL requests and session expiry detection with `Error::SessionExpired`
  ([4924a2a](https://github.com/vdavid/smb2/commit/4924a2a))
- Docker test infrastructure — 12 Samba containers covering guest, auth, signing, readonly, ancient (SMB1), flaky, slow,
  encryption (GCM + CCM), 50 shares, max read size, with 43 integration tests
  ([8edf837](https://github.com/vdavid/smb2/commit/8edf837),
  [7ee088f](https://github.com/vdavid/smb2/commit/7ee088f),
  [812ad39](https://github.com/vdavid/smb2/commit/812ad39))
- Docker tests in CI — builds containers and runs 43 tests on every PR
  ([488e1d0](https://github.com/vdavid/smb2/commit/488e1d0))
- 7 runnable examples: `list_shares`, `list_directory`, `read_file`, `streaming_download`, `disk_space`,
  `watch_directory`, `write_file` ([7203bdb](https://github.com/vdavid/smb2/commit/7203bdb))
- `Send + Sync` bounds on `Pack` trait for async callers
  ([4538205](https://github.com/vdavid/smb2/commit/4538205))
- GitHub Actions CI: fmt, clippy, test, doc, MSRV 1.85
  ([f0b00cd](https://github.com/vdavid/smb2/commit/f0b00cd))

### Fixed

- `STATUS_PENDING` handling — `receive_response()` now loops past interim responses instead of treating them as errors
  ([8edf837](https://github.com/vdavid/smb2/commit/8edf837))
- Multi-credit charges — streaming download/upload and `write_file_with_progress` were sending `credit_charge=1` for
  MB-sized payloads, Samba rejects with `STATUS_INVALID_PARAMETER`
  ([8edf837](https://github.com/vdavid/smb2/commit/8edf837))
- Cipher fallback — fall back to AES-128-CCM when server omits encryption negotiate context
  ([812ad39](https://github.com/vdavid/smb2/commit/812ad39))

### Improved

- Smart read selection — sequential for files < MaxReadSize (1 RTT), pipelined only when beneficial
  ([3f0cd77](https://github.com/vdavid/smb2/commit/3f0cd77))
- Credit request bumped from 32 to 256 per request, credits grow rapidly
  ([dd36181](https://github.com/vdavid/smb2/commit/dd36181))
- Pipeline uses server-negotiated MaxReadSize/MaxWriteSize with correct multi-credit CreditCharge
  ([b0cacdd](https://github.com/vdavid/smb2/commit/b0cacdd))
- `trivial_message!` and `nt_status_codes!` macros to reduce boilerplate
  ([fb4b9e4](https://github.com/vdavid/smb2/commit/fb4b9e4))
- CLAUDE.md files for all 8 modules, agent docs colocated with code
  ([2d884d0](https://github.com/vdavid/smb2/commit/2d884d0))

## [0.2.0] - 2026-04-08

### Added

- Concurrent pipelined read and write — send multiple READ/WRITE requests by filling the credit window, reassemble
  responses in offset order, handles out-of-order responses
  ([7f3068a](https://github.com/vdavid/smb2/commit/7f3068a))
- Share enumeration — IPC$ + srvsvc RPC flow, QNAP returns 8 disk shares, Pi returns 1
  ([cbed0ab](https://github.com/vdavid/smb2/commit/cbed0ab))
- `SmbClient` high-level API — `connect()`, `list_shares()`, `connect_share()`, `reconnect()`, stored credentials
  ([cbed0ab](https://github.com/vdavid/smb2/commit/cbed0ab))
- Convenience `smb2::client::connect("host:445", "user", "pass")` one-liner
  ([cbed0ab](https://github.com/vdavid/smb2/commit/cbed0ab))
- File operations: `write_file`, `delete_file`, `stat`, `rename`, `create_directory`, `delete_directory`
  ([c80f126](https://github.com/vdavid/smb2/commit/c80f126))
- Clean re-exports from `lib.rs` — `use smb2::{SmbClient, Tree}` instead of reaching into submodules
  ([cdb203e](https://github.com/vdavid/smb2/commit/cdb203e))
- 4 runnable examples: `list_shares`, `list_directory`, `read_file`, `write_file`
  ([cdb203e](https://github.com/vdavid/smb2/commit/cdb203e))
- Benchmarks against native macOS SMB and `smb` crate:
  small files 2-3x faster, medium files match native on upload, 8.5x faster than `smb` on download
  ([031d52b](https://github.com/vdavid/smb2/commit/031d52b),
  [4cbc961](https://github.com/vdavid/smb2/commit/4cbc961))
- Integration tests against QNAP NAS (SMB 3.1.1, NTLM, AES-GMAC) and Raspberry Pi 4 (SMB 3.1.1, guest)
  ([c80f126](https://github.com/vdavid/smb2/commit/c80f126))

### Fixed

- Preauth hash: exclude final SESSION_SETUP success response from hash — including it produces wrong keys for SMB 3.1.1
  ([32f0f30](https://github.com/vdavid/smb2/commit/32f0f30))
- QueryDirectory: cap `OutputBufferLength` to 65536, always send `"*"` pattern (empty filename rejected by QNAP + Samba)
  ([b9d49f7](https://github.com/vdavid/smb2/commit/b9d49f7))
- GMAC uses AES-128-GCM (16-byte key), not AES-256-GCM
  ([dc91351](https://github.com/vdavid/smb2/commit/dc91351))
- GMAC nonce needs server role bit for response verification
  ([dc91351](https://github.com/vdavid/smb2/commit/dc91351))
- Only verify signature when `SMB2_FLAGS_SIGNED` is set (skip STATUS_PENDING and oplock breaks)
  ([dc91351](https://github.com/vdavid/smb2/commit/dc91351))

## [0.1.0] - 2026-04-07

### Added

- SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 dialect support — negotiate with all five dialects, preauth integrity, encryption,
  compression, and signing negotiate contexts
  ([c3a2e43](https://github.com/vdavid/smb2/commit/c3a2e43),
  [36428728](https://github.com/vdavid/smb2/commit/36428728))
- NTLM authentication (NTLMv2 with MIC) — full NEGOTIATE/CHALLENGE/AUTHENTICATE flow, session key exchange, known-answer
  test vectors from MS-NLMP section 4.2.4
  ([60c4163](https://github.com/vdavid/smb2/commit/60c4163))
- Wire format pack/unpack for all 19 SMB2 commands — header, negotiate, session setup, tree connect, create, close,
  read, write, flush, lock, ioctl, query directory, change notify, query info, set info, echo, cancel, logoff, oplock
  break, transform header, compression header
  ([c3a2e43](https://github.com/vdavid/smb2/commit/c3a2e43))
- Binary serialization primitives — `ReadCursor`/`WriteCursor` with LE primitives, UTF-16LE, alignment, backpatching,
  `Pack`/`Unpack` traits, `Guid` with mixed-endian layout, `FileTime` with Windows epoch conversion
  ([8be0549](https://github.com/vdavid/smb2/commit/8be0549))
- Newtypes for all protocol IDs: `SessionId`, `MessageId`, `TreeId`, `CreditCharge`, `FileId` with sentinel constants
  ([8be0549](https://github.com/vdavid/smb2/commit/8be0549))
- TCP transport with split send/receive traits (avoids deadlock in pipeline's `select!` loop), correct framing (0x00 +
  3-byte BE length), 16 MB max frame, Nagle disabled
  ([5ae8027](https://github.com/vdavid/smb2/commit/5ae8027))
- MockTransport for TDD — FIFO response queue, message recording, assertion helpers
  ([5ae8027](https://github.com/vdavid/smb2/commit/5ae8027))
- SMB 3.x signing: HMAC-SHA256 (2.0.2/2.1), AES-128-CMAC (3.0/3.0.2), AES-256-GMAC (3.1.1)
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- SMB 3.x encryption: AES-128/256-CCM and AES-128/256-GCM with monotonic nonce generator
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- SP800-108 key derivation for SMB 3.0/3.0.2 (legacy labels) and 3.1.1 (preauth hash context)
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- LZ4 compression via `lz4_flex` (pure Rust, zero C deps)
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- Connection layer: negotiate, credit management, message ID sequencing, preauth hash tracking, signing integration
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- Session layer: multi-round-trip SESSION_SETUP with NTLM, key derivation per dialect, signing activation
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- Tree layer: TREE_CONNECT with UNC path, directory listing, file reading
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- RPC module: DCE/RPC PDU encoding, NDR encoding for `NetShareEnumAll`
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- Structured logging via `log` crate — info for lifecycle, debug for protocol, trace for bytes, never logs secrets
  ([1d7273a](https://github.com/vdavid/smb2/commit/1d7273a))
- Error types with `is_retryable()`, `status()`, `Auth`, `Timeout`, `Disconnected`, `SessionExpired` variants
  ([5ae8027](https://github.com/vdavid/smb2/commit/5ae8027))
- `MAX_UNPACK_BUFFER` (16 MB) allocation cap to prevent OOM from malicious packets
  ([073452c](https://github.com/vdavid/smb2/commit/073452c))
- 512 unit tests, 10 integration tests against real hardware, zero clippy warnings
