# Tests

Four test categories, each serving a different purpose.

## Unit tests (in `src/`)

Inline `#[cfg(test)]` modules, colocated with the code they test. Use `MockTransport` to simulate server responses without a network connection. Run with `cargo test`.

~555 tests covering: pack/unpack roundtrips, wire format encoding, signing/encryption, NTLM auth (with MS-NLMP spec test vectors), compound construction, pipelined I/O, credit tracking, oplock break handling, session expiry, CANCEL requests.

Property-based tests (proptest) cover pack/unpack for all primitive types and UTF-16LE strings.

**Key pattern:** Most unit tests queue canned responses on `MockTransport`, call the method under test, and verify the result + the sent messages. For compound operations, queue one compound response frame (not separate responses).

## Integration tests (`tests/integration.rs`)

Real-server tests against David's NAS and Pi. Marked `#[ignore]` — skipped by `cargo test`, run with:

```sh
cargo test --test integration -- --ignored --nocapture
```

**Requirements:**
- QNAP NAS at 192.168.1.111 (NTLM auth, SMB 3.1.1, AES-GMAC signing)
- Raspberry Pi at 192.168.1.150 (guest access, SMB 3.1.1)
- `SMB2_TEST_NAS_PASSWORD` env var (from `.env` file or shell). See `.env.example`.

**What they cover:** Connect, negotiate, auth (NTLM + guest), tree connect, list directory, read/write/delete file, stat, create/delete directory, compound read/write, pipelined I/O, streaming download/upload with progress, reconnect, share enumeration, file watching, disk space, rename. Also a micro-benchmark comparing smb2 vs native macOS SMB.

These are secondary validation — the primary safety net is the unit tests and (soon) Docker tests. Contributors without NAS hardware can skip these.

## Wire format captures (`tests/wire_format_captures.rs`)

Connect to the real NAS, send a NegotiateRequest, capture the server's raw response bytes, and verify our Pack/Unpack produces byte-identical output. The strongest wire format test — proves we match real-world traffic, not just our own roundtrips.

5 tests, all `#[ignore]` (require NAS). Covers negotiate request/response and header byte layout.

## Docker integration tests (`tests/docker_integration.rs`)

Tests against 13 Docker-based Samba containers. Deterministic, no real hardware needed. Runs in CI on every PR. See `docs/specs/docker-test-infrastructure.md` for the full plan.

Containers live in `tests/docker/internal/`.

**Running Docker tests:**

```sh
# One command does everything (~28s locally, ~2-3 min in CI):
just test-docker

# For faster iteration, keep containers running between runs:
./tests/docker/start.sh internal    # once (~10s)
cargo test --test docker_integration -- --ignored   # repeat (~8s)
./tests/docker/stop.sh              # when done (~10s)
```

**Containers and what they exercise:**

| Container | Port | Focus |
|-----------|------|-------|
| smb-guest | 10445 | Guest auth, CRUD, compound, pipelined, streaming, progress, cancel, fs_info, reconnect, file watching |
| smb-auth | 10446 | NTLM auth, wrong-password rejection |
| smb-signing | 10447 | Mandatory signing: write/read, compound, pipelined 512 KB |
| smb-readonly | 10448 | Read-only share: list/read/stat succeed, write/delete/mkdir fail cleanly |
| smb-ancient | 10449 | SMB1-only server: negotiate fails cleanly (not hang) |
| smb-flaky | 10450 | 5s up / 5s down: connect during up, get clean error when down |
| smb-slow | 10451 | 200ms latency: operations still work, pipelining under delay |
| smb-encryption | 10452 | Mandatory encryption (AES-128-GCM, SMB 3.1.1): write/read, pipelined, share listing |
| smb-50shares | 10453 | 50 shares: RPC enumeration returns all 50 |
| smb-maxreadsize | 10454 | 64 KB max read/write: pipelined 512 KB, streaming download chunk count |
| smb-encryption-aes128 | 10455 | Mandatory encryption (AES-128-CCM, SMB 3.0.2): different cipher family |
| smb-dfs-root | 10456 | DFS namespace root with msdfs link to smb-dfs-target |
| smb-dfs-target | 10457 | DFS target server with test files (hello.txt, subdir/nested.txt) |

## How to run

| Command | What it runs | Needs |
|---|---|---|
| `cargo test` | Unit tests only (~555) | Nothing |
| `just check` | fmt + clippy + unit tests + doc | Nothing |
| `cargo test --test integration -- --ignored` | Real NAS/Pi tests | NAS + Pi + .env |
| `cargo test --test wire_format_captures -- --ignored` | Wire format vs real server | NAS + .env |
| `just test-docker` | Docker integration tests | Docker |

## AWS integration tests (Kerberos)

For Kerberos end-to-end testing, we use AWS EC2 to spin up a Windows Server with Active Directory Domain Services. No Docker alternative exists (Samba AD DC doesn't work on macOS).

**AWS access:**
- **Profile:** `smb2-agent` (configured in `~/.aws/credentials`)
- **Region:** `eu-north-1`
- **IAM user:** `smb2-agent` (account 791732162721)
- **Permissions:** EC2 lifecycle (run/terminate/describe instances, security groups, key pairs), SSM parameter reads. Scoped to eu-north-1 only.

**Usage:** Always pass `AWS_PROFILE=smb2-agent` or `--profile smb2-agent` for all AWS CLI calls.

**Important:** Terminate instances when testing is done. David has billing guards but don't leave things running.

**Test:** `kerberos_auth_against_aws_windows_ad` in `integration.rs` -- connects to a Windows AD DC, authenticates via Kerberos (AS + TGS + AP-REQ), establishes an SMB session, writes and reads a file. Requires env vars: `SMB2_TEST_AWS_AD_IP`, `SMB2_TEST_AWS_AD_HOSTNAME`, and optionally `SMB2_TEST_AWS_AD_SPN`. Tested successfully against Windows Server 2022 with AD DS (2026-04-09).

## Writing new tests

- **Protocol correctness** (does our Pack/Unpack match the spec?): unit test with known byte sequences
- **Client logic** (does the state machine work?): unit test with MockTransport
- **Real server compatibility** (does it work against Samba?): Docker test or integration test
- **Performance** (is it fast?): micro-benchmark in integration tests or `benchmarks/smb/`

**TDD encouraged:** Write the test first, then the implementation. The test defines the expected behavior.

**Avoid self-referential tests:** Roundtrip tests (pack then unpack) don't catch symmetric bugs. Always include at least one known-byte-sequence test per message type, or a real-server repack test.
