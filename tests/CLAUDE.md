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

Tests against Docker-based Samba containers. Deterministic, no real hardware needed. Planned to run in CI on every PR. See `docs/specs/docker-test-infrastructure.md` for the full plan.

Containers live in `tests/docker/`. Start with `./tests/docker/start.sh`.

Currently covers: guest auth, NTLM auth, read/write/delete, compound, pipelined, streaming, share enumeration, disk space, file watching, reconnect after flaky disconnect.

## How to run

| Command | What it runs | Needs |
|---|---|---|
| `cargo test` | Unit tests only (~555) | Nothing |
| `just check` | fmt + clippy + unit tests + doc | Nothing |
| `cargo test --test integration -- --ignored` | Real NAS/Pi tests | NAS + Pi + .env |
| `cargo test --test wire_format_captures -- --ignored` | Wire format vs real server | NAS + .env |
| `just test-docker` | Docker integration tests | Docker |

## Writing new tests

- **Protocol correctness** (does our Pack/Unpack match the spec?): unit test with known byte sequences
- **Client logic** (does the state machine work?): unit test with MockTransport
- **Real server compatibility** (does it work against Samba?): Docker test or integration test
- **Performance** (is it fast?): micro-benchmark in integration tests or `benchmarks/smb/`

**TDD encouraged:** Write the test first, then the implementation. The test defines the expected behavior.

**Avoid self-referential tests:** Roundtrip tests (pack then unpack) don't catch symmetric bugs. Always include at least one known-byte-sequence test per message type, or a real-server repack test.
