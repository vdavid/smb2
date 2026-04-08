# Docker test infrastructure plan

Two separate features built on shared infrastructure:

1. **smb2's own CI tests** -- protocol-level verification against real Samba servers. Replaces `#[ignore]` tests that
   need David's NAS and Pi. Runs in CI on every PR.
2. **Consumer test harness** -- an `smb2::testing` API (feature-gated)
   that apps like Cmdr use to test their SMB integration. Like mtp-rs's virtual device, but for SMB.

These are two different features that share a base image and tooling. The container sets are disjoint -- different
goals, different configs.

## Shared infrastructure

Both features build on the same foundation:

- **Base image**: Alpine Linux 3.21 + Samba package (~50 MB per container)
- **Tooling**: `docker-compose.yml`, `start.sh`, `stop.sh`
- **Ports**: 10445-10470 range (high ports, no conflicts with real SMB on 445 or other dev services)
- **Latency injection**: iproute2-tc where needed (smb-slow)
- **mDNS**: Avahi + dbus (consumer containers only, for Bonjour discovery testing on Pi)

Each container is a thin Dockerfile: `FROM` the base, drop in an
`smb.conf`, maybe a startup script. Cheap to create and maintain independently.

### File structure

```
tests/
  docker/
    base/Dockerfile             # Alpine + Samba base image
    start.sh                    # Start containers by profile
    stop.sh                     # Stop everything
    internal/                   # smb2's own test containers
      docker-compose.yml
      smb-guest/
        Dockerfile
        smb.conf
      smb-auth/
        Dockerfile
        smb.conf
      ... (one dir per container)
    consumer/                   # Consumer test harness containers
      docker-compose.yml
      smb-consumer-guest/
        Dockerfile
        smb.conf
      smb-consumer-auth/
        Dockerfile
        smb.conf
      ... (one dir per container)
  docker_integration.rs         # Docker-based protocol tests (smb2 CI)
  integration.rs                # Real-hardware tests (#[ignore], stay)
```

## Feature 1: smb2's own CI tests

### Purpose

Test the protocol implementation against a real Samba server. Things the mock transport can't catch: actual NTLM
handshakes, real signing verification, wire-level NDR encoding, NTSTATUS codes from a real server, etc.

### Current state

28 integration tests marked `#[ignore]`, all require David's NAS
(192.168.1.111) or Pi. Contributors can't run them. CI can't run them.

### New state

Docker-based tests that run in CI on every PR. No hardware needed. The `#[ignore]` tests stay for validation against
real commercial hardware (QNAP, Pi) but aren't the primary safety net.

### Containers

| Container       | Port  | What it tests                               |
|-----------------|-------|---------------------------------------------|
| smb-guest       | 10445 | Guest access, basic operations              |
| smb-auth        | 10446 | NTLM auth (testuser/testpass)               |
| smb-signing     | 10447 | Mandatory signing (server rejects unsigned) |
| smb-readonly    | 10448 | Write/delete -> clean NTSTATUS errors       |
| smb-ancient     | 10449 | SMB1 only -> clean protocol rejection       |
| smb-flaky       | 10450 | 5s up / 5s down -> reconnect logic          |
| smb-slow        | 10451 | 500ms+ latency -> pipelining advantage      |
| smb-encryption  | 10452 | Mandatory encryption (AES-CCM/GCM)          |
| smb-50shares    | 10453 | 50 shares -> RPC enumeration at scale       |
| smb-maxreadsize | 10454 | Tiny MaxReadSize -> chunking edge cases     |

No unicode/longnames/deepnest/manyfiles containers here -- those test data handling, not protocol implementation. If we
need them later, we add them.

### Test plan

Tests that replace the 28 `#[ignore]` tests and add coverage we couldn't test before:

**Basic operations (smb-guest):**

- Connect as guest, list shares, list directory, read/write/delete
- Compound read (CREATE+READ+CLOSE in one round-trip)
- Compound write (CREATE+WRITE+FLUSH+CLOSE in one round-trip)
- Compound partial failure handling
- fs_info returns sane values (total > 0, free <= total)

**Authentication (smb-auth):**

- NTLM connect, all operations succeed
- Wrong password -> clean error (not hang)

**Pipelined I/O (smb-guest):**

- Pipelined read of large file (sliding window)
- Pipelined write of large file
- Write then read back, compare bytes (data integrity)

**Streaming (smb-guest):**

- FileDownload with progress callback
- FileUpload with progress callback
- Cancellation mid-transfer

**Signing (smb-signing):**

- signing_required=true in NegotiatedParams
- All operations work (server accepts our signatures)
- Tampered message -> server rejects (if testable)

**Encryption (smb-encryption):**

- Negotiate encryption, verify it's active
- All operations work over encrypted transport
- Correct cipher negotiated (AES-128-CCM or AES-128-GCM)

**Read-only (smb-readonly):**

- Read, list, stat succeed
- Write -> clean NTSTATUS error
- Delete -> clean NTSTATUS error
- create_directory -> clean NTSTATUS error

**SMB1 rejection (smb-ancient):**

- Server only speaks SMB1
- We return a clean error (not hang, not crash)
- Error indicates protocol incompatibility

**Reconnect (smb-flaky):**

- Connect, do operation, wait for server to cycle
- Error::Disconnected returned (not hang)
- Reconnect succeeds, operations work after

**Pipelining advantage (smb-slow):**

- Large file read with 500ms+ RTT
- Verify pipelining completes faster than sequential would

**Share enumeration (smb-guest, smb-50shares):**

- list_shares() returns correct shares via RPC
- 50-share server returns all 50
- Filtering: no IPC$, no admin $ shares

**Chunking edge cases (smb-maxreadsize):**

- Server with tiny MaxReadSize (for example, 64 KB)
- Large file read still works (many chunks)
- Large file write still works

**File watching (smb-guest):**

- Watch directory, create file from second connection, get event
- Recursive watching
- Watch with timeout (no changes -> no hang)

### CI integration

```yaml
docker-tests:
  name: Docker integration tests
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v5
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
    - name: Start SMB containers
      run: ./tests/docker/start.sh internal
    - name: Wait for health checks
      run: ./tests/docker/start.sh wait
    - name: Run Docker tests
      run: cargo test --test docker_integration
      env:
        RUST_LOG: smb2=debug
    - name: Stop containers
      if: always()
      run: ./tests/docker/stop.sh
```

Runs on every PR. Full suite, all internal containers. These are small Alpine images, startup is fast.

## Feature 2: Consumer test harness

### Purpose

Let apps that depend on smb2 test their SMB integration without maintaining their own Docker infrastructure. Like
mtp-rs's
`virtual-device` feature: enable a feature flag, get test servers for free.

Consumers trust smb2 to handle signing, encryption, and protocol edge cases. They need servers that represent what their
users have:
a NAS with guest access, a NAS requiring login, a server with lots of shares, a server with unicode names, etc.

### Containers

| Container              | Port  | What consumers test against               |
|------------------------|-------|-------------------------------------------|
| smb-consumer-guest     | 10460 | Guest access works end-to-end             |
| smb-consumer-auth      | 10461 | Login flow works end-to-end               |
| smb-consumer-both      | 10462 | Mixed: guest allowed, auth extends access |
| smb-consumer-50shares  | 10463 | UI handles many shares                    |
| smb-consumer-unicode   | 10464 | Non-ASCII share/file names render right   |
| smb-consumer-longnames | 10465 | 200+ char filenames display and work      |
| smb-consumer-deepnest  | 10466 | 50-level deep tree (breadcrumb, nav)      |
| smb-consumer-manyfiles | 10467 | 10k+ files (listing perf, virtual scroll) |
| smb-consumer-readonly  | 10468 | Read-only share (disable write UI)        |
| smb-consumer-windows   | 10469 | Windows server string (OS detection UI)   |
| smb-consumer-synology  | 10470 | Synology NAS mimicry (NAS-specific UI)    |

No smb-ancient, smb-encryption, smb-signing, smb-flaky, smb-slow here. Consumers don't care about protocol internals.

### API

```rust
use smb2::testing::TestServers;

// Start minimal set (guest + auth, fast)
let servers = TestServers::start().await?;

// Or start everything
let servers = TestServers::start_all().await?;

// Get pre-connected clients
let guest = servers.guest_client().await?;
let auth = servers.auth_client("testuser", "testpass").await?;

// Use like any SmbClient
let shares = guest.list_shares().await?;
let share = guest.connect_share("public").await?;
let entries = guest.list_directory( & share, "").await?;

// Containers stop on drop
drop(servers);
```

### TestServers

```rust
/// Docker-based SMB test servers for integration testing.
///
/// Starts Samba containers on construction, stops on drop. Each
/// server type has a factory method returning a connected SmbClient.
pub struct TestServers {
    /* ... */
}

impl TestServers {
    /// Start minimal set: guest + auth (~100 MB, ~2s).
    pub async fn start() -> Result<Self>;

    /// Start all consumer containers (~600 MB, ~5s).
    pub async fn start_all() -> Result<Self>;

    /// Guest-access server. No credentials needed.
    pub async fn guest_client(&self) -> Result<SmbClient>;

    /// Auth-required server. Needs username + password.
    pub async fn auth_client(&self, user: &str, pass: &str) -> Result<SmbClient>;

    /// Mixed server. Guest gets "public", auth gets "public" + "private".
    pub async fn both_client(&self) -> Result<SmbClient>;
    pub async fn both_client_auth(&self, user: &str, pass: &str) -> Result<SmbClient>;

    /// Read-only server. Writes return errors.
    pub async fn readonly_client(&self) -> Result<SmbClient>;

    /// Server with 50 shares.
    pub async fn many_shares_client(&self) -> Result<SmbClient>;

    /// Server with unicode share/file names.
    pub async fn unicode_client(&self) -> Result<SmbClient>;

    /// Server with 10k+ files.
    pub async fn many_files_client(&self) -> Result<SmbClient>;
}

impl Drop for TestServers {
    fn drop(&mut self) { /* best-effort: docker compose down */ }
}
```

No `signing_client()`, no `flaky_client()`, no `slow_client()`. Those are smb2 internals, not consumer concerns.

### Feature gating

```toml
[features]
testing = []  # Enables smb2::testing module

# No extra deps. Uses std::process::Command for docker compose.
```

### How Cmdr would use it

Before (Cmdr owns Docker infra):

```
cmdr/test/smb-servers/docker-compose.yml     <- Cmdr maintains
cmdr/test/smb-servers/containers/             <- Cmdr maintains
cmdr/src/network/virtual_smb_hosts.rs         <- manual setup code
```

After (smb2 provides test infra):

```rust
// Cmdr's integration test setup
let servers = smb2::testing::TestServers::start_all().await?;
let guest = servers.guest_client().await?;
app.inject_smb_client("virtual-smb-guest", guest);
```

Cmdr deletes its Docker files and server management code. Exactly the same pattern as mtp-rs's virtual device.

### Pi deployment (future)

For Cmdr's Bonjour discovery testing on a Raspberry Pi, the consumer containers support macvlan networking with real LAN
IPs. Containers advertise via Avahi/mDNS and appear in the app's network browser.

This is a consumer-specific need (smb2 doesn't care about mDNS). The Pi compose file is a separate overlay in the
consumer directory.

## Samba RPC compatibility (NDR64 non-issue)

Cmdr's earlier SMB library (smb-rs) couldn't list shares against Docker Samba because it proposed NDR64 transfer syntax
(`71710533-beba-4937-...`) for SRVSVC RPC binds, which Samba rejects with `ProposedTransferSyntaxesNotSupported`.

This doesn't affect us. Our RPC implementation (`src/rpc/mod.rs`)
uses plain NDR (`8A885D04-1CEB-11C9-...`, version 2), which is the universally supported transfer syntax. Samba,
Windows, Synology -- everything speaks it. Share listing against Docker Samba works fine.

## What we don't build

- **In-process SMB server.** Too complex (state machine, credits, signing, leases). Docker Samba is realistic and
  battle-tested.

- **SMB1 support.** smb-ancient tests graceful rejection, not that we speak SMB1.

- **Network simulation in-process.** Docker networking + tc qdisc is more realistic than simulating failures in code.

- **Shared containers between the two features.** Keeping them disjoint is cheap (~20-line Dockerfiles, ~50 MB each) and
  avoids coupling the two use cases. If a container config needs to change for protocol testing, it shouldn't affect
  consumers, and vice versa.

## Implementation order

### Phase 1: smb2 CI tests (immediate value)

1. Create base Dockerfile (Alpine + Samba)
2. Create internal containers: smb-guest, smb-auth, smb-signing, smb-readonly
3. Write `tests/docker_integration.rs` covering basic ops, auth, signing, read-only errors
4. Add CI job to run Docker tests on every PR
5. Verify: all Docker tests pass, CI green
6. Add remaining internal containers (smb-ancient, smb-flaky, smb-slow, smb-encryption, smb-50shares, smb-maxreadsize)
7. Add tests for those containers

### Phase 2: Consumer test harness (after client API settles)

8. Create consumer containers: smb-consumer-guest, smb-consumer-auth, smb-consumer-both
9. Build `smb2::testing` module (TestServers struct, docker compose lifecycle, health checks)
10. Add remaining consumer containers (unicode, longnames, deepnest, manyfiles, readonly, windows, synology)
11. Help Cmdr migrate from its own Docker infra to `smb2::testing`

Phase 2 depends on the client API being stable enough that consumers aren't coupling to a moving target. Phase 1 has no
such constraint and provides immediate value.

## Resource profile and lifecycle

### Container resources

| Profile                         | Containers | Disk (shared base) | RAM (idle)  | RAM (peak) |
|---------------------------------|------------|--------------------|-------------|------------|
| smb2 CI (all internal)          | 10         | ~80 MB             | ~200-300 MB | ~400 MB    |
| Consumer minimal (guest + auth) | 2          | ~55 MB             | ~60 MB      | ~100 MB    |
| Consumer all                    | 11         | ~150 MB            | ~300 MB     | ~500 MB    |

Alpine + Samba base image is ~50 MB. Each container adds ~1 MB
(an `smb.conf` and maybe a startup script). Docker layer sharing
means 10 containers don't cost 10x the base image.

### Startup and teardown timing

- `docker compose up` (all containers in parallel): 2-3 seconds
- Health check (TCP port open): 1-2 seconds
- `docker compose down`: 1-2 seconds
- **Total overhead: ~5 seconds startup + ~2 seconds teardown**

Most individual tests are sub-second. Exceptions:
- `smb-slow` tests: 500ms+ per round-trip (intentional)
- `smb-flaky` tests: need to wait for server cycle (5-10 seconds)

A full CI run (startup + all tests + teardown) should take under
90 seconds.

### Lifecycle: start once per suite, not per test

Spinning up Docker containers takes seconds. Per-test startup
would add 2-5 seconds per test, which is not acceptable.

**smb2 CI:** Start all internal containers once before
`cargo test`, stop after. The CI job does this explicitly via
`start.sh` / `stop.sh`.

**Consumers:** The `TestServers` struct should live for the
duration of a test suite. Recommended pattern:

```rust
use std::sync::LazyLock;
use smb2::testing::TestServers;

static SERVERS: LazyLock<TestServers> = LazyLock::new(|| {
    TestServers::start_blocking().unwrap()
});

#[tokio::test]
async fn test_guest_listing() {
    let guest = SERVERS.guest_client().await.unwrap();
    let shares = guest.list_shares().await.unwrap();
    assert!(!shares.is_empty());
}

#[tokio::test]
async fn test_auth_listing() {
    let auth = SERVERS.auth_client("testuser", "testpass").await.unwrap();
    // ...
}
```

Containers start on first test, stop on process exit. Zero
overhead after the initial 2-3 seconds.

### Intentionally slow tests

The `smb-slow` and `smb-flaky` containers exist to test behavior
under adverse conditions. Their tests will be slower than
everything else by design. If the CI test suite suddenly takes
much longer, look at these tests first — but don't assume
they're broken just because they're slow.

## Relationship to real-hardware tests

The `#[ignore]` tests against David's NAS and Pi stay. They test against real commercial hardware (QNAP, Raspberry Pi)
which may have quirks that Docker Samba doesn't reproduce. Docker tests are the primary safety net (CI, every PR).
Hardware tests are secondary validation (David runs locally).
