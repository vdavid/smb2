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
- **Ports**: 10445-10457 for internal, 10480-10493 for consumer (high ports, no conflicts with real SMB on 445 or
  other dev services, with room for ~20 more internal containers between the ranges)
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
mtp-rs's `virtual-device` feature: enable a feature flag, get test servers for free.

The internal containers (Feature 1) test "does our SMB implementation conform to the spec?" The consumer containers
test "does your app handle the real world?" Consumers trust smb2 to handle signing, encryption, and protocol edge
cases. They need servers that represent what their users encounter: a NAS with guest access, a NAS requiring login, a
server with lots of shares, a server with unicode names, a flaky connection, a slow link, etc.

### Embedded infrastructure

Consumers can't access compose files from smb2's source tree once they depend on the published crate. The `testing`
module solves this by embedding all Docker infrastructure (compose file, Dockerfiles, smb.conf files, startup scripts)
as Rust `const &str` constants using `include_str!`. At runtime, `TestServers::start()` writes these to a temp
directory and runs `docker compose up` from there. This is fully self-contained: enable the feature flag, get test
servers. No need to clone the smb2 repo or copy files around.

For Layers 2 and 3 (below), the `testing` module also provides a `TestServers::write_compose_files(path)` method that
writes the embedded infrastructure to a directory of the consumer's choice, so non-Rust tools can use the same
containers.

**Temp directory structure.** `write_compose_files` (and `start()` internally) creates a self-contained directory that
mirrors the source tree layout Docker expects:

```
<dir>/
  docker-compose.yml
  base/Dockerfile
  smb-consumer-guest/
    Dockerfile
    smb.conf
  smb-consumer-auth/
    Dockerfile
    smb.conf
  ...
```

Each container's `Dockerfile` uses `build: ./smb-consumer-guest` (relative to the compose file), so Docker's build
context resolves correctly from the temp directory. No symlinks or references back to the smb2 source tree.

### Three-layer testing model

The consumer harness serves three testing layers:

**Layer 1: Rust integration tests** -- Fast, targeted tests via `TestServers` API. Consumers write `#[tokio::test]`
functions that get pre-connected `SmbClient` instances. Sub-millisecond per test after initial container startup.

**Layer 2: E2E tests via Docker containers** -- Playwright, Cypress, or other frameworks connect to containers at
known ports. No Rust needed. Use `TestServers::write_compose_files("./test-infra")` to extract the embedded
compose files, then run `docker compose up` from there.

**Layer 3: Manual QA via Docker containers** -- Developer extracts compose files once, then runs `docker compose up`
and browses virtual servers in their app during development. Same containers, same ports, no test framework involved.

Containers are the primary artifact. `TestServers` is a convenience wrapper for Rust consumers.

### Containers

14 containers, each with pre-populated data so tests and manual QA have something to work with immediately.

| Container | Default Port | Pre-populated data                         | What apps test                                |
|-----------|--------------|--------------------------------------------|-----------------------------------------------|
| guest     | 10480        | Sample files in public/                    | Guest access works end-to-end                 |
| auth      | 10481        | Sample files in private/                   | Login flow works                              |
| both      | 10482        | public/ (guest) + private/ (auth)          | Mixed auth: guest allowed, auth extends       |
| 50shares  | 10483        | 50 shares with sample files                | Share list UI, scrolling, search              |
| unicode   | 10484        | Files/dirs with CJK, emoji, accented chars | Non-ASCII rendering                           |
| longnames | 10485        | 200+ char filenames                        | Path truncation, tooltips                     |
| deepnest  | 10486        | 50-level deep tree                         | Breadcrumb, navigation, path bar overflow     |
| manyfiles | 10487        | 10k+ files in one dir                      | Listing perf, virtual scroll                  |
| readonly  | 10488        | Sample files, read-only share              | Disable write UI, clean errors                |
| windows   | 10489        | Windows-like server string                 | OS detection, server-specific icons           |
| synology  | 10490        | Synology-like server string + TimeMachine  | NAS-specific UI, backup detection             |
| linux     | 10491        | Default Linux Samba string                 | Baseline server, most common real-world type  |
| flaky     | 10492        | Sample files                               | Error recovery UI, reconnect handling         |
| slow      | 10493        | Sample files                               | Loading spinners, progress bars, timeouts     |

The internal containers include flaky and slow for protocol testing (reconnect logic, pipelining advantage). The
consumer containers include them too because consumers care about UX under adverse conditions: does the error recovery
UI work? Do spinners appear? Do timeouts fire correctly? Same infrastructure, different testing purpose.

No smb-ancient, smb-encryption, smb-signing, smb-maxreadsize, or DFS containers here. Those test protocol internals
that consumers don't interact with directly. Consumers trust smb2 to handle DFS transparently; DFS containers are for
internal protocol testing only.

### Server string realism (windows, synology containers)

The "windows" and "synology" containers set the `server string` parameter in `smb.conf`. This string appears in srvsvc
RPC responses (NetServerGetInfo, level 101) which is how `list_shares()` discovers server metadata. It does NOT appear
in the SMB2 negotiate exchange -- the negotiate response has no server identification field.

What this enables: apps can test OS-detection logic that reads the server string from RPC to show different icons or
enable NAS-specific features (for example, Time Machine detection on Synology).

What this does NOT fake: actual Windows or Synology SMB behavior. The underlying server is still Samba on Alpine Linux.
Protocol-level quirks specific to Windows Server or Synology DSM (for example, different default MaxReadSize, different
DFS behavior) are not reproduced. For testing against real Windows, use the Kerberos/AD test environment documented in
`tests/CLAUDE.md`.

### Configurable ports via env vars

Compose files use `${SMB_CONSUMER_GUEST_PORT:-10480}:445` patterns so consumers can override ports to avoid conflicts
with their own services:

```yaml
# docker-compose.yml (consumer)
services:
  guest:
    ports:
      - "${SMB_CONSUMER_GUEST_PORT:-10480}:445"
  auth:
    ports:
      - "${SMB_CONSUMER_AUTH_PORT:-10481}:445"
  # ...
```

`TestServers` uses hardcoded default ports as Rust constants in the `testing` module (for example,
`const GUEST_PORT: u16 = 10480`). Env vars override the defaults (for example, `SMB_CONSUMER_GUEST_PORT=11480`). No
YAML parsing, no extra dependencies. The embedded compose files use the same env-var names with the same defaults, so
both paths stay in sync. Consumers who use the compose files directly (Layers 2 and 3) set env vars or accept the
defaults.

### API

```rust
use smb2::testing::TestServers;

// Start minimal set (guest + auth, fast)
let servers = TestServers::start().await?;

// Or start everything
let servers = TestServers::start_all().await?;

// Get pre-connected clients
let mut guest = servers.guest_client().await?;
let mut auth = servers.auth_client("testuser", "testpass").await?;

// Use like any SmbClient
let shares = guest.list_shares().await?;
let mut share = guest.connect_share("public").await?;  // mut required for list_directory
let entries = guest.list_directory(&mut share, "").await?;

// Containers stop on drop
drop(servers);
```

### Error type

The testing module has its own error type to keep Docker/process noise out of `smb2::Error`:

```rust
/// Errors from the test infrastructure (Docker, process, port discovery).
/// Separate from smb2::Error because these are test-setup failures, not protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("docker command failed: {0}")]
    Docker(std::io::Error),

    #[error("container not started: call start_all() to start all containers")]
    ContainerNotStarted,

    #[error("container health check timed out after {0:?}")]
    HealthCheckTimeout(std::time::Duration),

    #[error("smb connection failed: {0}")]
    Smb(smb2::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
```

### TestServers

```rust
/// Docker-based SMB test servers for integration testing.
///
/// Starts Samba containers on construction, stops on drop. Each
/// server type has a factory method returning a connected SmbClient.
///
/// Consumers can also skip TestServers entirely and use the compose
/// files directly for E2E or manual testing.
pub struct TestServers {
    /* ... */
}

impl TestServers {
    /// Start minimal set: guest + auth (~55 MB disk, ~2s).
    pub async fn start() -> testing::Result<Self>;

    /// Start all consumer containers (~800 MB, ~5s).
    pub async fn start_all() -> testing::Result<Self>;

    /// Blocking version for use in LazyLock statics.
    pub fn start_blocking() -> testing::Result<Self>;

    /// Write embedded compose files to a directory (for Layers 2 and 3).
    pub fn write_compose_files(dir: &Path) -> testing::Result<()>;

    /// Guest-access server. No credentials needed.
    pub async fn guest_client(&self) -> testing::Result<SmbClient>;

    /// Auth-required server. Needs username + password.
    pub async fn auth_client(&self, user: &str, pass: &str) -> testing::Result<SmbClient>;

    /// Mixed server, guest connection. Can access "public" share only.
    pub async fn both_client(&self) -> testing::Result<SmbClient>;
    /// Mixed server, authenticated connection. Can access both "public" and "private" shares.
    pub async fn both_client_auth(&self, user: &str, pass: &str) -> testing::Result<SmbClient>;

    /// Read-only server. Writes return errors.
    pub async fn readonly_client(&self) -> testing::Result<SmbClient>;

    /// Server with 50 shares.
    pub async fn many_shares_client(&self) -> testing::Result<SmbClient>;

    /// Server with unicode share/file names.
    pub async fn unicode_client(&self) -> testing::Result<SmbClient>;

    /// Server with 200+ char filenames. Tests path truncation.
    pub async fn longnames_client(&self) -> testing::Result<SmbClient>;

    /// Server with 50-level deep directory tree. Tests navigation overflow.
    pub async fn deepnest_client(&self) -> testing::Result<SmbClient>;

    /// Server with 10k+ files.
    pub async fn many_files_client(&self) -> testing::Result<SmbClient>;

    /// Windows-like server (server string in smb.conf). Tests OS detection.
    pub async fn windows_client(&self) -> testing::Result<SmbClient>;

    /// Synology-like server (server string in smb.conf). Tests NAS-specific UI.
    pub async fn synology_client(&self) -> testing::Result<SmbClient>;

    /// Flaky server (5s up / 5s down). Tests error recovery UI.
    pub async fn flaky_client(&self) -> testing::Result<SmbClient>;

    /// Slow server (200ms latency). Tests loading states and timeouts.
    pub async fn slow_client(&self) -> testing::Result<SmbClient>;

    /// Generic Linux Samba server. Most common real-world server type.
    pub async fn linux_client(&self) -> testing::Result<SmbClient>;
}

impl Drop for TestServers {
    fn drop(&mut self) { /* best-effort: docker compose down */ }
}
```

**Non-started container behavior:** Methods for containers that weren't started (for example, calling
`unicode_client()` after `start()` which only starts guest + auth) return `Err(testing::Error::ContainerNotStarted)`.
The error message suggests calling `start_all()`. Containers are never lazily started -- explicit is better than
implicit, and surprise Docker pulls in the middle of a test run are not acceptable.

```rust
// This fails clearly:
let servers = TestServers::start().await?;       // only guest + auth
let uc = servers.unicode_client().await;         // Err(ContainerNotStarted)

// This works:
let servers = TestServers::start_all().await?;   // all 14 containers
let uc = servers.unicode_client().await?;        // Ok(SmbClient)
```

Port discovery uses hardcoded Rust constants with env-var overrides. No YAML parsing needed. Consumers who don't use
`TestServers` get the same ports from the embedded compose files or by setting the same env vars.

### Feature gating

```toml
[features]
testing = []  # Enables smb2::testing module

# No extra deps. Uses std::process::Command for docker compose.
```

### How Cmdr would use it

**Layer 1: Rust tests with TestServers** (SMB subsystem tests)

```rust
// Cmdr's SMB integration tests
use std::sync::LazyLock;
use smb2::testing::TestServers;

static SERVERS: LazyLock<TestServers> = LazyLock::new(|| {
    TestServers::start_blocking().unwrap()
});

#[tokio::test]
async fn test_guest_browse() {
    let mut guest = SERVERS.guest_client().await.unwrap();
    let shares = guest.list_shares().await.unwrap();
    assert!(!shares.is_empty());
}

#[tokio::test]
async fn test_error_recovery_after_flaky_disconnect() {
    let mut flaky = SERVERS.flaky_client().await.unwrap();
    // verify app-level error handling, not protocol internals
}
```

**Layer 2: E2E with Playwright** (UI tests)

```javascript
// playwright.config.ts -- virtual_smb_hosts injects container hosts
const smbHosts = {
  guest: `localhost:${process.env.SMB_CONSUMER_GUEST_PORT || 10480}`,
  auth: `localhost:${process.env.SMB_CONSUMER_AUTH_PORT || 10481}`,
  // ...
};

// test: browse guest server in the app
test('guest server shows files', async ({ page }) => {
  await page.goto('/browse/virtual-smb-guest');
  await expect(page.locator('.file-list')).toContainText('sample.txt');
});
```

**Layer 3: Manual QA** (developer browses virtual servers)

```rust
// Extract embedded compose files to a local directory (one-time)
smb2::testing::TestServers::write_compose_files(Path::new("./test-infra")).unwrap();
```

```sh
# Start all consumer containers
cd test-infra
docker compose up -d

# Browse virtual servers in the dev app -- they appear at known ports
# Guest at localhost:10480, auth at localhost:10481, etc.
```

Cmdr deletes its Docker files and server management code. The compose files, the `TestServers` wrapper, and the
raw ports all point to the same containers.

### Consumer-specific additions (docker-compose.override.yml)

For needs specific to a consumer (Pi deployment, macvlan networking, mDNS), use the standard
`docker-compose.override.yml` pattern:

```yaml
# Cmdr's docker-compose.override.yml (not in smb2 repo)
services:
  guest:
    networks:
      lan:
        ipv4_address: 192.168.1.200
    volumes:
      - ./avahi-guest.conf:/etc/avahi/services/smb.service
networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: eth0
```

This is a consumer-specific need (smb2 doesn't care about mDNS). Documented here so consumers know the pattern
exists.

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

- **Merged internal and consumer containers.** Internal containers test protocol conformance; consumer containers test
  app behavior. Some container types overlap (for example, both have a flaky server) but they serve different purposes
  and may diverge in configuration. Keeping them separate is cheap (~20-line Dockerfiles, ~50 MB each).

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

8. Create consumer compose file with env-var port patterns and core containers (guest, auth, both, readonly)
9. Add remaining containers (50shares, unicode, longnames, deepnest, manyfiles, windows, synology, linux, flaky, slow)
10. Add data-population scripts (sample files, unicode names, deep trees, 10k files, 50 shares) and wire them into container startup
11. Verify all 14 containers work standalone via `docker compose up` (Layer 3: manual QA)
12. Build `smb2::testing` module (TestServers struct, embedded compose files, hardcoded port constants with env-var overrides, `start_blocking()` for LazyLock)
13. Document `docker-compose.override.yml` pattern for consumer-specific additions
14. Help Cmdr migrate from its own Docker infra to the three-layer model

Phase 2 depends on the client API being stable enough that consumers aren't coupling to a moving target. Phase 1 has no
such constraint and provides immediate value.

## Resource profile and lifecycle

### Container resources

| Profile                         | Containers | Disk (shared base) | RAM (idle)  | RAM (peak) |
|---------------------------------|------------|--------------------|-------------|------------|
| smb2 CI (all internal)          | 10         | ~80 MB             | ~200-300 MB | ~400 MB    |
| Consumer minimal (guest + auth) | 2          | ~55 MB             | ~60 MB      | ~100 MB    |
| Consumer all                    | 14         | ~200 MB            | ~400 MB     | ~700 MB    |

Alpine + Samba base image is ~50 MB. Each container adds ~1 MB
(an `smb.conf` and maybe a startup script). Docker layer sharing
means 10 containers don't cost 10x the base image.

### Health checks

Each consumer container includes a Docker `HEALTHCHECK` instruction that verifies the Samba port is accepting
connections. `TestServers::start()` and `start_all()` wait for all started containers to report healthy before
returning. If a container doesn't become healthy within 30 seconds, `start()` returns
`Err(testing::Error::HealthCheckTimeout)`.

### Startup and teardown timing

- `docker compose up` (all containers in parallel): 2-3 seconds
- Health check (Docker HEALTHCHECK, TCP port open): 1-2 seconds
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
    let mut guest = SERVERS.guest_client().await.unwrap();
    let shares = guest.list_shares().await.unwrap();
    assert!(!shares.is_empty());
}

#[tokio::test]
async fn test_auth_listing() {
    let mut auth = SERVERS.auth_client("testuser", "testpass").await.unwrap();
    // ...
}
```

Containers start on first test (whichever test Rust's test harness
picks first), stop on process exit. The first test will be slow
(2-5 seconds for container startup + health checks). All subsequent
tests pay zero container overhead. This is inherent to the LazyLock
pattern -- if a test run appears to hang briefly at the start, this
is expected.

**Note on cleanup:** `LazyLock` statics are never dropped, so `TestServers::drop()` won't run at process exit.
Containers will be orphaned until manually stopped. Mitigations:

- **CI:** Use `if: always()` on the cleanup step (as shown in the CI integration section above) so `docker compose down`
  runs even if tests fail or the process is killed.
- **Local dev:** `start_blocking()` could register an `atexit` handler (via `libc::atexit` or a Ctrl-C signal handler)
  as a best-effort cleanup. This is a convenience, not a guarantee -- crashes and SIGKILL will still orphan containers.

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
