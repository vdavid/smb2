# Docker test infrastructure plan

Adopt Cmdr's Docker-based SMB test server suite for comprehensive
protocol testing. 16 Samba containers covering auth, edge cases,
stress, and compatibility scenarios.

## Why

Our current integration tests hit two real servers (QNAP + Pi). This
covers the happy path but misses:

- Flaky connections (reconnect logic)
- High-latency servers (pipelining advantage)
- Mandatory signing (we handle it but haven't tested it)
- Unicode paths (UTF-16LE edge cases)
- Long filenames (200+ chars)
- Read-only shares (write error handling)
- SMB1-only servers (graceful rejection)
- Large share counts (share enumeration at scale)
- Large file counts (listing performance)
- Deep directory nesting (path handling)

## What we adopt from Cmdr

Source: `cmdr/apps/desktop/test/smb-servers/`

### Docker containers (16 servers)

| Container | Port | What it tests |
|---|---|---|
| smb-guest | 9445 | Guest-only access |
| smb-auth | 9446 | Credentials required (testuser/testpass) |
| smb-both | 9447 | Guest allowed + authenticated |
| smb-flaky | 9448 | 5s up / 5s down cycling |
| smb-50shares | 9449 | 50 shares on one host |
| smb-slow | 9450 | 500ms+ artificial latency |
| smb-readonly | 9451 | Read-only share |
| smb-ancient | 9452 | SMB1/NT1 only |
| smb-signing | 9453 | Mandatory signing |
| smb-unicode | 9454 | Unicode share names (日本語, émojis📁) |
| smb-longnames | 9455 | 200+ char filenames |
| smb-deepnest | 9456 | 50-level deep directory tree |
| smb-manyfiles | 9457 | 10k+ files |
| smb-like-windows | 9458 | Windows Server string |
| smb-like-synology | 9459 | Synology NAS mimicry |
| smb-like-linux | 9460 | Default Linux Samba |

### Files to copy

```
tests/docker/
  docker-compose.yml          # All 16 containers
  start.sh                    # Launch script (minimal/core/all)
  stop.sh                     # Cleanup
  containers/
    smb-base/
      Dockerfile              # Alpine + Samba base image
      entrypoint.sh
      smb.conf.template
    smb-guest/Dockerfile
    smb-auth/Dockerfile
    smb-both/Dockerfile
    smb-flaky/
      Dockerfile
      entrypoint.sh           # 5s up/down cycling
    smb-50shares/Dockerfile
    smb-slow/
      Dockerfile
      entrypoint.sh           # tc qdisc latency injection
    smb-readonly/Dockerfile
    smb-ancient/Dockerfile
    smb-signing/Dockerfile
    smb-unicode/Dockerfile
    smb-longnames/
      Dockerfile
      setup-files.sh          # Creates long-named files
    smb-deepnest/
      Dockerfile
      setup-files.sh          # Creates 50-level nesting
    smb-manyfiles/
      Dockerfile
      setup-files.sh          # Creates 10k files
    smb-like-windows/Dockerfile
    smb-like-synology/Dockerfile
    smb-like-linux/Dockerfile
```

### Deployment modes

- **minimal** (2 containers, ~100 MB): smb-guest + smb-auth
- **core** (6 containers, ~300 MB): + smb-both, smb-flaky, smb-readonly, smb-signing
- **all** (16 containers, ~800 MB): everything

## Test file structure

```
tests/
  docker_integration.rs       # Docker-based tests (gated)
  integration.rs              # Existing real-hardware tests
  wire_format_captures.rs     # Existing wire format tests
```

### Gating

Docker tests run only when `SMB2_DOCKER_TESTS=1` env var is set:

```rust
fn require_docker() {
    if std::env::var("SMB2_DOCKER_TESTS").is_err() {
        eprintln!("Skipping: set SMB2_DOCKER_TESTS=1 to run Docker tests");
        return;
    }
}
```

Normal `cargo test` skips them. CI can run them with Docker.

### Test plan by container

**smb-guest (port 9445):**
- Connect with empty credentials
- List shares
- List directory, read file, write file, delete
- Compound read and write
- Streaming download and upload
- fs_info (disk space)

**smb-auth (port 9446):**
- Connect with testuser/testpass
- Reject wrong password (clean error, not hang)
- All file operations work after auth
- Signing is active (non-guest session)

**smb-both (port 9447):**
- Guest access works (no signing)
- Authenticated access works (with signing)
- Both see the same files

**smb-flaky (port 9448):**
- Connect, do operation, wait for disconnect
- Verify Error::Disconnected returned (not hang)
- reconnect() works after disconnect
- Operations succeed after reconnect

**smb-50shares (port 9449):**
- list_shares() returns all 50
- Connect to specific shares by name
- Share names are correct

**smb-slow (port 9450):**
- Connect (with adequate timeout)
- Pipelined read is faster than sequential (latency hiding)
- Operations complete (don't timeout prematurely)
- Compare: compound read vs sequential on slow link

**smb-readonly (port 9451):**
- Read operations succeed
- Write operations fail with clean error
- Delete fails with clean error
- list_directory works
- stat works

**smb-ancient (port 9452):**
- Negotiate falls back to SMB 2.0.2 or 2.1 (not SMB1)
- If server only speaks SMB1, we get a clean error (not hang or crash)
- Test that we don't accidentally speak SMB1

**smb-signing (port 9453):**
- Connect requires signing
- All operations work with signing active
- Verify signing_required=true in NegotiatedParams
- Tampering with a signed message fails verification

**smb-unicode (port 9454):**
- list_shares() returns Unicode names correctly
- Connect to shares with Unicode names
- Read/write files with Unicode filenames
- Path normalization handles Unicode

**smb-longnames (port 9455):**
- List directory with 200+ char filenames
- Read file with long name
- Write file with long name
- Verify names aren't truncated

**smb-deepnest (port 9456):**
- Navigate 50 levels deep
- List directory at each level
- Read file at deepest level
- Path construction handles deep nesting

**smb-manyfiles (port 9457):**
- list_directory with 10k+ files (performance test)
- Verify all entries returned (no truncation)
- Time the listing, compare with expected performance

**smb-like-windows/synology/linux (ports 9458-9460):**
- Connect and negotiate (dialect may vary)
- All basic operations work
- Server identification (server string) is readable

## Testing module for Cmdr (optional, feature-gated)

A `smb2::testing` module that provides pre-connected clients for
each Docker server type. Cmdr can use this instead of managing
connections itself in tests.

```rust
// In smb2, feature = "testing"
pub mod testing {
    pub struct DockerServers {
        pub guest: SmbClient,
        pub auth: SmbClient,
        pub readonly: SmbClient,
        // ...
    }

    impl DockerServers {
        pub async fn connect() -> Result<Self> {
            // Connect to all running Docker containers
            // Skip containers that aren't running
        }
    }
}
```

This is optional and lower priority than the test suite itself.

## Known issues from Cmdr's experience

1. **NDR64 incompatibility:** The `smb` crate uses NDR64 for RPC,
   which Docker Samba doesn't support. Our smb2 uses NDR (not NDR64),
   so this should work fine. Verify with smb-guest.

2. **macOS Docker networking:** SMB connections sometimes break with
   "Broken pipe" because macOS Docker runs in a VM. The Pi with
   macvlan networking is more reliable for realistic testing.

3. **Port range:** All containers use ports 9445-9460 (non-standard)
   to avoid conflicts with real SMB on port 445.

## Implementation order

1. Copy Docker infrastructure from Cmdr (containers + compose)
2. Write `tests/docker_integration.rs` with tests for core servers
   (guest, auth, readonly, signing)
3. Add tests for edge cases (unicode, longnames, deepnest, manyfiles)
4. Add tests for stress scenarios (flaky, slow, 50shares)
5. Add CI job that starts Docker containers and runs the tests
6. (Optional) Add `smb2::testing` module for Cmdr

## CI integration

Add a separate CI job that only runs on push to main (not on PRs,
to save credits):

```yaml
docker-tests:
  name: Docker integration tests
  runs-on: ubuntu-latest
  if: github.event_name == 'push'
  steps:
    - uses: actions/checkout@v5
    - name: Start SMB containers (core)
      run: ./tests/docker/start.sh core
    - name: Run Docker tests
      run: SMB2_DOCKER_TESTS=1 cargo test --test docker_integration
      env:
        RUST_LOG: smb2=debug
    - name: Stop containers
      if: always()
      run: ./tests/docker/stop.sh
```

## What we don't build

- **Virtual SMB server in-process.** Too much effort (SMB2 state
  machine is complex). Docker containers are real Samba and test
  real protocol behavior. The MockTransport covers unit testing.

- **SMB1 support.** The smb-ancient container tests that we reject
  SMB1 gracefully, not that we speak it.

- **Flaky server simulation in-process.** The Docker container with
  5s up/down cycling is simpler and more realistic than simulating
  network failures in code.
