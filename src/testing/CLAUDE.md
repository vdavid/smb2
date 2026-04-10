# Testing module -- Docker-based SMB test servers

Feature-gated (`testing` feature flag). Provides Docker-based Samba containers for consumers (apps that depend on smb2) to test their SMB integration.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `TestServers`, `Error`, port constants, embedded Docker files, `write_compose_files()` |

## Architecture

Three-layer testing model:

1. **Layer 1 (Rust)**: `TestServers::start()` / `start_all()` / `start_blocking()` return a struct with `*_client()` methods that connect to Docker containers.
2. **Layer 2 (E2E)**: `write_compose_files(dir)` extracts embedded Docker infrastructure to disk for non-Rust test frameworks.
3. **Layer 3 (Manual QA)**: Same compose files, run manually.

## Embedded files

All 35 Docker files (compose, Dockerfiles, smb.conf, scripts) are embedded via `include_str!` at compile time. At runtime, `write_compose_files()` writes them to a temp directory. Docker Compose runs from there.

## Port scheme

14 containers on ports 10480-10493. Each port has an env-var override (`SMB_CONSUMER_*_PORT`). The `port()` function checks the env var, falls back to the hardcoded default.

## Profiles

- **Minimal**: guest + auth only (2 containers, fast startup).
- **All**: all 14 containers.

Calling a `*_client()` method for a container not in the current profile returns `Error::ContainerNotStarted`.

## Key decisions

| Decision | Choice | Why |
|---|---|---|
| No extra deps | `std::process::Command` for Docker | Keep the crate lean |
| Temp dir via `std::env::temp_dir()` | No `tempfile` crate | No extra deps |
| Embedded files via `include_str!` | Self-contained published crate | Consumers don't need smb2 source tree |
| Separate error type | `testing::Error` vs `smb2::Error` | Docker failures are not protocol errors |
| Best-effort cleanup in Drop | `docker compose down` | LazyLock statics never drop, so this is convenience only |

## Gotchas

- **LazyLock statics never drop**: `TestServers::drop()` won't run at process exit. CI should use explicit cleanup steps.
- **Flaky container has no health check**: The 5s-up/5s-down cycle means health checks would randomly fail. `wait_healthy()` skips it.
- **DFS is disabled on test clients**: Consumer containers don't set up DFS. The `connect_guest` / `connect_auth` helpers set `dfs_enabled: false`.
