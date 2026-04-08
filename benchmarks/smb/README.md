# SMB benchmark

Three-way comparison of SMB file operations:

1. **Native**: OS-mounted SMB via `std::fs`
2. **smb**: `smb` crate (third-party Rust SMB client)
3. **smb2**: our `smb2` crate (pure-Rust pipelined SMB2/3 client)

Measures upload, list, download, and delete across configurable file sizes, counts, and NAS targets.

## Setup

1. Copy `config.example.toml` to `config.toml` and fill in your NAS details (credentials, share name, IP). `config.toml`
   is gitignored.
2. Mount each share in Finder (`smb://<ip>/`) so the native path (for example `/Volumes/naspi`) exists.

## Running

```sh
cargo run -p smb-benchmark --release
```

### Flags

- `--skip-smb` skips the `smb` crate runner entirely. Useful when the smb crate hangs or you only want to compare
  native vs smb2.
- `--cleanup-only` removes leftover test directories on all targets without running benchmarks.
- Set `RUST_LOG=debug` for verbose SMB protocol logs.

Release mode matters: without it, local file I/O and data generation are noticeably slower.

## Interpreting results

The benchmark prints a table with median times per operation and two ratio columns:

- **smb2/nat**: smb2 time / native time. Values < 1.0 mean smb2 is faster than native.
- **smb2/smb**: smb2 time / smb crate time. Values < 1.0 mean smb2 is faster than the smb crate.

Each suite runs multiple iterations (after a warmup run). The order of all three methods is randomized per iteration to
reduce cache bias. Each iteration uses a unique directory name to avoid stale SMB cache reads.

Each operation has a 90-second timeout. If an operation times out, "TIMEOUT" is shown instead of a time, and the
benchmark continues with the next operation.

JSON results are saved to `results/` with a timestamp.

## `sspi` version pin

`sspi` 0.18.9 breaks NTLM auth when the `kerberos` feature isn't enabled. We pin `sspi = "=0.18.7"` until that's fixed
upstream.
