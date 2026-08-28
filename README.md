# smb2 workspace

[![CI](https://github.com/vdavid/smb2/actions/workflows/ci.yml/badge.svg)](https://github.com/vdavid/smb2/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

Pure-Rust SMB2/3 for talking to a file share over the network. No `libsmbclient`, no FFI, no mounting. Async,
runtime-agnostic, and faster than the native macOS SMB client on uploads, downloads, listings, and deletes.

This repo ships two crates:

| Crate | What it is | Page |
|---|---|---|
| **[`smb2`](crates/smb2/)** | The library. Use it from your own Rust code. | [crates.io](https://crates.io/crates/smb2) · [docs.rs](https://docs.rs/smb2) |
| **[`smb2-cli`](crates/smb2-cli/)** | A ready-made `smb2` binary. `cargo install smb2-cli`. | [crates.io](https://crates.io/crates/smb2-cli) |

For the API, the benchmarks, the protocol features covered, and the servers it's tested against, see the
[`smb2` README](crates/smb2/README.md).

For the command line, see the [`smb2-cli` README](crates/smb2-cli/README.md).

The CLI depends on the library by path, so a protocol fix and the CLI change that uses it land together instead of
waiting on a release.

## Sister projects

- [Cmdr](https://github.com/vdavid/cmdr): an AI-native file manager that uses `smb2` for SMB access.
- [mtp-rs](https://github.com/vdavid/mtp-rs): the same idea for MTP, so a phone or camera is reachable without
  `libmtp`.

## Development

```sh
just            # fast checks: fmt, clippy, test, doc
just check-all  # plus MSRV, security audit, license check
just fix        # auto-fix formatting and clippy warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more, and [docs/releasing.md](docs/releasing.md) for how a release goes out.

## License

MIT OR Apache-2.0, at your option.
