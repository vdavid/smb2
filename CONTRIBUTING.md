# Contributing to smb2

Thanks for considering contributing! This document covers the practical stuff you need to know.

## Getting started

```bash
git clone https://github.com/vdavid/smb2
cd smb2
cargo build
cargo test
```

You don't need an SMB server for most development. The test suite uses mock transports for protocol logic.

### Dev tools

We use [`just`](https://github.com/casey/just) as a command runner. Install it, then:

```bash
just            # Run all checks: format, lint, test, doc
just fix        # Auto-fix formatting and clippy warnings
just check-all  # Include MSRV check, security audit, and license check
```

Run `just --list` to see all available commands.

### MSRV (minimum supported Rust version)

We support Rust 1.85. Before submitting PRs, verify MSRV compatibility:

```bash
rustup toolchain install 1.85.0  # One-time setup
just msrv                         # Check MSRV compatibility
```

This catches issues that only appear on older Rust versions. CI runs this check, so `just msrv` locally saves a round-trip.

## Project structure

```
src/
├── lib.rs              # Crate root
├── error.rs            # Error types, NTSTATUS mapping
├── pack/               # Binary serialization (ReadCursor, WriteCursor)
├── types/              # Newtypes (SessionId, TreeId, FileId, etc.)
├── msg/                # Wire format message structs
├── transport/          # Transport trait, TCP implementation, mock
├── crypto/             # Signing, encryption, key derivation
├── auth/               # NTLM authentication
└── client/             # High-level API (SmbClient, Tree, Pipeline)

tests/
├── pack_roundtrip.rs   # Property-based tests for pack/unpack
├── msg_wire_format.rs  # Test messages against known byte sequences
├── protocol_flow.rs    # Full protocol flows with mock transport
└── integration.rs      # Tests against real Samba server (Docker)
```

## Running tests

```bash
# Unit tests (no server needed)
cargo test

# Integration tests (requires Docker Samba)
cargo test --test integration -- --ignored --nocapture
```

Integration tests need a Samba server running in Docker. See the test file for setup instructions.

## Code style

We follow standard Rust conventions with a few specific choices:

- `#![forbid(unsafe_code)]` — no unsafe code, ever
- `#![warn(missing_docs)]` — doc comments for all public APIs
- Hand-rolled binary serialization (no proc macros for wire format)
- Newtypes for protocol IDs (`SessionId`, `TreeId`, `FileId`, etc.)
- `thiserror` for error types

The quick version:

- Run `just` before committing (or `just fix` to auto-fix issues)
- Tests for new functionality
- Doc comments for public APIs

## Architecture decisions

A few things that might not be obvious:

- **Single crate:** Everything lives in one crate (like mtp-rs). Keeps things simple, avoids cross-crate dependency management.
- **Hand-rolled pack/unpack:** We serialize SMB messages manually with `ReadCursor`/`WriteCursor` instead of using derive macros. Full control, easier to debug protocol issues, and the wire format has too many variable-length fields and padding rules for serde to handle well.
- **`dyn Transport`:** The transport layer uses trait objects (`async_trait`) instead of generics. Simpler API, and the overhead is negligible compared to network I/O.
- **Pipeline as a core feature:** The pipeline isn't an optimization bolted on later. It's the reason this library exists. The credit window, message sequencing, and compounding are all designed around it.
- **Runtime-agnostic:** We don't depend on tokio directly. Use `futures` traits. Tokio is a dev-dependency for running async tests.

## What we're looking for

- Testing with real SMB servers (Windows, Samba, NAS devices) and reporting results
- Bug reports with reproduction steps
- Protocol edge cases (compound failures, credit management, etc.)
- Doc improvements

## What we're not looking for right now

- Server implementation (this is a client library)
- QUIC or RDMA transport
- Kerberos authentication (planned but not yet)
- SMB1 support (deprecated, insecure)

These might come later, but they're not the current focus.

## The protocol

If you need to understand SMB2/3, the spec files in `docs/specs/` are the primary reference. The implementation plan at `docs/specs/implementation-plan.md` has a good overview of the protocol flow and known pitfalls.

The protocol is essentially:

1. Negotiate capabilities (dialect, signing, encryption)
2. Authenticate (NTLM challenge/response)
3. Connect to a share (tree connect)
4. Open files, read/write/list, close files
5. Disconnect

Everything is little-endian on the wire (except the TCP transport framing, which is big-endian). Strings are UTF-16LE.

## Submitting changes

1. Fork and create a branch
2. Make your changes
3. Run `just` (checks format, lint, test, and doc)
4. Run `just msrv` to verify Rust 1.85 compatibility
5. If you have a Samba server, run integration tests
6. Open a PR with a clear description including how you tested your changes

For non-trivial changes, consider opening an issue first to discuss the approach.

## Questions?

Open an issue. Happy to chat!
