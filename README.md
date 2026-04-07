# smb2

[![Crates.io](https://img.shields.io/crates/v/smb2)](https://crates.io/crates/smb2)
[![docs.rs](https://img.shields.io/docsrs/smb2)](https://docs.rs/smb2)
[![CI](https://github.com/vdavid/smb2/actions/workflows/ci.yml/badge.svg)](https://github.com/vdavid/smb2/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/smb2)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

A pure-Rust SMB2/3 client library with pipelined I/O.
No C dependencies, no FFI. Downloads are ~10-25x faster than sequential SMB clients, and directory listings are ~2x faster than native macOS SMB.

I built this because I needed fast SMB access for [Cmdr](https://github.com/vdavid/cmdr) (my file manager), and the existing Rust SMB options weren't cutting it. The `smb` crate works fine for listing files but downloads are painfully slow because it sends one read at a time. Native OS SMB clients pipeline their reads, and so does this library.

**Why this matters:**

- Cross-compile without system lib headaches (no `libsmbclient`, no `-sys` crates)
- Pipelined I/O by default, not as an afterthought
- Async and runtime-agnostic (uses `futures` traits)
- Works anywhere Rust compiles

## What it does

- Connect to SMB2/3 shares using NTLM authentication
- List directories, read files, write files, delete, rename
- Pipeline operations: push requests into one end, results stream out the other
- Large file transfers chunked at the server's `MaxReadSize`/`MaxWriteSize`
- Credit-window-based flow control (the server tells us how fast to go)
- Handles SMB 3.x signing and encryption

## What it doesn't do (yet)

- Kerberos authentication (NTLM only for now)
- DFS path resolution (returns a clear error so you can handle it)
- QUIC transport (SMB over QUIC, for Azure Files)
- RDMA transport
- Server implementation (this is a client library)
- Multi-channel (multiple TCP connections to the same server)

## Quick start

```rust
use smb2::SmbClient;

#[tokio::main]
async fn main() -> Result<(), smb2::Error> {
    // Connect to a share
    let client = SmbClient::connect("192.168.1.100", "user", "password").await?;
    let share = client.connect_share("Documents").await?;

    // List files
    for entry in share.list("projects/").await? {
        println!("{} {:>10} bytes", entry.name, entry.size);
    }

    // Read a file
    let data = share.read_file("projects/report.pdf").await?;
    std::fs::write("report.pdf", data)?;

    Ok(())
}
```

## Pipeline API

The pipeline is the core feature. It lets you push requests from anywhere, at any time, and results stream back as they complete. You don't need to know the total count upfront.

```rust
let (tx, mut rx) = share.open_pipeline();

// Push requests — from any task, any time
tx.request(Op::ReadFile("a.txt")).await;
tx.request(Op::WriteFile("b.txt", data)).await;
tx.request(Op::Delete("c.txt")).await;
tx.request(Op::List("projects/")).await;

// Results stream back as they complete
while let Some(result) = rx.next().await {
    match result {
        OpResult::FileData(path, bytes) => { /* ... */ }
        OpResult::Written(path, n) => { /* ... */ }
        OpResult::Deleted(path) => { /* ... */ }
        OpResult::DirEntries(path, entries) => { /* ... */ }
        OpResult::Error(path, err) => { /* ... */ }
    }
}

// Drop tx to signal "no more requests" — pipeline drains gracefully
```

The simple API (`share.read_file()`, etc.) wraps this internally. One request in, one result out.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
smb2 = "0.1"
```

You'll also need an async runtime. The library is runtime-agnostic, but [tokio](https://github.com/tokio-rs/tokio) is the most common choice:

```toml
[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## API overview

### Simple API

For when you want to do one thing and get the result:

- `SmbClient::connect()` — connect and authenticate
- `share.list()` — list a directory
- `share.read_file()` — download a file
- `share.write_file()` — upload a file
- `share.delete()` — delete a file
- `share.stat()` — get file metadata

### Pipeline API

For when you have many operations and want them fast:

- `share.open_pipeline()` — returns `(tx, rx)` channel pair
- `tx.request(Op)` — push an operation (from any task)
- `rx.next()` — receive the next completed result

The pipeline handles credit management, chunking, compounding, and reordering internally. Multiple operations fly over the wire concurrently, bounded by the server's credit grants.

## Performance

SMB2/3 servers advertise `MaxReadSize` (typically 1-8 MB) and grant credits that allow multiple outstanding requests. Sequential clients ignore this and send one request at a time, leaving the TCP pipe idle most of the time.

This library fills the pipe. Based on testing against Samba:

- **Downloads:** ~10-25x faster than sequential (the `smb` crate's approach)
- **Directory listings:** ~2x faster than native macOS SMB (Finder/`ls`)
- **Mixed operations:** Pipeline handles reads, writes, deletes, and listings concurrently

The exact speedup depends on network latency and server configuration. Higher latency = bigger win from pipelining.

## Known limitations

| Limitation | Details |
|---|---|
| NTLM only | No Kerberos yet (NTLM works against Samba and most Windows servers) |
| No DFS | Returns `Error::DfsReferralRequired` with the path, you handle it |
| No multi-channel | Single TCP connection per client |
| SMB1 not supported | SMB2/3 only (SMB1 is deprecated and insecure) |

## Comparison with existing libraries

### vs `smb` crate

The [`smb`](https://crates.io/crates/smb) crate is the main Rust SMB2 option right now. It works for basic operations, but:

- No pipelining (one request at a time, ~10x slower for downloads)
- Almost no tests
- MIT-only license (this crate is MIT OR Apache-2.0)

I initially considered forking `smb`, but the architecture didn't support pipelining well, and adding it would have been a near-complete rewrite anyway.

### vs `pavao`

[`pavao`](https://crates.io/crates/pavao) wraps `libsmbclient` via FFI. It works, but you need `libsmbclient` installed, which means system package management, cross-compilation headaches, and all the fun that comes with C dependencies.

`smb2` is pure Rust. `cargo build` and done.

## Implementation notes

- I used Claude extensively for this implementation. The code has a comprehensive test suite (unit tests with mock transport, property tests with proptest, integration tests against Docker Samba), and it works for my use case in Cmdr. If you distrust AI-generated code, that's fair, but please check the tests and decide for yourself.
- The protocol implementation is based on Microsoft's [MS-SMB2 spec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/). I converted the relevant sections to Markdown so AI agents could work from them effectively. The spec files live in `docs/specs/`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT OR Apache-2.0, at your option.
