# smb2

[![Crates.io](https://img.shields.io/crates/v/smb2)](https://crates.io/crates/smb2)
[![docs.rs](https://img.shields.io/docsrs/smb2)](https://docs.rs/smb2)
[![CI](https://github.com/vdavid/smb2/actions/workflows/ci.yml/badge.svg)](https://github.com/vdavid/smb2/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/smb2)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

A pure-Rust SMB2/3 client library with pipelined I/O.
No C dependencies, no FFI. Faster than native macOS SMB across all operations — 1.3-5x faster on uploads, downloads, listings, and deletes.

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
- SMB 3.x signing, encryption, and LZ4 compression
- Share enumeration (list shares on a server)

## What it doesn't do (yet)

If you need any of these, check the [`smb`](https://crates.io/crates/smb) crate which supports them:

- **Kerberos authentication** -- NTLM only for now. Kerberos is needed for Active Directory environments that disable NTLM. Most home NAS setups (Synology, QNAP, Pi) use NTLM.
- **DFS path resolution** -- returns `Error::DfsReferralRequired` with the path so you can handle it yourself. Full automatic DFS follow-through is planned for post-1.0.
- **Multi-channel** -- multiple TCP connections to the same server for higher throughput. Planned for post-1.0.
- **QUIC transport** -- SMB over QUIC for Azure Files and Windows Server 2022+ over the internet
- **RDMA transport** -- datacenter-only, ultra-low-latency storage

These aren't planned:

- Server implementation (this is a client library)
- SMB1 (deprecated, insecure)

## Quick start

```rust
use smb2::{SmbClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), smb2::Error> {
    let mut client = smb2::connect("192.168.1.100:445", "user", "pass").await?;

    // List shares
    let shares = client.list_shares().await?;
    for share in &shares {
        println!("{} - {}", share.name, share.comment);
    }

    // Connect to a share
    let share = client.connect_share("Documents").await?;

    // List files
    let entries = client.list_directory(&share, "projects/").await?;
    for entry in &entries {
        println!("{} ({} bytes)", entry.name, entry.size);
    }

    // Read a file
    let data = client.read_file(&share, "report.pdf").await?;
    std::fs::write("report.pdf", data)?;

    // Write a file
    let content = std::fs::read("local_file.txt")?;
    client.write_file(&share, "remote_file.txt", &content).await?;

    // Clean up
    client.disconnect_share(&share).await?;

    Ok(())
}
```

## Pipeline API

The pipeline is the core feature. It lets you batch multiple operations and execute them together:

```rust
use smb2::{Pipeline, Op, OpResult};

# async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
let mut pipeline = Pipeline::new(client.connection_mut(), &share);

let results = pipeline.execute(vec![
    Op::ReadFile("a.txt".into()),
    Op::ReadFile("b.txt".into()),
    Op::ListDirectory("docs/".into()),
    Op::Delete("temp.txt".into()),
]).await;

for result in results {
    match result {
        OpResult::FileData { path, data } => println!("{}: {} bytes", path, data.len()),
        OpResult::DirEntries { path, entries } => println!("{}: {} entries", path, entries.len()),
        OpResult::Deleted { path } => println!("deleted {}", path),
        OpResult::Error { path, error } => eprintln!("{}: {}", path, error),
        other => println!("{:?}", other),
    }
}
# Ok(())
# }
```

For large file I/O, use the pipelined variants which fill the credit window:

```rust
# async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
// Pipelined I/O with sliding window for large files
let data = client.read_file_pipelined(&share, "big_file.iso").await?;
client.write_file_pipelined(&share, "copy.iso", &data).await?;
# Ok(())
# }
```

## Streaming I/O

For large files that don't fit in memory, use the streaming API. It downloads one chunk at a time and supports progress reporting and cancellation.

### Streaming download

```rust
use tokio::io::AsyncWriteExt;

# async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
let mut download = client.download(&share, "big_video.mp4").await?;
println!("Downloading {} bytes...", download.size());

let mut file = tokio::fs::File::create("big_video.mp4").await?;
while let Some(chunk) = download.next_chunk().await {
    let bytes = chunk?;
    file.write_all(&bytes).await?;
    println!("{:.1}%", download.progress().percent());
}
# Ok(())
# }
```

### Write with progress and cancellation

```rust
use std::ops::ControlFlow;

# async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
let data = std::fs::read("big_file.bin")?;
client.write_file_with_progress(&share, "remote.bin", &data, |progress| {
    println!("{:.1}%", progress.percent());
    ControlFlow::Continue(()) // return ControlFlow::Break(()) to cancel
}).await?;
# Ok(())
# }
```

All write methods (`write_file`, `write_file_pipelined`, `write_file_with_progress`) flush data to persistent storage before closing the file handle.

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

### High-level API

For when you want to do one thing and get the result:

- `smb2::connect()` -- connect and authenticate (shorthand)
- `SmbClient::connect()` -- connect with full config
- `client.list_shares()` -- list available shares
- `client.connect_share()` -- connect to a share
- `client.list_directory(&share, path)` -- list a directory
- `client.read_file(&share, path)` -- download a file
- `client.write_file(&share, path, data)` -- upload a file
- `client.delete_file(&share, path)` -- delete a file
- `client.stat(&share, path)` -- get file metadata
- `client.rename(&share, from, to)` -- rename a file
- `client.create_directory(&share, path)` -- create a directory
- `client.delete_directory(&share, path)` -- remove a directory
- `client.download(&share, path)` -- streaming download (memory-efficient)
- `client.write_file_with_progress(&share, path, data, callback)` -- upload with progress
- `client.flush_file(&share, file_id)` -- flush file to persistent storage
- `client.disconnect_share(&share)` -- disconnect from a share

### Pipeline API

For when you have many operations and want them fast:

- `Pipeline::new(conn, &share)` -- create a pipeline
- `pipeline.execute(ops)` -- run a batch of operations

### Low-level API

For advanced use cases, the underlying types are available:

- `Connection` -- message exchange, credit tracking
- `Session` -- NTLM authentication, key derivation
- `Tree` -- share-level file operations (take `&mut Connection`)
- `NegotiatedParams` -- protocol parameters from negotiate

## Performance

Benchmarked against native macOS SMB (with F_NOCACHE to disable kernel page cache) and the `smb` crate on a QNAP NAS over Gigabit LAN, SMB 3.1.1:

### Small files (100 × 100 KB)

| Operation | native | smb2 | Speedup |
|---|---|---|---|
| Upload | 3.69s | 1.91s | **1.9x faster** |
| List | 47ms | 21ms | **2.2x faster** |
| Download | 3.10s | 617ms | **5.0x faster** |
| Delete | 3.08s | 1.03s | **3.0x faster** |

### Medium files (10 × 10 MB)

| Operation | native | smb2 | Speedup |
|---|---|---|---|
| Upload | 1.66s | 1.23s | **1.3x faster** |
| List | 27ms | 19ms | **1.4x faster** |
| Download | 4.00s | 2.93s | **1.4x faster** |
| Delete | 301ms | 128ms | **2.4x faster** |

### Large files (3 × 50 MB)

| Operation | native | smb2 | Speedup |
|---|---|---|---|
| Upload | 1.69s | 1.56s | ~parity |
| List | 27ms | 18ms | **1.5x faster** |
| Download | 5.62s | 1.11s | **5.1x faster** |
| Delete | 117ms | 54ms | **2.1x faster** |

Key optimizations: compound requests (CREATE+READ+CLOSE in 1 round-trip), pipelined I/O with sliding window and adaptive chunk sizing, and 256-credit request for wide pipeline windows.

**Note:** Native macOS download benchmarks use F_NOCACHE to bypass the kernel page cache. Without this, cached native reads appear ~20x faster because they skip the network entirely. F_NOCACHE gives a fair comparison of actual network I/O performance.

The benchmark tool is included at `benchmarks/smb/`. Run with `cargo run -p smb-benchmark --release`.

## Known limitations

| Limitation | Details |
|---|---|
| NTLM only | No Kerberos yet (works against Samba and most Windows servers) |
| No DFS follow-through | Returns `Error::DfsReferralRequired` with the path, you handle it |
| No multi-channel | Single TCP connection per client |
| No QUIC/RDMA | TCP only (covers ~99% of use cases) |
| SMB1 not supported | SMB2/3 only (SMB1 is deprecated and insecure) |
| LZ4 only | No LZNT1 compression (LZ4 is the modern choice, LZNT1 is legacy) |

## Comparison with existing libraries

### vs `smb` crate

The [`smb`](https://crates.io/crates/smb) crate is the most complete Rust SMB2 option right now. It covers more features than `smb2` (Kerberos, DFS, multi-channel, QUIC, RDMA). If you need those, use it.

But for the common case (connect to a NAS, move files around), `smb2` is a better fit:

- **Compound + pipelined I/O** -- `smb` sends one request at a time; smb2 uses compound requests and pipelined reads with sliding window
- **Auto-reconnect with durable handles** -- survives Wi-Fi drops without restarting transfers
- **Comprehensive test suite** -- `smb` has almost no tests
- **MIT OR Apache-2.0** -- `smb` is MIT-only

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
