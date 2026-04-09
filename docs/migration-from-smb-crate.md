# Migrating from the `smb` crate to `smb2`

API mapping for switching Cmdr from `smb` (smb-rs) to `smb2`. Based on
how Cmdr actually uses the `smb` crate in `smb_connection.rs`,
`smb_client.rs`, and the benchmark's `direct.rs`.

## Connection

### smb crate

```rust
use smb::{Client, ClientConfig};

let mut config = ClientConfig::default();
config.connection.allow_unsigned_guest_access = true;
let client = Client::new(config);

// Connect via IP
let socket_addr: SocketAddr = "192.168.1.111:445".parse()?;
client.connect_to_address("server_name", socket_addr).await?;

// Then connect to a share (separate step)
let unc = UncPath::from_str(r"\\192.168.1.111\ShareName")?;
client.share_connect(&unc, "user", password).await?;
```

### smb2 crate

```rust
use smb2;

// One call does TCP connect + negotiate + session setup
let mut client = smb2::connect("192.168.1.111:445", "user", "pass").await?;

// Then connect to a share (share name only, no UNC path)
let mut tree = client.connect_share("ShareName").await?;
```

Or with full config:

```rust
let mut client = smb2::SmbClient::connect(smb2::ClientConfig {
    addr: "192.168.1.111:445".to_string(),
    timeout: Duration::from_secs(5),
    username: "user".to_string(),
    password: "pass".to_string(),
    domain: String::new(),
    auto_reconnect: false,
    compression: true,
    dfs_enabled: true,
}).await?;
```

## Guest access

### smb crate

```rust
config.connection.allow_unsigned_guest_access = true;
let client = Client::new(config);
client.connect_to_address(server_name, socket_addr).await?;
client.ipc_connect(connect_name, "Guest", String::new()).await?;
```

### smb2 crate

```rust
// Empty username and password = guest
let mut client = smb2::connect("192.168.1.111:445", "", "").await?;
```

## Share enumeration

### smb crate

```rust
// Requires separate IPC connect first
client.ipc_connect(connect_name, "Guest", String::new()).await?;
let shares: Vec<ShareInfo1> = client.list_shares(connect_name).await?;
```

### smb2 crate

```rust
// Handles IPC$ internally
let shares: Vec<ShareInfo> = client.list_shares().await?;
// Returns only disk shares (admin shares filtered out)
```

## File operations

### Read a file

smb crate:

```rust
let tree = client.get_tree(&unc_path).await?;
let access = FileAccessMask::new().with_generic_read(true);
let resource = tree.open_existing(&file_path, access).await?;
let file = resource.unwrap_file();

let file_size = file.get_len().await?;
let mut offset = 0u64;
while offset < file_size {
    let to_read = std::cmp::min(chunk_size, (file_size - offset) as usize);
    let mut buf = vec![0u8; to_read];
    let n = file.read_block(&mut buf, offset, None, false).await?;
    offset += n as u64;
}
```

smb2 crate:

```rust
// Simple (loads entire file into memory)
let data = client.read_file(&mut tree, "path/to/file").await?;

// Compound (single round-trip, best for small files)
let data = client.read_file_compound(&mut tree, "path/to/file").await?;

// Pipelined (best for large files)
let data = client.read_file_pipelined(&mut tree, "path/to/file").await?;

// Streaming with progress (memory-efficient for large files)
let mut download = client.download(&tree, "path/to/file").await?;
while let Some(chunk) = download.next_chunk().await {
    let bytes = chunk?;
    // write bytes to disk
    println!("{:.1}%", download.progress().percent());
}
```

### Write a file

smb crate:

```rust
let tree = client.get_tree(&unc_path).await?;
let access = FileAccessMask::new().with_generic_write(true);
let resource = tree.create_file(&path, CreateDisposition::Create, access).await?;
let file = resource.unwrap_file();

let mut offset = 0u64;
while (offset as usize) < data.len() {
    let end = std::cmp::min(offset as usize + chunk_size, data.len());
    file.write_block(&data[offset as usize..end], offset, None).await?;
    offset = end as u64;
}
drop(file); // no explicit flush
```

smb2 crate:

```rust
// Simple (auto-flushes before close)
client.write_file(&mut tree, "path/to/file", &data).await?;

// Compound (single round-trip for small files, auto-flushes)
client.write_file_compound(&mut tree, "path/to/file", &data).await?;

// Pipelined (best for large files, auto-flushes)
client.write_file_pipelined(&mut tree, "path/to/file", &data).await?;

// Streaming with progress
let mut upload = client.upload(&tree, "path/to/file", &data).await?;
while upload.write_next_chunk().await? {
    println!("{:.1}%", upload.progress().percent());
}
```

### List a directory

smb crate:

```rust
let tree = client.get_tree(&unc_path).await?;
let access = FileAccessMask::new().with_generic_read(true);
let resource = tree.open_existing(dir_path, access).await?;
let dir = Arc::new(resource.unwrap_dir());
let stream = Directory::query::<FileBothDirectoryInformation>(&dir, "*").await?;
let entries: Vec<_> = stream.collect().await;
```

smb2 crate:

```rust
let entries = client.list_directory(&mut tree, "path/to/dir").await?;
// Each entry has: name, size, created, modified, is_directory
```

### Delete a file

smb crate:

```rust
let access = FileAccessMask::new().with_delete(true);
let resource = tree.open_existing(&path, access).await?;
let handle = match &resource {
    Resource::File(f) => f.handle(),
    Resource::Directory(d) => d.handle(),
    Resource::Pipe(p) => p.handle(),
};
handle.set_info(FileDispositionInformation::default()).await?;
drop(resource);
```

smb2 crate:

```rust
client.delete_file(&mut tree, "path/to/file").await?;
```

### Create a directory

smb crate:

```rust
let access = FileAccessMask::new()
    .with_generic_read(true)
    .with_generic_write(true);
tree.create_directory(path, CreateDisposition::OpenIf, access).await?;
```

smb2 crate:

```rust
client.create_directory(&mut tree, "path/to/dir").await?;
```

### Other operations in smb2 (no smb crate equivalent used in Cmdr)

```rust
client.delete_directory(&mut tree, "path").await?;
client.rename(&mut tree, "old", "new").await?;
client.stat(&mut tree, "path").await?;         // -> FileInfo
client.fs_info(&mut tree).await?;              // -> FsInfo (disk space)
client.watch(&tree, "path", true).await?;  // -> Watcher (change notifications)
client.reconnect().await?;                 // re-establish after connection loss
client.disconnect_share(&tree).await?;
```

## Error handling

### smb crate

The `smb` crate returns `smb::Error` (opaque, string-based). Cmdr
wraps all errors in `format!("context: {e}")` strings.

### smb2 crate

```rust
use smb2::Error;

match result {
    Err(Error::Auth { message }) => // auth failed
    Err(Error::Protocol { status, command }) => {
        // status is NtStatus enum, can match specific codes
        if err.is_retryable() { /* retry */ }
    }
    Err(Error::Timeout) => // connection timeout
    Err(Error::Disconnected) => // connection lost
    Err(Error::Io(e)) => // std::io::Error
    Err(Error::Cancelled) => // progress callback returned Break
    Err(Error::DfsReferralRequired { path }) => // DFS redirect
    Err(Error::SessionExpired) => // reauthentication failed
    Err(Error::InvalidData { message }) => // malformed data
}
```

## Key differences

- **No UNC paths:** smb2 uses plain share name strings ("Documents"),
  not UNC paths (`\\server\Documents`). The server address is set at
  connect time.

- **No separate connect + share_connect:** smb2 combines TCP connect,
  negotiate, and session setup into one `connect()` call. Share
  connection is then `connect_share("name")`.

- **Auto compound vs pipelined:** smb2 picks the right strategy based
  on file size. Callers don't choose between compound and pipelined
  for most operations (though explicit methods exist if needed).

- **Flush on every write:** smb2 flushes before closing write handles
  to ensure data is persisted. The smb crate doesn't flush, so data
  could be lost on server crash.

- **Tree is a value, not a lookup:** In smb, you call
  `client.get_tree(&unc_path)` every time you need the tree. In smb2,
  `connect_share()` returns a `Tree` that you pass to operations.

- **Connection is borrowed:** smb2 operations take `&mut self` on
  `SmbClient`. You can't run multiple operations concurrently on one
  client. Use a second `SmbClient` (second TCP connection) for
  concurrent work like watching + reading.

- **Test credentials:** smb2 uses environment variables or `.env`
  files for test credentials (SMB_HOST, SMB_USER, SMB_PASS). Nothing
  is hardcoded.

- **Path separators:** smb2 accepts forward slashes and normalizes
  them to backslashes internally. The smb crate requires backslashes.
