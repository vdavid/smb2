// List files in a directory on an SMB share.
//
// Usage:
//   cargo run --example list_directory
//
// Set RUST_LOG=smb2=debug for protocol-level logging.

#[tokio::main]
async fn main() -> Result<(), smb2::Error> {
    env_logger::init();

    // Change these to match your server.
    let addr = "192.168.1.100:445";
    let username = "user";
    let password = "password";
    let share_name = "Documents";
    let directory = ""; // empty = root of the share

    let mut client = smb2::connect(addr, username, password).await?;
    let share = client.connect_share(share_name).await?;

    let entries = client.list_directory(&share, directory).await?;

    println!("{} entries in \\\\{}\\{}\\{}:", entries.len(), addr, share_name, directory);
    for entry in &entries {
        let kind = if entry.is_directory { "DIR " } else { "    " };
        println!("  {} {:>12} bytes  {}", kind, entry.size, entry.name);
    }

    client.disconnect_share(&share).await?;

    Ok(())
}
