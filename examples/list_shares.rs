// List available shares on an SMB server.
//
// Usage:
//   cargo run --example list_shares
//
// Set RUST_LOG=smb2=debug for protocol-level logging.

#[tokio::main]
async fn main() -> Result<(), smb2::Error> {
    env_logger::init();

    // Change these to match your server.
    let addr = "192.168.1.100:445";
    let username = "user";
    let password = "password";

    let mut client = smb2::connect(addr, username, password).await?;

    println!("Connected to {}", addr);
    if let Some(params) = client.params() {
        println!("Dialect: {}", params.dialect);
    }

    let shares = client.list_shares().await?;

    println!("\nShares ({} total):", shares.len());
    for share in &shares {
        if share.comment.is_empty() {
            println!("  {}", share.name);
        } else {
            println!("  {} - {}", share.name, share.comment);
        }
    }

    Ok(())
}
