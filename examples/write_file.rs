// Write a local file to an SMB share.
//
// Usage:
//   cargo run --example write_file
//
// Set RUST_LOG=smb2=debug for protocol-level logging.

use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Change these to match your server.
    let addr = "192.168.1.100:445";
    let username = "user";
    let password = "password";
    let share_name = "Documents";
    let local_path = "local_file.txt";
    let remote_path = "uploaded_file.txt";

    let data = std::fs::read(local_path)?;
    println!("Read {} bytes from {}", data.len(), local_path);

    let mut client = smb2::connect(addr, username, password).await?;
    let share = client.connect_share(share_name).await?;

    // Use pipelined write for large files (much faster).
    let start = Instant::now();
    let written = client.write_file_pipelined(&share, remote_path, &data).await?;
    let elapsed = start.elapsed();

    println!(
        "Uploaded {} bytes to {} in {:.2?}",
        written, remote_path, elapsed,
    );
    if elapsed.as_secs_f64() > 0.0 {
        println!(
            "  {:.1} MB/s",
            written as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
        );
    }

    client.disconnect_share(&share).await?;

    Ok(())
}
