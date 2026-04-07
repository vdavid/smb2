// Read a file from an SMB share and save it to disk.
//
// Usage:
//   cargo run --example read_file
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
    let remote_path = "report.pdf";
    let local_path = "report.pdf";

    let mut client = smb2::connect(addr, username, password).await?;
    let share = client.connect_share(share_name).await?;

    // Use pipelined read for large files (much faster).
    let start = Instant::now();
    let data = client.read_file_pipelined(&share, remote_path).await?;
    let elapsed = start.elapsed();

    std::fs::write(local_path, &data)?;

    println!(
        "Downloaded {} ({} bytes) in {:.2?}",
        remote_path,
        data.len(),
        elapsed,
    );
    if elapsed.as_secs_f64() > 0.0 {
        println!(
            "  {:.1} MB/s",
            data.len() as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
        );
    }

    client.disconnect_share(&share).await?;

    Ok(())
}
