//! SMB2 operations — uses our `smb2` crate to talk SMB2/3 directly.

use crate::config::Target;
use smb2::{ClientConfig, SmbClient, Tree};
use std::io::Write;
use std::time::{Duration, Instant};

/// Establish an SMB2 connection + session + tree for a target.
/// Returns the client and tree handle.
pub async fn connect(target: &Target) -> Result<(SmbClient, Tree), String> {
    let (username, password) = if target.guest {
        (String::new(), String::new())
    } else {
        (
            target.username.clone().unwrap_or_default(),
            target.password.clone().unwrap_or_default(),
        )
    };

    let config = ClientConfig {
        addr: format!("{}:445", target.host),
        timeout: Duration::from_secs(10),
        username,
        password,
        domain: String::new(),
        auto_reconnect: false,
    };

    let mut client = SmbClient::connect(config)
        .await
        .map_err(|e| format!("smb2 connect: {e}"))?;

    let tree = client
        .connect_share(&target.share)
        .await
        .map_err(|e| format!("smb2 connect_share '{}': {e}", target.share))?;

    if let Some(params) = client.params() {
        println!(
            "  smb2 negotiated: max_read={}KB, max_write={}KB",
            params.max_read_size / 1024,
            params.max_write_size / 1024,
        );
    }

    Ok((client, tree))
}

/// Create the test directory on the share via smb2.
pub async fn setup(client: &mut SmbClient, tree: &Tree, cycle_id: &str) -> Result<String, String> {
    let base = Target::smb2_test_base();
    let test_dir = format!(r"{base}\{cycle_id}");

    // Try to delete existing test dir first (best-effort)
    let _ = delete_dir_recursive(client, tree, &test_dir).await;

    // Create base dir if needed
    let _ = client.create_directory(tree, base).await;

    // Create cycle-specific subdir
    client
        .create_directory(tree, &test_dir)
        .await
        .map_err(|e| format!("smb2 create_directory '{test_dir}': {e}"))?;

    Ok(test_dir)
}

/// Upload `count` files of `size` bytes each via smb2 pipelined writes. Returns elapsed time.
pub async fn upload(
    client: &mut SmbClient,
    tree: &Tree,
    test_dir: &str,
    count: usize,
    size: usize,
    data: &[u8],
) -> Duration {
    let start = Instant::now();
    for i in 0..count {
        let file_path = format!(r"{test_dir}\bench_{i:05}.dat");
        client
            .write_file_pipelined(tree, &file_path, &data[..size])
            .await
            .expect("smb2 write_file_pipelined");
    }
    start.elapsed()
}

/// List the test directory via smb2. Returns (count, elapsed).
pub async fn list(client: &mut SmbClient, tree: &Tree, test_dir: &str) -> (usize, Duration) {
    let start = Instant::now();
    let entries = client
        .list_directory(tree, test_dir)
        .await
        .expect("smb2 list_directory");
    let count = entries
        .iter()
        .filter(|e| e.name != "." && e.name != "..")
        .count();
    (count, start.elapsed())
}

/// Download all files to a local temp dir via smb2 pipelined reads. Returns (bytes, elapsed).
pub async fn download(
    client: &mut SmbClient,
    tree: &Tree,
    test_dir: &str,
    local_dest: &std::path::PathBuf,
) -> (u64, Duration) {
    std::fs::create_dir_all(local_dest).expect("create local dest");

    // First, list files to know what to download
    let entries = client
        .list_directory(tree, test_dir)
        .await
        .expect("smb2 list_directory");
    let file_names: Vec<String> = entries
        .iter()
        .filter(|e| !e.is_directory && e.name != "." && e.name != "..")
        .map(|e| e.name.clone())
        .collect();

    // Use compound (CREATE+READ+CLOSE in 1 round-trip) for files that
    // fit in MaxReadSize. Fall back to pipelined for larger files.
    let max_read = client
        .params()
        .map(|p| p.max_read_size as usize)
        .unwrap_or(65536);

    let start = Instant::now();
    let mut total_bytes = 0u64;
    for name in &file_names {
        let file_path = format!(r"{test_dir}\{name}");
        let data = match client.read_file_compound(tree, &file_path).await {
            Ok(d) => d,
            Err(_) => {
                // Compound may fail for files > MaxReadSize; fall back.
                client
                    .read_file_pipelined(tree, &file_path)
                    .await
                    .expect("smb2 download fallback")
            }
        };
        let local_path = local_dest.join(name);
        let mut local_file = std::fs::File::create(&local_path).expect("create local file");
        local_file.write_all(&data).expect("write local");
        total_bytes += data.len() as u64;
    }
    let _ = max_read; // suppress unused warning
    (total_bytes, start.elapsed())
}

/// Delete all files in the test directory and then the directory itself via smb2.
pub async fn delete(client: &mut SmbClient, tree: &Tree, test_dir: &str) -> Duration {
    let start = Instant::now();
    delete_dir_recursive(client, tree, test_dir)
        .await
        .expect("smb2 delete_dir_recursive");
    start.elapsed()
}

/// Recursively delete a directory and its contents via smb2.
async fn delete_dir_recursive(
    client: &mut SmbClient,
    tree: &Tree,
    dir_name: &str,
) -> Result<(), String> {
    // List directory contents
    let entries = client
        .list_directory(tree, dir_name)
        .await
        .map_err(|e| format!("smb2 list_directory '{dir_name}': {e}"))?;

    // Delete each file
    for entry in &entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let path = format!(r"{dir_name}\{}", entry.name);
        if entry.is_directory {
            // Recurse into subdirectories
            Box::pin(delete_dir_recursive(client, tree, &path)).await?;
        } else {
            client
                .delete_file(tree, &path)
                .await
                .map_err(|e| format!("smb2 delete_file '{path}': {e}"))?;
        }
    }

    // Delete the directory itself
    client
        .delete_directory(tree, dir_name)
        .await
        .map_err(|e| format!("smb2 delete_directory '{dir_name}': {e}"))?;

    Ok(())
}

/// Remove test base directory if it exists (for --cleanup-only).
pub async fn cleanup(target: &Target) {
    match connect(target).await {
        Ok((mut client, tree)) => {
            let base = Target::smb2_test_base();
            match delete_dir_recursive(&mut client, &tree, base).await {
                Ok(()) => println!("  Removed {base} (smb2)"),
                Err(e) => println!("  smb2 cleanup: {e} (may not exist)"),
            }
        }
        Err(e) => println!("  Can't connect for smb2 cleanup: {e}"),
    }
}
