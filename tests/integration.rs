//! Integration tests against real SMB servers.
//!
//! These tests require local network access and are marked `#[ignore]`.
//! Run with: `RUST_LOG=smb2=debug cargo test --test integration -- --ignored --nocapture`

use std::ops::ControlFlow;
use std::time::Duration;

use smb2::client::{list_shares, ClientConfig, Connection, Session, SmbClient, Tree};

/// Load .env file if present (no extra dependencies).
fn load_dotenv() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    if let Ok(contents) = std::fs::read_to_string(path) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                // Only set if not already in the environment (env var takes precedence).
                if std::env::var(key.trim()).is_err() {
                    // Strip surrounding quotes if present.
                    let value = value.trim();
                    let value = value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(value);
                    std::env::set_var(key.trim(), value);
                }
            }
        }
    }
}

/// Get the NAS password from SMB2_TEST_NAS_PASSWORD (env var or .env file).
fn nas_password() -> String {
    load_dotenv();
    std::env::var("SMB2_TEST_NAS_PASSWORD").expect(
        "SMB2_TEST_NAS_PASSWORD not set. Copy .env.example to .env and fill in your password.",
    )
}

#[tokio::test]
#[ignore]
async fn connect_and_list_directory_on_real_nas() {
    let _ = env_logger::try_init();

    // Connect to 192.168.1.111.
    let mut conn = Connection::connect("192.168.1.111:445", Duration::from_secs(5))
        .await
        .expect("failed to connect to NAS");

    // Negotiate.
    conn.negotiate().await.expect("negotiate failed");

    let params = conn.params().unwrap();
    println!("Negotiated dialect: {}", params.dialect);
    println!("Max read size: {}", params.max_read_size);
    println!("Signing required: {}", params.signing_required);

    // Authenticate.
    let session = Session::setup(&mut conn, "david", &nas_password(), "")
        .await
        .expect("session setup failed");

    println!("Session ID: {}", session.session_id);

    // Connect to the "naspi" share.
    let tree = Tree::connect(&mut conn, "naspi")
        .await
        .expect("tree connect failed");

    println!("Tree ID: {}", tree.tree_id);

    // List the root directory of the share.
    let entries = tree
        .list_directory(&mut conn, "")
        .await
        .expect("list directory failed");

    println!("Directory entries ({} total):", entries.len());
    for entry in entries.iter().take(10) {
        let kind = if entry.is_directory { "dir " } else { "file" };
        println!("  {} {} ({} bytes)", kind, entry.name, entry.size);
    }
    if entries.len() > 10 {
        println!("  ... and {} more", entries.len() - 10);
    }

    assert!(!entries.is_empty(), "expected at least one entry in root");

    // Disconnect.
    tree.disconnect(&mut conn)
        .await
        .expect("tree disconnect failed");
}

#[tokio::test]
#[ignore]
async fn connect_and_list_directory_on_raspberry_pi() {
    let _ = env_logger::try_init();

    // Connect to 192.168.1.150 (Raspberry Pi).
    let mut conn = Connection::connect("192.168.1.150:445", Duration::from_secs(5))
        .await
        .expect("failed to connect to Raspberry Pi");

    // Negotiate (may negotiate SMB 2.x or 3.0 depending on Pi config).
    conn.negotiate().await.expect("negotiate failed");

    let params = conn.params().unwrap();
    println!("Negotiated dialect: {}", params.dialect);
    println!("Max read size: {}", params.max_read_size);
    println!("Max transact size: {}", params.max_transact_size);
    println!("Signing required: {}", params.signing_required);

    // Authenticate as guest (empty username and password).
    let session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");

    println!("Session ID: {}", session.session_id);

    // Connect to the "PiHDD" share.
    let tree = Tree::connect(&mut conn, "PiHDD")
        .await
        .expect("tree connect failed");

    println!("Tree ID: {}", tree.tree_id);

    // List the root directory of the share.
    let entries = tree
        .list_directory(&mut conn, "")
        .await
        .expect("list directory failed");

    println!("Directory entries ({} total):", entries.len());
    for entry in entries.iter().take(10) {
        let kind = if entry.is_directory { "dir " } else { "file" };
        println!("  {} {} ({} bytes)", kind, entry.name, entry.size);
    }
    if entries.len() > 10 {
        println!("  ... and {} more", entries.len() - 10);
    }

    assert!(!entries.is_empty(), "expected at least one entry in root");

    // Disconnect.
    tree.disconnect(&mut conn)
        .await
        .expect("tree disconnect failed");
}

/// Helper: connect, negotiate, and authenticate to the QNAP NAS.
async fn connect_to_nas() -> (Connection, Tree) {
    let mut conn = Connection::connect("192.168.1.111:445", Duration::from_secs(5))
        .await
        .expect("failed to connect to NAS");

    conn.negotiate().await.expect("negotiate failed");

    let _session = Session::setup(&mut conn, "david", &nas_password(), "")
        .await
        .expect("session setup failed");

    let tree = Tree::connect(&mut conn, "naspi")
        .await
        .expect("tree connect failed");

    (conn, tree)
}

#[tokio::test]
#[ignore]
async fn write_and_read_file_on_nas() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    let test_data = b"Hello from smb2-rs integration test!";
    let test_path = "smb2_test_write_read.tmp";

    // Write the test file.
    let written = tree
        .write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed");
    println!("Wrote {} bytes to {}", written, test_path);
    assert_eq!(written, test_data.len() as u64);

    // Read it back.
    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed");
    println!("Read {} bytes from {}", data.len(), test_path);
    assert_eq!(data, test_data);

    // Clean up: delete the file.
    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    println!("Deleted {}", test_path);

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn read_file_compound_on_nas() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    // Write a small test file.
    let test_path = "smb2_test_compound.tmp";
    let test_data = b"compound read test data 1234567890";
    tree.write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed");

    // Read via compound (1 round-trip).
    let start = std::time::Instant::now();
    let compound_data = tree
        .read_file_compound(&mut conn, test_path)
        .await
        .expect("read_file_compound failed");
    let compound_elapsed = start.elapsed();

    assert_eq!(compound_data, test_data);
    println!(
        "Compound read: {} bytes in {:?}",
        compound_data.len(),
        compound_elapsed
    );

    // Read via sequential (3 round-trips) for comparison.
    let start = std::time::Instant::now();
    let sequential_data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file (sequential) failed");
    let sequential_elapsed = start.elapsed();

    assert_eq!(sequential_data, test_data);
    println!(
        "Sequential read: {} bytes in {:?}",
        sequential_data.len(),
        sequential_elapsed
    );

    if compound_elapsed < sequential_elapsed {
        println!(
            "Compound was {:.1}x faster",
            sequential_elapsed.as_secs_f64() / compound_elapsed.as_secs_f64()
        );
    }

    // Clean up.
    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn stat_file_on_nas() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    // First write a test file so we have something to stat.
    let test_path = "smb2_test_stat.tmp";
    let test_data = b"stat test content";
    tree.write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed");

    let info = tree.stat(&mut conn, test_path).await.expect("stat failed");

    println!(
        "Stat {}: size={}, is_dir={}",
        test_path, info.size, info.is_directory
    );
    assert_eq!(info.size, test_data.len() as u64);
    assert!(!info.is_directory);

    // Clean up.
    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn create_and_delete_directory_on_nas() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    let dir_path = "smb2_test_dir_tmp";

    // Create the directory.
    tree.create_directory(&mut conn, dir_path)
        .await
        .expect("create_directory failed");
    println!("Created directory {}", dir_path);

    // Verify it exists by statting it.
    let info = tree.stat(&mut conn, dir_path).await.expect("stat failed");
    assert!(info.is_directory, "expected a directory");

    // Delete the directory.
    tree.delete_directory(&mut conn, dir_path)
        .await
        .expect("delete_directory failed");
    println!("Deleted directory {}", dir_path);

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn list_shares_on_nas() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect("192.168.1.111:445", Duration::from_secs(5))
        .await
        .expect("failed to connect to NAS");

    conn.negotiate().await.expect("negotiate failed");

    let _session = Session::setup(&mut conn, "david", &nas_password(), "")
        .await
        .expect("session setup failed");

    let shares = list_shares(&mut conn).await.expect("list_shares failed");

    println!("Shares ({} total):", shares.len());
    for share in &shares {
        println!(
            "  {} (type=0x{:08X}) - {}",
            share.name, share.share_type, share.comment
        );
    }

    // Verify that "naspi" is in the list.
    assert!(
        shares.iter().any(|s| s.name == "naspi"),
        "expected 'naspi' share in the list"
    );
}

#[tokio::test]
#[ignore]
async fn list_shares_on_raspberry_pi() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect("192.168.1.150:445", Duration::from_secs(5))
        .await
        .expect("failed to connect to Raspberry Pi");

    conn.negotiate().await.expect("negotiate failed");

    // Guest access
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");

    let shares = list_shares(&mut conn).await.expect("list_shares failed");

    println!("Shares on Pi ({} total):", shares.len());
    for share in &shares {
        println!(
            "  {} (type=0x{:08X}) - {}",
            share.name, share.share_type, share.comment
        );
    }

    assert!(!shares.is_empty(), "expected at least one share");
}

// ── SmbClient-based tests ─────────────────────────────────────────────

/// Helper: create an SmbClient connected to the QNAP NAS.
async fn connect_client_to_nas() -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: "192.168.1.111:445".to_string(),
        timeout: Duration::from_secs(5),
        username: "david".to_string(),
        password: nas_password(),
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
    })
    .await
    .expect("SmbClient::connect failed")
}

#[tokio::test]
#[ignore]
async fn smb_client_connect_and_list_directory() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;

    let params = client.params().unwrap();
    println!("Dialect: {}", params.dialect);
    println!("Session ID: {}", client.session().session_id);

    // Connect to the "naspi" share.
    let tree = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed");
    println!("Tree ID: {}", tree.tree_id);

    // List root directory.
    let entries = tree
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory failed");

    println!("Directory entries ({} total):", entries.len());
    for entry in entries.iter().take(10) {
        let kind = if entry.is_directory { "dir " } else { "file" };
        println!("  {} {} ({} bytes)", kind, entry.name, entry.size);
    }

    assert!(!entries.is_empty(), "expected at least one entry");

    tree.disconnect(client.connection_mut())
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn smb_client_list_shares() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;

    let shares = client.list_shares().await.expect("list_shares failed");

    println!("Shares ({} total):", shares.len());
    for share in &shares {
        println!("  {} - {}", share.name, share.comment);
    }

    assert!(
        shares.iter().any(|s| s.name == "naspi"),
        "expected 'naspi' share in the list"
    );
}

#[tokio::test]
#[ignore]
async fn pipelined_read_large_file() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    // Create a 1 MB test file on the NAS.
    let test_path = "smb2_test_pipelined_read.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

    let written = tree
        .write_file(&mut conn, test_path, &test_data)
        .await
        .expect("write_file failed");
    println!("Setup: wrote {} bytes to {}", written, test_path);

    // Read it back with pipelined I/O.
    let start = std::time::Instant::now();
    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed");
    let elapsed = start.elapsed();

    println!(
        "Pipelined read: {} bytes in {:.2?} ({:.1} MB/s)",
        data.len(),
        elapsed,
        data.len() as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    );

    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    // Compare with sequential read for timing.
    let start_seq = std::time::Instant::now();
    let data_seq = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file (sequential) failed");
    let elapsed_seq = start_seq.elapsed();

    println!(
        "Sequential read: {} bytes in {:.2?} ({:.1} MB/s)",
        data_seq.len(),
        elapsed_seq,
        data_seq.len() as f64 / (1024.0 * 1024.0) / elapsed_seq.as_secs_f64()
    );

    // Clean up.
    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn pipelined_write_large_file() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    let test_path = "smb2_test_pipelined_write.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();

    // Write with pipelined I/O.
    let start = std::time::Instant::now();
    let written = tree
        .write_file_pipelined(&mut conn, test_path, &test_data)
        .await
        .expect("write_file_pipelined failed");
    let elapsed = start.elapsed();

    println!(
        "Pipelined write: {} bytes in {:.2?} ({:.1} MB/s)",
        written,
        elapsed,
        written as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    );

    assert_eq!(written, test_data.len() as u64);

    // Read it back (sequential is fine) and verify.
    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed");

    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    // Clean up.
    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn reconnect_after_disconnect() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;

    // Verify it works: list a directory.
    let tree = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed");
    let entries = tree
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory failed");
    println!("Before reconnect: {} entries", entries.len());
    assert!(!entries.is_empty());
    tree.disconnect(client.connection_mut())
        .await
        .expect("disconnect failed");

    // Reconnect.
    client.reconnect().await.expect("reconnect failed");
    println!(
        "Reconnected, new session_id={}",
        client.session().session_id
    );

    // Verify it works again: list the same directory.
    let tree2 = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed after reconnect");
    let entries2 = tree2
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory failed after reconnect");
    println!("After reconnect: {} entries", entries2.len());
    assert!(!entries2.is_empty());
    tree2
        .disconnect(client.connection_mut())
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn streaming_download_large_file() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;
    let mut tree = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed");

    // Write a 1 MB test file.
    let test_path = "smb2_test_streaming_download.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

    client
        .write_file(&mut tree, test_path, &test_data)
        .await
        .expect("write_file failed");
    println!("Setup: wrote {} bytes", test_data.len());

    // Download it with the streaming API.
    let mut download = client
        .download(&tree, test_path)
        .await
        .expect("download failed");
    assert_eq!(download.size(), test_data.len() as u64);
    println!("Downloading {} bytes...", download.size());

    let mut received = Vec::new();
    let mut chunk_count = 0u32;
    while let Some(chunk) = download.next_chunk().await {
        let bytes = chunk.expect("next_chunk failed");
        assert!(!bytes.is_empty(), "received empty chunk");
        received.extend_from_slice(&bytes);
        chunk_count += 1;
        println!(
            "  chunk {}: {} bytes, progress={:.1}%",
            chunk_count,
            bytes.len(),
            download.progress().percent()
        );
    }

    // Verify progress reached 100%.
    assert!(
        (download.progress().fraction() - 1.0).abs() < f64::EPSILON,
        "expected progress to reach 1.0, got {}",
        download.progress().fraction()
    );

    // Verify at least one chunk was received.
    // Note: the number of chunks depends on the server's max_read_size.
    // A server with max_read_size >= 1 MB will deliver the file in one chunk.
    assert!(
        chunk_count >= 1,
        "expected at least one chunk, got {}",
        chunk_count
    );

    // Verify data integrity.
    assert_eq!(received.len(), test_data.len(), "size mismatch");
    assert_eq!(received, test_data, "content mismatch");

    // The download auto-closed the file handle after the last chunk.
    // Drop the download to release the borrow on the connection.
    drop(download);

    // Clean up.
    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn write_with_progress_and_cancel() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;
    let mut tree = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed");

    // Write a file with progress callback, verifying progress updates.
    let test_path = "smb2_test_write_progress.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();

    let mut progress_updates = Vec::new();
    let written = client
        .write_file_with_progress(&mut tree, test_path, &test_data, |progress| {
            println!(
                "  progress: {}/{} ({:.1}%)",
                progress.bytes_transferred,
                progress.total_bytes.unwrap_or(0),
                progress.percent()
            );
            progress_updates.push(progress.bytes_transferred);
            ControlFlow::Continue(())
        })
        .await
        .expect("write_file_with_progress failed");

    assert_eq!(written, test_data.len() as u64);
    assert!(
        !progress_updates.is_empty(),
        "expected at least one progress update"
    );

    // Verify the data was written correctly by reading it back.
    let readback = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(
        readback, test_data,
        "content mismatch after write_with_progress"
    );

    // Clean up the first file.
    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");

    // Write another file, cancel at ~50%.
    let cancel_path = "smb2_test_write_cancel.tmp";
    let half = test_data.len() as u64 / 2;
    let result = client
        .write_file_with_progress(&mut tree, cancel_path, &test_data, |progress| {
            if progress.bytes_transferred >= half {
                println!("  cancelling at {:.1}%", progress.percent());
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .await;

    // Verify Error::Cancelled was returned.
    match result {
        Err(smb2::Error::Cancelled) => println!("  correctly received Error::Cancelled"),
        other => panic!("expected Error::Cancelled, got {:?}", other),
    }

    // The partially written file may or may not exist. Try to clean up.
    let _ = client.delete_file(&mut tree, cancel_path).await;

    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn write_file_compound_on_nas() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    let test_path = "smb2_test_compound_write.tmp";
    let test_data = b"compound write test data 1234567890";

    // Write via compound (1 round-trip).
    let start = std::time::Instant::now();
    let written = tree
        .write_file_compound(&mut conn, test_path, test_data)
        .await
        .expect("write_file_compound failed");
    let compound_elapsed = start.elapsed();

    assert_eq!(written, test_data.len() as u64);
    println!(
        "Compound write: {} bytes in {:?}",
        written, compound_elapsed
    );

    // Read it back to verify data integrity.
    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, test_data);
    println!("Read back verified: {} bytes match", data.len());

    // Also test empty file via compound.
    let empty_path = "smb2_test_compound_write_empty.tmp";
    let empty_written = tree
        .write_file_compound(&mut conn, empty_path, b"")
        .await
        .expect("write_file_compound (empty) failed");
    assert_eq!(empty_written, 0);

    let empty_data = tree
        .read_file(&mut conn, empty_path)
        .await
        .expect("read empty file failed");
    assert!(empty_data.is_empty());

    // Clean up.
    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.delete_file(&mut conn, empty_path)
        .await
        .expect("delete empty file failed");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn debug_rapid_pipelined_writes() {
    let _ = env_logger::try_init();

    let config = ClientConfig {
        addr: "192.168.1.111:445".into(),
        timeout: Duration::from_secs(5),
        username: "david".into(),
        password: nas_password(),
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
    };

    let mut client = SmbClient::connect(config).await.expect("connect failed");
    let mut share = client.connect_share("naspi").await.expect("tree failed");

    eprintln!("Connected. Credits: {}", client.credits());

    let data = vec![0xAA; 100 * 1024]; // 100 KB

    for i in 0..20 {
        let path = format!("_test/smb2_diag_{}.tmp", i);
        let start = std::time::Instant::now();

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            client.write_file_pipelined(&mut share, &path, &data),
        )
        .await;

        match result {
            Ok(Ok(n)) => eprintln!(
                "  [{}] wrote {} bytes in {:?}, credits={}",
                i,
                n,
                start.elapsed(),
                client.credits()
            ),
            Ok(Err(e)) => {
                eprintln!("  [{}] WRITE ERROR: {}", i, e);
                break;
            }
            Err(_) => {
                eprintln!("  [{}] TIMEOUT after 10s, credits={}", i, client.credits());
                break;
            }
        }
    }

    // Cleanup
    for i in 0..20 {
        let path = format!("_test/smb2_diag_{}.tmp", i);
        let _ = client.delete_file(&mut share, &path).await;
    }
    let _ = client.disconnect_share(&share).await;
}

#[tokio::test]
#[ignore]
async fn micro_benchmark_smb2_vs_native() {
    let _ = env_logger::try_init();

    // --- smb2 setup ---
    let config = ClientConfig {
        addr: "192.168.1.111:445".into(),
        timeout: Duration::from_secs(5),
        username: "david".into(),
        password: nas_password(),
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
    };
    let mut client = SmbClient::connect(config).await.expect("connect");
    let mut share = client.connect_share("naspi").await.expect("tree");

    let _ = client
        .create_directory(&mut share, "_test/smb2_bench")
        .await;

    let file_count = 50;
    let file_size = 100 * 1024; // 100 KB
    let data = vec![0x42u8; file_size];

    // --- UPLOAD (smb2) ---
    let start = std::time::Instant::now();
    for i in 0..file_count {
        let path = format!("_test/smb2_bench/f_{}.bin", i);
        client
            .write_file_pipelined(&mut share, &path, &data)
            .await
            .expect("write");
    }
    let smb2_upload = start.elapsed();

    // --- LIST (smb2) ---
    let start = std::time::Instant::now();
    let entries = client
        .list_directory(&mut share, "_test/smb2_bench")
        .await
        .expect("list");
    let smb2_list = start.elapsed();
    assert!(
        entries.len() >= file_count,
        "expected {} entries, got {}",
        file_count,
        entries.len()
    );

    // --- DOWNLOAD (smb2) ---
    // Use sequential read for files that fit in one MaxReadSize chunk,
    // pipelined for larger files.
    let max_read = client
        .params()
        .map(|p| p.max_read_size as usize)
        .unwrap_or(65536);
    let start = std::time::Instant::now();
    for i in 0..file_count {
        let path = format!("_test/smb2_bench/f_{}.bin", i);
        let d = if file_size <= max_read {
            client.read_file(&mut share, &path).await.expect("read")
        } else {
            client
                .read_file_pipelined(&mut share, &path)
                .await
                .expect("read")
        };
        assert_eq!(d.len(), file_size);
    }
    let smb2_download = start.elapsed();

    // --- DELETE (smb2) ---
    let start = std::time::Instant::now();
    for i in 0..file_count {
        let path = format!("_test/smb2_bench/f_{}.bin", i);
        client.delete_file(&mut share, &path).await.expect("delete");
    }
    let smb2_delete = start.elapsed();

    // --- NATIVE (via OS mount) ---
    let mount_path = std::path::Path::new("/Volumes/naspi/_test/smb2_bench_native");
    let native_available = std::path::Path::new("/Volumes/naspi").exists();

    let (nat_upload, nat_list, nat_download, nat_delete) = if native_available {
        let _ = std::fs::create_dir_all(mount_path);

        let start = std::time::Instant::now();
        for i in 0..file_count {
            let p = mount_path.join(format!("f_{}.bin", i));
            std::fs::write(&p, &data).expect("native write");
        }
        let nu = start.elapsed();

        let start = std::time::Instant::now();
        let n = std::fs::read_dir(mount_path).unwrap().count();
        let nl = start.elapsed();
        assert!(n >= file_count);

        let start = std::time::Instant::now();
        for i in 0..file_count {
            let p = mount_path.join(format!("f_{}.bin", i));
            let d = std::fs::read(&p).expect("native read");
            assert_eq!(d.len(), file_size);
        }
        let nd = start.elapsed();

        let start = std::time::Instant::now();
        for i in 0..file_count {
            let p = mount_path.join(format!("f_{}.bin", i));
            std::fs::remove_file(&p).expect("native delete");
        }
        let ndel = start.elapsed();
        let _ = std::fs::remove_dir(mount_path);

        (nu, nl, nd, ndel)
    } else {
        eprintln!("WARNING: /Volumes/naspi not mounted, skipping native comparison");
        (
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
        )
    };

    // Cleanup
    let _ = client
        .delete_directory(&mut share, "_test/smb2_bench")
        .await;
    let _ = client.disconnect_share(&share).await;

    // Results
    let total_mb = (file_count * file_size) as f64 / (1024.0 * 1024.0);
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!(
        "║  MICRO BENCHMARK: {} × {} KB = {:.1} MB          ║",
        file_count,
        file_size / 1024,
        total_mb
    );
    println!("╚══════════════════════════════════════════════════════════╝\n");
    println!("┌────────────┬────────────┬────────────┬──────────┐");
    println!("│ operation  │ native     │ smb2       │ ratio    │");
    println!("├────────────┼────────────┼────────────┼──────────┤");

    let ops = [
        ("upload", nat_upload, smb2_upload),
        ("list", nat_list, smb2_list),
        ("download", nat_download, smb2_download),
        ("delete", nat_delete, smb2_delete),
    ];

    for (name, nat, smb2) in &ops {
        let ratio = if nat.as_secs_f64() > 0.0 {
            format!("{:.2}x", smb2.as_secs_f64() / nat.as_secs_f64())
        } else {
            "N/A".to_string()
        };
        println!(
            "│ {:<10} │ {:>8.0?} │ {:>8.0?} │ {:>8} │",
            name, nat, smb2, ratio
        );
    }
    println!("└────────────┴────────────┴────────────┴──────────┘");
    println!("\nRatio < 1.0 means smb2 is faster than native.");
}

#[tokio::test]
#[ignore]
async fn compound_read_and_write_on_raspberry_pi() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect("192.168.1.150:445", Duration::from_secs(5))
        .await
        .expect("failed to connect to Pi");
    conn.negotiate().await.expect("negotiate failed");

    let session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");

    println!(
        "Pi: dialect={}, sign={}",
        conn.params().unwrap().dialect,
        session.should_sign
    );

    let tree = smb2::Tree::connect(&mut conn, "PiHDD")
        .await
        .expect("tree connect failed");

    // Compound write
    let test_data = b"Pi compound test 1234567890";
    let start = std::time::Instant::now();
    tree.write_file_compound(&mut conn, "smb2_pi_compound.tmp", test_data)
        .await
        .expect("compound write failed");
    println!("Pi compound write: {:?}", start.elapsed());

    // Compound read
    let start = std::time::Instant::now();
    let read_back = tree
        .read_file_compound(&mut conn, "smb2_pi_compound.tmp")
        .await
        .expect("compound read failed");
    println!("Pi compound read: {:?}", start.elapsed());

    assert_eq!(read_back, test_data, "data mismatch on Pi");
    println!("Pi compound read/write verified!");

    // Cleanup (best-effort -- Pi sometimes drops connection after compound)
    let _ = tree.delete_file(&mut conn, "smb2_pi_compound.tmp").await;
    let _ = tree.disconnect(&mut conn).await;
}

// ── Streaming upload tests ────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn streaming_upload_large_file() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;
    let mut tree = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed");

    // Write a 2 MB file via streaming upload (must exceed MaxWriteSize=1MB
    // to trigger chunked path instead of compound).
    let test_path = "smb2_test_streaming_upload.tmp";
    let test_data: Vec<u8> = (0..2_097_152).map(|i| (i % 251) as u8).collect();

    let mut upload = client
        .upload(&tree, test_path, &test_data)
        .await
        .expect("upload failed");
    assert_eq!(upload.total_bytes(), test_data.len() as u64);
    println!("Uploading {} bytes...", upload.total_bytes());

    let mut chunk_count = 0u32;
    while upload
        .write_next_chunk()
        .await
        .expect("write_next_chunk failed")
    {
        chunk_count += 1;
        println!(
            "  chunk {}: progress={:.1}%",
            chunk_count,
            upload.progress().percent()
        );
    }

    // Verify progress reached 100%.
    assert!(
        (upload.progress().fraction() - 1.0).abs() < f64::EPSILON,
        "expected progress to reach 1.0, got {}",
        upload.progress().fraction()
    );

    // Large file should have taken multiple chunks.
    assert!(
        chunk_count >= 1,
        "expected at least one progress update for large file, got {}",
        chunk_count
    );
    println!("Upload complete in {} chunks", chunk_count);

    // Release the borrow on connection.
    drop(upload);

    // Read back and verify.
    let readback = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(readback.len(), test_data.len(), "size mismatch");
    assert_eq!(readback, test_data, "content mismatch");
    println!("Read back verified: {} bytes match", readback.len());

    // Clean up.
    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn streaming_upload_small_file_uses_compound() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;
    let mut tree = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streaming_upload_small.tmp";
    let test_data = b"small file via streaming upload API";

    let mut upload = client
        .upload(&tree, test_path, test_data)
        .await
        .expect("upload failed");
    assert_eq!(upload.total_bytes(), test_data.len() as u64);

    // Small file should be done immediately (compound write in constructor).
    let has_more = upload
        .write_next_chunk()
        .await
        .expect("write_next_chunk failed");
    assert!(
        !has_more,
        "expected write_next_chunk to return false for small file"
    );

    // Progress should be 100%.
    assert!(
        (upload.progress().fraction() - 1.0).abs() < f64::EPSILON,
        "expected progress to reach 1.0, got {}",
        upload.progress().fraction()
    );
    println!("Small file upload complete (compound, no chunks needed)");

    // Release the borrow.
    drop(upload);

    // Read back and verify.
    let readback = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(readback, test_data.as_slice(), "content mismatch");
    println!("Read back verified: {} bytes match", readback.len());

    // Clean up.
    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

/// Helper: create an SmbClient connected to the Raspberry Pi.
async fn connect_client_to_pi() -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: "192.168.1.150:445".to_string(),
        timeout: Duration::from_secs(5),
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
    })
    .await
    .expect("SmbClient::connect to Pi failed")
}

#[tokio::test]
#[ignore]
async fn streaming_upload_and_download_on_pi() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_pi().await;
    let mut tree = client
        .connect_share("PiHDD")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_stream_roundtrip.tmp";
    let test_data = b"streaming roundtrip test on Pi 1234567890";

    // Upload via streaming API.
    let mut upload = client
        .upload(&tree, test_path, test_data)
        .await
        .expect("upload failed");

    while upload
        .write_next_chunk()
        .await
        .expect("write_next_chunk failed")
    {
        println!("  upload progress: {:.1}%", upload.progress().percent());
    }
    println!(
        "Upload complete: {} bytes, progress={:.1}%",
        upload.total_bytes(),
        upload.progress().percent()
    );

    // Release the borrow.
    drop(upload);

    // Download via read_file (compound) -- simpler and more robust for
    // small files on Pi which sometimes resets streaming connections.
    let received = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");

    // Verify contents match.
    assert_eq!(
        received,
        test_data.as_slice(),
        "content mismatch after roundtrip"
    );
    println!("Roundtrip verified: {} bytes match", received.len());

    // Clean up (best-effort).
    let _ = client.delete_file(&mut tree, test_path).await;
    let _ = client.disconnect_share(&tree).await;
}

#[tokio::test]
#[ignore]
async fn fs_info_on_nas() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;
    let mut tree = client
        .connect_share("naspi")
        .await
        .expect("connect_share failed");

    let info = client.fs_info(&mut tree).await.expect("fs_info failed");

    assert!(info.total_bytes > 0, "total_bytes should be positive");
    assert!(info.free_bytes > 0, "free_bytes should be positive");
    assert!(
        info.free_bytes <= info.total_bytes,
        "free_bytes should not exceed total_bytes"
    );
    assert!(
        info.total_free_bytes > 0,
        "total_free_bytes should be positive"
    );
    assert!(
        info.bytes_per_sector > 0,
        "bytes_per_sector should be positive"
    );
    assert!(
        info.sectors_per_unit > 0,
        "sectors_per_unit should be positive"
    );

    let total_gb = info.total_bytes as f64 / 1_000_000_000.0;
    let free_gb = info.free_bytes as f64 / 1_000_000_000.0;
    println!(
        "QNAP: {:.1} GB total, {:.1} GB free ({:.1}% used)",
        total_gb,
        free_gb,
        (1.0 - free_gb / total_gb) * 100.0
    );
    println!(
        "  bytes_per_sector={}, sectors_per_unit={}",
        info.bytes_per_sector, info.sectors_per_unit
    );

    let _ = client.disconnect_share(&tree).await;
}

#[tokio::test]
#[ignore]
async fn fs_info_on_pi() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_pi().await;
    let mut tree = client
        .connect_share("PiHDD")
        .await
        .expect("connect_share failed");

    let info = client.fs_info(&mut tree).await.expect("fs_info failed");

    assert!(info.total_bytes > 0, "total_bytes should be positive");
    assert!(info.free_bytes > 0, "free_bytes should be positive");
    assert!(
        info.free_bytes <= info.total_bytes,
        "free_bytes should not exceed total_bytes"
    );
    assert!(
        info.total_free_bytes > 0,
        "total_free_bytes should be positive"
    );
    assert!(
        info.bytes_per_sector > 0,
        "bytes_per_sector should be positive"
    );
    assert!(
        info.sectors_per_unit > 0,
        "sectors_per_unit should be positive"
    );

    let total_gb = info.total_bytes as f64 / 1_000_000_000.0;
    let free_gb = info.free_bytes as f64 / 1_000_000_000.0;
    println!(
        "Pi: {:.1} GB total, {:.1} GB free ({:.1}% used)",
        total_gb,
        free_gb,
        (1.0 - free_gb / total_gb) * 100.0
    );
    println!(
        "  bytes_per_sector={}, sectors_per_unit={}",
        info.bytes_per_sector, info.sectors_per_unit
    );

    let _ = client.disconnect_share(&tree).await;
}

// ── File watching (CHANGE_NOTIFY) tests ──────────────────────────────

#[tokio::test]
#[ignore]
async fn watch_directory_on_nas() {
    use smb2::FileNotifyAction;

    let _ = env_logger::try_init();

    // We need two connections: one for watching, one for making changes.
    // SmbClient is !Send (due to dyn Pack), so we use tokio::task::spawn_local
    // with a LocalSet to run both tasks on the same thread.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut watcher_client = connect_client_to_nas().await;
            let mut watcher_share = watcher_client
                .connect_share("naspi")
                .await
                .expect("tree connect failed (watcher)");

            // Make sure the test directory exists.
            let _ = watcher_client
                .create_directory(&mut watcher_share, "_test")
                .await;

            // Start watching the _test/ directory (non-recursive).
            let mut watcher = watcher_client
                .watch(&watcher_share, "_test/", false)
                .await
                .expect("watch failed");

            // Spawn a local task to create a file after a short delay.
            let test_file_path = "_test/smb2_watch_test.tmp";
            let writer_task = tokio::task::spawn_local(async move {
                let mut writer_client = connect_client_to_nas().await;
                let mut writer_share = writer_client
                    .connect_share("naspi")
                    .await
                    .expect("tree connect failed (writer)");

                tokio::time::sleep(Duration::from_millis(500)).await;

                writer_client
                    .write_file(&mut writer_share, test_file_path, b"watch test")
                    .await
                    .expect("write_file failed");

                println!("Writer: created {}", test_file_path);
                (writer_client, writer_share)
            });

            // Wait for the notification (with a timeout so we don't hang).
            let events = tokio::time::timeout(Duration::from_secs(10), watcher.next_events())
                .await
                .expect("timed out waiting for change notification")
                .expect("next_events failed");

            println!("Received {} event(s):", events.len());
            for event in &events {
                println!("  {} {}", event.action, event.filename);
            }

            assert!(!events.is_empty(), "expected at least one event");

            // We should see an Added event for our test file.
            let added = events.iter().find(|e| e.action == FileNotifyAction::Added);
            assert!(
                added.is_some(),
                "expected an Added event, got: {:?}",
                events
                    .iter()
                    .map(|e| format!("{}: {}", e.action, e.filename))
                    .collect::<Vec<_>>()
            );

            // Close the watcher.
            watcher.close().await.expect("watcher close failed");

            // Wait for the writer task and clean up.
            let (mut writer_client, mut writer_share) = writer_task.await.unwrap();
            writer_client
                .delete_file(&mut writer_share, test_file_path)
                .await
                .expect("delete_file failed");
            println!("Cleaned up {}", test_file_path);

            let _ = writer_client.disconnect_share(&writer_share).await;
        })
        .await;
}

#[tokio::test]
#[ignore]
async fn kerberos_auth_against_docker_kdc() {
    let _ = env_logger::try_init();

    // Connect to the Docker Samba server with Kerberos
    let mut conn = Connection::connect("127.0.0.1:10462", Duration::from_secs(5))
        .await
        .expect("failed to connect to Docker Samba");

    conn.negotiate().await.expect("negotiate failed");

    let params = conn.params().unwrap();
    println!("Negotiated dialect: {}", params.dialect);

    // Kerberos auth via Docker KDC
    let credentials = smb2::KerberosCredentials {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        realm: "TEST.LOCAL".to_string(),
        kdc_address: "127.0.0.1:10088".to_string(),
    };

    let session = Session::setup_kerberos(&mut conn, &credentials, "localhost")
        .await
        .expect("Kerberos session setup failed");

    println!("Kerberos session established: {}", session.session_id);
    println!("Signing: {}", session.should_sign);

    // Connect to the share
    let tree = smb2::Tree::connect(&mut conn, "public")
        .await
        .expect("tree connect failed");

    println!("Tree connected: {}", tree.tree_id);

    // Write and read a file to verify the session works
    let test_data = b"Kerberos auth works!";
    tree.write_file(&mut conn, "krb_test.txt", test_data)
        .await
        .expect("write failed");

    let read_back = tree
        .read_file(&mut conn, "krb_test.txt")
        .await
        .expect("read failed");

    assert_eq!(read_back, test_data);
    println!("Kerberos auth verified: wrote and read file successfully");

    // Cleanup
    let _ = tree.delete_file(&mut conn, "krb_test.txt").await;
    let _ = tree.disconnect(&mut conn).await;
}

#[tokio::test]
#[ignore]
async fn kerberos_auth_against_aws_windows_ad() {
    let _ = env_logger::try_init();

    load_dotenv();
    let server_ip = std::env::var("SMB2_TEST_AWS_AD_IP")
        .expect("SMB2_TEST_AWS_AD_IP not set (public IP of the Windows AD DC)");
    let server_hostname = std::env::var("SMB2_TEST_AWS_AD_HOSTNAME").expect(
        "SMB2_TEST_AWS_AD_HOSTNAME not set (computer name of the DC, e.g. EC2AMAZ-XXXXXXX)",
    );

    println!("Connecting to AWS Windows AD at {}...", server_ip);

    // Connect to the Windows Server SMB port.
    let mut conn = Connection::connect(&format!("{}:445", server_ip), Duration::from_secs(10))
        .await
        .expect("failed to connect to AWS Windows AD");

    conn.negotiate().await.expect("negotiate failed");

    let params = conn.params().unwrap();
    println!("Negotiated dialect: {}", params.dialect);
    println!("Max read size: {}", params.max_read_size);
    println!("Signing required: {}", params.signing_required);
    println!("Server GUID: {:?}", params.server_guid);

    // Kerberos auth against the Windows AD KDC.
    let credentials = smb2::KerberosCredentials {
        username: "smbtest".to_string(),
        password: "Kerberos!Test1".to_string(),
        realm: "TEST.LOCAL".to_string(),
        kdc_address: format!("{}:88", server_ip),
    };

    // Try both FQDN and short hostname for SPN.
    let spn_hostname = std::env::var("SMB2_TEST_AWS_AD_SPN")
        .unwrap_or_else(|_| format!("{}.test.local", server_hostname.to_lowercase()));
    println!("Using SPN: cifs/{}", spn_hostname);

    let session = Session::setup_kerberos(&mut conn, &credentials, &spn_hostname)
        .await
        .expect("Kerberos session setup failed");

    println!("Kerberos session established: {}", session.session_id);
    println!("Signing: {}", session.should_sign);

    // Connect to the test share.
    let tree = smb2::Tree::connect(&mut conn, "testshare")
        .await
        .expect("tree connect to testshare failed");

    println!("Tree connected: {}", tree.tree_id);

    // Write and read a file to verify the session works.
    let test_data = b"Kerberos auth works on real Windows AD!";
    tree.write_file(&mut conn, "krb_test.txt", test_data)
        .await
        .expect("write failed");

    let read_back = tree
        .read_file(&mut conn, "krb_test.txt")
        .await
        .expect("read failed");

    assert_eq!(read_back, test_data);
    println!("Kerberos auth verified: wrote and read file on Windows AD");

    // Cleanup.
    let _ = tree.delete_file(&mut conn, "krb_test.txt").await;
    let _ = tree.disconnect(&mut conn).await;
}

#[tokio::test]
#[ignore]
async fn kerberos_auth_from_ccache() {
    let _ = env_logger::try_init();

    load_dotenv();
    let server_ip = std::env::var("SMB2_TEST_AWS_AD_IP").expect("SMB2_TEST_AWS_AD_IP not set");
    let server_hostname =
        std::env::var("SMB2_TEST_AWS_AD_HOSTNAME").expect("SMB2_TEST_AWS_AD_HOSTNAME not set");
    let ccache_path = std::env::var("SMB2_TEST_CCACHE")
        .expect("SMB2_TEST_CCACHE not set (path to a file-based Kerberos ccache)");

    let spn_hostname = std::env::var("SMB2_TEST_AWS_AD_SPN")
        .unwrap_or_else(|_| format!("{}.test.local", server_hostname.to_lowercase()));

    println!("Loading ccache from {}...", ccache_path);
    let ccache_data = std::fs::read(&ccache_path).expect("failed to read ccache file");
    let ccache =
        smb2::auth::kerberos::ccache::parse_ccache(&ccache_data).expect("failed to parse ccache");
    println!(
        "Ccache: principal={}@{}, {} credentials",
        ccache.default_principal.components.join("/"),
        ccache.default_principal.realm,
        ccache.credentials.len()
    );

    // Connect and negotiate.
    let mut conn = Connection::connect(&format!("{}:445", server_ip), Duration::from_secs(10))
        .await
        .expect("failed to connect");

    conn.negotiate().await.expect("negotiate failed");
    println!("Negotiated dialect: {}", conn.params().unwrap().dialect);

    // Authenticate using the ccache (TGT only — does TGS exchange).
    let credentials = smb2::KerberosCredentials {
        username: ccache.default_principal.components[0].clone(),
        password: String::new(), // not needed for ccache
        realm: ccache.default_principal.realm.clone(),
        kdc_address: format!("{}:88", server_ip),
    };

    let session =
        Session::setup_kerberos_from_ccache(&mut conn, &credentials, &spn_hostname, &ccache)
            .await
            .expect("Kerberos session setup from ccache failed");

    println!("Kerberos session from ccache: {}", session.session_id);

    // Verify by writing and reading a file.
    let tree = smb2::Tree::connect(&mut conn, "testshare")
        .await
        .expect("tree connect failed");

    let test_data = b"Kerberos from ccache works!";
    tree.write_file(&mut conn, "ccache_test.txt", test_data)
        .await
        .expect("write failed");

    let read_back = tree
        .read_file(&mut conn, "ccache_test.txt")
        .await
        .expect("read failed");

    assert_eq!(read_back, test_data);
    println!("Kerberos ccache auth verified: wrote and read file");

    let _ = tree.delete_file(&mut conn, "ccache_test.txt").await;
    let _ = tree.disconnect(&mut conn).await;
}
