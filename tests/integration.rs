//! Integration tests against real SMB servers.
//!
//! These tests require local network access and are marked `#[ignore]`.
//! Run with: `RUST_LOG=smb2=debug cargo test --test integration -- --ignored --nocapture`

use std::ops::ControlFlow;
use std::time::Duration;

use smb2::client::{list_shares, ClientConfig, Connection, Session, SmbClient, Tree};

#[tokio::test]
#[ignore]
async fn connect_and_list_directory_on_real_nas() {
    let _ = env_logger::try_init();

    // Connect to 192.168.1.111.
    let mut conn = Connection::connect("192.168.1.111:445", Duration::from_secs(5))
        .await
        .expect("failed to connect to NAS");

    // Negotiate.
    conn.negotiate()
        .await
        .expect("negotiate failed");

    let params = conn.params().unwrap();
    println!("Negotiated dialect: {}", params.dialect);
    println!("Max read size: {}", params.max_read_size);
    println!("Signing required: {}", params.signing_required);

    // Authenticate.
    let session = Session::setup(
        &mut conn,
        "david",
        "cVYiKPJK*fRbQN5!%b&cBb63",
        "",
    )
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
    conn.negotiate()
        .await
        .expect("negotiate failed");

    let params = conn.params().unwrap();
    println!("Negotiated dialect: {}", params.dialect);
    println!("Max read size: {}", params.max_read_size);
    println!("Max transact size: {}", params.max_transact_size);
    println!("Signing required: {}", params.signing_required);

    // Authenticate as guest (empty username and password).
    let session = Session::setup(
        &mut conn,
        "",
        "",
        "",
    )
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

    let _session = Session::setup(&mut conn, "david", "cVYiKPJK*fRbQN5!%b&cBb63", "")
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
async fn stat_file_on_nas() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_to_nas().await;

    // First write a test file so we have something to stat.
    let test_path = "smb2_test_stat.tmp";
    let test_data = b"stat test content";
    tree.write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed");

    let info = tree
        .stat(&mut conn, test_path)
        .await
        .expect("stat failed");

    println!("Stat {}: size={}, is_dir={}", test_path, info.size, info.is_directory);
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
    let info = tree
        .stat(&mut conn, dir_path)
        .await
        .expect("stat failed");
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

    let _session = Session::setup(&mut conn, "david", "cVYiKPJK*fRbQN5!%b&cBb63", "")
        .await
        .expect("session setup failed");

    let shares = list_shares(&mut conn).await.expect("list_shares failed");

    println!("Shares ({} total):", shares.len());
    for share in &shares {
        println!("  {} (type=0x{:08X}) - {}", share.name, share.share_type, share.comment);
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
        println!("  {} (type=0x{:08X}) - {}", share.name, share.share_type, share.comment);
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
        password: "cVYiKPJK*fRbQN5!%b&cBb63".to_string(),
        domain: String::new(),
        auto_reconnect: false,
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
    let tree = client.connect_share("naspi").await.expect("connect_share failed");
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

    tree.disconnect(client.connection_mut()).await.expect("disconnect failed");
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
    let tree = client.connect_share("naspi").await.expect("connect_share failed");
    let entries = tree
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory failed");
    println!("Before reconnect: {} entries", entries.len());
    assert!(!entries.is_empty());
    tree.disconnect(client.connection_mut()).await.expect("disconnect failed");

    // Reconnect.
    client.reconnect().await.expect("reconnect failed");
    println!("Reconnected, new session_id={}", client.session().session_id);

    // Verify it works again: list the same directory.
    let tree2 = client.connect_share("naspi").await.expect("connect_share failed after reconnect");
    let entries2 = tree2
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory failed after reconnect");
    println!("After reconnect: {} entries", entries2.len());
    assert!(!entries2.is_empty());
    tree2.disconnect(client.connection_mut()).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn streaming_download_large_file() {
    let _ = env_logger::try_init();

    let mut client = connect_client_to_nas().await;
    let tree = client.connect_share("naspi").await.expect("connect_share failed");

    // Write a 1 MB test file.
    let test_path = "smb2_test_streaming_download.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

    client
        .write_file(&tree, test_path, &test_data)
        .await
        .expect("write_file failed");
    println!("Setup: wrote {} bytes", test_data.len());

    // Download it with the streaming API.
    let mut download = client.download(&tree, test_path).await.expect("download failed");
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
        .delete_file(&tree, test_path)
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
    let tree = client.connect_share("naspi").await.expect("connect_share failed");

    // Write a file with progress callback, verifying progress updates.
    let test_path = "smb2_test_write_progress.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();

    let mut progress_updates = Vec::new();
    let written = client
        .write_file_with_progress(&tree, test_path, &test_data, |progress| {
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
        .read_file(&tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(readback, test_data, "content mismatch after write_with_progress");

    // Clean up the first file.
    client
        .delete_file(&tree, test_path)
        .await
        .expect("delete_file failed");

    // Write another file, cancel at ~50%.
    let cancel_path = "smb2_test_write_cancel.tmp";
    let half = test_data.len() as u64 / 2;
    let result = client
        .write_file_with_progress(&tree, cancel_path, &test_data, |progress| {
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
    let _ = client.delete_file(&tree, cancel_path).await;

    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}
