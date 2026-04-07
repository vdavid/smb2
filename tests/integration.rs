//! Integration tests against real SMB servers.
//!
//! These tests require local network access and are marked `#[ignore]`.
//! Run with: `RUST_LOG=smb2=debug cargo test --test integration -- --ignored --nocapture`

use std::time::Duration;

use smb2::client::{Connection, Session, Tree};

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
