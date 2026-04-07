//! Integration tests against real SMB servers.
//!
//! These tests require local network access and are marked `#[ignore]`.
//! Run with: `RUST_LOG=smb2=debug cargo test --test integration -- --ignored --nocapture`

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
