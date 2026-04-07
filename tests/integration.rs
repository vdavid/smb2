//! Integration tests against a real SMB server.
//!
//! These tests require a NAS at 192.168.1.111 and are marked `#[ignore]`.
//! Run with: `cargo test --test integration -- --ignored`

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
