//! Integration tests against Docker Samba containers.
//!
//! Requires containers running (see tests/docker/start.sh).
//! All tests are `#[ignore]` so `cargo test` doesn't fail without Docker.
//!
//! Run with:
//!   just test-docker                      # starts containers, runs, stops
//!   cargo test --test docker_integration -- --ignored   # if containers are already running

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::time::Duration;

use smb2::client::{list_shares, ClientConfig, Connection, Session, SmbClient, Tree};

const GUEST_ADDR: &str = "127.0.0.1:10445";
const AUTH_ADDR: &str = "127.0.0.1:10446";
const SIGNING_ADDR: &str = "127.0.0.1:10447";
const READONLY_ADDR: &str = "127.0.0.1:10448";
const ANCIENT_ADDR: &str = "127.0.0.1:10449";
const FLAKY_ADDR: &str = "127.0.0.1:10450";
const SLOW_ADDR: &str = "127.0.0.1:10451";
const ENCRYPTION_ADDR: &str = "127.0.0.1:10452";
const SHARES50_ADDR: &str = "127.0.0.1:10453";
const MAXREAD_ADDR: &str = "127.0.0.1:10454";
const ENCRYPTION_AES128_ADDR: &str = "127.0.0.1:10455";
const DFS_ROOT_ADDR: &str = "127.0.0.1:10456";
const DFS_TARGET_ADDR: &str = "127.0.0.1:10457";
const TIMEOUT: Duration = Duration::from_secs(5);

// ── Helpers ──────────────────────────────────────────────────────────

/// Connect, negotiate, and authenticate as guest to smb-guest.
async fn connect_guest() -> (Connection, Tree) {
    let mut conn = Connection::connect(GUEST_ADDR, TIMEOUT)
        .await
        .expect("failed to connect to smb-guest");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("guest session setup failed");
    let tree = Tree::connect(&mut conn, "public")
        .await
        .expect("tree connect to 'public' failed");
    (conn, tree)
}

/// Create an SmbClient connected as guest to smb-guest.
async fn guest_client() -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: GUEST_ADDR.to_string(),
        timeout: TIMEOUT,
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("SmbClient::connect to smb-guest failed")
}

/// Create an SmbClient connected with credentials to smb-auth.
async fn auth_client() -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: AUTH_ADDR.to_string(),
        timeout: TIMEOUT,
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("SmbClient::connect to smb-auth failed")
}

// ── Basic operations (smb-guest) ─────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_connect_negotiate_list_directory() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let params = conn.params().unwrap();
    // Any SMB2+ dialect is fine — just verify we negotiated successfully.
    assert!(
        params.dialect as u16 >= 0x0202,
        "expected SMB2+ dialect, got {}",
        params.dialect
    );

    let entries = tree
        .list_directory(&mut conn, "")
        .await
        .expect("list directory failed");

    // Empty directory is fine — we just need it to not error.
    // The directory exists and is listable.
    drop(entries);

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_write_read_delete() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let test_path = "docker_test_write_read.tmp";
    let test_data = b"Hello from Docker integration test!";

    // Write.
    let written = tree
        .write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed");
    assert_eq!(written, test_data.len() as u64);

    // Read back.
    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, test_data);

    // Delete.
    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_stat_file() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let test_path = "docker_test_stat.tmp";
    let test_data = b"stat test content";
    tree.write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed");

    let info = tree.stat(&mut conn, test_path).await.expect("stat failed");
    assert_eq!(info.size, test_data.len() as u64);
    assert!(!info.is_directory);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_create_delete_directory() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let dir_path = "docker_test_dir_tmp";

    tree.create_directory(&mut conn, dir_path)
        .await
        .expect("create_directory failed");

    let info = tree.stat(&mut conn, dir_path).await.expect("stat failed");
    assert!(info.is_directory);

    tree.delete_directory(&mut conn, dir_path)
        .await
        .expect("delete_directory failed");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

// ── Compound operations (smb-guest) ──────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_compound_read() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let test_path = "docker_test_compound_read.tmp";
    let test_data = b"compound read test data 1234567890";
    tree.write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed");

    let data = tree
        .read_file_compound(&mut conn, test_path)
        .await
        .expect("read_file_compound failed");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_compound_write() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let test_path = "docker_test_compound_write.tmp";
    let test_data = b"compound write test data 1234567890";

    let written = tree
        .write_file_compound(&mut conn, test_path, test_data)
        .await
        .expect("write_file_compound failed");
    assert_eq!(written, test_data.len() as u64);

    // Read back to verify.
    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, test_data);

    // Empty file via compound.
    let empty_path = "docker_test_compound_empty.tmp";
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

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.delete_file(&mut conn, empty_path)
        .await
        .expect("delete empty file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

// ── Pipelined I/O (smb-guest) ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_pipelined_read() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let test_path = "docker_test_pipelined_read.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

    tree.write_file(&mut conn, test_path, &test_data)
        .await
        .expect("write_file failed");

    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed");

    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_pipelined_write() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let test_path = "docker_test_pipelined_write.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();

    let written = tree
        .write_file_pipelined(&mut conn, test_path, &test_data)
        .await
        .expect("write_file_pipelined failed");
    assert_eq!(written, test_data.len() as u64);

    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

// ── Share enumeration ────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_list_shares() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(GUEST_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");

    let shares = list_shares(&mut conn).await.expect("list_shares failed");

    assert!(
        shares.iter().any(|s| s.name == "public"),
        "expected 'public' share, got: {:?}",
        shares.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
#[ignore]
async fn auth_list_shares() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(AUTH_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "testuser", "testpass", "")
        .await
        .expect("session setup failed");

    let shares = list_shares(&mut conn).await.expect("list_shares failed");

    assert!(
        shares.iter().any(|s| s.name == "private"),
        "expected 'private' share, got: {:?}",
        shares.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
}

// ── SmbClient high-level API (smb-guest) ─────────────────────────────

#[tokio::test]
#[ignore]
async fn smb_client_guest_connect_and_list() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;

    let params = client.params().unwrap();
    assert!(params.dialect as u16 >= 0x0202);

    let tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let entries = tree
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory failed");
    drop(entries);

    tree.disconnect(client.connection_mut())
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn smb_client_guest_list_shares() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let shares = client.list_shares().await.expect("list_shares failed");

    assert!(
        shares.iter().any(|s| s.name == "public"),
        "expected 'public' share"
    );
}

// ── Authentication (smb-auth) ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn auth_connect_and_operate() {
    let _ = env_logger::try_init();

    let mut client = auth_client().await;
    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    // Write, read, delete.
    let test_path = "docker_test_auth.tmp";
    let test_data = b"authenticated write test";

    client
        .write_file(&mut tree, test_path, test_data)
        .await
        .expect("write_file failed");

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, test_data);

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
async fn auth_wrong_password_fails_cleanly() {
    let _ = env_logger::try_init();

    let result = SmbClient::connect(ClientConfig {
        addr: AUTH_ADDR.to_string(),
        timeout: TIMEOUT,
        username: "testuser".to_string(),
        password: "wrongpassword".to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: HashMap::new(),
    })
    .await;

    assert!(result.is_err(), "expected auth failure, got Ok");
}

// ── Streaming (smb-guest) ────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_streaming_download() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_stream_download.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

    client
        .write_file(&mut tree, test_path, &test_data)
        .await
        .expect("write_file failed");

    let mut download = client
        .download(&tree, test_path)
        .await
        .expect("download failed");
    assert_eq!(download.size(), test_data.len() as u64);

    let mut received = Vec::new();
    while let Some(chunk) = download.next_chunk().await {
        let bytes = chunk.expect("next_chunk failed");
        assert!(!bytes.is_empty());
        received.extend_from_slice(&bytes);
    }

    assert!(
        (download.progress().fraction() - 1.0).abs() < f64::EPSILON,
        "expected progress 1.0, got {}",
        download.progress().fraction()
    );
    assert_eq!(received, test_data);

    drop(download);

    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

/// `Tree::download` (borrowed `&mut Connection`) mirrors
/// `SmbClient::download` against a real Samba container. Same payload, same
/// RTT shape — the only difference is the caller holds the `Connection`
/// directly, which is what unlocks concurrent downloads on cloned
/// connections.
#[tokio::test]
#[ignore]
async fn guest_tree_download_streams_via_connection() {
    let _ = env_logger::try_init();

    let (mut conn, tree) = connect_guest().await;

    let test_path = "docker_test_tree_download.tmp";
    let test_data: Vec<u8> = (0..524_288).map(|i| (i % 251) as u8).collect();

    // Seed the file through the high-level client, then download it back
    // via the low-level Tree::download API.
    {
        let mut client = guest_client().await;
        let mut write_tree = client
            .connect_share("public")
            .await
            .expect("connect_share failed");
        client
            .write_file(&mut write_tree, test_path, &test_data)
            .await
            .expect("write_file failed");
        client
            .disconnect_share(&write_tree)
            .await
            .expect("disconnect failed");
    }

    let mut download = tree
        .download(&mut conn, test_path)
        .await
        .expect("Tree::download failed");
    assert_eq!(download.size(), test_data.len() as u64);

    let mut received = Vec::new();
    while let Some(chunk) = download.next_chunk().await {
        let bytes = chunk.expect("next_chunk failed");
        assert!(!bytes.is_empty());
        received.extend_from_slice(&bytes);
    }
    assert_eq!(received, test_data);

    drop(download);

    // Clean up via a fresh client (we already consumed `conn` for the
    // download; reuse it for the delete to exercise the same connection
    // end-to-end).
    let mut client = guest_client().await;
    let mut cleanup_tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");
    client
        .delete_file(&mut cleanup_tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&cleanup_tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_streaming_upload() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    // 2 MB to exceed MaxWriteSize and trigger chunked path.
    let test_path = "docker_test_stream_upload.tmp";
    let test_data: Vec<u8> = (0..2_097_152).map(|i| (i % 251) as u8).collect();

    let mut upload = client
        .upload(&tree, test_path, &test_data)
        .await
        .expect("upload failed");
    assert_eq!(upload.total_bytes(), test_data.len() as u64);

    while upload
        .write_next_chunk()
        .await
        .expect("write_next_chunk failed")
    {}

    assert!(
        (upload.progress().fraction() - 1.0).abs() < f64::EPSILON,
        "expected progress 1.0, got {}",
        upload.progress().fraction()
    );

    drop(upload);

    let readback = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(readback, test_data);

    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

// ── Write with progress and cancellation (smb-guest) ─────────────────

#[tokio::test]
#[ignore]
async fn guest_write_with_progress() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_write_progress.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();

    let mut progress_updates = Vec::new();
    let written = client
        .write_file_with_progress(&mut tree, test_path, &test_data, |progress| {
            progress_updates.push(progress.bytes_transferred);
            ControlFlow::Continue(())
        })
        .await
        .expect("write_file_with_progress failed");

    assert_eq!(written, test_data.len() as u64);
    assert!(!progress_updates.is_empty());

    let readback = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(readback, test_data);

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
async fn guest_write_cancel_midway() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let cancel_path = "docker_test_write_cancel.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();
    let half = test_data.len() as u64 / 2;

    let result = client
        .write_file_with_progress(&mut tree, cancel_path, &test_data, |progress| {
            if progress.bytes_transferred >= half {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .await;

    match result {
        Err(smb2::Error::Cancelled) => {}
        other => panic!("expected Error::Cancelled, got {:?}", other),
    }

    // Best-effort cleanup.
    let _ = client.delete_file(&mut tree, cancel_path).await;
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

// ── fs_info (smb-guest) ──────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_fs_info() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let info = client.fs_info(&mut tree).await.expect("fs_info failed");

    assert!(info.total_bytes > 0);
    assert!(info.free_bytes <= info.total_bytes);
    assert!(info.bytes_per_sector > 0);
    assert!(info.sectors_per_unit > 0);

    let _ = client.disconnect_share(&tree).await;
}

// ── Reconnect (smb-guest) ────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_reconnect() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;

    // Verify it works.
    let tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");
    let entries = tree
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory failed");
    drop(entries);
    tree.disconnect(client.connection_mut())
        .await
        .expect("disconnect failed");

    // Reconnect.
    client.reconnect().await.expect("reconnect failed");

    // Verify it works again.
    let tree2 = client
        .connect_share("public")
        .await
        .expect("connect_share after reconnect failed");
    let entries2 = tree2
        .list_directory(client.connection_mut(), "")
        .await
        .expect("list_directory after reconnect failed");
    drop(entries2);
    tree2
        .disconnect(client.connection_mut())
        .await
        .expect("disconnect failed");
}

// ── File watching (smb-guest) ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_watch_directory() {
    use smb2::FileNotifyAction;

    let _ = env_logger::try_init();

    // File watching needs two connections on the same thread (SmbClient is !Send).
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut watcher_client = guest_client().await;
            let mut watcher_share = watcher_client
                .connect_share("public")
                .await
                .expect("tree connect failed (watcher)");

            // Ensure a subdirectory to watch exists.
            let _ = watcher_client
                .create_directory(&mut watcher_share, "_test_watch")
                .await;

            let mut watcher = watcher_client
                .watch(&watcher_share, "_test_watch/", false)
                .await
                .expect("watch failed");

            // Spawn a writer on a second connection.
            let test_file_path = "_test_watch/docker_watch_test.tmp";
            let writer_task = tokio::task::spawn_local(async move {
                let mut writer_client = guest_client().await;
                let mut writer_share = writer_client
                    .connect_share("public")
                    .await
                    .expect("tree connect failed (writer)");

                tokio::time::sleep(Duration::from_millis(500)).await;

                writer_client
                    .write_file(&mut writer_share, test_file_path, b"watch test")
                    .await
                    .expect("write_file failed");

                (writer_client, writer_share)
            });

            let events = tokio::time::timeout(Duration::from_secs(10), watcher.next_events())
                .await
                .expect("timed out waiting for change notification")
                .expect("next_events failed");

            assert!(!events.is_empty());
            let added = events.iter().find(|e| e.action == FileNotifyAction::Added);
            assert!(added.is_some(), "expected an Added event");

            watcher.close().await.expect("watcher close failed");

            // Cleanup.
            let (mut writer_client, mut writer_share) = writer_task.await.unwrap();
            writer_client
                .delete_file(&mut writer_share, test_file_path)
                .await
                .expect("delete_file failed");
            let _ = writer_client.disconnect_share(&writer_share).await;

            let _ = watcher_client
                .delete_directory(&mut watcher_share, "_test_watch")
                .await;
        })
        .await;
}

// ── Mandatory signing (smb-signing) ──────────────────────────────────

#[tokio::test]
#[ignore]
async fn signing_negotiated_as_required() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SIGNING_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");

    let params = conn.params().unwrap();
    assert!(
        params.signing_required,
        "expected signing_required=true from smb-signing server"
    );
}

#[tokio::test]
#[ignore]
async fn signing_write_read_roundtrip() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SIGNING_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "testuser", "testpass", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "private")
        .await
        .expect("tree connect failed");

    let test_path = "docker_test_signing.tmp";
    let test_data = b"signed write test data 1234567890";

    let written = tree
        .write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed (signing)");
    assert_eq!(written, test_data.len() as u64);

    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed (signing)");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn signing_compound_operations() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SIGNING_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "testuser", "testpass", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "private")
        .await
        .expect("tree connect failed");

    let test_path = "docker_test_signing_compound.tmp";
    let test_data = b"compound over signed transport";

    tree.write_file_compound(&mut conn, test_path, test_data)
        .await
        .expect("write_file_compound failed (signing)");

    let data = tree
        .read_file_compound(&mut conn, test_path)
        .await
        .expect("read_file_compound failed (signing)");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn signing_pipelined_large_file() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SIGNING_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "testuser", "testpass", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "private")
        .await
        .expect("tree connect failed");

    let test_path = "docker_test_signing_pipelined.tmp";
    let test_data: Vec<u8> = (0..524_288).map(|i| (i % 251) as u8).collect();

    tree.write_file_pipelined(&mut conn, test_path, &test_data)
        .await
        .expect("write_file_pipelined failed (signing)");

    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed (signing)");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

// ── Read-only share (smb-readonly) ───────────────────────────────────

#[tokio::test]
#[ignore]
async fn readonly_list_and_read_succeed() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(READONLY_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "readonly")
        .await
        .expect("tree connect failed");

    // List directory succeeds.
    let entries = tree
        .list_directory(&mut conn, "")
        .await
        .expect("list_directory failed");
    assert!(
        entries.iter().any(|e| e.name == "sample.txt"),
        "expected sample.txt in readonly share"
    );

    // Read file succeeds.
    let data = tree
        .read_file(&mut conn, "sample.txt")
        .await
        .expect("read_file failed on readonly share");
    assert!(!data.is_empty());

    // Stat file succeeds.
    let info = tree
        .stat(&mut conn, "sample.txt")
        .await
        .expect("stat failed on readonly share");
    assert!(!info.is_directory);

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn readonly_write_returns_error() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(READONLY_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "readonly")
        .await
        .expect("tree connect failed");

    let result = tree.write_file(&mut conn, "should_fail.tmp", b"nope").await;

    assert!(result.is_err(), "expected write to fail on readonly share");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn readonly_delete_returns_error() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(READONLY_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "readonly")
        .await
        .expect("tree connect failed");

    let result = tree.delete_file(&mut conn, "sample.txt").await;
    assert!(result.is_err(), "expected delete to fail on readonly share");

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn readonly_create_directory_returns_error() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(READONLY_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "readonly")
        .await
        .expect("tree connect failed");

    let result = tree.create_directory(&mut conn, "should_fail_dir").await;
    assert!(
        result.is_err(),
        "expected create_directory to fail on readonly share"
    );

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

// ── SMB1-only server (smb-ancient) ───────────────────────────────────

#[tokio::test]
#[ignore]
async fn ancient_smb1_rejected_cleanly() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(ANCIENT_ADDR, TIMEOUT)
        .await
        .expect("TCP connect should succeed even to SMB1 server");

    // Negotiate should fail: server only speaks SMB1, we only speak SMB2+.
    let result = conn.negotiate().await;
    assert!(
        result.is_err(),
        "expected negotiate to fail against SMB1-only server"
    );
}

// ── Mandatory encryption (smb-encryption, share-level, SMB 3.1.1) ────

/// Helper: SmbClient connected to the encryption server.
async fn encryption_client() -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: ENCRYPTION_ADDR.to_string(),
        timeout: TIMEOUT,
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("SmbClient::connect to smb-encryption failed")
}

#[tokio::test]
#[ignore]
async fn encryption_required_connect_and_operate() {
    let _ = env_logger::try_init();

    let mut client = encryption_client().await;
    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_encrypted.tmp";
    let test_data = b"encrypted write test data 1234567890";

    client
        .write_file(&mut tree, test_path, test_data)
        .await
        .expect("write_file failed (encrypted)");

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed (encrypted)");
    assert_eq!(data, test_data);

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
async fn encryption_required_pipelined_large_file() {
    let _ = env_logger::try_init();

    let mut client = encryption_client().await;
    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_encrypted_pipelined.tmp";
    let test_data: Vec<u8> = (0..524_288).map(|i| (i % 199) as u8).collect();

    client
        .write_file_pipelined(&mut tree, test_path, &test_data)
        .await
        .expect("write_file_pipelined failed (encrypted)");

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed (encrypted)");
    assert_eq!(data, test_data);

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
async fn encryption_required_list_shares() {
    let _ = env_logger::try_init();

    let mut client = encryption_client().await;
    let shares = client.list_shares().await.expect("list_shares failed");
    assert!(
        shares.iter().any(|s| s.name == "private"),
        "expected 'private' share, got: {:?}",
        shares.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
}

// ── AES-128-CCM encryption (smb-encryption-aes128, SMB 3.0.2) ───────

#[tokio::test]
#[ignore]
async fn encryption_aes128_ccm_connect_and_operate() {
    let _ = env_logger::try_init();

    let mut client = SmbClient::connect(ClientConfig {
        addr: ENCRYPTION_AES128_ADDR.to_string(),
        timeout: TIMEOUT,
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("connect failed");

    let params = client.params().unwrap();
    assert!(
        params.dialect as u16 >= 0x0300 && params.dialect as u16 <= 0x0302,
        "expected SMB 3.0-3.0.2, got {}",
        params.dialect
    );

    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_aes128.tmp";
    let test_data = b"AES-128-CCM encrypted write test";

    client
        .write_file(&mut tree, test_path, test_data)
        .await
        .expect("write_file failed (AES-128-CCM)");

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed (AES-128-CCM)");
    assert_eq!(data, test_data);

    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

// ── Flaky server (smb-flaky, 5s up / 5s down) ───────────────────────

#[tokio::test]
#[ignore]
async fn flaky_connect_during_up_phase() {
    let _ = env_logger::try_init();

    // The flaky server cycles 5s up / 5s down. We retry the full
    // connect+negotiate sequence for up to 15 seconds to catch an "up" window.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let (mut conn, tree) = loop {
        let connect_result = async {
            let mut c = Connection::connect(FLAKY_ADDR, Duration::from_secs(2)).await?;
            c.negotiate().await?;
            let _session = Session::setup(&mut c, "", "", "").await?;
            let t = Tree::connect(&mut c, "public").await?;
            Ok::<_, smb2::Error>((c, t))
        }
        .await;

        match connect_result {
            Ok(result) => break result,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("could not connect to flaky server within 15s: {}", e),
        }
    };

    // Verify basic operation works during the up phase.
    let entries = tree
        .list_directory(&mut conn, "")
        .await
        .expect("list_directory failed");
    drop(entries);

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn flaky_error_is_clean_not_hang() {
    let _ = env_logger::try_init();

    // Connect during an up phase.
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut client = loop {
        match SmbClient::connect(ClientConfig {
            addr: FLAKY_ADDR.to_string(),
            timeout: Duration::from_secs(1),
            username: String::new(),
            password: String::new(),
            domain: String::new(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: true,
            dfs_target_overrides: HashMap::new(),
        })
        .await
        {
            Ok(c) => break c,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("could not connect to flaky server within 12s: {}", e),
        }
    };

    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    // Wait for the server to cycle down (up to 10s).
    // Keep trying operations — eventually one should fail with a clean error.
    let mut got_error = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        match client.list_directory(&mut tree, "").await {
            Ok(_) => continue,
            Err(smb2::Error::Io(_) | smb2::Error::Disconnected) => {
                got_error = true;
                break;
            }
            Err(e) => {
                // Any error is acceptable — the point is it didn't hang.
                got_error = true;
                eprintln!("flaky server error (acceptable): {}", e);
                break;
            }
        }
    }

    assert!(got_error, "expected an error after server went down");
}

// ── Slow server (smb-slow, 200ms latency) ────────────────────────────

#[tokio::test]
#[ignore]
async fn slow_operations_still_work() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SLOW_ADDR, Duration::from_secs(10))
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "public")
        .await
        .expect("tree connect failed");

    let test_path = "docker_test_slow.tmp";
    let test_data = b"slow server test data";

    tree.write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed (slow)");

    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed (slow)");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn slow_pipelined_large_file() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SLOW_ADDR, Duration::from_secs(10))
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "public")
        .await
        .expect("tree connect failed");

    // 256 KB over a 200ms-latency link — pipelining matters here.
    let test_path = "docker_test_slow_pipelined.tmp";
    let test_data: Vec<u8> = (0..262_144).map(|i| (i % 199) as u8).collect();

    tree.write_file_pipelined(&mut conn, test_path, &test_data)
        .await
        .expect("write_file_pipelined failed (slow)");

    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed (slow)");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

// ── 50-share server (smb-50shares) ───────────────────────────────────

#[tokio::test]
#[ignore]
async fn shares50_list_all() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SHARES50_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");

    let shares = list_shares(&mut conn).await.expect("list_shares failed");

    // Filter out IPC$ and other admin shares.
    let user_shares: Vec<_> = shares.iter().filter(|s| !s.name.ends_with('$')).collect();

    assert_eq!(
        user_shares.len(),
        50,
        "expected 50 user shares, got {} (total including admin: {})",
        user_shares.len(),
        shares.len()
    );

    // Verify naming pattern.
    assert!(user_shares.iter().any(|s| s.name == "share_01"));
    assert!(user_shares.iter().any(|s| s.name == "share_50"));
}

#[tokio::test]
#[ignore]
async fn shares50_connect_to_first_and_last() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SHARES50_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");

    // Connect to first share.
    let tree1 = Tree::connect(&mut conn, "share_01")
        .await
        .expect("tree connect to share_01 failed");
    tree1
        .disconnect(&mut conn)
        .await
        .expect("disconnect failed");

    // Connect to last share.
    let tree50 = Tree::connect(&mut conn, "share_50")
        .await
        .expect("tree connect to share_50 failed");
    tree50
        .disconnect(&mut conn)
        .await
        .expect("disconnect failed");
}

// ── Tiny MaxReadSize (smb-maxreadsize) ───────────────────────────────

#[tokio::test]
#[ignore]
async fn maxread_negotiated_small() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(MAXREAD_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");

    let params = conn.params().unwrap();
    assert!(
        params.max_read_size <= 65536,
        "expected max_read_size <= 64KB, got {}",
        params.max_read_size
    );
    assert!(
        params.max_write_size <= 65536,
        "expected max_write_size <= 64KB, got {}",
        params.max_write_size
    );
}

#[tokio::test]
#[ignore]
async fn maxread_large_file_still_works() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(MAXREAD_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "public")
        .await
        .expect("tree connect failed");

    // 512 KB file with 64 KB max read/write -> many chunks.
    let test_path = "docker_test_maxread.tmp";
    let test_data: Vec<u8> = (0..524_288).map(|i| (i % 199) as u8).collect();

    tree.write_file_pipelined(&mut conn, test_path, &test_data)
        .await
        .expect("write_file_pipelined failed (maxreadsize)");

    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed (maxreadsize)");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn maxread_streaming_download() {
    let _ = env_logger::try_init();

    let mut client = SmbClient::connect(ClientConfig {
        addr: MAXREAD_ADDR.to_string(),
        timeout: TIMEOUT,
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("connect failed");

    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_maxread_stream.tmp";
    let test_data: Vec<u8> = (0..262_144).map(|i| (i % 251) as u8).collect();

    client
        .write_file(&mut tree, test_path, &test_data)
        .await
        .expect("write_file failed");

    let mut download = client
        .download(&tree, test_path)
        .await
        .expect("download failed");

    let mut received = Vec::new();
    let mut chunk_count = 0u32;
    while let Some(chunk) = download.next_chunk().await {
        let bytes = chunk.expect("next_chunk failed");
        received.extend_from_slice(&bytes);
        chunk_count += 1;
    }

    assert_eq!(received, test_data);
    // With 64KB max read and 256KB file, we should get at least 4 chunks.
    assert!(
        chunk_count >= 4,
        "expected at least 4 chunks, got {}",
        chunk_count
    );

    drop(download);
    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

// ── DFS tests (smb-dfs-root:10456 -> smb-dfs-target:10457) ─────────

/// Helper: SmbClient connected to the DFS root server.
///
/// The DFS link in the root share points to `smb-dfs-target\files` (Docker
/// internal hostname). Since the test runs on the host, we override
/// `smb-dfs-target` to `127.0.0.1:10457` (the port-mapped address).
async fn dfs_client() -> SmbClient {
    let mut overrides = HashMap::new();
    overrides.insert("smb-dfs-target".to_string(), DFS_TARGET_ADDR.to_string());
    SmbClient::connect(ClientConfig {
        addr: DFS_ROOT_ADDR.to_string(),
        timeout: TIMEOUT,
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: overrides,
    })
    .await
    .expect("SmbClient::connect to smb-dfs-root failed")
}

#[tokio::test]
#[ignore]
async fn dfs_tree_connect_reports_dfs_capability() {
    let _ = env_logger::try_init();

    let mut client = dfs_client().await;
    let tree = client
        .connect_share("dfs")
        .await
        .expect("connect_share('dfs') failed");

    assert!(tree.is_dfs, "expected DFS root share to report is_dfs=true");

    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn dfs_read_file_through_link() {
    let _ = env_logger::try_init();

    let mut client = dfs_client().await;
    let mut tree = client
        .connect_share("dfs")
        .await
        .expect("connect_share('dfs') failed");

    // "data/hello.txt" goes through the DFS link to smb-dfs-target's "files" share.
    let data = client
        .read_file(&mut tree, "data/hello.txt")
        .await
        .expect("read_file through DFS link failed");

    let text = String::from_utf8(data).expect("not UTF-8");
    assert_eq!(text.trim(), "Hello from DFS target!");

    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn dfs_list_directory_through_link() {
    let _ = env_logger::try_init();

    let mut client = dfs_client().await;
    let mut tree = client
        .connect_share("dfs")
        .await
        .expect("connect_share('dfs') failed");

    // List the "data/" directory, which is a DFS link to smb-dfs-target's "files" share.
    let entries = client
        .list_directory(&mut tree, "data")
        .await
        .expect("list_directory through DFS link failed");

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"hello.txt"),
        "expected hello.txt in DFS-linked directory, got: {:?}",
        names
    );
    assert!(
        names.contains(&"subdir"),
        "expected subdir in DFS-linked directory, got: {:?}",
        names
    );

    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn dfs_write_and_read_roundtrip() {
    let _ = env_logger::try_init();

    let test_path = "data/docker_dfs_roundtrip.tmp";
    let test_data = b"DFS roundtrip test data 1234567890";

    // Write through DFS link using a fresh client.
    {
        let mut client = dfs_client().await;
        let mut tree = client
            .connect_share("dfs")
            .await
            .expect("connect_share('dfs') failed");

        client
            .write_file(&mut tree, test_path, test_data)
            .await
            .expect("write_file through DFS link failed");

        client
            .disconnect_share(&tree)
            .await
            .expect("disconnect failed");
    }

    // Read back through DFS link using a fresh client (separate DFS resolution).
    {
        let mut client = dfs_client().await;
        let mut tree = client
            .connect_share("dfs")
            .await
            .expect("connect_share('dfs') failed");

        let data = client
            .read_file(&mut tree, test_path)
            .await
            .expect("read_file through DFS link failed");
        assert_eq!(data, test_data);

        // Clean up: after the DFS redirect, the tree now points to the
        // target share directly. Use the target-relative path (without
        // the "data/" DFS link prefix) for cleanup.
        client
            .delete_file(&mut tree, "docker_dfs_roundtrip.tmp")
            .await
            .expect("delete_file on target failed");

        client
            .disconnect_share(&tree)
            .await
            .expect("disconnect failed");
    }
}

// ── Streamed write (smb-guest) ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_streamed_write() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_1mb.tmp";
    let total_size = 1_048_576usize; // 1 MB
    let chunk_size = 256 * 1024; // 256 KB
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 199) as u8).collect();

    let mut offset = 0usize;
    let data_ref = &test_data;
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if offset >= data_ref.len() {
            return None;
        }
        let end = (offset + chunk_size).min(data_ref.len());
        let chunk = data_ref[offset..end].to_vec();
        offset = end;
        Some(Ok(chunk))
    };

    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    assert_eq!(written, total_size as u64);

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

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
async fn guest_streamed_write_small_file() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_small.tmp";
    let test_data: Vec<u8> = (0..100).map(|i| (i % 199) as u8).collect();

    let mut called = false;
    let data_clone = test_data.clone();
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if called {
            return None;
        }
        called = true;
        Some(Ok(data_clone.clone()))
    };

    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    assert_eq!(written, 100);

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, test_data);

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
async fn guest_streamed_write_large() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_10mb.tmp";
    let total_size = 10 * 1024 * 1024usize; // 10 MB
    let chunk_size = 256 * 1024;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 199) as u8).collect();

    let mut offset = 0usize;
    let data_ref = &test_data;
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if offset >= data_ref.len() {
            return None;
        }
        let end = (offset + chunk_size).min(data_ref.len());
        let chunk = data_ref[offset..end].to_vec();
        offset = end;
        Some(Ok(chunk))
    };

    let start = std::time::Instant::now();
    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    let elapsed = start.elapsed();
    assert_eq!(written, total_size as u64);

    println!(
        "Streamed write: {} bytes in {:.2?} ({:.1} MB/s)",
        written,
        elapsed,
        written as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    );

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

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
async fn guest_streamed_write_empty() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_empty.tmp";

    let mut next_chunk = || -> Option<Result<Vec<u8>, std::io::Error>> { None };

    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    assert_eq!(written, 0);

    // Verify empty file was created.
    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert!(data.is_empty(), "expected empty file");

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
async fn maxread_streamed_write() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(MAXREAD_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "public")
        .await
        .expect("tree connect failed");

    let test_path = "smb2_test_streamed_maxread.tmp";
    let total_size = 512 * 1024usize; // 512 KB
    let chunk_size = 64 * 1024; // 64 KB (matches server max)
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 199) as u8).collect();

    let mut offset = 0usize;
    let data_ref = &test_data;
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if offset >= data_ref.len() {
            return None;
        }
        let end = (offset + chunk_size).min(data_ref.len());
        let chunk = data_ref[offset..end].to_vec();
        offset = end;
        Some(Ok(chunk))
    };

    let written = tree
        .write_file_streamed(&mut conn, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed (maxreadsize)");
    assert_eq!(written, total_size as u64);

    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed (maxreadsize)");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn signing_streamed_write() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(SIGNING_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "testuser", "testpass", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "private")
        .await
        .expect("tree connect failed");

    let test_path = "smb2_test_streamed_signing.tmp";
    let total_size = 512 * 1024usize;
    let chunk_size = 64 * 1024;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 199) as u8).collect();

    let mut offset = 0usize;
    let data_ref = &test_data;
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if offset >= data_ref.len() {
            return None;
        }
        let end = (offset + chunk_size).min(data_ref.len());
        let chunk = data_ref[offset..end].to_vec();
        offset = end;
        Some(Ok(chunk))
    };

    let written = tree
        .write_file_streamed(&mut conn, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed (signing)");
    assert_eq!(written, total_size as u64);

    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed (signing)");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn encryption_streamed_write() {
    let _ = env_logger::try_init();

    let mut client = encryption_client().await;
    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_encryption.tmp";
    let total_size = 512 * 1024usize;
    let chunk_size = 64 * 1024;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 199) as u8).collect();

    let mut offset = 0usize;
    let data_ref = &test_data;
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if offset >= data_ref.len() {
            return None;
        }
        let end = (offset + chunk_size).min(data_ref.len());
        let chunk = data_ref[offset..end].to_vec();
        offset = end;
        Some(Ok(chunk))
    };

    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed (encryption)");
    assert_eq!(written, total_size as u64);

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed (encryption)");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

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
async fn readonly_streamed_write_fails() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(READONLY_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "", "", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "readonly")
        .await
        .expect("tree connect failed");

    let mut next_chunk =
        || -> Option<Result<Vec<u8>, std::io::Error>> { Some(Ok(vec![0x42; 100])) };

    let result = tree
        .write_file_streamed(
            &mut conn,
            "smb2_test_streamed_readonly.tmp",
            &mut next_chunk,
        )
        .await;

    assert!(
        result.is_err(),
        "expected streamed write to fail on readonly share"
    );

    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_streamed_write_early_stop() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_early_stop.tmp";
    let chunk_size = 1024usize;
    let chunks_to_send = 2;

    // Build deterministic data for 2 chunks.
    let expected_data: Vec<u8> = (0..(chunk_size * chunks_to_send))
        .map(|i| (i % 199) as u8)
        .collect();

    let mut call_count = 0usize;
    let data_ref = &expected_data;
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if call_count >= chunks_to_send {
            return None; // Stop early (a 10-chunk file would need 10 calls).
        }
        let start = call_count * chunk_size;
        let end = start + chunk_size;
        let chunk = data_ref[start..end].to_vec();
        call_count += 1;
        Some(Ok(chunk))
    };

    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    assert_eq!(written, (chunk_size * chunks_to_send) as u64);

    // Verify partial file exists with correct content.
    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data.len(), expected_data.len(), "size mismatch");
    assert_eq!(data, expected_data, "content mismatch");

    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

// ── Streamed write stress tests ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_streamed_write_stress_100mb() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_stress_100mb.tmp";
    let total_size = 100 * 1024 * 1024usize; // 100 MB
    let chunk_size = 1024 * 1024; // 1 MB chunks

    // Build deterministic data.
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 251) as u8).collect();

    let mut offset = 0usize;
    let data_ref = &test_data;
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if offset >= data_ref.len() {
            return None;
        }
        let end = (offset + chunk_size).min(data_ref.len());
        let chunk = data_ref[offset..end].to_vec();
        offset = end;
        Some(Ok(chunk))
    };

    let start = std::time::Instant::now();
    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    let write_elapsed = start.elapsed();
    assert_eq!(written, total_size as u64);

    println!(
        "Stress write: {} MB in {:.2?} ({:.1} MB/s)",
        total_size / (1024 * 1024),
        write_elapsed,
        written as f64 / (1024.0 * 1024.0) / write_elapsed.as_secs_f64()
    );

    // Read back and verify integrity.
    let read_data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(read_data.len(), test_data.len(), "size mismatch");
    assert_eq!(
        read_data, test_data,
        "content mismatch in 100 MB stress test"
    );

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
async fn guest_streamed_write_rapid_sequential_50_files() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let file_count = 50;
    let file_size = 1024usize; // 1 KB each

    for i in 0..file_count {
        let test_path = format!("smb2_test_rapid_seq_{:03}.tmp", i);
        let test_data: Vec<u8> = (0..file_size).map(|j| ((j + i * 7) % 251) as u8).collect();

        let mut called = false;
        let data_clone = test_data.clone();
        let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
            if called {
                return None;
            }
            called = true;
            Some(Ok(data_clone.clone()))
        };

        let written = client
            .write_file_streamed(&mut tree, &test_path, &mut next_chunk)
            .await
            .unwrap_or_else(|e| panic!("write_file_streamed failed on file {}: {}", i, e));
        assert_eq!(written, file_size as u64, "wrong byte count for file {}", i);
    }

    // Read back all 50 files and verify.
    for i in 0..file_count {
        let test_path = format!("smb2_test_rapid_seq_{:03}.tmp", i);
        let expected: Vec<u8> = (0..file_size).map(|j| ((j + i * 7) % 251) as u8).collect();

        let data = client
            .read_file(&mut tree, &test_path)
            .await
            .unwrap_or_else(|e| panic!("read_file failed on file {}: {}", i, e));
        assert_eq!(data, expected, "content mismatch on file {}", i);
    }

    // Cleanup.
    for i in 0..file_count {
        let test_path = format!("smb2_test_rapid_seq_{:03}.tmp", i);
        client
            .delete_file(&mut tree, &test_path)
            .await
            .unwrap_or_else(|e| panic!("delete_file failed on file {}: {}", i, e));
    }

    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_streamed_write_large_single_chunk() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_large_chunk.tmp";
    let total_size = 5 * 1024 * 1024usize; // 5 MB as a single chunk
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 251) as u8).collect();

    // Deliver the entire 5 MB in one callback call. This forces the
    // chunk-splitting logic to split against max_write_size.
    let mut called = false;
    let data_clone = test_data.clone();
    let mut next_chunk = move || -> Option<Result<Vec<u8>, std::io::Error>> {
        if called {
            return None;
        }
        called = true;
        Some(Ok(data_clone.clone()))
    };

    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    assert_eq!(written, total_size as u64);

    let read_data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(read_data.len(), test_data.len(), "size mismatch");
    assert_eq!(
        read_data, test_data,
        "content mismatch in large single-chunk test"
    );

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
async fn guest_streamed_write_alternating_sizes() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_streamed_alternating.tmp";

    // Build chunks alternating between 1 byte and 1 MB.
    let small_size = 1usize;
    let large_size = 1024 * 1024usize;
    let num_pairs = 5; // 5 pairs of (1 byte, 1 MB)

    let mut expected_data = Vec::new();
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    for pair in 0..num_pairs {
        // Small chunk: 1 byte.
        let small = vec![(pair * 2) as u8; small_size];
        expected_data.extend_from_slice(&small);
        chunks.push(small);

        // Large chunk: 1 MB with deterministic pattern.
        let large: Vec<u8> = (0..large_size)
            .map(|j| ((j + pair * 13) % 251) as u8)
            .collect();
        expected_data.extend_from_slice(&large);
        chunks.push(large);
    }

    let mut chunk_iter = chunks.into_iter();
    let mut next_chunk =
        move || -> Option<Result<Vec<u8>, std::io::Error>> { chunk_iter.next().map(Ok) };

    let written = client
        .write_file_streamed(&mut tree, test_path, &mut next_chunk)
        .await
        .expect("write_file_streamed failed");
    assert_eq!(written, expected_data.len() as u64);

    let read_data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(read_data.len(), expected_data.len(), "size mismatch");
    assert_eq!(
        read_data, expected_data,
        "content mismatch in alternating sizes test"
    );

    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

// ── FileWriter (push-based streaming writes) ──────────────────────────

#[tokio::test]
#[ignore]
async fn guest_file_writer_basic() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_basic.bin";
    let chunk1 = b"Hello, ";
    let chunk2 = b"FileWriter ";
    let chunk3 = b"world!";
    let expected: Vec<u8> = [&chunk1[..], &chunk2[..], &chunk3[..]].concat();

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    writer
        .write_chunk(chunk1)
        .await
        .expect("write_chunk 1 failed");
    writer
        .write_chunk(chunk2)
        .await
        .expect("write_chunk 2 failed");
    writer
        .write_chunk(chunk3)
        .await
        .expect("write_chunk 3 failed");

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, expected.len() as u64);

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, expected, "content mismatch");

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
async fn guest_file_writer_large() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_large.bin";
    let chunk_size = 1024 * 1024; // 1 MB
    let num_chunks = 5;
    let total_size = chunk_size * num_chunks;
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 199) as u8).collect();

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        let end = start + chunk_size;
        writer
            .write_chunk(&test_data[start..end])
            .await
            .expect("write_chunk failed");
    }

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, total_size as u64);

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

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
async fn guest_file_writer_empty_file() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_empty.bin";

    let writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, 0);

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert!(data.is_empty(), "expected empty file");

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
async fn guest_file_writer_single_byte() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_single_byte.bin";

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    writer
        .write_chunk(&[0x42])
        .await
        .expect("write_chunk failed");

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, 1);

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, vec![0x42]);

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
async fn guest_file_writer_overwrite() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_overwrite.bin";

    // Write a 10 KB file first.
    let big_data: Vec<u8> = (0..10240).map(|i| (i % 251) as u8).collect();
    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed (first write)");
    writer
        .write_chunk(&big_data)
        .await
        .expect("write_chunk failed (first write)");
    let written1 = writer.finish().await.expect("finish failed (first write)");
    assert_eq!(written1, 10240);

    // Overwrite with a 1 KB file.
    let small_data: Vec<u8> = (0..1024).map(|i| (i % 173) as u8).collect();
    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed (overwrite)");
    writer
        .write_chunk(&small_data)
        .await
        .expect("write_chunk failed (overwrite)");
    let written2 = writer.finish().await.expect("finish failed (overwrite)");
    assert_eq!(written2, 1024);

    // Read back -- must be exactly 1 KB, no leftover from old file.
    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data.len(), 1024, "expected 1 KB, got {} bytes", data.len());
    assert_eq!(data, small_data, "content mismatch after overwrite");

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
async fn guest_file_writer_equivalence_with_pipelined() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_data: Vec<u8> = (0..512 * 1024).map(|i| (i % 199) as u8).collect();

    // Write via write_file_pipelined.
    let pipelined_path = "smb2_test_fw_equiv_pipelined.bin";
    client
        .write_file_pipelined(&mut tree, pipelined_path, &test_data)
        .await
        .expect("write_file_pipelined failed");

    // Write via FileWriter.
    let writer_path = "smb2_test_fw_equiv_writer.bin";
    let chunk_size = 64 * 1024;
    let mut writer = client
        .create_file_writer(&tree, writer_path)
        .await
        .expect("create_file_writer failed");
    for chunk in test_data.chunks(chunk_size) {
        writer.write_chunk(chunk).await.expect("write_chunk failed");
    }
    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, test_data.len() as u64);

    // Read both back and compare.
    let pipelined_data = client
        .read_file_pipelined(&mut tree, pipelined_path)
        .await
        .expect("read pipelined file failed");
    let writer_data = client
        .read_file_pipelined(&mut tree, writer_path)
        .await
        .expect("read writer file failed");

    assert_eq!(pipelined_data.len(), writer_data.len(), "size mismatch");
    assert_eq!(
        pipelined_data, writer_data,
        "FileWriter output differs from write_file_pipelined"
    );

    client
        .delete_file(&mut tree, pipelined_path)
        .await
        .expect("delete pipelined file failed");
    client
        .delete_file(&mut tree, writer_path)
        .await
        .expect("delete writer file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn guest_file_writer_binary_data() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_binary.bin";

    // Build data containing all 256 byte values, repeated for good measure.
    let mut test_data = Vec::with_capacity(256 * 4);
    for round in 0..4u8 {
        for byte in 0..=255u8 {
            test_data.push(byte.wrapping_add(round.wrapping_mul(37)));
        }
    }

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    // Write in two chunks to exercise boundary handling.
    let mid = test_data.len() / 2;
    writer
        .write_chunk(&test_data[..mid])
        .await
        .expect("write_chunk 1 failed");
    writer
        .write_chunk(&test_data[mid..])
        .await
        .expect("write_chunk 2 failed");

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, test_data.len() as u64);

    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, test_data, "binary data mismatch");

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
async fn maxread_file_writer() {
    let _ = env_logger::try_init();

    let mut client = SmbClient::connect(ClientConfig {
        addr: MAXREAD_ADDR.to_string(),
        timeout: TIMEOUT,
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: false,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("connect failed");
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_maxread.bin";
    let total_size = 200 * 1024usize; // 200 KB
    let chunk_size = 50 * 1024; // 50 KB chunks
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 199) as u8).collect();

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    for chunk in test_data.chunks(chunk_size) {
        writer.write_chunk(chunk).await.expect("write_chunk failed");
    }

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, total_size as u64);

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(data.len(), test_data.len(), "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

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
async fn signing_file_writer() {
    let _ = env_logger::try_init();

    let mut client = SmbClient::connect(ClientConfig {
        addr: SIGNING_ADDR.to_string(),
        timeout: TIMEOUT,
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: false,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("connect failed");
    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_signing.bin";
    let test_data: Vec<u8> = (0..128 * 1024).map(|i| (i % 199) as u8).collect();

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    for chunk in test_data.chunks(32 * 1024) {
        writer.write_chunk(chunk).await.expect("write_chunk failed");
    }

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, test_data.len() as u64);

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(data, test_data, "content mismatch");

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
async fn encryption_file_writer() {
    let _ = env_logger::try_init();

    let mut client = encryption_client().await;
    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_encryption.bin";
    let test_data: Vec<u8> = (0..128 * 1024).map(|i| (i % 199) as u8).collect();

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    for chunk in test_data.chunks(32 * 1024) {
        writer.write_chunk(chunk).await.expect("write_chunk failed");
    }

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, test_data.len() as u64);

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(data, test_data, "content mismatch");

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
async fn readonly_file_writer_error() {
    let _ = env_logger::try_init();

    let mut client = SmbClient::connect(ClientConfig {
        addr: READONLY_ADDR.to_string(),
        timeout: TIMEOUT,
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: false,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("connect failed");
    let tree = client
        .connect_share("readonly")
        .await
        .expect("connect_share failed");

    let is_err = client
        .create_file_writer(&tree, "smb2_test_file_writer_readonly.bin")
        .await
        .is_err();

    assert!(
        is_err,
        "expected create_file_writer to fail on readonly share"
    );

    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

// ── FileWriter stress tests ──────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_file_writer_stress_100mb() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_stress_100mb.bin";
    let chunk_size = 1024 * 1024; // 1 MB
    let num_chunks = 100;
    let total_size = chunk_size * num_chunks;

    // Build deterministic data
    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 251) as u8).collect();

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        let end = start + chunk_size;
        writer
            .write_chunk(&test_data[start..end])
            .await
            .expect("write_chunk failed");
    }

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, total_size as u64);

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(data.len(), total_size, "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

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
async fn slow_file_writer_stress_100mb() {
    let _ = env_logger::try_init();

    let mut client = SmbClient::connect(ClientConfig {
        addr: SLOW_ADDR.to_string(),
        timeout: Duration::from_secs(30),
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: false,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .expect("connect failed");
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "smb2_test_file_writer_slow_stress.bin";
    let chunk_size = 512 * 1024; // 512 KB chunks to test more pipelining cycles
    let num_chunks = 200; // 100 MB total
    let total_size = chunk_size * num_chunks;

    let test_data: Vec<u8> = (0..total_size).map(|i| (i % 173) as u8).collect();

    let mut writer = client
        .create_file_writer(&tree, test_path)
        .await
        .expect("create_file_writer failed");

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        let end = start + chunk_size;
        writer
            .write_chunk(&test_data[start..end])
            .await
            .expect("write_chunk failed");
    }

    let bytes_written = writer.finish().await.expect("finish failed");
    assert_eq!(bytes_written, total_size as u64);

    let data = client
        .read_file_pipelined(&mut tree, test_path)
        .await
        .expect("read_file_pipelined failed");
    assert_eq!(data.len(), total_size, "size mismatch");
    assert_eq!(data, test_data, "content mismatch");

    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}
