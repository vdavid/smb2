//! Integration tests against Docker Samba containers.
//!
//! Requires containers running (see tests/docker/start.sh).
//! All tests are `#[ignore]` so `cargo test` doesn't fail without Docker.
//!
//! Run with:
//!   just test-docker                      # starts containers, runs, stops
//!   cargo test --test docker_integration -- --ignored   # if containers are already running

use std::ops::ControlFlow;
use std::time::Duration;

use smb2::client::{list_shares, ClientConfig, Connection, Session, SmbClient, Tree};

const GUEST_ADDR: &str = "127.0.0.1:10445";
const AUTH_ADDR: &str = "127.0.0.1:10446";
const SIGNING_ADDR: &str = "127.0.0.1:10447";
const READONLY_ADDR: &str = "127.0.0.1:10448";
const ANCIENT_ADDR: &str = "127.0.0.1:10449";
const ENCRYPTION_ADDR: &str = "127.0.0.1:10452";
const SHARES50_ADDR: &str = "127.0.0.1:10453";
const MAXREAD_ADDR: &str = "127.0.0.1:10454";
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
    let tree = client
        .connect_share("private")
        .await
        .expect("connect_share failed");

    // Write, read, delete.
    let test_path = "docker_test_auth.tmp";
    let test_data = b"authenticated write test";

    client
        .write_file(&tree, test_path, test_data)
        .await
        .expect("write_file failed");

    let data = client
        .read_file(&tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(data, test_data);

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
    let tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_stream_download.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

    client
        .write_file(&tree, test_path, &test_data)
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
async fn guest_streaming_upload() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let tree = client
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
        .read_file(&tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(readback, test_data);

    client
        .delete_file(&tree, test_path)
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
    let tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_write_progress.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();

    let mut progress_updates = Vec::new();
    let written = client
        .write_file_with_progress(&tree, test_path, &test_data, |progress| {
            progress_updates.push(progress.bytes_transferred);
            ControlFlow::Continue(())
        })
        .await
        .expect("write_file_with_progress failed");

    assert_eq!(written, test_data.len() as u64);
    assert!(!progress_updates.is_empty());

    let readback = client
        .read_file(&tree, test_path)
        .await
        .expect("read_file failed");
    assert_eq!(readback, test_data);

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
async fn guest_write_cancel_midway() {
    let _ = env_logger::try_init();

    let mut client = guest_client().await;
    let tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let cancel_path = "docker_test_write_cancel.tmp";
    let test_data: Vec<u8> = (0..1_048_576).map(|i| (i % 199) as u8).collect();
    let half = test_data.len() as u64 / 2;

    let result = client
        .write_file_with_progress(&tree, cancel_path, &test_data, |progress| {
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
    let _ = client.delete_file(&tree, cancel_path).await;
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
    let tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let info = client.fs_info(&tree).await.expect("fs_info failed");

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
            let watcher_share = watcher_client
                .connect_share("public")
                .await
                .expect("tree connect failed (watcher)");

            // Ensure a subdirectory to watch exists.
            let _ = watcher_client
                .create_directory(&watcher_share, "_test_watch")
                .await;

            let mut watcher = watcher_client
                .watch(&watcher_share, "_test_watch/", false)
                .await
                .expect("watch failed");

            // Spawn a writer on a second connection.
            let test_file_path = "_test_watch/docker_watch_test.tmp";
            let writer_task = tokio::task::spawn_local(async move {
                let mut writer_client = guest_client().await;
                let writer_share = writer_client
                    .connect_share("public")
                    .await
                    .expect("tree connect failed (writer)");

                tokio::time::sleep(Duration::from_millis(500)).await;

                writer_client
                    .write_file(&writer_share, test_file_path, b"watch test")
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
            let (mut writer_client, writer_share) = writer_task.await.unwrap();
            writer_client
                .delete_file(&writer_share, test_file_path)
                .await
                .expect("delete_file failed");
            let _ = writer_client.disconnect_share(&writer_share).await;

            let _ = watcher_client
                .delete_directory(&watcher_share, "_test_watch")
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

// ── Mandatory encryption (smb-encryption) ────────────────────────────

#[tokio::test]
#[ignore]
async fn encryption_connect_and_operate() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(ENCRYPTION_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");

    let params = conn.params().unwrap();
    // With smb encrypt = desired, server advertises encryption support.
    // Verify we negotiated SMB3+ (required for encryption).
    assert!(
        params.dialect as u16 >= 0x0300,
        "expected SMB 3.x dialect for encryption server, got {}",
        params.dialect
    );

    let _session = Session::setup(&mut conn, "testuser", "testpass", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "private")
        .await
        .expect("tree connect failed");

    // Write, read, verify data integrity. With smb encrypt = desired,
    // the transport may or may not be encrypted (our lib doesn't yet
    // wrap messages in TRANSFORM_HEADER), but operations should work.
    let test_path = "docker_test_encrypted.tmp";
    let test_data = b"encryption-capable server test data 1234567890";

    let written = tree
        .write_file(&mut conn, test_path, test_data)
        .await
        .expect("write_file failed (encrypted)");
    assert_eq!(written, test_data.len() as u64);

    let data = tree
        .read_file(&mut conn, test_path)
        .await
        .expect("read_file failed (encrypted)");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn encryption_pipelined_large_file() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(ENCRYPTION_ADDR, TIMEOUT)
        .await
        .expect("connect failed");
    conn.negotiate().await.expect("negotiate failed");
    let _session = Session::setup(&mut conn, "testuser", "testpass", "")
        .await
        .expect("session setup failed");
    let tree = Tree::connect(&mut conn, "private")
        .await
        .expect("tree connect failed");

    let test_path = "docker_test_encrypted_pipelined.tmp";
    let test_data: Vec<u8> = (0..524_288).map(|i| (i % 199) as u8).collect();

    tree.write_file_pipelined(&mut conn, test_path, &test_data)
        .await
        .expect("write_file_pipelined failed (encrypted)");

    let data = tree
        .read_file_pipelined(&mut conn, test_path)
        .await
        .expect("read_file_pipelined failed (encrypted)");
    assert_eq!(data, test_data);

    tree.delete_file(&mut conn, test_path)
        .await
        .expect("delete_file failed");
    tree.disconnect(&mut conn).await.expect("disconnect failed");
}

#[tokio::test]
#[ignore]
async fn encryption_list_shares() {
    let _ = env_logger::try_init();

    let mut conn = Connection::connect(ENCRYPTION_ADDR, TIMEOUT)
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
    })
    .await
    .expect("connect failed");

    let tree = client
        .connect_share("public")
        .await
        .expect("connect_share failed");

    let test_path = "docker_test_maxread_stream.tmp";
    let test_data: Vec<u8> = (0..262_144).map(|i| (i % 251) as u8).collect();

    client
        .write_file(&tree, test_path, &test_data)
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
        .delete_file(&tree, test_path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}
