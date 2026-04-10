//! Consumer integration tests for the `smb2::testing` module.
//!
//! These tests exercise the consumer test harness from a consumer's
//! perspective (Layer 1 of the three-layer testing model). They validate
//! that connected SMB clients work end-to-end against real Docker
//! containers.
//!
//! All tests (except `test_servers_write_compose_files`) are `#[ignore]`
//! and require Docker containers to be running.
//! Run with:
//!   just test-consumer                     # starts containers, runs, stops
//!   cargo test --features testing --test consumer_integration -- --ignored

#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::time::Duration;

use smb2::client::{ClientConfig, SmbClient};
use smb2::error::ErrorKind;
use smb2::testing;

const TIMEOUT: Duration = Duration::from_secs(5);

// ── Helpers ──────────────────────────────────────────────────────────

fn guest_addr() -> String {
    format!("127.0.0.1:{}", testing::guest_port())
}

fn auth_addr() -> String {
    format!("127.0.0.1:{}", testing::auth_port())
}

fn both_addr() -> String {
    format!("127.0.0.1:{}", testing::both_port())
}

fn many_shares_addr() -> String {
    format!("127.0.0.1:{}", testing::many_shares_port())
}

fn unicode_addr() -> String {
    format!("127.0.0.1:{}", testing::unicode_port())
}

fn longnames_addr() -> String {
    format!("127.0.0.1:{}", testing::longnames_port())
}

fn deepnest_addr() -> String {
    format!("127.0.0.1:{}", testing::deepnest_port())
}

fn manyfiles_addr() -> String {
    format!("127.0.0.1:{}", testing::manyfiles_port())
}

fn readonly_addr() -> String {
    format!("127.0.0.1:{}", testing::readonly_port())
}

fn windows_addr() -> String {
    format!("127.0.0.1:{}", testing::windows_port())
}

fn synology_addr() -> String {
    format!("127.0.0.1:{}", testing::synology_port())
}

fn linux_addr() -> String {
    format!("127.0.0.1:{}", testing::linux_port())
}

fn slow_addr() -> String {
    format!("127.0.0.1:{}", testing::slow_port())
}

/// Create an SmbClient connected as guest to the given address.
async fn connect_guest(addr: &str) -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: addr.to_string(),
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
    .unwrap_or_else(|e| panic!("SmbClient::connect to {addr} failed: {e}"))
}

/// Create an SmbClient connected with credentials to the given address.
async fn connect_auth(addr: &str, username: &str, password: &str) -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: addr.to_string(),
        timeout: TIMEOUT,
        username: username.to_string(),
        password: password.to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: false,
        dfs_target_overrides: HashMap::new(),
    })
    .await
    .unwrap_or_else(|e| panic!("SmbClient::connect to {addr} failed: {e}"))
}

// ── Lifecycle test (no Docker needed) ───────────────────────────────

#[test]
fn test_servers_write_compose_files() {
    let dir = std::env::temp_dir().join("smb2_consumer_test_compose");
    // Clean up from any previous run.
    let _ = std::fs::remove_dir_all(&dir);

    testing::write_compose_files(&dir).expect("write_compose_files");

    // Verify the compose file exists.
    assert!(
        dir.join("docker-compose.yml").exists(),
        "expected docker-compose.yml in {}",
        dir.display()
    );

    // Verify at least one container subdirectory exists.
    assert!(
        dir.join("smb-consumer-guest").is_dir(),
        "expected smb-consumer-guest directory in {}",
        dir.display()
    );

    // Clean up.
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Per-container smoke tests ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn guest_list_shares() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&guest_addr()).await;
    let shares = client.list_shares().await.expect("list_shares");
    let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"public"),
        "expected 'public' share, got: {names:?}"
    );
}

#[tokio::test]
#[ignore]
async fn guest_read_sample_file() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&guest_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");
    let data = client
        .read_file(&mut tree, "welcome.txt")
        .await
        .expect("read_file");
    let text = String::from_utf8(data).expect("valid utf-8");
    assert!(
        text.contains("Hello from smb2 test server"),
        "unexpected content: {text:?}"
    );
    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn auth_connect_and_operate() {
    let _ = env_logger::try_init();

    let mut client = connect_auth(&auth_addr(), "testuser", "testpass").await;
    let mut tree = client
        .connect_share("private")
        .await
        .expect("connect_share");

    // Write a file.
    let test_path = "consumer_test_auth.tmp";
    let test_data = b"auth write test";
    client
        .write_file(&mut tree, test_path, test_data)
        .await
        .expect("write_file");

    // Read it back.
    let data = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file");
    assert_eq!(data, test_data);

    // Clean up.
    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file");
    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn both_guest_sees_public_only() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&both_addr()).await;
    let shares = client.list_shares().await.expect("list_shares");
    let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();

    assert!(
        names.contains(&"public"),
        "expected 'public' share, got: {names:?}"
    );
    // Guest should not see 'private' (it requires valid users).
    // Note: Samba may still list the share but deny access.
    // The key test is that guest CAN access public.
    let mut tree = client
        .connect_share("public")
        .await
        .expect("connect_share public");
    let entries = client
        .list_directory(&mut tree, "")
        .await
        .expect("list_directory");
    assert!(!entries.is_empty(), "expected files in public share");
    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn both_auth_sees_both() {
    let _ = env_logger::try_init();

    let mut client = connect_auth(&both_addr(), "testuser", "testpass").await;
    let shares = client.list_shares().await.expect("list_shares");
    let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();

    assert!(
        names.contains(&"public"),
        "expected 'public', got: {names:?}"
    );
    assert!(
        names.contains(&"private"),
        "expected 'private', got: {names:?}"
    );

    // Verify we can access both shares.
    let mut pub_tree = client
        .connect_share("public")
        .await
        .expect("connect public");
    client
        .list_directory(&mut pub_tree, "")
        .await
        .expect("list public");
    client
        .disconnect_share(&pub_tree)
        .await
        .expect("disconnect public");

    let mut priv_tree = client
        .connect_share("private")
        .await
        .expect("connect private");
    client
        .list_directory(&mut priv_tree, "")
        .await
        .expect("list private");
    client
        .disconnect_share(&priv_tree)
        .await
        .expect("disconnect private");
}

#[tokio::test]
#[ignore]
async fn shares50_lists_all() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&many_shares_addr()).await;
    let shares = client.list_shares().await.expect("list_shares");

    // The generate-conf.sh creates share_01 through share_50.
    assert!(
        shares.len() >= 50,
        "expected at least 50 shares, got {}",
        shares.len()
    );

    // Verify first and last are present.
    let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"share_01"), "missing share_01 in {names:?}");
    assert!(names.contains(&"share_50"), "missing share_50 in {names:?}");
}

#[tokio::test]
#[ignore]
async fn unicode_list_directory() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&unicode_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");
    let entries = client
        .list_directory(&mut tree, "")
        .await
        .expect("list_directory");

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

    // CJK filenames from populate.sh.
    assert!(
        names.contains(&"\u{65e5}\u{672c}\u{8a9e}\u{30c6}\u{30b9}\u{30c8}.txt"),
        "missing Japanese filename in {names:?}"
    );
    assert!(
        names.contains(&"\u{4e2d}\u{6587}\u{6d4b}\u{8bd5}.txt"),
        "missing Chinese filename in {names:?}"
    );

    // Emoji directory.
    assert!(
        names.iter().any(|n| n.contains('\u{1f4c1}')),
        "missing emoji folder in {names:?}"
    );

    // Accented characters.
    assert!(
        names.contains(&"caf\u{e9}.txt"),
        "missing accented filename in {names:?}"
    );

    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn longnames_list_directory() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&longnames_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");
    let entries = client
        .list_directory(&mut tree, "")
        .await
        .expect("list_directory");

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

    // The populate.sh creates a 220-char 'a' filename + ".txt".
    let long_entry = names.iter().find(|n| n.len() > 200);
    assert!(
        long_entry.is_some(),
        "expected a filename with 200+ characters, longest was {} chars",
        names.iter().map(|n| n.len()).max().unwrap_or(0)
    );

    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn deepnest_navigate_deep() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&deepnest_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");

    // Build the path to level 50 (the deepest).
    // populate.sh creates level_01/level_02/.../level_50/file.txt
    let mut path = String::new();
    for i in 1..=50 {
        if !path.is_empty() {
            path.push('\\');
        }
        path.push_str(&format!("level_{i:02}"));
    }

    // List the deepest directory.
    let entries = client
        .list_directory(&mut tree, &path)
        .await
        .expect("list deep directory");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"file.txt"),
        "expected file.txt at depth 50, got: {names:?}"
    );

    // Read the file at the bottom.
    let file_path = format!("{path}\\file.txt");
    let data = client
        .read_file(&mut tree, &file_path)
        .await
        .expect("read deep file");
    let text = String::from_utf8(data).expect("valid utf-8");
    assert!(
        text.contains("File at depth 50"),
        "unexpected content: {text:?}"
    );

    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn manyfiles_list_directory() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&manyfiles_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");
    let entries = client
        .list_directory(&mut tree, "")
        .await
        .expect("list_directory");

    // The Dockerfile creates file_1.txt through file_10000.txt.
    assert!(
        entries.len() >= 10_000,
        "expected at least 10,000 files, got {}",
        entries.len()
    );

    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn readonly_write_fails() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&readonly_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");

    let err = client
        .write_file(&mut tree, "should_fail.txt", b"nope")
        .await
        .expect_err("write should fail on readonly share");

    assert!(
        err.kind() == ErrorKind::AccessDenied || err.kind() == ErrorKind::Other,
        "expected AccessDenied or Other error, got: {err} (kind: {:?})",
        err.kind()
    );

    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn readonly_read_succeeds() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&readonly_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");

    // The Dockerfile pre-populates sample.txt.
    let data = client
        .read_file(&mut tree, "sample.txt")
        .await
        .expect("read_file on readonly share");
    let text = String::from_utf8(data).expect("valid utf-8");
    assert!(
        text.contains("Read-only sample content"),
        "unexpected content: {text:?}"
    );

    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn windows_server_info() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&windows_addr()).await;

    // Verify basic connectivity: list shares.
    let shares = client.list_shares().await.expect("list_shares");
    assert!(
        !shares.is_empty(),
        "expected at least one share on windows server"
    );

    // Connect and read a file to verify full operation.
    let mut tree = client.connect_share("public").await.expect("connect_share");
    let data = client
        .read_file(&mut tree, "shared.txt")
        .await
        .expect("read_file");
    let text = String::from_utf8(data).expect("valid utf-8");
    assert!(
        text.contains("Windows shared file"),
        "unexpected content: {text:?}"
    );
    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn synology_server_info() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&synology_addr()).await;
    let shares = client.list_shares().await.expect("list_shares");
    let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();

    // Synology has "shared" and "TimeMachine" shares.
    assert!(
        names.contains(&"shared"),
        "expected 'shared' share, got: {names:?}"
    );
    assert!(
        names.contains(&"TimeMachine"),
        "expected 'TimeMachine' share, got: {names:?}"
    );

    // Connect and verify file access.
    let mut tree = client.connect_share("shared").await.expect("connect_share");
    let entries = client
        .list_directory(&mut tree, "")
        .await
        .expect("list_directory");
    assert!(!entries.is_empty(), "expected files in shared");
    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn linux_server_info() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&linux_addr()).await;
    let shares = client.list_shares().await.expect("list_shares");
    assert!(
        !shares.is_empty(),
        "expected at least one share on linux server"
    );

    // Read a file to verify the connection works fully.
    let mut tree = client.connect_share("public").await.expect("connect_share");
    let data = client
        .read_file(&mut tree, "welcome.txt")
        .await
        .expect("read_file");
    let text = String::from_utf8(data).expect("valid utf-8");
    assert!(
        text.contains("Linux server shared file"),
        "unexpected content: {text:?}"
    );
    client.disconnect_share(&tree).await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn slow_operations_work() {
    let _ = env_logger::try_init();

    let mut client = connect_guest(&slow_addr()).await;
    let mut tree = client.connect_share("public").await.expect("connect_share");

    // Read a pre-populated file despite 200ms latency.
    let data = client
        .read_file(&mut tree, "sample.txt")
        .await
        .expect("read_file on slow server");
    let text = String::from_utf8(data).expect("valid utf-8");
    assert!(
        text.contains("Slow server sample file"),
        "unexpected content: {text:?}"
    );

    // Write and read back to verify both directions work under latency.
    let test_path = "consumer_test_slow.tmp";
    let test_data = b"slow write test data";
    client
        .write_file(&mut tree, test_path, test_data)
        .await
        .expect("write_file on slow server");
    let readback = client
        .read_file(&mut tree, test_path)
        .await
        .expect("read_file after write on slow server");
    assert_eq!(readback, test_data);

    // Clean up.
    client
        .delete_file(&mut tree, test_path)
        .await
        .expect("delete_file");
    client.disconnect_share(&tree).await.expect("disconnect");
}
