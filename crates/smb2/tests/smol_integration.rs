//! The client on smol against real Samba: the proof that it is runtime
//! agnostic, not just claiming it (issue #1).
//!
//! Every test runs inside `smol::block_on` and first proves there is no tokio
//! runtime in reach. Run it against a smol-only build, where tokio's reactor
//! isn't compiled in at all:
//!
//!   just test-docker   # runs this suite too
//!   cargo test -p smb2 --no-default-features --features smol --test smol_integration -- --ignored
//!
//! Covers what differs between runtimes: sockets, the connection's background
//! tasks, and every timer, across the session shapes that exercise them
//! (guest, NTLM with signing, mandatory signing, mandatory encryption), plus
//! the pipelined and streaming paths and a watcher's long poll.
//!
//! Requires the containers from `tests/docker/start.sh internal`. All tests
//! are `#[ignore]` so `cargo test` doesn't fail without Docker.

#![cfg(feature = "smol")]

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use smb2::client::{ClientConfig, SmbClient};
use smb2::FileNotifyAction;

const GUEST_ADDR: &str = "127.0.0.1:10445";
const AUTH_ADDR: &str = "127.0.0.1:10446";
const SIGNING_ADDR: &str = "127.0.0.1:10447";
const ENCRYPTION_ADDR: &str = "127.0.0.1:10452";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Bound for any single test's work. A hang shows up as a failure.
const TEST_BUDGET: Duration = Duration::from_secs(60);

/// Run `test` on smol, after proving tokio isn't there to catch a mistake.
fn on_smol(test: impl Future<Output = ()>) {
    let _ = env_logger::try_init();
    smol::block_on(async {
        // The dev-dependency tokio has its runtime compiled in whatever smb2's
        // features are, so this can always ask.
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "these tests must run with no tokio runtime in reach"
        );
        within(TEST_BUDGET, "the whole test", test).await;
    });
}

/// `future`, or a panic naming `what` once `budget` runs out.
async fn within<T>(budget: Duration, what: &str, future: impl Future<Output = T>) -> T {
    smol::future::or(future, async {
        smol::Timer::after(budget).await;
        panic!("{what} did not finish within {budget:?}");
    })
    .await
}

fn config(addr: &str, username: &str, password: &str) -> ClientConfig {
    ClientConfig {
        addr: addr.to_string(),
        timeout: TIMEOUT,
        username: username.to_string(),
        password: password.to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: true,
        dfs_target_overrides: HashMap::new(),
        connect_options: None,
    }
}

async fn guest_client() -> SmbClient {
    SmbClient::connect(config(GUEST_ADDR, "", ""))
        .await
        .expect("SmbClient::connect to smb-guest failed")
}

/// Write, read back, and delete one small file on `share`.
async fn write_read_delete(client: &mut SmbClient, share: &str, path: &str) {
    let mut tree = client
        .connect_share(share)
        .await
        .expect("connect_share failed");
    let data = format!("written from smol to {share}").into_bytes();

    client
        .write_file(&mut tree, path, &data)
        .await
        .expect("write_file failed");
    let read = client
        .read_file(&mut tree, path)
        .await
        .expect("read_file failed");
    assert_eq!(read, data);

    client
        .delete_file(&mut tree, path)
        .await
        .expect("delete_file failed");
    client
        .disconnect_share(&tree)
        .await
        .expect("disconnect failed");
}

#[test]
#[ignore]
fn smol_guest_lists_shares_and_round_trips_a_file() {
    on_smol(async {
        let mut client = guest_client().await;

        let shares = client.list_shares().await.expect("list_shares failed");
        assert!(shares.iter().any(|s| s.name == "public"), "got {shares:?}");

        write_read_delete(&mut client, "public", "smol_guest_round_trip.tmp").await;
    });
}

#[test]
#[ignore]
fn smol_ntlm_login_with_signing_round_trips_a_file() {
    on_smol(async {
        let mut client = SmbClient::connect(config(AUTH_ADDR, "testuser", "testpass"))
            .await
            .expect("SmbClient::connect to smb-auth failed");
        write_read_delete(&mut client, "private", "smol_auth_round_trip.tmp").await;
    });
}

#[test]
#[ignore]
fn smol_mandatory_signing_round_trips_a_file() {
    on_smol(async {
        let mut client = SmbClient::connect(config(SIGNING_ADDR, "testuser", "testpass"))
            .await
            .expect("SmbClient::connect to smb-signing failed");
        write_read_delete(&mut client, "private", "smol_signing_round_trip.tmp").await;
    });
}

#[test]
#[ignore]
fn smol_mandatory_encryption_round_trips_a_file() {
    on_smol(async {
        let mut client = SmbClient::connect(config(ENCRYPTION_ADDR, "testuser", "testpass"))
            .await
            .expect("SmbClient::connect to smb-encryption failed");
        write_read_delete(&mut client, "private", "smol_encryption_round_trip.tmp").await;
    });
}

/// The streaming paths are where the timers work hardest: the adaptive
/// read-ahead races each READ against a dispatch timer, and every upload
/// runs on the same pacing.
#[test]
#[ignore]
fn smol_streams_a_download_and_an_upload() {
    on_smol(async {
        let mut client = guest_client().await;
        let mut tree = client
            .connect_share("public")
            .await
            .expect("connect_share failed");
        let path = "smol_streaming.tmp";
        let data: Vec<u8> = (0..3 * 1_048_576).map(|i| (i % 251) as u8).collect();

        let mut upload = client
            .upload(&tree, path, &data)
            .await
            .expect("upload failed");
        while upload
            .write_next_chunk()
            .await
            .expect("write_next_chunk failed")
        {}
        drop(upload);

        let mut download = client.download(&tree, path).await.expect("download failed");
        let mut received = Vec::new();
        while let Some(chunk) = download.next_chunk().await {
            received.extend_from_slice(&chunk.expect("next_chunk failed"));
        }
        drop(download);
        assert_eq!(received, data);

        client
            .delete_file(&mut tree, path)
            .await
            .expect("delete_file failed");
        client
            .disconnect_share(&tree)
            .await
            .expect("disconnect failed");
    });
}

/// A watcher's CHANGE_NOTIFY is a long poll: it sits on the wire with the
/// keepalive and the long-poll bound (both timers) watching over it.
#[test]
#[ignore]
fn smol_watcher_sees_a_file_another_connection_writes() {
    on_smol(async {
        let dir = "_smol_watch";
        let file = "_smol_watch/smol_watch.tmp";

        let mut watcher_client = guest_client().await;
        let mut watcher_share = watcher_client
            .connect_share("public")
            .await
            .expect("connect_share failed (watcher)");
        let _ = watcher_client
            .create_directory(&mut watcher_share, dir)
            .await;
        let mut watcher = watcher_client
            .watch(&watcher_share, "_smol_watch/", false)
            .await
            .expect("watch failed");

        let mut writer_client = guest_client().await;
        let mut writer_share = writer_client
            .connect_share("public")
            .await
            .expect("connect_share failed (writer)");

        let write = async {
            smol::Timer::after(Duration::from_millis(500)).await;
            writer_client
                .write_file(&mut writer_share, file, b"watch me")
                .await
                .expect("write_file failed");
        };
        let ((), events) = smol::future::zip(
            write,
            within(
                Duration::from_secs(10),
                "the change notification",
                watcher.next_events(),
            ),
        )
        .await;

        let events = events.expect("next_events failed");
        assert!(
            events.iter().any(|e| e.action == FileNotifyAction::Added),
            "expected an Added event, got {events:?}"
        );
        watcher.close().await.expect("watcher close failed");

        writer_client
            .delete_file(&mut writer_share, file)
            .await
            .expect("delete_file failed");
        let _ = writer_client.disconnect_share(&writer_share).await;
        let _ = watcher_client
            .delete_directory(&mut watcher_share, dir)
            .await;
    });
}
