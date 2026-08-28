//! TDD repro for a production deadlock in concurrent pipelined writes.
//!
//! These tests exercise the push-based [`FileWriter`] code path used by
//! cmdr's `SmbVolume::write_from_stream`:
//!
//!   client.create_file_writer(&tree, path).await
//!   loop { writer.write_chunk(&data).await }
//!   writer.finish().await
//!
//! The production hang shows up inside `FileWriter::finish()` after the
//! CLOSE has been sent and the writer is awaiting its response. We try
//! to provoke it locally against the `smb-maxreadsize` (64 KB chunk) and
//! `smb-slow` (200 ms latency) Docker fixtures, with growing concurrency
//! and an "interleaved stats" variant that mirrors cmdr's `OverwriteSmaller`
//! pre-flight pattern.
//!
//! The test API constraint: `FileWriter` borrows `&mut Connection` for its
//! lifetime, so we can't run N writers off one `SmbClient`. Instead each
//! task opens its own full `SmbClient::connect(...)` — N independent
//! connections to the same server. That still hammers the server side
//! (queueing, locks, signing context per session), which is what we care
//! about for reproducing the bug.
//!
//! These tests are `#[ignore]`d because they need the Docker containers.
//!
//! Run with:
//!   docker compose -f tests/docker/internal/docker-compose.yml up -d smb-maxreadsize smb-slow
//!   RUST_LOG=smb2=debug cargo test --test concurrent_writes -- --ignored --nocapture
//!   docker compose -f tests/docker/internal/docker-compose.yml down

use std::sync::Arc;
use std::time::{Duration, Instant};

use smb2::{ClientConfig, SmbClient};
use tokio::time::timeout;

const MAXREAD_ADDR: &str = "127.0.0.1:10454";
const SLOW_ADDR: &str = "127.0.0.1:10451";
const SHARE: &str = "public";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default wall-clock budget for fast-fixture tests.
const HANG_BUDGET: Duration = Duration::from_secs(30);
/// Generous budget for the slow-fixture variant (200 ms latency × many ops).
const SLOW_HANG_BUDGET: Duration = Duration::from_secs(60);

/// Build a guest-auth ClientConfig for the given server address.
fn guest_config(addr: &str) -> ClientConfig {
    ClientConfig {
        addr: addr.to_string(),
        timeout: CONNECT_TIMEOUT,
        username: String::new(),
        password: String::new(),
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: false,
        dfs_target_overrides: std::collections::HashMap::new(),
    }
}

/// Generate a deterministic test payload of `size` bytes.
fn make_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 199) as u8).collect()
}

/// Open a fresh `SmbClient` against `addr`, authenticate as guest, and
/// tree-connect to `SHARE`. Returns the client and tree.
async fn fresh_client(addr: &str) -> (SmbClient, smb2::Tree) {
    let mut client = SmbClient::connect(guest_config(addr))
        .await
        .expect("SmbClient::connect failed (is the Docker container up?)");
    let tree = client
        .connect_share(SHARE)
        .await
        .expect("connect_share('public') failed");
    (client, tree)
}

/// Drive one push-based writer end-to-end: write `payload` in chunks of
/// `chunk_size` bytes, then call `finish()`. Returns the bytes finished.
async fn drive_writer(
    client: &mut SmbClient,
    tree: &smb2::Tree,
    path: &str,
    payload: &[u8],
    chunk_size: usize,
) -> u64 {
    let mut writer = client
        .create_file_writer(tree, path)
        .await
        .unwrap_or_else(|e| panic!("create_file_writer({}) failed: {:?}", path, e));
    for chunk in payload.chunks(chunk_size) {
        writer
            .write_chunk(chunk)
            .await
            .unwrap_or_else(|e| panic!("write_chunk on {} failed: {:?}", path, e));
    }
    writer
        .finish()
        .await
        .unwrap_or_else(|e| panic!("finish() on {} failed: {:?}", path, e))
}

/// Run `n` concurrent writers, each on its own SmbClient, all pointed at
/// `addr`. Each writes `payload` to a distinct path under `prefix`. Returns
/// `Ok(elapsed)` on success or `Err(())` on hang-timeout.
async fn run_concurrent_writers(
    addr: &str,
    n: usize,
    prefix: &str,
    payload: Arc<Vec<u8>>,
    chunk_size: usize,
    budget: Duration,
) -> Result<Duration, ()> {
    let start = Instant::now();
    let prefix = prefix.to_string();
    let run = async move {
        let mut joins = Vec::with_capacity(n);
        for i in 0..n {
            let payload = Arc::clone(&payload);
            let path = format!("{}_{}.bin", prefix, i);
            let addr = addr.to_string();
            joins.push(tokio::spawn(async move {
                let (mut client, tree) = fresh_client(&addr).await;
                let bytes = drive_writer(&mut client, &tree, &path, &payload, chunk_size).await;
                assert_eq!(
                    bytes,
                    payload.len() as u64,
                    "writer {} wrote wrong byte count",
                    i
                );
                i
            }));
        }
        for j in joins {
            j.await.expect("writer task panicked");
        }
    };

    match timeout(budget, run).await {
        Ok(()) => Ok(start.elapsed()),
        Err(_) => Err(()),
    }
}

// ── Test 1: baseline (N=8) via SmbClient + FileWriter ─────────────────
//
// 8 concurrent writers, each on its own SmbClient connection, each writes
// a 256 KB file via the push-based FileWriter (create_file_writer →
// write_chunk → finish). This matches cmdr's `SmbVolume::write_from_stream`
// shape exactly. If the bug is per-FileWriter::finish, this should hit it.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn concurrent_writers_via_smbclient_finish_all_n8() {
    let _ = env_logger::try_init();

    let n: usize = 8;
    let payload = Arc::new(make_payload(256 * 1024)); // 4 wire WRITEs at 64 KB

    let result = run_concurrent_writers(
        MAXREAD_ADDR,
        n,
        "concurrent_test_n8",
        payload,
        256 * 1024, // single write_chunk; FileWriter splits to max_write
        HANG_BUDGET,
    )
    .await;

    match result {
        Ok(elapsed) => {
            eprintln!(
                "concurrent_writers_via_smbclient_finish_all_n8: PASSED in {:?} (n={})",
                elapsed, n
            );
        }
        Err(()) => panic!(
            "concurrent writers (N={}) hung past {:?} — FileWriter::finish deadlock reproduced",
            n, HANG_BUDGET
        ),
    }
}

// ── Test 2: higher concurrency (N=32) ────────────────────────────────
//
// Same shape as test 1, but with 32 writers. If 8 isn't enough to expose
// the bug locally, 32 widens the in-flight window across the server and
// gives the receiver loop more frames to multiplex.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn concurrent_writers_via_smbclient_high_concurrency_finish_all() {
    let _ = env_logger::try_init();

    let n: usize = 32;
    let payload = Arc::new(make_payload(256 * 1024));

    let result = run_concurrent_writers(
        MAXREAD_ADDR,
        n,
        "concurrent_test_n32",
        payload,
        256 * 1024,
        HANG_BUDGET,
    )
    .await;

    match result {
        Ok(elapsed) => {
            eprintln!(
                "concurrent_writers_via_smbclient_high_concurrency_finish_all: PASSED in {:?} (n={})",
                elapsed, n
            );
        }
        Err(()) => panic!(
            "concurrent writers (N={}) hung past {:?} — high-concurrency deadlock reproduced",
            n, HANG_BUDGET
        ),
    }
}

// ── Test 3: interleaved with stats (mixed traffic) ────────────────────
//
// Mirrors cmdr's `OverwriteSmaller` pre-flight pattern. While 8 writers
// are mid-flight, fire a stream of `Tree::stat` calls (get_metadata) on a
// separate SmbClient against random paths on the same share. The
// production log showed a `get_metadata` for source #20 queued forever at
// `clone_session.lock` next to a stuck writer. The bug may need this
// mixed traffic shape, not pure writes.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn concurrent_writers_interleaved_with_stats() {
    let _ = env_logger::try_init();

    let n: usize = 8;
    let payload = Arc::new(make_payload(256 * 1024));

    // Stat-spammer: an independent SmbClient hammering stat() while
    // writers run. We stop it as soon as the writer batch returns.
    let stop = Arc::new(tokio::sync::Notify::new());
    let stop_for_stats = Arc::clone(&stop);

    let stat_handle = tokio::spawn(async move {
        let (mut client, mut tree) = fresh_client(MAXREAD_ADDR).await;
        let stat_paths = [
            "stat_target_a.bin",
            "stat_target_b.bin",
            "stat_target_c.bin",
            "concurrent_test_mixed_0.bin",
            "concurrent_test_mixed_4.bin",
            "concurrent_test_mixed_7.bin",
            "this_file_does_not_exist.bin",
        ];
        let mut i = 0usize;
        let mut stats = 0u64;
        loop {
            tokio::select! {
                biased;
                _ = stop_for_stats.notified() => break,
                _ = async {
                    let path = stat_paths[i % stat_paths.len()];
                    // Errors are expected (NOT_FOUND) — we only care about
                    // generating traffic.
                    let _ = client.stat(&mut tree, path).await;
                    i = i.wrapping_add(1);
                    stats += 1;
                    // Tiny yield so we don't saturate one core.
                    tokio::task::yield_now().await;
                } => {}
            }
        }
        stats
    });

    let writer_result = run_concurrent_writers(
        MAXREAD_ADDR,
        n,
        "concurrent_test_mixed",
        payload,
        256 * 1024,
        HANG_BUDGET,
    )
    .await;

    stop.notify_waiters();
    let stats_done = stat_handle.await.unwrap_or(0);

    match writer_result {
        Ok(elapsed) => {
            eprintln!(
                "concurrent_writers_interleaved_with_stats: PASSED in {:?} (n={}, stats={})",
                elapsed, n, stats_done
            );
        }
        Err(()) => panic!(
            "interleaved writers+stats (N={}) hung past {:?} — mixed-traffic deadlock reproduced",
            n, HANG_BUDGET
        ),
    }
}

// ── Test 4: slow fixture (200 ms latency) ────────────────────────────
//
// Same N=8/256 KB load against `smb-slow` (200 ms one-way latency). The
// wider in-flight window may expose races the fast Samba fixture hides
// behind quick response turnaround.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn concurrent_writers_slow_fixture_finish_all() {
    let _ = env_logger::try_init();

    let n: usize = 8;
    let payload = Arc::new(make_payload(256 * 1024));

    let result = run_concurrent_writers(
        SLOW_ADDR,
        n,
        "concurrent_test_slow",
        payload,
        256 * 1024,
        SLOW_HANG_BUDGET,
    )
    .await;

    match result {
        Ok(elapsed) => {
            eprintln!(
                "concurrent_writers_slow_fixture_finish_all: PASSED in {:?} (n={})",
                elapsed, n
            );
        }
        Err(()) => panic!(
            "slow-fixture concurrent writers (N={}) hung past {:?} — \
             deadlock reproduced with 200ms RTT",
            n, SLOW_HANG_BUDGET
        ),
    }
}
