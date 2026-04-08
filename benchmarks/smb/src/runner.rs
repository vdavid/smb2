//! Orchestrates benchmark runs: warmup, iterations, median calculation.

use crate::config::{BenchConfig, Target};
use crate::{native, smb2_runner, smb_runner, Suite};
use rand::Rng;
use smb2::{SmbClient, Tree};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Per-operation timeout (90 seconds).
const OP_TIMEOUT: Duration = Duration::from_secs(90);

/// Results for a single operation across iterations (three methods).
#[derive(Clone)]
pub struct OpResult {
    pub name: String,
    pub native_times: Vec<Duration>,
    pub smb_times: Vec<Duration>,
    pub smb2_times: Vec<Duration>,
}

/// Sentinel value indicating the smb runner was skipped entirely.
pub const SKIPPED: Duration = Duration::ZERO;
/// Sentinel value indicating an operation timed out.
pub const TIMED_OUT: Duration = Duration::from_secs(u64::MAX);

impl OpResult {
    pub fn native_median(&self) -> Duration {
        median(&self.native_times)
    }

    pub fn smb_median(&self) -> Duration {
        median(&self.smb_times)
    }

    pub fn smb2_median(&self) -> Duration {
        median(&self.smb2_times)
    }

    /// Whether the smb runner was skipped (all times are ZERO).
    pub fn smb_skipped(&self) -> bool {
        self.smb_times.iter().all(|&t| t == SKIPPED)
    }

    /// Whether the smb runner timed out (any time is TIMED_OUT).
    pub fn smb_timed_out(&self) -> bool {
        self.smb_times.iter().any(|&t| t == TIMED_OUT)
    }

    /// Whether the native runner timed out.
    pub fn native_timed_out(&self) -> bool {
        self.native_times.iter().any(|&t| t == TIMED_OUT)
    }

    /// Whether the smb2 runner timed out.
    pub fn smb2_timed_out(&self) -> bool {
        self.smb2_times.iter().any(|&t| t == TIMED_OUT)
    }

    /// Ratio: smb2 / native (< 1.0 means smb2 is faster).
    pub fn smb2_vs_native(&self) -> f64 {
        let n = self.native_median().as_secs_f64();
        let s = self.smb2_median().as_secs_f64();
        if n > 0.0 { s / n } else { f64::INFINITY }
    }

    /// Ratio: smb2 / smb (< 1.0 means smb2 is faster).
    pub fn smb2_vs_smb(&self) -> f64 {
        let d = self.smb_median().as_secs_f64();
        let s = self.smb2_median().as_secs_f64();
        if d > 0.0 { s / d } else { f64::INFINITY }
    }
}

/// Results for one suite (file size category) against one target.
pub struct SuiteResult {
    pub target_name: String,
    pub suite_name: String,
    pub file_count: usize,
    pub file_size_bytes: usize,
    pub operations: Vec<OpResult>,
    pub smb_skipped: bool,
}

/// All results across all targets and suites.
pub struct AllResults {
    pub suites: Vec<SuiteResult>,
}

pub async fn run_all(
    config: &BenchConfig,
    suites: &[Suite],
    iterations: usize,
    skip_smb: bool,
) -> AllResults {
    let mut all = Vec::new();

    for target in &config.targets {
        for suite in suites {
            if suite.file_count == 0 {
                continue;
            }
            println!(
                "\n========================================\n\
                 Target: {} ({})\n\
                 Suite: {} — {} x {} KB\n\
                 ========================================",
                target.name,
                target.host,
                suite.name,
                suite.file_count,
                suite.file_size_bytes / 1024,
            );

            match run_suite(target, suite, iterations, skip_smb).await {
                Ok(result) => all.push(result),
                Err(e) => {
                    println!("  SKIPPED: {e}");
                    continue;
                }
            }
        }
    }

    AllResults { suites: all }
}

/// Format elapsed seconds since `start` as MM:SS.
fn elapsed_tag(start: Instant) -> String {
    let secs = start.elapsed().as_secs();
    format!("[{:02}:{:02}]", secs / 60, secs % 60)
}

async fn run_suite(
    target: &Target,
    suite: &Suite,
    iterations: usize,
    skip_smb: bool,
) -> Result<SuiteResult, String> {
    let bench_start = Instant::now();

    // Generate random test data (same data for all methods)
    let data = generate_data(suite.file_size_bytes);
    let tmp_base = std::env::temp_dir().join("smb-benchmark");

    let mut upload_native = Vec::new();
    let mut upload_smb = Vec::new();
    let mut upload_smb2 = Vec::new();
    let mut list_native = Vec::new();
    let mut list_smb = Vec::new();
    let mut list_smb2 = Vec::new();
    let mut download_native = Vec::new();
    let mut download_smb = Vec::new();
    let mut download_smb2 = Vec::new();
    let mut delete_native = Vec::new();
    let mut delete_smb = Vec::new();
    let mut delete_smb2 = Vec::new();

    // Connect for smb crate operations (unless skipped)
    let smb_conn = if skip_smb {
        println!("  {} {}/{}: smb crate skipped (--skip-smb)", elapsed_tag(bench_start), target.name, suite.name);
        None
    } else {
        print!("  {} {}/{}: smb crate connecting...", elapsed_tag(bench_start), target.name, suite.name);
        let conn = smb_runner::connect(target).await?;
        println!("done");
        Some(conn)
    };

    // Connect for smb2 operations
    print!("  {} {}/{}: smb2 connecting...", elapsed_tag(bench_start), target.name, suite.name);
    let (mut smb2_client, smb2_tree) = smb2_runner::connect(target).await?;
    println!("done");

    // Warmup run (not counted) — primes NAS caches
    println!("  {} {}/{}: warmup run...", elapsed_tag(bench_start), target.name, suite.name);
    run_one_cycle(
        target,
        smb_conn.as_ref(),
        &mut smb2_client,
        &smb2_tree,
        suite,
        &data,
        &tmp_base,
        bench_start,
    )
    .await;
    // Let the SMB cache settle after warmup cleanup
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Build a randomized schedule
    let mut rng = rand::rng();

    let methods_count = if skip_smb { 2 } else { 3 };

    for iter in 0..iterations {
        // Randomize order of methods
        let mut order: Vec<u8> = if skip_smb {
            vec![0, 2] // 0=native, 2=smb2
        } else {
            vec![0, 1, 2] // 0=native, 1=smb, 2=smb2
        };
        // Fisher-Yates shuffle
        for i in (1..methods_count).rev() {
            let j = rng.random_range(0..=i);
            order.swap(i, j);
        }
        println!(
            "  {} {}/{}: iteration {}/{} (order: {})...",
            elapsed_tag(bench_start),
            target.name,
            suite.name,
            iter + 1,
            iterations,
            order
                .iter()
                .map(|&m| match m {
                    0 => "native",
                    1 => "smb",
                    2 => "smb2",
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>()
                .join(", "),
        );

        let n_id = format!("n-{iter}");
        let d_id = format!("d-{iter}");
        let s_id = format!("s-{iter}");

        // Run methods in randomized order
        let mut n_result = None;
        let mut d_result = None;
        let mut s_result = None;

        for &method in &order {
            match method {
                0 => {
                    n_result =
                        Some(run_native_cycle(target, suite, &data, &tmp_base, &n_id, bench_start).await);
                }
                1 => {
                    let (client, unc_path, chunks) = smb_conn.as_ref().unwrap();
                    d_result = Some(
                        run_smb_cycle(
                            client,
                            unc_path,
                            chunks,
                            suite,
                            &data,
                            &tmp_base,
                            &d_id,
                            target,
                            bench_start,
                        )
                        .await,
                    );
                }
                2 => {
                    s_result = Some(
                        run_smb2_cycle(
                            &mut smb2_client,
                            &smb2_tree,
                            suite,
                            &data,
                            &tmp_base,
                            &s_id,
                            target,
                            bench_start,
                        )
                        .await,
                    );
                }
                _ => unreachable!(),
            }
        }

        let (un, ln, dn, deln) = n_result.unwrap();
        let (ud, ld, dd, deld) = d_result.unwrap_or((SKIPPED, SKIPPED, SKIPPED, SKIPPED));
        let (us, ls, ds, dels) = s_result.unwrap();

        upload_native.push(un);
        list_native.push(ln);
        download_native.push(dn);
        delete_native.push(deln);

        upload_smb.push(ud);
        list_smb.push(ld);
        download_smb.push(dd);
        delete_smb.push(deld);

        upload_smb2.push(us);
        list_smb2.push(ls);
        download_smb2.push(ds);
        delete_smb2.push(dels);
    }

    Ok(SuiteResult {
        target_name: target.name.clone(),
        suite_name: suite.name.to_string(),
        file_count: suite.file_count,
        file_size_bytes: suite.file_size_bytes,
        smb_skipped: skip_smb,
        operations: vec![
            OpResult {
                name: "upload".into(),
                native_times: upload_native,
                smb_times: upload_smb,
                smb2_times: upload_smb2,
            },
            OpResult {
                name: "list".into(),
                native_times: list_native,
                smb_times: list_smb,
                smb2_times: list_smb2,
            },
            OpResult {
                name: "download".into(),
                native_times: download_native,
                smb_times: download_smb,
                smb2_times: download_smb2,
            },
            OpResult {
                name: "delete".into(),
                native_times: delete_native,
                smb_times: delete_smb,
                smb2_times: delete_smb2,
            },
        ],
    })
}

/// Run one full native cycle: setup, upload, list, download, delete.
/// Each operation is wrapped in a 90-second timeout.
async fn run_native_cycle(
    target: &Target,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
    cycle_id: &str,
    bench_start: Instant,
) -> (Duration, Duration, Duration, Duration) {
    let prefix = format!("{}/{}", target.name, suite.name);

    let dir = native::setup(target, cycle_id).expect("native setup");

    // Upload
    print!("  {} {}: native upload...", elapsed_tag(bench_start), prefix);
    let upload_time = {
        let dir = dir.clone();
        let count = suite.file_count;
        let size = suite.file_size_bytes;
        let data = data.to_vec();
        match tokio::time::timeout(OP_TIMEOUT, tokio::task::spawn_blocking(move || {
            native::upload(&dir, count, size, &data)
        })).await {
            Ok(Ok(d)) => { println!("done ({:.2}s)", d.as_secs_f64()); d }
            Ok(Err(e)) => { println!("FAILED: {e}"); TIMED_OUT }
            Err(_) => { println!("TIMEOUT"); TIMED_OUT }
        }
    };

    // List
    print!("  {} {}: native list...", elapsed_tag(bench_start), prefix);
    let list_time = {
        let dir = dir.clone();
        let expected = suite.file_count;
        match tokio::time::timeout(OP_TIMEOUT, tokio::task::spawn_blocking(move || {
            let (count, elapsed) = native::list(&dir);
            if count != expected {
                log::warn!(
                    "Native list count mismatch: got {} expected {} (SMB cache likely stale)",
                    count, expected
                );
            }
            elapsed
        })).await {
            Ok(Ok(d)) => { println!("done ({:.2}s)", d.as_secs_f64()); d }
            Ok(Err(e)) => { println!("FAILED: {e}"); TIMED_OUT }
            Err(_) => { println!("TIMEOUT"); TIMED_OUT }
        }
    };

    // Download
    print!("  {} {}: native download...", elapsed_tag(bench_start), prefix);
    let download_time = {
        let dir = dir.clone();
        let dl_dir = tmp_base.join(format!("native-dl-{cycle_id}"));
        let dl_dir2 = dl_dir.clone();
        match tokio::time::timeout(OP_TIMEOUT, tokio::task::spawn_blocking(move || {
            let (_, elapsed) = native::download(&dir, &dl_dir2);
            elapsed
        })).await {
            Ok(Ok(d)) => { println!("done ({:.2}s)", d.as_secs_f64()); let _ = std::fs::remove_dir_all(&dl_dir); d }
            Ok(Err(e)) => { println!("FAILED: {e}"); TIMED_OUT }
            Err(_) => { println!("TIMEOUT"); TIMED_OUT }
        }
    };

    // Delete
    print!("  {} {}: native delete...", elapsed_tag(bench_start), prefix);
    let delete_time = {
        let dir = dir.clone();
        match tokio::time::timeout(OP_TIMEOUT, tokio::task::spawn_blocking(move || {
            native::delete(&dir)
        })).await {
            Ok(Ok(d)) => { println!("done ({:.2}s)", d.as_secs_f64()); d }
            Ok(Err(e)) => { println!("FAILED: {e}"); TIMED_OUT }
            Err(_) => { println!("TIMEOUT"); TIMED_OUT }
        }
    };

    (upload_time, list_time, download_time, delete_time)
}

/// Run one full smb crate cycle: setup, upload, list, download, delete.
/// Each operation is wrapped in a 90-second timeout.
async fn run_smb_cycle(
    client: &smb::Client,
    unc_path: &smb::UncPath,
    chunks: &smb_runner::ChunkSizes,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
    cycle_id: &str,
    target: &Target,
    bench_start: Instant,
) -> (Duration, Duration, Duration, Duration) {
    let prefix = format!("{}/{}", target.name, suite.name);

    let test_dir = smb_runner::setup(client, unc_path, cycle_id)
        .await
        .expect("smb setup");

    // Upload
    print!("  {} {}: smb upload...", elapsed_tag(bench_start), prefix);
    let upload_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb_runner::upload(client, unc_path, &test_dir, suite.file_count, suite.file_size_bytes, data, chunks.write),
    ).await {
        Ok(d) => { println!("done ({:.2}s)", d.as_secs_f64()); d }
        Err(_) => { println!("TIMEOUT"); TIMED_OUT }
    };

    // List
    print!("  {} {}: smb list...", elapsed_tag(bench_start), prefix);
    let list_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb_runner::list(client, unc_path, &test_dir),
    ).await {
        Ok((count, d)) => {
            if count != suite.file_count {
                log::warn!(
                    "smb list count mismatch: got {} expected {} (stale directory?)",
                    count, suite.file_count
                );
            }
            println!("done ({:.2}s)", d.as_secs_f64());
            d
        }
        Err(_) => { println!("TIMEOUT"); TIMED_OUT }
    };

    // Download
    print!("  {} {}: smb download...", elapsed_tag(bench_start), prefix);
    let dl_dir = tmp_base.join(format!("smb-dl-{cycle_id}"));
    let download_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb_runner::download(client, unc_path, &test_dir, &dl_dir, chunks.read),
    ).await {
        Ok((_, d)) => { println!("done ({:.2}s)", d.as_secs_f64()); let _ = std::fs::remove_dir_all(&dl_dir); d }
        Err(_) => { println!("TIMEOUT"); let _ = std::fs::remove_dir_all(&dl_dir); TIMED_OUT }
    };

    // Delete
    print!("  {} {}: smb delete...", elapsed_tag(bench_start), prefix);
    let delete_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb_runner::delete(client, unc_path, &test_dir),
    ).await {
        Ok(d) => { println!("done ({:.2}s)", d.as_secs_f64()); d }
        Err(_) => { println!("TIMEOUT"); TIMED_OUT }
    };

    (upload_time, list_time, download_time, delete_time)
}

/// Run one full smb2 cycle: setup, upload, list, download, delete.
/// Each operation is wrapped in a 90-second timeout.
async fn run_smb2_cycle(
    client: &mut SmbClient,
    tree: &Tree,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
    cycle_id: &str,
    target: &Target,
    bench_start: Instant,
) -> (Duration, Duration, Duration, Duration) {
    let prefix = format!("{}/{}", target.name, suite.name);

    let test_dir = smb2_runner::setup(client, tree, cycle_id)
        .await
        .expect("smb2 setup");

    // Upload
    print!("  {} {}: smb2 upload...", elapsed_tag(bench_start), prefix);
    let upload_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb2_runner::upload(client, tree, &test_dir, suite.file_count, suite.file_size_bytes, data),
    ).await {
        Ok(d) => { println!("done ({:.2}s)", d.as_secs_f64()); d }
        Err(_) => { println!("TIMEOUT"); TIMED_OUT }
    };

    // List
    print!("  {} {}: smb2 list...", elapsed_tag(bench_start), prefix);
    let list_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb2_runner::list(client, tree, &test_dir),
    ).await {
        Ok((count, d)) => {
            if count != suite.file_count {
                log::warn!(
                    "smb2 list count mismatch: got {} expected {} (stale directory?)",
                    count, suite.file_count
                );
            }
            println!("done ({:.2}s)", d.as_secs_f64());
            d
        }
        Err(_) => { println!("TIMEOUT"); TIMED_OUT }
    };

    // Download
    print!("  {} {}: smb2 download...", elapsed_tag(bench_start), prefix);
    let dl_dir = tmp_base.join(format!("smb2-dl-{cycle_id}"));
    let download_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb2_runner::download(client, tree, &test_dir, &dl_dir),
    ).await {
        Ok((_, d)) => { println!("done ({:.2}s)", d.as_secs_f64()); let _ = std::fs::remove_dir_all(&dl_dir); d }
        Err(_) => { println!("TIMEOUT"); let _ = std::fs::remove_dir_all(&dl_dir); TIMED_OUT }
    };

    // Delete
    print!("  {} {}: smb2 delete...", elapsed_tag(bench_start), prefix);
    let delete_time = match tokio::time::timeout(
        OP_TIMEOUT,
        smb2_runner::delete(client, tree, &test_dir),
    ).await {
        Ok(d) => { println!("done ({:.2}s)", d.as_secs_f64()); d }
        Err(_) => { println!("TIMEOUT"); TIMED_OUT }
    };

    (upload_time, list_time, download_time, delete_time)
}

/// Combined warmup (all methods once, results discarded).
async fn run_one_cycle(
    target: &Target,
    smb_conn: Option<&(smb::Client, smb::UncPath, smb_runner::ChunkSizes)>,
    smb2_client: &mut SmbClient,
    smb2_tree: &Tree,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
    bench_start: Instant,
) {
    let _ = run_native_cycle(target, suite, data, tmp_base, "warmup-n", bench_start).await;
    if let Some((client, unc_path, chunks)) = smb_conn {
        let _ = run_smb_cycle(client, unc_path, chunks, suite, data, tmp_base, "warmup-d", target, bench_start).await;
    }
    let _ = run_smb2_cycle(smb2_client, smb2_tree, suite, data, tmp_base, "warmup-s", target, bench_start).await;
}

fn generate_data(size: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);
    data
}

/// Public accessor for median calculation (used by report module).
pub fn median_pub(times: &[Duration]) -> Duration {
    median(times)
}

fn median(times: &[Duration]) -> Duration {
    if times.is_empty() {
        return Duration::ZERO;
    }
    let mut sorted: Vec<Duration> = times.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}
