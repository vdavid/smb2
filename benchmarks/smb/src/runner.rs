//! Orchestrates benchmark runs: warmup, iterations, median calculation.

use crate::config::{BenchConfig, Target};
use crate::{direct, native, smb2_runner, Suite};
use rand::Rng;
use smb2::{SmbClient, Tree};
use std::path::PathBuf;
use std::time::Duration;

/// Results for a single operation across iterations (three methods).
#[derive(Clone)]
pub struct OpResult {
    pub name: String,
    pub native_times: Vec<Duration>,
    pub direct_times: Vec<Duration>,
    pub smb2_times: Vec<Duration>,
}

impl OpResult {
    pub fn native_median(&self) -> Duration {
        median(&self.native_times)
    }

    pub fn direct_median(&self) -> Duration {
        median(&self.direct_times)
    }

    pub fn smb2_median(&self) -> Duration {
        median(&self.smb2_times)
    }

    /// Ratio: smb2 / native (< 1.0 means smb2 is faster).
    pub fn smb2_vs_native(&self) -> f64 {
        let n = self.native_median().as_secs_f64();
        let s = self.smb2_median().as_secs_f64();
        if n > 0.0 { s / n } else { f64::INFINITY }
    }

    /// Ratio: smb2 / direct (< 1.0 means smb2 is faster).
    pub fn smb2_vs_direct(&self) -> f64 {
        let d = self.direct_median().as_secs_f64();
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
}

/// All results across all targets and suites.
pub struct AllResults {
    pub suites: Vec<SuiteResult>,
}

pub async fn run_all(config: &BenchConfig, suites: &[Suite], iterations: usize) -> AllResults {
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

            match run_suite(target, suite, iterations).await {
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

async fn run_suite(
    target: &Target,
    suite: &Suite,
    iterations: usize,
) -> Result<SuiteResult, String> {
    // Generate random test data (same data for all methods)
    let data = generate_data(suite.file_size_bytes);
    let tmp_base = std::env::temp_dir().join("smb-benchmark");

    let mut upload_native = Vec::new();
    let mut upload_direct = Vec::new();
    let mut upload_smb2 = Vec::new();
    let mut list_native = Vec::new();
    let mut list_direct = Vec::new();
    let mut list_smb2 = Vec::new();
    let mut download_native = Vec::new();
    let mut download_direct = Vec::new();
    let mut download_smb2 = Vec::new();
    let mut delete_native = Vec::new();
    let mut delete_direct = Vec::new();
    let mut delete_smb2 = Vec::new();

    // Connect for direct operations
    println!("  Connecting via direct SMB (smb crate)...");
    let (client, unc_path, chunk_sizes) = direct::connect(target).await?;
    println!("  Connected.");

    // Connect for smb2 operations
    println!("  Connecting via smb2 crate...");
    let (mut smb2_client, smb2_tree) = smb2_runner::connect(target).await?;
    println!("  Connected.");

    // Warmup run (not counted) — primes NAS caches
    println!("  Warmup run...");
    run_one_cycle(
        target,
        &client,
        &unc_path,
        &chunk_sizes,
        &mut smb2_client,
        &smb2_tree,
        suite,
        &data,
        &tmp_base,
    )
    .await;
    // Let the SMB cache settle after warmup cleanup
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Build a randomized schedule
    let mut rng = rand::rng();

    for iter in 0..iterations {
        // Randomize order of three methods using a permutation
        let mut order = [0u8, 1, 2]; // 0=native, 1=direct, 2=smb2
        // Fisher-Yates shuffle
        for i in (1..3).rev() {
            let j = rng.random_range(0..=i);
            order.swap(i, j);
        }
        println!(
            "  Iteration {}/{} (order: {})...",
            iter + 1,
            iterations,
            order
                .iter()
                .map(|&m| match m {
                    0 => "native",
                    1 => "direct",
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
                        Some(run_native_cycle(target, suite, &data, &tmp_base, &n_id).await);
                }
                1 => {
                    d_result = Some(
                        run_direct_cycle(
                            &client,
                            &unc_path,
                            &chunk_sizes,
                            suite,
                            &data,
                            &tmp_base,
                            &d_id,
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
                        )
                        .await,
                    );
                }
                _ => unreachable!(),
            }
        }

        let (un, ln, dn, deln) = n_result.unwrap();
        let (ud, ld, dd, deld) = d_result.unwrap();
        let (us, ls, ds, dels) = s_result.unwrap();

        upload_native.push(un);
        list_native.push(ln);
        download_native.push(dn);
        delete_native.push(deln);

        upload_direct.push(ud);
        list_direct.push(ld);
        download_direct.push(dd);
        delete_direct.push(deld);

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
        operations: vec![
            OpResult {
                name: "upload".into(),
                native_times: upload_native,
                direct_times: upload_direct,
                smb2_times: upload_smb2,
            },
            OpResult {
                name: "list".into(),
                native_times: list_native,
                direct_times: list_direct,
                smb2_times: list_smb2,
            },
            OpResult {
                name: "download".into(),
                native_times: download_native,
                direct_times: download_direct,
                smb2_times: download_smb2,
            },
            OpResult {
                name: "delete".into(),
                native_times: delete_native,
                direct_times: delete_direct,
                smb2_times: delete_smb2,
            },
        ],
    })
}

/// Run one full native cycle: setup, upload, list, download, delete.
async fn run_native_cycle(
    target: &Target,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
    cycle_id: &str,
) -> (Duration, Duration, Duration, Duration) {
    let dir = native::setup(target, cycle_id).expect("native setup");
    let upload_time = native::upload(&dir, suite.file_count, suite.file_size_bytes, data);
    let (count, list_time) = native::list(&dir);
    if count != suite.file_count {
        log::warn!(
            "Native list count mismatch: got {} expected {} (SMB cache likely stale)",
            count,
            suite.file_count
        );
    }

    let dl_dir = tmp_base.join(format!("native-dl-{cycle_id}"));
    let (_, download_time) = native::download(&dir, &dl_dir);
    let _ = std::fs::remove_dir_all(&dl_dir);

    let delete_time = native::delete(&dir);
    (upload_time, list_time, download_time, delete_time)
}

/// Run one full direct cycle: setup, upload, list, download, delete.
async fn run_direct_cycle(
    client: &smb::Client,
    unc_path: &smb::UncPath,
    chunks: &direct::ChunkSizes,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
    cycle_id: &str,
) -> (Duration, Duration, Duration, Duration) {
    let test_dir = direct::setup(client, unc_path, cycle_id)
        .await
        .expect("direct setup");
    let upload_time = direct::upload(
        client,
        unc_path,
        &test_dir,
        suite.file_count,
        suite.file_size_bytes,
        data,
        chunks.write,
    )
    .await;
    let (count, list_time) = direct::list(client, unc_path, &test_dir).await;
    if count != suite.file_count {
        log::warn!(
            "Direct list count mismatch: got {} expected {} (stale directory?)",
            count,
            suite.file_count
        );
    }

    let dl_dir = tmp_base.join(format!("direct-dl-{cycle_id}"));
    let (_, download_time) =
        direct::download(client, unc_path, &test_dir, &dl_dir, chunks.read).await;
    let _ = std::fs::remove_dir_all(&dl_dir);

    let delete_time = direct::delete(client, unc_path, &test_dir).await;
    (upload_time, list_time, download_time, delete_time)
}

/// Run one full smb2 cycle: setup, upload, list, download, delete.
async fn run_smb2_cycle(
    client: &mut SmbClient,
    tree: &Tree,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
    cycle_id: &str,
) -> (Duration, Duration, Duration, Duration) {
    let test_dir = smb2_runner::setup(client, tree, cycle_id)
        .await
        .expect("smb2 setup");
    let upload_time =
        smb2_runner::upload(client, tree, &test_dir, suite.file_count, suite.file_size_bytes, data)
            .await;
    let (count, list_time) = smb2_runner::list(client, tree, &test_dir).await;
    if count != suite.file_count {
        log::warn!(
            "smb2 list count mismatch: got {} expected {} (stale directory?)",
            count,
            suite.file_count
        );
    }

    let dl_dir = tmp_base.join(format!("smb2-dl-{cycle_id}"));
    let (_, download_time) = smb2_runner::download(client, tree, &test_dir, &dl_dir).await;
    let _ = std::fs::remove_dir_all(&dl_dir);

    let delete_time = smb2_runner::delete(client, tree, &test_dir).await;
    (upload_time, list_time, download_time, delete_time)
}

/// Combined warmup (all three methods once, results discarded).
async fn run_one_cycle(
    target: &Target,
    client: &smb::Client,
    unc_path: &smb::UncPath,
    chunks: &direct::ChunkSizes,
    smb2_client: &mut SmbClient,
    smb2_tree: &Tree,
    suite: &Suite,
    data: &[u8],
    tmp_base: &PathBuf,
) {
    let _ = run_native_cycle(target, suite, data, tmp_base, "warmup-n").await;
    let _ = run_direct_cycle(client, unc_path, chunks, suite, data, tmp_base, "warmup-d").await;
    let _ = run_smb2_cycle(smb2_client, smb2_tree, suite, data, tmp_base, "warmup-s").await;
}

fn generate_data(size: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);
    data
}

fn median(times: &[Duration]) -> Duration {
    if times.is_empty() {
        return Duration::ZERO;
    }
    let mut sorted: Vec<Duration> = times.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}
