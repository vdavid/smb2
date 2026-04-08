//! SMB benchmark: compares native (OS-mounted) vs smb (smb crate) vs smb2 (our crate)
//! file operations.
//!
//! Measures upload, list, download, and delete for configurable file counts and sizes
//! across multiple NAS targets.

mod config;
mod native;
mod report;
mod runner;
mod smb2_runner;
mod smb_runner;

use std::path::PathBuf;
use std::process;

use config::BenchConfig;

/// Test file counts and sizes -- turn these down during development, up for real benchmarks.
/// Each suite is run independently against all three methods.
const SUITES: &[Suite] = &[
    Suite {
        name: "small",
        file_count: 100,
        file_size_bytes: 100 * 1024,
    }, // 100 x 100 KB
    Suite {
        name: "medium",
        file_count: 10,
        file_size_bytes: 10 * 1024 * 1024,
    }, // 10 x 10 MB
    Suite {
        name: "large",
        file_count: 3,
        file_size_bytes: 50 * 1024 * 1024,
    }, // 3 x 50 MB
];

/// How many times to repeat each operation (after one warmup run).
const ITERATIONS: usize = 3;

pub struct Suite {
    pub name: &'static str,
    pub file_count: usize,
    pub file_size_bytes: usize,
}

fn config_path() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.join("config.toml")
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();

    let skip_smb = args.iter().any(|a| a == "--skip-smb");

    let config_path = config_path();
    if !config_path.exists() {
        eprintln!("Missing config.toml at {}", config_path.display());
        eprintln!("Copy config.example.toml and fill in your NAS details.");
        process::exit(1);
    }

    let config = match BenchConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse config.toml: {e}");
            process::exit(1);
        }
    };

    if args.iter().any(|a| a == "--cleanup-only") {
        for target in &config.targets {
            println!(
                "Cleaning up test dirs on {} ({})...",
                target.name, target.host
            );
            native::cleanup(target).await;
            if !skip_smb {
                smb_runner::cleanup(target).await;
            }
            smb2_runner::cleanup(target).await;
        }
        println!("Done.");
        return;
    }

    let all_results = runner::run_all(&config, SUITES, ITERATIONS, skip_smb).await;
    report::print_table(&all_results);
    report::save_json(&all_results);
}
