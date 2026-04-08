//! Output formatting: terminal table and JSON file.

use crate::runner::{AllResults, TIMED_OUT};
use std::path::PathBuf;

pub fn print_table(results: &AllResults) {
    println!(
        "\n\n╔══════════════════════════════════════════════════════════════════════════════════════╗"
    );
    println!(
        "║                              SMB BENCHMARK RESULTS                                 ║"
    );
    println!(
        "╚══════════════════════════════════════════════════════════════════════════════════════╝\n"
    );

    for suite in &results.suites {
        let total_mb = (suite.file_count as f64 * suite.file_size_bytes as f64) / (1024.0 * 1024.0);
        println!(
            "Target: {} | Suite: {} — {} files x {} KB ({:.1} MB total)",
            suite.target_name,
            suite.suite_name,
            suite.file_count,
            suite.file_size_bytes / 1024,
            total_mb,
        );
        println!(
            "┌──────────────┬──────────────┬──────────────┬──────────────┬──────────┬──────────┐"
        );
        println!(
            "│ operation    │ native       │ smb          │ smb2         │ smb2/nat │ smb2/smb │"
        );
        println!(
            "├──────────────┼──────────────┼──────────────┼──────────────┼──────────┼──────────┤"
        );

        for op in &suite.operations {
            let native_str = format_time_or_status(&op.native_times);
            let smb_str = if suite.smb_skipped {
                "N/A".to_string()
            } else {
                format_time_or_status(&op.smb_times)
            };
            let smb2_str = format_time_or_status(&op.smb2_times);

            let vs_native_str = if op.native_timed_out() || op.smb2_timed_out() {
                "N/A".to_string()
            } else {
                format_ratio(op.smb2_vs_native())
            };

            let vs_smb_str = if suite.smb_skipped
                || op.smb_skipped()
                || op.smb_timed_out()
                || op.smb2_timed_out()
            {
                "N/A".to_string()
            } else {
                format_ratio(op.smb2_vs_smb())
            };

            println!(
                "│ {:<12} │ {:>10} │ {:>10} │ {:>10} │ {:>7} │ {:>7} │",
                op.name, native_str, smb_str, smb2_str, vs_native_str, vs_smb_str,
            );
        }
        println!(
            "└──────────────┴──────────────┴──────────────┴──────────────┴──────────┴──────────┘\n"
        );
    }

    println!("Ratios: smb2/native and smb2/smb — values < 1.0 mean smb2 is faster.\n");
}

/// Format a list of durations as a median time string, or "TIMEOUT" / "N/A" as appropriate.
fn format_time_or_status(times: &[std::time::Duration]) -> String {
    if times.iter().any(|&t| t == TIMED_OUT) {
        "TIMEOUT".to_string()
    } else {
        let median = crate::runner::median_pub(times);
        format_duration_ms(median.as_secs_f64() * 1000.0)
    }
}

pub fn save_json(results: &AllResults) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d-%H%M%S");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&dir).expect("create results dir");
    let path = dir.join(format!("results-{timestamp}.json"));

    let json = build_json(results);
    std::fs::write(&path, json).expect("write results JSON");
    println!("Results saved to {}", path.display());
}

fn build_json(results: &AllResults) -> String {
    let mut out = String::from("{\n  \"suites\": [\n");
    for (si, suite) in results.suites.iter().enumerate() {
        out.push_str(&format!(
            "    {{\n      \"target\": \"{}\",\n      \"suite\": \"{}\",\n      \"file_count\": {},\n      \"file_size_bytes\": {},\n      \"smb_skipped\": {},\n      \"operations\": [\n",
            suite.target_name, suite.suite_name, suite.file_count, suite.file_size_bytes, suite.smb_skipped
        ));
        for (oi, op) in suite.operations.iter().enumerate() {
            let smb_median_ms = if suite.smb_skipped || op.smb_timed_out() {
                "null".to_string()
            } else {
                format!("{:.2}", op.smb_median().as_secs_f64() * 1000.0)
            };
            let native_median_ms = if op.native_timed_out() {
                "null".to_string()
            } else {
                format!("{:.2}", op.native_median().as_secs_f64() * 1000.0)
            };
            let smb2_median_ms = if op.smb2_timed_out() {
                "null".to_string()
            } else {
                format!("{:.2}", op.smb2_median().as_secs_f64() * 1000.0)
            };

            out.push_str(&format!(
                "        {{\n          \"name\": \"{}\",\n          \"native_ms\": [{native}],\n          \"smb_ms\": [{smb}],\n          \"smb2_ms\": [{smb2}],\n          \"native_median_ms\": {native_median_ms},\n          \"smb_median_ms\": {smb_median_ms},\n          \"smb2_median_ms\": {smb2_median_ms},\n          \"smb2_vs_native\": {vs_native},\n          \"smb2_vs_smb\": {vs_smb}\n        }}",
                op.name,
                vs_native = if op.native_timed_out() || op.smb2_timed_out() { "null".to_string() } else { format!("{:.3}", op.smb2_vs_native()) },
                vs_smb = if suite.smb_skipped || op.smb_timed_out() || op.smb2_timed_out() { "null".to_string() } else { format!("{:.3}", op.smb2_vs_smb()) },
                native = format_times_json(&op.native_times),
                smb = format_times_json(&op.smb_times),
                smb2 = format_times_json(&op.smb2_times),
            ));
            if oi < suite.operations.len() - 1 {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("      ]\n    }");
        if si < results.suites.len() - 1 {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

fn format_times_json(times: &[std::time::Duration]) -> String {
    times
        .iter()
        .map(|d| {
            if *d == TIMED_OUT {
                "null".to_string()
            } else {
                format!("{:.2}", d.as_secs_f64() * 1000.0)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_duration_ms(ms: f64) -> String {
    if ms < 1.0 {
        format!("{:.2} ms", ms)
    } else if ms < 1000.0 {
        format!("{:.0} ms", ms)
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

fn format_ratio(ratio: f64) -> String {
    if ratio >= 100.0 {
        format!("{:.0}x", ratio)
    } else {
        format!("{:.2}x", ratio)
    }
}
