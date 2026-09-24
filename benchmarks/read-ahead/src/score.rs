//! Minimax-regret scoring of tuning candidates across the grid.
//!
//! `score [--detail] F...` reads download and upload CSVs (told apart by
//! their headers) and scores every variant with a `:<tuning>` suffix
//! (`auto:X` as `X`, any other base under its full name). A cell
//! is one direction × link × load. In each cell, per candidate:
//!
//! - **Throughput regret**: `1 − MB/s ÷ best MB/s`, on the cell's largest file.
//! - **Listing regret**: `(stat p50 − best p50) ÷ max(best p50, 50 ms)`, from
//!   the side `stat` during that same transfer.
//! - **Per-file regret**: the worst over the cell's smaller files of
//!   `(time − best time) ÷ max(best time, 50 ms)`, where time is the last chunk
//!   in hand (downloads) or the CLOSE's answer (uploads).
//!
//! A cell's regret is the largest of the three, and a candidate's score is its
//! worst cell. The 50 ms floor keeps a few ms of noise on a wait nobody
//! notices from reading as a large ratio.
//!
//! `--control PATTERN` (repeatable) marks cells whose link contains PATTERN,
//! or whose link has no rate cap for `uncapped`, as controls: cells where
//! every candidate runs at the 4 MiB cap, so the headroom cannot matter and
//! the spread between candidates is the rig's noise. They're shown, and left
//! out of the worst-cell ranking.

use std::collections::BTreeMap;

use crate::median;

/// Waits below this count as this, in the ratios.
const FLOOR_MS: f64 = 50.0;

#[derive(Default)]
struct Samples {
    mbps: Vec<f64>,
    p50: Vec<f64>,
    max: Vec<f64>,
    time: Vec<f64>,
}

/// One candidate's medians and regrets in one cell.
struct Scored {
    mbps: f64,
    p50: f64,
    max: f64,
    times: Vec<(u64, f64)>,
    r_tput: f64,
    r_stat: f64,
    r_file: f64,
}

impl Scored {
    fn regret(&self) -> f64 {
        self.r_tput.max(self.r_stat).max(self.r_file)
    }

    /// Which score set the cell's regret: throughput, listing, or file.
    fn why(&self) -> &'static str {
        let r = self.regret();
        if r < 0.005 {
            ""
        } else if r == self.r_tput {
            " t"
        } else if r == self.r_stat {
            " s"
        } else {
            " f"
        }
    }
}

type Cell = BTreeMap<String, BTreeMap<u64, Samples>>;

pub fn run(args: &[String]) {
    let detail = args.iter().any(|a| a == "--detail");
    let controls: Vec<&str> =
        args.windows(2).filter(|w| w[0] == "--control").map(|w| w[1].as_str()).collect();
    let is_control = |link: &str| {
        controls.iter().any(|c| if *c == "uncapped" { !link.contains('@') } else { link.contains(c) })
    };
    let files = args.iter().enumerate().filter(|(i, a)| !a.starts_with("--") && (*i == 0 || args[i - 1] != "--control"));
    // (direction, link sort key, link, load) -> tuning -> size -> samples
    let mut cells: BTreeMap<(&'static str, (u64, String), u64), Cell> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for (_, path) in files {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut lines = text.lines();
        let header: Vec<&str> = lines.next().unwrap().split(',').collect();
        let col = |n: &str| header.iter().position(|h| *h == n);
        let (dir, time_col) = match col("last_chunk_ms") {
            Some(i) => ("down", i),
            None => ("up", col("wall_ms").unwrap()),
        };
        for line in lines {
            let f: Vec<&str> = line.split(',').collect();
            let variant = f[col("variant").unwrap()];
            // `auto:X` is the grid's candidate X; any other base keeps its full
            // name, so `adaptive:X` gets a column of its own instead of
            // pooling its samples into `auto:X`'s.
            let tuning = match variant.split_once(':') {
                Some(("auto", tuning)) => tuning,
                Some(_) => variant,
                None => continue,
            };
            if !order.iter().any(|t| t == tuning) {
                order.push(tuning.to_string());
            }
            let link = f[col("rtt_ms").unwrap()].to_string();
            let digits: String = link.chars().take_while(char::is_ascii_digit).collect();
            let key = (dir, (digits.parse().unwrap_or(u64::MAX), link), f[col("load").unwrap()].parse().unwrap());
            let s = cells
                .entry(key)
                .or_default()
                .entry(tuning.to_string())
                .or_default()
                .entry(f[col("size").unwrap()].parse().unwrap())
                .or_default();
            let num = |n: &str| f[col(n).unwrap()].parse::<f64>().unwrap_or(f64::NAN);
            s.mbps.push(num("mbps"));
            s.p50.push(num("probe_p50_ms"));
            s.max.push(num("probe_max_ms"));
            s.time.push(f[time_col].parse().unwrap_or(f64::NAN));
        }
    }

    let label = |dir: &str, link: &str, load: u64| {
        let load = if load == 0 { String::new() } else { format!(", {load} writers") };
        format!("{dir} +{link}{load}")
    };
    let mut scored: Vec<(String, BTreeMap<String, Scored>)> = Vec::new();
    for ((dir, (_, link), load), cell) in &cells {
        let mut rows: BTreeMap<String, Scored> = BTreeMap::new();
        for (tuning, sizes) in cell {
            let (&largest, big) = sizes.iter().next_back().unwrap();
            let times = sizes
                .iter()
                .filter(|(&size, _)| size < largest)
                .map(|(&size, s)| (size, median(s.time.clone())))
                .collect();
            rows.insert(
                tuning.clone(),
                Scored {
                    mbps: median(big.mbps.clone()),
                    p50: median(big.p50.clone()),
                    max: median(big.max.clone()),
                    times,
                    r_tput: 0.0,
                    r_stat: 0.0,
                    r_file: 0.0,
                },
            );
        }
        let best_mbps = rows.values().map(|s| s.mbps).fold(0.0, f64::max);
        let best_p50 = rows.values().map(|s| s.p50).fold(f64::INFINITY, f64::min);
        let mut best_time: BTreeMap<u64, f64> = BTreeMap::new();
        for s in rows.values() {
            for &(size, t) in &s.times {
                let b = best_time.entry(size).or_insert(f64::INFINITY);
                *b = b.min(t);
            }
        }
        for s in rows.values_mut() {
            s.r_tput = 1.0 - s.mbps / best_mbps;
            s.r_stat = (s.p50 - best_p50) / best_p50.max(FLOOR_MS);
            s.r_file = s
                .times
                .iter()
                .map(|&(size, t)| (t - best_time[&size]) / best_time[&size].max(FLOOR_MS))
                .fold(0.0, f64::max);
        }
        let mut cell = label(dir, link, *load);
        if is_control(link) {
            cell.push_str(" (control)");
        }
        scored.push((cell, rows));
    }

    let pct = |r: f64| format!("{:.0}%", r * 100.0);
    println!("### Regret by cell\n");
    println!("The largest of throughput (t), listing (s), and per-file (f) regret; 0% is the best candidate there.\n");
    println!("| cell | {} |", order.join(" | "));
    println!("|---|{}", "---:|".repeat(order.len()));
    for (cell, rows) in &scored {
        let cols: Vec<String> =
            order.iter().map(|t| rows.get(t).map_or("n/a".into(), |s| format!("{}{}", pct(s.regret()), s.why()))).collect();
        println!("| {cell} | {} |", cols.join(" | "));
    }

    println!("\n### Worst cells per candidate\n");
    println!("Control cells left out; `worst control` is the rig's noise on the same scale.\n");
    println!("| candidate | worst | where | second worst | mean | worst control |");
    println!("|---|---:|---|---:|---:|---:|");
    let mut summary: Vec<(String, Vec<(f64, String)>, f64)> = order
        .iter()
        .map(|t| {
            let (mut r, mut control) = (Vec::new(), 0.0f64);
            for (cell, rows) in &scored {
                let Some(s) = rows.get(t) else { continue };
                if cell.ends_with("(control)") {
                    control = control.max(s.regret());
                } else {
                    r.push((s.regret(), cell.clone()));
                }
            }
            r.sort_by(|a: &(f64, String), b| b.0.total_cmp(&a.0));
            (t.clone(), r, control)
        })
        .collect();
    summary.sort_by(|a, b| a.1[0].0.total_cmp(&b.1[0].0).then(a.1.get(1).map_or(0.0, |x| x.0).total_cmp(&b.1.get(1).map_or(0.0, |x| x.0))));
    for (t, r, control) in &summary {
        let mean = r.iter().map(|x| x.0).sum::<f64>() / r.len() as f64;
        println!(
            "| {t} | {} | {} | {} | {} | {} |",
            pct(r[0].0),
            r[0].1,
            r.get(1).map_or("n/a".into(), |x| pct(x.0)),
            pct(mean),
            pct(*control)
        );
    }

    if !detail {
        return;
    }
    println!("\n### Medians per cell\n");
    for (cell, rows) in &scored {
        let sizes: Vec<u64> = rows.values().next().unwrap().times.iter().map(|&(s, _)| s).collect();
        let heads: Vec<String> = sizes.iter().map(|s| format!("{} MiB ms", s >> 20)).collect();
        println!("\n#### {cell}\n");
        println!("| candidate | MB/s | stat p50/max ms | {} | regret t / s / f |", heads.join(" | "));
        println!("|---|---:|---:|{}---:|", "---:|".repeat(sizes.len()));
        for t in &order {
            let Some(s) = rows.get(t) else { continue };
            let times: Vec<String> = s.times.iter().map(|&(_, t)| format!("{t:.0}")).collect();
            println!(
                "| {t} | {:.1} | {:.0} / {:.0} | {} | {} / {} / {} |",
                s.mbps,
                s.p50,
                s.max,
                times.join(" | "),
                pct(s.r_tput),
                pct(s.r_stat),
                pct(s.r_file)
            );
        }
    }
}
