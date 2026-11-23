//! SMB directory-listing probe.
//!
//! Instruments `smb2`'s directory listing against a real NAS to explain a
//! throughput gap: which phase of a listing dominates (CREATE / QUERY / CLOSE),
//! how throughput scales with in-flight depth on one TCP session versus several,
//! how warm (ARC-cached) and cold listings differ, and how much a bigger
//! QUERY_DIRECTORY buffer saves on fat directories.
//!
//! Read-only: it only lists directories. See `README.md`.

mod config;
mod probe;
mod report;

use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use config::BenchConfig;
use probe::Session;

struct Args {
    config: PathBuf,
    target: Option<String>,
    root: String,
    sample: usize,
    windows: Vec<usize>,
    cold_slice: usize,
    session_window: usize,
    sessions: Vec<usize>,
    fat: usize,
    buffers_kib: Vec<u32>,
}

impl Args {
    fn parse() -> Args {
        let mut a = Args {
            config: config::default_config_path(),
            target: None,
            root: String::new(),
            sample: 200,
            windows: vec![1, 8, 32, 64, 128],
            cold_slice: 60,
            session_window: 64,
            sessions: vec![1, 2, 4],
            fat: 5,
            buffers_kib: vec![64, 256, 1024],
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut val = || it.next().unwrap_or_default();
            match flag.as_str() {
                "--config" => a.config = PathBuf::from(val()),
                "--target" => a.target = Some(val()),
                "--root" => a.root = val().replace('\\', "/"),
                "--sample" => a.sample = val().parse().unwrap_or(a.sample),
                "--windows" => a.windows = parse_usize_csv(&val()),
                "--cold-slice" => a.cold_slice = val().parse().unwrap_or(a.cold_slice),
                "--session-window" => a.session_window = val().parse().unwrap_or(a.session_window),
                "--sessions" => a.sessions = parse_usize_csv(&val()),
                "--fat" => a.fat = val().parse().unwrap_or(a.fat),
                "--buffers" => a.buffers_kib = parse_u32_csv(&val()),
                other => eprintln!("Ignoring unknown flag: {other}"),
            }
        }
        a
    }
}

fn parse_usize_csv(s: &str) -> Vec<usize> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}
fn parse_u32_csv(s: &str) -> Vec<u32> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    let cfg = match BenchConfig::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config error: {e}");
            eprintln!(
                "Pass --config <path> or set SMB_LISTING_CONFIG. Default is ../smb/config.toml."
            );
            process::exit(1);
        }
    };
    let target = match cfg.pick(args.target.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    // Collect the whole report so we can save it alongside printing live.
    let mut out = String::new();
    let mut emit = |line: String| {
        println!("{line}");
        out.push_str(&line);
        out.push('\n');
    };

    emit(format!(
        "SMB listing probe — target '{}' ({}), share '{}', root '{}'",
        target.name,
        target.host,
        target.share,
        if args.root.is_empty() {
            "<share root>"
        } else {
            &args.root
        }
    ));
    emit(format!("Started {}", jiff::Zoned::now()));

    let mut primary = match probe::connect_session(&target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Connect failed: {e}");
            process::exit(1);
        }
    };
    let max_transact = probe::max_transact_size(&primary);
    if let Some(p) = primary.client.params() {
        emit(format!(
            "Negotiated: max_read={}KiB, max_write={}KiB, max_transact={}KiB",
            p.max_read_size / 1024,
            p.max_write_size / 1024,
            p.max_transact_size / 1024,
        ));
    }

    // Serial-path handle and tree (used before the connection is shared out).
    let mut c0 = primary.conn_handle();
    let tree0 = primary.tree.clone();

    // ── 1. Discovery ──────────────────────────────────────────────────────
    // We need cold (never-listed) directories for several jobs, all disjoint:
    //   - the serial phase breakdown + warm/cold comparison (`sample` dirs),
    //   - a fresh slice per window size for the COLD in-flight sweep,
    //   - a fresh slice per session count for the COLD multi-session sweep.
    // Each cold dir is listed exactly once so its metadata is genuinely cold.
    emit("\n== Discovery ==".to_string());
    let cold_needed = args.sample + (args.windows.len() + args.sessions.len()) * args.cold_slice;
    let t = Instant::now();
    let disc = match probe::discover(&mut c0, &tree0, &args.root, cold_needed).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Discovery failed: {e}");
            process::exit(1);
        }
    };
    emit(format!(
        "Expanded {} dirs in {:.1}s; collected {} cold dirs (need {}); fattest listed: {}",
        disc.expanded,
        t.elapsed().as_secs_f64(),
        disc.cold_dirs.len(),
        cold_needed,
        disc.fat_dirs
            .iter()
            .take(3)
            .map(|(d, n)| format!("{}({n})", short(d)))
            .collect::<Vec<_>>()
            .join(", "),
    ));
    if disc.cold_dirs.is_empty() {
        eprintln!("No sample directories found under root; nothing to measure.");
        process::exit(1);
    }

    // Partition the cold pool: the first `sample` for the serial breakdown and
    // warm sweeps, the remainder for per-window cold concurrency slices.
    let sample_n = args.sample.min(disc.cold_dirs.len());
    let sample_dirs: Vec<String> = disc.cold_dirs[..sample_n].to_vec();
    let cold_pool: Vec<String> = disc.cold_dirs[sample_n..].to_vec();

    // ── 2. Phase breakdown: cold then warm ────────────────────────────────
    emit("\n== Phase breakdown (serial, one connection) ==".to_string());
    let t = Instant::now();
    let (cold, cold_failed) = probe::phase_breakdown(&mut c0, &tree0, &sample_dirs).await;
    let cold_wall = t.elapsed();
    emit("Pass 1 (cold — dirs never listed before):".to_string());
    emit(report::summarize_phases(&cold, cold_wall));
    if let Some(line) = report::failures(&cold_failed) {
        emit(line);
    }

    let t = Instant::now();
    let (warm, warm_failed) = probe::phase_breakdown(&mut c0, &tree0, &sample_dirs).await;
    let warm_wall = t.elapsed();
    emit("Pass 2 (warm — same dirs, ARC-cached):".to_string());
    emit(report::summarize_phases(&warm, warm_wall));
    if let Some(line) = report::failures(&warm_failed) {
        emit(line);
    }

    // ── 3. Large-dir query-buffer sweep ───────────────────────────────────
    emit("\n== Query-buffer sweep (fat dirs, warm) ==".to_string());
    let buffers: Vec<u32> = args
        .buffers_kib
        .iter()
        .map(|k| k * 1024)
        .filter(|b| *b <= max_transact)
        .collect();
    emit(format!(
        "Buffers: {}",
        buffers
            .iter()
            .map(|b| format!("{}KiB", b / 1024))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let fat: Vec<(String, usize)> = disc.fat_dirs.iter().take(args.fat).cloned().collect();
    let buf_results = probe::large_dir_buffers(&mut c0, &tree0, &fat, &buffers).await;
    emit("  dir                                    entries  buffer   round-trips  query ms  total ms".to_string());
    for r in &buf_results {
        emit(format!(
            "  {:38}  {:6}  {:>5}KiB  {:>11}  {:8.2}  {:8.2}",
            short(&r.dir),
            r.entries,
            r.buffer_len / 1024,
            r.round_trips,
            r.query_total.as_secs_f64() * 1000.0,
            r.total.as_secs_f64() * 1000.0,
        ));
    }

    // ── 4a. COLD throughput vs in-flight window (one TCP session) ─────────
    // The Cmdr-scan scenario: every directory is listed for the first time, so
    // its metadata is cold. Each window size gets its own fresh, disjoint slice
    // of never-listed dirs, so no measurement benefits from another's caching.
    emit(
        "\n== COLD throughput vs in-flight window (one TCP session, fresh dirs each) =="
            .to_string(),
    );
    emit(format!(
        "  Each window lists a disjoint {}-dir slice, never listed before.",
        args.cold_slice
    ));
    emit("  window   dirs/s   entries/s   wall s   ok   err   dirs".to_string());
    {
        let mut one = [primary];
        for (i, &w) in args.windows.iter().enumerate() {
            let lo = i * args.cold_slice;
            let hi = (lo + args.cold_slice).min(cold_pool.len());
            if lo >= hi {
                emit(format!("  {w:>6}  (no cold dirs left for this window)"));
                continue;
            }
            let slice: Arc<[String]> = Arc::from(cold_pool[lo..hi].to_vec().into_boxed_slice());
            let workers = probe::build_workers(&mut one, w);
            let r = probe::run_pool(workers, slice.clone()).await;
            emit(format!(
                "  {:>6}  {:7.1}  {:9.0}  {:7.2}  {:>3}  {:>3}  {:>4}",
                w,
                r.dirs_per_sec(),
                r.entries_per_sec(),
                r.elapsed.as_secs_f64(),
                r.ok,
                r.err,
                hi - lo,
            ));
            if let Some(e) = &r.first_error {
                emit(format!("          first error: {e}"));
            }
        }
        primary = one.into_iter().next().unwrap();
    }

    // ── 4b. WARM throughput vs in-flight window (one TCP session) ─────────
    // The protocol/code ceiling: all dirs cached in ARC, so this isolates
    // concurrency scaling from disk-metadata cost. Warm the sample once first.
    emit("\n== WARM throughput vs in-flight window (one TCP session) ==".to_string());
    let _ = probe::phase_breakdown(&mut c0, &tree0, &sample_dirs).await;
    let dirs: Arc<[String]> = Arc::from(sample_dirs.clone().into_boxed_slice());
    emit("  window   dirs/s   entries/s   wall s   ok   err".to_string());
    {
        let mut one = [primary];
        for &w in &args.windows {
            let workers = probe::build_workers(&mut one, w);
            let r = probe::run_pool(workers, dirs.clone()).await;
            emit(format!(
                "  {:>6}  {:7.1}  {:9.0}  {:7.2}  {:>3}  {:>3}",
                w,
                r.dirs_per_sec(),
                r.entries_per_sec(),
                r.elapsed.as_secs_f64(),
                r.ok,
                r.err,
            ));
            if let Some(e) = &r.first_error {
                emit(format!("          first error: {e}"));
            }
        }
        primary = one.into_iter().next().unwrap();
    }

    // ── 5. Same in-flight depth across N TCP sessions ─────────────────────
    // Connect all the sessions we'll need up front, then sweep COLD (the scan
    // scenario, fresh dirs per session count) and WARM (the ceiling).
    let mut sessions: Vec<Session> = vec![primary];
    let max_k = args.sessions.iter().copied().max().unwrap_or(1);
    while sessions.len() < max_k {
        match probe::connect_session(&target).await {
            Ok(s) => sessions.push(s),
            Err(e) => {
                eprintln!("Extra session connect failed: {e}");
                break;
            }
        }
    }

    // 5a. COLD: does spreading the scan over more TCP sessions beat the
    // single-session cold ceiling, or is the disk the shared bottleneck? Fresh
    // disjoint slice per session count, drawn after the window-sweep slices.
    let session_cold_base = args.windows.len() * args.cold_slice;
    emit(format!(
        "\n== COLD: in-flight window {} across N TCP sessions (fresh dirs each) ==",
        args.session_window
    ));
    emit(
        "  Caveat: each session count lists a different cold slice, and cold per-dir cost"
            .to_string(),
    );
    emit("  varies ~10x, so read this as rough, not a clean scaling curve.".to_string());
    emit("  sessions   dirs/s   entries/s   wall s   ok   err   dirs".to_string());
    for (j, &k) in args.sessions.iter().enumerate() {
        let avail = k.min(sessions.len());
        let lo = session_cold_base + j * args.cold_slice;
        let hi = (lo + args.cold_slice).min(cold_pool.len());
        if lo >= hi {
            emit(format!(
                "  {avail:>8}  (no cold dirs left for this session count)"
            ));
            continue;
        }
        let slice: Arc<[String]> = Arc::from(cold_pool[lo..hi].to_vec().into_boxed_slice());
        let workers = probe::build_workers(&mut sessions[..avail], args.session_window);
        let r = probe::run_pool(workers, slice.clone()).await;
        emit(format!(
            "  {:>8}  {:7.1}  {:9.0}  {:7.2}  {:>3}  {:>3}  {:>4}",
            avail,
            r.dirs_per_sec(),
            r.entries_per_sec(),
            r.elapsed.as_secs_f64(),
            r.ok,
            r.err,
            hi - lo,
        ));
        if let Some(e) = &r.first_error {
            emit(format!("          first error: {e}"));
        }
    }

    // 5b. WARM: the ceiling, all dirs ARC-cached.
    emit(format!(
        "\n== WARM: in-flight window {} across N TCP sessions ==",
        args.session_window
    ));
    emit("  sessions   dirs/s   entries/s   wall s   ok   err".to_string());
    for &k in &args.sessions {
        let avail = k.min(sessions.len());
        let workers = probe::build_workers(&mut sessions[..avail], args.session_window);
        let r = probe::run_pool(workers, dirs.clone()).await;
        emit(format!(
            "  {:>8}  {:7.1}  {:9.0}  {:7.2}  {:>3}  {:>3}",
            avail,
            r.dirs_per_sec(),
            r.entries_per_sec(),
            r.elapsed.as_secs_f64(),
            r.ok,
            r.err,
        ));
        if let Some(e) = &r.first_error {
            emit(format!("          first error: {e}"));
        }
    }

    emit(format!("\nFinished {}", jiff::Zoned::now()));

    // Save the report.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    if std::fs::create_dir_all(&dir).is_ok() {
        let path = dir.join(format!(
            "listing-{}.txt",
            jiff::Zoned::now().strftime("%Y-%m-%d-%H%M%S")
        ));
        if std::fs::write(&path, &out).is_ok() {
            println!("\nSaved report to {}", path.display());
        }
    }
}

/// Shorten a long share-relative path for table display.
fn short(path: &str) -> String {
    if path.is_empty() {
        return "<root>".to_string();
    }
    if path.len() <= 38 {
        return path.to_string();
    }
    let tail = &path[path.len() - 35..];
    format!("...{tail}")
}
