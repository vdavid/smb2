//! Read-ahead benchmark for `FileDownload`.
//!
//! `run` measures every (size × variant) cell `--runs` times against one
//! server and appends one CSV row per run. `summarize` turns the CSV into
//! median tables. `run.sh` drives the RTT × load matrix around it.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smb2::{ClientConfig, FileDownload, ReadAhead, SmbClient};

mod score;
mod tuning;
mod upload;

/// Share, username, and password, from `SMB_BENCH_SHARE` / `SMB_BENCH_USER` /
/// `SMB_BENCH_PASS`. Defaults are the guest fixture's.
pub(crate) fn share() -> String {
    std::env::var("SMB_BENCH_SHARE").unwrap_or_else(|_| "public".to_string())
}

/// How a variant fetches the file.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Fetch {
    /// A `FileDownload` with the variant's chunk and window.
    Stream,
    /// One compound CREATE + READ + CLOSE (`read_file_compound_sized`).
    Compound,
    /// Compound when the file fits `Connection::quick_read_limit`, the
    /// adaptive stream otherwise: what a consumer using the limit gets.
    Auto,
}

#[derive(Clone, Copy, Debug)]
struct Variant {
    fetch: Fetch,
    /// `None` means "the server's MaxReadSize", which is what `Tree::download` used before 0.24.
    chunk: Option<u32>,
    read_ahead: ReadAhead,
    /// Measure on a fresh connection, so no earlier download's rate seeds the
    /// window. Every other variant runs on the connection the previous ones
    /// used, which is what a folder copy looks like.
    cold: bool,
}

impl Variant {
    fn parse(s: &str) -> Variant {
        let stream = Fetch::Stream;
        if s == "baseline" {
            return Variant { fetch: stream, chunk: None, read_ahead: ReadAhead::SEQUENTIAL, cold: false };
        }
        if s == "adaptive" || s == "adaptive-cold" || s == "compound" || s == "auto" {
            // What `Tree::download` does since 0.24.
            let fetch = match s {
                "compound" => Fetch::Compound,
                "auto" => Fetch::Auto,
                _ => stream,
            };
            return Variant { fetch, chunk: Some(smb2::DOWNLOAD_CHUNK_SIZE), read_ahead: ReadAhead::Adaptive, cold: s == "adaptive-cold" };
        }
        if let Some(k) = s.strip_prefix("seq") {
            return Variant { fetch: stream, chunk: Some(k.parse::<u32>().unwrap() * 1024), read_ahead: ReadAhead::SEQUENTIAL, cold: false };
        }
        let rest = s.strip_prefix("ra").expect("variant: baseline | adaptive | compound | auto | seq<KiB> | ra<KiB>x<W>");
        let (k, w) = rest.split_once('x').unwrap();
        Variant { fetch: stream, chunk: Some(k.parse::<u32>().unwrap() * 1024), read_ahead: ReadAhead::Fixed(w.parse().unwrap()), cold: false }
    }

    /// The CSV's `window` column.
    fn window_label(&self) -> String {
        if self.fetch == Fetch::Compound {
            return "compound".to_string();
        }
        match self.read_ahead {
            ReadAhead::Fixed(w) => w.to_string(),
            _ => "adaptive".to_string(),
        }
    }
}

struct Sample {
    /// CREATE to the CLOSE's answer (the `None` from `next_chunk`).
    wall: Duration,
    /// CREATE to the last chunk in hand: when a consumer has every byte.
    last_chunk: Duration,
    deliveries: usize,
    ttfc: Duration,
    max_gap: Duration,
    peak_in_flight: u64,
    bytes: u64,
    checksum: u64,
    /// Latency of a `stat` issued on a clone of the same connection while the
    /// download runs: what another pane's listing would feel.
    probe_p50: Duration,
    probe_max: Duration,
}

pub(crate) fn fnv(data: &[u8], mut h: u64) -> u64 {
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub(crate) async fn connect(addr: &str) -> SmbClient {
    SmbClient::connect(ClientConfig {
        addr: addr.to_string(),
        timeout: Duration::from_secs(10),
        username: std::env::var("SMB_BENCH_USER").unwrap_or_default(),
        password: std::env::var("SMB_BENCH_PASS").unwrap_or_default(),
        domain: String::new(),
        auto_reconnect: false,
        compression: false,
        dfs_enabled: false,
        dfs_target_overrides: Default::default(),
        connect_options: None,
    })
    .await
    .expect("connect")
}

async fn measure(client: &mut SmbClient, tree: &smb2::Tree, path: &str, size_hint: u64, v: Variant) -> Sample {
    let max_read = client.params().map(|p| p.max_read_size).unwrap_or(65536);
    let chunk = v.chunk.unwrap_or(max_read).min(max_read);
    let conn = client.connection_mut();

    let stop = Arc::new(AtomicBool::new(false));
    let probe = {
        let mut c = conn.clone();
        let t = tree.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut lat = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let s = Instant::now();
                t.stat(&mut c, "bench/f_65536.bin").await.expect("probe stat");
                lat.push(s.elapsed());
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            lat
        })
    };

    let compound = match v.fetch {
        Fetch::Compound => true,
        Fetch::Auto => size_hint <= conn.quick_read_limit(),
        Fetch::Stream => false,
    };
    let t0 = Instant::now();
    let mut chunks = Vec::new();
    let mut last = t0;
    let mut ttfc = None;
    let mut max_gap = Duration::ZERO;
    let peak = if compound {
        let data = tree.read_file_compound_sized(conn, path, size_hint).await.expect("compound read");
        last = Instant::now();
        ttfc = Some(last - t0);
        max_gap = last - t0;
        let n = data.len() as u64;
        chunks.push(data);
        n
    } else {
        let (fid, size) = tree.open_file(conn, path).await.expect("open");
        let mut dl = FileDownload::new(tree, conn, fid, size, chunk).with_read_ahead(v.read_ahead);
        while let Some(c) = dl.next_chunk().await {
            let c = c.expect("chunk");
            let now = Instant::now();
            ttfc.get_or_insert(now - t0);
            max_gap = max_gap.max(now - last);
            last = now;
            chunks.push(c);
        }
        dl.peak_in_flight_bytes()
    };
    let wall = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    let mut lat = probe.await.unwrap();
    lat.sort();
    let probe_p50 = lat.get(lat.len() / 2).copied().unwrap_or_default();
    let probe_max = lat.last().copied().unwrap_or_default();

    let mut h = 0xcbf29ce484222325;
    let mut bytes = 0;
    for c in &chunks {
        h = fnv(c, h);
        bytes += c.len() as u64;
    }
    Sample {
        wall,
        last_chunk: last - t0,
        deliveries: chunks.len(),
        ttfc: ttfc.unwrap_or(wall),
        max_gap,
        peak_in_flight: peak,
        bytes,
        checksum: h,
        probe_p50,
        probe_max,
    }
}

/// Read a quarter of the file, drop the download, and time the next `stat` on
/// the same connection: how long abandoned read-ahead blocks the connection.
async fn cancel_cost(client: &mut SmbClient, tree: &smb2::Tree, path: &str, v: Variant) -> Duration {
    let max_read = client.params().map(|p| p.max_read_size).unwrap_or(65536);
    let chunk = v.chunk.unwrap_or(max_read).min(max_read);
    let conn = client.connection_mut();
    let (fid, size) = tree.open_file(conn, path).await.expect("open");
    let mut dl = FileDownload::new(tree, conn, fid, size, chunk).with_read_ahead(v.read_ahead);
    while dl.bytes_received() < size / 4 {
        dl.next_chunk().await.expect("chunk").expect("chunk ok");
    }
    drop(dl);
    let s = Instant::now();
    tree.stat(conn, "bench/f_65536.bin").await.expect("stat after cancel");
    let d = s.elapsed();
    // The abandoned handle is left open, exactly as a dropped download leaves
    // it today; let the discarded responses finish before the next sample.
    tokio::time::sleep(Duration::from_millis(500)).await;
    d
}

/// Keeps `writers` connections busy writing `block`-sized files to the same
/// share until `stop` flips. Returns the bytes written.
pub(crate) fn spawn_load(addr: String, writers: usize, stop: Arc<AtomicBool>) -> Arc<AtomicU64> {
    let written = Arc::new(AtomicU64::new(0));
    for i in 0..writers {
        let addr = addr.clone();
        let stop = stop.clone();
        let written = written.clone();
        tokio::spawn(async move {
            let mut client = connect(&addr).await;
            let mut tree = client.connect_share(&share()).await.expect("share");
            let block = vec![0x5au8; 32 * 1024 * 1024];
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let path = format!("load/w{i}-{}.bin", n % 2);
                match client.write_file(&mut tree, &path, &block).await {
                    Ok(w) => {
                        written.fetch_add(w, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("load writer {i}: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
                n += 1;
            }
        });
    }
    written
}

pub(crate) fn arg(args: &[String], name: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == name)
        .map(|i| args[i + 1].clone())
        .unwrap_or_else(|| default.to_string())
}

async fn run(args: &[String]) {
    let addr = arg(args, "--addr", "127.0.0.1:17445");
    let rtt = arg(args, "--rtt-ms", "0");
    let load_writers: usize = arg(args, "--load-writers", "0").parse().unwrap();
    let runs: usize = arg(args, "--runs", "3").parse().unwrap();
    let out = arg(args, "--out", "results.csv");
    let sizes: Vec<u64> = arg(args, "--sizes", "65536,386048,1048576,8388608,104857600")
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();
    // (name, variant, tuning): `auto:wmax16` is `auto` under the `wmax16` tuning.
    let variants: Vec<(String, Variant, Option<String>)> =
        arg(args, "--variants", "baseline,seq512,ra512x4,ra512x8,ra512x16,ra512x32")
            .split(',')
            .map(|s| {
                let (base, t) = tuning::split(s);
                (s.to_string(), Variant::parse(base), t.map(str::to_string))
            })
            .collect();

    let mut client = connect(&addr).await;
    let mut tree = client.connect_share(&share()).await.expect("share");
    if args.iter().any(|a| a == "--prep") {
        // For a server where `run.sh` can't create the files (a real NAS).
        let _ = client.create_directory(&mut tree, "bench").await;
        let _ = client.create_directory(&mut tree, "load").await;
        // Where `upload` writes.
        let _ = client.create_directory(&mut tree, "up").await;
        let mut seed = 0x9e3779b97f4a7c15u64;
        for &size in &sizes {
            let data: Vec<u8> = (0..size)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            client.write_file(&mut tree, &format!("bench/f_{size}.bin"), &data).await.expect("prep write");
        }
        eprintln!("prepared {} files under bench/", sizes.len());
    }
    let max_read = client.params().map(|p| p.max_read_size).unwrap_or(0);
    eprintln!("max_read_size={max_read}");

    let stop = Arc::new(AtomicBool::new(false));
    let written = if load_writers > 0 {
        let w = spawn_load(addr.clone(), load_writers, stop.clone());
        tokio::time::sleep(Duration::from_secs(3)).await;
        Some(w)
    } else {
        None
    };
    let load_start = Instant::now();
    let load_start_bytes = written.as_ref().map_or(0, |w| w.load(Ordering::Relaxed));

    let new_file = !std::path::Path::new(&out).exists();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&out).unwrap();
    if new_file {
        writeln!(f, "rtt_ms,load,size,variant,chunk,window,run,wall_ms,mbps,deliveries,ttfc_ms,max_gap_ms,peak_in_flight,bytes,checksum,probe_p50_ms,probe_max_ms,cancel_stat_ms,last_chunk_ms").unwrap();
    }
    // Each tuning gets a connection of its own, so what one candidate learned
    // (rate, headroom) never seeds another. Untuned variants share the first.
    let mut conns: BTreeMap<String, (SmbClient, smb2::Tree)> = BTreeMap::new();
    for t in variants.iter().filter_map(|(_, _, t)| t.clone()) {
        if !conns.contains_key(&t) {
            let mut c = connect(&addr).await;
            let tr = c.connect_share(&share()).await.expect("share");
            conns.insert(t, (c, tr));
        }
    }
    conns.insert(String::new(), (client, tree));
    let mut reference: BTreeMap<u64, u64> = BTreeMap::new();
    for run in 0..runs {
        for &size in &sizes {
            let path = format!("bench/f_{size}.bin");
            // Tuned variants rotate per run, so no candidate always follows the
            // same one; untuned ones keep their order (see `adaptive-cold`).
            let offset = if conns.len() > 1 { run } else { 0 };
            for i in 0..variants.len() {
                let (name, v, tuned) = &variants[(i + offset) % variants.len()];
                tuning::apply(tuned.as_deref());
                let mut fresh = if v.cold {
                    let mut c = connect(&addr).await;
                    let t = c.connect_share(&share()).await.expect("share");
                    Some((c, t))
                } else {
                    None
                };
                let (c, t) = match fresh {
                    Some((ref mut c, ref t)) => (c, t),
                    None => {
                        let (c, t) = conns.get_mut(tuned.as_deref().unwrap_or("")).unwrap();
                        (c, &*t)
                    }
                };
                let s = measure(c, t, &path, size, *v).await;
                let cancel = if size >= 8 << 20 && v.fetch == Fetch::Stream {
                    cancel_cost(c, t, &path, *v).await.as_secs_f64() * 1000.0
                } else {
                    f64::NAN
                };
                assert_eq!(s.bytes, size, "{name} read {} of {size} bytes", s.bytes);
                let expected = *reference.entry(size).or_insert(s.checksum);
                assert_eq!(s.checksum, expected, "{name} content differs on {path}");
                let chunk = v.chunk.unwrap_or(max_read).min(max_read);
                let secs = s.wall.as_secs_f64();
                writeln!(
                    f,
                    "{rtt},{load_writers},{size},{name},{chunk},{},{run},{:.2},{:.2},{},{:.2},{:.2},{},{},{:x},{:.2},{:.2},{:.2},{:.2}",
                    v.window_label(),
                    secs * 1000.0,
                    size as f64 / 1e6 / secs,
                    s.deliveries,
                    s.ttfc.as_secs_f64() * 1000.0,
                    s.max_gap.as_secs_f64() * 1000.0,
                    s.peak_in_flight,
                    s.bytes,
                    s.checksum,
                    s.probe_p50.as_secs_f64() * 1000.0,
                    s.probe_max.as_secs_f64() * 1000.0,
                    cancel,
                    s.last_chunk.as_secs_f64() * 1000.0
                )
                .unwrap();
            }
        }
        eprintln!("rtt={rtt} load={load_writers} run {} of {runs} done", run + 1);
    }
    stop.store(true, Ordering::Relaxed);
    if let Some(w) = written {
        let bytes = w.load(Ordering::Relaxed) - load_start_bytes;
        let secs = load_start.elapsed().as_secs_f64();
        eprintln!("background writers: {:.1} MB/s during measurement", bytes as f64 / 1e6 / secs);
        let mut lf = std::fs::OpenOptions::new().create(true).append(true).open(format!("{out}.load")).unwrap();
        writeln!(lf, "rtt_ms={rtt} writers={load_writers} load_mb_s={:.1}", bytes as f64 / 1e6 / secs).unwrap();
    }
}

pub(crate) fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

fn summarize(path: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap().split(',').collect();
    let col = |n: &str| header.iter().position(|h| *h == n);
    // (rtt, load, size) -> variant order -> column samples
    type Cell = BTreeMap<&'static str, Vec<f64>>;
    let mut groups: BTreeMap<(u64, String, u64, u64), Vec<(String, Cell)>> = BTreeMap::new();
    for line in lines {
        let f: Vec<&str> = line.split(',').collect();
        let link = f[col("rtt_ms").unwrap()].to_string();
        let key = (
            link.split('@').next().unwrap().parse().unwrap_or(u64::MAX),
            link,
            f[col("load").unwrap()].parse().unwrap(),
            f[col("size").unwrap()].parse().unwrap(),
        );
        let variant = f[col("variant").unwrap()].to_string();
        let rows = groups.entry(key).or_default();
        let idx = match rows.iter().position(|(v, _)| *v == variant) {
            Some(i) => i,
            None => {
                rows.push((variant, BTreeMap::new()));
                rows.len() - 1
            }
        };
        for name in ["wall_ms", "last_chunk_ms", "mbps", "deliveries", "ttfc_ms", "max_gap_ms", "peak_in_flight", "probe_p50_ms", "probe_max_ms", "cancel_stat_ms"] {
            // CSVs from before `last_chunk_ms` existed read as NaN there.
            let value = col(name).map_or(f64::NAN, |i| f[i].parse().unwrap());
            rows[idx].1.entry(name).or_default().push(value);
        }
    }
    let human = |b: u64| -> String {
        if b >= 1 << 20 { format!("{} MiB", b >> 20) } else { format!("{} KiB", b >> 10) }
    };
    for ((_, rtt, load, size), rows) in groups {
        let n = rows[0].1["wall_ms"].len();
        println!(
            "\n#### Link +{rtt} ms, load: {}, file {} (median of {n})\n",
            if load == 0 { "none".to_string() } else { format!("{load} writers") },
            human(size)
        );
        println!("| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |");
        println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
        for (v, c) in rows {
            let m = |k: &str| median(c[k].clone());
            let cancel = m("cancel_stat_ms");
            println!(
                "| {v} | {:.1} | {} | {:.1} | {:.0} | {:.1} | {:.1} | {} | {:.0} / {:.0} | {} |",
                m("wall_ms"),
                if m("last_chunk_ms").is_nan() { "n/a".to_string() } else { format!("{:.1}", m("last_chunk_ms")) },
                m("mbps"),
                m("deliveries"),
                m("ttfc_ms"),
                m("max_gap_ms"),
                human(m("peak_in_flight") as u64),
                m("probe_p50_ms"),
                m("probe_max_ms"),
                if cancel.is_nan() { "n/a".to_string() } else { format!("{cancel:.0}") }
            );
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => run(&args).await,
        Some("summarize") => summarize(&args[2]),
        Some("upload") => upload::run(&args).await,
        Some("summarize-upload") => upload::summarize(&args[2]),
        Some("score") => score::run(&args[2..]),
        _ => eprintln!("usage: read-ahead-bench run [--addr A] [--rtt-ms N] [--load-writers N] [--runs N] [--out F] [--sizes a,b] [--variants v,w] | summarize F | upload [same flags] | summarize-upload F | score [--detail] F... (variants take a `:<tuning>` suffix; tunings: {})", tuning::NAMES),
    }
}
