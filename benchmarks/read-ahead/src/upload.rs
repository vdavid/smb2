//! Upload benchmark for `FileWriter` and the one-frame compound write.
//!
//! `upload` measures every (size × variant) cell `--runs` times and appends
//! one CSV row per run; `summarize-upload` turns the CSV into median tables.
//! `run.sh` with `DIRECTION=up` shapes the client-to-server direction instead
//! of the server-to-client one, since an upload's payload flows that way.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smb2::SmbClient;

use crate::{arg, connect, fnv, median, share, spawn_load};

/// How a variant writes the file.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Put {
    /// A `FileWriter` fed 1 MiB pushes.
    Stream,
    /// One compound CREATE + WRITE + FLUSH + CLOSE (`write_file_compound`).
    /// Skipped for a file above `compound_write_limit`.
    Compound,
    /// Compound when the file fits `Connection::quick_write_limit`, the
    /// default `FileWriter` otherwise: what a consumer using the limit gets.
    Auto,
}

#[derive(Clone, Copy, Debug)]
struct Variant {
    put: Put,
    /// `None` means the writer's default chunk.
    chunk: Option<u32>,
    /// `None` means the writer's default window.
    window: Option<usize>,
}

impl Variant {
    fn parse(s: &str) -> Variant {
        match s {
            // Whatever `FileWriter` does by default in the build under test.
            "default" => return Variant { put: Put::Stream, chunk: None, window: None },
            "compound" => return Variant { put: Put::Compound, chunk: None, window: None },
            "auto" => return Variant { put: Put::Auto, chunk: None, window: None },
            _ => {}
        }
        // `wb<KiB>x<W>`: a fixed window of W WRITEs of that size; `wbmaxx<W>`
        // uses the server's MaxWriteSize.
        let rest = s.strip_prefix("wb").expect("variant: default | compound | auto | wb<KiB|max>x<W>");
        let (k, w) = rest.rsplit_once('x').unwrap();
        let chunk = if k == "max" { u32::MAX } else { k.parse::<u32>().unwrap() * 1024 };
        Variant { put: Put::Stream, chunk: Some(chunk), window: Some(w.parse().unwrap()) }
    }
}

struct Sample {
    /// CREATE to the CLOSE's answer.
    wall: Duration,
    /// Chunks the server confirmed, or 1 for a compound write.
    writes: u64,
    peak_in_flight: Option<u64>,
    /// Latency of a `stat` issued on a clone of the same connection while the
    /// upload runs: what another pane's listing would feel.
    probe_p50: Duration,
    probe_max: Duration,
}

/// Wraps `smb2::FileWriter` construction so the variants that need the new
/// knobs stay in one place.
async fn open_writer(conn: &smb2::client::Connection, tree: &Arc<smb2::Tree>, path: &str, v: Variant) -> smb2::FileWriter {
    let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);
    let writer = tree.create_file_writer(conn.clone(), path).await.expect("open writer");
    let writer = match v.chunk {
        Some(c) => writer.with_chunk_size(c.min(max_write)),
        None => writer,
    };
    match v.window {
        Some(w) => writer.with_write_behind(smb2::WriteBehind::Fixed(w)),
        None => writer,
    }
}

async fn measure(client: &mut SmbClient, tree: &Arc<smb2::Tree>, path: &str, data: &[u8], v: Variant) -> Option<Sample> {
    let conn = client.connection_mut().clone();
    let compound = match v.put {
        Put::Compound => {
            if data.len() as u64 > conn.compound_write_limit() {
                return None;
            }
            true
        }
        Put::Auto => data.len() as u64 <= conn.quick_write_limit(),
        Put::Stream => false,
    };

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

    let t0 = Instant::now();
    let (writes, peak) = if compound {
        let mut c = conn.clone();
        tree.write_file_compound(&mut c, path, data).await.expect("compound write");
        (1, Some(data.len() as u64))
    } else {
        let mut w = open_writer(&conn, tree, path, v).await;
        for piece in data.chunks(1 << 20) {
            w.write_chunk(piece).await.expect("write_chunk");
        }
        let peak = w.peak_in_flight_bytes();
        let chunk = u64::from(w.chunk_size());
        let written = w.finish().await.expect("finish");
        assert_eq!(written, data.len() as u64);
        (written.div_ceil(chunk), Some(peak))
    };
    let wall = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    let mut lat = probe.await.unwrap();
    lat.sort();
    Some(Sample {
        wall,
        writes,
        peak_in_flight: peak,
        probe_p50: lat.get(lat.len() / 2).copied().unwrap_or_default(),
        probe_max: lat.last().copied().unwrap_or_default(),
    })
}

/// Push a quarter of the file, abort, and time until a `stat` on the same
/// connection answers: what a user cancelling a copy waits for before the
/// share responds again.
async fn cancel_cost(client: &mut SmbClient, tree: &Arc<smb2::Tree>, path: &str, data: &[u8], v: Variant) -> Duration {
    let conn = client.connection_mut().clone();
    let mut w = open_writer(&conn, tree, path, v).await;
    for piece in data[..data.len() / 4].chunks(1 << 20) {
        w.write_chunk(piece).await.expect("write_chunk");
    }
    let s = Instant::now();
    w.abort().await.expect("abort");
    let mut c = conn.clone();
    tree.stat(&mut c, "bench/f_65536.bin").await.expect("stat after cancel");
    s.elapsed()
}

pub async fn run(args: &[String]) {
    let addr = arg(args, "--addr", "127.0.0.1:17445");
    let rtt = arg(args, "--rtt-ms", "0");
    let load_writers: usize = arg(args, "--load-writers", "0").parse().unwrap();
    let runs: usize = arg(args, "--runs", "3").parse().unwrap();
    let out = arg(args, "--out", "upload.csv");
    let sizes: Vec<u64> = arg(args, "--sizes", "1048576,8388608,104857600").split(',').map(|s| s.parse().unwrap()).collect();
    let variants: Vec<(String, Variant)> = arg(args, "--variants", "default,compound")
        .split(',')
        .map(|s| (s.to_string(), Variant::parse(s)))
        .collect();

    let mut client = connect(&addr).await;
    let tree = Arc::new(client.connect_share(&share()).await.expect("share"));
    let max_write = client.params().map(|p| p.max_write_size).unwrap_or(0);
    eprintln!("max_write_size={max_write}");

    let stop = Arc::new(AtomicBool::new(false));
    if load_writers > 0 {
        spawn_load(addr.clone(), load_writers, stop.clone());
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let new_file = !std::path::Path::new(&out).exists();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&out).unwrap();
    if new_file {
        writeln!(f, "rtt_ms,load,size,variant,run,wall_ms,mbps,writes,peak_in_flight,probe_p50_ms,probe_max_ms,cancel_stat_ms").unwrap();
    }
    let mut seed = 0x9e3779b97f4a7c15u64;
    let files: BTreeMap<u64, Vec<u8>> = sizes
        .iter()
        .map(|&size| {
            let data = (0..size)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            (size, data)
        })
        .collect();
    for run in 0..runs {
        for (&size, data) in &files {
            let path = format!("up/u_{size}.bin");
            for (name, v) in &variants {
                let Some(s) = measure(&mut client, &tree, &path, data, *v).await else {
                    continue;
                };
                // Read it back: a wrong write fails the run.
                let mut c = client.connection_mut().clone();
                let back = tree.read_file_pipelined(&mut c, &path).await.expect("read back");
                assert_eq!(fnv(&back, 0), fnv(data, 0), "{name} wrote different bytes to {path}");
                let cancel = if size >= 8 << 20 && v.put == Put::Stream {
                    cancel_cost(&mut client, &tree, "up/cancelled.bin", data, *v).await.as_secs_f64() * 1000.0
                } else {
                    f64::NAN
                };
                let secs = s.wall.as_secs_f64();
                writeln!(
                    f,
                    "{rtt},{load_writers},{size},{name},{run},{:.2},{:.2},{},{},{:.2},{:.2},{:.2}",
                    secs * 1000.0,
                    size as f64 / 1e6 / secs,
                    s.writes,
                    s.peak_in_flight.map_or(String::new(), |p| p.to_string()),
                    s.probe_p50.as_secs_f64() * 1000.0,
                    s.probe_max.as_secs_f64() * 1000.0,
                    cancel,
                )
                .unwrap();
            }
        }
        eprintln!("upload rtt={rtt} load={load_writers} run {} of {runs} done", run + 1);
    }
    stop.store(true, Ordering::Relaxed);
}

pub fn summarize(path: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap().split(',').collect();
    let col = |n: &str| header.iter().position(|h| *h == n).unwrap();
    type Cell = BTreeMap<&'static str, Vec<f64>>;
    let mut groups: BTreeMap<(u64, String, u64, u64), Vec<(String, Cell)>> = BTreeMap::new();
    for line in lines {
        let f: Vec<&str> = line.split(',').collect();
        let link = f[col("rtt_ms")].to_string();
        let key = (
            link.split('@').next().unwrap().parse().unwrap_or(u64::MAX),
            link,
            f[col("load")].parse().unwrap(),
            f[col("size")].parse().unwrap(),
        );
        let variant = f[col("variant")].to_string();
        let rows = groups.entry(key).or_default();
        let idx = match rows.iter().position(|(v, _)| *v == variant) {
            Some(i) => i,
            None => {
                rows.push((variant, BTreeMap::new()));
                rows.len() - 1
            }
        };
        for name in ["wall_ms", "mbps", "writes", "peak_in_flight", "probe_p50_ms", "probe_max_ms", "cancel_stat_ms"] {
            let value = f[col(name)].parse().unwrap_or(f64::NAN);
            rows[idx].1.entry(name).or_default().push(value);
        }
    }
    let human = |b: f64| -> String {
        if b.is_nan() {
            "n/a".to_string()
        } else if b >= f64::from(1 << 20) {
            format!("{:.1} MiB", b / f64::from(1 << 20))
        } else {
            format!("{} KiB", (b as u64) >> 10)
        }
    };
    for ((_, rtt, load, size), rows) in groups {
        let n = rows[0].1["wall_ms"].len();
        println!(
            "\n#### Uplink +{rtt} ms, load: {}, file {} (median of {n})\n",
            if load == 0 { "none".to_string() } else { format!("{load} writers") },
            human(size as f64)
        );
        println!("| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |");
        println!("|---|---:|---:|---:|---:|---:|---:|");
        for (v, c) in rows {
            let m = |k: &str| median(c[k].clone());
            let cancel = m("cancel_stat_ms");
            println!(
                "| {v} | {:.1} | {:.1} | {:.0} | {} | {:.0} / {:.0} | {} |",
                m("wall_ms"),
                m("mbps"),
                m("writes"),
                human(m("peak_in_flight")),
                m("probe_p50_ms"),
                m("probe_max_ms"),
                if cancel.is_nan() { "n/a".to_string() } else { format!("{cancel:.0}") }
            );
        }
    }
}
