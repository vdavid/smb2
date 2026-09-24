//! Measurement engine for the listing probe.
//!
//! Everything here is read-only against the server: it only ever issues
//! CREATE(dir) + QUERY_DIRECTORY + CLOSE via `smb2`'s listing calls. No writes,
//! no deletes.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use smb2::client::Connection;
use smb2::{ClientConfig, ListingTrace, SmbClient, Tree};

use crate::config::Target;

/// One authenticated connection to the NAS: a TCP session, its SMB session,
/// and a tree connect. `client.connection_mut().clone()` mints extra
/// `Connection` handles that multiplex over this one TCP session.
pub struct Session {
    pub client: SmbClient,
    pub tree: Tree,
}

impl Session {
    /// Mint a `Connection` handle that shares this session's TCP transport.
    pub fn conn_handle(&mut self) -> Connection {
        self.client.connection_mut().clone()
    }
}

/// A pool worker: owns one `Connection` handle plus the `Tree` it belongs to.
pub struct Worker {
    pub conn: Connection,
    pub tree: Tree,
}

/// Connect, authenticate, and tree-connect to the target's share.
pub async fn connect_session(target: &Target) -> Result<Session, String> {
    let (username, password) = if target.guest {
        (String::new(), String::new())
    } else {
        (
            target.username.clone().unwrap_or_default(),
            target.password.clone().unwrap_or_default(),
        )
    };

    let config = ClientConfig {
        addr: format!("{}:445", target.host),
        timeout: Duration::from_secs(10),
        username,
        password,
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
        dfs_target_overrides: std::collections::HashMap::new(),
        connect_options: None,
    };

    let mut client = SmbClient::connect(config)
        .await
        .map_err(|e| format!("connect {}: {e}", target.host))?;
    let tree = client
        .connect_share(&target.share)
        .await
        .map_err(|e| format!("connect_share '{}': {e}", target.share))?;
    Ok(Session { client, tree })
}

/// The server's negotiated max transact size, which caps the QUERY_DIRECTORY
/// output buffer we can ask for.
pub fn max_transact_size(session: &Session) -> u32 {
    session
        .client
        .params()
        .map(|p| p.max_transact_size)
        .unwrap_or(65536)
}

// ─────────────────────────────── discovery ───────────────────────────────

/// The directory sample discovered for measurement.
pub struct Discovered {
    /// Directories discovered from their parents' listings but never listed
    /// themselves, so their own metadata is cold on first access. This is the
    /// warm/cold sample.
    pub cold_dirs: Vec<String>,
    /// The fattest directories we did list during discovery, `(path, entries)`,
    /// sorted by entry count descending. Used for the query-buffer experiment.
    pub fat_dirs: Vec<(String, usize)>,
    /// How many directories we listed to run discovery (all now warm).
    pub expanded: usize,
}

/// Breadth-first walk from `root` that collects a cold directory sample.
///
/// We expand (list) directories to enumerate their children, but the children
/// themselves stay unlisted. We keep expanding until at least `sample_target`
/// unlisted directories are queued; those queued directories are the cold
/// sample (their own contents were never read, so ARC hasn't cached them).
pub async fn discover(
    conn: &mut Connection,
    tree: &Tree,
    root: &str,
    sample_target: usize,
) -> Result<Discovered, String> {
    let mut to_expand: VecDeque<String> = VecDeque::new();
    to_expand.push_back(root.to_string());
    let mut expanded_counts: Vec<(String, usize)> = Vec::new();

    while to_expand.len() < sample_target {
        let Some(dir) = to_expand.pop_front() else {
            break;
        };
        let entries = match tree.list_directory(conn, &dir).await {
            Ok(e) => e,
            // A dir we can't list (permissions, vanished) just doesn't expand.
            Err(_) => continue,
        };
        let mut real = 0usize;
        for e in &entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            real += 1;
            if e.is_directory {
                let child = if dir.is_empty() {
                    e.name.clone()
                } else {
                    format!("{dir}\\{}", e.name)
                };
                to_expand.push_back(child);
            }
        }
        expanded_counts.push((dir, real));
    }

    let cold_dirs: Vec<String> = to_expand.into_iter().take(sample_target).collect();

    let mut fat_dirs = expanded_counts.clone();
    fat_dirs.sort_by_key(|d| std::cmp::Reverse(d.1));
    fat_dirs.truncate(32);

    Ok(Discovered {
        cold_dirs,
        fat_dirs,
        expanded: expanded_counts.len(),
    })
}

// ───────────────────────── serial phase breakdown ────────────────────────

/// Serial, one-connection listing of every dir in `dirs`, capturing a
/// per-phase [`ListingTrace`] for each.
pub async fn phase_breakdown(
    conn: &mut Connection,
    tree: &Tree,
    dirs: &[String],
) -> Vec<ListingTrace> {
    let mut traces = Vec::with_capacity(dirs.len());
    for dir in dirs {
        if let Ok((_, trace)) = tree.list_directory_instrumented(conn, dir, None).await {
            traces.push(trace);
        }
    }
    traces
}

// ─────────────────────────── concurrency pool ────────────────────────────

/// Outcome of running a worker pool over a directory set.
pub struct PoolResult {
    pub elapsed: Duration,
    pub entries: u64,
    pub ok: u64,
    pub err: u64,
}

impl PoolResult {
    pub fn dirs_per_sec(&self) -> f64 {
        self.ok as f64 / self.elapsed.as_secs_f64()
    }
    pub fn entries_per_sec(&self) -> f64 {
        self.entries as f64 / self.elapsed.as_secs_f64()
    }
}

/// Run `workers.len()` concurrent listings over `dirs`, work-stealing from a
/// shared cursor so every worker stays busy until the set is drained.
pub async fn run_pool(workers: Vec<Worker>, dirs: Arc<[String]>) -> PoolResult {
    let cursor = Arc::new(AtomicUsize::new(0));
    let entries = Arc::new(AtomicU64::new(0));
    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let mut handles = Vec::with_capacity(workers.len());
    for mut w in workers {
        let dirs = dirs.clone();
        let cursor = cursor.clone();
        let entries = entries.clone();
        let ok = ok.clone();
        let err = err.clone();
        handles.push(tokio::spawn(async move {
            loop {
                let idx = cursor.fetch_add(1, Ordering::Relaxed);
                if idx >= dirs.len() {
                    break;
                }
                match w.tree.list_directory(&mut w.conn, &dirs[idx]).await {
                    Ok(es) => {
                        entries.fetch_add(es.len() as u64, Ordering::Relaxed);
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    PoolResult {
        elapsed: start.elapsed(),
        entries: entries.load(Ordering::Relaxed),
        ok: ok.load(Ordering::Relaxed),
        err: err.load(Ordering::Relaxed),
    }
}

/// Build `window` workers spread round-robin across `sessions`, each worker a
/// fresh `Connection` handle on its session's TCP transport.
pub fn build_workers(sessions: &mut [Session], window: usize) -> Vec<Worker> {
    let mut workers = Vec::with_capacity(window);
    for i in 0..window {
        let s = &mut sessions[i % sessions.len()];
        workers.push(Worker {
            conn: s.conn_handle(),
            tree: s.tree.clone(),
        });
    }
    workers
}

// ───────────────────────── large-dir buffer sweep ────────────────────────

/// One (directory, buffer size) measurement in the query-buffer experiment.
pub struct BufferResult {
    pub dir: String,
    pub entries: usize,
    pub buffer_len: u32,
    pub round_trips: usize,
    pub query_total: Duration,
    pub total: Duration,
}

/// For each fat directory, list it once per candidate query-buffer size and
/// record round-trip count and timing. Warms the directory first so the
/// comparison isolates the buffer effect from cold-cache cost.
pub async fn large_dir_buffers(
    conn: &mut Connection,
    tree: &Tree,
    fat_dirs: &[(String, usize)],
    buffers: &[u32],
) -> Vec<BufferResult> {
    let mut results = Vec::new();
    for (dir, _) in fat_dirs {
        // Warm the directory so buffer sizes compete on equal cache footing.
        let _ = tree.list_directory(conn, dir).await;
        for &buf in buffers {
            match tree.list_directory_instrumented(conn, dir, Some(buf)).await {
                Ok((entries, trace)) => results.push(BufferResult {
                    dir: dir.clone(),
                    entries: entries.len(),
                    buffer_len: buf,
                    round_trips: trace.queries.len(),
                    query_total: trace.query_total(),
                    total: trace.total(),
                }),
                Err(_) => {
                    // Buffer too big for the server or credits short; skip it.
                }
            }
        }
    }
    results
}
