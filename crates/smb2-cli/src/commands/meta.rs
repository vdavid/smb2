//! Read-only commands: `ls`, `stat`, `realpath`, `df`, and `shares`.

use anyhow::{Context, Result};
use serde_json::json;
use smb2::{DirectoryEntry, ListOptions, SmbClient, Tree};

use crate::auth::Credentials;
use crate::output;
use crate::pool::{self, Job, Outcome};
use crate::target::Target;

/// How `ls` prints its rows.
#[derive(Clone, Copy)]
pub struct LsFormat {
    /// `-l`: type, size, and modification time before the name.
    pub long: bool,
    /// `-R`: descend into subdirectories, and print share-relative paths.
    pub recursive: bool,
    /// `--sort`: wait for the whole listing and sort it by path.
    pub sort: bool,
    /// `-i`: each entry's index number (the file system's file ID), before
    /// the rest of the row.
    pub index: bool,
}

impl LsFormat {
    /// What to ask the server for: index numbers only when they're shown, so
    /// a plain `ls` sends exactly the default listing.
    fn list_options(self) -> ListOptions {
        ListOptions::new().index_numbers(self.index)
    }
}

/// List a directory.
///
/// Text output streams: each server batch is printed as it arrives, in the
/// server's order, so the first rows of a 100,000-entry folder show up after
/// one round trip and `| head` stops the listing early. `--sort` and `--json`
/// wait for everything and sort by path; a JSON array is no use to a parser
/// until its last row anyway, and a stable order keeps it diffable.
pub async fn ls(
    target: &Target,
    credentials: &Credentials,
    format: LsFormat,
    as_json: bool,
) -> Result<()> {
    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");

    let result = if format.sort || as_json {
        ls_sorted(&mut client, &mut tree, target, format, as_json).await
    } else {
        ls_streaming(&mut client, &mut tree, target, format).await
    };

    let _ = client.disconnect_share(&tree).await;
    result
}

/// Every row, then sorted output.
async fn ls_sorted(
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    format: LsFormat,
    as_json: bool,
) -> Result<()> {
    let mut pending = vec![target.path.clone()];
    let mut rows = Vec::new();
    while let Some(path) = pending.pop() {
        let entries = client
            .list_directory_with(tree, &path, format.list_options())
            .await
            .with_context(|| format!("listing {}", target.with_path(&path).display()))?;
        for entry in entries {
            if let Some(full) = child_path(&path, &entry) {
                // A junction or directory symlink lists, but isn't walked:
                // its contents live elsewhere, and one pointing up loops.
                if format.recursive && entry.is_directory && !entry.is_link() {
                    pending.push(full.clone());
                }
                rows.push((full, entry));
            }
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    if as_json {
        let items: Vec<_> = rows
            .iter()
            .map(|(path, entry)| {
                let mut item = json!({
                    "path": path,
                    "name": entry.name,
                    "isDirectory": entry.is_directory,
                    "isLink": entry.is_link(),
                    // The raw tag, `null` when it isn't a reparse point.
                    "reparseTag": entry.reparse_tag.map(|tag| tag.0),
                    "size": entry.size,
                    "modified": output::unix_seconds(entry.modified),
                    "created": output::unix_seconds(entry.created),
                    "changed": output::unix_seconds(entry.changed),
                });
                if format.index {
                    // `null` when the server has no file ID for it.
                    item["indexNumber"] = json!(entry.index_number);
                }
                item
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    let mut text = String::new();
    for (path, entry) in &rows {
        push_row(&mut text, path, entry, format);
    }
    match write_stdout(&text) {
        Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => Err(error.into()),
        _ => Ok(()),
    }
}

/// Each batch printed as it arrives. A recursive walk lists a directory to
/// the end before descending, so one reader is open at a time.
async fn ls_streaming(
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    format: LsFormat,
) -> Result<()> {
    let mut pending = vec![target.path.clone()];
    while let Some(path) = pending.pop() {
        let listing = || format!("listing {}", target.with_path(&path).display());
        let mut reader = client
            .open_directory_reader_with(tree, &path, format.list_options())
            .await
            .with_context(listing)?;
        let mut subdirectories = Vec::new();
        // An error closes the reader by itself.
        while let Some(batch) = reader.next_batch().await.with_context(listing)? {
            let mut text = String::new();
            for entry in &batch {
                if let Some(full) = child_path(&path, entry) {
                    push_row(&mut text, &full, entry, format);
                    if format.recursive && entry.is_directory && !entry.is_link() {
                        subdirectories.push(full);
                    }
                }
            }
            if let Err(error) = write_stdout(&text) {
                // `| head` has what it wanted: stop listing, quietly.
                let _ = reader.close().await;
                return match error.kind() {
                    std::io::ErrorKind::BrokenPipe => Ok(()),
                    _ => Err(error.into()),
                };
            }
        }
        // Reversed onto the stack, so subdirectories come out in the order
        // the server listed them.
        pending.extend(subdirectories.into_iter().rev());
    }
    Ok(())
}

/// The share-relative path of `entry` inside `parent`, or `None` for `.` and
/// `..`.
fn child_path(parent: &str, entry: &DirectoryEntry) -> Option<String> {
    if entry.name == "." || entry.name == ".." {
        return None;
    }
    Some(if parent.is_empty() {
        entry.name.clone()
    } else {
        format!("{parent}/{}", entry.name)
    })
}

/// One text row. The columns are fixed-width, so a row never depends on the
/// rows around it, which is what lets `-l` stream.
fn push_row(text: &mut String, path: &str, entry: &DirectoryEntry, format: LsFormat) {
    use std::fmt::Write;
    let name = if format.recursive { path } else { &entry.name };
    if format.index {
        // Fixed width like the other columns, so a row still never waits on
        // the rest. A longer number widens only its own row.
        let index = entry
            .index_number
            .map_or_else(|| "-".to_string(), |n| n.to_string());
        let _ = write!(text, "{index:>12}  ");
    }
    if format.long {
        let _ = writeln!(
            text,
            "{}  {:>15}  {}  {}",
            if entry.is_directory { "d" } else { "-" },
            output::bytes(entry.size),
            output::timestamp(entry.modified),
            name,
        );
    } else {
        let _ = writeln!(text, "{name}");
    }
}

/// Write `text` to stdout and flush it, so a batch shows up as soon as it's
/// listed and not when a buffer fills. Errors come back (a closed pipe is
/// `BrokenPipe`) where `print!` would panic.
fn write_stdout(text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()
}

pub async fn stat(
    base: &Target,
    credentials: &Credentials,
    paths: Vec<String>,
    concurrency: usize,
    as_json: bool,
) -> Result<()> {
    let jobs: Vec<Job> = paths.iter().map(|path| Job::Stat(path.clone())).collect();
    let outcomes = pool::run(base, credentials, concurrency, jobs, |_, _| {}).await?;

    let mut failures = 0;
    let mut items = Vec::new();
    for (path, outcome) in paths.iter().zip(&outcomes) {
        match outcome {
            Outcome::Stat(info) => {
                if as_json {
                    items.push(json!({
                        "path": path,
                        "isDirectory": info.is_directory,
                        "isLink": info.is_link(),
                        "reparseTag": info.reparse_tag.map(|tag| tag.0),
                        "size": info.size,
                        "modified": output::unix_seconds(info.modified),
                        "created": output::unix_seconds(info.created),
                        "accessed": output::unix_seconds(info.accessed),
                        "changed": output::unix_seconds(info.changed),
                    }));
                } else {
                    println!("{path}");
                    println!(
                        "  type:     {}",
                        if info.is_directory {
                            "directory"
                        } else {
                            "file"
                        }
                    );
                    println!("  size:     {} bytes", output::bytes(info.size));
                    println!("  created:  {}", output::timestamp(info.created));
                    println!("  modified: {}", output::timestamp(info.modified));
                    println!("  accessed: {}", output::timestamp(info.accessed));
                    println!("  changed:  {}", output::timestamp(info.changed));
                }
            }
            other => {
                failures += 1;
                let message = other.error().unwrap_or("unknown error");
                if as_json {
                    items.push(json!({ "path": path, "error": message }));
                } else {
                    eprintln!("{path}: {message}");
                }
            }
        }
    }
    if as_json {
        println!("{}", serde_json::to_string_pretty(&items)?);
    }
    if failures > 0 {
        anyhow::bail!("{failures} of {} paths failed", paths.len());
    }
    Ok(())
}

/// Print the path the server stores `target` under: its on-disk casing, with
/// any 8.3 alias replaced by the long name.
pub async fn realpath(target: &Target, credentials: &Credentials, as_json: bool) -> Result<()> {
    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let resolved = client
        .resolve(&mut tree, &target.path)
        .await
        .with_context(|| format!("resolving {}", target.display()))?;
    // After a DFS redirect `tree` names the target server and share, which is
    // what the resolved path is relative to.
    let (host, port) = match tree.server.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => {
            (host.to_string(), port.parse().expect("checked"))
        }
        _ => (tree.server.clone(), target.port),
    };
    let canonical = Target {
        host,
        port,
        share: tree.share_name.clone(),
        ..target.with_path(&resolved.path)
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "target": canonical.display(),
                "share": canonical.share,
                "path": resolved.path,
                "isDirectory": resolved.info.is_directory,
            }))?
        );
    } else {
        println!("{}", canonical.display());
    }

    let _ = client.disconnect_share(&tree).await;
    Ok(())
}

pub async fn df(target: &Target, credentials: &Credentials, as_json: bool) -> Result<()> {
    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let info = client
        .fs_info(&mut tree)
        .await
        .with_context(|| format!("querying {}", target.display()))?;
    let used = info.total_bytes.saturating_sub(info.total_free_bytes);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "share": target.share,
                "totalBytes": info.total_bytes,
                "usedBytes": used,
                "freeBytes": info.free_bytes,
                "totalFreeBytes": info.total_free_bytes,
                "bytesPerSector": info.bytes_per_sector,
                "sectorsPerUnit": info.sectors_per_unit,
            }))?
        );
    } else {
        let percent = if info.total_bytes == 0 {
            0.0
        } else {
            used as f64 * 100.0 / info.total_bytes as f64
        };
        println!("Share:     {}", target.share);
        println!("Total:     {}", output::human_bytes(info.total_bytes));
        println!("Used:      {} ({percent:.0}%)", output::human_bytes(used));
        println!("Available: {}", output::human_bytes(info.free_bytes));
    }

    let _ = client.disconnect_share(&tree).await;
    Ok(())
}

pub async fn shares(host: &str, port: u16, credentials: &Credentials, as_json: bool) -> Result<()> {
    let addr = format!("{host}:{port}");
    let mut client = credentials
        .connect(&addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    let shares = client
        .list_shares()
        .await
        .with_context(|| format!("listing shares on {addr}"))?;

    if as_json {
        let items: Vec<_> = shares
            .iter()
            .map(|share| {
                json!({ "name": share.name, "type": share.share_type, "comment": share.comment })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        for share in &shares {
            if share.comment.is_empty() {
                println!("{}", share.name);
            } else {
                println!("{:<20} {}", share.name, share.comment);
            }
        }
    }
    Ok(())
}
