//! Read-only commands: `ls`, `stat`, `df`, and `shares`.

use anyhow::{Context, Result};
use serde_json::json;

use crate::auth::Credentials;
use crate::output;
use crate::pool::{self, Job, Outcome};
use crate::target::Target;

pub async fn ls(
    target: &Target,
    credentials: &Credentials,
    long: bool,
    recursive: bool,
    as_json: bool,
) -> Result<()> {
    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");

    let mut pending = vec![target.path.clone()];
    let mut rows = Vec::new();
    while let Some(path) = pending.pop() {
        let entries = client
            .list_directory(&mut tree, &path)
            .await
            .with_context(|| format!("listing {}", target.with_path(&path).display()))?;
        for entry in entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let full = if path.is_empty() {
                entry.name.clone()
            } else {
                format!("{path}/{}", entry.name)
            };
            if recursive && entry.is_directory {
                pending.push(full.clone());
            }
            rows.push((full, entry));
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    if as_json {
        let items: Vec<_> = rows
            .iter()
            .map(|(path, entry)| {
                json!({
                    "path": path,
                    "name": entry.name,
                    "isDirectory": entry.is_directory,
                    "size": entry.size,
                    "modified": output::unix_seconds(entry.modified),
                    "created": output::unix_seconds(entry.created),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        for (path, entry) in &rows {
            let name = if recursive { path } else { &entry.name };
            if long {
                println!(
                    "{}  {:>15}  {}  {}",
                    if entry.is_directory { "d" } else { "-" },
                    output::bytes(entry.size),
                    output::timestamp(entry.modified),
                    name,
                );
            } else {
                println!("{name}");
            }
        }
    }

    let _ = client.disconnect_share(&tree).await;
    Ok(())
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
                        "size": info.size,
                        "modified": output::unix_seconds(info.modified),
                        "created": output::unix_seconds(info.created),
                        "accessed": output::unix_seconds(info.accessed),
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
    let mut client = smb2::connect(&addr, &credentials.username, &credentials.password)
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
