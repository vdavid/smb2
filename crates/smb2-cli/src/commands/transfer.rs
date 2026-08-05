//! Moving bytes between the share and the local machine: `cat`, `get`, `put`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;

use crate::auth::Credentials;
use crate::pool;
use crate::target::Target;

pub async fn cat(target: &Target, credentials: &Credentials) -> Result<()> {
    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let data = client
        .read_file(&mut tree, &target.path)
        .await
        .with_context(|| format!("reading {}", target.display()))?;
    tokio::io::stdout()
        .write_all(&data)
        .await
        .context("writing to stdout")?;
    let _ = client.disconnect_share(&tree).await;
    Ok(())
}

pub async fn get(
    target: &Target,
    credentials: &Credentials,
    destination: Option<&str>,
) -> Result<()> {
    let destination = match destination {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(
            target
                .path
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .context("no file name in the target; pass a destination")?,
        ),
    };
    let destination = if destination.is_dir() {
        destination.join(
            target
                .path
                .rsplit('/')
                .next()
                .context("no file name in the target")?,
        )
    } else {
        destination
    };

    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let data = client
        .read_file(&mut tree, &target.path)
        .await
        .with_context(|| format!("reading {}", target.display()))?;
    tokio::fs::write(&destination, &data)
        .await
        .with_context(|| format!("writing {}", destination.display()))?;
    println!(
        "Downloaded {} bytes to {}",
        crate::output::bytes(data.len() as u64),
        destination.display()
    );
    let _ = client.disconnect_share(&tree).await;
    Ok(())
}

pub async fn put(source: &Path, target: &Target, credentials: &Credentials) -> Result<()> {
    let data = tokio::fs::read(source)
        .await
        .with_context(|| format!("reading {}", source.display()))?;
    let remote_path = if target.path.is_empty() || target.path.ends_with('/') {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .context("the source has no file name")?;
        format!("{}/{name}", target.path.trim_end_matches('/'))
            .trim_start_matches('/')
            .to_string()
    } else {
        target.path.clone()
    };

    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let written = client
        .write_file(&mut tree, &remote_path, &data)
        .await
        .with_context(|| format!("writing {}", target.with_path(&remote_path).display()))?;
    println!(
        "Uploaded {} bytes to {}",
        crate::output::bytes(written),
        target.with_path(&remote_path).display()
    );
    let _ = client.disconnect_share(&tree).await;
    Ok(())
}
