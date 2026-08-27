//! Moving bytes between the share and the local machine: `cat`, `get`, `put`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use smb2::types::status::NtStatus;
use smb2::{SmbClient, Tree};
use tokio::io::AsyncWriteExt;

use crate::auth::Credentials;
use crate::pool;
use crate::target::Target;

/// What's already sitting at a path on the share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteKind {
    Missing,
    File,
    Directory,
    /// A dry run makes no connection, so it can't ask the server.
    Unknown,
}

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
    dry_run: bool,
) -> Result<()> {
    let destination = download_path(destination, &target.path)?;
    if dry_run {
        println!("get {} {}", target.display(), destination.display());
        println!("Would have downloaded 1 file.");
        return Ok(());
    }

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

/// Where `get` should write. A destination that's an existing local directory,
/// or that's written with a trailing separator, takes the remote file's name
/// inside it; anything else is the file to write.
fn download_path(destination: Option<&str>, remote_path: &str) -> Result<PathBuf> {
    let name = remote_file_name(remote_path)?;
    let Some(destination) = destination else {
        return Ok(PathBuf::from(name));
    };
    let path = PathBuf::from(destination);
    if path.is_dir() {
        return Ok(path.join(name));
    }
    if destination.ends_with('/') || destination.ends_with(std::path::MAIN_SEPARATOR) {
        bail!("{destination} is not a directory, so there's nowhere to put {name}");
    }
    Ok(path)
}

/// The last segment of a path inside the share.
fn remote_file_name(remote_path: &str) -> Result<&str> {
    remote_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .context("no file name in the target; pass a destination")
}

pub async fn put(
    source: &Path,
    target: &Target,
    credentials: &Credentials,
    dry_run: bool,
) -> Result<()> {
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .context("the source has no file name")?;

    if dry_run {
        let size = tokio::fs::metadata(source)
            .await
            .with_context(|| format!("reading {}", source.display()))?
            .len();
        // No connection, so the server can't be asked whether the target is a
        // directory: a trailing separator is all there is to go on.
        let remote_path = upload_path(target, RemoteKind::Unknown, source_name)?;
        println!(
            "put {} {}",
            source.display(),
            target.with_path(&remote_path).display()
        );
        println!("Would have uploaded {} bytes.", crate::output::bytes(size));
        return Ok(());
    }

    let data = tokio::fs::read(source)
        .await
        .with_context(|| format!("reading {}", source.display()))?;

    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let kind = remote_kind(&mut client, &mut tree, target, &target.path).await?;
    let remote_path = upload_path(target, kind, source_name)?;
    // Appending the source's name can still land on a directory of its own, and
    // an upload must never replace one.
    if remote_path != target.path {
        let destination = target.with_path(&remote_path);
        if remote_kind(&mut client, &mut tree, target, &remote_path).await? == RemoteKind::Directory
        {
            bail!(
                "{} is a directory; move it or rename the source instead of overwriting it",
                destination.display()
            );
        }
    }

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

/// Where `put` should write, given what the target names and what's already
/// there. Follows `cp`: a target that ends in a separator, or that is an
/// existing directory, takes the source's file name inside it.
fn upload_path(target: &Target, kind: RemoteKind, source_name: &str) -> Result<String> {
    // The share root is a directory whether or not it was spelled with a
    // trailing separator.
    let into_directory = if target.path.is_empty() || kind == RemoteKind::Directory {
        true
    } else if target.trailing_slash {
        match kind {
            RemoteKind::File => bail!(
                "{} is a file, not a directory, so {source_name} can't go inside it",
                target.display()
            ),
            RemoteKind::Missing => bail!(
                "{} doesn't exist on the share, so {source_name} can't go inside it; \
                 create it first with `smb2 mkdir -p`",
                target.display()
            ),
            // A dry run reports what the trailing separator asked for.
            RemoteKind::Unknown => true,
            RemoteKind::Directory => unreachable!("handled above"),
        }
    } else {
        false
    };

    if !into_directory {
        return Ok(target.path.clone());
    }
    Ok(if target.path.is_empty() {
        source_name.to_string()
    } else {
        format!("{}/{source_name}", target.path)
    })
}

/// What the server has at `path`, so `put` can tell a directory from a file
/// before it writes. Only a clean "it isn't there" counts as missing; any other
/// error stops the upload, since guessing wrong means clobbering a directory.
async fn remote_kind(
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    path: &str,
) -> Result<RemoteKind> {
    if path.is_empty() {
        return Ok(RemoteKind::Directory);
    }
    match client.stat(tree, path).await {
        Ok(info) if info.is_directory => Ok(RemoteKind::Directory),
        Ok(_) => Ok(RemoteKind::File),
        Err(error) if is_not_found(&error) => Ok(RemoteKind::Missing),
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("checking what's at {}", target.with_path(path).display())),
    }
}

fn is_not_found(error: &smb2::Error) -> bool {
    matches!(
        error.status(),
        Some(NtStatus::OBJECT_NAME_NOT_FOUND)
            | Some(NtStatus::OBJECT_PATH_NOT_FOUND)
            | Some(NtStatus::NO_SUCH_FILE)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(path: &str) -> Target {
        Target::parse(&format!("//host/share/{path}")).unwrap()
    }

    #[test]
    fn puts_a_file_into_a_target_written_with_a_trailing_separator() {
        let path = upload_path(&target("inbox/"), RemoteKind::Directory, "a.jpg").unwrap();
        assert_eq!(path, "inbox/a.jpg");
    }

    #[test]
    fn puts_a_file_into_a_target_that_is_already_a_directory() {
        let path = upload_path(&target("inbox"), RemoteKind::Directory, "a.jpg").unwrap();
        assert_eq!(path, "inbox/a.jpg");
    }

    #[test]
    fn puts_a_file_into_the_share_root() {
        let path = upload_path(&target(""), RemoteKind::Directory, "a.jpg").unwrap();
        assert_eq!(path, "a.jpg");
    }

    #[test]
    fn treats_a_plain_target_as_the_destination_name() {
        let path = upload_path(&target("inbox/b.jpg"), RemoteKind::Missing, "a.jpg").unwrap();
        assert_eq!(path, "inbox/b.jpg");
        let overwrite = upload_path(&target("inbox/b.jpg"), RemoteKind::File, "a.jpg").unwrap();
        assert_eq!(overwrite, "inbox/b.jpg");
    }

    #[test]
    fn refuses_a_directory_target_that_is_really_a_file() {
        let error = upload_path(&target("notes.txt/"), RemoteKind::File, "a.jpg")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a directory"), "{error}");
    }

    #[test]
    fn refuses_a_directory_target_that_isnt_there() {
        let error = upload_path(&target("inbox/"), RemoteKind::Missing, "a.jpg")
            .unwrap_err()
            .to_string();
        assert!(error.contains("doesn't exist"), "{error}");
    }

    #[test]
    fn plans_for_a_directory_when_a_dry_run_cannot_ask() {
        let path = upload_path(&target("inbox/"), RemoteKind::Unknown, "a.jpg").unwrap();
        assert_eq!(path, "inbox/a.jpg");
    }

    #[test]
    fn downloads_under_the_remote_name_by_default() {
        let path = download_path(None, "photos/a.jpg").unwrap();
        assert_eq!(path, PathBuf::from("a.jpg"));
    }

    #[test]
    fn downloads_to_an_explicit_local_name() {
        let path = download_path(Some("b.jpg"), "photos/a.jpg").unwrap();
        assert_eq!(path, PathBuf::from("b.jpg"));
    }

    #[test]
    fn downloads_into_a_local_directory() {
        let directory = std::env::temp_dir();
        let path = download_path(Some(directory.to_str().unwrap()), "photos/a.jpg").unwrap();
        assert_eq!(path, directory.join("a.jpg"));
    }

    #[test]
    fn refuses_a_local_directory_destination_that_isnt_there() {
        let missing = std::env::temp_dir().join("smb2-cli-no-such-directory-here");
        let error = download_path(Some(&format!("{}/", missing.display())), "photos/a.jpg")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a directory"), "{error}");
    }
}
