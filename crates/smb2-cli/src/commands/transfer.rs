//! Moving bytes between the share and the local machine: `cat`, `get`, `put`.

use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use smb2::{SmbClient, Tree};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::auth::Credentials;
use crate::pool;
use crate::remote::{self, RemoteKind};
use crate::target::Target;

pub async fn cat(target: &Target, credentials: &Credentials) -> Result<()> {
    let (mut client, tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let mut stdout = tokio::io::stdout();
    download(&mut client, &tree, target, &mut stdout).await?;
    stdout.flush().await.context("writing to stdout")?;
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

    let (mut client, tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let mut file = tokio::fs::File::create(&destination)
        .await
        .with_context(|| format!("writing {}", destination.display()))?;
    let received = download(&mut client, &tree, target, &mut file).await?;
    file.flush()
        .await
        .with_context(|| format!("writing {}", destination.display()))?;
    println!(
        "Downloaded {} bytes to {}",
        crate::output::bytes(received),
        destination.display()
    );
    let _ = client.disconnect_share(&tree).await;
    Ok(())
}

/// Bytes to keep in flight while a download runs.
///
/// Each positioned read is one wire READ of the server's `MaxReadSize`, so this
/// budget divided by that size gives the window: 32 reads of 64 KB against a
/// server with a small cap, two of 8 MB against a generous one. Either way it,
/// and not the file's size, is what a download costs in memory.
const IN_FLIGHT_BYTES: u64 = 16 * 1024 * 1024;

/// Ceiling on the window, so a server advertising a tiny `MaxReadSize` doesn't
/// turn the budget into thousands of outstanding requests. Matches the depth
/// the library's own pipelined read uses.
const MAX_IN_FLIGHT_READS: u64 = 32;

/// Reads `target` off the share and writes it to `sink`, returning the byte
/// count.
///
/// Reads run in a sliding window and each chunk goes out to `sink` as it lands,
/// so a download costs [`IN_FLIGHT_BYTES`] of memory whatever the file weighs.
/// That bound is the point: `get` and `cat` used to ask for the whole file in a
/// single READ, which held all of it in memory and, past the server's
/// `MaxReadSize` (8 MB on a stock Samba), could not be answered at all -- a
/// 12 MB download failed outright.
///
/// The cost is that a small file now takes three round trips (open, read,
/// close) where a compound CREATE+READ+CLOSE took one. Trying the compound
/// first isn't the way to win it back: the server answers that READ with a full
/// `MaxReadSize` of data before the client can see the file is too big, so
/// every large download would pull 8 MB it throws away.
async fn download<W: AsyncWrite + Unpin>(
    client: &mut SmbClient,
    tree: &Tree,
    target: &Target,
    sink: &mut W,
) -> Result<u64> {
    let chunk = u64::from(
        client
            .params()
            .map(|params| params.max_read_size)
            .unwrap_or(65_536),
    )
    .max(1);
    let window = (IN_FLIGHT_BYTES / chunk).clamp(2, MAX_IN_FLIGHT_READS) as usize;

    let reader = Arc::new(
        client
            .open_file_reader(tree, &target.path)
            .await
            .with_context(|| format!("reading {}", target.display()))?,
    );
    let size = reader.size();

    let mut in_flight: VecDeque<tokio::task::JoinHandle<smb2::Result<Vec<u8>>>> = VecDeque::new();
    let mut offset = 0u64;
    let mut received = 0u64;
    let mut failure: Option<anyhow::Error> = None;

    loop {
        while in_flight.len() < window && offset < size {
            let reader = Arc::clone(&reader);
            let at = offset;
            offset += chunk;
            in_flight.push_back(tokio::spawn(async move { reader.read_at(at, chunk).await }));
        }
        let Some(next) = in_flight.pop_front() else {
            break;
        };
        let data = match next.await {
            Ok(Ok(data)) => data,
            Ok(Err(error)) => {
                failure = Some(
                    anyhow::Error::new(error).context(format!("reading {}", target.display())),
                );
                break;
            }
            Err(joined) => {
                failure = Some(anyhow::Error::new(joined).context("a download task failed"));
                break;
            }
        };
        if let Err(error) = sink.write_all(&data).await {
            failure = Some(anyhow::Error::new(error).context("writing the downloaded bytes"));
            break;
        }
        received += data.len() as u64;
    }

    // Whatever is still in flight has to finish before the reader is ours alone
    // again, and the handle has to be closed explicitly: dropping a `FileReader`
    // leaks the server-side handle until the session goes away.
    while let Some(pending) = in_flight.pop_front() {
        let _ = pending.await;
    }
    if let Ok(reader) = Arc::try_unwrap(reader) {
        let _ = reader.close().await;
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(received),
    }
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
        let remote_path = upload_path(target, None, source_name)?;
        println!(
            "put {} {}",
            source.display(),
            target.with_path(&remote_path).display()
        );
        println!("Would have uploaded {} bytes.", crate::output::bytes(size));
        return Ok(());
    }

    let size = tokio::fs::metadata(source)
        .await
        .with_context(|| format!("reading {}", source.display()))?
        .len();

    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let kind = remote_kind(&mut client, &mut tree, target, &target.path).await?;
    let remote_path = upload_path(target, Some(kind), source_name)?;
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

    let written = upload(&mut client, &mut tree, source, &remote_path, size)
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

/// Writes `source` to `remote_path`, returning the byte count the server
/// acknowledged.
///
/// A file that fits in one WRITE goes up as a single compound
/// CREATE+WRITE+FLUSH+CLOSE, which is one round trip and worth keeping for the
/// common case of uploading something small. Anything larger is pulled off disk
/// a chunk at a time and fed to the library's pipelined streaming write, so the
/// memory an upload costs is the pipeline's window rather than the file: this
/// path has carried a 2.35 GB video, which the old `tokio::fs::read` held in
/// full before a single byte went out.
async fn upload(
    client: &mut SmbClient,
    tree: &mut Tree,
    source: &Path,
    remote_path: &str,
    size: u64,
) -> Result<u64> {
    let chunk = client
        .params()
        .map(|params| params.max_write_size)
        .unwrap_or(65_536)
        .max(1);

    if size <= u64::from(chunk) {
        let data = tokio::fs::read(source)
            .await
            .with_context(|| format!("reading {}", source.display()))?;
        return Ok(client.write_file(tree, remote_path, &data).await?);
    }

    let mut file =
        std::fs::File::open(source).with_context(|| format!("reading {}", source.display()))?;
    let mut next_chunk = || {
        let mut buffer = vec![0u8; chunk as usize];
        let mut filled = 0;
        // `read` is free to return short, and does on a pipe or a network
        // filesystem, so fill the buffer rather than treating the first short
        // read as the end of the file.
        while filled < buffer.len() {
            match file.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Some(Err(error)),
            }
        }
        if filled == 0 {
            return None;
        }
        buffer.truncate(filled);
        Some(Ok(buffer))
    };
    Ok(client
        .write_file_streamed(tree, remote_path, &mut next_chunk)
        .await?)
}

/// Where `put` should write, given what the target names and what's already
/// there. Follows `cp`: a target that ends in a separator, or that is an
/// existing directory, takes the source's file name inside it.
fn upload_path(target: &Target, kind: Option<RemoteKind>, source_name: &str) -> Result<String> {
    // The share root is a directory whether or not it was spelled with a
    // trailing separator.
    let into_directory = if target.path.is_empty() || kind == Some(RemoteKind::Directory) {
        true
    } else if target.trailing_slash {
        match kind {
            Some(RemoteKind::File) => bail!(
                "{} is a file, not a directory, so {source_name} can't go inside it",
                target.display()
            ),
            Some(RemoteKind::Missing) => bail!(
                "{} doesn't exist on the share, so {source_name} can't go inside it; \
                 create it first with `smb2 mkdir -p`",
                target.display()
            ),
            // A dry run makes no connection, so it reports what the trailing
            // separator asked for.
            None => true,
            Some(RemoteKind::Directory) => unreachable!("handled above"),
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

/// What the server has at `path`, named the way the CLI was asked for it, so
/// `put` can tell a directory from a file before it writes.
async fn remote_kind(
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    path: &str,
) -> Result<RemoteKind> {
    remote::kind(client, tree, path)
        .await
        .with_context(|| format!("checking what's at {}", target.with_path(path).display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(path: &str) -> Target {
        Target::parse(&format!("//host/share/{path}")).unwrap()
    }

    #[test]
    fn puts_a_file_into_a_target_written_with_a_trailing_separator() {
        let path = upload_path(&target("inbox/"), Some(RemoteKind::Directory), "a.jpg").unwrap();
        assert_eq!(path, "inbox/a.jpg");
    }

    #[test]
    fn puts_a_file_into_a_target_that_is_already_a_directory() {
        let path = upload_path(&target("inbox"), Some(RemoteKind::Directory), "a.jpg").unwrap();
        assert_eq!(path, "inbox/a.jpg");
    }

    #[test]
    fn puts_a_file_into_the_share_root() {
        let path = upload_path(&target(""), Some(RemoteKind::Directory), "a.jpg").unwrap();
        assert_eq!(path, "a.jpg");
    }

    #[test]
    fn treats_a_plain_target_as_the_destination_name() {
        let path = upload_path(&target("inbox/b.jpg"), Some(RemoteKind::Missing), "a.jpg").unwrap();
        assert_eq!(path, "inbox/b.jpg");
        let overwrite =
            upload_path(&target("inbox/b.jpg"), Some(RemoteKind::File), "a.jpg").unwrap();
        assert_eq!(overwrite, "inbox/b.jpg");
    }

    #[test]
    fn refuses_a_directory_target_that_is_really_a_file() {
        let error = upload_path(&target("notes.txt/"), Some(RemoteKind::File), "a.jpg")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a directory"), "{error}");
    }

    #[test]
    fn refuses_a_directory_target_that_isnt_there() {
        let error = upload_path(&target("inbox/"), Some(RemoteKind::Missing), "a.jpg")
            .unwrap_err()
            .to_string();
        assert!(error.contains("doesn't exist"), "{error}");
    }

    #[test]
    fn plans_for_a_directory_when_a_dry_run_cannot_ask() {
        let path = upload_path(&target("inbox/"), None, "a.jpg").unwrap();
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
