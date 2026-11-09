//! Moving bytes between the share and the local machine: `cat`, `get`, `put`.
//!
//! All three carry on after a dropped connection: they reconnect and pick up
//! from the last byte the library vouches for, so a Wi-Fi blip costs a pause
//! rather than the whole transfer. See § Resuming after a dropped connection
//! in this crate's `CLAUDE.md`.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use smb2::{
    DownloadCheckpoint, ErrorKind, FileDownload, RenameOptions, SmbClient, Tree, WriteCheckpoint,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use crate::auth::Credentials;
use crate::pool;
use crate::remote::{self, RemoteKind};
use crate::target::Target;

pub async fn cat(target: &Target, credentials: &Credentials) -> Result<()> {
    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let download = Download::open(&mut client, &tree, target).await?;
    let mut stdout = tokio::io::stdout();
    download
        .pump(&mut client, &mut tree, target, &mut stdout)
        .await?;
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

    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");

    // Open the remote file before touching anything local, and land the bytes
    // on a sibling path that's renamed into place only once the whole transfer
    // has succeeded. A download that fails then leaves the destination exactly
    // as it found it -- which for `get` means an earlier copy of the file
    // survives a failed re-download instead of being truncated to nothing.
    let download = Download::open(&mut client, &tree, target).await?;
    let partial = partial_path(&destination);
    let received = write_to_partial(download, &mut client, &mut tree, target, &partial).await;
    let received = match received {
        Ok(received) => received,
        Err(error) => {
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(error);
        }
    };
    tokio::fs::rename(&partial, &destination)
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

/// Where a download lands while it's still in progress: alongside the
/// destination, so the rename that finishes it stays on one filesystem and is
/// therefore atomic.
fn partial_path(destination: &Path) -> PathBuf {
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(PARTIAL_SUFFIX);
    destination.with_file_name(name)
}

/// What a transfer's in-progress copy is called, locally for `get` and on the
/// share for `put`.
const PARTIAL_SUFFIX: &str = ".smb2-part";

async fn write_to_partial(
    download: Download,
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    partial: &Path,
) -> Result<u64> {
    let mut file = tokio::fs::File::create(partial)
        .await
        .with_context(|| format!("writing {}", partial.display()))?;
    let received = download.pump(client, tree, target, &mut file).await?;
    file.flush()
        .await
        .with_context(|| format!("writing {}", partial.display()))?;
    Ok(received)
}

/// A file on the share, open and ready to be read.
///
/// Opening is separate from reading so a caller can find out the transfer will
/// work before it creates anything locally. `get` depends on that: a download
/// that fails must leave the destination alone.
struct Download {
    inner: FileDownload<'static>,
}

impl Download {
    async fn open(client: &mut SmbClient, tree: &Tree, target: &Target) -> Result<Self> {
        let inner = client
            .open_file_download(tree, &target.path)
            .await
            .with_context(|| format!("reading {}", target.display()))?;
        Ok(Self { inner })
    }

    /// Reads the whole file into `sink`, returning the byte count.
    ///
    /// The library's `FileDownload` paces its READs to the link and hands
    /// chunks out in file order, so a download costs a few MiB of memory
    /// whatever the file weighs, and a `stat` on the same connection never
    /// queues behind much of it.
    ///
    /// In file order is also what makes a resume possible: the checkpoint is
    /// exactly the bytes handed to `sink`, so after a dropped connection the
    /// download reopens the file, proves it's the version it was reading
    /// (`Error::FileChanged` otherwise), and carries on from there. Nothing
    /// written to `sink` is ever written twice, which is what lets `cat` resume
    /// into a pipe.
    ///
    /// The cost is that a small file takes three round trips (open, read,
    /// close) where a compound CREATE+READ+CLOSE took one. Trying the compound
    /// first isn't the way to win it back: the server answers that READ with a
    /// full `MaxReadSize` of data before the client can see the file is too
    /// big, so every large download would pull 8 MB it throws away.
    async fn pump<W: AsyncWrite + Unpin>(
        self,
        client: &mut SmbClient,
        tree: &mut Tree,
        target: &Target,
        sink: &mut W,
    ) -> Result<u64> {
        let reading = || format!("reading {}", target.display());
        let mut download = self.inner;
        let mut resumes = Resumes::new();
        let mut received = 0u64;
        loop {
            let mut error = match download.next_chunk().await {
                None => return Ok(received),
                Some(Ok(data)) => {
                    sink.write_all(&data)
                        .await
                        .context("writing the downloaded bytes")?;
                    received += data.len() as u64;
                    continue;
                }
                Some(Err(error)) => error,
            };
            let checkpoint: DownloadCheckpoint = download
                .checkpoint()
                .expect("a download opened from a path hands out a checkpoint");
            // The checkpoint counts what `next_chunk` handed out, and so does
            // `received`. If they ever disagree, resuming would duplicate or
            // skip bytes in the sink, so stop rather than corrupt the copy.
            if checkpoint.offset != received {
                bail!(
                    "{}: the download vouches for {} bytes but {received} reached the destination",
                    reading(),
                    checkpoint.offset
                );
            }
            drop(download);
            download = loop {
                resumes
                    .recover(client, tree, target, error, received)
                    .await
                    .with_context(reading)?;
                match client.resume_download(tree, &checkpoint).await {
                    Ok(resumed) => break resumed,
                    Err(next) => error = next,
                }
            };
        }
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

    // The bytes land on a sibling first and are renamed over the destination
    // only once every one of them is on the share, the way `get` does it
    // locally. An upload that fails then leaves an earlier copy of the file
    // exactly as it was, where writing in place truncated it first.
    let partial = format!("{remote_path}{PARTIAL_SUFFIX}");
    let uploaded = async {
        let written = upload(&mut client, &mut tree, target, source, &partial, size).await?;
        move_into_place(
            &mut client,
            &mut tree,
            target,
            &partial,
            &remote_path,
            written,
        )
        .await?;
        Ok::<_, anyhow::Error>(written)
    }
    .await;
    let written = match uploaded {
        Ok(written) => written,
        Err(error) => {
            discard_partial_upload(&mut client, &mut tree, target, &partial).await;
            return Err(error.context(format!(
                "writing {}",
                target.with_path(&remote_path).display()
            )));
        }
    };
    println!(
        "Uploaded {} bytes to {}",
        crate::output::bytes(written),
        target.with_path(&remote_path).display()
    );
    let _ = client.disconnect_share(&tree).await;
    Ok(())
}

/// How often a large upload takes a checkpoint: drains its WRITEs, FLUSHes,
/// and records how far the share now holds the file. A dropped connection
/// resumes from the last one, so this is the most an upload re-sends after a
/// drop. Each checkpoint costs about a round trip plus the server's fsync, a
/// few percent of a fast link's time at this spacing.
const CHECKPOINT_EVERY: u64 = 64 * 1024 * 1024;

/// How much a large upload reads off the local disk at a time. The writer
/// slices it into WRITEs of its own size, so this only sets how often the
/// disk is asked.
const READ_CHUNK: usize = 1024 * 1024;

/// Writes `source` to `path` on the share, returning the byte count.
///
/// A file that fits in one WRITE goes up as a single compound
/// CREATE+WRITE+FLUSH plus a CLOSE, two round trips and worth keeping for the
/// common case of uploading something small; after a dropped connection it's
/// simply sent again. Anything larger streams through a `FileWriter`, read off
/// disk a chunk at a time, so the memory an upload costs is the writer's window
/// rather than the file: this path has carried a 2.35 GB video.
async fn upload(
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    source: &Path,
    path: &str,
    size: u64,
) -> Result<u64> {
    let max_write = client
        .params()
        .map(|params| params.max_write_size)
        .unwrap_or(65_536)
        .max(1);
    let mut resumes = Resumes::new();

    if size <= u64::from(max_write) {
        let data = tokio::fs::read(source)
            .await
            .with_context(|| format!("reading {}", source.display()))?;
        loop {
            match client.write_file(tree, path, &data).await {
                Ok(written) => return Ok(written),
                Err(error) => resumes.recover(client, tree, target, error, 0).await?,
            }
        }
    }

    let mut file = tokio::fs::File::open(source)
        .await
        .with_context(|| format!("reading {}", source.display()))?;
    let mut checkpoint: Option<WriteCheckpoint> = None;
    loop {
        let error = match stream_upload(client, tree, path, &mut file, &mut checkpoint).await {
            Ok(written) => return Ok(written),
            Err(UploadFailure::Local(error)) => {
                return Err(error).with_context(|| format!("reading {}", source.display()))
            }
            Err(UploadFailure::Remote(error)) => error,
        };
        // The partial file is ours alone, so one that can't be resumed (gone,
        // or replaced by someone else meanwhile) is simply started again.
        if error.kind() == ErrorKind::ResumeRefused {
            eprintln!("Couldn't resume ({error}); starting the upload again.");
            checkpoint = None;
            resumes.spend(error)?;
            continue;
        }
        let at = checkpoint.map_or(0, |checkpoint| checkpoint.offset);
        resumes.recover(client, tree, target, error, at).await?;
    }
}

/// Why one attempt at a streamed upload stopped.
enum UploadFailure {
    /// Reading the source failed: nothing a reconnect can help with.
    Local(std::io::Error),
    /// The share or the connection failed, and maybe a reconnect helps.
    Remote(smb2::Error),
}

/// One attempt at a streamed upload: from `checkpoint` if there is one
/// (proven by the library to still be the file it names), else from the
/// start. Leaves the latest checkpoint in `checkpoint`, so a failed attempt
/// tells the next one where to pick up.
async fn stream_upload(
    client: &mut SmbClient,
    tree: &Tree,
    path: &str,
    file: &mut tokio::fs::File,
    checkpoint: &mut Option<WriteCheckpoint>,
) -> std::result::Result<u64, UploadFailure> {
    let mut writer = match checkpoint {
        Some(checkpoint) => client.resume_file_writer(tree, path, checkpoint).await,
        None => client.create_file_writer(tree, path).await,
    }
    .map_err(UploadFailure::Remote)?;
    let mut offset = checkpoint.map_or(0, |checkpoint| checkpoint.offset);
    file.seek(SeekFrom::Start(offset))
        .await
        .map_err(UploadFailure::Local)?;

    let mut buffer = vec![0u8; READ_CHUNK];
    let mut since_checkpoint = 0u64;
    loop {
        let read = read_full(file, &mut buffer)
            .await
            .map_err(UploadFailure::Local)?;
        if read == 0 {
            break;
        }
        writer
            .write_chunk(&buffer[..read])
            .await
            .map_err(UploadFailure::Remote)?;
        offset += read as u64;
        since_checkpoint += read as u64;
        if since_checkpoint >= CHECKPOINT_EVERY {
            *checkpoint = Some(
                writer
                    .flush_checkpoint()
                    .await
                    .map_err(UploadFailure::Remote)?,
            );
            since_checkpoint = 0;
        }
    }
    // A writer dropped by an error above closes its handle on the way out
    // (on a dead session that sends nothing), so only success needs this.
    writer.finish().await.map_err(UploadFailure::Remote)?;
    Ok(offset)
}

/// Fills `buffer` from `reader`, short only at the end of the file. `read` is
/// free to return short, and does on a pipe or a network filesystem, so the
/// first short read can't be taken as the end.
async fn read_full<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]).await {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Renames the finished upload over `destination` in one step, so the name is
/// never missing and never holds half a file.
///
/// A rename whose answer was lost with the connection may have happened
/// anyway, so after a reconnect a missing `partial` with a file of the right
/// size at `destination` is that rename having worked.
async fn move_into_place(
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    partial: &str,
    destination: &str,
    size: u64,
) -> Result<()> {
    let replace = RenameOptions::new().replace_if_exists(true);
    let mut resumes = Resumes::new();
    let mut retried = false;
    loop {
        let error = match client
            .rename_with(tree, partial, destination, replace)
            .await
        {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if retried && error.kind() == ErrorKind::NotFound {
            if let Ok(info) = client.stat(tree, destination).await {
                if !info.is_directory && info.size == size {
                    return Ok(());
                }
            }
        }
        resumes
            .recover(client, tree, target, error, size)
            .await
            .context("moving the upload into place")?;
        retried = true;
    }
}

/// Best effort: deletes a failed upload's partial file, reconnecting once if
/// the connection is what failed, and says so when it can't.
async fn discard_partial_upload(
    client: &mut SmbClient,
    tree: &mut Tree,
    target: &Target,
    partial: &str,
) {
    let mut deleted = client.delete_file(tree, partial).await;
    if matches!(&deleted, Err(error) if error.is_retryable())
        && revive(client, tree, target).await.is_ok()
    {
        deleted = client.delete_file(tree, partial).await;
    }
    match deleted {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => eprintln!(
            "Couldn't remove the partial upload {}: {error}",
            target.with_path(partial).display()
        ),
    }
}

/// How many times one transfer picks up after a dropped connection before
/// giving up. Each reconnect is bounded on its own by the library's
/// `ReconnectPolicy` (about a minute), so this bounds a transfer over a link
/// that keeps dropping, not one that's down.
const MAX_RESUMES: u32 = 5;

/// How long to wait out a file the dead session still holds, in steps of
/// `BUSY_WAIT`. A writer shares nothing, and a server learns that a session
/// died only when it notices the old socket is gone: at once for a clean
/// close, later for a link that just went quiet. Signing in again names the
/// old session (`PreviousSessionId`), which makes Samba let go of it straight
/// away for a named login but not for a guest one.
const MAX_BUSY_WAITS: u32 = 15;
const BUSY_WAIT: Duration = Duration::from_secs(2);

/// What a transfer has left to spend on dropped connections.
struct Resumes {
    left: u32,
    busy_waits_left: u32,
    /// Whether this transfer has reconnected, which is the only time a
    /// sharing violation means the old session still holds our file.
    revived: bool,
}

impl Resumes {
    fn new() -> Self {
        Self {
            left: MAX_RESUMES,
            busy_waits_left: MAX_BUSY_WAITS,
            revived: false,
        }
    }

    /// Spends one resume on `error`, or hands it back when none are left.
    fn spend(&mut self, error: smb2::Error) -> Result<()> {
        if self.left == 0 {
            return Err(error).context(format!(
                "gave up after {MAX_RESUMES} reconnects in one transfer"
            ));
        }
        self.left -= 1;
        Ok(())
    }

    /// Decides what `error` means for a transfer `at` bytes in, and gets the
    /// transfer ready to try again: a reconnect for a lost connection, a
    /// pause for a file the dead session still holds. Anything else, or a
    /// transfer out of resumes, is the error itself.
    ///
    /// Any retryable error reconnects, not only a lost connection: a resume
    /// is proven safe by the library whatever the state of the old session,
    /// and a fresh one is the surest way past a timeout or a credit stall.
    async fn recover(
        &mut self,
        client: &mut SmbClient,
        tree: &mut Tree,
        target: &Target,
        error: smb2::Error,
        at: u64,
    ) -> Result<()> {
        if self.revived && error.kind() == ErrorKind::SharingViolation && self.busy_waits_left > 0 {
            self.busy_waits_left -= 1;
            tokio::time::sleep(BUSY_WAIT).await;
            return Ok(());
        }
        if !error.is_retryable() {
            return Err(error.into());
        }
        let shown = error.to_string();
        self.spend(error)?;
        eprintln!(
            "Lost the connection at {} bytes ({shown}); reconnecting...",
            crate::output::bytes(at)
        );
        revive(client, tree, target)
            .await
            .with_context(|| format!("the connection dropped ({shown}) and couldn't be revived"))?;
        self.revived = true;
        eprintln!("Reconnected; resuming.");
        Ok(())
    }
}

/// A fresh session on the same client, and the share connected again on it.
/// The old session's tree and handles are gone with it, so `tree` is replaced.
async fn revive(client: &mut SmbClient, tree: &mut Tree, target: &Target) -> Result<()> {
    client
        .reconnect()
        .await
        .with_context(|| format!("reconnecting to {}", target.addr()))?;
    *tree = client
        .connect_share(&target.share)
        .await
        .with_context(|| format!("connecting to share {:?}", target.share))?;
    Ok(())
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
