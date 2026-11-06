//! Opening a [`FileReader`], and reopening one after a reconnect without
//! reading on into a file that changed.
//!
//! Every reader open goes through [`open_file_reader_with`];
//! [`open_file_reader`](crate::client::stream::open_file_reader) is its
//! default-options case. A [`FileReader`] holds one handle, and a handle dies
//! with its session. A consumer that serves positioned reads for a long time
//! (a media server streaming a film, an indexer walking an archive) wants to
//! carry on after a dropped connection without either of two failures:
//! reading on into a file that has since been replaced or rewritten, mixing
//! bytes from two versions, or touching the file in any way a reader
//! shouldn't.
//!
//! ## What a reader asks for, and never more
//!
//! `FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`, opened `FileOpen`:
//! never created, never truncated, never write access, sharing read, write
//! and delete so other clients are not locked out. The durable variant adds a
//! batch oplock and the `DH2Q` context on SMB 3.x (`durable.rs`
//! `ask_for_durability`, the same dressing a durable write gets), and its
//! reclaim asks for exactly the same access (a [`DurableHandle`](crate::DurableHandle) records
//! which kind of open it came from). ❌ Don't reuse
//! [`Tree::open_file_durable`] for reading: it asks for write access and
//! creates a missing file (`FileOpenIf`).
//!
//! ## One round trip records everything a reopen checks
//!
//! The open is `resolve.rs` `open_and_name` with `OpenFor::Reading`: CREATE,
//! the two [`FileIdentity`] queries, class 18, class 48 (last, AGENTS.md
//! pitfall 31). So every reader, durable or not, carries a [`FileVersion`]
//! (length and last-write time from the CREATE, identity from the queries)
//! and its [`resolved_path`](FileReader::resolved_path). A durable reader's
//! reclaim runs the same compound, so the reader it produces keeps both too.
//!
//! ## The version check
//!
//! [`reopen_file_reader`] compares the reopened file against the recorded
//! version, identity first (a different file's length says nothing), and
//! fails with [`Error::FileChanged`] after closing what it opened.
//!
//! The identity is best-effort: a server that won't answer the queries still
//! gives a working reader, whose reopen then checks length and time alone. A
//! server that answered at open and won't at reopen fails the check, which is
//! the safe direction.
//!
//! ## Durable first, path second
//!
//! When the previous reader holds a durable handle and its session is gone,
//! the reopen reclaims that handle (two proofs, see `durable.rs`). If the
//! server no longer has it ([`Error::DurableHandleLost`]), the reopen falls
//! back to opening the path afresh. Either way the version check runs: a
//! durable handle keeps the open alive, not the bytes, and another client may
//! have written to the file while ours was disconnected.
//!
//! The durability itself is fragile by design: it rides on a batch oplock,
//! and the first other client to open the file breaks it. The connection
//! acknowledges the break at once (so that client isn't kept waiting), and
//! the acknowledgment gives the durability up on the server. A reconnect
//! after that finds nothing to reclaim and takes the path. A handle-caching
//! lease would survive other clients' opens; this crate doesn't do leases.

use std::sync::Arc;

use log::{debug, trace};

use crate::client::connection::Connection;
use crate::client::durable::{ask_for_durability, FileIdentity};
use crate::client::resolve::OpenFor;
use crate::client::stream::FileReader;
use crate::client::tree::Tree;
use crate::error::{FileChange, Result};
use crate::pack::FileTime;
use crate::Error;

/// `FILE_NON_DIRECTORY_FILE` (MS-SMB2 § 2.2.13).
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

/// How [`open_file_reader_with`] opens a file. The open is always read-only.
///
/// ```
/// let options = smb2::ReaderOptions::new().durable(true);
/// assert!(options.is_durable());
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReaderOptions {
    durable: bool,
}

impl ReaderOptions {
    /// A plain read-only open: no oplock, no durable handle. The same as
    /// [`open_file_reader`](crate::client::stream::open_file_reader).
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the server for a durable handle, so a reader whose connection
    /// drops can claim the same open back with [`reopen_file_reader`] instead
    /// of opening the path again.
    ///
    /// Only on SMB 3.x, and only granted with a batch oplock (MS-SMB2
    /// § 3.3.5.9.10). A server that declines gives an ordinary reader with
    /// [`durable_handle`](FileReader::durable_handle) `None`, never an error.
    ///
    /// ⚠️ **The durability lasts until another client opens the file.** A
    /// batch oplock is broken by any other open, and the connection
    /// acknowledges the break at once (otherwise that client waits out the
    /// server's break timeout, around 35 s), which gives the durability up.
    /// [`reopen_file_reader`] then finds nothing to reclaim and opens the path
    /// again, with the same version check, so nothing is read from a changed
    /// file either way; it just costs the reopen a fresh open. Durability that
    /// survives other readers would take a handle-caching lease, which this
    /// crate doesn't implement.
    pub fn durable(mut self, durable: bool) -> Self {
        self.durable = durable;
        self
    }

    /// Whether these options ask for a durable handle.
    pub fn is_durable(&self) -> bool {
        self.durable
    }
}

/// Which version of a file a [`FileReader`] reads: what a reopen compares to
/// tell "the same file, unchanged" from anything else.
///
/// Get one from [`FileReader::version`]. Non-exhaustive, so what a version
/// records can grow without breaking anyone reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileVersion {
    /// The file's length at open.
    pub size: u64,
    /// The file's last-write time at open.
    pub modified: FileTime,
    /// Which file it is, or `None` on a server that won't say (see
    /// [`FileIdentity`]).
    pub identity: Option<FileIdentity>,
}

impl FileVersion {
    /// How `now` differs from this version, or `None` when it is the same
    /// file with the same length and last-write time.
    ///
    /// Identity first: once it differs, the length says nothing. An identity
    /// only `now` has is ignored (there is nothing to compare it with); one
    /// only `self` has is [`FileChange::IdentityUnavailable`].
    pub(crate) fn change_to(&self, now: &FileVersion) -> Option<FileChange> {
        match (self.identity, now.identity) {
            (Some(was), Some(is)) if was != is => return Some(FileChange::Replaced),
            (Some(_), None) => return Some(FileChange::IdentityUnavailable),
            _ => {}
        }
        if self.size != now.size {
            return Some(FileChange::Size {
                was: self.size,
                now: now.size,
            });
        }
        if self.modified != now.modified {
            return Some(FileChange::Modified);
        }
        None
    }
}

/// Open a file read-only and return a [`FileReader`] that records which
/// version of the file it reads and the name the server stores it under, so
/// [`reopen_file_reader`] can carry on after a reconnect and refuse if the
/// file changed.
///
/// One round trip: the CREATE (`FileOpen`, read access only, never creating)
/// plus the identity and name queries in the same compound. A missing file is
/// the CREATE's error (`ErrorKind::NotFound`). With
/// [`ReaderOptions::durable`], the open also asks for a durable handle.
///
/// [`open_file_reader`](crate::client::stream::open_file_reader) is this with
/// the default options; [`Tree::open_file_reader_with`] and
/// [`SmbClient::open_file_reader_with`](crate::SmbClient::open_file_reader_with)
/// are the convenience wrappers.
pub async fn open_file_reader_with(
    tree: Arc<Tree>,
    conn: Connection,
    path: &str,
    options: ReaderOptions,
) -> Result<FileReader> {
    trace!(
        "stream: open_file_reader path={path:?} durable={}",
        options.durable
    );
    // Pinned before the CREATE, like every handle: the reader must never send
    // this file id into a later session.
    let mut conn = tree.pinned_conn(&conn).pinned_to_session();
    let mut request = tree.read_open_request(path);
    let asked = if options.durable {
        // A durable handle on a directory would buy an oplock for nothing.
        request.create_options = FILE_NON_DIRECTORY_FILE;
        ask_for_durability(&conn, &mut request)
    } else {
        None
    };
    let opened = tree
        .open_and_name(&mut conn, path, &request, OpenFor::Reading)
        .await?;
    let durable = asked.map(|asked| {
        tree.durability_granted(&conn, &opened.created, opened.identity, asked, path, true)
    });
    // The reader owns the handle from here, so an error below closes it on
    // drop.
    let mut reader = FileReader::opened(
        tree,
        conn,
        &opened.created,
        opened.identity,
        opened.name,
        options,
    );
    reader.durable = durable.transpose()?.flatten();
    Ok(reader)
}

/// Carry on reading after a reconnect: reopen the file `previous` was
/// reading, read-only, and check it is still the same version.
///
/// `tree` is a tree connect to the same share on the current session, and
/// `path` the path `previous` was opened at. When `previous` holds a durable
/// handle and its session is gone, the handle is reclaimed; when the server
/// no longer has it, the path is opened afresh. A `previous` whose session is
/// still current is not reclaimed (its handle is still open): the path is
/// opened again, and `previous` stays the caller's to close.
///
/// The new reader is opened with `previous`'s options, and its own
/// [`version`](FileReader::version), read fresh from the server, was checked
/// against `previous`'s. Fails with [`Error::FileChanged`] when the file is no
/// longer that version, after closing what it opened, and with the CREATE's
/// own error when the file is gone. Any other error (the network, access
/// denied) comes back as itself, so [`Error::is_retryable`] says whether to
/// try the reopen again later.
///
/// # Example
///
/// ```no_run
/// # async fn example(
/// #     client: &mut smb2::SmbClient,
/// #     share: &mut smb2::Tree,
/// #     reader: smb2::FileReader,
/// # ) -> Result<(), smb2::Error> {
/// let reader = match reader.read_at(0, 4096).await {
///     Err(e) if e.kind() == smb2::ErrorKind::ConnectionLost => {
///         let reopened = client.reopen_file_reader(share, "film.mkv", &reader).await?;
///         // Its session is gone, so this sends nothing.
///         reader.close().await?;
///         reopened
///     }
///     _ => reader,
/// };
/// # let _ = reader;
/// # Ok(())
/// # }
/// ```
pub async fn reopen_file_reader(
    tree: Arc<Tree>,
    conn: Connection,
    path: &str,
    previous: &FileReader,
) -> Result<FileReader> {
    let expected = previous.version();
    let previous_is_live = previous.pin().is_some_and(|pin| conn.pin_is_current(pin));
    if let Some(handle) = previous.durable.filter(|_| !previous_is_live) {
        let mut pinned = tree.pinned_conn(&conn).pinned_to_session();
        match tree.reclaim(&mut pinned, &handle, path).await {
            Ok(reclaimed) => {
                let mut reader = FileReader::opened(
                    tree,
                    pinned,
                    &reclaimed.created,
                    Some(reclaimed.handle.identity()),
                    reclaimed.name,
                    previous.options,
                );
                reader.durable = Some(reclaimed.handle);
                return verified(reader, &expected, path).await;
            }
            Err(Error::DurableHandleLost { reason, .. }) => {
                debug!("reopen: no durable handle to reclaim ({reason}); reopening path={path:?}");
            }
            Err(e) => return Err(e),
        }
    }
    let reader = open_file_reader_with(tree, conn, path, previous.options).await?;
    verified(reader, &expected, path).await
}

/// `reader`, if it reads `expected`; otherwise closed, and the change.
async fn verified(reader: FileReader, expected: &FileVersion, path: &str) -> Result<FileReader> {
    let Some(change) = expected.change_to(&reader.version()) else {
        return Ok(reader);
    };
    debug!("reopen: refusing path={path:?}: {change}");
    // The refusal is the answer; a failed CLOSE can't change it, and the
    // reader closes on drop regardless.
    let _ = reader.close().await;
    Err(Error::FileChanged {
        path: path.to_string(),
        change,
    })
}
