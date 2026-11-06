//! Read-only readers that can be reopened after a reconnect, and refuse to be
//! when the file changed.
//!
//! A [`FileReader`] holds one handle, and a handle dies with its session. A
//! consumer that serves positioned reads for a long time (a media server
//! streaming a film, an indexer walking an archive) wants to carry on after a
//! dropped connection without either of two failures: reading on into a file
//! that has since been replaced or rewritten, mixing bytes from two versions,
//! or touching the file in any way a reader shouldn't.
//!
//! ## What a reader here asks for, and never more
//!
//! `FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`, opened `FileOpen`:
//! never created, never truncated, never write access, sharing read, write
//! and delete so other clients are not locked out. The durable variant adds a
//! batch oplock and the `DH2Q` context on SMB 3.x, and its reclaim asks for
//! exactly the same access (a [`DurableHandle`] records which kind of open it
//! came from). ❌ Don't reuse [`Tree::open_file_durable`] for reading: it asks
//! for write access and creates a missing file (`FileOpenIf`).
//!
//! ## The version check
//!
//! A reader records a [`FileVersion`] at open: the length and last-write time
//! from the CREATE's own answer, and the file's [`FileIdentity`] from two
//! `QUERY_INFO`s compounded onto it (the same pair, for the same Samba
//! reasons, as `durable.rs`). [`reopen_file_reader`] compares the reopened
//! file against it, identity first (a different file's length says nothing),
//! and fails with [`Error::FileChanged`] after closing what it opened.
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

use std::sync::Arc;

use log::debug;

use crate::client::connection::Connection;
use crate::client::durable::{DurableHandle, FileIdentity};
use crate::client::stream::FileReader;
use crate::client::tree::{file_info_from_create, Tree};
use crate::error::{FileChange, Result};
use crate::msg::create::CreateResponse;
use crate::pack::{FileTime, ReadCursor, Unpack};
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
    /// A plain read-only open: no oplock, no durable handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the server for a durable handle, so a reader whose connection
    /// drops can claim the same open back with [`reopen_file_reader`] instead
    /// of opening the path again.
    ///
    /// Only on SMB 3.x, and only granted with a batch oplock (MS-SMB2
    /// § 3.3.5.9.10). While the reader holds one, another client opening the
    /// file makes the server send an oplock break, which the connection
    /// acknowledges on its own, and wait for that answer first. A server that
    /// declines gives an ordinary reader with
    /// [`durable_handle`](FileReader::durable_handle) `None`, never an error.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersion {
    /// The file's length at open.
    pub size: u64,
    /// The file's last-write time at open.
    pub modified: FileTime,
    /// Which file it is, when the server said (see [`FileIdentity`]). `None`
    /// for a reader from the plain [`open_file_reader`](crate::client::stream::open_file_reader),
    /// which doesn't ask, and on a server that won't answer.
    pub identity: Option<FileIdentity>,
}

impl FileVersion {
    /// How `now` differs from this version, or `None` when it is the same
    /// file with the same length and last-write time.
    ///
    /// Identity first: once it differs, the length says nothing. An identity
    /// only `now` has is ignored (there is nothing to compare it with); one
    /// only `self` has is [`FileChange::IdentityUnavailable`].
    pub fn change_to(&self, now: &FileVersion) -> Option<FileChange> {
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
/// version of the file it reads, so [`reopen_file_reader`] can carry on after
/// a reconnect and refuse if the file changed.
///
/// One round trip: the CREATE (`FileOpen`, read access only, never creating)
/// plus the two identity queries in the same compound. A missing file is the
/// CREATE's error (`ErrorKind::NotFound`). With
/// [`ReaderOptions::durable`], the open also asks for a durable handle.
///
/// [`Tree::open_file_reader_with`] and
/// [`SmbClient::open_file_reader_with`](crate::SmbClient::open_file_reader_with)
/// are the convenience wrappers.
pub async fn open_file_reader_with(
    tree: Arc<Tree>,
    conn: Connection,
    path: &str,
    options: ReaderOptions,
) -> Result<FileReader> {
    // Pinned before the CREATE, like every handle: the reader must never send
    // this file id into a later session.
    let mut conn = tree.pinned_conn(&conn).pinned_to_session();
    let mut request = tree.read_open_request(path);
    let (created, identity, durable) = if options.durable {
        // A durable handle on a directory would buy an oplock for nothing.
        request.create_options = FILE_NON_DIRECTORY_FILE;
        tree.open_durably(&mut conn, request, path, true).await?
    } else {
        let (frame, identity) = tree.create_and_identify(&mut conn, &request).await?;
        let created = CreateResponse::unpack(&mut ReadCursor::new(&frame.body))?;
        (created, identity, None)
    };
    Ok(reader_from(
        tree, conn, &created, identity, durable, options,
    ))
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
/// The new reader keeps `previous`'s version and options. Fails with
/// [`Error::FileChanged`] when the file is no longer that version, after
/// closing what it opened, and with the CREATE's own error when the file is
/// gone. Any other error (the network, access denied) comes back as itself,
/// so [`Error::is_retryable`] says whether to try the reopen again later.
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
///         client.reopen_file_reader(share, "film.mkv", &reader).await?
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
    let expected = previous.version;
    let previous_is_live = previous.pin().is_some_and(|pin| conn.pin_is_current(pin));
    if let Some(handle) = previous.durable.filter(|_| !previous_is_live) {
        let mut pinned = tree.pinned_conn(&conn).pinned_to_session();
        match tree.reclaim(&mut pinned, &handle, path).await {
            Ok((created, reclaimed)) => {
                let reader = reader_from(
                    tree,
                    pinned,
                    &created,
                    Some(reclaimed.identity()),
                    Some(reclaimed),
                    previous.options,
                );
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

/// A reader over what a CREATE (or a reclaim) opened, on the clone pinned
/// before it.
fn reader_from(
    tree: Arc<Tree>,
    conn: Connection,
    created: &CreateResponse,
    identity: Option<FileIdentity>,
    durable: Option<DurableHandle>,
    options: ReaderOptions,
) -> FileReader {
    let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
    let mut reader = FileReader::new(
        tree,
        conn,
        created.file_id,
        file_info_from_create(created),
        max_read,
    );
    reader.version.identity = identity;
    reader.durable = durable;
    reader.options = options;
    reader
}

/// `reader`, if it reads `expected`; otherwise closed, and the change.
async fn verified(reader: FileReader, expected: &FileVersion, path: &str) -> Result<FileReader> {
    let Some(change) = expected.change_to(&reader.version) else {
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
