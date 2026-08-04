//! Tree (share) connection and file operations.
//!
//! The [`Tree`] type represents a connection to a specific share on the server.
//! It provides methods for directory listing, file reading/writing, deletion,
//! renaming, stat, and directory creation.

use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, trace, warn};

use crate::client::connection::{CompoundOp, Connection};
use crate::client::durable::FileIdentity;
use crate::client::stream::{FileDownload, Progress};
use crate::error::Result;
use crate::msg::close::CloseRequest;
use crate::msg::create::{
    CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
};
use crate::msg::flush::FlushRequest;
use crate::msg::query_directory::{
    FileInformationClass, QueryDirectoryFlags, QueryDirectoryRequest, QueryDirectoryResponse,
};
use crate::msg::query_info::{InfoType, QueryInfoRequest, QueryInfoResponse};
use crate::msg::read::{ReadRequest, ReadResponse, SMB2_CHANNEL_NONE};
use crate::msg::set_info::SetInfoRequest;
use crate::msg::tree_connect::{TreeConnectRequest, TreeConnectRequestFlags, TreeConnectResponse};
use crate::msg::tree_disconnect::TreeDisconnectRequest;
use crate::msg::write::{WriteRequest, WriteResponse};
use crate::pack::{FileTime, ReadCursor, Unpack};
use crate::types::flags::FileAccessMask;
use crate::types::status::NtStatus;
#[cfg(test)]
use crate::types::MessageId;
use crate::types::{Command, CreditCharge, FileId, OplockLevel, SessionId, TreeId};
use crate::Error;

/// Maximum number of requests to keep in flight during pipelining.
///
/// More than 32 in-flight requests creates diminishing returns and
/// increases memory usage (buffering responses). 32 x 64 KB = 2 MB
/// in flight is plenty for Gigabit LAN.
const MAX_PIPELINE_WINDOW: usize = 32;

/// Unwrap an `execute_compound` result, propagating the first inner
/// waiter-level error (session expired, signature verify failure,
/// connection disconnected mid-await) as the outer `Err`. Returns a
/// `Vec<Frame>` of exactly `expected` frames, so callers can index per
/// sub-op.
///
/// Any routing-level failure aborts the whole operation rather than
/// silently handing back a partial response list the caller would have to
/// inspect one-by-one. Sub-op status codes (`STATUS_OBJECT_NAME_NOT_FOUND`
/// and friends) are NOT errors here; they ride in `Frame::header.status`
/// and the caller checks them.
///
/// The `expected` count is what keeps every caller's `responses[2]` from
/// being a panic: a server that answers a four-op chain with two frames is
/// a protocol error, not a reason to take the process down.
fn all_or_first_err(
    frames: Vec<Result<crate::client::connection::Frame>>,
    expected: usize,
) -> Result<Vec<crate::client::connection::Frame>> {
    let mut out = Vec::with_capacity(frames.len());
    for r in frames {
        out.push(r?);
    }
    if out.len() != expected {
        return Err(Error::invalid_data(format!(
            "compound response has {} frames, expected {}",
            out.len(),
            expected
        )));
    }
    Ok(out)
}

/// File attribute constant: the entry is a directory.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// Create option: the target must be a directory.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

/// Create option: the target must not be a directory.
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

/// FileBasicInformation class for QUERY_INFO (MS-FSCC 2.4.7).
const FILE_BASIC_INFORMATION: u8 = 4;

/// FileStandardInformation class for QUERY_INFO (MS-FSCC 2.4.41).
const FILE_STANDARD_INFORMATION: u8 = 5;

/// FileRenameInformation class for SET_INFO (MS-FSCC 2.4.34.2).
const FILE_RENAME_INFORMATION: u8 = 10;

/// FileDispositionInformation class for SET_INFO (MS-FSCC 2.4.11).
const FILE_DISPOSITION_INFORMATION: u8 = 13;

/// FileFsFullSizeInformation class for QUERY_INFO (MS-FSCC 2.5.4).
const FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;

/// A directory entry returned by [`Tree::list_directory`] or
/// [`DirectoryReader::next_batch`].
///
/// This result type is non-exhaustive so future protocol metadata can be
/// exposed without repeatedly breaking callers that only read its fields.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// The file or directory name.
    pub name: String,
    /// The file size in bytes (0 for directories).
    pub size: u64,
    /// Whether this entry is a directory.
    pub is_directory: bool,
    /// The creation time.
    pub created: FileTime,
    /// The last modification time.
    pub modified: FileTime,
    /// The last metadata or content change time.
    pub changed: FileTime,
    /// The server-provided 64-bit file index, when the file system supports it.
    ///
    /// A zero value is reported as `None` because the protocol requires clients
    /// to ignore it when stable file IDs are unavailable.
    pub file_index: Option<u64>,
}

/// Controls the server-side semantics of an SMB rename.
///
/// The replacement decision is encoded in the single atomic
/// `FileRenameInformation` operation. The client never emulates replacement by
/// deleting the destination first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenameOptions {
    /// Replace an existing destination when the server supports it.
    ///
    /// `false` preserves [`Tree::rename`]'s no-replace behavior.
    pub replace_if_exists: bool,
}

/// One QUERY_DIRECTORY round trip within a directory listing, captured by
/// [`Tree::list_directory_instrumented`].
#[derive(Debug, Clone)]
pub struct QueryStep {
    /// Wall-clock time for this QUERY_DIRECTORY request and its response.
    pub elapsed: Duration,
    /// Directory entries this round trip returned (0 for the terminal
    /// NO_MORE_FILES reply).
    pub entries: usize,
    /// Output-buffer bytes the server returned for this round trip.
    pub bytes: usize,
    /// True for the terminal round trip that returned STATUS_NO_MORE_FILES.
    pub no_more_files: bool,
}

/// Per-phase timing for a single directory listing, returned by
/// [`Tree::list_directory_instrumented`]. Every field is a real wire round
/// trip, so [`total`](Self::total) sums to the listing's wall time minus
/// local parse cost. Useful for diagnosing slow shares: it shows whether the
/// CREATE, the QUERY_DIRECTORY loop, or the CLOSE dominates, and how many
/// QUERY round trips a directory needs (which the query buffer size drives).
#[derive(Debug, Clone)]
pub struct ListingTrace {
    /// Time for the CREATE that opens the directory handle.
    pub create: Duration,
    /// One entry per QUERY_DIRECTORY round trip, in order. The last one is the
    /// terminal NO_MORE_FILES reply.
    pub queries: Vec<QueryStep>,
    /// Time for the CLOSE that releases the handle.
    pub close: Duration,
    /// Output-buffer length (bytes) requested per QUERY_DIRECTORY.
    pub query_buffer_len: u32,
    /// Total directory entries returned (includes `.` and `..`).
    pub entries: usize,
}

impl ListingTrace {
    /// Total wire time: CREATE + every QUERY_DIRECTORY + CLOSE.
    pub fn total(&self) -> Duration {
        self.create + self.query_total() + self.close
    }

    /// Summed time of all QUERY_DIRECTORY round trips (including the terminal
    /// NO_MORE_FILES reply).
    pub fn query_total(&self) -> Duration {
        self.queries.iter().map(|q| q.elapsed).sum()
    }

    /// Total round trips: CREATE + every QUERY_DIRECTORY + CLOSE.
    pub fn round_trips(&self) -> usize {
        1 + self.queries.len() + 1
    }
}

/// Outcome of a single QUERY_DIRECTORY round trip.
enum QueryStepOutcome {
    /// The server returned entries. `bytes` is the output-buffer length.
    Entries {
        entries: Vec<DirectoryEntry>,
        bytes: usize,
    },
    /// The server returned STATUS_NO_MORE_FILES, ending the scan.
    NoMoreFiles { bytes: usize },
    /// The preferred compact information class is unavailable. Retry the same
    /// scan with the broadly supported class that omits stable file IDs.
    UnsupportedInformationClass { bytes: usize },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirectoryInfoLayout {
    FileIdFull,
    FileBoth,
}

impl DirectoryInfoLayout {
    fn information_class(self) -> FileInformationClass {
        match self {
            Self::FileIdFull => FileInformationClass::FileIdFullDirectoryInformation,
            Self::FileBoth => FileInformationClass::FileBothDirectoryInformation,
        }
    }

    fn fixed_len(self) -> usize {
        match self {
            Self::FileIdFull => 80,
            Self::FileBoth => 94,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::FileIdFull => "FileIdFullDirectoryInformation",
            Self::FileBoth => "FileBothDirectoryInformation",
        }
    }
}

type BoxedDirectoryQuery = Pin<Box<dyn Future<Output = Result<QueryStepOutcome>> + Send + 'static>>;
type BoxedDirectoryClose = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

enum DirectoryReaderAfterClose {
    Eof,
    QueryFailed(Error),
}

enum DirectoryReaderState {
    Ready {
        restart: bool,
    },
    Querying(BoxedDirectoryQuery),
    Closing {
        future: BoxedDirectoryClose,
        after: DirectoryReaderAfterClose,
    },
    Done,
}

/// File metadata returned by [`Tree::stat`].
///
/// This result type is non-exhaustive so future protocol metadata can be
/// exposed without repeatedly breaking callers that only read its fields.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// The file size in bytes.
    pub size: u64,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// The creation time.
    pub created: FileTime,
    /// The last modification time.
    pub modified: FileTime,
    /// The last access time.
    pub accessed: FileTime,
    /// The last metadata or content change time.
    pub changed: FileTime,
    /// Stable identity for this file, when the server exposes a non-zero
    /// `FileInternalInformation` index.
    pub identity: Option<FileIdentity>,
}

/// An open source handle for an identity-checked rename or deletion.
///
/// The metadata was captured from the same CREATE that produced `file_id`, so
/// a caller can validate a version token and then mutate this handle without a
/// path-based time-of-check/time-of-use window. Call [`rename`](Self::rename),
/// [`delete`](Self::delete), or [`close`](Self::close); dropping a live handle
/// cannot perform the asynchronous CLOSE and leaves cleanup to session teardown.
#[must_use = "rename, delete, or close the mutation handle"]
pub struct MutationHandle {
    tree: Arc<Tree>,
    conn: Connection,
    generation: u64,
    session_id: SessionId,
    file_id: FileId,
    info: FileInfo,
    closed: bool,
}

impl MutationHandle {
    /// Metadata captured when this exact handle was opened.
    #[must_use]
    pub fn info(&self) -> &FileInfo {
        &self.info
    }

    fn is_current(&self) -> bool {
        self.conn.generation() == self.generation && self.conn.session_id() == self.session_id
    }

    fn ensure_current(&mut self) -> Result<()> {
        if self.is_current() {
            Ok(())
        } else {
            // Session teardown already released the old handle. Mark it closed
            // locally so Drop does not report a leak that no longer exists.
            self.closed = true;
            Err(Error::Disconnected)
        }
    }

    async fn close_current(&mut self) -> Result<()> {
        if !self.is_current() {
            self.closed = true;
            return Ok(());
        }
        let result = Tree::close_handle_bound(
            self.tree.tree_id,
            &mut self.conn,
            self.file_id,
            self.generation,
            self.session_id,
        )
        .await;
        self.closed = true;
        result
    }

    /// Atomically rename this open source handle.
    ///
    /// Replacement is encoded directly in `FileRenameInformation`; no target
    /// deletion is performed. A failed SET_INFO leaves the handle open only
    /// long enough for a best-effort CLOSE before the error is returned.
    pub async fn rename(mut self, destination: &str, options: RenameOptions) -> Result<()> {
        self.ensure_current()?;
        let request = SetInfoRequest {
            info_type: InfoType::File,
            file_info_class: FILE_RENAME_INFORMATION,
            additional_information: 0,
            file_id: self.file_id,
            buffer: build_rename_info_buffer(
                &normalize_path(destination),
                options.replace_if_exists,
            ),
        };
        let frame = self
            .conn
            .execute_bound(
                Command::SetInfo,
                &request,
                Some(self.tree.tree_id),
                self.generation,
                self.session_id,
            )
            .await;
        match frame {
            Ok(frame) if frame.header.status == NtStatus::SUCCESS => {
                // The rename committed in SET_INFO. CLOSE failure cannot undo
                // it and is therefore non-fatal, matching Tree::rename.
                if let Err(error) = self.close_current().await {
                    debug!("tree: mutation-handle CLOSE after rename failed: {error}");
                }
                Ok(())
            }
            Ok(frame) => {
                let error = Error::Protocol {
                    status: frame.header.status,
                    command: Command::SetInfo,
                };
                let _ = self.close_current().await;
                Err(error)
            }
            Err(error) => {
                let _ = self.close_current().await;
                Err(error)
            }
        }
    }

    /// Mark this exact open handle for deletion and close it.
    ///
    /// Directories must be empty. The returned result includes CLOSE because
    /// delete-pending takes final effect when the handle closes.
    pub async fn delete(mut self) -> Result<()> {
        self.ensure_current()?;
        let request = SetInfoRequest {
            info_type: InfoType::File,
            file_info_class: FILE_DISPOSITION_INFORMATION,
            additional_information: 0,
            file_id: self.file_id,
            buffer: vec![1],
        };
        let frame = self
            .conn
            .execute_bound(
                Command::SetInfo,
                &request,
                Some(self.tree.tree_id),
                self.generation,
                self.session_id,
            )
            .await;
        match frame {
            Ok(frame) if frame.header.status == NtStatus::SUCCESS => self.close_current().await,
            Ok(frame) => {
                let error = Error::Protocol {
                    status: frame.header.status,
                    command: Command::SetInfo,
                };
                let _ = self.close_current().await;
                Err(error)
            }
            Err(error) => {
                let _ = self.close_current().await;
                Err(error)
            }
        }
    }

    /// Close without mutating the entry.
    pub async fn close(mut self) -> Result<()> {
        self.close_current().await
    }
}

impl Drop for MutationHandle {
    fn drop(&mut self) {
        if !self.closed && self.is_current() {
            debug!("tree: MutationHandle dropped without rename(), delete(), or close()")
        }
    }
}

/// File system space information for a share.
#[derive(Debug, Clone)]
pub struct FsInfo {
    /// Total capacity in bytes.
    pub total_bytes: u64,
    /// Free space available to the caller in bytes.
    pub free_bytes: u64,
    /// Total free space on the volume in bytes (may differ from
    /// `free_bytes` if quotas are in effect).
    pub total_free_bytes: u64,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
    /// Sectors per allocation unit (cluster).
    pub sectors_per_unit: u32,
}

/// A connection to a specific share (tree connect).
#[derive(Clone)]
pub struct Tree {
    /// The tree ID assigned by the server.
    pub tree_id: TreeId,
    /// The share name.
    pub share_name: String,
    /// The server name (hostname or IP) this tree is connected to.
    ///
    /// Used by `SmbClient` to route operations through the correct
    /// connection when DFS referrals point to different servers.
    pub server: String,
    /// Whether the share is a DFS share.
    pub is_dfs: bool,
    /// Whether the share requires encryption.
    pub encrypt_data: bool,
}

/// Incremental directory enumeration over one open SMB directory handle.
///
/// Each call to [`next_batch`](Self::next_batch) issues one
/// `QUERY_DIRECTORY` request and returns only the entries from that server
/// response. This keeps memory bounded for large directories; batch sizes are
/// chosen by the server and are not a stable page size.
///
/// Reaching the end of the directory closes the handle automatically. If the
/// caller stops before then, it must call [`close`](Self::close). Rust has no
/// asynchronous drop, so dropping a live reader can leave the server handle
/// open until the SMB session ends.
///
/// [`next_batch`](Self::next_batch) is cancellation-safe: cancelling a call
/// retains its in-flight QUERY_DIRECTORY (or EOF CLOSE), and the next call
/// resumes that same request. A transport or session error is terminal because
/// SMB directory cursors cannot be resumed portably after reconnecting. The
/// reader also tracks the connection generation and session ID. Once it
/// detects an in-place reconnect, it rejects the old tree and file IDs rather
/// than reusing them against the replacement session.
///
/// ```no_run
/// # async fn example(
/// #     client: &mut smb2::SmbClient,
/// #     share: &mut smb2::Tree,
/// # ) -> Result<(), smb2::Error> {
/// let mut reader = client.open_directory_reader(share, "projects").await?;
/// while let Some(entries) = reader.next_batch().await? {
///     for entry in entries {
///         println!("{}", entry.name);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[must_use = "consume the directory reader to EOF or call close()"]
pub struct DirectoryReader {
    tree_id: TreeId,
    conn: Connection,
    generation: u64,
    session_id: SessionId,
    file_id: FileId,
    output_buffer_length: u32,
    layout: DirectoryInfoLayout,
    state: DirectoryReaderState,
}

impl DirectoryReader {
    /// Return the next server-provided batch of directory entries.
    ///
    /// `Ok(Some(entries))` contains one `QUERY_DIRECTORY` response.
    /// `Ok(None)` means the enumeration is complete and the directory handle
    /// has been closed. Calls after completion continue to return `Ok(None)`
    /// without sending more requests.
    ///
    /// This method is cancellation-safe: if its future is dropped after the
    /// request has been sent, the same in-flight request is resumed by the
    /// next call rather than silently skipping the server's response batch.
    pub async fn next_batch(&mut self) -> Result<Option<Vec<DirectoryEntry>>> {
        loop {
            if matches!(&self.state, DirectoryReaderState::Done) {
                return Ok(None);
            }

            let restart = match &self.state {
                DirectoryReaderState::Ready { restart } => Some(*restart),
                _ => None,
            };
            if let Some(restart) = restart {
                self.begin_query(restart);
                continue;
            }

            if matches!(&self.state, DirectoryReaderState::Querying(_)) {
                let result = match &mut self.state {
                    DirectoryReaderState::Querying(future) => future.as_mut().await,
                    _ => unreachable!("query state checked above"),
                };

                match result {
                    Ok(QueryStepOutcome::Entries { entries, .. }) => {
                        self.state = DirectoryReaderState::Ready { restart: false };
                        return Ok(Some(entries));
                    }
                    Ok(QueryStepOutcome::NoMoreFiles { .. }) => {
                        self.begin_close(DirectoryReaderAfterClose::Eof);
                    }
                    Ok(QueryStepOutcome::UnsupportedInformationClass { .. }) => {
                        debug!(
                            "tree: server declined FileIdFullDirectoryInformation, retrying with FileBothDirectoryInformation"
                        );
                        self.layout = DirectoryInfoLayout::FileBoth;
                        self.state = DirectoryReaderState::Ready { restart: true };
                    }
                    Err(error) => {
                        // Preserve the query failure, matching `list_directory`'s
                        // error precedence, while still avoiding a leaked handle.
                        self.begin_close(DirectoryReaderAfterClose::QueryFailed(error));
                    }
                }
                continue;
            }

            let (close_result, after) = self.await_close().await;
            return match after {
                DirectoryReaderAfterClose::Eof => {
                    close_result?;
                    Ok(None)
                }
                DirectoryReaderAfterClose::QueryFailed(error) => {
                    let _ = close_result;
                    Err(error)
                }
            };
        }
    }

    /// Close the directory handle before reaching the end of the enumeration.
    ///
    /// Consumes the reader so it cannot be used after it has been closed. If a
    /// cancelled [`next_batch`](Self::next_batch) left a query in flight, this
    /// first drains that response so QUERY_DIRECTORY and CLOSE cannot race on
    /// the stateful server handle.
    pub async fn close(mut self) -> Result<()> {
        if matches!(&self.state, DirectoryReaderState::Done) {
            return Ok(());
        }

        // A cancelled `next_batch` may have left one QUERY_DIRECTORY in
        // flight. Drain it before CLOSE so operations on the stateful server
        // enumeration handle cannot race each other.
        if matches!(&self.state, DirectoryReaderState::Querying(_)) {
            let _ = match &mut self.state {
                DirectoryReaderState::Querying(future) => future.as_mut().await,
                _ => unreachable!("query state checked above"),
            };
            self.begin_close(DirectoryReaderAfterClose::Eof);
        } else if matches!(&self.state, DirectoryReaderState::Ready { .. }) {
            self.begin_close(DirectoryReaderAfterClose::Eof);
        }

        let (result, _) = self.await_close().await;
        result
    }

    fn begin_query(&mut self, restart: bool) {
        let tree_id = self.tree_id;
        let mut conn = self.conn.clone();
        let generation = self.generation;
        let session_id = self.session_id;
        let file_id = self.file_id;
        let output_buffer_length = self.output_buffer_length;
        let layout = self.layout;
        self.state = DirectoryReaderState::Querying(Box::pin(async move {
            if conn.generation() != generation || conn.session_id() != session_id {
                return Err(Error::Disconnected);
            }
            let result = Tree::query_directory_step(
                tree_id,
                &mut conn,
                file_id,
                restart,
                output_buffer_length,
                layout,
                generation,
                session_id,
            )
            .await;
            if conn.generation() != generation || conn.session_id() != session_id {
                return Err(Error::Disconnected);
            }
            result
        }));
    }

    fn begin_close(&mut self, after: DirectoryReaderAfterClose) {
        let tree_id = self.tree_id;
        let mut conn = self.conn.clone();
        let generation = self.generation;
        let session_id = self.session_id;
        let file_id = self.file_id;
        self.state = DirectoryReaderState::Closing {
            future: Box::pin(async move {
                if conn.generation() != generation || conn.session_id() != session_id {
                    return Ok(());
                }
                let result =
                    Tree::close_handle_bound(tree_id, &mut conn, file_id, generation, session_id)
                        .await;
                if conn.generation() != generation || conn.session_id() != session_id {
                    return Ok(());
                }
                result
            }),
            after,
        };
    }

    async fn await_close(&mut self) -> (Result<()>, DirectoryReaderAfterClose) {
        let result = match &mut self.state {
            DirectoryReaderState::Closing { future, .. } => future.as_mut().await,
            _ => unreachable!("await_close requires a closing reader"),
        };
        let state = std::mem::replace(&mut self.state, DirectoryReaderState::Done);
        let DirectoryReaderState::Closing { after, .. } = state else {
            unreachable!("closing state replaced above")
        };
        (result, after)
    }
}

impl Drop for DirectoryReader {
    fn drop(&mut self) {
        if !matches!(&self.state, DirectoryReaderState::Done)
            && self.conn.generation() == self.generation
            && self.conn.session_id() == self.session_id
        {
            debug!(
                "tree: DirectoryReader dropped without close(), directory handle may leak until \
                 session teardown"
            );
        }
    }
}

impl Tree {
    /// Connect to a share on the server.
    ///
    /// Sends a TREE_CONNECT request with the UNC path `\\server\share`
    /// encoded in UTF-16LE.
    pub async fn connect(conn: &mut Connection, share_name: &str) -> Result<Tree> {
        let server = conn.server_name().to_string();
        let unc_path = format!(r"\\{}\{}", server, share_name);
        let generation = conn.generation();
        let session_id = conn.session_id();

        let req = TreeConnectRequest {
            flags: TreeConnectRequestFlags::default(),
            path: unc_path,
        };

        let frame = conn
            .execute_bound(Command::TreeConnect, &req, None, generation, session_id)
            .await?;

        if frame.header.command != Command::TreeConnect {
            return Err(Error::invalid_data(format!(
                "expected TreeConnect response, got {:?}",
                frame.header.command
            )));
        }

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::TreeConnect,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = TreeConnectResponse::unpack(&mut cursor)?;

        let tree_id = frame
            .header
            .tree_id
            .ok_or_else(|| Error::invalid_data("TreeConnect response missing tree ID"))?;

        let is_dfs = resp
            .capabilities
            .contains(crate::types::flags::ShareCapabilities::DFS);
        let encrypt_data = resp
            .share_flags
            .contains(crate::types::flags::ShareFlags::ENCRYPT_DATA);

        info!("tree: connected share={}, tree_id={}", share_name, tree_id);
        debug!("tree: is_dfs={}, encrypt_data={}", is_dfs, encrypt_data);

        if is_dfs {
            conn.register_dfs_tree(tree_id);
        }

        Ok(Tree {
            tree_id,
            share_name: share_name.to_string(),
            server: server.clone(),
            is_dfs,
            encrypt_data,
        })
    }

    /// Normalize and format a path for this tree.
    ///
    /// When `is_dfs` is true, the server expects the path to include the
    /// `server\share\` prefix (MS-SMB2 3.2.4.3: "the client MUST pass a
    /// DFS path containing the server, share, and path to the open").
    /// The server strips the first two path components to get the local path,
    /// and if the resulting path starts with a DFS link name, it returns
    /// `STATUS_PATH_NOT_COVERED` so the client can resolve the referral.
    pub(crate) fn format_path(&self, path: &str) -> String {
        let normalized = normalize_path(path);
        if self.is_dfs {
            // Extract hostname (strip port if present) for the DFS path prefix.
            let hostname = self.server.split(':').next().unwrap_or(&self.server);
            if normalized.is_empty() {
                format!("{}\\{}", hostname, self.share_name)
            } else {
                format!("{}\\{}\\{}", hostname, self.share_name, normalized)
            }
        } else {
            normalized
        }
    }

    /// Open a directory for incremental enumeration.
    ///
    /// The returned [`DirectoryReader`] owns a cheap clone of the connection
    /// and a copy of this tree's ID, so it does not borrow this tree or the
    /// caller's connection. Each [`DirectoryReader::next_batch`] call performs
    /// one `QUERY_DIRECTORY` round trip and keeps at most one response batch in
    /// memory.
    ///
    /// If the connection is revived while the directory is being opened, the
    /// open fails rather than returning a handle tied to the old session.
    pub async fn open_directory_reader(
        &self,
        mut conn: Connection,
        path: &str,
    ) -> Result<DirectoryReader> {
        let normalized = self.format_path(path);
        trace!("tree: open_directory_reader path={}", normalized);

        let generation = conn.generation();
        let session_id = conn.session_id();
        let output_buffer_length = Self::default_query_buffer_len(&conn);
        let open_result = self
            .open_directory_bound(&mut conn, &normalized, generation, session_id)
            .await;
        if conn.generation() != generation || conn.session_id() != session_id {
            return Err(Error::Disconnected);
        }
        let file_id = open_result?;

        Ok(DirectoryReader {
            tree_id: self.tree_id,
            conn,
            generation,
            session_id,
            file_id,
            output_buffer_length,
            layout: DirectoryInfoLayout::FileIdFull,
            state: DirectoryReaderState::Ready { restart: true },
        })
    }

    /// List files in a directory.
    ///
    /// Opens the directory with CREATE, queries entries with QUERY_DIRECTORY
    /// (looping until STATUS_NO_MORE_FILES), then closes the handle.
    pub async fn list_directory(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<Vec<DirectoryEntry>> {
        // TRACE, not DEBUG: a recursive scan calls list_directory once per directory
        // (millions of times on a large share), so at DEBUG it dominates a consumer's
        // log. Per-operation mutations (rename/delete/write) stay at DEBUG. See AGENTS.md.
        trace!("tree: list_directory path={}", path);

        let mut reader = self.open_directory_reader(conn.clone(), path).await?;
        let mut all_entries = Vec::new();
        while let Some(entries) = reader.next_batch().await? {
            all_entries.extend(entries);
        }

        trace!("tree: list_directory done, entries={}", all_entries.len());
        Ok(all_entries)
    }

    /// List a directory while recording a per-phase timing breakdown.
    ///
    /// Same wire path as [`list_directory`](Self::list_directory) (CREATE →
    /// QUERY_DIRECTORY loop → CLOSE), but returns a [`ListingTrace`] alongside
    /// the entries, timing each round trip. Meant for diagnosing slow shares
    /// and sizing protocol tweaks, not for the hot path.
    ///
    /// `query_buffer_len` overrides the output-buffer length requested per
    /// QUERY_DIRECTORY. `None` uses the production default (min of the server's
    /// max transact size and 65536). A larger buffer packs more entries per
    /// round trip, cutting the number of QUERY_DIRECTORY calls a fat directory
    /// needs; the request charges credits to match (ceil(len / 65536)).
    pub async fn list_directory_instrumented(
        &self,
        conn: &mut Connection,
        path: &str,
        query_buffer_len: Option<u32>,
    ) -> Result<(Vec<DirectoryEntry>, ListingTrace)> {
        let normalized = self.format_path(path);
        let buffer_len = query_buffer_len.unwrap_or_else(|| Self::default_query_buffer_len(conn));
        let generation = conn.generation();
        let session_id = conn.session_id();

        let create_start = Instant::now();
        let file_id = self
            .open_directory_bound(conn, &normalized, generation, session_id)
            .await?;
        let create = create_start.elapsed();

        let mut queries = Vec::new();
        let mut all_entries = Vec::new();
        let mut restart = true;
        let mut layout = DirectoryInfoLayout::FileIdFull;
        let query_result = loop {
            let step_start = Instant::now();
            match Self::query_directory_step(
                self.tree_id,
                conn,
                file_id,
                restart,
                buffer_len,
                layout,
                generation,
                session_id,
            )
            .await
            {
                Ok(QueryStepOutcome::Entries { entries, bytes }) => {
                    queries.push(QueryStep {
                        elapsed: step_start.elapsed(),
                        entries: entries.len(),
                        bytes,
                        no_more_files: false,
                    });
                    all_entries.extend(entries);
                }
                Ok(QueryStepOutcome::NoMoreFiles { bytes }) => {
                    queries.push(QueryStep {
                        elapsed: step_start.elapsed(),
                        entries: 0,
                        bytes,
                        no_more_files: true,
                    });
                    break Ok(());
                }
                Ok(QueryStepOutcome::UnsupportedInformationClass { bytes }) => {
                    queries.push(QueryStep {
                        elapsed: step_start.elapsed(),
                        entries: 0,
                        bytes,
                        no_more_files: false,
                    });
                    layout = DirectoryInfoLayout::FileBoth;
                    restart = true;
                    continue;
                }
                Err(e) => break Err(e),
            }
            restart = false;
        };

        // Close the handle regardless of query result, mirroring `list_directory`.
        let close_start = Instant::now();
        let close_result =
            Self::close_handle_bound(self.tree_id, conn, file_id, generation, session_id).await;
        let close = close_start.elapsed();

        query_result?;
        close_result?;

        let trace = ListingTrace {
            create,
            queries,
            close,
            query_buffer_len: buffer_len,
            entries: all_entries.len(),
        };
        Ok((all_entries, trace))
    }

    /// Read a small file using a compound CREATE+READ+CLOSE request.
    ///
    /// Sends all three operations in a single transport frame, reducing
    /// round-trips from 3 to 1. Best for files that fit in a single
    /// READ (up to MaxReadSize).
    ///
    /// A single READ can't return more than the server's `MaxReadSize`, so a
    /// file larger than that fails with
    /// [`Error::FileTooLargeForSingleRead`]
    /// rather than coming back truncated. Use
    /// [`read_file_pipelined`](Self::read_file_pipelined) for files of any size.
    pub async fn read_file_compound(&self, conn: &mut Connection, path: &str) -> Result<Vec<u8>> {
        let normalized = self.format_path(path);
        let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
        trace!(
            "tree: read_file_compound path={}, max_read={}",
            normalized,
            max_read
        );

        // Build CREATE request (same params as open_file).
        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_DATA
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: normalized.clone(),
            create_contexts: vec![],
        };

        // Build READ request with sentinel FileId.
        // CreditCharge for READ = ceil(max_read / 65536).
        let read_credit_charge = (max_read as u64).div_ceil(65536) as u16;
        let read_req = ReadRequest {
            padding: 0x50,
            flags: 0,
            length: max_read,
            offset: 0,
            file_id: FileId::SENTINEL,
            minimum_count: 0,
            channel: SMB2_CHANNEL_NONE,
            remaining_bytes: 0,
            read_channel_info: vec![],
        };

        // Build CLOSE request with sentinel FileId.
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        // Send as compound.
        let ops = [
            CompoundOp {
                command: Command::Create,
                body: &create_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::Read,
                body: &read_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(read_credit_charge),
            },
            CompoundOp {
                command: Command::Close,
                body: &close_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
        ];

        let responses = all_or_first_err(conn.execute_compound(&ops).await?, ops.len())?;

        let create_header = &responses[0].header;
        let create_body = &responses[0].body;
        let read_header = &responses[1].header;
        let read_body = &responses[1].body;
        let close_header = &responses[2].header;

        // Check CREATE response.
        if create_header.status != NtStatus::SUCCESS {
            // CREATE failed -- all three fail (cascaded). No handle to clean up.
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(create_body);
        let create_resp = CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        // A single READ returns at most `max_read` bytes, so a larger file
        // would come back truncated. Fail with a typed error instead of
        // silently dropping the tail; the caller switches to
        // `read_file_pipelined`. The compound's CLOSE already released the
        // handle, so there's nothing to clean up here.
        if create_resp.end_of_file > max_read as u64 {
            debug!(
                "tree: read_file_compound path={} is {} bytes > {}-byte single-read limit",
                normalized, create_resp.end_of_file, max_read
            );
            return Err(Error::FileTooLargeForSingleRead {
                size: create_resp.end_of_file,
                max_read,
            });
        }

        // Check READ response.
        if read_header.status != NtStatus::SUCCESS && read_header.status != NtStatus::END_OF_FILE {
            // READ failed. CLOSE also failed in the compound (cascaded).
            // Issue a standalone CLOSE to clean up the handle.
            debug!(
                "tree: compound READ failed ({:?}), issuing standalone CLOSE",
                read_header.status
            );
            let _ = self.close_handle(conn, file_id).await;
            return Err(Error::Protocol {
                status: read_header.status,
                command: Command::Read,
            });
        }

        // Parse READ data.
        let data = if read_header.status == NtStatus::END_OF_FILE {
            // Empty file.
            Vec::new()
        } else {
            let mut cursor = ReadCursor::new(read_body);
            let read_resp = ReadResponse::unpack(&mut cursor)?;
            read_resp.data
        };

        // Check CLOSE response. If it failed but CREATE and READ succeeded,
        // the handle might still be open, but there's nothing we can do
        // since we already have the data.
        if close_header.status != NtStatus::SUCCESS {
            debug!(
                "tree: compound CLOSE returned {:?} (non-fatal, data already read)",
                close_header.status,
            );
        }

        trace!("tree: read_file_compound done, read {} bytes", data.len());
        Ok(data)
    }

    /// Read a file's contents using a compound request (1 round-trip).
    ///
    /// Sends CREATE+READ+CLOSE as a single compound message. For files
    /// that fit in MaxReadSize (typically 8 MB), this is the fastest
    /// path -- 1 round-trip instead of 3+.
    ///
    /// A file larger than the server's `MaxReadSize` can't be returned by a
    /// single READ, so this fails with
    /// [`Error::FileTooLargeForSingleRead`]
    /// (classified [`ErrorKind::TooLarge`](crate::ErrorKind::TooLarge)) instead
    /// of silently returning only the first chunk. Reach for
    /// [`read_file_pipelined`](Self::read_file_pipelined), which reads any size
    /// with concurrent chunked READs.
    pub async fn read_file(&self, conn: &mut Connection, path: &str) -> Result<Vec<u8>> {
        self.read_file_compound(conn, path).await
    }

    /// Disconnect from the share.
    pub async fn disconnect(&self, conn: &mut Connection) -> Result<()> {
        trace!(
            "tree: disconnecting share={}, tree_id={}",
            self.share_name,
            self.tree_id
        );
        let body = TreeDisconnectRequest;
        let frame = conn
            .execute(Command::TreeDisconnect, &body, Some(self.tree_id))
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::TreeDisconnect,
            });
        }

        conn.deregister_dfs_tree(self.tree_id);

        info!(
            "tree: disconnected share={}, tree_id={}",
            self.share_name, self.tree_id
        );
        Ok(())
    }

    /// Start watching a directory for changes.
    ///
    /// Opens the directory and returns a [`Watcher`](crate::client::watcher::Watcher) that yields change
    /// events via [`next_events()`](crate::client::watcher::Watcher::next_events).
    /// The server holds each request until changes occur, making this a
    /// long-poll operation.
    ///
    /// Set `recursive` to `true` to watch the entire subtree.
    ///
    /// The returned `Watcher` owns a cloned `Connection` (cheap
    /// `Arc::clone`, all clones multiplex over the same SMB session), so
    /// the caller is free to perform other operations on `conn` while
    /// watching. No second `SmbClient` is required.
    pub async fn watch(
        &self,
        conn: &mut Connection,
        path: &str,
        recursive: bool,
    ) -> Result<crate::client::watcher::Watcher> {
        debug!(
            "tree: watch path={}, recursive={}, tree_id={}",
            path, recursive, self.tree_id
        );

        // Open the directory with FILE_LIST_DIRECTORY access (same as
        // FILE_READ_DATA = 0x0001). We need the handle to stay open for
        // the lifetime of the watcher.
        let file_id = self.open_directory(conn, path).await?;

        // Hand the watcher an owned Tree clone and an owned Connection
        // clone so it can pipeline CHANGE_NOTIFY requests independently
        // of the caller's connection use.
        Ok(crate::client::watcher::Watcher::new(
            self.clone(),
            conn.clone(),
            file_id,
            recursive,
        ))
    }

    /// Delete a file using a compound request (1 round-trip).
    ///
    /// Sends CREATE (with `DELETE_ON_CLOSE`) + CLOSE as a single compound
    /// message. The server deletes the file when the CLOSE completes.
    pub async fn delete_file(&self, conn: &mut Connection, path: &str) -> Result<()> {
        self.delete_compound(conn, path, FILE_NON_DIRECTORY_FILE, "file")
            .await
    }

    /// Delete multiple files, one compound request each.
    ///
    /// Returns results in the same order as the input paths. Each file's
    /// result is independent: one failure does not affect the others.
    ///
    /// Each delete costs one round trip and they do not overlap, so this
    /// saves the per-call setup rather than the wire time. To overlap server
    /// work, run `delete_file` on several connections concurrently.
    pub async fn delete_files(&self, conn: &mut Connection, paths: &[&str]) -> Vec<Result<()>> {
        if paths.is_empty() {
            return vec![];
        }

        debug!("tree: delete_files batch, count={}", paths.len());

        let mut results: Vec<Result<()>> = Vec::with_capacity(paths.len());
        for path in paths {
            results.push(self.delete_file(conn, path).await);
        }

        debug!(
            "tree: delete_files batch done, {}/{} succeeded",
            results.iter().filter(|r| r.is_ok()).count(),
            paths.len()
        );
        results
    }

    /// Get file metadata (size, timestamps, is_directory) using a compound request (1 round-trip).
    ///
    /// Sends CREATE + QUERY_INFO (FileBasicInformation) +
    /// QUERY_INFO (FileStandardInformation) + QUERY_INFO
    /// (FileInternalInformation) + QUERY_INFO (FileFsVolumeInformation) +
    /// CLOSE as a single compound message.
    pub async fn stat(&self, conn: &mut Connection, path: &str) -> Result<FileInfo> {
        let normalized = self.format_path(path);
        trace!("tree: stat (compound) path={}", normalized);
        let generation = conn.generation();
        let session_id = conn.session_id();

        // BUILD CREATE request for reading attributes.
        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_ATTRIBUTES | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: normalized.clone(),
            create_contexts: vec![],
        };

        // QUERY_INFO for FileBasicInformation (timestamps + attributes).
        let basic_req = QueryInfoRequest {
            info_type: InfoType::File,
            file_info_class: FILE_BASIC_INFORMATION,
            output_buffer_length: 40,
            additional_information: 0,
            flags: 0,
            file_id: FileId::SENTINEL,
            input_buffer: vec![],
        };

        // QUERY_INFO for FileStandardInformation (size + is_directory).
        let std_req = QueryInfoRequest {
            info_type: InfoType::File,
            file_info_class: FILE_STANDARD_INFORMATION,
            output_buffer_length: 24,
            additional_information: 0,
            flags: 0,
            file_id: FileId::SENTINEL,
            input_buffer: vec![],
        };

        // Optional stable 64-bit file index. Servers that do not support it
        // return an error for this sub-operation; stat still succeeds with a
        // `None` identity.
        let identity_req = FileIdentity::index_query();
        let volume_req = FileIdentity::volume_query();

        // CLOSE with sentinel FileId.
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let ops = [
            CompoundOp {
                command: Command::Create,
                body: &create_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::QueryInfo,
                body: &basic_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::QueryInfo,
                body: &std_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::QueryInfo,
                body: &identity_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::QueryInfo,
                body: &volume_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::Close,
                body: &close_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
        ];

        let responses = all_or_first_err(
            conn.execute_compound_bound(&ops, generation, session_id)
                .await?,
            ops.len(),
        )?;
        if conn.generation() != generation || conn.session_id() != session_id {
            return Err(Error::Disconnected);
        }

        let create_header = &responses[0].header;
        let create_body = &responses[0].body;
        let basic_header = &responses[1].header;
        let basic_body = &responses[1].body;
        let std_header = &responses[2].header;
        let std_body = &responses[2].body;
        let identity_frame = &responses[3];
        let volume_frame = &responses[4];
        let close_header = &responses[5].header;

        // If CREATE failed, all ops cascade. No handle to clean up.
        if create_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        let create_resp = CreateResponse::unpack(&mut ReadCursor::new(create_body))?;
        // A failed optional identity query can cascade through the related
        // compound and make CLOSE fail with the same status. Release the
        // successfully created handle explicitly before parsing/returning any
        // metadata so every later error path is leak-free.
        if close_header.status != NtStatus::SUCCESS {
            warn!(
                "tree: compound CLOSE returned {:?}, issuing standalone CLOSE",
                close_header.status
            );
            let _ = Self::close_handle_bound(
                self.tree_id,
                conn,
                create_resp.file_id,
                generation,
                session_id,
            )
            .await;
        }

        // Check first QUERY_INFO (basic).
        if !basic_header.status.is_success_or_partial() {
            return Err(Error::Protocol {
                status: basic_header.status,
                command: Command::QueryInfo,
            });
        }
        if basic_header.status == NtStatus::BUFFER_OVERFLOW {
            warn!("recv: STATUS_BUFFER_OVERFLOW on FileBasicInformation, response data may be truncated");
        }

        // Parse FileBasicInformation.
        let mut cursor = ReadCursor::new(basic_body);
        let basic_resp = QueryInfoResponse::unpack(&mut cursor)?;
        let basic_buf = &basic_resp.output_buffer;

        if basic_buf.len() < 36 {
            return Err(Error::invalid_data(format!(
                "FileBasicInformation too short: {} bytes",
                basic_buf.len()
            )));
        }

        let created = FileTime(u64::from_le_bytes(basic_buf[0..8].try_into().unwrap()));
        let accessed = FileTime(u64::from_le_bytes(basic_buf[8..16].try_into().unwrap()));
        let modified = FileTime(u64::from_le_bytes(basic_buf[16..24].try_into().unwrap()));
        let changed = FileTime(u64::from_le_bytes(basic_buf[24..32].try_into().unwrap()));
        let file_attributes = u32::from_le_bytes(basic_buf[32..36].try_into().unwrap());

        // Check second QUERY_INFO (standard).
        if !std_header.status.is_success_or_partial() {
            return Err(Error::Protocol {
                status: std_header.status,
                command: Command::QueryInfo,
            });
        }
        if std_header.status == NtStatus::BUFFER_OVERFLOW {
            warn!("recv: STATUS_BUFFER_OVERFLOW on FileStandardInformation, response data may be truncated");
        }

        // Parse FileStandardInformation.
        let mut cursor = ReadCursor::new(std_body);
        let std_resp = QueryInfoResponse::unpack(&mut cursor)?;
        let std_buf = &std_resp.output_buffer;

        if std_buf.len() < 22 {
            return Err(Error::invalid_data(format!(
                "FileStandardInformation too short: {} bytes",
                std_buf.len()
            )));
        }

        let _allocation_size = u64::from_le_bytes(std_buf[0..8].try_into().unwrap());
        let end_of_file = u64::from_le_bytes(std_buf[8..16].try_into().unwrap());
        let _number_of_links = u32::from_le_bytes(std_buf[16..20].try_into().unwrap());
        let _delete_pending = std_buf[20];
        let is_directory_byte = std_buf[21];

        let is_directory =
            is_directory_byte != 0 || (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        trace!(
            "tree: stat done, size={}, is_dir={}",
            end_of_file,
            is_directory
        );
        Ok(FileInfo {
            size: end_of_file,
            is_directory,
            created,
            modified,
            accessed,
            changed,
            identity: FileIdentity::from_frames(Some(identity_frame), Some(volume_frame)),
        })
    }

    /// Stat multiple files, one compound request each.
    ///
    /// Returns results in the same order as the input paths. Each path's
    /// result is independent: one failure does not affect the others.
    ///
    /// Each stat costs one round trip and they do not overlap, so this saves
    /// the per-call setup rather than the wire time. To overlap server work,
    /// run `stat` on several connections concurrently. To describe a whole
    /// directory, `list_directory` is far cheaper than a stat per entry.
    pub async fn stat_files(&self, conn: &mut Connection, paths: &[&str]) -> Vec<Result<FileInfo>> {
        if paths.is_empty() {
            return vec![];
        }

        debug!("tree: stat_files batch, count={}", paths.len());

        let mut results: Vec<Result<FileInfo>> = Vec::with_capacity(paths.len());
        for path in paths {
            results.push(self.stat(conn, path).await);
        }

        debug!(
            "tree: stat_files batch done, {}/{} succeeded",
            results.iter().filter(|r| r.is_ok()).count(),
            paths.len()
        );
        results
    }

    /// Query file system space information for this share.
    ///
    /// Returns total capacity, free space, and allocation unit sizes.
    /// Uses a compound CREATE+QUERY_INFO+CLOSE for efficiency (one round-trip).
    pub async fn fs_info(&self, conn: &mut Connection) -> Result<FsInfo> {
        trace!("tree: fs_info on share={}", self.share_name);

        // Build CREATE request to open the root directory of the share.
        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_ATTRIBUTES | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: FILE_DIRECTORY_FILE,
            name: String::new(), // root of share
            create_contexts: vec![],
        };

        // Build QUERY_INFO request for FileFsFullSizeInformation.
        // Use sentinel FileId; the compound will fill it in.
        let query_req = QueryInfoRequest {
            info_type: InfoType::Filesystem,
            file_info_class: FILE_FS_FULL_SIZE_INFORMATION,
            output_buffer_length: 32, // 3 x i64 + 2 x u32
            additional_information: 0,
            flags: 0,
            file_id: FileId::SENTINEL,
            input_buffer: vec![],
        };

        // Build CLOSE request with sentinel FileId.
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        // Send as compound.
        let ops = [
            CompoundOp {
                command: Command::Create,
                body: &create_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::QueryInfo,
                body: &query_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::Close,
                body: &close_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
        ];

        let responses = all_or_first_err(conn.execute_compound(&ops).await?, ops.len())?;

        let create_header = &responses[0].header;
        let query_header = &responses[1].header;
        let query_body = &responses[1].body;
        let close_header = &responses[2].header;

        // Check CREATE response.
        if create_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        // Check QUERY_INFO response.
        if !query_header.status.is_success_or_partial() {
            // QUERY_INFO failed. Issue standalone CLOSE to clean up.
            let mut cursor = ReadCursor::new(&responses[0].body);
            let create_resp = CreateResponse::unpack(&mut cursor)?;
            debug!(
                "tree: compound QUERY_INFO failed ({:?}), issuing standalone CLOSE",
                query_header.status
            );
            let _ = self.close_handle(conn, create_resp.file_id).await;
            return Err(Error::Protocol {
                status: query_header.status,
                command: Command::QueryInfo,
            });
        }
        if query_header.status == NtStatus::BUFFER_OVERFLOW {
            warn!("recv: STATUS_BUFFER_OVERFLOW on FileFsFullSizeInformation, response data may be truncated");
        }

        // Parse the FileFsFullSizeInformation response.
        let mut cursor = ReadCursor::new(query_body);
        let query_resp = QueryInfoResponse::unpack(&mut cursor)?;
        let buf = &query_resp.output_buffer;

        if buf.len() < 32 {
            return Err(Error::invalid_data(format!(
                "FileFsFullSizeInformation too short: {} bytes",
                buf.len()
            )));
        }

        let total_allocation_units = i64::from_le_bytes(buf[0..8].try_into().unwrap()) as u64;
        let caller_available_units = i64::from_le_bytes(buf[8..16].try_into().unwrap()) as u64;
        let actual_available_units = i64::from_le_bytes(buf[16..24].try_into().unwrap()) as u64;
        let sectors_per_unit = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let bytes_per_sector = u32::from_le_bytes(buf[28..32].try_into().unwrap());

        let bytes_per_unit = sectors_per_unit as u64 * bytes_per_sector as u64;
        let total_bytes = total_allocation_units * bytes_per_unit;
        let free_bytes = caller_available_units * bytes_per_unit;
        let total_free_bytes = actual_available_units * bytes_per_unit;

        // Check CLOSE response (non-fatal if it failed).
        if close_header.status != NtStatus::SUCCESS {
            debug!(
                "tree: compound CLOSE returned {:?} (non-fatal, fs_info already read)",
                close_header.status,
            );
        }

        trace!(
            "tree: fs_info done, total={}, free={}, total_free={}",
            total_bytes,
            free_bytes,
            total_free_bytes
        );
        Ok(FsInfo {
            total_bytes,
            free_bytes,
            total_free_bytes,
            bytes_per_sector,
            sectors_per_unit,
        })
    }

    /// Rename or move a file within the same share using a compound request (1 round-trip).
    ///
    /// Sends CREATE + SET_INFO (FileRenameInformation) + CLOSE as a single
    /// compound message. Existing destinations are not replaced.
    pub async fn rename(&self, conn: &mut Connection, from: &str, to: &str) -> Result<()> {
        self.rename_with_options(conn, from, to, RenameOptions::default())
            .await
    }

    /// Rename or move a file within the same share with explicit replacement
    /// semantics.
    ///
    /// This is one SMB `FileRenameInformation` mutation. When
    /// [`RenameOptions::replace_if_exists`] is true, `ReplaceIfExists` is sent
    /// to the server directly; this method never performs delete-then-rename.
    pub async fn rename_with_options(
        &self,
        conn: &mut Connection,
        from: &str,
        to: &str,
        options: RenameOptions,
    ) -> Result<()> {
        let from_normalized = self.format_path(from);
        let to_normalized = normalize_path(to);
        trace!(
            "tree: rename (compound) from={} to={} replace_if_exists={}",
            from_normalized,
            to_normalized,
            options.replace_if_exists
        );

        // Build CREATE request with DELETE access (required for rename).
        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::DELETE | FileAccessMask::FILE_READ_ATTRIBUTES,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: from_normalized.clone(),
            create_contexts: vec![],
        };

        // Build SET_INFO request with FileRenameInformation and sentinel FileId.
        let setinfo_req = SetInfoRequest {
            info_type: InfoType::File,
            file_info_class: FILE_RENAME_INFORMATION,
            additional_information: 0,
            file_id: FileId::SENTINEL,
            buffer: build_rename_info_buffer(&to_normalized, options.replace_if_exists),
        };

        // Build CLOSE request with sentinel FileId.
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let ops = [
            CompoundOp {
                command: Command::Create,
                body: &create_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::SetInfo,
                body: &setinfo_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::Close,
                body: &close_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
        ];

        let responses = all_or_first_err(conn.execute_compound(&ops).await?, ops.len())?;

        let create_header = &responses[0].header;
        let create_body = &responses[0].body;
        let setinfo_header = &responses[1].header;
        let close_header = &responses[2].header;

        // If CREATE failed, all ops cascade. No handle to clean up.
        if create_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        // CREATE succeeded. If SET_INFO failed, CLOSE also cascaded.
        // Issue standalone CLOSE to avoid leaking the handle.
        if setinfo_header.status != NtStatus::SUCCESS {
            let mut cursor = ReadCursor::new(create_body);
            let create_resp = CreateResponse::unpack(&mut cursor)?;
            warn!(
                "tree: compound SET_INFO failed ({:?}), issuing standalone CLOSE",
                setinfo_header.status
            );
            let _ = self.close_handle(conn, create_resp.file_id).await;
            return Err(Error::Protocol {
                status: setinfo_header.status,
                command: Command::SetInfo,
            });
        }

        // Check CLOSE response (non-fatal if it failed, rename already done).
        if close_header.status != NtStatus::SUCCESS {
            debug!(
                "tree: compound CLOSE returned {:?} (non-fatal, rename already done)",
                close_header.status,
            );
        }

        debug!(
            "tree: renamed from={} to={}",
            from_normalized, to_normalized
        );
        Ok(())
    }

    /// Rename multiple files, one compound request each.
    ///
    /// Returns results in the same order as the input pairs. Each rename's
    /// result is independent: one failure does not affect the others.
    ///
    /// Each rename costs one round trip and they do not overlap, so this
    /// saves the per-call setup rather than the wire time. To overlap server
    /// work, run `rename` on several connections concurrently.
    pub async fn rename_files(
        &self,
        conn: &mut Connection,
        renames: &[(&str, &str)],
    ) -> Vec<Result<()>> {
        if renames.is_empty() {
            return vec![];
        }

        debug!("tree: rename_files batch, count={}", renames.len());

        let mut results: Vec<Result<()>> = Vec::with_capacity(renames.len());
        for (from, to) in renames {
            results.push(self.rename(conn, from, to).await);
        }

        debug!(
            "tree: rename_files batch done, {}/{} succeeded",
            results.iter().filter(|r| r.is_ok()).count(),
            renames.len()
        );
        results
    }

    /// Write a file using a compound CREATE+WRITE+FLUSH+CLOSE request.
    ///
    /// Sends all four operations in a single transport frame (1 round-trip).
    /// Best for files that fit in MaxWriteSize. For larger files, use
    /// [`write_file_pipelined`](Self::write_file_pipelined).
    pub async fn write_file_compound(
        &self,
        conn: &mut Connection,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        let normalized = self.format_path(path);
        trace!(
            "tree: write_file_compound path={}, len={}",
            normalized,
            data.len()
        );

        // Build CREATE request (write access, overwrite-if disposition).
        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_WRITE_DATA
                    | FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess(0),
            create_disposition: CreateDisposition::FileOverwriteIf,
            create_options: FILE_NON_DIRECTORY_FILE,
            name: normalized.clone(),
            create_contexts: vec![],
        };

        // Build WRITE request with sentinel FileId.
        // DataOffset = Header::SIZE (64) + WriteRequest fixed body (48) = 0x70.
        let write_credit_charge = (data.len() as u64).div_ceil(65536).max(1) as u16;
        let write_req = WriteRequest {
            data_offset: 0x70,
            offset: 0,
            file_id: FileId::SENTINEL,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: data.to_vec(),
        };

        // Build FLUSH request with sentinel FileId.
        let flush_req = FlushRequest {
            file_id: FileId::SENTINEL,
        };

        // Build CLOSE request with sentinel FileId.
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        // Send as 4-way compound.
        let ops = [
            CompoundOp {
                command: Command::Create,
                body: &create_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::Write,
                body: &write_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(write_credit_charge),
            },
            CompoundOp {
                command: Command::Flush,
                body: &flush_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::Close,
                body: &close_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
        ];

        let responses = all_or_first_err(conn.execute_compound(&ops).await?, ops.len())?;

        let create_header = &responses[0].header;
        let create_body = &responses[0].body;
        let write_header = &responses[1].header;
        let write_body = &responses[1].body;
        let flush_header = &responses[2].header;
        let close_header = &responses[3].header;

        // Check CREATE response.
        if create_header.status != NtStatus::SUCCESS {
            // CREATE failed -- all four fail (cascaded). No handle to clean up.
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(create_body);
        let create_resp = CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        // Check WRITE response.
        if write_header.status != NtStatus::SUCCESS {
            // WRITE failed. FLUSH and CLOSE also failed in the compound (cascaded).
            // Issue a standalone CLOSE to clean up the handle.
            debug!(
                "tree: compound WRITE failed ({:?}), issuing standalone CLOSE",
                write_header.status
            );
            let _ = self.close_handle(conn, file_id).await;
            return Err(Error::Protocol {
                status: write_header.status,
                command: Command::Write,
            });
        }

        let mut cursor = ReadCursor::new(write_body);
        let write_resp = WriteResponse::unpack(&mut cursor)?;
        let bytes_written = write_resp.count as u64;

        // Check FLUSH response. If it failed but WRITE succeeded,
        // the data might not be persisted yet but the write did happen.
        if flush_header.status != NtStatus::SUCCESS {
            debug!(
                "tree: compound FLUSH returned {:?} (data written but may not be persisted)",
                flush_header.status,
            );
        }

        // Check CLOSE response. If it failed but CREATE and WRITE succeeded,
        // the handle might still be open, but there's nothing we can do
        // since we already have the data written.
        if close_header.status != NtStatus::SUCCESS {
            debug!(
                "tree: compound CLOSE returned {:?} (non-fatal, data already written)",
                close_header.status,
            );
        }

        debug!(
            "tree: write_file_compound done, wrote {} bytes",
            bytes_written
        );
        Ok(bytes_written)
    }

    /// Write data to a file (create or overwrite).
    ///
    /// For data that fits in MaxWriteSize (typically 64 KB to 8 MB), uses a
    /// compound CREATE+WRITE+FLUSH+CLOSE in a single round-trip. For larger
    /// data, falls back to the pipelined write path.
    ///
    /// Returns the total number of bytes written.
    pub async fn write_file(&self, conn: &mut Connection, path: &str, data: &[u8]) -> Result<u64> {
        let max_write = conn
            .params()
            .map(|p| p.max_write_size as usize)
            .unwrap_or(65536);
        if data.len() <= max_write {
            self.write_file_compound(conn, path, data).await
        } else {
            self.write_file_pipelined(conn, path, data).await
        }
    }

    /// Read a file using pipelined I/O with a sliding window.
    ///
    /// Opens the file, determines its size, then uses a sliding window to
    /// keep the pipe full: as each response arrives, the next request is sent
    /// immediately. Much faster than sequential [`read_file`](Self::read_file)
    /// for large files.
    ///
    /// Uses 64 KB chunks with CreditCharge=1 to maximize concurrency.
    /// The window is capped at 32 in-flight requests (2 MB).
    pub async fn read_file_pipelined(&self, conn: &mut Connection, path: &str) -> Result<Vec<u8>> {
        // Open the file.
        let (file_id, file_size) = self.open_file(conn, path).await?;

        if file_size == 0 {
            trace!(
                "tree: read_file_pipelined path={}, size=0 (empty file)",
                path
            );
            self.close_handle(conn, file_id).await?;
            return Ok(Vec::new());
        }

        // Balance chunk size for pipelining: small enough to keep many
        // in flight (sliding window benefit), large enough to minimize
        // per-chunk overhead (headers, signing).
        //
        // For files that fit in one read: use file size (no chunking).
        // For larger files: use 512 KB -- gives ~20 chunks per 10 MB
        // (enough for pipelining) with 8 credits per chunk (manageable).
        let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
        let pipeline_chunk = 512 * 1024_u32; // 512 KB
        let chunk_size = if file_size <= max_read as u64 {
            // File fits in one read -- no pipelining needed.
            (file_size as u32).min(max_read)
        } else {
            // Use pipeline chunk size, capped to MaxReadSize.
            pipeline_chunk.min(max_read)
        };
        let credit_charge = chunk_size.div_ceil(65536) as u16;
        let total_chunks = file_size.div_ceil(chunk_size as u64) as usize;
        trace!(
            "tree: read_file_pipelined path={}, size={}, chunk_size={}, credit_charge={}, total_chunks={}, credits={}",
            path, file_size, chunk_size, credit_charge, total_chunks, conn.credits()
        );

        let start = std::time::Instant::now();
        let result = self
            .read_pipelined_loop(
                conn,
                file_id,
                file_size,
                chunk_size,
                credit_charge,
                total_chunks,
            )
            .await;

        // Close the handle regardless of read result.
        let close_result = self.close_handle(conn, file_id).await;

        let data = result?;
        close_result?;

        let elapsed = start.elapsed();
        let mb = data.len() as f64 / (1024.0 * 1024.0);
        let mbps = if elapsed.as_secs_f64() > 0.0 {
            mb / elapsed.as_secs_f64()
        } else {
            0.0
        };
        debug!(
            "tree: read_file_pipelined done, read {} bytes in {:.2?} ({:.1} MB/s)",
            data.len(),
            elapsed,
            mbps
        );

        Ok(data)
    }

    /// Read a file using pipelined I/O with progress reporting and cancellation.
    ///
    /// Same as [`read_file_pipelined`](Self::read_file_pipelined) but calls
    /// `on_progress` after each chunk is received. Return
    /// `ControlFlow::Break(())` from the callback to cancel the read.
    pub async fn read_file_pipelined_with_progress<F>(
        &self,
        conn: &mut Connection,
        path: &str,
        mut on_progress: F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(Progress) -> ControlFlow<()>,
    {
        let (file_id, file_size) = self.open_file(conn, path).await?;

        if file_size == 0 {
            trace!(
                "tree: read_file_pipelined_with_progress path={}, size=0 (empty file)",
                path
            );
            self.close_handle(conn, file_id).await?;
            let _ = on_progress(Progress {
                bytes_transferred: 0,
                total_bytes: Some(0),
            });
            return Ok(Vec::new());
        }

        let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
        let pipeline_chunk = 512 * 1024_u32;
        let chunk_size = if file_size <= max_read as u64 {
            (file_size as u32).min(max_read)
        } else {
            pipeline_chunk.min(max_read)
        };
        let credit_charge = chunk_size.div_ceil(65536) as u16;
        let total_chunks = file_size.div_ceil(chunk_size as u64) as usize;
        trace!(
            "tree: read_file_pipelined_with_progress path={}, size={}, chunk_size={}, total_chunks={}",
            path, file_size, chunk_size, total_chunks
        );

        let result = self
            .read_pipelined_loop_with_progress(
                conn,
                file_id,
                file_size,
                chunk_size,
                credit_charge,
                total_chunks,
                &mut on_progress,
            )
            .await;

        // Close the handle regardless of read result.
        let close_result = self.close_handle(conn, file_id).await;

        let data = result?;
        close_result?;

        debug!(
            "tree: read_file_pipelined_with_progress done, read {} bytes",
            data.len()
        );
        Ok(data)
    }

    /// Start a streaming file download on this tree.
    ///
    /// Issues CREATE and returns a [`FileDownload`] that pulls the body in
    /// chunks via [`next_chunk`](FileDownload::next_chunk). Mirrors
    /// [`SmbClient::download`](crate::SmbClient::download) but accepts a
    /// borrowed [`Connection`] directly, so callers who hold a cloned
    /// `Connection` (see [`Connection::clone`]) can drive concurrent
    /// downloads on one SMB session.
    ///
    /// For files that fit in one READ (≤ `max_read_size`), prefer
    /// [`read_file_compound`](Self::read_file_compound) — 1 RTT vs. 3 RTTs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # async fn example(conn: &mut smb2::Connection, tree: &smb2::Tree) -> Result<(), smb2::Error> {
    /// let mut download = tree.download(conn, "big.bin").await?;
    /// while let Some(chunk) = download.next_chunk().await {
    ///     let bytes = chunk?;
    ///     // process bytes
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download<'a>(
        &'a self,
        conn: &'a mut Connection,
        path: &str,
    ) -> Result<FileDownload<'a>> {
        let (file_id, file_size) = self.open_file(conn, path).await?;
        let chunk_size = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
        Ok(FileDownload::new(
            self, conn, file_id, file_size, chunk_size,
        ))
    }

    /// Write a file using pipelined I/O with a sliding window.
    ///
    /// Opens/creates the file, then uses a sliding window to keep the pipe
    /// full: as each response arrives, the next request is sent immediately.
    /// Flushes to ensure data is persisted on the server. Much faster than
    /// sequential [`write_file`](Self::write_file) for large data.
    ///
    /// Uses MaxWriteSize chunks to minimize overhead for large payloads.
    pub async fn write_file_pipelined(
        &self,
        conn: &mut Connection,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        let normalized = self.format_path(path);

        if data.is_empty() {
            trace!(
                "tree: write_file_pipelined path={}, len=0 (empty write)",
                normalized
            );
            // Still create the file (to match write_file behavior).
            return self.write_file_compound(conn, path, data).await;
        }

        // Open (or create) the file for writing.
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_WRITE_DATA
                    | FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess(0),
            create_disposition: CreateDisposition::FileOverwriteIf,
            create_options: FILE_NON_DIRECTORY_FILE,
            name: normalized.clone(),
            create_contexts: vec![],
        };

        let frame = conn
            .execute(Command::Create, &req, Some(self.tree_id))
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let create_resp = CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        // Use MaxWriteSize for pipelined writes: minimizes overhead for
        // large payloads being sent (we're sending data, not just a small request).
        let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);
        let chunk_size = max_write;
        let credit_charge = chunk_size.div_ceil(65536) as u16;
        let total_chunks = data.len().div_ceil(chunk_size as usize);
        trace!(
            "tree: write_file_pipelined path={}, len={}, chunk_size={}, credit_charge={}, total_chunks={}, credits={}",
            normalized, data.len(), chunk_size, credit_charge, total_chunks, conn.credits()
        );

        let start = std::time::Instant::now();
        let result = self
            .write_pipelined_loop(conn, file_id, data, chunk_size, credit_charge, total_chunks)
            .await;

        // Flush to ensure data is persisted on the server.
        if result.is_ok() {
            self.flush_handle(conn, file_id).await?;
        }

        // Close the handle.
        let close_result = self.close_handle(conn, file_id).await;

        let bytes_written = result?;
        close_result?;

        let elapsed = start.elapsed();
        let mb = bytes_written as f64 / (1024.0 * 1024.0);
        let mbps = if elapsed.as_secs_f64() > 0.0 {
            mb / elapsed.as_secs_f64()
        } else {
            0.0
        };
        debug!(
            "tree: write_file_pipelined done, wrote {} bytes in {:.2?} ({:.1} MB/s)",
            bytes_written, elapsed, mbps
        );

        Ok(bytes_written)
    }

    /// Write a file from a streaming source using pipelined I/O.
    ///
    /// Pulls data on demand from a callback, so you never need the full
    /// file in memory. Ideal for writing from a network stream, a
    /// channel, or any producer that generates data incrementally.
    ///
    /// # Callback contract
    ///
    /// Each call to `next_chunk` must return one of:
    /// - `Some(Ok(data))` — the next chunk to write (any size; chunks
    ///   larger than `MaxWriteSize` are split automatically)
    /// - `Some(Err(e))` — an I/O error from the source; aborts the
    ///   write, drains in-flight responses, and propagates the error
    /// - `None` — end of stream; all remaining in-flight writes are
    ///   completed before returning
    ///
    /// An empty `Vec<u8>` in `Some(Ok(vec![]))` is treated the same as
    /// `None` (end of stream).
    ///
    /// # Behavior
    ///
    /// - Returns the total number of bytes the server acknowledged.
    /// - The file handle is always closed, even on error.
    /// - If `next_chunk` returns `None` on the first call, an empty file
    ///   is created.
    /// - On early termination (callback error or server error), a partial
    ///   file may remain on the server. The caller is responsible for
    ///   cleanup (for example, calling [`delete_file`](Self::delete_file)).
    ///
    /// # Performance
    ///
    /// Uses a sliding window of up to 32 in-flight WRITE requests (same
    /// approach as [`write_file_pipelined`](Self::write_file_pipelined)),
    /// so throughput stays high even on high-latency links. Memory usage
    /// is bounded to the sliding window, not the full file size.
    ///
    /// # When to use which write method
    ///
    /// | Method | Best for |
    /// |--------|----------|
    /// | [`write_file`](Self::write_file) | Small files that fit in a single compound (one round-trip) |
    /// | [`write_file_pipelined`](Self::write_file_pipelined) | Large files already in a `&[u8]` buffer |
    /// | `write_file_streamed` | Data produced incrementally (streams, channels, generators) |
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(tree: &smb2::client::Tree, conn: &mut smb2::client::Connection) -> smb2::Result<()> {
    /// let chunks = vec![b"hello ".to_vec(), b"world".to_vec()];
    /// let mut iter = chunks.into_iter();
    /// let mut next = || iter.next().map(Ok);
    ///
    /// let bytes_written = tree.write_file_streamed(conn, "greeting.txt", &mut next).await?;
    /// assert_eq!(bytes_written, 11);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn write_file_streamed<F>(
        &self,
        conn: &mut Connection,
        path: &str,
        next_chunk: &mut F,
    ) -> Result<u64>
    where
        F: FnMut() -> Option<std::result::Result<Vec<u8>, std::io::Error>>,
    {
        trace!("tree: write_file_streamed path={}", path);

        // Open (or create) the file for writing.
        let file_id = self.open_file_for_write(conn, path).await?;

        let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);

        let start = std::time::Instant::now();
        let result = self
            .write_streamed_loop(conn, file_id, next_chunk, max_write)
            .await;

        // Flush to ensure data is persisted on the server.
        if result.is_ok() {
            self.flush_handle(conn, file_id).await?;
        }

        // Close the handle (always, even on error).
        let close_result = self.close_handle(conn, file_id).await;

        let bytes_written = result?;
        close_result?;

        let elapsed = start.elapsed();
        let mb = bytes_written as f64 / (1024.0 * 1024.0);
        let mbps = if elapsed.as_secs_f64() > 0.0 {
            mb / elapsed.as_secs_f64()
        } else {
            0.0
        };
        debug!(
            "tree: write_file_streamed done, wrote {} bytes in {:.2?} ({:.1} MB/s)",
            bytes_written, elapsed, mbps
        );

        Ok(bytes_written)
    }

    /// Open a random-access [`FileReader`](super::stream::FileReader) that owns
    /// its `Connection` and `Arc<Tree>`.
    ///
    /// Opens the file for reading and hands back a reader that serves any number
    /// of positioned reads at arbitrary offsets over the one open handle, then
    /// [`close`](super::stream::FileReader::close)s. The returned reader is
    /// `'static` — multiple readers built from clones of the same `Connection`
    /// pipeline their READs over a single SMB session.
    pub async fn open_file_reader(
        self: &Arc<Self>,
        conn: Connection,
        path: &str,
    ) -> Result<super::stream::FileReader> {
        super::stream::open_file_reader(Arc::clone(self), conn, path).await
    }

    /// Open a source handle for an identity-checked rename or deletion.
    ///
    /// The returned metadata belongs to the same handle the mutation methods
    /// operate on, eliminating a path replacement between stat and mutation.
    pub async fn open_mutation_handle(
        self: &Arc<Self>,
        mut conn: Connection,
        path: &str,
    ) -> Result<MutationHandle> {
        let normalized = self.format_path(path);
        let generation = conn.generation();
        let session_id = conn.session_id();
        let (file_id, info) = self
            .open_file_for_mutation(&mut conn, &normalized, generation, session_id)
            .await?;
        Ok(MutationHandle {
            tree: Arc::clone(self),
            conn,
            generation,
            session_id,
            file_id,
            info,
            closed: false,
        })
    }

    /// Create a push-based pipelined streaming writer that owns its
    /// `Connection` and `Arc<Tree>`.
    ///
    /// Opens (or creates) the file for writing and returns a
    /// [`FileWriter`](super::stream::FileWriter) that accepts pushed
    /// chunks. The caller drives writes at their own pace and calls
    /// [`FileWriter::finish`](super::stream::FileWriter::finish) to
    /// flush and close.
    ///
    /// The returned writer is `'static` — multiple writers built from
    /// clones of the same `Connection` pipeline their WRITEs over a
    /// single SMB session without external locking.
    pub async fn create_file_writer(
        self: &Arc<Self>,
        conn: Connection,
        path: &str,
    ) -> Result<super::stream::FileWriter> {
        super::stream::open_file_writer(Arc::clone(self), conn, path).await
    }

    /// Open a push-based pipelined file writer with **exclusive-create**
    /// semantics. Same shape as [`Tree::create_file_writer`], but the CREATE
    /// uses `FileCreate` disposition: if the file already exists the open
    /// fails with [`crate::ErrorKind::AlreadyExists`]
    /// instead of truncating it.
    ///
    /// Use this when the consumer needs a race-free "create only if absent"
    /// write — for example, a file manager's "New File" action where
    /// silently clobbering an existing file is unsafe.
    ///
    /// The returned writer is `'static` and behaves identically to
    /// `create_file_writer` from there on; chunks are pipelined over the
    /// shared SMB session.
    pub async fn create_file_writer_exclusive(
        self: &Arc<Self>,
        conn: Connection,
        path: &str,
    ) -> Result<super::stream::FileWriter> {
        super::stream::open_file_writer_exclusive(Arc::clone(self), conn, path).await
    }

    /// Open a push-based pipelined file writer positioned at `offset`. Same
    /// shape as [`Tree::create_file_writer`], but the file is opened without
    /// truncating (`FileOpenIf`) and the writer's first byte lands at `offset`.
    ///
    /// The natural way to append after a server-side-copied prefix
    /// ([`server_side_copy_range`](Self::server_side_copy_range)) or to patch a
    /// known region of an existing file.
    pub async fn create_file_writer_at(
        self: &Arc<Self>,
        conn: Connection,
        path: &str,
        offset: u64,
    ) -> Result<super::stream::FileWriter> {
        super::stream::open_file_writer_at(Arc::clone(self), conn, path, offset).await
    }

    /// Open an existing file for positioned streaming writes.
    ///
    /// Unlike [`create_file_writer_at`](Self::create_file_writer_at), this
    /// never creates a missing file. The expected identity and minimum length
    /// are checked on the retained write handle, so path replacement and
    /// truncation between checkpoint validation and open fail closed.
    pub async fn open_existing_file_writer_at(
        self: &Arc<Self>,
        conn: Connection,
        path: &str,
        offset: u64,
        expected_identity: FileIdentity,
    ) -> Result<super::stream::FileWriter> {
        super::stream::open_existing_file_writer_at(
            Arc::clone(self),
            conn,
            path,
            offset,
            expected_identity,
        )
        .await
    }

    /// Create a directory.
    ///
    /// Opens the path with `FileCreate` disposition and `FILE_DIRECTORY_FILE`
    /// option, then immediately closes the handle.
    pub async fn create_directory(&self, conn: &mut Connection, path: &str) -> Result<()> {
        let normalized = self.format_path(path);
        trace!("tree: create_directory path={}", normalized);

        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_ATTRIBUTES | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: FILE_ATTRIBUTE_DIRECTORY,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileCreate,
            create_options: FILE_DIRECTORY_FILE,
            name: normalized.clone(),
            create_contexts: vec![],
        };

        let frame = conn
            .execute(Command::Create, &req, Some(self.tree_id))
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let create_resp = CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        // Close the handle immediately.
        self.close_handle(conn, file_id).await?;
        debug!("tree: created directory={}", normalized);
        Ok(())
    }

    /// Delete a directory using a compound request (1 round-trip).
    ///
    /// Sends CREATE (with `DELETE_ON_CLOSE`) + CLOSE as a single compound
    /// message. The directory must be empty.
    pub async fn delete_directory(&self, conn: &mut Connection, path: &str) -> Result<()> {
        self.delete_compound(conn, path, FILE_DIRECTORY_FILE, "directory")
            .await
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// Compound CREATE + SET_INFO (FileDispositionInformation) + CLOSE in a
    /// single round-trip.
    ///
    /// `type_option` selects file vs directory (`FILE_NON_DIRECTORY_FILE`
    /// or `FILE_DIRECTORY_FILE`). `kind` is used only for log messages.
    ///
    /// Don't switch this back to `FILE_DELETE_ON_CLOSE`. Samba accepts a
    /// delete-on-close CREATE against a non-empty directory, answers both
    /// CREATE and CLOSE with `STATUS_SUCCESS`, and then doesn't delete
    /// anything — so the caller is told a delete happened that never did.
    /// Setting the disposition explicitly makes the server validate while it
    /// still has somewhere to put the error, and it comes back as
    /// `STATUS_DIRECTORY_NOT_EMPTY`.
    async fn delete_compound(
        &self,
        conn: &mut Connection,
        path: &str,
        type_option: u32,
        kind: &str,
    ) -> Result<()> {
        let normalized = self.format_path(path);
        trace!("tree: delete_{} (compound) path={}", kind, normalized);

        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::DELETE | FileAccessMask::FILE_READ_ATTRIBUTES,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: type_option,
            name: normalized.clone(),
            create_contexts: vec![],
        };

        let disposition_req = SetInfoRequest {
            info_type: InfoType::File,
            file_info_class: FILE_DISPOSITION_INFORMATION,
            additional_information: 0,
            file_id: FileId::SENTINEL,
            buffer: vec![1], // DeletePending = true (MS-FSCC 2.4.11).
        };

        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let ops = [
            CompoundOp {
                command: Command::Create,
                body: &create_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::SetInfo,
                body: &disposition_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::Close,
                body: &close_req,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
        ];

        let responses = all_or_first_err(conn.execute_compound(&ops).await?, ops.len())?;

        let create_header = &responses[0].header;
        let create_body = &responses[0].body;
        let setinfo_header = &responses[1].header;
        let close_header = &responses[2].header;

        // If CREATE failed, all ops in the compound fail (cascaded). No handle to clean up.
        if create_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        // CREATE succeeded, so a handle exists. Any later failure has to close
        // it by hand: a cascaded CLOSE fails along with the op before it and
        // leaves the handle open on the server.
        for (header, command) in [
            (setinfo_header, Command::SetInfo),
            (close_header, Command::Close),
        ] {
            if header.status != NtStatus::SUCCESS {
                let mut cursor = ReadCursor::new(create_body);
                let create_resp = CreateResponse::unpack(&mut cursor)?;
                warn!(
                    "tree: compound {:?} failed ({:?}), issuing standalone CLOSE",
                    command, header.status
                );
                let _ = self.close_handle(conn, create_resp.file_id).await;
                return Err(Error::Protocol {
                    status: header.status,
                    command,
                });
            }
        }

        debug!("tree: deleted {}={}", kind, normalized);
        Ok(())
    }

    /// Open a directory handle.
    async fn open_directory(&self, conn: &mut Connection, path: &str) -> Result<FileId> {
        let path = self.format_path(path);
        let generation = conn.generation();
        let session_id = conn.session_id();
        self.open_directory_bound(conn, &path, generation, session_id)
            .await
    }

    async fn open_directory_bound(
        &self,
        conn: &mut Connection,
        path: &str,
        generation: u64,
        session_id: SessionId,
    ) -> Result<FileId> {
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_DATA
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: FILE_DIRECTORY_FILE,
            name: path.to_string(),
            create_contexts: vec![],
        };

        let frame = conn
            .execute_bound(
                Command::Create,
                &req,
                Some(self.tree_id),
                generation,
                session_id,
            )
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = CreateResponse::unpack(&mut cursor)?;
        if conn.generation() != generation || conn.session_id() != session_id {
            return Err(Error::Disconnected);
        }
        Ok(resp.file_id)
    }

    /// Open a file handle for reading and return the file ID and size.
    ///
    /// Sends a single CREATE with read access, `FileOpen` disposition (fail
    /// if absent), and the standard share mask. Returns the server's
    /// [`FileId`] plus the file's size in bytes (end-of-file offset) so
    /// callers can size their read loop.
    ///
    /// Most callers want [`read_file_compound`](Self::read_file_compound),
    /// [`read_file_pipelined`](Self::read_file_pipelined), or
    /// [`download`](Self::download), which all open the file, read it, and
    /// close it in one call. Use `open_file` directly when you want to build
    /// a custom read loop — for example, constructing a [`FileDownload`]
    /// with a non-default `chunk_size` via
    /// [`FileDownload::new`](crate::client::stream::FileDownload::new).
    ///
    /// The caller is responsible for closing the handle when done (either
    /// by handing it to a [`FileDownload`], which closes on completion or
    /// drop, or by calling the internal close path). Leaking the handle
    /// wastes server resources.
    pub async fn open_file(&self, conn: &mut Connection, path: &str) -> Result<(FileId, u64)> {
        let path = self.format_path(path);
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_DATA
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: path,
            create_contexts: vec![],
        };

        let frame = conn
            .execute(Command::Create, &req, Some(self.tree_id))
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = CreateResponse::unpack(&mut cursor)?;
        Ok((resp.file_id, resp.end_of_file))
    }

    /// Open a file or directory with DELETE access and capture metadata for
    /// that exact handle.
    async fn open_file_for_mutation(
        &self,
        conn: &mut Connection,
        path: &str,
        generation: u64,
        session_id: SessionId,
    ) -> Result<(FileId, FileInfo)> {
        let request = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::DELETE
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: path.to_owned(),
            create_contexts: vec![],
        };
        let frame = conn
            .execute_bound(
                Command::Create,
                &request,
                Some(self.tree_id),
                generation,
                session_id,
            )
            .await?;
        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }
        let response = CreateResponse::unpack(&mut ReadCursor::new(&frame.body))?;
        if conn.generation() != generation || conn.session_id() != session_id {
            return Err(Error::Disconnected);
        }

        let mut index_request = FileIdentity::index_query();
        index_request.file_id = response.file_id;
        let mut volume_request = FileIdentity::volume_query();
        volume_request.file_id = response.file_id;
        let operations = [
            CompoundOp {
                command: Command::QueryInfo,
                body: &index_request,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
            CompoundOp {
                command: Command::QueryInfo,
                body: &volume_request,
                tree_id: Some(self.tree_id),
                credit_charge: CreditCharge(1),
            },
        ];
        let frames = match conn
            .execute_compound_bound(&operations, generation, session_id)
            .await
        {
            Ok(frames) => match all_or_first_err(frames, operations.len()) {
                Ok(frames) => frames,
                Err(error) => {
                    let _ = Self::close_handle_bound(
                        self.tree_id,
                        conn,
                        response.file_id,
                        generation,
                        session_id,
                    )
                    .await;
                    return Err(error);
                }
            },
            Err(error) => {
                let _ = Self::close_handle_bound(
                    self.tree_id,
                    conn,
                    response.file_id,
                    generation,
                    session_id,
                )
                .await;
                return Err(error);
            }
        };
        if conn.generation() != generation || conn.session_id() != session_id {
            return Err(Error::Disconnected);
        }
        let identity = FileIdentity::from_frames(frames.first(), frames.get(1));
        let is_directory = response.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        Ok((
            response.file_id,
            FileInfo {
                size: response.end_of_file,
                is_directory,
                created: response.creation_time,
                modified: response.last_write_time,
                accessed: response.last_access_time,
                changed: response.change_time,
                identity,
            },
        ))
    }

    /// Open (or create) a file for writing, returning the file handle.
    ///
    /// Uses `FileOverwriteIf` disposition (create if absent, overwrite if present)
    /// and requests write access. Used by [`FileUpload`](crate::client::stream::FileUpload).
    pub(crate) async fn open_file_for_write(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<FileId> {
        let generation = conn.generation();
        let session_id = conn.session_id();
        self.open_file_for_write_bound(conn, path, generation, session_id)
            .await
    }

    pub(crate) async fn open_file_for_write_bound(
        &self,
        conn: &mut Connection,
        path: &str,
        generation: u64,
        session_id: SessionId,
    ) -> Result<FileId> {
        self.open_file_for_write_with_disposition(
            conn,
            path,
            CreateDisposition::FileOverwriteIf,
            generation,
            session_id,
        )
        .await
    }

    /// Open a file for writing using a specific `CreateDisposition`.
    ///
    /// Shared body for the overwrite, exclusive-create, and positioned writer
    /// opens. Held private so the disposition stays a strict allow-list inside
    /// the crate.
    async fn open_file_for_write_with_disposition(
        &self,
        conn: &mut Connection,
        path: &str,
        create_disposition: CreateDisposition,
        generation: u64,
        session_id: SessionId,
    ) -> Result<FileId> {
        let path = self.format_path(path);
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_WRITE_DATA
                    | FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess(0),
            create_disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            name: path,
            create_contexts: vec![],
        };

        let frame = conn
            .execute_bound(
                Command::Create,
                &req,
                Some(self.tree_id),
                generation,
                session_id,
            )
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = CreateResponse::unpack(&mut cursor)?;
        if conn.generation() != generation || conn.session_id() != session_id {
            return Err(Error::Disconnected);
        }
        Ok(resp.file_id)
    }

    /// Open a file for writing with `FileCreate` disposition (exclusive create).
    ///
    /// Returns the file handle on success. When the file already exists the
    /// server returns `STATUS_OBJECT_NAME_COLLISION`, which surfaces as
    /// [`crate::ErrorKind::AlreadyExists`]. Used by
    /// [`Tree::create_file_writer_exclusive`](Self::create_file_writer_exclusive)
    /// so consumers can implement a race-free "create only if absent" file
    /// write.
    ///
    /// Pairs with [`open_file_for_write`](Self::open_file_for_write), which
    /// uses `FileOverwriteIf` (truncating).
    pub(crate) async fn open_file_for_exclusive_create_bound(
        &self,
        conn: &mut Connection,
        path: &str,
        generation: u64,
        session_id: SessionId,
    ) -> Result<FileId> {
        self.open_file_for_write_with_disposition(
            conn,
            path,
            CreateDisposition::FileCreate,
            generation,
            session_id,
        )
        .await
    }

    /// Open an existing file (or create it if absent) for writing *without*
    /// truncating it, returning the file handle.
    ///
    /// Uses `FileOpenIf` disposition and requests write access. Unlike
    /// [`open_file_for_write`](Self::open_file_for_write) (`FileOverwriteIf`,
    /// which truncates), this preserves existing content so a caller can write
    /// at an arbitrary offset over or past it. Used by the positioned
    /// [`FileWriter`](crate::client::stream::FileWriter) built via
    /// [`create_file_writer_at`](Self::create_file_writer_at).
    pub(crate) async fn open_file_for_write_at_bound(
        &self,
        conn: &mut Connection,
        path: &str,
        generation: u64,
        session_id: SessionId,
    ) -> Result<FileId> {
        self.open_file_for_write_with_disposition(
            conn,
            path,
            CreateDisposition::FileOpenIf,
            generation,
            session_id,
        )
        .await
    }

    /// Open an existing file for positioned writes without truncating it.
    ///
    /// Uses `FileOpen` and queries identity on the related handle. The caller
    /// compares the returned identity and CREATE length before constructing a
    /// writer, so missing, replaced, and truncated checkpoints fail closed.
    pub(crate) async fn open_existing_file_for_write_at(
        &self,
        conn: &mut Connection,
        path: &str,
        generation: u64,
        session_id: SessionId,
    ) -> Result<(FileId, u64, Option<FileIdentity>)> {
        let path = self.format_path(path);
        let request = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_WRITE_DATA
                    | FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0x80,
            share_access: ShareAccess(0),
            create_disposition: CreateDisposition::FileOpen,
            create_options: FILE_NON_DIRECTORY_FILE,
            name: path,
            create_contexts: vec![],
        };
        let (frame, identity) = self
            .create_and_identify_bound(conn, &request, generation, session_id)
            .await?;
        let response = CreateResponse::unpack(&mut ReadCursor::new(&frame.body))?;
        Ok((response.file_id, response.end_of_file, identity))
    }

    /// Open (or create) a file with combined read+write access, **without**
    /// truncating it, returning the handle and its current size.
    ///
    /// Requests `FILE_READ_DATA | FILE_WRITE_DATA` with `FileOpenIf`
    /// disposition (open if present, create if absent) and preserves existing
    /// content. Use it to open a destination for the low-level server-side copy
    /// primitives ([`copy_chunks`](Self::copy_chunks),
    /// [`server_side_copy_range`](Self::server_side_copy_range)) — those need
    /// the destination handle to carry read access as well as write for
    /// [`FSCTL_SRV_COPYCHUNK`](crate::msg::ioctl::FSCTL_SRV_COPYCHUNK) (MS-SMB2
    /// 3.3.5.15.6). Close it with [`close_handle`](Self::close_handle) when done.
    pub async fn open_file_readwrite(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<(FileId, u64)> {
        self.open_readwrite_with_disposition(conn, path, CreateDisposition::FileOpenIf)
            .await
    }

    /// Read+write open with `FileOverwriteIf` (truncating). Used by the
    /// whole-file [`server_side_copy_file`](Self::server_side_copy_file), where
    /// the destination becomes an exact copy of the source.
    pub(crate) async fn open_readwrite_overwrite(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<(FileId, u64)> {
        self.open_readwrite_with_disposition(conn, path, CreateDisposition::FileOverwriteIf)
            .await
    }

    /// Shared body for the read+write opens. Requests read+write data access so
    /// the handle works as a server-side copy destination.
    async fn open_readwrite_with_disposition(
        &self,
        conn: &mut Connection,
        path: &str,
        create_disposition: CreateDisposition,
    ) -> Result<(FileId, u64)> {
        let path = self.format_path(path);
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_DATA
                    | FileAccessMask::FILE_WRITE_DATA
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            name: path,
            create_contexts: vec![],
        };

        let frame = conn
            .execute(Command::Create, &req, Some(self.tree_id))
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = CreateResponse::unpack(&mut cursor)?;
        Ok((resp.file_id, resp.end_of_file))
    }

    /// Default per-QUERY_DIRECTORY output-buffer length.
    ///
    /// Capped at 65536 so that CreditCharge=1 is valid: the spec requires
    /// CreditCharge = 1 + (OutputBufferLength - 1) / 65536 for multi-credit
    /// dialects, and 65536 keeps it at 1 while still holding plenty of entries.
    fn default_query_buffer_len(conn: &Connection) -> u32 {
        conn.params()
            .map(|p| p.max_transact_size.min(65536))
            .unwrap_or(65536)
    }

    /// Issue one QUERY_DIRECTORY round trip and parse its reply.
    ///
    /// The single-source of the CREATE-less half of a listing: both
    /// [`DirectoryReader::next_batch`] and
    /// [`list_directory_instrumented`](Self::list_directory_instrumented) drive
    /// this, so they always exercise the same wire request.
    ///
    /// `output_buffer_length` above 65536 needs a matching multi-credit charge;
    /// this computes it as ceil(len / 65536).
    async fn query_directory_step(
        tree_id: TreeId,
        conn: &mut Connection,
        file_id: FileId,
        restart: bool,
        output_buffer_length: u32,
        layout: DirectoryInfoLayout,
        generation: u64,
        session_id: SessionId,
    ) -> Result<QueryStepOutcome> {
        let req = QueryDirectoryRequest {
            file_information_class: layout.information_class(),
            flags: QueryDirectoryFlags(if restart {
                QueryDirectoryFlags::RESTART_SCANS
            } else {
                0
            }),
            file_index: 0,
            file_id,
            output_buffer_length,
            file_name: "*".to_string(),
        };
        let credit_charge =
            CreditCharge((output_buffer_length as u64).div_ceil(65536).max(1) as u16);

        let frame = conn
            .execute_with_credits_bound(
                Command::QueryDirectory,
                &req,
                Some(tree_id),
                credit_charge,
                generation,
                session_id,
            )
            .await?;

        if frame.header.status == NtStatus::NO_MORE_FILES {
            return Ok(QueryStepOutcome::NoMoreFiles {
                bytes: frame.body.len(),
            });
        }

        if layout == DirectoryInfoLayout::FileIdFull
            && matches!(
                frame.header.status,
                NtStatus::NOT_SUPPORTED | NtStatus::INVALID_INFO_CLASS
            )
        {
            return Ok(QueryStepOutcome::UnsupportedInformationClass {
                bytes: frame.body.len(),
            });
        }

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::QueryDirectory,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = QueryDirectoryResponse::unpack(&mut cursor)?;
        let bytes = resp.output_buffer.len();

        let entries = parse_directory_info(&resp.output_buffer, layout)?;
        for e in &entries {
            trace!(
                "tree: dir_entry name={}, size={}, is_dir={}",
                e.name,
                e.size,
                e.is_directory
            );
        }
        Ok(QueryStepOutcome::Entries { entries, bytes })
    }

    /// Read file data in chunks.
    #[allow(dead_code)] // Will be used by read_file_pipelined for large-file chunked reads.
    async fn read_loop(
        &self,
        conn: &mut Connection,
        file_id: FileId,
        file_size: u64,
    ) -> Result<Vec<u8>> {
        let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);

        let mut data = Vec::with_capacity(file_size as usize);
        let mut offset = 0u64;

        loop {
            let remaining = file_size.saturating_sub(offset);
            if remaining == 0 {
                break;
            }

            let chunk_size = remaining.min(max_read as u64) as u32;

            let req = ReadRequest {
                padding: 0x50,
                flags: 0,
                length: chunk_size,
                offset,
                file_id,
                minimum_count: 0,
                channel: SMB2_CHANNEL_NONE,
                remaining_bytes: 0,
                read_channel_info: vec![],
            };

            let frame = conn
                .execute(Command::Read, &req, Some(self.tree_id))
                .await?;

            // STATUS_END_OF_FILE means we read past the end.
            if frame.header.status == NtStatus::END_OF_FILE {
                break;
            }

            if frame.header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: frame.header.status,
                    command: Command::Read,
                });
            }

            let mut cursor = ReadCursor::new(&frame.body);
            let resp = ReadResponse::unpack(&mut cursor)?;

            if resp.data.is_empty() {
                break;
            }

            offset += resp.data.len() as u64;
            data.extend_from_slice(&resp.data);
        }

        Ok(data)
    }

    /// Pipelined read using a sliding window.
    ///
    /// Instead of batch send/receive phases, each received response
    /// immediately triggers the next send. The pipe stays full at all times,
    /// eliminating idle gaps between batches.
    async fn read_pipelined_loop(
        &self,
        conn: &mut Connection,
        file_id: FileId,
        file_size: u64,
        chunk_size: u32,
        credit_charge: u16,
        total_chunks: usize,
    ) -> Result<Vec<u8>> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let mut data = vec![0u8; file_size as usize];
        let mut chunks_sent = 0usize;
        let mut chunks_received = 0usize;

        // How many requests to keep queued, not how many the credit budget
        // allows: `Connection` reserves credits per send and parks a request
        // that can't afford one, so throttling here as well could only
        // under-send.
        let initial_window = total_chunks.min(MAX_PIPELINE_WINDOW);

        trace!(
            "tree: pipeline read sliding window: initial_window={}, total_chunks={}, credits={}",
            initial_window,
            total_chunks,
            conn.credits()
        );

        // Spawn each chunk read as an independent `execute_with_credits`
        // future. `FuturesUnordered` polls them concurrently — the actor-
        // based receiver task routes responses by `MessageId`, so all
        // chunks compete fairly even when they arrive out of order.
        let mut in_flight = FuturesUnordered::new();
        let build_req = |chunk_index: usize| -> ReadRequest {
            let offset = chunk_index as u64 * chunk_size as u64;
            let this_chunk = if chunk_index == total_chunks - 1 {
                (file_size - offset) as u32
            } else {
                chunk_size
            };
            ReadRequest {
                padding: 0x50,
                flags: 0,
                length: this_chunk,
                offset,
                file_id,
                minimum_count: 0,
                channel: SMB2_CHANNEL_NONE,
                remaining_bytes: 0,
                read_channel_info: vec![],
            }
        };
        let launch_chunk = |conn: &Connection, chunk_index: usize, tree_id: TreeId| -> _ {
            let c = conn.clone();
            let req = build_req(chunk_index);
            async move {
                let frame = c
                    .execute_with_credits(
                        Command::Read,
                        &req,
                        Some(tree_id),
                        CreditCharge(credit_charge),
                    )
                    .await;
                (chunk_index, frame)
            }
        };

        for _ in 0..initial_window {
            in_flight.push(launch_chunk(conn, chunks_sent, self.tree_id));
            chunks_sent += 1;
        }

        while chunks_received < total_chunks {
            let Some((chunk_index, frame_result)) = in_flight.next().await else {
                break;
            };
            chunks_received += 1;
            let frame = frame_result?;

            if frame.header.status == NtStatus::END_OF_FILE {
                // File is shorter than expected. Keep draining but don't
                // launch more.
                continue;
            }

            if frame.header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: frame.header.status,
                    command: Command::Read,
                });
            }

            let mut cursor = ReadCursor::new(&frame.body);
            let resp = ReadResponse::unpack(&mut cursor)?;

            if !resp.data.is_empty() {
                let dest_offset = chunk_index as u64 * chunk_size as u64;
                let dest_end = (dest_offset as usize + resp.data.len()).min(data.len());
                let src_len = dest_end - dest_offset as usize;
                data[dest_offset as usize..dest_end].copy_from_slice(&resp.data[..src_len]);
            }

            if chunks_sent < total_chunks {
                in_flight.push(launch_chunk(conn, chunks_sent, self.tree_id));
                chunks_sent += 1;
            }
        }

        Ok(data)
    }

    /// Pipelined read with progress callback and cancellation.
    ///
    /// Same sliding window as `read_pipelined_loop`, but calls `on_progress`
    /// after each chunk. Returns `Error::Cancelled` if the callback breaks.
    async fn read_pipelined_loop_with_progress<F>(
        &self,
        conn: &mut Connection,
        file_id: FileId,
        file_size: u64,
        chunk_size: u32,
        credit_charge: u16,
        total_chunks: usize,
        on_progress: &mut F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(Progress) -> ControlFlow<()>,
    {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let mut data = vec![0u8; file_size as usize];
        let mut chunks_sent = 0usize;
        let mut chunks_received = 0usize;
        let mut bytes_received = 0u64;

        // How many requests to keep queued, not how many the credit budget
        // allows: `Connection` reserves credits per send and parks a request
        // that can't afford one, so throttling here as well could only
        // under-send.
        let initial_window = total_chunks.min(MAX_PIPELINE_WINDOW);

        let mut in_flight = FuturesUnordered::new();
        let build_req = |chunk_index: usize| -> ReadRequest {
            let offset = chunk_index as u64 * chunk_size as u64;
            let this_chunk = if chunk_index == total_chunks - 1 {
                (file_size - offset) as u32
            } else {
                chunk_size
            };
            ReadRequest {
                padding: 0x50,
                flags: 0,
                length: this_chunk,
                offset,
                file_id,
                minimum_count: 0,
                channel: SMB2_CHANNEL_NONE,
                remaining_bytes: 0,
                read_channel_info: vec![],
            }
        };
        let launch_chunk = |conn: &Connection, chunk_index: usize, tree_id: TreeId| {
            let c = conn.clone();
            let req = build_req(chunk_index);
            async move {
                let frame = c
                    .execute_with_credits(
                        Command::Read,
                        &req,
                        Some(tree_id),
                        CreditCharge(credit_charge),
                    )
                    .await;
                (chunk_index, frame)
            }
        };

        for _ in 0..initial_window {
            in_flight.push(launch_chunk(conn, chunks_sent, self.tree_id));
            chunks_sent += 1;
        }

        while chunks_received < total_chunks {
            let Some((chunk_index, frame_result)) = in_flight.next().await else {
                break;
            };
            chunks_received += 1;
            let frame = frame_result?;

            if frame.header.status == NtStatus::END_OF_FILE {
                continue;
            }

            if frame.header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: frame.header.status,
                    command: Command::Read,
                });
            }

            let mut cursor = ReadCursor::new(&frame.body);
            let resp = ReadResponse::unpack(&mut cursor)?;

            if !resp.data.is_empty() {
                let dest_offset = chunk_index as u64 * chunk_size as u64;
                let dest_end = (dest_offset as usize + resp.data.len()).min(data.len());
                let src_len = dest_end - dest_offset as usize;
                data[dest_offset as usize..dest_end].copy_from_slice(&resp.data[..src_len]);
                bytes_received += src_len as u64;
            }

            let progress = Progress {
                bytes_transferred: bytes_received,
                total_bytes: Some(file_size),
            };
            if let ControlFlow::Break(()) = on_progress(progress) {
                return Err(Error::Cancelled);
            }

            if chunks_sent < total_chunks {
                in_flight.push(launch_chunk(conn, chunks_sent, self.tree_id));
                chunks_sent += 1;
            }
        }

        Ok(data)
    }

    /// Pipelined write using a sliding window.
    ///
    /// Instead of batch send/receive phases, each received response
    /// immediately triggers the next send. The pipe stays full at all times.
    async fn write_pipelined_loop(
        &self,
        conn: &mut Connection,
        file_id: FileId,
        data: &[u8],
        chunk_size: u32,
        credit_charge: u16,
        total_chunks: usize,
    ) -> Result<u64> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let mut chunks_sent = 0usize;
        let mut chunks_received = 0usize;
        let mut total_written = 0u64;

        // How many requests to keep queued, not how many the credit budget
        // allows: `Connection` reserves credits per send and parks a request
        // that can't afford one, so throttling here as well could only
        // under-send.
        let initial_window = total_chunks.min(MAX_PIPELINE_WINDOW);

        trace!(
            "tree: pipeline write sliding window: initial_window={}, total_chunks={}, credits={}",
            initial_window,
            total_chunks,
            conn.credits()
        );

        let mut in_flight = FuturesUnordered::new();
        let build_req = |chunk_index: usize| -> WriteRequest {
            let offset = chunk_index * chunk_size as usize;
            let end = (offset + chunk_size as usize).min(data.len());
            let chunk = &data[offset..end];
            WriteRequest {
                data_offset: 0x70,
                offset: offset as u64,
                file_id,
                channel: 0,
                remaining_bytes: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: 0,
                data: chunk.to_vec(),
            }
        };
        let launch_chunk = |conn: &Connection, chunk_index: usize, tree_id: TreeId| {
            let c = conn.clone();
            let req = build_req(chunk_index);
            async move {
                let frame = c
                    .execute_with_credits(
                        Command::Write,
                        &req,
                        Some(tree_id),
                        CreditCharge(credit_charge),
                    )
                    .await;
                (chunk_index, frame)
            }
        };

        for _ in 0..initial_window {
            in_flight.push(launch_chunk(conn, chunks_sent, self.tree_id));
            chunks_sent += 1;
        }

        while chunks_received < total_chunks {
            let Some((_chunk_index, frame_result)) = in_flight.next().await else {
                break;
            };
            chunks_received += 1;
            let frame = frame_result?;

            if frame.header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: frame.header.status,
                    command: Command::Write,
                });
            }

            let mut cursor = ReadCursor::new(&frame.body);
            let resp = WriteResponse::unpack(&mut cursor)?;
            total_written += resp.count as u64;

            if chunks_sent < total_chunks {
                in_flight.push(launch_chunk(conn, chunks_sent, self.tree_id));
                chunks_sent += 1;
            }
        }

        Ok(total_written)
    }

    /// Inner loop for streamed writes with a sliding window.
    ///
    /// Pulls chunks from the callback, splits them if larger than
    /// `max_write`, and sends WRITE requests. Uses a sliding window
    /// of in-flight requests for throughput.
    async fn write_streamed_loop<F>(
        &self,
        conn: &mut Connection,
        file_id: FileId,
        next_chunk: &mut F,
        max_write: u32,
    ) -> Result<u64>
    where
        F: FnMut() -> Option<std::result::Result<Vec<u8>, std::io::Error>>,
    {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        type BoxedExecute = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<crate::client::connection::Frame>> + Send>,
        >;

        let mut offset = 0u64;
        let mut in_flight = 0usize;
        let mut total_written = 0u64;
        let mut done = false; // callback exhausted or errored
        let mut callback_err: Option<std::io::Error> = None;
        let mut in_flight_futs: FuturesUnordered<BoxedExecute> = FuturesUnordered::new();

        // Buffer for leftover data when a callback chunk is larger than max_write.
        let mut pending_data: Vec<u8> = Vec::new();
        let mut pending_offset = 0usize;

        // Helper: try to get the next wire-level chunk (up to max_write bytes).
        // Returns Some(data) or None if no more data available.
        let next_wire_chunk = |pending_data: &mut Vec<u8>,
                               pending_offset: &mut usize,
                               done: &mut bool,
                               callback_err: &mut Option<std::io::Error>,
                               next_chunk: &mut F|
         -> Option<Vec<u8>> {
            // First, drain any pending leftover from a previous large chunk.
            if *pending_offset < pending_data.len() {
                let end = (*pending_offset + max_write as usize).min(pending_data.len());
                let slice = pending_data[*pending_offset..end].to_vec();
                *pending_offset = end;
                if *pending_offset >= pending_data.len() {
                    pending_data.clear();
                    *pending_offset = 0;
                }
                return Some(slice);
            }

            if *done {
                return None;
            }

            // Pull from the callback.
            match next_chunk() {
                None => {
                    *done = true;
                    None
                }
                Some(Err(e)) => {
                    *done = true;
                    *callback_err = Some(e);
                    None
                }
                Some(Ok(data)) => {
                    if data.is_empty() {
                        // Treat empty chunk as end of stream.
                        *done = true;
                        return None;
                    }
                    if data.len() <= max_write as usize {
                        Some(data)
                    } else {
                        // Split: return first max_write bytes, buffer the rest.
                        let first = data[..max_write as usize].to_vec();
                        *pending_data = data;
                        *pending_offset = max_write as usize;
                        Some(first)
                    }
                }
            }
        };

        // Initial fill: queue up to a full window of writes. The window is a
        // queue bound, not a credit bound — `Connection` reserves credits per
        // send and parks a write that can't afford one, so a chunk pulled from
        // the callback is always eventually sent.
        while in_flight < MAX_PIPELINE_WINDOW {
            let chunk = next_wire_chunk(
                &mut pending_data,
                &mut pending_offset,
                &mut done,
                &mut callback_err,
                next_chunk,
            );

            match chunk {
                None => break,
                Some(chunk_data) => {
                    let data_len = chunk_data.len() as u64;
                    let cc = data_len.div_ceil(65536).max(1) as u16;
                    let c = conn.clone();
                    let tree_id = self.tree_id;
                    let req = WriteRequest {
                        data_offset: 0x70,
                        offset,
                        file_id,
                        channel: 0,
                        remaining_bytes: 0,
                        write_channel_info_offset: 0,
                        write_channel_info_length: 0,
                        flags: 0,
                        data: chunk_data,
                    };
                    in_flight_futs.push(Box::pin(async move {
                        c.execute_with_credits(
                            Command::Write,
                            &req,
                            Some(tree_id),
                            CreditCharge(cc),
                        )
                        .await
                    }));
                    offset += data_len;
                    in_flight += 1;
                }
            }
        }

        // Sliding loop: receive one response, send next chunk (if any).
        while in_flight > 0 {
            let frame_result = match in_flight_futs.next().await {
                Some(r) => r,
                None => break,
            };
            in_flight -= 1;
            let frame = frame_result?;

            if frame.header.status != NtStatus::SUCCESS {
                // Drain remaining in-flight responses (best-effort).
                while in_flight_futs.next().await.is_some() {}
                return Err(Error::Protocol {
                    status: frame.header.status,
                    command: Command::Write,
                });
            }

            let mut cursor = ReadCursor::new(&frame.body);
            let resp = WriteResponse::unpack(&mut cursor)?;
            total_written += resp.count as u64;

            if callback_err.is_none() {
                let chunk = next_wire_chunk(
                    &mut pending_data,
                    &mut pending_offset,
                    &mut done,
                    &mut callback_err,
                    next_chunk,
                );

                if let Some(chunk_data) = chunk {
                    let data_len = chunk_data.len() as u64;
                    let cc = data_len.div_ceil(65536).max(1) as u16;
                    let c = conn.clone();
                    let tree_id = self.tree_id;
                    let req = WriteRequest {
                        data_offset: 0x70,
                        offset,
                        file_id,
                        channel: 0,
                        remaining_bytes: 0,
                        write_channel_info_offset: 0,
                        write_channel_info_length: 0,
                        flags: 0,
                        data: chunk_data,
                    };
                    in_flight_futs.push(Box::pin(async move {
                        c.execute_with_credits(
                            Command::Write,
                            &req,
                            Some(tree_id),
                            CreditCharge(cc),
                        )
                        .await
                    }));
                    offset += data_len;
                    in_flight += 1;
                }
            }
        }

        // If the callback returned an error, propagate it now
        // (after all in-flight responses have been drained).
        if let Some(io_err) = callback_err {
            return Err(Error::Io(io_err));
        }

        Ok(total_written)
    }

    /// Flush a file handle to ensure data is persisted on the server.
    ///
    /// Sends an SMB2 FLUSH request and waits for the server to confirm
    /// that all cached data has been written to persistent storage.
    pub(crate) async fn flush_handle(&self, conn: &mut Connection, file_id: FileId) -> Result<()> {
        trace!("tree: flushing file handle");
        let req = FlushRequest { file_id };

        let frame = conn
            .execute(Command::Flush, &req, Some(self.tree_id))
            .await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Flush,
            });
        }

        Ok(())
    }

    /// Close an open file handle, releasing it on the server.
    ///
    /// Pairs with the raw-handle opens ([`open_file`](Self::open_file),
    /// [`open_file_readwrite`](Self::open_file_readwrite)): a handle you opened
    /// and did not hand to a streaming type (which close themselves) must be
    /// closed with this, or it leaks server-side until session teardown.
    pub async fn close_handle(&self, conn: &mut Connection, file_id: FileId) -> Result<()> {
        Self::close_handle_for_tree(self.tree_id, conn, file_id).await
    }

    async fn close_handle_for_tree(
        tree_id: TreeId,
        conn: &mut Connection,
        file_id: FileId,
    ) -> Result<()> {
        // A no-op for the handles that never held an oplock, which is nearly
        // all of them. Done before the CLOSE so a break arriving in the gap
        // isn't acknowledged on a handle that is on its way out.
        conn.forget_oplock(file_id);
        let req = CloseRequest { flags: 0, file_id };

        let frame = conn.execute(Command::Close, &req, Some(tree_id)).await?;

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Close,
            });
        }

        Ok(())
    }

    pub(crate) async fn close_handle_bound(
        tree_id: TreeId,
        conn: &mut Connection,
        file_id: FileId,
        generation: u64,
        session_id: SessionId,
    ) -> Result<()> {
        conn.forget_oplock(file_id);
        let req = CloseRequest { flags: 0, file_id };
        let frame = conn
            .execute_bound(Command::Close, &req, Some(tree_id), generation, session_id)
            .await?;
        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Close,
            });
        }
        Ok(())
    }

    pub(crate) async fn flush_handle_bound(
        &self,
        conn: &mut Connection,
        file_id: FileId,
        generation: u64,
        session_id: SessionId,
    ) -> Result<()> {
        debug!("tree: flushing session-bound file handle");
        let req = FlushRequest { file_id };
        let frame = conn
            .execute_bound(
                Command::Flush,
                &req,
                Some(self.tree_id),
                generation,
                session_id,
            )
            .await?;
        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Flush,
            });
        }
        Ok(())
    }

    /// Write data to a file in chunks.
    ///
    /// Kept for potential future use by callers that need per-chunk control
    /// without pipelining or compounding.
    #[allow(dead_code)]
    async fn write_loop(&self, conn: &mut Connection, file_id: FileId, data: &[u8]) -> Result<u64> {
        let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);

        let mut total_written = 0u64;
        let mut offset = 0usize;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = remaining.min(max_write as usize);
            let chunk = &data[offset..offset + chunk_size];

            // DataOffset: header (64) + fixed write body (48) = 112 = 0x70
            let req = WriteRequest {
                data_offset: 0x70,
                offset: offset as u64,
                file_id,
                channel: 0,
                remaining_bytes: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: 0,
                data: chunk.to_vec(),
            };

            let frame = conn
                .execute(Command::Write, &req, Some(self.tree_id))
                .await?;

            if frame.header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: frame.header.status,
                    command: Command::Write,
                });
            }

            let mut cursor = ReadCursor::new(&frame.body);
            let resp = WriteResponse::unpack(&mut cursor)?;

            total_written += resp.count as u64;
            offset += chunk_size;
        }

        Ok(total_written)
    }
}

/// Build a FileRenameInformation buffer (MS-FSCC 2.4.34.2).
fn build_rename_info_buffer(new_name: &str, replace_if_exists: bool) -> Vec<u8> {
    let name_u16: Vec<u16> = new_name.encode_utf16().collect();
    let name_byte_len = name_u16.len() * 2;

    let mut buf = Vec::with_capacity(20 + name_byte_len);
    buf.push(u8::from(replace_if_exists)); // ReplaceIfExists
    buf.extend_from_slice(&[0u8; 7]); // Reserved
    buf.extend_from_slice(&0u64.to_le_bytes()); // RootDirectory
    buf.extend_from_slice(&(name_byte_len as u32).to_le_bytes()); // FileNameLength
    for &u in &name_u16 {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    buf
}

/// Turn a caller's path into the wire path SMB2 wants.
///
/// `/` is the separator, `\` is a name character, and any character SMB2
/// refuses is mapped into the private-use area per component. See
/// [`crate::name`] for the table and why the mapping is unconditional.
fn normalize_path(path: &str) -> String {
    crate::name::encode_path(path)
}

/// Parse either the compact ID-bearing directory layout or its compatibility
/// fallback. Their first 68 bytes are identical; only the fixed suffix differs.
fn parse_directory_info(data: &[u8], layout: DirectoryInfoLayout) -> Result<Vec<DirectoryEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let fixed_len = layout.fixed_len();
    let layout_name = layout.name();

    while offset < data.len() {
        let remaining = data.len() - offset;
        if remaining < fixed_len {
            return Err(Error::invalid_data(format!(
                "{layout_name} fixed record is truncated at byte {offset}"
            )));
        }

        let next_entry_offset = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .expect("four-byte slice"),
        ) as usize;
        let record_len = if next_entry_offset == 0 {
            remaining
        } else {
            if next_entry_offset < fixed_len
                || next_entry_offset > remaining
                || next_entry_offset % 8 != 0
            {
                return Err(Error::invalid_data(format!(
                    "invalid {layout_name} NextEntryOffset {next_entry_offset} at byte {offset}"
                )));
            }
            next_entry_offset
        };

        let entry_data = &data[offset..offset + record_len];
        let mut cursor = ReadCursor::new(entry_data);

        let parsed_next_entry_offset = cursor.read_u32_le()? as usize;
        debug_assert_eq!(parsed_next_entry_offset, next_entry_offset);
        let _file_index = cursor.read_u32_le()?;
        let creation_time = FileTime::unpack(&mut cursor)?;
        let _last_access_time = FileTime::unpack(&mut cursor)?;
        let last_write_time = FileTime::unpack(&mut cursor)?;
        let change_time = FileTime::unpack(&mut cursor)?;
        let end_of_file = cursor.read_u64_le()?;
        let _allocation_size = cursor.read_u64_le()?;
        let file_attributes = cursor.read_u32_le()?;
        let file_name_length = cursor.read_u32_le()? as usize;
        let _ea_size = cursor.read_u32_le()?;
        let file_index = match layout {
            DirectoryInfoLayout::FileIdFull => {
                cursor.skip(4)?; // Reserved
                let id = cursor.read_u64_le()?;
                (id != 0).then_some(id)
            }
            DirectoryInfoLayout::FileBoth => {
                let short_name_length = cursor.read_u8()? as usize;
                if short_name_length > 24 || short_name_length % 2 != 0 {
                    return Err(Error::invalid_data(format!(
                        "invalid FileBothDirectoryInformation ShortNameLength {short_name_length} at byte {offset}"
                    )));
                }
                cursor.skip(1)?; // Reserved
                cursor.skip(24)?; // ShortName
                None
            }
        };
        // FileName is one component, so decode it as a name rather than a path.
        if file_name_length % 2 != 0 || file_name_length > cursor.remaining() {
            return Err(Error::invalid_data(format!(
                "invalid {layout_name} FileNameLength {file_name_length} at byte {offset}"
            )));
        }
        let name = if file_name_length > 0 {
            crate::name::decode_name(&cursor.read_utf16_le(file_name_length)?).into_owned()
        } else {
            String::new()
        };

        let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        entries.push(DirectoryEntry {
            name,
            size: end_of_file,
            is_directory,
            created: creation_time,
            modified: last_write_time,
            changed: change_time,
            file_index,
        });

        if next_entry_offset == 0 {
            break;
        }
        offset = offset
            .checked_add(next_entry_offset)
            .ok_or_else(|| Error::invalid_data(format!("{layout_name} offset overflow")))?;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::connection::pack_message;
    use crate::client::test_helpers::{
        build_close_error_response, build_close_response, build_create_error_response,
        build_create_response, build_query_info_error_response, build_tree_connect_response,
        setup_connection,
    };
    use crate::msg::create::{CreateAction, CreateResponse};
    use crate::msg::header::Header;
    use crate::msg::query_directory::QueryDirectoryResponse;
    use crate::msg::tree_connect::ShareType;
    use crate::transport::MockTransport;
    use crate::types::status::NtStatus;
    use crate::types::{Command, TreeId};
    use std::sync::Arc;

    fn build_flush_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::Flush);
        h.flags.set_response();
        h.credits = 32;

        let body = crate::msg::flush::FlushResponse;
        pack_message(&h, &body)
    }

    fn build_query_directory_response(status: NtStatus, entries_data: Vec<u8>) -> Vec<u8> {
        let mut h = Header::new_request(Command::QueryDirectory);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;

        if status != NtStatus::SUCCESS {
            use crate::msg::header::ErrorResponse;
            let body = ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            };
            return pack_message(&h, &body);
        }

        let body = QueryDirectoryResponse {
            output_buffer: entries_data,
        };

        pack_message(&h, &body)
    }

    async fn wait_for_mock_counts(mock: &MockTransport, sent: usize, received: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < sent || mock.received_count() < received {
            if Instant::now() > deadline {
                panic!(
                    "mock counts did not reach sent={sent}, received={received}: got sent={}, \
                     received={}",
                    mock.sent_count(),
                    mock.received_count()
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn build_read_response(status: NtStatus, data: Vec<u8>) -> Vec<u8> {
        let mut h = Header::new_request(Command::Read);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;

        if status == NtStatus::END_OF_FILE {
            use crate::msg::header::ErrorResponse;
            let body = ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            };
            return pack_message(&h, &body);
        }

        let body = ReadResponse {
            data_offset: 0x50,
            data_remaining: 0,
            flags: 0,
            data,
        };

        pack_message(&h, &body)
    }

    /// Build a single FileIdFullDirectoryInformation entry.
    fn build_file_id_full_dir_info(
        name: &str,
        size: u64,
        is_directory: bool,
        next_offset: u32,
    ) -> Vec<u8> {
        build_file_id_full_dir_info_with_index(
            name,
            size,
            is_directory,
            next_offset,
            0x1122_3344_5566_7788,
        )
    }

    fn build_file_id_full_dir_info_with_index(
        name: &str,
        size: u64,
        is_directory: bool,
        next_offset: u32,
        file_index: u64,
    ) -> Vec<u8> {
        let name_u16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_u16.len() * 2;

        let mut buf = Vec::new();
        // NextEntryOffset (4)
        buf.extend_from_slice(&next_offset.to_le_bytes());
        // FileIndex (4)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // CreationTime (8)
        buf.extend_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        // LastAccessTime (8)
        buf.extend_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        // LastWriteTime (8)
        buf.extend_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        // ChangeTime (8)
        buf.extend_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        // EndOfFile (8)
        buf.extend_from_slice(&size.to_le_bytes());
        // AllocationSize (8)
        buf.extend_from_slice(&((size + 4095) & !4095).to_le_bytes());
        // FileAttributes (4)
        let attrs = if is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            0x00000020 // ARCHIVE
        };
        buf.extend_from_slice(&attrs.to_le_bytes());
        // FileNameLength (4)
        buf.extend_from_slice(&(name_bytes_len as u32).to_le_bytes());
        // EaSize (4)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // Reserved (4) + FileId (8)
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&file_index.to_le_bytes());
        // FileName (variable)
        for &u in &name_u16 {
            buf.extend_from_slice(&u.to_le_bytes());
        }

        buf
    }

    fn build_file_both_dir_info(
        name: &str,
        size: u64,
        is_directory: bool,
        next_offset: u32,
    ) -> Vec<u8> {
        let full = build_file_id_full_dir_info(name, size, is_directory, next_offset);
        let mut buf = full[..68].to_vec();
        buf.extend_from_slice(&[0u8; 26]); // ShortNameLength, Reserved, ShortName
        buf.extend_from_slice(&full[80..]);
        buf
    }

    #[tokio::test]
    async fn tree_connect_stores_tree_id() {
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(42);
        mock.queue_response(build_tree_connect_response(tree_id, ShareType::Disk));

        let mut conn = setup_connection(&mock);
        let tree = Tree::connect(&mut conn, "naspi").await.unwrap();
        assert_eq!(tree.tree_id, tree_id);
        assert_eq!(tree.share_name, "naspi");
    }

    #[tokio::test]
    async fn tree_connect_sends_unc_path() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_tree_connect_response(TreeId(1), ShareType::Disk));

        let mut conn = setup_connection(&mock);
        let _tree = Tree::connect(&mut conn, "myshare").await.unwrap();

        // Verify the sent request contains the UNC path.
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = TreeConnectRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req.path, r"\\test-server\myshare");
    }

    #[tokio::test]
    async fn list_directory_returns_entries() {
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(10);
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };

        // Build two directory entries.
        let entry1 = build_file_id_full_dir_info("file1.txt", 1024, false, 0);
        let total_entry_len = entry1.len().next_multiple_of(8);
        let mut entry1_with_next =
            build_file_id_full_dir_info("file1.txt", 1024, false, total_entry_len as u32);
        entry1_with_next.resize(total_entry_len, 0);
        let entry2 = build_file_id_full_dir_info("subdir", 0, true, 0);

        let mut entries_data = entry1_with_next;
        entries_data.extend_from_slice(&entry2);

        // Queue: CREATE response, QUERY_DIRECTORY response (with data), QUERY_DIRECTORY response (no more), CLOSE response.
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_query_directory_response(
            NtStatus::SUCCESS,
            entries_data,
        ));
        mock.queue_response(build_query_directory_response(
            NtStatus::NO_MORE_FILES,
            vec![],
        ));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let entries = tree.list_directory(&mut conn, "somedir").await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "file1.txt");
        assert_eq!(entries[0].size, 1024);
        assert!(!entries[0].is_directory);
        assert_eq!(entries[1].name, "subdir");
        assert!(entries[1].is_directory);

        let sent = mock.sent_message(1).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let request = QueryDirectoryRequest::unpack(&mut cursor).unwrap();
        assert_eq!(
            request.file_information_class,
            FileInformationClass::FileIdFullDirectoryInformation
        );
    }

    #[tokio::test]
    async fn list_directory_falls_back_when_file_id_full_is_unsupported() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };
        mock.queue_responses(vec![
            build_create_response(file_id, 0),
            build_query_directory_response(NtStatus::NOT_SUPPORTED, vec![]),
            build_query_directory_response(
                NtStatus::SUCCESS,
                build_file_both_dir_info("compatible.txt", 7, false, 0),
            ),
            build_query_directory_response(NtStatus::NO_MORE_FILES, vec![]),
            build_close_response(),
        ]);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let entries = tree.list_directory(&mut conn, "somedir").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "compatible.txt");
        assert_eq!(entries[0].file_index, None);

        for (request_index, expected_class) in [
            FileInformationClass::FileIdFullDirectoryInformation,
            FileInformationClass::FileBothDirectoryInformation,
        ]
        .into_iter()
        .enumerate()
        {
            let sent = mock.sent_message(request_index + 1).unwrap();
            let mut cursor = ReadCursor::new(&sent);
            let _header = Header::unpack(&mut cursor).unwrap();
            let request = QueryDirectoryRequest::unpack(&mut cursor).unwrap();
            assert_eq!(request.file_information_class, expected_class);
            assert_ne!(request.flags.0 & QueryDirectoryFlags::RESTART_SCANS, 0);
        }
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn directory_reader_yields_one_response_at_a_time_and_closes_at_eof() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_query_directory_response(
            NtStatus::SUCCESS,
            build_file_id_full_dir_info("first.txt", 10, false, 0),
        ));
        mock.queue_response(build_query_directory_response(
            NtStatus::SUCCESS,
            build_file_id_full_dir_info("second.txt", 20, false, 0),
        ));
        mock.queue_response(build_query_directory_response(
            NtStatus::NO_MORE_FILES,
            vec![],
        ));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut reader = tree.open_directory_reader(conn, "somedir").await.unwrap();
        assert_eq!(mock.sent_count(), 1, "opening must not prefetch entries");

        let first = reader.next_batch().await.unwrap().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].name, "first.txt");
        assert_eq!(mock.sent_count(), 2);

        let second = reader.next_batch().await.unwrap().unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].name, "second.txt");
        assert_eq!(mock.sent_count(), 3);

        assert!(reader.next_batch().await.unwrap().is_none());
        assert_eq!(mock.sent_count(), 5, "EOF must issue exactly one CLOSE");
        assert!(reader.next_batch().await.unwrap().is_none());
        assert_eq!(mock.sent_count(), 5, "reads after EOF must stay local");

        let first_query = mock.sent_message(1).unwrap();
        let mut first_cursor = ReadCursor::new(&first_query);
        Header::unpack(&mut first_cursor).unwrap();
        let first_request = QueryDirectoryRequest::unpack(&mut first_cursor).unwrap();
        assert_eq!(first_request.flags.0, QueryDirectoryFlags::RESTART_SCANS);

        let second_query = mock.sent_message(2).unwrap();
        let mut second_cursor = ReadCursor::new(&second_query);
        Header::unpack(&mut second_cursor).unwrap();
        let second_request = QueryDirectoryRequest::unpack(&mut second_cursor).unwrap();
        assert_eq!(second_request.flags.0, 0);
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn directory_reader_rejects_changed_connection_identity_without_sending() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };
        mock.queue_responses(vec![
            build_create_response(file_id, 0),
            build_create_response(file_id, 0),
        ]);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut querying_reader = tree
            .open_directory_reader(conn.clone(), "somedir")
            .await
            .unwrap();
        let mut closing_reader = tree
            .open_directory_reader(conn.clone(), "somedir")
            .await
            .unwrap();
        assert_eq!(mock.sent_count(), 2);

        // install_transport clears the old SessionId before reauthentication
        // and before generation increments. Model that reconnect window while
        // proving the generation-only guard would not catch it.
        let generation = conn.generation();
        let session_id = conn.session_id();
        conn.set_session_id(SessionId(0));
        assert_eq!(conn.generation(), generation);

        let error = querying_reader.next_batch().await.unwrap_err();
        assert!(matches!(error, Error::Disconnected));
        assert!(querying_reader.next_batch().await.unwrap().is_none());

        // A completed reconnect changes the generation as well. Restore the
        // session ID so this close exercises that independent guard.
        conn.set_session_id(session_id);
        closing_reader.generation += 1;
        closing_reader.close().await.unwrap();

        assert_eq!(
            mock.sent_count(),
            2,
            "stale readers must not send QUERY_DIRECTORY or CLOSE"
        );
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn directory_reader_resumes_cancelled_query_without_skipping_its_batch() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_query_directory_response(
            NtStatus::SUCCESS,
            build_file_id_full_dir_info("first.txt", 10, false, 0),
        ));

        let conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut reader = tree.open_directory_reader(conn, "somedir").await.unwrap();
        assert_eq!(
            reader.next_batch().await.unwrap().unwrap()[0].name,
            "first.txt"
        );

        // Poll the second call until its QUERY_DIRECTORY is on the wire, then
        // cancel only the outer `next_batch` future. The reader must retain
        // the inner request and deliver its eventual response on the next call.
        let mut pending = Box::pin(reader.next_batch());
        tokio::select! {
            result = &mut pending => panic!("query unexpectedly completed: {result:?}"),
            () = wait_for_mock_counts(&mock, 3, 2) => {}
        }
        drop(pending);

        mock.queue_response(build_query_directory_response(
            NtStatus::SUCCESS,
            build_file_id_full_dir_info("preserved.txt", 20, false, 0),
        ));
        wait_for_mock_counts(&mock, 3, 3).await;

        let resumed = tokio::time::timeout(Duration::from_secs(1), reader.next_batch())
            .await
            .expect("resumed call must use the already-sent request")
            .unwrap()
            .unwrap();
        assert_eq!(resumed[0].name, "preserved.txt");
        assert_eq!(mock.sent_count(), 3, "resume must not send another QUERY");

        mock.queue_responses(vec![
            build_query_directory_response(NtStatus::NO_MORE_FILES, vec![]),
            build_close_response(),
        ]);
        assert!(reader.next_batch().await.unwrap().is_none());
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn directory_reader_resumes_cancelled_eof_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_query_directory_response(
            NtStatus::NO_MORE_FILES,
            vec![],
        ));

        let conn = setup_connection(&mock);
        let metrics_conn = conn.clone();
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut reader = tree.open_directory_reader(conn, "somedir").await.unwrap();
        let mut pending = Box::pin(reader.next_batch());
        tokio::select! {
            result = &mut pending => panic!("close unexpectedly completed: {result:?}"),
            () = wait_for_mock_counts(&mock, 3, 2) => {}
        }
        drop(pending);

        mock.queue_response(build_close_response());
        wait_for_mock_counts(&mock, 3, 3).await;

        assert!(reader.next_batch().await.unwrap().is_none());
        assert_eq!(mock.sent_count(), 3, "resume must not send a second CLOSE");
        assert_eq!(
            metrics_conn.metrics().responses_late_after_drop,
            0,
            "the CLOSE waiter must survive cancellation"
        );
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn directory_reader_close_drains_a_cancelled_query() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };

        mock.queue_response(build_create_response(file_id, 0));

        let conn = setup_connection(&mock);
        let metrics_conn = conn.clone();
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut reader = tree.open_directory_reader(conn, "somedir").await.unwrap();
        let mut pending = Box::pin(reader.next_batch());
        tokio::select! {
            result = &mut pending => panic!("query unexpectedly completed: {result:?}"),
            () = wait_for_mock_counts(&mock, 2, 1) => {}
        }
        drop(pending);

        mock.queue_responses(vec![
            build_query_directory_response(
                NtStatus::SUCCESS,
                build_file_id_full_dir_info("discarded.txt", 10, false, 0),
            ),
            build_close_response(),
        ]);
        reader.close().await.unwrap();

        assert_eq!(mock.sent_count(), 3, "close must not issue another QUERY");
        assert_eq!(
            metrics_conn.metrics().responses_late_after_drop,
            0,
            "explicit close must drain the retained QUERY waiter"
        );
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn directory_reader_can_close_before_requesting_entries() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        tree.open_directory_reader(conn, "somedir")
            .await
            .unwrap()
            .close()
            .await
            .unwrap();

        assert_eq!(mock.sent_count(), 2);
        let close = mock.sent_message(1).unwrap();
        let mut cursor = ReadCursor::new(&close);
        assert_eq!(Header::unpack(&mut cursor).unwrap().command, Command::Close);
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn directory_reader_closes_after_query_failure() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_query_directory_response(
            NtStatus::ACCESS_DENIED,
            vec![],
        ));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut reader = tree.open_directory_reader(conn, "somedir").await.unwrap();
        let error = reader.next_batch().await.unwrap_err();
        assert_eq!(error.status(), Some(NtStatus::ACCESS_DENIED));
        assert_eq!(mock.sent_count(), 3, "query failure must still issue CLOSE");
        assert!(reader.next_batch().await.unwrap().is_none());
        assert_eq!(mock.sent_count(), 3);
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn list_directory_instrumented_reports_phase_breakdown() {
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(10);
        let file_id = FileId {
            persistent: 0x1111,
            volatile: 0x2222,
        };

        let entry1 = build_file_id_full_dir_info("file1.txt", 1024, false, 0);
        let entry1_len = entry1.len().next_multiple_of(8);
        let mut entry1_with_next =
            build_file_id_full_dir_info("file1.txt", 1024, false, entry1_len as u32);
        entry1_with_next.resize(entry1_len, 0);
        let entry2 = build_file_id_full_dir_info("subdir", 0, true, 0);
        let mut entries_data = entry1_with_next;
        entries_data.extend_from_slice(&entry2);
        let payload_len = entries_data.len();

        // CREATE, one QUERY with entries, one QUERY NO_MORE_FILES, CLOSE.
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_query_directory_response(
            NtStatus::SUCCESS,
            entries_data,
        ));
        mock.queue_response(build_query_directory_response(
            NtStatus::NO_MORE_FILES,
            vec![],
        ));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let (entries, trace) = tree
            .list_directory_instrumented(&mut conn, "somedir", None)
            .await
            .unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(trace.entries, 2);

        // Two QUERY round trips: the data reply, then the terminal NO_MORE_FILES.
        assert_eq!(trace.queries.len(), 2);
        assert_eq!(trace.queries[0].entries, 2);
        assert_eq!(trace.queries[0].bytes, payload_len);
        assert!(!trace.queries[0].no_more_files);
        assert_eq!(trace.queries[1].entries, 0);
        assert!(trace.queries[1].no_more_files);

        // CREATE + 2 QUERY + CLOSE.
        assert_eq!(trace.round_trips(), 4);
        // total() sums the phases; query_total() only the QUERY round trips.
        assert_eq!(
            trace.total(),
            trace.create + trace.query_total() + trace.close
        );
    }

    #[tokio::test]
    async fn read_file_returns_data() {
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(20);
        let file_id = FileId {
            persistent: 0x3333,
            volatile: 0x4444,
        };
        let file_data = b"Hello, SMB world!";

        // Queue a single compound response frame: CREATE + READ + CLOSE.
        let create_resp = build_create_response(file_id, file_data.len() as u64);
        let read_resp = build_read_response(NtStatus::SUCCESS, file_data.to_vec());
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let data = tree.read_file(&mut conn, "test.txt").await.unwrap();
        assert_eq!(data, file_data);
    }

    #[tokio::test]
    async fn read_file_errors_when_larger_than_single_read() {
        // The mock negotiates a 64 KiB MaxReadSize (see setup_connection). A
        // file bigger than that can't come back in one READ, so read_file must
        // fail with a typed error rather than silently returning the first
        // 64 KiB. Pre-fix this returned a truncated buffer.
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(21);
        let file_id = FileId {
            persistent: 0x55,
            volatile: 0x66,
        };
        let big_size = 100_000u64; // > 65536

        // Even though we error on size, the compound still carried READ + CLOSE
        // sub-responses; queue a well-formed frame so routing is realistic.
        let create_resp = build_create_response(file_id, big_size);
        let read_resp = build_read_response(NtStatus::SUCCESS, vec![0u8; 65536]);
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let err = tree.read_file(&mut conn, "big.bin").await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::FileTooLargeForSingleRead {
                    size: 100_000,
                    max_read: 65536
                }
            ),
            "expected FileTooLargeForSingleRead, got {err:?}"
        );
        assert_eq!(err.kind(), crate::ErrorKind::TooLarge);
    }

    #[tokio::test]
    async fn normalize_path_converts_slashes() {
        assert_eq!(normalize_path("foo/bar/baz"), "foo\\bar\\baz");
        assert_eq!(normalize_path("/leading/slash"), "leading\\slash");
        assert_eq!(normalize_path("no_change"), "no_change");
        // A `\` is a name character now, not a second separator.
        assert_eq!(
            normalize_path("\\leading\\backslash"),
            "\u{F026}leading\u{F026}backslash"
        );
    }

    #[tokio::test]
    async fn illegal_characters_are_mapped_into_the_private_use_area() {
        // The exact name that a QNAP Samba share rejected with
        // STATUS_OBJECT_NAME_INVALID before the mapping existed.
        assert_eq!(
            normalize_path("dir/\"how_are_you_feeling?\"_emojis.json"),
            "dir\\\u{F020}how_are_you_feeling\u{F025}\u{F020}_emojis.json"
        );
        // A backslash inside a name is a name character, not a separator.
        assert_eq!(normalize_path("a\\b"), "a\u{F026}b");
        // The trailing rule applies per component, to the last character only.
        assert_eq!(normalize_path("dir /file. "), "dir\u{F028}\\file.\u{F028}");
    }

    #[tokio::test]
    async fn directory_listings_decode_private_use_area_names() {
        let data = build_file_both_dir_info("a\u{F025}b", 7, false, 0);
        let entries = parse_directory_info(&data, DirectoryInfoLayout::FileBoth).unwrap();
        assert_eq!(entries[0].name, "a?b");
    }

    #[tokio::test]
    async fn format_path_prepends_dfs_prefix() {
        let tree = Tree {
            tree_id: TreeId(1),
            share_name: "dfs".to_string(),
            server: "server1".to_string(),
            is_dfs: true,
            encrypt_data: false,
        };
        assert_eq!(
            tree.format_path("data/hello.txt"),
            "server1\\dfs\\data\\hello.txt"
        );
        assert_eq!(tree.format_path(""), "server1\\dfs");
        assert_eq!(
            tree.format_path("nested/path"),
            "server1\\dfs\\nested\\path"
        );
    }

    #[tokio::test]
    async fn format_path_strips_port_from_dfs_prefix() {
        let tree = Tree {
            tree_id: TreeId(1),
            share_name: "dfs".to_string(),
            server: "server1:10456".to_string(),
            is_dfs: true,
            encrypt_data: false,
        };
        assert_eq!(
            tree.format_path("data/hello.txt"),
            "server1\\dfs\\data\\hello.txt"
        );
    }

    #[tokio::test]
    async fn format_path_no_prefix_when_not_dfs() {
        let tree = Tree {
            tree_id: TreeId(1),
            share_name: "public".to_string(),
            server: "server1".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };
        assert_eq!(tree.format_path("data/hello.txt"), "data\\hello.txt");
        assert_eq!(tree.format_path(""), "");
    }

    #[tokio::test]
    async fn parse_file_id_full_dir_info_single_entry() {
        let data = build_file_id_full_dir_info("test.txt", 42, false, 0);
        let entries = parse_directory_info(&data, DirectoryInfoLayout::FileIdFull).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
        assert_eq!(entries[0].size, 42);
        assert!(!entries[0].is_directory);
        assert_eq!(entries[0].changed, FileTime(133_000_000_000_000_000));
        assert_eq!(entries[0].file_index, Some(0x1122_3344_5566_7788));
    }

    #[test]
    fn parse_file_id_full_dir_info_ignores_zero_file_id() {
        let data = build_file_id_full_dir_info_with_index("unstable.txt", 42, false, 0, 0);
        let entries = parse_directory_info(&data, DirectoryInfoLayout::FileIdFull).unwrap();
        assert_eq!(entries[0].file_index, None);
    }

    #[test]
    fn parse_file_both_dir_info_has_no_stable_file_id() {
        let data = build_file_both_dir_info("compatible.txt", 42, false, 0);
        let entries = parse_directory_info(&data, DirectoryInfoLayout::FileBoth).unwrap();
        assert_eq!(entries[0].name, "compatible.txt");
        assert_eq!(entries[0].file_index, None);
    }

    #[test]
    fn parse_file_id_full_dir_info_rejects_truncated_record() {
        let error = parse_directory_info(&[0u8; 79], DirectoryInfoLayout::FileIdFull).unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_file_id_full_dir_info_rejects_bad_next_offset() {
        let mut data = build_file_id_full_dir_info("bad.txt", 42, false, 0);
        data[0..4].copy_from_slice(&81u32.to_le_bytes());
        let error = parse_directory_info(&data, DirectoryInfoLayout::FileIdFull).unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_file_id_full_dir_info_rejects_name_crossing_record() {
        let mut first = build_file_id_full_dir_info("first.txt", 42, false, 0);
        let record_len = first.len().next_multiple_of(8);
        first.resize(record_len, 0);
        first[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        first[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        first.extend_from_slice(&build_file_id_full_dir_info("second.txt", 1, false, 0));

        let error = parse_directory_info(&first, DirectoryInfoLayout::FileIdFull).unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn tree_disconnect_sends_request() {
        let mock = Arc::new(MockTransport::new());

        // Queue a tree disconnect response.
        let mut h = Header::new_request(Command::TreeDisconnect);
        h.flags.set_response();
        h.credits = 32;
        use crate::msg::tree_disconnect::TreeDisconnectResponse;
        mock.queue_response(pack_message(&h, &TreeDisconnectResponse));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(99),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        tree.disconnect(&mut conn).await.unwrap();
        assert_eq!(mock.sent_count(), 1);
    }

    // ── Delete file tests ────────────────────────────────────────────

    fn build_write_response(count: u32) -> Vec<u8> {
        use crate::msg::write::WriteResponse;
        let mut h = Header::new_request(Command::Write);
        h.flags.set_response();
        h.credits = 32;

        let body = WriteResponse {
            count,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        };

        pack_message(&h, &body)
    }

    use crate::client::test_helpers::{
        build_query_info_response, build_query_info_response_with_status, build_set_info_response,
    };

    fn sent_rename_request(mock: &MockTransport, message: usize) -> SetInfoRequest {
        let sent = mock.sent_message(message).unwrap();
        let mut create_cursor = ReadCursor::new(&sent);
        let create_header = Header::unpack(&mut create_cursor).unwrap();
        let set_info_offset = create_header.next_command as usize;
        assert!(set_info_offset > Header::SIZE);

        let mut set_info_cursor = ReadCursor::new(&sent[set_info_offset..]);
        let set_info_header = Header::unpack(&mut set_info_cursor).unwrap();
        assert_eq!(set_info_header.command, Command::SetInfo);
        SetInfoRequest::unpack(&mut set_info_cursor).unwrap()
    }
    /// Build a FileBasicInformation buffer (40 bytes).
    fn build_file_basic_info(
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
        file_attributes: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&creation_time.to_le_bytes());
        buf.extend_from_slice(&last_access_time.to_le_bytes());
        buf.extend_from_slice(&last_write_time.to_le_bytes());
        buf.extend_from_slice(&change_time.to_le_bytes());
        buf.extend_from_slice(&file_attributes.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved/padding
        buf
    }

    /// Build a FileStandardInformation buffer (24 bytes).
    fn build_file_standard_info(
        allocation_size: u64,
        end_of_file: u64,
        number_of_links: u32,
        delete_pending: bool,
        directory: bool,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&allocation_size.to_le_bytes());
        buf.extend_from_slice(&end_of_file.to_le_bytes());
        buf.extend_from_slice(&number_of_links.to_le_bytes());
        buf.push(if delete_pending { 1 } else { 0 });
        buf.push(if directory { 1 } else { 0 });
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf
    }

    /// Build a FileInternalInformation buffer containing a 64-bit file ID.
    fn build_file_internal_info(index_number: u64) -> Vec<u8> {
        index_number.to_le_bytes().to_vec()
    }

    /// Build the fixed prefix of FileFsVolumeInformation used by identity.
    fn build_file_fs_volume_info(volume_serial: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 8]; // VolumeCreationTime
        buf.extend_from_slice(&volume_serial.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // VolumeLabelLength
        buf.extend_from_slice(&[0, 0]); // SupportsObjects + Reserved
        buf
    }

    #[tokio::test]
    async fn delete_file_sends_compound_create_and_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        };

        // DELETE = compound CREATE + SET_INFO(disposition) + CLOSE
        let create_resp = build_create_response(file_id, 0);
        let setinfo_resp = build_set_info_response();
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, setinfo_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        tree.delete_file(&mut conn, "remove.txt").await.unwrap();

        // One compound frame sent.
        assert_eq!(mock.sent_count(), 1);

        // The CREATE asks for DELETE access and leaves the deleting to the
        // SET_INFO. Pre-fix this asserted FILE_DELETE_ON_CLOSE, which Samba
        // silently ignores on a non-empty directory.
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        assert!(req.desired_access.contains(FileAccessMask::DELETE));
        assert_ne!(req.create_options & FILE_NON_DIRECTORY_FILE, 0);
    }

    #[tokio::test]
    async fn delete_file_create_failure_returns_error() {
        let mock = Arc::new(MockTransport::new());

        // Build compound response where CREATE fails.
        let mut create_hdr = Header::new_request(Command::Create);
        create_hdr.flags.set_response();
        create_hdr.credits = 32;
        create_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_resp = pack_message(
            &create_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_resp = pack_message(
            &close_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut setinfo_hdr = Header::new_request(Command::SetInfo);
        setinfo_hdr.flags.set_response();
        setinfo_hdr.credits = 32;
        setinfo_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let setinfo_resp = pack_message(
            &setinfo_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame = build_compound_response_frame(&[create_resp, setinfo_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.delete_file(&mut conn, "nonexistent.txt").await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().status(),
            Some(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        // Only the one compound frame, no standalone CLOSE needed.
        assert_eq!(mock.sent_count(), 1);
    }

    #[tokio::test]
    async fn delete_file_close_failure_issues_standalone_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        };

        // Compound: CREATE and SET_INFO succeed, CLOSE fails.
        let create_resp = build_create_response(file_id, 0);
        let setinfo_resp = build_set_info_response();

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::UNSUCCESSFUL;
        let close_resp = pack_message(
            &close_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame = build_compound_response_frame(&[create_resp, setinfo_resp, close_resp]);
        mock.queue_response(frame);

        // Queue response for the standalone CLOSE retry.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.delete_file(&mut conn, "tricky.txt").await;
        assert!(result.is_err());
        // Compound frame + standalone CLOSE = 2 messages sent.
        assert_eq!(mock.sent_count(), 2);
    }

    // ── Write file tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn write_file_sends_create_write_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xCC,
            volatile: 0xDD,
        };

        // write_file for small data now uses compound: CREATE+WRITE+FLUSH+CLOSE in one frame.
        let create_resp = build_create_response(file_id, 0);
        let write_resp = build_write_response(5);
        let flush_resp = build_flush_response();
        let close_resp = build_close_response();

        let frame =
            build_compound_response_frame(&[create_resp, write_resp, flush_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let written = tree
            .write_file(&mut conn, "out.txt", b"hello")
            .await
            .unwrap();
        assert_eq!(written, 5);
        // One compound frame sent.
        assert_eq!(mock.sent_count(), 1);
    }

    // ── Stat tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn stat_sends_compound_and_returns_file_info() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xEE,
            volatile: 0xFF,
        };

        // STAT = CREATE + basic + standard + internal + volume + CLOSE.
        let create_resp = build_create_response(file_id, 0);
        let basic = build_file_basic_info(
            132_000_000_000_000_000,
            132_100_000_000_000_000,
            133_000_000_000_000_000,
            133_000_000_000_000_000,
            0x20, // ARCHIVE
        );
        let basic_resp = build_query_info_response(basic);
        let std_info = build_file_standard_info(4096, 2048, 1, false, false);
        let std_resp = build_query_info_response(std_info);
        let identity_resp = build_query_info_response(build_file_internal_info(0x1234));
        let volume_resp = build_query_info_response(build_file_fs_volume_info(0xABCD));
        let close_resp = build_close_response();

        let frame = build_compound_response_frame(&[
            create_resp,
            basic_resp,
            std_resp,
            identity_resp,
            volume_resp,
            close_resp,
        ]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let info = tree.stat(&mut conn, "doc.txt").await.unwrap();
        assert_eq!(info.size, 2048);
        assert!(!info.is_directory);
        assert_eq!(info.created, FileTime(132_000_000_000_000_000));
        assert_eq!(info.modified, FileTime(133_000_000_000_000_000));
        assert_eq!(info.accessed, FileTime(132_100_000_000_000_000));
        assert_eq!(info.changed, FileTime(133_000_000_000_000_000));
        assert_eq!(
            info.identity,
            Some(FileIdentity {
                volume_serial: 0xABCD,
                index_number: 0x1234,
            })
        );
        // One compound frame sent.
        assert_eq!(mock.sent_count(), 1);
    }

    #[tokio::test]
    async fn stat_succeeds_when_server_declines_file_identity() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xEE,
            volatile: 0xFF,
        };
        let responses = [
            build_create_response(file_id, 0),
            build_query_info_response(build_file_basic_info(1, 2, 3, 4, 0x20)),
            build_query_info_response(build_file_standard_info(4096, 2048, 1, false, false)),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
            build_close_error_response(NtStatus::NOT_SUPPORTED),
        ];
        mock.queue_response(build_compound_response_frame(&responses));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let info = tree.stat(&mut conn, "doc.txt").await.unwrap();
        assert_eq!(info.identity, None);
        assert_eq!(info.changed, FileTime(4));
        assert_eq!(
            mock.sent_count(),
            2,
            "cascaded CLOSE failure must be cleaned up"
        );
    }

    #[tokio::test]
    async fn stat_create_failure_returns_error() {
        let mock = Arc::new(MockTransport::new());

        // Build compound response where CREATE fails (all ops cascade).
        let mut create_hdr = Header::new_request(Command::Create);
        create_hdr.flags.set_response();
        create_hdr.credits = 32;
        create_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let err_body = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };
        let create_resp = pack_message(&create_hdr, &err_body);

        let mut q1_hdr = Header::new_request(Command::QueryInfo);
        q1_hdr.flags.set_response();
        q1_hdr.credits = 32;
        q1_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let q1_resp = pack_message(&q1_hdr, &err_body);

        let mut q2_hdr = Header::new_request(Command::QueryInfo);
        q2_hdr.flags.set_response();
        q2_hdr.credits = 32;
        q2_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let q2_resp = pack_message(&q2_hdr, &err_body);

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_resp = pack_message(&close_hdr, &err_body);

        let frame = build_compound_response_frame(&[
            create_resp,
            q1_resp,
            q2_resp,
            build_query_info_error_response(NtStatus::OBJECT_NAME_NOT_FOUND),
            build_query_info_error_response(NtStatus::OBJECT_NAME_NOT_FOUND),
            close_resp,
        ]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.stat(&mut conn, "nonexistent.txt").await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().status(),
            Some(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(mock.sent_count(), 1);
    }

    #[tokio::test]
    async fn stat_query_failure_issues_standalone_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xEE,
            volatile: 0xFF,
        };

        // Compound: CREATE succeeds, first QUERY_INFO fails, rest cascade.
        let create_resp = build_create_response(file_id, 0);

        let err_body = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };

        let mut q1_hdr = Header::new_request(Command::QueryInfo);
        q1_hdr.flags.set_response();
        q1_hdr.credits = 32;
        q1_hdr.status = NtStatus::UNSUCCESSFUL;
        let q1_resp = pack_message(&q1_hdr, &err_body);

        let mut q2_hdr = Header::new_request(Command::QueryInfo);
        q2_hdr.flags.set_response();
        q2_hdr.credits = 32;
        q2_hdr.status = NtStatus::UNSUCCESSFUL;
        let q2_resp = pack_message(&q2_hdr, &err_body);

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::UNSUCCESSFUL;
        let close_resp = pack_message(&close_hdr, &err_body);

        let frame = build_compound_response_frame(&[
            create_resp,
            q1_resp,
            q2_resp,
            build_query_info_error_response(NtStatus::UNSUCCESSFUL),
            build_query_info_error_response(NtStatus::UNSUCCESSFUL),
            close_resp,
        ]);
        mock.queue_response(frame);

        // Queue response for the standalone CLOSE retry.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.stat(&mut conn, "tricky.txt").await;
        assert!(result.is_err());
        // Compound frame + standalone CLOSE = 2 messages sent.
        assert_eq!(mock.sent_count(), 2);
    }

    // ── Batch stat tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn stat_files_batch_happy_path() {
        let mock = Arc::new(MockTransport::new());

        // Queue 3 compound responses (CREATE + four QUERY_INFO + CLOSE each).
        for i in 0..3u64 {
            let file_id = FileId {
                persistent: i + 1,
                volatile: i + 100,
            };
            let create_resp = build_create_response(file_id, 0);
            let basic = build_file_basic_info(
                132_000_000_000_000_000 + i,
                132_100_000_000_000_000 + i,
                133_000_000_000_000_000 + i,
                133_000_000_000_000_000 + i,
                0x20,
            );
            let basic_resp = build_query_info_response(basic);
            let std_info = build_file_standard_info(4096, 1024 * (i + 1), 1, false, false);
            let std_resp = build_query_info_response(std_info);
            let identity_resp = build_query_info_response(build_file_internal_info(i + 1));
            let volume_resp = build_query_info_response(build_file_fs_volume_info(0xABCD));
            let close_resp = build_close_response();
            mock.queue_response(build_compound_response_frame(&[
                create_resp,
                basic_resp,
                std_resp,
                identity_resp,
                volume_resp,
                close_resp,
            ]));
        }

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree
            .stat_files(&mut conn, &["a.txt", "b.txt", "c.txt"])
            .await;

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_ref().unwrap().size, 1024);
        assert_eq!(results[1].as_ref().unwrap().size, 2048);
        assert_eq!(results[2].as_ref().unwrap().size, 3072);
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn stat_files_cleans_up_a_close_cascaded_from_optional_identity() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 7,
            volatile: 8,
        };
        mock.queue_responses(vec![
            build_compound_response_frame(&[
                build_create_response(file_id, 0),
                build_query_info_response(build_file_basic_info(1, 2, 3, 4, 0x20)),
                build_query_info_response(build_file_standard_info(4096, 2048, 1, false, false)),
                build_query_info_error_response(NtStatus::NOT_SUPPORTED),
                build_query_info_error_response(NtStatus::NOT_SUPPORTED),
                build_close_error_response(NtStatus::NOT_SUPPORTED),
            ]),
            build_close_response(),
        ]);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };
        let results = tree.stat_files(&mut conn, &["doc.txt"]).await;

        assert_eq!(results[0].as_ref().unwrap().identity, None);
        assert_eq!(mock.sent_count(), 2);
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn stat_files_batch_partial_failure() {
        let mock = Arc::new(MockTransport::new());

        let err_body = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };

        // File 1: success
        let file_id = FileId {
            persistent: 1,
            volatile: 100,
        };
        let create_resp = build_create_response(file_id, 0);
        let basic = build_file_basic_info(
            132_000_000_000_000_000,
            132_100_000_000_000_000,
            133_000_000_000_000_000,
            133_000_000_000_000_000,
            0x20,
        );
        let basic_resp = build_query_info_response(basic);
        let std_info = build_file_standard_info(4096, 512, 1, false, false);
        let std_resp = build_query_info_response(std_info);
        let identity_resp = build_query_info_response(build_file_internal_info(1));
        let volume_resp = build_query_info_response(build_file_fs_volume_info(0xABCD));
        let close_resp = build_close_response();
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            basic_resp,
            std_resp,
            identity_resp,
            volume_resp,
            close_resp,
        ]));

        // File 2: CREATE fails -- cascaded failure
        let mut create_hdr = Header::new_request(Command::Create);
        create_hdr.flags.set_response();
        create_hdr.credits = 32;
        create_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_err = pack_message(&create_hdr, &err_body);

        let mut q1_hdr = Header::new_request(Command::QueryInfo);
        q1_hdr.flags.set_response();
        q1_hdr.credits = 32;
        q1_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let q1_err = pack_message(&q1_hdr, &err_body);

        let mut q2_hdr = Header::new_request(Command::QueryInfo);
        q2_hdr.flags.set_response();
        q2_hdr.credits = 32;
        q2_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let q2_err = pack_message(&q2_hdr, &err_body);

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_err = pack_message(&close_hdr, &err_body);
        mock.queue_response(build_compound_response_frame(&[
            create_err,
            q1_err,
            q2_err,
            build_query_info_error_response(NtStatus::OBJECT_NAME_NOT_FOUND),
            build_query_info_error_response(NtStatus::OBJECT_NAME_NOT_FOUND),
            close_err,
        ]));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree
            .stat_files(&mut conn, &["exists.txt", "missing.txt"])
            .await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().size, 512);
        assert!(results[1].is_err());
        assert_eq!(
            results[1].as_ref().unwrap_err().status(),
            Some(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
    }

    #[tokio::test]
    async fn stat_files_empty_returns_empty() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results: Vec<Result<FileInfo>> = tree.stat_files(&mut conn, &[]).await;
        assert!(results.is_empty());
    }

    // ── Rename tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn rename_sends_compound_create_setinfo_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };

        // RENAME = compound CREATE + SET_INFO + CLOSE
        let create_resp = build_create_response(file_id, 0);
        let setinfo_resp = build_set_info_response();
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, setinfo_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        tree.rename(&mut conn, "old.txt", "new.txt").await.unwrap();

        // One compound frame sent.
        assert_eq!(mock.sent_count(), 1);

        // Verify the CREATE has DELETE access (required for rename)
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        assert!(req.desired_access.contains(FileAccessMask::DELETE));

        let rename = sent_rename_request(&mock, 0);
        assert_eq!(rename.file_info_class, FILE_RENAME_INFORMATION);
        assert_eq!(rename.buffer[0], 0, "rename defaults to no-replace");
        assert_eq!(&rename.buffer[1..8], &[0; 7]);
        assert_eq!(&rename.buffer[8..16], &0u64.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(rename.buffer[16..20].try_into().unwrap()),
            14,
            "new.txt is seven UTF-16 code units"
        );
    }

    #[tokio::test]
    async fn rename_with_replace_encodes_one_atomic_server_mutation() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        mock.queue_response(build_compound_response_frame(&[
            build_create_response(file_id, 0),
            build_set_info_response(),
            build_close_response(),
        ]));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        tree.rename_with_options(
            &mut conn,
            "old.txt",
            "new.txt",
            RenameOptions {
                replace_if_exists: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(mock.sent_count(), 1, "replacement is not delete + rename");
        let rename = sent_rename_request(&mock, 0);
        assert_eq!(rename.buffer[0], 1, "SMB ReplaceIfExists must be set");
    }

    #[tokio::test]
    async fn mutation_handle_renames_the_same_identity_checked_open() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x31,
            volatile: 0x32,
        };
        let mut volume = vec![0u8; 16];
        volume[8..12].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        mock.queue_response(build_create_response(file_id, 42));
        mock.queue_response(build_compound_response_frame(&[
            build_query_info_response(0x8877_6655_4433_2211u64.to_le_bytes().to_vec()),
            build_query_info_response(volume),
        ]));
        mock.queue_response(build_set_info_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = Arc::new(Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        });
        let handle = tree.open_mutation_handle(conn, "old.txt").await.unwrap();
        assert_eq!(
            handle.info().identity,
            Some(FileIdentity {
                volume_serial: 0x1234_5678,
                index_number: 0x8877_6655_4433_2211,
            })
        );
        handle
            .rename(
                "new.txt",
                RenameOptions {
                    replace_if_exists: true,
                },
            )
            .await
            .unwrap();

        assert_eq!(mock.sent_count(), 4, "the source is opened exactly once");
        let sent = mock.sent_message(2).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let header = Header::unpack(&mut cursor).unwrap();
        assert_eq!(header.command, Command::SetInfo);
        let request = SetInfoRequest::unpack(&mut cursor).unwrap();
        assert_eq!(request.file_id, file_id);
        assert_eq!(request.file_info_class, FILE_RENAME_INFORMATION);
        assert_eq!(request.buffer[0], 1);
    }

    #[tokio::test]
    async fn mutation_handle_deletes_by_file_id_then_closes() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x41,
            volatile: 0x42,
        };
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_compound_response_frame(&[
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
        ]));
        mock.queue_response(build_set_info_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = Arc::new(Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        });
        let handle = tree.open_mutation_handle(conn, "empty-dir").await.unwrap();
        assert_eq!(handle.info().identity, None);
        handle.delete().await.unwrap();

        let sent = mock.sent_message(2).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let header = Header::unpack(&mut cursor).unwrap();
        assert_eq!(header.command, Command::SetInfo);
        let request = SetInfoRequest::unpack(&mut cursor).unwrap();
        assert_eq!(request.file_id, file_id);
        assert_eq!(request.file_info_class, FILE_DISPOSITION_INFORMATION);
        assert_eq!(request.buffer, vec![1]);
        assert_eq!(mock.sent_count(), 4);
    }

    #[tokio::test]
    async fn mutation_handle_never_reuses_ids_after_session_change() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x51,
            volatile: 0x52,
        };
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_compound_response_frame(&[
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
        ]));

        let conn = setup_connection(&mock);
        let mut shared = conn.clone();
        let tree = Arc::new(Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        });
        let handle = tree.open_mutation_handle(conn, "old.txt").await.unwrap();
        shared.set_session_id(SessionId(0xCAFE));

        let error = handle.delete().await.unwrap_err();
        assert!(matches!(error, Error::Disconnected));
        assert_eq!(
            mock.sent_count(),
            2,
            "stale SetInfo and Close must stay off the replacement session"
        );
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn no_replace_surfaces_an_existing_destination_conflict() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let create_resp = build_create_response(file_id, 0);
        let mut setinfo_hdr = Header::new_request(Command::SetInfo);
        setinfo_hdr.flags.set_response();
        setinfo_hdr.credits = 32;
        setinfo_hdr.status = NtStatus::OBJECT_NAME_COLLISION;
        let error = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };
        let setinfo_resp = pack_message(&setinfo_hdr, &error);
        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::OBJECT_NAME_COLLISION;
        let close_resp = pack_message(&close_hdr, &error);
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            setinfo_resp,
            close_resp,
        ]));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let error = tree
            .rename(&mut conn, "old.txt", "occupied.txt")
            .await
            .unwrap_err();

        assert_eq!(error.status(), Some(NtStatus::OBJECT_NAME_COLLISION));
        assert_eq!(error.kind(), crate::ErrorKind::AlreadyExists);
        assert_eq!(sent_rename_request(&mock, 0).buffer[0], 0);
    }

    #[tokio::test]
    async fn rename_create_failure_returns_error() {
        let mock = Arc::new(MockTransport::new());

        // Build compound response where CREATE fails.
        let mut create_hdr = Header::new_request(Command::Create);
        create_hdr.flags.set_response();
        create_hdr.credits = 32;
        create_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_resp = pack_message(
            &create_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut setinfo_hdr = Header::new_request(Command::SetInfo);
        setinfo_hdr.flags.set_response();
        setinfo_hdr.credits = 32;
        setinfo_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let setinfo_resp = pack_message(
            &setinfo_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_resp = pack_message(
            &close_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame = build_compound_response_frame(&[create_resp, setinfo_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.rename(&mut conn, "old.txt", "new.txt").await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().status(),
            Some(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        // Only the one compound frame, no standalone CLOSE needed.
        assert_eq!(mock.sent_count(), 1);
    }

    #[tokio::test]
    async fn rename_setinfo_failure_issues_standalone_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };

        // Compound: CREATE succeeds, SET_INFO fails, CLOSE cascades failure.
        let create_resp = build_create_response(file_id, 0);

        let mut setinfo_hdr = Header::new_request(Command::SetInfo);
        setinfo_hdr.flags.set_response();
        setinfo_hdr.credits = 32;
        setinfo_hdr.status = NtStatus::UNSUCCESSFUL;
        let setinfo_resp = pack_message(
            &setinfo_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::UNSUCCESSFUL;
        let close_resp = pack_message(
            &close_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame = build_compound_response_frame(&[create_resp, setinfo_resp, close_resp]);
        mock.queue_response(frame);

        // Queue response for the standalone CLOSE retry.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.rename(&mut conn, "old.txt", "new.txt").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status(), Some(NtStatus::UNSUCCESSFUL));
        // Compound frame + standalone CLOSE = 2 messages sent.
        assert_eq!(mock.sent_count(), 2);
    }

    // ── Batch rename tests ────────────────────────────────────────────

    #[tokio::test]
    async fn rename_files_batch_happy_path() {
        let mock = Arc::new(MockTransport::new());

        // Queue 3 compound responses (CREATE+SET_INFO+CLOSE each).
        for i in 0..3u64 {
            let file_id = FileId {
                persistent: i + 1,
                volatile: i + 100,
            };
            let create_resp = build_create_response(file_id, 0);
            let setinfo_resp = build_set_info_response();
            let close_resp = build_close_response();
            mock.queue_response(build_compound_response_frame(&[
                create_resp,
                setinfo_resp,
                close_resp,
            ]));
        }

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree
            .rename_files(
                &mut conn,
                &[
                    ("a.txt", "a2.txt"),
                    ("b.txt", "b2.txt"),
                    ("c.txt", "c2.txt"),
                ],
            )
            .await;

        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_ok());
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn rename_files_batch_partial_failure() {
        let mock = Arc::new(MockTransport::new());

        let err_body = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };

        // File 1: success
        let file_id = FileId {
            persistent: 1,
            volatile: 100,
        };
        let create_resp = build_create_response(file_id, 0);
        let setinfo_resp = build_set_info_response();
        let close_resp = build_close_response();
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            setinfo_resp,
            close_resp,
        ]));

        // File 2: CREATE fails (not found)
        let mut create_hdr = Header::new_request(Command::Create);
        create_hdr.flags.set_response();
        create_hdr.credits = 32;
        create_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_err = pack_message(&create_hdr, &err_body);

        let mut si_hdr = Header::new_request(Command::SetInfo);
        si_hdr.flags.set_response();
        si_hdr.credits = 32;
        si_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let si_err = pack_message(&si_hdr, &err_body);

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_err = pack_message(&close_hdr, &err_body);
        mock.queue_response(build_compound_response_frame(&[
            create_err, si_err, close_err,
        ]));

        // File 3: success
        let file_id = FileId {
            persistent: 3,
            volatile: 102,
        };
        let create_resp = build_create_response(file_id, 0);
        let setinfo_resp = build_set_info_response();
        let close_resp = build_close_response();
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            setinfo_resp,
            close_resp,
        ]));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree
            .rename_files(
                &mut conn,
                &[
                    ("a.txt", "a2.txt"),
                    ("missing.txt", "m2.txt"),
                    ("c.txt", "c2.txt"),
                ],
            )
            .await;

        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert_eq!(
            results[1].as_ref().unwrap_err().status(),
            Some(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert!(results[2].is_ok());
    }

    #[tokio::test]
    async fn rename_files_empty_returns_empty() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results: Vec<Result<()>> = tree.rename_files(&mut conn, &[]).await;
        assert!(results.is_empty());
        assert_eq!(mock.sent_count(), 0);
    }

    // ── Create directory tests ───────────────────────────────────────

    #[tokio::test]
    async fn create_directory_sends_create_and_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x33,
            volatile: 0x44,
        };

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        tree.create_directory(&mut conn, "new_dir").await.unwrap();
        assert_eq!(mock.sent_count(), 2);

        // Verify the CREATE has FILE_DIRECTORY_FILE option and FileCreate disposition
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req.create_disposition, CreateDisposition::FileCreate);
        assert_ne!(req.create_options & FILE_DIRECTORY_FILE, 0);
    }

    // ── Exclusive-create writer open tests ────────────────────────────

    #[tokio::test]
    async fn open_file_for_exclusive_create_sends_file_create_disposition() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        };
        mock.queue_response(build_create_response(file_id, 0));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let generation = conn.generation();
        let session_id = conn.session_id();
        tree.open_file_for_exclusive_create_bound(&mut conn, "new.bin", generation, session_id)
            .await
            .unwrap();

        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        assert_eq!(
            req.create_disposition,
            CreateDisposition::FileCreate,
            "exclusive-create writer must use FileCreate, not FileOverwriteIf"
        );
        // File, not directory.
        assert_ne!(req.create_options & FILE_NON_DIRECTORY_FILE, 0);
    }

    #[tokio::test]
    async fn open_file_for_exclusive_create_maps_collision_to_already_exists() {
        let mock = Arc::new(MockTransport::new());
        // STATUS_OBJECT_NAME_COLLISION = 0xC0000035; the server response any
        // time `FileCreate` hits an existing file.
        mock.queue_response(build_create_error_response(NtStatus::OBJECT_NAME_COLLISION));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let generation = conn.generation();
        let session_id = conn.session_id();
        let err = tree
            .open_file_for_exclusive_create_bound(&mut conn, "existing.bin", generation, session_id)
            .await
            .expect_err("exclusive-create on an existing file must error");
        assert_eq!(
            err.kind(),
            crate::ErrorKind::AlreadyExists,
            "STATUS_OBJECT_NAME_COLLISION must map to ErrorKind::AlreadyExists, got: {err}"
        );
    }

    // ── Delete directory tests ───────────────────────────────────────

    #[tokio::test]
    async fn delete_directory_sends_compound_create_and_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x55,
            volatile: 0x66,
        };

        // DELETE = compound CREATE + SET_INFO(disposition) + CLOSE
        let create_resp = build_create_response(file_id, 0);
        let setinfo_resp = build_set_info_response();
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, setinfo_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        tree.delete_directory(&mut conn, "old_dir").await.unwrap();

        // One compound frame sent.
        assert_eq!(mock.sent_count(), 1);

        // The CREATE opens the directory; the SET_INFO is what deletes it.
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        assert!(req.desired_access.contains(FileAccessMask::DELETE));
        assert_ne!(req.create_options & FILE_DIRECTORY_FILE, 0);
    }

    #[tokio::test]
    async fn delete_directory_surfaces_not_empty_instead_of_reporting_success() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x51,
            volatile: 0x52,
        };

        // A non-empty directory: CREATE opens it, SET_INFO refuses. Pre-fix
        // this used FILE_DELETE_ON_CLOSE, where Samba answers every op with
        // SUCCESS and deletes nothing, so the caller was told it worked.
        let create_resp = build_create_response(file_id, 0);
        let mut setinfo_hdr = Header::new_request(Command::SetInfo);
        setinfo_hdr.flags.set_response();
        setinfo_hdr.credits = 32;
        setinfo_hdr.status = NtStatus::DIRECTORY_NOT_EMPTY;
        let setinfo_resp = pack_message(
            &setinfo_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );
        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::DIRECTORY_NOT_EMPTY;
        let close_resp = pack_message(
            &close_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            setinfo_resp,
            close_resp,
        ]));
        // The standalone CLOSE that releases the handle.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.delete_directory(&mut conn, "full_dir").await;

        assert_eq!(
            result.unwrap_err().status(),
            Some(NtStatus::DIRECTORY_NOT_EMPTY)
        );
        // The compound plus the standalone CLOSE, so the handle isn't leaked.
        assert_eq!(mock.sent_count(), 2);
    }

    #[test]
    fn all_or_first_err_rejects_a_short_chain() {
        // Callers index responses[2] straight after this returns, so a chain
        // that came back short has to be an error, not a panic waiting to
        // happen.
        let result = all_or_first_err(vec![], 3);
        assert!(
            result.is_err(),
            "a 3-op chain answered with 0 frames must be an error"
        );
    }

    // ── Batch delete tests ───────────────────────────────────────────

    #[tokio::test]
    async fn delete_files_batch_happy_path() {
        let mock = Arc::new(MockTransport::new());

        // Queue 3 compound responses (CREATE+SET_INFO+CLOSE each).
        for i in 0..3u64 {
            let file_id = FileId {
                persistent: i + 1,
                volatile: i + 100,
            };
            let create_resp = build_create_response(file_id, 0);
            let setinfo_resp = build_set_info_response();
            let close_resp = build_close_response();
            mock.queue_response(build_compound_response_frame(&[
                create_resp,
                setinfo_resp,
                close_resp,
            ]));
        }

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree
            .delete_files(&mut conn, &["a.txt", "b.txt", "c.txt"])
            .await;

        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_ok());
        // 3 compound frames sent (one per file).
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn delete_files_batch_partial_failure() {
        let mock = Arc::new(MockTransport::new());

        let err_body = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };

        // File 1: success
        let file_id = FileId {
            persistent: 1,
            volatile: 100,
        };
        let create_resp = build_create_response(file_id, 0);
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            build_set_info_response(),
            build_close_response(),
        ]));

        // File 2: CREATE fails (not found) -- cascaded failure
        let mut create_hdr = Header::new_request(Command::Create);
        create_hdr.flags.set_response();
        create_hdr.credits = 32;
        create_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_err = pack_message(&create_hdr, &err_body);

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_err = pack_message(&close_hdr, &err_body);

        let mut setinfo_hdr = Header::new_request(Command::SetInfo);
        setinfo_hdr.flags.set_response();
        setinfo_hdr.credits = 32;
        setinfo_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let setinfo_err = pack_message(&setinfo_hdr, &err_body);
        mock.queue_response(build_compound_response_frame(&[
            create_err,
            setinfo_err,
            close_err,
        ]));

        // File 3: success
        let file_id = FileId {
            persistent: 3,
            volatile: 102,
        };
        let create_resp = build_create_response(file_id, 0);
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            build_set_info_response(),
            build_close_response(),
        ]));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree
            .delete_files(&mut conn, &["a.txt", "missing.txt", "c.txt"])
            .await;

        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert_eq!(
            results[1].as_ref().unwrap_err().status(),
            Some(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert!(results[2].is_ok());
    }

    #[tokio::test]
    async fn delete_files_batch_close_failure_issues_cleanup() {
        let mock = Arc::new(MockTransport::new());

        let err_body = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };

        // File 1: CREATE succeeds, CLOSE fails
        let file_id = FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        };
        let create_resp = build_create_response(file_id, 0);

        let mut close_hdr = Header::new_request(Command::Close);
        close_hdr.flags.set_response();
        close_hdr.credits = 32;
        close_hdr.status = NtStatus::UNSUCCESSFUL;
        let close_fail = pack_message(&close_hdr, &err_body);
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            build_set_info_response(),
            close_fail,
        ]));

        // File 1's handle is closed before file 2 starts, so its standalone
        // CLOSE response is queued between the two compounds.
        mock.queue_response(build_close_response());

        // File 2: success
        let file_id2 = FileId {
            persistent: 0xCC,
            volatile: 0xDD,
        };
        let create_resp2 = build_create_response(file_id2, 0);
        let close_resp2 = build_close_response();
        mock.queue_response(build_compound_response_frame(&[
            create_resp2,
            build_set_info_response(),
            close_resp2,
        ]));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree.delete_files(&mut conn, &["leaky.txt", "ok.txt"]).await;

        assert_eq!(results.len(), 2);
        assert!(results[0].is_err());
        assert!(results[1].is_ok());
        // 2 compound frames + 1 standalone CLOSE = 3 messages sent.
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn delete_files_empty_returns_empty() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let results = tree.delete_files(&mut conn, &[]).await;
        assert!(results.is_empty());
        assert_eq!(mock.sent_count(), 0);
    }

    // ── Pipelined read tests ────────────────────────────────────────

    fn build_read_response_with_msg_id(
        status: NtStatus,
        msg_id: MessageId,
        data: Vec<u8>,
    ) -> Vec<u8> {
        let mut h = Header::new_request(Command::Read);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;
        h.message_id = msg_id;

        if status == NtStatus::END_OF_FILE {
            use crate::msg::header::ErrorResponse;
            let body = ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            };
            return pack_message(&h, &body);
        }

        let body = ReadResponse {
            data_offset: 0x50,
            data_remaining: 0,
            flags: 0,
            data,
        };

        pack_message(&h, &body)
    }

    fn build_write_response_with_msg_id(msg_id: MessageId, count: u32) -> Vec<u8> {
        use crate::msg::write::WriteResponse;
        let mut h = Header::new_request(Command::Write);
        h.flags.set_response();
        h.credits = 32;
        h.message_id = msg_id;

        let body = WriteResponse {
            count,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        };

        pack_message(&h, &body)
    }

    #[tokio::test]
    async fn pipelined_read_four_chunks() {
        // File: 256 KB = 4 chunks of 64 KB.
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(20);
        let file_id = FileId {
            persistent: 0x100,
            volatile: 0x200,
        };
        let file_size = 256 * 1024u64;

        // Build 256 KB of test data with a recognizable pattern.
        let mut expected_data = vec![0u8; file_size as usize];
        for (i, byte) in expected_data.iter_mut().enumerate() {
            *byte = (i % 251) as u8; // prime to avoid alignment artifacts
        }

        // Queue: CREATE response.
        mock.queue_response(build_create_response(file_id, file_size));

        // Queue: 4 READ responses (in order, matching the MessageIds
        // that send_request will assign).
        // After CREATE, the next message_id = 1 (CREATE consumed 0).
        // Actually, connection starts at next_message_id=0. But setup_connection
        // doesn't call negotiate (which would consume msg_id 0).
        // send_request for CREATE will use msg_id 0, then the 4 READs will
        // use msg_ids 1, 2, 3, 4.
        for i in 0..4 {
            let offset = i * 65536;
            let chunk = expected_data[offset..offset + 65536].to_vec();
            mock.queue_response(build_read_response_with_msg_id(
                NtStatus::SUCCESS,
                MessageId((i / 65536 + 1) as u64), // msg_ids 1..4
                chunk,
            ));
        }
        // Fix: the message IDs. send_request increments next_message_id each time.
        // After CREATE (msg_id=0), the 4 READs get msg_ids 1, 2, 3, 4.
        // Let me rebuild these correctly.
        // Actually I already did it wrong above. Let me clear and redo.
        // The loop above computed msg_id as (i / 65536 + 1) which is always 1.
        // Let me fix this.

        // Clear the mock and redo.
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_create_response(file_id, file_size));

        for i in 0u64..4 {
            let offset = (i * 65536) as usize;
            let chunk = expected_data[offset..offset + 65536].to_vec();
            mock.queue_response(build_read_response_with_msg_id(
                NtStatus::SUCCESS,
                MessageId(i + 1), // msg_ids 1, 2, 3, 4
                chunk,
            ));
        }

        // Queue: CLOSE response.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let data = tree
            .read_file_pipelined(&mut conn, "big.bin")
            .await
            .unwrap();

        assert_eq!(data.len(), expected_data.len());
        assert_eq!(data, expected_data);

        // 1 CREATE + 4 READs + 1 CLOSE = 6 messages sent.
        assert_eq!(mock.sent_count(), 6);
    }

    #[tokio::test]
    async fn pipelined_read_responses_out_of_order() {
        // File: 192 KB = 3 chunks of 64 KB. Responses arrive in reverse order.
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(20);
        let file_id = FileId {
            persistent: 0x300,
            volatile: 0x400,
        };
        let file_size = 192 * 1024u64;

        let mut expected_data = vec![0u8; file_size as usize];
        for (i, byte) in expected_data.iter_mut().enumerate() {
            *byte = (i % 199) as u8;
        }

        mock.queue_response(build_create_response(file_id, file_size));

        // Queue responses in REVERSE order (msg_id 3, 2, 1) to test reassembly.
        for i in (0u64..3).rev() {
            let offset = (i * 65536) as usize;
            let chunk = expected_data[offset..offset + 65536].to_vec();
            mock.queue_response(build_read_response_with_msg_id(
                NtStatus::SUCCESS,
                MessageId(i + 1),
                chunk,
            ));
        }

        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let data = tree
            .read_file_pipelined(&mut conn, "reverse.bin")
            .await
            .unwrap();

        assert_eq!(data.len(), expected_data.len());
        assert_eq!(data, expected_data);
    }

    #[tokio::test]
    async fn pipelined_read_zero_byte_file() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x500,
            volatile: 0x600,
        };

        // CREATE reports file_size=0.
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let data = tree
            .read_file_pipelined(&mut conn, "empty.bin")
            .await
            .unwrap();

        assert!(data.is_empty());
        // 1 CREATE + 1 CLOSE = 2 messages (no READs needed).
        assert_eq!(mock.sent_count(), 2);
    }

    #[tokio::test]
    async fn pipelined_read_end_of_file_mid_window() {
        // File claims to be 128 KB (2 chunks), but second chunk returns STATUS_END_OF_FILE.
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x700,
            volatile: 0x800,
        };
        let file_size = 128 * 1024u64;
        let first_chunk = vec![0xAA; 65536];

        mock.queue_response(build_create_response(file_id, file_size));
        // First chunk succeeds.
        mock.queue_response(build_read_response_with_msg_id(
            NtStatus::SUCCESS,
            MessageId(1),
            first_chunk.clone(),
        ));
        // Second chunk returns END_OF_FILE.
        mock.queue_response(build_read_response_with_msg_id(
            NtStatus::END_OF_FILE,
            MessageId(2),
            vec![],
        ));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let data = tree
            .read_file_pipelined(&mut conn, "truncated.bin")
            .await
            .unwrap();

        // We got the full buffer since file_size was 128 KB.
        // The second chunk area stays as zeros (from vec initialization).
        assert_eq!(data.len(), file_size as usize);
        assert_eq!(&data[..65536], &first_chunk);
    }

    #[tokio::test]
    async fn pipelined_read_window_sliding() {
        // File: 192 KB = 3 chunks. Credits = 2, so we need 2 windows.
        let file_id = FileId {
            persistent: 0x900,
            volatile: 0xA00,
        };
        let file_size = 192 * 1024u64;

        let mut expected_data = vec![0u8; file_size as usize];
        for (i, byte) in expected_data.iter_mut().enumerate() {
            *byte = (i % 173) as u8;
        }

        // Build with limited credits to force window sliding.
        // CREATE response grants only 2 credits (instead of default 32),
        // so the pipeline can only send 2 reads per window.
        let mock = Arc::new(MockTransport::new());

        let create_resp = {
            let mut h = Header::new_request(Command::Create);
            h.flags.set_response();
            h.credits = 2; // Only grant 2 credits.
            let body = CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: file_size,
                file_attributes: 0,
                file_id,
                create_contexts: vec![],
            };
            pack_message(&h, &body)
        };
        mock.queue_response(create_resp);

        // Window 1: 2 READs (chunks 0, 1). Responses grant 2 credits each.
        for i in 0u64..2 {
            let offset = (i * 65536) as usize;
            let chunk_data = expected_data[offset..offset + 65536].to_vec();
            let mut h = Header::new_request(Command::Read);
            h.flags.set_response();
            h.credits = 2; // Grant 2 credits per response.
            h.message_id = MessageId(i + 1);
            let body = ReadResponse {
                data_offset: 0x50,
                data_remaining: 0,
                flags: 0,
                data: chunk_data,
            };
            mock.queue_response(pack_message(&h, &body));
        }

        // Window 2: 1 READ (chunk 2).
        {
            let offset = (2 * 65536) as usize;
            let chunk_data = expected_data[offset..offset + 65536].to_vec();
            let mut h = Header::new_request(Command::Read);
            h.flags.set_response();
            h.credits = 2;
            h.message_id = MessageId(3);
            let body = ReadResponse {
                data_offset: 0x50,
                data_remaining: 0,
                flags: 0,
                data: chunk_data,
            };
            mock.queue_response(pack_message(&h, &body));
        }

        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let data = tree
            .read_file_pipelined(&mut conn, "sliding.bin")
            .await
            .unwrap();

        assert_eq!(data.len(), expected_data.len());
        assert_eq!(data, expected_data);
        // 1 CREATE + 3 READs + 1 CLOSE = 5.
        assert_eq!(mock.sent_count(), 5);
    }

    #[tokio::test]
    async fn sliding_window_sends_immediately_after_receive() {
        // File: 512 KB = 8 chunks of 64 KB. Only 4 credits available initially.
        // With sliding window: 4 sends, then each receive triggers a new send.
        // Total: 8 sends interleaved with 8 receives (not 2 batches of 4).
        let file_id = FileId {
            persistent: 0xF00,
            volatile: 0xF01,
        };
        let file_size = 8 * 65536u64;

        let mut expected_data = vec![0u8; file_size as usize];
        for (i, byte) in expected_data.iter_mut().enumerate() {
            *byte = (i % 137) as u8;
        }

        let mock = Arc::new(MockTransport::new());

        // CREATE response grants 4 credits (not the default 32).
        let create_resp = {
            let mut h = Header::new_request(Command::Create);
            h.flags.set_response();
            h.credits = 4;
            let body = CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: file_size,
                file_attributes: 0,
                file_id,
                create_contexts: vec![],
            };
            pack_message(&h, &body)
        };
        mock.queue_response(create_resp);

        // Queue 8 READ responses. Each grants 1 credit so the window
        // stays at 1 after the initial 4 are consumed (4 - 4 + 1 per response).
        // With sliding window, after initial 4 sends, each response triggers 1 more send.
        for i in 0u64..8 {
            let offset = (i * 65536) as usize;
            let chunk_data = expected_data[offset..offset + 65536].to_vec();
            let mut h = Header::new_request(Command::Read);
            h.flags.set_response();
            h.credits = 1; // Grant 1 credit per response.
            h.message_id = MessageId(i + 1);
            let body = ReadResponse {
                data_offset: 0x50,
                data_remaining: 0,
                flags: 0,
                data: chunk_data,
            };
            mock.queue_response(pack_message(&h, &body));
        }

        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let data = tree
            .read_file_pipelined(&mut conn, "sliding_test.bin")
            .await
            .unwrap();

        assert_eq!(data.len(), expected_data.len());
        assert_eq!(data, expected_data);

        // 1 CREATE + 8 READs + 1 CLOSE = 10 messages sent.
        assert_eq!(mock.sent_count(), 10);
    }

    // ── Pipelined read with progress tests ────────────────────────────

    #[tokio::test]
    async fn read_pipelined_with_progress_reports_progress() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xF1,
            volatile: 0xF2,
        };
        // 2 chunks of 65536 bytes each.
        let file_size = 65536u64 * 2;
        let expected_data = vec![0xABu8; file_size as usize];

        // CREATE response with file size.
        let create_resp = {
            let mut h = Header::new_request(Command::Create);
            h.flags.set_response();
            h.credits = 32;
            let body = CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: file_size,
                file_attributes: 0,
                file_id,
                create_contexts: vec![],
            };
            pack_message(&h, &body)
        };
        mock.queue_response(create_resp);

        // 2 READ responses.
        for i in 0..2u64 {
            let offset = (i * 65536) as usize;
            let chunk = expected_data[offset..offset + 65536].to_vec();
            let resp = build_read_response_with_msg_id(NtStatus::SUCCESS, MessageId(i + 1), chunk);
            mock.queue_response(resp);
        }

        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut progress_reports = Vec::new();
        let data = tree
            .read_file_pipelined_with_progress(&mut conn, "progress_test.bin", |p| {
                progress_reports.push(p.bytes_transferred);
                ControlFlow::Continue(())
            })
            .await
            .unwrap();

        assert_eq!(data.len(), file_size as usize);
        // Should have received 2 progress callbacks (one per chunk).
        assert_eq!(progress_reports.len(), 2);
        assert_eq!(progress_reports[0], 65536);
        assert_eq!(progress_reports[1], file_size);
    }

    #[tokio::test]
    async fn read_pipelined_with_progress_cancellation() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xF3,
            volatile: 0xF4,
        };
        // 4 chunks of 65536 bytes.
        let file_size = 65536u64 * 4;

        let create_resp = {
            let mut h = Header::new_request(Command::Create);
            h.flags.set_response();
            h.credits = 32;
            let body = CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: file_size,
                file_attributes: 0,
                file_id,
                create_contexts: vec![],
            };
            pack_message(&h, &body)
        };
        mock.queue_response(create_resp);

        // Queue all 4 READ responses (some won't be consumed due to cancellation).
        for i in 0..4u64 {
            let chunk = vec![0x42u8; 65536];
            let resp = build_read_response_with_msg_id(NtStatus::SUCCESS, MessageId(i + 1), chunk);
            mock.queue_response(resp);
        }

        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        // Cancel after the first chunk.
        let result = tree
            .read_file_pipelined_with_progress(&mut conn, "cancel_test.bin", |_p| {
                ControlFlow::Break(())
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Cancelled => {} // expected
            other => panic!("expected Cancelled, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn read_pipelined_with_progress_empty_file() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xF5,
            volatile: 0xF6,
        };

        // CREATE response with size=0.
        let create_resp = {
            let mut h = Header::new_request(Command::Create);
            h.flags.set_response();
            h.credits = 32;
            let body = CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: 0,
                file_attributes: 0,
                file_id,
                create_contexts: vec![],
            };
            pack_message(&h, &body)
        };
        mock.queue_response(create_resp);
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut progress_called = false;
        let data = tree
            .read_file_pipelined_with_progress(&mut conn, "empty.bin", |p| {
                progress_called = true;
                assert_eq!(p.bytes_transferred, 0);
                assert_eq!(p.total_bytes, Some(0));
                ControlFlow::Continue(())
            })
            .await
            .unwrap();

        assert!(data.is_empty());
        assert!(progress_called);
    }

    // ── Pipelined write tests ───────────────────────────────────────

    #[tokio::test]
    async fn pipelined_write_four_chunks() {
        let mock = Arc::new(MockTransport::new());
        let tree_id = TreeId(20);
        let file_id = FileId {
            persistent: 0xB00,
            volatile: 0xC00,
        };
        let data_to_write = vec![0x42u8; 256 * 1024]; // 256 KB = 4 chunks

        // CREATE response.
        mock.queue_response(build_create_response(file_id, 0));

        // 4 WRITE responses.
        for i in 0u64..4 {
            mock.queue_response(build_write_response_with_msg_id(MessageId(i + 1), 65536));
        }

        // FLUSH + CLOSE responses.
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let written = tree
            .write_file_pipelined(&mut conn, "big_write.bin", &data_to_write)
            .await
            .unwrap();

        assert_eq!(written, 256 * 1024);
        // 1 CREATE + 4 WRITEs + 1 FLUSH + 1 CLOSE = 7.
        assert_eq!(mock.sent_count(), 7);

        // Verify that each WRITE request contains the correct data chunk.
        for i in 0..4 {
            let sent = mock.sent_message(i + 1).unwrap(); // skip CREATE at index 0
            let mut cursor = ReadCursor::new(&sent);
            let _header = Header::unpack(&mut cursor).unwrap();
            let req = WriteRequest::unpack(&mut cursor).unwrap();
            assert_eq!(req.data.len(), 65536);
            assert_eq!(req.offset, i as u64 * 65536);
            assert!(req.data.iter().all(|&b| b == 0x42));
        }
    }

    #[tokio::test]
    async fn pipelined_write_last_chunk_smaller() {
        // 100 KB = 1 full chunk (64 KB) + 1 partial chunk (36 KB).
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xD00,
            volatile: 0xE00,
        };
        let data_to_write = vec![0x55u8; 100 * 1024];

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response_with_msg_id(MessageId(1), 65536));
        mock.queue_response(build_write_response_with_msg_id(MessageId(2), 36 * 1024));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let written = tree
            .write_file_pipelined(&mut conn, "partial.bin", &data_to_write)
            .await
            .unwrap();

        assert_eq!(written, 65536 + 36 * 1024);
        assert_eq!(mock.sent_count(), 5); // CREATE + 2 WRITEs + FLUSH + CLOSE
    }

    // ── Compound request tests ──────────────────────────────────────

    /// Build a compound response frame with proper NextCommand offsets and padding.
    use crate::client::test_helpers::build_compound_response_frame;

    #[tokio::test]
    async fn read_file_compound_returns_file_data() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        // Set up tree.
        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        // Build compound response frame: CREATE + READ + CLOSE.
        let file_id = FileId {
            persistent: 0x42,
            volatile: 0x99,
        };
        let file_data = b"Hello, compound!".to_vec();

        let create_resp = build_create_response(file_id, file_data.len() as u64);
        let read_resp = build_read_response(NtStatus::SUCCESS, file_data.clone());
        let close_resp = build_close_response();

        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        let data = tree
            .read_file_compound(&mut conn, "test.txt")
            .await
            .unwrap();

        assert_eq!(data, b"Hello, compound!");
        // Should have sent one compound frame (plus the tree connect).
        assert_eq!(mock.sent_count(), 2); // TreeConnect + compound
    }

    #[tokio::test]
    async fn read_file_compound_handles_empty_file() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        let file_id = FileId {
            persistent: 1,
            volatile: 2,
        };

        // Build compound response: CREATE ok, READ returns END_OF_FILE, CLOSE ok.
        let create_resp = build_create_response(file_id, 0);

        // For END_OF_FILE, we need an error response body.
        let read_resp = build_read_response(NtStatus::END_OF_FILE, vec![]);
        let close_resp = build_close_response();

        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        let data = tree
            .read_file_compound(&mut conn, "empty.txt")
            .await
            .unwrap();

        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn read_file_compound_create_failure_returns_error() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        // Build compound response where CREATE fails with OBJECT_NAME_NOT_FOUND.
        // When CREATE fails, server cascades error to READ and CLOSE.
        let mut create_resp_header = Header::new_request(Command::Create);
        create_resp_header.flags.set_response();
        create_resp_header.credits = 32;
        create_resp_header.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_resp = pack_message(
            &create_resp_header,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut read_resp_header = Header::new_request(Command::Read);
        read_resp_header.flags.set_response();
        read_resp_header.credits = 32;
        read_resp_header.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let read_resp = pack_message(
            &read_resp_header,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut close_resp_header = Header::new_request(Command::Close);
        close_resp_header.flags.set_response();
        close_resp_header.credits = 32;
        close_resp_header.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_resp = pack_message(
            &close_resp_header,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        let result = tree.read_file_compound(&mut conn, "nonexistent.txt").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status(), Some(NtStatus::OBJECT_NAME_NOT_FOUND));
    }

    #[tokio::test]
    async fn read_file_compound_read_failure_issues_standalone_close() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        let file_id = FileId {
            persistent: 0x42,
            volatile: 0x99,
        };

        // CREATE succeeds.
        let create_resp = build_create_response(file_id, 1024);

        // READ fails with INSUFFICIENT_RESOURCES.
        let mut read_resp_header = Header::new_request(Command::Read);
        read_resp_header.flags.set_response();
        read_resp_header.credits = 32;
        read_resp_header.status = NtStatus::INSUFFICIENT_RESOURCES;
        let read_resp = pack_message(
            &read_resp_header,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        // CLOSE also fails (cascaded).
        let mut close_resp_header = Header::new_request(Command::Close);
        close_resp_header.flags.set_response();
        close_resp_header.credits = 32;
        close_resp_header.status = NtStatus::INSUFFICIENT_RESOURCES;
        let close_resp = pack_message(
            &close_resp_header,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        // Queue a standalone CLOSE response for the cleanup.
        mock.queue_response(build_close_response());

        let result = tree.read_file_compound(&mut conn, "problem.txt").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status(), Some(NtStatus::INSUFFICIENT_RESOURCES));

        // Should have sent: TreeConnect + compound + standalone CLOSE = 3.
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn read_file_compound_sends_correct_request_structure() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        let file_id = FileId {
            persistent: 1,
            volatile: 2,
        };
        let create_resp = build_create_response(file_id, 5);
        let read_resp = build_read_response(NtStatus::SUCCESS, vec![1, 2, 3, 4, 5]);
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        tree.read_file_compound(&mut conn, "verify.txt")
            .await
            .unwrap();

        // The second sent message is the compound request.
        let compound = mock.sent_message(1).unwrap();

        // Verify it contains 3 headers linked by NextCommand.
        let mut cursor = ReadCursor::new(&compound);
        let h1 = Header::unpack(&mut cursor).unwrap();
        assert_eq!(h1.command, Command::Create);
        assert!(!h1.flags.is_related());
        assert!(h1.next_command > 0);
        assert_eq!(h1.tree_id, Some(TreeId(7)));

        let off2 = h1.next_command as usize;
        let mut cursor2 = ReadCursor::new(&compound[off2..]);
        let h2 = Header::unpack(&mut cursor2).unwrap();
        assert_eq!(h2.command, Command::Read);
        assert!(h2.flags.is_related());
        assert!(h2.next_command > 0);

        // Verify READ uses sentinel FileId.
        let read_parsed = ReadRequest::unpack(&mut cursor2).unwrap();
        assert_eq!(read_parsed.file_id, FileId::SENTINEL);

        let off3 = off2 + h2.next_command as usize;
        let mut cursor3 = ReadCursor::new(&compound[off3..]);
        let h3 = Header::unpack(&mut cursor3).unwrap();
        assert_eq!(h3.command, Command::Close);
        assert!(h3.flags.is_related());
        assert_eq!(h3.next_command, 0);

        // Verify CLOSE uses sentinel FileId.
        let close_parsed = CloseRequest::unpack(&mut cursor3).unwrap();
        assert_eq!(close_parsed.file_id, FileId::SENTINEL);
    }

    // ── Compound write tests ────────────────────────────────────────

    #[tokio::test]
    async fn write_file_compound_returns_bytes_written() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        let file_id = FileId {
            persistent: 0x42,
            volatile: 0x99,
        };
        let file_data = b"Hello, compound write!";

        let create_resp = build_create_response(file_id, 0);
        let write_resp = build_write_response(file_data.len() as u32);
        let flush_resp = build_flush_response();
        let close_resp = build_close_response();

        let frame =
            build_compound_response_frame(&[create_resp, write_resp, flush_resp, close_resp]);
        mock.queue_response(frame);

        let written = tree
            .write_file_compound(&mut conn, "test.txt", file_data)
            .await
            .unwrap();

        assert_eq!(written, file_data.len() as u64);
        // Should have sent one compound frame (plus the tree connect).
        assert_eq!(mock.sent_count(), 2); // TreeConnect + compound
    }

    #[tokio::test]
    async fn write_file_compound_empty_file() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        let file_id = FileId {
            persistent: 1,
            volatile: 2,
        };

        let create_resp = build_create_response(file_id, 0);
        let write_resp = build_write_response(0);
        let flush_resp = build_flush_response();
        let close_resp = build_close_response();

        let frame =
            build_compound_response_frame(&[create_resp, write_resp, flush_resp, close_resp]);
        mock.queue_response(frame);

        let written = tree
            .write_file_compound(&mut conn, "empty.txt", b"")
            .await
            .unwrap();

        assert_eq!(written, 0);
    }

    #[tokio::test]
    async fn write_file_compound_create_failure_returns_error() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        // Build compound response where CREATE fails.
        // When CREATE fails, server cascades error to WRITE, FLUSH, and CLOSE.
        let mut create_h = Header::new_request(Command::Create);
        create_h.flags.set_response();
        create_h.credits = 32;
        create_h.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_resp = pack_message(
            &create_h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut write_h = Header::new_request(Command::Write);
        write_h.flags.set_response();
        write_h.credits = 32;
        write_h.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let write_resp = pack_message(
            &write_h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut flush_h = Header::new_request(Command::Flush);
        flush_h.flags.set_response();
        flush_h.credits = 32;
        flush_h.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let flush_resp = pack_message(
            &flush_h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let mut close_h = Header::new_request(Command::Close);
        close_h.flags.set_response();
        close_h.credits = 32;
        close_h.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let close_resp = pack_message(
            &close_h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame =
            build_compound_response_frame(&[create_resp, write_resp, flush_resp, close_resp]);
        mock.queue_response(frame);

        let result = tree
            .write_file_compound(&mut conn, "bad/path.txt", b"data")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status(), Some(NtStatus::OBJECT_NAME_NOT_FOUND));
    }

    #[tokio::test]
    async fn write_file_compound_write_failure_issues_standalone_close() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        let file_id = FileId {
            persistent: 0x42,
            volatile: 0x99,
        };

        // CREATE succeeds.
        let create_resp = build_create_response(file_id, 0);

        // WRITE fails with INSUFFICIENT_RESOURCES.
        let mut write_h = Header::new_request(Command::Write);
        write_h.flags.set_response();
        write_h.credits = 32;
        write_h.status = NtStatus::INSUFFICIENT_RESOURCES;
        let write_resp = pack_message(
            &write_h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        // FLUSH also fails (cascaded).
        let mut flush_h = Header::new_request(Command::Flush);
        flush_h.flags.set_response();
        flush_h.credits = 32;
        flush_h.status = NtStatus::INSUFFICIENT_RESOURCES;
        let flush_resp = pack_message(
            &flush_h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        // CLOSE also fails (cascaded).
        let mut close_h = Header::new_request(Command::Close);
        close_h.flags.set_response();
        close_h.credits = 32;
        close_h.status = NtStatus::INSUFFICIENT_RESOURCES;
        let close_resp = pack_message(
            &close_h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );

        let frame =
            build_compound_response_frame(&[create_resp, write_resp, flush_resp, close_resp]);
        mock.queue_response(frame);

        // Queue a standalone CLOSE response for the cleanup.
        mock.queue_response(build_close_response());

        let result = tree
            .write_file_compound(&mut conn, "problem.txt", b"data")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status(), Some(NtStatus::INSUFFICIENT_RESOURCES));

        // Should have sent: TreeConnect + compound + standalone CLOSE = 3.
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn write_file_compound_sends_correct_request_structure() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        mock.queue_response(build_tree_connect_response(TreeId(7), ShareType::Disk));
        let tree = Tree::connect(&mut conn, "share").await.unwrap();

        let file_id = FileId {
            persistent: 1,
            volatile: 2,
        };
        let create_resp = build_create_response(file_id, 0);
        let write_resp = build_write_response(5);
        let flush_resp = build_flush_response();
        let close_resp = build_close_response();
        let frame =
            build_compound_response_frame(&[create_resp, write_resp, flush_resp, close_resp]);
        mock.queue_response(frame);

        tree.write_file_compound(&mut conn, "verify.txt", &[1, 2, 3, 4, 5])
            .await
            .unwrap();

        // The second sent message is the compound request.
        let compound = mock.sent_message(1).unwrap();

        // Verify it contains 4 headers linked by NextCommand.
        let mut cursor = ReadCursor::new(&compound);
        let h1 = Header::unpack(&mut cursor).unwrap();
        assert_eq!(h1.command, Command::Create);
        assert!(!h1.flags.is_related());
        assert!(h1.next_command > 0);
        assert_eq!(h1.tree_id, Some(TreeId(7)));

        let off2 = h1.next_command as usize;
        let mut cursor2 = ReadCursor::new(&compound[off2..]);
        let h2 = Header::unpack(&mut cursor2).unwrap();
        assert_eq!(h2.command, Command::Write);
        assert!(h2.flags.is_related());
        assert!(h2.next_command > 0);

        // Verify WRITE uses sentinel FileId.
        let write_parsed = WriteRequest::unpack(&mut cursor2).unwrap();
        assert_eq!(write_parsed.file_id, FileId::SENTINEL);
        assert_eq!(write_parsed.data, vec![1, 2, 3, 4, 5]);

        let off3 = off2 + h2.next_command as usize;
        let mut cursor3 = ReadCursor::new(&compound[off3..]);
        let h3 = Header::unpack(&mut cursor3).unwrap();
        assert_eq!(h3.command, Command::Flush);
        assert!(h3.flags.is_related());
        assert!(h3.next_command > 0);

        // Verify FLUSH uses sentinel FileId.
        let flush_parsed = FlushRequest::unpack(&mut cursor3).unwrap();
        assert_eq!(flush_parsed.file_id, FileId::SENTINEL);

        let off4 = off3 + h3.next_command as usize;
        let mut cursor4 = ReadCursor::new(&compound[off4..]);
        let h4 = Header::unpack(&mut cursor4).unwrap();
        assert_eq!(h4.command, Command::Close);
        assert!(h4.flags.is_related());
        assert_eq!(h4.next_command, 0);

        // Verify CLOSE uses sentinel FileId.
        let close_parsed = CloseRequest::unpack(&mut cursor4).unwrap();
        assert_eq!(close_parsed.file_id, FileId::SENTINEL);
    }

    // ── BUFFER_OVERFLOW tests ───────────────────────────────────────

    #[tokio::test]
    async fn stat_accepts_buffer_overflow_as_partial_data() {
        // STATUS_BUFFER_OVERFLOW is a warning, not an error. The response
        // body contains valid partial data and should be parsed.
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xCC,
            volatile: 0xDD,
        };

        // STAT = CREATE + basic (BUFFER_OVERFLOW) + standard + identity + volume + CLOSE.
        let create_resp = build_create_response(file_id, 0);

        let basic = build_file_basic_info(
            132_000_000_000_000_000,
            132_100_000_000_000_000,
            133_000_000_000_000_000,
            133_000_000_000_000_000,
            0x20, // ARCHIVE
        );
        let basic_resp = build_query_info_response_with_status(NtStatus::BUFFER_OVERFLOW, basic);

        let std_info = build_file_standard_info(4096, 1024, 1, false, false);
        let std_resp = build_query_info_response(std_info);
        let identity_resp = build_query_info_response(build_file_internal_info(0x1234));
        let volume_resp = build_query_info_response(build_file_fs_volume_info(0xABCD));

        let close_resp = build_close_response();

        let frame = build_compound_response_frame(&[
            create_resp,
            basic_resp,
            std_resp,
            identity_resp,
            volume_resp,
            close_resp,
        ]);
        mock.queue_response(frame);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        // Should succeed despite BUFFER_OVERFLOW on the basic info query.
        let info = tree.stat(&mut conn, "partial.txt").await.unwrap();
        assert_eq!(info.size, 1024);
        assert!(!info.is_directory);
        assert_eq!(info.created, FileTime(132_000_000_000_000_000));
        // One compound frame sent.
        assert_eq!(mock.sent_count(), 1);
    }

    // ── Streamed write tests ───────────────────────────────────────

    #[tokio::test]
    async fn write_file_streamed_basic() {
        // Provide 3 small chunks, verify CREATE + 3 WRITEs + CLOSE.
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        };

        let chunk1 = vec![0x01; 100];
        let chunk2 = vec![0x02; 200];
        let chunk3 = vec![0x03; 150];
        let chunks = vec![Ok(chunk1.clone()), Ok(chunk2.clone()), Ok(chunk3.clone())];
        let mut chunk_iter = chunks.into_iter();

        // Queue: CREATE, 3x WRITE, FLUSH, CLOSE.
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(200));
        mock.queue_response(build_write_response(150));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(30),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut next_chunk =
            move || -> Option<std::result::Result<Vec<u8>, std::io::Error>> { chunk_iter.next() };

        let written = tree
            .write_file_streamed(&mut conn, "streamed.bin", &mut next_chunk)
            .await
            .unwrap();

        assert_eq!(written, 450); // 100 + 200 + 150

        // Verify CREATE + 3 WRITEs + FLUSH + CLOSE = 6 messages.
        assert_eq!(mock.sent_count(), 6);

        // Verify WRITE offsets and data.
        // Message 0 = CREATE, 1..3 = WRITEs, 4 = FLUSH, 5 = CLOSE.
        let sent1 = mock.sent_message(1).unwrap();
        let mut cursor1 = ReadCursor::new(&sent1);
        let _ = Header::unpack(&mut cursor1).unwrap();
        let req1 = WriteRequest::unpack(&mut cursor1).unwrap();
        assert_eq!(req1.offset, 0);
        assert_eq!(req1.data, chunk1);

        let sent2 = mock.sent_message(2).unwrap();
        let mut cursor2 = ReadCursor::new(&sent2);
        let _ = Header::unpack(&mut cursor2).unwrap();
        let req2 = WriteRequest::unpack(&mut cursor2).unwrap();
        assert_eq!(req2.offset, 100);
        assert_eq!(req2.data, chunk2);

        let sent3 = mock.sent_message(3).unwrap();
        let mut cursor3 = ReadCursor::new(&sent3);
        let _ = Header::unpack(&mut cursor3).unwrap();
        let req3 = WriteRequest::unpack(&mut cursor3).unwrap();
        assert_eq!(req3.offset, 300);
        assert_eq!(req3.data, chunk3);

        // Verify last message is CLOSE.
        let sent5 = mock.sent_message(5).unwrap();
        let mut cursor5 = ReadCursor::new(&sent5);
        let h5 = Header::unpack(&mut cursor5).unwrap();
        assert_eq!(h5.command, Command::Close);
    }

    #[tokio::test]
    async fn write_file_streamed_empty() {
        // Callback returns None immediately -> CREATE + FLUSH + CLOSE (empty file).
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xCC,
            volatile: 0xDD,
        };

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(31),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut next_chunk = || -> Option<std::result::Result<Vec<u8>, std::io::Error>> { None };

        let written = tree
            .write_file_streamed(&mut conn, "empty_stream.bin", &mut next_chunk)
            .await
            .unwrap();

        assert_eq!(written, 0);
        // CREATE + FLUSH + CLOSE = 3 messages.
        assert_eq!(mock.sent_count(), 3);

        // Verify CREATE then FLUSH then CLOSE.
        let sent0 = mock.sent_message(0).unwrap();
        let mut c0 = ReadCursor::new(&sent0);
        let h0 = Header::unpack(&mut c0).unwrap();
        assert_eq!(h0.command, Command::Create);

        let sent1 = mock.sent_message(1).unwrap();
        let mut c1 = ReadCursor::new(&sent1);
        let h1 = Header::unpack(&mut c1).unwrap();
        assert_eq!(h1.command, Command::Flush);

        let sent2 = mock.sent_message(2).unwrap();
        let mut c2 = ReadCursor::new(&sent2);
        let h2 = Header::unpack(&mut c2).unwrap();
        assert_eq!(h2.command, Command::Close);
    }

    #[tokio::test]
    async fn write_file_streamed_callback_error() {
        // Callback returns Ok on first call, Err on second.
        // Verify: handle is closed (CLOSE sent) and error is propagated.
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xEE,
            volatile: 0xFF,
        };

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(64));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(32),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut call_count = 0u32;
        let mut next_chunk = move || -> Option<std::result::Result<Vec<u8>, std::io::Error>> {
            call_count += 1;
            match call_count {
                1 => Some(Ok(vec![0x42; 64])),
                2 => Some(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "source stream broke",
                ))),
                _ => None,
            }
        };

        let result = tree
            .write_file_streamed(&mut conn, "error_stream.bin", &mut next_chunk)
            .await;

        assert!(result.is_err(), "expected error from callback to propagate");

        // Verify CLOSE was still sent (handle cleanup).
        // Messages: CREATE + WRITE + CLOSE = 3.
        assert_eq!(mock.sent_count(), 3);

        let sent_last = mock.sent_message(2).unwrap();
        let mut cl = ReadCursor::new(&sent_last);
        let hl = Header::unpack(&mut cl).unwrap();
        assert_eq!(hl.command, Command::Close);
    }

    #[tokio::test]
    async fn write_file_streamed_callback_error_is_not_connection_lost() {
        // A callback error is a consumer issue, not a connection failure.
        // The error kind should NOT be ConnectionLost — the connection is
        // still usable after write_file_streamed drains in-flight responses.
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(64));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(40),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut call_count = 0u32;
        let mut next_chunk = move || -> Option<std::result::Result<Vec<u8>, std::io::Error>> {
            call_count += 1;
            match call_count {
                1 => Some(Ok(vec![0x42; 64])),
                2 => Some(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "user cancelled",
                ))),
                _ => None,
            }
        };

        let err = tree
            .write_file_streamed(&mut conn, "cancel_test.bin", &mut next_chunk)
            .await
            .unwrap_err();

        // The error should NOT be classified as ConnectionLost.
        // A callback cancellation doesn't break the SMB connection — all
        // in-flight responses were drained and the handle was closed cleanly.
        assert_ne!(
            err.kind(),
            crate::ErrorKind::ConnectionLost,
            "callback error should not be classified as ConnectionLost; the connection is still healthy"
        );
    }

    #[tokio::test]
    async fn write_file_streamed_callback_error_connection_still_usable() {
        // After a callback error in write_file_streamed, the connection should
        // be in a clean state: all in-flight WRITE responses drained, handle
        // CLOSEd. A subsequent operation (read_file) should work.
        let mock = Arc::new(MockTransport::new());
        let write_file_id = FileId {
            persistent: 0x33,
            volatile: 0x44,
        };
        let read_file_id = FileId {
            persistent: 0x55,
            volatile: 0x66,
        };

        // Phase 1: Streamed write that errors after 2 chunks.
        // With max_write=65536, 2 small chunks fit in the initial window.
        mock.queue_response(build_create_response(write_file_id, 0));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(200));
        mock.queue_response(build_close_response());

        // Phase 2: A subsequent read_file (compound: CREATE+READ+CLOSE).
        let read_data = b"hello from the server";
        mock.queue_response(build_compound_read_response(
            read_file_id,
            read_data.to_vec(),
        ));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(41),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        // Streamed write: 2 chunks succeed, then callback errors.
        let mut call_count = 0u32;
        let mut next_chunk = move || -> Option<std::result::Result<Vec<u8>, std::io::Error>> {
            call_count += 1;
            match call_count {
                1 => Some(Ok(vec![0xAA; 100])),
                2 => Some(Ok(vec![0xBB; 200])),
                3 => Some(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled by user",
                ))),
                _ => None,
            }
        };

        let write_result = tree
            .write_file_streamed(&mut conn, "partial.bin", &mut next_chunk)
            .await;
        assert!(
            write_result.is_err(),
            "write should fail due to callback error"
        );

        // Now verify the connection still works: read a file.
        let data = tree
            .read_file_compound(&mut conn, "other.txt")
            .await
            .unwrap();
        assert_eq!(data, read_data);
    }

    /// Builds a compound CREATE+READ+CLOSE response (single transport frame)
    /// for use with `read_file_compound`.
    fn build_compound_read_response(file_id: FileId, data: Vec<u8>) -> Vec<u8> {
        use crate::msg::read::ReadResponse;

        // CREATE response (chained: next_command points to READ response)
        let mut h1 = Header::new_request(Command::Create);
        h1.flags.set_response();
        h1.credits = 32;
        let create_body = CreateResponse {
            oplock_level: OplockLevel::None,
            flags: 0u8,
            create_action: CreateAction::FileOpened,
            creation_time: crate::pack::FileTime(0),
            last_access_time: crate::pack::FileTime(0),
            last_write_time: crate::pack::FileTime(0),
            change_time: crate::pack::FileTime(0),
            allocation_size: 0,
            end_of_file: data.len() as u64,
            file_attributes: 0x80,
            file_id,
            create_contexts: vec![],
        };
        let create_bytes = pack_message(&h1, &create_body);

        // READ response (chained: next_command points to CLOSE response)
        let mut h2 = Header::new_request(Command::Read);
        h2.flags.set_response();
        h2.credits = 32;
        let read_body = ReadResponse {
            data_offset: 0x50,
            data: data.clone(),
            data_remaining: 0,
            flags: 0,
        };
        let read_bytes = pack_message(&h2, &read_body);

        // CLOSE response (last in chain)
        let close_bytes = build_close_response();

        // Patch next_command offsets for compounding
        let mut frame = Vec::new();

        let mut create_buf = create_bytes;
        let create_len = create_buf.len();
        // Align to 8 bytes
        let padded_create_len = (create_len + 7) & !7;
        create_buf.resize(padded_create_len, 0);
        // Set NextCommand in header (offset 20, 4 bytes LE)
        let next_cmd = padded_create_len as u32;
        create_buf[20..24].copy_from_slice(&next_cmd.to_le_bytes());
        // Set RELATED_OPERATIONS flag on subsequent headers? No — compound READ
        // uses the same file_id from CREATE, but read_file_compound sends
        // FileId::SENTINEL which gets filled in by the server. For mock,
        // we just need the responses to parse correctly.
        frame.extend_from_slice(&create_buf);

        let mut read_buf = read_bytes;
        let read_len = read_buf.len();
        let padded_read_len = (read_len + 7) & !7;
        read_buf.resize(padded_read_len, 0);
        let next_cmd2 = padded_read_len as u32;
        read_buf[20..24].copy_from_slice(&next_cmd2.to_le_bytes());
        frame.extend_from_slice(&read_buf);

        frame.extend_from_slice(&close_bytes);

        frame
    }

    // ── Tree::download (streaming via &mut Connection) ─────────────────────

    /// Happy path: `Tree::download` returns a `FileDownload` that yields
    /// all chunks of a small file in order and closes the handle cleanly.
    #[tokio::test]
    async fn tree_download_streams_small_file() {
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 0xA1,
            volatile: 0xB2,
        };
        let payload = b"streaming hello from Tree::download".to_vec();

        // CREATE (open_file) — server returns handle + size.
        mock.queue_response(build_create_response(file_id, payload.len() as u64));
        // Single READ covering the whole file (payload fits in one
        // max_read_size=65536 chunk).
        mock.queue_response(build_read_response(NtStatus::SUCCESS, payload.clone()));
        // CLOSE after the last chunk.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(11),
            share_name: "share".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut download = tree
            .download(&mut conn, "hello.txt")
            .await
            .expect("download");
        assert_eq!(download.size(), payload.len() as u64);

        let mut received = Vec::new();
        while let Some(chunk) = download.next_chunk().await {
            let bytes = chunk.expect("chunk");
            received.extend_from_slice(&bytes);
        }
        assert_eq!(received, payload);

        // CREATE + READ + CLOSE = 3 messages on the wire.
        assert_eq!(mock.sent_count(), 3);
        mock.assert_fully_consumed();
    }

    /// Error path: if CREATE fails, `Tree::download` surfaces the NTSTATUS
    /// as `Error::Protocol` without ever constructing a `FileDownload`.
    #[tokio::test]
    async fn tree_download_create_failure_returns_protocol_error() {
        let mock = Arc::new(MockTransport::new());

        let mut create_hdr = Header::new_request(Command::Create);
        create_hdr.flags.set_response();
        create_hdr.credits = 32;
        create_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let create_err = pack_message(
            &create_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );
        mock.queue_response(create_err);

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(12),
            share_name: "share".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let result = tree.download(&mut conn, "missing.txt").await;
        let err = result.err().expect("expected error");
        assert_eq!(err.status(), Some(NtStatus::OBJECT_NAME_NOT_FOUND));
    }

    /// Dropping a `FileDownload` mid-stream (before draining all chunks)
    /// must not panic. The `Drop` impl logs a warning; the handle may leak
    /// on the server, but the client stays healthy.
    #[tokio::test]
    async fn tree_download_drop_mid_stream_does_not_panic() {
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 0xC3,
            volatile: 0xD4,
        };
        // 3x max_read_size payload so at least one READ remains unsent
        // after the caller drops early.
        let total = 3 * 65536usize;
        mock.queue_response(build_create_response(file_id, total as u64));
        // Queue one READ response; we'll consume only that one and drop.
        mock.queue_response(build_read_response(NtStatus::SUCCESS, vec![0xAB; 65536]));

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id: TreeId(13),
            share_name: "share".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        };

        let mut download = tree.download(&mut conn, "big.bin").await.expect("download");

        let first = download
            .next_chunk()
            .await
            .expect("first chunk exists")
            .expect("first chunk ok");
        assert_eq!(first.len(), 65536);

        // Drop mid-stream -- must not panic.
        drop(download);
    }

    /// Two `Tree::download` futures on cloned `Connection`s must both
    /// complete with correct data, proving the headline reason for adding
    /// `Tree::download`: concurrent downloads on one SMB session.
    ///
    /// The mock transport routes responses via the Phase 3 receiver task
    /// (shared across all `Connection::clone()`s), so msg-id demux is what
    /// wires each CREATE/READ/CLOSE to the right waiter. We queue the
    /// responses AFTER the sends land (just like
    /// `concurrent_execute_on_one_connection_all_succeed` in
    /// `connection.rs`) so `enable_auto_rewrite_msg_id` can stamp them in
    /// FIFO send order. Both downloads use the same payload, so it doesn't
    /// matter which task's READ lands in which slot — whoever gets routed
    /// their msg_id wins the correct bytes.
    ///
    /// Gotcha/Why: if the two tasks fetched DIFFERENT payloads, the FIFO
    /// auto-rewrite in `MockTransport` would mis-pair sends and responses
    /// unless we hand-serialized each phase across tasks, which would
    /// defeat the concurrency the test is meant to prove. Keeping the
    /// payloads identical lets both downloads race freely while we still
    /// assert correctness of the whole pipeline.
    #[tokio::test(flavor = "multi_thread")]
    async fn tree_download_concurrent_on_cloned_connections() {
        use std::time::{Duration, Instant};

        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();

        let params = crate::client::connection::NegotiatedParams {
            dialect: crate::types::Dialect::Smb2_0_2,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: crate::pack::Guid::ZERO,
            signing_required: false,
            capabilities: crate::types::flags::Capabilities::default(),
            gmac_negotiated: false,
            cipher: None,
            compression_supported: false,
        };
        let mut conn_primary = crate::client::connection::Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn_primary.set_test_params(params);
        conn_primary.set_session_id(crate::types::SessionId(0x1234));
        conn_primary.set_credits(512);
        let mut conn_secondary = conn_primary.clone();

        let tree = Arc::new(Tree {
            tree_id: TreeId(14),
            share_name: "share".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        });

        let payload = b"shared-body-for-both-readers".to_vec();

        let file_id_1 = FileId {
            persistent: 0x0A,
            volatile: 0x1A,
        };
        let file_id_2 = FileId {
            persistent: 0x0B,
            volatile: 0x1B,
        };

        let tree_a = Arc::clone(&tree);
        let payload_a = payload.clone();
        let handle_a = tokio::spawn(async move {
            let mut dl = tree_a
                .download(&mut conn_primary, "same.txt")
                .await
                .expect("download a");
            let mut buf = Vec::new();
            while let Some(c) = dl.next_chunk().await {
                buf.extend_from_slice(&c.expect("chunk a"));
            }
            assert_eq!(buf, payload_a);
        });

        let tree_b = Arc::clone(&tree);
        let payload_b = payload.clone();
        let handle_b = tokio::spawn(async move {
            let mut dl = tree_b
                .download(&mut conn_secondary, "same.txt")
                .await
                .expect("download b");
            let mut buf = Vec::new();
            while let Some(c) = dl.next_chunk().await {
                buf.extend_from_slice(&c.expect("chunk b"));
            }
            assert_eq!(buf, payload_b);
        });

        // Wait for both CREATE sends before queuing responses.
        let deadline = Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < 2 {
            if Instant::now() > deadline {
                panic!("CREATE sends did not land: {}", mock.sent_count());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        mock.queue_response(build_create_response(file_id_1, payload.len() as u64));
        mock.queue_response(build_create_response(file_id_2, payload.len() as u64));

        // Wait for both READs, then answer with identical payloads.
        let deadline = Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < 4 {
            if Instant::now() > deadline {
                panic!("READ sends did not land: {}", mock.sent_count());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        mock.queue_response(build_read_response(NtStatus::SUCCESS, payload.clone()));
        mock.queue_response(build_read_response(NtStatus::SUCCESS, payload.clone()));

        // Both downloads issue a CLOSE after the final chunk.
        let deadline = Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < 6 {
            if Instant::now() > deadline {
                panic!("CLOSE sends did not land: {}", mock.sent_count());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        mock.queue_response(build_close_response());
        mock.queue_response(build_close_response());

        handle_a.await.expect("task a panicked");
        handle_b.await.expect("task b panicked");

        assert_eq!(mock.sent_count(), 6); // 2 CREATE + 2 READ + 2 CLOSE
    }
}
