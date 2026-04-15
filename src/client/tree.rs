//! Tree (share) connection and file operations.
//!
//! The [`Tree`] type represents a connection to a specific share on the server.
//! It provides methods for directory listing, file reading/writing, deletion,
//! renaming, stat, and directory creation.

use std::ops::ControlFlow;

use log::{debug, info, trace, warn};

use crate::client::connection::Connection;
use crate::client::stream::Progress;
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
use crate::types::{Command, CreditCharge, FileId, MessageId, OplockLevel, TreeId};
use crate::Error;

/// Maximum number of requests to keep in flight during pipelining.
///
/// More than 32 in-flight requests creates diminishing returns and
/// increases memory usage (buffering responses). 32 x 64 KB = 2 MB
/// in flight is plenty for Gigabit LAN.
const MAX_PIPELINE_WINDOW: usize = 32;

/// File attribute constant: the entry is a directory.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// Create option: the target must be a directory.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

/// Create option: the target must not be a directory.
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

/// Create option: delete file when all handles are closed.
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// FileBasicInformation class for QUERY_INFO (MS-FSCC 2.4.7).
const FILE_BASIC_INFORMATION: u8 = 4;

/// FileStandardInformation class for QUERY_INFO (MS-FSCC 2.4.41).
const FILE_STANDARD_INFORMATION: u8 = 5;

/// FileRenameInformation class for SET_INFO (MS-FSCC 2.4.34.2).
const FILE_RENAME_INFORMATION: u8 = 10;

/// FileFsFullSizeInformation class for QUERY_INFO (MS-FSCC 2.5.4).
const FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;

/// A directory entry returned by [`Tree::list_directory`].
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
}

/// File metadata returned by [`Tree::stat`].
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

impl Tree {
    /// Connect to a share on the server.
    ///
    /// Sends a TREE_CONNECT request with the UNC path `\\server\share`
    /// encoded in UTF-16LE.
    pub async fn connect(conn: &mut Connection, share_name: &str) -> Result<Tree> {
        let server = conn.server_name().to_string();
        let unc_path = format!(r"\\{}\{}", server, share_name);

        let req = TreeConnectRequest {
            flags: TreeConnectRequestFlags::default(),
            path: unc_path,
        };

        let (_, _req_raw) = conn.send_request(Command::TreeConnect, &req, None).await?;

        let (resp_header, resp_body, _resp_raw) = conn.receive_response().await?;

        if resp_header.command != Command::TreeConnect {
            return Err(Error::invalid_data(format!(
                "expected TreeConnect response, got {:?}",
                resp_header.command
            )));
        }

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::TreeConnect,
            });
        }

        let mut cursor = ReadCursor::new(&resp_body);
        let resp = TreeConnectResponse::unpack(&mut cursor)?;

        let tree_id = resp_header
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
    fn format_path(&self, path: &str) -> String {
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

    /// List files in a directory.
    ///
    /// Opens the directory with CREATE, queries entries with QUERY_DIRECTORY
    /// (looping until STATUS_NO_MORE_FILES), then closes the handle.
    pub async fn list_directory(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<Vec<DirectoryEntry>> {
        let normalized = self.format_path(path);
        debug!("tree: list_directory path={}", normalized);

        // Open the directory.
        let file_id = self.open_directory(conn, &normalized).await?;

        // Query directory entries.
        let result = self.query_directory_loop(conn, file_id).await;

        // Close the handle regardless of query result.
        let close_result = self.close_handle(conn, file_id).await;

        // Return the query result, or if it succeeded, check the close result.
        let entries = result?;
        close_result?;
        debug!("tree: list_directory done, entries={}", entries.len());
        Ok(entries)
    }

    /// Read a small file using a compound CREATE+READ+CLOSE request.
    ///
    /// Sends all three operations in a single transport frame, reducing
    /// round-trips from 3 to 1. Best for files that fit in a single
    /// READ (up to MaxReadSize).
    ///
    /// For files larger than MaxReadSize, use `read_file_pipelined` instead.
    pub async fn read_file_compound(&self, conn: &mut Connection, path: &str) -> Result<Vec<u8>> {
        let normalized = self.format_path(path);
        let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
        debug!(
            "tree: read_file_compound path={}, max_read={}",
            normalized, max_read
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
        let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::Read, &read_req, CreditCharge(read_credit_charge)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(self.tree_id, &operations).await?;

        // Receive compound response.
        let responses = conn.receive_compound().await?;

        if responses.len() != 3 {
            return Err(Error::invalid_data(format!(
                "expected 3 compound responses, got {}",
                responses.len()
            )));
        }

        let (create_header, create_body) = &responses[0];
        let (read_header, read_body) = &responses[1];
        let (close_header, _close_body) = &responses[2];

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

        debug!("tree: read_file_compound done, read {} bytes", data.len());
        Ok(data)
    }

    /// Read a file's contents using a compound request (1 round-trip).
    ///
    /// Sends CREATE+READ+CLOSE as a single compound message. For files
    /// that fit in MaxReadSize (typically 8 MB), this is the fastest
    /// path -- 1 round-trip instead of 3+.
    ///
    /// For files larger than MaxReadSize, the compound returns only the
    /// first chunk. In that case, use [`read_file_pipelined`](Self::read_file_pipelined)
    /// for concurrent chunked reads.
    pub async fn read_file(&self, conn: &mut Connection, path: &str) -> Result<Vec<u8>> {
        self.read_file_compound(conn, path).await
    }

    /// Disconnect from the share.
    pub async fn disconnect(&self, conn: &mut Connection) -> Result<()> {
        debug!(
            "tree: disconnecting share={}, tree_id={}",
            self.share_name, self.tree_id
        );
        let body = TreeDisconnectRequest;
        let (_, _) = conn
            .send_request(Command::TreeDisconnect, &body, Some(self.tree_id))
            .await?;

        let (resp_header, _, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
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
    /// The returned `Watcher` borrows the connection mutably, so no other
    /// operations can run on it while watching. Use a separate connection
    /// (a second `SmbClient`) if you need to perform operations while watching.
    pub async fn watch<'a>(
        &'a self,
        conn: &'a mut Connection,
        path: &str,
        recursive: bool,
    ) -> Result<crate::client::watcher::Watcher<'a>> {
        let normalized = self.format_path(path);
        debug!(
            "tree: watch path={}, recursive={}, tree_id={}",
            normalized, recursive, self.tree_id
        );

        // Open the directory with FILE_LIST_DIRECTORY access (same as
        // FILE_READ_DATA = 0x0001). We need the handle to stay open for
        // the lifetime of the watcher.
        let file_id = self.open_directory(conn, &normalized).await?;

        Ok(crate::client::watcher::Watcher::new(
            self, conn, file_id, recursive,
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

    /// Delete multiple files using batch compound requests.
    ///
    /// Sends all compound (CREATE+CLOSE) requests before waiting for any
    /// responses, minimizing total round-trips. Returns results in the same
    /// order as the input paths. Each file's result is independent -- one
    /// failure does not affect the others.
    pub async fn delete_files(&self, conn: &mut Connection, paths: &[&str]) -> Vec<Result<()>> {
        if paths.is_empty() {
            return vec![];
        }

        debug!("tree: delete_files batch, count={}", paths.len());

        // Phase 1: Send all compound requests.
        let mut sent_count = 0;
        let mut send_error: Option<Error> = None;

        for path in paths {
            let normalized = self.format_path(path);
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
                create_options: FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE,
                name: normalized,
                create_contexts: vec![],
            };

            let close_req = CloseRequest {
                flags: 0,
                file_id: FileId::SENTINEL,
            };

            let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
                (Command::Create, &create_req, CreditCharge(1)),
                (Command::Close, &close_req, CreditCharge(1)),
            ];

            match conn.send_compound(self.tree_id, &operations).await {
                Ok(_) => sent_count += 1,
                Err(e) => {
                    send_error = Some(e);
                    break;
                }
            }
        }

        // Phase 2: Receive all compound responses.
        let mut results: Vec<Result<()>> = Vec::with_capacity(paths.len());
        let mut cleanup_handles: Vec<FileId> = Vec::new();

        for (i, path) in paths.iter().enumerate().take(sent_count) {
            match conn.receive_compound().await {
                Ok(responses) => {
                    if responses.len() != 2 {
                        results.push(Err(Error::invalid_data(format!(
                            "expected 2 compound responses, got {}",
                            responses.len()
                        ))));
                        continue;
                    }

                    let (create_header, create_body) = &responses[0];
                    let (close_header, _) = &responses[1];

                    if create_header.status != NtStatus::SUCCESS {
                        results.push(Err(Error::Protocol {
                            status: create_header.status,
                            command: Command::Create,
                        }));
                    } else if close_header.status != NtStatus::SUCCESS {
                        // CREATE succeeded, CLOSE failed. Need cleanup.
                        if let Ok(create_resp) =
                            CreateResponse::unpack(&mut ReadCursor::new(create_body))
                        {
                            cleanup_handles.push(create_resp.file_id);
                        }
                        results.push(Err(Error::Protocol {
                            status: close_header.status,
                            command: Command::Close,
                        }));
                    } else {
                        info!("tree: batch deleted file={}", path);
                        results.push(Ok(()));
                    }
                }
                Err(e) => {
                    results.push(Err(e));
                    for _ in (i + 1)..sent_count {
                        results.push(Err(Error::Disconnected));
                    }
                    break;
                }
            }
        }

        // Fill unsent paths with the send error.
        if let Some(err) = send_error {
            results.push(Err(err));
            for _ in (sent_count + 1)..paths.len() {
                results.push(Err(Error::Disconnected));
            }
        }

        // Phase 3: Cleanup -- issue standalone CLOSEs for leaked handles.
        for file_id in &cleanup_handles {
            warn!(
                "tree: batch delete cleanup, issuing standalone CLOSE for {:?}",
                file_id
            );
            let _ = self.close_handle(conn, *file_id).await;
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
    /// QUERY_INFO (FileStandardInformation) + CLOSE as a single compound message.
    pub async fn stat(&self, conn: &mut Connection, path: &str) -> Result<FileInfo> {
        let normalized = self.format_path(path);
        debug!("tree: stat (compound) path={}", normalized);

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

        // CLOSE with sentinel FileId.
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::QueryInfo, &basic_req, CreditCharge(1)),
            (Command::QueryInfo, &std_req, CreditCharge(1)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(self.tree_id, &operations).await?;
        let responses = conn.receive_compound().await?;

        if responses.len() != 4 {
            return Err(Error::invalid_data(format!(
                "expected 4 compound responses, got {}",
                responses.len()
            )));
        }

        let (create_header, create_body) = &responses[0];
        let (basic_header, basic_body) = &responses[1];
        let (std_header, std_body) = &responses[2];
        let (close_header, _close_body) = &responses[3];

        // If CREATE failed, all ops cascade. No handle to clean up.
        if create_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        // Check first QUERY_INFO (basic). If it failed, issue standalone CLOSE.
        if !basic_header.status.is_success_or_partial() {
            let mut cursor = ReadCursor::new(create_body);
            let create_resp = CreateResponse::unpack(&mut cursor)?;
            warn!(
                "tree: compound QUERY_INFO (basic) failed ({:?}), issuing standalone CLOSE",
                basic_header.status
            );
            let _ = self.close_handle(conn, create_resp.file_id).await;
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
        let _change_time = u64::from_le_bytes(basic_buf[24..32].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(basic_buf[32..36].try_into().unwrap());

        // Check second QUERY_INFO (standard). If it failed, issue standalone CLOSE.
        if !std_header.status.is_success_or_partial() {
            let mut cursor = ReadCursor::new(create_body);
            let create_resp = CreateResponse::unpack(&mut cursor)?;
            warn!(
                "tree: compound QUERY_INFO (standard) failed ({:?}), issuing standalone CLOSE",
                std_header.status
            );
            let _ = self.close_handle(conn, create_resp.file_id).await;
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

        // Check CLOSE response (non-fatal, we already have the data).
        if close_header.status != NtStatus::SUCCESS {
            debug!(
                "tree: compound CLOSE returned {:?} (non-fatal, stat data already read)",
                close_header.status,
            );
        }

        debug!(
            "tree: stat done, size={}, is_dir={}",
            end_of_file, is_directory
        );
        Ok(FileInfo {
            size: end_of_file,
            is_directory,
            created,
            modified,
            accessed,
        })
    }

    /// Stat multiple files using batch compound requests.
    ///
    /// Sends all compound (CREATE+QUERY_INFO+QUERY_INFO+CLOSE) requests before
    /// waiting for any responses. Returns results in the same order as the
    /// input paths.
    pub async fn stat_files(&self, conn: &mut Connection, paths: &[&str]) -> Vec<Result<FileInfo>> {
        if paths.is_empty() {
            return vec![];
        }

        debug!("tree: stat_files batch, count={}", paths.len());

        // Phase 1: Send all compound requests.
        let mut sent_count = 0;
        let mut send_error: Option<Error> = None;

        for path in paths {
            let normalized = self.format_path(path);

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
                name: normalized,
                create_contexts: vec![],
            };

            let basic_req = QueryInfoRequest {
                info_type: InfoType::File,
                file_info_class: FILE_BASIC_INFORMATION,
                output_buffer_length: 40,
                additional_information: 0,
                flags: 0,
                file_id: FileId::SENTINEL,
                input_buffer: vec![],
            };

            let std_req = QueryInfoRequest {
                info_type: InfoType::File,
                file_info_class: FILE_STANDARD_INFORMATION,
                output_buffer_length: 24,
                additional_information: 0,
                flags: 0,
                file_id: FileId::SENTINEL,
                input_buffer: vec![],
            };

            let close_req = CloseRequest {
                flags: 0,
                file_id: FileId::SENTINEL,
            };

            let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
                (Command::Create, &create_req, CreditCharge(1)),
                (Command::QueryInfo, &basic_req, CreditCharge(1)),
                (Command::QueryInfo, &std_req, CreditCharge(1)),
                (Command::Close, &close_req, CreditCharge(1)),
            ];

            match conn.send_compound(self.tree_id, &operations).await {
                Ok(_) => sent_count += 1,
                Err(e) => {
                    send_error = Some(e);
                    break;
                }
            }
        }

        // Phase 2: Receive all compound responses.
        let mut results: Vec<Result<FileInfo>> = Vec::with_capacity(paths.len());
        let mut cleanup_handles: Vec<FileId> = Vec::new();

        for i in 0..sent_count {
            match conn.receive_compound().await {
                Ok(responses) => {
                    results.push(self.parse_stat_batch_response(&responses, &mut cleanup_handles));
                    if results[i].is_ok() {
                        debug!("tree: batch stat done for file={}", paths[i]);
                    }
                }
                Err(e) => {
                    results.push(Err(e));
                    for _ in (i + 1)..sent_count {
                        results.push(Err(Error::Disconnected));
                    }
                    break;
                }
            }
        }

        // Fill unsent paths with the send error.
        if let Some(err) = send_error {
            results.push(Err(err));
            for _ in (sent_count + 1)..paths.len() {
                results.push(Err(Error::Disconnected));
            }
        }

        // Phase 3: Cleanup -- standalone CLOSEs for leaked handles.
        for file_id in &cleanup_handles {
            warn!(
                "tree: batch stat cleanup, issuing standalone CLOSE for {:?}",
                file_id
            );
            let _ = self.close_handle(conn, *file_id).await;
        }

        debug!(
            "tree: stat_files batch done, {}/{} succeeded",
            results.iter().filter(|r| r.is_ok()).count(),
            paths.len()
        );
        results
    }

    /// Parse a single stat compound response for the batch stat method.
    fn parse_stat_batch_response(
        &self,
        responses: &[(crate::msg::header::Header, Vec<u8>)],
        cleanup_handles: &mut Vec<FileId>,
    ) -> Result<FileInfo> {
        if responses.len() != 4 {
            return Err(Error::invalid_data(format!(
                "expected 4 compound responses, got {}",
                responses.len()
            )));
        }

        let (create_header, create_body) = &responses[0];
        let (basic_header, basic_body) = &responses[1];
        let (std_header, std_body) = &responses[2];

        if create_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        // CREATE succeeded -- if a later op fails, we need cleanup.
        let file_id = CreateResponse::unpack(&mut ReadCursor::new(create_body))
            .map(|r| r.file_id)
            .ok();

        if !basic_header.status.is_success_or_partial() {
            if let Some(fid) = file_id {
                cleanup_handles.push(fid);
            }
            return Err(Error::Protocol {
                status: basic_header.status,
                command: Command::QueryInfo,
            });
        }

        let mut cursor = ReadCursor::new(basic_body);
        let basic_resp = QueryInfoResponse::unpack(&mut cursor)?;
        let basic_buf = &basic_resp.output_buffer;

        if basic_buf.len() < 36 {
            if let Some(fid) = file_id {
                cleanup_handles.push(fid);
            }
            return Err(Error::invalid_data(format!(
                "FileBasicInformation too short: {} bytes",
                basic_buf.len()
            )));
        }

        let created = FileTime(u64::from_le_bytes(basic_buf[0..8].try_into().unwrap()));
        let accessed = FileTime(u64::from_le_bytes(basic_buf[8..16].try_into().unwrap()));
        let modified = FileTime(u64::from_le_bytes(basic_buf[16..24].try_into().unwrap()));
        let file_attributes = u32::from_le_bytes(basic_buf[32..36].try_into().unwrap());

        if !std_header.status.is_success_or_partial() {
            if let Some(fid) = file_id {
                cleanup_handles.push(fid);
            }
            return Err(Error::Protocol {
                status: std_header.status,
                command: Command::QueryInfo,
            });
        }

        let mut cursor = ReadCursor::new(std_body);
        let std_resp = QueryInfoResponse::unpack(&mut cursor)?;
        let std_buf = &std_resp.output_buffer;

        if std_buf.len() < 22 {
            if let Some(fid) = file_id {
                cleanup_handles.push(fid);
            }
            return Err(Error::invalid_data(format!(
                "FileStandardInformation too short: {} bytes",
                std_buf.len()
            )));
        }

        let end_of_file = u64::from_le_bytes(std_buf[8..16].try_into().unwrap());
        let is_directory_byte = std_buf[21];

        let is_directory =
            is_directory_byte != 0 || (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        Ok(FileInfo {
            size: end_of_file,
            is_directory,
            created,
            modified,
            accessed,
        })
    }

    /// Query file system space information for this share.
    ///
    /// Returns total capacity, free space, and allocation unit sizes.
    /// Uses a compound CREATE+QUERY_INFO+CLOSE for efficiency (one round-trip).
    pub async fn fs_info(&self, conn: &mut Connection) -> Result<FsInfo> {
        debug!("tree: fs_info on share={}", self.share_name);

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
        let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::QueryInfo, &query_req, CreditCharge(1)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(self.tree_id, &operations).await?;

        // Receive compound response.
        let responses = conn.receive_compound().await?;

        if responses.len() != 3 {
            return Err(Error::invalid_data(format!(
                "expected 3 compound responses, got {}",
                responses.len()
            )));
        }

        let (create_header, _create_body) = &responses[0];
        let (query_header, query_body) = &responses[1];
        let (close_header, _close_body) = &responses[2];

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
            let mut cursor = ReadCursor::new(&responses[0].1);
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

        debug!(
            "tree: fs_info done, total={}, free={}, total_free={}",
            total_bytes, free_bytes, total_free_bytes
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
    /// compound message.
    pub async fn rename(&self, conn: &mut Connection, from: &str, to: &str) -> Result<()> {
        let from_normalized = self.format_path(from);
        let to_normalized = normalize_path(to);
        debug!(
            "tree: rename (compound) from={} to={}",
            from_normalized, to_normalized
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
            buffer: build_rename_info_buffer(&to_normalized),
        };

        // Build CLOSE request with sentinel FileId.
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::SetInfo, &setinfo_req, CreditCharge(1)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(self.tree_id, &operations).await?;
        let responses = conn.receive_compound().await?;

        if responses.len() != 3 {
            return Err(Error::invalid_data(format!(
                "expected 3 compound responses, got {}",
                responses.len()
            )));
        }

        let (create_header, create_body) = &responses[0];
        let (setinfo_header, _setinfo_body) = &responses[1];
        let (close_header, _close_body) = &responses[2];

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

        info!(
            "tree: renamed from={} to={}",
            from_normalized, to_normalized
        );
        Ok(())
    }

    /// Rename multiple files using batch compound requests.
    ///
    /// Sends all compound (CREATE+SET_INFO+CLOSE) requests before waiting for
    /// any responses. Returns results in the same order as the input pairs.
    pub async fn rename_files(
        &self,
        conn: &mut Connection,
        renames: &[(&str, &str)],
    ) -> Vec<Result<()>> {
        if renames.is_empty() {
            return vec![];
        }

        debug!("tree: rename_files batch, count={}", renames.len());

        // Phase 1: Send all compound requests.
        let mut sent_count = 0;
        let mut send_error: Option<Error> = None;

        for (from, to) in renames {
            let from_normalized = self.format_path(from);
            let to_normalized = normalize_path(to);

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
                name: from_normalized,
                create_contexts: vec![],
            };

            let setinfo_req = SetInfoRequest {
                info_type: InfoType::File,
                file_info_class: FILE_RENAME_INFORMATION,
                additional_information: 0,
                file_id: FileId::SENTINEL,
                buffer: build_rename_info_buffer(&to_normalized),
            };

            let close_req = CloseRequest {
                flags: 0,
                file_id: FileId::SENTINEL,
            };

            let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
                (Command::Create, &create_req, CreditCharge(1)),
                (Command::SetInfo, &setinfo_req, CreditCharge(1)),
                (Command::Close, &close_req, CreditCharge(1)),
            ];

            match conn.send_compound(self.tree_id, &operations).await {
                Ok(_) => sent_count += 1,
                Err(e) => {
                    send_error = Some(e);
                    break;
                }
            }
        }

        // Phase 2: Receive all compound responses.
        let mut results: Vec<Result<()>> = Vec::with_capacity(renames.len());
        let mut cleanup_handles: Vec<FileId> = Vec::new();

        for (i, (from, to)) in renames.iter().enumerate().take(sent_count) {
            match conn.receive_compound().await {
                Ok(responses) => {
                    if responses.len() != 3 {
                        results.push(Err(Error::invalid_data(format!(
                            "expected 3 compound responses, got {}",
                            responses.len()
                        ))));
                        continue;
                    }

                    let (create_header, create_body) = &responses[0];
                    let (setinfo_header, _) = &responses[1];
                    let (close_header, _) = &responses[2];

                    if create_header.status != NtStatus::SUCCESS {
                        results.push(Err(Error::Protocol {
                            status: create_header.status,
                            command: Command::Create,
                        }));
                    } else if setinfo_header.status != NtStatus::SUCCESS {
                        // CREATE succeeded, SET_INFO failed. Need cleanup.
                        if let Ok(create_resp) =
                            CreateResponse::unpack(&mut ReadCursor::new(create_body))
                        {
                            cleanup_handles.push(create_resp.file_id);
                        }
                        results.push(Err(Error::Protocol {
                            status: setinfo_header.status,
                            command: Command::SetInfo,
                        }));
                    } else {
                        // Check CLOSE (non-fatal if rename succeeded).
                        if close_header.status != NtStatus::SUCCESS {
                            debug!(
                                "tree: batch rename CLOSE returned {:?} (non-fatal)",
                                close_header.status,
                            );
                        }
                        info!("tree: batch renamed from={} to={}", from, to);
                        results.push(Ok(()));
                    }
                }
                Err(e) => {
                    results.push(Err(e));
                    for _ in (i + 1)..sent_count {
                        results.push(Err(Error::Disconnected));
                    }
                    break;
                }
            }
        }

        // Fill unsent paths with the send error.
        if let Some(err) = send_error {
            results.push(Err(err));
            for _ in (sent_count + 1)..renames.len() {
                results.push(Err(Error::Disconnected));
            }
        }

        // Phase 3: Cleanup -- standalone CLOSEs for leaked handles.
        for file_id in &cleanup_handles {
            warn!(
                "tree: batch rename cleanup, issuing standalone CLOSE for {:?}",
                file_id
            );
            let _ = self.close_handle(conn, *file_id).await;
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
        debug!(
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
        let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (
                Command::Write,
                &write_req,
                CreditCharge(write_credit_charge),
            ),
            (Command::Flush, &flush_req, CreditCharge(1)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(self.tree_id, &operations).await?;

        // Receive compound response.
        let responses = conn.receive_compound().await?;

        if responses.len() != 4 {
            return Err(Error::invalid_data(format!(
                "expected 4 compound responses, got {}",
                responses.len()
            )));
        }

        let (create_header, create_body) = &responses[0];
        let (write_header, write_body) = &responses[1];
        let (flush_header, _flush_body) = &responses[2];
        let (close_header, _close_body) = &responses[3];

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
        let normalized = self.format_path(path);

        // Open the file.
        let (file_id, file_size) = self.open_file(conn, &normalized).await?;

        if file_size == 0 {
            debug!(
                "tree: read_file_pipelined path={}, size=0 (empty file)",
                normalized
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
        debug!(
            "tree: read_file_pipelined path={}, size={}, chunk_size={}, credit_charge={}, total_chunks={}, credits={}",
            normalized, file_size, chunk_size, credit_charge, total_chunks, conn.credits()
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
        let normalized = self.format_path(path);

        let (file_id, file_size) = self.open_file(conn, &normalized).await?;

        if file_size == 0 {
            debug!(
                "tree: read_file_pipelined_with_progress path={}, size=0 (empty file)",
                normalized
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
        debug!(
            "tree: read_file_pipelined_with_progress path={}, size={}, chunk_size={}, total_chunks={}",
            normalized, file_size, chunk_size, total_chunks
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
            debug!(
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

        let (_, _) = conn
            .send_request(Command::Create, &req, Some(self.tree_id))
            .await?;

        let (resp_header, resp_body, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&resp_body);
        let create_resp = CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        // Use MaxWriteSize for pipelined writes: minimizes overhead for
        // large payloads being sent (we're sending data, not just a small request).
        let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);
        let chunk_size = max_write;
        let credit_charge = chunk_size.div_ceil(65536) as u16;
        let total_chunks = data.len().div_ceil(chunk_size as usize);
        debug!(
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
        let normalized = self.format_path(path);
        debug!("tree: write_file_streamed path={}", normalized);

        // Open (or create) the file for writing.
        let file_id = self.open_file_for_write(conn, &normalized).await?;

        let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);

        let start = std::time::Instant::now();
        let result = self
            .write_streamed_loop(conn, file_id, next_chunk, max_write)
            .await;

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

    /// Create a directory.
    ///
    /// Opens the path with `FileCreate` disposition and `FILE_DIRECTORY_FILE`
    /// option, then immediately closes the handle.
    pub async fn create_directory(&self, conn: &mut Connection, path: &str) -> Result<()> {
        let normalized = self.format_path(path);
        debug!("tree: create_directory path={}", normalized);

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

        let (_, _) = conn
            .send_request(Command::Create, &req, Some(self.tree_id))
            .await?;

        let (resp_header, resp_body, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&resp_body);
        let create_resp = CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        // Close the handle immediately.
        self.close_handle(conn, file_id).await?;
        info!("tree: created directory={}", normalized);
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

    /// Compound CREATE (DELETE_ON_CLOSE) + CLOSE in a single round-trip.
    ///
    /// `type_option` selects file vs directory (`FILE_NON_DIRECTORY_FILE`
    /// or `FILE_DIRECTORY_FILE`). `kind` is used only for log messages.
    async fn delete_compound(
        &self,
        conn: &mut Connection,
        path: &str,
        type_option: u32,
        kind: &str,
    ) -> Result<()> {
        let normalized = self.format_path(path);
        debug!("tree: delete_{} (compound) path={}", kind, normalized);

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
            create_options: FILE_DELETE_ON_CLOSE | type_option,
            name: normalized.clone(),
            create_contexts: vec![],
        };

        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let operations: Vec<(Command, &dyn crate::pack::Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(self.tree_id, &operations).await?;
        let responses = conn.receive_compound().await?;

        if responses.len() != 2 {
            return Err(Error::invalid_data(format!(
                "expected 2 compound responses, got {}",
                responses.len()
            )));
        }

        let (create_header, create_body) = &responses[0];
        let (close_header, _close_body) = &responses[1];

        // If CREATE failed, all ops in the compound fail (cascaded). No handle to clean up.
        if create_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: create_header.status,
                command: Command::Create,
            });
        }

        // CREATE succeeded. If CLOSE failed, issue a standalone CLOSE
        // to avoid leaking the handle (and to ensure deletion happens).
        if close_header.status != NtStatus::SUCCESS {
            let mut cursor = ReadCursor::new(create_body);
            let create_resp = CreateResponse::unpack(&mut cursor)?;
            warn!(
                "tree: compound CLOSE failed ({:?}), issuing standalone CLOSE",
                close_header.status
            );
            let _ = self.close_handle(conn, create_resp.file_id).await;
            return Err(Error::Protocol {
                status: close_header.status,
                command: Command::Close,
            });
        }

        info!("tree: deleted {}={}", kind, normalized);
        Ok(())
    }

    /// Open a directory handle.
    async fn open_directory(&self, conn: &mut Connection, path: &str) -> Result<FileId> {
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

        let (_, _) = conn
            .send_request(Command::Create, &req, Some(self.tree_id))
            .await?;

        let (resp_header, resp_body, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&resp_body);
        let resp = CreateResponse::unpack(&mut cursor)?;
        Ok(resp.file_id)
    }

    /// Open a file handle and return the file ID and size.
    pub(crate) async fn open_file(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<(FileId, u64)> {
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
            name: path.to_string(),
            create_contexts: vec![],
        };

        let (_, _) = conn
            .send_request(Command::Create, &req, Some(self.tree_id))
            .await?;

        let (resp_header, resp_body, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&resp_body);
        let resp = CreateResponse::unpack(&mut cursor)?;
        Ok((resp.file_id, resp.end_of_file))
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
            name: path.to_string(),
            create_contexts: vec![],
        };

        let (_, _) = conn
            .send_request(Command::Create, &req, Some(self.tree_id))
            .await?;

        let (resp_header, resp_body, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Create,
            });
        }

        let mut cursor = ReadCursor::new(&resp_body);
        let resp = CreateResponse::unpack(&mut cursor)?;
        Ok(resp.file_id)
    }

    /// Loop QUERY_DIRECTORY until STATUS_NO_MORE_FILES.
    async fn query_directory_loop(
        &self,
        conn: &mut Connection,
        file_id: FileId,
    ) -> Result<Vec<DirectoryEntry>> {
        // Cap output buffer to 65536 so that CreditCharge=1 is valid.
        // The spec requires CreditCharge = 1 + (OutputBufferLength - 1) / 65536
        // for multi-credit dialects. Using 65536 keeps CreditCharge=1 which
        // matches what send_request sets, while still being plenty for dir entries.
        let max_output = conn
            .params()
            .map(|p| p.max_transact_size.min(65536))
            .unwrap_or(65536);

        let mut all_entries = Vec::new();
        let mut first = true;

        loop {
            let req = QueryDirectoryRequest {
                file_information_class: FileInformationClass::FileBothDirectoryInformation,
                flags: QueryDirectoryFlags(if first {
                    QueryDirectoryFlags::RESTART_SCANS
                } else {
                    0
                }),
                file_index: 0,
                file_id,
                output_buffer_length: max_output,
                file_name: "*".to_string(),
            };
            first = false;

            let (_, _) = conn
                .send_request(Command::QueryDirectory, &req, Some(self.tree_id))
                .await?;

            let (resp_header, resp_body, _) = conn.receive_response().await?;

            if resp_header.status == NtStatus::NO_MORE_FILES {
                break;
            }

            if resp_header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: resp_header.status,
                    command: Command::QueryDirectory,
                });
            }

            let mut cursor = ReadCursor::new(&resp_body);
            let resp = QueryDirectoryResponse::unpack(&mut cursor)?;

            // Parse FileBothDirectoryInformation entries from the output buffer.
            let entries = parse_file_both_directory_info(&resp.output_buffer)?;
            for e in &entries {
                trace!(
                    "tree: dir_entry name={}, size={}, is_dir={}",
                    e.name,
                    e.size,
                    e.is_directory
                );
            }
            all_entries.extend(entries);
        }

        Ok(all_entries)
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

            let (_, _) = conn
                .send_request(Command::Read, &req, Some(self.tree_id))
                .await?;

            let (resp_header, resp_body, _) = conn.receive_response().await?;

            // STATUS_END_OF_FILE means we read past the end.
            if resp_header.status == NtStatus::END_OF_FILE {
                break;
            }

            if resp_header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: resp_header.status,
                    command: Command::Read,
                });
            }

            let mut cursor = ReadCursor::new(&resp_body);
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
        let mut data = vec![0u8; file_size as usize];
        let mut chunks_sent = 0usize;
        let mut chunks_received = 0usize;
        let mut in_flight: Vec<(MessageId, usize)> = Vec::new();

        // Initial fill: send up to window_size reads.
        let max_from_credits = conn.credits() as usize / credit_charge.max(1) as usize;
        let initial_window = total_chunks.min(max_from_credits).min(MAX_PIPELINE_WINDOW);

        if initial_window == 0 {
            return Err(Error::invalid_data(
                "no credits available for pipelined read",
            ));
        }

        debug!(
            "tree: pipeline read sliding window: initial_window={}, total_chunks={}, credits={}",
            initial_window,
            total_chunks,
            conn.credits()
        );

        for _ in 0..initial_window {
            let offset = chunks_sent as u64 * chunk_size as u64;
            let this_chunk = if chunks_sent == total_chunks - 1 {
                (file_size - offset) as u32
            } else {
                chunk_size
            };

            let req = ReadRequest {
                padding: 0x50,
                flags: 0,
                length: this_chunk,
                offset,
                file_id,
                minimum_count: 0,
                channel: SMB2_CHANNEL_NONE,
                remaining_bytes: 0,
                read_channel_info: vec![],
            };

            let (msg_id, _) = conn
                .send_request_with_credits(Command::Read, &req, Some(self.tree_id), credit_charge)
                .await?;

            in_flight.push((msg_id, chunks_sent));
            chunks_sent += 1;
        }

        // Sliding loop: receive one, send one, until all chunks received.
        while chunks_received < total_chunks {
            let (resp_header, resp_body, _) = conn.receive_response().await?;
            chunks_received += 1;

            if resp_header.status == NtStatus::END_OF_FILE {
                // File is shorter than expected. Continue collecting remaining
                // in-flight responses but don't send more.
                continue;
            }

            if resp_header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: resp_header.status,
                    command: Command::Read,
                });
            }

            // Find which chunk this response belongs to by matching MessageId.
            let msg_id = resp_header.message_id;
            let chunk_index = in_flight
                .iter()
                .find(|(mid, _)| *mid == msg_id)
                .map(|(_, idx)| *idx)
                .ok_or_else(|| {
                    Error::invalid_data(format!(
                        "received response with unexpected MessageId {}",
                        msg_id
                    ))
                })?;

            let mut cursor = ReadCursor::new(&resp_body);
            let resp = ReadResponse::unpack(&mut cursor)?;

            if !resp.data.is_empty() {
                // Place data at the correct offset.
                let dest_offset = chunk_index as u64 * chunk_size as u64;
                let dest_end = (dest_offset as usize + resp.data.len()).min(data.len());
                let src_len = dest_end - dest_offset as usize;
                data[dest_offset as usize..dest_end].copy_from_slice(&resp.data[..src_len]);
            }

            // Immediately send the next chunk if available and credits allow.
            if chunks_sent < total_chunks {
                let credits_available = conn.credits() as usize / credit_charge.max(1) as usize;
                if credits_available > 0 {
                    let offset = chunks_sent as u64 * chunk_size as u64;
                    let this_chunk = if chunks_sent == total_chunks - 1 {
                        (file_size - offset) as u32
                    } else {
                        chunk_size
                    };

                    let req = ReadRequest {
                        padding: 0x50,
                        flags: 0,
                        length: this_chunk,
                        offset,
                        file_id,
                        minimum_count: 0,
                        channel: SMB2_CHANNEL_NONE,
                        remaining_bytes: 0,
                        read_channel_info: vec![],
                    };

                    let (msg_id, _) = conn
                        .send_request_with_credits(
                            Command::Read,
                            &req,
                            Some(self.tree_id),
                            credit_charge,
                        )
                        .await?;

                    in_flight.push((msg_id, chunks_sent));
                    chunks_sent += 1;
                }
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
        let mut data = vec![0u8; file_size as usize];
        let mut chunks_sent = 0usize;
        let mut chunks_received = 0usize;
        let mut bytes_received = 0u64;
        let mut in_flight: Vec<(MessageId, usize)> = Vec::new();

        let max_from_credits = conn.credits() as usize / credit_charge.max(1) as usize;
        let initial_window = total_chunks.min(max_from_credits).min(MAX_PIPELINE_WINDOW);

        if initial_window == 0 {
            return Err(Error::invalid_data(
                "no credits available for pipelined read",
            ));
        }

        // Initial fill: send up to window_size reads.
        for _ in 0..initial_window {
            let offset = chunks_sent as u64 * chunk_size as u64;
            let this_chunk = if chunks_sent == total_chunks - 1 {
                (file_size - offset) as u32
            } else {
                chunk_size
            };

            let req = ReadRequest {
                padding: 0x50,
                flags: 0,
                length: this_chunk,
                offset,
                file_id,
                minimum_count: 0,
                channel: SMB2_CHANNEL_NONE,
                remaining_bytes: 0,
                read_channel_info: vec![],
            };

            let (msg_id, _) = conn
                .send_request_with_credits(Command::Read, &req, Some(self.tree_id), credit_charge)
                .await?;

            in_flight.push((msg_id, chunks_sent));
            chunks_sent += 1;
        }

        // Sliding loop: receive one, report progress, send one.
        while chunks_received < total_chunks {
            let (resp_header, resp_body, _) = conn.receive_response().await?;
            chunks_received += 1;

            if resp_header.status == NtStatus::END_OF_FILE {
                continue;
            }

            if resp_header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: resp_header.status,
                    command: Command::Read,
                });
            }

            let msg_id = resp_header.message_id;
            let chunk_index = in_flight
                .iter()
                .find(|(mid, _)| *mid == msg_id)
                .map(|(_, idx)| *idx)
                .ok_or_else(|| {
                    Error::invalid_data(format!(
                        "received response with unexpected MessageId {}",
                        msg_id
                    ))
                })?;

            let mut cursor = ReadCursor::new(&resp_body);
            let resp = ReadResponse::unpack(&mut cursor)?;

            if !resp.data.is_empty() {
                let dest_offset = chunk_index as u64 * chunk_size as u64;
                let dest_end = (dest_offset as usize + resp.data.len()).min(data.len());
                let src_len = dest_end - dest_offset as usize;
                data[dest_offset as usize..dest_end].copy_from_slice(&resp.data[..src_len]);
                bytes_received += src_len as u64;
            }

            // Report progress and check for cancellation.
            let progress = Progress {
                bytes_transferred: bytes_received,
                total_bytes: Some(file_size),
            };
            if let ControlFlow::Break(()) = on_progress(progress) {
                return Err(Error::Cancelled);
            }

            // Send next chunk if available.
            if chunks_sent < total_chunks {
                let credits_available = conn.credits() as usize / credit_charge.max(1) as usize;
                if credits_available > 0 {
                    let offset = chunks_sent as u64 * chunk_size as u64;
                    let this_chunk = if chunks_sent == total_chunks - 1 {
                        (file_size - offset) as u32
                    } else {
                        chunk_size
                    };

                    let req = ReadRequest {
                        padding: 0x50,
                        flags: 0,
                        length: this_chunk,
                        offset,
                        file_id,
                        minimum_count: 0,
                        channel: SMB2_CHANNEL_NONE,
                        remaining_bytes: 0,
                        read_channel_info: vec![],
                    };

                    let (msg_id, _) = conn
                        .send_request_with_credits(
                            Command::Read,
                            &req,
                            Some(self.tree_id),
                            credit_charge,
                        )
                        .await?;

                    in_flight.push((msg_id, chunks_sent));
                    chunks_sent += 1;
                }
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
        let mut chunks_sent = 0usize;
        let mut chunks_received = 0usize;
        let mut total_written = 0u64;

        // Initial fill: send up to window_size writes.
        let max_from_credits = conn.credits() as usize / credit_charge.max(1) as usize;
        let initial_window = total_chunks.min(max_from_credits).min(MAX_PIPELINE_WINDOW);

        if initial_window == 0 {
            return Err(Error::invalid_data(
                "no credits available for pipelined write",
            ));
        }

        debug!(
            "tree: pipeline write sliding window: initial_window={}, total_chunks={}, credits={}",
            initial_window,
            total_chunks,
            conn.credits()
        );

        for _ in 0..initial_window {
            let offset = chunks_sent * chunk_size as usize;
            let end = (offset + chunk_size as usize).min(data.len());
            let chunk = &data[offset..end];

            let req = WriteRequest {
                data_offset: 0x70, // header (64) + fixed write body (48) = 112 = 0x70
                offset: offset as u64,
                file_id,
                channel: 0,
                remaining_bytes: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: 0,
                data: chunk.to_vec(),
            };

            let (_, _) = conn
                .send_request_with_credits(Command::Write, &req, Some(self.tree_id), credit_charge)
                .await?;

            chunks_sent += 1;
        }

        // Sliding loop: receive one, send one, until all chunks received.
        while chunks_received < total_chunks {
            let (resp_header, resp_body, _) = conn.receive_response().await?;
            chunks_received += 1;

            if resp_header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: resp_header.status,
                    command: Command::Write,
                });
            }

            let mut cursor = ReadCursor::new(&resp_body);
            let resp = WriteResponse::unpack(&mut cursor)?;
            total_written += resp.count as u64;

            // Immediately send the next chunk if available and credits allow.
            if chunks_sent < total_chunks {
                let credits_available = conn.credits() as usize / credit_charge.max(1) as usize;
                if credits_available > 0 {
                    let offset = chunks_sent * chunk_size as usize;
                    let end = (offset + chunk_size as usize).min(data.len());
                    let chunk = &data[offset..end];

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

                    let (_, _) = conn
                        .send_request_with_credits(
                            Command::Write,
                            &req,
                            Some(self.tree_id),
                            credit_charge,
                        )
                        .await?;

                    chunks_sent += 1;
                }
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
        let mut offset = 0u64;
        let mut in_flight = 0usize;
        let mut total_written = 0u64;
        let mut done = false; // callback exhausted or errored
        let mut callback_err: Option<std::io::Error> = None;

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

        // Initial fill: send up to window_size writes.
        loop {
            let credit_charge_per = max_write.div_ceil(65536).max(1) as u16;
            let max_from_credits = conn.credits() as usize / credit_charge_per.max(1) as usize;
            let can_send = max_from_credits.min(MAX_PIPELINE_WINDOW.saturating_sub(in_flight));

            if can_send == 0 {
                break;
            }

            let chunk = next_wire_chunk(
                &mut pending_data,
                &mut pending_offset,
                &mut done,
                &mut callback_err,
                next_chunk,
            );

            match chunk {
                None => break,
                Some(data) => {
                    let credit_charge = (data.len() as u64).div_ceil(65536).max(1) as u16;
                    let req = WriteRequest {
                        data_offset: 0x70,
                        offset,
                        file_id,
                        channel: 0,
                        remaining_bytes: 0,
                        write_channel_info_offset: 0,
                        write_channel_info_length: 0,
                        flags: 0,
                        data: data.clone(),
                    };

                    let (_, _) = conn
                        .send_request_with_credits(
                            Command::Write,
                            &req,
                            Some(self.tree_id),
                            credit_charge,
                        )
                        .await?;

                    offset += data.len() as u64;
                    in_flight += 1;
                }
            }
        }

        // Sliding loop: receive one response, send next chunk (if any).
        while in_flight > 0 {
            let (resp_header, resp_body, _) = conn.receive_response().await?;
            in_flight -= 1;

            if resp_header.status != NtStatus::SUCCESS {
                // Drain remaining in-flight responses (best-effort).
                for _ in 0..in_flight {
                    let _ = conn.receive_response().await;
                }
                return Err(Error::Protocol {
                    status: resp_header.status,
                    command: Command::Write,
                });
            }

            let mut cursor = ReadCursor::new(&resp_body);
            let resp = WriteResponse::unpack(&mut cursor)?;
            total_written += resp.count as u64;

            // Send the next chunk if available and we don't have a pending error.
            if callback_err.is_none() {
                let chunk = next_wire_chunk(
                    &mut pending_data,
                    &mut pending_offset,
                    &mut done,
                    &mut callback_err,
                    next_chunk,
                );

                if let Some(data) = chunk {
                    let credit_charge = (data.len() as u64).div_ceil(65536).max(1) as u16;
                    let credits_available = conn.credits() as usize / credit_charge.max(1) as usize;

                    if credits_available > 0 {
                        let req = WriteRequest {
                            data_offset: 0x70,
                            offset,
                            file_id,
                            channel: 0,
                            remaining_bytes: 0,
                            write_channel_info_offset: 0,
                            write_channel_info_length: 0,
                            flags: 0,
                            data: data.clone(),
                        };

                        let (_, _) = conn
                            .send_request_with_credits(
                                Command::Write,
                                &req,
                                Some(self.tree_id),
                                credit_charge,
                            )
                            .await?;

                        offset += data.len() as u64;
                        in_flight += 1;
                    }
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
        debug!("tree: flushing file handle");
        let req = FlushRequest { file_id };

        let (_, _) = conn
            .send_request(Command::Flush, &req, Some(self.tree_id))
            .await?;

        let (resp_header, _, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Flush,
            });
        }

        Ok(())
    }

    /// Close a file handle.
    pub(crate) async fn close_handle(&self, conn: &mut Connection, file_id: FileId) -> Result<()> {
        let req = CloseRequest { flags: 0, file_id };

        let (_, _) = conn
            .send_request(Command::Close, &req, Some(self.tree_id))
            .await?;

        let (resp_header, _, _) = conn.receive_response().await?;

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Close,
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

            let (_, _) = conn
                .send_request(Command::Write, &req, Some(self.tree_id))
                .await?;

            let (resp_header, resp_body, _) = conn.receive_response().await?;

            if resp_header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: resp_header.status,
                    command: Command::Write,
                });
            }

            let mut cursor = ReadCursor::new(&resp_body);
            let resp = WriteResponse::unpack(&mut cursor)?;

            total_written += resp.count as u64;
            offset += chunk_size;
        }

        Ok(total_written)
    }
}

/// Build a FileRenameInformation buffer (MS-FSCC 2.4.34.2).
fn build_rename_info_buffer(new_name: &str) -> Vec<u8> {
    let name_u16: Vec<u16> = new_name.encode_utf16().collect();
    let name_byte_len = name_u16.len() * 2;

    let mut buf = Vec::with_capacity(20 + name_byte_len);
    buf.push(0); // ReplaceIfExists = false
    buf.extend_from_slice(&[0u8; 7]); // Reserved
    buf.extend_from_slice(&0u64.to_le_bytes()); // RootDirectory
    buf.extend_from_slice(&(name_byte_len as u32).to_le_bytes()); // FileNameLength
    for &u in &name_u16 {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    buf
}

/// Normalize a file path: convert `/` to `\` and strip leading `\`.
fn normalize_path(path: &str) -> String {
    let p = path.replace('/', "\\");
    p.trim_start_matches('\\').to_string()
}

/// Parse `FileBothDirectoryInformation` entries from raw bytes.
///
/// Each entry has:
/// - NextEntryOffset (4 bytes)
/// - FileIndex (4 bytes)
/// - CreationTime (8 bytes)
/// - LastAccessTime (8 bytes)
/// - LastWriteTime (8 bytes)
/// - ChangeTime (8 bytes)
/// - EndOfFile (8 bytes)
/// - AllocationSize (8 bytes)
/// - FileAttributes (4 bytes)
/// - FileNameLength (4 bytes)
/// - EaSize (4 bytes)
/// - ShortNameLength (1 byte)
/// - Reserved (1 byte)
/// - ShortName (24 bytes)
/// - FileName (variable, FileNameLength bytes)
fn parse_file_both_directory_info(data: &[u8]) -> Result<Vec<DirectoryEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    loop {
        if offset + 94 > data.len() {
            // Not enough data for the fixed part.
            break;
        }

        let entry_data = &data[offset..];
        let mut cursor = ReadCursor::new(entry_data);

        let next_entry_offset = cursor.read_u32_le()? as usize;
        let _file_index = cursor.read_u32_le()?;
        let creation_time = FileTime::unpack(&mut cursor)?;
        let _last_access_time = FileTime::unpack(&mut cursor)?;
        let last_write_time = FileTime::unpack(&mut cursor)?;
        let _change_time = FileTime::unpack(&mut cursor)?;
        let end_of_file = cursor.read_u64_le()?;
        let _allocation_size = cursor.read_u64_le()?;
        let file_attributes = cursor.read_u32_le()?;
        let file_name_length = cursor.read_u32_le()? as usize;
        let _ea_size = cursor.read_u32_le()?;
        let _short_name_length = cursor.read_u8()?;
        let _reserved = cursor.read_u8()?;
        // ShortName: 24 bytes (fixed, null-padded).
        cursor.skip(24)?;
        // FileName: FileNameLength bytes in UTF-16LE.
        let name = if file_name_length > 0 {
            cursor.read_utf16_le(file_name_length)?
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
        });

        if next_entry_offset == 0 {
            break;
        }
        offset += next_entry_offset;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::connection::pack_message;
    use crate::client::test_helpers::{
        build_close_response, build_create_response, build_tree_connect_response, setup_connection,
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

        if status == NtStatus::NO_MORE_FILES {
            // Error response body for NO_MORE_FILES.
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

    /// Build a single FileBothDirectoryInformation entry.
    fn build_file_both_dir_info(
        name: &str,
        size: u64,
        is_directory: bool,
        next_offset: u32,
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
        // ShortNameLength (1)
        buf.push(0);
        // Reserved (1)
        buf.push(0);
        // ShortName (24 bytes, zero-padded)
        buf.extend_from_slice(&[0u8; 24]);
        // FileName (variable)
        for &u in &name_u16 {
            buf.extend_from_slice(&u.to_le_bytes());
        }

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
        let entry1 = build_file_both_dir_info("file1.txt", 1024, false, 0);
        let total_entry_len = entry1.len();
        let entry1_with_next =
            build_file_both_dir_info("file1.txt", 1024, false, total_entry_len as u32);
        let entry2 = build_file_both_dir_info("subdir", 0, true, 0);

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
    async fn normalize_path_converts_slashes() {
        assert_eq!(normalize_path("foo/bar/baz"), "foo\\bar\\baz");
        assert_eq!(normalize_path("/leading/slash"), "leading\\slash");
        assert_eq!(normalize_path("\\leading\\backslash"), "leading\\backslash");
        assert_eq!(normalize_path("no_change"), "no_change");
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
    async fn parse_file_both_dir_info_single_entry() {
        let data = build_file_both_dir_info("test.txt", 42, false, 0);
        let entries = parse_file_both_directory_info(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
        assert_eq!(entries[0].size, 42);
        assert!(!entries[0].is_directory);
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

    fn build_query_info_response(output_buffer: Vec<u8>) -> Vec<u8> {
        build_query_info_response_with_status(NtStatus::SUCCESS, output_buffer)
    }

    fn build_query_info_response_with_status(status: NtStatus, output_buffer: Vec<u8>) -> Vec<u8> {
        use crate::msg::query_info::QueryInfoResponse;
        let mut h = Header::new_request(Command::QueryInfo);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;

        let body = QueryInfoResponse { output_buffer };
        pack_message(&h, &body)
    }

    fn build_set_info_response() -> Vec<u8> {
        use crate::msg::set_info::SetInfoResponse;
        let mut h = Header::new_request(Command::SetInfo);
        h.flags.set_response();
        h.credits = 32;

        let body = SetInfoResponse;
        pack_message(&h, &body)
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

    #[tokio::test]
    async fn delete_file_sends_compound_create_and_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        };

        // DELETE = compound CREATE(DELETE_ON_CLOSE) + CLOSE
        let create_resp = build_create_response(file_id, 0);
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, close_resp]);
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

        // Verify the CREATE request has DELETE access and DELETE_ON_CLOSE
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        assert!(req.desired_access.contains(FileAccessMask::DELETE));
        assert_ne!(req.create_options & FILE_DELETE_ON_CLOSE, 0);
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

        let frame = build_compound_response_frame(&[create_resp, close_resp]);
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

        // Compound: CREATE succeeds, CLOSE fails.
        let create_resp = build_create_response(file_id, 0);

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

        let frame = build_compound_response_frame(&[create_resp, close_resp]);
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

        // STAT = compound CREATE + QUERY_INFO(basic) + QUERY_INFO(standard) + CLOSE
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
        let close_resp = build_close_response();

        let frame = build_compound_response_frame(&[create_resp, basic_resp, std_resp, close_resp]);
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
        // One compound frame sent.
        assert_eq!(mock.sent_count(), 1);
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

        let frame = build_compound_response_frame(&[create_resp, q1_resp, q2_resp, close_resp]);
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

        let frame = build_compound_response_frame(&[create_resp, q1_resp, q2_resp, close_resp]);
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

        // Queue 3 compound responses (CREATE+QUERY+QUERY+CLOSE each).
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
            let close_resp = build_close_response();
            mock.queue_response(build_compound_response_frame(&[
                create_resp,
                basic_resp,
                std_resp,
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
        let close_resp = build_close_response();
        mock.queue_response(build_compound_response_frame(&[
            create_resp,
            basic_resp,
            std_resp,
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
            create_err, q1_err, q2_err, close_err,
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

    // ── Delete directory tests ───────────────────────────────────────

    #[tokio::test]
    async fn delete_directory_sends_compound_create_and_close() {
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0x55,
            volatile: 0x66,
        };

        // DELETE = compound CREATE(DELETE_ON_CLOSE) + CLOSE
        let create_resp = build_create_response(file_id, 0);
        let close_resp = build_close_response();
        let frame = build_compound_response_frame(&[create_resp, close_resp]);
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

        // Verify the CREATE has DELETE_ON_CLOSE and FILE_DIRECTORY_FILE
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        assert_ne!(req.create_options & FILE_DELETE_ON_CLOSE, 0);
        assert_ne!(req.create_options & FILE_DIRECTORY_FILE, 0);
    }

    // ── Batch delete tests ───────────────────────────────────────────

    #[tokio::test]
    async fn delete_files_batch_happy_path() {
        let mock = Arc::new(MockTransport::new());

        // Queue 3 compound responses (CREATE+CLOSE each).
        for i in 0..3u64 {
            let file_id = FileId {
                persistent: i + 1,
                volatile: i + 100,
            };
            let create_resp = build_create_response(file_id, 0);
            let close_resp = build_close_response();
            mock.queue_response(build_compound_response_frame(&[create_resp, close_resp]));
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
        let close_resp = build_close_response();
        mock.queue_response(build_compound_response_frame(&[create_resp, close_resp]));

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
        mock.queue_response(build_compound_response_frame(&[create_err, close_err]));

        // File 3: success
        let file_id = FileId {
            persistent: 3,
            volatile: 102,
        };
        let create_resp = build_create_response(file_id, 0);
        let close_resp = build_close_response();
        mock.queue_response(build_compound_response_frame(&[create_resp, close_resp]));

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
        mock.queue_response(build_compound_response_frame(&[create_resp, close_fail]));

        // File 2: success
        let file_id2 = FileId {
            persistent: 0xCC,
            volatile: 0xDD,
        };
        let create_resp2 = build_create_response(file_id2, 0);
        let close_resp2 = build_close_response();
        mock.queue_response(build_compound_response_frame(&[create_resp2, close_resp2]));

        // Queue response for the standalone CLOSE cleanup of file 1.
        mock.queue_response(build_close_response());

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
    fn build_compound_response_frame(responses: &[Vec<u8>]) -> Vec<u8> {
        let mut padded: Vec<Vec<u8>> = Vec::new();
        for (i, resp) in responses.iter().enumerate() {
            let mut r = resp.clone();
            let is_last = i == responses.len() - 1;
            if !is_last {
                // Pad to 8-byte alignment.
                let remainder = r.len() % 8;
                if remainder != 0 {
                    r.resize(r.len() + (8 - remainder), 0);
                }
                // Set NextCommand.
                let next_cmd = r.len() as u32;
                r[20..24].copy_from_slice(&next_cmd.to_le_bytes());
            }
            padded.push(r);
        }
        let mut frame = Vec::new();
        for r in &padded {
            frame.extend_from_slice(r);
        }
        frame
    }

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

        // STAT = compound CREATE + QUERY_INFO(basic, BUFFER_OVERFLOW) + QUERY_INFO(standard) + CLOSE
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

        let close_resp = build_close_response();

        let frame = build_compound_response_frame(&[create_resp, basic_resp, std_resp, close_resp]);
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

        // Queue: CREATE, 3x WRITE, CLOSE.
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(200));
        mock.queue_response(build_write_response(150));
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

        // Verify CREATE + 3 WRITEs + CLOSE = 5 messages.
        assert_eq!(mock.sent_count(), 5);

        // Verify WRITE offsets and data.
        // Message 0 = CREATE, 1..3 = WRITEs, 4 = CLOSE.
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
        let sent4 = mock.sent_message(4).unwrap();
        let mut cursor4 = ReadCursor::new(&sent4);
        let h4 = Header::unpack(&mut cursor4).unwrap();
        assert_eq!(h4.command, Command::Close);
    }

    #[tokio::test]
    async fn write_file_streamed_empty() {
        // Callback returns None immediately -> CREATE + CLOSE (empty file).
        let mock = Arc::new(MockTransport::new());
        let file_id = FileId {
            persistent: 0xCC,
            volatile: 0xDD,
        };

        mock.queue_response(build_create_response(file_id, 0));
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
        // CREATE + CLOSE = 2 messages.
        assert_eq!(mock.sent_count(), 2);

        // Verify CREATE then CLOSE.
        let sent0 = mock.sent_message(0).unwrap();
        let mut c0 = ReadCursor::new(&sent0);
        let h0 = Header::unpack(&mut c0).unwrap();
        assert_eq!(h0.command, Command::Create);

        let sent1 = mock.sent_message(1).unwrap();
        let mut c1 = ReadCursor::new(&sent1);
        let h1 = Header::unpack(&mut c1).unwrap();
        assert_eq!(h1.command, Command::Close);
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
}
