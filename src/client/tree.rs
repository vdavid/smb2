//! Tree (share) connection and basic file operations.
//!
//! The [`Tree`] type represents a connection to a specific share on the server.
//! It provides methods for directory listing, file reading, and tree disconnect.

use log::{debug, info, trace};

use crate::client::connection::Connection;
use crate::error::Result;
use crate::msg::close::CloseRequest;
use crate::msg::create::{
    CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
};
use crate::msg::query_directory::{
    FileInformationClass, QueryDirectoryFlags, QueryDirectoryRequest, QueryDirectoryResponse,
};
use crate::msg::read::{ReadRequest, ReadResponse, SMB2_CHANNEL_NONE};
use crate::msg::tree_connect::{TreeConnectRequest, TreeConnectRequestFlags, TreeConnectResponse};
use crate::msg::tree_disconnect::TreeDisconnectRequest;
use crate::pack::{FileTime, ReadCursor, Unpack};
use crate::types::flags::FileAccessMask;
use crate::types::status::NtStatus;
use crate::types::{Command, FileId, OplockLevel, TreeId};
use crate::Error;

/// File attribute constant: the entry is a directory.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// Create option: the target must be a directory.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

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

/// A connection to a specific share (tree connect).
pub struct Tree {
    /// The tree ID assigned by the server.
    pub tree_id: TreeId,
    /// The share name.
    pub share_name: String,
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
    pub async fn connect(
        conn: &mut Connection,
        share_name: &str,
    ) -> Result<Tree> {
        let server = conn.server_name().to_string();
        let unc_path = format!(r"\\{}\{}", server, share_name);

        let req = TreeConnectRequest {
            flags: TreeConnectRequestFlags::default(),
            path: unc_path,
        };

        let (_, _req_raw) = conn
            .send_request(Command::TreeConnect, &req, None)
            .await?;

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

        info!("tree: connected share={}, tree_id={}", share_name, tree_id);
        debug!("tree: is_dfs={}, encrypt_data={}",
            resp.capabilities.contains(crate::types::flags::ShareCapabilities::DFS),
            resp.share_flags.contains(crate::types::flags::ShareFlags::ENCRYPT_DATA),
        );

        Ok(Tree {
            tree_id,
            share_name: share_name.to_string(),
            is_dfs: resp.capabilities.contains(crate::types::flags::ShareCapabilities::DFS),
            encrypt_data: resp.share_flags.contains(crate::types::flags::ShareFlags::ENCRYPT_DATA),
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
        let normalized = normalize_path(path);
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

    /// Read a file's contents.
    ///
    /// Opens the file with CREATE, reads in chunks up to max_read_size,
    /// then closes the handle.
    pub async fn read_file(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<Vec<u8>> {
        let normalized = normalize_path(path);

        // Open the file.
        let (file_id, file_size) = self.open_file(conn, &normalized).await?;
        let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
        let chunks = file_size.div_ceil(max_read as u64);
        debug!("tree: read_file path={}, size={}, chunks={}", normalized, file_size, chunks);

        // Read the file in chunks.
        let result = self.read_loop(conn, file_id, file_size).await;

        // Close the handle.
        let close_result = self.close_handle(conn, file_id).await;

        let data = result?;
        close_result?;
        debug!("tree: read_file done, read {} bytes", data.len());
        Ok(data)
    }

    /// Disconnect from the share.
    pub async fn disconnect(
        &self,
        conn: &mut Connection,
    ) -> Result<()> {
        debug!("tree: disconnecting share={}, tree_id={}", self.share_name, self.tree_id);
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

        info!("tree: disconnected share={}, tree_id={}", self.share_name, self.tree_id);
        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// Open a directory handle.
    async fn open_directory(
        &self,
        conn: &mut Connection,
        path: &str,
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
    async fn open_file(
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

    /// Loop QUERY_DIRECTORY until STATUS_NO_MORE_FILES.
    async fn query_directory_loop(
        &self,
        conn: &mut Connection,
        file_id: FileId,
    ) -> Result<Vec<DirectoryEntry>> {
        let max_output = conn
            .params()
            .map(|p| p.max_transact_size)
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
                file_name: if first { "*".to_string() } else { String::new() },
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
                trace!("tree: dir_entry name={}, size={}, is_dir={}", e.name, e.size, e.is_directory);
            }
            all_entries.extend(entries);
        }

        Ok(all_entries)
    }

    /// Read file data in chunks.
    async fn read_loop(
        &self,
        conn: &mut Connection,
        file_id: FileId,
        file_size: u64,
    ) -> Result<Vec<u8>> {
        let max_read = conn
            .params()
            .map(|p| p.max_read_size)
            .unwrap_or(65536);

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

    /// Close a file handle.
    async fn close_handle(
        &self,
        conn: &mut Connection,
        file_id: FileId,
    ) -> Result<()> {
        let req = CloseRequest {
            flags: 0,
            file_id,
        };

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
    use crate::client::connection::{pack_message, Connection, NegotiatedParams};
    use crate::msg::close::CloseResponse;
    use crate::msg::create::{CreateAction, CreateResponse};
    use crate::msg::header::Header;
    use crate::msg::query_directory::QueryDirectoryResponse;
    use crate::msg::tree_connect::{ShareType, TreeConnectResponse};
    use crate::pack::Guid;
    use crate::transport::MockTransport;
    use crate::types::flags::{Capabilities, ShareCapabilities, ShareFlags};
    use crate::types::status::NtStatus;
    use crate::types::{Command, Dialect, SessionId, TreeId};
    use std::sync::Arc;

    fn setup_connection(mock: &Arc<MockTransport>) -> Connection {
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_test_params(NegotiatedParams {
            dialect: Dialect::Smb2_0_2,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: Guid::ZERO,
            signing_required: false,
            capabilities: Capabilities::default(),
            gmac_negotiated: false,
            cipher: None,
        });
        conn.set_session_id(SessionId(0x1234));
        conn
    }

    fn build_tree_connect_response(tree_id: TreeId) -> Vec<u8> {
        let mut h = Header::new_request(Command::TreeConnect);
        h.flags.set_response();
        h.credits = 32;
        h.tree_id = Some(tree_id);

        let body = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::default(),
            capabilities: ShareCapabilities::default(),
            maximal_access: 0x001F_01FF,
        };

        pack_message(&h, &body)
    }

    fn build_create_response(file_id: FileId, end_of_file: u64) -> Vec<u8> {
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
            end_of_file,
            file_attributes: 0,
            file_id,
            create_contexts: vec![],
        };

        pack_message(&h, &body)
    }

    fn build_close_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::Close);
        h.flags.set_response();
        h.credits = 32;

        let body = CloseResponse {
            flags: 0,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: FileTime::ZERO,
            change_time: FileTime::ZERO,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
        };

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
        mock.queue_response(build_tree_connect_response(tree_id));

        let mut conn = setup_connection(&mock);
        let tree = Tree::connect(&mut conn, "naspi").await.unwrap();
        assert_eq!(tree.tree_id, tree_id);
        assert_eq!(tree.share_name, "naspi");
    }

    #[tokio::test]
    async fn tree_connect_sends_unc_path() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_tree_connect_response(TreeId(1)));

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
        let entry1_with_next = build_file_both_dir_info("file1.txt", 1024, false, total_entry_len as u32);
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

        // Queue: CREATE response, READ response, CLOSE response.
        mock.queue_response(build_create_response(file_id, file_data.len() as u64));
        mock.queue_response(build_read_response(
            NtStatus::SUCCESS,
            file_data.to_vec(),
        ));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = Tree {
            tree_id,
            share_name: "test".to_string(),
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
            is_dfs: false,
            encrypt_data: false,
        };

        tree.disconnect(&mut conn).await.unwrap();
        assert_eq!(mock.sent_count(), 1);
    }
}
