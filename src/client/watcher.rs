//! Directory change notification via SMB2 CHANGE_NOTIFY.
//!
//! The [`Watcher`] type registers for change notifications on a directory
//! and returns [`FileNotifyEvent`] entries describing changes as they happen.
//! The server holds the request until a change occurs, making this a long-poll
//! operation.

use log::debug;

use crate::client::connection::Connection;
use crate::client::tree::Tree;
use crate::error::Result;
use crate::msg::change_notify::{
    ChangeNotifyRequest, ChangeNotifyResponse, FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, SMB2_WATCH_TREE,
};
use crate::pack::{ReadCursor, Unpack};
use crate::types::status::NtStatus;
use crate::types::{Command, FileId};
use crate::Error;

/// Default completion filter: watch for most common changes.
const DEFAULT_COMPLETION_FILTER: u32 = FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_CREATION;

/// Default output buffer length for CHANGE_NOTIFY responses (64 KB).
const OUTPUT_BUFFER_LENGTH: u32 = 65536;

/// The type of change that occurred on a file or directory.
///
/// These correspond to the `Action` field in `FILE_NOTIFY_INFORMATION`
/// (MS-FSCC section 2.4.42).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileNotifyAction {
    /// A file was added to the directory.
    Added,
    /// A file was removed from the directory.
    Removed,
    /// A file was modified.
    Modified,
    /// A file was renamed (this is the old name).
    RenamedOldName,
    /// A file was renamed (this is the new name).
    RenamedNewName,
}

impl FileNotifyAction {
    /// Parse an action value from the wire format.
    fn from_u32(value: u32) -> Result<Self> {
        match value {
            0x0000_0001 => Ok(FileNotifyAction::Added),
            0x0000_0002 => Ok(FileNotifyAction::Removed),
            0x0000_0003 => Ok(FileNotifyAction::Modified),
            0x0000_0004 => Ok(FileNotifyAction::RenamedOldName),
            0x0000_0005 => Ok(FileNotifyAction::RenamedNewName),
            other => Err(Error::invalid_data(format!(
                "unknown FILE_NOTIFY_INFORMATION action: {other:#010X}"
            ))),
        }
    }
}

impl std::fmt::Display for FileNotifyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileNotifyAction::Added => write!(f, "added"),
            FileNotifyAction::Removed => write!(f, "removed"),
            FileNotifyAction::Modified => write!(f, "modified"),
            FileNotifyAction::RenamedOldName => write!(f, "renamed (old name)"),
            FileNotifyAction::RenamedNewName => write!(f, "renamed (new name)"),
        }
    }
}

/// A single file change notification.
///
/// Represents one `FILE_NOTIFY_INFORMATION` entry from the server.
#[derive(Debug, Clone)]
pub struct FileNotifyEvent {
    /// What kind of change occurred.
    pub action: FileNotifyAction,
    /// The relative file name within the watched directory.
    pub filename: String,
}

/// Watches a directory for changes via SMB2 CHANGE_NOTIFY.
///
/// The server holds the request until something changes, then responds
/// with one or more [`FileNotifyEvent`] entries. Each call to
/// [`next_events()`](Watcher::next_events) blocks until the server
/// reports a change.
///
/// ```no_run
/// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// let mut watcher = client.watch(&share, "_test/", true).await?;
/// loop {
///     let events = watcher.next_events().await?;
///     for event in &events {
///         println!("{}: {}", event.filename, event.action);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct Watcher<'a> {
    tree: &'a Tree,
    conn: &'a mut Connection,
    file_id: FileId,
    recursive: bool,
}

impl<'a> Watcher<'a> {
    /// Create a new watcher (called by `Tree::watch`).
    pub(crate) fn new(
        tree: &'a Tree,
        conn: &'a mut Connection,
        file_id: FileId,
        recursive: bool,
    ) -> Self {
        Watcher {
            tree,
            conn,
            file_id,
            recursive,
        }
    }

    /// Wait for the next batch of change events.
    ///
    /// Sends a CHANGE_NOTIFY request and waits for the server to respond.
    /// The server holds the request until changes occur, so this call
    /// may block for a long time.
    ///
    /// Returns `Ok(events)` with one or more events when changes are detected.
    ///
    /// # Errors
    ///
    /// Returns `Error::Protocol` with `STATUS_NOTIFY_ENUM_DIR` if too many
    /// changes occurred and the server could not fit them in the response
    /// buffer. In this case, the caller should re-scan the directory.
    pub async fn next_events(&mut self) -> Result<Vec<FileNotifyEvent>> {
        let flags = if self.recursive { SMB2_WATCH_TREE } else { 0 };

        let req = ChangeNotifyRequest {
            flags,
            output_buffer_length: OUTPUT_BUFFER_LENGTH,
            file_id: self.file_id,
            completion_filter: DEFAULT_COMPLETION_FILTER,
        };

        // `execute` handles STATUS_PENDING transparently: the receiver task
        // keeps the waiter registered through interim responses and only
        // resolves the oneshot when the real (non-pending) response arrives.
        let frame = self
            .conn
            .execute(Command::ChangeNotify, &req, Some(self.tree.tree_id))
            .await?;

        if frame.header.status == NtStatus::NOTIFY_ENUM_DIR {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::ChangeNotify,
            });
        }

        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::ChangeNotify,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = ChangeNotifyResponse::unpack(&mut cursor)?;

        let events = parse_notify_information(&resp.output_data)?;
        debug!("watcher: received {} change event(s)", events.len());
        Ok(events)
    }

    /// Close the directory handle.
    ///
    /// This stops watching for changes. If not called explicitly,
    /// the handle will be leaked (there is no async drop in Rust).
    pub async fn close(self) -> Result<()> {
        self.tree.close_handle(self.conn, self.file_id).await
    }
}

/// Parse a chain of FILE_NOTIFY_INFORMATION entries from the response buffer.
///
/// Each entry has:
/// - `NextEntryOffset` (u32): offset to next entry, 0 for last
/// - `Action` (u32): the change type
/// - `FileNameLength` (u32): length of filename in bytes (UTF-16LE)
/// - `FileName` (variable): UTF-16LE, NOT null-terminated
///
/// Entries are 4-byte aligned.
fn parse_notify_information(data: &[u8]) -> Result<Vec<FileNotifyEvent>> {
    let mut events = Vec::new();
    let mut offset = 0usize;

    if data.is_empty() {
        return Ok(events);
    }

    loop {
        // Need at least 12 bytes for the fixed fields.
        if offset + 12 > data.len() {
            return Err(Error::invalid_data(
                "FILE_NOTIFY_INFORMATION truncated: not enough bytes for fixed fields",
            ));
        }

        let next_entry_offset =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        let action_raw = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
        let filename_length =
            u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()) as usize;

        // Filename starts right after the 12-byte fixed header.
        let filename_start = offset + 12;
        let filename_end = filename_start + filename_length;

        if filename_end > data.len() {
            return Err(Error::invalid_data(format!(
                "FILE_NOTIFY_INFORMATION filename extends beyond buffer: \
                 need {} bytes at offset {}, buffer is {} bytes",
                filename_length,
                filename_start,
                data.len()
            )));
        }

        let filename_bytes = &data[filename_start..filename_end];

        // Decode UTF-16LE filename.
        let filename = decode_utf16le(filename_bytes)?;
        let action = FileNotifyAction::from_u32(action_raw)?;

        events.push(FileNotifyEvent { action, filename });

        if next_entry_offset == 0 {
            break;
        }

        offset += next_entry_offset;
    }

    Ok(events)
}

/// Decode a UTF-16LE byte slice into a Rust String.
fn decode_utf16le(bytes: &[u8]) -> Result<String> {
    if bytes.len() % 2 != 0 {
        return Err(Error::invalid_data("UTF-16LE filename has odd byte count"));
    }

    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16(&u16s)
        .map_err(|e| Error::invalid_data(format!("invalid UTF-16LE filename: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_notify_entry() {
        // Build a single FILE_NOTIFY_INFORMATION entry.
        let filename = "test.txt";
        let utf16: Vec<u16> = filename.encode_utf16().collect();
        let filename_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let filename_len = filename_bytes.len() as u32;

        let mut data = Vec::new();
        // NextEntryOffset = 0 (last entry)
        data.extend_from_slice(&0u32.to_le_bytes());
        // Action = FILE_ACTION_ADDED (0x00000001)
        data.extend_from_slice(&1u32.to_le_bytes());
        // FileNameLength
        data.extend_from_slice(&filename_len.to_le_bytes());
        // FileName (UTF-16LE)
        data.extend_from_slice(&filename_bytes);

        let events = parse_notify_information(&data).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, FileNotifyAction::Added);
        assert_eq!(events[0].filename, "test.txt");
    }

    #[test]
    fn parse_multiple_notify_entries() {
        // Build two FILE_NOTIFY_INFORMATION entries.
        let build_entry = |name: &str, action: u32, is_last: bool| -> Vec<u8> {
            let utf16: Vec<u16> = name.encode_utf16().collect();
            let filename_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
            let filename_len = filename_bytes.len() as u32;

            let mut entry = Vec::new();
            // Fixed header is 12 bytes + filename. Align to 4 bytes.
            let entry_size = 12 + filename_bytes.len();
            let aligned_size = (entry_size + 3) & !3;

            let next_offset = if is_last { 0u32 } else { aligned_size as u32 };
            entry.extend_from_slice(&next_offset.to_le_bytes());
            entry.extend_from_slice(&action.to_le_bytes());
            entry.extend_from_slice(&filename_len.to_le_bytes());
            entry.extend_from_slice(&filename_bytes);

            // Pad to 4-byte alignment.
            while entry.len() < aligned_size {
                entry.push(0);
            }

            entry
        };

        let mut data = Vec::new();
        data.extend_from_slice(&build_entry("added.txt", 1, false));
        data.extend_from_slice(&build_entry("removed.txt", 2, true));

        let events = parse_notify_information(&data).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, FileNotifyAction::Added);
        assert_eq!(events[0].filename, "added.txt");
        assert_eq!(events[1].action, FileNotifyAction::Removed);
        assert_eq!(events[1].filename, "removed.txt");
    }

    #[test]
    fn parse_empty_buffer_returns_no_events() {
        let events = parse_notify_information(&[]).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_truncated_buffer_returns_error() {
        // Only 8 bytes, need at least 12 for fixed fields.
        let data = vec![0u8; 8];
        let result = parse_notify_information(&data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_utf16le_basic() {
        let input = "hello";
        let utf16: Vec<u16> = input.encode_utf16().collect();
        let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let result = decode_utf16le(&bytes).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn decode_utf16le_non_ascii() {
        let input = "photos/\u{00E9}t\u{00E9}";
        let utf16: Vec<u16> = input.encode_utf16().collect();
        let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let result = decode_utf16le(&bytes).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn decode_utf16le_odd_bytes_is_error() {
        let result = decode_utf16le(&[0x41, 0x00, 0x42]);
        assert!(result.is_err());
    }

    #[test]
    fn file_notify_action_display() {
        assert_eq!(format!("{}", FileNotifyAction::Added), "added");
        assert_eq!(format!("{}", FileNotifyAction::Removed), "removed");
        assert_eq!(format!("{}", FileNotifyAction::Modified), "modified");
        assert_eq!(
            format!("{}", FileNotifyAction::RenamedOldName),
            "renamed (old name)"
        );
        assert_eq!(
            format!("{}", FileNotifyAction::RenamedNewName),
            "renamed (new name)"
        );
    }

    #[test]
    fn file_notify_action_from_u32_unknown_is_error() {
        let result = FileNotifyAction::from_u32(0x9999);
        assert!(result.is_err());
    }
}
