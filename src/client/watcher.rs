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

/// Loss-window tests using a strict-server simulator.
///
/// These probe the architectural property the watcher contract should
/// guarantee: every event the server observes is eventually delivered
/// to the consumer, even when the server drops events that arrive
/// while no `CHANGE_NOTIFY` request is outstanding (the naspi / older
/// Samba behavior that triggered cmdr's field reproduction).
///
/// **TDD-red on `main`**: `LossySim` drops events when no request is
/// outstanding; current `next_events()` issues one CHANGE_NOTIFY per
/// call, so there's always a gap between response delivery and the
/// next request. Events pushed during that gap are dropped, and the
/// test fails. The pipelined-watcher fix (always keep one CHANGE_NOTIFY
/// pre-issued on the wire) closes the gap, the simulator never drops,
/// and the test passes.
#[cfg(test)]
mod loss_window_tests {
    use super::*;
    use crate::client::connection::{pack_message, Connection, NegotiatedParams};
    use crate::client::tree::Tree;
    use crate::msg::change_notify::ChangeNotifyResponse;
    use crate::msg::header::Header;
    use crate::pack::Guid;
    use crate::transport::{TransportReceive, TransportSend};
    use crate::types::flags::Capabilities;
    use crate::types::{Command, Dialect, MessageId, SessionId, TreeId};
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::Notify;

    /// Simulates a CHANGE_NOTIFY server that DROPS events that arrive
    /// while no request is outstanding. Models naspi / older Samba
    /// firmware (the server side of cmdr's 9-files → 4-events field
    /// reproduction). Forgiving servers like Docker Samba buffer
    /// generously and won't trigger this; the simulator's job is to
    /// surface the architectural bug regardless of how forgiving any
    /// real server happens to be.
    struct LossySim {
        /// Outstanding CHANGE_NOTIFY request msg_ids (FIFO).
        outstanding: Mutex<VecDeque<u64>>,
        /// Events the server has observed but not yet delivered.
        pending_events: Mutex<Vec<(String, u32)>>,
        /// Response queue read by `receive()`.
        responses: Mutex<VecDeque<Vec<u8>>>,
        /// Count of events the server saw with no request outstanding.
        dropped: Mutex<usize>,
        send_notify: Notify,
        recv_notify: Notify,
        closed: AtomicBool,
    }

    impl LossySim {
        fn new() -> Self {
            Self {
                outstanding: Mutex::new(VecDeque::new()),
                pending_events: Mutex::new(Vec::new()),
                responses: Mutex::new(VecDeque::new()),
                dropped: Mutex::new(0),
                send_notify: Notify::new(),
                recv_notify: Notify::new(),
                closed: AtomicBool::new(false),
            }
        }

        /// Block until at least one CHANGE_NOTIFY request is outstanding.
        async fn wait_outstanding(&self) {
            loop {
                if !self.outstanding.lock().unwrap().is_empty() {
                    return;
                }
                if self.closed.load(Ordering::Acquire) {
                    return;
                }
                self.send_notify.notified().await;
            }
        }

        /// Push an event. If a CHANGE_NOTIFY request is outstanding, buffer
        /// the event for the next `deliver_pending()`. Else, drop silently
        /// and bump the dropped counter.
        fn push_event(&self, name: &str) {
            let outstanding = !self.outstanding.lock().unwrap().is_empty();
            if outstanding {
                self.pending_events
                    .lock()
                    .unwrap()
                    .push((name.to_string(), 1 /* FILE_ACTION_ADDED */));
            } else {
                *self.dropped.lock().unwrap() += 1;
            }
        }

        /// Wrap all buffered events into a single CHANGE_NOTIFY response,
        /// consuming one outstanding msg_id.
        fn deliver_pending(&self) {
            let msg_id = self.outstanding.lock().unwrap().pop_front();
            let events = std::mem::take(&mut *self.pending_events.lock().unwrap());
            if let Some(id) = msg_id {
                let resp = build_response(id, &events);
                self.responses.lock().unwrap().push_back(resp);
                self.recv_notify.notify_one();
            }
        }

        fn dropped_count(&self) -> usize {
            *self.dropped.lock().unwrap()
        }

        fn close(&self) {
            self.closed.store(true, Ordering::Release);
            self.recv_notify.notify_waiters();
            self.send_notify.notify_waiters();
        }
    }

    #[async_trait]
    impl TransportSend for LossySim {
        async fn send(&self, data: &[u8]) -> crate::error::Result<()> {
            if let Some(msg_id) = extract_change_notify_msg_id(data) {
                self.outstanding.lock().unwrap().push_back(msg_id);
                self.send_notify.notify_waiters();
            }
            Ok(())
        }
    }

    #[async_trait]
    impl TransportReceive for LossySim {
        async fn receive(&self) -> crate::error::Result<Vec<u8>> {
            loop {
                if let Some(data) = self.responses.lock().unwrap().pop_front() {
                    return Ok(data);
                }
                if self.closed.load(Ordering::Acquire) {
                    return Err(crate::Error::Disconnected);
                }
                self.recv_notify.notified().await;
            }
        }
    }

    /// Pull `MessageId` out of a request frame, but only for CHANGE_NOTIFY.
    /// Non-CHANGE_NOTIFY sends are ignored by the simulator (the test
    /// pre-configures the connection so no other requests should hit this
    /// transport — but if any do, we won't track them).
    fn extract_change_notify_msg_id(data: &[u8]) -> Option<u64> {
        const HEADER_MIN: usize = 64;
        if data.len() < HEADER_MIN || &data[0..4] != b"\xFESMB" {
            return None;
        }
        let cmd = u16::from_le_bytes([data[12], data[13]]);
        if cmd != Command::ChangeNotify as u16 {
            return None;
        }
        Some(u64::from_le_bytes(data[24..32].try_into().unwrap()))
    }

    /// Pack a CHANGE_NOTIFY response carrying the given (name, action) pairs.
    fn build_response(msg_id: u64, events: &[(String, u32)]) -> Vec<u8> {
        let mut output_data = Vec::new();
        for (i, (name, action)) in events.iter().enumerate() {
            let is_last = i == events.len() - 1;
            let utf16: Vec<u16> = name.encode_utf16().collect();
            let filename_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
            let filename_len = filename_bytes.len() as u32;
            let entry_size = 12 + filename_bytes.len();
            let aligned_size = (entry_size + 3) & !3;
            let next_offset = if is_last { 0u32 } else { aligned_size as u32 };
            let start = output_data.len();
            output_data.extend_from_slice(&next_offset.to_le_bytes());
            output_data.extend_from_slice(&action.to_le_bytes());
            output_data.extend_from_slice(&filename_len.to_le_bytes());
            output_data.extend_from_slice(&filename_bytes);
            while output_data.len() - start < aligned_size {
                output_data.push(0);
            }
        }
        let mut h = Header::new_request(Command::ChangeNotify);
        h.flags.set_response();
        h.message_id = MessageId(msg_id);
        h.credits = 32;
        let body = ChangeNotifyResponse { output_data };
        pack_message(&h, &body)
    }

    fn setup_connection(sim: &Arc<LossySim>) -> Connection {
        let mut conn =
            Connection::from_transport(Box::new(sim.clone()), Box::new(sim.clone()), "test-server");
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
            compression_supported: false,
        });
        conn.set_session_id(SessionId(0x1234));
        conn
    }

    fn test_tree() -> Tree {
        Tree {
            tree_id: TreeId(1),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        }
    }

    /// Cycle, repeated N times:
    ///   1. wait for outstanding (watcher armed)
    ///   2. push event A → buffered
    ///   3. deliver_pending → response queued, msg_id consumed
    ///   4. push GAP event → on `main`, no outstanding → DROPPED;
    ///      on the pipelined-watcher fix, the next request is already
    ///      issued → buffered.
    ///
    /// Final flush: one more wait_outstanding + push + deliver to make
    /// sure any buffered gap events on the fix path get out.
    ///
    /// On `main`: `dropped_count() > 0`, `delivered.len() < expected`.
    /// On the fix: `dropped_count() == 0`, all events delivered.
    #[tokio::test]
    async fn watcher_does_not_lose_events_between_consecutive_requests() {
        let _ = env_logger::try_init();

        const N_CYCLES: usize = 5;

        let sim = Arc::new(LossySim::new());
        let mut conn = setup_connection(&sim);
        let tree = test_tree();

        let scenario_sim = sim.clone();
        let scenario = tokio::spawn(async move {
            let sim = scenario_sim;
            for round in 0..N_CYCLES {
                sim.wait_outstanding().await;
                sim.push_event(&format!("a_{round:02}"));
                sim.deliver_pending();
                // Inline push (no .await) — outstanding queue was just
                // emptied by deliver_pending. On `main`, no request has
                // been re-issued yet, so this lands in the "drop" branch.
                // On the fix, a pre-issued request is still outstanding,
                // so it lands in the "buffer" branch.
                sim.push_event(&format!("gap_{round:02}"));
            }
            // Flush: drive one more cycle to push any buffered gap events
            // out the door for the fix path.
            sim.wait_outstanding().await;
            sim.push_event("flush_marker");
            sim.deliver_pending();
            // Brief grace period for the watcher to drain the response,
            // then close so its next next_events() returns Disconnected
            // and the consumer loop exits.
            tokio::time::sleep(Duration::from_millis(50)).await;
            sim.close();
        });

        let mut watcher = Watcher::new(
            &tree,
            &mut conn,
            crate::types::FileId {
                persistent: 0x1111,
                volatile: 0x2222,
            },
            true,
        );
        let mut delivered: Vec<String> = Vec::new();
        while let Ok(events) = watcher.next_events().await {
            for e in &events {
                delivered.push(e.filename.clone());
            }
        }
        scenario.await.unwrap();

        let dropped = sim.dropped_count();
        // `a_*` events always land in the outstanding window. `flush_marker`
        // ditto. `gap_*` events expose the bug: dropped today, delivered
        // after the fix.
        let expected_min = N_CYCLES /* a_* */ + 1 /* flush_marker */;
        let expected_max = expected_min + N_CYCLES /* gap_* */;

        assert!(
            delivered.len() >= expected_min,
            "watcher dropped 'a_*' or 'flush_marker' events: got {:?}",
            delivered
        );
        assert_eq!(
            dropped, 0,
            "{} server-side event(s) arrived with no outstanding CHANGE_NOTIFY \
             request and were dropped. The pipelined-watcher fix should keep \
             one CHANGE_NOTIFY request continuously outstanding so no event \
             ever lands in the drop branch. Delivered to consumer: {:?}",
            dropped, delivered
        );
        assert_eq!(
            delivered.len(),
            expected_max,
            "expected every 'a_*', 'gap_*', and 'flush_marker' event delivered; \
             got {:?}",
            delivered
        );
    }
}
