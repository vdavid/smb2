//! Shared test helper functions for `client` module tests.
//!
//! These build mock SMB2 responses used across pipeline, shares, and tree tests.

use std::sync::Arc;

use crate::client::connection::{pack_message, Connection, NegotiatedParams};
use crate::msg::close::CloseResponse;
use crate::msg::create::{CreateAction, CreateResponse};
use crate::msg::header::Header;
use crate::msg::tree_connect::{ShareType, TreeConnectResponse};
use crate::pack::{FileTime, Guid};
use crate::transport::MockTransport;
use crate::types::flags::{Capabilities, ShareCapabilities, ShareFlags};
use crate::types::{Command, Dialect, FileId, OplockLevel, SessionId, TreeId};

/// Create a mock-backed connection with standard negotiated params.
///
/// Enables the mock's auto-msg_id-rewrite so canned `build_*_response`
/// helpers (which hardcode `MessageId(0)` and don't know the caller's
/// allocated msg_ids) still route through the Phase 3 receiver task: on
/// each `receive()` the mock patches sub-frame msg_ids to match the next
/// pending sent msg_id in FIFO order. Replaces the pre-Phase-3
/// `set_orphan_filter_enabled(false)` path.
pub(crate) fn setup_connection(mock: &Arc<MockTransport>) -> Connection {
    mock.enable_auto_rewrite_msg_id();
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
        compression_supported: false,
    });
    conn.set_session_id(SessionId(0x1234));
    conn
}

/// Build a CREATE response with the given file ID and end-of-file size.
pub(crate) fn build_create_response(file_id: FileId, end_of_file: u64) -> Vec<u8> {
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

/// Build a CLOSE response with zeroed fields.
pub(crate) fn build_close_response() -> Vec<u8> {
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

/// Build a WRITE response with the given byte count.
pub(crate) fn build_write_response(count: u32) -> Vec<u8> {
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

/// Build a WRITE response with a non-success status (for error tests).
pub(crate) fn build_write_error_response(status: crate::types::status::NtStatus) -> Vec<u8> {
    use crate::msg::header::ErrorResponse;
    let mut h = Header::new_request(Command::Write);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;

    let body = ErrorResponse {
        error_context_count: 0,
        error_data: vec![],
    };

    pack_message(&h, &body)
}

/// Build a CLOSE response with a non-success status (for error tests).
pub(crate) fn build_close_error_response(status: crate::types::status::NtStatus) -> Vec<u8> {
    use crate::msg::header::ErrorResponse;
    let mut h = Header::new_request(Command::Close);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;

    let body = ErrorResponse {
        error_context_count: 0,
        error_data: vec![],
    };

    pack_message(&h, &body)
}

/// Build a FLUSH response.
pub(crate) fn build_flush_response() -> Vec<u8> {
    let mut h = Header::new_request(Command::Flush);
    h.flags.set_response();
    h.credits = 32;

    let body = crate::msg::flush::FlushResponse;
    pack_message(&h, &body)
}

/// Build a TREE_CONNECT response with the given tree ID and share type.
pub(crate) fn build_tree_connect_response(tree_id: TreeId, share_type: ShareType) -> Vec<u8> {
    let mut h = Header::new_request(Command::TreeConnect);
    h.flags.set_response();
    h.credits = 32;
    h.tree_id = Some(tree_id);

    let body = TreeConnectResponse {
        share_type,
        share_flags: ShareFlags::default(),
        capabilities: ShareCapabilities::default(),
        maximal_access: 0x001F_01FF,
    };

    pack_message(&h, &body)
}
