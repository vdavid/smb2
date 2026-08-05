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

/// Build a successful SET_INFO response.
pub(crate) fn build_set_info_response() -> Vec<u8> {
    use crate::msg::set_info::SetInfoResponse;
    let mut h = Header::new_request(Command::SetInfo);
    h.flags.set_response();
    h.credits = 32;
    pack_message(&h, &SetInfoResponse)
}

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
    // Stage a credit window the way a real connection would have one by this
    // point: NEGOTIATE, SESSION_SETUP, and TREE_CONNECT have all come back
    // with grants before any of these tests' operations run. Without it the
    // pool holds the single pre-NEGOTIATE credit and any compound is
    // unsendable.
    conn.set_credits(512);
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

/// Build a CREATE response carrying a chain of create contexts.
pub(crate) fn build_create_response_with_contexts(
    file_id: FileId,
    end_of_file: u64,
    contexts: &[crate::msg::create_context::CreateContext],
) -> Vec<u8> {
    let mut h = Header::new_request(Command::Create);
    h.flags.set_response();
    h.credits = 32;

    let body = CreateResponse {
        oplock_level: OplockLevel::Batch,
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
        create_contexts: crate::msg::create_context::pack_contexts(contexts),
    };

    pack_message(&h, &body)
}

/// Build a CREATE response with a non-success status (for error tests).
pub(crate) fn build_create_error_response(status: crate::types::status::NtStatus) -> Vec<u8> {
    use crate::msg::header::ErrorResponse;
    let mut h = Header::new_request(Command::Create);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;

    let body = ErrorResponse {
        error_context_count: 0,
        error_data: vec![],
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

/// Build a READ response carrying the given data bytes.
pub(crate) fn build_read_response(data: Vec<u8>) -> Vec<u8> {
    use crate::msg::read::ReadResponse;
    let mut h = Header::new_request(Command::Read);
    h.flags.set_response();
    h.credits = 32;

    let body = ReadResponse {
        data_offset: 0x50,
        data_remaining: 0,
        flags: 0,
        data,
    };

    pack_message(&h, &body)
}

/// Build a READ response with a non-success status (for error tests).
pub(crate) fn build_read_error_response(status: crate::types::status::NtStatus) -> Vec<u8> {
    use crate::msg::header::ErrorResponse;
    let mut h = Header::new_request(Command::Read);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;

    let body = ErrorResponse {
        error_context_count: 0,
        error_data: vec![],
    };

    pack_message(&h, &body)
}

/// Build a successful IOCTL response carrying the given output buffer.
pub(crate) fn build_ioctl_response(ctl_code: u32, output_data: Vec<u8>) -> Vec<u8> {
    build_ioctl_response_status(
        ctl_code,
        crate::types::status::NtStatus::SUCCESS,
        output_data,
    )
}

/// Build an IOCTL response with an explicit status and output buffer. Used for
/// the server-side-copy limits negotiation, where the server returns
/// `STATUS_INVALID_PARAMETER` *with* a 12-byte copychunk response payload.
pub(crate) fn build_ioctl_response_status(
    ctl_code: u32,
    status: crate::types::status::NtStatus,
    output_data: Vec<u8>,
) -> Vec<u8> {
    use crate::msg::ioctl::IoctlResponse;
    let mut h = Header::new_request(Command::Ioctl);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;

    let body = IoctlResponse {
        ctl_code,
        file_id: FileId::SENTINEL,
        flags: crate::msg::ioctl::SMB2_0_IOCTL_IS_FSCTL,
        output_data,
    };
    pack_message(&h, &body)
}

/// Build an IOCTL error response (an `ErrorResponse` body, no output buffer) --
/// for example a server that lacks server-side copy replying `STATUS_NOT_SUPPORTED`.
pub(crate) fn build_ioctl_error_response(status: crate::types::status::NtStatus) -> Vec<u8> {
    use crate::msg::header::ErrorResponse;
    let mut h = Header::new_request(Command::Ioctl);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;

    let body = ErrorResponse {
        error_context_count: 0,
        error_data: vec![],
    };
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

/// Concatenate sub-responses into one compound transport frame, chaining them
/// with `NextCommand` offsets the way a server does.
pub(crate) fn build_compound_response_frame(responses: &[Vec<u8>]) -> Vec<u8> {
    let mut frame = Vec::new();
    for (i, resp) in responses.iter().enumerate() {
        let mut r = resp.clone();
        if i != responses.len() - 1 {
            // Every sub-response but the last is 8-byte aligned and points at
            // the next one.
            let remainder = r.len() % 8;
            if remainder != 0 {
                r.resize(r.len() + (8 - remainder), 0);
            }
            let next_cmd = r.len() as u32;
            r[20..24].copy_from_slice(&next_cmd.to_le_bytes());
        }
        frame.extend_from_slice(&r);
    }
    frame
}

/// Build a successful QUERY_INFO response wrapping `output_buffer`.
pub(crate) fn build_query_info_response(output_buffer: Vec<u8>) -> Vec<u8> {
    build_query_info_response_with_status(crate::types::status::NtStatus::SUCCESS, output_buffer)
}

/// Build a QUERY_INFO response the server refused, with no payload.
pub(crate) fn build_query_info_error_response(status: crate::types::status::NtStatus) -> Vec<u8> {
    build_query_info_response_with_status(status, Vec::new())
}

/// Build a QUERY_INFO response with an explicit status.
pub(crate) fn build_query_info_response_with_status(
    status: crate::types::status::NtStatus,
    output_buffer: Vec<u8>,
) -> Vec<u8> {
    use crate::msg::query_info::QueryInfoResponse;
    let mut h = Header::new_request(Command::QueryInfo);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;
    pack_message(&h, &QueryInfoResponse { output_buffer })
}
