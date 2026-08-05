//! Fuzzing entry points for `fuzz/` targets.
//!
//! This module is feature-gated behind `fuzzing` and only exists to give
//! `cargo-fuzz` targets stable, public access to otherwise-internal parse
//! functions. Applications must not depend on it -- it's unstable by
//! design, and enabling the feature pulls in nothing of runtime value.
//!
//! Every function here takes untrusted bytes and returns either a parsed
//! value or a clean typed error. No function here is allowed to panic on
//! bad input; that's what the fuzzer tests.
//!
//! Targets (see `fuzz/fuzz_targets/`):
//!
//! - [`fuzz_header_parse`] -- SMB2 header (`msg::header::Header`).
//! - [`fuzz_transform_header_parse`] -- encryption transform header.
//! - [`fuzz_compression_transform_header_parse`] -- compression wrapper.
//! - [`fuzz_compound_split`] -- `client::connection::split_compound`.
//! - [`fuzz_frame_parse`] -- compound split + per-sub-frame header parse,
//!   which is the real receiver-loop path up to the body.
//! - [`fuzz_sub_frame_parse`] -- header + body (dispatched by `Command`).
//! - [`fuzz_negotiate_request_parse`] / [`fuzz_negotiate_response_parse`]
//! - [`fuzz_create_request_parse`] / [`fuzz_create_response_parse`]
//!   -- CreateContext list lives inside these bodies.
//! - [`fuzz_query_info_response_parse`] -- opaque output buffer sharp edge.
//! - [`fuzz_dfs_referral_response_parse`] -- manual offset arithmetic,
//!   obvious fuzzing target.
//! - [`fuzz_name_round_trip`] -- the private-use-area filename mapping. The
//!   only target here that asserts a property rather than "doesn't panic".

use crate::msg::header::Header;
use crate::msg::transform::{CompressionTransformHeader, TransformHeader};
use crate::pack::{ReadCursor, Unpack};
use crate::types::Command;

/// Fuzz the top-level SMB2 header parser.
pub fn fuzz_header_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = Header::unpack(&mut cursor);
}

/// Fuzz the encryption transform header parser.
pub fn fuzz_transform_header_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = TransformHeader::unpack(&mut cursor);
}

/// Fuzz the compression transform header parser.
pub fn fuzz_compression_transform_header_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = CompressionTransformHeader::unpack(&mut cursor);
}

/// Fuzz the compound-frame splitter. Takes a preprocessed (already decrypted
/// and decompressed) buffer and returns the sub-frame byte slices.
pub fn fuzz_compound_split(data: &[u8]) {
    let _ = crate::client::connection::split_compound(data);
}

/// Fuzz the full receiver-loop parse path: compound split, plus parsing the
/// header of every sub-frame. Mirrors what `prepare_sub_frame` does before
/// it dispatches on `Command`.
pub fn fuzz_frame_parse(data: &[u8]) {
    let subs = match crate::client::connection::split_compound(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    for sub in subs {
        let mut cursor = ReadCursor::new(&sub);
        let _ = Header::unpack(&mut cursor);
    }
}

/// Fuzz header + body (dispatched by `Command`). Much wider surface than
/// [`fuzz_frame_parse`] because it actually parses the response body for
/// every command type.
pub fn fuzz_sub_frame_parse(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let mut cursor = ReadCursor::new(data);
    let header = match Header::unpack(&mut cursor) {
        Ok(h) => h,
        Err(_) => return,
    };

    let body = &data[Header::SIZE..];
    let is_response = header.is_response();
    dispatch_body(header.command, is_response, body);
}

fn dispatch_body(command: Command, is_response: bool, body: &[u8]) {
    use crate::msg;

    // Unpack the given type from `body` and discard the result. Parse errors
    // are fine (boring path); panics / UB are what libfuzzer catches.
    macro_rules! try_unpack {
        ($ty:ty) => {{
            let mut cursor = ReadCursor::new(body);
            let _ = <$ty as Unpack>::unpack(&mut cursor);
        }};
    }

    match (command, is_response) {
        (Command::Negotiate, false) => try_unpack!(msg::negotiate::NegotiateRequest),
        (Command::Negotiate, true) => try_unpack!(msg::negotiate::NegotiateResponse),
        (Command::SessionSetup, false) => try_unpack!(msg::session_setup::SessionSetupRequest),
        (Command::SessionSetup, true) => try_unpack!(msg::session_setup::SessionSetupResponse),
        (Command::Logoff, false) => try_unpack!(msg::logoff::LogoffRequest),
        (Command::Logoff, true) => try_unpack!(msg::logoff::LogoffResponse),
        (Command::TreeConnect, false) => try_unpack!(msg::tree_connect::TreeConnectRequest),
        (Command::TreeConnect, true) => try_unpack!(msg::tree_connect::TreeConnectResponse),
        (Command::TreeDisconnect, false) => {
            try_unpack!(msg::tree_disconnect::TreeDisconnectRequest)
        }
        (Command::TreeDisconnect, true) => {
            try_unpack!(msg::tree_disconnect::TreeDisconnectResponse)
        }
        (Command::Create, false) => try_unpack!(msg::create::CreateRequest),
        (Command::Create, true) => try_unpack!(msg::create::CreateResponse),
        (Command::Close, false) => try_unpack!(msg::close::CloseRequest),
        (Command::Close, true) => try_unpack!(msg::close::CloseResponse),
        (Command::Flush, false) => try_unpack!(msg::flush::FlushRequest),
        (Command::Flush, true) => try_unpack!(msg::flush::FlushResponse),
        (Command::Read, false) => try_unpack!(msg::read::ReadRequest),
        (Command::Read, true) => try_unpack!(msg::read::ReadResponse),
        (Command::Write, false) => try_unpack!(msg::write::WriteRequest),
        (Command::Write, true) => try_unpack!(msg::write::WriteResponse),
        (Command::Lock, false) => try_unpack!(msg::lock::LockRequest),
        (Command::Lock, true) => try_unpack!(msg::lock::LockResponse),
        (Command::Ioctl, false) => try_unpack!(msg::ioctl::IoctlRequest),
        (Command::Ioctl, true) => try_unpack!(msg::ioctl::IoctlResponse),
        (Command::Cancel, false) => try_unpack!(msg::cancel::CancelRequest),
        (Command::Echo, false) => try_unpack!(msg::echo::EchoRequest),
        (Command::Echo, true) => try_unpack!(msg::echo::EchoResponse),
        (Command::QueryDirectory, false) => {
            try_unpack!(msg::query_directory::QueryDirectoryRequest)
        }
        (Command::QueryDirectory, true) => {
            try_unpack!(msg::query_directory::QueryDirectoryResponse)
        }
        (Command::ChangeNotify, false) => try_unpack!(msg::change_notify::ChangeNotifyRequest),
        (Command::ChangeNotify, true) => try_unpack!(msg::change_notify::ChangeNotifyResponse),
        (Command::QueryInfo, false) => try_unpack!(msg::query_info::QueryInfoRequest),
        (Command::QueryInfo, true) => try_unpack!(msg::query_info::QueryInfoResponse),
        (Command::SetInfo, false) => try_unpack!(msg::set_info::SetInfoRequest),
        (Command::SetInfo, true) => try_unpack!(msg::set_info::SetInfoResponse),
        _ => {}
    }
}

/// Fuzz `NegotiateRequest::unpack` directly.
pub fn fuzz_negotiate_request_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = crate::msg::negotiate::NegotiateRequest::unpack(&mut cursor);
}

/// Fuzz `NegotiateResponse::unpack` directly. Covers negotiate-context parsing.
pub fn fuzz_negotiate_response_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = crate::msg::negotiate::NegotiateResponse::unpack(&mut cursor);
}

/// Fuzz `CreateRequest::unpack` directly. Covers create-context list parsing.
pub fn fuzz_create_request_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = crate::msg::create::CreateRequest::unpack(&mut cursor);
}

/// Fuzz `CreateResponse::unpack` directly.
pub fn fuzz_create_response_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = crate::msg::create::CreateResponse::unpack(&mut cursor);
}

/// Fuzz `QueryInfoResponse::unpack`, which has the tricky
/// output-buffer-offset-from-header arithmetic.
pub fn fuzz_query_info_response_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = crate::msg::query_info::QueryInfoResponse::unpack(&mut cursor);
}

/// Fuzz the DFS referral response parser. Manual offset arithmetic makes
/// this a classic sharp-edge target.
pub fn fuzz_dfs_referral_response_parse(data: &[u8]) {
    let mut cursor = ReadCursor::new(data);
    let _ = crate::msg::dfs::RespGetDfsReferral::unpack(&mut cursor);
}

/// Fuzz the private-use-area name mapping in [`crate::name`].
///
/// Unlike every other target here, this one asserts a property rather than
/// only "does not panic". The round trip is the contract a consumer relies
/// on -- a listing hands back a name and the next call opens it -- and it is
/// exactly the kind of contract a hand-written test set can leave a hole in.
///
/// Two documented exemptions, both inherent to the scheme and both matching
/// what macOS does: a name that already carries U+F001–U+F029 is not
/// round-trip stable, and `encode_path` drops leading separators. Those
/// inputs still have to encode without panicking and without emitting
/// anything SMB2 rejects, so they are checked, just not for equality.
pub fn fuzz_name_round_trip(data: &[u8]) {
    let Ok(name) = std::str::from_utf8(data) else {
        return;
    };

    let encoded_name = crate::name::encode_name(name);
    assert_wire_safe(&encoded_name, name);
    let encoded_path = crate::name::encode_path(name);
    for component in encoded_path.split('\\') {
        if component != "." && component != ".." {
            assert_wire_safe(component, name);
        }
    }

    // The scheme owns U+F001–U+F029, so a name already holding one stands for
    // something else after a round trip. Documented, and macOS agrees.
    if name
        .chars()
        .any(|c| (0xF001..=0xF029).contains(&(c as u32)))
    {
        return;
    }

    assert_eq!(
        crate::name::decode_name(&encoded_name),
        name,
        "decode_name did not undo encode_name for {name:?}"
    );

    // A leading separator is dropped on purpose (SMB2 paths are relative to
    // the share root), so only paths without one can round-trip.
    if !name.starts_with('/') {
        assert_eq!(
            crate::name::decode_path(&encoded_path),
            name,
            "decode_path did not undo encode_path for {name:?}"
        );
    }
}

/// Nothing SMB2 refuses may survive an encode.
fn assert_wire_safe(encoded: &str, original: &str) {
    assert!(
        !encoded.contains(['"', '*', ':', '<', '>', '?', '\\', '|']),
        "encoding {original:?} left a character SMB2 rejects"
    );
    assert!(
        !encoded.chars().any(|c| ('\u{01}'..='\u{1F}').contains(&c)),
        "encoding {original:?} left a control character"
    );
    assert!(
        !matches!(encoded.chars().next_back(), Some(' ') | Some('.')),
        "encoding {original:?} left a trailing space or period"
    );
}
