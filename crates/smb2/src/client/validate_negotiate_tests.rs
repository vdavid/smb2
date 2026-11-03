//! A connection below SMB 3.1.1 proves its NEGOTIATE with a signed
//! `FSCTL_VALIDATE_NEGOTIATE_INFO` after its first tree connect (MS-SMB2
//! § 3.2.5.5, § 3.2.5.14.12), and anything short of a matching, signed answer
//! (or a signed "not implemented") tears it down.
//!
//! Each test scripts a server on a signed 3.0.2 session: the TREE_CONNECT
//! answer (message 0), then the IOCTL answer (message 1), both signed the way
//! a server signs unless the test says otherwise.

use std::sync::Arc;

use crate::client::connection::{pack_message, Connection, NegotiatedParams};
use crate::client::test_helpers::{build_ioctl_error_response, build_tree_connect_response};
use crate::client::tree::Tree;
use crate::crypto::signing::{self, SigningAlgorithm};
use crate::error::Error;
use crate::msg::header::Header;
use crate::msg::ioctl::{
    IoctlRequest, IoctlResponse, ValidateNegotiateInfoResponse, FSCTL_VALIDATE_NEGOTIATE_INFO,
    SMB2_0_IOCTL_IS_FSCTL,
};
use crate::msg::tree_connect::ShareType;
use crate::pack::{Guid, Pack, ReadCursor, Unpack, WriteCursor};
use crate::transport::MockTransport;
use crate::types::flags::{Capabilities, SecurityMode};
use crate::types::status::NtStatus;
use crate::types::{Command, Dialect, FileId, SessionId, TreeId};
use crate::ErrorKind;

const KEY: [u8; 16] = [0x5A; 16];
const SESSION: SessionId = SessionId(0x77);
const TREE: TreeId = TreeId(9);
const SERVER_GUID: Guid = Guid {
    data1: 0x1122_3344,
    data2: 0x5566,
    data3: 0x7788,
    data4: [1, 2, 3, 4, 5, 6, 7, 8],
};
const SERVER_CAPS: Capabilities = Capabilities::new(Capabilities::DFS | Capabilities::LARGE_MTU);
const SERVER_MODE: SecurityMode = SecurityMode::new(SecurityMode::SIGNING_ENABLED);

/// What NEGOTIATE told the client, and so what a genuine answer repeats.
fn genuine() -> ValidateNegotiateInfoResponse {
    ValidateNegotiateInfoResponse {
        capabilities: SERVER_CAPS,
        guid: SERVER_GUID,
        security_mode: SERVER_MODE,
        dialect: 0x0302,
    }
}

/// A connection that negotiated `dialect` and, with `signing`, has a session
/// that signs.
fn connection(dialect: Dialect, signing: bool) -> (Arc<MockTransport>, Connection) {
    let mock = Arc::new(MockTransport::new());
    mock.enable_auto_rewrite_msg_id();
    let mut conn = Connection::from_transport(
        Box::new(mock.clone()),
        Box::new(mock.clone()),
        "test-server",
    );
    conn.set_test_params(NegotiatedParams {
        dialect,
        max_read_size: 65536,
        max_write_size: 65536,
        max_transact_size: 65536,
        server_guid: SERVER_GUID,
        signing_required: false,
        security_mode: SERVER_MODE,
        capabilities: SERVER_CAPS,
        signing_algorithm: SigningAlgorithm::AesCmac,
        cipher: None,
        compression_supported: false,
    });
    conn.set_session_id(SESSION);
    if signing {
        conn.activate_signing(KEY.to_vec(), SigningAlgorithm::AesCmac);
    }
    conn.set_credits(512);
    (mock, conn)
}

/// `frame`, as message `id` of the session, signed by the session key.
fn signed(mut frame: Vec<u8>, id: u64) -> Vec<u8> {
    frame[24..32].copy_from_slice(&id.to_le_bytes());
    frame[40..48].copy_from_slice(&SESSION.0.to_le_bytes());
    let flags = u32::from_le_bytes(frame[16..20].try_into().unwrap()) | 0x0000_0008;
    frame[16..20].copy_from_slice(&flags.to_le_bytes());
    signing::sign_message_as_server(&mut frame, &KEY, SigningAlgorithm::AesCmac, id, false)
        .unwrap();
    frame
}

fn tree_connected(id: u64) -> Vec<u8> {
    signed(build_tree_connect_response(TREE, ShareType::Disk), id)
}

/// An IOCTL answer with `status` and, on success, `answer` as its output.
fn ioctl_answer(status: NtStatus, answer: Option<ValidateNegotiateInfoResponse>) -> Vec<u8> {
    let mut h = Header::new_request(Command::Ioctl);
    h.flags.set_response();
    h.credits = 32;
    h.status = status;
    h.tree_id = Some(TREE);
    match answer {
        Some(answer) => {
            let mut out = WriteCursor::new();
            answer.pack(&mut out);
            let body = IoctlResponse {
                ctl_code: FSCTL_VALIDATE_NEGOTIATE_INFO,
                file_id: FileId::SENTINEL,
                flags: 0,
                output_data: out.into_inner(),
            };
            pack_message(&h, &body)
        }
        None => build_ioctl_error_response(status),
    }
}

/// Connect a share on `conn` and return what came back.
async fn connect(conn: &mut Connection) -> crate::Result<Tree> {
    Tree::connect(conn, "share").await
}

fn assert_refused(result: crate::Result<Tree>, conn: &Connection, what: &str) {
    match result {
        Err(e @ Error::NegotiateValidationFailed { .. }) => {
            assert_eq!(e.kind(), ErrorKind::NegotiateValidationFailed);
            assert!(!e.is_retryable());
        }
        other => panic!("{what}: expected NegotiateValidationFailed, got {other:?}"),
    }
    assert!(conn.is_disconnected(), "{what}: the connection must go");
}

#[tokio::test]
async fn a_matching_answer_validates_and_is_asked_for_once() {
    let (mock, mut conn) = connection(Dialect::Smb3_0_2, true);
    mock.queue_response(tree_connected(0));
    mock.queue_response(signed(ioctl_answer(NtStatus::SUCCESS, Some(genuine())), 1));
    mock.queue_response(tree_connected(2));

    connect(&mut conn)
        .await
        .expect("a genuine answer validates");

    // The request repeats what NEGOTIATE sent, on the tree just connected.
    let sent = mock.sent_message(1).expect("the validation went out");
    let header = Header::unpack(&mut ReadCursor::new(&sent)).unwrap();
    assert_eq!(header.command, Command::Ioctl);
    assert_eq!(header.tree_id, Some(TREE));
    assert!(header.flags.is_signed(), "the request is signed");
    let request = IoctlRequest::unpack(&mut ReadCursor::new(&sent[Header::SIZE..])).unwrap();
    assert_eq!(request.ctl_code, FSCTL_VALIDATE_NEGOTIATE_INFO);
    assert_eq!(request.file_id, FileId::SENTINEL);
    assert_eq!(request.flags, SMB2_0_IOCTL_IS_FSCTL);
    assert_eq!(request.max_output_response, 24);
    let mut expected = WriteCursor::new();
    expected.write_u32_le(
        Capabilities::DFS
            | Capabilities::LEASING
            | Capabilities::LARGE_MTU
            | Capabilities::ENCRYPTION,
    );
    conn.client_guid().pack(&mut expected);
    expected.write_u16_le(SecurityMode::SIGNING_ENABLED);
    expected.write_u16_le(5);
    for d in [0x0202u16, 0x0210, 0x0300, 0x0302, 0x0311] {
        expected.write_u16_le(d);
    }
    assert_eq!(request.input_data, expected.into_inner());

    // A second share on the same connection asks nothing more.
    connect(&mut conn).await.expect("the second share connects");
    assert_eq!(
        mock.sent_count(),
        3,
        "only the second TREE_CONNECT went out"
    );
    assert!(!conn.is_disconnected());
}

#[tokio::test]
async fn an_answer_that_differs_in_any_field_drops_the_connection() {
    type Tamper = fn(&mut ValidateNegotiateInfoResponse);
    let cases: [(&str, Tamper); 4] = [
        ("dialect", |a| a.dialect = 0x0210),
        ("server GUID", |a| a.guid = Guid::ZERO),
        ("security mode", |a| {
            a.security_mode = SecurityMode::new(SecurityMode::SIGNING_REQUIRED)
        }),
        ("capabilities", |a| {
            a.capabilities = Capabilities::new(SERVER_CAPS.bits() | Capabilities::ENCRYPTION)
        }),
    ];
    for (field, tamper) in cases {
        let (mock, mut conn) = connection(Dialect::Smb3_0_2, true);
        let mut answer = genuine();
        tamper(&mut answer);
        mock.queue_response(tree_connected(0));
        mock.queue_response(signed(ioctl_answer(NtStatus::SUCCESS, Some(answer)), 1));

        let result = connect(&mut conn).await;
        if let Err(Error::NegotiateValidationFailed { reason }) = &result {
            assert!(reason.contains(field), "{field}: reason was {reason:?}");
        }
        assert_refused(result, &conn, field);
    }
}

#[tokio::test]
async fn access_denied_drops_the_connection() {
    let (mock, mut conn) = connection(Dialect::Smb3_0_2, true);
    mock.queue_response(tree_connected(0));
    mock.queue_response(signed(ioctl_answer(NtStatus::ACCESS_DENIED, None), 1));
    assert_refused(connect(&mut conn).await, &conn, "ACCESS_DENIED");
}

#[tokio::test]
async fn an_unsigned_answer_drops_the_connection_even_if_it_matches() {
    let (mock, mut conn) = connection(Dialect::Smb3_0_2, true);
    mock.queue_response(tree_connected(0));
    let mut unsigned = ioctl_answer(NtStatus::SUCCESS, Some(genuine()));
    unsigned[24..32].copy_from_slice(&1u64.to_le_bytes());
    mock.queue_response(unsigned);
    assert_refused(connect(&mut conn).await, &conn, "unsigned");
}

#[tokio::test]
async fn a_server_that_hangs_up_on_the_question_fails_the_connect() {
    let (mock, mut conn) = connection(Dialect::Smb3_0_2, true);
    mock.queue_response(tree_connected(0));
    // What Samba does when what we say we sent isn't what it received.
    mock.close();
    let result = connect(&mut conn).await;
    assert!(
        matches!(result, Err(Error::NegotiateValidationFailed { .. })),
        "got {result:?}"
    );
}

#[tokio::test]
async fn a_signed_not_implemented_is_accepted_and_remembered() {
    for status in [
        NtStatus::NOT_SUPPORTED,
        NtStatus::INVALID_DEVICE_REQUEST,
        NtStatus::FILE_CLOSED,
    ] {
        let (mock, mut conn) = connection(Dialect::Smb3_0, true);
        mock.queue_response(tree_connected(0));
        mock.queue_response(signed(ioctl_answer(status, None), 1));
        mock.queue_response(tree_connected(2));

        connect(&mut conn)
            .await
            .unwrap_or_else(|e| panic!("{status:?}: {e}"));
        connect(&mut conn).await.unwrap();
        assert_eq!(mock.sent_count(), 3, "{status:?}: asked once");
    }
}

#[tokio::test]
async fn any_other_refusal_fails_closed() {
    let (mock, mut conn) = connection(Dialect::Smb3_0_2, true);
    mock.queue_response(tree_connected(0));
    mock.queue_response(signed(ioctl_answer(NtStatus::INVALID_PARAMETER, None), 1));
    assert_refused(connect(&mut conn).await, &conn, "INVALID_PARAMETER");
}

#[tokio::test]
async fn a_2x_dialect_is_validated_too() {
    // The downgrade to 2.1 is one of the two the check exists for.
    let (mock, mut conn) = connection(Dialect::Smb2_1, true);
    mock.queue_response(tree_connected(0));
    let mut answer = genuine();
    answer.dialect = 0x0210;
    mock.queue_response(signed(ioctl_answer(NtStatus::SUCCESS, Some(answer)), 1));
    connect(&mut conn).await.expect("validates on 2.1");
    assert_eq!(mock.sent_count(), 2);
}

#[tokio::test]
async fn smb_3_1_1_sends_nothing() {
    let (mock, mut conn) = connection(Dialect::Smb3_1_1, true);
    mock.queue_response(tree_connected(0));
    connect(&mut conn).await.unwrap();
    assert_eq!(
        mock.sent_count(),
        1,
        "the preauth hash already covers 3.1.1"
    );
}

#[tokio::test]
async fn a_session_that_does_not_sign_waits_for_one_that_does() {
    let (mock, mut conn) = connection(Dialect::Smb3_0_2, false);
    let mut guest_tree = build_tree_connect_response(TREE, ShareType::Disk);
    guest_tree[24..32].copy_from_slice(&0u64.to_le_bytes());
    mock.queue_response(guest_tree);
    connect(&mut conn).await.unwrap();
    assert_eq!(
        mock.sent_count(),
        1,
        "a guest session can't sign the question"
    );

    // A signing session set up afterwards validates at its first share.
    conn.activate_signing(KEY.to_vec(), SigningAlgorithm::AesCmac);
    mock.queue_response(tree_connected(1));
    mock.queue_response(signed(ioctl_answer(NtStatus::SUCCESS, Some(genuine())), 2));
    connect(&mut conn).await.unwrap();
    assert_eq!(mock.sent_count(), 3);
}
