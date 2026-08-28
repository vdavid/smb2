//! Integration tests for the public `Connection::diagnostics` snapshot.
//!
//! These live in `tests/` so they exercise only the public surface a
//! consumer can reach. Tests that need to *construct* a full
//! `Diagnostics` (which is `#[non_exhaustive]`, so external crates can't
//! struct-literal it) live alongside the impl in
//! `src/client/diagnostics.rs` and go through the lib-crate `tests` mod.

use std::sync::Arc;
use std::time::Duration;

use smb2::client::Connection;
use smb2::msg::echo::{EchoRequest, EchoResponse};
use smb2::msg::header::Header;
use smb2::pack::Pack;
use smb2::transport::mock::MockTransport;
use smb2::types::status::NtStatus;
use smb2::types::{Command, MessageId};

fn pack(header: &Header, body: &dyn Pack) -> Vec<u8> {
    let mut cursor = smb2::pack::WriteCursor::with_capacity(80);
    header.pack(&mut cursor);
    body.pack(&mut cursor);
    cursor.into_inner()
}

fn echo_ok(msg_id: MessageId) -> Vec<u8> {
    let mut h = Header::new_request(Command::Echo);
    h.flags.set_response();
    h.credits = 10;
    h.message_id = msg_id;
    h.status = NtStatus::SUCCESS;
    pack(&h, &EchoResponse)
}

async fn wait_for_sent(mock: &MockTransport, n: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while mock.sent_count() < n {
        if std::time::Instant::now() > deadline {
            panic!("expected {n} sent, got {}", mock.sent_count());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn fresh_conn() -> (Connection, Arc<MockTransport>) {
    let mock = Arc::new(MockTransport::new());
    mock.enable_auto_rewrite_msg_id();
    let conn = Connection::from_transport(
        Box::new(mock.clone()),
        Box::new(mock.clone()),
        "test-server",
    );
    (conn, mock)
}

/// A NEGOTIATE response granting a credit window, so the connection can send
/// something afterwards.
///
/// A client holds no credits until the server grants some, and NEGOTIATE is
/// the only request exempt from that. There is no public way to stage a window
/// -- deliberately, since no consumer can conjure credits either -- so a test
/// that needs to send anything has to negotiate for them like everybody else.
fn negotiate_ok(granting: u16) -> Vec<u8> {
    let mut h = Header::new_request(Command::Negotiate);
    h.flags.set_response();
    h.credits = granting;
    h.message_id = MessageId(0);
    h.status = NtStatus::SUCCESS;

    let body = smb2::msg::negotiate::NegotiateResponse {
        security_mode: smb2::types::flags::SecurityMode::new(0),
        dialect_revision: smb2::types::Dialect::Smb2_0_2,
        server_guid: smb2::pack::Guid::ZERO,
        capabilities: smb2::types::flags::Capabilities::default(),
        max_transact_size: 65536,
        max_read_size: 65536,
        max_write_size: 65536,
        system_time: 0,
        server_start_time: 0,
        security_buffer: Vec::new(),
        negotiate_contexts: Vec::new(),
    };
    pack(&h, &body)
}

/// [`fresh_conn`] taken through a real NEGOTIATE, which is the only state a
/// consumer can send a request from.
async fn negotiated_conn(granting: u16) -> (Connection, Arc<MockTransport>) {
    let (mut conn, mock) = fresh_conn();
    mock.queue_response(negotiate_ok(granting));
    conn.negotiate().await.expect("the mock answers NEGOTIATE");
    (conn, mock)
}

#[tokio::test(flavor = "multi_thread")]
async fn pre_negotiate_snapshot_has_no_negotiated_params() {
    let (conn, mock) = fresh_conn();
    let d = conn.diagnostics();

    assert_eq!(d.server, "test-server");
    assert!(d.negotiated.is_none(), "no negotiate yet");
    assert!(!d.signing.active);
    assert!(!d.encryption.active);
    assert!(!d.compression.negotiated);
    assert!(d.compression.requested, "default is true");
    assert!(!d.disconnected);
    assert_eq!(d.credits.in_flight, 0);
    assert_eq!(d.credits.next_message_id, 0);
    assert!(d.session.is_none(), "no session before SmbClient assembly");
    assert!(d.dfs_trees.is_empty());
    assert_eq!(d.metrics.requests_sent, 0);

    mock.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn in_flight_is_visible_in_snapshot() {
    let (conn, mock) = negotiated_conn(512).await;
    // The handshake is on the wire and counted too, so everything below reads
    // as a delta from where it left the connection.
    let base = conn.diagnostics().metrics;
    let sent_before = mock.sent_count();

    let c = conn.clone();
    let handle = tokio::spawn(async move {
        // Blocks forever — no response queued.
        c.execute(Command::Echo, &EchoRequest, None).await
    });

    wait_for_sent(&mock, sent_before + 1).await;
    // Give the receiver task a tick to register the waiter.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let d = conn.diagnostics();
    assert_eq!(d.credits.in_flight, 1);
    assert_eq!(d.metrics.requests_sent, base.requests_sent + 1);
    assert!(d.metrics.wire_bytes_sent > base.wire_bytes_sent);

    handle.abort();
    let _ = handle.await;
    mock.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_survives_teardown() {
    let (conn, mock) = negotiated_conn(512).await;
    let base = conn.diagnostics().metrics;
    let sent_before = mock.sent_count();

    let c = conn.clone();
    let handle = tokio::spawn(async move { c.execute(Command::Echo, &EchoRequest, None).await });
    wait_for_sent(&mock, sent_before + 1).await;
    mock.queue_response(echo_ok(MessageId(0)));
    handle.await.unwrap().unwrap();

    mock.close();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let d = conn.diagnostics();
    assert!(d.disconnected, "after close, snapshot reports disconnected");
    assert_eq!(
        d.metrics.responses_routed_ok,
        base.responses_routed_ok + 1,
        "counter survives teardown"
    );
    assert_eq!(d.metrics.requests_sent, base.requests_sent + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_types_are_send_sync_and_debug_clone() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn assert_clone<T: Clone>() {}
    assert_send::<smb2::Diagnostics>();
    assert_sync::<smb2::Diagnostics>();
    assert_clone::<smb2::Diagnostics>();
    assert_send::<smb2::ConnectionDiagnostics>();
    assert_clone::<smb2::ConnectionDiagnostics>();
    assert_send::<smb2::MetricsSnapshot>();

    let (conn, mock) = fresh_conn();
    let _ = format!("{:?}", conn.diagnostics());
    mock.close();
}
