//! Read-only readers against the mock: what they ask the server for, and
//! what a reopen accepts and refuses (`reopen.rs`).
//!
//! A reconnect is modelled by moving the connection to a new session id: the
//! previous reader's pin stops being current, exactly as after a revival, and
//! the mock keeps answering whatever the test queued.

use std::sync::Arc;

use crate::client::connection::{pack_message, Connection};
use crate::client::durable::FileIdentity;
use crate::client::reopen::{open_file_reader_with, reopen_file_reader, ReaderOptions};
use crate::client::stream::FileReader;
use crate::client::test_helpers::{
    build_close_response, build_compound_response_frame, build_query_info_error_response,
    build_query_info_response, build_read_response, build_reader_open_refused,
    build_reader_open_response, setup_connection,
};
use crate::client::tree::Tree;
use crate::error::{Error, ErrorKind, FileChange};
use crate::msg::create::{CreateAction, CreateDisposition, CreateRequest, CreateResponse};
use crate::msg::create_context::{self, CreateContext};
use crate::msg::header::Header;
use crate::pack::{FileTime, ReadCursor, Unpack};
use crate::transport::MockTransport;
use crate::types::flags::FileAccessMask;
use crate::types::status::NtStatus;
use crate::types::{Command, Dialect, FileId, OplockLevel, SessionId, TreeId};

const PATH: &str = "films/big.mkv";
const SIZE: u64 = 4_000_000_000;
const WRITTEN: FileTime = FileTime(133_000_000_000_000_000);
const OURS: FileIdentity = FileIdentity {
    volume_serial: 0xABCD,
    index_number: 0x1234_5678,
};
const SOMEONE_ELSES: FileIdentity = FileIdentity {
    volume_serial: 0xABCD,
    index_number: 0x9999_9999,
};
const READ_ONLY: u32 = FileAccessMask::FILE_READ_DATA
    | FileAccessMask::FILE_READ_ATTRIBUTES
    | FileAccessMask::SYNCHRONIZE;

fn share() -> Arc<Tree> {
    Arc::new(Tree {
        pin: None,
        tree_id: TreeId(20),
        share_name: "media".to_string(),
        server: "test-server".to_string(),
        is_dfs: false,
        encrypt_data: false,
        dfs_origin: None,
    })
}

fn smb3(mock: &Arc<MockTransport>) -> Connection {
    let mut conn = setup_connection(mock);
    let mut params = conn.params().unwrap();
    params.dialect = Dialect::Smb3_1_1;
    conn.set_test_params(params);
    conn
}

/// What a reconnect does to every handle opened before it.
fn reconnect(conn: &mut Connection) {
    let next = SessionId(conn.session_id().0 + 1);
    conn.set_session_id(next);
}

fn file(n: u64) -> FileId {
    FileId {
        persistent: n,
        volatile: n,
    }
}

/// The file as the server describes it in one answer.
#[derive(Clone, Copy)]
struct Seen {
    size: u64,
    modified: FileTime,
    identity: Option<FileIdentity>,
}

const UNCHANGED: Seen = Seen {
    size: SIZE,
    modified: WRITTEN,
    identity: Some(OURS),
};

fn granted() -> CreateContext {
    let mut body = Vec::new();
    body.extend_from_slice(&180_000u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    CreateContext::new(create_context::NAME_DH2Q, body)
}

/// The name the server stores [`PATH`] under, in its own casing.
const STORED: &str = "Films/Big.mkv";

/// The CREATE's own answer.
fn created(file_id: FileId, seen: Seen, contexts: &[CreateContext]) -> Vec<u8> {
    let mut h = Header::new_request(Command::Create);
    h.flags.set_response();
    h.credits = 32;
    pack_message(
        &h,
        &CreateResponse {
            oplock_level: OplockLevel::Batch,
            flags: 0,
            create_action: CreateAction::FileOpened,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: seen.modified,
            change_time: seen.modified,
            allocation_size: 0,
            end_of_file: seen.size,
            file_attributes: 0,
            file_id,
            create_contexts: create_context::pack_contexts(contexts),
        },
    )
}

/// CREATE + identity + class 18 + class 48, the compound every reader open
/// and every read handle's reclaim sends. The server names the file
/// [`STORED`].
fn answer(file_id: FileId, seen: Seen, contexts: &[CreateContext]) -> Vec<u8> {
    build_reader_open_response(
        created(file_id, seen, contexts),
        seen.identity,
        None,
        Some(&STORED.replace('/', "\\")),
    )
}

/// CREATE + identity alone, what a WRITE handle's open and reclaim send.
fn write_answer(file_id: FileId, seen: Seen, contexts: &[CreateContext]) -> Vec<u8> {
    let (index, volume) = match seen.identity {
        Some(id) => {
            let mut volume = vec![0u8; 8];
            volume.extend_from_slice(&id.volume_serial.to_le_bytes());
            volume.extend_from_slice(&[0; 6]);
            (
                build_query_info_response(id.index_number.to_le_bytes().to_vec()),
                build_query_info_response(volume),
            )
        }
        None => (
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
        ),
    };
    build_compound_response_frame(&[created(file_id, seen, contexts), index, volume])
}

/// The CREATE the client sent as request `n`.
fn sent_create(mock: &MockTransport, n: usize) -> CreateRequest {
    let sent = mock.sent_message(n).unwrap();
    let mut cursor = ReadCursor::new(&sent);
    let header = Header::unpack(&mut cursor).unwrap();
    assert_eq!(header.command, Command::Create, "request {n}");
    CreateRequest::unpack(&mut cursor).unwrap()
}

/// The `QUERY_INFO` classes compounded into request `n`, in order.
fn sent_query_classes(mock: &MockTransport, n: usize) -> Vec<u8> {
    let sent = mock.sent_message(n).unwrap();
    let mut classes = Vec::new();
    let mut offset = 0usize;
    loop {
        let mut cursor = ReadCursor::new(&sent[offset..]);
        let header = Header::unpack(&mut cursor).unwrap();
        if header.command == Command::QueryInfo {
            let req = crate::msg::query_info::QueryInfoRequest::unpack(&mut cursor).unwrap();
            classes.push(req.file_info_class);
        }
        if header.next_command == 0 {
            return classes;
        }
        offset += header.next_command as usize;
    }
}

fn sent_command(mock: &MockTransport, n: usize) -> Command {
    let sent = mock.sent_message(n).unwrap();
    Header::unpack(&mut ReadCursor::new(&sent)).unwrap().command
}

fn contexts(req: &CreateRequest) -> Vec<CreateContext> {
    create_context::parse_contexts(&req.create_contexts).unwrap()
}

/// Every CREATE a reader sends asks to read, and to do nothing else.
fn assert_read_only(req: &CreateRequest) {
    assert_eq!(
        req.desired_access.bits(),
        READ_ONLY,
        "a reader must ask for read access and nothing more"
    );
    assert_eq!(
        req.create_disposition,
        CreateDisposition::FileOpen,
        "a reader must never create the file"
    );
}

async fn open(conn: &Connection, options: ReaderOptions) -> FileReader {
    open_file_reader_with(share(), conn.clone(), PATH, options)
        .await
        .expect("the open must succeed")
}

async fn open_durable(mock: &Arc<MockTransport>, conn: &Connection) -> FileReader {
    mock.queue_response(answer(file(1), UNCHANGED, &[granted()]));
    let reader = open(conn, ReaderOptions::new().durable(true)).await;
    assert!(reader.durable_handle().is_some(), "the server granted one");
    reader
}

async fn reopen(conn: &Connection, previous: &FileReader) -> crate::Result<FileReader> {
    reopen_file_reader(share(), conn.clone(), PATH, previous).await
}

fn changed(outcome: crate::Result<FileReader>) -> FileChange {
    match outcome {
        Err(Error::FileChanged { change, path }) => {
            assert_eq!(path, PATH);
            change
        }
        Err(e) => panic!("expected FileChanged, got {e}"),
        Ok(_) => panic!("expected FileChanged, got a reader"),
    }
}

// ── Opening ──────────────────────────────────────────────────────────

#[tokio::test]
async fn a_plain_reader_asks_for_read_access_only_and_records_its_version() {
    let mock = Arc::new(MockTransport::new());
    let conn = smb3(&mock);
    mock.queue_response(answer(file(1), UNCHANGED, &[]));

    let reader = open(&conn, ReaderOptions::new()).await;

    let req = sent_create(&mock, 0);
    assert_read_only(&req);
    assert_eq!(req.requested_oplock_level, OplockLevel::None);
    assert!(
        contexts(&req).is_empty(),
        "no durable request was asked for"
    );
    let version = reader.version();
    assert_eq!(version.size, SIZE);
    assert_eq!(version.modified, WRITTEN);
    assert_eq!(version.identity, Some(OURS));
    assert_eq!(reader.resolved_path(), Some(STORED));
    assert!(reader.durable_handle().is_none());
}

/// `open_file_reader` is the default-options case of the same open, so it
/// records exactly what `open_file_reader_with` does.
#[tokio::test]
async fn the_plain_open_is_the_default_options_open() {
    let mock = Arc::new(MockTransport::new());
    let conn = smb3(&mock);
    mock.queue_response(answer(file(1), UNCHANGED, &[]));
    mock.queue_response(answer(file(1), UNCHANGED, &[]));

    let plain = crate::client::stream::open_file_reader(share(), conn.clone(), PATH)
        .await
        .unwrap();
    let with = open(&conn, ReaderOptions::new()).await;

    assert_eq!(sent_create(&mock, 0), sent_create(&mock, 1));
    assert_eq!(sent_query_classes(&mock, 0), vec![6, 1, 18, 48]);
    assert_eq!(sent_query_classes(&mock, 1), vec![6, 1, 18, 48]);
    assert_eq!(plain.version(), with.version());
    assert_eq!(plain.resolved_path(), with.resolved_path());
}

#[tokio::test]
async fn a_durable_reader_asks_for_a_durable_handle_with_read_access_only() {
    let mock = Arc::new(MockTransport::new());
    let conn = smb3(&mock);

    let reader = open_durable(&mock, &conn).await;

    let req = sent_create(&mock, 0);
    assert_read_only(&req);
    assert_eq!(
        req.requested_oplock_level,
        OplockLevel::Batch,
        "without a batch oplock the server ignores the durable request"
    );
    assert!(create_context::find(&contexts(&req), create_context::NAME_DH2Q).is_some());
    assert_eq!(
        sent_query_classes(&mock, 0),
        vec![6, 1, 18, 48],
        "the durable open is the same compound as a plain one"
    );
    let handle = reader.durable_handle().unwrap();
    assert!(handle.is_read_only());
    assert_eq!(handle.identity(), OURS);
    assert_eq!(reader.version().identity, Some(OURS));
    assert_eq!(reader.resolved_path(), Some(STORED));
}

/// A server that won't identify the file still gives a working reader; its
/// version just has no identity to compare.
#[tokio::test]
async fn a_server_that_will_not_identify_the_file_still_opens_it() {
    let mock = Arc::new(MockTransport::new());
    let conn = smb3(&mock);
    mock.queue_response(answer(
        file(1),
        Seen {
            identity: None,
            ..UNCHANGED
        },
        &[],
    ));

    let reader = open(&conn, ReaderOptions::new()).await;

    assert_eq!(reader.version().identity, None);
}

// ── Reopening by reclaiming the durable handle ───────────────────────

#[tokio::test]
async fn a_reopen_reclaims_the_durable_handle_with_read_access_only() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = smb3(&mock);
    let previous = open_durable(&mock, &conn).await;
    let guid_at_open = {
        let dh2q = contexts(&sent_create(&mock, 0));
        create_context::find(&dh2q, create_context::NAME_DH2Q)
            .unwrap()
            .data[16..32]
            .to_vec()
    };
    reconnect(&mut conn);
    assert!(!previous.is_current(), "its session is gone");

    mock.queue_response(answer(file(2), UNCHANGED, &[]));
    let reader = reopen(&conn, &previous)
        .await
        .expect("same file, unchanged");

    let req = sent_create(&mock, 1);
    assert_read_only(&req);
    let sent = contexts(&req);
    assert_eq!(sent.len(), 1, "the reconnect context travels alone");
    let dh2c = create_context::find(&sent, create_context::NAME_DH2C).expect("a reclaim");
    assert_eq!(dh2c.data[16..32], guid_at_open[..]);
    assert_eq!(reader.version(), previous.version());
    assert!(reader.is_current());
    assert!(reader.durable_handle().unwrap().is_read_only());
    assert_eq!(
        reader.resolved_path(),
        Some(STORED),
        "the reclaim asks the name too, so the reader keeps one"
    );
    assert_eq!(sent_query_classes(&mock, 1), vec![6, 1, 18, 48]);

    // And it reads through the reclaimed handle, not the dead one.
    mock.queue_response(build_read_response(vec![7; 16]));
    assert_eq!(reader.read_at(0, 16).await.unwrap(), vec![7; 16]);
    let read = mock.sent_message(2).unwrap();
    let mut cursor = ReadCursor::new(&read);
    Header::unpack(&mut cursor).unwrap();
    let read = crate::msg::read::ReadRequest::unpack(&mut cursor).unwrap();
    assert_eq!(read.file_id, file(2));
}

/// The durable handle kept the open alive, not the bytes: another client
/// may have written while ours was away. A reclaimed handle onto a file of a
/// different length is closed and refused.
#[tokio::test]
async fn a_reclaimed_handle_onto_a_changed_file_is_refused_and_closed() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = smb3(&mock);
    let previous = open_durable(&mock, &conn).await;
    reconnect(&mut conn);

    mock.queue_response(answer(
        file(2),
        Seen {
            size: SIZE + 10,
            ..UNCHANGED
        },
        &[],
    ));
    mock.queue_response(build_close_response());
    let outcome = reopen(&conn, &previous).await;

    assert_eq!(
        changed(outcome),
        FileChange::Size {
            was: SIZE,
            now: SIZE + 10
        }
    );
    assert_eq!(sent_command(&mock, 2), Command::Close, "nothing left open");
}

/// The server no longer has the open (it timed out, or restarted): the
/// reopen falls back to the path, and asks for a new durable handle.
#[tokio::test]
async fn a_lost_durable_handle_falls_back_to_reopening_the_path() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = smb3(&mock);
    let previous = open_durable(&mock, &conn).await;
    reconnect(&mut conn);

    mock.queue_response(build_reader_open_refused(NtStatus::OBJECT_NAME_NOT_FOUND));
    mock.queue_response(answer(file(3), UNCHANGED, &[granted()]));
    let reader = reopen(&conn, &previous)
        .await
        .expect("the path holds the same version");

    let reclaim = sent_create(&mock, 1);
    assert!(create_context::find(&contexts(&reclaim), create_context::NAME_DH2C).is_some());
    let reopened = sent_create(&mock, 2);
    assert_read_only(&reopened);
    assert!(
        create_context::find(&contexts(&reopened), create_context::NAME_DH2Q).is_some(),
        "the fresh open asks for durability again"
    );
    assert!(reader.durable_handle().is_some());
}

/// A reader whose session is still current holds a live handle; reclaiming
/// it would only fail. The reopen opens the path instead.
#[tokio::test]
async fn a_live_reader_is_reopened_by_path_not_reclaimed() {
    let mock = Arc::new(MockTransport::new());
    let conn = smb3(&mock);
    let previous = open_durable(&mock, &conn).await;

    mock.queue_response(answer(file(2), UNCHANGED, &[granted()]));
    reopen(&conn, &previous).await.unwrap();

    let req = sent_create(&mock, 1);
    assert!(create_context::find(&contexts(&req), create_context::NAME_DH2C).is_none());
}

// ── Reopening by path ────────────────────────────────────────────────

async fn reopen_plain(now: Seen) -> (Arc<MockTransport>, crate::Result<FileReader>) {
    let mock = Arc::new(MockTransport::new());
    let mut conn = smb3(&mock);
    mock.queue_response(answer(file(1), UNCHANGED, &[]));
    let previous = open(&conn, ReaderOptions::new()).await;
    reconnect(&mut conn);

    mock.queue_response(answer(file(2), now, &[]));
    mock.queue_response(build_close_response());
    let outcome = reopen(&conn, &previous).await;
    (mock, outcome)
}

#[tokio::test]
async fn an_unchanged_file_reopens_by_path() {
    let (mock, outcome) = reopen_plain(UNCHANGED).await;

    let reader = outcome.expect("same file, same length, same time");
    assert_read_only(&sent_create(&mock, 1));
    assert!(contexts(&sent_create(&mock, 1)).is_empty());
    assert_eq!(reader.version().identity, Some(OURS));
}

#[tokio::test]
async fn a_file_written_since_is_refused_and_closed() {
    let (mock, outcome) = reopen_plain(Seen {
        modified: FileTime(WRITTEN.0 + 1),
        ..UNCHANGED
    })
    .await;

    assert_eq!(changed(outcome), FileChange::Modified);
    assert_eq!(sent_command(&mock, 2), Command::Close);
}

#[tokio::test]
async fn a_different_file_at_the_path_is_refused_even_at_the_same_length_and_time() {
    let (mock, outcome) = reopen_plain(Seen {
        identity: Some(SOMEONE_ELSES),
        ..UNCHANGED
    })
    .await;

    assert_eq!(changed(outcome), FileChange::Replaced);
    assert_eq!(sent_command(&mock, 2), Command::Close);
}

/// Identity first: a replaced file's length says nothing about ours.
#[tokio::test]
async fn a_replaced_file_reports_the_replacement_not_its_length() {
    let (_, outcome) = reopen_plain(Seen {
        size: 1,
        identity: Some(SOMEONE_ELSES),
        ..UNCHANGED
    })
    .await;

    assert_eq!(changed(outcome), FileChange::Replaced);
}

/// A server that identified the file at open and won't now proves nothing,
/// so the reopen refuses: the safe direction.
#[tokio::test]
async fn an_identity_that_goes_missing_is_refused() {
    let (_, outcome) = reopen_plain(Seen {
        identity: None,
        ..UNCHANGED
    })
    .await;

    assert_eq!(changed(outcome), FileChange::IdentityUnavailable);
}

#[tokio::test]
async fn a_file_that_is_gone_reports_not_found() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = smb3(&mock);
    mock.queue_response(answer(file(1), UNCHANGED, &[]));
    let previous = open(&conn, ReaderOptions::new()).await;
    reconnect(&mut conn);

    mock.queue_response(build_reader_open_refused(NtStatus::OBJECT_NAME_NOT_FOUND));
    let err = reopen(&conn, &previous).await.err().unwrap();

    assert_eq!(err.kind(), ErrorKind::NotFound, "{err}");
}

#[test]
fn a_changed_file_is_its_own_kind_and_not_retryable() {
    let err = Error::FileChanged {
        path: PATH.to_string(),
        change: FileChange::Modified,
    };
    assert_eq!(err.kind(), ErrorKind::FileChanged);
    assert!(
        !err.is_retryable(),
        "asking again can only be refused again"
    );
}

/// The read-only flag rides on the handle, so a write handle's reclaim is
/// exactly what it always was: write access, for the transfer it resumes.
#[tokio::test]
async fn a_write_handle_is_still_reclaimed_with_write_access() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = smb3(&mock);
    mock.queue_response(write_answer(file(1), UNCHANGED, &[granted()]));
    let durable = share()
        .open_file_durable(&mut conn, PATH)
        .await
        .unwrap()
        .durable
        .unwrap();
    assert!(!durable.is_read_only());
    reconnect(&mut conn);

    mock.queue_response(write_answer(file(2), UNCHANGED, &[]));
    share()
        .reclaim_durable_handle(&mut conn, &durable, PATH)
        .await
        .unwrap();

    let access = sent_create(&mock, 1).desired_access.bits();
    assert_ne!(access & FileAccessMask::FILE_WRITE_DATA, 0);
}
