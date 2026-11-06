//! Download checkpoints and resumes against the mock (`reopen.rs`
//! § Resuming a download): what a checkpoint counts, that it keeps
//! `next_chunk` cancel-safe, and every outcome of a resume.
//!
//! A reconnect is modelled the way `reopen_tests.rs` models it: the
//! connection moves to a new session id, so every handle opened before it
//! stops being current, and the mock keeps answering whatever is queued.

use std::sync::Arc;
use std::time::Duration;

use crate::client::connection::{pack_message, Connection};
use crate::client::durable::FileIdentity;
use crate::client::stream::{resume_file_download, DownloadCheckpoint, FileDownload, ReadAhead};
use crate::client::test_helpers::{
    build_close_response, build_download_open_with_listing, build_query_info_error_response,
    build_read_response, build_reader_open_refused, build_reader_open_response,
    setup_connection_with_max_read,
};
use crate::client::tree::Tree;
use crate::error::{Error, ErrorKind, FileChange};
use crate::msg::create::{CreateAction, CreateDisposition, CreateRequest, CreateResponse};
use crate::msg::header::Header;
use crate::msg::read::ReadRequest;
use crate::pack::{FileTime, ReadCursor, Unpack};
use crate::transport::MockTransport;
use crate::types::flags::FileAccessMask;
use crate::types::status::NtStatus;
use crate::types::{Command, FileId, OplockLevel, SessionId, TreeId};

const PATH: &str = "films/big.mkv";
const CHUNK: u32 = 65536;
const SIZE: u64 = 4 * CHUNK as u64;
const WRITTEN: FileTime = FileTime(133_000_000_000_000_000);
const OURS: FileIdentity = FileIdentity {
    volume_serial: 0xABCD,
    index_number: 0x1234_5678,
};
const SOMEONE_ELSES: FileIdentity = FileIdentity {
    volume_serial: 0xABCD,
    index_number: 0x9999_9999,
};

fn share() -> Tree {
    Tree {
        pin: None,
        tree_id: TreeId(20),
        share_name: "media".to_string(),
        server: "test-server".to_string(),
        is_dfs: false,
        encrypt_data: false,
        dfs_origin: None,
    }
}

/// Reads one chunk per READ, so the offsets below are whole chunks.
fn connection(mock: &Arc<MockTransport>) -> Connection {
    setup_connection_with_max_read(mock, CHUNK)
}

/// What a reconnect does to every handle opened before it.
fn reconnect(conn: &Connection) {
    let next = SessionId(conn.session_id().0 + 1);
    conn.clone().set_session_id(next);
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
    changed: FileTime,
    identity: Option<FileIdentity>,
}

const UNCHANGED: Seen = Seen {
    size: SIZE,
    modified: WRITTEN,
    changed: WRITTEN,
    identity: Some(OURS),
};

/// The reader open's compound, answered: CREATE, identity, class 18, 48.
fn opened(file_id: FileId, seen: Seen) -> Vec<u8> {
    build_reader_open_response(
        created(file_id, seen),
        seen.identity,
        None,
        Some("Films\\Big.mkv"),
    )
}

/// The CREATE's own answer.
fn created(file_id: FileId, seen: Seen) -> Vec<u8> {
    let mut h = Header::new_request(Command::Create);
    h.flags.set_response();
    h.credits = 32;
    pack_message(
        &h,
        &CreateResponse {
            oplock_level: OplockLevel::None,
            flags: 0,
            create_action: CreateAction::FileOpened,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: seen.modified,
            change_time: seen.changed,
            allocation_size: 0,
            end_of_file: seen.size,
            file_attributes: 0,
            file_id,
            create_contexts: vec![],
        },
    )
}

fn chunk_of(i: u8) -> Vec<u8> {
    vec![i; CHUNK as usize]
}

/// Every sent request's command, in send order.
fn sent_commands(mock: &MockTransport) -> Vec<Command> {
    mock.sent_messages()
        .iter()
        .map(|b| Header::unpack(&mut ReadCursor::new(b)).unwrap().command)
        .collect()
}

/// Offsets and file ids of every READ the mock saw, in send order.
fn sent_reads(mock: &MockTransport) -> Vec<(u64, FileId)> {
    mock.sent_messages()
        .iter()
        .filter(|b| Header::unpack(&mut ReadCursor::new(b)).unwrap().command == Command::Read)
        .map(|b| {
            let r = ReadRequest::unpack(&mut ReadCursor::new(&b[Header::SIZE..])).unwrap();
            (r.offset, r.file_id)
        })
        .collect()
}

/// The CREATE the client sent as request `n`.
fn sent_create(mock: &MockTransport, n: usize) -> CreateRequest {
    let sent = mock.sent_message(n).unwrap();
    let mut cursor = ReadCursor::new(&sent);
    assert_eq!(
        Header::unpack(&mut cursor).unwrap().command,
        Command::Create
    );
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

/// A download of [`PATH`] that has handed out its first chunk, and the
/// checkpoint it gives after it.
async fn one_chunk_in(
    mock: &Arc<MockTransport>,
    tree: &Tree,
    conn: &mut Connection,
) -> DownloadCheckpoint {
    mock.queue_response(opened(file(1), UNCHANGED));
    let mut download = tree
        .download(conn, PATH)
        .await
        .unwrap()
        .with_read_ahead(ReadAhead::SEQUENTIAL);
    mock.queue_response(build_read_response(chunk_of(1)));
    assert_eq!(download.next_chunk().await.unwrap().unwrap(), chunk_of(1));
    let checkpoint = download
        .checkpoint()
        .expect("a download from a path has one");
    // The READ that went out behind the first chunk is abandoned with the
    // download, which closes its handle. Answer both, so the next queued
    // answer goes to the next request.
    mock.queue_response(build_read_response(chunk_of(2)));
    mock.queue_response(build_close_response());
    drop(download);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        sent_commands(mock),
        vec![
            Command::Create,
            Command::Read,
            Command::Read,
            Command::Close
        ]
    );
    checkpoint
}

// ── What a download records ──────────────────────────────────────────

/// A download opens the way a reader does (read access only, never
/// creating, version and name in the one round trip), so it can hand out a
/// checkpoint from the start.
#[tokio::test]
async fn a_download_opens_like_a_reader_and_records_its_version() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    mock.queue_response(opened(file(1), UNCHANGED));

    let download = tree.download(&mut conn, PATH).await.unwrap();

    let req = sent_create(&mock, 0);
    assert_eq!(
        req.desired_access.bits(),
        FileAccessMask::FILE_READ_DATA
            | FileAccessMask::FILE_READ_ATTRIBUTES
            | FileAccessMask::SYNCHRONIZE
    );
    assert_eq!(req.create_disposition, CreateDisposition::FileOpen);
    assert_eq!(sent_query_classes(&mock, 0), vec![6, 1, 18, 48]);
    let checkpoint = download.checkpoint().unwrap();
    assert_eq!(checkpoint.path, PATH);
    assert_eq!(checkpoint.offset, 0);
    assert_eq!(checkpoint.version.size, SIZE);
    assert_eq!(checkpoint.version.modified, WRITTEN);
    assert_eq!(checkpoint.version.identity, Some(OURS));
}

/// The stream listing rides the same compound, after class 18 and before
/// class 48, so the download that keeps xattrs can resume too.
#[tokio::test]
async fn a_download_with_streams_lists_them_in_the_same_open() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    // The listing's answer is `streams.rs`'s business; refused here.
    mock.queue_response(build_download_open_with_listing(
        created(file(1), UNCHANGED),
        Some(OURS),
        build_query_info_error_response(NtStatus::NOT_SUPPORTED),
    ));

    let download = tree.download_with_streams(&mut conn, PATH).await.unwrap();

    assert_eq!(sent_query_classes(&mock, 0), vec![6, 1, 18, 22, 48]);
    let checkpoint = download.checkpoint().unwrap();
    assert_eq!(checkpoint.version.identity, Some(OURS));
}

/// A handle the caller opened itself carries no version, so there is
/// nothing a resume could check against.
#[tokio::test]
async fn a_download_around_the_callers_own_handle_has_no_checkpoint() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    let download = FileDownload::new(&tree, &mut conn, file(1), SIZE, CHUNK);
    assert!(download.checkpoint().is_none());
}

// ── What a checkpoint counts ─────────────────────────────────────────

/// Only bytes handed to the consumer count. READs on the wire, and answers
/// that have landed but wait behind the head, are not the consumer's yet.
#[tokio::test]
async fn the_checkpoint_counts_delivered_bytes_never_ones_in_flight() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    mock.queue_response(opened(file(1), UNCHANGED));
    let mut download = tree
        .download(&mut conn, PATH)
        .await
        .unwrap()
        .with_read_ahead(ReadAhead::Fixed(3));
    for i in 1..=3u8 {
        mock.queue_response(build_read_response(chunk_of(i)));
    }

    assert_eq!(download.next_chunk().await.unwrap().unwrap(), chunk_of(1));
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(sent_reads(&mock).len(), 4, "three answered, one still out");
    assert_eq!(download.bytes_received(), u64::from(CHUNK));
    assert_eq!(download.checkpoint().unwrap().offset, u64::from(CHUNK));
}

/// Cancel safety holds: a `next_chunk` dropped mid-wait hands out nothing
/// and counts nothing, and the next call delivers and counts the chunk.
#[tokio::test]
async fn a_dropped_next_chunk_moves_the_checkpoint_nowhere() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    mock.queue_response(opened(file(1), UNCHANGED));
    let mut download = tree
        .download(&mut conn, PATH)
        .await
        .unwrap()
        .with_read_ahead(ReadAhead::Fixed(2));

    let lost = tokio::time::timeout(Duration::from_millis(50), download.next_chunk()).await;
    assert!(lost.is_err(), "nothing was answered yet");
    assert_eq!(download.checkpoint().unwrap().offset, 0);

    mock.queue_response(build_read_response(chunk_of(1)));
    assert_eq!(download.next_chunk().await.unwrap().unwrap(), chunk_of(1));
    assert_eq!(download.checkpoint().unwrap().offset, u64::from(CHUNK));
}

/// A chunk that came off the wire just before the session died is good
/// data: it's handed out, counted, and the error follows on the next call.
/// Thrown away, the checkpoint would vouch for bytes nobody received.
#[tokio::test]
async fn a_chunk_taken_before_the_session_died_is_still_handed_out() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let side = conn.clone();
    let tree = share();
    mock.queue_response(opened(file(1), UNCHANGED));
    let mut download = tree
        .download(&mut conn, PATH)
        .await
        .unwrap()
        .with_read_ahead(ReadAhead::Fixed(1));

    // The head's answer lands after the session moved on, so the READ that
    // would go out behind it is refused.
    let (first, ()) = tokio::join!(download.next_chunk(), async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        reconnect(&side);
        mock.queue_response(build_read_response(chunk_of(1)));
    });

    assert_eq!(first.unwrap().unwrap(), chunk_of(1));
    assert_eq!(download.checkpoint().unwrap().offset, u64::from(CHUNK));
    match download.next_chunk().await {
        Some(Err(Error::HandleInvalidated { .. })) => {}
        other => panic!("expected HandleInvalidated, got {other:?}"),
    }
    assert!(download.next_chunk().await.is_none());
    assert_eq!(download.checkpoint().unwrap().offset, u64::from(CHUNK));
}

// ── Resuming ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_resume_reads_on_from_the_checkpoint() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    let checkpoint = one_chunk_in(&mock, &tree, &mut conn).await;
    reconnect(&conn);
    let sent_before = mock.sent_count();

    mock.queue_response(opened(file(2), UNCHANGED));
    let mut resumed = resume_file_download(Arc::new(tree.clone()), conn.clone(), &checkpoint)
        .await
        .expect("the same file, unchanged");
    assert_eq!(
        sent_create(&mock, sent_before).name,
        sent_create(&mock, 0).name,
        "the checkpoint remembers the path"
    );
    assert_eq!(resumed.checkpoint().unwrap(), checkpoint);
    assert_eq!(resumed.size(), SIZE);
    assert_eq!(resumed.progress().bytes_transferred, u64::from(CHUNK));

    for i in 2..=4u8 {
        mock.queue_response(build_read_response(chunk_of(i)));
    }
    mock.queue_response(build_close_response());
    let mut rest = Vec::new();
    while let Some(chunk) = resumed.next_chunk().await {
        rest.extend(chunk.unwrap());
    }

    let reads: Vec<_> = sent_reads(&mock)
        .into_iter()
        .filter(|r| r.1 == file(2))
        .collect();
    assert_eq!(
        reads.iter().map(|r| r.0).collect::<Vec<_>>(),
        vec![u64::from(CHUNK), 2 * u64::from(CHUNK), 3 * u64::from(CHUNK)],
        "nothing before the checkpoint is read again"
    );
    assert_eq!(rest, (2..=4u8).flat_map(chunk_of).collect::<Vec<_>>());
    assert_eq!(resumed.bytes_received(), 3 * u64::from(CHUNK));
    assert_eq!(resumed.progress().bytes_transferred, SIZE);
    assert_eq!(resumed.checkpoint().unwrap().offset, SIZE);
}

/// A resume against a changed file closes what it opened and sends no READ.
async fn refused(now: Seen) -> (Arc<MockTransport>, FileChange) {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    let checkpoint = one_chunk_in(&mock, &tree, &mut conn).await;
    reconnect(&conn);
    let reads_before = sent_reads(&mock).len();

    mock.queue_response(opened(file(2), now));
    mock.queue_response(build_close_response());
    let outcome = tree.resume_download(&mut conn, &checkpoint).await;

    let change = match outcome {
        Err(Error::FileChanged { path, change }) => {
            assert_eq!(path, PATH);
            change
        }
        Err(e) => panic!("expected FileChanged, got {e}"),
        Ok(_) => panic!("expected FileChanged, got a download"),
    };
    assert_eq!(
        sent_reads(&mock).len(),
        reads_before,
        "no READ before the check"
    );
    assert_eq!(
        sent_commands(&mock).last(),
        Some(&Command::Close),
        "nothing left open"
    );
    (mock, change)
}

#[tokio::test]
async fn a_replaced_file_is_refused() {
    let (_, change) = refused(Seen {
        identity: Some(SOMEONE_ELSES),
        size: 1,
        ..UNCHANGED
    })
    .await;
    assert_eq!(change, FileChange::Replaced);
}

#[tokio::test]
async fn a_file_that_no_longer_says_which_it_is_is_refused() {
    let (_, change) = refused(Seen {
        identity: None,
        ..UNCHANGED
    })
    .await;
    assert_eq!(change, FileChange::IdentityUnavailable);
}

#[tokio::test]
async fn a_resized_file_is_refused() {
    let (_, change) = refused(Seen {
        size: SIZE + 1,
        ..UNCHANGED
    })
    .await;
    assert_eq!(
        change,
        FileChange::Size {
            was: SIZE,
            now: SIZE + 1
        }
    );
}

#[tokio::test]
async fn a_file_written_since_is_refused() {
    let (_, change) = refused(Seen {
        modified: FileTime(WRITTEN.0 + 1),
        ..UNCHANGED
    })
    .await;
    assert_eq!(change, FileChange::Modified);
}

/// Samba holds the last-write time back while a writer is open; the change
/// time moves with the write.
#[tokio::test]
async fn a_file_whose_change_time_moved_is_refused() {
    let (_, change) = refused(Seen {
        changed: FileTime(WRITTEN.0 + 1),
        ..UNCHANGED
    })
    .await;
    assert_eq!(change, FileChange::Modified);
}

#[tokio::test]
async fn a_file_that_is_gone_reports_not_found() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    let checkpoint = one_chunk_in(&mock, &tree, &mut conn).await;
    reconnect(&conn);

    mock.queue_response(build_reader_open_refused(NtStatus::OBJECT_NAME_NOT_FOUND));
    let err = tree
        .resume_download(&mut conn, &checkpoint)
        .await
        .err()
        .unwrap();

    assert_eq!(err.kind(), ErrorKind::NotFound, "{err}");
}

/// A checkpoint past the end of the version it names was never handed out
/// by a download, so it's refused before anything is sent.
#[tokio::test]
async fn a_checkpoint_past_the_files_end_is_refused_unsent() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    let mut checkpoint = one_chunk_in(&mock, &tree, &mut conn).await;
    checkpoint.offset = SIZE + 1;
    let sent = mock.sent_count();

    let err = tree
        .resume_download(&mut conn, &checkpoint)
        .await
        .err()
        .unwrap();

    assert_eq!(err.kind(), ErrorKind::Io, "{err}");
    assert_eq!(mock.sent_count(), sent);
}

/// Resuming at the very end is a download with nothing left: its first
/// call collects the CLOSE and returns `None`.
#[tokio::test]
async fn a_resume_at_the_end_reads_nothing_and_closes() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = connection(&mock);
    let tree = share();
    let mut checkpoint = one_chunk_in(&mock, &tree, &mut conn).await;
    checkpoint.offset = SIZE;
    let reads = sent_reads(&mock).len();

    mock.queue_response(opened(file(2), UNCHANGED));
    mock.queue_response(build_close_response());
    let mut resumed = tree.resume_download(&mut conn, &checkpoint).await.unwrap();

    assert!(resumed.next_chunk().await.is_none());
    assert_eq!(sent_reads(&mock).len(), reads);
    assert_eq!(sent_commands(&mock).last(), Some(&Command::Close));
}

#[cfg(feature = "serde")]
#[test]
fn a_checkpoint_round_trips_through_json() {
    let checkpoint = DownloadCheckpoint {
        path: PATH.to_string(),
        offset: 42,
        version: crate::client::stream::FileVersion {
            size: SIZE,
            modified: WRITTEN,
            changed: WRITTEN,
            identity: Some(OURS),
        },
    };
    let json = serde_json::to_string(&checkpoint).unwrap();
    assert_eq!(
        serde_json::from_str::<DownloadCheckpoint>(&json).unwrap(),
        checkpoint
    );
}
