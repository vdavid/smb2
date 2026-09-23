//! `FileDownload` against a mock server: delivery order, short reads, EOF,
//! errors, the window bound, cancel safety, and the adaptive window's timing.
//!
//! The mock answers READs in the order they were sent (FIFO pairing), so a
//! test controls what each READ gets by the order it queues responses. Tests
//! about timing run on tokio's paused clock, so "the READ took a second" is
//! exact and costs no wall time.

use std::sync::Arc;
use std::time::Duration;

use crate::client::stream::{FileDownload, ReadAhead};
use crate::client::test_helpers::{
    build_close_response, build_read_error_response, build_read_response, setup_connection,
    setup_connection_with_max_read,
};
use crate::client::tree::Tree;
use crate::msg::header::Header;
use crate::msg::read::ReadRequest;
use crate::pack::{ReadCursor, Unpack};
use crate::transport::MockTransport;
use crate::types::status::NtStatus;
use crate::types::{Command, FileId, TreeId};
use crate::Error;

const CHUNK: u32 = 65536;

fn test_tree() -> Tree {
    Tree {
        tree_id: TreeId(10),
        share_name: "test".to_string(),
        server: "test-server".to_string(),
        is_dfs: false,
        encrypt_data: false,
        dfs_origin: None,
    }
}

fn test_file_id() -> FileId {
    FileId {
        persistent: 0xAA,
        volatile: 0xBB,
    }
}

/// Offsets and lengths of every READ the mock saw, in send order.
fn sent_reads(mock: &MockTransport) -> Vec<(u64, u32)> {
    mock.sent_messages()
        .iter()
        .filter_map(|bytes| {
            let header = Header::unpack(&mut ReadCursor::new(bytes)).ok()?;
            if header.command != Command::Read {
                return None;
            }
            ReadRequest::unpack(&mut ReadCursor::new(&bytes[Header::SIZE..]))
                .ok()
                .map(|r| (r.offset, r.length))
        })
        .collect()
}

fn chunk_of(i: u8) -> Vec<u8> {
    vec![i; CHUNK as usize]
}

// ── Fixed windows ──────────────────────────────────────────────────────

#[tokio::test]
async fn read_ahead_delivers_chunks_in_file_order() {
    let mock = Arc::new(MockTransport::new());
    for i in 1..=4u8 {
        mock.queue_response(build_read_response(chunk_of(i)));
    }
    mock.queue_response(build_close_response());

    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 4 * 65536, CHUNK)
        .with_read_ahead(ReadAhead::Fixed(4));

    let mut chunks = Vec::new();
    while let Some(chunk) = download.next_chunk().await {
        chunks.push(chunk.unwrap());
    }
    assert_eq!(download.peak_in_flight_bytes(), 4 * 65536);
    drop(download);

    assert_eq!(chunks, (1..=4u8).map(chunk_of).collect::<Vec<_>>());
    assert_eq!(
        sent_reads(&mock),
        vec![(0, CHUNK), (65536, CHUNK), (131072, CHUNK), (196608, CHUNK)]
    );
    // 4 READs + CLOSE.
    assert_eq!(mock.sent_count(), 5);
}

#[tokio::test]
async fn read_ahead_short_read_rerequests_remainder_before_later_chunks() {
    let mock = Arc::new(MockTransport::new());
    // FIFO pairing: READ@0 gets 32 KiB of 1s, READ@64K gets 64 KiB of 2s,
    // the remainder READ@32K gets 32 KiB of 3s.
    mock.queue_response(build_read_response(vec![1u8; 32768]));
    mock.queue_response(build_read_response(vec![2u8; 65536]));
    mock.queue_response(build_read_response(vec![3u8; 32768]));
    mock.queue_response(build_close_response());

    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 2 * 65536, CHUNK)
        .with_read_ahead(ReadAhead::Fixed(2));

    let mut chunks = Vec::new();
    while let Some(chunk) = download.next_chunk().await {
        chunks.push(chunk.unwrap());
    }
    assert_eq!(download.bytes_received(), 2 * 65536);
    drop(download);

    assert_eq!(
        chunks,
        vec![vec![1u8; 32768], vec![3u8; 32768], vec![2u8; 65536]]
    );
    assert_eq!(
        sent_reads(&mock),
        vec![(0, CHUNK), (65536, CHUNK), (32768, 32768)]
    );
}

#[tokio::test]
async fn read_ahead_end_of_file_mid_window_stops_and_closes() {
    let mock = Arc::new(MockTransport::new());
    mock.queue_response(build_read_response(chunk_of(1)));
    mock.queue_response(build_read_error_response(NtStatus::END_OF_FILE));
    mock.queue_response(build_read_error_response(NtStatus::END_OF_FILE));
    mock.queue_response(build_close_response());

    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 3 * 65536, CHUNK)
        .with_read_ahead(ReadAhead::Fixed(3));

    assert_eq!(download.next_chunk().await.unwrap().unwrap(), chunk_of(1));
    assert!(download.next_chunk().await.is_none());
    assert!(download.next_chunk().await.is_none());
    drop(download);

    // 3 READs + 1 CLOSE, and nothing after.
    assert_eq!(sent_reads(&mock).len(), 3);
    assert_eq!(mock.sent_count(), 4);
}

#[tokio::test]
async fn read_ahead_error_stops_without_more_reads() {
    let mock = Arc::new(MockTransport::new());
    mock.queue_response(build_read_error_response(NtStatus::ACCESS_DENIED));
    mock.queue_response(build_read_response(chunk_of(2)));

    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 4 * 65536, CHUNK)
        .with_read_ahead(ReadAhead::Fixed(2));

    assert!(matches!(
        download.next_chunk().await,
        Some(Err(Error::Protocol {
            status: NtStatus::ACCESS_DENIED,
            command: Command::Read,
        }))
    ));
    assert!(download.next_chunk().await.is_none());
    drop(download);
    assert_eq!(sent_reads(&mock).len(), 2);
}

#[tokio::test]
async fn read_ahead_window_bounds_reads_in_flight() {
    let mock = Arc::new(MockTransport::new());
    for i in 1..=6u8 {
        mock.queue_response(build_read_response(chunk_of(i)));
    }
    mock.queue_response(build_close_response());

    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 6 * 65536, CHUNK)
        .with_read_ahead(ReadAhead::Fixed(2));

    assert_eq!(download.next_chunk().await.unwrap().unwrap(), chunk_of(1));
    // Two sent up front, one more after the first delivery.
    assert_eq!(sent_reads(&mock).len(), 3);
    assert_eq!(download.peak_in_flight_bytes(), 2 * 65536);
    let mut n = 1;
    while let Some(chunk) = download.next_chunk().await {
        n += 1;
        assert_eq!(chunk.unwrap(), chunk_of(n));
    }
    assert_eq!(n, 6);
}

// ── Whatever the policy ────────────────────────────────────────────────

#[tokio::test]
async fn a_file_that_fits_one_chunk_costs_one_read() {
    for policy in [
        ReadAhead::Adaptive,
        ReadAhead::SEQUENTIAL,
        ReadAhead::Fixed(8),
    ] {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_read_response(vec![7u8; 1000]));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();
        let data = FileDownload::new(&tree, &mut conn, test_file_id(), 1000, CHUNK)
            .with_read_ahead(policy)
            .collect()
            .await
            .unwrap();

        assert_eq!(data, vec![7u8; 1000]);
        assert_eq!(sent_reads(&mock), vec![(0, 1000)], "{policy:?}");
        // READ + CLOSE.
        assert_eq!(mock.sent_count(), 2, "{policy:?}");
    }
}

#[tokio::test]
async fn dropping_next_chunk_while_a_read_is_out_loses_nothing() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 3 * 65536, CHUNK)
        .with_read_ahead(ReadAhead::Fixed(2));

    // A `select!` arm losing: the future goes away with two READs out.
    let first = tokio::time::timeout(Duration::from_millis(50), download.next_chunk()).await;
    assert!(first.is_err(), "nothing was answered yet");
    assert_eq!(sent_reads(&mock).len(), 2);

    for i in 1..=3u8 {
        mock.queue_response(build_read_response(chunk_of(i)));
    }
    mock.queue_response(build_close_response());
    let mut chunks = Vec::new();
    while let Some(chunk) = download.next_chunk().await {
        chunks.push(chunk.unwrap());
    }
    // Still in order and complete, with no READ sent twice.
    assert_eq!(chunks, (1..=3u8).map(chunk_of).collect::<Vec<_>>());
    assert_eq!(sent_reads(&mock).len(), 3);
}

#[tokio::test]
async fn dropping_next_chunk_during_the_close_still_hands_out_the_last_chunk() {
    let mock = Arc::new(MockTransport::new());
    // The READ is answered; the CLOSE isn't, yet.
    mock.queue_response(build_read_response(chunk_of(1)));

    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 65536, CHUNK)
        .with_read_ahead(ReadAhead::SEQUENTIAL);

    let first = tokio::time::timeout(Duration::from_millis(50), download.next_chunk()).await;
    assert!(first.is_err(), "the CLOSE is still waiting for its answer");

    // Pre-fix, the chunk was already counted and gone: this returned `None`,
    // and the file came out one chunk short with no error anywhere.
    assert_eq!(download.next_chunk().await.unwrap().unwrap(), chunk_of(1));
    assert!(download.next_chunk().await.is_none());
}

// ── Adaptive window ────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn adaptive_sends_one_read_until_the_first_answer() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = setup_connection(&mock);
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 4 * 65536, CHUNK);
    assert_eq!(download.read_ahead(), ReadAhead::Adaptive);

    let first = tokio::time::timeout(Duration::from_millis(500), download.next_chunk()).await;
    assert!(first.is_err());
    assert_eq!(
        sent_reads(&mock).len(),
        1,
        "nothing is measured yet, and on a slow link a second READ doubles the queue"
    );
}

#[tokio::test(start_paused = true)]
async fn adaptive_opens_the_window_to_4_mib_on_a_fast_link() {
    const BIG: u32 = 512 * 1024;
    let mock = Arc::new(MockTransport::new());
    for i in 1..=16u8 {
        mock.queue_response(build_read_response(vec![i; BIG as usize]));
    }
    mock.queue_response(build_close_response());

    let mut conn = setup_connection_with_max_read(&mock, 8 << 20);
    conn.set_estimated_rtt(Some(Duration::from_millis(1)));
    let tree = test_tree();
    let mut download =
        FileDownload::new(&tree, &mut conn, test_file_id(), 16 * u64::from(BIG), BIG);

    // The paused clock makes the first READ instant: as fast as a link gets.
    assert_eq!(download.next_chunk().await.unwrap().unwrap()[0], 1);
    assert_eq!(
        sent_reads(&mock).len(),
        9,
        "one delivered, then eight 512 KiB READs: the 4 MiB cap"
    );
    let mut n = 1u8;
    while let Some(chunk) = download.next_chunk().await {
        n += 1;
        assert_eq!(chunk.unwrap(), vec![n; BIG as usize]);
    }
    assert_eq!(n, 16);
    assert_eq!(download.peak_in_flight_bytes(), 4 << 20);
}

#[tokio::test(start_paused = true)]
async fn adaptive_sends_the_next_read_shortly_before_the_head_lands_on_a_slow_link() {
    let mock = Arc::new(MockTransport::new());
    let mut conn = setup_connection(&mock);
    conn.set_estimated_rtt(Some(Duration::ZERO));
    let tree = test_tree();
    let mut download = FileDownload::new(&tree, &mut conn, test_file_id(), 4 * 65536, CHUNK);

    // READ 1 takes a second: a 64 KiB/s link.
    let first = tokio::time::timeout(Duration::from_secs(1), download.next_chunk()).await;
    assert!(first.is_err());
    mock.queue_response(build_read_response(chunk_of(1)));
    assert_eq!(download.next_chunk().await.unwrap().unwrap(), chunk_of(1));

    // One READ goes straight out. The target is 250 ms at 64 KiB/s (16 KiB),
    // so the next one is due once 48 KiB of it have drained: 0.75 s later.
    assert_eq!(sent_reads(&mock).len(), 2);
    let early = tokio::time::timeout(Duration::from_millis(700), download.next_chunk()).await;
    assert!(early.is_err());
    assert_eq!(sent_reads(&mock).len(), 2, "not due yet");
    let due = tokio::time::timeout(Duration::from_millis(100), download.next_chunk()).await;
    assert!(due.is_err());
    assert_eq!(
        sent_reads(&mock).len(),
        3,
        "sent while still waiting for the head, so the link never idles"
    );

    for i in 2..=4u8 {
        mock.queue_response(build_read_response(chunk_of(i)));
    }
    mock.queue_response(build_close_response());
    let mut n = 1u8;
    while let Some(chunk) = download.next_chunk().await {
        n += 1;
        assert_eq!(chunk.unwrap(), chunk_of(n));
    }
    assert_eq!(n, 4);
    assert_eq!(
        sent_reads(&mock),
        vec![(0, CHUNK), (65536, CHUNK), (131072, CHUNK), (196608, CHUNK)]
    );
}
