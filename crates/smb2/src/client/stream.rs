//! Streaming file I/O with progress reporting.
//!
//! Provides [`FileDownload`] for memory-efficient large file downloads,
//! [`FileReader`] for random-access positioned reads over one open handle,
//! [`FileUpload`] for streaming uploads with progress,
//! [`FileWriter`] for push-based pipelined writes (use
//! [`FileWriter::finish`] for normal completion, [`FileWriter::abort`] for
//! fast cancellation), and [`Progress`] for tracking transfer progress.

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::sync::Arc;

use futures_util::future::{select, Either};
use log::{debug, trace};
use tokio::time::Instant;

use crate::client::connection::{
    reserve_write_budget_or_drain, Connection, Frame, WaiterGuard, WriteBudgetStep,
};
use crate::client::credits;
use crate::client::read_ahead::{Dispatch, LinkHint, Window};
pub use crate::client::read_ahead::{ReadAhead, DOWNLOAD_CHUNK_SIZE};
use crate::client::tree::{close_outcome, Tree};
use crate::error::Result;
use crate::msg::create::CreateDisposition;
use crate::msg::read::{ReadRequest, ReadResponse, SMB2_CHANNEL_NONE};
use crate::msg::write::{WriteRequest, WriteResponse};
use crate::pack::{ReadCursor, Unpack};
use crate::types::status::NtStatus;
use crate::types::{Command, CreditCharge, FileId};
use crate::Error;

/// Maximum number of pipelined write requests in flight.
/// Matches `MAX_PIPELINE_WINDOW` in `tree.rs`.
const MAX_PIPELINE_WINDOW: usize = 32;

/// Progress information for a file transfer.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Total file size (if known).
    pub total_bytes: Option<u64>,
}

impl Progress {
    /// Progress as a percentage (0.0 to 100.0).
    #[must_use]
    pub fn percent(&self) -> f64 {
        self.fraction() * 100.0
    }

    /// Progress as a fraction (0.0 to 1.0).
    #[must_use]
    pub fn fraction(&self) -> f64 {
        match self.total_bytes {
            Some(total) if total > 0 => self.bytes_transferred as f64 / total as f64,
            Some(_) => 1.0, // Empty file is "complete"
            None => 0.0,
        }
    }
}

/// An in-progress file download that yields chunks without buffering
/// the entire file in memory.
///
/// Chunks come back in file order, one per
/// [`next_chunk`](FileDownload::next_chunk). Underneath, several READs can be
/// on the wire at once: by default the download sizes that window to the link
/// ([`ReadAhead::Adaptive`]), so a fast link stays full while a slow one
/// queues no more than about one chunk ahead of anything else on the
/// connection. [`with_read_ahead`](Self::with_read_ahead) pins it instead. A
/// file that fits one chunk costs exactly one READ.
///
/// At most [`ADAPTIVE_MAX_IN_FLIGHT`](crate::client::read_ahead::ADAPTIVE_MAX_IN_FLIGHT)
/// bytes (4 MiB) are requested but undelivered at a time, so that is also what
/// one download buffers at most.
///
/// `next_chunk` is cancel-safe: dropping its future (a `select!` arm losing)
/// loses no data, and the next call picks up where it left off. The CLOSE goes
/// out as the last chunk arrives, so a download dropped after its last chunk
/// has closed its handle; one dropped before that leaves the handle open until
/// the session ends (there is no async drop).
///
/// # Example
///
/// ```ignore
/// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// use tokio::io::AsyncWriteExt;
///
/// let mut download = client.download(&share, "big_video.mp4").await?;
/// println!("Downloading {} bytes...", download.size());
///
/// let mut file = tokio::fs::File::create("big_video.mp4").await?;
/// while let Some(chunk) = download.next_chunk().await {
///     let bytes = chunk?;
///     file.write_all(&bytes).await?;
///     println!("{:.1}%", download.progress().percent());
/// }
/// # Ok(())
/// # }
/// ```
pub struct FileDownload<'a> {
    tree: &'a Tree,
    conn: &'a mut Connection,
    file_id: FileId,
    file_size: u64,
    bytes_received: u64,
    chunk_size: u32,
    done: bool,
    read_ahead: ReadAhead,
    /// Built on the first READ, so the builder methods can still change what
    /// it's built from.
    window: Option<Window>,
    /// Offset of the next READ to request.
    next_offset: u64,
    /// Requested READs in offset order. Chunks are delivered from the front,
    /// so a response that lands early waits in its guard.
    in_flight: VecDeque<InFlightRead>,
    /// Bytes requested but not yet delivered.
    in_flight_bytes: u64,
    peak_in_flight_bytes: u64,
    /// A chunk already taken off the wire but not yet handed out. It waits
    /// here across the awaits that follow a delivery (the next READs, the
    /// CLOSE), so a caller that drops `next_chunk` there gets it on the next
    /// call rather than losing it.
    ready: Option<Vec<u8>>,
    /// The CLOSE, once it's on the wire and until its answer is collected.
    /// Sent as the last chunk lands, so handing that chunk out never waits a
    /// round trip for it; the `None` call after the last chunk collects it.
    closing: Option<WaiterGuard>,
    /// Why the CLOSE couldn't be sent, held for the `None` call so the last
    /// chunk, whose data is good, is still handed out.
    close_failed: Option<Error>,
}

/// One requested READ of a [`FileDownload`].
///
/// Dropping it drops the [`WaiterGuard`], which deregisters the waiter; the
/// late response is then discarded by the receiver task (its credits still
/// bank).
struct InFlightRead {
    offset: u64,
    len: u32,
    /// `None` for the remainder of a short read, until it's sent.
    guard: Option<WaiterGuard>,
    dispatched_at: Instant,
}

impl<'a> FileDownload<'a> {
    /// Create a new streaming download from an already-opened file handle.
    ///
    /// Most callers want [`SmbClient::download`](crate::SmbClient::download) or
    /// [`Tree::download`](crate::Tree::download), which issue the CREATE
    /// themselves and wrap the resulting handle. Use this constructor when
    /// you've already opened the file via [`Tree::open_file`] (for example,
    /// to reuse a handle across multiple readers, or to build a custom
    /// chunk loop with non-default `chunk_size`).
    ///
    /// `chunk_size` must not exceed the server's `MaxReadSize`. The download
    /// uses [`ReadAhead::Adaptive`] unless told otherwise.
    ///
    /// The caller is responsible for making sure `file_id` belongs to `tree`
    /// and was opened with read access. The `FileDownload` will CLOSE the
    /// handle when the last chunk arrives.
    pub fn new(
        tree: &'a Tree,
        conn: &'a mut Connection,
        file_id: FileId,
        file_size: u64,
        chunk_size: u32,
    ) -> Self {
        Self {
            tree,
            conn,
            file_id,
            file_size,
            bytes_received: 0,
            chunk_size: chunk_size.max(1),
            done: false,
            read_ahead: ReadAhead::default(),
            window: None,
            next_offset: 0,
            in_flight: VecDeque::new(),
            in_flight_bytes: 0,
            peak_in_flight_bytes: 0,
            ready: None,
            closing: None,
            close_failed: None,
        }
    }

    /// Choose how many READs to keep on the wire. See [`ReadAhead`].
    ///
    /// Takes effect from the next READ sent; meant to be called before the
    /// first [`next_chunk`](Self::next_chunk).
    #[must_use]
    pub fn with_read_ahead(mut self, read_ahead: ReadAhead) -> Self {
        self.read_ahead = read_ahead;
        self.window = None;
        self
    }

    /// Change how many bytes each READ asks for. It must not exceed the
    /// server's `MaxReadSize`.
    ///
    /// Takes effect from the next READ sent; meant to be called before the
    /// first [`next_chunk`](Self::next_chunk).
    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: u32) -> Self {
        self.chunk_size = chunk_size.max(1);
        self.window = None;
        self
    }

    /// The read-ahead policy in use.
    #[must_use]
    pub fn read_ahead(&self) -> ReadAhead {
        self.read_ahead
    }

    /// Bytes each READ asks for.
    #[must_use]
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// The most bytes this download has had requested but not yet delivered
    /// at once. A gauge for tuning; it's also the most it buffered.
    #[must_use]
    pub fn peak_in_flight_bytes(&self) -> u64 {
        self.peak_in_flight_bytes
    }

    /// Total file size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.file_size
    }

    /// Bytes received so far.
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Current transfer progress.
    #[must_use]
    pub fn progress(&self) -> Progress {
        Progress {
            bytes_transferred: self.bytes_received,
            total_bytes: Some(self.file_size),
        }
    }

    /// Get the next chunk of data from the server.
    ///
    /// Returns `None` when the download is complete. Chunks come in file
    /// order and are at most the chunk size; a short read from the server
    /// shows up as a shorter chunk. After an error, the download is over:
    /// every later call returns `None`, and the handle is left open (the
    /// connection may be what failed).
    ///
    /// The CLOSE goes out as the last chunk lands, and the last chunk is handed
    /// out without waiting for its answer. The call after the last chunk
    /// collects that answer: it returns `None`, or `Some(Err(_))` if the CLOSE
    /// failed. A caller that stops at the last byte instead (dropping the
    /// download without that call) still gets the handle closed, since the
    /// server acts on the CLOSE either way; only a CLOSE error goes unseen.
    ///
    /// Cancel-safe: if this future is dropped before it completes, no data is
    /// lost and the next call continues the download.
    pub async fn next_chunk(&mut self) -> Option<Result<Vec<u8>>> {
        if self.ready.is_none() {
            if self.closing.is_some() || self.close_failed.is_some() {
                return self.finish_close().await.err().map(Err);
            }
            if self.done {
                return None;
            }
            match self.receive_next().await {
                Ok(Some(data)) => self.ready = Some(data),
                Ok(None) => return self.close().await.err().map(Err),
                Err(e) => return Some(Err(self.fail(e))),
            }
        }
        // Keep the wire busy while the caller works on this chunk, or send
        // the CLOSE if it was the last. The chunk waits in `ready` meanwhile.
        let all_delivered = self.in_flight.is_empty() && self.next_offset >= self.file_size;
        if all_delivered {
            if let Err(e) = self.start_close().await {
                self.close_failed = Some(e);
            }
        } else if let Err(e) = self.send_reads().await {
            self.ready = None;
            return Some(Err(self.fail(e)));
        }
        self.ready.take().map(Ok)
    }

    /// Wait for the chunk at the front, sending READs as the window allows
    /// meanwhile. `Ok(None)` means there's nothing left to receive.
    async fn receive_next(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let send_at = self.send_reads().await?;
            let Some(head) = self.in_flight.front_mut() else {
                return Ok(None);
            };
            let guard = head
                .guard
                .as_mut()
                .expect("send_reads sends the head before anything behind it");
            let waiting = self.conn.await_response_in_place(guard, Command::Read);
            let frame = match send_at {
                None => waiting.await?,
                Some(at) => {
                    let timer = std::pin::pin!(tokio::time::sleep_until(at));
                    match select(std::pin::pin!(waiting), timer).await {
                        Either::Left((frame, _)) => frame?,
                        // The next READ is due before the head has landed.
                        // The head's response keeps waiting in its guard.
                        Either::Right(_) => continue,
                    }
                }
            };
            return self.take_head(frame);
        }
    }

    /// Send every READ the window allows right now. Returns when the next one
    /// is due, if that's a time rather than "after the head is delivered".
    async fn send_reads(&mut self) -> Result<Option<Instant>> {
        // The rest of a short read goes out first: it's the next chunk due.
        if let Some(front) = self.in_flight.front_mut() {
            if front.guard.is_none() {
                let guard =
                    send_read(self.conn, self.tree, self.file_id, front.offset, front.len).await?;
                let now = Instant::now();
                front.guard = Some(guard);
                front.dispatched_at = now;
                let len = front.len;
                self.window().on_dispatch(now, len);
            }
        }
        loop {
            if self.next_offset >= self.file_size {
                return Ok(None);
            }
            let chunk = self.conn.fundable_chunk(self.chunk_size);
            let len = (self.file_size - self.next_offset).min(u64::from(chunk)) as u32;
            let (reads, bytes) = (self.in_flight.len(), self.in_flight_bytes);
            match self.window().decide(Instant::now(), reads, bytes, len) {
                Dispatch::Now => {}
                Dispatch::At(at) => return Ok(Some(at)),
                Dispatch::AfterHead => return Ok(None),
            }
            let offset = self.next_offset;
            let guard = send_read(self.conn, self.tree, self.file_id, offset, len).await?;
            let now = Instant::now();
            self.in_flight.push_back(InFlightRead {
                offset,
                len,
                guard: Some(guard),
                dispatched_at: now,
            });
            self.next_offset += u64::from(len);
            self.in_flight_bytes += u64::from(len);
            self.peak_in_flight_bytes = self.peak_in_flight_bytes.max(self.in_flight_bytes);
            self.window().on_dispatch(now, len);
        }
    }

    /// Take the head READ's response off the queue. Synchronous on purpose:
    /// from here to handing the chunk out, nothing may be interrupted.
    fn take_head(&mut self, frame: Frame) -> Result<Option<Vec<u8>>> {
        let head = self
            .in_flight
            .pop_front()
            .expect("only called with the head's response");
        self.in_flight_bytes -= u64::from(head.len);

        if frame.header.status == NtStatus::END_OF_FILE {
            // The file shrank since the CREATE. Nothing past here exists.
            self.stop_at_eof();
            return Ok(None);
        }
        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Read,
            });
        }
        let mut data = ReadResponse::unpack(&mut ReadCursor::new(&frame.body))?.data;
        if data.is_empty() {
            self.stop_at_eof();
            return Ok(None);
        }
        data.truncate(head.len as usize);
        let got = data.len() as u32;
        if got < head.len {
            // Short read: the rest is the next chunk due, ahead of anything
            // already requested. `send_reads` sends it.
            let rest = head.len - got;
            self.in_flight.push_front(InFlightRead {
                offset: head.offset + u64::from(got),
                len: rest,
                guard: None,
                dispatched_at: head.dispatched_at,
            });
            self.in_flight_bytes += u64::from(rest);
        }
        self.bytes_received += u64::from(got);
        let in_flight_bytes = self.in_flight_bytes;
        let window = self.window();
        window.on_delivery(Instant::now(), head.dispatched_at, got, in_flight_bytes);
        if let Some(rate) = window.rate_to_share() {
            self.conn.note_read_rate(rate);
        }
        Ok(Some(data))
    }

    fn window(&mut self) -> &mut Window {
        let (read_ahead, chunk) = (self.read_ahead, self.chunk_size);
        let conn = &*self.conn;
        self.window.get_or_insert_with(|| {
            let hint = LinkHint {
                rtt: conn.estimated_rtt(),
                rate: conn.read_rate_hint(),
            };
            Window::new(read_ahead, chunk, hint)
        })
    }

    /// Nothing past this point exists: drop what's still requested (the
    /// responses are discarded as they land) and ask for nothing more.
    fn stop_at_eof(&mut self) {
        self.abandon_in_flight();
        self.next_offset = self.file_size;
    }

    /// Stop on an error: no more chunks, and no CLOSE (the connection may be
    /// the thing that failed).
    fn fail(&mut self, e: Error) -> Error {
        self.abandon_in_flight();
        self.done = true;
        e
    }

    fn abandon_in_flight(&mut self) {
        self.in_flight.clear();
        self.in_flight_bytes = 0;
    }

    /// Consume the download and collect all data with a progress callback.
    ///
    /// Return `ControlFlow::Break(())` from the callback to cancel the download.
    /// Cancellation returns `Error::Cancelled`.
    pub async fn collect_with_progress<F>(mut self, mut on_progress: F) -> Result<Vec<u8>>
    where
        F: FnMut(Progress) -> ControlFlow<()>,
    {
        let mut data = Vec::with_capacity(self.file_size as usize);

        while let Some(result) = self.next_chunk().await {
            let chunk = result?;
            data.extend_from_slice(&chunk);

            if let ControlFlow::Break(()) = on_progress(self.progress()) {
                // Best-effort close before returning.
                let _ = self.close().await;
                return Err(Error::Cancelled);
            }
        }

        Ok(data)
    }

    /// Consume the download and collect all data into a `Vec<u8>`.
    pub async fn collect(mut self) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(self.file_size as usize);

        while let Some(result) = self.next_chunk().await {
            let chunk = result?;
            data.extend_from_slice(&chunk);
        }

        Ok(data)
    }

    /// Close the file handle and wait for the answer.
    async fn close(&mut self) -> Result<()> {
        self.start_close().await?;
        self.finish_close().await
    }

    /// Put the CLOSE on the wire, without waiting for its answer. Only ever
    /// sends one: `done` is set first, so a caller dropped mid-send doesn't
    /// send a second (the handle then stays open, as with any dropped
    /// download).
    async fn start_close(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        // Any READs still out were sent before the CLOSE, so the server
        // answers them first; their responses are discarded once the guards
        // drop here.
        self.abandon_in_flight();
        let guard = self.tree.dispatch_close(self.conn, self.file_id).await?;
        self.closing = Some(guard);
        Ok(())
    }

    /// Collect the CLOSE's answer, if one is out. Cancel-safe: the guard stays
    /// in `closing` until the answer is in.
    async fn finish_close(&mut self) -> Result<()> {
        if let Some(e) = self.close_failed.take() {
            return Err(e);
        }
        let Some(guard) = self.closing.as_mut() else {
            return Ok(());
        };
        let answer = self
            .conn
            .await_response_in_place(guard, Command::Close)
            .await;
        self.closing = None;
        close_outcome(&answer?)
    }
}

/// Send one READ and return its guard, once it's on the wire.
async fn send_read(
    conn: &Connection,
    tree: &Tree,
    file_id: FileId,
    offset: u64,
    len: u32,
) -> Result<WaiterGuard> {
    let req = ReadRequest {
        padding: 0x50,
        flags: 0,
        length: len,
        offset,
        file_id,
        minimum_count: 0,
        channel: SMB2_CHANNEL_NONE,
        remaining_bytes: 0,
        read_channel_info: vec![],
    };
    conn.dispatch_with_credits(
        Command::Read,
        &req,
        Some(tree.tree_id),
        CreditCharge(credits::charge_for_payload(u64::from(len))),
    )
    .await
}

impl Drop for FileDownload<'_> {
    fn drop(&mut self) {
        if !self.done {
            debug!(
                "stream: FileDownload dropped before completion, file handle may leak \
                 (bytes_received={}/{})",
                self.bytes_received, self.file_size
            );
            // We can't close the handle in Drop because it's async.
            // The caller should consume the download fully or call close().
        }
    }
}

/// A random-access reader over one open file handle.
///
/// Where [`FileDownload`] streams a file front-to-back (one chunk in memory,
/// forward only), `FileReader` holds the handle open and serves any number of
/// *positioned* reads at arbitrary offsets — the SMB analog of `pread`. It's the
/// right primitive for a consumer that parses a file's structure by jumping
/// around it (a zip's end-of-central-directory near the tail, then the central
/// directory before it, then member data mid-file), all over a SINGLE
/// open → N reads → close handle lifecycle rather than one open per read.
///
/// Owns a cheap `Arc::clone` of [`Connection`] and an `Arc<Tree>`, so it's
/// `'static` — move it across tasks or hand it to `tokio::spawn`. Because
/// [`read_at`](FileReader::read_at) takes `&self` and holds no shared cursor,
/// concurrent positioned reads over one reader are independent and pipeline over
/// the single SMB session (the receiver task multiplexes responses by
/// `MessageId`).
///
/// Call [`close`](FileReader::close) when done to release the server handle.
/// Like the other stream handles, `Drop` cannot CLOSE (Rust has no async drop),
/// so a reader dropped without `close()` leaks the handle until session teardown
/// and logs a debug warning.
///
/// # Example
///
/// ```no_run
/// # async fn example(client: &smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// let reader = client.open_file_reader(share, "archive.zip").await?;
/// let size = reader.size();
/// // Read the 22-byte end-of-central-directory record at the tail, then jump
/// // to the central directory it points at — two positioned reads, one handle.
/// let eocd = reader.read_at(size.saturating_sub(22), 22).await?;
/// let dir = reader.read_at(0x1000, 512).await?;
/// reader.close().await?;
/// # let _ = (eocd, dir);
/// # Ok(())
/// # }
/// ```
pub struct FileReader {
    tree: Arc<Tree>,
    conn: Connection,
    file_id: FileId,
    file_size: u64,
    max_read: u32,
    resolved_path: Option<String>,
    closed: bool,
}

/// Open a file for reading and return a random-access [`FileReader`] that owns
/// its `Connection` and `Arc<Tree>`.
///
/// Use this when you hold a cloned `Connection` and want to serve many
/// positioned reads over one open handle without holding any external lock.
/// The returned reader is `'static` — it doesn't borrow from anything.
///
/// [`SmbClient::open_file_reader`](crate::SmbClient::open_file_reader) and
/// [`Tree::open_file_reader`] are thin convenience wrappers; reach for them when
/// you already hold an `&SmbClient` or `&Arc<Tree>` and don't need the explicit
/// connection clone.
pub async fn open_file_reader(
    tree: Arc<Tree>,
    mut conn: Connection,
    path: &str,
) -> Result<FileReader> {
    trace!("stream: open_file_reader path={}", path);

    let (created, resolved_path) = tree
        .open_and_name(&mut conn, path, &tree.read_open_request(path), true)
        .await?;
    let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);

    let mut reader = FileReader::new(tree, conn, created.file_id, created.end_of_file, max_read);
    reader.resolved_path = resolved_path;
    Ok(reader)
}

impl FileReader {
    /// Wrap an already-opened read handle. Most callers want
    /// [`open_file_reader`], [`Tree::open_file_reader`], or
    /// [`SmbClient::open_file_reader`](crate::SmbClient::open_file_reader),
    /// which issue the CREATE for you.
    pub(crate) fn new(
        tree: Arc<Tree>,
        conn: Connection,
        file_id: FileId,
        file_size: u64,
        max_read: u32,
    ) -> Self {
        Self {
            tree,
            conn,
            file_id,
            file_size,
            max_read,
            resolved_path: None,
            closed: false,
        }
    }

    /// Total file size in bytes, as seen when the handle was opened.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.file_size
    }

    /// The path the server opened, as it stores it: relative to the share,
    /// `/`-separated, in on-disk casing, with 8.3 aliases replaced by their
    /// long names (see [`Tree::resolve`]). Asked in the same round trip as
    /// the open, so it names exactly the file this handle reads.
    ///
    /// `None` when the server can't name it (SMB 2.x or 3.0.2, or Windows
    /// before 10 / Server v1803); the open itself is unaffected.
    #[must_use]
    pub fn resolved_path(&self) -> Option<&str> {
        self.resolved_path.as_deref()
    }

    /// Read up to `len` bytes starting at `offset`.
    ///
    /// Positioned like `pread`: `offset` is absolute in the file and no cursor
    /// advances, so calls are independent and may run concurrently. Returns
    /// fewer than `len` bytes only at end of file — a read wholly at or past the
    /// end yields an empty `Vec`, and a read that straddles the end is clamped
    /// to what exists. A range larger than the server's `MaxReadSize` is split
    /// into that many wire-level READs and reassembled, so the caller passes the
    /// range it wants without minding the negotiated cap.
    pub async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        // A read at or past EOF yields no bytes; a read overrunning EOF is
        // clamped so we never ask the server for bytes that don't exist (which
        // would come back as STATUS_END_OF_FILE and complicate the loop).
        if len == 0 || offset >= self.file_size {
            return Ok(Vec::new());
        }
        let to_read = len.min(self.file_size - offset);
        let end = offset + to_read;
        let mut out = Vec::with_capacity(to_read as usize);
        let mut pos = offset;

        while pos < end {
            let chunk_len =
                (end - pos).min(u64::from(self.conn.fundable_chunk(self.max_read))) as u32;
            let req = ReadRequest {
                padding: 0x50,
                flags: 0,
                length: chunk_len,
                offset: pos,
                file_id: self.file_id,
                minimum_count: 0,
                channel: SMB2_CHANNEL_NONE,
                remaining_bytes: 0,
                read_channel_info: vec![],
            };

            let credit_charge = credits::charge_for_payload(chunk_len as u64);
            let frame = self
                .conn
                .execute_with_credits(
                    Command::Read,
                    &req,
                    Some(self.tree.tree_id),
                    crate::types::CreditCharge(credit_charge),
                )
                .await?;

            // Even after clamping to the size seen at open, a racing truncation
            // (or a zero-length file) can surface EOF; treat it as a short read.
            if frame.header.status == NtStatus::END_OF_FILE {
                break;
            }
            if frame.header.status != NtStatus::SUCCESS {
                return Err(Error::Protocol {
                    status: frame.header.status,
                    command: Command::Read,
                });
            }

            let mut cursor = ReadCursor::new(&frame.body);
            let resp = ReadResponse::unpack(&mut cursor)?;
            if resp.data.is_empty() {
                break;
            }
            pos += resp.data.len() as u64;
            out.extend_from_slice(&resp.data);
        }

        Ok(out)
    }

    /// Close the file handle, releasing it on the server.
    ///
    /// Consumes `self` so read-after-close is a compile error. Call this on
    /// every reader; a dropped-without-close reader leaks the handle (see the
    /// type-level note).
    pub async fn close(mut self) -> Result<()> {
        self.closed = true;
        self.tree.close_handle(&mut self.conn, self.file_id).await
    }
}

impl Drop for FileReader {
    fn drop(&mut self) {
        if !self.closed {
            debug!(
                "stream: FileReader dropped without close(), file handle may leak \
                 until session teardown"
            );
        }
    }
}

/// An in-progress file upload that writes data in chunks with progress.
///
/// Each call to [`write_next_chunk`](FileUpload::write_next_chunk) sends one
/// SMB2 WRITE request and returns `true` while there is more data to send.
/// When the last chunk is written, the file handle is automatically flushed
/// and closed, and `write_next_chunk` returns `false`.
///
/// The connection is borrowed mutably for the lifetime of the upload,
/// preventing accidental interleaving of SMB messages.
///
/// # Cancellation
///
/// To cancel an upload, stop calling `write_next_chunk`. The file handle
/// will be closed (without flush) when the `FileUpload` is dropped, though
/// this cannot be guaranteed in async contexts since `Drop` is synchronous.
/// For clean cancellation, call `write_next_chunk` in a loop that checks
/// your own cancellation condition.
///
/// # Example
///
/// ```no_run
/// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// let data = std::fs::read("large_video.mp4")?;
/// let mut upload = client.upload(&share, "remote_video.mp4", &data).await?;
/// println!("Uploading {} bytes...", upload.total_bytes());
///
/// while upload.write_next_chunk().await? {
///     println!("{:.1}%", upload.progress().percent());
/// }
/// // File is flushed and closed automatically after the last chunk.
/// # Ok(())
/// # }
/// ```
pub struct FileUpload<'a> {
    tree: &'a Tree,
    conn: &'a mut Connection,
    file_id: FileId,
    data: &'a [u8],
    total_bytes: u64,
    bytes_written: u64,
    chunk_size: u32,
    done: bool,
}

impl<'a> FileUpload<'a> {
    /// Create a streaming upload for a large file (data larger than one chunk).
    ///
    /// Opens the file for writing. The caller then drives the upload with
    /// [`write_next_chunk`](FileUpload::write_next_chunk).
    pub(crate) fn new(
        tree: &'a Tree,
        conn: &'a mut Connection,
        file_id: FileId,
        data: &'a [u8],
        chunk_size: u32,
    ) -> Self {
        Self {
            tree,
            conn,
            file_id,
            data,
            total_bytes: data.len() as u64,
            bytes_written: 0,
            chunk_size,
            done: false,
        }
    }

    /// Create a "done" upload for small files that were already written
    /// via compound in the constructor.
    pub(crate) fn new_done(tree: &'a Tree, conn: &'a mut Connection, total_bytes: u64) -> Self {
        Self {
            tree,
            conn,
            file_id: FileId::SENTINEL,
            data: &[],
            total_bytes,
            bytes_written: total_bytes,
            chunk_size: 0,
            done: true,
        }
    }

    /// Total data size in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Bytes written so far.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Current transfer progress.
    #[must_use]
    pub fn progress(&self) -> Progress {
        Progress {
            bytes_transferred: self.bytes_written,
            total_bytes: Some(self.total_bytes),
        }
    }

    /// Write the next chunk of data to the server.
    ///
    /// Returns `Ok(true)` while there is more data to write, and `Ok(false)`
    /// when the upload is complete. After the last chunk, automatically flushes
    /// and closes the file handle.
    ///
    /// For small files that were written via compound in the constructor,
    /// this immediately returns `Ok(false)`.
    pub async fn write_next_chunk(&mut self) -> Result<bool> {
        if self.done {
            return Ok(false);
        }

        let offset = self.bytes_written as usize;
        if offset >= self.data.len() {
            // All data written -- flush and close.
            self.flush_and_close().await?;
            return Ok(false);
        }

        let remaining = self.data.len() - offset;
        let this_chunk = remaining.min(self.conn.fundable_chunk(self.chunk_size) as usize);
        let chunk = &self.data[offset..offset + this_chunk];

        let write_req = WriteRequest {
            data_offset: 0x70,
            offset: offset as u64,
            file_id: self.file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: chunk.to_vec(),
        };

        let credit_charge = credits::charge_for_payload(this_chunk as u64);
        let exec_result = self
            .conn
            .execute_with_credits(
                Command::Write,
                &write_req,
                Some(self.tree.tree_id),
                crate::types::CreditCharge(credit_charge),
            )
            .await;

        match exec_result {
            Err(e) => {
                self.done = true;
                Err(e)
            }
            Ok(frame) => {
                if frame.header.status != NtStatus::SUCCESS {
                    self.done = true;
                    // Best-effort close without flush.
                    let _ = self.tree.close_handle(self.conn, self.file_id).await;
                    return Err(Error::Protocol {
                        status: frame.header.status,
                        command: Command::Write,
                    });
                }

                let mut cursor = ReadCursor::new(&frame.body);
                let resp = WriteResponse::unpack(&mut cursor)?;
                self.bytes_written += resp.count as u64;

                // If all data is written, flush and close.
                if self.bytes_written >= self.total_bytes {
                    self.flush_and_close().await?;
                    return Ok(false);
                }

                Ok(true)
            }
        }
    }

    /// Flush and close the file handle. Only runs once.
    async fn flush_and_close(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;

        // Flush to ensure data is persisted.
        self.tree.flush_handle(self.conn, self.file_id).await?;
        // Close the handle.
        self.tree.close_handle(self.conn, self.file_id).await
    }
}

impl Drop for FileUpload<'_> {
    fn drop(&mut self) {
        if !self.done {
            debug!(
                "stream: FileUpload dropped before completion, file handle may leak \
                 (bytes_written={}/{})",
                self.bytes_written, self.total_bytes
            );
            // We can't close the handle in Drop because it's async.
            // The caller should drive the upload to completion.
        }
    }
}

/// A push-based pipelined streaming file writer.
///
/// The consumer pushes data chunks at their own pace. Writes are pipelined
/// using a sliding window (up to 32 in-flight requests)
/// for high throughput. Chunks larger than `max_write_size` are split
/// internally into wire-level WRITE requests.
///
/// Call [`finish`](FileWriter::finish) when done to flush, close the handle,
/// and get the total confirmed byte count.
///
/// # Example
///
/// ```no_run
/// # async fn example(client: &smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// let mut writer = client.create_file_writer(share, "output.bin").await?;
/// writer.write_chunk(b"first part").await?;
/// writer.write_chunk(b"second part").await?;
/// let total = writer.finish().await?;
/// println!("Wrote {total} bytes");
/// # Ok(())
/// # }
/// ```
/// Pinned-boxed `execute_with_credits` future, kept owned by `FileWriter`
/// in a `FuturesUnordered` so multiple WRITEs can be in flight on one
/// connection concurrently.
type BoxedWriteFut = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<crate::client::connection::Frame>> + Send>,
>;

/// Push-based streaming writer. Owns its `Connection` and `Arc<Tree>`,
/// so the writer is `'static` and N concurrent writers pipeline over one
/// SMB session without any external locking.
///
/// Both fields are cheap `Arc::clone`s. The receiver task multiplexes
/// responses by `MessageId` so N independent `FileWriter`s can write to
/// different files on the same connection concurrently.
pub struct FileWriter {
    tree: Arc<Tree>,
    conn: Connection,
    file_id: FileId,
    max_write_size: u32,
    /// Next write offset in the file.
    offset: u64,
    /// In-flight WRITE futures. `FuturesUnordered::len()` is the count of
    /// responses still pending.
    in_flight: futures_util::stream::FuturesUnordered<BoxedWriteFut>,
    /// Confirmed bytes (from WRITE responses).
    total_written: u64,
    /// Buffer for leftover data when a push chunk is larger than `max_write_size`.
    pending_data: Vec<u8>,
    /// Read position within `pending_data`.
    pending_offset: usize,
    /// Chunk that was pulled but couldn't be sent due to credit exhaustion.
    stashed_chunk: Option<Vec<u8>>,
    /// Whether the writer has been finalized (handle closed).
    done: bool,
    /// What the server called the file at open, if it said.
    resolved_path: Option<String>,
}

/// Open (or create) a file for writing and return a streaming [`FileWriter`]
/// that owns its `Connection` and `Arc<Tree>`.
///
/// Use this when you hold a cloned `Connection` and want to drive a
/// streaming write without holding any external lock for the upload's
/// duration. The returned writer is `'static` — drop it, move it across
/// tasks, hand it to `tokio::spawn`, it doesn't borrow from anything.
///
/// Multiple `FileWriter`s built from clones of the same `Connection`
/// pipeline their WRITEs over a single SMB session.
///
/// `SmbClient::create_file_writer` and `Tree::create_file_writer` are
/// thin convenience wrappers around this; reach for them when you already
/// hold an `&SmbClient` or `&Arc<Tree>` and don't need the explicit
/// connection clone.
pub async fn open_file_writer(
    tree: Arc<Tree>,
    mut conn: Connection,
    path: &str,
) -> Result<FileWriter> {
    trace!("stream: open_file_writer path={}", path);

    let (file_id, resolved_path) =
        open_for_writer(&tree, &mut conn, path, CreateDisposition::FileOverwriteIf).await?;
    let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);

    let mut writer = FileWriter::new(tree, conn, file_id, max_write);
    writer.resolved_path = resolved_path;
    Ok(writer)
}

/// Exclusive-create sibling of [`open_file_writer`]. Opens the CREATE with
/// `FileCreate` disposition: if the file already exists the open fails with
/// [`crate::ErrorKind::AlreadyExists`] instead of
/// truncating it.
///
/// `Tree::create_file_writer_exclusive` is the convenience wrapper most
/// callers want.
pub async fn open_file_writer_exclusive(
    tree: Arc<Tree>,
    mut conn: Connection,
    path: &str,
) -> Result<FileWriter> {
    trace!("stream: open_file_writer_exclusive path={}", path);

    let (file_id, resolved_path) =
        open_for_writer(&tree, &mut conn, path, CreateDisposition::FileCreate).await?;
    let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);

    let mut writer = FileWriter::new(tree, conn, file_id, max_write);
    writer.resolved_path = resolved_path;
    Ok(writer)
}

/// Open a file for writing at an arbitrary starting offset, returning a
/// [`FileWriter`] whose first byte lands at `offset`.
///
/// Unlike [`open_file_writer`] (which truncates), this opens with `FileOpenIf`
/// disposition and does *not* truncate: existing content is preserved, and the
/// writer's chunks are written starting at `offset` (overwriting or extending
/// from there). This is the positioned-write analog of
/// [`FileReader`]'s positioned reads — the natural shape for appending after a
/// server-side-copied prefix, or patching a known region of an existing file.
///
/// `bytes_written()` counts bytes this writer confirmed, not the absolute file
/// position. `SmbClient::create_file_writer_at` and `Tree::create_file_writer_at`
/// are thin convenience wrappers.
///
/// # Example
///
/// ```no_run
/// # async fn example(client: &smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// // Append after a 4 KiB prefix already present in the file.
/// let mut writer = client.create_file_writer_at(share, "patched.bin", 4096).await?;
/// writer.write_chunk(b"appended tail").await?;
/// writer.finish().await?;
/// # Ok(())
/// # }
/// ```
pub async fn open_file_writer_at(
    tree: Arc<Tree>,
    mut conn: Connection,
    path: &str,
    offset: u64,
) -> Result<FileWriter> {
    trace!(
        "stream: open_file_writer_at path={} offset={}",
        path,
        offset
    );

    let (file_id, resolved_path) =
        open_for_writer(&tree, &mut conn, path, CreateDisposition::FileOpenIf).await?;
    let max_write = conn.params().map(|p| p.max_write_size).unwrap_or(65536);

    let mut writer = FileWriter::new(tree, conn, file_id, max_write);
    writer.offset = offset;
    writer.resolved_path = resolved_path;
    Ok(writer)
}

/// The CREATE behind every [`FileWriter`], with the server's name for the
/// file asked in the same round trip.
async fn open_for_writer(
    tree: &Tree,
    conn: &mut Connection,
    path: &str,
    disposition: CreateDisposition,
) -> Result<(FileId, Option<String>)> {
    let (created, resolved_path) = tree
        .open_and_name(
            conn,
            path,
            &tree.write_open_request(path, disposition),
            false,
        )
        .await?;
    Ok((created.file_id, resolved_path))
}

impl FileWriter {
    /// Create a new push-based streaming writer.
    ///
    /// Most callers want [`open_file_writer`], [`Tree::create_file_writer`],
    /// or [`SmbClient::create_file_writer`](crate::SmbClient::create_file_writer)
    /// which issue the CREATE for you. Use this constructor when you've
    /// already opened the file via [`Tree::open_file_for_write`] (for
    /// example, to reuse a handle across multiple writers).
    pub(crate) fn new(
        tree: Arc<Tree>,
        conn: Connection,
        file_id: FileId,
        max_write_size: u32,
    ) -> Self {
        Self {
            tree,
            conn,
            file_id,
            max_write_size,
            offset: 0,
            in_flight: futures_util::stream::FuturesUnordered::new(),
            total_written: 0,
            pending_data: Vec::new(),
            pending_offset: 0,
            stashed_chunk: None,
            done: false,
            resolved_path: None,
        }
    }

    /// The path the server opened, as it stores it: relative to the share,
    /// `/`-separated, in on-disk casing, with 8.3 aliases replaced by their
    /// long names (see [`Tree::resolve`]). Asked in the same round trip as
    /// the open, so it names exactly the file this handle writes.
    ///
    /// `None` when the server can't name it (SMB 2.x or 3.0.2, or Windows
    /// before 10 / Server v1803); the open itself is unaffected.
    #[must_use]
    pub fn resolved_path(&self) -> Option<&str> {
        self.resolved_path.as_deref()
    }

    /// Push a data chunk to the writer.
    ///
    /// The data is split into wire-level WRITE requests (each up to
    /// `max_write_size` bytes) and sent pipelined. When the sliding window
    /// is full, this method drains one in-flight response before sending,
    /// providing backpressure.
    ///
    /// Empty chunks are no-ops.
    pub async fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Append to pending buffer. If there's already pending data, extend it;
        // otherwise set the new chunk as pending.
        if self.pending_offset < self.pending_data.len() {
            let leftover = self.pending_data[self.pending_offset..].to_vec();
            self.pending_data = leftover;
            self.pending_offset = 0;
            self.pending_data.extend_from_slice(data);
        } else {
            self.pending_data = data.to_vec();
            self.pending_offset = 0;
        }

        // Flush any stashed chunk from a previous call before processing new data.
        self.flush_stash().await?;

        // Send as many wire chunks as the window allows.
        while let Some(wire_chunk) = self.next_pending_chunk() {
            if !self.send_or_stash(wire_chunk).await? {
                return Ok(()); // Stashed — will be sent on next call or finish()
            }
        }

        Ok(())
    }

    /// Finish the writer: drain all in-flight responses, flush, and close.
    ///
    /// Returns the total number of confirmed bytes written. Consumes `self`
    /// to prevent write-after-close at compile time.
    pub async fn finish(mut self) -> Result<u64> {
        // Flush stash and drain all remaining pending data. Unlike write_chunk,
        // finish() must send everything — it loops send_or_stash until the stash
        // is empty, draining responses to free credits as needed.
        self.flush_stash().await?;

        while let Some(wire_chunk) = self.next_pending_chunk() {
            // send_or_stash may stash if credits are exhausted. Keep flushing
            // until everything is sent. This terminates because drain_one frees
            // a credit, and we have finite data.
            if !self.send_or_stash(wire_chunk).await? {
                self.flush_stash().await?;
            }
        }

        // Drain all in-flight responses.
        self.drain_all().await?;

        // Flush to ensure data is persisted.
        self.tree.flush_handle(&mut self.conn, self.file_id).await?;

        // Close the handle.
        self.tree.close_handle(&mut self.conn, self.file_id).await?;

        self.done = true;
        Ok(self.total_written)
    }

    /// Abort the writer: discard unsent data, drain in-flight responses, and
    /// close the handle without flushing.
    ///
    /// Use this when you want to cancel a write partway through — for example
    /// on user-triggered cancellation or an error path where the partial upload
    /// will be deleted anyway. `abort()` skips the server-side fsync that
    /// [`finish`](FileWriter::finish) does, so it returns as soon as the
    /// in-flight window is drained.
    ///
    /// What it does:
    /// - Discards any buffered (unsent) data. Wire WRITEs already in flight
    ///   still have responses on the way; those are drained to keep credits
    ///   and message-IDs in sync with the server. Errors on those responses
    ///   are swallowed — at this point we don't care.
    /// - Skips the FLUSH that [`finish`](FileWriter::finish) sends before
    ///   CLOSE, so the server does not fsync. This is the main reason to
    ///   prefer `abort()` over `finish()` on cancellation.
    /// - Best-effort CLOSE of the file handle. If the CLOSE fails, the error
    ///   is logged at debug and swallowed.
    ///
    /// Contrast with [`finish`](FileWriter::finish): `finish()` sends every
    /// pending byte, flushes, and propagates errors from the flush/close
    /// paths. `abort()` sends nothing more, never flushes, and returns `Ok`
    /// regardless of what the server said on the way out.
    ///
    /// Returns the number of confirmed bytes written at the moment of abort
    /// (from WRITE responses seen so far). Consumes `self` to prevent
    /// write-after-abort at compile time. The `Result` wrapper mirrors
    /// [`finish`](FileWriter::finish)'s signature and leaves room for future
    /// failure modes; today `abort()` never returns `Err`.
    ///
    /// The caller is responsible for deleting the partial remote file if they
    /// don't want it to linger — the server now has a zero-to-N byte file
    /// depending on how many WRITEs completed before the abort.
    ///
    /// # Future extension
    ///
    /// A `close_and_delete()` variant that sends `SET_INFO
    /// FileDispositionInformation(DeletePending=true)` before CLOSE would
    /// combine the two round-trips the caller does today. Out of scope here.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::ops::ControlFlow;
    /// # async fn example(
    /// #     client: &smb2::SmbClient,
    /// #     share: &smb2::Tree,
    /// #     cancel: impl Fn() -> bool,
    /// # ) -> Result<(), smb2::Error> {
    /// let mut writer = client.create_file_writer(share, "output.bin").await?;
    /// for chunk in [b"first".as_slice(), b"second", b"third"] {
    ///     if cancel() {
    ///         let written = writer.abort().await?;
    ///         println!("Aborted after {written} bytes confirmed");
    ///         // Caller: delete the partial remote file here if desired.
    ///         return Ok(());
    ///     }
    ///     writer.write_chunk(chunk).await?;
    /// }
    /// writer.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn abort(mut self) -> Result<u64> {
        use futures_util::stream::StreamExt;

        // 1. Discard anything we have not yet put on the wire. Unsent data
        //    means nothing to the server and carries no credits.
        self.pending_data.clear();
        self.pending_offset = 0;
        self.stashed_chunk = None;

        // 2. Drain in-flight WRITE responses — they're already in the
        //    kernel/network buffer, and dropping them unread would desync
        //    credits and message IDs. Errors are swallowed: on abort we
        //    don't care if a WRITE failed or succeeded.
        while let Some(result) = self.in_flight.next().await {
            match result {
                Ok(frame) => {
                    if frame.header.status == NtStatus::SUCCESS {
                        // Keep total_written accurate for callers that log it.
                        let mut cursor = ReadCursor::new(&frame.body);
                        if let Ok(resp) = WriteResponse::unpack(&mut cursor) {
                            self.total_written += resp.count as u64;
                        }
                    } else {
                        debug!(
                            "stream: FileWriter::abort() ignoring WRITE error status {:?}",
                            frame.header.status
                        );
                    }
                }
                Err(e) => {
                    // Transport-level failure while draining. There's nothing
                    // sensible to do — the connection may already be gone.
                    // Mark everything drained and move on.
                    debug!(
                        "stream: FileWriter::abort() giving up on remaining in-flight \
                         response(s) after transport error: {}",
                        e
                    );
                    break;
                }
            }
        }

        // 3. Skip flush_handle() — that's the whole point of abort().

        // 4. Best-effort CLOSE. If it fails, log and move on.
        if let Err(e) = self.tree.close_handle(&mut self.conn, self.file_id).await {
            debug!(
                "stream: FileWriter::abort() best-effort CLOSE failed, handle may leak \
                 server-side until session teardown: {}",
                e
            );
        }

        // 5. Silence the Drop warning — we finalized cleanly.
        self.done = true;
        Ok(self.total_written)
    }

    /// Confirmed bytes written (from server WRITE responses).
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.total_written
    }

    /// Current transfer progress.
    ///
    /// `total_bytes` is always `None` because push-based writers don't
    /// know the total size upfront.
    #[must_use]
    pub fn progress(&self) -> Progress {
        Progress {
            bytes_transferred: self.total_written,
            total_bytes: None,
        }
    }

    /// Get the next wire-level chunk from the pending buffer.
    fn next_pending_chunk(&mut self) -> Option<Vec<u8>> {
        if self.pending_offset >= self.pending_data.len() {
            return None;
        }

        let chunk = self.conn.fundable_chunk(self.max_write_size) as usize;
        let end = (self.pending_offset + chunk).min(self.pending_data.len());
        let slice = self.pending_data[self.pending_offset..end].to_vec();
        self.pending_offset = end;

        if self.pending_offset >= self.pending_data.len() {
            self.pending_data.clear();
            self.pending_offset = 0;
        }

        Some(slice)
    }

    /// Launch one wire-level WRITE request into the `in_flight` queue.
    ///
    /// `permit` is the connection-wide write budget for this frame's bytes, and
    /// it is parked INSIDE the future on purpose: completing, aborting, or
    /// dropping the future returns the budget with no explicit release anywhere.
    /// ❌ Don't hold it on `self` instead: a writer dropped mid-flight (a user
    /// cancelling a copy) would strand the budget for the life of the connection.
    fn launch_wire_chunk(
        &mut self,
        data: Vec<u8>,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let data_len = data.len() as u64;
        let credit_charge = credits::charge_for_payload(data_len);

        let req = WriteRequest {
            data_offset: 0x70,
            offset: self.offset,
            file_id: self.file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data,
        };

        let c = self.conn.clone();
        let tree_id = self.tree.tree_id;
        self.in_flight.push(Box::pin(async move {
            let _budget = permit;
            c.execute_with_credits(
                Command::Write,
                &req,
                Some(tree_id),
                crate::types::CreditCharge(credit_charge),
            )
            .await
        }));

        self.offset += data_len;
    }

    /// Receive one in-flight WRITE response.
    async fn drain_one(&mut self) -> Result<()> {
        use futures_util::stream::StreamExt;

        let Some(result) = self.in_flight.next().await else {
            return Ok(());
        };
        self.take_write_response(result).await
    }

    /// Account for one finished WRITE, whoever awaited it.
    ///
    /// Split out of [`Self::drain_one`] so the budget's drain step can hand its
    /// response here instead of duplicating the failure handling.
    async fn take_write_response(&mut self, result: Result<Frame>) -> Result<()> {
        use futures_util::stream::StreamExt;

        let frame = result?;

        if frame.header.status != NtStatus::SUCCESS {
            // Drain remaining in-flight (best-effort), then close handle.
            while self.in_flight.next().await.is_some() {}
            // Best-effort close.
            let _ = self.tree.close_handle(&mut self.conn, self.file_id).await;
            self.done = true;
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Write,
            });
        }

        let mut cursor = ReadCursor::new(&frame.body);
        let resp = WriteResponse::unpack(&mut cursor)?;
        self.total_written += resp.count as u64;

        Ok(())
    }

    /// Drain all in-flight WRITE responses.
    async fn drain_all(&mut self) -> Result<()> {
        while !self.in_flight.is_empty() {
            self.drain_one().await?;
        }
        Ok(())
    }

    /// Whether there is room in the pipeline window for another chunk.
    ///
    /// Deliberately not a credit check: `Connection` reserves credits per send
    /// and parks a write that can't afford one, so second-guessing it here
    /// could only stall a chunk that the connection would have sent.
    fn can_send(&self, _data: &[u8]) -> bool {
        self.in_flight.len() < MAX_PIPELINE_WINDOW
    }

    /// Try to send a wire chunk. If the window is full or credits are exhausted,
    /// drain one response and retry. If still unable, stash the chunk and return
    /// `Ok(false)` (caller decides whether to wait or return).
    async fn send_or_stash(&mut self, data: Vec<u8>) -> Result<bool> {
        // Make room if the window is full.
        if self.in_flight.len() >= MAX_PIPELINE_WINDOW {
            self.drain_one().await?;
        }

        if !self.can_send(&data) {
            // Window still full — drain one response and retry.
            if !self.in_flight.is_empty() {
                self.drain_one().await?;
            }
            if !self.can_send(&data) {
                self.stashed_chunk = Some(data);
                return Ok(false);
            }
        }

        // This stream has room; the CONNECTION may not. The window bounds one
        // stream, the budget bounds all of them together. This waits rather
        // than stashing: unlike the window, the budget is shared, so there is
        // nothing the caller could usefully do with an `Ok(false)` here.
        let permit = self.reserve_budget(data.len() as u64).await?;
        self.launch_wire_chunk(data, permit);
        Ok(true)
    }

    /// Connection-wide write budget for one wire chunk.
    ///
    /// The deadlock-safe ordering lives in `reserve_write_budget_or_drain`;
    /// this loop only accounts for the responses that ordering drains on the
    /// way. ❌ Don't inline a shortcut past it.
    async fn reserve_budget(
        &mut self,
        bytes: u64,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
        loop {
            let step = reserve_write_budget_or_drain(&self.conn, bytes, &mut self.in_flight).await;
            match step {
                WriteBudgetStep::Granted(permit) => return Ok(permit),
                WriteBudgetStep::Drained(result) => self.take_write_response(result).await?,
            }
        }
    }

    /// Send any stashed chunk, draining responses as needed to free credits.
    async fn flush_stash(&mut self) -> Result<()> {
        if let Some(stashed) = self.stashed_chunk.take() {
            // Make room if needed.
            if !self.in_flight.is_empty() && !self.can_send(&stashed) {
                self.drain_one().await?;
            }
            if self.can_send(&stashed) {
                let permit = self.reserve_budget(stashed.len() as u64).await?;
                self.launch_wire_chunk(stashed, permit);
            } else {
                // Re-stash — caller must drain more or give up.
                self.stashed_chunk = Some(stashed);
            }
        }
        Ok(())
    }
}

impl Drop for FileWriter {
    fn drop(&mut self) {
        if !self.done {
            debug!(
                "stream: FileWriter dropped without finish(), file handle may leak \
                 (bytes_written={})",
                self.total_written
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_helpers::{
        build_close_error_response, build_close_response, build_compound_response_frame,
        build_create_error_response, build_create_response, build_flush_response,
        build_query_info_error_response, build_query_info_response, build_read_error_response,
        build_read_response, build_write_error_response, build_write_response,
        file_all_information, file_name_information, setup_connection,
    };
    use crate::transport::MockTransport;
    use crate::types::status::NtStatus;
    use crate::types::{FileId, TreeId};
    use std::sync::Arc;

    fn test_tree() -> Arc<Tree> {
        Arc::new(Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
            dfs_origin: None,
        })
    }

    fn test_file_id() -> FileId {
        FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        }
    }

    /// The compound a writer's open gets back: CREATE, then a class 48 name
    /// query the server refused (so `resolved_path` is `None`).
    fn writer_opened(file_id: FileId) -> Vec<u8> {
        build_compound_response_frame(&[
            build_create_response(file_id, 0),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
        ])
    }

    /// The compound a reader's open gets back: CREATE, then class 18 and
    /// class 48, both refused.
    fn reader_opened(file_id: FileId, end_of_file: u64) -> Vec<u8> {
        build_compound_response_frame(&[
            build_create_response(file_id, end_of_file),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
        ])
    }

    // ── FileWriter tests ───────────────────────────────────────────────

    /// A 1 MiB WRITE charges 16 credits, which a window the server stopped
    /// growing at 8 can never fund. The writer sends what half that window
    /// funds instead (four credits, 256 KiB), so a small window slows the
    /// upload down rather than failing it.
    #[tokio::test]
    async fn file_writer_sizes_its_writes_to_a_small_credit_window() {
        let mock = Arc::new(MockTransport::new());
        let quarter = 256 * 1024;
        for _ in 0..4 {
            mock.queue_response(build_write_response(quarter));
        }
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        conn.set_credit_ceiling(8);
        let mut writer = FileWriter::new(test_tree(), conn, test_file_id(), 1024 * 1024);
        writer.write_chunk(&vec![0u8; 1024 * 1024]).await.unwrap();
        assert_eq!(writer.finish().await.unwrap(), 1024 * 1024);

        // Four WRITEs, then FLUSH and CLOSE.
        assert_eq!(mock.sent_count(), 6);
    }

    #[tokio::test]
    async fn file_writer_at_offset_writes_from_given_position() {
        use crate::msg::header::Header;
        use crate::msg::write::WriteRequest;
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        // CREATE (FileOpenIf) + WRITE(50) + FLUSH + CLOSE.
        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(50));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree
            .create_file_writer_at(conn, "patched.bin", 4096)
            .await
            .unwrap();
        writer.write_chunk(&[7u8; 50]).await.unwrap();
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 50);

        // The WRITE must have gone out at offset 4096, not 0.
        let sent = mock.sent_messages();
        let write_frame = sent
            .iter()
            .find_map(|bytes| {
                let mut c = ReadCursor::new(&bytes[Header::SIZE..]);
                WriteRequest::unpack(&mut c)
                    .ok()
                    .filter(|w| !w.data.is_empty())
            })
            .expect("a WRITE with data was sent");
        assert_eq!(write_frame.offset, 4096);
    }

    #[tokio::test]
    async fn file_writer_single_chunk() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        // Queue: CREATE + WRITE(100) + FLUSH + CLOSE
        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[0u8; 100]).await.unwrap();
        assert_eq!(writer.bytes_written(), 0); // Not yet drained
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 100);
    }

    #[tokio::test]
    async fn file_writer_multiple_chunks() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[1u8; 100]).await.unwrap();
        writer.write_chunk(&[2u8; 100]).await.unwrap();
        writer.write_chunk(&[3u8; 100]).await.unwrap();
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 300);
    }

    #[tokio::test]
    async fn file_writer_empty_finish() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        // Queue: CREATE + FLUSH + CLOSE (no WRITE)
        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree.create_file_writer(conn, "empty.bin").await.unwrap();
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 0);

        // Verify: CREATE + FLUSH + CLOSE = 3 sent messages.
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn file_writer_empty_chunk_noop() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        // Queue: CREATE + WRITE(50) + FLUSH + CLOSE
        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(50));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[]).await.unwrap(); // No-op
        writer.write_chunk(&[0u8; 50]).await.unwrap();
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 50);

        // CREATE + WRITE + FLUSH + CLOSE = 4 (no extra WRITE for empty chunk).
        assert_eq!(mock.sent_count(), 4);
    }

    #[tokio::test]
    async fn file_writer_chunk_splitting() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        // max_write_size = 65536, send 200KB = 3 x 65536 + 1 x 8192.
        // 200 * 1024 = 204800. 204800 / 65536 = 3.125 -> 4 wire writes.
        let chunk_size = 200 * 1024;
        let wire_1 = 65536u32;
        let wire_2 = 65536u32;
        let wire_3 = 65536u32;
        let wire_4 = (chunk_size - 3 * 65536) as u32; // 8192

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(wire_1));
        mock.queue_response(build_write_response(wire_2));
        mock.queue_response(build_write_response(wire_3));
        mock.queue_response(build_write_response(wire_4));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "big.bin").await.unwrap();
        writer.write_chunk(&vec![0u8; chunk_size]).await.unwrap();
        let total = writer.finish().await.unwrap();
        assert_eq!(total, (wire_1 + wire_2 + wire_3 + wire_4) as u64);

        // CREATE + 4 WRITEs + FLUSH + CLOSE = 7
        assert_eq!(mock.sent_count(), 7);
    }

    #[tokio::test]
    async fn file_writer_progress_none_total() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        let progress = writer.progress();
        assert!(progress.total_bytes.is_none());
        assert_eq!(progress.bytes_transferred, 0);
        writer.finish().await.unwrap();
    }

    #[tokio::test]
    async fn file_writer_bytes_written_tracks_confirmed() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(200));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();

        // After pushing but before finish, bytes_written reflects only drained responses.
        writer.write_chunk(&[0u8; 100]).await.unwrap();
        assert_eq!(writer.bytes_written(), 0); // Not yet drained

        writer.write_chunk(&[0u8; 200]).await.unwrap();
        assert_eq!(writer.bytes_written(), 0); // Still not drained

        // finish() drains all.
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 300);
    }

    #[tokio::test]
    async fn file_writer_backpressure() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));

        // Queue MAX_PIPELINE_WINDOW + 1 write responses.
        for _ in 0..MAX_PIPELINE_WINDOW + 1 {
            mock.queue_response(build_write_response(64));
        }
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();

        // Fill the window.
        for _ in 0..MAX_PIPELINE_WINDOW {
            writer.write_chunk(&[0u8; 64]).await.unwrap();
        }

        // This write must drain one response before sending (backpressure).
        writer.write_chunk(&[0u8; 64]).await.unwrap();

        // At least one response was drained by backpressure.
        assert!(writer.bytes_written() >= 64);

        let total = writer.finish().await.unwrap();
        assert_eq!(total, (MAX_PIPELINE_WINDOW as u64 + 1) * 64);
    }

    #[tokio::test]
    async fn file_writer_server_error() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        // Return error for the WRITE.
        mock.queue_response(build_write_error_response(NtStatus::DISK_FULL));
        // CLOSE after error cleanup.
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[0u8; 100]).await.unwrap();
        let result = writer.finish().await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(
            format!("{err:?}").contains("DISK_FULL"),
            "expected DISK_FULL, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn file_writer_finish_drains_all() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(50));
        mock.queue_response(build_write_response(75));
        mock.queue_response(build_write_response(25));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[0u8; 50]).await.unwrap();
        writer.write_chunk(&[0u8; 75]).await.unwrap();
        writer.write_chunk(&[0u8; 25]).await.unwrap();

        // None drained yet.
        assert_eq!(writer.bytes_written(), 0);

        // finish() must drain all 3.
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 150);
    }

    // ── FileWriter::abort tests ────────────────────────────────────────

    #[tokio::test]
    async fn file_writer_abort_no_in_flight() {
        // abort() with nothing in flight: just CLOSE, no FLUSH, no extra reads.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        // Queue: CREATE + CLOSE (note: no FLUSH — abort skips fsync).
        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        let total = writer.abort().await.unwrap();
        assert_eq!(total, 0);

        // Exactly 2 messages on the wire: CREATE, CLOSE.
        assert_eq!(mock.sent_count(), 2);
    }

    #[tokio::test]
    async fn file_writer_abort_drains_in_flight() {
        // abort() must consume in-flight WRITE responses to keep the
        // connection in sync, but skips FLUSH.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        // Three WRITEs on the wire, three responses queued.
        mock.queue_response(build_write_response(50));
        mock.queue_response(build_write_response(75));
        mock.queue_response(build_write_response(25));
        // No FLUSH response — abort must not send FLUSH.
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[0u8; 50]).await.unwrap();
        writer.write_chunk(&[0u8; 75]).await.unwrap();
        writer.write_chunk(&[0u8; 25]).await.unwrap();

        // Nothing drained yet — write_chunk doesn't drain unless the window fills.
        assert_eq!(writer.bytes_written(), 0);

        // abort() drains all three and returns the confirmed total.
        let total = writer.abort().await.unwrap();
        assert_eq!(total, 150);

        // Wire traffic: CREATE + 3 WRITEs + CLOSE = 5. No FLUSH.
        assert_eq!(mock.sent_count(), 5);
    }

    #[tokio::test]
    async fn file_writer_abort_swallows_write_errors() {
        // Mid-stream WRITE failure during abort's drain: swallowed, abort
        // still closes and returns Ok.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(100));
        // Second WRITE errors — abort must not bubble this up.
        mock.queue_response(build_write_error_response(NtStatus::DISK_FULL));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[0u8; 100]).await.unwrap();
        writer.write_chunk(&[0u8; 100]).await.unwrap();

        // abort() should return Ok despite the DISK_FULL on the second WRITE.
        // total_written reflects only the successful WRITE (100).
        let total = writer.abort().await.unwrap();
        assert_eq!(total, 100);

        // Wire: CREATE + 2 WRITEs + CLOSE = 4.
        assert_eq!(mock.sent_count(), 4);
    }

    #[tokio::test]
    async fn file_writer_abort_discards_stashed_chunk() {
        // If a chunk was stashed (credit/window exhaustion scenario in
        // real traffic), abort() must not send it.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();

        // Inject a stashed chunk and pending buffer directly — in real traffic
        // these would accumulate when credits run out. Neither should get sent.
        writer.stashed_chunk = Some(vec![0u8; 500]);
        writer.pending_data = vec![0u8; 1000];
        writer.pending_offset = 0;

        let total = writer.abort().await.unwrap();
        assert_eq!(total, 0);

        // Only CREATE + CLOSE on the wire. No WRITE from the stash or buffer.
        assert_eq!(mock.sent_count(), 2);
    }

    #[tokio::test]
    async fn file_writer_abort_close_error_is_swallowed() {
        // CLOSE failing at the end is logged but not surfaced — abort
        // is a best-effort fast exit.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_write_response(100));
        // CLOSE returns an error. abort() must still return Ok.
        mock.queue_response(build_close_error_response(NtStatus::FILE_CLOSED));

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        writer.write_chunk(&[0u8; 100]).await.unwrap();

        let result = writer.abort().await;
        assert!(
            result.is_ok(),
            "abort() should swallow CLOSE errors, got: {result:?}"
        );
        assert_eq!(result.unwrap(), 100);

        // CREATE + WRITE + CLOSE = 3.
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn file_writer_abort_sets_done_so_drop_is_silent() {
        // After abort() returns, the `done` flag is set, so the Drop impl
        // does not log a "dropped without finish()" warning. We can't
        // inspect `done` once the writer has been consumed, but we can
        // confirm abort returns Ok (which only happens on the done=true
        // path) and that the test ends cleanly under log capture.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(writer_opened(file_id));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree.create_file_writer(conn, "out.bin").await.unwrap();
        let result = writer.abort().await;
        assert!(result.is_ok());
        // The writer has been consumed. `Drop` ran inside abort's frame
        // with done=true, so no warning fired. (Behavior-only check;
        // exposing `done` for inspection was not needed.)
    }

    // ── FileReader tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn file_reader_positioned_reads_one_open_one_close() {
        // The core no-leak contract: one CREATE, N positioned READs at
        // arbitrary offsets, one CLOSE — the handle is opened once and released
        // once no matter how many reads run.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(reader_opened(file_id, 1000));
        mock.queue_response(build_read_response(vec![0xAA; 4]));
        mock.queue_response(build_read_response(vec![0xBB; 8]));
        mock.queue_response(build_read_response(vec![0xCC; 2]));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let reader = tree.open_file_reader(conn, "archive.zip").await.unwrap();
        assert_eq!(reader.size(), 1000);

        // Three reads at different offsets, out of order — no shared cursor.
        assert_eq!(reader.read_at(500, 4).await.unwrap(), vec![0xAA; 4]);
        assert_eq!(reader.read_at(0, 8).await.unwrap(), vec![0xBB; 8]);
        assert_eq!(reader.read_at(998, 2).await.unwrap(), vec![0xCC; 2]);

        reader.close().await.unwrap();

        // CREATE + 3 READ + CLOSE = 5. Exactly one open, exactly one close.
        assert_eq!(mock.sent_count(), 5);
    }

    #[tokio::test]
    async fn file_reader_clamps_and_skips_reads_at_or_past_eof() {
        // A read wholly past EOF issues NO wire READ and returns empty; a read
        // straddling EOF is clamped to what exists. file_size = 10.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(reader_opened(file_id, 10));
        // Only ONE READ hits the wire: the clamped [8, 10) read of 2 bytes.
        mock.queue_response(build_read_response(vec![0xEE; 2]));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let reader = tree.open_file_reader(conn, "small.bin").await.unwrap();

        // Wholly past EOF → empty, no wire traffic.
        assert!(reader.read_at(10, 5).await.unwrap().is_empty());
        assert!(reader.read_at(99, 100).await.unwrap().is_empty());
        // Zero-length → empty, no wire traffic.
        assert!(reader.read_at(0, 0).await.unwrap().is_empty());
        // Straddling EOF: asked for 100 at offset 8, clamped to 2 bytes.
        assert_eq!(reader.read_at(8, 100).await.unwrap(), vec![0xEE; 2]);

        reader.close().await.unwrap();

        // CREATE + 1 READ (the clamped one) + CLOSE = 3. The past-EOF and
        // zero-length reads never touched the wire.
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn file_reader_splits_range_larger_than_max_read() {
        // A single read_at spanning more than MaxReadSize (65536 in the test
        // params) is split into consecutive wire READs and reassembled.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        let total = 65536usize * 2 + 100; // 3 wire reads: 65536, 65536, 100
        mock.queue_response(reader_opened(file_id, total as u64));
        mock.queue_response(build_read_response(vec![1u8; 65536]));
        mock.queue_response(build_read_response(vec![2u8; 65536]));
        mock.queue_response(build_read_response(vec![3u8; 100]));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let reader = tree.open_file_reader(conn, "big.bin").await.unwrap();
        let data = reader.read_at(0, total as u64).await.unwrap();
        assert_eq!(data.len(), total);
        assert_eq!(&data[..65536], &vec![1u8; 65536][..]);
        assert_eq!(&data[65536..65536 * 2], &vec![2u8; 65536][..]);
        assert_eq!(&data[65536 * 2..], &vec![3u8; 100][..]);

        reader.close().await.unwrap();

        // CREATE + 3 READ + CLOSE = 5 — still ONE open and ONE close for the
        // whole split range.
        assert_eq!(mock.sent_count(), 5);
    }

    #[tokio::test]
    async fn file_reader_surfaces_read_error() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(reader_opened(file_id, 100));
        mock.queue_response(build_read_error_response(NtStatus::ACCESS_DENIED));
        mock.queue_response(build_close_response());

        let conn = setup_connection(&mock);
        let tree = test_tree();

        let reader = tree.open_file_reader(conn, "denied.bin").await.unwrap();
        let result = reader.read_at(0, 10).await;
        assert!(matches!(
            result,
            Err(Error::Protocol {
                status: NtStatus::ACCESS_DENIED,
                command: Command::Read,
            })
        ));
        // The caller still owns the handle and can close it cleanly.
        reader.close().await.unwrap();
    }

    #[tokio::test]
    async fn file_reader_dropped_without_close_sends_no_close() {
        // Documents the leak contract: dropping without close() issues NO CLOSE
        // (the handle lingers server-side until session teardown). Drop logs a
        // debug warning; we assert the wire behavior it implies.
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(reader_opened(file_id, 100));
        mock.queue_response(build_read_response(vec![0x11; 4]));

        let conn = setup_connection(&mock);
        let tree = test_tree();

        {
            let reader = tree.open_file_reader(conn, "leak.bin").await.unwrap();
            assert_eq!(reader.read_at(0, 4).await.unwrap(), vec![0x11; 4]);
            // Dropped here without close().
        }

        // CREATE + 1 READ, and crucially NO CLOSE.
        assert_eq!(mock.sent_count(), 2);
    }

    // ── Progress tests ─────────────────────────────────────────────────

    #[test]
    fn progress_calculations() {
        let cases = [
            (50, Some(100), 50.0, 0.5),
            (100, Some(100), 100.0, 1.0),
            (25, Some(100), 25.0, 0.25),
            (0, Some(0), 100.0, 1.0), // Empty file
            (50, None, 0.0, 0.0),     // Unknown total
        ];
        for (transferred, total, expected_pct, expected_frac) in cases {
            let p = Progress {
                bytes_transferred: transferred,
                total_bytes: total,
            };
            assert_eq!(
                p.percent(),
                expected_pct,
                "percent failed for {transferred}/{total:?}"
            );
            assert_eq!(
                p.fraction(),
                expected_frac,
                "fraction failed for {transferred}/{total:?}"
            );
        }

        // Large numbers.
        let large = Progress {
            bytes_transferred: u64::MAX / 2,
            total_bytes: Some(u64::MAX),
        };
        let frac = large.fraction();
        assert!(frac > 0.49 && frac < 0.51);
    }

    // ── What the server opened ─────────────────────────────────────────

    /// The query classes a compound request carried, in order.
    fn sent_query_classes(mock: &MockTransport, n: usize) -> Vec<u8> {
        use crate::msg::header::Header;
        use crate::msg::query_info::QueryInfoRequest;
        let sent = mock.sent_message(n).unwrap();
        let mut classes = Vec::new();
        let mut offset = 0usize;
        loop {
            let mut cursor = ReadCursor::new(&sent[offset..]);
            let header = Header::unpack(&mut cursor).unwrap();
            if header.command == Command::QueryInfo {
                classes.push(
                    QueryInfoRequest::unpack(&mut cursor)
                        .unwrap()
                        .file_info_class,
                );
            }
            if header.next_command == 0 {
                return classes;
            }
            offset += header.next_command as usize;
        }
    }

    #[tokio::test]
    async fn a_reader_records_the_name_the_server_opened_in_the_open_round_trip() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_compound_response_frame(&[
            build_create_response(test_file_id(), 5),
            build_query_info_response(file_all_information("\\Docs\\Report.txt")),
            build_query_info_response(file_name_information("Docs\\Report.txt")),
        ]));
        let reader = test_tree()
            .open_file_reader(setup_connection(&mock), "DOCS/report.TXT")
            .await
            .unwrap();
        assert_eq!(reader.resolved_path(), Some("Docs/Report.txt"));
        assert_eq!(reader.size(), 5);
        assert_eq!(mock.sent_count(), 1, "the name costs no extra round trip");
        // Class 18 before 48, so a server cascading a refused 18 can't take
        // 48 down with it.
        assert_eq!(sent_query_classes(&mock, 0), vec![18, 48]);
    }

    #[tokio::test]
    async fn a_reader_falls_back_to_file_all_information() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_compound_response_frame(&[
            build_create_response(test_file_id(), 5),
            build_query_info_response(file_all_information("\\Docs\\Report.txt")),
            build_query_info_error_response(NtStatus::NOT_SUPPORTED),
        ]));
        let reader = test_tree()
            .open_file_reader(setup_connection(&mock), "docs/report.txt")
            .await
            .unwrap();
        assert_eq!(reader.resolved_path(), Some("Docs/Report.txt"));
    }

    #[tokio::test]
    async fn a_reader_opens_fine_on_a_server_that_names_nothing() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(reader_opened(test_file_id(), 5));
        let reader = test_tree()
            .open_file_reader(setup_connection(&mock), "docs/report.txt")
            .await
            .unwrap();
        assert_eq!(reader.resolved_path(), None);
        assert_eq!(reader.size(), 5);
    }

    #[tokio::test]
    async fn a_reader_that_cannot_open_reports_the_create_error() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_compound_response_frame(&[
            build_create_error_response(NtStatus::OBJECT_NAME_NOT_FOUND),
            build_query_info_error_response(NtStatus::OBJECT_NAME_NOT_FOUND),
            build_query_info_error_response(NtStatus::OBJECT_NAME_NOT_FOUND),
        ]));
        let err = test_tree()
            .open_file_reader(setup_connection(&mock), "missing.txt")
            .await
            .err()
            .expect("a missing file must not open");
        assert_eq!(err.kind(), crate::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn a_writer_records_the_name_the_server_opened() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_compound_response_frame(&[
            build_create_response(test_file_id(), 0),
            build_query_info_response(file_name_information("Out\\new\u{F025}.bin")),
        ]));
        mock.queue_response(build_close_response());
        let writer = test_tree()
            .create_file_writer(setup_connection(&mock), "out/new?.bin")
            .await
            .unwrap();
        assert_eq!(writer.resolved_path(), Some("Out/new?.bin"));
        // A write handle has no FILE_READ_ATTRIBUTES, so class 18 isn't asked.
        assert_eq!(sent_query_classes(&mock, 0), vec![48]);
        writer.abort().await.unwrap();
    }

    #[tokio::test]
    async fn every_writer_open_names_what_it_opened() {
        for disposition in ["exclusive", "at"] {
            let mock = Arc::new(MockTransport::new());
            mock.queue_response(build_compound_response_frame(&[
                build_create_response(test_file_id(), 0),
                build_query_info_response(file_name_information("Out.bin")),
            ]));
            mock.queue_response(build_close_response());
            let conn = setup_connection(&mock);
            let writer = match disposition {
                "exclusive" => {
                    test_tree()
                        .create_file_writer_exclusive(conn, "out.bin")
                        .await
                }
                _ => test_tree().create_file_writer_at(conn, "out.bin", 10).await,
            }
            .unwrap();
            assert_eq!(writer.resolved_path(), Some("Out.bin"), "{disposition}");
            writer.abort().await.unwrap();
        }
    }
}
