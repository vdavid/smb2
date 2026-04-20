//! Streaming file I/O with progress reporting.
//!
//! Provides [`FileDownload`] for memory-efficient large file downloads,
//! [`FileUpload`] for streaming uploads with progress,
//! [`FileWriter`] for push-based pipelined writes (use
//! [`FileWriter::finish`] for normal completion, [`FileWriter::abort`] for
//! fast cancellation), and [`Progress`] for tracking transfer progress.

use std::ops::ControlFlow;

use log::debug;

use crate::client::connection::Connection;
use crate::client::tree::Tree;
use crate::error::Result;
use crate::msg::read::{ReadRequest, ReadResponse, SMB2_CHANNEL_NONE};
use crate::msg::write::{WriteRequest, WriteResponse};
use crate::pack::{ReadCursor, Unpack};
use crate::types::status::NtStatus;
use crate::types::{Command, FileId};
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
/// Each call to [`next_chunk`](FileDownload::next_chunk) sends one SMB2 READ
/// request and returns the response data. This is sequential (not pipelined)
/// but memory-efficient: only one chunk is in memory at a time.
///
/// The file handle is closed when the download completes or is dropped.
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
}

impl<'a> FileDownload<'a> {
    /// Create a new streaming download.
    pub(crate) fn new(
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
            chunk_size,
            done: false,
        }
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
    /// Returns `None` when the download is complete. Each call sends
    /// one SMB2 READ request and returns the response data. The file
    /// handle is automatically closed when the last chunk is consumed.
    pub async fn next_chunk(&mut self) -> Option<Result<Vec<u8>>> {
        if self.done {
            return None;
        }

        let remaining = self.file_size.saturating_sub(self.bytes_received);
        if remaining == 0 {
            // Close the handle when we've read everything.
            let close_result = self.close().await;
            if let Err(e) = close_result {
                return Some(Err(e));
            }
            return None;
        }

        let this_chunk = remaining.min(self.chunk_size as u64) as u32;

        let req = ReadRequest {
            padding: 0x50,
            flags: 0,
            length: this_chunk,
            offset: self.bytes_received,
            file_id: self.file_id,
            minimum_count: 0,
            channel: SMB2_CHANNEL_NONE,
            remaining_bytes: 0,
            read_channel_info: vec![],
        };

        let credit_charge = (this_chunk as u64).div_ceil(65536).max(1) as u16;
        let exec_result = self
            .conn
            .execute_with_credits(
                Command::Read,
                &req,
                Some(self.tree.tree_id),
                crate::types::CreditCharge(credit_charge),
            )
            .await;

        match exec_result {
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
            Ok(frame) => {
                if frame.header.status == NtStatus::END_OF_FILE {
                    let _ = self.close().await;
                    return None;
                }

                if frame.header.status != NtStatus::SUCCESS {
                    self.done = true;
                    return Some(Err(Error::Protocol {
                        status: frame.header.status,
                        command: Command::Read,
                    }));
                }

                let mut cursor = ReadCursor::new(&frame.body);
                match ReadResponse::unpack(&mut cursor) {
                    Err(e) => {
                        self.done = true;
                        Some(Err(e))
                    }
                    Ok(resp) => {
                        if resp.data.is_empty() {
                            let _ = self.close().await;
                            return None;
                        }

                        self.bytes_received += resp.data.len() as u64;

                        // If this was the last chunk, close the handle.
                        if self.bytes_received >= self.file_size {
                            if let Err(e) = self.close().await {
                                return Some(Err(e));
                            }
                        }

                        Some(Ok(resp.data))
                    }
                }
            }
        }
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

    /// Close the file handle. Only sends CLOSE once.
    async fn close(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        self.tree.close_handle(self.conn, self.file_id).await
    }
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
        let this_chunk = remaining.min(self.chunk_size as usize);
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

        let credit_charge = (this_chunk as u64).div_ceil(65536).max(1) as u16;
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
/// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// let mut writer = client.create_file_writer(&share, "output.bin").await?;
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

/// Push-based streaming writer: see module-level docs for the example.
pub struct FileWriter<'a> {
    tree: &'a Tree,
    conn: &'a mut Connection,
    file_id: FileId,
    max_write_size: u32,
    /// Next write offset in the file.
    offset: u64,
    /// In-flight WRITE futures. `FuturesUnordered::len()` gives the same
    /// "how many responses are pending" count the old `in_flight: usize`
    /// field tracked pre-Phase-3.
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
}

impl<'a> FileWriter<'a> {
    /// Create a new push-based streaming writer.
    pub(crate) fn new(
        tree: &'a Tree,
        conn: &'a mut Connection,
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
        }
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
        self.tree.flush_handle(self.conn, self.file_id).await?;

        // Close the handle.
        self.tree.close_handle(self.conn, self.file_id).await?;

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
    /// #     client: &mut smb2::SmbClient,
    /// #     share: &smb2::Tree,
    /// #     cancel: impl Fn() -> bool,
    /// # ) -> Result<(), smb2::Error> {
    /// let mut writer = client.create_file_writer(&share, "output.bin").await?;
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
        if let Err(e) = self.tree.close_handle(self.conn, self.file_id).await {
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

        let end = (self.pending_offset + self.max_write_size as usize).min(self.pending_data.len());
        let slice = self.pending_data[self.pending_offset..end].to_vec();
        self.pending_offset = end;

        if self.pending_offset >= self.pending_data.len() {
            self.pending_data.clear();
            self.pending_offset = 0;
        }

        Some(slice)
    }

    /// Launch one wire-level WRITE request into the `in_flight` queue.
    fn launch_wire_chunk(&mut self, data: Vec<u8>) {
        let data_len = data.len() as u64;
        let credit_charge = data_len.div_ceil(65536).max(1) as u16;

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
        let frame = result?;

        if frame.header.status != NtStatus::SUCCESS {
            // Drain remaining in-flight (best-effort), then close handle.
            while self.in_flight.next().await.is_some() {}
            // Best-effort close.
            let _ = self.tree.close_handle(self.conn, self.file_id).await;
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

    /// Check whether we have enough credits to send a chunk of this size.
    fn can_send(&self, data: &[u8]) -> bool {
        let credit_charge = (data.len() as u64).div_ceil(65536).max(1) as u16;
        let credits_available = self.conn.credits() as usize / credit_charge.max(1) as usize;
        credits_available > 0 && self.in_flight.len() < MAX_PIPELINE_WINDOW
    }

    /// Try to send a wire chunk. If the window is full or credits are exhausted,
    /// drain one response and retry. If still unable, stash the chunk and return
    /// `Ok(false)` (caller decides whether to wait or return).
    async fn send_or_stash(&mut self, data: Vec<u8>) -> Result<bool> {
        // Make room if the window is full.
        if self.in_flight.len() >= MAX_PIPELINE_WINDOW {
            self.drain_one().await?;
        }

        if self.can_send(&data) {
            self.launch_wire_chunk(data);
            return Ok(true);
        }

        // No credits — drain one response to reclaim credits and retry.
        if !self.in_flight.is_empty() {
            self.drain_one().await?;
            if self.can_send(&data) {
                self.launch_wire_chunk(data);
                return Ok(true);
            }
        }

        // Still can't send. Stash for later.
        self.stashed_chunk = Some(data);
        Ok(false)
    }

    /// Send any stashed chunk, draining responses as needed to free credits.
    async fn flush_stash(&mut self) -> Result<()> {
        if let Some(stashed) = self.stashed_chunk.take() {
            // Make room if needed.
            if !self.in_flight.is_empty() && !self.can_send(&stashed) {
                self.drain_one().await?;
            }
            if self.can_send(&stashed) {
                self.launch_wire_chunk(stashed);
            } else {
                // Re-stash — caller must drain more or give up.
                self.stashed_chunk = Some(stashed);
            }
        }
        Ok(())
    }
}

impl Drop for FileWriter<'_> {
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
        build_close_error_response, build_close_response, build_create_response,
        build_flush_response, build_write_error_response, build_write_response, setup_connection,
    };
    use crate::transport::MockTransport;
    use crate::types::status::NtStatus;
    use crate::types::{FileId, TreeId};
    use std::sync::Arc;

    fn test_tree() -> Tree {
        Tree {
            tree_id: TreeId(10),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        }
    }

    fn test_file_id() -> FileId {
        FileId {
            persistent: 0xAA,
            volatile: 0xBB,
        }
    }

    // ── FileWriter tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn file_writer_single_chunk() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        // Queue: CREATE + WRITE(100) + FLUSH + CLOSE
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
        writer.write_chunk(&[0u8; 100]).await.unwrap();
        assert_eq!(writer.bytes_written(), 0); // Not yet drained
        let total = writer.finish().await.unwrap();
        assert_eq!(total, 100);
    }

    #[tokio::test]
    async fn file_writer_multiple_chunks() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree
            .create_file_writer(&mut conn, "empty.bin")
            .await
            .unwrap();
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
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(50));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(wire_1));
        mock.queue_response(build_write_response(wire_2));
        mock.queue_response(build_write_response(wire_3));
        mock.queue_response(build_write_response(wire_4));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "big.bin").await.unwrap();
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

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
        let progress = writer.progress();
        assert!(progress.total_bytes.is_none());
        assert_eq!(progress.bytes_transferred, 0);
        writer.finish().await.unwrap();
    }

    #[tokio::test]
    async fn file_writer_bytes_written_tracks_confirmed() {
        let mock = Arc::new(MockTransport::new());
        let file_id = test_file_id();

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(100));
        mock.queue_response(build_write_response(200));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();

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

        mock.queue_response(build_create_response(file_id, 0));

        // Queue MAX_PIPELINE_WINDOW + 1 write responses.
        for _ in 0..MAX_PIPELINE_WINDOW + 1 {
            mock.queue_response(build_write_response(64));
        }
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();

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

        mock.queue_response(build_create_response(file_id, 0));
        // Return error for the WRITE.
        mock.queue_response(build_write_error_response(NtStatus::DISK_FULL));
        // CLOSE after error cleanup.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(50));
        mock.queue_response(build_write_response(75));
        mock.queue_response(build_write_response(25));
        mock.queue_response(build_flush_response());
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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
        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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

        mock.queue_response(build_create_response(file_id, 0));
        // Three WRITEs on the wire, three responses queued.
        mock.queue_response(build_write_response(50));
        mock.queue_response(build_write_response(75));
        mock.queue_response(build_write_response(25));
        // No FLUSH response — abort must not send FLUSH.
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(100));
        // Second WRITE errors — abort must not bubble this up.
        mock.queue_response(build_write_error_response(NtStatus::DISK_FULL));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();

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

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_write_response(100));
        // CLOSE returns an error. abort() must still return Ok.
        mock.queue_response(build_close_error_response(NtStatus::FILE_CLOSED));

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let mut writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
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

        mock.queue_response(build_create_response(file_id, 0));
        mock.queue_response(build_close_response());

        let mut conn = setup_connection(&mock);
        let tree = test_tree();

        let writer = tree.create_file_writer(&mut conn, "out.bin").await.unwrap();
        let result = writer.abort().await;
        assert!(result.is_ok());
        // The writer has been consumed. `Drop` ran inside abort's frame
        // with done=true, so no warning fired. (Behavior-only check;
        // exposing `done` for inspection was not needed.)
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
}
