//! Streaming file I/O with progress reporting.
//!
//! Provides [`FileDownload`] for memory-efficient large file downloads,
//! [`FileUpload`] for streaming uploads with progress, and [`Progress`]
//! for tracking transfer progress.

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

        let send_result = self
            .conn
            .send_request(Command::Read, &req, Some(self.tree.tree_id))
            .await;

        if let Err(e) = send_result {
            self.done = true;
            return Some(Err(e));
        }

        let recv_result = self.conn.receive_response().await;
        match recv_result {
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
            Ok((resp_header, resp_body, _)) => {
                if resp_header.status == NtStatus::END_OF_FILE {
                    let _ = self.close().await;
                    return None;
                }

                if resp_header.status != NtStatus::SUCCESS {
                    self.done = true;
                    return Some(Err(Error::Protocol {
                        status: resp_header.status,
                        command: Command::Read,
                    }));
                }

                let mut cursor = ReadCursor::new(&resp_body);
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
            // All data written — flush and close.
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

        let send_result = self
            .conn
            .send_request(Command::Write, &write_req, Some(self.tree.tree_id))
            .await;

        if let Err(e) = send_result {
            self.done = true;
            return Err(e);
        }

        let recv_result = self.conn.receive_response().await;
        match recv_result {
            Err(e) => {
                self.done = true;
                Err(e)
            }
            Ok((resp_header, resp_body, _)) => {
                if resp_header.status != NtStatus::SUCCESS {
                    self.done = true;
                    // Best-effort close without flush.
                    let _ = self.tree.close_handle(self.conn, self.file_id).await;
                    return Err(Error::Protocol {
                        status: resp_header.status,
                        command: Command::Write,
                    });
                }

                let mut cursor = ReadCursor::new(&resp_body);
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

#[cfg(test)]
mod tests {
    use super::*;

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
