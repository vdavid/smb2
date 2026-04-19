//! High-level SMB2 client API.
//!
//! Provides [`SmbClient`] for easy connect-and-use access, plus lower-level
//! types: [`Connection`] for message exchange, [`Session`] for authenticated
//! sessions, [`Tree`] for share access with file operations, and [`Pipeline`]
//! for batched concurrent operations.

pub mod connection;
pub(crate) mod dfs;
pub mod pipeline;
pub mod session;
pub mod shares;
pub mod stream;
#[cfg(test)]
pub(crate) mod test_helpers;
pub mod tree;
pub mod watcher;

pub use crate::crypto::encryption::Cipher;
pub use connection::{Connection, Frame, NegotiatedParams};
pub use pipeline::{Op, OpResult, Pipeline};
pub use session::Session;
pub use shares::list_shares;
pub use stream::{FileDownload, FileUpload, FileWriter, Progress};
pub use tree::{DirectoryEntry, FileInfo, FsInfo, Tree};
pub use watcher::{FileNotifyAction, FileNotifyEvent, Watcher};

// Re-export high-level client types.
// (SmbClient, ClientConfig, and connect are defined below in this file.)

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::time::Duration;

use log::{debug, info};

use crate::client::dfs::DfsResolver;
use crate::error::{ErrorKind, Result};
use crate::pack::Unpack;
use crate::rpc::srvsvc::ShareInfo;
use crate::types::FileId;
use crate::Error;

/// Configuration for an SMB client connection.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server address (host:port).
    pub addr: String,
    /// Connection timeout.
    pub timeout: Duration,
    /// Username (empty for guest).
    pub username: String,
    /// Password (empty for guest).
    ///
    /// **Security note:** The password is stored in memory so that the client
    /// can reconnect without asking the user again. It is not encrypted in
    /// memory. Ensure the `SmbClient` is dropped when no longer needed.
    pub password: String,
    /// Domain (empty for local).
    pub domain: String,
    /// Whether to automatically reconnect on connection loss.
    ///
    /// When `true`, the client will attempt to reconnect with exponential
    /// backoff when a connection loss is detected. The actual auto-reconnect
    /// logic (retry with backoff, re-issue failed operations) will be
    /// implemented alongside the concurrent pipeline. For now this flag
    /// is stored so the API is ready.
    pub auto_reconnect: bool,
    /// Enable LZ4 compression for SMB 3.1.1 connections.
    /// When enabled, messages are compressed if it reduces their size.
    /// Incompressible data (photos, videos) is sent uncompressed automatically.
    /// Default: true.
    pub compression: bool,
    /// Enable DFS (Distributed File System) path resolution.
    ///
    /// When `true`, operations that receive a DFS referral response
    /// (`STATUS_PATH_NOT_COVERED`) automatically resolve the referral,
    /// connect to the target server, and retry the operation.
    /// Default: true.
    pub dfs_enabled: bool,
    /// Override addresses for DFS target servers.
    ///
    /// Maps server hostnames (as they appear in DFS referrals) to
    /// `host:port` socket addresses. Useful when DFS targets use
    /// internal hostnames that the client can't resolve, or when
    /// port mapping is needed (for example, Docker test environments).
    ///
    /// Default: empty (use the server hostname from the referral
    /// with port 445).
    pub dfs_target_overrides: std::collections::HashMap<String, String>,
}

/// A connection to a specific server with its authenticated session.
///
/// Used for DFS cross-server referrals where the client needs connections
/// to multiple servers simultaneously.
#[allow(dead_code)]
pub(crate) struct ConnectionEntry {
    /// The connection to the server.
    pub conn: Connection,
    /// The authenticated session on this connection.
    pub session: Session,
}

/// High-level SMB2 client with reconnection support.
///
/// Wraps a [`Connection`] + [`Session`] and provides methods for connecting
/// to shares, listing shares, and reconnecting after network failures.
///
/// **Security note:** This struct stores the password in memory so it can
/// reconnect without asking the user again. The password is not encrypted.
/// Drop the `SmbClient` when no longer needed.
pub struct SmbClient {
    config: ClientConfig,
    conn: Connection,
    session: Session,
    /// Server name of the primary connection (from `conn.server_name()`).
    primary_server: String,
    /// Extra connections for DFS cross-server targets, keyed by server name.
    extra_connections: HashMap<String, ConnectionEntry>,
    /// DFS referral resolver with TTL-based cache.
    dfs_resolver: DfsResolver,
}

impl SmbClient {
    /// Connect to an SMB server and authenticate.
    ///
    /// Performs TCP connect, negotiate, and session setup in one call.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        info!("smb_client: connecting to {}", config.addr);

        let mut conn = Connection::connect(&config.addr, config.timeout).await?;
        conn.set_compression_requested(config.compression);
        conn.negotiate().await?;

        let session = Session::setup(
            &mut conn,
            &config.username,
            &config.password,
            &config.domain,
        )
        .await?;

        info!(
            "smb_client: connected and authenticated, session_id={}, compression={}",
            session.session_id,
            conn.compression_enabled()
        );

        let primary_server = config.addr.clone();

        Ok(SmbClient {
            config,
            conn,
            session,
            primary_server,
            extra_connections: HashMap::new(),
            dfs_resolver: DfsResolver::new(),
        })
    }

    /// Connect using an existing connection and session (for testing).
    #[cfg(test)]
    pub(crate) fn from_parts(config: ClientConfig, conn: Connection, session: Session) -> Self {
        let primary_server = config.addr.clone();
        SmbClient {
            config,
            conn,
            session,
            primary_server,
            extra_connections: HashMap::new(),
            dfs_resolver: DfsResolver::new(),
        }
    }

    /// List available shares on the server.
    ///
    /// Connects to the IPC$ share, performs an RPC exchange via the srvsvc
    /// named pipe, and returns only disk shares (excluding admin shares
    /// ending with `$`).
    pub async fn list_shares(&mut self) -> Result<Vec<ShareInfo>> {
        shares::list_shares(&mut self.conn).await
    }

    /// Connect to a share on the server.
    ///
    /// If the share requires encryption (`SMB2_SHAREFLAG_ENCRYPT_DATA`)
    /// and encryption is not already active, encryption is activated
    /// using the session's keys.
    pub async fn connect_share(&mut self, share_name: &str) -> Result<Tree> {
        let mut tree = Tree::connect(&mut self.conn, share_name).await?;
        tree.server = self.primary_server.clone();

        // Activate encryption if the share requires it and it's not already active.
        // Fall back to AES-128-CCM if the server didn't send an encryption
        // negotiate context (same fallback as session-level encryption).
        if tree.encrypt_data && !self.conn.should_encrypt() {
            if let (Some(ref enc_key), Some(ref dec_key)) =
                (&self.session.encryption_key, &self.session.decryption_key)
            {
                let cipher = self
                    .conn
                    .params()
                    .and_then(|p| p.cipher)
                    .unwrap_or(crate::crypto::encryption::Cipher::Aes128Ccm);
                self.conn
                    .activate_encryption(enc_key.clone(), dec_key.clone(), cipher);
            }
        }

        Ok(tree)
    }

    /// Manually reconnect after a connection loss.
    ///
    /// Re-does TCP connect, negotiate, and session setup using the stored
    /// credentials. All previous tree connections and file handles are
    /// invalidated. The caller must re-do [`SmbClient::connect_share`] for
    /// any shares they need.
    pub async fn reconnect(&mut self) -> Result<()> {
        info!("smb_client: reconnecting to {}", self.config.addr);

        let conn = Connection::connect(&self.config.addr, self.config.timeout).await?;
        self.reconnect_with(conn).await
    }

    /// Reconnect using an already-established connection.
    ///
    /// Negotiates and authenticates on the given connection using stored
    /// credentials. This is the core reconnection logic, separated from
    /// TCP connect so it can be tested with mock transports.
    async fn reconnect_with(&mut self, mut conn: Connection) -> Result<()> {
        conn.set_compression_requested(self.config.compression);
        conn.negotiate().await?;

        let session = Session::setup(
            &mut conn,
            &self.config.username,
            &self.config.password,
            &self.config.domain,
        )
        .await?;

        self.primary_server = self.config.addr.clone();
        self.conn = conn;
        self.session = session;
        self.extra_connections.clear();

        info!(
            "smb_client: reconnected, new session_id={}",
            self.session.session_id
        );
        Ok(())
    }

    /// Get the negotiated parameters.
    pub fn params(&self) -> Option<&NegotiatedParams> {
        self.conn.params()
    }

    /// Get the session info.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Get the client config.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Current number of available credits.
    pub fn credits(&self) -> u16 {
        self.conn.credits()
    }

    /// Estimated round-trip time from the negotiate exchange.
    pub fn estimated_rtt(&self) -> Option<Duration> {
        self.conn.estimated_rtt()
    }

    /// Get a mutable reference to the underlying connection.
    ///
    /// Needed when using [`Tree`] methods directly, since they require
    /// `&mut Connection`. For most use cases, prefer the convenience methods
    /// on `SmbClient` (like [`list_directory`](Self::list_directory)) instead.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Get a mutable reference to the connection that owns the given tree.
    ///
    /// Routes through the primary connection when the tree's server matches,
    /// or through an extra connection established for a DFS cross-server
    /// referral.
    pub(crate) fn connection_for_tree(&mut self, tree: &Tree) -> &mut Connection {
        if tree.server == self.primary_server {
            &mut self.conn
        } else {
            &mut self
                .extra_connections
                .get_mut(&tree.server)
                .expect("no connection for tree server")
                .conn
        }
    }

    // ── DFS helpers ───────────────────────────────────────────────────

    /// Handle a DFS redirect by resolving the referral, connecting to
    /// the target server (creating a new connection if needed), and
    /// updating the tree in-place.
    ///
    /// Returns the resolved remaining path to use for the retry.
    async fn handle_dfs_redirect(
        &mut self,
        tree: &mut Tree,
        original_path: &str,
    ) -> Result<String> {
        // Extract hostname (strip port) for UNC path construction.
        let hostname = tree
            .server
            .split(':')
            .next()
            .unwrap_or(&tree.server)
            .to_string();
        let share = tree.share_name.clone();
        let normalized = original_path.replace('/', "\\");
        let unc_path = format!("\\\\{}\\{}\\{}", hostname, share, normalized);

        debug!("dfs: resolving {}", unc_path);

        // Resolve the referral (uses cache or IOCTL).
        // We inline the connection lookup to avoid borrowing both
        // `self.dfs_resolver` and `self` (via connection_for_tree)
        // at the same time.
        let conn = if tree.server == self.primary_server {
            &mut self.conn
        } else {
            &mut self
                .extra_connections
                .get_mut(&tree.server)
                .expect("no connection for tree server")
                .conn
        };
        let resolved_list = self.dfs_resolver.resolve(conn, &unc_path).await?;

        // Try each target (multi-target failover).
        let mut last_error = None;
        for resolved in &resolved_list {
            let target_addr = self
                .config
                .dfs_target_overrides
                .get(&resolved.server)
                .cloned()
                .unwrap_or_else(|| format!("{}:{}", resolved.server, resolved.port));

            // Get or create connection to target server.
            match self.ensure_connection(&target_addr).await {
                Ok(()) => {}
                Err(e) => {
                    debug!("dfs: failed to connect to {}: {}", target_addr, e);
                    last_error = Some(e);
                    continue;
                }
            }

            // Get or create tree on the target share.
            match self.ensure_tree(&target_addr, &resolved.share).await {
                Ok(new_tree) => {
                    // Update the caller's tree in-place.
                    *tree = new_tree;
                    return Ok(resolved.remaining_path.clone());
                }
                Err(e) => {
                    debug!(
                        "dfs: failed to connect to share {} on {}: {}",
                        resolved.share, target_addr, e
                    );
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::invalid_data("DFS: no targets in referral")))
    }

    /// Ensure a connection exists in the pool for the given server address.
    async fn ensure_connection(&mut self, target_addr: &str) -> Result<()> {
        if target_addr == self.primary_server {
            return Ok(()); // Already have primary connection.
        }
        if self.extra_connections.contains_key(target_addr) {
            return Ok(()); // Already in pool.
        }

        // Create new connection to target.
        let mut conn = Connection::connect(target_addr, self.config.timeout).await?;
        conn.set_compression_requested(self.config.compression);
        conn.negotiate().await?;

        // Authenticate with same credentials.
        let session = Session::setup(
            &mut conn,
            &self.config.username,
            &self.config.password,
            &self.config.domain,
        )
        .await?;

        self.extra_connections
            .insert(target_addr.to_string(), ConnectionEntry { conn, session });
        Ok(())
    }

    /// Ensure a tree-connect exists for the given server and share.
    async fn ensure_tree(&mut self, target_addr: &str, share: &str) -> Result<Tree> {
        let conn = if target_addr == self.primary_server {
            &mut self.conn
        } else {
            &mut self
                .extra_connections
                .get_mut(target_addr)
                .ok_or_else(|| Error::invalid_data("DFS: no connection for target"))?
                .conn
        };

        let mut tree = Tree::connect(conn, share).await?;
        // Override server to the full addr:port so connection_for_tree
        // can distinguish targets that share the same hostname but
        // use different ports (for example, Docker port-mapped containers).
        tree.server = target_addr.to_string();
        Ok(tree)
    }

    /// Check whether a DFS retry should be attempted for the given error.
    fn should_retry_dfs(&self, err: &Error) -> bool {
        self.config.dfs_enabled && err.kind() == ErrorKind::DfsReferral
    }

    // ── Convenience methods that delegate to Tree ──────────────────────

    /// List files in a directory on the given share.
    ///
    /// This is a convenience wrapper around [`Tree::list_directory`] that
    /// saves you from threading `connection_mut()` through every call.
    /// If the server returns a DFS referral, the tree is updated in-place
    /// and the operation is retried on the target server.
    pub async fn list_directory(
        &mut self,
        tree: &mut Tree,
        path: &str,
    ) -> Result<Vec<DirectoryEntry>> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.list_directory(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.list_directory(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Read a file from the given share.
    pub async fn read_file(&mut self, tree: &mut Tree, path: &str) -> Result<Vec<u8>> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.read_file(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.read_file(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Read a small file using a compound CREATE+READ+CLOSE request.
    ///
    /// Sends all three operations in a single transport frame, reducing
    /// round-trips from 3 to 1. Best for files that fit in a single
    /// READ (up to MaxReadSize, typically 8 MB).
    pub async fn read_file_compound(&mut self, tree: &mut Tree, path: &str) -> Result<Vec<u8>> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.read_file_compound(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.read_file_compound(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Read a file using pipelined I/O (faster for large files).
    pub async fn read_file_pipelined(&mut self, tree: &mut Tree, path: &str) -> Result<Vec<u8>> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.read_file_pipelined(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.read_file_pipelined(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Write data to a file on the given share (create or overwrite).
    pub async fn write_file(&mut self, tree: &mut Tree, path: &str, data: &[u8]) -> Result<u64> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.write_file(conn, path, data).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.write_file(conn, &new_path, data).await
            }
            other => other,
        }
    }

    /// Write a small file using a compound CREATE+WRITE+FLUSH+CLOSE request.
    ///
    /// Sends all four operations in a single transport frame, reducing
    /// round-trips from 4 to 1. Best for files that fit in MaxWriteSize
    /// (typically 64 KB to 8 MB). For larger files, use
    /// [`write_file_pipelined`](Self::write_file_pipelined).
    pub async fn write_file_compound(
        &mut self,
        tree: &mut Tree,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.write_file_compound(conn, path, data).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.write_file_compound(conn, &new_path, data).await
            }
            other => other,
        }
    }

    /// Write data to a file using pipelined I/O (faster for large files).
    pub async fn write_file_pipelined(
        &mut self,
        tree: &mut Tree,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.write_file_pipelined(conn, path, data).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.write_file_pipelined(conn, &new_path, data).await
            }
            other => other,
        }
    }

    /// Query file system space information for the given share.
    ///
    /// Returns total capacity, free space, and allocation unit sizes.
    /// Uses a compound CREATE+QUERY_INFO+CLOSE for efficiency (one round-trip).
    pub async fn fs_info(&mut self, tree: &mut Tree) -> Result<tree::FsInfo> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.fs_info(conn).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                // fs_info has no path argument -- the DFS redirect uses
                // the root of the share as the path.
                let _new_path = self.handle_dfs_redirect(tree, "").await?;
                let conn = self.connection_for_tree(tree);
                tree.fs_info(conn).await
            }
            other => other,
        }
    }

    /// Delete a file on the given share.
    pub async fn delete_file(&mut self, tree: &mut Tree, path: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.delete_file(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.delete_file(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Delete multiple files on the given share in a single batch.
    ///
    /// Sends all requests before waiting for responses, minimizing
    /// round-trips. Returns results in the same order as the input paths.
    ///
    /// Note: DFS retry is not applied to batch operations. If the share
    /// is a DFS target, perform a single-file operation first to trigger
    /// the redirect, then use the batch method on the resolved tree.
    pub async fn delete_files(&mut self, tree: &mut Tree, paths: &[&str]) -> Vec<Result<()>> {
        let conn = self.connection_for_tree(tree);
        tree.delete_files(conn, paths).await
    }

    /// Get file metadata (size, timestamps, whether it's a directory).
    pub async fn stat(&mut self, tree: &mut Tree, path: &str) -> Result<FileInfo> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.stat(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.stat(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Stat multiple files on the given share in a single batch.
    ///
    /// Sends all requests before waiting for responses, minimizing
    /// round-trips. Returns results in the same order as the input paths.
    ///
    /// Note: DFS retry is not applied to batch operations. If the share
    /// is a DFS target, perform a single-file operation first to trigger
    /// the redirect, then use the batch method on the resolved tree.
    pub async fn stat_files(&mut self, tree: &mut Tree, paths: &[&str]) -> Vec<Result<FileInfo>> {
        let conn = self.connection_for_tree(tree);
        tree.stat_files(conn, paths).await
    }

    /// Rename a file or directory on the given share.
    pub async fn rename(&mut self, tree: &mut Tree, from: &str, to: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.rename(conn, from, to).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, from).await?;
                let conn = self.connection_for_tree(tree);
                tree.rename(conn, &new_path, to).await
            }
            other => other,
        }
    }

    /// Rename multiple files on the given share in a single batch.
    ///
    /// Sends all requests before waiting for responses, minimizing
    /// round-trips. Returns results in the same order as the input pairs.
    ///
    /// Note: DFS retry is not applied to batch operations. If the share
    /// is a DFS target, perform a single-file operation first to trigger
    /// the redirect, then use the batch method on the resolved tree.
    pub async fn rename_files(
        &mut self,
        tree: &mut Tree,
        renames: &[(&str, &str)],
    ) -> Vec<Result<()>> {
        let conn = self.connection_for_tree(tree);
        tree.rename_files(conn, renames).await
    }

    /// Create a directory on the given share.
    pub async fn create_directory(&mut self, tree: &mut Tree, path: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.create_directory(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.create_directory(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Delete an empty directory on the given share.
    pub async fn delete_directory(&mut self, tree: &mut Tree, path: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree);
            tree.delete_directory(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree);
                tree.delete_directory(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Start a streaming file download (memory-efficient for large files).
    ///
    /// Returns a [`FileDownload`] that yields chunks one at a time without
    /// buffering the entire file in memory. Each call to
    /// [`next_chunk`](FileDownload::next_chunk) sends one READ request.
    ///
    /// The connection is borrowed mutably for the lifetime of the download,
    /// so no other operations can run concurrently. This prevents accidental
    /// interleaving of SMB messages.
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
    pub async fn download<'a>(
        &'a mut self,
        tree: &'a Tree,
        path: &str,
    ) -> Result<FileDownload<'a>> {
        let normalized = path.replace('/', "\\");
        let normalized = normalized.trim_start_matches('\\');

        let (file_id, file_size) = tree.open_file(&mut self.conn, normalized).await?;
        let chunk_size = self.conn.params().map(|p| p.max_read_size).unwrap_or(65536);

        Ok(FileDownload::new(
            tree,
            &mut self.conn,
            file_id,
            file_size,
            chunk_size,
        ))
    }

    /// Start a streaming file upload with progress tracking.
    ///
    /// Returns a [`FileUpload`] that writes data in chunks. Each call to
    /// [`write_next_chunk`](FileUpload::write_next_chunk) sends one WRITE
    /// request and reports progress.
    ///
    /// For small files (data fits in one MaxWriteSize), the data is written
    /// immediately via a compound CREATE+WRITE+FLUSH+CLOSE request in the
    /// constructor. The returned `FileUpload` is already complete, and
    /// `write_next_chunk` returns `false` immediately. This gives the caller
    /// a uniform API regardless of file size.
    ///
    /// The connection is borrowed mutably for the lifetime of the upload,
    /// so no other operations can run concurrently. This prevents accidental
    /// interleaving of SMB messages.
    ///
    /// # Example
    ///
    /// ```ignore
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
    pub async fn upload<'a>(
        &'a mut self,
        tree: &'a Tree,
        path: &str,
        data: &'a [u8],
    ) -> Result<stream::FileUpload<'a>> {
        let normalized = path.replace('/', "\\");
        let normalized = normalized.trim_start_matches('\\');

        let max_write = self
            .conn
            .params()
            .map(|p| p.max_write_size as usize)
            .unwrap_or(65536);

        if data.len() <= max_write {
            // Small file: write everything via compound in one round-trip.
            tree.write_file_compound(&mut self.conn, normalized, data)
                .await?;
            Ok(stream::FileUpload::new_done(
                tree,
                &mut self.conn,
                data.len() as u64,
            ))
        } else {
            // Large file: open the file, let the caller drive chunks.
            let file_id = tree.open_file_for_write(&mut self.conn, normalized).await?;
            let chunk_size = max_write as u32;
            Ok(stream::FileUpload::new(
                tree,
                &mut self.conn,
                file_id,
                data,
                chunk_size,
            ))
        }
    }

    /// Create a push-based pipelined streaming file writer.
    ///
    /// Opens (or creates) the file for writing and returns a [`FileWriter`]
    /// that the caller drives by pushing data chunks. No DFS retry (the
    /// returned handle borrows the tree for its lifetime).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
    /// let mut writer = client.create_file_writer(&share, "output.bin").await?;
    /// writer.write_chunk(b"hello").await?;
    /// writer.write_chunk(b" world").await?;
    /// let total = writer.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_file_writer<'a>(
        &'a mut self,
        tree: &'a Tree,
        path: &str,
    ) -> Result<stream::FileWriter<'a>> {
        tree.create_file_writer(&mut self.conn, path).await
    }

    /// Read a file with progress reporting and cancellation.
    ///
    /// Uses pipelined I/O for performance, calling `on_progress` after each
    /// chunk is received. Return `ControlFlow::Break(())` to cancel the read.
    pub async fn read_file_with_progress<F>(
        &mut self,
        tree: &mut Tree,
        path: &str,
        on_progress: F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(Progress) -> ControlFlow<()>,
    {
        // DFS retry is not straightforward with progress callbacks (the
        // callback is consumed by the first attempt). For now, attempt
        // the operation directly. If DFS redirect is needed, the caller
        // should resolve the tree first using a simpler method.
        let conn = self.connection_for_tree(tree);
        tree.read_file_pipelined_with_progress(conn, path, on_progress)
            .await
    }

    /// Write a file with progress reporting and cancellation.
    ///
    /// Writes data in chunks, calling `on_progress` after each chunk.
    /// Return `ControlFlow::Break(())` to cancel the write.
    ///
    /// The file is flushed before closing to ensure data is persisted
    /// on the server.
    pub async fn write_file_with_progress<F>(
        &mut self,
        tree: &mut Tree,
        path: &str,
        data: &[u8],
        mut on_progress: F,
    ) -> Result<u64>
    where
        F: FnMut(Progress) -> ControlFlow<()>,
    {
        let normalized = path.replace('/', "\\");
        let normalized = normalized.trim_start_matches('\\');

        // Open the file for writing.
        let req = crate::msg::create::CreateRequest {
            requested_oplock_level: crate::types::OplockLevel::None,
            impersonation_level: crate::msg::create::ImpersonationLevel::Impersonation,
            desired_access: crate::types::flags::FileAccessMask::new(
                crate::types::flags::FileAccessMask::FILE_WRITE_DATA
                    | crate::types::flags::FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | crate::types::flags::FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            share_access: crate::msg::create::ShareAccess(0),
            create_disposition: crate::msg::create::CreateDisposition::FileOverwriteIf,
            create_options: 0x0000_0040, // FILE_NON_DIRECTORY_FILE
            name: normalized.to_string(),
            create_contexts: vec![],
        };

        let (_, _) = self
            .conn
            .send_request(crate::types::Command::Create, &req, Some(tree.tree_id))
            .await?;

        let (resp_header, resp_body, _) = self.conn.receive_response().await?;

        if resp_header.status != crate::types::status::NtStatus::SUCCESS {
            return Err(crate::Error::Protocol {
                status: resp_header.status,
                command: crate::types::Command::Create,
            });
        }

        let mut cursor = crate::pack::ReadCursor::new(&resp_body);
        let create_resp = crate::msg::create::CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        let max_write = self
            .conn
            .params()
            .map(|p| p.max_write_size)
            .unwrap_or(65536);

        let mut total_written = 0u64;
        let mut offset = 0usize;
        let mut cancelled = false;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = remaining.min(max_write as usize);
            let chunk = &data[offset..offset + chunk_size];

            let write_req = crate::msg::write::WriteRequest {
                data_offset: 0x70,
                offset: offset as u64,
                file_id,
                channel: 0,
                remaining_bytes: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: 0,
                data: chunk.to_vec(),
            };

            let credit_charge = (chunk_size as u64).div_ceil(65536).max(1) as u16;
            let (_, _) = self
                .conn
                .send_request_with_credits(
                    crate::types::Command::Write,
                    &write_req,
                    Some(tree.tree_id),
                    credit_charge,
                )
                .await?;

            let (resp_header, resp_body, _) = self.conn.receive_response().await?;

            if resp_header.status != crate::types::status::NtStatus::SUCCESS {
                // Close handle before returning error.
                let _ = tree.close_handle(&mut self.conn, file_id).await;
                return Err(crate::Error::Protocol {
                    status: resp_header.status,
                    command: crate::types::Command::Write,
                });
            }

            let mut cursor = crate::pack::ReadCursor::new(&resp_body);
            let resp = crate::msg::write::WriteResponse::unpack(&mut cursor)?;

            total_written += resp.count as u64;
            offset += chunk_size;

            let progress = Progress {
                bytes_transferred: total_written,
                total_bytes: Some(data.len() as u64),
            };

            if let ControlFlow::Break(()) = on_progress(progress) {
                cancelled = true;
                break;
            }
        }

        if cancelled {
            // Best-effort close without flush.
            let _ = tree.close_handle(&mut self.conn, file_id).await;
            return Err(crate::Error::Cancelled);
        }

        // Flush to ensure data is persisted.
        tree.flush_handle(&mut self.conn, file_id).await?;

        // Close the handle.
        tree.close_handle(&mut self.conn, file_id).await?;

        Ok(total_written)
    }

    /// Write a file from a streaming source using pipelined I/O.
    ///
    /// Pulls data on demand from a callback, so you never need the full
    /// file in memory. See [`Tree::write_file_streamed`] for the full
    /// callback contract, performance characteristics, and usage guide.
    ///
    /// DFS retry is not supported for streamed writes (the callback is
    /// consumed by the first attempt). If the share uses DFS, resolve
    /// the tree first using a simpler method.
    pub async fn write_file_streamed<F>(
        &mut self,
        tree: &mut Tree,
        path: &str,
        next_chunk: &mut F,
    ) -> Result<u64>
    where
        F: FnMut() -> Option<std::result::Result<Vec<u8>, std::io::Error>>,
    {
        let conn = self.connection_for_tree(tree);
        tree.write_file_streamed(conn, path, next_chunk).await
    }

    /// Flush a file to ensure data is persisted on the server.
    ///
    /// This sends an SMB2 FLUSH request for the given file handle.
    /// Write methods (`write_file`, `write_file_pipelined`,
    /// `write_file_with_progress`) flush automatically before closing.
    /// Use this if you need to flush a handle obtained through the
    /// low-level API.
    pub async fn flush_file(&mut self, tree: &mut Tree, file_id: FileId) -> Result<()> {
        let conn = self.connection_for_tree(tree);
        tree.flush_handle(conn, file_id).await
    }

    /// Watch a directory for changes.
    ///
    /// Opens the directory and returns a [`Watcher`] that yields change
    /// events. The server holds each request until changes occur (long poll).
    ///
    /// Set `recursive` to `true` to watch the entire subtree.
    ///
    /// The returned `Watcher` borrows the connection mutably, so no other
    /// operations can run on this client while watching. Use a separate
    /// `SmbClient` (second TCP connection) to perform operations during a watch.
    pub async fn watch<'a>(
        &'a mut self,
        tree: &'a Tree,
        path: &str,
        recursive: bool,
    ) -> Result<Watcher<'a>> {
        tree.watch(&mut self.conn, path, recursive).await
    }

    /// Disconnect from a share.
    pub async fn disconnect_share(&mut self, tree: &Tree) -> Result<()> {
        let conn = self.connection_for_tree(tree);
        tree.disconnect(conn).await
    }
}

/// Connect to an SMB server with the simplest possible API.
///
/// This is a shorthand for creating a [`ClientConfig`] and calling
/// [`SmbClient::connect`]. Uses a five-second timeout and no auto-reconnect.
pub async fn connect(addr: &str, username: &str, password: &str) -> Result<SmbClient> {
    SmbClient::connect(ClientConfig {
        addr: addr.to_string(),
        timeout: Duration::from_secs(5),
        username: username.to_string(),
        password: password.to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
        dfs_target_overrides: std::collections::HashMap::new(),
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::connection::pack_message;
    use crate::msg::header::Header;
    use crate::msg::negotiate::{NegotiateContext, NegotiateResponse, HASH_ALGORITHM_SHA512};
    use crate::msg::session_setup::{SessionFlags, SessionSetupResponse};
    use crate::msg::tree_connect::ShareType;
    use crate::pack::Guid;
    use crate::transport::MockTransport;
    use crate::types::flags::{Capabilities, SecurityMode};
    use crate::types::status::NtStatus;
    use crate::types::{Command, Dialect, SessionId, TreeId};
    use std::sync::Arc;

    /// Build a negotiate response.
    fn build_negotiate_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::Negotiate);
        h.flags.set_response();
        h.credits = 32;
        let body = NegotiateResponse {
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            dialect_revision: Dialect::Smb3_1_1,
            server_guid: Guid::ZERO,
            capabilities: Capabilities::new(Capabilities::DFS | Capabilities::LEASING),
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: 132_000_000_000_000_000,
            server_start_time: 131_000_000_000_000_000,
            security_buffer: vec![0x60, 0x00],
            negotiate_contexts: vec![NegotiateContext::PreauthIntegrity {
                hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                salt: vec![0xBB; 32],
            }],
        };
        pack_message(&h, &body)
    }

    /// Build a session setup response.
    fn build_session_setup_response(
        status: NtStatus,
        session_id: SessionId,
        security_buffer: Vec<u8>,
        session_flags: SessionFlags,
    ) -> Vec<u8> {
        let mut h = Header::new_request(Command::SessionSetup);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;
        h.session_id = session_id;

        let body = SessionSetupResponse {
            session_flags,
            security_buffer,
        };

        pack_message(&h, &body)
    }

    /// Build a minimal NTLM challenge message (Type 2).
    fn build_ntlm_challenge() -> Vec<u8> {
        let mut buf = Vec::new();

        // Signature
        buf.extend_from_slice(b"NTLMSSP\0");
        // MessageType = 2
        buf.extend_from_slice(&2u32.to_le_bytes());
        // TargetNameFields: Len=0, MaxLen=0, Offset=56
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        // NegotiateFlags
        let flags: u32 = 0x0000_0001 // UNICODE
            | 0x0000_0200  // NTLM
            | 0x0008_0000  // EXTENDED_SESSIONSECURITY
            | 0x0080_0000  // TARGET_INFO
            | 0x2000_0000  // 128
            | 0x4000_0000  // KEY_EXCH
            | 0x8000_0000  // 56
            | 0x0000_0010  // SIGN
            | 0x0000_0020; // SEAL
        buf.extend_from_slice(&flags.to_le_bytes());
        // ServerChallenge
        buf.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        // Reserved
        buf.extend_from_slice(&[0u8; 8]);
        // TargetInfoFields
        let target_info = {
            let mut ti = Vec::new();
            ti.extend_from_slice(&0u16.to_le_bytes()); // MsvAvEOL AvId=0
            ti.extend_from_slice(&0u16.to_le_bytes()); // AvLen=0
            ti
        };
        let ti_offset = 56u32;
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        buf.extend_from_slice(&ti_offset.to_le_bytes());
        while buf.len() < 56 {
            buf.push(0);
        }
        buf.extend_from_slice(&target_info);
        buf
    }

    /// Queue negotiate + session setup responses on a mock transport.
    fn queue_negotiate_and_session(mock: &MockTransport, session_id: SessionId) {
        mock.queue_response(build_negotiate_response());

        let challenge = build_ntlm_challenge();
        mock.queue_response(build_session_setup_response(
            NtStatus::MORE_PROCESSING_REQUIRED,
            session_id,
            challenge,
            SessionFlags(0),
        ));

        mock.queue_response(build_session_setup_response(
            NtStatus::SUCCESS,
            session_id,
            vec![],
            SessionFlags(0),
        ));
    }

    /// Create a mock-backed SmbClient without going through TCP.
    async fn make_mock_client(mock: &Arc<MockTransport>, session_id: SessionId) -> SmbClient {
        queue_negotiate_and_session(mock, session_id);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        // Mock responses use default MessageId(0); orphan filter would drop
        // them after the first. See setup_connection in test_helpers.rs.
        conn.set_orphan_filter_enabled(false);

        conn.negotiate().await.unwrap();

        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();

        let config = ClientConfig {
            addr: "test-server:445".to_string(),
            timeout: Duration::from_secs(5),
            username: "user".to_string(),
            password: "pass".to_string(),
            domain: String::new(),
            auto_reconnect: false,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: std::collections::HashMap::new(),
        };

        SmbClient::from_parts(config, conn, session)
    }

    #[tokio::test]
    async fn smb_client_connect_via_mock_negotiates_and_authenticates() {
        let mock = Arc::new(MockTransport::new());
        let session_id = SessionId(0xABCD);

        let client = make_mock_client(&mock, session_id).await;

        assert_eq!(client.session().session_id, session_id);
        assert!(client.params().is_some());
        assert_eq!(client.params().unwrap().dialect, Dialect::Smb3_1_1);
    }

    #[tokio::test]
    async fn smb_client_stores_config() {
        let mock = Arc::new(MockTransport::new());
        let client = make_mock_client(&mock, SessionId(1)).await;

        assert_eq!(client.config().addr, "test-server:445");
        assert_eq!(client.config().username, "user");
        assert_eq!(client.config().password, "pass");
        assert!(!client.config().auto_reconnect);
    }

    #[tokio::test]
    async fn smb_client_connect_share_returns_tree() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(1)).await;

        // Queue tree connect response.
        mock.queue_response(crate::client::test_helpers::build_tree_connect_response(
            TreeId(42),
            ShareType::Disk,
        ));

        let tree = client.connect_share("TestShare").await.unwrap();
        assert_eq!(tree.tree_id, TreeId(42));
        assert_eq!(tree.share_name, "TestShare");
    }

    #[tokio::test]
    async fn smb_client_reconnect_creates_new_session() {
        let mock = Arc::new(MockTransport::new());
        let original_session_id = SessionId(0x1111);
        let mut client = make_mock_client(&mock, original_session_id).await;

        // Verify original session.
        assert_eq!(client.session().session_id, original_session_id);

        // Create a new mock for the "reconnected" transport.
        let mock2 = Arc::new(MockTransport::new());
        let new_session_id = SessionId(0x2222);
        queue_negotiate_and_session(mock2.as_ref(), new_session_id);

        let mut new_conn = Connection::from_transport(
            Box::new(mock2.clone()),
            Box::new(mock2.clone()),
            "test-server",
        );
        new_conn.set_orphan_filter_enabled(false);

        client.reconnect_with(new_conn).await.unwrap();

        // Session should be new.
        assert_eq!(client.session().session_id, new_session_id);
    }

    #[tokio::test]
    async fn smb_client_reconnect_invalidates_old_params() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x1111)).await;

        // Get old params for comparison.
        let old_server_guid = client.params().unwrap().server_guid;

        // Create a new mock for the "reconnected" transport.
        let mock2 = Arc::new(MockTransport::new());
        queue_negotiate_and_session(mock2.as_ref(), SessionId(0x2222));

        let mut new_conn = Connection::from_transport(
            Box::new(mock2.clone()),
            Box::new(mock2.clone()),
            "test-server",
        );
        new_conn.set_orphan_filter_enabled(false);

        client.reconnect_with(new_conn).await.unwrap();

        // Params should be freshly negotiated (same values in this mock,
        // but the connection is new).
        assert!(client.params().is_some());
        assert_eq!(client.params().unwrap().server_guid, old_server_guid);
    }

    #[tokio::test]
    async fn smb_client_auto_reconnect_flag_stored() {
        let mock = Arc::new(MockTransport::new());
        queue_negotiate_and_session(mock.as_ref(), SessionId(1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.negotiate().await.unwrap();
        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();

        let config = ClientConfig {
            addr: "test-server:445".to_string(),
            timeout: Duration::from_secs(5),
            username: "user".to_string(),
            password: "pass".to_string(),
            domain: String::new(),
            auto_reconnect: true,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: std::collections::HashMap::new(),
        };

        let client = SmbClient::from_parts(config, conn, session);
        assert!(client.config().auto_reconnect);
    }

    #[tokio::test]
    async fn smb_client_connection_mut_returns_connection() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(1)).await;

        // Verify we can access the connection.
        assert!(client.connection_mut().params().is_some());
    }

    #[tokio::test]
    async fn smb_client_list_shares_delegates_to_shares_module() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x5555)).await;

        // Queue the full share listing flow (same as shares module tests).
        // This verifies SmbClient.list_shares() delegates correctly.
        use crate::client::shares::tests::queue_share_listing_responses;
        queue_share_listing_responses(
            &mock,
            &[
                (
                    "Documents",
                    crate::rpc::srvsvc::STYPE_DISKTREE,
                    "Shared docs",
                ),
                (
                    "IPC$",
                    crate::rpc::srvsvc::STYPE_IPC | crate::rpc::srvsvc::STYPE_SPECIAL,
                    "Remote IPC",
                ),
            ],
        );

        let shares = client.list_shares().await.unwrap();

        // Only disk shares returned.
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "Documents");
    }
}
