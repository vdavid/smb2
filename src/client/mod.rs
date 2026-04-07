//! High-level SMB2 client API.
//!
//! Provides [`SmbClient`] for easy connect-and-use access, plus lower-level
//! types: [`Connection`] for message exchange, [`Session`] for authenticated
//! sessions, [`Tree`] for share access with file operations, and [`Pipeline`]
//! for batched concurrent operations.

pub mod connection;
pub mod pipeline;
pub mod session;
pub mod shares;
pub mod tree;

pub use connection::{Cipher, Connection, NegotiatedParams};
pub use pipeline::{Op, OpResult, Pipeline};
pub use session::Session;
pub use shares::list_shares;
pub use tree::{DirectoryEntry, FileInfo, Tree};

// Re-export high-level client types.
// (SmbClient, ClientConfig, and connect are defined below in this file.)

use std::time::Duration;

use log::info;

use crate::error::Result;
use crate::rpc::srvsvc::ShareInfo;

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
}

impl SmbClient {
    /// Connect to an SMB server and authenticate.
    ///
    /// Performs TCP connect, negotiate, and session setup in one call.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        info!("smb_client: connecting to {}", config.addr);

        let mut conn = Connection::connect(&config.addr, config.timeout).await?;
        conn.negotiate().await?;

        let session = Session::setup(
            &mut conn,
            &config.username,
            &config.password,
            &config.domain,
        )
        .await?;

        info!(
            "smb_client: connected and authenticated, session_id={}",
            session.session_id
        );

        Ok(SmbClient {
            config,
            conn,
            session,
        })
    }

    /// Connect using an existing connection and session (for testing).
    #[cfg(test)]
    pub(crate) fn from_parts(config: ClientConfig, conn: Connection, session: Session) -> Self {
        SmbClient {
            config,
            conn,
            session,
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
    pub async fn connect_share(&mut self, share_name: &str) -> Result<Tree> {
        Tree::connect(&mut self.conn, share_name).await
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
        conn.negotiate().await?;

        let session = Session::setup(
            &mut conn,
            &self.config.username,
            &self.config.password,
            &self.config.domain,
        )
        .await?;

        self.conn = conn;
        self.session = session;

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

    /// Get a mutable reference to the underlying connection.
    ///
    /// Needed when using [`Tree`] methods directly, since they require
    /// `&mut Connection`. For most use cases, prefer the convenience methods
    /// on `SmbClient` (like [`list_directory`](Self::list_directory)) instead.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    // ── Convenience methods that delegate to Tree ──────────────────────

    /// List files in a directory on the given share.
    ///
    /// This is a convenience wrapper around [`Tree::list_directory`] that
    /// saves you from threading `connection_mut()` through every call.
    pub async fn list_directory(
        &mut self,
        tree: &Tree,
        path: &str,
    ) -> Result<Vec<DirectoryEntry>> {
        tree.list_directory(&mut self.conn, path).await
    }

    /// Read a file from the given share.
    pub async fn read_file(&mut self, tree: &Tree, path: &str) -> Result<Vec<u8>> {
        tree.read_file(&mut self.conn, path).await
    }

    /// Read a file using pipelined I/O (faster for large files).
    pub async fn read_file_pipelined(&mut self, tree: &Tree, path: &str) -> Result<Vec<u8>> {
        tree.read_file_pipelined(&mut self.conn, path).await
    }

    /// Write data to a file on the given share (create or overwrite).
    pub async fn write_file(
        &mut self,
        tree: &Tree,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        tree.write_file(&mut self.conn, path, data).await
    }

    /// Write data to a file using pipelined I/O (faster for large files).
    pub async fn write_file_pipelined(
        &mut self,
        tree: &Tree,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        tree.write_file_pipelined(&mut self.conn, path, data).await
    }

    /// Delete a file on the given share.
    pub async fn delete_file(&mut self, tree: &Tree, path: &str) -> Result<()> {
        tree.delete_file(&mut self.conn, path).await
    }

    /// Get file metadata (size, timestamps, whether it's a directory).
    pub async fn stat(&mut self, tree: &Tree, path: &str) -> Result<FileInfo> {
        tree.stat(&mut self.conn, path).await
    }

    /// Rename a file or directory on the given share.
    pub async fn rename(&mut self, tree: &Tree, from: &str, to: &str) -> Result<()> {
        tree.rename(&mut self.conn, from, to).await
    }

    /// Create a directory on the given share.
    pub async fn create_directory(&mut self, tree: &Tree, path: &str) -> Result<()> {
        tree.create_directory(&mut self.conn, path).await
    }

    /// Delete an empty directory on the given share.
    pub async fn delete_directory(&mut self, tree: &Tree, path: &str) -> Result<()> {
        tree.delete_directory(&mut self.conn, path).await
    }

    /// Disconnect from a share.
    pub async fn disconnect_share(&mut self, tree: &Tree) -> Result<()> {
        tree.disconnect(&mut self.conn).await
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
    use crate::msg::tree_connect::{ShareType, TreeConnectResponse};
    use crate::msg::tree_disconnect::TreeDisconnectResponse;
    use crate::pack::Guid;
    use crate::transport::MockTransport;
    use crate::types::flags::{Capabilities, SecurityMode, ShareCapabilities, ShareFlags};
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

        conn.negotiate().await.unwrap();

        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();

        let config = ClientConfig {
            addr: "test-server:445".to_string(),
            timeout: Duration::from_secs(5),
            username: "user".to_string(),
            password: "pass".to_string(),
            domain: String::new(),
            auto_reconnect: false,
        };

        SmbClient::from_parts(config, conn, session)
    }

    /// Build a tree connect response.
    fn build_tree_connect_response(tree_id: TreeId) -> Vec<u8> {
        let mut h = Header::new_request(Command::TreeConnect);
        h.flags.set_response();
        h.credits = 32;
        h.tree_id = Some(tree_id);

        let body = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::default(),
            capabilities: ShareCapabilities::default(),
            maximal_access: 0x001F01FF,
        };

        pack_message(&h, &body)
    }

    /// Build a tree disconnect response.
    #[allow(dead_code)]
    fn build_tree_disconnect_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::TreeDisconnect);
        h.flags.set_response();
        h.credits = 32;
        pack_message(&h, &TreeDisconnectResponse)
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
        mock.queue_response(build_tree_connect_response(TreeId(42)));

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

        let new_conn = Connection::from_transport(
            Box::new(mock2.clone()),
            Box::new(mock2.clone()),
            "test-server",
        );

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

        let new_conn = Connection::from_transport(
            Box::new(mock2.clone()),
            Box::new(mock2.clone()),
            "test-server",
        );

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
        conn.negotiate().await.unwrap();
        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();

        let config = ClientConfig {
            addr: "test-server:445".to_string(),
            timeout: Duration::from_secs(5),
            username: "user".to_string(),
            password: "pass".to_string(),
            domain: String::new(),
            auto_reconnect: true,
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
                ("Documents", crate::rpc::srvsvc::STYPE_DISKTREE, "Shared docs"),
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
