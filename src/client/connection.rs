//! Connection state and sequential message exchange.
//!
//! The [`Connection`] type manages a single TCP connection to an SMB server,
//! handling negotiate, credit tracking, message ID sequencing, preauth hash
//! maintenance, and message signing.

use std::time::Duration;

use log::{debug, info, trace, warn};

use crate::crypto::kdf::PreauthHasher;
use crate::crypto::signing::{self, SigningAlgorithm};
use crate::error::Result;
use crate::msg::header::Header;
use crate::msg::negotiate::{
    NegotiateContext, NegotiateRequest, NegotiateResponse, CIPHER_AES_128_CCM, CIPHER_AES_128_GCM,
    CIPHER_AES_256_CCM, CIPHER_AES_256_GCM, HASH_ALGORITHM_SHA512, SIGNING_AES_CMAC,
    SIGNING_AES_GMAC, SIGNING_HMAC_SHA256,
};
use crate::pack::{Guid, Pack, ReadCursor, Unpack, WriteCursor};
use crate::transport::{TcpTransport, TransportReceive, TransportSend};
use crate::types::flags::{Capabilities, HeaderFlags, SecurityMode};
use crate::types::status::NtStatus;
use crate::types::{Command, CreditCharge, Dialect, MessageId, SessionId, TreeId};
use crate::Error;

/// Negotiated cipher for SMB 3.x encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-128-CCM.
    Aes128Ccm,
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-CCM.
    Aes256Ccm,
    /// AES-256-GCM.
    Aes256Gcm,
}

/// Parameters established during negotiate.
#[derive(Debug, Clone)]
pub struct NegotiatedParams {
    /// The dialect both sides agreed on.
    pub dialect: Dialect,
    /// Maximum read size the server supports.
    pub max_read_size: u32,
    /// Maximum write size the server supports.
    pub max_write_size: u32,
    /// Maximum transact size the server supports.
    pub max_transact_size: u32,
    /// The server's GUID.
    pub server_guid: Guid,
    /// Whether the server requires signing.
    pub signing_required: bool,
    /// Server capabilities.
    pub capabilities: Capabilities,
    /// Whether AES-GMAC signing was negotiated (SMB 3.1.1).
    pub gmac_negotiated: bool,
    /// The cipher negotiated for encryption (SMB 3.x).
    pub cipher: Option<Cipher>,
}

/// Low-level connection that handles sequential message exchange.
///
/// Manages credit tracking, message ID sequencing, preauth integrity hash,
/// and message signing. This is the non-pipelined variant: one request at
/// a time, wait for the response before sending the next.
pub struct Connection {
    sender: Box<dyn TransportSend>,
    receiver: Box<dyn TransportReceive>,
    /// Negotiated parameters (populated after negotiate).
    params: Option<NegotiatedParams>,
    /// Next message ID (simple counter for sequential mode).
    next_message_id: u64,
    /// Available credits.
    credits: u16,
    /// Preauth integrity hash (for SMB 3.1.1 key derivation).
    preauth_hasher: PreauthHasher,
    /// Signing key, set after session setup.
    signing_key: Option<Vec<u8>>,
    /// Signing algorithm, set after session setup.
    signing_algorithm: Option<SigningAlgorithm>,
    /// Whether to sign outgoing messages.
    should_sign: bool,
    /// Active session ID.
    session_id: SessionId,
    /// The server name (hostname or IP) used for UNC paths.
    server_name: String,
    /// Estimated round-trip time, measured during negotiate.
    estimated_rtt: Option<Duration>,
}

impl Connection {
    /// Create a connection from an existing transport (for testing with mock).
    pub fn from_transport(
        sender: Box<dyn TransportSend>,
        receiver: Box<dyn TransportReceive>,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            sender,
            receiver,
            params: None,
            next_message_id: 0,
            credits: 1,
            preauth_hasher: PreauthHasher::new(),
            signing_key: None,
            signing_algorithm: None,
            should_sign: false,
            session_id: SessionId::NONE,
            server_name: server_name.into(),
            estimated_rtt: None,
        }
    }

    /// Connect to an SMB server over TCP.
    pub async fn connect(addr: &str, timeout: Duration) -> Result<Self> {
        // Extract the server name (host part) from addr.
        let server_name = addr
            .split(':')
            .next()
            .unwrap_or(addr)
            .to_string();

        let transport = TcpTransport::connect(addr, timeout).await?;
        info!("connection: connected to {}", addr);
        // Clone into two Arc-wrapped halves is not needed because TcpTransport
        // implements both traits. We wrap it in Arc for the split.
        let transport = std::sync::Arc::new(transport);
        Ok(Self {
            sender: Box::new(transport.clone()),
            receiver: Box::new(transport),
            params: None,
            next_message_id: 0,
            credits: 1,
            preauth_hasher: PreauthHasher::new(),
            signing_key: None,
            signing_algorithm: None,
            should_sign: false,
            session_id: SessionId::NONE,
            server_name,
            estimated_rtt: None,
        })
    }

    /// Perform the SMB2 NEGOTIATE exchange.
    ///
    /// Sends a NegotiateRequest with all five dialects and required negotiate
    /// contexts, processes the response, validates it, and stores the
    /// negotiated parameters.
    pub async fn negotiate(&mut self) -> Result<()> {
        debug!("negotiate: sending request, dialects={:?}", Dialect::ALL);
        let client_guid = generate_guid();

        let request = NegotiateRequest {
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            capabilities: Capabilities::new(
                Capabilities::DFS | Capabilities::LEASING | Capabilities::LARGE_MTU,
            ),
            client_guid,
            dialects: Dialect::ALL.to_vec(),
            negotiate_contexts: vec![
                NegotiateContext::PreauthIntegrity {
                    hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                    salt: generate_salt(),
                },
                NegotiateContext::Encryption {
                    ciphers: vec![
                        CIPHER_AES_128_GCM,
                        CIPHER_AES_128_CCM,
                        CIPHER_AES_256_GCM,
                        CIPHER_AES_256_CCM,
                    ],
                },
                NegotiateContext::Signing {
                    algorithms: vec![SIGNING_AES_GMAC, SIGNING_AES_CMAC, SIGNING_HMAC_SHA256],
                },
            ],
        };

        // Pack header + body to get the raw wire bytes.
        let mut header = Header::new_request(Command::Negotiate);
        header.message_id = MessageId(self.next_message_id);
        header.credits = 1;

        let req_bytes = pack_message(&header, &request);
        self.next_message_id += 1;

        // Update preauth hash with request bytes.
        self.preauth_hasher.update(&req_bytes);
        trace!("negotiate: preauth hash updated with request ({} bytes)", req_bytes.len());

        // Send and measure RTT.
        let rtt_start = std::time::Instant::now();
        self.sender.send(&req_bytes).await?;

        // Receive.
        let resp_bytes = self.receiver.receive().await?;
        self.estimated_rtt = Some(rtt_start.elapsed());
        trace!(
            "negotiate: received response ({} bytes), rtt={:?}",
            resp_bytes.len(),
            self.estimated_rtt.unwrap()
        );

        // Update preauth hash with response bytes.
        self.preauth_hasher.update(&resp_bytes);

        // Parse response header.
        let mut cursor = ReadCursor::new(&resp_bytes);
        let resp_header = Header::unpack(&mut cursor)?;

        if !resp_header.is_response() {
            return Err(Error::invalid_data(
                "expected a response but got a request",
            ));
        }

        if resp_header.command != Command::Negotiate {
            return Err(Error::invalid_data(format!(
                "expected Negotiate response, got {:?}",
                resp_header.command
            )));
        }

        // Update credits from response.
        self.credits = resp_header.credits;

        // Check for error status (but allow success).
        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Negotiate,
            });
        }

        // Parse response body.
        let resp = NegotiateResponse::unpack(&mut cursor)?;

        // Validate the dialect is one we offered.
        if !Dialect::ALL.contains(&resp.dialect_revision) {
            return Err(Error::invalid_data(format!(
                "server selected dialect 0x{:04X} which we did not offer",
                u16::from(resp.dialect_revision)
            )));
        }

        // Validate MaxReadSize/MaxWriteSize >= 65536.
        if resp.max_read_size < 65536 {
            return Err(Error::invalid_data(format!(
                "MaxReadSize {} is below minimum 65536",
                resp.max_read_size
            )));
        }
        if resp.max_write_size < 65536 {
            return Err(Error::invalid_data(format!(
                "MaxWriteSize {} is below minimum 65536",
                resp.max_write_size
            )));
        }

        // Determine signing and encryption from negotiate contexts.
        let mut gmac_negotiated = false;
        let mut cipher = None;

        for ctx in &resp.negotiate_contexts {
            match ctx {
                NegotiateContext::Signing { algorithms } => {
                    if algorithms.contains(&SIGNING_AES_GMAC) {
                        gmac_negotiated = true;
                    }
                }
                NegotiateContext::Encryption { ciphers } => {
                    // Server picks one cipher in the response.
                    if let Some(&c) = ciphers.first() {
                        cipher = match c {
                            CIPHER_AES_128_CCM => Some(Cipher::Aes128Ccm),
                            CIPHER_AES_128_GCM => Some(Cipher::Aes128Gcm),
                            CIPHER_AES_256_CCM => Some(Cipher::Aes256Ccm),
                            CIPHER_AES_256_GCM => Some(Cipher::Aes256Gcm),
                            _ => None,
                        };
                    }
                }
                _ => {}
            }
        }

        let signing_required = resp.security_mode.signing_required();

        self.params = Some(NegotiatedParams {
            dialect: resp.dialect_revision,
            max_read_size: resp.max_read_size,
            max_write_size: resp.max_write_size,
            max_transact_size: resp.max_transact_size,
            server_guid: resp.server_guid,
            signing_required,
            capabilities: resp.capabilities,
            gmac_negotiated,
            cipher,
        });

        info!(
            "negotiate: dialect={}, signing_required={}, capabilities={:?}",
            resp.dialect_revision, signing_required, resp.capabilities
        );
        debug!(
            "negotiate: max_read={}, max_write={}, max_transact={}, server_guid={:?}, cipher={:?}, gmac={}",
            resp.max_read_size, resp.max_write_size, resp.max_transact_size,
            resp.server_guid, cipher, gmac_negotiated
        );

        Ok(())
    }

    /// Send a request and return the raw bytes that were sent (for preauth hash).
    ///
    /// Packs the header + body, optionally signs, sends, and returns the bytes.
    pub async fn send_request(
        &mut self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
    ) -> Result<(MessageId, Vec<u8>)> {
        let mut header = Header::new_request(command);
        header.message_id = MessageId(self.next_message_id);
        header.credits = 256; // Request more credits.
        header.credit_charge = CreditCharge(1);
        header.session_id = self.session_id;
        if let Some(tid) = tree_id {
            header.tree_id = Some(tid);
        }

        // Sign if signing is active.
        if self.should_sign {
            header.flags.set_signed();
        }

        let mut msg_bytes = pack_message(&header, body);
        let msg_id = MessageId(self.next_message_id);
        self.next_message_id += 1;

        // Sign the message if needed.
        if self.should_sign {
            if let (Some(key), Some(algo)) = (&self.signing_key, &self.signing_algorithm) {
                signing::sign_message(&mut msg_bytes, key, *algo, msg_id.0, false)?;
            }
        }

        self.sender.send(&msg_bytes).await?;
        debug!(
            "send: cmd={:?}, msg_id={}, tree_id={:?}, signed={}, len={}",
            command, msg_id.0, tree_id, self.should_sign, msg_bytes.len()
        );
        Ok((msg_id, msg_bytes))
    }

    /// Send a request with a custom CreditCharge (for multi-credit operations).
    ///
    /// The CreditCharge determines how many credits this request consumes
    /// and how many consecutive MessageIds it uses. For READ/WRITE with
    /// payloads larger than 64KB, CreditCharge = ceil(payload / 65536).
    pub async fn send_request_with_credits(
        &mut self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
        credit_charge: u16,
    ) -> Result<(MessageId, Vec<u8>)> {
        let mut header = Header::new_request(command);
        header.message_id = MessageId(self.next_message_id);
        header.credits = 256; // Request more credits.
        header.credit_charge = CreditCharge(credit_charge);
        header.session_id = self.session_id;
        if let Some(tid) = tree_id {
            header.tree_id = Some(tid);
        }

        if self.should_sign {
            header.flags.set_signed();
        }

        let mut msg_bytes = pack_message(&header, body);
        let msg_id = MessageId(self.next_message_id);
        // Multi-credit requests consume consecutive MessageIds.
        self.next_message_id += credit_charge as u64;

        if self.should_sign {
            if let (Some(key), Some(algo)) = (&self.signing_key, &self.signing_algorithm) {
                signing::sign_message(&mut msg_bytes, key, *algo, msg_id.0, false)?;
            }
        }

        self.sender.send(&msg_bytes).await?;
        debug!(
            "send: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, len={}",
            command, msg_id.0, credit_charge, tree_id, self.should_sign, msg_bytes.len()
        );
        Ok((msg_id, msg_bytes))
    }

    /// Get the estimated round-trip time (measured during negotiate).
    pub fn estimated_rtt(&self) -> Option<Duration> {
        self.estimated_rtt
    }

    /// Receive a response, verify signature if needed, and update credits.
    ///
    /// Returns the parsed header, the raw body bytes, and the full raw
    /// response bytes (needed for preauth hash updates).
    pub async fn receive_response(&mut self) -> Result<(Header, Vec<u8>, Vec<u8>)> {
        let resp_bytes = self.receiver.receive().await?;
        trace!("recv: raw response {} bytes", resp_bytes.len());

        // Verify signature if signing is active AND the response has the
        // SIGNED flag set (spec section 3.2.5.1.3). Skip for STATUS_PENDING
        // interim responses and unsolicited oplock break notifications.
        if self.should_sign && resp_bytes.len() >= 20 {
            let flags = u32::from_le_bytes(
                resp_bytes[16..20]
                    .try_into()
                    .map_err(|_| Error::invalid_data("response too short for flags"))?,
            );
            let is_signed = (flags & HeaderFlags::SIGNED) != 0;

            // Also check for STATUS_PENDING (skip verification) and
            // unsolicited messages (MessageId 0xFFFFFFFFFFFFFFFF).
            let status = u32::from_le_bytes(
                resp_bytes[8..12]
                    .try_into()
                    .map_err(|_| Error::invalid_data("response too short for status"))?,
            );
            let msg_id_bytes: [u8; 8] = resp_bytes[24..32]
                .try_into()
                .map_err(|_| Error::invalid_data("response too short for message ID"))?;
            let msg_id = u64::from_le_bytes(msg_id_bytes);
            let is_pending = status == NtStatus::PENDING.0;
            let is_unsolicited = msg_id == 0xFFFF_FFFF_FFFF_FFFF;

            if is_signed && !is_pending && !is_unsolicited {
                if let (Some(key), Some(algo)) = (&self.signing_key, &self.signing_algorithm) {
                    signing::verify_signature(&resp_bytes, key, *algo, msg_id, false)?;
                }
            }
        }

        // Parse header.
        let mut cursor = ReadCursor::new(&resp_bytes);
        let header = Header::unpack(&mut cursor)?;

        // Update credits.
        let prev_credits = self.credits;
        if header.credits > 0 {
            self.credits = self.credits.saturating_add(header.credits);
        }

        // Consume one credit for the request that generated this response.
        self.credits = self.credits.saturating_sub(1);

        debug!(
            "recv: cmd={:?}, status={:?}, msg_id={}, credits={} (was {}, granted {})",
            header.command, header.status, header.message_id.0,
            self.credits, prev_credits, header.credits
        );
        if self.credits == 0 {
            warn!("recv: zero credits remaining — credit starvation");
        }

        // Return the body bytes (everything after the header).
        let body_bytes = resp_bytes[Header::SIZE..].to_vec();

        Ok((header, body_bytes, resp_bytes))
    }

    /// Get the negotiated parameters.
    pub fn params(&self) -> Option<&NegotiatedParams> {
        self.params.as_ref()
    }

    /// Get a mutable reference to the preauth hasher.
    pub fn preauth_hasher_mut(&mut self) -> &mut PreauthHasher {
        &mut self.preauth_hasher
    }

    /// Get the preauth hasher.
    pub fn preauth_hasher(&self) -> &PreauthHasher {
        &self.preauth_hasher
    }

    /// Set the session ID.
    pub fn set_session_id(&mut self, id: SessionId) {
        self.session_id = id;
    }

    /// Get the current session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Activate signing with the given key and algorithm.
    pub fn activate_signing(&mut self, key: Vec<u8>, algorithm: SigningAlgorithm) {
        debug!("signing: activated, algo={:?}, key_len={}", algorithm, key.len());
        self.signing_key = Some(key);
        self.signing_algorithm = Some(algorithm);
        self.should_sign = true;
    }

    /// Get the current number of available credits.
    pub fn credits(&self) -> u16 {
        self.credits
    }

    /// Get the next message ID (without incrementing).
    pub fn next_message_id(&self) -> u64 {
        self.next_message_id
    }

    /// Get the server name.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Set negotiated params directly (for testing).
    #[cfg(test)]
    pub(crate) fn set_test_params(&mut self, params: NegotiatedParams) {
        self.params = Some(params);
    }
}

/// Pack a header + body into raw SMB2 message bytes (no transport framing).
pub(crate) fn pack_message(header: &Header, body: &dyn Pack) -> Vec<u8> {
    let mut cursor = WriteCursor::new();
    header.pack(&mut cursor);
    body.pack(&mut cursor);
    cursor.into_inner()
}

/// Generate a random GUID.
fn generate_guid() -> Guid {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("failed to generate random GUID");
    Guid {
        data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_le_bytes([bytes[4], bytes[5]]),
        data3: u16::from_le_bytes([bytes[6], bytes[7]]),
        data4: [
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    }
}

/// Generate a 32-byte random salt for preauth integrity.
fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    getrandom::fill(&mut salt).expect("failed to generate random salt");
    salt
}

// We need Arc-based TransportSend/TransportReceive for TcpTransport sharing.
use std::sync::Arc;

#[async_trait::async_trait]
impl<T: TransportSend> TransportSend for Arc<T> {
    async fn send(&self, data: &[u8]) -> Result<()> {
        (**self).send(data).await
    }
}

#[async_trait::async_trait]
impl<T: TransportReceive> TransportReceive for Arc<T> {
    async fn receive(&self) -> Result<Vec<u8>> {
        (**self).receive().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::negotiate::{NegotiateContext, HASH_ALGORITHM_SHA512};
    use crate::transport::MockTransport;
    use crate::types::flags::HeaderFlags;

    /// Build a canned negotiate response with the given dialect.
    fn build_negotiate_response(dialect: Dialect) -> Vec<u8> {
        let resp_header = {
            let mut h = Header::new_request(Command::Negotiate);
            h.flags.set_response();
            h.credits = 32;
            h
        };
        let resp_body = NegotiateResponse {
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            dialect_revision: dialect,
            server_guid: Guid::ZERO,
            capabilities: Capabilities::new(Capabilities::DFS | Capabilities::LEASING),
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: 132_000_000_000_000_000,
            server_start_time: 131_000_000_000_000_000,
            security_buffer: vec![0x60, 0x00],
            negotiate_contexts: if dialect == Dialect::Smb3_1_1 {
                vec![NegotiateContext::PreauthIntegrity {
                    hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                    salt: vec![0xBB; 32],
                }]
            } else {
                vec![]
            },
        };
        pack_message(&resp_header, &resp_body)
    }

    #[tokio::test]
    async fn negotiate_stores_params_correctly() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.negotiate().await.unwrap();

        let params = conn.params().unwrap();
        assert_eq!(params.dialect, Dialect::Smb3_1_1);
        assert_eq!(params.max_read_size, 65536);
        assert_eq!(params.max_write_size, 65536);
        assert_eq!(params.max_transact_size, 65536);
        assert!(!params.signing_required);
    }

    #[tokio::test]
    async fn negotiate_updates_credits() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb3_0));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.negotiate().await.unwrap();

        // Server granted 32 credits, minus 1 consumed for our request.
        assert_eq!(conn.credits(), 32);
    }

    #[tokio::test]
    async fn negotiate_increments_message_id() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb2_0_2));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        assert_eq!(conn.next_message_id(), 0);
        conn.negotiate().await.unwrap();
        assert_eq!(conn.next_message_id(), 1);
    }

    #[tokio::test]
    async fn negotiate_updates_preauth_hash() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        let initial_hash = *conn.preauth_hasher().value();
        conn.negotiate().await.unwrap();
        assert_ne!(conn.preauth_hasher().value(), &initial_hash);
    }

    #[tokio::test]
    async fn negotiate_rejects_invalid_max_read_size() {
        let resp_header = {
            let mut h = Header::new_request(Command::Negotiate);
            h.flags.set_response();
            h.credits = 1;
            h
        };
        let resp_body = NegotiateResponse {
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            dialect_revision: Dialect::Smb2_0_2,
            server_guid: Guid::ZERO,
            capabilities: Capabilities::default(),
            max_transact_size: 65536,
            max_read_size: 1024, // Too small
            max_write_size: 65536,
            system_time: 0,
            server_start_time: 0,
            security_buffer: vec![],
            negotiate_contexts: vec![],
        };
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(pack_message(&resp_header, &resp_body));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        let result = conn.negotiate().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MaxReadSize"));
    }

    #[tokio::test]
    async fn message_id_increments_on_send_request() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Manually set past negotiate.
        conn.next_message_id = 5;

        use crate::msg::tree_disconnect::TreeDisconnectRequest;
        let body = TreeDisconnectRequest;
        let (mid, _) = conn
            .send_request(Command::TreeDisconnect, &body, None)
            .await
            .unwrap();
        assert_eq!(mid, MessageId(5));
        assert_eq!(conn.next_message_id(), 6);
    }

    #[tokio::test]
    async fn signing_applied_to_outgoing_messages() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Activate signing.
        let key = vec![0xAA; 16];
        conn.activate_signing(key, SigningAlgorithm::HmacSha256);
        conn.session_id = SessionId(0x1234);

        use crate::msg::tree_disconnect::TreeDisconnectRequest;
        let body = TreeDisconnectRequest;
        let (_mid, msg_bytes) = conn
            .send_request(Command::TreeDisconnect, &body, None)
            .await
            .unwrap();

        // Verify the signed flag is set in the header.
        let flags = u32::from_le_bytes(msg_bytes[16..20].try_into().unwrap());
        assert!(flags & HeaderFlags::SIGNED != 0, "message should be signed");

        // Verify signature is non-zero.
        let sig = &msg_bytes[48..64];
        assert_ne!(sig, &[0u8; 16], "signature should not be all zeros");
    }

    #[tokio::test]
    async fn negotiate_with_smb2_dialect() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb2_0_2));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.negotiate().await.unwrap();

        let params = conn.params().unwrap();
        assert_eq!(params.dialect, Dialect::Smb2_0_2);
        assert!(!params.gmac_negotiated);
        assert!(params.cipher.is_none());
    }

    #[tokio::test]
    async fn negotiate_sends_all_five_dialects() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.negotiate().await.unwrap();

        // Verify the sent request contains all 5 dialects.
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = NegotiateRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req.dialects.len(), 5);
        assert!(req.dialects.contains(&Dialect::Smb2_0_2));
        assert!(req.dialects.contains(&Dialect::Smb2_1));
        assert!(req.dialects.contains(&Dialect::Smb3_0));
        assert!(req.dialects.contains(&Dialect::Smb3_0_2));
        assert!(req.dialects.contains(&Dialect::Smb3_1_1));
    }
}
