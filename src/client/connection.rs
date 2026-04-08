//! Connection state and sequential message exchange.
//!
//! The [`Connection`] type manages a single TCP connection to an SMB server,
//! handling negotiate, credit tracking, message ID sequencing, preauth hash
//! maintenance, and message signing.

use std::time::Duration;

use log::{debug, info, trace, warn};

use crate::crypto::compression::{compress_message, decompress_message, CompressedMessage};
use crate::crypto::encryption::Cipher;
use crate::crypto::kdf::PreauthHasher;
use crate::crypto::signing::{self, SigningAlgorithm};
use crate::error::Result;
use crate::msg::header::Header;
use crate::msg::negotiate::{
    NegotiateContext, NegotiateRequest, NegotiateResponse, CIPHER_AES_128_CCM, CIPHER_AES_128_GCM,
    CIPHER_AES_256_CCM, CIPHER_AES_256_GCM, COMPRESSION_LZ4, HASH_ALGORITHM_SHA512,
    SIGNING_AES_CMAC, SIGNING_AES_GMAC, SIGNING_HMAC_SHA256,
};
use crate::msg::transform::{
    CompressionTransformHeader, COMPRESSION_ALGORITHM_LZ4, COMPRESSION_PROTOCOL_ID,
    SMB2_COMPRESSION_FLAG_NONE,
};
use crate::pack::{Guid, Pack, ReadCursor, Unpack, WriteCursor};
use crate::transport::{TcpTransport, TransportReceive, TransportSend};
use crate::types::flags::{Capabilities, HeaderFlags, SecurityMode};
use crate::types::status::NtStatus;
use crate::types::{Command, CreditCharge, Dialect, MessageId, SessionId, TreeId};
use crate::Error;

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
    /// Whether compression was negotiated with the server.
    pub compression_supported: bool,
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
    /// Whether to attempt compression on outgoing messages.
    compression_enabled: bool,
    /// Whether the client wants compression (from config).
    compression_requested: bool,
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
            compression_enabled: false,
            compression_requested: true,
        }
    }

    /// Connect to an SMB server over TCP.
    pub async fn connect(addr: &str, timeout: Duration) -> Result<Self> {
        // Extract the server name (host part) from addr.
        let server_name = addr.split(':').next().unwrap_or(addr).to_string();

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
            compression_enabled: false,
            compression_requested: true,
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

        let mut negotiate_contexts = vec![
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
        ];

        if self.compression_requested {
            negotiate_contexts.push(NegotiateContext::Compression {
                flags: 0, // unchained
                algorithms: vec![COMPRESSION_LZ4],
            });
        }

        let request = NegotiateRequest {
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            capabilities: Capabilities::new(
                Capabilities::DFS | Capabilities::LEASING | Capabilities::LARGE_MTU,
            ),
            client_guid,
            dialects: Dialect::ALL.to_vec(),
            negotiate_contexts,
        };

        // Pack header + body to get the raw wire bytes.
        let mut header = Header::new_request(Command::Negotiate);
        header.message_id = MessageId(self.next_message_id);
        header.credits = 1;

        let req_bytes = pack_message(&header, &request);
        self.next_message_id += 1;

        // Update preauth hash with request bytes.
        self.preauth_hasher.update(&req_bytes);
        trace!(
            "negotiate: preauth hash updated with request ({} bytes)",
            req_bytes.len()
        );

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
            return Err(Error::invalid_data("expected a response but got a request"));
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

        // Determine signing, encryption, and compression from negotiate contexts.
        let mut gmac_negotiated = false;
        let mut cipher = None;
        let mut compression_supported = false;

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
                NegotiateContext::Compression { algorithms, .. } => {
                    if algorithms.contains(&COMPRESSION_LZ4) {
                        compression_supported = true;
                    }
                }
                _ => {}
            }
        }

        let signing_required = resp.security_mode.signing_required();

        // Enable compression if both client and server support it.
        self.compression_enabled = self.compression_requested && compression_supported;

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
            compression_supported,
        });

        info!(
            "negotiate: dialect={}, signing_required={}, capabilities={:?}",
            resp.dialect_revision, signing_required, resp.capabilities
        );
        debug!(
            "negotiate: max_read={}, max_write={}, max_transact={}, server_guid={:?}, cipher={:?}, gmac={}, compression={}",
            resp.max_read_size, resp.max_write_size, resp.max_transact_size,
            resp.server_guid, cipher, gmac_negotiated, self.compression_enabled
        );

        Ok(())
    }

    /// Send a request and return the raw bytes that were sent (for preauth hash).
    ///
    /// Packs the header + body, optionally signs, sends, and returns the bytes.
    /// Equivalent to `send_request_with_credits(command, body, tree_id, 1)`.
    pub async fn send_request(
        &mut self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
    ) -> Result<(MessageId, Vec<u8>)> {
        self.send_request_with_credits(command, body, tree_id, 1)
            .await
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

        // Try to compress after signing (per spec: sign then compress).
        if self.compression_enabled && msg_bytes.len() > Header::SIZE {
            if let Some(compressed) = compress_message(&msg_bytes, Header::SIZE) {
                let framed = build_compressed_frame(&compressed);
                self.sender.send(&framed).await?;
                debug!(
                    "send: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, compressed {}->{} bytes",
                    command, msg_id.0, credit_charge, tree_id, self.should_sign,
                    msg_bytes.len(), framed.len()
                );
                return Ok((msg_id, msg_bytes));
            }
        }

        self.sender.send(&msg_bytes).await?;
        debug!(
            "send: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, len={}",
            command,
            msg_id.0,
            credit_charge,
            tree_id,
            self.should_sign,
            msg_bytes.len()
        );
        Ok((msg_id, msg_bytes))
    }

    /// Get the estimated round-trip time (measured during negotiate).
    pub fn estimated_rtt(&self) -> Option<Duration> {
        self.estimated_rtt
    }

    /// Receive a response, verify signature if needed, and update credits.
    ///
    /// Automatically loops past `STATUS_PENDING` interim responses
    /// (MS-SMB2 3.3.4.3): collects their credits and keeps waiting
    /// for the final response.
    ///
    /// Returns the parsed header, the raw body bytes, and the full raw
    /// response bytes (needed for preauth hash updates).
    pub async fn receive_response(&mut self) -> Result<(Header, Vec<u8>, Vec<u8>)> {
        loop {
            let resp_bytes = self.receiver.receive().await?;
            trace!("recv: raw response {} bytes", resp_bytes.len());

            // Check for compression transform header and decompress if needed.
            // Per spec: decompress first, then verify signature.
            let resp_bytes = if resp_bytes.len() >= 4 && resp_bytes[0..4] == COMPRESSION_PROTOCOL_ID
            {
                trace!("recv: detected compression transform header, decompressing");
                decompress_response(&resp_bytes)?
            } else {
                resp_bytes
            };

            // Verify signature if signing is active AND the response has the
            // SIGNED flag set (spec section 3.2.5.1.3). Skip for STATUS_PENDING
            // interim responses and unsolicited oplock break notifications.
            // A valid SMB2 header is always 64 bytes. Guard on that so the
            // field accesses below (up to byte 32) are guaranteed in-bounds.
            if self.should_sign && resp_bytes.len() >= Header::SIZE {
                let flags = u32::from_le_bytes(resp_bytes[16..20].try_into().unwrap());
                let is_signed = (flags & HeaderFlags::SIGNED) != 0;

                // Also check for STATUS_PENDING (skip verification) and
                // unsolicited messages (MessageId 0xFFFFFFFFFFFFFFFF).
                let status = u32::from_le_bytes(resp_bytes[8..12].try_into().unwrap());
                let msg_id_bytes: [u8; 8] = resp_bytes[24..32].try_into().unwrap();
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

            // Update credits (interim responses carry credits too).
            let prev_credits = self.credits;
            if header.credits > 0 {
                self.credits = self.credits.saturating_add(header.credits);
            }

            // Unsolicited oplock/lease break notification: arrives with
            // MessageId = 0xFFFFFFFFFFFFFFFF (MS-SMB2 3.2.5.19).
            // We don't cache, so we skip the notification without sending
            // an acknowledgment. The server will time out and forcibly
            // break the oplock after ~35 seconds, which is safe.
            if header.message_id == MessageId::UNSOLICITED {
                debug!(
                    "recv: skipping unsolicited oplock break notification, cmd={:?}",
                    header.command,
                );
                continue;
            }

            // STATUS_PENDING is an interim response: collect credits and
            // keep waiting for the final response (MS-SMB2 3.3.4.3).
            if header.status.is_pending() {
                debug!(
                    "recv: STATUS_PENDING (interim), cmd={:?}, msg_id={}, credits={} (was {}, granted {})",
                    header.command,
                    header.message_id.0,
                    self.credits,
                    prev_credits,
                    header.credits
                );
                continue;
            }

            // Consume one credit for the request that generated this response.
            self.credits = self.credits.saturating_sub(1);

            debug!(
                "recv: cmd={:?}, status={:?}, msg_id={}, credits={} (was {}, granted {})",
                header.command,
                header.status,
                header.message_id.0,
                self.credits,
                prev_credits,
                header.credits
            );
            if self.credits == 0 {
                warn!("recv: zero credits remaining -- credit starvation");
            }

            // Return the body bytes (everything after the header).
            let body_bytes = resp_bytes[Header::SIZE..].to_vec();

            return Ok((header, body_bytes, resp_bytes));
        }
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
        debug!(
            "signing: activated, algo={:?}, key_len={}",
            algorithm,
            key.len()
        );
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

    /// Set whether the client wants compression.
    ///
    /// Must be called before [`negotiate`](Self::negotiate) to have effect.
    pub fn set_compression_requested(&mut self, requested: bool) {
        self.compression_requested = requested;
    }

    /// Whether compression is active on this connection.
    pub fn compression_enabled(&self) -> bool {
        self.compression_enabled
    }

    /// Set negotiated params directly (for testing).
    /// Send a related compound request (multiple operations chained).
    ///
    /// Related compounds share SessionId and TreeId. The first operation
    /// provides the real FileId; subsequent operations use the sentinel
    /// FileId `{0xFFFF..., 0xFFFF...}` meaning "use the FileId from the
    /// previous response."
    ///
    /// Each sub-request is packed with its own header. The `NextCommand`
    /// field links them. All sub-requests except the last are padded
    /// to 8-byte alignment. The `SMB2_FLAGS_RELATED_OPERATIONS` flag is
    /// set on all sub-requests except the first.
    ///
    /// Returns the MessageIds assigned to each sub-request.
    pub async fn send_compound(
        &mut self,
        tree_id: TreeId,
        operations: &[(Command, &dyn Pack, CreditCharge)],
    ) -> Result<Vec<MessageId>> {
        if operations.is_empty() {
            return Err(Error::invalid_data(
                "compound request must have at least one operation",
            ));
        }

        let mut message_ids = Vec::with_capacity(operations.len());
        let mut sub_requests: Vec<Vec<u8>> = Vec::with_capacity(operations.len());

        // Step 1: Pack each sub-request with its header.
        for (i, (command, body, credit_charge)) in operations.iter().enumerate() {
            let mut header = Header::new_request(*command);
            header.message_id = MessageId(self.next_message_id);
            header.credits = 256; // Request more credits.
            header.credit_charge = *credit_charge;
            header.session_id = self.session_id;
            header.tree_id = Some(tree_id);

            // Set RELATED_OPERATIONS on all except the first.
            if i > 0 {
                header.flags.set_related();
            }

            // Sign flag (actual signing happens after padding).
            if self.should_sign {
                header.flags.set_signed();
            }

            let msg_id = MessageId(self.next_message_id);
            message_ids.push(msg_id);
            self.next_message_id += credit_charge.0 as u64;

            let msg_bytes = pack_message(&header, *body);
            sub_requests.push(msg_bytes);
        }

        // Step 2: Pad all sub-requests except the last to 8-byte alignment.
        let last_idx = sub_requests.len() - 1;
        for sub_req in sub_requests.iter_mut().take(last_idx) {
            let current_len = sub_req.len();
            let remainder = current_len % 8;
            if remainder != 0 {
                let pad = 8 - remainder;
                sub_req.resize(current_len + pad, 0);
            }
        }

        // Step 3: Set NextCommand offsets by backpatching each header.
        // NextCommand is at header bytes 20..24.
        for sub_req in sub_requests.iter_mut().take(last_idx) {
            let next_cmd = sub_req.len() as u32;
            sub_req[20..24].copy_from_slice(&next_cmd.to_le_bytes());
        }
        // Last sub-request: NextCommand = 0 (already the default).

        // Step 4: Sign each sub-request individually (including padding).
        if self.should_sign {
            if let (Some(key), Some(algo)) = (&self.signing_key, &self.signing_algorithm) {
                for (i, sub_req) in sub_requests.iter_mut().enumerate() {
                    signing::sign_message(sub_req, key, *algo, message_ids[i].0, false)?;
                }
            }
        }

        // Step 5: Concatenate all sub-requests into one buffer and send.
        let total_len: usize = sub_requests.iter().map(|r| r.len()).sum();
        let mut compound_buf = Vec::with_capacity(total_len);
        for sub_req in &sub_requests {
            compound_buf.extend_from_slice(sub_req);
        }

        self.sender.send(&compound_buf).await?;

        debug!(
            "send_compound: {} operations, total_len={}, msg_ids={:?}, tree_id={}, signed={}",
            operations.len(),
            compound_buf.len(),
            message_ids.iter().map(|m| m.0).collect::<Vec<_>>(),
            tree_id,
            self.should_sign,
        );

        Ok(message_ids)
    }

    /// Receive a compound response (multiple responses in one frame).
    ///
    /// Splits the response by `NextCommand` offsets and returns each
    /// sub-response as `(Header, body_bytes)`.
    pub async fn receive_compound(&mut self) -> Result<Vec<(Header, Vec<u8>)>> {
        // Loop to skip unsolicited oplock/lease break notifications that
        // may arrive before the compound response we're waiting for.
        let resp_bytes = loop {
            let raw = self.receiver.receive().await?;
            trace!("recv_compound: raw response {} bytes", raw.len());

            // Check for compression transform header and decompress if needed.
            let decompressed = if raw.len() >= 4 && raw[0..4] == COMPRESSION_PROTOCOL_ID {
                trace!("recv_compound: detected compression transform header, decompressing");
                decompress_response(&raw)?
            } else {
                raw
            };

            // Check if this is an unsolicited oplock break (MessageId = 0xFFFF...).
            // Parse the MessageId from the raw header bytes (offset 24..32).
            if decompressed.len() >= Header::SIZE {
                let msg_id = u64::from_le_bytes(decompressed[24..32].try_into().unwrap());
                if msg_id == MessageId::UNSOLICITED.0 {
                    debug!("recv_compound: skipping unsolicited oplock break notification");
                    continue;
                }
            }

            break decompressed;
        };

        let mut results = Vec::new();
        let mut offset = 0usize;

        loop {
            if offset + Header::SIZE > resp_bytes.len() {
                return Err(Error::invalid_data(format!(
                    "compound response truncated at offset {}: need {} bytes for header, but only {} remain",
                    offset,
                    Header::SIZE,
                    resp_bytes.len() - offset,
                )));
            }

            // All responses except the first must start at 8-byte aligned offsets.
            if !results.is_empty() && offset % 8 != 0 {
                return Err(Error::invalid_data(format!(
                    "compound response at offset {} is not 8-byte aligned -- must disconnect",
                    offset,
                )));
            }

            // Verify signature on this sub-response if signing is active.
            let sub_start = offset;

            // Parse the header to get NextCommand.
            let mut cursor = ReadCursor::new(&resp_bytes[offset..]);
            let header = Header::unpack(&mut cursor)?;
            let next_command = header.next_command;

            // Determine the end of this sub-response.
            let sub_end = if next_command > 0 {
                offset + next_command as usize
            } else {
                resp_bytes.len()
            };

            if sub_end > resp_bytes.len() {
                return Err(Error::invalid_data(format!(
                    "compound NextCommand offset {} at position {} exceeds response length {}",
                    next_command,
                    offset,
                    resp_bytes.len(),
                )));
            }

            // Verify signature on the sub-response slice if needed.
            if self.should_sign {
                let sub_slice = &resp_bytes[sub_start..sub_end];
                if sub_slice.len() >= 20 {
                    // Length already checked (>= 20), so these slices are always 4 bytes.
                    let flags = u32::from_le_bytes(sub_slice[16..20].try_into().unwrap());
                    let is_signed = (flags & HeaderFlags::SIGNED) != 0;
                    let status = u32::from_le_bytes(sub_slice[8..12].try_into().unwrap());
                    let is_pending = status == NtStatus::PENDING.0;

                    if is_signed && !is_pending {
                        if let (Some(key), Some(algo)) =
                            (&self.signing_key, &self.signing_algorithm)
                        {
                            signing::verify_signature(
                                sub_slice,
                                key,
                                *algo,
                                header.message_id.0,
                                false,
                            )?;
                        }
                    }
                }
            }

            // Update credits from this sub-response.
            if header.credits > 0 {
                self.credits = self.credits.saturating_add(header.credits);
            }
            // Consume credits for the request that generated this response.
            self.credits = self.credits.saturating_sub(header.credit_charge.0);

            debug!(
                "recv_compound: cmd={:?}, status={:?}, msg_id={}, credits={}",
                header.command, header.status, header.message_id.0, self.credits,
            );

            // Extract the body bytes (everything after the header in this sub-response).
            let body_start = offset + Header::SIZE;
            let body_bytes = if body_start < sub_end {
                resp_bytes[body_start..sub_end].to_vec()
            } else {
                Vec::new()
            };

            results.push((header, body_bytes));

            if next_command == 0 {
                break;
            }
            offset += next_command as usize;
        }

        if self.credits == 0 {
            warn!("recv_compound: zero credits remaining -- credit starvation");
        }

        Ok(results)
    }

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

/// Build a compressed frame: CompressionTransformHeader + uncompressed prefix + compressed data.
///
/// The header is 16 bytes (unchained mode). The offset field tells the receiver
/// how many uncompressed bytes precede the compressed data.
fn build_compressed_frame(compressed: &CompressedMessage) -> Vec<u8> {
    let header = CompressionTransformHeader {
        original_compressed_segment_size: compressed.original_size,
        compression_algorithm: COMPRESSION_ALGORITHM_LZ4,
        flags: SMB2_COMPRESSION_FLAG_NONE,
        offset_or_length: compressed.offset,
    };

    let mut cursor = WriteCursor::new();
    header.pack(&mut cursor);
    let mut frame = cursor.into_inner();
    frame.extend_from_slice(&compressed.uncompressed_prefix);
    frame.extend_from_slice(&compressed.compressed_data);
    frame
}

/// Decompress a response that starts with a CompressionTransformHeader.
///
/// Parses the 16-byte unchained header, extracts the uncompressed prefix and
/// compressed data, decompresses, and returns the reconstructed full message.
fn decompress_response(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < CompressionTransformHeader::SIZE {
        return Err(Error::invalid_data(
            "compressed response too short for CompressionTransformHeader",
        ));
    }

    let mut cursor = ReadCursor::new(data);
    let header = CompressionTransformHeader::unpack(&mut cursor)?;

    if header.compression_algorithm != COMPRESSION_ALGORITHM_LZ4 {
        return Err(Error::invalid_data(format!(
            "unsupported compression algorithm 0x{:04X}, only LZ4 (0x{:04X}) is supported",
            header.compression_algorithm, COMPRESSION_ALGORITHM_LZ4
        )));
    }

    if header.flags != SMB2_COMPRESSION_FLAG_NONE {
        return Err(Error::invalid_data(format!(
            "unsupported compression flags 0x{:04X}, only unchained (0x0000) is supported",
            header.flags
        )));
    }

    let offset = header.offset_or_length as usize;
    let remaining = &data[CompressionTransformHeader::SIZE..];

    if offset > remaining.len() {
        return Err(Error::invalid_data(format!(
            "compression offset {} exceeds remaining data length {}",
            offset,
            remaining.len()
        )));
    }

    let uncompressed_prefix = &remaining[..offset];
    let compressed_data = &remaining[offset..];

    decompress_message(
        uncompressed_prefix,
        compressed_data,
        header.original_compressed_segment_size,
    )
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

    // ── Compound tests ──────────────────────────────────────────────

    use crate::msg::close::CloseRequest;
    use crate::msg::close::CloseResponse;
    use crate::msg::create::{
        CreateAction, CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel,
        ShareAccess,
    };
    use crate::msg::read::{ReadRequest, ReadResponse, SMB2_CHANNEL_NONE};
    use crate::pack::FileTime;
    use crate::types::flags::FileAccessMask;
    use crate::types::{CreditCharge, FileId, OplockLevel, TreeId};

    /// Build a compound response frame with proper NextCommand offsets.
    fn build_compound_response_frame(responses: &[Vec<u8>]) -> Vec<u8> {
        let mut padded: Vec<Vec<u8>> = Vec::new();
        for (i, resp) in responses.iter().enumerate() {
            let mut r = resp.clone();
            let is_last = i == responses.len() - 1;
            if !is_last {
                // Pad to 8-byte alignment.
                let remainder = r.len() % 8;
                if remainder != 0 {
                    r.resize(r.len() + (8 - remainder), 0);
                }
                // Set NextCommand to the padded size.
                let next_cmd = r.len() as u32;
                r[20..24].copy_from_slice(&next_cmd.to_le_bytes());
            }
            // Last: NextCommand stays 0 (already default from pack_message).
            padded.push(r);
        }
        let mut frame = Vec::new();
        for r in &padded {
            frame.extend_from_slice(r);
        }
        frame
    }

    fn build_test_create_response(file_id: FileId, end_of_file: u64) -> Vec<u8> {
        let mut h = Header::new_request(Command::Create);
        h.flags.set_response();
        h.credits = 10;
        h.message_id = MessageId(0);

        let body = CreateResponse {
            oplock_level: OplockLevel::None,
            flags: 0,
            create_action: CreateAction::FileOpened,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: FileTime::ZERO,
            change_time: FileTime::ZERO,
            allocation_size: 0,
            end_of_file,
            file_attributes: 0,
            file_id,
            create_contexts: vec![],
        };

        pack_message(&h, &body)
    }

    fn build_test_read_response(data: Vec<u8>) -> Vec<u8> {
        let mut h = Header::new_request(Command::Read);
        h.flags.set_response();
        h.credits = 10;
        h.message_id = MessageId(1);

        let body = ReadResponse {
            data_offset: 0x50,
            data_remaining: 0,
            flags: 0,
            data,
        };

        pack_message(&h, &body)
    }

    fn build_test_close_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::Close);
        h.flags.set_response();
        h.credits = 10;
        h.message_id = MessageId(2);

        let body = CloseResponse {
            flags: 0,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: FileTime::ZERO,
            change_time: FileTime::ZERO,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
        };

        pack_message(&h, &body)
    }

    #[tokio::test]
    async fn send_compound_packs_three_operations_into_one_frame() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 256;

        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(FileAccessMask::FILE_READ_DATA),
            file_attributes: 0,
            share_access: ShareAccess(ShareAccess::FILE_SHARE_READ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: "test.txt".to_string(),
            create_contexts: vec![],
        };
        let read_req = ReadRequest {
            padding: 0x50,
            flags: 0,
            length: 65536,
            offset: 0,
            file_id: FileId::SENTINEL,
            minimum_count: 0,
            channel: SMB2_CHANNEL_NONE,
            remaining_bytes: 0,
            read_channel_info: vec![],
        };
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let operations: Vec<(Command, &dyn Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::Read, &read_req, CreditCharge(1)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let msg_ids = conn.send_compound(TreeId(42), &operations).await.unwrap();

        // Should get 3 consecutive message IDs.
        assert_eq!(msg_ids.len(), 3);
        assert_eq!(msg_ids[0], MessageId(0));
        assert_eq!(msg_ids[1], MessageId(1));
        assert_eq!(msg_ids[2], MessageId(2));

        // Should have sent exactly one frame.
        assert_eq!(mock.sent_count(), 1);

        let sent = mock.sent_message(0).unwrap();

        // Parse the first header: no RELATED_OPERATIONS.
        let mut cursor = ReadCursor::new(&sent);
        let h1 = Header::unpack(&mut cursor).unwrap();
        assert_eq!(h1.command, Command::Create);
        assert!(!h1.flags.is_related());
        assert!(h1.next_command > 0, "first NextCommand should be non-zero");
        assert_eq!(h1.tree_id, Some(TreeId(42)));
        assert_eq!(h1.next_command % 8, 0, "NextCommand must be 8-byte aligned");

        // Jump to second header.
        let offset2 = h1.next_command as usize;
        let mut cursor2 = ReadCursor::new(&sent[offset2..]);
        let h2 = Header::unpack(&mut cursor2).unwrap();
        assert_eq!(h2.command, Command::Read);
        assert!(
            h2.flags.is_related(),
            "second request must have RELATED_OPERATIONS"
        );
        assert!(h2.next_command > 0, "second NextCommand should be non-zero");
        assert_eq!(h2.next_command % 8, 0, "NextCommand must be 8-byte aligned");

        // Jump to third header.
        let offset3 = offset2 + h2.next_command as usize;
        let mut cursor3 = ReadCursor::new(&sent[offset3..]);
        let h3 = Header::unpack(&mut cursor3).unwrap();
        assert_eq!(h3.command, Command::Close);
        assert!(
            h3.flags.is_related(),
            "third request must have RELATED_OPERATIONS"
        );
        assert_eq!(h3.next_command, 0, "last NextCommand must be 0");
    }

    #[tokio::test]
    async fn send_compound_uses_sentinel_file_id_in_subsequent_requests() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 256;

        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(FileAccessMask::FILE_READ_DATA),
            file_attributes: 0,
            share_access: ShareAccess(ShareAccess::FILE_SHARE_READ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: "x.txt".to_string(),
            create_contexts: vec![],
        };
        let read_req = ReadRequest {
            padding: 0x50,
            flags: 0,
            length: 65536,
            offset: 0,
            file_id: FileId::SENTINEL,
            minimum_count: 0,
            channel: SMB2_CHANNEL_NONE,
            remaining_bytes: 0,
            read_channel_info: vec![],
        };
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let operations: Vec<(Command, &dyn Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::Read, &read_req, CreditCharge(1)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        conn.send_compound(TreeId(1), &operations).await.unwrap();
        let sent = mock.sent_message(0).unwrap();

        // Parse first header to get offset to second.
        let mut c = ReadCursor::new(&sent);
        let h1 = Header::unpack(&mut c).unwrap();
        let off2 = h1.next_command as usize;

        // Parse second sub-request body (ReadRequest) to verify sentinel FileId.
        let mut c2 = ReadCursor::new(&sent[off2..]);
        let _h2 = Header::unpack(&mut c2).unwrap();
        let read_parsed = ReadRequest::unpack(&mut c2).unwrap();
        assert_eq!(read_parsed.file_id, FileId::SENTINEL);

        // Parse third sub-request offset.
        let mut c2b = ReadCursor::new(&sent[off2..]);
        let h2b = Header::unpack(&mut c2b).unwrap();
        let off3 = off2 + h2b.next_command as usize;

        // Parse third sub-request body (CloseRequest) to verify sentinel FileId.
        let mut c3 = ReadCursor::new(&sent[off3..]);
        let _h3 = Header::unpack(&mut c3).unwrap();
        let close_parsed = CloseRequest::unpack(&mut c3).unwrap();
        assert_eq!(close_parsed.file_id, FileId::SENTINEL);
    }

    #[tokio::test]
    async fn receive_compound_splits_three_responses() {
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let file_data = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let create_resp = build_test_create_response(file_id, file_data.len() as u64);
        let read_resp = build_test_read_response(file_data.clone());
        let close_resp = build_test_close_response();

        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 10;

        let responses = conn.receive_compound().await.unwrap();

        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0].0.command, Command::Create);
        assert_eq!(responses[1].0.command, Command::Read);
        assert_eq!(responses[2].0.command, Command::Close);

        // Verify the READ body contains our data.
        let mut cursor = ReadCursor::new(&responses[1].1);
        let read_body = ReadResponse::unpack(&mut cursor).unwrap();
        assert_eq!(read_body.data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[tokio::test]
    async fn send_compound_increments_message_ids_by_credit_charge() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 256;

        let create_req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(FileAccessMask::FILE_READ_DATA),
            file_attributes: 0,
            share_access: ShareAccess(ShareAccess::FILE_SHARE_READ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: "t.txt".to_string(),
            create_contexts: vec![],
        };
        let read_req = ReadRequest {
            padding: 0x50,
            flags: 0,
            length: 65536 * 4, // 256 KB -> CreditCharge = 4
            offset: 0,
            file_id: FileId::SENTINEL,
            minimum_count: 0,
            channel: SMB2_CHANNEL_NONE,
            remaining_bytes: 0,
            read_channel_info: vec![],
        };
        let close_req = CloseRequest {
            flags: 0,
            file_id: FileId::SENTINEL,
        };

        let operations: Vec<(Command, &dyn Pack, CreditCharge)> = vec![
            (Command::Create, &create_req, CreditCharge(1)),
            (Command::Read, &read_req, CreditCharge(4)),
            (Command::Close, &close_req, CreditCharge(1)),
        ];

        let msg_ids = conn.send_compound(TreeId(1), &operations).await.unwrap();

        // CREATE: msg_id=0, charge=1 -> next = 1
        // READ:   msg_id=1, charge=4 -> next = 5
        // CLOSE:  msg_id=5, charge=1 -> next = 6
        assert_eq!(msg_ids[0], MessageId(0));
        assert_eq!(msg_ids[1], MessageId(1));
        assert_eq!(msg_ids[2], MessageId(5));
        assert_eq!(conn.next_message_id(), 6);
    }

    #[tokio::test]
    async fn receive_compound_updates_credits() {
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 1,
            volatile: 2,
        };
        let create_resp = build_test_create_response(file_id, 0);
        let read_resp = build_test_read_response(vec![]);
        let close_resp = build_test_close_response();

        let frame = build_compound_response_frame(&[create_resp, read_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 3;

        let _responses = conn.receive_compound().await.unwrap();

        // Each response grants 10 credits, consumes 1 (CreditCharge=1 default from new_request).
        // Initial: 3
        // After resp1: 3 + 10 - 0 (credit_charge 0 from new_request default) = 13
        // After resp2: 13 + 10 - 0 = 23
        // After resp3: 23 + 10 - 0 = 33
        // (new_request sets credit_charge to CreditCharge(0))
        assert!(conn.credits() > 3);
    }

    // ── Compression tests ────────────────────────────────────────────

    use crate::msg::negotiate::COMPRESSION_LZ4;
    use crate::msg::transform::{
        CompressionTransformHeader, COMPRESSION_ALGORITHM_LZ4, COMPRESSION_PROTOCOL_ID,
        SMB2_COMPRESSION_FLAG_NONE,
    };

    /// Build a negotiate response that includes a compression context with LZ4.
    fn build_negotiate_response_with_compression(dialect: Dialect) -> Vec<u8> {
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
            negotiate_contexts: vec![
                NegotiateContext::PreauthIntegrity {
                    hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                    salt: vec![0xBB; 32],
                },
                NegotiateContext::Compression {
                    flags: 0,
                    algorithms: vec![COMPRESSION_LZ4],
                },
            ],
        };
        pack_message(&resp_header, &resp_body)
    }

    #[tokio::test]
    async fn negotiate_detects_compression_support() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response_with_compression(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.negotiate().await.unwrap();

        let params = conn.params().unwrap();
        assert!(params.compression_supported);
        assert!(conn.compression_enabled());
    }

    #[tokio::test]
    async fn negotiate_without_compression_context_disables_compression() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.negotiate().await.unwrap();

        let params = conn.params().unwrap();
        assert!(!params.compression_supported);
        assert!(!conn.compression_enabled());
    }

    #[tokio::test]
    async fn compression_disabled_when_client_config_says_no() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response_with_compression(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_compression_requested(false);
        conn.negotiate().await.unwrap();

        // Server supports it, but client disabled it.
        let params = conn.params().unwrap();
        assert!(params.compression_supported);
        assert!(!conn.compression_enabled());
    }

    #[tokio::test]
    async fn negotiate_offers_compression_context_when_requested() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response_with_compression(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        // compression_requested defaults to true.
        conn.negotiate().await.unwrap();

        // Parse the sent negotiate request and check for compression context.
        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = NegotiateRequest::unpack(&mut cursor).unwrap();

        let has_compression = req.negotiate_contexts.iter().any(|ctx| {
            matches!(ctx, NegotiateContext::Compression { algorithms, .. }
                if algorithms.contains(&COMPRESSION_LZ4))
        });
        assert!(
            has_compression,
            "negotiate request should include compression context with LZ4"
        );
    }

    #[tokio::test]
    async fn negotiate_does_not_offer_compression_when_disabled() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_negotiate_response(Dialect::Smb3_1_1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_compression_requested(false);
        conn.negotiate().await.unwrap();

        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = Header::unpack(&mut cursor).unwrap();
        let req = NegotiateRequest::unpack(&mut cursor).unwrap();

        let has_compression = req
            .negotiate_contexts
            .iter()
            .any(|ctx| matches!(ctx, NegotiateContext::Compression { .. }));
        assert!(
            !has_compression,
            "negotiate request should not include compression context"
        );
    }

    #[tokio::test]
    async fn send_request_compresses_compressible_data() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 256;
        conn.compression_enabled = true;

        // Build a request with highly compressible payload.
        // We need a body that produces bytes larger than Header::SIZE.
        use crate::msg::write::WriteRequest;
        let compressible_data: Vec<u8> = b"AAAA".iter().copied().cycle().take(4096).collect();
        let write_req = WriteRequest {
            data_offset: 0x70,
            offset: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: compressible_data,
        };

        let (_msg_id, _original_bytes) = conn
            .send_request(Command::Write, &write_req, Some(TreeId(1)))
            .await
            .unwrap();

        // Check that the sent data starts with a compression transform header.
        let sent = mock.sent_message(0).unwrap();
        assert_eq!(
            &sent[0..4],
            &COMPRESSION_PROTOCOL_ID,
            "compressible message should be sent with compression transform header"
        );

        // Parse the header and verify it's valid.
        let mut cursor = ReadCursor::new(&sent);
        let comp_header = CompressionTransformHeader::unpack(&mut cursor).unwrap();
        assert_eq!(comp_header.compression_algorithm, COMPRESSION_ALGORITHM_LZ4);
        assert_eq!(comp_header.flags, SMB2_COMPRESSION_FLAG_NONE);

        // The compressed frame should be smaller than the original.
        assert!(
            sent.len() < _original_bytes.len(),
            "compressed frame ({}) should be smaller than original ({})",
            sent.len(),
            _original_bytes.len()
        );
    }

    #[tokio::test]
    async fn send_request_does_not_compress_when_disabled() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 256;
        conn.compression_enabled = false; // Compression disabled.

        // Build a request with compressible payload.
        use crate::msg::write::WriteRequest;
        let compressible_data: Vec<u8> = b"AAAA".iter().copied().cycle().take(4096).collect();
        let write_req = WriteRequest {
            data_offset: 0x70,
            offset: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: compressible_data,
        };

        let (_msg_id, _original_bytes) = conn
            .send_request(Command::Write, &write_req, Some(TreeId(1)))
            .await
            .unwrap();

        // Check that the sent data starts with the normal SMB2 protocol ID, not compression.
        let sent = mock.sent_message(0).unwrap();
        assert_eq!(
            &sent[0..4],
            &crate::msg::header::PROTOCOL_ID,
            "message should be sent uncompressed when compression is disabled"
        );
    }

    #[tokio::test]
    async fn receive_response_decompresses_compressed_data() {
        let mock = Arc::new(MockTransport::new());

        // Build a READ response with a compressible payload (repeated pattern).
        let compressible_data: Vec<u8> = b"DECOMPRESS_TEST_"
            .iter()
            .copied()
            .cycle()
            .take(4096)
            .collect();
        let mut resp_header = Header::new_request(Command::Read);
        resp_header.flags.set_response();
        resp_header.credits = 10;
        resp_header.message_id = MessageId(0);
        let resp_body = ReadResponse {
            data_offset: 0x50,
            data_remaining: 0,
            flags: 0,
            data: compressible_data,
        };
        let original_resp = pack_message(&resp_header, &resp_body);

        // Compress it using our compress function.
        let compressed = compress_message(&original_resp, Header::SIZE)
            .expect("large read response should compress");

        // Build the compressed frame.
        let framed = build_compressed_frame(&compressed);

        // Queue it as a response.
        mock.queue_response(framed);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 10;

        let (header, body, raw) = conn.receive_response().await.unwrap();
        assert_eq!(header.command, Command::Read);
        assert!(header.is_response());
        // The raw bytes should be the decompressed message.
        assert_eq!(raw, original_resp);

        // Verify the body contains the read data.
        let mut cursor = ReadCursor::new(&body);
        let read_body = ReadResponse::unpack(&mut cursor).unwrap();
        assert_eq!(read_body.data.len(), 4096);
    }

    #[tokio::test]
    async fn receive_response_handles_uncompressed_data() {
        let mock = Arc::new(MockTransport::new());

        // Build a normal (uncompressed) SMB2 response.
        let mut resp_header = Header::new_request(Command::Echo);
        resp_header.flags.set_response();
        resp_header.credits = 10;
        let resp_body = crate::msg::echo::EchoResponse;
        let original_resp = pack_message(&resp_header, &resp_body);

        mock.queue_response(original_resp.clone());

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 10;

        let (header, _body, raw) = conn.receive_response().await.unwrap();
        assert_eq!(header.command, Command::Echo);
        assert_eq!(raw, original_resp);
    }

    #[test]
    fn build_compressed_frame_roundtrip() {
        // Create a message with a compressible payload.
        let mut message = vec![0xFE; Header::SIZE]; // header-like prefix
        let payload: Vec<u8> = b"COMPRESS_ME_".iter().copied().cycle().take(2048).collect();
        message.extend_from_slice(&payload);

        let compressed = compress_message(&message, Header::SIZE).expect("should compress");
        let framed = build_compressed_frame(&compressed);

        // Verify the frame starts with compression protocol ID.
        assert_eq!(&framed[0..4], &COMPRESSION_PROTOCOL_ID);

        // Decompress and verify roundtrip.
        let decompressed = decompress_response(&framed).expect("should decompress");
        assert_eq!(decompressed, message);
    }

    #[test]
    fn decompress_response_rejects_unsupported_algorithm() {
        // Build a compression transform header with an unsupported algorithm.
        let header = CompressionTransformHeader {
            original_compressed_segment_size: 100,
            compression_algorithm: 0x0001, // LZNT1, not LZ4
            flags: SMB2_COMPRESSION_FLAG_NONE,
            offset_or_length: 0,
        };
        let mut cursor = WriteCursor::new();
        header.pack(&mut cursor);
        let mut frame = cursor.into_inner();
        frame.extend_from_slice(&[0u8; 10]); // bogus data

        let result = decompress_response(&frame);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported compression algorithm"));
    }

    #[test]
    fn decompress_response_rejects_chained_compression() {
        let header = CompressionTransformHeader {
            original_compressed_segment_size: 100,
            compression_algorithm: COMPRESSION_ALGORITHM_LZ4,
            flags: 0x0001, // chained
            offset_or_length: 0,
        };
        let mut cursor = WriteCursor::new();
        header.pack(&mut cursor);
        let mut frame = cursor.into_inner();
        frame.extend_from_slice(&[0u8; 10]);

        let result = decompress_response(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unchained"));
    }

    #[test]
    fn decompress_response_rejects_too_short_data() {
        let result = decompress_response(&[0xFC, b'S', b'M']);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    // ── Unsolicited oplock break tests ─────────────────────────────

    use crate::msg::oplock_break::OplockBreak;

    /// Build an unsolicited oplock break notification frame.
    fn build_oplock_break_notification() -> Vec<u8> {
        let mut h = Header::new_request(Command::OplockBreak);
        h.message_id = MessageId::UNSOLICITED;
        h.flags.set_response();
        h.credits = 0;

        let body = OplockBreak {
            oplock_level: OplockLevel::LevelII,
            file_id: FileId {
                persistent: 0x1234,
                volatile: 0x5678,
            },
        };

        pack_message(&h, &body)
    }

    /// Build a simple Echo response for use as the "real" response
    /// after oplock break notifications.
    fn build_echo_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::Echo);
        h.flags.set_response();
        h.credits = 10;
        h.message_id = MessageId(42);

        let body = crate::msg::echo::EchoResponse;
        pack_message(&h, &body)
    }

    #[tokio::test]
    async fn receive_response_skips_unsolicited_oplock_break() {
        let mock = Arc::new(MockTransport::new());

        // Queue an oplock break notification followed by a normal response.
        mock.queue_response(build_oplock_break_notification());
        mock.queue_response(build_echo_response());

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 10;

        let (header, _body, _raw) = conn.receive_response().await.unwrap();

        // Should have skipped the oplock break and returned the Echo response.
        assert_eq!(header.command, Command::Echo);
        assert_eq!(header.message_id, MessageId(42));

        // Both messages should have been received from the mock.
        assert_eq!(mock.received_count(), 2);
    }

    #[tokio::test]
    async fn receive_response_skips_multiple_oplock_breaks() {
        let mock = Arc::new(MockTransport::new());

        // Queue 3 oplock break notifications then a normal response.
        mock.queue_response(build_oplock_break_notification());
        mock.queue_response(build_oplock_break_notification());
        mock.queue_response(build_oplock_break_notification());
        mock.queue_response(build_echo_response());

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 10;

        let (header, _body, _raw) = conn.receive_response().await.unwrap();

        assert_eq!(header.command, Command::Echo);
        assert_eq!(header.message_id, MessageId(42));

        // All 4 messages should have been received from the mock.
        assert_eq!(mock.received_count(), 4);
    }

    #[tokio::test]
    async fn receive_compound_skips_unsolicited_oplock_break() {
        let mock = Arc::new(MockTransport::new());

        // Queue an oplock break notification before the compound response.
        mock.queue_response(build_oplock_break_notification());

        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let create_resp = build_test_create_response(file_id, 100);
        let close_resp = build_test_close_response();
        let frame = build_compound_response_frame(&[create_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.credits = 10;

        let responses = conn.receive_compound().await.unwrap();

        // Should have skipped the oplock break and returned the compound.
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].0.command, Command::Create);
        assert_eq!(responses[1].0.command, Command::Close);

        // Both frames should have been received from the mock.
        assert_eq!(mock.received_count(), 2);
    }
}
