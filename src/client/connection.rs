//! Connection state and message exchange with actor-based routing.
//!
//! The [`Connection`] type manages a single TCP connection to an SMB server.
//! A background receiver task owns the transport's read half, demultiplexes
//! incoming frames by `MessageId`, and routes each response to the matching
//! per-request `oneshot::Sender`. The caller-thread path holds the write
//! half (guarded by its own Mutex via the transport trait) and pushes a
//! per-request `oneshot::Receiver` onto a FIFO that `receive_response`
//! pops from.
//!
//! See `docs/specs/connection-actor.md` for the full design (Phase 2).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use log::{debug, info, trace, warn};
use tokio::sync::oneshot;

use crate::crypto::compression::{compress_message, decompress_message, CompressedMessage};
use crate::crypto::encryption::{self, Cipher, NonceGenerator};
use crate::crypto::kdf::PreauthHasher;
use crate::crypto::signing::{self, SigningAlgorithm};
use crate::error::{Error, Result};
use crate::msg::header::Header;
use crate::msg::negotiate::{
    NegotiateContext, NegotiateRequest, NegotiateResponse, CIPHER_AES_128_CCM, CIPHER_AES_128_GCM,
    CIPHER_AES_256_CCM, CIPHER_AES_256_GCM, COMPRESSION_LZ4, HASH_ALGORITHM_SHA512,
    SIGNING_AES_CMAC, SIGNING_AES_GMAC, SIGNING_HMAC_SHA256,
};
use crate::msg::transform::{
    CompressionTransformHeader, TransformHeader, COMPRESSION_ALGORITHM_LZ4,
    COMPRESSION_PROTOCOL_ID, SMB2_COMPRESSION_FLAG_NONE, TRANSFORM_PROTOCOL_ID,
};
use crate::pack::{Guid, Pack, ReadCursor, Unpack, WriteCursor};
use crate::transport::{TcpTransport, TransportReceive, TransportSend};
use crate::types::flags::{Capabilities, HeaderFlags, SecurityMode};
use crate::types::status::NtStatus;
use crate::types::{Command, CreditCharge, Dialect, MessageId, SessionId, TreeId};

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

/// A received SMB2 sub-response, post-decrypt / post-decompress / post-header-parse.
///
/// This is what `Connection::execute` / `execute_with_credits` return on
/// success (and what each inner `Result` in `execute_compound`'s return
/// vector wraps). The three fields cover every downstream parse need:
///
/// - `header`: the parsed SMB2 header. Includes `status`, `command`,
///   `message_id`, `credits`, `tree_id`, etc.
/// - `body`: the sub-frame bytes after the header (i.e.
///   `raw[Header::SIZE..]`). Most callers unpack this via `ReadCursor` +
///   `Unpack`.
/// - `raw`: the full sub-frame bytes, header included. Kept for preauth
///   hash updates and any caller that wants to re-verify signatures or
///   inspect the original wire bytes.
///
/// Callers receive one `Frame` per matched `MessageId`. Frames are owned;
/// the receiver task allocates fresh `Vec`s for `body` / `raw` as it splits
/// compound frames, so you can store or mutate them freely.
#[derive(Debug)]
pub struct Frame {
    /// Parsed SMB2 header of this sub-response.
    pub header: Header,
    /// Sub-frame bytes after the header (body portion only).
    pub body: Vec<u8>,
    /// Full sub-frame bytes including the header.
    pub raw: Vec<u8>,
}

/// One sub-operation in a compound request, as passed to
/// [`Connection::execute_compound`].
///
/// Each `CompoundOp` describes a single SMB2 operation (CREATE, READ,
/// CLOSE, etc.) that the receiver side pairs with a [`Frame`] response
/// by `MessageId`. The server MAY split compound responses into multiple
/// transport frames — the receiver task handles that transparently; each
/// sub-op still gets routed to its own waiter by msg_id.
///
/// Field-by-field:
///
/// - `command`: the SMB2 command code (`Create`, `Read`, `Write`, etc.).
/// - `body`: the packed request body as a `&dyn Pack`. Typical callers
///   pass `&MyRequest { ... }` — the trait object lets one compound
///   chain hold heterogeneous request types.
/// - `tree_id`: the `TreeId` to stamp into the header, or `None` when
///   the op predates tree connect (for example, SESSION_SETUP in a
///   compound). For ordinary file ops, pass `Some(tree.tree_id)`.
/// - `credit_charge`: the number of credits (and consecutive MessageIds)
///   this op consumes. Most ops use `CreditCharge(1)`. Large READ / WRITE
///   ops consume `ceil(payload_size / 65536)` — see the docs on
///   [`execute_with_credits`](Connection::execute_with_credits) for details.
pub struct CompoundOp<'a> {
    /// The SMB2 command code.
    pub command: Command,
    /// The packed request body, as a `&dyn Pack`.
    pub body: &'a dyn Pack,
    /// `Some(tree_id)` for tree-scoped ops, `None` for connection-level ones.
    pub tree_id: Option<TreeId>,
    /// Credit charge (and consecutive-MessageId count) for this sub-op.
    pub credit_charge: CreditCharge,
}

impl<'a> CompoundOp<'a> {
    /// Build a `CompoundOp` with the default single-credit charge.
    ///
    /// Equivalent to setting `credit_charge: CreditCharge(1)`. For reads
    /// or writes larger than 64 KB, construct the struct directly with
    /// the right charge.
    pub fn new(command: Command, body: &'a dyn Pack, tree_id: Option<TreeId>) -> Self {
        Self {
            command,
            body,
            tree_id,
            credit_charge: CreditCharge(1),
        }
    }
}

/// Crypto state shared between the caller thread (sending) and receiver task
/// (verifying signatures, decrypting).
///
/// Uses `std::sync::Mutex` because the critical sections are short and never
/// hold the lock across an `.await`. Mutation is rare (once at session setup),
/// reads happen once per frame on either side.
struct CryptoState {
    signing_key: Option<Vec<u8>>,
    signing_algorithm: Option<SigningAlgorithm>,
    should_sign: bool,
    encryption_key: Option<Vec<u8>>,
    decryption_key: Option<Vec<u8>>,
    encryption_cipher: Option<Cipher>,
    should_encrypt: bool,
    nonce_gen: Option<NonceGenerator>,
    session_id: SessionId,
}

impl CryptoState {
    fn new() -> Self {
        Self {
            signing_key: None,
            signing_algorithm: None,
            should_sign: false,
            encryption_key: None,
            decryption_key: None,
            encryption_cipher: None,
            should_encrypt: false,
            nonce_gen: None,
            session_id: SessionId::NONE,
        }
    }
}

/// Shared connection state held in an `Arc` by the caller-facing `Connection`
/// (including all its clones) and the spawned receiver task.
///
/// Phase 3 Stage A.1 moved all connection-wide state here so `Connection`
/// can be `Clone`: each clone shares the same `Arc<Inner>` and therefore
/// sees the same credits, session id, negotiated params, and crypto state.
/// Phase 3 Stage A.3 removed the legacy caller-local FIFO and orphan-filter
/// fallback channel; `execute` / `execute_compound` own their per-call
/// `oneshot::Receiver`s locally, so there is no per-clone bookkeeping at
/// all now — `Connection` is just a handle to `Arc<Inner>`.
struct Inner {
    /// Per-request routing: msg_id → oneshot sender waiting for its response.
    waiters: StdMutex<HashMap<MessageId, oneshot::Sender<Result<Frame>>>>,
    /// Credits available to the caller. Updated by the receiver task on every
    /// frame (orphans included), read by the caller thread for pre-send checks.
    credits: AtomicU32,
    /// Next message id to allocate. Incremented by caller on send.
    next_message_id: AtomicU64,
    /// Crypto state for signing / encryption.
    crypto: StdMutex<CryptoState>,
    /// Set to true when the receiver task exits (transport error / EOF).
    /// New `execute` / `execute_compound` calls short-circuit to
    /// `Err(Disconnected)` once this flips so they don't register waiters
    /// into a dead map.
    disconnected: AtomicBool,

    /// Shared transport send handle. `TransportSend::send` takes `&self` so
    /// this can be called from any clone without a wrapping mutex — the
    /// transport's implementation already serializes writes internally.
    sender: Arc<dyn TransportSend>,
    /// Handle for the background receiver task. Aborted when the last clone
    /// of `Connection` drops (via `Inner`'s `Drop`). The transport's read
    /// half's EOF also stops the task; the abort is a safety net.
    receiver_task: StdMutex<Option<tokio::task::JoinHandle<()>>>,

    /// Server name (hostname or IP) used for UNC paths. Set at construction
    /// and never mutated.
    server_name: String,
    /// Negotiated parameters, populated once by `negotiate`.
    params: OnceLock<NegotiatedParams>,
    /// Estimated round-trip time measured during negotiate.
    estimated_rtt: StdMutex<Option<Duration>>,
    /// Whether compression is active on this connection (negotiated).
    compression_enabled: AtomicBool,
    /// Whether the client wants compression (from config).
    compression_requested: AtomicBool,
    /// Preauth integrity hash (for SMB 3.1.1 key derivation). Mutated during
    /// negotiate and session setup; both happen on one task before any clone
    /// is expected to observe it.
    preauth_hasher: StdMutex<PreauthHasher>,
    /// Tree IDs that have DFS capability (auto-set `SMB2_FLAGS_DFS_OPERATIONS`).
    dfs_trees: StdMutex<HashSet<TreeId>>,
}

impl Inner {
    fn new(sender: Arc<dyn TransportSend>, server_name: String) -> Self {
        Self {
            waiters: StdMutex::new(HashMap::new()),
            credits: AtomicU32::new(1),
            next_message_id: AtomicU64::new(0),
            crypto: StdMutex::new(CryptoState::new()),
            disconnected: AtomicBool::new(false),
            sender,
            receiver_task: StdMutex::new(None),
            server_name,
            params: OnceLock::new(),
            estimated_rtt: StdMutex::new(None),
            compression_enabled: AtomicBool::new(false),
            compression_requested: AtomicBool::new(true),
            preauth_hasher: StdMutex::new(PreauthHasher::new()),
            dfs_trees: StdMutex::new(HashSet::new()),
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Last `Arc<Inner>` dropping: abort the receiver task if still alive.
        if let Some(handle) = self.receiver_task.lock().unwrap().take() {
            handle.abort();
        }
    }
}

/// Low-level connection with actor-based response routing.
///
/// Manages credit tracking, message ID sequencing, preauth integrity hash,
/// message signing, and encryption. A background receiver task owns the
/// transport's read half and routes each incoming frame to the
/// `oneshot::Sender` registered for its `MessageId`. Callers go through
/// [`execute`](Self::execute) / [`execute_compound`](Self::execute_compound)
/// which register the waiter, send the frame, and await the matching
/// `oneshot::Receiver` — all owned locally by the future, so dropping the
/// future mid-flight is safe (the late arrival is discarded on the receiver
/// task when the `Sender` fails to deliver).
///
/// `Connection` is `Clone`; cloning is a cheap `Arc::clone` bump. All clones
/// share the same receiver task, credits, and waiters map, so concurrent
/// `execute` calls on different clones multiplex over the same SMB session.
#[derive(Clone)]
pub struct Connection {
    /// Shared state (credits, waiters, crypto, transport sender, negotiated
    /// params, receiver task) behind `Arc<Inner>`. `clone()` bumps this.
    inner: Arc<Inner>,
}

impl Connection {
    /// Create a connection from an existing transport (for testing with mock).
    pub fn from_transport(
        sender: Box<dyn TransportSend>,
        receiver: Box<dyn TransportReceive>,
        server_name: impl Into<String>,
    ) -> Self {
        let sender: Arc<dyn TransportSend> = Arc::from(sender);
        let inner = Arc::new(Inner::new(sender, server_name.into()));
        let inner_for_task = Arc::clone(&inner);
        let handle = tokio::spawn(async move {
            receiver_loop(receiver, inner_for_task).await;
        });
        *inner.receiver_task.lock().unwrap() = Some(handle);
        Self { inner }
    }

    /// Connect to an SMB server over TCP.
    pub async fn connect(addr: &str, timeout: Duration) -> Result<Self> {
        let server_name = addr.split(':').next().unwrap_or(addr).to_string();
        let transport = TcpTransport::connect(addr, timeout).await?;
        info!("connection: connected to {}", addr);
        let transport = Arc::new(transport);
        Ok(Self::from_transport(
            Box::new(Arc::clone(&transport)),
            Box::new(transport),
            server_name,
        ))
    }

    /// Perform the SMB2 NEGOTIATE exchange.
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

        if self.inner.compression_requested.load(Ordering::Acquire) {
            negotiate_contexts.push(NegotiateContext::Compression {
                flags: 0,
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

        // Register a waiter for msg_id=0 (negotiate is always first).
        let mut header = Header::new_request(Command::Negotiate);
        let msg_id = self.allocate_msg_id(1);
        header.message_id = msg_id;
        header.credits = 1;
        let req_bytes = pack_message(&header, &request);

        // Update preauth hash with request bytes.
        self.inner.preauth_hasher.lock().unwrap().update(&req_bytes);

        let rx = self.register_waiter(msg_id)?;

        let rtt_start = std::time::Instant::now();
        if let Err(e) = self.inner.sender.send(&req_bytes).await {
            self.remove_waiter(msg_id);
            return Err(e);
        }

        let frame = await_frame(rx).await?;
        *self.inner.estimated_rtt.lock().unwrap() = Some(rtt_start.elapsed());

        // Preauth hash update with response bytes.
        self.inner.preauth_hasher.lock().unwrap().update(&frame.raw);

        let resp_header = &frame.header;
        if !resp_header.is_response() {
            return Err(Error::invalid_data("expected a response but got a request"));
        }
        if resp_header.command != Command::Negotiate {
            return Err(Error::invalid_data(format!(
                "expected Negotiate response, got {:?}",
                resp_header.command
            )));
        }

        if resp_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp_header.status,
                command: Command::Negotiate,
            });
        }

        // Parse the body.
        let mut cursor = ReadCursor::new(&frame.body);
        let resp = NegotiateResponse::unpack(&mut cursor)?;

        if !Dialect::ALL.contains(&resp.dialect_revision) {
            return Err(Error::invalid_data(format!(
                "server selected dialect 0x{:04X} which we did not offer",
                u16::from(resp.dialect_revision)
            )));
        }
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

        let mut gmac_negotiated = false;
        let mut cipher = None;
        let mut compression_supported = false;

        for ctx in &resp.negotiate_contexts {
            match ctx {
                NegotiateContext::Signing { algorithms }
                    if algorithms.contains(&SIGNING_AES_GMAC) =>
                {
                    gmac_negotiated = true;
                }
                NegotiateContext::Encryption { ciphers } => {
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
                NegotiateContext::Compression { algorithms, .. }
                    if algorithms.contains(&COMPRESSION_LZ4) =>
                {
                    compression_supported = true;
                }
                _ => {}
            }
        }

        let signing_required = resp.security_mode.signing_required();
        let compression_enabled =
            self.inner.compression_requested.load(Ordering::Acquire) && compression_supported;
        self.inner
            .compression_enabled
            .store(compression_enabled, Ordering::Release);

        // OnceLock: set is idempotent-first-writer-wins. Re-negotiation isn't
        // a supported flow; if this ever fails it means negotiate was called
        // twice on the same connection.
        let _ = self.inner.params.set(NegotiatedParams {
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
            resp.server_guid, cipher, gmac_negotiated, compression_enabled
        );

        Ok(())
    }

    /// Get the estimated round-trip time.
    pub fn estimated_rtt(&self) -> Option<Duration> {
        *self.inner.estimated_rtt.lock().unwrap()
    }

    /// Get the negotiated parameters.
    pub fn params(&self) -> Option<&NegotiatedParams> {
        self.inner.params.get()
    }

    /// Get a clone of the preauth hasher's current state.
    ///
    /// The hasher lives behind a lock (shared across `Connection` clones
    /// now that the type is `Clone`). Callers that want to derive per-session
    /// keys — see `session.rs` — take a snapshot via this method and feed
    /// their own session-specific updates into it without disturbing the
    /// shared connection-level hasher. Returning an owned clone is ~a few
    /// hundred bytes of SHA-512 state; cheaper than the actual KDF it feeds.
    pub fn preauth_hasher(&self) -> PreauthHasher {
        self.inner.preauth_hasher.lock().unwrap().clone()
    }

    /// Run a closure with a mutable borrow of the preauth hasher.
    ///
    /// The hasher lives behind a lock now that `Connection` is `Clone`; a
    /// naked `&mut PreauthHasher` can no longer be handed out. Closure-based
    /// access keeps the lock scoped to the caller's update.
    #[doc(hidden)] // unused outside the crate; kept for crate-internal parity.
    pub fn with_preauth_hasher_mut<R>(&self, f: impl FnOnce(&mut PreauthHasher) -> R) -> R {
        let mut h = self.inner.preauth_hasher.lock().unwrap();
        f(&mut h)
    }

    /// Set the session ID.
    pub fn set_session_id(&mut self, id: SessionId) {
        self.inner.crypto.lock().unwrap().session_id = id;
    }

    /// Get the current session ID.
    pub fn session_id(&self) -> SessionId {
        self.inner.crypto.lock().unwrap().session_id
    }

    /// Activate signing with the given key and algorithm.
    pub fn activate_signing(&mut self, key: Vec<u8>, algorithm: SigningAlgorithm) {
        debug!(
            "signing: activated, algo={:?}, key_len={}",
            algorithm,
            key.len()
        );
        let mut c = self.inner.crypto.lock().unwrap();
        c.signing_key = Some(key);
        c.signing_algorithm = Some(algorithm);
        c.should_sign = true;
    }

    /// Activate encryption with the given keys and cipher.
    pub fn activate_encryption(&mut self, enc_key: Vec<u8>, dec_key: Vec<u8>, cipher: Cipher) {
        debug!(
            "encryption: activated, cipher={:?}, enc_key_len={}, dec_key_len={}",
            cipher,
            enc_key.len(),
            dec_key.len()
        );
        let mut c = self.inner.crypto.lock().unwrap();
        c.encryption_key = Some(enc_key);
        c.decryption_key = Some(dec_key);
        c.encryption_cipher = Some(cipher);
        c.nonce_gen = Some(NonceGenerator::new());
        c.should_encrypt = true;
    }

    /// Whether encryption is active on this connection.
    pub fn should_encrypt(&self) -> bool {
        self.inner.crypto.lock().unwrap().should_encrypt
    }

    /// Get the current number of available credits.
    pub fn credits(&self) -> u16 {
        self.inner.credits.load(Ordering::Acquire) as u16
    }

    /// Get the next message ID (without incrementing).
    pub fn next_message_id(&self) -> u64 {
        self.inner.next_message_id.load(Ordering::Acquire)
    }

    /// Get the server name.
    pub fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    /// Set whether the client wants compression.
    pub fn set_compression_requested(&mut self, requested: bool) {
        self.inner
            .compression_requested
            .store(requested, Ordering::Release);
    }

    /// Whether compression is active on this connection.
    pub fn compression_enabled(&self) -> bool {
        self.inner.compression_enabled.load(Ordering::Acquire)
    }

    /// Send a single SMB2 request and wait for its response.
    ///
    /// Takes `&self` so multiple clones of a `Connection` can call `execute`
    /// concurrently from different tasks — the receiver task routes each
    /// response to its own `oneshot::Sender` by `MessageId`. Cancellation
    /// by drop is safe by construction: if the caller's future is dropped
    /// before the response arrives, the `oneshot::Receiver` drops, and
    /// the receiver task discards the late frame silently on arrival
    /// (credits still apply).
    ///
    /// Equivalent to `execute_with_credits(command, body, tree_id, CreditCharge(1))`.
    /// For large READ / WRITE ops (> 64 KB payload), use `execute_with_credits`
    /// with a charge of `ceil(payload_size / 65536)` — each credit consumed
    /// also consumes one consecutive `MessageId`, and gaps in the id
    /// sequence cause the server to drop the connection.
    pub async fn execute(
        &self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
    ) -> Result<Frame> {
        self.execute_with_credits(command, body, tree_id, CreditCharge(1))
            .await
    }

    /// Crate-internal variant of [`execute`] that also returns the plaintext
    /// request bytes that were packed on the wire (before any encryption).
    ///
    /// Only `session.rs` needs this: its SESSION_SETUP rounds feed the
    /// *request* bytes into the session-local preauth hasher for key
    /// derivation, and the signed/encrypted wire form would break the
    /// hash because preauth covers the plaintext. Rather than forcing
    /// session.rs to re-pack messages with a predicted msg_id, we let
    /// `execute_with_credits_capturing_request` hand them back.
    pub(crate) async fn execute_capturing_request(
        &self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
    ) -> Result<(Frame, Vec<u8>)> {
        self.execute_with_credits_capturing_request(command, body, tree_id, CreditCharge(1))
            .await
    }

    /// See [`Self::execute_capturing_request`].
    pub(crate) async fn execute_with_credits_capturing_request(
        &self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
        credit_charge: CreditCharge,
    ) -> Result<(Frame, Vec<u8>)> {
        if self.inner.disconnected.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        let charge = credit_charge.0.max(1);
        let msg_id = self.allocate_msg_id(charge as u64);

        let mut header = Header::new_request(command);
        header.message_id = msg_id;
        header.credits = 256;
        header.credit_charge = CreditCharge(charge);
        header.session_id = self.session_id();
        if let Some(tid) = tree_id {
            header.tree_id = Some(tid);
        }

        let (should_sign, should_encrypt) = {
            let c = self.inner.crypto.lock().unwrap();
            (c.should_sign, c.should_encrypt)
        };

        if should_sign && !should_encrypt {
            header.flags.set_signed();
        }
        if self.should_set_dfs_flag(tree_id) {
            header.flags |= HeaderFlags::new(HeaderFlags::DFS_OPERATIONS);
        }

        let mut msg_bytes = pack_message(&header, body);
        let captured = msg_bytes.clone();

        let rx = self.register_waiter(msg_id)?;

        let wire_bytes = if should_encrypt {
            match self.encrypt_bytes(&msg_bytes) {
                Ok(enc) => enc,
                Err(e) => {
                    self.remove_waiter(msg_id);
                    return Err(e);
                }
            }
        } else {
            if should_sign {
                let c = self.inner.crypto.lock().unwrap();
                if let (Some(key), Some(algo)) = (&c.signing_key, &c.signing_algorithm) {
                    if let Err(e) =
                        signing::sign_message(&mut msg_bytes, key, *algo, msg_id.0, false)
                    {
                        drop(c);
                        self.remove_waiter(msg_id);
                        return Err(e);
                    }
                }
            }
            msg_bytes
        };

        if let Err(e) = self.inner.sender.send(&wire_bytes).await {
            self.remove_waiter(msg_id);
            return Err(e);
        }
        debug!(
            "execute_cap: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, encrypted={}",
            command, msg_id.0, charge, tree_id, should_sign, should_encrypt
        );
        let frame = await_frame(rx).await?;
        Ok((frame, captured))
    }

    /// Send a single SMB2 request with a caller-specified credit charge.
    ///
    /// Same semantics as [`execute`](Self::execute) — see that method's doc
    /// for the concurrency / cancellation invariants — but lets the caller
    /// set `credit_charge` directly. Use `CreditCharge(ceil(payload_size /
    /// 65536))` for READ / WRITE ops larger than 64 KB.
    ///
    /// On the wire this is the same as `send_request_with_credits` +
    /// `receive_response` — the difference is that this method owns its
    /// `oneshot::Receiver` locally (not in a caller-shared FIFO), so
    /// it's safe to call from multiple tasks on clones of the same
    /// `Connection`.
    pub async fn execute_with_credits(
        &self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
        credit_charge: CreditCharge,
    ) -> Result<Frame> {
        if self.inner.disconnected.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        let charge = credit_charge.0.max(1);
        let msg_id = self.allocate_msg_id(charge as u64);

        let mut header = Header::new_request(command);
        header.message_id = msg_id;
        header.credits = 256;
        header.credit_charge = CreditCharge(charge);
        header.session_id = self.session_id();
        if let Some(tid) = tree_id {
            header.tree_id = Some(tid);
        }

        let (should_sign, should_encrypt) = {
            let c = self.inner.crypto.lock().unwrap();
            (c.should_sign, c.should_encrypt)
        };

        if should_sign && !should_encrypt {
            header.flags.set_signed();
        }
        if self.should_set_dfs_flag(tree_id) {
            header.flags |= HeaderFlags::new(HeaderFlags::DFS_OPERATIONS);
        }

        let mut msg_bytes = pack_message(&header, body);

        // Register waiter BEFORE send so the receiver task can match any
        // fast-arriving response. `register_waiter` atomically rechecks
        // `disconnected` under the waiters lock, so a receiver-task
        // teardown between the early fast-path check above and this
        // insertion returns `Err(Disconnected)` instead of leaving a
        // ghost Sender that never gets routed.
        let rx = self.register_waiter(msg_id)?;

        // Build the wire bytes with encryption / signing / compression.
        let wire_bytes = if should_encrypt {
            match self.encrypt_bytes(&msg_bytes) {
                Ok(enc) => enc,
                Err(e) => {
                    self.remove_waiter(msg_id);
                    return Err(e);
                }
            }
        } else {
            if should_sign {
                let c = self.inner.crypto.lock().unwrap();
                if let (Some(key), Some(algo)) = (&c.signing_key, &c.signing_algorithm) {
                    if let Err(e) =
                        signing::sign_message(&mut msg_bytes, key, *algo, msg_id.0, false)
                    {
                        drop(c);
                        self.remove_waiter(msg_id);
                        return Err(e);
                    }
                }
            }
            if self.compression_enabled() && msg_bytes.len() > Header::SIZE {
                if let Some(compressed) = compress_message(&msg_bytes, Header::SIZE) {
                    let framed = build_compressed_frame(&compressed);
                    match self.inner.sender.send(&framed).await {
                        Ok(()) => {
                            debug!(
                                "execute: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, compressed {}->{} bytes",
                                command, msg_id.0, charge, tree_id, should_sign,
                                msg_bytes.len(), framed.len()
                            );
                            return await_frame(rx).await;
                        }
                        Err(e) => {
                            self.remove_waiter(msg_id);
                            return Err(e);
                        }
                    }
                }
            }
            msg_bytes
        };

        if let Err(e) = self.inner.sender.send(&wire_bytes).await {
            self.remove_waiter(msg_id);
            return Err(e);
        }
        debug!(
            "execute: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, encrypted={}, len={}",
            command, msg_id.0, charge, tree_id, should_sign, should_encrypt, wire_bytes.len()
        );
        await_frame(rx).await
    }

    /// Send a compound SMB2 request (multiple operations in one transport
    /// frame) and return the per-sub-op responses.
    ///
    /// Takes `&self`. Each [`CompoundOp`] is assigned its own `MessageId`
    /// and its own `oneshot::Sender` registered in the waiters map. The
    /// server MAY split the compound response into multiple transport
    /// frames (MS-SMB2 § 3.3.4.1.3) — the receiver task's per-`MessageId`
    /// routing handles that transparently; each sub-op's waiter resolves
    /// independently.
    ///
    /// Return shape (per decision E3 in `docs/specs/connection-actor.md`):
    ///
    /// - Outer `Result`: `Err` if the compound didn't make it onto the wire
    ///   (encryption failed, signing failed, transport send failed, or the
    ///   connection was already disconnected). On this path no waiter
    ///   observes a response — we clean them up before returning.
    /// - Inner `Vec<Result<Frame>>`: one entry per sub-op, in the same
    ///   order as `ops`. `Ok(frame)` with the server's response, including
    ///   non-success statuses encoded in `frame.header.status`. `Err` when
    ///   a sub-op hit a waiter-level error (session expired, signature
    ///   verify failure, connection dropped mid-await). Compound partial
    ///   failure is protocol-normal — for example, CREATE may succeed but
    ///   a later READ fail — so callers typically match on each inner
    ///   result individually.
    pub async fn execute_compound(&self, ops: &[CompoundOp<'_>]) -> Result<Vec<Result<Frame>>> {
        if ops.is_empty() {
            return Err(Error::invalid_data(
                "compound request must have at least one operation",
            ));
        }
        if self.inner.disconnected.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }

        let (should_sign, should_encrypt) = {
            let c = self.inner.crypto.lock().unwrap();
            (c.should_sign, c.should_encrypt)
        };

        let session_id = self.session_id();
        let mut message_ids: Vec<MessageId> = Vec::with_capacity(ops.len());
        let mut sub_requests: Vec<Vec<u8>> = Vec::with_capacity(ops.len());

        for (i, op) in ops.iter().enumerate() {
            let charge = op.credit_charge.0.max(1);
            let msg_id = self.allocate_msg_id(charge as u64);

            let mut header = Header::new_request(op.command);
            header.message_id = msg_id;
            header.credits = 256;
            header.credit_charge = CreditCharge(charge);
            header.session_id = session_id;
            header.tree_id = op.tree_id;

            if i > 0 {
                header.flags.set_related();
            }
            if should_sign && !should_encrypt {
                header.flags.set_signed();
            }
            if self.should_set_dfs_flag(op.tree_id) {
                header.flags |= HeaderFlags::new(HeaderFlags::DFS_OPERATIONS);
            }

            message_ids.push(msg_id);
            sub_requests.push(pack_message(&header, op.body));
        }

        // 8-byte align all but the last sub-request, then wire up
        // `NextCommand` offsets.
        let last_idx = sub_requests.len() - 1;
        for sub_req in sub_requests.iter_mut().take(last_idx) {
            let rem = sub_req.len() % 8;
            if rem != 0 {
                let pad = 8 - rem;
                let new_len = sub_req.len() + pad;
                sub_req.resize(new_len, 0);
            }
        }
        for sub_req in sub_requests.iter_mut().take(last_idx) {
            let next_cmd = sub_req.len() as u32;
            sub_req[20..24].copy_from_slice(&next_cmd.to_le_bytes());
        }

        if should_sign && !should_encrypt {
            let c = self.inner.crypto.lock().unwrap();
            if let (Some(key), Some(algo)) = (&c.signing_key, &c.signing_algorithm) {
                for (i, sub_req) in sub_requests.iter_mut().enumerate() {
                    signing::sign_message(sub_req, key, *algo, message_ids[i].0, false)?;
                }
            }
        }

        // Register one oneshot::Receiver per sub-op BEFORE the send,
        // collected in the same order as `ops` / `message_ids`. On any
        // registration error, unregister the ones we already inserted.
        let mut receivers: Vec<oneshot::Receiver<Result<Frame>>> =
            Vec::with_capacity(message_ids.len());
        let mut registered: Vec<MessageId> = Vec::with_capacity(message_ids.len());
        for id in &message_ids {
            match self.register_waiter(*id) {
                Ok(rx) => {
                    receivers.push(rx);
                    registered.push(*id);
                }
                Err(e) => {
                    for done in &registered {
                        self.remove_waiter(*done);
                    }
                    return Err(e);
                }
            }
        }

        let total_len: usize = sub_requests.iter().map(|r| r.len()).sum();
        let mut compound_buf = Vec::with_capacity(total_len);
        for sub_req in &sub_requests {
            compound_buf.extend_from_slice(sub_req);
        }

        let send_result = if should_encrypt {
            match self.encrypt_bytes(&compound_buf) {
                Ok(enc) => self.inner.sender.send(&enc).await,
                Err(e) => {
                    for id in &registered {
                        self.remove_waiter(*id);
                    }
                    return Err(e);
                }
            }
        } else {
            self.inner.sender.send(&compound_buf).await
        };

        if let Err(e) = send_result {
            for id in &registered {
                self.remove_waiter(*id);
            }
            return Err(e);
        }

        debug!(
            "execute_compound: {} operations, total_len={}, msg_ids={:?}, signed={}, encrypted={}",
            ops.len(),
            compound_buf.len(),
            message_ids.iter().map(|m| m.0).collect::<Vec<_>>(),
            should_sign,
            should_encrypt,
        );

        // Collect per-sub-op results in submission order. Each `rx.await`
        // resolves independently — the receiver task splits the response
        // frame by `NextCommand` and routes each sub-response to its own
        // waiter, so we can await them sequentially without blocking any
        // of them (they may already all be resolved by the time we loop).
        let mut results: Vec<Result<Frame>> = Vec::with_capacity(receivers.len());
        for rx in receivers {
            results.push(await_frame(rx).await);
        }
        Ok(results)
    }

    /// Send a CANCEL request for an outstanding operation.
    pub async fn send_cancel(
        &mut self,
        original_msg_id: MessageId,
        async_id: Option<u64>,
    ) -> Result<()> {
        use crate::msg::cancel::CancelRequest;

        let (should_sign, should_encrypt) = {
            let c = self.inner.crypto.lock().unwrap();
            (c.should_sign, c.should_encrypt)
        };
        let session_id = self.session_id();

        let mut header = Header::new_request(Command::Cancel);
        header.message_id = original_msg_id;
        header.credit_charge = CreditCharge(0);
        header.credits = 0;
        header.session_id = session_id;

        if let Some(aid) = async_id {
            header.flags.set_async();
            header.async_id = Some(aid);
            header.tree_id = None;
        }
        if should_sign && !should_encrypt {
            header.flags.set_signed();
        }

        let body = CancelRequest;
        let mut msg_bytes = pack_message(&header, &body);

        if should_encrypt {
            let encrypted = self.encrypt_bytes(&msg_bytes)?;
            self.inner.sender.send(&encrypted).await?;
            debug!(
                "send_cancel: msg_id={}, async_id={:?}, encrypted",
                original_msg_id.0, async_id
            );
        } else {
            if should_sign {
                let c = self.inner.crypto.lock().unwrap();
                if let (Some(key), Some(algo)) = (&c.signing_key, &c.signing_algorithm) {
                    signing::sign_message(&mut msg_bytes, key, *algo, original_msg_id.0, false)?;
                }
            }
            self.inner.sender.send(&msg_bytes).await?;
            debug!(
                "send_cancel: msg_id={}, async_id={:?}, signed={}",
                original_msg_id.0, async_id, should_sign
            );
        }
        Ok(())
    }

    /// Encrypt plaintext into a TRANSFORM_HEADER + ciphertext frame.
    fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut c = self.inner.crypto.lock().unwrap();
        let enc_key = c
            .encryption_key
            .as_ref()
            .ok_or_else(|| Error::invalid_data("encryption active but no encryption key"))?
            .clone();
        let cipher = c
            .encryption_cipher
            .ok_or_else(|| Error::invalid_data("encryption active but no cipher"))?;
        let session_id = c.session_id.0;
        let nonce = c
            .nonce_gen
            .as_mut()
            .ok_or_else(|| Error::invalid_data("encryption active but no nonce generator"))?
            .next(cipher);
        drop(c);

        let (transform_header, ciphertext) =
            encryption::encrypt_message(plaintext, &enc_key, cipher, &nonce, session_id)?;

        let mut encrypted = transform_header;
        encrypted.extend_from_slice(&ciphertext);

        trace!(
            "encrypt: plaintext={} bytes, encrypted={} bytes, nonce={:02X?}",
            plaintext.len(),
            encrypted.len(),
            &nonce[..cipher.nonce_len()]
        );

        Ok(encrypted)
    }

    /// Register a tree as DFS-enabled.
    pub fn register_dfs_tree(&mut self, tree_id: TreeId) {
        self.inner.dfs_trees.lock().unwrap().insert(tree_id);
    }

    /// Deregister a tree from DFS tracking.
    pub fn deregister_dfs_tree(&mut self, tree_id: TreeId) {
        self.inner.dfs_trees.lock().unwrap().remove(&tree_id);
    }

    fn should_set_dfs_flag(&self, tree_id: Option<TreeId>) -> bool {
        tree_id.is_some_and(|id| self.inner.dfs_trees.lock().unwrap().contains(&id))
    }

    /// Allocate `charge` consecutive MessageIds and return the first.
    fn allocate_msg_id(&self, charge: u64) -> MessageId {
        let first = self
            .inner
            .next_message_id
            .fetch_add(charge, Ordering::SeqCst);
        MessageId(first)
    }

    /// Register a waiter in the shared map and return the Receiver.
    ///
    /// Atomically checks `disconnected` under the waiters lock. If the
    /// connection died between `send_request`'s fast-path check and
    /// this call, returns `Err(Disconnected)` without inserting —
    /// prevents a TOCTOU where the receiver task has already drained
    /// the waiters map but we'd insert a new entry that no one will
    /// ever route to, leaving the caller hanging on `rx.await`.
    ///
    /// `fan_error_to_waiters` sets `disconnected = true` under the
    /// same lock, making the two paths strictly ordered.
    fn register_waiter(&self, msg_id: MessageId) -> Result<oneshot::Receiver<Result<Frame>>> {
        let mut waiters = self.inner.waiters.lock().unwrap();
        if self.inner.disconnected.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        let (tx, rx) = oneshot::channel();
        waiters.insert(msg_id, tx);
        Ok(rx)
    }

    /// Remove a waiter from the map (used on send error).
    fn remove_waiter(&self, msg_id: MessageId) {
        self.inner.waiters.lock().unwrap().remove(&msg_id);
    }

    #[cfg(test)]
    pub(crate) fn set_test_params(&mut self, params: NegotiatedParams) {
        // OnceLock: first setter wins. Tests sometimes stage params on a
        // fresh connection; ignore any collision.
        let _ = self.inner.params.set(params);
    }

    #[cfg(test)]
    pub(crate) fn set_credits(&mut self, credits: u16) {
        self.inner.credits.store(credits as u32, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn set_next_message_id(&mut self, id: u64) {
        self.inner.next_message_id.store(id, Ordering::Release);
    }
}

// `Connection`'s teardown lives on `Inner::drop`: the receiver task is
// aborted only when the last clone drops (the last `Arc<Inner>` goes away).

/// Receiver task loop: owns the transport receive half, routes each frame
/// to its waiter.
async fn receiver_loop(transport_recv: Box<dyn TransportReceive>, inner: Arc<Inner>) {
    loop {
        let raw = match transport_recv.receive().await {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!("receiver_loop: transport error: {}, shutting down", e);
                fan_error_to_waiters(&inner, &e);
                return;
            }
        };
        trace!("receiver_loop: received {} bytes", raw.len());

        // Decrypt if TRANSFORM_HEADER. Per P3.4 / decision E6: on an
        // unrecoverable frame error (decrypt auth tag mismatch, decompress
        // failure, malformed sub-frame structure) we tear the connection
        // down instead of log-and-continue. The msg_id isn't recoverable
        // from an unparseable frame, so there's no targeted waiter to
        // notify; log-and-continue would leave the matching waiter
        // hanging forever. Teardown fans Err(Disconnected) to every
        // pending waiter; the caller reconnects.
        let (decoded, was_encrypted) = if raw.len() >= 4 && raw[0..4] == TRANSFORM_PROTOCOL_ID {
            match decrypt_frame(&raw, &inner) {
                Ok(plain) => (plain, true),
                Err(e) => {
                    warn!(
                        "receiver_loop: decrypt failed: {}; tearing down connection",
                        e
                    );
                    fan_error_to_waiters(&inner, &e);
                    return;
                }
            }
        } else {
            (raw, false)
        };

        // Decompress if COMPRESSION_HEADER.
        let decoded = if decoded.len() >= 4 && decoded[0..4] == COMPRESSION_PROTOCOL_ID {
            match decompress_response(&decoded) {
                Ok(plain) => plain,
                Err(e) => {
                    warn!(
                        "receiver_loop: decompress failed: {}; tearing down connection",
                        e
                    );
                    fan_error_to_waiters(&inner, &e);
                    return;
                }
            }
        } else {
            decoded
        };

        // Split by NextCommand.
        let sub_frames = match split_compound(&decoded) {
            Ok(subs) => subs,
            Err(e) => {
                warn!(
                    "receiver_loop: malformed frame: {}; tearing down connection",
                    e
                );
                fan_error_to_waiters(&inner, &e);
                return;
            }
        };

        // Produce a list of routable entries for this transport frame.
        // SubFrameAction::Skip frames (oplock break, STATUS_PENDING) are
        // dropped silently. A parse error from prepare_sub_frame is fatal:
        // the compound split succeeded (framing looked valid) but a header
        // inside is corrupt — the connection is out of sync and we can't
        // recover. Tear down so pending waiters see Err(Disconnected)
        // rather than hanging forever.
        let mut routable: Vec<(MessageId, Result<Frame>)> = Vec::new();
        for sub in sub_frames {
            match prepare_sub_frame(&sub, was_encrypted, &inner) {
                Ok(SubFrameAction::Route(msg_id, result)) => routable.push((msg_id, result)),
                Ok(SubFrameAction::Skip) => { /* oplock break / STATUS_PENDING */ }
                Err(e) => {
                    warn!(
                        "receiver_loop: sub-frame parse failed: {}; tearing down connection",
                        e
                    );
                    fan_error_to_waiters(&inner, &e);
                    return;
                }
            }
        }

        if routable.is_empty() {
            continue;
        }

        for (msg_id, result) in routable {
            let maybe_tx = inner.waiters.lock().unwrap().remove(&msg_id);
            match maybe_tx {
                Some(tx) => {
                    if tx.send(result).is_err() {
                        trace!("recv: late arrival for dropped waiter, msg_id={}", msg_id.0);
                    }
                }
                None => {
                    debug!("recv: orphan dropped, msg_id={}", msg_id.0);
                }
            }
        }
    }
}

/// Outcome of preparing a single sub-frame.
pub(crate) enum SubFrameAction {
    /// Route this response to the waiter for `msg_id`.
    ///
    /// The inner `Result` lets us deliver a per-sub-op error (signature
    /// verification failure, session expired) targeted at its matching
    /// waiter without disturbing others.
    Route(MessageId, std::result::Result<Frame, Error>),
    /// Skip silently — not forwarded to any waiter.
    /// Used for oplock-break notifications (MessageId=UNSOLICITED) and
    /// STATUS_PENDING interim responses (keep the waiter alive).
    Skip,
}

/// Prepare a routable sub-frame from raw bytes.
///
/// Returns `Ok(SubFrameAction::Route(...))` for a normal response (possibly
/// carrying a sub-op error), `Ok(SubFrameAction::Skip)` for oplock/PENDING
/// frames that the caller should drop silently, and `Err(e)` for
/// unrecoverable errors where the connection is now out of sync
/// (header parse failure on a sub-frame the compound-splitter claimed was
/// valid — the receiver loop fans the error to all waiters and exits).
fn prepare_sub_frame(sub: &[u8], was_encrypted: bool, inner: &Inner) -> Result<SubFrameAction> {
    // Parse the header. A failure here means split_compound produced a
    // chunk that doesn't start with a valid SMB2 header — the framing is
    // corrupt and we can't know where the next sub-frame begins. Fatal
    // to the connection.
    let mut cursor = ReadCursor::new(sub);
    let header = match Header::unpack(&mut cursor) {
        Ok(h) => h,
        Err(e) => {
            return Err(Error::invalid_data(format!(
                "sub-frame header parse failed: {}",
                e
            )));
        }
    };

    // Always update credits.
    if header.credits > 0 {
        let prev = inner.credits.load(Ordering::Relaxed) as u16;
        let next = prev.saturating_add(header.credits);
        inner.credits.store(next as u32, Ordering::Release);
    }

    // Oplock break notification: MessageId=UNSOLICITED. Skip silently.
    if header.message_id == MessageId::UNSOLICITED {
        debug!(
            "recv: skipping unsolicited oplock break notification, cmd={:?}",
            header.command
        );
        return Ok(SubFrameAction::Skip);
    }

    // STATUS_PENDING is an interim response — don't forward, keep waiter.
    if header.status.is_pending() {
        debug!(
            "recv: STATUS_PENDING (interim), cmd={:?}, msg_id={}",
            header.command, header.message_id.0
        );
        return Ok(SubFrameAction::Skip);
    }

    // Consume credit_charge (or 1 if zero).
    let consume = header.credit_charge.0.max(1);
    let prev = inner.credits.load(Ordering::Relaxed) as u16;
    inner
        .credits
        .store(prev.saturating_sub(consume) as u32, Ordering::Release);

    // Verify signature if signing is active and not encrypted.
    let (should_sign, signing_key, signing_algorithm) = {
        let c = inner.crypto.lock().unwrap();
        (c.should_sign, c.signing_key.clone(), c.signing_algorithm)
    };
    if should_sign && !was_encrypted && sub.len() >= Header::SIZE {
        let flags = u32::from_le_bytes(sub[16..20].try_into().unwrap());
        let is_signed = (flags & HeaderFlags::SIGNED) != 0;
        let status = u32::from_le_bytes(sub[8..12].try_into().unwrap());
        let is_pending = status == NtStatus::PENDING.0;
        if is_signed && !is_pending {
            if let (Some(key), Some(algo)) = (signing_key, signing_algorithm) {
                if let Err(e) =
                    signing::verify_signature(sub, &key, algo, header.message_id.0, false)
                {
                    return Ok(SubFrameAction::Route(header.message_id, Err(e)));
                }
            }
        }
    }

    // Special status handling: session expired → error.
    if header.status == NtStatus::NETWORK_SESSION_EXPIRED {
        warn!(
            "recv: session expired (STATUS_NETWORK_SESSION_EXPIRED), cmd={:?}, msg_id={}",
            header.command, header.message_id.0
        );
        return Ok(SubFrameAction::Route(
            header.message_id,
            Err(Error::SessionExpired),
        ));
    }

    let body = if sub.len() > Header::SIZE {
        sub[Header::SIZE..].to_vec()
    } else {
        Vec::new()
    };
    let raw = sub.to_vec();
    let msg_id = header.message_id;
    Ok(SubFrameAction::Route(
        msg_id,
        Ok(Frame { header, body, raw }),
    ))
}

/// Fan the given error (as best we can clone it) to every pending waiter
/// and clear the waiters map. Marks the connection as disconnected so
/// new sends fail-fast.
///
/// `disconnected` is set UNDER the waiters lock so `register_waiter` sees
/// either "still alive → insert succeeds" or "dead → insert rejected",
/// never "inserted but already drained" (which would leave the caller
/// hanging on `rx.await`).
fn fan_error_to_waiters(inner: &Inner, e: &Error) {
    let drained: Vec<(MessageId, oneshot::Sender<Result<Frame>>)> = {
        let mut waiters = inner.waiters.lock().unwrap();
        inner.disconnected.store(true, Ordering::Release);
        waiters.drain().collect()
    };
    for (_id, tx) in drained {
        let _ = tx.send(Err(clone_err_as_disconnected(e)));
    }
}

/// Best-effort error clone: `Error` isn't `Clone` (Io holds std::io::Error).
/// Everything maps to `Error::Disconnected` for waiter-fan-out purposes —
/// waiters only need to know "the connection died".
fn clone_err_as_disconnected(_e: &Error) -> Error {
    Error::Disconnected
}

fn decrypt_frame(data: &[u8], inner: &Inner) -> Result<Vec<u8>> {
    let c = inner.crypto.lock().unwrap();
    let dec_key = c
        .decryption_key
        .as_ref()
        .ok_or_else(|| Error::invalid_data("received encrypted message but no decryption key"))?
        .clone();
    let cipher = c
        .encryption_cipher
        .ok_or_else(|| Error::invalid_data("received encrypted message but no cipher"))?;
    drop(c);

    if data.len() < TransformHeader::SIZE {
        return Err(Error::invalid_data(
            "encrypted message too short for TransformHeader",
        ));
    }

    let transform_header = &data[..TransformHeader::SIZE];
    let ciphertext = &data[TransformHeader::SIZE..];
    let plaintext = encryption::decrypt_message(transform_header, ciphertext, &dec_key, cipher)?;
    Ok(plaintext)
}

/// Split a preprocessed frame into sub-frames by `NextCommand` offsets.
/// Returns the raw byte slices (as owned Vec<u8>) for each sub-frame.
fn split_compound(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut results = Vec::new();
    let mut offset = 0usize;

    loop {
        if offset + Header::SIZE > data.len() {
            return Err(Error::invalid_data(format!(
                "compound response truncated at offset {}: need {} bytes for header, but only {} remain",
                offset,
                Header::SIZE,
                data.len() - offset,
            )));
        }

        if !results.is_empty() && offset % 8 != 0 {
            return Err(Error::invalid_data(format!(
                "compound response at offset {} is not 8-byte aligned -- must disconnect",
                offset,
            )));
        }

        // Parse NextCommand directly from header bytes 20..24.
        let next_cmd = u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap());
        let sub_end = if next_cmd > 0 {
            offset + next_cmd as usize
        } else {
            data.len()
        };

        if sub_end > data.len() {
            return Err(Error::invalid_data(format!(
                "compound NextCommand offset {} at position {} exceeds response length {}",
                next_cmd,
                offset,
                data.len(),
            )));
        }

        results.push(data[offset..sub_end].to_vec());
        if next_cmd == 0 {
            break;
        }
        offset += next_cmd as usize;
    }
    Ok(results)
}

/// Await a per-request `oneshot::Receiver` and translate the three
/// outcomes into a `Result<Frame>`:
///
/// - `Ok(Ok(frame))` — the receiver task routed a successful response.
/// - `Ok(Err(e))` — the receiver task delivered a targeted error for
///   this `MessageId` (signature-verify failure, session expired, etc.).
/// - `Err(_)` on the outer await means the `oneshot::Sender` was dropped
///   without sending, which happens on connection teardown (see
///   `fan_error_to_waiters` — it calls `send(Err(Disconnected))` for
///   every pending waiter, so we only see a raw canceled channel if
///   the whole map was dropped without that call, i.e. Arc teardown).
///   Map it to `Error::Disconnected`.
async fn await_frame(rx: oneshot::Receiver<Result<Frame>>) -> Result<Frame> {
    match rx.await {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(e)) => Err(e),
        Err(_canceled) => Err(Error::Disconnected),
    }
}

/// Pack a header + body into raw SMB2 message bytes.
pub(crate) fn pack_message(header: &Header, body: &dyn Pack) -> Vec<u8> {
    let mut cursor = WriteCursor::new();
    header.pack(&mut cursor);
    body.pack(&mut cursor);
    cursor.into_inner()
}

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

fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    getrandom::fill(&mut salt).expect("failed to generate random salt");
    salt
}

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

// Arc-based TransportSend/TransportReceive for TcpTransport sharing.
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

    /// Pack a set of SMB2 sub-responses into one compound transport frame
    /// by wiring up `NextCommand` offsets and 8-byte-padding each sub
    /// except the last. Used by compound execute tests below.
    fn build_compound_response_frame(responses: &[Vec<u8>]) -> Vec<u8> {
        let mut padded: Vec<Vec<u8>> = Vec::new();
        for (i, resp) in responses.iter().enumerate() {
            let mut r = resp.clone();
            let is_last = i == responses.len() - 1;
            if !is_last {
                let remainder = r.len() % 8;
                if remainder != 0 {
                    r.resize(r.len() + (8 - remainder), 0);
                }
                let next_cmd = r.len() as u32;
                r[20..24].copy_from_slice(&next_cmd.to_le_bytes());
            }
            padded.push(r);
        }
        let mut frame = Vec::new();
        for r in &padded {
            frame.extend_from_slice(r);
        }
        frame
    }

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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Manually set past negotiate.
        conn.set_next_message_id(5);

        use crate::msg::tree_disconnect::TreeDisconnectRequest;
        let body = TreeDisconnectRequest;
        // With execute(), the msg_id is an internal allocation — we peek it
        // via next_message_id() before sending. Use a timeout so the test
        // doesn't wait for a response the mock never produces.
        assert_eq!(conn.next_message_id(), 5);
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.execute(Command::TreeDisconnect, &body, None),
        )
        .await;
        assert_eq!(conn.next_message_id(), 6);
    }

    #[tokio::test]
    async fn signing_applied_to_outgoing_messages() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Activate signing.
        let key = vec![0xAA; 16];
        conn.activate_signing(key, SigningAlgorithm::HmacSha256);
        conn.set_session_id(SessionId(0x1234));

        use crate::msg::tree_disconnect::TreeDisconnectRequest;
        let body = TreeDisconnectRequest;
        // execute() awaits the response, but we only care about the sent bytes.
        // Spawn+abort the future so the send runs but the await doesn't block on
        // a response that never comes.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.execute(Command::TreeDisconnect, &body, None),
        )
        .await;

        let msg_bytes = mock.sent_message(0).expect("one send recorded");
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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

    // (Compound-specific send/receive tests removed — execute_compound tests live below.)

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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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
        mock.enable_auto_rewrite_msg_id();
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

    // ── Phase 2 (actor + oneshot routing) red tests ─────────────────
    //
    // These tests pin the invariants the Phase 2 refactor must establish.
    // They target the cancellation-by-drop failure mode that Phase 1's
    // `HashSet<MessageId>` demux cannot solve: when a caller's future is
    // dropped mid-flight (for example, by `tokio::task::JoinHandle::abort()`),
    // the in-flight MessageIds stay in `pending`; server responses for those
    // ids then get handed to the next caller as if they were legitimate.
    //
    // Post-Phase-2, each in-flight request carries its own `oneshot::Sender`;
    // when the caller's `Receiver` is dropped (future aborted), the receiver
    // task discards the response silently on arrival.
    //
    // These tests fail against current code (Phase 1). They must pass after
    // Phase 2 lands. See `docs/specs/connection-actor.md`.

    // ── Phase 3 (silent-discard fix) red test ───────────────────────
    //
    // Pins the invariant that an unrecoverable frame-level error
    // (decrypt failure, decompress failure, malformed header after
    // decryption) MUST NOT silently discard the frame and leave the
    // matching waiter hanging forever. The Phase 2 receiver task
    // currently `log-at-WARN + continue`s on decrypt failure — the
    // msg_id isn't recoverable from an unparseable frame, so there's
    // no waiter to notify targeted; the only correct behavior is to
    // tear down the connection and fan `Err(Disconnected)` to all
    // pending waiters.
    //
    // This test uses `tokio::time::timeout` to detect the hang: if
    // the waiter doesn't resolve within 2 seconds, it's hung (bug
    // present, test fails). Post-P3.4 fix, the waiter resolves with
    // an error before the timeout.

    #[tokio::test]
    async fn phase3_decrypt_failure_errors_waiter_not_hangs() {
        use crate::crypto::encryption::Cipher;

        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);

        // Activate encryption with a key that WON'T match what the
        // malformed frame was "encrypted" with — decrypt will fail auth.
        let enc_key = vec![0x42; 16];
        let dec_key = vec![0x99; 16]; // deliberately wrong decryption key
        conn.activate_encryption(enc_key, dec_key, Cipher::Aes128Gcm);

        // Register a waiter manually so we can inject a bad frame without
        // racing with a real send.
        let rx = conn.register_waiter(MessageId(4)).unwrap();

        // Build a frame that starts with TRANSFORM_PROTOCOL_ID so the
        // receiver task takes the decrypt path, but whose ciphertext
        // is garbage that will fail the GCM auth tag check. We craft a
        // "valid-shape" transform header (52 bytes) plus ~64 bytes of
        // garbage ciphertext. The receiver task's decrypt_frame call
        // returns Err; currently it's log+continue (the bug).
        let mut frame = Vec::new();
        frame.extend_from_slice(&TRANSFORM_PROTOCOL_ID); // 0xFD 'S' 'M' 'B'
        frame.extend_from_slice(&[0u8; 16]); // signature
        frame.extend_from_slice(&[0u8; 16]); // nonce
        frame.extend_from_slice(&64u32.to_le_bytes()); // original_message_size
        frame.extend_from_slice(&0u16.to_le_bytes()); // reserved
        frame.extend_from_slice(&1u16.to_le_bytes()); // flags (Encrypted)
        frame.extend_from_slice(&0xDEADu64.to_le_bytes()); // session_id
                                                           // Garbage ciphertext — will fail GCM auth on decrypt.
        frame.extend_from_slice(&[0xAAu8; 64]);
        mock.queue_response(frame);

        // Await the waiter with a short timeout. If Phase 3's fix is in
        // place, the receiver task tears down on decrypt failure and the
        // waiter resolves with Err(Disconnected) quickly. Without the
        // fix, the receiver task `log+continue`s, the waiter hangs, and
        // the timeout fires (test fails).
        let result = tokio::time::timeout(Duration::from_secs(2), await_frame(rx)).await;

        assert!(
            result.is_ok(),
            "waiter hung forever on a decrypt-failed frame — Phase 3's silent-discard \
             fix must tear down the connection on unrecoverable frame errors and propagate \
             Err(Disconnected) to pending waiters. Instead the receiver task silently discards \
             the frame and the waiter never resolves. (P3.4 fixes this.)"
        );
        let waiter_result = result.unwrap();
        assert!(
            waiter_result.is_err(),
            "waiter should return an error on decrypt failure, not Ok"
        );
    }

    // ── CANCEL tests (pitfall #7) ────────────────────────────────────

    #[tokio::test]
    async fn send_cancel_does_not_consume_credit_or_advance_message_id() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_next_message_id(10);
        conn.set_credits(5);

        conn.send_cancel(MessageId(7), None).await.unwrap();

        // MessageId should NOT have advanced.
        assert_eq!(conn.next_message_id(), 10);
        // Credits should NOT have been consumed.
        assert_eq!(conn.credits(), 5);
    }

    #[tokio::test]
    async fn send_cancel_sync_uses_original_message_id() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_session_id(SessionId(0xAAAA));

        conn.send_cancel(MessageId(42), None).await.unwrap();

        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let header = Header::unpack(&mut cursor).unwrap();

        assert_eq!(header.command, Command::Cancel);
        assert_eq!(header.message_id, MessageId(42));
        assert_eq!(header.credit_charge, CreditCharge(0));
        assert_eq!(header.credits, 0);
        assert_eq!(header.session_id, SessionId(0xAAAA));
        assert!(!header.flags.is_async());

        // Body should be CancelRequest: StructureSize=4, Reserved=0.
        assert_eq!(sent.len(), Header::SIZE + 4);
        let body_structure_size = u16::from_le_bytes(sent[64..66].try_into().unwrap());
        assert_eq!(body_structure_size, 4);
    }

    #[tokio::test]
    async fn send_cancel_async_sets_async_flag_and_async_id() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_session_id(SessionId(0xBBBB));

        let async_id = 0x1234_5678_9ABC_DEF0u64;
        conn.send_cancel(MessageId(99), Some(async_id))
            .await
            .unwrap();

        let sent = mock.sent_message(0).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let header = Header::unpack(&mut cursor).unwrap();

        assert_eq!(header.command, Command::Cancel);
        assert_eq!(header.message_id, MessageId(99));
        assert!(header.flags.is_async());
        assert_eq!(header.async_id, Some(async_id));
        assert_eq!(header.tree_id, None);
        assert_eq!(header.credit_charge, CreditCharge(0));
        assert_eq!(header.credits, 0);
    }

    #[tokio::test]
    async fn send_cancel_signs_message_when_signing_active() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        let key = vec![0xCC; 16];
        conn.activate_signing(key, SigningAlgorithm::HmacSha256);
        conn.set_session_id(SessionId(0xDDDD));

        conn.send_cancel(MessageId(50), None).await.unwrap();

        let sent = mock.sent_message(0).unwrap();

        // Verify the signed flag is set.
        let flags = u32::from_le_bytes(sent[16..20].try_into().unwrap());
        assert!(flags & HeaderFlags::SIGNED != 0, "CANCEL should be signed");

        // Verify the signature is non-zero.
        let sig = &sent[48..64];
        assert_ne!(sig, &[0u8; 16], "signature should not be all zeros");
    }

    // ── Encryption tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn no_encryption_when_not_activated() {
        use crate::msg::echo::EchoRequest;

        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_test_params(NegotiatedParams {
            dialect: Dialect::Smb3_1_1,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: Guid::ZERO,
            signing_required: false,
            capabilities: Capabilities::default(),
            gmac_negotiated: false,
            cipher: Some(Cipher::Aes128Gcm),
            compression_supported: false,
        });
        conn.set_session_id(SessionId(1));
        conn.set_credits(5);

        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.execute(Command::Echo, &EchoRequest, None),
        )
        .await;

        // Without encryption activated, the sent bytes should start with
        // the normal SMB2 protocol ID (0xFE).
        let sent = mock.sent_message(0).unwrap();
        assert_eq!(
            sent[0], 0xFE,
            "without encryption, message must start with 0xFE"
        );
    }

    #[tokio::test]
    async fn activate_encryption_sets_state() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        assert!(!conn.should_encrypt());

        conn.activate_encryption(vec![0x42; 16], vec![0x42; 16], Cipher::Aes128Gcm);

        assert!(conn.should_encrypt());
    }

    // ── DFS flag tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn dfs_flag_set_for_registered_tree() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(256);

        let tree_id = TreeId(7);
        conn.register_dfs_tree(tree_id);

        use crate::msg::echo::EchoRequest;
        let body = EchoRequest;
        // Fire execute with a short timeout so the test doesn't block on a
        // response that never comes — we only care about the sent bytes.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.execute_with_credits(Command::Echo, &body, Some(tree_id), CreditCharge(1)),
        )
        .await;
        let msg_bytes = mock.sent_message(0).expect("one send recorded");

        // Header flags are at bytes 16..20 (little-endian u32).
        let flags_raw = u32::from_le_bytes(msg_bytes[16..20].try_into().unwrap());
        assert_ne!(
            flags_raw & HeaderFlags::DFS_OPERATIONS,
            0,
            "DFS_OPERATIONS flag must be set for registered tree"
        );
    }

    #[tokio::test]
    async fn dfs_flag_not_set_for_unregistered_tree() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(256);

        use crate::msg::echo::EchoRequest;
        let body = EchoRequest;
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.execute_with_credits(Command::Echo, &body, Some(TreeId(7)), CreditCharge(1)),
        )
        .await;
        let msg_bytes = mock.sent_message(0).expect("one send recorded");

        let flags_raw = u32::from_le_bytes(msg_bytes[16..20].try_into().unwrap());
        assert_eq!(
            flags_raw & HeaderFlags::DFS_OPERATIONS,
            0,
            "DFS_OPERATIONS flag must NOT be set for unregistered tree"
        );
    }

    #[tokio::test]
    async fn dfs_flag_cleared_after_deregister() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(256);

        let tree_id = TreeId(7);
        conn.register_dfs_tree(tree_id);
        conn.deregister_dfs_tree(tree_id);

        use crate::msg::echo::EchoRequest;
        let body = EchoRequest;
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.execute_with_credits(Command::Echo, &body, Some(tree_id), CreditCharge(1)),
        )
        .await;
        let msg_bytes = mock.sent_message(0).expect("one send recorded");

        let flags_raw = u32::from_le_bytes(msg_bytes[16..20].try_into().unwrap());
        assert_eq!(
            flags_raw & HeaderFlags::DFS_OPERATIONS,
            0,
            "DFS_OPERATIONS flag must NOT be set after deregister"
        );
    }

    // ── Phase 3 A.1: Connection: Clone ───────────────────────────────

    /// Confirms clones share the same connection-wide state via `Arc<Inner>`.
    ///
    /// Design note (Option A from `docs/specs/connection-actor.md` review):
    /// a cloned `Connection` starts with an EMPTY caller-local `pending_fifo`.
    /// `oneshot::Receiver` isn't `Clone`, and in-flight waiters belong to
    /// the task that sent the request — a new clone is a fresh sender
    /// handle to the same actor, not a snapshot. Credits, session id,
    /// negotiated params, and crypto state are shared.
    #[tokio::test]
    async fn connection_is_cloneable_and_clones_share_state() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut original = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Mutate shared state on the original.
        original.set_credits(42);
        original.set_session_id(SessionId(0x1234_5678_9ABC_DEF0));
        original.set_next_message_id(100);

        // Clone and verify the clone sees the same shared state.
        let cloned = original.clone();
        assert_eq!(cloned.credits(), 42);
        assert_eq!(cloned.session_id(), SessionId(0x1234_5678_9ABC_DEF0));
        assert_eq!(cloned.next_message_id(), 100);
        assert_eq!(cloned.server_name(), "test-server");

        // Mutate via the clone and verify the original observes it too.
        cloned.inner.credits.store(7, Ordering::Release);
        assert_eq!(original.credits(), 7);

        // Phase 3 A.3 removed the caller-local `pending_fifo`; there is no
        // per-clone state anymore. Clones share `Arc<Inner>` exclusively.
    }

    // ── Phase 3 A.2: `execute` / `execute_with_credits` / `execute_compound` ──
    //
    // These tests exercise the additive concurrent-op API. All callers take
    // `&self`, so the orphan filter stays ENABLED (production behavior). Mock
    // responses hardcode the MessageIds that `execute` allocates, starting at 0
    // by default (or a specific `set_next_message_id` for multi-op tests).

    /// Build an ECHO response with a specific MessageId.
    fn build_echo_response_with_msg_id(msg_id: MessageId) -> Vec<u8> {
        let mut h = Header::new_request(Command::Echo);
        h.flags.set_response();
        h.credits = 10;
        h.message_id = msg_id;
        pack_message(&h, &crate::msg::echo::EchoResponse)
    }

    /// Queue a response AFTER the spawned task has sent its request (and
    /// thus registered its waiter). Using `multi_thread` so the receiver
    /// task can race the test task — catching any regression where the
    /// orphan filter silently drops the response.
    #[tokio::test(flavor = "multi_thread")]
    async fn execute_returns_correct_frame_for_sent_request() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();

        let conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Spawn the execute first. `execute` allocates msg_id=0.
        let c = conn.clone();
        let handle = tokio::spawn(async move {
            c.execute(Command::Echo, &crate::msg::echo::EchoRequest, None)
                .await
        });

        // Wait for the send to land, then queue the response.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < 1 {
            if std::time::Instant::now() > deadline {
                panic!("execute task did not send its request in 5s");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        mock.queue_response(build_echo_response_with_msg_id(MessageId(0)));

        let frame = handle.await.unwrap().unwrap();

        assert_eq!(frame.header.command, Command::Echo);
        assert_eq!(frame.header.message_id, MessageId(0));
        assert!(frame.header.is_response());
        // Body should unpack as EchoResponse.
        let mut cursor = ReadCursor::new(&frame.body);
        crate::msg::echo::EchoResponse::unpack(&mut cursor).unwrap();

        mock.assert_fully_consumed();
    }

    /// N concurrent `execute` calls on clones of the same `Connection` all
    /// succeed — the receiver task's per-MessageId routing delivers each
    /// response to its own waiter. Needs a multi-threaded runtime so the
    /// receiver task can make progress while the task-under-test runs.
    ///
    /// Gotcha/Why: we MUST spawn the tasks first and wait for all N sends
    /// to register waiters before queuing responses. The receiver task
    /// starts reading `mock` immediately after `from_transport`. If we
    /// pre-queue all N responses, the receiver races the spawned tasks —
    /// any response whose msg_id hasn't had its waiter registered yet is
    /// dropped by the orphan filter (enabled by default in production
    /// mode), and the task hangs forever waiting for a response that's
    /// already been discarded. This ordering reflects the production
    /// reality: responses always arrive AFTER the client sent them.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_execute_on_one_connection_all_succeed() {
        const N: u64 = 20;

        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();

        let conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Spawn N tasks FIRST — they register waiters and send requests.
        let mut handles = Vec::with_capacity(N as usize);
        for _ in 0..N {
            let c = conn.clone();
            handles.push(tokio::spawn(async move {
                c.execute(Command::Echo, &crate::msg::echo::EchoRequest, None)
                    .await
            }));
        }

        // Wait until all N requests have been sent AND all waiters are
        // registered. Poll `sent_count` rather than hardcode a sleep.
        // `execute` registers the waiter BEFORE calling `sender.send`,
        // so `sent_count >= N` implies all N waiters are live.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < N as usize {
            if std::time::Instant::now() > deadline {
                panic!(
                    "tasks did not send all {} requests in 5s (got {})",
                    N,
                    mock.sent_count()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Now queue responses for msg_ids 0..N. Each one routes to a
        // registered waiter.
        for i in 0..N {
            mock.queue_response(build_echo_response_with_msg_id(MessageId(i)));
        }

        let mut got_ids: Vec<u64> = Vec::with_capacity(N as usize);
        for h in handles {
            let frame = h.await.unwrap().unwrap();
            assert_eq!(frame.header.command, Command::Echo);
            got_ids.push(frame.header.message_id.0);
        }
        got_ids.sort_unstable();
        assert_eq!(got_ids, (0..N).collect::<Vec<_>>());

        mock.assert_fully_consumed();
    }

    /// Dropping 2 of 5 execute futures before their responses arrive does
    /// NOT corrupt the other 3: the receiver task silently discards the
    /// frames routed to dropped oneshots, and the 3 surviving tasks see
    /// their own responses.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropped_execute_future_does_not_affect_others() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();

        let conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Spawn 5 tasks. Each allocates its own MessageId in submission
        // order: 0, 1, 2, 3, 4. To make allocation deterministic on the
        // multi_thread runtime, wait for each task's send to land before
        // spawning the next. `yield_now` alone isn't enough — on a
        // multi-worker runtime, the next spawn can race the previous
        // task's send and reorder msg_id allocation.
        let mut handles = Vec::new();
        for idx in 0..5 {
            let c = conn.clone();
            let h = tokio::spawn(async move {
                c.execute(Command::Echo, &crate::msg::echo::EchoRequest, None)
                    .await
            });
            handles.push(h);

            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while mock.sent_count() < idx + 1 {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "task {} did not send its request in 5s (sent_count={})",
                        idx,
                        mock.sent_count()
                    );
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        // All 5 tasks have sent; waiters registered; msg_ids = 0..5.
        assert_eq!(mock.sent_count(), 5);

        // Abort tasks at indices 1 and 3 (msg_ids 1 and 3).
        handles[1].abort();
        handles[3].abort();

        // Now queue responses for all 5 msg_ids. The 2 aborted-task
        // responses route to closed oneshots and get silently discarded;
        // the 3 live tasks get their responses.
        for i in 0..5u64 {
            mock.queue_response(build_echo_response_with_msg_id(MessageId(i)));
        }

        // Collect results: tasks 0, 2, 4 should complete OK; tasks 1, 3
        // return JoinError (they were aborted).
        for (idx, h) in handles.into_iter().enumerate() {
            let res = h.await;
            if idx == 1 || idx == 3 {
                assert!(res.is_err(), "task {} should have been aborted", idx);
            } else {
                let frame = res.unwrap().unwrap();
                assert_eq!(frame.header.command, Command::Echo);
                assert_eq!(frame.header.message_id, MessageId(idx as u64));
            }
        }

        // All 5 responses were consumed by the receiver task (even the 2
        // whose waiters were dropped — the task reads every frame off the
        // mock regardless of waiter state).
        mock.assert_fully_consumed();
    }

    /// Compound partial failure: op 1 succeeds, op 2 returns an error
    /// status, op 3 succeeds. Outer result is `Ok(vec)`; inner is
    /// `[Ok, Ok(with-error-status), Ok]` — the per-sub-op error is
    /// encoded in `frame.header.status`, not in the inner `Result`,
    /// because the server returned a well-formed frame for every op.
    #[tokio::test(flavor = "multi_thread")]
    async fn execute_compound_partial_failure_routes_correctly() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();

        // 3-op compound. `execute_compound` allocates msg_ids 0, 1, 2.
        let echo_ok_0 = build_echo_response_with_msg_id(MessageId(0));
        let mut err_hdr = Header::new_request(Command::Echo);
        err_hdr.flags.set_response();
        err_hdr.credits = 10;
        err_hdr.message_id = MessageId(1);
        err_hdr.status = NtStatus::OBJECT_NAME_NOT_FOUND;
        let err_body = pack_message(
            &err_hdr,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        );
        let echo_ok_2 = build_echo_response_with_msg_id(MessageId(2));

        let compound_response = build_compound_response_frame(&[echo_ok_0, err_body, echo_ok_2]);

        let conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        let c = conn.clone();
        let handle = tokio::spawn(async move {
            let ops = [
                CompoundOp::new(Command::Echo, &crate::msg::echo::EchoRequest, None),
                CompoundOp::new(Command::Echo, &crate::msg::echo::EchoRequest, None),
                CompoundOp::new(Command::Echo, &crate::msg::echo::EchoRequest, None),
            ];
            c.execute_compound(&ops).await
        });

        // Wait for the compound request to land on the wire — one send
        // for all 3 sub-ops — then queue the response. All 3 waiters
        // are registered before the send, so the single compound-reply
        // frame routes to all of them.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < 1 {
            if std::time::Instant::now() > deadline {
                panic!("execute_compound did not send in 5s");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        mock.queue_response(compound_response);

        let results = handle.await.unwrap().unwrap();

        assert_eq!(results.len(), 3);
        let f0 = results[0].as_ref().expect("op 0 should be Ok");
        assert_eq!(f0.header.status, NtStatus::SUCCESS);
        assert_eq!(f0.header.message_id, MessageId(0));

        let f1 = results[1]
            .as_ref()
            .expect("op 1 still carries a Frame — error status in header");
        assert_eq!(f1.header.status, NtStatus::OBJECT_NAME_NOT_FOUND);
        assert_eq!(f1.header.message_id, MessageId(1));

        let f2 = results[2].as_ref().expect("op 2 should be Ok");
        assert_eq!(f2.header.status, NtStatus::SUCCESS);
        assert_eq!(f2.header.message_id, MessageId(2));

        mock.assert_fully_consumed();
    }

    /// Using a clone after the original is dropped: the `Arc<Inner>` keeps
    /// the receiver task alive. Specifically for `execute` (the A.1 test
    /// only exercised direct `sender.send`).
    #[tokio::test(flavor = "multi_thread")]
    async fn execute_on_clone_works_after_original_dropped() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();

        let original = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        let cloned = original.clone();
        drop(original);

        let c = cloned.clone();
        let handle = tokio::spawn(async move {
            c.execute(Command::Echo, &crate::msg::echo::EchoRequest, None)
                .await
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while mock.sent_count() < 1 {
            if std::time::Instant::now() > deadline {
                panic!("execute on clone did not send in 5s");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        mock.queue_response(build_echo_response_with_msg_id(MessageId(0)));

        let frame = handle.await.unwrap().unwrap();
        assert_eq!(frame.header.command, Command::Echo);
        assert_eq!(frame.header.message_id, MessageId(0));

        mock.assert_fully_consumed();
    }

    /// A clone'd `Connection` survives the original being dropped: the
    /// receiver task and transport sender are behind `Arc<Inner>`, so
    /// dropping the last Arc (not the first) is what aborts the task.
    #[tokio::test]
    async fn connection_is_cloneable_clone_outlives_original() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        let mut original = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        original.set_credits(9);

        let cloned = original.clone();
        drop(original);

        // Shared state still accessible — the receiver task is still live
        // because the clone holds an `Arc<Inner>`.
        assert_eq!(cloned.credits(), 9);
        assert_eq!(cloned.server_name(), "test-server");

        // Send should still work: the transport's send half lives on Inner.
        // We won't register a waiter (no response queued), just verify the
        // send path doesn't panic on a dead-task-map.
        // (Easier: send_cancel has no waiter registration.)
        cloned
            .inner
            .sender
            .send(b"\x00\x00\x00\x10ignore-me")
            .await
            .unwrap();
        assert_eq!(mock.sent_count(), 1);
    }
}
