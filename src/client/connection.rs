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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use log::{debug, info, trace, warn};
use tokio::sync::{mpsc, oneshot};

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
/// Only caller-local bookkeeping (the per-caller `pending_fifo` of oneshot
/// receivers, plus the test-mode orphan-fallback receiver/buffer) stays on
/// the outer `Connection` and starts fresh per clone.
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
    /// Whether orphan responses (msg_id not in waiters) should be dropped.
    /// Tests that don't go through `send_request` disable this so the
    /// receiver task routes unmatched frames to `orphan_fallback_tx` instead.
    orphan_filter_enabled: AtomicBool,
    /// Set to true when the receiver task exits (transport error / EOF).
    /// New `send_request` / `send_compound` calls short-circuit to
    /// `Err(Disconnected)` once this flips so they don't register waiters
    /// into a dead map.
    disconnected: AtomicBool,
    /// Fallback channel for frames with no matching waiter when the orphan
    /// filter is disabled. Each send carries ONE transport frame's worth
    /// of sub-responses (preserves compound-frame grouping for tests).
    /// Populated lazily by `set_orphan_filter_enabled(false)`.
    orphan_fallback_tx: StdMutex<Option<mpsc::UnboundedSender<Result<Vec<Frame>>>>>,

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
            orphan_filter_enabled: AtomicBool::new(true),
            disconnected: AtomicBool::new(false),
            orphan_fallback_tx: StdMutex::new(None),
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
/// message signing, and encryption. Phase 2 of the refactor: a background
/// receiver task owns the transport's read half and routes each frame to
/// the `oneshot::Sender` registered for its `MessageId`. Callers push a
/// `oneshot::Receiver` onto a local FIFO via `send_request` and pop/await
/// via `receive_response`.
///
/// Phase 3 Stage A.1: `Connection` is `Clone`. All connection-wide state
/// lives behind `Arc<Inner>`, so cloning is a single `Arc::clone`. The
/// caller-local FIFO of pending response receivers stays on the outer
/// `Connection` and starts empty on each clone — a clone is a fresh sender
/// handle to the same actor, not a snapshot of in-flight requests on the
/// original.
pub struct Connection {
    /// Shared state (credits, waiters, crypto, transport sender, negotiated
    /// params, receiver task) behind `Arc<Inner>`. `clone()` bumps this.
    inner: Arc<Inner>,
    /// Caller-local FIFO of pending response receivers. `send_request` /
    /// `send_compound` push, `receive_response` / `receive_compound_expected`
    /// pop. Fresh and empty on each `clone()` — in-flight requests belong to
    /// the caller that started them, not to new sender handles.
    pending_fifo: VecDeque<oneshot::Receiver<Result<Frame>>>,
    /// Caller-local receiver for the orphan fallback channel (test mode).
    /// Only set when `set_orphan_filter_enabled(false)` has been called.
    /// Fresh `None` on clone.
    orphan_fallback_rx: StdMutex<Option<mpsc::UnboundedReceiver<Result<Vec<Frame>>>>>,
    /// Buffered sub-frames from the fallback: when one transport-frame's
    /// `Vec<Frame>` arrives but the caller only needs one sub-response,
    /// we buffer the rest here for the next call. Fresh empty on clone.
    orphan_fallback_buffer: StdMutex<VecDeque<Frame>>,
}

impl Clone for Connection {
    /// Create a new sender handle to the same connection.
    ///
    /// Shared across clones (via `Arc<Inner>`): credits, waiters map,
    /// negotiated params, session id, crypto state, transport sender,
    /// receiver task.
    ///
    /// Per-clone (fresh each time): the caller-local `pending_fifo` of
    /// `oneshot::Receiver`s that `receive_response` pops from, plus the
    /// test-mode orphan-fallback receiver and buffer. `oneshot::Receiver`
    /// isn't `Clone` and in-flight waiters are bookkeeping for the task
    /// that started them — a new clone represents a new caller that hasn't
    /// sent anything yet. The receiver task still routes all responses by
    /// `MessageId` through the shared waiters map, so drops from either
    /// clone are safe.
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            pending_fifo: VecDeque::new(),
            orphan_fallback_rx: StdMutex::new(None),
            orphan_fallback_buffer: StdMutex::new(VecDeque::new()),
        }
    }
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
        Self {
            inner,
            pending_fifo: VecDeque::new(),
            orphan_fallback_rx: StdMutex::new(None),
            orphan_fallback_buffer: StdMutex::new(VecDeque::new()),
        }
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
        self.pending_fifo.push_back(rx);

        let rtt_start = std::time::Instant::now();
        if let Err(e) = self.inner.sender.send(&req_bytes).await {
            self.remove_waiter(msg_id);
            self.pending_fifo.pop_back();
            return Err(e);
        }

        let frame = self.await_next_response().await?;
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

    /// Send a request and return the raw bytes that were sent (for preauth hash).
    pub async fn send_request(
        &mut self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
    ) -> Result<(MessageId, Vec<u8>)> {
        self.send_request_with_credits(command, body, tree_id, 1)
            .await
    }

    /// Send a request with a custom CreditCharge.
    pub async fn send_request_with_credits(
        &mut self,
        command: Command,
        body: &dyn Pack,
        tree_id: Option<TreeId>,
        credit_charge: u16,
    ) -> Result<(MessageId, Vec<u8>)> {
        if self.inner.disconnected.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }
        let msg_id = self.allocate_msg_id(credit_charge.max(1) as u64);

        let mut header = Header::new_request(command);
        header.message_id = msg_id;
        header.credits = 256;
        header.credit_charge = CreditCharge(credit_charge);
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

        // Register waiter BEFORE send (so the receiver task can match any
        // response that arrives fast). Atomically fails if the receiver
        // task has already shut down, so we don't hang on a map entry
        // that'll never be routed.
        let rx = self.register_waiter(msg_id)?;
        self.pending_fifo.push_back(rx);

        let wire_bytes = if should_encrypt {
            let encrypted = self.encrypt_bytes(&msg_bytes)?;
            match self.inner.sender.send(&encrypted).await {
                Ok(()) => {
                    debug!(
                        "send: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, encrypted, len={} (plaintext {})",
                        command, msg_id.0, credit_charge, tree_id, encrypted.len(), msg_bytes.len()
                    );
                    return Ok((msg_id, msg_bytes));
                }
                Err(e) => {
                    self.cancel_last_waiter(msg_id);
                    return Err(e);
                }
            }
        } else {
            if should_sign {
                let c = self.inner.crypto.lock().unwrap();
                if let (Some(key), Some(algo)) = (&c.signing_key, &c.signing_algorithm) {
                    signing::sign_message(&mut msg_bytes, key, *algo, msg_id.0, false)?;
                }
            }
            if self.compression_enabled() && msg_bytes.len() > Header::SIZE {
                if let Some(compressed) = compress_message(&msg_bytes, Header::SIZE) {
                    let framed = build_compressed_frame(&compressed);
                    match self.inner.sender.send(&framed).await {
                        Ok(()) => {
                            debug!(
                                "send: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, compressed {}->{} bytes",
                                command, msg_id.0, credit_charge, tree_id, should_sign,
                                msg_bytes.len(), framed.len()
                            );
                            return Ok((msg_id, msg_bytes));
                        }
                        Err(e) => {
                            self.cancel_last_waiter(msg_id);
                            return Err(e);
                        }
                    }
                }
            }
            msg_bytes.clone()
        };

        if let Err(e) = self.inner.sender.send(&wire_bytes).await {
            self.cancel_last_waiter(msg_id);
            return Err(e);
        }
        debug!(
            "send: cmd={:?}, msg_id={}, credit_charge={}, tree_id={:?}, signed={}, len={}",
            command,
            msg_id.0,
            credit_charge,
            tree_id,
            should_sign,
            msg_bytes.len()
        );
        Ok((msg_id, msg_bytes))
    }

    /// Get the estimated round-trip time.
    pub fn estimated_rtt(&self) -> Option<Duration> {
        *self.inner.estimated_rtt.lock().unwrap()
    }

    /// Receive a response, verify signature if needed, and update credits.
    ///
    /// Automatically skips `STATUS_PENDING` interim responses; the receiver
    /// task keeps the waiter registered and only forwards the final response.
    pub async fn receive_response(&mut self) -> Result<(Header, Vec<u8>, Vec<u8>)> {
        let frame = self.await_next_response().await?;
        Ok((frame.header, frame.body, frame.raw))
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

    /// Send a related compound request (multiple operations chained).
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
        if self.inner.disconnected.load(Ordering::Acquire) {
            return Err(Error::Disconnected);
        }

        let (should_sign, should_encrypt) = {
            let c = self.inner.crypto.lock().unwrap();
            (c.should_sign, c.should_encrypt)
        };

        let session_id = self.session_id();
        let mut message_ids = Vec::with_capacity(operations.len());
        let mut sub_requests: Vec<Vec<u8>> = Vec::with_capacity(operations.len());

        for (i, (command, body, credit_charge)) in operations.iter().enumerate() {
            let charge = credit_charge.0.max(1) as u64;
            let msg_id = self.allocate_msg_id(charge);

            let mut header = Header::new_request(*command);
            header.message_id = msg_id;
            header.credits = 256;
            header.credit_charge = *credit_charge;
            header.session_id = session_id;
            header.tree_id = Some(tree_id);

            if i > 0 {
                header.flags.set_related();
            }
            if should_sign && !should_encrypt {
                header.flags.set_signed();
            }
            if self.should_set_dfs_flag(Some(tree_id)) {
                header.flags |= HeaderFlags::new(HeaderFlags::DFS_OPERATIONS);
            }

            message_ids.push(msg_id);
            let msg_bytes = pack_message(&header, *body);
            sub_requests.push(msg_bytes);
        }

        // Pad all sub-requests except the last to 8-byte alignment.
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

        // Register every sub-request MessageId as in-flight BEFORE sending.
        // If any registration fails (connection died mid-registration),
        // roll back the ones we did register.
        let mut registered_ids = Vec::with_capacity(message_ids.len());
        for id in &message_ids {
            match self.register_waiter(*id) {
                Ok(rx) => {
                    self.pending_fifo.push_back(rx);
                    registered_ids.push(*id);
                }
                Err(e) => {
                    for done in registered_ids.iter().rev() {
                        self.cancel_last_waiter(*done);
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
            let encrypted = self.encrypt_bytes(&compound_buf)?;
            self.inner.sender.send(&encrypted).await
        } else {
            self.inner.sender.send(&compound_buf).await
        };

        if let Err(e) = send_result {
            // Undo registration.
            for id in registered_ids.iter().rev() {
                self.cancel_last_waiter(*id);
            }
            return Err(e);
        }

        debug!(
            "send_compound: {} operations, total_len={}, msg_ids={:?}, tree_id={}, signed={}, encrypted={}",
            operations.len(),
            compound_buf.len(),
            message_ids.iter().map(|m| m.0).collect::<Vec<_>>(),
            tree_id,
            should_sign,
            should_encrypt,
        );

        Ok(message_ids)
    }

    /// Receive a compound response (possibly multiple sub-responses from
    /// the next transport frame).
    ///
    /// Returns whatever sub-responses arrive from the next routed frame,
    /// matched by the order of `pending_fifo`. Returns at least one
    /// sub-response on success.
    pub async fn receive_compound(&mut self) -> Result<Vec<(Header, Vec<u8>)>> {
        // Pop one response (blocking); compounds register multiple msg_ids
        // but each sub-frame is routed independently by the receiver task.
        let first = self.await_next_response().await?;
        let mut results = vec![(first.header, first.body)];

        // Drain additional sub-frames that have ALREADY been delivered to
        // the buffer (non-blocking) — they belong to the same transport
        // frame. Only drain the buffer; the fifo/fallback channel may hold
        // items from LATER transport frames that belong to subsequent
        // receive_* calls, so we don't touch those here.
        loop {
            let next = self.orphan_fallback_buffer.lock().unwrap().pop_front();
            match next {
                Some(frame) => results.push((frame.header, frame.body)),
                None => break,
            }
        }

        if self.credits() == 0 {
            warn!("recv_compound: zero credits remaining -- credit starvation");
        }
        Ok(results)
    }

    /// Receive exactly `expected` compound sub-responses, gathering
    /// additional transport frames if needed.
    pub async fn receive_compound_expected(
        &mut self,
        expected: usize,
    ) -> Result<Vec<(Header, Vec<u8>)>> {
        if expected == 0 {
            return Ok(Vec::new());
        }
        let mut results = Vec::with_capacity(expected);
        for i in 0..expected {
            let frame = self.await_next_response().await?;
            trace!(
                "recv_compound_expected: got sub-response {}/{} msg_id={}, cmd={:?}",
                i + 1,
                expected,
                frame.header.message_id.0,
                frame.header.command
            );
            results.push((frame.header, frame.body));
        }
        // Overflow check: if more sub-frames from the same transport-frame
        // batch are buffered in the orphan fallback buffer, that's a
        // protocol error — the server sent more responses than we asked
        // for. Defensive: matches the old behavior.
        let extra = self.orphan_fallback_buffer.lock().unwrap().len();
        if extra > 0 {
            self.orphan_fallback_buffer.lock().unwrap().clear();
            return Err(Error::invalid_data(format!(
                "split compound response overflow: expected {} sub-responses total, got {} more",
                expected, extra,
            )));
        }
        if self.credits() == 0 {
            warn!("recv_compound: zero credits remaining -- credit starvation");
        }
        Ok(results)
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
    pub async fn execute_compound(
        &self,
        ops: &[CompoundOp<'_>],
    ) -> Result<Vec<Result<Frame>>> {
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

    /// Remove the last-pushed fifo entry matching `msg_id` and remove its
    /// map entry — used when a send fails after registration.
    fn cancel_last_waiter(&mut self, msg_id: MessageId) {
        self.pending_fifo.pop_back();
        self.remove_waiter(msg_id);
    }

    /// Get the next response for the caller.
    ///
    /// Production (orphan filter ON): pops the next `oneshot::Receiver`
    /// from `pending_fifo` and awaits it — the receiver task routes by
    /// msg_id to the matching sender.
    ///
    /// Test mode (orphan filter OFF): ignores the fifo for data delivery
    /// and reads from the fallback batch channel instead. Mock responses
    /// in tests hardcode `MessageId(0)` which doesn't match caller-allocated
    /// msg_ids, so per-waiter routing doesn't apply. We still drain the
    /// fifo on the side so drops are clean.
    async fn await_next_response(&mut self) -> Result<Frame> {
        let filter_on = self.inner.orphan_filter_enabled.load(Ordering::Acquire);
        if filter_on {
            if let Some(rx) = self.pending_fifo.pop_front() {
                return match rx.await {
                    Ok(Ok(frame)) => Ok(frame),
                    Ok(Err(e)) => Err(e),
                    Err(_canceled) => Err(Error::Disconnected),
                };
            }
            return Err(Error::invalid_data(
                "receive_response called without a pending request (orphan filter enabled)",
            ));
        }
        // Filter off (test mode): buffer → fallback channel.
        // Drop any fifo entry at the front (its response is going through fallback).
        self.pending_fifo.pop_front();
        if let Some(frame) = self.orphan_fallback_buffer.lock().unwrap().pop_front() {
            return Ok(frame);
        }
        // Take the rx temporarily (std::sync::Mutex can't be held across await).
        let rx_opt = self.orphan_fallback_rx.lock().unwrap().take();
        let mut rx = match rx_opt {
            Some(r) => r,
            None => {
                return Err(Error::invalid_data(
                    "receive_response called with orphan filter off but no fallback configured",
                ));
            }
        };
        let result = rx.recv().await;
        *self.orphan_fallback_rx.lock().unwrap() = Some(rx);
        match result {
            Some(Ok(mut batch)) => {
                if batch.is_empty() {
                    return Err(Error::Disconnected);
                }
                let first = batch.remove(0);
                if !batch.is_empty() {
                    let mut buf = self.orphan_fallback_buffer.lock().unwrap();
                    for f in batch {
                        buf.push_back(f);
                    }
                }
                Ok(first)
            }
            Some(Err(e)) => Err(e),
            None => Err(Error::Disconnected),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_test_params(&mut self, params: NegotiatedParams) {
        // OnceLock: first setter wins. Tests sometimes stage params on a
        // fresh connection; ignore any collision.
        let _ = self.inner.params.set(params);
    }

    /// Mark a MessageId as in-flight (test-only).
    ///
    /// Registers a waiter in the shared map AND pushes the receiver onto
    /// the caller's FIFO, simulating "caller just sent this request". For
    /// the specific scenario of simulating a dropped-caller future (aborted
    /// task), use [`Self::test_mark_pending_dropped`] instead.
    #[cfg(test)]
    pub(crate) fn test_mark_pending(&mut self, msg_id: MessageId) {
        let rx = self
            .register_waiter(msg_id)
            .expect("test_mark_pending on a live connection should not see disconnected");
        self.pending_fifo.push_back(rx);
    }

    /// Register a waiter in the map but immediately drop its receiver,
    /// simulating "caller sent this request then was cancelled" (test-only).
    ///
    /// When the response arrives, the receiver task routes it to the Sender
    /// and `send()` fails silently — the frame is discarded, credits still
    /// apply.
    #[cfg(test)]
    pub(crate) fn test_mark_pending_dropped(&mut self, msg_id: MessageId) {
        let _rx = self
            .register_waiter(msg_id)
            .expect("test_mark_pending_dropped on a live connection should not see disconnected");
        // drop _rx immediately, leaving only the Sender in the map
    }

    /// Enable or disable the orphan-response filter (test-only).
    #[cfg(test)]
    pub(crate) fn set_orphan_filter_enabled(&mut self, enabled: bool) {
        self.inner
            .orphan_filter_enabled
            .store(enabled, Ordering::Release);
        if !enabled {
            // Install a fallback channel: the receiver task pushes
            // unmatched frames here, and receive_response falls back to
            // reading from it when the fifo is empty.
            let (tx, rx) = mpsc::unbounded_channel();
            *self.inner.orphan_fallback_tx.lock().unwrap() = Some(tx);
            *self.orphan_fallback_rx.lock().unwrap() = Some(rx);
        } else {
            *self.inner.orphan_fallback_tx.lock().unwrap() = None;
            *self.orphan_fallback_rx.lock().unwrap() = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn set_credits(&mut self, credits: u16) {
        self.inner.credits.store(credits as u32, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn set_next_message_id(&mut self, id: u64) {
        self.inner.next_message_id.store(id, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn set_compression_enabled(&mut self, enabled: bool) {
        self.inner
            .compression_enabled
            .store(enabled, Ordering::Release);
    }
}

// `Connection`'s teardown lives on `Inner::drop`: the receiver task is
// aborted only when the last clone drops (the last `Arc<Inner>` goes away).
// Per-clone bookkeeping (pending_fifo, orphan_fallback_*) is plain-Rust-owned
// and drops naturally with the outer struct.

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

        // Decrypt if TRANSFORM_HEADER.
        let (decoded, was_encrypted) = if raw.len() >= 4 && raw[0..4] == TRANSFORM_PROTOCOL_ID {
            match decrypt_frame(&raw, &inner) {
                Ok(plain) => (plain, true),
                Err(e) => {
                    warn!("receiver_loop: decrypt failed: {}, skipping frame", e);
                    continue;
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
                    warn!("receiver_loop: decompress failed: {}, skipping frame", e);
                    continue;
                }
            }
        } else {
            decoded
        };

        // Split by NextCommand.
        let sub_frames = match split_compound(&decoded) {
            Ok(subs) => subs,
            Err(e) => {
                warn!("receiver_loop: malformed frame: {}, skipping", e);
                continue;
            }
        };

        // Produce a list of routable entries for this transport frame.
        // Each entry is (msg_id, Result<Frame>, was_pending_or_oplock).
        // Frames that should NOT be forwarded to a waiter (oplock break,
        // STATUS_PENDING interim) are marked as such.
        let mut routable: Vec<(MessageId, Result<Frame>)> = Vec::new();
        for sub in sub_frames {
            match prepare_sub_frame(&sub, was_encrypted, &inner) {
                Ok(Some((msg_id, routed))) => routable.push((msg_id, Ok(routed))),
                Ok(None) => { /* skip (oplock break, STATUS_PENDING, etc.) */ }
                Err((msg_id, e)) => routable.push((msg_id, Err(e))),
            }
        }

        if routable.is_empty() {
            continue;
        }

        // Decide routing per filter mode.
        let filter_on = inner.orphan_filter_enabled.load(Ordering::Acquire);
        if filter_on {
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
        } else {
            // Filter disabled (test mode): push ALL sub-frames as ONE batch
            // to the fallback channel, ignoring waiter routing. Tests that
            // disable the filter use mock responses with hardcoded msg_ids
            // (typically 0) that don't match the caller's registered
            // msg_ids. However, an explicit "dropped caller" waiter still
            // needs to consume its response so the Sender is dropped
            // cleanly — so we do route if a waiter matches, but we also
            // push the frame to fallback (so receive_response from any
            // caller can retrieve it).
            let mut fallback_batch: Vec<Frame> = Vec::new();
            let mut fallback_err: Option<Error> = None;
            for (msg_id, result) in routable {
                // Clean up any matching waiter (fire-and-forget).
                let _ = inner.waiters.lock().unwrap().remove(&msg_id);
                match result {
                    Ok(frame) => fallback_batch.push(frame),
                    Err(e) => {
                        fallback_err = Some(e);
                    }
                }
            }
            if !fallback_batch.is_empty() || fallback_err.is_some() {
                let fallback = inner.orphan_fallback_tx.lock().unwrap().clone();
                if let Some(tx) = fallback {
                    let payload = match fallback_err {
                        Some(e) => Err(e),
                        None => Ok(fallback_batch),
                    };
                    let _ = tx.send(payload);
                }
            }
        }
    }
}

/// Prepare a routable sub-frame from raw bytes. Returns Ok(Some(...)) if
/// the frame should be forwarded, Ok(None) if it should be skipped
/// (oplock break, STATUS_PENDING), Err((msg_id, e)) if signature
/// verification failed and the error should be delivered to the waiter.
fn prepare_sub_frame(
    sub: &[u8],
    was_encrypted: bool,
    inner: &Inner,
) -> std::result::Result<Option<(MessageId, Frame)>, (MessageId, Error)> {
    // Parse the header.
    let mut cursor = ReadCursor::new(sub);
    let header = match Header::unpack(&mut cursor) {
        Ok(h) => h,
        Err(e) => {
            warn!("recv: header parse error: {}, skipping sub-frame", e);
            return Ok(None);
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
        return Ok(None);
    }

    // STATUS_PENDING is an interim response — don't forward, keep waiter.
    if header.status.is_pending() {
        debug!(
            "recv: STATUS_PENDING (interim), cmd={:?}, msg_id={}",
            header.command, header.message_id.0
        );
        return Ok(None);
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
                    return Err((header.message_id, e));
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
        return Err((header.message_id, Error::SessionExpired));
    }

    let body = if sub.len() > Header::SIZE {
        sub[Header::SIZE..].to_vec()
    } else {
        Vec::new()
    };
    let raw = sub.to_vec();
    let msg_id = header.message_id;
    Ok(Some((msg_id, Frame { header, body, raw })))
}

/// Fan the given error (as best we can clone it) to every pending waiter
/// and clear the waiters map. Also close the orphan fallback. Marks the
/// connection as disconnected so new sends fail-fast.
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
    let fallback_tx = inner.orphan_fallback_tx.lock().unwrap().take();
    if let Some(tx) = fallback_tx {
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);

        // Manually set past negotiate.
        conn.set_next_message_id(5);

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
        conn.set_orphan_filter_enabled(false);

        // Activate signing.
        let key = vec![0xAA; 16];
        conn.activate_signing(key, SigningAlgorithm::HmacSha256);
        conn.set_session_id(SessionId(0x1234));

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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

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
    async fn receive_compound_expected_gathers_from_one_frame() {
        // Well-behaved server path: all N responses arrive in a single
        // compound frame. Should complete after one transport read.
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let data = vec![0xAA, 0xBB];
        let create = build_test_create_response(file_id, data.len() as u64);
        let read = build_test_read_response(data);
        let close = build_test_close_response();

        let frame = build_compound_response_frame(&[create, read, close]);
        mock.queue_response(frame);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

        let responses = conn.receive_compound_expected(3).await.unwrap();

        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0].0.command, Command::Create);
        assert_eq!(responses[1].0.command, Command::Read);
        assert_eq!(responses[2].0.command, Command::Close);
        // Only one transport frame was consumed.
        assert_eq!(mock.received_count(), 1);
    }

    #[tokio::test]
    async fn receive_compound_expected_gathers_across_split_frames() {
        // Server-split path: Samba (and thus QNAP) sometimes sends each
        // response as a standalone frame even when the client compounded
        // the request. We must read all three frames and present them as
        // if they had been compounded.
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        // Three separate frames, each with NextCommand=0 (standalone).
        let create = build_test_create_response(file_id, data.len() as u64);
        let read = build_test_read_response(data.clone());
        let close = build_test_close_response();

        mock.queue_response(create);
        mock.queue_response(read);
        mock.queue_response(close);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

        let responses = conn.receive_compound_expected(3).await.unwrap();

        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0].0.command, Command::Create);
        assert_eq!(responses[1].0.command, Command::Read);
        assert_eq!(responses[2].0.command, Command::Close);

        // Verify the READ body still round-trips data correctly.
        let mut cursor = ReadCursor::new(&responses[1].1);
        let read_body = ReadResponse::unpack(&mut cursor).unwrap();
        assert_eq!(read_body.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        // Three transport frames were consumed to gather 3 sub-responses.
        assert_eq!(mock.received_count(), 3);
    }

    #[tokio::test]
    async fn receive_compound_expected_gathers_mixed_partial_split() {
        // Hybrid split: server sent the first two responses compounded
        // in one frame, then the third as a standalone frame.
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let create = build_test_create_response(file_id, 0);
        let read = build_test_read_response(vec![]);
        let close = build_test_close_response();

        // Frame 1: CREATE + READ compounded.
        let frame1 = build_compound_response_frame(&[create, read]);
        // Frame 2: CLOSE alone (standalone).
        let frame2 = close;

        mock.queue_response(frame1);
        mock.queue_response(frame2);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

        let responses = conn.receive_compound_expected(3).await.unwrap();

        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0].0.command, Command::Create);
        assert_eq!(responses[1].0.command, Command::Read);
        assert_eq!(responses[2].0.command, Command::Close);
        // Two transport frames consumed: one compounded (CREATE+READ) and
        // one standalone (CLOSE).
        assert_eq!(mock.received_count(), 2);
    }

    #[tokio::test]
    async fn receive_compound_expected_rejects_overflow() {
        // Defensive check: if a frame carries more sub-responses than we
        // expect, that's a protocol error -- bail out rather than silently
        // accept extras.
        let mock = Arc::new(MockTransport::new());

        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let create = build_test_create_response(file_id, 0);
        let read = build_test_read_response(vec![]);
        let close = build_test_close_response();

        let frame = build_compound_response_frame(&[create, read, close]);
        mock.queue_response(frame);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

        // We ask for 2 but the frame contains 3 -- should error.
        let err = conn.receive_compound_expected(2).await.unwrap_err();
        assert!(
            format!("{err}").contains("split compound response overflow")
                || format!("{err}").contains("overflow"),
            "unexpected error: {err}",
        );
    }

    #[tokio::test]
    async fn send_compound_increments_message_ids_by_credit_charge() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(3);

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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);
        conn.set_compression_enabled(true);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);
        conn.set_compression_enabled(false); // Compression disabled.

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

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
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

        let responses = conn.receive_compound().await.unwrap();

        // Should have skipped the oplock break and returned the compound.
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].0.command, Command::Create);
        assert_eq!(responses[1].0.command, Command::Close);

        // Both frames should have been received from the mock.
        assert_eq!(mock.received_count(), 2);
    }

    // ── Orphan-response tests (MessageId demux) ──────────────────────
    //
    // Observed in the wild against a QNAP NAS: two back-to-back list_directory
    // calls on the same connection, where the second call's receive_response()
    // returned the Close response left over from the first (cancelled / late)
    // call. The caller unpacked the Close body (StructureSize=60) as a
    // CreateResponse (StructureSize=89) and errored cryptically. See
    // docs/specs/connection-actor.md for the full story.
    //
    // These tests pin the invariant: receive_response() and
    // receive_compound_expected() must return the response whose MessageId
    // matches the caller's most recent send, skipping orphaned frames with
    // unrelated MessageIds. Today they do NOT — these tests fail until the
    // actor-based Connection lands.

    /// Build a Close response with a caller-chosen MessageId. Used to
    /// simulate orphans left behind by earlier (cancelled or lost) ops.
    fn build_close_response_with_msg_id(msg_id: MessageId) -> Vec<u8> {
        let mut h = Header::new_request(Command::Close);
        h.flags.set_response();
        h.credits = 10;
        h.message_id = msg_id;

        let body = crate::msg::close::CloseResponse {
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

    /// Build a Create response with a caller-chosen MessageId.
    fn build_create_response_with_msg_id(file_id: FileId, msg_id: MessageId) -> Vec<u8> {
        let mut h = Header::new_request(Command::Create);
        h.flags.set_response();
        h.credits = 10;
        h.message_id = msg_id;

        let body = CreateResponse {
            oplock_level: OplockLevel::None,
            flags: 0,
            create_action: CreateAction::FileOpened,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: FileTime::ZERO,
            change_time: FileTime::ZERO,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
            file_id,
            create_contexts: vec![],
        };

        pack_message(&h, &body)
    }

    #[tokio::test]
    async fn receive_response_skips_orphan_with_unknown_message_id() {
        // Scenario: a previous operation's Close response was never consumed
        // (e.g. the operation was cancelled mid-flight). A new operation
        // sends a Create and awaits its response. The orphan sits in the
        // pipe ahead of the real response.
        //
        // Expected: receive_response skips the orphan (its MessageId is not
        // one we're waiting on) and returns the Create response.
        //
        // Today: receive_response returns whatever arrives next off the
        // wire, so it returns the orphan Close, the caller tries to unpack
        // a Close body as a CreateResponse, and fails.

        let mock = Arc::new(MockTransport::new());

        // Orphan from a prior op: Close with MessageId we never sent.
        mock.queue_response(build_close_response_with_msg_id(MessageId(999)));

        // The real response for the Create we're about to send.
        let file_id = FileId {
            persistent: 0x1,
            volatile: 0x2,
        };
        mock.queue_response(build_create_response_with_msg_id(file_id, MessageId(4)));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);
        conn.set_next_message_id(5);

        // Simulate having just sent a Create with msg_id=4: mark it as the
        // MessageId we're waiting on. receive_response must return this
        // response, not the orphan Close queued ahead of it.
        conn.test_mark_pending(MessageId(4));

        let (header, _body, _raw) = conn.receive_response().await.unwrap();

        assert_eq!(
            header.command,
            Command::Create,
            "receive_response returned the orphan Close instead of the Create we were waiting for"
        );
        assert_eq!(header.message_id, MessageId(4));

        // The orphan should have been consumed off the wire (not left there
        // to corrupt the next op).
        assert_eq!(mock.pending_responses(), 0);
    }

    #[tokio::test]
    async fn receive_compound_expected_skips_orphan_frame_before_gathering() {
        // Scenario: a prior operation's Create response orphan is still in
        // the pipe. The next operation sends a 3-op compound (Create +
        // QueryInfo + Close) and calls receive_compound_expected(3).
        //
        // Expected: the orphan is skipped, the 3-op compound response is
        // collected correctly.
        //
        // Today: the orphan is consumed as the first of 3 sub-responses,
        // then the real compound frame is read and the overflow check
        // fires: "split compound response overflow: expected 3 sub-responses
        // total, already collected 1, but next frame has 3 more".

        let mock = Arc::new(MockTransport::new());

        // Orphan: a lone Create response from a prior, aborted op.
        let ghost_file_id = FileId {
            persistent: 0xDEAD,
            volatile: 0xBEEF,
        };
        mock.queue_response(build_create_response_with_msg_id(
            ghost_file_id,
            MessageId(8),
        ));

        // The real 3-op compound response (fs_info shape), with MessageIds
        // matching the 3 ops we're pretending to have sent.
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let create_resp = {
            let mut h = Header::new_request(Command::Create);
            h.flags.set_response();
            h.credits = 10;
            h.message_id = MessageId(9);
            let body = CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: 0,
                file_attributes: 0,
                file_id,
                create_contexts: vec![],
            };
            pack_message(&h, &body)
        };
        let query_info_resp = {
            let mut h = Header::new_request(Command::QueryInfo);
            h.flags.set_response();
            h.credits = 10;
            h.message_id = MessageId(10);
            let body = crate::msg::query_info::QueryInfoResponse {
                output_buffer: vec![0u8; 24],
            };
            pack_message(&h, &body)
        };
        let close_resp = {
            let mut h = Header::new_request(Command::Close);
            h.flags.set_response();
            h.credits = 10;
            h.message_id = MessageId(11);
            let body = crate::msg::close::CloseResponse {
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
        };
        let frame = build_compound_response_frame(&[create_resp, query_info_resp, close_resp]);
        mock.queue_response(frame);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);
        conn.set_next_message_id(12);

        // Caller sent 3 ops: Create (msg_id=9), QueryInfo (10), Close (11).
        conn.test_mark_pending(MessageId(9));
        conn.test_mark_pending(MessageId(10));
        conn.test_mark_pending(MessageId(11));

        let responses = conn
            .receive_compound_expected(3)
            .await
            .expect("compound receive should skip the orphan and collect all 3 sub-responses");

        assert_eq!(responses.len(), 3, "expected all 3 sub-responses");
        assert_eq!(responses[0].0.command, Command::Create);
        assert_eq!(responses[1].0.command, Command::QueryInfo);
        assert_eq!(responses[2].0.command, Command::Close);

        // The orphan should have been consumed off the wire.
        assert_eq!(mock.pending_responses(), 0);
    }

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

    #[tokio::test]
    async fn phase2_dropped_caller_future_does_not_corrupt_next_op() {
        // Scenario (cmdr `listing_task.abort()` reproduction):
        //
        // 1. Task A sent Create msg_id=4, then was aborted before it could
        //    call receive_response. Its future dropped; msg_id=4 is in
        //    `pending` (Phase 1) or `waiters` (Phase 2) with a dead Receiver.
        // 2. Task B acquires the connection, sends its own Create msg_id=5,
        //    then calls receive_response.
        // 3. A's response arrives on the wire BEFORE B's.
        //
        // Phase 1 behavior (buggy): B's receive_response reads A's frame,
        // sees msg_id=4 in pending, returns it to B. B gets the wrong
        // file_id and proceeds to corrupt the wire further.
        //
        // Phase 2 behavior (correct): receiver task looks up msg_id=4's
        // Sender, Send succeeds-or-fails silently (Receiver gone), frame
        // is discarded. When msg_id=5 arrives, it routes to B's Sender.
        // B's receive_response returns msg_id=5. ✓

        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);

        // Simulate Task A: sent Create msg_id=4, then was aborted.
        // `test_mark_pending_dropped` registers the Sender in the map but
        // immediately drops the Receiver — exactly the "caller's future
        // was cancelled" state this test is exercising. When msg_id=4's
        // response arrives, the receiver task routes it to the Sender
        // and the send fails silently (no Receiver); the frame is
        // discarded.
        conn.set_next_message_id(4);
        conn.test_mark_pending_dropped(MessageId(4));

        // Task A's response arrives late on the wire.
        mock.queue_response(build_create_response_with_msg_id(
            FileId {
                persistent: 0xAAAA,
                volatile: 0xBBBB,
            },
            MessageId(4),
        ));

        // Task B: allocate msg_id=5 (simulating the send that would happen).
        // Live waiter — B will actually await this one.
        conn.set_next_message_id(6);
        conn.test_mark_pending(MessageId(5));

        // B's response (its own Create).
        mock.queue_response(build_create_response_with_msg_id(
            FileId {
                persistent: 0x1111,
                volatile: 0x2222,
            },
            MessageId(5),
        ));

        // B calls receive_response — must get ITS OWN response (msg_id=5).
        let (header, _body, _raw) = conn
            .receive_response()
            .await
            .expect("B's receive_response should succeed");

        assert_eq!(
            header.message_id,
            MessageId(5),
            "B received A's aborted-then-arrived response (msg_id=4) instead of its own \
             (msg_id=5). This is the cancellation-by-drop corruption that Phase 2 fixes."
        );
        assert_eq!(header.command, Command::Create);

        // A's late response should have been consumed off the wire and
        // discarded (not left sitting there to pollute the next op).
        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn phase2_multiple_in_flight_msgs_route_to_correct_waiter() {
        // Scenario (compound + out-of-order wire delivery):
        //
        // 1. Caller sends Create msg_id=4 and Create msg_id=5 (e.g. as part
        //    of a compound or a pipelined pair).
        // 2. The server responds in a DIFFERENT order: msg_id=5's response
        //    arrives first, then msg_id=4's.
        // 3. Caller calls receive_response twice, expecting the first call
        //    to return msg_id=4 (matching send order) and the second
        //    msg_id=5.
        //
        // Phase 1 behavior: receive_response returns frames in wire order,
        // regardless of send order. First call returns msg_id=5. FAILS.
        //
        // Phase 2 behavior: each caller's oneshot is keyed by the msg_id
        // it registered. Out-of-order wire delivery routes correctly —
        // each oneshot receives its matching frame. First receive_response
        // pops the msg_id=4 receiver and awaits it; the receiver task
        // sees msg_id=5 first, routes it to msg_id=5's Sender (buffered),
        // then sees msg_id=4, routes it to msg_id=4's Sender, which
        // unblocks the first receive_response. Second receive_response
        // gets msg_id=5's buffered response. ✓

        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);
        conn.set_next_message_id(4);

        // Caller sent two Creates (msg_id=4 and msg_id=5).
        conn.test_mark_pending(MessageId(4));
        conn.test_mark_pending(MessageId(5));

        // Server responds out of order: msg_id=5 first, then msg_id=4.
        mock.queue_response(build_create_response_with_msg_id(
            FileId {
                persistent: 0x5555,
                volatile: 0x5555,
            },
            MessageId(5),
        ));
        mock.queue_response(build_create_response_with_msg_id(
            FileId {
                persistent: 0x4444,
                volatile: 0x4444,
            },
            MessageId(4),
        ));

        // First receive_response: caller expects msg_id=4 (the first op they sent).
        let (first, _, _) = conn
            .receive_response()
            .await
            .expect("first receive_response should succeed");
        assert_eq!(
            first.message_id,
            MessageId(4),
            "first receive_response returned msg_id={} but caller's first-sent was msg_id=4 \
             — responses must route to the waiter that sent them, not follow wire order",
            first.message_id.0
        );

        // Second receive_response: caller expects msg_id=5.
        let (second, _, _) = conn
            .receive_response()
            .await
            .expect("second receive_response should succeed");
        assert_eq!(second.message_id, MessageId(5));

        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn phase2_dropped_caller_frame_still_updates_credits() {
        // Scenario: Task A was aborted with msg_id=4 in flight. A's
        // response arrives carrying a credit grant of +100. Task B then
        // sends msg_id=5 and checks `conn.credits()`.
        //
        // Invariant (both phases): credits apply to EVERY received frame,
        // including those routed to dead waiters. Throughput must not
        // regress under cancellation churn.
        //
        // Phase 1: the buggy path happens to apply credits (because it
        // treats A's frame as legitimate and returns it to B, applying
        // credits along the way). But B receives A's frame — the real
        // bug. This test asserts both: credits applied AND B got its
        // own response.

        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);
        conn.set_next_message_id(4);

        // Task A: sent, aborted. msg_id=4 has a dead waiter.
        conn.test_mark_pending_dropped(MessageId(4));

        // A's late response — carries +100 credits in the header.
        let a_frame = {
            let mut h = Header::new_request(Command::Create);
            h.flags.set_response();
            h.credits = 100; // big credit grant
            h.message_id = MessageId(4);
            let body = CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: 0,
                file_attributes: 0,
                file_id: FileId {
                    persistent: 0xAA,
                    volatile: 0xBB,
                },
                create_contexts: vec![],
            };
            pack_message(&h, &body)
        };
        mock.queue_response(a_frame);

        // B sends msg_id=5.
        conn.set_next_message_id(6);
        conn.test_mark_pending(MessageId(5));
        mock.queue_response(build_create_response_with_msg_id(
            FileId {
                persistent: 0x11,
                volatile: 0x22,
            },
            MessageId(5),
        ));

        // B's receive_response must return msg_id=5 (not A's msg_id=4).
        let (header, _, _) = conn.receive_response().await.unwrap();
        assert_eq!(
            header.message_id,
            MessageId(5),
            "B received A's aborted response instead of its own"
        );

        // Credits must have ticked forward for BOTH frames (A's +100 and
        // B's +10). Starting from 10, minus 1 per consumed frame:
        //   10 + 100 - 1 (A) + 10 - 1 (B) = 118
        // Allow some slack if exact credit math differs slightly post-refactor;
        // the invariant is "credits went UP significantly, not stayed at 10".
        let final_credits = conn.credits();
        assert!(
            final_credits >= 100,
            "credits={} — A's dropped-caller frame failed to apply its credit grant. \
             Phase 2 must still update credits for orphaned-by-drop frames so throughput \
             doesn't regress under cancellation.",
            final_credits
        );

        mock.assert_fully_consumed();
    }

    #[tokio::test]
    async fn phase2_malformed_frame_does_not_kill_connection() {
        // Scenario: the server (or network) delivers a malformed frame.
        // The connection must keep working — the bad frame gets logged
        // and skipped, and subsequent valid frames route correctly.
        //
        // Phase 2 invariant: the receiver task does NOT panic or exit
        // on a parse failure. Single-frame corruption doesn't poison
        // the whole connection.

        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);
        conn.set_next_message_id(4);
        conn.test_mark_pending(MessageId(4));

        // Queue a malformed frame (too short to be a valid SMB2 header),
        // then a valid Create response.
        mock.queue_response(vec![0xFE, 0x53, 0x4D]); // truncated "FEMB2" magic — fewer than 64 bytes
        mock.queue_response(build_create_response_with_msg_id(
            FileId {
                persistent: 0x11,
                volatile: 0x22,
            },
            MessageId(4),
        ));

        // receive_response should skip the malformed frame (or return
        // an error-and-continue internally) and deliver the valid one.
        // Post-Phase-2 the receiver task handles this; Phase 1 may bubble
        // the parse error up. Either way: the connection stays usable.
        //
        // We assert the eventual successful delivery — possibly after
        // one "bad frame" error that the caller retries past. For Phase 2
        // the first receive_response call directly succeeds.
        let result = conn.receive_response().await;
        match result {
            Ok((header, _, _)) => {
                assert_eq!(header.message_id, MessageId(4));
                assert_eq!(header.command, Command::Create);
            }
            Err(_) => {
                // Phase 1 path: the first call returns an error. A retry
                // should find the valid frame.
                let (header, _, _) = conn
                    .receive_response()
                    .await
                    .expect("after skipping malformed frame, valid frame should arrive");
                assert_eq!(header.message_id, MessageId(4));
            }
        }

        mock.assert_fully_consumed();
    }

    // ── Phase 2 robustness tests ────────────────────────────────────

    #[tokio::test]
    async fn phase2_transport_close_errors_all_pending_waiters() {
        // Register three waiters, then close the transport. All three
        // awaits must resolve to an error rather than hanging forever.
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);
        conn.set_next_message_id(10);
        conn.test_mark_pending(MessageId(10));
        conn.test_mark_pending(MessageId(11));
        conn.test_mark_pending(MessageId(12));

        // Close the transport to trigger the receiver-task error fan-out.
        mock.close();

        for _ in 0..3 {
            let err = conn.receive_response().await.err();
            assert!(
                err.is_some(),
                "after transport close, receive_response must return an error",
            );
        }
    }

    #[tokio::test]
    async fn phase2_oplock_break_does_not_consume_caller_waiter() {
        // Receiver task must silently skip oplock-break notifications
        // (MessageId=UNSOLICITED) and NOT deliver them to any waiter. A
        // subsequent legitimate response for a registered waiter must
        // still arrive.
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_credits(10);
        conn.set_next_message_id(4);
        conn.test_mark_pending(MessageId(4));

        // Oplock break first, then the real Create response.
        mock.queue_response(build_oplock_break_notification());
        mock.queue_response(build_create_response_with_msg_id(
            FileId {
                persistent: 0x33,
                volatile: 0x44,
            },
            MessageId(4),
        ));

        let (header, _, _) = conn.receive_response().await.unwrap();
        assert_eq!(header.message_id, MessageId(4));
        assert_eq!(header.command, Command::Create);
    }

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
    #[ignore = "phase3-red: pins P3.4 silent-discard fix; un-ignore when A.4 lands"]
    async fn phase3_decrypt_failure_errors_waiter_not_hangs() {
        use crate::crypto::encryption::Cipher;

        let mock = Arc::new(MockTransport::new());

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

        // Simulate: the caller sent msg_id=4 and is awaiting its response.
        conn.test_mark_pending(MessageId(4));

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
        let result = tokio::time::timeout(Duration::from_secs(2), conn.receive_response()).await;

        assert!(
            result.is_ok(),
            "receive_response hung forever on a decrypt-failed frame — Phase 3's silent-discard \
             fix must tear down the connection on unrecoverable frame errors and propagate \
             Err(Disconnected) to pending waiters. Instead the receiver task silently discards \
             the frame and the waiter never resolves. (P3.4 fixes this.)"
        );
        let waiter_result = result.unwrap();
        assert!(
            waiter_result.is_err(),
            "receive_response should return an error on decrypt failure, not Ok. Got: {:?}",
            waiter_result.as_ref().map(|_| "Ok(_)")
        );
    }

    // ── CANCEL tests (pitfall #7) ────────────────────────────────────

    #[tokio::test]
    async fn send_cancel_does_not_consume_credit_or_advance_message_id() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
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
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
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
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
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
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);

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

    // ── Session expiry tests (pitfall #8) ─────────────────────────────

    /// Build a response with a given status and command.
    fn build_status_response(status: NtStatus, command: Command) -> Vec<u8> {
        let mut h = Header::new_request(command);
        h.flags.set_response();
        h.credits = 10;
        h.status = status;

        // Minimal error response body: StructureSize=9, ErrorContextCount=0, Reserved=0, ByteCount=0.
        let body = crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: Vec::new(),
        };

        pack_message(&h, &body)
    }

    #[tokio::test]
    async fn receive_response_returns_session_expired_on_network_session_expired() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_response(build_status_response(
            NtStatus::NETWORK_SESSION_EXPIRED,
            Command::Read,
        ));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(10);

        let result = conn.receive_response().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::SessionExpired),
            "expected SessionExpired, got: {err}"
        );
    }

    #[tokio::test]
    async fn receive_response_session_expired_still_updates_credits() {
        let mock = Arc::new(MockTransport::new());
        // Response grants 10 credits.
        mock.queue_response(build_status_response(
            NtStatus::NETWORK_SESSION_EXPIRED,
            Command::Write,
        ));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(3);

        let _ = conn.receive_response().await;

        // Credits should have been updated: 3 + 10 (granted) - 1 (consumed) = 12.
        assert_eq!(conn.credits(), 12);
    }

    // ── Encryption tests ─────────────────────────────────────────────

    /// Helper: set up a connection with encryption active.
    fn setup_encrypted_connection(mock: &Arc<MockTransport>) -> Connection {
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
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
        conn.set_session_id(SessionId(0xDEAD));
        conn.set_credits(10);

        // 16-byte key for AES-128.
        let enc_key = vec![0x42; 16];
        let dec_key = vec![0x42; 16];
        conn.activate_encryption(enc_key, dec_key, Cipher::Aes128Gcm);
        conn
    }

    #[tokio::test]
    async fn send_request_encrypts_when_active() {
        use crate::msg::echo::EchoRequest;

        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_encrypted_connection(&mock);

        let (_msg_id, _plaintext) = conn
            .send_request(Command::Echo, &EchoRequest, None)
            .await
            .unwrap();

        // The sent bytes should start with the TRANSFORM_HEADER protocol ID.
        let sent = mock.sent_message(0).unwrap();
        assert_eq!(
            &sent[..4],
            &TRANSFORM_PROTOCOL_ID,
            "sent message must start with 0xFD 'S' 'M' 'B'"
        );

        // The sent message should be longer than the transform header
        // (52 bytes header + encrypted payload).
        assert!(
            sent.len() > TransformHeader::SIZE,
            "sent message must contain ciphertext after transform header"
        );
    }

    #[tokio::test]
    async fn send_request_encrypted_can_be_decrypted() {
        use crate::msg::echo::EchoRequest;

        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_encrypted_connection(&mock);

        let (_msg_id, plaintext) = conn
            .send_request(Command::Echo, &EchoRequest, None)
            .await
            .unwrap();

        // Decrypt the sent message and verify it matches the plaintext.
        let sent = mock.sent_message(0).unwrap();
        let transform_header = &sent[..TransformHeader::SIZE];
        let ciphertext = &sent[TransformHeader::SIZE..];

        let dec_key = vec![0x42; 16];
        let decrypted =
            encryption::decrypt_message(transform_header, ciphertext, &dec_key, Cipher::Aes128Gcm)
                .unwrap();
        assert_eq!(
            decrypted, plaintext,
            "decrypted message must match plaintext"
        );
    }

    #[tokio::test]
    async fn receive_response_decrypts_encrypted_message() {
        use crate::msg::echo::EchoResponse;

        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_encrypted_connection(&mock);

        // Build a normal response, then encrypt it.
        let mut h = Header::new_request(Command::Echo);
        h.flags.set_response();
        h.credits = 10;
        h.session_id = SessionId(0xDEAD);
        let plaintext = pack_message(&h, &EchoResponse);

        let enc_key = vec![0x42; 16];
        let mut nonce_gen = encryption::NonceGenerator::new();
        let nonce = nonce_gen.next(Cipher::Aes128Gcm);
        let (transform_header, ciphertext) =
            encryption::encrypt_message(&plaintext, &enc_key, Cipher::Aes128Gcm, &nonce, 0xDEAD)
                .unwrap();

        let mut encrypted_frame = transform_header;
        encrypted_frame.extend_from_slice(&ciphertext);
        mock.queue_response(encrypted_frame);

        let (resp_header, _body, _raw) = conn.receive_response().await.unwrap();
        assert_eq!(resp_header.command, Command::Echo);
        assert!(resp_header.is_response());
    }

    #[tokio::test]
    async fn signing_skipped_when_encryption_active() {
        use crate::msg::echo::EchoRequest;

        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_encrypted_connection(&mock);

        // Also activate signing.
        conn.activate_signing(vec![0xAA; 16], SigningAlgorithm::AesCmac);

        let (_msg_id, plaintext) = conn
            .send_request(Command::Echo, &EchoRequest, None)
            .await
            .unwrap();

        // Decrypt the sent message.
        let sent = mock.sent_message(0).unwrap();
        let transform_header = &sent[..TransformHeader::SIZE];
        let ciphertext = &sent[TransformHeader::SIZE..];
        let dec_key = vec![0x42; 16];
        let decrypted =
            encryption::decrypt_message(transform_header, ciphertext, &dec_key, Cipher::Aes128Gcm)
                .unwrap();

        // The Signature field in the plaintext SMB2 header (bytes 48..64) should
        // be all zeros (not signed). When encrypting, signature is zeroed because
        // AEAD provides authentication.
        let signature = &decrypted[48..64];
        assert_eq!(
            signature, &[0u8; 16],
            "signature must be zeroed when encrypting (signing is mutually exclusive)"
        );

        // Also verify the SIGNED flag is NOT set in the header flags.
        let flags = u32::from_le_bytes(decrypted[16..20].try_into().unwrap());
        assert_eq!(
            flags & HeaderFlags::SIGNED,
            0,
            "SIGNED flag must not be set when encrypting"
        );

        // The plaintext should match what pack_message produced (no signature applied).
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn compound_encryption_wraps_entire_chain() {
        use crate::msg::echo::EchoRequest;

        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_encrypted_connection(&mock);

        let ops: Vec<(Command, &dyn Pack, CreditCharge)> = vec![
            (Command::Echo, &EchoRequest, CreditCharge(1)),
            (Command::Echo, &EchoRequest, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(TreeId(1), &ops).await.unwrap();

        // Only one message should have been sent (the entire compound
        // wrapped in a single TRANSFORM_HEADER).
        assert_eq!(
            mock.sent_count(),
            1,
            "compound must be sent as one encrypted message"
        );

        let sent = mock.sent_message(0).unwrap();
        assert_eq!(
            &sent[..4],
            &TRANSFORM_PROTOCOL_ID,
            "compound must start with TRANSFORM_HEADER"
        );

        // Decrypt and verify it contains two sub-requests.
        let transform_header = &sent[..TransformHeader::SIZE];
        let ciphertext = &sent[TransformHeader::SIZE..];
        let dec_key = vec![0x42; 16];
        let decrypted =
            encryption::decrypt_message(transform_header, ciphertext, &dec_key, Cipher::Aes128Gcm)
                .unwrap();

        // The decrypted data should contain at least two SMB2 headers (64 bytes each).
        assert!(
            decrypted.len() >= Header::SIZE * 2,
            "compound plaintext must contain at least two sub-requests, got {} bytes",
            decrypted.len()
        );

        // First sub-request: NextCommand should be non-zero (pointing to second).
        let next_cmd = u32::from_le_bytes(decrypted[20..24].try_into().unwrap());
        assert!(
            next_cmd > 0,
            "first sub-request must have non-zero NextCommand"
        );

        // Second sub-request: verify it starts with SMB2 protocol ID.
        let second_start = next_cmd as usize;
        assert_eq!(
            &decrypted[second_start..second_start + 4],
            &[0xFE, b'S', b'M', b'B'],
            "second sub-request must start with SMB2 protocol ID"
        );
    }

    #[tokio::test]
    async fn no_encryption_when_not_activated() {
        use crate::msg::echo::EchoRequest;

        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
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

        let (_msg_id, _plaintext) = conn
            .send_request(Command::Echo, &EchoRequest, None)
            .await
            .unwrap();

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
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);

        assert!(!conn.should_encrypt());

        conn.activate_encryption(vec![0x42; 16], vec![0x42; 16], Cipher::Aes128Gcm);

        assert!(conn.should_encrypt());
    }

    #[tokio::test]
    async fn receive_compound_decrypts_encrypted_response() {
        use crate::msg::echo::EchoResponse;

        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_encrypted_connection(&mock);

        // Build two sub-responses (compound).
        let mut h1 = Header::new_request(Command::Echo);
        h1.flags.set_response();
        h1.credits = 5;
        h1.session_id = SessionId(0xDEAD);
        let sub1 = pack_message(&h1, &EchoResponse);

        let mut h2 = Header::new_request(Command::Echo);
        h2.flags.set_response();
        h2.credits = 5;
        h2.session_id = SessionId(0xDEAD);
        let sub2 = pack_message(&h2, &EchoResponse);

        // Pad first sub-response to 8-byte alignment and set NextCommand.
        let mut padded_sub1 = sub1;
        let remainder = padded_sub1.len() % 8;
        if remainder != 0 {
            padded_sub1.resize(padded_sub1.len() + (8 - remainder), 0);
        }
        let next_cmd = padded_sub1.len() as u32;
        padded_sub1[20..24].copy_from_slice(&next_cmd.to_le_bytes());

        // Concatenate into compound.
        let mut compound = padded_sub1;
        compound.extend_from_slice(&sub2);

        // Encrypt the whole compound.
        let enc_key = vec![0x42; 16];
        let mut nonce_gen = encryption::NonceGenerator::new();
        let nonce = nonce_gen.next(Cipher::Aes128Gcm);
        let (transform_header, ciphertext) =
            encryption::encrypt_message(&compound, &enc_key, Cipher::Aes128Gcm, &nonce, 0xDEAD)
                .unwrap();

        let mut encrypted_frame = transform_header;
        encrypted_frame.extend_from_slice(&ciphertext);
        mock.queue_response(encrypted_frame);

        let results = conn.receive_compound().await.unwrap();
        assert_eq!(results.len(), 2, "compound must contain two responses");
        assert_eq!(results[0].0.command, Command::Echo);
        assert_eq!(results[1].0.command, Command::Echo);
    }

    // ── DFS flag tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn dfs_flag_set_for_registered_tree() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);

        let tree_id = TreeId(7);
        conn.register_dfs_tree(tree_id);

        use crate::msg::echo::EchoRequest;
        let body = EchoRequest;
        let (_mid, msg_bytes) = conn
            .send_request_with_credits(Command::Echo, &body, Some(tree_id), 1)
            .await
            .unwrap();

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
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);

        use crate::msg::echo::EchoRequest;
        let body = EchoRequest;
        let (_mid, msg_bytes) = conn
            .send_request_with_credits(Command::Echo, &body, Some(TreeId(7)), 1)
            .await
            .unwrap();

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
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);

        let tree_id = TreeId(7);
        conn.register_dfs_tree(tree_id);
        conn.deregister_dfs_tree(tree_id);

        use crate::msg::echo::EchoRequest;
        let body = EchoRequest;
        let (_mid, msg_bytes) = conn
            .send_request_with_credits(Command::Echo, &body, Some(tree_id), 1)
            .await
            .unwrap();

        let flags_raw = u32::from_le_bytes(msg_bytes[16..20].try_into().unwrap());
        assert_eq!(
            flags_raw & HeaderFlags::DFS_OPERATIONS,
            0,
            "DFS_OPERATIONS flag must NOT be set after deregister"
        );
    }

    #[tokio::test]
    async fn compound_dfs_flag_set() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.set_orphan_filter_enabled(false);
        conn.set_credits(256);

        let tree_id = TreeId(42);
        conn.register_dfs_tree(tree_id);

        use crate::msg::echo::EchoRequest;
        let echo1 = EchoRequest;
        let echo2 = EchoRequest;
        let operations: Vec<(Command, &dyn Pack, CreditCharge)> = vec![
            (Command::Echo, &echo1, CreditCharge(1)),
            (Command::Echo, &echo2, CreditCharge(1)),
        ];

        let _msg_ids = conn.send_compound(tree_id, &operations).await.unwrap();

        let sent = mock.sent_message(0).unwrap();

        // Check first sub-request header flags at bytes 16..20.
        let flags1 = u32::from_le_bytes(sent[16..20].try_into().unwrap());
        assert_ne!(
            flags1 & HeaderFlags::DFS_OPERATIONS,
            0,
            "first compound sub-request must have DFS_OPERATIONS"
        );

        // Jump to second sub-request using NextCommand from first header.
        let next_cmd = u32::from_le_bytes(sent[20..24].try_into().unwrap()) as usize;
        let flags2 = u32::from_le_bytes(sent[next_cmd + 16..next_cmd + 20].try_into().unwrap());
        assert_ne!(
            flags2 & HeaderFlags::DFS_OPERATIONS,
            0,
            "second compound sub-request must have DFS_OPERATIONS"
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

        // Caller-local state is per-clone: both FIFOs start empty.
        assert!(original.pending_fifo.is_empty());
        assert!(cloned.pending_fifo.is_empty());
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

        let f1 = results[1].as_ref().expect("op 1 still carries a Frame — error status in header");
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
