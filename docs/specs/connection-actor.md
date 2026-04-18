# Connection actor refactor

Design for making `Connection` own a receiver task that demultiplexes SMB2 responses by `MessageId`, exposing a simple `execute()` API to callers. Replaces the current `send_request` + `receive_response` split, which is unsafe under any glitch that leaves a response unconsumed on the wire.

This doc is the single source of truth during the refactor. Decisions are pinned here; when in doubt, update this doc rather than drifting from it.

## Why

Today, `Connection::receive_response()` returns the next frame off the wire without matching it to the request that asked for it. If any operation leaves a response unconsumed — cancellation, mid-flight error, fire-and-forget cleanup, server oddity — the orphan sits in the socket, and the next operation picks it up as its own. One glitch corrupts every subsequent op on that connection.

Observed symptom: two back-to-back `list_directory` calls against a QNAP NAS, where the second one's `CreateResponse.StructureSize` check fails with `expected 89, got 60` — the second call consumed the first call's Close response. The fs_info compound that followed then mis-grouped responses. See the April 2026 conversation in the cmdr repo for the log.

The library's `AGENTS.md` already claims that "Only ONE task reads from the transport. Multiple pipelines on the same connection share a single receive task that demultiplexes by `MessageId`." This refactor makes the code match that claim.

Beyond correctness, this unlocks:
- True concurrent operations on one connection (N `execute()` calls in parallel) — needed for cmdr's "100 tiny files" copy goal.
- Clean cancellation via SMB CANCEL when a caller's future is dropped.
- Pause/resume of transfers as actor state, not caller-scattered state.
- Centralized credit discipline across all in-flight ops on a connection.

## The design in one paragraph

`Connection` owns a pair of background tasks: a sender task that drains a command queue (callers submit `ActorCommand` via an `mpsc` channel), and a receiver task that reads frames from the transport and routes each sub-response to the `oneshot::Sender` registered for its `MessageId`. Callers interact with `Connection` through `execute()` (single op) and `execute_compound()` (one frame, N sub-responses). Connection state is split: frequently-read data (`credits`, `params`, `should_encrypt`, etc.) is behind `Arc<AtomicU*>` or `Arc<OnceLock>` for lock-free reads; state mutated only during handshake is behind a short-lived `Arc<Mutex<HandshakeState>>`. `Connection` is `Clone` (just an `Arc` clone of the inner handle), so spawning 100 parallel `execute()` calls across as many tasks is the normal case.

## Decisions

| # | Decision | Choice | Why |
|---|----------|--------|-----|
| D1 | `Connection` cloneability | `Clone`, backed by `Arc<ConnectionInner>` | Parallel op submission from many tasks. Cheap to clone. |
| D2 | Public method signature | `fn execute(&self, ...) -> Future` (no `&mut`) | Concurrent callers don't need exclusive access. |
| D3 | Caller–actor transport | `mpsc::UnboundedSender<ActorCommand>` | Unbounded is fine: one item per in-flight op, capped by credits upstream. Simpler than bounded + backpressure plumbing. |
| D4 | Response delivery | Per-request `oneshot::Sender<Result<Frame>>` registered in `HashMap<MessageId, Sender>` | Classic demux. `oneshot` is the right fit for "exactly one response". |
| D5 | Number of actor tasks | Two: sender + receiver, sharing `Arc<Mutex<Waiters>>` and `Arc<State>` | Lets large frame reads not block new sends. Clean lifecycle: receiver drives connection liveness; sender follows. |
| D6 | State layout | `Arc<ConnectionState>` with `AtomicU32` credits, `OnceLock<NegotiatedParams>`, `Arc<Mutex<Crypto>>` for signing/nonce | Hot reads are lock-free; mutation is rare and scoped. |
| D7 | Credits discipline | Caller pre-checks via `conn.credits()`; actor honors `credit_charge` in message ID advance and consumes credits on response. No semaphore, no queuing inside actor. | Matches today's pattern exactly. Callers already do this. Keeps actor simple. |
| D8 | Pre-encode request bodies | Yes. Caller packs the body to `Vec<u8>` before submitting the command. | Keeps actor generic over message types. Signing operates on bytes anyway. |
| D9 | Pipelined read/write location | Stays in `tree.rs`. Each chunk becomes one `execute()` call; futures drive the sliding window via `FuturesUnordered`. | Lets `Tree` own the "N chunks of one file" semantics. Actor just routes. Credits are still enforced by the caller loop, same as today. |
| D10 | Compound handling | `execute_compound(ops) -> Future<Vec<Result<Frame>>>`. Internally: one frame sent, N oneshots registered, N responses routed (server may split — each sub-response finds its oneshot by MessageId regardless). | No special "batch" machinery in actor. The split-compound tolerance we already added (commit `7f79392`) continues to work because routing is per-MessageId. |
| D11 | `send_request` + `receive_response` removal | Remove from public API. Internal helpers only, used by the actor. | The split is what caused the bug. Keeping it as a shim invites re-introduction. |
| D12 | MockTransport changes | None. Existing `Arc<MockTransport>` already works across tasks via `std::sync::Mutex`. | Test setup gets a helper `setup_connection_with_actor(mock)` that spawns the tasks. |
| D13 | Cancellation protocol | Dropping the caller's future closes the oneshot. On the next frame for that MessageId, the actor finds the `Sender` gone and discards the response (credits still applied). For explicit mid-op abort, callers use `conn.cancel(op_handle)` which sends SMB CANCEL. | Safe by default; explicit when needed. |
| D14 | Session expiry | Receiver task detects `STATUS_NETWORK_SESSION_EXPIRED`, sends `Err(Error::SessionExpired)` to the matched oneshot, keeps running. Other ops continue; caller is expected to reconnect. | Matches today's behavior. No blast-radius change. |
| D15 | Transport failure | Receiver task fans `Err(Error::Disconnected)` (or the actual I/O error, cloned) to every pending oneshot, signals the sender task to stop accepting new commands, both tasks exit. Subsequent `execute()` on the dropped connection returns `Err(Error::Disconnected)` from the closed mpsc channel. | One clear unhealthy state. No half-dead connections. |
| D16 | `Connection::disconnect()` | Sends `ActorCommand::Shutdown` to sender, which flushes pending, closes the transport, signals the receiver to exit. Both tasks `await` cleanly. | Graceful teardown for `on_unmount` and similar. |
| D17 | `Watcher` | No special handling needed. `conn.execute(CHANGE_NOTIFY, ...)` returns a future; the oneshot sits in the map for as long as the server takes. Drop = cancel. | One less thing to think about. |
| D18 | Public API stability | Deprecate-and-break: the internal-level API changes, but `SmbClient` / `Tree` / `FileWriter` / `Pipeline` public surface stays the same. Consumers of the high-level API (cmdr) don't notice. | Minimizes downstream churn. |
| D19 | Runtime requirement | tokio is a hard requirement (formalized). `async_trait` stays. | Already de-facto true — only tokio transports exist. Formalize in the README. |

## Public API

What external consumers see. (Internal types like `ActorCommand` or `Waiters` are crate-private.)

### `Connection`

```rust
/// A connected, authenticated SMB2 connection to a server.
///
/// `Connection` is cheap to clone — every clone is a shared handle to the
/// same underlying TCP connection and actor tasks. Clone freely to share
/// a connection across tasks; the actor serializes sends and demultiplexes
/// responses by `MessageId`.
///
/// When the last `Connection` handle is dropped, the actor tasks shut down
/// and the TCP connection is closed. For graceful shutdown, call
/// [`disconnect()`](Self::disconnect) to flush pending operations first.
#[derive(Clone)]
pub struct Connection { /* Arc<ConnectionInner> */ }

impl Connection {
    /// Connect to an SMB server over TCP. Spawns the actor tasks.
    pub async fn connect(addr: impl ToSocketAddrs, timeout: Duration) -> Result<Self>;

    /// Send one request, await one response. The primary API for most callers.
    ///
    /// The frame is signed and/or encrypted according to the connection's
    /// negotiated state. The response is delivered when the server replies
    /// to this specific MessageId — other operations' responses can arrive
    /// interleaved without affecting this call.
    pub async fn execute(
        &self,
        command: Command,
        body: &impl Pack,
        tree_id: Option<TreeId>,
    ) -> Result<Frame>;

    /// Like [`execute`](Self::execute), but charges `credit_charge` credits
    /// against the connection's credit pool — required for large READ and
    /// WRITE requests whose payload exceeds 64 KB.
    pub async fn execute_with_credits(
        &self,
        command: Command,
        body: &impl Pack,
        tree_id: Option<TreeId>,
        credit_charge: CreditCharge,
    ) -> Result<Frame>;

    /// Send a compounded chain of related requests in a single frame.
    /// Returns one `Result<Frame>` per sub-op, in the submitted order.
    ///
    /// The server MAY split the response across multiple frames
    /// (MS-SMB2 3.3.4.1.3). This method is transparent to that — each
    /// sub-response is routed by its `MessageId` regardless of framing.
    ///
    /// Partial failure: each sub-op's `Result` is independent. If CREATE
    /// succeeds but READ fails, the caller still gets the FileId from
    /// CREATE and can issue a standalone CLOSE.
    pub async fn execute_compound(
        &self,
        ops: &[(Command, &dyn Pack, Option<TreeId>, CreditCharge)],
    ) -> Result<Vec<Result<Frame>>>;

    /// Send an SMB CANCEL for an in-flight MessageId. Fire-and-forget.
    ///
    /// Typical use: attach a `CancelHandle` to a long-running operation,
    /// and on user-initiated cancel, call `handle.cancel()` which
    /// internally calls this.
    pub async fn cancel(
        &self,
        target_msg_id: MessageId,
        async_id: Option<u64>,
    ) -> Result<()>;

    /// Graceful shutdown: stop accepting new commands, drain in-flight,
    /// close the transport, join the actor tasks.
    pub async fn disconnect(self) -> Result<()>;

    // ── Fast read-only accessors (lock-free) ────────────────────────

    pub fn credits(&self) -> u16;
    pub fn params(&self) -> Option<&NegotiatedParams>;
    pub fn should_encrypt(&self) -> bool;
    pub fn should_sign(&self) -> bool;
    pub fn session_id(&self) -> SessionId;
    pub fn server_name(&self) -> &str;
    pub fn compression_enabled(&self) -> bool;
    pub fn estimated_rtt(&self) -> Option<Duration>;

    // ── Handshake state mutators (used by session.rs during setup) ──

    pub async fn negotiate(&self) -> Result<()>;
    pub async fn activate_signing(&self, key: Vec<u8>, algorithm: SigningAlgorithm) -> Result<()>;
    pub async fn activate_encryption(&self, enc_key: Vec<u8>, dec_key: Vec<u8>, cipher: Cipher) -> Result<()>;
    pub async fn set_session_id(&self, id: SessionId) -> Result<()>;

    // ── DFS tree registration ───────────────────────────────────────

    pub async fn register_dfs_tree(&self, tree_id: TreeId) -> Result<()>;
    pub async fn deregister_dfs_tree(&self, tree_id: TreeId) -> Result<()>;

    // ── Preauth hash access (for session setup key derivation) ──────

    pub async fn preauth_hash(&self) -> PreauthHashValue;
    pub async fn update_preauth_hash(&self, bytes: &[u8]) -> Result<()>;
}
```

### `Frame`

```rust
/// A successfully received SMB2 response frame, post-decrypt/decompress/verify.
pub struct Frame {
    pub header: Header,
    pub body: Vec<u8>,
    /// Raw bytes of the frame after decryption but before signature verification.
    /// Used for preauth hash updates during session setup.
    pub raw: Vec<u8>,
}
```

### Breaking changes for direct `Connection` users

Anyone using `Connection` directly (not via `SmbClient` / `Tree`) sees these changes:

- `send_request`, `send_request_with_credits`, `send_compound`, `receive_response`, `receive_compound`, `receive_compound_expected`: **removed**. Replace with `execute*`.
- `Connection::from_transport(...)` still exists for testing but returns a started-actor connection.
- `&mut Connection` → `&Connection` throughout. Downstream: `Tree` methods that took `&mut Connection` now take `&Connection`. `SmbClient` methods that took `&mut self` for connection access can often take `&self` too.

For the current (only) user — cmdr — no public API change: `SmbClient::read_file_pipelined(...)` etc. look the same.

## Internal architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Connection                             │
│                      (Arc<ConnectionInner>)                     │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ ConnectionInner {                                       │    │
│  │   cmd_tx: mpsc::UnboundedSender<ActorCommand>,          │    │
│  │   state: Arc<ConnectionState>,                          │    │
│  │   shutdown: watch::Sender<bool>,                        │    │
│  │ }                                                       │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                │                                    ▲
                │ ActorCommand                       │ Frame
                ▼                                    │
┌──────────────────────────────┐         ┌──────────────────────────┐
│ Sender task                  │         │ Receiver task            │
│                              │         │                          │
│ loop {                       │         │ loop {                   │
│   cmd = cmd_rx.recv()        │         │   frame = xport.recv()   │
│   build_header(credits++)    │         │   decrypt/decompress     │
│   sign/encrypt               │         │   parse by NextCommand   │
│   xport.send(bytes)          │         │   for each sub:          │
│   waiters.insert(msg_id, tx) │         │     update credits       │
│ }                            │         │     find waiter(msg_id)  │
└──────────────────────────────┘         │     tx.send(frame)       │
                │                        │ }                        │
                │                        └──────────────────────────┘
                ▼                                    ▲
           ┌──────────────────────────────────────────┐
           │ Transport (TcpTransport or MockTransport) │
           │   send_half: Mutex<OwnedWriteHalf>        │
           │   recv_half: Mutex<OwnedReadHalf>         │
           └──────────────────────────────────────────┘
```

Shared state:
- `waiters: Arc<Mutex<HashMap<MessageId, oneshot::Sender<Result<Frame>>>>>`
- `state: Arc<ConnectionState>` — see below

### `ConnectionState`

```rust
pub(crate) struct ConnectionState {
    // Hot read-only (after handshake). Set via OnceLock.
    pub params: OnceLock<NegotiatedParams>,
    pub server_name: String,
    pub estimated_rtt: Mutex<Option<Duration>>,  // Measured during negotiate, then read-only.

    // Hot, read by many, mutated by receiver task only. Atomic for lock-free reads.
    pub credits: AtomicU32,  // u32 because u16 atomic isn't stable; cast on read.

    // Handshake state — only mutated during session setup, otherwise read-only.
    // Mutex because the mutations happen infrequently and sequentially.
    pub crypto: Mutex<CryptoState>,

    // Sender-task-local state — not shared. Lives in the sender task closure:
    //   - next_message_id: u64
    //   - nonce_gen: Option<NonceGenerator>
}

pub(crate) struct CryptoState {
    pub signing_key: Option<Vec<u8>>,
    pub signing_algorithm: Option<SigningAlgorithm>,
    pub should_sign: bool,
    pub encryption_key: Option<Vec<u8>>,
    pub decryption_key: Option<Vec<u8>>,
    pub encryption_cipher: Option<Cipher>,
    pub should_encrypt: bool,
    pub compression_enabled: bool,
    pub compression_requested: bool,
    pub session_id: SessionId,
    pub preauth_hasher: PreauthHasher,
    pub dfs_trees: HashSet<TreeId>,
}
```

The split: **atomics for per-message-cycle reads**, **Mutex for handshake reads**. The sender task is the only writer of `next_message_id` and `nonce_gen`, so those live as locals in the task.

### `ActorCommand`

```rust
pub(crate) enum ActorCommand {
    SendRequest {
        command: Command,
        body: Vec<u8>,  // pre-encoded by caller
        tree_id: Option<TreeId>,
        credit_charge: CreditCharge,
        reply: oneshot::Sender<Result<Frame>>,
    },
    SendCompound {
        ops: Vec<CompoundOp>,  // each with its own reply oneshot
    },
    SendCancel {
        target_msg_id: MessageId,
        async_id: Option<u64>,
        reply: oneshot::Sender<Result<()>>,
    },
    UpdatePreauthHash {
        bytes: Vec<u8>,
        reply: oneshot::Sender<()>,
    },
    ReadPreauthHash {
        reply: oneshot::Sender<PreauthHashValue>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

pub(crate) struct CompoundOp {
    pub command: Command,
    pub body: Vec<u8>,
    pub tree_id: Option<TreeId>,
    pub credit_charge: CreditCharge,
    pub reply: oneshot::Sender<Result<Frame>>,
}
```

Crypto state mutators (`activate_signing`, `activate_encryption`, `set_session_id`) don't need commands — they lock `state.crypto` directly. They only happen at handshake time so contention with the sender task is negligible.

DFS tree registration similarly locks directly.

### Sender task loop

```
loop {
    cmd = cmd_rx.recv().await
    match cmd {
      SendRequest { command, body, tree_id, credit_charge, reply } => {
        let msg_id = next_message_id;
        next_message_id += credit_charge;
        let bytes = build_frame(command, body, tree_id, credit_charge, msg_id, &state);
        waiters.lock().insert(msg_id, reply);
        transport.send(&bytes).await?; // on error, fan error and exit
      }
      SendCompound { ops } => {
        // Build one compounded frame, one waiter per op.
        for op in &ops { waiters.insert(msg_id_for_op, op.reply); }
        transport.send(&compound_bytes).await?;
      }
      SendCancel { target_msg_id, async_id, reply } => {
        // Build CANCEL frame (no credit consumed, no msg_id advance).
        transport.send(&cancel_bytes).await?;
        let _ = reply.send(Ok(()));
      }
      UpdatePreauthHash { bytes, reply } => {
        state.crypto.lock().preauth_hasher.update(&bytes);
        let _ = reply.send(());
      }
      ReadPreauthHash { reply } => {
        let _ = reply.send(state.crypto.lock().preauth_hasher.finish());
      }
      Shutdown { reply } => {
        // Drain waiters, fan Error::Disconnected, close transport, exit.
        break;
      }
    }
}
```

### Receiver task loop

```
loop {
    frame_bytes = transport.receive().await  // on error, fan error, exit

    // Decrypt if TRANSFORM_HEADER
    // Decompress if COMPRESSION_HEADER
    // Split into sub-responses by NextCommand offsets

    for each sub_response in frame {
        let header = parse(sub_response)
        let msg_id = header.message_id

        credits.store(credits.load() + header.credits - 1, Ordering::Release)

        if header.is_oplock_break(msg_id) { log+skip; continue }

        if header.status == STATUS_PENDING {
            // Keep the waiter registered; continue waiting for the final response.
            continue
        }

        // Verify signature if signed and not was_encrypted
        if signing_active && should_verify { verify_signature(sub_response)? }

        if header.status == STATUS_NETWORK_SESSION_EXPIRED {
            // Fan to this op's waiter; do not disturb other waiters.
            if let Some(tx) = waiters.lock().remove(&msg_id) {
                let _ = tx.send(Err(Error::SessionExpired));
            }
            continue
        }

        if let Some(tx) = waiters.lock().remove(&msg_id) {
            let _ = tx.send(Ok(Frame { header, body, raw }))
        } else {
            // Orphan: no waiter. Could be a late response after cancel. Log at DEBUG.
            debug!("orphan response, msg_id={}, cmd={:?}", msg_id, header.command);
        }
    }
}
```

## Migration plan

### Phase 2 — Red tests
1. `receive_response_ignores_orphaned_response_with_unrelated_message_id` in `connection.rs`. Queue a stale Close with MessageId 999, then the real Create for MessageId 4. Current code returns the Close body (60 bytes) to a caller unpacking it as CreateResponse (expected 89). Fails today.
2. `concurrent_ops_on_one_connection_do_not_cross_talk`. Two `execute()` calls on the same connection, submitted in parallel. Each gets its own response. Can't be written against current API; write as stub that's `#[ignore]`d until the actor lands.
3. `dropping_execute_future_does_not_corrupt_pipe`. Submit an execute, drop the future before the response arrives, submit another — second one succeeds. Also `#[ignore]`d until actor.
4. `session_expiry_fans_to_specific_waiter_not_all`. Only the affected waiter gets `Err(SessionExpired)`. Others keep running.
5. Add `MockTransport::assert_fully_consumed()` helper.

Commit as red.

### Phase 3 — Actor core
- Introduce `ConnectionInner`, `ConnectionState`, `CryptoState`, `ActorCommand`, `CompoundOp`, `Waiters` types.
- `Connection::from_transport()` spawns both tasks.
- `execute()`, `execute_with_credits()`, `execute_compound()`, `cancel()`, `disconnect()` implemented.
- Handshake mutators (`activate_signing`, etc.) become state-lock operations (no command needed).
- Fast accessors read atomics / OnceLock directly.

Old API (`send_request`, `receive_response`, etc.) removed in the same commit.

### Phase 4 — Caller migration
All call sites in `src/client/*.rs` update from:
```rust
let (msg_id, _sent) = conn.send_request(cmd, &body, tree_id).await?;
let (header, body, raw) = conn.receive_response().await?;
```
to:
```rust
let frame = conn.execute(cmd, &body, tree_id).await?;
```

Compound call sites similarly collapse from `send_compound` + `receive_compound_expected(N)` to `execute_compound(ops)`.

Pipelined loops in `tree.rs`: each chunk becomes `conn.execute_with_credits(...)`; the loop collects `N` futures into a `FuturesUnordered`; credit discipline on the caller side stays as-is (reading `conn.credits()` before submitting).

`Watcher` becomes a thin wrapper around `conn.execute(CHANGE_NOTIFY, ...)`, no special lifecycle.

### Phase 5 — Test migration
Unit tests in `src/client/*.rs`:
- ~80% are "queue response(s), call high-level method, assert" — mechanical swap of `conn.send_request + conn.receive_response` → `conn.execute`.
- ~20% inspect raw sent bytes or call the low-level API directly — need restructuring. In most cases, the assertion can shift to inspecting `mock.sent_messages()` after `conn.execute()` returns.
- `MockTransport::assert_fully_consumed()` is applied to every `connection.rs` and `tree.rs` test to catch any leaks.

Wire-format tests (`pack_roundtrip.rs`, `msg_wire_format.rs`): untouched.

Docker / consumer / real-NAS integration tests: unchanged (black-box against `SmbClient` / `Tree`). These are the safety net.

### Phase 6 — Docs
- `src/client/CLAUDE.md`: rewrite "Connection" section to describe the actor design.
- `src/transport/CLAUDE.md`: note that the transport's `send()` and `recv()` may be called from different tasks concurrently (was de-facto true; now formalized).
- `AGENTS.md`: the "Only ONE task reads from the transport" paragraph stays — it's now accurate.

### Phase 7 — Checks
- `just check-all`
- `just test-docker`
- `cargo test --test integration -- --ignored` against QNAP
- Manual run of the original failing scenario (two back-to-back `list_directory` on main connection).

## Risks and non-risks

**Not risky:**
- Wire format: unchanged.
- Transport: already split; no trait changes.
- Docker integration: black-box, unaffected.
- High-level API (SmbClient, Tree, Pipeline, FileWriter): stays.

**Risky:**
- Credit discipline in concurrent-ops scenarios. Today's callers are serial. When many tasks submit `execute()` in parallel, they all read `credits()` and may all decide "plenty available" simultaneously — then all send, exceeding credits. For v1, this is acceptable: SMB servers return `STATUS_INSUFFICIENT_RESOURCES` if exceeded; we'd need to add retry. For today's cmdr usage (single-op-at-a-time via SmbVolume mutex), no regression. When we actually parallelize (the 100-files goal), add a credit semaphore then.
- Actor teardown on `Connection::drop`. If callers drop the connection with in-flight ops, the oneshots should receive `Err(Disconnected)`. Needs explicit test.
- `next_message_id` starts at 0, but after handshake advances. Tests that bypass handshake and manipulate it directly (~30 tests) need `setup_connection` to also initialize the sender task's starting `next_message_id`. Easy but must not be missed.

**Unknown:**
- Test migration effort. Estimated 2-4 hours of Haiku-parallel work. True cost will be known after the first 50 tests are migrated.

## Non-goals for this refactor

Explicitly deferred:
- Concurrent-ops credit semaphore. Added when parallelism is actually used.
- Pause/resume. Added when cmdr wires it up to the UI.
- Automatic CANCEL on future drop for in-flight ops (beyond just oneshot closure). Added when we measure that drop-without-cancel leaves server handles for too long.
- Streaming read (like `write_file_streamed` but for reads). The current `read_file_with_progress` pattern works after migration; streaming can come as a separate addition.
- `Connection` pool / multichannel. Future work.

Keeping these out of scope makes the refactor tractable.

## For future consumers

If you're writing a library or tool that uses `smb2` directly (not via cmdr):

- `Connection` is `Clone`. Clone it, spawn tasks, each task runs `execute()` calls independently. The library handles serialization of sends and routing of responses.
- Dropping a future mid-flight is safe: the response is discarded when it arrives, credits are still applied. No wire-state corruption.
- For explicit cancellation (e.g., the user cancelled a long upload), use `conn.cancel(msg_id, async_id)` before dropping the future. This sends SMB CANCEL so the server stops work.
- Check `conn.credits()` before launching many parallel ops if your server is credit-conservative (QNAP, some NAS firmwares). Default credit discipline in the library is "assume you asked reasonably".
- Errors from `execute()` are always typed. `Err(Error::Disconnected)` means the actor is gone and this `Connection` handle is dead; clone or reconnect.
- `Connection::disconnect().await` is the graceful shutdown. Dropping without calling it aborts in-flight ops with `Err(Disconnected)`.
