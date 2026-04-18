# Connection actor refactor

Design for moving `Connection`'s demux from "synchronous HashSet over one thread" to "receiver task + per-request `oneshot::Sender` routing". Fixes a correctness gap that lets cancelled-by-drop in-flight requests corrupt subsequent operations on the same connection.

This doc is the single source of truth during the refactor. Decisions are pinned here; when in doubt, update this doc rather than drifting from it.

## Staging

Three phases on `main`, each landed as a separate PR:

1. **Phase 1 — `HashSet<MessageId>` demux (done, commit `750e07a`).** `Connection` tracks in-flight `MessageId`s in a `pending: HashSet<MessageId>`. `send_request` / `send_compound` insert; `receive_response` / `receive_compound_expected` skip frames whose MessageId isn't in the set (crediting them so throughput stays correct, logging at DEBUG). Zero public API change, zero caller change, ~260 LOC. Fixes the observed field bug for strictly-sequential callers.

2. **Phase 2 — Actor task + `oneshot`-per-request routing (this PR).** Spawn a receiver task on `Connection::connect` that owns the read half of the transport and routes each frame to the `oneshot::Sender` registered for its `MessageId`. `send_request` / `send_compound` now register an `oneshot::Receiver` in a caller-local FIFO before returning; `receive_response` / `receive_compound_expected` pop from that FIFO and await the next response. Public API signatures unchanged. No `Connection: Clone`, no `execute()` API — those are Phase 3. **The key semantic improvement: dropping a caller's future (`tokio::spawn`'d task aborted, `select!` arm cancelled, etc.) no longer corrupts the wire — the `oneshot::Receiver` closes, the frame is discarded on arrival.**

3. **Phase 3 — Public `execute()` API + `Connection: Clone` + caller migration (future PR).** Expose `execute()` / `execute_compound()` for callers that want concurrent ops per connection. `Connection` becomes `Clone` (wraps the existing `Arc<Inner>`). Callers in `tree.rs` migrate from `send_request` + `receive_response` to `execute()`. Pipelined loops in `tree.rs` become `FuturesUnordered` over `execute_with_credits()` calls. Unlocks "100 tiny files in parallel" and similar. Strictly additive — Phase 2's public API stays valid during and after Phase 3.

Each phase is a strict subset of the next. Work from Phase 1 carries into Phase 2 (the `HashSet` becomes a `HashMap<MessageId, oneshot::Sender>`); Phase 2's actor is what Phase 3 exposes.

## Why

Today (pre-Phase-2), `Connection::receive_response()` returns the next frame off the wire whose MessageId is in `pending`, then removes it from the set. This is correct for strictly-sequential callers — but breaks under any caller that drops its future mid-flight.

Scenario hit in the field (logged against cmdr's `listing_task.abort()` at `apps/desktop/src-tauri/src/file_system/listing/streaming.rs:429`):

1. `tokio::spawn`'d task A holds the `SmbVolume` mutex, has sent `Create msg_id=4` over smb2. `msg_id=4` is in `pending`.
2. The task is aborted by `listing_task.abort()`. The spawned future drops. The `MutexGuard` drops. `msg_id=4` stays in `pending` (nothing unregisters it — abort is protocol-unaware).
3. Task B takes the newly-available mutex, sends `Create msg_id=5`, calls `receive_response()`.
4. Server's response for msg_id=4 arrives first. `msg_id=4 ∈ pending` → returned to B. B parses it as its own CreateResponse and gets a corrupted file_id; or B calls receive_response for a QueryDirectoryResponse and gets `msg_id=4`'s CreateResponse (`expected 9, got 89`).

Phase 1's `HashSet` drops *never-sent* orphans. It doesn't distinguish "we're still waiting for this response" from "we once were but the caller is gone". Phase 2 closes that gap: a `oneshot::Sender` is registered per request, and when the corresponding `oneshot::Receiver` is dropped (because the caller's future was dropped), the `Sender::send` fails silently on arrival — the frame is discarded, credits are still applied, no wire corruption.

### Beyond correctness

This refactor is also the foundation Phase 3 needs. Once responses route by `MessageId`, multiple callers can safely interleave on one connection — which is what cmdr's "100 tiny files in parallel" copy goal requires. Phase 2 lays the mechanism; Phase 3 exposes it via `execute()`.

The library's `AGENTS.md` already claims: "Only ONE task reads from the transport. Multiple pipelines on the same connection share a single receive task that demultiplexes by `MessageId`." Phase 2 makes the code match that claim.

## In one paragraph (Phase 2 scope)

`Connection::connect` spawns a receiver task that owns the transport's read half. On each received frame, the receiver task decrypts/decompresses/verifies/handles PENDING+oplock-break+session-expiry, updates credits atomically, and looks up the frame's `MessageId` in a shared `waiters: Arc<Mutex<HashMap<MessageId, oneshot::Sender<Frame>>>>` map — sending the frame to the matched `Sender` if it exists, dropping the frame (with an orphan-drop log) if not. Callers still call `send_request(...)` / `receive_response()` exactly as before: `send_request` allocates a `MessageId` (from a shared `AtomicU64`), registers a `oneshot::Sender` in `waiters`, pushes the `oneshot::Receiver` onto a `Connection`-local `VecDeque<Receiver>`, and sends the framed bytes through the transport's write half (still guarded by its existing `tokio::sync::Mutex`). `receive_response` pops the front receiver and awaits it. No public API change, no caller change.

## Decisions

| # | Decision | Choice | Why |
|---|----------|--------|-----|
| D1 | `Connection` cloneability | **Phase 2: stays owning; `&mut` on send/receive.** Internals are `Arc`-based so Phase 3's `Clone` flip is trivial. | Scope discipline. Phase 2 is purely correctness, not concurrency. |
| D2 | Public method signatures | **Phase 2: unchanged.** `send_request`, `send_request_with_credits`, `send_compound`, `receive_response`, `receive_compound`, `receive_compound_expected` all keep today's signatures and semantics. | Zero caller churn, zero cmdr-side change beyond the `Cargo.lock` bump. |
| D3 | Number of actor tasks | **One: a receiver task.** Send path stays caller-driven (caller locks transport write half, signs, sends) — no sender task needed in Phase 2. | Half the moving parts. The receiver is where the routing bug lives; the sender path is already fine. Phase 3 may add a sender task if `execute()` benefits from it. |
| D4 | Response delivery | Per-request `oneshot::Sender<Result<Frame>>` registered in `Arc<Mutex<HashMap<MessageId, Sender>>>` | Classic demux. `oneshot` is the right fit for "exactly one response per request". |
| D5 | Caller-local pending queue | `VecDeque<oneshot::Receiver<Result<Frame>>>` on `Connection` (caller thread only) | Preserves today's "send N then receive_response N times in order" API. `send_request` pushes back, `receive_response` pops front. |
| D6 | State layout | `state: Arc<ConnectionState>` with `AtomicU32` credits, `AtomicU64` next_msg_id, `OnceLock<NegotiatedParams>`, `Mutex<CryptoState>` for signing/encryption/preauth | Hot reads are lock-free; sender and receiver share via `Arc`. Mutation during handshake only (rare, short, sequential). |
| D7 | MessageId allocation | Caller-thread atomic `fetch_add(credit_charge)` on `state.next_msg_id` **before** inserting waiter and sending. Frame then carries the pre-allocated id. | No actor round-trip for id allocation. Send order = allocation order = msg_id order (mpsc+single-writer preserves it). |
| D8 | Credits accounting | Receiver task updates `state.credits` atomically on every frame (orphans included). Caller-thread reads `state.credits.load()` for pre-send checks. | Orphans don't starve throughput. Same invariant as Phase 1. |
| D9 | Handshake mutators | `session.rs` still calls `conn.activate_signing(...)`, `conn.set_session_id(...)`, etc. These now take `&state.crypto.lock()`. | No semantic change; internal plumbing only. |
| D10 | Preauth hash updates | Receiver task updates preauth hash on the chosen frames (SESSION_SETUP responses except final SUCCESS). Sender path (caller thread) updates on send. | Matches today's split. |
| D11 | Cancellation-by-drop | Caller's `oneshot::Receiver` drops → `Sender::send` fails silently on arrival → frame is discarded, credits still applied, waiter map entry removed. | The primary correctness win of Phase 2. No special API; works through normal Rust drop. |
| D12 | Transport failure | Receiver task fans `Err(Error::Disconnected)` (or the actual I/O error) to every pending waiter, clears the map, exits. Subsequent caller ops get `Err(Disconnected)` from a closed waiter channel or the next transport send. | One clear dead-state. No half-dead connections. |
| D13 | Session expiry | Receiver task detects `STATUS_NETWORK_SESSION_EXPIRED`, sends `Err(Error::SessionExpired)` to the matched waiter only. Other waiters keep running (they'll hit the same error on their own responses, or succeed if the session recovers quickly). | Minimum-blast-radius. Caller is expected to reconnect. |
| D14 | STATUS_PENDING (interim responses) | Receiver task keeps the waiter registered, does NOT forward the interim response. Caller sees only the final response. | Matches today's behavior exactly. CHANGE_NOTIFY and other long-poll ops "just work". |
| D15 | Oplock breaks (MessageId=0xFFFF...) | Receiver task logs at DEBUG, skips. No waiter lookup. | Matches today. |
| D16 | Malformed frame | Receiver task logs at WARN, skips, keeps running. Does NOT panic or stop routing. | Robustness invariant — one bad frame doesn't kill the connection. |
| D17 | `Connection::disconnect()` (teardown) | Drop closes the transport write half, which triggers the receiver task to exit and fan `Err(Disconnected)` to remaining waiters. Explicit `disconnect()` stays for symmetry but does the same thing. | Graceful + panic-safe. |
| D18 | `MockTransport` changes | None beyond Phase 1's `assert_fully_consumed()` helper. Tests that bypass `send_request` (direct `mock.queue_response` + `conn.receive_response`) continue to work — the receiver task reads from the mock's queue normally. | No test-infra churn. |
| D19 | Test-fixture orphan-filter toggle | The existing `conn.set_orphan_filter_enabled(false)` (Phase 1, used by `setup_connection`) keeps working. The actor-based demux respects it: when disabled, the receiver task returns any frame via a single "broadcast" waiter. (Implementation detail: when disabled, the `Connection` exposes a single always-present receiver that the actor forwards to.) | Preserves ~300 existing unit tests that use hardcoded MessageId(0). |
| D20 | Runtime requirement | tokio is formalized as a hard requirement (de-facto already true — no other transport exists). `async_trait` stays. Documented in `AGENTS.md` + `README`. | Clarity. No new dependency. |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Connection                               │
│                       (owned, &mut on ops)                       │
│                                                                  │
│  pending_fifo: VecDeque<oneshot::Receiver<Result<Frame>>>        │
│  inner: Arc<ConnectionInner>                                     │
└─────────────────────────────────────────────────────────────────┘
                        │
                        │ Arc share
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ConnectionInner                              │
│                                                                  │
│  state: Arc<ConnectionState>        (atomics + OnceLock + Mutex) │
│  waiters: Arc<Mutex<WaitersMap>>    (HashMap<MsgId, OnceTx>)     │
│  transport_send: Arc<dyn TransportSend>                          │
│  receiver_task: JoinHandle<()>      (drops = aborts task)        │
└─────────────────────────────────────────────────────────────────┘
         │                                       ▲
         │ transport.send(frame_bytes)           │ transport.receive()
         ▼                                       │
┌───────────────────────────────────────────────────────────────────┐
│    Transport (TcpTransport or MockTransport) — split halves       │
│    send_half: Mutex<OwnedWriteHalf>    recv_half: owned by receiver│
└───────────────────────────────────────────────────────────────────┘
                                                 ▲
                                                 │
                                     ┌───────────────────────┐
                                     │  Receiver task        │
                                     │                       │
                                     │  loop {               │
                                     │    frame = recv()     │
                                     │    decrypt/decompress │
                                     │    parse sub-frames   │
                                     │    for each sub:      │
                                     │      update credits   │
                                     │      handle PENDING   │
                                     │      handle oplock    │
                                     │      verify sig       │
                                     │      match msg_id →   │
                                     │        waiter.send()  │
                                     │      else → log+drop  │
                                     │  }                    │
                                     └───────────────────────┘
```

### Caller flow (`send_request` + `receive_response`)

```rust
// send_request
let msg_id = state.next_msg_id.fetch_add(credit_charge, Ordering::SeqCst);
let (tx, rx) = oneshot::channel();
waiters.lock().insert(msg_id, tx);
let frame_bytes = build_and_sign_frame(msg_id, ...);
transport.send(&frame_bytes).await?;   // transport's own Mutex still protects write half
self.pending_fifo.push_back(rx);
Ok((msg_id, header_stub))

// receive_response
let rx = self.pending_fifo.pop_front().ok_or(Error::invalid_data("no in-flight request"))?;
let frame = rx.await.map_err(|_| Error::Disconnected)??;
Ok((frame.header, frame.body, frame.raw))
```

### Caller flow (`send_compound` + `receive_compound_expected(N)`)

```rust
// send_compound — for each of N sub-ops:
for op in ops {
    let msg_id = state.next_msg_id.fetch_add(credit_charge, ...);
    let (tx, rx) = oneshot::channel();
    waiters.lock().insert(msg_id, tx);
    self.pending_fifo.push_back(rx);
}
transport.send(&compound_bytes).await?;

// receive_compound_expected(n):
let mut sub_responses = Vec::with_capacity(n);
for _ in 0..n {
    let rx = self.pending_fifo.pop_front()...;
    sub_responses.push(rx.await??);
}
Ok(sub_responses)
```

Note: in Phase 2 the receiver task itself splits server-compounded frames into sub-responses as it parses the frame. Each sub-response gets routed independently to its matching waiter. This replaces Phase 1's "gather N frames then hand to caller" logic — the receiver does the gather internally by matching `MessageId`s.

### Cancellation-by-drop flow

```
Caller task: send_request(...) → waiter inserted, receiver pushed onto pending_fifo
Caller task: runs other await points (e.g., other ops, yielded to scheduler)
External: listing_task.abort() → Caller task's future is dropped
Drop propagates: pending_fifo drops → Receivers drop → waiters' Senders are still in map
... server's response arrives ...
Receiver task: looks up msg_id in waiters → finds Sender → send(frame) fails silently (no Receiver)
Receiver task: removes entry from map, logs at TRACE "late arrival for dropped waiter"
Credits were already applied earlier in the receiver loop.
```

The `oneshot::Sender::send(frame)` call returns `Err(frame)` when the Receiver is dropped. Receiver task discards the returned frame. Map entry is removed unconditionally. No leaks.

## Internal types

```rust
pub(crate) struct ConnectionInner {
    state: Arc<ConnectionState>,
    waiters: Arc<Mutex<HashMap<MessageId, oneshot::Sender<Result<Frame>>>>>,
    transport_send: Arc<dyn TransportSend>,
    receiver_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

pub(crate) struct ConnectionState {
    // Negotiated once at handshake, then read-only.
    pub params: OnceLock<NegotiatedParams>,
    pub server_name: String,

    // Hot, updated by receiver task only, read by callers for pre-send checks.
    pub credits: AtomicU32,  // u32 because AtomicU16 wasn't stable at project-MSRV.
    pub next_msg_id: AtomicU64,

    // Handshake state — mutations are rare and sequential.
    pub crypto: std::sync::Mutex<CryptoState>,

    // Feature toggles set at construction (test support).
    pub orphan_filter_enabled: AtomicBool,
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
    pub nonce_counter: u64,
}

/// A successfully received SMB2 sub-response.
pub struct Frame {
    pub header: Header,
    pub body: Vec<u8>,
    pub raw: Vec<u8>,
}
```

## Receiver task loop (pseudocode)

```rust
async fn receiver_loop(
    transport_recv: Box<dyn TransportReceive>,
    state: Arc<ConnectionState>,
    waiters: Arc<Mutex<WaitersMap>>,
) {
    loop {
        let frame_bytes = match transport_recv.receive().await {
            Ok(b) => b,
            Err(e) => {
                // Fan to all pending waiters and exit.
                let drained: Vec<_> = waiters.lock().drain().collect();
                for (_msg_id, tx) in drained {
                    let _ = tx.send(Err(e.clone_or_disconnected()));
                }
                return;
            }
        };

        // Decrypt if TRANSFORM_HEADER; decompress if COMPRESSION_HEADER.
        let (decoded, was_encrypted) = match preprocess(&frame_bytes, &state) {
            Ok(x) => x,
            Err(e) => { log::warn!("malformed frame: {e}"); continue; }
        };

        // Split into sub-responses by NextCommand offsets.
        let sub_responses = match split_compound(&decoded) {
            Ok(subs) => subs,
            Err(e) => { log::warn!("compound parse: {e}"); continue; }
        };

        for sub in sub_responses {
            let header = match parse_header(&sub) { Ok(h) => h, Err(e) => { log::warn!(...); continue; } };

            // Credits first — always applied.
            update_credits(&state, &header);

            if header.is_oplock_break() { log::debug!(...); continue; }

            if header.status == STATUS_PENDING {
                // Keep the waiter; interim response, don't forward.
                continue;
            }

            if state.should_sign_receive() && !was_encrypted {
                if let Err(e) = verify_signature(&sub, &state) {
                    // Signature bad: send to waiter as error; do not poison connection.
                    if let Some(tx) = waiters.lock().remove(&header.message_id) {
                        let _ = tx.send(Err(e));
                    }
                    continue;
                }
            }

            let frame = Frame { header, body: sub[HEADER_SIZE..].to_vec(), raw: sub };

            // Special case: session expired — send error to waiter, don't poison others.
            let result = if frame.header.status == STATUS_NETWORK_SESSION_EXPIRED {
                Err(Error::SessionExpired)
            } else {
                Ok(frame)
            };

            match waiters.lock().remove(&header.message_id) {
                Some(tx) => {
                    let _ = tx.send(result); // ignore send failure (caller dropped)
                }
                None => {
                    if state.orphan_filter_enabled() {
                        log::debug!("orphan msg_id={}, cmd={:?}", header.message_id, header.command);
                    } else {
                        // Test mode: we'd need a fallback broadcast receiver here.
                        // (Details in §"Test-fixture compatibility".)
                    }
                }
            }
        }
    }
}
```

### Test-fixture compatibility

Phase 1 added `Connection::set_orphan_filter_enabled(bool)` to let tests that call `mock.queue_response(...)` + `conn.receive_response()` directly (without going through `send_request`) keep working. Roughly 550 unit tests rely on this.

In Phase 2, when the filter is *disabled*, the Connection maintains a single "broadcast waiter" that receives any otherwise-unmatched frame. `receive_response` pops from `pending_fifo` if present, else from the broadcast waiter. This is a narrow test-only path; production always has the filter enabled.

Implementation: an internal `std::sync::Mutex<Option<mpsc::UnboundedSender<Result<Frame>>>>` on `ConnectionInner`, set up by `set_orphan_filter_enabled(false)`. `receive_response` uses `tokio::select!` to await whichever arrives first.

## Phase 2 public API (unchanged from today)

```rust
impl Connection {
    pub async fn connect(addr: impl ToSocketAddrs, timeout: Duration) -> Result<Self>;
    pub fn from_transport(send: Box<dyn TransportSend>, recv: Box<dyn TransportReceive>, server_name: &str) -> Self;

    pub async fn negotiate(&mut self) -> Result<NegotiatedParams>;

    pub async fn send_request(&mut self, command: Command, body: &impl Pack, tree_id: Option<TreeId>) -> Result<(MessageId, ())>;
    pub async fn send_request_with_credits(&mut self, command: Command, body: &impl Pack, tree_id: Option<TreeId>, credit_charge: u16) -> Result<(MessageId, ())>;
    pub async fn send_compound(&mut self, ops: &[(Command, &dyn Pack, CreditCharge)], tree_id: TreeId) -> Result<Vec<MessageId>>;
    pub async fn send_cancel(&mut self, target_msg_id: MessageId, async_id: Option<u64>) -> Result<()>;

    pub async fn receive_response(&mut self) -> Result<(Header, Vec<u8>, Vec<u8>)>;
    pub async fn receive_compound(&mut self) -> Result<Vec<(Header, Vec<u8>)>>;
    pub async fn receive_compound_expected(&mut self, expected: usize) -> Result<Vec<(Header, Vec<u8>)>>;

    // Handshake mutators (used by session.rs)
    pub fn activate_signing(&self, key: Vec<u8>, algorithm: SigningAlgorithm);
    pub fn activate_encryption(&self, enc_key: Vec<u8>, dec_key: Vec<u8>, cipher: Cipher);
    pub fn set_session_id(&self, id: SessionId);
    pub fn set_compression_requested(&self, requested: bool);
    pub fn register_dfs_tree(&self, tree_id: TreeId);
    pub fn deregister_dfs_tree(&self, tree_id: TreeId);

    // Lock-free accessors
    pub fn credits(&self) -> u16;
    pub fn params(&self) -> Option<NegotiatedParams>;
    pub fn should_encrypt(&self) -> bool;
    pub fn should_sign(&self) -> bool;
    pub fn session_id(&self) -> SessionId;
    pub fn server_name(&self) -> &str;
    pub fn compression_enabled(&self) -> bool;

    // Test support
    pub(crate) fn set_orphan_filter_enabled(&self, enabled: bool);
}
```

Differences from pre-Phase-2:
- Handshake mutators can take `&self` instead of `&mut self` (state is behind atomics / Mutex). Call sites in `session.rs` change `conn.activate_signing(...)` from `&mut conn` to `&conn`. This is the only source-level change in callers.
- Fast accessors also go from `&self` with interior access — no change for readers.

## Test plan

### Red tests (committed red before impl)

These go in `src/client/connection.rs` tests (a new `actor_routing` test module):

1. **`dropped_caller_future_does_not_corrupt_next_op`** — simulates the streaming-listing abort. Send a request A, drop the caller future before receive_response runs, simulate the late frame arrival (via mock), send a new request B, assert B's receive_response returns B's response correctly. **Fails on pre-Phase-2.**

2. **`concurrent_ops_on_one_connection_route_correctly`** — once Phase 3's `execute()` lands this becomes useful for parallel; in Phase 2, since `&mut` still serializes callers, this test is written as "two sequential send_request calls, responses queued out of order on the mock, each `receive_response` gets the right one" which tests the demux routing. **Fails on pre-Phase-2 without the `assert_fully_consumed` helper catching the leak.**

3. **`dropped_caller_credits_still_applied`** — send a request, drop before receive, simulate late frame arrival, assert `conn.credits()` ticks forward as if the response were consumed. **Fails on pre-Phase-2 (credits only applied at the receive_response call site).**

4. **`receiver_task_survives_malformed_frame`** — queue a garbage frame (invalid header), then a valid frame for an in-flight msg_id, assert the valid frame arrives. **Fails on pre-Phase-2 (the first bad parse kills the receive loop for the calling op).**

### Robustness tests (alongside impl)

5. **`transport_drop_errors_all_pending_waiters`** — send 3 requests, close the mock transport, assert all 3 `receive_response` awaits return `Err(Disconnected)`.

6. **`stress_concurrent_ops_with_random_drops`** — 1000 iterations of: spawn a random number of listings on one connection, drop a random subset mid-flight, verify the survivors complete correctly. Guards against subtle timing issues in the receiver task.

### Integration (Docker, real-NAS)

- `just test-docker` (13 internal containers)
- `just test-consumer` (14 consumer containers, cmdr's contract surface)
- `cargo test --test integration -- --ignored` against QNAP + Pi manually before push

### `MockTransport::assert_fully_consumed()` adoption

Phase 1 added this helper. Phase 2 is the right time to actually wire it into every test that calls `conn.receive_response()`. Catches test-level regressions where responses are queued but never consumed (which was the latent shape that let the bug hide for this long).

## Migration (Phase 2 only)

### Code changes

1. `src/client/connection.rs`:
   - Introduce `ConnectionInner`, `ConnectionState`, `CryptoState`, `WaitersMap`.
   - `Connection::from_transport(send, recv, server_name)` spawns the receiver task.
   - `send_request(_with_credits)`: allocate msg_id atomically, register waiter, push receiver, send frame.
   - `send_compound`: same loop per sub-op.
   - `send_cancel`: no waiter, just transport.send.
   - `receive_response`: pop from pending_fifo, await.
   - `receive_compound_expected(n)`: pop n receivers, await all.
   - Handshake mutators switch from `&mut self` to `&self` (interior mutability).
   - All existing inline signing/decryption/compound-parsing logic moves into receiver task helpers.

2. `src/client/session.rs`:
   - `Session::setup()` callers of `conn.activate_signing(...)` etc. stop needing `&mut conn`. One-line touch.

3. `src/client/tree.rs`:
   - `Tree::*` methods still take `&mut Connection` (Phase 3 flips these to `&Connection`).
   - `read_pipelined_loop_with_progress` and friends continue to work unchanged — they already match responses to requests by MessageId on the caller side; with Phase 2 they'll simply stop seeing other callers' frames.

4. `src/transport/tcp.rs`, `src/transport/mock.rs`:
   - No changes beyond what Phase 1 already has.

### Test migration

Expected impact:
- Roughly 80% of `connection.rs` and `tree.rs` unit tests work unchanged (they go through `send_request` + `receive_response` and don't inspect internals).
- Tests that directly manipulate `conn.credits = N;` or `conn.next_message_id = M;` as field writes: replace with the atomic-setter helpers. ~35 sites.
- Tests that call `receive_response()` directly after `mock.queue_response()` without a preceding `send_request`: these rely on `set_orphan_filter_enabled(false)` (Phase 1). With Phase 2 they route through the broadcast-waiter fallback. ~550 sites — no per-site change needed if the helper is maintained.

### Docs

- Update `src/client/CLAUDE.md` with the new architecture sketch and the cancellation-by-drop invariant.
- Update `AGENTS.md` "Only ONE task reads from the transport" paragraph to point at the receiver task as the implementation of that invariant.

## Risks and non-risks

**Not risky:**
- Wire format: unchanged.
- Transport trait: unchanged.
- High-level API (SmbClient, Tree, FileWriter, Pipeline): unchanged.
- Docker and consumer integration tests: unchanged (black-box against SmbClient).

**Risky (but mitigated):**
- **Receiver task panic safety.** A panic in the receiver task would strand every caller forever. Mitigation: every `parse_header`/`verify_signature`/`decrypt` path uses `Result`, logged-and-continue on `Err`. No `unwrap` on frame content. Test `receiver_task_survives_malformed_frame` pins this.
- **Transport drop edge cases.** If the transport errors during a caller's `transport.send(...)`, the waiter was registered but the frame never went out. Mitigation: on send error, remove the just-inserted waiter from the map before returning the error (caller observes the error; no orphan waiter).
- **Preauth hash ordering.** Session setup depends on precise preauth hash updates. Mitigation: hash updates happen on the caller thread during send and in the receiver task on non-PENDING response arrival — same ordering as today, just split across threads. Tested by the existing session setup integration tests (real Docker + mocked).
- **Shutdown races.** Dropping `Connection` while the receiver task is mid-route: the task holds `Arc<WaitersMap>`, the drop of `ConnectionInner` decrements the Arc but the task holds it. When the task exits (after transport EOF or `JoinHandle::abort`), the Arc is released. No leak.

**Scope carve-outs (deferred to Phase 3 or later):**
- Concurrent-ops credit semaphore. Added when parallelism is actually wired up in callers.
- `Connection::clone()`.
- `execute()` / `execute_compound()` public API.
- Automatic SMB CANCEL on future drop (today: drop just closes the oneshot; frame gets discarded on arrival).
- Pause/resume transfers.

## For future consumers

(Applies after Phase 3 lands. Phase 2 preserves today's API, so no new consumer-facing guidance yet.)

When Phase 3 arrives:
- `Connection` becomes `Clone`. Clone freely across tasks.
- Dropping a future mid-flight is safe — the response is discarded when it arrives.
- For explicit protocol-level cancellation (e.g., a multi-second upload), use `conn.cancel(msg_id, async_id)` before dropping the future.
- `Err(Error::Disconnected)` means the connection is dead; reconnect (not clone).

## Phase 3 preview (NOT in this PR)

For planning purposes — not implemented in Phase 2:

- `Connection` gains `#[derive(Clone)]` (just wraps `Arc<Inner>`).
- New public methods `execute(cmd, body, tree_id) -> Result<Frame>`, `execute_compound(ops) -> Result<Vec<Result<Frame>>>`, `execute_with_credits(..., credit_charge)`.
- `tree.rs` methods flip `&mut Connection` → `&Connection`; callers of `Tree::*` similarly.
- `Pipeline::execute()` migrates from serial iteration to `FuturesUnordered` of `execute()` futures.
- Legacy `send_request` + `receive_response` may remain as thin wrappers for a deprecation period.
- SmbVolume in cmdr drops its `tokio::sync::Mutex`; parallel `copy_between_volumes` becomes feasible.

Phase 3 is a big enough scope to warrant its own design doc when we get there. Mentioned here only to clarify Phase 2 is not a dead end.
