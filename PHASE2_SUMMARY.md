# Phase 2 implementation summary

## What changed

- `Connection` now owns an `Arc<Inner>` that holds shared atomics
  (`credits: AtomicU32`, `next_message_id: AtomicU64`), a
  `StdMutex<CryptoState>` for signing/encryption keys and nonce gen,
  and a waiters map `HashMap<MessageId, oneshot::Sender<Result<RoutedFrame>>>`.
- A background receiver task is spawned on `Connection::from_transport`
  (and thus also via `Connection::connect`). It owns the transport's
  read half, preprocesses each frame (decrypt → decompress → split
  compound by NextCommand → signature verify per sub-frame), updates
  credits atomically, and routes each sub-response to the matching
  `oneshot::Sender` in the waiters map.
- Caller-side, `send_request` / `send_compound` allocate MessageIds,
  register a waiter in the map, push the corresponding
  `oneshot::Receiver` onto a local `VecDeque`, and write to the
  transport. `receive_response` / `receive_compound_expected` pop
  the front Receiver and await it.
- Dropping a caller's future (e.g. `tokio::task::JoinHandle::abort()`)
  drops the `oneshot::Receiver`; the receiver task's `tx.send()` then
  fails silently on frame arrival; the frame is discarded. Credits are
  still applied in the receiver task, so throughput doesn't regress
  under cancellation churn.
- Receiver task survives malformed frames (logs at WARN, continues),
  session expiry (routes `Error::SessionExpired` to the matched
  waiter only), and transport drop (fans `Error::Disconnected` to all
  pending waiters, then exits).
- `MockTransport::receive()` now awaits on an internal
  `tokio::sync::Notify` when the queue is empty instead of returning
  `Err(Disconnected)` immediately. Added `MockTransport::close()` to
  signal explicit end-of-stream. This was necessary so the background
  receiver task doesn't exit prematurely between a test's
  `queue_response` calls — which happen interleaved with client
  operations.
- Handshake mutators (`activate_signing`, `activate_encryption`,
  `set_session_id`, etc.) still take `&mut self` to match the existing
  call sites. Internally they lock the shared `CryptoState` via
  `inner.crypto.lock()`. (The design doc mentioned these COULD switch
  to `&self` — unchanged here to keep the diff small; no downstream
  call-site edits needed.)
- `tokio` feature set gained `"rt"` (required for `task::spawn` /
  `JoinHandle`). No new dependency.

## Test-fixture compatibility

- `set_orphan_filter_enabled(false)` now installs an mpsc fallback
  channel. The receiver task sends each transport-frame's batch of
  successfully-parsed sub-responses as a single `Vec<RoutedFrame>`,
  preserving compound-frame grouping for tests. `receive_response`
  / `receive_compound_expected` read from the fallback when the filter
  is off, buffering any extra sub-frames from the same batch in a
  local `VecDeque` so subsequent calls drain them.
- `test_mark_pending(msg_id)` now registers a Sender in the map AND
  pushes the Receiver onto `pending_fifo` — "live waiter".
- Added `test_mark_pending_dropped(msg_id)` which registers the Sender
  but immediately drops the Receiver — "caller future was aborted".

## Deviations from the design doc

1. **Test edits for red tests 3005 & 3158.** Two Phase 2 red tests
   (`phase2_dropped_caller_future_does_not_corrupt_next_op`,
   `phase2_dropped_caller_frame_still_updates_credits`) rewrote
   `conn.test_mark_pending(MessageId(4))` to
   `conn.test_mark_pending_dropped(MessageId(4))` for the aborted task's
   msg_id. The original test comment says: "`test_mark_pending` adds
   msg_id=4 to the in-flight set (Phase 1) or registers a **dead waiter**
   in the map (Phase 2 evolution)." But a single helper can't be both
   "live waiter" (needed for tests like
   `phase2_multiple_in_flight_msgs_route_to_correct_waiter` and
   `phase2_malformed_frame_does_not_kill_connection`) AND "dead waiter"
   (needed for 3005 & 3158). I split into two helpers and updated only
   the tests that explicitly simulate a dropped caller. All test intent
   is preserved. See the test diff in the Phase 2 commit.

2. **Receive-compound vs. per-msg-id demux.** The old semantics of
   `receive_compound` was "return whatever sub-responses arrived in the
   next transport frame". With per-msg-id routing there's no concept of
   "transport frame" at the caller level. Phase 2 preserves the old
   behavior ONLY for test-mode (orphan filter off) where the receiver
   task delivers sub-frames as a per-transport-frame batch to the
   fallback channel. In production (filter on), `receive_compound` pops
   the first response from the fifo (blocking) and drains any
   already-delivered sub-responses from the buffer (non-blocking). This
   is slightly different from today's behavior but preserves the test
   semantics and is strictly better for the production case (no
   coupling to transport-frame boundaries).

3. **CryptoState session_id.** The `session_id` lives inside
   `CryptoState` rather than as a separate atomic. Only hot path that
   reads it is `encrypt_bytes`, which already locks crypto briefly.
   Accessor `Connection::session_id()` also locks briefly — fine for
   Phase 2.

4. **Handshake mutators stayed `&mut self`.** Design doc mentioned
   they COULD switch to `&self`. Left as `&mut self` to minimize diff.
   Interior state is still behind `Arc<Inner>`, so Phase 3's `Clone`
   flip will be trivial.

## Caveats for the leader

- `MockTransport::receive()` blocking behavior change means any
  external consumer (outside smb2 itself) that relied on the old
  "Err on empty queue" behavior would break. The only known consumer
  is smb2's own tests, all updated. If cmdr or another downstream has
  tests using MockTransport directly, they'll need to call `close()`
  to get the old behavior.
- The Phase 2 red tests required splitting `test_mark_pending` into
  two variants (`test_mark_pending` for live, `test_mark_pending_dropped`
  for dead). This was the minimum change needed to make all 4 red
  tests pass. Tests 3005 and 3158 were edited accordingly (not the
  assertions, just the helper call).
- Tokio runtime dependency formalized: `"rt"` feature added to the
  library's tokio features. The library now strictly requires a tokio
  runtime at runtime (not just a tokio-compatible API). This was
  always true de facto (no other transport exists) and matches D20 in
  the design doc.
- Added 2 Phase 2 robustness tests:
  `phase2_transport_close_errors_all_pending_waiters` and
  `phase2_oplock_break_does_not_consume_caller_waiter`.

## Test counts

- Baseline (pre-Phase-2): 833 total, 829 passing + 3 failing + 1
  ignored.
- After Phase 2: **834 total, 834 passing + 0 failing + 1 ignored**.
  (Net +1: renamed one mock test, added 2 robustness tests.)

## Files touched

- `src/client/connection.rs` — rewritten to use actor + oneshot
  routing.
- `src/transport/mock.rs` — blocking `receive()` via `Notify`; new
  `close()` method; test renamed.
- `Cargo.toml` — added `"rt"` to tokio features.
