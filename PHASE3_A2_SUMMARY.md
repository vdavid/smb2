# Phase 3 A.2 — Additive `execute` / `execute_compound` API

Branch: `phase3-a2-execute`. Stage commits off `main`:

- `1d1b20e` — Promote `RoutedFrame` to public `Frame`
- `218e885` — Add public `CompoundOp<'a>`
- `12e22d8` — Add `execute` / `execute_with_credits` / `execute_compound`
- `50d19e0` — Tests for `execute` / `execute_compound`
- `c8e14e5` — CI: mark Phase 3 red test `#[ignore]` (cherry-picked from `main`)
- `681502c` — Chore: untrack worktree submodule refs (cherry-picked from `main`)
- `a61257d` — `cargo fmt`

Three files touched: `src/client/connection.rs` (+721 lines), `src/client/mod.rs` (+1/-1), `src/lib.rs` (+1/-1).

## What changed

1. **`Frame` is now the public response type.** Previously `RoutedFrame` was a pub(crate) internal. Renamed and exported from `src/lib.rs` so `execute`'s return type is usable from outside the crate.

2. **`CompoundOp<'a>`** — a new public borrow struct describing one sub-op of a compound request: `command`, `body: &dyn Pack`, `tree_id`, `credit_charge`. `new(command, body, tree_id)` defaults `credit_charge = CreditCharge(1)`; callers doing large READ/WRITE build with `new_with_credits`.

3. **Three new public methods on `Connection`** (all `&self`):

   ```rust
   pub async fn execute(&self, cmd, body, tree_id) -> Result<Frame>;
   pub async fn execute_with_credits(&self, cmd, body, tree_id, charge) -> Result<Frame>;
   pub async fn execute_compound(&self, ops: &[CompoundOp<'_>]) -> Result<Vec<Result<Frame>>>;
   ```

   Implementation pattern matches the design doc (E1-E4):
   - Allocate `MessageId`(s) via `allocate_msg_id`.
   - Build header(s), apply session/tree/DFS/sign/encrypt flags.
   - **Register waiter(s) BEFORE sending.** `register_waiter` atomically rechecks `disconnected` under the waiters lock, so a receiver-task teardown between the pre-send disconnected check and the insert returns `Err(Disconnected)` rather than leaving a ghost `Sender`.
   - Sign/encrypt/compress the frame as dictated by connection state. On any failure, unregister the waiter(s) before returning.
   - `sender.send(bytes).await`. On error, unregister and return.
   - `await_frame(rx).await` (or one await per sub-op for compound).

   `execute_compound` wires up `NextCommand` offsets, sets `RELATED_OPERATIONS` on sub-ops after the first, 8-byte-aligns all but the last sub-request, signs each sub-request individually when not encrypted. Outer `Result` is `Err` only when the compound didn't land on the wire; inner `Vec<Result<Frame>>` holds one entry per sub-op — non-success statuses come back as `Ok(frame)` with `frame.header.status` set (protocol-normal partial failure).

4. **Five new unit tests** (see `Gotcha` below on the test-harness ordering):

   - `execute_returns_correct_frame_for_sent_request` — single round trip.
   - `concurrent_execute_on_one_connection_all_succeed` — 20 concurrent `execute`s on clones, each task gets its own response via per-`MessageId` routing.
   - `dropped_execute_future_does_not_affect_others` — abort 2 of 5 in-flight tasks, the remaining 3 still resolve; the 2 discarded frames are silently dropped by the receiver task.
   - `execute_compound_partial_failure_routes_correctly` — 3-op compound with middle-op `OBJECT_NAME_NOT_FOUND` returns `Ok(vec![Ok, Ok(err-status), Ok])`.
   - `execute_on_clone_works_after_original_dropped` — verifies that `Arc<Inner>` keeps the receiver task alive when the original `Connection` is dropped.

## Gotcha/Why — test-harness ordering

All five tests queue responses AFTER the spawned test task has sent its request. Pre-queuing responses before spawning races the receiver task: on the `multi_thread` runtime the receiver can read a queued frame before its `MessageId` has a registered waiter, and the orphan filter (enabled in production mode) silently drops it → task hangs forever on the `oneshot`.

Pattern:

```rust
let conn = Connection::from_transport(...);  // receiver task starts here

let handle = tokio::spawn(async move { conn.execute(...).await });

// Wait for the send to land, then queue the response.
while mock.sent_count() < 1 { tokio::time::sleep(10ms).await; }
mock.queue_response(build_echo_response_with_msg_id(MessageId(0)));

let frame = handle.await.unwrap().unwrap();
```

This mirrors production reality: responses arrive AFTER the client sent them. `execute` registers the waiter BEFORE `sender.send().await`, so `sent_count >= N` implies all N waiters are live.

All five tests use `#[tokio::test(flavor = "multi_thread")]` to actually stress the race (`current_thread` serializes the receiver task and the test task, hiding any real concurrency bugs).

## Green-light checks

Run from the worktree root:

- `cargo test --lib` → 841 passed, 0 failed, 2 ignored (the 2 ignored are the unrelated `negotiate_via_tcp_transport` + the Phase 3 A.4 red test pinned via `c4abb1f`).
- `cargo fmt --check` → clean.
- `cargo clippy --all-targets --all-features -- -D warnings` → clean.
- `cargo doc --no-deps` → builds.

## What's next

Stage A.3 migrates `tree.rs` callers (CREATE / READ / WRITE / IOCTL / etc.) off the legacy `send_request` + `receive_response` path onto `execute`. A.4 closes the silent-discard hole so the A.4 red test (`phase3_decrypt_failure_errors_waiter_not_hangs`) can be un-ignored. A.2 itself does NOT migrate any caller — it's purely additive, so `main` behavior is unchanged until A.3.
