# Phase 3 A.1 — `Connection: Clone` flip

Branch: `phase3-a1-connection-clone`. Two commits, 1 file changed
(`src/client/connection.rs`).

## What changed

1. **All connection-wide state moved into `Arc<Inner>`.** Before A.1,
   only the waiters map, credits, `next_message_id`, crypto state, and
   a couple of flags lived on `Inner`. The outer `Connection` held
   `sender`, `receiver_task`, `params`, `server_name`, `estimated_rtt`,
   `compression_enabled/requested`, `preauth_hasher`, and `dfs_trees`.
   None of those could be shared across clones as-is. After A.1 they
   all live behind `Arc<Inner>` with the appropriate primitive:
   - `sender: Arc<dyn TransportSend>` (already `&self`-callable)
   - `receiver_task: StdMutex<Option<JoinHandle<()>>>` (abort moved to
     `Inner::drop` so it fires only when the LAST clone drops)
   - `params: OnceLock<NegotiatedParams>` (set once at negotiate)
   - `server_name: String` (immutable post-construction)
   - `estimated_rtt: StdMutex<Option<Duration>>`
   - `compression_enabled/compression_requested: AtomicBool`
   - `preauth_hasher: StdMutex<PreauthHasher>`
   - `dfs_trees: StdMutex<HashSet<TreeId>>`

2. **Manual `Clone` impl for `Connection`** (Option A from the task's
   spec). Each clone gets a fresh, empty `pending_fifo`,
   `orphan_fallback_rx`, and `orphan_fallback_buffer`. Reasoning: those
   fields hold per-caller bookkeeping (in-flight oneshot receivers,
   test-mode fallback channel). A clone is a new sender handle to the
   same actor, not a snapshot of the original's in-flight requests.
   `oneshot::Receiver` isn't `Clone` anyway.

3. **`Drop` for `Connection` removed; `Drop` for `Inner` added.** The
   receiver task is aborted when the last `Arc<Inner>` drops, not on
   the first `Connection` drop — required so clones outlive the
   original.

4. **Readers flip to `&self`: no-op.** All seven readers listed in the
   task spec (`credits`, `params`, `session_id`, `should_encrypt`,
   `server_name`, `compression_enabled`, plus `next_message_id` and
   `estimated_rtt`) already took `&self` in the pre-A.1 code. No
   `should_sign` method exists (boolean lives only inside `crypto`
   under the mutex). Nothing to flip.

5. **Two new unit tests:**
   - `connection_is_cloneable_and_clones_share_state` — mutate credits,
     session id, next_message_id via the test helpers; clone; verify
     the clone reads the same values. Mutate via clone; verify the
     original observes the change. Both handles' caller-local FIFOs
     start empty.
   - `connection_is_cloneable_clone_outlives_original` — clone, drop
     original, verify the clone still reads shared state and can drive
     the transport send path. Pins the `Arc<Inner>` lifetime guarantee.

## Deviations from the task spec

- **`preauth_hasher()` signature changed** from `&PreauthHasher` to
  owned `PreauthHasher`. Returning a reference through a lock guard
  isn't expressible without a wrapper type, and `PreauthHasher` is
  `Clone`. Callers in `session.rs` were already doing
  `conn.preauth_hasher().clone()` — now the `.clone()` is redundant
  but harmless and compiles unchanged. This is the only source-level
  API signature change in this PR.
- **`preauth_hasher_mut(&mut self) -> &mut PreauthHasher` removed;
  replaced with `with_preauth_hasher_mut(f: FnOnce(&mut _))`.** The
  old signature can't be kept when the field sits behind a `Mutex`.
  The method was defined but unused anywhere in the repo (verified via
  `grep -r` across both `smb2` and `cmdr`), so this is functionally
  dead-code removal. The new closure form is `#[doc(hidden)]` and
  reserved for crate-internal parity.

## Green-light criteria

- `cargo test --lib`: 836 passed + 1 failed + 1 ignored. The failing
  test is `phase3_decrypt_failure_errors_waiter_not_hangs` (the red
  test written in P3.0 for the silent-discard hole, which P3.4
  fixes). The two new Clone tests are in the 836 passing count
  (original baseline was 834).
- `cargo test --lib connection_is_cloneable`: both new tests pass.
- `just fmt-check`, `just clippy`, `just doc`, `just msrv`,
  `just audit`, `just deny` — all green individually.
- `just test-docker` — not run (Docker not started this session).
- `just check-all` as a single command exits non-zero because
  `just test` includes the known red test; expected per the task
  spec.

## Things to know for A.2

- The `sender` being `Arc<dyn TransportSend>` means concurrent callers
  can share the send path. `TransportSend::send` takes `&self`; the
  implementations (`TcpTransport`, `MockTransport`) serialize writes
  internally, so there's no new locking to add on the smb2 side for
  concurrent execute.
- `pending_fifo` remains per-caller. `execute()` should NOT use the
  FIFO — it should `register_waiter(msg_id)` directly and await the
  returned `oneshot::Receiver` itself, bypassing the FIFO entirely.
  That way concurrent `execute()` calls on one clone (or across
  clones) don't serialize through a shared FIFO.
- `set_orphan_filter_enabled(false)` and the whole orphan-fallback
  mechanism keep working for existing tests. A.3 removes them when
  the FIFO-based `send_request` / `receive_response` pair is deleted.
- `params()` returns `Option<&NegotiatedParams>` thanks to `OnceLock`;
  no clone needed on the hot path.
