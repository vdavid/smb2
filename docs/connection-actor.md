# Connection actor: decisions and why

`Connection` routes every response to its caller by `MessageId`: one receiver task per connection owns the transport's
read half and hands each sub-frame to the `oneshot::Sender` its request registered. How it works today (writer task,
waiters, socket lifetime) lives in `crates/smb2/src/client/CLAUDE.md` § Connection internals. This doc keeps what that
section doesn't: the decisions behind the shape, the ones code cites by ID, and what was deliberately left out.

## Why routing by `MessageId`

A caller that drops its future mid-request must not corrupt the next caller's response. Consumers drop futures all the
time (`JoinHandle::abort()`, a losing `select!` arm), and a demux that only knows "which ids are pending" can't tell
"still waiting" from "the caller is gone". That is what Cmdr hit when a listing task was aborted: the aborted task's
CREATE response arrived first and was handed to the next task, which parsed it as its own and read a garbage `FileId`,
or asked for a QUERY_DIRECTORY response and got a CREATE one. A per-request `oneshot` closes it by construction: the
dropped caller's `Receiver` goes with it, the late frame fails to send, and it's discarded.

## Decisions

IDs are stable: code cites them. The `D` series set up the actor, the `E` series its public, concurrent API.

- **D11, cancellation by drop.** Dropping a caller's future drops its `oneshot::Receiver`; the late frame is discarded
  on arrival, its credit grant is still banked, and it counts as `responses_late_after_drop`. No API, it's ordinary
  Rust drop. Pinned by `dropped_execute_future_does_not_affect_others`.
- **D12, one dead state.** A transport failure fans `Err(Disconnected)` to every pending waiter and marks the
  connection disconnected under the waiters lock, so there are no half-dead connections and no waiter registered after
  the drain (the register-waiter check and the insert share that lock).
- **D13, minimum blast radius for session expiry.** `STATUS_NETWORK_SESSION_EXPIRED` goes to the matched waiter only;
  other waiters meet the same status on their own responses, or succeed.
- **D14, interim responses stay inside.** On `STATUS_PENDING` the waiter stays registered and the interim frame is not
  forwarded, so a long poll looks like any other request to its caller.
- **E2, `execute` returns a `Frame`** (`header`, `body`, `raw`): what callers actually consume.
- **E3, `execute_compound` returns `Result<Vec<Result<Frame>>>`.** The outer `Result` says whether the compound made it
  onto the wire. The inner one is per sub-op, because compound partial failure is protocol-normal: CREATE succeeds, READ
  fails, and the caller needs the CREATE's `FileId` to send a standalone CLOSE. A sub-op's NTSTATUS rides in
  `frame.header.status`; the inner `Err` is for waiter-level failures (session expired, bad signature, connection lost).
- **E4, `CompoundOp` is a typed struct** (`command`, `body`, `tree_id`, `credit_charge`), passed as a slice.
- **E5, handshake mutators keep `&mut self`** (`install_signing`, `install_encryption`, `set_session_id`, and friends, all crate-private; `encrypt_for_share` is a tree-connect step, not a handshake one, and takes `&self`). They run once, on
  one task, during session setup; flipping them to `&self` buys nothing. Flip one only when a real need to call it from
  any clone shows up.
- **E6, tear down on an unrecoverable frame.** A decrypt failure, a decompress failure, or a malformed sub-frame header
  fans `Err(Disconnected)` to every waiter and ends the receiver. The `MessageId` can't be recovered from a frame that
  can't be read, so log-and-continue left the matching waiter hanging forever, and the stream is out of sync after one
  bad frame anyway. A transient bit flip costs a reconnect, which beats a hang. Pinned by
  `phase3_decrypt_failure_errors_waiter_not_hangs`; counted as `decrypt_failures`, `decompress_failures`,
  `malformed_frames`.
- **E8, the last clone ends it.** `Connection` is `Clone` over one `Arc<Inner>`, and only `Inner::drop` stops the
  background tasks. Socket consequences: `client/CLAUDE.md` § Socket lifetime.
- **E9, no automatic CANCEL on drop.** Drop is already correct; a proactive CANCEL would only save server work on long
  operations, at the price of an async drop path. A caller who wants it sends `Connection::send_cancel` itself, with the
  `AsyncId` from `outstanding_requests()`.
- **E10, transfer pacing lives above the actor.** A pipelined transfer is many `execute_with_credits` calls in flight
  at once (`FuturesUnordered` in `tree.rs`, `client/write_pipe.rs` for uploads), paced by `client/read_ahead.rs`. The
  actor only routes; it knows nothing about files.

## Deliberately out of scope

- **A connection pool.** One `Connection` is one SMB session, and a multi-connection pool belongs to the application:
  file handles are per session, so a transparent pool only works for self-contained open-read-close operations; work
  stealing drops the "op 2 runs after op 1" ordering; pool size and eagerness depend on the workload; and each session
  costs the server memory and auth state, which is impolite for a library to spend eagerly. A consumer that wants more
  parallelism opens more `SmbClient`s; for Cmdr that's its `SmbVolume`.
- **SMB3 multichannel.** Diminishing returns for home and prosumer servers.

## Evidence

`bench_100_tiny_files_seq_vs_parallel` (`crates/smb2/tests/integration.rs`) against the QNAP over Wi-Fi 6E, 2026-04:
100 tiny files took 593 ms sequentially on one connection (169 files/s) and 79 ms across 10 connections (1,264 files/s),
7.5× faster. One connection with many concurrent `execute` calls captures only part of that, since the QNAP appears to
serialize work within a session; the rest needs more sessions, which is why the pool question matters at all.
