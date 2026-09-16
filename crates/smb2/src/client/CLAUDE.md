# Client -- high-level SMB2 API

Entry point for most users. `SmbClient` wraps `Connection` + `Session` and provides convenience methods for file operations.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `SmbClient`, `ClientConfig`, `connect()` shorthand |
| `connection.rs` | `Connection` -- message sequencing, response deadline, signing, encryption, `execute` / `execute_compound` |
| `credits.rs` | `CreditPool` -- the connection-wide credit budget and the send-side gate |
| `session.rs` | `Session::setup()` -- NTLM auth, key derivation, signing/encryption activation |
| `tree.rs` | `Tree` -- share connection, file CRUD, compound and pipelined I/O |
| `stream.rs` | `FileDownload` / `FileReader` (random-access positioned reads) / `FileUpload` / `FileWriter` (owns `Connection` + `Arc<Tree>`, `'static`) / `open_file_writer` / `open_file_reader` -- streaming and positioned I/O |
| `watcher.rs` | `Watcher` -- directory change notifications via CHANGE_NOTIFY long-poll |
| `pipeline.rs` | `Pipeline` / `Op` / `OpResult` -- batched concurrent operations (the core feature) |
| `shares.rs` | Share enumeration via IPC$ + srvsvc RPC |
| `dfs.rs` | DFS referral IOCTL helper, `DfsResolver` with TTL-based referral cache |
| `copy.rs` | Server-side copy (`FSCTL_SRV_COPYCHUNK`): resume-key + copychunk primitives, batched range/whole-file convenience, `ResumeKey` / `CopyChunk` / `ServerSideCopyLimits` public types |
| `durable.rs` | Durable handles: `open_file_durable` / `reclaim_durable_handle`, `DurableHandle`, `FileIdentity`, and the two-proof rule that makes a resume safe |

## Layering

```
SmbClient  (owns Connection + Session, stores credentials for reconnect)
  Connection  (TCP transport, credits, message IDs, signing, encryption)
    Session   (NTLM auth, key derivation -- setup mutates Connection)
      Tree    (share-level ops, borrows &mut Connection for each call)
  extra_connections  (HashMap<String, ConnectionEntry> for DFS cross-server)
  dfs_resolver       (DfsResolver with TTL-based referral cache)
```

All `Tree` methods take `&mut Connection` as a parameter. `SmbClient` convenience methods use `connection_for_tree(tree)` to route through the correct connection (primary or DFS extra connection) based on the tree's `server` field.

## Connection and credits

Full model, rationale, and the incident behind it: `credits.rs` module docs.

- **Credits are reserved on send, never on receipt.** `CreditPool` (`credits.rs`) is a `Semaphore`, one permit per unspent credit; `Inner::reserve_credits` takes the charge before the bytes go out, and only a `CreditResponse` grant puts permits back. Accounting on the response instead makes every in-flight request invisible, which is how concurrent streams over one connection out-spend the server's window and get themselves silently cut off.
- **NEGOTIATE is exempt from the window, never funded by it** (MS-SMB2 § 3.2.5.1.1). A fresh or reset pool holds ZERO permits and NEGOTIATE takes a `CreditReservation::exempt()`. ❌ Don't seed a permit for it: a permit is fungible, so anything racing the handshake spends it instead and sends a frame the server funded nothing for. Servers answer that by silently discarding it, so the client waits out a full response deadline (up to 180 s with the ECHO extension, since the connection itself is fine) for an answer that was never coming.
- **The budget is per connection**, on the `Arc<Inner>` every clone shares. ❌ Don't add a per-stream credit check: `conn.credits()` is a gauge, not a gate, and second-guessing the pool can only under-send. The pipelined loops queue against `MAX_PIPELINE_WINDOW` alone for exactly this reason.
- **Outstanding WRITE payload is bounded connection-wide** by a second `Semaphore` alongside the credit pool, `DEFAULT_WRITE_BUDGET_BYTES` (32 MiB) worth, moved by the public `Connection::set_write_budget`. `MAX_PIPELINE_WINDOW` bounds ONE stream, so N concurrent uploads multiply it: ten files at a 1 MiB `MaxWriteSize` reached 320 MiB queued in-process, ~48 s of latency on a 6.7 MB/s link. All three pipelined write paths take it: `FileWriter`, `Tree::write_file_pipelined`, `Tree::write_file_streamed`. The permit rides INSIDE the in-flight WRITE future, so drain, abort, cancel, and drop all return it for free. ❌ Never hold it on the writer.
- **❌ Never await the write budget while holding a permit you aren't polling** -- the one way to deadlock it. Go through `reserve_write_budget_or_drain`, which is where that ordering lives: take budget only if free, otherwise drain one of your OWN responses, and wait only when you hold nothing. ❌ Don't hand-roll a second copy of it.
- Budget granule is 64 KiB, so `set_write_budget` rounds up and floors at one. A frame bigger than the whole budget is clamped to it (`Connection::clamped_units`) rather than refused: `acquire_many` for more permits than the semaphore will ever hold waits forever. Growing is immediate; shrinking takes back only permits that are FREE, so `Inner::settle_write_budget` pays the rest down as frames complete, and every reserve calls it first.
- Multi-credit requests (reads/writes > 64 KB) charge `ceil(payload_size / 65536)` credits and use that many consecutive `MessageId` values. Gaps in `MessageId` sequences cause the server to drop the connection.
- **A read charges for what it ASKS for, not for what the file weighs.** The charge follows the *expected response* size (MS-SMB2 § 3.2.4.1.2), and `execute_compound` reserves the sum of the chain. `read_file_compound` knows nothing about the file, so it asks for a whole `MaxReadSize`: 130 credits on a server granting 8 MiB (128 for the READ, 1 each for CREATE and CLOSE), which fits three concurrent reads in the 512-credit window however small the files are. The rest park in `reserve_credits`, and a caller that launched ten looks stalled. Pass a size you already have (a directory scan) to `Tree::read_file_compound_sized`, and size the batch with `Connection::credit_capacity_for(bytes)` rather than guessing. `credits::charge_for_payload` is the one formula.
- **❌ The compound read's truncation guard compares `end_of_file` against what the READ requested, never against `MaxReadSize`.** A file that grew past the caller's `expected_size` between the scan and the read comes back exactly `requested` bytes, which is indistinguishable from a complete read of a smaller file. `Error::FileTooLargeForSingleRead { size, requested }` carries the server's authoritative size, so the caller can retry with it.
- A short send parks until a grant arrives, bounded so it can't become a starvation hang: nothing outstanding to fund the wait → immediate `Error::CreditStarvation`; connection death → `CreditPool::close` wakes every waiter; otherwise the 30 s `set_credit_wait_timeout` deadline.
- Every request asks for its own charge back plus enough to reach a 512-credit target. ❌ Don't flatten this to a constant: asking for less than the charge lets the window shrink to nothing and serializes every transfer.
- `STATUS_PENDING` interim responses carry credits but the request isn't done -- keep waiting.

## The send path: a writer task, and why

`Connection` never lets a caller touch the socket. `send_and_count` hands a **whole frame** to an `mpsc` queue and waits
for the writer task's ack; `writer_loop` owns the transport's write half and is the only thing that writes.

- **Bounded.** Each frame gets `set_send_timeout` (20 s default) to reach the socket, then `Error::SendTimeout` and the
  connection is torn down. Nothing else in this crate bounds this: the response deadline and the credit deadline both
  start once the server has been asked, so a socket that stops accepting writes is invisible to them. That is exactly
  how a 2026-08-01 Cmdr wedge sat frozen for 40 minutes with ~700 requests "in flight" and zero bytes on the wire.
- **Torn down, not retried, on failure.** A write abandoned partway has already put bytes on the wire, so the stream
  can't be resynced. A frame rejected *before* any byte went out (oversized) is the caller's problem alone and leaves
  the connection alive.
- **Whole frames only.** `TcpTransport::send` writes a 4-byte length header and then the body. A caller cancelled
  between the two used to leave a header with no body on the wire and every later frame landed inside it — and
  consumers cancel constantly (a user aborting a copy). Queuing the frame as one message makes that unreachable.
- ❌ **Don't add a second writer, or let a caller call `TransportSend::send` directly.** Frames would interleave.
- The queue is bounded (`WRITE_QUEUE_DEPTH`); `send_queue_depth()` is the gauge. Persistently non-zero while
  `wire_bytes_sent` stands still means the send side is stuck, not the server.
- ❌ **The writer tallies, it doesn't log per frame.** `SendTally::record` counts every frame that reached the socket
  and how bad the worst queue time and worst write time were; the sweeper drains it and says so once. `SLOW_SEND_REPORT`
  (5 s) is a threshold on the frame, never a gate on a log line: every frame in a bulk copy over a slow link crosses it,
  so per-frame it emitted six or seven `WARN`s a second for a sixteen-minute transfer (2026-08-26).

## In-flight bookkeeping: registered vs sent

`register_waiter` returns a `WaiterGuard` that removes its map entry on `Drop`, so an aborted caller can't leak one.
Before that, only the response deadline removed a waiter, which inflated the diagnostic and made `reserve_credits`'
"is anything outstanding?" starvation check permanently true.

- `Waiter` carries `registered_at` **and** `sent_at`. `OutstandingRequest::sent_age` is `None` while a request is still
  queued for the transport. ❌ Never read a large `age` as "the server didn't answer" without checking `sent_age`
  first — that conflation is what sent three investigations after an innocent server.
- The stale-request warning says which case it is. `classify_outstanding` owns the split into three populations
  (`unanswered` / `queued` / `parked`) and `sweep_report` turns them, plus the send-side reading, into log records, so both the split and the VOLUME
  can be tested apart from the wording.
- ❌ **One line per sweep for the whole send side, never one per frame.** Frames waiting for the socket collapse into a
  single record naming the count, the oldest one's age, the command mix, the queue depth, and what the writer actually
  got out over the interval (frames, rate, how many were slow, worst queue time + worst write time); the frame-by-frame
  detail is at `TRACE`. An idle-and-healthy connection says nothing at all. Copying 282 × 66 MB to a NAS over 6.7 MB/s Wi-Fi keeps ~320 one-MiB frames queued at all times,
  and a line each made 4,487 of the 4,744 lines in a user's diagnostic bundle this one message — a bundle covering
  2 minutes 30 seconds, with everything else already rotated out (2026-08-26).
- ❌ **A deep send queue is only a `WARN` when it isn't draining.** `Inner::observe_send_side` tracks when a whole
  frame last reached the socket. Recently enough means the link is simply slower than the writers filling it, the
  transfer is working, and that gets `INFO`. Silence past `stall_tolerance` means the writer task or the socket is the
  problem, and that keeps `WARN`. ❌ Don't demote the stalled half to match, and ❌ don't call `observe_send_side` from
  anywhere but the sweeper: it consumes the previous reading, and a second caller would leave the sweeper measuring
  silence from its own last look. `INFO` rather than `DEBUG` because consumers ship `INFO` in bundles, and a bundle that
  can't show the link was the bottleneck sends the next investigation after the server again.
- ❌ **`stall_tolerance` is the send deadline, never one sweep.** `wire_bytes_sent` ticks only on a WHOLE frame, so
  between completions it stands still by construction and the gap between them is the per-frame write time. Judging a
  single sweep would call any link slower than one frame per `STALE_WAITER_SWEEP` a wedge: ~105 KB/s at a 1 MiB
  `MaxWriteSize`, ~840 KB/s at the 8 MiB one Windows and several NAS boxes negotiate, while `SEND_TIMEOUT` is sized for
  50 KB/s and 400 KB/s. That whole band is ordinary Wi-Fi. Deferring to `send_timeout` closes it by construction: a link
  the send path tolerates is never called stalled, and one it doesn't tears itself down with `Error::SendTimeout`
  anyway. `send_timeout: None` falls back to the default rather than going quiet -- that consumer removed the teardown,
  not the diagnosis, and `set_stale_request_warning(None)` is the knob for silence.
- The send side's clocks restart on revival (`install_transport`): a fresh socket owes nothing, and carrying the dead
  one's silence over would let the first sweep call the new connection wedged.
- ❌ **Long polls are never warned about.** Every line the sweeper writes means "this should have come back by now", which for a CHANGE_NOTIFY is false by construction, so warning about one is the sweeper contradicting the deadline. At the sweeper's cadence it also buries the genuine lines: a file manager watching two panes logged 5,911 `WARN`s in six hours about requests nothing was ever going to answer (2026-08-03). They stay observable at `TRACE` every sweep, and named in full at `WARN` alongside any REAL stale request (an unanswered request, or a send queue that has stopped draining), because a wedge investigation wants the whole in-flight picture.
- Dropping a guard records the id in a bounded ring so a late response still counts as `responses_late_after_drop`
  rather than `responses_stray`; without it, routine cancellation would drown the "we got a frame we never asked for"
  signal.

## Response deadline

`Connection::await_response` gives up with `Error::Timeout` after 30 s of silence, so a server that stops answering on a live socket can't hang a caller. Tune or disable with `set_response_timeout`.

- The clock measures **silence, not elapsed time**: `Waiter.last_activity` is refreshed on every interim `STATUS_PENDING` and by `mark_sent`, so an acknowledged long operation is never cut short and a frame that crawled onto a slow link still gets the full budget afterwards. ❌ Don't remove either refresh to "simplify" the deadline — both are what make 30 s safe, and each has a test that fails without it.
- **A request on a provably-alive connection gets `ALIVE_DEADLINE_FACTOR` × the budget** (6, so 3 minutes at the defaults) before being abandoned. See § Liveness below for what "provably" means; the counter is `response_deadline_extensions`.
- **Running out of budget produces one of two errors, and the difference is the connection, not the request.** `Inner::unresponsive_for()` (`Some` only when the keepalive is armed AND the wire has been quiet past the liveness window) turns `Error::Timeout` into `Error::ServerUnresponsive` and tears the connection down via `declare_unresponsive`, so every other waiter is told at once and `reconnect_if_needed` has something to revive. ❌ Read it BEFORE `remove_waiter`: `quiet_for` measures from the oldest outstanding request, so a lone waiter deregistering first takes the evidence with it.
- **The teardown costs a request its whole deadline first, and that is the point.** The keepalive on its own must never end anything (§ Liveness); pairing "this request is out of budget" with "the connection said nothing at all" is what makes the verdict safe from a NAS that drops probes while it writes.
- CHANGE_NOTIFY is exempt from the *request's* deadline (`is_long_poll`) — it waits for an event that may never come. Add any new wait-for-an-event command there. Two things stand in for the deadline, and neither substitutes for the other: the connection-silence bound in `await_long_poll` (the same `unresponsive_for` verdict on `quiet_for`'s clock, held to the response-deadline budget) ends a watch on a DEAD LINK, and the refresh cycle below retires a subscription a live link cannot speak for. Without the first a `Watcher` on a dead session waits forever, and with the keepalive off it does exactly that, deliberately.
- ❌ **Anything holding a `WaiterGuard` must finish through `await_response`, never a bare `guard.recv()`.** `recv()` is an unbounded `oneshot` await — it walks past the deadline, the alive-extension, and the long-poll bound alike. `Watcher::next_events` did exactly that, so the one production consumer of the long-poll bound never reached it: against a real Samba with `smbd` suspended, 90.3 s of connection-wide silence and 17 consecutive unanswered probes left the watcher waiting (2026-08-02). Routed through `await_response` it is now told at 30.1 s, measured on the same rig.
- Timing out removes the waiter, so an abandoned request leaves no entry in the routing map.
- **These are `Connection` setters, not `ClientConfig` fields**, like every other tunable here (credit wait, stale-request warning, keepalive). `ClientConfig` has all-public fields and no `Default`, so adding one breaks every consumer's struct literal — a minor bump under this crate's pre-1.0 SemVer, spent to save a setter call.
- **The defaults are a set, not independent numbers**: slow-send report (5 s) < send deadline (20 s) < response deadline (30 s); the stale-request warning (15 s) plus one sweep (10 s) fits inside the response deadline so a wedge is always named in the log before its waiter disappears; and a probe goes out and gets its answer (5 s + a tick), and liveness stops looking proven (15 s), both well inside the response deadline. `the_default_deadlines_are_layered` fails if a tuning pass breaks any of it. The fault-injection harness scales the same ratios down — ❌ don't set its `BASE_DEADLINE` below `LIVENESS_WINDOW_PROBES` × `KEEPALIVE`, or requests there expire before the connection can be judged and the tests stop describing the shipping shape.

## The long-poll refresh cycle

Full rationale in `connection.rs` on `LONG_POLL_REFRESH`.

**A subscription is retired and re-issued every 10 minutes, because nothing can tell a dead one from a quiet one.** A CHANGE_NOTIFY the server has silently forgotten and one watching a directory nobody has touched produce the identical observation: nothing at all. Every liveness verdict this crate reaches is about the CONNECTION, so a server answering everything except one dropped subscription reads as perfectly healthy — and a QNAP TS-464 did exactly that for 6,186 s while `fs_info` on the same connection round-tripped in 4 ms and every ECHO probe was answered (2026-08-03). Re-issuing on a cycle heals that with no verdict to get wrong.

- ❌ **It is not a detector and can't be made into one.** Don't add a "this watch looks dead" heuristic on top: the healthy case *is* silence, so any such rule ends healthy watches. `long_poll_refreshes` counts handovers, never faults.
- **`Connection::set_long_poll_refresh(Option<Duration>)`** tunes it; `None` keeps one subscription forever, which is what a consumer re-creating its own watchers wants. Per connection, like every other tunable here.
- **Both of a `Watcher`'s subscriptions are replaced, and the replacement goes out first.** The pipelined watcher's whole guarantee is that the server is never without an outstanding request; a refresh that cancelled before it re-issued would open the exact loss window that design exists to close. ❌ Don't reorder `Watcher::refresh`.
- **The CANCEL must carry the `AsyncId`** the server assigned in its interim STATUS_PENDING (MS-SMB2 § 3.2.4.24); one sent against the `MessageId` alone matches nothing and the server keeps the subscription, so every cycle would leave another one registered. `Waiter.async_id` records it, `OutstandingRequest::async_id` exposes it, and `send_cancel` takes it.
- **A CANCEL is stamped with the generation its `MessageId` came from**, and `send_cancel` drops one that doesn't match the connection's current generation, or that would go out with no session id. A `MessageId` means nothing outside the session that issued it: a revival resets the counter to zero, so a stale cancel names an unrelated live request or nothing at all. ❌ Don't read `generation()` at cancel time — a revival in between has already moved it, which is the case the stamp exists to catch. `WaiterGuard::generation` and `LongPollOutcome::RefreshDue.generation` carry it from registration. The no-session half is separate and load-bearing: `revivals` ticks only after a WHOLE revival succeeds, so the generation still matches through NEGOTIATE and SESSION_SETUP, when the server's credit window is zero wide and an over-spent frame is discarded in silence.
- **The clock is `waiter_sent_age`, not `last_activity`.** A long poll gets exactly one interim PENDING, right at the start; measuring from something that restarts there would silently measure the same thing under a different name.
- **The refresh is off on the `execute` path** (`await_response` passes `None`). Retiring a subscription is only useful to whoever can issue its replacement, and an `execute` caller has handed over the only handle to it. `Watcher` owns that loop and uses `await_long_poll_refreshable`.
- It is the slowest clock on a connection by design and `the_default_deadlines_are_layered` pins that: everything faster than it is about detecting a death, and this detects nothing.

## Liveness: the ECHO keepalive

Full rationale in `connection.rs` on `KEEPALIVE_AFTER` and `Connection::echo_probe`.

**The keepalive tells the response deadline whether the server is alive; an alive server gets more time.** That is the whole feature, and it is on by default because it can only ever hand time out. A deadline alone cannot tell "slow" from "dead", so it has to be sized for the slowest healthy case and is therefore a poor detector of the dead one. SMB2 ECHO touches no share, handle, or disk, so an answer means the server is processing requests — which is what lets the deadline be both short and safe.

- **`last_frame_at` is the liveness clock**, fed by EVERY received frame (responses, interim PENDING, oplock breaks, even strays), because all of them prove the same thing. `None` until the server has actually spoken: a connection that has never said anything has proven nothing, and ❌ the extension must never be granted on an assumption.
- **The keepalive probes only when `quiet_for()` ≥ the threshold** (5 s, `set_keepalive`). `quiet_for` measures from the LATER of "the server last spoke" and "the oldest unanswered request went out" — a server can't be silent about a question it hasn't been asked, and a connection that never spoke is quiet from the first ask. `None` (nothing on the wire) means no probe: no work to protect. So a busy connection never probes at all, and an idle one doesn't either.
- ❌ **A missed probe ends nothing.** It leaves the liveness clock stale, which withholds the deadline extension, and that is its entire consequence. The QNAP TS-464 drops probes precisely while it is writing (measured 2026-08-02: two answered, one dropped, under write load), so a keepalive that could declare death would tear down healthy connections exactly during a transfer. `keepalive_loop`'s only action is `ProbeOutcome::Broken → return`; everything a caller can feel is decided in `await_response`.
- **`Error::ServerUnresponsive` is the response deadline's verdict, not the keepalive's**, and `fan_error_to_waiters` preserves it rather than collapsing it to `Disconnected` (the two answer different questions for a consumer deciding between reconnect and retry-the-file). See § Response deadline.
- **A probe that can't be sent is `Skipped`, never a failure.** ❌ Don't make it wait for credits: the window is fully spent exactly when the pipeline is deepest, so counting "couldn't ask" as "didn't answer" would put the busiest healthy transfers first in line for every harsh conclusion. It takes its credit with `try_reserve` (via `dispatch_reserved`) or skips.
- **Getting the probe onto the wire is the send deadline's business**, not the keepalive's, so `echo_probe` puts no timeout around the dispatch. A stuck socket already has an owner that tears the connection down; blaming the server for it is the misdiagnosis `sent_at` exists to prevent.
- ❌ **Don't coarsen the loop's tick while idle.** The sleep is chosen before the check, so a long idle interval delays the round that would notice a `set_keepalive` change too. That cost 5 s of setter lag for one timer per second.
- **Every clock here measures wall time, so it measures THIS PROCESS too**, and `forgive_scheduling_stall` is what keeps that from becoming a verdict. A system sleep, an App Nap, or a machine starved by a parallel build stops the loops while `Instant` keeps running, and the wire then reads as silent for minutes because nobody was listening. The witness is cadence: every loop here wakes on a `keepalive_tick` or faster, so a gap since the last one that exceeds the probe threshold on top of the tick is us, not the server. Forgiving it shifts `last_frame_at` and every waiter's timestamps forward by the gap ("nothing aged while we were gone"), logs one `info`, and counts `scheduling_stalls`.
- ❌ **Don't leave the stall check to the keepalive task alone.** Every wait loop wakes from the same stall at the same instant, so one that read its clock before the keepalive got scheduled would declare the death this prevents. `await_response` and `await_long_poll` both call it before reading any clock; it's idempotent, so whoever arrives first does the correction.
- ⚠️ **It forgives, it never exonerates.** The clocks restart, the probes restart with them, and a genuinely dead server is declared dead one budget later. Suppressing the verdict outright would trade a false death for a permanent hang.

## Paths and the names SMB2 won't carry

Table, rationale, and the empirical evidence: `src/name.rs` module docs. What matters at this layer:

- **`Tree::format_path` is the one outbound encode point**, and every method taking a caller path calls it at its own boundary. ❌ Nothing may hand an already-formatted path to another method: a second pass turns the wire path's `\` separators into U+F026 name characters and prepends the DFS prefix twice. The four `open_*` helpers format their own argument, which is what makes double-encoding unreachable rather than merely avoided.
- **Decoding has to cover every site a name arrives at, or the two halves disagree** and a listing hands back names that nothing can open. Today: `parse_file_both_directory_info` (`tree.rs`, single components → `decode_name`) and `parse_notify_information` (`watcher.rs`, relative paths → `decode_path`). ❌ Adding an info class that carries a name means adding a decode there too.
- **What is deliberately NOT mapped**: share names, tree-connect paths, the `srvsvc` pipe name, DFS referral *server* and *share* fields, and the `*` search pattern in QUERY_DIRECTORY. Those aren't file names, and the wildcard is meant to be a wildcard.
- **`/` is the only separator a caller can write.** A `\` is a name character (U+F026). `Tree::rename`'s target, `SmbClient::upload`, `Tree::download`, and the DFS remaining-path all go through the same codec so one convention holds end to end.
- **DFS referral paths are encoded too** (`SmbClient::handle_dfs_redirect`), because the lookup and the CREATE that follows have to agree on where a component ends; the remaining path comes back through `decode_path` into caller form.

## Compound requests

`Connection::execute_compound(&[CompoundOp])` packs multiple operations into a single transport frame. Each sub-request is 8-byte aligned, linked via `NextCommand`. Subsequent related operations use `FileId::SENTINEL` (the server substitutes the real handle from the first CREATE).

- **Read compound**: CREATE + READ + CLOSE (3 ops, 1 round-trip). Default for `read_file`. `read_file_compound_sized` is the same chain asking only for a known size, which is what keeps the credit charge off the whole window (see Connection and credits).
- **Write compound**: CREATE + WRITE + FLUSH + CLOSE (4 ops, 1 round-trip). Default for `write_file`.
- **Delete compound**: CREATE (DELETE_ON_CLOSE) + CLOSE (2 ops, 1 round-trip). Default for `delete_file` / `delete_directory`.
- **Rename compound**: CREATE + SET_INFO + CLOSE (3 ops, 1 round-trip). Default for `rename`.
- **Stat compound**: CREATE + QUERY_INFO (basic) + QUERY_INFO (standard) + CLOSE (4 ops, 1 round-trip). Default for `stat`.
- **Fs-info compound**: CREATE + QUERY_INFO (FileFsFullSizeInformation) + CLOSE (3 ops, 1 round-trip). Default for `fs_info`.
- If CREATE succeeds but a later op fails, the client issues a standalone CLOSE to avoid leaking the handle.

### Receiving compound responses

`execute_compound` returns `Result<Vec<Result<Frame>>>`. The outer `Result` is "did the compound hit the wire"; the inner one is per-sub-op (waiter-level: session expired, signature verify, connection dropped mid-await). Sub-op protocol status codes (`STATUS_OBJECT_NAME_NOT_FOUND` etc.) ride in the inner frame's `header.status`, not the inner `Result`. Per MS-SMB2 3.3.4.1.3 the server MAY split the compound response across multiple transport frames (Samba, QNAP, Windows Server in some cases); the receiver task routes each sub-response by `MessageId` so the per-waiter `oneshot::Receiver`s resolve independently and `execute_compound` reassembles the result vector in submission order.

Most callers use a small `all_or_first_err` helper (see `tree.rs`) that propagates the first inner `Err` as the outer `Err` and hands back a `Vec<Frame>` indexable per sub-op. It takes the expected frame count and errors on a mismatch, because every caller indexes fixed positions (`responses[2]`) straight afterwards and a short chain would otherwise panic. Tolerating partial failure (for example, CREATE ok, READ fails → issue standalone CLOSE with the create's returned `FileId`) keeps the individual inner `Result`s.

## Batch operations

`delete_files`, `rename_files`, and `stat_files` are thin loops over `delete_file`, `rename`, and `stat`. Partial failures are independent — if 3 of 50 files fail, the other 47 still succeed. Each method returns `Vec<Result<T>>` in the same order as the input.

Decision/Why — these are convenience, not throughput. Each item costs one round trip and nothing overlaps, so they save the per-call setup and nothing else. Don't document them as pipelined: they were, once, and the docs outlived the behavior long enough to mislead a consumer into expecting overlap it never got. A caller that needs real overlap runs the single-item call on several connections concurrently, which is what `smb2-cli` does. They loop over the single-item methods on purpose, so a fix like the delete disposition change lands in one place.

## DFS (Distributed File System) resolution

**Two entry points, because a namespace root and a link fail in completely different places.** Design and evidence:
`docs/specs/dfs-namespace-root-plan.md` (roots) and `docs/specs/dfs-implementation-plan.md` (links).

**A namespace root, at `connect_share`.** `\\<domain>\<namespace>` is not a share on the server answering that name,
so its TreeConnect is refused with `STATUS_BAD_NETWORK_NAME` — required by MS-SMB2 § 3.3.5.7, so a contract rather than
a quirk — and `STATUS_PATH_NOT_COVERED` is never returned. `connect_share` checks the referral cache first
(§ 3.1.4.1 step 2), otherwise tree-connects, and on refusal asks for a ROOT referral and connects the target, following
an Interlink by re-resolving and stopping at `MAX_DFS_HOPS`.

**A link, at any convenience method.** `STATUS_PATH_NOT_COVERED` (mapped to `ErrorKind::DfsReferral`) sends
`handle_dfs_redirect` to resolve the referral, connect the target, update the caller's `&mut Tree` in place, and retry
with the resolved remaining path.

- ❌ **A failed referral must never replace the original error.** The overwhelmingly common cause of
  `STATUS_BAD_NETWORK_NAME` is a mistyped share name, and telling that person about DFS is worse than telling them
  nothing. A referral that fails, is empty, or names nothing connectable gives back the refusal. The one exception is
  `Error::DfsNoReachableTarget`: the namespace is real, and its storage is not reachable.
- **The trigger is gated on the negotiated `SMB2_GLOBAL_CAP_DFS`**, so a plain NAS pays zero extra round-trips when
  someone mistypes a share name.
- ❌ **Never gate on `ServerType`.** Samba answers a root referral with `0` and header flags `0x02` where Windows
  answers `1` and `0x03` (verified 2026-09-16). A client that requires the Windows values works against Windows and
  silently refuses every Samba namespace. `RootOrLink` is stored, and decides what happens next, never whether to
  accept the referral.
- **`Error::ShareRedirected` is not a DFS case.** MS-SMB2 § 2.2.2.2.2 reuses `STATUS_BAD_NETWORK_NAME` with an
  `SMB2_ERROR_ID_SHARE_REDIRECT` context for scale-out cluster redirection. `Tree::connect` separates it out, so the
  namespace trigger can't fire on it by construction.
- **`Tree::dfs_origin` keeps the caller's own name for a redirected tree.** Show `requested`, not `server`: a person
  who typed `\\lgs-net.com\aleu` should not be shown `\\fs01\aleu_dfs`, and macOS reports `SERVER_NAME lgs-net.com`
  for exactly this mount.
- **`TargetHint`** (§ 3.1.1): the target that worked is tried first next time, so a failover survives the next lookup
  instead of re-walking the dead target on every operation.
- **A root target is `\\server\share` and nothing more** (§ 2.2.1.6). A target carrying a path suffix is skipped, not
  silently truncated: a `Tree` cannot express one, and dropping it would open the wrong directory.

**Key design decisions:**
- Convenience methods take `&mut Tree` (not `&Tree`) so DFS can update the tree in-place
- `disconnect_share` stays as `&Tree` (no redirect on teardown)
- Streaming methods (`download`, `upload`) keep `&Tree` because they return handles that borrow the tree for their lifetime
- `watch` returns an *owned* `Watcher` (no lifetime); see the [Watcher pipelining](#watcher-pipelining) section
- Batch methods (`delete_files`, `rename_files`, `stat_files`) don't retry per-file; the caller should trigger one single-file operation first to resolve the redirect
- `dfs_enabled` flag on `ClientConfig` (default `true`) gates all DFS resolution
- Borrow checker requires inlining the connection lookup in `handle_dfs_redirect` and `root_referral` to avoid double `&mut self` borrows

## Watcher pipelining

`Watcher` keeps **one CHANGE_NOTIFY request pre-issued on the wire at all times** after the first `next_events()` call. The wire never sits idle between responses. This closes the response→re-arm loss window that strict servers (older Samba builds, NAS firmware) drop events through.

The wait itself ends one of three ways: the server answers, the connection goes silent (§ Response deadline — and see there for why a bare `recv()` here is a bug rather than a shortcut), or the subscription reaches its refresh age and `Watcher::refresh` replaces both requests (§ The long-poll refresh cycle). `next_events` is a loop for the third case: a refresh is a handover, not an answer, so the caller never sees it.

Shape: `Watcher` owns a cloned `Connection` (cheap `Arc::clone`, all clones multiplex over the same SMB session) and a `Tree` clone — no lifetime parameter, no borrow against the caller's `Connection`. `next_events` dispatches the next request via `Connection::dispatch` (a sibling to `execute` that returns once `transport.send().await` completes, handing back the `oneshot::Receiver` for the response) *before* awaiting the previous response. So when control returns to the consumer, the server already has somewhere to put new events.

Decision/Why — eager-send `dispatch` vs `tokio::spawn(conn.execute(...))`: the spawn-based approach defers the send to when the spawned task is polled, which under tokio's `current_thread` scheduler may not happen until the spawning task yields. That left a gap where the simulator-modeled strict server dropped events. `dispatch` awaits transport.send() inline, so the eager-send guarantee is "after `.await` returns, the request is on the wire" — independent of scheduler.

Pinned by `client::watcher::loss_window_tests::watcher_does_not_lose_events_between_consecutive_requests`: a strict-server simulator drops events that arrive with no outstanding request. Pre-fix: 5/5 gap events dropped. Post-fix: 0/5 dropped.

## Pipelined I/O

For large files, `read_file_pipelined` / `write_file_pipelined` issue multiple `execute_with_credits` calls concurrently on cloned connections via `futures_util::stream::FuturesUnordered`. The sliding window stays at 32 in-flight requests; credits are not checked here (the connection's pool gates every send). Chunk size is `min(512 KB, max_read_size)`. This is the core performance feature -- without it, throughput is ~10x worse.

`FileWriter` owns its `Connection` (cheap `Arc::clone`) and `Arc<Tree>` — no lifetime parameter, no borrow against the `SmbClient` that built it. It keeps an owned `FuturesUnordered<BoxedWriteFut>` field — `launch_wire_chunk` pushes a boxed `execute_with_credits` future, `drain_one` awaits `in_flight.next()`, and the public `write_chunk` / `finish` / `abort` drive that state machine.

FileWriter provides push-based pipelined writes. The consumer pushes chunks at their own pace via `write_chunk`, with the sliding window handling backpressure. Complement to FileDownload (read streaming). Build one via `open_file_writer(tree, conn, path)` (free function), `Tree::create_file_writer(&Arc<Self>, conn, path)`, or `SmbClient::create_file_writer(&self, tree, path)` — the last clones the client's primary connection internally for convenience.

## Random-access reads (`FileReader`)

`FileReader` (in `stream.rs`) holds ONE open handle and serves any number of *positioned* reads (`read_at(offset, len)`, the SMB analog of `pread`) before an explicit `close()`. It's the primitive for a consumer that parses a file's structure by jumping around it (zip central-directory browse + entry extract), where reopening per read would leak a handle each time. Build one via `open_file_reader(tree: Arc<Tree>, conn, path)` (free fn), `Tree::open_file_reader(&Arc<Self>, conn, path)`, or `SmbClient::open_file_reader(&self, tree, path)` (clones the primary connection).

Same owned-`Connection` + `Arc<Tree>` shape as `FileWriter`, so it's `'static`. `read_at` takes `&self` (no shared cursor) and issues `execute_with_credits` READs, splitting a range larger than `MaxReadSize` into consecutive wire reads and reassembling. It clamps to the size seen at open, so a read at/after EOF returns empty and a straddling read is short — never an error. `close()` consumes `self` (read-after-close is a compile error); like the other stream handles, `Drop` can't CLOSE (no async drop) and only logs a debug warning, so a dropped-without-close reader leaks the handle until session teardown. Pinned by the `stream.rs` `file_reader_*` mock tests (one CREATE, N READs, one CLOSE; EOF clamping; range splitting; drop-sends-no-close) and the `guest_file_reader_positioned_reads` Docker test.

## Server-side copy (`copy.rs`)

`FSCTL_SRV_COPYCHUNK` copies byte ranges between two files *on the server* — the data never crosses the wire. Two tiers, both on `Tree` (with `SmbClient` wrappers that route via `connection_for_tree`):

- **Convenience**: `server_side_copy_file` (whole file, truncating dest) and `server_side_copy_file_range` (a range at a chosen dest offset, non-truncating dest). Both open source (read) + dest (read+write), get a resume key, batch the copy, flush+close both, and never leak a handle on an error path (shared `copy_paths` helper).
- **Primitives**: `request_resume_key` (source handle → opaque `ResumeKey`), `copy_chunks` (one IOCTL against an open read+write dest), and `server_side_copy_range` (batches over open handles). These take caller-held `FileId`s like `open_file` does; `open_file_readwrite` opens a dest and `close_handle` (now public) releases it.

Gotchas / why:
- **Dest needs read+write.** `FSCTL_SRV_COPYCHUNK` requires the destination open to carry `FILE_READ_DATA` *and* `FILE_WRITE_DATA` (MS-SMB2 3.3.5.15.6). The read+write opens grant both; a plain write handle would get `ACCESS_DENIED`.
- **Limits negotiation is a normal path, not an error.** When a request exceeds the server's per-request limits it returns `STATUS_INVALID_PARAMETER` *with* a 12-byte `SRV_COPYCHUNK_RESPONSE` carrying the limits (MS-SMB2 3.2.5.14.3). `copy_chunks` surfaces that as `Ok(CopyChunkOutcome::Rejected { limits })`, not `Err`; `server_side_copy_range` starts at `ServerSideCopyLimits::CONSERVATIVE` (16×1 MiB / 16 MiB, the common Windows/Samba minimum) and re-batches within advertised limits, guarding against an infinite loop via "advertised == current → error".
- **Unsupported servers are typed.** Old Samba / NAS firmware without copychunk return `STATUS_NOT_SUPPORTED` / `STATUS_INVALID_DEVICE_REQUEST`, classified `ErrorKind::Unsupported`. Consumers branch on it to fall back to read-then-write — no string matching.
- **Positioned append pairs with it.** `create_file_writer_at(path, offset)` opens non-truncating (`FileOpenIf`) and seeds the writer's offset, so a consumer can server-side-copy a retained prefix into a temp, then append (the archive tail-rewrite shape).

Full behavioral detail lives in the `copy.rs` module rustdoc.

## Streaming download entry points

Two symmetric ways to start a `FileDownload`:

- `SmbClient::download(&mut self, &Tree, path)` — convenience wrapper that borrows the client's internal `Connection`.
- `Tree::download(&self, &mut Connection, path)` — takes the `Connection` directly. Use this when you hold a
  `conn.clone()` and want to drive concurrent downloads on the same SMB session (each clone pairs with one outstanding
  download; the receiver task multiplexes responses by `MessageId`). `SmbClient::download` delegates here.

For full control, `Tree::open_file` (returns `(FileId, u64)`) plus `FileDownload::new` let callers build custom chunk
loops with non-default `chunk_size`. Most users shouldn't need this — `read_file_compound` (1 RTT, or `read_file_compound_sized`
when the size is already known) handles small files and `Tree::download` / `SmbClient::download` handle the streaming
case.

FileWriter has two terminal operations:
- `finish()` — send all buffered data, drain in-flight WRITEs, FLUSH (fsync on the server), CLOSE. Use on normal completion.
- `abort()` — discard unsent data, drain in-flight WRITEs to keep credits/message-ids in sync, skip FLUSH, best-effort CLOSE. Use on cancellation or error paths where the partial remote file is going to be deleted anyway — `abort()` saves the fsync round-trip. The caller is responsible for deleting the partial remote file.

Both consume `self` so write-after-close/abort is a compile error. `Drop` logs a debug warning if neither was called (handle leaks).

## Session setup flow

1. Send NTLM NEGOTIATE in SESSION_SETUP
2. Receive STATUS_MORE_PROCESSING_REQUIRED with challenge, update preauth hash
3. Send NTLM AUTHENTICATE in SESSION_SETUP, update preauth hash with request only
4. Receive STATUS_SUCCESS (do NOT include in preauth hash)
5. Derive signing/encryption keys via SP800-108 KDF
6. Activate signing on the connection
7. If session or share requires encryption, activate encryption (TRANSFORM_HEADER wrapping with AEAD)

## Encryption

Encryption is activated when the session flags include `ENCRYPT_DATA` or a share has `SMB2_SHAREFLAG_ENCRYPT_DATA`. When active:
- Outgoing messages are wrapped in TRANSFORM_HEADER (protocol ID 0xFD) with a monotonic nonce
- Incoming messages with 0xFD are decrypted before processing
- Signing is skipped (AEAD provides authentication)
- Compound chains are encrypted as one unit (pitfall #9)

Tree-level encryption: `connect_share()` checks the share's encrypt flag and activates encryption on the connection if needed, even if the session didn't require it.

## Reconnection

Full rationale on `Connection::reconnect_if_needed` and `ReconnectPolicy`.

**A revival happens in place, under the existing `Arc<Inner>`.** `FileWriter`, `FileReader`, `Watcher`, and every pipelined task own a `Connection` clone; minting a new `Connection` would leave all of them permanently dead and force the consumer to rebuild the world. ❌ Don't "simplify" this back to returning a fresh `Connection`.

- **Armed by the consumer, never assumed.** `Connection::set_reviver` supplies the two things this crate deliberately doesn't keep: an address and credentials. `ClientConfig::auto_reconnect` installs one built from the config. With none installed a dead connection reports `Error::Disconnected` and stays dead.
- **Written for a stampede.** A 32-deep pipeline discovers the same dead session 32 times at once; `reconnect_if_needed` dials once and everyone else returns off the same attempt (`revive_lock` + the `revivals` counter, which is bumped only on success so the double-check can't see a half-built session).
- **Every bound lives in `ReconnectPolicy`.** The wall-clock budget wraps the ENTIRE revival, not each attempt: a per-attempt timeout multiplies by the attempt count, and an attempt that parks forever never reaches the second one. A failed revival's verdict stands for `failure_cooldown`, or each caller pays the full budget in turn (32 × 60 s is the unbounded hang again).
- **`install_transport` erases the dead session completely** and in a fixed order: tear down (which sets `disconnected` under the waiters lock), reset, rebuild, clear `disconnected` LAST. ❌ Nothing may carry over — a stale credit window out-spends the new server, a stale message id makes the server drop us for a sequence gap, stale keys fail verification on every frame. `send_queue_depth` is the deliberate exception (resetting it underflows a caller mid-increment).
- **The plumbing is respawned, not just the socket.** The keepalive, the connection sweeper, and the receiver all exit for good on `disconnected`, so a revival that only swapped the transport would come back with no liveness detection, silently. `spawn_plumbing` is shared with construction so the two can't drift.
- **The consumer always finds out**: `reconnects_succeeded` / `reconnects_failed` / `reconnect_attempts` counters (always on, answer "was this link quietly flaky?" after the fact), log lines, and a pushed `ReconnectEvent` via `Connection::on_reconnect` for a UI that wants to say "reconnected, resuming" while it happens.
- **`SESSION_SETUP` announces `PreviousSessionId`** after a revival (`Connection::previous_session_id`), which is how a client says "this is me again" — MS-SMB2 § 2.2.5. Without it the server holds the dead session's state until its own timeout.
- All previous `Tree` handles and `FileId` values are invalidated regardless; the caller must `connect_share` again. ❌ `execute` never reconnects on your behalf: re-issuing an arbitrary request against a new session is a data-safety decision only the layer that knows the operation's semantics can make. At the `SmbClient` level that means listings, reads, `stat`, and `fs_info` replay; `delete`, `rename`, `create`, and writes surface the error.

## Durable handles

Full rationale in `durable.rs`'s module docs. `Tree::open_file_durable` asks for an open the server keeps alive across a disconnect; `Tree::reclaim_durable_handle` claims it back so an interrupted write resumes instead of restarting.

- **A reclaim is two independent proofs, and anything less fails.** (1) The `DH2C` context carries the `CreateGuid` the client chose at open, which the server matched (MS-SMB2 § 3.3.5.9.12). (2) A compounded `QUERY_INFO` says which file the handle points at, read at open and again after the reclaim. Writing into the wrong file is far worse than a failed transfer, so ❌ never relax either check or let a reclaim through on one.
- ❌ **v1 durable handles (`DHnQ`/`DHnC`) are not implemented and must not be.** They identify the open by nothing but the server-allocated `FileId`, so a server that recycles ids could hand back a different file. On SMB 2.1 a dead session means the transfer restarts.
- ❌ **The reconnect context must travel alone.** A server may reject a reclaim carrying any other create context (MS-SMB2 § 3.3.5.9.12) and Samba does, which is why the identity check is a compounded `QUERY_INFO` and not the tidier `QFid` create context. Use `FileInternalInformation` (class 6), not `FileIdInformation` (class 59): Samba 4.20 answers 59 with `STATUS_INVALID_INFO_CLASS`.
- **A batch oplock is the price** (MS-SMB2 § 3.3.5.9.10) and it bills other clients ~35 s per break, so breaks are acknowledged from the receiver task on the tree the open belongs to (`Connection::register_oplock` / `forget_oplock`). Acknowledging gives the durability up, which is the right trade.
- **Everything degrades quietly.** A pre-SMB3 server, durable handles off, a declined oplock, a server that won't answer the identity query: all produce a working handle with `DurableOpen::durable == None`, never an error.

## Connection internals: receiver task + `oneshot` routing

`Connection::execute` / `execute_compound` is the primary API. A background receiver task (spawned per `Connection` at `from_transport`) owns the transport's read half and routes each sub-frame to a per-request `oneshot::Sender` by `MessageId`.

- `Connection` is `Clone` and holds just `Arc<Inner>`. `Inner` owns `waiters: Mutex<HashMap<MessageId, Waiter>>`, `credits: CreditPool`, `next_message_id: AtomicU64`, the transport send half (via `Arc<dyn TransportSend>`), the receiver task's `JoinHandle`, and crypto state. All state is behind atomics or short-critical-section `std::sync::Mutex`.
- `execute(command, body, tree_id)` allocates a `MessageId` (`AtomicU64::fetch_add(credit_charge)`), registers a `oneshot::Sender` in `waiters` atomically under the waiters lock (re-checks `disconnected` there to rule out a TOCTOU where the receiver task has already shut down and drained the map), packs the frame, signs/encrypts/compresses as needed, and writes through `TransportSend::send`. Then it awaits the local `oneshot::Receiver`. Returns `Result<Frame { header, body, raw }>`.
- `execute_compound(&[CompoundOp])` does the same per sub-op, building one compound transport frame with `NextCommand` offsets, then awaits each per-sub-op receiver sequentially. Each receiver resolves independently (the receiver task splits the server's response by `NextCommand` and routes each sub-response by its `MessageId`). The outer `Result` is "did the compound hit the wire"; the inner `Vec<Result<Frame>>` has one entry per sub-op.
- **Cancellation-by-drop is safe by construction.** If a caller's future is aborted (`tokio::spawn` + `JoinHandle::abort()` is the common path in consumers), the locally-owned `oneshot::Receiver` drops; the receiver task's `Sender::send` then fails silently when the late frame arrives; the frame is discarded. Credit grants are still banked in the receiver task so dropped-caller frames don't starve throughput.
- **Transport drop** fans `Err(Disconnected)` to every pending `oneshot::Sender` and sets `disconnected=true` under the waiters lock. Subsequent `execute` / `execute_compound` sees `disconnected=true` and returns `Err(Disconnected)` without inserting (no leaked waiters).

Gotcha/Why — there is no split `send_request` / `receive_response` API, so tests can't hand-drive the two halves. Tests that build mocks without going through `setup_connection` call `mock.enable_auto_rewrite_msg_id()`, which rewrites each queued response's zero-msg_id to match the next pending sent msg_id in FIFO order.

Full design in [docs/specs/connection-actor.md](../../docs/specs/connection-actor.md).

## Key decisions

- **Owned `FileWriter`: N concurrent streamed writes over one Connection without external locking**: `FileWriter` owns its `Connection` (cheap `Arc::clone`) and `Arc<Tree>` instead of borrowing `&'a mut Connection` from the `SmbClient`. Built via the free `open_file_writer(tree: Arc<Tree>, conn: Connection, path: &str)` or one of the two convenience wrappers (`Tree::create_file_writer`, `SmbClient::create_file_writer`). Multiple writers built from clones of the same `Connection` pipeline their WRITEs over one SMB session — the receiver task multiplexes responses by `MessageId`. The borrowed variant was the root cause of a production-reproducing deadlock in the cmdr SMB volume's `write_from_stream` (Phase C QNAP test, 200 × 7 MB concurrent overwrites): the consumer had to hold its session mutex for the entire upload because the writer borrowed `&'a mut Connection`. Owning the connection removes the lock from the hot path entirely.
- **`execute` / `execute_compound` take `&self`**: `Connection: Clone` supports concurrent ops per connection — clone freely across tasks, the receiver task multiplexes responses by `MessageId`. `Tree::*` methods still take `&mut Connection` because session-setup mutators (`activate_signing`, `set_session_id`) keep `&mut self`; Tree code calls both, so `&mut` at that layer is the least-churn choice.
- **Sender work stays on the caller thread, only the receiver is a task**: The send path already uses an internal Mutex on the transport write half for ordering; adding a second task just to drive sends would add latency without correctness gain. The receiver bug (orphan/dropped-caller frames corrupting the wire) only existed on the receive side, so only the receive side needed a task.
- **Compound reads as default**: One round-trip for small files. Saves 2 RTTs vs sequential CREATE/READ/CLOSE.
- **512 KB pipeline chunks**: Balances between too many small requests (overhead) and too few large ones (credit starvation). Gives ~20 chunks per 10 MB file.
- **Password stored in `SmbClient`**: Enables reconnect without re-prompting. Not encrypted in memory. Drop when done.

## Gotchas

- **Preauth hash excludes the final success response**: Only STATUS_MORE_PROCESSING_REQUIRED responses are hashed. Including the success response produces wrong keys. (MS-SMB2 3.2.5.3.1)
- **Oplock break notifications arrive with MessageId 0xFFFFFFFFFFFFFFFF**: The receiver task detects these and skips them without invoking a waiter lookup.
- **Register-waiter must be atomic with `disconnected` check**: The waiters lock covers both reading `disconnected` and inserting the `oneshot::Sender`. If the check and insert were racy, a receiver-task failure mid-send could leave an orphan `Sender` in the map that never gets routed — caller would hang on `rx.await` forever. Same goes for `fan_error_to_waiters`: it sets `disconnected=true` UNDER the same waiters lock before draining, so new sends strictly either succeed-and-get-drained or fail at the insert check.
- **Unrecoverable frame errors tear down the connection** (Phase 3 P3.4): decrypt failure, decompress failure, or a malformed sub-frame header that survives `split_compound` all cause the receiver task to call `fan_error_to_waiters(Err(Disconnected))` and exit. The alternative — log-and-continue — would leave the matching waiter hanging forever, because the msg_id isn't recoverable from an unparseable frame. The connection is also out of sync after one bad frame, so reconnect is the right move anyway. Counted via `MetricsSnapshot::{decrypt_failures, decompress_failures, malformed_frames}`.
- **STATUS_PENDING loop**: CHANGE_NOTIFY and other long-poll operations get STATUS_PENDING first. The receiver task keeps the waiter registered on PENDING and does NOT forward the interim response. Credits from PENDING are still banked, and the waiter's `last_activity` is refreshed so the response deadline restarts. Counted via `MetricsSnapshot::status_pending_loops`.
- **Signing and encryption are mutually exclusive on the wire**: When encrypting, zero the signature field (AEAD provides integrity). On receive, skip signature verification if decryption succeeded.
- **Compound encryption wraps the entire chain**: One TRANSFORM_HEADER for all sub-requests concatenated, not per sub-request.
- **Share-level encryption**: If a share has `SMB2_SHAREFLAG_ENCRYPT_DATA`, encryption is activated even if the session didn't require it.
- **FileDownload/FileUpload can leak handles on drop**: Rust has no async drop. If not consumed fully, the file handle leaks. The types log a warning.
- **FileWriter can leak handles on drop**: Same as FileDownload/FileUpload. Rust has no async drop. If not consumed via `finish()` or `abort()`, the file handle leaks. The type logs a debug warning.
- **DFS paths must include server\share prefix**: When `SMB2_FLAGS_DFS_OPERATIONS` is set, the server expects the path to start with `server\share\` (MS-SMB2 3.2.4.3). `Tree::format_path()` handles this automatically for DFS shares. Without the prefix, Samba strips the first two path components, leading to wrong file opens.
- **DFS redirect changes the tree in-place**: After a DFS redirect, `tree.server`, `tree.share_name`, and `tree.tree_id` all change. Subsequent operations on the same tree use the target server directly -- they must use target-relative paths, not the original DFS paths.
- **tree.server stores addr:port**: The `server` field on `Tree` stores the full `addr:port` string (not just hostname) so `connection_for_tree` can distinguish servers that share the same hostname but use different ports.
- **Servers MAY split compound responses**: MS-SMB2 section 3.3.4.1.3 says the server SHOULD compound responses but is not required to. Samba (and QNAP firmware built on it) is known to split compound chains into separate frames in some scenarios; Windows Server does too under certain conditions. Compound-using methods (`read_file_compound`, `write_file_compound`, `fs_info`, `stat`, `rename`, `delete_file`, batch `*_files`) call `Connection::receive_compound_expected(n)` instead of `receive_compound()`, which transparently gathers additional frames if the server splits. Logged at DEBUG, not WARN -- it's a spec edge case, not a problem.
