# Diagnostics

Add an in-process observability surface so consumers (applications, AI agents, humans behind a UI) can ask a running
`SmbClient` what's going on inside: credits, in-flight requests, negotiated parameters, per-connection counters, DFS
cache state, sessions. One snapshot type, one tree of data, two render formats — `Display` for a terminal, optional
`serde::Serialize` for everything else.

This doc is the source of truth during implementation. When something drifts, update this doc rather than the code.
Plan v2 incorporates fresh-eyes review feedback (see § "Plan v2 changes" at the bottom).

## Why

The library has rich internal state but no way to ask "what's the current state?" without grepping logs or adding ad-hoc
`println!`s. The recent CHANGE_NOTIFY loss-window investigation (commits `e3a35f1` → `cbe94df`) would have been minutes
instead of days if `oplock_breaks_received`, `status_pending_loops`, and a current "in-flight requests" gauge had been
queryable. Same for DFS failovers, compound splits (QNAP/Samba), signature verification failures, and credit starvation.

Why snapshot-only (and not an event stream), even though cmdr's principles say "subscribe, don't poll":

- **State-shaped, not event-shaped.** What consumers want to see — credits, in-flight count, negotiated dialect,
  per-counter totals — is *current state*, not a sequence of past events.
- **Event-shaped things already exist.** Oplock breaks, session expiry, DFS failovers, decrypt failures all log through
  the `log` facade today. Consumers wanting a temporal view subscribe to `log` (`tracing`, `env_logger`, or a custom
  appender) at the application layer.
- **Polling cost is genuinely nothing.** Snapshot is a handful of atomic loads + a few short critical sections under
  `StdMutex` (uncontended typical wait <100 ns). Polling at 1 Hz for a dashboard is below noise.
- **An event channel is the kind of API mistake you can't take back.** Add it once, every consumer wires their own
  subscriber, the channel's bounded/unbounded/drop-policy is a forever decision. Adding it later when there's a real
  workload is strictly safer than adding it now and discovering nobody uses it.

If a real event-driven workload appears later, `diagnostics()` and a future `event_stream()` coexist cleanly.

Consumers that benefit:

- **`cmdr`** wants a "connection details" dev panel and an MCP tool returning the same snapshot.
  Smart-backend/thin-frontend: smb2 owns the data, cmdr does the rendering.
- **Agents** diagnosing real SMB issues over MCP need a single structured tree they can read once, not a log scrape.
- **Tests** can replace fragile log-grep assertions with typed ones (`assert!(diag.primary.metrics.status_pending_loops > 0)`).
- **Operators** (humans behind `examples/diagnostics.rs` or a future `smb2-diag` CLI) get a readable terminal dump.

## Non-goals

- No web frontend, no HTML, no JS — wrong layer for a protocol library.
- No `tracing` integration, no `tokio-console` wiring. These belong in consumers; smb2 keeps the `log` facade.
- No async event channel, broadcast bus, or callback hooks. See "Why" above.
- No reset/clear API for counters. Monotonic is easier; consumers diff two snapshots for rate.
- No per-NTSTATUS error histogram. Too noisy for now; can be added later as a separate optional field.
- No exposing key material. Lengths, algorithm IDs, and "active/inactive" flags only — same rule as the existing logger.
- No tracking of caller-owned objects (open `FileId`s, live `FileDownload`/`FileUpload`/`FileWriter`/`Watcher`
  instances). The library doesn't own these — the caller does. Forcing registration back would require `Arc` soup.
  Document that consumers fold their own stream handles into their own diagnostics view.

## Design summary

```
Diagnostics                                ←  SmbClient::diagnostics()
├── client : ClientInfo                    ←  config + ClientMetricsSnapshot
├── primary : ConnectionDiagnostics        ←  primary connection
│   ├── server, negotiated (Option), credits, signing, encryption, compression,
│   │   rtt_estimate, disconnected, dfs_trees, metrics : MetricsSnapshot,
│   └── session : Option<SessionDiagnostics>   ←  None until session-setup
├── extra_connections : Vec<ConnectionDiagnostics>   ←  one per DFS cross-server conn,
│                                                       each with its own .session
└── dfs_cache : Vec<DfsCacheEntry>
```

`ConnectionDiagnostics::session` carries the session info **per connection**, because DFS extra connections each have
their own `Session` (one auth per target server). There is no top-level `session` field — `client.diagnostics().primary.session`
is the conventional path for the main connection's session.

`Tree`, `FileDownload`, `FileUpload`, `FileWriter`, `Watcher` already expose per-instance progress (`bytes_received`,
`bytes_written`, `Progress`). The snapshot does not try to enumerate live instances — the library doesn't own them.

### Counters

Two atomic-bearing structs, internal:

- `Metrics` lives on each `Inner` (per connection).
- `ClientMetrics` lives on each `SmbClient` (above the connection layer).

Both expose one method: `snapshot()` returning a plain `Copy` value type. The atomic-bearing types are
crate-private; the snapshot value types are public.

All increments are `Relaxed` (single uncontended cache line, ~1 ns). Reads are `Relaxed`. Fields may skew between
samples — this is documented as the eventual-consistency contract on the snapshot.

```rust
// Per-connection (per-Inner). Snapshotted as MetricsSnapshot.
struct Metrics {
    // Send path
    requests_sent: AtomicU64,            // every msg_id allocated -- centralized in allocate_msg_id
    compound_requests_sent: AtomicU64,   // every execute_compound call (chain count, not sub-op count)
    wire_bytes_sent: AtomicU64,          // bytes written to transport (post-encrypt/compress/sign)
    explicit_cancels_sent: AtomicU64,    // send_cancel calls (drop-cancel is invisible — Phase-3 E9)

    // Receive path
    responses_routed_ok: AtomicU64,      // sub-frames where waiters.remove → Some(tx) AND tx.send(Ok(frame)) delivered
    responses_routed_err: AtomicU64,     // sub-frames where waiters.remove → Some(tx) AND tx.send(Err(_)) delivered.
                                         //   Today this is the union: signature_failures + session_expired_events.
                                         //   Don't sum those WITH this counter; they're a partition of it.
    responses_late_after_drop: AtomicU64,// sub-frames where waiters.remove → Some(tx) BUT tx.send fails
                                         //   (caller's oneshot::Receiver was dropped — typical for spawn/abort)
    responses_stray: AtomicU64,          // sub-frames where waiters.remove → None
                                         //   (msg_id never registered: server bug, or send-error cleanup race)
    wire_bytes_received: AtomicU64,      // bytes off transport (pre-decrypt/decompress)

    // Protocol events
    status_pending_loops: AtomicU64,     // interim STATUS_PENDING frames the receiver kept-waiter on
    unsolicited_notifications_received: AtomicU64,  // MessageId::UNSOLICITED frames
                                                    //  (today: all oplock breaks; future: lease breaks)
    signature_failures: AtomicU64,       // signature verify failed — routed to waiter as Err (also ticks responses_routed_err)
    decrypt_failures: AtomicU64,         // decrypt failed — counted ONCE before fan_error_to_waiters
                                         //  (counter survives connection teardown; see invariant below)
    decompress_failures: AtomicU64,      // decompress failed — counted ONCE before fan
    malformed_frames: AtomicU64,         // header/parse failed — counted ONCE before fan
                                         //  (covers split_compound parse failure + prepare_sub_frame parse failure)
    session_expired_events: AtomicU64,   // STATUS_NETWORK_SESSION_EXPIRED sub-frames (not session-expiry events).
                                         //   A compound of N expired sub-ops ticks N times. For the event-shaped
                                         //   signal "did we reconnect" use ClientMetrics::reconnects.
                                         //   Subset of responses_routed_err; don't sum.

    // Caller-observed outcomes
    requests_returned_err: AtomicU64,    // execute / execute_with_credits / execute_compound returned outer Err
                                         //   to a caller that polled to completion. Per-compound, not per-sub-op.
                                         //   Caller-drop is captured by responses_late_after_drop, not here.
}

// Client-level. Snapshotted as ClientMetricsSnapshot.
struct ClientMetrics {
    reconnects: AtomicU64,              // SmbClient::reconnect() invocations
    dfs_referrals_resolved: AtomicU64,  // DfsResolver::resolve hit a server (cache miss)
    dfs_cache_hits: AtomicU64,          // DfsResolver::resolve served from cache
}
```

#### Invariants

- **Metrics survive teardown.** `Metrics` lives on `Inner`, which outlives `disconnected = true`. A consumer calling
  `diagnostics()` on a torn-down connection sees the counts at the moment of death. Documented on
  `Connection::diagnostics`.
- **Counters reset across `SmbClient::reconnect()`.** Reconnect builds a fresh `Connection` with a fresh `Inner`, so
  per-connection counters return to zero. `ClientMetrics` survive (they live on `SmbClient`), so `reconnects` is
  monotonic across the client's lifetime. Documented on `SmbClient::diagnostics` and on `Diagnostics`.
- **`wire_bytes_sent` and `wire_bytes_received` measure the wire layer**, after any sign/encrypt/compress on the send
  side and before any of those on the receive side. This is the byte count a packet capture would observe. Documented on
  each field. A future `plaintext_bytes_*` pair can land additively if a use case appears.
- **Fields may skew.** `credits.available`, `credits.in_flight`, and each counter is sampled independently. Their sum
  (e.g. `available + in_flight`) is *not* invariant. Documented on `CreditInfo`.

#### `response_splits_observed` is deferred

A "compound response was split across N transport frames" counter would be useful for diagnosing QNAP/Samba splits
(AGENTS.md pitfall #13). Wiring it cleanly is not trivial under the actor model: each sub-op's `oneshot::Receiver`
resolves independently as its `MessageId` arrives, so neither the receiver task (no notion of "N expected for this
caller") nor the caller (no view into transport-frame count) naturally has the data.

Spec'ing it concretely would mean adding "source-frame-index" tagging to each routed sub-frame and a check in
`execute_compound` that all its sub-op responses carry the same index. That's meaningful new plumbing in the demux path.

**Decision:** drop this counter from the initial diagnostics PR. Track as a follow-up. The DEBUG log line in the
receiver loop already covers manual diagnosis today, and a future PR can revisit once the demux path is touched for
another reason.

### Snapshot types (public)

All in a new `src/client/diagnostics.rs`, re-exported from `lib.rs`.

**Snapshot lock order.** The snapshot acquires these locks, *one at a time*, in this order, and never holds one across
an `.await`: **`crypto` → `waiters` → `dfs_trees` → `estimated_rtt`**. Each is held only as long as it takes to copy
primitives out and release. `params` (`OnceLock`) is a wait-free atomic read, not a lock. `preauth_hasher` and
`receiver_task` (the other `Inner` mutexes) are not touched by the snapshot — they're handshake-only / lifecycle-only.
Top-of-file doc comment in `diagnostics.rs` restates this and warns: "if you add a field that touches a new lock,
extend this order, don't reshuffle it."

```rust
pub struct Diagnostics {
    pub client: ClientInfo,
    pub primary: ConnectionDiagnostics,
    pub extra_connections: Vec<ConnectionDiagnostics>,
    pub dfs_cache: Vec<DfsCacheEntry>,
}

pub struct ClientInfo {
    pub primary_server: String,
    pub timeout: Duration,
    pub auto_reconnect: bool,
    pub dfs_enabled: bool,
    pub metrics: ClientMetricsSnapshot,
}

pub struct ConnectionDiagnostics {
    pub server: String,
    pub negotiated: Option<NegotiatedSummary>,   // None until negotiate() runs
    pub credits: CreditInfo,
    pub signing: SigningInfo,
    pub encryption: EncryptionInfo,
    pub compression: CompressionInfo,
    pub rtt_estimate: Option<Duration>,
    pub disconnected: bool,
    pub dfs_trees: Vec<TreeId>,
    pub session: Option<SessionDiagnostics>,     // None until session-setup runs
    pub metrics: MetricsSnapshot,
}

pub struct NegotiatedSummary { /* dialect, max_*_size, server_guid, signing_required, capabilities, gmac_negotiated, cipher, compression_supported */ }

pub struct CreditInfo {
    pub available: u16,
    pub in_flight: usize,    // waiters.len(); see "fields may skew" invariant
    pub next_message_id: u64, // the id that will be assigned to the next request
}

pub struct SigningInfo    { pub active: bool, pub algorithm: Option<SigningAlgorithm> }
pub struct EncryptionInfo { pub active: bool, pub cipher: Option<Cipher> }
pub struct CompressionInfo{ pub requested: bool, pub negotiated: bool }

pub struct SessionDiagnostics {
    pub session_id: SessionId,
    pub should_sign: bool,
    pub should_encrypt: bool,
    pub signing_algorithm: SigningAlgorithm,
}

pub struct DfsCacheEntry {
    pub path_prefix: String,
    pub target_count: usize,
    pub expires_in: Option<Duration>,    // None if already expired
}

#[derive(Copy, Clone)]
pub struct MetricsSnapshot { /* one u64 per Metrics field */ }
#[derive(Copy, Clone)]
pub struct ClientMetricsSnapshot { /* one u64 per ClientMetrics field */ }
```

Trait bounds: every public diagnostics type is `Debug + Clone`. **Not** `PartialEq` (snapshots aren't equality-shaped),
**not** `Eq`, **not** `Deserialize`. `MetricsSnapshot` and `ClientMetricsSnapshot` are also `Copy`.

#### `#[non_exhaustive]` policy

Applied to the top-level container types only: `Diagnostics`, `ClientInfo`, `ConnectionDiagnostics`,
`NegotiatedSummary`, `SessionDiagnostics`, `DfsCacheEntry`, `MetricsSnapshot`, `ClientMetricsSnapshot`. These can
plausibly grow. The leaf info types — `CreditInfo`, `SigningInfo`, `EncryptionInfo`, `CompressionInfo` — are not marked
`#[non_exhaustive]`: their shape is locked by the protocol. Consumers can synthesize them in tests with struct literals.
Document this distinction in the rustdoc.

### Public API

```rust
impl Connection {
    /// Capture an eventually-consistent snapshot of this connection's state and counters.
    ///
    /// Survives connection teardown: a torn-down `Connection` returns its final counter values
    /// alongside `disconnected: true`. Fields are sampled independently; values may skew.
    pub fn diagnostics(&self) -> ConnectionDiagnostics;
}

impl SmbClient {
    /// Capture a tree of diagnostics for the client, its primary and DFS-extra connections,
    /// each connection's session, and the DFS referral cache.
    ///
    /// Per-connection counters reset on `reconnect()`. Client-level counters survive.
    pub fn diagnostics(&self) -> Diagnostics;
}
```

### Optional `serde` feature

```toml
[features]
serde = ["dep:serde"]
```

When enabled, every public diagnostics type gains `#[derive(Serialize)]`. **No `Deserialize`** — snapshots are
write-only outputs of the library; nothing inside the library reads one back.

#### Re-used types serde audit (per BLOCKER finding)

The snapshot embeds these existing types. Per-type plan:

| Type | Location | Today's derives | Action |
|---|---|---|---|
| `Dialect` | `types/mod.rs` | `num_enum::IntoPrimitive`, `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash` | Add `cfg_attr(feature = "serde", derive(Serialize))`. Plain enum, trivial. |
| `SigningAlgorithm` | `crypto/signing.rs` | similar | Add `cfg_attr`. |
| `Cipher` | `crypto/encryption.rs` | similar | Add `cfg_attr`. |
| `Capabilities` | `types/flags.rs` | bitflags newtype around `u32` | Add a manual `Serialize` impl (3 lines): serialize as the underlying `u32` bits. Document "JSON form is bits, not field list" on the field. |
| `Guid` | `pack/guid.rs` | wire-format struct (mixed-endian) | Add `cfg_attr`. JSON form is field-shape, not wire-shape — document on the field. |
| `TreeId`, `SessionId`, `MessageId` | `types/mod.rs` | newtype `u32`/`u64`/`u64` | Add `cfg_attr` with `transparent` so JSON form is the bare integer. |
| `Duration`, `String`, primitives | std | serde has built-in impls | No action. |

All listed `cfg_attr` additions are non-breaking even with the feature off (cfg-attr disappears at parse time).

### `Display` impl

`Diagnostics` (top level only) gets a `Display` impl that prints a compact terminal view. The `Display` impl prints
**raw `u64` byte counts** (no humanization in the lib). Example `Display` output:

```
SMB client → 192.168.1.100:445
  dialect:      SMB 3.1.1                        rtt:        2.3 ms
  signing:      active (AesGmac)                 encryption: inactive
  compression:  requested, not negotiated         dfs:        enabled (cache: 3 entries)
  reconnects:   0                                 dfs hits:   12 / 1 miss

Primary connection (192.168.1.100:445)
  credits:           63 available · 2 in flight · next msg_id 1407
  wire bytes:        14894592 sent · 328007680 received
  responses:         1405 ok · 0 wire-err · 2 late · 0 stray         (sent: 1407, caller-err: 2)
  protocol events:   8 status-pending · 1 unsolicited
  errors:            0 signature · 0 decrypt · 0 decompress · 0 malformed · 0 session-expired

DFS extra connections: (0)
```

The example binary (`examples/diagnostics.rs`) applies its local `humanize_bytes` helper for human display, so its
output looks like `wire bytes: 14.2 MiB sent · 312.8 MiB received`.

Only one `Display` impl, on the top level. No `Display` on `ConnectionDiagnostics` — consumers who want per-connection
text can render their own, or use the `serde` feature. Keeps the lib slim.

The `Display` format is **not part of the SemVer contract**. For programmatic use, enable the `serde` feature.

### Example binary

`examples/diagnostics.rs`: connects to an env-driven server, lists a directory, prints the snapshot.

- Default: `Display` form, with `humanize_bytes` applied to byte counts.
- `--json` flag: only honored if compiled with `--features serde`. Otherwise prints a one-line stderr error and exits 2:
  `"--json requires building with --features serde"`.

## Send-site counter consolidation

Counters at the send sites are factored so they can't drift apart from the code.

- **`requests_sent`** ticks inside `allocate_msg_id` (the one funnel every send path goes through: `negotiate`,
  `execute_with_credits`, `execute_with_credits_capturing_request`, `dispatch_with_credits`, and `execute_compound`'s
  loop). This catches `dispatch` and Watcher's pre-arm CHANGE_NOTIFY, which the v1 plan missed. **Note:** because the
  funnel is shared, `requests_sent` counts negotiate and session-setup messages too, not just user-issued ops. Document
  this on the field.

- **`wire_bytes_sent`** is collected by a small private helper on `Inner`:
  ```rust
  async fn send_and_count(&self, bytes: &[u8]) -> Result<()> {
      self.metrics.wire_bytes_sent.fetch_add(bytes.len() as u64, Relaxed);
      self.sender.send(bytes).await
  }
  ```
  Every `inner.sender.send(...)` call site (in `negotiate`, both branches of `execute_with_credits` and
  `execute_with_credits_capturing_request`, both branches of `dispatch_with_credits`, both branches of `execute_compound`,
  both branches of `send_cancel`) flips to `inner.send_and_count(...)`. **Why factor:** v1 listed "four sites plus
  cancel"; the actual count is ten once compressed/plain and encrypted/plain branches are enumerated. Hand-placing ten
  bumps invites a missed branch and a leaking counter. The helper is purely additive — same `await`, same `Result`.

- **`compound_requests_sent`** ticks once at the top of `execute_compound`.

- **`explicit_cancels_sent`** ticks once at the top of `send_cancel`.

## Receive-site counter consolidation

- `wire_bytes_received` ticks at the top of the receiver_loop, right after `transport_recv.receive().await` returns
  `Ok(bytes)`, before decrypt/decompress.

- The four routing outcomes (the `waiters.remove(&msg_id)` branch) all tick exactly one counter — disjoint, together
  covering every routed sub-frame. Naming chosen so the meanings can't blur:
  - `Some(tx)` + `tx.send(Ok(frame))` succeeded → `responses_routed_ok`.
  - `Some(tx)` + `tx.send(Err(_))` succeeded (signature failure / session expired branches) → `responses_routed_err`.
  - `Some(tx)` + `tx.send(...)` returned `Err(_)` (the caller's `oneshot::Receiver` was dropped — the spawn/abort path
    documented in the actor spec) → `responses_late_after_drop`. *This is the one that catches caller-drop.*
  - `None` (msg_id not in map) → `responses_stray`. This is the genuine orphan: server sent a frame for an id we never
    allocated, or send-error cleanup raced with frame arrival.

  Together: `responses_routed_ok + responses_routed_err + responses_late_after_drop + responses_stray` covers every
  sub-frame whose msg_id was looked up. (Sub-frames that never reach the lookup — STATUS_PENDING skips, UNSOLICITED
  skips — have their own counters.)

- `status_pending_loops` ticks in the STATUS_PENDING `Skip` branch (counted once per interim frame).
- `unsolicited_notifications_received` ticks where `MessageId::UNSOLICITED` is matched.
- `signature_failures` ticks where signature verify fails. *Also* causes `responses_routed_err` to tick when the Err is
  sent to the waiter (documented on both fields).
- `decrypt_failures` ticks in `decrypt_frame` failure branch, **before** `fan_error_to_waiters`.
- `decompress_failures` ticks in the decompress failure branch (`connection.rs:~1325`), **before** `fan_error_to_waiters`.
- `malformed_frames` ticks in both the `split_compound` parse-failure branch and the `prepare_sub_frame` parse-failure
  branch, **before** `fan_error_to_waiters`.
- `session_expired_events` ticks where STATUS_NETWORK_SESSION_EXPIRED is detected. *Also* causes `responses_routed_err`
  to tick when the Err is sent to the waiter. If a compound returns N session-expired sub-frames, this counter ticks N
  times — that's truthful (each sub-frame is one routed expiry event) but documented so consumers aren't surprised.

## Milestones

### M1 — Atomics + increment sites (no public API change)

**Intent.** Land the cheap, hot-path-touching part in isolation. If something breaks, it's a regression caught here, not
muddled with the public surface.

- Add `pub(crate) struct Metrics { … AtomicU64 … }` to `connection.rs` with `Default` impl.
- Add `metrics: Metrics` field to `Inner`.
- Add the increments per § "Send-site / Receive-site counter consolidation" above. **No call site renames, no signature
  changes — only `+= 1` and `+= bytes.len()` insertions.**
- Add `pub(crate) struct ClientMetrics { … }` to `client/mod.rs` with `Default` impl; field on `SmbClient`. Increment
  on `reconnect()` and in the DFS resolver paths.
- Crate-internal `Metrics::snapshot() -> MetricsSnapshot` and likewise for `ClientMetrics`. These can be `pub(crate)`
  until M2 promotes them.
- **Tests** in `tests/diagnostics_counters.rs` exercise each counter via `MockTransport`. Each test asserts the counter
  ticks exactly N times for N expected events. Access via a `#[cfg(test)]` helper on `Connection` /
  `SmbClient` that returns the snapshot. Public surface unchanged.

### M2 — Public `Diagnostics` snapshot API

**Intent.** Lock the public surface.

- New file `src/client/diagnostics.rs` with all snapshot types (§ "Snapshot types") and one `Display` impl on
  `Diagnostics`.
- `Connection::diagnostics() -> ConnectionDiagnostics`. Implements the lock order documented in this file's top doc
  comment. Asserts (via doc, not runtime) that no two locks are held simultaneously and no lock crosses an `.await`.
- `SmbClient::diagnostics() -> Diagnostics`. Walks primary, extras, DFS cache.
- Re-export from `lib.rs`: `Diagnostics`, `ConnectionDiagnostics`, `MetricsSnapshot`, `ClientMetricsSnapshot`,
  `ClientInfo`, `SessionDiagnostics`, `NegotiatedSummary`, `CreditInfo`, `SigningInfo`, `EncryptionInfo`,
  `CompressionInfo`, `DfsCacheEntry`.
- `#[non_exhaustive]` on the types listed above (top-level containers); leaf info types stay constructible.
- Doc comments call out: eventual consistency, lock order, counter-survives-teardown, reconnect-resets-per-conn-counters,
  field skew, wire-layer byte semantics.

### M3 — `serde` feature + tests + example + docs

**Intent.** Make it nice to use.

- `Cargo.toml`: optional `serde` dep with `derive` feature; `features.serde = ["dep:serde"]`. Hidden behind cfg-attr so
  the default tree is unchanged.
- Per-type derives from the audit table above (including the manual `Capabilities` Serialize impl).
- `examples/diagnostics.rs`: env-driven connect, run a couple of ops, print `Display` or `--json`. Local `humanize_bytes`
  helper.
- `tests/diagnostics_snapshot.rs`: shape tests (pre/post negotiate, in-flight, lock-order regression, smoke `Display`,
  serde round-trip into `serde_json::Value`). Test that `Diagnostics: Send + Sync + Clone + Debug`.
- `tests/docker_integration.rs` additions (gated `#[ignore]`, hooked into `just test-docker` not consumer): hit
  `smb-encryption`, `smb-flaky`, `smb-slow`, `smb-dfs-root/target`, assert the counters tick. Live in
  `docker_integration.rs` to match the existing layout (`tests/docker/diagnostics_docker.rs` would be a new directory
  style that doesn't exist here).
- README: short "Diagnostics" section under "Quick start" with two code blocks (`Display` and JSON).
- `AGENTS.md`: add "Diagnostics" subsection under § Architecture (one paragraph + pointer).
- `src/client/CLAUDE.md`: add "Diagnostics" subsection describing the snapshot + counter model + lock order.
- CHANGELOG entry. No version bump (user decides).

### M4 — Loose-end fixes turned up during the work

- **Stale CLAUDE.md gotcha.** `src/client/CLAUDE.md` says "Silent frame discard on decrypt/decompress/malformed header:
  receiver task currently log+continues, hangs the waiter forever." Code (`connection.rs:1280, :1311, :1333, :1354, :1381`)
  calls `fan_error_to_waiters` on all of those paths. Remove the gotcha. Replace with a Decision/Why line about the
  teardown-on-unrecoverable invariant.
- **Duplicated STATUS_PENDING bullets** in `src/client/CLAUDE.md` Gotchas. Collapse into one.
- **`Connection::next_message_id` docstring.** Change "next id" wording to "the id that will be assigned to the next
  request" — unambiguous at boundary including the initial 0-state.

Deferred (not load-bearing for diagnostics; tracked in their own follow-ups):

- `Connection::send_cancel` is the lone `&mut self` on a Phase-3 `Clone`able `Connection`. Inconsistent but doesn't
  block diagnostics. Open a separate issue.
- `Inner::Drop` doesn't synchronously fan `Err(Disconnected)`. The receiver-task's transport-error branch covers it
  shortly after. Theoretical TOCTOU; flag in a follow-up.
- `Connection::credits()` clamps a `u32` to `u16`; behavior is right, docstring is silent. One-line doc follow-up.

## Testing

### Unit tests (mock transport, fast — runs in `just check`)

`tests/diagnostics_counters.rs`:
- `requests_sent` and `wire_bytes_sent` tick for a single execute.
- `compound_requests_sent` ticks for an `execute_compound` of 3 sub-ops; `requests_sent` ticks by 3 as well (each sub-op
  allocates a msg_id).
- `requests_returned_err` ticks when the connection is torn down mid-await and the *caller polled to completion*.
- `responses_late_after_drop` ticks for a dropped caller future: spawn an `execute`, `abort()` the task before the
  response arrives, queue the response on the mock, observe the counter bumps and `responses_stray` does NOT.
- `responses_stray` ticks for a queued frame with a msg_id that was never allocated.
- `responses_routed_ok` ticks for a normal execute.
- `responses_routed_err` ticks for a frame with a signature failure (also bumps `signature_failures`).
- `explicit_cancels_sent` ticks for `send_cancel`.
- `unsolicited_notifications_received` ticks for a queued frame with `MessageId::UNSOLICITED`.
- `status_pending_loops` ticks for a queued STATUS_PENDING + final response (via the mock-helper chosen in
  § "Mock STATUS_PENDING helper").
- `decrypt_failures` ticks via the existing `phase3_decrypt_failure_errors_waiter_not_hangs` shape — extended to also
  assert the counter is `1` after teardown (proves "counters survive teardown" invariant).
- `decompress_failures` ticks for a queued frame with a bogus compression header (mirrors decrypt test shape).
- `malformed_frames` ticks for a queued frame with a junk SMB2 header (after decrypt).
- `session_expired_events` ticks for a queued STATUS_NETWORK_SESSION_EXPIRED (and `responses_routed_err` bumps too).
- `dispatch` (Watcher's pre-arm path) bumps `requests_sent` and `wire_bytes_sent` exactly once per call.
- Routing outcomes are disjoint: for N sent requests with K dropped futures and L stray frames, assert
  `responses_routed_ok + responses_routed_err + responses_late_after_drop + responses_stray ==` total sub-frames routed.

`tests/diagnostics_snapshot.rs`:
- Pre-negotiate connection: `negotiated == None`, signing/encryption inactive, counters zero, `disconnected == false`.
- Post-negotiate: dialect, max_*_size, server_guid, etc. populated.
- One in-flight execute (blocked on never-arriving frame): `credits.in_flight == 1`.
- `Diagnostics: Send + Sync + Clone + Debug` (compile-time + a smoke `assert_send_sync!`).
- `Display` output contains the server name, the dialect, "credits", "wire bytes", "requests" — smoke, not byte-exact.
- With `--features serde`: `serde_json::to_string(&diag)` parses back into `serde_json::Value`; check a couple of nested
  keys (`primary.credits.available`, `primary.metrics.requests_sent`).
- Lock-order regression test: snapshot a connection holding `crypto`, then `waiters`, then `dfs_trees` (a trivial
  ordering check via `Mutex::try_lock` after the snapshot returns — confirms no lock left held).

### Integration tests (Docker, gated `#[ignore]`, runs in `just check-live`)

`tests/docker_integration.rs` additions:
- `smb-encryption`: snapshot → `encryption.active == true`, `encryption.cipher == Some(...)`,
  `wire_bytes_received > 0`.
- `smb-flaky`: force disconnect → `disconnected == true`, `responses_orphaned` may or may not tick, `requests_returned_err`
  ticks for the in-flight call.
- `smb-slow`: read a small file → `wire_bytes_received > 0`, `responses_received >= 1`, RTT estimate sensible.
- `smb-dfs-root` + `smb-dfs-target`: first op triggers referral → `client.metrics.dfs_referrals_resolved == 1`; second
  op via cache → `dfs_cache_hits == 1`. Extra connection appears in `diagnostics().extra_connections`.

### Real-hardware tests (manual, `#[ignore]`, not in CI)

`tests/integration.rs`: one extra test that dumps `diagnostics()` after a `read_file` from QNAP — purely smoke, to
verify the field values look sane on a real server. Not asserted on; the test prints and passes if no panic.

### Property / fuzz

None. The snapshot is `Relaxed` atomic loads + cloned primitives. No parsing.

## Doc updates

- `README.md`: add a "Diagnostics" section. Two snippets.
- `AGENTS.md`: short "Diagnostics" subsection under § Architecture.
- `src/client/CLAUDE.md`: M4 fixes plus a new "Diagnostics model" subsection summarising counters + lock order +
  invariants.
- `src/client/diagnostics.rs` top-of-file doc-comment: full lock order, eventual-consistency contract, "snapshot
  survives teardown", "counters reset across reconnect", "fields may skew".
- `CHANGELOG.md`: entry under Unreleased.

## What can be done in parallel

Sequential is fine. Only doc updates can run independently; save them for the end.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Counter increments on the hot path add overhead. | `AtomicU64::fetch_add(_, Relaxed)` is single uncontended cache line; ~1 ns. Re-run `bench_100_tiny_files_seq_vs_parallel` before/after M1; expect noise. If a real regression appears, the candidates are `wire_bytes_*` (one extra atomic per send/recv); easy to drop. |
| Snapshot consistency: fields skew. | Documented eventual-consistency contract on the public methods. Consumers who need atomicity quiesce ops first. |
| `serde` feature compile-time cost. | Optional, off by default. Plain derive on plain structs. Measure with `cargo check --features serde`; budget +50 ms. |
| Field additions break consumers. | `#[non_exhaustive]` on top-level types. Adding fields is minor; renaming is major. Document on rustdoc. |
| `Display` becomes a parse target. | Rustdoc says explicitly: "format is human-only and may change; use the `serde` feature for programmatic access." |
| Holding `crypto` lock briefly for the snapshot contends with the receiver task. | Receiver task takes the lock to verify signatures. Diagnostics hold it for ~50 ns to copy `bool + Option<algo enum> + Option<cipher enum>`. Measured negligible; documented. |
| Mock-transport STATUS_PENDING test design. | See § "Mock STATUS_PENDING helper" below — needs a small mock-side extension. |
| Counters reset across reconnect surprises consumers. | Documented on `SmbClient::diagnostics`. Consumers tracking long-running totals fold per-snapshot deltas into their own counters. |
| The compound-split counter site is more involved than other counters. | If the actor-internal "frames per fulfilled compound" plumbing turns out to be a thicket, downgrade `response_splits_observed` to a separate follow-up. Not load-bearing for M1/M2; can ship as a zero. |

## Mock STATUS_PENDING helper

Today's `MockTransport::enable_auto_rewrite_msg_id` pops one `pending_sent_msg_ids` entry per `receive()` call. A
STATUS_PENDING flow needs *two* responses (interim PENDING + final) for *one* sent request — the auto-rewrite FIFO
doesn't fit.

Two viable shapes; pick whichever is cleaner once implementing:

1. **`queue_pending_then_final(final_bytes: Vec<u8>)`** — pushes two responses tagged "pair". The mock's `receive()`
   pops the next sent msg_id once, reuses it for both responses, doesn't pop again on the second `receive()`. Requires
   a small `ResponseRecord` enum extension on the mock: `{ Single(bytes), PairFirst(bytes), PairSecond(bytes) }` so the
   second member knows to reuse the prior msg_id.

2. **`peek_next_pending_msg_id() -> Option<MessageId>`** — read-only peek into the FIFO. Test code calls it after the
   `dispatch` future has registered the waiter, builds both response frames with the peeked msg_id, calls
   `queue_response` twice with auto-rewrite OFF. More invasive at the call site, but no enum extension.

Decision goes to whichever lands smaller; M1's STATUS_PENDING test is the only consumer until proven otherwise. The
plan tracks the constraint here so the implementer doesn't discover it mid-test.

## Backwards compatibility

- New types only.
- Two new public methods (`Connection::diagnostics`, `SmbClient::diagnostics`). Additive.
- New optional `serde` feature, off by default. Doesn't affect anyone not opting in.
- Per-type `cfg_attr(feature = "serde", derive(Serialize))` on a handful of existing public types — additive even with
  the feature on.
- `#[non_exhaustive]` on top-level types so future field additions are minor.

## Open questions (resolved)

- **Reset/clear counters?** No. Monotonic. Diff snapshots for rate.
- **Per-NTSTATUS histogram?** Not now. Possible as a future optional field, gated behind a sub-feature.
- **Track open file handles?** No. Library doesn't own them. Caller folds in.
- **SMB3 multi-channel?** Not implemented. "Channels" in smb2 here means open *connections* (primary + DFS-extra) plus
  the in-flight set on each.
- **Add `tracing` spans?** No. Keep `log`. A `tracing` feature can land later without touching diagnostics.
- **Polling vs event stream?** Snapshot only. State is state-shaped; events that exist (oplock break, session expiry,
  DFS failover) already log. Polling at 1 Hz is essentially free. See "Why".

## Done means

- `Connection::diagnostics()` and `SmbClient::diagnostics()` are public, documented, tested.
- All counters listed under `Metrics` and `ClientMetrics` are wired, including the `dispatch` path.
- `Display` impl renders the example shown above (close — exact wording is editorial).
- `serde` feature compiles green; JSON round-trip test passes; `Capabilities` serializes as bits.
- `examples/diagnostics.rs` runs against a Docker container and prints a sensible snapshot.
- `just check` green; `just check-live` green; `just test-docker` green.
- `README.md`, `AGENTS.md`, `src/client/CLAUDE.md`, `CHANGELOG.md` updated; M4 stale gotcha removed.
- Counter set documented as eventually consistent, surviving teardown, resetting on reconnect.

## Plan v3 changes (vs v2)

Addresses second-round fresh-eyes review (Opus). Material changes:

1. **Caller-drop counter rewired to the correct receiver-loop branch.** v2 incorrectly attributed caller-drop to the
   `None` branch (msg_id not in map). The actual branch is `Some(tx)` + `tx.send().is_err()`. Counter set split:
   - `responses_routed_ok` — `Some(tx)` + delivered Ok
   - `responses_routed_err` — `Some(tx)` + delivered Err (signature / session-expired)
   - `responses_late_after_drop` — `Some(tx)` + send failed (caller-drop)
   - `responses_stray` — `None` (true orphan)

   Disjoint by construction; their sum equals every sub-frame whose msg_id was looked up.
2. **`wire_bytes_sent` enumerated correctly via a helper.** v2 listed "four sites plus cancel" but the actual count is
   ~10 once compressed/encrypted branches are included. Added a private `Inner::send_and_count(bytes)` helper that
   wraps `sender.send` and bumps the counter. Every `inner.sender.send(...)` call site flips to it. Can't drift.
3. **`response_splits_observed` deferred to a follow-up.** v2's site ("caller-side compound assembly") was
   hand-waved against an actor model that doesn't carry the needed metadata. Wiring it requires "source-frame-index"
   tagging through the demux — not in scope for this PR. The DEBUG log line in the receiver loop still aids manual
   diagnosis today.
4. **`decompress_failures` added.** v2 had counters for decrypt and malformed but not for the decompress fatal-frame
   branch (`connection.rs:~1325`). Added its own counter so each of the four fatal-frame paths has a distinct
   attribution.
5. **`malformed_frames` scope made explicit.** Covers both the `split_compound` parse-failure branch and the
   `prepare_sub_frame` parse-failure branch. Documented on the field.
6. **`requests_sent` includes negotiate / session-setup messages.** Funnel-counted via `allocate_msg_id`. Documented on
   the field so consumers aren't surprised by non-zero counts pre-app-traffic.
7. **`requests_returned_err` per-compound, not per-sub-op.** Disambiguated in the field comment: outer Err only; inner
   per-sub-op errors don't tick it.
8. **`session_expired_events` per sub-frame** explicitly documented (compound with N expired sub-ops ticks N times).
9. **Lock order corrected.** Removed `params` (it's `OnceLock`, not a mutex). Listed only the locks the snapshot
   actually touches. Added a note about `preauth_hasher` / `receiver_task` not being touched by the snapshot.
10. **`Display` showcase output rewritten with raw `u64` byte counts** so it matches the "Display is raw" contract.
    Humanized example moved to a sentence about `examples/diagnostics.rs`.
11. **Mock STATUS_PENDING helper specified concretely.** Two viable designs documented; implementer picks the smaller.
    Previous version promised a helper that couldn't work against existing `auto_rewrite` mechanics.

Plan v2 vs v1 changelog (kept for history):

1. Per-DFS-target session model: `SessionDiagnostics` moved onto `ConnectionDiagnostics::session`.
2. `dispatch` path counted: `requests_sent` ticks inside `allocate_msg_id`.
3. v2 introduced `responses_orphaned` to "capture caller-drop" — v3 corrects the branch (see #1 above).
4. Byte semantics: wire-layer (post-encrypt on send, pre-decrypt on recv).
5. v2 renamed `compound_splits` → `response_splits_observed`; v3 defers the counter entirely.
6. `oplock_breaks_received` → `unsolicited_notifications_received`.
7. Counter teardown invariant documented.
8. Reconnect counter-reset semantics documented.
9. Lock order initially specified (corrected in v3 #9).
10. `#[non_exhaustive]` vs `PartialEq`: no `PartialEq`, `#[non_exhaustive]` only on top-level containers.
11. `humanize_bytes` moved to the example binary.
12. Re-used types serde audit with per-type plan; `Capabilities` manual `Serialize`.
13. `--json` flag without `serde`: stderr error + exit 2.
14. Example binary in `examples/`; docker integration tests in existing `tests/docker_integration.rs`.
15. "Subscribe vs poll" rationale spelled out in "Why".
16. `Display` impl on top level only.
