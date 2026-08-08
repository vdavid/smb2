# Changelog

All notable changes to smb2 will be documented in this file.

The format is based on [keep a changelog](https://keepachangelog.com/en/1.1.0/), and we use
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [0.18.1] - 2026-08-08

### Fixed

- **A process that stops running no longer gets a healthy server declared dead.** Every liveness clock in the crate measures wall time, which quietly assumes the process was running to hear the silence it is measuring. A system sleep, an App Nap, or a machine starved by a parallel build breaks that assumption: the loops stop, `Instant` keeps advancing, and the first tick after the freeze reads minutes of "server silence" that nobody was listening to. The verdict that followed was `Error::ServerUnresponsive` against a NAS that had been answering the whole time, every waiter failed, and the session torn down and rebuilt. A consumer watching a directory saw it three times in twelve minutes on a busy dev machine (freezes of 62 s, 175 s, and 355 s), and **a closed laptop lid produces the same shape on any machine**, which is what makes this worth a patch release rather than a dev-box curiosity.
  - **The witness is cadence, and it was already there.** Every loop on a connection wakes on a keepalive tick or faster, so a gap since the last one that exceeds the probe threshold on top of the tick is this process, not the server. `Inner::forgive_scheduling_stall` shifts `last_frame_at` and every waiter's timestamps forward by that gap, which is exactly the statement "nothing aged while we were gone".
  - **It forgives, it never exonerates.** The clocks restart and the ECHO probes restart with them, so a server that really is dead is declared dead one response deadline later. Suppressing the verdict instead would have traded a false death for a permanent hang, which is the worse of the two.
  - **Checked by every loop, not just the keepalive task.** They all wake from the same stall at the same instant, so `await_response` and `await_long_poll` each correct before reading a clock. The correction is idempotent; whoever gets there first does it.

### Changed

- **`Error::ServerUnresponsive` is logged at `warn` instead of `error`, and says what to check.** The crate reconnects itself, and an `error` a library heals on its own teaches consumers to filter the level out. It stays above `info` because the reader does have somewhere to look: the wire is up, so this is a server that accepted a session and then served nothing. The line now names the command and message id it was waiting on, replacing a duplicate pair of lines that reported the same silence twice.

### Added

- **`MetricsSnapshot::scheduling_stalls`**, the only counter here about the process rather than the server. Read it before blaming a burst of `response_timeouts` on the network. `Connection::diagnostics()` prints it only when non-zero.

## [0.18.0] - 2026-08-05

### Breaking

- **`\` in a path is a name character now, not a second separator.** It has to be: an SMB2 name cannot contain a literal backslash, so carrying one means mapping it to U+F026 (see *Fixed* below), and one string cannot mean both separator and character. `/` is the separator. A caller passing `"dir\file.txt"` used to reach `dir\file.txt` and now asks for a single file whose name contains a backslash. **This is the one thing to check when upgrading**: search your call sites for `\`-separated paths and switch them to `/`. It fails loudly rather than quietly on reads -- a depth-50 navigation test in this repo caught it with `STATUS_OBJECT_NAME_INVALID` -- but a `write_file` with a `\`-separated path will create an oddly named file rather than erroring.

- **`FileNotifyEvent::filename` reports `/` separators and decoded names.** It used to carry the server's raw `\`-separated form, so a recursive watch's path can now be joined onto the watched directory's path and handed straight to any `Tree` method. Code that split it on `\` needs to split on `/`.

- **`delete_directory` returns an error for a non-empty directory instead of reporting success.** It used `FILE_DELETE_ON_CLOSE`, and against Samba a delete-on-close CREATE on a non-empty directory answers `STATUS_SUCCESS` for both CREATE and CLOSE and then deletes nothing -- so the crate logged "deleted directory" and returned `Ok(())` while the directory was still there. A consumer clearing 4,883 directories was told every one of them worked; none had. The compound is now CREATE + SET_INFO (`FileDispositionInformation`) + CLOSE, still one round trip, and the server validates while it still has somewhere to put the error. Code that relied on the old `Ok(())` now sees `STATUS_DIRECTORY_NOT_EMPTY`, which is the truth it was missing. Verified against the Docker fixtures and a live Samba 4 on Debian trixie.

### Fixed

- **A file whose name carries `?`, `*`, `"`, `:`, `<`, `>`, `\`, `|`, or a trailing space or period can now be written to a share at all.** SMB2 borrows its name syntax from Windows, so those eight characters are wildcards or separators in the protocol's own grammar and are illegal in a name, along with the control characters and a trailing space or period. The crate put such a name on the wire verbatim and the server answered `STATUS_OBJECT_NAME_INVALID` (0xC0000033), which no amount of retrying could fix. A real QNAP Samba share refused `"how_are_you_feeling?"_emojis.json` this way.
  - **The fix is the one every SMB client carrying POSIX names has used since Services for Macintosh**: substitute each illegal character with a code point in the Unicode private-use area at U+F000 on the way out, and substitute back on the way in. The server stores an ordinary legal name and never knows it happened. **No server-side configuration is involved.**
  - **The table is an interop contract, not a design choice.** macOS smbfs does exactly this, so a file written through this crate and the same file written through Finder have to land on the same on-disk name or the two clients disagree about what a share contains. It was derived empirically -- probe files created through a macOS `/Volumes` mount, on-disk bytes read back over SSH on a QNAP TS-464 (2026-08-05) -- rather than from a spec: `"` → U+F020, `*` → U+F021, `:` → U+F022, `<` → U+F023, `>` → U+F024, `?` → U+F025, `\` → U+F026, `|` → U+F027, trailing space → U+F028, trailing period → U+F029, control `0x01`–`0x1F` → U+F001–U+F01F. Two details a table copied from memory gets wrong: the trailing rule applies to the **last character of each path component and only that one** (`"a.. "` is one substitution, not three), and a private-use code point already in a name travels unescaped.
  - **Always on, and public.** For a name with nothing to map -- almost every name -- encoding is the identity and returns the input borrowed. For a name with something to map, the mapped form is the only form the server accepts, so there is no competing correct behavior to offer and no switch to get wrong. `smb2::name::{encode_name, decode_name, encode_path, decode_path}` are public for anyone who wants the literal wire form.
  - **Mapped per path component, decoded everywhere a name arrives.** Directory listings (`DirectoryEntry::name`) and change notifications (`FileNotifyEvent::filename`) both decode; share names, tree-connect paths, DFS server and share fields, the `srvsvc` pipe name, and the `*` search pattern are deliberately left alone. An encode/decode asymmetry would be worse than no mapping at all, so the audit for it was the bulk of the work.
  - **Where the round trip is not exact is documented in the `name` module**, and both gaps match macOS: a local name already holding U+F001–U+F029 reads back as the character it stands for, and a wire name carrying U+F028/U+F029 mid-component decodes to a space or period that re-encoding will not restore. U+F000 is deliberately outside the table -- decoding it would hand you a name with an embedded NUL, which truncates in every C API it reaches, and macOS does exactly that.

- **`Tree::download`, `SmbClient::upload`, and `SmbClient::write_file_streamed_with_progress` never applied the `server\share\` prefix a DFS share needs.** Each carried its own copy of the old path normalization instead of going through `Tree::format_path`, so all three would have opened the wrong path on a DFS tree (and none would have got the new mapping either). `SmbClient::upload` also normalized and then handed the result to `write_file_compound`, which normalizes again -- harmless while normalizing was idempotent, corrupting once a mapping exists. The public `Tree::open_file`, `open_file_for_write`, `open_file_for_exclusive_create`, and `open_file_readwrite` never normalized at all, so a consumer calling them directly put a raw `/` on the wire. Every method that accepts a caller path now formats it at its own boundary, and nothing passes a formatted path to another method.

- **A server that answered a compound chain with fewer frames than it had sub-requests was a panic waiting to happen.** `all_or_first_err` now takes the expected frame count and errors on a mismatch; every caller indexes fixed positions (`responses[2]`) right after it returns.

### Added

- **`ErrorKind::InvalidName`**, and `NtStatus::OBJECT_NAME_INVALID` to go with it. The status was missing from the table, so it rendered as bare hex in every log line and classified as `ErrorKind::Other`. The old doc comment said it fell through "because no consumer needs to branch on it", which is no longer true: a file manager that just failed a copy wants to distinguish a name this server cannot store (rename and retry) from a generic protocol error (don't). Rarer now that the mapping handles the characters SMB2 forbids outright, but still reachable -- a reserved Windows device name, a name past the server's length limit, a character the server's filesystem cannot hold. `ErrorKind` is `#[non_exhaustive]`, so this is not a breaking change.

- **`smb-weirdnames`, a 15th internal Docker fixture** (port 10459), seeded with filenames whose *on-disk bytes* are the ones macOS smbfs writes. Real Finder cannot run in Linux CI, so those pinned bytes stand in for it: a listing that comes back with the plain characters proves the two clients agree. `weirdnames_what_this_crate_writes_is_what_finder_writes` checks the other direction, requiring an exclusive create of a name the fixture already holds to fail with `AlreadyExists` -- an encoding off by one code point would create a second file and pass on an `Ok`. Ten tests cover every character in every position, multiple substitutions in one name, illegal characters in directory components, control characters, the trailing rule taking the last character only, emoji/CJK/NFC-vs-NFD names proving nothing else is disturbed, a full write → list → read → stat → rename → delete round trip, and CHANGE_NOTIFY as its own decode site.

- **The consumer fixture `smb-consumer-unicode` carries them too**, so an app depending on smb2 can test the case without building its own server. It previously held only CJK, emoji, accents, Cyrillic, and Arabic -- all perfectly legal SMB2 names, which is why the fixture that looks like it covers "weird filenames" never caught this.

- **`fuzz_name_round_trip`**, the first target in `fuzz/` that asserts a property rather than "does not panic": `decode(encode(name)) == name` over arbitrary UTF-8, plus "nothing SMB2 rejects survives an encode". 2,375,202 executions found nothing.

- **`NtStatus::DIRECTORY_NOT_EMPTY`**, so it prints as a name rather than `0xC0000101`.

### Changed

- **`delete_files`, `rename_files`, and `stat_files` are loops over the single-item methods**, not three hand-inlined copies of the same compound. No API change and no behavior change beyond the `delete_directory` fix above; ~500 lines go away, and the next fix of that shape lands in one place instead of two.

- **The Docker test fixtures publish on `127.0.0.1`, not `0.0.0.0`.** Both harnesses used Docker's default, so running the tests put 29 unauthenticated Samba servers (guest shares included, one writable) on the LAN and tailnet of whoever ran them, for as long as the containers lived. `SMB_BIND_ADDR=0.0.0.0` is the escape hatch for an SMB client that isn't on the Docker host, notably a NAT'd VM reaching the host by gateway IP. ⚠️ **Consumers vendoring the fixtures have to change it at the source and re-vendor**: Compose *concatenates* `ports` across override files rather than replacing them, so an override collides on the host port instead of rebinding it.

- **The batch and pipeline docs stopped promising overlap the crate doesn't do.** `delete_files`, `stat_files`, and `rename_files` (on both `SmbClient` and `Tree`) claimed to send every request before waiting for responses; they issue one round trip per item and wait for each. `Pipeline`'s module doc advertised filling the credit window while its own struct doc said it runs sequentially. Corrected everywhere including `README.md`, with what these APIs are actually for: they save the per-call setup, not wire time, and real overlap comes from several connections.

### Notes

- **No Unicode normalization, deliberately.** macOS smbfs converts decomposed names to NFC before sending (verified the same way, same date) because its local filesystem stores NFD. A cross-platform crate has no such local form to convert from, and an NFD name is perfectly legal on the wire, so this crate sends what it is given. A macOS consumer that wants byte-for-byte Finder parity should normalize to NFC before calling.

## [0.17.1] - 2026-08-05

### Changed

- **`DEBUG` belongs to the application again: an idle connection now logs essentially nothing.** The crate emitted one `DEBUG` line per SMB request, so a consumer that turned on `smb2=debug` to debug its own code got the crate's packet trace instead. Measured over one representative hour on a single NAS with about 12 short-lived connections, mostly idle background watching: 2,150 lines, of which 1,008 were keepalive `ECHO` dispatches, 666 were long-polling `CHANGE_NOTIFY` dispatches, and 255 were interim `STATUS_PENDING` responses. Nothing was happening. The same hour now produces well under 150 lines, and the volume no longer scales with frames on the wire, so a bulk copy or a deep tree walk stops flooding the consumer's log file too.
  - **Per-request and per-response plumbing moved to `TRACE`**, which is where the crate's own convention already put it: `dispatch`, interim `STATUS_PENDING` responses, `send_cancel`, the `pipeline:` operation entries, `stream:` handle opens, the `shares:` and `dfs:` RPC frame steps, and the Kerberos and NTLM key and ciphertext lengths. Turn on `RUST_LOG=smb2=trace` for a packet-by-packet trace; nothing is gone.
  - **The read path moved to `TRACE` as well**: `stat`, `fs_info`, single-round-trip reads, and opening a handle. Reads change nothing and are exactly what a polling consumer does constantly. Mutations stay at `DEBUG`, one line each, and so does one summary line per multi-round-trip transfer with its byte count and MB/s.
  - **A watch that has nothing to report says so at `TRACE`.** An empty `CHANGE_NOTIFY` response is a refresh handover, not an event; on an idle directory that was most of them. Actual events still log at `DEBUG`.
  - **`INFO` is back to protocol milestones only.** Per-file mutations (`tree: created directory`, `tree: deleted`, `tree: renamed`, both batch variants, and `durable: opened with a durable handle`) were logging at `INFO`, so deleting 5,000 files produced 5,000 `INFO` lines; they're `DEBUG` now. The `smb_client:` connect and reconnect lines duplicated the `connection:`, `session:`, and `reconnect:` lines that follow them, so a single connect announced itself six times at `INFO` and now does it four: connected, negotiated dialect, session established, tree connected.

### Notes

- **The rule is written down now**, in `AGENTS.md`: no site at `DEBUG` or above may fire at a rate proportional to the number of frames on the wire, one `DEBUG` line per consumer-visible operation rather than a start/done pair, and `INFO` gets one line per protocol milestone and nothing else. An idle connection is the test case: keepalives and long polls must produce nothing at `DEBUG` when they're working. Without the rule stated, this drifts back.
- **Log levels aren't API, so this is a patch.** No signature, type, or wire behavior changed. If you grep your logs for specific smb2 lines, the ones that moved are listed above; the message text is unchanged in every case except the empty-watch line, and everything still exists at some level.

## [0.17.0] - 2026-08-03

### Fixed

- **`Connection::send_cancel` never actually cancelled anything on an SMB 3.1.1 server negotiating AES-GMAC.** The GMAC signature nonce carries a bit for "this message is an SMB2 CANCEL" (MS-SMB2 § 3.1.4.1) and the crate signed every cancel with it cleared, so the server refused the request. A CANCEL has no success response, so the refusal was invisible: `explicit_cancels_sent` ticked while the server went on holding the operation. The matching read is fixed too -- the server's rejection response is itself a CANCEL-command frame, so verifying it with the bit cleared reported a `signature_failures` tick and a protocol-anomaly log line instead of the one frame that said the cancel had not taken.
  - Found by running the new watch refresh cycle against a QNAP TS-464 (2026-08-03): with the bit missing, every cancel was refused, the abandoned CHANGE_NOTIFYs stayed registered, and the directory watch stopped delivering events entirely. With it set, the same watch survived three cancel-and-re-issue rounds and reported the change. **Only AES-GMAC signing is affected** — HMAC-SHA256 and AES-CMAC don't use a nonce, so SMB 3.0/3.0.2 and any 3.1.1 server that didn't negotiate GMAC were never wrong.

### Added

- **A directory watch now heals itself when a server quietly drops the subscription.** Every liveness verdict this crate reaches is about the *connection* -- the ECHO probes, `quiet_for`, `unresponsive_for`, and the long-poll bound built on them. A server that keeps answering everything while it has silently forgotten one CHANGE_NOTIFY is, to all of them, perfectly healthy, so the watch waited on an event that could never arrive with nothing anywhere able to say so. Measured on a QNAP TS-464 (2026-08-03): two CHANGE_NOTIFY requests outstanding for 6,186 s, while `fs_info` on the same connection round-tripped in 4 ms and every ECHO probe was answered.
  - **This cannot be detected, so it isn't.** A subscription the server has forgotten and a directory nobody has touched produce the identical observation: nothing. Hours of silence is the healthy case -- it is why CHANGE_NOTIFY is exempt from the response deadline in the first place -- so any rule that "notices" a dead watch also ends live ones. Instead the client stops relying on one subscription surviving indefinitely: `Connection::set_long_poll_refresh` (10 minutes, on by default) retires each request and issues a fresh one, and a server-side loss heals within a cycle with no verdict to get wrong.
  - **The wire is never left unarmed.** The replacement goes out before either retirement, so the pipelined watcher's guarantee -- the server always has an outstanding request to deliver events into -- holds through the handover. Strict servers (older Samba, NAS firmware) drop events that land in such a gap, which is the bug the pipelining was written to fix.
  - **Retired requests are CANCELled properly.** A request the server has answered with an interim `STATUS_PENDING` has been assigned an `AsyncId`, and a cancel that does not carry it matches nothing (MS-SMB2 § 3.2.4.24) -- so without this the server would keep every subscription the cycle walked away from, one more per interval for the life of the watch. The client now records the `AsyncId` from the interim response and cancels with it.
  - **Cost and settings.** Three frames per cycle per watched directory. `set_long_poll_refresh(None)` restores the old behavior, which suits a consumer that re-creates its own watchers on a schedule. Watch `MetricsSnapshot::long_poll_refreshes` to see cycles happening -- it counts handovers, never faults. ❌ Shortening the interval detects nothing faster; there is nothing to detect.
  - **No API breaks.** `Connection::set_long_poll_refresh` / `long_poll_refresh` and `MetricsSnapshot::long_poll_refreshes` are new; `OutstandingRequest` gained an `async_id` field (a struct nothing constructs outside the crate); `Connection::send_cancel` relaxed from `&mut self` to `&self`, which accepts strictly more callers. `Watcher::next_events` behaves the same from the outside: a refresh is a handover, so the caller never sees one.

### Changed

- **A parked CHANGE_NOTIFY is no longer logged as a stalled request.** The stale-request sweeper's every line means "this should have come back by now", which for a long poll is false by construction -- the deadline exempts it precisely because hours of silence is healthy. Warning about it every 10 s anyway was the sweeper contradicting the deadline, and at that volume it buried the lines that matter: a file manager watching two panes logged 5,911 `WARN`s in six hours about requests nothing was ever going to answer.
  - They stay observable, in the two places worth being observable: at `TRACE` on every sweep, and named in full at `WARN` whenever a genuine stale request is reported, because a wedge investigation wants the whole in-flight picture rather than a filtered one. The per-request naming that the 2026-07-31 incident asked for is untouched for every command that can actually stall.
  - With the refresh cycle above, a long poll no longer stays parked longer than the interval either, so the state the old lines described is now bounded rather than perpetual.

### Notes

- **Nothing breaks, and a minor bump anyway.** `MetricsSnapshot` and `OutstandingRequest` are both `#[non_exhaustive]`, so their new fields are additive, and `send_cancel` relaxing from `&mut self` to `&self` accepts strictly more callers. The bump is minor because the behavior on the wire changes for everyone holding a `Watcher`: a subscription is now cancelled and re-issued every 10 minutes where it used to sit forever. Nobody should have to discover that from a patch release.
- **Nothing to do to adopt it.** The refresh is on by default and `Watcher::next_events` looks the same from the outside — a handover is not an answer, so the caller never sees one. `Connection::set_long_poll_refresh(None)` restores the old behavior if a consumer would rather manage its own watcher lifetime.

## [0.16.1] - 2026-08-02

### Fixed

- **A `Watcher` on a silent-but-open session is finally told, instead of watching a dead server forever.** 0.16.0 bounded CHANGE_NOTIFY by connection-wide silence rather than by its own deadline, which is the only thing that can end a wait for an event that may never come. That bound lives in `Connection::await_response`, and `Watcher::next_events` was the one caller that never went through it: it awaited its `WaiterGuard` directly, and `recv()` is a bare `oneshot` await with no deadline of any kind. So the single production consumer of the long-poll bound was the one thing it did not protect, and a watcher whose server stopped answering on a still-open socket waited silently forever -- the exact failure the feature was written to end.
  - **Only the long-poll path could reach this.** Every other operation in the crate already finished through `Connection::await_response` and was bounded the whole time, so if you don't hold a `Watcher`, 0.16.1 changes nothing you can observe. Directory watching is the entire blast radius.
  - Measured against a real Samba (Raspberry Pi 4, Samba 4.9.5) with its `smbd` suspended: 90.3 s of connection-wide silence and 17 consecutive unanswered ECHO probes left the watcher none the wiser. Through `await_response` it is now told at 30.1 s -- the response-deadline budget, as documented. A 20 s stall (25.0 s of silence, three missed probes) still correctly survives.
  - **Nothing else changes.** The bound was already there and already tested; only the path to it was missing. A watch on a healthy server is unaffected: on a QNAP TS-464 saturated with concurrent streamed writes, the connection's longest gap without a frame stayed at the 5 s probe cadence, six times under the 30 s bound.
  - **No API changed**, so this is a drop-in patch. `Connection::await_response` widened from private to `pub(crate)`, which is invisible outside the crate. The one behavior change a consumer can see is that `Watcher::next_events` can now return `Err(Error::ServerUnresponsive { .. })` where it previously never returned at all; `Error` is `#[non_exhaustive]` and that variant shipped in 0.16.0, which already promised this. Handle it like `Error::Disconnected` (both are `ErrorKind::ConnectionLost` and both report `is_retryable() == true`): re-establish the session and re-register the watch.
  - The regression test drives a real `Watcher` rather than `Connection::execute` with a CHANGE_NOTIFY body. The two existing long-poll tests use `execute`, which is why they passed throughout: they exercised a path no consumer takes.
  - Evidence, the per-server silence numbers, and the deterministic `SIGSTOP` recipe: `docs/notes/watcher-silence-tolerance.md`, reproducible via `examples/liveness_probe.rs`.

## [0.16.0] - 2026-08-02

### Breaking

- **`Connection::params()` and `SmbClient::params()` return `Option<NegotiatedParams>` instead of `Option<&NegotiatedParams>`.** A connection revived on a fresh socket renegotiates from scratch, and a rebooted server may come back with a smaller `MaxWriteSize` or a different dialect, so the parameters can no longer live in a `OnceLock`. Every field is a plain scalar, so the copy costs nothing. Call sites of the shape `.map(|p| p.max_write_size)` or `.unwrap().dialect` are unaffected; only code binding `&NegotiatedParams` explicitly needs a touch (drop the `&`, or drop a now-redundant `.clone()`).
- **`SmbClient::reconnect()` no longer replaces the underlying `Connection`.** It revives the existing one in place, so `Connection` clones a consumer was holding stay usable instead of being permanently dead. Tree connects and file handles are still invalidated — they belong to a session that no longer exists — so callers must still `connect_share` again.
  - **The error you get from misusing a stale handle changes.** Before, an old clone was dead and everything through it failed `Disconnected`. Now the clone is alive on a *new* session, so a stale `FileId` or `TreeId` reaches the server and comes back as a protocol status (`STATUS_FILE_CLOSED`, `STATUS_NETWORK_NAME_DELETED`) instead. Not a data-safety change — a fresh session's open table can't resolve another session's handle — but if you were treating `Disconnected` as "I must have used a stale handle", that signal has moved. `Connection::generation()` is the reliable one: it changes on every successful revival.

### Added

- **`ClientConfig::auto_reconnect` finally does what its name says.** It has been stored and ignored since the crate's first release; its own doc admitted the logic "will be implemented alongside the concurrent pipeline". Setting it now arms the connection with a reviver built from the same config, so a session that dies — a NAS rebooting, a Wi-Fi roam with no TCP reset, a share briefly offline — is re-dialed, re-negotiated, and re-authenticated. The ECHO keepalive in this same release turned a permanent wedge into a clean error, which is better and still a failed transfer; this is the part where the transfer survives.
  - **The revival happens in place, under the handles that outlived the connection.** `FileWriter`, `FileReader`, `Watcher`, and every pipelined task own a `Connection` clone. Minting a fresh `Connection` on reconnect would leave every one of them dead and force the consumer to rebuild the world, which is reporting the blip with extra steps.
  - **It cannot become an unbounded retry.** `ReconnectPolicy` (4 attempts, 0.5 s backoff doubling to 8 s, 60 s total, 10 s failure cooldown) bounds attempts, backoff, and wall clock. The budget wraps the *entire* revival rather than each attempt, because a per-attempt timeout multiplies by the attempt count and an attempt that parks forever never reaches the second one. A failed revival's verdict stands for a cooldown, so a 32-deep pipeline doesn't pay the budget 32 times over. Exhaustion surfaces as `Error::ReconnectFailed`.
  - **The 60 s default is sized for what actually recovers** — a Wi-Fi roam, a share flapping, a switch relearning a port — and deliberately *not* for a full NAS reboot. Sitting on a frozen transfer for minutes on the chance the box comes back is the behavior this whole effort exists to delete.
  - **Only work whose retry cannot change what you asked for is replayed.** Directory listings, reads, `stat`, and `fs_info` re-run with the tree re-connected in place. A `delete`, `rename`, `create`, or write that died in flight may already have taken effect on the server, so it surfaces the error and lets you decide — the library has no way to tell, and guessing about your data is not its job.
- **Durable handles, so an interrupted write resumes instead of restarting.** `Tree::open_file_durable` asks the server to keep an open alive across a disconnect; `Tree::reclaim_durable_handle` claims it back on the new session.
  - **A reclaim is two independent proofs, and anything less fails.** Reclaiming the wrong handle writes your bytes into the wrong file, which is far worse than a failed transfer. The `DH2C` context carries a `CreateGuid` this client chose at open and the server stored with the open (MS-SMB2 § 3.3.5.9.12), so a grant means it found *your* open; and a compounded `QUERY_INFO` says which file the handle points at, read at open and again after the reclaim. Both must hold, or the handle is closed and `Error::DurableHandleLost` says which guarantee didn't.
  - **SMB 2.1's v1 durable handles are deliberately not implemented.** They identify the open by nothing but the server-allocated `FileId`, so a server that recycles ids across a restart could hand back a different file. On SMB 2.1 a dead session means the transfer restarts.
  - **Everything degrades quietly.** A pre-SMB3 server, durable handles switched off, a share that declines the batch oplock, a server that won't answer the identity query: all produce an ordinary working handle with `DurableOpen::durable == None`, never an error.
  - Verified end to end against Samba 4.20.6: a handle granted, the connection dropped and re-established on a fresh socket with a new NTLM session, and the handle claimed back with both proofs intact.
- **Oplock breaks are now acknowledged.** A batch oplock is the price of a durable handle (MS-SMB2 § 3.3.5.9.10), and while a client holds one, anyone else opening the file waits out the server's break timeout — about 35 s on both Samba and Windows. Breaks used to be logged and dropped. Acknowledging gives the oplock up and therefore the durability, which is the right trade: a resumable transfer is worth less than freezing somebody else's file operation for half a minute. **Only handles from `open_file_durable` ever hold an oplock**, so nothing changes for code that doesn't opt into durable handles.
- **`Connection::set_reviver` / `can_reconnect` / `reconnect_if_needed` / `mark_dead` / `is_disconnected` / `generation`**, plus `set_reconnect_policy` and `on_reconnect`. `SmbClient` mirrors the last three.
- **`ReconnectEvent`, pushed via `Connection::on_reconnect`.** A counter says how flaky a link has been to whoever polls it later and a log line is for a human reading a bug report; neither can put "reconnected to the NAS, resuming" in front of someone watching a progress dialog. The observer must not block or call back into the connection.
- **`MetricsSnapshot::reconnect_attempts` / `reconnects_succeeded` / `reconnects_failed`.** `reconnects_succeeded` is the after-the-fact answer to "was this link quietly flaky?" — a transfer that finished with a non-zero value survived something the user never saw, and the number is there whether or not anyone subscribed to the events.
- **`Error::ReconnectFailed { attempts, waited, cause, reason }`** and **`Error::DurableHandleLost { path, reason }`** with a typed `DurableLoss`. Both classify as `ErrorKind::ConnectionLost` and report as retryable. `reason` on `ReconnectFailed` is display text for a human; branch on `cause` (`Error` is `#[non_exhaustive]`, so neither breaks compilation).
- **`msg::create_context`**: the CREATE context codec plus `DH2Q` / `DH2C` (durable handles v2) and `QFid`, pinned against the `smb-rs` reference implementation's wire vectors and hardened against a chain that points outside itself.
- **An SMB2 ECHO keepalive, so "slow" and "dead" stop looking the same.** In one sentence: **the keepalive tells the response deadline whether the server is alive, and an alive server gets more time.** A deadline on its own cannot tell those apart, so it has to be sized for the slowest healthy case, which makes it a poor detector of the dead one: a large write to a loaded spinning-disk NAS gets killed for being slow, while a genuinely dead session freezes a transfer for the full deadline. ECHO settles it — it touches no share, no handle, and no disk, so an answer means the server is processing requests, full stop.
  - **On by default (5 s), because it can only ever hand time out.** A request on a connection ECHO has just proven alive gets six times the response deadline (3 minutes at the defaults) before being abandoned; a probe the server ignores simply leaves that extension ungranted. `MetricsSnapshot::response_deadline_extensions` counts every request this rescued.
  - ❌ **A missed probe never ends anything.** That is the safety property the whole design turns on. A real NAS drops ECHO probes precisely when it is busy writing, which is exactly when a transfer is running (measured on the QNAP TS-464 from the original incident: two answered, one dropped, under write load), so a keepalive that could declare a session dead would tear connections down during the transfers it exists to protect. The worst a dropped probe can do is decline to be generous.
  - **It measures silence, not elapsed time.** A connection with responses flowing never probes at all, so a busy transfer pays nothing for this, and an idle connection isn't probed either because there is no work to protect. It only ever fires on the shape that wedges: requests outstanding, wire quiet.
  - **A probe answered with an error still counts as alive.** `STATUS_NETWORK_SESSION_EXPIRED` is the realistic case: the session needs re-establishing, but the server put a frame on the wire, which is the only question the probe asks. Reading it as death would retire the keepalive for the life of a connection a consumer is about to re-authenticate on, and silently — nothing announces a keepalive that stopped.
  - **Independent of `auto_reconnect`.** This decides how patient a deadline is; that decides whether a dead session gets re-dialed. Neither switches the other on.
  - Verified against real Samba in guest, NTLM, and mandatory-signing modes: all three answer the probe as constructed, with the session id set and signed to match the session. ⚠️ A fourth mode was originally claimed here as "mandatory encryption"; that claim is withdrawn — see Notes, the encryption fixtures do not actually negotiate encryption, so no test in this repo has ever exercised the probe (or anything else) on an encrypted session.
- **`Connection::set_keepalive(Option<Duration>)`** (default `Some(5 s)`) — how much server silence, with a request on the wire, triggers a probe. `None` turns it off, and with it two things: the deadline extension (with nothing refreshing the liveness clock, a fresh reading is luck rather than evidence, and a deadline extended on luck is the hang coming back) and `Error::ServerUnresponsive`, since "nobody could get a word out of this server" is a claim only probing can support.
- **`Error::ServerUnresponsive { silent_for }`** — the socket is up and the server is answering nothing at all. It is `Error::Timeout` with a second fact attached: a request burned its whole deadline *and* the connection produced no frame of any kind meanwhile, not even an answer to a probe. One stuck operation cannot look like that, so the connection is torn down and every other waiter is told at once instead of sitting out its own deadline one by one. Distinct from the three that already existed: `Timeout` means *this* request went unanswered and the connection may be fine, `SendTimeout` means the request never reached the network so nothing about the server follows, `Disconnected` means the socket went away. Classifies as `ErrorKind::ConnectionLost`, the same as `Disconnected`, so existing reconnect paths pick it up unchanged, and reports `is_retryable() == true`.
  - **Reaching it always costs a request its full deadline first**, which is what keeps it off the false-positive path: it can never abandon anything the plain deadline was not already abandoning, and it only relabels the failure once the whole link has gone quiet.
  - **A `Watcher` on a dead session finally finds out.** CHANGE_NOTIFY is exempt from the *request's* deadline by design — it waits for an event that may never come, and hours of silence is the healthy case — so before this a dead server left a watcher waiting on an event that could never arrive. It is bounded by the connection instead: the same verdict, measured on how long the whole link has been quiet rather than on how long this one request has waited.
- **`MetricsSnapshot::keepalive_probes_sent` / `keepalive_probes_skipped` / `keepalive_failures` / `response_deadline_extensions`.** Neither middle counter is a failure in any operational sense: a skipped probe (no credit on hand) says nothing about the server, and an unanswered one costs the connection only the extension it would otherwise have earned. Read them next to `response_deadline_extensions` — probes going unanswered while slow operations need the extra room is the shape that ends in `Error::Timeout`.

### Changed

- **Per-connection diagnostics counters now carry across a reconnect** instead of returning to zero, because the connection survives one rather than being replaced. The numbers describe the whole life of the client's link to a server, blips included — which is also what makes `reconnects_succeeded` meaningful, since a counter reset by the event it counts would always read zero.
- **`SESSION_SETUP` now announces `PreviousSessionId` after a reconnect**, which is how a client says "this is me again" (MS-SMB2 § 2.2.5). A wire-level change with no API: expect the server to reap the old session's state promptly instead of holding it until its own timeout. Zero on a first connect, as before.
- **An explicit `SmbClient::reconnect()` leaves the connection armed to reconnect**, because it installs a reviver from the config if there isn't one. `Connection::can_reconnect()` therefore reports `true` afterwards even with `auto_reconnect: false`. Nothing automatic uses it — the crate's own retry path checks the config flag as well — but a consumer calling `Connection::reconnect_if_needed()` directly will find it works where it previously returned `Disconnected`.
- **A connection that has gone quiet with work outstanding now sends a periodic ECHO.** Notably, a connection holding a `Watcher` open counts as having work outstanding, so it will show a probe every few seconds where it used to be entirely silent. That is what lets a watcher discover a dead session at all.
- **`fan_error_to_waiters` no longer collapses every cause to `Disconnected`.** Waiters on a connection declared unresponsive get `Error::ServerUnresponsive` instead. If you match on `Error::Disconnected` specifically rather than on `ErrorKind::ConnectionLost`, add the new variant (`Error` is `#[non_exhaustive]`, so this doesn't break compilation).
- **A wedged connection now recovers in half a minute instead of three.** The deadlines added in 0.14.0 and 0.15.0 were correct but far too patient to be a recovery: a stuck transfer sat there for minutes before anything fired, which for anyone watching a progress bar is indistinguishable from the hang they were meant to fix. The response deadline (`Connection::set_response_timeout`) drops from **180 s to 30 s** and the send deadline (`Connection::set_send_timeout`) from **60 s to 20 s**. Worst case for a dead socket goes from 4 minutes to 50 s.
  - **Nothing legitimately slow gets cut off, and the shorter number doesn't change that.** The response deadline measures *silence*, never elapsed time. Its clock starts when the frame reaches the wire, and every interim `STATUS_PENDING` restarts it (MS-SMB2 § 3.2.5.1.5), so a `FSCTL_SRV_COPYCHUNK` that runs for 10 minutes or a multi-megabyte write to a busy NAS is never touched — the server keeps saying "still working" and the budget keeps resetting. 30 s is the amount of *total silence* tolerated, sized to clear the slowest thing a healthy server does without a word: spinning a parked NAS disk back up (10–20 s) before answering the first CREATE. CHANGE_NOTIFY remains exempt at any setting.
  - **The send deadline has no such refresh**, so 20 s is sized to cover a whole worst-case frame in one go: a 1 MB `MaxWriteSize` frame at 50 KB/s, or an 8 MB one at 400 KB/s. If you support a link slower than that, raise it.
  - If you'd already tuned either setter, nothing changes for you — only the defaults moved.
- **The stale-request warning now fires at 15 s** (`Connection::set_stale_request_warning`, was 30 s). At 30 s it would have coincided with the new response deadline, meaning the log line that names a wedged request would only ever have been written after that request was already abandoned. Expect the warning a little earlier and on connections that never used to produce it; that's the point of it.

### Fixed

- **The client GUID was regenerated on every NEGOTIATE**, so this client reintroduced itself as a stranger on every connection. MS-SMB2 § 3.2.1.1 makes `ClientGuid` a property of the *client*, and it is now stable for the life of the process. Wire-visible and worth knowing about even if you change nothing: a server that logs, rate-limits, or groups sessions by client GUID now sees one identity per process instead of one per connection. It is also what durable-handle reconnect keys on, so nothing could ever have been resumed without this.
- **`CreditPool` could never reopen once a teardown closed it** (tokio makes closing a `Semaphore` terminal), which would have left a revived connection with no budget at all.
- **Three of the four background tasks exited for good when a connection was marked dead**, so a revival that only swapped the transport would have come back with no keepalive and no stale-request warning — silently, which is how the wedge this effort started with went undiagnosed for a year.

### Notes

- **⚠️ The encryption test fixtures do not test encryption.** Both `smb-encryption` and `smb-encryption-aes128` run `smb encrypt = desired`, and Samba 4.20 only sets `SMB2_SHAREFLAG_ENCRYPT_DATA` for `required` — so this client never activates encryption against either, and their traffic is plaintext (verified 2026-08-02: `should_encrypt` and `tree.encrypt_data` are both false, and each fixture's own comment claims the opposite). Nothing in this release changes that; it is called out because the encrypted-session path is far less covered than `AGENTS.md`'s container table implies, and one claim in this changelog rested on it. Encryption *code* is covered by unit tests; encryption *against a real server* is not covered at all.
- **Two findings a mock could never have surfaced**, both verified against Samba 4.20.6 with `log level = 10` on 2026-08-02. A durable-reconnect CREATE carrying *any* other create context is rejected outright before the open is even looked up (MS-SMB2 § 3.3.5.9.12 permits this), which is why the identity proof is a compounded `QUERY_INFO` rather than the tidier `QFid` create context. And `FileIdInformation` (class 59), which returns both halves of the identity at once, is answered `STATUS_INVALID_INFO_CLASS`; the proof uses `FileInternalInformation` (class 6) plus `FileFsVolumeInformation` instead. The volume serial is best-effort: a server that won't answer it reports 0 on both sides, so the comparison degrades to the index number alone and never to anything weaker.

## [0.15.0] - 2026-08-01

### Fixed

- **A transfer could wedge forever because nothing bounded getting a request ONTO the wire.** 0.14.0 bounded the wait for a *response*; this bounds the wait to *ask*. Every caller used to lock the transport's write half for the duration of its own `write_all`, so one send that never completed silently parked every later request behind it — with no deadline, no error, and no log line. Caught live on 2026-08-01: a Cmdr copy to a QNAP TS-464 sat frozen for **40 minutes** with ~700 requests registered as in-flight and **zero bytes** in either direction on two `ESTABLISHED` sockets, while a fresh connection wrote to the very same directory at 84 MiB/s. Neither the 180 s response deadline nor the 30 s credit deadline could fire: both live downstream of the send, and the server had never been asked. A dedicated writer task now owns the write half; callers hand it whole frames through a bounded queue, each frame gets `Connection::set_send_timeout` (60 s default) to reach the socket, and a breach surfaces as `Error::SendTimeout` and tears the connection down.
- **A cancelled caller could desynchronize the connection permanently.** `TcpTransport::send` writes a 4-byte length header and then the body. A future dropped between the two left a header with no body on the wire, and every subsequent frame landed inside the length the server was still waiting to fill. Consumers cancel routinely — a user aborting a copy — so this was reachable in normal use. Frames are now queued as one unit, which makes a partial write impossible from cancellation.
- **Aborted requests leaked their in-flight entry for the life of the connection.** Only the response deadline ever removed a waiter, so the usual `tokio::spawn` + `abort()` shape left one behind every time. Two things broke: `Connection::outstanding_requests()` accumulated long-dead requests (observed climbing to 219 and never draining under 1-in-3 cancellation), and `reserve_credits`' "is anything outstanding that could bring a grant back?" check could never again be false, so genuine starvation waited out the full deadline instead of failing immediately. `register_waiter` now returns a guard that deregisters on drop.
- **`Watcher` leaked its pre-issued CHANGE_NOTIFY** on every drop, for the same reason. A long-lived watcher's abandoned requests showed up as unanswered for hours.

### Added

- **`Error::SendTimeout { command, bytes, waited }`** — a request could not be handed to the network in time. Distinct from `Error::Timeout` on purpose: `Timeout` means the server was asked and said nothing, `SendTimeout` means it was never asked, so nothing about the server follows from it. Classifies as `ErrorKind::TimedOut` and reports `is_retryable() == true`.
- **`Connection::set_send_timeout(Option<Duration>)`** (default `Some(60 s)`) — how long one frame may take to reach the socket. Generous enough that a `MaxWriteSize` frame on a very slow link is never cut off; `None` restores the pre-0.15 unbounded behavior.
- **`OutstandingRequest::sent_age: Option<Duration>`** — how long ago the frame reached the transport, or `None` while it is still queued. **Read this before concluding anything about a server.** "In flight" starts at registration, which is before the bytes go out; reading a large `age` as server silence is precisely the mistake that misdirected this investigation three times. The stale-request warning now says which case it is, and reports the send-queue depth when a request isn't on the wire yet.
- **`Connection::send_queue_depth()` and `CreditInfo::send_queue_depth`** — frames handed to the writer task and not yet written. Persistently non-zero while `wire_bytes_sent` stands still is the signature of a stuck send side.
- **`MetricsSnapshot::send_failures`** — frames the transport refused to write. Non-zero means the wedge was on the client's side of the wire.

### Changed

- **Breaking: `Error` and `CreditInfo` gained members, and both are now `#[non_exhaustive]`.** An exhaustive `match` on `Error` needs a `_` arm, and `CreditInfo` can no longer be built with a struct literal. Both were already breaking through the new members, so they are marked now to stop the next addition from breaking anyone. Matching on `ErrorKind` needs no change: `SendTimeout` classifies as the existing `ErrorKind::TimedOut`.
- **Behavior change: a failed or timed-out send now tears the connection down.** It previously returned an error and left the connection up, which is not safe once bytes may already be on the wire — the stream can't be resynced past a partial frame. A frame rejected before any byte went out (oversized) still leaves the connection alive.
- **`wire_bytes_sent` counts bytes actually written**, not bytes handed to the transport, so a frame that never made it no longer inflates the one counter that says whether we are talking to the server at all.

### Notes

- Samba 4.9.5 crashes on `write_file_compound` (`PANIC: Bad talloc magic value`, 8/8 reproductions at concurrency 1 with a 4 KB body). Samba 4.20.6 and QNAP QTS are immune, so this is a server bug rather than a malformed frame from us, but it means small-file copies kill the connection on older Samba builds. Written up in `docs/notes/samba-4.9-compound-write-crash.md`; not fixed here.

## [0.14.0] - 2026-08-01

### Fixed

- **A transfer to a NAS could wedge forever because the client was over-spending the server's credit budget.** Every SMB2 request spends credits the server grants and replenishes on each response; sending more than you hold is a protocol violation MS-SMB2 § 3.3.1.1 lets the server punish. This crate charged credits when the **response** arrived rather than when the request was **sent**, so every in-flight request was invisible to the counter: `Connection::credits()` reported the server's whole window instead of the unspent part, and each of the four pipelined loops divided that same number by its own chunk charge. Several concurrent transfers over one connection therefore each filled a full window from a budget they were all sharing. Observed against a QNAP TS-464 (2026-07-31, reproduced twice): seven transfers all reached their final byte and never returned, 13 requests outstanding, **zero** SMB responses of any kind, while TCP stayed `ESTABLISHED` and other clients were served the same share instantly. Credits are now reserved before a request's bytes reach the wire, from a pool shared by every clone of a `Connection`, and a request that can't afford its charge waits for a grant instead of sending anyway.
- **Two silent-truncation paths in the pipelined loops.** `read_file_pipelined`, its progress-reporting variant, and `write_file_pipelined` only launched the next chunk `if credits_available > 0`; skipping it drained the in-flight set to zero with chunks still unsent, ending the loop early and returning a partially-filled buffer as success. `write_file_streamed` could likewise strand a chunk it had stashed for lack of credits if the stash happened on the final response. Both were latent before this release (the inflated credit reading made the branch nearly unreachable) and would have become live once the reading was accurate. All four loops now bound only the queue depth and let the connection's gate do the throttling, which is the only place that can do it correctly.
- **A server that stops answering no longer hangs the caller.** A request whose server goes silent while the TCP socket stays open now ends in `Error::Timeout` after 180 s rather than an `await` that never resolves. The deadline measures silence, not elapsed time: every interim `STATUS_PENDING` restarts it (MS-SMB2 § 3.2.5.1.5), so a slow operation the server has acknowledged — a multi-minute `FSCTL_SRV_COPYCHUNK`, say — is never cut short. CHANGE_NOTIFY, whose job is to wait for an event that may never come, is exempt at any setting.

### Added

- **`Error::CreditStarvation { needed, available, waited }`** — the typed answer when a send waits out its deadline for a credit grant that never comes. In practice it means the server has stopped answering while its socket is still up, so treat it as a dead connection and reconnect. Classifies as `ErrorKind::TimedOut` and reports `is_retryable() == true`, so existing retry logic keyed on either handles it without changes.
- **`Connection::set_credit_wait_timeout(Duration)`** (default 30 s) — how long a send waits for a grant before giving up. A send only waits at all once the connection's whole budget is in flight, which on a healthy server clears in milliseconds. There is deliberately no "wait forever" setting: an unbounded wait is the failure this bound exists to prevent.
- **`Connection::set_response_timeout(Option<Duration>)`** (default `Some(180 s)`) — the silence deadline described above. Pass `None` to restore the pre-0.14 wait-forever behavior if your application imposes its own.
- **Three diagnostics counters**: `credit_waits` (sends that parked on credits — a trickle is normal on a saturated pipeline, a flood means the server's window is small relative to your chunk size), `credit_starvations`, and `response_timeouts`.

### Changed

- **Breaking: `Error` has a new variant.** `Error` is not `#[non_exhaustive]`, so an exhaustive `match` on it needs a new arm for `CreditStarvation`. Matching on `ErrorKind` (which is `#[non_exhaustive]`) needs no change — the new variant classifies as the existing `ErrorKind::TimedOut`.
- **Behavior change: sends can now block, and requests can now time out.** Both are bounded and both replace a hang, but a `Connection` that previously always sent immediately may now park briefly under a saturated pipeline, and a request that previously waited indefinitely may now return `Error::Timeout`. Nothing needs to be re-tuned for a healthy server; the knobs above exist for the unusual ones.
- **`Connection::credits()` means something different.** It now reports credits *on hand* — granted and not reserved by a request in flight — where it previously reported the server's window as of the last response. It is a gauge, not a gate: the connection reserves and waits internally, so callers should not pre-check it before issuing a request.
- **The credit request on each message is derived rather than a flat 256.** Every request now asks for its own charge back plus enough to climb to a 512-credit target, so an idle connection asks for little and the window can't shrink under a steady load.

### Notes

- Validated against the full Docker Samba suite (84 tests), the consumer harness (16), and real hardware.

## [0.13.3] - 2026-08-01

### Fixed

- **0.13.2 doesn't compile with the `serde` feature enabled. Skip it: take 0.13.3 or later.** `OutstandingRequest` (new in 0.13.2) derives `Serialize` under that feature and carries a `Command`, which did not implement `Serialize`, so any consumer building `smb2` with `features = ["serde"]` got a trait-bound error from inside the crate. `Command` now derives `Serialize` under the same feature. Consumers on default features were unaffected. **0.13.2 has been yanked**, but a yank only stops *new* resolutions: an existing `Cargo.lock` pinning 0.13.2 still resolves it, so pin `>=0.13.3` if you enable `serde`.

### Changed

- **The release gate builds every feature it ships.** `just check-all` ran clippy and the tests on default features only, which is exactly why the above shipped: nothing in the pre-release gate ever compiled the `serde` path. Both steps now run a second time under `--all-features`. That immediately caught a second, unrelated staleness: `testing::tests::embedded_files_count` still asserted 35 embedded fixtures after a 15th container brought the real count to 37, and had gone unchecked because the `testing` feature was never built either.


## [0.13.2] - 2026-08-01

### Added

- **A hung request can now be identified, instead of only being counted.** `ConnectionDiagnostics::outstanding` lists every request that has been sent and not yet answered — command, `MessageId`, and age, oldest first — and `Connection::outstanding_requests()` returns the same data directly. Previously a connection waiting forever on one request was indistinguishable from a healthy one: credits recover, counters advance, `disconnected` stays `false`, and `CreditInfo::in_flight` gives a bare number with no way to tell WHICH request is stuck or for how long. This is the case where a client keeps serving small requests normally while one large write never comes back. `ConnectionDiagnostics` is `#[non_exhaustive]`, so the new field is additive.
- **A background sweeper logs a warning naming any request outstanding past a threshold** (default 30 s), re-reporting every 10 s while it stays stuck, since a single line is easy to miss in a long session. It runs as its own task rather than inside the receive loop: that loop is parked in `transport_recv.receive()` exactly when a wedged connection most needs reporting, and racing that read against a timer would mean dropping a read that isn't necessarily cancel-safe. It holds a `Weak` and exits when the last `Connection` clone drops.
- **`Connection::set_stale_request_warning(Option<Duration>)`** to retune that threshold or silence it entirely. The default is a guess about someone else's server, so it has to be tunable: raise it for a server that's legitimately slow under load, or pass `None` if your application renders `outstanding` itself and doesn't want the log line.

### Notes

- No breaking changes; `Waiter` bookkeeping is internal, and the new diagnostics field lands on a `#[non_exhaustive]` struct. Existing code needs no edits, and consumers that want none of this get one background task per connection whose only cost is a 10 s timer.

## [0.13.1] - 2026-07-15

### Fixed

- **Logon-rejection statuses now classify as `ErrorKind::AuthRequired` instead of `ErrorKind::Other`.** When a server refuses a session because the credentials or the account itself were rejected, the response NTSTATUS is one of a known logon-failure family — but only `STATUS_LOGON_FAILURE` and `STATUS_ACCOUNT_DISABLED` were mapped, so the rest fell through to the generic `ErrorKind::Other` and a consumer couldn't tell an auth refusal from an unrelated protocol error. In particular, macOS smbd answers a guest/anonymous `SessionSetup` it won't accept with `STATUS_ACCOUNT_RESTRICTION` (0xC000006E), which consumers were treating as a generic failure (a misleading warning plus a pointless CLI fallback in Cmdr). The full family now maps to `AuthRequired`: `STATUS_ACCOUNT_RESTRICTION`, `STATUS_INVALID_LOGON_HOURS`, `STATUS_INVALID_WORKSTATION`, `STATUS_PASSWORD_EXPIRED`, `STATUS_ACCOUNT_EXPIRED`, `STATUS_PASSWORD_MUST_CHANGE`, and `STATUS_ACCOUNT_LOCKED_OUT`, alongside the existing `STATUS_LOGON_FAILURE` and `STATUS_ACCOUNT_DISABLED`. They all mean the same thing to a caller: this logon won't work, supply different credentials. No new `ErrorKind` variant, so no `match` needs updating. Pinned by rows in the `classify_status_contract` test.

### Added

- **`NtStatus` constants for the logon-rejection family** (from MS-ERREF): `ACCOUNT_RESTRICTION` (0xC000006E), `INVALID_LOGON_HOURS` (0xC000006F), `INVALID_WORKSTATION` (0xC0000070), `PASSWORD_EXPIRED` (0xC0000071), `ACCOUNT_EXPIRED` (0xC0000193), `PASSWORD_MUST_CHANGE` (0xC0000224), and `ACCOUNT_LOCKED_OUT` (0xC0000234). Additive constants on the `NtStatus` newtype, so they carry named `Debug`/`Display` output and feed the classification above.

## [0.13.0] - 2026-07-09

### Added

- **Server-side copy (`FSCTL_SRV_COPYCHUNK`): copy byte ranges between two files on the server without the data crossing the wire.** This is the mechanism Windows Explorer uses for same-share copies — the server copies the bytes between two of its own open files, so a multi-gigabyte copy moves only a handful of small control messages instead of the whole file twice (down and back up). Two tiers, both on `Tree` with `SmbClient` wrappers:
  - **Convenience:** `server_side_copy_file(source, dest)` copies a whole file (truncating the destination); `server_side_copy_file_range(source, source_offset, dest, dest_offset, length)` copies a byte range to a chosen destination offset without truncating. Both open source (read) and destination (read+write), fetch a resume key, batch the copy within the server's limits, flush and close both handles, and never leak a handle on an error path. They return the number of bytes copied.
  - **Primitives:** `request_resume_key` (turn an open source handle into an opaque `ResumeKey`), `copy_chunks` (one copychunk IOCTL against an open read+write destination, returning a typed `CopyChunkOutcome`), and `server_side_copy_range` (batch a range over already-open handles). New public types: `ResumeKey`, `CopyChunk`, `CopyChunkResult`, `CopyChunkOutcome`, `ServerSideCopyLimits`.
  - **Limits are negotiated transparently.** A server that receives a request exceeding its per-request limits doesn't fail — it returns `STATUS_INVALID_PARAMETER` carrying a `SRV_COPYCHUNK_RESPONSE` that advertises the limits (MS-SMB2 3.2.5.14.3). The batched methods start at a conservative 16 × 1 MiB / 16 MiB per request (the common Windows/Samba minimum) and re-batch within the advertised limits if rejected; `copy_chunks` surfaces this as `Ok(CopyChunkOutcome::Rejected { limits })` rather than an error.
  - **Unsupported servers are typed, not string-matched.** Older Samba builds and some NAS firmware lack copychunk and return `STATUS_NOT_SUPPORTED` / `STATUS_INVALID_DEVICE_REQUEST`; these now classify as the new `ErrorKind::Unsupported`, so a consumer can branch on it and fall back to a read-then-write copy. The `server_side_copy` example shows the fallback.
  - Pinned by unit tests (copychunk wire round-trips including the limits-negotiation path; batching across chunk and per-request limits; renegotiation; the full open→copy→close choreography; chunk offsets) and three Docker tests against real Samba: a whole-file copy verified to move <10% of the file size on the wire (proving the data stays server-side), a 20 MiB copy that spans multiple copychunk requests and byte-matches, and a range-copy-then-positioned-append round-trip.
- **Positioned `FileWriter`: `create_file_writer_at(path, offset)`.** Opens a file without truncating (`FileOpenIf`) and starts writing at an arbitrary offset — the write analog of `FileReader`'s positioned reads. The natural way to append after a server-side-copied prefix (the archive tail-rewrite shape) or to patch a known region of an existing file. Available as `open_file_writer_at` (free fn), `Tree::create_file_writer_at`, and `SmbClient::create_file_writer_at`.
- **`Tree::open_file_readwrite` and public `Tree::close_handle`.** A read+write open (needed as a server-side copy destination) and a public close for the raw handles that `open_file` / `open_file_readwrite` / `request_resume_key` hand back — completing the raw-handle open/close pair for advanced callers.
- **`ErrorKind::Unsupported`** (and the `STATUS_NOT_SUPPORTED` NTSTATUS): the typed classification for "the server doesn't implement this operation". `ErrorKind` is `#[non_exhaustive]`, so adding it is non-breaking; `STATUS_NOT_IMPLEMENTED` now classifies here too (previously `Other`).
- **`ErrorKind::TooLarge`** and `Error::FileTooLargeForSingleRead { size, max_read }`: the typed signal that a single-read path was asked for a file bigger than the server's per-READ maximum (see the behavior change below).

### Changed

- **Behavior change: `read_file` / `read_file_compound` now error on files larger than one READ instead of silently truncating.** These paths issue a single CREATE+READ+CLOSE compound, so a file larger than the server's negotiated `MaxReadSize` (commonly 8 MiB, but as small as 64 KiB on some servers) came back as just the first chunk — a silent short read that looked like success and could corrupt whatever consumed the "file". They now return the new typed `Error::FileTooLargeForSingleRead { size, max_read }` (classified `ErrorKind::TooLarge`), whose message and rustdoc steer the caller to `read_file_pipelined`, which reads any size in a sliding window of chunked READs. Callers that only ever read small files (config, metadata, text) are unaffected; callers that might hit large files should branch on the error (or use `read_file_pipelined` unconditionally). Detected via the CREATE response's end-of-file size, so it costs no extra round-trip. Pinned by a unit test (a file past the negotiated cap errors rather than returning short) and a Docker test against the 64 KiB-`MaxReadSize` Samba fixture (a 128 KiB file errors from `read_file`, while `read_file_pipelined` returns it whole).

### Notes

- Minor bump per the crate's pre-1.0 SemVer (minor = potentially breaking). Most of the release is additive (server-side copy, positioned writer, the read+write/close handle methods, `ErrorKind::Unsupported`/`TooLarge`), and no existing signatures changed. Two things are technically breaking and land in this minor deliberately: `read_file` / `read_file_compound` now return an error instead of a truncated buffer for oversized files (see Changed), and `Error` gains the `FileTooLargeForSingleRead` variant (a non-wildcard `match` on `Error` must add an arm).

## [0.12.1] - 2026-07-09

### Changed

- **RustCrypto dependencies relaxed from release-candidate pins to stable.** `aes` (`=0.9.0-rc.4` → `0.9.1`), `aes-gcm` (`=0.11.0-rc.3` → `0.11.0`), `cmac` (`=0.8.0-rc.5` → `0.8.0`), and `pbkdf2` (`=0.13.0-rc.10` → `0.13.0`) now track the stable releases. These crates had been hard-pinned to specific pre-releases because a stable `aes 0.9` didn't exist yet; now that it does, the exact `=` pins were forcing every downstream that also wants a RustCrypto crate onto the same rc, causing unresolvable version conflicts. In particular this unblocks Cmdr from enabling `zip`'s `aes-crypto` and `sevenz-rust2`'s `aes256` features, both of which require stable `aes ^0.9`. No API or behavior change — the rc-to-stable transition of these crates carried no public-API drift, so smb2's own surface is unchanged; verified by a clean `--all-features` build, the full check suite, both Docker suites, and real-hardware AES-CMAC/GMAC signing against a QNAP NAS. `ccm` stays pinned at `=0.6.0-rc.3` because it has no stable 0.6 release yet; it unifies cleanly with the stable `aes`/`aes-gcm`/`aead`/`cipher` versions in one lockfile with no duplicate crates. Revisit and unpin `ccm` when its stable ships.

## [0.12.0] - 2026-07-06

### Added

- **`FileReader`: random-access positioned reads over one open handle.** Opens a file once and serves any number of `read_at(offset, len)` calls — the SMB analog of `pread` — at arbitrary offsets, then an explicit `close()`. It's the primitive for a consumer that parses a file's structure by jumping around it (a media container's index, a database page, a zip's end-of-central-directory then its central directory then member data) rather than streaming front-to-back, where the previous public read paths (`FileDownload` sequential, `read_file` whole-file) forced a reopen-and-leak per read. Same owned-`Connection` + `Arc<Tree>` shape as `FileWriter`, so it's `'static`; `read_at` takes `&self` (no shared cursor), so concurrent positioned reads pipeline over the single SMB session. A range larger than the negotiated `MaxReadSize` splits into consecutive wire READs and reassembles; reads clamp to the size seen at open, so a read at or past EOF returns empty and a straddling read is short, never an error. `close()` consumes `self` (read-after-close is a compile error); like the other stream handles, `Drop` can't CLOSE (no async drop) and only logs a debug warning, so close explicitly. Build one via `open_file_reader(tree, conn, path)` (free fn), `Tree::open_file_reader`, or `SmbClient::open_file_reader`. Exported at the crate root. Pinned by the `stream.rs` `file_reader_*` mock tests (one CREATE, N READs, one CLOSE; EOF clamping; range splitting; drop-sends-no-close proving the no-leak contract) and the `guest_file_reader_positioned_reads` Docker test against real Samba.

## [0.11.4] - 2026-06-28

### Changed

- **Per-frame protocol logging moved from DEBUG to TRACE.** Per-message signing (`signing: signed …`), per-request dispatch (`execute …`, `execute_cap …`, `execute_compound …`), per-response success routing (`recv: routed …`), and per-listing directory ops (`tree: list_directory …`) now log at TRACE instead of DEBUG. These fire once per SMB frame, so on a high-throughput operation — a recursive directory scan walking millions of dirs — they flooded a consumer logging at DEBUG (one report: ~170 MB of logs in 25 min, ~90% of it this plumbing, so a rotating buffer held only minutes of history). Lifecycle (connect, negotiate, session, tree connect), credit changes, per-operation mutations (rename/delete/write), and the low-volume error/orphan/late-arrival routing diagnostics stay at DEBUG; routing error and orphan frames stay visible. No behavior change beyond log levels. Get the per-frame detail back with `RUST_LOG=smb2=trace`. The AGENTS.md logging table is updated to match (per-frame request/response is TRACE, not DEBUG).

## [0.11.3] - 2026-06-01

### Fixed

- **Share enumeration on servers that fragment the srvsvc reply.** `list_shares` (and `SmbClient::list_shares`) now reassembles a `NetShareEnum` response that the server splits across multiple DCE/RPC fragments — `PFC_LAST_FRAG` set only on the last (MS-RPCE 2.2.2.6) — and follows `STATUS_BUFFER_OVERFLOW` on pipe reads (MS-SMB2 3.3.5.10) instead of treating it as a fatal error. Previously a listing larger than one 4280-byte RPC fragment or one 64 KiB pipe read came back as an error or a truncated list against older Samba builds and some NAS firmware (many shares and/or long comments). New `parse_response_fragment` reports the last-fragment flag; the read loop stitches fragments before NDR-decoding. Pinned by unit tests on both seams plus the `smb-manyshares` Docker fixture (200 long-comment shares — real Samba fragments the reply into 26 RPC fragments, all reassembled).

## [0.11.2] - 2026-05-28

### Added

- **Exclusive-create file writers.** `Tree::create_file_writer_exclusive` and `SmbClient::create_file_writer_exclusive` mirror their `create_file_writer` siblings but issue the underlying CREATE with `FileCreate` disposition instead of `FileOverwriteIf`. If the file already exists the server returns `STATUS_OBJECT_NAME_COLLISION`, which maps to `ErrorKind::AlreadyExists`. Use this for race-free "create only if absent" writes (file managers' "New File" actions, ID-claim files, etc.) where silently truncating an existing file is unsafe. Pinned by `client::tree::tests::open_file_for_exclusive_create_*` and the Docker integration `guest_create_file_writer_exclusive_fails_on_existing`.

## [0.11.1] - 2026-05-28

### Changed

- **`receiver_loop` log levels.** Idle teardowns (transport error with no in-flight waiters — the routine "server or OS reaped a quiet session" case) drop from WARN to DEBUG. The decrypt / decompress / malformed-frame teardowns stay at WARN since those are protocol corruption regardless of how many waiters were affected, and transport teardowns *with* pending waiters also stay at WARN since they surface real disconnects to callers. No behavior change beyond log levels — cuts a meaningful amount of false-positive noise in long-running clients (cmdr was logging 6 WARNs per session on idle SMB connections).

## [0.11.0] - 2026-05-21

### Added

- **In-process diagnostics.** `SmbClient::diagnostics()` and `Connection::diagnostics()` return a `Diagnostics` / `ConnectionDiagnostics` snapshot of the client's current state — negotiated dialect, credits + in-flight count + next `MessageId`, signing/encryption/compression status, RTT estimate, DFS cache, the per-connection session, and a `MetricsSnapshot` of 17 monotonic `AtomicU64` counters (requests sent, wire bytes sent/received, the four disjoint routing outcomes — `responses_routed_ok`, `responses_routed_err`, `responses_late_after_drop`, `responses_stray` — plus `status_pending_loops`, `unsolicited_notifications_received`, `signature_failures`, `decrypt_failures`, `decompress_failures`, `malformed_frames`, `session_expired_events`, `compound_requests_sent`, `explicit_cancels_sent`, `requests_returned_err`). Counters survive connection teardown; per-connection counters reset on `SmbClient::reconnect`, client-level counters (`reconnects`, `dfs_referrals_resolved`, `dfs_cache_hits`) survive. A `Display` impl renders a compact terminal view. See [`docs/specs/diagnostics-plan.md`](docs/specs/diagnostics-plan.md).
- **Optional `serde` feature** (off by default): `Serialize` impls on every diagnostics type plus the protocol enums they embed (`Dialect`, `Cipher`, `SigningAlgorithm`, `Capabilities`, `Guid`, `SessionId`, `TreeId`, `MessageId`). For consumers building MCP tools, dashboards, or any structured exporter. JSON form is the in-memory shape (newtypes are `transparent`, `Capabilities` is the raw `u32` bits).
- **`examples/diagnostics.rs`**: connect, run a couple of ops, dump the snapshot via `Display` — or `--json` when built with `--features serde`.

### Fixed

- **Stale `src/client/CLAUDE.md` gotcha** about silent frame discard on decrypt/decompress/malformed-header errors. Phase 3 P3.4 fixed this — the receiver task tears down the connection on those paths and fans `Err(Disconnected)` to every pending waiter. Note now matches the code, and the diagnostics counters above attribute each tear-down to its trigger.

## [0.10.0] - 2026-05-19

### Changed

- **Breaking: `Watcher` owns its `Connection` and `Tree` instead of borrowing them.** The lifetime parameter is gone; `Watcher` is now `'static`. `Tree::watch` and `SmbClient::watch` lose their `'a` parameter and return `Watcher` instead of `Watcher<'a>`. Existing call sites that wrote `let mut w = client.watch(&tree, "path", true).await?;` keep compiling unchanged — only code that explicitly named the type as `Watcher<'_>` needs the `<'_>` removed. The connection clone is cheap (`Arc::clone`, multiplexes over the same SMB session), so the caller is free to keep using their `Connection` for other ops while a watcher runs. The previous "use a separate `SmbClient` to perform operations while watching" workaround is no longer needed.

### Fixed

- **CHANGE_NOTIFY consumer-side loss window closed.** `Watcher::next_events` now keeps one CHANGE_NOTIFY request continuously outstanding on the wire by pre-issuing the next request before awaiting the current response. Without this, server-side events that arrived during the consumer's response-processing window were dropped silently by strict servers (older Samba builds, NAS firmware) that don't queue events between consecutive CHANGE_NOTIFY requests. Reproduced in the field as 9 file copies → 4 watcher events delivered. Confirmed against Docker Samba, QNAP TS-464, and Windows-shape servers via `tests/integration.rs::nas_accepts_stacked_change_notify` and the new unit test in `src/client/watcher.rs::loss_window_tests`.

### Added

- `Connection::dispatch` / `Connection::dispatch_with_credits` (crate-internal): variant of `execute` that returns once `transport.send().await` completes, handing back the response `oneshot::Receiver` for the caller to await separately. Enables pipelining patterns where the next request must be on the wire before the previous one's response is processed.

### Notes

- **Server compatibility check**: the fix relies on the server accepting two simultaneous CHANGE_NOTIFY requests on the same `FileId`. MS-SMB2 allows it; Windows, modern Samba (Docker fixtures), and QNAP TS-464 firmware all confirmed-good. Servers that reject would surface `Err(Error::Protocol { status: ..., command: ChangeNotify })` on the second `next_events()` call. If you hit this on a particular NAS, please file an issue with the NTSTATUS — a config-flag fallback to depth-0 (pre-issue off) is straightforward to add but hasn't been needed yet.

## [0.9.1] - 2026-05-17

### Added

- New consumer-class fixture `smb-consumer-maxreadsize` (port 10494, env `SMB_CONSUMER_MAXREADSIZE_PORT`)
  with `smb2 max read = smb2 max write = 65536`. Mirrors the internal-fixture
  `smb-maxreadsize` so consumer apps can guard against streaming-fallback regressions
  (every transfer >64 KB is chunked, exercising the same code path that hung pre-0.9.0)
  without standing up smb2's `internal/` fixtures. Exposed via `smb2::testing::maxreadsize_port()`
  and shipped through `write_compose_files`.

## [0.9.0] - 2026-05-17

### Changed

- **Breaking: `FileWriter` owns its `Connection` and `Arc<Tree>` instead of borrowing `&'a mut Connection`.** The
  lifetime parameter is gone; `FileWriter` is now `'static`. Multiple writers built from clones of the same
  `Connection` pipeline their WRITEs over one SMB session, multiplexed by `MessageId` in the receiver task — no
  external locking needed.
- **Breaking: `Tree::create_file_writer` signature changed** from `(&self, conn: &mut Connection, path)` to
  `(self: &Arc<Self>, conn: Connection, path)`. Callers that previously held an owned `Tree` need
  `Arc::new(tree)` once; callers using `SmbClient::create_file_writer` are unaffected at the call site (the
  client wraps the cloning internally).
- **Breaking: `SmbClient::create_file_writer` takes `&self` instead of `&mut self`** and returns
  `FileWriter` (no lifetime) instead of `FileWriter<'_>`. The previous `&mut self` requirement was the root cause
  of a deadlock in the cmdr SMB volume's `write_from_stream` under sustained concurrent pressure on QNAP — the
  consumer had to hold its session mutex for the entire streaming upload.
- **Breaking: `Tree` is now `#[derive(Clone)]`.** Lets convenience constructors wrap a `Tree` in `Arc` without
  reconstructing field-by-field. Cloning a `Tree` is cheap (one `TreeId`, three short `String`s, two bools).

### Added

- `client::stream::open_file_writer(tree: Arc<Tree>, conn: Connection, path: &str) -> Result<FileWriter>` — free
  function for building a `FileWriter` when you already hold a cloned `Connection` and an `Arc<Tree>` and don't
  want the convenience-wrapper indirection. `Tree::create_file_writer` and `SmbClient::create_file_writer` both
  delegate to it.

### Notes

- Internal callers in `Tree::write_file_pipelined` and `Tree::write_file_streamed` were not touched: they use
  their own per-chunk `execute_with_credits` loop and never built a `FileWriter`.

## [0.8.0] - 2026-05-08

### Changed

- **Breaking: `ErrorKind` is now `#[non_exhaustive]`.** Match expressions over `ErrorKind` must include a `_` arm.
  Adding a new variant in a future release is now a non-breaking change. Consumers that already use a `_` fallback
  (the pattern recommended by the doc example) need no update.

### Added

- `ErrorKind::AlreadyExists` — `STATUS_OBJECT_NAME_COLLISION` (returned by `Create` when a file or directory of the
  same name exists) now classifies as `AlreadyExists` instead of falling through to `Other`. Lets callers handle
  "merge into existing directory" or surface a friendly "name taken" message without substring-matching the error
  text.
- `ErrorKind::IsADirectory` — `STATUS_FILE_IS_A_DIRECTORY` now classifies as `IsADirectory`. Useful for
  delete-fast-path callers that try `delete_file` first and fall back to `delete_directory` on this kind.
- `ErrorKind::NotADirectory` — `STATUS_NOT_A_DIRECTORY` now classifies as `NotADirectory` (e.g., `list_directory` on
  a file).
- `error::tests::classify_status_contract`: a single table-driven test that documents the full `NtStatus → ErrorKind`
  mapping, including statuses intentionally left as `Other`. Replaces the per-arm classification tests so the contract
  lives in one auditable place; adding a new `NtStatus` should also add a row here.

### Notes

- `STATUS_OBJECT_NAME_INVALID`, `STATUS_DELETE_PENDING`, `STATUS_INSUFFICIENT_RESOURCES`, and
  `STATUS_INSUFF_SERVER_RESOURCES` deliberately still classify as `ErrorKind::Other` — no current consumer needs to
  branch on them. Promoting any of these to its own variant is non-breaking under the `#[non_exhaustive]` policy.

## [0.7.2] - 2026-04-21

### Fixed

- DFS referral response parser (`msg::dfs::RespGetDfsReferral::unpack`): a V2 entry whose server-declared `entry_size`
  was small enough to pass the initial `entry_size < 4` guard but short enough to truncate the fixed body would
  trigger a panic (out-of-bounds) on the final `network_address_offset` read. The V2 body is 18 bytes after the
  4-byte version/size prefix, not 16. Found by fuzzing; regression covered by
  `msg::dfs::tests::resp_parse_v2_short_entry_returns_clean_error`.

### Added

- `fuzz/` crate using `cargo-fuzz` with 12 fuzz targets across the parse entry points: top-level SMB2 header,
  TRANSFORM/COMPRESSION transform headers, compound-frame splitter, full frame + sub-frame body parse, Negotiate
  request/response (negotiate contexts), Create request/response (create contexts), QueryInfo response, and DFS
  referral response. Seed corpus generator at `tests/fuzz_seeds.rs` (run with
  `cargo test --test fuzz_seeds -- --ignored`). Targets are feature-gated behind `fuzzing`; the feature exposes
  parse entry points via `smb2::fuzzing` and is not meant for application use.
- `.github/workflows/fuzz.yml`: weekly 5-minute-per-target fuzz run on schedule + manual dispatch.

## [0.7.1] - 2026-04-21

### Added

- `Tree::download` for streaming reads driven by a borrowed `Connection`, mirroring the existing `SmbClient::download`
  but unlocking concurrent downloads on a single SMB session (via `Connection::clone`).

### Changed

- `Tree::open_file` and `FileDownload::new` are now `pub` (were `pub(crate)`), so callers can build custom chunk loops
  or reuse a handle across multiple readers.
- `SmbClient::download` now delegates to `Tree::download` — zero behavior change.

## [0.7.0] - 2026-04-21

First public release on crates.io. Bundles the FileWriter streaming write API with the Phase 3 Connection actor
refactor (breaking API change).

### Changed

- **Breaking: `Connection`'s send/receive API collapsed into `execute` / `execute_compound`** (Phase 3 of the
  actor refactor). The legacy `send_request`, `send_request_with_credits`, `send_compound`,
  `receive_response`, `receive_compound`, and `receive_compound_expected` are gone; callers use a single
  awaitable call per op. `Connection::execute(command, body, tree_id)` returns `Result<Frame>` where
  `Frame = { header, body, raw }`. `Connection::execute_compound(&[CompoundOp])` returns
  `Result<Vec<Result<Frame>>>` — the outer `Result` is "did the compound hit the wire", the inner one is
  per-sub-op so partial-failure handling (for example, `CREATE` ok, `READ` fails, issue standalone `CLOSE`
  with the returned `FileId`) is straightforward. `Connection: Clone`; clones share the receiver task so
  concurrent `execute` calls from different tasks/clones multiplex over the same SMB session. Cancelling
  (dropping) a future mid-flight is safe by construction — the matching late-arriving frame is discarded.
- `Connection` now uses a background receiver task with per-request `oneshot::Sender` routing (Phase 2 of
  the actor refactor). See `docs/specs/connection-actor.md`. A caller's dropped future (for example,
  `tokio::task::JoinHandle::abort()` in a downstream consumer) now correctly discards the corresponding
  late-arriving response instead of letting it pollute the next operation's receive. Credits still tick on
  dropped-caller frames so throughput stays correct under cancellation churn.
- `tokio` is formalized as a hard runtime requirement; added `"rt"` to the tokio feature set. The library
  spawns a receiver task per `Connection`.
- `MockTransport::receive()` now awaits via `tokio::sync::Notify` when the queue is empty instead of
  returning `Err(Disconnected)` immediately. Added `MockTransport::close()` to signal end-of-stream. This
  lets the background receiver task stay alive across a test's interleaved `queue_response` calls. External
  consumers writing tests with `MockTransport` directly need to call `close()` to get the old behavior.
- `MockTransport::enable_auto_rewrite_msg_id()` — opt-in test-mode shim that rewrites each zero-msg_id
  sub-frame of a queued response to match the next pending sent msg_id in FIFO order, so canned
  `build_*_response` helpers that hardcode `MessageId(0)` route through the Phase 3 receiver task without
  needing to predict the caller's allocated msg_ids. Replaces the pre-Phase-3
  `Connection::set_orphan_filter_enabled(false)` escape hatch.

### Migration guide (pre-Phase-3 → Phase 3)

Single request:
```rust
// Before
conn.send_request(Command::Create, &req, Some(tree_id)).await?;
let (header, body, _raw) = conn.receive_response().await?;
// After
let frame = conn.execute(Command::Create, &req, Some(tree_id)).await?;
// frame.header, frame.body, frame.raw
```

Compound request:
```rust
// Before
let ops = vec![(Command::Create, &create_req, CreditCharge(1)), /*...*/];
conn.send_compound(tree_id, &ops).await?;
let responses = conn.receive_compound_expected(3).await?;
// responses: Vec<(Header, Vec<u8>)>
// After
let ops = [
    CompoundOp { command: Command::Create, body: &create_req, tree_id: Some(tree_id), credit_charge: CreditCharge(1) },
    // ...
];
let frames = conn.execute_compound(&ops).await?;
// frames: Vec<Result<Frame>> — each entry may independently be Err (session expired, signature
// verify failure, etc.). Sub-op status codes (OBJECT_NAME_NOT_FOUND and friends) ride in
// frames[i].as_ref()?.header.status, NOT in the inner Result.
```

Pipelined sliding-window reads/writes: use `futures_util::stream::FuturesUnordered` of boxed
`execute_with_credits` futures across `conn.clone()`s — see `src/client/tree.rs::read_pipelined_loop` for
the canonical pattern. `MAX_PIPELINE_WINDOW` and `conn.credits()`-based pacing stay on the caller side.

### Added

- `FileWriter` — push-based streaming write API with pipelined I/O. Consumer drives the loop, pushing chunks via
  `write_chunk()` with automatic backpressure (sliding window, credit-aware). Complement to `FileDownload` for reads.
  Created via `SmbClient::create_file_writer()`.
- `FileWriter::abort()` — fast-cancel companion to `finish()`. Discards any unsent data, drains in-flight
  WRITE responses to keep credits and message IDs in sync, skips the server-side FLUSH (fsync), and does a
  best-effort CLOSE. Errors during drain/close are swallowed so callers can exit quickly. Use on
  cancellation or error paths where the partial remote file is going to be deleted anyway — it saves the
  fsync round-trip vs. calling `finish()`. The caller is responsible for deleting the partial file.
- `Connection::receive_compound_expected(n)` — gathers exactly `n` compound sub-responses, transparently
  reading additional transport frames when the server splits the chain. All compound-using methods
  (`read_file_compound`, `write_file_compound`, `fs_info`, `stat`, `rename`, `delete_file`/`delete_directory`,
  and the batch `delete_files`/`rename_files`/`stat_files`) now use it.
- 13 new Docker integration tests for `FileWriter`: basic, large (5 MB), empty, single byte, overwrite,
  equivalence with `write_file_pipelined`, binary data integrity, 64 KB max-write-size, signing, encryption,
  read-only rejection, 100 MB stress (guest), 100 MB stress (200ms latency)
- 10 new unit tests for `FileWriter` pipelining, backpressure, chunk splitting, error handling

### Fixed

- Unrecoverable frame errors (decrypt auth-tag mismatch, decompression failure, malformed sub-frame
  header after compound splitting) no longer hang pending waiters indefinitely. Previously the
  receiver task log-at-WARN'd and `continue`d, which left any waiter matching the discarded frame's
  `MessageId` stuck on `rx.await` forever — the `msg_id` isn't recoverable from an unparseable frame,
  so no targeted error could be delivered. Per decision E6 in the Phase 3 design, the receiver task
  now tears the connection down on these conditions: fans `Err(Disconnected)` to every pending
  waiter and exits. Callers see the error promptly and can reconnect. Sub-frame signature-verification
  failures and `STATUS_NETWORK_SESSION_EXPIRED` stay targeted (delivered only to the matching waiter)
  because the `msg_id` is known.
- Caller futures that get dropped mid-flight (for example, a cancelled listing task in a consuming
  application) no longer leave in-flight SMB requests on the wire that corrupt subsequent operations.
  The receiver task discards late-arriving frames whose waiter's `oneshot::Receiver` has been dropped.
  Reproduces and fixes the cmdr `listing_task.abort()` regression.
- Compound requests no longer error with `invalid_data: expected N compound responses, got M` when the
  server sends responses as separate frames instead of one compounded frame. Per MS-SMB2 3.3.4.1.3 the
  server SHOULD compound but MAY split, and Samba (including QNAP NAS firmware built on Samba) splits
  in some scenarios. Hit in the wild via `fs_info` against a QNAP NAS.

## [0.6.0] - 2026-04-15

### Added

- `write_file_streamed` — write files from a streaming callback source with pipelined I/O, bounded memory usage
  (sliding window, not full file), automatic chunk splitting at `MaxWriteSize`, works with signing and encryption
  ([f5ade78](https://github.com/vdavid/smb2/commit/f5ade78))
- 14 new tests: 3 unit (basic, empty, callback error), 9 Docker integration (guest, small, large 10 MB, empty, early
  stop, 64 KB max-write-size, mandatory signing, mandatory encryption, read-only rejection), 2 NAS integration
  (write + verify, performance comparison vs `write_file_pipelined`)

### Fixed

- Bumped `rand` 0.9.2 → 0.9.4 (RUSTSEC-2026-0097)

## [0.5.0] - 2026-04-10

### Added

- DFS (Distributed File System) support — resolve `\\domain\dfs-namespace\path` transparently, follow referrals across
  servers, multi-target failover, TTL-based referral cache
  ([d353490](https://github.com/vdavid/smb2/commit/d353490),
  [bfd8557](https://github.com/vdavid/smb2/commit/bfd8557),
  [03c4c2a](https://github.com/vdavid/smb2/commit/03c4c2a),
  [87a7d78](https://github.com/vdavid/smb2/commit/87a7d78))
- Compound delete (1 RTT instead of 2), compound rename (1 RTT instead of 3), compound stat (1 RTT instead of 4)
  ([33938591](https://github.com/vdavid/smb2/commit/33938591),
  [5e0f7a5](https://github.com/vdavid/smb2/commit/5e0f7a5),
  [4dc8fb8](https://github.com/vdavid/smb2/commit/4dc8fb8))
- `read_file_with_progress` for pipelined reads with progress callback and cancellation
  ([37e3370](https://github.com/vdavid/smb2/commit/37e3370))
- Batch operations — `delete_files`, `rename_files`, `stat_files` send all compound requests before waiting for
  responses, partial failures are independent ([afe4395](https://github.com/vdavid/smb2/commit/afe4395))
- DFS wire format types: `ReqGetDfsReferral`, `RespGetDfsReferral` with V2/V3/V4 referral entries
  ([e9e5bf9](https://github.com/vdavid/smb2/commit/e9e5bf9))
- Auto-set `SMB2_FLAGS_DFS_OPERATIONS` based on tree capabilities
  ([f254e96](https://github.com/vdavid/smb2/commit/f254e96))
- Connection pool for DFS cross-server routing, `ClientConfig.dfs_enabled` and `dfs_target_overrides`
  ([03c4c2a](https://github.com/vdavid/smb2/commit/03c4c2a),
  [edcf730](https://github.com/vdavid/smb2/commit/edcf730))
- Docker DFS test containers (smb-dfs-root:10456, smb-dfs-target:10457) with 4 integration tests
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))

### Fixed

- IOCTL `InputOffset` double-counted `Header::SIZE`, causing `STATUS_INVALID_PARAMETER` on DFS referral requests
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))
- DFS paths missing `server\share` prefix in `Tree::format_path`
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))
- Cross-server routing matched hostname-only instead of addr:port
  ([edcf730](https://github.com/vdavid/smb2/commit/edcf730))

## [0.4.0] - 2026-04-09

### Added

- Kerberos authentication — full AS + TGS + AP-REQ flow with pre-auth, tested end-to-end against Windows Server 2022
  with Active Directory Domain Services
  ([9b40b00](https://github.com/vdavid/smb2/commit/9b40b00))
- Kerberos credential cache (ccache) support — read MIT Kerberos ccache files (v3 and v4) for password-less auth from
  `kinit` tickets, `Session::setup_kerberos_from_ccache()`
  ([2344f15](https://github.com/vdavid/smb2/commit/2344f15))
- AP-REP mutual authentication — server sub-session key extraction for cryptographic server identity proof
  ([b966d2c](https://github.com/vdavid/smb2/commit/b966d2c))
- SPNEGO token wrapping — hand-rolled ASN.1/DER encoding for NegTokenInit/NegTokenResp (RFC 4178 / MS-SPNG), no external
  ASN.1 dependency ([c27c88f](https://github.com/vdavid/smb2/commit/c27c88f))
- Kerberos crypto: AES-CTS (RFC 3962), RC4-HMAC (RFC 4757), PBKDF2 string-to-key, n-fold, HMAC-SHA1-96 checksums
  ([e23b851](https://github.com/vdavid/smb2/commit/e23b851))
- Kerberos ASN.1 messages: AS-REQ, TGS-REQ, AP-REQ, Authenticator, KDC-REP parsing — all hand-rolled DER
  ([97b57a5](https://github.com/vdavid/smb2/commit/97b57a5))
- KDC client: UDP primary with TCP fallback on `KRB_ERR_RESPONSE_TOO_BIG`, exponential backoff retries
  ([97b57a5](https://github.com/vdavid/smb2/commit/97b57a5))
- `Session::setup_kerberos()` and `Session::setup_kerberos_from_ccache()` public API
  ([3a63337](https://github.com/vdavid/smb2/commit/3a63337),
  [2344f15](https://github.com/vdavid/smb2/commit/2344f15))
- Support for AES-256, AES-128, and RC4-HMAC encryption types, with AES-256 preferred
  ([01ad252](https://github.com/vdavid/smb2/commit/01ad252))

### Fixed

- KDC-REP field tags: pvno is `[0]` not `[1]` per RFC 4120
  ([3a63337](https://github.com/vdavid/smb2/commit/3a63337))
- AES-CTS key derivation: Ki constant is 0x55 (encrypt/decrypt integrity), not 0x99 (standalone checksum)
  ([661a245](https://github.com/vdavid/smb2/commit/661a245))
- TGS-REQ AP-REQ Authenticator was missing body checksum over KDC-REQ-BODY (RFC 4120 section 7.2.2, key usage 6)
  ([661a245](https://github.com/vdavid/smb2/commit/661a245))

### Key implementation details

Hard-won lessons from testing against Windows AD (documented in `src/auth/CLAUDE.md`):

- MS Kerberos OID (`1.2.840.48018.1.2.2`) required as primary SPNEGO mechanism for Windows
- Key usage 11 (not 7) for AP-REQ Authenticator encryption in SPNEGO exchanges
- GSS-API wrapping of AP-REQ inside SPNEGO mechToken
- Raw ticket byte pass-through (re-encoding corrupts the encrypted ticket)
- Session key etype detection from TGS-REP (may differ from ticket encryption type)

## [0.3.0] - 2026-04-08

### Added

- Compound requests — CREATE+READ+CLOSE (3-way) and CREATE+WRITE+FLUSH+CLOSE (4-way) as single transport frames,
  reducing round-trips from 3-4 to 1 per file operation
  ([a9293b6](https://github.com/vdavid/smb2/commit/a9293b6),
  [cb022bc](https://github.com/vdavid/smb2/commit/cb022bc))
- `read_file()` and `write_file()` auto-select compound (small) or pipelined (large) — callers don't choose
  ([25b2f68](https://github.com/vdavid/smb2/commit/25b2f68),
  [cb022bc](https://github.com/vdavid/smb2/commit/cb022bc))
- Streaming upload with `FileUpload` — compound for small files, chunked for large, same caller API either way
  ([8b2283a](https://github.com/vdavid/smb2/commit/8b2283a))
- Streaming download with `FileDownload`, progress reporting with `ControlFlow`-based cancellation
  ([c11f5f3](https://github.com/vdavid/smb2/commit/c11f5f3))
- Sliding window pipeline — each response immediately triggers the next chunk, keeping the TCP pipe full
  ([dd36181](https://github.com/vdavid/smb2/commit/dd36181))
- SMB 3.x encryption wired into client layer — TRANSFORM_HEADER wrapping, sign-then-compress-then-encrypt send path,
  AES-128/256-CCM/GCM ([101d22d](https://github.com/vdavid/smb2/commit/101d22d))
- LZ4 compression wired into connection layer — negotiated during handshake, applied per-message when it reduces size
  ([e2921f9](https://github.com/vdavid/smb2/commit/e2921f9))
- File watching via `CHANGE_NOTIFY` — `Watcher` struct with `next_events()` long-poll, recursive watching support
  ([75b281d](https://github.com/vdavid/smb2/commit/75b281d))
- Disk space query (`fs_info`) via compound CREATE+QUERY_INFO+CLOSE
  ([6d3a05c](https://github.com/vdavid/smb2/commit/6d3a05c))
- `ErrorKind` for high-level error classification — `NotFound`, `AccessDenied`, `ConnectionLost`, etc. instead of raw
  NTSTATUS codes ([58aead2](https://github.com/vdavid/smb2/commit/58aead2))
- Oplock break notification handling — detected by MessageId `0xFFFF...`, logged and skipped without crashing
  ([371b984](https://github.com/vdavid/smb2/commit/371b984))
- `STATUS_BUFFER_OVERFLOW` accepted as partial success in QueryInfo responses
  ([4122d16](https://github.com/vdavid/smb2/commit/4122d16))
- CANCEL requests and session expiry detection with `Error::SessionExpired`
  ([4924a2a](https://github.com/vdavid/smb2/commit/4924a2a))
- Docker test infrastructure — 12 Samba containers covering guest, auth, signing, readonly, ancient (SMB1), flaky, slow,
  encryption (GCM + CCM), 50 shares, max read size, with 43 integration tests
  ([8edf837](https://github.com/vdavid/smb2/commit/8edf837),
  [7ee088f](https://github.com/vdavid/smb2/commit/7ee088f),
  [812ad39](https://github.com/vdavid/smb2/commit/812ad39))
- Docker tests in CI — builds containers and runs 43 tests on every PR
  ([488e1d0](https://github.com/vdavid/smb2/commit/488e1d0))
- 7 runnable examples: `list_shares`, `list_directory`, `read_file`, `streaming_download`, `disk_space`,
  `watch_directory`, `write_file` ([7203bdb](https://github.com/vdavid/smb2/commit/7203bdb))
- `Send + Sync` bounds on `Pack` trait for async callers
  ([4538205](https://github.com/vdavid/smb2/commit/4538205))
- GitHub Actions CI: fmt, clippy, test, doc, MSRV 1.85
  ([f0b00cd](https://github.com/vdavid/smb2/commit/f0b00cd))

### Fixed

- `STATUS_PENDING` handling — `receive_response()` now loops past interim responses instead of treating them as errors
  ([8edf837](https://github.com/vdavid/smb2/commit/8edf837))
- Multi-credit charges — streaming download/upload and `write_file_with_progress` were sending `credit_charge=1` for
  MB-sized payloads, Samba rejects with `STATUS_INVALID_PARAMETER`
  ([8edf837](https://github.com/vdavid/smb2/commit/8edf837))
- Cipher fallback — fall back to AES-128-CCM when server omits encryption negotiate context
  ([812ad39](https://github.com/vdavid/smb2/commit/812ad39))

### Improved

- Smart read selection — sequential for files < MaxReadSize (1 RTT), pipelined only when beneficial
  ([3f0cd77](https://github.com/vdavid/smb2/commit/3f0cd77))
- Credit request bumped from 32 to 256 per request, credits grow rapidly
  ([dd36181](https://github.com/vdavid/smb2/commit/dd36181))
- Pipeline uses server-negotiated MaxReadSize/MaxWriteSize with correct multi-credit CreditCharge
  ([b0cacdd](https://github.com/vdavid/smb2/commit/b0cacdd))
- `trivial_message!` and `nt_status_codes!` macros to reduce boilerplate
  ([fb4b9e4](https://github.com/vdavid/smb2/commit/fb4b9e4))
- CLAUDE.md files for all 8 modules, agent docs colocated with code
  ([2d884d0](https://github.com/vdavid/smb2/commit/2d884d0))

## [0.2.0] - 2026-04-08

### Added

- Concurrent pipelined read and write — send multiple READ/WRITE requests by filling the credit window, reassemble
  responses in offset order, handles out-of-order responses
  ([7f3068a](https://github.com/vdavid/smb2/commit/7f3068a))
- Share enumeration — IPC$ + srvsvc RPC flow, QNAP returns 8 disk shares, Pi returns 1
  ([cbed0ab](https://github.com/vdavid/smb2/commit/cbed0ab))
- `SmbClient` high-level API — `connect()`, `list_shares()`, `connect_share()`, `reconnect()`, stored credentials
  ([cbed0ab](https://github.com/vdavid/smb2/commit/cbed0ab))
- Convenience `smb2::client::connect("host:445", "user", "pass")` one-liner
  ([cbed0ab](https://github.com/vdavid/smb2/commit/cbed0ab))
- File operations: `write_file`, `delete_file`, `stat`, `rename`, `create_directory`, `delete_directory`
  ([c80f126](https://github.com/vdavid/smb2/commit/c80f126))
- Clean re-exports from `lib.rs` — `use smb2::{SmbClient, Tree}` instead of reaching into submodules
  ([cdb203e](https://github.com/vdavid/smb2/commit/cdb203e))
- 4 runnable examples: `list_shares`, `list_directory`, `read_file`, `write_file`
  ([cdb203e](https://github.com/vdavid/smb2/commit/cdb203e))
- Benchmarks against native macOS SMB and `smb` crate:
  small files 2-3x faster, medium files match native on upload, 8.5x faster than `smb` on download
  ([031d52b](https://github.com/vdavid/smb2/commit/031d52b),
  [4cbc961](https://github.com/vdavid/smb2/commit/4cbc961))
- Integration tests against QNAP NAS (SMB 3.1.1, NTLM, AES-GMAC) and Raspberry Pi 4 (SMB 3.1.1, guest)
  ([c80f126](https://github.com/vdavid/smb2/commit/c80f126))

### Fixed

- Preauth hash: exclude final SESSION_SETUP success response from hash — including it produces wrong keys for SMB 3.1.1
  ([32f0f30](https://github.com/vdavid/smb2/commit/32f0f30))
- QueryDirectory: cap `OutputBufferLength` to 65536, always send `"*"` pattern (empty filename rejected by QNAP + Samba)
  ([b9d49f7](https://github.com/vdavid/smb2/commit/b9d49f7))
- GMAC uses AES-128-GCM (16-byte key), not AES-256-GCM
  ([dc91351](https://github.com/vdavid/smb2/commit/dc91351))
- GMAC nonce needs server role bit for response verification
  ([dc91351](https://github.com/vdavid/smb2/commit/dc91351))
- Only verify signature when `SMB2_FLAGS_SIGNED` is set (skip STATUS_PENDING and oplock breaks)
  ([dc91351](https://github.com/vdavid/smb2/commit/dc91351))

## [0.1.0] - 2026-04-07

### Added

- SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 dialect support — negotiate with all five dialects, preauth integrity, encryption,
  compression, and signing negotiate contexts
  ([c3a2e43](https://github.com/vdavid/smb2/commit/c3a2e43),
  [36428728](https://github.com/vdavid/smb2/commit/36428728))
- NTLM authentication (NTLMv2 with MIC) — full NEGOTIATE/CHALLENGE/AUTHENTICATE flow, session key exchange, known-answer
  test vectors from MS-NLMP section 4.2.4
  ([60c4163](https://github.com/vdavid/smb2/commit/60c4163))
- Wire format pack/unpack for all 19 SMB2 commands — header, negotiate, session setup, tree connect, create, close,
  read, write, flush, lock, ioctl, query directory, change notify, query info, set info, echo, cancel, logoff, oplock
  break, transform header, compression header
  ([c3a2e43](https://github.com/vdavid/smb2/commit/c3a2e43))
- Binary serialization primitives — `ReadCursor`/`WriteCursor` with LE primitives, UTF-16LE, alignment, backpatching,
  `Pack`/`Unpack` traits, `Guid` with mixed-endian layout, `FileTime` with Windows epoch conversion
  ([8be0549](https://github.com/vdavid/smb2/commit/8be0549))
- Newtypes for all protocol IDs: `SessionId`, `MessageId`, `TreeId`, `CreditCharge`, `FileId` with sentinel constants
  ([8be0549](https://github.com/vdavid/smb2/commit/8be0549))
- TCP transport with split send/receive traits (avoids deadlock in pipeline's `select!` loop), correct framing (0x00 +
  3-byte BE length), 16 MB max frame, Nagle disabled
  ([5ae8027](https://github.com/vdavid/smb2/commit/5ae8027))
- MockTransport for TDD — FIFO response queue, message recording, assertion helpers
  ([5ae8027](https://github.com/vdavid/smb2/commit/5ae8027))
- SMB 3.x signing: HMAC-SHA256 (2.0.2/2.1), AES-128-CMAC (3.0/3.0.2), AES-256-GMAC (3.1.1)
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- SMB 3.x encryption: AES-128/256-CCM and AES-128/256-GCM with monotonic nonce generator
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- SP800-108 key derivation for SMB 3.0/3.0.2 (legacy labels) and 3.1.1 (preauth hash context)
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- LZ4 compression via `lz4_flex` (pure Rust, zero C deps)
  ([a7080f3](https://github.com/vdavid/smb2/commit/a7080f3))
- Connection layer: negotiate, credit management, message ID sequencing, preauth hash tracking, signing integration
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- Session layer: multi-round-trip SESSION_SETUP with NTLM, key derivation per dialect, signing activation
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- Tree layer: TREE_CONNECT with UNC path, directory listing, file reading
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- RPC module: DCE/RPC PDU encoding, NDR encoding for `NetShareEnumAll`
  ([36428728](https://github.com/vdavid/smb2/commit/36428728))
- Structured logging via `log` crate — info for lifecycle, debug for protocol, trace for bytes, never logs secrets
  ([1d7273a](https://github.com/vdavid/smb2/commit/1d7273a))
- Error types with `is_retryable()`, `status()`, `Auth`, `Timeout`, `Disconnected`, `SessionExpired` variants
  ([5ae8027](https://github.com/vdavid/smb2/commit/5ae8027))
- `MAX_UNPACK_BUFFER` (16 MB) allocation cap to prevent OOM from malicious packets
  ([073452c](https://github.com/vdavid/smb2/commit/073452c))
- 512 unit tests, 10 integration tests against real hardware, zero clippy warnings
