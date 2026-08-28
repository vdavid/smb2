# Concurrent connects from one process wedge against Samba

**Symptom:** a connect that hangs ~30 s and ends in `Error::ServerUnresponsive` ("nothing on the wire for
30.05s"), or in `Error::Disconnected`. It lands on a different caller each run, at a low single-digit rate, and
only when several connects to the same server overlap. Samba's own log says:

```
smb2_validate_message_id: client used more credits than granted,
    mid 1, charge 1, credits_granted 0, seqnum low/range: 1/0
```

## What's actually happening

`credits_granted 0` with a sequence window of `low=1, range=0` is Samba's state *after* it validated the
NEGOTIATE (mid 0) and *before* it credited that request's response. In other words, the SESSION_SETUP arrives
against a connection whose NEGOTIATE grant was never committed.

The client is not at fault, and that was measured rather than assumed. Probing the negotiate response and the
session-setup reservation across 100 concurrent connects gave the same two lines every single time:

```
neg-response granted=1 pool_now=1 msg_id=MessageId(0)
session-setup reserved charge=1 pool_left=0
```

The client asks for one credit, is granted one, spends exactly one, and never sends a second request on it.
This matters because Samba grants **no additional credits** on NEGPROT or SESSION_SETUP (`smb2_set_operation_credit`
caps `additional_max` at 0 for both), so a client holds exactly one credit for the whole handshake and has no
room to be sloppy.

What differs between a working connect and a wedged one is which smbd process serves it. Every connection a
single process opens carries the same `ClientGuid` — MS-SMB2 § 3.2.1.1 makes it a per-client value, and
`client::connection::client_guid` holds one in a process-wide `OnceLock`. Samba, seeing a second connection
bearing a `ClientGuid` it already knows, passes the TCP connection to the smbd process that owns the first one
(`smbXsrv_connection_pass`, the machinery behind multi-channel; it keys off the GUID at negprot time, before any
capability negotiation, so not advertising `SMB2_GLOBAL_CAP_MULTI_CHANNEL` doesn't opt out of it). Under
concurrency that hand-off loses the negotiate's credit grant.

## The measurements

Samba 4.20.6 (`tests/docker/internal/smb-auth`), 2026-08-28, connects issued in waves from one process:

- 2 at a time: 0 failures in 200 connects.
- 4 at a time: 11 in 200.
- 8 at a time: 5 in 200.
- 16 at a time: 7 in 208.
- 25 at a time, **each connection given its own `ClientGuid`**: 0 in 250.

So it starts at four concurrent connects, doesn't get much worse with width, and vanishes entirely when the
GUIDs differ. Reproduce it with a program that spawns N tasks each doing `smb2::connect` + `connect_share`
against `127.0.0.1:10446`, in waves.

## What rests on this

- **`crates/smb2/tests/docker_integration.rs`** — the ~2-of-101 failures under full parallelism, always
  `ServerUnresponsive`, always different tests. Same cause: 101 tests in one process, one GUID.
- **`crates/smb2-cli/tests/e2e.rs`** — opens exactly one connection for the whole binary for this reason. Its
  `server()` doc explains it at the call site.
- **`smb2-cli -j N`** — the pool opens N connections from one process, so they share a GUID too. `-j 16` against
  a Raspberry Pi is the benchmark the CLI's README quotes and it has been reliable, and the E2E suite's batch
  commands (2–3 workers) have not tripped it in ~150 runs, but it is the same exposure and it is worth knowing
  about if a bulk run ever wedges at connect time.

## What hasn't been decided

Giving each `Connection` its own `ClientGuid` makes the symptom go away, and this crate implements no
multi-channel, so nothing here wants connections grouped. But `ClientGuid` identifies the *client*, not the
connection, and durable-handle reclaim (`client/durable.rs`) is specified in terms of it — a reclaim after a
revival has to look like the same client. Any change here has to keep a revived connection's GUID stable rather
than minting a fresh one per negotiate. That trade-off is unresolved; this note exists so the next person hits
the measurements instead of the mystery.
