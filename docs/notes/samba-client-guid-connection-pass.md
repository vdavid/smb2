# Samba hands off connections that share a `ClientGuid`

Samba routes a new connection by the `ClientGuid` in its NEGOTIATE. If the guid belongs to a client it
already has, it passes the TCP connection to the smbd process owning the first one
(`smbXsrv_connection_pass`, the machinery behind multi-channel). That hand-off is racy: when two connects
overlap, one of them arrives in the destination process with its negotiate never replayed, so its sequence
window is never opened and the next request on it is rejected.

**This crate sidesteps it by giving every connection its own guid** (`Inner::client_guid`). What follows is
why that is the right shape and how to tell if it ever regresses.

## What it looked like

A connect that hung ~30 s and ended in `Error::ServerUnresponsive` ("nothing on the wire for 30.05s"), or in
`Error::Disconnected`. It landed on a different caller each run, at a few percent, and only when several
connects to the same server overlapped. Samba's log said:

```
smb2_validate_message_id: client used more credits than granted,
    mid 1, charge 1, credits_granted 0, seqnum low/range: 1/0
```

`credits_granted 0` with a window of `low=1, range=0` is Samba's state *after* it validated the NEGOTIATE
(mid 0) and *before* it credited that request's response. The SESSION_SETUP arrived against a connection
whose NEGOTIATE grant was never committed.

**Not the credit-pool bug 0.20.0 fixed**, though it prints the same Samba line. That one was a request racing
the handshake and spending NEGOTIATE's seeded permit; it needs a second request, and this needs none.

The client was never at fault, and that was measured rather than assumed. Probing the negotiate response and
the session-setup reservation across 100 concurrent connects gave the same two lines every time:

```
neg-response granted=1 pool_now=1 msg_id=MessageId(0)
session-setup reserved charge=1 pool_left=0
```

One credit asked for, one granted, exactly one spent, no second request. Which matters, because Samba grants
**no additional credits** on NEGPROT or SESSION_SETUP (`smb2_set_operation_credit` caps `additional_max` at 0
for both): a client holds exactly one credit for the whole handshake and has no room to be sloppy.

## The evidence for the hand-off

Samba 4.20.6 at `log level = 10`, 200 connects four at a time. `smbXsrv_connection_pass` appears 2,358 times,
so essentially every connection is passed. Around each failure the log carries two pass records for the same
guid: the first with the negotiate stored (`negotiate_request: DATA_BLOB length=218`), the second with
nothing in it (`length=0`), and then, on the very next request:

```
smbd_smb2_request idx[1] of 5 vectors
smb2_validate_message_id: client used more credits than granted, mid 1, ...
smbd_server_connection_terminate_ex: conn[PID=191,CLIENT=086a7099-...,channel=1,...]
    num_ok[0] reason[NT_STATUS_INVALID_PARAMETER]
```

The keying happens at negprot, before any capability is negotiated, so declining
`SMB2_GLOBAL_CAP_MULTI_CHANNEL` does not opt out of it. Setting `server multi channel support = no` on the
server does: with it, 448 concurrent handshakes that otherwise failed 25 times passed in 0.24 s. That's the
escape hatch for a server whose clients you don't control; it is not what this crate relies on.

## The measurements

Samba 4.20.6 (`tests/docker/internal/smb-auth`), 2026-08-28, connects issued in waves from one process.

With one guid shared across connections:

- 2 at a time: 0 failures in 200 connects.
- 4 at a time: 11 in 200.
- 8 at a time: 5 in 200.
- 16 at a time: 7 in 208.
- 4, 8, and 16 mixed: 25 in 448, and the run took 51.6 s because each failure waits out a timeout.
- 25 at a time, **each connection given its own guid**: 0 in 250.

With a guid per connection, which is what ships: 0 in 448, in 0.39 s.

## Why a guid per connection is safe

`ClientGuid` identifies the *client*, not the connection (MS-SMB2 § 2.2.3), and two things in SMB care:
multi-channel, and durable-handle reclaim (MS-SMB2 § 3.3.5.9.12 matches on it). This crate implements no
multi-channel and opens independent connections rather than channels, so nothing here wants them grouped.

Reclaim does need stability, and gets it: the guid lives on `Inner`, which survives a revival. A connection
that comes back on a fresh socket renegotiates with the same guid it always had, so a reclaim after a
reconnect still looks like the same client. That is the constraint to respect if this ever changes; a guid
minted per NEGOTIATE would break resume, which is a data-integrity feature, not a nicety.

## What guards it

- `concurrent_connects_all_finish_their_handshake` in `crates/smb2/tests/docker_integration.rs`: 448
  handshakes at widths 4, 8, and 16. It fails within a minute if a shared guid ever comes back.
- `rm_at_full_pool_width_deletes_every_path` in `crates/smb2-cli/tests/e2e.rs`: the same thing through the
  binary, at the `-j 16` the CLI's README quotes.
