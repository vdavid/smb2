# Share enumeration on legacy servers: RAP `NetShareEnum` fallback — maintainer assessment

Status: triage / scoping (no implementation). Date: 2026-06-01.

> **Update (2026-06-01):** the narrower work recommended in §5 (DCE/RPC fragment reassembly +
> `STATUS_BUFFER_OVERFLOW` continuation) has since been implemented and verified against real Samba — see the
> `smb-manyshares` fixture and `manyshares_list_all_spans_multiple_fragments` (the server fragmented a 200-share
> reply into 26 RPC fragments, all reassembled). The RAP fallback remains declined as below. Line numbers cited
> below are from before the fix.

A downstream consumer asked us to add a legacy RAP `NetShareEnum` fallback (LANMAN API opcode 0, over
`\PIPE\LANMAN`) so `list_shares` covers older SMB servers (older Samba, some NAS firmware) where our srvsvc
path returns an error or an empty list. They currently shell out to `smbutil view` / `smbclient -L` to cover
those servers and want to delete that platform glue.

**Verdict: decline the RAP fallback (out of scope for an SMB2/3 crate). Do a narrower thing instead — harden
the existing srvsvc path.** Reasoning below, grounded in our source and the specs.

## 1. How we enumerate today

`SmbClient::list_shares` → `client/shares.rs` → `rpc/srvsvc.rs`:

- Tree-connect `IPC$`, `CREATE` the `srvsvc` pipe, RPC `BIND`, then one RPC `REQUEST` and one `RESPONSE`
  (`client/shares.rs:108-138`).
- The call is **srvsvc `NetrShareEnum`, opnum 15, `SHARE_INFO_1`** (`rpc/srvsvc.rs:66-89`, `94-97`). That
  matches MS-SRVS §3.1.4.8 (`NetrShareEnum`) with a `SHARE_INFO_1` container.
- The pipe exchange uses SMB2 `WRITE` + `READ` against the pipe handle (`client/shares.rs:172-233`), not
  `FSCTL_PIPE_TRANSCEIVE`. Functionally equivalent for DCE/RPC.

So the consumer's hypothesis — "we implement srvsvc but not RAP" — is factually correct about what we
implement. It's the *conclusion* (add RAP over SMB2) that doesn't hold up.

### Two real weaknesses in the srvsvc path

Both can produce exactly the reported symptom (error / short list where shares clearly exist), and both are
on SMB2-capable servers, so they're in scope:

1. **No multi-fragment RPC reassembly.** `rpc::parse_response` reads a single PDU's stub up to `frag_length`
   and ignores anything after it (`rpc/mod.rs:233-269`); `client/shares.rs` issues exactly one `read_pipe`
   (`shares.rs:133`). A DCE/RPC server may split a large `NetrShareEnum` reply across fragments, clearing
   `PFC_LAST_FRAG` on all but the last (MS-RPCE §2.2.2.6, the `pfc_flags` stitching rules). Our `BIND`
   advertises `MAX_RECV_FRAG = 4280` (`rpc/mod.rs:48`), which invites fragmentation. We get away with it on
   the `smb-50shares` fixture because that reply lands in one fragment, but a server with more shares or long
   names/comments would feed `parse_net_share_enum_all_stub` a truncated first fragment → parse error or a
   short list. This is silent on the happy path and exactly matches "empty/short list where the listing
   exists."

2. **No `STATUS_BUFFER_OVERFLOW` continuation.** `read_pipe` treats any non-`SUCCESS` status as a hard error
   (`shares.rs:222-227`). When a pipe message is larger than the read buffer, the SMB2 server returns
   `STATUS_BUFFER_OVERFLOW` (a warning, `0x80000005`) with partial data and expects another `READ`
   (MS-SMB2 §3.3.5.10, pipe-read semantics). We already model this warning as partial success
   (`NtStatus::is_success_or_partial`, `types/status.rs:218`) and use it on the QueryInfo path
   (`client/tree.rs`), but the pipe-read path doesn't. So a server that chunks its srvsvc reply makes us
   error out instead of reading the rest.

These two are the cheap, in-scope fix and the most likely real cause for any server we *can* reach.

## 2. The gating question: are the failing servers SMB1-only?

This decides everything, and the answer is the reason to decline.

**RAP is structurally bound to SMB1.** MS-RAP §2.1 (Transport): *"The Remote Administration Protocol is
implemented using the SMB_COM_TRANSACTION functionality in the SMB Protocol."* MS-RAP §1.5
(Prerequisites): the negotiated dialect *"has to be for Microsoft LAN Manager version 1.0 or later"* — i.e.
the SMB1 dialect family. The whole request/response is carried in the **Parameters** and **Data** sub-buffers
of an `SMB_COM_TRANSACTION` (MS-RAP §2.2, §2.3; MS-CIFS §2.2.4.33).

`SMB_COM_TRANSACTION` does not exist in SMB2/3. It appears **zero times** in the MS-SMB2 spec. There is no
SMB2 PDU that carries a TRANS Parameters/Data pair. RAP requests are split across those two sub-buffers
(request block in Parameters; bulk data in Data; response status + converter + `EntriesReturned` in
Parameters, `RAPOutData` in Data) — a shape that has no representation over an SMB2 connection.

**The "RAP over `FSCTL_PIPE_TRANSCEIVE`" idea conflates two different pipe transports.** We do have
`FSCTL_PIPE_TRANSCEIVE` (`msg/ioctl.rs:19`, used by DFS), and yes, you can write arbitrary bytes to a pipe
and read a reply with it. But:
- It's a single input buffer + single output buffer. It cannot express the TRANS Parameters-vs-Data split
  that RAP framing requires.
- More importantly, no server *serves* `\PIPE\LANMAN` as a RAP endpoint over SMB2. In Samba, RAP
  (`source3/smbd/lanman.c`) is dispatched only from the SMB1 `reply_trans` path. Over SMB2, named-pipe opens
  route to the DCE/RPC subsystem (`np_*`), which has no LANMAN/RAP handler. Modern Windows dropped SMB1
  entirely, so the RAP pipe isn't there at all over SMB2.

So `smbclient -L`'s RAP fallback succeeds on those boxes precisely because it **drops to SMB1 (NT1)** to do
it — that's what "fall back to RAP" means in practice. The servers where RAP is the only thing that answers
are servers being spoken to over SMB1.

Our crate negotiates **SMB 2.0.2 and up only** (`msg/negotiate.rs:657`, `:734`) and already rejects SMB1
servers cleanly at negotiate (`tests/docker_integration.rs:1300`, `ancient_smb1_rejected_cleanly`, against the
`smb-ancient` NT1-only container). An SMB2/3 client fundamentally cannot reach a RAP-only server. Adding RAP
code wouldn't change that — there's no SMB2 frame to put it in.

This splits the consumer's "failing servers" into two cases:
- **SMB1-only boxes** (the genuine legacy case): unreachable by us, period. Out of scope no matter what we
  build. The only way to serve them is to implement SMB1 negotiate + session setup + `SMB_COM_TRANSACTION`,
  which is a different protocol and a non-goal for this crate.
- **SMB2/3-capable boxes whose srvsvc misbehaves** (restricted, chunked, or fragmented replies): reachable,
  and the right fix is §1's srvsvc hardening, not RAP.

## 3. Broad-benefit vs. cost — the maintainer call

Even setting feasibility aside, RAP is a poor fit for this crate:

- **It's strictly inferior where it works.** RAP `NetShareEnum` is ASCII-only and *"incapable of transmitting
  more than 64 KB of data in any protocol exchange"* (MS-RAP §1.6) — no Unicode share names or comments, hard
  64 KB cap. srvsvc (UTF-16, fragmentable, resume handle) is the better answer on every server that can run
  it.
- **It's a distinct, fiddly serialization surface.** The packed `WrLeh`-style parameter/data descriptor
  strings (MS-RAP §2.2.5) are a separate codec from our DCE/RPC + NDR work in `rpc/`. Carrying it means a new
  parser, new fuzz targets, and new edge cases, for a path that only an SMB1 transport could ever exercise —
  which we don't have.
- **Reach doesn't actually grow.** The consumer base benefit of "enumerate shares on SMB2/3-capable servers"
  is real and we should capture it — but that's §1, not RAP. RAP only adds reach to SMB1-only servers, which
  we can't connect to anyway.

Net: carrying RAP is protocol-surface creep with no reachable consumer it can serve.

## 4. If we ever did want SMB1-only-server reach (we don't)

For completeness: covering genuine SMB1-only boxes would require SMB1 framing
(`SMB_COM_NEGOTIATE`/`SESSION_SETUP_ANDX`/`TREE_CONNECT_ANDX`/`TRANSACTION`, MS-CIFS / MS-SMB). That's a
second protocol stack bolted onto a crate whose entire identity is "pure-Rust **SMB2/3** client." It would
roughly double the negotiate/session surface and reintroduce the SMB1 security posture we deliberately don't
speak. Decline.

## 5. Recommended narrower work (srvsvc hardening)

Scope this as one focused change to `rpc/` + `client/shares.rs`:

1. **Multi-fragment RPC reassembly.** In the response path, loop reading PDUs and concatenating stub data
   until a fragment has `PFC_LAST_FRAG` set, validating `call_id` and `ptype` per fragment (MS-RPCE §2.2.2.6).
2. **`STATUS_BUFFER_OVERFLOW` continuation reads.** In `read_pipe`, accept `is_success_or_partial()` and keep
   issuing `READ`s, appending data, until a `SUCCESS` read completes the message — reusing the existing
   `NtStatus::is_success_or_partial` helper (`types/status.rs:218`).
3. (Optional, low value) **Info-level fallback.** If a server rejects `SHARE_INFO_1`, retry `SHARE_INFO_0`.
   Defer unless a real server shows the need — level 1 is near-universal on srvsvc.

### Effort

Small. Roughly a half-day to a day: the codec changes are localized to `rpc/mod.rs::parse_response` (frag
loop) and `client/shares.rs::read_pipe` (overflow loop), plus tests. No new public API, no new dependency, no
new transport.

### Test strategy (deterministic, no live archaeology needed)

- **Unit (codec):** Hand-build a two-fragment `NetrShareEnum` RESPONSE (first PDU `PFC_FIRST_FRAG` only, second
  `PFC_LAST_FRAG`) and assert the reassembled stub parses to the full share list. We already build canned PDUs
  in `rpc/srvsvc.rs` tests and `client/shares.rs` tests — extend those helpers. Add a fuzz seed for a
  multi-fragment response.
- **Unit (overflow):** Queue a `read_pipe` sequence on `MockTransport` returning `STATUS_BUFFER_OVERFLOW` +
  partial data, then `SUCCESS` + the rest; assert we stitch and parse correctly. `MockTransport` already drives
  the `shares.rs` flow (`client/shares.rs:457` `queue_share_listing_responses`).
- **Docker (repro):** Add a Samba fixture that forces fragmentation — a `smb-manyshares` container with enough
  shares + long comments to push the srvsvc reply past one 4280-byte fragment. That reproduces the failing
  condition against a real server and pins the fix. (Toggling srvsvc *off* would only reproduce the SMB1 case,
  which we've established we can't serve — so the useful fixture is "srvsvc on, reply fragmented," not "srvsvc
  off.")

## 6. What to tell the consumer

- We can make `list_shares` more robust on **SMB2/3-capable** servers via §5 (fragment reassembly + overflow
  continuation). That's likely to recover a chunk of the boxes where they see errors/short lists today.
- For genuinely **SMB1-only** servers, no SMB2/3 library can enumerate shares — `smbclient -L` succeeds there
  by dropping to SMB1, which is out of scope for `smb2`. They should either keep the platform-CLI fallback
  scoped to *only* the SMB1-only case (after our negotiate returns the clean SMB1-rejection error), or accept
  that those boxes are unreachable. The credential-on-command-line concern they raised is real, but it only
  applies to the SMB1 remnant, not the broad case.

## References

- MS-RAP §1.5, §1.6, §1.7, §1.9, §2.1, §2.2, §2.3, §2.5.6 (`NetShareEnum`) — RAP transport, dialect
  prerequisite, 64 KB / ASCII limits, `\PIPE\LANMAN`.
- MS-SMB2 — no `SMB_COM_TRANSACTION` (0 occurrences); §3.3.5.10 pipe-read / `STATUS_BUFFER_OVERFLOW`.
- MS-RPCE §2.2.2.6 — `pfc_flags` first/last fragment stitching.
- MS-SRVS §3.1.4.8 — `NetrShareEnum`, opnum 15, `SHARE_INFO_1`.
- Our source: `client/shares.rs:108-233`, `rpc/mod.rs:233-269`, `rpc/srvsvc.rs:66-97`,
  `msg/negotiate.rs:657`, `msg/ioctl.rs:19`, `types/status.rs:218`, `tests/docker_integration.rs:1300`.
</content>
</invoke>
