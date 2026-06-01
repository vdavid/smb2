# RPC -- named pipe RPC for share enumeration

DCE/RPC over SMB2 named pipes. Used to list shares on a server via the srvsvc interface.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | RPC PDU building/parsing: BIND, BIND_ACK, REQUEST, RESPONSE |
| `srvsvc.rs` | NDR encoding for `NetShareEnumAll` (opnum 15), `ShareInfo` type |

## Protocol flow

1. Tree connect to `IPC$`
2. CREATE `srvsvc` pipe (server prepends `\pipe\`)
3. WRITE: RPC BIND (call_id=1, srvsvc UUID + NDR transfer syntax)
4. READ: RPC BIND_ACK -- verify context accepted
5. WRITE: RPC REQUEST (call_id=2, opnum=15, NDR-encoded NetShareEnumAll)
6. READ: RPC RESPONSE -- NDR-decode share list
7. CLOSE pipe
8. Tree disconnect IPC$

Used by `client/shares.rs` which orchestrates the full flow via `SmbClient::list_shares()`.

## NDR encoding

`srvsvc.rs` handles NDR (Network Data Representation) encoding/decoding:
- Conformant arrays: max_count prefix, then elements
- Conformant varying strings: max_count + offset + actual_count + UTF-16LE data
- Referent pointers: non-zero pointer ID, then deferred data
- All 4-byte aligned

## Key decisions

- **call_id convention**: 1 for BIND, 2 for REQUEST. Arbitrary but consistent with smb-rs.
- **Max fragment size 4280**: Default `MAX_XMIT_FRAG` / `MAX_RECV_FRAG`. Matches common implementations.

## Response reassembly (two independent layers)

A `NetShareEnum` reply can be split two different ways, and the client handles both. They compose: a fragment loop wrapping a buffer-overflow loop.

- **DCE/RPC fragmentation (MS-RPCE 2.2.2.6)**: a large response may arrive as several RESPONSE PDUs, each its own pipe message, with `PFC_LAST_FRAG` set only on the last. `parse_response_fragment` returns `(stub, is_last)`; `client/shares.rs` loops reading PDUs and concatenating stubs until `is_last`, then NDR-decodes the joined stub via `srvsvc::parse_net_share_enum_all_stub`. `parse_response` is the single-fragment convenience wrapper (`parse_response_fragment(..).map(|(s, _)| s)`).
- **SMB pipe `STATUS_BUFFER_OVERFLOW` (MS-SMB2 3.3.5.10)**: a single pipe message larger than our 64 KiB read buffer comes back as overflow reads (partial data) terminated by a `SUCCESS` read. `client::shares::read_pipe_message` follows this, appending chunks until `SUCCESS`. The two phenomena are usually mutually exclusive in practice (fragments ≤ `MAX_RECV_FRAG` 4280 fit in one read; a server that ignores the frag cap sends one big PDU that overflows), but the code handles either or both.

## Gotchas

- **Pipe name is `srvsvc`**: The server prepends `\pipe\` automatically. Don't include it in the CREATE request.
- **Admin shares filtered out**: `list_shares` filters shares ending with `$` (IPC$, ADMIN$, C$). Only disk shares returned by default.
- **RPC version is 5.0**: Connection-oriented RPC. `PFC_FIRST_FRAG | PFC_LAST_FRAG` together mark a complete single-fragment PDU; a cleared `PFC_LAST_FRAG` means more fragments follow (see reassembly above).
- **NDR string alignment**: After each string, pad to 4-byte boundary. Missing alignment causes the server to reject the request silently.
- **Don't gate pipe reads on `SUCCESS` only**: `STATUS_BUFFER_OVERFLOW` is a warning (partial data), not a failure. Use `NtStatus::is_success_or_partial` and read again, or you truncate/error on large replies from servers that chunk them. This previously made `list_shares` fail on servers whose listing exceeded one read or one fragment.
