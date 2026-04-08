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

## Gotchas

- **Pipe name is `srvsvc`**: The server prepends `\pipe\` automatically. Don't include it in the CREATE request.
- **Admin shares filtered out**: `list_shares` filters shares ending with `$` (IPC$, ADMIN$, C$). Only disk shares returned by default.
- **RPC version is 5.0**: Connection-oriented RPC. The `PFC_FIRST_FRAG | PFC_LAST_FRAG` flags indicate single-fragment PDUs (no fragmentation).
- **NDR string alignment**: After each string, pad to 4-byte boundary. Missing alignment causes the server to reject the request silently.
