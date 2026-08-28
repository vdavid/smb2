# Msg -- wire format message structs

One sub-module per SMB2 command. Each defines request and response structs with `Pack` and `Unpack` implementations.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `trivial_message!` macro for 4-byte stub messages, module declarations |
| `header.rs` | 64-byte SMB2 header (sync + async variants), `PROTOCOL_ID` (`0xFE 'S' 'M' 'B'`) |
| `negotiate.rs` | Negotiate contexts (preauth integrity, encryption, signing, compression) |
| `create.rs` | CREATE request/response; `create_contexts` is a raw byte chain, decoded by `create_context.rs` |
| `create_context.rs` | The CREATE context codec plus `DH2Q` / `DH2C` (durable handles v2) and `QFid` |
| `transform.rs` | `TransformHeader` (encryption, protocol ID `0xFD`), `CompressionTransformHeader` (`0xFC`) |

19 command modules total: negotiate, session_setup, logoff, tree_connect, tree_disconnect, create, close, flush, read, write, lock, ioctl, query_directory, change_notify, query_info, set_info, echo, cancel, oplock_break. Plus `dfs.rs` for DFS referral request/response wire format (used by IOCTL FSCTL_DFS_GET_REFERRALS) and `copychunk.rs` for the server-side copy structures (`SrvCopychunkCopy` / `SrvCopychunkResponse` / `SrvRequestResumeKeyResponse`, used by IOCTL FSCTL_SRV_COPYCHUNK / FSCTL_SRV_REQUEST_RESUME_KEY; the client API is in `client/copy.rs`).

## Patterns

- **Pack/Unpack**: All structs implement `pack(&self, &mut WriteCursor)` and `unpack(&mut ReadCursor) -> Result<Self>`. Hand-rolled, no proc macros.
- **Offset calculation**: All offsets in SMB2 are relative to the start of the SMB2 header (not the body, not the transport frame). When packing variable-length fields, compute `header_size + fixed_body_size` as the base offset.
- **StructureSize validation**: `Unpack` implementations read `StructureSize` first and return an error if it doesn't match the expected value.
- **`trivial_message!` macro**: Generates Pack/Unpack for 4-byte stub messages (StructureSize=4 + Reserved=0). Used by echo, cancel, logoff, tree_disconnect.

## Create contexts

`create_context.rs` packs and parses the name-tagged blob chain a CREATE carries (MS-SMB2 § 2.2.13.2): `Next` / `NameOffset` / `NameLength` / `DataOffset` / `DataLength`, name then data, every entry padded to 8 (the last one included — the spec only requires it of entries something follows, but Windows pads them all).

- The parser rejects a chain whose `Next`, name, or data points outside the entry rather than walking off the buffer.
- A context with no data reports `DataOffset = 0`, not a position past the end: servers read the field even when the length is 0.
- ❌ A durable-reconnect context (`DH2C`) must be the ONLY context in its CREATE — MS-SMB2 § 3.3.5.9.12 lets a server reject one that travels with company, and Samba does. See `client/durable.rs`.
- Wire layouts are pinned against the `smb-rs` reference implementation's own test vectors.

## Compound messages

Built by `Connection::send_compound`. Each sub-request's header has a `NextCommand` field pointing to the next message (8-byte aligned). The last message has `NextCommand = 0`. Related operations use `FileId::SENTINEL` (`0xFFFFFFFF:0xFFFFFFFF`) so the server substitutes the handle from the first CREATE.

## Transform headers

- **Encryption** (`0xFD 'S' 'M' 'B'`): 52-byte `TransformHeader` wraps encrypted message(s). Contains nonce, auth tag (signature), original message size, session ID.
- **Compression** (`0xFC 'S' 'M' 'B'`): `CompressionTransformHeader` wraps LZ4-compressed messages. Contains original and compressed sizes, algorithm ID.

## Gotchas

- **TCP framing is big-endian**: The 4-byte transport header (1 zero byte + 3-byte length) uses big-endian byte order. Everything inside the SMB2 message is little-endian. This is the only big-endian value in the entire protocol.
- **StructureSize is "fixed"**: The spec says StructureSize is the size of the fixed-length portion of the struct. It does NOT include variable-length buffers. It's validated on unpack.
- **`#![allow(missing_docs)]`**: This module opts out of doc requirements because wire format field names are self-documenting from the spec.
- **Manual offset arithmetic requires careful bounds**: In `dfs.rs`, `parse_referral_entry` uses `ensure_remaining(buf, pos, N)` before raw `buf[pos..]` reads. Count the fixed fields carefully -- V2's body is **18** bytes (server_type+flags+proximity+ttl + three u16 offsets), not 16. An off-by-2 here lets a malformed `entry_size` slip past the initial guard and panic on the last offset read. Fuzz-caught in 0.7.2; regression test `resp_parse_v2_short_entry_returns_clean_error`.

## Fuzzing

Parse entry points are exposed via the `fuzzing` feature (`smb2::fuzzing`) and exercised by the `fuzz/` crate. See
`fuzz/README.md` (if present) or run `just fuzz fuzz_header_parse 300` for a local sweep. Every new parser touching
external bytes should get a fuzz target wrapper added in `src/fuzzing.rs` and a matching `fuzz/fuzz_targets/*.rs`.
