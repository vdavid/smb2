# Msg -- wire format message structs

One sub-module per SMB2 command. Each defines request and response structs with `Pack` and `Unpack` implementations.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `trivial_message!` macro for 4-byte stub messages, module declarations |
| `header.rs` | 64-byte SMB2 header (sync + async variants), `PROTOCOL_ID` (`0xFE 'S' 'M' 'B'`) |
| `negotiate.rs` | Negotiate contexts (preauth integrity, encryption, signing, compression) |
| `create.rs` | CREATE request/response with create contexts |
| `transform.rs` | `TransformHeader` (encryption, protocol ID `0xFD`), `CompressionTransformHeader` (`0xFC`) |

19 command modules total: negotiate, session_setup, logoff, tree_connect, tree_disconnect, create, close, flush, read, write, lock, ioctl, query_directory, change_notify, query_info, set_info, echo, cancel, oplock_break.

## Patterns

- **Pack/Unpack**: All structs implement `pack(&self, &mut WriteCursor)` and `unpack(&mut ReadCursor) -> Result<Self>`. Hand-rolled, no proc macros.
- **Offset calculation**: All offsets in SMB2 are relative to the start of the SMB2 header (not the body, not the transport frame). When packing variable-length fields, compute `header_size + fixed_body_size` as the base offset.
- **StructureSize validation**: `Unpack` implementations read `StructureSize` first and return an error if it doesn't match the expected value.
- **`trivial_message!` macro**: Generates Pack/Unpack for 4-byte stub messages (StructureSize=4 + Reserved=0). Used by echo, cancel, logoff, tree_disconnect.

## Compound messages

Built by `Connection::send_compound`. Each sub-request's header has a `NextCommand` field pointing to the next message (8-byte aligned). The last message has `NextCommand = 0`. Related operations use `FileId::SENTINEL` (`0xFFFFFFFF:0xFFFFFFFF`) so the server substitutes the handle from the first CREATE.

## Transform headers

- **Encryption** (`0xFD 'S' 'M' 'B'`): 52-byte `TransformHeader` wraps encrypted message(s). Contains nonce, auth tag (signature), original message size, session ID.
- **Compression** (`0xFC 'S' 'M' 'B'`): `CompressionTransformHeader` wraps LZ4-compressed messages. Contains original and compressed sizes, algorithm ID.

## Gotchas

- **TCP framing is big-endian**: The 4-byte transport header (1 zero byte + 3-byte length) uses big-endian byte order. Everything inside the SMB2 message is little-endian. This is the only big-endian value in the entire protocol.
- **StructureSize is "fixed"**: The spec says StructureSize is the size of the fixed-length portion of the struct. It does NOT include variable-length buffers. It's validated on unpack.
- **`#![allow(missing_docs)]`**: This module opts out of doc requirements because wire format field names are self-documenting from the spec.
