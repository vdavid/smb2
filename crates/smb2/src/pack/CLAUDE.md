# Pack -- binary serialization primitives

Cursor-based binary reader/writer for SMB2 wire format. Hand-rolled, no proc macros.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `ReadCursor`, `WriteCursor`, `Pack`/`Unpack` traits, primitive read/write methods |
| `guid.rs` | GUID pack/unpack with mixed-endian layout |
| `filetime.rs` | Windows FILETIME (100ns ticks since 1601-01-01) to/from `SystemTime` |

## Core types

- **`ReadCursor<'a>`**: Reads from `&[u8]` with position tracking. Returns `Error` on buffer overrun (no panics). All reads are little-endian.
- **`WriteCursor`**: Writes into a growable `Vec<u8>`. Supports backpatching (`set_u16_le_at`, `set_u32_le_at`) for length fields written before their values are known. `align_to(n)` pads with zeros to n-byte boundary.
- **`Pack` trait**: `fn pack(&self, cursor: &mut WriteCursor)` -- serialize to binary.
- **`Unpack` trait**: `fn unpack(cursor: &mut ReadCursor) -> Result<Self>` -- deserialize from binary.

## GUID mixed-endian layout

Windows GUIDs have a mixed-endian wire format:
- `data1` (u32): little-endian
- `data2` (u16): little-endian
- `data3` (u16): little-endian
- `data4` ([u8; 8]): raw bytes (no endian conversion)

This matches the COM/DCOM convention. Not the same as RFC 4122 UUID byte order.

## FileTime conversion

Windows FILETIME: 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
Unix epoch: 1970-01-01 00:00:00 UTC.
Offset: 11,644,473,600 seconds (116,444,736,000,000,000 ticks).

## Key decisions

- **Hand-rolled instead of proc macros**: Full control over wire format details (offsets, alignment, backpatching). Easier to debug. No build-time dependency.
- **`MAX_UNPACK_BUFFER` (16 MB)**: `read_bytes_bounded` refuses allocations larger than 16 MB. Prevents OOM from malicious packets claiming huge lengths.

## Gotchas

- **Everything is little-endian**: Except TCP framing (see transport module). ReadCursor/WriteCursor only do LE.
- **UTF-16LE byte length must be even**: `read_utf16_le` returns an error on odd byte counts.
- **Backpatching requires placeholder**: Write a zero first, then `set_u32_le_at` to overwrite once the real value is known. Common pattern for length-prefixed fields.
