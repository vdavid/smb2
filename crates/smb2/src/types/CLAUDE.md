# Types -- protocol newtypes and enums

Zero-cost newtype wrappers for protocol IDs, command/dialect enums, and bitflag types.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `SessionId`, `TreeId`, `FileId`, `MessageId`, `CreditCharge`, `Command`, `Dialect`, `OplockLevel` |
| `flags.rs` | Bitflag types: `HeaderFlags`, `Capabilities`, `SecurityMode`, `FileAccessMask`, etc. |
| `status.rs` | `NtStatus` enum (from MS-ERREF) with severity/facility helpers |

## Newtype IDs

All protocol IDs are newtypes over their raw integer:
- `SessionId(u64)` -- has `NONE` sentinel (0)
- `MessageId(u64)` -- has `UNSOLICITED` sentinel (0xFFFFFFFFFFFFFFFF) for oplock breaks
- `TreeId(u32)`
- `CreditCharge(u16)`
- `FileId { persistent: u64, volatile: u64 }` -- has `SENTINEL` (all-F's) for compound related requests

All implement `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `Display`.

## Command and Dialect enums

- `Command`: 19 variants (Negotiate through OplockBreak), `repr(u16)`, uses `num_enum` for `TryFrom<u16>`/`Into<u16>`
- `Dialect`: 5 variants (2.0.2 through 3.1.1), `repr(u16)`, ordered (`PartialOrd`/`Ord`). `Dialect::ALL` is a sorted slice.

## Key decisions

- **Newtypes over raw u32/u64**: Prevents accidentally passing a TreeId where a SessionId is expected. Zero runtime cost.
- **`num_enum` for command/dialect**: Avoids manual match arms for TryFrom. Compile-time checked exhaustive conversions.

## Gotchas

- **`MORE_PROCESSING_REQUIRED` has error severity bits but isn't an error**: `NtStatus` severity is encoded in bits 30-31. `MORE_PROCESSING_REQUIRED` (0xC0000016) has severity=3 (error), but it's a normal part of the session setup flow. Use `is_more_processing_required()` instead of checking `is_error()`.
- **`STATUS_BUFFER_OVERFLOW` is a warning, not an error**: Returns valid partial data. Don't discard the response body.
- **FileId::SENTINEL vs FileId::default()**: SENTINEL is all-F's (used in compound requests). Default is all-zeros (unused). Don't mix them up.
