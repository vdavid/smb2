# fuzz: cargo-fuzz targets over the parse paths

One `[[bin]]` per entry point in `src/fuzzing.rs` (the `fuzzing` feature). Each takes server-chosen bytes and must
return or reject, never panic. Two also assert a property: `fuzz_name_round_trip` (the private-use-area name mapping
round-trips and leaves nothing SMB2 rejects) and `fuzz_error_context_walk` (a context count the buffer can't back never
reports a redirect).

## Files

- `fuzz_targets/*.rs`: six-line wrappers that call `smb2::fuzzing::<name>`
- `corpus/<target>/seed_*.bin`: committed seeds from `tests/fuzz_seeds.rs` (`just fuzz-seeds`); everything else a run
  adds is gitignored
- `Cargo.lock`: its own workspace; see `docs/dependency-updates.md` for how it gets refreshed

## Running

- `just fuzz <target> [seconds]` locally.
- `.github/workflows/fuzz.yml` runs every `[[bin]]` for five minutes each on Mondays, reading the list from
  `Cargo.toml`, so a new target needs no workflow edit. It also builds every target on Rust nightly-2025-07-16.

## Rules for a target (OSS Verify)

These targets are written to qualify for [OSS Verify](https://theorem.dev/oss-verify/), which proves that a target
can't crash on any input. Its model is one Linux process whose only data is the input, so a target must:

- start no thread and spawn no async task, read no clock, use no network or environment, and open no file;
- take its "random" choices from the input bytes;
- bound every loop and count that comes from the input (a server-chosen length walks at most the buffer it's in);
- express a property as `assert!` (Rust keeps it in release builds, and the panic aborts), never `debug_assert!`;
- not install a panic hook or catch panics.

OSS Verify builds with rustc 1.90 (nightly-2025-07-16), which is exactly our MSRV, so its build needs no
`rust-version` patch. ❌ Raising the MSRV past 1.90 breaks the proof builds until OSS Verify moves its toolchain; the
weekly `oss-verify-toolchain` job (no `--ignore-rust-version`) catches it.
