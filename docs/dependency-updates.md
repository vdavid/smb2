# Dependency updates and the MSRV

Renovate (the Mend-hosted GitHub app) opens every dependency PR, and nobody runs `cargo update` by hand. This doc covers
the MSRV policy, how it and Renovate fit together, and what an MSRV raise touches. Read it before merging or closing a
Renovate PR, or before touching `rust-version`.

## MSRV policy

- **Promise**: we support the Rust releases from the last 12 months. `rust-version` in the root `Cargo.toml` is the
  oldest stable released within that window (or older, if nothing needs newer).
- **Raising it** is a minor version bump (0.x: the `x`), with a **Breaking** changelog line. Raise it when a dependency
  or a language feature needs it; don't chase the window for its own sake.
- **Held at 1.90 for OSS Verify**: its proof builds use rustc 1.90 (`nightly-2025-07-16`), and a `rust-version` above
  that needs a patch on their side. So a raise also waits for OSS Verify's toolchain, unless a dependency forces it
  (`crates/smb2/fuzz/CLAUDE.md`).
- **Scope**: what consumers compile, so the library (every feature, smol-only too) and the CLI binary. Tests,
  examples, and dev-dependencies run on stable only.
- ❌ **Never cap a dependency in `Cargo.toml` for the MSRV** (like `aes = ">=0.9.1, <0.9.3"`). A cap forces every
  consumer's graph onto the old version, even consumers on a new Rust (it held Cmdr on old `sha2`). Consumers on the
  MSRV get a buildable version from Cargo's MSRV-aware resolver instead (`resolver = "3"`, the edition 2024 default,
  or `resolver.incompatible-rust-versions = "fallback"`).

## How CI checks the MSRV

The `msrv` job (and `just msrv`) runs `cargo update` with `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback` on the
MSRV toolchain before `cargo check`, so it builds the graph a consumer on the MSRV would resolve, never the committed
`Cargo.lock`. `just msrv` puts the committed `Cargo.lock` back afterward and builds into `target/msrv`.

So the committed `Cargo.lock` is free to hold versions that need a newer Rust: it serves our stable-only tests and the
CLI binary we ship. A red `msrv` job means a consumer on the MSRV really can't build us: a dependency raised its MSRV
in a version our `Cargo.toml` floor requires, or it published no version our MSRV can build. Raise our MSRV, or (rarely)
lower our floor.

## Why Renovate can't keep `Cargo.lock` MSRV-compatible

Verified on 2026-10-27 against Renovate `main` (`lib/modules/manager/cargo/artifacts.ts`) and by running Renovate
44.181.0 locally (`--platform=local --dry-run=lookup`) with cargo 1.99.1:

- **In-range updates force the version.** With `rangeStrategy: "update-lockfile"` (cargo's default under `auto`),
  Renovate runs `cargo update --package <crate>@<locked> --precise <new>`, then `cargo update --workspace`. `--precise`
  ignores the MSRV-aware resolver: in a `rust-version = "1.87"` crate it took `sha2` 0.11.0 → 0.11.1 ("requires Rust
  1.88"), and the `--workspace` pass kept it. That's how smb2 PR #25 and mtp-rs PR #48 went red on the MSRV jobs
  while touching only `Cargo.lock`.
- **`constraintsFiltering: "strict"` with `constraints.rust` doesn't fix it.** The `crate` datasource does attach each
  release's `rust_version`, but the comparison is unreliable: `"1.87"` let `serial_test` 4.0.1 (`rust_version`
  "1.93.1") through, a range like `"<=1.88.0"` filtered out every release (compatible ones too), and
  `semver-coerced` constraint versioning let 4.0.1 through again. Renovate doesn't read `rust-version` from
  `Cargo.toml` either (renovatebot/renovate#26314, open).
- **`lockFileMaintenance` would respect the MSRV** (it runs a plain `cargo update`), but Renovate can't apply
  `minimumReleaseAge` to it, so it would drop our three-day window. Not enabled, except for the fuzz harness below.

Hence the split above: Renovate keeps `Cargo.lock` current with `--precise` (and the three-day window), and the MSRV
job checks the consumer's view independently.

## How Renovate is set up

- **Config**: `renovate.json`. Every package rule has a `description` with its reason, so read those first.
- **Release age**: every update waits three days after release (`minimumReleaseAge`).
- **Cargo range strategy**: `update-lockfile`, pinned by a rule. In-range updates move only `Cargo.lock`; a `Cargo.toml`
  floor is a promise to consumers and moves only on purpose (a fix we need, a major bump).
- **Non-major updates**: one grouped PR, weekly before 6am Monday (Europe/Budapest), automerged once CI is green.
- **Major updates**: one grouped PR, monthly on the 1st, never automerged.
- **Security fixes**: immediate PRs, automerged.
- **Fuzz harness lockfile**: `crates/smb2/fuzz/` is its own workspace, so the grouped PR never refreshes its
  `Cargo.lock`, and its indirect deps drift (a `cmov` advisory on 2026-10-27). A `lockFileMaintenance` PR (a plain
  `cargo update` there) opens weekly before 6am Monday and never automerges, for two reasons: it skips the three-day
  window (see above), and PR CI never builds the harness (`fuzz.yml` runs only on its Monday 04:15 UTC schedule).
  Cmdr's weekly `/weekly-upgrades` pass merges it once every version in it is at least three days old and the harness
  builds (`cargo +nightly fuzz build` in `crates/smb2/`). A package rule turns it off for every other `Cargo.toml`.
- **Ubuntu runner**: held on GA images (`allowedVersions` below 26 while 26.04 is a preview), since the Homebrew publish
  job only runs at release time. The rule's `description` says when to lift it.
- **Not managed**: the Rust toolchain in workflows (moves with the MSRV), `dist`'s generated release workflow, and
  `benchmarks/smb/**`. Their rules say why.

## Raising the MSRV

Touch every one of these in the same commit:

- `Cargo.toml`: workspace `rust-version`.
- `.github/workflows/ci.yml`: the `msrv` job's name and `toolchain`.
- `justfile`: the `msrv` recipe (comments, the `rustup run` probe, every `cargo +1.xx.0`) and the header lines.
- `README.md` and `crates/smb2/README.md`: the MSRV badge and the MSRV paragraph.
- `CONTRIBUTING.md`: the MSRV section and the "Submitting changes" step.
- `.github/workflows/fuzz.yml` and `crates/smb2/fuzz/CLAUDE.md`: the OSS Verify notes (a raise past its toolchain
  needs `--ignore-rust-version` back on the `oss-verify-toolchain` build).
- `CHANGELOG.md`: a **Breaking** entry ("The MSRV is now Rust B (was A)"), and a minor version bump at release.
