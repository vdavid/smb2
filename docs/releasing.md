# Releasing to crates.io

This repo is a Cargo workspace with two published crates:

- `smb2` (library, `crates/smb2/`)
- `smb2-cli` (CLI binary, `crates/smb2-cli/`; the binary it installs is named `smb2`)

Publishing is manual — no CI automation.

## Prerequisites

- A crates.io API token configured via `cargo login`
- `cargo-audit` and `cargo-deny` installed (`just install-tools` if you haven't)
- Docker running locally (the Docker integration suites are part of the pre-release gate)
- Optional: a NAS + Pi reachable via the credentials in `.env` for `just check-live` against real hardware

## Versioning

- The **library** version is the API contract downstream consumers track, and it's also what the CLI's
  `smb2 = { version = "X.Y.Z", path = "../smb2" }` dep names. Bump it with normal SemVer rules.
- The **CLI** version moves independently. A CLI-only fix bumps only the CLI.
- When you bump the library, bump the CLI's `smb2 = "X.Y.Z"` in the same commit. Usually you release both together.

## What ships

Each package's root is its own crate directory, so the shared files at the repo root — `docs/`, `benchmarks/`,
`justfile`, the lint configs, `CHANGELOG.md`, `CONTRIBUTING.md`, `LICENSE-*`, `.github/` — are outside both packages
and never ship. The library's `exclude` only has to strip `tests/`, which is dev-only; `fuzz/` is auto-excluded by
Cargo as a nested package. Fixtures the published crate embeds — the `testing` feature's consumer Docker files and the
ccache test vectors — live under `src/` (`src/testing/fixtures/`, `src/auth/kerberos/fixtures/`), so excluding
`tests/` wholesale ships nothing the crate needs. Re-check the `exclude` lists if you add a directory inside a crate
that shouldn't ship, or an `include_str!`/`include_bytes!` that reaches outside `src/`.

## Steps

1. **Bump version** in `crates/smb2/Cargo.toml` (and/or `crates/smb2-cli/Cargo.toml`). Follow
   [SemVer](https://semver.org/): pre-1.0, treat **minor** as breaking.
   - Adding a variant to a non-`#[non_exhaustive]` enum, removing or renaming a public item, or tightening a trait bound
     is breaking. When unsure, search for the symbol in `apps/desktop/src-tauri/` of the cmdr repo (the only known
     consumer today) — if a `_ =>` fallback handles it, bump minor; if not, bump minor regardless and call it out
     in the changelog.
   - When the **minor** changes, also bump the `smb2 = "X.Y"` install snippet in `crates/smb2/README.md` (it pins
     major.minor, so patch releases don't touch it). Stale here is what shipped `smb2 = "0.2"` long after the crate
     reached 0.11.
   - Bump the CLI's `smb2 = { version = "X.Y.Z", path = "../smb2" }` to match. A stale number there fails
     `cargo publish` (crates.io has no such version yet) rather than shipping a CLI built against a library nobody
     can install.
2. **Update `CHANGELOG.md`** — replace `[Unreleased]` with the new version + ISO date. Keep the keep-a-changelog
   sections (`Added`, `Changed`, `Fixed`, `Notes`). Lead with **Breaking** entries when present.
3. **Update `crates/smb2/fuzz/Cargo.lock`** so the fuzz crate sees the new version:
   ```bash
   (cd crates/smb2/fuzz && cargo update -p smb2)
   ```
   Commit it alongside `Cargo.lock`.
4. **Run the full check suite**. Every gate must be green — there's no "we'll fix it in a patch" once the version
   ships.
   ```bash
   just check-all          # fmt, clippy, unit tests, doc, MSRV, audit, deny
   just test-docker        # Docker SMB integration suite (~30 s)
   just test-consumer      # consumer-facing harness suite (~30 s)
   just check-live         # real-hardware integration tests (NAS + Pi, ~6 s) — if your .env is set up
   ```
5. **Commit and tag**. Use the `Release X.Y.Z — <one-line summary>` title style established by previous releases.
   Tag the workspace release with the **library** version, since that's the contract consumers track; a CLI-only
   release tags `smb2-cli-vA.B.C` instead.
   ```bash
   git commit -m "Release vX.Y.Z — <summary>"
   git tag vX.Y.Z
   ```
   Commit *before* the dry run: `cargo publish --dry-run` refuses a dirty tree, and the point of the dry run is to
   verify exactly the tree you're about to publish. If it turns up a problem, amend the release commit and re-run.
6. **Dry-run the package** to catch packaging issues without uploading:
   ```bash
   just release-dry
   ```
   Read the file lists it prints. If anything sensitive or unexpected slipped in, fix the crate's `exclude` list
   and re-run.

   This fully dry-runs the library, then only prints the CLI's would-be file list. It can't fully dry-run the CLI
   yet: `cargo publish --dry-run -p smb2-cli` resolves `smb2 = "X.Y.Z"` against crates.io, and the new library
   version is still local. The CLI gets its full dry run in step 7, once the library is up.
7. **Publish in order** — library first, CLI second, since the CLI's dep resolves against the published library:
   ```bash
   cargo publish -p smb2
   # Wait ~30 seconds for the crates.io index to update, then:
   just release-dry-cli
   cargo publish -p smb2-cli
   ```
   This is **irreversible** — crates.io versions are immutable. If something is wrong, the recourse is `cargo yank`
   plus a follow-up patch release, not a re-upload. See *Yanking a bad release* below.
8. **Push** the commit and tag:
   ```bash
   git push && git push --tags
   ```
9. **Verify** the published artifacts:
   - https://crates.io/crates/smb2 and https://crates.io/crates/smb2-cli — confirm the version, description, and
     links render correctly
   - https://docs.rs/smb2/X.Y.Z — confirm the build succeeded and the doc example for `ErrorKind` renders
   - Install it in a throwaway project: `cargo new /tmp/smb2-verify && cd /tmp/smb2-verify && cargo add smb2@X.Y.Z &&
     cargo build`. A green build here is the strongest signal that the published package is intact.

## Troubleshooting

### Pre-release tests failed, need to fix and re-tag

If you've tagged but not yet published, the tag is just a local marker — no external state to clean up.

```bash
git tag -d vX.Y.Z              # delete local tag
# ... fix and commit the fix on top of the release commit, or amend ...
git tag vX.Y.Z                 # recreate
```

If you've already pushed the tag but not published:

```bash
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z   # delete remote tag
# ... fix, commit, recreate tag, push ...
```

Don't `--amend` once the tag is on `origin` — make a new commit and re-tag instead, so the tagged commit is the one
that actually shipped (no rebase confusion later).

### `cargo publish` rejected the upload

- **"crate version X.Y.Z is already uploaded"**: you've already published. Bump to X.Y.Z+1 and try again — crates.io
  versions are immutable, you can never re-upload the same one.
- **"failed to verify package tarball"**: usually a transient network hiccup. Retry. If it persists, run
  `cargo publish --dry-run` and inspect; sometimes a missing license file or out-of-tree symlink is the cause.
- **Rate-limited (429)**: crates.io throttles new-version publishes per crate. Wait 10–15 minutes and retry.

### Yanking a bad release

If the release built and published but is broken (panic, severe bug, accidentally-shipped private API):

```bash
cargo yank --version X.Y.Z
```

Yanking does **not** delete the version — existing `Cargo.lock`s still resolve it — but it stops new resolutions from
picking it up. Cut a patch release (`X.Y.Z+1`) with the fix as soon as possible. To un-yank later if you mistakenly
yanked a good release: `cargo yank --version X.Y.Z --undo`.

### Publishing from a dirty tree

`cargo publish` will refuse if the tree has uncommitted changes (the `--allow-dirty` override exists, **don't use
it** — the published artifact must match a committed, tagged state so future-you can `git checkout vX.Y.Z` and
reproduce the release exactly). Commit (or stash *deliberately*) before retrying.

### Docs.rs build failed

Docs.rs builds on a clean Linux container with the latest stable Rust. If the build failed, the most common causes:

- A `cfg(target_os = "macos")` block that breaks compilation on Linux without `#[cfg(...)]` guards on its callers
- A doctest that depends on a feature flag not enabled in the default `[package.metadata.docs.rs]` config
- A doc link to an item that's been renamed since publication

Click "Build log" on the docs.rs failed-build page, fix the issue, cut a patch release.

### `crates/smb2/fuzz/Cargo.lock` left at the old version after release

Mostly cosmetic, but it's noise on every subsequent fuzz run. The fix is the same as step 3:
`(cd crates/smb2/fuzz && cargo update -p smb2) && git commit -am "Fuzz: bump smb2 path dep to X.Y.Z"`. Worth doing as
a follow-up commit rather than re-tagging.

## CLI-only patch flow

If only the CLI changes:

1. Bump `crates/smb2-cli/Cargo.toml`'s own `version` only.
2. `just check-all` (this refreshes `Cargo.lock`).
3. Commit and tag as `smb2-cli-vA.B.C`. Commit before the dry run, which refuses a dirty tree.
4. `cargo publish --dry-run -p smb2-cli`. The library version it depends on is already published, so the full dry run
   works here.
5. `cargo publish -p smb2-cli`.

## Previous releases

See [CHANGELOG.md](../CHANGELOG.md) for the full history. Git tags (`v0.7.0`, `v0.7.1`, …) mark each library release
commit. CLI-only releases use the `smb2-cli-v*` prefix.
