# Releasing to crates.io

How to release a new version of smb2. Publishing is manual — no CI automation.

## Prerequisites

- A crates.io API token configured via `cargo login`
- `cargo-audit` and `cargo-deny` installed (`just install-tools` if you haven't)
- Docker running locally (the Docker integration suites are part of the pre-release gate)
- Optional: a NAS + Pi reachable via the credentials in `.env` for `just check-live` against real hardware

The `exclude` list in `Cargo.toml` keeps the published package small — it strips `.github/`, `AGENTS.md`, `docs/`,
`tests/`, the `justfile`, and the lint configs (`fuzz/` and `benchmarks/` are auto-excluded by Cargo as nested
packages). Fixtures the published crate embeds — the `testing` feature's consumer Docker files and the ccache test
vectors — live under `src/` (`src/testing/fixtures/`, `src/auth/kerberos/fixtures/`), so excluding `tests/` wholesale
ships nothing the crate needs. Re-check the list if you've added a new top-level dir that shouldn't ship, or a new
`include_str!`/`include_bytes!` that reaches outside `src/`.

## Steps

1. **Bump version** in `Cargo.toml`. Follow [SemVer](https://semver.org/): pre-1.0, treat **minor** as breaking.
   - Adding a variant to a non-`#[non_exhaustive]` enum, removing or renaming a public item, or tightening a trait bound
     is breaking. When unsure, search for the symbol in `apps/desktop/src-tauri/` of the cmdr repo (the only known
     consumer today) — if a `_ =>` fallback handles it, bump minor; if not, bump minor regardless and call it out
     in the changelog.
2. **Update `CHANGELOG.md`** — replace `[Unreleased]` with the new version + ISO date. Keep the keep-a-changelog
   sections (`Added`, `Changed`, `Fixed`, `Notes`). Lead with **Breaking** entries when present.
3. **Update `fuzz/Cargo.lock`** so the fuzz crate sees the new version:
   ```bash
   (cd fuzz && cargo update -p smb2)
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
5. **Dry-run the package** to catch packaging issues without uploading:
   ```bash
   cargo publish --dry-run
   ```
   Read the file list it prints. If anything sensitive or unexpected slipped in, fix `Cargo.toml`'s `exclude` list
   and re-run.
6. **Commit and tag**. Use the `Release X.Y.Z — <one-line summary>` title style established by previous releases.
   ```bash
   git commit -m "Release vX.Y.Z — <summary>"
   git tag vX.Y.Z
   ```
7. **Publish to crates.io**:
   ```bash
   cargo publish
   ```
   This is **irreversible** — crates.io versions are immutable. If something is wrong, the recourse is `cargo yank`
   plus a follow-up patch release, not a re-upload. See *Yanking a bad release* below.
8. **Push** the commit and tag:
   ```bash
   git push && git push --tags
   ```
9. **Verify** the published artifact:
   - https://crates.io/crates/smb2 — confirm the version, description, and links render correctly
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

### `fuzz/Cargo.lock` left at the old version after release

Mostly cosmetic, but it's noise on every subsequent fuzz run. The fix is the same as step 3:
`(cd fuzz && cargo update -p smb2) && git commit -am "Fuzz: bump smb2 path dep to X.Y.Z"`. Worth doing as a follow-up
commit rather than re-tagging.

## Previous releases

See [CHANGELOG.md](../CHANGELOG.md) for the full history. Git tags (`v0.7.0`, `v0.7.1`, …) mark each release commit.
