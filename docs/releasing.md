# Releasing to crates.io

Publishing is manual — there's no CI automation for it.

## Steps

1. **Bump version** in `Cargo.toml`
2. **Update `CHANGELOG.md`** — set the new version and date
3. **Run `just check-all`** (formatting, clippy, tests, docs, MSRV, audit, license). Fix everything — the release commit
   must produce zero warnings, zero formatting diffs, zero doc-link issues. Re-run until fully clean.
4. **Commit and tag**:
   ```bash
   git commit -m "Prepare vX.Y.Z for release"
   git tag vX.Y.Z
   ```
5. DISABLED FOR NOW BECAUSE NO CARGO PACKAGE - **Dry run** to catch packaging issues:
   ```bash
   cargo publish --dry-run
   ```
6. DISABLED FOR NOW BECAUSE NO CARGO PACKAGE - **Publish**:
   ```bash
   cargo publish
   ```
7. **Push** the commit and tag:
   ```bash
   git push && git push --tags
   ```

## Prerequisites

- A crates.io API token configured via `cargo login`
- The `exclude` list in `Cargo.toml` keeps the published package small (strips `.github/`, `docs/`, `justfile`, etc.)

## Previous releases

See [CHANGELOG.md](../CHANGELOG.md) for the full release history. Git tags (`v0.1.0`, `v0.2.0`, etc.) mark each release
commit.
