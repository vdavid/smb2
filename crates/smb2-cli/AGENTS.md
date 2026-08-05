# smb2-cli

A command-line SMB2/3 client built on the [smb2](https://github.com/vdavid/smb2) crate, pulled from crates.io. The binary is named `smb2`; the package is `smb2-cli`.

Don't turn `smb2` into a path or git dependency: a path dep breaks this build whenever David bumps the version in `../smb2`, and a git dep tracking the default branch breaks even more often. To try an unreleased change, use a temporary `[patch.crates-io]` entry and take it out before committing.

## Layout

- `src/main.rs`: clap definitions and dispatch. Global flags (`--json`, `--dry-run`, `-j/--concurrency`, and everything in `AuthArgs`) live on the top-level `Cli`.
- `src/target.rs`: parses `//host/share/path`, `smb://…`, and `\\host\share\path` into a `Target`. `Target::resolve` joins a relative path onto a base, which is how batch inputs stay short.
- `src/auth.rs`: `AuthArgs` and credential resolution, in order: `--guest`, `--password-command`, `--password`/`SMB2_PASS`, terminal prompt.
- `src/batch.rs`: turns command-line targets or a `--from-file` list into one share plus a list of paths. Everything in a batch must be on the same host and share.
- `src/pool.rs`: the concurrency engine. `Job` is the unit of work, `Outcome` the result.
- `src/output.rs`: timestamp and byte formatting. Dates are ISO in UTC, computed with civil-from-days so we don't pull in a date crate.
- `src/commands/`: `meta` (read-only), `mutate` (changes the share), `transfer` (bytes in and out).

## How concurrency works

The smb2 crate's `stat_files`, `rename_files`, and `delete_files` are named like batch APIs, but each issues one round trip per item on a single connection: they don't overlap server work. So `pool::run` opens N independent connections instead, deals jobs to them round-robin by index, and stitches results back into the caller's order. Each worker owns its client and tree, so there are no locks.

This is why `-j` matters so much on high-latency links, and why raising it past the server's worker count stops helping.

Gotcha: `mkdir -p` forces concurrency to 1, since a parent has to exist before its child.

## Conventions

- Batch commands never abort the whole run on one bad path. They collect failures, report up to 50 on stderr, and exit non-zero.
- `--dry-run` prints the operations and makes no connection at all for mutating commands.
- Every command supports `--json`. Human output is for people, JSON is the contract; if you change a JSON key, that's a breaking change.

## Testing

`cargo test` covers parsing and formatting with no network.

End-to-end runs use the Samba fixtures in the smb2 repo:

```sh
cd ../smb2/tests/docker/internal && docker compose up -d --build smb-auth
SMB2_USER=testuser SMB2_PASS=testpass cargo run -- ls -l //127.0.0.1:10446/private
```

`smb-auth` is `testuser`/`testpass` on port 10446, share `private`. The other fixtures in that directory cover signing, encryption, guest access, DFS, and flaky servers.
