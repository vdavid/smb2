# smb2-cli

A command-line SMB2/3 client built on the [smb2](https://github.com/vdavid/smb2) crate, pulled from crates.io. The binary is named `smb2`; the package is `smb2-cli`.

Don't turn `smb2` into a path or git dependency: a path dep breaks this build whenever David bumps the version in `../smb2`, and a git dep tracking the default branch breaks even more often. To try an unreleased change, use a temporary `[patch.crates-io]` entry and take it out before committing.

## Layout

- `src/main.rs`: clap definitions and dispatch. Global flags (`--json`, `--dry-run`, and everything in `AuthArgs`) live on the top-level `Cli`. `-j/--concurrency` deliberately isn't global: it's a flattened `pool::Concurrency` on the five commands that reach `pool::run`, since every other command opens exactly one connection and would be advertising something it can't do.
- `src/target.rs`: parses `//host/share/path`, `smb://…`, and `\\host\share\path` into a `Target`. `Target::resolve` joins a relative path onto a base, which is how batch inputs stay short.
- `src/auth.rs`: `AuthArgs` and credential resolution, in order: `--guest`, `--password-command`, `--password`/`SMB2_PASS`, terminal prompt.
- `src/batch.rs`: turns command-line targets or a `--from-file` list into one share plus a list of paths. Everything in a batch must be on the same host and share.
- `src/pool.rs`: the concurrency engine. `Job` is the unit of work, `Outcome` the result, and `Concurrency` is the `-j` flag the pooling commands flatten in.
- `src/remote.rs`: what the server has at a path (`RemoteKind`, and the stat behind it). `put` and `mkdir` both have to tell a file from a directory before they act, and only a clean "it isn't there" counts as missing: an `ACCESS_DENIED` read as "nothing there" is how an upload clobbers a directory.
- `src/output.rs`: timestamp and byte formatting. Dates are ISO in UTC, computed with civil-from-days so we don't pull in a date crate.
- `src/commands/`: `meta` (read-only), `mutate` (changes the share), `transfer` (bytes in and out). `transfer` keeps its destination rules in two pure functions, `upload_path` and `download_path`, so `cargo test` can cover them without a server.

## How concurrency works

The smb2 crate's `stat_files`, `rename_files`, and `delete_files` are named like batch APIs, but each issues one round trip per item on a single connection: they don't overlap server work. So `pool::run` opens N independent connections instead, deals jobs to them round-robin by index, and stitches results back into the caller's order. Each worker owns its client and tree, so there are no locks.

This is why `-j` matters so much on high-latency links, and why raising it past the server's worker count stops helping.

`-j` is only offered on the commands that come through here: `stat`, `mkdir`, `rm`, `rmdir`, and `mv`. If you add a command that pools, flatten `pool::Concurrency` into it; if you make one stop pooling, take the flag off.

Gotcha: `mkdir -p` forces concurrency to 1, since a parent has to exist before its child. That's about ordering, not about the flag: `-j` is still accepted on `mkdir` and still spends connections without `-p`.

## Conventions

- Batch commands never abort the whole run on one bad path. They collect failures, report up to 50 on stderr, and exit non-zero.
- `--dry-run` prints the operations and makes no connection at all. It covers everything that writes: `mkdir`, `rm`, `rmdir`, `mv`, `put`, and `get` (which writes locally). Read-only commands ignore it. `tests/dry_run.rs` holds every one of them to that by aiming at a port nothing listens on, so a command that connects fails the test.
- `put` picks its destination the way `cp` does: a target written with a trailing separator, or one the server says is already a directory, takes the source's file name inside it; anything else is the full destination path. It stats the target first and refuses to write a file over a directory, since that's how a folder disappears. A dry run can't stat, so it goes on the trailing separator alone.
- `mkdir` asks what holds a name only after the server reports `OBJECT_NAME_COLLISION`, so a batch that creates fresh directories pays nothing extra. `-p` treats an existing *directory* as done and an existing *file* as a failure, the way GNU `mkdir -p` does; reporting success over a file is what once hid a wrong path until a much later `ls` tripped over it. Plain `mkdir` fails on either.
- Every command supports `--json`. Human output is for people, JSON is the contract; if you change a JSON key, that's a breaking change.

## Testing

`cargo test` covers parsing, formatting, the transfer destination rules, the `mkdir` collision rules, and which commands accept `-j`, all with no network. `tests/dry_run.rs` runs the built binary against `//127.0.0.1:1/…`, where connecting is refused instantly, which is what makes "`--dry-run` doesn't connect" testable.

End-to-end runs use the Samba fixtures in the smb2 repo:

```sh
cd ../smb2/tests/docker/internal && docker compose up -d --build smb-auth
SMB2_USER=testuser SMB2_PASS=testpass cargo run -- ls -l //127.0.0.1:10446/private
```

`smb-auth` is `testuser`/`testpass` on port 10446, share `private`. The other fixtures in that directory cover signing, encryption, guest access, DFS, and flaky servers.
