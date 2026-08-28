# smb2-cli

The command-line SMB2/3 client. The package is `smb2-cli`; the binary it installs is named `smb2`.

## How it depends on the library

`smb2` is a workspace sibling, declared as `smb2 = { version = "0.20.0", path = "../smb2" }`:

- The **path** is what every local build, test, and `cargo run` resolves, so a library change and the CLI change that
  goes with it land in the same commit and are checked together.
- The **version** is what `cargo publish` writes into the published manifest, after stripping the path. crates.io users
  get a plain `smb2 = "0.20.0"`.

Both parts are required. A bare path dep can't be published at all, and a version that drifts from the library's own
`version` in `crates/smb2/Cargo.toml` makes `cargo publish` fail (crates.io has no such release yet) instead of shipping
a CLI built against a library nobody can install. So: when you bump the library, bump this number in the same commit.

Reaching for `[patch.crates-io]` isn't needed here anymore; unreleased library changes are already what the CLI builds
against.

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

The library's `stat_files`, `rename_files`, and `delete_files` are named like batch APIs, but each issues one round trip per item on a single connection: they don't overlap server work. So `pool::run` opens N independent connections instead, deals jobs to them round-robin by index, and stitches results back into the caller's order. Each worker owns its client and tree, so there are no locks.

This is why `-j` matters so much on high-latency links, and why raising it past the server's worker count stops helping.

`-j` is only offered on the commands that come through here: `stat`, `mkdir`, `rm`, `rmdir`, and `mv`. If you add a command that pools, flatten `pool::Concurrency` into it; if you make one stop pooling, take the flag off.

Gotcha: `mkdir -p` forces concurrency to 1, since a parent has to exist before its child. That's about ordering, not about the flag: `-j` is still accepted on `mkdir` and still spends connections without `-p`.

## Conventions

- Batch commands never abort the whole run on one bad path. They collect failures, report up to 50 on stderr, and exit non-zero.
- `--dry-run` prints the operations and makes no connection at all. It covers everything that writes: `mkdir`, `rm`, `rmdir`, `mv`, `put`, and `get` (which writes locally). Read-only commands ignore it. `tests/dry_run.rs` holds every one of them to that by aiming at a port nothing listens on, so a command that connects fails the test.
- `put` picks its destination the way `cp` does: a target written with a trailing separator, or one the server says is already a directory, takes the source's file name inside it; anything else is the full destination path. It stats the target first and refuses to write a file over a directory, since that's how a folder disappears. A dry run can't stat, so it goes on the trailing separator alone.
- `mkdir` asks what holds a name only after the server reports `OBJECT_NAME_COLLISION`, so a batch that creates fresh directories pays nothing extra. `-p` treats an existing *directory* as done and an existing *file* as a failure, the way GNU `mkdir -p` does; reporting success over a file is what once hid a wrong path until a much later `ls` tripped over it. Plain `mkdir` fails on either.
- Every command supports `--json`. Human output is for people, JSON is the contract; if you change a JSON key, that's a breaking change.

## How bytes move

Neither direction ever holds a whole file. That is a correctness matter as much as a memory one, because the
server's `MaxReadSize` (8 MB on a stock Samba) is a hard ceiling on what one READ can return.

- **`put`** (`transfer::upload`): a file that fits in one WRITE is read into memory and sent as a single compound
  CREATE+WRITE+FLUSH+CLOSE, which keeps a small upload at one round trip. Anything larger is pulled off disk a
  chunk at a time and fed to `write_file_streamed`, whose pipeline window is what the upload then costs. The
  callback reads with blocking `std::fs`, on purpose: it is called from inside the write pipeline's own task, so
  it stalls only itself.
- **`get` and `cat`** (`transfer::Download`): always a `FileReader` plus a sliding window of positioned reads,
  each chunk written to the sink as it lands. The window is `IN_FLIGHT_BYTES / MaxReadSize`, clamped to 2..32, so
  a server with a 64 KB cap gets the same 32-deep pipeline the library's own `read_file_pipelined` uses and one
  with an 8 MB cap gets two.
  - **Opening is a separate step from pumping, and `get` needs it that way.** Streaming means the destination is
    open while the bytes are still arriving, so a `get` that creates the destination first turns every failed
    download into a truncated local file -- including the case where the destination was a good earlier copy of
    the same file. `Download::open` proves the remote side works before anything local is touched, and the bytes
    then land on a `.smb2-part` sibling that is renamed into place only on success (sibling, so the rename is
    within one filesystem and therefore atomic). A failure removes the partial file and leaves the destination
    exactly as it was.
  - ❌ **Don't "optimize" this by trying the compound `read_file` first and falling back.** It looks free and
    isn't: the server answers that compound's READ with a full `MaxReadSize` of data *before* the client can see
    the file is too big, so every large download would pull 8 MB it throws away. The cost of not doing that is
    three round trips for a small download where the compound took one.
  - The library's `Tree::read_file` is `read_file_compound` with no size check, unlike `write_file`, which picks
    compound or pipelined by size. If `read_file` ever grows the same dispatch, this can go back to one round
    trip for small files and keep streaming for large ones.
- A `FileReader` must be closed explicitly. Dropping one only logs, and leaks the server-side handle until the
  session goes away.

## Testing

`cargo test -p smb2-cli` covers parsing, formatting, the transfer destination rules, the `mkdir` collision rules, and which commands accept `-j`, all with no network. `tests/dry_run.rs` runs the built binary against `//127.0.0.1:1/…`, where connecting is refused instantly, which is what makes "`--dry-run` doesn't connect" testable.

`tests/e2e.rs` is the other half: 28 tests that run the built binary against a live Samba fixture and check what
it left on the share, because a command that writes the wrong thing passes every test that never connects. Both
data-safety bugs this CLI has shipped were caught by hand for exactly that reason. Run it with `just test-cli-e2e`,
or by hand:

```sh
./crates/smb2/tests/docker/start.sh internal smb-auth
cargo test -p smb2-cli --test e2e -- --ignored
./crates/smb2/tests/docker/stop.sh
```

`smb-auth` is `testuser`/`testpass` on port 10446, share `private`. The other fixtures in `crates/smb2/tests/docker/internal/` cover signing, encryption, guest access, DFS, and flaky servers. `start.sh` takes service names after the profile, which is how the CLI suite brings up one container instead of 16.

Two things to know before adding a test there:

- **The suite opens exactly one SMB connection for the whole binary**, and its `server()` doc says why at length:
  concurrent connects from one process share a `ClientGuid` and trip a Samba bug that hangs one of them for 30 s.
  Use the `Fixture` helpers rather than reaching for a connection of your own. Same reason the batch tests pass
  `-j 2`. See `docs/notes/samba-client-guid-connection-pass.md`.
- **Each test owns `cli-e2e/<its own name>/`** and wipes it on entry, which is what lets the file run in parallel
  and makes a re-run independent of the last one. Setup and verification go through the library, so a CLI bug
  can't hide behind the CLI agreeing with itself.

The bulk-operation benchmark that produced the `-j` numbers lives at `benchmarks/cli-bulk-ops/`.
