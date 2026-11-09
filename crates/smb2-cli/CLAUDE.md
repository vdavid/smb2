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

- `src/main.rs`: clap definitions and dispatch. Global flags (`--json`, `--dry-run`, and everything in `AuthArgs`) live on the top-level `Cli`. `-j/--concurrency` deliberately isn't global: it's a flattened `pool::Concurrency` on the six commands that reach `pool::run`, since every other command opens exactly one connection and would be advertising something it can't do.
- `src/target.rs`: parses `//host/share/path`, `smb://…`, and `\\host\share\path` into a `Target`. `Target::resolve` joins a relative path onto a base, which is how batch inputs stay short.
- `src/auth.rs`: `AuthArgs` and credential resolution, in order: `--guest`, `--password-command`, `--password`/`SMB2_PASS`, terminal prompt. `--require-encryption` rides along on `Credentials`, and `Credentials::connect` is the one place a connection is opened, so every command honours it.
- `src/batch.rs`: turns command-line targets or a `--from-file` list into one share plus a list of paths. Everything in a batch must be on the same host and share.
- `src/pool.rs`: the concurrency engine. `Job` is the unit of work, `Outcome` the result, and `Concurrency` is the `-j` flag the pooling commands flatten in.
- `src/remote.rs`: what the server has at a path (`RemoteKind`, and the stat behind it). `put` and `mkdir` both have to tell a file from a directory before they act, and only a clean "it isn't there" counts as missing: an `ACCESS_DENIED` read as "nothing there" is how an upload clobbers a directory.
- `src/output.rs`: timestamp and byte formatting. Dates are ISO in UTC, computed with civil-from-days so we don't pull in a date crate.
- `src/commands/`: `meta` (read-only), `mutate` (changes the share), `transfer` (bytes in and out), `xattr` (`xattr` and `streams`). `transfer` keeps its destination rules in two pure functions, `upload_path` and `download_path`, so `cargo test` can cover them without a server.

## How concurrency works

The library's `stat_files`, `rename_files`, and `delete_files` are named like batch APIs, but each issues one round trip per item on a single connection: they don't overlap server work. So `pool::run` opens N independent connections instead, deals jobs to them round-robin by index, and stitches results back into the caller's order. Each worker owns its client and tree, so there are no locks.

This is why `-j` matters so much on high-latency links, and why raising it past the server's worker count stops helping.

`-j` is only offered on the commands that come through here: `stat`, `mkdir`, `rm`, `rmdir`, `mv`, and `xattr`. If you add a command that pools, flatten `pool::Concurrency` into it; if you make one stop pooling, take the flag off.

Gotcha: `mkdir -p` forces concurrency to 1, since a parent has to exist before its child. That's about ordering, not about the flag: `-j` is still accepted on `mkdir` and still spends connections without `-p`.

## Conventions

- Batch commands never abort the whole run on one bad path. They collect failures, report up to 50 on stderr, and exit non-zero.
- `--dry-run` prints the operations and makes no connection at all. It covers everything that writes: `mkdir`, `rm`, `rmdir`, `mv`, `put`, `get` (which writes locally), and `xattr -w` / `-d`. Read-only commands ignore it. `tests/dry_run.rs` holds every one of them to that by aiming at a port nothing listens on, so a command that connects fails the test.
- `put` picks its destination the way `cp` does: a target written with a trailing separator, or one the server says is already a directory, takes the source's file name inside it; anything else is the full destination path. It stats the target first and refuses to write a file over a directory, since that's how a folder disappears. A dry run can't stat, so it goes on the trailing separator alone.
- `mkdir` asks what holds a name only after the server reports `OBJECT_NAME_COLLISION`, so a batch that creates fresh directories pays nothing extra. `-p` treats an existing *directory* as done and an existing *file* as a failure, the way GNU `mkdir -p` does; reporting success over a file is what once hid a wrong path until a much later `ls` tripped over it. Plain `mkdir` fails on either. An existing directory under `-p` comes back as `Outcome::AlreadyThere`, so the summary counts only what it created ("Created 1 of 4 paths; 3 already existed.", or "Nothing to create: …" when that's all of them).
- `mv` refuses a destination that already exists (the server's `OBJECT_NAME_COLLISION`); `--replace` passes `RenameOptions::replace_if_exists`, so the server swaps the file in one step and the name is never missing. It never deletes the destination itself. A directory at either end is refused either way. A dry run prints `mv --replace …` so the plan shows it.
- **`ls` streams text and buffers everything else.** Plain, `-l`, and `-R` text goes through `DirectoryReader` and prints each batch as it arrives, in server order, flushed per batch (`meta::ls_streaming`). `--sort` and `--json` collect and sort by path (`meta::ls_sorted`). Decision/Why: first-output latency is the point on a big folder (`ls -R` over 15,250 entries on the QNAP: first line at 0.15 s instead of 7.6 s, same total), and nothing in text mode needs the whole listing, since `-l`'s columns are fixed-width (`push_row`). JSON always sorts: a parser can't use the array before its last row, so streaming buys it nothing and a stable order keeps it diffable. ❌ Don't make a `-l` column auto-size to its widest value; that's what would force `-l` to buffer. `-R` lists one directory to the end before descending, so one reader is open at a time, and never descends into a link (`DirectoryEntry::is_link`: a junction or directory symlink), which would walk someone else's tree or loop. `ls` stays on one connection and takes no `-j`.
- `ls -i` is the only thing that asks for index numbers (`LsFormat::list_options`), so a plain `ls` sends exactly the library's default listing. The index column is fixed-width too, for the same streaming reason. `indexNumber` appears in `--json` only with `-i`, and is `null` for an entry the server gave no ID.
- `ls` writes with `write_stdout`, not `println!`: a closed pipe (`| head`) is `BrokenPipe`, which closes the reader and exits 0, where `println!` panicked with exit 101.
- `realpath` is `SmbClient::resolve`: one compound round trip, one connection. After a DFS redirect it prints the target server and share (from the `Tree`, which the redirect updated), since that is what the resolved path is relative to.
- Every command supports `--json`. Human output is for people, JSON is the contract; if you change a JSON key, that's a breaking change.

## How bytes move

Neither direction ever holds a whole file. That is a correctness matter as much as a memory one, because the
server's `MaxReadSize` (8 MB on a stock Samba) is a hard ceiling on what one READ can return.

- **`put`** (`transfer::upload`): a file that fits in one WRITE is read into memory and sent as a single compound
  CREATE+WRITE+FLUSH and a CLOSE (`write_file`), two round trips. Anything larger streams through a `FileWriter`,
  read off disk 1 MiB at a time with `tokio::fs`, so the writer's window is what the upload costs.
  - **It writes to `<destination>.smb2-part` on the share and renames that over the destination**
    (`RenameOptions::replace_if_exists`, so the name is never missing) only once every byte is there
    (`move_into_place`); a failure deletes the partial file (`discard_partial_upload`, which reconnects once to do
    it and says so on stderr when it can't). Decision/Why: writing in place truncated the destination at the
    CREATE, so a failed upload destroyed a good earlier copy. The costs: one more round trip (the rename), the
    folder must let us create a file, and the replaced file's ACLs, streams, and creation time are the new file's,
    the same trade `rsync` makes by default.
- **`get` and `cat`** (`transfer::Download`): a `FileDownload` (`SmbClient::open_file_download`), each chunk
  written to the sink as `next_chunk` hands it out, in file order. The library's adaptive window paces the READs to
  the link (`crates/smb2/src/client/CLAUDE.md` § Streaming download entry points), which beats the fixed
  16 MiB-of-positioned-reads window this used to hand-roll over a `FileReader`, and is what makes resume possible.
  Measured against the QNAP over Tailscale (512 MiB, 2026-11-09): no throughput change either way, ~20 MiB/s up and
  down for both, which is that link's ceiling; a fast-LAN comparison hasn't been run.
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

## Resuming after a dropped connection

`get`, `cat`, and `put` reconnect and carry on. The library proves every resume safe; the CLI only decides when to
try and how often (`transfer::Resumes`).

- **Explicit reconnects, no `auto_reconnect`.** `Resumes::recover` calls `SmbClient::reconnect` then `connect_share`
  (`revive`), and every other command still ends on a drop. A dead session's tree is gone, so `revive` replaces the
  caller's `Tree`; `resume_file_writer` goes through `beside_tree`, which doesn't heal a stale tree the way
  `resume_download`'s `replaying` does.
- **Any `is_retryable()` error reconnects**, not only a lost connection: a timeout or a credit stall gets a fresh
  session too, since the resume is proven safe whatever the old session's state. Anything else is final, including
  `FileChanged` on a download.
- **Bounds:** `MAX_RESUMES` (5) per transfer step, each reconnect bounded by the library's `ReconnectPolicy` (about a
  minute). A `SharingViolation` right after a reconnect is the dead session still holding our file (a writer shares
  nothing), so it waits `BUSY_WAIT` (2 s) up to `MAX_BUSY_WAITS` (15) times without reconnecting. Samba lets go at once
  on a clean close, and for a named login also when the new session names the old one (`PreviousSessionId`); a guest
  session that died quietly is the case the wait is for.
- **Downloads resume from `FileDownload::checkpoint`**, which counts exactly the bytes handed out, so nothing reaches
  the sink twice and `cat` can resume into a pipe. `pump` refuses to resume if the checkpoint and its own count
  disagree, rather than corrupt the copy.
- **Uploads checkpoint every `CHECKPOINT_EVERY` (64 MiB)** with `FileWriter::flush_checkpoint` (drain, FLUSH), and a
  drop resumes from the last one with `resume_file_writer`, seeking the source to its offset. Before the first
  checkpoint, it starts over. A `ResumeRefused` starts over too, since the partial file is ours alone. A small file's
  one compound is simply sent again.
- **The rename is retried after a reconnect**, and a retry that finds the partial gone with a file of the right size
  at the destination counts as done: the first rename may have happened with its answer lost.
- Close a `FileReader` explicitly to hear how the CLOSE went. Dropping one still closes its handle (the library
  queues the CLOSE as it drops), but the answer goes unseen.

## Testing

`cargo test -p smb2-cli` covers parsing, formatting, the transfer destination rules, the `mkdir` collision rules, and which commands accept `-j`, all with no network. `tests/dry_run.rs` runs the built binary against `//127.0.0.1:1/…`, where connecting is refused instantly, which is what makes "`--dry-run` doesn't connect" testable.

`tests/e2e.rs` is the other half: 48 tests that run the built binary against a live Samba fixture and check what
it left on the share, because a command that writes the wrong thing passes every test that never connects. Both
data-safety bugs this CLI has shipped were caught by hand for exactly that reason. Run it with `just test-cli-e2e`,
or by hand:

```sh
./crates/smb2/tests/docker/start.sh internal smb-auth
cargo test -p smb2-cli --test e2e -- --ignored
./crates/smb2/tests/docker/stop.sh
```

`smb-auth` is `testuser`/`testpass` on port 10446, share `private`. The `xattr` and `streams` tests need named streams, so they use `smb-fruit` as guest on port 10464, on a connection of their own; `just test-cli-e2e` starts both. The other fixtures in `crates/smb2/tests/docker/internal/` cover signing, encryption, guest access, DFS, and flaky servers. `start.sh` takes service names after the profile, which is how the CLI suite brings up one container instead of 16.

Two things to know before adding a test there:

- **The suite opens exactly one SMB connection for the whole binary**: setup and verification are a few round
  trips each, and 30 handshakes would cost more than the work they support. Use the `Fixture` helpers rather
  than reaching for a connection of your own.
- **Each test owns `cli-e2e/<its own name>/`** and wipes it on entry, which is what lets the file run in parallel
  and makes a re-run independent of the last one. Setup and verification go through the library, so a CLI bug
  can't hide behind the CLI agreeing with itself.
- **Dropped connections come from `CuttingProxy`**, a std-thread TCP proxy in front of `smb-auth` that cuts its
  first N connections after a chosen byte count in one direction and lets later ones through (`Fixture::target_at`
  aims the CLI at it). Decision/Why: deterministic, where `smb-flaky`'s 5 s up / 5 s down depends on how fast the
  transfer runs. `carried()` reports each connection's bytes, which is how a test tells a resume from a restart.

The bulk-operation benchmark that produced the `-j` numbers lives at `benchmarks/cli-bulk-ops/`.
