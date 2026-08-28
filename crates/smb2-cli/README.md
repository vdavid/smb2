# smb2-cli

A command-line SMB2/3 client. It talks to a share directly over the network, so you never mount it: no root, no `mount_smbfs`, no kernel client. One binary and a target like `//host/share/path`.

Built on the [`smb2`](https://crates.io/crates/smb2) crate, which does all the protocol work. Both live in the
[same repo](https://github.com/vdavid/smb2), so a protocol fix and the CLI change that uses it ship together.

## Why

A mounted share is fine until you have thousands of small metadata operations. macOS smbfs does one synchronous round trip per syscall with no overlap, so a bulk delete crawls. `smb2-cli` opens N independent connections and spreads the batch across them.

Measured against a Raspberry Pi over LAN, 500-path batches, each arm getting its own disjoint slice:

| Operation | Mounted share | `smb2` at `-j 16` |
|---|---|---|
| Delete files | 34/s | 500/s |
| Remove empty directories | 3.3/s | 155/s |

For reference, one SSH process doing plain local syscalls on the Pi managed 556/s on the deletes. So the CLI beats going through the mount, and it beats shelling into the box. On a longer run (39,176 files) it sustained 877/s.

`-j 16` was the sweet spot on that four-core Pi. `-j 32` was slower, so don't crank it past what the server can serve.

`benchmarks/cli-bulk-ops/bulk-bench.sh` in the repo reproduces all of this.

Every command also prints JSON, which makes it pleasant to drive from a script or an agent.

## Install

```sh
cargo install smb2-cli
```

The binary is called `smb2`.

## Credentials

In order of preference:

1. **`--password-command`** runs a command and reads its stdout: `--password-command 'secret RASPI_SMB_PASSWORD'`. Keeps the password out of your shell history and out of `ps`.
2. **`SMB2_PASS`**, usually from a `.env` file or a secrets manager.
3. **A prompt**, when you're on a terminal and gave none of the above.

There's also `--password`, but your shell will remember it and so will the process list. Avoid it.

`--user` (or `SMB2_USER`) sets the username; `--guest` connects with no credentials.

## Commands

```sh
# Look around
smb2 shares raspi
smb2 df //raspi/PiHDD
smb2 ls -l //raspi/PiHDD/photos
smb2 ls -R --json //raspi/PiHDD/photos
smb2 stat //raspi/PiHDD/photos/IMG_0001.jpg

# Move bytes
smb2 cat //raspi/PiHDD/notes.txt
smb2 get //raspi/PiHDD/notes.txt ./notes.txt
smb2 put ./notes.txt //raspi/PiHDD/inbox/     # into the directory, keeping the name
smb2 put ./notes.txt //raspi/PiHDD/read-me.txt # under a name you choose

# Change things
smb2 mkdir -p //raspi/PiHDD/2026/2026-08-05
smb2 mv //raspi/PiHDD/old.txt //raspi/PiHDD/new.txt
smb2 rm //raspi/PiHDD/junk.txt
smb2 rmdir //raspi/PiHDD/empty-dir
```

`mkdir -p` is happy to find the directory already there, and stops when the name belongs to a file, the way GNU `mkdir -p` does.

`put` picks its destination the way `cp` does. A target that ends in `/`, or that's already a directory on the share, gets the file inside it under its own name; anything else is the full path to write. An upload never replaces a directory: if the destination is one, `put` says so and stops.

`--json` works on every command. `--dry-run` works on everything that writes (`mkdir`, `rm`, `rmdir`, `mv`, `put`, and `get`): it prints what would happen and makes no connection at all.

## Batches

Every path-taking command accepts `--from-file`, where each line is a path relative to the target you give. Use `-` to read from stdin. `mv --from-file` takes `from<TAB>to` pairs.

```sh
# Delete 5,000 empty directories over 16 connections
smb2 rmdir --from-file dirs.txt -j 16 //raspi/PiHDD/xiaomi_camera_videos/788b2a1989e9

# Rename in bulk
printf 'a/old.mp4\ta/new.mp4\n' | smb2 mv --from-file - //raspi/PiHDD
```

`-j` sets how many connections to spread the work over (default 8). It goes after the subcommand, and only the commands that actually spread work take it: `stat`, `mkdir`, `rm`, `rmdir`, and `mv`. Everything in one batch has to live on the same host and share.

## Exit codes

`0` when everything worked, `1` when anything failed.

A batch doesn't abandon the run on the first bad path. It processes the rest, reports the per-path failures on stderr, and exits non-zero. So you always find out, and you never have to guess how far it got.

## License

MIT or Apache-2.0, your choice.
