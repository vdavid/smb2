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

No Rust toolchain needed. On macOS or Linux, with [Homebrew](https://brew.sh):

```sh
brew install vdavid/tap/smb2
```

Or with the install script (macOS and Linux):

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/vdavid/smb2/releases/latest/download/smb2-cli-installer.sh | sh
```

On Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/vdavid/smb2/releases/latest/download/smb2-cli-installer.ps1 | iex"
```

Prebuilt binaries for each platform are on [GitHub Releases](https://github.com/vdavid/smb2/releases). If you have Rust, `cargo install smb2-cli` works too.

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
smb2 ls -i //raspi/PiHDD/photos                  # with each file's index number
smb2 stat //raspi/PiHDD/photos/IMG_0001.jpg
smb2 realpath //raspi/PiHDD/PHOTOS/img_0001.JPG  # the name the server stores

# Move bytes
smb2 cat //raspi/PiHDD/notes.txt
smb2 get //raspi/PiHDD/notes.txt ./notes.txt
smb2 put ./notes.txt //raspi/PiHDD/inbox/     # into the directory, keeping the name
smb2 put ./notes.txt //raspi/PiHDD/read-me.txt # under a name you choose

# Change things
smb2 mkdir -p //raspi/PiHDD/2026/2026-08-05
smb2 mv //raspi/PiHDD/old.txt //raspi/PiHDD/new.txt
smb2 mv --replace //raspi/PiHDD/notes.tmp //raspi/PiHDD/notes.txt  # over a file that's there
smb2 rm //raspi/PiHDD/junk.txt
smb2 rmdir //raspi/PiHDD/empty-dir

# Extended attributes and named streams
smb2 xattr //raspi/PiHDD/notes.txt                   # attribute names
smb2 xattr -l //raspi/PiHDD/notes.txt                # names and values
smb2 xattr -p user.note //raspi/PiHDD/notes.txt
smb2 xattr -w user.note hello //raspi/PiHDD/notes.txt
smb2 xattr -x -w user.note 68656c6c6f //raspi/PiHDD/notes.txt  # the value as hex
smb2 xattr -d user.note //raspi/PiHDD/notes.txt
smb2 streams //raspi/PiHDD/notes.txt                 # the raw stream list
```

`xattr` works like macOS's own command and stores attributes the way macOS's SMB client does, so a Finder tag is the same bytes under the same name either way. `-w` never creates a missing file. `-d` on an attribute that isn't there succeeds. It takes `-j` and `--from-file` like the other batch commands, and `--json` reports values as `valueHex`.

`ls` prints as the server answers, a batch of a few hundred entries at a time, in the order the server lists them. So a folder of 100,000 files starts showing up after one round trip, and `smb2 ls … | head` stops listing as soon as `head` has enough. Pass `--sort` to get the rows sorted by path instead; that waits for the whole listing first. `--json` is always sorted, since a JSON array is only useful once it's complete. `-R` lists each directory to the end before going into its subdirectories. Measured against a QNAP NAS on a LAN, `ls -R` over 15,250 photos printed its first line after 0.15 s instead of 7.6 s, and finished in the same time as before.

`ls -i` puts each entry's index number in front of it: the file system's ID for the file, like an inode number, which stays put when the file is renamed. With `--json` it's `indexNumber`, or `null` when the server has none for that entry.

`stat` shows four times: created, modified, accessed, and changed. `changed` moves on any change to the file, its attributes and timestamps included, so it catches an edit `modified` doesn't. `ls --json` carries `changed` too.

`realpath` prints the path the way the server stores it: its casing, and long names in place of 8.3 aliases like `PROGRA~1`. It needs SMB 3.1.1 (Samba, or Windows 10 / Server v1803 and later) and says so when the server can't answer.

`mv` won't replace a file that's already at the destination unless you pass `--replace`. With it, the server swaps the file in one step, so the destination is never missing in between. It never replaces a directory.

`mkdir -p` is happy to find the directory already there, and stops when the name belongs to a file, the way GNU `mkdir -p` does.

`put` picks its destination the way `cp` does. A target that ends in `/`, or that's already a directory on the share, gets the file inside it under its own name; anything else is the full path to write. An upload never replaces a directory: if the destination is one, `put` says so and stops.

Transfers stream in both directions, so size isn't a limit and neither is your memory: a 600 MB `get` runs in about 60 MB of RAM, and `put` is the same the other way.

`--json` works on every command. `--dry-run` works on everything that writes (`mkdir`, `rm`, `rmdir`, `mv`, `put`, `get`, and `xattr -w` / `-d`): it prints what would happen and makes no connection at all.

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
