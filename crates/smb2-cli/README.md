# smb2-cli

A command-line SMB2/3 client. It talks to a share directly over the network, so you don't have to mount it first: no root, no `mount_smbfs`, no kernel client, just a binary and a target like `//host/share/path`.

Built on the [smb2](https://github.com/vdavid/smb2) crate.

## Why

Mounting a share and using ordinary tools works fine until you have thousands of small metadata operations. Every `stat`, `rename`, and `rmdir` through a kernel SMB mount is a synchronous round trip, and they don't overlap. `smb2-cli` keeps a pool of authenticated connections open and spreads a batch across them, which turns a long serial crawl into a short parallel one.

It also prints JSON for every command, which makes it pleasant to drive from a script or an agent.

## Install

```sh
cargo install --path .
```

The binary is called `smb2`.

## Use

```sh
# Look around
smb2 shares raspi
smb2 df //raspi/PiHDD
smb2 ls -l //raspi/PiHDD/photos
smb2 ls -R --json //raspi/PiHDD/photos

# Move bytes
smb2 cat //raspi/PiHDD/notes.txt
smb2 get //raspi/PiHDD/notes.txt ./notes.txt
smb2 put ./notes.txt //raspi/PiHDD/

# Change things
smb2 mkdir -p //raspi/PiHDD/2026/2026-08-05
smb2 mv //raspi/PiHDD/old.txt //raspi/PiHDD/new.txt
smb2 rm //raspi/PiHDD/junk.txt
smb2 rmdir //raspi/PiHDD/empty-dir
```

### Batches

Every path-taking command accepts `--from-file`, where each line is a path relative to the target you give. Use `-` to read from stdin. `mv --from-file` takes `from<TAB>to` pairs.

```sh
# Delete 5,000 empty directories over 16 connections
smb2 rmdir --from-file dirs.txt -j 16 //raspi/PiHDD/xiaomi_camera_videos/788b2a1989e9

# Rename in bulk
printf 'a/old.mp4\ta/new.mp4\n' | smb2 mv --from-file - //raspi/PiHDD
```

`--dry-run` prints what would happen and touches nothing. `-j` sets how many connections to spread the work over (default 8).

### Credentials

In order of preference:

1. `--password-command 'secret RASPI_SMB_PASSWORD'` runs a command and uses its stdout. This keeps the password out of your shell history and out of the process list.
2. `SMB2_PASS`, usually from a `.env` file or a secrets manager.
3. `--password`, which your shell will remember. Avoid it.
4. A prompt, when you're on a terminal and gave none of the above.

`--user` (or `SMB2_USER`) sets the username; `--guest` connects with no credentials.

## Exit codes

`0` when everything worked, `1` when anything failed. Batch commands report per-path failures on stderr and still process the rest of the batch, so one bad path doesn't abandon the run.
