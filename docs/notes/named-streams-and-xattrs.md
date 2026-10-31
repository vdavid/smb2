# Named streams and macOS xattrs: what servers do, and what it costs

Evidence behind `crates/smb2/src/client/streams.rs`, `xattr.rs`, and `batch.rs`. Measured 2026-10-31 unless it says
otherwise.

## Rig

- **QNAP TS-464**: QuTS hero, ZFS, Samba 4.20, `vfs objects = shadow_copy2 widelinks richacl catia fruit qnap_macea streams_depot aio_pthread`. Client: a Mac on Wi-Fi, ~3.2 ms ping on the LAN and ~4.5 ms over Tailscale. The macOS mount goes over Tailscale.
- **`smb-fruit`**: Docker, Samba 4.20.6 on Alpine, `catia fruit streams_xattr`, `fruit:metadata = stream`, `fruit:resource = stream`.
- **`smb-guest`**: Docker, plain Samba with no streams module.
- **No Windows server was tested.** Everything about Windows below is unverified.

## Finder compatibility

Proved on the QNAP through a real `smbfs` mount, by `tests/integration.rs` (`macos_*`, `nas_*`; needs `SMB2_TEST_NAS_MOUNT`) and by hand with the API Finder's tags go through (`NSURLTagNamesKey`, a small Swift program):

- A tag set with that API on a file and a folder reads back through `smb2`, byte for byte.
- macOS's own 50-byte `Red` plist written by `smb2` reads as `["Red"]` through that API, on a file and a folder.
- FinderInfo written by either side reads on the other. The stream is `AFP_AfpInfo`: `AFP\0`, version bytes `00 00 01 00`, 4 reserved, backup time (`80 00 00 00` for none), 32 bytes of FinderInfo at offset 16, then ProDOS and padding. ❌ The version isn't `00 01 00 00`: `vfs_fruit` refuses that with `STATUS_NOT_FOUND` on the WRITE, and QNAP accepts and rewrites it.
- Changes show on the other side within 25 ms. The mount doesn't serve stale xattrs here.

Not checked by eye: the Finder window itself. David's tag-color dot in Finder is the remaining manual check.

## What a consumer has to know

- **A QNAP keeps two streams it reports deleted.** Deleting `com.apple.metadata:_kMDItemUserTags` or `AFP_Resource` answers success and changes nothing, by compound SET_INFO, standalone SET_INFO, and `FILE_DELETE_ON_CLOSE` alike, and for macOS's own `xattr -d` too (exit 0, attribute still on disk as `user.com.apple.metadata:_kMDItemUserTags`). `user.*`, `com.apple.foo`, and FinderInfo do delete. So `delete_stream` checks with a listing and answers `Error::StreamDeleteIgnored`.
- **macOS never deletes tags anyway.** Clearing the last tag through its API writes a 42-byte plist holding an empty array, and that's what works everywhere. The bytes: `62706c6973743030a0080000000000000101000000000000000100000000000000000000000000000009`. Setting a color tag through that API also sets the label bits in FinderInfo; writing the plist alone doesn't, and the API still reads the tag.
- **A resource fork on a QNAP leaves a `._name` file** (AppleDouble, `fruit:resource = file`), which stays behind when the file is deleted, so the folder can't be removed until it goes too. Tags and FinderInfo leave none.
- **A zero-length value reads as one NUL byte through the mount** on the QNAP, and as empty through `smb2`.
- **The modification time differs by server.** Writing a stream bumps the file's `LastWriteTime` on `smb-fruit` (`streams_xattr`), and doesn't on the QNAP (`qnap_macea`).
- **Size limit differs by server.** `smb-fruit` refuses a stream past 64 KiB with `STATUS_FILE_SYSTEM_LIMITATION`, after emptying it, so `write_stream` then deletes it and the old value is gone. The QNAP took 200 KiB.
- **`FileFsAttributeInformation`'s name says `NTFS` on every Samba tested**, ZFS included. Only the `supports_named_streams` bit means anything.
- **A plain Samba** reports the bit off, lists no streams (so `get_xattr` is `Ok(None)`), and refuses a stream's name with `STATUS_OBJECT_NAME_INVALID`, which `smb2` reports as `Error::NamedStreamsUnsupported`.
- **A missing stream and a missing file answer alike** (`STATUS_OBJECT_NAME_NOT_FOUND`), and a missing parent folder answers `STATUS_OBJECT_PATH_NOT_FOUND`.
- **Streams on folders and the share root work** on both servers. A stream op on a file another client has open works, since every open shares everything.
- **A metadata watch** (`WatchOptions::metadata`) reports another client's tag as `Modified` under the plain file name on both servers. Neither sent the stream actions (6–8), which are typed anyway for servers that do.

## How fast

`crates/smb2/examples/xattr_bulk_bench.rs`, 2,000 files with 5% tagged, Samba's `smbd` idle (load ~1). Each row is the median of its runs. "Mount" is a serial `getxattr` loop in C over the macOS mount, what Cmdr does today.

Over Tailscale, the mount's own route:

- Mount, serial: 188 files/s, p50 5.0 ms, p99 9.5 ms, max 33 ms
- `smb2` one at a time: 174 files/s
- `get_xattr_many`, defaults: **1,181 files/s, 6.3× the mount**, p50 12.7 ms, p99 28 ms, max 43 ms
- With `assume_paths_exist`: 1,100 files/s, p99 25 ms
- Over two connections, default mode: 1,010–1,930 files/s across runs, too noisy to rank

On the LAN:

- `smb2` one at a time: 218 files/s
- `get_xattr_many`, defaults: 1,359 files/s, p50 10.9 ms, p99 26 ms
- With `assume_paths_exist`: 1,167 files/s, p99 21 ms
- Over two connections, default mode: 2,054 files/s, p50 6.9 ms

So the issue's "well over 10×" didn't hold on one connection: `smbd` handles a connection on one thread, and that's the ceiling at about 0.8 ms per file. Two connections nearly double it on the LAN.

**Window.** On the LAN, reading straight to the stream: 1,065 files/s at 8, 1,200 at 16, 1,100 at 32, 1,180 at 64, 1,150 at 128, while p50 climbs 7, 13, 28, 53, 109 ms. Past 16 it only adds latency to everything else on the connection, so 16 is the default.

**Strategy.** Files/s on the LAN, one connection, window 16:

- 5% tagged: list first 1,400, read first and assume 1,150, read first and then check the file 900
- 100% tagged (1,000 files): list first 620, assume 1,150, read first and then check 1,170
- `smb-fruit`, 5% tagged: list first 9,500, assume 10,200, read first and then check 6,000

Listing first is the default because few files carry a given attribute, and it tells a missing file apart. A failed stream open costs this server more than opening the file and listing. `assume_paths_exist` is the steady choice when many files carry it.

**Under load.** Six writers on the NAS looping 32 MiB of random data plus `sync`, load 5–7, in a scratch folder of ours:

- Defaults: 980–1,460 files/s, p99 22–100 ms, max 157 ms, nothing over 300 ms
- `assume_paths_exist`: 1,070–1,180 files/s, p99 20–24 ms, max 32 ms
- At window 64, `assume_paths_exist`: p99 up to 341 ms, 35 of 2,000 over 300 ms

The multi-second stalls in `benchmarks/read-ahead/results/stat-stall-diagnosis.md` did not show up in these runs. That load is ours, not the photo app's, so this neither confirms nor rules them out for a batch. The engine is built for them either way: results arrive as they finish, and no per-item timeout can turn a stall into a failure.
