# Samba 4.9.5 crashes on `write_file_compound`

**Status**: confirmed against real hardware, not chased further. Affects the server, not this crate.

`Tree::write_file_compound` (CREATE + WRITE + FLUSH + CLOSE in one frame) reliably panics Samba 4.9.5. The connection
dies mid-transfer; the client sees `Disconnected` or `Broken pipe`.

## What the server says

```
[.., 0] ../source3/lib/popt_common.c:67(popt_s3_talloc_log_fn)
  talloc: access after free error - first free may be at ../tevent_req.c:289
  Bad talloc magic value - access after free
[.., 0] ../source3/lib/util.c:816(smb_panic_s3)
  PANIC (pid 9435): Bad talloc magic value - access after free
  dumping core in /var/log/samba/cores/smbd
```

A use-after-free on a `tevent_req`, with a core dump each time.

## Reproducing it (2026-08-01)

Raspberry Pi 4 (192.168.1.156), Debian buster, `samba 2:4.9.5+dfsg-5+deb10u1+rpi1` (armhf), guest share. Driven by
`examples/write_storm`:

- **8/8 runs crashed it.** Fastest kill: 126 ms into a run.
- **The server's config doesn't matter.** The first eight runs were against `smb2 max write = 1048576` (set to mimic
  the QNAP); re-confirmed afterwards against the Pi's stock `smb2 max write = 8388608`, same panic, same core.
- **Concurrency is not the trigger.** `WS_CONC=1` crashes after 2 files.
- **Size is not the trigger.** A 4 KB body crashes it (`WS_SMALL=4096`), as does 520 KB.
- **One compound write is not enough.** It takes ~2, which is why the single-write
  `compound_read_and_write_on_raspberry_pi` integration test passes against the same box.
- **Streamed writes are innocent.** `WS_LARGE_EVERY=1 WS_CONC=8` (pure `FileWriter`, 1 MB wire writes, no compound)
  ran 8/8 files clean, repeatedly. Only the compound path kills it.

## Who is affected

- **Samba 4.20.6** (the crate's Docker fixtures): immune. 96 files / 16 concurrent / with a watcher, clean.
- **Samba 4.22.10** (Debian 13 trixie, armhf): immune. Re-checked on the same Raspberry Pi that used to die, after it
  was rebuilt on trixie (2026-08-08): `WS_CONC=1 WS_SMALL=4096`, the shape that killed 4.9.5 after two files, plus 96
  files at 8 concurrent with a watcher. 0 failures, 0 core dumps, no `talloc` line in any log, `smbd` still active.
- **QNAP TS-464, QTS, SMB 3.1.1**: immune. 768 files × 6 rounds, clean.
- **Samba 4.9.5**: dies.

4.9.5 shipped in 2019 and is long out of support, so this is almost certainly a Samba bug fixed upstream rather than a
malformed frame from us — newer Samba and the NAS both accept the identical frame. It has not been bisected against
Samba's history, and no upstream bug id has been matched to it.

## Why it is written down

The blast radius is wider than it looks. `write_file_compound` is the fast path for **every** file that fits one
`max_write_size`, so on an affected server a routine small-file copy kills the server-side connection — the common case,
not an edge case. Anyone running an older Samba build (a Debian buster NAS, an old OpenMediaVault, vendor firmware built
on 4.9-era Samba) hits it immediately.

If a consumer reports "the connection dies on small-file copies but large ones are fine", check the server's Samba
version before looking anywhere in this crate. A workaround exists without code changes: sending those writes through
`create_file_writer` instead of the compound path avoids it entirely, at the cost of three extra round trips per file.
