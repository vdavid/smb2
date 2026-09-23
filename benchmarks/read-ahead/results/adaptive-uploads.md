# Adaptive uploads against the fixed window (2026-09-23)

The same rig as `adaptive.md` (M1 Max, OrbStack, Samba on Alpine 3.21, container capped at two CPUs, `MaxWriteSize`
8 MiB), with the shaping turned around: `DIRECTION=up` puts `netem` on the container's ingress through an ifb device, so
the delay and the rate cap sit on the client-to-server direction, which is the one an upload's payload takes. The
downlink carries only the WRITE answers and the side `stat`'s reply, unshaped.

Variants (`src/upload.rs`):

- `0.24.4`: the published 0.24.4 `FileWriter` (up to 32 WRITEs of `MaxWriteSize` in flight, pushed as unpolled
  futures, bounded at 32 MiB by the connection's write budget), built from crates.io in a separate copy of the bench.
- `adaptive`: the 0.25 default, 512 KiB WRITEs and `WriteBehind::Adaptive`, on the connection the previous variants
  used, so it starts from the upload rate the last one measured.
- `wbmaxx32`: the old shape through the new knobs (`with_chunk_size(MaxWriteSize)`, `WriteBehind::Fixed(32)`). It
  differs from `0.24.4` in one way: each WRITE is on the wire before the next is built, so at most one frame waits in
  this process's send queue and the rest of the backlog sits in the socket buffer and the link.
- `wb512x8`, `wb512x16`: fixed windows of 512 KiB WRITEs.
- `compound`: one compound CREATE + WRITE + FLUSH + CLOSE (`write_file_compound`), skipped above `compound_write_limit`.
- `auto`: `compound` when the file fits `Connection::quick_write_limit`, `adaptive` otherwise.

Each upload is pushed in 1 MiB pieces and read back afterwards (a wrong byte fails the run). "Side stat" is a `stat`
every 20 ms on a clone of the same connection during the upload; "stat after cancel" pushes a quarter of the file,
calls `abort()`, and times until a `stat` answers.

Commands (`BIN` pointing at the 0.24.4 build for the `0.24.4` rows):

- `DIRECTION=up VARIANTS=default,compound SIZES=1048576,8388608,104857600 BIN=... ./run.sh base-fast.csv 3 "0 60 200"`
- `DIRECTION=up LOADS=0 VARIANTS=default,compound SIZES=1048576,8388608 BIN=... ./run.sh base-slow.csv 2 "60@3mbit 20@24mbit"`
- `DIRECTION=up VARIANTS=default,wbmaxx32,wb512x8,compound,auto SIZES=1048576,8388608,104857600 ./run.sh new-fast.csv 3 "0 60"`
- `DIRECTION=up LOADS=0 VARIANTS=default,wbmaxx32,wb512x8,wb512x16,compound,auto SIZES=1048576,8388608,104857600 ./run.sh new-200.csv 3 200`
- `DIRECTION=up LOADS=0 VARIANTS=default,wbmaxx32,wb512x8,compound,auto SIZES=1048576,8388608 ./run.sh new-slow375.csv 2 "60@3mbit"`
- `DIRECTION=up LOADS=0 VARIANTS=default,wbmaxx32,wb512x8,compound,auto SIZES=1048576,8388608 ./run.sh new-slow3m.csv 3 "20@24mbit"`

## What it shows

- **Slow uplinks stop queueing the whole file ahead of everything else.** At 375 KB/s (`60@3mbit`), a `stat` during
  an 8 MiB upload waited 23.4 s at most with 0.24.4 and 1.5 s with `adaptive`: one 512 KiB chunk plus the headroom. A
  cancel came back in 2.0 s instead of 6.1 s. At 3 MB/s (`20@24mbit`) the worst `stat` went from 2.9 s to 370 ms. Wall
  time is the same on both, within 1%.
- **Fast links keep their throughput.** Unshaped, 100 MiB ran at 793 MB/s against 637 MB/s for 0.24.4 (and
  488 against 483 with two background writers). At +60 ms, 45.6 against 49.7 MB/s (49.0 against 53.2 loaded), and at
  +200 ms 16.0 against 16.6 MB/s, while the worst `stat` there dropped from 1.8 s to 416 ms and a cancel from 2.1 s to
  650 ms. The 4 MiB cap is the cost: `wb512x16` (8 MiB) bought 2.5% at +200 ms for 50% more queue, the same trade the
  read-ahead cap made.
- **The one-frame cut-off holds up.** `auto` picks the compound write when the file fits what the uplink moves in
  250 ms: a 1 MiB file at +60 ms in 82 ms against 355 ms streamed, 8 MiB in 236 against 455 ms on the fast link, while
  on the slow links it streams everything above one chunk, where one frame would hold the connection for seconds (a
  1 MiB compound at 375 KB/s: every `stat` waited 2.9 s). It errs toward streaming: at +200 ms it streams 8 MiB, which
  one frame would have done in 680 against 1,290 ms.
- **Small files pay the cold window.** With no upload rate on the connection, the first WRITE goes out alone, so a
  1 MiB streamed upload costs an extra round trip until something has been measured. That's what `quick_write_limit`
  is for: a consumer that sends small files as one frame never pays it.
- **Background writers on a shaped uplink are out of scope.** Writers on other connections fill the shared uplink
  queue themselves, which no per-connection window can bound, and the side `stat` then times out. So the loaded rows are
  the unshaped and +60 ms links only.

## Fast links


### Uplink +0 ms, load: none, file 1.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 29.8 | 35.2 | 1 | n/a | 2 / 2 | n/a |
| adaptive | 22.1 | 47.5 | 2 | 1.0 MiB | 4 / 4 | n/a |
| wbmaxx32 | 12.2 | 86.1 | 1 | 1.0 MiB | 2 / 2 | n/a |
| wb512x8 | 11.0 | 95.3 | 2 | 1.0 MiB | 3 / 3 | n/a |
| compound | 8.9 | 117.8 | 1 | 1.0 MiB | 2 / 2 | n/a |
| auto | 9.1 | 115.1 | 1 | 1.0 MiB | 2 / 2 | n/a |

### Uplink +0 ms, load: none, file 8.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 30.6 | 273.7 | 1 | n/a | 4 / 4 | 11 |
| adaptive | 31.1 | 269.4 | 16 | 4.0 MiB | 6 / 6 | 3 |
| wbmaxx32 | 16.8 | 500.4 | 1 | 8.0 MiB | 1 / 1 | 3 |
| wb512x8 | 14.9 | 563.3 | 16 | 4.0 MiB | 1 / 1 | 3 |
| compound | 18.9 | 443.2 | 1 | 8.0 MiB | 0 / 0 | n/a |
| auto | 17.4 | 482.7 | 1 | 8.0 MiB | 1 / 1 | n/a |

### Uplink +0 ms, load: none, file 100.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 164.7 | 636.8 | 13 | n/a | 9 / 29 | 55 |
| adaptive | 132.3 | 792.6 | 200 | 4.0 MiB | 3 / 7 | 14 |
| wbmaxx32 | 146.1 | 717.7 | 13 | 32.0 MiB | 1 / 12 | 18 |
| wb512x8 | 125.0 | 839.1 | 200 | 4.0 MiB | 2 / 8 | 13 |
| auto | 121.8 | 860.8 | 200 | 4.0 MiB | 1 / 8 | n/a |

### Uplink +0 ms, load: 2 writers, file 1.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 12.0 | 87.3 | 1 | n/a | 1 / 1 | n/a |
| adaptive | 29.5 | 35.5 | 2 | 1.0 MiB | 1 / 1 | n/a |
| wbmaxx32 | 9.1 | 115.7 | 1 | 1.0 MiB | 2 / 2 | n/a |
| wb512x8 | 8.8 | 119.5 | 2 | 1.0 MiB | 1 / 1 | n/a |
| compound | 7.2 | 145.8 | 1 | 1.0 MiB | 1 / 1 | n/a |
| auto | 19.1 | 54.9 | 1 | 1.0 MiB | 1 / 1 | n/a |

### Uplink +0 ms, load: 2 writers, file 8.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 43.0 | 195.3 | 1 | n/a | 1 / 3 | 9 |
| adaptive | 22.4 | 373.6 | 16 | 4.0 MiB | 4 / 4 | 7 |
| wbmaxx32 | 21.4 | 391.6 | 1 | 8.0 MiB | 2 / 2 | 32 |
| wb512x8 | 50.0 | 167.7 | 16 | 4.0 MiB | 1 / 3 | 5 |
| compound | 23.6 | 355.5 | 1 | 8.0 MiB | 1 / 1 | n/a |
| auto | 24.2 | 346.9 | 1 | 8.0 MiB | 1 / 1 | n/a |

### Uplink +0 ms, load: 2 writers, file 100.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 217.0 | 483.3 | 13 | n/a | 6 / 32 | 41 |
| adaptive | 215.1 | 487.5 | 200 | 4.0 MiB | 4 / 56 | 14 |
| wbmaxx32 | 275.2 | 381.0 | 13 | 32.0 MiB | 9 / 59 | 22 |
| wb512x8 | 268.4 | 390.7 | 200 | 4.0 MiB | 4 / 44 | 17 |
| auto | 344.2 | 304.6 | 200 | 4.0 MiB | 3 / 46 | n/a |

### Uplink +60 ms, load: none, file 1.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 325.2 | 3.2 | 1 | n/a | 67 / 71 | n/a |
| adaptive | 355.4 | 3.0 | 2 | 1.0 MiB | 74 / 101 | n/a |
| wbmaxx32 | 294.1 | 3.6 | 1 | 1.0 MiB | 70 / 74 | n/a |
| wb512x8 | 293.8 | 3.6 | 2 | 1.0 MiB | 69 / 72 | n/a |
| compound | 77.1 | 13.6 | 1 | 1.0 MiB | 71 / 71 | n/a |
| auto | 82.4 | 12.7 | 1 | 1.0 MiB | 69 / 69 | n/a |

### Uplink +60 ms, load: none, file 8.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 419.6 | 20.0 | 1 | n/a | 66 / 185 | 213 |
| adaptive | 454.7 | 18.4 | 16 | 4.0 MiB | 67 / 116 | 212 |
| wbmaxx32 | 449.0 | 18.7 | 1 | 8.0 MiB | 78 / 191 | 214 |
| wb512x8 | 460.1 | 18.2 | 16 | 4.0 MiB | 74 / 122 | 213 |
| compound | 256.1 | 32.8 | 1 | 8.0 MiB | 72 / 130 | n/a |
| auto | 236.2 | 35.5 | 1 | 8.0 MiB | 122 / 124 | n/a |

### Uplink +60 ms, load: none, file 100.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 2110.4 | 49.7 | 13 | n/a | 76 / 601 | 705 |
| adaptive | 2299.3 | 45.6 | 200 | 4.0 MiB | 98 / 137 | 235 |
| wbmaxx32 | 2148.7 | 48.8 | 13 | 32.0 MiB | 103 / 581 | 579 |
| wb512x8 | 2326.4 | 45.1 | 200 | 4.0 MiB | 106 / 135 | 257 |
| auto | 2338.6 | 44.8 | 200 | 4.0 MiB | 115 / 140 | n/a |

### Uplink +60 ms, load: 2 writers, file 1.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 274.8 | 3.8 | 1 | n/a | 65 / 72 | n/a |
| adaptive | 263.8 | 4.0 | 2 | 1.0 MiB | 66 / 68 | n/a |
| wbmaxx32 | 304.1 | 3.5 | 1 | 1.0 MiB | 66 / 75 | n/a |
| wb512x8 | 312.9 | 3.4 | 2 | 1.0 MiB | 65 / 79 | n/a |
| compound | 78.0 | 13.4 | 1 | 1.0 MiB | 69 / 69 | n/a |
| auto | 91.6 | 11.4 | 1 | 1.0 MiB | 69 / 69 | n/a |

### Uplink +60 ms, load: 2 writers, file 8.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 427.6 | 19.6 | 1 | n/a | 68 / 179 | 210 |
| adaptive | 407.9 | 20.6 | 16 | 4.0 MiB | 67 / 111 | 204 |
| wbmaxx32 | 446.2 | 18.8 | 1 | 8.0 MiB | 74 / 188 | 203 |
| wb512x8 | 446.1 | 18.8 | 16 | 4.0 MiB | 67 / 114 | 203 |
| compound | 246.6 | 34.0 | 1 | 8.0 MiB | 108 / 130 | n/a |
| auto | 245.5 | 34.2 | 1 | 8.0 MiB | 141 / 141 | n/a |

### Uplink +60 ms, load: 2 writers, file 100.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 1970.7 | 53.2 | 13 | n/a | 500 / 583 | 604 |
| adaptive | 2138.4 | 49.0 | 200 | 4.0 MiB | 104 / 127 | 232 |
| wbmaxx32 | 1963.7 | 53.4 | 13 | 32.0 MiB | 90 / 461 | 507 |
| wb512x8 | 2175.3 | 48.2 | 200 | 4.0 MiB | 107 / 119 | 220 |
| auto | 2115.5 | 49.6 | 200 | 4.0 MiB | 102 / 130 | n/a |

### Uplink +200 ms, load: none, file 1.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 871.9 | 1.2 | 1 | n/a | 208 / 212 | n/a |
| adaptive | 882.6 | 1.2 | 2 | 1.0 MiB | 212 / 236 | n/a |
| wbmaxx32 | 872.6 | 1.2 | 1 | 1.0 MiB | 210 / 219 | n/a |
| wb512x8 | 863.7 | 1.2 | 2 | 1.0 MiB | 211 / 214 | n/a |
| wb512x16 | 846.8 | 1.2 | 2 | 1.0 MiB | 206 / 207 | n/a |
| compound | 234.8 | 4.5 | 1 | 1.0 MiB | 214 / 214 | n/a |
| auto | 221.4 | 4.7 | 1 | 1.0 MiB | 208 / 208 | n/a |

### Uplink +200 ms, load: none, file 8.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 1283.9 | 6.5 | 1 | n/a | 210 / 607 | 630 |
| adaptive | 1289.7 | 6.5 | 16 | 4.0 MiB | 207 / 403 | 633 |
| wbmaxx32 | 1267.5 | 6.6 | 1 | 8.0 MiB | 225 / 598 | 644 |
| wb512x8 | 1287.5 | 6.5 | 16 | 4.0 MiB | 208 / 399 | 639 |
| wb512x16 | 1310.1 | 6.4 | 16 | 8.0 MiB | 220 / 604 | 631 |
| compound | 679.4 | 12.3 | 1 | 8.0 MiB | 217 / 422 | n/a |
| auto | 1281.8 | 6.5 | 16 | 4.0 MiB | 211 / 392 | n/a |

### Uplink +200 ms, load: none, file 100.0 MiB (median of 3)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 6321.2 | 16.6 | 13 | n/a | 213 / 1847 | 2093 |
| adaptive | 6553.5 | 16.0 | 200 | 4.0 MiB | 244 / 416 | 650 |
| wbmaxx32 | 6238.3 | 16.8 | 13 | 32.0 MiB | 1008 / 1244 | 1483 |
| wb512x8 | 6553.3 | 16.0 | 200 | 4.0 MiB | 371 / 419 | 689 |
| wb512x16 | 6377.1 | 16.4 | 200 | 8.0 MiB | 582 / 612 | 849 |
| auto | 6551.8 | 16.0 | 200 | 4.0 MiB | 385 / 418 | n/a |

## Slow links

### Uplink +20@24mbit ms, load: none, file 1.0 MiB (median of 2)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 493.8 | 2.1 | 1 | n/a | 28 / 385 | n/a |
| adaptive | 486.3 | 2.2 | 2 | 1.0 MiB | 37 / 368 | n/a |
| wbmaxx32 | 489.2 | 2.1 | 1 | 1.0 MiB | 30 / 373 | n/a |
| wb512x8 | 476.4 | 2.2 | 2 | 1.0 MiB | 26 / 371 | n/a |
| compound | 414.5 | 2.5 | 1 | 1.0 MiB | 395 / 395 | n/a |
| auto | 475.7 | 2.2 | 2 | 1.0 MiB | 31 / 371 | n/a |

### Uplink +20@24mbit ms, load: none, file 8.0 MiB (median of 2)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 3078.7 | 2.7 | 1 | n/a | 51 / 2929 | 815 |
| adaptive | 3056.1 | 2.7 | 16 | 1.5 MiB | 343 / 370 | 530 |
| wbmaxx32 | 3055.1 | 2.8 | 1 | 8.0 MiB | 37 / 2925 | 815 |
| wb512x8 | 3056.6 | 2.7 | 16 | 4.0 MiB | 31 / 1468 | 817 |
| compound | 2999.9 | 2.8 | 1 | 8.0 MiB | 38 / 2915 | n/a |
| auto | 3070.2 | 2.7 | 16 | 1.5 MiB | 344 / 371 | n/a |

### Uplink +60@3mbit ms, load: none, file 1.0 MiB (median of 2)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 3234.7 | 0.3 | 1 | n/a | 80 / 2982 | n/a |
| adaptive | 3279.2 | 0.3 | 2 | 768 KiB | 77 / 1528 | n/a |
| wbmaxx32 | 3219.3 | 0.3 | 1 | 1.0 MiB | 74 / 2970 | n/a |
| wb512x8 | 3200.5 | 0.3 | 2 | 1.0 MiB | 75 / 2969 | n/a |
| compound | 3008.6 | 0.3 | 1 | 1.0 MiB | 2900 / 2900 | n/a |
| auto | 3237.0 | 0.3 | 2 | 1.0 MiB | 80 / 1506 | n/a |

### Uplink +60@3mbit ms, load: none, file 8.0 MiB (median of 2)

| variant | wall ms | MB/s | WRITEs | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|
| 0.24.4 | 23708.3 | 0.3 | 1 | n/a | 75 / 23443 | 6067 |
| adaptive | 23786.9 | 0.3 | 16 | 1.0 MiB | 1442 / 1508 | 2023 |
| wbmaxx32 | 23714.4 | 0.3 | 1 | 8.0 MiB | 71 / 21985 | 6061 |
| wb512x8 | 23721.0 | 0.3 | 16 | 4.0 MiB | 77 / 11752 | 6057 |
| compound | 23531.8 | 0.4 | 1 | 8.0 MiB | 69 / 23403 | n/a |
| auto | 23809.3 | 0.3 | 16 | 1.0 MiB | 1442 / 1507 | n/a |
