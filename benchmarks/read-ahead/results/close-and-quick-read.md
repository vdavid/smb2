# Eager CLOSE and `quick_read_limit`, 2026-09-23

smb2 0.24.1 (`e816864`, the last chunk waits for the CLOSE's answer) against 0.24.2 (the CLOSE goes out as the last
chunk lands, and `auto` picks compound or stream by `Connection::quick_read_limit`). Same rig as `adaptive.md`: M1 Max,
OrbStack, Samba on Alpine 3.21 capped at two CPUs, `tc netem` delay on the container's egress, no bandwidth cap, no
background writers, warm connection (every variant runs on the connection the previous ones used). Medians of five runs.
The box was also running other agents' fixtures, so treat single-digit-ms differences as noise.

Command: `SIZES=1048576,4194304,8388608 VARIANTS=compound,adaptive,auto LOADS=0 ./run.sh OUT.csv 5 "60 200"` (0.24.1
without `auto`, which needs the new API).

- `wall ms` runs from CREATE to the CLOSE's answer (the `None` from `next_chunk`); `last chunk ms` from CREATE to the
  last chunk in hand, which is when a consumer has every byte.
- On 0.24.1 the two are equal: the last chunk waited for the CLOSE. On 0.24.2 the last chunk lands one round trip
  earlier (+60 ms: 64–68 ms; +200 ms: 202–210 ms), and `wall` is unchanged.
- Streamed against compound, the last chunk is now one round trip behind (CREATE is its own), where it was two.
- `auto` compounds whatever fits `quick_read_limit`: 1 MiB on both links and 4 MiB at +60 ms. It streams 8 MiB at
  +60 ms and 4–8 MiB at +200 ms, because the rate hint reads lower than the link: a download's rate is measured from
  its first dispatch, so a short download's first round trip counts as transfer time. It errs toward streaming.

## 0.24.1


### Link +60 ms, load: none, file 1 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 80.8 | 80.8 | 13.0 | 1 | 80.8 | 80.8 | 1 MiB | 81 / 81 | n/a |
| adaptive | 214.1 | 214.1 | 4.9 | 2 | 143.6 | 143.6 | 1 MiB | 69 / 72 | n/a |

### Link +60 ms, load: none, file 4 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 152.8 | 152.8 | 27.4 | 1 | 152.8 | 152.8 | 4 MiB | 153 / 153 | n/a |
| adaptive | 273.6 | 273.6 | 15.3 | 8 | 141.7 | 141.7 | 4 MiB | 72 / 109 | n/a |

### Link +60 ms, load: none, file 8 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 222.9 | 222.9 | 37.6 | 1 | 222.9 | 222.9 | 8 MiB | 222 / 222 | n/a |
| adaptive | 345.6 | 345.6 | 24.3 | 16 | 145.5 | 145.5 | 4 MiB | 68 / 113 | 70 |

### Link +200 ms, load: none, file 1 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 219.8 | 219.8 | 4.8 | 1 | 219.8 | 219.8 | 1 MiB | 220 / 220 | n/a |
| adaptive | 637.9 | 637.9 | 1.6 | 2 | 422.2 | 422.2 | 1 MiB | 207 / 214 | n/a |

### Link +200 ms, load: none, file 4 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 219.3 | 219.3 | 19.1 | 1 | 219.3 | 219.3 | 4 MiB | 407 / 407 | n/a |
| adaptive | 834.2 | 834.2 | 5.0 | 8 | 418.2 | 418.2 | 4 MiB | 211 / 213 | n/a |

### Link +200 ms, load: none, file 8 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 641.0 | 641.0 | 13.1 | 1 | 641.0 | 641.0 | 8 MiB | 640 / 640 | n/a |
| adaptive | 1050.1 | 1050.1 | 8.0 | 16 | 420.5 | 420.5 | 4 MiB | 212 / 395 | 211 |

## 0.24.2

### Link +60 ms, load: none, file 1 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 75.1 | 75.1 | 14.0 | 1 | 75.1 | 75.1 | 1 MiB | 75 / 75 | n/a |
| adaptive | 209.8 | 143.8 | 5.0 | 2 | 135.8 | 135.8 | 1 MiB | 71 / 71 | n/a |
| auto | 71.3 | 71.3 | 14.7 | 1 | 71.3 | 71.3 | 1 MiB | 71 / 71 | n/a |

### Link +60 ms, load: none, file 4 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 137.3 | 137.3 | 30.6 | 1 | 137.3 | 137.3 | 4 MiB | 135 / 135 | n/a |
| adaptive | 268.1 | 203.3 | 15.7 | 8 | 142.5 | 142.5 | 4 MiB | 75 / 107 | n/a |
| auto | 138.8 | 138.8 | 30.2 | 1 | 138.8 | 138.8 | 4 MiB | 138 / 138 | n/a |

### Link +60 ms, load: none, file 8 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 213.6 | 213.6 | 39.3 | 1 | 213.6 | 213.6 | 8 MiB | 214 / 214 | n/a |
| adaptive | 348.8 | 280.8 | 24.1 | 16 | 135.9 | 135.9 | 4 MiB | 71 / 106 | 76 |
| auto | 345.9 | 277.6 | 24.2 | 16 | 134.2 | 134.2 | 4 MiB | 70 / 115 | n/a |

### Link +200 ms, load: none, file 1 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 218.2 | 218.2 | 4.8 | 1 | 218.2 | 218.2 | 1 MiB | 218 / 218 | n/a |
| adaptive | 631.3 | 421.8 | 1.7 | 2 | 418.6 | 418.6 | 1 MiB | 207 / 211 | n/a |
| auto | 211.6 | 211.6 | 5.0 | 1 | 211.6 | 211.6 | 1 MiB | 211 / 211 | n/a |

### Link +200 ms, load: none, file 4 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 427.2 | 427.2 | 9.8 | 1 | 427.2 | 427.2 | 4 MiB | 427 / 427 | n/a |
| adaptive | 831.6 | 629.2 | 5.0 | 8 | 427.4 | 427.4 | 4 MiB | 208 / 213 | n/a |
| auto | 829.4 | 619.1 | 5.1 | 8 | 422.1 | 422.1 | 4 MiB | 210 / 391 | n/a |

### Link +200 ms, load: none, file 8 MiB (median of 5)

| variant | wall ms | last chunk ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| compound | 642.5 | 642.5 | 13.1 | 1 | 642.5 | 642.5 | 8 MiB | 642 / 642 | n/a |
| adaptive | 1057.2 | 853.8 | 7.9 | 16 | 424.3 | 424.3 | 4 MiB | 216 / 396 | 214 |
| auto | 1055.4 | 847.1 | 8.0 | 16 | 422.9 | 422.9 | 4 MiB | 213 / 398 | n/a |
