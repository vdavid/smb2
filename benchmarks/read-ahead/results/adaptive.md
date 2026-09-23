# Adaptive read-ahead against the fixed windows (2026-09-23)

The same rig as `main.md` and `slow.md` (M1 Max, OrbStack, Samba on Alpine 3.21, container capped at two CPUs, no
background load), rerun with `adaptive`: 512 KiB chunks and `ReadAhead::Adaptive`, what `Tree::download` does from
0.24.0. `baseline` is the pre-0.24 default (sequential, chunk = `MaxReadSize` = 8 MiB).

Every variant runs on the connection the previous ones used, so `adaptive` starts from the rate the last download
measured, as a folder copy would. A download with no recent rate on its connection (the first one) sends one READ and
opens the window once that answers: an earlier run of the same matrix without that hint measured +60 ms at 269 ms for
1 MiB (one extra round trip), 420 ms for 8 MiB, and 2,071 ms for 100 MiB.

Commands:

- `VARIANTS=baseline,seq512,ra512x4,ra512x8,ra512x16,adaptive SIZES=1048576,8388608,104857600 LOADS=0 ./run.sh fast.csv 3 "5 60"`
- `VARIANTS=baseline,seq512,ra512x4,ra512x8,adaptive SIZES=1048576,8388608 LOADS=0 ./run.sh slow375.csv 2 "60@3mbit"`
- `VARIANTS=baseline,seq512,ra512x4,ra512x8,adaptive SIZES=1048576,8388608 LOADS=0 ./run.sh slow3m.csv 3 "20@24mbit"`

## Fast links

### Link +5 ms, load: none, file 1 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 33.6 | 31.2 | 1 | 33.6 | 33.6 | 1 MiB | 12 / 12 | n/a |
| seq512 | 32.2 | 32.6 | 2 | 16.4 | 16.4 | 512 KiB | 8 / 8 | n/a |
| ra512x4 | 31.0 | 33.8 | 2 | 23.1 | 23.1 | 1 MiB | 11 / 11 | n/a |
| ra512x8 | 26.2 | 40.0 | 2 | 19.0 | 19.0 | 1 MiB | 7 / 7 | n/a |
| ra512x16 | 22.5 | 46.5 | 2 | 15.2 | 15.2 | 1 MiB | 7 / 7 | n/a |
| adaptive | 26.4 | 39.7 | 2 | 17.5 | 17.5 | 1 MiB | 7 / 7 | n/a |

### Link +5 ms, load: none, file 8 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 49.4 | 169.7 | 1 | 49.4 | 49.4 | 8 MiB | 11 / 12 | 7 |
| seq512 | 174.4 | 48.1 | 16 | 15.1 | 22.8 | 512 KiB | 11 / 16 | 9 |
| ra512x4 | 66.6 | 125.9 | 16 | 25.3 | 25.3 | 2 MiB | 8 / 10 | 9 |
| ra512x8 | 52.4 | 160.2 | 16 | 23.1 | 23.1 | 4 MiB | 9 / 9 | 9 |
| ra512x16 | 49.3 | 170.2 | 16 | 23.9 | 23.9 | 8 MiB | 13 / 13 | 14 |
| adaptive | 53.6 | 156.6 | 16 | 25.1 | 25.1 | 4 MiB | 13 / 13 | 10 |

### Link +5 ms, load: none, file 100 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 398.1 | 263.4 | 13 | 59.7 | 59.7 | 8 MiB | 10 / 26 | 8 |
| seq512 | 1816.3 | 57.7 | 200 | 16.2 | 30.6 | 512 KiB | 9 / 21 | 11 |
| ra512x4 | 584.7 | 179.3 | 200 | 35.3 | 35.3 | 2 MiB | 10 / 17 | 9 |
| ra512x8 | 257.4 | 407.4 | 200 | 21.1 | 21.6 | 4 MiB | 8 / 13 | 10 |
| ra512x16 | 209.7 | 500.2 | 200 | 22.2 | 22.2 | 8 MiB | 12 / 15 | 12 |
| adaptive | 256.3 | 409.2 | 200 | 25.8 | 25.8 | 4 MiB | 8 / 13 | 8 |

### Link +60 ms, load: none, file 1 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 195.2 | 5.4 | 1 | 195.2 | 195.2 | 1 MiB | 65 / 68 | n/a |
| seq512 | 260.7 | 4.0 | 2 | 132.6 | 132.6 | 512 KiB | 66 / 66 | n/a |
| ra512x4 | 197.7 | 5.3 | 2 | 132.8 | 132.8 | 1 MiB | 67 / 68 | n/a |
| ra512x8 | 199.5 | 5.3 | 2 | 136.0 | 136.0 | 1 MiB | 68 / 70 | n/a |
| ra512x16 | 199.8 | 5.2 | 2 | 132.9 | 132.9 | 1 MiB | 66 / 67 | n/a |
| adaptive | 191.1 | 5.5 | 2 | 128.7 | 128.7 | 1 MiB | 66 / 67 | n/a |

### Link +60 ms, load: none, file 8 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 327.5 | 25.6 | 1 | 327.5 | 327.5 | 8 MiB | 67 / 180 | 65 |
| seq512 | 1183.9 | 7.1 | 16 | 132.6 | 132.6 | 512 KiB | 66 / 72 | 66 |
| ra512x4 | 521.2 | 16.1 | 16 | 191.5 | 191.5 | 2 MiB | 67 / 166 | 65 |
| ra512x8 | 391.3 | 21.4 | 16 | 138.2 | 138.2 | 4 MiB | 68 / 171 | 68 |
| ra512x16 | 329.1 | 25.5 | 16 | 133.3 | 133.3 | 8 MiB | 67 / 174 | 124 |
| adaptive | 338.0 | 24.8 | 16 | 137.7 | 137.7 | 4 MiB | 67 / 118 | 70 |

### Link +60 ms, load: none, file 100 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 2740.6 | 38.3 | 13 | 288.9 | 288.9 | 8 MiB | 180 / 195 | 70 |
| seq512 | 13430.5 | 7.8 | 200 | 135.7 | 135.7 | 512 KiB | 66 / 87 | 69 |
| ra512x4 | 3707.5 | 28.3 | 200 | 138.4 | 138.4 | 2 MiB | 66 / 116 | 68 |
| ra512x8 | 2080.4 | 50.4 | 200 | 137.3 | 137.3 | 4 MiB | 71 / 176 | 66 |
| ra512x16 | 1907.0 | 55.0 | 200 | 139.6 | 139.6 | 8 MiB | 116 / 189 | 129 |
| adaptive | 2012.0 | 52.1 | 200 | 142.8 | 142.8 | 4 MiB | 107 / 118 | 69 |

## 375 KB/s (60 ms @ 3 Mbit)

### Link +60@3mbit ms, load: none, file 1 MiB (median of 2)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 3141.9 | 0.3 | 1 | 3141.9 | 3141.9 | 1 MiB | 73 / 2981 | n/a |
| seq512 | 3181.1 | 0.3 | 2 | 1590.6 | 1591.2 | 512 KiB | 1504 / 1504 | n/a |
| ra512x4 | 3120.6 | 0.3 | 2 | 1594.4 | 1594.4 | 1 MiB | 69 / 2968 | n/a |
| ra512x8 | 3126.1 | 0.3 | 2 | 1596.3 | 1596.3 | 1 MiB | 67 / 2970 | n/a |
| adaptive | 3128.7 | 0.3 | 2 | 1592.3 | 1592.3 | 1 MiB | 1445 / 1505 | n/a |

### Link +60@3mbit ms, load: none, file 8 MiB (median of 2)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 23604.1 | 0.4 | 1 | 23604.1 | 23604.1 | 8 MiB | 71 / 23450 | 67 |
| seq512 | 24552.7 | 0.3 | 16 | 1595.7 | 1595.7 | 512 KiB | 1504 / 1506 | 798 |
| ra512x4 | 24080.3 | 0.3 | 16 | 3507.7 | 3507.7 | 2 MiB | 5831 / 5897 | 2925 |
| ra512x8 | 25954.9 | 0.3 | 16 | 5417.1 | 5417.1 | 4 MiB | 11674 / 11747 | 5848 |
| adaptive | 23676.5 | 0.3 | 16 | 1592.6 | 1592.6 | 1 MiB | 1442 / 1504 | 1464 |

## 3 MB/s (20 ms @ 24 Mbit)

### Link +20@24mbit ms, load: none, file 1 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 438.6 | 2.4 | 1 | 438.6 | 438.6 | 1 MiB | 29 / 368 | n/a |
| seq512 | 465.0 | 2.2 | 2 | 236.4 | 236.4 | 512 KiB | 185 / 186 | n/a |
| ra512x4 | 438.7 | 2.4 | 2 | 230.3 | 230.3 | 1 MiB | 32 / 367 | n/a |
| ra512x8 | 433.2 | 2.4 | 2 | 229.0 | 229.0 | 1 MiB | 28 / 368 | n/a |
| adaptive | 438.6 | 2.4 | 2 | 235.0 | 235.0 | 1 MiB | 27 / 366 | n/a |

### Link +20@24mbit ms, load: none, file 8 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 3017.2 | 2.8 | 1 | 3017.2 | 3017.2 | 8 MiB | 27 / 2943 | 26 |
| seq512 | 3343.0 | 2.5 | 16 | 235.0 | 235.0 | 512 KiB | 184 / 190 | 27 |
| ra512x4 | 3001.0 | 2.8 | 16 | 233.2 | 233.2 | 2 MiB | 709 / 734 | 730 |
| ra512x8 | 2995.3 | 2.8 | 16 | 237.5 | 548.7 | 4 MiB | 1441 / 1469 | 1458 |
| adaptive | 3001.3 | 2.8 | 16 | 233.5 | 233.5 | 1 MiB | 344 / 367 | 365 |
