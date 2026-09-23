
#### Link +20@24mbit ms, load: none, file 1 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 451.7 | 2.3 | 1 | 451.7 | 451.7 | 1 MiB | 34 / 375 | n/a |
| seq512 | 464.6 | 2.3 | 2 | 234.1 | 234.1 | 512 KiB | 185 / 185 | n/a |
| ra512x4 | 446.0 | 2.4 | 2 | 239.5 | 239.5 | 1 MiB | 31 / 369 | n/a |
| ra512x8 | 445.4 | 2.4 | 2 | 251.9 | 251.9 | 1 MiB | 31 / 370 | n/a |
| ra512x16 | 446.8 | 2.4 | 2 | 235.3 | 235.3 | 1 MiB | 32 / 369 | n/a |
| ra256x16 | 443.0 | 2.4 | 4 | 145.1 | 145.1 | 1 MiB | 32 / 368 | n/a |

#### Link +20@24mbit ms, load: none, file 8 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 3023.1 | 2.8 | 1 | 3023.1 | 3023.1 | 8 MiB | 31 / 2945 | 33 |
| seq512 | 3371.3 | 2.5 | 16 | 237.5 | 237.5 | 512 KiB | 185 / 192 | 31 |
| ra512x4 | 3005.4 | 2.8 | 16 | 239.5 | 243.6 | 2 MiB | 710 / 734 | 550 |
| ra512x8 | 3002.3 | 2.8 | 16 | 247.6 | 600.4 | 4 MiB | 1442 / 1467 | 1461 |
| ra512x16 | 3007.0 | 2.8 | 16 | 243.6 | 732.3 | 8 MiB | 31 / 2930 | 2010 |
| ra256x16 | 3009.3 | 2.8 | 32 | 148.4 | 367.8 | 4 MiB | 1441 / 1467 | 1367 |

#### Link +20@24mbit ms, load: 2 writers, file 1 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 443.2 | 2.4 | 1 | 443.2 | 443.2 | 1 MiB | 26 / 368 | n/a |
| seq512 | 487.2 | 2.1 | 2 | 236.8 | 248.4 | 512 KiB | 186 / 193 | n/a |
| ra512x4 | 437.4 | 2.4 | 2 | 229.9 | 229.9 | 1 MiB | 27 / 368 | n/a |
| ra512x8 | 450.0 | 2.3 | 2 | 232.2 | 232.2 | 1 MiB | 24 / 372 | n/a |
| ra512x16 | 451.8 | 2.3 | 2 | 233.1 | 233.1 | 1 MiB | 27 / 375 | n/a |
| ra256x16 | 449.6 | 2.3 | 4 | 138.2 | 138.2 | 1 MiB | 27 / 368 | n/a |

#### Link +20@24mbit ms, load: 2 writers, file 8 MiB (median of 3)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 3005.1 | 2.8 | 1 | 3005.1 | 3005.1 | 8 MiB | 24 / 2935 | 24 |
| seq512 | 3498.1 | 2.4 | 16 | 239.4 | 242.8 | 512 KiB | 190 / 204 | 27 |
| ra512x4 | 3017.5 | 2.8 | 16 | 232.8 | 232.8 | 2 MiB | 711 / 733 | 720 |
| ra512x8 | 3016.4 | 2.8 | 16 | 410.7 | 410.7 | 4 MiB | 1458 / 1464 | 1281 |
| ra512x16 | 3000.7 | 2.8 | 16 | 231.1 | 910.5 | 8 MiB | 29 / 2934 | 2011 |
| ra256x16 | 3009.2 | 2.8 | 32 | 139.8 | 182.5 | 4 MiB | 1446 / 1465 | 1481 |

#### Link +60@3mbit ms, load: none, file 1 MiB (median of 2)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 3166.9 | 0.3 | 1 | 3166.9 | 3166.9 | 1 MiB | 80 / 3002 | n/a |
| seq512 | 3204.8 | 0.3 | 2 | 1595.4 | 1609.3 | 512 KiB | 1505 / 1507 | n/a |
| ra512x4 | 3126.0 | 0.3 | 2 | 2327.8 | 2327.8 | 1 MiB | 68 / 2967 | n/a |
| ra512x8 | 3133.6 | 0.3 | 2 | 2335.6 | 2335.6 | 1 MiB | 78 / 2967 | n/a |
| ra512x16 | 3130.7 | 0.3 | 2 | 2330.1 | 2330.1 | 1 MiB | 72 / 2966 | n/a |
| ra256x16 | 3129.5 | 0.3 | 4 | 870.5 | 870.5 | 1 MiB | 73 / 2968 | n/a |

#### Link +60@3mbit ms, load: none, file 8 MiB (median of 2)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 23622.3 | 0.4 | 1 | 23622.3 | 23622.3 | 8 MiB | 73 / 23455 | 84 |
| seq512 | 24603.5 | 0.3 | 16 | 1601.2 | 1601.2 | 512 KiB | 1505 / 1519 | 75 |
| ra512x4 | 23612.2 | 0.4 | 16 | 1604.2 | 2923.6 | 2 MiB | 5830 / 5894 | 5850 |
| ra512x8 | 23603.7 | 0.4 | 16 | 2332.9 | 3729.9 | 4 MiB | 11677 / 11744 | 10965 |
| ra512x16 | 23598.6 | 0.4 | 16 | 1593.0 | 3658.6 | 8 MiB | 73 / 23439 | 15354 |
| ra256x16 | 23615.9 | 0.4 | 32 | 3795.3 | 5921.8 | 4 MiB | 11679 / 11753 | 9139 |

#### Link +60@3mbit ms, load: 2 writers, file 1 MiB (median of 2)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 3236.3 | 0.3 | 1 | 3236.2 | 3236.2 | 1 MiB | 71 / 3073 | n/a |
| seq512 | 3235.2 | 0.3 | 2 | 1620.3 | 1620.3 | 512 KiB | 1517 / 1524 | n/a |
| ra512x4 | 3158.6 | 0.3 | 2 | 2358.1 | 2358.1 | 1 MiB | 69 / 3001 | n/a |
| ra512x8 | 3150.4 | 0.3 | 2 | 1607.3 | 1607.3 | 1 MiB | 73 / 2987 | n/a |
| ra512x16 | 3132.7 | 0.3 | 2 | 1591.3 | 1591.3 | 1 MiB | 67 / 2971 | n/a |
| ra256x16 | 3126.9 | 0.3 | 4 | 1962.7 | 1962.7 | 1 MiB | 72 / 2969 | n/a |

#### Link +60@3mbit ms, load: 2 writers, file 8 MiB (median of 2)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 23638.7 | 0.3 | 1 | 23638.7 | 23638.7 | 8 MiB | 66 / 23479 | 68 |
| seq512 | 24723.4 | 0.3 | 16 | 1605.2 | 1612.8 | 512 KiB | 1512 / 1529 | 77 |
| ra512x4 | 23643.5 | 0.3 | 16 | 1599.9 | 2265.8 | 2 MiB | 5838 / 5901 | 5856 |
| ra512x8 | 23624.1 | 0.4 | 16 | 1595.7 | 3725.9 | 4 MiB | 11694 / 11756 | 10975 |
| ra512x16 | 24094.6 | 0.3 | 16 | 2057.0 | 2935.2 | 8 MiB | 533 / 23474 | 14633 |
| ra256x16 | 23629.2 | 0.4 | 32 | 864.5 | 4751.5 | 4 MiB | 11686 / 11756 | 9889 |
