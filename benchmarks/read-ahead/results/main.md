
#### Link +0 ms, load: none, file 64 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 5.5 | 12.0 | 1 | 5.5 | 5.5 | 64 KiB | 4 / 4 | n/a |
| seq512 | 4.1 | 15.9 | 1 | 4.1 | 4.1 | 64 KiB | 3 / 3 | n/a |
| ra512x4 | 6.3 | 10.3 | 1 | 6.3 | 6.3 | 64 KiB | 4 / 4 | n/a |
| ra512x8 | 7.8 | 8.3 | 1 | 7.8 | 7.8 | 64 KiB | 3 / 3 | n/a |
| ra512x16 | 9.3 | 7.0 | 1 | 9.3 | 9.3 | 64 KiB | 6 / 6 | n/a |
| ra512x32 | 6.9 | 9.5 | 1 | 6.9 | 6.9 | 64 KiB | 5 / 5 | n/a |

#### Link +0 ms, load: none, file 377 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 11.5 | 33.7 | 1 | 11.5 | 11.5 | 377 KiB | 6 / 6 | n/a |
| seq512 | 4.9 | 79.0 | 1 | 4.9 | 4.9 | 377 KiB | 3 / 3 | n/a |
| ra512x4 | 6.4 | 60.1 | 1 | 6.4 | 6.4 | 377 KiB | 2 / 2 | n/a |
| ra512x8 | 4.9 | 79.2 | 1 | 4.9 | 4.9 | 377 KiB | 2 / 2 | n/a |
| ra512x16 | 5.3 | 72.4 | 1 | 5.3 | 5.3 | 377 KiB | 3 / 3 | n/a |
| ra512x32 | 4.3 | 90.6 | 1 | 4.3 | 4.3 | 377 KiB | 3 / 3 | n/a |

#### Link +0 ms, load: none, file 1 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 6.2 | 168.0 | 1 | 6.2 | 6.2 | 1 MiB | 2 / 2 | n/a |
| seq512 | 6.6 | 159.2 | 2 | 4.0 | 4.0 | 512 KiB | 2 / 2 | n/a |
| ra512x4 | 7.0 | 149.3 | 2 | 5.6 | 5.6 | 1 MiB | 3 / 3 | n/a |
| ra512x8 | 8.7 | 120.3 | 2 | 7.3 | 7.3 | 1 MiB | 3 / 3 | n/a |
| ra512x16 | 10.7 | 98.1 | 2 | 6.7 | 6.7 | 1 MiB | 5 / 5 | n/a |
| ra512x32 | 10.9 | 96.4 | 2 | 9.8 | 9.8 | 1 MiB | 5 / 5 | n/a |

#### Link +0 ms, load: none, file 8 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 22.0 | 381.3 | 1 | 22.0 | 22.0 | 8 MiB | 3 / 3 | 1 |
| seq512 | 36.9 | 227.4 | 16 | 9.1 | 9.1 | 512 KiB | 5 / 5 | 1 |
| ra512x4 | 33.9 | 247.7 | 16 | 15.9 | 15.9 | 2 MiB | 8 / 8 | 3 |
| ra512x8 | 25.1 | 333.7 | 16 | 11.8 | 11.8 | 4 MiB | 4 / 4 | 5 |
| ra512x16 | 27.6 | 303.4 | 16 | 12.4 | 14.3 | 8 MiB | 6 / 6 | 2 |
| ra512x32 | 25.8 | 324.8 | 16 | 13.0 | 13.0 | 8 MiB | 6 / 6 | 4 |

#### Link +0 ms, load: none, file 100 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 154.0 | 680.9 | 13 | 23.8 | 23.8 | 8 MiB | 5 / 8 | 1 |
| seq512 | 252.4 | 415.5 | 200 | 9.2 | 9.2 | 512 KiB | 1 / 6 | 1 |
| ra512x4 | 100.2 | 1046.7 | 200 | 8.2 | 8.2 | 2 MiB | 2 / 4 | 1 |
| ra512x8 | 86.8 | 1208.2 | 200 | 9.5 | 9.5 | 4 MiB | 4 / 5 | 2 |
| ra512x16 | 79.1 | 1324.9 | 200 | 17.4 | 17.4 | 8 MiB | 6 / 8 | 2 |
| ra512x32 | 71.8 | 1460.6 | 200 | 11.7 | 11.7 | 16 MiB | 6 / 10 | 6 |

#### Link +0 ms, load: 2 writers, file 64 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 7.3 | 8.9 | 1 | 7.3 | 7.3 | 64 KiB | 3 / 3 | n/a |
| seq512 | 3.2 | 20.5 | 1 | 3.2 | 3.2 | 64 KiB | 1 / 1 | n/a |
| ra512x4 | 2.4 | 27.9 | 1 | 2.4 | 2.4 | 64 KiB | 1 / 1 | n/a |
| ra512x8 | 2.3 | 29.0 | 1 | 2.3 | 2.3 | 64 KiB | 1 / 1 | n/a |
| ra512x16 | 7.8 | 8.4 | 1 | 7.8 | 7.8 | 64 KiB | 3 / 3 | n/a |
| ra512x32 | 1.8 | 37.4 | 1 | 1.8 | 1.8 | 64 KiB | 1 / 1 | n/a |

#### Link +0 ms, load: 2 writers, file 377 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 11.2 | 34.6 | 1 | 11.2 | 11.2 | 377 KiB | 2 / 2 | n/a |
| seq512 | 2.3 | 169.1 | 1 | 2.3 | 2.3 | 377 KiB | 1 / 1 | n/a |
| ra512x4 | 4.3 | 89.1 | 1 | 4.3 | 4.3 | 377 KiB | 1 / 1 | n/a |
| ra512x8 | 4.0 | 97.7 | 1 | 4.0 | 4.0 | 377 KiB | 1 / 1 | n/a |
| ra512x16 | 2.0 | 192.4 | 1 | 2.0 | 2.0 | 377 KiB | 1 / 1 | n/a |
| ra512x32 | 2.9 | 135.1 | 1 | 2.9 | 2.9 | 377 KiB | 1 / 1 | n/a |

#### Link +0 ms, load: 2 writers, file 1 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 7.8 | 133.6 | 1 | 7.8 | 7.8 | 1 MiB | 3 / 3 | n/a |
| seq512 | 4.3 | 242.7 | 2 | 2.8 | 2.8 | 512 KiB | 1 / 1 | n/a |
| ra512x4 | 5.7 | 182.5 | 2 | 4.8 | 4.8 | 1 MiB | 3 / 3 | n/a |
| ra512x8 | 2.1 | 497.9 | 2 | 1.7 | 1.7 | 1 MiB | 1 / 1 | n/a |
| ra512x16 | 2.4 | 446.6 | 2 | 2.1 | 2.1 | 1 MiB | 1 / 1 | n/a |
| ra512x32 | 9.9 | 106.4 | 2 | 6.9 | 6.9 | 1 MiB | 3 / 3 | n/a |

#### Link +0 ms, load: 2 writers, file 8 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 14.5 | 580.0 | 1 | 14.5 | 14.5 | 8 MiB | 3 / 3 | 1 |
| seq512 | 35.7 | 234.9 | 16 | 6.4 | 6.4 | 512 KiB | 3 / 3 | 1 |
| ra512x4 | 6.7 | 1248.8 | 16 | 2.4 | 2.4 | 2 MiB | 1 / 1 | 2 |
| ra512x8 | 8.8 | 948.7 | 16 | 3.2 | 3.2 | 4 MiB | 2 / 2 | 2 |
| ra512x16 | 6.9 | 1214.3 | 16 | 2.7 | 2.7 | 8 MiB | 1 / 1 | 2 |
| ra512x32 | 7.0 | 1201.3 | 16 | 2.1 | 2.1 | 8 MiB | 1 / 1 | 2 |

#### Link +0 ms, load: 2 writers, file 100 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 112.8 | 929.8 | 13 | 15.2 | 18.6 | 8 MiB | 3 / 8 | 1 |
| seq512 | 249.1 | 421.0 | 200 | 1.7 | 11.5 | 512 KiB | 1 / 5 | 1 |
| ra512x4 | 91.4 | 1146.7 | 200 | 2.6 | 10.3 | 2 MiB | 2 / 4 | 1 |
| ra512x8 | 69.5 | 1508.7 | 200 | 4.2 | 6.0 | 4 MiB | 2 / 4 | 1 |
| ra512x16 | 63.6 | 1648.4 | 200 | 5.1 | 8.5 | 8 MiB | 3 / 8 | 2 |
| ra512x32 | 56.2 | 1867.1 | 200 | 2.8 | 6.3 | 16 MiB | 6 / 14 | 6 |

#### Link +5 ms, load: none, file 64 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 26.6 | 2.5 | 1 | 26.6 | 26.6 | 64 KiB | 11 / 11 | n/a |
| seq512 | 24.6 | 2.7 | 1 | 24.6 | 24.6 | 64 KiB | 9 / 9 | n/a |
| ra512x4 | 23.2 | 2.8 | 1 | 23.2 | 23.2 | 64 KiB | 9 / 9 | n/a |
| ra512x8 | 23.3 | 2.8 | 1 | 23.3 | 23.3 | 64 KiB | 9 / 9 | n/a |
| ra512x16 | 23.9 | 2.8 | 1 | 23.9 | 23.9 | 64 KiB | 8 / 8 | n/a |
| ra512x32 | 22.6 | 2.9 | 1 | 22.6 | 22.6 | 64 KiB | 9 / 9 | n/a |

#### Link +5 ms, load: none, file 377 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 23.0 | 16.8 | 1 | 23.0 | 23.0 | 377 KiB | 8 / 8 | n/a |
| seq512 | 23.1 | 16.7 | 1 | 23.1 | 23.1 | 377 KiB | 8 / 8 | n/a |
| ra512x4 | 26.2 | 14.7 | 1 | 26.2 | 26.2 | 377 KiB | 8 / 8 | n/a |
| ra512x8 | 21.5 | 18.0 | 1 | 21.5 | 21.5 | 377 KiB | 7 / 7 | n/a |
| ra512x16 | 25.3 | 15.3 | 1 | 25.3 | 25.3 | 377 KiB | 8 / 8 | n/a |
| ra512x32 | 24.1 | 16.0 | 1 | 24.1 | 24.1 | 377 KiB | 8 / 8 | n/a |

#### Link +5 ms, load: none, file 1 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 24.3 | 43.2 | 1 | 24.3 | 24.3 | 1 MiB | 10 / 10 | n/a |
| seq512 | 34.3 | 30.6 | 2 | 18.0 | 18.0 | 512 KiB | 9 / 9 | n/a |
| ra512x4 | 22.9 | 45.8 | 2 | 15.5 | 15.5 | 1 MiB | 8 / 8 | n/a |
| ra512x8 | 23.5 | 44.7 | 2 | 16.5 | 16.5 | 1 MiB | 8 / 8 | n/a |
| ra512x16 | 22.5 | 46.7 | 2 | 15.2 | 15.2 | 1 MiB | 8 / 8 | n/a |
| ra512x32 | 24.8 | 42.3 | 2 | 17.3 | 17.3 | 1 MiB | 8 / 8 | n/a |

#### Link +5 ms, load: none, file 8 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 47.2 | 177.8 | 1 | 47.2 | 47.2 | 8 MiB | 11 / 11 | 7 |
| seq512 | 156.7 | 53.5 | 16 | 16.1 | 17.3 | 512 KiB | 9 / 12 | 7 |
| ra512x4 | 77.5 | 108.2 | 16 | 24.8 | 24.8 | 2 MiB | 8 / 9 | 10 |
| ra512x8 | 52.1 | 161.1 | 16 | 21.7 | 21.7 | 4 MiB | 12 / 12 | 11 |
| ra512x16 | 48.9 | 171.6 | 16 | 26.5 | 26.5 | 8 MiB | 11 / 11 | 15 |
| ra512x32 | 51.2 | 163.8 | 16 | 25.5 | 25.5 | 8 MiB | 11 / 11 | 11 |

#### Link +5 ms, load: none, file 100 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 396.0 | 264.8 | 13 | 57.0 | 57.0 | 8 MiB | 10 / 26 | 8 |
| seq512 | 1876.4 | 55.9 | 200 | 19.5 | 25.3 | 512 KiB | 9 / 15 | 8 |
| ra512x4 | 514.0 | 204.0 | 200 | 29.5 | 29.5 | 2 MiB | 9 / 13 | 8 |
| ra512x8 | 272.9 | 384.3 | 200 | 24.6 | 24.6 | 4 MiB | 9 / 15 | 9 |
| ra512x16 | 219.7 | 477.2 | 200 | 22.6 | 22.6 | 8 MiB | 12 / 17 | 13 |
| ra512x32 | 214.0 | 489.9 | 200 | 29.1 | 29.1 | 16 MiB | 26 / 30 | 29 |

#### Link +5 ms, load: 2 writers, file 64 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 23.5 | 2.8 | 1 | 23.5 | 23.5 | 64 KiB | 7 / 7 | n/a |
| seq512 | 21.8 | 3.0 | 1 | 21.8 | 21.8 | 64 KiB | 8 / 8 | n/a |
| ra512x4 | 22.2 | 3.0 | 1 | 22.2 | 22.2 | 64 KiB | 7 / 7 | n/a |
| ra512x8 | 23.8 | 2.8 | 1 | 23.8 | 23.8 | 64 KiB | 9 / 9 | n/a |
| ra512x16 | 21.9 | 3.0 | 1 | 21.9 | 21.9 | 64 KiB | 8 / 8 | n/a |
| ra512x32 | 24.4 | 2.7 | 1 | 24.4 | 24.4 | 64 KiB | 9 / 9 | n/a |

#### Link +5 ms, load: 2 writers, file 377 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 22.4 | 17.2 | 1 | 22.4 | 22.4 | 377 KiB | 7 / 7 | n/a |
| seq512 | 23.9 | 16.1 | 1 | 23.9 | 23.9 | 377 KiB | 7 / 7 | n/a |
| ra512x4 | 21.2 | 18.2 | 1 | 21.2 | 21.2 | 377 KiB | 7 / 7 | n/a |
| ra512x8 | 24.4 | 15.8 | 1 | 24.4 | 24.4 | 377 KiB | 8 / 8 | n/a |
| ra512x16 | 21.1 | 18.3 | 1 | 21.1 | 21.1 | 377 KiB | 7 / 7 | n/a |
| ra512x32 | 22.7 | 17.0 | 1 | 22.7 | 22.7 | 377 KiB | 8 / 8 | n/a |

#### Link +5 ms, load: 2 writers, file 1 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 23.6 | 44.5 | 1 | 23.6 | 23.6 | 1 MiB | 8 / 8 | n/a |
| seq512 | 27.3 | 38.4 | 2 | 13.1 | 14.3 | 512 KiB | 7 / 7 | n/a |
| ra512x4 | 23.9 | 43.8 | 2 | 14.4 | 14.4 | 1 MiB | 7 / 7 | n/a |
| ra512x8 | 25.1 | 41.8 | 2 | 16.9 | 16.9 | 1 MiB | 8 / 8 | n/a |
| ra512x16 | 22.4 | 46.8 | 2 | 15.6 | 15.6 | 1 MiB | 7 / 7 | n/a |
| ra512x32 | 21.9 | 48.0 | 2 | 15.6 | 15.6 | 1 MiB | 7 / 7 | n/a |

#### Link +5 ms, load: 2 writers, file 8 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 39.1 | 214.8 | 1 | 39.1 | 39.1 | 8 MiB | 7 / 7 | 7 |
| seq512 | 140.7 | 59.6 | 16 | 14.2 | 15.5 | 512 KiB | 7 / 11 | 7 |
| ra512x4 | 61.6 | 136.1 | 16 | 22.2 | 22.2 | 2 MiB | 8 / 9 | 8 |
| ra512x8 | 45.7 | 183.7 | 16 | 17.2 | 17.2 | 4 MiB | 9 / 9 | 8 |
| ra512x16 | 41.9 | 200.2 | 16 | 16.9 | 16.9 | 8 MiB | 8 / 8 | 11 |
| ra512x32 | 40.0 | 209.9 | 16 | 14.3 | 14.3 | 8 MiB | 8 / 8 | 11 |

#### Link +5 ms, load: 2 writers, file 100 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 306.4 | 342.3 | 13 | 33.8 | 33.8 | 8 MiB | 11 / 19 | 8 |
| seq512 | 1577.2 | 66.5 | 200 | 13.6 | 18.0 | 512 KiB | 7 / 12 | 7 |
| ra512x4 | 452.1 | 231.9 | 200 | 26.0 | 26.0 | 2 MiB | 7 / 13 | 7 |
| ra512x8 | 240.0 | 436.9 | 200 | 16.1 | 16.1 | 4 MiB | 8 / 10 | 9 |
| ra512x16 | 193.4 | 542.1 | 200 | 13.8 | 13.8 | 8 MiB | 12 / 16 | 12 |
| ra512x32 | 189.8 | 552.3 | 200 | 16.9 | 16.9 | 16 MiB | 24 / 30 | 24 |

#### Link +60 ms, load: none, file 64 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 192.8 | 0.3 | 1 | 192.8 | 192.8 | 64 KiB | 64 / 66 | n/a |
| seq512 | 196.4 | 0.3 | 1 | 196.4 | 196.4 | 64 KiB | 66 / 67 | n/a |
| ra512x4 | 194.8 | 0.3 | 1 | 194.8 | 194.8 | 64 KiB | 64 / 67 | n/a |
| ra512x8 | 197.1 | 0.3 | 1 | 197.1 | 197.1 | 64 KiB | 64 / 65 | n/a |
| ra512x16 | 191.7 | 0.3 | 1 | 191.7 | 191.7 | 64 KiB | 64 / 65 | n/a |
| ra512x32 | 190.8 | 0.3 | 1 | 190.8 | 190.8 | 64 KiB | 66 / 67 | n/a |

#### Link +60 ms, load: none, file 377 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 193.0 | 2.0 | 1 | 193.0 | 193.0 | 377 KiB | 65 / 67 | n/a |
| seq512 | 193.7 | 2.0 | 1 | 193.7 | 193.7 | 377 KiB | 66 / 68 | n/a |
| ra512x4 | 194.0 | 2.0 | 1 | 194.0 | 194.0 | 377 KiB | 65 / 66 | n/a |
| ra512x8 | 195.3 | 2.0 | 1 | 195.3 | 195.3 | 377 KiB | 65 / 68 | n/a |
| ra512x16 | 198.4 | 1.9 | 1 | 198.4 | 198.4 | 377 KiB | 66 / 68 | n/a |
| ra512x32 | 194.4 | 2.0 | 1 | 194.4 | 194.4 | 377 KiB | 65 / 65 | n/a |

#### Link +60 ms, load: none, file 1 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 198.2 | 5.3 | 1 | 198.2 | 198.2 | 1 MiB | 65 / 67 | n/a |
| seq512 | 257.1 | 4.1 | 2 | 130.7 | 130.7 | 512 KiB | 65 / 68 | n/a |
| ra512x4 | 199.8 | 5.2 | 2 | 133.0 | 133.0 | 1 MiB | 66 / 67 | n/a |
| ra512x8 | 197.4 | 5.3 | 2 | 130.9 | 130.9 | 1 MiB | 63 / 64 | n/a |
| ra512x16 | 196.1 | 5.3 | 2 | 130.8 | 130.8 | 1 MiB | 65 / 67 | n/a |
| ra512x32 | 193.3 | 5.4 | 2 | 129.4 | 129.4 | 1 MiB | 66 / 66 | n/a |

#### Link +60 ms, load: none, file 8 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 336.5 | 24.9 | 1 | 336.5 | 336.5 | 8 MiB | 66 / 184 | 64 |
| seq512 | 1183.7 | 7.1 | 16 | 132.1 | 132.9 | 512 KiB | 66 / 71 | 65 |
| ra512x4 | 533.7 | 15.7 | 16 | 201.2 | 201.2 | 2 MiB | 68 / 175 | 69 |
| ra512x8 | 400.1 | 21.0 | 16 | 141.5 | 141.5 | 4 MiB | 69 / 175 | 73 |
| ra512x16 | 386.6 | 21.7 | 16 | 130.4 | 140.6 | 8 MiB | 66 / 235 | 121 |
| ra512x32 | 347.2 | 24.2 | 16 | 137.0 | 137.0 | 8 MiB | 66 / 189 | 121 |

#### Link +60 ms, load: none, file 100 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 2752.5 | 38.1 | 13 | 330.5 | 330.5 | 8 MiB | 177 / 242 | 67 |
| seq512 | 13361.9 | 7.8 | 200 | 131.2 | 131.3 | 512 KiB | 65 / 78 | 66 |
| ra512x4 | 3652.2 | 28.7 | 200 | 195.4 | 195.4 | 2 MiB | 66 / 179 | 66 |
| ra512x8 | 2068.8 | 50.7 | 200 | 132.8 | 132.8 | 4 MiB | 72 / 170 | 65 |
| ra512x16 | 1878.8 | 55.8 | 200 | 141.0 | 141.0 | 8 MiB | 115 / 229 | 128 |
| ra512x32 | 1904.9 | 55.0 | 200 | 143.0 | 143.0 | 16 MiB | 249 / 370 | 251 |

#### Link +60 ms, load: 2 writers, file 64 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 195.9 | 0.3 | 1 | 195.9 | 195.9 | 64 KiB | 66 / 72 | n/a |
| seq512 | 190.6 | 0.3 | 1 | 190.6 | 190.6 | 64 KiB | 64 / 65 | n/a |
| ra512x4 | 193.9 | 0.3 | 1 | 193.9 | 193.9 | 64 KiB | 66 / 74 | n/a |
| ra512x8 | 194.7 | 0.3 | 1 | 194.7 | 194.7 | 64 KiB | 68 / 70 | n/a |
| ra512x16 | 187.5 | 0.3 | 1 | 187.5 | 187.5 | 64 KiB | 64 / 64 | n/a |
| ra512x32 | 191.3 | 0.3 | 1 | 191.3 | 191.3 | 64 KiB | 66 / 71 | n/a |

#### Link +60 ms, load: 2 writers, file 377 KiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 192.5 | 2.0 | 1 | 192.5 | 192.5 | 377 KiB | 64 / 69 | n/a |
| seq512 | 204.1 | 1.9 | 1 | 204.1 | 204.1 | 377 KiB | 65 / 74 | n/a |
| ra512x4 | 191.4 | 2.0 | 1 | 191.4 | 191.4 | 377 KiB | 66 / 71 | n/a |
| ra512x8 | 199.1 | 1.9 | 1 | 199.1 | 199.1 | 377 KiB | 65 / 68 | n/a |
| ra512x16 | 195.2 | 2.0 | 1 | 195.2 | 195.2 | 377 KiB | 66 / 69 | n/a |
| ra512x32 | 196.0 | 2.0 | 1 | 196.0 | 196.0 | 377 KiB | 65 / 75 | n/a |

#### Link +60 ms, load: 2 writers, file 1 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 210.8 | 5.0 | 1 | 210.8 | 210.8 | 1 MiB | 65 / 72 | n/a |
| seq512 | 272.2 | 3.9 | 2 | 133.7 | 139.8 | 512 KiB | 71 / 72 | n/a |
| ra512x4 | 203.1 | 5.2 | 2 | 135.2 | 135.2 | 1 MiB | 68 / 72 | n/a |
| ra512x8 | 206.6 | 5.1 | 2 | 138.1 | 138.1 | 1 MiB | 67 / 70 | n/a |
| ra512x16 | 206.3 | 5.1 | 2 | 134.6 | 134.6 | 1 MiB | 68 / 72 | n/a |
| ra512x32 | 191.7 | 5.5 | 2 | 128.1 | 128.1 | 1 MiB | 65 / 74 | n/a |

#### Link +60 ms, load: 2 writers, file 8 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 366.5 | 22.9 | 1 | 366.5 | 366.5 | 8 MiB | 65 / 210 | 64 |
| seq512 | 1217.8 | 6.9 | 16 | 137.3 | 137.3 | 512 KiB | 65 / 73 | 63 |
| ra512x4 | 525.7 | 16.0 | 16 | 189.7 | 189.7 | 2 MiB | 65 / 169 | 66 |
| ra512x8 | 342.2 | 24.5 | 16 | 141.2 | 141.2 | 4 MiB | 78 / 120 | 67 |
| ra512x16 | 337.9 | 24.8 | 16 | 137.0 | 137.0 | 8 MiB | 71 / 183 | 124 |
| ra512x32 | 337.5 | 24.9 | 16 | 136.3 | 136.3 | 8 MiB | 70 / 181 | 124 |

#### Link +60 ms, load: 2 writers, file 100 MiB (median of 5)

| variant | wall ms | MB/s | chunks | first chunk ms | max gap ms | peak in flight | side stat p50/max ms | stat after cancel ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 2747.0 | 38.2 | 13 | 268.1 | 268.1 | 8 MiB | 181 / 199 | 65 |
| seq512 | 13908.1 | 7.5 | 200 | 132.0 | 136.8 | 512 KiB | 66 / 92 | 66 |
| ra512x4 | 3642.3 | 28.8 | 200 | 197.6 | 197.6 | 2 MiB | 66 / 176 | 65 |
| ra512x8 | 2038.2 | 51.5 | 200 | 143.3 | 143.3 | 4 MiB | 99 / 137 | 65 |
| ra512x16 | 1909.1 | 54.9 | 200 | 131.5 | 136.7 | 8 MiB | 113 / 179 | 134 |
| ra512x32 | 1919.2 | 54.6 | 200 | 143.0 | 143.0 | 16 MiB | 252 / 325 | 254 |
