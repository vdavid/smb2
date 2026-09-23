# Read-ahead benchmark for `FileDownload`, and its upload twin

The evidence behind `Tree::download`'s default since 0.24.0: 512 KiB chunks and an adaptive read-ahead window
(`crates/smb2/src/client/read_ahead.rs`). Measures `FileDownload` with different chunk sizes and read-ahead policies
against a local Samba in Docker, with latency and bandwidth injected by `tc netem` on the container's egress. With
`DIRECTION=up` it measures uploads instead (the evidence behind 0.25.0's adaptive write-behind window,
`crates/smb2/src/client/write_behind.rs`); see *Uploads* below.

- `./run.sh OUT.csv [runs] [links] [writers]`: builds and starts the container (published on `127.0.0.1:17445`,
  override with `SMB_BENCH_PORT`), writes random test files (the default sizes plus any in `SIZES`), then for each link runs every size × variant with no load
  and with `writers` background writer connections hammering the same share. A link is `<delay ms>` or
  `<delay ms>[@<netem rate>][~<jitter ms>][+stall]`, for example `"0 5 60"`, `"60@3mbit"`, `"20@240mbit~10"`, or
  `"5@240mbit+stall"`. Jitter is netem's normal distribution, always with a rate (an uncapped link gets
  `rate 100gbit`), because without one netem reorders packets and the run turns into a TCP reordering test. `+stall`
  freezes every `smbd` for `STALL_MS` (150) every `STALL_EVERY_MS` (1,000) via `docker/stall.sh`. Every shaped link
  queues up to 100,000 packets instead of dropping. Env: `VARIANTS`, `SIZES`, `LOADS` (for example `LOADS=0`),
  `BENCH_PROJECT` and `SMB_BENCH_PORT` (to run beside another copy), `BENCH_SLOW_START_AFTER_IDLE=0` (the container's
  TCP keeps its window across idle periods). Tears the container down on exit.
- `./grid.sh OUT_DIR GROUP...`: the tuning grid behind `results/self-tuning.md`. It runs every candidate in `TUNINGS`
  as `auto:<tuning>` on the group's links, on its own container (`smb2-ra-grid`, port 17545) with slow start after
  idle off. Groups: `d30 d3 d300 dfree djitter djitter3 dstall dstall3 dload up30 up3`, each under ten minutes.
- `./target/release/read-ahead-bench score [--detail] [--control PATTERN]... CSV...`: minimax-regret tables over
  download and upload CSVs (the scoring is defined in `src/score.rs` and `results/self-tuning.md`).
- **Tuning candidates**: any variant takes a `:<tuning>` suffix (`auto:wmax16-n25`, `adaptive:ref`) and then runs with
  that tuning (the bench builds smb2 with the unstable `__bench-tuning` feature) on a connection of its own, so what one
  candidate learns never seeds another. Tuned variants rotate their order every run. Names are in `src/tuning.rs`:
  `shipping` is what the build ships, `ref` is 0.25.1's behavior (fixed 250 ms headroom, delivery-paced rate).
- `./target/release/read-ahead-bench summarize OUT.csv`: median tables in Markdown.
- Variants:
  - `baseline`: sequential, chunk = `MaxReadSize` (what `Tree::download` did before 0.24.0).
  - `adaptive`: 512 KiB chunks, `ReadAhead::Adaptive` (the default since 0.24.0), on the connection the previous
    variants used.
  - `adaptive-cold`: the same on a fresh connection. Its numbers are mostly TCP slow start, and the idle it leaves on
    the shared connection makes the variant after it pay slow start again (Linux restarts it after an idle period), so
    run it on its own.
  - `compound`: one compound CREATE + READ + CLOSE (`read_file_compound_sized`), the single-READ alternative.
  - `auto`: `compound` when the file fits `Connection::quick_read_limit`, `adaptive` otherwise.
  - `seq<KiB>`: sequential. `ra<KiB>x<W>`: a fixed window of W READs.
- Per run: wall time from CREATE to the CLOSE's answer, time to the last chunk (when a consumer has every byte), chunk count, time to first chunk, the longest gap between deliveries, peak
  bytes in flight, the p50/max latency of a `stat` issued every 20 ms on a clone of the same connection during the
  download, and (8 MiB+ files) the latency of a `stat` right after dropping a download at 25%.
- Every run's bytes are checksummed and compared across variants, so a wrong read fails the run.

## Uploads

- `DIRECTION=up ./run.sh OUT.csv [runs] [links] [writers]`: the same matrix, but it runs `read-ahead-bench upload` and
  shapes the container's INGRESS (the client-to-server direction an upload's payload takes), redirected through an ifb
  device because `netem` only shapes what leaves an interface, with a deep queue (`limit 100000`) so a slow uplink
  queues instead of dropping. The downlink stays unshaped. `BIN=path/to/read-ahead-bench` runs a prebuilt binary, for
  example one built against an older smb2 from crates.io in a copy of this directory, to measure the "before".
- `./target/release/read-ahead-bench summarize-upload OUT.csv`: median tables.
- Variants: `default` (`FileWriter` as the build under test ships it), `wb<KiB>x<W>` (a fixed window of W WRITEs of
  that size; `wbmaxx32` is `MaxWriteSize` × 32, the pre-0.25 shape), `compound` (`write_file_compound`, skipped above
  `compound_write_limit`), and `auto` (`compound` when the file fits `Connection::quick_write_limit`, `default`
  otherwise).
- Per run: wall time from CREATE to the CLOSE's answer, WRITE count, peak bytes unconfirmed, the p50/max latency of a
  `stat` every 20 ms on a clone of the same connection, and (8 MiB+) how long a cancel takes: push a quarter, `abort()`,
  then a `stat`. Every upload is read back and compared.
- Background writers on a shaped uplink fill the shared link queue from other connections, which no per-connection
  window can bound (the side `stat` times out), so use `LOADS=0` on rate-capped links.

Against a real NAS (from a machine that can reach it): `SMB_BENCH_SHARE=<share> SMB_BENCH_USER=<user>
SMB_BENCH_PASS=<pass> ./target/release/read-ahead-bench run --prep --addr <host>:445 --rtt-ms real --load-writers 0
--runs 3 --out nas.csv`. `--prep` uploads the test files to `bench/` (the `stat` probe needs `bench/f_65536.bin`);
`--load-writers 2` adds the background writers, which write 32 MiB files to `load/`. Delete both folders afterwards.

`results/` holds the median tables (M1 Max, OrbStack, Samba on Alpine 3.21, container capped at two CPUs):

- `main.md`, `extras.md`, `slow.md`: the fixed-window matrix from 2026-09-22 that chose 512 KiB chunks and the 4 MiB
  cap, and showed no fixed window works on both fast and slow links. `load-writers.txt` is what the background writers
  managed on each link.
- `adaptive.md`: the adaptive default against the fixed windows on the key links, 2026-09-23.
- `close-and-quick-read.md`: the last chunk no longer waiting for the CLOSE (0.24.2), and `auto` against `compound` and
  `adaptive` at +60 and +200 ms, 2026-09-23.
- `adaptive-uploads.md`: the adaptive write-behind window (0.25.0) against 0.24.4's fixed 32-WRITE window, fixed
  512 KiB windows, and the compound write with and without `quick_write_limit`, on shaped uplinks, 2026-09-23.
- `self-tuning.md`: ten headroom and rate candidates on a grid of 28 shaped links (RTT, bandwidth, jitter, server
  stalls, background writers, uploads), picked by minimax regret, 2026-09-24. Samba 4.23 on Alpine 3.24. Has the
  real-NAS validation command.
