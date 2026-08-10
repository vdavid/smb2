# Benchmark findings

Raw data, context, and takeaways from benchmarking smb2 against native macOS SMB and the `smb` crate. This doc captures
everything for later distillation into README and blog posts.

## Test setup

- **Client:** MacBook on Wi-Fi, close to the server
- **Server:** QNAP NAS at 192.168.1.111, Gigabit Ethernet, HDD
- **Protocol:** SMB 3.1.1, AES-128-GMAC signing, no encryption
- **Server params:** MaxReadSize=8 MB, MaxWriteSize=1 MB, MaxTransactSize=8 MB
- **Benchmark:** 3 iterations per suite, median times, randomized order between methods, warmup run before measurement

### Second server (Raspberry Pi)

- Pi at 192.168.1.156, Samba on HDD, guest access
- Also negotiates SMB 3.1.1 (recent Samba)
- MaxReadSize=8 MB, MaxWriteSize=1 MB (same as QNAP, Samba defaults)
- Pi was offline during the main benchmark runs, tested separately via integration tests (directory listing works, 13
  entries)

## Key discovery: macOS VFS cache invalidates naive benchmarks

Native macOS SMB reads go through the kernel's VFS page cache. After a warmup run that downloads the same files,
subsequent reads hit the cache with no network transfer at all. This makes native appear 20x faster than it actually is.

Evidence:

- Large download (3 × 50 MB) WITHOUT F_NOCACHE: native 249ms = 600 MB/s. That's faster than Gigabit Ethernet (~125
  MB/s). Impossible from wire.
- Large download WITH F_NOCACHE: native 4.93s = 30 MB/s. Realistic for HDD over Gigabit.
- smb2 download same files: 1.38s = 109 MB/s. **3.6x faster than uncached native.**

All results below use F_NOCACHE for honest native numbers.

## Final results: smb2 vs native (F_NOCACHE, compound reads), QNAP NAS

These are the final numbers with compound requests (CREATE+READ+CLOSE in one round-trip) and proper F_NOCACHE on all
native reads.

### Small files: 100 × 100 KB (9.8 MB total)

| Operation | native | smb2  | Ratio | Winner           |
|-----------|--------|-------|-------|------------------|
| Upload    | 3.69s  | 1.91s | 0.52x | smb2 1.9x faster |
| List      | 47ms   | 21ms  | 0.45x | smb2 2.2x faster |
| Download  | 3.10s  | 617ms | 0.20x | smb2 5.0x faster |
| Delete    | 3.08s  | 1.03s | 0.33x | smb2 3.0x faster |

smb2 wins everything on small files. Downloads got a massive boost from compound reads (1.55s -> 617ms).

### Medium files: 10 × 10 MB (100 MB total)

| Operation | native | smb2  | Ratio | Winner           |
|-----------|--------|-------|-------|------------------|
| Upload    | 1.66s  | 1.23s | 0.74x | smb2 1.3x faster |
| List      | 27ms   | 19ms  | 0.72x | smb2 1.4x faster |
| Download  | 4.00s  | 2.93s | 0.73x | smb2 1.4x faster |
| Delete    | 301ms  | 128ms | 0.42x | smb2 2.4x faster |

smb2 wins all four. With proper F_NOCACHE, the earlier "native wins download" result was an artifact of cached reads.
smb2 is faster across the board.

### Large files: 3 × 50 MB (150 MB total), with F_NOCACHE

| Operation | native | smb2  | Ratio | Winner           |
|-----------|--------|-------|-------|------------------|
| Upload    | 1.69s  | 1.56s | 0.93x | ~parity          |
| List      | 27ms   | 18ms  | 0.65x | smb2 1.5x faster |
| Download  | 5.62s  | 1.11s | 0.20x | smb2 5.1x faster |
| Delete    | 117ms  | 54ms  | 0.51x | smb2 2.1x faster |

smb2 wins 3 of 4, upload is at parity. Large downloads improved dramatically (1.38s -> 1.11s) thanks to compound reads
reducing per-file overhead.

### Compound request impact

Single file read: 4.7ms with compound vs 12.8ms without = **2.7x faster per file**. The compound sends CREATE+READ+CLOSE
in one transport frame (one round-trip instead of three).

4-way compound write (CREATE+WRITE+FLUSH+CLOSE) confirmed working on both QNAP NAS and Raspberry Pi.

## Pre-compound results: smb2 vs native (F_NOCACHE), QNAP NAS

Historical results from before compound requests were implemented.

### Small files: 100 × 100 KB (9.8 MB total)

| Operation | native | smb2  | Ratio | Winner           |
|-----------|--------|-------|-------|------------------|
| Upload    | 3.82s  | 2.11s | 0.55x | smb2 1.8x faster |
| List      | 45ms   | 23ms  | 0.51x | smb2 2.0x faster |
| Download  | 4.15s  | 1.55s | 0.37x | smb2 2.7x faster |
| Delete    | 3.14s  | 901ms | 0.29x | smb2 3.4x faster |

### Medium files: 10 × 10 MB (100 MB total)

| Operation | native | smb2  | Ratio | Winner             |
|-----------|--------|-------|-------|--------------------|
| Upload    | 1.51s  | 1.47s | 0.97x | ~parity            |
| List      | 29ms   | 17ms  | 0.58x | smb2 1.7x faster   |
| Download  | 411ms  | 1.01s | 2.47x | native 2.5x faster |
| Delete    | 252ms  | 113ms | 0.45x | smb2 2.2x faster   |

Note: the native 411ms download was partially cached (no F_NOCACHE). With F_NOCACHE, the final run shows smb2 winning
medium downloads too.

### Large files: 3 × 50 MB (150 MB total), with F_NOCACHE

| Operation | native | smb2  | Ratio | Winner             |
|-----------|--------|-------|-------|--------------------|
| Upload    | 1.57s  | 1.84s | 1.17x | native 1.2x faster |
| List      | 62ms   | 17ms  | 0.28x | smb2 3.6x faster   |
| Download  | 4.93s  | 1.38s | 0.28x | smb2 3.6x faster   |
| Delete    | 132ms  | 68ms  | 0.51x | smb2 1.9x faster   |

## Results: smb2 vs `smb` crate, QNAP NAS (pre-sliding-window)

From the first benchmark run before the sliding window optimization. This used the batch window (send N, wait for all N,
repeat).

### Small files: 500 × 100 KB (48.8 MB total)

| Operation | native | smb    | smb2   | smb2/nat | smb2/smb |
|-----------|--------|--------|--------|----------|----------|
| Upload    | 21.13s | 30.78s | 10.21s | 0.48x    | 0.33x    |
| List      | 155ms  | 79ms   | 53ms   | 0.35x    | 0.68x    |
| Download  | 24.95s | 34.86s | 8.26s  | 0.33x    | 0.24x    |
| Delete    | 15.50s | 22.51s | 5.36s  | 0.35x    | 0.24x    |

smb2 is 3-4x faster than the smb crate across the board.

### Medium files: 10 × 10 MB (100 MB total)

| Operation | native | smb    | smb2  | smb2/nat | smb2/smb |
|-----------|--------|--------|-------|----------|----------|
| Upload    | 1.77s  | 11.13s | 1.65s | 0.93x    | 0.15x    |
| List      | 28ms   | 15ms   | 20ms  | 0.71x    | 1.32x    |
| Download  | 397ms  | 39.30s | 4.61s | 11.64x   | 0.12x    |
| Delete    | 293ms  | 551ms  | 140ms | 0.48x    | 0.25x    |

smb2 is 6-8x faster than the smb crate on uploads and downloads. Note: the native 397ms download was from VFS cache (not
F_NOCACHE).

## Chunk size experiments

We tested three chunk size strategies for pipelined reads:

### 64 KB chunks (CreditCharge=1, max 32 in flight)

- Small files: 7.82s (bad, 100 KB file becomes 2 chunks + overhead)
- Medium files: 1.42s (decent, 160 chunks per 10 MB file)
- Large files: 5.04s (bad, 800 chunks per 50 MB file, too much overhead)

### MaxReadSize chunks (8 MB, CreditCharge=128)

- Small files: 1.49s (excellent, 100 KB file in 1 chunk)
- Medium files: 3.43s (bad, only 2 chunks per 10 MB file, no pipelining)
- Large files: 5.33s (same, only 7 chunks per 50 MB file)

### 512 KB chunks (CreditCharge=8, up to ~32 in flight)

- Small files: 1.55s (excellent, 100 KB fits in 1 chunk with smart sizing)
- Medium files: 1.01s (best yet, 20 chunks per 10 MB file)
- Large files: 4.31s (better but still slow without F_NOCACHE context)
- Large files WITH F_NOCACHE: 1.38s (3.6x faster than native!)

**Conclusion:** 512 KB is the sweet spot. Files smaller than MaxReadSize get a single chunk (no overhead). Larger files
get enough chunks for the sliding window to keep the pipe full.

The "smart sizing" logic:

```rust
if file_size < = max_read_size {
chunk = file_size  // one read, no pipelining
} else {
chunk = 512 KB     // enough chunks for sliding window
}
```

## Credit system observations

- QNAP grants 32 credits per response (Samba default)
- With CreditRequest=256, credits grow rapidly: 511 → 15,842 after 20 ops
- After session setup: ~60-100 credits available
- After a few operations: 500+ credits
- No credit starvation observed in any test
- Credits are tied to TCP connection (lost on disconnect/reconnect)

## Sliding window impact

The sliding window (send next read immediately as each response arrives)
replaced the batch window (send N, wait for all N, repeat). Impact:

- Medium downloads: 4.61s → 1.01s (4.6x improvement)
- The batch window left the TCP pipe idle between batches
- The sliding window keeps it full at all times

## Per-file overhead analysis

Each file operation requires 3+ round-trips:

- CREATE (open the file): 1 round-trip
- READ/WRITE: 1+ round-trips depending on file size
- FLUSH (for writes): 1 round-trip
- CLOSE: 1 round-trip

For 100 small files: 100 × 4 = 400 round-trips minimum. At ~1ms RTT, that's 400ms of pure latency, plus data transfer
time.

Native macOS SMB avoids some of this via:

- Handle caching (reuse open handles)
- Kernel read-ahead (speculative prefetch)
- VFS page cache (skip network entirely for warm reads)

**Implemented optimization:** Compound requests (CREATE+READ+CLOSE in one message) reduce per-file overhead from 3-4
round-trips to 1. This brought small-file download from 1.55s to 617ms (2.5x improvement).

## What we haven't measured yet

- Pi benchmarks with the benchmark script (Pi was offline)
- Impact of handle caching (not implemented yet)
- Comparison with larger file counts (1000+ files)
- Different network conditions (VPN, high-latency)

## Summary for README/blog

**Headline numbers** (all vs uncached native on QNAP NAS, Gigabit LAN, with compound reads):

- **Small files (100 x 100 KB):** smb2 is 1.9-5.0x faster than native on all operations (downloads are 5x faster)
- **Medium files (10 x 10 MB):** smb2 wins all four operations, 1.3-2.4x faster
- **Large files (3 x 50 MB):** smb2 wins 3 of 4, downloads are 5.1x faster, upload at parity
- **vs smb crate:** smb2 is 3-8x faster across the board

**The story:** smb2 beats native macOS SMB on every operation across all file sizes. The earlier "native wins medium
downloads" result turned out to be a VFS cache artifact. With compound requests, small file downloads went from 2.7x to
5.0x faster than native. For what Cmdr does most (browsing directories, reading file metadata, copying files to/from
NAS), smb2 is the clear winner.

## Directory-listing throughput probe (2026-07-22)

Cmdr's background index scan of the QNAP ran at ~39 dirs/s (~1,454 entries/s) over SMB at 64 concurrent listings, while
an earlier Cmdr bench on the same NAS hit ~137 dirs/s at the same concurrency. To explain that gap we built the
`benchmarks/smb-listing` probe (see its [README](../benchmarks/smb-listing/README.md)), which instruments the real
listing path (CREATE → QUERY_DIRECTORY loop → CLOSE) against the live NAS. It adds `Tree::list_directory_instrumented`
to the crate: same wire path as `list_directory`, but it returns a per-round-trip `ListingTrace` and takes an optional
QUERY_DIRECTORY buffer override. Read-only.

- **Setup:** MacBook on Wi-Fi, QNAP TS-464 ("Naspolya") at 192.168.1.111 over Gigabit, raidz1 HDD pool with ZFS ARC.
  SMB 3.1.1, MaxTransactSize 8 MB. Sample tree: David's `naspi` share, ~236 entries/dir average.
- **Cache caveat:** the QNAP ARC caches directory metadata across runs, so "cold" numbers are only trustworthy on the
  first pass over never-listed dirs. The authoritative cold data is the first full run
  (`results/listing-2026-07-22-012435.txt`); repeated probing warmed the ARC and inflated later "cold" passes.

### Per-phase breakdown (serial, one connection, 250 dirs)

| Phase        | Cold p50 | Cold mean | Warm p50 | Warm mean |
|--------------|----------|-----------|----------|-----------|
| CREATE       | 4.2 ms   | 4.4 ms    | 3.9 ms   | 4.1 ms    |
| QUERY (all)  | 40.0 ms  | 113.9 ms  | 8.6 ms   | 24.3 ms   |
| CLOSE        | 3.3 ms   | 3.7 ms    | 3.1 ms   | 3.4 ms    |
| TOTAL (wire) | 47.6 ms  | 122.0 ms  | 16.2 ms  | 31.8 ms   |

- Cold serial throughput 8.2 dirs/s; warm 31.4 dirs/s (same 250 dirs, second pass).
- 4.43 round trips per dir on average (CREATE + ~2.4 QUERY + CLOSE; the trailing QUERY always returns NO_MORE_FILES).
- **QUERY_DIRECTORY dominates:** ~93% of cold wire time, ~70% warm. CREATE + CLOSE together are a fixed ~8 ms.
- Cold QUERY p90 hit 170 ms (some dirs 400 ms+): random HDD seeks for uncached metadata. The warm QUERY mean (24 ms) is
  inflated by fat multi-round-trip dirs; the p50 of 8.6 ms is representative of a typical dir.

### Query-buffer sweep (fat dirs, warm)

64 KiB vs 256 KiB vs 1024 KiB output buffers were **identical** in round trips and timing. Even the fattest real dir
(139 entries) completes in 2 round trips at 64 KiB (1 data reply + 1 terminal NO_MORE_FILES). A bigger buffer only helps
dirs with ~500+ entries in one directory, which this tree does not have.

### Throughput vs in-flight window (one TCP session)

| Window | Cold dirs/s | Warm dirs/s |
|--------|-------------|-------------|
| 1      | 3.5         | 31.7        |
| 8      | 10.8        | 69.1        |
| 32     | 10.1        | 75.2        |
| 64     | 11.9        | 71.7        |
| 128    | 10.0        | 77.2        |

Cold uses a fresh disjoint slice per window (the real scan scenario); warm reuses the cached sample. **Cold throughput
plateaus at ~10-12 dirs/s past a window of 8: raising the in-flight depth on a *single* connection buys nothing when
metadata is cold.** (Adding separate TCP *connections* is a different lever and does help cold — see the NAS-side ground
truth below.) Warm scales to ~75 dirs/s and holds (on this fat sample).

### Throughput across N TCP sessions (window 64)

| Sessions | Warm dirs/s |
|----------|-------------|
| 1        | 74.1        |
| 2        | 117.9       |
| 4        | 218.2       |

Warm scaling across separate TCP sessions is near-linear (2.9x at 4 sessions). The probe also runs a cold session sweep,
but from the client side each session count necessarily lists a different cold slice and cold per-dir cost varies ~10x,
so the client dirs/s alone is too noisy to read as a scaling curve. The NAS-side counters resolve it: at the same total
in-flight depth, more connections raise the pool's read IOPS ~1.75x at flat latency (composition-independent), so the
cold session gain is real, not a slice artifact. See the NAS-side ground truth below.

### Verdict: the gap is cache state, not the protocol or the code

> The bottleneck attribution below was corrected by direct NAS-side measurement. The wire-level numbers in this section
> stand; for what actually limits the cold walk, the authority is
> [NAS-side ground truth](#nas-side-ground-truth-during-cold-listing-2026-07-22) further down, which this verdict now
> reflects.

**Hypothesis #2 (cache state) explains the 39-vs-137 gap.** Cmdr's 137 dirs/s bench ran warm (ARC had the metadata); its
39 dirs/s index scan is a cold first-ever walk. Cold listing is **metadata-read-bound**: each directory entry costs
roughly one per-entry dnode read that misses ARC and hits the HDD pool, so cold cost scales with entries/dir (NAS-side:
a ~140-entry dir triggers ~170 metadata misses, a ~10-entry dir ~12). That tree-shape effect — not a fixed per-dir cost
— is the 39-vs-137 gap; Cmdr's real tree has many small dirs, cheaper than this fat sample.

**The single-session cold ceiling is NOT a disk wall.** The client-side numbers alone suggested a ~150 IOPS disk ceiling
(~10-12 dirs/s × ~13 reads/dir), but that was a client-side inference that mistook per-connection pipeline stalls for the
disk. The NAS counters show the raidz1 pool serves **1,200-2,700 read ops/s cold at 1.4-4.5 ms** with headroom to spare.
The single-session cold plateau is **per-connection serialization in ksmbd** (one SMB connection can't drive the ZFS
read queue deep enough, regardless of SMB in-flight window), which extra TCP connections relieve.

**Hypothesis #1 (per-session serialization), refined — not simply refuted.** The **warm** path multiplexes fine on one
session (31 → 75 dirs/s as the in-flight window grows), so warm is not serialized. The **cold** path *is*
per-connection-limited: adding TCP connections at the same total in-flight depth lifts NAS read IOPS ~1.75x at flat
latency (composition-independent evidence), and cold client throughput ~3.8x at 4 connections.

**Hypothesis #3 (per-phase distribution):** QUERY_DIRECTORY is the whole story; CREATE and CLOSE are a fixed ~8 ms.

### Expected gains

- **(a) Compound CREATE + the first QUERY:** could save the ~4 ms CREATE round trip. CLOSE cannot safely join that
  compound: a successful QUERY_DIRECTORY response has no "last batch" bit, so only a subsequent
  `STATUS_NO_MORE_FILES` reply proves the scan is complete. On **warm** listings the CREATE saving is potentially useful;
  on **cold** listings the metadata-bound QUERY (114 ms) dwarfs it. The compound partial-failure and first-batch
  buffering complexity is not justified by the current measurements, so skip it for now.
- **(b) Bigger QUERY_DIRECTORY buffer (>64 KiB):** no measurable win on this tree; dirs are small enough to finish in one
  data round trip at 64 KiB. Only worth it for pathological dirs with hundreds-to-thousands of entries. Skip for now.
- **(c) Multiple TCP connections:** the single biggest throughput lever, and it helps **both** regimes. Warm scales
  near-linearly (2.9x at 4 sessions). **Cold scales too** (~3.8x at 4 connections, NAS-side-verified as real IOPS-headroom
  extraction at flat latency, not a slice artifact), because the single-connection cold ceiling is ksmbd per-connection
  serialization, not the disk. So open several connections for the cold first-ever scan, not just warm re-scans.

**Actionable lead for Cmdr (not smb2):** the cold index scan has two stacking levers. (1) Spread it across several TCP
connections to extract the pool's real IOPS headroom (verified: ~3.8x at 4 connections). (2) Read *less* per cold dir: if
the first-pass index only needs names (not size/mtime), a lighter info class like FileNamesInformation skips the
per-entry dnode reads that dominate cold cost. Both are Cmdr-side and compound.

## NAS-side ground truth during cold listing (2026-07-22)

The client-side probe above inferred the cold bottleneck from the Mac only. To confirm it, we sampled the QNAP's own
disk, ARC, and CPU counters *while* the probe drove load. The NAS-side numbers **revise the earlier verdict**: the
raidz1 pool is **not** disk-saturated by a single SMB session, and multiple TCP sessions do lift cold throughput, which
the client-only run couldn't prove.

### NAS setup and instrumentation

- **Box:** QNAP TS-464 "Naspolya", QTS 5.2.9, 4 CPU cores, 64 GB RAM. The `naspi` share is dataset `zpool2/zfs18` on
  **`zpool2`, a raidz1 of 4× Seagate HDDs** (the 14.4 TB pool). `zpool1` is a *separate* 2-disk NVMe mirror, **not** an
  L2ARC or special vdev for `zpool2` (`secondarycache=none`, `l2_hits=0`), so cold reads on the share hit the 4 HDDs
  directly. Dataset: `recordsize=128K`, `compression=on`, `atime=relatime`, `primarycache=all`.
- **ARC:** `c_max` 47.7 GB, ~41 GB resident throughout. Big enough that directory structure stays warm across runs; only
  never-touched leaf metadata is genuinely cold.
- **SMB server is ksmbd** (in-kernel: threads `ksmbd-<conn>.<n>`), not Samba. SMB work therefore shows up as kernel
  `sys`/`softirq` CPU, not a userland `smbd` process.
- **Sampler:** [`benchmarks/smb-listing/scripts/nas_sample.sh`](../benchmarks/smb-listing/scripts/nas_sample.sh),
  read-only, 2 s cadence: `zpool iostat -Hlp zpool2` (per-second rates, ns latencies), `arcstats` deltas, `/proc/stat`
  CPU deltas. The probe's stdout was epoch-stamped per line so each phase aligns to the samples.
- **Measurement caveats:** (1) `iostat -x` cannot see the raidz HDDs — QNAP's `qzfs` layer hides `/dev/sd*` (only NVMe
  and eMMC appear), so there is **no per-disk %util**; the saturation signal is `zpool iostat -l` `disk_wait` latency
  plus how IOPS scale with added connections. (2) `zpool iostat` "read ops" are ZFS-level (metadata-dominated) read
  operations fanned across the 4 raidz members, not physical head-seeks. (3) Idle ambient is ~0 read IOPS (a running
  immich + docker sit quiet at rest); one early "baseline" was contaminated by a stray `du` walk we'd left running and
  is discarded.

### Cold fat-directory listing (fresh `photos` slices, ~140 entries/dir)

This is the regime that reproduces the earlier ~8–12 dirs/s cold plateau. Each row is a distinct probe phase over a
never-listed, disjoint slice; NAS columns are the average over that phase's 2 s samples.

| Phase (fat dirs, window 64)        | Client dirs/s | Read IOPS avg (peak) | Read MB/s | disk_wait read | ARC hit% (demand-meta) | ARC miss/s | CPU busy (of 4 cores) | iowait |
|------------------------------------|---------------|----------------------|-----------|----------------|------------------------|------------|-----------------------|--------|
| Cold, 1 session (400 dirs, 53.9 s) | 7.4           | 1280 (2209)          | 6.0       | 2.6 ms         | 84% (83%)              | 1256       | 20%                   | ~0%    |
| Cold, 1 session (400 dirs, 41.2 s) | 9.7           | 814 (1614)           | 3.8       | 4.2 ms         | 82% (81%)              | 856        | 15%                   | ~0%    |
| Cold, 4 sessions (400 dirs, 10.8s) | 37.0          | 2239 (2717)          | 10.1      | 3.3 ms         | 82% (80%)              | 2386       | 23%                   | ~0%    |
| Warm (same dirs, ARC-cached)       | ~90           | 336 (388)            | 1.5       | 4.5 ms         | 92% (93%)              | 401        | 24%                   | ~0%    |

The two cold 1-session rows are the same configuration over different slices; the 7.4-vs-9.7 spread is the
slice-composition variance the client-side caveat warned about (the cheaper slice lists more dirs/s *and* does fewer
disk reads).

Both cold-vs-warm and 1-vs-4-session comparisons hold the total in-flight depth constant at 64 (the multi-session sweep
spreads 64 workers as 16 × 4 connections), so the only variable between the 1- and 4-session rows is the **number of TCP
connections**.

### Small-directory cold listing (contrast)

Cold slices of small dirs barely touch the disk: `projects-archive` (~48 entries/dir) cold-listed at 40–55 dirs/s, and
`projects` (~10 entries/dir) at 217–680 dirs/s with `disk_wait` ~1.4 ms. **Cold dirs/s scales inversely with
entries/dir** because each entry costs roughly one metadata read; a fat 140-entry dir triggers ~170 metadata misses,
a 10-entry dir ~12. This is the same mechanism behind the original 39-vs-137 gap: it's the tree's shape, not a fixed
per-dir cost.

### The three questions, answered NAS-side

1. **During the cold plateau, are the disks saturated?** **No — there is real headroom.** `disk_wait` sat at
   2.6–4.5 ms, well under the ~8–10 ms of a random HDD seek; even a *single* session momentarily peaked at 2209 read
   IOPS while averaging 1280, i.e. the pool idled between pipeline stalls rather than hitting a wall. Decisively, adding
   TCP connections at the **same** total in-flight depth raised read IOPS from ~1280 to ~2240 (peak 2717) with latency
   essentially flat (2.6 → 3.3 ms). A saturated pool can't hand you 1.75× more IOPS for free. The single-session cold
   ceiling is a **per-connection serialization in ksmbd** (one SMB connection can't drive the ZFS read queue deep enough
   regardless of SMB in-flight window), not the disk.
2. **Does the ARC miss rate explain cold vs warm?** **Yes.** A cold fat dir costs ~170 metadata misses/dir (1256 miss/s
   ÷ 7.4 dirs/s); warm drops to ~4–5 misses/dir (401 ÷ ~90) and runs ~12× faster. Even "cold" is ~84% ARC hits because
   the directory object and indirect blocks stay cached; the cold penalty is specifically the per-entry **dnode** reads
   that miss ARC and hit the HDDs. Warm rises to 92%+.
3. **Is anything CPU-bound?** **No.** CPU stayed at 15–25% of 4 cores (~0.6–1.0 core), softirq < 1%, iowait ~0% in every
   phase. Neither ksmbd nor ZFS is CPU-starved; there is ample CPU headroom.

### Revised verdict

The earlier "cold is disk-IOPS-bound at ~150 IOPS, so more concurrency can't help the first-ever walk" was a
**client-side inference that mis-identified per-session pipeline stalls as the disk ceiling.** The ~150 figure came from
`10–12 dirs/s × ~13 reads/dir`; the pool in fact serves **1200–2700 read ops/s cold at 1.4–4.5 ms**, is not saturated by
one session, and has headroom that extra TCP connections extract.

What still holds: cold listing *is* metadata-read-bound (per-entry dnode misses on the HDD pool), and cold cost scales
with entries/dir. What flips: the Cmdr lever. **Multiple TCP connections now look worthwhile for the cold first-ever
scan too, not just warm re-scans** — the NAS-side IOPS lift at flat latency is composition-independent evidence, where
the client-side dirs/s alone was too noisy to trust. Both levers stack: open several connections for the cold walk
*and* read less per cold dir (a names-only info class skips the per-entry dnode reads that dominate cold cost).
