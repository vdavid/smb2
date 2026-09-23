//! How much a streaming download keeps on the wire.
//!
//! [`ReadAhead`] is the public knob; `Window` is the controller a
//! [`FileDownload`](crate::FileDownload) consults before every READ it sends.
//! The controller is pure (it takes instants, it never reads a clock or sends
//! anything), so its behavior is pinned by deterministic tests below.
//!
//! # Why adaptive is the default
//!
//! Measured against Samba with injected latency and bandwidth caps
//! (`benchmarks/read-ahead/`, 2026-09-22 and 2026-09-23), two constraints pull
//! in opposite directions:
//!
//! - **A fast link needs bytes in flight.** At +60 ms RTT a sequential
//!   512 KiB download ran at 7.8 MB/s against 50.7 MB/s with eight READs in
//!   flight, because each chunk costs a round trip.
//! - **On a slow link, every queued byte is latency for everything else on the
//!   connection.** At 375 KB/s a `stat` on the same connection waited 1.5 s
//!   behind one 512 KiB READ, 11.7 s behind eight, and 23.4 s behind the old
//!   default of one 8 MiB READ. A cancel waits the same way.
//!
//! No fixed window satisfies both, so the default sizes the window to the link:
//! it keeps about `delivery rate × (RTT + 250 ms)` bytes requested but not yet
//! arrived, at least one READ and at most [`ADAPTIVE_MAX_IN_FLIGHT`]. On a fast
//! link that reaches the cap within a few round trips; on a slow one it stays at
//! about one chunk, and the next READ goes out shortly before the current one
//! finishes arriving, so the pipe never idles and nothing queues behind more
//! than about one chunk plus 250 ms of transfer.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

/// Chunk size [`Tree::download`](crate::Tree::download) uses: one READ's worth,
/// capped at the server's `MaxReadSize`.
///
/// Small enough that a 375 KB/s link delivers a chunk every 1.4 s (an 8 MiB
/// chunk took 23 s, with no progress in between), large enough that it costs
/// half the requests of 256 KiB. Throughput tracks bytes in flight, not chunk
/// size: at +60 ms, 4 MiB in flight ran within 8% whether as 256 KiB × 16,
/// 512 KiB × 8, or 1 MiB × 4.
pub const DOWNLOAD_CHUNK_SIZE: u32 = 512 * 1024;

/// The most an adaptive download keeps requested but not yet delivered.
///
/// Eight 512 KiB READs. It captured 90–100% of the fast-link gain in the
/// benchmark (+60 ms: 50.7 MB/s at 4 MiB against 55.8 MB/s at 8 MiB), and it
/// bounds what one download buffers and what it can make the connection wait
/// for when the link collapses under it.
pub const ADAPTIVE_MAX_IN_FLIGHT: u64 = 4 * 1024 * 1024;

/// The most READs an adaptive download keeps in flight, whatever the chunk.
///
/// Only a caller-chosen chunk far below 512 KiB reaches it (4 MiB of 4 KiB
/// READs would be 1,024 of them, each holding a credit and a waiter). Matches
/// the write pipeline's window.
pub(crate) const ADAPTIVE_MAX_READS: usize = 32;

/// Margin on top of the round trip, in time at the delivery rate.
///
/// Covers server-side hiccups (a NAS disk seek, a busy CPU) and jitter, so the
/// pipe stays full. It is also the price: roughly the most anything else on the
/// connection waits beyond the chunk that is already arriving.
pub(crate) const ADAPTIVE_HEADROOM: Duration = Duration::from_millis(250);

/// How many recent deliveries the rate is measured over.
///
/// Samba completes concurrent READs in whatever order they finish, so chunks
/// arrive in bursts that in-order delivery makes burstier. A rate taken over
/// one gap would swing with every burst; eight deliveries span a full window
/// at the cap, which is where reordering happens.
const RATE_SAMPLES: usize = 8;

/// A span shorter than this is measured as this, so a burst of chunks that
/// were already waiting can't produce an unbounded rate.
const MIN_RATE_SPAN: Duration = Duration::from_millis(1);

/// A dispatch due sooner than this goes out now. Timers don't fire more
/// precisely, and a wait that rounds to nothing would spin.
const TIMER_RESOLUTION: Duration = Duration::from_millis(1);

/// How many READs a [`FileDownload`](crate::FileDownload) keeps on the wire.
///
/// Whatever the policy, chunks are delivered in file order, one per
/// [`next_chunk`](crate::FileDownload::next_chunk), and a file that fits one
/// chunk costs exactly one READ.
///
/// # Example
///
/// ```ignore
/// # async fn example(conn: &mut smb2::Connection, tree: &smb2::Tree) -> Result<(), smb2::Error> {
/// use smb2::ReadAhead;
///
/// // The behavior before read-ahead existed: one READ of `MaxReadSize` at a time.
/// let max_read = conn.params().map(|p| p.max_read_size).unwrap_or(65536);
/// let mut download = tree
///     .download(conn, "big.bin")
///     .await?
///     .with_chunk_size(max_read)
///     .with_read_ahead(ReadAhead::SEQUENTIAL);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ReadAhead {
    /// Size the window to the link (the default).
    ///
    /// Keeps about `delivery rate × (RTT + 250 ms)` bytes requested but not yet
    /// arrived: never fewer than one READ, never more than
    /// [`ADAPTIVE_MAX_IN_FLIGHT`] requested but not yet delivered. The rate is
    /// re-measured over the last eight deliveries, and the RTT is the
    /// connection's NEGOTIATE round trip or the fastest READ so far, whichever
    /// is smaller. See the [module docs](crate::client::read_ahead) for the
    /// measurements behind it.
    #[default]
    Adaptive,
    /// Keep exactly this many READs in flight (values below one mean one).
    ///
    /// `Fixed(1)` ([`ReadAhead::SEQUENTIAL`]) sends one READ and waits for it.
    /// A big fixed window is fastest on a fast link and worst on a slow one:
    /// every other request on the connection queues behind all of it.
    Fixed(usize),
}

impl ReadAhead {
    /// One READ at a time.
    pub const SEQUENTIAL: Self = Self::Fixed(1);

    /// The fixed window this policy pins, if any.
    pub(crate) fn fixed_window(self) -> Option<usize> {
        match self {
            Self::Adaptive => None,
            Self::Fixed(n) => Some(n.max(1)),
        }
    }
}

/// What a download should do about its next READ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dispatch {
    /// Send it now.
    Now,
    /// Send it at this instant if the head READ hasn't landed by then.
    At(Instant),
    /// Nothing to send until the head READ is delivered.
    AfterHead,
}

/// What the connection already knows about the link when a download starts.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LinkHint {
    /// The NEGOTIATE round trip, if one was measured.
    pub(crate) rtt: Option<Duration>,
    /// The delivery rate a recent download on the same connection measured,
    /// in bytes per second.
    pub(crate) rate: Option<f64>,
}

/// The read-ahead controller for one download.
///
/// The download reports every READ it sends and every chunk it delivers; in
/// return this says when the next READ should go out. "In flight" below means
/// requested but not yet delivered to the caller, which is what the memory
/// and window bounds count. The adaptive target counts something narrower:
/// bytes estimated to be still on their way (`unarrived`), drained at the
/// measured rate since the last event. That is what lets the next READ leave
/// shortly before the current one finishes arriving, instead of one round trip
/// after.
#[derive(Debug)]
pub(crate) struct Window {
    policy: ReadAhead,
    max_in_flight: u64,
    hint: LinkHint,
    /// The fastest dispatch-to-delivery time seen, an upper bound on the RTT.
    fastest_read: Option<Duration>,
    /// `(when, total bytes delivered by then)`, oldest first. The first entry
    /// is the first dispatch, with zero bytes.
    deliveries: VecDeque<(Instant, u64)>,
    delivered: u64,
    /// Estimated bytes still on their way, as of `unarrived_at`.
    unarrived: f64,
    unarrived_at: Option<Instant>,
}

impl Window {
    pub(crate) fn new(policy: ReadAhead, chunk_size: u32, hint: LinkHint) -> Self {
        Self {
            policy,
            // A chunk bigger than the cap still gets one READ in flight.
            max_in_flight: ADAPTIVE_MAX_IN_FLIGHT.max(u64::from(chunk_size)),
            hint,
            fastest_read: None,
            deliveries: VecDeque::with_capacity(RATE_SAMPLES + 1),
            delivered: 0,
            unarrived: 0.0,
            unarrived_at: None,
        }
    }

    /// Whether to send a READ of `next_len` bytes, given what's in flight.
    pub(crate) fn decide(
        &self,
        now: Instant,
        reads_in_flight: usize,
        bytes_in_flight: u64,
        next_len: u32,
    ) -> Dispatch {
        if reads_in_flight == 0 {
            return Dispatch::Now;
        }
        if let Some(window) = self.policy.fixed_window() {
            return if reads_in_flight < window {
                Dispatch::Now
            } else {
                Dispatch::AfterHead
            };
        }
        if reads_in_flight >= ADAPTIVE_MAX_READS
            || bytes_in_flight + u64::from(next_len) > self.max_in_flight
        {
            return Dispatch::AfterHead;
        }
        let (Some(rate), Some(target)) = (self.rate(), self.target()) else {
            // Nothing measured and nothing known: one READ until the first one
            // tells us something. Two would already double what a slow link
            // queues.
            return Dispatch::AfterHead;
        };
        let unarrived = self.unarrived_at(now, rate);
        if unarrived < target as f64 {
            return Dispatch::Now;
        }
        let wait = Duration::from_secs_f64((unarrived - target as f64) / rate);
        if wait < TIMER_RESOLUTION {
            return Dispatch::Now;
        }
        now.checked_add(wait)
            .map_or(Dispatch::AfterHead, Dispatch::At)
    }

    /// A READ of `len` bytes went out at `now`.
    pub(crate) fn on_dispatch(&mut self, now: Instant, len: u32) {
        if self.deliveries.is_empty() {
            self.deliveries.push_back((now, 0));
        }
        self.drain(now);
        self.unarrived += f64::from(len);
    }

    /// A chunk of `len` bytes, requested at `dispatched_at`, was delivered at
    /// `now`, leaving `bytes_in_flight` requested but undelivered.
    pub(crate) fn on_delivery(
        &mut self,
        now: Instant,
        dispatched_at: Instant,
        len: u32,
        bytes_in_flight: u64,
    ) {
        self.drain(now);
        // Everything delivered has arrived, so what's still on its way is at
        // most what's still in flight.
        self.unarrived = self.unarrived.min(bytes_in_flight as f64);

        let took = now.saturating_duration_since(dispatched_at);
        self.fastest_read = Some(self.fastest_read.map_or(took, |f| f.min(took)));

        self.delivered += u64::from(len);
        self.deliveries.push_back((now, self.delivered));
        while self.deliveries.len() > RATE_SAMPLES + 1 {
            self.deliveries.pop_front();
        }
    }

    /// Delivery rate over the recent deliveries, in bytes per second. Before
    /// the first delivery, the connection's hint stands in.
    pub(crate) fn rate(&self) -> Option<f64> {
        self.measured_rate().or(self.hint.rate)
    }

    /// The rate worth handing to the next download on this connection: one
    /// measured over at least two deliveries. A single READ's rate is mostly
    /// its round trip, and recording it after every small file would keep
    /// dragging the hint down to that.
    pub(crate) fn rate_to_share(&self) -> Option<f64> {
        if self.deliveries.len() < 3 {
            return None;
        }
        self.measured_rate()
    }

    fn measured_rate(&self) -> Option<f64> {
        let (&(first_at, first), &(last_at, last)) =
            (self.deliveries.front()?, self.deliveries.back()?);
        if last <= first {
            return None;
        }
        let span = last_at
            .saturating_duration_since(first_at)
            .max(MIN_RATE_SPAN);
        Some((last - first) as f64 / span.as_secs_f64())
    }

    /// The round trip the target budgets for.
    pub(crate) fn rtt(&self) -> Duration {
        match (self.hint.rtt, self.fastest_read) {
            (Some(seed), Some(fastest)) => seed.min(fastest),
            (Some(rtt), None) | (None, Some(rtt)) => rtt,
            (None, None) => Duration::ZERO,
        }
    }

    /// Bytes the adaptive policy wants on their way, once a rate is known.
    pub(crate) fn target(&self) -> Option<u64> {
        let rate = self.rate()?;
        Some((rate * (self.rtt() + ADAPTIVE_HEADROOM).as_secs_f64()) as u64)
    }

    fn unarrived_at(&self, now: Instant, rate: f64) -> f64 {
        let Some(since) = self.unarrived_at else {
            return self.unarrived;
        };
        let drained = rate * now.saturating_duration_since(since).as_secs_f64();
        (self.unarrived - drained).max(0.0)
    }

    fn drain(&mut self, now: Instant) {
        if let Some(rate) = self.rate() {
            self.unarrived = self.unarrived_at(now, rate);
        }
        self.unarrived_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHUNK: u32 = DOWNLOAD_CHUNK_SIZE;
    const MS: Duration = Duration::from_millis(1);

    /// Drives a [`Window`] the way a download does, against a simulated link:
    /// the server answers instantly, the link adds `rtt` and serializes
    /// responses back to back at `rate` bytes/s, and the consumer takes each
    /// chunk the moment it has fully arrived. No clocks, no sleeps.
    struct Link {
        rtt: Duration,
        rate: f64,
    }

    struct Run {
        /// Delivery instants, as offsets from the start.
        delivered_at: Vec<Duration>,
        /// The most READs in flight at once.
        peak_reads: usize,
        /// The most bytes queued ahead of a request sent at any instant: what a
        /// `stat` on the same connection would have waited behind.
        worst_queue: u64,
    }

    impl Link {
        fn download(&self, window: &mut Window, file: u64, chunk: u32) -> Run {
            let t0 = Instant::now();
            // (offset, len, dispatched_at, arrives_at)
            let mut in_flight: VecDeque<(u32, Instant, Instant)> = VecDeque::new();
            let mut link_free_at = t0;
            let mut next_offset = 0u64;
            let mut now = t0;
            let mut run = Run {
                delivered_at: Vec::new(),
                peak_reads: 0,
                worst_queue: 0,
            };
            let send = |now: Instant, len: u32, link_free_at: &mut Instant| {
                // Server answers on receipt; the response then waits for the
                // link behind everything already queued on it.
                let reaches_server = now + self.rtt / 2;
                let starts = reaches_server.max(*link_free_at);
                let done = starts + Duration::from_secs_f64(f64::from(len) / self.rate);
                *link_free_at = done;
                done + self.rtt / 2
            };
            loop {
                // Dispatch whatever the window allows right now.
                loop {
                    if next_offset >= file {
                        break;
                    }
                    let len = (file - next_offset).min(u64::from(chunk)) as u32;
                    let bytes: u64 = in_flight.iter().map(|r| u64::from(r.0)).sum();
                    match window.decide(now, in_flight.len(), bytes, len) {
                        Dispatch::Now => {
                            let arrives = send(now, len, &mut link_free_at);
                            window.on_dispatch(now, len);
                            in_flight.push_back((len, now, arrives));
                            next_offset += u64::from(len);
                            run.peak_reads = run.peak_reads.max(in_flight.len());
                        }
                        Dispatch::At(at) => {
                            let head = in_flight.front().expect("a timer needs a head").2;
                            if at < head {
                                now = at;
                                continue;
                            }
                            break;
                        }
                        Dispatch::AfterHead => break,
                    }
                }
                // What a request sent now would queue behind on the link.
                let queued = link_free_at.saturating_duration_since(now + self.rtt / 2);
                run.worst_queue = run
                    .worst_queue
                    .max((queued.as_secs_f64() * self.rate) as u64);
                let Some((len, sent, arrives)) = in_flight.pop_front() else {
                    break;
                };
                now = now.max(arrives);
                let left: u64 = in_flight.iter().map(|r| u64::from(r.0)).sum();
                window.on_delivery(now, sent, len, left);
                run.delivered_at.push(now - t0);
            }
            run
        }
    }

    fn adaptive(rtt_seed: Duration) -> Window {
        Window::new(
            ReadAhead::Adaptive,
            CHUNK,
            LinkHint {
                rtt: Some(rtt_seed),
                rate: None,
            },
        )
    }

    #[test]
    fn the_first_read_goes_out_alone() {
        let w = adaptive(60 * MS);
        let now = Instant::now();
        assert_eq!(w.decide(now, 0, 0, CHUNK), Dispatch::Now);
        let mut w = w;
        w.on_dispatch(now, CHUNK);
        assert_eq!(
            w.decide(now, 1, u64::from(CHUNK), CHUNK),
            Dispatch::AfterHead,
            "nothing is measured yet, so one READ must not become two"
        );
    }

    #[test]
    fn a_fixed_window_ignores_the_link() {
        let w = Window::new(ReadAhead::Fixed(3), CHUNK, LinkHint::default());
        let now = Instant::now();
        assert_eq!(w.decide(now, 2, 2 * u64::from(CHUNK), CHUNK), Dispatch::Now);
        assert_eq!(
            w.decide(now, 3, 3 * u64::from(CHUNK), CHUNK),
            Dispatch::AfterHead
        );
        let seq = Window::new(ReadAhead::Fixed(0), CHUNK, LinkHint::default());
        assert_eq!(seq.decide(now, 1, 1, CHUNK), Dispatch::AfterHead);
    }

    #[test]
    fn a_fast_link_opens_the_window_to_the_cap() {
        // +60 ms at 50 MB/s: the benchmark's fast row.
        let link = Link {
            rtt: 60 * MS,
            rate: 50e6,
        };
        let mut w = adaptive(60 * MS);
        let run = link.download(&mut w, 100 << 20, CHUNK);
        assert_eq!(run.delivered_at.len(), 200);
        assert_eq!(run.peak_reads, 8, "4 MiB of 512 KiB READs");
        // A 100 MiB file at 50 MB/s is 2.1 s of link time plus one RTT. The
        // ramp may cost a few round trips on top, never a sequential crawl
        // (13 s).
        let total = *run.delivered_at.last().unwrap();
        assert!(total < Duration::from_millis(2_600), "took {total:?}");
    }

    #[test]
    fn a_slow_link_keeps_about_one_chunk_queued() {
        // 375 KB/s at +60 ms: the link behind the original report.
        let link = Link {
            rtt: 60 * MS,
            rate: 375e3,
        };
        let mut w = adaptive(60 * MS);
        let run = link.download(&mut w, 8 << 20, CHUNK);
        assert_eq!(run.delivered_at.len(), 16);
        // What anything else on the connection waits behind: one chunk plus
        // the headroom, never the window (8 READs would be 4 MiB, 11 s).
        let bound = u64::from(CHUNK) + (375e3 * (0.060 + 0.250)) as u64;
        assert!(
            run.worst_queue <= bound,
            "queued {} bytes, bound {bound}",
            run.worst_queue
        );
        // And the pipe never idled: the whole file in link time plus one RTT,
        // unlike sequential, which idles one RTT per chunk.
        let link_time = (8 << 20) as f64 / 375e3;
        let total = run.delivered_at.last().unwrap().as_secs_f64();
        assert!(total < link_time + 0.2, "took {total:.2} s");
        // Progress: no gap much longer than one chunk's transfer time (1.4 s).
        let worst_gap = run
            .delivered_at
            .windows(2)
            .map(|p| p[1] - p[0])
            .max()
            .unwrap();
        assert!(
            worst_gap < Duration::from_millis(1_500),
            "gap {worst_gap:?}"
        );
    }

    #[test]
    fn a_mid_speed_link_overlaps_reads_without_queueing_a_window() {
        // 3 MB/s at +20 ms: sequential loses 11–16% here to idle round trips.
        let link = Link {
            rtt: 20 * MS,
            rate: 3e6,
        };
        let mut w = adaptive(20 * MS);
        let run = link.download(&mut w, 8 << 20, CHUNK);
        let link_time = (8 << 20) as f64 / 3e6;
        let total = run.delivered_at.last().unwrap().as_secs_f64();
        assert!(total < link_time + 0.1, "took {total:.2} s");
        let bound = u64::from(CHUNK) + (3e6 * (0.020 + 0.250)) as u64;
        assert!(
            run.worst_queue <= bound,
            "queued {} bytes, bound {bound}",
            run.worst_queue
        );
        assert!(run.peak_reads <= 3, "peak {} READs", run.peak_reads);
    }

    #[test]
    fn the_window_shrinks_when_deliveries_slow_down() {
        let mut w = adaptive(10 * MS);
        let t0 = Instant::now();
        let mut now = t0;
        // Eight fast deliveries (5 ms apart, ~100 MB/s): the target clears the cap.
        w.on_dispatch(now, CHUNK);
        for _ in 0..8 {
            now += 5 * MS;
            w.on_delivery(now, now - 5 * MS, CHUNK, 0);
        }
        assert!(w.target().unwrap() >= ADAPTIVE_MAX_IN_FLIGHT);
        // Then the link drops to ~375 KB/s: a chunk every 1.4 s.
        for _ in 0..8 {
            now += Duration::from_millis(1_400);
            w.on_delivery(now, now - 5 * MS, CHUNK, 0);
        }
        let rate = w.rate().unwrap();
        assert!((350e3..400e3).contains(&rate), "rate {rate}");
        assert!(
            w.target().unwrap() < u64::from(CHUNK),
            "target {} should be under one chunk",
            w.target().unwrap()
        );
        // With one READ out and barely anything drained, a second must wait.
        w.on_dispatch(now, CHUNK);
        assert!(matches!(
            w.decide(now, 1, u64::from(CHUNK), CHUNK),
            Dispatch::At(_)
        ));
    }

    #[test]
    fn the_window_grows_when_deliveries_speed_up() {
        let mut w = adaptive(10 * MS);
        let mut now = Instant::now();
        w.on_dispatch(now, CHUNK);
        for _ in 0..8 {
            now += Duration::from_millis(1_400);
            w.on_delivery(now, now - Duration::from_millis(1_400), CHUNK, 0);
        }
        assert!(w.target().unwrap() < u64::from(CHUNK));
        for _ in 0..8 {
            now += 5 * MS;
            w.on_delivery(now, now - 5 * MS, CHUNK, 0);
        }
        assert!(w.target().unwrap() >= ADAPTIVE_MAX_IN_FLIGHT);
        // Seven READs out still leaves room for an eighth, and no more.
        assert_eq!(w.decide(now, 7, 7 * u64::from(CHUNK), CHUNK), Dispatch::Now);
        assert_eq!(
            w.decide(now, 8, 8 * u64::from(CHUNK), CHUNK),
            Dispatch::AfterHead
        );
    }

    #[test]
    fn the_next_read_is_timed_to_leave_before_the_head_finishes() {
        let mut w = adaptive(Duration::ZERO);
        let mut now = Instant::now();
        w.on_dispatch(now, CHUNK);
        // 1 MB/s steady.
        for _ in 0..8 {
            now += Duration::from_micros(524_288);
            w.on_delivery(now, now, CHUNK, 0);
        }
        w.on_dispatch(now, CHUNK);
        let Dispatch::At(at) = w.decide(now, 1, u64::from(CHUNK), CHUNK) else {
            panic!("one chunk out at 1 MB/s is above the 250 ms target");
        };
        // 512 KiB on its way, 250 KB wanted: the next READ is due once
        // ~274 KB have drained, about 274 ms from now.
        let wait = at - now;
        assert!(
            (Duration::from_millis(270)..Duration::from_millis(280)).contains(&wait),
            "wait {wait:?}"
        );
        assert_eq!(w.decide(at, 1, u64::from(CHUNK), CHUNK), Dispatch::Now);
    }

    #[test]
    fn a_burst_of_reordered_chunks_does_not_blow_up_the_rate() {
        // Samba answers two concurrent READs in either order, so pairs land
        // together: 0 ms apart, then 2.8 s apart. Measured over one gap that
        // is either infinite or half the link; over the window it's the link.
        let mut w = adaptive(60 * MS);
        let mut now = Instant::now();
        w.on_dispatch(now, CHUNK);
        for i in 0..16 {
            now += if i % 2 == 0 {
                Duration::from_millis(2_796)
            } else {
                Duration::ZERO
            };
            w.on_delivery(now, now, CHUNK, 0);
        }
        let rate = w.rate().unwrap();
        assert!((300e3..480e3).contains(&rate), "rate {rate}");
    }

    #[test]
    fn a_huge_negotiate_rtt_is_capped_by_the_reads_themselves() {
        // A NEGOTIATE that took 5 s (a NAS waking up) must not budget 5 s of
        // queue on a slow link once a READ has come back faster.
        let mut w = adaptive(Duration::from_secs(5));
        let mut now = Instant::now();
        w.on_dispatch(now, CHUNK);
        now += Duration::from_millis(1_460);
        w.on_delivery(now, now - Duration::from_millis(1_460), CHUNK, 0);
        assert_eq!(w.rtt(), Duration::from_millis(1_460));
    }

    #[test]
    fn a_rate_from_the_last_download_opens_the_window_before_the_first_answer() {
        // A 1 MiB file at +60 ms: without a hint its second READ waits for the
        // first answer, a whole round trip.
        let hint = LinkHint {
            rtt: Some(60 * MS),
            rate: Some(30e6),
        };
        let mut w = Window::new(ReadAhead::Adaptive, CHUNK, hint);
        let now = Instant::now();
        w.on_dispatch(now, CHUNK);
        assert_eq!(w.decide(now, 1, u64::from(CHUNK), CHUNK), Dispatch::Now);

        // A slow link's hint keeps it at one.
        let slow = LinkHint {
            rtt: Some(60 * MS),
            rate: Some(375e3),
        };
        let mut w = Window::new(ReadAhead::Adaptive, CHUNK, slow);
        w.on_dispatch(now, CHUNK);
        assert!(matches!(
            w.decide(now, 1, u64::from(CHUNK), CHUNK),
            Dispatch::At(_)
        ));
    }

    #[test]
    fn a_stale_hint_gives_way_to_the_first_measurement() {
        // The hint says fast; the link is now slow. The first delivery is
        // what counts from then on.
        let hint = LinkHint {
            rtt: Some(60 * MS),
            rate: Some(50e6),
        };
        let mut w = Window::new(ReadAhead::Adaptive, CHUNK, hint);
        let t0 = Instant::now();
        w.on_dispatch(t0, CHUNK);
        let t1 = t0 + Duration::from_millis(1_460);
        w.on_delivery(t1, t0, CHUNK, 0);
        let rate = w.rate().unwrap();
        assert!((350e3..370e3).contains(&rate), "rate {rate}");
    }

    #[test]
    fn only_a_multi_chunk_measurement_is_shared() {
        let mut w = adaptive(60 * MS);
        let t0 = Instant::now();
        w.on_dispatch(t0, CHUNK);
        w.on_delivery(t0 + 70 * MS, t0, CHUNK, 0);
        assert_eq!(w.rate_to_share(), None, "one READ is mostly its round trip");
        w.on_dispatch(t0 + 70 * MS, CHUNK);
        w.on_delivery(t0 + 140 * MS, t0 + 70 * MS, CHUNK, 0);
        assert!(w.rate_to_share().is_some());
    }

    #[test]
    fn a_chunk_bigger_than_the_cap_still_gets_one_read() {
        let w = Window::new(ReadAhead::Adaptive, 8 << 20, LinkHint::default());
        assert_eq!(w.decide(Instant::now(), 0, 0, 8 << 20), Dispatch::Now);
    }
}
