//! How much a streaming download keeps on the wire.
//!
//! [`ReadAhead`] is the public knob; `Window` is the controller a
//! [`FileDownload`](crate::FileDownload) consults before every READ it sends.
//! Uploads pace through the same controller (`write_behind.rs`), since the
//! arithmetic doesn't care which way the payload flows. The controller is pure
//! (it takes instants, it never reads a clock or sends anything), so its
//! behavior is pinned by deterministic tests below, against a simulated link
//! that can reorder, jitter, and freeze answers. Its tunables live in
//! `client/tuning.rs`.
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
//! it keeps about `link rate × (RTT + headroom)` bytes requested but not yet
//! arrived, at least one READ and at most [`ADAPTIVE_MAX_IN_FLIGHT`]. On a fast
//! link that reaches the cap within a few round trips; on a slow one it stays at
//! about one chunk, and the next READ goes out shortly before the current one
//! finishes arriving, so the pipe never idles and nothing queues behind more
//! than about one chunk plus the headroom's worth of transfer.
//!
//! # The headroom is learned per connection
//!
//! The headroom is the margin that absorbs server stalls (a disk seek, a busy
//! CPU) and link jitter, and it's also the price: roughly how long anything
//! else on the connection waits beyond the chunk already arriving. No one
//! value fits every link (0.25.1 shipped a fixed 250 ms), so the window learns
//! it from how late answers come, on the connection, per direction: tens of
//! milliseconds on a steady link, more where answers stall, and back down once
//! they stop. See `Window` § Learning the headroom. The parameters were
//! picked by minimax regret over a grid of shaped links against Samba
//! (`benchmarks/read-ahead/results/self-tuning.md`): on a steady 30 MB/s link
//! a `stat` behind a download waits 52–66 ms where 0.25.1 made it wait
//! 141 ms, with the same throughput on every link in the grid.
//!
//! # The rate is the link's, not the transfer's
//!
//! The same rate is left on the connection for the next transfer, and
//! consumers read it through `quick_read_limit` to choose between one compound
//! READ and a stream. A transfer's own pace reads far below the link whenever
//! something else set it: a 4 MiB download at +60 ms on a ~1 GB/s link went
//! at about 24 MB/s, because eight READs in flight never fill that link's
//! 60 MB bandwidth-delay product. So the window measures the link from answers
//! that queued behind each other on the wire, timed as the receiver read them
//! off it (see `Window` § Measuring the link). An estimate may read low,
//! never high: too high sends as one READ a file the link can't move quickly.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

use crate::client::tuning::{Estimator, Headroom, LearnedHeadroom, RateMeasure, Tuning};

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
/// READs would be 1,024 of them, each holding a credit and a waiter). Caps an
/// adaptive upload's WRITEs the same way.
pub(crate) const ADAPTIVE_MAX_REQUESTS: usize = 32;

/// How long a file may hold the connection as one frame: the time budget
/// behind [`quick_read_limit`] and the upload one-frame cut-off.
///
/// A product latency budget, not a transfer margin: how long a listing may
/// wait behind one compound READ or WRITE. It stays fixed while a transfer's
/// headroom is learned, because the two answer different questions. On a
/// quiet LAN the learned headroom shrinks to tens of ms, and a cut-off that
/// shrank with it would stream small files, each costing extra round trips,
/// to save a listing a wait nobody notices.
pub(crate) const QUICK_FRAME_BUDGET: Duration = Duration::from_millis(250);

/// How many recent gaps between answers the rate is measured over.
///
/// Samba completes concurrent READs in whatever order they finish, and a
/// server's disk and a busy receiver both make answers bunch up. A rate taken
/// over one gap would swing with every burst; eight answers span a full
/// window at the cap, which is where reordering happens.
const RATE_SAMPLES: usize = 8;

/// How many recent answers a window remembers for its rate. Twice
/// [`RATE_SAMPLES`], so the full-pipe estimate still has samples to draw on
/// while a stretch of answers the window or the consumer paced passes through.
const ARRIVAL_MEMORY: usize = 2 * RATE_SAMPLES;

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
    /// Keeps about `link rate × (RTT + headroom)` bytes requested but not yet
    /// arrived: never fewer than one READ, never more than
    /// [`ADAPTIVE_MAX_IN_FLIGHT`] requested but not yet delivered. The link
    /// rate is re-measured over the last eight answers that queued behind
    /// each other on the wire, and the RTT is the connection's NEGOTIATE round
    /// trip or the fastest READ so far, whichever is smaller. The headroom is
    /// learned per connection from how late answers come: tens of
    /// milliseconds on a steady link, up to 500 ms where answers stall. See
    /// the [module docs](crate::client::read_ahead) for the measurements
    /// behind it.
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
}

/// The policy a [`Window`] runs, whichever way it paces: what [`ReadAhead`]
/// and [`WriteBehind`](crate::WriteBehind) both come down to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pacing {
    Adaptive,
    Fixed(usize),
}

impl Pacing {
    /// The fixed window this policy pins, if any.
    pub(crate) fn fixed_window(self) -> Option<usize> {
        match self {
            Self::Adaptive => None,
            Self::Fixed(n) => Some(n.max(1)),
        }
    }
}

impl From<ReadAhead> for Pacing {
    fn from(policy: ReadAhead) -> Self {
        match policy {
            ReadAhead::Adaptive => Self::Adaptive,
            ReadAhead::Fixed(n) => Self::Fixed(n),
        }
    }
}

/// What a transfer should do about its next request: a READ for a download,
/// a WRITE for an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dispatch {
    /// Send it now.
    Now,
    /// Send it at this instant if nothing in flight has landed by then.
    At(Instant),
    /// Nothing to send until a request in flight lands (for a download, the
    /// head READ, since chunks are delivered in file order).
    AfterHead,
}

/// The largest read worth making as one READ: what the link moves in
/// [`QUICK_FRAME_BUDGET`] at `rate` bytes/s, never less than one download chunk and never
/// more than `max_read`. Behind
/// [`Connection::quick_read_limit`](crate::client::Connection::quick_read_limit),
/// which documents the reasoning.
pub(crate) fn quick_read_limit(rate: Option<f64>, max_read: u32) -> u64 {
    quick_limit(rate, DOWNLOAD_CHUNK_SIZE, u64::from(max_read))
}

/// What the link moves in [`QUICK_FRAME_BUDGET`] at `rate` bytes/s, at least `chunk`
/// and at most `cap`: the one-frame cut-off in either direction.
pub(crate) fn quick_limit(rate: Option<f64>, chunk: u32, cap: u64) -> u64 {
    let in_budget = rate.map_or(0, |rate| (rate * QUICK_FRAME_BUDGET.as_secs_f64()) as u64);
    u64::from(chunk).max(in_budget).min(cap)
}

/// What the connection already knows about the link when a transfer starts.
///
/// Per connection and per direction, with the same expiry and revival rules
/// for every field, so anything else worth carrying from one transfer to the
/// next belongs here.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LinkHint {
    /// The NEGOTIATE round trip, if one was measured.
    pub(crate) rtt: Option<Duration>,
    /// The rate a recent transfer the same way on the same connection
    /// measured, in bytes per second.
    pub(crate) rate: Option<f64>,
    /// How late answers came for recent transfers the same way on the same
    /// connection: what the learned headroom starts from.
    pub(crate) lateness: Option<Lateness>,
}

/// How many peaks [`Lateness`] keeps for its windowed max.
const PEAK_SLOTS: usize = 16;

/// One lateness sample the windowed max still remembers.
#[derive(Debug, Clone, Copy)]
struct Peak {
    late: Duration,
    /// When the answer it came from arrived.
    at: Instant,
    /// Which answer it was, counting every sample this memory has taken.
    answer: u64,
}

/// What a connection has learned about how late answers come, for the
/// learned headroom. Both estimators are kept up to date whichever one the
/// tuning picks, so switching tuning never starts from nothing.
///
/// `Copy`, so a finished transfer hands it to the connection and the next
/// transfer carries on from it as if the two were one stream.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lateness {
    /// Samples in arrival order whose lateness no later sample has matched:
    /// the classic sliding-window-maximum queue, so the first one still
    /// remembered is the max. Oldest first; `peaks[..peak_count]` is live.
    peaks: [Option<Peak>; PEAK_SLOTS],
    peak_count: usize,
    /// Samples taken so far.
    answers: u64,
    /// [`Estimator::MeanDeviation`]'s smoothed mean and mean deviation, in
    /// seconds.
    mean: f64,
    deviation: f64,
}

impl Lateness {
    /// Nothing learned yet: the headroom is `learned.cold` until samples say
    /// otherwise.
    pub(crate) fn cold(learned: &LearnedHeadroom) -> Self {
        Self {
            peaks: [None; PEAK_SLOTS],
            peak_count: 0,
            answers: 0,
            mean: learned.cold.as_secs_f64(),
            deviation: 0.0,
        }
    }

    /// One answer, arrived at `at`, came `late` after an ideal full pipe
    /// would have delivered it.
    fn observe(&mut self, late: Duration, at: Instant, learned: &LearnedHeadroom) {
        self.answers += 1;
        // RFC 6298 § 2.3: the deviation from the old mean first.
        let sample = late.as_secs_f64();
        self.deviation += ((sample - self.mean).abs() - self.deviation) / 4.0;
        self.mean += (sample - self.mean) / 8.0;

        if let Estimator::WindowedMax { answers, span } = learned.estimator {
            // Forget what fell out of both memories.
            let expired = |p: &Peak| {
                self.answers - p.answer > u64::from(answers)
                    && at.saturating_duration_since(p.at) > span
            };
            let live = self.peaks[..self.peak_count]
                .iter()
                .flatten()
                .position(|p| !expired(p))
                .unwrap_or(self.peak_count);
            self.peaks.copy_within(live..self.peak_count, 0);
            self.peak_count -= live;
        }
        // A sample at least as late as a newer one can never be the max again.
        while self.peak_count > 0 && self.peaks[self.peak_count - 1].is_some_and(|p| p.late <= late)
        {
            self.peak_count -= 1;
        }
        // Full: the newest (and smallest) gives way. That only drops a value
        // that would have been the max once every older one expired, and only
        // after 16 samples each smaller than the one before.
        if self.peak_count == PEAK_SLOTS {
            self.peak_count -= 1;
        }
        self.peaks[self.peak_count] = Some(Peak {
            late,
            at,
            answer: self.answers,
        });
        self.peak_count += 1;
    }

    /// The headroom these samples call for under `learned`.
    fn headroom(&self, learned: &LearnedHeadroom) -> Duration {
        let estimate = match learned.estimator {
            Estimator::WindowedMax { answers, .. } => {
                let max = self.peaks[0]
                    .filter(|_| self.peak_count > 0)
                    .map(|p| p.late);
                let warm = self.answers >= u64::from(answers);
                match (max, warm) {
                    (Some(max), true) => max,
                    (Some(max), false) => max.max(learned.cold),
                    (None, _) => learned.cold,
                }
            }
            Estimator::MeanDeviation { k } => {
                Duration::try_from_secs_f64(self.mean + k * self.deviation)
                    .unwrap_or(learned.ceiling)
            }
        };
        estimate.clamp(learned.floor, learned.ceiling.max(learned.floor))
    }
}

/// One answer, as the rate measurement sees it.
#[derive(Debug, Clone, Copy)]
struct Arrival {
    /// When its request went out.
    sent: Instant,
    /// When its frame came off the wire.
    at: Instant,
    len: u32,
    /// Whether the learned headroom has taken its lateness yet.
    scored: bool,
}

/// The pacing controller for one transfer, download or upload.
///
/// A download reports every READ it sends and every chunk it delivers; an
/// upload reports every WRITE it hands the connection and every WRITE the
/// server confirms. In return this says when the next request should go out.
/// The docs below speak of READs; for an upload read WRITEs, with
/// "delivered" meaning confirmed: a WRITE's bytes are on their way until the
/// server has them, which its response says. "In flight" below means
/// requested but not yet delivered to the caller, which is what the memory
/// and window bounds count. The adaptive target counts something narrower:
/// bytes estimated to be still on their way (`unarrived`), drained at the
/// measured rate since the last event. That is what lets the next READ leave
/// shortly before the current one finishes arriving, instead of one round trip
/// after.
///
/// # Measuring the link
///
/// The rate is the link's capacity, both for pacing and for the hint the
/// connection hands the next transfer (and `quick_read_limit` /
/// `quick_write_limit` with it). Two things make that different from how fast
/// this transfer happened to go:
///
/// - **Only a full pipe measures the link.** While the window ramps, or sits
///   capped below the bandwidth-delay product (4 MiB against 60 MB at +60 ms
///   on a 1 GB/s link), answers come at the window's pace, and a rate over
///   them is the window's. BBR calls these samples application-limited. The
///   gap between answer n−1 and answer n measures the link only if READ n
///   reached the server before answer n−1 had finished leaving it, so that n
///   went out right behind n−1. That holds when READ n was sent at least one
///   round trip before answer n−1 arrived, and only such gaps count: their
///   bytes over their summed gaps, across the last [`RATE_SAMPLES`] of them,
///   so bursts average out.
/// - **Arrival, not delivery.** Each answer is timed when the receiver task
///   read it off the wire. A consumer slow to take chunks would otherwise read
///   the link low, and one catching up after a stall takes a burst of
///   long-arrived chunks at once and reads it several times too high.
///
/// The round trip used is [`rtt`](Self::rtt), and errors in it can only lower
/// the estimate. Guessed long, it discards gaps that did queue: fewer samples,
/// none wrong. Guessed short, it admits gaps during which the link sat idle
/// waiting for the request, and those are longer than the link's time for the
/// bytes. That matters because an overestimate is the costly direction: it
/// makes `quick_read_limit` send as one READ a file the link can't move
/// quickly, which is the head-of-line blocking this controller exists to
/// prevent.
///
/// When no gap qualifies (a download too short to overlap its READs), the
/// rate is the arrivals' own pace over the last few answers, which is a lower
/// bound. Where both exist the larger one wins, since each is at most what
/// the link carries. Before a second answer, the first READ's own
/// dispatch-to-arrival rate stands in, and before that the hint.
///
/// Known limit: the stamps are taken by the receiver task, so a process stall
/// long enough to leave several answers waiting in the socket stamps them
/// together, and a gap between two of them reads short. Summing over several
/// gaps keeps that small, and it can only bite once a stall outlasts a
/// chunk's time on the wire, which on the slow links where an overestimate
/// costs most is seconds.
///
/// # Learning the headroom
///
/// With [`Headroom::Learned`] (what ships), the margin comes from how late
/// answers come compared with an ideal full pipe, the same idea as TCP's
/// retransmit timer learning from measured variation. Each answer is scored
/// once, and in the order answers came off the wire:
///
/// - **Lateness is idle link time.** An answer is due no sooner than a round
///   trip plus its own time on the wire after its request went out, and no
///   sooner than its time on the wire after the answer before it. Arriving
///   later than both means the link sat idle waiting for it. Samba answering
///   concurrent READs out of order still sends them back to back, so a
///   reordered burst is on time by construction, and so is a stretch the
///   window itself paced.
/// - **Scored only once nothing unheard-of can precede it.** Chunks are
///   delivered in file order, so the window hears of an answer that arrived
///   early only once the chunks ahead of it are taken. Scoring an answer
///   before that would compare it with the wrong neighbor and read every
///   swapped pair as a chunk's time of lateness. An answer is scored once
///   every request still in flight went out less than a round trip before it
///   arrived: none of those can have beaten it.
/// - **A stall is measured whole.** A stall the backlog already covers leaves
///   no idle time at all, and one it partly covers shows only the uncovered
///   part. So a late answer counts its idle time plus how long the answer
///   before it waited behind others, which is the backlog the stall ate
///   through first. Without that, the headroom settles just under the stall
///   it keeps failing to cover.
/// - **A wobble is not a stall.** On a full pipe every answer has the
///   window's own standing queue ahead of it, so an answer stamped a few ms
///   late, or a rate estimate a few percent high, read as lateness would also
///   count that whole queue, and the headroom would stay pinned at the queue
///   it built (113–118 ms against a 30 ms floor on a steady 30 MB/s link in
///   the benchmark). Idle time under 5 ms or a quarter of the answer's own
///   time on the wire, whichever is longer, counts as none
///   (`LearnedHeadroom::noise_floor` / `noise_share`).
/// - **A backlog follows an on-time answer.** After a stall the held answers
///   come back to back, so only the first is late. Late answers in a row
///   mean the link slowed, and each waited behind the late one before it,
///   which is no backlog; counted as one, a three-answer slowdown compounded
///   to 1,072 ms.
/// - **The first flight isn't scored.** What a transfer sends before its
///   first answer lands crosses while TCP restarts slow start after an idle
///   spell (RFC 5681 § 4.1), at a fraction of the rate, and more queued
///   ahead couldn't have made it faster. Scored, one idle spell taught a
///   3 MB/s uplink ~190 ms of headroom, which it kept for the whole file.
/// - **The memory outlasts covered stalls.** Since a covered stall is
///   invisible, a memory that forgot a stall once it stopped showing would
///   shrink straight back under it. The windowed max keeps a sample for
///   `answers` answers or `span` of time, whichever reaches further back.
///   Until `answers` samples exist, the cold headroom counts as one of them.
///
/// The memory ([`Lateness`]) is shared with the next transfer the same way on
/// the connection, so a folder of small files learns as one stream, and the
/// cold headroom only applies to a connection's first transfers.
///
/// The margin also grows the window while it ramps: before a pair of answers
/// has queued behind each other, the rate is a lower bound (one READ over its
/// round trip), and only a second READ sent with the first answer measures
/// the link. A 30 ms margin sends one only when a chunk crosses the wire in
/// under 30 ms, so until a full-pipe gap is in hand the margin is at least the
/// cold headroom.
#[derive(Debug)]
pub(crate) struct Window {
    policy: Pacing,
    tuning: Tuning,
    max_in_flight: u64,
    hint: LinkHint,
    /// The fastest dispatch-to-arrival time seen, an upper bound on the RTT.
    fastest_read: Option<Duration>,
    /// Recent answers, oldest arrival first (answers can arrive in another
    /// order than they're delivered).
    arrivals: VecDeque<Arrival>,
    /// How late answers come, carried over from the connection.
    lateness: Lateness,
    /// Whether this transfer has scored an answer's lateness yet.
    learned: bool,
    /// The latest answer scored for lateness, by arrival, and how late it
    /// scored.
    last_scored: Option<(Arrival, Duration)>,
    /// When this transfer's first answer landed.
    first_arrival: Option<Instant>,
    /// Whether `bytes_in_flight` counts only requests not yet answered
    /// (`with_unanswered_in_flight`).
    in_flight_is_unanswered: bool,
    /// When each request still in flight went out, oldest first.
    sent_in_flight: VecDeque<Instant>,
    /// `(when, total bytes delivered by then)`, oldest first. The first entry
    /// is the first dispatch, with zero bytes. [`RateMeasure::Deliveries`]
    /// only.
    deliveries: VecDeque<(Instant, u64)>,
    delivered: u64,
    /// Estimated bytes still on their way, as of `unarrived_at`.
    unarrived: f64,
    unarrived_at: Option<Instant>,
}

impl Window {
    pub(crate) fn new(policy: impl Into<Pacing>, chunk_size: u32, hint: LinkHint) -> Self {
        Self::with_tuning(policy, chunk_size, hint, Tuning::current())
    }

    pub(crate) fn with_tuning(
        policy: impl Into<Pacing>,
        chunk_size: u32,
        hint: LinkHint,
        tuning: Tuning,
    ) -> Self {
        Self {
            policy: policy.into(),
            tuning,
            // A chunk bigger than the cap still gets one READ in flight.
            max_in_flight: ADAPTIVE_MAX_IN_FLIGHT.max(u64::from(chunk_size)),
            hint,
            fastest_read: None,
            arrivals: VecDeque::with_capacity(ARRIVAL_MEMORY + 1),
            lateness: hint.lateness.unwrap_or_else(|| {
                Lateness::cold(&match tuning.headroom {
                    Headroom::Learned(learned) => learned,
                    Headroom::Fixed(_) => LearnedHeadroom::SHIPPING,
                })
            }),
            learned: false,
            last_scored: None,
            first_arrival: None,
            in_flight_is_unanswered: false,
            sent_in_flight: VecDeque::with_capacity(ADAPTIVE_MAX_REQUESTS),
            deliveries: VecDeque::with_capacity(RATE_SAMPLES + 1),
            delivered: 0,
            unarrived: 0.0,
            unarrived_at: None,
        }
    }

    /// Declare that the `bytes_in_flight` passed to `on_delivery` counts only
    /// requests not yet answered, so the window can correct its open-loop
    /// estimate of what's still on its way against it.
    ///
    /// True for uploads: `WritePipe` handles each confirmation as it comes.
    /// Not for downloads: chunks are delivered in file order, so a READ that
    /// Samba answered early still counts as in flight until the ones ahead of
    /// it are taken, and correcting against that holds READs back on a
    /// reordering server until the link really idles (the headroom then
    /// learned 291 ms on a link that never needed any).
    pub(crate) fn with_unanswered_in_flight(mut self) -> Self {
        self.in_flight_is_unanswered = true;
        self
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
        if reads_in_flight >= ADAPTIVE_MAX_REQUESTS
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
        if self.tuning.rate == RateMeasure::Deliveries && self.deliveries.is_empty() {
            self.deliveries.push_back((now, 0));
        }
        self.drain(now);
        self.unarrived += f64::from(len);
        self.sent_in_flight.push_back(now);
    }

    /// A chunk of `len` bytes, requested at `dispatched_at` and arrived at
    /// `arrived_at`, was delivered at `now`, leaving `bytes_in_flight`
    /// requested but undelivered.
    pub(crate) fn on_delivery(
        &mut self,
        now: Instant,
        dispatched_at: Instant,
        arrived_at: Instant,
        len: u32,
        bytes_in_flight: u64,
    ) {
        self.drain(now);
        // Everything delivered has arrived, so what's still on its way is at
        // most what's still in flight.
        self.unarrived = self.unarrived.min(bytes_in_flight as f64);
        // And, where `bytes_in_flight` counts only unanswered requests, at
        // least that less what the link could have carried since this answer
        // landed. The drain alone is open-loop: when the link starts slower
        // than the rate it assumes (TCP restarting slow start after an idle
        // spell, another flow on the link), it counts bytes as landed that
        // are still queued, and the window kept that surplus queued for good
        // (1.5 MiB, a `stat` waiting ~520 ms, on a 3 MB/s uplink). See
        // `with_unanswered_in_flight` for why downloads don't get it.
        if let Some(rate) = self.rate().filter(|_| self.in_flight_is_unanswered) {
            let since = now.saturating_duration_since(arrived_at).as_secs_f64();
            self.unarrived = self.unarrived.max(bytes_in_flight as f64 - rate * since);
        }

        let landed = match self.tuning.rate {
            RateMeasure::Deliveries => now,
            RateMeasure::LinkCapacity => arrived_at,
        };
        let took = landed.saturating_duration_since(dispatched_at);
        self.fastest_read = Some(self.fastest_read.map_or(took, |f| f.min(took)));

        if self.tuning.rate == RateMeasure::Deliveries {
            self.delivered += u64::from(len);
            self.deliveries.push_back((now, self.delivered));
            while self.deliveries.len() > RATE_SAMPLES + 1 {
                self.deliveries.pop_front();
            }
        }
        if let Some(i) = self.sent_in_flight.iter().position(|&s| s == dispatched_at) {
            self.sent_in_flight.remove(i);
        }
        if bytes_in_flight == 0 {
            // Nothing is in flight, whatever went unmatched.
            self.sent_in_flight.clear();
        }
        self.first_arrival = Some(self.first_arrival.map_or(arrived_at, |f| f.min(arrived_at)));
        let arrival = Arrival {
            sent: dispatched_at,
            at: arrived_at,
            len,
            scored: false,
        };
        let after = self.arrivals.iter().rposition(|a| a.at <= arrived_at);
        self.arrivals.insert(after.map_or(0, |i| i + 1), arrival);
        while self.arrivals.len() > ARRIVAL_MEMORY {
            if let Some(oldest) = self.arrivals.pop_front().filter(|a| !a.scored) {
                self.score(oldest);
            }
        }
        self.settle();
    }

    /// Score the lateness of every answer nothing unheard-of can still
    /// precede, in arrival order.
    fn settle(&mut self) {
        // No answer can arrive sooner than a round trip after its request, so
        // nothing still in flight can have come off the wire before this.
        let horizon = self.sent_in_flight.front().map(|&sent| sent + self.rtt());
        for i in 0..self.arrivals.len() {
            let arrival = self.arrivals[i];
            if arrival.scored {
                continue;
            }
            if horizon.is_some_and(|horizon| arrival.at >= horizon) {
                break;
            }
            self.score(arrival);
            self.arrivals[i].scored = true;
        }
    }

    /// Feed the learned headroom how late `arrival` came against an ideal
    /// full pipe: no earlier than one round trip and its own time on the
    /// wire after its request went out, and no earlier than its time on the
    /// wire after the answer before it. A late answer also counts the backlog
    /// the stall ate through first (§ Learning the headroom).
    fn score(&mut self, arrival: Arrival) {
        let Headroom::Learned(learned) = self.tuning.headroom else {
            return;
        };
        let (rtt, rate) = (self.rtt(), self.rate());
        // The soonest an answer can land: a round trip plus its own bytes.
        let soonest = |a: &Arrival| {
            let on_the_wire = rate.map_or(Duration::ZERO, |rate| {
                Duration::from_secs_f64(f64::from(a.len) / rate)
            });
            (a.sent + rtt + on_the_wire, on_the_wire)
        };
        let (mut ideal, on_the_wire) = soonest(&arrival);
        let mut queued_ahead = Duration::ZERO;
        if let Some((previous, previous_late)) = self.last_scored {
            ideal = ideal.max(previous.at + on_the_wire);
            // A backlog only if the answer before was on time. After a stall,
            // the held answers come back to back, so only the first is late;
            // late answers in a row mean the link slowed, and each then waited
            // behind the late one before it, which is no backlog anything
            // queued could have used. Counted anyway, every late answer in a
            // run added onto the next (352, 505, 795 ms on a link that slowed
            // to a third of its rate for three answers).
            if previous_late.is_zero() {
                queued_ahead = previous.at.saturating_duration_since(soonest(&previous).0);
            }
        }
        let idle = arrival.at.saturating_duration_since(ideal);
        let noise = learned
            .noise_floor
            .max(on_the_wire.mul_f64(learned.noise_share));
        let late = if idle < noise {
            Duration::ZERO
        } else {
            idle + queued_ahead
        };
        // The first flight (everything sent before this transfer's first
        // answer landed) says how fast TCP ramped, not how the server
        // behaves: after an idle spell longer than its retransmit timeout,
        // TCP restarts slow start (RFC 5681 § 4.1), so those answers cross at
        // a fraction of the rate, and more queued ahead of them couldn't have
        // made them faster. Scored, one idle spell taught the headroom
        // ~190 ms that it then kept for the rest of the file.
        let first_flight = self.first_arrival.is_some_and(|first| arrival.sent < first);
        if !first_flight {
            self.lateness.observe(late, arrival.at, &learned);
            self.learned = true;
        }
        if self
            .last_scored
            .is_none_or(|(previous, _)| previous.at <= arrival.at)
        {
            self.last_scored = Some((arrival, late));
        }
    }

    /// The rate to pace by, in bytes per second. Before the first delivery,
    /// the connection's hint stands in.
    pub(crate) fn rate(&self) -> Option<f64> {
        let measured = match self.tuning.rate {
            RateMeasure::Deliveries => self.delivery_rate(),
            RateMeasure::LinkCapacity => self.capacity().or_else(|| self.first_answer_rate()),
        };
        measured.or(self.hint.rate)
    }

    /// The rate worth handing to the next transfer on this connection: one
    /// measured over at least two answers. A single request's rate is mostly
    /// its round trip, and recording it after every small file would keep
    /// dragging the hint down to that.
    pub(crate) fn rate_to_share(&self) -> Option<f64> {
        match self.tuning.rate {
            RateMeasure::Deliveries => {
                if self.deliveries.len() < 3 {
                    return None;
                }
                self.delivery_rate()
            }
            RateMeasure::LinkCapacity => self.capacity(),
        }
    }

    /// [`RateMeasure::Deliveries`]: bytes delivered since the oldest entry,
    /// over the time since it.
    fn delivery_rate(&self) -> Option<f64> {
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

    /// What the link carries, as far as two or more answers show it: the
    /// larger of the full-pipe estimate and the arrivals' own pace.
    fn capacity(&self) -> Option<f64> {
        match (self.full_pipe_rate(), self.arrival_rate()) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    /// Bytes over time across the gaps that measured the link: an answer
    /// whose request was sent at least one round trip before the answer
    /// ahead of it arrived, and so queued behind it at the server.
    fn full_pipe_rate(&self) -> Option<f64> {
        let rtt = self.rtt();
        let (mut bytes, mut span, mut samples) = (0u64, Duration::ZERO, 0);
        let newest_first = self.arrivals.iter().rev();
        for (answer, ahead) in newest_first.clone().zip(newest_first.skip(1)) {
            let queued = answer
                .sent
                .checked_add(rtt)
                .is_some_and(|reached| reached <= ahead.at);
            if !queued {
                continue;
            }
            bytes += u64::from(answer.len);
            span += answer.at.saturating_duration_since(ahead.at);
            samples += 1;
            if samples == RATE_SAMPLES {
                break;
            }
        }
        (samples > 0).then(|| bytes as f64 / span.max(MIN_RATE_SPAN).as_secs_f64())
    }

    /// The arrivals' own pace over the last few answers: bytes after the
    /// first one, over the time from the first to the last. What the link
    /// did carry, so never more than it can.
    fn arrival_rate(&self) -> Option<f64> {
        let skip = self.arrivals.len().saturating_sub(RATE_SAMPLES + 1);
        let mut recent = self.arrivals.iter().skip(skip);
        let first = recent.next()?;
        let (bytes, last) = recent.fold((0u64, None), |(bytes, _), a| {
            (bytes + u64::from(a.len), Some(a.at))
        });
        let span = last?.saturating_duration_since(first.at).max(MIN_RATE_SPAN);
        Some(bytes as f64 / span.as_secs_f64())
    }

    /// The first answer's own rate, dispatch to arrival: mostly its round
    /// trip, so a floor, but the only measurement there is until a second.
    fn first_answer_rate(&self) -> Option<f64> {
        let first = self.arrivals.front()?;
        let took = first
            .at
            .saturating_duration_since(first.sent)
            .max(MIN_RATE_SPAN);
        Some(f64::from(first.len) / took.as_secs_f64())
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
        Some((rate * (self.rtt() + self.headroom()).as_secs_f64()) as u64)
    }

    /// What this transfer learned about how late answers come, for the
    /// next transfer on the connection.
    pub(crate) fn lateness_to_share(&self) -> Option<Lateness> {
        self.learned.then_some(self.lateness)
    }

    /// The margin on top of the round trip the target budgets for.
    pub(crate) fn headroom(&self) -> Duration {
        match self.tuning.headroom {
            Headroom::Fixed(headroom) => headroom,
            Headroom::Learned(learned) => {
                let headroom = self.lateness.headroom(&learned);
                // Until answers have queued behind each other, the rate is a
                // lower bound and the margin is what sends the second READ
                // that measures the link. See § Learning the headroom.
                if self.full_pipe_rate().is_some() {
                    headroom
                } else {
                    headroom.max(learned.cold)
                }
            }
        }
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

    /// Drives a [`Window`] the way a download does, against a simulated link.
    /// No clocks, no sleeps.
    ///
    /// Each READ reaches the server half a round trip after it's sent, and
    /// its answer is ready `server_delay(i)` later (`i` counting READs in the
    /// order they were sent). The link carries ready answers one at a time at
    /// `rate × rate_wobble(i)` bytes/s, earliest-ready first, so uneven server delays reorder
    /// them the way Samba does; each lands half a round trip after its last
    /// byte leaves. The consumer spends `consumer_delay(k)` on chunk `k`
    /// before asking for the next, and the window only hears about a chunk
    /// when the consumer takes it, as in `FileDownload`. A freeze (a disk
    /// stall, a busy server CPU) holds back every answer that would have
    /// been ready during it until it ends; answers already ready keep
    /// flowing, as from a socket buffer. Answer `k` (in file order) is
    /// stamped `stamp_delay(k)` after it lands, as a receiver task that got
    /// scheduled late would. The delays default to zero and there are no
    /// freezes; the `with_*` builders set them.
    struct Link {
        rtt: Duration,
        rate: f64,
        server_delay: Box<dyn Fn(usize) -> Duration>,
        consumer_delay: Box<dyn Fn(usize) -> Duration>,
        stamp_delay: Box<dyn Fn(usize) -> Duration>,
        rate_wobble: Box<dyn Fn(usize) -> f64>,
        /// `(start, length)`, as offsets from the start of the download.
        freezes: Vec<(Duration, Duration)>,
    }

    struct Run {
        /// Delivery instants, as offsets from the start.
        delivered_at: Vec<Duration>,
        /// The most READs in flight at once.
        peak_reads: usize,
        /// The most bytes queued ahead of a request sent at any instant: what a
        /// `stat` on the same connection would have waited behind.
        worst_queue: u64,
        /// What a request sent right after each READ would have queued behind.
        queued: Vec<u64>,
        /// Every rate the window offered the connection, one per delivery.
        shared: Vec<f64>,
        /// When the most READs were first in flight at once.
        peak_reached_at: Duration,
        /// The window's headroom after each delivery.
        headroom: Vec<Duration>,
    }

    impl Run {
        /// What the connection is left with once the download is over.
        fn last_shared(&self) -> f64 {
            *self.shared.last().expect("the download shared a rate")
        }
    }

    /// One READ in the simulation.
    struct SimRead {
        len: u32,
        sent: Instant,
        /// When its answer is ready at the server.
        ready: Instant,
        /// When its answer lands, as scheduled by the latest `schedule`.
        lands: Instant,
    }

    impl Link {
        fn new(rtt: Duration, rate: f64) -> Self {
            Self {
                rtt,
                rate,
                server_delay: Box::new(|_| Duration::ZERO),
                consumer_delay: Box::new(|_| Duration::ZERO),
                stamp_delay: Box::new(|_| Duration::ZERO),
                rate_wobble: Box::new(|_| 1.0),
                freezes: Vec::new(),
            }
        }

        /// Answer `i` (in send order) crosses the link at `rate × wobble(i)`.
        fn with_rate_wobble(mut self, wobble: impl Fn(usize) -> f64 + 'static) -> Self {
            self.rate_wobble = Box::new(wobble);
            self
        }

        fn with_stamp_delay(mut self, delay: impl Fn(usize) -> Duration + 'static) -> Self {
            self.stamp_delay = Box::new(delay);
            self
        }

        /// The server freezes for `length` every `every`, first at `every`,
        /// until `until`.
        fn with_freezes(mut self, every: Duration, length: Duration, until: Duration) -> Self {
            let mut start = every;
            while start < until {
                self.freezes.push((start, length));
                start += every;
            }
            self
        }

        fn with_consumer_delay(mut self, delay: impl Fn(usize) -> Duration + 'static) -> Self {
            self.consumer_delay = Box::new(delay);
            self
        }

        fn with_server_delay(mut self, delay: impl Fn(usize) -> Duration + 'static) -> Self {
            self.server_delay = Box::new(delay);
            self
        }

        /// Lay every answer out on the link, earliest-ready first. A READ sent
        /// later is ready no earlier than half a round trip from its send, so
        /// re-running this after each send never moves an answer that has
        /// already started.
        fn schedule(&self, reads: &mut [SimRead]) -> Instant {
            let mut order: Vec<usize> = (0..reads.len()).collect();
            order.sort_by_key(|&i| (reads[i].ready, i));
            let mut link_free = None::<Instant>;
            for i in order {
                let starts = link_free.map_or(reads[i].ready, |f: Instant| f.max(reads[i].ready));
                let rate = self.rate * (self.rate_wobble)(i);
                let done = starts + Duration::from_secs_f64(f64::from(reads[i].len) / rate);
                reads[i].lands = done + self.rtt / 2;
                link_free = Some(done);
            }
            link_free.unwrap_or_else(Instant::now)
        }

        fn download(&self, window: &mut Window, file: u64, chunk: u32) -> Run {
            let t0 = Instant::now();
            let mut reads: Vec<SimRead> = Vec::new();
            // Indices into `reads`, in file order.
            let mut in_flight: VecDeque<usize> = VecDeque::new();
            let mut next_offset = 0u64;
            let mut now = t0;
            let mut run = Run {
                delivered_at: Vec::new(),
                peak_reads: 0,
                worst_queue: 0,
                queued: Vec::new(),
                shared: Vec::new(),
                peak_reached_at: Duration::ZERO,
                headroom: Vec::new(),
            };
            let bytes_of = |in_flight: &VecDeque<usize>, reads: &[SimRead]| -> u64 {
                in_flight.iter().map(|&i| u64::from(reads[i].len)).sum()
            };
            // Send every READ the window allows at `now`; `Some` when the next
            // one is due at a time rather than after the head.
            let mut send_reads = |now: Instant,
                                  reads: &mut Vec<SimRead>,
                                  in_flight: &mut VecDeque<usize>,
                                  window: &mut Window,
                                  run: &mut Run|
             -> Option<Instant> {
                loop {
                    if next_offset >= file {
                        return None;
                    }
                    let len = (file - next_offset).min(u64::from(chunk)) as u32;
                    let bytes = bytes_of(in_flight, reads);
                    match window.decide(now, in_flight.len(), bytes, len) {
                        Dispatch::Now => {}
                        Dispatch::At(at) => return Some(at),
                        Dispatch::AfterHead => return None,
                    }
                    let mut ready = now + self.rtt / 2 + (self.server_delay)(reads.len());
                    for &(start, length) in &self.freezes {
                        if (t0 + start..t0 + start + length).contains(&ready) {
                            ready = t0 + start + length;
                        }
                    }
                    reads.push(SimRead {
                        len,
                        sent: now,
                        ready,
                        lands: ready,
                    });
                    in_flight.push_back(reads.len() - 1);
                    window.on_dispatch(now, len);
                    next_offset += u64::from(len);
                    if in_flight.len() > run.peak_reads {
                        run.peak_reads = in_flight.len();
                        run.peak_reached_at = now - t0;
                    }
                    // What a request sent now would queue behind on the link.
                    let link_free = self.schedule(reads);
                    let queued = link_free.saturating_duration_since(now + self.rtt / 2);
                    let queued = (queued.as_secs_f64() * self.rate) as u64;
                    run.worst_queue = run.worst_queue.max(queued);
                    run.queued.push(queued);
                }
            };
            for k in 0.. {
                // `next_chunk`: wait for the head, sending READs as they fall
                // due meanwhile.
                let head = loop {
                    let due = send_reads(now, &mut reads, &mut in_flight, window, &mut run);
                    let Some(&head) = in_flight.front() else {
                        return run;
                    };
                    self.schedule(&mut reads);
                    match due {
                        Some(at) if at < reads[head].lands => now = at,
                        _ => break head,
                    }
                };
                in_flight.pop_front();
                let arrived = reads[head].lands + (self.stamp_delay)(k);
                now = now.max(arrived);
                let left = bytes_of(&in_flight, &reads);
                window.on_delivery(now, reads[head].sent, arrived, reads[head].len, left);
                run.delivered_at.push(now - t0);
                run.headroom.push(window.headroom());
                if let Some(rate) = window.rate_to_share() {
                    run.shared.push(rate);
                }
                // `next_chunk` tops the window up before handing the chunk
                // out; then the consumer works on it.
                send_reads(now, &mut reads, &mut in_flight, window, &mut run);
                now += (self.consumer_delay)(k);
            }
            unreachable!()
        }
    }

    fn adaptive(rtt_seed: Duration) -> Window {
        Window::new(
            ReadAhead::Adaptive,
            CHUNK,
            LinkHint {
                rtt: Some(rtt_seed),
                ..LinkHint::default()
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
        let link = Link::new(60 * MS, 50e6);
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
        let link = Link::new(60 * MS, 375e3);
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
        let link = Link::new(20 * MS, 3e6);
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
            w.on_delivery(now, now - 5 * MS, now, CHUNK, 0);
        }
        assert!(w.target().unwrap() >= ADAPTIVE_MAX_IN_FLIGHT);
        // Then the link drops to ~375 KB/s: a chunk every 1.4 s.
        for _ in 0..8 {
            now += Duration::from_millis(1_400);
            w.on_delivery(now, now - 5 * MS, now, CHUNK, 0);
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
            w.on_delivery(now, now - Duration::from_millis(1_400), now, CHUNK, 0);
        }
        assert!(w.target().unwrap() < u64::from(CHUNK));
        for _ in 0..8 {
            now += 5 * MS;
            w.on_delivery(now, now - 5 * MS, now, CHUNK, 0);
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
            w.on_delivery(now, now, now, CHUNK, 0);
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
        // Samba answers two concurrent READs in either order. On a 375 KB/s
        // link the answers still land a chunk's time (1.4 s) apart, but when
        // the later READ's answer comes first it waits for the earlier one,
        // and the pair is delivered together: 0 ms apart, then 2.8 s. Timed
        // by delivery over one gap, that is either unbounded or half the link.
        let mut w = adaptive(60 * MS);
        let t0 = Instant::now();
        let slot = |n: u32| t0 + Duration::from_millis(1_398) * (n + 1);
        for pair in 0..8 {
            let (early, late) = (slot(2 * pair), slot(2 * pair + 1));
            // Both READs went out together, well before either answer.
            let sent = early - Duration::from_millis(700);
            w.on_dispatch(sent, CHUNK);
            w.on_dispatch(sent, CHUNK);
            // The file-order-first READ is answered second; both are
            // delivered as it lands.
            w.on_delivery(late, sent, late, CHUNK, u64::from(CHUNK));
            w.on_delivery(late, sent, early, CHUNK, 0);
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
        w.on_delivery(now, now - Duration::from_millis(1_460), now, CHUNK, 0);
        assert_eq!(w.rtt(), Duration::from_millis(1_460));
    }

    #[test]
    fn a_rate_from_the_last_download_opens_the_window_before_the_first_answer() {
        // A 1 MiB file at +60 ms: without a hint its second READ waits for the
        // first answer, a whole round trip.
        let hint = LinkHint {
            rtt: Some(60 * MS),
            rate: Some(30e6),
            ..LinkHint::default()
        };
        let mut w = Window::new(ReadAhead::Adaptive, CHUNK, hint);
        let now = Instant::now();
        w.on_dispatch(now, CHUNK);
        assert_eq!(w.decide(now, 1, u64::from(CHUNK), CHUNK), Dispatch::Now);

        // A slow link's hint keeps it at one.
        let slow = LinkHint {
            rtt: Some(60 * MS),
            rate: Some(375e3),
            ..LinkHint::default()
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
            ..LinkHint::default()
        };
        let mut w = Window::new(ReadAhead::Adaptive, CHUNK, hint);
        let t0 = Instant::now();
        w.on_dispatch(t0, CHUNK);
        let t1 = t0 + Duration::from_millis(1_460);
        w.on_delivery(t1, t0, t1, CHUNK, 0);
        let rate = w.rate().unwrap();
        assert!((350e3..370e3).contains(&rate), "rate {rate}");
    }

    #[test]
    fn only_a_multi_chunk_measurement_is_shared() {
        let mut w = adaptive(60 * MS);
        let t0 = Instant::now();
        w.on_dispatch(t0, CHUNK);
        w.on_delivery(t0 + 70 * MS, t0, t0 + 70 * MS, CHUNK, 0);
        assert_eq!(w.rate_to_share(), None, "one READ is mostly its round trip");
        w.on_dispatch(t0 + 70 * MS, CHUNK);
        w.on_delivery(t0 + 140 * MS, t0 + 70 * MS, t0 + 140 * MS, CHUNK, 0);
        assert!(w.rate_to_share().is_some());
    }

    // ── The rate shared on the connection ──────────────────────────────

    /// A shared rate may read low, never high: `true` if `rate` is within
    /// float noise of `link` or below it.
    fn not_above(rate: f64, link: f64) -> bool {
        rate <= link * (1.0 + 1e-9)
    }

    #[test]
    fn a_short_download_on_a_fast_distant_link_shares_the_links_rate() {
        // 4 MiB at +60 ms on a ~1 GB/s link: the window never fills the
        // 60 MB bandwidth-delay product, so deliveries come at the window's
        // pace. Only answers that queued behind each other on the wire say
        // what the link carries. `quick_read_limit` is built on this number,
        // and reading 22 MB/s here streams files one READ would move in half
        // the time.
        let link = Link::new(60 * MS, 1e9);
        let mut w = adaptive(60 * MS);
        let run = link.download(&mut w, 4 << 20, CHUNK);
        let shared = run.last_shared();
        assert!(
            shared >= 0.9e9 && not_above(shared, 1e9),
            "shared {:.1} MB/s",
            shared / 1e6
        );
    }

    #[test]
    fn the_delivery_measurement_is_one_switch_away() {
        // The benchmark compares candidates through `Tuning`, so the old
        // measurement has to stay reachable and keep reading what it did.
        let link = Link::new(60 * MS, 1e9);
        let tuning = Tuning {
            rate: RateMeasure::Deliveries,
            ..Tuning::SHIPPING
        };
        let hint = LinkHint {
            rtt: Some(60 * MS),
            ..LinkHint::default()
        };
        let mut w = Window::with_tuning(ReadAhead::Adaptive, CHUNK, hint, tuning);
        let shared = link.download(&mut w, 4 << 20, CHUNK).last_shared();
        assert!((15e6..35e6).contains(&shared), "shared {shared}");
    }

    #[test]
    fn a_consumer_catching_up_after_a_stall_does_not_inflate_the_rate() {
        // 50 MB/s at +1 ms. The consumer stops for 300 ms after chunk 8, the
        // window fills meanwhile, and then it takes the waiting chunks all at
        // once. Measured when the consumer takes them, that burst reads as a
        // link several times faster than the real one.
        let link = Link::new(MS, 50e6).with_consumer_delay(|k| {
            if k == 7 {
                Duration::from_millis(300)
            } else {
                Duration::ZERO
            }
        });
        let mut w = adaptive(MS);
        let run = link.download(&mut w, 16 << 20, CHUNK);
        let worst = run.shared.iter().copied().fold(0.0, f64::max);
        assert!(not_above(worst, 50e6), "shared {:.1} MB/s", worst / 1e6);
        assert!(run.last_shared() >= 0.9 * 50e6);
    }

    #[test]
    fn a_slow_consumer_does_not_drag_the_rate_down() {
        // The consumer spends 20 ms on each chunk, a quarter of the link's
        // 100 MB/s. The chunks still arrived at the link's pace, and the rate
        // says so.
        let link = Link::new(MS, 100e6).with_consumer_delay(|_| 20 * MS);
        let mut w = adaptive(MS);
        let run = link.download(&mut w, 4 << 20, CHUNK);
        let shared = run.last_shared();
        assert!(
            shared >= 0.9 * 100e6 && not_above(shared, 100e6),
            "shared {:.1} MB/s",
            shared / 1e6
        );
    }

    #[test]
    fn a_wrong_round_trip_only_ever_lowers_the_rate() {
        // The round trip decides which answers queued behind each other on
        // the wire. Guessing it short counts answers the link waited for
        // (low); guessing it long discards ones that did queue (fewer
        // samples). Neither can read above the link.
        for (rtt, rate) in [(MS, 1e9), (20 * MS, 3e6), (60 * MS, 50e6), (60 * MS, 375e3)] {
            for seed in [
                Duration::ZERO,
                MS,
                rtt / 2,
                rtt,
                rtt * 2,
                Duration::from_secs(2),
            ] {
                for file in [1u64 << 20, 4 << 20, 16 << 20] {
                    let link = Link::new(rtt, rate);
                    let run = link.download(&mut adaptive(seed), file, CHUNK);
                    for &shared in &run.shared {
                        assert!(
                            not_above(shared, rate),
                            "rtt {rtt:?}, seed {seed:?}, {file} bytes at {rate}: shared {shared}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn answers_the_server_reorders_still_measure_the_link() {
        // Samba finishes concurrent READs in whatever order its disk gives
        // them up: here every other READ takes 3 ms longer, so answers land
        // out of file order and are delivered in bursts.
        let link = Link::new(60 * MS, 200e6).with_server_delay(|i| {
            if i % 2 == 0 {
                3 * MS
            } else {
                Duration::ZERO
            }
        });
        let mut w = adaptive(60 * MS);
        let run = link.download(&mut w, 16 << 20, CHUNK);
        let worst = run.shared.iter().copied().fold(0.0, f64::max);
        assert!(not_above(worst, 200e6), "shared {:.1} MB/s", worst / 1e6);
        assert!(run.last_shared() >= 0.8 * 200e6, "{}", run.last_shared());
    }

    // ── The learned headroom ───────────────────────────────────────────

    /// The shipping learned-headroom parameters.
    fn learned() -> LearnedHeadroom {
        match Tuning::SHIPPING.headroom {
            Headroom::Learned(learned) => learned,
            Headroom::Fixed(_) => panic!("the learned headroom ships"),
        }
    }

    /// An adaptive window with this headroom and the shipping rate measure.
    fn adaptive_with(headroom: Headroom, rtt_seed: Duration) -> Window {
        let tuning = Tuning {
            headroom,
            ..Tuning::SHIPPING
        };
        let hint = LinkHint {
            rtt: Some(rtt_seed),
            ..LinkHint::default()
        };
        Window::with_tuning(ReadAhead::Adaptive, CHUNK, hint, tuning)
    }

    /// Deterministic noise: somewhere in `0..=max` for READ `i`.
    fn noise(i: usize, max: Duration) -> Duration {
        let x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40;
        max.mul_f64((x % 1_000) as f64 / 999.0)
    }

    /// A lateness memory that has seen `answers` answers arrive on time.
    fn quiet_memory(answers: u32) -> Lateness {
        let mut memory = Lateness::cold(&learned());
        let t0 = Instant::now();
        for i in 0..answers {
            memory.observe(Duration::ZERO, t0 + MS * i, &learned());
        }
        memory
    }

    /// Every headroom candidate across a grid of simulated links: how long
    /// each left the pipe idle, and how long a request sent mid-transfer
    /// waits behind it. A table for choosing parameters, not an assertion;
    /// the real grid is `benchmarks/read-ahead/`. Run it with
    /// `cargo test --release -p smb2 --lib compare_headroom_candidates -- --ignored --nocapture`.
    #[test]
    #[ignore = "prints a comparison table"]
    fn compare_headroom_candidates() {
        type Make = Box<dyn Fn() -> Link>;
        let s = Duration::from_secs;
        let windowed = |answers, span| {
            Headroom::Learned(LearnedHeadroom {
                estimator: Estimator::WindowedMax { answers, span },
                ..learned()
            })
        };
        let rfc = |k| {
            Headroom::Learned(LearnedHeadroom {
                estimator: Estimator::MeanDeviation { k },
                ..learned()
            })
        };
        let candidates = [
            ("fixed 30 ms", Headroom::Fixed(30 * MS)),
            ("fixed 100 ms", Headroom::Fixed(100 * MS)),
            ("fixed 250 ms", Headroom::Fixed(250 * MS)),
            ("shipping", Tuning::SHIPPING.headroom),
            ("max 16/0 s", windowed(16, Duration::ZERO)),
            ("max 16/2 s", windowed(16, s(2))),
            ("max 8/10 s", windowed(8, s(10))),
            ("rfc k=2", rfc(2.0)),
            ("rfc k=4", rfc(4.0)),
        ];
        let freezing = |rtt, rate, jitter, every, length| -> Make {
            Box::new(move || {
                Link::new(rtt, rate)
                    .with_server_delay(move |i| noise(i, jitter))
                    .with_freezes(every, length, Duration::from_secs(40))
            })
        };
        let jittered = |rtt, rate, jitter| freezing(rtt, rate, jitter, s(60), Duration::ZERO);
        let scenarios: [(&str, Duration, f64, u64, Make); 8] = [
            (
                "steady, 50 MB/s +20 ms",
                20 * MS,
                50e6,
                256 << 20,
                jittered(20 * MS, 50e6, Duration::ZERO),
            ),
            (
                "jitter 20 ms, 20 MB/s +20 ms",
                20 * MS,
                20e6,
                128 << 20,
                jittered(20 * MS, 20e6, 20 * MS),
            ),
            (
                "jitter 60 ms, 20 MB/s +20 ms",
                20 * MS,
                20e6,
                128 << 20,
                jittered(20 * MS, 20e6, 60 * MS),
            ),
            (
                "150 ms freeze every 1 s, 20 MB/s +20 ms",
                20 * MS,
                20e6,
                160 << 20,
                freezing(20 * MS, 20e6, 5 * MS, s(1), 150 * MS),
            ),
            (
                "150 ms freeze every 3 s, 20 MB/s +20 ms",
                20 * MS,
                20e6,
                160 << 20,
                freezing(20 * MS, 20e6, 5 * MS, s(3), 150 * MS),
            ),
            (
                "100 ms freeze every 1 s, 3 MB/s +20 ms",
                20 * MS,
                3e6,
                24 << 20,
                freezing(20 * MS, 3e6, 20 * MS, s(1), 100 * MS),
            ),
            (
                "200 ms freeze every 2 s, 375 KB/s +60 ms",
                60 * MS,
                375e3,
                8 << 20,
                freezing(60 * MS, 375e3, 40 * MS, s(2), 200 * MS),
            ),
            (
                "150 ms freeze every 1 s, 50 MB/s +60 ms",
                60 * MS,
                50e6,
                256 << 20,
                freezing(60 * MS, 50e6, Duration::ZERO, s(1), 150 * MS),
            ),
        ];
        for (scenario, rtt, rate, file, make) in &scenarios {
            let link_time = *file as f64 / rate + rtt.as_secs_f64();
            eprintln!("{scenario}: {link_time:.2} s of link time");
            for (name, headroom) in &candidates {
                let mut w = adaptive_with(*headroom, *rtt);
                let run = make().download(&mut w, *file, CHUNK);
                let took = run.delivered_at.last().unwrap().as_secs_f64();
                let mut queued = run.queued.clone();
                queued.sort_unstable();
                let wait_ms = |q: f64| {
                    let at = ((queued.len() - 1) as f64 * q) as usize;
                    queued[at] as f64 / rate * 1e3
                };
                eprintln!(
                    "  {name:13} idle {:5.0} ms   stat waits p50 {:5.0} p90 {:5.0} max {:5.0} ms   ends at {:4.0} ms",
                    (took - link_time) * 1e3,
                    wait_ms(0.5),
                    wait_ms(0.9),
                    wait_ms(1.0),
                    w.headroom().as_secs_f64() * 1e3,
                );
            }
        }
    }

    #[test]
    fn a_steady_link_learns_a_small_headroom() {
        // 50 MB/s at +20 ms, answers exactly on time: nothing to absorb, so
        // the margin (and what a `stat` waits beyond the current chunk)
        // shrinks to the floor.
        let link = Link::new(20 * MS, 50e6);
        let mut w = adaptive(20 * MS);
        link.download(&mut w, 64 << 20, CHUNK);
        assert_eq!(w.headroom(), learned().floor);
    }

    #[test]
    fn a_steady_link_stamped_unevenly_still_learns_a_small_headroom() {
        // 30 MB/s at +5 ms, answers on time but stamped up to 3 ms late, as
        // a receiver task scheduled late stamps them, and each one crossing
        // the link up to 2% slower or faster. The cold ramp fills the
        // pipe to the cap, so every answer has ~100 ms queued ahead of it,
        // and a wobble read as lateness also counts that whole queue: the
        // headroom then stays pinned at the queue it built, and a `stat` waits
        // behind the full 4 MiB for good. Measured on the Docker grid
        // (`benchmarks/read-ahead/results/self-tuning.md`) before it was a test.
        let link = Link::new(5 * MS, 30e6)
            .with_stamp_delay(|k| noise(k, 3 * MS))
            // 0.98–1.02: `noise` spans 0–40 ms, read here as 0–0.04.
            .with_rate_wobble(|i| 0.98 + noise(i + 7, 40 * MS).as_secs_f64());
        let mut w = adaptive(5 * MS);
        let run = link.download(&mut w, 64 << 20, CHUNK);
        assert_eq!(w.headroom(), learned().floor);
        let settled = run.queued[run.queued.len() - 16..].iter().max().unwrap();
        assert!(*settled < 2 << 20, "still queues {settled} bytes");
    }

    #[test]
    fn a_noisy_link_learns_a_larger_headroom_and_keeps_the_pipe_full() {
        // 20 MB/s at +20 ms, answers jittered by up to 5 ms, and the server
        // freezing for 150 ms every second (a NAS disk seeking). A margin at
        // the floor idles the link for most of every freeze; the learned one
        // grows to cover them, and runs within a few percent of 0.25.1's
        // fixed 250 ms. (At 3 MB/s a chunk takes longer than the freeze, so
        // whether a freeze shows at all is down to where in a chunk it lands.)
        let noisy = || {
            Link::new(20 * MS, 20e6)
                .with_server_delay(|i| noise(i, 5 * MS))
                .with_freezes(Duration::from_secs(1), 150 * MS, Duration::from_secs(20))
        };
        let file = 160 << 20;
        let mut learned_window = adaptive(20 * MS);
        let learned_run = noisy().download(&mut learned_window, file, CHUNK);
        assert!(
            learned_window.headroom() >= 100 * MS,
            "headroom {:?}",
            learned_window.headroom()
        );
        let took = |run: &Run| run.delivered_at.last().unwrap().as_secs_f64();
        let at_floor = noisy().download(
            &mut adaptive_with(Headroom::Fixed(learned().floor), 20 * MS),
            file,
            CHUNK,
        );
        let fixed_250 = noisy().download(
            &mut adaptive_with(Headroom::Fixed(250 * MS), 20 * MS),
            file,
            CHUNK,
        );
        let (learned_s, floor_s, fixed_s) = (took(&learned_run), took(&at_floor), took(&fixed_250));
        assert!(
            learned_s < floor_s && learned_s <= fixed_s * 1.03,
            "learned {learned_s:.2} s, floor {floor_s:.2} s, fixed 250 ms {fixed_s:.2} s"
        );
    }

    #[test]
    fn the_headroom_shrinks_once_the_noise_stops() {
        // The same freezes for the first three seconds, then a quiet link.
        // Covered freezes leave no trace, so the memory has to outlast the
        // gaps between them; once the noise stops for longer than that, the
        // margin goes back to the floor.
        let link = Link::new(20 * MS, 20e6).with_freezes(
            Duration::from_secs(1),
            150 * MS,
            Duration::from_secs(3),
        );
        let mut w = adaptive(20 * MS);
        let run = link.download(&mut w, 320 << 20, CHUNK);
        let Estimator::WindowedMax { span, .. } = learned().estimator else {
            panic!("the windowed max ships");
        };
        let quiet_for = *run.delivered_at.last().unwrap() - Duration::from_secs(3);
        assert!(quiet_for > span, "quiet for {quiet_for:?}, memory {span:?}");
        let grew_to = run.headroom.iter().max().unwrap();
        assert!(*grew_to >= 100 * MS, "grew to {grew_to:?}");
        assert_eq!(w.headroom(), learned().floor);
    }

    #[test]
    fn answers_the_server_reorders_are_not_mistaken_for_jitter() {
        // 10 MB/s at +100 ms, every other READ held 80 ms at the server,
        // longer than a chunk takes on the wire (52 ms): the answers come off
        // the wire in swapped pairs, back to back, so the link never idles
        // and nothing was late. Chunks are delivered in file order, so the
        // window hears of the earlier answer only after the later one; scored
        // in that order, each swapped pair reads as a chunk's time of
        // lateness (52 ms). The connection already knows the link's rate, so
        // the window opens wide at once: a ramp with only a READ or two out
        // would genuinely idle the link behind each held one.
        let link = Link::new(100 * MS, 10e6).with_server_delay(|i| {
            if i % 2 == 0 {
                80 * MS
            } else {
                Duration::ZERO
            }
        });
        let hint = LinkHint {
            rtt: Some(100 * MS),
            rate: Some(10e6),
            lateness: None,
        };
        let mut w = Window::new(ReadAhead::Adaptive, CHUNK, hint);
        link.download(&mut w, 32 << 20, CHUNK);
        assert!(
            w.headroom() <= learned().floor + 5 * MS,
            "headroom {:?}",
            w.headroom()
        );
    }

    #[test]
    fn a_small_learned_headroom_still_opens_the_window_on_a_distant_fast_link() {
        // The margin also grows the window while it ramps: the target is
        // rate × (RTT + headroom), and before the link is measured the rate
        // is one READ's over its round trip. Only a second READ sent with the
        // first answer measures the link, and a 30 ms margin sends one only
        // while a chunk crosses the wire in under 30 ms (at 10 MB/s it takes
        // 52). A connection that learned 30 ms on a quiet link must ramp as
        // fast as a fresh one, and on a fast link reach the cap within a few
        // round trips.
        for (rtt, rate) in [(60 * MS, 1e9), (200 * MS, 1e9), (200 * MS, 10e6)] {
            let download = |lateness| {
                let hint = LinkHint {
                    rtt: Some(rtt),
                    rate: None,
                    lateness,
                };
                let mut w = Window::new(ReadAhead::Adaptive, CHUNK, hint);
                Link::new(rtt, rate).download(&mut w, 32 << 20, CHUNK)
            };
            let (learned, fresh) = (download(Some(quiet_memory(32))), download(None));
            let took = |run: &Run| *run.delivered_at.last().unwrap();
            assert!(
                took(&learned) <= took(&fresh) + MS,
                "at {rtt:?}, {rate} B/s: took {:?}, fresh {:?}",
                took(&learned),
                took(&fresh)
            );
            if rate >= 1e9 {
                assert_eq!(learned.peak_reads, 8, "at {rtt:?}");
                assert!(
                    learned.peak_reached_at <= rtt * 3,
                    "at {rtt:?}: full window after {:?}",
                    learned.peak_reached_at
                );
            }
        }
    }

    #[test]
    fn a_learned_headroom_carries_over_to_the_next_transfer() {
        // A 2 MiB file is four answers, too few to trust on their own: a fresh
        // window keeps the cold margin through all of it. After a download
        // that learned the link is quiet, the next file starts from that.
        let link = Link::new(20 * MS, 50e6);
        let mut first = adaptive(20 * MS);
        link.download(&mut first, 16 << 20, CHUNK);
        let hint = LinkHint {
            rtt: Some(20 * MS),
            rate: None,
            lateness: first.lateness_to_share(),
        };
        let mut second = Window::new(ReadAhead::Adaptive, CHUNK, hint);
        link.download(&mut second, 2 << 20, CHUNK);
        assert_eq!(second.headroom(), learned().floor);

        let mut fresh = adaptive(20 * MS);
        link.download(&mut fresh, 2 << 20, CHUNK);
        assert_eq!(fresh.headroom(), learned().cold);
    }

    #[test]
    fn a_run_of_late_answers_is_not_counted_twice() {
        // 3 MB/s at +60 ms, the link slowing to a third of its rate for three
        // answers mid-transfer. Each is ~245 ms late against the rate the
        // window knew; counting each one's lateness again as backlog ahead of
        // the next compounded it to 1,072 ms (clamped to the 500 ms ceiling).
        let link =
            Link::new(60 * MS, 3e6)
                .with_rate_wobble(|i| if (20..23).contains(&i) { 0.3 } else { 1.0 });
        let mut w = adaptive(60 * MS);
        let run = link.download(&mut w, 16 << 20, CHUNK);
        let peak = run.headroom.iter().max().unwrap();
        assert!(*peak < 400 * MS, "grew to {peak:?}");
    }

    #[test]
    fn a_link_that_starts_slower_than_the_hint_leaves_no_standing_queue() {
        // 3 MB/s at +60 ms, counted the way an upload counts (every answer
        // handled as it lands), on a connection whose last transfer measured
        // the link and found it quiet. This one starts after an idle spell,
        // so TCP restarts slow start and the first answers cross at a third
        // of the rate. Two things went wrong, and the benchmark's 3 MB/s
        // uplink showed both (1.5 MiB standing, every `stat` waiting ~520 ms
        // where 0.25.1's waited ~340):
        // - Those late answers taught the headroom 245 ms, compounding to
        //   500 ms through the backlog term, and the memory kept it for the
        //   rest of the file. Nothing queued could have made them faster.
        // - Draining what's on its way at the hint's rate from each send, the
        //   window counted the slow bytes as landed, and the surplus it sent
        //   stayed queued for good.
        let link = Link::new(60 * MS, 3e6).with_rate_wobble(|i| if i < 3 { 0.3 } else { 1.0 });
        let mut first = adaptive(60 * MS);
        Link::new(60 * MS, 3e6).download(&mut first, 16 << 20, CHUNK);
        let hint = LinkHint {
            rtt: Some(60 * MS),
            rate: Some(3e6),
            lateness: first.lateness_to_share(),
        };
        let mut w = Window::new(ReadAhead::Adaptive, CHUNK, hint).with_unanswered_in_flight();
        let run = link.download(&mut w, 8 << 20, CHUNK);
        assert_eq!(w.headroom(), learned().floor);
        let settled = run.queued[run.queued.len() - 8..].iter().max().unwrap();
        assert!(
            *settled <= u64::from(CHUNK),
            "still queues {settled} bytes, headroom {:?}",
            w.headroom()
        );
    }

    #[test]
    fn a_noisy_slow_link_still_queues_about_one_chunk() {
        // 375 KB/s at +60 ms with jitter and freezes: the headroom grows, but
        // what a `stat` waits behind stays one chunk plus the ceiling.
        let link = Link::new(60 * MS, 375e3)
            .with_server_delay(|i| noise(i, 40 * MS))
            .with_freezes(Duration::from_secs(3), 200 * MS, Duration::from_secs(30));
        let mut w = adaptive(60 * MS);
        let run = link.download(&mut w, 8 << 20, CHUNK);
        let bound = u64::from(CHUNK) + (375e3 * (0.060 + learned().ceiling.as_secs_f64())) as u64;
        assert!(
            run.worst_queue <= bound,
            "queued {} bytes, bound {bound}",
            run.worst_queue
        );
    }

    #[test]
    fn the_quick_frame_budget_ignores_the_learned_headroom() {
        // 16 MB/s moves 4 MB in 250 ms, however small the headroom learned.
        assert_eq!(QUICK_FRAME_BUDGET, 250 * MS);
        assert_eq!(quick_read_limit(Some(16e6), EIGHT_MIB), 4_000_000);
    }

    #[test]
    fn a_chunk_bigger_than_the_cap_still_gets_one_read() {
        let w = Window::new(ReadAhead::Adaptive, 8 << 20, LinkHint::default());
        assert_eq!(w.decide(Instant::now(), 0, 0, 8 << 20), Dispatch::Now);
    }

    // ── quick_read_limit ───────────────────────────────────────────────

    const EIGHT_MIB: u32 = 8 << 20;

    #[test]
    fn with_no_rate_one_chunk_is_quick() {
        assert_eq!(quick_read_limit(None, EIGHT_MIB), u64::from(CHUNK));
    }

    #[test]
    fn a_fast_link_makes_what_it_moves_in_the_headroom_quick() {
        // 16 MB/s moves 4 MB in 250 ms.
        assert_eq!(quick_read_limit(Some(16e6), EIGHT_MIB), 4_000_000);
    }

    #[test]
    fn a_slow_link_still_reads_one_chunk_in_one_go() {
        // 375 KB/s moves 94 KB in 250 ms, but one chunk is one READ either way.
        assert_eq!(quick_read_limit(Some(375e3), EIGHT_MIB), u64::from(CHUNK));
    }

    #[test]
    fn one_read_never_asks_for_more_than_max_read_size() {
        assert_eq!(quick_read_limit(Some(1e9), EIGHT_MIB), u64::from(EIGHT_MIB));
        assert_eq!(quick_read_limit(None, 65536), 65536);
        assert_eq!(quick_read_limit(Some(16e6), 65536), 65536);
    }
}
