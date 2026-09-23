//! The adaptive window's tunables, in one place so a benchmark can compare
//! candidates against what ships.
//!
//! Every `Window` reads [`Tuning::current`] when it's built. The module is
//! crate-private; with the unstable `__bench-tuning` feature, `smb2::__bench`
//! re-exports it together with a process-wide override, which is how
//! `benchmarks/read-ahead/` selects candidates at runtime. That feature is
//! not for consumers: nothing here is covered by SemVer, and it can change or
//! go away in any release.

use std::time::Duration;

/// What an adaptive transfer is paced by.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tuning {
    /// Margin on top of the round trip, in time at the measured rate.
    pub headroom: Headroom,
    /// How the rate is measured, for pacing and for the connection's hint.
    pub rate: RateMeasure,
}

impl Tuning {
    /// What ships. Provisional: the benchmark in `benchmarks/read-ahead/`
    /// re-picks the learned headroom's parameters.
    pub const SHIPPING: Self = Self {
        headroom: Headroom::Learned(LearnedHeadroom::SHIPPING),
        rate: RateMeasure::LinkCapacity,
    };

    /// The tuning in effect: [`SHIPPING`](Self::SHIPPING), unless a benchmark
    /// overrode it.
    pub fn current() -> Self {
        #[cfg(feature = "__bench-tuning")]
        if let Some(tuning) = *OVERRIDE.read().unwrap_or_else(|e| e.into_inner()) {
            return tuning;
        }
        Self::SHIPPING
    }
}

/// The margin a transfer keeps on top of the round trip, in time at the
/// measured rate.
///
/// It absorbs server stalls (a disk seek, a busy CPU) and link jitter, so the
/// pipe doesn't idle. It is also the price: roughly how long anything else on
/// the connection waits beyond the chunk that's already arriving.
#[derive(Debug, Clone, Copy, PartialEq)]
// Only the benchmark and the tests pick the variants that don't ship.
#[cfg_attr(not(feature = "__bench-tuning"), allow(dead_code))]
pub enum Headroom {
    /// The same margin on every link. 250 ms is what 0.25.1 shipped.
    Fixed(Duration),
    /// Learned per connection from how late answers come (see `Window`
    /// § Learning the headroom in `read_ahead.rs`).
    Learned(LearnedHeadroom),
}

/// How the headroom is learned.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LearnedHeadroom {
    /// What turns the lateness samples into a headroom.
    pub estimator: Estimator,
    /// The least headroom, whatever the samples say.
    pub floor: Duration,
    /// The most headroom, whatever the samples say.
    pub ceiling: Duration,
    /// The headroom before anything is learned, and the margin that paces
    /// the ramp until a full pipe has measured the link.
    pub cold: Duration,
}

impl LearnedHeadroom {
    /// What ships. Provisional, pending `benchmarks/read-ahead/results/self-tuning.md`.
    pub const SHIPPING: Self = Self {
        estimator: Estimator::WindowedMax {
            answers: 16,
            span: Duration::from_secs(10),
        },
        floor: Duration::from_millis(30),
        ceiling: Duration::from_millis(500),
        cold: Duration::from_millis(250),
    };
}

/// What turns lateness samples into a headroom.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(not(feature = "__bench-tuning"), allow(dead_code))]
pub enum Estimator {
    /// The latest answer seen within the last `answers` answers or the last
    /// `span` of time, whichever reaches further back. Until `answers`
    /// samples exist, the cold headroom counts as one of them.
    ///
    /// A stall the headroom already covers leaves no trace: the pipe never
    /// idled, so no answer comes late. A memory that forgot a stall as soon
    /// as it was covered would shrink the headroom straight back under it,
    /// so the memory spans time as well as answers: on a fast link, 16
    /// answers are a few milliseconds.
    WindowedMax {
        /// How many answers a sample is remembered for, at least.
        answers: u32,
        /// How long a sample is remembered for, at least.
        span: Duration,
    },
    /// RFC 6298's retransmit-timer shape: a smoothed mean plus `k` times the
    /// smoothed mean deviation (gains 1/8 and 1/4), starting from the cold
    /// headroom as the mean.
    MeanDeviation {
        /// How many mean deviations above the mean.
        k: f64,
    },
}

/// How a `Window` measures the rate it paces by and shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateMeasure {
    /// Bytes over time across the last few chunks, timed when the transfer
    /// took each one, counted from the first request's dispatch. What one
    /// transfer achieved, which reads far below the link whenever something
    /// other than the link set the pace: the window while it ramps or sits
    /// below the bandwidth-delay product, the first round trip, a slow
    /// consumer. And a consumer catching up after a stall reads it far above.
    /// Kept as the benchmark's reference point.
    Deliveries,
    /// What the link carries, from answers that queued behind each other on
    /// the wire, timed as they came off it. See `Window` § Measuring the link
    /// in `read_ahead.rs`.
    LinkCapacity,
}

#[cfg(feature = "__bench-tuning")]
static OVERRIDE: std::sync::RwLock<Option<Tuning>> = std::sync::RwLock::new(None);

/// Replace the tuning every transfer started from now on uses, process-wide;
/// `None` goes back to [`Tuning::SHIPPING`]. Transfers already running keep
/// what they started with.
#[cfg(feature = "__bench-tuning")]
pub fn set_tuning(tuning: Option<Tuning>) {
    *OVERRIDE.write().unwrap_or_else(|e| e.into_inner()) = tuning;
}
