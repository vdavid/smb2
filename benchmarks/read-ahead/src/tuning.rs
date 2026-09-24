//! The read-ahead / write-behind tuning candidates the grid compares.
//!
//! A variant suffixed `:<name>` (for example `auto:wmax16`) runs with that
//! tuning, on a connection of its own, so what one candidate learned never
//! seeds another. Names spell out their parameters, so `wmax16` keeps meaning
//! the same thing if what ships changes; `shipping` is whatever the build
//! under test ships.

use std::time::Duration;

use smb2::__bench::{Estimator, Headroom, LearnedHeadroom, RateMeasure, Tuning};

/// Every name `parse` knows, for the usage message.
pub(crate) const NAMES: &str = "shipping, ref, fixed250, fixed100, wmax16, wmax16-del, wmax8, wmax16-f20, meandev4, wmax16-n25, wmax16-n50, meandev4-n25, wmax16-b33, meandev4-b33";

/// The tuning a name stands for; `None` means what the build ships.
pub(crate) fn parse(name: &str) -> Option<Tuning> {
    let ms = Duration::from_millis;
    // `noise`: idle below max(noise_floor, share × the answer's wire time)
    // counts as on time. (1 ms, 0) is the tolerance 4aa8361 shipped. The
    // third value is the backlog share: idle below it × the backlog ahead
    // also counts as on time (0: every idle above the noise scores the
    // backlog, as before the contraction).
    let learned = |estimator, floor, (noise_floor, noise_share, backlog_share): (u64, f64, f64)| {
        Headroom::Learned(LearnedHeadroom {
            estimator,
            floor: ms(floor),
            ceiling: ms(500),
            cold: ms(250),
            noise_floor: ms(noise_floor),
            noise_share,
            backlog_share,
        })
    };
    let wmax = |answers| Estimator::WindowedMax { answers, span: Duration::from_secs(10) };
    let meandev = Estimator::MeanDeviation { k: 4.0 };
    let (strict, n25, n50, b33) = ((1, 0.0, 0.0), (5, 0.25, 0.0), (5, 0.5, 0.0), (5, 0.25, 1.0 / 3.0));
    let (headroom, rate) = match name {
        "shipping" => return None,
        // 0.25.1: a fixed 250 ms margin, and the rate a transfer achieved.
        "ref" => (Headroom::Fixed(ms(250)), RateMeasure::Deliveries),
        "fixed250" => (Headroom::Fixed(ms(250)), RateMeasure::LinkCapacity),
        "fixed100" => (Headroom::Fixed(ms(100)), RateMeasure::LinkCapacity),
        // What 4aa8361 shipped.
        "wmax16" => (learned(wmax(16), 30, strict), RateMeasure::LinkCapacity),
        "wmax16-del" => (learned(wmax(16), 30, strict), RateMeasure::Deliveries),
        "wmax8" => (learned(wmax(8), 30, strict), RateMeasure::LinkCapacity),
        "wmax16-f20" => (learned(wmax(16), 20, strict), RateMeasure::LinkCapacity),
        "meandev4" => (learned(meandev, 30, strict), RateMeasure::LinkCapacity),
        "wmax16-n25" => (learned(wmax(16), 30, n25), RateMeasure::LinkCapacity),
        "wmax16-n50" => (learned(wmax(16), 30, n50), RateMeasure::LinkCapacity),
        "meandev4-n25" => (learned(meandev, 30, n25), RateMeasure::LinkCapacity),
        // The noise tolerance plus the backlog contraction.
        "wmax16-b33" => (learned(wmax(16), 30, b33), RateMeasure::LinkCapacity),
        "meandev4-b33" => (learned(meandev, 30, b33), RateMeasure::LinkCapacity),
        _ => panic!("unknown tuning {name:?}; known: {NAMES}"),
    };
    Some(Tuning { headroom, rate })
}

/// Splits `base:tuning` into the variant and the tuning's name.
pub(crate) fn split(variant: &str) -> (&str, Option<&str>) {
    match variant.split_once(':') {
        Some((base, tuning)) => {
            parse(tuning); // Fail on a typo before anything runs.
            (base, Some(tuning))
        }
        None => (variant, None),
    }
}

/// Makes `tuning` the one every transfer started from now on uses. A variant
/// without a suffix runs what ships.
pub(crate) fn apply(tuning: Option<&str>) {
    smb2::__bench::set_tuning(tuning.and_then(parse));
}
