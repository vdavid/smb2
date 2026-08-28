//! Turning SMB metadata into something readable or machine-parseable.

use std::time::UNIX_EPOCH;

use smb2::pack::FileTime;

/// Formats a Windows FILETIME as an ISO timestamp in UTC, or `-` when the
/// server left it unset.
pub fn timestamp(time: FileTime) -> String {
    match unix_seconds(time) {
        Some(seconds) => iso_utc(seconds),
        None => "-".to_string(),
    }
}

/// Seconds since the Unix epoch, or `None` for an unset or pre-1970 time.
pub fn unix_seconds(time: FileTime) -> Option<i64> {
    let system_time = time.to_system_time()?;
    let duration = system_time.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_secs() as i64)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC, using the civil-from-days algorithm so we
/// don't need a date crate for one formatting job.
fn iso_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    )
}

/// Converts days since 1970-01-01 into a civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// A size in bytes with thousands separators, so long listings line up.
pub fn bytes(size: u64) -> String {
    let digits = size.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// A size rounded to a human-friendly unit.
pub fn human_bytes(size: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        // The epoch stamp Xiaomi put in 04M19S_1674385459.mp4.
        assert_eq!(iso_utc(1_674_385_459), "2023-01-22 11:04:19");
        assert_eq!(iso_utc(0), "1970-01-01 00:00:00");
        assert_eq!(iso_utc(951_782_400), "2000-02-29 00:00:00");
    }

    #[test]
    fn unset_filetime_shows_a_dash() {
        assert_eq!(timestamp(FileTime::ZERO), "-");
    }

    #[test]
    fn groups_digits() {
        assert_eq!(bytes(0), "0");
        assert_eq!(bytes(999), "999");
        assert_eq!(bytes(1_000), "1,000");
        assert_eq!(bytes(3_461_888), "3,461,888");
    }

    #[test]
    fn rounds_to_human_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
    }
}
