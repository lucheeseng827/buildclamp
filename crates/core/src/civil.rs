//! Civil dates, without a calendar dependency.
//!
//! Three things in this tool are dated — a generated grant's `why`, a break-glass
//! `expires`, and a grant's `first-seen` — and all three are compared, not merely
//! printed. A comparison needs arithmetic: "is this expiry more than seven days out?"
//! and "was this grant first seen within the grace window?" are day counts, and string
//! ordering cannot answer either.
//!
//! # Why not `chrono` or `time`
//!
//! The same reason the seccomp filter is not `seccompiler` and git's config is parsed by
//! hand: this is a fixed, published algorithm — Howard Hinnant's `days_from_civil` and
//! `civil_from_days`, the same pair the C++ standard's calendar support is specified
//! against — it is forty lines, and it is checked here against known values including
//! the two leap-year rules that catch naive implementations. A calendar crate would add
//! a dependency tree to a tool whose entire subject is what a build pulls in.
//!
//! # What this deliberately is not
//!
//! There is no clock here. `buildclamp-core` is pure, and everything in this file is a
//! function of its arguments — the caller supplies the day. [`Date::from_unix`] takes
//! the seconds rather than reading them, which is what lets the CLI test its own
//! `today()` against fixed epoch values.
//!
//! There are no times, no zones and no offsets. A policy expiry is a **date**: "expires
//! 2026-09-20" means the exception stops applying when the build host's calendar says
//! the 21st, and two hosts in different zones can disagree by a day about when that is.
//! That imprecision is deliberate and it is stated in the format's documentation rather
//! than papered over with a timestamp, because the alternative — an expiry that lands
//! mid-afternoon in one office and mid-morning in another — is worse to reason about and
//! no more correct.

use std::fmt;

/// A civil date, held as days since 1970-01-01 so that comparison and differencing are
/// both trivial and both correct.
///
/// Ordering is chronological, which is the reason for the newtype: `"2026-09-9"` and
/// `"2026-09-10"` compare the wrong way round as strings, and a policy that accepted a
/// sloppily written date would then treat an expired exception as live.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Date {
    days: i64,
}

impl Date {
    /// Parse `YYYY-MM-DD`, strictly.
    ///
    /// Strictly means all of: exactly four, two and two digits; a real month; a day that
    /// exists in that month of that year. `2026-02-30` is refused, and so is `2026-9-1`
    /// — the second because a format that accepts both spellings invites a file where
    /// two dates sort differently from how they read.
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return None;
        }
        if !b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                true
            } else {
                c.is_ascii_digit()
            }
        }) {
            return None;
        }
        let y: i64 = s[0..4].parse().ok()?;
        let m: i64 = s[5..7].parse().ok()?;
        let d: i64 = s[8..10].parse().ok()?;
        if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
            return None;
        }
        Some(Self {
            days: days_from_civil(y, m, d),
        })
    }

    /// The civil date at a Unix timestamp, in UTC.
    ///
    /// Takes the seconds rather than reading a clock so that the CLI's `today()` — the
    /// one place in this codebase that does read one — can be tested against fixed epoch
    /// values, leap day included.
    pub fn from_unix(secs: i64) -> Self {
        // Floor division: a timestamp before the epoch must round toward the earlier
        // day, and Rust's `/` truncates toward zero.
        let days = secs.div_euclid(86_400);
        Self { days }
    }

    /// Whole days from `self` to `other`, negative if `other` is earlier.
    pub fn days_until(self, other: Self) -> i64 {
        other.days - self.days
    }

    pub fn plus_days(self, n: i64) -> Self {
        Self {
            days: self.days + n,
        }
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, m, d) = civil_from_days(self.days);
        write!(f, "{y:04}-{m:02}-{d:02}")
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil`. Valid for every year this tool will ever see.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Its inverse.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_directions_are_inverses_across_a_long_span() {
        // Every day from 1970 to 2070. If either function is wrong anywhere in the range
        // this tool will be read in, this finds the day.
        for days in 0..36_525 {
            let d = Date { days };
            let round = Date::parse(&d.to_string()).expect("its own output must parse");
            assert_eq!(d, round, "{d}");
        }
    }

    #[test]
    fn known_epoch_values() {
        assert_eq!(Date::from_unix(0).to_string(), "1970-01-01");
        assert_eq!(Date::from_unix(86_399).to_string(), "1970-01-01");
        assert_eq!(Date::from_unix(86_400).to_string(), "1970-01-02");
        // A leap day, which is where this arithmetic usually goes wrong.
        assert_eq!(Date::from_unix(1_709_164_800).to_string(), "2024-02-29");
        // A time before the epoch must round to the earlier day, not toward zero.
        assert_eq!(Date::from_unix(-1).to_string(), "1969-12-31");
    }

    #[test]
    fn impossible_dates_are_refused() {
        for bad in [
            "2026-02-30", // February never has thirty days
            "2026-13-01", // no thirteenth month
            "2026-00-10", // nor a zeroth
            "2026-09-00",
            "2026-09-31", // September has thirty
            "2100-02-29", // a century year that is NOT a leap year
            "2026-9-01",  // one digit short, and it would sort wrongly
            "2026-09-1",
            "26-09-01",
            "2026/09/01",
            "",
            "today",
            "2026-09-01T00:00:00Z",
        ] {
            assert!(Date::parse(bad).is_none(), "{bad} should not parse");
        }
        // The one century year in range that IS a leap year, to prove the rule above is
        // the 400-year rule and not "centuries are never leap".
        assert!(Date::parse("2000-02-29").is_some());
    }

    #[test]
    fn differencing_counts_whole_days_and_has_a_sign() {
        let a = Date::parse("2026-09-15").unwrap();
        let b = Date::parse("2026-09-22").unwrap();
        assert_eq!(a.days_until(b), 7);
        assert_eq!(b.days_until(a), -7);
        assert_eq!(a.days_until(a), 0);
        assert_eq!(a.plus_days(7), b);
        // Across a month boundary and a leap day, where a naive implementation drifts.
        let feb = Date::parse("2024-02-28").unwrap();
        assert_eq!(feb.plus_days(1).to_string(), "2024-02-29");
        assert_eq!(feb.plus_days(2).to_string(), "2024-03-01");
    }

    #[test]
    fn ordering_is_chronological_where_string_ordering_is_not() {
        // The defect this newtype exists for, spelled out: as strings, "2026-09-9" sorts
        // after "2026-09-10". Refusing the first spelling is what makes the comparison
        // safe, and this pins that the refusal is the mechanism.
        assert!(Date::parse("2026-09-9").is_none());
        assert!(Date::parse("2026-09-09").unwrap() < Date::parse("2026-09-10").unwrap());
    }
}
