//! Calendar dates (`YYYY-MM-DD`, ISO 8601), without a date crate.

/// Seconds in a day.
pub(crate) const DAY: u64 = 86_400;

/// A valid Gregorian date, from 1970-01-01 onwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Date {
    year: u32,
    month: u32,
    day: u32,
}

const fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Date {
    /// Strict `YYYY-MM-DD`: four-digit year (1970 to 9999), valid month and day.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let digits = |r: core::ops::Range<usize>| -> Option<u32> {
            b.get(r.clone())
                .filter(|d| d.iter().all(u8::is_ascii_digit))
                .and_then(|_| s[r].parse().ok())
        };
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return None;
        }
        let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
        let valid = (1970..=9999).contains(&year)
            && (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day);
        valid.then_some(Self { year, month, day })
    }

    /// Days since 1970-01-01 (H. Hinnant, "chrono-Compatible Low-Level Date
    /// Algorithms").
    fn days(self) -> u64 {
        let (m, d) = (u64::from(self.month), u64::from(self.day));
        let y = u64::from(self.year) - u64::from(m <= 2);
        let era = y / 400;
        let yoe = y % 400;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// First second (Unix) after this day ends in UTC: the date is valid
    /// strictly before it.
    pub(crate) fn end_unix(self) -> u64 {
        (self.days() + 1) * DAY
    }
}

impl core::fmt::Display for Date {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        assert!(Date::parse("2027-03-31").is_some());
        assert!(Date::parse("2028-02-29").is_some());
        for bad in [
            "2027-02-29",
            "2100-02-29",
            "2027-13-01",
            "2027-00-10",
            "2027-04-31",
            "2027-1-01",
            "27-01-01",
            "2027/01/01",
            "2027-01-01T00:00:00Z",
            "1969-12-31",
            "+027-01-01",
            "",
        ] {
            assert_eq!(Date::parse(bad), None, "{bad}");
        }
        assert!(Date::parse("2000-02-29").is_some());
    }

    #[test]
    fn day_boundaries() {
        assert_eq!(Date::parse("1970-01-01").unwrap().end_unix(), DAY);
        // 2027-04-01T00:00:00Z.
        assert_eq!(Date::parse("2027-03-31").unwrap().end_unix(), 1_806_537_600);
        assert_eq!(Date::parse("2000-03-01").unwrap().days(), 11_017);
        assert_eq!(Date::parse("2027-03-31").unwrap().to_string(), "2027-03-31");
    }
}
