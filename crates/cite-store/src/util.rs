use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

// Multiplicative hasher for maps keyed by integers the store assigns itself, never by request text.
#[derive(Default)]
pub(crate) struct IntHasher(u64);

impl Hasher for IntHasher {
    fn finish(&self) -> u64 {
        self.0.rotate_left(26)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }

    fn write_u8(&mut self, n: u8) {
        self.write_u64(u64::from(n));
    }

    fn write_u32(&mut self, n: u32) {
        self.write_u64(u64::from(n));
    }

    fn write_i64(&mut self, n: i64) {
        self.write_u64(n as u64);
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
}

pub(crate) type IntMap<K, V> = HashMap<K, V, BuildHasherDefault<IntHasher>>;

pub(crate) fn to_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

pub(crate) fn from_i64(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

pub(crate) fn to_u32(n: i64) -> u32 {
    u32::try_from(n.max(0)).unwrap_or(u32::MAX)
}

pub(crate) fn to_u16(n: i64) -> u16 {
    u16::try_from(n.max(0)).unwrap_or(u16::MAX)
}

pub(crate) fn to_u8(n: i64) -> u8 {
    u8::try_from(n.max(0)).unwrap_or(u8::MAX)
}

// Media type without parameters, lowercased: "Text/HTML; charset=utf-8" becomes "text/html".
pub(crate) fn normalize_ctype(raw: &str) -> Cow<'_, str> {
    let base = raw.split(';').next().unwrap_or("").trim();
    if base.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(base.to_ascii_lowercase())
    } else {
        Cow::Borrowed(base)
    }
}

pub(crate) fn ascii_upper(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_lowercase()) {
        Cow::Owned(s.to_ascii_uppercase())
    } else {
        Cow::Borrowed(s)
    }
}

pub(crate) fn split_signals(s: &str) -> impl Iterator<Item = &str> {
    s.split(',').map(str::trim).filter(|p| !p.is_empty())
}

// Bucket 0..=4 for a bot score: 0-19, 20-39, 40-59, 60-79, 80-100.
pub(crate) fn score_bucket(score: u8) -> usize {
    usize::from(score / 20).min(4)
}

pub(crate) fn iso_utc(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s, milli) = (
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000,
    );
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z")
}

// Days since 1970-01-01 to a proleptic Gregorian date (Hinnant's civil_from_days).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_formats_known_instants() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_utc(1_730_721_600_123), "2024-11-04T12:00:00.123Z");
        assert_eq!(iso_utc(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(iso_utc(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn iso_does_not_panic_at_extremes() {
        let _ = iso_utc(i64::MIN);
        let _ = iso_utc(i64::MAX);
    }

    #[test]
    fn ctype_normalisation() {
        assert_eq!(normalize_ctype(" Text/HTML ; charset=utf-8"), "text/html");
        assert_eq!(normalize_ctype(""), "");
        assert_eq!(normalize_ctype("image/png"), "image/png");
    }

    #[test]
    fn signal_splitting_skips_blanks() {
        let got: Vec<&str> = split_signals(" a, ,b,,c ").collect();
        assert_eq!(got, ["a", "b", "c"]);
    }

    #[test]
    fn score_buckets_cover_the_range() {
        let got: Vec<usize> = [0u8, 19, 20, 39, 40, 59, 60, 79, 80, 100, 255]
            .into_iter()
            .map(score_bucket)
            .collect();
        assert_eq!(got, [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4]);
    }

    #[test]
    fn integer_narrowing_clamps() {
        assert_eq!(to_u16(-5), 0);
        assert_eq!(to_u16(70_000), u16::MAX);
        assert_eq!(to_u8(300), u8::MAX);
        assert_eq!(to_u32(i64::MAX), u32::MAX);
        assert_eq!(from_i64(-1), 0);
        assert_eq!(to_i64(u64::MAX), i64::MAX);
    }
}
