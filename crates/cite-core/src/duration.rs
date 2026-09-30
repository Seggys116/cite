use std::time::Duration;

use crate::error::{Error, Result};

/// How often the manager polls GitHub. `Off` is manual deploys only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollInterval {
    Off,
    Every(Duration),
}

pub fn parse_duration(input: &str) -> Result<Duration> {
    let s = input.trim();
    if s.is_empty() {
        return Err(Error::Config("empty duration".into()));
    }
    let split = s
        .find(|c: char| c.is_ascii_alphabetic())
        .ok_or_else(|| Error::Config(format!("duration `{s}` needs a unit")))?;
    let (num, unit) = s.split_at(split);
    if num.is_empty() || !unit.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(Error::Config(format!("bad duration `{s}`")));
    }
    let n: u64 = num
        .parse()
        .map_err(|_| Error::Config(format!("bad duration number `{s}`")))?;
    let dur = match unit.to_ascii_lowercase().as_str() {
        "ms" => Duration::from_millis(n),
        "s" | "sec" | "secs" => Duration::from_secs(n),
        "m" | "min" | "mins" => Duration::from_secs(n.saturating_mul(60)),
        "h" | "hr" | "hrs" => Duration::from_secs(n.saturating_mul(3_600)),
        "d" | "day" | "days" => Duration::from_secs(n.saturating_mul(86_400)),
        _ => return Err(Error::Config(format!("unknown duration unit `{unit}`"))),
    };
    if dur > Duration::from_secs(366 * 86_400) {
        return Err(Error::Config(format!("duration `{s}` is too large")));
    }
    Ok(dur)
}

/// `off` / `0` disable polling. Any other duration must be at least `min`.
pub fn parse_poll_interval(input: &str, min: Duration) -> Result<PollInterval> {
    let s = input.trim();
    if s == "0" || s.eq_ignore_ascii_case("off") {
        return Ok(PollInterval::Off);
    }
    let dur = parse_duration(s)?;
    if dur < min {
        return Err(Error::Config(format!(
            "poll interval {s} is below the minimum {}s",
            min.as_secs()
        )));
    }
    Ok(PollInterval::Every(dur))
}

/// Parse a byte size. `KB`/`MB`/`GB` are powers of 1024. A fractional coefficient is allowed (`1.5GB`).
pub fn parse_byte_size(input: &str) -> Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        return Err(Error::Config("empty byte size".into()));
    }
    let split = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    if num.is_empty() {
        return Err(Error::Config(format!("bad byte size `{s}`")));
    }
    let n: f64 = num
        .parse()
        .map_err(|_| Error::Config(format!("bad byte size `{s}`")))?;
    if !n.is_finite() || n < 0.0 {
        return Err(Error::Config(format!("bad byte size `{s}`")));
    }
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "ki" | "kib" => 1024,
        "m" | "mb" | "mi" | "mib" => 1024 * 1024,
        "g" | "gb" | "gi" | "gib" => 1024 * 1024 * 1024,
        _ => return Err(Error::Config(format!("unknown size unit `{unit}`"))),
    };
    let bytes = n * mult as f64;
    if !bytes.is_finite() || bytes > u64::MAX as f64 {
        return Err(Error::Config(format!("byte size `{s}` overflows")));
    }
    Ok(bytes.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_intervals() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("6h").unwrap(), Duration::from_secs(6 * 3600));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
    }

    #[test]
    fn poll_off_and_floor() {
        assert_eq!(
            parse_poll_interval("off", Duration::from_secs(60)).unwrap(),
            PollInterval::Off
        );
        assert_eq!(
            parse_poll_interval("0", Duration::from_secs(60)).unwrap(),
            PollInterval::Off
        );
        assert!(parse_poll_interval("30s", Duration::from_secs(60)).is_err());
        assert!(matches!(
            parse_poll_interval("1m", Duration::from_secs(60)).unwrap(),
            PollInterval::Every(_)
        ));
    }

    #[test]
    fn byte_sizes() {
        assert_eq!(parse_byte_size("2GB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(
            parse_byte_size("1.5GB").unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(parse_byte_size("100MB").unwrap(), 100 * 1024 * 1024);
    }
}
