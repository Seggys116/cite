use std::time::Duration;

use cite_core::PollInterval;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollDecision {
    IdleForever,
    Wait(Duration),
    PollNow,
}

/// Automatic polling never runs when the interval is off; manual polls are handled elsewhere.
pub fn decide_poll(
    poll: PollInterval,
    next_poll_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> PollDecision {
    match poll {
        PollInterval::Off => PollDecision::IdleForever,
        PollInterval::Every(_) => match next_poll_at {
            None => PollDecision::PollNow,
            Some(at) if at <= now => PollDecision::PollNow,
            Some(at) => {
                let wait = (at - now).unsigned_abs();
                PollDecision::Wait(wait.max(Duration::from_millis(50)))
            }
        },
    }
}

pub fn jittered_interval(base: Duration, jitter_unit: u32) -> Duration {
    if base.is_zero() {
        return base;
    }
    let nanos = base.as_nanos() as f64;
    // Takes the jitter as a parameter so tests stay deterministic.
    let frac = (f64::from(jitter_unit % 1000) / 1000.0) * 0.2 - 0.1;
    let adjusted = nanos * (1.0 + frac);
    Duration::from_nanos(adjusted.max(1.0) as u64)
}

pub fn parse_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

pub fn next_poll_stamp(now: OffsetDateTime, wait: Duration) -> String {
    let at = now + wait;
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| cite_core::now_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration as TimeDuration;

    #[test]
    fn poll_off_never_loops() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            decide_poll(PollInterval::Off, None, now),
            PollDecision::IdleForever
        );
        assert_eq!(
            decide_poll(PollInterval::Off, Some(now), now),
            PollDecision::IdleForever
        );
    }

    #[test]
    fn every_polls_when_due() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            decide_poll(PollInterval::Every(Duration::from_secs(60)), None, now),
            PollDecision::PollNow
        );
        let past = now - TimeDuration::seconds(1);
        assert_eq!(
            decide_poll(
                PollInterval::Every(Duration::from_secs(60)),
                Some(past),
                now
            ),
            PollDecision::PollNow
        );
        let future = now + TimeDuration::seconds(30);
        match decide_poll(
            PollInterval::Every(Duration::from_secs(60)),
            Some(future),
            now,
        ) {
            PollDecision::Wait(d) => assert!(d <= Duration::from_secs(30) + Duration::from_secs(1)),
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn jitter_stays_within_ten_percent() {
        let base = Duration::from_secs(100);
        for unit in [0u32, 500, 999] {
            let j = jittered_interval(base, unit);
            assert!(j >= Duration::from_secs(90));
            assert!(j <= Duration::from_secs(110));
        }
    }
}
