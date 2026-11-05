use std::collections::{HashMap, VecDeque};

const MAX_KEYS: usize = 4096;
const FAILURE_THRESHOLD: u32 = 5;
const KEY_WINDOW_SECS: u64 = 15 * 60;
const BASE_LOCK_SECS: u64 = 30;
const MAX_LOCK_SECS: u64 = 15 * 60;
const GLOBAL_WINDOW_SECS: u64 = 5 * 60;
const GLOBAL_THRESHOLD: usize = 100;
const GLOBAL_LOCK_SECS: u64 = 60;

#[derive(Debug, Clone)]
struct KeyState {
    count: u32,
    window_start: u64,
    locked_until: u64,
    last_seen: u64,
}

#[derive(Debug, Default)]
pub struct LoginLimiter {
    keys: HashMap<String, KeyState>,
    global_failures: VecDeque<u64>,
    global_locked_until: u64,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, key: &str, now: u64) -> Result<(), u64> {
        let key_until = self.keys.get(key).map_or(0, |s| s.locked_until);
        let until = key_until.max(self.global_locked_until);
        if now < until {
            Err((until - now).max(1))
        } else {
            Ok(())
        }
    }

    pub fn record_failure(&mut self, key: &str, now: u64) {
        self.record_global(now);
        self.record_failure_local(key, now);
    }

    // Counts against the key only, for failures that are cheap to forge and must not arm the global lock.
    pub fn record_failure_local(&mut self, key: &str, now: u64) {
        if !self.keys.contains_key(key) && self.keys.len() >= MAX_KEYS {
            self.evict_oldest();
        }
        let state = self.keys.entry(key.to_string()).or_insert(KeyState {
            count: 0,
            window_start: now,
            locked_until: 0,
            last_seen: now,
        });
        if now.saturating_sub(state.window_start) > KEY_WINDOW_SECS {
            state.count = 0;
            state.window_start = now;
        }
        state.count = state.count.saturating_add(1);
        state.last_seen = now;
        if state.count >= FAILURE_THRESHOLD {
            // The exponent is clamped so the shift can never overflow before the cap applies.
            let exponent = (state.count - FAILURE_THRESHOLD).min(10);
            let lock = (BASE_LOCK_SECS << exponent).min(MAX_LOCK_SECS);
            state.locked_until = now.saturating_add(lock);
        }
    }

    pub fn record_success(&mut self, key: &str) {
        self.keys.remove(key);
    }

    pub fn tracked_keys(&self) -> usize {
        self.keys.len()
    }

    fn record_global(&mut self, now: u64) {
        // Failures older than the sliding window no longer count toward the ceiling.
        while let Some(&front) = self.global_failures.front() {
            if now.saturating_sub(front) > GLOBAL_WINDOW_SECS {
                self.global_failures.pop_front();
            } else {
                break;
            }
        }
        self.global_failures.push_back(now);
        if self.global_failures.len() >= GLOBAL_THRESHOLD {
            self.global_locked_until = now.saturating_add(GLOBAL_LOCK_SECS);
            self.global_failures.clear();
        }
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .keys
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest {
            self.keys.remove(&key);
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    per_sec: f64,
    tokens: f64,
    last_ms: Option<u64>,
}

impl TokenBucket {
    pub fn new(capacity: u32, per_sec: u32) -> Self {
        Self {
            capacity: f64::from(capacity),
            per_sec: f64::from(per_sec),
            tokens: f64::from(capacity),
            last_ms: None,
        }
    }

    pub fn try_take(&mut self, now_ms: u64) -> bool {
        if let Some(last) = self.last_ms {
            let elapsed = now_ms.saturating_sub(last) as f64;
            self.tokens = (self.tokens + elapsed * self.per_sec / 1000.0).min(self.capacity);
        }
        self.last_ms = Some(self.last_ms.map_or(now_ms, |last| last.max(now_ms)));
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail_n(l: &mut LoginLimiter, key: &str, n: u32, now: u64) {
        for _ in 0..n {
            l.record_failure(key, now);
        }
    }

    #[test]
    fn local_failures_never_arm_the_global_lock() {
        let mut l = LoginLimiter::new();
        for i in 0..200 {
            l.record_failure_local(&format!("k{i}"), 10);
        }
        assert_eq!(l.check("fresh", 10), Ok(()));
        fail_n(&mut l, "ip", 5, 10);
        assert_eq!(l.check("ip", 10), Err(30));
    }

    #[test]
    fn fresh_key_is_allowed() {
        assert_eq!(LoginLimiter::new().check("1.2.3.4", 0), Ok(()));
    }

    #[test]
    fn four_failures_do_not_lock() {
        let mut l = LoginLimiter::new();
        fail_n(&mut l, "ip", 4, 100);
        assert_eq!(l.check("ip", 100), Ok(()));
    }

    #[test]
    fn fifth_failure_locks_for_30_seconds() {
        let mut l = LoginLimiter::new();
        fail_n(&mut l, "ip", 5, 100);
        assert_eq!(l.check("ip", 100), Err(30));
        assert_eq!(l.check("ip", 129), Err(1));
        assert_eq!(l.check("ip", 130), Ok(()));
    }

    #[test]
    fn lock_is_per_key() {
        let mut l = LoginLimiter::new();
        fail_n(&mut l, "bad", 5, 0);
        assert!(l.check("bad", 1).is_err());
        assert_eq!(l.check("good", 1), Ok(()));
    }

    #[test]
    fn lockout_doubles_then_caps_at_15_minutes() {
        let mut l = LoginLimiter::new();
        fail_n(&mut l, "ip", 4, 0);
        let mut observed = Vec::new();
        for _ in 0..8 {
            l.record_failure("ip", 0);
            observed.push(l.check("ip", 0).unwrap_err());
        }
        assert_eq!(observed, vec![30, 60, 120, 240, 480, 900, 900, 900]);
    }

    #[test]
    fn success_clears_the_key() {
        let mut l = LoginLimiter::new();
        fail_n(&mut l, "ip", 5, 0);
        l.record_success("ip");
        assert_eq!(l.check("ip", 1), Ok(()));
        fail_n(&mut l, "ip", 4, 2);
        assert_eq!(l.check("ip", 2), Ok(()));
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate() {
        let mut l = LoginLimiter::new();
        fail_n(&mut l, "ip", 4, 0);
        l.record_failure("ip", KEY_WINDOW_SECS + 1);
        assert_eq!(l.check("ip", KEY_WINDOW_SECS + 1), Ok(()));
    }

    #[test]
    fn global_ceiling_locks_every_key_for_a_minute() {
        let mut l = LoginLimiter::new();
        for i in 0..100 {
            l.record_failure(&format!("ip{i}"), 1000);
        }
        assert_eq!(l.check("someone-new", 1000), Err(60));
        assert_eq!(l.check("someone-new", 1059), Err(1));
        assert_eq!(l.check("someone-new", 1060), Ok(()));
    }

    #[test]
    fn global_failures_age_out_of_the_window() {
        let mut l = LoginLimiter::new();
        for i in 0..99 {
            l.record_failure(&format!("ip{i}"), 0);
        }
        l.record_failure("late", GLOBAL_WINDOW_SECS + 10);
        assert_eq!(l.check("anyone", GLOBAL_WINDOW_SECS + 10), Ok(()));
    }

    #[test]
    fn key_map_is_bounded_and_evicts_oldest() {
        let mut l = LoginLimiter::new();
        for i in 0..(MAX_KEYS as u64 + 50) {
            l.record_failure(&format!("ip{i}"), i);
        }
        assert_eq!(l.tracked_keys(), MAX_KEYS);
        assert!(!l.keys.contains_key("ip0"));
        assert!(l.keys.contains_key(&format!("ip{}", MAX_KEYS as u64 + 49)));
    }

    #[test]
    fn bucket_starts_full_and_drains() {
        let mut b = TokenBucket::new(3, 1);
        assert!(b.try_take(0));
        assert!(b.try_take(0));
        assert!(b.try_take(0));
        assert!(!b.try_take(0));
    }

    #[test]
    fn bucket_refills_at_the_configured_rate() {
        let mut b = TokenBucket::new(3, 2);
        for _ in 0..3 {
            assert!(b.try_take(0));
        }
        assert!(!b.try_take(400));
        assert!(b.try_take(600));
        assert!(!b.try_take(600));
    }

    #[test]
    fn bucket_never_exceeds_capacity() {
        let mut b = TokenBucket::new(2, 100);
        assert!(b.try_take(0));
        assert!(b.try_take(10_000));
        assert!(b.try_take(10_000));
        assert!(!b.try_take(10_000));
    }

    #[test]
    fn bucket_tolerates_clock_going_backwards() {
        let mut b = TokenBucket::new(1, 1);
        assert!(b.try_take(5_000));
        assert!(!b.try_take(1_000));
        assert!(b.try_take(6_000));
    }
}
