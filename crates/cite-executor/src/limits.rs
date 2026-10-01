#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use cite_core::ExecutorConfig;
use tracing::{info, warn};

const SHARDS: usize = 16;
/// Candidates examined when a full shard needs room, so insertion cost does not grow with the table.
const EVICTION_SAMPLE: usize = 16;
/// Upper bound on tracked clients across all shards.
pub const MAX_TRACKED: usize = 100_000;
/// Window in which rate-limit violations count towards a ban.
const BAN_WINDOW: Duration = Duration::from_secs(10);
/// Ban log lines allowed per sweep interval; the rest are summarised.
const LOG_BUDGET: u32 = 10;
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// Client identity: an IPv4 address, or the /64 prefix of an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKey {
    V4(u32),
    V6(u64),
}

impl ClientKey {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(addr) => Self::V4(u32::from(addr)),
            IpAddr::V6(addr) => match addr.to_ipv4_mapped() {
                Some(v4) => Self::V4(u32::from(v4)),
                None => Self::V6((u128::from(addr) >> 64) as u64),
            },
        }
    }
}

impl fmt::Display for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(bits) => write!(f, "{}", std::net::Ipv4Addr::from(*bits)),
            Self::V6(bits) => write!(
                f,
                "{}/64",
                std::net::Ipv6Addr::from(u128::from(*bits) << 64)
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LimitConfig {
    pub max_conn_per_ip: usize,
    pub rate: u32,
    pub burst: u32,
    pub ban_threshold: u32,
    pub ban_duration: Duration,
    pub capacity: usize,
}

impl LimitConfig {
    pub fn from_executor(config: &ExecutorConfig) -> Self {
        Self {
            max_conn_per_ip: config.max_conn_per_ip,
            rate: config.rate_limit,
            burst: config.rate_burst,
            ban_threshold: config.ban_threshold,
            ban_duration: config.ban_duration,
            capacity: MAX_TRACKED,
        }
    }

    fn rate_enabled(&self) -> bool {
        self.rate > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Limited { retry_after: u64 },
    Banned { retry_after: u64 },
}

pub enum Admission {
    Allowed(Option<ConnSlot>),
    Banned,
    TooMany,
}

struct Entry {
    tokens: f64,
    refilled: Instant,
    conns: u32,
    strikes: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
    last_seen: Instant,
}

impl Entry {
    fn new(burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            refilled: now,
            conns: 0,
            strikes: 0,
            window_start: now,
            banned_until: None,
            last_seen: now,
        }
    }

    fn banned(&self, now: Instant) -> bool {
        self.banned_until.is_some_and(|until| until > now)
    }
}

/// Clients plus their insertion order; `order` holds exactly the keys of `map`, oldest first.
#[derive(Default)]
struct Shard {
    map: HashMap<ClientKey, Entry>,
    order: VecDeque<ClientKey>,
}

pub struct Limiter {
    cfg: LimitConfig,
    hasher: RandomState,
    shards: Vec<Mutex<Shard>>,
    limited: AtomicU64,
    bans: AtomicU64,
    dropped: AtomicU64,
    interval_limited: AtomicU64,
    interval_bans: AtomicU64,
    interval_dropped: AtomicU64,
    log_budget: AtomicU32,
    untrusted_forwarded: AtomicU64,
}

/// Releases a client's connection count when the connection (or upgraded tunnel) ends.
pub struct ConnSlot {
    limiter: Arc<Limiter>,
    key: ClientKey,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut shard = self.limiter.shard(self.key);
        if let Some(entry) = shard.map.get_mut(&self.key) {
            entry.conns = entry.conns.saturating_sub(1);
        }
    }
}

impl Limiter {
    pub fn new(cfg: LimitConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect(),
            limited: AtomicU64::new(0),
            bans: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            interval_limited: AtomicU64::new(0),
            interval_bans: AtomicU64::new(0),
            interval_dropped: AtomicU64::new(0),
            log_budget: AtomicU32::new(0),
            untrusted_forwarded: AtomicU64::new(0),
        })
    }

    pub fn limited_requests(&self) -> u64 {
        self.limited.load(Ordering::Relaxed)
    }

    pub fn bans(&self) -> u64 {
        self.bans.load(Ordering::Relaxed)
    }

    pub fn dropped_connections(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn tracked(&self) -> usize {
        (0..SHARDS)
            .map(|idx| lock(&self.shards[idx]).map.len())
            .sum()
    }

    fn shard(&self, key: ClientKey) -> MutexGuard<'_, Shard> {
        let idx = (self.hasher.hash_one(key) as usize) % SHARDS;
        lock(&self.shards[idx])
    }

    fn shard_capacity(&self) -> usize {
        (self.cfg.capacity / SHARDS).max(1)
    }

    fn idle_after(&self) -> Duration {
        if !self.cfg.rate_enabled() {
            return BAN_WINDOW;
        }
        let refill = Duration::from_secs_f64(f64::from(self.cfg.burst) / f64::from(self.cfg.rate));
        BAN_WINDOW.max(refill + Duration::from_secs(1))
    }

    /// Returns the entry for `key`; a full shard evicts its oldest unpinned client, or `None` when every candidate is pinned.
    fn entry<'a>(
        &self,
        shard: &'a mut Shard,
        key: ClientKey,
        now: Instant,
    ) -> Option<&'a mut Entry> {
        if !shard.map.contains_key(&key) {
            if shard.map.len() >= self.shard_capacity() && !Self::evict_one(shard, now) {
                return None;
            }
            shard.map.insert(key, Entry::new(self.cfg.burst, now));
            shard.order.push_back(key);
        }
        shard.map.get_mut(&key)
    }

    /// Pinned or banned clients are rotated to the back, so they never block eviction of the rest.
    fn evict_one(shard: &mut Shard, now: Instant) -> bool {
        for _ in 0..EVICTION_SAMPLE {
            let Some(candidate) = shard.order.pop_front() else {
                return false;
            };
            let keep = shard
                .map
                .get(&candidate)
                .is_some_and(|e| e.conns > 0 || e.banned(now));
            if keep {
                shard.order.push_back(candidate);
            } else {
                shard.map.remove(&candidate);
                return true;
            }
        }
        false
    }

    /// Records a request from an untrusted peer that carried X-Forwarded-For; the sweep logs one hint per interval.
    pub fn note_untrusted_forwarded(&self) {
        self.untrusted_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Connection-level admission for a peer that is not a trusted proxy.
    pub fn admit_connection(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Admission {
        let key = ClientKey::from_ip(ip);
        let track = self.cfg.max_conn_per_ip > 0;
        if !track && !self.cfg.rate_enabled() {
            return Admission::Allowed(None);
        }
        let mut shard = self.shard(key);
        if self.cfg.rate_enabled() && shard.map.get(&key).is_some_and(|e| e.banned(now)) {
            drop(shard);
            self.count_dropped();
            return Admission::Banned;
        }
        if !track {
            return Admission::Allowed(None);
        }
        let Some(entry) = self.entry(&mut shard, key, now) else {
            return Admission::Allowed(None);
        };
        if entry.conns as usize >= self.cfg.max_conn_per_ip {
            drop(shard);
            self.count_dropped();
            return Admission::TooMany;
        }
        entry.conns += 1;
        entry.last_seen = now;
        drop(shard);
        Admission::Allowed(Some(ConnSlot {
            limiter: self.clone(),
            key,
        }))
    }

    pub fn check_request(&self, ip: IpAddr, now: Instant) -> Verdict {
        if !self.cfg.rate_enabled() {
            return Verdict::Allow;
        }
        let key = ClientKey::from_ip(ip);
        let mut event = Event::None;
        let verdict = {
            let mut shard = self.shard(key);
            match self.entry(&mut shard, key, now) {
                Some(entry) => self.step(entry, now, &mut event),
                None => Verdict::Allow,
            }
        };
        match event {
            Event::None => {}
            Event::Banned => {
                self.bans.fetch_add(1, Ordering::Relaxed);
                self.interval_bans.fetch_add(1, Ordering::Relaxed);
                self.log_ban(key, "client banned for repeated rate limit violations");
            }
            Event::Unbanned => self.log_ban(key, "client ban expired"),
        }
        if matches!(verdict, Verdict::Limited { .. } | Verdict::Banned { .. }) {
            self.limited.fetch_add(1, Ordering::Relaxed);
            self.interval_limited.fetch_add(1, Ordering::Relaxed);
        }
        verdict
    }

    fn step(&self, entry: &mut Entry, now: Instant, event: &mut Event) -> Verdict {
        entry.last_seen = now;
        if let Some(until) = entry.banned_until {
            if until > now {
                return Verdict::Banned {
                    retry_after: ceil_secs(until - now),
                };
            }
            entry.banned_until = None;
            entry.strikes = 0;
            entry.window_start = now;
            entry.tokens = f64::from(self.cfg.burst);
            entry.refilled = now;
            *event = Event::Unbanned;
        }
        let rate = f64::from(self.cfg.rate);
        let elapsed = now.saturating_duration_since(entry.refilled).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * rate).min(f64::from(self.cfg.burst));
        entry.refilled = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            return Verdict::Allow;
        }
        if now.saturating_duration_since(entry.window_start) > BAN_WINDOW {
            entry.strikes = 0;
            entry.window_start = now;
        }
        entry.strikes += 1;
        if entry.strikes > self.cfg.ban_threshold {
            entry.banned_until = Some(now + self.cfg.ban_duration);
            *event = Event::Banned;
            return Verdict::Banned {
                retry_after: ceil_secs(self.cfg.ban_duration),
            };
        }
        let wait = (1.0 - entry.tokens) / rate;
        Verdict::Limited {
            retry_after: (wait.ceil() as u64).max(1),
        }
    }

    fn count_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.interval_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn log_ban(&self, key: ClientKey, message: &str) {
        if self.log_budget.fetch_add(1, Ordering::Relaxed) < LOG_BUDGET {
            warn!(client = %key, "{message}");
        }
    }

    /// Drops idle entries, ends expired bans and logs one summary line per interval.
    pub fn sweep(&self, now: Instant) {
        let idle = self.idle_after();
        let mut ended = Vec::new();
        for idx in 0..SHARDS {
            let mut shard = lock(&self.shards[idx]);
            for (key, entry) in shard.map.iter_mut() {
                if entry.banned_until.is_some_and(|until| until <= now) {
                    entry.banned_until = None;
                    entry.strikes = 0;
                    entry.last_seen = now;
                    ended.push(*key);
                }
            }
            shard.map.retain(|_, e| {
                e.conns > 0 || e.banned(now) || now.saturating_duration_since(e.last_seen) <= idle
            });
            let Shard { map, order } = &mut *shard;
            order.retain(|key| map.contains_key(key));
        }
        for key in ended {
            self.log_ban(key, "client ban expired");
        }
        let forwarded = self.untrusted_forwarded.swap(0, Ordering::Relaxed);
        if forwarded > 0 {
            warn!(
                requests = forwarded,
                "requests with X-Forwarded-For from an untrusted peer are attributed to that peer; behind a reverse proxy set CITE_TRUSTED_PROXIES to its address"
            );
        }
        let limited = self.interval_limited.swap(0, Ordering::Relaxed);
        let bans = self.interval_bans.swap(0, Ordering::Relaxed);
        let dropped = self.interval_dropped.swap(0, Ordering::Relaxed);
        let logged = self.log_budget.swap(0, Ordering::Relaxed);
        if limited + bans + dropped > 0 {
            info!(
                limited,
                bans,
                dropped,
                suppressed_ban_logs = logged.saturating_sub(LOG_BUDGET),
                tracked = self.tracked(),
                "abuse protection activity in the last interval"
            );
        }
    }
}

enum Event {
    None,
    Banned,
    Unbanned,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn ceil_secs(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn cfg() -> LimitConfig {
        LimitConfig {
            max_conn_per_ip: 2,
            rate: 10,
            burst: 5,
            ban_threshold: 3,
            ban_duration: Duration::from_secs(30),
            capacity: MAX_TRACKED,
        }
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn token_bucket_allows_burst_then_limits_and_refills() {
        let limiter = Limiter::new(cfg());
        let t0 = Instant::now();
        for _ in 0..5 {
            assert_eq!(limiter.check_request(v4(1), t0), Verdict::Allow);
        }
        assert_eq!(
            limiter.check_request(v4(1), t0),
            Verdict::Limited { retry_after: 1 }
        );
        let later = t0 + Duration::from_millis(250);
        assert_eq!(limiter.check_request(v4(1), later), Verdict::Allow);
        assert_eq!(limiter.check_request(v4(1), later), Verdict::Allow);
        assert!(matches!(
            limiter.check_request(v4(1), later),
            Verdict::Limited { .. }
        ));
        let full = t0 + Duration::from_secs(60);
        for _ in 0..5 {
            assert_eq!(limiter.check_request(v4(1), full), Verdict::Allow);
        }
        assert!(matches!(
            limiter.check_request(v4(1), full),
            Verdict::Limited { .. }
        ));
    }

    #[test]
    fn clients_are_limited_independently() {
        let limiter = Limiter::new(cfg());
        let t0 = Instant::now();
        for _ in 0..5 {
            limiter.check_request(v4(1), t0);
        }
        assert!(matches!(
            limiter.check_request(v4(1), t0),
            Verdict::Limited { .. }
        ));
        assert_eq!(limiter.check_request(v4(2), t0), Verdict::Allow);
    }

    #[test]
    fn ban_after_threshold_then_expires() {
        let limiter = Limiter::new(cfg());
        let t0 = Instant::now();
        for _ in 0..5 {
            limiter.check_request(v4(1), t0);
        }
        for _ in 0..3 {
            assert!(matches!(
                limiter.check_request(v4(1), t0),
                Verdict::Limited { .. }
            ));
        }
        assert_eq!(
            limiter.check_request(v4(1), t0),
            Verdict::Banned { retry_after: 30 }
        );
        assert_eq!(limiter.bans(), 1);
        assert!(matches!(
            limiter.admit_connection(v4(1), t0),
            Admission::Banned
        ));
        assert_eq!(limiter.dropped_connections(), 1);
        let during = t0 + Duration::from_secs(10);
        assert_eq!(
            limiter.check_request(v4(1), during),
            Verdict::Banned { retry_after: 20 }
        );
        let after = t0 + Duration::from_secs(31);
        assert_eq!(limiter.check_request(v4(1), after), Verdict::Allow);
        assert!(matches!(
            limiter.admit_connection(v4(1), after),
            Admission::Allowed(_)
        ));
        assert!(limiter.limited_requests() >= 5);
    }

    #[test]
    fn violations_outside_the_window_do_not_ban() {
        let limiter = Limiter::new(cfg());
        let t0 = Instant::now();
        for step in 0..6u64 {
            let at = t0 + Duration::from_secs(step * 11);
            let mut last = Verdict::Allow;
            for _ in 0..8 {
                last = limiter.check_request(v4(1), at);
            }
            assert!(matches!(last, Verdict::Limited { .. }), "step {step}");
        }
        assert_eq!(limiter.bans(), 0);
    }

    #[test]
    fn connection_cap_is_per_client_and_released_on_drop() {
        let limiter = Limiter::new(cfg());
        let now = Instant::now();
        let first = limiter.admit_connection(v4(1), now);
        let second = limiter.admit_connection(v4(1), now);
        assert!(matches!(first, Admission::Allowed(Some(_))));
        assert!(matches!(second, Admission::Allowed(Some(_))));
        assert!(matches!(
            limiter.admit_connection(v4(1), now),
            Admission::TooMany
        ));
        assert!(matches!(
            limiter.admit_connection(v4(2), now),
            Admission::Allowed(Some(_))
        ));
        drop(first);
        assert!(matches!(
            limiter.admit_connection(v4(1), now),
            Admission::Allowed(Some(_))
        ));
        drop(second);
    }

    #[test]
    fn ipv6_clients_share_a_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse::<Ipv6Addr>().unwrap().into();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse::<Ipv6Addr>().unwrap().into();
        let c: IpAddr = "2001:db8:1:3::1".parse::<Ipv6Addr>().unwrap().into();
        assert_eq!(ClientKey::from_ip(a), ClientKey::from_ip(b));
        assert_ne!(ClientKey::from_ip(a), ClientKey::from_ip(c));
        let limiter = Limiter::new(cfg());
        let t0 = Instant::now();
        for _ in 0..5 {
            limiter.check_request(a, t0);
        }
        assert!(matches!(
            limiter.check_request(b, t0),
            Verdict::Limited { .. }
        ));
        assert_eq!(limiter.check_request(c, t0), Verdict::Allow);
        let mapped: IpAddr = "::ffff:192.0.2.1".parse::<Ipv6Addr>().unwrap().into();
        assert_eq!(ClientKey::from_ip(mapped), ClientKey::from_ip(v4(1)));
        assert_eq!(ClientKey::from_ip(a).to_string(), "2001:db8:1:2::/64");
    }

    #[test]
    fn table_is_bounded_and_evicts_idle_entries() {
        let mut small = cfg();
        small.capacity = SHARDS * 4;
        let limiter = Limiter::new(small);
        let t0 = Instant::now();
        for host in 0..2000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + host));
            let at = t0 + Duration::from_millis(u64::from(host));
            assert_eq!(limiter.check_request(ip, at), Verdict::Allow);
            assert!(limiter.tracked() <= SHARDS * 4);
        }
        assert!(limiter.tracked() > 0);
    }

    #[test]
    fn insertion_at_capacity_stays_fast_and_bounded() {
        let mut small = cfg();
        small.capacity = MAX_TRACKED;
        let limiter = Limiter::new(small);
        let t0 = Instant::now();
        let started = Instant::now();
        for n in 0..200_000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32.wrapping_add(n)));
            limiter.check_request(ip, t0 + Duration::from_micros(u64::from(n)));
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(limiter.tracked() <= MAX_TRACKED);
    }

    #[test]
    fn eviction_never_removes_pinned_connections() {
        let mut small = cfg();
        small.capacity = SHARDS * 2;
        small.max_conn_per_ip = 5;
        let limiter = Limiter::new(small);
        let t0 = Instant::now();
        let pinned = limiter.admit_connection(v4(1), t0);
        assert!(matches!(pinned, Admission::Allowed(Some(_))));
        for n in 0..5000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + n));
            limiter.check_request(ip, t0 + Duration::from_millis(u64::from(n)));
        }
        let second = limiter.admit_connection(v4(1), t0);
        let third = limiter.admit_connection(v4(1), t0);
        let fourth = limiter.admit_connection(v4(1), t0);
        let fifth = limiter.admit_connection(v4(1), t0);
        assert!(matches!(fifth, Admission::Allowed(Some(_))));
        assert!(matches!(
            limiter.admit_connection(v4(1), t0),
            Admission::TooMany
        ));
        drop((pinned, second, third, fourth, fifth));
    }

    #[test]
    fn pinned_entries_at_the_iteration_front_do_not_make_the_limiter_fail_open() {
        let mut small = cfg();
        small.capacity = SHARDS * 64;
        small.max_conn_per_ip = 5;
        let limiter = Limiter::new(small);
        let t0 = Instant::now();
        let mut pinned = Vec::new();
        for n in 0..400u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0c00_0000 + n));
            if let Admission::Allowed(Some(slot)) = limiter.admit_connection(ip, t0) {
                pinned.push(slot);
            }
        }
        for n in 0..2000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0d00_0000 + n));
            limiter.check_request(ip, t0 + Duration::from_millis(u64::from(n)));
        }
        let fresh = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
        let at = t0 + Duration::from_secs(5);
        for _ in 0..5 {
            limiter.check_request(fresh, at);
        }
        assert!(matches!(
            limiter.check_request(fresh, at),
            Verdict::Limited { .. }
        ));
        assert!(limiter.tracked() <= SHARDS * 64);
        drop(pinned);
    }

    #[test]
    fn saturated_table_fails_open_for_pinned_entries() {
        let mut small = cfg();
        small.capacity = SHARDS;
        let limiter = Limiter::new(small);
        let now = Instant::now();
        let mut slots = Vec::new();
        for host in 0..200u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + host));
            if let Admission::Allowed(Some(slot)) = limiter.admit_connection(ip, now) {
                slots.push(slot);
            }
        }
        assert!(limiter.tracked() <= SHARDS);
        let stranger = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(limiter.check_request(stranger, now), Verdict::Allow);
    }

    #[test]
    fn sweep_removes_idle_entries_and_keeps_live_ones() {
        let limiter = Limiter::new(cfg());
        let t0 = Instant::now();
        limiter.check_request(v4(1), t0);
        let held = limiter.admit_connection(v4(2), t0);
        assert_eq!(limiter.tracked(), 2);
        limiter.sweep(t0 + Duration::from_secs(120));
        assert_eq!(limiter.tracked(), 1);
        drop(held);
        limiter.sweep(t0 + Duration::from_secs(240));
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn disabled_rate_limit_never_limits_or_bans() {
        let mut off = cfg();
        off.rate = 0;
        let limiter = Limiter::new(off);
        let t0 = Instant::now();
        for _ in 0..10_000 {
            assert_eq!(limiter.check_request(v4(1), t0), Verdict::Allow);
        }
        assert_eq!(limiter.tracked(), 0);
        assert_eq!(limiter.bans(), 0);
        assert!(matches!(
            limiter.admit_connection(v4(1), t0),
            Admission::Allowed(Some(_))
        ));
    }

    #[test]
    fn zero_connection_cap_disables_the_cap_only() {
        let mut open = cfg();
        open.max_conn_per_ip = 0;
        let limiter = Limiter::new(open);
        let now = Instant::now();
        for _ in 0..100 {
            assert!(matches!(
                limiter.admit_connection(v4(1), now),
                Admission::Allowed(None)
            ));
        }
        assert_eq!(limiter.tracked(), 0);
    }
}
