use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Write};
use std::ops::Bound;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::model::{LogEvent, Retention};

const MAX_SITES: usize = 256;
const OTHER_SITE: &str = "other";
const TOP_N: usize = 20;
const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;
const MINUTE_MAX_WINDOW_SECS: u64 = 48 * 3600;
const MAX_WINDOW_SECS: u64 = 400 * 86_400;
const PRUNE_EVERY: u32 = 8192;
const SNAPSHOT_VERSION: u32 = 1;
const DEFAULT_BUDGET: usize = 128 * 1024 * 1024;
const MIN_BUDGET: usize = 1024 * 1024;
// Eviction frees down to this fraction of the budget so it runs once per ten percent of growth.
const LOW_WATER_DIV: usize = 10;
// Budget pressure never touches the newest minutes and hours until nothing older is left.
const KEEP_MINUTES: i64 = 60;
const KEEP_HOURS: i64 = 24;
const MAX_CAP_SHIFT: u8 = 3;
const SPARE_CANDIDATES: usize = 8;
const MIN_CAP: usize = 2;
// Allocator, hash table and String header overhead added to the key bytes of one retained entry.
const ENTRY_OVERHEAD: usize = 96;
const COUNT_OVERHEAD: usize = 48;
// B-tree nodes are about two thirds full, so each bucket slot carries half again its inline size.
const BUCKET_BASE: usize = std::mem::size_of::<Bucket>() * 3 / 2 + (LAT_LEN + SIZE_LEN) * 4 + 64;

const LAT_LEN: usize = 128;
const SIZE_LES: [u64; 9] = [
    1 << 10,
    1 << 12,
    1 << 14,
    1 << 16,
    1 << 18,
    1 << 20,
    1 << 22,
    1 << 24,
    1 << 26,
];
const SIZE_LEN: usize = SIZE_LES.len() + 1;

const KEY_PATH: usize = 128;
const KEY_IP: usize = 45;
const KEY_UA: usize = 96;
const KEY_HOST: usize = 64;
const KEY_RULE: usize = 64;
const KEY_METHOD: usize = 16;
const KEY_CTYPE: usize = 64;

// Per-bucket key caps: minute buckets are numerous so they stay tiny, hour buckets carry the detail.
const MINUTE_CAPS: Caps = Caps {
    paths: 10,
    ips: 6,
    uas: 4,
    hosts: 3,
    rules: 3,
};
const HOUR_CAPS: Caps = Caps {
    paths: 64,
    ips: 32,
    uas: 16,
    hosts: 16,
    rules: 16,
};
const METHOD_CAP: usize = 16;
const CTYPE_CAP: usize = 32;

struct Caps {
    paths: usize,
    ips: usize,
    uas: usize,
    hosts: usize,
    rules: usize,
}

impl Caps {
    // Budget pressure halves every cap per shift step, never below MIN_CAP.
    fn shifted(&self, shift: u8) -> Caps {
        let f = |n: usize| (n >> shift).max(MIN_CAP);
        Caps {
            paths: f(self.paths),
            ips: f(self.ips),
            uas: f(self.uas),
            hosts: f(self.hosts),
            rules: f(self.rules),
        }
    }
}

fn caps_for(hour: bool, shift: u8) -> Caps {
    if hour { &HOUR_CAPS } else { &MINUTE_CAPS }.shifted(shift)
}

pub fn window_from_str(s: &str) -> Option<u64> {
    match s {
        "15m" => Some(15 * 60),
        "1h" => Some(3600),
        "24h" => Some(24 * 3600),
        "7d" => Some(7 * 86_400),
        "30d" => Some(30 * 86_400),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopItem {
    pub key: String,
    pub count: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeBucket {
    // None is the open-ended final bucket (+Inf); counts are cumulative like le buckets
    pub le: Option<u64>,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub blocked: u64,
    pub errors_4xx: u64,
    pub errors_5xx: u64,
    pub avg_ms: f64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub status: BTreeMap<String, u64>,
    pub methods: BTreeMap<String, u64>,
    pub content_types: BTreeMap<String, u64>,
    pub sizes: Vec<SizeBucket>,
    pub top_paths: Vec<TopItem>,
    pub top_ips: Vec<TopItem>,
    pub top_user_agents: Vec<TopItem>,
    pub top_hosts: Vec<TopItem>,
    pub top_blocked: Vec<TopItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub ts: i64,
    pub requests: u64,
    pub bytes_out: u64,
    pub errors: u64,
    pub blocked: u64,
    pub avg_ms: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Timeseries {
    pub step_secs: u64,
    pub points: Vec<Point>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestFilter {
    pub status: Option<u16>,
    pub method: Option<String>,
    pub path_contains: Option<String>,
    pub ip: Option<String>,
    pub blocked_only: bool,
    pub site: Option<String>,
}

impl RequestFilter {
    fn matches(&self, ev: &LogEvent) -> bool {
        self.status.is_none_or(|s| s == ev.status)
            && self.site.as_deref().is_none_or(|s| s == ev.site)
            && self
                .method
                .as_deref()
                .is_none_or(|m| m.eq_ignore_ascii_case(&ev.method))
            && self
                .path_contains
                .as_deref()
                .is_none_or(|p| ev.path.contains(p))
            && self.ip.as_deref().is_none_or(|i| i == ev.client_ip)
            && (!self.blocked_only || ev.blocked.is_some())
    }
}

// Log-scale histogram: exact below 4 ms, then four sub-buckets per power of two (about 12% error).
fn lat_index(ms: u32) -> usize {
    if ms < 4 {
        return ms as usize;
    }
    let bits = (32 - ms.leading_zeros()) as usize;
    let sub = ((ms >> (bits - 3)) & 3) as usize;
    4 + (bits - 3) * 4 + sub
}

fn lat_lower(idx: usize) -> u64 {
    if idx < 4 {
        return idx as u64;
    }
    let k = idx - 4;
    let bits = k / 4 + 3;
    (4 + (k % 4) as u64) << (bits - 3)
}

fn lat_mid(idx: usize) -> u64 {
    if idx < 4 {
        return idx as u64;
    }
    let lo = lat_lower(idx);
    let hi = lat_lower(idx + 1) - 1;
    (lo + hi) / 2
}

fn size_index(bytes: u64) -> usize {
    SIZE_LES
        .iter()
        .position(|&l| bytes <= l)
        .unwrap_or(SIZE_LES.len())
}

// Nearest-rank percentile over the merged histogram, reported as the bucket midpoint.
fn percentile(hist: &[u64], total: u64, pct: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let target = total.saturating_mul(pct).div_ceil(100).max(1);
    let mut acc = 0u64;
    for (i, c) in hist.iter().enumerate() {
        acc += c;
        if acc >= target {
            return lat_mid(i);
        }
    }
    0
}

fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

fn bump32(v: &mut [u32], i: usize) {
    if let Some(c) = v.get_mut(i) {
        *c = c.saturating_add(1);
    }
}

// Space-saving top-K: a full map evicts its minimum and the newcomer inherits that count.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TopK {
    cap: usize,
    map: HashMap<String, (u64, u64)>,
    // Eviction candidates at the minimum count `spare_min`; still minimal while that count holds.
    #[serde(skip)]
    spare: Vec<String>,
    #[serde(skip)]
    spare_min: u64,
}

impl TopK {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            map: HashMap::new(),
            spare: Vec::new(),
            spare_min: 0,
        }
    }

    fn take_min(&mut self) -> Option<(String, u64)> {
        while let Some(k) = self.spare.pop() {
            if self.map.get(&k).is_some_and(|v| v.0 == self.spare_min) {
                self.map.remove(&k);
                return Some((k, self.spare_min));
            }
        }
        let min = self.map.values().map(|v| v.0).min()?;
        self.spare = self
            .map
            .iter()
            .filter(|(_, v)| v.0 == min)
            .take(SPARE_CANDIDATES)
            .map(|(k, _)| k.clone())
            .collect();
        self.spare_min = min;
        let k = self.spare.pop()?;
        self.map.remove(&k);
        Some((k, min))
    }

    // Releases the candidate cache once a bucket stops receiving events.
    fn seal(&mut self) {
        self.spare = Vec::new();
    }

    // Returns the change in retained bytes.
    fn add(&mut self, key: &str, bytes: u64) -> isize {
        if let Some(e) = self.map.get_mut(key) {
            e.0 += 1;
            e.1 += bytes;
            return 0;
        }
        if self.map.len() >= self.cap
            && let Some((victim, count)) = self.take_min()
        {
            self.map.insert(key.to_string(), (count + 1, bytes));
            return entry_cost(key) as isize - entry_cost(&victim) as isize;
        }
        self.map.insert(key.to_string(), (1, bytes));
        entry_cost(key) as isize
    }

    fn cost(&self) -> usize {
        self.map.keys().map(|k| entry_cost(k)).sum()
    }

    // Re-applies a cap and key length to data that came from disk or from a larger cap.
    fn conform(&mut self, cap: usize, key_max: usize) {
        self.cap = cap;
        self.spare = Vec::new();
        let long = self.map.keys().any(|k| k.len() > key_max);
        if self.map.len() <= cap && !long {
            return;
        }
        let mut merged: HashMap<String, (u64, u64)> = HashMap::with_capacity(self.map.len());
        for (k, v) in self.map.drain() {
            let e = merged.entry(cut(&k, key_max).to_string()).or_insert((0, 0));
            e.0 += v.0;
            e.1 += v.1;
        }
        let mut ranked: Vec<(String, (u64, u64))> = merged.into_iter().collect();
        ranked.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
        ranked.truncate(cap);
        self.map = ranked.into_iter().collect();
    }
}

fn entry_cost(key: &str) -> usize {
    key.len() + ENTRY_OVERHEAD
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Counts {
    cap: usize,
    upper: bool,
    items: Vec<(String, u64)>,
}

impl Counts {
    fn new(cap: usize, upper: bool) -> Self {
        Self {
            cap,
            upper,
            items: Vec::new(),
        }
    }

    // Returns the change in retained bytes.
    fn add(&mut self, key: &str) -> isize {
        if let Some(it) = self
            .items
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
        {
            it.1 += 1;
            return 0;
        }
        if self.items.len() >= self.cap {
            let other = if self.upper { "OTHER" } else { "other" };
            if let Some(it) = self.items.iter_mut().find(|(k, _)| k == other) {
                it.1 += 1;
                return 0;
            }
            self.items.push((other.to_string(), 1));
            return item_cost(other);
        }
        let k = if self.upper {
            key.to_ascii_uppercase()
        } else {
            key.to_ascii_lowercase()
        };
        let cost = item_cost(&k);
        self.items.push((k, 1));
        cost
    }

    fn cost(&self) -> usize {
        self.items
            .iter()
            .map(|(k, _)| k.len() + COUNT_OVERHEAD)
            .sum()
    }

    fn conform(&mut self, cap: usize, key_max: usize) {
        self.cap = cap;
        for (k, _) in self.items.iter_mut() {
            if k.len() > key_max {
                *k = cut(k, key_max).to_string();
            }
        }
        self.items.truncate(cap);
    }
}

fn item_cost(key: &str) -> isize {
    (key.len() + COUNT_OVERHEAD) as isize
}

// Everything the hot path needs from one event, computed once and shared by all four buckets.
struct Prep<'a> {
    ts_ms: i64,
    class: usize,
    lat: usize,
    size: usize,
    ms: u64,
    bytes_in: u64,
    bytes_out: u64,
    blocked: Option<&'a str>,
    method: &'a str,
    ctype: &'a str,
    path: &'a str,
    ip: &'a str,
    ua: &'a str,
    host: &'a str,
}

impl<'a> Prep<'a> {
    fn new(ev: &'a LogEvent) -> Self {
        let class = match ev.status / 100 {
            c @ 1..=5 => c as usize,
            _ => 0,
        };
        let ctype = ev.content_type.split(';').next().unwrap_or("").trim();
        Self {
            ts_ms: ev.ts_ms,
            class,
            lat: lat_index(ev.total_ms),
            size: size_index(ev.bytes_out),
            ms: ev.total_ms as u64,
            bytes_in: ev.bytes_in,
            bytes_out: ev.bytes_out,
            blocked: ev
                .blocked
                .as_deref()
                .map(|b| cut(b, KEY_RULE))
                .filter(|b| !b.is_empty()),
            method: cut(&ev.method, KEY_METHOD),
            ctype: cut(ctype, KEY_CTYPE),
            path: cut(&ev.path, KEY_PATH),
            ip: cut(&ev.client_ip, KEY_IP),
            ua: cut(&ev.user_agent, KEY_UA),
            host: cut(&ev.host, KEY_HOST),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Bucket {
    requests: u64,
    bytes_in: u64,
    bytes_out: u64,
    blocked: u64,
    e4: u64,
    e5: u64,
    ms_sum: u64,
    status: [u64; 6],
    lat: Vec<u32>,
    sizes: Vec<u32>,
    methods: Counts,
    ctypes: Counts,
    paths: TopK,
    ips: TopK,
    uas: TopK,
    hosts: TopK,
    rules: TopK,
    // Running estimate of the heap this bucket retains; rebuilt on load, never written out.
    #[serde(skip)]
    est: usize,
}

impl Bucket {
    fn new(hour: bool, shift: u8) -> Self {
        let caps = caps_for(hour, shift);
        Self {
            est: BUCKET_BASE,
            requests: 0,
            bytes_in: 0,
            bytes_out: 0,
            blocked: 0,
            e4: 0,
            e5: 0,
            ms_sum: 0,
            status: [0; 6],
            lat: vec![0; LAT_LEN],
            sizes: vec![0; SIZE_LEN],
            methods: Counts::new(METHOD_CAP, true),
            ctypes: Counts::new(CTYPE_CAP, false),
            paths: TopK::new(caps.paths),
            ips: TopK::new(caps.ips),
            uas: TopK::new(caps.uas),
            hosts: TopK::new(caps.hosts),
            rules: TopK::new(caps.rules),
        }
    }

    // Returns the change in retained bytes.
    fn add(&mut self, p: &Prep) -> isize {
        self.requests += 1;
        self.bytes_in += p.bytes_in;
        self.bytes_out += p.bytes_out;
        self.ms_sum += p.ms;
        if let Some(c) = self.status.get_mut(p.class) {
            *c += 1;
        }
        match p.class {
            4 => self.e4 += 1,
            5 => self.e5 += 1,
            _ => {}
        }
        bump32(&mut self.lat, p.lat);
        bump32(&mut self.sizes, p.size);
        let mut delta = 0;
        if !p.method.is_empty() {
            delta += self.methods.add(p.method);
        }
        if !p.ctype.is_empty() {
            delta += self.ctypes.add(p.ctype);
        }
        if !p.path.is_empty() {
            delta += self.paths.add(p.path, p.bytes_out);
        }
        if !p.ip.is_empty() {
            delta += self.ips.add(p.ip, p.bytes_out);
        }
        if !p.ua.is_empty() {
            delta += self.uas.add(p.ua, p.bytes_out);
        }
        if !p.host.is_empty() {
            delta += self.hosts.add(p.host, p.bytes_out);
        }
        if let Some(rule) = p.blocked {
            self.blocked += 1;
            delta += self.rules.add(rule, p.bytes_out);
        }
        self.est = self.est.saturating_add_signed(delta);
        delta
    }

    fn seal(&mut self) {
        for t in [
            &mut self.paths,
            &mut self.ips,
            &mut self.uas,
            &mut self.hosts,
            &mut self.rules,
        ] {
            t.seal();
        }
    }

    fn measure(&self) -> usize {
        BUCKET_BASE
            + self.methods.cost()
            + self.ctypes.cost()
            + self.paths.cost()
            + self.ips.cost()
            + self.uas.cost()
            + self.hosts.cost()
            + self.rules.cost()
    }

    // Applies the current limits to a bucket that came from a snapshot or from larger caps.
    fn conform(&mut self, hour: bool, shift: u8) {
        self.lat.resize(LAT_LEN, 0);
        self.sizes.resize(SIZE_LEN, 0);
        let caps = caps_for(hour, shift);
        self.methods.conform(METHOD_CAP, KEY_METHOD);
        self.ctypes.conform(CTYPE_CAP, KEY_CTYPE);
        self.paths.conform(caps.paths, KEY_PATH);
        self.ips.conform(caps.ips, KEY_IP);
        self.uas.conform(caps.uas, KEY_UA);
        self.hosts.conform(caps.hosts, KEY_HOST);
        self.rules.conform(caps.rules, KEY_RULE);
        self.est = self.measure();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Scope {
    minutes: BTreeMap<i64, Bucket>,
    hours: BTreeMap<i64, Bucket>,
    // Buckets that last received an event; when it moves on they are sealed.
    #[serde(skip)]
    open_minute: i64,
    #[serde(skip)]
    open_hour: i64,
}

fn bucket_at<'a>(
    map: &'a mut BTreeMap<i64, Bucket>,
    key: i64,
    hour: bool,
    shift: u8,
    delta: &mut isize,
) -> &'a mut Bucket {
    match map.entry(key) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => {
            *delta += BUCKET_BASE as isize;
            v.insert(Bucket::new(hour, shift))
        }
    }
}

fn seal_previous(map: &mut BTreeMap<i64, Bucket>, open: &mut i64, now: i64) {
    if *open != now {
        if let Some(b) = map.get_mut(open) {
            b.seal();
        }
        *open = now;
    }
}

fn drop_before(map: &mut BTreeMap<i64, Bucket>, cut: i64) -> usize {
    if map.first_key_value().is_none_or(|(k, _)| *k >= cut) {
        return 0;
    }
    let kept = map.split_off(&cut);
    let dropped = std::mem::replace(map, kept);
    dropped.values().map(|b| b.est).sum()
}

fn drop_through(map: &mut BTreeMap<i64, Bucket>, upto: i64) -> usize {
    let mut freed = 0;
    while map.first_key_value().is_some_and(|(k, _)| *k <= upto) {
        if let Some((_, b)) = map.pop_first() {
            freed += b.est;
        }
    }
    freed
}

impl Scope {
    // Returns the change in retained bytes.
    fn add(&mut self, p: &Prep, shift: u8) -> isize {
        let mut delta = 0;
        let m = p.ts_ms.div_euclid(MINUTE_MS);
        seal_previous(&mut self.minutes, &mut self.open_minute, m);
        let minute = bucket_at(&mut self.minutes, m, false, shift, &mut delta);
        delta += minute.add(p);
        let h = p.ts_ms.div_euclid(HOUR_MS);
        seal_previous(&mut self.hours, &mut self.open_hour, h);
        let hour = bucket_at(&mut self.hours, h, true, shift, &mut delta);
        delta += hour.add(p);
        delta
    }

    // Returns the bytes released.
    fn prune(&mut self, minute_cut: i64, hour_cut: i64) -> usize {
        drop_before(&mut self.minutes, minute_cut) + drop_before(&mut self.hours, hour_cut)
    }

    fn oldest(&self, hours: bool) -> Option<i64> {
        let map = if hours { &self.hours } else { &self.minutes };
        map.first_key_value().map(|(k, _)| *k)
    }

    fn evict_through(&mut self, hours: bool, upto: i64) -> usize {
        drop_through(
            if hours {
                &mut self.hours
            } else {
                &mut self.minutes
            },
            upto,
        )
    }

    fn weight(&self) -> u64 {
        self.hours.values().map(|b| b.requests).sum()
    }

    fn measure(&self) -> usize {
        self.minutes
            .values()
            .chain(self.hours.values())
            .map(|b| b.est)
            .sum()
    }

    fn is_empty(&self) -> bool {
        self.minutes.is_empty() && self.hours.is_empty()
    }

    fn clear_identities(&mut self, ips: bool, uas: bool) {
        for b in self.minutes.values_mut().chain(self.hours.values_mut()) {
            if ips {
                b.ips.map.clear();
                b.ips.spare.clear();
            }
            if uas {
                b.uas.map.clear();
                b.uas.spare.clear();
            }
            b.est = b.measure();
        }
    }

    fn conform(&mut self, shift: u8) {
        for b in self.minutes.values_mut() {
            b.conform(false, shift);
        }
        for b in self.hours.values_mut() {
            b.conform(true, shift);
        }
    }
}

struct Agg {
    requests: u64,
    bytes_in: u64,
    bytes_out: u64,
    blocked: u64,
    e4: u64,
    e5: u64,
    ms_sum: u64,
    status: [u64; 6],
    lat: Vec<u64>,
    sizes: Vec<u64>,
    methods: HashMap<String, u64>,
    ctypes: HashMap<String, u64>,
    paths: HashMap<String, (u64, u64)>,
    ips: HashMap<String, (u64, u64)>,
    uas: HashMap<String, (u64, u64)>,
    hosts: HashMap<String, (u64, u64)>,
    rules: HashMap<String, (u64, u64)>,
}

fn merge_counts(dst: &mut HashMap<String, u64>, src: &Counts) {
    for (k, v) in &src.items {
        match dst.get_mut(k) {
            Some(d) => *d += v,
            None => {
                dst.insert(k.clone(), *v);
            }
        }
    }
}

fn merge_top(dst: &mut HashMap<String, (u64, u64)>, src: &TopK) {
    for (k, v) in &src.map {
        match dst.get_mut(k) {
            Some(d) => {
                d.0 += v.0;
                d.1 += v.1;
            }
            None => {
                dst.insert(k.clone(), *v);
            }
        }
    }
}

fn top_items(map: HashMap<String, (u64, u64)>) -> Vec<TopItem> {
    let mut v: Vec<TopItem> = map
        .into_iter()
        .map(|(key, (count, bytes))| TopItem { key, count, bytes })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    v.truncate(TOP_N);
    v
}

fn top_counts(map: HashMap<String, u64>) -> BTreeMap<String, u64> {
    let mut v: Vec<(String, u64)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(TOP_N);
    v.into_iter().collect()
}

impl Agg {
    fn new() -> Self {
        Self {
            requests: 0,
            bytes_in: 0,
            bytes_out: 0,
            blocked: 0,
            e4: 0,
            e5: 0,
            ms_sum: 0,
            status: [0; 6],
            lat: vec![0; LAT_LEN],
            sizes: vec![0; SIZE_LEN],
            methods: HashMap::new(),
            ctypes: HashMap::new(),
            paths: HashMap::new(),
            ips: HashMap::new(),
            uas: HashMap::new(),
            hosts: HashMap::new(),
            rules: HashMap::new(),
        }
    }

    fn merge(&mut self, b: &Bucket) {
        self.requests += b.requests;
        self.bytes_in += b.bytes_in;
        self.bytes_out += b.bytes_out;
        self.blocked += b.blocked;
        self.e4 += b.e4;
        self.e5 += b.e5;
        self.ms_sum += b.ms_sum;
        for (d, s) in self.status.iter_mut().zip(&b.status) {
            *d += s;
        }
        for (d, s) in self.lat.iter_mut().zip(&b.lat) {
            *d += u64::from(*s);
        }
        for (d, s) in self.sizes.iter_mut().zip(&b.sizes) {
            *d += u64::from(*s);
        }
        merge_counts(&mut self.methods, &b.methods);
        merge_counts(&mut self.ctypes, &b.ctypes);
        merge_top(&mut self.paths, &b.paths);
        merge_top(&mut self.ips, &b.ips);
        merge_top(&mut self.uas, &b.uas);
        merge_top(&mut self.hosts, &b.hosts);
        merge_top(&mut self.rules, &b.rules);
    }

    fn finish(self) -> Summary {
        const CLASSES: [&str; 6] = ["other", "1xx", "2xx", "3xx", "4xx", "5xx"];
        let status = CLASSES
            .iter()
            .zip(self.status.iter())
            .filter(|(_, n)| **n > 0)
            .map(|(k, n)| (k.to_string(), *n))
            .collect();
        let mut acc = 0u64;
        let sizes = self
            .sizes
            .iter()
            .enumerate()
            .map(|(i, c)| {
                acc += c;
                SizeBucket {
                    le: SIZE_LES.get(i).copied(),
                    count: acc,
                }
            })
            .collect();
        let avg_ms = match self.requests {
            0 => 0.0,
            n => self.ms_sum as f64 / n as f64,
        };
        Summary {
            requests: self.requests,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            blocked: self.blocked,
            errors_4xx: self.e4,
            errors_5xx: self.e5,
            avg_ms,
            p50_ms: percentile(&self.lat, self.requests, 50),
            p95_ms: percentile(&self.lat, self.requests, 95),
            p99_ms: percentile(&self.lat, self.requests, 99),
            status,
            methods: self.methods.into_iter().collect(),
            content_types: top_counts(self.ctypes),
            sizes,
            top_paths: top_items(self.paths),
            top_ips: top_items(self.ips),
            top_user_agents: top_items(self.uas),
            top_hosts: top_items(self.hosts),
            top_blocked: top_items(self.rules),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    version: u32,
    latest_ms: i64,
    global: Scope,
    sites: HashMap<String, Scope>,
    recent: Vec<LogEvent>,
}

#[derive(Debug)]
pub struct Analytics {
    retention: Retention,
    global: Scope,
    sites: HashMap<String, Scope>,
    recent: VecDeque<LogEvent>,
    latest_ms: i64,
    since_prune: u32,
    budget: usize,
    bytes: usize,
    cap_shift: u8,
}

fn event_cost(ev: &LogEvent) -> usize {
    std::mem::size_of::<LogEvent>()
        + ev.client_ip.len()
        + ev.host.len()
        + ev.method.len()
        + ev.path.len()
        + ev.user_agent.len()
        + ev.referer.len()
        + ev.content_type.len()
        + ev.backend.len()
        + ev.server.len()
        + ev.site.len()
        + ev.blocked.as_ref().map_or(0, String::len)
}

fn locked(shared: &Mutex<Analytics>) -> std::sync::MutexGuard<'_, Analytics> {
    shared.lock().unwrap_or_else(|p| p.into_inner())
}

impl Analytics {
    pub fn new(retention: Retention) -> Self {
        Self::with_budget(retention, DEFAULT_BUDGET)
    }

    pub fn with_budget(retention: Retention, bytes: usize) -> Self {
        Self {
            retention,
            global: Scope::default(),
            sites: HashMap::new(),
            recent: VecDeque::new(),
            latest_ms: 0,
            since_prune: 0,
            budget: bytes.max(MIN_BUDGET),
            bytes: 0,
            cap_shift: 0,
        }
    }

    pub fn set_budget(&mut self, bytes: usize) {
        self.budget = bytes.max(MIN_BUDGET);
        self.enforce_budget();
    }

    pub fn budget(&self) -> usize {
        self.budget
    }

    // Running estimate of the heap held by retained buckets and recent events.
    pub fn retained_bytes(&self) -> usize {
        self.bytes
    }

    fn recount(&mut self) {
        let scopes = self.global.measure() + self.sites.values().map(Scope::measure).sum::<usize>();
        self.bytes = scopes + self.recent.iter().map(event_cost).sum::<usize>();
    }

    fn adjust(&mut self, delta: isize) {
        self.bytes = self.bytes.saturating_add_signed(delta);
    }

    fn release(&mut self, freed: usize) {
        self.bytes = self.bytes.saturating_sub(freed);
    }

    fn scopes(&self) -> impl Iterator<Item = &Scope> {
        std::iter::once(&self.global).chain(self.sites.values())
    }

    fn evict_oldest(&mut self, hours: bool, below: i64, low: usize) {
        while self.bytes > low {
            let oldest = self.scopes().filter_map(|s| s.oldest(hours)).min();
            let Some(upto) = oldest.filter(|m| *m < below) else {
                break;
            };
            let mut freed = self.global.evict_through(hours, upto);
            for s in self.sites.values_mut() {
                freed += s.evict_through(hours, upto);
            }
            self.release(freed);
        }
    }

    fn conform_all(&mut self) {
        self.global.conform(self.cap_shift);
        for s in self.sites.values_mut() {
            s.conform(self.cap_shift);
        }
        self.recount();
    }

    // Order of loss: old minute buckets, then top-K detail, then old hour buckets, then recent events.
    fn enforce_budget(&mut self) {
        if self.bytes <= self.budget {
            return;
        }
        let low = self.budget - self.budget / LOW_WATER_DIV;
        let minute_keep = self.latest_ms.div_euclid(MINUTE_MS) - KEEP_MINUTES;
        let hour_keep = self.latest_ms.div_euclid(HOUR_MS) - KEEP_HOURS;
        self.evict_oldest(false, minute_keep, low);
        while self.bytes > low && self.cap_shift < MAX_CAP_SHIFT {
            self.cap_shift += 1;
            self.conform_all();
        }
        self.evict_oldest(true, hour_keep, low);
        self.evict_oldest(false, i64::MAX, low);
        self.evict_oldest(true, i64::MAX, low);
        while self.bytes > low {
            let Some(ev) = self.recent.pop_front() else {
                break;
            };
            self.release(event_cost(&ev));
        }
        self.sites.retain(|_, s| !s.is_empty());
    }

    pub fn set_retention(&mut self, r: Retention) {
        // turning a privacy flag off also erases what was already collected
        let drop_ips = self.retention.store_client_ips && !r.store_client_ips;
        let drop_uas = self.retention.store_user_agents && !r.store_user_agents;
        self.retention = r;
        if drop_ips || drop_uas {
            self.global.clear_identities(drop_ips, drop_uas);
            for s in self.sites.values_mut() {
                s.clear_identities(drop_ips, drop_uas);
            }
            for ev in self.recent.iter_mut() {
                if drop_ips {
                    ev.client_ip.clear();
                }
                if drop_uas {
                    ev.user_agent.clear();
                }
            }
            self.recount();
        }
        self.prune(self.latest_ms);
    }

    pub fn record(&mut self, mut ev: LogEvent) {
        if !self.retention.store_client_ips {
            ev.client_ip.clear();
        }
        if !self.retention.store_user_agents {
            ev.user_agent.clear();
        }
        self.latest_ms = self.latest_ms.max(ev.ts_ms);
        let shift = self.cap_shift;
        let mut delta = 0;
        {
            let p = Prep::new(&ev);
            delta += self.global.add(&p, shift);
            if !ev.site.is_empty() {
                if let Some(scope) = self.sites.get_mut(ev.site.as_str()) {
                    delta += scope.add(&p, shift);
                } else {
                    // site names come from the log stream, so the tracked set has a hard cap
                    let full = self.sites.len() >= MAX_SITES;
                    let key = if full { OTHER_SITE } else { ev.site.as_str() };
                    delta += self
                        .sites
                        .entry(key.to_string())
                        .or_default()
                        .add(&p, shift);
                }
            }
        }
        self.adjust(delta);
        let cap = self.retention.recent_events;
        if cap > 0 {
            while self.recent.len() >= cap {
                if let Some(old) = self.recent.pop_front() {
                    self.release(event_cost(&old));
                }
            }
            self.bytes += event_cost(&ev);
            self.recent.push_back(ev);
        }
        self.since_prune += 1;
        if self.since_prune >= PRUNE_EVERY {
            self.since_prune = 0;
            self.prune(self.latest_ms);
        } else if self.bytes > self.budget {
            self.enforce_budget();
        }
    }

    // Also runs automatically every PRUNE_EVERY records so memory stays bounded without a timer.
    pub fn prune(&mut self, now_ms: i64) {
        let minute_span = i64::from(self.retention.minute_buckets_hours) * HOUR_MS;
        let hour_span = i64::from(self.retention.hour_buckets_days) * DAY_MS;
        let minute_cut = now_ms.saturating_sub(minute_span).div_euclid(MINUTE_MS);
        let hour_cut = now_ms.saturating_sub(hour_span).div_euclid(HOUR_MS);
        let mut freed = self.global.prune(minute_cut, hour_cut);
        for s in self.sites.values_mut() {
            freed += s.prune(minute_cut, hour_cut);
        }
        self.sites.retain(|_, s| !s.is_empty());
        self.release(freed);
        let cap = self.retention.recent_events;
        while self.recent.len() > cap {
            if let Some(old) = self.recent.pop_front() {
                self.release(event_cost(&old));
            }
        }
        // Caps tightened under pressure relax again once usage falls well below the budget.
        if self.cap_shift > 0 && self.bytes < self.budget / 2 {
            self.cap_shift -= 1;
        }
        self.enforce_budget();
    }

    fn scope(&self, site: Option<&str>) -> Option<&Scope> {
        match site {
            None | Some("") => Some(&self.global),
            Some(s) => self.sites.get(s),
        }
    }

    // Returns (uses hour buckets, first bucket index, last bucket index) clipped to retention.
    fn window(&self, window_secs: u64, now_ms: i64) -> (bool, i64, i64) {
        let hour = window_secs > MINUTE_MAX_WINDOW_SECS;
        let step = if hour { HOUR_MS } else { MINUTE_MS };
        let span = if hour {
            i64::from(self.retention.hour_buckets_days) * DAY_MS
        } else {
            i64::from(self.retention.minute_buckets_hours) * HOUR_MS
        };
        let w = window_secs.min(MAX_WINDOW_SECS) as i64 * 1000;
        let from = now_ms.saturating_sub(w).max(now_ms.saturating_sub(span));
        (hour, from.div_euclid(step), now_ms.div_euclid(step))
    }

    pub fn summary(&self, window_secs: u64, site: Option<&str>, now_ms: i64) -> Summary {
        let mut agg = Agg::new();
        if let Some(scope) = self.scope(site) {
            let (hour, start, end) = self.window(window_secs, now_ms);
            let map = if hour { &scope.hours } else { &scope.minutes };
            if start <= end {
                for (_, b) in map.range(start..=end) {
                    agg.merge(b);
                }
            }
        }
        agg.finish()
    }

    pub fn timeseries(&self, window_secs: u64, site: Option<&str>, now_ms: i64) -> Timeseries {
        let (hour, start, end) = self.window(window_secs, now_ms);
        let step_secs: i64 = if hour { 3600 } else { 60 };
        let mut points = Vec::new();
        if let Some(scope) = self.scope(site) {
            let map = if hour { &scope.hours } else { &scope.minutes };
            if start <= end {
                let mut it = map.range(start..=end).peekable();
                for idx in start..=end {
                    // empty buckets are emitted as zero points so charts get a continuous axis
                    let hit = it.peek().is_some_and(|(k, _)| **k == idx);
                    let bucket = if hit { it.next().map(|(_, b)| b) } else { None };
                    points.push(match bucket {
                        Some(b) => Point {
                            ts: idx * step_secs,
                            requests: b.requests,
                            bytes_out: b.bytes_out,
                            errors: b.e4 + b.e5,
                            blocked: b.blocked,
                            avg_ms: b.ms_sum as f64 / b.requests.max(1) as f64,
                        },
                        None => Point {
                            ts: idx * step_secs,
                            requests: 0,
                            bytes_out: 0,
                            errors: 0,
                            blocked: 0,
                            avg_ms: 0.0,
                        },
                    });
                }
            }
        }
        Timeseries {
            step_secs: step_secs as u64,
            points,
        }
    }

    pub fn requests(&self, filter: &RequestFilter, limit: usize) -> Vec<LogEvent> {
        self.recent
            .iter()
            .rev()
            .filter(|e| filter.matches(e))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: SNAPSHOT_VERSION,
            latest_ms: self.latest_ms,
            global: self.global.clone(),
            sites: self.sites.clone(),
            recent: self.recent.iter().cloned().collect(),
        }
    }

    fn bucket_map(&self, site: Option<&str>, hours: bool) -> Option<&BTreeMap<i64, Bucket>> {
        let scope = match site {
            None => &self.global,
            Some(name) => self.sites.get(name)?,
        };
        Some(if hours { &scope.hours } else { &scope.minutes })
    }

    pub fn restore(retention: Retention, snap: Snapshot) -> Self {
        Self::restore_with_budget(retention, DEFAULT_BUDGET, snap)
    }

    // Everything read from disk is re-limited: caps, key lengths, site count, retention and budget.
    pub fn restore_with_budget(retention: Retention, budget: usize, snap: Snapshot) -> Self {
        let mut a = Self::with_budget(retention, budget);
        a.latest_ms = snap.latest_ms;
        a.global = snap.global;
        a.sites = snap.sites;
        a.limit_sites();
        for mut ev in snap.recent {
            if !a.retention.store_client_ips {
                ev.client_ip.clear();
            }
            if !a.retention.store_user_agents {
                ev.user_agent.clear();
            }
            a.recent.push_back(ev);
        }
        if !a.retention.store_client_ips || !a.retention.store_user_agents {
            let (ips, uas) = (
                !a.retention.store_client_ips,
                !a.retention.store_user_agents,
            );
            a.global.clear_identities(ips, uas);
            for s in a.sites.values_mut() {
                s.clear_identities(ips, uas);
            }
        }
        a.conform_all();
        a.prune(a.latest_ms);
        a
    }

    fn limit_sites(&mut self) {
        if self.sites.len() <= MAX_SITES {
            return;
        }
        let mut ranked: Vec<(String, u64)> = self
            .sites
            .iter()
            .map(|(name, scope)| (name.clone(), scope.weight()))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (name, _) in ranked.into_iter().skip(MAX_SITES) {
            self.sites.remove(&name);
        }
    }
}

// Writes one bucket map as a JSON object, taking the lock only while a single bucket is encoded.
fn stream_buckets<W: Write>(
    shared: &Mutex<Analytics>,
    out: &mut W,
    site: Option<&str>,
    hours: bool,
    scratch: &mut Vec<u8>,
) -> io::Result<()> {
    out.write_all(b"{")?;
    let mut cursor: Option<i64> = None;
    let mut first = true;
    loop {
        scratch.clear();
        let key = {
            let guard = locked(shared);
            let Some(map) = guard.bucket_map(site, hours) else {
                break;
            };
            let lower = cursor.map_or(Bound::Unbounded, Bound::Excluded);
            let Some((key, bucket)) = map.range((lower, Bound::Unbounded)).next() else {
                break;
            };
            serde_json::to_writer(&mut *scratch, bucket)?;
            *key
        };
        if !first {
            out.write_all(b",")?;
        }
        first = false;
        write!(out, "\"{key}\":")?;
        out.write_all(scratch)?;
        cursor = Some(key);
    }
    out.write_all(b"}")
}

fn stream_scope<W: Write>(
    shared: &Mutex<Analytics>,
    out: &mut W,
    site: Option<&str>,
    scratch: &mut Vec<u8>,
) -> io::Result<()> {
    out.write_all(b"{\"minutes\":")?;
    stream_buckets(shared, out, site, false, scratch)?;
    out.write_all(b",\"hours\":")?;
    stream_buckets(shared, out, site, true, scratch)?;
    out.write_all(b"}")
}

// Streams the Snapshot JSON one bucket at a time so the store is never copied under the lock.
pub fn write_snapshot<W: Write>(shared: &Mutex<Analytics>, mut out: W) -> io::Result<()> {
    let (latest_ms, names) = {
        let guard = locked(shared);
        let mut names: Vec<String> = guard.sites.keys().cloned().collect();
        names.sort();
        (guard.latest_ms, names)
    };
    let mut scratch = Vec::with_capacity(16 * 1024);
    write!(
        out,
        "{{\"version\":{SNAPSHOT_VERSION},\"latest_ms\":{latest_ms},\"global\":"
    )?;
    stream_scope(shared, &mut out, None, &mut scratch)?;
    out.write_all(b",\"sites\":{")?;
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            out.write_all(b",")?;
        }
        serde_json::to_writer(&mut out, name)?;
        out.write_all(b":")?;
        stream_scope(shared, &mut out, Some(name), &mut scratch)?;
    }
    out.write_all(b"},\"recent\":")?;
    scratch.clear();
    {
        let guard = locked(shared);
        serde_json::to_writer(&mut scratch, &guard.recent)?;
    }
    out.write_all(&scratch)?;
    out.write_all(b"}")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    // aligned to an hour boundary so bucket indexes are easy to reason about
    const NOW: i64 = 1_730_721_600_000;

    fn ev(ts: i64) -> LogEvent {
        LogEvent {
            ts_ms: ts,
            client_ip: "10.0.0.1".into(),
            host: "a.test".into(),
            method: "GET".into(),
            path: "/".into(),
            query_len: 0,
            status: 200,
            bytes_in: 100,
            bytes_out: 1000,
            total_ms: 10,
            user_agent: "ua".into(),
            referer: String::new(),
            content_type: "text/html".into(),
            backend: "be_s_blue".into(),
            server: "app1".into(),
            site: String::new(),
            blocked: None,
        }
    }

    fn analytics() -> Analytics {
        Analytics::new(Retention::default())
    }

    #[test]
    fn record_and_summary_totals() {
        let mut a = analytics();
        for _ in 0..10 {
            a.record(ev(NOW - 5000));
        }
        let s = a.summary(900, None, NOW);
        assert_eq!(s.requests, 10);
        assert_eq!(s.bytes_out, 10_000);
        assert_eq!(s.bytes_in, 1000);
        assert!((s.avg_ms - 10.0).abs() < 1e-9);
        assert_eq!(s.status.get("2xx"), Some(&10));
        assert_eq!(s.methods.get("GET"), Some(&10));
        assert_eq!(s.content_types.get("text/html"), Some(&10));
        assert_eq!(s.top_paths[0].key, "/");
        assert_eq!(s.top_paths[0].count, 10);
        assert_eq!(s.top_paths[0].bytes, 10_000);
        assert_eq!(s.top_hosts[0].key, "a.test");
    }

    #[test]
    fn status_classes_errors_and_blocked() {
        let mut a = analytics();
        for status in [200, 301, 404, 404, 500, 503] {
            let mut e = ev(NOW - 1000);
            e.status = status;
            a.record(e);
        }
        for rule in ["r1", "r1", "r2"] {
            let mut e = ev(NOW - 1000);
            e.status = 403;
            e.blocked = Some(rule.into());
            a.record(e);
        }
        let s = a.summary(900, None, NOW);
        assert_eq!(s.requests, 9);
        assert_eq!(s.errors_4xx, 5);
        assert_eq!(s.errors_5xx, 2);
        assert_eq!(s.blocked, 3);
        assert_eq!(s.status.get("3xx"), Some(&1));
        assert_eq!(s.top_blocked[0].key, "r1");
        assert_eq!(s.top_blocked[0].count, 2);
        assert_eq!(s.top_blocked[1].key, "r2");
    }

    #[test]
    fn percentiles_stay_within_histogram_tolerance() {
        let mut a = analytics();
        for ms in 1..=1000u32 {
            let mut e = ev(NOW - 1000);
            e.total_ms = ms;
            a.record(e);
        }
        let s = a.summary(900, None, NOW);
        assert!((s.avg_ms - 500.5).abs() < 1e-9);
        for (got, want) in [(s.p50_ms, 500.0), (s.p95_ms, 950.0), (s.p99_ms, 990.0)] {
            assert!(
                (got as f64 - want).abs() <= want * 0.13,
                "got {got} want {want}"
            );
        }
        assert!(s.p50_ms <= s.p95_ms && s.p95_ms <= s.p99_ms);
    }

    #[test]
    fn small_latencies_are_exact() {
        let mut a = analytics();
        for _ in 0..5 {
            let mut e = ev(NOW - 1000);
            e.total_ms = 2;
            a.record(e);
        }
        let s = a.summary(900, None, NOW);
        assert_eq!((s.p50_ms, s.p95_ms, s.p99_ms), (2, 2, 2));
    }

    #[test]
    fn latency_buckets_contain_their_values() {
        for ms in (0..200_000u32).chain([u32::MAX - 1, u32::MAX]) {
            let idx = lat_index(ms);
            assert!(idx < LAT_LEN);
            let lo = lat_lower(idx);
            let hi = if idx + 1 < LAT_LEN {
                lat_lower(idx + 1) - 1
            } else {
                u64::MAX
            };
            assert!(
                lo <= u64::from(ms) && u64::from(ms) <= hi,
                "ms {ms} idx {idx}"
            );
        }
    }

    #[test]
    fn site_filtering() {
        let mut a = analytics();
        for (site, n) in [("a", 3), ("b", 2), ("", 1)] {
            for _ in 0..n {
                let mut e = ev(NOW - 1000);
                e.site = site.into();
                a.record(e);
            }
        }
        assert_eq!(a.summary(900, None, NOW).requests, 6);
        assert_eq!(a.summary(900, Some(""), NOW).requests, 6);
        assert_eq!(a.summary(900, Some("a"), NOW).requests, 3);
        assert_eq!(a.summary(900, Some("b"), NOW).requests, 2);
        assert_eq!(a.summary(900, Some("missing"), NOW).requests, 0);
        let series = a.timeseries(900, Some("a"), NOW);
        assert_eq!(series.points.iter().map(|p| p.requests).sum::<u64>(), 3);
    }

    #[test]
    fn window_excludes_older_events() {
        let mut a = analytics();
        a.record(ev(NOW - 2 * HOUR_MS));
        a.record(ev(NOW - 5000));
        assert_eq!(a.summary(900, None, NOW).requests, 1);
        assert_eq!(a.summary(3600, None, NOW).requests, 1);
        assert_eq!(a.summary(86_400, None, NOW).requests, 2);
        assert_eq!(a.summary(7 * 86_400, None, NOW).requests, 2);
        assert_eq!(a.summary(30 * 86_400, None, NOW).requests, 2);
    }

    #[test]
    fn timeseries_uses_minute_then_hour_steps_and_fills_gaps() {
        let mut a = analytics();
        a.record(ev(NOW - 120_000));
        a.record(ev(NOW - 120_000));
        a.record(ev(NOW - 5000));
        let t = a.timeseries(900, None, NOW);
        assert_eq!(t.step_secs, 60);
        assert_eq!(t.points.len(), 16);
        assert_eq!(t.points.iter().map(|p| p.requests).sum::<u64>(), 3);
        let two = t.points.iter().find(|p| p.requests == 2).expect("point");
        assert_eq!(two.ts, (NOW - 120_000) / 1000);
        assert_eq!(two.bytes_out, 2000);
        assert!((two.avg_ms - 10.0).abs() < 1e-9);
        assert_eq!(t.points.last().map(|p| p.requests), Some(0));
        let long = a.timeseries(7 * 86_400, None, NOW);
        assert_eq!(long.step_secs, 3600);
        assert_eq!(long.points.len(), 7 * 24 + 1);
        assert_eq!(long.points.iter().map(|p| p.requests).sum::<u64>(), 3);
        let edge = a.timeseries(48 * 3600, None, NOW);
        assert_eq!(edge.step_secs, 60);
    }

    #[test]
    fn requests_are_newest_first_and_capped_by_retention() {
        let mut a = analytics();
        for i in 0..100 {
            a.record(ev(NOW - 100_000 + i));
        }
        let all = a.requests(&RequestFilter::default(), 1000);
        assert_eq!(all.len(), 100);
        assert!(all.windows(2).all(|w| w[0].ts_ms > w[1].ts_ms));
        let r = Retention {
            recent_events: 10,
            ..Retention::default()
        };
        a.set_retention(r);
        let kept = a.requests(&RequestFilter::default(), 1000);
        assert_eq!(kept.len(), 10);
        assert_eq!(kept[0].ts_ms, NOW - 100_000 + 99);
        a.record(ev(NOW));
        assert_eq!(a.requests(&RequestFilter::default(), 1000).len(), 10);
        assert_eq!(a.summary(900, None, NOW).requests, 101);
        assert_eq!(a.requests(&RequestFilter::default(), 3).len(), 3);
    }

    #[test]
    fn request_filters() {
        let mut a = analytics();
        let mut e1 = ev(NOW - 4000);
        e1.status = 404;
        e1.path = "/missing/page".into();
        let mut e2 = ev(NOW - 3000);
        e2.method = "POST".into();
        e2.client_ip = "10.9.9.9".into();
        let mut e3 = ev(NOW - 2000);
        e3.blocked = Some("r1".into());
        e3.status = 403;
        for e in [e1, e2, e3] {
            a.record(e);
        }
        let count = |f: RequestFilter| a.requests(&f, 10).len();
        let base = RequestFilter::default;
        assert_eq!(
            count(RequestFilter {
                status: Some(404),
                ..base()
            }),
            1
        );
        assert_eq!(
            count(RequestFilter {
                method: Some("post".into()),
                ..base()
            }),
            1
        );
        assert_eq!(
            count(RequestFilter {
                path_contains: Some("missing".into()),
                ..base()
            }),
            1
        );
        assert_eq!(
            count(RequestFilter {
                ip: Some("10.9.9.9".into()),
                ..base()
            }),
            1
        );
        assert_eq!(
            count(RequestFilter {
                blocked_only: true,
                ..base()
            }),
            1
        );
        assert_eq!(
            count(RequestFilter {
                status: Some(500),
                ..base()
            }),
            0
        );
        assert_eq!(count(base()), 3);
    }

    #[test]
    fn prune_drops_buckets_beyond_retention() {
        let r = Retention {
            minute_buckets_hours: 1,
            hour_buckets_days: 1,
            ..Retention::default()
        };
        let mut a = Analytics::new(r);
        a.record(ev(NOW - 3 * HOUR_MS));
        a.record(ev(NOW - 3 * DAY_MS));
        a.prune(NOW);
        assert!(a.global.minutes.is_empty());
        assert_eq!(a.global.hours.len(), 1);
        assert_eq!(a.summary(86_400, None, NOW).requests, 0);
        assert_eq!(a.summary(7 * 86_400, None, NOW).requests, 1);
    }

    #[test]
    fn shrinking_retention_prunes_immediately() {
        let mut a = analytics();
        let mut old = ev(NOW - 90 * 60_000);
        old.site = "s".into();
        a.record(old);
        a.record(ev(NOW));
        assert_eq!(a.global.minutes.len(), 2);
        a.set_retention(Retention {
            minute_buckets_hours: 1,
            ..Retention::default()
        });
        assert_eq!(a.global.minutes.len(), 1);
        assert_eq!(a.sites.get("s").map(|s| s.minutes.len()), Some(0));
        assert_eq!(a.summary(86_400, None, NOW).requests, 1);
    }

    #[test]
    fn auto_prune_removes_stale_buckets() {
        let r = Retention {
            minute_buckets_hours: 1,
            ..Retention::default()
        };
        let mut a = Analytics::new(r);
        for _ in 0..PRUNE_EVERY {
            a.record(ev(NOW));
        }
        a.record(ev(NOW - 5 * HOUR_MS));
        assert_eq!(a.global.minutes.len(), 2);
        for _ in 0..PRUNE_EVERY {
            a.record(ev(NOW));
        }
        assert_eq!(a.global.minutes.len(), 1);
    }

    #[test]
    fn privacy_flags_blank_and_skip_identities() {
        let r = Retention {
            store_client_ips: false,
            store_user_agents: false,
            ..Retention::default()
        };
        let mut a = Analytics::new(r);
        a.record(ev(NOW - 1000));
        let s = a.summary(900, None, NOW);
        assert_eq!(s.requests, 1);
        assert!(s.top_ips.is_empty());
        assert!(s.top_user_agents.is_empty());
        let stored = a.requests(&RequestFilter::default(), 1);
        assert_eq!(stored[0].client_ip, "");
        assert_eq!(stored[0].user_agent, "");

        let mut on = analytics();
        on.record(ev(NOW - 1000));
        assert_eq!(on.summary(900, None, NOW).top_ips[0].key, "10.0.0.1");
        assert_eq!(on.summary(900, None, NOW).top_user_agents[0].key, "ua");
    }

    #[test]
    fn disabling_privacy_flags_clears_existing_data() {
        let mut a = analytics();
        a.record(ev(NOW - 1000));
        let r = Retention {
            store_client_ips: false,
            store_user_agents: false,
            ..Retention::default()
        };
        a.set_retention(r);
        assert!(a.summary(900, None, NOW).top_ips.is_empty());
        assert!(a.summary(7 * 86_400, None, NOW).top_user_agents.is_empty());
        assert_eq!(a.requests(&RequestFilter::default(), 1)[0].client_ip, "");
    }

    #[test]
    fn top_k_stays_bounded_under_path_spraying() {
        // one heavy hitter hidden among 100k one-off paths must survive eviction
        let mut a = analytics();
        for i in 0..100_000u32 {
            if i % 5 == 0 {
                let mut e = ev(NOW - 1000);
                e.path = "/hot".into();
                a.record(e);
            }
            let mut e = ev(NOW - 1000);
            e.path = format!("/spray/{i}");
            a.record(e);
        }
        let s = a.summary(900, None, NOW);
        assert_eq!(s.requests, 120_000);
        assert!(s.top_paths.len() <= TOP_N);
        assert_eq!(s.top_paths[0].key, "/hot");
        assert!(s.top_paths[0].count >= 20_000);
        assert!(
            a.global
                .minutes
                .values()
                .all(|b| b.paths.map.len() <= MINUTE_CAPS.paths)
        );
        assert!(
            a.global
                .hours
                .values()
                .all(|b| b.paths.map.len() <= HOUR_CAPS.paths)
        );
    }

    #[test]
    fn long_keys_are_capped() {
        let mut a = analytics();
        let mut e = ev(NOW - 1000);
        e.path = format!("/{}", "x".repeat(5000));
        e.user_agent = "u".repeat(5000);
        a.record(e);
        let s = a.summary(900, None, NOW);
        assert_eq!(s.top_paths[0].key.len(), KEY_PATH);
        assert_eq!(s.top_user_agents[0].key.len(), KEY_UA);
    }

    #[test]
    fn tracked_sites_are_capped_with_overflow_bucket() {
        let mut a = analytics();
        for i in 0..300 {
            let mut e = ev(NOW - 1000);
            e.site = format!("site{i}");
            a.record(e);
        }
        assert_eq!(a.sites.len(), MAX_SITES + 1);
        assert_eq!(
            a.summary(900, Some("other"), NOW).requests,
            300 - MAX_SITES as u64
        );
        assert_eq!(a.summary(900, Some("site0"), NOW).requests, 1);
        assert_eq!(a.summary(900, None, NOW).requests, 300);
    }

    #[test]
    fn content_types_are_normalised() {
        let mut a = analytics();
        for ct in [
            "text/html; charset=utf-8",
            "TEXT/HTML",
            " text/html ;q=1",
            "",
            "image/png",
        ] {
            let mut e = ev(NOW - 1000);
            e.content_type = ct.into();
            a.record(e);
        }
        let s = a.summary(900, None, NOW);
        assert_eq!(s.content_types.get("text/html"), Some(&3));
        assert_eq!(s.content_types.get("image/png"), Some(&1));
        assert_eq!(s.content_types.len(), 2);
    }

    #[test]
    fn response_size_histogram_is_cumulative() {
        let mut a = analytics();
        for bytes in [500u64, 3000, 100_000_000] {
            let mut e = ev(NOW - 1000);
            e.bytes_out = bytes;
            a.record(e);
        }
        let s = a.summary(900, None, NOW);
        assert_eq!(s.sizes.len(), 10);
        assert_eq!(
            s.sizes[0],
            SizeBucket {
                le: Some(1024),
                count: 1
            }
        );
        assert_eq!(
            s.sizes[1],
            SizeBucket {
                le: Some(4096),
                count: 2
            }
        );
        assert_eq!(
            s.sizes[8],
            SizeBucket {
                le: Some(64 << 20),
                count: 2
            }
        );
        assert_eq!(s.sizes[9], SizeBucket { le: None, count: 3 });
    }

    #[test]
    fn snapshot_round_trip_through_json() {
        let mut a = analytics();
        for i in 0..50 {
            let mut e = ev(NOW - 1000 * i);
            e.site = if i % 2 == 0 { "a".into() } else { "b".into() };
            e.status = if i % 7 == 0 { 502 } else { 200 };
            e.path = format!("/p{}", i % 5);
            e.total_ms = (i as u32) * 3;
            e.blocked = (i % 11 == 0).then(|| "r1".to_string());
            a.record(e);
        }
        let json = serde_json::to_string(&a.snapshot()).expect("serialize");
        let snap: Snapshot = serde_json::from_str(&json).expect("deserialize");
        let b = Analytics::restore(Retention::default(), snap);
        for window in [900, 86_400, 7 * 86_400] {
            for site in [None, Some("a"), Some("b")] {
                assert_eq!(a.summary(window, site, NOW), b.summary(window, site, NOW));
                assert_eq!(
                    a.timeseries(window, site, NOW),
                    b.timeseries(window, site, NOW)
                );
            }
        }
        let f = RequestFilter::default();
        assert_eq!(a.requests(&f, 100), b.requests(&f, 100));
        assert_eq!(b.summary(900, None, NOW).requests, 50);
    }

    #[test]
    fn restore_applies_current_retention() {
        let mut a = analytics();
        for i in 0..20 {
            a.record(ev(NOW - 20_000 + 1000 * i));
        }
        let r = Retention {
            recent_events: 5,
            store_client_ips: false,
            ..Retention::default()
        };
        let b = Analytics::restore(r, a.snapshot());
        let recent = b.requests(&RequestFilter::default(), 100);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].ts_ms, NOW - 1000);
        assert!(recent.iter().all(|e| e.client_ip.is_empty()));
        assert!(b.summary(900, None, NOW).top_ips.is_empty());
        assert_eq!(b.summary(900, None, NOW).requests, 20);
    }

    #[test]
    fn window_from_str_maps_known_windows() {
        assert_eq!(window_from_str("15m"), Some(900));
        assert_eq!(window_from_str("1h"), Some(3600));
        assert_eq!(window_from_str("24h"), Some(86_400));
        assert_eq!(window_from_str("7d"), Some(604_800));
        assert_eq!(window_from_str("30d"), Some(2_592_000));
        for bad in ["", "2h", "1d", "15M", "30", "7 d"] {
            assert_eq!(window_from_str(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn summary_serializes_documented_field_names() {
        let mut a = analytics();
        a.record(ev(NOW - 1000));
        let v = serde_json::to_value(a.summary(900, None, NOW)).expect("json");
        for key in [
            "requests",
            "bytes_in",
            "bytes_out",
            "blocked",
            "errors_4xx",
            "errors_5xx",
            "avg_ms",
            "p50_ms",
            "p95_ms",
            "p99_ms",
            "status",
            "methods",
            "content_types",
            "sizes",
            "top_paths",
            "top_ips",
            "top_user_agents",
            "top_hosts",
            "top_blocked",
        ] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        let t = serde_json::to_value(a.timeseries(900, None, NOW)).expect("json");
        assert!(t.get("step_secs").is_some());
        let p = &t["points"][0];
        for key in ["ts", "requests", "bytes_out", "errors", "blocked", "avg_ms"] {
            assert!(p.get(key).is_some(), "missing {key}");
        }
    }

    #[test]
    fn throughput_totals_stay_exact() {
        // no timing assertion: this checks that totals survive a sustained burst
        let mut a = analytics();
        let n = 200_000u64;
        let mut bytes = 0u64;
        for i in 0..n {
            let mut e = ev(NOW - 1000 * (i as i64 % 600));
            e.path = format!("/p{}", i % 100);
            e.bytes_out = i % 5000;
            e.site = format!("s{}", i % 4);
            bytes += e.bytes_out;
            a.record(e);
        }
        let s = a.summary(3600, None, NOW);
        assert_eq!(s.requests, n);
        assert_eq!(s.bytes_out, bytes);
        let mut per_site = 0;
        for i in 0..4 {
            let name = format!("s{i}");
            per_site += a.summary(3600, Some(name.as_str()), NOW).requests;
        }
        assert_eq!(per_site, n);
        assert_eq!(
            a.requests(&RequestFilter::default(), usize::MAX).len(),
            5000
        );
    }

    #[test]
    fn requests_can_be_filtered_by_site() {
        let mut a = analytics();
        for (i, site) in ["shop", "blog", "shop", ""].iter().enumerate() {
            let mut e = ev(NOW - 4000 + 1000 * i as i64);
            e.site = (*site).to_string();
            a.record(e);
        }
        let only = |site: &str| RequestFilter {
            site: Some(site.into()),
            ..RequestFilter::default()
        };
        assert_eq!(a.requests(&only("shop"), 10).len(), 2);
        assert_eq!(a.requests(&only("blog"), 10).len(), 1);
        assert!(a.requests(&only("ghost"), 10).is_empty());
        assert_eq!(a.requests(&RequestFilter::default(), 10).len(), 4);
    }

    // xorshift keeps the traffic generator dependency free and repeatable
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn random_event(rng: &mut Rng, ts: i64) -> LogEvent {
        let mut e = ev(ts);
        e.site = format!("site{}", rng.next() % 8);
        e.path = format!("/p/{}/{}", rng.next() % 100_000, rng.next() % 1000);
        e.user_agent = format!("agent-{}/{}", rng.next() % 50_000, rng.next() % 100);
        e.client_ip = format!(
            "10.{}.{}.{}",
            rng.next() % 250,
            rng.next() % 250,
            rng.next() % 250
        );
        e.host = format!("h{}.example.com", rng.next() % 500);
        e.status = [200, 200, 404, 500][(rng.next() % 4) as usize];
        e.bytes_out = rng.next() % 3_000_000;
        e.total_ms = (rng.next() % 3000) as u32;
        e
    }

    #[test]
    fn random_traffic_stays_under_the_byte_budget() {
        let budget = 2 * 1024 * 1024;
        let mut a = Analytics::with_budget(Retention::default(), budget);
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut peak = 0;
        let mut last = NOW;
        for i in 0..100_000i64 {
            last = NOW + i * 20_000;
            a.record(random_event(&mut rng, last));
            if i % 1000 == 0 {
                peak = peak.max(a.retained_bytes());
            }
        }
        assert!(peak <= budget, "peak {peak} over {budget}");
        assert!(a.retained_bytes() <= budget);
        let before = a.retained_bytes();
        a.recount();
        assert_eq!(a.retained_bytes(), before, "running estimate drifted");
        assert!(a.summary(3600, None, last).requests > 0);
        let shared = Mutex::new(a);
        let mut out = Vec::new();
        write_snapshot(&shared, &mut out).expect("snapshot");
        assert!(out.len() <= budget, "snapshot of {} bytes", out.len());
        let snap: Snapshot = serde_json::from_slice(&out).expect("parse");
        let restored = Analytics::restore_with_budget(Retention::default(), budget, snap);
        assert!(restored.retained_bytes() <= budget);
    }

    #[test]
    fn streamed_snapshot_matches_the_in_memory_one() {
        let mut a = analytics();
        for i in 0..200 {
            let mut e = ev(NOW - 1000 * i);
            e.site = ["a", "b\"quoted", "c"][(i % 3) as usize].into();
            e.path = format!("/p{}", i % 7);
            e.blocked = (i % 13 == 0).then(|| "r1".to_string());
            a.record(e);
        }
        let direct = serde_json::to_value(a.snapshot()).expect("value");
        let shared = Mutex::new(a);
        let mut out = Vec::new();
        write_snapshot(&shared, &mut out).expect("snapshot");
        let streamed: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        assert_eq!(streamed, direct);
        let snap: Snapshot = serde_json::from_slice(&out).expect("typed");
        let b = Analytics::restore(Retention::default(), snap);
        let a = shared.into_inner().unwrap();
        assert_eq!(a.summary(86_400, None, NOW), b.summary(86_400, None, NOW));
    }

    #[test]
    fn restore_reapplies_caps_key_lengths_and_budget() {
        let mut a = analytics();
        for i in 0..10 {
            let mut e = ev(NOW - 1000 * i);
            e.site = "shop".into();
            a.record(e);
        }
        let mut snap = a.snapshot();
        let long = "x".repeat(4000);
        for scope in std::iter::once(&mut snap.global).chain(snap.sites.values_mut()) {
            for b in scope.hours.values_mut().chain(scope.minutes.values_mut()) {
                for i in 0..500u64 {
                    b.paths.map.insert(format!("/k{i}{long}"), (i + 1, 1));
                }
                b.paths.cap = 10_000;
            }
        }
        for i in 0..400 {
            snap.sites
                .insert(format!("extra{i}"), snap.sites["shop"].clone());
        }
        let b = Analytics::restore_with_budget(Retention::default(), 2 * 1024 * 1024, snap);
        assert!(b.sites.len() <= MAX_SITES);
        let ok = |m: &BTreeMap<i64, Bucket>, cap: usize| {
            m.values().all(|x| {
                x.paths.map.len() <= cap && x.paths.map.keys().all(|k| k.len() <= KEY_PATH)
            })
        };
        assert!(ok(&b.global.minutes, MINUTE_CAPS.paths));
        assert!(ok(&b.global.hours, HOUR_CAPS.paths));
        assert!(b.retained_bytes() <= b.budget());
        let mut check = b;
        let reported = check.retained_bytes();
        check.recount();
        assert_eq!(check.retained_bytes(), reported);
    }

    #[test]
    fn shrinking_the_budget_evicts_old_minutes_before_recent_ones() {
        let mut a = Analytics::with_budget(Retention::default(), 64 * 1024 * 1024);
        let mut rng = Rng(7);
        let end = NOW + 40 * 3_600_000;
        let mut ts = NOW;
        while ts < end {
            a.record(random_event(&mut rng, ts));
            ts += 20_000;
        }
        let full = a.retained_bytes();
        a.set_budget(full / 2);
        assert!(a.retained_bytes() <= a.budget());
        let newest = a.latest_ms.div_euclid(MINUTE_MS);
        let oldest = a.global.minutes.keys().next().copied().unwrap_or(newest);
        assert!(oldest > NOW.div_euclid(MINUTE_MS));
        assert!(a.global.minutes.contains_key(&newest));
        assert!(a.summary(900, None, a.latest_ms).requests > 0);
    }
}
