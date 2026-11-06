use std::collections::BTreeMap;

use cite_client::{DeployRequest, NodeInfo, NodeTargets, ReplicationMode, ReplicationPlan};
use cite_edge::analytics::{Point, SizeBucket, Summary, Timeseries, TopItem};
use cite_edge::model::{
    EdgeSettings, FirewallAction, FirewallRule, HealthCheck, Maintenance, Matchers, Retention,
    Site, SiteKind, Slot, Source, Target, Upstream,
};
use cite_edge::validate::validate_rule;
use serde_json::Value;

use crate::repo::parse_repo;

pub const WINDOWS: [&str; 5] = ["15m", "1h", "24h", "7d", "30d"];
pub const OVERVIEW_WINDOW_MINUTES: f64 = 15.0;

pub fn fmt_num(n: u64) -> String {
    let v = n as f64;
    let (scaled, suffix) = if v >= 1e9 {
        (v / 1e9, "B")
    } else if v >= 1e6 {
        (v / 1e6, "M")
    } else if v >= 1e3 {
        (v / 1e3, "K")
    } else {
        return n.to_string();
    };
    if scaled >= 100.0 {
        format!("{scaled:.0}{suffix}")
    } else {
        format!("{scaled:.1}{suffix}")
    }
}

pub fn fmt_int(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

// Binary units, matching the web dashboard.
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut i = 0;
    while value >= 1024.0 && i < UNITS.len() - 1 {
        value /= 1024.0;
        i += 1;
    }
    match i {
        0 => format!("{n} B"),
        _ if value >= 100.0 => format!("{value:.0} {}", UNITS[i]),
        _ => format!("{value:.1} {}", UNITS[i]),
    }
}

pub fn fmt_pct(ratio: f64, digits: usize) -> String {
    format!("{:.digits$}%", ratio * 100.0)
}

pub fn fmt_ms(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{} ms", ms.round() as u64)
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

pub fn fmt_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

pub fn slugify(text: &str) -> String {
    let mut out = String::new();
    let mut pending_dash = false;
    for ch in text.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(ch);
        } else {
            pending_dash = true;
        }
    }
    out.truncate(40);
    out.trim_end_matches('-').to_string()
}

// A throwaway rule runs the exact validation the connector applies, so the message matches.
pub fn matcher_problem(matchers: Matchers) -> Option<String> {
    let probe = FirewallRule {
        id: "probe".into(),
        name: "probe".into(),
        enabled: true,
        action: Some(FirewallAction::Deny),
        matchers,
        ..FirewallRule::default()
    };
    validate_rule(&probe).err().map(|e| {
        let text = e.to_string();
        match text.split_once(": ") {
            Some((_, rest)) => rest.to_string(),
            None => text,
        }
    })
}

// The form asks on every repaint, so the last answer is remembered for as long as the lists stay the same.
type PathsMemo = (Vec<String>, Vec<String>, Option<String>);

thread_local! {
    static PATHS_MEMO: std::cell::RefCell<Option<PathsMemo>> = const { std::cell::RefCell::new(None) };
    static REGEX_CACHE: std::cell::RefCell<std::collections::HashMap<String, Option<regex::Regex>>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

const REGEX_CACHE_LIMIT: usize = 128;

pub fn paths_problem(prefixes: &[String], regexes: &[String]) -> Option<String> {
    if prefixes.is_empty() && regexes.is_empty() {
        return None;
    }
    let hit = PATHS_MEMO.with(|m| {
        m.borrow()
            .as_ref()
            .filter(|(p, r, _)| p == prefixes && r == regexes)
            .map(|(_, _, answer)| answer.clone())
    });
    if let Some(answer) = hit {
        return answer;
    }
    let answer = matcher_problem(Matchers {
        path_prefixes: prefixes.to_vec(),
        path_regexes: regexes.to_vec(),
        ..Matchers::default()
    });
    PATHS_MEMO.with(|m| {
        *m.borrow_mut() = Some((prefixes.to_vec(), regexes.to_vec(), answer.clone()));
    });
    answer
}

// Compiling is the slow part of a sample check, so each pattern is compiled once and kept.
fn regex_hits(pattern: &str, sample: &str) -> bool {
    REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= REGEX_CACHE_LIMIT && !cache.contains_key(pattern) {
            cache.clear();
        }
        cache
            .entry(pattern.to_string())
            .or_insert_with(|| regex::Regex::new(pattern).ok())
            .as_ref()
            .is_some_and(|re| re.is_match(sample))
    })
}

// A sample path is routed when it starts with any prefix or matches any regex; None while there is nothing to judge.
pub fn paths_match(prefixes: &[String], regexes: &[String], sample: &str) -> Option<bool> {
    let prefixes = clean_list(prefixes.iter().cloned());
    let regexes = clean_list(regexes.iter().cloned());
    if sample.is_empty()
        || (prefixes.is_empty() && regexes.is_empty())
        || paths_problem(&prefixes, &regexes).is_some()
    {
        return None;
    }
    if prefixes.iter().any(|p| sample.starts_with(p.as_str())) {
        return Some(true);
    }
    Some(regexes.iter().any(|r| regex_hits(r, sample)))
}

pub const PATHS_HINT: &str = "Optional. Leave empty to route every path. A request is routed when its path starts with any prefix or matches any regex.";
pub const PATHS_LIMITS: &str = "Prefixes start with /. Regexes use a small safe subset: literals, classes, groups, | and the repeats ? * + {n,m}; lookarounds, backreferences and \\p are refused. Up to 16 prefixes and 16 regexes, 256 characters each.";

// Blank entries are dropped and repeats collapse, so a list always reaches the node as distinct values.
pub fn clean_list(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let t = item.trim().to_string();
        if !t.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// Accepts RFC 3339 timestamps such as 2026-11-05T12:30:00.250Z or with a numeric offset.
pub fn parse_rfc3339_ms(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once('T')?;
    let mut dp = date.split('-');
    let (y, m, d) = (
        dp.next()?.parse::<i64>().ok()?,
        dp.next()?.parse::<i64>().ok()?,
        dp.next()?.parse::<i64>().ok()?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let split = rest.find(['Z', 'z', '+', '-'])?;
    let (clock, zone) = rest.split_at(split);
    let mut cp = clock.split(':');
    let hh = cp.next()?.parse::<i64>().ok()?;
    let mm = cp.next()?.parse::<i64>().ok()?;
    let secs = cp.next()?.parse::<f64>().ok()?;
    let offset_min = match zone.as_bytes().first()? {
        b'Z' | b'z' => 0,
        sign => {
            let (oh, om) = zone[1..].split_once(':')?;
            let total = oh.parse::<i64>().ok()? * 60 + om.parse::<i64>().ok()?;
            if *sign == b'-' { -total } else { total }
        }
    };
    let whole = days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 - offset_min * 60;
    Some(whole * 1000 + (secs * 1000.0).round() as i64)
}

pub fn rel_time(now_ms: i64, then_ms: i64) -> String {
    let secs = ((now_ms - then_ms) / 1000).max(0);
    match secs {
        0..=4 => "just now".into(),
        5..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

pub fn fmt_clock(ms: i64) -> String {
    let day = ms.div_euclid(1000).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", day / 3600, day % 3600 / 60, day % 60)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InfoView {
    pub uptime_secs: u64,
    pub sites: usize,
    pub rules: usize,
    pub haproxy: Option<bool>,
}

// Counts arrive either as plain numbers or as lists, depending on the connector version.
fn count_of(value: Option<&Value>) -> usize {
    match value {
        Some(Value::Array(items)) => items.len(),
        Some(v) => v.as_u64().unwrap_or(0) as usize,
        None => 0,
    }
}

pub fn read_info(info: &NodeInfo) -> InfoView {
    InfoView {
        uptime_secs: info
            .extra
            .get("uptime_secs")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        sites: count_of(info.extra.get("sites")),
        rules: count_of(info.extra.get("firewall_rules")),
        haproxy: info
            .extra
            .get("haproxy")
            .and_then(|h| h.get("running"))
            .and_then(Value::as_bool),
    }
}

// Older connectors do not report the field, which reads as no node-level token.
pub fn node_has_github_token(info: &NodeInfo) -> bool {
    info.github.as_ref().is_some_and(|g| g.token_configured)
}

pub fn merge_top(lists: Vec<&Vec<TopItem>>, keep: usize) -> Vec<TopItem> {
    let mut by_key: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for item in lists.into_iter().flatten() {
        let slot = by_key.entry(item.key.clone()).or_default();
        slot.0 += item.count;
        slot.1 += item.bytes;
    }
    let mut out: Vec<TopItem> = by_key
        .into_iter()
        .map(|(key, (count, bytes))| TopItem { key, count, bytes })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out.truncate(keep);
    out
}

fn merge_counts(maps: Vec<&BTreeMap<String, u64>>) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (k, v) in maps.into_iter().flatten() {
        *out.entry(k.clone()).or_insert(0) += v;
    }
    out
}

// The API reports sizes cumulatively (each bucket counts everything up to its bound); charts need per-bucket counts.
pub fn per_bucket_sizes(sizes: &[SizeBucket]) -> Vec<SizeBucket> {
    let mut previous = 0u64;
    sizes
        .iter()
        .map(|b| {
            let count = b.count.saturating_sub(previous);
            previous = previous.max(b.count);
            SizeBucket { le: b.le, count }
        })
        .collect()
}

// Percentiles cannot be combined exactly, so the worst node is reported for them.
pub fn merge_summaries(all: &[Summary]) -> Summary {
    let requests: u64 = all.iter().map(|s| s.requests).sum();
    let weighted: f64 = all.iter().map(|s| s.avg_ms * s.requests as f64).sum();
    let mut sizes: BTreeMap<Option<u64>, u64> = BTreeMap::new();
    for b in all.iter().flat_map(|s| s.sizes.iter()) {
        *sizes.entry(b.le).or_insert(0) += b.count;
    }
    let mut sizes: Vec<SizeBucket> = sizes
        .into_iter()
        .map(|(le, count)| SizeBucket { le, count })
        .collect();
    sizes.sort_by_key(|b| b.le.unwrap_or(u64::MAX));
    Summary {
        requests,
        bytes_in: all.iter().map(|s| s.bytes_in).sum(),
        bytes_out: all.iter().map(|s| s.bytes_out).sum(),
        blocked: all.iter().map(|s| s.blocked).sum(),
        errors_4xx: all.iter().map(|s| s.errors_4xx).sum(),
        errors_5xx: all.iter().map(|s| s.errors_5xx).sum(),
        avg_ms: if requests == 0 {
            0.0
        } else {
            weighted / requests as f64
        },
        p50_ms: all.iter().map(|s| s.p50_ms).max().unwrap_or(0),
        p95_ms: all.iter().map(|s| s.p95_ms).max().unwrap_or(0),
        p99_ms: all.iter().map(|s| s.p99_ms).max().unwrap_or(0),
        status: merge_counts(all.iter().map(|s| &s.status).collect()),
        methods: merge_counts(all.iter().map(|s| &s.methods).collect()),
        content_types: merge_counts(all.iter().map(|s| &s.content_types).collect()),
        sizes,
        top_paths: merge_top(all.iter().map(|s| &s.top_paths).collect(), 8),
        top_ips: merge_top(all.iter().map(|s| &s.top_ips).collect(), 8),
        top_user_agents: merge_top(all.iter().map(|s| &s.top_user_agents).collect(), 8),
        top_hosts: merge_top(all.iter().map(|s| &s.top_hosts).collect(), 8),
        top_blocked: merge_top(all.iter().map(|s| &s.top_blocked).collect(), 8),
    }
}

pub fn merge_series(all: &[Timeseries]) -> Timeseries {
    let mut by_ts: BTreeMap<i64, Point> = BTreeMap::new();
    for p in all.iter().flat_map(|s| s.points.iter()) {
        let slot = by_ts.entry(p.ts).or_insert(Point {
            ts: p.ts,
            requests: 0,
            bytes_out: 0,
            errors: 0,
            blocked: 0,
            avg_ms: 0.0,
        });
        let total = slot.requests + p.requests;
        slot.avg_ms = if total == 0 {
            0.0
        } else {
            (slot.avg_ms * slot.requests as f64 + p.avg_ms * p.requests as f64) / total as f64
        };
        slot.requests = total;
        slot.bytes_out += p.bytes_out;
        slot.errors += p.errors;
        slot.blocked += p.blocked;
    }
    Timeseries {
        step_secs: all.iter().map(|s| s.step_secs).max().unwrap_or(60),
        points: by_ts.into_values().collect(),
    }
}

#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub name: String,
    pub online: bool,
    pub error: String,
    pub version: String,
    pub uptime_secs: u64,
    pub sites: usize,
    pub rules: usize,
    pub haproxy: Option<bool>,
    pub summary: Option<Summary>,
    pub series: Option<Timeseries>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Totals {
    pub nodes_online: usize,
    pub nodes_total: usize,
    pub sites: usize,
    pub requests: u64,
    pub req_per_min: f64,
    pub errors: u64,
    pub error_rate: f64,
    pub blocked: u64,
}

pub fn aggregate(nodes: &[NodeSnapshot], window_minutes: f64) -> Totals {
    let online: Vec<&NodeSnapshot> = nodes.iter().filter(|n| n.online).collect();
    let summaries = online.iter().filter_map(|n| n.summary.as_ref());
    let (mut requests, mut errors, mut blocked) = (0u64, 0u64, 0u64);
    for s in summaries {
        requests += s.requests;
        errors += s.errors_4xx + s.errors_5xx;
        blocked += s.blocked;
    }
    Totals {
        nodes_online: online.len(),
        nodes_total: nodes.len(),
        sites: online.iter().map(|n| n.sites).sum(),
        requests,
        req_per_min: if window_minutes > 0.0 {
            requests as f64 / window_minutes
        } else {
            0.0
        },
        errors,
        error_rate: if requests == 0 {
            0.0
        } else {
            errors as f64 / requests as f64
        },
        blocked,
    }
}

// Rounds a maximum up to 1, 2 or 5 times a power of ten so axis labels stay readable.
pub fn nice_max(max: u64) -> u64 {
    if max <= 1 {
        return 1;
    }
    let mut unit = 1u64;
    while unit * 10 < max {
        unit *= 10;
    }
    [1, 2, 5, 10]
        .iter()
        .map(|m| m * unit)
        .find(|v| *v >= max)
        .unwrap_or(unit * 10)
}

// Maps values into a width by height box with the origin at the top left.
pub fn scale_points(values: &[u64], ceiling: u64, width: f32, height: f32) -> Vec<(f32, f32)> {
    let top = ceiling.max(1) as f32;
    let n = values.len();
    values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = if n < 2 {
                width / 2.0
            } else {
                width * i as f32 / (n - 1) as f32
            };
            (x, height - (*v as f32 / top).min(1.0) * height)
        })
        .collect()
}

pub fn parse_hosts(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .map(|h| h.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

// One target per comma or line, written as host:port with an optional weight after a space.
pub fn parse_targets(text: &str) -> Result<Vec<Target>, String> {
    let mut out = Vec::new();
    for entry in text
        .split([',', '\n'])
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let mut parts = entry.split_whitespace();
        let addr = parts.next().unwrap_or_default();
        let weight = match parts.next() {
            None => 100,
            Some(w) => w
                .parse::<u32>()
                .ok()
                .filter(|w| *w <= 256)
                .ok_or_else(|| format!("weight {w:?} must be a number from 0 to 256"))?,
        };
        if parts.next().is_some() || !addr.contains(':') {
            return Err(format!("{entry:?} is not a host:port address"));
        }
        out.push(Target {
            addr: addr.to_string(),
            weight,
        });
    }
    Ok(out)
}

pub fn fmt_targets(targets: &[Target]) -> String {
    targets
        .iter()
        .map(|t| format!("{} x{}", t.addr, t.weight))
        .collect::<Vec<_>>()
        .join(", ")
}

// Where a new site's content comes from; building from GitHub is the product's main path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceKind {
    #[default]
    Github,
    Servers,
}

// The runtimes and Node majors the node's orchestrator accepts (docs/orchestrator.md, Source settings).
pub const RUNTIMES: [&str; 4] = ["node", "bun", "static", "rust"];
pub const NODE_MAJORS: [u8; 2] = [22, 24];
pub const DEFAULT_RUNTIME: &str = "node";
pub const DEFAULT_POLL: &str = "5m";
pub const DEFAULT_BRANCH: &str = "main";
pub const POLL_HELP: &str = "How often the node checks the branch for new commits: 1m or longer (for example 5m, 1h or 1d), or off to deploy only by hand.";
pub const NODE_HELP: &str = "The Node.js version the node builds with. If the repository asks for a different version the build fails.";
pub const BUILD_DETECTION_NOTE: &str = "Package manager and build commands are detected by the node from your lockfile (npm, pnpm, yarn or bun) and package.json scripts.";

// One line for each runtime the node accepts.
pub fn runtime_help(runtime: &str) -> &'static str {
    match runtime {
        "node" => "Install, build and run a Node.js site, server-rendered or static.",
        "bun" => "Built like a Node.js site, then run by Bun.",
        "static" => "Serve the built files only; no server process runs.",
        "rust" => "Build and run a Rust crate. Takes no Node version.",
        _ => "",
    }
}

// Every runtime except rust builds with Node, so only rust takes no version.
pub fn takes_node_major(runtime: &str) -> bool {
    runtime.trim() != "rust"
}

#[derive(Clone, Default)]
pub struct SiteDraft {
    pub api: bool,
    pub source: SourceKind,
    pub name: String,
    pub id: String,
    pub hosts: String,
    pub path_prefixes: Vec<String>,
    pub path_regexes: Vec<String>,
    pub blue: String,
    pub green: String,
    pub health_path: String,
    // Empty means the node's default for each of these.
    pub health_interval: String,
    pub health_timeout: String,
    pub health_rise: String,
    pub health_fall: String,
    pub repo: String,
    pub branch: String,
    pub runtime: String,
    pub node_major: u8,
    pub poll_interval: String,
    pub build: BuildDraft,
    pub github_token: String,
    pub access: crate::certs::AccessDraft,
}

impl std::fmt::Debug for SiteDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteDraft")
            .field("api", &self.api)
            .field("source", &self.source)
            .field("name", &self.name)
            .field("id", &self.id)
            .field("hosts", &self.hosts)
            .field("path_prefixes", &self.path_prefixes)
            .field("path_regexes", &self.path_regexes)
            .field("blue", &self.blue)
            .field("green", &self.green)
            .field("health_path", &self.health_path)
            .field("health_interval", &self.health_interval)
            .field("health_timeout", &self.health_timeout)
            .field("health_rise", &self.health_rise)
            .field("health_fall", &self.health_fall)
            .field("repo", &self.repo)
            .field("branch", &self.branch)
            .field("runtime", &self.runtime)
            .field("node_major", &self.node_major)
            .field("poll_interval", &self.poll_interval)
            .field("build", &self.build)
            .field("github_token", &"[redacted]")
            .field("access", &self.access)
            .finish()
    }
}

// Accepts owner/name or a repository address and returns owner/name; text that cannot be read is returned as typed.
pub fn normalize_repo(text: &str) -> String {
    parse_repo(text)
        .map(|r| r.name)
        .unwrap_or_else(|_| text.trim().to_string())
}

pub fn repo_problem(text: &str) -> Option<String> {
    parse_repo(text).err()
}

// Mirrors the node's git ref check: letters, digits, '.', '_', '/', '-', up to 100 characters.
pub fn branch_problem(text: &str) -> Option<String> {
    let b = text.trim();
    let ok = !b.is_empty()
        && b.len() <= 100
        && b.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
        && !b.starts_with('-')
        && !b.starts_with('/')
        && !b.ends_with('/')
        && !b.contains("..");
    (!ok).then(|| {
        "The branch may use letters, digits, '.', '_', '/' and '-' (up to 100 characters), cannot start with '-' and cannot contain '..'.".to_string()
    })
}

// Mirrors the node: off or 0 disables polling, anything else is a duration of at least 60 seconds.
pub fn poll_problem(text: &str) -> Option<String> {
    let t = text.trim();
    if t == "0" || t.eq_ignore_ascii_case("off") {
        return None;
    }
    let bad = || {
        Some("The poll interval is off, or a number with a unit such as 5m, 1h or 1d.".to_string())
    };
    let Some(split) = t.find(|c: char| c.is_ascii_alphabetic()) else {
        return bad();
    };
    let (num, unit) = t.split_at(split);
    let Ok(n) = num.parse::<u64>() else {
        return bad();
    };
    let unit_secs: u64 = match unit.to_ascii_lowercase().as_str() {
        "ms" => 0,
        "s" | "sec" | "secs" => 1,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hrs" => 3_600,
        "d" | "day" | "days" => 86_400,
        _ => return bad(),
    };
    let secs = if unit.eq_ignore_ascii_case("ms") {
        n / 1000
    } else {
        n.saturating_mul(unit_secs)
    };
    if secs < 60 {
        return Some("The poll interval must be at least 1m (or off).".into());
    }
    if secs > 366 * 86_400 {
        return Some("The poll interval is too large; use at most 366d.".into());
    }
    None
}

pub fn runtime_problem(text: &str) -> Option<String> {
    (!RUNTIMES.contains(&text.trim())).then(|| "Pick node, bun, static or rust.".to_string())
}

pub fn node_major_problem(runtime: &str, major: u8) -> Option<String> {
    (takes_node_major(runtime) && !NODE_MAJORS.contains(&major))
        .then(|| "Pick Node 22 or 24.".to_string())
}

// The GitHub fields, in the order the form shows them.
pub fn github_problem(draft: &SiteDraft) -> Option<String> {
    repo_problem(&draft.repo)
        .or_else(|| branch_problem(&draft.branch))
        .or_else(|| runtime_problem(&draft.runtime))
        .or_else(|| node_major_problem(&draft.runtime, draft.node_major))
        .or_else(|| poll_problem(&draft.poll_interval))
}

// The health check from its text fields; blank fields keep the node's defaults and the node's own ranges are checked with the site.
pub fn health_from_draft(d: &SiteDraft) -> Result<HealthCheck, String> {
    let def = HealthCheck::default();
    let number = |text: &str, what: &str, default: u32| -> Result<u32, String> {
        let t = text.trim();
        if t.is_empty() {
            return Ok(default);
        }
        t.parse::<u32>()
            .map_err(|_| format!("The health check {what} must be a whole number."))
    };
    Ok(HealthCheck {
        path: d.health_path.trim().to_string(),
        interval_ms: number(&d.health_interval, "interval", def.interval_ms)?,
        timeout_ms: number(&d.health_timeout, "timeout", def.timeout_ms)?,
        rise: number(&d.health_rise, "rise count", def.rise)?,
        fall: number(&d.health_fall, "fall count", def.fall)?,
    })
}

// The health check fields checked the way the node checks a site, so the message matches.
pub fn health_problem(d: &SiteDraft) -> Option<String> {
    let health = match health_from_draft(d) {
        Ok(h) => h,
        Err(e) => return Some(e),
    };
    let empty = || Upstream {
        targets: Vec::new(),
        label: None,
    };
    let probe = Site {
        id: "probe".into(),
        name: "probe".into(),
        hosts: vec!["probe.example.com".into()],
        path_prefixes: Vec::new(),
        path_regexes: Vec::new(),
        kind: SiteKind::Site,
        blue: empty(),
        green: empty(),
        active: Slot::Blue,
        maintenance: Maintenance::default(),
        health,
        source: None,
        history: Vec::new(),
        access: Default::default(),
    };
    cite_edge::validate::validate_site(&probe)
        .err()
        .map(|e| e.to_string().replacen("site probe: ", "", 1))
}

// The build settings as text, one field per Source field; a blank field means "let the node detect it".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildDraft {
    pub root_dir: String,
    pub install_command: String,
    pub build_command: String,
    pub output_dir: String,
    pub framework: String,
    pub start_command: String,
    pub spa_fallback: String,
    // "" for auto, otherwise npm, pnpm, yarn or bun.
    pub package_manager: String,
    // "" for auto, otherwise static or ssr.
    pub rendering: String,
    // "" for auto, otherwise yes or no.
    pub prune: String,
    pub memory_mb: String,
    pub cpus: String,
    pub build_memory_mb: String,
    pub build_cpus: String,
}

pub const PACKAGE_MANAGERS: [&str; 4] = ["npm", "pnpm", "yarn", "bun"];
pub const RENDERINGS: [&str; 2] = ["static", "ssr"];
// The node's defaults for the two containers, shown as hints because a blank field keeps them.
pub const BUILD_RESOURCE_HINT: &str = "Build container default: 4 GiB of memory and 2 CPUs.";
pub const SERVE_RESOURCE_HINT: &str = "Serving container default: 2 GiB of memory and 2 CPUs.";
pub const RESOURCE_NOTE: &str = "Resource limits apply on the next redeploy.";

fn opt_text(text: &str) -> Option<String> {
    Some(text.trim().to_string()).filter(|t| !t.is_empty())
}

fn opt_mb(text: &str, what: &str) -> Result<Option<u32>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(None);
    }
    t.parse::<u32>()
        .map(Some)
        .map_err(|_| format!("{what} must be a whole number of MiB."))
}

fn opt_cpus(text: &str, what: &str) -> Result<Option<cite_edge::model::Cpus>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(None);
    }
    t.parse::<f32>()
        .ok()
        .filter(|c| c.is_finite())
        .map(|c| Some(cite_edge::model::Cpus(c)))
        .ok_or_else(|| format!("{what} must be a number such as 2 or 0.5."))
}

// Copies the build text fields onto a source; the node's own validation (validate_source) judges the values afterwards.
pub fn apply_build(src: &mut Source, b: &BuildDraft) -> Result<(), String> {
    use cite_edge::model::{PackageManager, RenderMode};
    src.root_dir = opt_text(&b.root_dir);
    src.install_command = opt_text(&b.install_command);
    src.build_command = opt_text(&b.build_command);
    src.output_dir = opt_text(&b.output_dir);
    src.framework = opt_text(&b.framework);
    src.start_command = opt_text(&b.start_command);
    src.spa_fallback = opt_text(&b.spa_fallback);
    src.package_manager = match b.package_manager.trim() {
        "" => None,
        "npm" => Some(PackageManager::Npm),
        "pnpm" => Some(PackageManager::Pnpm),
        "yarn" => Some(PackageManager::Yarn),
        "bun" => Some(PackageManager::Bun),
        _ => return Err("Pick npm, pnpm, yarn or bun, or leave it on auto.".into()),
    };
    src.rendering = match b.rendering.trim() {
        "" => None,
        "static" => Some(RenderMode::Static),
        "ssr" => Some(RenderMode::Ssr),
        _ => return Err("Pick static or ssr, or leave it on auto.".into()),
    };
    src.prune = match b.prune.trim() {
        "" => None,
        "yes" => Some(true),
        "no" => Some(false),
        _ => return Err("Prune is yes, no or auto.".into()),
    };
    src.memory_mb = opt_mb(&b.memory_mb, "Serving memory")?;
    src.cpus = opt_cpus(&b.cpus, "Serving CPUs")?;
    src.build_memory_mb = opt_mb(&b.build_memory_mb, "Build memory")?;
    src.build_cpus = opt_cpus(&b.build_cpus, "Build CPUs")?;
    Ok(())
}

pub fn build_draft_from(src: &Source) -> BuildDraft {
    use cite_edge::model::{PackageManager, RenderMode};
    let text = |v: &Option<String>| v.clone().unwrap_or_default();
    BuildDraft {
        root_dir: text(&src.root_dir),
        install_command: text(&src.install_command),
        build_command: text(&src.build_command),
        output_dir: text(&src.output_dir),
        framework: text(&src.framework),
        start_command: text(&src.start_command),
        spa_fallback: text(&src.spa_fallback),
        package_manager: match src.package_manager {
            None => "",
            Some(PackageManager::Npm) => "npm",
            Some(PackageManager::Pnpm) => "pnpm",
            Some(PackageManager::Yarn) => "yarn",
            Some(PackageManager::Bun) => "bun",
        }
        .to_string(),
        rendering: match src.rendering {
            None => "",
            Some(RenderMode::Static) => "static",
            Some(RenderMode::Ssr) => "ssr",
        }
        .to_string(),
        prune: match src.prune {
            None => "",
            Some(true) => "yes",
            Some(false) => "no",
        }
        .to_string(),
        memory_mb: src.memory_mb.map(|m| m.to_string()).unwrap_or_default(),
        cpus: src.cpus.map(|c| c.0.to_string()).unwrap_or_default(),
        build_memory_mb: src
            .build_memory_mb
            .map(|m| m.to_string())
            .unwrap_or_default(),
        build_cpus: src.build_cpus.map(|c| c.0.to_string()).unwrap_or_default(),
    }
}

// The source the draft describes. A stored source is the starting point, so the token name and any field the form does not own survive an edit.
fn source_from_draft(d: &SiteDraft, base: Option<&Source>) -> Result<Source, String> {
    if let Some(problem) = github_problem(d) {
        return Err(problem);
    }
    let repo = parse_repo(&d.repo)?;
    let runtime = d.runtime.trim().to_string();
    let mut src = base.cloned().unwrap_or_default();
    // The node picks the forge for the whole node and refuses a per-site one.
    src.forge = None;
    src.repo = repo.name;
    src.branch = Some(d.branch.trim().to_string());
    src.node_major = takes_node_major(&runtime).then_some(d.node_major);
    src.runtime = Some(runtime);
    src.poll_interval = Some(d.poll_interval.trim().to_string());
    apply_build(&mut src, &d.build)?;
    Ok(src)
}

// The fields every site has, shared by creating a site and editing one.
fn fill_site(site: &mut Site, d: &SiteDraft) -> Result<(), String> {
    if d.name.trim().is_empty() {
        return Err("Give the site a name.".into());
    }
    let prefixes = clean_list(d.path_prefixes.iter().cloned());
    let regexes = clean_list(d.path_regexes.iter().cloned());
    if let Some(problem) = paths_problem(&prefixes, &regexes) {
        return Err(format!("The routing paths are not valid: {problem}"));
    }
    site.name = d.name.trim().to_string();
    site.hosts = parse_hosts(&d.hosts);
    site.path_prefixes = prefixes;
    site.path_regexes = regexes;
    site.kind = if d.api { SiteKind::Api } else { SiteKind::Site };
    site.health = health_from_draft(d)?;
    site.access = d.access.to_access();
    Ok(())
}

pub fn build_site(draft: &SiteDraft) -> Result<Site, String> {
    let github = draft.source == SourceKind::Github;
    let (blue, green, source) = if github {
        // The node builds the live slot itself, so both slots start empty.
        (
            Vec::new(),
            Vec::new(),
            Some(source_from_draft(draft, None)?),
        )
    } else {
        let blue = parse_targets(&draft.blue)?;
        if blue.is_empty() {
            return Err("Add at least one blue target.".into());
        }
        (blue, parse_targets(&draft.green)?, None)
    };
    let mut site = Site {
        id: draft.id.trim().to_string(),
        name: String::new(),
        hosts: Vec::new(),
        path_prefixes: Vec::new(),
        path_regexes: Vec::new(),
        kind: SiteKind::Site,
        blue: Upstream {
            targets: blue,
            label: None,
        },
        green: Upstream {
            targets: green,
            label: None,
        },
        active: Slot::Blue,
        maintenance: Maintenance::default(),
        health: HealthCheck::default(),
        source,
        history: Vec::new(),
        access: Default::default(),
    };
    fill_site(&mut site, draft)?;
    cite_edge::validate::validate_site_strict(&site).map_err(|e| e.to_string())?;
    Ok(site)
}

// The site as an edit would send it: everything the form owns is replaced, the slots, history and stored token stay as the node has them.
pub fn edit_site(existing: &Site, draft: &SiteDraft) -> Result<Site, String> {
    let mut site = existing.clone();
    fill_site(&mut site, draft)?;
    if let Some(old) = &existing.source {
        site.source = Some(source_from_draft(draft, Some(old))?);
    }
    cite_edge::validate::validate_site_strict(&site).map_err(|e| e.to_string())?;
    Ok(site)
}

// The node refuses an empty target list but ignores it for a source-built site, so a valid placeholder goes out.
pub fn source_deploy_request(note: Option<String>) -> DeployRequest {
    DeployRequest {
        targets: vec![Target {
            addr: "192.0.2.1:1".into(),
            weight: 100,
        }],
        note,
    }
}

// What saving would change: any difference, and whether it is one a redeploy is needed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteChange {
    pub dirty: bool,
    pub needs_redeploy: bool,
}

pub fn site_change(existing: &Site, edited: &Site) -> SiteChange {
    SiteChange {
        dirty: existing != edited,
        needs_redeploy: existing.source != edited.source,
    }
}

// The form's starting point for a stored site.
pub fn draft_from_site(site: &Site) -> SiteDraft {
    let src = site.source.as_ref();
    let runtime = src
        .and_then(|s| s.runtime.clone())
        .unwrap_or_else(|| DEFAULT_RUNTIME.to_string());
    SiteDraft {
        api: site.kind == SiteKind::Api,
        source: if src.is_some() {
            SourceKind::Github
        } else {
            SourceKind::Servers
        },
        name: site.name.clone(),
        id: site.id.clone(),
        hosts: site.hosts.join(", "),
        path_prefixes: site.path_prefixes.clone(),
        path_regexes: site.path_regexes.clone(),
        blue: String::new(),
        green: String::new(),
        health_path: site.health.path.clone(),
        health_interval: site.health.interval_ms.to_string(),
        health_timeout: site.health.timeout_ms.to_string(),
        health_rise: site.health.rise.to_string(),
        health_fall: site.health.fall.to_string(),
        repo: src.map(|s| s.repo.clone()).unwrap_or_default(),
        branch: src
            .and_then(|s| s.branch.clone())
            .unwrap_or_else(|| DEFAULT_BRANCH.to_string()),
        runtime,
        node_major: src.and_then(|s| s.node_major).unwrap_or(NODE_MAJORS[0]),
        poll_interval: src
            .and_then(|s| s.poll_interval.clone())
            .unwrap_or_else(|| DEFAULT_POLL.to_string()),
        build: src.map(build_draft_from).unwrap_or_default(),
        github_token: String::new(),
        access: crate::certs::AccessDraft::from_access(&site.access),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    Selected,
    ReplicateAll,
}

// The token travels beside the site, never inside it, and only applies to sites built from GitHub.
pub fn draft_github_token(draft: &SiteDraft) -> Option<String> {
    let token = draft.github_token.trim();
    (!token.is_empty() && draft.source == SourceKind::Github).then(|| token.to_string())
}

// Resolves which nodes receive the site and the plan that describes how each one gets it.
pub fn plan_placement(
    site: &Site,
    placement: &Placement,
    selected: &[String],
    all: &[String],
    overrides: &BTreeMap<String, NodeTargets>,
    github_token: Option<String>,
) -> Result<(Vec<String>, ReplicationPlan), String> {
    let (nodes, mode) = match placement {
        Placement::Selected => (selected.to_vec(), ReplicationMode::Each),
        Placement::ReplicateAll => (all.to_vec(), ReplicationMode::Replicate),
    };
    if nodes.is_empty() {
        return Err("Pick at least one node.".into());
    }
    let mut plan = ReplicationPlan::new(site.clone(), mode).with_github_token(github_token);
    for (node, targets) in overrides {
        if nodes.contains(node) {
            plan = plan.with_node_targets(node.clone(), targets.clone());
        }
    }
    Ok((nodes, plan))
}

// A secret header value is never part of the summary, so the list cannot show it back.
pub fn matcher_summary(m: &Matchers) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(m.path_regexes.iter().map(|v| format!("path ~ {v}")));
    out.extend(m.path_prefixes.iter().map(|v| format!("path {v}*")));
    if !m.methods.is_empty() {
        out.push(m.methods.join(" "));
    }
    out.extend(m.user_agent_regexes.iter().map(|v| format!("ua ~ {v}")));
    out.extend(m.cidrs.iter().cloned());
    out.extend(m.hosts.iter().map(|v| format!("host {v}")));
    for h in &m.headers {
        let (op, value) = match (&h.regex, &h.equals) {
            _ if h.secret => (if h.negate { "!=" } else { "=" }, "(hidden)".to_string()),
            (Some(re), _) => (if h.negate { "!~" } else { "~" }, re.clone()),
            (_, Some(eq)) => (if h.negate { "!=" } else { "=" }, eq.clone()),
            _ => ("=", String::new()),
        };
        out.push(format!("header {} {op} {value}", h.name));
    }
    if let Some(v) = &m.scheme {
        out.push(format!("scheme {v}"));
    }
    out.extend(m.referer_regexes.iter().map(|v| format!("referer ~ {v}")));
    out
}

#[derive(Debug, Clone, Default)]
pub struct SettingsDraft {
    pub recent_events: String,
    pub minute_buckets_hours: String,
    pub keep_forever: bool,
    pub hour_buckets_days: String,
    pub archive_before_delete: bool,
    pub audit_days: String,
    pub persist_interval_secs: String,
    pub per_ip_rate_limit: String,
    pub store_user_agents: bool,
    pub store_client_ips: bool,
}

impl SettingsDraft {
    pub fn from_settings(s: &EdgeSettings) -> Self {
        let r = &s.retention;
        Self {
            recent_events: r.recent_events.to_string(),
            minute_buckets_hours: r.minute_buckets_hours.to_string(),
            keep_forever: r.hour_buckets_days == 0,
            hour_buckets_days: if r.hour_buckets_days == 0 {
                String::new()
            } else {
                r.hour_buckets_days.to_string()
            },
            archive_before_delete: r.archive_before_delete,
            audit_days: r.audit_days.to_string(),
            persist_interval_secs: r.persist_interval_secs.to_string(),
            per_ip_rate_limit: s
                .per_ip_rate_limit
                .map(|n| n.to_string())
                .unwrap_or_default(),
            store_user_agents: r.store_user_agents,
            store_client_ips: r.store_client_ips,
        }
    }

    pub fn defaults() -> Self {
        Self::from_settings(&EdgeSettings::default())
    }

    // Applies the draft on top of the node's current settings and runs the connector's own checks.
    pub fn apply(&self, base: &EdgeSettings) -> Result<EdgeSettings, String> {
        fn num<T: std::str::FromStr>(label: &str, text: &str) -> Result<T, String> {
            text.trim()
                .parse::<T>()
                .map_err(|_| format!("{label} must be a whole number."))
        }
        let rate = self.per_ip_rate_limit.trim();
        let mut next = base.clone();
        let keep_days = if self.keep_forever {
            0
        } else {
            crate::archive::parse_keep_days(&self.hour_buckets_days)?
        };
        next.retention = Retention {
            recent_events: num("Recent events", &self.recent_events)?,
            minute_buckets_hours: num("Minute buckets", &self.minute_buckets_hours)?,
            hour_buckets_days: keep_days,
            archive_before_delete: self.archive_before_delete,
            audit_days: num("Audit days", &self.audit_days)?,
            persist_interval_secs: num("Persist interval", &self.persist_interval_secs)?,
            store_user_agents: self.store_user_agents,
            store_client_ips: self.store_client_ips,
        };
        next.per_ip_rate_limit = if rate.is_empty() {
            None
        } else {
            Some(num("Per-IP rate limit", rate)?)
        };
        cite_edge::validate::validate_settings(&next).map_err(|e| e.to_string())?;
        Ok(next)
    }
}

pub fn token_name(hostname: &str) -> String {
    let slug = slugify(hostname);
    if slug.is_empty() {
        "desktop-app".into()
    } else {
        format!("desktop-{slug}")
    }
}

pub fn action_label(a: FirewallAction) -> &'static str {
    match a {
        FirewallAction::Deny => "Deny",
        FirewallAction::Drop => "Drop silently",
        FirewallAction::Tarpit => "Tarpit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_sizes_become_per_bucket_counts() {
        let cumulative = [(Some(1024), 14), (Some(4096), 36), (None, 100)]
            .map(|(le, count)| SizeBucket { le, count });
        let counts: Vec<u64> = per_bucket_sizes(&cumulative)
            .iter()
            .map(|b| b.count)
            .collect();
        assert_eq!(counts, [14, 22, 64]);
        let les: Vec<Option<u64>> = per_bucket_sizes(&cumulative).iter().map(|b| b.le).collect();
        assert_eq!(les, [Some(1024), Some(4096), None]);
        assert!(per_bucket_sizes(&[]).is_empty());
    }

    #[test]
    fn a_decreasing_bucket_never_underflows() {
        let odd =
            [(Some(1), 5), (Some(2), 3), (None, 9)].map(|(le, count)| SizeBucket { le, count });
        let counts: Vec<u64> = per_bucket_sizes(&odd).iter().map(|b| b.count).collect();
        assert_eq!(counts, [5, 0, 4]);
    }

    #[test]
    fn demo_sizes_are_cumulative_like_the_api() {
        let sizes = crate::demo::cumulative_sizes(1000);
        assert!(sizes.windows(2).all(|w| w[0].count <= w[1].count));
        let counts: Vec<u64> = per_bucket_sizes(&sizes).iter().map(|b| b.count).collect();
        assert_eq!(counts, [380, 410, 160, 50]);
    }

    fn snap(
        name: &str,
        online: bool,
        requests: u64,
        e4: u64,
        e5: u64,
        blocked: u64,
    ) -> NodeSnapshot {
        let summary = Summary {
            requests,
            errors_4xx: e4,
            errors_5xx: e5,
            blocked,
            ..Summary::default()
        };
        NodeSnapshot {
            name: name.into(),
            online,
            error: String::new(),
            version: "0.2.0".into(),
            uptime_secs: 10,
            sites: 3,
            rules: 2,
            haproxy: Some(true),
            summary: online.then_some(summary),
            series: None,
        }
    }

    fn draft() -> SiteDraft {
        SiteDraft {
            name: "Storefront".into(),
            id: "storefront".into(),
            hosts: "shop.example.com, www.example.com".into(),
            blue: "10.0.0.1:8080, 10.0.0.2:8080 50".into(),
            health_path: "/".into(),
            source: SourceKind::Servers,
            ..SiteDraft::default()
        }
    }

    fn github_draft() -> SiteDraft {
        SiteDraft {
            source: SourceKind::Github,
            repo: "acme/shop".into(),
            branch: "main".into(),
            runtime: "node".into(),
            node_major: 22,
            poll_interval: "5m".into(),
            blue: String::new(),
            ..draft()
        }
    }

    #[test]
    fn build_settings_round_trip_through_a_source() {
        let mut src = Source {
            repo: "acme/shop".into(),
            ..Default::default()
        };
        let b = BuildDraft {
            root_dir: " web ".into(),
            build_command: "pnpm build".into(),
            package_manager: "pnpm".into(),
            rendering: "ssr".into(),
            prune: "no".into(),
            start_command: "node server.js".into(),
            memory_mb: "1024".into(),
            cpus: "0.5".into(),
            build_memory_mb: "4096".into(),
            build_cpus: "2".into(),
            ..BuildDraft::default()
        };
        apply_build(&mut src, &b).expect("valid");
        assert_eq!(src.root_dir.as_deref(), Some("web"));
        assert_eq!(src.install_command, None);
        assert_eq!(
            src.package_manager,
            Some(cite_edge::model::PackageManager::Pnpm)
        );
        assert_eq!(src.rendering, Some(cite_edge::model::RenderMode::Ssr));
        assert_eq!(src.prune, Some(false));
        assert_eq!(src.memory_mb, Some(1024));
        assert_eq!(src.cpus.map(|c| c.0), Some(0.5));
        assert_eq!(src.build_cpus.map(|c| c.0), Some(2.0));
        assert!(cite_edge::validate::validate_source(&src).is_ok());
        let back = build_draft_from(&src);
        assert_eq!(back.root_dir, "web");
        assert_eq!(back.cpus, "0.5");
        assert_eq!(back.build_cpus, "2");
        assert_eq!(back.prune, "no");
        let mut again = src.clone();
        apply_build(&mut again, &back).expect("valid");
        assert_eq!(again, src);
        apply_build(&mut again, &BuildDraft::default()).expect("blank");
        assert_eq!(again.root_dir, None);
        assert_eq!(again.cpus, None);
        assert_eq!(again.repo, "acme/shop");
    }

    #[test]
    fn bad_build_choices_and_numbers_are_refused_in_plain_words() {
        let mut src = Source::default();
        let bad = |f: fn(&mut BuildDraft)| {
            let mut b = BuildDraft::default();
            f(&mut b);
            apply_build(&mut Source::default(), &b).unwrap_err()
        };
        assert!(bad(|b| b.package_manager = "pip".into()).contains("npm"));
        assert!(bad(|b| b.rendering = "hybrid".into()).contains("static"));
        assert!(bad(|b| b.prune = "maybe".into()).contains("yes"));
        assert!(bad(|b| b.memory_mb = "lots".into()).contains("MiB"));
        assert!(bad(|b| b.build_cpus = "two".into()).contains("CPUs"));
        assert!(bad(|b| b.cpus = "inf".into()).contains("CPUs"));
        src.repo = "acme/shop".into();
        src.memory_mb = Some(64);
        assert!(cite_edge::validate::validate_source(&src).is_err());
    }

    #[test]
    fn an_edit_keeps_what_the_form_does_not_own() {
        let mut stored = build_site(&github_draft()).expect("valid");
        let src = stored.source.as_mut().expect("source");
        src.secret = Some("site-token-name".into());
        src.forge = Some("github".into());
        let mut d = draft_from_site(&stored);
        d.build.install_command = "npm ci".into();
        let edited = edit_site(&stored, &d).expect("valid");
        let got = edited.source.expect("source");
        assert_eq!(got.secret.as_deref(), Some("site-token-name"));
        assert_eq!(got.install_command.as_deref(), Some("npm ci"));
        assert_eq!(
            got.forge, None,
            "a per-site forge is dropped, the node refuses it"
        );
    }

    #[test]
    fn path_checks_are_remembered_between_calls() {
        let p = vec!["/api".to_string()];
        let r = vec!["^/v[0-9]+/".to_string()];
        assert_eq!(paths_problem(&p, &r), None);
        assert_eq!(paths_problem(&p, &r), None);
        let bad = vec!["(".to_string()];
        assert!(paths_problem(&p, &bad).is_some());
        assert!(paths_problem(&p, &bad).is_some());
        assert_eq!(paths_problem(&p, &r), None);
        for _ in 0..3 {
            assert_eq!(paths_match(&p, &r, "/v2/x"), Some(true));
            assert_eq!(paths_match(&p, &r, "/zzz"), Some(false));
        }
    }

    #[test]
    fn number_formatting() {
        assert_eq!(fmt_num(950), "950");
        assert_eq!(fmt_num(1_234), "1.2K");
        assert_eq!(fmt_num(250_000), "250K");
        assert_eq!(fmt_num(3_400_000), "3.4M");
        assert_eq!(fmt_int(0), "0");
        assert_eq!(fmt_int(1_234_567), "1,234,567");
        assert_eq!(fmt_int(100), "100");
    }

    #[test]
    fn byte_and_time_formatting() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_bytes(200 * 1024 * 1024), "200 MB");
        assert_eq!(fmt_ms(42.4), "42 ms");
        assert_eq!(fmt_ms(1500.0), "1.50 s");
        assert_eq!(fmt_pct(0.0123, 2), "1.23%");
        assert_eq!(fmt_uptime(26 * 86_400 + 3 * 3600), "26d 3h");
        assert_eq!(fmt_uptime(3 * 3600 + 120), "3h 2m");
        assert_eq!(fmt_uptime(59), "0m");
    }

    #[test]
    fn slugs() {
        assert_eq!(slugify("My Store!"), "my-store");
        assert_eq!(slugify("  --API v2--  "), "api-v2");
        assert_eq!(slugify("***"), "");
        assert!(slugify(&"a".repeat(80)).len() <= 40);
        assert_eq!(slugify("Caf\u{e9} Shop"), "caf-shop");
    }

    #[test]
    fn timestamps_parse_and_format() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2000-03-01T00:00:00Z"),
            Some(951_868_800_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2000-03-01T02:00:00+02:00"),
            Some(951_868_800_000)
        );
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:01.250Z"), Some(1250));
        assert_eq!(parse_rfc3339_ms("garbage"), None);
        assert_eq!(fmt_clock(3_723_000), "01:02:03");
        assert_eq!(rel_time(10_000, 9_000), "just now");
        assert_eq!(rel_time(100_000, 40_000), "1m ago");
        assert_eq!(rel_time(86_400_000 * 3, 0), "3d ago");
    }

    #[test]
    fn totals_only_count_online_nodes() {
        let nodes = vec![
            snap("a", true, 3000, 100, 50, 10),
            snap("b", true, 1500, 0, 0, 5),
            snap("c", false, 9999, 9999, 0, 9999),
        ];
        let t = aggregate(&nodes, 15.0);
        assert_eq!((t.nodes_online, t.nodes_total, t.sites), (2, 3, 6));
        assert_eq!(t.requests, 4500);
        assert!((t.req_per_min - 300.0).abs() < 1e-9);
        assert_eq!((t.errors, t.blocked), (150, 15));
        assert!((t.error_rate - 150.0 / 4500.0).abs() < 1e-9);
    }

    #[test]
    fn totals_handle_no_traffic() {
        let t = aggregate(&[], 15.0);
        assert_eq!((t.requests, t.error_rate), (0, 0.0));
        let t = aggregate(&[snap("a", true, 0, 0, 0, 0)], 0.0);
        assert_eq!(t.req_per_min, 0.0);
    }

    #[test]
    fn chart_scaling() {
        assert_eq!(nice_max(0), 1);
        assert_eq!(nice_max(7), 10);
        assert_eq!(nice_max(130), 200);
        assert_eq!(nice_max(420), 500);
        assert_eq!(nice_max(501), 1000);
        let pts = scale_points(&[0, 50, 100], 100, 200.0, 100.0);
        assert_eq!(pts, vec![(0.0, 100.0), (100.0, 50.0), (200.0, 0.0)]);
        assert_eq!(scale_points(&[10], 10, 80.0, 40.0), vec![(40.0, 0.0)]);
        assert!(scale_points(&[], 10, 80.0, 40.0).is_empty());
        assert_eq!(scale_points(&[500], 100, 10.0, 10.0)[0].1, 0.0);
    }

    #[test]
    fn target_parsing() {
        let t = parse_targets("10.0.0.1:80, 10.0.0.2:81 50\n[::1]:82").expect("parse");
        assert_eq!(t.len(), 3);
        assert_eq!((t[0].weight, t[1].weight, t[2].weight), (100, 50, 100));
        assert!(parse_targets("nohost").is_err());
        assert!(parse_targets("a:1 999").is_err());
        assert!(parse_targets("a:1 2 3").is_err());
        assert!(parse_targets("  ").expect("empty").is_empty());
    }

    #[test]
    fn host_parsing_lowercases_and_splits() {
        assert_eq!(
            parse_hosts("A.example.com, b.example.com\nC"),
            vec!["a.example.com", "b.example.com", "c"]
        );
    }

    #[test]
    fn site_drafts_validate() {
        let site = build_site(&draft()).expect("valid");
        assert_eq!(site.hosts.len(), 2);
        assert_eq!(site.blue.targets[1].weight, 50);
        assert_eq!(site.active, Slot::Blue);
        let mut bad = draft();
        bad.id = "Not Valid".into();
        assert!(build_site(&bad).is_err());
        let mut no_targets = draft();
        no_targets.blue.clear();
        assert!(build_site(&no_targets).is_err());
        let mut bad_re = draft();
        bad_re.path_regexes = vec!["(".into()];
        assert!(build_site(&bad_re).unwrap_err().contains("routing paths"));
        let mut bad_prefix = draft();
        bad_prefix.path_prefixes = vec!["no-slash".into()];
        assert!(build_site(&bad_prefix).is_err());
    }

    #[test]
    fn site_paths_are_lists_that_are_cleaned_and_limited() {
        let mut d = draft();
        d.path_prefixes = vec![" /a ".into(), "".into(), "/a".into(), "/b".into()];
        d.path_regexes = vec!["^/c[0-9]+$".into(), "^/d".into()];
        let site = build_site(&d).expect("valid");
        assert_eq!(site.path_prefixes, vec!["/a", "/b"]);
        assert_eq!(site.path_regexes.len(), 2);
        d.path_prefixes = (0..40).map(|i| format!("/p{i}")).collect();
        assert!(build_site(&d).unwrap_err().contains("at most"));
        assert!(paths_problem(&[], &[]).is_none());
        assert!(paths_problem(&["/ok".into()], &["^/x".into()]).is_none());
        assert!(paths_problem(&[], &["(".into()]).is_some());
        let (p, r) = (vec!["/static".to_string()], vec!["^/v[0-9]+/".to_string()]);
        assert_eq!(paths_match(&p, &r, "/static/a.css"), Some(true));
        assert_eq!(paths_match(&p, &r, "/v2/users"), Some(true));
        assert_eq!(paths_match(&p, &r, "/other"), Some(false));
        assert_eq!(paths_match(&p, &r, ""), None);
        assert_eq!(paths_match(&[], &[], "/x"), None);
        assert_eq!(paths_match(&[], &["(".to_string()], "/x"), None);
        assert_eq!(
            clean_list(["b".to_string(), "a".into(), "b".into(), " ".into()]),
            ["b", "a"]
        );
    }

    #[test]
    fn site_drafts_carry_access() {
        let open = build_site(&draft()).expect("valid");
        assert_eq!(open.access, cite_edge::model::SiteAccess::default());
        let mut d = draft();
        d.access.set_cloudflare_only(true);
        d.access.flexible = true;
        d.access.bots = cite_edge::model::BotPolicy::BlockBad;
        d.access.set_zone_lock(true);
        let site = build_site(&d).expect("valid");
        assert!(site.access.cloudflare_only && site.access.zone_lock);
        assert_eq!(site.access.tls, cite_edge::model::TlsMode::Flexible);
        assert_eq!(site.access.bots, cite_edge::model::BotPolicy::BlockBad);
        let mut lone = draft();
        lone.access.zone_lock = true;
        assert!(!build_site(&lone).expect("valid").access.zone_lock);
    }

    #[test]
    fn site_drafts_carry_source() {
        let mut d = github_draft();
        d.repo = "https://github.com/acme/shop.git".into();
        let token = crate::testkit::joined(&["gh", "-fixture", "-token"]);
        d.github_token = token.clone();
        let site = build_site(&d).expect("valid");
        assert!(site.blue.targets.is_empty() && site.green.targets.is_empty());
        let source = site.source.expect("source");
        assert_eq!(source.repo, "acme/shop");
        assert_eq!(source.branch.as_deref(), Some("main"));
        assert_eq!(source.runtime.as_deref(), Some("node"));
        assert_eq!(source.node_major, Some(22));
        assert_eq!(source.poll_interval.as_deref(), Some("5m"));
        assert!(source.secret.is_none());
        assert!(
            draft_github_token(&d).as_deref() == Some(token.as_str()),
            "values differ"
        );
        let site = build_site(&d).expect("valid");
        let all = vec!["a".to_string()];
        let (_, plan) = plan_placement(
            &site,
            &Placement::Selected,
            &["a".into()],
            &all,
            &BTreeMap::new(),
            draft_github_token(&d),
        )
        .expect("plan");
        assert!(
            plan.github_token.as_deref() == Some(token.as_str()),
            "values differ"
        );
        assert!(!format!("{plan:?}").contains(token.as_str()));
        d.source = SourceKind::Servers;
        assert!(draft_github_token(&d).is_none());
    }

    #[test]
    fn github_is_the_default_source() {
        assert_eq!(SourceKind::default(), SourceKind::Github);
        assert_eq!(SiteDraft::default().source, SourceKind::Github);
    }

    #[test]
    fn github_drafts_need_no_targets_and_check_their_fields() {
        let d = github_draft();
        assert!(build_site(&d).is_ok());
        for (repo, ok) in [
            ("acme/shop", true),
            ("https://github.com/acme/shop", true),
            ("acme", false),
            ("acme/.github", true),
            ("git@github.com:acme/shop.git", true),
            ("a/b/c", false),
            ("", false),
        ] {
            let mut x = d.clone();
            x.repo = repo.into();
            assert_eq!(build_site(&x).is_ok(), ok, "{repo}");
        }
        let mut url = d.clone();
        url.repo = "https://github.com/acme/shop.git".into();
        assert_eq!(build_site(&url).unwrap().source.unwrap().repo, "acme/shop");
        let mut x = d.clone();
        x.runtime = "ruby".into();
        assert!(build_site(&x).unwrap_err().contains("Pick node"));
        let mut x = d.clone();
        x.poll_interval = "soon".into();
        assert!(build_site(&x).unwrap_err().contains("poll interval"));
        let mut x = d.clone();
        x.branch = "a..b".into();
        assert!(build_site(&x).is_err());
        let mut x = d.clone();
        x.node_major = 18;
        assert!(build_site(&x).is_err());
        x.runtime = "rust".into();
        let site = build_site(&x).expect("rust needs no node version");
        assert_eq!(site.source.expect("source").node_major, None);
    }

    #[test]
    fn poll_intervals_follow_the_nodes_rules() {
        for ok in [
            "5m", "60s", "1m", "2h", "1d", "off", "OFF", "0", " 10m ", "120sec", "3days", "60000ms",
        ] {
            assert!(poll_problem(ok).is_none(), "{ok}");
        }
        for (bad, word) in [
            ("10s", "at least"),
            ("59s", "at least"),
            ("0m", "at least"),
            ("500ms", "at least"),
            ("5", "off, or a number"),
            ("m", "off, or a number"),
            ("", "off, or a number"),
            ("soon", "off, or a number"),
            ("5x", "off, or a number"),
            ("-5m", "off, or a number"),
            ("1.5h", "off, or a number"),
            ("999d", "too large"),
        ] {
            let got = poll_problem(bad).unwrap_or_else(|| panic!("{bad} should fail"));
            assert!(got.contains(word), "{bad}: {got}");
        }
    }

    #[test]
    fn branches_follow_the_nodes_ref_rules() {
        for ok in ["main", "release/1.2", "feature_x-y", "v1.0.0"] {
            assert!(branch_problem(ok).is_none(), "{ok}");
        }
        let long = "a".repeat(101);
        for bad in [
            "",
            " ",
            "-x",
            "/x",
            "x/",
            "a..b",
            "a b",
            "a~b",
            "a:b",
            long.as_str(),
        ] {
            assert!(branch_problem(bad).is_some(), "{bad:?}");
        }
        assert!(branch_problem(&"a".repeat(100)).is_none());
    }

    #[test]
    fn every_runtime_has_a_one_line_explanation() {
        for r in RUNTIMES {
            assert!(
                !runtime_help(r).is_empty() && !runtime_help(r).contains('\n'),
                "{r}"
            );
        }
        assert_eq!(runtime_help("cobol"), "");
        assert!(takes_node_major("node") && takes_node_major("bun") && takes_node_major("static"));
        assert!(!takes_node_major("rust"));
        assert!(node_major_problem("rust", 0).is_none());
        assert!(node_major_problem("node", 24).is_none());
        assert!(node_major_problem("bun", 18).is_some());
        assert!(
            BUILD_DETECTION_NOTE.contains("lockfile")
                && BUILD_DETECTION_NOTE.contains("package.json")
        );
    }

    #[test]
    fn health_checks_come_from_text_with_defaults() {
        let mut d = draft();
        let h = health_from_draft(&d).expect("defaults");
        assert_eq!(
            (h.interval_ms, h.timeout_ms, h.rise, h.fall),
            (2000, 1500, 2, 3)
        );
        d.health_interval = " 5000 ".into();
        d.health_timeout = "1000".into();
        d.health_rise = "3".into();
        d.health_fall = "4".into();
        let h = health_from_draft(&d).expect("set");
        assert_eq!(
            (h.interval_ms, h.timeout_ms, h.rise, h.fall),
            (5000, 1000, 3, 4)
        );
        d.health_rise = "two".into();
        assert!(health_from_draft(&d).unwrap_err().contains("rise count"));
        let site = build_site(&draft()).expect("valid");
        assert_eq!(site.health.path, "/");
        assert!(health_problem(&draft()).is_none());
        let mut odd = draft();
        odd.health_path = "health".into();
        assert!(health_problem(&odd).unwrap().contains("health path"));
        odd.health_path = "/".into();
        odd.health_fall = "11".into();
        assert!(health_problem(&odd).unwrap().contains("fall"));
        odd.health_fall = "x".into();
        assert!(health_problem(&odd).unwrap().contains("whole number"));
        let mut slow = draft();
        slow.health_interval = "50".into();
        assert!(build_site(&slow).unwrap_err().contains("100"));
        let mut tangled = draft();
        tangled.health_interval = "1000".into();
        tangled.health_timeout = "2000".into();
        assert!(build_site(&tangled).unwrap_err().contains("timeout"));
        let mut bad_path = draft();
        bad_path.health_path = "health".into();
        assert!(build_site(&bad_path).is_err());
    }

    #[test]
    fn editing_replaces_form_fields_and_keeps_the_rest() {
        let mut stored = build_site(&github_draft()).expect("valid");
        stored.source.as_mut().unwrap().secret = Some("site-token-name".into());
        stored.history.push(cite_edge::model::Deployment {
            id: "d1".into(),
            at: "2025-01-01T00:00:00Z".into(),
            slot: Slot::Blue,
            action: cite_edge::model::DeployAction::Promote,
            note: "first".into(),
        });
        stored.blue.targets = vec![Target {
            addr: "10.0.0.1:3000".into(),
            weight: 100,
        }];
        let unchanged = edit_site(&stored, &draft_from_site(&stored)).expect("round trip");
        assert_eq!(unchanged, stored);
        assert_eq!(
            site_change(&stored, &unchanged),
            SiteChange {
                dirty: false,
                needs_redeploy: false
            }
        );

        let mut d = draft_from_site(&stored);
        d.name = "Renamed".into();
        d.hosts = "a.example.com, b.example.com".into();
        d.api = true;
        d.path_prefixes = vec!["/api".into()];
        d.health_interval = "3000".into();
        let renamed = edit_site(&stored, &d).expect("valid");
        assert_eq!(renamed.name, "Renamed");
        assert_eq!(renamed.hosts.len(), 2);
        assert_eq!(renamed.kind, SiteKind::Api);
        assert_eq!(renamed.id, stored.id);
        assert_eq!(renamed.history, stored.history);
        assert_eq!(renamed.blue, stored.blue);
        assert_eq!(renamed.active, stored.active);
        assert_eq!(renamed.source, stored.source);
        assert_eq!(
            site_change(&stored, &renamed),
            SiteChange {
                dirty: true,
                needs_redeploy: false
            }
        );

        let mut d = draft_from_site(&stored);
        d.repo = "https://github.com/acme/other.git".into();
        d.branch = "release".into();
        d.runtime = "bun".into();
        d.node_major = 24;
        d.poll_interval = "1h".into();
        let moved = edit_site(&stored, &d).expect("valid");
        let src = moved.source.clone().expect("source");
        assert_eq!(src.repo, "acme/other");
        assert_eq!(src.branch.as_deref(), Some("release"));
        assert_eq!(src.runtime.as_deref(), Some("bun"));
        assert_eq!(src.node_major, Some(24));
        assert_eq!(src.poll_interval.as_deref(), Some("1h"));
        assert_eq!(src.secret.as_deref(), Some("site-token-name"));
        assert_eq!(
            site_change(&stored, &moved),
            SiteChange {
                dirty: true,
                needs_redeploy: true
            }
        );

        d.runtime = "rust".into();
        assert_eq!(
            edit_site(&stored, &d).unwrap().source.unwrap().node_major,
            None
        );
        d.poll_interval = "5s".into();
        assert!(edit_site(&stored, &d).is_err());
    }

    #[test]
    fn a_source_redeploy_sends_a_target_the_node_accepts_and_ignores() {
        let req = source_deploy_request(Some("rebuild".into()));
        assert_eq!(req.note.as_deref(), Some("rebuild"));
        assert_eq!(req.targets.len(), 1);
        let mut site = build_site(&github_draft()).expect("valid");
        site.blue.targets = req.targets.clone();
        cite_edge::validate::validate_site(&site).unwrap();
        assert!(source_deploy_request(None).note.is_none());
    }

    #[test]
    fn editing_a_server_site_never_adds_a_source() {
        let stored = build_site(&draft()).expect("valid");
        let mut d = draft_from_site(&stored);
        assert_eq!(d.source, SourceKind::Servers);
        d.repo = "acme/shop".into();
        d.name = "Other".into();
        let edited = edit_site(&stored, &d).expect("valid");
        assert!(edited.source.is_none());
        assert_eq!(edited.blue, stored.blue);
        d.hosts = "".into();
        assert!(edit_site(&stored, &d).is_err());
    }

    #[test]
    fn the_form_starts_from_the_stored_site() {
        let mut stored = build_site(&github_draft()).expect("valid");
        stored.source = Some(Source {
            repo: "acme/shop".into(),
            secret: Some("name".into()),
            ..Default::default()
        });
        let d = draft_from_site(&stored);
        assert_eq!(d.source, SourceKind::Github);
        assert_eq!(
            (
                d.branch.as_str(),
                d.runtime.as_str(),
                d.node_major,
                d.poll_interval.as_str()
            ),
            ("main", "node", 22, "5m")
        );
        assert!(d.github_token.is_empty());
        assert_eq!(d.health_interval, "2000");
        assert_eq!(d.hosts, "shop.example.com, www.example.com");
    }

    #[test]
    fn server_drafts_carry_no_source() {
        let mut d = draft();
        d.repo = "acme/shop".into();
        assert!(build_site(&d).expect("valid").source.is_none());
        assert!(draft_github_token(&d).is_none());
    }

    #[test]
    fn site_draft_debug_hides_the_github_token() {
        let mut d = draft();
        let token = crate::testkit::joined(&["gh", "-fixture", "-token"]);
        d.github_token = token.clone();
        let shown = format!("{d:?}");
        assert!(!shown.contains(token.as_str()));
        assert!(shown.contains(&d.name));
    }

    #[test]
    fn placement_selected_and_replicated() {
        let site = build_site(&draft()).expect("valid");
        let all = vec!["a".to_string(), "b".to_string()];
        let (nodes, plan) = plan_placement(
            &site,
            &Placement::Selected,
            &["b".into()],
            &all,
            &BTreeMap::new(),
            None,
        )
        .expect("plan");
        assert_eq!(nodes, vec!["b".to_string()]);
        assert_eq!(plan.mode, ReplicationMode::Each);
        let (nodes, plan) = plan_placement(
            &site,
            &Placement::ReplicateAll,
            &[],
            &all,
            &BTreeMap::new(),
            None,
        )
        .expect("plan");
        assert_eq!(nodes.len(), 2);
        assert_eq!(plan.mode, ReplicationMode::Replicate);
        assert!(
            plan_placement(
                &site,
                &Placement::Selected,
                &[],
                &all,
                &BTreeMap::new(),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn placement_overrides_apply_per_node_only_when_each() {
        let site = build_site(&draft()).expect("valid");
        let custom = vec![Target {
            addr: "10.9.9.9:80".into(),
            weight: 100,
        }];
        let mut over = BTreeMap::new();
        over.insert(
            "a".to_string(),
            NodeTargets {
                blue: Some(custom.clone()),
                green: None,
            },
        );
        let all = vec!["a".to_string(), "b".to_string()];
        let (_, each) = plan_placement(
            &site,
            &Placement::Selected,
            &["a".into()],
            &all,
            &over,
            None,
        )
        .expect("plan");
        assert_eq!(each.site_for("a").blue.targets, custom);
        assert_eq!(each.site_for("b").blue.targets, site.blue.targets);
        let (_, rep) =
            plan_placement(&site, &Placement::ReplicateAll, &[], &all, &over, None).expect("plan");
        assert_eq!(rep.site_for("a").blue.targets, site.blue.targets);
    }

    #[test]
    fn info_counts_accept_numbers_and_lists() {
        let mut extra = serde_json::Map::new();
        extra.insert("uptime_secs".into(), serde_json::json!(90));
        extra.insert("sites".into(), serde_json::json!(4));
        extra.insert("firewall_rules".into(), serde_json::json!([1, 2]));
        extra.insert("haproxy".into(), serde_json::json!({"running": false}));
        let info = NodeInfo {
            name: "n".into(),
            version: "1".into(),
            capabilities: Vec::new(),
            github: None,
            extra,
        };
        assert_eq!(
            read_info(&info),
            InfoView {
                uptime_secs: 90,
                sites: 4,
                rules: 2,
                haproxy: Some(false)
            }
        );
        let bare = NodeInfo {
            name: String::new(),
            version: String::new(),
            capabilities: Vec::new(),
            github: None,
            extra: Default::default(),
        };
        assert_eq!(read_info(&bare), InfoView::default());
        assert!(!node_has_github_token(&bare));
        let with = NodeInfo {
            github: Some(cite_client::GithubInfo {
                token_configured: true,
                source: "env".into(),
                api_host: None,
            }),
            ..bare
        };
        assert!(node_has_github_token(&with));
    }

    #[test]
    fn summaries_merge_by_key() {
        let item = |k: &str, n: u64| TopItem {
            key: k.into(),
            count: n,
            bytes: n * 10,
        };
        let a = Summary {
            requests: 100,
            avg_ms: 10.0,
            p95_ms: 50,
            top_paths: vec![item("/a", 60), item("/b", 40)],
            ..Summary::default()
        };
        let b = Summary {
            requests: 300,
            avg_ms: 30.0,
            p95_ms: 20,
            top_paths: vec![item("/b", 200), item("/c", 100)],
            ..Summary::default()
        };
        let m = merge_summaries(&[a, b]);
        assert_eq!(m.requests, 400);
        assert!((m.avg_ms - 25.0).abs() < 1e-9);
        assert_eq!(m.p95_ms, 50);
        let keys: Vec<_> = m
            .top_paths
            .iter()
            .map(|t| (t.key.as_str(), t.count))
            .collect();
        assert_eq!(keys, vec![("/b", 240), ("/c", 100), ("/a", 60)]);
        assert_eq!(merge_summaries(&[]).requests, 0);
    }

    #[test]
    fn series_merge_sums_matching_timestamps() {
        let p = |ts, requests, errors| Point {
            ts,
            requests,
            bytes_out: 1,
            errors,
            blocked: 0,
            avg_ms: 10.0,
        };
        let a = Timeseries {
            step_secs: 60,
            points: vec![p(1, 5, 1), p(2, 6, 0)],
        };
        let b = Timeseries {
            step_secs: 60,
            points: vec![p(2, 4, 2), p(3, 1, 0)],
        };
        let m = merge_series(&[a, b]);
        let got: Vec<_> = m
            .points
            .iter()
            .map(|p| (p.ts, p.requests, p.errors))
            .collect();
        assert_eq!(got, vec![(1, 5, 1), (2, 10, 2), (3, 1, 0)]);
    }

    #[test]
    fn settings_drafts_round_trip_and_validate() {
        let base = EdgeSettings::default();
        let draft = SettingsDraft::from_settings(&base);
        assert_eq!(draft.recent_events, "5000");
        assert_eq!(draft.per_ip_rate_limit, "600");
        assert_eq!(draft.apply(&base).expect("unchanged"), base);
        let defaults = SettingsDraft::defaults();
        assert_eq!(defaults.audit_days, "365");
        let mut off = draft.clone();
        off.per_ip_rate_limit = String::new();
        assert_eq!(off.apply(&base).expect("off").per_ip_rate_limit, None);
        let mut bad = draft.clone();
        bad.recent_events = "lots".into();
        assert!(bad.apply(&base).unwrap_err().contains("Recent events"));
        let mut zero = draft;
        zero.persist_interval_secs = "0".into();
        assert!(zero.apply(&base).is_err());
    }

    #[test]
    fn retention_is_unlimited_unless_a_limit_is_chosen() {
        let base = EdgeSettings::default();
        let draft = SettingsDraft::from_settings(&base);
        assert!(draft.keep_forever);
        assert!(draft.archive_before_delete);
        assert_eq!(draft.hour_buckets_days, "");
        let mut limited = draft.clone();
        limited.keep_forever = false;
        limited.hour_buckets_days = "365".into();
        limited.archive_before_delete = false;
        let next = limited.apply(&base).expect("limited");
        assert_eq!(next.retention.hour_buckets_days, 365);
        assert!(!next.retention.archive_before_delete);
        let back = SettingsDraft::from_settings(&next);
        assert!(!back.keep_forever);
        assert_eq!(back.hour_buckets_days, "365");
        limited.hour_buckets_days = "3651".into();
        assert!(limited.apply(&base).is_err());
        limited.hour_buckets_days = String::new();
        assert!(limited.apply(&base).is_err());
        let mut forever = limited;
        forever.keep_forever = true;
        assert_eq!(
            forever
                .apply(&base)
                .expect("forever")
                .retention
                .hour_buckets_days,
            0
        );
    }

    #[test]
    fn matcher_summaries_and_names() {
        let m = Matchers {
            path_prefixes: vec!["/admin".into(), "/staff".into()],
            methods: vec!["POST".into()],
            cidrs: vec!["10.0.0.0/8".into()],
            ..Matchers::default()
        };
        assert_eq!(
            matcher_summary(&m),
            vec!["path /admin*", "path /staff*", "POST", "10.0.0.0/8"]
        );
        let extra = Matchers {
            headers: vec![cite_edge::model::HeaderMatch {
                name: "X-Beta".into(),
                equals: Some(crate::testkit::joined(&["hidden", "-gate", "-value"])),
                negate: true,
                secret: true,
                ..Default::default()
            }],
            scheme: Some("http".into()),
            referer_regexes: vec!["spam".into()],
            ..Matchers::default()
        };
        let shown = matcher_summary(&extra);
        assert_eq!(
            shown,
            vec!["header X-Beta != (hidden)", "scheme http", "referer ~ spam"]
        );
        assert!(!shown.join(" ").contains("hidden-gate-value"));
        let open = Matchers {
            headers: vec![cite_edge::model::HeaderMatch {
                name: "X-A".into(),
                regex: Some("^a".into()),
                ..Default::default()
            }],
            ..Matchers::default()
        };
        assert_eq!(matcher_summary(&open), vec!["header X-A ~ ^a"]);
        assert_eq!(
            token_name("Zak's MacBook.local"),
            "desktop-zak-s-macbook-local"
        );
        assert_eq!(token_name("..."), "desktop-app");
    }
}
