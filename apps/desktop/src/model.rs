use std::collections::BTreeMap;

use cite_client::{NodeInfo, NodeTargets, ReplicationMode, ReplicationPlan};
use cite_edge::analytics::{Point, SizeBucket, Summary, Timeseries, TopItem};
use cite_edge::model::{
    EdgeSettings, FirewallAction, FirewallRule, HealthCheck, Maintenance, Matchers, Retention,
    Site, SiteKind, Slot, Source, Target, Upstream,
};
use cite_edge::validate::validate_rule;
use serde_json::Value;

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
pub fn regex_problem(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return None;
    }
    let probe = FirewallRule {
        id: "probe".into(),
        name: "probe".into(),
        enabled: true,
        action: FirewallAction::Deny,
        matchers: Matchers {
            path_regex: Some(pattern.to_string()),
            ..Matchers::default()
        },
        site: None,
    };
    validate_rule(&probe).err().map(|e| {
        let text = e.to_string();
        match text.split_once(": ") {
            Some((_, rest)) => rest.to_string(),
            None => text,
        }
    })
}

// The sample check mirrors the pattern field so a bad regex reports no match result at all.
pub fn regex_matches(pattern: &str, sample: &str) -> Option<bool> {
    if pattern.is_empty() || sample.is_empty() || regex_problem(pattern).is_some() {
        return None;
    }
    regex::Regex::new(pattern)
        .ok()
        .map(|re| re.is_match(sample))
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

#[derive(Clone, Default)]
pub struct SiteDraft {
    pub api: bool,
    pub name: String,
    pub id: String,
    pub hosts: String,
    pub path_regex: String,
    pub blue: String,
    pub green: String,
    pub health_path: String,
    pub repo: String,
    pub branch: String,
    pub github_token: String,
}

impl std::fmt::Debug for SiteDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteDraft")
            .field("api", &self.api)
            .field("name", &self.name)
            .field("id", &self.id)
            .field("hosts", &self.hosts)
            .field("path_regex", &self.path_regex)
            .field("blue", &self.blue)
            .field("green", &self.green)
            .field("health_path", &self.health_path)
            .field("repo", &self.repo)
            .field("branch", &self.branch)
            .field("github_token", &"[redacted]")
            .finish()
    }
}

pub fn build_site(draft: &SiteDraft) -> Result<Site, String> {
    if draft.name.trim().is_empty() {
        return Err("Give the site a name.".into());
    }
    let blue = parse_targets(&draft.blue)?;
    if blue.is_empty() {
        return Err("Add at least one blue target.".into());
    }
    let green = parse_targets(&draft.green)?;
    let path = draft.path_regex.trim();
    if let Some(problem) = regex_problem(path) {
        return Err(format!("The path regex is not valid: {problem}"));
    }
    let repo = draft.repo.trim();
    let source = (!repo.is_empty()).then(|| Source {
        repo: repo.to_string(),
        branch: Some(draft.branch.trim().to_string()).filter(|b| !b.is_empty()),
        runtime: None,
        node_major: None,
        poll_interval: None,
        secret: None,
    });
    let site = Site {
        id: draft.id.trim().to_string(),
        name: draft.name.trim().to_string(),
        hosts: parse_hosts(&draft.hosts),
        path_regex: (!path.is_empty()).then(|| path.to_string()),
        kind: if draft.api {
            SiteKind::Api
        } else {
            SiteKind::Site
        },
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
        health: HealthCheck {
            path: draft.health_path.trim().to_string(),
            ..HealthCheck::default()
        },
        source,
        history: Vec::new(),
    };
    cite_edge::validate::validate_site(&site).map_err(|e| e.to_string())?;
    Ok(site)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    Selected,
    ReplicateAll,
}

// The token travels beside the site, never inside it, and only applies when a repository is set.
pub fn draft_github_token(draft: &SiteDraft) -> Option<String> {
    let token = draft.github_token.trim();
    (!token.is_empty() && !draft.repo.trim().is_empty()).then(|| token.to_string())
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

#[derive(Debug, Clone, Default)]
pub struct RuleDraft {
    pub name: String,
    pub action: Option<FirewallAction>,
    pub path_regex: String,
    pub path_prefix: String,
    pub methods: String,
    pub user_agent_regex: String,
    pub cidrs: String,
    pub host: String,
    pub site: String,
}

fn some_trimmed(text: &str) -> Option<String> {
    Some(text.trim().to_string()).filter(|t| !t.is_empty())
}

pub fn build_rule(draft: &RuleDraft, suffix: &str) -> Result<FirewallRule, String> {
    if draft.name.trim().is_empty() {
        return Err("Give the rule a name.".into());
    }
    let list = |t: &str| -> Vec<String> {
        t.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    let rule = FirewallRule {
        id: format!("{}-{}", slugify(&draft.name), suffix.to_lowercase()),
        name: draft.name.trim().to_string(),
        enabled: true,
        action: draft.action.unwrap_or(FirewallAction::Deny),
        matchers: Matchers {
            path_regex: some_trimmed(&draft.path_regex),
            path_prefix: some_trimmed(&draft.path_prefix),
            methods: list(&draft.methods)
                .into_iter()
                .map(|m| m.to_uppercase())
                .collect(),
            user_agent_regex: some_trimmed(&draft.user_agent_regex),
            cidrs: list(&draft.cidrs),
            host: some_trimmed(&draft.host),
        },
        site: some_trimmed(&draft.site),
    };
    validate_rule(&rule).map_err(|e| e.to_string())?;
    Ok(rule)
}

pub fn matcher_summary(m: &Matchers) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(v) = &m.path_regex {
        out.push(format!("path ~ {v}"));
    }
    if let Some(v) = &m.path_prefix {
        out.push(format!("path {v}*"));
    }
    if !m.methods.is_empty() {
        out.push(m.methods.join(" "));
    }
    if let Some(v) = &m.user_agent_regex {
        out.push(format!("ua ~ {v}"));
    }
    out.extend(m.cidrs.iter().cloned());
    if let Some(v) = &m.host {
        out.push(format!("host {v}"));
    }
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
            ..SiteDraft::default()
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
    fn regex_validity() {
        assert_eq!(regex_problem(""), None);
        assert_eq!(regex_problem("^/api/"), None);
        assert!(regex_problem("(unclosed").is_some());
        assert!(regex_problem("has space").is_some());
    }

    #[test]
    fn regex_sample_matching() {
        assert_eq!(regex_matches("^/api/", "/api/v1"), Some(true));
        assert_eq!(regex_matches("^/api/", "/web"), Some(false));
        assert_eq!(regex_matches("(", "/x"), None);
        assert_eq!(regex_matches("", "/x"), None);
        assert_eq!(regex_matches("^/", ""), None);
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
        bad_re.path_regex = "(".into();
        assert!(build_site(&bad_re).unwrap_err().contains("regex"));
    }

    #[test]
    fn site_drafts_carry_source() {
        let mut d = draft();
        d.repo = "https://github.com/acme/shop".into();
        d.branch = "main".into();
        d.github_token = "ghp_secret".into();
        let site = build_site(&d).expect("valid");
        let source = site.source.expect("source");
        assert_eq!(source.branch.as_deref(), Some("main"));
        assert_eq!(source.secret, None);
        assert_eq!(draft_github_token(&d).as_deref(), Some("ghp_secret"));
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
        assert_eq!(plan.github_token.as_deref(), Some("ghp_secret"));
        assert!(!format!("{plan:?}").contains("ghp_secret"));
        d.repo.clear();
        assert_eq!(draft_github_token(&d), None);
    }

    #[test]
    fn site_draft_debug_hides_the_github_token() {
        let mut d = draft();
        d.github_token = "ghp_secret".into();
        let shown = format!("{d:?}");
        assert!(!shown.contains("ghp_secret"));
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
    fn rule_drafts_validate() {
        let d = RuleDraft {
            name: "Block WP".into(),
            action: Some(FirewallAction::Drop),
            path_regex: "^/wp-".into(),
            methods: "get, post".into(),
            ..RuleDraft::default()
        };
        let rule = build_rule(&d, "AB12").expect("valid");
        assert_eq!(rule.id, "block-wp-ab12");
        assert_eq!(rule.matchers.methods, vec!["GET", "POST"]);
        assert!(build_rule(&RuleDraft::default(), "x").is_err());
        let empty = RuleDraft {
            name: "Nothing".into(),
            ..RuleDraft::default()
        };
        assert!(build_rule(&empty, "x").is_err());
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
            extra: Default::default(),
        };
        assert_eq!(read_info(&bare), InfoView::default());
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
            path_prefix: Some("/admin".into()),
            methods: vec!["POST".into()],
            cidrs: vec!["10.0.0.0/8".into()],
            ..Matchers::default()
        };
        assert_eq!(
            matcher_summary(&m),
            vec!["path /admin*", "POST", "10.0.0.0/8"]
        );
        assert_eq!(
            token_name("Zak's MacBook.local"),
            "desktop-zak-s-macbook-local"
        );
        assert_eq!(token_name("..."), "desktop-app");
    }
}
