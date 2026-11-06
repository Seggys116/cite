use std::collections::BTreeMap;
use std::net::IpAddr;

use cite_client::{
    AnalyticsMeta, AnalyticsQuery, BlockedFilter, ExportFormat, ExportKind, ExportQuery,
    FacetValue, Facets,
};
use cite_edge::analytics::{Summary, Timeseries, TopItem, window_from_str};
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;

use crate::bots::merge_bot_summaries;
use crate::config::SavedPreset;
use crate::demo::iso;
use crate::model::{
    fmt_bytes, fmt_int, fmt_ms, fmt_num, fmt_pct, merge_series, merge_summaries, merge_top,
    parse_rfc3339_ms,
};
use crate::theme::Tone;

pub const CAP_ANALYTICS: &str = "analytics-filters";
pub const METHOD_CHIPS: [&str; 6] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];
pub const STATUS_CHIPS: [&str; 4] = ["2xx", "3xx", "4xx", "5xx"];
pub const DEFAULT_WINDOW: &str = "1h";
pub const MAX_PRESETS: usize = 30;
pub const PRESET_NAME_MAX: usize = 40;
pub const PAGE_SIZE: usize = 50;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlockedMode {
    #[default]
    Any,
    Blocked,
    Unblocked,
}

// The text fields of a filter, so one code path serves inputs, chips and click-to-filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Host,
    PathPrefix,
    PathExact,
    ClientIp,
    UserAgent,
    Referer,
    ContentType,
    Status,
    MinDuration,
}

impl Field {
    pub const ALL: [Field; 9] = [
        Field::Host,
        Field::PathPrefix,
        Field::PathExact,
        Field::ClientIp,
        Field::UserAgent,
        Field::Referer,
        Field::ContentType,
        Field::Status,
        Field::MinDuration,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Field::Host => "Host",
            Field::PathPrefix => "Path prefix",
            Field::PathExact => "Path",
            Field::ClientIp => "Client IP",
            Field::UserAgent => "User agent",
            Field::Referer => "Referer",
            Field::ContentType => "Content type",
            Field::Status => "Status",
            Field::MinDuration => "Slower than (ms)",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Field::Host => "host",
            Field::PathPrefix => "path_prefix",
            Field::PathExact => "path_exact",
            Field::ClientIp => "ip",
            Field::UserAgent => "ua",
            Field::Referer => "referer",
            Field::ContentType => "ctype",
            Field::Status => "status",
            Field::MinDuration => "min_ms",
        }
    }
}

// What the page filters on. Blank text means "not set"; a blank window means the custom range in from and to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    pub window: String,
    pub from: String,
    pub to: String,
    pub sites: Vec<String>,
    pub methods: Vec<String>,
    pub status_classes: Vec<String>,
    pub bot_classes: Vec<String>,
    pub blocked: BlockedMode,
    pub host: String,
    pub path_prefix: String,
    pub path_exact: String,
    pub client_ip: String,
    pub user_agent: String,
    pub referer: String,
    pub content_type: String,
    pub status: String,
    pub min_duration: String,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW.into(),
            from: String::new(),
            to: String::new(),
            sites: Vec::new(),
            methods: Vec::new(),
            status_classes: Vec::new(),
            bot_classes: Vec::new(),
            blocked: BlockedMode::Any,
            host: String::new(),
            path_prefix: String::new(),
            path_exact: String::new(),
            client_ip: String::new(),
            user_agent: String::new(),
            referer: String::new(),
            content_type: String::new(),
            status: String::new(),
            min_duration: String::new(),
        }
    }
}

// One removable piece of the filter, shown as a chip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChipKey {
    Range,
    Site(String),
    Method(String),
    StatusClass(String),
    BotClass(String),
    Blocked,
    Text(Field),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chip {
    pub label: String,
    pub key: ChipKey,
}

// Adds the value when absent and removes it when present.
pub fn toggled(list: &[String], value: &str) -> Vec<String> {
    if list.iter().any(|v| v == value) {
        list.iter().filter(|v| *v != value).cloned().collect()
    } else {
        let mut out = list.to_vec();
        out.push(value.to_string());
        out
    }
}

// "2026-11-05" or "2026-11-05 12:30", read as UTC. A date that does not exist (such as 31 February) is refused.
pub fn parse_stamp(text: &str) -> Result<i64, String> {
    let t = text.trim();
    let (date, clock) = match t.split_once([' ', 'T']) {
        Some((d, c)) => (d, c.trim()),
        None => (t, "00:00"),
    };
    let fail = || format!("{t:?} is not a date such as 2026-11-05 or 2026-11-05 12:30.");
    if date.len() != 10 || clock.len() != 5 {
        return Err(fail());
    }
    let ms = parse_rfc3339_ms(&format!("{date}T{clock}:00Z")).ok_or_else(fail)?;
    if iso(ms)[..16] != format!("{date}T{clock}") {
        return Err(fail());
    }
    Ok(ms)
}

fn pct_encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:/,".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text
                .get(i + 1..i + 3)
                .ok_or("a preset ends inside a %-escape")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "a preset has a bad %-escape")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "a preset is not valid text".to_string())
}

fn list_of(text: &str) -> Vec<String> {
    text.split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl Filter {
    pub fn text(&self, field: Field) -> &str {
        match field {
            Field::Host => &self.host,
            Field::PathPrefix => &self.path_prefix,
            Field::PathExact => &self.path_exact,
            Field::ClientIp => &self.client_ip,
            Field::UserAgent => &self.user_agent,
            Field::Referer => &self.referer,
            Field::ContentType => &self.content_type,
            Field::Status => &self.status,
            Field::MinDuration => &self.min_duration,
        }
    }

    pub fn set_text(&mut self, field: Field, value: &str) {
        let slot = match field {
            Field::Host => &mut self.host,
            Field::PathPrefix => &mut self.path_prefix,
            Field::PathExact => &mut self.path_exact,
            Field::ClientIp => &mut self.client_ip,
            Field::UserAgent => &mut self.user_agent,
            Field::Referer => &mut self.referer,
            Field::ContentType => &mut self.content_type,
            Field::Status => &mut self.status,
            Field::MinDuration => &mut self.min_duration,
        };
        *slot = value.trim().to_string();
    }

    pub fn custom_range(&self) -> bool {
        self.window.is_empty()
    }

    // The query this filter describes, checked with the client library's own rules.
    pub fn query(&self, now_ms: i64) -> Result<AnalyticsQuery, String> {
        let mut q = AnalyticsQuery::new();
        if self.custom_range() {
            let from = parse_stamp(&self.from).map_err(|e| format!("From: {e}"))?;
            if self.to.trim().is_empty() {
                q = q.range(from, now_ms.max(from + 1));
            } else {
                q = q.range(from, parse_stamp(&self.to).map_err(|e| format!("To: {e}"))?);
            }
        } else {
            q = q.window(self.window.clone());
        }
        q = q.sites(self.sites.iter().cloned());
        q.methods = self.methods.clone();
        q.status_classes = self.status_classes.clone();
        q.bot_classes = self.bot_classes.clone();
        q.blocked = match self.blocked {
            BlockedMode::Any => None,
            BlockedMode::Blocked => Some(BlockedFilter::Blocked),
            BlockedMode::Unblocked => Some(BlockedFilter::Unblocked),
        };
        let some = |s: &str| Some(s.trim().to_string()).filter(|t| !t.is_empty());
        q.host = some(&self.host);
        q.path_prefix = some(&self.path_prefix);
        q.path_exact = some(&self.path_exact);
        q.client_ip = some(&self.client_ip);
        q.user_agent = some(&self.user_agent);
        q.referer = some(&self.referer);
        q.content_type = some(&self.content_type);
        if let Some(s) = some(&self.status) {
            q.status = Some(
                s.parse()
                    .map_err(|_| "Status is a number such as 404.".to_string())?,
            );
        }
        if let Some(ms) = some(&self.min_duration) {
            q.min_duration_ms = Some(
                ms.parse()
                    .map_err(|_| "Slower than is a whole number of milliseconds.".to_string())?,
            );
        }
        q.validate().map_err(|e| {
            e.to_string()
                .trim_start_matches("invalid node settings: ")
                .to_string()
        })?;
        Ok(q)
    }

    // A node without the capability understands a window and one site, nothing else.
    pub fn restricted(&self) -> Filter {
        Filter {
            window: if self.custom_range() {
                DEFAULT_WINDOW.into()
            } else {
                self.window.clone()
            },
            sites: self.sites.iter().take(1).cloned().collect(),
            ..Filter::default()
        }
    }

    // Everything the filter narrows down, as removable chips; the default window is not one.
    pub fn chips(&self) -> Vec<Chip> {
        let mut out = Vec::new();
        if self.custom_range() {
            let to = if self.to.trim().is_empty() {
                "now"
            } else {
                self.to.trim()
            };
            out.push(Chip {
                label: format!("{} to {to}", self.from.trim()),
                key: ChipKey::Range,
            });
        } else if self.window != DEFAULT_WINDOW {
            out.push(Chip {
                label: format!("Last {}", self.window),
                key: ChipKey::Range,
            });
        }
        out.extend(self.sites.iter().map(|s| Chip {
            label: format!("Site {s}"),
            key: ChipKey::Site(s.clone()),
        }));
        out.extend(self.methods.iter().map(|m| Chip {
            label: m.clone(),
            key: ChipKey::Method(m.clone()),
        }));
        out.extend(self.status_classes.iter().map(|s| Chip {
            label: format!("Status {s}"),
            key: ChipKey::StatusClass(s.clone()),
        }));
        out.extend(self.bot_classes.iter().map(|b| Chip {
            label: format!("Bot: {b}"),
            key: ChipKey::BotClass(b.clone()),
        }));
        match self.blocked {
            BlockedMode::Any => {}
            BlockedMode::Blocked => out.push(Chip {
                label: "Blocked".into(),
                key: ChipKey::Blocked,
            }),
            BlockedMode::Unblocked => out.push(Chip {
                label: "Not blocked".into(),
                key: ChipKey::Blocked,
            }),
        }
        for f in Field::ALL {
            let v = self.text(f);
            if !v.is_empty() {
                out.push(Chip {
                    label: format!("{}: {v}", f.label()),
                    key: ChipKey::Text(f),
                });
            }
        }
        out
    }

    pub fn remove(&mut self, key: &ChipKey) {
        match key {
            ChipKey::Range => {
                self.window = DEFAULT_WINDOW.into();
                self.from.clear();
                self.to.clear();
            }
            ChipKey::Site(s) => self.sites.retain(|v| v != s),
            ChipKey::Method(m) => self.methods.retain(|v| v != m),
            ChipKey::StatusClass(s) => self.status_classes.retain(|v| v != s),
            ChipKey::BotClass(b) => self.bot_classes.retain(|v| v != b),
            ChipKey::Blocked => self.blocked = BlockedMode::Any,
            ChipKey::Text(f) => self.set_text(*f, ""),
        }
    }

    // The shareable form: key=value pairs joined by &, values %-encoded, lists joined by commas.
    pub fn encode(&self) -> String {
        let mut parts: Vec<(&str, String)> = Vec::new();
        if self.custom_range() {
            parts.push(("from", pct_encode(self.from.trim())));
            parts.push(("to", pct_encode(self.to.trim())));
        } else {
            parts.push(("window", pct_encode(&self.window)));
        }
        for (key, list) in [
            ("site", &self.sites),
            ("method", &self.methods),
            ("status_class", &self.status_classes),
            ("bot_class", &self.bot_classes),
        ] {
            if !list.is_empty() {
                parts.push((
                    key,
                    list.iter()
                        .map(|v| pct_encode(v))
                        .collect::<Vec<_>>()
                        .join(","),
                ));
            }
        }
        match self.blocked {
            BlockedMode::Any => {}
            BlockedMode::Blocked => parts.push(("blocked", "true".into())),
            BlockedMode::Unblocked => parts.push(("blocked", "unblocked".into())),
        }
        for f in Field::ALL {
            let v = self.text(f);
            if !v.is_empty() {
                parts.push((f.key(), pct_encode(v)));
            }
        }
        parts
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    pub fn decode(text: &str) -> Result<Filter, String> {
        let mut f = Filter::default();
        let mut custom = false;
        for part in text.trim().split('&').filter(|p| !p.is_empty()) {
            let (key, raw) = part
                .split_once('=')
                .ok_or_else(|| "a preset is made of key=value pairs".to_string())?;
            let items = |raw: &str| -> Result<Vec<String>, String> {
                list_of(raw).iter().map(|v| pct_decode(v)).collect()
            };
            match key {
                "window" => f.window = pct_decode(raw)?,
                "from" => {
                    custom = true;
                    f.from = pct_decode(raw)?;
                }
                "to" => {
                    custom = true;
                    f.to = pct_decode(raw)?;
                }
                "site" => f.sites = items(raw)?,
                "method" => f.methods = items(raw)?,
                "status_class" => f.status_classes = items(raw)?,
                "bot_class" => f.bot_classes = items(raw)?,
                "blocked" => {
                    f.blocked = match raw {
                        "true" => BlockedMode::Blocked,
                        "unblocked" => BlockedMode::Unblocked,
                        _ => return Err("blocked is true or unblocked".into()),
                    }
                }
                other => {
                    let field = Field::ALL
                        .into_iter()
                        .find(|f| f.key() == other)
                        .ok_or_else(|| format!("unknown filter key {other:?}"))?;
                    f.set_text(field, &pct_decode(raw)?);
                }
            }
        }
        if custom {
            f.window.clear();
        } else if window_from_str(&f.window).is_none() {
            return Err("window is one of 15m, 1h, 24h, 7d, 30d".into());
        }
        Ok(f)
    }
}

pub fn preset_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > PRESET_NAME_MAX || n.chars().any(char::is_control) {
        return Err(format!(
            "A preset name is 1 to {PRESET_NAME_MAX} characters without control characters."
        ));
    }
    Ok(n.to_string())
}

// A preset with the same name is replaced, so saving twice never piles up copies.
pub fn upsert_preset(
    presets: &mut Vec<SavedPreset>,
    name: &str,
    filter: &Filter,
) -> Result<(), String> {
    let name = preset_name(name)?;
    let query = filter.encode();
    if let Some(existing) = presets.iter_mut().find(|p| p.name == name) {
        existing.query = query;
        return Ok(());
    }
    if presets.len() >= MAX_PRESETS {
        return Err(format!("At most {MAX_PRESETS} presets can be saved."));
    }
    presets.push(SavedPreset { name, query });
    Ok(())
}

// What the export route can apply: one site, one method, one bot class, a status range and the fields it lists.
pub fn export_gaps(q: &AnalyticsQuery) -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if q.sites.len() > 1 {
        gaps.push("more than one site");
    }
    if q.methods.len() > 1 {
        gaps.push("more than one method");
    }
    if q.bot_classes.len() > 1 {
        gaps.push("more than one bot class");
    }
    if q.blocked.is_some() {
        gaps.push("blocked");
    }
    if q.path_exact.is_some() {
        gaps.push("exact path");
    }
    if q.user_agent.is_some() {
        gaps.push("user agent");
    }
    if q.referer.is_some() {
        gaps.push("referer");
    }
    if q.content_type.is_some() {
        gaps.push("content type");
    }
    if q.min_duration_ms.is_some() {
        gaps.push("slower than");
    }
    if q.max_bot_score.is_some() {
        gaps.push("maximum bot score");
    }
    if q.client_ip.as_deref().is_some_and(|ip| ip.contains('/')) {
        gaps.push("client network");
    }
    gaps
}

fn status_bounds(q: &AnalyticsQuery) -> (Option<u16>, Option<u16>) {
    if let Some(s) = q.status {
        return (Some(s), Some(s));
    }
    let class_bounds = q.status_classes.iter().filter_map(|c| {
        let n: u16 = c.get(..1)?.parse().ok()?;
        Some((n * 100, n * 100 + 99))
    });
    let lo = class_bounds.clone().map(|b| b.0).min();
    let hi = class_bounds.map(|b| b.1).max();
    (q.status_min.or(lo), q.status_max.or(hi))
}

// The range the export route takes: explicit bounds, with a window turned into the last N seconds.
pub fn export_range(q: &AnalyticsQuery, now_ms: i64) -> (i64, i64) {
    match (&q.window, q.from_ms, q.to_ms) {
        (_, Some(from), to) => (from, to.unwrap_or(now_ms)),
        (Some(w), _, _) => {
            let secs = window_from_str(w).unwrap_or(3600) as i64;
            (now_ms - secs * 1000, now_ms)
        }
        _ => (now_ms - 3_600_000, now_ms),
    }
}

pub fn export_query(
    q: &AnalyticsQuery,
    now_ms: i64,
    kind: ExportKind,
    format: ExportFormat,
) -> Result<ExportQuery, String> {
    let (from, to) = export_range(q, now_ms);
    let mut e = ExportQuery::new(kind)
        .format(format)
        .starting_at(from)
        .ending_at(to);
    if let Some(site) = q.sites.first() {
        e = e.site(site.clone());
    }
    let (lo, hi) = status_bounds(q);
    if let Some(lo) = lo {
        e = e.status_min(lo);
    }
    if let Some(hi) = hi {
        e = e.status_max(hi);
    }
    if let Some(b) = q.bot_classes.first() {
        e = e.bot_class(b.clone());
    }
    if let Some(s) = q.min_bot_score {
        e = e.min_bot_score(s);
    }
    if let Some(h) = &q.host {
        e = e.host(h.clone());
    }
    if let Some(p) = &q.path_prefix {
        e = e.path_prefix(p.clone());
    }
    if let Some(ip) = q.client_ip.as_ref().filter(|ip| !ip.contains('/')) {
        e = e.client_ip(ip.clone());
    }
    if let Some(m) = q.methods.first() {
        e = e.method(m.clone());
    }
    e.validate().map_err(|err| {
        err.to_string()
            .trim_start_matches("invalid node settings: ")
            .to_string()
    })?;
    Ok(e)
}

// One headline number with its change against the previous period.
#[derive(Clone, Debug, PartialEq)]
pub struct Kpi {
    pub label: &'static str,
    pub value: String,
    pub sub: String,
    pub delta: Option<(String, Tone)>,
}

// Text and tone of a change; for numbers where more is worse (errors, latency) a rise is red.
pub fn delta_view(current: f64, previous: f64, up_is_bad: bool) -> (String, Tone) {
    if previous == 0.0 {
        return if current == 0.0 {
            ("no change".into(), Tone::Muted)
        } else {
            ("new, none before".into(), Tone::Muted)
        };
    }
    let pct = (current - previous) / previous;
    if pct.abs() < 0.0005 {
        return ("no change".into(), Tone::Muted);
    }
    let text = format!(
        "{}{} vs before",
        if pct > 0.0 { "+" } else { "-" },
        fmt_pct(pct.abs(), 1)
    );
    let tone = match (pct > 0.0, up_is_bad) {
        (true, true) => Tone::Bad,
        (false, true) => Tone::Ok,
        _ => Tone::Muted,
    };
    (text, tone)
}

pub fn kpis(cur: &Summary, prev: Option<&Summary>) -> Vec<Kpi> {
    let errors = |s: &Summary| (s.errors_4xx + s.errors_5xx) as f64;
    let rate = |s: &Summary| {
        if s.requests == 0 {
            0.0
        } else {
            errors(s) / s.requests as f64
        }
    };
    let d =
        |c: f64, p: fn(&Summary) -> f64, bad: bool| prev.map(|prev| delta_view(c, p(prev), bad));
    vec![
        Kpi {
            label: "Requests",
            value: fmt_num(cur.requests),
            sub: format!("{} total", fmt_int(cur.requests)),
            delta: d(cur.requests as f64, |s| s.requests as f64, false),
        },
        Kpi {
            label: "Bandwidth out",
            value: fmt_bytes(cur.bytes_out),
            sub: format!("{} received", fmt_bytes(cur.bytes_in)),
            delta: d(cur.bytes_out as f64, |s| s.bytes_out as f64, false),
        },
        Kpi {
            label: "Errors",
            value: fmt_num(cur.errors_4xx + cur.errors_5xx),
            sub: format!("{} of requests", fmt_pct(rate(cur), 2)),
            delta: d(errors(cur), errors, true),
        },
        Kpi {
            label: "Blocked",
            value: fmt_num(cur.blocked),
            sub: "stopped by the firewall".into(),
            delta: d(cur.blocked as f64, |s| s.blocked as f64, false),
        },
        Kpi {
            label: "p95 latency",
            value: fmt_ms(cur.p95_ms as f64),
            sub: format!("average {}", fmt_ms(cur.avg_ms)),
            delta: d(cur.p95_ms as f64, |s| s.p95_ms as f64, true),
        },
    ]
}

pub const TOPS_SHOWN: [&str; 6] = ["paths", "hosts", "referers", "agents", "ips", "statuses"];
pub const TOP_ROWS: usize = 8;

// Everything one node answered for the current filter.
pub struct NodeResult {
    pub node: String,
    pub modern: bool,
    pub current: Summary,
    pub previous: Option<Summary>,
    pub partial: bool,
    pub series: Timeseries,
    pub bots: Option<BotSummary>,
    pub tops: Vec<(String, Vec<TopItem>)>,
    pub facets: Option<Facets>,
}

// The page's numbers: one node as it answered, or several merged.
pub struct Data {
    pub summary: Summary,
    pub previous: Option<Summary>,
    pub series: Timeseries,
    pub bots: Option<BotSummary>,
    pub tops: Vec<(String, Vec<TopItem>)>,
    pub facets: Facets,
    pub partial: bool,
    // Nodes that only understood the window and one site.
    pub restricted: Vec<String>,
}

fn merge_values<'a>(lists: impl Iterator<Item = &'a Vec<FacetValue>>) -> Vec<FacetValue> {
    let mut by_key: BTreeMap<String, u64> = BTreeMap::new();
    for v in lists.flatten() {
        *by_key.entry(v.key.clone()).or_default() += v.count;
    }
    let mut out: Vec<FacetValue> = by_key
        .into_iter()
        .map(|(key, count)| FacetValue { key, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out
}

pub fn merge_facets(all: &[Facets]) -> Facets {
    let meta = AnalyticsMeta {
        partial: all.iter().any(|f| f.meta.partial),
        ..AnalyticsMeta::default()
    };
    Facets {
        site: merge_values(all.iter().map(|f| &f.site)),
        host: merge_values(all.iter().map(|f| &f.host)),
        method: merge_values(all.iter().map(|f| &f.method)),
        status_class: merge_values(all.iter().map(|f| &f.status_class)),
        bot_class: merge_values(all.iter().map(|f| &f.bot_class)),
        meta,
    }
}

// The change against the previous period only means something when every node could give one.
pub fn combine(results: Vec<NodeResult>) -> Data {
    let summaries: Vec<Summary> = results.iter().map(|r| r.current.clone()).collect();
    let previous = results
        .iter()
        .map(|r| r.previous.clone())
        .collect::<Option<Vec<Summary>>>()
        .filter(|p| !p.is_empty())
        .map(|p| merge_summaries(&p));
    let series: Vec<Timeseries> = results.iter().map(|r| r.series.clone()).collect();
    let bots: Vec<BotSummary> = results.iter().filter_map(|r| r.bots.clone()).collect();
    let tops = TOPS_SHOWN
        .iter()
        .map(|kind| {
            let lists: Vec<&Vec<TopItem>> = results
                .iter()
                .flat_map(|r| {
                    r.tops
                        .iter()
                        .filter(|(k, _)| k.as_str() == *kind)
                        .map(|(_, v)| v)
                })
                .collect();
            ((*kind).to_string(), merge_top(lists, TOP_ROWS))
        })
        .collect();
    let facets: Vec<Facets> = results.iter().filter_map(|r| r.facets.clone()).collect();
    Data {
        summary: merge_summaries(&summaries),
        previous,
        series: merge_series(&series),
        bots: (!bots.is_empty()).then(|| merge_bot_summaries(&bots)),
        tops,
        facets: merge_facets(&facets),
        partial: results.iter().any(|r| r.partial),
        restricted: results
            .iter()
            .filter(|r| !r.modern)
            .map(|r| r.node.clone())
            .collect(),
    }
}

// New pages join the list newest first, whichever node they came from.
pub fn merge_pages(rows: &mut Vec<(String, LogEvent)>, pages: Vec<(String, Vec<LogEvent>)>) {
    for (node, events) in pages {
        rows.extend(events.into_iter().map(|e| (node.clone(), e)));
    }
    rows.sort_by_key(|(_, e)| std::cmp::Reverse(e.ts_ms));
}

// The text a top-list click puts into the filter: the chip to switch on, or the field to fill.
pub enum Pick {
    Class(String),
    Text(Field, String),
}

pub fn pick_for(kind: &str, key: &str) -> Option<Pick> {
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some(match kind {
        "paths" => Pick::Text(Field::PathExact, key.to_string()),
        "hosts" => Pick::Text(Field::Host, key.to_string()),
        "referers" => Pick::Text(Field::Referer, key.chars().take(64).collect()),
        "agents" => Pick::Text(Field::UserAgent, key.chars().take(64).collect()),
        "ips" => Pick::Text(Field::ClientIp, key.to_string()),
        "content_types" => Pick::Text(Field::ContentType, key.to_string()),
        "statuses" if key.to_ascii_lowercase().ends_with("xx") => Pick::Class(key.to_lowercase()),
        "statuses" => Pick::Text(Field::Status, key.to_string()),
        _ => return None,
    })
}

fn ip_in_network(ip: &str, net: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    let Some((base, len)) = net.split_once('/') else {
        return net.parse::<IpAddr>().is_ok_and(|n| n == addr);
    };
    let (Ok(base), Ok(len)) = (base.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    let bits = |a: IpAddr| match a {
        IpAddr::V4(v) => (u128::from(u32::from(v)), 32u32),
        IpAddr::V6(v) => (u128::from(v), 128u32),
    };
    let ((a, wa), (b, wb)) = (bits(addr), bits(base));
    if wa != wb || len > wa {
        return false;
    }
    let shift = wa - len;
    shift == 128 || (a >> shift) == (b >> shift)
}

fn class_of(status: u16) -> String {
    format!("{}xx", status / 100)
}

// The same filter the node applies, for places that hold events locally (the demo node).
pub fn event_matches(q: &AnalyticsQuery, ev: &LogEvent, now_ms: i64) -> bool {
    let contains = |hay: &str, needle: &Option<String>| {
        needle
            .as_deref()
            .is_none_or(|n| hay.to_lowercase().contains(&n.to_lowercase()))
    };
    let (from, to) = export_range(q, now_ms);
    ev.ts_ms >= from
        && ev.ts_ms <= to
        && (q.sites.is_empty() || q.sites.contains(&ev.site))
        && q.host.as_deref().is_none_or(|h| h == ev.host)
        && q.path_prefix
            .as_deref()
            .is_none_or(|p| ev.path.starts_with(p))
        && q.path_exact.as_deref().is_none_or(|p| ev.path == p)
        && (q.methods.is_empty() || q.methods.iter().any(|m| m.eq_ignore_ascii_case(&ev.method)))
        && q.status.is_none_or(|s| s == ev.status)
        && q.status_min.is_none_or(|s| ev.status >= s)
        && q.status_max.is_none_or(|s| ev.status <= s)
        && (q.status_classes.is_empty() || q.status_classes.contains(&class_of(ev.status)))
        && match &q.blocked {
            None => true,
            Some(BlockedFilter::Blocked) => ev.blocked.is_some(),
            Some(BlockedFilter::Unblocked) => ev.blocked.is_none(),
            Some(BlockedFilter::Rule(id)) => ev.blocked.as_deref() == Some(id.as_str()),
        }
        && (q.bot_classes.is_empty() || q.bot_classes.contains(&ev.bot_class))
        && q.min_bot_score.is_none_or(|s| ev.bot_score >= s)
        && q.max_bot_score.is_none_or(|s| ev.bot_score <= s)
        && q.client_ip
            .as_deref()
            .is_none_or(|n| ip_in_network(&ev.client_ip, n))
        && contains(&ev.user_agent, &q.user_agent)
        && contains(&ev.referer, &q.referer)
        && q.min_duration_ms.is_none_or(|m| ev.total_ms >= m)
        && q.content_type
            .as_deref()
            .is_none_or(|t| ev.content_type.starts_with(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn busy() -> Filter {
        Filter {
            window: "24h".into(),
            sites: vec!["shop".into(), "api".into()],
            methods: vec!["GET".into()],
            status_classes: vec!["5xx".into()],
            bot_classes: vec!["crawler".into()],
            blocked: BlockedMode::Unblocked,
            host: "shop.example.com".into(),
            path_prefix: "/a b&c".into(),
            client_ip: "10.0.0.0/8".into(),
            user_agent: "curl/8, tool".into(),
            min_duration: "250".into(),
            ..Filter::default()
        }
    }

    #[test]
    fn stamps_are_read_as_utc_and_impossible_dates_refused() {
        assert_eq!(parse_stamp("1970-01-02").unwrap(), 86_400_000);
        assert_eq!(parse_stamp("1970-01-01 01:30").unwrap(), 5_400_000);
        assert_eq!(parse_stamp(" 1970-01-01T01:30 ").unwrap(), 5_400_000);
        for bad in [
            "",
            "soon",
            "2026-02-31",
            "2026-13-01",
            "2026-11-05 25:00",
            "2026-11-05 9:00",
            "26-11-05",
        ] {
            assert!(parse_stamp(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_filter_becomes_a_checked_query() {
        let q = busy().query(NOW).expect("valid");
        assert_eq!(q.window.as_deref(), Some("24h"));
        assert_eq!(q.sites, vec!["shop", "api"]);
        assert_eq!(q.min_duration_ms, Some(250));
        assert_eq!(q.blocked, Some(BlockedFilter::Unblocked));
        let pairs = q.to_query().expect("pairs");
        assert!(pairs.contains(&("site".to_string(), "shop,api".to_string())));
        assert!(pairs.contains(&("status_class".to_string(), "5xx".to_string())));
    }

    #[test]
    fn custom_ranges_and_bad_values_report_which_field() {
        let mut f = Filter {
            window: String::new(),
            from: "2026-11-01".into(),
            to: "2026-11-02 06:00".into(),
            ..Filter::default()
        };
        let q = f.query(NOW).expect("valid");
        assert_eq!(q.window, None);
        assert_eq!(q.to_ms.unwrap() - q.from_ms.unwrap(), 30 * 3_600_000);
        f.to.clear();
        let open = f.query(NOW).expect("valid");
        assert_eq!(open.to_ms, Some(NOW));
        f.to = "2026-10-01".into();
        assert!(f.query(NOW).unwrap_err().contains("earlier"));
        f.from = "never".into();
        assert!(f.query(NOW).unwrap_err().starts_with("From:"));
        f.from = "2026-11-01".into();
        f.to = "nope".into();
        assert!(f.query(NOW).unwrap_err().starts_with("To:"));
        let with = |edit: fn(&mut Filter)| {
            let mut g = Filter::default();
            edit(&mut g);
            g.query(NOW)
        };
        assert!(
            with(|g| g.status = "abc".into())
                .unwrap_err()
                .contains("Status")
        );
        assert!(
            with(|g| g.min_duration = "-1".into())
                .unwrap_err()
                .contains("milliseconds")
        );
        assert!(with(|g| g.client_ip = "10.0.0.0/99".into()).is_err());
        assert!(with(|g| g.user_agent = "ab".into()).is_err());
        assert!(with(|g| g.sites = (0..21).map(|i| format!("s{i}")).collect()).is_err());
    }

    #[test]
    fn older_nodes_get_a_window_and_one_site() {
        let r = busy().restricted();
        assert_eq!(r.window, "24h");
        assert_eq!(r.sites, vec!["shop"]);
        assert!(r.methods.is_empty() && r.host.is_empty() && r.status_classes.is_empty());
        let custom = Filter {
            window: String::new(),
            from: "2026-11-01".into(),
            ..Filter::default()
        };
        assert_eq!(custom.restricted().window, DEFAULT_WINDOW);
    }

    #[test]
    fn chips_list_each_narrowing_and_remove_it() {
        let mut f = busy();
        let chips = f.chips();
        let labels: Vec<&str> = chips.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.contains(&"Last 24h") && labels.contains(&"Site api"));
        assert!(labels.contains(&"Status 5xx") && labels.contains(&"Not blocked"));
        assert!(labels.contains(&"Host: shop.example.com"));
        assert!(Filter::default().chips().is_empty());
        for chip in chips {
            f.remove(&chip.key);
        }
        assert_eq!(f, Filter::default());
        let custom = Filter {
            window: String::new(),
            from: "2026-11-01".into(),
            ..Filter::default()
        };
        assert_eq!(custom.chips()[0].label, "2026-11-01 to now");
    }

    #[test]
    fn toggling_adds_and_removes() {
        let a = toggled(&[], "GET");
        assert_eq!(a, vec!["GET"]);
        let b = toggled(&a, "POST");
        assert_eq!(b, vec!["GET", "POST"]);
        assert_eq!(toggled(&b, "GET"), vec!["POST"]);
    }

    #[test]
    fn presets_round_trip_with_awkward_text() {
        let f = busy();
        let text = f.encode();
        assert!(!text.contains(' ') && !text.contains("a b"));
        assert_eq!(Filter::decode(&text).unwrap(), f);
        let custom = Filter {
            window: String::new(),
            from: "2026-11-01 08:00".into(),
            to: "2026-11-02".into(),
            ..Filter::default()
        };
        assert_eq!(Filter::decode(&custom.encode()).unwrap(), custom);
        assert_eq!(Filter::decode("").unwrap(), Filter::default());
        assert_eq!(
            Filter::decode(&Filter::default().encode()).unwrap(),
            Filter::default()
        );
        let unicode = Filter {
            referer: "caf\u{e9} \u{2603}".into(),
            ..Filter::default()
        };
        assert_eq!(Filter::decode(&unicode.encode()).unwrap(), unicode);
    }

    #[test]
    fn bad_presets_are_refused() {
        for bad in [
            "window",
            "window=2h",
            "bogus=1",
            "blocked=maybe",
            "host=%ZZ",
            "host=%4",
            "host=%FF",
        ] {
            assert!(Filter::decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn saved_presets_are_named_replaced_and_capped() {
        let mut list = Vec::new();
        upsert_preset(&mut list, " Errors ", &busy()).unwrap();
        upsert_preset(&mut list, "Errors", &Filter::default()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Errors");
        assert_eq!(Filter::decode(&list[0].query).unwrap(), Filter::default());
        assert!(upsert_preset(&mut list, "  ", &busy()).is_err());
        assert!(upsert_preset(&mut list, &"x".repeat(41), &busy()).is_err());
        for i in 1..MAX_PRESETS {
            upsert_preset(&mut list, &format!("p{i}"), &busy()).unwrap();
        }
        assert!(
            upsert_preset(&mut list, "one too many", &busy())
                .unwrap_err()
                .contains("At most")
        );
        upsert_preset(&mut list, "p1", &Filter::default()).expect("replacing is allowed when full");
    }

    #[test]
    fn export_maps_what_it_can_and_names_what_it_cannot() {
        let q = busy().query(NOW).unwrap();
        let gaps = export_gaps(&q);
        assert!(gaps.contains(&"more than one site") && gaps.contains(&"blocked"));
        assert!(gaps.contains(&"user agent") && gaps.contains(&"slower than"));
        let e = export_query(&q, NOW, ExportKind::Requests, ExportFormat::Csv).unwrap();
        let pairs: Vec<(String, String)> = e
            .pairs()
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|p| p.1.clone());
        assert_eq!(get("site").as_deref(), Some("shop"));
        assert_eq!(get("status_min").as_deref(), Some("500"));
        assert_eq!(get("status_max").as_deref(), Some("599"));
        assert_eq!(get("to").unwrap(), NOW.to_string());
        assert_eq!(get("from").unwrap(), (NOW - 86_400_000).to_string());
        assert!(export_gaps(&Filter::default().query(NOW).unwrap()).is_empty());
        let exact = Filter {
            status: "404".into(),
            ..Filter::default()
        }
        .query(NOW)
        .unwrap();
        let e = export_query(&exact, NOW, ExportKind::Hourly, ExportFormat::Ndjson).unwrap();
        let p = e.pairs().unwrap();
        assert!(
            p.contains(&("status_min", "404".to_string()))
                && p.contains(&("status_max", "404".to_string()))
        );
    }

    #[test]
    fn changes_are_signed_and_coloured_by_what_is_good() {
        assert_eq!(
            delta_view(110.0, 100.0, false),
            ("+10.0% vs before".into(), Tone::Muted)
        );
        assert_eq!(delta_view(110.0, 100.0, true).1, Tone::Bad);
        assert_eq!(
            delta_view(50.0, 100.0, true),
            ("-50.0% vs before".into(), Tone::Ok)
        );
        assert_eq!(delta_view(100.0, 100.0, true).0, "no change");
        assert_eq!(delta_view(0.0, 0.0, true).0, "no change");
        assert_eq!(delta_view(5.0, 0.0, true).0, "new, none before");
    }

    #[test]
    fn kpis_carry_deltas_only_when_a_previous_period_exists() {
        let cur = Summary {
            requests: 2000,
            errors_4xx: 30,
            errors_5xx: 10,
            p95_ms: 200,
            ..Summary::default()
        };
        let prev = Summary {
            requests: 1000,
            errors_4xx: 10,
            errors_5xx: 10,
            p95_ms: 100,
            ..Summary::default()
        };
        let with = kpis(&cur, Some(&prev));
        assert_eq!(with.len(), 5);
        assert_eq!(with[0].delta.as_ref().unwrap().0, "+100.0% vs before");
        assert_eq!(with[2].value, "40");
        assert_eq!(with[2].delta.as_ref().unwrap().1, Tone::Bad);
        assert_eq!(with[2].sub, "2.00% of requests");
        assert!(kpis(&cur, None).iter().all(|k| k.delta.is_none()));
    }

    fn result(node: &str, modern: bool, requests: u64, with_previous: bool) -> NodeResult {
        let item = |k: &str, n: u64| TopItem {
            key: k.into(),
            count: n,
            bytes: 0,
        };
        NodeResult {
            node: node.into(),
            modern,
            current: Summary {
                requests,
                ..Summary::default()
            },
            previous: with_previous.then(|| Summary {
                requests: requests / 2,
                ..Summary::default()
            }),
            partial: node == "b",
            series: Timeseries::default(),
            bots: None,
            tops: vec![("paths".into(), vec![item("/", requests), item(node, 1)])],
            facets: Some(Facets {
                site: vec![FacetValue {
                    key: "shop".into(),
                    count: requests,
                }],
                ..Facets::default()
            }),
        }
    }

    #[test]
    fn nodes_are_merged_into_one_picture() {
        let d = combine(vec![
            result("a", true, 100, true),
            result("b", true, 50, true),
        ]);
        assert_eq!(d.summary.requests, 150);
        assert_eq!(d.previous.as_ref().map(|p| p.requests), Some(75));
        assert!(d.partial);
        assert!(d.restricted.is_empty());
        assert_eq!(d.facets.site[0].count, 150);
        assert!(d.bots.is_none());
        assert_eq!(d.tops.len(), TOPS_SHOWN.len());
        let paths = &d.tops[0];
        assert_eq!(paths.0, "paths");
        assert_eq!(paths.1[0].key, "/");
        assert_eq!(paths.1[0].count, 150);
    }

    #[test]
    fn a_missing_previous_period_or_old_node_is_reported_not_guessed() {
        let d = combine(vec![
            result("a", true, 100, true),
            result("old", false, 50, false),
        ]);
        assert!(d.previous.is_none());
        assert_eq!(d.restricted, vec!["old"]);
        assert!(combine(Vec::new()).previous.is_none());
    }

    #[test]
    fn facets_add_up_by_key() {
        let f = |k: &str, n: u64| Facets {
            method: vec![FacetValue {
                key: k.into(),
                count: n,
            }],
            ..Facets::default()
        };
        let m = merge_facets(&[f("GET", 5), f("POST", 9), f("GET", 6)]);
        assert_eq!(
            m.method[0],
            FacetValue {
                key: "GET".into(),
                count: 11
            }
        );
        assert_eq!(m.method[1].key, "POST");
        assert!(merge_facets(&[]).site.is_empty());
    }

    #[test]
    fn pages_merge_newest_first() {
        let at = |ts: i64| LogEvent {
            ts_ms: ts,
            ..LogEvent::default()
        };
        let mut rows = vec![("a".to_string(), at(50))];
        merge_pages(
            &mut rows,
            vec![
                ("b".into(), vec![at(90), at(10)]),
                ("a".into(), vec![at(70)]),
            ],
        );
        let order: Vec<i64> = rows.iter().map(|(_, e)| e.ts_ms).collect();
        assert_eq!(order, vec![90, 70, 50, 10]);
        assert_eq!(rows[0].0, "b");
    }

    #[test]
    fn a_click_on_a_top_list_becomes_a_filter() {
        assert!(
            matches!(pick_for("paths", "/x"), Some(Pick::Text(Field::PathExact, p)) if p == "/x")
        );
        assert!(matches!(
            pick_for("hosts", "a.com"),
            Some(Pick::Text(Field::Host, _))
        ));
        assert!(matches!(
            pick_for("statuses", "404"),
            Some(Pick::Text(Field::Status, _))
        ));
        assert!(matches!(pick_for("statuses", "5XX"), Some(Pick::Class(c)) if c == "5xx"));
        assert!(matches!(
            pick_for("ips", "1.2.3.4"),
            Some(Pick::Text(Field::ClientIp, _))
        ));
        let long = "u".repeat(200);
        match pick_for("agents", &long) {
            Some(Pick::Text(Field::UserAgent, v)) => assert_eq!(v.len(), 64),
            _ => panic!("agents fill the user agent"),
        }
        assert!(pick_for("languages", "en").is_none());
        assert!(pick_for("paths", "  ").is_none());
    }

    fn event() -> LogEvent {
        LogEvent {
            ts_ms: NOW - 60_000,
            client_ip: "10.1.2.3".into(),
            host: "shop.example.com".into(),
            method: "GET".into(),
            path: "/api/items".into(),
            status: 502,
            total_ms: 300,
            user_agent: "curl/8.1".into(),
            referer: "https://x.test/".into(),
            content_type: "application/json".into(),
            site: "shop".into(),
            blocked: Some("r1".into()),
            bot_score: 70,
            bot_class: "tool".into(),
            ..LogEvent::default()
        }
    }

    #[test]
    fn events_are_matched_the_way_the_node_filters() {
        let ev = event();
        let q = |f: Filter| f.query(NOW).unwrap();
        assert!(event_matches(&q(Filter::default()), &ev, NOW));
        let hit = |edit: fn(&mut Filter)| {
            let mut f = Filter::default();
            edit(&mut f);
            event_matches(&q(f), &ev, NOW)
        };
        assert!(hit(|f| f.sites = vec!["shop".into()]));
        assert!(!hit(|f| f.sites = vec!["blog".into()]));
        assert!(hit(|f| f.methods = vec!["GET".into()]));
        assert!(!hit(|f| f.methods = vec!["POST".into()]));
        assert!(hit(|f| f.status_classes = vec!["5xx".into()]));
        assert!(!hit(|f| f.status_classes = vec!["2xx".into()]));
        assert!(hit(|f| f.status = "502".into()));
        assert!(hit(|f| f.client_ip = "10.0.0.0/8".into()));
        assert!(!hit(|f| f.client_ip = "192.168.0.0/16".into()));
        assert!(hit(|f| f.client_ip = "10.1.2.3".into()));
        assert!(hit(|f| f.user_agent = "CURL".into()));
        assert!(!hit(|f| f.user_agent = "firefox".into()));
        assert!(hit(|f| f.blocked = BlockedMode::Blocked));
        assert!(!hit(|f| f.blocked = BlockedMode::Unblocked));
        assert!(hit(|f| f.bot_classes = vec!["tool".into()]));
        assert!(hit(|f| f.min_duration = "300".into()));
        assert!(!hit(|f| f.min_duration = "301".into()));
        assert!(hit(|f| f.content_type = "application/".into()));
        assert!(hit(|f| f.path_prefix = "/api".into()));
        assert!(!hit(|f| f.path_exact = "/api".into()));
        assert!(hit(|f| f.host = "shop.example.com".into()));
        let old = LogEvent {
            ts_ms: NOW - 3 * 3_600_000,
            ..event()
        };
        assert!(!event_matches(&q(Filter::default()), &old, NOW));
        assert!(!ip_in_network("::1", "10.0.0.0/8"));
        assert!(ip_in_network("2001:db8::5", "2001:db8::/32"));
    }
}
