use std::collections::HashMap;
use std::net::IpAddr;

use cite_edge::analytics::window_from_str;
use cite_edge::validate::is_valid_id;
use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;
use serde::{Serialize, Serializer};

use crate::error::{Error, Result};
use crate::limits::DAY_MS;

/// Most sites one query may name.
pub const MAX_FILTER_SITES: usize = 20;
/// Longest time range a query may cover, in days.
pub const MAX_SPAN_DAYS: i64 = 400;
/// Most events one page of the request list holds.
pub const MAX_PAGE: usize = 1000;
/// Most rows a page may skip with offset; deeper pages use the cursor.
pub const MAX_OFFSET: usize = 100_000;
/// Window used when a query names no time range at all.
pub const DEFAULT_WINDOW_SECS: u64 = 3600;

const MAX_SPAN_MS: i64 = MAX_SPAN_DAYS * DAY_MS;
// Largest instant a year-9999 timestamp can name, so offsets and arithmetic stay far from overflow.
const MAX_TIME_MS: i64 = 253_402_300_799_999;
const MAX_HOST: usize = 255;
const MAX_PATH: usize = 2048;
const MAX_PATH_CONTAINS: usize = 256;
const MAX_METHOD: usize = 16;
const TEXT_MIN: usize = 3;
const TEXT_MAX: usize = 64;
const CTYPE_MIN: usize = 2;
const BOT_CLASSES: [&str; 5] = ["human", "suspect", "crawler", "tool", "bot"];
const STATUS_CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];
const SCALARS: [&str; 17] = [
    "window",
    "from",
    "to",
    "host",
    "path_prefix",
    "path_exact",
    "status",
    "status_min",
    "status_max",
    "blocked",
    "min_bot_score",
    "max_bot_score",
    "client_ip",
    "user_agent",
    "referer",
    "min_duration_ms",
    "content_type",
];
const LISTS: [&str; 4] = ["site", "method", "status_class", "bot_class"];
// The request list also takes its two original names: path is a substring match and ip an exact address.
const LEGACY_SCALARS: [&str; 2] = ["path", "ip"];

fn bad(msg: impl Into<String>) -> Error {
    Error::Rejected(msg.into())
}

/// Which blocked requests a filter keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    /// Requests a firewall rule blocked.
    Any,
    /// Requests no rule blocked.
    Unblocked,
    /// Requests blocked by one rule id.
    Rule(String),
}

impl Blocked {
    fn label(&self) -> String {
        match self {
            Blocked::Any => "true".to_string(),
            Blocked::Unblocked => "unblocked".to_string(),
            Blocked::Rule(id) => format!("rule:{id}"),
        }
    }
}

impl Serialize for Blocked {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.label())
    }
}

/// One filter shared by summary, timeseries, bots, top, requests, facets and compare. Every field is optional and the set fields are ANDed; list fields match any of their values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AnalyticsFilter {
    /// One of 15m, 1h, 24h, 7d, 30d; exclusive with from_ms and to_ms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ms: Option<i64>,
    #[serde(rename = "site", skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_exact: Option<String>,
    /// Substring of the path; only the request list takes it, as `path`.
    #[serde(rename = "path", skip_serializing_if = "Option::is_none")]
    pub path_contains: Option<String>,
    /// Upper-case method tokens.
    #[serde(rename = "method", skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_min: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_max: Option<u16>,
    /// Classes such as "2xx" or "5xx".
    #[serde(rename = "status_class", skip_serializing_if = "Vec::is_empty")]
    pub status_classes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<Blocked>,
    #[serde(rename = "bot_class", skip_serializing_if = "Vec::is_empty")]
    pub bot_classes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_bot_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bot_score: Option<u8>,
    /// A normalised address, or a network such as "10.0.0.0/8".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Case-insensitive substring of the user agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Case-insensitive substring of the referer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_duration_ms: Option<u32>,
    /// Case-insensitive prefix of the response content type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Names of the query parameters a call takes besides the filter, so the parser can skip them.
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOpts<'a> {
    pub extras: &'a [&'a str],
    /// Also accept `path` (substring) and `ip` (exact address), the request list's original names.
    pub requests: bool,
}

/// The time range a filter names, relative to now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Span {
    Window(u64),
    Range { from: i64, to: i64 },
}

/// A client address match: one address or a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpMatch {
    Exact(IpAddr),
    Net(IpAddr, u8),
}

impl IpMatch {
    pub(crate) fn parse(raw: &str) -> Option<IpMatch> {
        match raw.split_once('/') {
            None => raw.parse::<IpAddr>().ok().map(IpMatch::Exact),
            Some((addr, len)) => {
                let ip: IpAddr = addr.parse().ok()?;
                if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let len: u8 = len.parse().ok()?;
                let max = if ip.is_ipv4() { 32 } else { 128 };
                (len <= max).then(|| IpMatch::Net(mask(ip, len), len))
            }
        }
    }

    pub(crate) fn label(&self) -> String {
        match self {
            IpMatch::Exact(ip) => ip.to_string(),
            IpMatch::Net(ip, len) => format!("{ip}/{len}"),
        }
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match *self {
            IpMatch::Exact(want) => want == ip,
            IpMatch::Net(net, len) => ip.is_ipv4() == net.is_ipv4() && mask(ip, len) == net,
        }
    }
}

// Keeps the first len bits of an address and clears the rest.
fn mask(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let keep = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len))
            };
            IpAddr::V4((bits & keep).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let keep = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len))
            };
            IpAddr::V6((bits & keep).into())
        }
    }
}

/// Registers cite_in_cidr(address, cidr) on a reader so a network filter can run inside SQL over the dictionary.
pub(crate) fn register_functions(conn: &Connection) -> rusqlite::Result<()> {
    conn.create_scalar_function(
        "cite_in_cidr",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let addr: String = ctx.get(0)?;
            let net: String = ctx.get(1)?;
            let hit = match (addr.parse::<IpAddr>(), IpMatch::parse(&net)) {
                (Ok(ip), Some(m)) => m.contains(ip),
                _ => false,
            };
            Ok(hit)
        },
    )
}

/// Escapes LIKE wildcards so user text matches literally under ESCAPE '\'.
pub(crate) fn like_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    for c in raw.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn shown(raw: &str) -> String {
    raw.chars()
        .take(48)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn split_list(raw: &str) -> impl Iterator<Item = String> + '_ {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn parse_num<T: std::str::FromStr>(key: &str, raw: &str, what: &str) -> Result<T> {
    raw.parse::<T>()
        .map_err(|_| bad(format!("{key} must be {what}")))
}

fn civil_days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// RFC 3339 date-time with a mandatory offset; fractions beyond milliseconds are dropped.
fn parse_rfc3339(raw: &str) -> Option<i64> {
    let b = raw.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let digits = |s: usize, e: usize| -> Option<i64> {
        let t = raw.get(s..e)?;
        if t.bytes().all(|c| c.is_ascii_digit()) {
            t.parse().ok()
        } else {
            None
        }
    };
    let (y, mo, d) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    let (h, mi, s) = (digits(11, 13)?, digits(14, 16)?, digits(17, 19)?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let mut at = 19;
    let mut frac_ms = 0;
    if b[at] == b'.' {
        at += 1;
        let start = at;
        while at < b.len() && b[at].is_ascii_digit() {
            at += 1;
        }
        if at == start {
            return None;
        }
        for (k, c) in b[start..at].iter().take(3).enumerate() {
            frac_ms += i64::from(c - b'0') * [100, 10, 1][k];
        }
    }
    let rest = raw.get(at..)?;
    let offset_min = if rest == "Z" || rest == "z" {
        0
    } else {
        let rb = rest.as_bytes();
        let sign = match rb.first()? {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        if rb.len() != 6 || rb[3] != b':' {
            return None;
        }
        let (oh, om) = (
            rest.get(1..3)?.parse::<i64>().ok()?,
            rest.get(4..6)?.parse::<i64>().ok()?,
        );
        if !rb[1..3].iter().chain(&rb[4..6]).all(u8::is_ascii_digit) || oh > 23 || om > 59 {
            return None;
        }
        sign * (oh * 60 + om)
    };
    let secs = civil_days(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - offset_min * 60;
    Some(secs * 1000 + frac_ms)
}

// Milliseconds since the epoch, or an RFC 3339 timestamp.
pub(crate) fn parse_time(key: &str, raw: &str) -> Result<i64> {
    let invalid = || {
        bad(format!(
            "{key} must be milliseconds since the epoch or an RFC 3339 timestamp"
        ))
    };
    let ms = if raw.bytes().all(|b| b.is_ascii_digit()) {
        raw.parse::<i64>().map_err(|_| invalid())?
    } else {
        // an unescaped "+" offset reaches the server as a space
        parse_rfc3339(&raw.replace(' ', "+")).ok_or_else(invalid)?
    };
    if (0..=MAX_TIME_MS).contains(&ms) {
        Ok(ms)
    } else {
        Err(invalid())
    }
}

fn parse_blocked(raw: &str) -> Result<Option<Blocked>> {
    Ok(match raw {
        "" | "false" | "0" => None,
        "true" | "1" => Some(Blocked::Any),
        "unblocked" => Some(Blocked::Unblocked),
        _ => match raw.strip_prefix("rule:") {
            Some(id) => Some(Blocked::Rule(id.to_string())),
            None => return Err(bad("blocked must be true, false, unblocked or rule:<id>")),
        },
    })
}

impl AnalyticsFilter {
    /// Reads a query string already split into pairs (repeats kept in order). Parameters named in opts.extras are skipped; any other unknown name is rejected.
    pub fn parse(pairs: &[(String, String)], opts: ParseOpts<'_>) -> Result<Self> {
        let mut scalars: HashMap<&'static str, &str> = HashMap::new();
        let mut lists: HashMap<&'static str, Vec<String>> = HashMap::new();
        for (key, value) in pairs {
            let key = key.as_str();
            if opts.extras.contains(&key) {
                continue;
            }
            if let Some(name) = LISTS.iter().copied().find(|n| *n == key) {
                lists.entry(name).or_default().extend(split_list(value));
                continue;
            }
            let name = SCALARS
                .iter()
                .chain(LEGACY_SCALARS.iter().filter(|_| opts.requests))
                .copied()
                .find(|n| *n == key);
            let Some(name) = name else {
                return Err(bad(format!("unknown parameter {}", shown(key))));
            };
            if scalars.insert(name, value.as_str()).is_some() {
                return Err(bad(format!("{name} must be given once")));
            }
        }
        let text = |name: &str| {
            scalars
                .get(name)
                .copied()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let mut f = AnalyticsFilter {
            window: scalars.get("window").map(|s| (*s).to_string()),
            ..AnalyticsFilter::default()
        };
        f.from_ms = text("from").map(|v| parse_time("from", &v)).transpose()?;
        f.to_ms = text("to").map(|v| parse_time("to", &v)).transpose()?;
        f.sites = dedup(lists.remove("site").unwrap_or_default());
        f.host = text("host");
        f.path_prefix = text("path_prefix");
        f.path_exact = text("path_exact");
        f.path_contains = text("path");
        f.methods = dedup(
            lists
                .remove("method")
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.to_ascii_uppercase())
                .collect(),
        );
        // an empty status was always a 400 on the request list
        f.status = scalars
            .get("status")
            .map(|v| parse_num::<u16>("status", v, "an HTTP status code"))
            .transpose()?;
        f.status_min = text("status_min")
            .map(|v| parse_num::<u16>("status_min", &v, "an HTTP status code"))
            .transpose()?;
        f.status_max = text("status_max")
            .map(|v| parse_num::<u16>("status_max", &v, "an HTTP status code"))
            .transpose()?;
        f.status_classes = dedup(
            lists
                .remove("status_class")
                .unwrap_or_default()
                .into_iter()
                .map(|c| c.to_ascii_lowercase())
                .collect(),
        );
        if let Some(v) = scalars.get("blocked") {
            f.blocked = parse_blocked(v)?;
        }
        f.bot_classes = dedup(
            lists
                .remove("bot_class")
                .unwrap_or_default()
                .into_iter()
                .map(|c| c.to_ascii_lowercase())
                .collect(),
        );
        f.min_bot_score = text("min_bot_score")
            .map(|v| parse_num::<u8>("min_bot_score", &v, "a score from 0 to 100"))
            .transpose()?;
        f.max_bot_score = text("max_bot_score")
            .map(|v| parse_num::<u8>("max_bot_score", &v, "a score from 0 to 100"))
            .transpose()?;
        let ip = text("ip");
        f.client_ip = text("client_ip").map(|raw| match IpMatch::parse(&raw) {
            Some(m) => m.label(),
            None => raw,
        });
        if let Some(ip) = ip {
            if f.client_ip.is_some() {
                return Err(bad("ip and client_ip are the same filter; give one"));
            }
            let parsed: IpAddr = ip.parse().map_err(|_| bad("ip must be an IP address"))?;
            f.client_ip = Some(parsed.to_string());
        }
        f.user_agent = text("user_agent");
        f.referer = text("referer");
        f.min_duration_ms = text("min_duration_ms")
            .map(|v| parse_num::<u32>("min_duration_ms", &v, "a number of milliseconds"))
            .transpose()?;
        f.content_type = text("content_type");
        f.validate()?;
        Ok(f)
    }

    /// Checks every field and normalises client_ip to its canonical text. Parsing calls it; code that builds a filter by hand must too (the query functions do).
    pub fn validate(&self) -> Result<()> {
        if let Some(w) = &self.window {
            if window_from_str(w).is_none() {
                return Err(bad("window must be one of 15m, 1h, 24h, 7d, 30d"));
            }
            if self.from_ms.is_some() || self.to_ms.is_some() {
                return Err(bad(
                    "window cannot be combined with from or to; give a window or a range",
                ));
            }
        }
        for (key, v) in [("from", self.from_ms), ("to", self.to_ms)] {
            if v.is_some_and(|v| !(0..=MAX_TIME_MS).contains(&v)) {
                return Err(bad(format!("{key} is out of range")));
            }
        }
        if self.to_ms.is_some() && self.from_ms.is_none() {
            return Err(bad("from is required when to is given"));
        }
        if let (Some(from), Some(to)) = (self.from_ms, self.to_ms) {
            if from >= to {
                return Err(bad("from must be earlier than to"));
            }
            if to - from > MAX_SPAN_MS {
                return Err(bad(format!(
                    "the range between from and to must not be longer than {MAX_SPAN_DAYS} days"
                )));
            }
        }
        if self.sites.len() > MAX_FILTER_SITES {
            return Err(bad(format!("site takes at most {MAX_FILTER_SITES} sites")));
        }
        if self.sites.iter().any(|s| !is_valid_id(s)) {
            return Err(bad("site must be a valid site id"));
        }
        let plain = |key: &str, v: &Option<String>, max: usize| -> Result<()> {
            match v {
                Some(v) if v.is_empty() || v.len() > max || has_control(v) => Err(bad(format!(
                    "{key} must be 1 to {max} bytes without control characters"
                ))),
                _ => Ok(()),
            }
        };
        plain("host", &self.host, MAX_HOST)?;
        plain("path_prefix", &self.path_prefix, MAX_PATH)?;
        plain("path_exact", &self.path_exact, MAX_PATH)?;
        plain("path", &self.path_contains, MAX_PATH_CONTAINS)?;
        for m in &self.methods {
            let ok = !m.is_empty()
                && m.len() <= MAX_METHOD
                && m.bytes().all(|b| b.is_ascii_uppercase() || b == b'-');
            if !ok {
                return Err(bad("method must be an HTTP method token"));
            }
        }
        for (key, v) in [
            ("status", self.status),
            ("status_min", self.status_min),
            ("status_max", self.status_max),
        ] {
            if v.is_some_and(|v| !(100..=599).contains(&v)) {
                return Err(bad(format!("{key} must be an HTTP status code")));
            }
        }
        if let (Some(min), Some(max)) = (self.status_min, self.status_max)
            && min > max
        {
            return Err(bad("status_min must not be greater than status_max"));
        }
        if let Some(c) = self
            .status_classes
            .iter()
            .find(|c| !STATUS_CLASSES.contains(&c.as_str()))
        {
            return Err(bad(format!(
                "status_class must be one of 1xx, 2xx, 3xx, 4xx, 5xx, not {}",
                shown(c)
            )));
        }
        if let Some(Blocked::Rule(id)) = &self.blocked
            && !is_valid_id(id)
        {
            return Err(bad("blocked rule id is not a valid id"));
        }
        if self
            .bot_classes
            .iter()
            .any(|c| !BOT_CLASSES.contains(&c.as_str()))
        {
            return Err(bad(
                "bot_class must be one of human, suspect, crawler, tool, bot",
            ));
        }
        for (key, v) in [
            ("min_bot_score", self.min_bot_score),
            ("max_bot_score", self.max_bot_score),
        ] {
            if v.is_some_and(|v| v > 100) {
                return Err(bad(format!("{key} must be a score from 0 to 100")));
            }
        }
        if let (Some(min), Some(max)) = (self.min_bot_score, self.max_bot_score)
            && min > max
        {
            return Err(bad("min_bot_score must not be greater than max_bot_score"));
        }
        if let Some(ip) = &self.client_ip
            && IpMatch::parse(ip).is_none()
        {
            return Err(bad(
                "client_ip must be an IP address or a network such as 10.0.0.0/8",
            ));
        }
        for (key, v, min) in [
            ("user_agent", &self.user_agent, TEXT_MIN),
            ("referer", &self.referer, TEXT_MIN),
            ("content_type", &self.content_type, CTYPE_MIN),
        ] {
            if let Some(v) = v {
                let n = v.chars().count();
                if n < min || n > TEXT_MAX || has_control(v) {
                    return Err(bad(format!(
                        "{key} must be {min} to {TEXT_MAX} characters without control characters"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The client address match in its normalised form.
    pub(crate) fn ip_match(&self) -> Option<IpMatch> {
        self.client_ip.as_deref().and_then(IpMatch::parse)
    }

    /// The time range as given, None when the filter names none.
    pub(crate) fn bounded_span(&self, now_ms: i64) -> Result<Option<Span>> {
        self.validate()?;
        if let Some(w) = &self.window {
            return Ok(window_from_str(w).map(Span::Window));
        }
        let Some(from) = self.from_ms else {
            return Ok(None);
        };
        let to = self.to_ms.unwrap_or(now_ms);
        if from >= to {
            return Err(bad("from must be earlier than to"));
        }
        if to - from > MAX_SPAN_MS {
            return Err(bad(format!(
                "the range between from and to must not be longer than {MAX_SPAN_DAYS} days"
            )));
        }
        Ok(Some(Span::Range { from, to }))
    }

    pub(crate) fn span(&self, now_ms: i64) -> Result<Span> {
        Ok(self
            .bounded_span(now_ms)?
            .unwrap_or(Span::Window(DEFAULT_WINDOW_SECS)))
    }

    /// The filter without its time range.
    fn without_time(&self) -> AnalyticsFilter {
        AnalyticsFilter {
            window: None,
            from_ms: None,
            to_ms: None,
            ..self.clone()
        }
    }

    /// True when anything besides the time range is set.
    pub(crate) fn has_row_conditions(&self) -> bool {
        self.without_time() != AnalyticsFilter::default()
    }

    /// True when the rollup tables can answer: a time range and at most one site, nothing else.
    pub(crate) fn rollup_only(&self) -> bool {
        let mut rest = self.without_time();
        if rest.sites.len() > 1 {
            return false;
        }
        rest.sites.clear();
        rest == AnalyticsFilter::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn parse(items: &[(&str, &str)]) -> Result<AnalyticsFilter> {
        AnalyticsFilter::parse(&pairs(items), ParseOpts::default())
    }

    fn rejected(items: &[(&str, &str)]) -> String {
        match parse(items) {
            Err(Error::Rejected(msg)) => msg,
            other => panic!("{items:?} was not rejected: {other:?}"),
        }
    }

    #[test]
    fn an_empty_query_is_the_default_filter() {
        assert_eq!(parse(&[]).unwrap(), AnalyticsFilter::default());
        let f = parse(&[("site", ""), ("host", ""), ("blocked", ""), ("from", "")]).unwrap();
        assert_eq!(f, AnalyticsFilter::default());
    }

    #[test]
    fn every_parameter_is_parsed_and_echoed() {
        let f = parse(&[
            ("from", "1000"),
            ("to", "2000"),
            ("site", "blog,shop"),
            ("site", "docs"),
            ("host", "a.example.com"),
            ("path_prefix", "/api"),
            ("path_exact", "/api/v1"),
            ("method", "get,Post"),
            ("status_min", "400"),
            ("status_max", "499"),
            ("status_class", "5XX,2xx"),
            ("blocked", "rule:rate-limit"),
            ("bot_class", "Crawler"),
            ("min_bot_score", "10"),
            ("max_bot_score", "90"),
            ("client_ip", "10.1.2.3/8"),
            ("user_agent", "curl"),
            ("referer", "example"),
            ("min_duration_ms", "250"),
            ("content_type", "text/"),
        ])
        .unwrap();
        assert_eq!(f.sites, ["blog", "shop", "docs"]);
        assert_eq!(f.methods, ["GET", "POST"]);
        assert_eq!(f.status_classes, ["5xx", "2xx"]);
        assert_eq!(f.bot_classes, ["crawler"]);
        assert_eq!(f.client_ip.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(f.blocked, Some(Blocked::Rule("rate-limit".into())));
        let echo = serde_json::to_value(&f).unwrap();
        assert_eq!(echo["site"], serde_json::json!(["blog", "shop", "docs"]));
        assert_eq!(echo["blocked"], "rule:rate-limit");
        assert_eq!(echo["from_ms"], 1000);
        assert_eq!(echo["client_ip"], "10.0.0.0/8");
        assert!(echo.get("window").is_none() && echo.get("path").is_none());
    }

    #[test]
    fn unknown_parameters_are_named() {
        let msg = rejected(&[("window", "1h"), ("colour", "red")]);
        assert!(msg.contains("colour"), "{msg}");
        // country is not recorded, so it is not a filter
        assert!(rejected(&[("country", "DE")]).contains("country"));
        // the request list's original names are not general filters
        assert!(rejected(&[("ip", "10.0.0.1")]).contains("ip"));
        assert!(rejected(&[("path", "/x")]).contains("path"));
        let hostile = "a\u{0}\u{1b}[31m".repeat(40);
        let msg = rejected(&[(hostile.as_str(), "1")]);
        assert!(
            !msg.chars().any(char::is_control) && msg.len() < 100,
            "{msg}"
        );
    }

    #[test]
    fn extras_are_skipped_and_request_names_are_accepted_on_request() {
        let opts = ParseOpts {
            extras: &["limit", "kind"],
            requests: true,
        };
        let f = AnalyticsFilter::parse(
            &pairs(&[
                ("limit", "5"),
                ("kind", "paths"),
                ("ip", "2001:0db8::1"),
                ("path", "/x"),
                ("status", "404"),
            ]),
            opts,
        )
        .unwrap();
        assert_eq!(f.client_ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(f.path_contains.as_deref(), Some("/x"));
        assert_eq!(f.status, Some(404));
        let both = AnalyticsFilter::parse(
            &pairs(&[("ip", "10.0.0.1"), ("client_ip", "10.0.0.1")]),
            opts,
        );
        assert!(matches!(both, Err(Error::Rejected(_))));
        let net = AnalyticsFilter::parse(&pairs(&[("ip", "10.0.0.0/8")]), opts);
        assert!(matches!(net, Err(Error::Rejected(_))));
    }

    #[test]
    fn window_and_range_are_exclusive_and_validated() {
        assert_eq!(
            parse(&[("window", "24h")]).unwrap().window.as_deref(),
            Some("24h")
        );
        for window in ["", "2w", "1H", "1h "] {
            assert!(
                rejected(&[("window", window)]).contains("window"),
                "{window:?}"
            );
        }
        assert!(rejected(&[("window", "1h"), ("from", "1000")]).contains("window"));
        assert!(rejected(&[("window", "1h"), ("to", "1000")]).contains("window"));
        assert!(rejected(&[("to", "1000")]).contains("from"));
        assert!(rejected(&[("from", "2000"), ("to", "1000")]).contains("earlier"));
        assert!(rejected(&[("from", "1000"), ("to", "1000")]).contains("earlier"));
        // 400 days exactly passes, one millisecond more does not
        let day = DAY_MS;
        let (edge, over) = ((400 * day).to_string(), (400 * day + 1).to_string());
        assert!(parse(&[("from", "0"), ("to", edge.as_str())]).is_ok());
        assert!(rejected(&[("from", "0"), ("to", over.as_str())]).contains("400"));
        for bad_time in [
            "yesterday",
            "-5",
            "99999999999999999999",
            "2023-11-14",
            "1e3",
            "0x10",
        ] {
            assert!(
                rejected(&[("from", bad_time)]).contains("from"),
                "{bad_time}"
            );
        }
        assert!(rejected(&[("from", "253402300800000")]).contains("from"));
    }

    #[test]
    fn open_ended_ranges_are_checked_against_now() {
        let f = parse(&[("from", "1000")]).unwrap();
        assert_eq!(
            f.span(5000).unwrap(),
            Span::Range {
                from: 1000,
                to: 5000
            }
        );
        assert!(matches!(f.span(1000), Err(Error::Rejected(_))));
        assert!(matches!(
            f.span(1000 + 401 * DAY_MS),
            Err(Error::Rejected(_))
        ));
        assert_eq!(
            parse(&[]).unwrap().span(5).unwrap(),
            Span::Window(DEFAULT_WINDOW_SECS)
        );
        assert_eq!(parse(&[]).unwrap().bounded_span(5).unwrap(), None);
    }

    #[test]
    fn times_accept_milliseconds_and_rfc3339() {
        assert_eq!(
            parse_time("from", "1700000000123").unwrap(),
            1_700_000_000_123
        );
        assert_eq!(
            parse_time("from", "2023-11-14T22:13:20Z").unwrap(),
            1_700_000_000_000
        );
        assert_eq!(
            parse_time("from", "2023-11-14t22:13:20z").unwrap(),
            1_700_000_000_000
        );
        assert_eq!(
            parse_time("from", "2023-11-14T22:13:20.5Z").unwrap(),
            1_700_000_000_500
        );
        assert_eq!(
            parse_time("from", "2023-11-14T22:13:20.123456789Z").unwrap(),
            1_700_000_000_123
        );
        assert_eq!(
            parse_time("from", "2023-11-14T23:13:20+01:00").unwrap(),
            1_700_000_000_000
        );
        assert_eq!(
            parse_time("from", "2023-11-14T17:13:20-05:00").unwrap(),
            1_700_000_000_000
        );
        // the same offset with its plus sign decoded to a space
        assert_eq!(
            parse_time("from", "2023-11-14T23:13:20 01:00").unwrap(),
            1_700_000_000_000
        );
        assert_eq!(
            parse_time("from", "2000-02-29T00:00:00Z").unwrap(),
            951_782_400_000
        );
        for raw in [
            "2023-11-14",
            "2023-11-14T22:13:20",
            "2023-02-29T00:00:00Z",
            "2023-13-01T00:00:00Z",
            "2023-11-14T24:00:00Z",
            "2023-11-14T22:60:00Z",
            "2023-11-14T22:13:60Z",
            "2023-11-14T22:13:20+0100",
            "2023-11-14T22:13:20+24:00",
            "2023-11-14T22:13:20.Z",
            "2023-11-14T22:13:20Zjunk",
            "1969-12-31T23:59:59Z",
            "20\u{e9}3-11-14T22:13:20Z",
        ] {
            assert!(parse_time("from", raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn site_lists_are_deduplicated_validated_and_capped() {
        let many: Vec<String> = (0..20).map(|i| format!("s{i}")).collect();
        let joined = many.join(",");
        assert_eq!(parse(&[("site", joined.as_str())]).unwrap().sites.len(), 20);
        let too_many = format!("{joined},extra");
        assert!(rejected(&[("site", too_many.as_str())]).contains("20"));
        assert_eq!(parse(&[("site", "a,a, a ,,b")]).unwrap().sites, ["a", "b"]);
        for site in ["Bad Site", "a;b", "a'b", "../x", "x\u{0}y", "UPPER"] {
            assert!(rejected(&[("site", site)]).contains("site"), "{site:?}");
        }
    }

    #[test]
    fn scalar_values_are_checked() {
        for (items, name) in [
            (&[("status", "abc")][..], "status"),
            (&[("status", "")], "status"),
            (&[("status", "99")], "status"),
            (&[("status", "600")], "status"),
            (
                &[("status_min", "500"), ("status_max", "400")],
                "status_min",
            ),
            (&[("status_class", "6xx")], "status_class"),
            (&[("status_class", "2xx,xx")], "status_class"),
            (&[("blocked", "maybe")], "blocked"),
            (&[("blocked", "rule:Bad Id")], "blocked"),
            (&[("bot_class", "robot")], "bot_class"),
            (&[("min_bot_score", "101")], "min_bot_score"),
            (&[("min_bot_score", "-1")], "min_bot_score"),
            (&[("max_bot_score", "x")], "max_bot_score"),
            (
                &[("min_bot_score", "60"), ("max_bot_score", "20")],
                "min_bot_score",
            ),
            (&[("client_ip", "nope")], "client_ip"),
            (&[("client_ip", "10.0.0.0/33")], "client_ip"),
            (&[("client_ip", "10.0.0.0/")], "client_ip"),
            (&[("client_ip", "10.0.0.0/-1")], "client_ip"),
            (&[("client_ip", "::/129")], "client_ip"),
            (&[("client_ip", "10.0.0.1/8/8")], "client_ip"),
            (&[("method", "GE T")], "method"),
            (&[("method", "GET;DROP")], "method"),
            (&[("host", "a\nb")], "host"),
            (&[("path_prefix", "/a\u{7}")], "path_prefix"),
            (&[("path_exact", "x\u{0}")], "path_exact"),
            (&[("min_duration_ms", "-1")], "min_duration_ms"),
            (&[("min_duration_ms", "4294967296")], "min_duration_ms"),
            (&[("user_agent", "ab")], "user_agent"),
            (&[("referer", "x")], "referer"),
            (&[("content_type", "t")], "content_type"),
            (&[("host", "a"), ("host", "b")], "host"),
        ] {
            assert!(rejected(items).contains(name), "{items:?}");
        }
        let long = "x".repeat(65);
        assert!(rejected(&[("user_agent", long.as_str())]).contains("user_agent"));
        let (host, path, agent) = ("h".repeat(256), "p".repeat(2049), "x".repeat(64));
        assert!(rejected(&[("host", host.as_str())]).contains("host"));
        assert!(rejected(&[("path_prefix", path.as_str())]).contains("path_prefix"));
        assert!(parse(&[("user_agent", agent.as_str())]).is_ok());
        // characters are counted, not bytes
        assert!(parse(&[("user_agent", "\u{e9}\u{e9}\u{e9}")]).is_ok());
        assert!(parse(&[("client_ip", "::/0"), ("blocked", "unblocked")]).is_ok());
    }

    #[test]
    fn blocked_forms() {
        assert_eq!(
            parse(&[("blocked", "true")]).unwrap().blocked,
            Some(Blocked::Any)
        );
        assert_eq!(
            parse(&[("blocked", "1")]).unwrap().blocked,
            Some(Blocked::Any)
        );
        assert_eq!(parse(&[("blocked", "false")]).unwrap().blocked, None);
        assert_eq!(parse(&[("blocked", "0")]).unwrap().blocked, None);
        assert_eq!(
            parse(&[("blocked", "unblocked")]).unwrap().blocked,
            Some(Blocked::Unblocked)
        );
    }

    #[test]
    fn like_wildcards_are_escaped() {
        assert_eq!(like_escape("plain"), "plain");
        assert_eq!(like_escape("100%_sure\\"), "100\\%\\_sure\\\\");
        assert_eq!(like_escape("%"), "\\%");
    }

    #[test]
    fn networks_are_masked_and_matched_by_family() {
        let net = IpMatch::parse("192.168.5.77/16").unwrap();
        assert_eq!(net.label(), "192.168.0.0/16");
        assert!(net.contains("192.168.200.1".parse().unwrap()));
        assert!(!net.contains("192.169.0.1".parse().unwrap()));
        assert!(!net.contains("::ffff:192.168.0.1".parse().unwrap()));
        let all = IpMatch::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()) && !all.contains("::1".parse().unwrap()));
        let v6 = IpMatch::parse("2001:db8:ffff::1/32").unwrap();
        assert_eq!(v6.label(), "2001:db8::/32");
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        let host = IpMatch::parse("10.0.0.1/32").unwrap();
        assert!(
            host.contains("10.0.0.1".parse().unwrap())
                && !host.contains("10.0.0.2".parse().unwrap())
        );
        assert_eq!(
            IpMatch::parse("10.0.0.1").unwrap(),
            IpMatch::Exact("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn row_conditions_and_rollup_eligibility() {
        let base = parse(&[("window", "24h"), ("site", "a")]).unwrap();
        assert!(base.rollup_only() && base.has_row_conditions());
        assert!(
            parse(&[("from", "0"), ("to", "3600000")])
                .unwrap()
                .rollup_only()
        );
        assert!(!parse(&[("site", "a,b")]).unwrap().rollup_only());
        assert!(!parse(&[("host", "x")]).unwrap().rollup_only());
        assert!(!parse(&[("status", "200")]).unwrap().rollup_only());
        assert!(!parse(&[("blocked", "true")]).unwrap().rollup_only());
        assert!(parse(&[("blocked", "false")]).unwrap().rollup_only());
        assert!(!parse(&[]).unwrap().has_row_conditions());
        assert!(parse(&[("site", "a")]).unwrap().has_row_conditions());
    }
}
