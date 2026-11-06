use std::net::IpAddr;

use cite_edge::analytics::{Summary, Timeseries, TopItem, window_from_str};
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;
use cite_edge::validate::is_valid_id;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ClientError;

type Res<T> = std::result::Result<T, ClientError>;

pub const MAX_QUERY_SITES: usize = 20;
pub const MAX_QUERY_SPAN_DAYS: i64 = 400;
pub const MAX_ANALYTICS_PAGE: usize = 1000;

const DAY_MS: i64 = 86_400_000;
const MAX_TIME_MS: i64 = 253_402_300_799_999;
const MAX_HOST: usize = 255;
const MAX_PATH: usize = 2048;
const MAX_METHOD: usize = 16;
const TEXT_MAX: usize = 64;
const TEXT_MIN: usize = 3;
const CTYPE_MIN: usize = 2;
const BOT_CLASSES: [&str; 5] = ["human", "suspect", "crawler", "tool", "bot"];
const STATUS_CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

/// Which blocked requests a query keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockedFilter {
    /// Blocked by any rule.
    Blocked,
    /// Not blocked by any rule.
    Unblocked,
    /// Blocked by one rule id.
    Rule(String),
}

/// Order of a top list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TopSort {
    #[default]
    Count,
    Bytes,
}

impl TopSort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Bytes => "bytes",
        }
    }
}

/// The filter every analytics read shares. Set fields are ANDed; list fields match any value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyticsQuery {
    /// One of 15m, 1h, 24h, 7d, 30d; exclusive with from_ms and to_ms. The node defaults to 1h.
    pub window: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub sites: Vec<String>,
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub path_exact: Option<String>,
    pub methods: Vec<String>,
    pub status: Option<u16>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub status_classes: Vec<String>,
    pub blocked: Option<BlockedFilter>,
    pub bot_classes: Vec<String>,
    pub min_bot_score: Option<u8>,
    pub max_bot_score: Option<u8>,
    /// An address or a network such as 10.0.0.0/8.
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub min_duration_ms: Option<u32>,
    pub content_type: Option<String>,
}

impl AnalyticsQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn window(mut self, window: impl Into<String>) -> Self {
        self.window = Some(window.into());
        self
    }

    pub fn range(mut self, from_ms: i64, to_ms: i64) -> Self {
        self.from_ms = Some(from_ms);
        self.to_ms = Some(to_ms);
        self
    }

    /// An open-ended range that runs to now.
    pub fn since(mut self, from_ms: i64) -> Self {
        self.from_ms = Some(from_ms);
        self.to_ms = None;
        self
    }

    pub fn site(mut self, site: impl Into<String>) -> Self {
        self.sites.push(site.into());
        self
    }

    pub fn sites<I, S>(mut self, sites: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.sites.extend(sites.into_iter().map(Into::into));
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = Some(prefix.into());
        self
    }

    pub fn path_exact(mut self, path: impl Into<String>) -> Self {
        self.path_exact = Some(path.into());
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.methods.push(method.into());
        self
    }

    pub fn status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    pub fn status_range(mut self, min: u16, max: u16) -> Self {
        self.status_min = Some(min);
        self.status_max = Some(max);
        self
    }

    pub fn status_class(mut self, class: impl Into<String>) -> Self {
        self.status_classes.push(class.into());
        self
    }

    pub fn blocked(mut self, blocked: BlockedFilter) -> Self {
        self.blocked = Some(blocked);
        self
    }

    pub fn bot_class(mut self, class: impl Into<String>) -> Self {
        self.bot_classes.push(class.into());
        self
    }

    pub fn min_bot_score(mut self, score: u8) -> Self {
        self.min_bot_score = Some(score);
        self
    }

    pub fn max_bot_score(mut self, score: u8) -> Self {
        self.max_bot_score = Some(score);
        self
    }

    pub fn client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    pub fn user_agent(mut self, text: impl Into<String>) -> Self {
        self.user_agent = Some(text.into());
        self
    }

    pub fn referer(mut self, text: impl Into<String>) -> Self {
        self.referer = Some(text.into());
        self
    }

    pub fn min_duration_ms(mut self, ms: u32) -> Self {
        self.min_duration_ms = Some(ms);
        self
    }

    pub fn content_type(mut self, text: impl Into<String>) -> Self {
        self.content_type = Some(text.into());
        self
    }

    /// Checks the query the way the node does and returns its parameters in a fixed order. Values are never joined into a URL; the HTTP layer encodes them.
    pub fn to_query(&self) -> Res<Vec<(String, String)>> {
        Ok(self
            .pairs()?
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect())
    }

    pub fn validate(&self) -> Res<()> {
        self.pairs().map(|_| ())
    }

    pub(crate) fn pairs(&self) -> Res<Vec<(&'static str, String)>> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        if let Some(w) = &self.window {
            if window_from_str(w).is_none() {
                return Err(invalid("window must be one of 15m, 1h, 24h, 7d, 30d"));
            }
            if self.from_ms.is_some() || self.to_ms.is_some() {
                return Err(invalid("give a window or a from and to range, not both"));
            }
            out.push(("window", w.clone()));
        }
        for (key, v) in [("from", self.from_ms), ("to", self.to_ms)] {
            if let Some(v) = v {
                if !(0..=MAX_TIME_MS).contains(&v) {
                    return Err(invalid(format!("{key} is out of range")));
                }
                out.push((key, v.to_string()));
            }
        }
        if self.to_ms.is_some() && self.from_ms.is_none() {
            return Err(invalid("from is required when to is given"));
        }
        if let (Some(from), Some(to)) = (self.from_ms, self.to_ms) {
            if from >= to {
                return Err(invalid("from must be earlier than to"));
            }
            if to - from > MAX_QUERY_SPAN_DAYS * DAY_MS {
                return Err(invalid(format!(
                    "the range must not be longer than {MAX_QUERY_SPAN_DAYS} days"
                )));
            }
        }
        let sites = dedup(self.sites.iter().map(|s| s.trim().to_string()));
        if sites.len() > MAX_QUERY_SITES {
            return Err(invalid(format!(
                "at most {MAX_QUERY_SITES} sites can be named"
            )));
        }
        if sites.iter().any(|s| !is_valid_id(s)) {
            return Err(invalid("site must be a valid site id"));
        }
        if !sites.is_empty() {
            out.push(("site", sites.join(",")));
        }
        for (key, v, max) in [
            ("host", &self.host, MAX_HOST),
            ("path_prefix", &self.path_prefix, MAX_PATH),
            ("path_exact", &self.path_exact, MAX_PATH),
        ] {
            if let Some(v) = v {
                if v.is_empty() || v.len() > max || v.chars().any(char::is_control) {
                    return Err(invalid(format!(
                        "{key} must be 1 to {max} bytes without control characters"
                    )));
                }
                out.push((key, v.clone()));
            }
        }
        let methods = dedup(self.methods.iter().map(|m| m.trim().to_ascii_uppercase()));
        for m in &methods {
            let ok = !m.is_empty()
                && m.len() <= MAX_METHOD
                && m.bytes().all(|b| b.is_ascii_uppercase() || b == b'-');
            if !ok {
                return Err(invalid("method must be an HTTP method token"));
            }
        }
        if !methods.is_empty() {
            out.push(("method", methods.join(",")));
        }
        for (key, v) in [
            ("status", self.status),
            ("status_min", self.status_min),
            ("status_max", self.status_max),
        ] {
            if let Some(v) = v {
                if !(100..=599).contains(&v) {
                    return Err(invalid(format!("{key} must be an HTTP status code")));
                }
                out.push((key, v.to_string()));
            }
        }
        if let (Some(min), Some(max)) = (self.status_min, self.status_max)
            && min > max
        {
            return Err(invalid("status_min must not be greater than status_max"));
        }
        let classes = dedup(
            self.status_classes
                .iter()
                .map(|c| c.trim().to_ascii_lowercase()),
        );
        if classes
            .iter()
            .any(|c| !STATUS_CLASSES.contains(&c.as_str()))
        {
            return Err(invalid(
                "status_class must be one of 1xx, 2xx, 3xx, 4xx, 5xx",
            ));
        }
        if !classes.is_empty() {
            out.push(("status_class", classes.join(",")));
        }
        match &self.blocked {
            None => {}
            Some(BlockedFilter::Blocked) => out.push(("blocked", "true".to_string())),
            Some(BlockedFilter::Unblocked) => out.push(("blocked", "unblocked".to_string())),
            Some(BlockedFilter::Rule(id)) => {
                if !is_valid_id(id) {
                    return Err(invalid("blocked rule id is not a valid id"));
                }
                out.push(("blocked", format!("rule:{id}")));
            }
        }
        let bots = dedup(
            self.bot_classes
                .iter()
                .map(|c| c.trim().to_ascii_lowercase()),
        );
        if bots.iter().any(|c| !BOT_CLASSES.contains(&c.as_str())) {
            return Err(invalid(
                "bot_class must be one of human, suspect, crawler, tool, bot",
            ));
        }
        if !bots.is_empty() {
            out.push(("bot_class", bots.join(",")));
        }
        for (key, v) in [
            ("min_bot_score", self.min_bot_score),
            ("max_bot_score", self.max_bot_score),
        ] {
            if let Some(v) = v {
                if v > 100 {
                    return Err(invalid(format!("{key} must be a score from 0 to 100")));
                }
                out.push((key, v.to_string()));
            }
        }
        if let (Some(min), Some(max)) = (self.min_bot_score, self.max_bot_score)
            && min > max
        {
            return Err(invalid(
                "min_bot_score must not be greater than max_bot_score",
            ));
        }
        if let Some(ip) = &self.client_ip {
            let ip = ip.trim();
            if !valid_client_ip(ip) {
                return Err(invalid(
                    "client_ip must be an IP address or a network such as 10.0.0.0/8",
                ));
            }
            out.push(("client_ip", ip.to_string()));
        }
        for (key, v, min) in [
            ("user_agent", &self.user_agent, TEXT_MIN),
            ("referer", &self.referer, TEXT_MIN),
        ] {
            if let Some(v) = v {
                out.push((key, bounded_text(key, v, min)?));
            }
        }
        if let Some(ms) = self.min_duration_ms {
            out.push(("min_duration_ms", ms.to_string()));
        }
        if let Some(v) = &self.content_type {
            out.push(("content_type", bounded_text("content_type", v, CTYPE_MIN)?));
        }
        Ok(out)
    }
}

fn dedup(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items.filter(|s| !s.is_empty()) {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn bounded_text(key: &str, value: &str, min: usize) -> Res<String> {
    let n = value.chars().count();
    if n < min || n > TEXT_MAX || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{key} must be {min} to {TEXT_MAX} characters without control characters"
        )));
    }
    Ok(value.to_string())
}

fn valid_client_ip(raw: &str) -> bool {
    match raw.split_once('/') {
        None => raw.parse::<IpAddr>().is_ok(),
        Some((addr, len)) => {
            let Ok(ip) = addr.parse::<IpAddr>() else {
                return false;
            };
            let max = if ip.is_ipv4() { 32 } else { 128 };
            !len.is_empty()
                && len.bytes().all(|b| b.is_ascii_digit())
                && len.parse::<u8>().is_ok_and(|l| l <= max)
        }
    }
}

/// What the node says it applied; every field is absent on a node that predates filtering.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AnalyticsMeta {
    /// The node's own reading of the filter, kept as JSON because its shape may grow.
    #[serde(default)]
    pub filters: Option<Value>,
    /// True when only the newest part of the range was read.
    #[serde(default)]
    pub partial: bool,
    #[serde(default)]
    pub scanned: Option<u64>,
    #[serde(default)]
    pub from_ms: Option<i64>,
    #[serde(default)]
    pub to_ms: Option<i64>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SummaryReport {
    #[serde(flatten)]
    pub summary: Summary,
    #[serde(flatten)]
    pub meta: AnalyticsMeta,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TimeseriesReport {
    #[serde(flatten)]
    pub series: Timeseries,
    #[serde(flatten)]
    pub meta: AnalyticsMeta,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BotReport {
    #[serde(flatten)]
    pub bots: BotSummary,
    #[serde(flatten)]
    pub meta: AnalyticsMeta,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TopReport {
    #[serde(default)]
    pub items: Vec<TopItem>,
    #[serde(flatten)]
    pub meta: AnalyticsMeta,
}

/// Where the next page of the request list starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestCursor {
    pub before_ts: i64,
    pub before_id: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestsPage {
    #[serde(default)]
    pub items: Vec<LogEvent>,
    /// None on the last page.
    #[serde(default)]
    pub next_cursor: Option<RequestCursor>,
    #[serde(flatten)]
    pub meta: AnalyticsMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacetValue {
    pub key: String,
    #[serde(default)]
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Facets {
    #[serde(default)]
    pub site: Vec<FacetValue>,
    #[serde(default)]
    pub host: Vec<FacetValue>,
    #[serde(default)]
    pub method: Vec<FacetValue>,
    #[serde(default)]
    pub status_class: Vec<FacetValue>,
    #[serde(default)]
    pub bot_class: Vec<FacetValue>,
    #[serde(flatten)]
    pub meta: AnalyticsMeta,
}

/// One headline number against the range before it; pct is absent when the earlier value was 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct DeltaValue {
    #[serde(default)]
    pub current: f64,
    #[serde(default)]
    pub previous: f64,
    #[serde(default)]
    pub abs: f64,
    #[serde(default)]
    pub pct: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CompareDelta {
    #[serde(default)]
    pub requests: DeltaValue,
    #[serde(default)]
    pub bytes_in: DeltaValue,
    #[serde(default)]
    pub bytes_out: DeltaValue,
    #[serde(default)]
    pub blocked: DeltaValue,
    #[serde(default)]
    pub errors_4xx: DeltaValue,
    #[serde(default)]
    pub errors_5xx: DeltaValue,
    #[serde(default)]
    pub avg_ms: DeltaValue,
    #[serde(default)]
    pub p50_ms: DeltaValue,
    #[serde(default)]
    pub p95_ms: DeltaValue,
    #[serde(default)]
    pub p99_ms: DeltaValue,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Compare {
    #[serde(default)]
    pub against: String,
    #[serde(default)]
    pub current: SummaryReport,
    #[serde(default)]
    pub previous: SummaryReport,
    #[serde(default)]
    pub delta: CompareDelta,
}

pub(crate) fn page_pairs(
    limit: Option<usize>,
    cursor: Option<&RequestCursor>,
) -> Res<Vec<(&'static str, String)>> {
    let mut out = vec![("envelope", "true".to_string())];
    out.extend(limit_pair(limit)?);
    if let Some(c) = cursor {
        out.push(("before_ts", c.before_ts.to_string()));
        out.push(("before_id", c.before_id.to_string()));
    }
    Ok(out)
}

pub(crate) fn limit_pair(limit: Option<usize>) -> Res<Option<(&'static str, String)>> {
    match limit {
        None => Ok(None),
        Some(n) if (1..=MAX_ANALYTICS_PAGE).contains(&n) => Ok(Some(("limit", n.to_string()))),
        Some(_) => Err(invalid(format!("limit must be 1 to {MAX_ANALYTICS_PAGE}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pairs(q: &AnalyticsQuery) -> Vec<(String, String)> {
        q.to_query().expect("valid query")
    }

    fn kv(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn query_building_table() {
        let cases: Vec<(AnalyticsQuery, Vec<(&str, &str)>)> = vec![
            (AnalyticsQuery::new(), vec![]),
            (
                AnalyticsQuery::new().window("24h").site("blog"),
                vec![("window", "24h"), ("site", "blog")],
            ),
            (
                AnalyticsQuery::new()
                    .range(1000, 2000)
                    .sites(["a", "b", "a"]),
                vec![("from", "1000"), ("to", "2000"), ("site", "a,b")],
            ),
            (AnalyticsQuery::new().since(5), vec![("from", "5")]),
            (
                AnalyticsQuery::new()
                    .method("get")
                    .method("Post")
                    .status_class("5XX")
                    .bot_class("Crawler")
                    .blocked(BlockedFilter::Rule("r1".into())),
                vec![
                    ("method", "GET,POST"),
                    ("status_class", "5xx"),
                    ("blocked", "rule:r1"),
                    ("bot_class", "crawler"),
                ],
            ),
            (
                AnalyticsQuery::new()
                    .host("example.com")
                    .path_prefix("/a b&c=d")
                    .path_exact("/x?y#z")
                    .status_range(400, 499)
                    .min_bot_score(10)
                    .max_bot_score(90)
                    .client_ip("10.0.0.0/8")
                    .user_agent("curl/8 & co")
                    .referer("https://x.test/?q=1")
                    .min_duration_ms(250)
                    .content_type("text/"),
                vec![
                    ("host", "example.com"),
                    ("path_prefix", "/a b&c=d"),
                    ("path_exact", "/x?y#z"),
                    ("status_min", "400"),
                    ("status_max", "499"),
                    ("min_bot_score", "10"),
                    ("max_bot_score", "90"),
                    ("client_ip", "10.0.0.0/8"),
                    ("user_agent", "curl/8 & co"),
                    ("referer", "https://x.test/?q=1"),
                    ("min_duration_ms", "250"),
                    ("content_type", "text/"),
                ],
            ),
            (
                AnalyticsQuery::new()
                    .status(404)
                    .blocked(BlockedFilter::Unblocked),
                vec![("status", "404"), ("blocked", "unblocked")],
            ),
            (
                AnalyticsQuery::new().client_ip(" 2001:db8::/32 "),
                vec![("client_ip", "2001:db8::/32")],
            ),
        ];
        for (query, want) in cases {
            assert_eq!(pairs(&query), kv(&want), "{query:?}");
        }
    }

    #[test]
    fn invalid_queries_are_refused_before_sending() {
        let many: Vec<String> = (0..21).map(|i| format!("s{i}")).collect();
        let day = DAY_MS;
        let bad: Vec<AnalyticsQuery> = vec![
            AnalyticsQuery::new().window("2h"),
            AnalyticsQuery::new().window("1h").range(1, 2),
            AnalyticsQuery::new().window("1h").since(1),
            AnalyticsQuery {
                to_ms: Some(10),
                ..AnalyticsQuery::new()
            },
            AnalyticsQuery::new().range(10, 10),
            AnalyticsQuery::new().range(10, 5),
            AnalyticsQuery::new().range(-1, 5),
            AnalyticsQuery::new().range(0, 400 * day + 1),
            AnalyticsQuery::new().sites(many),
            AnalyticsQuery::new().site("Bad Site"),
            AnalyticsQuery::new().host(""),
            AnalyticsQuery::new().host("a".repeat(256)),
            AnalyticsQuery::new().path_prefix("a".repeat(2049)),
            AnalyticsQuery::new().path_exact("/a\nb"),
            AnalyticsQuery::new().method("GE T"),
            AnalyticsQuery::new().method("a".repeat(17)),
            AnalyticsQuery::new().status(99),
            AnalyticsQuery::new().status(600),
            AnalyticsQuery::new().status_range(500, 400),
            AnalyticsQuery::new().status_class("6xx"),
            AnalyticsQuery::new().blocked(BlockedFilter::Rule("../x".into())),
            AnalyticsQuery::new().bot_class("robot"),
            AnalyticsQuery::new().min_bot_score(101),
            AnalyticsQuery::new().min_bot_score(60).max_bot_score(40),
            AnalyticsQuery::new().client_ip("10.0.0.0/33"),
            AnalyticsQuery::new().client_ip("10.0.0.0/"),
            AnalyticsQuery::new().client_ip("not-an-ip"),
            AnalyticsQuery::new().user_agent("ab"),
            AnalyticsQuery::new().user_agent("a".repeat(65)),
            AnalyticsQuery::new().referer("ab"),
            AnalyticsQuery::new().referer("tab\there"),
            AnalyticsQuery::new().content_type("t"),
        ];
        for q in bad {
            assert!(matches!(q.to_query(), Err(ClientError::Config(_))), "{q:?}");
        }
    }

    #[test]
    fn boundary_values_are_accepted() {
        let day = DAY_MS;
        let ok = [
            AnalyticsQuery::new().range(0, 400 * day),
            AnalyticsQuery::new().sites((0..20).map(|i| format!("s{i}"))),
            AnalyticsQuery::new().user_agent("abc"),
            AnalyticsQuery::new().user_agent("a".repeat(64)),
            AnalyticsQuery::new().content_type("te"),
            AnalyticsQuery::new().host("a".repeat(255)),
            AnalyticsQuery::new().path_prefix("a".repeat(2048)),
            AnalyticsQuery::new().status_range(100, 599),
            AnalyticsQuery::new().client_ip("::1"),
            AnalyticsQuery::new().client_ip("192.0.2.1"),
        ];
        for q in ok {
            assert!(q.validate().is_ok(), "{q:?}");
        }
    }

    #[test]
    fn page_and_limit_pairs() {
        assert_eq!(
            page_pairs(
                Some(50),
                Some(&RequestCursor {
                    before_ts: 9,
                    before_id: 3
                })
            )
            .expect("ok"),
            vec![
                ("envelope", "true".to_string()),
                ("limit", "50".to_string()),
                ("before_ts", "9".to_string()),
                ("before_id", "3".to_string()),
            ]
        );
        assert_eq!(
            page_pairs(None, None).expect("ok"),
            vec![("envelope", "true".to_string())]
        );
        assert!(page_pairs(Some(0), None).is_err());
        assert!(page_pairs(Some(1001), None).is_err());
        assert!(limit_pair(Some(1000)).is_ok());
    }

    #[test]
    fn old_summary_shape_still_parses_with_empty_meta() {
        let old = serde_json::to_value(Summary::default()).expect("json");
        let report: SummaryReport = serde_json::from_value(old).expect("old shape");
        assert_eq!(report.summary, Summary::default());
        assert_eq!(report.meta, AnalyticsMeta::default());
    }

    #[test]
    fn new_shapes_parse_and_unknown_fields_are_ignored() {
        let mut v = serde_json::to_value(Summary::default()).expect("json");
        let obj = v.as_object_mut().expect("object");
        obj.insert("filters".into(), json!({ "site": ["blog"] }));
        obj.insert("partial".into(), json!(true));
        obj.insert("scanned".into(), json!(5_000_000));
        obj.insert("from_ms".into(), json!(10));
        obj.insert("to_ms".into(), json!(20));
        obj.insert("source".into(), json!("raw"));
        obj.insert("future_field".into(), json!([1, 2]));
        let report: SummaryReport = serde_json::from_value(v).expect("new shape");
        assert!(report.meta.partial);
        assert_eq!(report.meta.scanned, Some(5_000_000));
        assert_eq!(
            (report.meta.from_ms, report.meta.to_ms),
            (Some(10), Some(20))
        );
        assert_eq!(report.meta.source.as_deref(), Some("raw"));
        assert_eq!(report.meta.filters, Some(json!({ "site": ["blog"] })));

        let series: TimeseriesReport = serde_json::from_value(json!({
            "step_secs": 60,
            "points": [{ "ts": 1, "requests": 2, "bytes_out": 3, "errors": 0, "blocked": 0, "avg_ms": 1.5 }],
            "partial": false, "source": "minute"
        }))
        .expect("series");
        assert_eq!(series.series.points.len(), 1);
        assert_eq!(series.meta.source.as_deref(), Some("minute"));

        let top: TopReport = serde_json::from_value(json!({
            "items": [{ "key": "/", "count": 4, "bytes": 8 }], "partial": true
        }))
        .expect("top");
        assert_eq!(top.items[0].count, 4);
        assert!(top.meta.partial);
        let bare: TopReport = serde_json::from_value(json!({})).expect("empty top");
        assert!(bare.items.is_empty());
    }

    #[test]
    fn request_pages_parse_with_and_without_a_cursor() {
        let mut event = serde_json::to_value(LogEvent::default()).expect("json");
        event["path"] = json!("/a");
        let page: RequestsPage = serde_json::from_value(json!({
            "items": [event],
            "next_cursor": { "before_ts": 7, "before_id": 41 },
            "partial": true, "scanned": 100, "filters": {}, "from_ms": 1
        }))
        .expect("page");
        assert_eq!(page.items[0].path, "/a");
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.next_cursor,
            Some(RequestCursor {
                before_ts: 7,
                before_id: 41
            })
        );
        assert!(page.meta.partial);
        let last: RequestsPage =
            serde_json::from_value(json!({ "items": [], "next_cursor": null })).expect("last");
        assert_eq!(last.next_cursor, None);
    }

    #[test]
    fn facets_and_compare_parse() {
        let facets: Facets = serde_json::from_value(json!({
            "site": [{ "key": "blog", "count": 9 }],
            "status_class": [{ "key": "2xx", "count": 8 }, { "key": "5xx", "count": 1 }],
            "partial": false
        }))
        .expect("facets");
        assert_eq!(facets.site[0].key, "blog");
        assert_eq!(facets.status_class.len(), 2);
        assert!(facets.host.is_empty() && facets.bot_class.is_empty());

        let mut cur = serde_json::to_value(Summary::default()).expect("json");
        cur["requests"] = json!(10);
        cur["from_ms"] = json!(100);
        let mut prev = serde_json::to_value(Summary::default()).expect("json");
        prev["requests"] = json!(5);
        let compare: Compare = serde_json::from_value(json!({
            "against": "previous",
            "current": cur,
            "previous": prev,
            "delta": {
                "requests": { "current": 10, "previous": 5, "abs": 5, "pct": 100.0 },
                "blocked": { "current": 1, "previous": 0, "abs": 1 }
            }
        }))
        .expect("compare");
        assert_eq!(compare.against, "previous");
        assert_eq!(compare.current.summary.requests, 10);
        assert_eq!(compare.current.meta.from_ms, Some(100));
        assert_eq!(compare.previous.summary.requests, 5);
        assert_eq!(compare.delta.requests.pct, Some(100.0));
        assert_eq!(compare.delta.blocked.pct, None);
        assert_eq!(compare.delta.p99_ms, DeltaValue::default());
    }
}
