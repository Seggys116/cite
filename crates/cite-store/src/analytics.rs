use std::collections::BTreeMap;

use cite_edge::analytics::{Point, Summary, Timeseries, TopItem};
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;
use rusqlite::types::Value;
use rusqlite::{Connection, params, params_from_iter};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::filter::{AnalyticsFilter, Blocked, IpMatch, MAX_OFFSET, MAX_PAGE, Span, like_escape};
use crate::limits::{DAY_MS, HOUR_MS, MAX_TOP_LIMIT, MINUTE_MS, TOP_N};
use crate::queries::{self, FOLD_FETCH, SortBy, Source, TopKind, Where, Window};
use crate::schema::{dim, kind};
use crate::util::{ascii_upper, from_i64, to_i64};

/// Raw rows one filtered query examines, newest first, before it answers from what it has and says so.
pub const SCAN_CAP: usize = 5_000_000;
const FACET_N: usize = 50;
// Longest span the minute rollups serve, matching the six hours of ROLLUP_MIN_WINDOW_SECS.
const MINUTE_SPAN_MS: i64 = 6 * HOUR_MS;
// Timeseries steps a filtered query picks from; the first one that keeps a chart within MAX_POINTS wins.
const STEPS_MS: [i64; 6] = [
    MINUTE_MS,
    5 * MINUTE_MS,
    15 * MINUTE_MS,
    HOUR_MS,
    6 * HOUR_MS,
    DAY_MS,
];
const MAX_POINTS: i64 = 360;

const SITES_IN: &str = "site_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val IN (SELECT value FROM json_each(?)))";
const HOST_EQ: &str = "host_id = (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val = ?)";
const METHOD_EQ: &str =
    "method_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val = ? COLLATE NOCASE)";
const METHODS_IN: &str = "method_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND upper(s.val) IN (SELECT value FROM json_each(?)))";
const BLOCKED_EQ: &str = "blocked_id = (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val = ?)";
const BOT_CLASS_EQ: &str =
    "bot_class_id = (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val = ?)";
const BOT_CLASS_IN: &str = "bot_class_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val IN (SELECT value FROM json_each(?)))";
const IP_IN_NET: &str =
    "client_ip_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND cite_in_cidr(s.val, ?))";
const UA_LIKE: &str =
    "ua_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val LIKE ? ESCAPE '\\')";
const REFERER_LIKE: &str =
    "referer_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val LIKE ? ESCAPE '\\')";
const CTYPE_LIKE: &str =
    "ctype_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val LIKE ? ESCAPE '\\')";
// One OR group per status class, so a status index can still serve a single class.
const CLASS_FRAGS: [&str; 5] = [
    "(status >= ? AND status < ?)",
    "((status >= ? AND status < ?) OR (status >= ? AND status < ?))",
    "((status >= ? AND status < ?) OR (status >= ? AND status < ?) OR (status >= ? AND status < ?))",
    "((status >= ? AND status < ?) OR (status >= ? AND status < ?) OR (status >= ? AND status < ?) OR (status >= ? AND status < ?))",
    "((status >= ? AND status < ?) OR (status >= ? AND status < ?) OR (status >= ? AND status < ?) OR (status >= ? AND status < ?) OR (status >= ? AND status < ?))",
];

/// What every filtered answer carries besides its data.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Answer<T> {
    #[serde(flatten)]
    pub data: T,
    /// The filter as applied.
    pub filters: AnalyticsFilter,
    /// True when the query hit the scan cap and covers only the newest part of the range.
    pub partial: bool,
    /// Raw rows examined; absent when rollups answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned: Option<u64>,
    /// The range actually used, [from_ms, to_ms).
    pub from_ms: i64,
    pub to_ms: i64,
    /// `rollup_minute`, `rollup_hour` or `raw`.
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TopList {
    pub items: Vec<TopItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FacetValue {
    pub key: String,
    pub count: u64,
}

/// Distinct values and counts under a filter, for pickers; each list holds at most 50 values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Facets {
    pub site: Vec<FacetValue>,
    pub host: Vec<FacetValue>,
    pub method: Vec<FacetValue>,
    pub status_class: Vec<FacetValue>,
    pub bot_class: Vec<FacetValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeltaValue {
    pub current: f64,
    pub previous: f64,
    pub abs: f64,
    /// Change in percent of the previous value; absent when that was zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pct: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Compare {
    pub against: &'static str,
    pub current: Answer<Summary>,
    pub previous: Answer<Summary>,
    pub delta: BTreeMap<&'static str, DeltaValue>,
}

/// Position in the newest-first request list; the next page holds rows strictly older than it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Cursor {
    pub before_ts: i64,
    pub before_id: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PageRequest {
    pub limit: usize,
    pub offset: usize,
    pub before: Option<Cursor>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestPage {
    pub items: Vec<LogEvent>,
    /// Where the next page starts; absent when there is nothing older in the range.
    pub next_cursor: Option<Cursor>,
    pub partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned: Option<u64>,
    pub filters: AnalyticsFilter,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ms: Option<i64>,
}

fn json_list(items: &[String]) -> Value {
    Value::Text(serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string()))
}

/// The where clause of a filter over raw rows; every value is a bound parameter and every fragment is static.
pub(crate) fn build_where(f: &AnalyticsFilter, from: Option<i64>, to: Option<i64>) -> Where {
    let mut w = Where::default();
    if let Some(v) = from {
        w.and("ts >= ?", [queries::int(v)]);
    }
    if let Some(v) = to {
        w.and("ts < ?", [queries::int(v)]);
    }
    match f.sites.as_slice() {
        [] => {}
        [one] => queries::site_filter(&mut w, Some(one.as_str())),
        many => {
            w.and(
                SITES_IN,
                [queries::int(i64::from(kind::SITE)), json_list(many)],
            );
        }
    }
    if let Some(h) = &f.host {
        w.and(HOST_EQ, queries::dict_params(kind::HOST, h));
    }
    if let Some(p) = f.path_prefix.as_deref().filter(|p| !p.is_empty()) {
        // U+10FFFF sorts after every other code point, so the pair is a half-open prefix range
        let upper = format!("{p}\u{10FFFF}");
        w.and(
            "path >= ? AND path <= ?",
            [queries::text(p), Value::Text(upper)],
        );
    }
    if let Some(p) = &f.path_exact {
        w.and("path = ?", [queries::text(p)]);
    }
    if let Some(p) = &f.path_contains {
        w.and("instr(path, ?) > 0", [queries::text(p)]);
    }
    match f.methods.as_slice() {
        [] => {}
        [one] => {
            w.and(METHOD_EQ, queries::dict_params(kind::METHOD, one));
        }
        many => {
            w.and(
                METHODS_IN,
                [queries::int(i64::from(kind::METHOD)), json_list(many)],
            );
        }
    }
    if let Some(s) = f.status {
        w.and("status = ?", [queries::int(i64::from(s))]);
    }
    if let Some(s) = f.status_min {
        w.and("status >= ?", [queries::int(i64::from(s))]);
    }
    if let Some(s) = f.status_max {
        w.and("status <= ?", [queries::int(i64::from(s))]);
    }
    let mut classes: Vec<i64> = f
        .status_classes
        .iter()
        .map(|c| i64::from(c.bytes().next().unwrap_or(b'0').saturating_sub(b'0')))
        .collect();
    classes.sort_unstable();
    classes.dedup();
    if !classes.is_empty() {
        let bounds: Vec<Value> = classes
            .iter()
            .flat_map(|n| [queries::int(n * 100), queries::int(n * 100 + 100)])
            .collect();
        w.and(
            CLASS_FRAGS[classes.len().min(CLASS_FRAGS.len()) - 1],
            bounds,
        );
    }
    match &f.blocked {
        None => {}
        Some(Blocked::Any) => {
            w.and("blocked_id IS NOT NULL", []);
        }
        Some(Blocked::Unblocked) => {
            w.and("blocked_id IS NULL", []);
        }
        Some(Blocked::Rule(id)) => {
            w.and(BLOCKED_EQ, queries::dict_params(kind::BLOCKED, id));
        }
    }
    match f.bot_classes.as_slice() {
        [] => {}
        [one] => {
            w.and(BOT_CLASS_EQ, queries::dict_params(kind::BOT_CLASS, one));
        }
        many => {
            w.and(
                BOT_CLASS_IN,
                [queries::int(i64::from(kind::BOT_CLASS)), json_list(many)],
            );
        }
    }
    if let Some(s) = f.min_bot_score {
        w.and("bot_score >= ?", [queries::int(i64::from(s))]);
    }
    if let Some(s) = f.max_bot_score {
        w.and("bot_score <= ?", [queries::int(i64::from(s))]);
    }
    match f.ip_match() {
        None => {}
        Some(IpMatch::Exact(ip)) => queries::ip_filter(&mut w, &ip.to_string()),
        Some(net @ IpMatch::Net(..)) => {
            w.and(
                IP_IN_NET,
                [
                    queries::int(i64::from(kind::CLIENT_IP)),
                    queries::text(&net.label()),
                ],
            );
        }
    }
    if let Some(ua) = &f.user_agent {
        w.and(
            UA_LIKE,
            [
                queries::int(i64::from(kind::USER_AGENT)),
                Value::Text(format!("%{}%", like_escape(ua))),
            ],
        );
    }
    if let Some(r) = &f.referer {
        w.and(
            REFERER_LIKE,
            [
                queries::int(i64::from(kind::REFERER)),
                Value::Text(format!("%{}%", like_escape(r))),
            ],
        );
    }
    if let Some(ms) = f.min_duration_ms {
        w.and("total_ms >= ?", [queries::int(i64::from(ms))]);
    }
    if let Some(ct) = &f.content_type {
        w.and(
            CTYPE_LIKE,
            [
                queries::int(i64::from(kind::CONTENT_TYPE)),
                Value::Text(format!("{}%", like_escape(ct))),
            ],
        );
    }
    w
}

// The part of a range one raw query reads: the whole of it, or the newest SCAN_CAP rows when it holds more.
#[derive(Debug, Clone, Copy)]
struct Scope {
    from: i64,
    to: i64,
    partial: bool,
    scanned: u64,
}

// Counts raw rows of the range through the time index alone, stopping one past the cap; over the cap the range is cut at the timestamp of the first row beyond it.
fn scope(conn: &Connection, from: i64, to: i64, cap: usize) -> Result<Scope> {
    let cap = to_i64(cap as u64);
    let seen: i64 = conn.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM requests INDEXED BY idx_requests_ts \
         WHERE ts >= ?1 AND ts < ?2 LIMIT ?3)",
        params![from, to, cap.saturating_add(1)],
        |r| r.get(0),
    )?;
    if seen <= cap {
        return Ok(Scope {
            from,
            to,
            partial: false,
            scanned: from_i64(seen),
        });
    }
    let cut: i64 = conn.query_row(
        "SELECT ts FROM requests INDEXED BY idx_requests_ts \
         WHERE ts >= ?1 AND ts < ?2 ORDER BY ts DESC LIMIT 1 OFFSET ?3",
        params![from, to, cap],
        |r| r.get(0),
    )?;
    Ok(Scope {
        from: cut.saturating_add(1).max(from),
        to,
        partial: true,
        scanned: from_i64(cap),
    })
}

// How a query is answered: from a rollup window, or by reading raw rows of a range.
enum Plan {
    Window(Window),
    Raw { from: i64, to: i64 },
}

impl Plan {
    fn bounds(&self) -> (i64, i64) {
        match self {
            Plan::Window(w) => (w.from, w.to),
            Plan::Raw { from, to } => (*from, *to),
        }
    }
}

fn source_label(win: &Window) -> &'static str {
    match win.source {
        Source::Raw => "raw",
        Source::Minute => "rollup_minute",
        Source::Hour => "rollup_hour",
    }
}

// A rollup window for an explicit range, when the range falls on whole buckets (an open end counts as the current bucket) and the rollups still hold it.
fn aligned_window(conn: &Connection, from: i64, to: i64, now_ms: i64) -> Result<Option<Window>> {
    let open_end = to >= now_ms;
    let build = |step: i64, source: Source| -> Option<Window> {
        if from.rem_euclid(step) != 0 || !(open_end || to.rem_euclid(step) == 0) {
            return None;
        }
        let first = from.div_euclid(step);
        let last = if open_end {
            now_ms.div_euclid(step)
        } else {
            to.div_euclid(step) - 1
        };
        (last >= first).then_some(Window {
            first,
            last,
            step,
            from: first * step,
            to: (last + 1) * step,
            source,
        })
    };
    // minute rollups are removed after seven hours, so only spans that start within the last six are safe
    if to - from <= MINUTE_SPAN_MS
        && from >= now_ms - MINUTE_SPAN_MS
        && let Some(win) = build(MINUTE_MS, Source::Minute)
        && win.first >= queries::valid_from(conn)?
        && queries::heavy_ready(conn, dim::ANY, &win)?
    {
        return Ok(Some(win));
    }
    Ok(build(HOUR_MS, Source::Hour))
}

// Windows and sites alone keep the exact rollup choice the original endpoints made; anything else reads raw rows.
fn make_plan(
    conn: &Connection,
    f: &AnalyticsFilter,
    now_ms: i64,
    minute_step: bool,
    force_raw: bool,
) -> Result<Plan> {
    let rollup = !force_raw && f.rollup_only();
    Ok(match f.span(now_ms)? {
        Span::Window(secs) if rollup => {
            Plan::Window(Window::pick(conn, secs, now_ms, minute_step)?)
        }
        Span::Window(secs) => {
            let w = Window::new(secs, now_ms, false);
            Plan::Raw {
                from: w.from,
                to: w.to,
            }
        }
        Span::Range { from, to } => {
            match rollup
                .then(|| aligned_window(conn, from, to, now_ms))
                .transpose()?
                .flatten()
            {
                Some(win) => Plan::Window(win),
                None => Plan::Raw { from, to },
            }
        }
    })
}

fn answer<T>(
    data: T,
    f: &AnalyticsFilter,
    range: (i64, i64),
    source: &'static str,
    scope: Option<&Scope>,
) -> Answer<T> {
    Answer {
        data,
        filters: f.clone(),
        partial: scope.is_some_and(|s| s.partial),
        scanned: scope.map(|s| s.scanned),
        from_ms: range.0,
        to_ms: range.1,
        source,
    }
}

fn one_site(f: &AnalyticsFilter) -> Option<&str> {
    f.sites.first().map(String::as_str)
}

fn summary_with(
    conn: &Connection,
    f: &AnalyticsFilter,
    plan: &Plan,
    cap: usize,
) -> Result<Answer<Summary>> {
    match plan {
        Plan::Window(win) => {
            let data = queries::summary_in(conn, win, one_site(f))?;
            Ok(answer(data, f, (win.from, win.to), source_label(win), None))
        }
        Plan::Raw { from, to } => {
            let sc = scope(conn, *from, *to, cap)?;
            let w = build_where(f, Some(sc.from), Some(sc.to));
            let data = queries::summary_raw(conn, &w)?;
            Ok(answer(data, f, (sc.from, sc.to), "raw", Some(&sc)))
        }
    }
}

pub(crate) fn summary(
    conn: &Connection,
    f: &AnalyticsFilter,
    now_ms: i64,
    cap: usize,
) -> Result<Answer<Summary>> {
    let conn = &queries::snapshot(conn)?;
    let plan = make_plan(conn, f, now_ms, false, false)?;
    summary_with(conn, f, &plan, cap)
}

// Step that keeps a chart within MAX_POINTS points; the longest span a query accepts still fits the largest step.
pub(crate) fn pick_step(span_ms: i64) -> i64 {
    STEPS_MS
        .iter()
        .copied()
        .find(|s| span_ms / s <= MAX_POINTS)
        .unwrap_or(DAY_MS)
}

pub(crate) fn timeseries(
    conn: &Connection,
    f: &AnalyticsFilter,
    now_ms: i64,
    cap: usize,
) -> Result<Answer<Timeseries>> {
    let conn = &queries::snapshot(conn)?;
    match make_plan(conn, f, now_ms, true, false)? {
        Plan::Window(win) => {
            let data = queries::timeseries_in(conn, &win, one_site(f))?;
            Ok(answer(
                data,
                f,
                (win.from, win.to),
                source_label(&win),
                None,
            ))
        }
        Plan::Raw { from, to } => {
            let step = pick_step(to - from);
            let sc = scope(conn, from, to, cap)?;
            let w = build_where(f, Some(sc.from), Some(sc.to));
            let sql = format!(
                "SELECT (ts - ((ts % {step}) + {step}) % {step}) / {step}, count(*), \
                 coalesce(sum(bytes_out), 0), \
                 coalesce(sum(status >= 400 AND status < 600), 0), coalesce(sum(blocked_id IS NOT NULL), 0), \
                 coalesce(sum(total_ms), 0) FROM requests r{} GROUP BY 1",
                w.clause()
            );
            let map = queries::bucket_rows(conn, &sql, &w)?;
            let step_secs = step / 1000;
            let first = sc.from.div_euclid(step);
            let last = (sc.to - 1).div_euclid(step);
            let points = (first..=last)
                .map(|idx| {
                    let (requests, bytes_out, errors, blocked, ms_sum) =
                        map.get(&idx).copied().unwrap_or_default();
                    Point {
                        ts: idx * step_secs,
                        requests,
                        bytes_out,
                        errors,
                        blocked,
                        avg_ms: if requests == 0 {
                            0.0
                        } else {
                            ms_sum as f64 / requests as f64
                        },
                    }
                })
                .collect();
            let data = Timeseries {
                step_secs: u64::try_from(step_secs).unwrap_or(0),
                points,
            };
            Ok(answer(data, f, (sc.from, sc.to), "raw", Some(&sc)))
        }
    }
}

pub(crate) fn bots(
    conn: &Connection,
    f: &AnalyticsFilter,
    now_ms: i64,
    cap: usize,
) -> Result<Answer<BotSummary>> {
    let conn = &queries::snapshot(conn)?;
    match make_plan(conn, f, now_ms, false, false)? {
        Plan::Window(win) => {
            let data = queries::bots_in(conn, &win, one_site(f))?;
            Ok(answer(
                data,
                f,
                (win.from, win.to),
                source_label(&win),
                None,
            ))
        }
        Plan::Raw { from, to } => {
            let sc = scope(conn, from, to, cap)?;
            let w = build_where(f, Some(sc.from), Some(sc.to));
            let data = queries::bots_from_where(conn, &w, TOP_N)?;
            Ok(answer(data, f, (sc.from, sc.to), "raw", Some(&sc)))
        }
    }
}

pub(crate) fn top(
    conn: &Connection,
    f: &AnalyticsFilter,
    list: TopKind,
    limit: usize,
    sort: SortBy,
    now_ms: i64,
    cap: usize,
) -> Result<Answer<TopList>> {
    let limit = limit.min(MAX_TOP_LIMIT);
    let conn = &queries::snapshot(conn)?;
    match make_plan(conn, f, now_ms, false, sort == SortBy::Bytes)? {
        Plan::Window(win) => {
            let items = if limit == 0 {
                Vec::new()
            } else {
                queries::top_in(conn, list, &win, one_site(f), limit)?
            };
            Ok(answer(
                TopList { items },
                f,
                (win.from, win.to),
                source_label(&win),
                None,
            ))
        }
        Plan::Raw { from, to } => {
            let sc = scope(conn, from, to, cap)?;
            let items = if limit == 0 {
                Vec::new()
            } else {
                let w = build_where(f, Some(sc.from), Some(sc.to));
                queries::top_raw_by(conn, list, &w, limit, sort)?
            };
            Ok(answer(
                TopList { items },
                f,
                (sc.from, sc.to),
                "raw",
                Some(&sc),
            ))
        }
    }
}

fn facet_values(items: Vec<TopItem>) -> Vec<FacetValue> {
    items
        .into_iter()
        .map(|i| FacetValue {
            key: i.key,
            count: i.count,
        })
        .collect()
}

// Methods are stored as sent; facets merge them case-insensitively like the summary does.
fn method_facets(items: Vec<TopItem>) -> Vec<FacetValue> {
    let mut merged: BTreeMap<String, u64> = BTreeMap::new();
    for it in items {
        *merged.entry(ascii_upper(&it.key).into_owned()).or_default() += it.count;
    }
    let mut out: Vec<FacetValue> = merged
        .into_iter()
        .map(|(key, count)| FacetValue { key, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out.truncate(FACET_N);
    out
}

fn class_facets(counts: [u64; 6]) -> Vec<FacetValue> {
    const KEYS: [&str; 6] = ["other", "1xx", "2xx", "3xx", "4xx", "5xx"];
    let mut out: Vec<FacetValue> = KEYS
        .iter()
        .zip(counts)
        .filter(|(_, n)| *n > 0)
        .map(|(k, n)| FacetValue {
            key: (*k).to_string(),
            count: n,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out
}

fn rollup_facets(conn: &Connection, win: &Window, site: Option<&str>) -> Result<Facets> {
    let n = FACET_N;
    let rw = queries::roll_where(win, site);
    let sql = format!(
        "SELECT d.val, sum(x.requests) FROM {} x JOIN dict d ON d.id = x.site_id{} \
         GROUP BY x.site_id ORDER BY 2 DESC, 1 ASC LIMIT ?",
        win.level().rollup,
        rw.clause()
    );
    let sites = queries::collect(
        conn,
        &sql,
        &rw.bind([queries::int(to_i64(n as u64))]),
        |r| {
            Ok(FacetValue {
                key: r.get::<_, String>(0)?,
                count: from_i64(r.get(1)?),
            })
        },
    )?;
    let sql = format!(
        "SELECT coalesce(sum(s0), 0), coalesce(sum(s1), 0), coalesce(sum(s2), 0), \
         coalesce(sum(s3), 0), coalesce(sum(s4), 0), coalesce(sum(s5), 0) FROM {}{}",
        win.level().rollup,
        rw.clause()
    );
    let counts = conn.query_row(&sql, params_from_iter(rw.bind([]).iter()), |r| {
        let mut c = [0u64; 6];
        for (i, slot) in c.iter_mut().enumerate() {
            *slot = from_i64(r.get(i)?);
        }
        Ok(c)
    })?;
    Ok(Facets {
        site: sites,
        host: facet_values(queries::rollup_top_dict(conn, dim::HOST, win, site, n)?),
        method: method_facets(queries::rollup_top_dict(
            conn,
            dim::METHOD,
            win,
            site,
            FOLD_FETCH,
        )?),
        status_class: class_facets(counts),
        bot_class: facet_values(queries::rollup_top_dict(
            conn,
            dim::BOT_CLASS,
            win,
            site,
            n,
        )?),
    })
}

fn raw_facets(conn: &Connection, w: &Where) -> Result<Facets> {
    let n = FACET_N;
    let by = |col: &'static str, limit: usize| {
        queries::raw_top_dict_by(conn, col, w, limit, SortBy::Count)
    };
    let sql = format!(
        "SELECT CASE WHEN status < 100 OR status >= 600 THEN 0 ELSE status / 100 END, count(*) \
         FROM requests r{} GROUP BY 1",
        w.clause()
    );
    let mut counts = [0u64; 6];
    for (class, count) in queries::collect(conn, &sql, &w.bind([]), |r| {
        Ok((r.get::<_, i64>(0)?, from_i64(r.get(1)?)))
    })? {
        if let Some(slot) = usize::try_from(class).ok().and_then(|i| counts.get_mut(i)) {
            *slot = count;
        }
    }
    Ok(Facets {
        site: facet_values(by("site_id", n)?),
        host: facet_values(by("host_id", n)?),
        method: method_facets(by("method_id", FOLD_FETCH)?),
        status_class: class_facets(counts),
        bot_class: facet_values(by("bot_class_id", n)?),
    })
}

pub(crate) fn facets(
    conn: &Connection,
    f: &AnalyticsFilter,
    now_ms: i64,
    cap: usize,
) -> Result<Answer<Facets>> {
    let conn = &queries::snapshot(conn)?;
    let (from, to) = match make_plan(conn, f, now_ms, false, false)? {
        Plan::Window(win) if win.source != Source::Raw => {
            let data = rollup_facets(conn, &win, one_site(f))?;
            return Ok(answer(
                data,
                f,
                (win.from, win.to),
                source_label(&win),
                None,
            ));
        }
        plan => plan.bounds(),
    };
    let sc = scope(conn, from, to, cap)?;
    let w = build_where(f, Some(sc.from), Some(sc.to));
    let data = raw_facets(conn, &w)?;
    Ok(answer(data, f, (sc.from, sc.to), "raw", Some(&sc)))
}

fn delta(cur: f64, prev: f64) -> DeltaValue {
    DeltaValue {
        current: cur,
        previous: prev,
        abs: cur - prev,
        pct: (prev != 0.0).then(|| (cur - prev) / prev * 100.0),
    }
}

fn deltas(cur: &Summary, prev: &Summary) -> BTreeMap<&'static str, DeltaValue> {
    let n = |v: u64| v as f64;
    BTreeMap::from([
        ("requests", delta(n(cur.requests), n(prev.requests))),
        ("bytes_in", delta(n(cur.bytes_in), n(prev.bytes_in))),
        ("bytes_out", delta(n(cur.bytes_out), n(prev.bytes_out))),
        ("blocked", delta(n(cur.blocked), n(prev.blocked))),
        ("errors_4xx", delta(n(cur.errors_4xx), n(prev.errors_4xx))),
        ("errors_5xx", delta(n(cur.errors_5xx), n(prev.errors_5xx))),
        ("avg_ms", delta(cur.avg_ms, prev.avg_ms)),
        ("p50_ms", delta(n(cur.p50_ms), n(prev.p50_ms))),
        ("p95_ms", delta(n(cur.p95_ms), n(prev.p95_ms))),
        ("p99_ms", delta(n(cur.p99_ms), n(prev.p99_ms))),
    ])
}

// The summary of the range and of the equally long range right before it, both from one snapshot.
pub(crate) fn compare(
    conn: &Connection,
    f: &AnalyticsFilter,
    now_ms: i64,
    cap: usize,
) -> Result<Compare> {
    let conn = &queries::snapshot(conn)?;
    let plan = make_plan(conn, f, now_ms, false, false)?;
    let (from, to) = plan.bounds();
    let current = summary_with(conn, f, &plan, cap)?;
    let mut before = f.clone();
    before.window = None;
    before.from_ms = Some(from - (to - from));
    before.to_ms = Some(from);
    let prev_plan = make_plan(conn, &before, now_ms, false, false)?;
    let previous = summary_with(conn, &before, &prev_plan, cap)?;
    Ok(Compare {
        against: "previous",
        delta: deltas(&current.data, &previous.data),
        current,
        previous,
    })
}

pub(crate) fn requests(
    conn: &Connection,
    f: &AnalyticsFilter,
    page: &PageRequest,
    now_ms: i64,
    cap: usize,
) -> Result<RequestPage> {
    f.validate()?;
    if page.offset > MAX_OFFSET {
        return Err(Error::Rejected(format!(
            "offset must be at most {MAX_OFFSET}; page with the cursor instead"
        )));
    }
    if page.offset > 0 && page.before.is_some() {
        return Err(Error::Rejected(
            "offset and a cursor cannot be combined".into(),
        ));
    }
    let limit = page.limit.min(MAX_PAGE);
    let empty = |lo: Option<i64>, hi: Option<i64>| RequestPage {
        items: Vec::new(),
        next_cursor: None,
        partial: false,
        scanned: None,
        filters: f.clone(),
        from_ms: lo,
        to_ms: hi,
    };
    let bounds = match f.bounded_span(now_ms)? {
        None => None,
        Some(Span::Window(secs)) => {
            let w = Window::new(secs, now_ms, false);
            Some((w.from, w.to))
        }
        Some(Span::Range { from, to }) => Some((from, to)),
    };
    if limit == 0 {
        return Ok(empty(bounds.map(|b| b.0), bounds.map(|b| b.1)));
    }
    let conn = &queries::snapshot(conn)?;
    let mut lo = bounds.map(|b| b.0);
    let mut hi = bounds.map(|b| b.1);
    if let Some(c) = page.before {
        let ceiling = c.before_ts.saturating_add(1);
        hi = Some(hi.map_or(ceiling, |h| h.min(ceiling)));
    }
    let mut seen = None;
    if let (Some(l), Some(h)) = (lo, hi)
        && f.has_row_conditions()
    {
        let sc = scope(conn, l, h, cap)?;
        lo = Some(sc.from);
        seen = Some(sc);
    }
    let mut w = build_where(f, lo, hi);
    if let Some(c) = page.before {
        w.and(
            "(ts, r.id) < (?, ?)",
            [queries::int(c.before_ts), queries::int(c.before_id)],
        );
    }
    let sql = format!(
        "{}{} ORDER BY r.ts DESC, r.id DESC LIMIT ? OFFSET ?",
        queries::EVENT_SELECT,
        w.clause()
    );
    let rows = queries::collect(
        conn,
        &sql,
        &w.bind([
            queries::int(to_i64(limit as u64)),
            queries::int(to_i64(page.offset as u64)),
        ]),
        queries::decode,
    )?;
    let full = rows.len() == limit;
    let partial = !full && seen.is_some_and(|s| s.partial);
    let next_cursor = match (full, partial, rows.last(), lo) {
        (true, _, Some((id, ev)), _) => Some(Cursor {
            before_ts: ev.ts_ms,
            before_id: *id,
        }),
        // the cap cut the range short of the page, so the cursor resumes just before the part that was read
        (false, true, _, Some(cut)) => Some(Cursor {
            before_ts: cut,
            before_id: 0,
        }),
        _ => None,
    };
    Ok(RequestPage {
        items: rows.into_iter().map(|(_, ev)| ev).collect(),
        next_cursor,
        partial,
        scanned: seen.map(|s| s.scanned),
        filters: f.clone(),
        from_ms: lo,
        to_ms: hi,
    })
}
