use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use cite_edge::analytics::{Point, RequestFilter, SizeBucket, Summary, Timeseries, TopItem};
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};

use crate::error::Result;
use crate::hist::{LAT_LEN, SIZE_LEN, SIZE_LES, lat_index, percentile};
use crate::limits::{
    HOUR_MS, MAX_REQUEST_LIMIT, MAX_TOP_LIMIT, MAX_WINDOW_SECS, METHOD_CAP, MINUTE_MS,
    MINUTE_STEP_MAX_WINDOW_SECS, ROLLUP_MIN_WINDOW_SECS, TOP_N,
};
use crate::schema::{ALL_SITES, HOURLY, Level, MINUTELY, dim, kind, series};
use crate::util::{
    ascii_upper, from_i64, normalize_ctype, split_signals, to_i64, to_u8, to_u16, to_u32,
};

const SCORE_KEYS: [&str; 5] = ["0-19", "20-39", "40-59", "60-79", "80-100"];
// Groups fetched before folding in Rust (content types, methods, signal lists); bounds work on hostile cardinality.
pub(crate) const FOLD_FETCH: usize = 5000;
// Key bytes a top query keeps in memory before it stops reading ranked rows.
pub(crate) const TOP_RESULT_BYTES: usize = 64 * 1024 * 1024;

/// Dimensions a top query can rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopKind {
    Paths,
    Hosts,
    Referers,
    UserAgents,
    ContentTypes,
    StatusCodes,
    ClientIps,
    Languages,
}

// A WHERE clause assembled only from static fragments; every value travels as a bound parameter.
#[derive(Clone, Default)]
pub(crate) struct Where {
    frags: Vec<&'static str>,
    params: Vec<Value>,
}

impl Where {
    pub(crate) fn and(
        &mut self,
        frag: &'static str,
        params: impl IntoIterator<Item = Value>,
    ) -> &mut Self {
        self.frags.push(frag);
        self.params.extend(params);
        self
    }

    pub(crate) fn clause(&self) -> String {
        if self.frags.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.frags.join(" AND "))
        }
    }

    pub(crate) fn bind(&self, extra: impl IntoIterator<Item = Value>) -> Vec<Value> {
        let mut all = self.params.clone();
        all.extend(extra);
        all
    }
}

macro_rules! dict_eq {
    ($col:literal) => {
        concat!(
            $col,
            " = (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val = ?)"
        )
    };
}

const METHOD_NOCASE: &str =
    "method_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val = ? COLLATE NOCASE)";
// Must match the expression in idx_requests_ip_bucket.
const IP_BUCKET: &str =
    "client_ip_id % 256 = (SELECT s.id % 256 FROM dict s WHERE s.kind = ? AND s.val = ?)";
const NOT_HUMAN: &str = "bot_class_id IN (SELECT s.id FROM dict s WHERE s.kind = ? AND s.val <> ?)";

pub(crate) fn int(n: i64) -> Value {
    Value::Integer(n)
}

pub(crate) fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub(crate) fn dict_params(k: u8, val: &str) -> [Value; 2] {
    [int(i64::from(k)), text(val)]
}

fn text_col(row: &Row, i: usize) -> rusqlite::Result<String> {
    Ok(match row.get_ref(i)? {
        ValueRef::Text(b) | ValueRef::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    })
}

fn count_col(row: &Row, i: usize) -> rusqlite::Result<u64> {
    Ok(from_i64(row.get(i)?))
}

pub(crate) fn collect<T>(
    conn: &Connection,
    sql: &str,
    params: &[Value],
    f: impl FnMut(&Row) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), f)?;
    let out = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(out)
}

// Where a window's numbers come from: raw rows, the minute rollups or the hourly rollups.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Raw,
    Minute,
    Hour,
}

// Bucket-aligned time range for a window, as bucket indexes and as milliseconds [from, to).
pub(crate) struct Window {
    pub(crate) first: i64,
    pub(crate) last: i64,
    pub(crate) step: i64,
    pub(crate) from: i64,
    pub(crate) to: i64,
    pub(crate) source: Source,
}

impl Window {
    pub(crate) fn new(window_secs: u64, now_ms: i64, hourly: bool) -> Self {
        let span = i64::try_from(window_secs.min(MAX_WINDOW_SECS)).unwrap_or(0) * 1000;
        let step = if hourly { HOUR_MS } else { MINUTE_MS };
        let first = now_ms.saturating_sub(span).div_euclid(step);
        let last = now_ms.div_euclid(step);
        Self {
            first,
            last,
            step,
            from: first.saturating_mul(step),
            to: last.saturating_add(1).saturating_mul(step),
            source: if hourly { Source::Hour } else { Source::Raw },
        }
    }

    // A minute-step window served by the minute rollups.
    pub(crate) fn minute(window_secs: u64, now_ms: i64) -> Self {
        Self {
            source: Source::Minute,
            ..Self::new(window_secs, now_ms, false)
        }
    }

    // Windows of up to six hours read the minute rollups once they cover every minute of the window; longer ones read the hourly rollups, or raw minutes when the chart still steps per minute.
    pub(crate) fn pick(
        conn: &Connection,
        window_secs: u64,
        now_ms: i64,
        minute_step: bool,
    ) -> Result<Self> {
        if window_secs > ROLLUP_MIN_WINDOW_SECS {
            let hourly = !minute_step || window_secs > MINUTE_STEP_MAX_WINDOW_SECS;
            return Ok(Self::new(window_secs, now_ms, hourly));
        }
        let win = Self::minute(window_secs, now_ms);
        if win.first >= valid_from(conn)? && heavy_ready(conn, dim::ANY, &win)? {
            Ok(win)
        } else {
            Ok(Self::new(window_secs, now_ms, false))
        }
    }

    pub(crate) fn level(&self) -> &'static Level {
        if self.source == Source::Hour {
            &HOURLY
        } else {
            &MINUTELY
        }
    }

    fn range_frags(&self) -> (&'static str, &'static str) {
        if self.source == Source::Hour {
            ("hour >= ?", "hour <= ?")
        } else {
            ("minute >= ?", "minute <= ?")
        }
    }
}

// First minute the minute rollups cover completely.
pub(crate) fn valid_from(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT valid_from FROM rollup_state", [], |r| r.get(0))?)
}

// Highest request id whose heavy keys are in the minute tables; later rows are read raw.
fn folded_id(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT folded_id FROM rollup_state", [], |r| r.get(0))?)
}

// A read snapshot, so the statements of one query see the same rollups and watermark.
pub(crate) fn snapshot(conn: &Connection) -> Result<rusqlite::Transaction<'_>> {
    Ok(conn.unchecked_transaction()?)
}

// Exact client ip match plus the bucket term that lets idx_requests_ip_bucket serve it.
pub(crate) fn ip_filter(w: &mut Where, ip: &str) {
    w.and(IP_BUCKET, dict_params(kind::CLIENT_IP, ip));
    w.and(dict_eq!("client_ip_id"), dict_params(kind::CLIENT_IP, ip));
}

pub(crate) fn site_filter(w: &mut Where, site: Option<&str>) {
    if let Some(s) = site.filter(|s| !s.is_empty()) {
        w.and(dict_eq!("site_id"), dict_params(kind::SITE, s));
    }
}

pub(crate) fn range_where(from: i64, to: i64, site: Option<&str>) -> Where {
    let mut w = Where::default();
    w.and("ts >= ?", [int(from)]).and("ts < ?", [int(to)]);
    site_filter(&mut w, site);
    w
}

fn raw_where(win: &Window, site: Option<&str>) -> Where {
    range_where(win.from, win.to, site)
}

pub(crate) fn roll_where(win: &Window, site: Option<&str>) -> Where {
    let (lo, hi) = win.range_frags();
    let mut w = Where::default();
    w.and(lo, [int(win.first)]).and(hi, [int(win.last)]);
    site_filter(&mut w, site);
    w
}

// rollup_dim and rollup_path rows exist per site and summed under ALL_SITES, so one site range serves either query.
fn scope_where(win: &Window, site: Option<&str>, d: Option<u8>) -> Where {
    let mut w = Where::default();
    if let Some(d) = d {
        w.and("dim = ?", [int(i64::from(d))]);
    }
    let (lo, hi) = win.range_frags();
    w.and(lo, [int(win.first)]).and(hi, [int(win.last)]);
    match site {
        Some(_) => site_filter(&mut w, site),
        None => {
            w.and("site_id = ?", [int(ALL_SITES)]);
        }
    }
    w
}

fn site_known(conn: &Connection, site: &str) -> Result<bool> {
    let known = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM dict WHERE kind = ?1 AND val = ?2)",
        params![kind::SITE, site],
        |r| r.get::<_, bool>(0),
    )?;
    Ok(known)
}

fn sort_items(items: &mut [TopItem]) {
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
}

// Rows come back ranked, so stopping at the budget drops only the lowest-ranked tail of a hostile-cardinality list.
fn run_top(conn: &Connection, sql: &str, params: &[Value]) -> Result<Vec<TopItem>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let mut rows = stmt.query(params_from_iter(params.iter()))?;
    let mut out = Vec::new();
    let mut held = 0usize;
    while let Some(r) = rows.next()? {
        let key = text_col(r, 0)?;
        held += key.len() + std::mem::size_of::<TopItem>();
        out.push(TopItem {
            key,
            count: count_col(r, 1)?,
            bytes: count_col(r, 2)?,
        });
        if held >= TOP_RESULT_BYTES {
            break;
        }
    }
    Ok(out)
}

fn run_top_int(conn: &Connection, sql: &str, params: &[Value]) -> Result<Vec<TopItem>> {
    collect(conn, sql, params, |r| {
        Ok(TopItem {
            key: r.get::<_, i64>(0)?.to_string(),
            count: count_col(r, 1)?,
            bytes: count_col(r, 2)?,
        })
    })
}

/// Ranking of a top list: by request count, or by response bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Count,
    Bytes,
}

impl SortBy {
    fn order(self) -> &'static str {
        match self {
            SortBy::Count => "2 DESC, 1 ASC",
            SortBy::Bytes => "3 DESC, 2 DESC, 1 ASC",
        }
    }
}

fn raw_top_dict(
    conn: &Connection,
    col: &'static str,
    w: &Where,
    limit: usize,
) -> Result<Vec<TopItem>> {
    raw_top_dict_by(conn, col, w, limit, SortBy::Count)
}

pub(crate) fn raw_top_dict_by(
    conn: &Connection,
    col: &'static str,
    w: &Where,
    limit: usize,
    sort: SortBy,
) -> Result<Vec<TopItem>> {
    let sql = format!(
        "SELECT d.val, count(*), coalesce(sum(r.bytes_out), 0) FROM requests r \
         JOIN dict d ON d.id = r.{col}{} GROUP BY r.{col} ORDER BY {} LIMIT ?",
        w.clause(),
        sort.order()
    );
    run_top(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

fn raw_top_path(conn: &Connection, w: &Where, limit: usize) -> Result<Vec<TopItem>> {
    raw_top_path_by(conn, w, limit, SortBy::Count)
}

fn raw_top_path_by(
    conn: &Connection,
    w: &Where,
    limit: usize,
    sort: SortBy,
) -> Result<Vec<TopItem>> {
    let mut w = w.clone();
    w.and("path <> ''", []);
    let sql = format!(
        "SELECT r.path, count(*), coalesce(sum(r.bytes_out), 0) FROM requests r{} \
         GROUP BY r.path ORDER BY {} LIMIT ?",
        w.clause(),
        sort.order()
    );
    run_top(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

fn raw_top_status(
    conn: &Connection,
    w: &Where,
    limit: usize,
    sort: SortBy,
) -> Result<Vec<TopItem>> {
    let sql = format!(
        "SELECT r.status, count(*), coalesce(sum(r.bytes_out), 0) FROM requests r{} \
         GROUP BY r.status ORDER BY {} LIMIT ?",
        w.clause(),
        sort.order()
    );
    run_top_int(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

// Groups first and joins the dictionary only for groups at or above the limit-th count, so the join stays small.
pub(crate) fn rollup_top_dict(
    conn: &Connection,
    d: u8,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let w = scope_where(win, site, Some(d));
    let sql = format!(
        "WITH g AS MATERIALIZED (SELECT key_id, sum(n) AS n, sum(bytes) AS b FROM {}{} GROUP BY key_id) \
         SELECT dc.val, g.n, g.b FROM g JOIN dict dc ON dc.id = g.key_id \
         WHERE g.n >= coalesce((SELECT n FROM g ORDER BY n DESC LIMIT 1 OFFSET ?), 0) \
         ORDER BY 2 DESC, 1 ASC LIMIT ?",
        win.level().dim,
        w.clause()
    );
    let offset = to_i64(limit.saturating_sub(1) as u64);
    run_top(
        conn,
        &sql,
        &w.bind([int(offset), int(to_i64(limit as u64))]),
    )
}

fn rollup_top_path(
    conn: &Connection,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let w = scope_where(win, site, None);
    let sql = format!(
        "SELECT path, sum(n), sum(bytes) FROM {}{} GROUP BY path ORDER BY 2 DESC, 1 ASC LIMIT ?",
        win.level().path,
        w.clause()
    );
    run_top(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

fn rollup_top_int(
    conn: &Connection,
    d: u8,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let w = scope_where(win, site, Some(d));
    let sql = format!(
        "SELECT x.key_id, sum(x.n), sum(x.bytes) FROM {} x{} \
         GROUP BY x.key_id ORDER BY 2 DESC, 1 ASC LIMIT ?",
        win.level().dim,
        w.clause()
    );
    run_top_int(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

// Rows newer than the fold watermark in the window, which the minute tables do not hold yet; readers scan them by id with NOT INDEXED, since the planner would otherwise walk the whole window through the ts index.
fn tail_where(win: &Window, site: Option<&str>, after: i64) -> Where {
    let mut w = Where::default();
    w.and("id > ?", [int(after)]);
    w.and("ts >= ?", [int(win.from)])
        .and("ts < ?", [int(win.to)]);
    site_filter(&mut w, site);
    w
}

// False when a minute of the window outgrew the key cap or came in with a backfill, so the tables do not hold it.
pub(crate) fn heavy_ready(conn: &Connection, d: u8, win: &Window) -> Result<bool> {
    let over = conn.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM rollup_over WHERE dim IN (?1, ?4) AND minute >= ?2 AND minute <= ?3)",
    )?
    .query_row(params![d, win.first, win.last, dim::ANY], |r| r.get::<_, bool>(0))?;
    Ok(!over)
}

// Largest list the hot-path shortcut answers, and the most keys whose single sightings it looks up.
const HOT_LIMIT: usize = 100;
const HOT_CANDIDATES: usize = 400;

// Exact top paths of a minute window: the folded minutes plus the raw rows the fold has not reached.
fn minute_top_path(
    conn: &Connection,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Vec<TopItem>> {
    if !heavy_ready(conn, dim::PATH, win)? {
        return raw_top_path(conn, &raw_where(win, site), limit);
    }
    if limit <= HOT_LIMIT
        && let Some(items) = hot_top_path(conn, win, site, limit)?
    {
        return Ok(items);
    }
    let rolled = scope_where(win, site, None);
    let mut tail = tail_where(win, site, folded_id(conn)?);
    tail.and("path <> ''", []);
    let sql = format!(
        "SELECT k, sum(n), sum(b) FROM (SELECT path AS k, n, bytes AS b FROM {}{} \
         UNION ALL SELECT r.path, 1, r.bytes_out FROM requests r NOT INDEXED{}) \
         GROUP BY k ORDER BY 2 DESC, 1 ASC LIMIT ?",
        MINUTELY.path,
        rolled.clause(),
        tail.clause()
    );
    let params = rolled.bind(tail.bind([int(to_i64(limit as u64))]));
    run_top(conn, &sql, &params)
}

// A path seen once in a minute is a "single"; it can add at most one per minute to a total. Summing only the paths seen at least twice (plus the unfolded rows) gives a lower bound for every key, and the keys that could still reach the limit-th place are then completed with their singles by point lookups. Returns None when the bound cannot prove the list, and the caller scans every row.
fn hot_top_path(
    conn: &Connection,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Option<Vec<TopItem>>> {
    let site_id = match site {
        None => ALL_SITES,
        Some(s) => {
            let id = conn
                .prepare_cached("SELECT id FROM dict WHERE kind = ?1 AND val = ?2")?
                .query_row(params![kind::SITE, s], |r| r.get::<_, i64>(0))
                .optional()?;
            match id {
                Some(id) => id,
                None => return Ok(Some(Vec::new())),
            }
        }
    };
    let mut rolled = scope_where(win, site, None);
    rolled.and("n >= 2", []);
    let mut tail = tail_where(win, site, folded_id(conn)?);
    tail.and("path <> ''", []);
    let sql = format!(
        "SELECT k, sum(n), sum(b) FROM (SELECT path AS k, n, bytes AS b FROM {} INDEXED BY idx_rollup_path_min_hot{} \
         UNION ALL SELECT r.path, 1, r.bytes_out FROM requests r NOT INDEXED{}) \
         GROUP BY k ORDER BY 2 DESC, 1 ASC",
        MINUTELY.path,
        rolled.clause(),
        tail.clause()
    );
    let hot = run_top(conn, &sql, &rolled.bind(tail.bind([])))?;
    if hot.len() < limit {
        return Ok(None);
    }
    let minutes = u64::try_from(win.last - win.first + 1).unwrap_or(u64::MAX);
    let cutoff = hot[limit - 1].count;
    let mut ranked: Vec<TopItem> = hot
        .into_iter()
        .take_while(|it| it.count.saturating_add(minutes) >= cutoff)
        .collect();
    if ranked.len() > HOT_CANDIDATES {
        return Ok(None);
    }
    let mut single = conn.prepare_cached(
        "SELECT n, bytes FROM rollup_path_min WHERE site_id = ?1 AND minute = ?2 AND path = ?3 AND n < 2",
    )?;
    for it in &mut ranked {
        for minute in win.first..=win.last {
            let found = single
                .query_row(params![site_id, minute, it.key], |r| {
                    Ok((count_col(r, 0)?, count_col(r, 1)?))
                })
                .optional()?;
            if let Some((n, bytes)) = found {
                it.count += n;
                it.bytes += bytes;
            }
        }
    }
    sort_items(&mut ranked);
    ranked.truncate(limit);
    match ranked.last() {
        Some(last) if last.count > minutes => Ok(Some(ranked)),
        _ => Ok(None),
    }
}

#[cfg(test)]
pub(crate) fn hot_top_path_for_test(
    conn: &Connection,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Option<Vec<TopItem>>> {
    hot_top_path(conn, win, site, limit)
}

// Same for a dictionary dimension; only_bots keeps the unfolded rows whose class is not human.
fn minute_top_dict(
    conn: &Connection,
    d: u8,
    col: &'static str,
    only_bots: bool,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let raw = || {
        let mut w = raw_where(win, site);
        if only_bots {
            w.and(NOT_HUMAN, dict_params(kind::BOT_CLASS, "human"));
        }
        raw_top_dict(conn, col, &w, limit)
    };
    if !heavy_ready(conn, d, win)? {
        return raw();
    }
    let rolled = scope_where(win, site, Some(d));
    let mut tail = tail_where(win, site, folded_id(conn)?);
    tail.and(
        match col {
            "client_ip_id" => "client_ip_id IS NOT NULL",
            "referer_id" => "referer_id IS NOT NULL",
            _ => "ua_id IS NOT NULL",
        },
        [],
    );
    if only_bots {
        tail.and(NOT_HUMAN, dict_params(kind::BOT_CLASS, "human"));
    }
    let sql = format!(
        "WITH g AS MATERIALIZED (SELECT k, sum(n) AS n, sum(b) AS b FROM \
         (SELECT key_id AS k, n, bytes AS b FROM {}{} \
         UNION ALL SELECT r.{col}, 1, r.bytes_out FROM requests r NOT INDEXED{}) GROUP BY k) \
         SELECT dc.val, g.n, g.b FROM g JOIN dict dc ON dc.id = g.k \
         WHERE g.n >= coalesce((SELECT n FROM g ORDER BY n DESC LIMIT 1 OFFSET ?), 0) \
         ORDER BY 2 DESC, 1 ASC LIMIT ?",
        MINUTELY.dim,
        rolled.clause(),
        tail.clause()
    );
    let offset = to_i64(limit.saturating_sub(1) as u64);
    let params = rolled.bind(tail.bind([int(offset), int(to_i64(limit as u64))]));
    run_top(conn, &sql, &params)
}

// Merges raw content types under their normalised media type.
fn fold_ctypes(items: Vec<TopItem>, limit: usize) -> Vec<TopItem> {
    fold_ctypes_by(items, limit, SortBy::Count)
}

fn fold_ctypes_by(items: Vec<TopItem>, limit: usize, sort: SortBy) -> Vec<TopItem> {
    let mut merged: HashMap<String, (u64, u64)> = HashMap::new();
    for it in items {
        let key = normalize_ctype(&it.key);
        if key.is_empty() {
            continue;
        }
        let e = merged.entry(key.into_owned()).or_default();
        e.0 += it.count;
        e.1 += it.bytes;
    }
    let mut out: Vec<TopItem> = merged
        .into_iter()
        .map(|(key, (count, bytes))| TopItem { key, count, bytes })
        .collect();
    match sort {
        SortBy::Count => sort_items(&mut out),
        SortBy::Bytes => out.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.key.cmp(&b.key))
        }),
    }
    out.truncate(limit);
    out
}

// Upper-cases methods and folds everything beyond the cap into OTHER.
fn fold_methods(items: Vec<TopItem>) -> BTreeMap<String, u64> {
    let mut merged: HashMap<String, u64> = HashMap::new();
    for it in items {
        *merged.entry(ascii_upper(&it.key).into_owned()).or_default() += it.count;
    }
    let mut ranked: Vec<(String, u64)> = merged.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    let mut other = 0u64;
    for (i, (k, n)) in ranked.into_iter().enumerate() {
        if i < METHOD_CAP {
            out.insert(k, n);
        } else {
            other += n;
        }
    }
    if other > 0 {
        *out.entry("OTHER".to_string()).or_default() += other;
    }
    out
}

pub(crate) fn top_raw(
    conn: &Connection,
    kind: TopKind,
    w: &Where,
    limit: usize,
) -> Result<Vec<TopItem>> {
    top_raw_by(conn, kind, w, limit, SortBy::Count)
}

pub(crate) fn top_raw_by(
    conn: &Connection,
    kind: TopKind,
    w: &Where,
    limit: usize,
    sort: SortBy,
) -> Result<Vec<TopItem>> {
    match kind {
        TopKind::Paths => raw_top_path_by(conn, w, limit, sort),
        TopKind::Hosts => raw_top_dict_by(conn, "host_id", w, limit, sort),
        TopKind::Referers => raw_top_dict_by(conn, "referer_id", w, limit, sort),
        TopKind::UserAgents => raw_top_dict_by(conn, "ua_id", w, limit, sort),
        TopKind::ClientIps => raw_top_dict_by(conn, "client_ip_id", w, limit, sort),
        TopKind::Languages => raw_top_dict_by(conn, "accept_lang_id", w, limit, sort),
        TopKind::StatusCodes => raw_top_status(conn, w, limit, sort),
        // Groups are folded under their media type in Rust, so the SQL fetch is ranked the same way and then re-ranked.
        TopKind::ContentTypes => Ok(fold_ctypes_by(
            raw_top_dict_by(conn, "ctype_id", w, FOLD_FETCH, sort)?,
            limit,
            sort,
        )),
    }
}

pub(crate) fn top(
    conn: &Connection,
    kind: TopKind,
    window_secs: u64,
    site: Option<&str>,
    now_ms: i64,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let limit = limit.min(MAX_TOP_LIMIT);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let conn = &snapshot(conn)?;
    let win = Window::pick(conn, window_secs, now_ms, false)?;
    top_in(conn, kind, &win, site, limit)
}

// Top list of a prepared window; limit must already be clamped.
pub(crate) fn top_in(
    conn: &Connection,
    kind: TopKind,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let site = site.filter(|s| !s.is_empty());
    match win.source {
        Source::Raw => {}
        Source::Minute => match kind {
            TopKind::Hosts => return rollup_top_dict(conn, dim::HOST, win, site, limit),
            TopKind::Languages => return rollup_top_dict(conn, dim::LANGUAGE, win, site, limit),
            TopKind::ContentTypes => {
                return rollup_top_dict(conn, dim::CONTENT_TYPE, win, site, limit);
            }
            TopKind::StatusCodes => return rollup_top_int(conn, dim::STATUS, win, site, limit),
            TopKind::Paths => return minute_top_path(conn, win, site, limit),
            TopKind::ClientIps => {
                return minute_top_dict(
                    conn,
                    dim::CLIENT_IP,
                    "client_ip_id",
                    false,
                    win,
                    site,
                    limit,
                );
            }
            TopKind::UserAgents => {
                return minute_top_dict(conn, dim::USER_AGENT, "ua_id", false, win, site, limit);
            }
            TopKind::Referers => {
                return minute_top_dict(conn, dim::REFERER, "referer_id", false, win, site, limit);
            }
        },
        Source::Hour => match kind {
            TopKind::Hosts => return rollup_top_dict(conn, dim::HOST, win, site, limit),
            TopKind::Languages => return rollup_top_dict(conn, dim::LANGUAGE, win, site, limit),
            TopKind::ContentTypes => {
                return rollup_top_dict(conn, dim::CONTENT_TYPE, win, site, limit);
            }
            TopKind::StatusCodes => return rollup_top_int(conn, dim::STATUS, win, site, limit),
            // The heavy-key rollups only hold TOP_KEEP keys per hour, so deeper lists read raw rows.
            TopKind::Paths if limit <= TOP_N => return rollup_top_path(conn, win, site, limit),
            TopKind::ClientIps if limit <= TOP_N => {
                return rollup_top_dict(conn, dim::CLIENT_IP, win, site, limit);
            }
            TopKind::UserAgents if limit <= TOP_N => {
                return rollup_top_dict(conn, dim::USER_AGENT, win, site, limit);
            }
            TopKind::Referers if limit <= TOP_N => {
                return rollup_top_dict(conn, dim::REFERER, win, site, limit);
            }
            _ => {}
        },
    }
    top_raw(conn, kind, &raw_where(win, site), limit)
}

struct Totals {
    requests: u64,
    bytes_in: u64,
    bytes_out: u64,
    blocked: u64,
    ms_sum: u64,
    classes: [u64; 6],
    lat: Vec<u64>,
    sizes_cum: [u64; SIZE_LEN],
}

fn raw_totals(conn: &Connection, w: &Where) -> Result<Totals> {
    let mut sql = String::from(
        "SELECT count(*), coalesce(sum(bytes_in), 0), coalesce(sum(bytes_out), 0), \
         coalesce(sum(blocked_id IS NOT NULL), 0), coalesce(sum(total_ms), 0), \
         coalesce(sum(status < 100 OR status >= 600), 0), coalesce(sum(status / 100 = 1), 0), \
         coalesce(sum(status / 100 = 2), 0), coalesce(sum(status / 100 = 3), 0), \
         coalesce(sum(status / 100 = 4), 0), coalesce(sum(status / 100 = 5), 0)",
    );
    for le in SIZE_LES {
        let _ = write!(sql, ", coalesce(sum(bytes_out <= {le}), 0)");
    }
    sql.push_str(" FROM requests r");
    sql.push_str(&w.clause());
    let mut t = conn.query_row(&sql, params_from_iter(w.bind([]).iter()), |r| {
        let mut classes = [0u64; 6];
        for (i, c) in classes.iter_mut().enumerate() {
            *c = count_col(r, 5 + i)?;
        }
        let mut sizes_cum = [0u64; SIZE_LEN];
        for (i, s) in sizes_cum.iter_mut().take(SIZE_LES.len()).enumerate() {
            *s = count_col(r, 11 + i)?;
        }
        Ok(Totals {
            requests: count_col(r, 0)?,
            bytes_in: count_col(r, 1)?,
            bytes_out: count_col(r, 2)?,
            blocked: count_col(r, 3)?,
            ms_sum: count_col(r, 4)?,
            classes,
            lat: vec![0; LAT_LEN],
            sizes_cum,
        })
    })?;
    t.sizes_cum[SIZE_LEN - 1] = t.requests;
    let sql = format!(
        "SELECT total_ms, count(*) FROM requests r{} GROUP BY total_ms",
        w.clause()
    );
    for (ms, n) in collect(conn, &sql, &w.bind([]), |r| {
        Ok((r.get::<_, i64>(0)?, count_col(r, 1)?))
    })? {
        if let Some(slot) = t.lat.get_mut(lat_index(to_u32(ms))) {
            *slot += n;
        }
    }
    Ok(t)
}

fn rollup_totals(conn: &Connection, l: &Level, rw: &Where) -> Result<Totals> {
    let sql = format!(
        "SELECT coalesce(sum(requests), 0), coalesce(sum(bytes_in), 0), coalesce(sum(bytes_out), 0), \
         coalesce(sum(blocked), 0), coalesce(sum(ms_sum), 0), coalesce(sum(s0), 0), coalesce(sum(s1), 0), \
         coalesce(sum(s2), 0), coalesce(sum(s3), 0), coalesce(sum(s4), 0), coalesce(sum(s5), 0) \
         FROM {}{}",
        l.rollup,
        rw.clause()
    );
    let mut t = conn.query_row(&sql, params_from_iter(rw.bind([]).iter()), |r| {
        let mut classes = [0u64; 6];
        for (i, c) in classes.iter_mut().enumerate() {
            *c = count_col(r, 5 + i)?;
        }
        Ok(Totals {
            requests: count_col(r, 0)?,
            bytes_in: count_col(r, 1)?,
            bytes_out: count_col(r, 2)?,
            blocked: count_col(r, 3)?,
            ms_sum: count_col(r, 4)?,
            classes,
            lat: vec![0; LAT_LEN],
            sizes_cum: [0; SIZE_LEN],
        })
    })?;
    let sql = format!(
        "SELECT series, bucket, sum(n) FROM {}{} GROUP BY series, bucket",
        l.hist,
        rw.clause()
    );
    let mut sizes = [0u64; SIZE_LEN];
    for (s, bucket, n) in collect(conn, &sql, &rw.bind([]), |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, count_col(r, 2)?))
    })? {
        let Ok(bucket) = usize::try_from(bucket) else {
            continue;
        };
        if s == i64::from(series::LATENCY) {
            if let Some(slot) = t.lat.get_mut(bucket) {
                *slot += n;
            }
        } else if let Some(slot) = sizes.get_mut(bucket) {
            *slot += n;
        }
    }
    let mut acc = 0;
    for (cum, n) in t.sizes_cum.iter_mut().zip(sizes) {
        acc += n;
        *cum = acc;
    }
    Ok(t)
}

fn assemble(
    t: Totals,
    methods: BTreeMap<String, u64>,
    content_types: Vec<TopItem>,
    tops: [Vec<TopItem>; 5],
) -> Summary {
    const CLASSES: [&str; 6] = ["other", "1xx", "2xx", "3xx", "4xx", "5xx"];
    let [top_paths, top_ips, top_user_agents, top_hosts, top_blocked] = tops;
    let status = CLASSES
        .iter()
        .zip(t.classes.iter())
        .filter(|(_, n)| **n > 0)
        .map(|(k, n)| (k.to_string(), *n))
        .collect();
    let sizes = t
        .sizes_cum
        .iter()
        .enumerate()
        .map(|(i, c)| SizeBucket {
            le: SIZE_LES.get(i).copied(),
            count: *c,
        })
        .collect();
    let avg_ms = match t.requests {
        0 => 0.0,
        n => t.ms_sum as f64 / n as f64,
    };
    Summary {
        requests: t.requests,
        bytes_in: t.bytes_in,
        bytes_out: t.bytes_out,
        blocked: t.blocked,
        errors_4xx: t.classes[4],
        errors_5xx: t.classes[5],
        avg_ms,
        p50_ms: percentile(&t.lat, t.requests, 50),
        p95_ms: percentile(&t.lat, t.requests, 95),
        p99_ms: percentile(&t.lat, t.requests, 99),
        status,
        methods,
        content_types: content_types
            .into_iter()
            .map(|i| (i.key, i.count))
            .collect(),
        sizes,
        top_paths,
        top_ips,
        top_user_agents,
        top_hosts,
        top_blocked,
    }
}

pub(crate) fn summary(
    conn: &Connection,
    window_secs: u64,
    site: Option<&str>,
    now_ms: i64,
) -> Result<Summary> {
    let conn = &snapshot(conn)?;
    summary_in(conn, &Window::pick(conn, window_secs, now_ms, false)?, site)
}

pub(crate) fn summary_in(conn: &Connection, win: &Window, site: Option<&str>) -> Result<Summary> {
    let site = site.filter(|s| !s.is_empty());
    let raw = raw_where(win, site);
    if win.source != Source::Raw {
        let rw = roll_where(win, site);
        let totals = rollup_totals(conn, win.level(), &rw)?;
        let methods = fold_methods(rollup_top_dict(conn, dim::METHOD, win, site, FOLD_FETCH)?);
        let ctypes = rollup_top_dict(conn, dim::CONTENT_TYPE, win, site, TOP_N)?;
        let hosts = rollup_top_dict(conn, dim::HOST, win, site, TOP_N)?;
        let blocked = rollup_top_dict(conn, dim::BLOCKED, win, site, TOP_N)?;
        let (paths, ips, uas) = if win.source == Source::Minute {
            (
                minute_top_path(conn, win, site, TOP_N)?,
                minute_top_dict(
                    conn,
                    dim::CLIENT_IP,
                    "client_ip_id",
                    false,
                    win,
                    site,
                    TOP_N,
                )?,
                minute_top_dict(conn, dim::USER_AGENT, "ua_id", false, win, site, TOP_N)?,
            )
        } else {
            (
                rollup_top_path(conn, win, site, TOP_N)?,
                rollup_top_dict(conn, dim::CLIENT_IP, win, site, TOP_N)?,
                rollup_top_dict(conn, dim::USER_AGENT, win, site, TOP_N)?,
            )
        };
        return Ok(assemble(
            totals,
            methods,
            ctypes,
            [paths, ips, uas, hosts, blocked],
        ));
    }
    summary_raw(conn, &raw)
}

// The summary of the raw rows a where clause selects.
pub(crate) fn summary_raw(conn: &Connection, raw: &Where) -> Result<Summary> {
    let paths = raw_top_path(conn, raw, TOP_N)?;
    let ips = raw_top_dict(conn, "client_ip_id", raw, TOP_N)?;
    let uas = raw_top_dict(conn, "ua_id", raw, TOP_N)?;
    let totals = raw_totals(conn, raw)?;
    let methods = fold_methods(raw_top_dict(conn, "method_id", raw, FOLD_FETCH)?);
    let ctypes = fold_ctypes(raw_top_dict(conn, "ctype_id", raw, FOLD_FETCH)?, TOP_N);
    let hosts = raw_top_dict(conn, "host_id", raw, TOP_N)?;
    let blocked = raw_top_dict(conn, "blocked_id", raw, TOP_N)?;
    Ok(assemble(
        totals,
        methods,
        ctypes,
        [paths, ips, uas, hosts, blocked],
    ))
}

pub(crate) fn timeseries(
    conn: &Connection,
    window_secs: u64,
    site: Option<&str>,
    now_ms: i64,
) -> Result<Timeseries> {
    let conn = &snapshot(conn)?;
    let win = Window::pick(conn, window_secs, now_ms, true)?;
    timeseries_in(conn, &win, site)
}

pub(crate) type Bucketed = (u64, u64, u64, u64, u64);

pub(crate) fn timeseries_in(
    conn: &Connection,
    win: &Window,
    site: Option<&str>,
) -> Result<Timeseries> {
    let site = site.filter(|s| !s.is_empty());
    let step_secs = win.step / 1000;
    let empty = Timeseries {
        step_secs: step_secs as u64,
        points: Vec::new(),
    };
    if let Some(s) = site
        && !site_known(conn, s)?
    {
        return Ok(empty);
    }
    let map: HashMap<i64, Bucketed> = if win.source != Source::Raw {
        let rw = roll_where(win, site);
        let l = win.level();
        let sql = format!(
            "SELECT {b}, sum(requests), sum(bytes_out), sum(s4 + s5), sum(blocked), sum(ms_sum) \
             FROM {}{} GROUP BY {b}",
            l.rollup,
            rw.clause(),
            b = l.bucket
        );
        bucket_rows(conn, &sql, &rw)?
    } else {
        let w = raw_where(win, site);
        let sql = format!(
            "SELECT (ts - ((ts % {MINUTE_MS}) + {MINUTE_MS}) % {MINUTE_MS}) / {MINUTE_MS}, count(*), \
             coalesce(sum(bytes_out), 0), \
             coalesce(sum(status >= 400 AND status < 600), 0), coalesce(sum(blocked_id IS NOT NULL), 0), \
             coalesce(sum(total_ms), 0) FROM requests r{} GROUP BY 1",
            w.clause()
        );
        bucket_rows(conn, &sql, &w)?
    };
    let mut points = Vec::new();
    for idx in win.first..=win.last {
        let (requests, bytes_out, errors, blocked, ms_sum) =
            map.get(&idx).copied().unwrap_or_default();
        points.push(Point {
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
        });
    }
    Ok(Timeseries {
        step_secs: step_secs as u64,
        points,
    })
}

pub(crate) fn bucket_rows(
    conn: &Connection,
    sql: &str,
    w: &Where,
) -> Result<HashMap<i64, Bucketed>> {
    let rows = collect(conn, sql, &w.bind([]), |r| {
        Ok((
            r.get::<_, i64>(0)?,
            (
                count_col(r, 1)?,
                count_col(r, 2)?,
                count_col(r, 3)?,
                count_col(r, 4)?,
                count_col(r, 5)?,
            ),
        ))
    })?;
    Ok(rows.into_iter().collect())
}

pub(crate) const EVENT_SELECT: &str = "SELECT r.id, r.ts, ip.val, h.val, m.val, r.path, r.query_len, r.status, \
    r.bytes_in, r.bytes_out, r.total_ms, ua.val, rf.val, ct.val, be.val, sv.val, st.val, bl.val, hv.val, \
    ac.val, al.val, ae.val, fs.val, fm.val, fd.val, cu.val, tl.val, r.resp_ms, r.bot_score, bc.val, bs.val \
    FROM requests r \
    LEFT JOIN dict ip ON ip.id = r.client_ip_id \
    LEFT JOIN dict h ON h.id = r.host_id \
    LEFT JOIN dict m ON m.id = r.method_id \
    LEFT JOIN dict ua ON ua.id = r.ua_id \
    LEFT JOIN dict rf ON rf.id = r.referer_id \
    LEFT JOIN dict ct ON ct.id = r.ctype_id \
    LEFT JOIN dict be ON be.id = r.backend_id \
    LEFT JOIN dict sv ON sv.id = r.server_id \
    LEFT JOIN dict st ON st.id = r.site_id \
    LEFT JOIN dict bl ON bl.id = r.blocked_id \
    LEFT JOIN dict hv ON hv.id = r.http_version_id \
    LEFT JOIN dict ac ON ac.id = r.accept_id \
    LEFT JOIN dict al ON al.id = r.accept_lang_id \
    LEFT JOIN dict ae ON ae.id = r.accept_enc_id \
    LEFT JOIN dict fs ON fs.id = r.sfs_id \
    LEFT JOIN dict fm ON fm.id = r.sfm_id \
    LEFT JOIN dict fd ON fd.id = r.sfd_id \
    LEFT JOIN dict cu ON cu.id = r.sec_ch_ua_id \
    LEFT JOIN dict tl ON tl.id = r.tls_id \
    LEFT JOIN dict bc ON bc.id = r.bot_class_id \
    LEFT JOIN dict bs ON bs.id = r.bot_signals_id";

pub(crate) fn decode(row: &Row) -> rusqlite::Result<(i64, LogEvent)> {
    let blocked = match row.get_ref(17)? {
        ValueRef::Text(b) | ValueRef::Blob(b) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    };
    let ev = LogEvent {
        ts_ms: row.get(1)?,
        client_ip: text_col(row, 2)?,
        host: text_col(row, 3)?,
        method: text_col(row, 4)?,
        path: text_col(row, 5)?,
        query_len: to_u32(row.get(6)?),
        status: to_u16(row.get(7)?),
        bytes_in: count_col(row, 8)?,
        bytes_out: count_col(row, 9)?,
        total_ms: to_u32(row.get(10)?),
        user_agent: text_col(row, 11)?,
        referer: text_col(row, 12)?,
        content_type: text_col(row, 13)?,
        backend: text_col(row, 14)?,
        server: text_col(row, 15)?,
        site: text_col(row, 16)?,
        blocked,
        http_version: text_col(row, 18)?,
        accept: text_col(row, 19)?,
        accept_language: text_col(row, 20)?,
        accept_encoding: text_col(row, 21)?,
        sec_fetch_site: text_col(row, 22)?,
        sec_fetch_mode: text_col(row, 23)?,
        sec_fetch_dest: text_col(row, 24)?,
        sec_ch_ua: text_col(row, 25)?,
        tls_version: text_col(row, 26)?,
        resp_ms: to_u32(row.get(27)?),
        bot_score: to_u8(row.get(28)?),
        bot_class: text_col(row, 29)?,
        bot_signals: text_col(row, 30)?,
    };
    Ok((row.get(0)?, ev))
}

// Events matching w in (ts, id) order, optionally resuming after a (ts, id) position for keyset paging.
pub(crate) fn fetch_events(
    conn: &Connection,
    w: &Where,
    newest_first: bool,
    limit: usize,
    after: Option<(i64, i64)>,
) -> Result<Vec<(i64, LogEvent)>> {
    let mut w = w.clone();
    if let Some((ts, id)) = after {
        w.and("ts >= ?", [int(ts)]);
        w.and("(ts, r.id) > (?, ?)", [int(ts), int(id)]);
    }
    let order = if newest_first {
        " ORDER BY r.ts DESC, r.id DESC"
    } else {
        " ORDER BY r.ts ASC, r.id ASC"
    };
    let sql = format!("{EVENT_SELECT}{}{order} LIMIT ?", w.clause());
    collect(conn, &sql, &w.bind([int(to_i64(limit as u64))]), decode)
}

pub(crate) fn requests(
    conn: &Connection,
    filter: &RequestFilter,
    limit: usize,
) -> Result<Vec<LogEvent>> {
    let limit = limit.min(MAX_REQUEST_LIMIT);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut w = Where::default();
    match filter.site.as_deref() {
        None => {}
        Some("") => {
            w.and("site_id = 0", []);
        }
        Some(s) => {
            w.and(dict_eq!("site_id"), dict_params(kind::SITE, s));
        }
    }
    if let Some(status) = filter.status {
        w.and("status = ?", [int(i64::from(status))]);
    }
    if let Some(m) = filter.method.as_deref() {
        w.and(METHOD_NOCASE, dict_params(kind::METHOD, m));
    }
    if let Some(p) = filter.path_contains.as_deref() {
        w.and("instr(path, ?) > 0", [text(p)]);
    }
    if let Some(ip) = filter.ip.as_deref() {
        ip_filter(&mut w, ip);
    }
    if filter.blocked_only {
        w.and("blocked_id IS NOT NULL", []);
    }
    let rows = fetch_events(conn, &w, true, limit, None)?;
    Ok(rows.into_iter().map(|(_, ev)| ev).collect())
}

pub(crate) fn bots(
    conn: &Connection,
    window_secs: u64,
    site: Option<&str>,
    now_ms: i64,
) -> Result<BotSummary> {
    let conn = &snapshot(conn)?;
    let win = Window::pick(conn, window_secs, now_ms, false)?;
    bots_in(conn, &win, site)
}

// Bot breakdown of a prepared window, from rollups or raw rows depending on its source.
pub(crate) fn bots_in(conn: &Connection, win: &Window, site: Option<&str>) -> Result<BotSummary> {
    let site = site.filter(|s| !s.is_empty());
    if win.source == Source::Raw {
        return bots_raw(conn, win.from, win.to, site, TOP_N);
    }
    let rw = roll_where(win, site);
    let sql = format!(
        "SELECT coalesce(sum(requests), 0), coalesce(sum(bot_requests), 0) FROM {}{}",
        win.level().rollup,
        rw.clause()
    );
    let (total, bot) = conn.query_row(&sql, params_from_iter(rw.bind([]).iter()), |r| {
        Ok((count_col(r, 0)?, count_col(r, 1)?))
    })?;
    let classes = rollup_top_dict(conn, dim::BOT_CLASS, win, site, TOP_N)?;
    let signals = rollup_top_dict(conn, dim::SIGNAL, win, site, TOP_N)?;
    let mut scores = vec![(0u64, 0u64); SCORE_KEYS.len()];
    for it in rollup_top_int(conn, dim::SCORE, win, site, SCORE_KEYS.len())? {
        if let Some(slot) = it.key.parse::<usize>().ok().and_then(|i| scores.get_mut(i)) {
            *slot = (it.count, it.bytes);
        }
    }
    let agents = if win.source == Source::Minute {
        minute_top_dict(conn, dim::BOT_AGENT, "ua_id", true, win, site, TOP_N)?
    } else {
        rollup_top_dict(conn, dim::BOT_AGENT, win, site, TOP_N)?
    };
    Ok(bot_summary(total, bot, classes, signals, agents, &scores))
}

// Bot breakdown computed from raw rows in [from, to).
pub(crate) fn bots_raw(
    conn: &Connection,
    from: i64,
    to: i64,
    site: Option<&str>,
    n: usize,
) -> Result<BotSummary> {
    let site = site.filter(|s| !s.is_empty());
    bots_from_where(conn, &range_where(from, to, site), n)
}

// Bot breakdown of the raw rows a where clause selects.
pub(crate) fn bots_from_where(conn: &Connection, w: &Where, n: usize) -> Result<BotSummary> {
    let total = count_requests(conn, w)?;
    let mut bot_w = w.clone();
    bot_w.and(NOT_HUMAN, dict_params(kind::BOT_CLASS, "human"));
    let bot = count_requests(conn, &bot_w)?;
    let classes = raw_top_dict(conn, "bot_class_id", w, n)?;
    let agents = raw_top_dict(conn, "ua_id", &bot_w, n)?;
    let mut merged: HashMap<String, (u64, u64)> = HashMap::new();
    for it in raw_top_dict(conn, "bot_signals_id", w, FOLD_FETCH)? {
        for sig in split_signals(&it.key) {
            let e = merged.entry(sig.to_string()).or_default();
            e.0 += it.count;
            e.1 += it.bytes;
        }
    }
    let mut signals: Vec<TopItem> = merged
        .into_iter()
        .map(|(key, (count, bytes))| TopItem { key, count, bytes })
        .collect();
    sort_items(&mut signals);
    signals.truncate(n);
    let mut classified = w.clone();
    classified.and("bot_class_id IS NOT NULL", []);
    let sql = format!(
        "SELECT min(bot_score / 20, 4), count(*), coalesce(sum(bytes_out), 0) FROM requests r{} GROUP BY 1",
        classified.clause()
    );
    let mut scores = vec![(0u64, 0u64); SCORE_KEYS.len()];
    for (i, count, bytes) in collect(conn, &sql, &classified.bind([]), |r| {
        Ok((r.get::<_, i64>(0)?, count_col(r, 1)?, count_col(r, 2)?))
    })? {
        if let Some(slot) = usize::try_from(i).ok().and_then(|i| scores.get_mut(i)) {
            *slot = (count, bytes);
        }
    }
    Ok(bot_summary(total, bot, classes, signals, agents, &scores))
}

fn count_requests(conn: &Connection, w: &Where) -> Result<u64> {
    let sql = format!("SELECT count(*) FROM requests r{}", w.clause());
    let n = conn.query_row(&sql, params_from_iter(w.bind([]).iter()), |r| {
        count_col(r, 0)
    })?;
    Ok(n)
}

fn bot_summary(
    total: u64,
    bot: u64,
    classes: Vec<TopItem>,
    signals: Vec<TopItem>,
    agents: Vec<TopItem>,
    scores: &[(u64, u64)],
) -> BotSummary {
    BotSummary {
        total_requests: total,
        bot_requests: bot,
        bot_share_pct: if total == 0 {
            0.0
        } else {
            bot as f64 * 100.0 / total as f64
        },
        classes,
        signals,
        agents,
        score_buckets: SCORE_KEYS
            .iter()
            .zip(scores)
            .map(|(k, (count, bytes))| TopItem {
                key: (*k).to_string(),
                count: *count,
                bytes: *bytes,
            })
            .collect(),
    }
}

// Filter for exports and ad-hoc scans; each present field adds one fixed fragment and its bound values.
pub(crate) fn export_where(f: &crate::export::ExportFilter) -> Where {
    let mut w = Where::default();
    if let Some(v) = f.from_ms {
        w.and("ts >= ?", [int(v)]);
    }
    if let Some(v) = f.to_ms {
        w.and("ts < ?", [int(v)]);
    }
    site_filter(&mut w, f.site.as_deref());
    if let Some(v) = f.status_min {
        w.and("status >= ?", [int(i64::from(v))]);
    }
    if let Some(v) = f.status_max {
        w.and("status <= ?", [int(i64::from(v))]);
    }
    match f.bot_class.as_deref() {
        None => {}
        Some("") => {
            w.and("bot_class_id IS NULL", []);
        }
        Some(c) => {
            w.and(dict_eq!("bot_class_id"), dict_params(kind::BOT_CLASS, c));
        }
    }
    if let Some(v) = f.min_bot_score {
        w.and("bot_score >= ?", [int(i64::from(v))]);
    }
    if let Some(h) = f.host.as_deref() {
        w.and(dict_eq!("host_id"), dict_params(kind::HOST, h));
    }
    if let Some(p) = f.path_prefix.as_deref().filter(|p| !p.is_empty()) {
        // U+10FFFF sorts after every other code point, so the pair is a half-open prefix range
        let upper = format!("{p}\u{10FFFF}");
        w.and("path >= ? AND path <= ?", [text(p), Value::Text(upper)]);
    }
    if let Some(ip) = f.client_ip.as_deref() {
        ip_filter(&mut w, ip);
    }
    if let Some(m) = f.method.as_deref() {
        w.and(METHOD_NOCASE, dict_params(kind::METHOD, m));
    }
    w
}
