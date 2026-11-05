use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use cite_edge::analytics::{Point, RequestFilter, SizeBucket, Summary, Timeseries, TopItem};
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, Row, params, params_from_iter};

use crate::error::Result;
use crate::hist::{LAT_LEN, SIZE_LEN, SIZE_LES, lat_index, percentile};
use crate::limits::{
    HOUR_MS, MAX_REQUEST_LIMIT, MAX_TOP_LIMIT, MAX_WINDOW_SECS, METHOD_CAP, MINUTE_MS,
    MINUTE_STEP_MAX_WINDOW_SECS, ROLLUP_MIN_WINDOW_SECS, TOP_N,
};
use crate::schema::{ALL_SITES, dim, kind, series};
use crate::util::{
    ascii_upper, from_i64, normalize_ctype, split_signals, to_i64, to_u8, to_u16, to_u32,
};

const SCORE_KEYS: [&str; 5] = ["0-19", "20-39", "40-59", "60-79", "80-100"];
// Groups fetched before folding in Rust (content types, methods, signal lists); bounds work on hostile cardinality.
const FOLD_FETCH: usize = 5000;
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

fn dict_params(k: u8, val: &str) -> [Value; 2] {
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

fn collect<T>(
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

// Bucket-aligned time range for a window, as bucket indexes and as milliseconds [from, to).
pub(crate) struct Window {
    pub(crate) first: i64,
    pub(crate) last: i64,
    pub(crate) step: i64,
    pub(crate) from: i64,
    pub(crate) to: i64,
    pub(crate) hourly: bool,
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
            hourly,
        }
    }

    fn for_summary(window_secs: u64, now_ms: i64) -> Self {
        Self::new(window_secs, now_ms, window_secs > ROLLUP_MIN_WINDOW_SECS)
    }
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

fn roll_where(win: &Window, site: Option<&str>) -> Where {
    let mut w = Where::default();
    w.and("hour >= ?", [int(win.first)])
        .and("hour <= ?", [int(win.last)]);
    site_filter(&mut w, site);
    w
}

// rollup_dim and rollup_path rows exist per site and summed under ALL_SITES, so one site range serves either query.
fn scope_where(win: &Window, site: Option<&str>, d: Option<u8>) -> Where {
    let mut w = Where::default();
    if let Some(d) = d {
        w.and("dim = ?", [int(i64::from(d))]);
    }
    w.and("hour >= ?", [int(win.first)])
        .and("hour <= ?", [int(win.last)]);
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

fn raw_top_dict(
    conn: &Connection,
    col: &'static str,
    w: &Where,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let sql = format!(
        "SELECT d.val, count(*), coalesce(sum(r.bytes_out), 0) FROM requests r \
         JOIN dict d ON d.id = r.{col}{} GROUP BY r.{col} ORDER BY 2 DESC, 1 ASC LIMIT ?",
        w.clause()
    );
    run_top(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

fn raw_top_path(conn: &Connection, w: &Where, limit: usize) -> Result<Vec<TopItem>> {
    let mut w = w.clone();
    w.and("path <> ''", []);
    let sql = format!(
        "SELECT r.path, count(*), coalesce(sum(r.bytes_out), 0) FROM requests r{} \
         GROUP BY r.path ORDER BY 2 DESC, 1 ASC LIMIT ?",
        w.clause()
    );
    run_top(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

fn raw_top_status(conn: &Connection, w: &Where, limit: usize) -> Result<Vec<TopItem>> {
    let sql = format!(
        "SELECT r.status, count(*), coalesce(sum(r.bytes_out), 0) FROM requests r{} \
         GROUP BY r.status ORDER BY 2 DESC, 1 ASC LIMIT ?",
        w.clause()
    );
    run_top_int(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

// Groups first and joins the dictionary only for groups at or above the limit-th count, so the join stays small.
fn rollup_top_dict(
    conn: &Connection,
    d: u8,
    win: &Window,
    site: Option<&str>,
    limit: usize,
) -> Result<Vec<TopItem>> {
    let w = scope_where(win, site, Some(d));
    let sql = format!(
        "WITH g AS MATERIALIZED (SELECT key_id, sum(n) AS n, sum(bytes) AS b FROM rollup_dim{} GROUP BY key_id) \
         SELECT dc.val, g.n, g.b FROM g JOIN dict dc ON dc.id = g.key_id \
         WHERE g.n >= coalesce((SELECT n FROM g ORDER BY n DESC LIMIT 1 OFFSET ?), 0) \
         ORDER BY 2 DESC, 1 ASC LIMIT ?",
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
        "SELECT path, sum(n), sum(bytes) FROM rollup_path{} GROUP BY path ORDER BY 2 DESC, 1 ASC LIMIT ?",
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
        "SELECT x.key_id, sum(x.n), sum(x.bytes) FROM rollup_dim x{} \
         GROUP BY x.key_id ORDER BY 2 DESC, 1 ASC LIMIT ?",
        w.clause()
    );
    run_top_int(conn, &sql, &w.bind([int(to_i64(limit as u64))]))
}

// Merges raw content types under their normalised media type.
fn fold_ctypes(items: Vec<TopItem>, limit: usize) -> Vec<TopItem> {
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
    sort_items(&mut out);
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
    match kind {
        TopKind::Paths => raw_top_path(conn, w, limit),
        TopKind::Hosts => raw_top_dict(conn, "host_id", w, limit),
        TopKind::Referers => raw_top_dict(conn, "referer_id", w, limit),
        TopKind::UserAgents => raw_top_dict(conn, "ua_id", w, limit),
        TopKind::ClientIps => raw_top_dict(conn, "client_ip_id", w, limit),
        TopKind::Languages => raw_top_dict(conn, "accept_lang_id", w, limit),
        TopKind::StatusCodes => raw_top_status(conn, w, limit),
        TopKind::ContentTypes => Ok(fold_ctypes(
            raw_top_dict(conn, "ctype_id", w, FOLD_FETCH)?,
            limit,
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
    let site = site.filter(|s| !s.is_empty());
    let win = Window::for_summary(window_secs, now_ms);
    if win.hourly {
        match kind {
            TopKind::Hosts => return rollup_top_dict(conn, dim::HOST, &win, site, limit),
            TopKind::Languages => return rollup_top_dict(conn, dim::LANGUAGE, &win, site, limit),
            TopKind::ContentTypes => {
                return rollup_top_dict(conn, dim::CONTENT_TYPE, &win, site, limit);
            }
            TopKind::StatusCodes => return rollup_top_int(conn, dim::STATUS, &win, site, limit),
            // The heavy-key rollups only hold TOP_KEEP keys per hour, so deeper lists read raw rows.
            TopKind::Paths if limit <= TOP_N => return rollup_top_path(conn, &win, site, limit),
            TopKind::ClientIps if limit <= TOP_N => {
                return rollup_top_dict(conn, dim::CLIENT_IP, &win, site, limit);
            }
            TopKind::UserAgents if limit <= TOP_N => {
                return rollup_top_dict(conn, dim::USER_AGENT, &win, site, limit);
            }
            TopKind::Referers if limit <= TOP_N => {
                return rollup_top_dict(conn, dim::REFERER, &win, site, limit);
            }
            _ => {}
        }
    }
    top_raw(conn, kind, &raw_where(&win, site), limit)
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

fn rollup_totals(conn: &Connection, rw: &Where) -> Result<Totals> {
    let sql = format!(
        "SELECT coalesce(sum(requests), 0), coalesce(sum(bytes_in), 0), coalesce(sum(bytes_out), 0), \
         coalesce(sum(blocked), 0), coalesce(sum(ms_sum), 0), coalesce(sum(s0), 0), coalesce(sum(s1), 0), \
         coalesce(sum(s2), 0), coalesce(sum(s3), 0), coalesce(sum(s4), 0), coalesce(sum(s5), 0) \
         FROM rollup{}",
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
        "SELECT series, bucket, sum(n) FROM rollup_hist{} GROUP BY series, bucket",
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
    summary_in(conn, &Window::for_summary(window_secs, now_ms), site)
}

pub(crate) fn summary_in(conn: &Connection, win: &Window, site: Option<&str>) -> Result<Summary> {
    let site = site.filter(|s| !s.is_empty());
    let raw = raw_where(win, site);
    if win.hourly {
        let rw = roll_where(win, site);
        let totals = rollup_totals(conn, &rw)?;
        let methods = fold_methods(rollup_top_dict(conn, dim::METHOD, win, site, FOLD_FETCH)?);
        let ctypes = rollup_top_dict(conn, dim::CONTENT_TYPE, win, site, TOP_N)?;
        let hosts = rollup_top_dict(conn, dim::HOST, win, site, TOP_N)?;
        let blocked = rollup_top_dict(conn, dim::BLOCKED, win, site, TOP_N)?;
        let paths = rollup_top_path(conn, win, site, TOP_N)?;
        let ips = rollup_top_dict(conn, dim::CLIENT_IP, win, site, TOP_N)?;
        let uas = rollup_top_dict(conn, dim::USER_AGENT, win, site, TOP_N)?;
        return Ok(assemble(
            totals,
            methods,
            ctypes,
            [paths, ips, uas, hosts, blocked],
        ));
    }
    let paths = raw_top_path(conn, &raw, TOP_N)?;
    let ips = raw_top_dict(conn, "client_ip_id", &raw, TOP_N)?;
    let uas = raw_top_dict(conn, "ua_id", &raw, TOP_N)?;
    let totals = raw_totals(conn, &raw)?;
    let methods = fold_methods(raw_top_dict(conn, "method_id", &raw, FOLD_FETCH)?);
    let ctypes = fold_ctypes(raw_top_dict(conn, "ctype_id", &raw, FOLD_FETCH)?, TOP_N);
    let hosts = raw_top_dict(conn, "host_id", &raw, TOP_N)?;
    let blocked = raw_top_dict(conn, "blocked_id", &raw, TOP_N)?;
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
    let win = Window::new(
        window_secs,
        now_ms,
        window_secs > MINUTE_STEP_MAX_WINDOW_SECS,
    );
    timeseries_in(conn, &win, site)
}

type Bucketed = (u64, u64, u64, u64, u64);

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
    let map: HashMap<i64, Bucketed> = if win.hourly {
        let rw = roll_where(win, site);
        let sql = format!(
            "SELECT hour, sum(requests), sum(bytes_out), sum(s4 + s5), sum(blocked), sum(ms_sum) \
             FROM rollup{} GROUP BY hour",
            rw.clause()
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

fn bucket_rows(conn: &Connection, sql: &str, w: &Where) -> Result<HashMap<i64, Bucketed>> {
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

const EVENT_SELECT: &str = "SELECT r.id, r.ts, ip.val, h.val, m.val, r.path, r.query_len, r.status, \
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

fn decode(row: &Row) -> rusqlite::Result<(i64, LogEvent)> {
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
    let site = site.filter(|s| !s.is_empty());
    let win = Window::for_summary(window_secs, now_ms);
    if !win.hourly {
        return bots_raw(conn, win.from, win.to, site, TOP_N);
    }
    let rw = roll_where(&win, site);
    let sql = format!(
        "SELECT coalesce(sum(requests), 0), coalesce(sum(bot_requests), 0) FROM rollup{}",
        rw.clause()
    );
    let (total, bot) = conn.query_row(&sql, params_from_iter(rw.bind([]).iter()), |r| {
        Ok((count_col(r, 0)?, count_col(r, 1)?))
    })?;
    let classes = rollup_top_dict(conn, dim::BOT_CLASS, &win, site, TOP_N)?;
    let signals = rollup_top_dict(conn, dim::SIGNAL, &win, site, TOP_N)?;
    let mut scores = vec![(0u64, 0u64); SCORE_KEYS.len()];
    for it in rollup_top_int(conn, dim::SCORE, &win, site, SCORE_KEYS.len())? {
        if let Some(slot) = it.key.parse::<usize>().ok().and_then(|i| scores.get_mut(i)) {
            *slot = (it.count, it.bytes);
        }
    }
    let agents = rollup_top_dict(conn, dim::BOT_AGENT, &win, site, TOP_N)?;
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
    let w = range_where(from, to, site);
    let total = count_requests(conn, &w)?;
    let mut bot_w = w.clone();
    bot_w.and(NOT_HUMAN, dict_params(kind::BOT_CLASS, "human"));
    let bot = count_requests(conn, &bot_w)?;
    let classes = raw_top_dict(conn, "bot_class_id", &w, n)?;
    let agents = raw_top_dict(conn, "ua_id", &bot_w, n)?;
    let mut merged: HashMap<String, (u64, u64)> = HashMap::new();
    for it in raw_top_dict(conn, "bot_signals_id", &w, FOLD_FETCH)? {
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
