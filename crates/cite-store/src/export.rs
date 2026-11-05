use std::io::Write;

use cite_edge::analytics::TopItem;
use cite_edge::model::LogEvent;
use rusqlite::params_from_iter;

use crate::error::Result;
use crate::limits::{DEFAULT_EXPORT_LIMIT, HOUR_MS};
use crate::queries::{self, TopKind, Where, int};
use crate::store::Inner;
use crate::util::{iso_utc, to_i64};

// Rows fetched per keyset page; the read connection is released between pages so long exports never pin a snapshot.
const PAGE: usize = 2000;
const BOT_ROWS: usize = 1000;

/// Request export columns in their stable order: ISO-8601 UTC timestamp, epoch milliseconds, then every LogEvent field.
pub const REQUEST_COLUMNS: [&str; 31] = [
    "timestamp",
    "ts_ms",
    "client_ip",
    "host",
    "method",
    "path",
    "query_len",
    "status",
    "bytes_in",
    "bytes_out",
    "total_ms",
    "user_agent",
    "referer",
    "content_type",
    "backend",
    "server",
    "site",
    "blocked",
    "http_version",
    "accept",
    "accept_language",
    "accept_encoding",
    "sec_fetch_site",
    "sec_fetch_mode",
    "sec_fetch_dest",
    "sec_ch_ua",
    "tls_version",
    "resp_ms",
    "bot_score",
    "bot_class",
    "bot_signals",
];

/// Hourly rollup export columns; one row per hour and site.
pub const HOURLY_COLUMNS: [&str; 16] = [
    "hour",
    "hour_ts_ms",
    "site",
    "requests",
    "bytes_in",
    "bytes_out",
    "status_other",
    "status_1xx",
    "status_2xx",
    "status_3xx",
    "status_4xx",
    "status_5xx",
    "blocked",
    "bot_requests",
    "ms_sum",
    "avg_ms",
];

/// Bot export columns; section is summary, class, signal, agent or score_bucket.
pub const BOT_COLUMNS: [&str; 4] = ["section", "key", "count", "bytes"];

/// Top export columns.
pub const TOP_COLUMNS: [&str; 3] = ["key", "count", "bytes"];

/// What an export contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// Every request row matching the filter, oldest first.
    Requests,
    /// Hourly rollup rows; honours from_ms, to_ms (hour granularity), site and limit.
    Hourly,
    /// Class, signal, agent and score breakdown over raw rows; honours from_ms, to_ms, site and limit.
    Bots,
    /// Highest-count values of one dimension over raw rows; honours from_ms, to_ms, site and limit.
    Top(TopKind),
}

/// Row selection for exports; from_ms is inclusive, to_ms exclusive, status bounds inclusive.
#[derive(Debug, Clone, Default)]
pub struct ExportFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub site: Option<String>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub bot_class: Option<String>,
    pub min_bot_score: Option<u8>,
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    /// Row cap; None means 1,000,000. A larger value is honoured when the caller asks for it explicitly.
    pub limit: Option<u64>,
}

pub(crate) enum Cell<'a> {
    Text(&'a str),
    Int(i64),
    Float(f64),
}

pub(crate) trait Sink {
    fn header(&mut self, cols: &[&str]) -> Result<()>;
    fn row(&mut self, cells: &[Cell<'_>]) -> Result<()>;
}

pub(crate) struct CsvSink<W: Write> {
    out: W,
}

impl<W: Write> CsvSink<W> {
    pub(crate) fn new(out: W) -> Self {
        Self { out }
    }

    pub(crate) fn finish(mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

// Quotes per RFC 4180 and, for text cells, defuses spreadsheet formulas with a leading apostrophe.
fn csv_field(out: &mut impl Write, s: &str, neutralise: bool) -> std::io::Result<()> {
    let formula = neutralise
        && matches!(
            s.as_bytes().first(),
            Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r')
        );
    let quoted = s.bytes().any(|b| matches!(b, b',' | b'"' | b'\r' | b'\n'));
    if quoted {
        out.write_all(b"\"")?;
    }
    if formula {
        out.write_all(b"'")?;
    }
    if quoted {
        let mut rest = s;
        while let Some(i) = rest.find('"') {
            out.write_all(&rest.as_bytes()[..=i])?;
            out.write_all(b"\"")?;
            rest = &rest[i + 1..];
        }
        out.write_all(rest.as_bytes())?;
        out.write_all(b"\"")
    } else {
        out.write_all(s.as_bytes())
    }
}

impl<W: Write> Sink for CsvSink<W> {
    fn header(&mut self, cols: &[&str]) -> Result<()> {
        for (i, c) in cols.iter().enumerate() {
            if i > 0 {
                self.out.write_all(b",")?;
            }
            csv_field(&mut self.out, c, false)?;
        }
        self.out.write_all(b"\r\n")?;
        Ok(())
    }

    fn row(&mut self, cells: &[Cell<'_>]) -> Result<()> {
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                self.out.write_all(b",")?;
            }
            match cell {
                Cell::Text(s) => csv_field(&mut self.out, s, true)?,
                Cell::Int(n) => write!(self.out, "{n}")?,
                Cell::Float(f) => write!(self.out, "{f}")?,
            }
        }
        self.out.write_all(b"\r\n")?;
        Ok(())
    }
}

pub(crate) struct NdjsonSink<W: Write> {
    out: W,
    cols: Vec<String>,
}

impl<W: Write> NdjsonSink<W> {
    pub(crate) fn new(out: W) -> Self {
        Self {
            out,
            cols: Vec::new(),
        }
    }

    pub(crate) fn finish(mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

impl<W: Write> Sink for NdjsonSink<W> {
    fn header(&mut self, cols: &[&str]) -> Result<()> {
        self.cols = cols.iter().map(|c| (*c).to_string()).collect();
        Ok(())
    }

    fn row(&mut self, cells: &[Cell<'_>]) -> Result<()> {
        self.out.write_all(b"{")?;
        for (i, (col, cell)) in self.cols.iter().zip(cells).enumerate() {
            if i > 0 {
                self.out.write_all(b",")?;
            }
            serde_json::to_writer(&mut self.out, col)?;
            self.out.write_all(b":")?;
            match cell {
                Cell::Text(s) => serde_json::to_writer(&mut self.out, s)?,
                Cell::Int(n) => write!(self.out, "{n}")?,
                Cell::Float(f) => serde_json::to_writer(&mut self.out, f)?,
            }
        }
        self.out.write_all(b"}\n")?;
        Ok(())
    }
}

pub(crate) fn run(
    inner: &Inner,
    sink: &mut dyn Sink,
    kind: ExportKind,
    f: &ExportFilter,
) -> Result<u64> {
    let cap = f.limit.unwrap_or(DEFAULT_EXPORT_LIMIT);
    match kind {
        ExportKind::Requests => requests(inner, sink, f, cap),
        ExportKind::Hourly => hourly(inner, sink, f, cap),
        ExportKind::Bots => bots(inner, sink, f, cap),
        ExportKind::Top(k) => top(inner, sink, f, k, cap),
    }
}

fn write_event(sink: &mut dyn Sink, ev: &LogEvent) -> Result<()> {
    let iso = iso_utc(ev.ts_ms);
    let blocked = ev.blocked.as_deref().unwrap_or("");
    sink.row(&[
        Cell::Text(&iso),
        Cell::Int(ev.ts_ms),
        Cell::Text(&ev.client_ip),
        Cell::Text(&ev.host),
        Cell::Text(&ev.method),
        Cell::Text(&ev.path),
        Cell::Int(i64::from(ev.query_len)),
        Cell::Int(i64::from(ev.status)),
        Cell::Int(to_i64(ev.bytes_in)),
        Cell::Int(to_i64(ev.bytes_out)),
        Cell::Int(i64::from(ev.total_ms)),
        Cell::Text(&ev.user_agent),
        Cell::Text(&ev.referer),
        Cell::Text(&ev.content_type),
        Cell::Text(&ev.backend),
        Cell::Text(&ev.server),
        Cell::Text(&ev.site),
        Cell::Text(blocked),
        Cell::Text(&ev.http_version),
        Cell::Text(&ev.accept),
        Cell::Text(&ev.accept_language),
        Cell::Text(&ev.accept_encoding),
        Cell::Text(&ev.sec_fetch_site),
        Cell::Text(&ev.sec_fetch_mode),
        Cell::Text(&ev.sec_fetch_dest),
        Cell::Text(&ev.sec_ch_ua),
        Cell::Text(&ev.tls_version),
        Cell::Int(i64::from(ev.resp_ms)),
        Cell::Int(i64::from(ev.bot_score)),
        Cell::Text(&ev.bot_class),
        Cell::Text(&ev.bot_signals),
    ])
}

fn requests(inner: &Inner, sink: &mut dyn Sink, f: &ExportFilter, cap: u64) -> Result<u64> {
    sink.header(&REQUEST_COLUMNS)?;
    let w = queries::export_where(f);
    let mut written = 0u64;
    let mut after: Option<(i64, i64)> = None;
    while written < cap {
        let want = usize::try_from((cap - written).min(PAGE as u64)).unwrap_or(PAGE);
        let page = inner.read(|c| queries::fetch_events(c, &w, false, want, after))?;
        for (_, ev) in &page {
            write_event(sink, ev)?;
        }
        written += page.len() as u64;
        let Some((id, last)) = page.last() else {
            break;
        };
        after = Some((last.ts_ms, *id));
        if page.len() < want {
            break;
        }
    }
    Ok(written)
}

fn hourly(inner: &Inner, sink: &mut dyn Sink, f: &ExportFilter, cap: u64) -> Result<u64> {
    sink.header(&HOURLY_COLUMNS)?;
    let mut w = Where::default();
    if let Some(v) = f.from_ms {
        w.and("hour >= ?", [int(v.div_euclid(HOUR_MS))]);
    }
    if let Some(v) = f.to_ms {
        w.and(
            "hour < ?",
            [int(v.saturating_add(HOUR_MS - 1).div_euclid(HOUR_MS))],
        );
    }
    queries::site_filter(&mut w, f.site.as_deref());
    let mut written = 0u64;
    let mut after: Option<(i64, i64)> = None;
    while written < cap {
        let want = usize::try_from((cap - written).min(PAGE as u64)).unwrap_or(PAGE);
        let mut pw = w.clone();
        if let Some((hour, site)) = after {
            pw.and("(x.hour, x.site_id) > (?, ?)", [int(hour), int(site)]);
        }
        let sql = format!(
            "SELECT x.hour, x.site_id, sn.val, x.requests, x.bytes_in, x.bytes_out, x.s0, x.s1, x.s2, x.s3, x.s4, \
             x.s5, x.blocked, x.bot_requests, x.ms_sum FROM rollup x LEFT JOIN dict sn ON sn.id = x.site_id{} \
             ORDER BY x.hour, x.site_id LIMIT ?",
            pw.clause()
        );
        let params = pw.bind([int(to_i64(want as u64))]);
        let page = inner.read(|c| {
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt.query_map(params_from_iter(params.iter()), |r| {
                let mut n = [0i64; 12];
                for (i, slot) in n.iter_mut().enumerate() {
                    *slot = r.get(3 + i)?;
                }
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    n,
                ))
            })?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        })?;
        for (hour, _, site, n) in &page {
            let ts = hour.saturating_mul(HOUR_MS);
            let iso = iso_utc(ts);
            let avg = if n[0] > 0 {
                n[11] as f64 / n[0] as f64
            } else {
                0.0
            };
            sink.row(&[
                Cell::Text(&iso),
                Cell::Int(ts),
                Cell::Text(site.as_deref().unwrap_or("")),
                Cell::Int(n[0]),
                Cell::Int(n[1]),
                Cell::Int(n[2]),
                Cell::Int(n[3]),
                Cell::Int(n[4]),
                Cell::Int(n[5]),
                Cell::Int(n[6]),
                Cell::Int(n[7]),
                Cell::Int(n[8]),
                Cell::Int(n[9]),
                Cell::Int(n[10]),
                Cell::Int(n[11]),
                Cell::Float(avg),
            ])?;
        }
        written += page.len() as u64;
        let Some((hour, site_id, _, _)) = page.last() else {
            break;
        };
        after = Some((*hour, *site_id));
        if page.len() < want {
            break;
        }
    }
    Ok(written)
}

fn emit(
    sink: &mut dyn Sink,
    section: &str,
    items: &[TopItem],
    written: &mut u64,
    cap: u64,
) -> Result<()> {
    for it in items {
        if *written >= cap {
            break;
        }
        sink.row(&[
            Cell::Text(section),
            Cell::Text(&it.key),
            Cell::Int(to_i64(it.count)),
            Cell::Int(to_i64(it.bytes)),
        ])?;
        *written += 1;
    }
    Ok(())
}

fn bots(inner: &Inner, sink: &mut dyn Sink, f: &ExportFilter, cap: u64) -> Result<u64> {
    sink.header(&BOT_COLUMNS)?;
    let from = f.from_ms.unwrap_or(i64::MIN);
    let to = f.to_ms.unwrap_or(i64::MAX);
    let summary =
        inner.read_long(|c| queries::bots_raw(c, from, to, f.site.as_deref(), BOT_ROWS))?;
    let mut written = 0u64;
    let totals = [
        TopItem {
            key: "total_requests".into(),
            count: summary.total_requests,
            bytes: 0,
        },
        TopItem {
            key: "bot_requests".into(),
            count: summary.bot_requests,
            bytes: 0,
        },
    ];
    emit(sink, "summary", &totals, &mut written, cap)?;
    emit(sink, "class", &summary.classes, &mut written, cap)?;
    emit(sink, "signal", &summary.signals, &mut written, cap)?;
    emit(sink, "agent", &summary.agents, &mut written, cap)?;
    emit(
        sink,
        "score_bucket",
        &summary.score_buckets,
        &mut written,
        cap,
    )?;
    Ok(written)
}

fn top(
    inner: &Inner,
    sink: &mut dyn Sink,
    f: &ExportFilter,
    kind: TopKind,
    cap: u64,
) -> Result<u64> {
    sink.header(&TOP_COLUMNS)?;
    let w = queries::range_where(
        f.from_ms.unwrap_or(i64::MIN),
        f.to_ms.unwrap_or(i64::MAX),
        f.site.as_deref(),
    );
    let limit = usize::try_from(cap).unwrap_or(usize::MAX);
    let items = inner.read_long(|c| queries::top_raw(c, kind, &w, limit))?;
    for it in &items {
        sink.row(&[
            Cell::Text(&it.key),
            Cell::Int(to_i64(it.count)),
            Cell::Int(to_i64(it.bytes)),
        ])?;
    }
    Ok(items.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(s: &str, neutralise: bool) -> String {
        let mut out = Vec::new();
        csv_field(&mut out, s, neutralise).expect("write");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn plain_fields_pass_through() {
        assert_eq!(field("hello", true), "hello");
        assert_eq!(field("", true), "");
        assert_eq!(field("zażółć 日本", true), "zażółć 日本");
    }

    #[test]
    fn specials_are_quoted_and_quotes_doubled() {
        assert_eq!(field("a,b", true), "\"a,b\"");
        assert_eq!(field("say \"hi\"", true), "\"say \"\"hi\"\"\"");
        assert_eq!(field("line1\nline2", true), "\"line1\nline2\"");
        assert_eq!(field("a\r\nb", true), "\"a\r\nb\"");
    }

    #[test]
    fn formula_prefixes_are_defused() {
        for lead in ["=1+1", "+1", "-1", "@SUM(A1)", "\tx"] {
            assert_eq!(field(lead, true), format!("'{lead}"));
        }
        assert_eq!(field("\rx", true), "\"'\rx\"");
        assert_eq!(field("=a,b", true), "\"'=a,b\"");
    }

    #[test]
    fn headers_and_non_text_are_left_alone() {
        assert_eq!(field("-1", false), "-1");
        let mut sink = CsvSink::new(Vec::new());
        sink.row(&[Cell::Int(-5), Cell::Float(1.5), Cell::Text("-x")])
            .expect("row");
        assert_eq!(String::from_utf8(sink.out).expect("utf8"), "-5,1.5,'-x\r\n");
    }

    #[test]
    fn ndjson_rows_are_valid_json() {
        let mut sink = NdjsonSink::new(Vec::new());
        sink.header(&["a", "b", "c"]).expect("header");
        sink.row(&[Cell::Text("x\"y"), Cell::Int(3), Cell::Float(0.5)])
            .expect("row");
        let line = String::from_utf8(sink.out).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
        assert_eq!(v["a"], "x\"y");
        assert_eq!(v["b"], 3);
        assert_eq!(v["c"], 0.5);
    }

    #[test]
    fn column_lists_have_fixed_widths() {
        assert_eq!(REQUEST_COLUMNS.len(), 31);
        assert_eq!(HOURLY_COLUMNS.len(), 16);
    }
}
