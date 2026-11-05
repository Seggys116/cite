use std::collections::HashMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::Extension;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::Response;
use bytes::Bytes;
use cite_store::{DEFAULT_EXPORT_LIMIT, ExportFilter, ExportKind};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use super::handlers::{check_id, now_ms, parse_method, parse_top_kind};
use super::{ApiError, ApiResult, AppState, Params, Principal};
use crate::ConnectorError;

const CHUNK: usize = 32 * 1024;
// Chunks buffered between the database thread and the socket; a slow client stalls the query here.
const CHANNEL_CHUNKS: usize = 4;
const MAX_HOST: usize = 255;
const MAX_PATH_PREFIX: usize = 1024;
const BOT_CLASSES: [&str; 5] = ["human", "suspect", "crawler", "tool", "bot"];

struct ExportRequest {
    kind: ExportKind,
    label: String,
    ndjson: bool,
    filter: ExportFilter,
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::bad(msg)
}

fn opt<'a>(q: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    q.get(key).map(String::as_str).filter(|s| !s.is_empty())
}

fn parse_num<T: FromStr>(
    q: &HashMap<String, String>,
    key: &str,
    what: &str,
) -> ApiResult<Option<T>> {
    match opt(q, key) {
        None => Ok(None),
        Some(raw) => raw
            .parse::<T>()
            .map(Some)
            .map_err(|_| bad(format!("{key} must be {what}"))),
    }
}

// Milliseconds since the epoch, or an RFC 3339 timestamp.
fn parse_time(key: &str, raw: &str) -> ApiResult<i64> {
    let invalid = || {
        bad(format!(
            "{key} must be milliseconds since the epoch or an RFC 3339 timestamp"
        ))
    };
    if raw.bytes().all(|b| b.is_ascii_digit()) {
        return raw.parse::<i64>().map_err(|_| invalid());
    }
    // an unescaped "+" offset reaches the server as a space
    let text = raw.replace(' ', "+");
    let at = OffsetDateTime::parse(&text, &Rfc3339).map_err(|_| invalid())?;
    i64::try_from(at.unix_timestamp_nanos() / 1_000_000).map_err(|_| invalid())
}

fn plain_text(key: &str, raw: &str, max: usize) -> ApiResult<String> {
    if raw.len() > max || raw.chars().any(char::is_control) {
        return Err(bad(format!(
            "{key} must be at most {max} bytes without control characters"
        )));
    }
    Ok(raw.to_string())
}

fn parse_export(q: &HashMap<String, String>) -> ApiResult<ExportRequest> {
    let top = opt(q, "top");
    let (kind, label) = match opt(q, "kind").unwrap_or("requests") {
        "requests" => (ExportKind::Requests, "requests".to_string()),
        "hourly" => (ExportKind::Hourly, "hourly".to_string()),
        "bots" => (ExportKind::Bots, "bots".to_string()),
        "top" => {
            let name = top.ok_or_else(|| bad("top is required when kind is top"))?;
            (
                ExportKind::Top(parse_top_kind(name)?),
                format!("top-{name}"),
            )
        }
        _ => return Err(bad("kind must be one of requests, hourly, bots, top")),
    };
    if top.is_some() && !matches!(kind, ExportKind::Top(_)) {
        return Err(bad("top is only valid when kind is top"));
    }
    let ndjson = match opt(q, "format").unwrap_or("csv") {
        "csv" => false,
        "ndjson" => true,
        _ => return Err(bad("format must be csv or ndjson")),
    };

    let from_ms = opt(q, "from").map(|v| parse_time("from", v)).transpose()?;
    let to_ms = opt(q, "to").map(|v| parse_time("to", v)).transpose()?;
    if let (Some(from), Some(to)) = (from_ms, to_ms)
        && from >= to
    {
        return Err(bad("from must be earlier than to"));
    }
    let site = match opt(q, "site") {
        Some(id) => {
            check_id(id)?;
            Some(id.to_string())
        }
        None => None,
    };
    let status = |key: &str| -> ApiResult<Option<u16>> {
        let value = parse_num::<u16>(q, key, "an HTTP status code")?;
        if value.is_some_and(|v| !(100..=599).contains(&v)) {
            return Err(bad(format!("{key} must be an HTTP status code")));
        }
        Ok(value)
    };
    let (status_min, status_max) = (status("status_min")?, status("status_max")?);
    if let (Some(min), Some(max)) = (status_min, status_max)
        && min > max
    {
        return Err(bad("status_min must not be greater than status_max"));
    }
    let bot_class = match opt(q, "bot_class") {
        Some(class) if BOT_CLASSES.contains(&class) => Some(class.to_string()),
        Some(_) => {
            return Err(bad(
                "bot_class must be one of human, suspect, crawler, tool, bot",
            ));
        }
        None => None,
    };
    let min_bot_score = parse_num::<u8>(q, "min_bot_score", "a score from 0 to 100")?;
    if min_bot_score.is_some_and(|s| s > 100) {
        return Err(bad("min_bot_score must be a score from 0 to 100"));
    }
    let client_ip = match opt(q, "client_ip") {
        Some(raw) => {
            let ip: IpAddr = raw
                .parse()
                .map_err(|_| bad("client_ip must be an IP address"))?;
            Some(ip.to_string())
        }
        None => None,
    };
    let limit = parse_num::<u64>(q, "limit", "a positive integer")?;
    if limit.is_some_and(|n| n == 0 || n > DEFAULT_EXPORT_LIMIT) {
        return Err(bad(format!(
            "limit must be between 1 and {DEFAULT_EXPORT_LIMIT}"
        )));
    }
    let filter = ExportFilter {
        from_ms,
        to_ms,
        site,
        status_min,
        status_max,
        bot_class,
        min_bot_score,
        host: opt(q, "host")
            .map(|v| plain_text("host", v, MAX_HOST))
            .transpose()?,
        path_prefix: opt(q, "path_prefix")
            .map(|v| plain_text("path_prefix", v, MAX_PATH_PREFIX))
            .transpose()?,
        client_ip,
        method: opt(q, "method").map(parse_method).transpose()?,
        limit,
    };
    Ok(ExportRequest {
        kind,
        label,
        ndjson,
        filter,
    })
}

fn utc_date(ms: i64) -> String {
    let at = OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}",
        at.year(),
        u8::from(at.month()),
        at.day()
    )
}

// Built only from fixed words, a validated site id and the date, so nothing else from the request can reach the header.
fn file_name(req: &ExportRequest, at_ms: i64) -> String {
    let site: String = req
        .filter
        .site
        .as_deref()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect();
    let site = if site.is_empty() {
        "all"
    } else {
        site.as_str()
    };
    let ext = if req.ndjson { "ndjson" } else { "csv" };
    format!("cite-{}-{site}-{}.{ext}", req.label, utc_date(at_ms))
}

fn audit_detail(req: &ExportRequest) -> String {
    let f = &req.filter;
    let mut parts = vec![
        format!("kind={}", req.label),
        format!("format={}", if req.ndjson { "ndjson" } else { "csv" }),
    ];
    let mut text = |key: &str, value: &Option<String>| {
        if let Some(v) = value {
            parts.push(format!("{key}={v:?}"));
        }
    };
    text("site", &f.site);
    text("bot_class", &f.bot_class);
    text("host", &f.host);
    text("path_prefix", &f.path_prefix);
    text("client_ip", &f.client_ip);
    text("method", &f.method);
    let numbers = [
        ("from", f.from_ms),
        ("to", f.to_ms),
        ("status_min", f.status_min.map(i64::from)),
        ("status_max", f.status_max.map(i64::from)),
        ("min_bot_score", f.min_bot_score.map(i64::from)),
        ("limit", f.limit.and_then(|n| i64::try_from(n).ok())),
    ];
    for (key, value) in numbers {
        if let Some(v) = value {
            parts.push(format!("{key}={v}"));
        }
    }
    parts.join(" ")
}

// Batches writes into chunks for the response body and reports a gone client as a broken pipe so the export stops.
struct ChunkWriter {
    tx: mpsc::Sender<io::Result<Bytes>>,
    buf: Vec<u8>,
    disconnected: bool,
}

impl ChunkWriter {
    fn new(tx: mpsc::Sender<io::Result<Bytes>>) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(CHUNK + 8192),
            disconnected: false,
        }
    }

    fn ship(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let full = std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK + 8192));
        if self.tx.blocking_send(Ok(Bytes::from(full))).is_err() {
            self.disconnected = true;
            return Err(gone());
        }
        Ok(())
    }
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "client disconnected")
}

impl Write for ChunkWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.disconnected {
            return Err(gone());
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() >= CHUNK {
            self.ship()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ship()
    }
}

fn run_export(
    store: &cite_store::Store,
    _permit: OwnedSemaphorePermit,
    req: &ExportRequest,
    tx: mpsc::Sender<io::Result<Bytes>>,
) {
    let mut out = ChunkWriter::new(tx.clone());
    let result = if req.ndjson {
        store.export_ndjson(&mut out, req.kind, &req.filter)
    } else {
        store.export_csv(&mut out, req.kind, &req.filter)
    };
    match result {
        Ok(rows) => tracing::debug!(rows, "analytics export finished"),
        Err(_) if out.disconnected => tracing::debug!("analytics export stopped, the client left"),
        Err(e) => {
            tracing::error!(error = %e, "analytics export failed");
            // An error item aborts the response so the client sees a truncated download, not a complete one.
            let _ = tx.blocking_send(Err(io::Error::other("export failed")));
        }
    }
}

fn start_export(
    store: Arc<cite_store::Store>,
    permit: OwnedSemaphorePermit,
    req: ExportRequest,
) -> Body {
    let (tx, rx) = mpsc::channel(CHANNEL_CHUNKS);
    tokio::task::spawn_blocking(move || run_export(&store, permit, &req, tx));
    Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

pub(super) async fn analytics_export(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Params(q): Params,
) -> ApiResult<Response> {
    let req = parse_export(&q)?;
    let permit = Arc::clone(&st.exports).try_acquire_owned().map_err(|_| {
        ConnectorError::TooManyRequests("too many exports are running; try again shortly".into())
    })?;
    st.store
        .audit(&p.actor(), "analytics.export", &audit_detail(&req))
        .await;
    let disposition = format!("attachment; filename=\"{}\"", file_name(&req, now_ms()));
    let content_type = if req.ndjson {
        "application/x-ndjson"
    } else {
        "text/csv; charset=utf-8"
    };
    let disposition = HeaderValue::from_str(&disposition)
        .map_err(|e| ConnectorError::Internal(format!("export file name: {e}")))?;
    let mut res = Response::new(start_export(Arc::clone(&st.analytics), permit, req));
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn rejected(pairs: &[(&str, &str)]) -> bool {
        parse_export(&query(pairs)).is_err()
    }

    #[test]
    fn defaults_are_all_requests_as_csv() {
        let req = parse_export(&query(&[])).unwrap();
        assert_eq!(req.kind, ExportKind::Requests);
        assert!(!req.ndjson);
        assert!(req.filter.limit.is_none() && req.filter.from_ms.is_none());
    }

    #[test]
    fn every_filter_is_parsed() {
        let req = parse_export(&query(&[
            ("kind", "top"),
            ("top", "paths"),
            ("format", "ndjson"),
            ("from", "1000"),
            ("to", "2000"),
            ("site", "blog"),
            ("status_min", "400"),
            ("status_max", "499"),
            ("bot_class", "crawler"),
            ("min_bot_score", "40"),
            ("host", "a.example.com"),
            ("path_prefix", "/api"),
            ("client_ip", "2001:0db8::1"),
            ("method", "post"),
            ("limit", "25"),
        ]))
        .unwrap();
        assert!(req.ndjson);
        assert!(matches!(
            req.kind,
            ExportKind::Top(cite_store::TopKind::Paths)
        ));
        let f = req.filter;
        assert_eq!((f.from_ms, f.to_ms), (Some(1000), Some(2000)));
        assert_eq!(f.site.as_deref(), Some("blog"));
        assert_eq!((f.status_min, f.status_max), (Some(400), Some(499)));
        assert_eq!(f.bot_class.as_deref(), Some("crawler"));
        assert_eq!(f.min_bot_score, Some(40));
        assert_eq!(f.host.as_deref(), Some("a.example.com"));
        assert_eq!(f.path_prefix.as_deref(), Some("/api"));
        assert_eq!(f.client_ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(f.method.as_deref(), Some("POST"));
        assert_eq!(f.limit, Some(25));
    }

    #[test]
    fn bad_values_are_rejected() {
        for pairs in [
            &[("kind", "everything")][..],
            &[("kind", "top")],
            &[("kind", "top"), ("top", "nope")],
            &[("kind", "bots"), ("top", "paths")],
            &[("format", "xml")],
            &[("from", "yesterday")],
            &[("from", "-5")],
            &[("to", "99999999999999999999")],
            &[("from", "2000"), ("to", "1000")],
            &[("from", "1000"), ("to", "1000")],
            &[("site", "Bad Site")],
            &[("status_min", "abc")],
            &[("status_min", "99")],
            &[("status_max", "600")],
            &[("status_min", "500"), ("status_max", "400")],
            &[("bot_class", "robot")],
            &[("min_bot_score", "101")],
            &[("min_bot_score", "x")],
            &[("client_ip", "nope")],
            &[("method", "GE T")],
            &[("host", "a\nb")],
            &[("path_prefix", "/a\u{7}")],
            &[("limit", "0")],
            &[("limit", "-1")],
            &[("limit", "1000001")],
            &[("limit", "many")],
        ] {
            assert!(rejected(pairs), "{pairs:?}");
        }
    }

    #[test]
    fn empty_values_count_as_absent() {
        let req = parse_export(&query(&[("site", ""), ("from", ""), ("limit", "")])).unwrap();
        assert!(req.filter.site.is_none() && req.filter.from_ms.is_none());
        assert!(req.filter.limit.is_none());
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
            parse_time("from", "2023-11-14T23:13:20+01:00").unwrap(),
            1_700_000_000_000
        );
        // the same offset with its plus sign decoded to a space
        assert_eq!(
            parse_time("from", "2023-11-14T23:13:20 01:00").unwrap(),
            1_700_000_000_000
        );
        assert!(parse_time("from", "2023-11-14").is_err());
    }

    #[test]
    fn file_names_use_only_fixed_words_a_site_id_and_the_date() {
        let mut req = parse_export(&query(&[("kind", "top"), ("top", "content_types")])).unwrap();
        assert_eq!(
            file_name(&req, 1_700_000_000_000),
            "cite-top-content_types-all-2023-11-14.csv"
        );
        req.filter.site = Some("my-site_1".into());
        req.ndjson = true;
        assert_eq!(
            file_name(&req, 0),
            "cite-top-content_types-my-site_1-1970-01-01.ndjson"
        );
        req.filter.site = Some("a\"b/../c".into());
        assert_eq!(
            file_name(&req, 0),
            "cite-top-content_types-abc-1970-01-01.ndjson"
        );
    }

    #[test]
    fn audit_detail_lists_the_filters_that_were_applied() {
        let req = parse_export(&query(&[
            ("kind", "requests"),
            ("site", "blog"),
            ("host", "a b"),
            ("status_min", "500"),
        ]))
        .unwrap();
        assert_eq!(
            audit_detail(&req),
            "kind=requests format=csv site=\"blog\" host=\"a b\" status_min=500"
        );
    }

    #[test]
    fn chunk_writer_batches_and_stops_when_the_receiver_is_gone() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut out = ChunkWriter::new(tx);
        out.write_all(b"abc").unwrap();
        assert!(rx.try_recv().is_err());
        out.write_all(&vec![b'x'; CHUNK]).unwrap();
        let first = rx.try_recv().unwrap().unwrap();
        assert_eq!(first.len(), CHUNK + 3);
        out.write_all(b"tail").unwrap();
        out.flush().unwrap();
        assert_eq!(&rx.try_recv().unwrap().unwrap()[..], b"tail");

        drop(rx);
        let err = out.write_all(&vec![b'y'; CHUNK]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(out.disconnected);
        assert_eq!(
            out.write_all(b"more").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
