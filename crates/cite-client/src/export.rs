use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::error::ClientError;
use crate::fsio::new_id;

type Res<T> = std::result::Result<T, ClientError>;

// A large hourly or request export can run for many minutes on a busy node.
pub const EXPORT_TIMEOUT: Duration = Duration::from_secs(1800);
pub const DEFAULT_EXPORT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub const TOP_KINDS: [&str; 8] = [
    "paths",
    "hosts",
    "referers",
    "agents",
    "content_types",
    "statuses",
    "ips",
    "languages",
];
pub const BOT_CLASSES: [&str; 5] = ["human", "suspect", "crawler", "tool", "bot"];

const MAX_TEXT_CHARS: usize = 512;
const MAX_METHOD_CHARS: usize = 16;
const MAX_FILENAME_CHARS: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyticsStats {
    #[serde(default)]
    pub rows: u64,
    #[serde(default)]
    pub db_bytes: u64,
    #[serde(default)]
    pub oldest_ts_ms: Option<i64>,
    #[serde(default)]
    pub newest_ts_ms: Option<i64>,
    #[serde(default)]
    pub write_batches: u64,
    #[serde(default)]
    pub write_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    Requests,
    Hourly,
    Bots,
    Top,
}

impl ExportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Hourly => "hourly",
            Self::Bots => "bots",
            Self::Top => "top",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExportFormat {
    #[default]
    Csv,
    Ndjson,
}

impl ExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Ndjson => "ndjson",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportQuery {
    kind: ExportKind,
    top: Option<String>,
    format: ExportFormat,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    site: Option<String>,
    status_min: Option<u16>,
    status_max: Option<u16>,
    bot_class: Option<String>,
    min_bot_score: Option<u8>,
    host: Option<String>,
    path_prefix: Option<String>,
    client_ip: Option<String>,
    method: Option<String>,
    limit: Option<usize>,
}

impl ExportQuery {
    pub fn new(kind: ExportKind) -> Self {
        Self {
            kind,
            top: None,
            format: ExportFormat::default(),
            from_ms: None,
            to_ms: None,
            site: None,
            status_min: None,
            status_max: None,
            bot_class: None,
            min_bot_score: None,
            host: None,
            path_prefix: None,
            client_ip: None,
            method: None,
            limit: None,
        }
    }

    pub fn top_kind(mut self, kind: impl Into<String>) -> Self {
        self.top = Some(kind.into());
        self
    }

    pub fn format(mut self, format: ExportFormat) -> Self {
        self.format = format;
        self
    }

    pub fn starting_at(mut self, ts: i64) -> Self {
        self.from_ms = Some(ts);
        self
    }

    pub fn ending_at(mut self, ts: i64) -> Self {
        self.to_ms = Some(ts);
        self
    }

    pub fn site(mut self, site: impl Into<String>) -> Self {
        self.site = Some(site.into());
        self
    }

    pub fn status_min(mut self, status: u16) -> Self {
        self.status_min = Some(status);
        self
    }

    pub fn status_max(mut self, status: u16) -> Self {
        self.status_max = Some(status);
        self
    }

    pub fn bot_class(mut self, class: impl Into<String>) -> Self {
        self.bot_class = Some(class.into());
        self
    }

    pub fn min_bot_score(mut self, score: u8) -> Self {
        self.min_bot_score = Some(score);
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

    pub fn client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn validate(&self) -> Res<()> {
        self.pairs().map(|_| ())
    }

    pub fn pairs(&self) -> Res<Vec<(&'static str, String)>> {
        let mut out = vec![
            ("kind", self.kind.as_str().to_string()),
            ("format", self.format.as_str().to_string()),
        ];
        match (self.kind, self.top.as_deref()) {
            (ExportKind::Top, Some(top)) => out.push(("top", validate_top_kind(top)?.to_string())),
            (ExportKind::Top, None) => return Err(invalid("a top export needs a top kind")),
            (_, Some(_)) => return Err(invalid("a top kind is only valid for a top export")),
            (_, None) => {}
        }
        if let (Some(from), Some(to)) = (self.from_ms, self.to_ms)
            && from > to
        {
            return Err(invalid("the start of the range is after its end"));
        }
        for (name, value) in [("from", self.from_ms), ("to", self.to_ms)] {
            if let Some(ts) = value {
                if ts < 0 {
                    return Err(invalid(format!("{name} must not be negative")));
                }
                out.push((name, ts.to_string()));
            }
        }
        if let Some(site) = &self.site {
            out.push(("site", text("site", site)?));
        }
        for (name, value) in [
            ("status_min", self.status_min),
            ("status_max", self.status_max),
        ] {
            if let Some(status) = value {
                if !(100..=599).contains(&status) {
                    return Err(invalid(format!("{name} must be between 100 and 599")));
                }
                out.push((name, status.to_string()));
            }
        }
        if let (Some(lo), Some(hi)) = (self.status_min, self.status_max)
            && lo > hi
        {
            return Err(invalid("status_min is above status_max"));
        }
        if let Some(class) = &self.bot_class {
            let class = class.trim().to_ascii_lowercase();
            if !BOT_CLASSES.contains(&class.as_str()) {
                return Err(invalid(format!("unknown bot class `{class}`")));
            }
            out.push(("bot_class", class));
        }
        if let Some(score) = self.min_bot_score {
            if score > 100 {
                return Err(invalid("min_bot_score must be between 0 and 100"));
            }
            out.push(("min_bot_score", score.to_string()));
        }
        if let Some(host) = &self.host {
            out.push(("host", text("host", host)?));
        }
        if let Some(prefix) = &self.path_prefix {
            out.push(("path_prefix", text("path_prefix", prefix)?));
        }
        if let Some(ip) = &self.client_ip {
            let ip = text("client_ip", ip)?;
            ip.parse::<IpAddr>()
                .map_err(|_| invalid("client_ip is not an IP address"))?;
            out.push(("client_ip", ip));
        }
        if let Some(method) = &self.method {
            let method = text("method", method)?.to_ascii_uppercase();
            if method.chars().count() > MAX_METHOD_CHARS
                || !method.bytes().all(|b| b.is_ascii_alphabetic())
            {
                return Err(invalid("method must be a plain HTTP method name"));
            }
            out.push(("method", method));
        }
        if let Some(limit) = self.limit {
            if limit == 0 {
                return Err(invalid("limit must be at least 1"));
            }
            out.push(("limit", limit.to_string()));
        }
        Ok(out)
    }
}

pub(crate) fn validate_top_kind(kind: &str) -> Res<&str> {
    let kind = kind.trim();
    if TOP_KINDS.contains(&kind) {
        Ok(kind)
    } else {
        Err(invalid(format!("unknown top kind `{kind}`")))
    }
}

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

fn text(name: &str, value: &str) -> Res<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid(format!("{name} must not be empty")));
    }
    if value.chars().count() > MAX_TEXT_CHARS {
        return Err(invalid(format!("{name} is too long")));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!("{name} contains control characters")));
    }
    Ok(value.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReport {
    pub path: PathBuf,
    pub bytes: u64,
    pub content_type: Option<String>,
    pub suggested_name: Option<String>,
}

// The raw node response, unread, so a caller can relay the body without buffering it.
#[derive(Debug)]
pub struct ExportStream {
    response: reqwest::Response,
}

impl ExportStream {
    pub(crate) fn new(response: reqwest::Response) -> Self {
        Self { response }
    }

    pub fn status(&self) -> u16 {
        self.response.status().as_u16()
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header(reqwest::header::CONTENT_TYPE)
    }

    pub fn content_disposition(&self) -> Option<&str> {
        self.header(reqwest::header::CONTENT_DISPOSITION)
    }

    pub fn content_length(&self) -> Option<u64> {
        self.response.content_length()
    }

    fn header(&self, name: reqwest::header::HeaderName) -> Option<&str> {
        self.response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
    }

    pub fn into_body_stream(self) -> impl Stream<Item = Res<Bytes>> + Send + 'static {
        self.response
            .bytes_stream()
            .map(|chunk| chunk.map_err(ClientError::from_reqwest))
    }

    // Writes beside `dest` and renames on success, so a failed or oversized download leaves nothing behind.
    pub(crate) async fn save(mut self, dest: &Path, max_bytes: u64) -> Res<ExportReport> {
        let dir = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = dest
            .file_name()
            .ok_or_else(|| invalid("destination has no file name"))?;
        if self.content_length().is_some_and(|len| len > max_bytes) {
            return Err(too_large(max_bytes));
        }
        let content_type = self.content_type().map(str::to_string);
        let suggested_name = export_file_name(self.content_disposition(), self.content_type());
        let tmp = dir.join(format!(".{}.{}.tmp", name.to_string_lossy(), new_id()));
        // Declared before the file so the handle closes first when the guard removes the path.
        let mut guard = TmpGuard(Some(tmp.clone()));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Backups hold visitor addresses, so the file must not follow a permissive umask.
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).await.map_err(io_error)?;
        let mut written: u64 = 0;
        while let Some(chunk) = self
            .response
            .chunk()
            .await
            .map_err(ClientError::from_reqwest)?
        {
            written += chunk.len() as u64;
            if written > max_bytes {
                return Err(too_large(max_bytes));
            }
            file.write_all(&chunk).await.map_err(io_error)?;
        }
        file.flush().await.map_err(io_error)?;
        file.sync_all().await.map_err(io_error)?;
        drop(file);
        tokio::fs::rename(&tmp, dest).await.map_err(io_error)?;
        guard.0 = None;
        Ok(ExportReport {
            path: dest.to_path_buf(),
            bytes: written,
            content_type,
            suggested_name,
        })
    }
}

struct TmpGuard(Option<PathBuf>);

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn io_error(err: std::io::Error) -> ClientError {
    ClientError::Config(format!("cannot write export: {err}"))
}

fn too_large(max: u64) -> ClientError {
    ClientError::Decode(format!("export exceeds the {max} byte limit"))
}

// Only a plain basename of safe characters is kept, since the node chooses this value.
pub fn filename_from_disposition(value: &str) -> Option<String> {
    let raw = value.split(';').skip(1).map(str::trim).find_map(|part| {
        let (key, val) = part.split_once('=')?;
        key.trim().eq_ignore_ascii_case("filename").then_some(val)
    })?;
    let cleaned: String = raw
        .trim()
        .trim_matches('"')
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(MAX_FILENAME_CHARS)
        .collect();
    let cleaned = cleaned.trim_start_matches('.').to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// The extension comes from the content type, never from the node, so a download cannot be renamed to something executable.
pub fn export_file_name(disposition: Option<&str>, content_type: Option<&str>) -> Option<String> {
    let ext = match content_type {
        Some(c) if c.starts_with("text/csv") => "csv",
        Some(c) if c.starts_with("application/x-ndjson") => "ndjson",
        _ => return None,
    };
    let stem = disposition
        .and_then(filename_from_disposition)
        .and_then(|n| n.split('.').next().map(str::to_string))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cite-export".to_string());
    Some(format!("{stem}.{ext}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(q: &ExportQuery) -> Vec<(String, String)> {
        q.pairs()
            .expect("valid")
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    #[test]
    fn minimal_query_carries_kind_and_format() {
        let q = ExportQuery::new(ExportKind::Requests);
        assert_eq!(
            pairs(&q),
            [
                ("kind".to_string(), "requests".to_string()),
                ("format".to_string(), "csv".to_string())
            ]
        );
    }

    #[test]
    fn full_query_serialises_every_filter() {
        let q = ExportQuery::new(ExportKind::Requests)
            .format(ExportFormat::Ndjson)
            .starting_at(10)
            .ending_at(20)
            .site("shop")
            .status_min(400)
            .status_max(499)
            .bot_class("Crawler")
            .min_bot_score(40)
            .host("example.com")
            .path_prefix("/api")
            .client_ip("2001:db8::1")
            .method("get")
            .limit(500);
        let got = pairs(&q);
        let find = |k: &str| got.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(find("format"), Some("ndjson"));
        assert_eq!(find("bot_class"), Some("crawler"));
        assert_eq!(find("method"), Some("GET"));
        assert_eq!(find("client_ip"), Some("2001:db8::1"));
        assert_eq!(find("limit"), Some("500"));
        assert_eq!(find("min_bot_score"), Some("40"));
        assert_eq!(find("from"), Some("10"));
        assert_eq!(find("to"), Some("20"));
    }

    #[test]
    fn top_exports_need_a_known_top_kind() {
        assert!(ExportQuery::new(ExportKind::Top).validate().is_err());
        assert!(
            ExportQuery::new(ExportKind::Top)
                .top_kind("nonsense")
                .validate()
                .is_err()
        );
        assert!(
            ExportQuery::new(ExportKind::Requests)
                .top_kind("paths")
                .validate()
                .is_err()
        );
        for kind in TOP_KINDS {
            let q = ExportQuery::new(ExportKind::Top).top_kind(kind);
            assert!(pairs(&q).contains(&("top".to_string(), kind.to_string())));
        }
    }

    #[test]
    fn invalid_filters_are_rejected_before_any_request() {
        let bad = [
            ExportQuery::new(ExportKind::Requests)
                .starting_at(5)
                .ending_at(1),
            ExportQuery::new(ExportKind::Requests).starting_at(-1),
            ExportQuery::new(ExportKind::Requests).status_min(99),
            ExportQuery::new(ExportKind::Requests).status_max(600),
            ExportQuery::new(ExportKind::Requests)
                .status_min(500)
                .status_max(400),
            ExportQuery::new(ExportKind::Requests).bot_class("robot"),
            ExportQuery::new(ExportKind::Requests).min_bot_score(101),
            ExportQuery::new(ExportKind::Requests).client_ip("not-an-ip"),
            ExportQuery::new(ExportKind::Requests).method("GE T"),
            ExportQuery::new(ExportKind::Requests).host("  "),
            ExportQuery::new(ExportKind::Requests).path_prefix("/a\nb"),
            ExportQuery::new(ExportKind::Requests).site("x".repeat(600)),
            ExportQuery::new(ExportKind::Requests).limit(0),
        ];
        for q in bad {
            assert!(matches!(q.validate(), Err(ClientError::Config(_))), "{q:?}");
        }
    }

    #[test]
    fn export_names_take_their_extension_from_the_content_type() {
        let csv = Some("text/csv; charset=utf-8");
        let nd = Some("application/x-ndjson");
        assert_eq!(
            export_file_name(
                Some("attachment; filename=\"cite-requests-all-2026-11-05.csv\""),
                csv
            ),
            Some("cite-requests-all-2026-11-05.csv".to_string())
        );
        assert_eq!(
            export_file_name(Some("attachment; filename=\"report.exe\""), csv),
            Some("report.csv".to_string())
        );
        assert_eq!(
            export_file_name(Some("attachment; filename=\"x.html\""), nd),
            Some("x.ndjson".to_string())
        );
        assert_eq!(
            export_file_name(None, csv),
            Some("cite-export.csv".to_string())
        );
        assert_eq!(
            export_file_name(
                Some("attachment; filename=\"a.svg\""),
                Some("image/svg+xml")
            ),
            None
        );
    }

    #[test]
    fn disposition_filenames_are_reduced_to_a_safe_basename() {
        let name = |v: &str| filename_from_disposition(v);
        assert_eq!(
            name("attachment; filename=\"cite-requests.csv\""),
            Some("cite-requests.csv".to_string())
        );
        assert_eq!(
            name("attachment; FILENAME=a.ndjson"),
            Some("a.ndjson".to_string())
        );
        assert_eq!(
            name("attachment; filename=\"../../etc/passwd\""),
            Some("etcpasswd".to_string())
        );
        assert_eq!(name("attachment; filename=\"..\""), None);
        assert_eq!(name("attachment"), None);
    }

    #[test]
    fn stats_tolerate_missing_and_null_timestamps() {
        let stats: AnalyticsStats = serde_json::from_str(
            r#"{"rows":0,"db_bytes":4096,"oldest_ts_ms":null,"newest_ts_ms":null,"write_batches":1,"write_errors":0}"#,
        )
        .expect("stats");
        assert_eq!(stats.db_bytes, 4096);
        assert_eq!(stats.oldest_ts_ms, None);
        let empty: AnalyticsStats = serde_json::from_str("{}").expect("empty");
        assert_eq!(empty, AnalyticsStats::default());
    }
}
