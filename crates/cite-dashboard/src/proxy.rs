use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use cite_client::{
    ClientError, NodeClient, archive_download_name, archive_kind_from_name, export_file_name,
    validate_archive_name,
};

use crate::error::ApiError;
use crate::state::AppState;

pub const MAX_REQUEST_BODY: usize = 1024 * 1024;

const PREFIX: &str = "/api/v1/nodes/";
const PROXY_TIMEOUT: Duration = Duration::from_secs(30);
// Switch, rollback, deploy and create wait on health checks and stack starts, which can take over a minute.
const LONG_TIMEOUT: Duration = Duration::from_secs(700);
const LONG_ACTIONS: [&str; 4] = ["switch", "rollback", "deploy", "maintenance"];
const MAX_SEGMENT_LEN: usize = 128;
const EXPORT_ROUTE: &str = "analytics/export";
const ANALYTICS_ROUTES: [&str; 7] = [
    "summary",
    "timeseries",
    "requests",
    "bots",
    "top",
    "stats",
    "export",
];
const ANALYTICS_WRITE_ROUTES: [&str; 3] = ["backup", "cut", "restore"];
const ARCHIVE_PREFIX: &str = "analytics/archives/";
const ALLOWED_PREFIXES: [&str; 9] = [
    "node",
    "settings",
    "audit",
    "sites",
    "pages",
    "firewall",
    "analytics",
    "haproxy",
    "tokens",
];

// Segments are limited to unreserved characters, which rules out traversal and encoded separators.
fn clean_rest(rest: &str) -> Option<&str> {
    let rest = rest.trim_end_matches('/');
    let valid = !rest.is_empty()
        && rest.split('/').all(|seg| {
            !seg.is_empty()
                && seg.len() <= MAX_SEGMENT_LEN
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
        });
    valid.then_some(rest)
}

fn allowed(rest: &str) -> bool {
    rest.split('/')
        .next()
        .is_some_and(|first| ALLOWED_PREFIXES.contains(&first))
}

fn response_content_type(upstream: Option<&str>) -> &'static str {
    match upstream {
        Some(c) if c.starts_with("application/json") => "application/json",
        Some(c) if c.starts_with("text/plain") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

// Unlike the other prefixes, analytics is limited to the exact routes the console uses.
fn analytics_route_ok(method: &Method, rest: &str) -> bool {
    let mut segments = rest.split('/');
    if segments.next() != Some("analytics") {
        return true;
    }
    let route = segments.next();
    let name = segments.next();
    if segments.next().is_some() {
        return false;
    }
    match (route, name) {
        (Some("archives"), None) => method == Method::GET,
        (Some("archives"), Some(name)) => {
            (method == Method::GET || method == Method::DELETE)
                && validate_archive_name(name).is_ok()
        }
        (Some(route), None) if method == Method::GET => ANALYTICS_ROUTES.contains(&route),
        (Some(route), None) => method == Method::POST && ANALYTICS_WRITE_ROUTES.contains(&route),
        _ => false,
    }
}

fn archive_download_target(rest: &str) -> Option<&str> {
    rest.strip_prefix(ARCHIVE_PREFIX)
        .filter(|name| validate_archive_name(name).is_ok())
}

fn archive_content_type(upstream: Option<&str>) -> &'static str {
    match upstream {
        Some(c) if c.starts_with("application/gzip") => "application/gzip",
        Some(c) if c.starts_with("application/vnd.sqlite3") => "application/vnd.sqlite3",
        _ => "application/octet-stream",
    }
}

// The file name comes from the requested name, never from the node's header.
fn archive_disposition(name: &str) -> String {
    let safe = archive_download_name(name, archive_kind_from_name(name));
    format!("attachment; filename=\"{safe}\"")
}

async fn stream_archive(client: &NodeClient, name: &str) -> Result<Response, ApiError> {
    let stream = client
        .analytics_archive_stream(name)
        .await
        .map_err(export_error)?;
    let status = StatusCode::from_u16(stream.status())
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "node sent an invalid status"))?;
    Response::builder()
        .status(status)
        .header(
            header::CONTENT_TYPE,
            archive_content_type(stream.content_type()),
        )
        .header(header::CONTENT_DISPOSITION, archive_disposition(name))
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream.into_body_stream()))
        .map_err(ApiError::internal)
}

fn export_content_type(upstream: Option<&str>) -> &'static str {
    match upstream {
        Some(c) if c.starts_with("text/csv") => "text/csv; charset=utf-8",
        Some(c) if c.starts_with("application/x-ndjson") => "application/x-ndjson",
        _ => "application/octet-stream",
    }
}

// The node picks the file name, so it is rebuilt from safe characters rather than relayed.
fn export_disposition(upstream: Option<&str>, content_type: Option<&str>) -> String {
    let name =
        export_file_name(upstream, content_type).unwrap_or_else(|| "cite-export.bin".to_string());
    format!("attachment; filename=\"{name}\"")
}

fn export_error(err: ClientError) -> ApiError {
    match err {
        ClientError::Status {
            code: code @ (400 | 404 | 422),
            message,
        } => ApiError::new(
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            message,
        ),
        other => other.into(),
    }
}

// The body is relayed chunk by chunk, so a large export never sits in dashboard memory.
async fn stream_export(
    client: &NodeClient,
    rest: &str,
    query: Option<&str>,
) -> Result<Response, ApiError> {
    let stream = client
        .forward_stream(rest, query)
        .await
        .map_err(export_error)?;
    let status = StatusCode::from_u16(stream.status())
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "node sent an invalid status"))?;
    let content_type = export_content_type(stream.content_type());
    let disposition = export_disposition(stream.content_disposition(), stream.content_type());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(Body::from_stream(stream.into_body_stream()))
        .map_err(ApiError::internal)
}

fn timeout_for(method: &Method, rest: &str) -> Duration {
    if method == Method::GET {
        return PROXY_TIMEOUT;
    }
    let mut segments = rest.split('/');
    let long = match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some("sites"), None, ..) => method == Method::POST,
        (Some("sites"), Some(_), Some(action), None) => LONG_ACTIONS.contains(&action),
        (Some("analytics"), Some(route), None, _) => {
            method == Method::POST && ANALYTICS_WRITE_ROUTES.contains(&route)
        }
        _ => false,
    };
    if long { LONG_TIMEOUT } else { PROXY_TIMEOUT }
}

pub async fn proxy(State(state): State<Arc<AppState>>, req: Request) -> Response {
    match forward(&state, req).await {
        Ok(resp) => resp,
        Err(err) => err.into_response(),
    }
}

async fn forward(state: &AppState, req: Request) -> Result<Response, ApiError> {
    let (parts, body) = req.into_parts();
    let not_found = || ApiError::not_found("route is not available through the dashboard");
    let tail = parts
        .uri
        .path()
        .strip_prefix(PREFIX)
        .ok_or_else(not_found)?;
    let (node, rest) = tail.split_once('/').ok_or_else(not_found)?;
    let rest = clean_rest(rest).ok_or_else(not_found)?;
    if !allowed(rest) || !analytics_route_ok(&parts.method, rest) {
        return Err(not_found());
    }
    if !matches!(
        parts.method,
        Method::GET | Method::POST | Method::PUT | Method::DELETE
    ) {
        return Err(ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        ));
    }
    let client = state
        .client(node)
        .await
        .ok_or_else(|| ApiError::not_found("node is not configured"))?;
    if rest == EXPORT_ROUTE {
        return stream_export(&client, rest, parts.uri.query()).await;
    }
    if parts.method == Method::GET
        && let Some(name) = archive_download_target(rest)
    {
        return stream_archive(&client, name).await;
    }
    let payload = if matches!(parts.method, Method::POST | Method::PUT) {
        to_bytes(body, MAX_REQUEST_BODY).await.map_err(|_| {
            ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
        })?
    } else {
        Bytes::new()
    };
    let timeout = timeout_for(&parts.method, rest);
    let forwarded = client
        .forward(
            parts.method.clone(),
            rest,
            parts.uri.query(),
            payload.to_vec(),
            timeout,
        )
        .await?;
    let status = StatusCode::from_u16(forwarded.status)
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "node sent an invalid status"))?;
    // A relayed 401 would look like the browser's own session ending, so it becomes a 502.
    if status == StatusCode::UNAUTHORIZED {
        return Err(cite_client::ClientError::Status {
            code: 401,
            message: String::new(),
        }
        .into());
    }
    if status.is_redirection() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "node sent an unexpected redirect",
        ));
    }
    Response::builder()
        .status(status)
        .header(
            header::CONTENT_TYPE,
            response_content_type(forwarded.content_type.as_deref()),
        )
        .body(Body::from(forwarded.body))
        .map_err(ApiError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_safe_segments_survive_cleaning() {
        assert_eq!(clean_rest("sites/abc-1"), Some("sites/abc-1"));
        assert_eq!(clean_rest("sites/abc/"), Some("sites/abc"));
        let bad_paths = [
            "",
            "/",
            "sites//x",
            "sites/../tokens",
            "sites/./x",
            "sites/%2e%2e/x",
            "sites/a b",
            "sites/a\\b",
            "sites/a?x=1",
            "sites/a:b",
        ];
        for bad in bad_paths {
            assert_eq!(clean_rest(bad), None, "{bad:?}");
        }
        assert_eq!(clean_rest(&format!("sites/{}", "a".repeat(129))), None);
    }

    #[test]
    fn prefix_allowlist_excludes_auth_and_unknown_routes() {
        let good = [
            "node",
            "settings",
            "audit/x",
            "sites/a/deploy",
            "pages",
            "firewall/rules",
        ];
        for ok in good {
            assert!(allowed(ok), "{ok}");
        }
        for bad in [
            "auth/login",
            "auth/me",
            "healthz",
            "nodes",
            "sitesx",
            "admin",
        ] {
            assert!(!allowed(bad), "{bad}");
        }
        assert!(allowed("analytics/summary") && allowed("haproxy/reload") && allowed("tokens/x"));
    }

    #[test]
    fn analytics_is_limited_to_known_read_routes() {
        for route in ANALYTICS_ROUTES {
            assert!(analytics_route_ok(
                &Method::GET,
                &format!("analytics/{route}")
            ));
            assert!(!analytics_route_ok(
                &Method::POST,
                &format!("analytics/{route}")
            ));
        }
        assert!(!analytics_route_ok(&Method::GET, "analytics"));
        assert!(!analytics_route_ok(&Method::GET, "analytics/purge"));
        assert!(!analytics_route_ok(&Method::GET, "analytics/export/extra"));
        assert!(analytics_route_ok(&Method::POST, "sites"));
    }

    #[test]
    fn archive_routes_are_allowed_with_their_exact_methods() {
        let yes = [
            (Method::GET, "analytics/archives"),
            (
                Method::GET,
                "analytics/archives/requests-2026-11-05.ndjson.gz",
            ),
            (
                Method::DELETE,
                "analytics/archives/analytics-20261105-101500.db",
            ),
            (Method::POST, "analytics/backup"),
            (Method::POST, "analytics/cut"),
            (Method::POST, "analytics/restore"),
        ];
        for (method, rest) in yes {
            assert!(analytics_route_ok(&method, rest), "{method} {rest}");
        }
        let no = [
            (Method::POST, "analytics/archives"),
            (Method::DELETE, "analytics/archives"),
            (Method::PUT, "analytics/archives/x.db"),
            (Method::POST, "analytics/archives/x.db"),
            (Method::GET, "analytics/backup"),
            (Method::GET, "analytics/cut"),
            (Method::DELETE, "analytics/cut"),
            (Method::PUT, "analytics/restore"),
            (Method::POST, "analytics/restore/x"),
            (Method::GET, "analytics/archives/.hidden"),
            (Method::GET, "analytics/archives/x/y"),
            (Method::GET, "analytics/archives/~tilde"),
            (Method::POST, "analytics/purge"),
        ];
        for (method, rest) in no {
            assert!(!analytics_route_ok(&method, rest), "{method} {rest}");
        }
    }

    #[test]
    fn archive_downloads_get_rebuilt_headers() {
        assert_eq!(
            archive_download_target("analytics/archives/a.db"),
            Some("a.db")
        );
        assert_eq!(archive_download_target("analytics/archives/.a"), None);
        assert_eq!(archive_download_target("analytics/archives"), None);
        assert_eq!(archive_download_target("analytics/export"), None);
        assert_eq!(
            archive_content_type(Some("application/gzip")),
            "application/gzip"
        );
        assert_eq!(
            archive_content_type(Some("application/vnd.sqlite3")),
            "application/vnd.sqlite3"
        );
        assert_eq!(
            archive_content_type(Some("text/html")),
            "application/octet-stream"
        );
        assert_eq!(
            archive_disposition("requests-2026-11-05.ndjson.gz"),
            "attachment; filename=\"requests-2026-11-05.ndjson.gz\""
        );
        assert_eq!(
            archive_disposition("a.exe"),
            "attachment; filename=\"a_exe.ndjson.gz\""
        );
        assert_eq!(
            archive_disposition("analytics-1.db"),
            "attachment; filename=\"analytics-1.db\""
        );
    }

    #[test]
    fn export_headers_are_rebuilt_from_known_values() {
        assert_eq!(
            export_content_type(Some("text/csv; charset=utf-8")),
            "text/csv; charset=utf-8"
        );
        assert_eq!(
            export_content_type(Some("application/x-ndjson")),
            "application/x-ndjson"
        );
        assert_eq!(
            export_content_type(Some("text/html")),
            "application/octet-stream"
        );
        assert_eq!(
            export_disposition(
                Some("attachment; filename=\"a b/../c.exe\""),
                Some("text/csv")
            ),
            "attachment; filename=\"ab.csv\""
        );
        assert_eq!(
            export_disposition(None, Some("application/x-ndjson")),
            "attachment; filename=\"cite-export.ndjson\""
        );
        assert_eq!(
            export_disposition(Some("attachment; filename=\"a.html\""), Some("text/html")),
            "attachment; filename=\"cite-export.bin\""
        );
    }

    #[test]
    fn slow_site_actions_get_the_long_timeout_and_reads_stay_short() {
        for (method, rest) in [
            (Method::POST, "sites"),
            (Method::POST, "sites/a/deploy"),
            (Method::POST, "sites/a/switch"),
            (Method::POST, "sites/a/rollback"),
            (Method::PUT, "sites/a/maintenance"),
            (Method::DELETE, "sites/a/maintenance"),
            (Method::POST, "analytics/backup"),
            (Method::POST, "analytics/cut"),
            (Method::POST, "analytics/restore"),
        ] {
            assert_eq!(timeout_for(&method, rest), LONG_TIMEOUT, "{method} {rest}");
        }
        for (method, rest) in [
            (Method::GET, "sites"),
            (Method::GET, "sites/a/maintenance"),
            (Method::PUT, "sites/a"),
            (Method::DELETE, "sites/a"),
            (Method::POST, "firewall/rules"),
            (Method::POST, "sites/a/other"),
            (Method::GET, "analytics/archives"),
            (Method::DELETE, "analytics/archives/x.db"),
        ] {
            assert_eq!(timeout_for(&method, rest), PROXY_TIMEOUT, "{method} {rest}");
        }
        assert!(LONG_TIMEOUT >= Duration::from_secs(600));
    }

    #[test]
    fn upstream_content_types_are_normalised() {
        let json = response_content_type(Some("application/json; charset=utf-8"));
        assert_eq!(json, "application/json");
        let text = response_content_type(Some("text/plain"));
        assert_eq!(text, "text/plain; charset=utf-8");
        let html = response_content_type(Some("text/html"));
        assert_eq!(html, "application/octet-stream");
        assert_eq!(response_content_type(None), "application/octet-stream");
    }
}
