use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use cite_client::{
    ClientError, NodeClient, archive_download_name, archive_kind_from_name, export_file_name,
    validate_archive_name, validate_certificate_id, validate_doppler_slug, validate_job_id,
    validate_site_id,
};

use crate::error::ApiError;
use crate::state::AppState;

pub const MAX_REQUEST_BODY: usize = 1024 * 1024;
// The connector caps the JSON at 128 KiB; escaped newlines make a 100 KiB PEM pair somewhat larger on the wire.
pub const MAX_CERTIFICATE_BODY: usize = 144 * 1024;
// Several hundred rules in one change; a rule is a few hundred bytes, so this is generous and still half the general cap.
pub const MAX_BULK_BODY: usize = 512 * 1024;
// A token is a few dozen characters; a kilobyte leaves room for the JSON and nothing more.
pub const MAX_TOKEN_BODY: usize = 1024;
pub const MAX_ENV_BODY: usize = 64 * 1024;
pub const MAX_ISSUE_BODY: usize = 16 * 1024;
pub const MAX_ALERTS_BODY: usize = 64 * 1024;
// A Doppler binding is two names, two flags and an optional token.
pub const MAX_DOPPLER_BODY: usize = 4 * 1024;

const PREFIX: &str = "/api/v1/nodes/";
const PROXY_TIMEOUT: Duration = Duration::from_secs(30);
// Switch, rollback, deploy and create wait on health checks and stack starts, which can take over a minute.
const LONG_TIMEOUT: Duration = Duration::from_secs(700);
const LONG_ACTIONS: [&str; 5] = [
    "switch",
    "rollback",
    "deploy",
    "maintenance",
    "github-token",
];
const MAX_SEGMENT_LEN: usize = 128;
const EXPORT_ROUTE: &str = "analytics/export";
const ANALYTICS_ROUTES: [&str; 9] = [
    "summary",
    "timeseries",
    "requests",
    "bots",
    "top",
    "facets",
    "compare",
    "stats",
    "export",
];
const ANALYTICS_WRITE_ROUTES: [&str; 3] = ["backup", "cut", "restore"];
const ARCHIVE_PREFIX: &str = "analytics/archives/";
const ALLOWED_PREFIXES: [&str; 13] = [
    "alerts",
    "doppler",
    "node",
    "settings",
    "audit",
    "sites",
    "pages",
    "firewall",
    "analytics",
    "haproxy",
    "tokens",
    "certificates",
    "cloudflare",
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

// Certificates and the Cloudflare list are also limited to the exact (method, route) pairs the console uses.
fn certificate_route_ok(method: &Method, rest: &str) -> bool {
    let mut segments = rest.split('/');
    let first = segments.next();
    if !matches!(first, Some("certificates" | "cloudflare")) {
        return true;
    }
    let second = segments.next();
    let third = segments.next();
    if first == Some("certificates") && second == Some("acme") {
        let more = segments.next().is_some();
        return match third {
            None => method == Method::GET || method == Method::POST,
            Some(job) => !more && method == Method::GET && validate_job_id(job).is_ok(),
        };
    }
    // Anything beyond the exact shapes below is refused, but only for these two prefixes.
    if third.is_some() {
        return false;
    }
    match (first, second) {
        (Some("certificates"), Some("generate" | "origin-ca")) => method == Method::POST,
        (Some("certificates"), None) => method == Method::GET || method == Method::POST,
        (Some("certificates"), Some(id)) => {
            (method == Method::GET || method == Method::PUT || method == Method::DELETE)
                && validate_certificate_id(id).is_ok()
        }
        (Some("cloudflare"), Some("ranges")) => method == Method::GET,
        _ => false,
    }
}

fn is_zone_secret_route(rest: &str) -> bool {
    let mut segments = rest.split('/');
    segments.next() == Some("sites") && segments.nth(1) == Some("zone-secret")
}

// Only the exact status and rotate pair is open here; the other site routes keep their prefix-level access.
fn zone_secret_route_ok(method: &Method, rest: &str) -> bool {
    if !is_zone_secret_route(rest) {
        return true;
    }
    let segments: Vec<&str> = rest.split('/').collect();
    matches!(segments.as_slice(), [_, id, _] if validate_site_id(id).is_ok())
        && (method == Method::GET || method == Method::POST)
}

// The bulk route is a single POST with no further segments; the other firewall routes keep their prefix-level access.
fn bulk_route_ok(method: &Method, rest: &str) -> bool {
    let mut segments = rest.split('/');
    if segments.next() != Some("firewall") || segments.next() != Some("bulk") {
        return true;
    }
    segments.next().is_none() && method == Method::POST
}

// Site status, logs, token, environment and Doppler routes are exact (method, route) pairs; the other site actions keep prefix-level access.
const SITE_OPS: [&str; 7] = [
    "status",
    "logs",
    "github-token",
    "build-env",
    "runtime-env",
    "doppler",
    "volumes",
];

fn site_ops_action(rest: &str) -> Option<&str> {
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        ["sites", _, action, ..] if SITE_OPS.contains(action) => Some(*action),
        _ => None,
    }
}

fn site_ops_route_ok(method: &Method, rest: &str) -> bool {
    let Some(action) = site_ops_action(rest) else {
        return true;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    let (id, sub) = match segments.as_slice() {
        [_, id, _] => (*id, None),
        [_, id, "doppler", "sync"] => (*id, Some("sync")),
        [_, id, "volumes", name] => (*id, Some(*name)),
        _ => return false,
    };
    if validate_site_id(id).is_err() {
        return false;
    }
    match (action, sub) {
        ("doppler", Some(_)) => method == Method::POST,
        ("volumes", Some(name)) => {
            method == Method::DELETE && cite_edge::validate::is_valid_volume_name(name)
        }
        ("volumes", None) => method == Method::GET,
        (_, Some(_)) => false,
        ("status" | "logs", None) => method == Method::GET,
        ("github-token" | "doppler", None) => {
            method == Method::GET || method == Method::PUT || method == Method::DELETE
        }
        (_, None) => method == Method::GET || method == Method::PATCH,
    }
}

// The project list and a project's configs are the only node-level Doppler reads.
fn doppler_route_ok(method: &Method, rest: &str) -> bool {
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        ["doppler", ..] if method != Method::GET => false,
        ["doppler", "projects"] => true,
        ["doppler", "projects", project, "configs"] => validate_doppler_slug(project).is_ok(),
        ["doppler", ..] => false,
        _ => true,
    }
}

fn alerts_route_ok(method: &Method, rest: &str) -> bool {
    let mut segments = rest.split('/');
    if segments.next() != Some("alerts") {
        return true;
    }
    let second = segments.next();
    if segments.next().is_some() {
        return false;
    }
    match second {
        None => method == Method::GET || method == Method::PUT,
        Some("test") => method == Method::POST,
        Some(_) => false,
    }
}

// Tokens, status, logs and certificate issuing carry secrets or live state, so no cache may keep them.
fn is_no_store(rest: &str) -> bool {
    if is_zone_secret_route(rest) {
        return true;
    }
    if site_ops_action(rest).is_some() {
        return true;
    }
    let mut segments = rest.split('/');
    matches!(
        (segments.next(), segments.next()),
        (
            Some("certificates"),
            Some("generate" | "origin-ca" | "acme")
        ) | (Some("alerts" | "doppler"), _)
    )
}

fn route_ok(method: &Method, rest: &str) -> bool {
    analytics_route_ok(method, rest)
        && certificate_route_ok(method, rest)
        && zone_secret_route_ok(method, rest)
        && bulk_route_ok(method, rest)
        && site_ops_route_ok(method, rest)
        && alerts_route_ok(method, rest)
        && doppler_route_ok(method, rest)
}

fn body_limit_for(method: &Method, rest: &str) -> usize {
    let write = matches!(*method, Method::POST | Method::PUT | Method::PATCH);
    if !write {
        return MAX_REQUEST_BODY;
    }
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        ["certificates", "generate" | "origin-ca" | "acme"] => MAX_ISSUE_BODY,
        ["certificates", ..] if *method != Method::PATCH => MAX_CERTIFICATE_BODY,
        ["firewall", "bulk"] if *method == Method::POST => MAX_BULK_BODY,
        ["sites", _, "github-token"] if *method == Method::PUT => MAX_TOKEN_BODY,
        ["sites", _, "build-env" | "runtime-env"] if *method == Method::PATCH => MAX_ENV_BODY,
        ["sites", _, "doppler"] if *method == Method::PUT => MAX_DOPPLER_BODY,
        ["sites", _, "doppler", "sync"] => MAX_TOKEN_BODY,
        ["alerts"] if *method == Method::PUT => MAX_ALERTS_BODY,
        ["alerts", "test"] => MAX_TOKEN_BODY,
        _ => MAX_REQUEST_BODY,
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
        (Some("certificates"), Some("acme" | "origin-ca"), None, _) => method == Method::POST,
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
    if !allowed(rest) || !route_ok(&parts.method, rest) {
        return Err(not_found());
    }
    // PATCH exists only for the environment routes, and route_ok has already pinned it to them.
    let env_patch = parts.method == Method::PATCH
        && matches!(site_ops_action(rest), Some("build-env" | "runtime-env"));
    if !(matches!(
        parts.method,
        Method::GET | Method::POST | Method::PUT | Method::DELETE
    ) || env_patch)
    {
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
    let payload = if matches!(parts.method, Method::POST | Method::PUT | Method::PATCH) {
        to_bytes(body, body_limit_for(&parts.method, rest))
            .await
            .map_err(|_| {
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
    let mut builder = Response::builder().status(status).header(
        header::CONTENT_TYPE,
        response_content_type(forwarded.content_type.as_deref()),
    );
    // A rotated secret is shown once, so no cache may keep it
    if is_no_store(rest) {
        builder = builder.header(header::CACHE_CONTROL, "no-store");
    }
    builder
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
        assert_eq!(ANALYTICS_ROUTES.len(), 9);
        for route in ["facets", "compare"] {
            assert!(ANALYTICS_ROUTES.contains(&route));
            assert!(!analytics_route_ok(
                &Method::DELETE,
                &format!("analytics/{route}")
            ));
            assert!(!analytics_route_ok(
                &Method::GET,
                &format!("analytics/{route}/extra")
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
    fn certificate_and_cloudflare_routes_use_exact_method_pairs() {
        let id = "01JC9ZQ7M3X8V4N2B6T5R0WHYA";
        let item = format!("certificates/{id}");
        let yes = [
            (Method::GET, "certificates"),
            (Method::POST, "certificates"),
            (Method::GET, item.as_str()),
            (Method::PUT, item.as_str()),
            (Method::DELETE, item.as_str()),
            (Method::GET, "cloudflare/ranges"),
        ];
        for (method, rest) in yes {
            assert!(allowed(rest), "{rest}");
            assert!(route_ok(&method, rest), "{method} {rest}");
        }
        let no = [
            (Method::PUT, "certificates"),
            (Method::DELETE, "certificates"),
            (Method::POST, item.as_str()),
            (Method::PATCH, item.as_str()),
            (Method::POST, "cloudflare/ranges"),
            (Method::PUT, "cloudflare/ranges"),
            (Method::GET, "cloudflare"),
            (Method::GET, "cloudflare/other"),
            (Method::GET, "certificates/x"),
            (Method::GET, "certificates/01jc9zq7m3x8v4n2b6t5r0whya"),
            (Method::GET, "certificates/0123456789abcdef0123456789abcdef"),
            (Method::PUT, "certificates/0123456789abcdef0123456789abcdef"),
            (
                Method::DELETE,
                "certificates/0123456789abcdef0123456789abcdef",
            ),
            (Method::GET, "certificates/01JC9ZQ7M3X8V4N2B6T5R0WHY"),
            (Method::DELETE, "certificates/.."),
            (Method::GET, "certificates/01JC9ZQ7M3X8V4N2B6T5R0WHYA/extra"),
            (Method::GET, "cloudflare/ranges/extra"),
        ];
        for (method, rest) in no {
            assert!(!route_ok(&method, rest), "{method} {rest}");
        }
        assert!(route_ok(&Method::POST, "sites"));
        assert!(route_ok(&Method::GET, "analytics/archives"));
    }

    #[test]
    fn zone_secret_routes_are_exact_pairs_with_valid_site_ids() {
        for method in [Method::GET, Method::POST] {
            assert!(route_ok(&method, "sites/shop/zone-secret"), "{method}");
        }
        for method in [Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(!route_ok(&method, "sites/shop/zone-secret"), "{method}");
        }
        for rest in [
            "sites/shop/zone-secret/extra",
            "sites/Shop/zone-secret",
            "sites/-x/zone-secret",
            "sites/a_b/zone-secret",
        ] {
            assert!(!route_ok(&Method::GET, rest), "{rest}");
            assert!(!route_ok(&Method::POST, rest), "{rest}");
        }
        assert!(is_zone_secret_route("sites/shop/zone-secret"));
        assert!(!is_zone_secret_route("sites/zone-secret"));
        assert!(!is_zone_secret_route("sites/shop/deploy"));
        assert!(route_ok(&Method::POST, "sites/shop/deploy"));
        assert!(route_ok(&Method::PUT, "sites/shop"));
        assert_eq!(
            timeout_for(&Method::POST, "sites/shop/zone-secret"),
            PROXY_TIMEOUT
        );
    }

    #[test]
    fn site_status_token_and_env_routes_are_exact_pairs() {
        let yes = [
            (Method::GET, "sites/shop/status"),
            (Method::GET, "sites/shop/logs"),
            (Method::GET, "sites/shop/github-token"),
            (Method::PUT, "sites/shop/github-token"),
            (Method::DELETE, "sites/shop/github-token"),
            (Method::GET, "sites/shop/build-env"),
            (Method::PATCH, "sites/shop/build-env"),
            (Method::GET, "sites/shop/runtime-env"),
            (Method::PATCH, "sites/shop/runtime-env"),
            (Method::POST, "sites/shop/deploy"),
        ];
        for (method, rest) in yes {
            assert!(allowed(rest) && route_ok(&method, rest), "{method} {rest}");
        }
        let no = [
            (Method::POST, "sites/shop/status"),
            (Method::PUT, "sites/shop/logs"),
            (Method::POST, "sites/shop/github-token"),
            (Method::PATCH, "sites/shop/github-token"),
            (Method::PUT, "sites/shop/build-env"),
            (Method::DELETE, "sites/shop/runtime-env"),
            (Method::GET, "sites/shop/status/extra"),
            (Method::GET, "sites/Bad_Id/status"),
            (Method::PUT, "sites/../github-token"),
        ];
        for (method, rest) in no {
            assert!(!route_ok(&method, rest), "{method} {rest}");
        }
        assert!(is_no_store("sites/shop/status") && is_no_store("sites/shop/github-token"));
        assert!(is_no_store("sites/shop/logs") && is_no_store("certificates/acme"));
        assert!(!is_no_store("sites/shop") && !is_no_store("sites/shop/deploy"));
    }

    #[test]
    fn volume_routes_are_a_listing_and_a_named_delete() {
        for (method, rest) in [
            (Method::GET, "sites/shop/volumes"),
            (Method::DELETE, "sites/shop/volumes/data"),
            (Method::DELETE, "sites/shop/volumes/uploads-2"),
        ] {
            assert!(route_ok(&method, rest), "{method} {rest}");
            assert!(is_no_store(rest), "{rest}");
        }
        for (method, rest) in [
            (Method::POST, "sites/shop/volumes"),
            (Method::DELETE, "sites/shop/volumes"),
            (Method::GET, "sites/shop/volumes/data"),
            (Method::PUT, "sites/shop/volumes/data"),
            (Method::DELETE, "sites/shop/volumes/Data"),
            (Method::DELETE, "sites/shop/volumes/a_b"),
            (Method::DELETE, "sites/shop/volumes/data/extra"),
            (Method::DELETE, "sites/Bad_Id/volumes/data"),
        ] {
            assert!(!route_ok(&method, rest), "{method} {rest}");
        }
    }

    #[test]
    fn doppler_routes_are_exact_pairs_with_small_bodies() {
        let yes = [
            (Method::GET, "doppler/projects"),
            (Method::GET, "doppler/projects/shop.web/configs"),
            (Method::GET, "sites/shop/doppler"),
            (Method::PUT, "sites/shop/doppler"),
            (Method::DELETE, "sites/shop/doppler"),
            (Method::POST, "sites/shop/doppler/sync"),
        ];
        for (method, rest) in yes {
            assert!(allowed(rest) && route_ok(&method, rest), "{method} {rest}");
            assert!(is_no_store(rest), "{rest}");
        }
        let long = format!("doppler/projects/{}/configs", "a".repeat(101));
        let no = [
            (Method::POST, "doppler/projects"),
            (Method::DELETE, "doppler/projects"),
            (Method::GET, "doppler"),
            (Method::GET, "doppler/other"),
            (Method::GET, "doppler/projects/shop"),
            (Method::GET, "doppler/projects/shop/configs/extra"),
            (Method::PUT, "doppler/projects/shop/configs"),
            (Method::GET, long.as_str()),
            (Method::POST, "sites/shop/doppler"),
            (Method::PATCH, "sites/shop/doppler"),
            (Method::GET, "sites/shop/doppler/sync"),
            (Method::PUT, "sites/shop/doppler/sync"),
            (Method::POST, "sites/shop/doppler/other"),
            (Method::POST, "sites/shop/doppler/sync/extra"),
            (Method::POST, "sites/Bad_Id/doppler/sync"),
            (Method::GET, "sites/Bad_Id/doppler"),
            (Method::POST, "sites/shop/github-token/sync"),
        ];
        for (method, rest) in no {
            assert!(!route_ok(&method, rest), "{method} {rest}");
        }
        assert_eq!(body_limit_for(&Method::PUT, "sites/a/doppler"), 4 * 1024);
        assert_eq!(
            body_limit_for(&Method::POST, "sites/a/doppler/sync"),
            MAX_TOKEN_BODY
        );
        assert_eq!(
            timeout_for(&Method::PUT, "sites/a/doppler"),
            PROXY_TIMEOUT
        );
    }

    #[test]
    fn certificate_issue_and_alert_routes_are_exact_pairs() {
        let yes = [
            (Method::POST, "certificates/generate"),
            (Method::POST, "certificates/origin-ca"),
            (Method::POST, "certificates/acme"),
            (Method::GET, "certificates/acme"),
            (Method::GET, "certificates/acme/job-1"),
            (Method::GET, "alerts"),
            (Method::PUT, "alerts"),
            (Method::POST, "alerts/test"),
        ];
        for (method, rest) in yes {
            assert!(allowed(rest) && route_ok(&method, rest), "{method} {rest}");
        }
        let no = [
            (Method::GET, "certificates/generate"),
            (Method::PUT, "certificates/acme"),
            (Method::POST, "certificates/acme/job-1"),
            (Method::GET, "certificates/acme/job-1/extra"),
            (Method::GET, "certificates/acme/a%2Fb"),
            (Method::POST, "alerts"),
            (Method::DELETE, "alerts"),
            (Method::GET, "alerts/test"),
            (Method::POST, "alerts/other"),
            (Method::PUT, "alerts/test/x"),
        ];
        for (method, rest) in no {
            assert!(!route_ok(&method, rest), "{method} {rest}");
        }
    }

    #[test]
    fn the_new_write_routes_have_their_own_body_caps() {
        assert_eq!(body_limit_for(&Method::PUT, "sites/a/github-token"), 1024);
        assert_eq!(
            body_limit_for(&Method::PATCH, "sites/a/build-env"),
            64 * 1024
        );
        assert_eq!(
            body_limit_for(&Method::PATCH, "sites/a/runtime-env"),
            64 * 1024
        );
        assert_eq!(
            body_limit_for(&Method::POST, "certificates/generate"),
            16 * 1024
        );
        assert_eq!(
            body_limit_for(&Method::POST, "certificates/acme"),
            16 * 1024
        );
        assert_eq!(body_limit_for(&Method::PUT, "alerts"), 64 * 1024);
        assert_eq!(
            body_limit_for(&Method::POST, "certificates"),
            MAX_CERTIFICATE_BODY
        );
        assert_eq!(timeout_for(&Method::POST, "sites/a/deploy"), LONG_TIMEOUT);
        assert_eq!(
            timeout_for(&Method::PUT, "sites/a/github-token"),
            LONG_TIMEOUT
        );
        assert_eq!(
            timeout_for(&Method::POST, "certificates/acme"),
            LONG_TIMEOUT
        );
        assert_eq!(timeout_for(&Method::GET, "sites/a/status"), PROXY_TIMEOUT);
    }

    #[test]
    fn the_bulk_route_is_one_post_with_its_own_body_limit() {
        assert!(route_ok(&Method::POST, "firewall/bulk"));
        for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(!route_ok(&method, "firewall/bulk"), "{method}");
        }
        assert!(!route_ok(&Method::POST, "firewall/bulk/extra"));
        assert!(route_ok(&Method::POST, "firewall/rules"));
        assert!(route_ok(&Method::PUT, "firewall/rules/a"));
        assert!(route_ok(&Method::GET, "firewall/presets"));
        assert_eq!(
            body_limit_for(&Method::POST, "firewall/bulk"),
            MAX_BULK_BODY
        );
        assert_eq!(MAX_BULK_BODY, 512 * 1024);
        assert_eq!(
            body_limit_for(&Method::POST, "firewall/rules"),
            MAX_REQUEST_BODY
        );
        assert_eq!(
            body_limit_for(&Method::GET, "firewall/bulk"),
            MAX_REQUEST_BODY
        );
        assert_eq!(timeout_for(&Method::POST, "firewall/bulk"), PROXY_TIMEOUT);
    }

    #[test]
    fn only_certificate_writes_get_the_small_body_limit() {
        for (method, rest) in [
            (Method::POST, "certificates"),
            (Method::PUT, "certificates/01JC9ZQ7M3X8V4N2B6T5R0WHYA"),
        ] {
            assert_eq!(body_limit_for(&method, rest), MAX_CERTIFICATE_BODY);
        }
        for (method, rest) in [
            (Method::POST, "sites"),
            (Method::PUT, "settings"),
            (Method::GET, "certificates"),
            (Method::POST, "cloudflare/ranges"),
        ] {
            assert_eq!(body_limit_for(&method, rest), MAX_REQUEST_BODY);
        }
        assert_eq!(MAX_CERTIFICATE_BODY, 144 * 1024);
        assert_eq!(timeout_for(&Method::POST, "certificates"), PROXY_TIMEOUT);
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

    #[test]
    fn the_combined_route_check_keeps_archive_and_other_routes_reachable() {
        assert!(route_ok(&Method::GET, "analytics/archives"));
        assert!(route_ok(
            &Method::GET,
            "analytics/archives/requests-2026-11-05.ndjson.gz"
        ));
        assert!(route_ok(&Method::GET, "certificates"));
        assert!(route_ok(&Method::GET, "cloudflare/ranges"));
        assert!(!route_ok(
            &Method::GET,
            "certificates/0123456789abcdef/extra"
        ));
        assert!(!route_ok(&Method::GET, "cloudflare/other"));
    }
}
