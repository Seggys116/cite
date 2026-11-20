use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use cite_client::{
    ClientError, NodeClient, archive_download_name, archive_kind_from_name, backup_download_name,
    export_file_name, instance_backup_download_name, validate_archive_name, validate_backup_id,
    validate_certificate_id, validate_data_name, validate_doppler_slug, validate_env_name,
    validate_job_id, validate_pg_name, validate_site_id, validate_target_id,
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
// Data writes are names, small settings and credentials (an S3 key pair, one database URL); the connector caps them at 64 KiB too.
pub const MAX_DATA_BODY: usize = 64 * 1024;

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
const ALLOWED_PREFIXES: [&str; 14] = [
    "data",
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
const SITE_OPS: [&str; 8] = [
    "status",
    "logs",
    "github-token",
    "build-env",
    "runtime-env",
    "doppler",
    "volumes",
    "data",
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
    // The data routes nest several levels deep, so they have their own table rather than the shapes below.
    if action == "data" {
        return data_route_ok(method, rest);
    }
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

// The data routes are an exact (method, shape) table with every id and name validated; a path that matches no row is refused.
// Node-to-node transfer (`exports` and `imports`) is deliberately absent: the dashboard server drives those through `NodeClient`
// on its own `/api/v1/transfers` routes (`transfers.rs`), so a browser never relays a chunk or sees a manifest. The one transfer
// related arm here is the progress of an on-node conversion, which the browser polls for itself.
fn data_route_ok(method: &Method, rest: &str) -> bool {
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        ["sites", id, "data", tail @ ..] => {
            validate_site_id(id).is_ok() && site_data_route_ok(method, tail)
        }
        ["data", tail @ ..] => node_data_route_ok(method, tail),
        _ => true,
    }
}

fn site_data_route_ok(method: &Method, tail: &[&str]) -> bool {
    let get = method == Method::GET;
    let put = method == Method::PUT;
    let post = method == Method::POST;
    let patch = method == Method::PATCH;
    let delete = method == Method::DELETE;
    fn pg(name: &str) -> bool {
        validate_pg_name(name).is_ok()
    }
    fn named(name: &str) -> bool {
        validate_data_name(name).is_ok()
    }
    fn backup(id: &str) -> bool {
        validate_backup_id(id).is_ok()
    }
    match tail {
        [] => get,
        ["postgres"] => put || delete,
        ["postgres", "policy"] => put,
        ["postgres", "convert"] => post,
        ["postgres", "convert", session] => get && validate_job_id(session).is_ok(),
        ["postgres", "convert", session, "cutover" | "abort"] => {
            post && validate_job_id(session).is_ok()
        }
        ["postgres", "retired"] => delete,
        ["postgres", "databases"] => post,
        ["postgres", "databases", db] => delete && pg(db),
        ["postgres", "databases", db, "users"] => post && pg(db),
        ["postgres", "databases", db, "users", user] => (patch || delete) && pg(db) && pg(user),
        ["postgres", "databases", db, "users", user, "rotate"] => post && pg(db) && pg(user),
        ["external", name] | ["s3", name] => (put || delete) && named(name),
        ["secrets"] => post,
        ["secrets", name, "rotate"] => post && named(name),
        ["secrets", name] => delete && named(name),
        ["links"] => get || post,
        ["links", "preset"] => post,
        ["links", target, var] => {
            delete && matches!(*target, "runtime" | "build") && validate_env_name(var).is_ok()
        }
        ["backups"] => get || post,
        ["backups", id] => (get || patch || delete) && backup(id),
        ["backups", id, "download"] => get && backup(id),
        ["backups", id, "restore" | "push"] => post && backup(id),
        ["prune-preview"] => get,
        ["prune"] => post,
        _ => false,
    }
}

fn node_data_route_ok(method: &Method, tail: &[&str]) -> bool {
    let get = method == Method::GET;
    let put = method == Method::PUT;
    let post = method == Method::POST;
    let delete = method == Method::DELETE;
    fn backup(id: &str) -> bool {
        validate_backup_id(id).is_ok()
    }
    match tail {
        [] => get,
        ["jobs", job] => get && validate_job_id(job).is_ok(),
        ["targets"] => get || post,
        ["targets", target] => (put || delete) && validate_target_id(target).is_ok(),
        ["targets", target, "test"] => post && validate_target_id(target).is_ok(),
        ["shared"] => get || put || delete,
        ["shared", "restart"] => post,
        ["shared", "backups"] => get || post,
        ["shared", "backups", id] => delete && backup(id),
        ["shared", "backups", id, "download"] => get && backup(id),
        ["orphans"] => get,
        ["orphans", site] => delete && validate_site_id(site).is_ok(),
        _ => false,
    }
}

enum DataDownload<'a> {
    Site { site: &'a str, backup: &'a str },
    Shared { backup: &'a str },
}

// The two backup download routes, which are relayed as streams; ids are validated again so a caller cannot skip `route_ok`.
fn data_download_target(rest: &str) -> Option<DataDownload<'_>> {
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        ["sites", site, "data", "backups", backup, "download"]
            if validate_site_id(site).is_ok() && validate_backup_id(backup).is_ok() =>
        {
            Some(DataDownload::Site { site, backup })
        }
        ["data", "shared", "backups", backup, "download"] if validate_backup_id(backup).is_ok() => {
            Some(DataDownload::Shared { backup })
        }
        _ => None,
    }
}

// One byte range of digits (`bytes=0-99`, `bytes=100-`, `bytes=-50`); anything else is dropped rather than relayed.
fn range_header_ok(value: &str) -> bool {
    let Some((first, last)) = value
        .strip_prefix("bytes=")
        .and_then(|spec| spec.split_once('-'))
    else {
        return false;
    };
    let digits = |s: &str| s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit());
    digits(first) && digits(last) && !(first.is_empty() && last.is_empty())
}

fn content_range_ok(value: &str) -> bool {
    value.len() <= 64
        && value.strip_prefix("bytes ").is_some_and(|rest| {
            rest.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'/' | b'*'))
        })
}

// A refusal the console can act on keeps its status; the rest is a node failure.
fn data_stream_error(err: ClientError) -> ApiError {
    match err {
        ClientError::Status {
            code: code @ (400 | 404 | 409 | 416 | 422 | 429 | 501 | 503),
            message,
        } => ApiError::new(
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            message,
        ),
        other => other.into(),
    }
}

// The file name is rebuilt from the backup record (site, database, version) or the validated id, never from the node's header.
async fn stream_data_backup(
    client: &NodeClient,
    target: DataDownload<'_>,
    range: Option<&str>,
) -> Result<Response, ApiError> {
    let range = range.filter(|r| range_header_ok(r));
    let (stream, name) = match target {
        DataDownload::Site { site, backup } => {
            let record = client
                .site_backup(site, backup)
                .await
                .map_err(data_stream_error)?;
            let name = backup_download_name(site, &record.database, record.version);
            let stream = client
                .site_backup_stream(site, backup, range)
                .await
                .map_err(data_stream_error)?;
            (stream, name)
        }
        DataDownload::Shared { backup } => {
            let stream = client
                .data_shared_backup_stream(backup, range)
                .await
                .map_err(data_stream_error)?;
            (stream, instance_backup_download_name(backup))
        }
    };
    let status = match stream.status() {
        200 => StatusCode::OK,
        206 => StatusCode::PARTIAL_CONTENT,
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "node sent an unexpected status",
            ));
        }
    };
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        )
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(len) = stream.content_length() {
        builder = builder.header(header::CONTENT_LENGTH, len);
    }
    if let Some(value) = stream.content_range().filter(|v| content_range_ok(v)) {
        builder = builder.header(header::CONTENT_RANGE, value);
    }
    // `sha256()` only returns a well-formed 64 character hex value.
    if let Some(sha) = stream.sha256() {
        builder = builder.header("x-backup-sha256", sha);
    }
    builder
        .body(Body::from_stream(stream.into_body_stream()))
        .map_err(ApiError::internal)
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
        ) | (Some("alerts" | "doppler" | "data"), _)
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
        && data_route_ok(method, rest)
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
        ["sites", _, "data", ..] | ["data", ..] => MAX_DATA_BODY,
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
    // PATCH exists only for the environment and data routes, and route_ok has already pinned it to the exact rows of each.
    let env_patch = parts.method == Method::PATCH
        && matches!(
            site_ops_action(rest),
            Some("build-env" | "runtime-env" | "data")
        );
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
    if parts.method == Method::GET
        && let Some(target) = data_download_target(rest)
    {
        let range = parts
            .headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok());
        return stream_data_backup(&client, target, range).await;
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
        assert_eq!(timeout_for(&Method::PUT, "sites/a/doppler"), PROXY_TIMEOUT);
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

    const BID: &str = "01JC9ZQ7M3X8V4N2B6T5R0WHYA";

    fn site_data_rows() -> Vec<(Method, String)> {
        let b = BID;
        vec![
            (Method::GET, "sites/shop/data".into()),
            (Method::PUT, "sites/shop/data/postgres".into()),
            (Method::DELETE, "sites/shop/data/postgres".into()),
            (Method::PUT, "sites/shop/data/postgres/policy".into()),
            (Method::POST, "sites/shop/data/postgres/convert".into()),
            (
                Method::GET,
                "sites/shop/data/postgres/convert/01JC9ZQ7M3X8V4N2B6T5R0WHYA".into(),
            ),
            (
                Method::POST,
                "sites/shop/data/postgres/convert/01JC9ZQ7M3X8V4N2B6T5R0WHYA/cutover".into(),
            ),
            (
                Method::POST,
                "sites/shop/data/postgres/convert/01JC9ZQ7M3X8V4N2B6T5R0WHYA/abort".into(),
            ),
            (Method::DELETE, "sites/shop/data/postgres/retired".into()),
            (Method::POST, "sites/shop/data/postgres/databases".into()),
            (
                Method::DELETE,
                "sites/shop/data/postgres/databases/app".into(),
            ),
            (
                Method::POST,
                "sites/shop/data/postgres/databases/app/users".into(),
            ),
            (
                Method::PATCH,
                "sites/shop/data/postgres/databases/app/users/rw".into(),
            ),
            (
                Method::DELETE,
                "sites/shop/data/postgres/databases/app/users/rw".into(),
            ),
            (
                Method::POST,
                "sites/shop/data/postgres/databases/app/users/rw/rotate".into(),
            ),
            (Method::PUT, "sites/shop/data/external/billing-db".into()),
            (Method::DELETE, "sites/shop/data/external/billing-db".into()),
            (Method::PUT, "sites/shop/data/s3/media".into()),
            (Method::DELETE, "sites/shop/data/s3/media".into()),
            (Method::POST, "sites/shop/data/secrets".into()),
            (
                Method::POST,
                "sites/shop/data/secrets/auth-secret/rotate".into(),
            ),
            (Method::DELETE, "sites/shop/data/secrets/auth-secret".into()),
            (Method::GET, "sites/shop/data/links".into()),
            (Method::POST, "sites/shop/data/links".into()),
            (
                Method::DELETE,
                "sites/shop/data/links/runtime/DATABASE_URL".into(),
            ),
            (
                Method::DELETE,
                "sites/shop/data/links/build/DATABASE_URL".into(),
            ),
            (Method::POST, "sites/shop/data/links/preset".into()),
            (Method::GET, "sites/shop/data/backups".into()),
            (Method::POST, "sites/shop/data/backups".into()),
            (Method::GET, format!("sites/shop/data/backups/{b}")),
            (Method::PATCH, format!("sites/shop/data/backups/{b}")),
            (Method::DELETE, format!("sites/shop/data/backups/{b}")),
            (Method::GET, format!("sites/shop/data/backups/{b}/download")),
            (Method::POST, format!("sites/shop/data/backups/{b}/restore")),
            (Method::POST, format!("sites/shop/data/backups/{b}/push")),
            (Method::GET, "sites/shop/data/prune-preview".into()),
            (Method::POST, "sites/shop/data/prune".into()),
        ]
    }

    fn node_data_rows() -> Vec<(Method, String)> {
        let b = BID;
        vec![
            (Method::GET, "data".into()),
            (Method::GET, "data/jobs/01JC9ZQ7M3X8V4N2B6T5R0WHYA".into()),
            (Method::GET, "data/targets".into()),
            (Method::POST, "data/targets".into()),
            (Method::PUT, "data/targets/t1".into()),
            (Method::DELETE, "data/targets/t1".into()),
            (Method::POST, "data/targets/t1/test".into()),
            (Method::GET, "data/shared".into()),
            (Method::PUT, "data/shared".into()),
            (Method::DELETE, "data/shared".into()),
            (Method::POST, "data/shared/restart".into()),
            (Method::GET, "data/shared/backups".into()),
            (Method::POST, "data/shared/backups".into()),
            (Method::DELETE, format!("data/shared/backups/{b}")),
            (Method::GET, format!("data/shared/backups/{b}/download")),
            (Method::GET, "data/orphans".into()),
            (Method::DELETE, "data/orphans/old-shop".into()),
        ]
    }

    #[test]
    fn every_data_row_is_allowed_with_its_exact_method() {
        for (method, rest) in site_data_rows().into_iter().chain(node_data_rows()) {
            assert!(allowed(&rest), "{rest}");
            assert!(route_ok(&method, &rest), "{method} {rest}");
        }
        assert!(site_ops_action("sites/shop/data/links").is_some());
        assert_eq!(site_ops_action("sites/shop/data"), Some("data"));
        assert_eq!(site_ops_action("data/shared"), None);
    }

    #[test]
    fn data_routes_refuse_every_other_method() {
        let all = [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ];
        let rows: Vec<(Method, String)> = site_data_rows()
            .into_iter()
            .chain(node_data_rows())
            .collect();
        for (_, rest) in &rows {
            for method in &all {
                let listed = rows.iter().any(|(m, r)| m == method && r == rest);
                assert_eq!(route_ok(method, rest), listed, "{method} {rest}");
            }
        }
    }

    #[test]
    fn data_routes_refuse_extra_depth_and_unknown_shapes() {
        let b = BID;
        let no: Vec<(Method, String)> = vec![
            (Method::GET, "sites/shop/data/extra".into()),
            (Method::GET, "sites/shop/data/links/extra".into()),
            (Method::GET, "sites/shop/data/backups/x".into()),
            (
                Method::GET,
                format!("sites/shop/data/backups/{b}/download/extra"),
            ),
            (Method::POST, format!("sites/shop/data/backups/{b}/other")),
            (
                Method::POST,
                "sites/shop/data/postgres/convert/x/other".into(),
            ),
            (
                Method::POST,
                "sites/shop/data/postgres/convert/a%2Fb/abort".into(),
            ),
            (Method::GET, "sites/shop/data/postgres".into()),
            (Method::GET, "sites/shop/data/postgres/databases".into()),
            (
                Method::DELETE,
                "sites/shop/data/postgres/databases/app/users".into(),
            ),
            (
                Method::POST,
                "sites/shop/data/postgres/databases/app/users/rw/rotate/extra".into(),
            ),
            (Method::DELETE, "sites/shop/data/links".into()),
            (Method::DELETE, "sites/shop/data/links/runtime".into()),
            (
                Method::DELETE,
                "sites/shop/data/links/both/DATABASE_URL".into(),
            ),
            (
                Method::DELETE,
                "sites/shop/data/links/runtime/database_url".into(),
            ),
            (Method::GET, "sites/shop/data/secrets".into()),
            (Method::GET, "data/jobs".into()),
            (Method::GET, "data/jobs/a/b".into()),
            (Method::GET, "data/shared/other".into()),
            (Method::GET, "data/shared/restart".into()),
            (Method::DELETE, "data/targets".into()),
            (Method::GET, "data/orphans/old-shop".into()),
            (Method::GET, "data/unknown".into()),
        ];
        for (method, rest) in no {
            assert!(!route_ok(&method, &rest), "{method} {rest}");
        }
    }

    #[test]
    fn data_route_ids_and_names_are_validated() {
        let bad: Vec<(Method, String)> = vec![
            (Method::GET, "sites/Bad_Id/data".into()),
            (Method::GET, "sites/-x/data/links".into()),
            (
                Method::DELETE,
                "sites/shop/data/postgres/databases/App".into(),
            ),
            (
                Method::DELETE,
                "sites/shop/data/postgres/databases/a-b".into(),
            ),
            (
                Method::DELETE,
                "sites/shop/data/postgres/databases/abcdefghijklmnopq".into(),
            ),
            (
                Method::PATCH,
                "sites/shop/data/postgres/databases/app/users/RW".into(),
            ),
            (Method::PUT, "sites/shop/data/external/Billing".into()),
            (Method::PUT, "sites/shop/data/external/1db".into()),
            (Method::PUT, "sites/shop/data/s3/a_b".into()),
            (Method::DELETE, "sites/shop/data/secrets/Auth".into()),
            (Method::GET, "sites/shop/data/backups/not-a-ulid".into()),
            (
                Method::GET,
                "sites/shop/data/backups/01jc9zq7m3x8v4n2b6t5r0whya".into(),
            ),
            (
                Method::GET,
                "sites/shop/data/backups/01JC9ZQ7M3X8V4N2B6T5R0WHYI".into(),
            ),
            (Method::DELETE, "data/shared/backups/short".into()),
            (Method::DELETE, "data/orphans/Bad_Id".into()),
            (Method::PUT, "data/targets/a.b".into()),
            (Method::GET, "data/jobs/a.b".into()),
        ];
        for (method, rest) in bad {
            assert!(!route_ok(&method, &rest), "{method} {rest}");
        }
    }

    #[test]
    fn the_conversion_progress_route_is_a_get_of_one_validated_session() {
        let ok = format!("sites/shop/data/postgres/convert/{BID}");
        assert!(route_ok(&Method::GET, &ok));
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!route_ok(&method, &ok), "{method}");
        }
        for rest in [
            "sites/shop/data/postgres/convert/a%2Fb",
            "sites/shop/data/postgres/convert/a.b",
            "sites/shop/data/postgres/convert/..",
            "sites/shop/data/postgres/convert/x/y/z",
            "sites/Bad_Id/data/postgres/convert/x",
        ] {
            assert!(!route_ok(&Method::GET, rest), "{rest}");
        }
        // The start, cutover and abort rows keep their own methods.
        assert!(!route_ok(&Method::GET, "sites/shop/data/postgres/convert"));
        assert!(!route_ok(&Method::GET, &format!("{ok}/cutover")));
        assert!(!route_ok(&Method::GET, &format!("{ok}/abort")));
    }

    #[test]
    fn transfer_routes_are_not_reachable_through_the_proxy() {
        let b = BID;
        let denied: Vec<String> = vec![
            "sites/shop/data/exports".into(),
            "sites/shop/data/exports/s1".into(),
            "sites/shop/data/exports/s1/chunks/0".into(),
            "sites/shop/data/exports/s1/manifest".into(),
            "sites/shop/data/imports".into(),
            "sites/shop/data/imports/s1".into(),
            "sites/shop/data/imports/s1/chunks/0".into(),
            "sites/shop/data/imports/s1/commit".into(),
            "sites/shop/data/imports/s1/finish".into(),
            "sites/shop/data/postgres/exports".into(),
            "data/exports".into(),
            "data/exports/s1".into(),
            "data/imports".into(),
            "data/imports/s1/chunks/0".into(),
            format!("data/shared/exports/{b}"),
        ];
        for rest in denied {
            for method in [
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ] {
                assert!(!route_ok(&method, &rest), "{method} {rest}");
            }
        }
    }

    #[test]
    fn data_writes_get_the_small_body_limit_and_the_short_timeout() {
        for (method, rest) in [
            (Method::PUT, "sites/a/data/postgres"),
            (Method::POST, "sites/a/data/links"),
            (Method::PATCH, "sites/a/data/backups/x"),
            (Method::PUT, "data/targets/t1"),
            (Method::POST, "data/targets"),
        ] {
            assert_eq!(body_limit_for(&method, rest), MAX_DATA_BODY, "{rest}");
            assert_eq!(timeout_for(&method, rest), PROXY_TIMEOUT, "{rest}");
        }
        assert_eq!(MAX_DATA_BODY, 64 * 1024);
        assert_eq!(
            body_limit_for(&Method::GET, "sites/a/data/backups"),
            MAX_REQUEST_BODY
        );
        assert_eq!(
            body_limit_for(&Method::PUT, "sites/a/doppler"),
            MAX_DOPPLER_BODY
        );
        assert_eq!(body_limit_for(&Method::POST, "sites"), MAX_REQUEST_BODY);
        assert_eq!(timeout_for(&Method::POST, "sites/a/data"), PROXY_TIMEOUT);
    }

    #[test]
    fn data_responses_are_never_cached() {
        for rest in [
            "sites/shop/data",
            "sites/shop/data/links",
            "sites/shop/data/backups",
            "data",
            "data/shared",
            "data/targets",
        ] {
            assert!(is_no_store(rest), "{rest}");
        }
        assert!(!is_no_store("sites/shop") && !is_no_store("pages"));
    }

    #[test]
    fn download_targets_are_the_two_backup_routes_only() {
        let b = BID;
        match data_download_target(&format!("sites/shop/data/backups/{b}/download")) {
            Some(DataDownload::Site { site, backup }) => assert_eq!((site, backup), ("shop", b)),
            _ => panic!("site download not recognised"),
        }
        match data_download_target(&format!("data/shared/backups/{b}/download")) {
            Some(DataDownload::Shared { backup }) => assert_eq!(backup, b),
            _ => panic!("shared download not recognised"),
        }
        for rest in [
            format!("sites/shop/data/backups/{b}"),
            format!("sites/shop/data/backups/{b}/restore"),
            "sites/shop/data/backups/x/download".to_string(),
            "sites/Bad_Id/data/backups/01JC9ZQ7M3X8V4N2B6T5R0WHYA/download".to_string(),
            format!("data/shared/backups/{b}"),
            "data/shared/backups/x/download".to_string(),
            "analytics/archives/a.db".to_string(),
        ] {
            assert!(data_download_target(&rest).is_none(), "{rest}");
        }
    }

    #[test]
    fn only_a_single_plain_byte_range_is_relayed() {
        for ok in ["bytes=0-99", "bytes=100-", "bytes=-50", "bytes=0-0"] {
            assert!(range_header_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "bytes=",
            "bytes=-",
            "bytes=0-1,5-9",
            "bytes=a-b",
            "items=0-1",
            "bytes=0-1\r\nx: y",
            "bytes=0",
            "bytes=000000000000000000000-1",
        ] {
            assert!(!range_header_ok(bad), "{bad:?}");
        }
        assert!(content_range_ok("bytes 0-3/10") && content_range_ok("bytes */10"));
        for bad in [
            "",
            "items 0-3/10",
            "bytes 0-3/10\r\nx: y",
            "javascript:alert(1)",
        ] {
            assert!(!content_range_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn download_errors_keep_their_actionable_status() {
        let status = |code: u16| {
            data_stream_error(ClientError::Status {
                code,
                message: "m".into(),
            })
            .into_response()
            .status()
        };
        for code in [400, 404, 409, 416, 422, 429, 501, 503] {
            assert_eq!(status(code).as_u16(), code);
        }
        assert_eq!(status(500), StatusCode::BAD_GATEWAY);
        assert_eq!(status(401), StatusCode::BAD_GATEWAY);
    }

    mod relay {
        use std::sync::{Arc, Mutex};

        use axum::Router;
        use axum::extract::{Path, State};
        use axum::http::HeaderMap;
        use axum::routing::get;
        use cite_client::NodeConfig;

        use super::*;

        const GOOD: &str = "01JC9ZQ7M3X8V4N2B6T5R0WHYA";
        const ODD: &str = "01JC9ZQ7M3X8V4N2B6T5R0WHYB";

        type Seen = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

        async fn record(Path((_site, _bid)): Path<(String, String)>) -> Response {
            axum::Json(serde_json::json!({
                "id": GOOD, "database": "pg:app", "version": 3, "created_at": "2026-11-20T00:00:00Z"
            }))
            .into_response()
        }

        async fn download(
            State(seen): State<Seen>,
            Path(params): Path<std::collections::HashMap<String, String>>,
            headers: HeaderMap,
        ) -> Response {
            let bid = params.get("bid").cloned().unwrap_or_default();
            let range = headers
                .get(header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let auth = headers
                .get(cite_client::CLIENT_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            seen.lock().expect("lock").push((range.clone(), auth));
            let odd = bid == ODD;
            let sha = if odd {
                "zz".to_string()
            } else {
                "ab".repeat(32)
            };
            let mut b = Response::builder()
                .header(header::CONTENT_TYPE, "text/html")
                .header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"evil.exe\"",
                )
                .header("x-backup-sha256", sha);
            if range.is_some() {
                let value = if odd {
                    "javascript:alert(1)"
                } else {
                    "bytes 0-3/10"
                };
                b = b.status(206).header(header::CONTENT_RANGE, value);
                return b.body(Body::from("0123")).expect("response");
            }
            b.body(Body::from("0123456789")).expect("response")
        }

        async fn spawn(seen: Seen) -> NodeClient {
            let app = Router::new()
                .route("/api/v1/sites/{site}/data/backups/{bid}", get(record))
                .route(
                    "/api/v1/sites/{site}/data/backups/{bid}/download",
                    get(download),
                )
                .route("/api/v1/data/shared/backups/{bid}/download", get(download))
                .with_state(seen);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            let cfg = NodeConfig {
                name: "n1".into(),
                url: format!("http://{addr}"),
                ca_pem: None,
                token_ref: "n1".into(),
                insecure_http: false,
            };
            NodeClient::new(&cfg, "cite_good".into()).expect("client")
        }

        fn header_of(resp: &Response, name: &str) -> Option<String> {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        }

        #[tokio::test]
        async fn a_site_download_gets_a_rebuilt_name_and_the_node_headers_are_not_trusted() {
            let seen: Seen = Arc::default();
            let client = spawn(seen.clone()).await;
            let target = DataDownload::Site {
                site: "shop",
                backup: GOOD,
            };
            let resp = stream_data_backup(&client, target, None)
                .await
                .expect("relay");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                header_of(&resp, "content-disposition").as_deref(),
                Some("attachment; filename=\"shop-app-v3.dump\"")
            );
            assert_eq!(
                header_of(&resp, "content-type").as_deref(),
                Some("application/octet-stream")
            );
            assert_eq!(
                header_of(&resp, "x-content-type-options").as_deref(),
                Some("nosniff")
            );
            assert_eq!(
                header_of(&resp, "cache-control").as_deref(),
                Some("no-store")
            );
            assert_eq!(header_of(&resp, "accept-ranges").as_deref(), Some("bytes"));
            assert_eq!(header_of(&resp, "content-length").as_deref(), Some("10"));
            assert_eq!(
                header_of(&resp, "x-backup-sha256").as_deref(),
                Some("ab".repeat(32).as_str())
            );
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("body");
            assert_eq!(&body[..], b"0123456789");
            let seen = seen.lock().expect("lock");
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].0, None);
            assert_eq!(seen[0].1.as_deref(), Some(cite_client::CLIENT_VERSION));
        }

        #[tokio::test]
        async fn a_valid_range_is_passed_through_and_a_partial_answer_is_relayed() {
            let seen: Seen = Arc::default();
            let client = spawn(seen.clone()).await;
            let target = DataDownload::Site {
                site: "shop",
                backup: GOOD,
            };
            let resp = stream_data_backup(&client, target, Some("bytes=0-3"))
                .await
                .expect("relay");
            assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                header_of(&resp, "content-range").as_deref(),
                Some("bytes 0-3/10")
            );
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("body");
            assert_eq!(&body[..], b"0123");
            assert_eq!(
                seen.lock().expect("lock")[0].0.as_deref(),
                Some("bytes=0-3")
            );
        }

        #[tokio::test]
        async fn a_malformed_range_is_dropped_before_it_reaches_the_node() {
            let seen: Seen = Arc::default();
            let client = spawn(seen.clone()).await;
            let target = DataDownload::Site {
                site: "shop",
                backup: GOOD,
            };
            let resp = stream_data_backup(&client, target, Some("bytes=0-1,5-9"))
                .await
                .expect("relay");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(seen.lock().expect("lock")[0].0, None);
        }

        #[tokio::test]
        async fn malformed_node_headers_are_not_relayed() {
            let seen: Seen = Arc::default();
            let client = spawn(seen).await;
            let resp = stream_data_backup(
                &client,
                DataDownload::Shared { backup: ODD },
                Some("bytes=0-3"),
            )
            .await
            .expect("relay");
            assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
            assert!(header_of(&resp, "content-range").is_none());
            assert!(header_of(&resp, "x-backup-sha256").is_none());
            assert_eq!(
                header_of(&resp, "content-disposition").as_deref(),
                Some(format!("attachment; filename=\"cite-pg-shared-{ODD}.tar\"").as_str())
            );
        }
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
