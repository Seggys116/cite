use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cite_client::{
    AnalyticsQuery, ArchiveKind, BlockedFilter, CertificateUpload, ClientError, CutRequest,
    DopplerBindRequest, EnvPatch, ExportFormat, ExportKind, ExportQuery, FirewallBulk, GithubTokenBody, LogsQuery,
    MAX_PEM_BYTES, NodeClient, NodeConfig, NodeTargets, ReplicationMode, ReplicationPlan,
    RequestCursor, TopSort, apply_site_to_nodes, fan_out,
};
use cite_edge::analytics::Summary;
use cite_edge::model::{
    FirewallRule, HealthCheck, Maintenance, Redirect, Site, SiteKind, Slot, Source, Target,
    Upstream,
};
use serde_json::{Value, json};

struct Fake {
    token: String,
    sites: Mutex<Vec<Value>>,
    created_bodies: Mutex<Vec<Value>>,
    delay_ms: u64,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    seen_auth: Mutex<Vec<Option<String>>>,
    last_query: Mutex<Option<String>>,
}

type Shared = Arc<Fake>;

fn fake(token: &str, delay_ms: u64) -> Shared {
    Arc::new(Fake {
        token: token.to_string(),
        sites: Mutex::new(Vec::new()),
        created_bodies: Mutex::new(Vec::new()),
        delay_ms,
        in_flight: AtomicUsize::new(0),
        max_in_flight: AtomicUsize::new(0),
        seen_auth: Mutex::new(Vec::new()),
        last_query: Mutex::new(None),
    })
}

fn error_response(code: StatusCode, message: &str) -> Response {
    (code, Json(json!({ "error": message }))).into_response()
}

#[allow(clippy::result_large_err)]
fn check(state: &Fake, headers: &HeaderMap) -> Result<(), Response> {
    let got = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let want = format!("Bearer {}", state.token);
    let ok = got.as_deref() == Some(want.as_str());
    state.seen_auth.lock().expect("lock").push(got);
    if ok {
        Ok(())
    } else {
        Err(error_response(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

async fn healthz() -> Response {
    Json(json!({ "ok": true })).into_response()
}

async fn login(State(s): State<Shared>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    s.seen_auth.lock().expect("lock").push(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
    );
    if body["totp"] == "123456" && body["username"] == "admin" {
        Json(json!({ "token": "cite_login_token", "expires_at": "2030-01-01T00:00:00Z" }))
            .into_response()
    } else {
        error_response(StatusCode::UNAUTHORIZED, "invalid credentials")
    }
}

async fn node(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    let now = s.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    s.max_in_flight.fetch_max(now, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(s.delay_ms)).await;
    s.in_flight.fetch_sub(1, Ordering::SeqCst);
    Json(json!({
        "name": "fake",
        "version": "9.9.9",
        "uptime_secs": 5,
        "haproxy": { "running": true },
        "sites": 0,
        "firewall_rules": 0,
        "github": { "token_configured": true, "source": "env" },
        "doppler": { "configured": true, "source": "file" }
    }))
    .into_response()
}

async fn list_sites(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(Value::Array(s.sites.lock().expect("lock").clone())).into_response()
}

async fn create_site(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies.lock().expect("lock").push(body.clone());
    if let Some(obj) = body.as_object_mut() {
        obj.remove("github_token");
    }
    let mut sites = s.sites.lock().expect("lock");
    if sites.iter().any(|x| x["id"] == body["id"]) {
        return error_response(StatusCode::CONFLICT, "site already exists");
    }
    sites.push(body.clone());
    Json(body).into_response()
}

async fn get_site(State(s): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    let found = s
        .sites
        .lock()
        .expect("lock")
        .iter()
        .find(|x| x["id"] == id)
        .cloned();
    match found {
        Some(mut site) => {
            site["live"] = json!({ "blue": [], "green": [] });
            Json(site).into_response()
        }
        None => error_response(StatusCode::NOT_FOUND, "site not found"),
    }
}

async fn put_site(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    let mut sites = s.sites.lock().expect("lock");
    match sites.iter_mut().find(|x| x["id"] == id) {
        Some(slot) => {
            *slot = body.clone();
            Json(body).into_response()
        }
        None => error_response(StatusCode::NOT_FOUND, "site not found"),
    }
}

async fn summary(
    State(s): State<Shared>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = query;
    Json(Summary::default()).into_response()
}

async fn bots(State(s): State<Shared>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = query;
    Json(json!({
        "total_requests": 200,
        "bot_requests": 50,
        "bot_share_pct": 25.0,
        "classes": [{ "key": "crawler", "count": 30, "bytes": 900 }],
        "signals": [{ "key": "ua_generic_crawler", "count": 30, "bytes": 900 }],
        "agents": [{ "key": "Googlebot", "count": 30, "bytes": 900 }],
        "score_buckets": [{ "key": "80-100", "count": 20, "bytes": 0 }]
    }))
    .into_response()
}

async fn top(State(s): State<Shared>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = query;
    Json(json!({ "items": [{ "key": "/", "count": 9, "bytes": 90 }] })).into_response()
}

async fn timeseries(
    State(s): State<Shared>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = query;
    Json(json!({
        "step_secs": 300,
        "points": [{ "ts": 10, "requests": 4, "bytes_out": 8, "errors": 1, "blocked": 0, "avg_ms": 2.5 }],
        "partial": true, "scanned": 5_000_000, "from_ms": 1000, "to_ms": 2000, "source": "raw"
    }))
    .into_response()
}

async fn requests(
    State(s): State<Shared>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = query;
    Json(json!({
        "items": [],
        "next_cursor": { "before_ts": 77, "before_id": 12 },
        "partial": false, "filters": { "status_class": ["5xx"] }
    }))
    .into_response()
}

async fn facets(
    State(s): State<Shared>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = query;
    Json(json!({
        "site": [{ "key": "shop", "count": 3 }],
        "host": [], "method": [{ "key": "GET", "count": 3 }],
        "status_class": [], "bot_class": []
    }))
    .into_response()
}

async fn compare(
    State(s): State<Shared>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = query;
    let mut current = serde_json::to_value(Summary::default()).expect("json");
    current["requests"] = json!(12);
    Json(json!({
        "against": "previous",
        "current": current,
        "previous": Summary::default(),
        "delta": { "requests": { "current": 12, "previous": 0, "abs": 12 } }
    }))
    .into_response()
}

async fn stats(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(json!({
        "rows": 12, "db_bytes": 8192, "oldest_ts_ms": null, "newest_ts_ms": 5,
        "write_batches": 3, "write_errors": 0
    }))
    .into_response()
}

// The query decides the behaviour: kind=bots is a bad request, limit=1 is huge, limit=2 breaks mid-stream.
async fn export(
    State(s): State<Shared>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    let query = query.unwrap_or_default();
    *s.last_query.lock().expect("lock") = Some(query.clone());
    if query.contains("kind=bots") {
        return error_response(StatusCode::BAD_REQUEST, "bots export is disabled");
    }
    let chunk = || Ok::<_, std::io::Error>(vec![b'a'; 1024]);
    let body = if query.contains("limit=1&") || query.ends_with("limit=1") {
        Body::from_stream(futures_util::stream::iter((0..1000).map(move |_| chunk())))
    } else if query.contains("limit=2") {
        let items = vec![chunk(), Err(std::io::Error::other("connection lost"))];
        Body::from_stream(futures_util::stream::iter(items))
    } else {
        Body::from("ts,path\n1,/\n")
    };
    let mut resp = Response::new(body);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        "text/csv; charset=utf-8".parse().expect("ct"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        "attachment; filename=\"cite-requests.csv\""
            .parse()
            .expect("cd"),
    );
    resp
}

fn archive_item(name: &str, kind: &str) -> Value {
    json!({
        "name": name, "kind": kind, "bytes": 2048, "created_ms": 1_700_000_000_000_i64,
        "sha256": "ab".repeat(32), "rows": 7, "from_ms": 1, "to_ms": 2
    })
}

async fn archives(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(json!({
        "items": [archive_item("requests-2026-11-05.ndjson.gz", "archive")],
        "dir_bytes": 2048
    }))
    .into_response()
}

async fn backup(State(s): State<Shared>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies.lock().expect("lock").push(body);
    Json(archive_item("analytics-20261105-101500.db", "backup")).into_response()
}

async fn cut(State(s): State<Shared>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies.lock().expect("lock").push(body.clone());
    if body["before_days"] == 99 {
        return error_response(StatusCode::CONFLICT, "a cut is already running");
    }
    let dry = body["dry_run"] == true;
    let archived: u64 = if dry { 0 } else { 5 };
    let files: Vec<&str> = if dry {
        Vec::new()
    } else {
        vec!["requests-2026-11-05.ndjson.gz"]
    };
    Json(json!({
        "dry_run": dry, "cutoff_ms": 1_000, "rows": 5, "oldest_ms": 10,
        "archived_rows": archived, "files": files, "archive": body["archive"]
    }))
    .into_response()
}

async fn restore(State(s): State<Shared>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies.lock().expect("lock").push(body);
    Json(json!({ "rows": 7 })).into_response()
}

async fn archive_file(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    if name == "missing.db" {
        return error_response(StatusCode::NOT_FOUND, "no such archive");
    }
    let mut resp = Response::new(Body::from(vec![0x1f, 0x8b, 8, 0]));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        "application/gzip".parse().expect("ct"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        "attachment; filename=\"evil.exe\"".parse().expect("cd"),
    );
    resp
}

async fn archive_delete(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies
        .lock()
        .expect("lock")
        .push(json!({ "deleted": name }));
    StatusCode::NO_CONTENT.into_response()
}

const CERT_ID: &str = "01JC9ZQ7M3X8V4N2B6T5R0WHYA";
// PEM blocks are assembled at run time so no complete key block or secret-looking literal sits in the source.
fn pem(label: &[&str], body: &str) -> String {
    let name = label.join(" ");
    format!("-----BEGIN {name}-----\n{body}\n-----END {name}-----\n")
}

fn cert_pem() -> String {
    pem(&["CERTIFICATE"], "AAAA")
}

fn key_pem() -> String {
    pem(&["PRIVATE", "KEY"], "BBBB")
}

fn zone_secret_value() -> String {
    format!("Zs3{}", "cret".repeat(10))
}

fn cert_item(name: &str) -> Value {
    json!({
        "id": CERT_ID, "name": name, "subject": "example.com", "sans": ["example.com"],
        "issuer": "Test CA", "not_before": "2026-10-01", "not_after": "2026-12-01",
        "days_left": 25, "fingerprint_sha256": "ab:cd", "key_type": "ECDSA P-256",
        "created_at": "2026-11-01T00:00:00Z", "covers": ["example.com"]
    })
}

async fn certificates(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(json!({
        "items": [cert_item("main"), json!({
            "id": "file:legacy.pem", "name": "legacy.pem", "source": "manual",
            "warning": "the file could not be read", "covers": []
        })], "https_port": null,
        "dir_ready": true, "uncovered_hosts": ["blog.example.com"]
    }))
    .into_response()
}

async fn certificate_create(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    if body["name"] == "duplicate" {
        return error_response(StatusCode::CONFLICT, "a certificate with that name exists");
    }
    s.created_bodies.lock().expect("lock").push(body);
    let mut item = cert_item("main");
    item["warning"] = json!("expires in 25 days");
    (StatusCode::CREATED, Json(item)).into_response()
}

async fn certificate_one(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    if id != CERT_ID {
        return error_response(StatusCode::NOT_FOUND, "no such certificate");
    }
    Json(cert_item("main")).into_response()
}

async fn certificate_replace(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies.lock().expect("lock").push(body);
    Json(cert_item("main")).into_response()
}

async fn certificate_delete(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies
        .lock()
        .expect("lock")
        .push(json!({ "deleted": id }));
    StatusCode::NO_CONTENT.into_response()
}

async fn cloudflare_ranges(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(json!({
        "source": "builtin", "updated": "2026-11-06", "ranges": ["173.245.48.0/20", "2400:cb00::/32"]
    }))
    .into_response()
}

async fn zone_secret_status(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    if id == "ghost" {
        return error_response(StatusCode::NOT_FOUND, "site not found");
    }
    Json(json!({
        "configured": id == "shop", "header": "X-Cite-Origin-Secret", "readable": id != "locked",
        "created_at": if id == "shop" { json!("2026-11-06T10:00:00Z") } else { Value::Null },
        "fingerprint": if id == "shop" { json!("ab12cd34") } else { Value::Null }
    }))
    .into_response()
}

async fn zone_secret_rotate(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies
        .lock()
        .expect("lock")
        .push(json!({ "rotated": id, "body": body }));
    let mut resp = Json(json!({
        "secret": zone_secret_value(), "header": "X-Cite-Origin-Secret",
        "created_at": "2026-11-06T11:00:00Z", "fingerprint": "ef56ab78"
    }))
    .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().expect("cc"));
    resp
}

async fn firewall_bulk_route(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    let replace = body["replace"].as_array().map_or(0, Vec::len);
    let delete = body["delete"].as_array().map_or(0, Vec::len);
    s.created_bodies.lock().expect("lock").push(body);
    Json(json!({ "created": replace, "replaced": 0, "deleted": delete })).into_response()
}

async fn token_route(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies.lock().expect("lock").push(body);
    Json(json!({ "source": "site", "site_token_set": true, "node_token_configured": false }))
        .into_response()
}

async fn env_route(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    let names: Vec<String> = body["set"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    s.created_bodies.lock().expect("lock").push(body);
    Json(json!({ "names": names })).into_response()
}

async fn status_route(
    State(s): State<Shared>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(json!({ "phase": "idle", "query": query })).into_response()
}

fn doppler_view(bound: bool) -> Value {
    json!({
        "bound": bound, "project": bound.then_some("shop"), "config": bound.then_some("prd"),
        "build": bound, "runtime": false, "token_source": "site", "status": "synced",
        "last_sync_at": "2026-11-06T10:00:00Z", "last_error": null, "keys": 2,
        "redeploy_needed": true, "skipped": []
    })
}

async fn doppler_projects_route(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(json!([{ "slug": "shop", "name": "Shop" }, { "slug": "api" }])).into_response()
}

async fn doppler_configs_route(
    State(s): State<Shared>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    *s.last_query.lock().expect("lock") = Some(project);
    Json(json!([{ "name": "prd", "environment": "production" }])).into_response()
}

async fn doppler_site_get(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(doppler_view(true)).into_response()
}

async fn doppler_site_put(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    s.created_bodies.lock().expect("lock").push(body);
    Json(doppler_view(true)).into_response()
}

async fn doppler_site_delete(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
    }
    Json(doppler_view(false)).into_response()
}

async fn haproxy_config() -> Response {
    ([(header::CONTENT_TYPE, "text/plain")], "global\n  daemon\n").into_response()
}

async fn redirect() -> Response {
    (StatusCode::FOUND, [(header::LOCATION, "/api/v1/node")]).into_response()
}

async fn garbage() -> Response {
    "this is not json".into_response()
}

async fn forbidden() -> Response {
    error_response(StatusCode::FORBIDDEN, "forbidden")
}

async fn plain_failure() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
}

// Plain http on the loopback interface, which NodeConfig accepts without the insecure flag.
async fn spawn(state: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/healthz", get(healthz))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/node", get(node))
        .route("/api/v1/sites", get(list_sites).post(create_site))
        .route("/api/v1/sites/{id}", get(get_site).put(put_site))
        .route("/api/v1/analytics/summary", get(summary))
        .route("/api/v1/analytics/bots", get(bots))
        .route("/api/v1/analytics/timeseries", get(timeseries))
        .route("/api/v1/analytics/requests", get(requests))
        .route("/api/v1/analytics/facets", get(facets))
        .route("/api/v1/analytics/compare", get(compare))
        .route("/api/v1/analytics/top", get(top))
        .route("/api/v1/analytics/stats", get(stats))
        .route("/api/v1/analytics/export", get(export))
        .route("/api/v1/analytics/archives", get(archives))
        .route(
            "/api/v1/analytics/archives/{name}",
            get(archive_file).delete(archive_delete),
        )
        .route("/api/v1/analytics/backup", post(backup))
        .route("/api/v1/analytics/cut", post(cut))
        .route("/api/v1/analytics/restore", post(restore))
        .route(
            "/api/v1/certificates",
            get(certificates).post(certificate_create),
        )
        .route(
            "/api/v1/certificates/{id}",
            get(certificate_one)
                .put(certificate_replace)
                .delete(certificate_delete),
        )
        .route("/api/v1/firewall/bulk", post(firewall_bulk_route))
        .route(
            "/api/v1/sites/{id}/github-token",
            axum::routing::put(token_route),
        )
        .route(
            "/api/v1/sites/{id}/build-env",
            axum::routing::patch(env_route),
        )
        .route("/api/v1/doppler/projects", get(doppler_projects_route))
        .route(
            "/api/v1/doppler/projects/{project}/configs",
            get(doppler_configs_route),
        )
        .route(
            "/api/v1/sites/{id}/doppler",
            get(doppler_site_get)
                .put(doppler_site_put)
                .delete(doppler_site_delete),
        )
        .route("/api/v1/sites/{id}/doppler/sync", post(doppler_site_get))
        .route("/api/v1/sites/{id}/status", get(status_route))
        .route("/api/v1/sites/{id}/logs", get(status_route))
        .route("/api/v1/cloudflare/ranges", get(cloudflare_ranges))
        .route(
            "/api/v1/sites/{id}/zone-secret",
            get(zone_secret_status).post(zone_secret_rotate),
        )
        .route("/api/v1/haproxy/config", get(haproxy_config))
        .route("/api/v1/pages", get(redirect))
        .route("/api/v1/settings", get(garbage))
        .route("/api/v1/tokens", get(forbidden))
        .route("/api/v1/audit", get(plain_failure))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn node_config(name: &str, url: &str) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        url: url.to_string(),
        ca_pem: None,
        token_ref: name.to_string(),
        insecure_http: false,
    }
}

fn client(name: &str, url: &str, token: &str) -> NodeClient {
    NodeClient::new(&node_config(name, url), token.to_string()).expect("client")
}

fn site(id: &str) -> Site {
    Site {
        id: id.to_string(),
        name: format!("Site {id}"),
        hosts: vec![format!("{id}.example.com")],
        path_regexes: Vec::new(),
        path_prefixes: Vec::new(),
        kind: SiteKind::Site,
        blue: Upstream {
            targets: vec![Target {
                addr: "10.0.0.1:8080".into(),
                weight: 100,
            }],
            label: None,
        },
        green: Upstream::default(),
        active: Slot::Blue,
        maintenance: Maintenance::default(),
        health: HealthCheck::default(),
        source: None,
        history: Vec::new(),
        access: Default::default(),
        volumes: Vec::new(),
        outbound: true,
        outbound_rules: Default::default(),
    }
}

#[tokio::test]
async fn node_info_sends_the_bearer_token_and_decodes() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let info = client("n1", &url, "cite_good")
        .node_info()
        .await
        .expect("info");
    assert_eq!(info.version, "9.9.9");
    assert_eq!(info.extra["uptime_secs"], 5);
    let github = info.github.expect("github status");
    assert!(github.token_configured);
    assert_eq!(github.source, "env");
    assert!(!info.extra.contains_key("github"));
    let doppler = info.doppler.expect("doppler status");
    assert!(doppler.configured);
    assert_eq!(doppler.source, "file");
    assert!(!info.extra.contains_key("doppler"));
    let seen = state.seen_auth.lock().expect("lock");
    assert_eq!(seen.as_slice(), [Some("Bearer cite_good".to_string())]);
}

#[test]
fn node_info_decodes_with_and_without_the_github_status() {
    let old: cite_client::NodeInfo =
        serde_json::from_value(json!({ "name": "n", "version": "1.0.0", "sites": 2 }))
            .expect("old node");
    assert!(old.github.is_none());
    assert!(old.doppler.is_none());
    assert_eq!(old.extra["sites"], 2);
    let none: cite_client::NodeInfo = serde_json::from_value(
        json!({ "name": "n", "version": "1", "github": { "token_configured": false, "source": "none" } }),
    )
    .expect("no token");
    let status = none.github.expect("status");
    assert!(!status.token_configured);
    assert_eq!(status.source, "none");
    let partial: cite_client::NodeInfo =
        serde_json::from_value(json!({ "github": {} })).expect("partial");
    assert!(!partial.github.expect("status").token_configured);
}

#[test]
fn node_info_decodes_the_egress_mode_when_present() {
    let old: cite_client::NodeInfo =
        serde_json::from_value(json!({ "executor_egress": true })).expect("old node");
    assert_eq!((old.executor_egress, old.egress_mode), (Some(true), None));
    let new: cite_client::NodeInfo = serde_json::from_value(
        json!({ "executor_egress": true, "egress_mode": "filtered" }),
    )
    .expect("new node");
    assert_eq!(new.egress_mode.as_deref(), Some("filtered"));
    assert!(!new.extra.contains_key("egress_mode"));
}

#[test]
fn outbound_rules_default_and_round_trip_on_the_site() {
    let rules = cite_client::OutboundRules::default();
    assert_eq!(rules.mode, cite_client::OutboundMode::Public);
    assert!(rules.allow.is_empty() && rules.deny.is_empty() && rules.block_mail);
    let mut s = site("shop");
    let text = serde_json::to_value(&s).unwrap();
    assert!(text.get("outbound_rules").is_none(), "the default is left out");
    s.outbound_rules = cite_client::OutboundRules {
        mode: cite_client::OutboundMode::Allowlist,
        allow: vec!["api.github.com".into()],
        deny: Vec::new(),
        block_mail: false,
    };
    let text = serde_json::to_value(&s).unwrap();
    assert_eq!(text["outbound_rules"]["mode"], "allowlist");
    let back: Site = serde_json::from_value(text).unwrap();
    assert_eq!(back, s);
}

// Built at run time so the fake login does not look like a hard-coded credential.
fn fixture_secret() -> String {
    "x".repeat(12)
}

#[tokio::test]
async fn login_sends_no_bearer_and_returns_the_token() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "");
    let ok = c
        .login("admin", &fixture_secret(), "123456")
        .await
        .expect("login");
    assert_eq!(ok.token, "cite_login_token");
    assert!(!format!("{ok:?}").contains("cite_login_token"));
    let err = c
        .login("admin", &fixture_secret(), "000000")
        .await
        .expect_err("bad code");
    assert_eq!(err.status_code(), Some(401));
    let seen = state.seen_auth.lock().expect("lock");
    assert!(seen.iter().all(Option::is_none));
}

#[tokio::test]
async fn error_bodies_become_status_errors() {
    let url = spawn(fake("cite_good", 0)).await;
    let wrong = client("n1", &url, "cite_wrong");
    match wrong.node_info().await.expect_err("unauthorized") {
        ClientError::Status { code, message } => {
            assert_eq!(code, 401);
            assert_eq!(message, "unauthorized");
        }
        other => panic!("unexpected error {other:?}"),
    }
    let good = client("n1", &url, "cite_good");
    let forbidden = good.list_tokens().await.expect_err("forbidden");
    assert_eq!(forbidden.to_string(), "node returned 403: forbidden");
    // A non-JSON failure body falls back to the status reason.
    match good.audit(None).await.expect_err("500") {
        ClientError::Status { code, message } => {
            assert_eq!(code, 500);
            assert_eq!(message, "Internal Server Error");
        }
        other => panic!("unexpected error {other:?}"),
    }
}

#[tokio::test]
async fn malformed_success_bodies_are_decode_errors() {
    let url = spawn(fake("cite_good", 0)).await;
    let err = client("n1", &url, "cite_good")
        .get_settings()
        .await
        .expect_err("garbage");
    assert!(matches!(err, ClientError::Decode(_)), "{err:?}");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let err = client("n1", &url, "cite_good")
        .list_pages()
        .await
        .expect_err("redirect");
    assert_eq!(err.status_code(), Some(302));
    // The redirect target would have recorded a request had it been followed.
    assert!(state.seen_auth.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn unreachable_nodes_are_transport_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let err = client("n1", &format!("http://{addr}"), "cite_good")
        .healthz()
        .await
        .expect_err("closed port");
    assert!(matches!(err, ClientError::Transport { .. }), "{err:?}");
}

#[test]
fn debug_output_never_contains_the_token() {
    let c = client("n1", "https://node.example.com:7443", "cite_super_secret");
    let shown = format!("{c:?}");
    assert!(!shown.contains("cite_super_secret"));
    assert!(shown.contains("n1"));
}

#[test]
fn plain_http_to_a_remote_host_is_refused() {
    let err = NodeClient::new(
        &node_config("n1", "http://node.example.com:7443"),
        "t".into(),
    )
    .expect_err("remote http");
    assert!(matches!(err, ClientError::Config(_)));
    let mut flagged = node_config("n1", "http://node.example.com:7443");
    flagged.insecure_http = true;
    assert!(NodeClient::new(&flagged, "t".into()).is_ok());
}

#[tokio::test]
async fn site_routes_round_trip() {
    let url = spawn(fake("cite_good", 0)).await;
    let c = client("n1", &url, "cite_good");
    assert!(c.list_sites().await.expect("list").is_empty());
    let created = c.create_site(&site("shop"), None).await.expect("create");
    assert_eq!(created.id, "shop");
    let detail = c.get_site("shop").await.expect("get");
    assert_eq!(detail.site, site("shop"));
    assert_eq!(detail.live, Some(json!({ "blue": [], "green": [] })));
    let mut changed = site("shop");
    changed.name = "Renamed".into();
    assert_eq!(
        c.update_site("shop", &changed).await.expect("put").name,
        "Renamed"
    );
    assert_eq!(c.list_sites().await.expect("list").len(), 1);
    let missing = c.get_site("nope").await.expect_err("missing");
    assert_eq!(missing.status_code(), Some(404));
}

#[tokio::test]
async fn analytics_query_carries_window_and_site() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let sum = c
        .analytics_summary("15m", Some("shop"))
        .await
        .expect("summary");
    assert_eq!(sum, Summary::default());
    let query = state
        .last_query
        .lock()
        .expect("lock")
        .clone()
        .expect("query");
    assert!(query.contains("window=15m"));
    assert!(query.contains("site=shop"));
}

#[tokio::test]
async fn bot_top_and_stats_routes_decode() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let summary = c.analytics_bots("24h", Some("shop")).await.expect("bots");
    assert_eq!(summary.bot_requests, 50);
    assert_eq!(summary.classes[0].key, "crawler");
    let query = state.last_query.lock().expect("lock").clone().expect("q");
    assert!(query.contains("window=24h") && query.contains("site=shop"));

    let items = c
        .analytics_top("paths", "1h", None, Some(5))
        .await
        .expect("top");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].count, 9);
    let query = state.last_query.lock().expect("lock").clone().expect("q");
    assert!(query.contains("kind=paths") && query.contains("limit=5"));

    let bad = c.analytics_top("bogus", "1h", None, None).await;
    assert!(matches!(bad, Err(ClientError::Config(_))));

    let stats = c.analytics_stats().await.expect("stats");
    assert_eq!(stats.rows, 12);
    assert_eq!(stats.oldest_ts_ms, None);
    assert_eq!(stats.newest_ts_ms, Some(5));
}

fn last_query(state: &Fake) -> Vec<(String, String)> {
    let raw = state
        .last_query
        .lock()
        .expect("lock")
        .clone()
        .expect("query");
    raw.split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex digits"));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).expect("utf8")
}

#[tokio::test]
async fn filtered_reads_send_encoded_parameters_and_decode_the_extra_fields() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let q = AnalyticsQuery::new()
        .range(1000, 2000)
        .sites(["shop", "blog"])
        .path_prefix("/a b&x=1#frag")
        .status_class("5xx")
        .blocked(BlockedFilter::Rule("r1".into()))
        .client_ip("10.0.0.0/8");

    let series = c.analytics_timeseries_q(&q).await.expect("timeseries");
    assert_eq!(series.series.step_secs, 300);
    assert!(series.meta.partial);
    assert_eq!(series.meta.scanned, Some(5_000_000));
    assert_eq!(series.meta.source.as_deref(), Some("raw"));
    let got = last_query(&state);
    for (k, v) in [
        ("from", "1000"),
        ("to", "2000"),
        ("site", "shop,blog"),
        ("path_prefix", "/a b&x=1#frag"),
        ("status_class", "5xx"),
        ("blocked", "rule:r1"),
        ("client_ip", "10.0.0.0/8"),
    ] {
        assert!(got.contains(&(k.into(), v.into())), "{k}={v} in {got:?}");
    }
    assert_eq!(got.len(), 7, "{got:?}");

    let sum = c.analytics_summary_q(&q).await.expect("summary");
    assert_eq!(sum.summary, Summary::default());
    assert!(!sum.meta.partial);
    let bots = c.analytics_bots_q(&q).await.expect("bots");
    assert_eq!(bots.bots.bot_requests, 50);
}

#[tokio::test]
async fn top_requests_facets_and_compare_calls() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let q = AnalyticsQuery::new().window("24h");

    let top = c
        .analytics_top_q("agents", &q, Some(20), TopSort::Bytes)
        .await
        .expect("top");
    assert_eq!(top.items[0].count, 9);
    let got = last_query(&state);
    for (k, v) in [
        ("window", "24h"),
        ("kind", "agents"),
        ("limit", "20"),
        ("sort", "bytes"),
    ] {
        assert!(got.contains(&(k.into(), v.into())), "{k}={v} in {got:?}");
    }
    assert!(matches!(
        c.analytics_top_q("bogus", &q, None, TopSort::Count).await,
        Err(ClientError::Config(_))
    ));
    assert!(matches!(
        c.analytics_top_q("paths", &q, Some(0), TopSort::Count)
            .await,
        Err(ClientError::Config(_))
    ));

    let cursor = RequestCursor {
        before_ts: 5,
        before_id: 6,
    };
    let page = c
        .analytics_requests_q(&q, Some(200), Some(&cursor))
        .await
        .expect("requests");
    assert_eq!(
        page.next_cursor,
        Some(RequestCursor {
            before_ts: 77,
            before_id: 12
        })
    );
    assert!(!page.meta.partial);
    let got = last_query(&state);
    for (k, v) in [
        ("envelope", "true"),
        ("limit", "200"),
        ("before_ts", "5"),
        ("before_id", "6"),
    ] {
        assert!(got.contains(&(k.into(), v.into())), "{k}={v} in {got:?}");
    }

    let facets = c.analytics_facets(&q).await.expect("facets");
    assert_eq!(facets.site[0].key, "shop");
    assert_eq!(facets.method[0].count, 3);
    assert!(facets.host.is_empty());

    let compare = c.analytics_compare(&q).await.expect("compare");
    assert_eq!(compare.against, "previous");
    assert_eq!(compare.current.summary.requests, 12);
    assert_eq!(compare.delta.requests.abs, 12.0);
    assert_eq!(compare.delta.requests.pct, None);
}

#[tokio::test]
async fn an_invalid_filter_never_reaches_the_node() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let bad = AnalyticsQuery::new().window("1h").range(1, 2);
    assert!(matches!(
        c.analytics_facets(&bad).await,
        Err(ClientError::Config(_))
    ));
    assert!(matches!(
        c.analytics_requests_q(&bad, None, None).await,
        Err(ClientError::Config(_))
    ));
    assert!(state.last_query.lock().expect("lock").is_none());
}

#[tokio::test]
async fn export_streams_to_a_file_and_reports_it() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let dir = tempfile::tempdir().expect("dir");
    let dest = dir.path().join("out.csv");
    let q = ExportQuery::new(ExportKind::Requests)
        .format(ExportFormat::Csv)
        .site("shop");
    let report = c
        .analytics_export_to(&q, &dest, 1024 * 1024)
        .await
        .expect("export");
    assert_eq!(
        std::fs::read_to_string(&dest).expect("file"),
        "ts,path\n1,/\n"
    );
    assert_eq!(report.bytes, 12);
    assert_eq!(report.suggested_name.as_deref(), Some("cite-requests.csv"));
    assert!(report.content_type.expect("ct").starts_with("text/csv"));
    let query = state.last_query.lock().expect("lock").clone().expect("q");
    assert!(query.contains("kind=requests") && query.contains("site=shop"));
    assert_eq!(std::fs::read_dir(dir.path()).expect("ls").count(), 1);
}

#[tokio::test]
async fn failed_exports_leave_no_file_behind() {
    let url = spawn(fake("cite_good", 0)).await;
    let c = client("n1", &url, "cite_good");
    let dir = tempfile::tempdir().expect("dir");
    let dest = dir.path().join("out.csv");

    let rejected = c
        .analytics_export_to(&ExportQuery::new(ExportKind::Bots), &dest, 1 << 20)
        .await
        .expect_err("rejected");
    assert_eq!(rejected.status_code(), Some(400));

    let oversized = ExportQuery::new(ExportKind::Requests).limit(1);
    let err = c
        .analytics_export_to(&oversized, &dest, 10 * 1024)
        .await
        .expect_err("over the cap");
    assert!(matches!(err, ClientError::Decode(_)), "{err:?}");

    let broken = ExportQuery::new(ExportKind::Requests).limit(2);
    c.analytics_export_to(&broken, &dest, 1 << 20)
        .await
        .expect_err("connection lost mid body");

    let invalid = ExportQuery::new(ExportKind::Top);
    let err = c
        .analytics_export_to(&invalid, &dest, 1 << 20)
        .await
        .expect_err("invalid query");
    assert!(matches!(err, ClientError::Config(_)));

    assert_eq!(std::fs::read_dir(dir.path()).expect("ls").count(), 0);
}

#[tokio::test]
async fn export_replaces_an_existing_destination() {
    let url = spawn(fake("cite_good", 0)).await;
    let c = client("n1", &url, "cite_good");
    let dir = tempfile::tempdir().expect("dir");
    let dest = dir.path().join("out.csv");
    std::fs::write(&dest, "old").expect("seed");
    c.analytics_export_to(&ExportQuery::new(ExportKind::Hourly), &dest, 1 << 20)
        .await
        .expect("export");
    assert!(
        std::fs::read_to_string(&dest)
            .expect("file")
            .starts_with("ts,path")
    );
}

#[tokio::test]
async fn export_stream_exposes_headers_and_body() {
    use futures_util::StreamExt;
    let url = spawn(fake("cite_good", 0)).await;
    let c = client("n1", &url, "cite_good");
    let stream = c
        .analytics_export_stream(&ExportQuery::new(ExportKind::Requests))
        .await
        .expect("stream");
    assert_eq!(stream.status(), 200);
    assert!(
        stream
            .content_disposition()
            .expect("cd")
            .starts_with("attachment")
    );
    let mut body = Vec::new();
    let mut chunks = Box::pin(stream.into_body_stream());
    while let Some(chunk) = chunks.next().await {
        body.extend_from_slice(&chunk.expect("chunk"));
    }
    assert_eq!(body, b"ts,path\n1,/\n");
}

#[tokio::test]
async fn archive_routes_round_trip() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");

    let list = c.analytics_archives().await.expect("list");
    assert_eq!(list.dir_bytes, 2048);
    assert_eq!(list.items[0].kind, ArchiveKind::Archive);
    assert_eq!(list.items[0].rows, Some(7));

    let made = c.analytics_backup().await.expect("backup");
    assert_eq!(made.kind, ArchiveKind::Backup);
    assert_eq!(made.download_name(), "analytics-20261105-101500.db");

    let dry = c
        .analytics_cut(&CutRequest::before_days(30).dry_run(true))
        .await
        .expect("dry run");
    assert!(dry.dry_run && dry.archive);
    assert_eq!(
        (dry.rows, dry.oldest_ms, dry.archived_rows),
        (5, Some(10), 0)
    );
    let real = c
        .analytics_cut(&CutRequest::before_ms(5_000).archive(false))
        .await
        .expect("cut");
    assert!(!real.archive);
    assert_eq!(real.files, ["requests-2026-11-05.ndjson.gz"]);

    let restored = c
        .analytics_restore("requests-2026-11-05.ndjson.gz")
        .await
        .expect("restore");
    assert_eq!(restored.rows, 7);
    c.analytics_archive_delete("analytics-20261105-101500.db")
        .await
        .expect("delete");

    let bodies = state.created_bodies.lock().expect("lock").clone();
    assert_eq!(bodies[0], json!({}));
    assert_eq!(
        bodies[1],
        json!({ "before_days": 30, "archive": true, "dry_run": true })
    );
    assert_eq!(
        bodies[2],
        json!({ "before_ms": 5000, "archive": false, "dry_run": false })
    );
    assert_eq!(
        bodies[3],
        json!({ "name": "requests-2026-11-05.ndjson.gz" })
    );
    assert_eq!(
        bodies[4],
        json!({ "deleted": "analytics-20261105-101500.db" })
    );
}

#[tokio::test]
async fn archive_calls_validate_before_any_request() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let cut = c.analytics_cut(&CutRequest::before_days(0)).await;
    assert!(matches!(cut, Err(ClientError::Config(_))));
    for bad in ["../etc/passwd", ".hidden", "a/b", "", "a b"] {
        let restore = c.analytics_restore(bad).await;
        assert!(matches!(restore, Err(ClientError::Config(_))), "{bad:?}");
        let delete = c.analytics_archive_delete(bad).await;
        assert!(matches!(delete, Err(ClientError::Config(_))), "{bad:?}");
        let stream = c.analytics_archive_stream(bad).await;
        assert!(matches!(stream, Err(ClientError::Config(_))), "{bad:?}");
    }
    assert!(state.seen_auth.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn certificate_routes_round_trip() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");

    let list = c.certificates().await.expect("list");
    assert_eq!(list.items.len(), 2);
    assert!(
        !list.items[0].is_manual()
            && list.items[0].source == "api"
            && list.items[0].warning.is_none()
    );
    assert!(list.items[1].is_manual());
    assert_eq!(list.items[1].id, "file:legacy.pem");
    assert_eq!(
        list.items[1].warning.as_deref(),
        Some("the file could not be read")
    );
    assert_eq!(list.items[0].days_left, 25);
    assert_eq!(list.items[0].covers, ["example.com"]);
    assert_eq!(list.https_port, None);
    assert!(list.dir_ready);
    assert_eq!(list.uncovered_hosts, ["blog.example.com"]);

    let one = c.certificate(CERT_ID).await.expect("get");
    assert_eq!(one.key_type, "ECDSA P-256");

    let (cert, key) = (cert_pem(), key_pem());
    let created = c
        .certificate_create(&CertificateUpload::new("main", cert.as_str(), key.as_str()))
        .await
        .expect("create");
    assert_eq!(created.certificate.id, CERT_ID);
    assert_eq!(created.warning.as_deref(), Some("expires in 25 days"));

    c.certificate_replace(
        CERT_ID,
        &CertificateUpload::replacement(cert.as_str(), key.as_str()),
    )
    .await
    .expect("replace");
    c.certificate_delete(CERT_ID).await.expect("delete");

    let bodies = state.created_bodies.lock().expect("lock").clone();
    let expect_create = json!({ "name": "main", "certificate": cert, "private_key": key });
    let expect_replace = json!({ "certificate": cert, "private_key": key });
    assert!(bodies[0] == expect_create, "create body differs");
    assert!(bodies[1] == expect_replace, "replace body differs");
    assert_eq!(bodies[2], json!({ "deleted": CERT_ID }));

    let ranges = c.cloudflare_ranges().await.expect("ranges");
    assert_eq!(ranges.source, "builtin");
    assert_eq!(ranges.updated, "2026-11-06");
    assert_eq!(ranges.ranges.len(), 2);
}

#[tokio::test]
async fn certificate_calls_validate_before_any_request() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    for bad in [
        "../etc/passwd",
        "",
        "0123456789abcdef0123456789abcdef",
        "01jc9zq7m3x8v4n2b6t5r0whya",
        "abc",
        "a/b",
    ] {
        let get = c.certificate(bad).await;
        assert!(matches!(get, Err(ClientError::Config(_))), "{bad:?}");
        let delete = c.certificate_delete(bad).await;
        assert!(matches!(delete, Err(ClientError::Config(_))), "{bad:?}");
        let replace = c
            .certificate_replace(bad, &CertificateUpload::replacement(cert_pem(), key_pem()))
            .await;
        assert!(matches!(replace, Err(ClientError::Config(_))), "{bad:?}");
    }
    let (cert, key) = (cert_pem(), key_pem());
    let oversized = "A".repeat(MAX_PEM_BYTES + 1);
    let big_cert = format!("{cert}{}", "A".repeat(MAX_PEM_BYTES / 2));
    let big_key = format!("{key}{}", "B".repeat(MAX_PEM_BYTES / 2));
    let header_name = format!("-----BEGIN {}-----", "CERTIFICATE");
    let uploads = [
        CertificateUpload::new(header_name.as_str(), cert.as_str(), key.as_str()),
        CertificateUpload::new("main", big_cert.as_str(), big_key.as_str()),
        CertificateUpload::new("bad/name", cert.as_str(), key.as_str()),
        CertificateUpload::new("", cert.as_str(), key.as_str()),
        CertificateUpload::new("main", "not pem", key.as_str()),
        CertificateUpload::new("main", cert.as_str(), cert.as_str()),
        CertificateUpload::new("main", oversized.as_str(), key.as_str()),
    ];
    for upload in &uploads {
        let created = c.certificate_create(upload).await;
        assert!(matches!(created, Err(ClientError::Config(_))), "{upload:?}");
    }
    let nameless = c
        .certificate_create(&CertificateUpload::replacement(cert_pem(), key_pem()))
        .await;
    assert!(matches!(nameless, Err(ClientError::Config(_))));
    assert!(state.seen_auth.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn certificate_errors_keep_the_node_status_and_message() {
    let url = spawn(fake("cite_good", 0)).await;
    let c = client("n1", &url, "cite_good");
    let clash = c
        .certificate_create(&CertificateUpload::new("duplicate", cert_pem(), key_pem()))
        .await
        .expect_err("conflict");
    assert_eq!(clash.status_code(), Some(409));
    assert!(clash.to_string().contains("that name exists"));
    let missing = c
        .certificate("01JC9ZQ7M3X8V4N2B6T5R0WHYB")
        .await
        .expect_err("missing");
    assert_eq!(missing.status_code(), Some(404));
}

#[tokio::test]
async fn zone_secret_routes_round_trip_and_never_leak_in_debug() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");

    let on = c.zone_secret("shop").await.expect("status");
    assert!(on.configured);
    assert_eq!(on.header, "X-Cite-Origin-Secret");
    assert_eq!(on.fingerprint.as_deref(), Some("ab12cd34"));
    let off = c.zone_secret("docs").await.expect("status");
    assert!(!off.configured && off.created_at.is_none() && off.fingerprint.is_none());
    assert!(on.readable && off.readable);
    let unreadable = c.zone_secret("locked").await.expect("status");
    assert!(!unreadable.readable && !unreadable.configured);

    let rotated = c.rotate_zone_secret("shop").await.expect("rotate");
    let expected = zone_secret_value();
    assert!(rotated.secret() == expected, "rotated secret differs");
    assert_eq!(rotated.fingerprint.as_deref(), Some("ef56ab78"));
    assert!(!format!("{rotated:?}").contains(&expected));

    let bodies = state.created_bodies.lock().expect("lock").clone();
    assert_eq!(bodies[0], json!({ "rotated": "shop", "body": {} }));

    let missing = c.zone_secret("ghost").await.expect_err("missing");
    assert_eq!(missing.status_code(), Some(404));
}

fn redirect_rule(id: &str) -> FirewallRule {
    FirewallRule {
        id: id.to_string(),
        name: format!("Redirect {id}"),
        enabled: true,
        redirect: Some(Redirect {
            to: "/new".to_string(),
            status: 301,
        }),
        ..FirewallRule::default()
    }
}

#[tokio::test]
async fn firewall_bulk_sends_one_request_and_decodes_the_counts() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let bulk = FirewallBulk::new(
        vec![redirect_rule("redirect-1"), redirect_rule("redirect-2")],
        vec!["redirect-9".to_string()],
    );
    let done = c.firewall_bulk(&bulk).await.expect("bulk");
    assert_eq!((done.created, done.replaced, done.deleted), (2, 0, 1));
    let bodies = state.created_bodies.lock().expect("lock").clone();
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["replace"][1]["id"], "redirect-2");
    assert_eq!(bodies[0]["replace"][0]["redirect"]["status"], 301);
    assert_eq!(bodies[0]["delete"], json!(["redirect-9"]));
}

#[tokio::test]
async fn site_token_and_env_calls_send_the_documented_bodies() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let value = ["ghp", "_", "abc123"].concat();
    let status = c
        .github_token_set("shop", &GithubTokenBody::new(&value).expect("token"))
        .await
        .expect("set");
    assert!(status.site_token_set);
    assert_eq!(status.source, "site");
    let mut patch = EnvPatch::default();
    patch
        .set
        .insert("API_URL".into(), "https://x.example".into());
    let names = c.build_env_patch("shop", &patch).await.expect("patch");
    assert_eq!(names.names, vec!["API_URL".to_string()]);
    let bodies = state.created_bodies.lock().expect("lock").clone();
    assert!(bodies[0]["token"] == value.as_str(), "token not sent");
    assert_eq!(bodies[1]["set"]["API_URL"], "https://x.example");
}

#[tokio::test]
async fn doppler_calls_send_the_documented_bodies_and_validate_first() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let projects = c.doppler_projects().await.expect("projects");
    assert_eq!(projects.len(), 2);
    assert_eq!((projects[0].slug.as_str(), projects[0].name.as_str()), ("shop", "Shop"));
    assert_eq!(projects[1].name, "", "a missing name decodes as empty");
    let configs = c.doppler_configs("shop.web").await.expect("configs");
    assert_eq!(configs[0].name, "prd");
    assert_eq!(configs[0].environment, "production");
    assert_eq!(
        state.last_query.lock().expect("lock").as_deref(),
        Some("shop.web")
    );

    let view = c.site_doppler("shop").await.expect("view");
    assert!(view.bound && view.build && !view.runtime);
    assert_eq!((view.keys, view.status.as_str()), (2, "synced"));
    assert_eq!(view.token_source, "site");

    let token = ["dp.st.", "prd.", "secret"].concat();
    let req = DopplerBindRequest {
        project: "shop".into(),
        config: "prd".into(),
        build: true,
        runtime: false,
        token: Some(token.clone()),
    };
    let set = c.site_doppler_set("shop", &req).await.expect("set");
    assert_eq!(set.project.as_deref(), Some("shop"));
    let bodies = state.created_bodies.lock().expect("lock").clone();
    assert_eq!(
        bodies.last().expect("body"),
        &json!({ "project": "shop", "config": "prd", "build": true, "runtime": false, "token": token })
    );
    let cleared = c.site_doppler_clear("shop").await.expect("clear");
    assert!(!cleared.bound && cleared.project.is_none());
    let synced = c.site_doppler_sync("shop").await.expect("sync");
    assert_eq!(synced.last_sync_at.as_deref(), Some("2026-11-06T10:00:00Z"));

    let sent = state.seen_auth.lock().expect("lock").len();
    for bad in ["a/b", "", "a b"] {
        assert!(matches!(
            c.doppler_configs(bad).await,
            Err(ClientError::Config(_))
        ));
    }
    assert!(matches!(
        c.site_doppler("Bad Id").await,
        Err(ClientError::Config(_))
    ));
    let neither = DopplerBindRequest {
        project: "shop".into(),
        config: "prd".into(),
        build: false,
        runtime: false,
        token: None,
    };
    assert!(matches!(
        c.site_doppler_set("shop", &neither).await,
        Err(ClientError::Config(_))
    ));
    assert!(!format!("{req:?}").contains("secret"));
    assert_eq!(
        state.seen_auth.lock().expect("lock").len(),
        sent,
        "invalid input never reaches the node"
    );
}

#[tokio::test]
async fn site_status_and_logs_validate_before_sending() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let status = c.site_status("shop").await.expect("status");
    assert_eq!(status["phase"], "idle");
    let q = LogsQuery {
        source: "manager".into(),
        slot: Some("blue".into()),
        tail: Some(50),
        since: None,
    };
    let logs = c.site_logs("shop", &q).await.expect("logs");
    let seen = logs["query"].as_str().expect("query");
    assert!(seen.contains("source=manager") && seen.contains("tail=50"));
    let before = state.seen_auth.lock().expect("lock").len();
    assert!(c.site_status("../x").await.is_err());
    let bad = LogsQuery {
        source: "other".into(),
        ..LogsQuery::default()
    };
    assert!(c.site_logs("shop", &bad).await.is_err());
    assert!(
        c.build_env_patch("shop", &EnvPatch::default())
            .await
            .is_err()
    );
    assert_eq!(state.seen_auth.lock().expect("lock").len(), before);
}

#[tokio::test]
async fn env_patches_are_refused_by_the_kind_they_are_sent_to() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let before = state.seen_auth.lock().expect("lock").len();
    let mut runtime_only = EnvPatch::default();
    runtime_only.set.insert("NODE_ENV".into(), "x".into());
    assert!(c.runtime_env_patch("shop", &runtime_only).await.is_err());
    let mut build_only = EnvPatch::default();
    build_only.set.insert("SHELL".into(), "x".into());
    assert!(c.build_env_patch("shop", &build_only).await.is_err());
    assert_eq!(state.seen_auth.lock().expect("lock").len(), before);
}

#[tokio::test]
async fn firewall_bulk_is_validated_before_any_request() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let empty = c.firewall_bulk(&FirewallBulk::default()).await;
    assert!(matches!(empty, Err(ClientError::Config(_))));
    let twice = FirewallBulk::new(vec![redirect_rule("a"), redirect_rule("a")], vec![]);
    assert!(matches!(
        c.firewall_bulk(&twice).await,
        Err(ClientError::Config(_))
    ));
    let overlap = FirewallBulk::new(vec![redirect_rule("a")], vec!["a".to_string()]);
    assert!(matches!(
        c.firewall_bulk(&overlap).await,
        Err(ClientError::Config(_))
    ));
    let traversal = FirewallBulk::new(vec![], vec!["../x".to_string()]);
    assert!(matches!(
        c.firewall_bulk(&traversal).await,
        Err(ClientError::Config(_))
    ));
    assert!(state.seen_auth.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn zone_secret_calls_validate_the_site_id_before_any_request() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    for bad in ["", "../x", "A", "a/b", "a b", "-a"] {
        let status = c.zone_secret(bad).await;
        assert!(matches!(status, Err(ClientError::Config(_))), "{bad:?}");
        let rotate = c.rotate_zone_secret(bad).await;
        assert!(matches!(rotate, Err(ClientError::Config(_))), "{bad:?}");
    }
    assert!(state.seen_auth.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn archive_errors_keep_the_node_status() {
    let url = spawn(fake("cite_good", 0)).await;
    let c = client("n1", &url, "cite_good");
    let busy = c
        .analytics_cut(&CutRequest::before_days(99))
        .await
        .expect_err("conflict");
    assert_eq!(busy.status_code(), Some(409));
    let dir = tempfile::tempdir().expect("dir");
    let dest = dir.path().join("out.db");
    let missing = c
        .analytics_archive_download_to("missing.db", &dest, 1 << 20)
        .await
        .expect_err("missing");
    assert_eq!(missing.status_code(), Some(404));
    assert_eq!(std::fs::read_dir(dir.path()).expect("ls").count(), 0);
}

#[tokio::test]
async fn archive_downloads_save_atomically_with_a_safe_suggested_name() {
    let url = spawn(fake("cite_good", 0)).await;
    let c = client("n1", &url, "cite_good");
    let dir = tempfile::tempdir().expect("dir");
    let dest = dir.path().join("out.ndjson.gz");
    let report = c
        .analytics_archive_download_to("requests-2026-11-05.ndjson.gz", &dest, 1 << 20)
        .await
        .expect("download");
    assert_eq!(std::fs::read(&dest).expect("file"), [0x1f, 0x8b, 8, 0]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dest).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(report.bytes, 4);
    assert_eq!(
        report.suggested_name.as_deref(),
        Some("requests-2026-11-05.ndjson.gz")
    );
    let evil = c
        .analytics_archive_download_to("evil.exe", &dest, 1 << 20)
        .await
        .expect("download");
    assert_eq!(evil.suggested_name.as_deref(), Some("evil_exe.ndjson.gz"));
    let small = dir.path().join("small.gz");
    let over = c
        .analytics_archive_download_to("requests-2026-11-05.ndjson.gz", &small, 2)
        .await
        .expect_err("over the cap");
    assert!(matches!(over, ClientError::Decode(_)));
    assert!(!small.exists());
    assert_eq!(std::fs::read_dir(dir.path()).expect("ls").count(), 1);
}

#[tokio::test]
async fn forward_returns_node_statuses_and_bodies_without_erroring() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "cite_good");
    let wait = Duration::from_secs(5);
    let missing = c
        .forward(reqwest::Method::GET, "sites/nope", None, Vec::new(), wait)
        .await
        .expect("forwarded");
    assert_eq!(missing.status, 404);
    assert_eq!(missing.content_type.as_deref(), Some("application/json"));
    assert!(String::from_utf8_lossy(&missing.body).contains("site not found"));
    let ok = c
        .forward(
            reqwest::Method::GET,
            "analytics/summary",
            Some("window=1h"),
            Vec::new(),
            wait,
        )
        .await
        .expect("forwarded");
    assert_eq!(ok.status, 200);
    let query = state.last_query.lock().expect("lock").clone();
    assert_eq!(query.as_deref(), Some("window=1h"));
}

#[tokio::test]
async fn text_routes_return_plain_strings() {
    let url = spawn(fake("cite_good", 0)).await;
    let text = client("n1", &url, "")
        .haproxy_config()
        .await
        .expect("config");
    assert!(text.starts_with("global"));
}

#[tokio::test]
async fn fan_out_respects_the_concurrency_cap() {
    let state = fake("cite_good", 80);
    let url = spawn(state.clone()).await;
    // Six slow requests against a cap of two must overlap in pairs and never more.
    let clients: Vec<NodeClient> = (0..6)
        .map(|i| client(&format!("n{i}"), &url, "cite_good"))
        .collect();
    let results = fan_out(&clients, 2, None, |c| async move { c.node_info().await }).await;
    assert_eq!(results.len(), 6);
    assert!(results.iter().all(|(_, r)| r.is_ok()));
    assert_eq!(state.max_in_flight.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn fan_out_keeps_order_and_reports_partial_failure() {
    let url = spawn(fake("cite_good", 0)).await;
    let clients = vec![
        client("a", &url, "cite_good"),
        client("b", &url, "cite_wrong"),
        client("c", &url, "cite_good"),
    ];
    let results = fan_out(&clients, 8, None, |c| async move { c.node_info().await }).await;
    let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["a", "b", "c"]);
    assert!(results[0].1.is_ok());
    assert_eq!(
        results[1].1.as_ref().expect_err("bad token").status_code(),
        Some(401)
    );
    assert!(results[2].1.is_ok());
}

#[tokio::test]
async fn fan_out_enforces_the_per_node_timeout() {
    let url = spawn(fake("cite_good", 400)).await;
    let clients = vec![client("slow", &url, "cite_good")];
    let results = fan_out(
        &clients,
        1,
        Some(Duration::from_millis(50)),
        |c| async move { c.node_info().await },
    )
    .await;
    assert!(results[0].1.as_ref().expect_err("timeout").is_timeout());
}

#[tokio::test]
async fn each_mode_creates_per_node_and_reports_conflicts() {
    let fresh = fake("cite_good", 0);
    let taken = fake("cite_good", 0);
    taken
        .sites
        .lock()
        .expect("lock")
        .push(serde_json::to_value(site("shop")).expect("json"));
    let clients = vec![
        client("fresh", &spawn(fresh.clone()).await, "cite_good"),
        client("taken", &spawn(taken.clone()).await, "cite_good"),
    ];
    let outcomes = apply_site_to_nodes(&clients, &site("shop"), ReplicationMode::Each).await;
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes[0].ok);
    assert_eq!(outcomes[0].action.as_deref(), Some("created"));
    assert!(!outcomes[1].ok);
    assert!(outcomes[1].error.as_deref().unwrap_or("").contains("409"));
    assert_eq!(fresh.sites.lock().expect("lock").len(), 1);
    assert_eq!(taken.sites.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn replicate_mode_creates_or_updates_to_an_identical_site() {
    let fresh = fake("cite_good", 0);
    let stale = fake("cite_good", 0);
    let mut old = site("shop");
    old.name = "Old name".into();
    stale
        .sites
        .lock()
        .expect("lock")
        .push(serde_json::to_value(&old).expect("json"));
    let clients = vec![
        client("fresh", &spawn(fresh.clone()).await, "cite_good"),
        client("stale", &spawn(stale.clone()).await, "cite_good"),
    ];
    let outcomes = apply_site_to_nodes(&clients, &site("shop"), ReplicationMode::Replicate).await;
    assert_eq!(outcomes[0].action.as_deref(), Some("created"));
    assert_eq!(outcomes[1].action.as_deref(), Some("updated"));
    let want = serde_json::to_value(site("shop")).expect("json");
    assert_eq!(fresh.sites.lock().expect("lock")[0], want);
    assert_eq!(stale.sites.lock().expect("lock")[0], want);
}

#[tokio::test]
async fn replicate_mode_reports_a_failing_node_without_stopping_the_rest() {
    let good = fake("cite_good", 0);
    let bad = fake("cite_other", 0);
    let clients = vec![
        client("bad", &spawn(bad.clone()).await, "cite_good"),
        client("good", &spawn(good.clone()).await, "cite_good"),
    ];
    let outcomes = apply_site_to_nodes(&clients, &site("shop"), ReplicationMode::Replicate).await;
    assert!(!outcomes[0].ok);
    assert!(outcomes[1].ok);
    assert_eq!(good.sites.lock().expect("lock").len(), 1);
    assert!(bad.sites.lock().expect("lock").is_empty());
}

#[test]
fn each_mode_uses_the_per_node_targets_and_replicate_ignores_them() {
    let override_targets = NodeTargets {
        blue: Some(vec![Target {
            addr: "192.168.1.9:9000".into(),
            weight: 50,
        }]),
        green: None,
    };
    let mut seeded = site("shop");
    seeded.history = vec![];
    let each = ReplicationPlan::new(seeded.clone(), ReplicationMode::Each)
        .with_node_targets("edge-a", override_targets.clone());
    assert_eq!(
        each.site_for("edge-a").blue.targets[0].addr,
        "192.168.1.9:9000"
    );
    assert_eq!(each.site_for("edge-a").green, seeded.green);
    assert_eq!(each.site_for("edge-b"), seeded);
    let replicate = ReplicationPlan::new(seeded.clone(), ReplicationMode::Replicate)
        .with_node_targets("edge-a", override_targets);
    assert_eq!(replicate.site_for("edge-a"), seeded);
}

#[tokio::test]
async fn create_site_sends_the_github_token_beside_the_site() {
    let fake = fake("cite_good", 0);
    let c = client("n1", &spawn(fake.clone()).await, "cite_good");
    let mut with_source = site("shop");
    with_source.source = Some(Source {
        repo: "acme/shop".into(),
        branch: None,
        runtime: None,
        node_major: None,
        poll_interval: None,
        secret: None,
        ..Default::default()
    });
    c.create_site(&with_source, Some("ghp_example"))
        .await
        .expect("create");
    let mut expected = serde_json::to_value(&with_source).expect("json");
    expected["github_token"] = json!("ghp_example");
    let stored = fake.created_bodies.lock().expect("lock")[0].clone();
    assert_eq!(stored, expected);
    assert!(stored["source"]["secret"].is_null());
}

#[tokio::test]
async fn plans_pass_the_token_to_create_and_hide_it_from_debug() {
    let fake = fake("cite_good", 0);
    let clients = vec![client("n1", &spawn(fake.clone()).await, "cite_good")];
    let plan = ReplicationPlan::new(site("shop"), ReplicationMode::Each)
        .with_github_token(Some("ghp_example".into()));
    assert!(!format!("{plan:?}").contains("ghp_example"));
    let outcomes = cite_client::apply_plan(&clients, &plan).await;
    assert!(outcomes[0].ok);
    assert_eq!(
        fake.created_bodies.lock().expect("lock")[0]["github_token"],
        "ghp_example"
    );
    clients[0]
        .create_site(&site("blog"), None)
        .await
        .expect("create");
    assert!(
        fake.created_bodies.lock().expect("lock")[1]
            .get("github_token")
            .is_none()
    );
}
