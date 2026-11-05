use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cite_client::{
    ClientError, NodeClient, NodeConfig, NodeTargets, ReplicationMode, ReplicationPlan,
    apply_site_to_nodes, fan_out,
};
use cite_edge::analytics::Summary;
use cite_edge::model::{HealthCheck, Maintenance, Site, SiteKind, Slot, Target, Upstream};
use serde_json::{Value, json};

struct Fake {
    token: String,
    sites: Mutex<Vec<Value>>,
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
        "firewall_rules": 0
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
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check(&s, &headers) {
        return resp;
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
        path_regex: None,
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
    let seen = state.seen_auth.lock().expect("lock");
    assert_eq!(seen.as_slice(), [Some("Bearer cite_good".to_string())]);
}

#[tokio::test]
async fn login_sends_no_bearer_and_returns_the_token() {
    let state = fake("cite_good", 0);
    let url = spawn(state.clone()).await;
    let c = client("n1", &url, "");
    let ok = c.login("admin", "pw", "123456").await.expect("login");
    assert_eq!(ok.token, "cite_login_token");
    assert!(!format!("{ok:?}").contains("cite_login_token"));
    let err = c
        .login("admin", "pw", "000000")
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
    let created = c.create_site(&site("shop")).await.expect("create");
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
