use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use cite_client::{ConfigFile, DashboardConfig, MemoryTokenStore, NodeConfig, TokenStore};
use cite_dashboard::{AppState, Settings, router};
use cite_edge::analytics::Summary;
use cite_edge::auth::{Credentials, hash_password};
use cite_edge::model::{HealthCheck, Maintenance, Site, SiteKind, Slot, Source, Target, Upstream};
use cite_edge::totp;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD: &str = "correct horse battery";
const NODE_TOKEN: &str = "cite_node_token_value";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// Each step is 30 seconds; the server accepts the previous, current and next step.
fn code(steps_ahead: u64) -> String {
    totp::code_at(SECRET, now() + 30 * steps_ahead).expect("code")
}

// Found by exclusion from the accepted window, so the test can never hit a valid code by chance.
fn wrong_code() -> String {
    let valid: Vec<String> = (0..5)
        .filter_map(|i| totp::code_at(SECRET, (now() + 30 * i).saturating_sub(60)))
        .collect();
    (0..10)
        .map(|n| format!("00000{n}"))
        .find(|c| !valid.contains(c))
        .expect("an unused code")
}

fn password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password(PASSWORD).expect("hash"))
}

fn admin() -> Credentials {
    Credentials {
        username: "admin".to_string(),
        password_hash: password_hash().to_string(),
        totp_secret: SECRET.to_string(),
        totp_last_step: 0,
    }
}

struct Fake {
    token: String,
    sites: Mutex<Vec<Value>>,
    created_bodies: Mutex<Vec<Value>>,
    node_hits: AtomicUsize,
}

type Shared = Arc<Fake>;

fn new_fake(token: &str) -> Shared {
    Arc::new(Fake {
        token: token.to_string(),
        sites: Mutex::new(Vec::new()),
        created_bodies: Mutex::new(Vec::new()),
        node_hits: AtomicUsize::new(0),
    })
}

fn err(code: StatusCode, message: &str) -> Response {
    (code, Json(json!({ "error": message }))).into_response()
}

fn authorized(f: &Fake, headers: &HeaderMap) -> bool {
    let want = format!("Bearer {}", f.token);
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(want.as_str())
}

async fn node_info(State(f): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    f.node_hits.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "name": "fake",
        "version": "1.2.3",
        "uptime_secs": 7,
        "haproxy": { "running": true },
        "sites": 0,
        "firewall_rules": 0
    }))
    .into_response()
}

async fn summary(State(f): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    Json(Summary::default()).into_response()
}

async fn echo(
    State(f): State<Shared>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let seen: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| {
            let value = v.to_str().unwrap_or("").to_string();
            (k.as_str().to_string(), Value::String(value))
        })
        .collect();
    Json(json!({
        "method": method.as_str(),
        "headers": seen,
        "query": query,
        "body": String::from_utf8_lossy(&body),
    }))
    .into_response()
}

async fn big(State(f): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    // An oversized answer that the proxy has to refuse instead of buffering.
    vec![b'a'; 9 * 1024 * 1024].into_response()
}

async fn list_sites(State(f): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    Json(Value::Array(f.sites.lock().expect("lock").clone())).into_response()
}

async fn create_site(
    State(f): State<Shared>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    f.created_bodies.lock().expect("lock").push(body.clone());
    // Recorded as received, then stripped so the stored and echoed site never carries the token.
    if let Some(obj) = body.as_object_mut() {
        obj.remove("github_token");
    }
    let mut sites = f.sites.lock().expect("lock");
    if sites.iter().any(|s| s["id"] == body["id"]) {
        return err(StatusCode::CONFLICT, "site already exists");
    }
    sites.push(body.clone());
    Json(body).into_response()
}

async fn get_site(State(f): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let found = f
        .sites
        .lock()
        .expect("lock")
        .iter()
        .find(|s| s["id"] == id)
        .cloned();
    match found {
        Some(site) => Json(site).into_response(),
        None => err(StatusCode::NOT_FOUND, "site not found"),
    }
}

async fn put_site(
    State(f): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&f, &headers) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let mut sites = f.sites.lock().expect("lock");
    match sites.iter_mut().find(|s| s["id"] == id) {
        Some(slot) => {
            *slot = body.clone();
            Json(body).into_response()
        }
        None => err(StatusCode::NOT_FOUND, "site not found"),
    }
}

async fn spawn_fake(fake: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/node", get(node_info))
        .route("/api/v1/analytics/summary", get(summary))
        .route("/api/v1/settings", any(echo))
        .route("/api/v1/haproxy/stats", get(big))
        .route("/api/v1/sites", get(list_sites).post(create_site))
        .route("/api/v1/sites/{id}", get(get_site).put(put_site))
        .with_state(fake);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

struct Harness {
    app: Router,
    state: Arc<AppState>,
    tokens: Arc<MemoryTokenStore>,
    config_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn harness_with(config: DashboardConfig, tokens: &[(&str, &str)], env: &[(&str, &str)]) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("dashboard.json");
    let mut vars: HashMap<String, String> = HashMap::new();
    vars.insert(
        "CITE_DASHBOARD_CONFIG".to_string(),
        config_path.display().to_string(),
    );
    for (k, v) in env {
        vars.insert(k.to_string(), v.to_string());
    }
    let settings = Settings::from_env_map(&vars).expect("settings");
    let store = Arc::new(MemoryTokenStore::new());
    for (key, token) in tokens {
        store.set(key, token).expect("seed token");
    }
    let state = AppState::new(settings, config, store.clone() as Arc<dyn TokenStore>);
    Harness {
        app: router(state.clone()),
        state,
        tokens: store,
        config_path,
        _dir: dir,
    }
}

fn onboarded() -> DashboardConfig {
    DashboardConfig {
        admin: Some(admin()),
        ..DashboardConfig::default()
    }
}

fn node_entry(name: &str, url: &str) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        url: url.to_string(),
        ca_pem: None,
        token_ref: name.to_string(),
        insecure_http: false,
    }
}

fn harness() -> Harness {
    harness_with(onboarded(), &[], &[])
}

fn harness_with_nodes(nodes: &[(&str, &str, &str)]) -> Harness {
    let mut config = onboarded();
    let mut tokens = Vec::new();
    for (name, url, token) in nodes {
        config.nodes.push(node_entry(name, url));
        tokens.push((*name, *token));
    }
    harness_with(config, &tokens, &[])
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("json body")
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, Vec<u8>)>,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let payload = match body {
        Some((content_type, bytes)) => {
            builder = builder.header(header::CONTENT_TYPE, content_type);
            Body::from(bytes)
        }
        None => Body::empty(),
    };
    // oneshot has no socket, so a fixed peer from TEST-NET-3 is attached for the allowlist and login limiter.
    let mut req = builder.body(payload).expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 5555))));
    let resp = app.clone().oneshot(req).await.expect("response");
    let (parts, body) = resp.into_parts();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: to_bytes(body, usize::MAX).await.expect("body"),
    }
}

async fn get_path(app: &Router, uri: &str, headers: &[(&str, &str)]) -> Reply {
    call(app, Method::GET, uri, headers, None).await
}

async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> Reply {
    let bytes = serde_json::to_vec(&body).expect("encode");
    call(app, method, uri, headers, Some(("application/json", bytes))).await
}

struct Session {
    cookie: String,
    csrf: String,
}

impl Session {
    fn headers(&self) -> [(&str, &str); 2] {
        [
            ("cookie", self.cookie.as_str()),
            ("x-cite-csrf", self.csrf.as_str()),
        ]
    }
}

async fn login_with(h: &Harness, steps_ahead: u64) -> Session {
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(steps_ahead) });
    let reply = send_json(&h.app, Method::POST, "/api/v1/session", &[], body).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let set_cookie = reply.header("set-cookie");
    let cookie = set_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();
    Session {
        cookie,
        csrf: reply.json()["csrf"].as_str().expect("csrf").to_string(),
    }
}

async fn login(h: &Harness) -> Session {
    login_with(h, 0).await
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

fn site_json(id: &str) -> Value {
    serde_json::to_value(site(id)).expect("site json")
}

#[tokio::test]
async fn setup_status_tracks_whether_an_admin_exists() {
    let fresh = harness_with(DashboardConfig::default(), &[], &[]);
    let reply = get_path(&fresh.app, "/api/v1/setup", &[]).await;
    assert_eq!(
        reply.json(),
        json!({ "needs_onboarding": true, "needs_token": true })
    );
    let done = harness();
    let reply = get_path(&done.app, "/api/v1/setup", &[]).await;
    assert_eq!(reply.json()["needs_onboarding"], json!(false));
}

#[tokio::test]
async fn onboarding_happy_path_ends_with_a_working_login() {
    let h = harness_with(DashboardConfig::default(), &[], &[]);
    let setup_token = h.state.issue_setup_token().expect("setup token");
    assert_eq!(setup_token.len(), 32);
    assert!(setup_token.bytes().all(|b| b.is_ascii_hexdigit()));
    let begin = send_json(
        &h.app,
        Method::POST,
        "/api/v1/setup",
        &[],
        json!({ "setup_token": setup_token, "username": "operator", "password": "a long enough passphrase" }),
    )
    .await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.text());
    let started = begin.json();
    let secret = started["totp_secret"].as_str().expect("secret").to_string();
    assert!(
        started["totp_uri"]
            .as_str()
            .expect("uri")
            .starts_with("otpauth://totp/Cite:operator")
    );
    assert!(started["qr_svg"].as_str().expect("svg").starts_with("<svg"));
    assert!(h.state.needs_onboarding().await);

    let live = totp::code_at(&secret, now()).expect("code");
    let confirm = send_json(
        &h.app,
        Method::POST,
        "/api/v1/setup/confirm",
        &[],
        json!({ "code": live }),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text());
    assert!(!h.state.needs_onboarding().await);
    let saved = ConfigFile::load(&h.config_path).expect("config on disk");
    assert_eq!(saved.admin.expect("admin saved").username, "operator");
    assert!(!h.state.setup_token_matches(&setup_token));

    // The confirmation used this step, so the first login needs the next one.
    let next = totp::code_at(&secret, now() + 30).expect("code");
    let body =
        json!({ "username": "operator", "password": "a long enough passphrase", "totp": next });
    let reply = send_json(&h.app, Method::POST, "/api/v1/session", &[], body).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
}

#[tokio::test]
async fn setup_validates_username_and_password() {
    let h = harness_with(DashboardConfig::default(), &[], &[]);
    let t = h.state.issue_setup_token().expect("setup token");
    for body in [
        json!({ "setup_token": t, "username": "Bad Name", "password": "a long enough passphrase" }),
        json!({ "setup_token": t, "username": "ab", "password": "a long enough passphrase" }),
        json!({ "setup_token": t, "username": "operator", "password": "short" }),
        json!({ "setup_token": t, "username": "operator" }),
    ] {
        let reply = send_json(&h.app, Method::POST, "/api/v1/setup", &[], body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
    }
    assert!(h.state.needs_onboarding().await);
}

#[tokio::test]
async fn setup_confirm_needs_a_started_setup_and_a_valid_code() {
    let h = harness_with(DashboardConfig::default(), &[], &[]);
    let t = h.state.issue_setup_token().expect("setup token");
    let url = "/api/v1/setup/confirm";
    let early = send_json(&h.app, Method::POST, url, &[], json!({ "code": "123456" })).await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST);
    let begin = send_json(
        &h.app,
        Method::POST,
        "/api/v1/setup",
        &[],
        json!({ "setup_token": t, "username": "operator", "password": "a long enough passphrase" }),
    )
    .await;
    assert_eq!(begin.status, StatusCode::OK);
    let wrong = send_json(
        &h.app,
        Method::POST,
        url,
        &[],
        json!({ "code": wrong_code() }),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert!(h.state.needs_onboarding().await);
    assert!(!h.config_path.exists());
}

#[tokio::test]
async fn setup_endpoints_are_404_once_onboarded() {
    let h = harness();
    let begin = send_json(
        &h.app,
        Method::POST,
        "/api/v1/setup",
        &[],
        json!({ "setup_token": "x", "username": "intruder", "password": "a long enough passphrase" }),
    )
    .await;
    assert_eq!(begin.status, StatusCode::NOT_FOUND);
    let confirm = send_json(
        &h.app,
        Method::POST,
        "/api/v1/setup/confirm",
        &[],
        json!({ "code": "123456" }),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::NOT_FOUND);
    assert_eq!(
        h.state
            .config_snapshot()
            .await
            .admin
            .expect("admin")
            .username,
        "admin"
    );
}

#[tokio::test]
async fn login_sets_a_strict_http_only_cookie_and_returns_a_csrf_token() {
    let h = harness();
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(0) });
    let reply = send_json(&h.app, Method::POST, "/api/v1/session", &[], body).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let cookie = reply.header("set-cookie");
    assert!(cookie.starts_with("cite_session=cite_"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/"));
    assert!(!cookie.contains("Secure"));
    let csrf = reply.json()["csrf"].as_str().expect("csrf").to_string();

    let pair = cookie.split(';').next().expect("pair").to_string();
    let me = get_path(&h.app, "/api/v1/session", &[("cookie", &pair)]).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["username"], "admin");
    assert_eq!(me.json()["csrf"], csrf.as_str());
}

#[tokio::test]
async fn transport_settings_control_secure_cookies_and_hsts() {
    let tls_env = [
        ("CITE_DASHBOARD_TLS_CERT", "/unused/cert.pem"),
        ("CITE_DASHBOARD_TLS_KEY", "/unused/key.pem"),
    ];
    let secure = harness_with(onboarded(), &[], &tls_env);
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(0) });
    let reply = send_json(&secure.app, Method::POST, "/api/v1/session", &[], body).await;
    assert!(reply.header("set-cookie").ends_with("; Secure"));
    assert!(
        reply
            .header("strict-transport-security")
            .starts_with("max-age=")
    );

    let plain = get_path(&harness().app, "/healthz", &[]).await;
    assert!(plain.headers.get("strict-transport-security").is_none());

    let forced = harness_with(
        onboarded(),
        &[],
        &[("CITE_DASHBOARD_COOKIE_SECURE", "true")],
    );
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(0) });
    let reply = send_json(&forced.app, Method::POST, "/api/v1/session", &[], body).await;
    assert!(reply.header("set-cookie").ends_with("; Secure"));
}

// Wrong password, unknown user and wrong code answer identically, so an attacker cannot enumerate usernames or learn which factor failed.
#[tokio::test]
async fn failed_logins_look_identical_and_lock_out_after_five() {
    let h = harness();
    let url = "/api/v1/session";
    let attempts = [
        json!({ "username": "admin", "password": "wrong password!!", "totp": code(0) }),
        json!({ "username": "nobody", "password": PASSWORD, "totp": code(0) }),
        json!({ "username": "admin", "password": PASSWORD, "totp": wrong_code() }),
    ];
    let mut bodies = Vec::new();
    for body in attempts {
        let reply = send_json(&h.app, Method::POST, url, &[], body).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        bodies.push(reply.text());
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    for _ in 0..2 {
        let body = json!({ "username": "admin", "password": "wrong password!!", "totp": code(0) });
        let reply = send_json(&h.app, Method::POST, url, &[], body).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let good = json!({ "username": "admin", "password": PASSWORD, "totp": code(0) });
    let locked = send_json(&h.app, Method::POST, url, &[], good).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        locked
            .header("retry-after")
            .parse::<u64>()
            .expect("seconds")
            >= 1
    );
}

#[tokio::test]
async fn login_before_onboarding_is_a_conflict() {
    let h = harness_with(DashboardConfig::default(), &[], &[]);
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(0) });
    let reply = send_json(&h.app, Method::POST, "/api/v1/session", &[], body).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_totp_code_cannot_be_replayed() {
    let h = harness();
    // one code string for both requests, so a step boundary between them cannot hide a replay
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(0) });
    let first = send_json(&h.app, Method::POST, "/api/v1/session", &[], body.clone()).await;
    assert_eq!(first.status, StatusCode::OK);
    let replay = send_json(&h.app, Method::POST, "/api/v1/session", &[], body).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
}

// A made-up session token must be refused exactly like a missing cookie.
#[tokio::test]
async fn api_routes_need_a_live_session() {
    let h = harness();
    for uri in ["/api/v1/nodes", "/api/v1/session", "/api/v1/nodes/summary"] {
        let reply = get_path(&h.app, uri, &[]).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    let forged = get_path(
        &h.app,
        "/api/v1/nodes",
        &[("cookie", "cite_session=cite_forged")],
    )
    .await;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_the_session_and_clears_the_cookie() {
    let h = harness();
    let s = login(&h).await;
    let out = call(
        &h.app,
        Method::DELETE,
        "/api/v1/session",
        &s.headers(),
        None,
    )
    .await;
    assert_eq!(out.status, StatusCode::OK);
    assert!(out.header("set-cookie").contains("Max-Age=0"));
    let after = get_path(&h.app, "/api/v1/session", &[("cookie", &s.cookie)]).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

// A cross-site page can ride the session cookie but cannot read the CSRF token, so writes without it must fail.
#[tokio::test]
async fn state_changing_requests_need_the_session_csrf_token() {
    let h = harness();
    let s = login(&h).await;
    let body = json!({ "name": "edge-1", "url": "http://127.0.0.1:1", "token": "t" });
    let cookie_only = [("cookie", s.cookie.as_str())];
    let missing = send_json(
        &h.app,
        Method::POST,
        "/api/v1/nodes",
        &cookie_only,
        body.clone(),
    )
    .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    let wrong_headers = [("cookie", s.cookie.as_str()), ("x-cite-csrf", "nope")];
    let wrong = send_json(&h.app, Method::POST, "/api/v1/nodes", &wrong_headers, body).await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    let delete = call(
        &h.app,
        Method::DELETE,
        "/api/v1/nodes/x",
        &cookie_only,
        None,
    )
    .await;
    assert_eq!(delete.status, StatusCode::FORBIDDEN);
    let read = get_path(&h.app, "/api/v1/nodes", &cookie_only).await;
    assert_eq!(read.status, StatusCode::OK);
}

// A CSRF token taken from one session must not unlock writes on another.
#[tokio::test]
async fn csrf_tokens_do_not_transfer_between_sessions() {
    let h = harness();
    let a = login_with(&h, 0).await;
    let b = login_with(&h, 1).await;
    assert_ne!(a.csrf, b.csrf);
    let crossed = [
        ("cookie", b.cookie.as_str()),
        ("x-cite-csrf", a.csrf.as_str()),
    ];
    let reply = call(&h.app, Method::DELETE, "/api/v1/nodes/x", &crossed, None).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let own = call(
        &h.app,
        Method::DELETE,
        "/api/v1/nodes/x",
        &b.headers(),
        None,
    )
    .await;
    assert_eq!(own.status, StatusCode::NOT_FOUND);
}

// Form and multipart bodies are what a cross-site HTML form can send without a preflight, so they are refused.
#[tokio::test]
async fn request_bodies_must_be_json() {
    let h = harness();
    let s = login(&h).await;
    for content_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    ] {
        let body = Some((content_type, b"name=edge".to_vec()));
        let reply = call(&h.app, Method::POST, "/api/v1/nodes", &s.headers(), body).await;
        assert_eq!(
            reply.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type}"
        );
    }
}

// An Origin that differs from the Host is refused even with a valid session cookie, and login follows the same rule.
#[tokio::test]
async fn cross_origin_requests_are_refused() {
    let h = harness();
    let s = login(&h).await;
    let evil = [
        ("cookie", s.cookie.as_str()),
        ("origin", "https://evil.example"),
        ("host", "dashboard.local"),
    ];
    let reply = get_path(&h.app, "/api/v1/session", &evil).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(1) });
    let login_attempt = send_json(&h.app, Method::POST, "/api/v1/session", &evil[1..], body).await;
    assert_eq!(login_attempt.status, StatusCode::FORBIDDEN);
    let same = [
        ("cookie", s.cookie.as_str()),
        ("origin", "http://dashboard.local:8088"),
        ("host", "dashboard.local:8088"),
    ];
    let ok = get_path(&h.app, "/api/v1/session", &same).await;
    assert_eq!(ok.status, StatusCode::OK);
}

// Errors and 404s carry the same policy as pages, so no response is left without the CSP.
#[tokio::test]
async fn security_headers_are_on_every_response() {
    let h = harness();
    let replies = [
        get_path(&h.app, "/healthz", &[]).await,
        get_path(&h.app, "/api/v1/setup", &[]).await,
        get_path(&h.app, "/api/v1/nodes", &[]).await,
        get_path(&h.app, "/", &[]).await,
        get_path(&h.app, "/missing.js", &[]).await,
    ];
    for reply in &replies {
        let csp = reply.header("content-security-policy");
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-src 'self'",
        ] {
            assert!(csp.contains(directive), "{directive} missing from {csp}");
        }
        assert_eq!(reply.header("x-content-type-options"), "nosniff");
        assert_eq!(reply.header("referrer-policy"), "no-referrer");
        assert_eq!(reply.header("cross-origin-opener-policy"), "same-origin");
        assert!(reply.header("permissions-policy").contains("camera=()"));
    }
    assert_eq!(replies[1].header("cache-control"), "no-store");
}

#[tokio::test]
async fn index_is_served_with_revalidation() {
    let h = harness();
    let first = get_path(&h.app, "/", &[]).await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.header("content-type").starts_with("text/html"));
    assert_eq!(first.header("cache-control"), "no-cache");
    assert!(first.text().to_ascii_lowercase().contains("<html"));
    let etag = first.header("etag");
    assert!(etag.starts_with('"'));
    let again = get_path(&h.app, "/", &[("if-none-match", &etag)]).await;
    assert_eq!(again.status, StatusCode::NOT_MODIFIED);
    assert!(again.body.is_empty());
}

#[tokio::test]
async fn assets_get_types_and_a_one_hour_cache() {
    let h = harness();
    let css = get_path(&h.app, "/app.css", &[]).await;
    assert_eq!(css.status, StatusCode::OK);
    assert!(css.header("content-type").starts_with("text/css"));
    assert_eq!(css.header("cache-control"), "public, max-age=3600");
    let js = get_path(&h.app, "/js/api.js", &[]).await;
    assert_eq!(js.status, StatusCode::OK);
    assert!(js.header("content-type").starts_with("text/javascript"));
}

#[tokio::test]
async fn unknown_paths_fall_back_to_the_spa_but_not_assets_or_api() {
    let h = harness();
    let index = get_path(&h.app, "/", &[]).await;
    let route = get_path(&h.app, "/nodes/edge-1/sites", &[]).await;
    assert_eq!(route.status, StatusCode::OK);
    assert_eq!(route.body, index.body);
    let missing_asset = get_path(&h.app, "/js/does-not-exist.js", &[]).await;
    assert_eq!(missing_asset.status, StatusCode::NOT_FOUND);
    let missing_api = get_path(&h.app, "/api/v1/does-not-exist", &[]).await;
    assert_eq!(missing_api.status, StatusCode::NOT_FOUND);
    assert!(
        missing_api
            .header("content-type")
            .starts_with("application/json")
    );
    let post = call(&h.app, Method::POST, "/", &[], None).await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
}

// /healthz stays open to any peer so container healthchecks keep working behind the allowlist.
#[tokio::test]
async fn the_ip_allowlist_blocks_other_peers_but_not_the_healthcheck() {
    let h = harness_with(onboarded(), &[], &[("CITE_DASHBOARD_ALLOW", "10.0.0.0/8")]);
    assert_eq!(
        get_path(&h.app, "/", &[]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_path(&h.app, "/api/v1/setup", &[]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_path(&h.app, "/healthz", &[]).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn adding_a_node_probes_it_before_saving() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake.clone()).await;
    let h = harness();
    let s = login(&h).await;
    let bad = json!({ "name": "edge-1", "url": url, "token": "cite_wrong_token" });
    let rejected = send_json(&h.app, Method::POST, "/api/v1/nodes", &s.headers(), bad).await;
    assert_eq!(
        rejected.status,
        StatusCode::BAD_REQUEST,
        "{}",
        rejected.text()
    );
    assert_eq!(h.tokens.get("edge-1").expect("get"), None);
    assert!(h.state.config_snapshot().await.nodes.is_empty());
    assert!(
        ConfigFile::load(&h.config_path)
            .expect("config")
            .nodes
            .is_empty()
    );

    let good = json!({ "name": "edge-1", "url": url, "token": NODE_TOKEN });
    let added = send_json(&h.app, Method::POST, "/api/v1/nodes", &s.headers(), good).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.text());
    assert_eq!(added.json()["version"], "1.2.3");
    assert_eq!(
        h.tokens.get("edge-1").expect("get").as_deref(),
        Some(NODE_TOKEN)
    );
    let on_disk = ConfigFile::load(&h.config_path).expect("config saved");
    assert_eq!(on_disk.nodes.len(), 1);

    let list = get_path(&h.app, "/api/v1/nodes", &s.headers()).await;
    let nodes = list.json();
    assert_eq!(nodes[0]["name"], "edge-1");
    assert_eq!(nodes[0]["online"], true);
    assert_eq!(nodes[0]["version"], "1.2.3");

    let removed = call(
        &h.app,
        Method::DELETE,
        "/api/v1/nodes/edge-1",
        &s.headers(),
        None,
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK);
    assert_eq!(h.tokens.get("edge-1").expect("get"), None);
    assert!(
        ConfigFile::load(&h.config_path)
            .expect("config")
            .nodes
            .is_empty()
    );
    let gone = get_path(&h.app, "/api/v1/nodes/edge-1/sites", &s.headers()).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn adding_a_node_rejects_bad_input_duplicates_and_dead_nodes() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let cases = [
        (
            json!({ "name": "Bad Name", "url": url, "token": NODE_TOKEN }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "summary", "url": url, "token": NODE_TOKEN }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "edge-2", "url": "http://example.com:7443", "token": "t" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "edge-2", "url": url, "token": "has space" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "edge-2", "url": url, "token": NODE_TOKEN, "extra": 1 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "edge-1", "url": url, "token": NODE_TOKEN }),
            StatusCode::CONFLICT,
        ),
        (
            json!({ "name": "edge-2", "url": "http://127.0.0.1:1", "token": "t" }),
            StatusCode::BAD_GATEWAY,
        ),
    ];
    for (body, expected) in cases {
        let reply = send_json(
            &h.app,
            Method::POST,
            "/api/v1/nodes",
            &s.headers(),
            body.clone(),
        )
        .await;
        assert_eq!(reply.status, expected, "{body} -> {}", reply.text());
    }
    assert_eq!(h.state.config_snapshot().await.nodes.len(), 1);
}

#[tokio::test]
async fn node_status_probes_are_cached_between_requests() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake.clone()).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    for _ in 0..3 {
        let reply = get_path(&h.app, "/api/v1/nodes", &s.headers()).await;
        assert_eq!(reply.json()[0]["online"], true);
    }
    assert_eq!(fake.node_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn summary_marks_unreachable_nodes_without_failing_the_request() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake).await;
    let h = harness_with_nodes(&[
        ("edge-1", url.as_str(), NODE_TOKEN),
        ("edge-2", "http://127.0.0.1:1", NODE_TOKEN),
    ]);
    let s = login(&h).await;
    let reply = get_path(&h.app, "/api/v1/nodes/summary", &s.headers()).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let rows = reply.json();
    assert_eq!(rows[0]["name"], "edge-1");
    assert_eq!(rows[0]["online"], true);
    assert_eq!(rows[0]["node"]["version"], "1.2.3");
    assert!(rows[0]["summary"].is_object());
    assert_eq!(rows[1]["name"], "edge-2");
    assert_eq!(rows[1]["online"], false);
    assert!(
        rows[1]["error"]
            .as_str()
            .expect("error")
            .contains("unreachable")
    );
}

// The browser's own Authorization header and cookies must never reach a node, which only sees the stored node token.
#[tokio::test]
async fn proxy_forwards_with_the_stored_token_and_nothing_from_the_browser() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let headers = [
        ("cookie", s.cookie.as_str()),
        ("x-cite-csrf", s.csrf.as_str()),
        ("authorization", "Bearer browser-secret"),
    ];
    let reply = get_path(&h.app, "/api/v1/nodes/edge-1/settings?x=1&y=two", &headers).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let seen = reply.json();
    assert_eq!(seen["method"], "GET");
    assert_eq!(seen["query"], "x=1&y=two");
    assert_eq!(
        seen["headers"]["authorization"],
        format!("Bearer {NODE_TOKEN}")
    );
    assert!(seen["headers"].get("cookie").is_none());
    assert!(seen["headers"].get("x-cite-csrf").is_none());
    assert!(!reply.text().contains("browser-secret"));

    let put = send_json(
        &h.app,
        Method::PUT,
        "/api/v1/nodes/edge-1/settings",
        &s.headers(),
        json!({ "max_conn": 5 }),
    )
    .await;
    assert_eq!(put.json()["method"], "PUT");
    assert_eq!(put.json()["body"], "{\"max_conn\":5}");
    assert_eq!(put.json()["headers"]["content-type"], "application/json");
}

// Plain and percent-encoded dot-dot segments model an attempt to reach node endpoints the console does not expose, such as auth.
#[tokio::test]
async fn proxy_only_forwards_allowlisted_prefixes() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    for blocked in [
        "/api/v1/nodes/edge-1/auth/me",
        "/api/v1/nodes/edge-1/auth/login",
        "/api/v1/nodes/edge-1/healthz",
        "/api/v1/nodes/edge-1/sites/../auth/me",
        "/api/v1/nodes/edge-1/sites/%2e%2e/auth/me",
        "/api/v1/nodes/edge-1/sites//x",
        "/api/v1/nodes/ghost/sites",
    ] {
        let reply = get_path(&h.app, blocked, &s.headers()).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{blocked}");
    }
    for allowed in ["sites", "settings", "analytics/summary?window=15m"] {
        let uri = format!("/api/v1/nodes/edge-1/{allowed}");
        let reply = get_path(&h.app, &uri, &s.headers()).await;
        assert_eq!(reply.status, StatusCode::OK, "{allowed}");
    }
    let trace = call(
        &h.app,
        Method::PATCH,
        "/api/v1/nodes/edge-1/sites",
        &s.headers(),
        None,
    )
    .await;
    assert_eq!(trace.status, StatusCode::METHOD_NOT_ALLOWED);
}

// The proxy is a write path to the node, so it enforces CSRF itself and the fake node must see nothing.
#[tokio::test]
async fn proxy_requires_the_csrf_token_for_writes() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake.clone()).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let cookie_only = [("cookie", s.cookie.as_str())];
    let body = json!({ "id": "x" });
    let reply = send_json(
        &h.app,
        Method::POST,
        "/api/v1/nodes/edge-1/sites",
        &cookie_only,
        body,
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(fake.sites.lock().expect("lock").is_empty());
}

// The browser sees only name, url, online and version; stored tokens and CA material stay server side.
#[tokio::test]
async fn node_tokens_and_trust_material_never_reach_the_browser() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let list = get_path(&h.app, "/api/v1/nodes", &s.headers()).await;
    let first = list.json()[0].clone();
    let mut keys: Vec<String> = first.as_object().expect("object").keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["name", "online", "url", "version"]);
    for uri in ["/api/v1/nodes", "/api/v1/nodes/summary", "/api/v1/session"] {
        let reply = get_path(&h.app, uri, &s.headers()).await;
        assert!(!reply.text().contains(NODE_TOKEN), "{uri}");
        assert!(!reply.text().contains("ca_pem"), "{uri}");
        assert!(!reply.text().contains("token_ref"), "{uri}");
    }
    let proxied = get_path(&h.app, "/api/v1/nodes/edge-1/settings", &s.headers()).await;
    assert!(proxied.headers.get(header::AUTHORIZATION).is_none());
    assert!(proxied.headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn proxy_reports_a_rejected_stored_token_as_a_gateway_error() {
    let fake = new_fake("a_different_token");
    let url = spawn_fake(fake).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let reply = get_path(&h.app, "/api/v1/nodes/edge-1/sites", &s.headers()).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert!(
        reply.json()["error"]
            .as_str()
            .expect("error")
            .contains("rejected the stored token")
    );
}

// A node cannot make the dashboard buffer an unbounded response, and a client cannot push an unbounded request through.
#[tokio::test]
async fn proxy_bounds_request_and_response_sizes() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let huge = json!({ "pad": "a".repeat(1_500_000) });
    let request = send_json(
        &h.app,
        Method::PUT,
        "/api/v1/nodes/edge-1/settings",
        &s.headers(),
        huge,
    )
    .await;
    assert_eq!(request.status, StatusCode::PAYLOAD_TOO_LARGE);
    let response = get_path(&h.app, "/api/v1/nodes/edge-1/haproxy/stats", &s.headers()).await;
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn deployments_in_each_mode_report_every_node_including_failures() {
    let fresh = new_fake(NODE_TOKEN);
    let taken = new_fake(NODE_TOKEN);
    taken.sites.lock().expect("lock").push(site_json("shop"));
    let fresh_url = spawn_fake(fresh.clone()).await;
    let taken_url = spawn_fake(taken.clone()).await;
    let h = harness_with_nodes(&[
        ("fresh", fresh_url.as_str(), NODE_TOKEN),
        ("taken", taken_url.as_str(), NODE_TOKEN),
    ]);
    let s = login(&h).await;
    let body =
        json!({ "nodes": ["fresh", "taken", "ghost"], "site": site_json("shop"), "mode": "each" });
    let reply = send_json(
        &h.app,
        Method::POST,
        "/api/v1/deployments",
        &s.headers(),
        body,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let results = reply.json()["results"].clone();
    assert_eq!(results[0]["node"], "fresh");
    assert_eq!(results[0]["ok"], true);
    assert_eq!(results[0]["action"], "created");
    assert_eq!(results[1]["node"], "taken");
    assert_eq!(results[1]["ok"], false);
    assert!(results[1]["error"].as_str().expect("error").contains("409"));
    assert_eq!(results[2]["node"], "ghost");
    assert!(
        results[2]["error"]
            .as_str()
            .expect("error")
            .contains("not configured")
    );
    assert_eq!(fresh.sites.lock().expect("lock").len(), 1);
    assert_eq!(taken.sites.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn deployments_in_replicate_mode_make_every_node_identical() {
    let fresh = new_fake(NODE_TOKEN);
    let stale = new_fake(NODE_TOKEN);
    let mut old = site_json("shop");
    old["name"] = json!("Old name");
    stale.sites.lock().expect("lock").push(old);
    let fresh_url = spawn_fake(fresh.clone()).await;
    let stale_url = spawn_fake(stale.clone()).await;
    let h = harness_with_nodes(&[
        ("fresh", fresh_url.as_str(), NODE_TOKEN),
        ("stale", stale_url.as_str(), NODE_TOKEN),
    ]);
    let s = login(&h).await;
    let body =
        json!({ "nodes": ["fresh", "stale"], "site": site_json("shop"), "mode": "replicate" });
    let reply = send_json(
        &h.app,
        Method::POST,
        "/api/v1/deployments",
        &s.headers(),
        body,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let results = reply.json()["results"].clone();
    assert_eq!(results[0]["action"], "created");
    assert_eq!(results[1]["action"], "updated");
    assert_eq!(fresh.sites.lock().expect("lock")[0], site_json("shop"));
    assert_eq!(stale.sites.lock().expect("lock")[0], site_json("shop"));
}

#[tokio::test]
async fn deployments_where_every_node_fails_return_a_conflict_with_details() {
    let taken = new_fake(NODE_TOKEN);
    taken.sites.lock().expect("lock").push(site_json("shop"));
    let url = spawn_fake(taken).await;
    let h = harness_with_nodes(&[("taken", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let body = json!({ "nodes": ["taken"], "site": site_json("shop"), "mode": "each" });
    let reply = send_json(
        &h.app,
        Method::POST,
        "/api/v1/deployments",
        &s.headers(),
        body,
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    let payload = reply.json();
    assert!(
        payload["error"]
            .as_str()
            .expect("error")
            .starts_with("taken: ")
    );
    assert_eq!(payload["results"][0]["ok"], false);
}

#[tokio::test]
async fn deployments_validate_their_input() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake.clone()).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let mut bad_site = site_json("shop");
    bad_site["id"] = json!("Not A Slug");
    let cases = [
        json!({ "nodes": [], "site": site_json("shop"), "mode": "each" }),
        json!({ "nodes": ["edge-1"], "site": bad_site, "mode": "each" }),
        json!({ "nodes": ["edge-1"], "site": site_json("shop"), "mode": "sideways" }),
        json!({ "nodes": ["edge-1"], "site": site_json("shop"), "mode": "each", "surprise": 1 }),
        json!({ "nodes": ["edge-1"], "site": site_json("shop"), "mode": "each", "github_token": "ghp_x" }),
    ];
    for body in cases {
        let reply = send_json(
            &h.app,
            Method::POST,
            "/api/v1/deployments",
            &s.headers(),
            body.clone(),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{body} -> {}",
            reply.text()
        );
    }
    assert!(fake.sites.lock().expect("lock").is_empty());
}

// The GitHub token travels to the node beside the site but is never echoed to the browser or written to the dashboard config.
#[tokio::test]
async fn a_github_token_is_sent_beside_the_site_and_not_echoed() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake.clone()).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let mut with_source = site("shop");
    with_source.source = Some(Source {
        repo: "seggys116/cite".into(),
        branch: None,
        runtime: None,
        node_major: None,
        poll_interval: None,
        secret: None,
    });
    let body = json!({
        "nodes": ["edge-1"],
        "site": with_source,
        "mode": "each",
        "github_token": "ghp_example_token",
    });
    let reply = send_json(
        &h.app,
        Method::POST,
        "/api/v1/deployments",
        &s.headers(),
        body,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert!(!reply.text().contains("ghp_example_token"));
    let stored = fake.created_bodies.lock().expect("lock")[0].clone();
    assert_eq!(stored["github_token"], "ghp_example_token");
    assert!(stored["source"]["secret"].is_null());
    let on_disk = std::fs::read_to_string(&h.config_path).expect("config");
    assert!(!on_disk.contains("ghp_example_token"));
}

// Every field of the source is forwarded as given, and the token stays beside the site instead of landing in source.secret.
#[tokio::test]
async fn a_source_site_is_forwarded_whole_with_the_token_at_top_level() {
    let fake = new_fake(NODE_TOKEN);
    let url = spawn_fake(fake.clone()).await;
    let h = harness_with_nodes(&[("edge-1", url.as_str(), NODE_TOKEN)]);
    let s = login(&h).await;
    let mut built = site("shop");
    built.blue = Upstream::default();
    built.source = Some(Source {
        repo: "acme/shop".into(),
        branch: Some("release".into()),
        runtime: Some("bun".into()),
        node_major: Some(24),
        poll_interval: Some("30s".into()),
        secret: None,
    });
    let body = json!({
        "nodes": ["edge-1"],
        "site": built,
        "mode": "each",
        "github_token": "  ghp_private  ",
    });
    let reply = send_json(
        &h.app,
        Method::POST,
        "/api/v1/deployments",
        &s.headers(),
        body,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let sent = fake.created_bodies.lock().expect("lock")[0].clone();
    assert_eq!(sent["github_token"], "ghp_private");
    assert_eq!(sent["source"]["repo"], "acme/shop");
    assert_eq!(sent["source"]["branch"], "release");
    assert_eq!(sent["source"]["runtime"], "bun");
    assert_eq!(sent["source"]["node_major"], 24);
    assert_eq!(sent["source"]["poll_interval"], "30s");
    assert!(sent["source"]["secret"].is_null());
    assert!(!reply.text().contains("ghp_private"));
}

#[tokio::test]
async fn deployments_need_a_session_and_the_csrf_token() {
    let h = harness();
    let body = json!({ "nodes": ["a"], "site": site_json("shop"), "mode": "each" });
    let anonymous = send_json(
        &h.app,
        Method::POST,
        "/api/v1/deployments",
        &[],
        body.clone(),
    )
    .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let s = login(&h).await;
    let cookie_only = [("cookie", s.cookie.as_str())];
    let no_csrf = send_json(
        &h.app,
        Method::POST,
        "/api/v1/deployments",
        &cookie_only,
        body,
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
}

// Without the one-time token from the dashboard log nobody can claim a fresh install, and repeated bad tokens lock out even the right one.
#[tokio::test]
async fn setup_needs_the_one_time_token_and_failures_lock_out() {
    let h = harness_with(DashboardConfig::default(), &[], &[]);
    let body = |token: &str| json!({ "setup_token": token, "username": "operator", "password": "a long enough passphrase" });
    let before = send_json(&h.app, Method::POST, "/api/v1/setup", &[], body("anything")).await;
    assert_eq!(before.status, StatusCode::FORBIDDEN);
    let token = h.state.issue_setup_token().expect("setup token");
    let wrong = send_json(
        &h.app,
        Method::POST,
        "/api/v1/setup",
        &[],
        body("0".repeat(32).as_str()),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert!(h.state.needs_onboarding().await);
    let missing = send_json(
        &h.app,
        Method::POST,
        "/api/v1/setup",
        &[],
        json!({ "username": "operator", "password": "a long enough passphrase" }),
    )
    .await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    for _ in 0..4 {
        send_json(&h.app, Method::POST, "/api/v1/setup", &[], body("nope")).await;
    }
    let locked = send_json(&h.app, Method::POST, "/api/v1/setup", &[], body(&token)).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_new_setup_token_replaces_the_old_one() {
    let h = harness_with(DashboardConfig::default(), &[], &[]);
    let first = h.state.issue_setup_token().expect("token");
    let second = h.state.issue_setup_token().expect("token");
    assert_ne!(first, second);
    assert!(!h.state.setup_token_matches(&first));
    assert!(h.state.setup_token_matches(&second));
}

async fn store_preview(h: &Harness, s: &Session, html: &str) -> Reply {
    send_json(
        &h.app,
        Method::POST,
        "/api/v1/preview",
        &s.headers(),
        json!({ "html": html }),
    )
    .await
}

#[tokio::test]
async fn preview_creation_needs_a_session_and_csrf() {
    let h = harness();
    let anon = send_json(
        &h.app,
        Method::POST,
        "/api/v1/preview",
        &[],
        json!({ "html": "<p>x</p>" }),
    )
    .await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
    let s = login(&h).await;
    let no_csrf = send_json(
        &h.app,
        Method::POST,
        "/api/v1/preview",
        &[("cookie", s.cookie.as_str())],
        json!({ "html": "<p>x</p>" }),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
    let ok = store_preview(&h, &s, "<p>x</p>").await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    assert_eq!(ok.json()["id"].as_str().expect("id").len(), 32);
}

#[tokio::test]
async fn preview_html_is_capped_at_256_kib() {
    let h = harness();
    let s = login(&h).await;
    let at_limit = "a".repeat(256 * 1024);
    assert_eq!(
        store_preview(&h, &s, &at_limit).await.status,
        StatusCode::OK
    );
    let over = "a".repeat(256 * 1024 + 1);
    assert_eq!(
        store_preview(&h, &s, &over).await.status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

// Preview html is untrusted, so it is served only to signed-in users and under a sandbox policy that allows no script.
#[tokio::test]
async fn stored_previews_are_served_sandboxed_to_signed_in_users_only() {
    let h = harness();
    let s = login(&h).await;
    let html = "<style>p{color:red}</style><p>hi</p>";
    let id = store_preview(&h, &s, html).await.json()["id"]
        .as_str()
        .expect("id")
        .to_string();
    let uri = format!("/preview/{id}");
    let anon = get_path(&h.app, &uri, &[]).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
    let reply = get_path(&h.app, &uri, &[("cookie", s.cookie.as_str())]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.text(), html);
    assert_eq!(
        reply.header("content-security-policy"),
        "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:"
    );
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("x-content-type-options"), "nosniff");
    assert_eq!(reply.header("content-type"), "text/html; charset=utf-8");
    let missing = get_path(
        &h.app,
        "/preview/deadbeef",
        &[("cookie", s.cookie.as_str())],
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn secure_sessions_name_the_cookie_with_the_host_prefix() {
    let h = harness_with(
        onboarded(),
        &[],
        &[("CITE_DASHBOARD_COOKIE_SECURE", "true")],
    );
    let body = json!({ "username": "admin", "password": PASSWORD, "totp": code(0) });
    let reply = send_json(&h.app, Method::POST, "/api/v1/session", &[], body).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let set_cookie = reply.header("set-cookie");
    assert!(set_cookie.starts_with("__Host-cite_session=cite_"));
    assert!(set_cookie.contains("Path=/") && set_cookie.contains("Secure"));
    assert!(!set_cookie.contains("Domain"));
    let pair = set_cookie.split(';').next().expect("pair").to_string();
    let ok = get_path(&h.app, "/api/v1/session", &[("cookie", pair.as_str())]).await;
    assert_eq!(ok.status, StatusCode::OK);
    let planted = format!("{pair}; {pair}x");
    let dup = get_path(&h.app, "/api/v1/session", &[("cookie", planted.as_str())]).await;
    assert_eq!(dup.status, StatusCode::UNAUTHORIZED);
}

// A cookie planted from a sibling origin could shadow the real one, so two session cookies mean no session instead of picking one.
#[tokio::test]
async fn a_planted_duplicate_session_cookie_is_unauthenticated() {
    let h = harness();
    let s = login(&h).await;
    let planted = format!("cite_session=cite_planted; {}", s.cookie);
    let reply = get_path(&h.app, "/api/v1/session", &[("cookie", planted.as_str())]).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

// Guessing names from many addresses must not use up the real operator's attempts.
#[tokio::test]
async fn failures_for_unknown_usernames_never_lock_the_real_operator() {
    let h = harness();
    for i in 0..120 {
        let body =
            json!({ "username": format!("stranger{}", i % 3), "password": "x", "totp": "000000" });
        let reply = call_from(&h.app, i, body).await;
        assert_ne!(reply, StatusCode::TOO_MANY_REQUESTS, "attempt {i}");
    }
    let _ok = login(&h).await;
}

// Peers in one /64 share a limiter key, so rotating the low bits of an address does not dodge the limit.
#[tokio::test]
async fn ipv6_peers_in_one_prefix_share_a_limiter_key() {
    let h = harness();
    let body = || json!({ "username": "admin", "password": "wrong password", "totp": "000000" });
    for i in 0..5u16 {
        let peer = SocketAddr::from(([0x2001, 0xdb8, 1, 2, i, 0, 0, 1], 4000));
        assert_eq!(
            post_login_from(&h.app, peer, body()).await,
            StatusCode::UNAUTHORIZED
        );
    }
    let sibling = SocketAddr::from(([0x2001, 0xdb8, 1, 2, 9, 9, 9, 9], 4000));
    assert_eq!(
        post_login_from(&h.app, sibling, body()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

// A failing login must not wait on the config write gate, or a stuck write could freeze every login.
#[tokio::test]
async fn a_slow_login_does_not_hold_the_write_gate() {
    let h = harness();
    let _held = h.state.write_gate.lock().await;
    let body = json!({ "username": "stranger", "password": "x", "totp": "000000" });
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        post_login_from(&h.app, SocketAddr::from(([203, 0, 113, 50], 1)), body),
    )
    .await
    .expect("a failing login must not wait on the write gate");
    assert_eq!(reply, StatusCode::UNAUTHORIZED);
}

// Forty parallel guesses from one peer: only the limit's worth may reach the expensive password hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_login_burst_is_capped_at_the_limit_before_any_hash_runs() {
    let h = harness();
    let peer = SocketAddr::from(([203, 0, 113, 77], 1));
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let app = h.app.clone();
        tasks.push(tokio::spawn(async move {
            let body =
                json!({ "username": "admin", "password": "wrong password!!", "totp": "000000" });
            post_login_from(&app, peer, body).await
        }));
    }
    let (mut rejected, mut limited) = (0, 0);
    for task in tasks {
        match task.await.expect("task") {
            StatusCode::UNAUTHORIZED => rejected += 1,
            StatusCode::TOO_MANY_REQUESTS => limited += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(rejected, 5, "only the per-key limit may reach the hash");
    assert_eq!(limited, 35);
}

#[tokio::test]
async fn a_successful_login_clears_its_provisional_failure() {
    let h = harness();
    let url = "/api/v1/session";
    let wrong = || json!({ "username": "admin", "password": "wrong password!!", "totp": "000000" });
    for _ in 0..4 {
        let reply = send_json(&h.app, Method::POST, url, &[], wrong()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let _ok = login(&h).await;
    for _ in 0..4 {
        let reply = send_json(&h.app, Method::POST, url, &[], wrong()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
}

fn seed_config_file(h: &Harness) {
    ConfigFile::save(&h.config_path, &onboarded()).expect("seed config");
}

// After credentials are reset from the CLI, a session issued under the old credentials must stop working.
#[tokio::test]
async fn a_cli_reset_is_adopted_and_drops_existing_sessions() {
    let h = harness();
    seed_config_file(&h);
    let s = login(&h).await;
    let before = get_path(&h.app, "/api/v1/session", &[("cookie", s.cookie.as_str())]).await;
    assert_eq!(before.status, StatusCode::OK);
    cite_dashboard::cli::init_account(&h.config_path, "ops", true).expect("forced init");
    let after = get_path(&h.app, "/api/v1/session", &[("cookie", s.cookie.as_str())]).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    let admin = h.state.config_snapshot().await.admin.expect("admin");
    assert_eq!(admin.username, "ops");
}

// A stale in-memory config must not write over a reset made on disk meanwhile, or the old credentials would come back.
#[tokio::test]
async fn running_state_cannot_overwrite_a_cli_reset() {
    let h = harness();
    seed_config_file(&h);
    let stale = h.state.config_snapshot().await;
    cite_dashboard::cli::init_account(&h.config_path, "ops", true).expect("forced init");
    let _gate = h.state.write_gate.lock().await;
    let err = h
        .state
        .commit_config(stale)
        .await
        .expect_err("stale write must be refused");
    assert_eq!(err.status(), StatusCode::CONFLICT);
    let saved = ConfigFile::load(&h.config_path).expect("load");
    assert_eq!(saved.admin.expect("admin").username, "ops");
    assert_eq!(saved.generation, 1);
    let adopted = h.state.config_snapshot().await;
    assert_eq!(adopted.admin.expect("admin").username, "ops");
    h.state
        .commit_config(adopted_with_node(&h).await)
        .await
        .expect("commit after adopting");
    let saved = ConfigFile::load(&h.config_path).expect("load");
    assert_eq!(saved.admin.expect("admin").username, "ops");
    assert_eq!(saved.nodes.len(), 1);
}

async fn adopted_with_node(h: &Harness) -> DashboardConfig {
    let mut cfg = h.state.config_snapshot().await;
    cfg.add_node(node_entry("edge-1", "http://127.0.0.1:7443"))
        .expect("node");
    cfg
}

async fn post_login_from(app: &Router, peer: SocketAddr, body: Value) -> StatusCode {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("encode")))
        .expect("request");
    req.extensions_mut().insert(ConnectInfo(peer));
    app.clone().oneshot(req).await.expect("response").status()
}

async fn call_from(app: &Router, i: u32, body: Value) -> StatusCode {
    let peer = SocketAddr::from(([198, 51, (i / 250) as u8, (i % 250) as u8 + 1], 1));
    post_login_from(app, peer, body).await
}
