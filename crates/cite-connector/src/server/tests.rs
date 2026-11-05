use std::os::unix::fs::PermissionsExt;
use std::sync::OnceLock;

use cite_edge::auth::{Credentials, hash_password};
use cite_edge::model::{LogEvent, Site};
use cite_edge::totp;
use reqwest::{Client, Method};
use serde_json::{Value, json};

use super::*;
use crate::store::testing::test_config;

mod archive_api;

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD: &str = "correct horse battery";

fn password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password(PASSWORD).expect("hash"))
}

fn creds() -> Credentials {
    Credentials {
        username: "admin".into(),
        password_hash: password_hash().to_string(),
        totp_secret: SECRET.into(),
        totp_last_step: 0,
    }
}

fn current_code() -> String {
    totp::code_at(SECRET, now_unix()).expect("code")
}

fn now_ms() -> i64 {
    i64::try_from(now_unix()).expect("clock") * 1000
}

// Each harness runs the real accept loop on an ephemeral loopback port with its own data dir.
struct Harness {
    _dir: tempfile::TempDir,
    addr: SocketAddr,
    http: Client,
    state: AppState,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start() -> Harness {
    start_with(|_| {}).await
}

async fn start_with(tweak: impl FnOnce(&mut ConnectorConfig)) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = test_config(dir.path());
    tweak(&mut cfg);
    let store = Store::open(&cfg).await.expect("open");
    store.set_credentials(creds()).await.expect("credentials");
    let haproxy = Arc::new(Haproxy::new(&cfg));
    let deployer = Arc::new(Deployer::new(
        Arc::clone(&store),
        Arc::clone(&haproxy),
        None,
    ));
    let analytics = logsink::open_store(&cfg, 30).expect("analytics store");
    let acceptor = if cfg.tls {
        tls::ensure(&cfg).expect("tls material");
        Some(tls::load_acceptor(&cfg.tls_dir).expect("acceptor"))
    } else {
        None
    };
    let ingest = Arc::new(IngestStats::default());
    let state = Inner::new(cfg, store, haproxy, deployer, None, analytics, ingest);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(serve(listener, Arc::clone(&state), acceptor));
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    Harness {
        _dir: dir,
        addr,
        http,
        state,
        task,
    }
}

impl Harness {
    fn url(&self, path: &str) -> String {
        format!("http://{}/api/v1{path}", self.addr)
    }

    fn listen_cfg(&self) -> ConnectorConfig {
        let mut cfg = self.state.cfg.clone();
        cfg.listen = self.addr;
        cfg
    }

    async fn login_with(&self, user: &str, password: &str, code: &str) -> reqwest::Response {
        self.http
            .post(self.url("/auth/login"))
            .json(&json!({ "username": user, "password": password, "totp": code }))
            .send()
            .await
            .expect("login request")
    }

    // Resetting the stored TOTP step lets every helper login reuse the current code.
    async fn token(&self) -> String {
        self.state
            .store
            .set_credentials(creds())
            .await
            .expect("reset step");
        let res = self.login_with("admin", PASSWORD, &current_code()).await;
        assert_eq!(res.status().as_u16(), 200);
        let body: Value = res.json().await.expect("login body");
        body["token"].as_str().expect("token").to_string()
    }

    async fn call(
        &self,
        method: Method,
        token: Option<&str>,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut req = self.http.request(method, self.url(path));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.expect("request");
        let status = res.status().as_u16();
        let text = res.text().await.expect("body");
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn get(&self, token: &str, path: &str) -> (u16, Value) {
        self.call(Method::GET, Some(token), path, None).await
    }

    async fn post(&self, token: &str, path: &str, body: Value) -> (u16, Value) {
        self.call(Method::POST, Some(token), path, Some(body)).await
    }

    async fn put(&self, token: &str, path: &str, body: Value) -> (u16, Value) {
        self.call(Method::PUT, Some(token), path, Some(body)).await
    }

    async fn delete(&self, token: &str, path: &str) -> (u16, Value) {
        self.call(Method::DELETE, Some(token), path, None).await
    }

    // Goes through the real writer, so the events are durable and visible when this returns.
    fn ingest(&self, events: impl IntoIterator<Item = LogEvent>) {
        let writer = self.state.analytics.writer();
        for event in events {
            writer.send(event).expect("send");
        }
        writer.flush().expect("flush");
    }

    async fn get_raw(&self, token: &str, path: &str) -> reqwest::Response {
        self.http
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("request")
    }

    async fn seed_site(&self, id: &str) {
        let site: Site =
            serde_json::from_value(site_json(id, &format!("{id}.example.com"))).expect("site");
        self.state
            .store
            .update("test", "seed", move |cfg| {
                cfg.sites.push(site);
                Ok(())
            })
            .await
            .expect("seed");
    }
}

fn site_json(id: &str, host: &str) -> Value {
    json!({
        "id": id,
        "name": "Site",
        "hosts": [host],
        "blue": { "targets": [{ "addr": "10.0.0.1:8080" }] },
        "green": { "targets": [] },
        "active": "blue"
    })
}

fn page_json(id: &str) -> Value {
    json!({ "id": id, "name": "Down", "html": "<p>down</p>" })
}

fn rule_json(id: &str) -> Value {
    json!({
        "id": id,
        "name": "Block env files",
        "enabled": true,
        "action": "deny",
        "matchers": { "path_prefix": "/.env" }
    })
}

fn event(ip: &str, status: u16) -> LogEvent {
    LogEvent {
        ts_ms: now_ms(),
        client_ip: ip.into(),
        host: "a.example.com".into(),
        method: "GET".into(),
        path: "/x".into(),
        query_len: 0,
        status,
        bytes_in: 10,
        bytes_out: 100,
        total_ms: 5,
        user_agent: "ua".into(),
        referer: String::new(),
        content_type: "text/html".into(),
        backend: "be".into(),
        server: "s".into(),
        site: "blog".into(),
        blocked: None,
        ..LogEvent::default()
    }
}

// This predicate decides which sockets are dropped unread, before any TLS or HTTP parsing.
#[test]
fn admission_decisions_follow_the_allowlist_and_loopback_rule() {
    let allow = IpAllowlist::parse("10.0.0.0/8, 192.168.1.5").expect("allowlist");
    let decide = |ip: &str| admit(&allow, ip.parse().expect("ip"));
    assert_eq!(decide("10.1.2.3"), Admission::Full);
    assert_eq!(decide("::ffff:10.1.2.3"), Admission::Full);
    assert_eq!(decide("192.168.1.5"), Admission::Full);
    assert_eq!(decide("192.168.1.6"), Admission::Denied);
    assert_eq!(decide("8.8.8.8"), Admission::Denied);
    assert_eq!(decide("2001:db8::1"), Admission::Denied);
    assert_eq!(decide("127.0.0.1"), Admission::LoopbackOnly);
    assert_eq!(decide("::1"), Admission::LoopbackOnly);
    assert_eq!(decide("::ffff:127.0.0.1"), Admission::LoopbackOnly);
    let with_loopback = IpAllowlist::parse("127.0.0.1").expect("allowlist");
    assert_eq!(
        admit(&with_loopback, "127.0.0.1".parse().expect("ip")),
        Admission::Full
    );
}

#[test]
fn only_the_health_paths_are_loopback_reachable() {
    assert!(is_health_path("/healthz"));
    assert!(is_health_path("/api/v1/healthz"));
    assert!(!is_health_path("/api/v1/node"));
    assert!(!is_health_path("/healthz/extra"));
}

#[tokio::test]
async fn api_errors_use_status_mapping_and_hide_internal_detail() {
    let internal = ApiError::from(ConnectorError::Internal("secret path /etc/x".into()));
    let res = internal.into_response();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = axum::body::to_bytes(res.into_body(), 4096)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body, json!({ "error": "internal error" }));

    let conflict = ApiError::from(ConnectorError::Conflict("taken".into())).into_response();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let limited = ApiError::too_many(30).into_response();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.headers().get(header::RETRY_AFTER).expect("header"),
        "30"
    );
}

#[tokio::test]
async fn healthz_is_public_and_carries_security_headers() {
    let h = start().await;
    for url in [h.url("/healthz"), format!("http://{}/healthz", h.addr)] {
        let res = h.http.get(url).send().await.expect("request");
        assert_eq!(res.status().as_u16(), 200);
        assert_eq!(res.headers()["cache-control"], "no-store");
        assert_eq!(res.headers()["x-content-type-options"], "nosniff");
        let body: Value = res.json().await.expect("json");
        assert_eq!(body, json!({ "ok": true }));
    }
}

// With no credential every management route answers 401 with a challenge and a no-store header.
#[tokio::test]
async fn protected_routes_require_a_bearer_token() {
    let h = start().await;
    for path in [
        "/node",
        "/sites",
        "/pages",
        "/firewall/rules",
        "/settings",
        "/audit",
        "/tokens",
    ] {
        let res = h.http.get(h.url(path)).send().await.expect("request");
        assert_eq!(res.status().as_u16(), 401, "{path}");
        assert_eq!(res.headers()["www-authenticate"], "Bearer");
        assert_eq!(res.headers()["cache-control"], "no-store");
        let body: Value = res.json().await.expect("json");
        assert_eq!(body, json!({ "error": "unauthorized" }));
    }
}

// A wrong scheme, an empty bearer or a bare token must not be accepted by lenient header parsing.
#[tokio::test]
async fn garbage_and_malformed_credentials_are_rejected() {
    let h = start().await;
    for value in [
        "Bearer cite_nonsense",
        "Basic YWRtaW46cGFzcw==",
        "Bearer",
        "Bearer  ",
        "cite_x",
    ] {
        let res = h
            .http
            .get(h.url("/node"))
            .header("authorization", value)
            .send()
            .await
            .expect("request");
        assert_eq!(res.status().as_u16(), 401, "{value}");
    }
}

#[tokio::test]
async fn login_issues_a_session_token_that_works() {
    let h = start().await;
    let token = h.token().await;
    assert!(token.starts_with("cite_"));
    let (status, me) = h.get(&token, "/auth/me").await;
    assert_eq!(status, 200);
    assert_eq!(me["username"], "admin");
    assert_eq!(me["kind"], "session");
    assert!(me["expires_at"].as_str().is_some_and(|s| s.contains('T')));
}

// A mistyped password must never be persisted, so the audit trail cannot become a list of near-miss secrets.
#[tokio::test]
async fn failed_login_is_generic_and_audited_without_the_password() {
    let h = start().await;
    let code = current_code();
    let res = h.login_with("admin", "wrong password here", &code).await;
    assert_eq!(res.status().as_u16(), 401);
    let body: Value = res.json().await.expect("json");
    assert_eq!(body, json!({ "error": "invalid credentials" }));
    let tail = h.state.store.audit_tail(5).await;
    let entry = tail
        .iter()
        .find(|e| e.action == "login.failure")
        .expect("audit entry");
    assert!(entry.detail.contains("peer=127.0.0.1"));
    assert!(!entry.detail.contains("wrong password here"));
}

// Unknown user, wrong password and wrong code return the same body, so the response cannot be used to enumerate accounts.
#[tokio::test]
async fn every_credential_failure_looks_the_same() {
    let h = start().await;
    let code = current_code();
    let attempts = [
        ("nobody", PASSWORD, code.as_str()),
        ("admin", "not the password", code.as_str()),
        ("admin", PASSWORD, "000000"),
    ];
    for (user, password, otp) in attempts {
        let res = h.login_with(user, password, otp).await;
        assert_eq!(res.status().as_u16(), 401);
        let body: Value = res.json().await.expect("json");
        assert_eq!(body, json!({ "error": "invalid credentials" }));
    }
}

// A one-time code that was observed and resubmitted within its validity window must be refused.
#[tokio::test]
async fn totp_codes_cannot_be_replayed() {
    let h = start().await;
    h.state.store.set_credentials(creds()).await.expect("reset");
    let code = current_code();
    assert_eq!(
        h.login_with("admin", PASSWORD, &code)
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        h.login_with("admin", PASSWORD, &code)
            .await
            .status()
            .as_u16(),
        401
    );
}

// After five failures even correct credentials are refused, which is what stops online guessing.
#[tokio::test]
async fn repeated_failures_lock_the_client_out_with_retry_after() {
    let h = start().await;
    for _ in 0..5 {
        let res = h.login_with("admin", "wrong password here", "000000").await;
        assert_eq!(res.status().as_u16(), 401);
    }
    let res = h.login_with("admin", PASSWORD, &current_code()).await;
    assert_eq!(res.status().as_u16(), 429);
    assert!(res.headers().contains_key("retry-after"));
    let body: Value = res.json().await.expect("json");
    assert!(body["retry_after"].as_u64().is_some_and(|n| n >= 1));
    assert!(body["error"].is_string());
}

// Logout has to revoke the token on the server, since a client that merely forgets it leaves a stolen copy valid.
#[tokio::test]
async fn logout_revokes_the_session() {
    let h = start().await;
    let token = h.token().await;
    let (status, body) = h.post(&token, "/auth/logout", json!({})).await;
    assert_eq!((status, body), (200, json!({ "ok": true })));
    assert_eq!(h.get(&token, "/auth/me").await.0, 401);
}

#[tokio::test]
async fn api_tokens_can_be_created_used_listed_and_revoked() {
    let h = start().await;
    let session = h.token().await;
    let (status, created) = h.post(&session, "/tokens", json!({ "name": "ci" })).await;
    assert_eq!(status, 200);
    let api = created["token"].as_str().expect("token").to_string();
    let id = created["id"].as_str().expect("id").to_string();

    let (status, me) = h.get(&api, "/auth/me").await;
    assert_eq!(status, 200);
    assert_eq!(me["kind"], "api");
    assert_eq!(h.get(&api, "/node").await.0, 200);

    let (_, listed) = h.get(&session, "/tokens").await;
    let item = &listed.as_array().expect("array")[0];
    assert_eq!(item["name"], "ci");
    assert!(item.get("token").is_none() && item.get("hash").is_none());

    assert_eq!(h.delete(&session, &format!("/tokens/{id}")).await.0, 200);
    assert_eq!(h.get(&api, "/node").await.0, 401);
    assert_eq!(h.delete(&session, &format!("/tokens/{id}")).await.0, 404);
}

#[tokio::test]
async fn token_names_are_validated() {
    let h = start().await;
    let t = h.token().await;
    for name in ["", "   ", "bad\nname"] {
        assert_eq!(
            h.post(&t, "/tokens", json!({ "name": name })).await.0,
            400,
            "{name:?}"
        );
    }
    assert_eq!(
        h.post(&t, "/tokens", json!({ "name": "x".repeat(65) }))
            .await
            .0,
        400
    );
    assert_eq!(h.delete(&t, "/tokens/not-hex!").await.0, 404);
}

#[tokio::test]
async fn node_reports_identity_and_counts() {
    let h = start().await;
    let t = h.token().await;
    let (status, node) = h.get(&t, "/node").await;
    assert_eq!(status, 200);
    assert_eq!(node["name"], "test-node");
    assert_eq!(node["version"], env!("CARGO_PKG_VERSION"));
    assert!(node["uptime_secs"].is_u64());
    assert!(node["haproxy"].is_object());
    assert_eq!(node["sites"], 0);
    assert_eq!(node["firewall_rules"], 0);
    assert_eq!(
        node["orchestrator"],
        json!({ "enabled": false, "reachable": false })
    );
}

#[tokio::test]
async fn unknown_routes_and_methods_return_json_errors() {
    let h = start().await;
    let t = h.token().await;
    let (status, body) = h.get(&t, "/nope").await;
    assert_eq!((status, body), (404, json!({ "error": "not found" })));
    let res = h
        .http
        .delete(h.url("/node"))
        .bearer_auth(&t)
        .send()
        .await
        .expect("request");
    assert_eq!(res.status().as_u16(), 405);
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    let body: Value = res.json().await.expect("json");
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn malformed_json_is_a_400_with_the_error_shape() {
    let h = start().await;
    let t = h.token().await;
    for body in ["{not json", "", "[]", "{\"id\": 5}"] {
        let res = h
            .http
            .post(h.url("/pages"))
            .bearer_auth(&t)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .expect("request");
        assert_eq!(res.status().as_u16(), 400, "{body:?}");
        let parsed: Value = res.json().await.expect("json");
        assert!(parsed["error"].is_string());
    }
}

#[tokio::test]
// A small overshoot keeps the client from being reset while it is still uploading.
async fn bodies_over_one_mebibyte_are_rejected() {
    let h = start().await;
    let t = h.token().await;
    let res = h
        .http
        .post(h.url("/pages"))
        .bearer_auth(&t)
        .header("content-type", "application/json")
        .body(vec![b' '; MAX_BODY_BYTES + 16])
        .send()
        .await
        .expect("request");
    assert_eq!(res.status().as_u16(), 413);
    let body: Value = res.json().await.expect("json");
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn site_crud_round_trip() {
    let h = start().await;
    let t = h.token().await;
    let (status, created) = h
        .post(&t, "/sites", site_json("blog", "blog.example.com"))
        .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["id"], "blog");

    let (_, listed) = h.get(&t, "/sites").await;
    assert_eq!(listed.as_array().expect("array").len(), 1);
    let (status, one) = h.get(&t, "/sites/blog").await;
    assert_eq!(status, 200);
    assert!(one["live"]["blue"].is_array() && one["live"]["green"].is_array());

    let mut edited = site_json("blog", "blog.example.com");
    edited["name"] = json!("Renamed");
    let (status, updated) = h.put(&t, "/sites/blog", edited).await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["name"], "Renamed");

    assert_eq!(h.delete(&t, "/sites/blog").await.0, 200);
    assert_eq!(h.get(&t, "/sites/blog").await.0, 404);
}

#[tokio::test]
async fn site_input_is_validated() {
    let h = start().await;
    let t = h.token().await;
    let bad_host = site_json("bad", "not a host!");
    assert_eq!(h.post(&t, "/sites", bad_host).await.0, 400);
    let mut unknown = site_json("odd", "odd.example.com");
    unknown["bogus"] = json!(1);
    assert_eq!(h.post(&t, "/sites", unknown).await.0, 400);
    assert_eq!(h.post(&t, "/sites", json!([1, 2])).await.0, 400);
    let mut bad_token = site_json("tok", "tok.example.com");
    bad_token["github_token"] = json!(42);
    assert_eq!(h.post(&t, "/sites", bad_token).await.0, 400);

    h.seed_site("blog").await;
    let dup = site_json("blog", "other.example.com");
    assert_eq!(h.post(&t, "/sites", dup).await.0, 409);
    let mismatch = site_json("other", "other.example.com");
    assert_eq!(h.put(&t, "/sites/blog", mismatch).await.0, 400);
    assert_eq!(h.get(&t, "/sites/Bad_ID").await.0, 400);
    assert_eq!(h.get(&t, "/sites/missing").await.0, 404);
    let ghost = site_json("ghost", "ghost.example.com");
    assert_eq!(h.put(&t, "/sites/ghost", ghost).await.0, 404);
    assert_eq!(h.delete(&t, "/sites/ghost").await.0, 404);
}

#[tokio::test]
async fn github_token_is_accepted_but_never_echoed() {
    let h = start().await;
    let t = h.token().await;
    let mut body = site_json("gh", "gh.example.com");
    body["github_token"] = json!("ghp_exampletoken");
    let (status, created) = h.post(&t, "/sites", body).await;
    assert_eq!(status, 200, "{created}");
    assert!(created.get("github_token").is_none());
    let (_, fetched) = h.get(&t, "/sites/gh").await;
    assert!(!fetched.to_string().contains("ghp_exampletoken"));
}

#[tokio::test]
async fn deploy_requests_are_validated_before_the_deployer_runs() {
    let h = start().await;
    let t = h.token().await;
    h.seed_site("blog").await;
    let bad_bodies = [
        json!({ "targets": [] }),
        json!({ "targets": [{ "addr": "not-an-address" }] }),
        json!({ "git_ref": "--upload-pack=evil" }),
        json!({ "git_ref": "a..b" }),
        json!({ "note": "line\nbreak" }),
        json!({ "unknown": true }),
    ];
    for body in bad_bodies {
        assert_eq!(
            h.post(&t, "/sites/blog/deploy", body.clone()).await.0,
            400,
            "{body}"
        );
    }
    assert_eq!(h.post(&t, "/sites/ghost/deploy", json!({})).await.0, 404);
    assert_eq!(
        h.post(&t, "/sites/blog/switch", json!({ "slot": "purple" }))
            .await
            .0,
        400
    );
    assert_eq!(
        h.post(&t, "/sites/ghost/switch", json!({ "slot": "green" }))
            .await
            .0,
        404
    );
    assert_eq!(h.post(&t, "/sites/ghost/rollback", json!({})).await.0, 404);
    let bad_page = json!({ "enabled": true, "page_id": "Bad Id" });
    assert_eq!(h.post(&t, "/sites/blog/maintenance", bad_page).await.0, 400);
    let unknown = json!({ "enabled": true, "extra": 1 });
    assert_eq!(h.post(&t, "/sites/blog/maintenance", unknown).await.0, 400);
}

#[tokio::test]
async fn pages_can_be_managed_and_protected_while_in_use() {
    let h = start().await;
    let t = h.token().await;
    let (status, page) = h.post(&t, "/pages", page_json("down")).await;
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["status"], 503);
    assert_eq!(h.get(&t, "/pages/down").await.0, 200);
    assert_eq!(
        h.get(&t, "/pages").await.1.as_array().map(Vec::len),
        Some(1)
    );

    let mut edited = page_json("down");
    edited["name"] = json!("Back soon");
    assert_eq!(h.put(&t, "/pages/down", edited).await.0, 200);
    assert_eq!(h.get(&t, "/pages/down").await.1["name"], "Back soon");

    let mut site = site_json("blog", "blog.example.com");
    site["maintenance"] = json!({ "enabled": false, "page_id": "down" });
    let seeded: Site = serde_json::from_value(site).expect("site");
    h.state
        .store
        .update("test", "seed", move |cfg| {
            cfg.sites.push(seeded);
            Ok(())
        })
        .await
        .expect("seed");
    let (status, body) = h.delete(&t, "/pages/down").await;
    assert_eq!(status, 409, "{body}");
    assert!(body["error"].as_str().is_some_and(|e| e.contains("blog")));

    h.state
        .store
        .update("test", "unseed", |cfg| {
            cfg.sites.clear();
            Ok(())
        })
        .await
        .expect("unseed");
    assert_eq!(h.delete(&t, "/pages/down").await.0, 200);
    assert_eq!(h.get(&t, "/pages/down").await.0, 404);
}

#[tokio::test]
async fn page_input_is_validated() {
    let h = start().await;
    let t = h.token().await;
    let mut bad_status = page_json("down");
    bad_status["status"] = json!(200);
    assert_eq!(h.post(&t, "/pages", bad_status).await.0, 400);
    assert_eq!(h.post(&t, "/pages", page_json("Bad Id")).await.0, 400);
    assert_eq!(h.post(&t, "/pages", page_json("down")).await.0, 200);
    assert_eq!(h.post(&t, "/pages", page_json("down")).await.0, 409);
    assert_eq!(h.put(&t, "/pages/down", page_json("other")).await.0, 400);
    assert_eq!(h.put(&t, "/pages/ghost", page_json("ghost")).await.0, 404);
    assert_eq!(h.delete(&t, "/pages/ghost").await.0, 404);
}

#[tokio::test]
async fn firewall_rules_can_be_managed() {
    let h = start().await;
    let t = h.token().await;
    let (status, rule) = h.post(&t, "/firewall/rules", rule_json("no-env")).await;
    assert_eq!(status, 200, "{rule}");
    assert_eq!(
        h.get(&t, "/firewall/rules")
            .await
            .1
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    let mut edited = rule_json("no-env");
    edited["enabled"] = json!(false);
    let (status, saved) = h.put(&t, "/firewall/rules/no-env", edited).await;
    assert_eq!(status, 200);
    assert_eq!(saved["enabled"], false);
    assert_eq!(h.get(&t, "/node").await.1["firewall_rules"], 1);

    assert_eq!(h.delete(&t, "/firewall/rules/no-env").await.0, 200);
    assert_eq!(h.get(&t, "/firewall/rules").await.1, json!([]));
}

#[tokio::test]
async fn firewall_rule_input_is_validated() {
    let h = start().await;
    let t = h.token().await;
    let mut empty = rule_json("empty");
    empty["matchers"] = json!({});
    assert_eq!(h.post(&t, "/firewall/rules", empty).await.0, 400);
    let mut unknown_site = rule_json("scoped");
    unknown_site["site"] = json!("nowhere");
    assert_eq!(h.post(&t, "/firewall/rules", unknown_site).await.0, 400);
    let mut bad_action = rule_json("odd");
    bad_action["action"] = json!("explode");
    assert_eq!(h.post(&t, "/firewall/rules", bad_action).await.0, 400);
    assert_eq!(h.post(&t, "/firewall/rules", rule_json("one")).await.0, 200);
    assert_eq!(h.post(&t, "/firewall/rules", rule_json("one")).await.0, 409);
    assert_eq!(
        h.put(&t, "/firewall/rules/one", rule_json("two")).await.0,
        400
    );
    assert_eq!(
        h.put(&t, "/firewall/rules/ghost", rule_json("ghost"))
            .await
            .0,
        404
    );
    assert_eq!(h.delete(&t, "/firewall/rules/ghost").await.0, 404);
}

#[tokio::test]
async fn presets_list_and_apply_without_duplicating_rules() {
    let h = start().await;
    let t = h.token().await;
    let (status, listed) = h.get(&t, "/firewall/presets").await;
    assert_eq!(status, 200);
    let presets = listed.as_array().expect("array");
    assert!(presets.len() >= 4);
    for p in presets {
        assert!(p["name"].is_string() && p["title"].is_string() && p["description"].is_string());
        assert!(p["rules"].as_array().is_some_and(|r| !r.is_empty()));
    }
    let name = presets[0]["name"].as_str().expect("name").to_string();
    let expected = presets[0]["rules"].as_array().expect("rules").len();

    let (status, added) = h
        .post(&t, &format!("/firewall/presets/{name}/apply"), json!({}))
        .await;
    assert_eq!(status, 200, "{added}");
    assert_eq!(added.as_array().map(Vec::len), Some(expected));
    let (_, again) = h
        .post(&t, &format!("/firewall/presets/{name}/apply"), json!({}))
        .await;
    assert_eq!(again, json!([]));
    assert_eq!(
        h.get(&t, "/firewall/rules")
            .await
            .1
            .as_array()
            .map(Vec::len),
        Some(expected)
    );
    assert_eq!(
        h.post(&t, "/firewall/presets/nothing/apply", json!({}))
            .await
            .0,
        404
    );
}

#[tokio::test]
async fn settings_round_trip_and_validation() {
    let h = start().await;
    let t = h.token().await;
    let (status, mut settings) = h.get(&t, "/settings").await;
    assert_eq!(status, 200);
    assert_eq!(settings["http_port"], 80);

    settings["http_port"] = json!(8080);
    let (status, saved) = h.put(&t, "/settings", settings.clone()).await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["http_port"], 8080);
    assert_eq!(h.get(&t, "/settings").await.1["http_port"], 8080);

    settings["http_port"] = json!(0);
    assert_eq!(h.put(&t, "/settings", settings.clone()).await.0, 400);
    assert_eq!(h.get(&t, "/settings").await.1["http_port"], 8080);
    settings["http_port"] = json!(8080);
    settings["surprise"] = json!(true);
    assert_eq!(h.put(&t, "/settings", settings).await.0, 400);
}

#[tokio::test]
async fn settings_update_pushes_retention_days_into_the_store() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(h.state.analytics.retention_days(), 30);
    let (_, mut settings) = h.get(&t, "/settings").await;
    settings["retention"]["hour_buckets_days"] = json!(7);
    settings["retention"]["recent_events"] = json!(10);
    let (status, saved) = h.put(&t, "/settings", settings).await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(h.state.analytics.retention_days(), 7);
    // settings that no longer size anything are still accepted and returned unchanged
    assert_eq!(saved["retention"]["recent_events"], 10);
    assert_eq!(saved["retention"]["hour_buckets_days"], 7);
}

#[tokio::test]
async fn a_shorter_retention_removes_old_rows_without_a_restart() {
    let h = start().await;
    let t = h.token().await;
    let day = 86_400_000;
    let mut old = event("10.0.0.1", 200);
    old.ts_ms = now_ms() - 10 * day;
    h.ingest([old, event("10.0.0.2", 200)]);
    assert_eq!(h.state.analytics.stats().expect("stats").rows, 2);

    let (_, mut settings) = h.get(&t, "/settings").await;
    settings["retention"]["hour_buckets_days"] = json!(2);
    assert_eq!(h.put(&t, "/settings", settings).await.0, 200);
    let mut rows = 2;
    for _ in 0..100 {
        rows = h.state.analytics.stats().expect("stats").rows;
        if rows == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn turning_off_ip_storage_erases_stored_addresses() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([event("10.9.8.7", 200), event("10.9.8.6", 200)]);
    let ips = |h: &Harness| {
        h.state
            .analytics
            .requests(&Default::default(), 10)
            .expect("requests")
            .iter()
            .filter(|e| !e.client_ip.is_empty())
            .count()
    };
    assert_eq!(ips(&h), 2);

    let (_, mut settings) = h.get(&t, "/settings").await;
    settings["retention"]["store_client_ips"] = json!(false);
    assert_eq!(h.put(&t, "/settings", settings).await.0, 200);
    let mut left = 2;
    for _ in 0..100 {
        left = ips(&h);
        if left == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(left, 0);
    assert_eq!(h.state.analytics.stats().expect("stats").rows, 2);
}

#[tokio::test]
async fn audit_log_lists_changes_newest_first_and_validates_limit() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(h.post(&t, "/pages", page_json("down")).await.0, 200);
    let (status, entries) = h.get(&t, "/audit?limit=5").await;
    assert_eq!(status, 200);
    assert_eq!(entries[0]["action"], "page.create");
    assert_eq!(entries[0]["detail"], "down");
    assert!(entries[0]["at"].is_string() && entries[0]["actor"] == "admin");
    assert!(
        entries
            .as_array()
            .expect("array")
            .iter()
            .any(|e| e["action"] == "login.success")
    );
    for bad in ["0", "abc", "-1"] {
        assert_eq!(
            h.get(&t, &format!("/audit?limit={bad}")).await.0,
            400,
            "{bad}"
        );
    }
}

#[tokio::test]
async fn analytics_parameters_are_validated() {
    let h = start().await;
    let t = h.token().await;
    for query in [
        "/analytics/summary?window=2w",
        "/analytics/timeseries?window=",
        "/analytics/summary?site=Bad%20Site",
        "/analytics/requests?status=abc",
        "/analytics/requests?status=99",
        "/analytics/requests?blocked=maybe",
        "/analytics/requests?ip=nope",
        "/analytics/requests?method=GE%20T",
        "/analytics/requests?limit=0",
        "/analytics/bots?window=2w",
        "/analytics/bots?site=Bad%20Site",
        "/analytics/top",
        "/analytics/top?kind=nope",
        "/analytics/top?kind=paths&limit=0",
        "/analytics/top?kind=paths&limit=abc",
        "/analytics/top?kind=paths&window=2w",
        "/analytics/top?kind=paths&site=Bad%20Site",
    ] {
        assert_eq!(h.get(&t, query).await.0, 400, "{query}");
    }
}

#[tokio::test]
async fn analytics_endpoints_reflect_recorded_events() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([
        event("10.0.0.1", 200),
        event("10.0.0.2", 404),
        event("10.0.0.2", 500),
    ]);
    let (status, summary) = h.get(&t, "/analytics/summary?window=1h").await;
    assert_eq!(status, 200);
    assert_eq!(summary["requests"], 3);
    assert_eq!(summary["errors_4xx"], 1);
    assert_eq!(summary["errors_5xx"], 1);

    let (status, series) = h.get(&t, "/analytics/timeseries?window=15m").await;
    assert_eq!(status, 200);
    assert!(series["step_secs"].is_u64());
    assert!(series["points"].is_array());

    let (_, all) = h.get(&t, "/analytics/requests?limit=2").await;
    assert_eq!(all.as_array().map(Vec::len), Some(2));
    let (_, filtered) = h
        .get(&t, "/analytics/requests?status=404&ip=10.0.0.2")
        .await;
    assert_eq!(filtered.as_array().map(Vec::len), Some(1));
    assert_eq!(filtered[0]["status"], 404);
    let (_, none) = h.get(&t, "/analytics/requests?blocked=true").await;
    assert_eq!(none, json!([]));
}

#[tokio::test]
async fn analytics_requests_honour_the_site_filter() {
    let h = start().await;
    let t = h.token().await;
    let mut other = event("10.0.0.2", 200);
    other.site = "shop".into();
    h.ingest([event("10.0.0.1", 200), other]);
    let (_, blog) = h.get(&t, "/analytics/requests?site=blog").await;
    assert_eq!(blog.as_array().map(Vec::len), Some(1));
    assert_eq!(blog[0]["site"], "blog");
    let (_, ghost) = h.get(&t, "/analytics/requests?site=ghost").await;
    assert_eq!(ghost, json!([]));
    let (status, _) = h.get(&t, "/analytics/requests?site=Bad%20Id").await;
    assert_eq!(status, 400);
}

fn bot_event(ip: &str, class: &str, score: u8, signals: &str, ua: &str) -> LogEvent {
    LogEvent {
        bot_class: class.into(),
        bot_score: score,
        bot_signals: signals.into(),
        user_agent: ua.into(),
        ..event(ip, 200)
    }
}

// Events a millisecond apart and oldest first, each padded so the table grows quickly.
fn bulk(n: usize, pad: usize) -> impl Iterator<Item = LogEvent> {
    let start = now_ms() - 3_600_000;
    (0..n).map(move |i| LogEvent {
        ts_ms: start + i as i64,
        path: format!("/bulk/{i}/{}", "x".repeat(pad)),
        ..event("10.0.0.1", 200)
    })
}

fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut field) = (Vec::new(), Vec::new(), String::new());
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (true, _) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, _) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

// Data rows only; the header is checked separately by the tests that care about it.
async fn export_rows(h: &Harness, token: &str, query: &str) -> Vec<Vec<String>> {
    let res = h
        .get_raw(token, &format!("/analytics/export?{query}"))
        .await;
    assert_eq!(res.status().as_u16(), 200, "{query}");
    let mut rows = parse_csv(&res.text().await.expect("body"));
    assert!(!rows.is_empty(), "{query}");
    rows.remove(0);
    rows
}

fn count_of(section: &Value, key: &str) -> Option<u64> {
    section
        .as_array()?
        .iter()
        .find(|item| item["key"] == key)
        .and_then(|item| item["count"].as_u64())
}

#[tokio::test]
async fn bots_endpoint_reports_classes_signals_and_agents() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([
        bot_event("10.0.0.1", "human", 0, "", "Mozilla/5.0"),
        bot_event("10.0.0.2", "human", 10, "", "Mozilla/5.0"),
        bot_event("10.0.0.3", "crawler", 70, "ua_googlebot", "Googlebot/2.1"),
        bot_event(
            "10.0.0.4",
            "tool",
            85,
            "ua_curl,missing_accept_language",
            "curl/8",
        ),
    ]);
    let (status, bots) = h.get(&t, "/analytics/bots?window=1h").await;
    assert_eq!(status, 200, "{bots}");
    assert_eq!(bots["total_requests"], 4);
    assert_eq!(bots["bot_requests"], 2);
    assert_eq!(bots["bot_share_pct"].as_f64(), Some(50.0));
    assert_eq!(count_of(&bots["classes"], "human"), Some(2));
    assert_eq!(count_of(&bots["classes"], "crawler"), Some(1));
    assert_eq!(count_of(&bots["classes"], "tool"), Some(1));
    assert_eq!(count_of(&bots["signals"], "ua_curl"), Some(1));
    assert_eq!(
        count_of(&bots["signals"], "missing_accept_language"),
        Some(1)
    );
    assert_eq!(count_of(&bots["agents"], "curl/8"), Some(1));
    assert!(bots["score_buckets"].is_array());

    let (_, none) = h.get(&t, "/analytics/bots?site=ghost").await;
    assert_eq!(none["total_requests"], 0);
}

#[tokio::test]
async fn top_endpoint_ranks_every_kind() {
    let h = start().await;
    let t = h.token().await;
    let paths = ["/a", "/a", "/a", "/b"];
    h.ingest(paths.iter().map(|p| LogEvent {
        path: (*p).into(),
        ..event("10.0.0.1", 200)
    }));
    let (status, top) = h.get(&t, "/analytics/top?kind=paths&window=1h").await;
    assert_eq!(status, 200, "{top}");
    assert_eq!(top["items"][0]["key"], "/a");
    assert_eq!(top["items"][0]["count"], 3);
    assert_eq!(top["items"][1]["key"], "/b");
    let (_, hosts) = h.get(&t, "/analytics/top?kind=hosts").await;
    assert_eq!(hosts["items"][0]["key"], "a.example.com");
    assert_eq!(hosts["items"][0]["count"], 4);
    for kind in [
        "paths",
        "hosts",
        "referers",
        "agents",
        "content_types",
        "statuses",
        "ips",
        "languages",
    ] {
        let (status, body) = h.get(&t, &format!("/analytics/top?kind={kind}")).await;
        assert_eq!(status, 200, "{kind}");
        assert!(body["items"].is_array(), "{kind}");
    }
    let (_, one) = h.get(&t, "/analytics/top?kind=paths&limit=1").await;
    assert_eq!(one["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        h.get(&t, "/analytics/top?kind=paths&limit=5000").await.0,
        200
    );
    let (_, ghost) = h.get(&t, "/analytics/top?kind=paths&site=ghost").await;
    assert_eq!(ghost["items"], json!([]));
}

#[tokio::test]
async fn stats_endpoint_and_node_report_the_store() {
    let h = start().await;
    let t = h.token().await;
    let (_, empty) = h.get(&t, "/analytics/stats").await;
    assert_eq!(empty["rows"], 0);
    assert!(empty["oldest_ts_ms"].is_null());
    h.ingest([event("10.0.0.1", 200), event("10.0.0.2", 404)]);
    let (status, stats) = h.get(&t, "/analytics/stats").await;
    assert_eq!(status, 200, "{stats}");
    assert_eq!(stats["rows"], 2);
    assert!(stats["db_bytes"].as_u64().is_some_and(|n| n > 0));
    assert!(stats["oldest_ts_ms"].is_i64() && stats["newest_ts_ms"].is_i64());
    assert_eq!(stats["write_errors"], 0);
    assert_eq!(stats["retention_days"], 30);
    assert!(stats["max_bytes"].is_null());
    assert_eq!(stats["ingest_stalls"], 0);

    let (_, node) = h.get(&t, "/node").await;
    assert_eq!(node["analytics"]["rows"], 2);
    assert_eq!(node["name"], "test-node");
}

#[tokio::test]
async fn nothing_is_dropped_when_ingest_outpaces_the_writer() {
    let h = start().await;
    let t = h.token().await;
    let total = 50_000;
    h.ingest(bulk(total, 0));
    let (_, stats) = h.get(&t, "/analytics/stats").await;
    assert_eq!(stats["rows"], total);
    assert_eq!(stats["write_errors"], 0);
    let (_, summary) = h.get(&t, "/analytics/summary?window=24h").await;
    assert_eq!(summary["requests"], total);
}

#[tokio::test]
async fn without_a_size_cap_nothing_is_evicted() {
    let h = start().await;
    let total = 30_000;
    h.ingest(bulk(total, 500));
    h.state.analytics.prune(now_ms()).expect("prune");
    assert_eq!(h.state.analytics.stats().expect("stats").rows, total as u64);
}

#[tokio::test]
async fn with_a_size_cap_the_oldest_rows_go_first() {
    let h = start_with(|cfg| cfg.analytics_max_bytes = Some(8 * 1024 * 1024)).await;
    let total = 30_000;
    let mut first = i64::MAX;
    let mut last = 0;
    h.ingest(bulk(total, 500).inspect(|e| {
        first = first.min(e.ts_ms);
        last = last.max(e.ts_ms);
    }));
    h.state.analytics.prune(now_ms()).expect("prune");
    let stats = h.state.analytics.stats().expect("stats");
    assert!(stats.rows > 0 && stats.rows < total as u64, "{stats:?}");
    assert_eq!(stats.newest_ts_ms, Some(last));
    assert!(stats.oldest_ts_ms > Some(first), "{stats:?}");
}

#[tokio::test]
async fn export_csv_has_a_header_quoting_and_formula_protection() {
    let h = start().await;
    let t = h.token().await;
    let risky = LogEvent {
        path: "/a,b\"c".into(),
        user_agent: "=cmd|' /C calc'!A0".into(),
        referer: "line1\nline2".into(),
        ..event("10.0.0.1", 200)
    };
    h.ingest([risky, event("10.0.0.2", 404), event("10.0.0.3", 500)]);

    let res = h.get_raw(&t, "/analytics/export?kind=requests").await;
    assert_eq!(res.status().as_u16(), 200);
    let headers = res.headers().clone();
    assert_eq!(headers["content-type"], "text/csv; charset=utf-8");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["cache-control"], "no-store");
    let disposition = headers["content-disposition"].to_str().expect("ascii");
    assert!(
        disposition.starts_with("attachment; filename=\"cite-requests-all-")
            && disposition.ends_with(".csv\""),
        "{disposition}"
    );
    let body = res.text().await.expect("body");
    assert!(body.starts_with("timestamp,ts_ms,client_ip,"));
    assert!(body.contains("\r\n"));

    let rows = parse_csv(&body);
    assert_eq!(rows.len(), 4);
    let header = &rows[0];
    let names: Vec<&str> = header.iter().map(String::as_str).collect();
    assert_eq!(names, cite_store::REQUEST_COLUMNS.to_vec());
    assert!(rows[1..].iter().all(|r| r.len() == header.len()));
    let col = |name: &str| header.iter().position(|c| c == name).expect(name);
    assert_eq!(rows[1][col("path")], "/a,b\"c");
    assert_eq!(rows[1][col("user_agent")], "'=cmd|' /C calc'!A0");
    assert_eq!(rows[1][col("referer")], "line1\nline2");
    assert_eq!(rows[2][col("status")], "404");
    assert_eq!(rows[3][col("client_ip")], "10.0.0.3");
    assert_eq!(rows[1][col("site")], "blog");
}

#[tokio::test]
async fn export_file_names_carry_the_site_and_the_format() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([event("10.0.0.1", 200)]);
    let res = h
        .get_raw(
            &t,
            "/analytics/export?format=ndjson&site=blog&kind=top&top=ips",
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["content-type"], "application/x-ndjson");
    let disposition = res.headers()["content-disposition"]
        .to_str()
        .expect("ascii");
    assert!(
        disposition.starts_with("attachment; filename=\"cite-top-ips-blog-")
            && disposition.ends_with(".ndjson\""),
        "{disposition}"
    );
}

#[tokio::test]
async fn export_ndjson_has_one_json_object_per_row() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([
        bot_event("10.0.0.1", "crawler", 70, "ua_googlebot", "Googlebot/2.1"),
        event("10.0.0.2", 404),
        event("10.0.0.3", 500),
    ]);
    let res = h
        .get_raw(&t, "/analytics/export?kind=requests&format=ndjson")
        .await;
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    let body = res.text().await.expect("body");
    let lines: Vec<Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).expect("json line"))
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["bot_class"], "crawler");
    assert_eq!(lines[0]["bot_score"], 70);
    assert_eq!(lines[0]["bot_signals"], "ua_googlebot");
    assert_eq!(lines[1]["status"], 404);
    assert_eq!(lines[2]["client_ip"], "10.0.0.3");
}

#[tokio::test]
async fn export_filters_narrow_the_rows() {
    let h = start().await;
    let t = h.token().await;
    let mk =
        |ip: &str, status: u16, host: &str, method: &str, path: &str, class: &str, score: u8| {
            LogEvent {
                host: host.into(),
                method: method.into(),
                path: path.into(),
                bot_class: class.into(),
                bot_score: score,
                ..event(ip, status)
            }
        };
    let mut shop = mk(
        "10.0.0.3",
        500,
        "a.example.com",
        "GET",
        "/static/x.css",
        "crawler",
        70,
    );
    shop.site = "shop".into();
    h.ingest([
        mk(
            "10.0.0.1",
            200,
            "a.example.com",
            "GET",
            "/api/users",
            "human",
            0,
        ),
        mk(
            "10.0.0.2",
            404,
            "b.example.com",
            "POST",
            "/api/orders",
            "tool",
            80,
        ),
        shop,
        mk("10.0.0.4", 301, "b.example.com", "GET", "/old", "human", 5),
    ]);
    let soon = now_ms() + 60_000;
    let cases: [(String, usize); 20] = [
        ("".into(), 4),
        ("status_min=400".into(), 2),
        ("status_min=400&status_max=499".into(), 1),
        ("status_max=299".into(), 1),
        ("bot_class=crawler".into(), 1),
        ("bot_class=human".into(), 2),
        ("min_bot_score=70".into(), 2),
        ("host=a.example.com".into(), 2),
        ("path_prefix=/api".into(), 2),
        ("client_ip=10.0.0.2".into(), 1),
        ("method=post".into(), 1),
        ("site=shop".into(), 1),
        ("site=ghost".into(), 0),
        ("limit=2".into(), 2),
        ("status_min=400&bot_class=tool".into(), 1),
        (format!("from={soon}"), 0),
        (format!("to={}", now_ms() - 60_000), 0),
        (format!("from={}&to={soon}", now_ms() - 60_000), 4),
        (
            "from=1970-01-01T00:00:00Z&to=1970-01-01T00:00:01Z".into(),
            0,
        ),
        ("from=1970-01-01T00:00:00Z".into(), 4),
    ];
    for (query, want) in cases {
        let rows = export_rows(&h, &t, &query).await;
        assert_eq!(rows.len(), want, "{query}");
    }
}

#[tokio::test]
async fn export_supports_hourly_bots_and_top_kinds() {
    let h = start().await;
    let t = h.token().await;
    let paths = ["/a", "/a", "/b"];
    h.ingest(paths.iter().map(|p| LogEvent {
        path: (*p).into(),
        bot_class: "human".into(),
        ..event("10.0.0.1", 200)
    }));

    let hourly = export_rows(&h, &t, "kind=hourly").await;
    assert!(!hourly.is_empty());
    assert!(
        hourly
            .iter()
            .all(|r| r.len() == cite_store::HOURLY_COLUMNS.len())
    );
    let requests: u64 = hourly
        .iter()
        .map(|r| r[3].parse::<u64>().expect("count"))
        .sum();
    assert_eq!(requests, 3);

    let bots = export_rows(&h, &t, "kind=bots").await;
    assert!(
        bots.iter()
            .any(|r| r[..3] == ["summary", "total_requests", "3"]),
        "{bots:?}"
    );

    let top = export_rows(&h, &t, "kind=top&top=paths").await;
    assert_eq!(top[0][..2], ["/a", "2"]);
    assert_eq!(top[1][..2], ["/b", "1"]);
}

#[tokio::test]
async fn export_parameters_are_validated() {
    let h = start().await;
    let t = h.token().await;
    for query in [
        "kind=everything",
        "kind=top",
        "kind=top&top=nope",
        "kind=bots&top=paths",
        "format=xml",
        "from=yesterday",
        "from=2000&to=1000",
        "site=Bad%20Site",
        "status_min=abc",
        "status_min=99",
        "status_max=600",
        "status_min=500&status_max=400",
        "bot_class=robot",
        "min_bot_score=101",
        "min_bot_score=abc",
        "client_ip=nope",
        "method=GE%20T",
        "limit=0",
        "limit=-3",
        "limit=1000001",
        "limit=many",
    ] {
        let (status, body) = h
            .call(
                Method::GET,
                Some(&t),
                &format!("/analytics/export?{query}"),
                None,
            )
            .await;
        assert_eq!(status, 400, "{query}");
        assert!(
            body["error"].as_str().is_some_and(|m| !m.is_empty()),
            "{query}"
        );
    }
}

#[tokio::test]
async fn at_most_two_exports_run_at_once() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([event("10.0.0.1", 200)]);
    let held = Arc::clone(&h.state.exports)
        .try_acquire_many_owned(2)
        .expect("both permits");
    let (status, body) = h
        .call(Method::GET, Some(&t), "/analytics/export", None)
        .await;
    assert_eq!(status, 429);
    assert!(body["error"].is_string());
    drop(held);
    assert_eq!(export_rows(&h, &t, "").await.len(), 1);

    let one = Arc::clone(&h.state.exports)
        .try_acquire_owned()
        .expect("one permit");
    assert_eq!(export_rows(&h, &t, "").await.len(), 1);
    drop(one);
    for _ in 0..3 {
        assert_eq!(export_rows(&h, &t, "").await.len(), 1);
    }
    for _ in 0..100 {
        if h.state.exports.available_permits() == MAX_EXPORTS {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("finished exports did not return their permits");
}

#[tokio::test]
async fn abandoning_a_download_stops_the_export_and_frees_its_slot() {
    let h = start().await;
    let t = h.token().await;
    h.ingest(bulk(50_000, 200));
    let res = h.get_raw(&t, "/analytics/export?kind=requests").await;
    assert_eq!(res.status().as_u16(), 200);
    drop(res);
    for _ in 0..200 {
        if h.state.exports.available_permits() == MAX_EXPORTS {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("an abandoned export kept its slot");
}

#[tokio::test]
async fn exports_are_audited_with_the_filters_used() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([event("10.0.0.1", 500)]);
    export_rows(&h, &t, "site=blog&status_min=500&bot_class=human").await;
    let rejected = h.get_raw(&t, "/analytics/export?status_min=abc").await;
    assert_eq!(rejected.status().as_u16(), 400);
    let (_, entries) = h.get(&t, "/audit?limit=50").await;
    let exports: Vec<&Value> = entries
        .as_array()
        .expect("array")
        .iter()
        .filter(|e| e["action"] == "analytics.export")
        .collect();
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0]["actor"], "admin");
    let detail = exports[0]["detail"].as_str().expect("detail");
    for part in [
        "kind=requests",
        "format=csv",
        "site=\"blog\"",
        "bot_class=\"human\"",
        "status_min=500",
    ] {
        assert!(detail.contains(part), "{detail}");
    }
}

#[tokio::test]
async fn analytics_routes_share_the_same_auth_rules() {
    let h = start().await;
    let session = h.token().await;
    let (_, created) = h.post(&session, "/tokens", json!({ "name": "ci" })).await;
    let api = created["token"].as_str().expect("token").to_string();
    h.ingest([event("10.0.0.1", 200)]);
    for path in [
        "/analytics/summary",
        "/analytics/timeseries",
        "/analytics/requests",
        "/analytics/bots",
        "/analytics/top?kind=paths",
        "/analytics/stats",
        "/analytics/export",
    ] {
        let anonymous = h.http.get(h.url(path)).send().await.expect("request");
        assert_eq!(anonymous.status().as_u16(), 401, "{path}");
        assert_eq!(anonymous.headers()["www-authenticate"], "Bearer");
        let (garbage, _) = h.get("not-a-token", path).await;
        assert_eq!(garbage, 401, "{path}");
        assert_eq!(
            h.get_raw(&session, path).await.status().as_u16(),
            200,
            "{path}"
        );
        assert_eq!(h.get_raw(&api, path).await.status().as_u16(), 200, "{path}");
    }
}

#[tokio::test]
async fn reload_and_config_endpoints_agree() {
    let h = start().await;
    let t = h.token().await;
    // With no HAProxy running the reload may be refused; both outcomes keep a consistent shape.
    let (status, body) = h.post(&t, "/haproxy/reload", json!({})).await;
    assert!(status == 200 || status == 503, "{status} {body}");
    if status == 200 {
        assert_eq!(body["ok"], true);
        assert!(body["config_hash"].is_string());
        let res = h
            .http
            .get(h.url("/haproxy/config"))
            .bearer_auth(&t)
            .send()
            .await
            .expect("request");
        assert_eq!(res.status().as_u16(), 200);
        let content_type = res.headers()["content-type"]
            .to_str()
            .expect("header")
            .to_string();
        assert!(content_type.starts_with("text/plain"));
        assert!(!res.text().await.expect("body").is_empty());
    } else {
        assert!(body["error"].is_string());
    }
}

// Counts reload attempts and confirmed loads; the runtime socket reports a new pid per confirmed load.
struct FakeHaproxy {
    master: String,
    runtime: String,
    attempts: Arc<std::sync::atomic::AtomicU64>,
}

async fn fake_haproxy(refuse_first: bool) -> FakeHaproxy {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let attempts = Arc::new(AtomicU64::new(0));
    let loaded = Arc::new(AtomicU64::new(0));
    let master = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let runtime = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addrs = (
        master.local_addr().expect("addr").to_string(),
        runtime.local_addr().expect("addr").to_string(),
    );
    let (count, ok) = (attempts.clone(), loaded.clone());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = master.accept().await {
            let mut line = String::new();
            let _ = BufReader::new(&mut stream).read_line(&mut line).await;
            let n = count.fetch_add(1, Ordering::SeqCst) + 1;
            let reply = if refuse_first && n == 1 {
                "Success=0\n--\n[ALERT] refused\n"
            } else {
                ok.fetch_add(1, Ordering::SeqCst);
                "Success=1\n--\nok\n"
            };
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = runtime.accept().await {
            let mut line = String::new();
            let _ = BufReader::new(&mut stream).read_line(&mut line).await;
            let reply = format!("Pid: {}\n", 100 + loaded.load(Ordering::SeqCst));
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    FakeHaproxy {
        master: addrs.0,
        runtime: addrs.1,
        attempts,
    }
}

#[tokio::test]
async fn every_reload_request_reaches_haproxy_even_for_an_unchanged_config() {
    let fake = fake_haproxy(false).await;
    let (master, runtime) = (fake.master.clone(), fake.runtime.clone());
    let h = start_with(move |cfg| {
        cfg.master_addr = master;
        cfg.runtime_addr = runtime;
    })
    .await;
    let t = h.token().await;
    for expected in 1..=2u64 {
        let (status, body) = h.post(&t, "/haproxy/reload", json!({})).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["reloaded"], true);
        let seen = fake.attempts.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(seen, expected);
    }
}

#[tokio::test]
async fn a_reload_of_an_absent_haproxy_is_reported_as_unavailable() {
    let h = start().await;
    let t = h.token().await;
    let (status, body) = h.post(&t, "/haproxy/reload", json!({})).await;
    assert_eq!(status, 503, "{body}");
}

#[tokio::test]
async fn a_refused_change_is_a_400_and_the_old_config_is_loaded_again() {
    let fake = fake_haproxy(true).await;
    let (master, runtime) = (fake.master.clone(), fake.runtime.clone());
    let h = start_with(move |cfg| {
        cfg.master_addr = master;
        cfg.runtime_addr = runtime;
    })
    .await;
    let t = h.token().await;
    let (status, body) = h.post(&t, "/pages", page_json("down")).await;
    assert_eq!(status, 400, "{body}");
    assert!(h.state.store.config().pages.is_empty());
    assert_eq!(fake.attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn failed_apply_restores_the_previous_configuration() {
    if rustix::process::getuid().is_root() {
        return;
    }
    let h = start().await;
    let t = h.token().await;
    // A read-only HAProxy directory makes the apply step fail for any non-root user.
    let dir = h.state.cfg.haproxy_dir.clone();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("lock dir");
    let (status, body) = h.post(&t, "/pages", page_json("down")).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("unlock dir");
    assert_eq!(status, 503, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("haproxy"))
    );
    assert_eq!(h.get(&t, "/pages").await.1, json!([]));
    assert!(h.state.store.config().pages.is_empty());
}

#[tokio::test]
async fn loopback_peers_outside_the_allowlist_reach_only_healthz() {
    // The test client is 127.0.0.1, so this allowlist leaves only the loopback exception.
    let h = start_with(|cfg| {
        cfg.allow = IpAllowlist::parse("10.0.0.0/8").expect("allowlist");
    })
    .await;
    let health = h.http.get(h.url("/healthz")).send().await.expect("request");
    assert_eq!(health.status().as_u16(), 200);
    let node = h
        .http
        .get(h.url("/node"))
        .bearer_auth("cite_anything")
        .send()
        .await
        .expect("request");
    assert_eq!(node.status().as_u16(), 404);
    assert_eq!(node.headers()["cache-control"], "no-store");
    let login = h.login_with("admin", PASSWORD, &current_code()).await;
    assert_eq!(login.status().as_u16(), 404);
}

#[tokio::test]
async fn healthcheck_passes_against_a_live_server_and_fails_without_one() {
    let h = start().await;
    healthcheck(&h.listen_cfg()).await.expect("healthy");

    let spare = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let dead = spare.local_addr().expect("addr");
    drop(spare);
    let mut cfg = h.listen_cfg();
    cfg.listen = dead;
    assert!(healthcheck(&cfg).await.is_err());
}

#[tokio::test]
async fn healthcheck_and_server_agree_on_tls() {
    let h = start_with(|cfg| cfg.tls = true).await;
    healthcheck(&h.listen_cfg()).await.expect("tls healthcheck");

    let mut plain = h.listen_cfg();
    plain.tls = false;
    assert!(healthcheck(&plain).await.is_err());
}

#[tokio::test]
async fn a_hand_written_http_1_1_request_is_served() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let h = start().await;
    let mut stream = TcpStream::connect(h.addr).await.expect("connect");
    let request = b"GET /api/v1/healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await.expect("write");
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.expect("read");
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    let text = String::from_utf8_lossy(&reply).to_ascii_lowercase();
    assert!(text.contains("cache-control: no-store"));
    assert!(text.contains("x-content-type-options: nosniff"));
}

// A password pasted into the username field must not reach the audit log, so only whether the name matched is recorded.
#[tokio::test]
async fn failed_login_audit_records_only_whether_the_username_matched() {
    let h = start().await;
    let code = current_code();
    let pasted = "hunter2-pasted-into-the-username-field";
    assert_eq!(
        h.login_with(pasted, "wrong password here", &code)
            .await
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        h.login_with("admin", "wrong password here", &code)
            .await
            .status()
            .as_u16(),
        401
    );
    let tail = h.state.store.audit_tail(5).await;
    let details: Vec<&str> = tail
        .iter()
        .filter(|e| e.action == "login.failure")
        .map(|e| e.detail.as_str())
        .collect();
    assert_eq!(details.len(), 2);
    assert!(details.iter().all(|d| !d.contains(pasted)));
    assert!(details.contains(&"peer=127.0.0.1 username_matched=false"));
    assert!(details.contains(&"peer=127.0.0.1 username_matched=true"));
}

// Parallel guesses race the limiter: exactly the limit may be processed and audited, and the rest are turned away.
#[tokio::test]
async fn concurrent_failed_logins_stop_at_the_per_client_limit() {
    let h = start().await;
    let code = current_code();
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let http = h.http.clone();
        let url = h.url("/auth/login");
        let body = json!({ "username": "admin", "password": "wrong password here", "totp": code });
        tasks.push(tokio::spawn(async move {
            http.post(url)
                .json(&body)
                .send()
                .await
                .expect("login request")
                .status()
                .as_u16()
        }));
    }
    let mut rejected = 0;
    let mut limited = 0;
    for task in tasks {
        match task.await.expect("task") {
            401 => rejected += 1,
            429 => limited += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(rejected, 5);
    assert_eq!(limited, 35);
    let failures = h
        .state
        .store
        .audit_tail(100)
        .await
        .iter()
        .filter(|e| e.action == "login.failure")
        .count();
    assert_eq!(failures, 5);
}

// A leaked API token must not be able to mint or revoke tokens, or it could outlive the session that created it.
#[tokio::test]
async fn api_tokens_cannot_manage_api_tokens() {
    let h = start().await;
    let session = h.token().await;
    let (_, created) = h.post(&session, "/tokens", json!({ "name": "ci" })).await;
    let api = created["token"].as_str().expect("token").to_string();
    let id = created["id"].as_str().expect("id").to_string();

    assert_eq!(h.get(&api, "/tokens").await.0, 403);
    assert_eq!(
        h.post(&api, "/tokens", json!({ "name": "evil" })).await.0,
        403
    );
    assert_eq!(h.delete(&api, &format!("/tokens/{id}")).await.0, 403);
    assert_eq!(h.get(&api, "/node").await.0, 200);
    let (_, listed) = h.get(&session, "/tokens").await;
    assert_eq!(listed.as_array().expect("array").len(), 1);
}
