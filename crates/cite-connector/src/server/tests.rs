use std::os::unix::fs::PermissionsExt;
use std::sync::OnceLock;

use cite_edge::auth::{Credentials, hash_password};
use cite_edge::model::{LogEvent, Site};
use cite_edge::totp;
use reqwest::{Client, Method};
use serde_json::{Value, json};

use super::*;
use crate::store::testing::test_config;

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
    let retention = store.config().settings.retention.clone();
    let analytics = Arc::new(StdMutex::new(Analytics::new(retention)));
    let acceptor = if cfg.tls {
        tls::ensure(&cfg).expect("tls material");
        Some(tls::load_acceptor(&cfg.tls_dir).expect("acceptor"))
    } else {
        None
    };
    let state = Inner::new(cfg, store, haproxy, deployer, None, analytics);
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
async fn settings_update_pushes_retention_into_analytics() {
    let h = start().await;
    let t = h.token().await;
    lock_std(&h.state.analytics).record(event("10.1.2.3", 200));
    let (_, before) = h.get(&t, "/analytics/requests").await;
    assert_eq!(before[0]["client_ip"], "10.1.2.3");

    let (_, mut settings) = h.get(&t, "/settings").await;
    settings["retention"]["store_client_ips"] = json!(false);
    assert_eq!(h.put(&t, "/settings", settings).await.0, 200);
    let (_, after) = h.get(&t, "/analytics/requests").await;
    assert_eq!(after[0]["client_ip"], "");
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
    ] {
        assert_eq!(h.get(&t, query).await.0, 400, "{query}");
    }
}

#[tokio::test]
async fn analytics_endpoints_reflect_recorded_events() {
    let h = start().await;
    let t = h.token().await;
    {
        let mut analytics = lock_std(&h.state.analytics);
        analytics.record(event("10.0.0.1", 200));
        analytics.record(event("10.0.0.2", 404));
        analytics.record(event("10.0.0.2", 500));
    }
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
    {
        let mut analytics = lock_std(&h.state.analytics);
        analytics.record(event("10.0.0.1", 200));
        let mut other = event("10.0.0.2", 200);
        other.site = "shop".into();
        analytics.record(other);
    }
    let (_, blog) = h.get(&t, "/analytics/requests?site=blog").await;
    assert_eq!(blog.as_array().map(Vec::len), Some(1));
    assert_eq!(blog[0]["site"], "blog");
    let (_, ghost) = h.get(&t, "/analytics/requests?site=ghost").await;
    assert_eq!(ghost, json!([]));
    let (status, _) = h.get(&t, "/analytics/requests?site=Bad%20Id").await;
    assert_eq!(status, 400);
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
