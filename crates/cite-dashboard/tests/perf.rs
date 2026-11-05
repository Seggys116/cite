// Run with: cargo test -p cite-dashboard --release --test perf -- --ignored --nocapture
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use cite_client::{DashboardConfig, MemoryTokenStore, NodeConfig, TokenStore};
use cite_dashboard::{AppState, Settings, router};
use cite_edge::auth::{Credentials, hash_password};
use cite_edge::totp;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD: &str = "correct horse battery";
// Slow fake nodes make the summary timing show whether the 20 node calls run concurrently or one after another.
const NODE_DELAY: Duration = Duration::from_millis(50);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn spawn_node() -> String {
    let app = Router::new()
        .route(
            "/api/v1/node",
            get(|| async {
                tokio::time::sleep(NODE_DELAY).await;
                Json(json!({ "name": "fake", "version": "1", "uptime_secs": 7, "haproxy": { "running": true }, "sites": 0, "firewall_rules": 0 }))
            }),
        )
        .route(
            "/api/v1/analytics/summary",
            get(|| async {
                tokio::time::sleep(NODE_DELAY).await;
                Json(json!({ "requests": 1 }))
            }),
        )
        .route(
            "/api/v1/sites",
            get(|| async { Json(json!([])) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, usize, Vec<(String, String)>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let payload = match body {
        Some(b) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&b).expect("encode"))
        }
        None => Body::empty(),
    };
    let mut req = builder.body(payload).expect("request");
    // oneshot skips the listener, so the peer address handlers read from ConnectInfo is inserted by hand.
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 5555))));
    let resp = app.clone().oneshot(req).await.expect("response");
    let (parts, body) = resp.into_parts();
    let len = to_bytes(body, usize::MAX).await.expect("body").len();
    let heads = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    (parts.status, len, heads)
}

fn report(label: &str, mut v: Vec<f64>) {
    v.sort_by(|a, b| a.total_cmp(b));
    println!(
        "{label}: p50 {:.3} ms p99 {:.3} ms",
        v[v.len() / 2],
        v[v.len() * 99 / 100]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn dashboard_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = DashboardConfig {
        admin: Some(Credentials {
            username: "admin".into(),
            password_hash: hash_password(PASSWORD).expect("hash"),
            totp_secret: SECRET.into(),
            totp_last_step: 0,
        }),
        ..DashboardConfig::default()
    };
    let store = Arc::new(MemoryTokenStore::new());
    for i in 0..20 {
        let url = spawn_node().await;
        let name = format!("node-{i}");
        config.nodes.push(NodeConfig {
            name: name.clone(),
            url,
            ca_pem: None,
            token_ref: name.clone(),
            insecure_http: false,
        });
        store.set(&name, "tok").expect("token");
    }
    let mut vars: HashMap<String, String> = HashMap::new();
    vars.insert(
        "CITE_DASHBOARD_CONFIG".into(),
        dir.path().join("dashboard.json").display().to_string(),
    );
    let started = Instant::now();
    let settings = Settings::from_env_map(&vars).expect("settings");
    let state = AppState::new(settings, config, store as Arc<dyn TokenStore>);
    let app = router(state);
    println!(
        "state and router construction: {:.2} ms",
        started.elapsed().as_secs_f64() * 1e3
    );

    let code = totp::code_at(SECRET, now()).expect("code");
    let (status, _, heads) = {
        let body = json!({ "username": "admin", "password": PASSWORD, "totp": code });
        call(&app, Method::POST, "/api/v1/session", &[], Some(body)).await
    };
    assert_eq!(status, StatusCode::OK);
    let cookie = heads
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap_or("").to_string())
        .expect("cookie");
    let session = [("cookie", cookie.as_str())];

    let mut v = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        let (status, _, _) = call(&app, Method::GET, "/api/v1/nodes/summary", &session, None).await;
        assert_eq!(status, StatusCode::OK);
        v.push(t.elapsed().as_secs_f64() * 1e3);
    }
    report("GET /nodes/summary, 20 nodes x 50 ms", v);

    let mut v = Vec::new();
    for _ in 0..500 {
        let t = Instant::now();
        let (status, _, _) = call(
            &app,
            Method::GET,
            "/api/v1/nodes/node-3/sites",
            &session,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        v.push(t.elapsed().as_secs_f64() * 1e3);
    }
    report("proxy GET /nodes/node-3/sites (node answers instantly)", v);

    let mut v = Vec::new();
    for _ in 0..2000 {
        let t = Instant::now();
        let (status, len, _) = call(&app, Method::GET, "/app.css", &[], None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(len > 1000);
        v.push(t.elapsed().as_secs_f64() * 1e3);
    }
    report("static /app.css", v);
}
