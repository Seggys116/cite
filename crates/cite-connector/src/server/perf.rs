// Run with: cargo test -p cite-connector --release perf_api -- --ignored --nocapture
use std::time::Instant;

use cite_edge::analytics::Analytics;
use cite_edge::auth::{Credentials, hash_password};
use cite_edge::model::LogEvent;
use cite_edge::totp;
use reqwest::Client;
use serde_json::{Value, json};

use super::*;
use crate::store::testing::test_config;

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD: &str = "correct horse battery";

fn percentile(v: &mut [f64], p: usize) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[(v.len() * p / 100).min(v.len() - 1)]
}

fn report(label: &str, mut v: Vec<f64>) {
    let p50 = percentile(&mut v, 50);
    let p99 = percentile(&mut v, 99);
    println!("{label}: p50 {p50:.2} ms p99 {p99:.2} ms");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn perf_api_500_sites() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(dir.path());
    let store = Store::open(&cfg).await.expect("open");
    let hash = hash_password(PASSWORD).expect("hash");
    let creds = Credentials {
        username: "admin".into(),
        password_hash: hash,
        totp_secret: SECRET.into(),
        totp_last_step: 0,
    };
    store.set_credentials(creds).await.expect("credentials");
    let haproxy = Arc::new(Haproxy::new(&cfg));
    let deployer = Arc::new(Deployer::new(
        Arc::clone(&store),
        Arc::clone(&haproxy),
        None,
    ));
    let retention = store.config().settings.retention.clone();
    let analytics = Arc::new(StdMutex::new(Analytics::new(retention)));
    let state = Inner::new(
        cfg,
        Arc::clone(&store),
        haproxy,
        deployer,
        None,
        analytics.clone(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(serve(listener, state, None));
    let http = Client::new();
    let url = |path: &str| format!("http://{addr}/api/v1{path}");
    let code = totp::code_at(SECRET, now_unix()).expect("code");
    let login: Value = http
        .post(url("/auth/login"))
        .json(&json!({ "username": "admin", "password": PASSWORD, "totp": code }))
        .send()
        .await
        .expect("login")
        .json()
        .await
        .expect("login body");
    let token = login["token"].as_str().expect("token").to_string();

    let sites: Vec<Value> = (0..500)
        .map(|i| {
            json!({
                "id": format!("s{i}"), "name": "Site", "hosts": [format!("s{i}.example.com")],
                "blue": { "targets": [{ "addr": "10.0.0.1:8080" }] },
                "green": { "targets": [], "label": null }, "active": "blue"
            })
        })
        .collect();
    // Seeded through the store directly so the timed requests measure only the API paths.
    store
        .update_detailed("perf", "seed", "500 sites", |cfg| {
            cfg.sites = serde_json::from_value(Value::Array(sites.clone()))?;
            Ok(())
        })
        .await
        .expect("seed");

    let mut put = Vec::new();
    for i in 0..30 {
        let mut body = sites[7].clone();
        body["blue"]["targets"][0]["weight"] = json!(50 + i);
        let t = Instant::now();
        let res = http
            .put(url("/sites/s7"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .expect("put");
        let status = res.status();
        assert!(status.is_success(), "{status}");
        put.push(t.elapsed().as_secs_f64() * 1e3);
    }
    report("PUT /sites/s7 (validate, render, persist, apply)", put);

    {
        let mut a = analytics.lock().expect("lock");
        // Timestamps spread over 50 minutes so the windowed queries have to read many buckets.
        let now = now_ms();
        for i in 0..300_000i64 {
            a.record(LogEvent {
                ts_ms: now - (i % 3_000_000),
                client_ip: format!("203.0.{}.{}", (i / 250) % 250, i % 250),
                host: format!("s{}.example.com", i % 500),
                method: "GET".into(),
                path: format!("/p/{}", i % 997),
                query_len: 0,
                status: 200,
                bytes_in: 300,
                bytes_out: 2000,
                total_ms: 5 + (i % 90) as u32,
                user_agent: "Mozilla/5.0".into(),
                referer: String::new(),
                content_type: "text/html".into(),
                backend: format!("be_s{}_blue", i % 500),
                server: "t1".into(),
                site: format!("s{}", i % 500),
                blocked: None,
            });
        }
    }
    for path in [
        "/sites",
        "/analytics/summary?window=24h",
        "/analytics/summary?window=7d",
        "/analytics/timeseries?window=24h",
        "/analytics/requests?limit=100",
    ] {
        let mut v = Vec::new();
        for _ in 0..200 {
            let t = Instant::now();
            let res = http
                .get(url(path))
                .bearer_auth(&token)
                .send()
                .await
                .expect("get");
            let status = res.status();
            let _ = res.bytes().await.expect("body");
            assert!(status.is_success(), "{path} {status}");
            v.push(t.elapsed().as_secs_f64() * 1e3);
        }
        report(&format!("GET {path}"), v);
    }
    println!(
        "analytics retained: {} MiB",
        analytics.lock().expect("lock").retained_bytes() >> 20
    );
    task.abort();
}

fn now_ms() -> i64 {
    i64::try_from(now_unix()).expect("clock") * 1000
}
