#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use cite_core::schema::Rendering;
use cite_core::{
    Desired, DesiredAction, ExecutorConfig, Health, HealthExpect, Outcome, ReleaseManifest,
    RuntimeKind, SCHEMA_VERSION, Slot, SlotState, write_desired, write_release,
};
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tempfile::tempdir;

use crate::spawn;

fn next_port_base() -> u16 {
    static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    // Stay below the kernel ephemeral ranges so a released port is not handed to another socket.
    const LOW: u32 = 20_000;
    const PAIRS: u32 = 6_000;
    let seed = std::process::id().wrapping_mul(7_919);
    let bindable = |port: u16| std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok();
    loop {
        let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let port = u16::try_from(LOW + seed.wrapping_add(n) % PAIRS * 2).unwrap();
        if bindable(port) && bindable(port + 1) {
            return port;
        }
    }
}

fn base_env(data: &Path, listen: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("CITE_LISTEN".into(), listen.into());
    env.insert("CITE_DATA_DIR".into(), data.display().to_string());
    env.insert(
        "CITE_RELEASES_DIR".into(),
        data.join("releases").display().to_string(),
    );
    env.insert(
        "CITE_CONTROL_DIR".into(),
        data.join("control").display().to_string(),
    );
    env.insert(
        "CITE_STATUS_DIR".into(),
        data.join("status").display().to_string(),
    );
    env.insert(
        "CITE_RUNTIME_ENV_FILE".into(),
        data.join("runtime.env").display().to_string(),
    );
    env.insert("CITE_PORT_BASE".into(), next_port_base().to_string());
    env.insert("CITE_WATCH".into(), "5s".into());
    env.insert("CITE_WARM_GRACE".into(), "30s".into());
    env.insert("CITE_CRASH_LIMIT".into(), "3".into());
    env.insert("CITE_CRASH_WINDOW".into(), "1m".into());
    env.insert("CITE_RUNTIME".into(), "node".into());
    env.insert("CITE_NODE".into(), "22".into());
    env
}

fn config_from(data: &Path, listen: &str) -> ExecutorConfig {
    let env = base_env(data, listen);
    let _ = std::fs::write(data.join("runtime.env"), "");
    ExecutorConfig::load_from(&env, None).unwrap()
}

fn sample_static(slot: Slot, release_id: &str) -> ReleaseManifest {
    ReleaseManifest {
        v: SCHEMA_VERSION,
        release_id: release_id.to_string(),
        slot,
        sha: "a".repeat(40),
        branch: "main".into(),
        commit_message: "hi".into(),
        commit_author: "dev".into(),
        built_at: "2026-01-01T00:00:00Z".into(),
        rendering: Rendering::Static,
        runtime: RuntimeKind::Node,
        node_major: "22".into(),
        start_argv: vec![],
        port_env: "PORT".into(),
        health: Health {
            path: "/index.html".into(),
            expect: HealthExpect::Non2xxOk,
            timeout_s: 5,
            consecutive: 1,
        },
        spa_fallback: Some("index.html".into()),
        root: "app".into(),
        bytes: 10,
        file_count: 1,
        tree_sha256: "b".repeat(64),
    }
}

fn sample_ssr(slot: Slot, release_id: &str) -> ReleaseManifest {
    let mut m = sample_static(slot, release_id);
    m.rendering = Rendering::Ssr;
    m.start_argv = vec!["node".into(), "server.js".into()];
    m.health.path = "/".into();
    m.spa_fallback = None;
    m
}

fn seal_static(data: &Path, slot: Slot, release_id: &str, files: &[(&str, &[u8])]) {
    let slot_dir = data.join("releases").join(slot.as_str());
    let app = slot_dir.join("app");
    std::fs::create_dir_all(&app).unwrap();
    for (name, body) in files {
        let path = app.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }
    let manifest = sample_static(slot, release_id);
    write_release(&slot_dir.join("release.json"), &manifest).unwrap();
}

fn write_desired_action(
    data: &Path,
    generation: u64,
    live: Slot,
    action: DesiredAction,
    evict: Option<Slot>,
) {
    write_desired_grace(data, generation, live, action, evict, 30);
}

fn write_desired_grace(
    data: &Path,
    generation: u64,
    live: Slot,
    action: DesiredAction,
    evict: Option<Slot>,
    warm_grace_s: u64,
) {
    let desired = Desired {
        v: SCHEMA_VERSION,
        generation,
        live_slot: live,
        action,
        evict_slot: evict,
        warm_grace_s,
        restart_nonce: String::new(),
        written_at: "2026-01-01T00:00:00Z".into(),
    };
    std::fs::create_dir_all(data.join("control")).unwrap();
    write_desired(&data.join("control/desired.json"), &desired).unwrap();
}

async fn http_once(
    addr: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, http::HeaderMap, Bytes) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = Request::builder().method(method).uri(path);
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        builder = builder.header("host", format!("127.0.0.1:{}", addr.port()));
    }
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Empty::<Bytes>::new()).unwrap();
    let res = sender.send_request(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.collect().await.unwrap().to_bytes();
    (status, headers, body)
}

async fn raw_request(addr: SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn wait_status<F>(data: &Path, mut pred: F, timeout: Duration) -> bool
where
    F: FnMut(&cite_core::ExecutorStatus) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let path = data.join("status/executor.json");
    while tokio::time::Instant::now() < deadline {
        if let Ok(st) = cite_core::read_status(&path) {
            if pred(&st) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn static_get_head_304_range_spa_dotfile_404() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();

    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[
            ("index.html", b"<html>home</html>"),
            ("assets/app.deadbeef1234.js", b"console.log(1)"),
            ("hello.txt", b"hello-world-bytes"),
            (
                "assets/plain.txt",
                b"raw-body-not-served-when-gzip-is-accepted",
            ),
            ("assets/plain.txt.gz", &gzip_bytes(b"precompressed-body")),
        ],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);

    let cfg = config_from(data, "127.0.0.1:0");
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue) && s.ack_generation >= 1,
            Duration::from_secs(5)
        )
        .await
    );

    let addr = exe.addr;

    let (st, h, body) = http_once(addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(4).any(|w| w == b"home"));
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-cache");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");

    let (st, h, _) = http_once(addr, Method::GET, "/assets/app.deadbeef1234.js", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        h.get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(h.get(header::CONTENT_TYPE).unwrap(), "text/javascript");

    let (st, h, body) = http_once(
        addr,
        Method::GET,
        "/assets/plain.txt",
        &[("accept-encoding", "gzip")],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h.get(header::CONTENT_ENCODING).unwrap(), "gzip");
    assert_eq!(&body[..], gzip_bytes(b"precompressed-body").as_slice());

    let (st, h, body) = http_once(addr, Method::HEAD, "/hello.txt", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.is_empty());
    let etag = h.get(header::ETAG).unwrap().clone();

    let (st, _, body) = http_once(
        addr,
        Method::GET,
        "/hello.txt",
        &[("if-none-match", etag.to_str().unwrap())],
    )
    .await;
    assert_eq!(st, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());

    let (st, h, body) = http_once(addr, Method::GET, "/hello.txt", &[("range", "bytes=0-4")]).await;
    assert_eq!(st, StatusCode::PARTIAL_CONTENT);
    assert_eq!(&body[..], b"hello");
    assert!(h.get(header::CONTENT_RANGE).is_some());

    let (st, _, body) = http_once(
        addr,
        Method::GET,
        "/missing-route",
        &[("accept", "text/html")],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(4).any(|w| w == b"home"));

    let (st, _, _) = http_once(addr, Method::GET, "/.env", &[]).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = http_once(addr, Method::GET, "/../secret", &[]).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = http_once(addr, Method::GET, "/no-such-file.txt", &[]).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    assert!(
        wait_status(data, |s| s.requests >= 1, Duration::from_secs(5)).await,
        "request counter must show up in executor status"
    );

    exe.shutdown().await;
}

fn gzip_bytes(plain: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

#[tokio::test]
async fn proxy_forwarded_headers_trusted_and_untrusted() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();

    use crate::proxy::set_forwarded_headers;
    use http::HeaderMap;
    use http::HeaderValue;

    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
    headers.insert("connection", HeaderValue::from_static("keep-alive"));
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 9));
    set_forwarded_headers(&mut headers, peer, &[]);
    assert_eq!(
        headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
        "8.8.8.8"
    );

    let trusted: Vec<ipnet::IpNet> = vec!["8.8.8.8/32".parse().unwrap()];
    headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
    set_forwarded_headers(&mut headers, peer, &trusted);
    assert_eq!(
        headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
        "1.2.3.4, 8.8.8.8"
    );

    let header = |h: &HeaderMap, name: &str| h.get(name).unwrap().to_str().unwrap().to_string();
    let mut spoofed = HeaderMap::new();
    spoofed.insert("host", HeaderValue::from_static("internal:8080"));
    spoofed.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    spoofed.insert("x-forwarded-host", HeaderValue::from_static("app.example"));
    spoofed.insert(
        "forwarded",
        HeaderValue::from_static("for=1.2.3.4;proto=https;host=app.example"),
    );

    let mut from_untrusted = spoofed.clone();
    set_forwarded_headers(&mut from_untrusted, peer, &[]);
    assert_eq!(header(&from_untrusted, "x-forwarded-proto"), "http");
    assert_eq!(header(&from_untrusted, "x-forwarded-host"), "internal:8080");
    assert_eq!(
        header(&from_untrusted, "forwarded"),
        "for=\"8.8.8.8\";proto=http;host=\"internal:8080\""
    );

    let mut from_trusted = spoofed.clone();
    set_forwarded_headers(&mut from_trusted, peer, &trusted);
    assert_eq!(header(&from_trusted, "x-forwarded-proto"), "https");
    assert_eq!(header(&from_trusted, "x-forwarded-host"), "app.example");
    assert_eq!(
        header(&from_trusted, "forwarded"),
        "for=1.2.3.4;proto=https;host=app.example, for=\"8.8.8.8\";proto=https;host=\"app.example\""
    );

    for (raw, token) in [("https,http", "http"), ("x;y", "http"), ("HTTPS", "https")] {
        let mut odd = HeaderMap::new();
        odd.insert("host", HeaderValue::from_static("internal:8080"));
        odd.insert("x-forwarded-proto", HeaderValue::from_str(raw).unwrap());
        set_forwarded_headers(&mut odd, peer, &trusted);
        assert_eq!(header(&odd, "x-forwarded-proto"), raw);
        assert_eq!(
            header(&odd, "forwarded"),
            format!("for=\"8.8.8.8\";proto={token};host=\"internal:8080\"")
        );
    }

    let mut bare = HeaderMap::new();
    bare.insert("host", HeaderValue::from_static("internal:8080"));
    set_forwarded_headers(&mut bare, peer, &trusted);
    assert_eq!(header(&bare, "x-forwarded-proto"), "http");
    assert_eq!(header(&bare, "x-forwarded-host"), "internal:8080");
    assert_eq!(header(&bare, "x-forwarded-for"), "8.8.8.8");
}

#[tokio::test]
async fn blue_green_activate_health_fail_warm_rollback_corrupt() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("releases/green/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();

    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);

    let cfg = config_from(data, "127.0.0.1:0");
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(5)
        )
        .await
    );

    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(4).any(|w| w == b"blue"));

    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        &[("index.html", b"<html>green</html>")],
    );
    write_desired_action(data, 2, Slot::Green, DesiredAction::Activate, None);
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green)
                && s.slots.blue.state == SlotState::Warm
                && s.ack_generation >= 2,
            Duration::from_secs(5)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(5).any(|w| w == b"green"));

    write_desired_action(data, 3, Slot::Blue, DesiredAction::Evict, Some(Slot::Blue));
    assert!(
        wait_status(
            data,
            |s| s.slots.blue.state == SlotState::Stopped && s.ack_generation >= 3,
            Duration::from_secs(5)
        )
        .await
    );
    let blue_app = data.join("releases/blue/app");
    let _ = std::fs::remove_dir_all(&blue_app);
    std::fs::create_dir_all(&blue_app).unwrap();
    std::fs::write(blue_app.join("only.txt"), b"x").unwrap();
    let mut bad = sample_static(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FB1");
    bad.health.path = "/index.html".into();
    write_release(&data.join("releases/blue/release.json"), &bad).unwrap();
    write_desired_action(data, 4, Slot::Blue, DesiredAction::Activate, None);
    assert!(
        wait_status(
            data,
            |s| {
                s.ack_generation >= 4
                    && s.active_slot == Some(Slot::Green)
                    && s.last_result
                        .as_ref()
                        .is_some_and(|r| r.outcome == Outcome::Failed)
            },
            Duration::from_secs(8)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(5).any(|w| w == b"green"));

    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FB2",
        &[("index.html", b"<html>blue2</html>")],
    );
    write_desired_action(data, 5, Slot::Blue, DesiredAction::Activate, None);
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue) && s.slots.green.state == SlotState::Warm,
            Duration::from_secs(5)
        )
        .await
    );
    write_desired_action(data, 6, Slot::Green, DesiredAction::Rollback, None);
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green) && s.ack_generation >= 6,
            Duration::from_secs(5)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(5).any(|w| w == b"green"));

    std::fs::write(data.join("releases/blue/release.json"), b"{not-json").unwrap();
    write_desired_action(data, 7, Slot::Blue, DesiredAction::Activate, None);
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 7 && s.active_slot == Some(Slot::Green),
            Duration::from_secs(5)
        )
        .await
    );

    exe.shutdown().await;
}

#[tokio::test]
async fn no_release_is_503_and_bad_host_is_rejected() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    let mut env = base_env(data, "127.0.0.1:0");
    env.insert("CITE_ALLOWED_HOSTS".into(), "app.example".into());
    env.insert("CITE_RUNTIME".into(), "static".into());
    let _ = std::fs::write(data.join("runtime.env"), "");
    let exe = spawn(ExecutorConfig::load_from(&env, None).unwrap())
        .await
        .unwrap();

    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(!String::from_utf8_lossy(&body).contains("cite_data"));

    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[("host", "app.example")]).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("503"));
    assert!(!text.contains("release.json"));
    exe.shutdown().await;
}

#[tokio::test]
async fn refuses_mismatched_node_major() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(data.join("releases/blue/app/server.js"), b"/* unused */").unwrap();
    let mut manifest = sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FB9");
    manifest.node_major = "18".into();
    write_release(&data.join("releases/blue/release.json"), &manifest).unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let cfg = config_from(data, "127.0.0.1:0");
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| {
                s.ack_generation >= 1
                    && s.slots.blue.state == SlotState::Failed
                    && s.last_result.as_ref().is_some_and(|r| {
                        r.reason.contains("node_major") && r.outcome == Outcome::Failed
                    })
            },
            Duration::from_secs(5)
        )
        .await
    );
    let (st, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    exe.shutdown().await;
}

#[tokio::test]
async fn unsealed_slot_is_ignored() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/index.html"),
        b"<html>unsealed</html>",
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!String::from_utf8_lossy(&body).contains("unsealed"));
    let status = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    assert!(status.active_slot.is_none());
    exe.shutdown().await;
}

#[tokio::test]
async fn stale_generation_is_ignored() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("releases/green/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    write_desired_action(data, 2, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue) && s.ack_generation >= 2,
            Duration::from_secs(5)
        )
        .await
    );
    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        &[("index.html", b"<html>green</html>")],
    );
    write_desired_action(data, 1, Slot::Green, DesiredAction::Activate, None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(4).any(|w| w == b"blue"));
    let status = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    assert_eq!(status.active_slot, Some(Slot::Blue));
    assert!(status.ack_generation >= 2);
    exe.shutdown().await;
}

#[tokio::test]
async fn boot_falls_back_to_the_other_sealed_slot() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue")).unwrap();
    std::fs::create_dir_all(data.join("releases/green/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        &[("index.html", b"<html>green</html>")],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green),
            Duration::from_secs(5)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(5).any(|w| w == b"green"));

    std::fs::write(data.join("control/desired.json"), b"{not-json").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(5).any(|w| w == b"green"));
    exe.shutdown().await;
}

#[tokio::test]
async fn evict_acks_only_after_the_slot_stops() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(5)
        )
        .await
    );
    write_desired_action(data, 2, Slot::Blue, DesiredAction::Evict, Some(Slot::Blue));
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 2 && s.slots.blue.state == SlotState::Stopped,
            Duration::from_secs(5)
        )
        .await
    );
    let (st, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    exe.shutdown().await;
}

#[tokio::test]
async fn child_gets_only_port_host_node_env_and_runtime_file() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping env test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"const http=require('http');
const keys=Object.keys(process.env).sort().join(',');
const s=http.createServer((req,res)=>{res.writeHead(200);res.end(keys+'\n'+process.env.PORT+'\n'+process.env.HOST+'\n'+process.env.NODE_ENV+'\n'+process.env.PUBLIC_FOO);});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let port = Slot::Blue.loopback_port(cfg.port_base).unwrap();
    std::fs::write(data.join("runtime.env"), "PUBLIC_FOO=from-runtime\n").unwrap();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    let text = String::from_utf8(body.to_vec()).unwrap();
    let mut lines = text.lines();
    let keys: Vec<_> = lines.next().unwrap().split(',').collect();
    for required in ["HOST", "NODE_ENV", "PATH", "PORT", "PUBLIC_FOO"] {
        assert!(keys.contains(&required), "{keys:?}");
    }
    assert!(!keys.contains(&"HOME"));
    assert!(!keys.contains(&"USER"));
    assert!(
        !keys
            .iter()
            .any(|key| { key.contains("GITHUB") || key.starts_with("CITE_") })
    );
    assert_eq!(lines.next().unwrap(), port.to_string());
    assert_eq!(lines.next().unwrap(), "127.0.0.1");
    assert_eq!(lines.next().unwrap(), "production");
    assert_eq!(lines.next().unwrap(), "from-runtime");
    exe.shutdown().await;
}

#[tokio::test]
async fn http2_preface_is_not_a_successful_upgrade() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::create_dir_all(data.join("releases")).unwrap();
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    if n > 0 {
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(
            text.starts_with("HTTP/1."),
            "preface must be handled as HTTP/1.1, got {text}"
        );
    }
    exe.shutdown().await;
}

#[test]
fn child_log_line_is_prefixed_and_redacted() {
    let mut redactor = cite_core::Redactor::new();
    redactor.push_secret("super-secret");
    let line = crate::supervisor::child_log_line(
        "token super-secret ok",
        "out",
        "blue",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &redactor,
    );
    assert_eq!(
        line,
        "[blue/01ARZ3NDEKTSV4RRFFQ69G5FAV] out: token [REDACTED] ok"
    );
}

#[tokio::test]
async fn child_log_tail_is_prefixed_in_status() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping log tail test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{res.writeHead(200);res.end('ok');});
s.listen(process.env.PORT,'127.0.0.1',()=>{console.log('hello-tail');});
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| {
                s.last_result.as_ref().is_some_and(|r| {
                    r.log_tail.iter().any(|line| {
                        line.contains("[blue/01ARZ3NDEKTSV4RRFFQ69G5FAV] out:")
                            && line.contains("hello-tail")
                    })
                })
            },
            Duration::from_secs(15),
        )
        .await
    );
    exe.shutdown().await;
}

#[tokio::test]
async fn inflight_request_finishes_on_the_old_target() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping switch test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    for slot in ["blue", "green"] {
        std::fs::create_dir_all(data.join(format!("releases/{slot}/app"))).unwrap();
    }
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{setTimeout(()=>{res.writeHead(200);res.end('blue-hold');},700);});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    std::fs::write(
        data.join("releases/green/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{res.writeHead(200);res.end('green-now');});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_release(
        &data.join("releases/green/release.json"),
        &sample_ssr(Slot::Green, "01ARZ3NDEKTSV4RRFFQ69G5FB0"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );
    let first = tokio::spawn(http_once(exe.addr, Method::GET, "/", &[]));
    tokio::time::sleep(Duration::from_millis(80)).await;
    write_desired_action(data, 2, Slot::Green, DesiredAction::Activate, None);
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green),
            Duration::from_secs(15)
        )
        .await
    );
    let (st, _, body) = first.await.unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&body[..], b"blue-hold");
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&body[..], b"green-now");
    exe.shutdown().await;
}

#[test]
fn crash_backoff_is_exponential_and_capped() {
    use crate::supervisor::SlotManager;
    let d0 = SlotManager::backoff_delay(0);
    let d1 = SlotManager::backoff_delay(1);
    let d2 = SlotManager::backoff_delay(2);
    let cap = SlotManager::backoff_delay(6);
    let beyond = SlotManager::backoff_delay(20);
    assert!(d1 > d0);
    assert!(d2 > d1);
    assert_eq!(cap, beyond);
    assert!(cap <= Duration::from_secs(30));
}

#[tokio::test]
async fn steady_state_crashes_restart_then_fall_back() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping crash-limit test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("releases/green/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue-steady</html>")],
    );
    std::fs::write(
        data.join("releases/green/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{res.writeHead(200);res.end('green');});
s.listen(process.env.PORT,'127.0.0.1',()=>{setTimeout(()=>process.exit(1),3000);});
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/green/release.json"),
        &sample_ssr(Slot::Green, "01ARZ3NDEKTSV4RRFFQ69G5FB0"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    cfg.watch = Duration::from_millis(200);
    cfg.crash_limit = 2;
    cfg.warm_grace = Duration::from_secs(60);
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(10)
        )
        .await
    );
    write_desired_action(data, 2, Slot::Green, DesiredAction::Activate, None);
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green),
            Duration::from_secs(10)
        )
        .await
    );
    let fell_back = wait_status(
        data,
        |s| {
            s.active_slot == Some(Slot::Blue)
                && s.last_result.as_ref().is_some_and(|r| {
                    r.outcome == Outcome::Fallback && r.reason.contains("crash limit")
                })
        },
        Duration::from_secs(20),
    )
    .await;
    if !fell_back {
        let status = cite_core::read_status(&data.join("status/executor.json")).unwrap();
        panic!("expected crash-limit fallback, status={status:?}");
    }
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.windows(11).any(|w| w == b"blue-steady"));
    exe.shutdown().await;
}

#[tokio::test]
async fn shutdown_drains_the_inflight_request_then_kills_the_child() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping shutdown test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"process.on('SIGTERM',()=>{});
const http=require('http');
const s=http.createServer((req,res)=>{require('fs').writeFileSync('inflight','1');setTimeout(()=>{res.writeHead(200);res.end('drained');},400);});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, &format!("127.0.0.1:{}", next_port_base()));
    cfg.node_bin = which_node();
    cfg.child_term_grace = Duration::from_millis(300);
    let exe = spawn(cfg).await.unwrap();
    let addr = exe.addr;
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );
    let status = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    let pid = status.slots.blue.pid.expect("supervised child pid");
    let marker = data.join("releases/blue/app/inflight");
    std::fs::remove_file(&marker).unwrap();
    let inflight = tokio::spawn(http_once(addr, Method::GET, "/", &[]));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !marker.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(marker.exists(), "request never reached the upstream");
    let shutting_down = tokio::spawn(async move { exe.shutdown().await });
    let (st, _, body) = inflight.await.unwrap();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&body[..], b"drained");
    shutting_down.await.unwrap();
    let still = Command::new("kill").args(["-0", &pid.to_string()]).status();
    assert!(still.is_ok());
    assert!(
        !still.unwrap().success(),
        "child must be dead after SIGTERM grace"
    );
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn proxy_strips_hop_headers_and_caps_only_the_request_body() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping proxy header test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{
  if(req.url==='/big'){res.writeHead(200,{'content-length':'100'});res.end('x'.repeat(100));return;}
  if(req.url==='/fwd'){const b=[req.headers['x-forwarded-for'],req.headers['x-forwarded-proto'],req.headers['x-forwarded-host']].join('|');res.writeHead(200,{'content-length':b.length});res.end(b);return;}
  if(req.method==='POST'){let n=0;req.on('data',c=>{n+=c.length;});req.on('end',()=>{const b='got:'+n;res.writeHead(200,{'content-length':b.length});res.end(b);});return;}
  const saw=req.headers['x-cite-hop']?'saw-hop':'no-hop';
  const keep=req.headers['x-keep']||'';
  const body=saw+':'+keep;
  res.writeHead(200,{
    'content-length': Buffer.byteLength(body),
    'x-should-pass':'yes',
    'keep-alive':'timeout=5',
    'x-drop-me':'secret',
    'connection':'x-drop-me'
  });
  res.end(body);
});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    cfg.max_body = 16;
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );

    let (st, headers, body) = http_once(
        exe.addr,
        Method::GET,
        "/",
        &[
            ("connection", "x-cite-hop"),
            ("x-cite-hop", "leak"),
            ("x-keep", "yes"),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert_eq!(text, "no-hop:yes");
    assert!(headers.get("x-should-pass").is_some());
    assert!(headers.get("x-drop-me").is_none());
    assert!(headers.get("keep-alive").is_none());

    let (st, _, body) = http_once(exe.addr, Method::GET, "/big", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body.len(), 100);

    let (st, _, body) = http_once(
        exe.addr,
        Method::GET,
        "/fwd",
        &[
            (
                "connection",
                "x-forwarded-for, x-forwarded-proto, x-forwarded-host, forwarded",
            ),
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let host = format!("127.0.0.1:{}", exe.addr.port());
    assert_eq!(
        String::from_utf8_lossy(&body),
        format!("127.0.0.1|http|{host}")
    );

    let small = raw_request(
        exe.addr,
        "POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 10\r\nconnection: close\r\n\r\n0123456789",
    )
    .await;
    assert!(small.starts_with("HTTP/1.1 200"), "{small}");
    assert!(small.ends_with("got:10"), "{small}");

    let declared = raw_request(
        exe.addr,
        "POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 17\r\nconnection: close\r\n\r\n01234567890123456",
    )
    .await;
    assert!(declared.starts_with("HTTP/1.1 413"), "{declared}");

    let chunked = raw_request(
        exe.addr,
        "POST / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\nA\r\n0123456789\r\nA\r\n0123456789\r\n0\r\n\r\n",
    )
    .await;
    assert!(chunked.starts_with("HTTP/1.1 413"), "{chunked}");
    exe.shutdown().await;
}

#[tokio::test]
async fn visitor_panic_is_a_generic_500() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::create_dir_all(data.join("releases")).unwrap();
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    let (st, _, body) = http_once(exe.addr, Method::GET, "/__cite_test_panic", &[]).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("500"));
    assert!(!text.contains("secret-stack-frame"));
    assert!(!text.contains("panicked"));
    exe.shutdown().await;
}

#[tokio::test]
async fn proxy_streams_the_first_byte_before_the_body_ends() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping streaming test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{
  if(req.url==='/slow'){
    res.writeHead(200);
    res.write('A');
    setTimeout(()=>res.end('B'), 800);
    return;
  }
  res.end('ok');
});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );

    let stream = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/slow")
        .header("host", "127.0.0.1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let mut body = res.into_body();
    let started = tokio::time::Instant::now();
    let first = tokio::time::timeout(Duration::from_millis(400), body.frame())
        .await
        .expect("first byte should arrive before the upstream finishes")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(400));
    let bytes = first
        .data_ref()
        .map(|b| b.as_ref().to_vec())
        .unwrap_or_default();
    assert_eq!(bytes, b"A");
    let rest = body.collect().await.unwrap().to_bytes();
    assert_eq!(rest.as_ref(), b"B");
    exe.shutdown().await;
}

#[tokio::test]
async fn proxy_idle_and_header_timeouts_and_the_connection_cap() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping timeout test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{
  if(req.url==='/stall'){res.writeHead(200);res.write('A');return;}
  if(req.url==='/hang'){return;}
  res.end('ok');
});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    cfg.idle_timeout = Duration::from_millis(200);
    cfg.header_timeout = Duration::from_millis(400);
    cfg.max_connections = 1;
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // The cap is 1, so wait for the server to close this connection before opening the next.
    let mut first = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    first
        .write_all(b"GET /hang HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    first.read_to_end(&mut raw).await.unwrap();
    assert!(
        raw.starts_with(b"HTTP/1.1 504"),
        "{}",
        String::from_utf8_lossy(&raw)
    );

    let stream = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/stall")
        .header("host", "127.0.0.1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    let started = tokio::time::Instant::now();
    let err = res.into_body().collect().await.unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(2),
        "idle timeout did not bound the stalled body ({elapsed:?}): {err}"
    );

    let mut hold = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    hold.write_all(b"GET /hang HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut extra = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    extra
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_millis(500), extra.read(&mut buf)).await;
    let closed = match read {
        Ok(Ok(0)) | Err(_) => true,
        Ok(Ok(_)) => false,
        Ok(Err(_)) => true,
    };
    assert!(closed, "a connection past the cap must be dropped");
    exe.shutdown().await;
}

#[tokio::test]
async fn oversized_request_headers_are_rejected() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::create_dir_all(data.join("releases")).unwrap();
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.max_header_bytes = 8 * 1024;
    let exe = spawn(cfg).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let huge = "x".repeat(20_000);
    let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: {huge}\r\n\r\n");
    let _ = stream.write_all(req.as_bytes()).await;
    let mut buf = [0u8; 128];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    let rejected = match read {
        Ok(Ok(0)) | Err(_) | Ok(Err(_)) => true,
        Ok(Ok(n)) => {
            let text = String::from_utf8_lossy(&buf[..n]);
            text.contains("400") || text.contains("431")
        }
    };
    assert!(rejected, "an oversized header must not be served");
    exe.shutdown().await;
}

#[tokio::test]
async fn websocket_upgrade_is_proxied() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping websocket test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/blue/app/server.js"),
        br#"const http=require('http');
const crypto=require('crypto');
const s=http.createServer((req,res)=>res.end('ok'));
s.on('upgrade',(req,socket)=>{
  const key=req.headers['sec-websocket-key']||'';
  const accept=crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');
  socket.on('data',(buf)=>socket.write(buf));
});
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.contains("101"), "{text}");
    stream.write_all(b"hello-ws").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"hello-ws");
    exe.shutdown().await;
}

#[tokio::test]
async fn conflicting_framing_is_not_a_second_request() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::create_dir_all(data.join("releases")).unwrap();
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    let req = b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /__cite_test_panic HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let _ = stream.write_all(req).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(
        !text.contains("secret-stack-frame") && !text.contains("500"),
        "{text}"
    );
    exe.shutdown().await;
}

#[tokio::test]
async fn duplicate_length_obs_fold_and_slowloris_are_rejected() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::create_dir_all(data.join("releases")).unwrap();
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.header_timeout = Duration::from_millis(200);
    let exe = spawn(cfg).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut dup = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    let _ = dup
        .write_all(
            b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        )
        .await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), dup.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(
        !text.contains("secret-stack-frame") && !text.contains(" 500"),
        "{text}"
    );
    assert!(
        text.contains("400") || buf.is_empty(),
        "duplicate content-length was accepted: {text}"
    );

    let mut folded = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    let _ = folded
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Folded: one\r\n two\r\n\r\n")
        .await;
    buf.clear();
    let _ = tokio::time::timeout(Duration::from_secs(2), folded.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("400") || buf.is_empty(),
        "obs-fold was accepted: {text}"
    );

    let started = std::time::Instant::now();
    let mut slow = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    let _ = slow
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .await;
    buf.clear();
    let _ = tokio::time::timeout(Duration::from_secs(2), slow.read_to_end(&mut buf)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "slowloris held the connection open for {elapsed:?}"
    );
    let text = String::from_utf8_lossy(&buf);
    assert!(!text.contains("200 OK"), "{text}");

    let mut te_cl = tokio::net::TcpStream::connect(exe.addr).await.unwrap();
    let _ = te_cl
        .write_all(b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /__cite_test_panic HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await;
    buf.clear();
    let _ = tokio::time::timeout(Duration::from_secs(2), te_cl.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(
        !text.contains("secret-stack-frame") && !text.contains(" 500"),
        "TE.CL smuggle leaked: {text}"
    );
    exe.shutdown().await;
}

#[tokio::test]
async fn dead_upstream_with_no_fallback_is_503() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping upstream-down test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/green/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    std::fs::write(
        data.join("releases/green/app/server.js"),
        br#"const http=require('http');
const s=http.createServer((req,res)=>{res.end('up');});
s.listen(process.env.PORT,'127.0.0.1',()=>{setTimeout(()=>process.exit(1),3000);});
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/green/release.json"),
        &sample_ssr(Slot::Green, "01ARZ3NDEKTSV4RRFFQ69G5FB0"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Green, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    cfg.crash_limit = 1;
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green),
            Duration::from_secs(8)
        )
        .await,
        "upstream never became live: {}",
        std::fs::read_to_string(data.join("status/executor.json")).unwrap_or_default()
    );
    assert!(
        wait_status(
            data,
            |s| s.slots.green.state == SlotState::Failed,
            Duration::from_secs(8)
        )
        .await,
        "dead upstream was not marked failed"
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("503"), "{text}");
    assert!(!text.contains("child exited"), "{text}");
    exe.shutdown().await;
}

#[tokio::test]
async fn connect_times_out_when_the_upstream_queue_is_full() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping connect-timeout test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    let script = data.join("releases/blue/app/server.js");
    std::fs::write(
        &script,
        br#"const http=require('http');
const s=http.createServer((req,res)=>res.end('ok'));
s.listen(process.env.PORT,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    cfg.connect_timeout = Duration::from_millis(200);
    let port = cfg.port_base;
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );

    let child = listener_pid(port);
    struct ContinueOnDrop(i32);
    impl Drop for ContinueOnDrop {
        fn drop(&mut self) {
            if let Some(pid) = rustix::process::Pid::from_raw(self.0) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::CONT);
            }
        }
    }
    let _resume = ContinueOnDrop(child as i32);
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child as i32).unwrap(),
        rustix::process::Signal::STOP,
    )
    .unwrap();

    let upstream = SocketAddr::from(([127, 0, 0, 1], port));
    let mut held = Vec::new();
    let mut stalled = false;
    for _ in 0..2048 {
        let started = std::time::Instant::now();
        match std::net::TcpStream::connect_timeout(&upstream, Duration::from_millis(150)) {
            Ok(stream) => held.push(stream),
            Err(_) => {
                stalled = started.elapsed() >= Duration::from_millis(100);
                break;
            }
        }
    }
    assert!(
        stalled,
        "upstream connect never stalled (held {} sockets)",
        held.len()
    );
    let (st, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::GATEWAY_TIMEOUT);
    drop(held);
    exe.shutdown().await;
}

fn listener_pid(port: u16) -> u32 {
    let out = Command::new("lsof")
        .args(["-nP", "-t", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|line| line.trim().parse().ok())
        .unwrap_or_else(|| panic!("nothing listening on {port}: {text}"))
}

#[tokio::test]
async fn slot_transitions_follow_the_table() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();

    write_desired_action(data, 1, Slot::Green, DesiredAction::Activate, None);
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 1 && s.slots.green.state == SlotState::Failed,
            Duration::from_secs(5)
        )
        .await,
        "unsealed activate must fail"
    );
    let ack_after_fail = cite_core::read_status(&data.join("status/executor.json"))
        .unwrap()
        .ack_generation;

    write_desired_action(
        data,
        ack_after_fail,
        Slot::Blue,
        DesiredAction::Activate,
        None,
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stale = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    assert_eq!(stale.ack_generation, ack_after_fail);
    assert!(stale.active_slot.is_none());

    write_desired_action(
        data,
        ack_after_fail + 1,
        Slot::Blue,
        DesiredAction::Activate,
        None,
    );
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue) && s.ack_generation > ack_after_fail,
            Duration::from_secs(5)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/index.html", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.windows(4).any(|w| w == b"blue"));

    let live_ack = cite_core::read_status(&data.join("status/executor.json"))
        .unwrap()
        .ack_generation;
    write_desired_action(
        data,
        live_ack,
        Slot::Blue,
        DesiredAction::Evict,
        Some(Slot::Blue),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let still = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    assert_eq!(still.active_slot, Some(Slot::Blue));

    write_desired_action(
        data,
        live_ack + 1,
        Slot::Blue,
        DesiredAction::Evict,
        Some(Slot::Blue),
    );
    assert!(
        wait_status(
            data,
            |s| {
                s.ack_generation > live_ack
                    && s.active_slot.is_none()
                    && s.slots.blue.state == SlotState::Stopped
            },
            Duration::from_secs(5)
        )
        .await
    );

    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FBV",
        &[("index.html", b"<html>green</html>")],
    );
    write_desired_action(
        data,
        live_ack + 2,
        Slot::Green,
        DesiredAction::Activate,
        None,
    );
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green) && s.ack_generation >= live_ack + 2,
            Duration::from_secs(5)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/index.html", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.windows(5).any(|w| w == b"green"));
    exe.shutdown().await;
}

#[tokio::test]
async fn warm_grace_stops_the_slot_and_cold_rollback_serves_a_readonly_tree() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("releases/green/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        &[("index.html", b"<html>green</html>")],
    );
    write_desired_grace(data, 1, Slot::Blue, DesiredAction::Activate, None, 1);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(5)
        )
        .await
    );
    write_desired_grace(data, 2, Slot::Green, DesiredAction::Activate, None, 1);
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green) && s.slots.blue.state == SlotState::Warm,
            Duration::from_secs(5)
        )
        .await
    );
    assert!(
        wait_status(
            data,
            |s| s.slots.blue.state == SlotState::Stopped,
            Duration::from_secs(4)
        )
        .await,
        "warm slot did not stop after the grace"
    );

    let green_app = data.join("releases/green/app");
    let before = std::fs::read_dir(&green_app).unwrap().count();
    readonly_tree(&green_app);
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.windows(5).any(|w| w == b"green"));
    assert_eq!(std::fs::read_dir(&green_app).unwrap().count(), before);
    writable_tree(&green_app);

    write_desired_grace(data, 3, Slot::Blue, DesiredAction::Rollback, None, 1);
    assert!(
        wait_status(
            data,
            |s| {
                s.active_slot == Some(Slot::Blue)
                    && s.ack_generation >= 3
                    && s.last_result
                        .as_ref()
                        .is_some_and(|r| r.outcome == Outcome::Live)
            },
            Duration::from_secs(5)
        )
        .await,
        "cold rollback did not activate the stopped slot"
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.windows(4).any(|w| w == b"blue"));
    exe.shutdown().await;
}

fn readonly_tree(root: &Path) {
    set_tree_mode(root, 0o555, 0o444);
}

fn writable_tree(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(root).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(root, perms).unwrap();
    set_tree_mode(root, 0o755, 0o644);
}

fn set_tree_mode(path: &Path, dir_mode: u32, file_mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).unwrap();
    if meta.file_type().is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            set_tree_mode(&entry.unwrap().path(), dir_mode, file_mode);
        }
    }
    let mut perms = meta.permissions();
    perms.set_mode(if meta.file_type().is_dir() {
        dir_mode
    } else {
        file_mode
    });
    std::fs::set_permissions(path, perms).unwrap();
}

fn which_node() -> String {
    for candidate in ["node", "/usr/local/bin/node", "/opt/homebrew/bin/node"] {
        if Command::new(candidate).arg("-v").output().is_ok() {
            return candidate.to_string();
        }
    }
    "node".into()
}

#[tokio::test]
async fn ssr_node_and_crash_fallback() {
    let node = Command::new("node").arg("-v").output();
    if node.is_err() || !node.unwrap().status.success() {
        eprintln!("skipping ssr test: node not on PATH");
        return;
    }

    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("releases/blue/app")).unwrap();
    std::fs::create_dir_all(data.join("releases/green/app")).unwrap();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();

    let blue_app = data.join("releases/blue/app");
    std::fs::write(
        blue_app.join("server.js"),
        br#"const http=require('http');
const port=process.env.PORT||3000;
http.createServer((req,res)=>{res.writeHead(200,{'content-type':'text/plain'});res.end('blue-ssr');}).listen(port,'127.0.0.1');
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/blue/release.json"),
        &sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
    )
    .unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);

    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.watch = Duration::from_secs(5);
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue) && s.ack_generation >= 1,
            Duration::from_secs(15)
        )
        .await
    );

    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&body[..], b"blue-ssr");

    write_desired_action(
        data,
        2,
        Slot::Green,
        DesiredAction::Evict,
        Some(Slot::Green),
    );
    assert!(wait_status(data, |s| s.ack_generation >= 2, Duration::from_secs(5)).await);

    let green_app = data.join("releases/green/app");
    std::fs::create_dir_all(&green_app).unwrap();
    std::fs::write(
        green_app.join("server.js"),
        br#"const http=require('http');
const port=process.env.PORT||3000;
const s=http.createServer((req,res)=>{res.writeHead(200);res.end('green-ssr');});
s.listen(port,'127.0.0.1',()=>{setTimeout(()=>process.exit(1),1500);});
"#,
    )
    .unwrap();
    write_release(
        &data.join("releases/green/release.json"),
        &sample_ssr(Slot::Green, "01ARZ3NDEKTSV4RRFFQ69G5FB0"),
    )
    .unwrap();
    write_desired_action(data, 3, Slot::Green, DesiredAction::Activate, None);

    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Green) && s.ack_generation >= 3,
            Duration::from_secs(15)
        )
        .await
    );

    assert!(
        wait_status(
            data,
            |s| {
                s.active_slot == Some(Slot::Blue)
                    && s.last_result
                        .as_ref()
                        .is_some_and(|r| r.outcome == Outcome::Fallback)
            },
            Duration::from_secs(10)
        )
        .await
    );

    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&body[..], b"blue-ssr");

    exe.shutdown().await;
}

#[tokio::test]
async fn restart_executor_asks_the_process_to_exit() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>stay</html>")],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let cfg = config_from(data, "127.0.0.1:0");
    let mut exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue) && s.ack_generation >= 1,
            Duration::from_secs(5)
        )
        .await
    );
    write_desired_action(data, 2, Slot::Blue, DesiredAction::RestartExecutor, None);
    tokio::time::timeout(Duration::from_secs(3), exe.exited())
        .await
        .expect("restart_executor did not ask the process to exit");
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 2 && s.active_slot == Some(Slot::Blue),
            Duration::from_secs(2)
        )
        .await
    );
    exe.shutdown().await;
}

fn node_available() -> bool {
    Command::new(which_node())
        .arg("-v")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn seal_ssr(data: &Path, slot: Slot, release_id: &str, script: &str, timeout_s: u64) {
    let slot_dir = data.join("releases").join(slot.as_str());
    std::fs::create_dir_all(slot_dir.join("app")).unwrap();
    std::fs::write(slot_dir.join("app/server.js"), script).unwrap();
    let mut manifest = sample_ssr(slot, release_id);
    manifest.health.timeout_s = timeout_s;
    write_release(&slot_dir.join("release.json"), &manifest).unwrap();
}

#[tokio::test]
async fn heartbeat_keeps_flowing_during_a_long_health_gate() {
    if !node_available() {
        eprintln!("skipping heartbeat test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_ssr(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "setInterval(()=>{},1000);",
        8,
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();

    let path = data.join("status/executor.json");
    let mut stamps = std::collections::BTreeSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Ok(st) = cite_core::read_status(&path) {
            assert_eq!(st.ack_generation, 0, "health gate ended early");
            stamps.insert(st.updated_at);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(stamps.len() >= 3, "heartbeat stalled: {stamps:?}");
    exe.shutdown().await;
}

#[tokio::test]
async fn sealed_non_live_slot_boots_as_stopped_and_can_be_rolled_back_to() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        &[("index.html", b"<html>green</html>")],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue)
                && s.slots.green.state == SlotState::Stopped
                && s.slots.green.release_id.as_deref() == Some("01ARZ3NDEKTSV4RRFFQ69G5FB0"),
            Duration::from_secs(5)
        )
        .await
    );

    write_desired_action(data, 2, Slot::Green, DesiredAction::Rollback, None);
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 2 && s.active_slot == Some(Slot::Green),
            Duration::from_secs(8)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(5).any(|w| w == b"green"));
    exe.shutdown().await;
}

async fn boot_retry_case(boot_action: DesiredAction, generation: u64) {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("other.txt", b"not the health path")],
    );
    let release_path = data.join("releases/blue/release.json");
    let mut manifest = cite_core::read_release(&release_path).unwrap();
    manifest.health.timeout_s = 1;
    write_release(&release_path, &manifest).unwrap();
    write_desired_action(data, generation, Slot::Blue, boot_action, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    let (st, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);

    std::fs::write(
        data.join("releases/blue/app/index.html"),
        b"<html>late</html>",
    )
    .unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue) && s.ack_generation >= generation,
            Duration::from_secs(20)
        )
        .await
    );
    let (st, _, body) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.as_ref().windows(4).any(|w| w == b"late"));
    exe.shutdown().await;
}

#[tokio::test]
async fn boot_keeps_retrying_until_a_slot_becomes_healthy() {
    boot_retry_case(DesiredAction::Activate, 1).await;
}

#[tokio::test]
async fn boot_retry_survives_a_noop_generation_being_acked() {
    boot_retry_case(DesiredAction::Noop, 5).await;
}

#[tokio::test]
async fn stopping_a_slot_frees_the_port_held_by_a_grandchild() {
    if !node_available() {
        eprintln!("skipping process group test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_ssr(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "const cp=require('child_process');\
cp.spawn(process.execPath,['-e',\"require('http').createServer((q,r)=>r.end('ok')).listen(process.env.PORT,'127.0.0.1')\"],{stdio:'ignore'});\
setInterval(()=>{},1000);",
        15,
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let port = Slot::Blue.loopback_port(cfg.port_base).unwrap();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(20)
        )
        .await
    );

    write_desired_action(data, 2, Slot::Blue, DesiredAction::Evict, Some(Slot::Blue));
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 2 && s.slots.blue.state == SlotState::Stopped,
            Duration::from_secs(10)
        )
        .await
    );
    let mut freed = false;
    for _ in 0..40 {
        if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err()
        {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(freed, "grandchild still holds port {port}");
    exe.shutdown().await;
}

#[tokio::test]
async fn crash_with_no_fallback_ends_in_503_not_a_dead_live_slot() {
    if !node_available() {
        eprintln!("skipping crash test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_ssr(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "require('http').createServer((q,r)=>r.end('x')).listen(process.env.PORT,'127.0.0.1',()=>setTimeout(()=>process.exit(1),1500));",
        15,
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    cfg.watch = Duration::from_secs(60);
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.slots.blue.state == SlotState::Failed
                && s.active_slot.is_none()
                && s.last_result
                    .as_ref()
                    .is_some_and(|r| r.outcome == Outcome::Failed),
            Duration::from_secs(25)
        )
        .await
    );
    let (st, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    exe.shutdown().await;
}

#[tokio::test]
async fn boot_does_not_replay_a_restart_executor_generation() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("other.txt", b"unhealthy")],
    );
    let release_path = data.join("releases/blue/release.json");
    let mut manifest = cite_core::read_release(&release_path).unwrap();
    manifest.health.timeout_s = 1;
    write_release(&release_path, &manifest).unwrap();
    write_desired_action(data, 3, Slot::Blue, DesiredAction::RestartExecutor, None);
    let mut exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), exe.exited())
            .await
            .is_err(),
        "stale RestartExecutor was replayed"
    );
    assert!(wait_status(data, |s| s.ack_generation >= 3, Duration::from_secs(2)).await);
    exe.shutdown().await;
}

#[tokio::test]
async fn boot_never_starts_the_slot_named_by_an_evict() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        &[("index.html", b"<html>green</html>")],
    );
    write_desired_action(data, 4, Slot::Blue, DesiredAction::Evict, Some(Slot::Green));
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    let st = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    assert!(st.active_slot.is_none());
    let (code, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    exe.shutdown().await;
}

fn soften_health(data: &Path, slot: Slot, timeout_s: u64) {
    let path = data
        .join("releases")
        .join(slot.as_str())
        .join("release.json");
    let mut manifest = cite_core::read_release(&path).unwrap();
    manifest.health.timeout_s = timeout_s;
    write_release(&path, &manifest).unwrap();
}

#[tokio::test]
async fn a_health_path_that_never_answers_fails_the_gate_instead_of_hanging() {
    if !node_available() {
        eprintln!("skipping hung probe test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_ssr(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "require('http').createServer(()=>{}).listen(process.env.PORT,'127.0.0.1');",
        3,
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 1
                && s.last_result
                    .as_ref()
                    .is_some_and(|r| r.outcome == Outcome::Failed),
            Duration::from_secs(12)
        )
        .await
    );
    exe.shutdown().await;
}

#[tokio::test]
async fn failed_rollback_leaves_the_slot_stopped_and_retryable() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    seal_static(
        data,
        Slot::Green,
        "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        &[("other.txt", b"unhealthy")],
    );
    soften_health(data, Slot::Green, 1);
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(5)
        )
        .await
    );

    write_desired_action(data, 2, Slot::Green, DesiredAction::Rollback, None);
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 2
                && s.slots.green.state == SlotState::Stopped
                && s.last_result
                    .as_ref()
                    .is_some_and(|r| r.generation == 2 && r.outcome == Outcome::Failed),
            Duration::from_secs(8)
        )
        .await
    );

    std::fs::write(
        data.join("releases/green/app/index.html"),
        b"<html>green</html>",
    )
    .unwrap();
    write_desired_action(data, 3, Slot::Green, DesiredAction::Rollback, None);
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 3 && s.active_slot == Some(Slot::Green),
            Duration::from_secs(8)
        )
        .await
    );
    exe.shutdown().await;
}

#[tokio::test]
async fn restart_child_is_refused_when_the_slot_is_not_serving() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("other.txt", b"unhealthy")],
    );
    soften_health(data, Slot::Blue, 1);
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Noop, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    write_desired_action(data, 2, Slot::Blue, DesiredAction::RestartChild, None);
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 2
                && s.last_result.as_ref().is_some_and(|r| {
                    r.generation == 2
                        && r.outcome == Outcome::Failed
                        && r.reason.contains("restart refused")
                }),
            Duration::from_secs(6)
        )
        .await
    );
    exe.shutdown().await;
}

#[tokio::test]
async fn evicting_the_slot_that_is_serving_is_refused_when_not_declared_live() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[("index.html", b"<html>blue</html>")],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(5)
        )
        .await
    );

    write_desired_action(data, 2, Slot::Green, DesiredAction::Evict, Some(Slot::Blue));
    assert!(
        wait_status(
            data,
            |s| s
                .last_result
                .as_ref()
                .is_some_and(|r| r.generation == 2 && r.outcome == Outcome::Failed),
            Duration::from_secs(5)
        )
        .await
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    assert_eq!(st.ack_generation, 1);
    assert_eq!(st.slots.blue.state, SlotState::Live);
    let (code, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(code, StatusCode::OK);
    exe.shutdown().await;
}

#[tokio::test]
async fn shutdown_during_a_health_gate_does_not_ack_or_report_failure() {
    if !node_available() {
        eprintln!("skipping shutdown gate test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    seal_ssr(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "setInterval(()=>{},1000);",
        30,
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    let exe = spawn(cfg).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    tokio::time::timeout(Duration::from_secs(10), exe.shutdown())
        .await
        .expect("shutdown must not wait out the health gate");
    let st = cite_core::read_status(&data.join("status/executor.json")).unwrap();
    assert_eq!(st.ack_generation, 0);
    assert!(
        st.last_result
            .as_ref()
            .is_none_or(|r| r.outcome != Outcome::Failed)
    );
}

#[tokio::test]
async fn large_static_files_stream_ranges_and_skip_gzip_above_the_cap() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    let pattern: Vec<u8> = (0..251u32).map(|i| i as u8).collect();
    let bin: Vec<u8> = pattern
        .iter()
        .cycle()
        .take(3 * 1024 * 1024 + 17)
        .copied()
        .collect();
    let text = vec![b'a'; 9 * 1024 * 1024];
    seal_static(
        data,
        Slot::Blue,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &[
            ("index.html", b"<html>big</html>"),
            ("blob.bin", bin.as_slice()),
            ("huge.txt", text.as_slice()),
        ],
    );
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let exe = spawn(config_from(data, "127.0.0.1:0")).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(5)
        )
        .await
    );

    let (code, headers, body) = http_once(exe.addr, Method::GET, "/blob.bin", &[]).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        headers.get("content-length").unwrap(),
        bin.len().to_string().as_str()
    );
    assert!(body.as_ref() == bin.as_slice());

    let (code, headers, body) = http_once(
        exe.addr,
        Method::GET,
        "/blob.bin",
        &[("range", "bytes=1000000-1000999")],
    )
    .await;
    assert_eq!(code, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers.get("content-length").unwrap(), "1000");
    assert!(body.as_ref() == &bin[1_000_000..1_001_000]);

    let (code, headers, body) = http_once(
        exe.addr,
        Method::GET,
        "/huge.txt",
        &[("accept-encoding", "gzip")],
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert!(headers.get("content-encoding").is_none());
    assert_eq!(body.len(), text.len());

    let (code, headers, body) = http_once(exe.addr, Method::HEAD, "/blob.bin", &[]).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        headers.get("content-length").unwrap(),
        bin.len().to_string().as_str()
    );
    assert!(body.is_empty());
    exe.shutdown().await;
}

#[tokio::test]
async fn restart_child_spawn_failure_is_treated_as_a_crash() {
    if !node_available() {
        eprintln!("skipping restart failure test: node not on PATH");
        return;
    }
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("control")).unwrap();
    std::fs::create_dir_all(data.join("status")).unwrap();
    let bin_dir = data.join("releases/blue/app/node_modules/.bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(
        bin_dir.join("srv"),
        "require('http').createServer((q,r)=>r.end('ok')).listen(process.env.PORT,'127.0.0.1');",
    )
    .unwrap();
    let mut manifest = sample_ssr(Slot::Blue, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    manifest.start_argv = vec!["srv".into()];
    write_release(&data.join("releases/blue/release.json"), &manifest).unwrap();
    write_desired_action(data, 1, Slot::Blue, DesiredAction::Activate, None);
    let mut cfg = config_from(data, "127.0.0.1:0");
    cfg.node_bin = which_node();
    cfg.watch = Duration::from_secs(60);
    let exe = spawn(cfg).await.unwrap();
    assert!(
        wait_status(
            data,
            |s| s.active_slot == Some(Slot::Blue),
            Duration::from_secs(15)
        )
        .await
    );

    std::fs::remove_file(bin_dir.join("srv")).unwrap();
    write_desired_action(data, 2, Slot::Blue, DesiredAction::RestartChild, None);
    assert!(
        wait_status(
            data,
            |s| s.ack_generation >= 2
                && s.slots.blue.state == SlotState::Failed
                && s.active_slot.is_none(),
            Duration::from_secs(20)
        )
        .await
    );
    let (code, _, _) = http_once(exe.addr, Method::GET, "/", &[]).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    exe.shutdown().await;
}
