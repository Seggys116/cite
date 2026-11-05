mod common;

use std::time::Duration;

use cite_connector::orchestrator::{StackEnv, stack_specs};
use cite_dockerproxy::config::Config;
use cite_dockerproxy::proxy::healthcheck;
use cite_edge::model::{HealthCheck, Maintenance, Site, SiteKind, Slot, Source, Upstream};
use common::{build, call, call_json, proxy_and_docker, raw, start_proxy};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MANAGED: &str = "cite-shop-blue-manager";

fn managed_labels() -> Value {
    json!({ "cite.managed": "true", "cite.site": "shop", "cite.slot": "blue", "cite.role": "manager" })
}

// Built by the orchestrator itself, so the test breaks if the two drift apart.
fn manager_spec() -> (String, Value) {
    let site = Site {
        id: "shop".to_string(),
        name: "shop".to_string(),
        hosts: vec!["shop.example.com".to_string()],
        path_regex: None,
        kind: SiteKind::Site,
        blue: Upstream::default(),
        green: Upstream::default(),
        active: Slot::Blue,
        maintenance: Maintenance::default(),
        health: HealthCheck::default(),
        source: Some(Source {
            repo: "acme/shop".to_string(),
            branch: None,
            runtime: None,
            node_major: None,
            poll_interval: None,
            secret: None,
        }),
        history: Vec::new(),
    };
    let env = StackEnv {
        registry: common::REGISTRY,
        version: "0.2.0",
        edge_network: "cite_edge",
        isolate: true,
    };
    let specs = stack_specs(&site, Slot::Blue, None, "ghp_token", &env).unwrap();
    (specs.manager_name, specs.manager)
}

fn denied_body(r: &common::Reply) -> bool {
    r.status == 403 && r.text() == "{\"message\":\"denied\"}"
}

#[tokio::test]
async fn ping_is_forwarded_with_its_version_prefix() {
    let (addr, docker) = proxy_and_docker().await;
    let r = call(addr, "GET", "/v1.45/_ping").await;
    assert_eq!((r.status, r.text()), (200, "OK".to_string()));
    let seen = docker.seen();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].uri.as_str()),
        ("GET", "/v1.45/_ping")
    );
}

#[tokio::test]
async fn denied_requests_never_reach_docker() {
    let (addr, docker) = proxy_and_docker().await;
    for (method, target) in [
        ("GET", "/v1.45/info"),
        ("GET", "/v1.45/version"),
        ("POST", "/v1.45/build"),
        ("POST", "/v1.45/containers/cite-shop-blue-manager/exec"),
        ("POST", "/v1.45/containers/cite-shop-blue-manager/kill"),
        (
            "PUT",
            "/v1.45/containers/cite-shop-blue-manager/archive?path=/",
        ),
        ("GET", "/v1.45/containers/json"),
        ("POST", "/v1.45/images/create?fromImage=alpine&tag=latest"),
        ("GET", "/v1.45/containers/../volumes"),
        ("GET", "/v1.45/containers%2Fjson"),
        ("DELETE", "/v1.45/containers/redis?force=true"),
    ] {
        let r = call(addr, method, target).await;
        assert!(
            denied_body(&r),
            "{method} {target}: {} {}",
            r.status,
            r.text()
        );
    }
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn container_create_is_forwarded_byte_exact() {
    let (addr, docker) = proxy_and_docker().await;
    let (name, spec) = manager_spec();
    let bytes = serde_json::to_vec(&spec).unwrap();
    let target = format!("/v1.45/containers/create?name={name}");
    let r = raw(
        addr,
        &build(
            "POST",
            &target,
            &[("Content-Type", "application/json")],
            &bytes,
        ),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 201);
    let seen = docker.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].uri, target);
    assert_eq!(seen[0].body, bytes);
    assert_eq!(seen[0].header("content-type"), Some("application/json"));
}

#[tokio::test]
async fn privileged_create_is_denied_before_docker() {
    let (addr, docker) = proxy_and_docker().await;
    let (name, mut spec) = manager_spec();
    spec["HostConfig"]["Privileged"] = json!(true);
    spec["HostConfig"]["Binds"] = json!(["/:/host"]);
    let r = call_json(
        addr,
        "POST",
        &format!("/v1.45/containers/create?name={name}"),
        &spec,
    )
    .await;
    assert!(denied_body(&r));
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn bodies_need_a_json_content_type() {
    let (addr, docker) = proxy_and_docker().await;
    let (name, spec) = manager_spec();
    let bytes = serde_json::to_vec(&spec).unwrap();
    let target = format!("/v1.45/containers/create?name={name}");
    for headers in [
        vec![],
        vec![("Content-Type", "text/plain")],
        vec![("Content-Type", "application/x-www-form-urlencoded")],
    ] {
        let r = raw(addr, &build("POST", &target, &headers, &bytes))
            .await
            .unwrap();
        assert!(denied_body(&r), "{headers:?}");
    }
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn oversized_and_malformed_bodies_are_denied() {
    let (addr, docker) = proxy_and_docker().await;
    let target = "/v1.45/volumes/create";
    let big = vec![b' '; 70 * 1024];
    let r = raw(
        addr,
        &build(
            "POST",
            target,
            &[("Content-Type", "application/json")],
            &big,
        ),
    )
    .await
    .unwrap();
    assert!(denied_body(&r));
    let r = raw(
        addr,
        &build(
            "POST",
            target,
            &[("Content-Type", "application/json")],
            b"{not json",
        ),
    )
    .await
    .unwrap();
    assert!(denied_body(&r));
    let r = raw(
        addr,
        &build(
            "POST",
            target,
            &[("Content-Type", "application/json")],
            b"{} {\"Name\":\"x\"}",
        ),
    )
    .await
    .unwrap();
    assert!(denied_body(&r));
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn chunked_bodies_are_refused() {
    let (addr, docker) = proxy_and_docker().await;
    let body = b"{\"Name\":\"cite-shop-blue-data\"}";
    let mut req = b"POST /v1.45/volumes/create HTTP/1.1\r\nHost: p\r\nConnection: close\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    req.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
    req.extend_from_slice(body);
    req.extend_from_slice(b"\r\n0\r\n\r\n");
    let r = raw(addr, &req).await.unwrap();
    assert!(denied_body(&r));
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
// The second request hidden in the body must never be seen by the engine.
async fn smuggling_with_length_and_transfer_encoding_is_neutralised() {
    let (addr, docker) = proxy_and_docker().await;
    let smuggled = "GET /v1.45/info HTTP/1.1\r\nHost: p\r\n\r\n";
    let body = format!("0\r\n\r\n{smuggled}");
    let req = format!(
        "POST /v1.45/volumes/create HTTP/1.1\r\nHost: p\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n{body}",
        body.len()
    );
    let reply = raw(addr, req.as_bytes()).await;
    if let Some(r) = reply {
        assert!(r.status == 403 || r.status == 400, "status {}", r.status);
    }
    assert!(docker.seen().iter().all(|s| !s.uri.contains("/info")));
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn duplicate_content_length_is_not_forwarded() {
    let (addr, docker) = proxy_and_docker().await;
    let req = b"POST /v1.45/volumes/create HTTP/1.1\r\nHost: p\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 40\r\n\r\n{}";
    let reply = raw(addr, req).await;
    if let Some(r) = reply {
        assert!(r.status >= 400);
    }
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
// Any upgrade attempt would open a hijacked stream, which the proxy never allows.
async fn upgrade_requests_are_denied() {
    let (addr, docker) = proxy_and_docker().await;
    for headers in [
        vec![("Upgrade", "tcp"), ("Connection", "Upgrade")],
        vec![("Upgrade", "h2c")],
        vec![("Connection", "keep-alive, Upgrade")],
    ] {
        let r = raw(addr, &build("GET", "/v1.45/_ping", &headers, b""))
            .await
            .unwrap();
        assert!(denied_body(&r), "{headers:?}");
    }
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn absolute_form_and_odd_targets_are_denied() {
    let (addr, docker) = proxy_and_docker().await;
    for target in ["http://docker/v1.45/_ping", "*", "v1.45/_ping"] {
        let reply = raw(addr, &build("GET", target, &[], b"")).await;
        if let Some(r) = reply {
            assert!(r.status == 403 || r.status == 400, "{target}: {}", r.status);
        }
    }
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn get_and_delete_with_a_body_are_denied() {
    let (addr, docker) = proxy_and_docker().await;
    docker
        .world
        .lock()
        .unwrap()
        .add_container(MANAGED, managed_labels());
    let before = docker.seen_count();
    let r = raw(
        addr,
        &build(
            "GET",
            "/v1.45/_ping",
            &[("Content-Type", "application/json")],
            b"{}",
        ),
    )
    .await
    .unwrap();
    assert!(denied_body(&r));
    let r = raw(
        addr,
        &build(
            "DELETE",
            &format!("/v1.45/containers/{MANAGED}"),
            &[("Content-Type", "application/json")],
            b"{}",
        ),
    )
    .await
    .unwrap();
    assert!(denied_body(&r));
    assert_eq!(docker.seen_count(), before);
}

#[tokio::test]
// The label check is a separate GET to the engine before the delete is sent.
async fn managed_container_delete_is_inspected_then_forwarded() {
    let (addr, docker) = proxy_and_docker().await;
    docker
        .world
        .lock()
        .unwrap()
        .add_container(MANAGED, managed_labels());
    let r = call(
        addr,
        "DELETE",
        &format!("/v1.45/containers/{MANAGED}?force=true"),
    )
    .await;
    assert_eq!(r.status, 204);
    let log = docker.world.lock().unwrap().log();
    assert_eq!(
        log,
        vec![
            format!("GET /containers/{MANAGED}/json"),
            format!("DELETE /v1.45/containers/{MANAGED}?force=true")
        ]
    );
}

#[tokio::test]
async fn foreign_container_delete_is_denied_after_inspection() {
    let (addr, docker) = proxy_and_docker().await;
    docker
        .world
        .lock()
        .unwrap()
        .add_container(MANAGED, json!({}));
    let r = call(
        addr,
        "DELETE",
        &format!("/v1.45/containers/{MANAGED}?force=true"),
    )
    .await;
    assert!(denied_body(&r));
    assert!(docker.seen().iter().all(|s| s.method == "GET"));
    let r = call(addr, "POST", &format!("/v1.45/containers/{MANAGED}/start")).await;
    assert!(denied_body(&r));
    assert!(docker.seen().iter().all(|s| s.method == "GET"));
}

#[tokio::test]
async fn missing_container_gets_a_local_not_found() {
    let (addr, docker) = proxy_and_docker().await;
    let r = call(
        addr,
        "DELETE",
        &format!("/v1.45/containers/{MANAGED}?force=true"),
    )
    .await;
    assert_eq!(r.status, 404);
    assert!(docker.seen().iter().all(|s| s.method == "GET"));
}

#[tokio::test]
async fn foreign_volumes_and_networks_cannot_be_deleted() {
    let (addr, docker) = proxy_and_docker().await;
    {
        let mut w = docker.world.lock().unwrap();
        w.volumes
            .insert("cite-shop-blue-data".to_string(), json!({}));
        w.networks.insert(
            "cite-shop-blue-net".to_string(),
            (json!({}), Default::default()),
        );
    }
    assert!(denied_body(
        &call(addr, "DELETE", "/v1.45/volumes/cite-shop-blue-data").await
    ));
    assert!(denied_body(
        &call(addr, "DELETE", "/v1.45/networks/cite-shop-blue-net").await
    ));
    assert!(docker.seen().iter().all(|s| s.method == "GET"));
    docker
        .world
        .lock()
        .unwrap()
        .volumes
        .insert("cite-shop-blue-data".to_string(), managed_labels());
    assert_eq!(
        call(addr, "DELETE", "/v1.45/volumes/cite-shop-blue-data")
            .await
            .status,
        204
    );
}

#[tokio::test]
async fn only_haproxy_is_attached_to_a_managed_stack_network() {
    let (addr, docker) = proxy_and_docker().await;
    docker.world.lock().unwrap().networks.insert(
        "cite-shop-blue-net".to_string(),
        (managed_labels(), Default::default()),
    );
    let target = "/v1.45/networks/cite-shop-blue-net/connect";
    assert!(denied_body(
        &call_json(addr, "POST", target, &json!({ "Container": MANAGED })).await
    ));
    assert!(denied_body(
        &call_json(
            addr,
            "POST",
            target,
            &json!({ "Container": common::HAPROXY, "EndpointConfig": {} })
        )
        .await
    ));
    assert_eq!(
        docker.seen().iter().filter(|s| s.method == "POST").count(),
        0
    );
    let ok = call_json(
        addr,
        "POST",
        target,
        &json!({ "Container": common::HAPROXY }),
    )
    .await;
    assert_eq!(ok.status, 200);
    let w = docker.world.lock().unwrap();
    assert!(w.networks["cite-shop-blue-net"].1.contains(common::HAPROXY));
}

#[tokio::test]
async fn pull_query_is_forwarded_unchanged_and_progress_is_streamed() {
    let (addr, docker) = proxy_and_docker().await;
    let target =
        "/v1.45/images/create?fromImage=ghcr.io%2Fseggys116%2Fcite-manager&tag=0.2.0-node22";
    let r = call(addr, "POST", target).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.text(),
        "{\"status\":\"Pulling\"}\n{\"status\":\"Done\"}\n"
    );
    assert_eq!(docker.seen()[0].uri, target);
    assert!(r.header("keep-alive").is_none());
    assert_eq!(r.header("api-version"), Some("1.45"));
}

#[tokio::test]
async fn only_cite_images_are_pulled() {
    let (addr, docker) = proxy_and_docker().await;
    for target in [
        "/v1.45/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=latest",
        "/v1.45/images/create?fromImage=ghcr.io%2Fseggys116%2Fcite-manager&tag=0.2.0-node22&platform=linux%2Farm64",
        "/v1.45/images/create?fromImage=ghcr.io%2Fseggys116%2Fcite-manager&fromImage=alpine&tag=0.2.0-node22",
    ] {
        assert!(denied_body(&call(addr, "POST", target).await), "{target}");
    }
    assert_eq!(docker.seen_count(), 0);
}

#[tokio::test]
async fn listing_query_is_forwarded_when_pinned() {
    let (addr, docker) = proxy_and_docker().await;
    let pinned = "/v1.45/containers/json?all=true&filters=%7B%22label%22%3A%5B%22cite.managed%3Dtrue%22%5D%7D";
    assert_eq!(call(addr, "GET", pinned).await.status, 200);
    assert_eq!(docker.seen()[0].uri, pinned);
    assert!(denied_body(
        &call(addr, "GET", "/v1.45/containers/json?all=true").await
    ));
}

#[tokio::test]
// Credentials and forwarding headers from the client must not reach the engine.
async fn client_headers_are_not_passed_to_docker() {
    let (addr, docker) = proxy_and_docker().await;
    let headers = [
        ("X-Registry-Auth", "c2VjcmV0"),
        ("Authorization", "Bearer x"),
        ("X-Forwarded-For", "1.2.3.4"),
        ("Proxy-Authorization", "x"),
        ("X-Custom", "1"),
    ];
    let r = raw(addr, &build("GET", "/v1.45/_ping", &headers, b""))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    let seen = &docker.seen()[0];
    for (name, _) in headers {
        assert!(seen.header(name).is_none(), "{name} leaked");
    }
    assert_eq!(seen.header("host"), Some("docker"));
}

#[tokio::test]
async fn a_dead_socket_gives_bad_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start_proxy(&dir.path().join("missing.sock")).await;
    let r = call(addr, "GET", "/v1.45/_ping").await;
    assert_eq!(r.status, 502);
    assert_eq!(r.text(), "{\"message\":\"upstream unavailable\"}");
}

#[tokio::test]
async fn keep_alive_connections_keep_enforcing_policy() {
    let (addr, docker) = proxy_and_docker().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let first = b"GET /v1.45/_ping HTTP/1.1\r\nHost: p\r\n\r\n";
    let second = b"GET /v1.45/info HTTP/1.1\r\nHost: p\r\nConnection: close\r\n\r\n";
    stream.write_all(first).await.unwrap();
    stream.write_all(second).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("HTTP/1.1 200"));
    assert!(text.contains("HTTP/1.1 403"));
    assert_eq!(docker.seen_count(), 1);
}

#[tokio::test]
// With one permit, a second connection is not served until the first closes.
async fn connections_are_capped() {
    let docker = common::FakeDocker::start().await;
    let socket = docker.path.display().to_string();
    let cfg = Config::from_lookup(|k| match k {
        "CITE_PROXY_SOCKET" => Some(socket.clone()),
        "CITE_PROXY_MAX_CONNS" => Some("1".to_string()),
        _ => None,
    })
    .unwrap();
    let addr = common::start_proxy_with(cfg).await;
    let hog = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = TcpStream::connect(addr).await.unwrap();
    second
        .write_all(&build("GET", "/_ping", &[], b""))
        .await
        .unwrap();
    let mut buf = Vec::new();
    let blocked =
        tokio::time::timeout(Duration::from_millis(300), second.read_to_end(&mut buf)).await;
    assert!(
        blocked.is_err(),
        "second connection was served while the first was open"
    );
    drop(hog);
    tokio::time::timeout(Duration::from_secs(5), second.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf).contains("HTTP/1.1 200"));
}

#[tokio::test]
async fn healthcheck_reports_proxy_and_docker_state() {
    let (addr, _docker) = proxy_and_docker().await;
    healthcheck(addr).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let broken = start_proxy(&dir.path().join("missing.sock")).await;
    assert!(healthcheck(broken).await.is_err());
    let closed = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    assert!(healthcheck(closed).await.is_err());
}
