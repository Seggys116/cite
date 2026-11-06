mod common;

use cite_dockerproxy::policy::{BodyKind, Check, Route};
use cite_dockerproxy::target::normalise;

fn classify(method: &str, target: &str) -> Result<Route, String> {
    common::policy().classify(method, &normalise(target)?)
}

fn allowed(method: &str, target: &str) -> Route {
    classify(method, target).unwrap_or_else(|e| panic!("{method} {target}: {e}"))
}

fn refused(method: &str, target: &str) {
    assert!(
        classify(method, target).is_err(),
        "{method} {target} was allowed"
    );
}

// Registry prefix and image used by the default configuration.
const IMAGE: &str = "ghcr.io/seggys116/cite-manager";

#[test]
// These are the calls the orchestrator issues during a full stack lifecycle.
fn every_call_the_orchestrator_makes_is_routable() {
    assert_eq!(allowed("GET", "/v1.45/_ping"), Route::Ping);
    assert_eq!(allowed("GET", "/_ping"), Route::Ping);
    allowed(
        "POST",
        &format!("/v1.45/images/create?fromImage={IMAGE}&tag=0.2.0-node22"),
    );
    allowed("GET", &format!("/v1.45/images/{IMAGE}:0.2.0-node22/json"));
    allowed(
        "GET",
        "/v1.45/images/ghcr.io/seggys116/cite-executor-rust:0.2.0/json",
    );
    assert_eq!(
        allowed("POST", "/v1.45/volumes/create"),
        Route::VolumeCreate
    );
    allowed("GET", "/v1.45/volumes/cite-shop-blue-data");
    allowed("DELETE", "/v1.45/volumes/cite-shop-blue-data");
    assert_eq!(
        allowed("POST", "/v1.45/networks/create"),
        Route::NetworkCreate
    );
    allowed("GET", "/v1.45/networks/cite-shop-blue-net");
    allowed("DELETE", "/v1.45/networks/cite-shop-blue-egress");
    allowed("POST", "/v1.45/networks/cite-shop-blue-net/connect");
    allowed("POST", "/v1.45/networks/cite-shop-blue-net/disconnect");
    allowed(
        "POST",
        "/v1.45/containers/create?name=cite-shop-blue-manager",
    );
    allowed("POST", "/v1.45/containers/cite-shop-blue-manager/start");
    allowed("POST", "/v1.45/containers/cite-shop-blue-manager/stop?t=10");
    allowed(
        "POST",
        "/v1.45/containers/cite-shop-blue-init/wait?condition=not-running",
    );
    allowed("GET", "/v1.45/containers/cite-shop-blue-manager/json");
    allowed(
        "DELETE",
        "/v1.45/containers/cite-shop-blue-manager?force=true",
    );
}

#[test]
fn container_listing_must_be_pinned_to_managed_containers() {
    let pinned = "%7B%22label%22%3A%5B%22cite.managed%3Dtrue%22%5D%7D";
    assert_eq!(
        allowed(
            "GET",
            &format!("/v1.45/containers/json?all=true&filters={pinned}")
        ),
        Route::ContainerList
    );
    refused("GET", "/v1.45/containers/json");
    refused("GET", "/v1.45/containers/json?all=true");
    refused("GET", "/v1.45/containers/json?filters=%7B%7D");
    refused(
        "GET",
        "/v1.45/containers/json?filters=%7B%22label%22%3A%5B%22other%3D1%22%5D%7D",
    );
    refused(
        "GET",
        "/v1.45/containers/json?filters=%7B%22label%22%3A%5B%22cite.managed%3Dfalse%22%5D%7D",
    );
    refused(
        "GET",
        "/v1.45/containers/json?filters=%7B%22label%22%3A%7B%22cite.managed%3Dtrue%22%3Atrue%7D%7D",
    );
    refused(
        "GET",
        "/v1.45/containers/json?filters=%7B%22label%22%3A%5B%22cite.managed%3Dtrue%22%5D%2C%22name%22%3A%5B%22x%22%5D%7D",
    );
    refused("GET", "/v1.45/containers/json?filters=notjson");
    refused(
        "GET",
        &format!("/v1.45/containers/json?filters={pinned}&size=true"),
    );
    refused(
        "GET",
        &format!("/v1.45/containers/json?filters={pinned}&all=maybe"),
    );
}

#[test]
// Pulls are the only way to bring foreign code onto the host, so each deviation is covered.
fn pull_is_limited_to_cite_images_and_tags() {
    refused("POST", "/v1.45/images/create?fromImage=alpine&tag=latest");
    refused(
        "POST",
        "/v1.45/images/create?fromImage=evil.io/cite-manager&tag=0.2.0-node22",
    );
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-manager&tag=latest",
    );
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-manager&tag=0.2.0",
    );
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-executor-bun&tag=0.2.0-node22",
    );
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-manager&tag=0.2.0-node22&platform=linux/arm64",
    );
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-manager&tag=0.2.0-node22&fromSrc=http://evil/x.tar",
    );
    refused("POST", "/v1.45/images/create?fromSrc=http://evil/x.tar");
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-manager",
    );
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-manager:0.2.0-node22",
    );
    refused(
        "POST",
        "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-manager&tag=0.2.0-node22%0a",
    );
    refused("POST", "/v1.45/images/load");
    refused("GET", "/v1.45/images/json");
    refused("GET", "/v1.45/images/alpine/json");
}

#[test]
// Everything the orchestrator never calls, including methods other than GET, POST and DELETE.
fn unused_engine_endpoints_are_denied() {
    for (method, target) in [
        ("GET", "/v1.45/info"),
        ("GET", "/v1.45/version"),
        ("GET", "/v1.45/events"),
        ("GET", "/v1.45/system/df"),
        ("POST", "/v1.45/build"),
        ("POST", "/v1.45/commit"),
        ("POST", "/v1.45/auth"),
        ("POST", "/v1.45/exec/abc/start"),
        ("POST", "/v1.45/containers/cite-shop-blue-manager/exec"),
        ("POST", "/v1.45/containers/cite-shop-blue-manager/attach"),
        ("POST", "/v1.45/containers/cite-shop-blue-manager/kill"),
        ("POST", "/v1.45/containers/cite-shop-blue-manager/update"),
        (
            "POST",
            "/v1.45/containers/cite-shop-blue-manager/rename?name=x",
        ),
        ("POST", "/v1.45/containers/cite-shop-blue-manager/pause"),
        (
            "PUT",
            "/v1.45/containers/cite-shop-blue-manager/archive?path=/",
        ),
        (
            "GET",
            "/v1.45/containers/cite-shop-blue-manager/archive?path=/",
        ),
        ("GET", "/v1.45/containers/cite-shop-blue-manager/logs"),
        ("GET", "/v1.45/containers/cite-shop-blue-manager/export"),
        ("POST", "/v1.45/containers/prune"),
        ("POST", "/v1.45/volumes/prune"),
        ("POST", "/v1.45/networks/prune"),
        ("POST", "/v1.45/swarm/init"),
        ("GET", "/v1.45/secrets"),
        ("HEAD", "/v1.45/_ping"),
        ("OPTIONS", "/v1.45/_ping"),
        ("PUT", "/v1.45/volumes/create"),
        (
            "PATCH",
            "/v1.45/containers/create?name=cite-shop-blue-manager",
        ),
    ] {
        refused(method, target);
    }
}

#[test]
fn names_outside_the_scheme_are_denied() {
    refused("POST", "/v1.45/containers/create?name=redis");
    refused(
        "POST",
        "/v1.45/containers/create?name=cite-shop-blue-haproxy",
    );
    refused("POST", "/v1.45/containers/create?name=cite-node-haproxy");
    refused("POST", "/v1.45/containers/create");
    refused(
        "POST",
        "/v1.45/containers/create?name=cite-shop-blue-manager&platform=linux/amd64",
    );
    refused(
        "POST",
        "/v1.45/containers/create?name=cite-shop-blue-manager&name=cite-shop-blue-executor",
    );
    refused("DELETE", "/v1.45/containers/cite-node-haproxy?force=true");
    refused("POST", "/v1.45/containers/cite-node-haproxy/stop");
    refused("POST", "/v1.45/containers/cite-node-haproxy/restart");
    refused("GET", "/v1.45/containers/cite-node-haproxy/json");
    refused("DELETE", "/v1.45/volumes/some-other-volume");
    refused("DELETE", "/v1.45/networks/bridge");
    refused("DELETE", "/v1.45/networks/cite_edge");
    refused("POST", "/v1.45/networks/bridge/connect");
    refused("POST", "/v1.45/networks/cite-shop-blue-egress/connect");
    refused("GET", "/v1.45/networks/host");
    refused("GET", "/v1.45/volumes/cite-shop-blue-data/extra");
    refused(
        "POST",
        &format!("/v1.45/containers/{}-blue-manager/start", "cite-A"),
    );
}

#[test]
// Each form is a way a different parser could read the path as something other than what was matched.
fn path_tricks_are_denied() {
    for target in [
        "/v1.45/containers/create/../../..",
        "/v1.45/containers/create/../create?name=cite-shop-blue-manager",
        "/v1.45/containers/cite-shop-blue-manager/../../volumes/create",
        "/v1.45//containers/create?name=cite-shop-blue-manager",
        "/v1.45/containers//create?name=cite-shop-blue-manager",
        "/v1.45/containers/create/?name=cite-shop-blue-manager",
        "/v1.45/containers/%2e%2e/create",
        "/v1.45/containers%2Fcreate?name=cite-shop-blue-manager",
        "/v1.45/containers/create%00?name=cite-shop-blue-manager",
        "/v1.45/%63ontainers/create?name=cite-shop-blue-manager",
        "/v1.45/containers/%252e%252e/create",
        "/v1.45/containers\\create?name=cite-shop-blue-manager",
        "/V1.45/containers/create?name=cite-shop-blue-manager",
        "/v1.45/Containers/create?name=cite-shop-blue-manager",
        "/v1.44/containers/create?name=cite-shop-blue-manager",
        "/v1.45/v1.45/containers/create?name=cite-shop-blue-manager",
        "http://docker/v1.45/_ping",
    ] {
        refused("POST", target);
    }
}

#[test]
fn action_queries_are_constrained() {
    refused(
        "POST",
        "/v1.45/containers/cite-shop-blue-manager/start?detachKeys=x",
    );
    refused(
        "POST",
        "/v1.45/containers/cite-shop-blue-manager/stop?signal=SIGKILL",
    );
    refused(
        "POST",
        "/v1.45/containers/cite-shop-blue-manager/stop?t=9999",
    );
    refused("POST", "/v1.45/containers/cite-shop-blue-manager/stop?t=-1");
    refused(
        "POST",
        "/v1.45/containers/cite-shop-blue-manager/wait?condition=removed",
    );
    refused("DELETE", "/v1.45/containers/cite-shop-blue-manager?v=true");
    refused(
        "DELETE",
        "/v1.45/containers/cite-shop-blue-manager?link=true",
    );
    refused(
        "DELETE",
        "/v1.45/containers/cite-shop-blue-manager?force=yes",
    );
    refused("DELETE", "/v1.45/volumes/cite-shop-blue-data?force=true");
    refused("GET", "/v1.45/networks/cite-shop-blue-net?verbose=true");
    allowed("DELETE", "/v1.45/containers/cite-shop-blue-manager");
    allowed(
        "POST",
        "/v1.45/containers/cite-shop-blue-manager/restart?t=5",
    );
    allowed("POST", "/v1.45/containers/cite-shop-blue-manager/wait");
}

#[test]
fn routes_declare_their_bodies_and_checks() {
    assert_eq!(
        allowed("POST", "/containers/create?name=cite-shop-blue-manager").body(),
        BodyKind::Json
    );
    assert_eq!(allowed("POST", "/volumes/create").body(), BodyKind::Json);
    assert_eq!(allowed("POST", "/networks/create").body(), BodyKind::Json);
    assert_eq!(
        allowed("POST", "/networks/cite-shop-blue-net/connect").body(),
        BodyKind::Json
    );
    assert_eq!(
        allowed("POST", "/containers/cite-shop-blue-manager/start").body(),
        BodyKind::None
    );
    assert_eq!(
        allowed(
            "POST",
            "/images/create?fromImage=ghcr.io/seggys116/cite-manager&tag=0.2.0-node22"
        )
        .body(),
        BodyKind::None
    );
    assert_eq!(
        allowed("DELETE", "/containers/cite-shop-blue-manager").check(),
        Some(Check::Container("cite-shop-blue-manager".to_string()))
    );
    assert_eq!(
        allowed("DELETE", "/volumes/cite-shop-blue-data").check(),
        Some(Check::Volume("cite-shop-blue-data".to_string()))
    );
    assert_eq!(
        allowed("POST", "/networks/cite-shop-blue-net/connect").check(),
        Some(Check::Network("cite-shop-blue-net".to_string()))
    );
    assert_eq!(
        allowed("GET", "/containers/cite-shop-blue-manager/json").check(),
        None
    );
    let logs = allowed(
        "GET",
        "/containers/cite-shop-blue-manager/logs?stdout=1&tail=10",
    );
    assert_eq!(logs.body(), BodyKind::None);
    assert_eq!(
        logs.check(),
        Some(Check::Container("cite-shop-blue-manager".to_string()))
    );
    assert_eq!(
        allowed("POST", "/containers/create?name=cite-shop-blue-manager").check(),
        None
    );
}

#[test]
fn logs_are_a_bounded_read_of_stack_containers() {
    let base = "containers/cite-shop-blue-manager/logs";
    for target in [
        format!("/{base}?stdout=1&tail=100"),
        format!("/v1.45/{base}?stdout=1&tail=100"),
        format!("/v1.99/{base}?stderr=true&tail=1"),
        format!("/v1.45/{base}?stdout=true&stderr=true&tail=1000"),
        format!(
            "/v1.45/{base}?stdout=1&stderr=1&tail=50&timestamps=true&since=1700000000.123456789"
        ),
        format!("/v1.45/{base}?stdout=1&tail=5&since=12345678901234567890"),
        format!("/v1.45/{base}?stdout=1&tail=5&since=0"),
        format!("/v1.45/{base}?stdout=1&tail=5&timestamps=0"),
        format!("/v1.45/{base}?stdout=1&tail=5&timestamps=false"),
        format!("/v1.45/{base}?stdout=1&tail=5&timestamps=1"),
    ] {
        assert_eq!(
            allowed("GET", &target),
            Route::ContainerLogs("cite-shop-blue-manager".to_string()),
            "{target}"
        );
    }
    for name in ["cite-shop-green-executor", "cite-shop-blue-init"] {
        allowed(
            "GET",
            &format!("/v1.45/containers/{name}/logs?stdout=1&tail=5"),
        );
    }
}

#[test]
fn log_requests_outside_the_allowlist_are_refused() {
    let base = "/v1.45/containers/cite-shop-blue-manager/logs";
    for query in [
        "",
        "stdout=1",
        "stderr=1",
        "tail=10",
        "stdout=1&tail=all",
        "stdout=1&tail=0",
        "stdout=1&tail=1001",
        "stdout=1&tail=99999",
        "stdout=1&tail=-1",
        "stdout=1&tail=1.5",
        "stdout=1&tail=1e2",
        "stdout=1&tail=",
        "stdout=1&tail=%20",
        "stdout=1&tail=00001",
        "stdout=0&tail=10",
        "stdout=false&tail=10",
        "stdout=yes&tail=10",
        "stdout=1&stderr=0&tail=10",
        "stdout=&tail=10",
        "stdout=1&tail=10&follow=1",
        "stdout=1&tail=10&follow=true",
        "stdout=1&tail=10&follow=0",
        "stdout=1&tail=10&until=1700000000",
        "stdout=1&tail=10&details=true",
        "stdout=1&tail=10&details=1",
        "stdout=1&tail=10&unknown=1",
        "stdout=1&tail=10&Stdout=1",
        "stdout=1&tail=10&since=abc",
        "stdout=1&tail=10&since=",
        "stdout=1&tail=10&since=.",
        "stdout=1&tail=10&since=.5",
        "stdout=1&tail=10&since=5.",
        "stdout=1&tail=10&since=1.2.3",
        "stdout=1&tail=10&since=-5",
        "stdout=1&tail=10&since=1e9",
        "stdout=1&tail=10&since=2024-01-01T00:00:00Z",
        "stdout=1&tail=10&since=123456789012345678901",
        "stdout=1&tail=10&timestamps=2",
        "stdout=1&tail=10&timestamps=yes",
        "stdout=1&tail=10&timestamps=",
        "stdout=1&tail=10&stdout=1",
    ] {
        refused("GET", &format!("{base}?{query}"));
    }
}

#[test]
fn log_requests_need_a_stack_name_and_the_get_method() {
    let query = "stdout=1&tail=10";
    for name in [
        "cite-node-haproxy",
        "redis",
        "cite-shop-blue-manager-2",
        "cite-SHOP-blue-manager",
        "cite-shop-red-manager",
    ] {
        refused("GET", &format!("/v1.45/containers/{name}/logs?{query}"));
    }
    for method in ["POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
        refused(
            method,
            &format!("/v1.45/containers/cite-shop-blue-manager/logs?{query}"),
        );
    }
    refused(
        "GET",
        &format!("/v1.45/containers/cite-shop-blue-manager/logs/extra?{query}"),
    );
    refused(
        "GET",
        &format!("/v1.45/containers/cite-shop-blue-manager/../cite-node-haproxy/logs?{query}"),
    );
}

#[test]
fn registry_comes_from_configuration() {
    let cfg = cite_dockerproxy::config::Config::from_lookup(|k| {
        (k == "CITE_PROXY_REGISTRY").then(|| "registry.example.com:5000/team".to_string())
    })
    .unwrap();
    let policy = cite_dockerproxy::policy::Policy::new(&cfg);
    let ok = normalise(
        "/images/create?fromImage=registry.example.com:5000/team/cite-manager&tag=0.2.0-node22",
    )
    .unwrap();
    assert!(policy.classify("POST", &ok).is_ok());
    let old = normalise("/images/create?fromImage=ghcr.io/seggys116/cite-manager&tag=0.2.0-node22")
        .unwrap();
    assert!(policy.classify("POST", &old).is_err());
    let dotted = normalise(
        "/images/create?fromImage=registryXexample.com:5000/team/cite-manager&tag=0.2.0-node22",
    )
    .unwrap();
    assert!(policy.classify("POST", &dotted).is_err());
}
