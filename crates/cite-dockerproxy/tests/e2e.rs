mod common;

use std::sync::Arc;

use cite_connector::error::ConnectorError;
use cite_connector::orchestrator::Orchestrator;
use cite_edge::model::{HealthCheck, Maintenance, Site, SiteKind, Slot, Source, Upstream};

fn site(id: &str, runtime: &str) -> Site {
    Site {
        id: id.to_string(),
        name: id.to_string(),
        hosts: vec![format!("{id}.example.com")],
        path_regexes: Vec::new(),
        path_prefixes: Vec::new(),
        kind: SiteKind::Site,
        blue: Upstream::default(),
        green: Upstream::default(),
        active: Slot::Blue,
        maintenance: Maintenance::default(),
        health: HealthCheck::default(),
        source: Some(Source {
            repo: "acme/shop".to_string(),
            branch: None,
            runtime: Some(runtime.to_string()),
            node_major: None,
            poll_interval: None,
            secret: None,
            ..Default::default()
        }),
        history: Vec::new(),
        access: Default::default(),
        volumes: Vec::new(),
        outbound: true,
        outbound_rules: Default::default(),
    }
}

// The real orchestrator talks to the real proxy, which forwards to a fake engine.
async fn orchestrator(haproxy: &str) -> (Arc<Orchestrator>, common::FakeDocker) {
    let (addr, docker) = common::proxy_and_docker().await;
    let orch = Orchestrator::new(
        &format!("tcp://{addr}"),
        "cite_edge",
        "0.2.0",
        common::REGISTRY,
    )
    .unwrap()
    .with_haproxy_container(haproxy)
    .unwrap();
    (Arc::new(orch), docker)
}

#[tokio::test]
async fn the_orchestrator_works_through_the_proxy_for_every_runtime() {
    for haproxy in [common::HAPROXY, ""] {
        let (orch, docker) = orchestrator(haproxy).await;
        orch.ping().await.unwrap();
        for (i, runtime) in ["node", "bun", "static", "rust"].into_iter().enumerate() {
            let id = format!("site{i}");
            for slot in [Slot::Blue, Slot::Green] {
                orch.ensure_stack(&site(&id, runtime), slot, None, "ghp_token")
                    .await
                    .unwrap();
                assert!(orch.stack_running(&id, slot).await.unwrap(), "{runtime}");
            }
        }
        let stacks = orch.list_stacks().await.unwrap();
        assert_eq!(stacks.len(), 8);
        let created = docker.world.lock().unwrap().containers.len();
        assert_eq!(
            created, 22,
            "two per stack plus an egress proxy per server stack"
        );
    }
}

#[tokio::test]
async fn stop_redeploy_and_purge_work_through_the_proxy() {
    let (orch, docker) = orchestrator(common::HAPROXY).await;
    let s = site("shop", "node");
    orch.ensure_stack(&s, Slot::Blue, Some("release/1"), "ghp_token")
        .await
        .unwrap();
    orch.stop_stack("shop", Slot::Blue).await.unwrap();
    assert!(!orch.stack_running("shop", Slot::Blue).await.unwrap());
    orch.ensure_stack(&s, Slot::Blue, Some("release/2"), "ghp_rotated")
        .await
        .unwrap();
    assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
    orch.remove_stack("shop", true).await.unwrap();
    let w = docker.world.lock().unwrap();
    assert!(w.containers.is_empty() && w.volumes.is_empty());
    let left: Vec<&String> = w.networks.keys().collect();
    assert_eq!(
        left,
        vec!["cite-egress"],
        "only the node's egress bridge stays"
    );
}

#[tokio::test]
async fn reconcile_reattaches_haproxy_through_the_proxy() {
    let (orch, docker) = orchestrator(common::HAPROXY).await;
    orch.ensure_stack(&site("shop", "node"), Slot::Blue, None, "ghp_token")
        .await
        .unwrap();
    docker
        .world
        .lock()
        .unwrap()
        .networks
        .get_mut("cite-shop-blue-net")
        .unwrap()
        .1
        .clear();
    orch.reconcile_networks().await.unwrap();
    assert!(
        docker.world.lock().unwrap().networks["cite-shop-blue-net"]
            .1
            .contains(common::HAPROXY)
    );
}

#[tokio::test]
async fn foreign_objects_are_refused_end_to_end() {
    let (orch, docker) = orchestrator(common::HAPROXY).await;
    docker
        .world
        .lock()
        .unwrap()
        .add_container("cite-shop-blue-executor", serde_json::json!({}));
    let err = orch.remove_stack("shop", true).await.unwrap_err();
    assert!(matches!(err, ConnectorError::Conflict(_)), "{err}");
    assert!(
        docker
            .world
            .lock()
            .unwrap()
            .containers
            .contains_key("cite-shop-blue-executor")
    );
}

#[tokio::test]
// Replays what reached the engine against the policy to prove nothing relied on a gap.
async fn every_request_in_a_full_lifecycle_is_a_known_route() {
    let (orch, docker) = orchestrator(common::HAPROXY).await;
    orch.ensure_stack(&site("shop", "static"), Slot::Blue, None, "ghp_token")
        .await
        .unwrap();
    orch.stop_stack("shop", Slot::Blue).await.unwrap();
    orch.remove_stack("shop", true).await.unwrap();
    let policy = common::policy();
    for seen in docker.seen() {
        if seen.method == "GET" && seen.uri.contains("/json") && !seen.uri.starts_with("/v1.45") {
            continue;
        }
        let target = cite_dockerproxy::target::normalise(&seen.uri).unwrap();
        assert!(
            policy.classify(&seen.method, &target).is_ok(),
            "{} {}",
            seen.method,
            seen.uri
        );
    }
}
