use cite_edge::status::CAPABILITIES;

use super::*;

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

async fn seed_source_site(h: &Harness, id: &str) {
    let mut json = site_json(id, &format!("{id}.example.com"));
    json["source"] = json!({ "repo": "octo/site" });
    let site: Site = serde_json::from_value(json).expect("site");
    h.state
        .store
        .update("test", "seed", move |cfg| {
            cfg.sites.push(site);
            Ok(())
        })
        .await
        .expect("seed");
}

async fn send(h: &Harness, method: Method, t: &str, path: &str, body: &str) -> reqwest::Response {
    h.http
        .request(method, h.url(path))
        .bearer_auth(t)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("request")
}

#[tokio::test]
async fn every_site_ops_route_needs_a_session() {
    let h = start().await;
    for (method, path) in [
        (Method::GET, "/sites/shop/status"),
        (Method::GET, "/sites/shop/logs"),
        (Method::GET, "/sites/shop/github-token"),
        (Method::PUT, "/sites/shop/github-token"),
        (Method::DELETE, "/sites/shop/github-token"),
        (Method::GET, "/sites/shop/build-env"),
        (Method::PATCH, "/sites/shop/build-env"),
        (Method::GET, "/sites/shop/runtime-env"),
        (Method::PATCH, "/sites/shop/runtime-env"),
    ] {
        let (status, _) = h.call(method.clone(), None, path, None).await;
        assert_eq!(status, 401, "{method} {path}");
    }
}

#[tokio::test]
async fn unknown_sites_and_bad_ids_are_refused() {
    let h = start().await;
    let t = h.token().await;
    for path in [
        "/sites/ghost/status",
        "/sites/ghost/logs",
        "/sites/ghost/github-token",
        "/sites/ghost/build-env",
        "/sites/ghost/runtime-env",
    ] {
        let (status, _) = h.get(&t, path).await;
        assert_eq!(status, 404, "{path}");
    }
    let (status, _) = h.get(&t, "/sites/Bad%20Id/status").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn status_works_for_a_site_without_a_source() {
    let h = start().await;
    let t = h.token().await;
    h.seed_site("blog").await;
    let res = h.get_raw(&t, "/sites/blog/status").await;
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn sites_without_a_source_have_no_token_or_environment() {
    let h = start().await;
    let t = h.token().await;
    h.seed_site("blog").await;
    for path in [
        "/sites/blog/github-token",
        "/sites/blog/build-env",
        "/sites/blog/runtime-env",
        "/sites/blog/logs",
    ] {
        let (status, _) = h.get(&t, path).await;
        assert_eq!(status, 400, "{path}");
    }
    let (status, _) = h
        .put(&t, "/sites/blog/github-token", json!({ "token": TOKEN }))
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn logs_queries_that_are_junk_get_a_400() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    for query in [
        "source=nginx",
        "slot=red",
        "tail=0",
        "tail=1001",
        "tail=abc",
        "since=",
        "since=a%20b",
        "extra=1",
    ] {
        let (status, body) = h.get(&t, &format!("/sites/app/logs?{query}")).await;
        assert_eq!(status, 400, "{query}: {body}");
    }
}

#[tokio::test]
async fn the_token_is_validated_stored_and_never_echoed() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;

    for bad in [
        json!({}),
        json!({ "token": "" }),
        json!({ "token": "has space" }),
        json!({ "token": "x".repeat(513) }),
        json!({ "token": 5 }),
        json!({ "token": TOKEN, "extra": true }),
    ] {
        let (status, body) = h.put(&t, "/sites/app/github-token", bad.clone()).await;
        assert_eq!(status, 400, "{bad}: {body}");
    }

    let res = send(
        &h,
        Method::PUT,
        &t,
        "/sites/app/github-token",
        &json!({ "token": TOKEN }).to_string(),
    )
    .await;
    // The harness has no orchestration, so a valid token is refused cleanly; the stored path is covered in deploy tests.
    assert_eq!(res.status().as_u16(), 400);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let text = res.text().await.unwrap();
    assert!(text.contains("orchestration"), "{text}");
    assert!(!text.contains(TOKEN));

    let res = h.get_raw(&t, "/sites/app/github-token").await;
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["cache-control"], "no-store");
    assert!(!res.text().await.unwrap().contains(TOKEN));

    let (status, body) = h.delete(&t, "/sites/app/github-token").await;
    assert_eq!(status, 400, "{body}");
    assert!(!body.to_string().contains(TOKEN));
}

#[tokio::test]
async fn token_audit_entries_name_the_site_and_never_the_value() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    let (status, _) = h
        .put(&t, "/sites/app/github-token", json!({ "token": TOKEN }))
        .await;
    assert_eq!(status, 400);
    let (status, _) = h.delete(&t, "/sites/app/github-token").await;
    assert_eq!(status, 400);

    let (status, audit) = h.get(&t, "/audit").await;
    assert_eq!(status, 200);
    let text = audit.to_string();
    assert!(!text.contains(TOKEN), "{text}");
    assert!(!text.contains("site.token.set"), "{text}");
}

#[tokio::test]
async fn oversized_and_malformed_env_patches_are_refused() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    for kind in ["build-env", "runtime-env"] {
        let path = format!("/sites/app/{kind}");
        let big = format!("{{\"pad\":\"{}\"}}", "a".repeat(70 * 1024));
        let res = send(&h, Method::PATCH, &t, &path, &big).await;
        assert_eq!(res.status().as_u16(), 413, "{kind}");
        let res = send(&h, Method::PATCH, &t, &path, "").await;
        assert_eq!(res.status().as_u16(), 400, "{kind}");
        let res = send(&h, Method::PATCH, &t, &path, "[1,2]").await;
        assert_eq!(res.status().as_u16(), 400, "{kind}");
    }
}

#[tokio::test]
async fn environment_listings_carry_names_only() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    for kind in ["build-env", "runtime-env"] {
        let (status, body) = h.get(&t, &format!("/sites/app/{kind}")).await;
        assert_eq!(status, 200, "{kind}: {body}");
        let text = body.to_string();
        assert!(!text.contains("value"), "{kind}: {text}");
    }
}

#[tokio::test]
async fn node_capabilities_follow_what_the_node_can_do() {
    let h = start().await;
    let t = h.token().await;
    let (status, node) = h.get(&t, "/node").await;
    assert_eq!(status, 200);
    let caps: Vec<&str> = node["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .map(|v| v.as_str().expect("name"))
        .collect();
    assert!(!caps.is_empty());
    assert!(caps.iter().all(|c| CAPABILITIES.contains(c)));
    for cap in CAPABILITIES
        .iter()
        .filter(|c| c.contains("cert") || c.contains("alert"))
    {
        assert!(caps.contains(cap), "{cap} should always be offered");
    }
    for cap in &caps {
        for needs_stack in [
            "logs", "token", "env", "build", "doppler", "volumes", "outbound", "data-",
        ] {
            assert!(!cap.contains(needs_stack), "{cap} needs an orchestrator");
        }
    }
    // Pin the data capability names exactly; the node here has no orchestrator, so none may be offered.
    const DATA_CAPABILITIES: [&str; 7] = [
        "data-postgres",
        "data-shared",
        "data-external",
        "data-s3",
        "data-backups",
        "data-links",
        "data-transfer",
    ];
    let declared: Vec<&str> = CAPABILITIES
        .iter()
        .copied()
        .filter(|c| c.starts_with("data-"))
        .collect();
    assert_eq!(declared, DATA_CAPABILITIES);
    assert!(
        !caps.iter().any(|c| c.starts_with("data-")),
        "data services need the orchestrator: {caps:?}"
    );
    assert_eq!(node["github"]["api_host"], "api.github.com");
}

#[tokio::test]
async fn data_capabilities_need_the_orchestrator_as_well_as_a_running_data_service() {
    // A data service without an orchestrator is not a working one: still nothing data-* is offered.
    let h = super::data_api::start_with_data_service().await;
    let t = h.token().await;
    let (status, node) = h.get(&t, "/node").await;
    assert_eq!(status, 200);
    let caps = node["capabilities"].as_array().expect("capabilities");
    assert!(
        !caps
            .iter()
            .any(|c| c.as_str().is_some_and(|c| c.starts_with("data-"))),
        "{caps:?}"
    );
}

#[tokio::test]
async fn node_reports_the_host_of_a_custom_github_api() {
    let h = start_with(|cfg| {
        cfg.github_api_url = Some("https://ghe.example.com:8443/api/v3".into());
    })
    .await;
    let t = h.token().await;
    let (status, node) = h.get(&t, "/node").await;
    assert_eq!(status, 200);
    assert_eq!(node["github"]["api_host"], "ghe.example.com");
    assert!(!node.to_string().contains("api/v3"));
}

const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn data_json() -> Value {
    json!({
        "postgres": {
            "mode": "dedicated",
            "major": 18,
            "databases": [{ "name": "app", "users": [{ "name": "app", "level": "readwrite" }] }],
        },
    })
}

async fn seed_data_site(h: &Harness, id: &str) {
    let mut json = site_json(id, &format!("{id}.example.com"));
    json["source"] = json!({ "repo": "octo/site" });
    json["data"] = data_json();
    let site: Site = serde_json::from_value(json).expect("site");
    h.state
        .store
        .update("test", "seed", move |cfg| {
            cfg.sites.push(site);
            Ok(())
        })
        .await
        .expect("seed");
}

async fn get_as(h: &Harness, t: &str, path: &str, client: Option<&str>) -> (u16, Value) {
    let mut req = h.http.get(h.url(path)).bearer_auth(t);
    if let Some(version) = client {
        req = req.header("x-cite-client", version);
    }
    let res = req.send().await.expect("request");
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn site_data_is_sent_only_to_clients_that_announce_this_release_or_newer() {
    let h = start().await;
    let t = h.token().await;
    seed_data_site(&h, "shop").await;
    let current = format!("v{CLIENT_VERSION}");
    let named = format!("cite-client/{CLIENT_VERSION}");
    let pre = format!("{CLIENT_VERSION}-rc.1");
    let cases: [(Option<&str>, bool); 11] = [
        (None, false),
        (Some(""), false),
        (Some("garbage"), false),
        (Some("0.0.1"), false),
        (Some("0.4.0"), false),
        (Some("1.x"), false),
        (Some(CLIENT_VERSION), true),
        (Some(current.as_str()), true),
        (Some(named.as_str()), true),
        (Some(pre.as_str()), true),
        (Some("999.1.0"), true),
    ];
    for (client, sees) in cases {
        let (status, one) = get_as(&h, &t, "/sites/shop", client).await;
        assert_eq!(status, 200, "{client:?}");
        assert_eq!(
            one.get("data").is_some(),
            sees,
            "get with {client:?}: {one}"
        );
        if sees {
            assert_eq!(one["data"]["postgres"]["mode"], "dedicated");
        }
        let (status, list) = get_as(&h, &t, "/sites", client).await;
        assert_eq!(status, 200);
        assert_eq!(
            list[0].get("data").is_some(),
            sees,
            "list with {client:?}: {list}"
        );
        // Everything else about the site is the same either way.
        assert_eq!(one["id"], "shop");
        assert_eq!(one["source"]["repo"], "octo/site");
    }
    // The stored site is never altered by who reads it.
    let stored = h.state.store.config();
    assert!(stored.sites[0].data.postgres.is_some());
}

#[tokio::test]
async fn a_site_payload_cannot_carry_data_in() {
    let h = start().await;
    let t = h.token().await;
    let mut body = site_json("blog", "blog.example.com");
    body["data"] = data_json();
    let (status, created) = h.post(&t, "/sites", body).await;
    assert_eq!(status, 200, "{created}");
    assert!(created.get("data").is_none(), "{created}");
    let stored = h.state.store.config();
    let blog = stored.sites.iter().find(|s| s.id == "blog").expect("site");
    assert!(blog.data.is_empty(), "data comes from the data routes only");
}

#[tokio::test]
async fn deleting_a_site_takes_the_purge_flags_and_reports_what_s3_keeps() {
    let h = start().await;
    let t = h.token().await;
    h.seed_site("blog").await;
    h.seed_site("docs").await;
    for query in ["purge_data=maybe", "purge_volumes=2", "purge=true"] {
        let (status, _) = h.delete(&t, &format!("/sites/blog?{query}")).await;
        assert_eq!(status, 400, "{query}");
    }
    let (status, plain) = h.delete(&t, "/sites/docs").await;
    assert_eq!(status, 200);
    assert_eq!(plain, json!({ "ok": true }));
    let (status, purged) = h.delete(&t, "/sites/blog?purge_data=true").await;
    assert_eq!(status, 200, "{purged}");
    assert_eq!(purged, json!({ "ok": true, "s3_objects_left": 0 }));
    let audit = format!("{:?}", h.state.store.audit_tail(50).await);
    assert!(audit.contains("site.data.purge"), "{audit}");
}

#[tokio::test]
async fn a_deploy_that_does_not_wait_answers_202_with_an_id() {
    let h = start().await;
    let t = h.token().await;
    h.seed_site("blog").await;
    let (status, body) = h
        .post(
            &t,
            "/sites/blog/deploy",
            json!({ "targets": [{ "addr": "10.0.0.2:8080" }], "wait": false }),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    assert!(body["deployment_id"].is_string(), "{body}");

    let (status, _) = h
        .post(&t, "/sites/blog/deploy", json!({ "wait": "later" }))
        .await;
    assert_eq!(status, 400);
}
