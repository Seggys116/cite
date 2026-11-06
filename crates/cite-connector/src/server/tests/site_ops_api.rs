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
            "logs", "token", "env", "build", "doppler", "volumes", "outbound",
        ] {
            assert!(!cap.contains(needs_stack), "{cap} needs an orchestrator");
        }
    }
    assert_eq!(node["github"]["api_host"], "api.github.com");
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
