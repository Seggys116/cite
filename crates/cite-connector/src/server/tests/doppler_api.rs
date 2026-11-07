use std::sync::Arc;

use crate::doppler::mock::{self, MockDoppler, Mode};
use crate::doppler::{DopplerClient, NO_TOKEN};

use super::*;

const DOPPLER_TOKEN: &str = "dp.st.prd.routesecretvalue";
const SECRET_VALUE: &str = "postgres://user:hunter2@db";

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

async fn with_mock(h: &Harness) -> MockDoppler {
    let server = mock::start(DOPPLER_TOKEN).await;
    server.state.set(
        "shop",
        "prd",
        json!({ "DATABASE_URL": SECRET_VALUE, "PUBLIC_URL": "https://shop", "DOPPLER_CONFIG": "prd" }),
    );
    let client = DopplerClient::local(&server.base).expect("client");
    h.state.doppler.set_source(Arc::new(client));
    server
}

async fn start_with_node_token() -> Harness {
    start_with(|cfg| {
        cfg.doppler_token = Some(
            crate::config::NodeToken::new(DOPPLER_TOKEN, crate::config::TokenSource::Env).unwrap(),
        );
    })
    .await
}

#[tokio::test]
async fn every_doppler_route_needs_a_session() {
    let h = start().await;
    for (method, path) in [
        (Method::GET, "/doppler/projects"),
        (Method::GET, "/doppler/projects/shop/configs"),
        (Method::GET, "/sites/shop/doppler"),
        (Method::PUT, "/sites/shop/doppler"),
        (Method::DELETE, "/sites/shop/doppler"),
        (Method::POST, "/sites/shop/doppler/sync"),
    ] {
        let (status, _) = h.call(method.clone(), None, path, None).await;
        assert_eq!(status, 401, "{method} {path}");
    }
}

#[tokio::test]
async fn the_node_reports_the_doppler_token_source_but_never_the_token() {
    let h = start_with_node_token().await;
    let t = h.token().await;
    let (status, node) = h.get(&t, "/node").await;
    assert_eq!(status, 200);
    assert_eq!(
        node["doppler"],
        json!({ "configured": true, "source": "env" })
    );
    assert!(!node.to_string().contains("routesecretvalue"));
    let caps = node["capabilities"].to_string();
    assert!(
        !caps.contains("doppler"),
        "doppler needs the orchestrator: {caps}"
    );
}

#[tokio::test]
async fn projects_and_configs_list_through_the_node_token() {
    let h = start_with_node_token().await;
    let t = h.token().await;
    let _server = with_mock(&h).await;
    let res = h.get_raw(&t, "/doppler/projects").await;
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!([{ "slug": "shop", "name": "Project shop" }]));
    let (status, body) = h.get(&t, "/doppler/projects/shop/configs").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!([{ "name": "prd", "environment": "prd" }]));
    for bad in ["bad%20slug", "a%2Fb", &"a".repeat(101)] {
        let (status, _) = h.get(&t, &format!("/doppler/projects/{bad}/configs")).await;
        assert_eq!(status, 400, "{bad}");
    }
    let (status, body) = h.get(&t, "/doppler/projects/ghost/configs").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn listing_without_a_node_token_says_how_to_set_one() {
    let h = start().await;
    let t = h.token().await;
    let (status, body) = h.get(&t, "/doppler/projects").await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], NO_TOKEN);
}

#[tokio::test]
async fn a_binding_syncs_reports_and_never_echoes_values_or_tokens() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    let server = with_mock(&h).await;

    let (status, view) = h.get(&t, "/sites/app/doppler").await;
    assert_eq!(status, 200);
    assert_eq!(view["bound"], false);
    assert_eq!(view["status"], "idle");
    assert_eq!(view["token_source"], "none");

    let res = h
        .http
        .put(h.url("/sites/app/doppler"))
        .bearer_auth(&t)
        .json(&json!({
            "project": "shop", "config": "prd", "build": true, "runtime": true,
            "token": DOPPLER_TOKEN
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let text = res.text().await.unwrap();
    assert!(
        !text.contains(SECRET_VALUE) && !text.contains("routesecretvalue"),
        "{text}"
    );
    let view: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(view["bound"], true);
    assert_eq!(view["project"], "shop");
    assert_eq!(view["config"], "prd");
    assert_eq!(view["status"], "synced");
    assert_eq!(view["token_source"], "site");
    assert_eq!(view["keys"], 2);
    assert!(view["last_sync_at"].is_string());
    assert_eq!(
        view["redeploy_needed"], true,
        "no orchestrator in the harness"
    );
    assert!(
        view["last_error"]
            .as_str()
            .unwrap()
            .contains("DOPPLER_CONFIG")
    );
    assert_eq!(server.state.downloads(), 1);

    let (_, site) = h.get(&t, "/sites/app").await;
    assert_eq!(site["source"]["doppler"]["project"], "shop");
    assert!(!site.to_string().contains(SECRET_VALUE));
    let (_, names) = h.get(&t, "/sites/app/build-env").await;
    assert_eq!(
        names,
        json!({ "names": [] }),
        "manual variables are separate"
    );

    server
        .state
        .set("shop", "prd", json!({ "PUBLIC_URL": "https://shop2" }));
    let (status, view) = h.post(&t, "/sites/app/doppler/sync", json!({})).await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["keys"], 1);
    assert_eq!(view["skipped"], json!([]));
    assert!(
        view["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("next deploy")),
        "the change still waits for a deploy: {view}"
    );

    let (_, audit) = h.get(&t, "/audit?limit=200").await;
    let audit = audit.to_string();
    for action in [
        "site.doppler.bind",
        "site.doppler.sync",
        "site.doppler.token.set",
        "site.doppler.sync.request",
    ] {
        assert!(audit.contains(action), "{action}: {audit}");
    }
    assert!(
        !audit.contains(SECRET_VALUE) && !audit.contains("https://shop"),
        "{audit}"
    );
    assert!(!audit.contains("routesecretvalue"), "{audit}");

    let (status, view) = h.delete(&t, "/sites/app/doppler").await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["bound"], false);
    assert_eq!(view["redeploy_needed"], true);
    assert_eq!(view["token_source"], "none");
    let (status, _) = h.post(&t, "/sites/app/doppler/sync", json!({})).await;
    assert_eq!(status, 400, "an unbound site has nothing to sync");
}

#[tokio::test]
async fn a_failed_first_sync_keeps_nothing() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    let server = with_mock(&h).await;
    server.state.mode(Mode::Status(401));
    let (status, body) = h
        .put(
            &t,
            "/sites/app/doppler",
            json!({ "project": "shop", "config": "prd", "build": true, "token": DOPPLER_TOKEN }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("rejected"),
        "{body}"
    );
    assert!(!body.to_string().contains("routesecretvalue"));
    let (_, view) = h.get(&t, "/sites/app/doppler").await;
    assert_eq!(view["bound"], false);
    assert_eq!(view["token_source"], "none");
    let (_, site) = h.get(&t, "/sites/app").await;
    assert!(site["source"].get("doppler").is_none(), "{site}");

    server.state.mode(Mode::Normal);
    let (status, body) = h
        .put(
            &t,
            "/sites/app/doppler",
            json!({ "project": "shop", "config": "prd", "build": true }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], NO_TOKEN);
}

#[tokio::test]
async fn binding_requests_are_validated_strictly() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    h.seed_site("blog").await;
    let _server = with_mock(&h).await;
    for bad in [
        json!({ "project": "shop", "config": "prd" }),
        json!({ "project": "", "config": "prd", "build": true }),
        json!({ "project": "shop shop", "config": "prd", "build": true }),
        json!({ "project": "shop", "config": "a".repeat(101), "build": true }),
        json!({ "project": "shop", "config": "prd", "build": "yes" }),
        json!({ "project": "shop", "config": "prd", "build": true, "extra": 1 }),
        json!({ "project": "shop", "config": "prd", "build": true, "token": "has space" }),
        json!({ "config": "prd", "build": true }),
    ] {
        let (status, body) = h.put(&t, "/sites/app/doppler", bad.clone()).await;
        assert_eq!(status, 400, "{bad}: {body}");
    }
    let big =
        json!({ "project": "shop", "config": "prd", "build": true, "token": "a".repeat(5000) });
    let res = h
        .http
        .put(h.url("/sites/app/doppler"))
        .bearer_auth(&t)
        .json(&big)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 413);
    let ok = json!({ "project": "shop", "config": "prd", "build": true, "token": DOPPLER_TOKEN });
    let (status, _) = h.put(&t, "/sites/blog/doppler", ok.clone()).await;
    assert_eq!(status, 400, "a site without a source cannot be bound");
    let (status, _) = h.put(&t, "/sites/ghost/doppler", ok).await;
    assert_eq!(status, 404);
    let (status, _) = h.get(&t, "/sites/Bad%20Id/doppler").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn a_service_token_alone_binds_without_naming_a_project_or_config() {
    let h = start().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    let server = with_mock(&h).await;
    server.state.set(
        "",
        "",
        json!({ "API_KEY": SECRET_VALUE, "PUBLIC_URL": "https://shop" }),
    );
    let (status, view) = h
        .put(
            &t,
            "/sites/app/doppler",
            json!({ "project": "", "config": "", "runtime": true, "token": DOPPLER_TOKEN }),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["bound"], true);
    assert_eq!(view["project"], Value::Null);
    assert_eq!(view["config"], Value::Null);
    assert_eq!(view["token_source"], "site");
    assert_eq!(view["keys"], 2);
    assert_eq!(
        *server.state.download_params.lock().unwrap(),
        vec![(None, None)],
        "the service token implies the project and config"
    );
    let text = view.to_string();
    assert!(!text.contains(SECRET_VALUE) && !text.contains("routesecretvalue"));
    let (_, site) = h.get(&t, "/sites/app").await;
    assert_eq!(site["source"]["doppler"]["project"], "");
    assert!(!site.to_string().contains("routesecretvalue"));

    let (status, view) = h.post(&t, "/sites/app/doppler/sync", json!({})).await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(server.state.download_params.lock().unwrap().len(), 2);

    let (status, view) = h.delete(&t, "/sites/app/doppler").await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(
        view["token_source"], "none",
        "clearing the binding deletes the site token"
    );
}

#[tokio::test]
async fn a_token_only_binding_needs_a_site_service_token() {
    let h = start_with_node_token().await;
    let t = h.token().await;
    seed_source_site(&h, "app").await;
    let server = with_mock(&h).await;
    for (bad, why) in [
        (
            json!({ "project": "", "config": "", "build": true }),
            "node token only",
        ),
        (
            json!({ "project": "", "config": "", "build": true, "token": "dp.pt.personalsecret" }),
            "personal token",
        ),
        (
            json!({ "project": "shop", "config": "", "build": true, "token": DOPPLER_TOKEN }),
            "half",
        ),
        (
            json!({ "project": "", "config": "prd", "build": true, "token": DOPPLER_TOKEN }),
            "half",
        ),
        (
            json!({ "project": "", "config": "", "token": DOPPLER_TOKEN }),
            "no target",
        ),
    ] {
        let (status, body) = h.put(&t, "/sites/app/doppler", bad.clone()).await;
        assert_eq!(status, 400, "{why}: {bad}: {body}");
        assert!(!body.to_string().contains("personalsecret"), "{body}");
    }
    assert_eq!(server.state.downloads(), 0, "nothing reached Doppler");
    let (_, view) = h.get(&t, "/sites/app/doppler").await;
    assert_eq!(view["bound"], false);
    let (status, view) = h
        .put(
            &t,
            "/sites/app/doppler",
            json!({ "project": "shop", "config": "prd", "build": true }),
        )
        .await;
    assert_eq!(
        status, 200,
        "a named binding still works with the node token: {view}"
    );
    assert_eq!(view["token_source"], "node");
    assert_eq!(
        *server.state.download_params.lock().unwrap(),
        vec![(Some("shop".to_string()), Some("prd".to_string()))]
    );
}
