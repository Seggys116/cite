use std::os::unix::fs::PermissionsExt;

use sha2::{Digest, Sha256};

use super::*;

fn locked_site(id: &str, host: &str) -> Value {
    let mut site = site_json(id, host);
    site["access"] = json!({ "cloudflare_only": true, "zone_lock": true });
    site
}

fn secret_file(h: &Harness) -> std::path::PathBuf {
    h.state.cfg.data_dir.join("zone-secrets.json")
}

fn stored_secret(h: &Harness, site: &str) -> String {
    h.state
        .haproxy
        .zones()
        .secret_for(site)
        .expect("a stored secret")
}

fn fingerprint_of(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn zone_secret_routes_need_a_session() {
    let h = start().await;
    for method in [Method::GET, Method::POST] {
        let (status, _) = h.call(method, None, "/sites/shop/zone-secret", None).await;
        assert_eq!(status, 401);
    }
}

#[tokio::test]
async fn a_locked_site_gets_a_secret_that_only_a_rotation_reveals() {
    let h = start().await;
    let t = h.token().await;
    let (status, created) = h
        .post(&t, "/sites", locked_site("shop", "shop.example.com"))
        .await;
    assert_eq!(status, 200, "{created}");

    let secret = stored_secret(&h, "shop");
    assert_eq!(secret.len(), 43);
    let mode = std::fs::metadata(secret_file(&h))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let rendered = h.state.haproxy.current_config_text().expect("config");
    assert!(
        rendered.contains(&secret),
        "the rule belongs in the rendered config"
    );

    let (status, info) = h.get(&t, "/sites/shop/zone-secret").await;
    assert_eq!(status, 200);
    assert_eq!(info["configured"], true);
    assert_eq!(info["header"], "X-Cite-Origin-Secret");
    assert_eq!(info["fingerprint"], fingerprint_of(&secret).as_str());
    assert!(info.get("secret").is_none());
    assert!(!info.to_string().contains(&secret));

    let edge_json = std::fs::read_to_string(h.state.cfg.data_dir.join("edge.json")).unwrap();
    assert!(
        !edge_json.contains(&secret),
        "edge.json must not hold the zone secret"
    );
    assert!(
        !edge_json.contains("zone-shop"),
        "the injected rule is never persisted"
    );
    let (_, rules) = h.get(&t, "/firewall/rules").await;
    assert_eq!(rules, json!([]));
    assert!(!haproxy_text(&h, &t).await.contains(&secret));

    let before = h.state.haproxy.status().config_hash;
    let res = h
        .http
        .post(h.url("/sites/shop/zone-secret"))
        .bearer_auth(&t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(
        res.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let rotated: Value = res.json().await.unwrap();
    let new_secret = rotated["secret"].as_str().unwrap().to_string();
    assert_eq!(new_secret.len(), 43);
    assert!(new_secret != secret, "the rotation must change the secret");
    assert_eq!(rotated["fingerprint"], fingerprint_of(&new_secret).as_str());
    assert_ne!(h.state.haproxy.status().config_hash, before);
    let rendered = h.state.haproxy.current_config_text().expect("config");
    assert!(rendered.contains(&new_secret) && !rendered.contains(&secret));

    let (_, info) = h.get(&t, "/sites/shop/zone-secret").await;
    assert_eq!(info["fingerprint"], rotated["fingerprint"]);
    assert!(!info.to_string().contains(&new_secret));

    let (_, audit) = h.get(&t, "/audit?limit=200").await;
    let text = audit.to_string();
    assert!(text.contains("zone_secret.rotate"));
    assert!(text.contains(rotated["fingerprint"].as_str().unwrap()));
    for value in [&secret, &new_secret] {
        assert!(!text.contains(value.as_str()));
        let file = std::fs::read_to_string(h.state.cfg.data_dir.join("audit.jsonl")).unwrap();
        assert!(!file.contains(value.as_str()));
    }
}

async fn haproxy_text(h: &Harness, t: &str) -> String {
    h.get_raw(t, "/haproxy/config").await.text().await.unwrap()
}

#[tokio::test]
async fn rotation_needs_a_known_locked_site() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(
        h.post(&t, "/sites/ghost/zone-secret", json!({})).await.0,
        404
    );
    assert_eq!(h.get(&t, "/sites/ghost/zone-secret").await.0, 404);
    h.seed_site("plain").await;
    assert_eq!(
        h.post(&t, "/sites/plain/zone-secret", json!({})).await.0,
        400
    );
    let (_, info) = h.get(&t, "/sites/plain/zone-secret").await;
    assert_eq!(info["configured"], false);
    assert_eq!(info["fingerprint"], Value::Null);
}

#[tokio::test]
async fn the_secret_goes_when_the_lock_is_turned_off_or_the_site_is_deleted() {
    let h = start().await;
    let t = h.token().await;
    h.post(&t, "/sites", locked_site("shop", "shop.example.com"))
        .await;
    h.post(&t, "/sites", locked_site("blog", "blog.example.com"))
        .await;
    assert!(h.state.haproxy.zones().secret_for("shop").is_some());

    let (status, _) = h
        .put(&t, "/sites/shop", site_json("shop", "shop.example.com"))
        .await;
    assert_eq!(status, 200);
    assert!(h.state.haproxy.zones().secret_for("shop").is_none());
    assert!(h.state.haproxy.zones().secret_for("blog").is_some());
    let (_, info) = h.get(&t, "/sites/shop/zone-secret").await;
    assert_eq!(info["configured"], false);

    assert_eq!(h.delete(&t, "/sites/blog").await.0, 200);
    assert!(!h.state.haproxy.zones().has_any());
    let file = std::fs::read_to_string(secret_file(&h)).unwrap();
    assert_eq!(file.trim(), "{}");
}

#[tokio::test]
async fn a_locked_site_is_never_rendered_without_its_rule() {
    let h = start().await;
    let t = h.token().await;
    h.post(&t, "/sites", locked_site("shop", "shop.example.com"))
        .await;
    let cfg = h.state.store.config();
    let opts = h.state.haproxy.dry_options().expect("options");
    let bare = cite_edge::render::render(&cfg, &opts);
    assert!(
        bare.is_err(),
        "render itself refuses a lock without its rule"
    );
    let text = h.state.haproxy.current_config_text().unwrap();
    assert!(text.contains("X-Cite-Origin-Secret"));
}

#[tokio::test]
async fn protection_changes_need_a_running_haproxy_but_other_changes_do_not() {
    let h = start_absent().await;
    let t = h.token().await;
    let (status, body) = h.post(&t, "/firewall/rules", rule_json("block")).await;
    assert_eq!(status, 503, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("must be running"),
        "{body}"
    );
    assert_eq!(h.get(&t, "/firewall/rules").await.1, json!([]));

    let mut guarded = site_json("shop", "shop.example.com");
    guarded["access"] = json!({ "bots": "block_bad" });
    assert_eq!(h.post(&t, "/sites", guarded).await.0, 503);
    assert_eq!(h.get(&t, "/sites").await.1, json!([]));

    assert_eq!(h.post(&t, "/pages", page_json("down")).await.0, 200);
    let (_, audit) = h.get(&t, "/audit?limit=100").await;
    assert!(audit.to_string().contains("config.pending"));
}

#[tokio::test]
async fn a_refused_reload_rolls_a_protection_change_back() {
    let h = start().await;
    let t = h.token().await;
    h.fake
        .refuse_next
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let (status, body) = h.post(&t, "/firewall/rules", rule_json("block")).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        !body["error"].as_str().unwrap().contains("FAILED"),
        "{body}"
    );
    assert_eq!(h.get(&t, "/firewall/rules").await.1, json!([]));
    assert_eq!(
        h.post(&t, "/firewall/rules", rule_json("block")).await.0,
        200
    );
}

#[tokio::test]
async fn a_rollback_that_haproxy_does_not_confirm_is_reported_as_failed() {
    let h = start().await;
    let t = h.token().await;
    h.fake
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, body) = h.post(&t, "/firewall/rules", rule_json("block")).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("rollback FAILED"),
        "{body}"
    );
    let (_, audit) = h.get(&t, "/audit?limit=100").await;
    assert!(audit.to_string().contains("config.rollback_unconfirmed"));
}

#[tokio::test]
async fn a_rollback_that_cannot_be_stored_is_reported_as_failed() {
    let h = start().await;
    let t = h.token().await;
    h.fake
        .refuse_next
        .store(1, std::sync::atomic::Ordering::SeqCst);
    // the change is stored, then the write that would undo it fails
    h.state.store.fail_config_write_after(1);
    let (status, body) = h.post(&t, "/firewall/rules", rule_json("block")).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("rollback FAILED"),
        "{body}"
    );
    let (_, audit) = h.get(&t, "/audit?limit=100").await;
    assert!(audit.to_string().contains("config.rollback_failed"));
}

#[tokio::test]
async fn rotation_checks_the_site_again_once_it_holds_the_lock() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(
        h.post(&t, "/sites", locked_site("shop", "shop.example.com"))
            .await
            .0,
        200
    );
    // the handler's own check passes, then the config lock is held while the lock is turned off
    let gate = h.state.deployer.config_lock().lock().await;
    let (http, url, token) = (h.http.clone(), h.url("/sites/shop/zone-secret"), t.clone());
    let pending =
        tokio::spawn(async move { http.post(url).bearer_auth(token).send().await.unwrap() });
    // wait until the rotation has passed the handler's check and is blocked on the lock
    for _ in 0..500 {
        if h.state
            .rotations_waiting
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        h.state
            .rotations_waiting
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the rotation never reached the lock"
    );
    h.state
        .store
        .update("test", "unlock", |cfg| {
            cfg.sites[0].access.zone_lock = false;
            Ok(())
        })
        .await
        .unwrap();
    drop(gate);
    let res = pending.await.unwrap();
    assert_eq!(res.status().as_u16(), 400);
    let body: Value = res.json().await.unwrap();
    assert!(body.get("secret").is_none(), "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("while the rotation waited")),
        "the refusal must come from the check made under the lock: {body}"
    );
}

#[tokio::test]
async fn a_failed_secret_undo_is_reported_as_failed() {
    let h = start().await;
    let t = h.token().await;
    h.post(&t, "/sites", locked_site("shop", "shop.example.com"))
        .await;
    h.fake
        .refuse_next
        .store(1, std::sync::atomic::Ordering::SeqCst);
    h.state.haproxy.zones().fail_write_after(1);
    let (status, body) = h.post(&t, "/sites/shop/zone-secret", json!({})).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("rollback FAILED"),
        "{body}"
    );
    let (_, audit) = h.get(&t, "/audit?limit=100").await;
    assert!(audit.to_string().contains("zone_secret.rollback_failed"));
}

#[tokio::test]
async fn rotation_needs_a_confirmed_load_and_keeps_the_old_secret_otherwise() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(
        h.post(&t, "/sites", locked_site("shop", "shop.example.com"))
            .await
            .0,
        200
    );
    let before = stored_secret(&h, "shop");
    h.fake
        .refuse_next
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let (status, body) = h.post(&t, "/sites/shop/zone-secret", json!({})).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.get("secret").is_none());
    assert!(
        !body["error"].as_str().unwrap().contains("FAILED"),
        "{body}"
    );
    assert!(
        stored_secret(&h, "shop") == before,
        "the refused rotation changed the secret"
    );
    let (_, audit) = h.get(&t, "/audit?limit=100").await;
    assert!(audit.to_string().contains("\"zone_secret.rollback\""));
    assert_eq!(
        h.post(&t, "/sites/shop/zone-secret", json!({})).await.0,
        200
    );
    assert!(
        stored_secret(&h, "shop") != before,
        "the accepted rotation must change the secret"
    );
}

#[tokio::test]
async fn rotation_without_haproxy_is_a_503_and_leaves_no_secret_behind() {
    let h = start_absent().await;
    let t = h.token().await;
    let site: Site = serde_json::from_value(locked_site("shop", "shop.example.com")).unwrap();
    h.state
        .store
        .update("test", "seed", move |cfg| {
            cfg.sites.push(site);
            Ok(())
        })
        .await
        .unwrap();
    let (status, body) = h.post(&t, "/sites/shop/zone-secret", json!({})).await;
    assert_eq!(status, 503, "{body}");
    assert!(body.get("secret").is_none());
    // a locked site always holds a secret, so the failed rotation's re-apply may generate one, but it is never reported
    if let Some(kept) = h.state.haproxy.zones().secret_for("shop") {
        assert!(!body.to_string().contains(kept.as_str()));
    }
}

#[tokio::test]
async fn applying_a_preset_again_refreshes_its_rules_and_keeps_the_owner_choices() {
    let h = start().await;
    let t = h.token().await;
    let (_, presets) = h.get(&t, "/firewall/presets").await;
    let name = presets[0]["name"].as_str().unwrap().to_string();
    let first_id = presets[0]["rules"][0]["id"].as_str().unwrap().to_string();
    let path = format!("/firewall/presets/{name}/apply");
    assert_eq!(h.post(&t, &path, json!({})).await.0, 200);

    let stale_id = first_id.clone();
    h.state
        .store
        .update("test", "stale", move |cfg| {
            let rule = cfg.firewall.iter_mut().find(|r| r.id == stale_id).unwrap();
            rule.name = "stale".into();
            rule.enabled = false;
            Ok(())
        })
        .await
        .unwrap();
    let (status, refreshed) = h.post(&t, &path, json!({})).await;
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(refreshed.as_array().map(Vec::len), Some(1));
    assert_eq!(refreshed[0]["id"], first_id.as_str());
    let rule = h
        .state
        .store
        .config()
        .firewall
        .iter()
        .find(|r| r.id == first_id)
        .cloned()
        .unwrap();
    assert!(rule.name != "stale", "the definition is current again");
    assert!(!rule.enabled, "the owner's choice to keep it off is kept");
    assert_eq!(h.post(&t, &path, json!({})).await.1, json!([]));
}

fn secret_rule(equals: &str) -> Value {
    json!({
        "id": "hdr",
        "name": "Header gate",
        "enabled": true,
        "action": "deny",
        "matchers": { "header": { "name": "X-Token", "equals": equals, "negate": true, "secret": true } }
    })
}

#[tokio::test]
async fn secret_header_values_are_write_only() {
    let h = start().await;
    let t = h.token().await;
    let value = "user-secret-value-0123456789abcdef0123456789";
    let (status, created) = h.post(&t, "/firewall/rules", secret_rule(value)).await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["matchers"]["header"]["equals"], "");
    assert!(!created.to_string().contains(value));
    let stored = |h: &Harness| {
        h.state.store.config().firewall[0]
            .matchers
            .header
            .as_ref()
            .and_then(|m| m.equals.clone())
    };
    assert_eq!(stored(&h).as_deref(), Some(value));

    let (_, listed) = h.get(&t, "/firewall/rules").await;
    assert_eq!(listed[0]["matchers"]["header"]["equals"], "");
    assert!(!listed.to_string().contains(value));
    assert!(!haproxy_text(&h, &t).await.contains(value));

    let (status, kept) = h.put(&t, "/firewall/rules/hdr", secret_rule("")).await;
    assert_eq!(status, 200, "{kept}");
    assert_eq!(stored(&h).as_deref(), Some(value));
    assert_eq!(kept["matchers"]["header"]["equals"], "");

    let replacement = "another-secret-value-0123456789abcdef012345";
    let (status, _) = h
        .put(&t, "/firewall/rules/hdr", secret_rule(replacement))
        .await;
    assert_eq!(status, 200);
    assert_eq!(stored(&h).as_deref(), Some(replacement));

    let mut fresh = secret_rule("");
    fresh["id"] = json!("other");
    let (status, res) = h.post(&t, "/firewall/rules", fresh).await;
    assert_eq!(status, 400, "{res}");
    let (_, audit) = h.get(&t, "/audit?limit=200").await;
    let text = audit.to_string();
    assert!(!text.contains(value) && !text.contains(replacement));
}

#[tokio::test]
async fn new_rule_site_and_preset_fields_are_accepted_and_kept() {
    let h = start().await;
    let t = h.token().await;
    let rule = json!({
        "id": "www",
        "name": "Add www",
        "enabled": true,
        "label": "to-www",
        "matchers": { "scheme": "http" },
        "redirect": { "to": "{scheme}://{www_host}{path}{query}", "status": 308 }
    });
    let (status, body) = h.post(&t, "/firewall/rules", rule).await;
    assert_eq!(status, 200, "{body}");
    let (_, listed) = h.get(&t, "/firewall/rules").await;
    assert_eq!(listed[0]["redirect"]["status"], 308);
    assert_eq!(listed[0]["label"], "to-www");
    assert_eq!(listed[0]["matchers"]["scheme"], "http");
    assert!(listed[0].get("action").is_none());

    let mut site = site_json("blog", "blog.example.com");
    site["access"] = json!({ "bots": "block_bad" });
    assert_eq!(h.post(&t, "/sites", site).await.0, 200);
    let (_, one) = h.get(&t, "/sites/blog").await;
    assert_eq!(one["access"]["bots"], "block_bad");

    let (_, presets) = h.get(&t, "/firewall/presets").await;
    let names: Vec<&str> = presets
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    for name in ["redirect-to-www", "redirect-to-apex", "force-https"] {
        assert!(names.contains(&name), "{names:?}");
    }
}
