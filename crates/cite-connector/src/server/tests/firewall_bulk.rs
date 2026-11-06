use super::*;

const SECRET: &str = "bulk-secret-value-0123456789abcdef0123456789";

fn deny(id: &str, prefix: &str) -> Value {
    json!({
        "id": id,
        "name": "Deny",
        "enabled": true,
        "action": "deny",
        "matchers": { "path_prefixes": [prefix] }
    })
}

fn redirect(id: &str, to: &str) -> Value {
    json!({
        "id": id,
        "name": "Redirect",
        "enabled": true,
        "redirect": { "to": to, "status": 308 },
        "matchers": { "scheme": "http" }
    })
}

fn secret_rule(id: &str, equals: &str) -> Value {
    json!({
        "id": id,
        "name": "Gate",
        "enabled": true,
        "action": "deny",
        "matchers": { "headers": [{ "name": "X-Token", "equals": equals, "negate": true, "secret": true }] }
    })
}

fn ids(h: &Harness) -> Vec<String> {
    h.state
        .store
        .config()
        .firewall
        .iter()
        .map(|r| r.id.clone())
        .collect()
}

async fn actions(h: &Harness, t: &str) -> Vec<String> {
    let (_, entries) = h.get(t, "/audit?limit=200").await;
    entries
        .as_array()
        .expect("array")
        .iter()
        .map(|e| e["action"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn attempts(h: &Harness) -> u64 {
    h.fake.attempts.load(std::sync::atomic::Ordering::SeqCst)
}

#[tokio::test]
async fn the_bulk_route_needs_a_session() {
    let h = start().await;
    let (status, _) = h
        .call(
            Method::POST,
            None,
            "/firewall/bulk",
            Some(json!({ "delete": ["a"] })),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn one_bulk_call_creates_replaces_and_deletes_with_one_apply_and_one_audit_entry() {
    let h = start().await;
    let t = h.token().await;
    for id in ["keep", "swap", "drop"] {
        assert_eq!(h.post(&t, "/firewall/rules", deny(id, "/x")).await.0, 200);
    }
    let reloads = attempts(&h);
    let body = json!({
        "replace": [deny("swap", "/y"), deny("fresh", "/z")],
        "delete": ["drop", "never-existed"]
    });
    let (status, out) = h.post(&t, "/firewall/bulk", body).await;
    assert_eq!(status, 200, "{out}");
    assert_eq!(
        (
            out["created"].as_u64(),
            out["replaced"].as_u64(),
            out["deleted"].as_u64(),
            out["ignored"].as_u64()
        ),
        (Some(1), Some(1), Some(1), Some(1))
    );
    assert_eq!(out["rules"]["created"][0]["id"], "fresh");
    assert_eq!(out["rules"]["replaced"][0]["id"], "swap");
    assert_eq!(ids(&h), ["keep", "swap", "fresh"]);
    let swapped = h.state.store.config().firewall[1].clone();
    assert_eq!(swapped.matchers.path_prefixes, ["/y"]);
    assert_eq!(attempts(&h), reloads + 1, "one reload for the whole change");

    let log = actions(&h, &t).await;
    assert_eq!(
        log.iter().filter(|a| a.as_str() == "firewall.bulk").count(),
        1
    );
    let (_, entries) = h.get(&t, "/audit?limit=200").await;
    let entry = entries
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "firewall.bulk")
        .unwrap();
    let detail = entry["detail"].as_str().unwrap();
    assert!(detail.contains("swap") && detail.contains("fresh") && detail.contains("drop"));
    assert!(
        !detail.contains("/y"),
        "no rule bodies in the audit entry: {detail}"
    );
}

#[tokio::test]
async fn one_invalid_rule_changes_nothing_and_is_named() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(
        h.post(&t, "/firewall/rules", deny("old", "/x")).await.0,
        200
    );
    let before = h.state.store.config().firewall.clone();
    let reloads = attempts(&h);
    let mut bad = deny("broken", "/z");
    bad["matchers"] = json!({ "path_regexes": ["(unclosed"] });
    let body = json!({ "replace": [deny("fine", "/y"), bad], "delete": ["old"] });
    let (status, out) = h.post(&t, "/firewall/bulk", body).await;
    assert_eq!(status, 400, "{out}");
    assert!(out["error"].as_str().unwrap().contains("broken"), "{out}");
    assert_eq!(h.state.store.config().firewall, before);
    assert_eq!(attempts(&h), reloads);
    assert!(!actions(&h, &t).await.contains(&"firewall.bulk".to_string()));
}

#[tokio::test]
async fn conflicting_and_oversized_requests_are_refused() {
    let h = start().await;
    let t = h.token().await;
    let cases = [
        json!({}),
        json!({ "replace": [], "delete": [] }),
        json!({ "replace": [deny("a", "/x"), deny("a", "/y")] }),
        json!({ "delete": ["a", "a"] }),
        json!({ "replace": [deny("a", "/x")], "delete": ["a"] }),
        json!({ "delete": ["Bad Id"] }),
        json!({ "unknown": true }),
    ];
    for body in cases {
        let (status, out) = h.post(&t, "/firewall/bulk", body.clone()).await;
        assert_eq!(status, 400, "{body} -> {out}");
    }
    let many: Vec<Value> = (0..201).map(|n| deny(&format!("r{n}"), "/x")).collect();
    assert_eq!(
        h.post(&t, "/firewall/bulk", json!({ "replace": many }))
            .await
            .0,
        400
    );
    let gone: Vec<String> = (0..201).map(|n| format!("r{n}")).collect();
    assert_eq!(
        h.post(&t, "/firewall/bulk", json!({ "delete": gone }))
            .await
            .0,
        400
    );
    let huge = "a".repeat(600 * 1024);
    let (status, _) = h
        .post(
            &t,
            "/firewall/bulk",
            json!({ "replace": [deny("big", &huge)] }),
        )
        .await;
    assert_eq!(status, 413);
    assert!(ids(&h).is_empty());
}

#[tokio::test]
async fn a_redirect_loop_across_bulk_rows_is_rejected_whole() {
    let h = start().await;
    let t = h.token().await;
    h.seed_site("shop").await;
    let body = json!({ "replace": [
        redirect("to-www", "{scheme}://{www_host}{path}{query}"),
        redirect("to-apex", "{scheme}://{apex_host}{path}{query}"),
    ]});
    let (status, out) = h.post(&t, "/firewall/bulk", body).await;
    assert_eq!(status, 400, "{out}");
    assert!(out["error"].as_str().unwrap().contains("loop"), "{out}");
    assert!(ids(&h).is_empty());
}

#[tokio::test]
async fn a_refused_reload_rolls_the_whole_bulk_change_back() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(
        h.post(&t, "/firewall/rules", deny("old", "/x")).await.0,
        200
    );
    let before = h.state.store.config().firewall.clone();
    h.fake
        .refuse_next
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let body = json!({ "replace": [deny("new", "/y")], "delete": ["old"] });
    let (status, out) = h.post(&t, "/firewall/bulk", body).await;
    assert_eq!(status, 400, "{out}");
    assert_eq!(h.state.store.config().firewall, before);
    assert!(
        actions(&h, &t)
            .await
            .contains(&"config.rollback".to_string())
    );
}

#[tokio::test]
async fn blank_secret_headers_keep_their_stored_value_per_rule() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(
        h.post(&t, "/firewall/rules", secret_rule("gate", SECRET))
            .await
            .0,
        200
    );
    let body = json!({ "replace": [secret_rule("gate", ""), deny("plain", "/x")] });
    let (status, out) = h.post(&t, "/firewall/bulk", body).await;
    assert_eq!(status, 200, "{out}");
    assert!(!out.to_string().contains(SECRET));
    assert_eq!(
        out["rules"]["replaced"][0]["matchers"]["headers"][0]["equals"],
        ""
    );
    let kept = h.state.store.config().firewall[0].matchers.headers[0]
        .equals
        .clone();
    assert!(
        kept.as_deref() == Some(SECRET),
        "the stored secret was lost"
    );

    // a blank secret with nothing stored is refused by rule and header name, and nothing else lands
    let body = json!({ "replace": [secret_rule("unseen", ""), deny("late", "/y")] });
    let (status, out) = h.post(&t, "/firewall/bulk", body).await;
    assert_eq!(status, 400, "{out}");
    let text = out["error"].as_str().unwrap();
    assert!(
        text.contains("unseen") && text.contains("X-Token"),
        "{text}"
    );
    assert!(!ids(&h).contains(&"late".to_string()));
    let (_, log) = h.get(&t, "/audit?limit=200").await;
    assert!(!log.to_string().contains(SECRET));
}
