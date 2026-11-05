use sha2::{Digest, Sha256};

use super::*;

const DAY_MS: i64 = 86_400_000;

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn old_event(ip: &str, days_ago: i64) -> LogEvent {
    LogEvent {
        ts_ms: now_ms() - days_ago * DAY_MS,
        ..event(ip, 200)
    }
}

async fn stored_rows(h: &Harness) -> u64 {
    h.state.analytics.stats().expect("stats").rows
}

async fn audit_actions(h: &Harness, t: &str) -> Vec<String> {
    let (_, entries) = h.get(t, "/audit?limit=100").await;
    entries
        .as_array()
        .expect("array")
        .iter()
        .map(|e| e["action"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test]
async fn archive_routes_need_a_session() {
    let h = start().await;
    for (method, path) in [
        (Method::GET, "/analytics/archives"),
        (Method::POST, "/analytics/backup"),
        (Method::POST, "/analytics/cut"),
        (Method::POST, "/analytics/restore"),
        (Method::GET, "/analytics/archives/requests-1.ndjson.gz"),
        (Method::DELETE, "/analytics/archives/requests-1.ndjson.gz"),
    ] {
        let (status, _) = h.call(method.clone(), None, path, None).await;
        assert_eq!(status, 401, "{method} {path}");
    }
}

#[tokio::test]
async fn a_backup_is_listed_downloadable_and_audited() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([event("10.0.0.1", 200), event("10.0.0.2", 404)]);

    let (status, item) = h.post(&t, "/analytics/backup", json!({})).await;
    assert_eq!(status, 200, "{item}");
    assert_eq!(item["kind"], "backup");
    assert_eq!(item["rows"], 2);
    let name = item["name"].as_str().expect("name").to_string();

    let (_, list) = h.get(&t, "/analytics/archives").await;
    assert_eq!(list["items"][0]["name"], name.as_str());
    assert!(
        list["dir_bytes"]
            .as_u64()
            .is_some_and(|n| n >= item["bytes"].as_u64().unwrap())
    );

    let res = h.get_raw(&t, &format!("/analytics/archives/{name}")).await;
    assert_eq!(res.status().as_u16(), 200);
    let sha = res
        .headers()
        .get("x-archive-sha256")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("checksum header");
    let body = res.bytes().await.expect("body");
    assert!(body.starts_with(b"SQLite format 3\0"));
    assert_eq!(sha, item["sha256"].as_str().expect("sha"));
    assert_eq!(sha, sha_hex(&body));
    assert!(
        audit_actions(&h, &t)
            .await
            .contains(&"analytics.backup".to_string())
    );
}

#[tokio::test]
async fn a_cut_previews_then_archives_then_restores_through_the_api() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([old_event("10.0.0.1", 10), event("10.0.0.2", 200)]);
    assert_eq!(stored_rows(&h).await, 2);

    let (status, preview) = h
        .post(
            &t,
            "/analytics/cut",
            json!({ "before_days": 5, "dry_run": true }),
        )
        .await;
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["rows"], 1);
    assert_eq!(preview["archived_rows"], 0);
    assert_eq!(preview["files"], json!([]));
    assert_eq!(stored_rows(&h).await, 2);

    let (status, done) = h
        .post(&t, "/analytics/cut", json!({ "before_days": 5 }))
        .await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["archive"], true);
    assert_eq!(done["archived_rows"], 1);
    let name = done["files"][0].as_str().expect("file").to_string();
    assert_eq!(stored_rows(&h).await, 1);

    let (_, list) = h.get(&t, "/analytics/archives").await;
    assert_eq!(list["items"][0]["kind"], "archive");
    assert_eq!(list["items"][0]["rows"], 1);

    let (status, restored) = h
        .post(&t, "/analytics/restore", json!({ "name": name }))
        .await;
    assert_eq!(status, 200, "{restored}");
    assert_eq!(restored["rows"], 1);
    assert_eq!(stored_rows(&h).await, 2);

    let (status, _) = h.delete(&t, &format!("/analytics/archives/{name}")).await;
    assert_eq!(status, 200);
    let (_, list) = h.get(&t, "/analytics/archives").await;
    assert_eq!(list["items"], json!([]));

    let actions = audit_actions(&h, &t).await;
    for want in [
        "analytics.cut",
        "analytics.restore",
        "analytics.archive.delete",
    ] {
        assert!(actions.contains(&want.to_string()), "{want} in {actions:?}");
    }
}

#[tokio::test]
async fn skipping_the_archive_must_be_asked_for_explicitly() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([old_event("10.0.0.1", 10), event("10.0.0.2", 200)]);
    let (status, done) = h
        .post(
            &t,
            "/analytics/cut",
            json!({ "before_days": 5, "archive": false }),
        )
        .await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["archive"], false);
    assert_eq!(done["files"], json!([]));
    assert_eq!(stored_rows(&h).await, 1);
    let (_, list) = h.get(&t, "/analytics/archives").await;
    assert_eq!(list["items"], json!([]));
}

#[tokio::test]
async fn bad_cut_requests_are_rejected_and_delete_nothing() {
    let h = start().await;
    let t = h.token().await;
    h.ingest([old_event("10.0.0.1", 10), event("10.0.0.2", 200)]);
    let future = now_ms() + 3_600_000;
    for body in [
        json!({}),
        json!({ "before_days": 0 }),
        json!({ "before_days": 5, "before_ms": 1 }),
        json!({ "before_ms": future }),
        json!({ "before_ms": -1 }),
        json!({ "before_days": 5, "archive": "no" }),
        json!({ "before_days": 5, "force": true }),
    ] {
        let (status, _) = h.post(&t, "/analytics/cut", body.clone()).await;
        assert_eq!(status, 400, "{body}");
    }
    assert_eq!(stored_rows(&h).await, 2);
}

#[tokio::test]
async fn archive_names_cannot_leave_the_archive_directory() {
    let h = start().await;
    let t = h.token().await;
    for name in [
        "..%2F..%2Fetc%2Fpasswd",
        "..%2Fanalytics.db",
        "events.db",
        "requests-1.ndjson.gz%00",
        "requests-..ndjson.gz",
    ] {
        let path = format!("/analytics/archives/{name}");
        assert_eq!(h.get(&t, &path).await.0, 400, "get {name}");
        assert_eq!(h.delete(&t, &path).await.0, 400, "delete {name}");
    }
    for name in ["../analytics.db", "/etc/passwd", "a/b", ""] {
        let (status, _) = h
            .post(&t, "/analytics/restore", json!({ "name": name }))
            .await;
        assert_eq!(status, 400, "restore {name:?}");
    }
    let (status, _) = h
        .get(
            &t,
            "/analytics/archives/requests-0000000000001-0000000000002.ndjson.gz",
        )
        .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn restore_bodies_are_size_limited_and_strict() {
    let h = start().await;
    let t = h.token().await;
    let res = h
        .http
        .post(h.url("/analytics/restore"))
        .bearer_auth(&t)
        .header("content-type", "application/json")
        .body(vec![b' '; MAX_BODY_BYTES + 16])
        .send()
        .await
        .expect("request");
    assert_eq!(res.status().as_u16(), 413);
    let (status, _) = h
        .post(&t, "/analytics/restore", json!({ "name": "x", "extra": 1 }))
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn the_archive_setting_reaches_the_store_and_shows_in_stats() {
    let h = start().await;
    let t = h.token().await;
    assert!(h.state.analytics.archive_before_delete());
    let (_, stats) = h.get(&t, "/analytics/stats").await;
    assert_eq!(stats["archive_before_delete"], true);
    let (_, mut settings) = h.get(&t, "/settings").await;
    assert_eq!(settings["retention"]["archive_before_delete"], true);
    settings["retention"]["archive_before_delete"] = json!(false);
    assert_eq!(h.put(&t, "/settings", settings).await.0, 200);
    assert!(!h.state.analytics.archive_before_delete());
    let (_, stats) = h.get(&t, "/analytics/stats").await;
    assert_eq!(stats["archive_before_delete"], false);
}
