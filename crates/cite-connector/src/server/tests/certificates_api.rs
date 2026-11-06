use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use time::Duration;

use super::*;
use crate::certs::testing::{Issued, issue, issue_with};

fn upload(name: &str, issued: &Issued) -> Value {
    json!({ "name": name, "certificate": issued.cert_pem, "private_key": issued.key_pem })
}

fn certs_dir(h: &Harness) -> PathBuf {
    h.state.cfg.certs_dir.clone()
}

fn pem_files(h: &Harness) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(certs_dir(h))
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

async fn set_https(h: &Harness, t: &str, port: Option<u16>) {
    let (_, mut settings) = h.get(t, "/settings").await;
    settings["https_port"] = json!(port);
    let (status, body) = h.put(t, "/settings", settings).await;
    assert_eq!(status, 200, "{body}");
}

async fn haproxy_config(h: &Harness, t: &str) -> String {
    h.get_raw(t, "/haproxy/config")
        .await
        .text()
        .await
        .expect("config text")
}

async fn audit_actions(h: &Harness, t: &str) -> Vec<String> {
    let (_, entries) = h.get(t, "/audit?limit=200").await;
    entries
        .as_array()
        .expect("array")
        .iter()
        .map(|e| e["action"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn assert_no_key(text: &str, key_pem: &str) {
    let lines: Vec<&str> = key_pem
        .lines()
        .filter(|l| !l.starts_with("-----") && l.len() >= 16)
        .collect();
    assert!(!lines.is_empty());
    for line in lines {
        assert!(!text.contains(line), "key material leaked: {text}");
    }
}

#[tokio::test]
async fn certificate_routes_need_a_session() {
    let h = start().await;
    let id = "0".repeat(26);
    for (method, path) in [
        (Method::GET, "/certificates".to_string()),
        (Method::POST, "/certificates".to_string()),
        (Method::GET, format!("/certificates/{id}")),
        (Method::PUT, format!("/certificates/{id}")),
        (Method::DELETE, format!("/certificates/{id}")),
        (Method::GET, "/cloudflare/ranges".to_string()),
    ] {
        let (status, _) = h.call(method.clone(), None, &path, None).await;
        assert_eq!(status, 401, "{method} {path}");
    }
}

#[tokio::test]
async fn an_upload_is_stored_listed_fetched_and_audited() {
    let h = start().await;
    let t = h.token().await;
    h.seed_site("shop").await;
    h.seed_site("other").await;
    let issued = issue(&["shop.example.com", "*.example.net"]);

    let (status, created) = h
        .post(&t, "/certificates", upload("Shop cert", &issued))
        .await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().expect("id").to_string();
    assert_eq!(created["name"], "Shop cert");
    assert_eq!(
        created["sans"],
        json!(["shop.example.com", "*.example.net"])
    );
    assert_eq!(created["key_type"], "ecdsa-p256");
    assert_eq!(created["covers"], json!(["shop.example.com"]));
    assert_eq!(created["uncovered_hosts"], json!(["other.example.com"]));
    assert_eq!(
        created["fingerprint_sha256"].as_str().map(str::len),
        Some(64)
    );
    assert!(
        created["days_left"]
            .as_i64()
            .is_some_and(|d| (88..=90).contains(&d))
    );
    assert!(
        created["not_after"]
            .as_str()
            .is_some_and(|s| s.contains('T'))
    );
    assert!(
        created["warning"]
            .as_str()
            .is_some_and(|w| w.contains("https_port"))
    );
    assert!(created.get("private_key").is_none());

    let (_, list) = h.get(&t, "/certificates").await;
    assert_eq!(list["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(list["https_port"], Value::Null);
    assert_eq!(list["dir_ready"], true);
    assert_eq!(list["uncovered_hosts"], json!(["other.example.com"]));

    let (status, one) = h.get(&t, &format!("/certificates/{id}")).await;
    assert_eq!(status, 200);
    assert_eq!(one["fingerprint_sha256"], created["fingerprint_sha256"]);
    assert!(one.get("warning").is_none());

    assert_eq!(pem_files(&h), [format!("{id}.pem")]);
    let mode = std::fs::metadata(certs_dir(&h).join(format!("{id}.pem")))
        .expect("file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let (_, entries) = h.get(&t, "/audit?limit=50").await;
    let entry = entries
        .as_array()
        .expect("array")
        .iter()
        .find(|e| e["action"] == "certificates.create")
        .expect("audit entry");
    let detail = entry["detail"].as_str().expect("detail");
    assert!(detail.contains(&id), "{detail}");
    assert!(
        detail.contains(created["fingerprint_sha256"].as_str().unwrap()),
        "{detail}"
    );
    assert!(detail.contains("Shop cert"), "{detail}");
}

#[tokio::test]
async fn the_https_bind_follows_the_certificate_set() {
    let h = start().await;
    let t = h.token().await;
    set_https(&h, &t, Some(8443)).await;
    assert!(!haproxy_config(&h, &t).await.contains("ssl crt"));

    let issued = issue(&["a.example.com"]);
    let (status, created) = h.post(&t, "/certificates", upload("a", &issued)).await;
    assert_eq!(status, 201, "{created}");
    assert!(created.get("warning").is_none(), "{created}");
    let bind = format!("bind :8443 ssl crt {}", certs_dir(&h).display());
    assert!(haproxy_config(&h, &t).await.contains(&bind));

    let id = created["id"].as_str().unwrap().to_string();
    let (status, _) = h.delete(&t, &format!("/certificates/{id}")).await;
    assert_eq!(status, 204);
    assert!(!haproxy_config(&h, &t).await.contains("ssl crt"));
    let (_, list) = h.get(&t, "/certificates").await;
    assert_eq!(list["items"], json!([]));
    assert_eq!(list["https_port"], 8443);

    let (status, _) = h
        .post(&t, "/certificates", upload("b", &issue(&["b.example.com"])))
        .await;
    assert_eq!(status, 201);
    assert!(haproxy_config(&h, &t).await.contains(&bind));
}

#[tokio::test]
async fn invalid_uploads_are_refused_and_leave_nothing_behind() {
    let h = start().await;
    let t = h.token().await;
    let good = issue(&["a.example.com"]);
    let other = issue(&["a.example.com"]);
    let expired = issue_with(
        &["a.example.com"],
        &rcgen::PKCS_ECDSA_P256_SHA256,
        Duration::days(-30),
        Duration::days(10),
    );
    let crl = "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
    let encrypted =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({"name": "x", "certificate": good.cert_pem, "private_key": other.key_pem}),
            "does not match",
        ),
        (upload("x", &expired), "expired"),
        (
            json!({"name": "x", "certificate": good.cert_pem, "private_key": encrypted}),
            "encrypted",
        ),
        (
            json!({"name": "x", "certificate": format!("{}{crl}", good.cert_pem), "private_key": good.key_pem}),
            "unsupported PEM block",
        ),
        (
            json!({"name": "x", "certificate": good.cert_pem, "private_key": crl}),
            "unsupported PEM block",
        ),
        (
            json!({"name": "x", "certificate": format!("{}{}", good.cert_pem, good.key_pem), "private_key": good.key_pem}),
            "private key",
        ),
        (
            json!({"name": "x", "certificate": "nothing", "private_key": good.key_pem}),
            "certificate",
        ),
        (
            json!({"name": "x", "certificate": good.cert_pem, "private_key": format!("{}{}", good.key_pem, good.key_pem)}),
            "exactly one",
        ),
        (
            json!({"name": "x", "certificate": good.cert_pem, "private_key": good.key_pem, "extra": 1}),
            "unknown field",
        ),
        (
            json!({"name": "x", "certificate": good.cert_pem}),
            "private_key",
        ),
    ];
    for (body, needle) in cases {
        let (status, res) = h.post(&t, "/certificates", body).await;
        assert_eq!(status, 400, "{res}");
        let message = res["error"].as_str().unwrap_or_default();
        assert!(message.contains(needle), "{needle:?} not in {message:?}");
        assert_no_key(&res.to_string(), &good.key_pem);
        assert_no_key(&res.to_string(), &other.key_pem);
    }
    let long = "x".repeat(65);
    for name in [
        "",
        ".hidden",
        "-dash",
        "a-----BEGIN x",
        "a/b",
        "../../etc/passwd",
        "a\nb",
        long.as_str(),
        " pad",
    ] {
        let (status, res) = h.post(&t, "/certificates", upload(name, &good)).await;
        assert_eq!(status, 400, "{name:?}: {res}");
    }
    assert!(pem_files(&h).is_empty(), "{:?}", pem_files(&h));
    let (_, list) = h.get(&t, "/certificates").await;
    assert_eq!(list["items"], json!([]));
}

#[tokio::test]
async fn hand_placed_certificates_are_listed_read_only_and_keep_https_on() {
    let h = start().await;
    let t = h.token().await;
    set_https(&h, &t, Some(8443)).await;
    let issued = issue(&["manual.example.com"]);
    std::fs::create_dir_all(certs_dir(&h)).expect("dir");
    std::fs::write(
        certs_dir(&h).join("manual.pem"),
        format!("{}{}", issued.cert_pem, issued.key_pem),
    )
    .expect("pem");
    let (status, _) = h
        .post(
            &t,
            "/certificates",
            upload("api", &issue(&["a.example.com"])),
        )
        .await;
    assert_eq!(status, 201);
    let bind = format!("bind :8443 ssl crt {}", certs_dir(&h).display());
    assert!(haproxy_config(&h, &t).await.contains(&bind));
    let (_, list) = h.get(&t, "/certificates").await;
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    let manual = items
        .iter()
        .find(|i| i["source"] == "manual")
        .expect("manual entry");
    assert_eq!(manual["id"], "file:manual.pem");
    assert_eq!(manual["sans"], json!(["manual.example.com"]));
    assert_eq!(h.delete(&t, "/certificates/file:manual.pem").await.0, 404);
    assert_eq!(h.get(&t, "/certificates/file:manual.pem").await.0, 404);
    assert!(certs_dir(&h).join("manual.pem").is_file());
}

#[tokio::test]
async fn an_upload_while_haproxy_is_absent_is_kept_with_a_warning() {
    let h = start_absent().await;
    let t = h.token().await;
    set_https(&h, &t, Some(8443)).await;
    let (status, created) = h
        .post(&t, "/certificates", upload("a", &issue(&["a.example.com"])))
        .await;
    assert_eq!(status, 201, "{created}");
    assert!(
        created["warning"]
            .as_str()
            .is_some_and(|w| w.contains("could not be reached"))
    );
    assert!(
        audit_actions(&h, &t)
            .await
            .contains(&"certificates.create".to_string())
    );
}

#[tokio::test]
async fn a_write_that_fails_after_its_rename_leaves_nothing_behind() {
    let h = start().await;
    let t = h.token().await;
    h.state.certs.fail_next_write();
    let (status, res) = h
        .post(&t, "/certificates", upload("a", &issue(&["a.example.com"])))
        .await;
    assert!(status >= 400, "{status} {res}");
    assert!(pem_files(&h).is_empty());
    let (status, list) = h.get(&t, "/certificates").await;
    assert_eq!(status, 200);
    assert!(list["items"].as_array().is_some_and(|i| i.is_empty()));
    let (status, _) = h
        .post(&t, "/certificates", upload("a", &issue(&["a.example.com"])))
        .await;
    assert_eq!(status, 201);
}

#[tokio::test]
async fn a_duplicate_certificate_is_a_conflict() {
    let h = start().await;
    let t = h.token().await;
    let issued = issue(&["a.example.com"]);
    let (status, _) = h.post(&t, "/certificates", upload("one", &issued)).await;
    assert_eq!(status, 201);
    let (status, res) = h.post(&t, "/certificates", upload("two", &issued)).await;
    assert_eq!(status, 409, "{res}");
    assert_eq!(pem_files(&h).len(), 1);
}

#[tokio::test]
async fn oversized_bodies_are_refused_with_413() {
    let h = start().await;
    let t = h.token().await;
    let res = h
        .http
        .post(h.url("/certificates"))
        .bearer_auth(&t)
        .header("content-type", "application/json")
        .body(vec![b' '; crate::certs::MAX_BODY_BYTES + 16])
        .send()
        .await
        .expect("request");
    assert_eq!(res.status().as_u16(), 413);
}

#[tokio::test]
async fn a_certificate_is_replaced_in_place_and_can_be_renamed() {
    let h = start().await;
    let t = h.token().await;
    let first = issue(&["old.example.com"]);
    let (_, created) = h.post(&t, "/certificates", upload("site", &first)).await;
    let id = created["id"].as_str().unwrap().to_string();
    let path = format!("/certificates/{id}");

    let renewed = issue(&["new.example.com"]);
    let (status, body) = h
        .put(
            &t,
            &path,
            json!({"certificate": renewed.cert_pem, "private_key": renewed.key_pem}),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["id"], id.as_str());
    assert_eq!(body["name"], "site");
    assert_eq!(body["sans"], json!(["new.example.com"]));
    assert_eq!(body["created_at"], created["created_at"]);
    assert_ne!(body["fingerprint_sha256"], created["fingerprint_sha256"]);

    let (status, body) = h.put(&t, &path, upload("renamed", &renewed)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "renamed");
    assert_eq!(pem_files(&h), [format!("{id}.pem")]);

    let second = issue(&["second.example.com"]);
    let (_, other) = h.post(&t, "/certificates", upload("second", &second)).await;
    let other_path = format!("/certificates/{}", other["id"].as_str().unwrap());
    let (status, _) = h.put(&t, &other_path, upload("second", &renewed)).await;
    assert_eq!(status, 409);

    let missing = format!("/certificates/{}", "Z".repeat(26));
    let (status, _) = h.put(&t, &missing, upload("x", &renewed)).await;
    assert_eq!(status, 404);
    let (status, _) = h
        .put(&t, "/certificates/not-an-id", upload("x", &renewed))
        .await;
    assert_eq!(status, 404);
    let (status, _) = h
        .put(&t, &path, json!({"name": "../x", "certificate": renewed.cert_pem, "private_key": renewed.key_pem}))
        .await;
    assert_eq!(status, 400);
    assert!(
        audit_actions(&h, &t)
            .await
            .contains(&"certificates.replace".to_string())
    );
}

#[tokio::test]
async fn deleting_a_certificate_removes_its_file() {
    let h = start().await;
    let t = h.token().await;
    let (_, created) = h
        .post(
            &t,
            "/certificates",
            upload("gone", &issue(&["a.example.com"])),
        )
        .await;
    let path = format!("/certificates/{}", created["id"].as_str().unwrap());
    let (status, _) = h.delete(&t, &path).await;
    assert_eq!(status, 204);
    assert!(pem_files(&h).is_empty());
    assert_eq!(h.get(&t, &path).await.0, 404);
    assert_eq!(h.delete(&t, &path).await.0, 404);
    assert_eq!(h.delete(&t, "/certificates/..%2F..%2Fedge").await.0, 404);
    assert!(
        audit_actions(&h, &t)
            .await
            .contains(&"certificates.delete".to_string())
    );
}

#[tokio::test]
async fn the_private_key_is_in_no_response_audit_entry_or_config() {
    let h = start().await;
    let t = h.token().await;
    set_https(&h, &t, Some(8443)).await;
    let first = issue(&["a.example.com"]);
    let second = issue(&["b.example.com"]);
    let mut seen = Vec::new();

    let (_, created) = h.post(&t, "/certificates", upload("a", &first)).await;
    seen.push(created.to_string());
    let id = created["id"].as_str().unwrap().to_string();
    let (_, replaced) = h
        .put(&t, &format!("/certificates/{id}"), upload("a", &second))
        .await;
    seen.push(replaced.to_string());
    let (_, mismatch) = h
        .post(
            &t,
            "/certificates",
            json!({"name": "m", "certificate": first.cert_pem, "private_key": second.key_pem}),
        )
        .await;
    seen.push(mismatch.to_string());
    seen.push(h.get(&t, "/certificates").await.1.to_string());
    seen.push(
        h.get(&t, &format!("/certificates/{id}"))
            .await
            .1
            .to_string(),
    );
    seen.push(h.get(&t, "/audit?limit=200").await.1.to_string());
    seen.push(haproxy_config(&h, &t).await);
    seen.push(
        std::fs::read_to_string(h.state.cfg.data_dir.join("audit.jsonl")).expect("audit file"),
    );
    for text in &seen {
        assert_no_key(text, &first.key_pem);
        assert_no_key(text, &second.key_pem);
    }
    let on_disk = std::fs::read_to_string(certs_dir(&h).join(format!("{id}.pem"))).expect("pem");
    assert!(on_disk.contains("BEGIN PRIVATE KEY"));
    assert!(on_disk.contains("BEGIN CERTIFICATE"));
}

// Records the staged config it was asked to check and fails while a marker file exists.
fn fake_haproxy(dir: &std::path::Path) -> String {
    let script = dir.join("fake-haproxy");
    std::fs::write(
        &script,
        "#!/bin/sh\ncp \"$3\" \"$(dirname \"$0\")/capture.cfg\"\n[ -e \"$(dirname \"$0\")/fail\" ] && exit 1\nexit 0\n",
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    script.display().to_string()
}

#[tokio::test]
async fn a_change_haproxy_rejects_is_rolled_back_and_the_edge_keeps_serving() {
    let tools = tempfile::tempdir().expect("tools");
    let bin = fake_haproxy(tools.path());
    let h = start_with(move |cfg| {
        cfg.validate_with_haproxy = true;
        cfg.haproxy_bin = bin;
    })
    .await;
    let t = h.token().await;
    set_https(&h, &t, Some(8443)).await;

    let first = issue(&["a.example.com"]);
    let (status, created) = h.post(&t, "/certificates", upload("first", &first)).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let captured = std::fs::read_to_string(tools.path().join("capture.cfg")).expect("capture");
    assert!(
        captured.contains(&format!("ssl crt {}", certs_dir(&h).display())),
        "{captured}"
    );

    let file = certs_dir(&h).join(format!("{id}.pem"));
    let bytes_before = std::fs::read(&file).expect("pem");
    let config_before = haproxy_config(&h, &t).await;
    std::fs::write(tools.path().join("fail"), "").expect("marker");

    let (status, res) = h
        .post(
            &t,
            "/certificates",
            upload("second", &issue(&["b.example.com"])),
        )
        .await;
    assert_eq!(status, 400, "{res}");
    assert!(
        res["error"].as_str().unwrap().contains("rolled back"),
        "{res}"
    );
    assert_eq!(pem_files(&h), [format!("{id}.pem")]);

    let renewed = issue(&["a.example.com"]);
    let (status, _) = h
        .put(
            &t,
            &format!("/certificates/{id}"),
            upload("first", &renewed),
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(std::fs::read(&file).expect("pem"), bytes_before);

    let (status, _) = h.delete(&t, &format!("/certificates/{id}")).await;
    assert_eq!(status, 400);
    assert_eq!(std::fs::read(&file).expect("pem"), bytes_before);

    assert_eq!(haproxy_config(&h, &t).await, config_before);
    let (_, list) = h.get(&t, "/certificates").await;
    assert_eq!(list["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        list["items"][0]["fingerprint_sha256"],
        created["fingerprint_sha256"]
    );
    let rollbacks = audit_actions(&h, &t)
        .await
        .iter()
        .filter(|a| a.as_str() == "certificates.rollback")
        .count();
    assert_eq!(rollbacks, 3);

    std::fs::remove_file(tools.path().join("fail")).expect("marker");
    let (status, _) = h.delete(&t, &format!("/certificates/{id}")).await;
    assert_eq!(status, 204);
    assert!(!haproxy_config(&h, &t).await.contains("ssl crt"));
}

fn cf_site_json(id: &str, host: &str) -> Value {
    let mut site = site_json(id, host);
    site["access"] = json!({ "cloudflare_only": true });
    site
}

fn auto_item(list: &Value, site: &str) -> Option<Value> {
    list["items"]
        .as_array()?
        .iter()
        .find(|c| c["id"] == format!("auto:{site}").as_str())
        .cloned()
}

#[tokio::test]
async fn a_cloudflare_site_gets_a_read_only_automatic_certificate_that_uploads_supersede() {
    let h = start().await;
    let t = h.token().await;
    let (status, body) = h
        .post(&t, "/sites", cf_site_json("shop", "shop.example.com"))
        .await;
    assert_eq!(status, 200, "{body}");

    let (_, list) = h.get(&t, "/certificates").await;
    let item = auto_item(&list, "shop").expect("an automatic certificate");
    assert_eq!(item["source"], "auto");
    assert_eq!(item["sans"], json!(["shop.example.com"]));
    assert!(
        item["warning"].as_str().unwrap().contains("not trust"),
        "{item}"
    );
    assert!(list["https_port"].is_null());
    assert_eq!(list["https_effective_port"], 443);
    assert_eq!(list["uncovered_hosts"], json!(["shop.example.com"]));
    assert!(pem_files(&h).contains(&"auto-shop.pem".to_string()));
    assert!(haproxy_config(&h, &t).await.contains("bind :443 ssl crt"));
    assert_eq!(h.get(&t, "/certificates/auto:shop").await.0, 200);
    assert_eq!(h.get(&t, "/certificates/auto:ghost").await.0, 404);

    let issued = issue(&["x.example.com"]);
    let (status, body) = h
        .put(&t, "/certificates/auto:shop", upload("mine", &issued))
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("managed by the node")
    );
    let (status, body) = h.delete(&t, "/certificates/auto:shop").await;
    assert_eq!(status, 400, "{body}");
    assert!(pem_files(&h).contains(&"auto-shop.pem".to_string()));

    let file = std::fs::read_to_string(certs_dir(&h).join("auto-shop.pem")).unwrap();
    let mut seen = vec![list.to_string(), haproxy_config(&h, &t).await];
    seen.push(h.get(&t, "/audit?limit=200").await.1.to_string());
    for text in &seen {
        assert_no_key(text, &file);
    }

    let real = issue(&["shop.example.com"]);
    let (status, created) = h.post(&t, "/certificates", upload("real", &real)).await;
    assert_eq!(status, 201, "{created}");
    let (_, list) = h.get(&t, "/certificates").await;
    assert!(
        auto_item(&list, "shop").is_none(),
        "an uploaded certificate supersedes it"
    );
    assert!(!pem_files(&h).contains(&"auto-shop.pem".to_string()));
    assert_eq!(list["items"].as_array().map(Vec::len), Some(1));

    let id = created["id"].as_str().unwrap();
    assert_eq!(h.delete(&t, &format!("/certificates/{id}")).await.0, 204);
    let (_, list) = h.get(&t, "/certificates").await;
    assert!(
        auto_item(&list, "shop").is_some(),
        "it returns when nothing covers the host"
    );

    assert_eq!(h.delete(&t, "/sites/shop").await.0, 200);
    assert!(pem_files(&h).is_empty());
    assert!(!haproxy_config(&h, &t).await.contains("ssl crt"));
}

#[tokio::test]
async fn a_node_without_cloudflare_or_flexible_sites_makes_no_automatic_certificate() {
    let h = start().await;
    let t = h.token().await;
    assert_eq!(
        h.post(&t, "/sites", site_json("plain", "plain.example.com"))
            .await
            .0,
        200
    );
    let (_, list) = h.get(&t, "/certificates").await;
    assert_eq!(list["items"].as_array().map(Vec::len), Some(0));
    assert!(list["https_effective_port"].is_null());
    assert!(pem_files(&h).is_empty());
}

#[tokio::test]
async fn an_internal_failure_while_applying_never_puts_paths_in_the_response() {
    let tools = tempfile::tempdir().expect("tools");
    let bin = fake_haproxy(tools.path());
    let h = start_with({
        let bin = bin.clone();
        move |cfg| {
            cfg.validate_with_haproxy = true;
            cfg.haproxy_bin = bin;
        }
    })
    .await;
    let t = h.token().await;
    let (status, created) = h
        .post(
            &t,
            "/certificates",
            upload("first", &issue(&["a.example.com"])),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();

    // with the checker gone, `haproxy -c` cannot even start and the error names the binary's path
    std::fs::remove_file(&bin).expect("remove the fake binary");
    let tools_dir = tools.path().display().to_string();
    let path = format!("/certificates/{id}");
    let mut replies = Vec::new();
    replies.push(
        h.post(
            &t,
            "/certificates",
            upload("second", &issue(&["b.example.com"])),
        )
        .await,
    );
    replies.push(
        h.put(&t, &path, upload("first", &issue(&["a.example.com"])))
            .await,
    );
    replies.push(h.delete(&t, &path).await);
    for (status, body) in replies {
        assert_eq!(status, 503, "{body}");
        let text = body.to_string();
        assert!(
            !text.contains(&tools_dir),
            "a path reached the client: {text}"
        );
        assert!(
            !text.contains("No such file"),
            "an I/O error reached the client: {text}"
        );
        assert!(
            text.contains("haproxy could not apply the certificate change"),
            "{text}"
        );
    }
    assert_eq!(pem_files(&h), [format!("{id}.pem")]);
}

#[tokio::test]
async fn simultaneous_uploads_are_serialised_and_both_land() {
    let h = start().await;
    let t = h.token().await;
    let (a, b) = (issue(&["a.example.com"]), issue(&["b.example.com"]));
    let (first, second) = tokio::join!(
        h.post(&t, "/certificates", upload("a", &a)),
        h.post(&t, "/certificates", upload("b", &b)),
    );
    assert_eq!((first.0, second.0), (201, 201));
    assert_eq!(pem_files(&h).len(), 2);
    let (_, list) = h.get(&t, "/certificates").await;
    assert_eq!(list["items"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn the_cloudflare_range_list_reports_its_source() {
    let h = start().await;
    let t = h.token().await;
    let (status, builtin) = h.get(&t, "/cloudflare/ranges").await;
    assert_eq!(status, 200);
    assert_eq!(builtin["source"], "builtin");
    assert_eq!(
        builtin["updated"],
        cite_edge::cloudflare::CLOUDFLARE_RANGES_UPDATED
    );
    assert_eq!(
        builtin["ranges"],
        json!(cite_edge::cloudflare::BUILTIN_RANGES)
    );

    let (_, mut settings) = h.get(&t, "/settings").await;
    settings["cloudflare_ranges"] = json!(["192.0.2.0/24"]);
    let (status, saved) = h.put(&t, "/settings", settings).await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["cloudflare_ranges"], json!(["192.0.2.0/24"]));
    let (_, custom) = h.get(&t, "/cloudflare/ranges").await;
    assert_eq!(custom["source"], "custom");
    assert_eq!(custom["ranges"], json!(["192.0.2.0/24"]));
}
