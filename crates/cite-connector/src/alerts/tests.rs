use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use cite_edge::alerts::{DEFAULT_COOLDOWN_SECS, WebhookKind};
use cite_edge::model::Slot;
use cite_edge::status::{OperationInfo, SlotStatus};
use serde_json::Value;
use tempfile::TempDir;
use tokio::net::TcpListener;

use super::*;

struct FakeClock(AtomicU64);

impl FakeClock {
    fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct MapResolver {
    map: Mutex<HashMap<String, Vec<IpAddr>>>,
    lookups: AtomicUsize,
}

impl MapResolver {
    fn with(host: &str, ips: &[&str]) -> Arc<Self> {
        let resolver = Arc::new(Self::default());
        resolver.set(host, ips);
        resolver
    }

    fn set(&self, host: &str, ips: &[&str]) {
        let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect();
        lock(&self.map).insert(host.to_string(), ips);
    }
}

impl Resolver for MapResolver {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        _port: u16,
    ) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let found = lock(&self.map).get(host).cloned();
        Box::pin(
            async move { found.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound)) },
        )
    }
}

struct Rig {
    alerts: Arc<Alerts>,
    clock: Arc<FakeClock>,
    resolver: Arc<MapResolver>,
    dir: TempDir,
}

fn rig() -> Rig {
    let dir = TempDir::new().unwrap();
    let clock = Arc::new(FakeClock(AtomicU64::new(1_000_000)));
    let resolver = MapResolver::with("hooks.test", &["127.0.0.1"]);
    resolver.set("smtp.test", &["127.0.0.1"]);
    let alerts = Alerts::for_tests(dir.path(), clock.clone(), resolver.clone(), None);
    Rig {
        alerts,
        clock,
        resolver,
        dir,
    }
}

struct Seen {
    line: String,
    body: String,
}

type Log = Arc<Mutex<Vec<Seen>>>;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// Answers each request with the next scripted status (the last one repeats); never follows or sends redirects on its own.
async fn mock_http(replies: Vec<(u16, Option<&'static str>)>) -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 2048];
            let (head, body) = loop {
                let n = sock.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break (String::new(), String::new());
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find(&buf, b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + len {
                        break (
                            head,
                            String::from_utf8_lossy(&buf[pos + 4..pos + 4 + len]).to_string(),
                        );
                    }
                }
            };
            if head.is_empty() {
                continue;
            }
            let index = lock(&seen).len();
            lock(&seen).push(Seen {
                line: head.lines().next().unwrap_or("").to_string(),
                body,
            });
            let (code, location) = replies[index.min(replies.len() - 1)];
            let extra = location.map_or(String::new(), |l| format!("Location: {l}\r\n"));
            let reply = format!(
                "HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n{extra}\r\n"
            );
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    (port, log)
}

fn hook(id: &str, port: u16, path: &str, kind: WebhookKind) -> Webhook {
    Webhook {
        id: id.into(),
        name: format!("Hook {id}"),
        kind,
        url: format!("http://hooks.test:{port}{path}"),
        events: vec![],
    }
}

fn enabled(hooks: Vec<Webhook>) -> AlertSettings {
    AlertSettings {
        enabled: true,
        webhooks: hooks,
        ..AlertSettings::default()
    }
}

fn raised(event: AlertEvent, site: &str) -> Raised {
    Raised::new(event, Some(site), "message", "detail")
}

async fn finish(handles: Vec<JoinHandle<()>>) {
    for h in handles {
        h.await.unwrap();
    }
}

async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..300 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached in time");
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

fn count(log: &Log) -> usize {
    lock(log).len()
}

#[tokio::test]
async fn generic_slack_and_discord_bodies_reach_the_endpoint() {
    let rig = rig();
    let (port, log) = mock_http(vec![(200, None)]).await;
    rig.alerts.set_unchecked(enabled(vec![
        hook("gen", port, "/g", WebhookKind::Generic),
        hook("sl", port, "/s", WebhookKind::Slack),
        hook("di", port, "/d", WebhookKind::Discord),
    ]));
    finish(rig.alerts.dispatch(raised(AlertEvent::BuildFailed, "blog"))).await;
    let seen = lock(&log);
    assert_eq!(seen.len(), 3);
    let by_path = |path: &str| {
        let s = seen
            .iter()
            .find(|s| s.line == format!("POST {path} HTTP/1.1"))
            .unwrap();
        serde_json::from_str::<Value>(&s.body).unwrap()
    };
    let generic = by_path("/g");
    assert_eq!(generic["event"], "build_failed");
    assert_eq!(generic["site"], "blog");
    assert_eq!(generic["message"], "message");
    assert_eq!(generic["detail"], "detail");
    assert!(generic["at"].as_str().unwrap().starts_with("1970-01-"));
    assert_eq!(
        by_path("/s")["text"],
        "[build_failed] blog: message\ndetail"
    );
    assert_eq!(
        by_path("/d")["content"],
        "[build_failed] blog: message\ndetail"
    );
}

#[tokio::test]
async fn server_errors_are_retried_twice_and_client_errors_are_not() {
    let rig = rig();
    let (port, log) = mock_http(vec![(500, None), (503, None), (200, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    finish(rig.alerts.dispatch(raised(AlertEvent::NodeError, "a"))).await;
    assert_eq!(count(&log), 3);

    let (port, log) = mock_http(vec![(500, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    finish(rig.alerts.dispatch(raised(AlertEvent::NodeError, "b"))).await;
    assert_eq!(count(&log), 3, "one try and two retries, then give up");

    let (port, log) = mock_http(vec![(400, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    finish(rig.alerts.dispatch(raised(AlertEvent::NodeError, "c"))).await;
    assert_eq!(count(&log), 1);
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let rig = rig();
    let (port, log) = mock_http(vec![(302, Some("/elsewhere")), (200, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    finish(rig.alerts.dispatch(raised(AlertEvent::NodeError, "a"))).await;
    settle().await;
    let seen = lock(&log);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].line, "POST /h HTTP/1.1");
}

#[tokio::test]
async fn the_connection_is_pinned_to_one_lookup() {
    let rig = rig();
    let (port, log) = mock_http(vec![(200, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    finish(rig.alerts.dispatch(raised(AlertEvent::NodeError, "a"))).await;
    assert_eq!(count(&log), 1);
    assert_eq!(
        rig.resolver.lookups.load(Ordering::SeqCst),
        1,
        "the checked answer is the one connected to"
    );
}

fn strict(dir: &Path, resolver: Arc<MapResolver>) -> Arc<Alerts> {
    let mut net = Net::for_tests(resolver, None);
    net.allow_local = false;
    let clock = Arc::new(FakeClock(AtomicU64::new(1_000_000)));
    Alerts::assemble(dir, net, clock, Duration::from_millis(5))
}

fn public_hook(id: &str, host: &str) -> Webhook {
    Webhook {
        id: id.into(),
        name: id.into(),
        kind: WebhookKind::Generic,
        url: format!("https://{host}/secret-path"),
        events: vec![],
    }
}

#[tokio::test]
async fn private_answers_block_the_send_and_mixed_answers_do_too() {
    let dir = TempDir::new().unwrap();
    let resolver = Arc::new(MapResolver::default());
    for (host, ips) in [
        ("loop.test", vec!["127.0.0.1"]),
        ("lan.test", vec!["192.168.1.10"]),
        ("meta.test", vec!["169.254.169.254"]),
        ("ula.test", vec!["fd00::1"]),
        ("mapped.test", vec!["::ffff:10.0.0.1"]),
        ("mixed.test", vec!["93.184.216.34", "10.0.0.1"]),
        ("rebind.test", vec!["10.0.0.1", "93.184.216.34"]),
    ] {
        resolver.set(host, &ips);
    }
    let alerts = strict(dir.path(), resolver);
    for host in [
        "loop.test",
        "lan.test",
        "meta.test",
        "ula.test",
        "mapped.test",
        "mixed.test",
        "rebind.test",
    ] {
        alerts.set_unchecked(enabled(vec![public_hook("ops", host)]));
        match alerts.test("ops").await {
            TestOutcome::Failed(message) => {
                assert!(
                    message.contains("private, loopback or link-local"),
                    "{host}: {message}"
                );
                assert!(!message.contains("secret-path"));
            }
            other => panic!("{host}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn production_rules_refuse_loopback_literals_and_plain_http() {
    let net = Net::production();
    assert!(net.destination("http://127.0.0.1:8080/x").is_err());
    assert!(net.destination("http://example.com/x").is_err());
    assert!(net.destination("https://example.com/x").is_ok());
    for ip in ["127.0.0.1", "::1", "10.1.1.1", "169.254.169.254", "0.0.0.0"] {
        let target = Target {
            host: ip.into(),
            port: 443,
        };
        assert!(net.pin(&target).await.is_err(), "{ip}");
    }
    let resolver = MapResolver::with("pub.test", &["93.184.216.34", "2606:2800:220:1::1"]);
    let mut strict_net = Net::for_tests(resolver, None);
    strict_net.allow_local = false;
    let target = Target {
        host: "pub.test".into(),
        port: 443,
    };
    assert_eq!(
        strict_net.pin(&target).await.unwrap(),
        "93.184.216.34".parse::<IpAddr>().unwrap()
    );
    let missing = Target {
        host: "nowhere.test".into(),
        port: 443,
    };
    assert!(strict_net.pin(&missing).await.is_err());
}

#[tokio::test]
async fn cooldown_is_per_site_and_event_and_follows_the_clock() {
    let rig = rig();
    let (port, log) = mock_http(vec![(200, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    let first = rig
        .alerts
        .dispatch(raised(AlertEvent::SiteUnhealthy, "blog"));
    assert_eq!(first.len(), 1);
    finish(first).await;
    rig.clock.advance(DEFAULT_COOLDOWN_SECS - 1);
    assert!(
        rig.alerts
            .dispatch(raised(AlertEvent::SiteUnhealthy, "blog"))
            .is_empty()
    );
    finish(
        rig.alerts
            .dispatch(raised(AlertEvent::SiteUnhealthy, "shop")),
    )
    .await;
    finish(
        rig.alerts
            .dispatch(raised(AlertEvent::SiteRecovered, "blog")),
    )
    .await;
    assert_eq!(count(&log), 3);
    rig.clock.advance(1);
    finish(
        rig.alerts
            .dispatch(raised(AlertEvent::SiteUnhealthy, "blog")),
    )
    .await;
    assert_eq!(count(&log), 4);
}

#[tokio::test]
async fn disabled_alerts_and_unselected_events_send_nothing() {
    let rig = rig();
    let (port, log) = mock_http(vec![(200, None)]).await;
    let mut only_builds = hook("a", port, "/h", WebhookKind::Generic);
    only_builds.events = vec![AlertEvent::BuildFailed];
    let mut settings = enabled(vec![only_builds]);
    settings.enabled = false;
    rig.alerts.set_unchecked(settings.clone());
    assert!(
        rig.alerts
            .dispatch(raised(AlertEvent::BuildFailed, "x"))
            .is_empty()
    );
    settings.enabled = true;
    rig.alerts.set_unchecked(settings);
    assert!(
        rig.alerts
            .dispatch(raised(AlertEvent::SiteRecovered, "x"))
            .is_empty()
    );
    finish(rig.alerts.dispatch(raised(AlertEvent::BuildFailed, "x"))).await;
    assert_eq!(count(&log), 1);
}

#[tokio::test]
async fn test_sends_report_success_failure_and_unknown_targets_without_leaking_urls() {
    let rig = rig();
    let (port, log) = mock_http(vec![(200, None), (404, None)]).await;
    rig.alerts.set_unchecked(enabled(vec![hook(
        "ops",
        port,
        "/tok-123",
        WebhookKind::Slack,
    )]));
    assert_eq!(rig.alerts.test("ops").await, TestOutcome::Sent);
    assert_eq!(count(&log), 1);
    match rig.alerts.test("ops").await {
        TestOutcome::Failed(message) => assert!(
            message.contains("404") && !message.contains("tok-123"),
            "{message}"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(rig.alerts.test("nope").await, TestOutcome::Unknown);
    assert_eq!(rig.alerts.test(EMAIL_TARGET).await, TestOutcome::Unknown);

    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    rig.alerts.set_unchecked(enabled(vec![hook(
        "ops",
        closed,
        "/tok-123",
        WebhookKind::Generic,
    )]));
    match rig.alerts.test("ops").await {
        TestOutcome::Failed(message) => assert!(
            !message.contains("tok-123") && !message.contains("hooks.test"),
            "{message}"
        ),
        other => panic!("{other:?}"),
    }
}

fn stored_file(rig: &Rig) -> PathBuf {
    rig.dir.path().join(FILE)
}

fn incoming(url: &str) -> AlertSettings {
    AlertSettings {
        enabled: true,
        webhooks: vec![Webhook {
            id: "ops".into(),
            name: "Ops".into(),
            kind: WebhookKind::Slack,
            url: url.into(),
            events: vec![AlertEvent::BuildFailed, AlertEvent::BuildFailed],
        }],
        email: Some(EmailSettings {
            host: "smtp.example.com".into(),
            username: "user".into(),
            password: "hunter2".into(),
            from: "a@example.com".into(),
            to: vec!["b@example.com".into()],
            ..EmailSettings::default()
        }),
        cooldown_secs: 60,
    }
}

#[tokio::test]
async fn settings_persist_with_secrets_at_0600_and_views_mask_them() {
    let rig = rig();
    let view = rig
        .alerts
        .update(incoming("https://hooks.example.com/services/T0/B0/xyz"))
        .await
        .unwrap();
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("xyz") && !json.contains("hunter2"), "{json}");
    assert!(
        json.contains("https://hooks.example.com/...") && json.contains("\"password_set\":true")
    );
    assert_eq!(view.webhooks[0].events, vec![AlertEvent::BuildFailed]);

    let path = stored_file(&rig);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("services/T0/B0/xyz") && on_disk.contains("hunter2"));

    let reloaded = Alerts::new(rig.dir.path());
    assert_eq!(
        reloaded.settings().webhooks[0].url,
        "https://hooks.example.com/services/T0/B0/xyz"
    );
    assert_eq!(reloaded.view(), view);
    let debug = format!("{reloaded:?} {:?}", reloaded.settings());
    assert!(
        !debug.contains("xyz") && !debug.contains("hunter2"),
        "{debug}"
    );
}

#[tokio::test]
async fn blank_secrets_keep_the_stored_value_and_new_ids_need_a_url() {
    let rig = rig();
    rig.alerts
        .update(incoming("https://hooks.example.com/services/T0/B0/xyz"))
        .await
        .unwrap();

    let mut change = incoming("");
    change.email.as_mut().unwrap().password = String::new();
    change.webhooks[0].name = "Renamed".into();
    let view = rig.alerts.update(change).await.unwrap();
    assert_eq!(view.webhooks[0].name, "Renamed");
    assert!(view.email.unwrap().password_set);
    let stored = rig.alerts.settings();
    assert_eq!(
        stored.webhooks[0].url,
        "https://hooks.example.com/services/T0/B0/xyz"
    );
    assert_eq!(stored.email.as_ref().unwrap().password, "hunter2");

    let mut added = incoming("");
    added.webhooks[0].id = "fresh".into();
    assert!(matches!(
        rig.alerts.update(added).await,
        Err(ConnectorError::BadRequest(_))
    ));

    let mut swapped = incoming("https://other.example.com/new");
    swapped.email = None;
    let view = rig.alerts.update(swapped).await.unwrap();
    assert!(view.email.is_none());
    assert_eq!(
        rig.alerts.settings().webhooks[0].url,
        "https://other.example.com/new"
    );
}

#[tokio::test]
async fn invalid_updates_change_nothing_on_disk_or_in_memory() {
    let rig = rig();
    rig.alerts
        .update(incoming("https://hooks.example.com/a"))
        .await
        .unwrap();
    let before = std::fs::read(stored_file(&rig)).unwrap();
    for bad in [
        "http://hooks.example.com/a",
        "https://127.0.0.1/a",
        "https://user:pw@example.com/a",
    ] {
        let err = rig.alerts.update(incoming(bad)).await.unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)), "{bad}");
        assert!(!err.to_string().contains("pw@"), "{err}");
    }
    assert_eq!(std::fs::read(stored_file(&rig)).unwrap(), before);
    assert_eq!(
        rig.alerts.settings().webhooks[0].url,
        "https://hooks.example.com/a"
    );
}

#[tokio::test]
async fn an_unreadable_file_is_never_overwritten() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join(FILE), b"{ not json").unwrap();
    let alerts = Alerts::new(dir.path());
    assert!(!alerts.settings().enabled);
    let err = alerts
        .update(incoming("https://hooks.example.com/a"))
        .await
        .unwrap_err();
    assert!(matches!(err, ConnectorError::Internal(_)));
    assert_eq!(std::fs::read(dir.path().join(FILE)).unwrap(), b"{ not json");
}

#[test]
fn base64_matches_the_rfc_vectors() {
    for (raw, want) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(smtp::base64(raw.as_bytes()), want);
    }
}

fn observation(site: &str, unhealthy: Option<bool>) -> Observation {
    Observation {
        site: site.into(),
        unhealthy,
        detail: "why".into(),
        failure: None,
        promote: None,
    }
}

fn events(raised: &[Raised]) -> Vec<AlertEvent> {
    raised.iter().map(|r| r.event).collect()
}

#[test]
fn a_state_must_hold_for_two_checks_before_it_is_reported() {
    let mut t = Tracker::default();
    assert!(t.observe(&[observation("a", Some(true))]).is_empty());
    assert!(
        t.observe(&[observation("a", Some(false))]).is_empty(),
        "a blip resets the count"
    );
    assert!(t.observe(&[observation("a", Some(true))]).is_empty());
    let out = t.observe(&[observation("a", Some(true))]);
    assert_eq!(events(&out), vec![AlertEvent::SiteUnhealthy]);
    assert_eq!(out[0].site.as_deref(), Some("a"));
    assert!(
        t.observe(&[observation("a", Some(true))]).is_empty(),
        "no repeat while it stays down"
    );
    assert!(
        t.observe(&[observation("a", None)]).is_empty(),
        "unknown neither confirms nor clears"
    );
    assert!(t.observe(&[observation("a", Some(false))]).is_empty());
    assert_eq!(
        events(&t.observe(&[observation("a", Some(false))])),
        vec![AlertEvent::SiteRecovered]
    );
    assert!(t.observe(&[observation("a", Some(false))]).is_empty());
}

#[test]
fn healthy_sites_never_raise_a_recovery() {
    let mut t = Tracker::default();
    for _ in 0..4 {
        assert!(t.observe(&[observation("a", Some(false))]).is_empty());
    }
}

#[test]
fn only_new_failures_and_promotions_are_reported_after_the_first_sight() {
    let mut t = Tracker::default();
    let mut o = observation("a", Some(false));
    o.failure = Some(("t1".into(), "old failure".into()));
    o.promote = Some(("d1".into(), "old deploy".into()));
    assert!(
        t.observe(&[o.clone()]).is_empty(),
        "history at start is not news"
    );
    assert!(t.observe(&[o.clone()]).is_empty());
    o.failure = Some(("t2".into(), "boom".into()));
    let out = t.observe(&[o.clone()]);
    assert_eq!(events(&out), vec![AlertEvent::BuildFailed]);
    assert_eq!(out[0].detail, "boom");
    assert!(t.observe(&[o.clone()]).is_empty());
    o.promote = Some(("d2".into(), "shipped".into()));
    let out = t.observe(&[o.clone()]);
    assert_eq!(events(&out), vec![AlertEvent::DeploySucceeded]);
    assert_eq!(out[0].detail, "shipped");

    let mut late = observation("b", Some(false));
    assert!(t.observe(&[o.clone(), late.clone()]).is_empty());
    late.failure = Some(("t9".into(), "x".into()));
    assert_eq!(
        events(&t.observe(&[o, late])),
        vec![AlertEvent::BuildFailed],
        "a failure after a clean first sight is news"
    );
}

#[test]
fn removed_sites_are_forgotten() {
    let mut t = Tracker::default();
    let mut o = observation("a", Some(false));
    o.promote = Some(("d1".into(), String::new()));
    t.observe(&[o.clone()]);
    t.observe(&[]);
    o.promote = Some(("d2".into(), String::new()));
    assert!(
        t.observe(&[o]).is_empty(),
        "a site that comes back is seeded again"
    );
}

fn cert(id: &str, days: i64) -> CertExpiry {
    CertExpiry {
        id: id.into(),
        name: format!("Cert {id}"),
        days_left: days,
    }
}

#[test]
fn expiring_certificates_are_reported_once_a_day() {
    let mut t = Tracker::default();
    assert!(t.certs_due(0));
    assert!(t.certs(&[cert("a", 15), cert("b", 400)], 0).is_empty());
    assert!(!t.certs_due(CERT_CHECK_SECS - 1));
    assert!(t.certs_due(CERT_CHECK_SECS));
    let out = t.certs(&[cert("a", 14), cert("b", 400)], 1000);
    assert_eq!(events(&out), vec![AlertEvent::CertExpiring]);
    assert_eq!(out[0].scope, "cert:a");
    assert_eq!(out[0].site, None);
    assert!(out[0].message.contains("14 days"));
    assert!(
        t.certs(&[cert("a", 13)], 1000 + CERT_REPEAT_SECS - 1)
            .is_empty()
    );
    assert_eq!(t.certs(&[cert("a", 12)], 1000 + CERT_REPEAT_SECS).len(), 1);
    let expired = t.certs(&[cert("a", -1), cert("c", -3)], 1000 + 2 * CERT_REPEAT_SECS);
    assert_eq!(expired.len(), 2);
    assert!(expired.iter().all(|r| r.message.contains("has expired")));
}

#[test]
fn a_node_error_is_raised_once_per_streak_of_source_failures() {
    let mut t = Tracker::default();
    assert!(t.source_failed("down").is_none());
    assert!(t.source_failed("down").is_none());
    let raised = t.source_failed("down").unwrap();
    assert_eq!(raised.event, AlertEvent::NodeError);
    assert!(t.source_failed("down").is_none());
    t.source_ok();
    assert!(t.source_failed("down").is_none());
}

#[test]
fn health_is_read_from_the_active_slot_and_ignores_running_deploys() {
    let slot = |haproxy: Option<&str>, health: &str| SlotStatus {
        slot: Slot::Blue,
        haproxy: haproxy.map(str::to_string),
        health: health.into(),
        ..SlotStatus::default()
    };
    let status = |slots: Vec<SlotStatus>| SiteStatus {
        active: Slot::Blue,
        slots,
        ..SiteStatus::default()
    };
    assert_eq!(
        unhealthy_from(&status(vec![slot(Some("UP"), "healthy")])).map(|r| r.0),
        Some(false)
    );
    assert_eq!(
        unhealthy_from(&status(vec![slot(Some("DOWN"), "healthy")])).map(|r| r.0),
        Some(true)
    );
    assert_eq!(
        unhealthy_from(&status(vec![slot(Some("NOLB"), "")])).map(|r| r.0),
        Some(true)
    );
    assert_eq!(
        unhealthy_from(&status(vec![slot(None, "unhealthy")])).map(|r| r.0),
        Some(true)
    );
    assert!(unhealthy_from(&status(vec![])).is_none());
    let mut failing = status(vec![slot(Some("UP"), "healthy")]);
    failing.error = Some("container exited".into());
    assert_eq!(
        unhealthy_from(&failing),
        Some((true, "container exited".into()))
    );
    let mut deploying = failing.clone();
    deploying.operation = Some(OperationInfo::default());
    assert!(unhealthy_from(&deploying).is_none());
}

struct Script(Mutex<VecDeque<std::result::Result<Vec<Observation>, String>>>);

impl StatusSource for Script {
    fn observe(&self) -> BoxFuture<'_, std::result::Result<Vec<Observation>, String>> {
        let next = lock(&self.0).pop_front().unwrap_or_else(|| Ok(Vec::new()));
        Box::pin(async move { next })
    }
}

#[tokio::test]
async fn the_watcher_cycle_debounces_alerts_and_honours_the_cooldown() {
    let rig = rig();
    let (port, log) = mock_http(vec![(200, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    let down = || Ok(vec![observation("blog", Some(true))]);
    let up = || Ok(vec![observation("blog", Some(false))]);
    let source = Script(Mutex::new(VecDeque::from([
        down(),
        down(),
        down(),
        up(),
        up(),
        down(),
        down(),
    ])));
    let mut tracker = Tracker::default();

    run_cycle(&rig.alerts, &mut tracker, &source).await;
    settle().await;
    assert_eq!(count(&log), 0, "one bad check is not enough");
    run_cycle(&rig.alerts, &mut tracker, &source).await;
    until(|| count(&log) == 1).await;
    run_cycle(&rig.alerts, &mut tracker, &source).await;
    run_cycle(&rig.alerts, &mut tracker, &source).await;
    run_cycle(&rig.alerts, &mut tracker, &source).await;
    until(|| count(&log) == 2).await;
    let recovered: Value = serde_json::from_str(&lock(&log)[1].body).unwrap();
    assert_eq!(recovered["event"], "site_recovered");

    rig.clock.advance(10);
    run_cycle(&rig.alerts, &mut tracker, &source).await;
    run_cycle(&rig.alerts, &mut tracker, &source).await;
    settle().await;
    assert_eq!(count(&log), 2, "the second outage is inside the cooldown");
    let first: Value = serde_json::from_str(&lock(&log)[0].body).unwrap();
    assert_eq!(first["event"], "site_unhealthy");
    assert_eq!(first["site"], "blog");
}

#[tokio::test]
async fn a_disabled_cycle_does_not_read_status_and_forgets_state() {
    let rig = rig();
    let source = Script(Mutex::new(VecDeque::from([Ok(vec![observation(
        "blog",
        Some(true),
    )])])));
    let mut tracker = Tracker::default();
    run_cycle(&rig.alerts, &mut tracker, &source).await;
    assert_eq!(
        lock(&source.0).len(),
        1,
        "alerts are off, so the source is not asked"
    );
}

#[tokio::test]
async fn source_failures_raise_one_node_error() {
    let rig = rig();
    let (port, log) = mock_http(vec![(200, None)]).await;
    rig.alerts
        .set_unchecked(enabled(vec![hook("a", port, "/h", WebhookKind::Generic)]));
    let fail = || Err("docker unreachable".to_string());
    let source = Script(Mutex::new(VecDeque::from([fail(), fail(), fail(), fail()])));
    let mut tracker = Tracker::default();
    for _ in 0..4 {
        run_cycle(&rig.alerts, &mut tracker, &source).await;
    }
    until(|| count(&log) == 1).await;
    settle().await;
    assert_eq!(count(&log), 1);
    let body: Value = serde_json::from_str(&lock(&log)[0].body).unwrap();
    assert_eq!(body["event"], "node_error");
}

fn mail_for(port: u16, tls: TlsMode, username: &str) -> EmailSettings {
    EmailSettings {
        host: "smtp.test".into(),
        port,
        tls,
        username: username.into(),
        password: if username.is_empty() {
            String::new()
        } else {
            "hunter2".into()
        },
        from: "alerts@example.com".into(),
        to: vec!["one@example.com".into(), "two@example.com".into()],
        events: vec![],
    }
}

fn mail_payload() -> AlertPayload {
    AlertPayload {
        event: AlertEvent::SiteUnhealthy,
        site: Some("blog".into()),
        message: "site blog is unhealthy".into(),
        detail: "it is down\r\n.not an end of data".into(),
        at: "2026-01-01T00:00:00Z".into(),
    }
}

type Commands = Arc<Mutex<Vec<String>>>;

// Runs one SMTP conversation; `secure` decides whether AUTH or STARTTLS is offered. Returns the raw stream when the client asked to upgrade.
async fn smtp_loop<S>(io: S, secure: bool, log: &Commands, greet: bool) -> Option<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut io = BufReader::new(io);
    if greet {
        let _ = io.write_all(b"220 mock ready\r\n").await;
    }
    loop {
        let mut line = String::new();
        if io.read_line(&mut line).await.unwrap_or(0) == 0 {
            return None;
        }
        let line = line.trim_end().to_string();
        lock(log).push(line.clone());
        let reply: &[u8] = if line.starts_with("EHLO") {
            if secure {
                b"250-mock\r\n250 AUTH PLAIN LOGIN\r\n"
            } else {
                b"250-mock\r\n250 STARTTLS\r\n"
            }
        } else if line == "STARTTLS" {
            let _ = io.write_all(b"220 go ahead\r\n").await;
            let _ = io.flush().await;
            return Some(io.into_inner());
        } else if line == "DATA" {
            let _ = io.write_all(b"354 send it\r\n").await;
            let mut body = String::new();
            loop {
                let mut l = String::new();
                if io.read_line(&mut l).await.unwrap_or(0) == 0 {
                    return None;
                }
                if l == ".\r\n" {
                    break;
                }
                body.push_str(&l);
            }
            lock(log).push(format!("BODY {body}"));
            b"250 queued\r\n"
        } else if line == "QUIT" {
            let _ = io.write_all(b"221 bye\r\n").await;
            return None;
        } else if line.starts_with("AUTH PLAIN ") {
            b"235 ok\r\n"
        } else {
            b"250 ok\r\n"
        };
        let _ = io.write_all(reply).await;
        let _ = io.flush().await;
    }
}

async fn mock_smtp(acceptor: Option<tokio_rustls::TlsAcceptor>) -> (u16, Commands) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Commands = Arc::default();
    let shared = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let Some(upgraded) = smtp_loop(sock, acceptor.is_none(), &shared, true).await else {
                continue;
            };
            if let Some(acceptor) = &acceptor
                && let Ok(tls) = acceptor.accept(upgraded).await
            {
                smtp_loop(tls, true, &shared, false).await;
            }
        }
    });
    (port, log)
}

fn body_text(log: &Commands) -> String {
    let body = lock(log)
        .iter()
        .find_map(|l| l.strip_prefix("BODY ").map(str::to_string))
        .unwrap();
    let (headers, encoded) = body.split_once("\r\n\r\n").unwrap();
    assert!(
        headers.contains("Subject: [Cite] [site_unhealthy] blog: site blog is unhealthy"),
        "{headers}"
    );
    assert!(
        headers.contains("From: <alerts@example.com>")
            && headers.contains("To: <one@example.com>, <two@example.com>")
    );
    encoded.split("\r\n").collect()
}

#[tokio::test]
async fn plain_smtp_delivers_to_every_recipient() {
    let rig = rig();
    let (port, log) = mock_smtp(None).await;
    let mail = mail_for(port, TlsMode::None, "");
    rig.alerts.send_mail(&mail, &mail_payload()).await.unwrap();
    let cmds = lock(&log).clone();
    assert!(cmds.contains(&"MAIL FROM:<alerts@example.com>".to_string()));
    assert!(cmds.contains(&"RCPT TO:<one@example.com>".to_string()));
    assert!(cmds.contains(&"RCPT TO:<two@example.com>".to_string()));
    assert!(!cmds.iter().any(|c| c.starts_with("AUTH")));
    // The body travels as base64, so a line that looks like the end of data cannot cut the message short.
    assert_eq!(
        body_text(&log),
        smtp::base64(mail_payload().text().as_bytes())
    );
}

#[tokio::test]
async fn starttls_then_auth_plain_delivers() {
    crate::tls::install_provider();
    let certified = rcgen::generate_simple_self_signed(vec!["smtp.test".to_string()]).unwrap();
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(certified.key_pair.serialize_der()).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    let client = crate::tls::client_config_for_ca(certified.cert.pem().as_bytes()).unwrap();

    let dir = TempDir::new().unwrap();
    let clock = Arc::new(FakeClock(AtomicU64::new(1)));
    let resolver = MapResolver::with("smtp.test", &["127.0.0.1"]);
    let alerts = Alerts::for_tests(dir.path(), clock, resolver, Some(client));
    let (port, log) = mock_smtp(Some(tokio_rustls::TlsAcceptor::from(Arc::new(server)))).await;
    let mail = mail_for(port, TlsMode::Starttls, "user");
    alerts.send_mail(&mail, &mail_payload()).await.unwrap();

    let cmds = lock(&log).clone();
    let starttls = cmds.iter().position(|c| c == "STARTTLS").unwrap();
    let auth = cmds
        .iter()
        .position(|c| c.starts_with("AUTH PLAIN "))
        .unwrap();
    assert!(
        starttls < auth,
        "credentials are only sent after the upgrade"
    );
    assert_eq!(
        cmds[auth],
        format!("AUTH PLAIN {}", smtp::base64(b"\0user\0hunter2"))
    );
    assert!(cmds.iter().any(|c| c == "RCPT TO:<two@example.com>"));
    assert_eq!(
        body_text(&log),
        smtp::base64(mail_payload().text().as_bytes())
    );
}

#[tokio::test]
async fn smtp_refuses_a_server_without_starttls_and_hides_credentials_in_errors() {
    let rig = rig();
    let (port, log) = mock_smtp(None).await;
    let mail = mail_for(port, TlsMode::Starttls, "user");
    let err = rig
        .alerts
        .send_mail(&mail, &mail_payload())
        .await
        .unwrap_err();
    assert!(err.message.contains("STARTTLS"), "{}", err.message);
    assert!(!err.message.contains("hunter2"));
    assert!(
        !lock(&log).iter().any(|c| c.starts_with("AUTH")),
        "nothing is sent in the clear"
    );
}

#[tokio::test]
async fn private_smtp_hosts_are_refused_in_production() {
    let dir = TempDir::new().unwrap();
    let resolver = MapResolver::with("smtp.test", &["10.0.0.25"]);
    let alerts = strict(dir.path(), resolver);
    let mail = mail_for(587, TlsMode::Starttls, "user");
    let err = alerts.send_mail(&mail, &mail_payload()).await.unwrap_err();
    assert!(err.message.contains("private, loopback or link-local"));
}
