//! Data routes against a real service over a fake Docker engine: enable flows in both modes, users and rotation,
//! backups with encryption at rest, download and restore, links, secrets, targets, status codes and audit names.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::future::BoxFuture;
use sha2::{Digest, Sha256};

use super::*;
use crate::data::DataService;
use crate::data::service::{DataConfig, DataEngine};
use crate::data::shared::SharedSettings;
use crate::data::users::UserSecret;
use crate::egress::EgressMode;
use crate::orchestrator::data::{DbHealth, JobNet, JobOp, JobOutcome, JobScope, JobSpec};

type Fut<'a, T> = BoxFuture<'a, crate::Result<T>>;

fn dump_bytes() -> Vec<u8> {
    // Larger than two stream chunks so ranges and chunk boundaries are exercised.
    (0..150_000u32).map(|i| (i % 251) as u8).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn op_name(op: &JobOp) -> &'static str {
    match op {
        JobOp::Backup => "backup",
        JobOp::Restore => "restore",
        JobOp::Counts => "counts",
        JobOp::JobLogin => "joblogin",
        JobOp::Freeze => "freeze",
        JobOp::Unfreeze => "unfreeze",
        JobOp::Provision => "provision",
        JobOp::Deprovision => "deprovision",
        JobOp::Regrant => "regrant",
        JobOp::User => "user",
        JobOp::Hba => "hba",
        JobOp::Sizes => "sizes",
        JobOp::Globals => "globals",
    }
}

#[derive(Debug, Clone)]
struct Recorded {
    op: &'static str,
    env: BTreeMap<String, String>,
    shared_net: bool,
}

struct FakeEngine {
    root: PathBuf,
    events: StdMutex<Vec<String>>,
    jobs: StdMutex<Vec<Recorded>>,
    fail_ops: StdMutex<HashSet<&'static str>>,
    restored: StdMutex<Vec<Vec<u8>>>,
    ports_open: AtomicBool,
    /// What `env_mentions` answers: true while an old slot is imagined to still carry the login.
    mentioned: AtomicBool,
    /// What `dbnet_subnet` answers for every site.
    subnet: StdMutex<String>,
}

impl FakeEngine {
    fn new(root: PathBuf) -> FakeEngine {
        FakeEngine {
            root,
            events: StdMutex::new(Vec::new()),
            jobs: StdMutex::new(Vec::new()),
            fail_ops: StdMutex::new(HashSet::new()),
            restored: StdMutex::new(Vec::new()),
            ports_open: AtomicBool::new(true),
            mentioned: AtomicBool::new(true),
            subnet: StdMutex::new("172.31.1.0/24".to_string()),
        }
    }

    fn event(&self, text: &str) {
        self.events.lock().unwrap().push(text.to_string());
    }

    fn jobs_of(&self, op: &str) -> Vec<Recorded> {
        self.jobs
            .lock()
            .unwrap()
            .iter()
            .filter(|j| j.op == op)
            .cloned()
            .collect()
    }
}

impl DataEngine for FakeEngine {
    fn ensure_site_database<'a>(&'a self, site: &'a Site, _su: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.event(&format!("ensure_site_database:{}", site.id));
            Ok(())
        })
    }
    fn ensure_shared_instance<'a>(&'a self, _cfg: &'a SharedSettings, _su: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.event("ensure_shared_instance");
            Ok(())
        })
    }
    fn prepare_shared(&self) -> Fut<'_, String> {
        Box::pin(async move {
            self.event("prepare_shared");
            Ok("172.30.0.0/24".to_string())
        })
    }
    fn dbnet_subnet<'a>(&'a self, _site_id: &'a str) -> Fut<'a, String> {
        Box::pin(async move { Ok(self.subnet.lock().unwrap().clone()) })
    }
    fn connect_shared<'a>(&'a self, _site_id: &'a str) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn disconnect_shared<'a>(&'a self, _site_id: &'a str) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn reconnect_shared<'a>(&'a self, site_ids: &'a [String]) -> Fut<'a, ()> {
        Box::pin(async move {
            self.event(&format!("reconnect_shared:{}", site_ids.join(",")));
            Ok(())
        })
    }
    fn env_mentions<'a>(&'a self, _site_id: &'a str, _needles: &'a [String]) -> Fut<'a, bool> {
        Box::pin(async move { Ok(self.mentioned.load(Ordering::SeqCst)) })
    }
    fn run_job<'a>(
        &'a self,
        job: &'a JobSpec,
        _redact: &'a [String],
        _t: Duration,
    ) -> Fut<'a, JobOutcome> {
        Box::pin(async move {
            let op = op_name(&job.op);
            let env: BTreeMap<String, String> = job
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            self.event(&format!("job:{op}"));
            self.jobs.lock().unwrap().push(Recorded {
                op,
                env: env.clone(),
                shared_net: matches!(job.net, JobNet::SharedAdmin),
            });
            if self.fail_ops.lock().unwrap().contains(op) {
                return Ok(JobOutcome {
                    exit_code: 1,
                    log_tail: vec!["boom".into()],
                });
            }
            let dir = match &job.scope {
                JobScope::Site(id) => self.root.join("staging").join(id),
                JobScope::Shared => self.root.join("staging").join("_shared"),
            };
            let id = env.get("CITE_JOB_ID").cloned().unwrap_or_default();
            match op {
                "backup" => {
                    std::fs::write(dir.join(format!("{id}.dump")), dump_bytes()).unwrap();
                    std::fs::write(dir.join(format!("{id}.version")), "18.1\n").unwrap();
                }
                "restore" => {
                    let bytes = std::fs::read(dir.join(format!("{id}.dump"))).unwrap();
                    self.restored.lock().unwrap().push(bytes);
                }
                "sizes" => {
                    std::fs::write(dir.join(format!("{id}.sizes")), "postgres\t7000000\n").unwrap();
                }
                "globals" => {
                    std::fs::write(dir.join(format!("{id}.globals")), "-- globals\n").unwrap();
                }
                _ => {}
            }
            Ok(JobOutcome {
                exit_code: 0,
                log_tail: Vec::new(),
            })
        })
    }
    fn restart_database<'a>(&'a self, _name: &'a str) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn remove_site_database<'a>(&'a self, site_id: &'a str, purge: bool) -> Fut<'a, ()> {
        Box::pin(async move {
            self.event(&format!("remove_site_database:{site_id}:{purge}"));
            Ok(())
        })
    }
    fn remove_dedicated_database<'a>(&'a self, site_id: &'a str, purge: bool) -> Fut<'a, ()> {
        Box::pin(async move {
            self.event(&format!("remove_dedicated_database:{site_id}:{purge}"));
            Ok(())
        })
    }
    fn remove_shared_instance<'a>(&'a self, _purge: bool) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn database_health<'a>(&'a self, _name: &'a str) -> Fut<'a, DbHealth> {
        Box::pin(async {
            Ok(DbHealth {
                state: "running".into(),
                health: "healthy".into(),
                started_at: None,
                image: String::new(),
            })
        })
    }
    fn volume_size<'a>(&'a self, _name: &'a str) -> Fut<'a, Option<u64>> {
        Box::pin(async { Ok(Some(1234)) })
    }
    fn slot_running<'a>(
        &'a self,
        _site_id: &'a str,
        _slot: cite_edge::model::Slot,
    ) -> Fut<'a, bool> {
        Box::pin(async { Ok(true) })
    }
    fn egress_mode(&self) -> EgressMode {
        EgressMode::Filtered
    }
    fn node_ports_allow(&self, _port: u16) -> bool {
        self.ports_open.load(Ordering::SeqCst)
    }
}

/// A harness whose data service runs over the fake engine (and that has no orchestrator).
pub(super) async fn start_with_data_service() -> Harness {
    start_data().await.0
}

async fn start_data() -> (Harness, Arc<FakeEngine>) {
    start_data_with(false).await
}

async fn start_data_with(s3_allow_private: bool) -> (Harness, Arc<FakeEngine>) {
    let h = start().await;
    let root = h._dir.path().join("backups");
    let engine = Arc::new(FakeEngine::new(root.clone()));
    let cfg = DataConfig {
        data_dir: h.state.cfg.data_dir.clone(),
        backup_dir: root,
        backup_volume: "cite-backups".into(),
        s3_allow_private,
        job_timeout: Duration::from_secs(60),
        node_name: "test-node".into(),
        previous_key: None,
    };
    let svc = DataService::new(
        Arc::clone(&h.state.deployer),
        Arc::clone(&h.state.store),
        engine.clone(),
        Arc::clone(&h.state.alerts),
        cfg,
    )
    .expect("data service");
    h.state.set_data(svc);
    (h, engine)
}

fn svc_of(h: &Harness) -> Arc<DataService> {
    h.state.data.get().cloned().expect("data service")
}

async fn seed_shop(h: &Harness) {
    let mut json = site_json("shop", "shop.example.com");
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

async fn wait_job(h: &Harness, t: &str, job: &str) -> Value {
    for _ in 0..400 {
        let (status, v) = h.get(t, &format!("/data/jobs/{job}")).await;
        assert_eq!(status, 200, "{v}");
        if v["state"] != "running" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("job {job} did not finish");
}

async fn run_ok(h: &Harness, t: &str, method: Method, path: &str, body: Option<Value>) -> Value {
    let (status, v) = h.call(method, Some(t), path, body).await;
    assert_eq!(status, 202, "{path}: {v}");
    let job = v["job_id"].as_str().expect("job id").to_string();
    let done = wait_job(h, t, &job).await;
    assert_eq!(done["state"], "ok", "{path}: {done}");
    done
}

async fn enable(h: &Harness, t: &str) -> Value {
    run_ok(
        h,
        t,
        Method::PUT,
        "/sites/shop/data/postgres",
        Some(json!({ "mode": "dedicated" })),
    )
    .await
}

async fn secret_of(h: &Harness, db: &str, user: &str) -> UserSecret {
    svc_of(h)
        .secret_get(&cite_edge::datamodel::pg_user_secret_name("shop", db, user))
        .await
        .expect("read")
        .expect("secret")
}

async fn audit_actions(h: &Harness) -> Vec<String> {
    h.state
        .store
        .audit_tail(500)
        .await
        .into_iter()
        .map(|e| e.action)
        .collect()
}

#[tokio::test]
async fn data_routes_need_a_session_and_answer_404_when_the_node_has_no_data_services() {
    let h = start().await;
    let (status, _) = h.call(Method::GET, None, "/sites/shop/data", None).await;
    assert_eq!(status, 401);
    let t = h.token().await;
    h.seed_site("shop").await;
    let (status, body) = h.get(&t, "/sites/shop/data").await;
    assert_eq!(status, 404);
    assert!(
        body["error"].as_str().unwrap().contains("not enabled"),
        "{body}"
    );
    let (status, node) = h.get(&t, "/data").await;
    assert_eq!(status, 200);
    assert_eq!(node["enabled"], false);
    let (status, _) = h.get(&t, "/data/targets").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn enabling_dedicated_postgres_creates_default_database_users_and_links() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    let done = enable(&h, &t).await;
    assert_eq!(done["result"]["redeploy_needed"], true, "{done}");

    let (status, view) = h.get(&t, "/sites/shop/data").await;
    assert_eq!(status, 200, "{view}");
    let pg = &view["postgres"];
    assert_eq!(pg["mode"], "dedicated");
    assert_eq!(pg["major"], 18);
    let users: Vec<(&str, &str)> = pg["databases"][0]["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| (u["name"].as_str().unwrap(), u["level"].as_str().unwrap()))
        .collect();
    assert_eq!(users, [("app", "readwrite"), ("migrate", "owner")]);
    let links: Vec<(String, String)> = view["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["var"].as_str().unwrap().into(),
                l["target"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(links.contains(&("DATABASE_URL".into(), "runtime".into())));
    assert!(links.contains(&("MIGRATION_DATABASE_URL".into(), "build".into())));

    // The database is provisioned and both logins are created with a password that never reaches the API.
    assert_eq!(engine.jobs_of("provision").len(), 1);
    let creates: Vec<Recorded> = engine.jobs_of("user");
    assert_eq!(creates.len(), 2);
    for c in &creates {
        assert_eq!(c.env["CITE_USER_ACTION"], "create");
        assert!(c.env["CITE_USER_ROLE"].ends_with("_a"), "{:?}", c.env);
        assert_eq!(c.env["PGHOST"], "cite-shop-db");
        assert_eq!(c.env["PGDATABASE"], "app");
        assert_eq!(c.env["CITE_USER_PASSWORD"].len(), 43);
        assert!(!c.shared_net);
    }
    let pw = secret_of(&h, "app", "app").await.a.expect("password");
    assert!(!view.to_string().contains(&pw));
    assert!(!done.to_string().contains(&pw));
    let audit = audit_actions(&h).await;
    assert!(
        audit.iter().any(|a| a == "data.postgres.enable"),
        "{audit:?}"
    );
    for e in h.state.store.audit_tail(100).await {
        assert!(!e.detail.contains(&pw), "{e:?}");
    }
    // Enabling again updates instead of re-creating.
    let again = enable(&h, &t).await;
    assert_eq!(again["result"]["redeploy_needed"], false);
}

#[tokio::test]
async fn enabling_a_second_mode_is_refused_and_bad_requests_get_400() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let (status, body) = h
        .put(&t, "/sites/shop/data/postgres", json!({ "mode": "shared" }))
        .await;
    assert_eq!(status, 409, "{body}");
    let (status, _) = h
        .put(
            &t,
            "/sites/shop/data/postgres",
            json!({ "mode": "dedicated", "major": 12 }),
        )
        .await;
    assert_eq!(status, 400);
    let (status, _) = h
        .put(
            &t,
            "/sites/shop/data/postgres",
            json!({ "mode": "dedicated", "bogus": 1 }),
        )
        .await;
    assert_eq!(status, 400);
    h.seed_site("plain").await;
    let (status, _) = h
        .put(
            &t,
            "/sites/plain/data/postgres",
            json!({ "mode": "dedicated" }),
        )
        .await;
    assert_eq!(status, 400, "a site without a repository cannot have data");
    let (status, _) = h
        .put(
            &t,
            "/sites/ghost/data/postgres",
            json!({ "mode": "dedicated" }),
        )
        .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn rotation_keeps_both_logins_until_the_old_one_is_retired() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let before = secret_of(&h, "app", "app").await;
    assert_eq!(before.active, "a");

    let (status, accepted) = h
        .post(
            &t,
            "/sites/shop/data/postgres/databases/app/users/app/rotate",
            json!({}),
        )
        .await;
    assert_eq!(status, 202, "{accepted}");
    assert_eq!(
        accepted["redeploy_needed"], true,
        "app is linked at runtime"
    );
    wait_job(&h, &t, accepted["job_id"].as_str().unwrap()).await;

    let after = secret_of(&h, "app", "app").await;
    assert_eq!(after.active, "b");
    assert_eq!(after.retiring.as_ref().unwrap().alt, "a");
    assert_eq!(
        after.a, before.a,
        "the old login keeps its password while it retires"
    );
    assert_ne!(after.b, before.a);
    let rotations: Vec<Recorded> = engine
        .jobs_of("user")
        .into_iter()
        .filter(|j| j.env["CITE_USER_ROLE"].ends_with("_b"))
        .collect();
    assert_eq!(rotations.len(), 1);
    assert_eq!(rotations[0].env["CITE_USER_ACTION"], "create");

    let (status, view) = h.get(&t, "/sites/shop/data").await;
    assert_eq!(status, 200);
    let user = &view["postgres"]["databases"][0]["users"][0];
    assert_eq!(user["active"], "b");
    assert_eq!(user["retiring"], "a");
    assert!(!view.to_string().contains(&after.b.clone().unwrap()));

    let (status, body) = h
        .post(
            &t,
            "/sites/shop/data/postgres/databases/app/users/app/rotate",
            json!({}),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("still in progress"),
        "{body}"
    );

    // An old slot still carries the login, so it stays; once none does, it is retired.
    let svc = svc_of(&h);
    assert_eq!(svc.retire_due(time::OffsetDateTime::now_utc()).await, 0);
    engine.mentioned.store(false, Ordering::SeqCst);
    assert_eq!(svc.retire_due(time::OffsetDateTime::now_utc()).await, 1);
    let done = secret_of(&h, "app", "app").await;
    assert!(done.retiring.is_none() && done.a.is_none());
    let retires: Vec<Recorded> = engine
        .jobs_of("user")
        .into_iter()
        .filter(|j| j.env["CITE_USER_ACTION"] == "retire")
        .collect();
    assert_eq!(retires.len(), 1);
    assert!(retires[0].env["CITE_USER_ROLE"].ends_with("_a"));
    assert!(
        audit_actions(&h)
            .await
            .iter()
            .any(|a| a == "data.user.rotate")
    );
}

#[tokio::test]
async fn users_can_be_added_changed_disabled_and_removed_with_the_documented_refusals() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let base = "/sites/shop/data/postgres/databases/app/users";
    run_ok(
        &h,
        &t,
        Method::POST,
        base,
        Some(json!({ "name": "report", "level": "readonly" })),
    )
    .await;
    let (status, _) = h
        .post(&t, base, json!({ "name": "report", "level": "readonly" }))
        .await;
    assert_eq!(status, 409);
    let (status, _) = h
        .post(&t, base, json!({ "name": "Bad Name", "level": "readonly" }))
        .await;
    assert_eq!(status, 400);

    run_ok(
        &h,
        &t,
        Method::PATCH,
        &format!("{base}/report"),
        Some(json!({ "disabled": true })),
    )
    .await;
    assert!(
        engine
            .jobs_of("user")
            .iter()
            .any(|j| j.env["CITE_USER_ACTION"] == "disable"
                && j.env["CITE_USER_ROLE"].contains("_report_"))
    );
    let (status, _) = h
        .call(
            Method::PATCH,
            Some(&t),
            &format!("{base}/report"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, 400);

    let (status, body) = h.delete(&t, &format!("{base}/app")).await;
    assert_eq!(status, 409, "app is linked: {body}");
    assert!(
        body["error"].as_str().unwrap().contains("DATABASE_URL"),
        "{body}"
    );
    run_ok(&h, &t, Method::DELETE, &format!("{base}/report"), None).await;
    let (status, _) = h.delete(&t, &format!("{base}/report")).await;
    assert_eq!(status, 404);
    let audit = audit_actions(&h).await;
    for name in ["data.user.create", "data.user.disable", "data.user.delete"] {
        assert!(audit.iter().any(|a| a == name), "{name} in {audit:?}");
    }
}

#[tokio::test]
async fn backups_are_versioned_encrypted_downloadable_and_restorable() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let dump = dump_bytes();
    let sha = sha_hex(&dump);

    let (status, created) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "pg:app", "label": "first" }),
        )
        .await;
    assert_eq!(status, 202, "{created}");
    let backup_id = created["backup_id"].as_str().unwrap().to_string();
    let done = wait_job(&h, &t, created["job_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "ok", "{done}");

    let (status, list) = h.get(&t, "/sites/shop/data/backups?database=pg:app").await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 1);
    let rec = &list[0];
    assert_eq!(rec["version"], 1);
    assert_eq!(rec["status"], "ok");
    assert_eq!(rec["sha256"], sha);
    assert_eq!(rec["size_bytes"], dump.len());
    assert_eq!(rec["server_version"], "18.1");
    assert_eq!(rec["encryption"]["scheme"], "cite-stream-v1");

    // At rest the file is encrypted and staging holds nothing.
    let file = h
        ._dir
        .path()
        .join("backups/sites/shop")
        .join(format!("{backup_id}.cbk"));
    let stored = std::fs::read(&file).expect("backup file");
    assert!(stored.len() > dump.len());
    assert!(
        !stored.windows(64).any(|w| w == &dump[1000..1064]),
        "the dump is stored in plaintext"
    );
    let staged: Vec<_> = std::fs::read_dir(h._dir.path().join("backups/staging/shop"))
        .unwrap()
        .collect();
    assert!(staged.is_empty(), "plaintext left in staging");

    // The download is the plain dump, with its checksum, and honours one range.
    let res = h
        .get_raw(
            &t,
            &format!("/sites/shop/data/backups/{backup_id}/download"),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["x-backup-sha256"], sha.as_str());
    assert_eq!(
        res.headers()["content-length"],
        dump.len().to_string().as_str()
    );
    assert!(
        res.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("shop-pg-app-v1.dump")
    );
    assert_eq!(res.bytes().await.unwrap().as_ref(), dump.as_slice());
    let ranged = h
        .http
        .get(h.url(&format!("/sites/shop/data/backups/{backup_id}/download")))
        .bearer_auth(&t)
        .header("range", "bytes=65530-65545")
        .send()
        .await
        .unwrap();
    assert_eq!(ranged.status().as_u16(), 206);
    assert_eq!(
        ranged.headers()["content-range"],
        format!("bytes 65530-65545/{}", dump.len()).as_str()
    );
    assert_eq!(ranged.bytes().await.unwrap().as_ref(), &dump[65530..65546]);
    let bad = h
        .http
        .get(h.url(&format!("/sites/shop/data/backups/{backup_id}/download")))
        .bearer_auth(&t)
        .header("range", "bytes=999999999-")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 416);

    // Versions count up; a pinned one cannot be deleted; labels change.
    let second = run_ok(
        &h,
        &t,
        Method::POST,
        "/sites/shop/data/backups",
        Some(json!({ "database": "pg:app" })),
    )
    .await;
    assert!(second["result"]["backup_id"].is_string());
    let (_, list) = h.get(&t, "/sites/shop/data/backups").await;
    let versions: Vec<u64> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["version"].as_u64().unwrap())
        .collect();
    assert_eq!(versions, [2, 1], "newest first");
    let (status, rec) = h
        .call(
            Method::PATCH,
            Some(&t),
            &format!("/sites/shop/data/backups/{backup_id}"),
            Some(json!({ "pinned": true, "label": "keep" })),
        )
        .await;
    assert_eq!(status, 200, "{rec}");
    assert_eq!(rec["pinned"], true);
    assert_eq!(rec["label"], "keep");
    let (status, _) = h
        .delete(&t, &format!("/sites/shop/data/backups/{backup_id}"))
        .await;
    assert_eq!(status, 409);
    let (status, _) = h
        .delete(
            &t,
            &format!("/sites/shop/data/backups/{backup_id}?from=nowhere"),
        )
        .await;
    assert_eq!(status, 400);

    // Restore needs the site id as confirmation and takes a pre_restore backup first.
    let (status, _) = h
        .post(
            &t,
            &format!("/sites/shop/data/backups/{backup_id}/restore"),
            json!({ "confirm": "other" }),
        )
        .await;
    assert_eq!(status, 400);
    let (status, started) = h
        .post(
            &t,
            &format!("/sites/shop/data/backups/{backup_id}/restore"),
            json!({ "confirm": "shop" }),
        )
        .await;
    assert_eq!(status, 202, "{started}");
    let pre = started["pre_restore_backup_id"]
        .as_str()
        .unwrap()
        .to_string();
    let done = wait_job(&h, &t, started["job_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "ok", "{done}");
    let (_, pre_rec) = h.get(&t, &format!("/sites/shop/data/backups/{pre}")).await;
    assert_eq!(pre_rec["trigger"], "pre_restore");
    assert_eq!(pre_rec["status"], "ok");
    let restores = engine.jobs_of("restore");
    assert_eq!(restores.len(), 1);
    assert_eq!(
        restores[0].env["CITE_OWNER_ROLE"].rsplit('_').next(),
        Some("owner")
    );
    assert_eq!(
        restores[0].env["CITE_LOGIN_ROLE"].rsplit('_').next(),
        Some("login")
    );
    assert_eq!(
        engine.restored.lock().unwrap().as_slice(),
        std::slice::from_ref(&dump),
        "the restore job saw the plain dump"
    );
    let events = engine.events.lock().unwrap().clone();
    let last_backup = events.iter().rposition(|e| e == "job:backup").unwrap();
    let restore_at = events.iter().position(|e| e == "job:restore").unwrap();
    assert!(
        last_backup < restore_at,
        "the pre_restore backup runs before the restore"
    );
    let staged: Vec<_> = std::fs::read_dir(h._dir.path().join("backups/staging/shop"))
        .unwrap()
        .collect();
    assert!(staged.is_empty());

    let audit = audit_actions(&h).await;
    for name in [
        "data.backup.create",
        "data.backup.download",
        "data.backup.pin",
        "data.backup.label",
        "data.backup.restore",
    ] {
        assert!(audit.iter().any(|a| a == name), "{name} in {audit:?}");
    }
}

#[tokio::test]
async fn a_failed_dump_is_recorded_without_leaving_plaintext() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    engine.fail_ops.lock().unwrap().insert("backup");
    let (status, created) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "pg:app" }),
        )
        .await;
    assert_eq!(status, 202);
    let done = wait_job(&h, &t, created["job_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "failed");
    let (_, list) = h.get(&t, "/sites/shop/data/backups").await;
    assert_eq!(list[0]["status"], "failed");
    assert!(
        list[0]["error"]
            .as_str()
            .unwrap()
            .contains("backup job failed"),
        "{list}"
    );
    let id = created["backup_id"].as_str().unwrap();
    let status = h
        .get_raw(&t, &format!("/sites/shop/data/backups/{id}/download"))
        .await
        .status()
        .as_u16();
    assert_eq!(status, 409, "a failed backup cannot be downloaded");
    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "pg:missing" }),
        )
        .await;
    assert_eq!(status, 404);
    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "nonsense" }),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn a_busy_node_answers_429_to_manual_backups() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let svc = svc_of(&h);
    let held = Arc::clone(&svc.job_permits)
        .try_acquire_many_owned(2)
        .expect("permits");
    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "pg:app" }),
        )
        .await;
    assert_eq!(status, 429);
    drop(held);
    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "pg:app" }),
        )
        .await;
    assert_eq!(status, 202);
}

#[tokio::test]
async fn links_report_conflicts_with_manual_vars_and_can_replace_them() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    let (status, _) = h
        .call(
            Method::PATCH,
            Some(&t),
            "/sites/shop/runtime-env",
            Some(json!({ "set": { "DATABASE_URL": "postgres://manual" }, "unset": [] })),
        )
        .await;
    assert_eq!(status, 200);
    let done = enable(&h, &t).await;
    let skipped = done["result"]["skipped_links"].to_string();
    assert!(
        skipped.contains("DATABASE_URL"),
        "the default link steps aside for a manual var: {skipped}"
    );

    let body = json!({
        "links": [{ "var": "DATABASE_URL", "target": "runtime",
                    "source": { "kind": "postgres", "database": "app", "user": "app", "field": "url" } }]
    });
    let (status, conflict) = h.post(&t, "/sites/shop/data/links", body.clone()).await;
    assert_eq!(status, 409, "{conflict}");
    assert_eq!(
        conflict["conflicts"],
        json!([{ "var": "DATABASE_URL", "target": "runtime", "set_by": "manual" }])
    );
    let mut with_override = body;
    with_override["override"] = json!(true);
    let (status, views) = h.post(&t, "/sites/shop/data/links", with_override).await;
    assert_eq!(status, 200, "{views}");
    assert!(
        views
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["var"] == "DATABASE_URL")
    );
    let (_, names) = h.get(&t, "/sites/shop/runtime-env").await;
    assert!(
        !names.to_string().contains("DATABASE_URL"),
        "the manual var was removed: {names}"
    );

    let (status, conflict) = h
        .post(
            &t,
            "/sites/shop/data/links",
            json!({ "links": [{ "var": "DATABASE_URL", "target": "runtime",
                                 "source": { "kind": "postgres", "database": "app", "user": "migrate", "field": "url" } }] }),
        )
        .await;
    assert_eq!(status, 409);
    assert_eq!(conflict["conflicts"][0]["set_by"], "link");

    let (status, _) = h
        .delete(&t, "/sites/shop/data/links/runtime/DATABASE_URL")
        .await;
    assert_eq!(status, 200);
    let (status, _) = h
        .delete(&t, "/sites/shop/data/links/runtime/DATABASE_URL")
        .await;
    assert_eq!(status, 404);
    let (status, _) = h.delete(&t, "/sites/shop/data/links/elsewhere/X").await;
    assert_eq!(status, 400);
    let audit = audit_actions(&h).await;
    assert!(audit.iter().any(|a| a == "data.link.create"));
    assert!(audit.iter().any(|a| a == "data.link.delete"));
}

#[tokio::test]
async fn presets_create_what_they_need_and_report_it() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let (status, resp) = h
        .post(
            &t,
            "/sites/shop/data/links/preset",
            json!({ "preset": "authjs" }),
        )
        .await;
    assert_eq!(status, 202, "{resp}");
    assert_eq!(resp["created_secrets"], json!(["auth-secret"]));
    let done = wait_job(&h, &t, resp["job_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "ok", "{done}");
    let (_, view) = h.get(&t, "/sites/shop/data").await;
    let dbs: Vec<&str> = view["postgres"]["databases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert!(dbs.contains(&"auth"), "{dbs:?}");
    assert!(view["secrets"][0]["name"] == "auth-secret");
    let vars: Vec<&str> = view["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["var"].as_str().unwrap())
        .collect();
    assert!(
        vars.contains(&"AUTH_SECRET") && vars.contains(&"AUTH_DATABASE_URL"),
        "{vars:?}"
    );
    assert!(
        audit_actions(&h)
            .await
            .iter()
            .any(|a| a == "data.link.preset")
    );
}

#[tokio::test]
async fn generated_secrets_rotate_without_ever_being_returned() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    let (status, created) = h
        .post(
            &t,
            "/sites/shop/data/secrets",
            json!({ "name": "auth-secret" }),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["bytes"], 32);
    let name = cite_edge::datamodel::generated_secret_name("shop", "auth-secret");
    let first: serde_json::Value =
        serde_json::from_str(&h.state.store.get_secret(&name).await.unwrap()).unwrap();
    let value = first["value"].as_str().unwrap().to_string();
    assert_eq!(value.len(), 43);
    assert!(!created.to_string().contains(&value));
    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/secrets",
            json!({ "name": "auth-secret" }),
        )
        .await;
    assert_eq!(status, 409);
    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/secrets",
            json!({ "name": "x", "bytes": 8 }),
        )
        .await;
    assert_eq!(status, 400);

    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/links",
            json!({ "links": [{ "var": "AUTH_SECRET", "target": "runtime", "source": { "kind": "secret", "name": "auth-secret" } }] }),
        )
        .await;
    assert_eq!(status, 200);
    let (status, rotated) = h
        .post(&t, "/sites/shop/data/secrets/auth-secret/rotate", json!({}))
        .await;
    assert_eq!(status, 200, "{rotated}");
    assert_eq!(rotated["redeploy_needed"], true);
    let second: serde_json::Value =
        serde_json::from_str(&h.state.store.get_secret(&name).await.unwrap()).unwrap();
    assert_ne!(second["value"], first["value"]);
    assert_eq!(second["previous"], first["value"]);
    assert!(
        !rotated
            .to_string()
            .contains(second["value"].as_str().unwrap())
    );
    let (status, _) = h.delete(&t, "/sites/shop/data/secrets/auth-secret").await;
    assert_eq!(status, 409, "linked");
    h.delete(&t, "/sites/shop/data/links/runtime/AUTH_SECRET")
        .await;
    let (status, _) = h.delete(&t, "/sites/shop/data/secrets/auth-secret").await;
    assert_eq!(status, 200);
    assert!(h.state.store.get_secret(&name).await.is_none());
}

#[tokio::test]
async fn external_databases_are_write_only_and_respect_node_policy() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    let url = "postgres://user:hunter2hunter2@db.example.com:5432/billing?sslmode=require";
    let (status, view) = h
        .put(
            &t,
            "/sites/shop/data/external/billing",
            json!({ "url": url }),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["host"], "db.example.com");
    assert_eq!(view["database"], "billing");
    assert_eq!(view["forward_port"], 15432);
    assert!(!view.to_string().contains("hunter2"));
    let (_, all) = h.get(&t, "/sites/shop/data").await;
    assert!(!all.to_string().contains("hunter2"));
    for e in h.state.store.audit_tail(100).await {
        assert!(!e.detail.contains("hunter2"), "{e:?}");
    }

    engine.ports_open.store(false, Ordering::SeqCst);
    let (status, body) = h
        .put(
            &t,
            "/sites/shop/data/external/other",
            json!({ "url": "postgres://u:p@db2.example.com/x" }),
        )
        .await;
    assert_eq!(status, 422, "{body}");
    assert!(body["error"].as_str().unwrap().contains("ALLOW_PORTS"));
    engine.ports_open.store(true, Ordering::SeqCst);
    let (status, _) = h
        .put(
            &t,
            "/sites/shop/data/external/other",
            json!({ "url": "mysql://u:p@db2.example.com/x" }),
        )
        .await;
    assert_eq!(status, 400);

    // A linked attachment cannot be removed.
    let (status, _) = h
        .post(
            &t,
            "/sites/shop/data/links",
            json!({ "links": [{ "var": "BILLING_URL", "target": "runtime",
                                 "source": { "kind": "external", "name": "billing", "field": "url" } }] }),
        )
        .await;
    assert_eq!(status, 200);
    let (status, _) = h.delete(&t, "/sites/shop/data/external/billing").await;
    assert_eq!(status, 409);
    h.delete(&t, "/sites/shop/data/links/runtime/BILLING_URL")
        .await;
    let (status, _) = h.delete(&t, "/sites/shop/data/external/billing").await;
    assert_eq!(status, 200);
    assert!(
        h.state
            .store
            .get_secret(&cite_edge::datamodel::external_secret_name(
                "shop", "billing"
            ))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn redactions_cover_encoded_passwords_and_every_rendered_secret_value() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    let password = "pa$$w0rd!@:/";
    let encoded = "pa%24%24w0rd%21%40%3A%2F";
    let url = format!("postgres://user:{encoded}@db.example.com:5432/billing?sslmode=require");
    let (status, view) = h
        .put(
            &t,
            "/sites/shop/data/external/billing",
            json!({ "url": url }),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    let (status, body) = h
        .post(
            &t,
            "/sites/shop/data/links",
            json!({ "links": [
                { "var": "BILLING_URL", "target": "runtime",
                  "source": { "kind": "external", "name": "billing", "field": "url" } },
                { "var": "BILLING_PASSWORD", "target": "runtime",
                  "source": { "kind": "external", "name": "billing", "field": "password" } },
                { "var": "BILLING_HOST", "target": "runtime",
                  "source": { "kind": "external", "name": "billing", "field": "host" } }
            ] }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let site = h.state.deployer.get_site("shop").unwrap();
    let list = svc_of(&h).redactions(&site).await;
    assert!(list.iter().any(|s| s == password), "{list:?}");
    assert!(list.iter().any(|s| s == encoded), "{list:?}");
    // The URL the runtime gets on a filtered node goes through the slot's egress forward; both slots are covered.
    for slot in ["blue", "green"] {
        assert!(
            list.iter().any(|s| s.starts_with(&format!(
                "postgres://user:{encoded}@cite-shop-{slot}-egress-proxy:"
            ))),
            "{slot}: {list:?}"
        );
    }
    // Values without a secret in them stay readable in the logs.
    assert!(!list.iter().any(|s| s == "db.example.com"), "{list:?}");
    assert!(!list.iter().any(|s| s == "5432"), "{list:?}");
}

#[tokio::test]
async fn backup_targets_hold_their_keys_privately_and_guard_their_users() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let req = json!({
        "name": "offsite", "endpoint": "https://s3.example.com", "bucket": "my-backups", "region": "eu-west-1",
        "access_key_id": "AKIAEXAMPLE0000", "secret_access_key": "s3cretsecretvalue"
    });
    let (status, view) = h.post(&t, "/data/targets", req.clone()).await;
    assert_eq!(status, 201, "{view}");
    assert!(
        !view.to_string().contains("s3cretsecretvalue")
            && !view.to_string().contains("AKIAEXAMPLE")
    );
    assert_eq!(view["prefix"], "cite");
    assert_eq!(view["encrypt"], true);
    let tid = view["id"].as_str().unwrap().to_string();
    let (_, list) = h.get(&t, "/data/targets").await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains("s3cretsecretvalue"));
    let (status, _) = h.post(&t, "/data/targets", req).await;
    assert_eq!(status, 409, "names are unique");
    for (field, value) in [
        ("endpoint", json!("http://s3.example.com")),
        ("bucket", json!("X")),
        ("encrypt", json!(false)),
        ("prefix", json!("../x")),
    ] {
        let mut bad = json!({
            "name": "other", "endpoint": "https://s3.example.com", "bucket": "my-backups", "region": "eu-west-1",
            "access_key_id": "a", "secret_access_key": "b"
        });
        bad[field] = value;
        let (status, body) = h.post(&t, "/data/targets", bad).await;
        assert_eq!(status, 400, "{field}: {body}");
    }

    let (status, _) = h
        .put(
            &t,
            "/sites/shop/data/postgres/policy",
            json!({ "local": {}, "s3": { "target": "missing" } }),
        )
        .await;
    assert_eq!(status, 400);
    let (status, view) = h
        .put(
            &t,
            "/sites/shop/data/postgres/policy",
            json!({ "schedule": { "every_hours": 6, "minute": 15 }, "local": {}, "s3": { "target": tid } }),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["backup"]["schedule"]["every_hours"], 6);
    let (status, _) = h
        .put(
            &t,
            "/sites/shop/data/postgres/policy",
            json!({ "schedule": { "every_hours": 5, "minute": 0 }, "local": {} }),
        )
        .await;
    assert_eq!(status, 400, "5 is not an allowed interval");
    let (status, body) = h.delete(&t, &format!("/data/targets/{tid}")).await;
    assert_eq!(status, 409, "{body}");
    let audit = audit_actions(&h).await;
    assert!(audit.iter().any(|a| a == "data.target.create"));
    assert!(audit.iter().any(|a| a == "data.policy.update"));
}

fn target_body(name: &str, endpoint: &str) -> Value {
    json!({
        "name": name, "endpoint": endpoint, "bucket": "my-backups", "region": "eu-west-1",
        "access_key_id": "AKIAEXAMPLE0000", "secret_access_key": "s3cretsecretvalue"
    })
}

#[tokio::test]
async fn target_endpoints_follow_the_address_rule_with_the_flag_off_and_on() {
    let blocked = [
        "169.254.169.254",
        "127.0.0.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[fe80::1]",
        "0.0.0.0",
        "224.0.0.1",
    ];
    let private = [
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.10",
        "100.64.0.1",
        "[fd00::1]",
    ];
    for allow in [false, true] {
        let (h, _) = start_data_with(allow).await;
        let t = h.token().await;
        seed_shop(&h).await;
        enable(&h, &t).await;
        for host in blocked {
            for scheme in ["https", "http"] {
                let (status, body) = h
                    .post(
                        &t,
                        "/data/targets",
                        target_body("blocked", &format!("{scheme}://{host}:9000")),
                    )
                    .await;
                assert_eq!(status, 400, "{scheme}://{host} allow={allow}: {body}");
            }
        }
        for (i, host) in private.iter().enumerate() {
            for (j, scheme) in ["https", "http"].iter().enumerate() {
                let (status, body) = h
                    .post(
                        &t,
                        "/data/targets",
                        target_body(&format!("p{i}{j}"), &format!("{scheme}://{host}:9000")),
                    )
                    .await;
                assert_eq!(
                    status,
                    if allow { 201 } else { 400 },
                    "{scheme}://{host} allow={allow}: {body}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_target_test_reports_a_fixed_classification_and_no_server_text() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let (status, view) = h
        .post(
            &t,
            "/data/targets",
            target_body("offsite", "https://s3.example.com"),
        )
        .await;
    assert_eq!(status, 201, "{view}");
    let tid = view["id"].as_str().unwrap().to_string();
    // A stored endpoint that the address rule refuses (for example after the flag was turned off).
    let path = h.state.cfg.data_dir.join("data").join("targets.json");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("https://s3.example.com", "https://169.254.169.254"),
    )
    .unwrap();
    let (status, body) = h
        .post(&t, &format!("/data/targets/{tid}/test"), json!({}))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "refused_address", "{body}");
    assert!(!body.to_string().contains("s3cretsecretvalue"));
}

#[tokio::test]
async fn the_shared_instance_writes_its_hba_before_it_starts_and_confines_tenants() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    let (status, body) = h
        .put(&t, "/sites/shop/data/postgres", json!({ "mode": "shared" }))
        .await;
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("not enabled"),
        "{body}"
    );

    run_ok(
        &h,
        &t,
        Method::PUT,
        "/data/shared",
        Some(json!({ "memory_mb": 512, "cpus": 1.0, "max_connections": 100 })),
    )
    .await;
    let events = engine.events.lock().unwrap().clone();
    let hba = events.iter().position(|e| e == "job:hba").expect("hba job");
    let start = events
        .iter()
        .position(|e| e == "ensure_shared_instance")
        .expect("instance start");
    assert!(
        hba < start,
        "pg_hba.conf must exist before the server starts: {events:?}"
    );
    let first = &engine.jobs_of("hba")[0];
    assert_eq!(first.env["CITE_PG_RELOAD"], "0");
    assert_eq!(first.env["CITE_PG_HBA"], "_admin|172.30.0.0/24");
    assert!(first.shared_net);

    let (status, shared) = h.get(&t, "/data/shared").await;
    assert_eq!(status, 200);
    assert_eq!(shared["enabled"], true);
    assert_eq!(shared["major"], 18);

    run_ok(
        &h,
        &t,
        Method::PUT,
        "/sites/shop/data/postgres",
        Some(json!({ "mode": "shared" })),
    )
    .await;
    let tag = cite_edge::datamodel::pg_site_tag("shop");
    let provision = &engine.jobs_of("provision")[0];
    assert_eq!(provision.env["PGHOST"], "cite-pg-shared");
    assert_eq!(provision.env["PGDATABASE"], format!("t{tag}_app"));
    assert_eq!(provision.env["CITE_ROLE_TAG"], format!("t{tag}_app"));
    assert!(provision.shared_net);
    let last_hba = engine.jobs_of("hba").pop().unwrap();
    assert_eq!(last_hba.env["CITE_PG_RELOAD"], "1");
    assert_eq!(
        last_hba.env["CITE_PG_HBA"],
        format!("_admin|172.30.0.0/24;t{tag}_app|172.31.1.0/24"),
        "each tenant database is tied to its own network"
    );

    let (status, body) = h.delete(&t, "/data/shared").await;
    assert_eq!(status, 409, "tenants block deletion: {body}");
    let (status, body) = h.delete(&t, "/data/shared?force=maybe").await;
    assert_eq!(status, 400, "{body}");
    let audit = audit_actions(&h).await;
    assert!(audit.iter().any(|a| a == "data.shared.enable"));
}

#[tokio::test]
async fn disabling_postgres_removes_its_links_and_keeps_or_purges_the_data() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let done = run_ok(&h, &t, Method::DELETE, "/sites/shop/data/postgres", None).await;
    assert_eq!(done["result"]["links_removed"], 2, "{done}");
    assert!(
        engine
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e == "remove_site_database:shop:false")
    );
    let (_, view) = h.get(&t, "/sites/shop/data").await;
    assert!(view["postgres"].is_null());
    assert!(view["links"].as_array().unwrap().is_empty());
    assert!(
        h.state
            .store
            .get_secret(&cite_edge::datamodel::pg_user_secret_name(
                "shop", "app", "app"
            ))
            .await
            .is_some(),
        "credentials stay so the data can be adopted again"
    );
    enable(&h, &t).await;
    run_ok(
        &h,
        &t,
        Method::DELETE,
        "/sites/shop/data/postgres?purge=true",
        None,
    )
    .await;
    assert!(
        engine
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e == "remove_site_database:shop:true")
    );
    assert!(
        h.state
            .store
            .get_secret(&cite_edge::datamodel::pg_user_secret_name(
                "shop", "app", "app"
            ))
            .await
            .is_none()
    );
    let (status, _) = h.delete(&t, "/sites/shop/data/postgres").await;
    assert_eq!(status, 400, "nothing left to disable");
    let audit = audit_actions(&h).await;
    assert!(audit.iter().any(|a| a == "data.postgres.disable"));
    assert!(audit.iter().any(|a| a == "data.postgres.purge"));
}

#[tokio::test]
async fn databases_can_be_added_but_not_beyond_the_limit_or_while_linked() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let base = "/sites/shop/data/postgres/databases";
    run_ok(
        &h,
        &t,
        Method::POST,
        base,
        Some(json!({ "name": "reports" })),
    )
    .await;
    assert_eq!(engine.jobs_of("provision").len(), 2);
    let (status, _) = h.post(&t, base, json!({ "name": "reports" })).await;
    assert_eq!(status, 409);
    for bad in ["postgres", "template1", "Has-Dash", ""] {
        let (status, _) = h.post(&t, base, json!({ "name": bad })).await;
        assert_eq!(status, 400, "{bad:?}");
    }
    run_ok(&h, &t, Method::POST, base, Some(json!({ "name": "three" }))).await;
    run_ok(&h, &t, Method::POST, base, Some(json!({ "name": "four" }))).await;
    let (status, _) = h.post(&t, base, json!({ "name": "five" })).await;
    assert_eq!(status, 400, "at most four databases");
    let (status, body) = h.delete(&t, &format!("{base}/app")).await;
    assert_eq!(status, 409, "app is linked: {body}");
    run_ok(&h, &t, Method::DELETE, &format!("{base}/four"), None).await;
    let (_, view) = h.get(&t, "/sites/shop/data").await;
    assert_eq!(view["postgres"]["databases"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn jobs_that_do_not_exist_are_404_and_orphans_list_deleted_sites_data() {
    let (h, _) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let (status, _) = h.get(&t, "/data/jobs/01JZZZZZZZZZZZZZZZZZZZZZZZ").await;
    assert_eq!(status, 404);
    let (status, orphans) = h.get(&t, "/data/orphans").await;
    assert_eq!(status, 200);
    assert!(orphans.as_array().unwrap().is_empty());
    let (status, _) = h.delete(&t, "/data/orphans/shop").await;
    assert_eq!(status, 409, "the site still exists");
    h.state
        .store
        .update("test", "gone", |cfg| {
            cfg.sites.retain(|s| s.id != "shop");
            Ok(())
        })
        .await
        .unwrap();
    let (_, orphans) = h.get(&t, "/data/orphans").await;
    assert_eq!(orphans[0]["site"], "shop");
    assert_eq!(orphans[0]["dedicated_volume"], "cite-shop-db-data");
    assert!(orphans[0]["secrets"].as_u64().unwrap() >= 3);
    run_ok_delete(&h, &t, "/data/orphans/shop").await;
    let (_, orphans) = h.get(&t, "/data/orphans").await;
    assert!(orphans.as_array().unwrap().is_empty());
    assert!(
        h.state
            .store
            .get_secret(&cite_edge::datamodel::pg_user_secret_name(
                "shop", "app", "app"
            ))
            .await
            .is_none()
    );
}

/// Every recorded job in order, as `op` or `op:action` for the job-login steps.
fn job_trail(engine: &FakeEngine) -> Vec<String> {
    engine
        .jobs
        .lock()
        .unwrap()
        .iter()
        .map(|j| match j.env.get("CITE_JOB_ACTION") {
            Some(a) => format!("{}:{a}", j.op),
            None => j.op.to_string(),
        })
        .collect()
}

async fn superuser_password(h: &Harness) -> String {
    svc_of(h)
        .secret_get::<crate::data::service::PwSecret>(
            &cite_edge::datamodel::pg_superuser_secret_name("shop"),
        )
        .await
        .unwrap()
        .expect("superuser secret")
        .password
}

#[tokio::test]
async fn tenant_database_work_runs_as_the_job_login_between_an_open_and_a_close() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let tag = format!("t{}_app", cite_edge::datamodel::pg_site_tag("shop"));
    let job_login = format!("{tag}_job");
    let su = superuser_password(&h).await;

    // Provisioning: roles and database as the superuser, the layout inside the database as the job login.
    let trail = job_trail(&engine);
    let at = trail.iter().position(|o| o == "provision").unwrap();
    assert_eq!(
        trail[at..at + 4],
        ["provision", "joblogin:open", "regrant", "joblogin:close"],
        "{trail:?}"
    );

    let backup = run_ok(
        &h,
        &t,
        Method::POST,
        "/sites/shop/data/backups",
        Some(json!({ "database": "pg:app" })),
    )
    .await;
    let backup_id = backup["result"]["backup_id"].as_str().unwrap().to_string();
    run_ok(
        &h,
        &t,
        Method::POST,
        &format!("/sites/shop/data/backups/{backup_id}/restore"),
        Some(json!({ "confirm": "shop" })),
    )
    .await;
    let trail = job_trail(&engine);
    let restore = trail.iter().position(|o| o == "restore").unwrap();
    assert_eq!(
        trail[restore - 1..=restore + 1],
        ["joblogin:lock", "restore", "joblogin:close"],
        "a restore locks the tenant's logins while it runs: {trail:?}"
    );

    let jobs = engine.jobs.lock().unwrap().clone();
    for (i, j) in jobs.iter().enumerate() {
        match j.op {
            "backup" | "restore" | "counts" | "regrant" => {
                assert_eq!(j.env["PGUSER"], job_login, "{}", j.op);
                let pw = j.env.get("PGPASSWORD").unwrap_or_else(|| {
                    panic!("{} job {i} has no PGPASSWORD: {:?}", j.op, j.env.keys())
                });
                assert_ne!(pw, &su, "{}", j.op);
                // A restore names its database through the owner role; the other operations carry the tag itself.
                if j.op == "restore" {
                    assert_eq!(j.env["CITE_OWNER_ROLE"], format!("{tag}_owner"));
                } else {
                    assert_eq!(j.env["CITE_ROLE_TAG"].as_str(), tag, "{}", j.op);
                }
                // The password is the one the open step just set, and it is never reused.
                let open = &jobs[i - 1];
                assert_eq!(open.op, "joblogin");
                assert_eq!(open.env["CITE_JOB_PASSWORD"], j.env["PGPASSWORD"]);
                assert_eq!(open.env["PGUSER"], "postgres");
                assert_eq!(open.env["PGPASSWORD"], su);
                let close = &jobs[i + 1];
                assert_eq!(close.env["CITE_JOB_ACTION"], "close");
                assert!(!close.env.contains_key("CITE_JOB_PASSWORD"));
            }
            _ => {
                assert_eq!(j.env["PGUSER"], "postgres", "{}", j.op);
                assert!(!j.env.contains_key("CITE_JOB_PASSWORD") || j.op == "joblogin");
            }
        }
    }
    let passwords: HashSet<&str> = jobs
        .iter()
        .filter_map(|j| j.env.get("CITE_JOB_PASSWORD").map(String::as_str))
        .collect();
    let opens = jobs
        .iter()
        .filter(|j| j.env.contains_key("CITE_JOB_PASSWORD"))
        .count();
    assert_eq!(passwords.len(), opens, "every job gets a fresh password");
    assert!(passwords.iter().all(|p| p.len() == 43));
}

#[tokio::test]
async fn the_job_login_is_closed_even_when_the_job_fails() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    engine.fail_ops.lock().unwrap().insert("backup");
    let (status, created) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "pg:app" }),
        )
        .await;
    assert_eq!(status, 202);
    let done = wait_job(&h, &t, created["job_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "failed");
    let trail = job_trail(&engine);
    assert_eq!(
        trail[trail.len() - 3..],
        ["joblogin:open", "backup", "joblogin:close"],
        "{trail:?}"
    );

    // A failed open still runs the close, and the work never starts.
    engine.fail_ops.lock().unwrap().clear();
    engine.fail_ops.lock().unwrap().insert("joblogin");
    let (_, created) = h
        .post(
            &t,
            "/sites/shop/data/backups",
            json!({ "database": "pg:app" }),
        )
        .await;
    let done = wait_job(&h, &t, created["job_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "failed");
    let trail = job_trail(&engine);
    assert_eq!(
        trail[trail.len() - 2..],
        ["joblogin:open", "joblogin:close"],
        "{trail:?}"
    );
}

#[tokio::test]
async fn deleting_a_user_clears_what_it_owns_as_the_job_login_before_the_role_goes() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    enable(&h, &t).await;
    let base = "/sites/shop/data/postgres/databases/app/users";
    run_ok(
        &h,
        &t,
        Method::POST,
        base,
        Some(json!({ "name": "report", "level": "readonly" })),
    )
    .await;
    let before = engine.jobs.lock().unwrap().len();
    run_ok(&h, &t, Method::DELETE, &format!("{base}/report"), None).await;
    let jobs: Vec<Recorded> = engine.jobs.lock().unwrap()[before..].to_vec();
    let trail: Vec<String> = jobs
        .iter()
        .map(|j| {
            j.env
                .get("CITE_USER_ACTION")
                .or_else(|| j.env.get("CITE_JOB_ACTION"))
                .map_or(j.op.to_string(), |a| format!("{}:{a}", j.op))
        })
        .collect();
    assert_eq!(
        trail,
        [
            "user:disable",
            "joblogin:open",
            "regrant",
            "joblogin:close",
            "user:drop"
        ]
    );
    let login = format!(
        "t{}_app_report_a",
        cite_edge::datamodel::pg_site_tag("shop")
    );
    assert_eq!(jobs[2].env["CITE_USER_ROLE"], login);
    assert_eq!(jobs[4].env["PGUSER"], "postgres");
}

#[tokio::test]
async fn reconcile_rewrites_the_hba_file_only_when_a_subnet_changed() {
    let (h, engine) = start_data().await;
    let t = h.token().await;
    seed_shop(&h).await;
    run_ok(
        &h,
        &t,
        Method::PUT,
        "/data/shared",
        Some(json!({ "memory_mb": 512, "cpus": 1.0, "max_connections": 100 })),
    )
    .await;
    run_ok(
        &h,
        &t,
        Method::PUT,
        "/sites/shop/data/postgres",
        Some(json!({ "mode": "shared" })),
    )
    .await;
    let svc = svc_of(&h);
    let written = engine.jobs_of("hba").len();
    svc.reconcile().await;
    assert_eq!(
        engine.jobs_of("hba").len(),
        written,
        "nothing changed since the last reload"
    );

    // Docker recreated the tenant's network with another subnet.
    *engine.subnet.lock().unwrap() = "172.31.9.0/24".to_string();
    svc.reconcile().await;
    let hba = engine.jobs_of("hba");
    assert_eq!(hba.len(), written + 1);
    let last = hba.last().unwrap();
    let tag = cite_edge::datamodel::pg_site_tag("shop");
    assert_eq!(last.env["CITE_PG_RELOAD"], "1");
    assert_eq!(
        last.env["CITE_PG_HBA"],
        format!("_admin|172.30.0.0/24;t{tag}_app|172.31.9.0/24"),
        "the stale subnet is gone"
    );
    svc.reconcile().await;
    assert_eq!(engine.jobs_of("hba").len(), written + 1);

    // A failed write is tried again by the next pass.
    *engine.subnet.lock().unwrap() = "172.31.10.0/24".to_string();
    engine.fail_ops.lock().unwrap().insert("hba");
    svc.reconcile().await;
    engine.fail_ops.lock().unwrap().clear();
    svc.reconcile().await;
    let last = engine.jobs_of("hba").pop().unwrap();
    assert!(last.env["CITE_PG_HBA"].ends_with("|172.31.10.0/24"));
    assert_eq!(engine.jobs_of("hba").len(), written + 3);
}

async fn run_ok_delete(h: &Harness, t: &str, path: &str) {
    let (status, v) = h.delete(t, path).await;
    assert_eq!(status, 202, "{v}");
    let done = wait_job(h, t, v["job_id"].as_str().unwrap()).await;
    assert_eq!(done["state"], "ok", "{done}");
}
