//! Conversion and node-to-node transfer through the real routes over a fake Docker engine: exports and their chunk
//! hashes, import chunk idempotency and the 409 on a different hash, a commit whose checksum does not match, restart
//! recovery of sessions, conversion both ways, and the client driver between two in-process connectors.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use cite_client::transfer::{self, TransferEnv};
use cite_client::{
    CancelFlag, MemoryTransferStore, NodeClient, NodeConfig, TransferError, TransferPhase,
    TransferPlan, TransferState, TransferStore,
};
use cite_edge::datawire::{Freeze, TRANSFER_CHUNK_BYTES};
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

const CHUNK: usize = TRANSFER_CHUNK_BYTES as usize;
const COUNTS: &str = "public\torders\t3\n";

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
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
    dump: Vec<u8>,
    counts: String,
    counts_queue: StdMutex<VecDeque<String>>,
    events: StdMutex<Vec<String>>,
    jobs: StdMutex<Vec<Recorded>>,
    fail_ops: StdMutex<HashSet<&'static str>>,
    restored: StdMutex<Vec<Vec<u8>>>,
}

impl FakeEngine {
    fn new(root: PathBuf, dump: Vec<u8>, counts: &str) -> FakeEngine {
        FakeEngine {
            root,
            dump,
            counts: counts.to_string(),
            counts_queue: StdMutex::new(VecDeque::new()),
            events: StdMutex::new(Vec::new()),
            jobs: StdMutex::new(Vec::new()),
            fail_ops: StdMutex::new(HashSet::new()),
            restored: StdMutex::new(Vec::new()),
        }
    }

    fn event(&self, text: &str) {
        self.events.lock().unwrap().push(text.to_string());
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
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

    fn restored(&self) -> Vec<Vec<u8>> {
        self.restored.lock().unwrap().clone()
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
        Box::pin(async { Ok("172.30.0.0/24".to_string()) })
    }
    fn dbnet_subnet<'a>(&'a self, _site_id: &'a str) -> Fut<'a, String> {
        Box::pin(async { Ok("172.31.1.0/24".to_string()) })
    }
    fn connect_shared<'a>(&'a self, _site_id: &'a str) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn disconnect_shared<'a>(&'a self, site_id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.event(&format!("disconnect_shared:{site_id}"));
            Ok(())
        })
    }
    fn reconnect_shared<'a>(&'a self, _site_ids: &'a [String]) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn env_mentions<'a>(&'a self, _site_id: &'a str, _needles: &'a [String]) -> Fut<'a, bool> {
        Box::pin(async { Ok(true) })
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
                    std::fs::write(dir.join(format!("{id}.dump")), &self.dump).unwrap();
                    std::fs::write(dir.join(format!("{id}.version")), "18.1\n").unwrap();
                }
                "restore" => {
                    let bytes = std::fs::read(dir.join(format!("{id}.dump"))).unwrap();
                    self.restored.lock().unwrap().push(bytes);
                }
                "counts" => {
                    let text = self
                        .counts_queue
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| self.counts.clone());
                    std::fs::write(dir.join(format!("{id}.counts")), text).unwrap();
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
        true
    }
}

struct Node {
    h: Harness,
    engine: Arc<FakeEngine>,
    t: String,
}

impl Node {
    fn svc(&self) -> Arc<DataService> {
        self.h.state.data.get().cloned().expect("data service")
    }

    fn client(&self, name: &str) -> NodeClient {
        NodeClient::new(
            &NodeConfig {
                name: name.to_string(),
                url: format!("http://{}", self.h.addr),
                ca_pem: None,
                token_ref: "test".into(),
                insecure_http: false,
            },
            self.t.clone(),
        )
        .expect("client")
    }

    async fn actions(&self) -> Vec<String> {
        self.h
            .state
            .store
            .audit_tail(500)
            .await
            .into_iter()
            .map(|e| e.action)
            .collect()
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        self.h.get(&self.t, path).await
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        self.h.post(&self.t, path, body).await
    }

    async fn wait_job(&self, job: &str) -> Value {
        for _ in 0..800 {
            let (status, v) = self.get(&format!("/data/jobs/{job}")).await;
            assert_eq!(status, 200, "{v}");
            if v["state"] != "running" {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("job {job} did not finish");
    }

    async fn run_ok(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, v) = self.h.call(method, Some(&self.t), path, body).await;
        assert_eq!(status, 202, "{path}: {v}");
        let done = self.wait_job(v["job_id"].as_str().expect("job id")).await;
        assert_eq!(done["state"], "ok", "{path}: {done}");
        done
    }

    /// Polls a session until it reaches one of the wanted states; a failure is only allowed when it is wanted.
    async fn wait_session(&self, path: &str, want: &[&str]) -> Value {
        for _ in 0..800 {
            let (status, v) = self.get(path).await;
            assert_eq!(status, 200, "{path}: {v}");
            let state = v["state"].as_str().expect("state").to_string();
            if want.contains(&state.as_str()) {
                return v;
            }
            assert!(
                state != "failed" && state != "rolled_back",
                "{path} reached {state}: {v}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("{path} did not reach {want:?}");
    }

    async fn secret(&self, name: &str) -> Option<UserSecret> {
        self.svc().secret_get(name).await.expect("read secret")
    }
}

async fn start_node(dump: Vec<u8>, counts: &str) -> Node {
    let h = start().await;
    let root = h._dir.path().join("backups");
    let engine = Arc::new(FakeEngine::new(root.clone(), dump, counts));
    let cfg = DataConfig {
        data_dir: h.state.cfg.data_dir.clone(),
        backup_dir: root,
        backup_volume: "cite-backups".into(),
        s3_allow_private: false,
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
    let t = h.token().await;
    Node { h, engine, t }
}

/// A node with a dedicated database enabled for the `shop` site.
async fn node_with_postgres(dump: Vec<u8>, counts: &str) -> Node {
    let n = start_node(dump, counts).await;
    n.run_ok(
        Method::PUT,
        "/sites/shop/data/postgres",
        Some(json!({ "mode": "dedicated" })),
    )
    .await;
    n
}

async fn enable_shared_instance(n: &Node) {
    n.run_ok(
        Method::PUT,
        "/data/shared",
        Some(json!({ "memory_mb": 512, "cpus": 1.0, "max_connections": 100 })),
    )
    .await;
}

fn manifest_json(payload: &[u8], sha: &str, counts: &str) -> Value {
    let rows: Vec<Value> = counts
        .lines()
        .map(|l| {
            let p: Vec<&str> = l.split('\t').collect();
            json!({ "schema": p[0], "table": p[1], "rows": p[2].parse::<u64>().unwrap() })
        })
        .collect();
    json!({
        "site": "shop",
        "database": "pg:app",
        "server_version": "18.1",
        "size_bytes": payload.len(),
        "sha256": sha,
        "chunk_size": CHUNK,
        "chunks": payload.len().div_ceil(CHUNK),
        "counts": rows,
        "users": [
            { "name": "app", "level": "readwrite", "connection_limit": 20,
              "statement_timeout_ms": 30000, "idle_in_transaction_timeout_ms": 60000 },
            { "name": "migrate", "level": "owner", "connection_limit": 20,
              "statement_timeout_ms": 0, "idle_in_transaction_timeout_ms": 60000 }
        ],
        "links": [],
        "generated_secrets": []
    })
}

async fn create_import(n: &Node, payload: &[u8], sha: &str) -> String {
    let body = json!({ "manifest": manifest_json(payload, sha, COUNTS), "replace": true });
    let (status, v) = n.post("/sites/shop/data/imports", body).await;
    assert_eq!(status, 201, "{v}");
    v["session"].as_str().expect("session").to_string()
}

async fn put_chunk(n: &Node, sid: &str, index: u64, sha: &str, body: Vec<u8>) -> (u16, String) {
    let res =
        n.h.http
            .put(n.h.url(&format!("/sites/shop/data/imports/{sid}/chunks/{index}")))
            .bearer_auth(&n.t)
            .header("x-chunk-sha256", sha)
            .body(body)
            .send()
            .await
            .expect("request");
    let status = res.status().as_u16();
    (status, res.text().await.unwrap_or_default())
}

async fn upload_all(n: &Node, sid: &str, payload: &[u8]) {
    for (i, piece) in payload.chunks(CHUNK).enumerate() {
        let (status, body) = put_chunk(n, sid, i as u64, &sha_hex(piece), piece.to_vec()).await;
        assert_eq!(status, 204, "chunk {i}: {body}");
    }
}

async fn commit(n: &Node, sid: &str) -> Value {
    let (status, v) = n
        .post(&format!("/sites/shop/data/imports/{sid}/commit"), json!({}))
        .await;
    assert_eq!(status, 202, "{v}");
    n.wait_job(v["job_id"].as_str().expect("job")).await
}

// ---- export ----

#[tokio::test]
async fn an_export_serves_its_chunks_with_hashes_and_a_manifest() {
    let payload = patterned(CHUNK + 1000);
    let n = node_with_postgres(payload.clone(), COUNTS).await;
    let (status, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "none" }),
        )
        .await;
    assert_eq!(status, 202, "{v}");
    let sid = v["session"].as_str().unwrap().to_string();
    let base = format!("/sites/shop/data/exports/{sid}");
    let session = n.wait_session(&base, &["ready"]).await;
    assert_eq!(session["kind"], "export");
    assert_eq!(session["size_bytes"], payload.len());
    assert_eq!(session["chunks"], 2);
    assert_eq!(session["sha256"], sha_hex(&payload));
    assert_eq!(session["counts"][0]["table"], "orders");

    let mut joined = Vec::new();
    for (i, want_len) in [(0usize, CHUNK), (1, 1000)] {
        let res = n.h.get_raw(&n.t, &format!("{base}/chunks/{i}")).await;
        assert_eq!(res.status().as_u16(), 200);
        let claimed = res.headers()["x-chunk-sha256"]
            .to_str()
            .unwrap()
            .to_string();
        let bytes = res.bytes().await.unwrap();
        assert_eq!(bytes.len(), want_len);
        assert_eq!(
            claimed,
            sha_hex(&bytes),
            "the header is the hash of the bytes"
        );
        joined.extend_from_slice(&bytes);
    }
    assert_eq!(sha_hex(&joined), session["sha256"].as_str().unwrap());
    assert_eq!(joined, payload);
    let (status, _) = n.get(&format!("{base}/chunks/2")).await;
    assert_eq!(status, 404);

    let res = n.h.get_raw(&n.t, &format!("{base}/manifest")).await;
    assert_eq!(res.headers()["cache-control"], "no-store");
    let manifest: Value = res.json().await.unwrap();
    assert_eq!(manifest["database"], "pg:app");
    assert_eq!(manifest["sha256"], sha_hex(&payload));
    assert_eq!(manifest["chunks"], 2);
    assert_eq!(manifest["server_version"], "18.1");
    let users: Vec<&str> = manifest["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(users, ["app", "migrate"]);
    let (status, v) = n.get("/sites/shop/data/backups?database=pg:app").await;
    assert_eq!(status, 200);
    let record = v
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["trigger"] == "transfer")
        .expect("a transfer backup");
    assert_eq!(
        record["pinned"], true,
        "the dump is pinned while the session is open"
    );

    let (status, v) = n
        .post(&format!("{base}/finish"), json!({ "outcome": "cutover" }))
        .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["state"], "done");
    let (_, v) = n.get("/sites/shop/data/backups?database=pg:app").await;
    let record = v
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["trigger"] == "transfer")
        .unwrap();
    assert_eq!(record["pinned"], false);
    let actions = n.actions().await;
    for a in [
        "data.export.create",
        "data.export.manifest",
        "data.export.finish",
    ] {
        assert!(actions.contains(&a.to_string()), "{a} in {actions:?}");
    }
}

#[tokio::test]
async fn live_mode_and_bad_requests_to_exports_are_refused() {
    let n = node_with_postgres(patterned(100), COUNTS).await;
    let (status, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "mode": "live" }),
        )
        .await;
    assert_eq!(status, 501, "{v}");
    assert!(v["error"].as_str().unwrap().contains("not available"));
    for body in [
        json!({ "database": "pg:missing" }),
        json!({ "database": "ext:billing" }),
        json!({ "database": "app" }),
        json!({ "database": "pg:app", "extra": 1 }),
    ] {
        let (status, v) = n.post("/sites/shop/data/exports", body.clone()).await;
        assert!(status == 400 || status == 404, "{body}: {status} {v}");
    }
    let (status, _) = n.get("/sites/shop/data/exports/NOTASESSION").await;
    assert_eq!(status, 400);
    let (status, _) = n
        .get("/sites/shop/data/exports/01JC9ZQ7M3X8V4N2B6T5R0WHYA")
        .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn a_second_export_of_the_same_database_waits_for_the_first_to_be_finished() {
    let n = node_with_postgres(patterned(100), COUNTS).await;
    let (_, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "none" }),
        )
        .await;
    let sid = v["session"].as_str().unwrap().to_string();
    let base = format!("/sites/shop/data/exports/{sid}");
    n.wait_session(&base, &["ready"]).await;
    let (status, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "none" }),
        )
        .await;
    assert_eq!(status, 409, "{v}");
    // A session that is not resolved cannot be deleted either.
    let (status, _) = n.h.delete(&n.t, &base).await;
    assert_eq!(status, 409);
    let (status, _) = n
        .post(&format!("{base}/finish"), json!({ "outcome": "abort" }))
        .await;
    assert_eq!(status, 200);
    let (status, _) = n
        .post(&format!("{base}/finish"), json!({ "outcome": "abort" }))
        .await;
    assert_eq!(status, 409, "a finished session cannot be finished again");
    let (status, _) = n.h.delete(&n.t, &base).await;
    assert_eq!(status, 200);
    let (status, _) = n.get(&base).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn the_freeze_choice_is_applied_and_lifted_by_abort_but_kept_by_cutover() {
    // read-only: the database setting
    let n = node_with_postgres(patterned(100), COUNTS).await;
    let (_, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "read_only" }),
        )
        .await;
    let base = format!(
        "/sites/shop/data/exports/{}",
        v["session"].as_str().unwrap()
    );
    n.wait_session(&base, &["ready"]).await;
    let freeze = n.engine.jobs_of("freeze");
    assert_eq!(freeze.len(), 1);
    let tag = cite_edge::datamodel::pg_site_tag("shop");
    assert_eq!(
        freeze[0].env["CITE_LOGIN_ROLE"],
        format!("t{tag}_app_login")
    );
    assert_eq!(freeze[0].env["PGDATABASE"], "app");
    assert!(n.engine.jobs_of("unfreeze").is_empty());
    n.post(&format!("{base}/finish"), json!({ "outcome": "abort" }))
        .await;
    assert_eq!(n.engine.jobs_of("unfreeze").len(), 1);

    // maintenance: the site's flag, and its earlier value comes back on abort
    let (_, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "maintenance" }),
        )
        .await;
    let base = format!(
        "/sites/shop/data/exports/{}",
        v["session"].as_str().unwrap()
    );
    n.wait_session(&base, &["ready"]).await;
    assert!(n.h.state.store.config().sites[0].maintenance.enabled);
    n.post(&format!("{base}/finish"), json!({ "outcome": "abort" }))
        .await;
    assert!(!n.h.state.store.config().sites[0].maintenance.enabled);

    // cutover keeps the source frozen (A40): the database is never dropped by a transfer
    let (_, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "maintenance" }),
        )
        .await;
    let base = format!(
        "/sites/shop/data/exports/{}",
        v["session"].as_str().unwrap()
    );
    n.wait_session(&base, &["ready"]).await;
    let (status, v) = n
        .post(&format!("{base}/finish"), json!({ "outcome": "cutover" }))
        .await;
    assert_eq!(status, 200, "{v}");
    assert!(n.h.state.store.config().sites[0].maintenance.enabled);
    assert!(
        !n.engine
            .events()
            .iter()
            .any(|e| e.starts_with("remove_site_database")),
        "{:?}",
        n.engine.events()
    );
}

// ---- import ----

#[tokio::test]
async fn chunk_uploads_are_idempotent_and_a_different_hash_answers_409() {
    let payload = patterned(CHUNK + 5);
    let n = node_with_postgres(patterned(50), COUNTS).await;
    let sid = create_import(&n, &payload, &sha_hex(&payload)).await;
    let (c0, c1) = payload.split_at(CHUNK);

    let (status, body) = put_chunk(&n, &sid, 0, &sha_hex(c0), c0.to_vec()).await;
    assert_eq!(status, 204, "{body}");
    let (status, _) = put_chunk(&n, &sid, 0, &sha_hex(c0), c0.to_vec()).await;
    assert_eq!(status, 204, "sending a received chunk again is harmless");

    // The body does not match the hash it claims.
    let mut flipped = c0.to_vec();
    flipped[10] ^= 0xFF;
    let (status, _) = put_chunk(&n, &sid, 0, &sha_hex(c0), flipped.clone()).await;
    assert_eq!(status, 409);
    // A consistent chunk that differs from the one already stored.
    let (status, body) = put_chunk(&n, &sid, 0, &sha_hex(&flipped), flipped).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("different hash"), "{body}");

    // Other malformed uploads.
    let (status, _) = put_chunk(&n, &sid, 9, &sha_hex(c1), c1.to_vec()).await;
    assert_eq!(status, 400, "no such chunk");
    let (status, _) = put_chunk(&n, &sid, 1, &sha_hex(&c1[..4]), c1[..4].to_vec()).await;
    assert_eq!(status, 400, "wrong length");
    let (status, _) = put_chunk(&n, &sid, 1, "nothex", c1.to_vec()).await;
    assert_eq!(status, 400, "bad header");
    let res =
        n.h.http
            .put(n.h.url(&format!("/sites/shop/data/imports/{sid}/chunks/1")))
            .bearer_auth(&n.t)
            .body(c1.to_vec())
            .send()
            .await
            .unwrap();
    assert_eq!(res.status().as_u16(), 400, "the hash header is required");

    let (_, session) = n.get(&format!("/sites/shop/data/imports/{sid}")).await;
    assert_eq!(session["received"], json!([[0, 0]]));
    assert_eq!(session["state"], "receiving");

    // Not every chunk is there yet.
    let (status, v) = n
        .post(&format!("/sites/shop/data/imports/{sid}/commit"), json!({}))
        .await;
    assert_eq!(status, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("chunk 1"), "{v}");

    let (status, _) = put_chunk(&n, &sid, 1, &sha_hex(c1), c1.to_vec()).await;
    assert_eq!(status, 204);
    let (_, session) = n.get(&format!("/sites/shop/data/imports/{sid}")).await;
    assert_eq!(session["received"], json!([[0, 1]]));
}

#[tokio::test]
async fn a_commit_whose_dump_does_not_match_the_manifest_checksum_fails_before_any_restore() {
    let payload = patterned(CHUNK + 5);
    let n = node_with_postgres(patterned(50), COUNTS).await;
    let wrong = sha_hex(b"some other dump");
    let sid = create_import(&n, &payload, &wrong).await;
    upload_all(&n, &sid, &payload).await;
    let done = commit(&n, &sid).await;
    assert_eq!(done["state"], "failed", "{done}");
    let (_, session) = n.get(&format!("/sites/shop/data/imports/{sid}")).await;
    assert_eq!(session["state"], "failed");
    assert!(
        session["error"].as_str().unwrap().contains("checksum"),
        "{session}"
    );
    assert!(n.engine.jobs_of("restore").is_empty());
    assert!(n.engine.restored().is_empty());
    let (_, records) = n.get("/sites/shop/data/backups?database=pg:app").await;
    let import = records
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["trigger"] == "import")
        .expect("an import record");
    assert_eq!(import["status"], "failed");
    // The operator can still abort: nothing was created.
    let (status, v) = n
        .post(
            &format!("/sites/shop/data/imports/{sid}/finish"),
            json!({ "outcome": "abort" }),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["state"], "rolled_back");
}

#[tokio::test]
async fn an_import_restores_the_dump_compares_counts_and_waits_for_the_operator() {
    let payload = patterned(CHUNK + 5);
    let n = node_with_postgres(patterned(50), COUNTS).await;
    let sid = create_import(&n, &payload, &sha_hex(&payload)).await;
    upload_all(&n, &sid, &payload).await;
    let done = commit(&n, &sid).await;
    assert_eq!(done["state"], "ok", "{done}");
    let base = format!("/sites/shop/data/imports/{sid}");
    let (_, session) = n.get(&base).await;
    assert_eq!(session["state"], "awaiting_cutover", "{session}");
    assert_eq!(session["counts"], session["peer_counts"], "{session}");
    assert_eq!(session["counts"][0]["rows"], 3);
    assert!(
        session["pre_restore_backup"].is_string(),
        "replace takes a pre_restore backup"
    );
    assert!(session["backup_id"].is_string());
    assert_eq!(
        n.engine.restored().last().unwrap(),
        &payload,
        "the restore job saw exactly the transferred bytes"
    );
    let jobs = n.engine.jobs_of("restore");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].env["PGDATABASE"], "app");
    let imported = {
        let (_, records) = n.get("/sites/shop/data/backups?database=pg:app").await;
        records
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["trigger"] == "import")
            .cloned()
            .expect("an import record")
    };
    assert_eq!(imported["status"], "ok");
    assert_eq!(imported["sha256"], sha_hex(&payload));
    assert_eq!(imported["source"]["site"], "shop");

    let chunk_dir =
        n.h._dir
            .path()
            .join("backups/sites/shop/imports")
            .join(&sid);
    assert!(!chunk_dir.exists(), "the chunks go once they are assembled");

    let (status, v) = n
        .post(&format!("{base}/finish"), json!({ "outcome": "cutover" }))
        .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["state"], "done");
    let actions = n.actions().await;
    for a in [
        "data.import.create",
        "data.import.commit",
        "data.import.finish",
    ] {
        assert!(actions.contains(&a.to_string()), "{a} in {actions:?}");
    }
    let (status, _) = n.h.delete(&n.t, &base).await;
    assert_eq!(status, 200);
    assert!(
        n.actions()
            .await
            .contains(&"data.import.delete".to_string())
    );
}

#[tokio::test]
async fn aborting_an_import_that_replaced_a_database_puts_the_old_data_back() {
    let payload = patterned(300);
    let own_dump = patterned(77);
    let n = node_with_postgres(own_dump.clone(), COUNTS).await;
    let sid = create_import(&n, &payload, &sha_hex(&payload)).await;
    upload_all(&n, &sid, &payload).await;
    assert_eq!(commit(&n, &sid).await["state"], "ok");
    let (status, v) = n
        .post(
            &format!("/sites/shop/data/imports/{sid}/finish"),
            json!({ "outcome": "abort" }),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["state"], "rolled_back");
    let restored = n.engine.restored();
    assert_eq!(restored.len(), 2, "the import, then the pre_restore backup");
    assert_eq!(restored[0], payload);
    assert_eq!(restored[1], own_dump);
}

#[tokio::test]
async fn an_import_that_would_overwrite_a_database_needs_replace_and_bad_manifests_are_refused() {
    let payload = patterned(300);
    let n = node_with_postgres(patterned(50), COUNTS).await;
    let mut m = manifest_json(&payload, &sha_hex(&payload), COUNTS);
    let (status, v) = n
        .post("/sites/shop/data/imports", json!({ "manifest": m.clone() }))
        .await;
    assert_eq!(status, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("replace"));
    m["chunk_size"] = json!(1024);
    let (status, _) = n
        .post(
            "/sites/shop/data/imports",
            json!({ "manifest": m, "replace": true }),
        )
        .await;
    assert_eq!(status, 400);
    let mut m = manifest_json(&payload, &sha_hex(&payload), COUNTS);
    m["server_version"] = json!("19.0");
    let (status, v) = n
        .post(
            "/sites/shop/data/imports",
            json!({ "manifest": m, "replace": true }),
        )
        .await;
    assert_eq!(status, 409, "{v}");
    let (status, _) = n
        .post(
            "/sites/shop/data/imports",
            json!({ "manifest": manifest_json(&payload, &sha_hex(&payload), COUNTS), "extra": 1 }),
        )
        .await;
    assert_eq!(status, 400);
    // A site without managed Postgres cannot import.
    let bare = start_node(patterned(10), COUNTS).await;
    let (status, v) = bare
        .post(
            "/sites/shop/data/imports",
            json!({ "manifest": manifest_json(&payload, &sha_hex(&payload), COUNTS), "replace": true }),
        )
        .await;
    assert_eq!(status, 409, "{v}");
}

#[tokio::test]
async fn sessions_survive_a_restart_and_a_failed_step_can_be_retried() {
    let payload = patterned(120);
    let n = node_with_postgres(patterned(50), COUNTS).await;
    let sid = create_import(&n, &payload, &sha_hex(&payload)).await;
    upload_all(&n, &sid, &payload).await;
    let base = format!("/sites/shop/data/imports/{sid}");
    let svc = n.svc();

    // Waiting sessions are left as they are.
    svc.recover_transfers().await;
    let (_, session) = n.get(&base).await;
    assert_eq!(session["state"], "receiving");
    assert_eq!(session["received"], json!([[0, 0]]));

    // A step that was running when the connector stopped fails with a note.
    svc.mutate_session("shop", &sid, |s| {
        s.session.state = cite_edge::datawire::SessionState::Restoring;
        Ok(())
    })
    .await
    .unwrap();
    svc.recover_transfers().await;
    let (_, session) = n.get(&base).await;
    assert_eq!(session["state"], "failed");
    assert!(
        session["error"]
            .as_str()
            .unwrap()
            .contains("connector restart")
    );
    // Chunks were not lost with it: the commit carries on.
    assert_eq!(commit(&n, &sid).await["state"], "ok");
    let (_, session) = n.get(&base).await;
    assert_eq!(session["state"], "awaiting_cutover", "{session}");
    assert_eq!(n.engine.restored().last().unwrap(), &payload);

    // The same for an export that was dumping.
    let (_, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "none" }),
        )
        .await;
    let esid = v["session"].as_str().unwrap().to_string();
    let ebase = format!("/sites/shop/data/exports/{esid}");
    n.wait_session(&ebase, &["ready"]).await;
    svc.mutate_session("shop", &esid, |s| {
        s.session.state = cite_edge::datawire::SessionState::Dumping;
        Ok(())
    })
    .await
    .unwrap();
    svc.recover_transfers().await;
    let (_, session) = n.get(&ebase).await;
    assert_eq!(session["state"], "failed");
    let (status, _) = n.get(&format!("{ebase}/chunks/0")).await;
    assert_eq!(
        status, 409,
        "chunks are served only while the export is ready"
    );
    let (status, v) = n.post(&format!("{ebase}/retry"), json!({})).await;
    assert_eq!(status, 202, "{v}");
    n.wait_session(&ebase, &["ready"]).await;
    let (status, _) = n.get(&format!("{ebase}/chunks/0")).await;
    assert_eq!(status, 200);
}

// ---- conversion ----

fn link_pairs(view: &Value) -> Vec<(String, String)> {
    view["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["var"].as_str().unwrap().to_string(),
                l["target"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

async fn start_convert(n: &Node, to: &str, freeze: &str) -> String {
    let (status, v) = n
        .post(
            "/sites/shop/data/postgres/convert",
            json!({ "to": to, "freeze": freeze }),
        )
        .await;
    assert_eq!(status, 202, "{v}");
    v["session"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn converting_dedicated_to_shared_keeps_the_var_names_and_swaps_the_passwords_at_cutover() {
    let dump = patterned(4000);
    let n = node_with_postgres(dump.clone(), COUNTS).await;
    enable_shared_instance(&n).await;
    let (_, before) = n.get("/sites/shop/data").await;
    let old_app = n.secret("site-shop.data.pg.app.app").await.unwrap();
    let old_pw = old_app
        .password(cite_edge::datamodel::Alt::A)
        .unwrap()
        .to_string();

    // Shared needs to be running; a conversion to the mode a site already has is refused.
    let (status, v) = n
        .post(
            "/sites/shop/data/postgres/convert",
            json!({ "to": "dedicated", "freeze": "none" }),
        )
        .await;
    assert_eq!(status, 409, "{v}");

    let sid = start_convert(&n, "shared", "none").await;
    let base = format!("/sites/shop/data/postgres/convert/{sid}");
    let session = n.wait_session(&base, &["awaiting_cutover"]).await;
    assert_eq!(session["kind"], "convert");
    assert_eq!(session["database"], "pg:*");
    assert_eq!(session["counts"], session["peer_counts"]);
    assert!(session["error"].is_null(), "{session}");

    let tag = cite_edge::datamodel::pg_site_tag("shop");
    // Enabling the dedicated database made jobs too; the ones on the shared network belong to the conversion.
    let provision: Vec<Recorded> = n
        .engine
        .jobs_of("provision")
        .into_iter()
        .filter(|j| j.shared_net)
        .collect();
    assert_eq!(provision.len(), 1);
    assert_eq!(provision[0].env["PGDATABASE"], format!("t{tag}_app"));
    let created: Vec<Recorded> = n
        .engine
        .jobs_of("user")
        .into_iter()
        .filter(|j| j.shared_net && j.env["CITE_USER_ACTION"] == "create")
        .collect();
    assert_eq!(created.len(), 2);
    assert!(
        created
            .iter()
            .all(|j| j.env.contains_key("CITE_USER_PASSWORD"))
    );
    assert!(
        created
            .iter()
            .any(|j| j.env["CITE_USER_ROLE"] == format!("t{tag}_app_app_a"))
    );
    let new_pw = created
        .iter()
        .find(|j| j.env["CITE_USER_ROLE"] == format!("t{tag}_app_app_a"))
        .unwrap()
        .env["CITE_USER_PASSWORD"]
        .clone();
    assert_ne!(new_pw, old_pw, "the new server gets a new password");
    let backups = n.engine.jobs_of("backup");
    assert_eq!(backups.len(), 1);
    assert!(
        !backups[0].shared_net,
        "the dump is taken from the old server"
    );
    let restores = n.engine.jobs_of("restore");
    assert_eq!(restores.len(), 1);
    assert!(
        restores[0].shared_net,
        "the restore goes into the new server"
    );
    assert_eq!(n.engine.restored()[0], dump);
    let counts = n.engine.jobs_of("counts");
    assert_eq!(
        counts.iter().map(|j| j.shared_net).collect::<Vec<_>>(),
        [false, true]
    );

    // Until the cutover nothing the running site uses has changed.
    let live = n.secret("site-shop.data.pg.app.app").await.unwrap();
    assert_eq!(live.password(cite_edge::datamodel::Alt::A).unwrap(), old_pw);
    let (_, mid) = n.get("/sites/shop/data").await;
    assert_eq!(mid["postgres"]["mode"], "dedicated");
    assert!(n.secret("site-shop.data.pg-next.app.app").await.is_some());

    let (status, v) = n.post(&format!("{base}/cutover"), json!({})).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["state"], "done");
    let (_, after) = n.get("/sites/shop/data").await;
    assert_eq!(after["postgres"]["mode"], "shared");
    assert_eq!(after["postgres"]["retired"]["mode"], "dedicated");
    assert_eq!(
        link_pairs(&before),
        link_pairs(&after),
        "the env var names do not change"
    );
    let live = n.secret("site-shop.data.pg.app.app").await.unwrap();
    assert_eq!(live.password(cite_edge::datamodel::Alt::A).unwrap(), new_pw);
    let retired = n.secret("site-shop.data.pg-retired.app.app").await.unwrap();
    assert_eq!(
        retired.password(cite_edge::datamodel::Alt::A).unwrap(),
        old_pw
    );
    assert!(n.secret("site-shop.data.pg-next.app.app").await.is_none());
    let actions = n.actions().await;
    for a in ["data.convert.start", "data.convert.cutover"] {
        assert!(actions.contains(&a.to_string()), "{a} in {actions:?}");
    }

    // The old database stays until it is deleted, and a second conversion waits for that.
    let (status, v) = n
        .post(
            "/sites/shop/data/postgres/convert",
            json!({ "to": "dedicated", "freeze": "none" }),
        )
        .await;
    assert_eq!(status, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("retired"), "{v}");
    assert!(
        !n.engine
            .events()
            .iter()
            .any(|e| e.starts_with("remove_site_database")),
        "the conversion never drops the source"
    );
    n.run_ok(Method::DELETE, "/sites/shop/data/postgres/retired", None)
        .await;
    let events = n.engine.events();
    assert!(
        events.contains(&"remove_dedicated_database:shop:true".to_string()),
        "{events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| e.starts_with("remove_site_database") || e.starts_with("disconnect_shared")),
        "the site's network and the shared attachment are not touched: {events:?}"
    );
    let (_, done) = n.get("/sites/shop/data").await;
    assert!(done["postgres"]["retired"].is_null(), "{done}");
    assert!(
        n.secret("site-shop.data.pg-retired.app.app")
            .await
            .is_none()
    );
    let (status, _) = n.h.delete(&n.t, "/sites/shop/data/postgres/retired").await;
    assert_eq!(status, 409, "nothing is left to delete");
}

#[tokio::test]
async fn converting_shared_to_dedicated_can_be_aborted_and_then_completed() {
    let dump = patterned(2500);
    let n = start_node(dump.clone(), COUNTS).await;
    enable_shared_instance(&n).await;
    n.run_ok(
        Method::PUT,
        "/sites/shop/data/postgres",
        Some(json!({ "mode": "shared" })),
    )
    .await;
    let (_, before) = n.get("/sites/shop/data").await;

    // Abort: the new databases are removed and the site stays as it was.
    let sid = start_convert(&n, "dedicated", "none").await;
    let base = format!("/sites/shop/data/postgres/convert/{sid}");
    n.wait_session(&base, &["awaiting_cutover"]).await;
    assert!(n.secret("site-shop.data.pg-next.app.app").await.is_some());
    let restores = n.engine.jobs_of("restore");
    assert_eq!(restores.len(), 1);
    assert!(
        !restores[0].shared_net,
        "the restore goes into the new dedicated server"
    );
    let (status, v) = n.post(&format!("{base}/abort"), json!({})).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["state"], "rolled_back");
    assert!(n.secret("site-shop.data.pg-next.app.app").await.is_none());
    let events = n.engine.events();
    assert!(
        events.contains(&"remove_dedicated_database:shop:true".to_string()),
        "the new dedicated server is removed: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| e.starts_with("remove_site_database") || e.starts_with("disconnect_shared")),
        "the site's network and its link to the shared instance are untouched: {events:?}"
    );
    let (_, after) = n.get("/sites/shop/data").await;
    assert_eq!(after["postgres"]["mode"], "shared");
    assert!(after["postgres"]["retired"].is_null());
    assert_eq!(link_pairs(&before), link_pairs(&after));
    assert!(
        n.actions()
            .await
            .contains(&"data.convert.abort".to_string())
    );
    // An aborted conversion is resolved: the cutover of it is refused, a new one may start.
    let (status, _) = n.post(&format!("{base}/cutover"), json!({})).await;
    assert_eq!(status, 409);

    // Complete it this time.
    let sid = start_convert(&n, "dedicated", "none").await;
    let base = format!("/sites/shop/data/postgres/convert/{sid}");
    n.wait_session(&base, &["awaiting_cutover"]).await;
    let (status, v) = n.post(&format!("{base}/cutover"), json!({})).await;
    assert_eq!(status, 200, "{v}");
    let (_, done) = n.get("/sites/shop/data").await;
    assert_eq!(done["postgres"]["mode"], "dedicated");
    assert_eq!(done["postgres"]["retired"]["mode"], "shared");
    assert_eq!(link_pairs(&before), link_pairs(&done));
    // The retired shared databases go with a deprovision job.
    n.run_ok(Method::DELETE, "/sites/shop/data/postgres/retired", None)
        .await;
    let tag = cite_edge::datamodel::pg_site_tag("shop");
    let deprovision = n.engine.jobs_of("deprovision");
    assert_eq!(deprovision.len(), 1);
    assert_eq!(deprovision[0].env["PGDATABASE"], format!("t{tag}_app"));
    let (_, last) = n.get("/sites/shop/data").await;
    assert!(last["postgres"]["retired"].is_null());
}

#[tokio::test]
async fn a_conversion_whose_row_counts_differ_cannot_cut_over() {
    let n = node_with_postgres(patterned(900), COUNTS).await;
    enable_shared_instance(&n).await;
    {
        let mut queue = n.engine.counts_queue.lock().unwrap();
        queue.push_back("public\torders\t5\npublic\tusers\t2\n".to_string());
        queue.push_back("public\torders\t4\npublic\tusers\t2\n".to_string());
    }
    let sid = start_convert(&n, "shared", "none").await;
    let base = format!("/sites/shop/data/postgres/convert/{sid}");
    let session = n.wait_session(&base, &["awaiting_cutover"]).await;
    let error = session["error"]
        .as_str()
        .expect("the difference is reported");
    assert!(
        error.contains("app.public.orders") && error.contains("5") && error.contains("4"),
        "{error}"
    );
    assert_eq!(session["counts"][0]["schema"], "app.public");
    assert_eq!(session["counts"][0]["rows"], 5);
    assert_eq!(session["peer_counts"][0]["rows"], 4);
    let (status, v) = n.post(&format!("{base}/cutover"), json!({})).await;
    assert_eq!(status, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("differ"));
    let (_, view) = n.get("/sites/shop/data").await;
    assert_eq!(view["postgres"]["mode"], "dedicated");
    let (status, v) = n.post(&format!("{base}/abort"), json!({})).await;
    assert_eq!(status, 200, "{v}");
}

#[tokio::test]
async fn a_failed_conversion_keeps_the_source_frozen_until_it_is_aborted() {
    let n = node_with_postgres(patterned(900), COUNTS).await;
    enable_shared_instance(&n).await;
    n.engine.fail_ops.lock().unwrap().insert("restore");
    let sid = start_convert(&n, "shared", "read_only").await;
    let base = format!("/sites/shop/data/postgres/convert/{sid}");
    let session = n.wait_session(&base, &["failed"]).await;
    assert!(
        session["error"].as_str().unwrap().contains("restore"),
        "{session}"
    );
    assert_eq!(n.engine.jobs_of("freeze").len(), 1);
    assert!(
        n.engine.jobs_of("unfreeze").is_empty(),
        "the freeze stays after a failure"
    );
    let (status, _) = n.post(&format!("{base}/cutover"), json!({})).await;
    assert_eq!(status, 409);
    // A conversion that is not resolved blocks another one.
    let (status, _) = n
        .post(
            "/sites/shop/data/postgres/convert",
            json!({ "to": "shared", "freeze": "none" }),
        )
        .await;
    assert_eq!(status, 409);
    let (status, v) = n.post(&format!("{base}/abort"), json!({})).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        n.engine.jobs_of("unfreeze").len(),
        1,
        "abort lifts the freeze"
    );
    assert!(
        n.engine.jobs_of("deprovision").iter().all(|j| j.shared_net),
        "the half-made shared database is removed"
    );
    assert_eq!(n.engine.jobs_of("deprovision").len(), 1);
}

#[tokio::test]
async fn an_import_cannot_link_variables_to_users_or_secrets_the_target_already_had() {
    let payload = patterned(3000);
    let sha = sha_hex(&payload);
    let n = node_with_postgres(payload.clone(), COUNTS).await;
    let planted = |links: Value| {
        let mut m = manifest_json(&payload, &sha, COUNTS);
        m["links"] = links;
        json!({ "manifest": m, "replace": true })
    };
    // The target's own migrate user, exposed through a build variable the source chose.
    let (status, v) = n
        .post(
            "/sites/shop/data/imports",
            planted(json!([{ "var": "NEXT_PUBLIC_DB", "target": "build",
                "source": { "kind": "postgres", "database": "app", "user": "migrate", "field": "url" } }])),
        )
        .await;
    assert_eq!(status, 409, "{v}");
    let error = v["error"].as_str().unwrap();
    assert!(
        error.contains("NEXT_PUBLIC_DB (build)") && error.contains("app/migrate"),
        "{error}"
    );
    // The default links the target carries already are the same on both nodes, so a replace still works.
    let (status, v) = n
        .post(
            "/sites/shop/data/imports",
            planted(json!([{ "var": "DATABASE_URL", "target": "runtime",
                "source": { "kind": "postgres", "database": "app", "user": "app", "field": "url" } }])),
        )
        .await;
    assert_eq!(status, 201, "{v}");
    let sid = v["session"].as_str().unwrap().to_string();
    upload_all(&n, &sid, &payload).await;
    let done = commit(&n, &sid).await;
    assert_eq!(done["state"], "ok", "{done}");
    let (_, view) = n.get("/sites/shop/data").await;
    assert!(
        !view["links"].to_string().contains("NEXT_PUBLIC_DB"),
        "{view}"
    );
}

#[tokio::test]
async fn a_conversion_cutover_ends_a_maintenance_freeze_and_keeps_a_read_only_one_on_the_source() {
    let n = node_with_postgres(patterned(900), COUNTS).await;
    enable_shared_instance(&n).await;
    let sid = start_convert(&n, "shared", "maintenance").await;
    let base = format!("/sites/shop/data/postgres/convert/{sid}");
    n.wait_session(&base, &["awaiting_cutover"]).await;
    assert!(n.h.state.store.config().sites[0].maintenance.enabled);
    let (status, v) = n.post(&format!("{base}/cutover"), json!({})).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["state"], "done", "{v}");
    assert!(
        !n.h.state.store.config().sites[0].maintenance.enabled,
        "the site runs on the new server, so maintenance ends"
    );

    // Back to dedicated with a read-only freeze: the retired shared database stays frozen after the cutover.
    n.run_ok(Method::DELETE, "/sites/shop/data/postgres/retired", None)
        .await;
    let sid = start_convert(&n, "dedicated", "read_only").await;
    let base = format!("/sites/shop/data/postgres/convert/{sid}");
    n.wait_session(&base, &["awaiting_cutover"]).await;
    let (status, v) = n.post(&format!("{base}/cutover"), json!({})).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(n.engine.jobs_of("freeze").len(), 1);
    assert!(n.engine.jobs_of("unfreeze").is_empty());
}

// ---- the client driver against two connectors ----

fn plan(auto_cutover: bool, replace: bool) -> TransferPlan {
    TransferPlan {
        source_node: "a".into(),
        target_node: "b".into(),
        site: "shop".into(),
        database: "app".into(),
        freeze: Freeze::None,
        override_manual: false,
        replace,
        auto_cutover,
    }
}

#[tokio::test]
async fn the_driver_moves_a_database_between_two_connectors_and_resumes_after_an_interruption() {
    let payload = patterned(CHUNK + 1_000_000);
    let a = node_with_postgres(payload.clone(), "public\torders\t7\n").await;
    let b = node_with_postgres(patterned(64), "public\torders\t7\n").await;
    let (ca, cb) = (a.client("a"), b.client("b"));
    let store = MemoryTransferStore::new();
    let mut state = TransferState::new(plan(false, true)).unwrap();

    // The first run is stopped after the first chunk lands.
    let cancel = CancelFlag::new();
    let chunks_seen = Arc::new(AtomicUsize::new(0));
    let progress = {
        let (cancel, seen) = (cancel.clone(), Arc::clone(&chunks_seen));
        move |s: &TransferState| {
            seen.fetch_add(1, Ordering::SeqCst);
            if s.bytes_done >= TRANSFER_CHUNK_BYTES as u64 {
                cancel.cancel();
            }
        }
    };
    let env = TransferEnv {
        source: &ca,
        target: &cb,
        store: &store,
        cancel: cancel.clone(),
        progress: &progress,
        poll: Duration::from_millis(20),
    };
    let first = transfer::run(&env, &mut state).await;
    assert!(matches!(first, Err(TransferError::Cancelled)), "{first:?}");
    assert_eq!(state.phase, TransferPhase::Failed);
    assert!(state.error.as_deref().unwrap().contains("cancelled"));
    assert_eq!(store.load(&state.id).unwrap().phase, TransferPhase::Failed);
    let import_id = state.import_id.clone().expect("the import was created");
    let (_, session) = b
        .get(&format!("/sites/shop/data/imports/{import_id}"))
        .await;
    assert_eq!(session["state"], "receiving");
    assert!(
        !session["received"].as_array().unwrap().is_empty(),
        "{session}"
    );

    // The target restarts; its session and the chunks it holds are still there.
    b.svc().recover_transfers().await;

    // The second run reads what the connectors report and finishes the job.
    let again = CancelFlag::new();
    let quiet = |_: &TransferState| {};
    let env = TransferEnv {
        source: &ca,
        target: &cb,
        store: &store,
        cancel: again,
        progress: &quiet,
        poll: Duration::from_millis(20),
    };
    transfer::resume(&env, &mut state).await.expect("resume");
    assert_eq!(state.phase, TransferPhase::Verifying, "{state:?}");
    assert!(state.awaiting_operator());
    assert_eq!(state.counts_match, Some(true));
    assert!(state.mismatches.is_empty());
    assert_eq!(state.bytes_done, payload.len() as u64);
    assert_eq!(state.bytes_total, payload.len() as u64);
    assert_eq!(
        state.import_id.as_deref(),
        Some(import_id.as_str()),
        "the same import carried on"
    );
    assert_eq!(
        b.engine.restored().last().unwrap(),
        &payload,
        "the target restored exactly the source's dump"
    );

    transfer::cutover(&env, &mut state).await.expect("cutover");
    assert_eq!(state.phase, TransferPhase::Done);
    let (_, imp) = b
        .get(&format!("/sites/shop/data/imports/{import_id}"))
        .await;
    assert_eq!(imp["state"], "done");
    let (_, exp) = a
        .get(&format!(
            "/sites/shop/data/exports/{}",
            state.export_id.as_ref().unwrap()
        ))
        .await;
    assert_eq!(exp["state"], "done");
    assert!(
        !a.engine
            .events()
            .iter()
            .any(|e| e.starts_with("remove_site_database")),
        "the source database is never dropped by a transfer"
    );
    // Finished states stay finished.
    transfer::resume(&env, &mut state)
        .await
        .expect("a finished transfer is left alone");
    assert_eq!(state.phase, TransferPhase::Done);
    assert!(
        b.actions()
            .await
            .contains(&"data.import.finish".to_string())
    );
    assert!(
        a.actions()
            .await
            .contains(&"data.export.finish".to_string())
    );
}

#[tokio::test]
async fn the_driver_stops_on_different_row_counts_and_a_rollback_restores_both_sides() {
    let payload = patterned(5000);
    let a = node_with_postgres(payload.clone(), "public\torders\t7\n").await;
    let own = patterned(64);
    let b = node_with_postgres(own.clone(), "public\torders\t6\n").await;
    let (ca, cb) = (a.client("a"), b.client("b"));
    let store = MemoryTransferStore::new();
    let quiet = |_: &TransferState| {};
    let env = TransferEnv {
        source: &ca,
        target: &cb,
        store: &store,
        cancel: CancelFlag::new(),
        progress: &quiet,
        poll: Duration::from_millis(20),
    };
    let mut state = TransferState::new(plan(true, true)).unwrap();
    transfer::run(&env, &mut state).await.expect("run");
    assert_eq!(
        state.phase,
        TransferPhase::Verifying,
        "auto cutover must not fire on a mismatch"
    );
    assert_eq!(state.counts_match, Some(false));
    assert_eq!(state.mismatches.len(), 1);
    assert_eq!(state.mismatches[0].table, "orders");
    assert_eq!(state.mismatches[0].source, Some(7));
    assert_eq!(state.mismatches[0].target, Some(6));
    let refused = transfer::cutover(&env, &mut state).await;
    assert!(
        matches!(refused, Err(TransferError::Failed(_))),
        "{refused:?}"
    );
    assert_eq!(state.phase, TransferPhase::Verifying);

    transfer::rollback(&env, &mut state)
        .await
        .expect("rollback");
    assert_eq!(state.phase, TransferPhase::RolledBack);
    let (_, imp) = b
        .get(&format!(
            "/sites/shop/data/imports/{}",
            state.import_id.as_ref().unwrap()
        ))
        .await;
    assert_eq!(imp["state"], "rolled_back");
    let (_, exp) = a
        .get(&format!(
            "/sites/shop/data/exports/{}",
            state.export_id.as_ref().unwrap()
        ))
        .await;
    assert_eq!(exp["state"], "rolled_back");
    let restored = b.engine.restored();
    assert_eq!(
        restored.len(),
        2,
        "the transferred dump, then the target's own data again"
    );
    assert_eq!(restored[0], payload);
    assert_eq!(restored[1], own);
}

#[tokio::test]
async fn the_driver_cuts_over_by_itself_when_asked_and_the_counts_match() {
    let payload = patterned(4096);
    let a = node_with_postgres(payload.clone(), COUNTS).await;
    let b = node_with_postgres(patterned(10), COUNTS).await;
    let (ca, cb) = (a.client("a"), b.client("b"));
    let store = MemoryTransferStore::new();
    let quiet = |_: &TransferState| {};
    let env = TransferEnv {
        source: &ca,
        target: &cb,
        store: &store,
        cancel: CancelFlag::new(),
        progress: &quiet,
        poll: Duration::from_millis(20),
    };
    let mut state = TransferState::new(plan(true, true)).unwrap();
    transfer::run(&env, &mut state).await.expect("run");
    assert_eq!(state.phase, TransferPhase::Done);
    assert_eq!(store.load(&state.id).unwrap().phase, TransferPhase::Done);
    assert_eq!(b.engine.restored().last().unwrap(), &payload);
}

async fn disable_postgres(n: &Node) -> Value {
    let (status, v) = n.h.delete(&n.t, "/sites/shop/data/postgres").await;
    assert_eq!(status, 202, "{v}");
    n.wait_job(v["job_id"].as_str().expect("job")).await
}

#[tokio::test]
async fn postgres_stays_on_while_a_retired_database_or_an_open_session_exists() {
    let n = node_with_postgres(patterned(500), COUNTS).await;
    enable_shared_instance(&n).await;

    // An export that was not finished holds a freeze: turning Postgres off is refused.
    let (_, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "none" }),
        )
        .await;
    let ebase = format!(
        "/sites/shop/data/exports/{}",
        v["session"].as_str().unwrap()
    );
    n.wait_session(&ebase, &["ready"]).await;
    let job = disable_postgres(&n).await;
    assert_eq!(job["state"], "failed", "{job}");
    assert!(job["error"].as_str().unwrap().contains("export"), "{job}");
    n.post(&format!("{ebase}/finish"), json!({ "outcome": "abort" }))
        .await;

    // A conversion leaves the old database retired; it must be deleted on purpose first.
    let sid = start_convert(&n, "shared", "none").await;
    let cbase = format!("/sites/shop/data/postgres/convert/{sid}");
    n.wait_session(&cbase, &["awaiting_cutover"]).await;
    let job = disable_postgres(&n).await;
    assert_eq!(job["state"], "failed", "{job}");
    assert!(job["error"].as_str().unwrap().contains("convert"), "{job}");
    let (status, _) = n.post(&format!("{cbase}/cutover"), json!({})).await;
    assert_eq!(status, 200);
    let job = disable_postgres(&n).await;
    assert_eq!(job["state"], "failed", "{job}");
    assert!(job["error"].as_str().unwrap().contains("retired"), "{job}");
    let (_, view) = n.get("/sites/shop/data").await;
    assert_eq!(view["postgres"]["mode"], "shared", "nothing was removed");
    assert_eq!(view["postgres"]["retired"]["mode"], "dedicated");
    assert!(n.secret("site-shop.data.pg.app.app").await.is_some());

    n.run_ok(Method::DELETE, "/sites/shop/data/postgres/retired", None)
        .await;
    let job = disable_postgres(&n).await;
    assert_eq!(job["state"], "ok", "{job}");
    let (_, view) = n.get("/sites/shop/data").await;
    assert!(view["postgres"].is_null(), "{view}");
}

#[tokio::test]
async fn the_site_data_view_lists_the_open_conversion_and_transfers() {
    let n = node_with_postgres(patterned(500), COUNTS).await;
    enable_shared_instance(&n).await;
    let (_, idle) = n.get("/sites/shop/data").await;
    assert!(idle.get("conversion").is_none(), "{idle}");
    assert!(idle.get("transfers").is_none(), "{idle}");

    let (_, v) = n
        .post(
            "/sites/shop/data/exports",
            json!({ "database": "pg:app", "freeze": "none" }),
        )
        .await;
    let esid = v["session"].as_str().unwrap().to_string();
    let ebase = format!("/sites/shop/data/exports/{esid}");
    n.wait_session(&ebase, &["ready"]).await;
    let sid = start_convert(&n, "shared", "none").await;
    let cbase = format!("/sites/shop/data/postgres/convert/{sid}");
    n.wait_session(&cbase, &["awaiting_cutover"]).await;

    let (_, view) = n.get("/sites/shop/data").await;
    assert_eq!(view["conversion"]["id"], sid.as_str(), "{view}");
    assert_eq!(view["conversion"]["state"], "awaiting_cutover");
    assert_eq!(view["conversion"]["kind"], "convert");
    let transfers = view["transfers"].as_array().expect("transfers");
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0]["id"], esid.as_str());
    assert_eq!(transfers[0]["kind"], "export");
    assert_eq!(transfers[0]["state"], "ready");
    assert_eq!(transfers[0]["database"], "pg:app");

    // Once both are resolved the view is quiet again.
    n.post(&format!("{ebase}/finish"), json!({ "outcome": "abort" }))
        .await;
    n.post(&format!("{cbase}/abort"), json!({})).await;
    let (_, after) = n.get("/sites/shop/data").await;
    assert!(after.get("conversion").is_none(), "{after}");
    assert!(after.get("transfers").is_none(), "{after}");
}

#[tokio::test]
async fn an_import_larger_than_the_free_space_is_refused_with_507() {
    use crate::data::transfer::FREE_OVERRIDE;
    let n = node_with_postgres(patterned(50), COUNTS).await;
    let gib = 1u64 << 30;
    let sized = |bytes: u64| {
        let mut m = manifest_json(&patterned(10), &sha_hex(b"x"), COUNTS);
        m["size_bytes"] = json!(bytes);
        m["chunks"] = json!(bytes.div_ceil(CHUNK as u64));
        json!({ "manifest": m, "replace": true })
    };
    FREE_OVERRIDE.with(|c| c.set(Some(5 * gib)));
    // 4 GiB needs 2 x 4 GiB plus the margin; 5 GiB are free.
    let (status, v) = n.post("/sites/shop/data/imports", sized(4 * gib)).await;
    assert_eq!(status, 507, "{v}");
    assert!(v["error"].as_str().unwrap().contains("MiB are free"), "{v}");
    assert!(!v["error"].as_str().unwrap().contains("not enough space: "));
    let (status, v) = n.post("/sites/shop/data/imports", sized(gib)).await;
    assert_eq!(status, 201, "{v}");
    FREE_OVERRIDE.with(|c| c.set(None));
}
