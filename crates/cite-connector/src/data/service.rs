//! The data service: one object per node that owns managed and external databases, S3 attachments, generated
//! secrets, env links, backups and the shared instance. It talks to Docker only through [`DataEngine`], so the
//! flows here run against a fake in the tests.
//!
//! Locks, outermost first: the site lock (one operation per site at a time), the catalog lock (short
//! read-modify-write of one site's `catalog.json`), the config lock inside `Store::update_detailed`. Passwords
//! and secret values never leave this module except as job environment (to the Docker proxy), as env-link values
//! (to a deploy) and in redaction lists.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use cite_edge::datamodel::{
    Alt, BackupPolicy, DEFAULT_CONN_LIMIT, DEFAULT_PG_MAJOR, DEFAULT_PG_MAX_CONNECTIONS,
    DEFAULT_PG_MEMORY_MB, EnvLink, GeneratedSecret, LinkSource, LinkTarget, ManagedPostgres,
    PgDatabase, PgField, PgLevel, PgMode, PgUser, S3Attachment, S3Field, SHARED_DB, SecretEncoding,
    SiteData, db_container_name, db_volume_name, dbnet_name, external_secret_name,
    generated_secret_name, is_pg_ident, is_resource_name, pg_db_name, pg_login, pg_site_tag,
    pg_superuser_secret_name, pg_user_secret_name, s3_secret_name,
};
use cite_edge::datawire::{
    ConflictSetBy, DataNodeView, ExternalView, JobState, JobView, KeyView, LinkConflict, LinkView,
    LinksReq, OrphanView, PgDatabaseView, PgEnableReq, PgUserView, PgView, PresetRequest,
    PresetResponse, S3PutReq, S3View, SecretCreateReq, SecretView, ShadowedVar, SiteDataView,
};
use cite_edge::model::{Site, Slot};
use cite_edge::status::{BuildEnvPatch, CAPABILITIES, MAX_ENV_BYTES, MAX_ENV_KEYS};
use cite_edge::validate::{
    MAX_PG_DATABASES, PG_MAJORS, parse_s3_endpoint, runs_server, validate_backup_policy,
    validate_site_data,
};
use futures_util::future::BoxFuture;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::alerts::Alerts;
use crate::config::ConnectorConfig;
use crate::data::catalog::{self, BackupDirs, Catalog, CatalogError};
use crate::data::env::{self as denv, DataBindings, DbRoute, ExtCreds, PgCreds, S3Creds};
use crate::data::shared::SharedSettings;
use crate::data::users::UserSecret;
use crate::deploy::Deployer;
use crate::egress::EgressMode;
use crate::orchestrator::Orchestrator;
use crate::orchestrator::data::{DbHealth, JobOutcome, JobSpec};
use crate::seal::{KeySource, Keyring};
use crate::store::{Store, now_rfc3339};
use crate::{ConnectorError, Result};

pub const DB_PORT: u16 = 5432;
const MAX_JOBS_KEPT: usize = 200;
const JOB_PERMITS: usize = 2;
const UPLOAD_PERMITS: usize = 2;
/// Longest value an env var may hold; the Docker proxy enforces the same limit.
pub const ENV_VALUE_MAX: usize = 4096;
/// Marks a refusal that is the node's policy rather than a malformed request; the API answers it with 422.
pub const POLICY_PREFIX: &str = "node policy: ";

pub(crate) fn policy(msg: impl Into<String>) -> ConnectorError {
    ConnectorError::BadRequest(format!("{POLICY_PREFIX}{}", msg.into()))
}

pub(crate) fn lk<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub(crate) fn parse_time(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

pub(crate) fn join_err(e: tokio::task::JoinError) -> ConnectorError {
    ConnectorError::Internal(format!("data task failed: {e}"))
}

pub(crate) fn cat_err(e: CatalogError) -> ConnectorError {
    match e {
        CatalogError::Full(_) | CatalogError::Duplicate(_) => {
            ConnectorError::Conflict(e.to_string())
        }
        CatalogError::BadId(_) => ConnectorError::BadRequest(e.to_string()),
        other => ConnectorError::Internal(other.to_string()),
    }
}

/// What a client may read from an error: internal detail stays in the log.
pub(crate) fn public_error(e: &ConnectorError) -> String {
    match e {
        ConnectorError::Internal(detail) => {
            tracing::error!(%detail, "data operation failed");
            "internal error; see the connector log".to_string()
        }
        ConnectorError::BadRequest(m) => m.strip_prefix(POLICY_PREFIX).unwrap_or(m).to_string(),
        other => other.to_string(),
    }
}

// ---- configuration ----

#[derive(Debug, Clone)]
pub struct DataConfig {
    pub data_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub backup_volume: String,
    pub s3_allow_private: bool,
    pub job_timeout: Duration,
    pub node_name: String,
    /// The previous node key, when one is supplied or sits in the managed file: backups still sealed under it are
    /// re-wrapped, and S3 copies that need it are kept readable.
    pub previous_key: Option<String>,
}

impl DataConfig {
    /// None while the node has no backup directory: data services stay off.
    pub fn from_connector(cfg: &ConnectorConfig) -> Option<DataConfig> {
        let backup_dir = cfg.backup_dir.clone()?;
        let previous_key = match &cfg.secrets_key_previous {
            Some(k) => Some(k.expose().to_string()),
            None => std::fs::read_to_string(cfg.data_dir.join(crate::seal::MANAGED_PREVIOUS_FILE))
                .ok()
                .filter(|t| t.len() <= 1024),
        };
        Some(DataConfig {
            data_dir: cfg.data_dir.clone(),
            backup_dir,
            backup_volume: cfg.backup_volume.clone(),
            s3_allow_private: cfg.s3_allow_private,
            job_timeout: Duration::from_secs(cfg.data_job_timeout_secs),
            node_name: cfg.node_name.clone(),
            previous_key,
        })
    }
}

// ---- the Docker seam ----

type Fut<'a, T> = BoxFuture<'a, Result<T>>;

/// Database names with their sizes in bytes.
pub(crate) type SizesList = Vec<(String, u64)>;

/// Everything the data service asks of Docker. `Orchestrator` implements it over the D3 methods; the tests use a fake.
pub trait DataEngine: Send + Sync {
    fn ensure_site_database<'a>(&'a self, site: &'a Site, su_pw: &'a str) -> Fut<'a, ()>;
    fn ensure_shared_instance<'a>(&'a self, cfg: &'a SharedSettings, su_pw: &'a str)
    -> Fut<'a, ()>;
    /// Creates the shared instance's volumes and admin network (not its container) and returns the admin subnet,
    /// so the first `pg_hba.conf` can be written before the server starts.
    fn prepare_shared(&self) -> Fut<'_, String>;
    fn dbnet_subnet<'a>(&'a self, site_id: &'a str) -> Fut<'a, String>;
    fn connect_shared<'a>(&'a self, site_id: &'a str) -> Fut<'a, ()>;
    fn disconnect_shared<'a>(&'a self, site_id: &'a str) -> Fut<'a, ()>;
    /// Attaches a recreated shared instance to its tenants' networks again.
    fn reconnect_shared<'a>(&'a self, site_ids: &'a [String]) -> Fut<'a, ()>;
    /// True while a running manager or executor of the site still carries one of the strings in its env.
    fn env_mentions<'a>(&'a self, site_id: &'a str, needles: &'a [String]) -> Fut<'a, bool>;
    fn run_job<'a>(
        &'a self,
        job: &'a JobSpec,
        redact: &'a [String],
        timeout: Duration,
    ) -> Fut<'a, JobOutcome>;
    fn restart_database<'a>(&'a self, name: &'a str) -> Fut<'a, ()>;
    fn remove_site_database<'a>(&'a self, site_id: &'a str, purge: bool) -> Fut<'a, ()>;
    /// Removes only the dedicated container (and volume when purging); the site's network and the shared attachment stay.
    fn remove_dedicated_database<'a>(&'a self, site_id: &'a str, purge: bool) -> Fut<'a, ()>;
    fn remove_shared_instance<'a>(&'a self, purge: bool) -> Fut<'a, ()>;
    fn database_health<'a>(&'a self, name: &'a str) -> Fut<'a, DbHealth>;
    fn volume_size<'a>(&'a self, name: &'a str) -> Fut<'a, Option<u64>>;
    fn slot_running<'a>(&'a self, site_id: &'a str, slot: Slot) -> Fut<'a, bool>;
    fn egress_mode(&self) -> EgressMode;
    fn node_ports_allow(&self, port: u16) -> bool;
}

impl DataEngine for Orchestrator {
    fn ensure_site_database<'a>(&'a self, site: &'a Site, su_pw: &'a str) -> Fut<'a, ()> {
        Box::pin(Orchestrator::ensure_site_database(self, site, su_pw))
    }
    fn ensure_shared_instance<'a>(
        &'a self,
        cfg: &'a SharedSettings,
        su_pw: &'a str,
    ) -> Fut<'a, ()> {
        Box::pin(Orchestrator::ensure_shared_instance(self, cfg, su_pw))
    }
    fn prepare_shared(&self) -> Fut<'_, String> {
        Box::pin(Orchestrator::prepare_shared_instance(self))
    }
    fn dbnet_subnet<'a>(&'a self, site_id: &'a str) -> Fut<'a, String> {
        Box::pin(Orchestrator::dbnet_subnet(self, site_id))
    }
    fn connect_shared<'a>(&'a self, site_id: &'a str) -> Fut<'a, ()> {
        Box::pin(Orchestrator::connect_shared(self, site_id))
    }
    fn disconnect_shared<'a>(&'a self, site_id: &'a str) -> Fut<'a, ()> {
        Box::pin(Orchestrator::disconnect_shared(self, site_id))
    }
    fn reconnect_shared<'a>(&'a self, site_ids: &'a [String]) -> Fut<'a, ()> {
        Box::pin(Orchestrator::reconnect_shared(self, site_ids))
    }
    fn env_mentions<'a>(&'a self, site_id: &'a str, needles: &'a [String]) -> Fut<'a, bool> {
        Box::pin(Orchestrator::env_mentions(self, site_id, needles))
    }
    fn run_job<'a>(
        &'a self,
        job: &'a JobSpec,
        redact: &'a [String],
        timeout: Duration,
    ) -> Fut<'a, JobOutcome> {
        Box::pin(Orchestrator::run_job(self, job, redact, timeout))
    }
    fn restart_database<'a>(&'a self, name: &'a str) -> Fut<'a, ()> {
        Box::pin(Orchestrator::restart_database(self, name))
    }
    fn remove_site_database<'a>(&'a self, site_id: &'a str, purge: bool) -> Fut<'a, ()> {
        Box::pin(Orchestrator::remove_site_database(self, site_id, purge))
    }
    fn remove_dedicated_database<'a>(&'a self, site_id: &'a str, purge: bool) -> Fut<'a, ()> {
        Box::pin(Orchestrator::remove_dedicated_database(
            self, site_id, purge,
        ))
    }
    fn remove_shared_instance<'a>(&'a self, purge: bool) -> Fut<'a, ()> {
        Box::pin(Orchestrator::remove_shared_instance(self, purge))
    }
    fn database_health<'a>(&'a self, name: &'a str) -> Fut<'a, DbHealth> {
        Box::pin(Orchestrator::database_health(self, name))
    }
    fn volume_size<'a>(&'a self, name: &'a str) -> Fut<'a, Option<u64>> {
        Box::pin(Orchestrator::volume_size(self, name))
    }
    fn slot_running<'a>(&'a self, site_id: &'a str, slot: Slot) -> Fut<'a, bool> {
        Box::pin(async move {
            let seen = Orchestrator::inspect_slot(self, site_id, slot).await?;
            Ok(seen.state == "running")
        })
    }
    fn egress_mode(&self) -> EgressMode {
        self.egress().mode
    }
    fn node_ports_allow(&self, port: u16) -> bool {
        self.egress().node_ports_allow(port)
    }
}

// ---- stored secret shapes ----

#[derive(Serialize, Deserialize)]
pub(crate) struct PwSecret {
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExtSecret {
    pub url: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct S3Secret {
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct GenSecret {
    pub value: String,
    #[serde(default)]
    pub previous: Option<String>,
}

/// What the connector remembers about a site's data so a deleted site's leftovers can be found and purged.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SiteIndex {
    #[serde(default)]
    pub mode: Option<PgMode>,
    #[serde(default)]
    pub databases: BTreeSet<String>,
    #[serde(default)]
    pub secrets: BTreeSet<String>,
}

const INDEX_FILE: &str = "data-index.json";

// ---- jobs the API reports ----

#[derive(Default)]
struct JobTable {
    order: VecDeque<String>,
    map: HashMap<String, JobView>,
}

impl JobTable {
    fn insert(&mut self, view: JobView) {
        while self.order.len() >= MAX_JOBS_KEPT {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            self.map.remove(&old);
        }
        self.order.push_back(view.id.clone());
        self.map.insert(view.id.clone(), view);
    }
}

/// Handed to a running task so it can report its step.
pub(crate) struct JobCtx {
    pub svc: Arc<DataService>,
    pub id: String,
}

impl JobCtx {
    pub fn step(&self, text: &str) {
        let text = text.to_string();
        self.svc.job_update(&self.id, move |j| j.step = Some(text));
    }
}

// ---- the service ----

pub struct DataService {
    pub(crate) store: Arc<Store>,
    pub(crate) deployer: Arc<Deployer>,
    pub(crate) engine: Arc<dyn DataEngine>,
    pub(crate) alerts: Arc<Alerts>,
    pub(crate) cfg: DataConfig,
    pub(crate) keyring: Arc<Keyring>,
    pub(crate) dirs: BackupDirs,
    site_locks: StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    catalog_locks: StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    /// One lock per role tag around open, work and close of the database's job login, innermost of all.
    job_login_locks: StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    pub(crate) shared_lock: AsyncMutex<()>,
    pub(crate) targets_lock: AsyncMutex<()>,
    index_lock: AsyncMutex<()>,
    pub(crate) job_permits: Arc<Semaphore>,
    pub(crate) upload_permits: Arc<Semaphore>,
    jobs: StdMutex<JobTable>,
    /// One lock per `<site>/<session>` (and `<site>/*` for creating sessions) around the session files of `transfer`.
    pub(crate) transfer_locks: StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    /// Transfer chunks (8 MiB each) being read or received at once, node-wide.
    pub(crate) transfer_chunks: Arc<Semaphore>,
    /// `site/db-key` pairs a scheduled backup is already working on.
    pub(crate) inflight: StdMutex<HashSet<String>>,
    pub(crate) sizes_cache: StdMutex<Option<(Instant, SizesList)>>,
    /// The `pg_hba.conf` entries the shared instance last loaded, so `reconcile` rewrites the file only on a change.
    pub(crate) hba_applied: StdMutex<Option<Vec<String>>>,
    /// Held for the life of the process: a second connector on the same backup volume is refused.
    _flock: Option<std::fs::File>,
}

impl DataService {
    pub fn new(
        deployer: Arc<Deployer>,
        store: Arc<Store>,
        engine: Arc<dyn DataEngine>,
        alerts: Arc<Alerts>,
        cfg: DataConfig,
    ) -> Result<Arc<DataService>> {
        let keyring = store.require_keyring()?;
        let dirs = BackupDirs::new(cfg.backup_dir.clone());
        dirs.ensure_layout().map_err(cat_err)?;
        cite_core::atomic::ensure_dir(&cfg.data_dir.join("data"), 0o700).map_err(|e| {
            ConnectorError::Internal(format!("cannot create the data directory: {e}"))
        })?;
        let flock = {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(dirs.lock_path())
                .map_err(|e| {
                    ConnectorError::Internal(format!("cannot open the backup lock: {e}"))
                })?;
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| {
                    ConnectorError::Unavailable(
                        "another connector is using the backup volume".into(),
                    )
                })?;
            file
        };
        Ok(Arc::new(DataService {
            store,
            deployer,
            engine,
            alerts,
            cfg,
            keyring,
            dirs,
            site_locks: StdMutex::new(HashMap::new()),
            catalog_locks: StdMutex::new(HashMap::new()),
            job_login_locks: StdMutex::new(HashMap::new()),
            shared_lock: AsyncMutex::new(()),
            targets_lock: AsyncMutex::new(()),
            index_lock: AsyncMutex::new(()),
            job_permits: Arc::new(Semaphore::new(JOB_PERMITS)),
            upload_permits: Arc::new(Semaphore::new(UPLOAD_PERMITS)),
            jobs: StdMutex::new(JobTable::default()),
            transfer_locks: StdMutex::new(HashMap::new()),
            transfer_chunks: Arc::new(Semaphore::new(super::transfer::CHUNK_PERMITS)),
            inflight: StdMutex::new(HashSet::new()),
            sizes_cache: StdMutex::new(None),
            hba_applied: StdMutex::new(None),
            _flock: Some(flock),
        }))
    }

    pub(crate) fn site_lock(&self, id: &str) -> Arc<AsyncMutex<()>> {
        lk(&self.site_locks)
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    pub(crate) fn job_login_lock(&self, tag: &str) -> Arc<AsyncMutex<()>> {
        lk(&self.job_login_locks)
            .entry(tag.to_string())
            .or_default()
            .clone()
    }

    fn catalog_lock(&self, id: &str) -> Arc<AsyncMutex<()>> {
        lk(&self.catalog_locks)
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    pub(crate) fn site(&self, id: &str) -> Result<Site> {
        self.deployer.get_site(id)
    }

    /// Changes one site under the config lock; the result must still validate with the strict data rules.
    pub(crate) async fn update_site<T>(
        &self,
        actor: &str,
        action: &str,
        detail: &str,
        id: &str,
        f: impl FnOnce(&mut Site) -> Result<T>,
    ) -> Result<T> {
        let _gate = self.deployer.config_lock().lock().await;
        let id = id.to_string();
        self.store
            .update_detailed(actor, action, detail, move |cfg| {
                let site = cfg
                    .sites
                    .iter_mut()
                    .find(|s| s.id == id)
                    .ok_or_else(|| ConnectorError::NotFound(format!("site {id} not found")))?;
                let out = f(site)?;
                validate_site_data(site)?;
                Ok(out)
            })
            .await
    }

    // ---- secrets ----

    pub(crate) async fn secret_get<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        match self.store.get_secret(name).await {
            None => Ok(None),
            Some(text) => serde_json::from_str(&text).map(Some).map_err(|_| {
                ConnectorError::Internal(format!("the stored secret {name} is damaged"))
            }),
        }
    }

    /// Writes a secret and notes its name in the site's index (when it belongs to a site).
    pub(crate) async fn secret_put<T: Serialize>(
        &self,
        site: Option<&str>,
        name: &str,
        value: &T,
    ) -> Result<()> {
        let text = Zeroizing::new(serde_json::to_string(value)?);
        self.store.put_secret(name, &text).await?;
        if let Some(site) = site {
            let name = name.to_string();
            self.index_edit(site, move |i| {
                i.secrets.insert(name);
            })
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn secret_del(&self, site: Option<&str>, name: &str) {
        self.store.delete_secret(name).await;
        if let Some(site) = site {
            let name = name.to_string();
            if let Err(e) = self
                .index_edit(site, move |i| {
                    i.secrets.remove(&name);
                })
                .await
            {
                tracing::warn!(error = %e, "site data index could not be updated");
            }
        }
    }

    pub(crate) fn read_index(&self, site: &str) -> Result<SiteIndex> {
        let path = self.dirs.site_dir(site).map_err(cat_err)?.join(INDEX_FILE);
        match cite_core::atomic::read_limited(&path, 1 << 20) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
                ConnectorError::Internal(format!("the data index of {site} is damaged"))
            }),
            Err(_) if !path.exists() => Ok(SiteIndex::default()),
            Err(e) => Err(ConnectorError::Internal(format!(
                "cannot read the data index: {e}"
            ))),
        }
    }

    pub(crate) async fn index_edit(
        &self,
        site: &str,
        f: impl FnOnce(&mut SiteIndex),
    ) -> Result<()> {
        let _g = self.index_lock.lock().await;
        self.dirs.ensure_site(site).map_err(cat_err)?;
        let mut index = self.read_index(site)?;
        f(&mut index);
        let path = self.dirs.site_dir(site).map_err(cat_err)?.join(INDEX_FILE);
        let bytes = serde_json::to_vec(&index)?;
        cite_core::atomic::write_atomic(&path, &bytes, 0o600)
            .map_err(|e| ConnectorError::Internal(format!("cannot write the data index: {e}")))
    }

    // ---- catalog ----

    /// Read-modify-write of one site's catalog under its lock; nothing is written when `f` fails.
    pub(crate) async fn with_catalog<T: Send + 'static>(
        &self,
        site: &str,
        f: impl FnOnce(&mut Catalog) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let lock = self.catalog_lock(site);
        let _g = lock.lock().await;
        let dirs = self.dirs.clone();
        let site = site.to_string();
        tokio::task::spawn_blocking(move || {
            dirs.ensure_site(&site).map_err(cat_err)?;
            let path = dirs.catalog_path(&site).map_err(cat_err)?;
            let mut cat = catalog::load(&path).map_err(cat_err)?;
            let out = f(&mut cat)?;
            catalog::store(&path, &cat).map_err(cat_err)?;
            Ok(out)
        })
        .await
        .map_err(join_err)?
    }

    pub(crate) async fn read_catalog(&self, site: &str) -> Result<Catalog> {
        let lock = self.catalog_lock(site);
        let _g = lock.lock().await;
        let path = self.dirs.catalog_path(site).map_err(cat_err)?;
        tokio::task::spawn_blocking(move || catalog::load(&path).map_err(cat_err))
            .await
            .map_err(join_err)?
    }

    // ---- job table ----

    pub(crate) fn begin_job(&self, kind: &str, site: Option<&str>) -> String {
        let id = Ulid::generate().to_string();
        lk(&self.jobs).insert(JobView {
            id: id.clone(),
            kind: kind.to_string(),
            site: site.map(str::to_string),
            state: JobState::Running,
            step: None,
            error: None,
            result: None,
        });
        id
    }

    pub(crate) fn job_update(&self, id: &str, f: impl FnOnce(&mut JobView)) {
        if let Some(j) = lk(&self.jobs).map.get_mut(id) {
            f(j);
        }
    }

    pub fn job(&self, id: &str) -> Option<JobView> {
        lk(&self.jobs).map.get(id).cloned()
    }

    /// Runs `task` in the background; it finishes even when the caller goes away.
    pub(crate) fn spawn_task<F, Fut>(
        self: &Arc<Self>,
        kind: &str,
        site: Option<&str>,
        task: F,
    ) -> String
    where
        F: FnOnce(JobCtx) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        let id = self.begin_job(kind, site);
        let ctx = JobCtx {
            svc: Arc::clone(self),
            id: id.clone(),
        };
        let (svc, jid) = (Arc::clone(self), id.clone());
        tokio::spawn(async move {
            let outcome = task(ctx).await;
            match outcome {
                Ok(v) => svc.job_update(&jid, |j| {
                    j.state = JobState::Ok;
                    j.step = None;
                    j.result = (!v.is_null()).then_some(v);
                }),
                Err(e) => {
                    let msg = public_error(&e);
                    svc.job_update(&jid, |j| {
                        j.state = JobState::Failed;
                        j.step = None;
                        j.error = Some(msg);
                    });
                }
            }
        });
        id
    }

    /// 429 when both job slots are taken, so a manual request does not queue behind long backups.
    pub(crate) fn require_job_capacity(&self) -> Result<()> {
        if self.job_permits.available_permits() == 0 {
            return Err(ConnectorError::TooManyRequests(
                "two data jobs are already running; try again shortly".into(),
            ));
        }
        Ok(())
    }

    // ---- bindings for deploys ----

    /// The credentials and values the site's env links render. None for a site without data.
    pub async fn bindings(&self, site: &Site) -> Result<Option<DataBindings>> {
        if site.data.is_empty() {
            return Ok(None);
        }
        self.build_bindings(site, false).await.map(Some)
    }

    async fn build_bindings(&self, site: &Site, placeholder: bool) -> Result<DataBindings> {
        let data = &site.data;
        let id = &site.id;
        let mut b = DataBindings {
            links: data.links.clone(),
            site_url: site
                .hosts
                .first()
                .map(|h| format!("https://{h}"))
                .unwrap_or_default(),
            build_needs_dbnet: denv::build_needs_dbnet(data),
            ..DataBindings::default()
        };
        if let Some(pg) = &data.postgres {
            let host = match pg.mode {
                PgMode::Dedicated => db_container_name(id),
                PgMode::Shared => SHARED_DB.to_string(),
            };
            for db in &pg.databases {
                for u in &db.users {
                    let secret: Option<UserSecret> = self
                        .secret_get(&pg_user_secret_name(id, &db.name, &u.name))
                        .await?;
                    let (alt, password) = match secret {
                        Some(s) => {
                            let alt = s.active_alt()?;
                            let pw = s.password(alt).map(str::to_string);
                            match (pw, placeholder) {
                                (Some(pw), _) => (alt, pw),
                                (None, true) => (alt, "x".repeat(denv::PASSWORD_BYTES * 4 / 3 + 1)),
                                (None, false) => {
                                    return Err(ConnectorError::Unavailable(format!(
                                        "the credentials of {}/{} are missing",
                                        db.name, u.name
                                    )));
                                }
                            }
                        }
                        None if placeholder => (Alt::A, "x".repeat(43)),
                        None => {
                            return Err(ConnectorError::Unavailable(format!(
                                "the credentials of {}/{} are missing",
                                db.name, u.name
                            )));
                        }
                    };
                    b.pg.insert(
                        (db.name.clone(), u.name.clone()),
                        PgCreds {
                            host: host.clone(),
                            port: DB_PORT,
                            database: pg_db_name(pg.mode, id, &db.name),
                            user: pg_login(id, &db.name, &u.name, alt),
                            password: Zeroizing::new(password),
                            sslmode: "disable",
                        },
                    );
                }
            }
        }
        for e in &data.external_postgres {
            let secret: ExtSecret = self
                .secret_get(&external_secret_name(id, &e.name))
                .await?
                .ok_or_else(|| {
                    ConnectorError::Unavailable(format!(
                        "the URL of external database {} is missing",
                        e.name
                    ))
                })?;
            b.ext.insert(
                e.name.clone(),
                ExtCreds {
                    name: e.name.clone(),
                    url: Zeroizing::new(secret.url),
                    forward_port: denv::forward_port(data, &e.name).unwrap_or(0),
                },
            );
        }
        for s in &data.s3 {
            let secret: S3Secret = self
                .secret_get(&s3_secret_name(id, &s.name))
                .await?
                .ok_or_else(|| {
                    ConnectorError::Unavailable(format!(
                        "the keys of s3 attachment {} are missing",
                        s.name
                    ))
                })?;
            b.s3.insert(
                s.name.clone(),
                S3Creds {
                    att: s.clone(),
                    access_key_id: secret.access_key_id,
                    secret_access_key: Zeroizing::new(secret.secret_access_key),
                },
            );
        }
        for g in &data.secrets {
            let value = match self
                .secret_get::<GenSecret>(&generated_secret_name(id, &g.name))
                .await?
            {
                Some(s) => s.value,
                None if placeholder => "x".repeat(encoded_len(g.bytes, g.encoding)),
                None => {
                    return Err(ConnectorError::Unavailable(format!(
                        "the value of generated secret {} is missing",
                        g.name
                    )));
                }
            };
            b.secrets.insert(g.name.clone(), Zeroizing::new(value));
        }
        Ok(b)
    }

    /// Every value a log line of this site could leak from its data: passwords of both alternates, generated
    /// secrets, external URLs with their passwords, S3 secret keys.
    pub async fn redactions(&self, site: &Site) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let id = &site.id;
        if let Some(pg) = &site.data.postgres {
            if pg.mode == PgMode::Dedicated
                && let Ok(Some(pw)) = self
                    .secret_get::<PwSecret>(&pg_superuser_secret_name(id))
                    .await
            {
                out.push(pw.password);
            }
            for db in &pg.databases {
                for u in &db.users {
                    if let Ok(Some(s)) = self
                        .secret_get::<UserSecret>(&pg_user_secret_name(id, &db.name, &u.name))
                        .await
                    {
                        out.extend(s.passwords().into_iter().map(str::to_string));
                    }
                }
            }
        }
        for e in &site.data.external_postgres {
            if let Ok(Some(s)) = self
                .secret_get::<ExtSecret>(&external_secret_name(id, &e.name))
                .await
            {
                if let Ok(url) = denv::parse_postgres_url(&s.url) {
                    out.push(url.password.to_string());
                }
                out.push(s.url);
            }
        }
        for s in &site.data.s3 {
            if let Ok(Some(k)) = self
                .secret_get::<S3Secret>(&s3_secret_name(id, &s.name))
                .await
            {
                out.push(k.secret_access_key);
            }
        }
        for g in &site.data.secrets {
            if let Ok(Some(s)) = self
                .secret_get::<GenSecret>(&generated_secret_name(id, &g.name))
                .await
            {
                out.push(s.value);
                out.extend(s.previous);
            }
        }
        out.retain(|s| !s.is_empty());
        // A URL carries a password percent-encoded (an external one rewritten for the egress forward, say), which
        // the plain form does not match.
        let encoded: Vec<String> = out
            .iter()
            .map(|s| denv::percent_encode(s.as_bytes()))
            .filter(|e| !out.contains(e))
            .collect();
        out.extend(encoded);
        // The exact values the site's env receives, on every route a deploy may render them for. Only the ones that
        // carry one of the values above: a host name or a port is no secret, and redacting it would garble the logs.
        if let Ok(b) = self.build_bindings(site, false).await {
            let mut routes = vec![denv::DbRoute::Direct];
            for slot in ["blue", "green"] {
                routes.push(denv::DbRoute::ViaEgressProxy {
                    proxy_host: format!("cite-{id}-{slot}-egress-proxy"),
                });
            }
            let mut rendered: Vec<String> = Vec::new();
            for target in [LinkTarget::Runtime, LinkTarget::Build] {
                for route in &routes {
                    if let Ok(values) = denv::render(&b, target, route) {
                        rendered.extend(
                            values
                                .into_values()
                                .filter(|v| out.iter().any(|s| v.contains(s.as_str()))),
                        );
                    }
                }
            }
            out.extend(rendered);
        }
        out.sort();
        out.dedup();
        out
    }

    /// Names of the Docker objects the site's data owns, so garbage collection leaves them alone.
    pub async fn owned(&self, site: &Site) -> Vec<String> {
        let mut owned = match site.data.postgres.as_ref().map(|p| p.mode) {
            Some(PgMode::Dedicated) => vec![
                db_container_name(&site.id),
                db_volume_name(&site.id),
                dbnet_name(&site.id),
            ],
            Some(PgMode::Shared) => vec![dbnet_name(&site.id)],
            None => Vec::new(),
        };
        // A dedicated database left behind by a conversion to the shared instance stays until it is deleted explicitly.
        let retired_dedicated = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.retired.as_ref())
            .is_some_and(|r| r.mode == PgMode::Dedicated);
        if retired_dedicated {
            for name in [db_container_name(&site.id), db_volume_name(&site.id)] {
                if !owned.contains(&name) {
                    owned.push(name);
                }
            }
        }
        owned
    }

    /// Brings the shared instance's `pg_hba.conf` in line with the current subnets of the admin network and of every
    /// tenant network: entries of a recreated network move to its new subnet, entries of networks or databases that
    /// are gone disappear. Runs at startup and whenever the orchestrator creates a database network or recreates the
    /// instance; the file is rewritten only when the entries differ from what the instance last loaded.
    pub async fn reconcile(&self) {
        let Ok(settings) = self.shared_settings().await else {
            return;
        };
        if !settings.enabled {
            return;
        }
        let _g = self.shared_lock.lock().await;
        let entries = match self.hba_entries(None).await {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "the shared instance's networks could not be read");
                return;
            }
        };
        if lk(&self.hba_applied).as_ref() == Some(&entries) {
            return;
        }
        if let Err(e) = self.write_hba_entries(&settings, entries, true).await {
            tracing::warn!(error = %e, "the shared instance's hba file could not be refreshed");
        }
    }

    // ---- links ----

    fn route_for(&self, site_id: &str, target: LinkTarget) -> DbRoute {
        if target == LinkTarget::Runtime && self.engine.egress_mode() == EgressMode::Filtered {
            DbRoute::ViaEgressProxy {
                proxy_host: format!("cite-{site_id}-blue-egress-proxy"),
            }
        } else {
            DbRoute::Direct
        }
    }

    /// Validates new links against the site's current links, manual env vars and the proxy's env limits, the way a
    /// deploy would meet them, without changing anything.
    pub(crate) async fn plan_links(
        &self,
        site: &Site,
        wanted: Vec<EnvLink>,
        override_manual: bool,
    ) -> std::result::Result<LinkPlan, LinkError> {
        let manual_runtime: BTreeSet<String> = self
            .deployer
            .runtime_env_names(&site.id)
            .await
            .map(|n| n.names.into_iter().collect())
            .unwrap_or_default();
        let manual_build: BTreeSet<String> = self
            .deployer
            .build_env_names(&site.id)
            .await
            .map(|n| n.names.into_iter().collect())
            .unwrap_or_default();
        let mut conflicts = Vec::new();
        let mut add: Vec<EnvLink> = Vec::new();
        let mut unset: Vec<(LinkTarget, String)> = Vec::new();
        for l in wanted {
            if let Some(existing) = site
                .data
                .links
                .iter()
                .find(|e| e.var == l.var && e.target == l.target)
            {
                if existing.source != l.source {
                    conflicts.push(LinkConflict {
                        var: l.var.clone(),
                        target: l.target,
                        set_by: ConflictSetBy::Link,
                    });
                }
                continue;
            }
            if let Some(dup) = add.iter().find(|a| a.var == l.var && a.target == l.target) {
                if dup.source != l.source {
                    return Err(LinkError::Other(ConnectorError::BadRequest(format!(
                        "{} is linked twice for the {} target with different sources",
                        l.var,
                        l.target.as_str()
                    ))));
                }
                continue;
            }
            let manual = match l.target {
                LinkTarget::Runtime => &manual_runtime,
                LinkTarget::Build => &manual_build,
            };
            if manual.contains(&l.var) {
                if override_manual {
                    unset.push((l.target, l.var.clone()));
                } else {
                    conflicts.push(LinkConflict {
                        var: l.var.clone(),
                        target: l.target,
                        set_by: ConflictSetBy::Manual,
                    });
                    continue;
                }
            }
            add.push(l);
        }
        if !conflicts.is_empty() {
            return Err(LinkError::Conflicts(conflicts));
        }
        let mut candidate = site.clone();
        candidate.data.links.extend(add.clone());
        validate_site_data(&candidate).map_err(ConnectorError::from)?;
        let b = self.build_bindings(&candidate, true).await?;
        for target in [LinkTarget::Runtime, LinkTarget::Build] {
            let vars: Vec<String> = add
                .iter()
                .filter(|l| l.target == target)
                .map(|l| l.var.clone())
                .collect();
            if vars.is_empty() {
                continue;
            }
            let kind = match target {
                LinkTarget::Runtime => crate::siteops::EnvKind::Runtime,
                LinkTarget::Build => crate::siteops::EnvKind::Build,
            };
            let mut env = self
                .deployer
                .env_opt(&site.id, kind)
                .await?
                .unwrap_or_default();
            for (t, v) in &unset {
                if *t == target {
                    env.remove(v);
                }
            }
            let rendered = denv::render(&b, target, &self.route_for(&site.id, target))
                .map_err(ConnectorError::BadRequest)?;
            for (k, v) in &rendered {
                if v.len() > ENV_VALUE_MAX {
                    return Err(LinkError::Other(ConnectorError::BadRequest(format!(
                        "{k} would be {} characters; the limit is {ENV_VALUE_MAX}",
                        v.len()
                    ))));
                }
            }
            env.extend(rendered);
            check_env_size(&env, kind_label(target), &vars)?;
        }
        Ok(LinkPlan { add, unset })
    }

    /// Saves planned links; manual vars they replace are removed first and put back when the save fails.
    pub(crate) async fn apply_links(
        &self,
        actor: &str,
        site_id: &str,
        plan: LinkPlan,
        action: &str,
    ) -> Result<()> {
        let mut saved: Vec<(LinkTarget, String, String)> = Vec::new();
        for (target, var) in &plan.unset {
            let kind = match target {
                LinkTarget::Runtime => crate::siteops::EnvKind::Runtime,
                LinkTarget::Build => crate::siteops::EnvKind::Build,
            };
            if let Some(map) = self.deployer.env_opt(site_id, kind).await?
                && let Some(value) = map.get(var)
            {
                saved.push((*target, var.clone(), value.clone()));
            }
        }
        self.patch_manual(actor, site_id, &plan.unset, &[]).await?;
        let vars: Vec<String> = plan
            .add
            .iter()
            .map(|l| format!("{}:{}", l.target.as_str(), l.var))
            .collect();
        let add = plan.add;
        let result = self
            .update_site(
                actor,
                action,
                &format!("site={site_id} vars={}", vars.join(",")),
                site_id,
                move |site| {
                    site.data.links.extend(add);
                    Ok(())
                },
            )
            .await;
        if result.is_err() && !saved.is_empty() {
            let back: Vec<(LinkTarget, String, String)> = saved;
            if let Err(e) = self.patch_manual(actor, site_id, &[], &back).await {
                tracing::error!(error = %e, "manual env vars removed for a link could not be restored");
            }
        }
        result
    }

    async fn patch_manual(
        &self,
        actor: &str,
        site_id: &str,
        unset: &[(LinkTarget, String)],
        set: &[(LinkTarget, String, String)],
    ) -> Result<()> {
        for target in [LinkTarget::Runtime, LinkTarget::Build] {
            let patch = BuildEnvPatch {
                set: set
                    .iter()
                    .filter(|(t, _, _)| *t == target)
                    .map(|(_, k, v)| (k.clone(), v.clone()))
                    .collect(),
                unset: unset
                    .iter()
                    .filter(|(t, _)| *t == target)
                    .map(|(_, v)| v.clone())
                    .collect(),
            };
            if patch.set.is_empty() && patch.unset.is_empty() {
                continue;
            }
            match target {
                LinkTarget::Runtime => {
                    self.deployer
                        .patch_runtime_env(actor, site_id, patch)
                        .await?;
                }
                LinkTarget::Build => {
                    self.deployer.patch_build_env(actor, site_id, patch).await?;
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn create_links(
        &self,
        actor: &str,
        site_id: &str,
        req: LinksReq,
    ) -> std::result::Result<Vec<LinkView>, LinkError> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let wanted: Vec<EnvLink> = req.links.iter().flat_map(|l| l.expand()).collect();
        if wanted.is_empty() {
            return Err(LinkError::Other(ConnectorError::BadRequest(
                "give at least one link".into(),
            )));
        }
        let plan = self
            .plan_links(&site, wanted.clone(), req.override_manual)
            .await?;
        self.apply_links(actor, site_id, plan, "data.link.create")
            .await?;
        let site = self.site(site_id)?;
        Ok(self.link_views(&site).await)
    }

    pub(crate) async fn delete_link(
        &self,
        actor: &str,
        site_id: &str,
        target: LinkTarget,
        var: &str,
    ) -> Result<()> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let var = var.to_string();
        let detail = format!("site={site_id} var={var} target={}", target.as_str());
        self.update_site(actor, "data.link.delete", &detail, site_id, move |site| {
            let before = site.data.links.len();
            site.data
                .links
                .retain(|l| !(l.var == var && l.target == target));
            if site.data.links.len() == before {
                return Err(ConnectorError::NotFound(format!(
                    "no link {var} for {}",
                    target.as_str()
                )));
            }
            Ok(())
        })
        .await
    }

    async fn doppler_has(&self, site_id: &str, target: LinkTarget, var: &str) -> bool {
        let kind = match target {
            LinkTarget::Runtime => crate::siteops::EnvKind::Runtime,
            LinkTarget::Build => crate::siteops::EnvKind::Build,
        };
        match self
            .store
            .get_secret(&crate::doppler::snapshot_secret(site_id, kind))
            .await
        {
            Some(text) => serde_json::from_str::<BTreeMap<String, String>>(&text)
                .is_ok_and(|m| m.contains_key(var)),
            None => false,
        }
    }

    pub(crate) async fn link_views(&self, site: &Site) -> Vec<LinkView> {
        let mut out = Vec::new();
        for l in &site.data.links {
            out.push(LinkView {
                var: l.var.clone(),
                target: l.target,
                source: l.source.clone(),
                label: link_label(&l.source),
                shadows_doppler: self.doppler_has(&site.id, l.target, &l.var).await,
            });
        }
        out
    }

    // ---- presets ----

    pub(crate) async fn preset(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        req: PresetRequest,
    ) -> std::result::Result<(PresetResponse, bool), LinkError> {
        let site = self.site(site_id)?;
        let plan = denv::apply_preset(&site.data, &req).map_err(ConnectorError::BadRequest)?;
        let mut candidate = site.clone();
        apply_preset_to_site(&mut candidate, &plan);
        validate_site_data(&candidate).map_err(ConnectorError::from)?;
        // Dry run: conflicts and env limits surface before any job starts.
        let _ = self
            .plan_links(&candidate, plan.links.clone(), req.override_manual)
            .await?;
        let mut response = PresetResponse {
            links: Vec::new(),
            created_users: plan
                .users
                .iter()
                .map(|(d, u)| format!("{d}/{}", u.name))
                .collect(),
            created_secrets: plan.secrets.iter().map(|s| s.name.clone()).collect(),
            job_id: None,
        };
        let preview: Vec<LinkView> = plan
            .links
            .iter()
            .map(|l| LinkView {
                var: l.var.clone(),
                target: l.target,
                source: l.source.clone(),
                label: link_label(&l.source),
                shadows_doppler: false,
            })
            .collect();
        let needs_job = !plan.databases.is_empty() || !plan.users.is_empty();
        let (svc, actor, sid, override_manual) = (
            Arc::clone(self),
            actor.to_string(),
            site_id.to_string(),
            req.override_manual,
        );
        if needs_job {
            response.links = preview;
            let id = self.spawn_task("preset", Some(site_id), move |ctx| async move {
                svc.run_preset(&ctx, &actor, &sid, plan, override_manual)
                    .await
            });
            response.job_id = Some(id);
            return Ok((response, true));
        }
        svc.run_preset_sync(&actor, &sid, plan, override_manual)
            .await?;
        let fresh = self.site(site_id)?;
        response.links = self.link_views(&fresh).await;
        Ok((response, false))
    }

    async fn run_preset(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        plan: denv::PresetPlan,
        override_manual: bool,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        for db in &plan.databases {
            ctx.step(&format!("creating database {db}"));
            let users: Vec<PgUser> = plan
                .users
                .iter()
                .filter(|(d, _)| d == db)
                .map(|(_, u)| u.clone())
                .collect();
            self.provision_database(actor, site_id, db, &users).await?;
        }
        for (db, user) in plan
            .users
            .iter()
            .filter(|(d, _)| !plan.databases.contains(d))
        {
            ctx.step(&format!("creating user {db}/{}", user.name));
            self.add_user_locked(actor, site_id, db, user.clone())
                .await?;
        }
        ctx.step("saving links");
        self.save_preset_parts(actor, site_id, &plan, override_manual)
            .await?;
        Ok(json!({ "redeploy_needed": !plan.links.is_empty() }))
    }

    async fn run_preset_sync(
        &self,
        actor: &str,
        site_id: &str,
        plan: denv::PresetPlan,
        override_manual: bool,
    ) -> Result<()> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        self.save_preset_parts(actor, site_id, &plan, override_manual)
            .await
    }

    async fn save_preset_parts(
        &self,
        actor: &str,
        site_id: &str,
        plan: &denv::PresetPlan,
        override_manual: bool,
    ) -> Result<()> {
        for g in &plan.secrets {
            self.create_secret_locked(actor, site_id, g.name.clone(), g.bytes, g.encoding)
                .await?;
        }
        let site = self.site(site_id)?;
        match self
            .plan_links(&site, plan.links.clone(), override_manual)
            .await
        {
            Ok(link_plan) => {
                self.apply_links(actor, site_id, link_plan, "data.link.preset")
                    .await
            }
            Err(LinkError::Other(e)) => Err(e),
            Err(LinkError::Conflicts(c)) => Err(ConnectorError::Conflict(format!(
                "{} link(s) conflict with variables set by hand or other links",
                c.len()
            ))),
        }
    }

    // ---- generated secrets ----

    pub(crate) async fn create_secret(
        &self,
        actor: &str,
        site_id: &str,
        req: SecretCreateReq,
    ) -> Result<SecretView> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let bytes = req
            .bytes
            .unwrap_or(cite_edge::datamodel::DEFAULT_SECRET_BYTES);
        let encoding = req.encoding.unwrap_or_default();
        self.create_secret_locked(actor, site_id, req.name.clone(), bytes, encoding)
            .await?;
        let site = self.site(site_id)?;
        site.data
            .secrets
            .iter()
            .find(|s| s.name == req.name)
            .map(|s| secret_view(&site, s, false))
            .ok_or_else(|| ConnectorError::Internal("the secret vanished".into()))
    }

    async fn create_secret_locked(
        &self,
        actor: &str,
        site_id: &str,
        name: String,
        bytes: u16,
        encoding: SecretEncoding,
    ) -> Result<()> {
        if !is_resource_name(&name) {
            return Err(ConnectorError::BadRequest(
                "a secret name must match ^[a-z][a-z0-9-]{0,30}$".into(),
            ));
        }
        if !(32..=128).contains(&bytes) {
            return Err(ConnectorError::BadRequest("bytes must be 32 to 128".into()));
        }
        let site = self.site(site_id)?;
        if site.data.secrets.iter().any(|s| s.name == name) {
            return Err(ConnectorError::Conflict(format!(
                "secret {name} already exists"
            )));
        }
        let mut candidate = site.clone();
        candidate.data.secrets.push(GeneratedSecret {
            name: name.clone(),
            bytes,
            encoding,
            rotated_at: now_rfc3339(),
        });
        validate_site_data(&candidate)?;
        let value = denv::generate_secret(bytes, encoding).map_err(ConnectorError::Internal)?;
        let secret_name = generated_secret_name(site_id, &name);
        self.secret_put(
            Some(site_id),
            &secret_name,
            &GenSecret {
                value: value.to_string(),
                previous: None,
            },
        )
        .await?;
        let entry = candidate.data.secrets.pop();
        let detail = format!("site={site_id} secret={name}");
        let saved = self
            .update_site(actor, "data.secret.create", &detail, site_id, move |s| {
                s.data.secrets.extend(entry);
                Ok(())
            })
            .await;
        if saved.is_err() {
            self.secret_del(Some(site_id), &secret_name).await;
        }
        saved
    }

    pub(crate) async fn rotate_secret(
        &self,
        actor: &str,
        site_id: &str,
        name: &str,
    ) -> Result<SecretView> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let g = site
            .data
            .secrets
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ConnectorError::NotFound(format!("secret {name} not found")))?
            .clone();
        let secret_name = generated_secret_name(site_id, name);
        let old: GenSecret = self.secret_get(&secret_name).await?.ok_or_else(|| {
            ConnectorError::Unavailable(format!("the value of secret {name} is missing"))
        })?;
        let value = denv::generate_secret(g.bytes, g.encoding).map_err(ConnectorError::Internal)?;
        self.secret_put(
            Some(site_id),
            &secret_name,
            &GenSecret {
                value: value.to_string(),
                previous: Some(old.value.clone()),
            },
        )
        .await?;
        let (n, now) = (name.to_string(), now_rfc3339());
        let detail = format!("site={site_id} secret={name}");
        let saved = self
            .update_site(actor, "data.secret.rotate", &detail, site_id, move |s| {
                if let Some(e) = s.data.secrets.iter_mut().find(|e| e.name == n) {
                    e.rotated_at = now;
                }
                Ok(())
            })
            .await;
        if let Err(e) = saved {
            // Put the old value back so the stored value and the config agree.
            let _ = self
                .secret_put(
                    Some(site_id),
                    &secret_name,
                    &GenSecret {
                        value: old.value,
                        previous: old.previous,
                    },
                )
                .await;
            return Err(e);
        }
        let site = self.site(site_id)?;
        let g = site
            .data
            .secrets
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ConnectorError::Internal("the secret vanished".into()))?;
        Ok(secret_view(&site, g, true))
    }

    pub(crate) async fn delete_secret(&self, actor: &str, site_id: &str, name: &str) -> Result<()> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        if !site.data.secrets.iter().any(|s| s.name == name) {
            return Err(ConnectorError::NotFound(format!("secret {name} not found")));
        }
        let linked = links_to(
            &site.data,
            |s| matches!(s, LinkSource::Secret { name: n } if n == name),
        );
        if !linked.is_empty() {
            return Err(ConnectorError::Conflict(format!(
                "secret {name} is linked by {}; remove the links first",
                linked.join(", ")
            )));
        }
        let n = name.to_string();
        let detail = format!("site={site_id} secret={name}");
        self.update_site(actor, "data.secret.delete", &detail, site_id, move |s| {
            s.data.secrets.retain(|e| e.name != n);
            Ok(())
        })
        .await?;
        self.secret_del(Some(site_id), &generated_secret_name(site_id, name))
            .await;
        Ok(())
    }

    // ---- external Postgres and S3 attachments ----

    fn check_outbound_allowed(&self, site: &Site) -> Result<()> {
        if self.engine.egress_mode() == EgressMode::Off {
            return Err(policy(
                "outbound access is switched off on this node (CITE_STACK_EGRESS=off), so external services cannot be attached",
            ));
        }
        if !site.outbound {
            return Err(ConnectorError::BadRequest(
                "this site has outbound access switched off; enable it before attaching external services".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn put_external(
        &self,
        actor: &str,
        site_id: &str,
        name: &str,
        url: &str,
    ) -> Result<ExternalView> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        if !is_resource_name(name) {
            return Err(ConnectorError::BadRequest(
                "an attachment name must match ^[a-z][a-z0-9-]{0,30}$".into(),
            ));
        }
        self.check_outbound_allowed(&site)?;
        let parsed = denv::parse_postgres_url(url).map_err(ConnectorError::BadRequest)?;
        if !self.engine.node_ports_allow(parsed.port) {
            return Err(policy(format!(
                "the node's CITE_STACK_EGRESS_ALLOW_PORTS does not include {}",
                parsed.port
            )));
        }
        let entry = cite_edge::datamodel::ExternalPostgres {
            name: name.to_string(),
            host: parsed.host.clone(),
            port: parsed.port,
            database: parsed.database.clone(),
            sslmode: parsed.sslmode.clone(),
        };
        let mut candidate = site.clone();
        candidate.data.external_postgres.retain(|e| e.name != name);
        candidate.data.external_postgres.push(entry.clone());
        validate_site_data(&candidate)?;
        let secret_name = external_secret_name(site_id, name);
        let previous: Option<ExtSecret> = self.secret_get(&secret_name).await?;
        self.secret_put(
            Some(site_id),
            &secret_name,
            &ExtSecret {
                url: url.to_string(),
            },
        )
        .await?;
        let n = name.to_string();
        let detail = format!("site={site_id} external={name}");
        let saved = self
            .update_site(actor, "data.external.put", &detail, site_id, move |s| {
                s.data.external_postgres.retain(|e| e.name != n);
                s.data.external_postgres.push(entry);
                Ok(())
            })
            .await;
        if let Err(e) = saved {
            match previous {
                Some(p) => {
                    let _ = self.secret_put(Some(site_id), &secret_name, &p).await;
                }
                None => self.secret_del(Some(site_id), &secret_name).await,
            }
            return Err(e);
        }
        let site = self.site(site_id)?;
        Ok(self.external_view(&site, name))
    }

    fn external_view(&self, site: &Site, name: &str) -> ExternalView {
        let e = site.data.external_postgres.iter().find(|e| e.name == name);
        let filtered = self.engine.egress_mode() == EgressMode::Filtered;
        let mut warnings = Vec::new();
        if let Some(e) = e {
            if filtered && e.sslmode.as_deref() == Some("verify-full") {
                warnings.push(
                    "sslmode=verify-full fails host verification through the egress forward; link tls_servername for drivers that accept a server name"
                        .to_string(),
                );
            }
            if matches!(e.sslmode.as_deref(), Some("disable") | Some("allow")) {
                warnings.push("the connection to this database is not encrypted".to_string());
            }
        }
        ExternalView {
            name: name.to_string(),
            host: e.map(|e| e.host.clone()).unwrap_or_default(),
            port: e.map_or(0, |e| e.port),
            database: e.map(|e| e.database.clone()).unwrap_or_default(),
            sslmode: e.and_then(|e| e.sslmode.clone()),
            forward_port: if filtered {
                denv::forward_port(&site.data, name)
            } else {
                None
            },
            warnings,
        }
    }

    pub(crate) async fn delete_external(
        &self,
        actor: &str,
        site_id: &str,
        name: &str,
    ) -> Result<()> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        if !site.data.external_postgres.iter().any(|e| e.name == name) {
            return Err(ConnectorError::NotFound(format!(
                "external database {name} not found"
            )));
        }
        let linked = links_to(
            &site.data,
            |s| matches!(s, LinkSource::External { name: n, .. } if n == name),
        );
        if !linked.is_empty() {
            return Err(ConnectorError::Conflict(format!(
                "external database {name} is linked by {}; remove the links first",
                linked.join(", ")
            )));
        }
        let n = name.to_string();
        let detail = format!("site={site_id} external={name}");
        self.update_site(actor, "data.external.delete", &detail, site_id, move |s| {
            s.data.external_postgres.retain(|e| e.name != n);
            Ok(())
        })
        .await?;
        self.secret_del(Some(site_id), &external_secret_name(site_id, name))
            .await;
        Ok(())
    }

    pub(crate) async fn put_s3(
        &self,
        actor: &str,
        site_id: &str,
        name: &str,
        req: S3PutReq,
    ) -> Result<S3View> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        if !is_resource_name(name) {
            return Err(ConnectorError::BadRequest(
                "an attachment name must match ^[a-z][a-z0-9-]{0,30}$".into(),
            ));
        }
        self.check_outbound_allowed(&site)?;
        parse_s3_endpoint(&req.endpoint)
            .map_err(|e| ConnectorError::BadRequest(format!("endpoint: {e}")))?;
        let secret_name = s3_secret_name(site_id, name);
        let previous: Option<S3Secret> = self.secret_get(&secret_name).await?;
        let keys = match (&req.access_key_id, &req.secret_access_key, &previous) {
            (Some(id), Some(secret), _) => S3Secret {
                access_key_id: id.clone(),
                secret_access_key: secret.clone(),
            },
            (None, None, Some(p)) => S3Secret {
                access_key_id: p.access_key_id.clone(),
                secret_access_key: p.secret_access_key.clone(),
            },
            (Some(id), None, Some(p)) => S3Secret {
                access_key_id: id.clone(),
                secret_access_key: p.secret_access_key.clone(),
            },
            (None, Some(secret), Some(p)) => S3Secret {
                access_key_id: p.access_key_id.clone(),
                secret_access_key: secret.clone(),
            },
            _ => {
                return Err(ConnectorError::BadRequest(
                    "access_key_id and secret_access_key are required for a new attachment".into(),
                ));
            }
        };
        if keys.access_key_id.is_empty()
            || keys.secret_access_key.is_empty()
            || keys.access_key_id.len() > 256
            || keys.secret_access_key.len() > 512
            || !keys.access_key_id.bytes().all(|b| b.is_ascii_graphic())
            || !keys.secret_access_key.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(ConnectorError::BadRequest(
                "the S3 keys must be printable text without spaces".into(),
            ));
        }
        let entry = S3Attachment {
            name: name.to_string(),
            endpoint: req.endpoint.clone(),
            bucket: req.bucket.clone(),
            region: req.region.clone(),
            path_style: req.path_style,
        };
        let mut candidate = site.clone();
        candidate.data.s3.retain(|e| e.name != name);
        candidate.data.s3.push(entry.clone());
        validate_site_data(&candidate)?;
        self.secret_put(Some(site_id), &secret_name, &keys).await?;
        let n = name.to_string();
        let detail = format!("site={site_id} s3={name}");
        let saved = self
            .update_site(actor, "data.s3.put", &detail, site_id, move |s| {
                s.data.s3.retain(|e| e.name != n);
                s.data.s3.push(entry);
                Ok(())
            })
            .await;
        if let Err(e) = saved {
            match previous {
                Some(p) => {
                    let _ = self.secret_put(Some(site_id), &secret_name, &p).await;
                }
                None => self.secret_del(Some(site_id), &secret_name).await,
            }
            return Err(e);
        }
        let site = self.site(site_id)?;
        Ok(s3_view(&site, name))
    }

    pub(crate) async fn delete_s3(&self, actor: &str, site_id: &str, name: &str) -> Result<()> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        if !site.data.s3.iter().any(|e| e.name == name) {
            return Err(ConnectorError::NotFound(format!(
                "s3 attachment {name} not found"
            )));
        }
        let linked = links_to(
            &site.data,
            |s| matches!(s, LinkSource::S3 { name: n, .. } if n == name),
        );
        if !linked.is_empty() {
            return Err(ConnectorError::Conflict(format!(
                "s3 attachment {name} is linked by {}; remove the links first",
                linked.join(", ")
            )));
        }
        let n = name.to_string();
        let detail = format!("site={site_id} s3={name}");
        self.update_site(actor, "data.s3.delete", &detail, site_id, move |s| {
            s.data.s3.retain(|e| e.name != n);
            Ok(())
        })
        .await?;
        self.secret_del(Some(site_id), &s3_secret_name(site_id, name))
            .await;
        Ok(())
    }

    // ---- backup policy ----

    pub(crate) async fn put_policy(
        &self,
        actor: &str,
        site_id: &str,
        policy: BackupPolicy,
    ) -> Result<PgView> {
        let site = self.site(site_id)?;
        if site.data.postgres.is_none() {
            return Err(ConnectorError::BadRequest(
                "managed Postgres is not enabled for this site".into(),
            ));
        }
        validate_backup_policy("backup policy", &policy)?;
        if let Some(copy) = &policy.s3
            && self.target(&copy.target).await?.is_none()
        {
            return Err(ConnectorError::BadRequest(format!(
                "backup target {} does not exist",
                copy.target
            )));
        }
        let detail = format!("site={site_id}");
        self.update_site(actor, "data.policy.update", &detail, site_id, move |s| {
            if let Some(pg) = s.data.postgres.as_mut() {
                pg.backup = policy;
            }
            Ok(())
        })
        .await?;
        let site = self.site(site_id)?;
        Ok(self.pg_view(&site).await.unwrap_or_default())
    }

    // ---- views ----

    pub(crate) async fn pg_view(&self, site: &Site) -> Option<PgView> {
        let pg = site.data.postgres.as_ref()?;
        let health = {
            let name = match pg.mode {
                PgMode::Dedicated => db_container_name(&site.id),
                PgMode::Shared => SHARED_DB.to_string(),
            };
            self.engine.database_health(&name).await.ok().map(|h| {
                if h.health.is_empty() {
                    h.state
                } else {
                    format!("{} ({})", h.state, h.health)
                }
            })
        };
        let sizes = self.cached_sizes();
        let mut databases = Vec::new();
        for db in &pg.databases {
            let mut users = Vec::new();
            for u in &db.users {
                let secret: Option<UserSecret> = self
                    .secret_get(&pg_user_secret_name(&site.id, &db.name, &u.name))
                    .await
                    .ok()
                    .flatten();
                let linked_by = links_to(
                    &site.data,
                    |s| matches!(s, LinkSource::Postgres { database, user, .. } if *database == db.name && *user == u.name),
                );
                users.push(PgUserView {
                    name: u.name.clone(),
                    level: Some(u.level),
                    connection_limit: u.connection_limit,
                    statement_timeout_ms: u.effective_statement_timeout_ms(),
                    idle_in_transaction_timeout_ms: u.effective_idle_in_transaction_ms(),
                    disabled: u.disabled,
                    active: secret
                        .as_ref()
                        .map(|s| s.active.clone())
                        .unwrap_or_default(),
                    retiring: secret
                        .as_ref()
                        .and_then(|s| s.retiring.as_ref().map(|r| r.alt.clone())),
                    rotated_at: secret.and_then(|s| s.rotated_at),
                    linked_by,
                });
            }
            let wanted = pg_db_name(pg.mode, &site.id, &db.name);
            databases.push(PgDatabaseView {
                name: db.name.clone(),
                users,
                size_bytes: if pg.mode == PgMode::Shared {
                    sizes.iter().find(|(n, _)| *n == wanted).map(|(_, s)| *s)
                } else {
                    None
                },
            });
        }
        Some(PgView {
            mode: pg.mode,
            major: pg.major,
            memory_mb: pg.memory_mb,
            max_connections: pg.max_connections,
            databases,
            backup: pg.backup.clone(),
            health,
            retired: pg.retired.clone(),
        })
    }

    pub(crate) async fn site_view(&self, site: &Site) -> SiteDataView {
        let mut shadowed = Vec::new();
        for l in &site.data.links {
            if self.doppler_has(&site.id, l.target, &l.var).await {
                shadowed.push(ShadowedVar {
                    var: l.var.clone(),
                    target: Some(l.target),
                    by: "doppler".into(),
                });
            }
        }
        let redeploy_needed = !site.data.is_empty()
            && self
                .deployer
                .site_status(&site.id)
                .await
                .is_ok_and(|s| !s.settings_current);
        let (conversion, transfers) = self.open_sessions(&site.id).await;
        SiteDataView {
            conversion,
            transfers,
            postgres: self.pg_view(site).await,
            external: site
                .data
                .external_postgres
                .iter()
                .map(|e| self.external_view(site, &e.name))
                .collect(),
            s3: site
                .data
                .s3
                .iter()
                .map(|s| s3_view(site, &s.name))
                .collect(),
            secrets: site
                .data
                .secrets
                .iter()
                .map(|g| secret_view(site, g, false))
                .collect(),
            links: self.link_views(site).await,
            redeploy_needed,
            shadowed,
            capabilities: CAPABILITIES
                .iter()
                .filter(|c| c.starts_with("data-"))
                .map(|c| c.to_string())
                .collect(),
        }
    }

    pub(crate) async fn node_view(&self) -> DataNodeView {
        let shared = self.shared_view().await.ok().filter(|s| s.enabled);
        let sites: HashSet<String> = self.deployer.sites().into_iter().map(|s| s.id).collect();
        let orphans = self
            .dirs
            .sites()
            .iter()
            .filter(|s| !sites.contains(*s))
            .count();
        DataNodeView {
            enabled: true,
            backup_volume_ok: std::fs::metadata(self.dirs.root())
                .is_ok_and(|m| m.is_dir() && !m.permissions().readonly()),
            key: KeyView {
                kid: self.keyring.kid_hex(),
                source: match self.keyring.source() {
                    KeySource::Env => "env",
                    KeySource::File(_) => "file",
                    KeySource::Managed(_) => "managed",
                }
                .to_string(),
            },
            pg_majors: PG_MAJORS.to_vec(),
            shared,
            targets: self.list_targets().await.map_or(0, |t| t.len() as u32),
            orphans: orphans as u32,
        }
    }

    // ---- Postgres lifecycle ----

    pub(crate) fn check_enable(&self, site: &Site, req: &PgEnableReq) -> Result<()> {
        if !site.source.as_ref().is_some_and(runs_server) {
            return Err(ConnectorError::BadRequest(
                "managed Postgres needs a site built from a repository with a server runtime"
                    .into(),
            ));
        }
        if let Some(m) = req.major
            && !PG_MAJORS.contains(&m)
        {
            return Err(ConnectorError::BadRequest(format!(
                "major {m} must be one of {PG_MAJORS:?}"
            )));
        }
        if let Some(preset) = &req.preset
            && preset != "generic"
        {
            return Err(ConnectorError::BadRequest(
                "only the generic preset can be applied while enabling; use the links preset route for the others".into(),
            ));
        }
        if let Some(pg) = &site.data.postgres
            && pg.mode != req.mode
        {
            return Err(ConnectorError::Conflict(
                "the mode of an enabled database changes through the convert route".into(),
            ));
        }
        Ok(())
    }

    /// Enables managed Postgres for a site, or updates its resources when it is enabled.
    pub(crate) async fn do_enable_postgres(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        req: PgEnableReq,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        self.check_enable(&site, &req)?;
        if site.data.postgres.is_some() {
            return self.do_update_postgres(ctx, actor, &site, &req).await;
        }
        let mode = req.mode;
        let major = match mode {
            PgMode::Dedicated => req.major.unwrap_or(DEFAULT_PG_MAJOR),
            PgMode::Shared => {
                let shared = self.shared_settings().await?;
                if !shared.enabled {
                    return Err(ConnectorError::Conflict(
                        "the shared Postgres instance is not enabled on this node".into(),
                    ));
                }
                if req.major.is_some_and(|m| m != shared.major) {
                    return Err(ConnectorError::BadRequest(format!(
                        "the shared instance runs Postgres {}",
                        shared.major
                    )));
                }
                let tag = pg_site_tag(site_id);
                if self.deployer.sites().iter().any(|o| {
                    o.id != site_id
                        && o.data
                            .postgres
                            .as_ref()
                            .is_some_and(|p| p.mode == PgMode::Shared)
                        && pg_site_tag(&o.id) == tag
                }) {
                    return Err(ConnectorError::Conflict(
                        "another site on the shared instance has the same tag; pick another site id".into(),
                    ));
                }
                shared.major
            }
        };
        let mut pg = ManagedPostgres {
            mode,
            major,
            memory_mb: req.memory_mb.unwrap_or(DEFAULT_PG_MEMORY_MB),
            max_connections: req.max_connections.unwrap_or(DEFAULT_PG_MAX_CONNECTIONS),
            databases: vec![default_database()],
            backup: BackupPolicy::default(),
            tls: false,
            retired: None,
        };
        let mut candidate = site.clone();
        candidate.data.postgres = Some(pg.clone());
        validate_site_data(&candidate)?;
        ctx.step("preparing credentials");
        let su = self.ensure_su_secret(&site, mode).await?;
        for db in &pg.databases {
            for u in &db.users {
                self.ensure_user_secret(site_id, &db.name, &u.name).await?;
            }
        }
        ctx.step("starting the database");
        if mode == PgMode::Shared {
            self.require_shared_running().await?;
        }
        self.engine.ensure_site_database(&candidate, &su).await?;
        if mode == PgMode::Shared {
            ctx.step("updating the instance's access rules");
            let _sg = self.shared_lock.lock().await;
            self.write_hba(Some(&candidate), true).await?;
        }
        for db in &pg.databases {
            ctx.step(&format!("creating database {}", db.name));
            self.provision_db_job(&candidate, &db.name).await?;
            for u in &db.users {
                ctx.step(&format!("creating user {}/{}", db.name, u.name));
                self.ensure_login(&candidate, &db.name, u, Alt::A).await?;
            }
        }
        pg.databases.sort_by(|a, b| a.name.cmp(&b.name));
        let to_save = pg.clone();
        let detail = format!("site={site_id} mode={}", mode.as_str());
        self.update_site(actor, "data.postgres.enable", &detail, site_id, move |s| {
            s.data.postgres = Some(to_save);
            Ok(())
        })
        .await?;
        let names: Vec<String> = pg.databases.iter().map(|d| d.name.clone()).collect();
        self.index_edit(site_id, move |i| {
            i.mode = Some(mode);
            i.databases.extend(names);
        })
        .await?;
        ctx.step("linking environment variables");
        let (linked, skipped) = self
            .default_links(actor, site_id, req.preset.is_some())
            .await;
        Ok(json!({ "redeploy_needed": linked > 0, "links": linked, "skipped_links": skipped }))
    }

    async fn default_links(
        &self,
        actor: &str,
        site_id: &str,
        generic: bool,
    ) -> (usize, Vec<String>) {
        let pg_link = |var: &str, target: LinkTarget, user: &str, field: PgField| EnvLink {
            var: var.to_string(),
            target,
            source: LinkSource::Postgres {
                database: "app".into(),
                user: user.into(),
                field,
            },
        };
        let mut wanted = vec![
            pg_link("DATABASE_URL", LinkTarget::Runtime, "app", PgField::Url),
            pg_link(
                "MIGRATION_DATABASE_URL",
                LinkTarget::Build,
                "migrate",
                PgField::Url,
            ),
        ];
        if generic {
            for (var, field) in [
                ("PGHOST", PgField::Host),
                ("PGPORT", PgField::Port),
                ("PGDATABASE", PgField::Database),
                ("PGUSER", PgField::User),
                ("PGPASSWORD", PgField::Password),
                ("PGSSLMODE", PgField::Sslmode),
            ] {
                wanted.push(pg_link(var, LinkTarget::Runtime, "app", field));
            }
        }
        let mut linked = 0;
        let mut skipped = Vec::new();
        for link in wanted {
            let label = format!("{} ({})", link.var, link.target.as_str());
            let Ok(site) = self.site(site_id) else { break };
            match self.plan_links(&site, vec![link], false).await {
                Ok(plan) => {
                    if plan.add.is_empty() {
                        continue;
                    }
                    match self
                        .apply_links(actor, site_id, plan, "data.link.create")
                        .await
                    {
                        Ok(()) => linked += 1,
                        Err(e) => skipped.push(format!("{label}: {}", public_error(&e))),
                    }
                }
                Err(LinkError::Conflicts(_)) => skipped.push(format!("{label}: already set")),
                Err(LinkError::Other(e)) => skipped.push(format!("{label}: {}", public_error(&e))),
            }
        }
        (linked, skipped)
    }

    async fn do_update_postgres(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site: &Site,
        req: &PgEnableReq,
    ) -> Result<Value> {
        let pg =
            site.data.postgres.as_ref().ok_or_else(|| {
                ConnectorError::BadRequest("managed Postgres is not enabled".into())
            })?;
        if req.major.is_some_and(|m| m != pg.major) {
            return Err(ConnectorError::Conflict(
                "the Postgres major of a database is fixed; move the data to a new database to change it".into(),
            ));
        }
        let (memory, conns) = (
            req.memory_mb.unwrap_or(pg.memory_mb),
            req.max_connections.unwrap_or(pg.max_connections),
        );
        let mut candidate = site.clone();
        if pg.mode == PgMode::Dedicated
            && let Some(p) = candidate.data.postgres.as_mut()
        {
            p.memory_mb = memory;
            p.max_connections = conns;
        }
        validate_site_data(&candidate)?;
        if pg.mode == PgMode::Dedicated && (memory != pg.memory_mb || conns != pg.max_connections) {
            ctx.step("restarting the database with its new limits");
            let su = self.ensure_su_secret(site, pg.mode).await?;
            self.engine.ensure_site_database(&candidate, &su).await?;
            let id = site.id.clone();
            let detail = format!("site={id}");
            self.update_site(actor, "data.postgres.update", &detail, &id, move |s| {
                if let Some(p) = s.data.postgres.as_mut() {
                    p.memory_mb = memory;
                    p.max_connections = conns;
                }
                Ok(())
            })
            .await?;
        }
        Ok(json!({ "redeploy_needed": false }))
    }

    pub(crate) async fn ensure_su_secret(
        &self,
        site: &Site,
        mode: PgMode,
    ) -> Result<Zeroizing<String>> {
        match mode {
            PgMode::Shared => self.shared_password().await,
            PgMode::Dedicated => {
                let name = pg_superuser_secret_name(&site.id);
                if let Some(s) = self.secret_get::<PwSecret>(&name).await? {
                    return Ok(Zeroizing::new(s.password));
                }
                let pw = denv::generate_password().map_err(ConnectorError::Internal)?;
                self.secret_put(
                    Some(&site.id),
                    &name,
                    &PwSecret {
                        password: pw.to_string(),
                    },
                )
                .await?;
                Ok(pw)
            }
        }
    }

    /// Creates the user's credentials when none exist (a re-enabled site adopts the earlier ones).
    pub(crate) async fn ensure_user_secret(
        &self,
        site_id: &str,
        db: &str,
        user: &str,
    ) -> Result<()> {
        let name = pg_user_secret_name(site_id, db, user);
        if self.secret_get::<UserSecret>(&name).await?.is_some() {
            return Ok(());
        }
        let pw = denv::generate_password().map_err(ConnectorError::Internal)?;
        self.secret_put(
            Some(site_id),
            &name,
            &UserSecret::fresh(pw.to_string(), &now_rfc3339()),
        )
        .await
    }

    /// Turns managed Postgres off. Without `purge` the data stays: a dedicated container is removed but its volume,
    /// credentials and backups remain; shared logins are disabled but the databases remain.
    pub(crate) async fn do_disable_postgres(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        purge: bool,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let pg = site.data.postgres.clone().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        self.ensure_no_open_transfer(&site).await?;
        match pg.mode {
            PgMode::Dedicated => {
                ctx.step("removing the database");
                self.engine.remove_site_database(site_id, purge).await?;
            }
            PgMode::Shared => {
                for db in &pg.databases {
                    if purge {
                        ctx.step(&format!("dropping database {}", db.name));
                        self.deprovision_db_job(&site, &db.name).await?;
                    } else {
                        for u in &db.users {
                            ctx.step(&format!("disabling {}/{}", db.name, u.name));
                            self.set_login_state(&site, &db.name, u, "disable").await?;
                        }
                    }
                }
                self.engine.disconnect_shared(site_id).await?;
                let mut gone = site.clone();
                gone.data.postgres = None;
                let _sg = self.shared_lock.lock().await;
                self.write_hba(Some(&gone), true).await?;
            }
        }
        let mut removed_backups = 0u32;
        let mut s3_left = 0u32;
        if purge {
            for db in &pg.databases {
                for u in &db.users {
                    self.secret_del(
                        Some(site_id),
                        &pg_user_secret_name(site_id, &db.name, &u.name),
                    )
                    .await;
                }
            }
            self.secret_del(Some(site_id), &pg_superuser_secret_name(site_id))
                .await;
            let (r, l) = self.purge_pg_backups(site_id).await?;
            removed_backups = r;
            s3_left = l;
        }
        let detail = format!("site={site_id} purge={purge}");
        let action = if purge {
            "data.postgres.purge"
        } else {
            "data.postgres.disable"
        };
        let vars = self
            .update_site(actor, action, &detail, site_id, move |s| {
                s.data.postgres = None;
                let before: Vec<String> = s.data.links.iter().map(|l| l.var.clone()).collect();
                s.data
                    .links
                    .retain(|l| !matches!(l.source, LinkSource::Postgres { .. }));
                Ok(before.len() - s.data.links.len())
            })
            .await?;
        Ok(json!({
            "redeploy_needed": vars > 0,
            "links_removed": vars,
            "backups_removed": removed_backups,
            "s3_objects_left": s3_left,
        }))
    }

    // ---- orphans and purge ----

    pub(crate) async fn orphans(&self) -> Result<Vec<OrphanView>> {
        let live: HashSet<String> = self.deployer.sites().into_iter().map(|s| s.id).collect();
        let mut out = Vec::new();
        for id in self.dirs.sites() {
            if live.contains(&id) {
                continue;
            }
            let index = self.read_index(&id).unwrap_or_default();
            let backups = self
                .read_catalog(&id)
                .await
                .map(|c| c.databases.values().map(|d| d.backups.len() as u32).sum())
                .unwrap_or(0);
            out.push(OrphanView {
                site: id.clone(),
                dedicated_volume: (index.mode == Some(PgMode::Dedicated))
                    .then(|| db_volume_name(&id)),
                shared_databases: if index.mode == Some(PgMode::Shared) {
                    index
                        .databases
                        .iter()
                        .map(|d| pg_db_name(PgMode::Shared, &id, d))
                        .collect()
                } else {
                    Vec::new()
                },
                backups,
                secrets: index.secrets.len() as u32,
            });
        }
        Ok(out)
    }

    /// Removes everything a deleted site left: its database, credentials, backups and index. S3 copies stay;
    /// their count is returned.
    pub(crate) async fn purge_orphan(&self, id: &str) -> Result<Value> {
        if self.deployer.sites().iter().any(|s| s.id == id) {
            return Err(ConnectorError::Conflict(format!(
                "site {id} still exists; delete it with purge_data instead"
            )));
        }
        let lock = self.site_lock(id);
        let _g = lock.lock().await;
        let index = self.read_index(id)?;
        match index.mode {
            Some(PgMode::Dedicated) => self.engine.remove_site_database(id, true).await?,
            Some(PgMode::Shared) => {
                let shared = self.shared_settings().await?;
                if shared.enabled {
                    let su = self.shared_password().await?;
                    for db in &index.databases {
                        let spec = self.shared_site_job_for(id, shared.major, &su, db).await?;
                        self.run_ok("deprovision", spec, std::slice::from_ref(&*su))
                            .await?;
                    }
                    let _ = self.engine.disconnect_shared(id).await;
                    let _sg = self.shared_lock.lock().await;
                    self.write_hba(None, true).await?;
                }
            }
            None => {}
        }
        let s3_left = self.s3_copy_count(id).await.unwrap_or(0);
        for name in &index.secrets {
            self.store.delete_secret(name).await;
        }
        let dirs = self.dirs.clone();
        let sid = id.to_string();
        tokio::task::spawn_blocking(move || {
            for dir in [dirs.site_dir(&sid), dirs.staging_dir(&sid)]
                .into_iter()
                .flatten()
            {
                if dir.is_dir() {
                    std::fs::remove_dir_all(&dir).map_err(|e| {
                        ConnectorError::Internal(format!("cannot remove {}: {e}", dir.display()))
                    })?;
                }
            }
            Ok::<(), ConnectorError>(())
        })
        .await
        .map_err(join_err)??;
        Ok(json!({ "s3_objects_left": s3_left }))
    }

    /// Deletes a site's data for a purge delete: database, credentials, backups. Called with the site still in config.
    pub async fn purge_site(&self, site: &Site) -> Result<u32> {
        let id = site.id.as_str();
        let lock = self.site_lock(id);
        let _g = lock.lock().await;
        if let Some(pg) = &site.data.postgres {
            match pg.mode {
                PgMode::Dedicated => self.engine.remove_site_database(id, true).await?,
                PgMode::Shared => {
                    for db in &pg.databases {
                        self.deprovision_db_job(site, &db.name).await?;
                    }
                    let _ = self.engine.disconnect_shared(id).await;
                    let mut gone = site.clone();
                    gone.data.postgres = None;
                    let _sg = self.shared_lock.lock().await;
                    self.write_hba(Some(&gone), true).await?;
                }
            }
        }
        let index = self.read_index(id).unwrap_or_default();
        for name in &index.secrets {
            self.store.delete_secret(name).await;
        }
        let left = self.s3_copy_count(id).await.unwrap_or(0);
        let dirs = self.dirs.clone();
        let sid = id.to_string();
        tokio::task::spawn_blocking(move || {
            for dir in [dirs.site_dir(&sid), dirs.staging_dir(&sid)]
                .into_iter()
                .flatten()
            {
                if dir.is_dir() {
                    let _ = std::fs::remove_dir_all(&dir);
                }
            }
        })
        .await
        .map_err(join_err)?;
        Ok(left)
    }

    /// A shared tenant whose site was deleted without purge: every login goes NOLOGIN and its entries leave
    /// `pg_hba.conf`, so a later network that reuses the freed subnet gets no path to the data. Re-enabling
    /// Postgres for the same site id reverses both (the login upsert sets LOGIN with the stored password and the
    /// hba file is rewritten with the new network). A dedicated database needs nothing here: its container is
    /// removed by the orchestrator and its volume and credentials are kept.
    pub async fn detach_site(&self, site: &Site) -> Result<()> {
        let Some(pg) = site
            .data
            .postgres
            .as_ref()
            .filter(|p| p.mode == PgMode::Shared)
        else {
            return Ok(());
        };
        let lock = self.site_lock(&site.id);
        let _g = lock.lock().await;
        for db in &pg.databases {
            for u in &db.users {
                self.set_login_state(site, &db.name, u, "disable").await?;
            }
        }
        let mut gone = site.clone();
        gone.data.postgres = None;
        let _sg = self.shared_lock.lock().await;
        self.write_hba(Some(&gone), true).await
    }

    async fn s3_copy_count(&self, site: &str) -> Result<u32> {
        let cat = self.read_catalog(site).await?;
        Ok(cat
            .databases
            .values()
            .flat_map(|d| d.backups.iter())
            .filter(|r| r.s3.is_some())
            .count() as u32)
    }

    /// Startup recovery: interrupted records fail, staging and partial files go, and a finished key rotation is
    /// completed (local backup headers re-wrapped, keys S3 copies still need kept).
    pub async fn recover(self: &Arc<Self>) {
        let dirs = self.dirs.clone();
        let now = now_rfc3339();
        match tokio::task::spawn_blocking(move || dirs.recover(&now)).await {
            Ok(report) => {
                if report.interrupted + report.staging_entries + report.partials > 0 {
                    tracing::info!(
                        interrupted = report.interrupted,
                        staging = report.staging_entries,
                        partials = report.partials,
                        "backup volume recovered"
                    );
                }
                for failure in &report.failures {
                    tracing::warn!(%failure, "backup recovery problem");
                }
            }
            Err(e) => tracing::warn!(error = %e, "backup recovery task failed"),
        }
        self.recover_transfers().await;
        if let Err(e) = self.finish_key_rotation().await {
            tracing::warn!(error = %e, "key rotation could not be completed; the previous key stays in use");
        }
    }

    pub(crate) fn sites_with_data(&self) -> Vec<Site> {
        self.deployer
            .sites()
            .into_iter()
            .filter(|s| s.data.postgres.is_some())
            .collect()
    }
}

// ---- links: plan and errors ----

pub(crate) struct LinkPlan {
    pub add: Vec<EnvLink>,
    pub unset: Vec<(LinkTarget, String)>,
}

#[derive(Debug)]
pub(crate) enum LinkError {
    Conflicts(Vec<LinkConflict>),
    Other(ConnectorError),
}

impl From<ConnectorError> for LinkError {
    fn from(e: ConnectorError) -> Self {
        LinkError::Other(e)
    }
}

fn kind_label(target: LinkTarget) -> &'static str {
    match target {
        LinkTarget::Runtime => "runtime env",
        LinkTarget::Build => "build env",
    }
}

fn check_env_size(env: &BTreeMap<String, String>, label: &str, vars: &[String]) -> Result<()> {
    let list = vars.join(", ");
    if env.len() > MAX_ENV_KEYS {
        return Err(ConnectorError::BadRequest(format!(
            "linking {list} would make the {label} {} variables; the limit is {MAX_ENV_KEYS}",
            env.len()
        )));
    }
    let size = serde_json::to_string(env).map_or(usize::MAX, |s| s.len());
    if size > MAX_ENV_BYTES {
        return Err(ConnectorError::BadRequest(format!(
            "linking {list} would make the {label} {:.1} KiB; the limit is {} KiB",
            size as f64 / 1024.0,
            MAX_ENV_BYTES / 1024
        )));
    }
    Ok(())
}

/// Length of a generated secret once encoded.
pub(crate) fn encoded_len(bytes: u16, encoding: SecretEncoding) -> usize {
    match encoding {
        SecretEncoding::Hex => usize::from(bytes) * 2,
        SecretEncoding::Base64url => (usize::from(bytes) * 4).div_ceil(3),
    }
}

pub(crate) fn link_label(source: &LinkSource) -> String {
    match source {
        LinkSource::Postgres {
            database,
            user,
            field,
        } => {
            format!("postgres {database}/{user} {}", field.as_str())
        }
        LinkSource::External { name, field } => format!("external {name} {}", field.as_str()),
        LinkSource::S3 { name, field } => format!("s3 {name} {}", s3_field_text(*field)),
        LinkSource::Secret { name } => format!("secret {name}"),
        LinkSource::SiteUrl => "site url".to_string(),
    }
}

fn s3_field_text(f: S3Field) -> &'static str {
    f.as_str()
}

/// `VAR (target)` of every link whose source matches.
pub(crate) fn links_to(data: &SiteData, matches: impl Fn(&LinkSource) -> bool) -> Vec<String> {
    data.links
        .iter()
        .filter(|l| matches(&l.source))
        .map(|l| format!("{} ({})", l.var, l.target.as_str()))
        .collect()
}

fn secret_view(site: &Site, g: &GeneratedSecret, redeploy: bool) -> SecretView {
    SecretView {
        name: g.name.clone(),
        bytes: g.bytes,
        encoding: g.encoding,
        rotated_at: g.rotated_at.clone(),
        linked_by: links_to(
            &site.data,
            |s| matches!(s, LinkSource::Secret { name } if *name == g.name),
        ),
        redeploy_needed: redeploy
            && site
                .data
                .links
                .iter()
                .any(|l| matches!(&l.source, LinkSource::Secret { name } if *name == g.name)),
    }
}

fn s3_view(site: &Site, name: &str) -> S3View {
    let a = site.data.s3.iter().find(|s| s.name == name);
    S3View {
        name: name.to_string(),
        endpoint: a.map(|a| a.endpoint.clone()).unwrap_or_default(),
        bucket: a.map(|a| a.bucket.clone()).unwrap_or_default(),
        region: a.map(|a| a.region.clone()).unwrap_or_default(),
        path_style: a.is_some_and(|a| a.path_style),
        has_keys: a.is_some(),
        linked_by: links_to(
            &site.data,
            |s| matches!(s, LinkSource::S3 { name: n, .. } if n == name),
        ),
    }
}

pub(crate) fn default_database() -> PgDatabase {
    PgDatabase {
        name: "app".into(),
        users: vec![
            new_user("app", PgLevel::Readwrite),
            new_user("migrate", PgLevel::Owner),
        ],
    }
}

pub(crate) fn new_user(name: &str, level: PgLevel) -> PgUser {
    PgUser {
        name: name.to_string(),
        level,
        connection_limit: DEFAULT_CONN_LIMIT,
        statement_timeout_ms: None,
        idle_in_transaction_timeout_ms: None,
        disabled: false,
    }
}

/// What a preset adds, applied to an in-memory site so the whole result can be validated before any job runs.
fn apply_preset_to_site(site: &mut Site, plan: &denv::PresetPlan) {
    if let Some(pg) = site.data.postgres.as_mut() {
        for db in &plan.databases {
            if !pg.databases.iter().any(|d| d.name == *db) {
                pg.databases.push(PgDatabase {
                    name: db.clone(),
                    users: Vec::new(),
                });
            }
        }
        for (db, user) in &plan.users {
            if let Some(d) = pg.databases.iter_mut().find(|d| d.name == *db) {
                d.users.push(user.clone());
            }
        }
    }
    site.data.secrets.extend(plan.secrets.iter().cloned());
    site.data.links.extend(plan.links.iter().cloned());
}

pub(crate) fn valid_database_name(name: &str) -> bool {
    is_pg_ident(name) && !cite_edge::datamodel::RESERVED_PG_DATABASES.contains(&name)
}

pub(crate) const MAX_DATABASES: usize = MAX_PG_DATABASES;

#[cfg(test)]
mod tests {
    use super::*;

    fn env(n: usize, value_len: usize) -> BTreeMap<String, String> {
        (0..n)
            .map(|i| (format!("VAR_{i:03}"), "x".repeat(value_len)))
            .collect()
    }

    #[test]
    fn env_limits_name_the_links_and_the_limit() {
        let vars = vec!["DIRECT_URL".to_string()];
        assert!(check_env_size(&env(10, 100), "build env", &vars).is_ok());
        let keys = check_env_size(&env(MAX_ENV_KEYS + 1, 1), "build env", &vars)
            .unwrap_err()
            .to_string();
        assert!(
            keys.contains("DIRECT_URL") && keys.contains("build env") && keys.contains("128"),
            "{keys}"
        );
        let bytes = check_env_size(&env(7, 4000), "runtime env", &vars)
            .unwrap_err()
            .to_string();
        assert!(
            bytes.contains("KiB") && bytes.contains("limit is 24 KiB"),
            "{bytes}"
        );
    }

    #[test]
    fn encoded_secret_lengths_match_the_generator() {
        for (bytes, enc) in [
            (32u16, SecretEncoding::Base64url),
            (33, SecretEncoding::Base64url),
            (64, SecretEncoding::Hex),
            (128, SecretEncoding::Base64url),
        ] {
            let value = denv::generate_secret(bytes, enc).unwrap();
            assert_eq!(value.len(), encoded_len(bytes, enc), "{bytes} {enc:?}");
        }
    }

    #[test]
    fn link_labels_read_like_the_ui_text() {
        let pg = LinkSource::Postgres {
            database: "app".into(),
            user: "app".into(),
            field: PgField::Url,
        };
        assert_eq!(link_label(&pg), "postgres app/app url");
        assert_eq!(link_label(&LinkSource::SiteUrl), "site url");
        assert_eq!(
            link_label(&LinkSource::Secret {
                name: "auth-secret".into()
            }),
            "secret auth-secret"
        );
    }

    #[test]
    fn policy_refusals_are_marked_and_stripped_before_a_client_sees_them() {
        let e = policy("outbound is off");
        assert!(matches!(&e, ConnectorError::BadRequest(m) if m.starts_with(POLICY_PREFIX)));
        assert_eq!(public_error(&e), "outbound is off");
        assert_eq!(
            public_error(&ConnectorError::Internal("path /conf/x".into())),
            "internal error; see the connector log"
        );
    }

    #[test]
    fn the_default_database_has_the_documented_users() {
        let db = default_database();
        assert_eq!(db.name, "app");
        let users: Vec<(&str, PgLevel)> = db
            .users
            .iter()
            .map(|u| (u.name.as_str(), u.level))
            .collect();
        assert_eq!(
            users,
            [("app", PgLevel::Readwrite), ("migrate", PgLevel::Owner)]
        );
        assert!(
            valid_database_name("app")
                && !valid_database_name("postgres")
                && !valid_database_name("Bad")
        );
    }
}
