//! The node-wide shared Postgres instance: settings, lifecycle, the generated `pg_hba.conf` that confines every
//! tenant to its own database and network, tenant sizes, and optional whole-instance backups.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use cite_edge::datamodel::{
    DEFAULT_PG_MAJOR, LinkSource, PgMode, SHARED_DB, pg_db_name, pg_role_tag,
};
use cite_edge::datawire::{
    BackupStatus, InstanceBackupPart, InstanceBackupRecord, SharedReq, SharedView,
    TenantDatabaseView, TenantView,
};
use cite_edge::model::Site;
use cite_edge::validate::PG_MAJORS;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::jobs::{PgTarget, TenantJob, new_job_id};
use super::service::{DB_PORT, DataService, JobCtx, PwSecret, cat_err, join_err, lk};
use super::stream::{StreamReader, StreamWriter};
use crate::orchestrator::data::{JobNet, JobOp, JobScope, JobSpec};
use crate::store::now_rfc3339;
use crate::{ConnectorError, Result};

pub const SHARED_SECRET: &str = "node.data.pg-shared";
const SETTINGS_FILE: &str = "pg-shared.json";
const SIZES_TTL: Duration = Duration::from_secs(300);
const MIN_MEMORY_MB: u32 = 256;
const MAX_MEMORY_MB: u32 = 65_536;

/// `<data dir>/data/pg-shared.json`; also what the orchestrator needs to create the instance container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedSettings {
    pub version: u32,
    pub enabled: bool,
    pub major: u8,
    pub memory_mb: u32,
    pub nano_cpus: i64,
    pub max_connections: u32,
}

impl Default for SharedSettings {
    fn default() -> Self {
        SharedSettings {
            version: 1,
            enabled: false,
            major: DEFAULT_PG_MAJOR,
            memory_mb: 1024,
            nano_cpus: 1_000_000_000,
            max_connections: 200,
        }
    }
}

/// Validates a settings request against the current settings and returns the new ones.
pub fn merge_shared_request(current: &SharedSettings, req: &SharedReq) -> Result<SharedSettings> {
    if !(MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&req.memory_mb) {
        return Err(ConnectorError::BadRequest(format!(
            "memory_mb must be {MIN_MEMORY_MB} to {MAX_MEMORY_MB}"
        )));
    }
    if !(10..=1000).contains(&req.max_connections) {
        return Err(ConnectorError::BadRequest(
            "max_connections must be 10 to 1000".into(),
        ));
    }
    if !req.cpus.is_finite() || !(0.25..=64.0).contains(&req.cpus) {
        return Err(ConnectorError::BadRequest("cpus must be 0.25 to 64".into()));
    }
    let major = if current.enabled {
        if req.major.is_some_and(|m| m != current.major) {
            return Err(ConnectorError::Conflict(
                "the Postgres major of the shared instance is fixed once it exists".into(),
            ));
        }
        current.major
    } else {
        req.major.unwrap_or(DEFAULT_PG_MAJOR)
    };
    if !PG_MAJORS.contains(&major) {
        return Err(ConnectorError::BadRequest(format!(
            "major {major} must be one of {PG_MAJORS:?}"
        )));
    }
    Ok(SharedSettings {
        version: 1,
        enabled: true,
        major,
        memory_mb: req.memory_mb,
        nano_cpus: (req.cpus * 1e9).round() as i64,
        max_connections: req.max_connections,
    })
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SharedCatalog {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    backups: Vec<InstanceBackupRecord>,
}

impl DataService {
    fn shared_settings_path(&self) -> std::path::PathBuf {
        self.cfg.data_dir.join("data").join(SETTINGS_FILE)
    }

    pub(crate) async fn shared_settings(&self) -> Result<SharedSettings> {
        let path = self.shared_settings_path();
        if !path.exists() {
            return Ok(SharedSettings::default());
        }
        let bytes = cite_core::atomic::read_limited(&path, 1 << 16).map_err(|e| {
            ConnectorError::Internal(format!("cannot read the shared instance settings: {e}"))
        })?;
        serde_json::from_slice(&bytes).map_err(|_| {
            ConnectorError::Internal("the shared instance settings are damaged".into())
        })
    }

    fn write_shared_settings(&self, s: &SharedSettings) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(s)?;
        cite_core::atomic::write_atomic(&self.shared_settings_path(), &bytes, 0o600).map_err(|e| {
            ConnectorError::Internal(format!("cannot write the shared instance settings: {e}"))
        })
    }

    pub(crate) async fn shared_password(&self) -> Result<Zeroizing<String>> {
        let pw: PwSecret = self.secret_get(SHARED_SECRET).await?.ok_or_else(|| {
            ConnectorError::Unavailable("the shared instance credentials are missing".into())
        })?;
        Ok(Zeroizing::new(pw.password))
    }

    /// 409 unless the shared instance has been enabled on this node.
    pub(crate) async fn check_shared_ready(&self) -> Result<()> {
        if !self.shared_settings().await?.enabled {
            return Err(ConnectorError::Conflict(
                "the shared Postgres instance is not enabled on this node".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn require_shared_running(&self) -> Result<()> {
        let settings = self.shared_settings().await?;
        if !settings.enabled {
            return Err(ConnectorError::Conflict(
                "the shared Postgres instance is not enabled on this node".into(),
            ));
        }
        let health = self.engine.database_health(SHARED_DB).await?;
        if health.state != "running" || health.health == "unhealthy" || health.health == "starting"
        {
            return Err(ConnectorError::Unavailable(format!(
                "the shared Postgres instance is not ready ({} {})",
                health.state, health.health
            )));
        }
        Ok(())
    }

    pub(crate) fn shared_spec(
        &self,
        major: u8,
        su: &str,
        op: JobOp,
        extra: Vec<(&'static str, String)>,
    ) -> (String, JobSpec) {
        let id = new_job_id();
        let mut env: Vec<(String, Zeroizing<String>)> = vec![
            ("CITE_JOB_ID".into(), Zeroizing::new(id.clone())),
            ("PGHOST".into(), Zeroizing::new(SHARED_DB.into())),
            ("PGPORT".into(), Zeroizing::new(DB_PORT.to_string())),
            ("PGUSER".into(), Zeroizing::new("postgres".into())),
            ("PGPASSWORD".into(), Zeroizing::new(su.to_string())),
        ];
        env.extend(
            extra
                .into_iter()
                .map(|(k, v)| (k.to_string(), Zeroizing::new(v))),
        );
        (
            id,
            JobSpec {
                scope: JobScope::Shared,
                op,
                net: JobNet::SharedAdmin,
                major,
                env,
                read_only: false,
            },
        )
    }

    /// Entries of the generated hba file: the admin network first, then one `<db>|<subnet>` per tenant database.
    /// `extra` replaces (or adds) one site, so a change can be applied before it is stored.
    pub(crate) async fn hba_entries(&self, extra: Option<&Site>) -> Result<Vec<String>> {
        let admin = self.engine.prepare_shared().await?;
        let mut entries = vec![format!("_admin|{admin}")];
        let mut sites = self.deployer.sites();
        if let Some(x) = extra {
            sites.retain(|s| s.id != x.id);
            sites.push(x.clone());
        }
        sites.sort_by(|a, b| a.id.cmp(&b.id));
        for s in sites {
            let Some(pg) = s
                .data
                .postgres
                .as_ref()
                .filter(|p| p.mode == PgMode::Shared)
            else {
                continue;
            };
            let subnet = match self.engine.dbnet_subnet(&s.id).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(site = %s.id, error = %e, "a tenant network has no subnet yet; it is left out of pg_hba.conf");
                    continue;
                }
            };
            for db in &pg.databases {
                entries.push(format!("{}|{subnet}", pg_role_tag(&s.id, &db.name)));
            }
        }
        Ok(entries)
    }

    /// Regenerates `pg_hba.conf` through the hba job. The caller holds `shared_lock`.
    pub(crate) async fn write_hba(&self, extra: Option<&Site>, reload: bool) -> Result<()> {
        let settings = self.shared_settings().await?;
        let entries = self.hba_entries(extra).await?;
        self.write_hba_entries(&settings, entries, reload).await
    }

    /// Writes the given entries; after a reload the server runs them, which `reconcile` remembers. The caller
    /// holds `shared_lock`.
    pub(crate) async fn write_hba_entries(
        &self,
        settings: &SharedSettings,
        entries: Vec<String>,
        reload: bool,
    ) -> Result<()> {
        let su = self.shared_password().await?;
        let (_, spec) = self.shared_spec(
            settings.major,
            &su,
            JobOp::Hba,
            vec![
                ("CITE_PG_HBA", entries.join(";")),
                ("CITE_PG_RELOAD", if reload { "1" } else { "0" }.to_string()),
            ],
        );
        let written = self
            .run_ok("hba", spec, std::slice::from_ref(&*su))
            .await
            .map(|_| ());
        // A file the server has not loaded yet (or failed to write) must be compared again next time.
        *lk(&self.hba_applied) = match (&written, reload) {
            (Ok(()), true) => Some(entries),
            _ => None,
        };
        written
    }

    // ---- lifecycle ----

    /// Creates or updates the instance (memory, CPUs, connections recreate the container).
    pub(crate) async fn do_shared_put(&self, ctx: &JobCtx, req: SharedReq) -> Result<Value> {
        let _g = self.shared_lock.lock().await;
        let current = self.shared_settings().await?;
        let created = !current.enabled;
        let next = merge_shared_request(&current, &req)?;
        ctx.step("preparing credentials");
        let su = match self.secret_get::<PwSecret>(SHARED_SECRET).await? {
            Some(s) => Zeroizing::new(s.password),
            None => {
                let pw = super::env::generate_password().map_err(ConnectorError::Internal)?;
                self.secret_put(
                    None,
                    SHARED_SECRET,
                    &PwSecret {
                        password: pw.to_string(),
                    },
                )
                .await?;
                pw
            }
        };
        self.write_shared_settings(&next)?;
        ctx.step("preparing volumes and the admin network");
        self.write_hba(None, false).await?;
        ctx.step("starting the instance");
        self.engine.ensure_shared_instance(&next, &su).await?;
        // A recreated container starts with no tenant networks; only the service knows who the tenants are.
        let tenants: Vec<String> = self.shared_tenants().into_iter().map(|s| s.id).collect();
        if !tenants.is_empty() {
            ctx.step("reconnecting tenants");
            self.engine.reconnect_shared(&tenants).await?;
        }
        Ok(json!({ "created": created }))
    }

    pub(crate) async fn do_shared_restart(&self, ctx: &JobCtx) -> Result<Value> {
        let _g = self.shared_lock.lock().await;
        if !self.shared_settings().await?.enabled {
            return Err(ConnectorError::Conflict(
                "the shared instance is not enabled".into(),
            ));
        }
        ctx.step("restarting the instance");
        self.engine.restart_database(SHARED_DB).await?;
        Ok(Value::Null)
    }

    pub(crate) fn shared_tenants(&self) -> Vec<Site> {
        self.deployer
            .sites()
            .into_iter()
            .filter(|s| {
                s.data
                    .postgres
                    .as_ref()
                    .is_some_and(|p| p.mode == PgMode::Shared)
            })
            .collect()
    }

    pub(crate) fn check_shared_delete(&self, force: bool, purge: bool) -> Result<()> {
        let tenants = self.shared_tenants();
        if !tenants.is_empty() && !(force && purge) {
            return Err(ConnectorError::Conflict(format!(
                "the shared instance still has tenants ({}); remove them or pass force=true and purge=true",
                tenants
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        Ok(())
    }

    pub(crate) async fn do_shared_delete(
        &self,
        ctx: &JobCtx,
        actor: &str,
        force: bool,
        purge: bool,
    ) -> Result<Value> {
        let _g = self.shared_lock.lock().await;
        self.check_shared_delete(force, purge)?;
        let mut settings = self.shared_settings().await?;
        let mut dropped = Vec::new();
        for site in self.shared_tenants() {
            ctx.step(&format!("removing tenant {}", site.id));
            let lock = self.site_lock(&site.id);
            let _sg = lock.lock().await;
            let site = self.site(&site.id)?;
            if let Some(pg) = site.data.postgres.clone() {
                for db in &pg.databases {
                    self.deprovision_db_job(&site, &db.name).await?;
                    self.index_edit(&site.id, {
                        let n = db.name.clone();
                        move |i| {
                            i.databases.remove(&n);
                        }
                    })
                    .await?;
                }
                let _ = self.engine.disconnect_shared(&site.id).await;
                let detail = format!("site={} reason=shared-instance-deleted", site.id);
                self.update_site(actor, "data.postgres.purge", &detail, &site.id, |s| {
                    s.data.postgres = None;
                    s.data
                        .links
                        .retain(|l| !matches!(l.source, LinkSource::Postgres { .. }));
                    Ok(())
                })
                .await?;
                dropped.push(site.id.clone());
            }
        }
        ctx.step("removing the instance");
        self.engine.remove_shared_instance(purge).await?;
        if purge {
            self.secret_del(None, SHARED_SECRET).await;
            let path = self.shared_settings_path();
            let _ = std::fs::remove_file(path);
        } else {
            settings.enabled = false;
            self.write_shared_settings(&settings)?;
        }
        Ok(json!({ "tenants_removed": dropped, "redeploy_needed": !dropped.is_empty() }))
    }

    // ---- view and sizes ----

    pub(crate) fn cached_sizes(&self) -> Vec<(String, u64)> {
        lk(&self.sizes_cache)
            .as_ref()
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    async fn refresh_sizes(&self, settings: &SharedSettings) -> Result<Vec<(String, u64)>> {
        let su = self.shared_password().await?;
        let (job, spec) = self.shared_spec(settings.major, &su, JobOp::Sizes, Vec::new());
        self.run_ok("sizes", spec, std::slice::from_ref(&*su))
            .await?;
        let path = self.dirs.shared_staging_dir().join(format!("{job}.sizes"));
        let text = std::fs::read_to_string(&path)
            .map_err(|_| ConnectorError::Unavailable("the sizes job left no result".into()));
        let _ = std::fs::remove_file(&path);
        Ok(parse_sizes(&text?))
    }

    pub(crate) async fn shared_view(&self) -> Result<SharedView> {
        let settings = self.shared_settings().await?;
        if !settings.enabled {
            return Ok(SharedView::default());
        }
        let health = self.engine.database_health(SHARED_DB).await.ok();
        let running = health.as_ref().is_some_and(|h| h.state == "running");
        let stale = lk(&self.sizes_cache)
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() > SIZES_TTL);
        if running && stale {
            let sizes = self.refresh_sizes(&settings).await.unwrap_or_default();
            *lk(&self.sizes_cache) = Some((Instant::now(), sizes));
        }
        let sizes = self.cached_sizes();
        let tenants = self
            .shared_tenants()
            .into_iter()
            .map(|s| TenantView {
                databases: s
                    .data
                    .postgres
                    .as_ref()
                    .map(|p| {
                        p.databases
                            .iter()
                            .map(|d| {
                                let name = pg_db_name(PgMode::Shared, &s.id, &d.name);
                                TenantDatabaseView {
                                    size_bytes: sizes
                                        .iter()
                                        .find(|(n, _)| *n == name)
                                        .map_or(0, |(_, b)| *b),
                                    name: d.name.clone(),
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                site: s.id,
            })
            .collect();
        Ok(SharedView {
            enabled: true,
            major: settings.major,
            memory_mb: settings.memory_mb,
            nano_cpus: settings.nano_cpus,
            max_connections: settings.max_connections,
            health: health
                .map(|h| {
                    if h.health.is_empty() {
                        h.state
                    } else {
                        format!("{} ({})", h.state, h.health)
                    }
                })
                .unwrap_or_else(|| "unknown".into()),
            size_bytes: self
                .engine
                .volume_size(cite_edge::datamodel::SHARED_DATA)
                .await
                .ok()
                .flatten()
                .unwrap_or(0),
            tenants,
        })
    }

    // ---- whole-instance backups ----

    fn shared_catalog(&self) -> Result<SharedCatalog> {
        let path = self.dirs.shared_catalog_path();
        if !path.exists() {
            return Ok(SharedCatalog {
                version: 1,
                backups: Vec::new(),
            });
        }
        let bytes = cite_core::atomic::read_limited(&path, super::catalog::MAX_CATALOG_BYTES)
            .map_err(|e| {
                ConnectorError::Internal(format!("cannot read the instance backup catalog: {e}"))
            })?;
        serde_json::from_slice(&bytes)
            .map_err(|_| ConnectorError::Internal("the instance backup catalog is damaged".into()))
    }

    fn store_shared_catalog(&self, cat: &SharedCatalog) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(cat)?;
        cite_core::atomic::write_atomic(&self.dirs.shared_catalog_path(), &bytes, 0o600).map_err(
            |e| ConnectorError::Internal(format!("cannot write the instance backup catalog: {e}")),
        )
    }

    pub(crate) async fn list_instance_backups(&self) -> Result<Vec<InstanceBackupRecord>> {
        let _g = self.shared_lock.lock().await;
        let mut all = self.shared_catalog()?.backups;
        all.reverse();
        Ok(all)
    }

    pub(crate) fn start_instance_backup(self: &Arc<Self>) -> Result<String> {
        self.require_job_capacity()?;
        let svc = Arc::clone(self);
        Ok(
            self.spawn_task("shared-backup", None, move |ctx| async move {
                svc.do_instance_backup(&ctx).await
            }),
        )
    }

    async fn do_instance_backup(&self, ctx: &JobCtx) -> Result<Value> {
        let _g = self.shared_lock.lock().await;
        let settings = self.shared_settings().await?;
        if !settings.enabled {
            return Err(ConnectorError::Conflict(
                "the shared instance is not enabled".into(),
            ));
        }
        let su = self.shared_password().await?;
        let id = Ulid::generate().to_string();
        let mut cat = self.shared_catalog()?;
        cat.version = 1;
        cat.backups.push(InstanceBackupRecord {
            id: id.clone(),
            created_at: now_rfc3339(),
            parts: Vec::new(),
            status: BackupStatus::Running,
        });
        self.store_shared_catalog(&cat)?;
        let result = self.instance_parts(ctx, &settings, &su, &id).await;
        let mut cat = self.shared_catalog()?;
        if let Some(rec) = cat.backups.iter_mut().find(|r| r.id == id) {
            match &result {
                Ok(parts) => {
                    rec.parts = parts.clone();
                    rec.status = BackupStatus::Ok;
                }
                Err(_) => rec.status = BackupStatus::Failed,
            }
        }
        self.store_shared_catalog(&cat)?;
        if result.is_err() {
            let dir = self.dirs.shared_dir().join(&id);
            let _ = std::fs::remove_dir_all(dir);
        }
        result.map(|parts| json!({ "backup_id": id, "parts": parts.len() }))
    }

    async fn instance_parts(
        &self,
        ctx: &JobCtx,
        settings: &SharedSettings,
        su: &Zeroizing<String>,
        id: &str,
    ) -> Result<Vec<InstanceBackupPart>> {
        let redact = vec![su.to_string()];
        let mut parts = Vec::new();
        ctx.step("dumping global objects");
        let (job, spec) = self.shared_spec(settings.major, su, JobOp::Globals, Vec::new());
        self.run_ok("globals", spec, &redact).await?;
        parts.push(
            self.seal_shared_part(id, "globals", &job, "globals")
                .await?,
        );
        let mut tenants: Vec<(String, String)> = Vec::new();
        for s in self.shared_tenants() {
            if let Some(pg) = &s.data.postgres {
                tenants.extend(pg.databases.iter().map(|d| (s.id.clone(), d.name.clone())));
            }
        }
        for (site_id, db) in tenants {
            let mut tj = TenantJob::new(PgMode::Shared, &site_id, &db);
            tj.shared_scope = true;
            let name = tj.database.clone();
            ctx.step(&format!("dumping {name}"));
            // Each tenant database is dumped as its own job login, never as the superuser.
            let target = PgTarget {
                site_id,
                shared: true,
                host: SHARED_DB.to_string(),
                password: su.clone(),
                major: settings.major,
            };
            let (job, spec) = self.shared_spec(
                settings.major,
                su,
                JobOp::Backup,
                vec![
                    ("PGDATABASE", name.clone()),
                    ("CITE_ROLE_TAG", tj.tag.clone()),
                ],
            );
            self.run_tenant_ok("backup", &target, &tj, spec, &redact)
                .await?;
            parts.push(self.seal_shared_part(id, &name, &job, "dump").await?);
        }
        Ok(parts)
    }

    async fn seal_shared_part(
        &self,
        id: &str,
        part: &str,
        job: &str,
        ext: &str,
    ) -> Result<InstanceBackupPart> {
        let staging = self.dirs.shared_staging_dir().join(format!("{job}.{ext}"));
        let version = self
            .dirs
            .shared_staging_dir()
            .join(format!("{job}.version"));
        let dest = self.dirs.shared_part_file(id, part).map_err(cat_err)?;
        let (keyring, aad, part_name) = (
            Arc::clone(&self.keyring),
            format!("{id}.{part}"),
            part.to_string(),
        );
        tokio::task::spawn_blocking(move || -> Result<InstanceBackupPart> {
            if let Some(dir) = dest.parent() {
                cite_core::atomic::ensure_dir(dir, 0o700).map_err(|e| {
                    ConnectorError::Internal(format!("cannot create the backup directory: {e}"))
                })?;
            }
            let partial = dest.with_extension("cbk.partial");
            let result = (|| -> Result<InstanceBackupPart> {
                let mut writer = StreamWriter::create(&partial, &keyring, &aad)?;
                let mut input = std::fs::File::open(&staging)
                    .map_err(|_| ConnectorError::Unavailable("the job left no output".into()))?;
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let n = io::Read::read(&mut input, &mut buf).map_err(|e| {
                        ConnectorError::Internal(format!("cannot read the dump: {e}"))
                    })?;
                    if n == 0 {
                        break;
                    }
                    writer.write_all(&buf[..n])?;
                }
                let summary = writer.finish()?;
                std::fs::rename(&partial, &dest).map_err(|e| {
                    ConnectorError::Internal(format!("cannot move the backup into place: {e}"))
                })?;
                Ok(InstanceBackupPart {
                    database: part_name,
                    size_bytes: summary.plaintext_len,
                    sha256: summary.sha256,
                })
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&partial);
            }
            let _ = std::fs::remove_file(&staging);
            let _ = std::fs::remove_file(&version);
            result
        })
        .await
        .map_err(join_err)?
    }

    pub(crate) async fn delete_instance_backup(&self, id: &str) -> Result<()> {
        let _g = self.shared_lock.lock().await;
        let mut cat = self.shared_catalog()?;
        let at =
            cat.backups.iter().position(|r| r.id == id).ok_or_else(|| {
                ConnectorError::NotFound(format!("instance backup {id} not found"))
            })?;
        if cat.backups[at].status == BackupStatus::Running {
            return Err(ConnectorError::Conflict(
                "the backup is still running".into(),
            ));
        }
        cat.backups.remove(at);
        self.store_shared_catalog(&cat)?;
        let dir = self.dirs.shared_dir().join(id);
        if dir.is_dir() && !id.contains(['/', '.']) {
            std::fs::remove_dir_all(&dir).map_err(|e| {
                ConnectorError::Internal(format!("cannot remove the backup files: {e}"))
            })?;
        }
        Ok(())
    }

    /// The decrypted parts of an instance backup as one tar stream: its exact length and the body chunks.
    pub(crate) async fn instance_backup_tar(
        &self,
        id: &str,
        permit: OwnedSemaphorePermit,
    ) -> Result<(u64, mpsc::Receiver<io::Result<Bytes>>)> {
        let rec = {
            let _g = self.shared_lock.lock().await;
            self.shared_catalog()?
                .backups
                .into_iter()
                .find(|r| r.id == id)
                .ok_or_else(|| {
                    ConnectorError::NotFound(format!("instance backup {id} not found"))
                })?
        };
        if rec.status != BackupStatus::Ok {
            return Err(ConnectorError::Conflict(
                "only a finished backup can be downloaded".into(),
            ));
        }
        let mut files = Vec::new();
        for p in &rec.parts {
            let path = self
                .dirs
                .shared_part_file(id, &p.database)
                .map_err(cat_err)?;
            let name = if p.database == "globals" {
                "globals.sql".to_string()
            } else {
                format!("{}.dump", p.database)
            };
            files.push((
                name,
                path,
                format!("{id}.{}", p.database),
                p.size_bytes,
                p.sha256.clone(),
            ));
        }
        let total = files
            .iter()
            .map(|(_, _, _, size, _)| 512 + size.div_ceil(512) * 512)
            .sum::<u64>()
            + 1024;
        let keyring = self.read_keyring().await;
        let mtime = time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
        let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(4);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let run = || -> std::result::Result<(), String> {
                for (name, path, aad, size, sha) in &files {
                    let mut reader =
                        StreamReader::open(path, &keyring, aad).map_err(|e| e.to_string())?;
                    if reader.plaintext_len() != *size {
                        return Err("a part has an unexpected size".into());
                    }
                    if tx
                        .blocking_send(Ok(Bytes::copy_from_slice(&tar_header(name, *size, mtime))))
                        .is_err()
                    {
                        return Ok(());
                    }
                    let mut hasher = sha2::Sha256::default();
                    let mut offset = 0u64;
                    let mut buf = Vec::new();
                    while offset < *size {
                        buf.clear();
                        reader
                            .read_range(offset, 256 * 1024, &mut buf)
                            .map_err(|e| e.to_string())?;
                        if buf.is_empty() {
                            return Err("a part ended early".into());
                        }
                        sha2::Digest::update(&mut hasher, &buf);
                        offset += buf.len() as u64;
                        if tx.blocking_send(Ok(Bytes::copy_from_slice(&buf))).is_err() {
                            return Ok(());
                        }
                    }
                    let got: String = sha2::Digest::finalize(hasher)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    if got != *sha {
                        return Err("a part does not match its recorded checksum".into());
                    }
                    let pad = (size.div_ceil(512) * 512 - size) as usize;
                    if pad > 0 && tx.blocking_send(Ok(Bytes::from(vec![0u8; pad]))).is_err() {
                        return Ok(());
                    }
                }
                let _ = tx.blocking_send(Ok(Bytes::from(vec![0u8; 1024])));
                Ok(())
            };
            if let Err(msg) = run() {
                tracing::error!(error = %msg, "instance backup download failed");
                let _ = tx.blocking_send(Err(io::Error::other("the backup could not be read")));
            }
        });
        Ok((total, rx))
    }
}

/// `datname<TAB>bytes` lines of the sizes job.
pub(crate) fn parse_sizes(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter_map(|l| {
            let (name, size) = l.split_once('\t')?;
            Some((name.to_string(), size.trim().parse().ok()?))
        })
        .collect()
}

/// One ustar header block for a regular file.
pub(crate) fn tar_header(name: &str, size: u64, mtime: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
    h[100..108].copy_from_slice(b"0000600\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(format!("{mtime:011o}\0").as_bytes());
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(memory: u32, cpus: f64, conns: u32, major: Option<u8>) -> SharedReq {
        SharedReq {
            major,
            memory_mb: memory,
            cpus,
            max_connections: conns,
        }
    }

    #[test]
    fn a_new_instance_defaults_to_the_current_major_and_validates_limits() {
        let cur = SharedSettings::default();
        let s = merge_shared_request(&cur, &req(1024, 1.5, 200, None)).unwrap();
        assert!(s.enabled && s.major == DEFAULT_PG_MAJOR && s.nano_cpus == 1_500_000_000);
        assert!(merge_shared_request(&cur, &req(100, 1.0, 200, None)).is_err());
        assert!(merge_shared_request(&cur, &req(1024, 0.0, 200, None)).is_err());
        assert!(merge_shared_request(&cur, &req(1024, f64::NAN, 200, None)).is_err());
        assert!(merge_shared_request(&cur, &req(1024, 1.0, 5, None)).is_err());
        assert!(merge_shared_request(&cur, &req(1024, 1.0, 200, Some(16))).is_err());
        assert_eq!(
            merge_shared_request(&cur, &req(1024, 1.0, 200, Some(17)))
                .unwrap()
                .major,
            17
        );
    }

    #[test]
    fn the_major_of_an_existing_instance_cannot_change() {
        let cur = SharedSettings {
            enabled: true,
            major: 17,
            ..SharedSettings::default()
        };
        assert!(matches!(
            merge_shared_request(&cur, &req(1024, 1.0, 200, Some(18))),
            Err(ConnectorError::Conflict(_))
        ));
        assert_eq!(
            merge_shared_request(&cur, &req(2048, 2.0, 300, None))
                .unwrap()
                .major,
            17
        );
        assert_eq!(
            merge_shared_request(&cur, &req(2048, 2.0, 300, Some(17)))
                .unwrap()
                .max_connections,
            300
        );
    }

    #[test]
    fn sizes_parse_tab_separated_lines_and_skip_noise() {
        let got = parse_sizes("t0123456789_app\t8192\npostgres\t7000000\nbroken\nx\tnope\n");
        assert_eq!(
            got,
            vec![
                ("t0123456789_app".to_string(), 8192),
                ("postgres".to_string(), 7_000_000)
            ]
        );
    }

    #[test]
    fn tar_headers_are_valid_ustar_blocks() {
        let h = tar_header("app.dump", 1000, 1_700_000_000);
        assert_eq!(&h[257..262], b"ustar");
        assert_eq!(&h[..8], b"app.dump");
        let size = std::str::from_utf8(&h[124..135]).unwrap();
        assert_eq!(u64::from_str_radix(size, 8).unwrap(), 1000);
        let stored = u32::from_str_radix(std::str::from_utf8(&h[148..154]).unwrap(), 8).unwrap();
        let mut copy = h;
        copy[148..156].copy_from_slice(b"        ");
        let sum: u32 = copy.iter().map(|b| u32::from(*b)).sum();
        assert_eq!(stored, sum);
    }
}
