//! Database jobs (provision, users, dump, restore) and everything built on them: versioned backups, S3 copies,
//! pruning, restore with a pre-restore backup, downloads and key-rotation upkeep of the backup files.
//!
//! Plaintext dumps exist only in `staging/<site>` while a job runs; the connector encrypts them into
//! `sites/<site>/<id>.cbk` and deletes the staging files, whether the job worked or not.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cite_edge::datamodel::{
    Alt, BackupPolicy, PgGroup, PgMode, PgUser, SHARED_DB, db_container_name, pg_db_name, pg_group,
    pg_login, pg_role_tag, pg_superuser_secret_name,
};
use cite_edge::datawire::{
    BackupRecord, BackupStatus, BackupTrigger, DeleteFrom, EncryptionInfo, LocalCopy, PrunePreview,
    RestoreReq, S3CopyInfo,
};
use cite_edge::model::Site;
use cite_edge::validate::PG_MAJORS;
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::catalog::{ext_key, pg_key};
use super::retention::{PrunePlan, Tier, expired_failed, plan_prune, without_copies};
use super::service::{
    DB_PORT, DataService, JobCtx, PwSecret, cat_err, join_err, policy, public_error,
};
use super::stream::{StreamReader, StreamWriter, rewrap_header};
use super::users::UserSecret;
use crate::alerts::Raised;
use crate::egress::EgressMode;
use crate::orchestrator::data::{JobNet, JobOp, JobOutcome, JobScope, JobSpec, job_login_role};
use crate::seal::NodeKey;
use crate::store::now_rfc3339;
use crate::{ConnectorError, Result};
use cite_edge::alerts::AlertEvent;

const PERMIT_WAIT: Duration = Duration::from_secs(120);
const COPY_STEP: usize = 1 << 20;
const DOWNLOAD_STEP: u64 = 256 * 1024;
const DOWNLOAD_CHANNEL: usize = 4;
pub const RETIRED_KEYS_SECRET: &str = "node.data.retired-keys";
const FORMAT: &str = "pg_dump-custom";
const SCHEME: &str = "cite-stream-v1";

pub(crate) fn new_job_id() -> String {
    Ulid::generate().to_string()
}

/// `pg:<db>` or `ext:<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DbRef {
    Pg(String),
    Ext(String),
}

impl DbRef {
    pub fn parse(key: &str) -> Result<DbRef> {
        match key.split_once(':') {
            Some(("pg", n)) if !n.is_empty() => Ok(DbRef::Pg(n.to_string())),
            Some(("ext", n)) if !n.is_empty() => Ok(DbRef::Ext(n.to_string())),
            _ => Err(ConnectorError::BadRequest(
                "a database is named pg:<name> or ext:<name>".into(),
            )),
        }
    }

    pub fn key(&self) -> String {
        match self {
            DbRef::Pg(n) => pg_key(n),
            DbRef::Ext(n) => ext_key(n),
        }
    }
}

/// Where a site's managed jobs connect.
pub(crate) struct PgTarget {
    pub site_id: String,
    pub shared: bool,
    pub host: String,
    pub password: Zeroizing<String>,
    pub major: u8,
}

impl PgTarget {
    fn net(&self) -> JobNet {
        if self.shared {
            JobNet::SharedAdmin
        } else {
            JobNet::Dbnet
        }
    }
}

/// A job that works inside one tenant database. It runs as the database's job login (`<tag>_job`), which a
/// superuser job opens just before (fresh password, LOGIN) and closes right after (NOLOGIN, no password), so the
/// superuser never connects to a database the tenant controls.
pub(crate) struct TenantJob {
    /// `t<tag>_<db>`.
    pub tag: String,
    /// The database's name on its server (`PGDATABASE`).
    pub database: String,
    /// Lock the tenant's logins (NOLOGIN, sessions ended) while the job runs: a restore.
    pub lock: bool,
    /// Open and close from the shared job container (the whole-instance backup) instead of the site's.
    pub shared_scope: bool,
}

impl TenantJob {
    pub fn new(mode: PgMode, site_id: &str, db: &str) -> TenantJob {
        TenantJob {
            tag: pg_role_tag(site_id, db),
            database: pg_db_name(mode, site_id, db),
            lock: false,
            shared_scope: false,
        }
    }
}

/// Points a job built with the superuser's connection at the job login instead.
fn use_job_login(spec: &mut JobSpec, tag: &str, password: &str) {
    for (key, value) in spec.env.iter_mut() {
        match key.as_str() {
            "PGUSER" => *value = Zeroizing::new(job_login_role(tag)),
            "PGPASSWORD" => *value = Zeroizing::new(password.to_string()),
            _ => {}
        }
    }
}

fn s3e(e: super::s3::S3Error) -> ConnectorError {
    ConnectorError::Unavailable(e.to_string())
}

fn job_failure(op: &str, out: &JobOutcome) -> String {
    let tail: Vec<&str> = out
        .log_tail
        .iter()
        .rev()
        .take(5)
        .map(String::as_str)
        .collect();
    let mut text = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
    text.truncate(floor_boundary(&text, 400));
    format!("the {op} job failed (exit {}): {text}", out.exit_code)
}

fn floor_boundary(s: &str, max: usize) -> usize {
    let mut n = max.min(s.len());
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    n
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Leading number of a `server_version` such as `16.4` or `17.0 (Debian ...)`.
pub(crate) fn server_major(version: &str) -> Option<u8> {
    let digits: String = version
        .trim()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// One step of a login job: the action to run and the password it needs, when it needs one.
#[derive(Clone, Copy)]
struct UserStep<'a> {
    action: &'a str,
    password: Option<&'a str>,
}

impl DataService {
    // ---- running jobs ----

    pub(crate) async fn exec(&self, spec: JobSpec, redact: &[String]) -> Result<JobOutcome> {
        let permit =
            tokio::time::timeout(PERMIT_WAIT, Arc::clone(&self.job_permits).acquire_owned())
                .await
                .map_err(|_| {
                    ConnectorError::TooManyRequests("data jobs are busy; try again shortly".into())
                })?
                .map_err(|_| ConnectorError::Internal("the job semaphore closed".into()))?;
        let out = self
            .engine
            .run_job(&spec, redact, self.cfg.job_timeout)
            .await;
        drop(permit);
        out
    }

    /// Runs a job and fails on a non-zero exit with the redacted log tail.
    pub(crate) async fn run_ok(
        &self,
        op: &str,
        spec: JobSpec,
        redact: &[String],
    ) -> Result<JobOutcome> {
        let out = self.exec(spec, redact).await?;
        if out.exit_code != 0 {
            return Err(ConnectorError::Unavailable(job_failure(op, &out)));
        }
        Ok(out)
    }

    /// The superuser job that opens (`open`, `lock`) or closes (`close`) a database's job login.
    fn job_login_spec(
        &self,
        t: &PgTarget,
        tj: &TenantJob,
        action: &str,
        password: Option<&str>,
    ) -> JobSpec {
        let mut extra: Vec<(&'static str, String)> = vec![
            ("PGDATABASE", tj.database.clone()),
            ("CITE_ROLE_TAG", tj.tag.clone()),
            ("CITE_JOB_ACTION", action.to_string()),
        ];
        if let Some(p) = password {
            extra.push(("CITE_JOB_PASSWORD", p.to_string()));
        }
        if tj.shared_scope {
            self.shared_spec(t.major, &t.password, JobOp::JobLogin, extra)
                .1
        } else {
            self.build_spec(t, JobOp::JobLogin, false, extra).1
        }
    }

    /// Runs `work` (built by `build_spec`) inside a tenant database as its job login: the login is opened with a
    /// fresh password, the job runs, and the login is closed again whether the job worked or not. A close that
    /// cannot run (the connector stops) is repaired by the next open or close of the same database, and the
    /// password, kept only in memory here, is useless after it. Fails on a non-zero exit of any of the three.
    pub(crate) async fn run_tenant_ok(
        &self,
        op: &str,
        t: &PgTarget,
        tj: &TenantJob,
        mut work: JobSpec,
        redact: &[String],
    ) -> Result<JobOutcome> {
        let lock = self.job_login_lock(&tj.tag);
        let _g = lock.lock().await;
        let password = super::env::generate_password().map_err(ConnectorError::Internal)?;
        let mut redact = redact.to_vec();
        redact.push(password.to_string());
        let action = if tj.lock { "lock" } else { "open" };
        let open = self.job_login_spec(t, tj, action, Some(password.as_str()));
        let worked = match self.run_ok("job login open", open, &redact).await {
            Ok(_) => {
                use_job_login(&mut work, &tj.tag, &password);
                self.run_ok(op, work, &redact).await
            }
            Err(e) => Err(e),
        };
        let close = self.job_login_spec(t, tj, "close", None);
        let closed = self.run_ok("job login close", close, &redact).await;
        match (worked, closed) {
            (Ok(out), Ok(_)) => Ok(out),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Ok(_)) => Err(e),
            (Err(e), Err(close_err)) => {
                tracing::warn!(tag = %tj.tag, error = %close_err, "the job login could not be closed after a failed job; the next job of this database closes it");
                Err(e)
            }
        }
    }

    pub(crate) async fn pg_target(&self, site: &Site) -> Result<PgTarget> {
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        self.pg_target_for(&site.id, pg.mode, pg.major).await
    }

    pub(crate) async fn pg_target_for(
        &self,
        id: &str,
        mode: PgMode,
        major: u8,
    ) -> Result<PgTarget> {
        let (name, host) = match mode {
            PgMode::Dedicated => (pg_superuser_secret_name(id), db_container_name(id)),
            PgMode::Shared => (
                super::shared::SHARED_SECRET.to_string(),
                SHARED_DB.to_string(),
            ),
        };
        let pw: PwSecret = self.secret_get(&name).await?.ok_or_else(|| {
            ConnectorError::Unavailable("the database superuser credentials are missing".into())
        })?;
        Ok(PgTarget {
            site_id: id.to_string(),
            shared: mode == PgMode::Shared,
            host,
            password: Zeroizing::new(pw.password),
            major,
        })
    }

    pub(crate) fn build_spec(
        &self,
        t: &PgTarget,
        op: JobOp,
        read_only: bool,
        extra: Vec<(&'static str, String)>,
    ) -> (String, JobSpec) {
        let id = new_job_id();
        let mut env: Vec<(String, Zeroizing<String>)> = vec![
            ("CITE_JOB_ID".into(), Zeroizing::new(id.clone())),
            ("PGHOST".into(), Zeroizing::new(t.host.clone())),
            ("PGPORT".into(), Zeroizing::new(DB_PORT.to_string())),
            ("PGUSER".into(), Zeroizing::new("postgres".into())),
            ("PGPASSWORD".into(), Zeroizing::new((*t.password).clone())),
        ];
        env.extend(
            extra
                .into_iter()
                .map(|(k, v)| (k.to_string(), Zeroizing::new(v))),
        );
        (
            id,
            JobSpec {
                scope: JobScope::Site(t.site_id.clone()),
                op,
                net: t.net(),
                major: t.major,
                env,
                read_only,
            },
        )
    }

    /// The superuser password and the given extra values, on top of every data secret of the site.
    pub(crate) async fn job_redactions(&self, site: &Site, extra: &[&str]) -> Vec<String> {
        let mut out = self.redactions(site).await;
        if let Ok(t) = self.pg_target(site).await {
            out.push(t.password.to_string());
        }
        out.extend(extra.iter().map(|s| s.to_string()));
        out.retain(|s| !s.is_empty());
        out.sort();
        out.dedup();
        out
    }

    fn pg_mode(site: &Site) -> Result<(PgMode, u8)> {
        site.data
            .postgres
            .as_ref()
            .map(|p| (p.mode, p.major))
            .ok_or_else(|| {
                ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
            })
    }

    /// Roles, job login and database as the superuser, then the layout inside the database as the job login.
    pub(crate) async fn provision_db_job(&self, site: &Site, db: &str) -> Result<()> {
        self.db_role_job(site, db, JobOp::Provision, "provision")
            .await?;
        self.regrant_job(site, db, None).await
    }

    /// Re-applies the privilege layout inside a database as its job login. With `release`, the login also loses
    /// whatever it still holds there, which `user drop` needs before the role can go.
    pub(crate) async fn regrant_job(
        &self,
        site: &Site,
        db: &str,
        release: Option<&str>,
    ) -> Result<()> {
        let (mode, _) = Self::pg_mode(site)?;
        let t = self.pg_target(site).await?;
        let tj = TenantJob::new(mode, &site.id, db);
        let mut extra = vec![
            ("PGDATABASE", tj.database.clone()),
            ("CITE_ROLE_TAG", tj.tag.clone()),
        ];
        if let Some(role) = release {
            extra.push(("CITE_USER_ROLE", role.to_string()));
        }
        let (_, spec) = self.build_spec(&t, JobOp::Regrant, false, extra);
        let redact = self.job_redactions(site, &[]).await;
        self.run_tenant_ok("regrant", &t, &tj, spec, &redact)
            .await
            .map(|_| ())
    }

    pub(crate) async fn deprovision_db_job(&self, site: &Site, db: &str) -> Result<()> {
        self.db_role_job(site, db, JobOp::Deprovision, "deprovision")
            .await
    }

    async fn db_role_job(&self, site: &Site, db: &str, op: JobOp, name: &str) -> Result<()> {
        let (mode, _) = Self::pg_mode(site)?;
        let t = self.pg_target(site).await?;
        let (_, spec) = self.build_spec(
            &t,
            op,
            false,
            vec![
                ("PGDATABASE", pg_db_name(mode, &site.id, db)),
                ("CITE_ROLE_TAG", pg_role_tag(&site.id, db)),
            ],
        );
        let redact = self.job_redactions(site, &[]).await;
        self.run_ok(name, spec, &redact).await.map(|_| ())
    }

    /// A deprovision job for a site that is no longer in the config (orphan purge), shared instance only.
    pub(crate) async fn shared_site_job_for(
        &self,
        site_id: &str,
        major: u8,
        su: &str,
        db: &str,
    ) -> Result<JobSpec> {
        let t = PgTarget {
            site_id: site_id.to_string(),
            shared: true,
            host: SHARED_DB.to_string(),
            password: Zeroizing::new(su.to_string()),
            major,
        };
        let (_, spec) = self.build_spec(
            &t,
            JobOp::Deprovision,
            false,
            vec![
                ("PGDATABASE", pg_db_name(PgMode::Shared, site_id, db)),
                ("CITE_ROLE_TAG", pg_role_tag(site_id, db)),
            ],
        );
        Ok(spec)
    }

    // ---- logins ----

    fn user_spec(
        &self,
        t: &PgTarget,
        site: &Site,
        db: &str,
        user: &PgUser,
        alt: Alt,
        step: UserStep<'_>,
    ) -> Result<JobSpec> {
        let UserStep { action, password } = step;
        let (mode, _) = Self::pg_mode(site)?;
        let mut extra: Vec<(&'static str, String)> = vec![
            ("PGDATABASE", pg_db_name(mode, &site.id, db)),
            ("CITE_ROLE_TAG", pg_role_tag(&site.id, db)),
            ("CITE_USER_ACTION", action.to_string()),
            ("CITE_USER_ROLE", pg_login(&site.id, db, &user.name, alt)),
            ("CITE_USER_LEVEL", user.level.as_str().to_string()),
            ("CITE_USER_CONN_LIMIT", user.connection_limit.to_string()),
            (
                "CITE_USER_STMT_MS",
                user.effective_statement_timeout_ms().to_string(),
            ),
            (
                "CITE_USER_IDLE_MS",
                user.effective_idle_in_transaction_ms().to_string(),
            ),
        ];
        if matches!(action, "create" | "password") {
            let pw = password.ok_or_else(|| {
                ConnectorError::Internal("a password is needed for this action".into())
            })?;
            extra.push(("CITE_USER_PASSWORD", pw.to_string()));
        }
        Ok(self.build_spec(t, JobOp::User, false, extra).1)
    }

    /// One `user` job for one alternate.
    pub(crate) async fn login_action(
        &self,
        site: &Site,
        db: &str,
        user: &PgUser,
        alt: Alt,
        action: &str,
        password: Option<&str>,
    ) -> Result<()> {
        let t = self.pg_target(site).await?;
        let spec = self.user_spec(&t, site, db, user, alt, UserStep { action, password })?;
        let redact = self
            .job_redactions(site, &password.into_iter().collect::<Vec<_>>())
            .await;
        self.run_ok(&format!("user {action}"), spec, &redact)
            .await
            .map(|_| ())
    }

    /// Creates the login with the given password; when the role exists already (adopted data, a retry, a retired
    /// alternate) its password and settings are set instead. The role ends up with LOGIN.
    pub(crate) async fn upsert_login(
        &self,
        site: &Site,
        db: &str,
        user: &PgUser,
        alt: Alt,
        password: &str,
    ) -> Result<()> {
        let t = self.pg_target(site).await?;
        let create = self.user_spec(
            &t,
            site,
            db,
            user,
            alt,
            UserStep {
                action: "create",
                password: Some(password),
            },
        )?;
        let redact = self.job_redactions(site, &[password]).await;
        let out = self.exec(create, &redact).await?;
        if out.exit_code == 0 {
            return Ok(());
        }
        self.login_action(site, db, user, alt, "password", Some(password))
            .await?;
        self.login_action(site, db, user, alt, "settings", None)
            .await
    }

    /// Creates or refreshes the login of the stored password.
    pub(crate) async fn ensure_login(
        &self,
        site: &Site,
        db: &str,
        user: &PgUser,
        alt: Alt,
    ) -> Result<()> {
        let name = cite_edge::datamodel::pg_user_secret_name(&site.id, db, &user.name);
        let mut secret: UserSecret = self.secret_get(&name).await?.ok_or_else(|| {
            ConnectorError::Unavailable(format!(
                "the credentials of {db}/{} are missing",
                user.name
            ))
        })?;
        let pw = secret.password(alt).map(str::to_string).ok_or_else(|| {
            ConnectorError::Unavailable(format!("no password is stored for {db}/{}", user.name))
        })?;
        self.upsert_login(site, db, user, alt, &pw).await?;
        if !secret.exists(alt) {
            secret.mark_created(alt);
            self.secret_put(Some(&site.id), &name, &secret).await?;
        }
        Ok(())
    }

    /// Removes one login. What it owns or was granted inside the database is moved or revoked by a regrant run as
    /// the job login (the superuser never enters the tenant database); the login is switched off first so it
    /// cannot create anything new in between.
    pub(crate) async fn drop_login(
        &self,
        site: &Site,
        db: &str,
        user: &PgUser,
        alt: Alt,
    ) -> Result<()> {
        self.login_action(site, db, user, alt, "disable", None)
            .await?;
        self.regrant_job(site, db, Some(&pg_login(&site.id, db, &user.name, alt)))
            .await?;
        self.login_action(site, db, user, alt, "drop", None).await
    }

    /// Disable or enable every existing login of a user.
    pub(crate) async fn set_login_state(
        &self,
        site: &Site,
        db: &str,
        user: &PgUser,
        action: &str,
    ) -> Result<()> {
        let secret: Option<UserSecret> = self
            .secret_get(&cite_edge::datamodel::pg_user_secret_name(
                &site.id, db, &user.name,
            ))
            .await?;
        let Some(secret) = secret else { return Ok(()) };
        for alt in secret.existing() {
            self.login_action(site, db, user, alt, action, None).await?;
        }
        Ok(())
    }

    // ---- backups: records ----

    pub(crate) async fn begin_backup(
        &self,
        site_id: &str,
        key: &str,
        trigger: BackupTrigger,
        label: Option<String>,
        actor: &str,
    ) -> Result<BackupRecord> {
        if let Some(l) = &label
            && !cite_edge::datawire::is_valid_backup_label(l)
        {
            return Err(ConnectorError::BadRequest(
                "a label has at most 100 characters and no control characters".into(),
            ));
        }
        let (key_s, actor_s) = (key.to_string(), actor.to_string());
        let id = Ulid::generate().to_string();
        self.with_catalog(site_id, move |cat| {
            let version = cat.allocate_version(&key_s).map_err(cat_err)?;
            let rec = BackupRecord {
                id,
                database: key_s.clone(),
                version,
                created_at: now_rfc3339(),
                completed_at: None,
                trigger,
                label,
                pinned: false,
                size_bytes: 0,
                sha256: String::new(),
                server_version: String::new(),
                format: FORMAT.into(),
                encryption: None,
                local: None,
                s3: None,
                status: BackupStatus::Running,
                error: None,
                actor: actor_s,
                source: None,
            };
            cat.insert(&key_s, rec.clone()).map_err(cat_err)?;
            Ok(rec)
        })
        .await
    }

    async fn fail_backup(&self, site_id: &str, key: &str, id: &str, msg: &str) {
        let (key, id, msg) = (key.to_string(), id.to_string(), clip(msg, 1024));
        let res = self
            .with_catalog(site_id, move |cat| {
                if let Some(r) = cat.find_mut(&key, &id) {
                    r.status = BackupStatus::Failed;
                    r.error = Some(msg);
                    r.completed_at = Some(now_rfc3339());
                }
                Ok(())
            })
            .await;
        if let Err(e) = res {
            tracing::warn!(site = %site_id, error = %e, "a failed backup could not be recorded");
        }
    }

    /// The spec of the dump job for a database, the connection facts the redaction needs, and for a managed
    /// database the job login it runs as.
    async fn dump_spec(
        &self,
        site: &Site,
        db: &DbRef,
    ) -> Result<(JobSpec, Vec<String>, Option<(PgTarget, TenantJob)>)> {
        match db {
            DbRef::Pg(name) => {
                let (mode, _) = Self::pg_mode(site)?;
                if !site
                    .data
                    .postgres
                    .as_ref()
                    .is_some_and(|p| p.databases.iter().any(|d| d.name == *name))
                {
                    return Err(ConnectorError::NotFound(format!(
                        "database {name} not found"
                    )));
                }
                let t = self.pg_target(site).await?;
                let tj = TenantJob::new(mode, &site.id, name);
                let (_, spec) = self.build_spec(
                    &t,
                    JobOp::Backup,
                    false,
                    vec![
                        ("PGDATABASE", tj.database.clone()),
                        ("CITE_ROLE_TAG", tj.tag.clone()),
                    ],
                );
                Ok((spec, self.job_redactions(site, &[]).await, Some((t, tj))))
            }
            DbRef::Ext(name) => {
                if !site.data.external_postgres.iter().any(|e| e.name == *name) {
                    return Err(ConnectorError::NotFound(format!(
                        "external database {name} not found"
                    )));
                }
                let secret: super::service::ExtSecret = self
                    .secret_get(&cite_edge::datamodel::external_secret_name(&site.id, name))
                    .await?
                    .ok_or_else(|| {
                        ConnectorError::Unavailable(format!("the URL of {name} is missing"))
                    })?;
                let url = super::env::parse_postgres_url(&secret.url)
                    .map_err(ConnectorError::BadRequest)?;
                let slot = site.active;
                let mode = self.engine.egress_mode();
                if mode == EgressMode::Off {
                    return Err(policy("outbound access is switched off on this node"));
                }
                if !self.engine.node_ports_allow(url.port) {
                    return Err(policy(format!(
                        "the node's CITE_STACK_EGRESS_ALLOW_PORTS does not include {}",
                        url.port
                    )));
                }
                if !self.engine.slot_running(&site.id, slot).await? {
                    return Err(ConnectorError::Conflict(
                        "the active slot is not running; start the site first".into(),
                    ));
                }
                let (net, host, port) = match mode {
                    EgressMode::Filtered => (
                        JobNet::Xnet(slot),
                        format!("cite-{}-{}-egress-proxy", site.id, slot_name(slot)),
                        super::env::forward_port(&site.data, name).ok_or_else(|| {
                            ConnectorError::Conflict(
                                "the external database has no egress forward".into(),
                            )
                        })?,
                    ),
                    _ => (JobNet::Egress(slot), url.host.clone(), url.port),
                };
                let id = new_job_id();
                let mut env: Vec<(String, Zeroizing<String>)> = vec![
                    ("CITE_JOB_ID".into(), Zeroizing::new(id)),
                    ("PGHOST".into(), Zeroizing::new(host)),
                    ("PGPORT".into(), Zeroizing::new(port.to_string())),
                    ("PGUSER".into(), Zeroizing::new(url.user.clone())),
                    (
                        "PGPASSWORD".into(),
                        Zeroizing::new(url.password.to_string()),
                    ),
                    ("PGDATABASE".into(), Zeroizing::new(url.database.clone())),
                ];
                if let Some(s) = &url.sslmode {
                    env.push(("PGSSLMODE".into(), Zeroizing::new(s.clone())));
                }
                let mut redact = self.redactions(site).await;
                redact.push(url.password.to_string());
                let major = PG_MAJORS.iter().copied().max().unwrap_or(18);
                Ok((
                    JobSpec {
                        scope: JobScope::Site(site.id.clone()),
                        op: JobOp::Backup,
                        net,
                        major,
                        env,
                        read_only: false,
                    },
                    redact,
                    None,
                ))
            }
        }
    }

    fn job_id_of(spec: &JobSpec) -> Result<String> {
        spec.env
            .iter()
            .find(|(k, _)| k == "CITE_JOB_ID")
            .map(|(_, v)| v.to_string())
            .ok_or_else(|| ConnectorError::Internal("a job has no id".into()))
    }

    /// Runs the dump of a record `begin_backup` created and seals it. The site lock must be held by the caller.
    pub(crate) async fn complete_backup(
        &self,
        site: &Site,
        rec: &BackupRecord,
    ) -> Result<BackupRecord> {
        let result = self.complete_backup_inner(site, rec).await;
        if let Err(e) = &result {
            let msg = match e {
                ConnectorError::Internal(_) => "internal error; see the connector log".to_string(),
                other => other.to_string(),
            };
            self.fail_backup(&site.id, &rec.database, &rec.id, &msg)
                .await;
        }
        result
    }

    async fn complete_backup_inner(&self, site: &Site, rec: &BackupRecord) -> Result<BackupRecord> {
        let db = DbRef::parse(&rec.database)?;
        let (spec, redact, managed) = self.dump_spec(site, &db).await?;
        let job_id = Self::job_id_of(&spec)?;
        let dirs = self.dirs.clone();
        let sid = site.id.clone();
        tokio::task::spawn_blocking({
            let (dirs, sid) = (dirs.clone(), sid.clone());
            move || dirs.ensure_site(&sid).map_err(cat_err)
        })
        .await
        .map_err(join_err)??;
        let run = match &managed {
            Some((t, tj)) => self.run_tenant_ok("backup", t, tj, spec, &redact).await,
            None => self.run_ok("backup", spec, &redact).await,
        };
        let sealed = match run {
            Ok(_) => {
                let (dirs, keyring, sid, bid, jid) = (
                    dirs.clone(),
                    Arc::clone(&self.keyring),
                    sid.clone(),
                    rec.id.clone(),
                    job_id.clone(),
                );
                tokio::task::spawn_blocking(move || seal_dump(&dirs, &keyring, &sid, &bid, &jid))
                    .await
                    .map_err(join_err)?
            }
            Err(e) => Err(e),
        };
        self.clear_job_files(&sid, &job_id).await;
        let (summary, version) = sealed?;
        let (kid, key, id) = (self.keyring.kid_hex(), rec.database.clone(), rec.id.clone());
        let file = format!("{id}.cbk");
        self.with_catalog(&site.id, move |cat| {
            let r = cat
                .find_mut(&key, &id)
                .ok_or_else(|| ConnectorError::Internal("the backup record vanished".into()))?;
            r.status = BackupStatus::Ok;
            r.completed_at = Some(now_rfc3339());
            r.size_bytes = summary.plaintext_len;
            r.sha256 = summary.sha256;
            r.server_version = version;
            r.encryption = Some(EncryptionInfo {
                scheme: SCHEME.into(),
                kid,
            });
            r.local = Some(LocalCopy {
                file,
                stored_bytes: summary.stored_len,
            });
            Ok(r.clone())
        })
        .await
    }

    pub(crate) async fn clear_job_files(&self, site_id: &str, job_id: &str) {
        let (dirs, sid, jid) = (self.dirs.clone(), site_id.to_string(), job_id.to_string());
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(dir) = dirs.staging_dir(&sid)
                && let Ok(rd) = std::fs::read_dir(&dir)
            {
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().starts_with(&jid) {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        })
        .await;
    }

    // ---- backups: API-level flows ----

    pub(crate) fn check_backup_target(&self, site: &Site, key: &str) -> Result<()> {
        match DbRef::parse(key)? {
            DbRef::Pg(n) => {
                if !site
                    .data
                    .postgres
                    .as_ref()
                    .is_some_and(|p| p.databases.iter().any(|d| d.name == n))
                {
                    return Err(ConnectorError::NotFound(format!("database {n} not found")));
                }
            }
            DbRef::Ext(n) => {
                if !site.data.external_postgres.iter().any(|e| e.name == n) {
                    return Err(ConnectorError::NotFound(format!(
                        "external database {n} not found"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Manual backup: the record exists when this returns; the dump, optional S3 push and prune run as a job.
    pub(crate) async fn start_backup(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        key: &str,
        label: Option<String>,
        push_s3: bool,
    ) -> Result<(String, String)> {
        let site = self.site(site_id)?;
        self.check_backup_target(&site, key)?;
        self.require_job_capacity()?;
        if push_s3 && self.push_target(&site, None).is_err() {
            return Err(ConnectorError::BadRequest(
                "this site's backup policy has no S3 target".into(),
            ));
        }
        let rec = self
            .begin_backup(site_id, key, BackupTrigger::Manual, label, actor)
            .await?;
        let (svc, sid, backup_id) = (Arc::clone(self), site_id.to_string(), rec.id.clone());
        let job = self.spawn_task("backup", Some(site_id), move |ctx| async move {
            svc.backup_task(&ctx, &sid, rec, push_s3).await
        });
        Ok((job, backup_id))
    }

    async fn backup_task(
        &self,
        ctx: &JobCtx,
        site_id: &str,
        rec: BackupRecord,
        push_s3: bool,
    ) -> Result<Value> {
        let key = rec.database.clone();
        {
            let lock = self.site_lock(site_id);
            let _g = lock.lock().await;
            let site = self.site(site_id)?;
            ctx.step("dumping the database");
            self.complete_backup(&site, &rec).await?;
        }
        let mut pushed = false;
        if push_s3 {
            ctx.step("copying to S3");
            self.push_s3(site_id, &key, &rec.id, None).await?;
            pushed = true;
        }
        ctx.step("pruning old versions");
        if let Err(e) = self.prune_site(site_id).await {
            tracing::warn!(site = %site_id, error = %e, "prune after a backup failed");
        }
        Ok(json!({ "backup_id": rec.id, "s3": pushed }))
    }

    /// A scheduled backup: dump, push to S3 when the policy has a target, prune; failures raise an alert.
    pub(crate) async fn run_scheduled_backup(&self, site_id: &str, key: &str) -> Result<()> {
        let outcome = self.scheduled_inner(site_id, key).await;
        if let Err(e) = &outcome {
            let msg = public_error(e);
            self.alerts.notify(Raised::new(
                AlertEvent::BackupFailed,
                Some(site_id),
                format!("Scheduled backup of {key} for {site_id} failed"),
                msg,
            ));
        }
        outcome
    }

    async fn scheduled_inner(&self, site_id: &str, key: &str) -> Result<()> {
        let rec = self
            .begin_backup(site_id, key, BackupTrigger::Scheduled, None, "scheduler")
            .await?;
        {
            let lock = self.site_lock(site_id);
            let _g = lock.lock().await;
            let site = self.site(site_id)?;
            self.complete_backup(&site, &rec).await?;
        }
        let site = self.site(site_id)?;
        if self.push_target(&site, None).is_ok() {
            self.push_s3(site_id, key, &rec.id, None).await?;
        }
        if let Err(e) = self.prune_site(site_id).await {
            tracing::warn!(site = %site_id, error = %e, "prune after a scheduled backup failed");
        }
        Ok(())
    }

    /// The target id a push uses: the request's, else the site's policy.
    pub(crate) fn push_target(&self, site: &Site, requested: Option<&str>) -> Result<String> {
        if let Some(t) = requested {
            return Ok(t.to_string());
        }
        site.data
            .postgres
            .as_ref()
            .and_then(|p| p.backup.s3.as_ref())
            .map(|c| c.target.clone())
            .ok_or_else(|| ConnectorError::BadRequest("no S3 target is configured".into()))
    }

    pub(crate) async fn push_s3(
        &self,
        site_id: &str,
        key: &str,
        backup_id: &str,
        requested: Option<&str>,
    ) -> Result<()> {
        let site = self.site(site_id)?;
        let tid = self.push_target(&site, requested)?;
        let cat = self.read_catalog(site_id).await?;
        let rec = cat
            .find(key, backup_id)
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("backup {backup_id} not found")))?;
        let local = rec.local.clone().ok_or_else(|| {
            ConnectorError::Conflict("the backup has no local copy to push".into())
        })?;
        if rec.status != BackupStatus::Ok {
            return Err(ConnectorError::Conflict(
                "only a finished backup can be pushed".into(),
            ));
        }
        let (client, target) = self.s3_for_target(&tid).await?;
        let object = super::s3::object_key(
            &target.prefix,
            &self.cfg.node_name,
            site_id,
            key,
            rec.version,
            &rec.id,
        );
        let path = self.dirs.backup_file(site_id, &rec.id).map_err(cat_err)?;
        let _permit = Arc::clone(&self.upload_permits)
            .acquire_owned()
            .await
            .map_err(|_| ConnectorError::Internal("the upload semaphore closed".into()))?;
        let put = client
            .upload_file(&object, &path, local.stored_bytes)
            .await
            .map_err(s3e);
        let (k, id) = (key.to_string(), rec.id.clone());
        match put {
            Ok(put) => {
                self.with_catalog(site_id, move |cat| {
                    if let Some(r) = cat.find_mut(&k, &id) {
                        r.s3 = Some(S3CopyInfo {
                            target: tid,
                            key: object,
                            etag: Some(put.etag).filter(|e| !e.is_empty()),
                            version_id: put.version_id,
                            uploaded_at: now_rfc3339(),
                            delete_error: None,
                        });
                    }
                    Ok(())
                })
                .await
            }
            Err(e) => {
                self.alerts.notify(Raised::new(
                    AlertEvent::BackupFailed,
                    Some(site_id),
                    format!("Copying backup {key} of {site_id} to S3 failed"),
                    public_error(&e),
                ));
                Err(e)
            }
        }
    }

    // ---- patch and delete ----

    pub(crate) async fn patch_backup(
        &self,
        site_id: &str,
        key: &str,
        backup_id: &str,
        patch: cite_edge::datawire::BackupPatchReq,
    ) -> Result<BackupRecord> {
        if let Some(Some(l)) = &patch.label
            && !cite_edge::datawire::is_valid_backup_label(l)
        {
            return Err(ConnectorError::BadRequest(
                "a label has at most 100 characters and no control characters".into(),
            ));
        }
        let (k, id) = (key.to_string(), backup_id.to_string());
        self.with_catalog(site_id, move |cat| {
            let r = cat
                .find_mut(&k, &id)
                .ok_or_else(|| ConnectorError::NotFound(format!("backup {id} not found")))?;
            if let Some(l) = patch.label {
                r.label = l;
            }
            if let Some(p) = patch.pinned {
                r.pinned = p;
                if p && let Some(s3) = r.s3.as_mut() {
                    s3.delete_error = None;
                }
            }
            Ok(r.clone())
        })
        .await
    }

    /// Finds the record of a backup id across the site's databases.
    pub(crate) async fn find_backup(&self, site_id: &str, backup_id: &str) -> Result<BackupRecord> {
        let cat = self.read_catalog(site_id).await?;
        cat.databases
            .values()
            .flat_map(|d| d.backups.iter())
            .find(|r| r.id == backup_id)
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("backup {backup_id} not found")))
    }

    pub(crate) async fn delete_backup(
        &self,
        site_id: &str,
        backup_id: &str,
        from: DeleteFrom,
    ) -> Result<()> {
        let rec = self.find_backup(site_id, backup_id).await?;
        if rec.pinned {
            return Err(ConnectorError::Conflict(
                "the backup is pinned; unpin it first".into(),
            ));
        }
        if rec.status == BackupStatus::Running {
            return Err(ConnectorError::Conflict(
                "the backup is still running".into(),
            ));
        }
        let key = rec.database.clone();
        let do_local = matches!(from, DeleteFrom::Local | DeleteFrom::All) && rec.local.is_some();
        let do_s3 = matches!(from, DeleteFrom::S3 | DeleteFrom::All) && rec.s3.is_some();
        if do_s3 && let Some(info) = &rec.s3 {
            let (client, _) = self.s3_for_target(&info.target).await?;
            if let Err(e) = client.delete(&info.key, info.version_id.as_deref()).await {
                let (k, id, msg) = (key.clone(), rec.id.clone(), e.to_string());
                let _ = self
                    .with_catalog(site_id, move |cat| {
                        if let Some(s3) = cat.find_mut(&k, &id).and_then(|r| r.s3.as_mut()) {
                            s3.delete_error = Some(msg);
                        }
                        Ok(())
                    })
                    .await;
                return Err(s3e(e));
            }
        }
        let (k, id) = (key, rec.id.clone());
        self.with_catalog(site_id, move |cat| {
            if let Some(r) = cat.find_mut(&k, &id) {
                if do_local {
                    r.local = None;
                }
                if do_s3 {
                    r.s3 = None;
                }
                if r.local.is_none() && r.s3.is_none() {
                    cat.remove(&k, &id);
                }
            }
            Ok(())
        })
        .await?;
        if do_local {
            self.remove_local_file(site_id, backup_id).await;
        }
        Ok(())
    }

    async fn remove_local_file(&self, site_id: &str, backup_id: &str) {
        if let Ok(path) = self.dirs.backup_file(site_id, backup_id) {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = std::fs::remove_file(&path);
                let mut marker = path.into_os_string();
                marker.push(".hdr.new");
                let _ = std::fs::remove_file(PathBuf::from(marker));
            })
            .await;
        }
    }

    pub(crate) async fn has_pinned_backup(&self, site_id: &str, db: &str) -> Result<bool> {
        let cat = self.read_catalog(site_id).await?;
        Ok(cat
            .get(&pg_key(db))
            .is_some_and(|d| d.backups.iter().any(|r| r.pinned)))
    }

    /// Deletes every managed-database backup of a site; returns (records removed, S3 copies left).
    pub(crate) async fn purge_pg_backups(&self, site_id: &str) -> Result<(u32, u32)> {
        let (removed, left) = self
            .with_catalog(site_id, |cat| {
                let keys: Vec<String> = cat
                    .databases
                    .keys()
                    .filter(|k| k.starts_with("pg:"))
                    .cloned()
                    .collect();
                let mut files = Vec::new();
                let mut s3 = 0u32;
                for k in keys {
                    if let Some(db) = cat.databases.get_mut(&k) {
                        for r in db.backups.drain(..) {
                            if r.local.is_some() {
                                files.push(r.id.clone());
                            }
                            if r.s3.is_some() {
                                s3 += 1;
                            }
                        }
                    }
                }
                Ok((files, s3))
            })
            .await?;
        let n = removed.len() as u32;
        for id in removed {
            self.remove_local_file(site_id, &id).await;
        }
        Ok((n, left))
    }

    // ---- prune ----

    pub(crate) fn policy_of(site: Option<&Site>) -> BackupPolicy {
        site.and_then(|s| s.data.postgres.as_ref())
            .map(|p| p.backup.clone())
            .unwrap_or_default()
    }

    pub(crate) async fn prune_preview(&self, site_id: &str) -> Result<Vec<PrunePreview>> {
        let site = self.deployer.get_site(site_id).ok();
        let policy = Self::policy_of(site.as_ref());
        let cat = self.read_catalog(site_id).await?;
        let now = OffsetDateTime::now_utc();
        Ok(cat
            .databases
            .iter()
            .map(|(key, db)| {
                let (local, s3) = plans(&db.backups, &policy, now);
                PrunePreview {
                    database: key.clone(),
                    local: local.to_view(),
                    s3: s3.map(|p| p.to_view()).unwrap_or_default(),
                }
            })
            .collect())
    }

    /// Applies the retention plan of every database of a site; returns how many copies were deleted.
    pub(crate) async fn prune_site(&self, site_id: &str) -> Result<u32> {
        let site = self.deployer.get_site(site_id).ok();
        let policy = Self::policy_of(site.as_ref());
        let cat = self.read_catalog(site_id).await?;
        let now = OffsetDateTime::now_utc();
        let mut deleted = 0u32;
        for (key, db) in &cat.databases {
            let (local, s3) = plans(&db.backups, &policy, now);
            // S3 copies first: a refused delete keeps the record with its error and is retried at the next prune.
            let mut forced: BTreeSet<String> = db
                .backups
                .iter()
                .filter(|r| !r.pinned && r.s3.as_ref().is_some_and(|c| c.delete_error.is_some()))
                .map(|r| r.id.clone())
                .collect();
            if let Some(p) = &s3 {
                forced.extend(p.delete.iter().cloned());
            }
            let mut s3_done: Vec<String> = Vec::new();
            let mut s3_failed: BTreeMap<String, String> = BTreeMap::new();
            for id in &forced {
                let Some(rec) = db.backups.iter().find(|r| r.id == *id) else {
                    continue;
                };
                let Some(info) = &rec.s3 else { continue };
                let result = match self.s3_for_target(&info.target).await {
                    Ok((client, _)) => client
                        .delete(&info.key, info.version_id.as_deref())
                        .await
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                match result {
                    Ok(()) => s3_done.push(id.clone()),
                    Err(msg) => {
                        s3_failed.insert(id.clone(), msg);
                    }
                }
            }
            let local_ids: BTreeSet<String> = local.delete.iter().cloned().collect();
            let k = key.clone();
            let removed_files = self
                .with_catalog(site_id, move |cat| {
                    let mut files = Vec::new();
                    let mut count = 0u32;
                    if let Some(dbc) = cat.databases.get_mut(&k) {
                        for r in dbc.backups.iter_mut() {
                            // Pinned after the plan was made: keep every copy.
                            if r.pinned {
                                continue;
                            }
                            if local_ids.contains(&r.id) && r.local.is_some() {
                                r.local = None;
                                files.push(r.id.clone());
                                count += 1;
                            }
                            if s3_done.contains(&r.id) {
                                r.s3 = None;
                                count += 1;
                            }
                            if let (Some(msg), Some(s3)) = (s3_failed.get(&r.id), r.s3.as_mut()) {
                                s3.delete_error = Some(msg.clone());
                            }
                        }
                        let stale: Vec<String> =
                            expired_failed(&dbc.backups, OffsetDateTime::now_utc())
                                .into_iter()
                                .chain(without_copies(&dbc.backups))
                                .collect();
                        dbc.backups.retain(|r| !stale.contains(&r.id));
                    }
                    Ok((files, count))
                })
                .await?;
            for id in &removed_files.0 {
                self.remove_local_file(site_id, id).await;
            }
            deleted += removed_files.1;
        }
        Ok(deleted)
    }

    // ---- restore ----

    pub(crate) async fn begin_restore(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        backup_id: &str,
        req: RestoreReq,
    ) -> Result<(String, String)> {
        if req.confirm != site_id {
            return Err(ConnectorError::BadRequest(
                "confirm must equal the site id".into(),
            ));
        }
        let site = self.site(site_id)?;
        let rec = self.find_backup(site_id, backup_id).await?;
        let target = self.check_restore(&site, &rec, req.database.as_deref())?;
        self.require_job_capacity()?;
        let key = format!("pg:{target}");
        let pre = self
            .begin_backup(
                site_id,
                &key,
                BackupTrigger::PreRestore,
                Some(format!("before restoring v{}", rec.version)),
                actor,
            )
            .await?;
        let pre_id = pre.id.clone();
        let (svc, sid) = (Arc::clone(self), site_id.to_string());
        let job = self.spawn_task("restore", Some(site_id), move |ctx| async move {
            svc.restore_task(&ctx, &sid, rec, target, pre).await
        });
        Ok((job, pre_id))
    }

    /// Validates a restore and returns the managed database it targets.
    pub(crate) fn check_restore(
        &self,
        site: &Site,
        rec: &BackupRecord,
        database: Option<&str>,
    ) -> Result<String> {
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        if rec.status != BackupStatus::Ok {
            return Err(ConnectorError::Conflict(
                "only a finished backup can be restored".into(),
            ));
        }
        if rec.local.is_none() && rec.s3.is_none() {
            return Err(ConnectorError::Conflict(
                "the backup has no copy left".into(),
            ));
        }
        // A backup of an external database (`ext:`) may be restored into a managed one, in either mode. The dump is
        // untrusted, but so is everything the site's owner login can already send: pg_restore runs as the job
        // login with --role=<owner group>, in a container that holds no superuser credentials, so the dump can do
        // no more than the tenant's own SQL in its own database.
        let wanted = database.unwrap_or(&rec.database);
        let DbRef::Pg(target) = DbRef::parse(wanted)? else {
            return Err(ConnectorError::BadRequest(
                "a backup can only be restored into a managed database (pg:<name>)".into(),
            ));
        };
        if !pg.databases.iter().any(|d| d.name == target) {
            return Err(ConnectorError::NotFound(format!(
                "database {target} not found"
            )));
        }
        if let Some(major) = server_major(&rec.server_version)
            && major > pg.major
        {
            return Err(ConnectorError::Conflict(format!(
                "the backup comes from Postgres {major}, newer than this database ({})",
                pg.major
            )));
        }
        Ok(target)
    }

    async fn restore_task(
        &self,
        ctx: &JobCtx,
        site_id: &str,
        rec: BackupRecord,
        target: String,
        pre: BackupRecord,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        ctx.step("backing up the current data first");
        self.complete_backup(&site, &pre).await?;
        let (mode, _) = Self::pg_mode(&site)?;
        let job_spec_target = self.pg_target(&site).await?;
        let mut tj = TenantJob::new(mode, site_id, &target);
        tj.lock = true;
        let (job_id, spec) = self.build_spec(
            &job_spec_target,
            JobOp::Restore,
            true,
            vec![
                ("PGDATABASE", tj.database.clone()),
                (
                    "CITE_OWNER_ROLE",
                    pg_group(site_id, &target, PgGroup::Owner),
                ),
                (
                    "CITE_LOGIN_ROLE",
                    pg_group(site_id, &target, PgGroup::Login),
                ),
            ],
        );
        let outcome = async {
            ctx.step("decrypting the backup");
            self.stage_plain_dump(site_id, &rec, &job_id).await?;
            ctx.step("restoring");
            let redact = self.job_redactions(&site, &[]).await;
            self.run_tenant_ok("restore", &job_spec_target, &tj, spec, &redact)
                .await
        }
        .await;
        self.clear_job_files(site_id, &job_id).await;
        outcome?;
        Ok(json!({ "restored": rec.id, "database": target, "pre_restore_backup_id": pre.id }))
    }

    /// Decrypts a backup (local copy, else the S3 copy) into `staging/<site>/<job>.dump` and checks its checksum.
    pub(crate) async fn stage_plain_dump(
        &self,
        site_id: &str,
        rec: &BackupRecord,
        job_id: &str,
    ) -> Result<()> {
        let staging = self.dirs.staging_dir(site_id).map_err(cat_err)?;
        let dump = staging.join(format!("{job_id}.dump"));
        let (src, keyring, temp) = if rec.local.is_some() {
            (
                self.dirs.backup_file(site_id, &rec.id).map_err(cat_err)?,
                (*self.keyring).clone(),
                None,
            )
        } else {
            let tmp = staging.join(format!("{job_id}.cbk"));
            self.fetch_s3(rec, &tmp).await?;
            (tmp.clone(), self.read_keyring().await, Some(tmp))
        };
        let (id, want) = (rec.id.clone(), rec.sha256.clone());
        let dest = dump.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut reader = StreamReader::open(&src, &keyring, &id)?;
            let mut file = new_private_file(&dest)?;
            let sha = reader.copy_to(&mut file)?;
            file.sync_all().map_err(|e| {
                ConnectorError::Internal(format!("cannot flush the staged dump: {e}"))
            })?;
            if !want.is_empty() && sha != want {
                return Err(ConnectorError::Conflict(
                    "the backup does not match its recorded checksum".into(),
                ));
            }
            Ok(())
        })
        .await
        .map_err(join_err)?;
        if let Some(t) = temp {
            let _ = tokio::fs::remove_file(t).await;
        }
        result
    }

    async fn fetch_s3(&self, rec: &BackupRecord, dest: &Path) -> Result<()> {
        let info = rec
            .s3
            .as_ref()
            .ok_or_else(|| ConnectorError::Conflict("the backup has no S3 copy".into()))?;
        let (client, _) = self.s3_for_target(&info.target).await?;
        let _permit = Arc::clone(&self.upload_permits)
            .acquire_owned()
            .await
            .map_err(|_| ConnectorError::Internal("the upload semaphore closed".into()))?;
        let mut stream = client.get_range(&info.key, None).await.map_err(s3e)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dest)
            .await
            .map_err(|e| ConnectorError::Internal(format!("cannot stage the S3 copy: {e}")))?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(s3e)?;
            file.write_all(&chunk)
                .await
                .map_err(|e| ConnectorError::Internal(format!("cannot stage the S3 copy: {e}")))?;
        }
        file.sync_all()
            .await
            .map_err(|e| ConnectorError::Internal(format!("cannot stage the S3 copy: {e}")))?;
        Ok(())
    }

    // ---- download ----

    pub(crate) async fn prepare_download(
        &self,
        site_id: &str,
        backup_id: &str,
    ) -> Result<DownloadPlan> {
        let rec = self.find_backup(site_id, backup_id).await?;
        if rec.status != BackupStatus::Ok {
            return Err(ConnectorError::Conflict(
                "only a finished backup can be downloaded".into(),
            ));
        }
        let (path, keyring, cleanup) = if rec.local.is_some() {
            (
                self.dirs.backup_file(site_id, &rec.id).map_err(cat_err)?,
                (*self.keyring).clone(),
                None,
            )
        } else if rec.s3.is_some() {
            self.dirs.ensure_site(site_id).map_err(cat_err)?;
            let tmp = self
                .dirs
                .staging_dir(site_id)
                .map_err(cat_err)?
                .join(format!("{}.dl.cbk", new_job_id()));
            self.fetch_s3(&rec, &tmp).await?;
            (tmp.clone(), self.read_keyring().await, Some(tmp))
        } else {
            return Err(ConnectorError::Conflict(
                "the backup has no copy left".into(),
            ));
        };
        let (p, k, id) = (path.clone(), keyring.clone(), rec.id.clone());
        let opened = tokio::task::spawn_blocking(move || {
            StreamReader::open(&p, &k, &id).map(|r| r.plaintext_len())
        })
        .await
        .map_err(join_err)?;
        let total = match opened {
            Ok(t) => t,
            Err(e) => {
                if let Some(c) = &cleanup {
                    let _ = tokio::fs::remove_file(c).await;
                }
                return Err(e);
            }
        };
        Ok(DownloadPlan {
            record: rec,
            path,
            keyring,
            cleanup,
            total,
        })
    }

    // ---- keys ----

    pub(crate) async fn retired_keys(&self) -> BTreeMap<String, String> {
        match self
            .secret_get::<BTreeMap<String, String>>(RETIRED_KEYS_SECRET)
            .await
        {
            Ok(Some(m)) => m,
            _ => BTreeMap::new(),
        }
    }

    /// The node keyring plus keys that S3 copies sealed before a rotation still need.
    pub(crate) async fn read_keyring(&self) -> crate::seal::Keyring {
        let extra: Vec<NodeKey> = self
            .retired_keys()
            .await
            .values()
            .filter_map(|t| NodeKey::parse(t).ok())
            .collect();
        self.keyring.with_extra(extra)
    }

    /// Kids (other than the primary) of keys that S3 copies were sealed with.
    async fn s3_kids(&self) -> Result<BTreeSet<String>> {
        let primary = self.keyring.kid_hex();
        let mut kids = BTreeSet::new();
        for site in self.dirs.sites() {
            let cat = self.read_catalog(&site).await?;
            for r in cat.databases.values().flat_map(|d| d.backups.iter()) {
                if r.s3.is_some()
                    && let Some(e) = &r.encryption
                    && e.kid != primary
                {
                    kids.insert(e.kid.clone());
                }
            }
        }
        Ok(kids)
    }

    /// With an older key present: re-wrap every local backup header to the primary key, keep the keys S3 copies
    /// still need, then let the keyring drop the previous key. Afterwards, drop retired keys nothing references.
    pub(crate) async fn finish_key_rotation(&self) -> Result<()> {
        let referenced = self.s3_kids().await?;
        let mut retired = self.retired_keys().await;
        let before = retired.clone();
        if self.keyring.has_older() {
            for site in self.dirs.sites() {
                let cat = self.read_catalog(&site).await?;
                for r in cat.databases.values().flat_map(|d| d.backups.iter()) {
                    if r.local.is_none() {
                        continue;
                    }
                    let path = self.dirs.backup_file(&site, &r.id).map_err(cat_err)?;
                    if !path.exists() {
                        continue;
                    }
                    let (kr, id) = (Arc::clone(&self.keyring), r.id.clone());
                    tokio::task::spawn_blocking(move || rewrap_header(&path, &kr, &id))
                        .await
                        .map_err(join_err)??;
                }
            }
            if let Some(text) = &self.cfg.previous_key {
                let key = NodeKey::parse(text)?;
                let kid = key.kid_hex();
                if referenced.contains(&kid) {
                    retired.insert(kid, key.text().to_string());
                }
            }
            if retired != before {
                self.secret_put(None, RETIRED_KEYS_SECRET, &retired).await?;
            }
            self.keyring.finish_rotation()?;
        }
        retired.retain(|kid, _| referenced.contains(kid));
        if retired != before {
            if retired.is_empty() {
                self.secret_del(None, RETIRED_KEYS_SECRET).await;
            } else {
                self.secret_put(None, RETIRED_KEYS_SECRET, &retired).await?;
            }
        }
        Ok(())
    }
}

fn slot_name(slot: cite_edge::model::Slot) -> &'static str {
    match slot {
        cite_edge::model::Slot::Blue => "blue",
        cite_edge::model::Slot::Green => "green",
    }
}

fn clip(s: &str, max: usize) -> String {
    s[..floor_boundary(s, max)].to_string()
}

/// Local and S3 plans of one database's records.
pub(crate) fn plans(
    records: &[BackupRecord],
    policy: &BackupPolicy,
    now: OffsetDateTime,
) -> (PrunePlan, Option<PrunePlan>) {
    let local = plan_prune(records, Tier::Local, &policy.local, now);
    let s3 = policy
        .s3
        .as_ref()
        .map(|c| plan_prune(records, Tier::S3, &c.retention, now));
    (local, s3)
}

fn new_private_file(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| ConnectorError::Internal(format!("cannot create {}: {e}", path.display())))
}

/// Encrypts `staging/<site>/<job>.dump` into `sites/<site>/<backup>.cbk` and reads the server version the job wrote.
fn seal_dump(
    dirs: &super::catalog::BackupDirs,
    keyring: &crate::seal::Keyring,
    site: &str,
    backup_id: &str,
    job_id: &str,
) -> Result<(super::stream::StreamSummary, String)> {
    let staging = dirs.staging_dir(site).map_err(cat_err)?;
    let dump = staging.join(format!("{job_id}.dump"));
    let version_path = staging.join(format!("{job_id}.version"));
    let version = std::fs::read_to_string(&version_path)
        .map_err(|_| ConnectorError::Unavailable("the dump job left no server version".into()))?;
    let version = version.trim().to_string();
    if version.is_empty() || version.len() > 64 || version.chars().any(char::is_control) {
        return Err(ConnectorError::Unavailable(
            "the dump job reported an invalid server version".into(),
        ));
    }
    let partial = dirs.partial_file(site, backup_id).map_err(cat_err)?;
    let target = dirs.backup_file(site, backup_id).map_err(cat_err)?;
    let result = (|| -> Result<super::stream::StreamSummary> {
        let mut writer = StreamWriter::create(&partial, keyring, backup_id)?;
        let mut input = std::fs::File::open(&dump)
            .map_err(|_| ConnectorError::Unavailable("the dump job left no dump".into()))?;
        let mut buf = vec![0u8; COPY_STEP];
        loop {
            let n = input
                .read(&mut buf)
                .map_err(|e| ConnectorError::Internal(format!("cannot read the dump: {e}")))?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
        }
        let summary = writer.finish()?;
        std::fs::rename(&partial, &target).map_err(|e| {
            ConnectorError::Internal(format!("cannot move the backup into place: {e}"))
        })?;
        if let Some(dir) = target.parent()
            && let Ok(d) = std::fs::File::open(dir)
        {
            let _ = d.sync_all();
        }
        Ok(summary)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    Ok((result?, version))
}

// ---- download streaming ----

pub(crate) struct DownloadPlan {
    pub record: BackupRecord,
    pub path: PathBuf,
    pub keyring: crate::seal::Keyring,
    /// A temporary file (an S3 copy fetched for this download) to delete when the stream ends.
    pub cleanup: Option<PathBuf>,
    pub total: u64,
}

/// Streams plaintext bytes `first..=last` of a backup. A whole-file read is hashed and checked against the record
/// at the end; any failure becomes an error item that aborts the body.
pub(crate) fn stream_plaintext(
    plan: DownloadPlan,
    first: u64,
    last: u64,
    permit: OwnedSemaphorePermit,
) -> mpsc::Receiver<io::Result<Bytes>> {
    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(DOWNLOAD_CHANNEL);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let whole = first == 0 && last + 1 == plan.total;
        let outcome = (|| -> std::result::Result<(), String> {
            let mut reader = StreamReader::open(&plan.path, &plan.keyring, &plan.record.id)
                .map_err(|e| e.to_string())?;
            let mut hasher = Sha256::new();
            let mut offset = first;
            let mut buf = Vec::new();
            while offset <= last && plan.total > 0 {
                let n = DOWNLOAD_STEP.min(last + 1 - offset);
                buf.clear();
                reader
                    .read_range(offset, n, &mut buf)
                    .map_err(|e| e.to_string())?;
                if buf.is_empty() {
                    return Err("the backup ended early".into());
                }
                if whole {
                    hasher.update(&buf);
                }
                offset += buf.len() as u64;
                if tx.blocking_send(Ok(Bytes::copy_from_slice(&buf))).is_err() {
                    return Ok(());
                }
            }
            if whole
                && !plan.record.sha256.is_empty()
                && hex(&hasher.finalize()) != plan.record.sha256
            {
                return Err("the backup does not match its recorded checksum".into());
            }
            Ok(())
        })();
        if let Err(msg) = outcome {
            tracing::error!(backup = %plan.record.id, error = %msg, "backup download failed");
            let _ = tx.blocking_send(Err(io::Error::other("the backup could not be read")));
        }
        if let Some(c) = &plan.cleanup {
            let _ = std::fs::remove_file(c);
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_keys_parse_and_round_trip() {
        assert_eq!(DbRef::parse("pg:app").unwrap(), DbRef::Pg("app".into()));
        assert_eq!(DbRef::parse("ext:billing").unwrap().key(), "ext:billing");
        for bad in ["", "app", "pg:", "x:app", "pg"] {
            assert!(DbRef::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_tenant_job_names_its_database_and_connects_as_its_job_login() {
        let tj = TenantJob::new(PgMode::Shared, "shop", "app");
        let tag = pg_role_tag("shop", "app");
        assert_eq!(tj.tag, tag);
        assert_eq!(
            tj.database, tag,
            "the shared instance names the database like its tag"
        );
        assert!(!tj.lock && !tj.shared_scope);
        assert_eq!(
            TenantJob::new(PgMode::Dedicated, "shop", "app").database,
            "app"
        );

        let mut spec = JobSpec {
            scope: JobScope::Site("shop".into()),
            op: JobOp::Counts,
            net: JobNet::SharedAdmin,
            major: 18,
            env: vec![
                ("PGUSER".into(), Zeroizing::new("postgres".into())),
                (
                    "PGPASSWORD".into(),
                    Zeroizing::new("superuser-password".into()),
                ),
                ("PGDATABASE".into(), Zeroizing::new(tag.clone())),
            ],
            read_only: false,
        };
        use_job_login(&mut spec, &tag, "job-password");
        let env: Vec<(String, String)> = spec
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        assert_eq!(
            env,
            [
                ("PGUSER".to_string(), format!("{tag}_job")),
                ("PGPASSWORD".to_string(), "job-password".to_string()),
                ("PGDATABASE".to_string(), tag.clone()),
            ]
        );
    }

    #[test]
    fn server_major_reads_the_leading_number() {
        assert_eq!(server_major("18.1"), Some(18));
        assert_eq!(server_major("16.4 (Debian 16.4-1)"), Some(16));
        assert_eq!(server_major("junk"), None);
    }

    #[test]
    fn job_failures_quote_the_tail_without_overflowing() {
        let out = JobOutcome {
            exit_code: 3,
            log_tail: (0..20)
                .map(|i| format!("line {i} {}", "x".repeat(200)))
                .collect(),
        };
        let text = job_failure("restore", &out);
        assert!(text.starts_with("the restore job failed (exit 3): "));
        assert!(text.len() < 480, "{}", text.len());
    }
}
