//! Containers, volumes and networks of the site data services: the per-site Postgres (dedicated), the node-wide
//! shared instance, one-shot job containers and the database networks. The Docker proxy rebuilds every body
//! below and compares it exactly (`cite-dockerproxy/src/spec_data.rs`), so the shapes here must not drift from it.
//!
//! Nothing in this module runs SQL; the data service drives it through jobs. No secret is ever put in a label,
//! a log line or an error message.

use std::time::Duration;

use cite_edge::model::{ManagedPostgres, PgMode, db_container_name, db_volume_name, dbjob_name};
use cite_edge::validate::PG_MAJORS;
use tokio::time::{Instant, sleep};

use super::*;
use crate::data::shared::SharedSettings;

pub use cite_edge::model::{SHARED_ADMIN, SHARED_CONF, SHARED_DATA, SHARED_DB, SHARED_JOB};

/// Image repository name under the registry; mirrors `images/images.toml` and the proxy's pattern.
pub const POSTGRES_IMAGE: &str = "cite-postgres";
pub const PG_PORT: u16 = 5432;
/// How long a deploy or a job waits for a database to report healthy.
pub const DB_READY_TIMEOUT: Duration = Duration::from_secs(120);
/// The compose volume `CITE_DATA_BACKUP_VOLUME` defaults to.
pub const DEFAULT_BACKUP_VOLUME: &str = "cite-backups";

// A dedicated database gets one CPU unless the node maximum is lower; its memory is the site's `memory_mb`.
const DB_NANO_CPUS: i64 = 1_000_000_000;
const PG_SHM: i64 = 256 * MIB;
const PG_PIDS: i64 = 512;
const JOB_MEMORY: i64 = 512 * MIB;
const JOB_NANO_CPUS: i64 = 1_000_000_000;
const JOB_PIDS: i64 = 64;
// Docker's ContainerWait is capped at 300 s by the proxy, so jobs are polled instead.
const JOB_POLL: Duration = Duration::from_secs(2);
const DB_POLL: Duration = Duration::from_secs(1);
const JOB_LOG_TAIL: u32 = 200;
const JOB_LOG_KEEP: usize = 50;
const HEALTH_LOG_LINES: u32 = 20;
const RESTART_GRACE: &str = "10";

/// Names of one site's dedicated-database objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataNames {
    pub id: String,
    pub db: String,
    pub db_volume: String,
    pub dbnet: String,
    pub job: String,
}

impl DataNames {
    pub fn new(id: &str) -> Result<DataNames> {
        if !is_valid_id(id) {
            return Err(ConnectorError::BadRequest(format!(
                "site id {id:?} is not a valid slug"
            )));
        }
        Ok(DataNames {
            id: id.to_string(),
            db: db_container_name(id),
            db_volume: db_volume_name(id),
            dbnet: dbnet_name(id),
            job: dbjob_name(id),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobScope {
    /// Runs in `cite-<id>-dbjob` against that site's database (dedicated or its tenant database).
    Site(String),
    /// Runs in `cite-pg-shared-job` for instance-wide work.
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobNet {
    /// The site's own database network (dedicated server).
    Dbnet,
    SharedAdmin,
    /// The slot's filtered outbound network (backups of external databases through a forward).
    Xnet(Slot),
    /// The slot's open outbound bridge (backups of external databases in open mode).
    Egress(Slot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOp {
    Backup,
    Restore,
    Counts,
    /// Opens or closes the job login of one tenant database (superuser, maintenance database).
    JobLogin,
    Freeze,
    Unfreeze,
    Provision,
    Deprovision,
    Regrant,
    User,
    Hba,
    Sizes,
    Globals,
}

impl JobOp {
    /// The single `Cmd` argument of `cite-pg-job`.
    pub fn arg(self) -> &'static str {
        match self {
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

    // Instance-wide operations run only in the shared job container.
    fn site_scope(self) -> bool {
        !matches!(self, JobOp::Hba | JobOp::Sizes | JobOp::Globals)
    }

    fn shared_scope(self) -> bool {
        matches!(
            self,
            JobOp::Backup
                | JobOp::JobLogin
                | JobOp::Provision
                | JobOp::Deprovision
                | JobOp::User
                | JobOp::Hba
                | JobOp::Sizes
                | JobOp::Globals
        )
    }

    /// Work inside a tenant database: it runs as the database's job login, never as the superuser.
    pub fn runs_as_job_login(self) -> bool {
        matches!(
            self,
            JobOp::Backup | JobOp::Restore | JobOp::Counts | JobOp::Regrant
        )
    }
}

static NETWORKS_CHANGED: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

/// Signalled when a database network or the shared instance is created or recreated, so the data service checks
/// the shared instance's `pg_hba.conf` against the current subnets. A node runs one orchestrator; a wake-up with
/// nothing changed only costs a comparison.
pub fn networks_changed() -> &'static tokio::sync::Notify {
    &NETWORKS_CHANGED
}

/// `<tag>_job`, the login a job inside the tenant database `<tag>` connects as.
pub fn job_login_role(tag: &str) -> String {
    format!("{tag}_job")
}

/// One job container: its scope, the operation, the network it joins and its `KEY=value` env.
#[derive(Clone)]
pub struct JobSpec {
    pub scope: JobScope,
    pub op: JobOp,
    pub net: JobNet,
    /// The Postgres major of the job image (the server's, so `pg_dump` matches it).
    pub major: u8,
    pub env: Vec<(String, Zeroizing<String>)>,
    /// Must be true exactly for `restore`: the staging mount is read-only only there.
    pub read_only: bool,
}

// The env carries passwords, so only its keys are printed.
impl std::fmt::Debug for JobSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobSpec")
            .field("scope", &self.scope)
            .field("op", &self.op)
            .field("net", &self.net)
            .field("major", &self.major)
            .field(
                "env",
                &self.env.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            )
            .field("read_only", &self.read_only)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobOutcome {
    pub exit_code: i64,
    /// The last lines of the job's output, redacted; at most 50.
    pub log_tail: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbHealth {
    /// `running`, `exited`, `restarting`, `created` or `missing`.
    pub state: String,
    /// `healthy`, `unhealthy`, `starting` or `none`.
    pub health: String,
    pub started_at: Option<String>,
    pub image: String,
}

/// The create bodies of every data object of one site, for checking against the proxy's policy.
#[derive(Debug, Clone)]
pub struct DataSpecSet {
    pub names: DataNames,
    pub image: String,
    pub db: Value,
    pub db_volume: Value,
    pub dbnet: Value,
    pub shared_image: String,
    pub shared_db: Value,
    pub shared_data_volume: Value,
    pub shared_conf_volume: Value,
    pub shared_admin: Value,
    /// (container name, body) of each requested job.
    pub jobs: Vec<(String, Value)>,
}

/// `<registry>/cite-postgres:<version>-pg<major>`
pub fn postgres_image(registry: &str, version: &str, major: u8) -> Result<String> {
    if !PG_MAJORS.contains(&major) {
        return Err(ConnectorError::BadRequest(format!(
            "postgres major {major} is not supported"
        )));
    }
    Ok(format!("{registry}/{POSTGRES_IMAGE}:{version}-pg{major}"))
}

fn site_labels(id: &str, role: &str) -> Value {
    json!({ "cite.managed": "true", "cite.site": id, "cite.role": role })
}

fn shared_labels(role: &str) -> Value {
    json!({ "cite.managed": "true", "cite.role": role })
}

/// Labels of `cite-<id>-db-data`.
pub fn db_volume_labels(id: &str) -> Value {
    json!({ "cite.managed": "true", "cite.site": id, "cite.volume": "db-data" })
}

fn shared_volume_labels(volume: &str) -> Value {
    json!({ "cite.managed": "true", "cite.volume": volume })
}

/// Create body of a data volume: exactly name and labels.
pub fn volume_body(name: &str, labels: Value) -> Value {
    json!({ "Name": name, "Labels": labels })
}

/// Create body of a data network: always internal, so it has no gateway and no route out.
pub fn network_body(name: &str, labels: Value) -> Value {
    json!({ "Name": name, "Driver": "bridge", "Internal": true, "Labels": labels })
}

fn generated_password(pw: &str) -> bool {
    pw.len() == 43
        && pw
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

// The exact server body the proxy expects (`spec_data.rs:expected_db`), for either mode.
#[allow(clippy::too_many_arguments)]
fn server_body(
    network: &str,
    data_volume: &str,
    labels: Value,
    image: &str,
    max_connections: u32,
    memory: i64,
    nano_cpus: i64,
    su_pw: &str,
    shared: bool,
) -> Value {
    let mut cmd = vec![
        "postgres".to_string(),
        "-c".into(),
        "listen_addresses=*".into(),
        "-c".into(),
        format!("max_connections={max_connections}"),
        "-c".into(),
        "password_encryption=scram-sha-256".into(),
        "-c".into(),
        "log_connections=on".into(),
        "-c".into(),
        "log_disconnections=on".into(),
        "-c".into(),
        "idle_in_transaction_session_timeout=300000".into(),
    ];
    let mut mounts = vec![volume_mount(
        data_volume,
        "/var/lib/postgresql/data",
        None,
        false,
    )];
    if shared {
        cmd.extend(["-c".to_string(), "hba_file=/etc/cite-pg/pg_hba.conf".into()]);
        mounts.push(volume_mount(SHARED_CONF, "/etc/cite-pg", None, true));
    }
    json!({
        "Image": image,
        "User": "70:70",
        "Env": [
            "POSTGRES_USER=postgres",
            format!("POSTGRES_PASSWORD={su_pw}"),
            "POSTGRES_DB=postgres",
            "PGDATA=/var/lib/postgresql/data/pgdata",
            "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer",
        ],
        "Cmd": cmd,
        "Labels": labels,
        "Healthcheck": {
            "Test": ["CMD", "pg_isready", "-q", "-h", "127.0.0.1", "-p", "5432"],
            "Interval": 10_000_000_000u64,
            "Timeout": 5_000_000_000u64,
            "Retries": 6,
            "StartPeriod": 120_000_000_000u64,
            "StartInterval": 1_000_000_000u64,
        },
        "HostConfig": {
            "Init": true,
            "ReadonlyRootfs": true,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["ALL"],
            "Tmpfs": {
                "/tmp": "size=64m,mode=1777,noexec,nosuid,nodev",
                "/var/run/postgresql": "size=1m,uid=70,gid=70,mode=0775,noexec,nosuid,nodev",
            },
            "ShmSize": PG_SHM,
            "Mounts": mounts,
            "NetworkMode": network,
            "Memory": memory,
            "MemorySwap": memory,
            "NanoCpus": nano_cpus,
            "PidsLimit": PG_PIDS,
            "RestartPolicy": { "Name": "unless-stopped" },
            "LogConfig": log_config(),
        },
        "NetworkingConfig": { "EndpointsConfig": { network: {} } },
    })
}

/// Create body of a site's dedicated server. `limits` is (memory bytes, nano CPUs).
pub fn db_spec(
    n: &DataNames,
    image: &str,
    pg: &ManagedPostgres,
    limits: (i64, i64),
    su_pw: &str,
) -> Value {
    server_body(
        &n.dbnet,
        &n.db_volume,
        site_labels(&n.id, "db"),
        image,
        pg.max_connections,
        limits.0,
        limits.1,
        su_pw,
        false,
    )
}

/// Create body of the node-wide shared server.
pub fn shared_db_spec(image: &str, cfg: &SharedSettings, su_pw: &str) -> Value {
    server_body(
        SHARED_ADMIN,
        SHARED_DATA,
        shared_labels("pg-shared"),
        image,
        cfg.max_connections,
        i64::from(cfg.memory_mb) * MIB,
        cfg.nano_cpus,
        su_pw,
        true,
    )
}

/// Container name of a job: one per scope at a time.
pub fn job_container(scope: &JobScope) -> String {
    match scope {
        JobScope::Site(id) => dbjob_name(id),
        JobScope::Shared => SHARED_JOB.to_string(),
    }
}

// A shared-scope job can only sit on the admin network; anything else falls back to it (and run_job refuses first).
fn job_network(scope: &JobScope, net: JobNet) -> String {
    match (scope, net) {
        (JobScope::Site(id), JobNet::Dbnet) => dbnet_name(id),
        (JobScope::Site(id), JobNet::Xnet(slot)) => format!("cite-{id}-{}-xnet", slot.as_str()),
        (JobScope::Site(id), JobNet::Egress(slot)) => {
            format!("cite-{id}-{}-egress", slot.as_str())
        }
        (_, JobNet::SharedAdmin) | (JobScope::Shared, _) => SHARED_ADMIN.to_string(),
    }
}

/// Create body of a job container, exactly as the proxy rebuilds it (`spec_data.rs:validate_job`).
pub fn job_spec(job: &JobSpec, backup_volume: &str, image: &str) -> Value {
    let (labels, subpath) = match &job.scope {
        JobScope::Site(id) => (site_labels(id, "dbjob"), format!("staging/{id}")),
        JobScope::Shared => (
            shared_labels("pg-shared-job"),
            "staging/_shared".to_string(),
        ),
    };
    let network = job_network(&job.scope, job.net);
    let mut mounts = vec![volume_mount(
        backup_volume,
        "/backup",
        Some(subpath.as_str()),
        job.op == JobOp::Restore,
    )];
    if job.op == JobOp::Hba {
        mounts.push(volume_mount(SHARED_CONF, "/conf", None, false));
    }
    let env: Vec<String> = job
        .env
        .iter()
        .map(|(key, value)| format!("{key}={}", value.as_str()))
        .collect();
    json!({
        "Image": image,
        "User": "10001:10001",
        "Entrypoint": ["cite-pg-job"],
        "Cmd": [job.op.arg()],
        "Env": env,
        "Labels": labels,
        "Healthcheck": { "Test": ["NONE"] },
        "HostConfig": {
            "ReadonlyRootfs": true,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["ALL"],
            "Tmpfs": { "/tmp": "size=64m,mode=1777,noexec,nosuid,nodev" },
            "Mounts": mounts,
            "NetworkMode": network,
            "Memory": JOB_MEMORY,
            "MemorySwap": JOB_MEMORY,
            "NanoCpus": JOB_NANO_CPUS,
            "PidsLimit": JOB_PIDS,
            "RestartPolicy": { "Name": "no" },
            "LogConfig": log_config(),
        },
        "NetworkingConfig": { "EndpointsConfig": { network: {} } },
    })
}

/// Everything the proxy would be asked to create for a site's data services, for the proxy's own tests.
pub fn data_specs(
    site: &Site,
    env: &StackEnv<'_>,
    backup_volume: &str,
    su_pw: &str,
    shared: &SharedSettings,
    jobs: &[JobSpec],
) -> Result<DataSpecSet> {
    let pg = site.data.postgres.as_ref().ok_or_else(|| {
        ConnectorError::BadRequest(format!("site {} has no managed postgres", site.id))
    })?;
    let names = DataNames::new(&site.id)?;
    let image = postgres_image(env.registry, env.version, pg.major)?;
    let shared_image = postgres_image(env.registry, env.version, shared.major)?;
    let limits = (i64::from(pg.memory_mb) * MIB, DB_NANO_CPUS);
    let mut bodies = Vec::new();
    for job in jobs {
        let major = job.major;
        let job_image = postgres_image(env.registry, env.version, major)?;
        bodies.push((
            job_container(&job.scope),
            job_spec(job, backup_volume, &job_image),
        ));
    }
    Ok(DataSpecSet {
        db: db_spec(&names, &image, pg, limits, su_pw),
        db_volume: volume_body(&names.db_volume, db_volume_labels(&site.id)),
        dbnet: network_body(&names.dbnet, site_labels(&site.id, "dbnet")),
        shared_db: shared_db_spec(&shared_image, shared, su_pw),
        shared_data_volume: volume_body(SHARED_DATA, shared_volume_labels("pg-shared-data")),
        shared_conf_volume: volume_body(SHARED_CONF, shared_volume_labels("pg-shared-conf")),
        shared_admin: network_body(SHARED_ADMIN, shared_labels("pg-shared-admin")),
        jobs: bodies,
        names,
        image,
        shared_image,
    })
}

// The name of a database server container this module may restart or inspect.
fn check_server_name(name: &str) -> Result<()> {
    let site = name
        .strip_prefix("cite-")
        .and_then(|rest| rest.strip_suffix("-db"))
        .is_some_and(is_valid_id);
    if name == SHARED_DB || site {
        Ok(())
    } else {
        Err(ConnectorError::BadRequest(format!(
            "{name:?} is not a database container"
        )))
    }
}

// `t<10 hex>_<db>` with a lowercase `[a-z][a-z0-9]{0,15}` database part, as the proxy requires.
fn is_tenant_database(name: &str) -> bool {
    let Some((tag, db)) = name.strip_prefix('t').and_then(|r| r.split_once('_')) else {
        return false;
    };
    tag.len() == 10
        && tag.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && (1..=16).contains(&db.len())
        && db.as_bytes()[0].is_ascii_lowercase()
        && db
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

// Mirrors what the proxy refuses, so a bad job fails here with a precise reason instead of a 403.
fn check_job(job: &JobSpec) -> Result<()> {
    let bad = |why: &str| ConnectorError::BadRequest(format!("data job {}: {why}", job.op.arg()));
    if !PG_MAJORS.contains(&job.major) {
        return Err(bad("the postgres major is not supported"));
    }
    if job.read_only != (job.op == JobOp::Restore) {
        return Err(bad("only a restore mounts its staging directory read-only"));
    }
    match &job.scope {
        JobScope::Site(id) => {
            if !is_valid_id(id) {
                return Err(bad("the site id is not valid"));
            }
            if !job.op.site_scope() {
                return Err(bad("this operation runs only in the shared job container"));
            }
            let outbound = matches!(job.net, JobNet::Xnet(_) | JobNet::Egress(_));
            if outbound && job.op != JobOp::Backup {
                return Err(bad("only a backup may use an outbound network"));
            }
        }
        JobScope::Shared => {
            if !job.op.shared_scope() {
                return Err(bad(
                    "this operation does not run in the shared job container",
                ));
            }
            if job.net != JobNet::SharedAdmin {
                return Err(bad("the shared job runs on the admin network only"));
            }
            // The instance backup dumps one tenant database (`t<tag>_<db>`), never a system one.
            if job.op == JobOp::Backup {
                let tenant = job
                    .env
                    .iter()
                    .find(|(key, _)| key == "PGDATABASE")
                    .is_some_and(|(_, db)| is_tenant_database(db));
                if !tenant {
                    return Err(bad("the shared backup must name a tenant database"));
                }
            }
        }
    }
    let mut seen: Vec<&str> = Vec::new();
    for (key, value) in &job.env {
        let key_ok = !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !key_ok {
            return Err(bad("an env key is not valid"));
        }
        if value.contains(['\0', '\n', '\r']) {
            return Err(bad("an env value contains a control character"));
        }
        if seen.contains(&key.as_str()) {
            return Err(bad("an env key is repeated"));
        }
        seen.push(key);
    }
    // On the node's own servers the login is fixed by the operation (the proxy compares it exactly).
    let internal = matches!(job.net, JobNet::Dbnet | JobNet::SharedAdmin);
    let value = |name: &str| {
        job.env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, v)| v.as_str())
    };
    if internal && let Some(user) = value("PGUSER") {
        if job.op.runs_as_job_login() {
            let tag = value("CITE_ROLE_TAG").map(str::to_string).or_else(|| {
                value("CITE_OWNER_ROLE")
                    .and_then(|o| o.strip_suffix("_owner"))
                    .map(str::to_string)
            });
            if tag.map(|t| job_login_role(&t)).as_deref() != Some(user) {
                return Err(bad(
                    "work inside a tenant database runs as that database's job login",
                ));
            }
        } else if user != "postgres" {
            return Err(bad("this operation runs as the superuser"));
        }
    }
    Ok(())
}

// The stored configuration of a database server, other than the networks it sits on.
fn server_matches(have: &Inspected, spec: &Value, networks: bool) -> bool {
    let cmd_ok = match (&have.cmd, spec["Cmd"].as_array()) {
        (Some(have), Some(want)) => {
            have.iter().map(String::as_str).collect::<Vec<_>>()
                == want.iter().filter_map(Value::as_str).collect::<Vec<_>>()
        }
        _ => true,
    };
    cmd_ok
        && if networks {
            have.matches(spec)
        } else {
            have.same_config(spec)
        }
}

fn not_ready(site_id: &str, why: impl std::fmt::Display) -> ConnectorError {
    ConnectorError::Unavailable(format!(
        "the database of {site_id} is not ready: {why}; the running slot was not changed"
    ))
}

impl Orchestrator {
    // The deploy hook: brings the site's database up and healthy before any container of the slot changes.
    pub(super) async fn prepare_database(&self, site: &Site, opts: &StackOpts) -> Result<()> {
        let Some(pg) = site.data.postgres.as_ref() else {
            return Ok(());
        };
        // A tenant of the shared instance has no per-site superuser; the instance's own is the service's business.
        let password = match pg.mode {
            PgMode::Dedicated => match opts.db_password.as_ref() {
                Some(pw) => pw.as_str(),
                None => {
                    return Err(not_ready(
                        &site.id,
                        "no database password was supplied for the deploy",
                    ));
                }
            },
            PgMode::Shared => "",
        };
        self.ensure_site_database(site, password)
            .await
            .map_err(|e| not_ready(&site.id, e))
    }

    fn pg_image(&self, major: u8) -> Result<String> {
        postgres_image(&self.registry, &self.stack_version, major)
    }

    /// Dedicated mode: image, volume, network and container (recreated on drift), then waits until healthy.
    /// Shared mode: the site's network, the shared instance attached to it, then waits for the instance.
    /// A site without managed Postgres is a no-op. `su_pw` is unused in shared mode.
    pub async fn ensure_site_database(&self, site: &Site, su_pw: &str) -> Result<()> {
        let Some(pg) = site.data.postgres.as_ref() else {
            return Ok(());
        };
        let n = DataNames::new(&site.id)?;
        match pg.mode {
            PgMode::Shared => {
                self.create_data_network(&n.dbnet, site_labels(&n.id, "dbnet"))
                    .await?;
                self.connect_shared(&n.id).await?;
                self.wait_healthy(SHARED_DB, &[]).await
            }
            PgMode::Dedicated => {
                if !generated_password(su_pw) {
                    return Err(ConnectorError::Internal(format!(
                        "the stored database superuser password of {} is malformed",
                        n.id
                    )));
                }
                let image = self.pg_image(pg.major)?;
                self.ensure_image(&image).await?;
                self.create_data_volume(&n.db_volume, db_volume_labels(&n.id))
                    .await?;
                self.create_data_network(&n.dbnet, site_labels(&n.id, "dbnet"))
                    .await?;
                let limits = (
                    self.limits.clamp_memory(i64::from(pg.memory_mb) * MIB),
                    self.limits.clamp_cpus(DB_NANO_CPUS),
                );
                let spec = db_spec(&n, &image, pg, limits, su_pw);
                let existing = self.inspect_owned(&n.db).await?;
                let current = existing
                    .as_ref()
                    .is_some_and(|c| server_matches(c, &spec, true));
                self.converge(&n.db, &spec, existing, current).await?;
                self.wait_healthy(&n.db, &[su_pw.to_string()]).await
            }
        }
    }

    /// Creates the shared instance's volumes, admin network and container (recreated on drift) and waits until
    /// healthy. A recreated container loses its tenant networks: call `connect_shared` for every tenant after.
    pub async fn ensure_shared_instance(&self, cfg: &SharedSettings, su_pw: &str) -> Result<()> {
        if !generated_password(su_pw) {
            return Err(ConnectorError::Internal(
                "the stored shared database superuser password is malformed".to_string(),
            ));
        }
        let image = self.pg_image(cfg.major)?;
        self.ensure_image(&image).await?;
        self.prepare_shared_instance().await?;
        let spec = shared_db_spec(&image, cfg, su_pw);
        let existing = self.inspect_owned(SHARED_DB).await?;
        // Tenant networks come and go, so they are not part of the comparison.
        let current = existing
            .as_ref()
            .is_some_and(|c| server_matches(c, &spec, false));
        self.converge(SHARED_DB, &spec, existing, current).await?;
        if !current {
            networks_changed().notify_one();
        }
        self.wait_healthy(SHARED_DB, &[su_pw.to_string()]).await
    }

    /// The first subnet of the site's database network, for the shared instance's `pg_hba.conf`.
    pub async fn dbnet_subnet(&self, site_id: &str) -> Result<String> {
        let name = DataNames::new(site_id)?.dbnet;
        self.network_subnet(&name).await
    }

    /// Creates the shared instance's volumes and admin network without its container, and returns the admin
    /// subnet. The first `pg_hba.conf` needs that subnet before the server can start.
    pub async fn prepare_shared_instance(&self) -> Result<String> {
        self.create_data_volume(SHARED_DATA, shared_volume_labels("pg-shared-data"))
            .await?;
        self.create_data_volume(SHARED_CONF, shared_volume_labels("pg-shared-conf"))
            .await?;
        self.create_data_network(SHARED_ADMIN, shared_labels("pg-shared-admin"))
            .await?;
        self.network_subnet(SHARED_ADMIN).await
    }

    async fn network_subnet(&self, name: &str) -> Result<String> {
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/networks/{name}"),
                &[],
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Err(ConnectorError::NotFound(format!("network {name}")));
        }
        let v: Value = serde_json::from_slice(&reply.body)?;
        v["IPAM"]["Config"]
            .as_array()
            .and_then(|configs| {
                configs
                    .iter()
                    .filter_map(|c| c["Subnet"].as_str())
                    .find(|s| !s.is_empty())
            })
            .map(str::to_string)
            .ok_or_else(|| ConnectorError::Internal(format!("network {name} has no subnet")))
    }

    /// Attaches the shared instance to the site's database network; nothing happens when it already is.
    pub async fn connect_shared(&self, site_id: &str) -> Result<()> {
        let net = DataNames::new(site_id)?.dbnet;
        let Some(members) = self.network_members(&net).await? else {
            return Err(ConnectorError::NotFound(format!("network {net}")));
        };
        if members.iter().any(|m| m == SHARED_DB) {
            return Ok(());
        }
        let body = json!({ "Container": SHARED_DB });
        let reply = self
            .send(
                Method::POST,
                &format!("{API}/networks/{net}/connect"),
                &[],
                Some(&body),
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Err(ConnectorError::Unavailable(format!(
                "the shared database instance {SHARED_DB} or network {net} was not found"
            )));
        }
        Ok(())
    }

    /// Detaches the shared instance from the site's database network; nothing happens when it is not attached.
    pub async fn disconnect_shared(&self, site_id: &str) -> Result<()> {
        let net = DataNames::new(site_id)?.dbnet;
        let Some(members) = self.network_members(&net).await? else {
            return Ok(());
        };
        if !members.iter().any(|m| m == SHARED_DB) {
            return Ok(());
        }
        let body = json!({ "Container": SHARED_DB });
        self.send(
            Method::POST,
            &format!("{API}/networks/{net}/disconnect"),
            &[],
            Some(&body),
            REQUEST_TIMEOUT,
            &[404],
        )
        .await
        .map(|_| ())
    }

    /// Attaches the shared instance to each listed site's network, skipping sites whose network is gone.
    /// A recreated or restarted-by-engine instance needs this to serve its tenants again.
    pub async fn reconnect_shared(&self, site_ids: &[String]) -> Result<()> {
        for id in site_ids {
            match self.connect_shared(id).await {
                Ok(()) | Err(ConnectorError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Runs one job container to completion: leftover removed, created, started, polled every 2 s (never
    /// ContainerWait, which the proxy caps at 300 s), exit code and a redacted output tail read, container
    /// removed again (also on error or timeout, after a stop with a 10 s grace).
    pub async fn run_job(
        &self,
        job: &JobSpec,
        redact: &[String],
        timeout: Duration,
    ) -> Result<JobOutcome> {
        check_job(job)?;
        let image = self.pg_image(job.major)?;
        let name = job_container(&job.scope);
        let spec = job_spec(job, &self.backup_volume, &image);
        // Passwords reach the job as env values, so they are scrubbed from its output whatever the caller passed.
        let mut secrets = redact.to_vec();
        secrets.extend(
            job.env
                .iter()
                .filter(|(key, _)| {
                    matches!(
                        key.as_str(),
                        "PGPASSWORD" | "CITE_USER_PASSWORD" | "CITE_JOB_PASSWORD"
                    )
                })
                .map(|(_, value)| value.to_string()),
        );
        self.ensure_image(&image).await?;
        self.remove_container(&name).await?;
        let outcome = self.drive_job(&name, &spec, timeout, &secrets).await;
        let cleanup = self.remove_container(&name).await;
        if let Err(e) = &cleanup {
            tracing::warn!(job = %name, error = %e, "data job container could not be removed");
        }
        outcome
    }

    async fn drive_job(
        &self,
        name: &str,
        spec: &Value,
        timeout: Duration,
        secrets: &[String],
    ) -> Result<JobOutcome> {
        self.create_container(name, spec).await?;
        self.start_container(name).await?;
        let deadline = Instant::now() + timeout;
        let exit_code = loop {
            let Some(seen) = self.inspect_owned(name).await? else {
                return Err(ConnectorError::Internal(format!(
                    "data job container {name} disappeared"
                )));
            };
            if !seen.running && !matches!(seen.state.as_str(), "created" | "restarting") {
                break i64::from(seen.exit_code.unwrap_or(-1));
            }
            let now = Instant::now();
            if now >= deadline {
                self.send(
                    Method::POST,
                    &format!("{API}/containers/{name}/stop"),
                    &[("t", STOP_GRACE_SECS)],
                    None,
                    STOP_TIMEOUT,
                    &[304, 404],
                )
                .await?;
                return Err(ConnectorError::Unavailable(format!(
                    "data job {name} did not finish within {}s and was stopped",
                    timeout.as_secs()
                )));
            }
            sleep(JOB_POLL.min(deadline - now)).await;
        };
        let mut lines = self.redacted_tail(name, JOB_LOG_TAIL, secrets).await?;
        if lines.len() > JOB_LOG_KEEP {
            lines.drain(..lines.len() - JOB_LOG_KEEP);
        }
        Ok(JobOutcome {
            exit_code,
            log_tail: lines,
        })
    }

    // The last `tail` lines of a container's output as redacted text; a missing container has none.
    async fn redacted_tail(
        &self,
        name: &str,
        tail: u32,
        secrets: &[String],
    ) -> Result<Vec<String>> {
        let tail = tail.to_string();
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/containers/{name}/logs"),
                &[("stdout", "1"), ("stderr", "1"), ("tail", tail.as_str())],
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Ok(Vec::new());
        }
        Ok(build_batch(&reply.body, false, secrets)
            .lines
            .into_iter()
            .map(|l| l.text)
            .collect())
    }

    /// Polls once a second until the container reports healthy. Unhealthy, exited, restarting or missing fails
    /// at once with the last 20 redacted log lines; `DB_READY_TIMEOUT` bounds the wait.
    pub async fn wait_healthy(&self, name: &str, redact: &[String]) -> Result<()> {
        self.wait_healthy_for(name, redact, DB_READY_TIMEOUT, DB_POLL)
            .await
    }

    pub(crate) async fn wait_healthy_for(
        &self,
        name: &str,
        redact: &[String],
        timeout: Duration,
        poll: Duration,
    ) -> Result<()> {
        check_server_name(name)?;
        let deadline = Instant::now() + timeout;
        loop {
            let seen = self.inspect_owned(name).await?;
            let failure = match &seen {
                None => Some("the container does not exist".to_string()),
                Some(c) if c.health == "healthy" && c.running => return Ok(()),
                Some(c) if c.health == "unhealthy" => Some("it reports unhealthy".to_string()),
                Some(c) if matches!(c.state.as_str(), "exited" | "restarting") => {
                    Some(format!("it is {}", c.state))
                }
                Some(_) => None,
            };
            if let Some(why) = failure {
                let lines = self
                    .redacted_tail(name, HEALTH_LOG_LINES, redact)
                    .await
                    .unwrap_or_default();
                let detail = if lines.is_empty() {
                    String::new()
                } else {
                    format!(" (last output: {})", lines.join(" | "))
                };
                return Err(ConnectorError::Unavailable(format!(
                    "{name} is not healthy: {why}{detail}"
                )));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ConnectorError::Unavailable(format!(
                    "{name} was not healthy within {}s",
                    timeout.as_secs()
                )));
            }
            sleep(poll.min(deadline - now)).await;
        }
    }

    /// Restarts a database server (`cite-<id>-db` or the shared instance) and waits until it is healthy again.
    pub async fn restart_database(&self, name: &str) -> Result<()> {
        check_server_name(name)?;
        let reply = self
            .send(
                Method::POST,
                &format!("{API}/containers/{name}/restart"),
                &[("t", RESTART_GRACE)],
                None,
                STOP_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Err(ConnectorError::NotFound(format!(
                "database container {name}"
            )));
        }
        self.wait_healthy(name, &[]).await
    }

    /// Removes a site's dedicated database and job containers and its network; with `purge` also the data
    /// volume. The shared instance is detached from the network first. The network cannot go while a stack
    /// of the site is still attached, so callers remove the stack first.
    pub async fn remove_site_database(&self, site_id: &str, purge: bool) -> Result<()> {
        let n = DataNames::new(site_id)?;
        self.remove_container(&n.job).await?;
        self.remove_container(&n.db).await?;
        self.disconnect_shared(site_id).await?;
        self.remove_network(&n.dbnet).await?;
        if purge {
            self.delete_volume(&n.db_volume).await?;
        }
        Ok(())
    }

    /// Removes only a site's dedicated database container (and its job container), and with `purge` its volume. Unlike
    /// `remove_site_database` it leaves the site's database network and the shared instance's attachment to it alone, so a
    /// site that now lives on the shared instance keeps working while its retired dedicated database goes.
    pub async fn remove_dedicated_database(&self, site_id: &str, purge: bool) -> Result<()> {
        let n = DataNames::new(site_id)?;
        self.remove_container(&n.job).await?;
        self.remove_container(&n.db).await?;
        if purge {
            self.delete_volume(&n.db_volume).await?;
        }
        Ok(())
    }

    /// Removes the shared instance, its job container and admin network; with `purge` also its two volumes.
    pub async fn remove_shared_instance(&self, purge: bool) -> Result<()> {
        self.remove_container(SHARED_JOB).await?;
        self.remove_container(SHARED_DB).await?;
        self.remove_network(SHARED_ADMIN).await?;
        if purge {
            self.delete_volume(SHARED_DATA).await?;
            self.delete_volume(SHARED_CONF).await?;
        }
        Ok(())
    }

    /// State of a database server; a container that does not exist reports state `missing`.
    pub async fn database_health(&self, name: &str) -> Result<DbHealth> {
        check_server_name(name)?;
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/containers/{name}/json"),
                &[],
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Ok(DbHealth {
                state: "missing".to_string(),
                health: "none".to_string(),
                started_at: None,
                image: String::new(),
            });
        }
        let v: Value = serde_json::from_slice(&reply.body)?;
        if v["Config"]["Labels"]["cite.managed"].as_str() != Some("true") {
            return Err(ConnectorError::Conflict(format!(
                "container {name} exists and is not managed by cite"
            )));
        }
        let started = v["State"]["StartedAt"]
            .as_str()
            .filter(|s| !s.is_empty() && !s.starts_with("0001-"))
            .map(str::to_string);
        Ok(DbHealth {
            state: state_name(&v["State"]),
            health: health_name(&v["State"]["Health"]["Status"]),
            started_at: started,
            image: v["Config"]["Image"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        })
    }

    /// Size of a named data volume in bytes; None when the volume is missing or the engine reports no size.
    pub async fn volume_size(&self, name: &str) -> Result<Option<u64>> {
        let site_volume = name
            .strip_prefix("cite-")
            .and_then(|rest| rest.strip_suffix("-db-data"))
            .is_some_and(is_valid_id);
        if !site_volume && name != SHARED_DATA && name != SHARED_CONF {
            return Err(ConnectorError::BadRequest(format!(
                "{name:?} is not a data volume"
            )));
        }
        // The Docker proxy accepts only label filters on listings, so the name is matched below.
        let filters = json!({ "label": ["cite.managed=true"] }).to_string();
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/volumes"),
                &[("filters", filters.as_str())],
                None,
                REQUEST_TIMEOUT,
                &[],
            )
            .await?;
        let v: Value = serde_json::from_slice(&reply.body)?;
        Ok(v["Volumes"]
            .as_array()
            .and_then(|items| items.iter().find(|i| i["Name"].as_str() == Some(name)))
            .and_then(|item| item["UsageData"]["Size"].as_i64())
            .and_then(|n| u64::try_from(n).ok()))
    }

    /// True when a running manager or executor of the site (either slot) still carries one of the given
    /// strings in its env; used to decide when the previous login of a rotated user can be retired.
    pub async fn env_mentions(&self, site_id: &str, needles: &[String]) -> Result<bool> {
        let needles: Vec<&str> = needles
            .iter()
            .map(String::as_str)
            .filter(|n| !n.is_empty())
            .collect();
        if needles.is_empty() {
            return Ok(false);
        }
        for slot in [Slot::Blue, Slot::Green] {
            let names = StackNames::new(site_id, slot)?;
            for container in [&names.manager, &names.executor] {
                let Some(c) = self.inspect_owned(container).await? else {
                    continue;
                };
                if c.running
                    && c.env
                        .iter()
                        .any(|entry| needles.iter().any(|n| entry.contains(n)))
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    // The create call is idempotent and would silently adopt a foreign volume of the same name.
    async fn create_data_volume(&self, name: &str, labels: Value) -> Result<()> {
        match self.managed_label("volumes", name).await? {
            Some(true) => return Ok(()),
            Some(false) => return self.require_managed("volumes", name).await,
            None => {}
        }
        let body = volume_body(name, labels);
        let reply = self
            .send(
                Method::POST,
                &format!("{API}/volumes/create"),
                &[],
                Some(&body),
                REQUEST_TIMEOUT,
                &[409],
            )
            .await?;
        if reply.status == 409 {
            self.require_managed("volumes", name).await?;
        }
        Ok(())
    }

    /// Creates the network unless it exists. A new network may have a new subnet, which the shared instance's
    /// `pg_hba.conf` must follow, so its creation is announced through [`networks_changed`].
    async fn create_data_network(&self, name: &str, labels: Value) -> Result<()> {
        let body = network_body(name, labels);
        let reply = self
            .send(
                Method::POST,
                &format!("{API}/networks/create"),
                &[],
                Some(&body),
                REQUEST_TIMEOUT,
                &[409],
            )
            .await?;
        if reply.status == 409 {
            self.require_managed("networks", name).await?;
        } else {
            networks_changed().notify_one();
        }
        Ok(())
    }

    async fn delete_volume(&self, name: &str) -> Result<()> {
        if self.managed_label("volumes", name).await? == Some(false) {
            return Err(ConnectorError::Conflict(format!(
                "volume {name} exists and is not managed by cite"
            )));
        }
        self.send(
            Method::DELETE,
            &format!("{API}/volumes/{name}"),
            &[],
            None,
            REQUEST_TIMEOUT,
            &[404],
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";

    fn names() -> DataNames {
        DataNames::new("shop").unwrap()
    }

    fn pg() -> ManagedPostgres {
        serde_json::from_value(json!({
            "mode": "dedicated",
            "major": 18,
            "databases": [{ "name": "app", "users": [{ "name": "app", "level": "readwrite" }] }],
        }))
        .unwrap()
    }

    fn shared_cfg() -> SharedSettings {
        serde_json::from_value(json!({
            "version": 1,
            "enabled": true,
            "major": 18,
            "memory_mb": 1024,
            "nano_cpus": 2_000_000_000i64,
            "max_connections": 200,
        }))
        .unwrap()
    }

    fn job(scope: JobScope, op: JobOp, net: JobNet, env: &[(&str, &str)]) -> JobSpec {
        JobSpec {
            scope,
            op,
            net,
            major: 18,
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), Zeroizing::new((*v).to_string())))
                .collect(),
            read_only: op == JobOp::Restore,
        }
    }

    #[test]
    fn the_shared_names_match_the_proxys() {
        assert_eq!(SHARED_DB, "cite-pg-shared");
        assert_eq!(SHARED_DATA, "cite-pg-shared-data");
        assert_eq!(SHARED_CONF, "cite-pg-shared-conf");
        assert_eq!(SHARED_ADMIN, "cite-pg-shared-admin");
        assert_eq!(SHARED_JOB, "cite-pg-shared-job");
        let n = names();
        assert_eq!(n.db, "cite-shop-db");
        assert_eq!(n.db_volume, "cite-shop-db-data");
        assert_eq!(n.dbnet, "cite-shop-dbnet");
        assert_eq!(n.job, "cite-shop-dbjob");
        assert!(DataNames::new("Bad Id").is_err());
    }

    #[test]
    fn the_image_name_mirrors_images_toml() {
        assert_eq!(
            postgres_image("ghcr.io/seggys116", "0.5.0", 18).unwrap(),
            "ghcr.io/seggys116/cite-postgres:0.5.0-pg18"
        );
        assert!(postgres_image("r", "1", 16).is_err());
        let toml = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../images/images.toml"),
        )
        .unwrap();
        assert!(toml.contains(&format!("postgres = \"{POSTGRES_IMAGE}\"")));
    }

    #[test]
    fn a_dedicated_server_body_is_hardened_and_private() {
        let n = names();
        let spec = db_spec(
            &n,
            "r/cite-postgres:1-pg18",
            &pg(),
            (512 * MIB, 1_000_000_000),
            PW,
        );
        assert_eq!(spec["User"], "70:70");
        assert_eq!(spec["Labels"], site_labels("shop", "db"));
        assert_eq!(spec["Cmd"][4], "max_connections=100");
        let host = &spec["HostConfig"];
        assert_eq!(host["NetworkMode"], "cite-shop-dbnet");
        assert_eq!(host["ReadonlyRootfs"], true);
        assert_eq!(host["CapDrop"], json!(["ALL"]));
        assert!(host.get("CapAdd").is_none());
        assert!(host.get("PortBindings").is_none());
        assert!(host.get("Privileged").is_none());
        assert_eq!(host["Memory"], 512 * MIB);
        assert_eq!(host["MemorySwap"], 512 * MIB);
        assert_eq!(host["Mounts"].as_array().unwrap().len(), 1);
        assert_eq!(host["Mounts"][0]["Source"], "cite-shop-db-data");
        assert_eq!(
            spec["NetworkingConfig"]["EndpointsConfig"],
            json!({ "cite-shop-dbnet": {} })
        );
        let env: Vec<&str> = spec["Env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(env.len(), 6);
        assert!(env.contains(&format!("POSTGRES_PASSWORD={PW}").as_str()));
        // Labels never carry the password.
        assert!(!spec["Labels"].to_string().contains(PW));
    }

    #[test]
    fn the_shared_server_reads_its_hba_file_read_only_and_sits_on_the_admin_network() {
        let spec = shared_db_spec("r/cite-postgres:1-pg18", &shared_cfg(), PW);
        assert_eq!(spec["Labels"], shared_labels("pg-shared"));
        assert_eq!(spec["HostConfig"]["NetworkMode"], SHARED_ADMIN);
        assert_eq!(spec["HostConfig"]["Memory"], 1024 * MIB);
        assert_eq!(spec["HostConfig"]["NanoCpus"], 2_000_000_000i64);
        assert_eq!(spec["Cmd"][4], "max_connections=200");
        let cmd = spec["Cmd"].as_array().unwrap();
        assert_eq!(cmd[cmd.len() - 1], "hba_file=/etc/cite-pg/pg_hba.conf");
        let mounts = spec["HostConfig"]["Mounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0]["Source"], SHARED_DATA);
        assert_eq!(mounts[1]["Source"], SHARED_CONF);
        assert_eq!(mounts[1]["ReadOnly"], true);
    }

    #[test]
    fn job_bodies_mount_only_their_staging_subpath() {
        let env = [
            ("CITE_JOB_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            ("PGPASSWORD", PW),
        ];
        let backup = job(
            JobScope::Site("shop".into()),
            JobOp::Backup,
            JobNet::Dbnet,
            &env,
        );
        let spec = job_spec(&backup, "cite-backups", "r/cite-postgres:1-pg18");
        assert_eq!(spec["Entrypoint"], json!(["cite-pg-job"]));
        assert_eq!(spec["Cmd"], json!(["backup"]));
        assert_eq!(spec["User"], "10001:10001");
        assert_eq!(spec["Labels"], site_labels("shop", "dbjob"));
        assert_eq!(spec["Healthcheck"], json!({ "Test": ["NONE"] }));
        assert_eq!(spec["HostConfig"]["NetworkMode"], "cite-shop-dbnet");
        assert_eq!(spec["HostConfig"]["RestartPolicy"], json!({ "Name": "no" }));
        assert_eq!(
            spec["HostConfig"]["Mounts"],
            json!([{
                "Type": "volume", "Source": "cite-backups", "Target": "/backup", "ReadOnly": false,
                "VolumeOptions": { "Subpath": "staging/shop" },
            }])
        );
        assert_eq!(spec["Env"][1], format!("PGPASSWORD={PW}"));
        assert!(!spec["Labels"].to_string().contains(PW));

        let restore = job(
            JobScope::Site("shop".into()),
            JobOp::Restore,
            JobNet::SharedAdmin,
            &env,
        );
        let spec = job_spec(&restore, "cite-backups", "img");
        assert_eq!(spec["HostConfig"]["Mounts"][0]["ReadOnly"], true);
        assert_eq!(spec["HostConfig"]["NetworkMode"], SHARED_ADMIN);

        let hba = job(JobScope::Shared, JobOp::Hba, JobNet::SharedAdmin, &env);
        let spec = job_spec(&hba, "cite-backups", "img");
        assert_eq!(spec["Labels"], shared_labels("pg-shared-job"));
        let mounts = spec["HostConfig"]["Mounts"].as_array().unwrap();
        assert_eq!(mounts[0]["VolumeOptions"]["Subpath"], "staging/_shared");
        assert_eq!(mounts[1]["Source"], SHARED_CONF);
        assert_eq!(mounts[1]["Target"], "/conf");
        assert_eq!(mounts[1]["ReadOnly"], false);

        let xnet = job(
            JobScope::Site("shop".into()),
            JobOp::Backup,
            JobNet::Xnet(Slot::Green),
            &env,
        );
        assert_eq!(
            job_spec(&xnet, "cite-backups", "img")["HostConfig"]["NetworkMode"],
            "cite-shop-green-xnet"
        );
        let open = job(
            JobScope::Site("shop".into()),
            JobOp::Backup,
            JobNet::Egress(Slot::Blue),
            &env,
        );
        assert_eq!(
            job_spec(&open, "cite-backups", "img")["HostConfig"]["NetworkMode"],
            "cite-shop-blue-egress"
        );
    }

    #[test]
    fn jobs_the_proxy_would_refuse_are_refused_first() {
        let site = || JobScope::Site("shop".into());
        let env = [("PGPASSWORD", PW)];
        assert!(check_job(&job(site(), JobOp::Backup, JobNet::Dbnet, &env)).is_ok());
        assert!(
            check_job(&job(
                JobScope::Shared,
                JobOp::Sizes,
                JobNet::SharedAdmin,
                &env
            ))
            .is_ok()
        );

        // Instance-wide operations never run in a site job, and the reverse.
        assert!(check_job(&job(site(), JobOp::Hba, JobNet::SharedAdmin, &env)).is_err());
        // The shared backup must name a tenant database, and only on the admin network.
        assert!(
            check_job(&job(
                JobScope::Shared,
                JobOp::Backup,
                JobNet::SharedAdmin,
                &env
            ))
            .is_err()
        );
        for db in ["postgres", "template0", "template1", "app", "t0123456789_"] {
            let named = [("PGPASSWORD", PW), ("PGDATABASE", db)];
            assert!(
                check_job(&job(
                    JobScope::Shared,
                    JobOp::Backup,
                    JobNet::SharedAdmin,
                    &named
                ))
                .is_err(),
                "{db}"
            );
        }
        let tenant = [("PGPASSWORD", PW), ("PGDATABASE", "t0123456789_app")];
        assert!(
            check_job(&job(
                JobScope::Shared,
                JobOp::Backup,
                JobNet::SharedAdmin,
                &tenant
            ))
            .is_ok()
        );
        assert!(
            check_job(&job(
                JobScope::Shared,
                JobOp::Backup,
                JobNet::Dbnet,
                &tenant
            ))
            .is_err()
        );
        // The shared job stays on the admin network.
        assert!(check_job(&job(JobScope::Shared, JobOp::Sizes, JobNet::Dbnet, &env)).is_err());
        // Only a backup may leave the node's internal networks.
        assert!(check_job(&job(site(), JobOp::Counts, JobNet::Xnet(Slot::Blue), &env)).is_err());
        assert!(
            check_job(&job(
                site(),
                JobOp::Backup,
                JobNet::Egress(Slot::Blue),
                &env
            ))
            .is_ok()
        );

        let mut wrong_ro = job(site(), JobOp::Backup, JobNet::Dbnet, &env);
        wrong_ro.read_only = true;
        assert!(check_job(&wrong_ro).is_err());
        let mut no_ro = job(site(), JobOp::Restore, JobNet::Dbnet, &env);
        no_ro.read_only = false;
        assert!(check_job(&no_ro).is_err());

        let mut major = job(site(), JobOp::Backup, JobNet::Dbnet, &env);
        major.major = 16;
        assert!(check_job(&major).is_err());

        for bad in [
            job(site(), JobOp::Backup, JobNet::Dbnet, &[("lower", "x")]),
            job(site(), JobOp::Backup, JobNet::Dbnet, &[("A=B", "x")]),
            job(site(), JobOp::Backup, JobNet::Dbnet, &[("A", "x\ny")]),
            job(
                site(),
                JobOp::Backup,
                JobNet::Dbnet,
                &[("A", "1"), ("A", "2")],
            ),
        ] {
            assert!(check_job(&bad).is_err());
        }
        assert!(
            check_job(&job(
                JobScope::Site("Bad Id".into()),
                JobOp::Backup,
                JobNet::Dbnet,
                &env
            ))
            .is_err()
        );
    }

    #[test]
    fn tenant_database_work_runs_as_the_job_login_and_the_rest_as_the_superuser() {
        let site = || JobScope::Site("shop".into());
        let tag = "t0123456789_app";
        let with = |op: JobOp, net: JobNet, user: &str, extra: &[(&str, &str)]| {
            let mut env = vec![("PGUSER", user), ("PGPASSWORD", PW)];
            env.extend_from_slice(extra);
            check_job(&job(site(), op, net, &env))
        };
        let tagged = [("CITE_ROLE_TAG", tag)];
        for op in [JobOp::Backup, JobOp::Counts, JobOp::Regrant] {
            assert!(with(op, JobNet::Dbnet, "t0123456789_app_job", &tagged).is_ok());
            assert!(with(op, JobNet::SharedAdmin, "t0123456789_app_job", &tagged).is_ok());
            assert!(with(op, JobNet::Dbnet, "postgres", &tagged).is_err());
            assert!(with(op, JobNet::Dbnet, "t0123456789_other_job", &tagged).is_err());
            assert!(with(op, JobNet::Dbnet, "t0123456789_app_job", &[]).is_err());
        }
        let restore = [("CITE_OWNER_ROLE", "t0123456789_app_owner")];
        assert!(
            with(
                JobOp::Restore,
                JobNet::Dbnet,
                "t0123456789_app_job",
                &restore
            )
            .is_ok()
        );
        assert!(with(JobOp::Restore, JobNet::Dbnet, "postgres", &restore).is_err());
        for op in [
            JobOp::JobLogin,
            JobOp::Freeze,
            JobOp::Unfreeze,
            JobOp::Provision,
            JobOp::Deprovision,
            JobOp::User,
        ] {
            assert!(
                with(op, JobNet::Dbnet, "postgres", &tagged).is_ok(),
                "{op:?}"
            );
            assert!(
                with(op, JobNet::Dbnet, "t0123456789_app_job", &tagged).is_err(),
                "{op:?}"
            );
        }
        // An external database is dumped with its own user, whatever it is called.
        assert!(with(JobOp::Backup, JobNet::Egress(Slot::Blue), "postgres", &[]).is_ok());
    }

    #[test]
    fn a_job_spec_never_prints_its_env_values() {
        let j = job(
            JobScope::Site("shop".into()),
            JobOp::User,
            JobNet::Dbnet,
            &[("PGPASSWORD", PW), ("CITE_USER_PASSWORD", "hunter2hunter2")],
        );
        let shown = format!("{j:?}");
        assert!(!shown.contains(PW) && !shown.contains("hunter2"));
        assert!(shown.contains("PGPASSWORD"));
    }

    #[test]
    fn server_names_are_checked_before_any_call() {
        assert!(check_server_name("cite-shop-db").is_ok());
        assert!(check_server_name(SHARED_DB).is_ok());
        for bad in [
            "cite-shop-dbjob",
            "cite--db",
            "cite-Shop-db",
            "shop-db",
            "cite-shop-db-data",
            "",
        ] {
            assert!(check_server_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn data_specs_cover_every_object_of_a_site() {
        let mut site: Site = serde_json::from_value(json!({
            "id": "shop", "name": "shop", "hosts": ["shop.example.com"],
            "blue": {}, "green": {}, "active": "blue",
            "source": { "repo": "acme/shop" },
        }))
        .unwrap();
        site.data.postgres = Some(pg());
        let egress = crate::egress::Egress::default();
        let env = StackEnv {
            registry: "ghcr.io/seggys116",
            version: "0.5.0",
            edge_network: "cite_edge",
            isolate: true,
            github_api_url: None,
            egress: &egress,
        };
        let jobs = [job(
            JobScope::Site("shop".into()),
            JobOp::Counts,
            JobNet::Dbnet,
            &[("PGPASSWORD", PW)],
        )];
        let set = data_specs(&site, &env, "cite-backups", PW, &shared_cfg(), &jobs).unwrap();
        assert_eq!(set.image, "ghcr.io/seggys116/cite-postgres:0.5.0-pg18");
        assert_eq!(set.dbnet["Internal"], true);
        assert_eq!(set.dbnet["Labels"], site_labels("shop", "dbnet"));
        assert_eq!(set.db_volume["Labels"], db_volume_labels("shop"));
        assert_eq!(set.shared_admin["Labels"], shared_labels("pg-shared-admin"));
        assert_eq!(set.jobs.len(), 1);
        assert_eq!(set.jobs[0].0, "cite-shop-dbjob");
        site.data.postgres = None;
        assert!(data_specs(&site, &env, "cite-backups", PW, &shared_cfg(), &[]).is_err());
    }
}
