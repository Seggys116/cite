//! Exact create bodies of the data containers: the Postgres server of a site, the node-wide shared
//! instance, and the one-shot job containers that run `cite-pg-job` against them. Like the stack roles,
//! every body is rebuilt here and compared whole, so any key the connector never sends is refused.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::config::{EgressMode, MIN_STACK_MEMORY, MIN_STACK_NANO_CPUS};
use crate::envval;
use crate::policy::{DataContainer, DataRole, Policy};
use crate::spec::{first_difference, log_config, mount, object, within};

/// Postgres majors the proxy accepts images for; the connector's `cite_edge::validate::PG_MAJORS` must match.
pub const PG_MAJORS: [u8; 2] = [17, 18];

pub const SHARED_DATA: &str = "cite-pg-shared-data";
pub const SHARED_CONF: &str = "cite-pg-shared-conf";
pub const SHARED_ADMIN: &str = "cite-pg-shared-admin";
pub const SHARED_DB: &str = "cite-pg-shared";

const MIB: i64 = 1 << 20;
const MAX_ENV_ENTRIES: usize = 32;
const PG_PORT: &str = "5432";
const PG_PIDS: i64 = 512;
const PG_SHM: i64 = 256 * MIB;
const JOB_MEMORY: i64 = 512 * MIB;
const JOB_NANO_CPUS: i64 = 1_000_000_000;
const JOB_PIDS: i64 = 64;
const MIN_CONNECTIONS: u32 = 10;
const MAX_CONNECTIONS: u32 = 1000;
const FORWARD_PORTS: std::ops::RangeInclusive<u32> = 15432..=15439;
const MAINTENANCE_DB: &str = "postgres";
const RESERVED_DBS: [&str; 3] = ["postgres", "template0", "template1"];

/// 10 lowercase hex characters of sha256("cite-pg-v1:" + site id). A copy of
/// `cite_edge::datamodel::pg_site_tag`; the data specs test compares both on many ids.
pub fn pg_site_tag(site_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cite-pg-v1:");
    hasher.update(site_id.as_bytes());
    hasher
        .finalize()
        .iter()
        .take(5)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn site_labels(id: &str, role: &str) -> Value {
    json!({ "cite.managed": "true", "cite.site": id, "cite.role": role })
}

fn shared_labels(role: &str) -> Value {
    json!({ "cite.managed": "true", "cite.role": role })
}

// ---- Postgres servers (dedicated and shared) ----

const PG_ENV_KEYS: [&str; 6] = [
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
    "PGDATA",
    "POSTGRES_HOST_AUTH_METHOD",
    "POSTGRES_INITDB_ARGS",
];

fn pg_env_value_ok(key: &str, value: &str) -> bool {
    match key {
        "POSTGRES_USER" | "POSTGRES_DB" => value == "postgres",
        "POSTGRES_PASSWORD" => envval::generated_password(value),
        "PGDATA" => value == "/var/lib/postgresql/data/pgdata",
        "POSTGRES_HOST_AUTH_METHOD" => value == "scram-sha-256",
        "POSTGRES_INITDB_ARGS" => value == "--auth-host=scram-sha-256 --auth-local=peer",
        _ => false,
    }
}

// Splits `KEY=value` entries; a repeated key, a non-string entry or a missing `=` is refused.
fn env_pairs(env: Option<&Value>) -> Result<(Value, BTreeMap<String, String>), String> {
    let entries = env.and_then(Value::as_array).ok_or("Env is missing")?;
    if entries.len() > MAX_ENV_ENTRIES {
        return Err("Env has too many entries".to_string());
    }
    let mut map = BTreeMap::new();
    for entry in entries {
        let text = entry.as_str().ok_or("Env entry is not a string")?;
        let (key, value) = text.split_once('=').ok_or("Env entry has no value")?;
        if map.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("Env key {key:?} is repeated"));
        }
    }
    Ok((Value::Array(entries.clone()), map))
}

fn check_pg_env(env: Option<&Value>) -> Result<Value, String> {
    let (value, map) = env_pairs(env)?;
    for key in map.keys() {
        if !PG_ENV_KEYS.contains(&key.as_str()) {
            return Err(format!("Env key {key:?} is not allowed"));
        }
    }
    for key in PG_ENV_KEYS {
        match map.get(key) {
            None => return Err(format!("Env key {key:?} is missing")),
            Some(v) if !pg_env_value_ok(key, v) => {
                return Err(format!("Env value for {key:?} is not allowed"));
            }
            Some(_) => {}
        }
    }
    Ok(value)
}

// The connection cap is the one number inside Cmd; everything else in it is fixed text.
fn max_connections(obj: &Map<String, Value>) -> Result<u32, String> {
    obj.get("Cmd")
        .and_then(Value::as_array)
        .and_then(|cmd| cmd.get(4))
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("max_connections="))
        .filter(|n| envval::dec_in(n, MIN_CONNECTIONS, MAX_CONNECTIONS))
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| "Cmd max_connections is missing or out of range".to_string())
}

fn expected_db(
    role: DataRole,
    id: Option<&str>,
    image: &str,
    env: &Value,
    connections: u32,
    memory: i64,
    nano_cpus: i64,
) -> Value {
    let shared = role == DataRole::SharedDb;
    let (network, data) = match (shared, id) {
        (false, Some(id)) => (format!("cite-{id}-dbnet"), format!("cite-{id}-db-data")),
        _ => (SHARED_ADMIN.to_string(), SHARED_DATA.to_string()),
    };
    let mut cmd = vec![
        "postgres".to_string(),
        "-c".into(),
        "listen_addresses=*".into(),
        "-c".into(),
        format!("max_connections={connections}"),
        "-c".into(),
        "password_encryption=scram-sha-256".into(),
        "-c".into(),
        "log_connections=on".into(),
        "-c".into(),
        "log_disconnections=on".into(),
        "-c".into(),
        "idle_in_transaction_session_timeout=300000".into(),
    ];
    let mut mounts = vec![mount(&data, "/var/lib/postgresql/data", None, false)];
    if shared {
        cmd.extend(["-c".to_string(), "hba_file=/etc/cite-pg/pg_hba.conf".into()]);
        mounts.push(mount(SHARED_CONF, "/etc/cite-pg", None, true));
    }
    let labels = match (shared, id) {
        (false, Some(id)) => site_labels(id, "db"),
        _ => shared_labels("pg-shared"),
    };
    json!({
        "Image": image,
        "User": "70:70",
        "Env": env,
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

fn validate_db(
    policy: &Policy,
    container: &DataContainer,
    obj: &Map<String, Value>,
    image: &str,
    body: &Value,
) -> Result<(), String> {
    let env = check_pg_env(obj.get("Env"))?;
    let host = obj
        .get("HostConfig")
        .map(|h| object(h, "HostConfig"))
        .transpose()?
        .ok_or("HostConfig is missing")?;
    let memory = within(host, "Memory", MIN_STACK_MEMORY, policy.max_memory)?;
    let nano_cpus = within(host, "NanoCpus", MIN_STACK_NANO_CPUS, policy.max_nano_cpus)?;
    let connections = max_connections(obj)?;
    let want = expected_db(
        container.role,
        container.id.as_deref(),
        image,
        &env,
        connections,
        memory,
        nano_cpus,
    );
    match first_difference("body", &want, body) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

// ---- One-shot jobs ----

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Backup,
    Restore,
    Counts,
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

impl Op {
    fn parse(text: &str) -> Option<Op> {
        Some(match text {
            "backup" => Op::Backup,
            "restore" => Op::Restore,
            "counts" => Op::Counts,
            "joblogin" => Op::JobLogin,
            "freeze" => Op::Freeze,
            "unfreeze" => Op::Unfreeze,
            "provision" => Op::Provision,
            "deprovision" => Op::Deprovision,
            "regrant" => Op::Regrant,
            "user" => Op::User,
            "hba" => Op::Hba,
            "sizes" => Op::Sizes,
            "globals" => Op::Globals,
            _ => return None,
        })
    }

    // Operations on one site's databases may run in a site job; instance-wide ones only in the shared job.
    fn site_scope(self) -> bool {
        !matches!(self, Op::Hba | Op::Sizes | Op::Globals)
    }

    // The whole-instance backup dumps each tenant database through the shared job (admin network only).
    fn shared_scope(self) -> bool {
        matches!(
            self,
            Op::Backup
                | Op::JobLogin
                | Op::Provision
                | Op::Deprovision
                | Op::User
                | Op::Hba
                | Op::Sizes
                | Op::Globals
        )
    }

    fn has_database(self) -> bool {
        !matches!(self, Op::Hba | Op::Sizes | Op::Globals)
    }

    // Work inside a tenant database on the node's own servers runs as that database's job login, never as the
    // superuser; the superuser only ever opens the maintenance database.
    fn runs_as_job_login(self) -> bool {
        matches!(self, Op::Backup | Op::Restore | Op::Counts | Op::Regrant)
    }

    // Keys an operation may leave out; every other key of `extra_env` is required.
    fn optional(self, key: &str) -> bool {
        match key {
            "PGSSLMODE" | "CITE_USER_PASSWORD" | "CITE_JOB_PASSWORD" => true,
            // A managed backup names its tag; an external one has none (checked against the network below).
            "CITE_ROLE_TAG" => self == Op::Backup,
            "CITE_USER_ROLE" => self == Op::Regrant,
            _ => false,
        }
    }

    // Provisioning and role changes may connect to the maintenance database instead of the target.
    fn may_use_maintenance_db(self) -> bool {
        matches!(self, Op::Provision | Op::Deprovision | Op::User)
    }

    fn extra_env(self) -> &'static [&'static str] {
        match self {
            Op::Backup => &["PGDATABASE", "PGSSLMODE", "CITE_ROLE_TAG"],
            Op::Restore => &["PGDATABASE", "CITE_OWNER_ROLE", "CITE_LOGIN_ROLE"],
            Op::Counts => &["PGDATABASE", "CITE_ROLE_TAG"],
            Op::JobLogin => &[
                "PGDATABASE",
                "CITE_ROLE_TAG",
                "CITE_JOB_ACTION",
                "CITE_JOB_PASSWORD",
            ],
            Op::Freeze | Op::Unfreeze => &["PGDATABASE", "CITE_LOGIN_ROLE"],
            Op::Provision | Op::Deprovision => &["PGDATABASE", "CITE_ROLE_TAG"],
            Op::Regrant => &["PGDATABASE", "CITE_ROLE_TAG", "CITE_USER_ROLE"],
            Op::User => &[
                "PGDATABASE",
                "CITE_ROLE_TAG",
                "CITE_USER_ACTION",
                "CITE_USER_ROLE",
                "CITE_USER_LEVEL",
                "CITE_USER_PASSWORD",
                "CITE_USER_CONN_LIMIT",
                "CITE_USER_STMT_MS",
                "CITE_USER_IDLE_MS",
            ],
            Op::Hba => &["CITE_PG_HBA", "CITE_PG_RELOAD"],
            Op::Sizes | Op::Globals => &[],
        }
    }
}

const COMMON_JOB_ENV: [&str; 5] = ["CITE_JOB_ID", "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD"];
const SSL_MODES: [&str; 6] = [
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
];
const USER_ACTIONS: [&str; 7] = [
    "create", "password", "settings", "disable", "enable", "retire", "drop",
];
const USER_LEVELS: [&str; 3] = ["owner", "readwrite", "readonly"];
const JOB_ACTIONS: [&str; 3] = ["open", "lock", "close"];

#[derive(Clone, PartialEq, Eq)]
enum JobNet {
    Dbnet,
    Admin,
    Xnet(String),
    Egress(String),
}

impl JobNet {
    fn internal(&self) -> bool {
        matches!(self, JobNet::Dbnet | JobNet::Admin)
    }
}

// Only the networks this job's own scope owns can be named.
fn job_net(policy: &Policy, id: Option<&str>, mode: &str) -> Result<JobNet, String> {
    if mode == SHARED_ADMIN {
        return Ok(JobNet::Admin);
    }
    let Some(id) = id else {
        return Err("HostConfig.NetworkMode is not allowed".to_string());
    };
    let own = format!("cite-{id}-");
    let Some(rest) = mode.strip_prefix(&own) else {
        return Err("HostConfig.NetworkMode is not allowed".to_string());
    };
    let net = match rest {
        "dbnet" => JobNet::Dbnet,
        "blue-xnet" => JobNet::Xnet("blue".into()),
        "green-xnet" => JobNet::Xnet("green".into()),
        "blue-egress" => JobNet::Egress("blue".into()),
        "green-egress" => JobNet::Egress("green".into()),
        _ => return Err("HostConfig.NetworkMode is not allowed".to_string()),
    };
    // Mirrors executor_outbound: the outbound networks exist only in the node's configured egress mode.
    let mode_ok = match (&net, policy.egress_mode) {
        (JobNet::Xnet(_), mode) => mode == EgressMode::Filtered,
        (JobNet::Egress(_), mode) => mode == EgressMode::Open,
        _ => true,
    };
    if mode_ok {
        Ok(net)
    } else {
        Err("this job's outbound network does not match the node's egress mode (CITE_STACK_EGRESS_MODE)".to_string())
    }
}

fn net_allowed_for(op: Op, net: &JobNet, shared_job: bool) -> bool {
    match net {
        JobNet::Admin => true,
        _ if shared_job => false,
        JobNet::Dbnet => !matches!(op, Op::Hba | Op::Sizes | Op::Globals),
        JobNet::Xnet(_) | JobNet::Egress(_) => op == Op::Backup,
    }
}

// The role prefix a request names, taken from whichever role variable the operation carries.
fn named_tag(op: Op, env: &BTreeMap<String, String>) -> Option<String> {
    let strip = |key: &str, suffix: &str| {
        env.get(key)
            .and_then(|v| v.strip_suffix(suffix))
            .map(str::to_string)
    };
    match op {
        Op::Provision
        | Op::Deprovision
        | Op::Regrant
        | Op::User
        | Op::Backup
        | Op::Counts
        | Op::JobLogin => env.get("CITE_ROLE_TAG").cloned(),
        Op::Restore => {
            let owner = strip("CITE_OWNER_ROLE", "_owner")?;
            (strip("CITE_LOGIN_ROLE", "_login")? == owner).then_some(owner)
        }
        Op::Freeze | Op::Unfreeze => strip("CITE_LOGIN_ROLE", "_login"),
        _ => None,
    }
}

struct JobCtx<'a> {
    op: Op,
    id: Option<&'a str>,
    net: &'a JobNet,
    env: &'a BTreeMap<String, String>,
    tag: Option<String>,
}

impl JobCtx<'_> {
    // A site job may only name roles that start with that site's own tag; the shared job names any tenant.
    fn site_prefix(&self) -> Option<String> {
        self.id.map(|id| format!("t{}_", pg_site_tag(id)))
    }

    fn database_ok(&self, v: &str) -> bool {
        if !self.net.internal() {
            return envval::printable(v, 63);
        }
        if self.op.may_use_maintenance_db() && v == MAINTENANCE_DB {
            return true;
        }
        let in_shared_instance = *self.net == JobNet::Admin;
        match &self.tag {
            // The shared instance names a tenant database like its role tag; a dedicated server uses the logical name.
            Some(tag) if in_shared_instance => v == tag,
            Some(tag) => tag.split_once('_').is_some_and(|(_, db)| db == v),
            None => {
                let logical = match (&self.site_prefix(), in_shared_instance) {
                    (Some(prefix), true) => v.strip_prefix(prefix.as_str()),
                    // The shared job's instance backup names any one tenant database, never a system one.
                    (None, true) => return self.op == Op::Backup && envval::role_tag(v),
                    (_, false) => Some(v),
                };
                logical.is_some_and(|db| envval::pg_name(db) && !RESERVED_DBS.contains(&db))
            }
        }
    }

    fn value_ok(&self, key: &str, v: &str) -> bool {
        let id = self.id.unwrap_or_default();
        match key {
            "CITE_JOB_ID" => envval::deploy_id(v),
            "PGHOST" => match self.net {
                JobNet::Dbnet => v == format!("cite-{id}-db"),
                JobNet::Admin => v == SHARED_DB,
                JobNet::Xnet(slot) => v == format!("cite-{id}-{slot}-egress-proxy"),
                JobNet::Egress(_) => {
                    (!v.starts_with('.') && envval::egress_host(v)) || envval::ip_literal(v)
                }
            },
            "PGPORT" => match self.net {
                JobNet::Xnet(_) => envval::dec_in(v, *FORWARD_PORTS.start(), *FORWARD_PORTS.end()),
                // The open-mode egress bridge already has general outbound access: the database's own port.
                JobNet::Egress(_) => envval::dec_in(v, 1, 65535),
                _ => v == PG_PORT,
            },
            "PGUSER" => {
                if !self.net.internal() {
                    envval::pg_ident(v)
                } else if self.op.runs_as_job_login() {
                    // Exactly the job login of the database the job names, never the superuser.
                    self.tag
                        .as_deref()
                        .is_some_and(|tag| v == envval::job_login_role(tag))
                } else {
                    v == "postgres"
                }
            }
            // A job login's password is generated for the one job, like every other generated password.
            "PGPASSWORD" if self.net.internal() && self.op.runs_as_job_login() => {
                envval::generated_password(v)
            }
            "PGPASSWORD" => envval::printable(v, 256),
            "PGDATABASE" => self.database_ok(v),
            "PGSSLMODE" => SSL_MODES.contains(&v),
            // A role tag names a database on the node's own servers, so it never travels to an outbound network.
            "CITE_ROLE_TAG" => self.net.internal() && envval::role_tag(v) && self.tag_in_scope(v),
            "CITE_JOB_ACTION" => JOB_ACTIONS.contains(&v),
            "CITE_JOB_PASSWORD" => envval::generated_password(v),
            "CITE_OWNER_ROLE" => v
                .strip_suffix("_owner")
                .is_some_and(|t| envval::role_tag(t) && self.tag_in_scope(t)),
            "CITE_LOGIN_ROLE" => v
                .strip_suffix("_login")
                .is_some_and(|t| envval::role_tag(t) && self.tag_in_scope(t)),
            "CITE_USER_ACTION" => USER_ACTIONS.contains(&v),
            "CITE_USER_LEVEL" => USER_LEVELS.contains(&v),
            "CITE_USER_ROLE" => self.user_role_ok(v),
            "CITE_USER_PASSWORD" => envval::generated_password(v),
            "CITE_USER_CONN_LIMIT" => envval::dec_in(v, 1, 500),
            "CITE_USER_STMT_MS" => envval::dec_in(v, 0, 3_600_000),
            "CITE_USER_IDLE_MS" => envval::dec_in(v, 1_000, 3_600_000),
            "CITE_PG_HBA" => envval::pg_hba(v),
            "CITE_PG_RELOAD" => v == "0" || v == "1",
            _ => false,
        }
    }

    fn tag_in_scope(&self, tag: &str) -> bool {
        match self.site_prefix() {
            Some(prefix) => tag.starts_with(&prefix),
            None => true,
        }
    }

    // `<role tag>_<user>_a|b`, under the same tag the request names.
    fn user_role_ok(&self, v: &str) -> bool {
        let Some(tag) = self.env.get("CITE_ROLE_TAG") else {
            return false;
        };
        let Some(rest) = v
            .strip_prefix(tag.as_str())
            .and_then(|r| r.strip_prefix('_'))
        else {
            return false;
        };
        let Some((user, alt)) = rest.rsplit_once('_') else {
            return false;
        };
        envval::pg_name(user) && (alt == "a" || alt == "b")
    }
}

fn check_job_env(
    op: Op,
    id: Option<&str>,
    net: &JobNet,
    env: Option<&Value>,
) -> Result<Value, String> {
    let (value, map) = env_pairs(env)?;
    let allowed: Vec<&str> = COMMON_JOB_ENV
        .iter()
        .chain(op.extra_env())
        .copied()
        .collect();
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("Env key {key:?} is not allowed"));
        }
    }
    for key in &allowed {
        if !map.contains_key(*key) && !op.optional(key) {
            return Err(format!("Env key {key:?} is missing"));
        }
    }
    if op == Op::JobLogin {
        // A password travels only with the actions that set one.
        let sets_password = matches!(
            map.get("CITE_JOB_ACTION").map(String::as_str),
            Some("open" | "lock")
        );
        if sets_password != map.contains_key("CITE_JOB_PASSWORD") {
            return Err(
                "Env key \"CITE_JOB_PASSWORD\" does not fit the job login action".to_string(),
            );
        }
    }
    if op == Op::Backup && net.internal() != map.contains_key("CITE_ROLE_TAG") {
        return Err(
            "a backup names a role tag exactly when it dumps a database of the node".to_string(),
        );
    }
    if op == Op::User {
        // A password travels only with the actions that set one.
        let sets_password = matches!(
            map.get("CITE_USER_ACTION").map(String::as_str),
            Some("create" | "password")
        );
        if sets_password != map.contains_key("CITE_USER_PASSWORD") {
            return Err("Env key \"CITE_USER_PASSWORD\" does not fit the user action".to_string());
        }
    }
    let ctx = JobCtx {
        op,
        id,
        net,
        env: &map,
        tag: named_tag(op, &map),
    };
    for (key, v) in &map {
        if !ctx.value_ok(key, v) {
            return Err(format!("Env value for {key:?} is not allowed"));
        }
    }
    if op.has_database() && (op != Op::Backup || net.internal()) && ctx.tag.is_none() {
        return Err("the job does not name a role tag".to_string());
    }
    Ok(value)
}

fn validate_job(
    policy: &Policy,
    container: &DataContainer,
    obj: &Map<String, Value>,
    image: &str,
    body: &Value,
) -> Result<(), String> {
    let shared_job = container.role == DataRole::SharedJob;
    let id = container.id.as_deref();
    let op = obj
        .get("Cmd")
        .and_then(Value::as_array)
        .filter(|cmd| cmd.len() == 1)
        .and_then(|cmd| cmd[0].as_str())
        .and_then(Op::parse)
        .ok_or("Cmd is not a known job operation")?;
    let scope_ok = if shared_job {
        op.shared_scope()
    } else {
        op.site_scope()
    };
    if !scope_ok {
        return Err("this job operation does not run in this container".to_string());
    }
    let host = obj
        .get("HostConfig")
        .map(|h| object(h, "HostConfig"))
        .transpose()?
        .ok_or("HostConfig is missing")?;
    let mode = host
        .get("NetworkMode")
        .and_then(Value::as_str)
        .ok_or("NetworkMode is missing")?;
    let net = job_net(policy, id, mode)?;
    if !net_allowed_for(op, &net, shared_job) {
        return Err("HostConfig.NetworkMode is not allowed for this job operation".to_string());
    }
    let env = check_job_env(op, id, &net, obj.get("Env"))?;
    let subpath = match id {
        Some(id) => format!("staging/{id}"),
        None => "staging/_shared".to_string(),
    };
    let mut mounts = vec![mount(
        &policy.backup_volume,
        "/backup",
        Some(&subpath),
        op == Op::Restore,
    )];
    if op == Op::Hba {
        mounts.push(mount(SHARED_CONF, "/conf", None, false));
    }
    let labels = match id {
        Some(id) => site_labels(id, "dbjob"),
        None => shared_labels("pg-shared-job"),
    };
    let want = json!({
        "Image": image,
        "User": "10001:10001",
        "Entrypoint": ["cite-pg-job"],
        "Cmd": obj["Cmd"],
        "Env": env,
        "Labels": labels,
        "Healthcheck": { "Test": ["NONE"] },
        "HostConfig": {
            "ReadonlyRootfs": true,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["ALL"],
            "Tmpfs": { "/tmp": "size=64m,mode=1777,noexec,nosuid,nodev" },
            "Mounts": mounts,
            "NetworkMode": mode,
            "Memory": JOB_MEMORY,
            "MemorySwap": JOB_MEMORY,
            "NanoCpus": JOB_NANO_CPUS,
            "PidsLimit": JOB_PIDS,
            "RestartPolicy": { "Name": "no" },
            "LogConfig": log_config(),
        },
        "NetworkingConfig": { "EndpointsConfig": { mode: {} } },
    });
    match first_difference("body", &want, body) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// Entry point from `spec::validate_container` for every data container name.
pub(crate) fn validate_data_container(
    policy: &Policy,
    container: &DataContainer,
    body: &Value,
) -> Result<(), String> {
    policy.data_gate()?;
    let obj = object(body, "body")?;
    let image = obj
        .get("Image")
        .and_then(Value::as_str)
        .ok_or("Image is missing")?;
    if !policy.is_postgres_image(image) {
        return Err("Image is not allowed for this container".to_string());
    }
    match container.role {
        DataRole::Db | DataRole::SharedDb => validate_db(policy, container, obj, image, body),
        DataRole::DbJob | DataRole::SharedJob => validate_job(policy, container, obj, image, body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const IMAGE: &str = "ghcr.io/seggys116/cite-postgres:0.5.0-pg18";

    fn policy(pairs: &[(&str, &str)]) -> Policy {
        let cfg = Config::from_lookup(|k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        })
        .unwrap();
        Policy::new(&cfg)
    }

    fn check(policy: &Policy, name: &str, body: &Value) -> Result<(), String> {
        let container = policy.data_container(name).expect("a data name");
        validate_data_container(policy, &container, body)
    }

    fn mutated(body: &Value, f: impl Fn(&mut Value)) -> Value {
        let mut copy = body.clone();
        f(&mut copy);
        copy
    }

    fn password() -> String {
        "A".repeat(43)
    }

    fn pg_env() -> Value {
        json!([
            "POSTGRES_USER=postgres",
            format!("POSTGRES_PASSWORD={}", password()),
            "POSTGRES_DB=postgres",
            "PGDATA=/var/lib/postgresql/data/pgdata",
            "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer",
        ])
    }

    fn server_body(network: &str, data: &str, labels: Value, shared: bool) -> Value {
        let mut cmd = vec![
            "postgres",
            "-c",
            "listen_addresses=*",
            "-c",
            "max_connections=100",
            "-c",
            "password_encryption=scram-sha-256",
            "-c",
            "log_connections=on",
            "-c",
            "log_disconnections=on",
            "-c",
            "idle_in_transaction_session_timeout=300000",
        ];
        let mut mounts = vec![json!({
            "Type": "volume", "Source": data,
            "Target": "/var/lib/postgresql/data", "ReadOnly": false,
        })];
        if shared {
            cmd.extend(["-c", "hba_file=/etc/cite-pg/pg_hba.conf"]);
            mounts.push(json!({
                "Type": "volume", "Source": "cite-pg-shared-conf",
                "Target": "/etc/cite-pg", "ReadOnly": true,
            }));
        }
        json!({
            "Image": IMAGE,
            "User": "70:70",
            "Env": pg_env(),
            "Cmd": cmd,
            "Labels": labels,
            "Healthcheck": {
                "Test": ["CMD", "pg_isready", "-q", "-h", "127.0.0.1", "-p", "5432"],
                "Interval": 10_000_000_000u64, "Timeout": 5_000_000_000u64, "Retries": 6,
                "StartPeriod": 120_000_000_000u64, "StartInterval": 1_000_000_000u64,
            },
            "HostConfig": {
                "Init": true,
                "ReadonlyRootfs": true,
                "SecurityOpt": ["no-new-privileges:true"],
                "CapDrop": ["ALL"],
                "Tmpfs": {
                    "/tmp": "size=64m,mode=1777,noexec,nosuid,nodev",
                    "/var/run/postgresql":
                        "size=1m,uid=70,gid=70,mode=0775,noexec,nosuid,nodev",
                },
                "ShmSize": 268435456,
                "Mounts": mounts,
                "NetworkMode": network,
                "Memory": 536870912,
                "MemorySwap": 536870912,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 512,
                "RestartPolicy": { "Name": "unless-stopped" },
                "LogConfig": { "Type": "json-file", "Config": { "max-size": "10m", "max-file": "3" } },
            },
            "NetworkingConfig": { "EndpointsConfig": { network: {} } },
        })
    }

    fn db_body(id: &str) -> Value {
        server_body(
            &format!("cite-{id}-dbnet"),
            &format!("cite-{id}-db-data"),
            json!({ "cite.managed": "true", "cite.site": id, "cite.role": "db" }),
            false,
        )
    }

    fn shared_body() -> Value {
        server_body(
            "cite-pg-shared-admin",
            "cite-pg-shared-data",
            json!({ "cite.managed": "true", "cite.role": "pg-shared" }),
            true,
        )
    }

    #[test]
    fn site_tags_are_ten_lowercase_hex_characters() {
        for id in ["shop", "a", "my-site-2"] {
            let tag = pg_site_tag(id);
            assert_eq!(tag.len(), 10, "{id}");
            assert!(tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        }
        assert_ne!(pg_site_tag("a"), pg_site_tag("b"));
    }

    #[test]
    fn dedicated_database_body_is_accepted_only_exactly() {
        let p = policy(&[]);
        let ok = db_body("shop");
        check(&p, "cite-shop-db", &ok).unwrap();
        // Another site's name with this site's body.
        assert!(check(&p, "cite-other-db", &ok).is_err());
        let cases: Vec<(&str, Value)> = vec![
            (
                "privileged",
                mutated(&ok, |b| b["HostConfig"]["Privileged"] = json!(true)),
            ),
            (
                "cap add",
                mutated(&ok, |b| b["HostConfig"]["CapAdd"] = json!(["NET_ADMIN"])),
            ),
            (
                "ports",
                mutated(&ok, |b| {
                    b["HostConfig"]["PortBindings"] = json!({"5432/tcp": [{}]})
                }),
            ),
            (
                "publish all",
                mutated(&ok, |b| b["HostConfig"]["PublishAllPorts"] = json!(true)),
            ),
            (
                "host network",
                mutated(&ok, |b| b["HostConfig"]["NetworkMode"] = json!("host")),
            ),
            (
                "other dbnet",
                mutated(&ok, |b| {
                    b["HostConfig"]["NetworkMode"] = json!("cite-other-dbnet");
                    b["NetworkingConfig"] = json!({"EndpointsConfig": {"cite-other-dbnet": {}}});
                }),
            ),
            (
                "second endpoint",
                mutated(&ok, |b| {
                    b["NetworkingConfig"]["EndpointsConfig"]["cite-pg-shared-admin"] = json!({});
                }),
            ),
            (
                "host mount",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0] = json!({"Type":"bind","Source":"/","Target":"/var/lib/postgresql/data","ReadOnly":false});
                }),
            ),
            (
                "other site volume",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-other-db-data");
                }),
            ),
            (
                "shared volume",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-pg-shared-data");
                }),
            ),
            (
                "extra mount",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"].as_array_mut().unwrap().push(
                    json!({"Type":"volume","Source":"cite-backups","Target":"/b","ReadOnly":false}),
                );
                }),
            ),
            (
                "read-only data",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["ReadOnly"] = json!(true)
                }),
            ),
            (
                "writable rootfs",
                mutated(&ok, |b| b["HostConfig"]["ReadonlyRootfs"] = json!(false)),
            ),
            ("root user", mutated(&ok, |b| b["User"] = json!("0:0"))),
            (
                "entrypoint",
                mutated(&ok, |b| b["Entrypoint"] = json!(["sh"])),
            ),
            (
                "extra cmd",
                mutated(&ok, |b| {
                    b["Cmd"]
                        .as_array_mut()
                        .unwrap()
                        .extend([json!("-c"), json!("ssl=off")])
                }),
            ),
            (
                "trust env",
                mutated(&ok, |b| {
                    b["Env"][5] = json!("POSTGRES_HOST_AUTH_METHOD=trust")
                }),
            ),
            (
                "extra env",
                mutated(&ok, |b| {
                    b["Env"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("LD_PRELOAD=/x.so"))
                }),
            ),
            (
                "short password",
                mutated(&ok, |b| b["Env"][1] = json!("POSTGRES_PASSWORD=short")),
            ),
            (
                "memory above cap",
                mutated(&ok, |b| {
                    b["HostConfig"]["Memory"] = json!(1i64 << 40);
                    b["HostConfig"]["MemorySwap"] = json!(1i64 << 40);
                }),
            ),
            (
                "swap differs",
                mutated(&ok, |b| b["HostConfig"]["MemorySwap"] = json!(-1)),
            ),
            (
                "too few connections",
                mutated(&ok, |b| b["Cmd"][4] = json!("max_connections=9")),
            ),
            (
                "too many connections",
                mutated(&ok, |b| b["Cmd"][4] = json!("max_connections=1001")),
            ),
            (
                "hba file on a site db",
                mutated(&ok, |b| {
                    b["Cmd"]
                        .as_array_mut()
                        .unwrap()
                        .extend([json!("-c"), json!("hba_file=/etc/cite-pg/pg_hba.conf")])
                }),
            ),
            (
                "job label",
                mutated(&ok, |b| b["Labels"]["cite.role"] = json!("dbjob")),
            ),
            (
                "slot label",
                mutated(&ok, |b| b["Labels"]["cite.slot"] = json!("blue")),
            ),
            (
                "foreign image",
                mutated(&ok, |b| b["Image"] = json!("postgres:18")),
            ),
            (
                "manager image",
                mutated(&ok, |b| {
                    b["Image"] = json!("ghcr.io/seggys116/cite-manager:0.5.0-node22")
                }),
            ),
            (
                "pg 16",
                mutated(&ok, |b| {
                    b["Image"] = json!("ghcr.io/seggys116/cite-postgres:0.5.0-pg16")
                }),
            ),
            (
                "no pg suffix",
                mutated(&ok, |b| {
                    b["Image"] = json!("ghcr.io/seggys116/cite-postgres:0.5.0")
                }),
            ),
            (
                "sysctls",
                mutated(&ok, |b| b["HostConfig"]["Sysctls"] = json!({"a": "b"})),
            ),
            (
                "pid host",
                mutated(&ok, |b| b["HostConfig"]["PidMode"] = json!("host")),
            ),
        ];
        for (what, body) in cases {
            assert!(check(&p, "cite-shop-db", &body).is_err(), "{what}");
        }
        let mut sixteen = ok.clone();
        sixteen["Cmd"][4] = json!("max_connections=1000");
        check(&p, "cite-shop-db", &sixteen).unwrap();
        sixteen["Cmd"][4] = json!("max_connections=0100");
        assert!(check(&p, "cite-shop-db", &sixteen).is_err());
    }

    #[test]
    fn shared_instance_body_is_accepted_only_exactly() {
        let p = policy(&[]);
        let ok = shared_body();
        check(&p, "cite-pg-shared", &ok).unwrap();
        // The hba file is part of the shared instance only.
        let mut no_hba = ok.clone();
        no_hba["Cmd"].as_array_mut().unwrap().truncate(13);
        no_hba["HostConfig"]["Mounts"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        assert!(check(&p, "cite-pg-shared", &no_hba).is_err());
        for (what, body) in [
            (
                "writable conf",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][1]["ReadOnly"] = json!(false)
                }),
            ),
            (
                "site dbnet",
                mutated(&ok, |b| {
                    b["HostConfig"]["NetworkMode"] = json!("cite-shop-dbnet");
                    b["NetworkingConfig"] = json!({"EndpointsConfig": {"cite-shop-dbnet": {}}});
                }),
            ),
            (
                "site labels",
                mutated(&ok, |b| b["Labels"]["cite.site"] = json!("shop")),
            ),
            (
                "other conf",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][1]["Source"] = json!("cite-backups")
                }),
            ),
            (
                "backup volume as data",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-backups")
                }),
            ),
            (
                "site data",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-shop-db-data")
                }),
            ),
        ] {
            assert!(check(&p, "cite-pg-shared", &body).is_err(), "{what}");
        }
        // A site body is never valid for the shared name and the reverse.
        assert!(check(&p, "cite-pg-shared", &db_body("shop")).is_err());
        assert!(check(&p, "cite-shop-db", &ok).is_err());
    }

    fn mount_json(sub: &str, ro: bool) -> Value {
        json!({
            "Type": "volume", "Source": "cite-backups", "Target": "/backup", "ReadOnly": ro,
            "VolumeOptions": { "Subpath": sub },
        })
    }

    // A literal job body, built with no help from the code under test.
    fn job_body(id: Option<&str>, op: &str, net: &str, env: &[(&str, String)], ro: bool) -> Value {
        let (sub, labels) = match id {
            Some(id) => (
                format!("staging/{id}"),
                json!({ "cite.managed": "true", "cite.site": id, "cite.role": "dbjob" }),
            ),
            None => (
                "staging/_shared".to_string(),
                json!({ "cite.managed": "true", "cite.role": "pg-shared-job" }),
            ),
        };
        let mut mounts = vec![mount_json(&sub, ro)];
        if op == "hba" {
            mounts.push(json!({
                "Type": "volume", "Source": "cite-pg-shared-conf",
                "Target": "/conf", "ReadOnly": false,
            }));
        }
        let env: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        json!({
            "Image": IMAGE,
            "User": "10001:10001",
            "Entrypoint": ["cite-pg-job"],
            "Cmd": [op],
            "Env": env,
            "Labels": labels,
            "Healthcheck": { "Test": ["NONE"] },
            "HostConfig": {
                "ReadonlyRootfs": true,
                "SecurityOpt": ["no-new-privileges:true"],
                "CapDrop": ["ALL"],
                "Tmpfs": { "/tmp": "size=64m,mode=1777,noexec,nosuid,nodev" },
                "Mounts": mounts,
                "NetworkMode": net,
                "Memory": 536870912,
                "MemorySwap": 536870912,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 64,
                "RestartPolicy": { "Name": "no" },
                "LogConfig": { "Type": "json-file", "Config": { "max-size": "10m", "max-file": "3" } },
            },
            "NetworkingConfig": { "EndpointsConfig": { net: {} } },
        })
    }

    const JOB: &str = "01HZX3K9M2N4P5Q6R7S8T9V0WX";

    fn internal_env(host: &str, extra: &[(&str, String)]) -> Vec<(&'static str, String)> {
        let mut env = vec![
            ("CITE_JOB_ID", JOB.to_string()),
            ("PGHOST", host.to_string()),
            ("PGPORT", "5432".to_string()),
            ("PGUSER", "postgres".to_string()),
            ("PGPASSWORD", password()),
        ];
        for (k, v) in extra {
            let key: &'static str = match *k {
                "PGDATABASE" => "PGDATABASE",
                "CITE_ROLE_TAG" => "CITE_ROLE_TAG",
                "CITE_OWNER_ROLE" => "CITE_OWNER_ROLE",
                "CITE_LOGIN_ROLE" => "CITE_LOGIN_ROLE",
                "CITE_USER_ACTION" => "CITE_USER_ACTION",
                "CITE_USER_ROLE" => "CITE_USER_ROLE",
                "CITE_USER_LEVEL" => "CITE_USER_LEVEL",
                "CITE_USER_PASSWORD" => "CITE_USER_PASSWORD",
                "CITE_USER_CONN_LIMIT" => "CITE_USER_CONN_LIMIT",
                "CITE_USER_STMT_MS" => "CITE_USER_STMT_MS",
                "CITE_USER_IDLE_MS" => "CITE_USER_IDLE_MS",
                "CITE_PG_HBA" => "CITE_PG_HBA",
                "CITE_PG_RELOAD" => "CITE_PG_RELOAD",
                "CITE_JOB_ACTION" => "CITE_JOB_ACTION",
                "CITE_JOB_PASSWORD" => "CITE_JOB_PASSWORD",
                "PGSSLMODE" => "PGSSLMODE",
                other => panic!("unknown key {other}"),
            };
            env.push((key, v.clone()));
        }
        env
    }

    fn tag(id: &str, db: &str) -> String {
        format!("t{}_{db}", pg_site_tag(id))
    }

    // The env of a job inside the tenant database `tag`: its job login instead of the superuser.
    fn job_login_env(
        host: &str,
        tag: &str,
        extra: &[(&str, String)],
    ) -> Vec<(&'static str, String)> {
        let mut env = internal_env(host, extra);
        for (k, v) in env.iter_mut() {
            if *k == "PGUSER" {
                *v = format!("{tag}_job");
            }
        }
        env
    }

    #[test]
    fn site_jobs_on_the_own_dbnet_are_accepted_per_operation() {
        let p = policy(&[]);
        let id = "shop";
        let net = "cite-shop-dbnet";
        let host = "cite-shop-db";
        let t = tag(id, "app");
        type Case<'a> = (&'a str, bool, Vec<(&'a str, String)>);
        // Inside the tenant database: the job login.
        let tenant: Vec<Case> = vec![
            (
                "backup",
                false,
                vec![("PGDATABASE", "app".into()), ("CITE_ROLE_TAG", t.clone())],
            ),
            (
                "counts",
                false,
                vec![("PGDATABASE", "app".into()), ("CITE_ROLE_TAG", t.clone())],
            ),
            (
                "restore",
                true,
                vec![
                    ("PGDATABASE", "app".into()),
                    ("CITE_OWNER_ROLE", format!("{t}_owner")),
                    ("CITE_LOGIN_ROLE", format!("{t}_login")),
                ],
            ),
            (
                "regrant",
                false,
                vec![("PGDATABASE", "app".into()), ("CITE_ROLE_TAG", t.clone())],
            ),
            (
                "regrant",
                false,
                vec![
                    ("PGDATABASE", "app".into()),
                    ("CITE_ROLE_TAG", t.clone()),
                    ("CITE_USER_ROLE", format!("{t}_report_a")),
                ],
            ),
        ];
        for (op, ro, extra) in tenant {
            let body = job_body(Some(id), op, net, &job_login_env(host, &t, &extra), ro);
            check(&p, "cite-shop-dbjob", &body).unwrap_or_else(|e| panic!("{op}: {e}"));
            // Never as the superuser.
            let su = job_body(Some(id), op, net, &internal_env(host, &extra), ro);
            assert!(
                check(&p, "cite-shop-dbjob", &su).is_err(),
                "{op} as postgres"
            );
        }
        // Everything else: the superuser, in the maintenance database.
        let cases: Vec<Case> = vec![
            (
                "joblogin",
                false,
                vec![
                    ("PGDATABASE", "app".into()),
                    ("CITE_ROLE_TAG", t.clone()),
                    ("CITE_JOB_ACTION", "open".into()),
                    ("CITE_JOB_PASSWORD", password()),
                ],
            ),
            (
                "joblogin",
                false,
                vec![
                    ("PGDATABASE", "app".into()),
                    ("CITE_ROLE_TAG", t.clone()),
                    ("CITE_JOB_ACTION", "lock".into()),
                    ("CITE_JOB_PASSWORD", password()),
                ],
            ),
            (
                "joblogin",
                false,
                vec![
                    ("PGDATABASE", "app".into()),
                    ("CITE_ROLE_TAG", t.clone()),
                    ("CITE_JOB_ACTION", "close".into()),
                ],
            ),
            (
                "freeze",
                false,
                vec![
                    ("PGDATABASE", "app".into()),
                    ("CITE_LOGIN_ROLE", format!("{t}_login")),
                ],
            ),
            (
                "unfreeze",
                false,
                vec![
                    ("PGDATABASE", "app".into()),
                    ("CITE_LOGIN_ROLE", format!("{t}_login")),
                ],
            ),
            (
                "provision",
                false,
                vec![("PGDATABASE", "app".into()), ("CITE_ROLE_TAG", t.clone())],
            ),
            (
                "provision",
                false,
                vec![
                    ("PGDATABASE", "postgres".into()),
                    ("CITE_ROLE_TAG", t.clone()),
                ],
            ),
            (
                "deprovision",
                false,
                vec![
                    ("PGDATABASE", "postgres".into()),
                    ("CITE_ROLE_TAG", t.clone()),
                ],
            ),
        ];
        for (op, ro, extra) in cases {
            let body = job_body(Some(id), op, net, &internal_env(host, &extra), ro);
            check(&p, "cite-shop-dbjob", &body).unwrap_or_else(|e| panic!("{op}: {e}"));
            let as_job = job_body(Some(id), op, net, &job_login_env(host, &t, &extra), ro);
            assert!(
                check(&p, "cite-shop-dbjob", &as_job).is_err(),
                "{op} as the job login"
            );
        }
    }

    #[test]
    fn the_job_login_is_exactly_the_named_databases_and_its_password_is_generated() {
        let p = policy(&[]);
        let t = tag("shop", "app");
        let counts = |user: String, pw: String, role_tag: &str| {
            let mut env = internal_env(
                "cite-shop-db",
                &[
                    ("PGDATABASE", "app".into()),
                    ("CITE_ROLE_TAG", role_tag.to_string()),
                ],
            );
            for (k, v) in env.iter_mut() {
                match *k {
                    "PGUSER" => *v = user.clone(),
                    "PGPASSWORD" => *v = pw.clone(),
                    _ => {}
                }
            }
            job_body(Some("shop"), "counts", "cite-shop-dbnet", &env, false)
        };
        check(
            &p,
            "cite-shop-dbjob",
            &counts(format!("{t}_job"), password(), &t),
        )
        .unwrap();
        let other = tag("shop", "auth");
        for (what, body) in [
            ("superuser", counts("postgres".into(), password(), &t)),
            (
                "another database's job login",
                counts(format!("{other}_job"), password(), &t),
            ),
            ("a user login", counts(format!("{t}_app_a"), password(), &t)),
            (
                "the owner group",
                counts(format!("{t}_owner"), password(), &t),
            ),
            (
                "a short password",
                counts(format!("{t}_job"), "short".into(), &t),
            ),
            (
                "a password outside the generated alphabet",
                counts(format!("{t}_job"), format!("{}!", "A".repeat(42)), &t),
            ),
            (
                "another site's tag",
                counts(
                    format!("{}_job", tag("other", "app")),
                    password(),
                    &tag("other", "app"),
                ),
            ),
        ] {
            assert!(check(&p, "cite-shop-dbjob", &body).is_err(), "{what}");
        }
        // Counts without a tag no longer pass.
        let untagged = job_body(
            Some("shop"),
            "counts",
            "cite-shop-dbnet",
            &job_login_env("cite-shop-db", &t, &[("PGDATABASE", "app".into())]),
            false,
        );
        assert!(check(&p, "cite-shop-dbjob", &untagged).is_err());
    }

    #[test]
    fn a_job_login_password_travels_only_with_open_and_lock() {
        let p = policy(&[]);
        let t = tag("shop", "app");
        let run = |action: &str, pw: Option<String>, role_tag: &str| {
            let mut extra = vec![
                ("PGDATABASE", "app".to_string()),
                ("CITE_ROLE_TAG", role_tag.to_string()),
                ("CITE_JOB_ACTION", action.to_string()),
            ];
            if let Some(pw) = pw {
                extra.push(("CITE_JOB_PASSWORD", pw));
            }
            job_body(
                Some("shop"),
                "joblogin",
                "cite-shop-dbnet",
                &internal_env("cite-shop-db", &extra),
                false,
            )
        };
        check(&p, "cite-shop-dbjob", &run("open", Some(password()), &t)).unwrap();
        check(&p, "cite-shop-dbjob", &run("lock", Some(password()), &t)).unwrap();
        check(&p, "cite-shop-dbjob", &run("close", None, &t)).unwrap();
        for (what, body) in [
            ("open without a password", run("open", None, &t)),
            ("close with a password", run("close", Some(password()), &t)),
            ("unknown action", run("grant", Some(password()), &t)),
            ("short password", run("open", Some("pw".into()), &t)),
            (
                "another site's tag",
                run("open", Some(password()), &tag("other", "app")),
            ),
        ] {
            assert!(check(&p, "cite-shop-dbjob", &body).is_err(), "{what}");
        }
        // The shared job opens the login of any tenant (the instance backup), on the admin network only.
        let shared = job_body(
            None,
            "joblogin",
            "cite-pg-shared-admin",
            &internal_env(
                "cite-pg-shared",
                &[
                    ("PGDATABASE", tag("other", "app")),
                    ("CITE_ROLE_TAG", tag("other", "app")),
                    ("CITE_JOB_ACTION", "close".into()),
                ],
            ),
            false,
        );
        check(&p, "cite-pg-shared-job", &shared).unwrap();
    }

    #[test]
    fn user_jobs_tie_the_role_to_the_tag_and_the_password_to_the_action() {
        let p = policy(&[]);
        let t = tag("shop", "app");
        let user = |action: &str, password_set: bool, role: String| {
            let mut extra = vec![
                ("PGDATABASE", "app".to_string()),
                ("CITE_ROLE_TAG", t.clone()),
                ("CITE_USER_ACTION", action.to_string()),
                ("CITE_USER_ROLE", role),
                ("CITE_USER_LEVEL", "readwrite".to_string()),
                ("CITE_USER_CONN_LIMIT", "20".to_string()),
                ("CITE_USER_STMT_MS", "30000".to_string()),
                ("CITE_USER_IDLE_MS", "60000".to_string()),
            ];
            if password_set {
                extra.push(("CITE_USER_PASSWORD", password()));
            }
            job_body(
                Some("shop"),
                "user",
                "cite-shop-dbnet",
                &internal_env("cite-shop-db", &extra),
                false,
            )
        };
        check(
            &p,
            "cite-shop-dbjob",
            &user("create", true, format!("{t}_app_a")),
        )
        .unwrap();
        check(
            &p,
            "cite-shop-dbjob",
            &user("password", true, format!("{t}_app_b")),
        )
        .unwrap();
        check(
            &p,
            "cite-shop-dbjob",
            &user("disable", false, format!("{t}_app_a")),
        )
        .unwrap();
        assert!(
            check(
                &p,
                "cite-shop-dbjob",
                &user("create", false, format!("{t}_app_a"))
            )
            .is_err()
        );
        assert!(
            check(
                &p,
                "cite-shop-dbjob",
                &user("drop", true, format!("{t}_app_a"))
            )
            .is_err()
        );
        assert!(
            check(
                &p,
                "cite-shop-dbjob",
                &user("explode", false, format!("{t}_app_a"))
            )
            .is_err()
        );
        assert!(
            check(
                &p,
                "cite-shop-dbjob",
                &user("drop", false, format!("{t}_app_c"))
            )
            .is_err()
        );
        let other = tag("other", "app");
        assert!(
            check(
                &p,
                "cite-shop-dbjob",
                &user("drop", false, format!("{other}_app_a"))
            )
            .is_err()
        );
        assert!(
            check(
                &p,
                "cite-shop-dbjob",
                &user("drop", false, "postgres".to_string())
            )
            .is_err()
        );
    }

    #[test]
    fn site_jobs_cannot_name_another_sites_roles_databases_or_paths() {
        let p = policy(&[]);
        let mine = tag("shop", "app");
        let theirs = tag("other", "app");
        let ok_env = internal_env(
            "cite-shop-db",
            &[
                ("PGDATABASE", "app".into()),
                ("CITE_ROLE_TAG", mine.clone()),
            ],
        );
        let ok = job_body(Some("shop"), "provision", "cite-shop-dbnet", &ok_env, false);
        check(&p, "cite-shop-dbjob", &ok).unwrap();
        let foreign_tag = internal_env(
            "cite-shop-db",
            &[
                ("PGDATABASE", "app".into()),
                ("CITE_ROLE_TAG", theirs.clone()),
            ],
        );
        for (what, body) in [
            (
                "foreign role tag",
                job_body(
                    Some("shop"),
                    "provision",
                    "cite-shop-dbnet",
                    &foreign_tag,
                    false,
                ),
            ),
            (
                "foreign dbnet",
                job_body(
                    Some("shop"),
                    "provision",
                    "cite-other-dbnet",
                    &ok_env,
                    false,
                ),
            ),
            (
                "foreign host",
                job_body(
                    Some("shop"),
                    "provision",
                    "cite-shop-dbnet",
                    &internal_env(
                        "cite-other-db",
                        &[
                            ("PGDATABASE", "app".into()),
                            ("CITE_ROLE_TAG", mine.clone()),
                        ],
                    ),
                    false,
                ),
            ),
            (
                "shared host on the own dbnet",
                job_body(
                    Some("shop"),
                    "provision",
                    "cite-shop-dbnet",
                    &internal_env(
                        "cite-pg-shared",
                        &[
                            ("PGDATABASE", "app".into()),
                            ("CITE_ROLE_TAG", mine.clone()),
                        ],
                    ),
                    false,
                ),
            ),
            (
                "foreign subpath",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] =
                        json!("staging/other");
                }),
            ),
            (
                "whole backup volume",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("VolumeOptions");
                }),
            ),
            (
                "catalog subpath",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] = json!("sites/shop");
                }),
            ),
            (
                "shared staging for a site job",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] =
                        json!("staging/_shared");
                }),
            ),
            (
                "traversal",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] =
                        json!("staging/shop/../other");
                }),
            ),
            (
                "other volume",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-shop-db-data")
                }),
            ),
            (
                "bind mount",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0] =
                        json!({"Type":"bind","Source":"/","Target":"/backup","ReadOnly":false});
                }),
            ),
            (
                "privileged",
                mutated(&ok, |b| b["HostConfig"]["Privileged"] = json!(true)),
            ),
            (
                "cap add",
                mutated(&ok, |b| b["HostConfig"]["CapAdd"] = json!(["SYS_ADMIN"])),
            ),
            (
                "ports",
                mutated(&ok, |b| {
                    b["HostConfig"]["PortBindings"] = json!({"1/tcp": [{}]})
                }),
            ),
            ("root", mutated(&ok, |b| b["User"] = json!("0:0"))),
            (
                "postgres user",
                mutated(&ok, |b| b["User"] = json!("70:70")),
            ),
            (
                "entrypoint",
                mutated(&ok, |b| b["Entrypoint"] = json!(["sh", "-c"])),
            ),
            (
                "restart",
                mutated(&ok, |b| {
                    b["HostConfig"]["RestartPolicy"] = json!({"Name": "always"})
                }),
            ),
            (
                "more memory",
                mutated(&ok, |b| {
                    b["HostConfig"]["Memory"] = json!(1i64 << 34);
                    b["HostConfig"]["MemorySwap"] = json!(1i64 << 34);
                }),
            ),
            (
                "extra endpoint",
                mutated(&ok, |b| {
                    b["NetworkingConfig"]["EndpointsConfig"]["cite-pg-shared-admin"] = json!({});
                }),
            ),
            (
                "extra cmd arg",
                mutated(&ok, |b| b["Cmd"] = json!(["provision", "--x"])),
            ),
            ("unknown op", mutated(&ok, |b| b["Cmd"] = json!(["exec"]))),
            (
                "job label as db",
                mutated(&ok, |b| b["Labels"]["cite.role"] = json!("db")),
            ),
        ] {
            assert!(check(&p, "cite-shop-dbjob", &body).is_err(), "{what}");
        }
    }

    #[test]
    fn env_values_of_a_job_are_checked_one_by_one() {
        let p = policy(&[]);
        let mine = tag("shop", "app");
        let base = |overrides: &[(&str, &str)], drop: &[&str]| {
            let mut env: Vec<(&str, String)> = internal_env(
                "cite-shop-db",
                &[
                    ("PGDATABASE", "app".into()),
                    ("CITE_ROLE_TAG", mine.clone()),
                ],
            );
            env.retain(|(k, _)| !drop.contains(k));
            for (k, v) in overrides {
                if let Some(slot) = env.iter_mut().find(|(key, _)| key == k) {
                    slot.1 = v.to_string();
                }
            }
            job_body(Some("shop"), "provision", "cite-shop-dbnet", &env, false)
        };
        check(&p, "cite-shop-dbjob", &base(&[], &[])).unwrap();
        for (what, body) in [
            ("bad job id", base(&[("CITE_JOB_ID", "not-a-ulid")], &[])),
            ("odd port", base(&[("PGPORT", "5433")], &[])),
            ("non-postgres user", base(&[("PGUSER", "app")], &[])),
            ("control in password", base(&[("PGPASSWORD", "a\nb")], &[])),
            ("empty password", base(&[("PGPASSWORD", "")], &[])),
            (
                "long password",
                base(&[("PGPASSWORD", &"x".repeat(257))], &[]),
            ),
            ("other database", base(&[("PGDATABASE", "other")], &[])),
            (
                "template database",
                base(&[("PGDATABASE", "template1")], &[]),
            ),
            (
                "tag without database",
                base(
                    &[("CITE_ROLE_TAG", &format!("t{}", pg_site_tag("shop")))],
                    &[],
                ),
            ),
            ("missing password", base(&[], &["PGPASSWORD"])),
            ("missing tag", base(&[], &["CITE_ROLE_TAG"])),
            ("missing host", base(&[], &["PGHOST"])),
        ] {
            assert!(check(&p, "cite-shop-dbjob", &body).is_err(), "{what}");
        }
        let mut dup = base(&[], &[]);
        dup["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("PGPORT=5432"));
        assert!(check(&p, "cite-shop-dbjob", &dup).is_err());
        let mut extra = base(&[], &[]);
        extra["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("PGSSLMODE=disable"));
        assert!(
            check(&p, "cite-shop-dbjob", &extra).is_err(),
            "sslmode belongs to backup"
        );
        let mut shell = base(&[], &[]);
        shell["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("LD_PRELOAD=/x.so"));
        assert!(check(&p, "cite-shop-dbjob", &shell).is_err());
    }

    #[test]
    fn instance_wide_operations_run_only_in_the_shared_job() {
        let p = policy(&[]);
        let hba =
            "_admin|172.20.0.0/16;".to_string() + &format!("{}|172.21.0.0/16", tag("shop", "app"));
        let env = |extra: &[(&str, String)]| internal_env("cite-pg-shared", extra);
        let ok = job_body(
            None,
            "hba",
            "cite-pg-shared-admin",
            &env(&[("CITE_PG_HBA", hba.clone()), ("CITE_PG_RELOAD", "1".into())]),
            false,
        );
        check(&p, "cite-pg-shared-job", &ok).unwrap();
        for op in ["sizes", "globals"] {
            let body = job_body(None, op, "cite-pg-shared-admin", &env(&[]), false);
            check(&p, "cite-pg-shared-job", &body).unwrap_or_else(|e| panic!("{op}: {e}"));
            // Never in a site job, not even on the admin network.
            let site = job_body(Some("shop"), op, "cite-pg-shared-admin", &env(&[]), false);
            assert!(check(&p, "cite-shop-dbjob", &site).is_err(), "{op}");
        }
        let site_hba = job_body(
            Some("shop"),
            "hba",
            "cite-pg-shared-admin",
            &env(&[("CITE_PG_HBA", hba.clone()), ("CITE_PG_RELOAD", "1".into())]),
            false,
        );
        assert!(check(&p, "cite-shop-dbjob", &site_hba).is_err());
        // The shared job dumps a tenant database (the instance backup) but cannot restore one, and cannot leave
        // the admin network.
        let tenant = tag("shop", "app");
        let backup = job_body(
            None,
            "backup",
            "cite-pg-shared-admin",
            &job_login_env(
                "cite-pg-shared",
                &tenant,
                &[
                    ("PGDATABASE", tenant.clone()),
                    ("CITE_ROLE_TAG", tenant.clone()),
                ],
            ),
            false,
        );
        check(&p, "cite-pg-shared-job", &backup).unwrap();
        let system_backup = job_body(
            None,
            "backup",
            "cite-pg-shared-admin",
            &job_login_env(
                "cite-pg-shared",
                &tenant,
                &[
                    ("PGDATABASE", "postgres".into()),
                    ("CITE_ROLE_TAG", tenant.clone()),
                ],
            ),
            false,
        );
        assert!(check(&p, "cite-pg-shared-job", &system_backup).is_err());
        let off_net = job_body(
            None,
            "sizes",
            "cite-shop-dbnet",
            &internal_env("cite-shop-db", &[]),
            false,
        );
        assert!(check(&p, "cite-pg-shared-job", &off_net).is_err());
        // The conf volume is writable only for hba, and only that op mounts it.
        for (what, body) in [
            (
                "read-only conf",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][1]["ReadOnly"] = json!(true)
                }),
            ),
            (
                "conf source",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][1]["Source"] = json!("cite-pg-shared-data")
                }),
            ),
            (
                "conf target",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][1]["Target"] = json!("/etc")
                }),
            ),
            (
                "no conf",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"].as_array_mut().unwrap().pop();
                }),
            ),
            (
                "site subpath",
                mutated(&ok, |b| {
                    b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] = json!("staging/shop")
                }),
            ),
        ] {
            assert!(check(&p, "cite-pg-shared-job", &body).is_err(), "{what}");
        }
        let with_conf = job_body(None, "sizes", "cite-pg-shared-admin", &env(&[]), false);
        let mut conf_on_sizes = with_conf.clone();
        conf_on_sizes["HostConfig"]["Mounts"].as_array_mut().unwrap().push(json!({
            "Type": "volume", "Source": "cite-pg-shared-conf", "Target": "/conf", "ReadOnly": false,
        }));
        assert!(check(&p, "cite-pg-shared-job", &conf_on_sizes).is_err());
    }

    #[test]
    fn shared_job_provisioning_names_a_tenant_database_or_the_maintenance_one() {
        let p = policy(&[]);
        let t = tag("shop", "app");
        let run = |db: &str, role_tag: &str| {
            job_body(
                None,
                "provision",
                "cite-pg-shared-admin",
                &internal_env(
                    "cite-pg-shared",
                    &[
                        ("PGDATABASE", db.into()),
                        ("CITE_ROLE_TAG", role_tag.into()),
                    ],
                ),
                false,
            )
        };
        check(&p, "cite-pg-shared-job", &run(&t, &t)).unwrap();
        check(&p, "cite-pg-shared-job", &run("postgres", &t)).unwrap();
        assert!(check(&p, "cite-pg-shared-job", &run("app", &t)).is_err());
        assert!(check(&p, "cite-pg-shared-job", &run(&tag("other", "app"), &t)).is_err());
        assert!(check(&p, "cite-pg-shared-job", &run(&t, "app")).is_err());
        // A site job on the admin network reaches only the databases carrying its own tag.
        let site = |db: &str, role_tag: &str| {
            job_body(
                Some("shop"),
                "provision",
                "cite-pg-shared-admin",
                &internal_env(
                    "cite-pg-shared",
                    &[
                        ("PGDATABASE", db.into()),
                        ("CITE_ROLE_TAG", role_tag.into()),
                    ],
                ),
                false,
            )
        };
        check(&p, "cite-shop-dbjob", &site(&t, &t)).unwrap();
        let theirs = tag("other", "app");
        assert!(check(&p, "cite-shop-dbjob", &site(&theirs, &theirs)).is_err());
        assert!(check(&p, "cite-shop-dbjob", &site(&theirs, &t)).is_err());
    }

    #[test]
    fn admin_network_backups_reach_only_the_sites_own_tenant_databases() {
        let p = policy(&[]);
        // The tag a backup names is its database's (or the site's own app tag when the name is no tag at all).
        let run = |db: &str| {
            let role_tag = if envval::role_tag(db) {
                db.to_string()
            } else {
                tag("shop", "app")
            };
            job_body(
                Some("shop"),
                "backup",
                "cite-pg-shared-admin",
                &job_login_env(
                    "cite-pg-shared",
                    &role_tag,
                    &[
                        ("PGDATABASE", db.into()),
                        ("CITE_ROLE_TAG", role_tag.clone()),
                    ],
                ),
                false,
            )
        };
        check(&p, "cite-shop-dbjob", &run(&tag("shop", "app"))).unwrap();
        assert!(check(&p, "cite-shop-dbjob", &run(&tag("other", "app"))).is_err());
        assert!(check(&p, "cite-shop-dbjob", &run("postgres")).is_err());
        assert!(check(&p, "cite-shop-dbjob", &run("app")).is_err());
        // Any other database under the site's own tag is the site's own.
        check(&p, "cite-shop-dbjob", &run(&tag("shop", "auth"))).unwrap();
        assert!(
            check(
                &p,
                "cite-shop-dbjob",
                &run(&format!("t{}_", pg_site_tag("shop")))
            )
            .is_err()
        );
    }

    #[test]
    fn the_shared_job_backs_up_one_tenant_database_on_the_admin_network_only() {
        let p = policy(&[]);
        let run = |db: &str, net: &str, host: &str| {
            let role_tag = if envval::role_tag(db) {
                db.to_string()
            } else {
                tag("shop", "app")
            };
            job_body(
                None,
                "backup",
                net,
                &job_login_env(
                    host,
                    &role_tag,
                    &[
                        ("PGDATABASE", db.into()),
                        ("CITE_ROLE_TAG", role_tag.clone()),
                    ],
                ),
                false,
            )
        };
        let t = tag("shop", "app");
        check(
            &p,
            "cite-pg-shared-job",
            &run(&t, "cite-pg-shared-admin", "cite-pg-shared"),
        )
        .unwrap();
        check(
            &p,
            "cite-pg-shared-job",
            &run(
                &tag("other", "auth"),
                "cite-pg-shared-admin",
                "cite-pg-shared",
            ),
        )
        .unwrap();
        // Never a system database or a bare logical name.
        for db in [
            "postgres",
            "template0",
            "template1",
            "app",
            "t0123456789_",
            "t0123456789_App",
        ] {
            assert!(
                check(
                    &p,
                    "cite-pg-shared-job",
                    &run(db, "cite-pg-shared-admin", "cite-pg-shared")
                )
                .is_err(),
                "{db}"
            );
        }
        // Never another network.
        for net in [
            "cite-shop-dbnet",
            "cite-shop-blue-xnet",
            "cite-shop-blue-egress",
            "bridge",
        ] {
            assert!(
                check(&p, "cite-pg-shared-job", &run(&t, net, "cite-pg-shared")).is_err(),
                "{net}"
            );
        }
        assert!(
            check(
                &p,
                "cite-pg-shared-job",
                &run(&t, "cite-pg-shared-admin", "cite-shop-db")
            )
            .is_err()
        );
        // The other per-site operations stay out of the shared job.
        let counts = job_body(
            None,
            "counts",
            "cite-pg-shared-admin",
            &job_login_env(
                "cite-pg-shared",
                &t,
                &[("PGDATABASE", t.clone()), ("CITE_ROLE_TAG", t.clone())],
            ),
            false,
        );
        assert!(check(&p, "cite-pg-shared-job", &counts).is_err());
    }

    #[test]
    fn the_open_egress_bridge_accepts_any_port_but_internal_networks_keep_theirs() {
        let open = policy(&[("CITE_STACK_EGRESS_MODE", "open")]);
        let direct = |port: &str| {
            job_body(
                Some("shop"),
                "backup",
                "cite-shop-blue-egress",
                &external_env("db.example.com", port, "u"),
                false,
            )
        };
        for port in ["1", "5432", "6543", "15432", "65535"] {
            check(&open, "cite-shop-dbjob", &direct(port))
                .unwrap_or_else(|e| panic!("{port}: {e}"));
        }
        for port in ["0", "65536", "05432", "-1", "54 32", "", "99999999999"] {
            assert!(
                check(&open, "cite-shop-dbjob", &direct(port)).is_err(),
                "{port:?}"
            );
        }
        // Dedicated and shared networks stay on 5432.
        let internal = job_body(
            Some("shop"),
            "backup",
            "cite-shop-dbnet",
            &[
                ("CITE_JOB_ID", JOB.to_string()),
                ("PGHOST", "cite-shop-db".to_string()),
                ("PGPORT", "6543".to_string()),
                ("PGUSER", "postgres".to_string()),
                ("PGPASSWORD", password()),
                ("PGDATABASE", "app".to_string()),
            ],
            false,
        );
        assert!(check(&open, "cite-shop-dbjob", &internal).is_err());
    }

    fn external_env(host: &str, port: &str, user: &str) -> Vec<(&'static str, String)> {
        vec![
            ("CITE_JOB_ID", JOB.to_string()),
            ("PGHOST", host.to_string()),
            ("PGPORT", port.to_string()),
            ("PGUSER", user.to_string()),
            ("PGPASSWORD", "s3cr3t pass!".to_string()),
            ("PGDATABASE", "billing".to_string()),
            ("PGSSLMODE", "verify-full".to_string()),
        ]
    }

    #[test]
    fn external_backups_follow_the_nodes_egress_mode() {
        let filtered = policy(&[]);
        let open = policy(&[("CITE_STACK_EGRESS_MODE", "open")]);
        let off = policy(&[("CITE_STACK_EGRESS_MODE", "off")]);
        let xnet = job_body(
            Some("shop"),
            "backup",
            "cite-shop-blue-xnet",
            &external_env("cite-shop-blue-egress-proxy", "15432", "report-user"),
            false,
        );
        check(&filtered, "cite-shop-dbjob", &xnet).unwrap();
        assert!(check(&open, "cite-shop-dbjob", &xnet).is_err());
        assert!(check(&off, "cite-shop-dbjob", &xnet).is_err());
        for (what, host, port) in [
            ("direct host on xnet", "db.example.com", "15432"),
            ("other proxy", "cite-other-blue-egress-proxy", "15432"),
            ("other slot proxy", "cite-shop-green-egress-proxy", "15432"),
            (
                "postgres port on xnet",
                "cite-shop-blue-egress-proxy",
                "5432",
            ),
            (
                "forward port too high",
                "cite-shop-blue-egress-proxy",
                "15440",
            ),
            (
                "forward port too low",
                "cite-shop-blue-egress-proxy",
                "15431",
            ),
        ] {
            let body = job_body(
                Some("shop"),
                "backup",
                "cite-shop-blue-xnet",
                &external_env(host, port, "u"),
                false,
            );
            assert!(
                check(&filtered, "cite-shop-dbjob", &body).is_err(),
                "{what}"
            );
        }
        let direct = |host: &str, user: &str| {
            job_body(
                Some("shop"),
                "backup",
                "cite-shop-green-egress",
                &external_env(host, "5432", user),
                false,
            )
        };
        for host in ["db.example.com", "203.0.113.9", "2001:db8::5"] {
            check(&open, "cite-shop-dbjob", &direct(host, "u"))
                .unwrap_or_else(|e| panic!("{host}: {e}"));
            assert!(check(&filtered, "cite-shop-dbjob", &direct(host, "u")).is_err());
        }
        for host in [
            "DB.example.com",
            ".example.com",
            "db example",
            "0x7f.1",
            "2130706433",
            "[::1]",
            "db.example.com.",
        ] {
            assert!(
                check(&open, "cite-shop-dbjob", &direct(host, "u")).is_err(),
                "{host}"
            );
        }
        assert!(
            check(
                &open,
                "cite-shop-dbjob",
                &direct("db.example.com", "bad user")
            )
            .is_err()
        );
        assert!(check(&open, "cite-shop-dbjob", &direct("db.example.com", "")).is_err());
        // Only a backup may leave the node: restore and the rest stay on the internal networks.
        let restore = job_body(
            Some("shop"),
            "counts",
            "cite-shop-green-egress",
            &external_env("db.example.com", "5432", "u"),
            false,
        );
        assert!(check(&open, "cite-shop-dbjob", &restore).is_err());
        // Another site's outbound network is never reachable.
        let foreign = job_body(
            Some("shop"),
            "backup",
            "cite-other-green-egress",
            &external_env("db.example.com", "5432", "u"),
            false,
        );
        assert!(check(&open, "cite-shop-dbjob", &foreign).is_err());
    }

    #[test]
    fn hba_requires_the_cidr_floor_and_unique_tenant_entries() {
        let p = policy(&[]);
        let t = tag("shop", "app");
        let run = |hba: &str, reload: &str| {
            job_body(
                None,
                "hba",
                "cite-pg-shared-admin",
                &internal_env(
                    "cite-pg-shared",
                    &[
                        ("CITE_PG_HBA", hba.into()),
                        ("CITE_PG_RELOAD", reload.into()),
                    ],
                ),
                false,
            )
        };
        check(
            &p,
            "cite-pg-shared-job",
            &run(&format!("{t}|172.20.0.0/16"), "0"),
        )
        .unwrap();
        for bad in [
            format!("{t}|0.0.0.0/0"),
            format!("{t}|10.0.0.0/7"),
            format!("{t}|172.20.0.0"),
            format!("{t}|fd00::/47"),
            format!("{t}|172.20.0.0/16;{t}|172.20.0.0/16"),
            format!("{t}|172.20.0.0/16;_admin|172.19.0.0/16"),
            "all|172.20.0.0/16".to_string(),
            format!("{t}|172.20.0.0/16 reject"),
            format!("{t}|172.20.0.0/16;"),
            String::new(),
        ] {
            assert!(
                check(&p, "cite-pg-shared-job", &run(&bad, "0")).is_err(),
                "{bad:?}"
            );
        }
        assert!(
            check(
                &p,
                "cite-pg-shared-job",
                &run(&format!("{t}|172.20.0.0/16"), "2")
            )
            .is_err()
        );
    }

    #[test]
    fn data_names_are_refused_when_data_services_are_off() {
        let off = policy(&[("CITE_PROXY_DATA", "false")]);
        let container = off.data_container("cite-shop-db").unwrap();
        let err = validate_data_container(&off, &container, &db_body("shop")).unwrap_err();
        assert!(err.contains("CITE_PROXY_DATA=false"), "{err}");
        let shared = off.data_container("cite-pg-shared").unwrap();
        assert!(validate_data_container(&off, &shared, &shared_body()).is_err());
        assert!(!off.is_postgres_image(IMAGE));
        assert!(policy(&[]).is_postgres_image(IMAGE));
    }
}
