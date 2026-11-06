use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cite_core::parse_poll_interval;
use cite_edge::model::{Site, Slot, Source, Target};
use cite_edge::status::{BuildEnvPatch, LogLine, ManagerReport};
use cite_edge::validate::is_valid_id;
use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::{ConnectorConfig, NodeToken};
use crate::error::{ConnectorError, Result};

// Volume subpath mounts need Engine API 1.45 (Docker Engine 26).
const API: &str = "/v1.45";
const MAX_BODY: usize = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(3);
const PULL_TIMEOUT: Duration = Duration::from_secs(600);
const INIT_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_GRACE_SECS: &str = "10";
const STOP_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_POLL: Duration = Duration::from_secs(60);
const DEFAULT_POLL: &str = "5m";
const DEFAULT_BRANCH: &str = "main";
const DEFAULT_NODE_MAJOR: u8 = 22;
const NODE_MAJORS: [u8; 2] = [22, 24];
const MAX_REF_LEN: usize = 100;
const MAX_TOKEN_LEN: usize = 512;
const MAX_GITHUB_URL_LEN: usize = 200;
pub const DEFAULT_HAPROXY_CONTAINER: &str = "cite-node-haproxy";

const GIB: i64 = 1024 * 1024 * 1024;
const MIB: i64 = 1024 * 1024;
const MANAGER_MEMORY: i64 = 4 * GIB;
const MANAGER_NANO_CPUS: i64 = 2_000_000_000;
const MANAGER_PIDS: i64 = 2048;
const EXECUTOR_MEMORY: i64 = 2 * GIB;
const EXECUTOR_NANO_CPUS: i64 = 2_000_000_000;
const EXECUTOR_PIDS: i64 = 256;
const MIN_MEMORY: i64 = 256 * MIB;
// The Docker proxy refuses less than a quarter CPU (MIN_STACK_NANO_CPUS).
const MIN_NANO_CPUS: i64 = 250_000_000;
const MIN_CPUS: f64 = 0.25;
const MAX_CPUS: f64 = 1024.0;
// The Docker proxy's own maximums when CITE_STACK_MAX_MEM and CITE_STACK_MAX_CPUS are unset, and its ceiling.
const DEFAULT_MAX_MEMORY: i64 = 16 * GIB;
const DEFAULT_MAX_NANO_CPUS: i64 = 8_000_000_000;
const CEILING_MEMORY: i64 = 1024 * GIB;

const MAX_REPORT_BYTES: usize = 4096;
const MAX_LOG_TAIL: u32 = 1000;
const MAX_LOG_LINE: usize = 4096;
const MAX_LOG_TOTAL: usize = 1024 * 1024;
const MIN_REDACT_LEN: usize = 4;
const MIN_TOKEN_TAIL: usize = 8;
const TOKEN_PREFIXES: [&str; 6] = ["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"];
const REDACTED: &str = "[REDACTED]";
const MAX_DEPLOY_ID_LEN: usize = 64;

// Site settings the manager reads from its env, as (Source field, env key) in the order the proxy rebuilds them.
const SETTING_KEYS: [(&str, &str); 10] = [
    ("root_dir", "CITE_ROOT_DIR"),
    ("output_dir", "CITE_OUTPUT_DIR"),
    ("spa_fallback", "CITE_SPA_FALLBACK"),
    ("package_manager", "CITE_PACKAGE_MANAGER"),
    ("rendering", "CITE_RENDERING"),
    ("framework", "CITE_FRAMEWORK"),
    ("prune", "CITE_PRUNE"),
    ("install_command", "CITE_INSTALL_COMMAND"),
    ("build_command", "CITE_BUILD_COMMAND"),
    ("start_command", "CITE_START_COMMAND"),
];
// Keys whose removal from the desired spec must recreate a container that still carries them.
const DEPLOY_ID_KEY: &str = "CITE_DEPLOY_ID";
const BUILD_ENV_KEY: &str = "CITE_BUILD_ENV_JSON";
const RUNTIME_ENV_KEY: &str = "CITE_RUNTIME_ENV_JSON";
// Env entries safe to show a caller; the token and the build and runtime env JSON stay out.
const VISIBLE_KEYS: [&str; 5] = [
    DEPLOY_ID_KEY,
    "CITE_REPO",
    "CITE_BRANCH",
    "CITE_NODE",
    "CITE_POLL_INTERVAL",
];

const FORGE_KEY: &str = "CITE_FORGE";
const FORGE_API_URL_KEY: &str = "CITE_FORGE_API_URL";
const MAX_FORGE_LEN: usize = 32;

/// The operator's forge choice pushed to every manager; unset keeps GitHub and adds no env.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forge {
    pub name: Option<String>,
    pub api_url: Option<String>,
}

impl Forge {
    pub fn from_env() -> Result<Forge> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Forge> {
        let set = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let forge = Forge {
            name: set("CITE_STACK_FORGE"),
            api_url: set("CITE_STACK_FORGE_API_URL"),
        };
        forge.validate()?;
        if let Some(warning) = forge.missing_api_url() {
            tracing::warn!("{warning}");
        }
        Ok(forge)
    }

    // Only GitHub has a well-known API host, so any other forge without an API URL cannot reach its server.
    fn missing_api_url(&self) -> Option<String> {
        let name = self.name.as_deref()?;
        (name != "github" && self.api_url.is_none()).then(|| {
            format!(
                "CITE_STACK_FORGE is {name} but CITE_STACK_FORGE_API_URL is not set, so managers have no API address for that forge"
            )
        })
    }

    fn validate(&self) -> Result<()> {
        if let Some(name) = self.name.as_deref() {
            let ok = name.len() <= MAX_FORGE_LEN
                && name.starts_with(|c: char| c.is_ascii_lowercase())
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !ok {
                return Err(ConnectorError::BadRequest(format!(
                    "CITE_STACK_FORGE {name:?} is not a lowercase slug"
                )));
            }
        }
        if let Some(url) = self.api_url.as_deref() {
            validate_github_api_url(url).map_err(|e| {
                ConnectorError::BadRequest(format!("CITE_STACK_FORGE_API_URL: {e}"))
            })?;
        }
        Ok(())
    }

    fn env(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(n) = self.name.as_deref() {
            out.push(format!("{FORGE_KEY}={n}"));
        }
        if let Some(u) = self.api_url.as_deref() {
            out.push(format!("{FORGE_API_URL_KEY}={u}"));
        }
        out
    }
}

fn is_setting_key(key: &str) -> bool {
    key == FORGE_KEY
        || key == FORGE_API_URL_KEY
        || key == DEPLOY_ID_KEY
        || key == BUILD_ENV_KEY
        || key == RUNTIME_ENV_KEY
        || SETTING_KEYS.iter().any(|(_, k)| *k == key)
}

fn env_key(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(k, _)| k)
}

// The manager env entries for the site settings that are set, nothing for the ones left unset.
pub fn setting_env(source: &Source) -> Vec<String> {
    let value = serde_json::to_value(source).unwrap_or(Value::Null);
    SETTING_KEYS
        .iter()
        .filter_map(|(field, key)| match &value[*field] {
            Value::String(s) if !s.is_empty() => Some(format!("{key}={s}")),
            Value::Bool(b) => Some(format!("{key}={b}")),
            Value::Number(n) => Some(format!("{key}={n}")),
            _ => None,
        })
        .collect()
}

/// Per-deploy values that ride on one ensure call; none of them is ever a label.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct StackOpts {
    pub deploy_id: Option<String>,
    pub build_env: Option<BTreeMap<String, String>>,
    pub runtime_env: Option<BTreeMap<String, String>>,
}

// Env values are secrets, so only their names are ever printed.
impl std::fmt::Debug for StackOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |m: &Option<BTreeMap<String, String>>| {
            m.as_ref().map(|m| m.keys().cloned().collect::<Vec<_>>())
        };
        f.debug_struct("StackOpts")
            .field("deploy_id", &self.deploy_id)
            .field("build_env", &names(&self.build_env))
            .field("runtime_env", &names(&self.runtime_env))
            .finish()
    }
}

/// Resource limits of the manager (builds) and executor (serving); a site may override its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub manager_memory: i64,
    pub manager_nano_cpus: i64,
    pub executor_memory: i64,
    pub executor_nano_cpus: i64,
    pub max_memory: Option<i64>,
    pub max_nano_cpus: Option<i64>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            manager_memory: MANAGER_MEMORY,
            manager_nano_cpus: MANAGER_NANO_CPUS,
            executor_memory: EXECUTOR_MEMORY,
            executor_nano_cpus: EXECUTOR_NANO_CPUS,
            max_memory: Some(DEFAULT_MAX_MEMORY),
            max_nano_cpus: Some(DEFAULT_MAX_NANO_CPUS),
        }
    }
}

impl Limits {
    pub fn from_env() -> Result<Limits> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Limits> {
        let set = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let mut l = Limits::default();
        let bad = |k: &str, e: String| ConnectorError::BadRequest(format!("{k}: {e}"));
        let mem = |k: &str, slot: &mut i64| -> Result<()> {
            if let Some(v) = set(k) {
                *slot = parse_memory(&v).map_err(|e| bad(k, e))?;
            }
            Ok(())
        };
        let cpu = |k: &str, slot: &mut i64| -> Result<()> {
            if let Some(v) = set(k) {
                *slot = parse_cpus(&v).map_err(|e| bad(k, e))?;
            }
            Ok(())
        };
        mem("CITE_MANAGER_MEM", &mut l.manager_memory)?;
        cpu("CITE_MANAGER_CPUS", &mut l.manager_nano_cpus)?;
        mem("CITE_EXECUTOR_MEM", &mut l.executor_memory)?;
        cpu("CITE_EXECUTOR_CPUS", &mut l.executor_nano_cpus)?;
        if let Some(v) = set("CITE_STACK_MAX_MEM") {
            let max = parse_memory(&v).map_err(|e| bad("CITE_STACK_MAX_MEM", e))?;
            if max > CEILING_MEMORY {
                return Err(bad("CITE_STACK_MAX_MEM", format!("{v:?} is above 1t")));
            }
            l.max_memory = Some(max);
        }
        if let Some(v) = set("CITE_STACK_MAX_CPUS") {
            l.max_nano_cpus = Some(parse_cpus(&v).map_err(|e| bad("CITE_STACK_MAX_CPUS", e))?);
        }
        Ok(l)
    }

    fn clamp_memory(&self, bytes: i64) -> i64 {
        bytes.clamp(
            MIN_MEMORY,
            self.max_memory.unwrap_or(i64::MAX).max(MIN_MEMORY),
        )
    }

    fn clamp_cpus(&self, nano: i64) -> i64 {
        nano.clamp(
            MIN_NANO_CPUS,
            self.max_nano_cpus.unwrap_or(i64::MAX).max(MIN_NANO_CPUS),
        )
    }

    /// Refuses a site override above the node maximum, which the Docker proxy would refuse at create time.
    pub fn check_source(&self, source: &Source) -> Result<()> {
        let max_mb = self.max_memory.map(|m| m / MIB);
        for (field, value) in [
            ("memory_mb", source.memory_mb),
            ("build_memory_mb", source.build_memory_mb),
        ] {
            if let (Some(mb), Some(max)) = (value, max_mb)
                && i64::from(mb) > max
            {
                return Err(ConnectorError::BadRequest(format!(
                    "source {field}: {mb} MiB is above this node's maximum of {max} MiB (CITE_STACK_MAX_MEM)"
                )));
            }
        }
        for (field, value) in [("cpus", source.cpus), ("build_cpus", source.build_cpus)] {
            if let (Some(c), Some(max)) = (value, self.max_nano_cpus)
                && (f64::from(c.0) * 1e9).round() as i64 > max
            {
                return Err(ConnectorError::BadRequest(format!(
                    "source {field}: {} CPUs is above this node's maximum of {} CPUs (CITE_STACK_MAX_CPUS)",
                    c.0,
                    max as f64 / 1e9
                )));
            }
        }
        Ok(())
    }

    // Node defaults with the site's own overrides applied, all clamped to the node maximums.
    pub fn for_source(&self, source: &Source) -> Limits {
        let v = serde_json::to_value(source).unwrap_or(Value::Null);
        let mem = |field: &str, default: i64| {
            v[field]
                .as_u64()
                .filter(|m| *m > 0)
                .map_or(default, |m| (m.min(1 << 40) as i64) * MIB)
        };
        let cpu = |field: &str, default: i64| {
            v[field]
                .as_f64()
                .filter(|c| c.is_finite() && *c > 0.0)
                .map_or(default, |c| (c.min(MAX_CPUS) * 1e9).round() as i64)
        };
        Limits {
            manager_memory: self.clamp_memory(mem("build_memory_mb", self.manager_memory)),
            manager_nano_cpus: self.clamp_cpus(cpu("build_cpus", self.manager_nano_cpus)),
            executor_memory: self.clamp_memory(mem("memory_mb", self.executor_memory)),
            executor_nano_cpus: self.clamp_cpus(cpu("cpus", self.executor_nano_cpus)),
            ..*self
        }
    }
}

// Sizes like 512m or 2g (k, m, g, t, optional b or ib suffix); a bare number is bytes. Below 256m is refused.
pub fn parse_memory(raw: &str) -> std::result::Result<i64, String> {
    let s = raw.trim().to_ascii_lowercase();
    let s = s
        .strip_suffix("ib")
        .or_else(|| s.strip_suffix('b'))
        .unwrap_or(&s);
    let (digits, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => s.split_at(i),
        None => (s, ""),
    };
    let mult: i64 = match unit {
        "" => 1,
        "k" => 1024,
        "m" => MIB,
        "g" => GIB,
        "t" => 1024 * GIB,
        _ => return Err(format!("{raw:?} is not a size like 512m or 2g")),
    };
    let bytes = digits
        .parse::<i64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| format!("{raw:?} is not a size like 512m or 2g"))?;
    if bytes < MIN_MEMORY {
        return Err(format!("{raw:?} is below the 256m minimum"));
    }
    Ok(bytes)
}

// CPU counts as decimals (0.5, 2); returned as Docker nano CPUs.
pub fn parse_cpus(raw: &str) -> std::result::Result<i64, String> {
    let n: f64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("{raw:?} is not a CPU count"))?;
    if !n.is_finite() || !(MIN_CPUS..=MAX_CPUS).contains(&n) {
        return Err(format!("{raw:?} must be between 0.25 and 1024 CPUs"));
    }
    Ok((n * 1e9).round() as i64)
}
const INIT_MEMORY: i64 = 128 * 1024 * 1024;
const INIT_PIDS: i64 = 64;

const HEALTH_INTERVAL_NS: u64 = 30_000_000_000;
const HEALTH_TIMEOUT_NS: u64 = 5_000_000_000;
const HEALTH_RETRIES: u32 = 3;
const MANAGER_START_NS: u64 = 20_000_000_000;
const EXECUTOR_START_NS: u64 = 10_000_000_000;

const INIT_SCRIPT: &str = "mkdir -p /data/releases/blue /data/releases/green /data/control \
/data/status /data/state && \
chown 0:0 /data/releases /data/releases/blue /data/releases/green /data/control /data/state && \
chown 65532:65532 /data/status && \
chmod 0755 /data/releases /data/control /data/status && chmod 0750 /data/state";

struct RuntimeRow {
    runtime: &'static str,
    manager: &'static str,
    manager_node_tag: bool,
    executor: &'static str,
    executor_node_tag: bool,
}

// Mirrors images/images.toml: node tags carry a node<major> suffix, the others are bare versions.
static RUNTIMES: [RuntimeRow; 4] = [
    RuntimeRow {
        runtime: "node",
        manager: "cite-manager",
        manager_node_tag: true,
        executor: "cite-executor-node",
        executor_node_tag: true,
    },
    RuntimeRow {
        runtime: "bun",
        manager: "cite-manager",
        manager_node_tag: true,
        executor: "cite-executor-bun",
        executor_node_tag: false,
    },
    RuntimeRow {
        runtime: "static",
        manager: "cite-manager",
        manager_node_tag: true,
        executor: "cite-executor-static",
        executor_node_tag: false,
    },
    RuntimeRow {
        runtime: "rust",
        manager: "cite-manager-rust",
        manager_node_tag: false,
        executor: "cite-executor-rust",
        executor_node_tag: false,
    },
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StackInfo {
    pub site: String,
    pub slot: Slot,
    pub running: bool,
    pub health: String,
    pub image: String,
}

pub struct Orchestrator {
    http: reqwest::Client,
    base: String,
    edge_network: String,
    haproxy_container: String,
    stack_version: String,
    registry: String,
    github_api_url: Option<String>,
    // The token sites fall back to; resolved when a container is planned and never stored.
    default_token: Option<NodeToken>,
    limits: Limits,
    forge: Forge,
    reconciled: AtomicBool,
}

// Everything besides the site itself that shapes a stack; `isolate` gives each stack its own network.
pub struct StackEnv<'a> {
    pub registry: &'a str,
    pub version: &'a str,
    pub edge_network: &'a str,
    pub isolate: bool,
    pub github_api_url: Option<&'a str>,
}

// Names, images and bodies for one stack, in the form they are sent to the engine.
pub struct SpecSet {
    pub manager_name: String,
    pub executor_name: String,
    pub init_name: String,
    pub manager_image: String,
    pub executor_image: String,
    pub manager: Value,
    pub executor: Value,
    pub init: Value,
    pub volumes: Vec<String>,
    pub networks: Vec<String>,
}

// The exact container specs a stack would be created from, for checking against the proxy's policy.
pub fn stack_specs(
    site: &Site,
    slot: Slot,
    git_ref: Option<&str>,
    token: &str,
    env: &StackEnv<'_>,
) -> Result<SpecSet> {
    let plan = plan_stack(site, slot, git_ref, token, env)?;
    let names = plan.names;
    let mut networks = vec![names.egress.clone()];
    if env.isolate {
        networks.push(names.net.clone());
    }
    Ok(SpecSet {
        volumes: names.volumes().iter().map(|v| v.to_string()).collect(),
        manager_name: names.manager,
        executor_name: names.executor,
        init_name: names.init,
        manager_image: plan.manager_image,
        executor_image: plan.executor_image,
        manager: plan.manager,
        executor: plan.executor,
        init: plan.init,
        networks,
    })
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

struct Inspected {
    running: bool,
    image: String,
    env: Vec<String>,
    network: String,
    memory: i64,
    nano_cpus: i64,
    state: String,
    health: String,
    restart_count: u32,
    exit_code: Option<i32>,
    oom_killed: bool,
    report_text: String,
}

impl Inspected {
    // The image adds its own env vars, so every requested entry must be present rather than the sets being equal.
    fn matches(&self, spec: &Value) -> bool {
        let image = spec["Image"].as_str().unwrap_or_default();
        let env_ok = spec["Env"]
            .as_array()
            .map(|want| {
                let want: Vec<&str> = want.iter().filter_map(Value::as_str).collect();
                want.iter().all(|e| self.env.iter().any(|have| have == e))
                    && self.env.iter().all(|have| {
                        let key = env_key(have);
                        !is_setting_key(key) || want.iter().any(|w| env_key(w) == key)
                    })
            })
            .unwrap_or(true);
        let network = spec["HostConfig"]["NetworkMode"]
            .as_str()
            .unwrap_or_default();
        let limit_ok = |key: &str, have: i64| {
            spec["HostConfig"][key]
                .as_i64()
                .is_none_or(|want| want == have)
        };
        self.image == image
            && env_ok
            && self.network == network
            && limit_ok("Memory", self.memory)
            && limit_ok("NanoCpus", self.nano_cpus)
    }
}

/// A slot's manager as Docker sees it, plus the one-line report its healthcheck prints.
#[derive(Debug, Clone)]
pub struct SlotInspect {
    pub state: String,
    pub health: String,
    pub restart_count: u32,
    pub exit_code: Option<i32>,
    pub oom_killed: bool,
    /// Only the non-secret entries (site settings, deploy id, repo, branch, node, poll interval).
    pub env: Vec<String>,
    pub manager_report: Option<ManagerReport>,
    pub manager_memory: i64,
    pub manager_nano_cpus: i64,
    pub executor_memory: i64,
    pub executor_nano_cpus: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogRole {
    Manager,
    Executor,
}

#[derive(Debug, Clone)]
pub struct LogsBatch {
    pub lines: Vec<LogLine>,
    pub truncated: bool,
    /// The newest Docker timestamp in the batch (RFC3339); the cursor is taken from it, never from app output.
    pub last_ts: Option<String>,
}

#[derive(Debug, Clone)]
struct StackNames {
    id: String,
    slot: Slot,
    manager: String,
    executor: String,
    init: String,
    data: String,
    work: String,
    cache: String,
    egress: String,
    net: String,
}

impl StackNames {
    fn new(id: &str, slot: Slot) -> Result<Self> {
        if !is_valid_id(id) {
            return Err(ConnectorError::BadRequest(format!(
                "site id {id:?} is not a valid slug"
            )));
        }
        let base = format!("cite-{id}-{}", slot.as_str());
        Ok(Self {
            id: id.to_string(),
            slot,
            manager: format!("{base}-manager"),
            executor: format!("{base}-executor"),
            init: format!("{base}-init"),
            data: format!("{base}-data"),
            work: format!("{base}-work"),
            cache: format!("{base}-cache"),
            egress: format!("{base}-egress"),
            net: format!("{base}-net"),
        })
    }

    fn volumes(&self) -> [&str; 3] {
        [&self.data, &self.work, &self.cache]
    }
}

struct Plan {
    names: StackNames,
    manager_image: String,
    executor_image: String,
    manager: Value,
    executor: Value,
    init: Value,
}

impl Orchestrator {
    pub fn from_config(cfg: &ConnectorConfig) -> Result<Option<Orchestrator>> {
        match cfg.docker_host.as_deref() {
            None => Ok(None),
            Some(host) => Self::new(host, &cfg.edge_network, &cfg.stack_version, &cfg.registry)?
                .with_haproxy_container(&cfg.haproxy_container)?
                .with_github_api_url(cfg.github_api_url.as_deref())
                .and_then(|o| {
                    Ok(o.with_default_token(cfg.github_token.clone())
                        .with_limits(Limits::from_env()?)
                        .with_forge(Forge::from_env()?))
                })
                .map(Some),
        }
    }

    pub fn new(
        docker_host: &str,
        edge_network: &str,
        stack_version: &str,
        registry: &str,
    ) -> Result<Orchestrator> {
        let base = parse_docker_host(docker_host)?;
        check_chars("edge network", edge_network, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
        })?;
        check_chars("stack version", stack_version, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
        })?;
        check_chars("registry", registry, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':')
        })?;
        if registry.contains("..") || registry.starts_with('/') || registry.ends_with('/') {
            return Err(ConnectorError::BadRequest(format!(
                "registry {registry:?} is not valid"
            )));
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| ConnectorError::Internal(format!("docker client: {e}")))?;
        Ok(Orchestrator {
            http,
            base,
            edge_network: edge_network.to_string(),
            haproxy_container: DEFAULT_HAPROXY_CONTAINER.to_string(),
            stack_version: stack_version.to_string(),
            registry: registry.to_string(),
            github_api_url: None,
            default_token: None,
            limits: Limits::default(),
            forge: Forge::default(),
            reconciled: AtomicBool::new(false),
        })
    }

    pub fn with_forge(mut self, forge: Forge) -> Orchestrator {
        self.forge = forge;
        self
    }

    pub fn with_limits(mut self, limits: Limits) -> Orchestrator {
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn with_default_token(mut self, token: Option<NodeToken>) -> Orchestrator {
        self.default_token = token;
        self
    }

    // The node-wide token for sites that carry none of their own.
    pub fn default_token(&self) -> Option<&str> {
        self.default_token.as_ref().map(NodeToken::expose)
    }

    // Managers send the GitHub token to this URL, so it is validated before any stack can carry it.
    pub fn with_github_api_url(mut self, url: Option<&str>) -> Result<Orchestrator> {
        if let Some(url) = url {
            validate_github_api_url(url).map_err(ConnectorError::BadRequest)?;
        }
        self.github_api_url = url.map(str::to_string);
        Ok(self)
    }

    // An empty name turns per-stack networks off and puts executors on the shared edge network.
    pub fn with_haproxy_container(mut self, name: &str) -> Result<Orchestrator> {
        if !name.is_empty() {
            check_chars("haproxy container", name, |c| {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
            })?;
        }
        self.haproxy_container = name.to_string();
        Ok(self)
    }

    // Per-stack networks need a named HAProxy container to attach; without one the edge network is used.
    fn isolated(&self) -> bool {
        !self.haproxy_container.is_empty()
    }

    fn stack_env(&self) -> StackEnv<'_> {
        StackEnv {
            registry: &self.registry,
            version: &self.stack_version,
            edge_network: &self.edge_network,
            isolate: self.isolated(),
            github_api_url: self.github_api_url.as_deref(),
        }
    }

    pub async fn ping(&self) -> Result<()> {
        self.send(Method::GET, "/_ping", &[], None, PING_TIMEOUT, &[])
            .await
            .map(|_| ())
    }

    pub async fn ensure_stack(
        &self,
        site: &Site,
        slot: Slot,
        git_ref: Option<&str>,
        github_token: &str,
    ) -> Result<Vec<Target>> {
        self.ensure_stack_with(site, slot, git_ref, github_token, &StackOpts::default())
            .await
    }

    // The caller resolves the token (site secret or the node default) and passes the ref it wants, if any.
    pub async fn ensure_stack_with(
        &self,
        site: &Site,
        slot: Slot,
        git_ref: Option<&str>,
        github_token: &str,
        opts: &StackOpts,
    ) -> Result<Vec<Target>> {
        let plan = plan_stack_with(
            site,
            slot,
            git_ref,
            github_token,
            &self.stack_env(),
            opts,
            &self.limits,
            &self.forge,
        )?;
        self.preflight(site, &plan, opts, true)?;
        self.ensure_reconciled().await;
        let names = &plan.names;
        for image in [&plan.manager_image, &plan.executor_image] {
            self.ensure_image(image).await?;
        }
        for volume in names.volumes() {
            self.create_volume(volume, &names.id, names.slot).await?;
        }
        self.create_network(&names.egress, &names.id, names.slot, false)
            .await?;
        if self.isolated() {
            self.create_network(&names.net, &names.id, names.slot, true)
                .await?;
            self.attach_haproxy(&names.net).await?;
        }

        // Compare against the live containers so a changed ref or token recreates only what differs.
        let manager = self.inspect_owned(&names.manager).await?;
        let executor = self.inspect_owned(&names.executor).await?;
        let manager_ok = manager.as_ref().is_some_and(|c| c.matches(&plan.manager));
        let executor_ok = executor.as_ref().is_some_and(|c| c.matches(&plan.executor));
        let settled = manager_ok
            && executor_ok
            && manager.as_ref().is_some_and(|c| c.running)
            && executor.as_ref().is_some_and(|c| c.running);
        if !settled {
            self.run_init(&plan).await?;
            self.converge(&names.manager, &plan.manager, manager, manager_ok)
                .await?;
            self.converge(&names.executor, &plan.executor, executor, executor_ok)
                .await?;
            tracing::info!(site = %names.id, slot = names.slot.as_str(), "stack converged");
        }
        Ok(vec![Target {
            addr: format!("{}:8080", names.executor),
            weight: 100,
        }])
    }

    // Converges the manager alone; the executor is never touched, so a live slot keeps serving.
    pub async fn ensure_manager(
        &self,
        site: &Site,
        slot: Slot,
        git_ref: Option<&str>,
        github_token: &str,
        opts: &StackOpts,
    ) -> Result<()> {
        let plan = plan_stack_with(
            site,
            slot,
            git_ref,
            github_token,
            &self.stack_env(),
            opts,
            &self.limits,
            &self.forge,
        )?;
        self.preflight(site, &plan, opts, false)?;
        self.ensure_reconciled().await;
        let names = &plan.names;
        self.ensure_image(&plan.manager_image).await?;
        for volume in names.volumes() {
            self.create_volume(volume, &names.id, names.slot).await?;
        }
        self.create_network(&names.egress, &names.id, names.slot, false)
            .await?;
        let manager = self.inspect_owned(&names.manager).await?;
        let manager_ok = manager.as_ref().is_some_and(|c| c.matches(&plan.manager));
        if manager_ok && manager.as_ref().is_some_and(|c| c.running) {
            return Ok(());
        }
        self.run_init(&plan).await?;
        self.converge(&names.manager, &plan.manager, manager, manager_ok)
            .await?;
        tracing::info!(site = %names.id, slot = names.slot.as_str(), "manager converged");
        Ok(())
    }

    /// Reads the slot's manager and executor from Docker; a missing manager reports state "missing".
    pub async fn inspect_slot(&self, site_id: &str, slot: Slot) -> Result<SlotInspect> {
        let names = StackNames::new(site_id, slot)?;
        let manager = self.inspect_owned(&names.manager).await?;
        let executor = self.inspect_owned(&names.executor).await?;
        let (exec_memory, exec_cpus) = executor.map_or((0, 0), |e| (e.memory, e.nano_cpus));
        let Some(m) = manager else {
            return Ok(SlotInspect {
                state: "missing".to_string(),
                health: "none".to_string(),
                restart_count: 0,
                exit_code: None,
                oom_killed: false,
                env: Vec::new(),
                manager_report: None,
                manager_memory: 0,
                manager_nano_cpus: 0,
                executor_memory: exec_memory,
                executor_nano_cpus: exec_cpus,
            });
        };
        Ok(SlotInspect {
            manager_report: parse_report(&m.report_text),
            env: m
                .env
                .into_iter()
                .filter(|e| {
                    let key = env_key(e);
                    VISIBLE_KEYS.contains(&key) || SETTING_KEYS.iter().any(|(_, k)| *k == key)
                })
                .collect(),
            state: m.state,
            health: m.health,
            restart_count: m.restart_count,
            exit_code: m.exit_code,
            oom_killed: m.oom_killed,
            manager_memory: m.memory,
            manager_nano_cpus: m.nano_cpus,
            executor_memory: exec_memory,
            executor_nano_cpus: exec_cpus,
        })
    }

    /// True when the running manager carries exactly the site's current settings and limits; the deploy id is ignored.
    pub fn settings_current(&self, site: &Site, inspected: &SlotInspect) -> bool {
        let Some(source) = site.source.as_ref() else {
            return false;
        };
        let mut want = setting_env(source);
        let mut have: Vec<String> = inspected
            .env
            .iter()
            .filter(|e| SETTING_KEYS.iter().any(|(_, k)| *k == env_key(e)))
            .cloned()
            .collect();
        want.sort();
        have.sort();
        let limits = self.limits.for_source(source);
        inspected.state != "missing"
            && want == have
            && inspected.manager_memory == limits.manager_memory
            && inspected.manager_nano_cpus == limits.manager_nano_cpus
            && inspected.executor_memory == limits.executor_memory
            && inspected.executor_nano_cpus == limits.executor_nano_cpus
    }

    /// True when the slot's work or cache volume exists, managed or not.
    pub async fn build_volumes_exist(&self, site_id: &str, slot: Slot) -> Result<bool> {
        let names = StackNames::new(site_id, slot)?;
        for volume in [&names.work, &names.cache] {
            if self.managed_label("volumes", volume).await?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A volume in use cannot be deleted, so the manager goes first; the executor does not mount them and keeps serving.
    pub async fn reset_slot_volumes(&self, site_id: &str, slot: Slot) -> Result<()> {
        let names = StackNames::new(site_id, slot)?;
        self.remove_container(&names.manager).await?;
        for volume in [&names.work, &names.cache] {
            if self.managed_label("volumes", volume).await? == Some(false) {
                return Err(ConnectorError::Conflict(format!(
                    "volume {volume} exists and is not managed by cite"
                )));
            }
            self.send(
                Method::DELETE,
                &format!("{API}/volumes/{volume}"),
                &[],
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        }
        Ok(())
    }

    /// Recent log lines of one container, redacted; a container that does not exist yields an empty batch.
    pub async fn container_logs(
        &self,
        site_id: &str,
        slot: Slot,
        role: LogRole,
        tail: u32,
        since: Option<&str>,
        redact: &[String],
    ) -> Result<LogsBatch> {
        let names = StackNames::new(site_id, slot)?;
        let name = match role {
            LogRole::Manager => &names.manager,
            LogRole::Executor => &names.executor,
        };
        let tail = tail.clamp(1, MAX_LOG_TAIL).to_string();
        let mut query = vec![
            ("stdout", "1"),
            ("stderr", "1"),
            ("tail", tail.as_str()),
            ("timestamps", "1"),
        ];
        if let Some(since) = since {
            let ok = !since.is_empty()
                && since.len() <= 40
                && since
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '+'));
            if !ok {
                return Err(ConnectorError::BadRequest(format!(
                    "log since {since:?} is not valid"
                )));
            }
            query.push(("since", since));
        }
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/containers/{name}/logs"),
                &query,
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Ok(LogsBatch {
                lines: Vec::new(),
                truncated: false,
                last_ts: None,
            });
        }
        let mut secrets: Vec<String> = redact.to_vec();
        secrets.extend(self.default_token().map(str::to_string));
        Ok(build_batch(&reply.body, role == LogRole::Manager, &secrets))
    }

    pub async fn stop_stack(&self, site_id: &str, slot: Slot) -> Result<()> {
        let names = StackNames::new(site_id, slot)?;
        for name in [&names.executor, &names.manager] {
            self.send(
                Method::POST,
                &format!("{API}/containers/{name}/stop"),
                &[("t", STOP_GRACE_SECS)],
                None,
                STOP_TIMEOUT,
                &[304, 404],
            )
            .await?;
        }
        // The network stays so the stopped executor can start again; only HAProxy is cut off from it.
        self.detach_haproxy(&names.net).await
    }

    pub async fn remove_stack(&self, site_id: &str, purge: bool) -> Result<()> {
        for slot in [Slot::Blue, Slot::Green] {
            let names = StackNames::new(site_id, slot)?;
            for name in [&names.executor, &names.manager, &names.init] {
                self.remove_container(name).await?;
            }
            self.detach_haproxy(&names.net).await?;
            for network in [&names.net, &names.egress] {
                self.remove_network(network).await?;
            }
            if purge {
                for volume in names.volumes() {
                    self.send(
                        Method::DELETE,
                        &format!("{API}/volumes/{volume}"),
                        &[],
                        None,
                        REQUEST_TIMEOUT,
                        &[404],
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn stack_running(&self, site_id: &str, slot: Slot) -> Result<bool> {
        self.ensure_reconciled().await;
        let names = StackNames::new(site_id, slot)?;
        let manager = self.inspect_owned(&names.manager).await?;
        let executor = self.inspect_owned(&names.executor).await?;
        Ok(manager.is_some_and(|c| c.running) && executor.is_some_and(|c| c.running))
    }

    // The branch or tag the slot's manager was started with, if its container still exists.
    pub async fn slot_ref(&self, site_id: &str, slot: Slot) -> Result<Option<String>> {
        let names = StackNames::new(site_id, slot)?;
        let manager = self.inspect_owned(&names.manager).await?;
        Ok(manager.and_then(|c| {
            c.env
                .iter()
                .find_map(|e| e.strip_prefix("CITE_BRANCH=").map(str::to_string))
        }))
    }

    pub async fn list_stacks(&self) -> Result<Vec<StackInfo>> {
        self.ensure_reconciled().await;
        self.list_stacks_raw().await
    }

    // HAProxy may have been recreated since the stacks started, which drops it from their networks.
    pub async fn reconcile_networks(&self) -> Result<()> {
        if !self.isolated() {
            return Ok(());
        }
        let mut first_error = None;
        for stack in self.list_stacks_raw().await?.iter().filter(|s| s.running) {
            let names = StackNames::new(&stack.site, stack.slot)?;
            if let Err(e) = self.attach_haproxy(&names.net).await {
                tracing::warn!(site = %stack.site, error = %e, "could not reattach haproxy");
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    // A failed attempt is retried on the next call, so a restart while Docker is down heals later.
    pub async fn ensure_reconciled(&self) {
        if self.reconciled.load(Ordering::Acquire) {
            return;
        }
        match self.reconcile_networks().await {
            Ok(()) => self.reconciled.store(true, Ordering::Release),
            Err(e) => tracing::warn!(error = %e, "network reconcile failed, will retry"),
        }
    }

    async fn list_stacks_raw(&self) -> Result<Vec<StackInfo>> {
        let filters = json!({ "label": ["cite.managed=true"] }).to_string();
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/containers/json"),
                &[("all", "true"), ("filters", filters.as_str())],
                None,
                REQUEST_TIMEOUT,
                &[],
            )
            .await?;
        let items: Vec<Value> = serde_json::from_slice(&reply.body)?;
        Ok(collect_stacks(&items))
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
        timeout: Duration,
        accept: &[u16],
    ) -> Result<Reply> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .timeout(timeout);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(value) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(value)?);
        }
        let mut resp = req.send().await.map_err(net_error)?;
        let status = resp.status().as_u16();
        let success = resp.status().is_success();
        let body = read_capped(&mut resp).await?;
        if success || accept.contains(&status) {
            Ok(Reply { status, body })
        } else {
            Err(docker_error(status, &body))
        }
    }

    async fn ensure_image(&self, reference: &str) -> Result<()> {
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/images/{reference}/json"),
                &[],
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            self.pull_image(reference).await?;
        }
        Ok(())
    }

    async fn pull_image(&self, reference: &str) -> Result<()> {
        let (repo, tag) = reference
            .rsplit_once(':')
            .ok_or_else(|| ConnectorError::Internal(format!("image {reference} has no tag")))?;
        let mut resp = self
            .http
            .post(format!("{}{API}/images/create", self.base))
            .query(&[("fromImage", repo), ("tag", tag)])
            .timeout(PULL_TIMEOUT)
            .send()
            .await
            .map_err(net_error)?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = read_capped(&mut resp).await?;
            return Err(docker_error(status, &body));
        }
        // The pull response streams JSON lines; a failure arrives as an `error` line with status 200.
        let mut pending: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(net_error)? {
            pending.extend_from_slice(&chunk);
            while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = pending.drain(..=pos).collect();
                if let Some(msg) = stream_error(&line) {
                    return Err(ConnectorError::Internal(format!("pull {reference}: {msg}")));
                }
            }
            if pending.len() > MAX_BODY {
                pending.clear();
            }
        }
        match stream_error(&pending) {
            Some(msg) => Err(ConnectorError::Internal(format!("pull {reference}: {msg}"))),
            None => Ok(()),
        }
    }

    // Looks a volume or network up and reports whether it carries the cite.managed label.
    async fn managed_label(&self, kind: &str, name: &str) -> Result<Option<bool>> {
        let reply = self
            .send(
                Method::GET,
                &format!("{API}/{kind}/{name}"),
                &[],
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Ok(None);
        }
        let v: Value = serde_json::from_slice(&reply.body)?;
        Ok(Some(v["Labels"]["cite.managed"].as_str() == Some("true")))
    }

    async fn require_managed(&self, kind: &str, name: &str) -> Result<()> {
        match self.managed_label(kind, name).await? {
            Some(true) => Ok(()),
            Some(false) => Err(ConnectorError::Conflict(format!(
                "{kind} {name} exists and is not managed by cite"
            ))),
            None => Err(ConnectorError::Conflict(format!(
                "{kind} {name} disappeared during creation"
            ))),
        }
    }

    // The create call is idempotent and would silently adopt a foreign volume of the same name.
    async fn create_volume(&self, name: &str, id: &str, slot: Slot) -> Result<()> {
        match self.managed_label("volumes", name).await? {
            Some(true) => return Ok(()),
            Some(false) => return self.require_managed("volumes", name).await,
            None => {}
        }
        let body = json!({ "Name": name, "Labels": labels(id, slot, "volume") });
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

    async fn create_network(&self, name: &str, id: &str, slot: Slot, internal: bool) -> Result<()> {
        let body = json!({
            "Name": name,
            "Driver": "bridge",
            "Internal": internal,
            "Labels": labels(id, slot, "network"),
        });
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
        }
        Ok(())
    }

    async fn remove_network(&self, name: &str) -> Result<()> {
        if self.managed_label("networks", name).await? == Some(false) {
            return Err(ConnectorError::Conflict(format!(
                "network {name} exists and is not managed by cite"
            )));
        }
        self.send(
            Method::DELETE,
            &format!("{API}/networks/{name}"),
            &[],
            None,
            REQUEST_TIMEOUT,
            &[404],
        )
        .await
        .map(|_| ())
    }

    // Names of the containers attached to a network, or None when the network is gone.
    async fn network_members(&self, name: &str) -> Result<Option<Vec<String>>> {
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
            return Ok(None);
        }
        let v: Value = serde_json::from_slice(&reply.body)?;
        let members = v["Containers"]
            .as_object()
            .map(|m| {
                m.values()
                    .filter_map(|c| c["Name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some(members))
    }

    // Connecting an already attached container would fail, so membership is read first.
    async fn attach_haproxy(&self, network: &str) -> Result<()> {
        let Some(members) = self.network_members(network).await? else {
            return Ok(());
        };
        if members.contains(&self.haproxy_container) {
            return Ok(());
        }
        let body = json!({ "Container": self.haproxy_container });
        let reply = self
            .send(
                Method::POST,
                &format!("{API}/networks/{network}/connect"),
                &[],
                Some(&body),
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
        if reply.status == 404 {
            return Err(ConnectorError::Unavailable(format!(
                "haproxy container {:?} or network {network} not found; check CITE_HAPROXY_CONTAINER",
                self.haproxy_container
            )));
        }
        Ok(())
    }

    async fn detach_haproxy(&self, network: &str) -> Result<()> {
        if !self.isolated() {
            return Ok(());
        }
        let Some(members) = self.network_members(network).await? else {
            return Ok(());
        };
        if !members.contains(&self.haproxy_container) {
            return Ok(());
        }
        let body = json!({ "Container": self.haproxy_container });
        self.send(
            Method::POST,
            &format!("{API}/networks/{network}/disconnect"),
            &[],
            Some(&body),
            REQUEST_TIMEOUT,
            &[404],
        )
        .await
        .map(|_| ())
    }

    async fn inspect_owned(&self, name: &str) -> Result<Option<Inspected>> {
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
            return Ok(None);
        }
        let v: Value = serde_json::from_slice(&reply.body)?;
        // Never adopt or delete a container that merely shares our naming scheme.
        let managed = v["Config"]["Labels"]["cite.managed"].as_str() == Some("true");
        if !managed {
            return Err(ConnectorError::Conflict(format!(
                "container {name} exists and is not managed by cite"
            )));
        }
        Ok(Some(Inspected {
            running: v["State"]["Running"].as_bool().unwrap_or(false),
            image: v["Config"]["Image"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            env: v["Config"]["Env"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            network: v["HostConfig"]["NetworkMode"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            memory: v["HostConfig"]["Memory"].as_i64().unwrap_or(0),
            nano_cpus: v["HostConfig"]["NanoCpus"].as_i64().unwrap_or(0),
            state: state_name(&v["State"]),
            health: health_name(&v["State"]["Health"]["Status"]),
            restart_count: v["State"]["RestartCount"]
                .as_u64()
                .map_or(0, |n| n.min(u32::MAX as u64) as u32),
            exit_code: v["State"]["ExitCode"]
                .as_i64()
                .and_then(|n| i32::try_from(n).ok()),
            oom_killed: v["State"]["OOMKilled"].as_bool().unwrap_or(false),
            report_text: v["State"]["Health"]["Log"]
                .as_array()
                .and_then(|log| log.last())
                .and_then(|entry| entry["Output"].as_str())
                .unwrap_or_default()
                .to_string(),
        }))
    }

    async fn create_container(&self, name: &str, spec: &Value) -> Result<()> {
        self.send(
            Method::POST,
            &format!("{API}/containers/create"),
            &[("name", name)],
            Some(spec),
            REQUEST_TIMEOUT,
            &[],
        )
        .await
        .map(|_| ())
        .map_err(|e| match e {
            ConnectorError::Internal(m) if m.starts_with("docker api 4") && mentions_limits(&m) => {
                ConnectorError::Internal(format!(
                    "{m} (the docker proxy refused the stack limits; raise CITE_STACK_MAX_MEM or CITE_STACK_MAX_CPUS on the proxy or lower the site's limits)"
                ))
            }
            other => other,
        })
    }

    async fn start_container(&self, name: &str) -> Result<()> {
        self.send(
            Method::POST,
            &format!("{API}/containers/{name}/start"),
            &[],
            None,
            REQUEST_TIMEOUT,
            &[304],
        )
        .await
        .map(|_| ())
    }

    // Looking first means a container that merely shares our naming scheme is never deleted.
    async fn remove_container(&self, name: &str) -> Result<()> {
        if self.inspect_owned(name).await?.is_none() {
            return Ok(());
        }
        self.send(
            Method::DELETE,
            &format!("{API}/containers/{name}"),
            &[("force", "true")],
            None,
            REQUEST_TIMEOUT,
            &[404],
        )
        .await
        .map(|_| ())
    }

    // The proxy refuses a create only after the old container is gone, so the same rules are checked here first.
    fn preflight(&self, site: &Site, plan: &Plan, opts: &StackOpts, executor: bool) -> Result<()> {
        let refuse = |what: &str, why: String| {
            ConnectorError::BadRequest(format!(
                "the {what} of {}/{} would be refused by the Docker proxy: {why}; nothing was changed",
                site.id,
                plan.names.slot.as_str()
            ))
        };
        if let Some(source) = &site.source {
            // The forge is the operator's and never reaches the plan, so a stored per-site value is ignored here.
            let mut checked = source.clone();
            checked.forge = None;
            cite_edge::validate::validate_source(&checked).map_err(|e| refuse("manager", e.0))?;
        }
        let env_check = |map: &Option<BTreeMap<String, String>>, runtime: bool| {
            let patch = BuildEnvPatch {
                set: map.clone().unwrap_or_default(),
                unset: Vec::new(),
            };
            let checked = if runtime {
                patch.validate_runtime()
            } else {
                patch.validate()
            };
            checked.map_err(|e| e.0)
        };
        env_check(&opts.build_env, false).map_err(|why| refuse("manager", why))?;
        let max_memory = self.limits.max_memory.unwrap_or(CEILING_MEMORY);
        let max_cpus = self.limits.max_nano_cpus.unwrap_or((MAX_CPUS * 1e9) as i64);
        let mut specs = vec![("manager", &plan.manager)];
        if executor {
            env_check(&opts.runtime_env, true).map_err(|why| refuse("executor", why))?;
            specs.push(("executor", &plan.executor));
        }
        for (what, spec) in specs {
            let host = &spec["HostConfig"];
            let memory = host["Memory"].as_i64().unwrap_or_default();
            if !(MIN_MEMORY..=max_memory).contains(&memory) {
                return Err(refuse(
                    what,
                    format!(
                        "memory must be between {} MiB and {} MiB",
                        MIN_MEMORY / MIB,
                        max_memory / MIB
                    ),
                ));
            }
            let cpus = host["NanoCpus"].as_i64().unwrap_or_default();
            if !(MIN_NANO_CPUS..=max_cpus).contains(&cpus) {
                return Err(refuse(
                    what,
                    format!(
                        "CPUs must be between {} and {}",
                        MIN_CPUS,
                        max_cpus as f64 / 1e9
                    ),
                ));
            }
        }
        Ok(())
    }

    async fn converge(
        &self,
        name: &str,
        spec: &Value,
        existing: Option<Inspected>,
        matches: bool,
    ) -> Result<()> {
        match existing {
            Some(c) if matches => {
                if !c.running {
                    self.start_container(name).await?;
                }
            }
            Some(_) => {
                self.remove_container(name).await?;
                self.create_container(name, spec).await?;
                self.start_container(name).await?;
            }
            None => {
                self.create_container(name, spec).await?;
                self.start_container(name).await?;
            }
        }
        Ok(())
    }

    async fn run_init(&self, plan: &Plan) -> Result<()> {
        let name = &plan.names.init;
        self.remove_container(name).await?;
        self.create_container(name, &plan.init).await?;
        let outcome = self.run_init_container(name).await;
        let cleanup = self.remove_container(name).await;
        outcome?;
        cleanup
    }

    async fn run_init_container(&self, name: &str) -> Result<()> {
        self.start_container(name).await?;
        let reply = self
            .send(
                Method::POST,
                &format!("{API}/containers/{name}/wait"),
                &[("condition", "not-running")],
                None,
                INIT_TIMEOUT,
                &[],
            )
            .await?;
        let v: Value = serde_json::from_slice(&reply.body)?;
        match v["StatusCode"].as_i64() {
            Some(0) => Ok(()),
            Some(code) => Err(ConnectorError::Internal(format!(
                "init container {name} failed with exit code {code}"
            ))),
            None => Err(ConnectorError::Internal(format!(
                "init container {name} returned no exit code"
            ))),
        }
    }
}

fn mentions_limits(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    ["memory", "cpu", "limit"].iter().any(|w| m.contains(w))
}

fn state_name(state: &Value) -> String {
    match state["Status"].as_str() {
        Some(s @ ("running" | "exited" | "restarting" | "created")) => s.to_string(),
        Some("paused") => "running".to_string(),
        Some("dead" | "removing") => "exited".to_string(),
        _ if state["Restarting"].as_bool() == Some(true) => "restarting".to_string(),
        _ if state["Running"].as_bool() == Some(true) => "running".to_string(),
        _ => "exited".to_string(),
    }
}

fn health_name(status: &Value) -> String {
    match status.as_str() {
        Some(s @ ("healthy" | "unhealthy" | "starting")) => s.to_string(),
        _ => "none".to_string(),
    }
}

// The healthcheck prints the manager's one-line report; anything oversized or malformed is ignored.
fn parse_report(output: &str) -> Option<ManagerReport> {
    let line = output
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))?
        .trim();
    if line.len() > MAX_REPORT_BYTES {
        return None;
    }
    serde_json::from_str(line).ok()
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.next() {
                Some('[') => {
                    for n in chars.by_ref() {
                        if ('@'..='~').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(n) = chars.next() {
                        if n == '\x07' {
                            break;
                        }
                        if n == '\x1b' {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn redact_tokens(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let (mut i, mut last) = (0, 0);
    while i < b.len() {
        if let Some(prefix) = TOKEN_PREFIXES
            .iter()
            .find(|p| b[i..].starts_with(p.as_bytes()))
        {
            let start = i + prefix.len();
            let mut end = start;
            while end < b.len() && (b[end].is_ascii_alphanumeric() || b[end] == b'_') {
                end += 1;
            }
            if end - start >= MIN_TOKEN_TAIL {
                out.push_str(&s[last..i]);
                out.push_str(REDACTED);
                (i, last) = (end, end);
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

fn redact_text(s: &str, secrets: &[String]) -> String {
    let mut found: Vec<&String> = secrets
        .iter()
        .filter(|x| x.len() >= MIN_REDACT_LEN)
        .collect();
    found.sort_by_key(|x| std::cmp::Reverse(x.len()));
    let mut out = s.to_string();
    for secret in found {
        out = out.replace(secret.as_str(), REDACTED);
    }
    redact_tokens(&out)
}

fn cap_str(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

// Splits Docker's multiplexed log stream (8-byte header: stream, 3 zero bytes, big-endian size); headerless input is stdout.
fn demux(body: &[u8]) -> Vec<(bool, String)> {
    fn feed(pending: &mut Vec<u8>, data: &[u8], stderr: bool, out: &mut Vec<(bool, String)>) {
        pending.extend_from_slice(data);
        while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=pos).collect();
            out.push((stderr, line_text(&line)));
        }
        // A frame stream with no newline for this long is one runaway line.
        if pending.len() > MAX_LOG_LINE * 4 {
            out.push((stderr, line_text(pending)));
            pending.clear();
        }
    }
    fn line_text(raw: &[u8]) -> String {
        String::from_utf8_lossy(raw)
            .trim_end_matches(['\n', '\r'])
            .to_string()
    }
    let mut out = Vec::new();
    let mut pending: [Vec<u8>; 2] = Default::default();
    let framed = body.len() >= 8 && body[0] <= 2 && body[1..4] == [0, 0, 0];
    if !framed {
        feed(&mut pending[0], body, false, &mut out);
    } else {
        let mut pos = 0;
        while pos + 8 <= body.len() {
            if body[pos] > 2 || body[pos + 1..pos + 4] != [0, 0, 0] {
                break;
            }
            let size =
                u32::from_be_bytes([body[pos + 4], body[pos + 5], body[pos + 6], body[pos + 7]])
                    as usize;
            let start = pos + 8;
            let end = start + size.min(body.len() - start);
            let which = usize::from(body[pos] == 2);
            feed(&mut pending[which], &body[start..end], which == 1, &mut out);
            pos = end;
        }
    }
    for (which, rest) in pending.iter().enumerate() {
        if !rest.is_empty() {
            out.push((which == 1, line_text(rest)));
        }
    }
    out
}

fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 20 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && s.contains('T')
}

// Docker's own RFC3339 prefix, written by the daemon when it received the line.
fn split_docker_ts(raw: &str) -> (Option<OffsetDateTime>, &str, &str) {
    match raw.split_once(' ') {
        Some((first, rest)) if looks_like_timestamp(first) => {
            (OffsetDateTime::parse(first, &Rfc3339).ok(), first, rest)
        }
        _ => (None, "", raw),
    }
}

fn parse_log_line(raw: &str, stderr: bool, manager: bool, secrets: &[String]) -> LogLine {
    let (_, docker_ts, rest) = split_docker_ts(raw);
    let mut ts = docker_ts.to_string();
    let mut level = if stderr { "error" } else { "info" }.to_string();
    let mut phase: Option<String> = None;
    let mut text = rest.to_string();
    if manager
        && rest.trim_start().starts_with('{')
        && let Ok(v) = serde_json::from_str::<Value>(rest.trim())
    {
        let msg = v["msg"]
            .as_str()
            .or_else(|| v["message"].as_str())
            .or_else(|| v["fields"]["message"].as_str());
        let phase_text = v["phase"].as_str();
        if msg.is_some() || phase_text.is_some() {
            text = msg.or(phase_text).unwrap_or_default().to_string();
            phase = phase_text.map(str::to_string);
            // The app's own clock may be skewed, so its time only fills in when Docker gave none.
            if ts.is_empty()
                && let Some(t) = v["ts"].as_str().or_else(|| v["timestamp"].as_str())
                && !t.contains(char::is_whitespace)
            {
                ts = t.to_string();
            }
            if let Some(l) = v["level"].as_str() {
                level = l.to_ascii_lowercase();
            }
        }
    }
    let clean = |s: &str, max: usize| cap_str(redact_text(&strip_ansi(s), secrets), max);
    LogLine {
        ts: (!ts.is_empty()).then(|| cap_str(ts, 64)),
        stream: if stderr { "stderr" } else { "stdout" }.to_string(),
        level: Some(clean(&level, 16)),
        phase: phase.map(|p| clean(&p, 64)),
        text: clean(&text, MAX_LOG_LINE),
    }
}

fn line_cost(line: &LogLine) -> usize {
    line.ts.as_deref().map_or(0, str::len)
        + line.stream.len()
        + line.level.as_deref().map_or(0, str::len)
        + line.phase.as_deref().map_or(0, str::len)
        + line.text.len()
}

fn build_batch(body: &[u8], manager: bool, secrets: &[String]) -> LogsBatch {
    let mut newest: Option<OffsetDateTime> = None;
    let mut lines: Vec<LogLine> = demux(body)
        .into_iter()
        .map(|(stderr, raw)| {
            if let (Some(at), _, _) = split_docker_ts(&raw) {
                newest = Some(newest.map_or(at, |n| n.max(at)));
            }
            parse_log_line(&raw, stderr, manager, secrets)
        })
        .collect();
    let mut total = 0;
    let mut keep = lines.len();
    for (i, line) in lines.iter().enumerate().rev() {
        total += line_cost(line);
        if total > MAX_LOG_TOTAL {
            break;
        }
        keep = i;
    }
    let truncated = keep > 0;
    lines.drain(..keep);
    LogsBatch {
        lines,
        truncated,
        last_ts: newest.and_then(|t| t.format(&Rfc3339).ok()),
    }
}

fn parse_docker_host(host: &str) -> Result<String> {
    let rest = host
        .strip_prefix("tcp://")
        .or_else(|| host.strip_prefix("http://"))
        .ok_or_else(|| {
            ConnectorError::BadRequest(
                "docker host must be tcp://host:port or http://host:port".to_string(),
            )
        })?;
    // Only a bare host:port is accepted, so no path or query can be smuggled into request URLs.
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let bad = || ConnectorError::BadRequest(format!("docker host {host:?} is not host:port"));
    let (name, port) = rest.rsplit_once(':').ok_or_else(bad)?;
    let name_ok = !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p > 0);
    if !name_ok || !port_ok {
        return Err(bad());
    }
    Ok(format!("http://{name}:{port}"))
}

fn check_chars(what: &str, value: &str, ok: impl Fn(char) -> bool) -> Result<()> {
    if value.is_empty() || value.len() > 128 || !value.chars().all(ok) {
        return Err(ConnectorError::BadRequest(format!(
            "{what} {value:?} is not valid"
        )));
    }
    Ok(())
}

fn validate_git_ref(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= MAX_REF_LEN
        && !s.starts_with('-')
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
    if ok {
        Ok(())
    } else {
        Err(ConnectorError::BadRequest(format!(
            "git ref {s:?} is not valid"
        )))
    }
}

fn validate_repo(s: &str) -> Result<()> {
    let part_ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 100
            && p != "."
            && p != ".."
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    match s.split_once('/') {
        Some((owner, name)) if part_ok(owner) && part_ok(name) => Ok(()),
        _ => Err(ConnectorError::BadRequest(format!(
            "source repo {s:?} must be owner/name"
        ))),
    }
}

fn validate_token(token: &str) -> Result<()> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_LEN
        || !token.chars().all(|c| c.is_ascii_graphic())
    {
        return Err(ConnectorError::BadRequest(
            "github token is empty or contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

fn valid_host(host: &str) -> bool {
    let edge_ok = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    edge_ok(host.chars().next())
        && edge_ok(host.chars().last())
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
}

// An http(s) URL without userinfo, query or fragment, made only of host, port and plain path characters.
pub fn validate_github_api_url(url: &str) -> std::result::Result<(), String> {
    if url.len() > MAX_GITHUB_URL_LEN {
        return Err(format!(
            "github api url is longer than {MAX_GITHUB_URL_LEN} characters"
        ));
    }
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("github api url must start with http:// or https://")?;
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~' | ':' | '/'))
    {
        return Err("github api url has characters that are not allowed".to_string());
    }
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if !valid_host(host) || port.is_some_and(|p| !valid_port(p)) {
        return Err("github api url has no valid host and port".to_string());
    }
    if path.contains("//") || path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("github api url has an empty or relative path segment".to_string());
    }
    Ok(())
}

fn poll_interval(raw: Option<&str>) -> Result<String> {
    let value = raw
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(DEFAULT_POLL);
    parse_poll_interval(value, MIN_POLL)
        .map_err(|e| ConnectorError::BadRequest(format!("poll interval: {e}")))?;
    Ok(value.to_string())
}

fn runtime_row(runtime: &str) -> Result<&'static RuntimeRow> {
    RUNTIMES
        .iter()
        .find(|r| r.runtime == runtime)
        .ok_or_else(|| ConnectorError::BadRequest(format!("unknown runtime {runtime:?}")))
}

// Returns (manager, executor) image references including the tag.
fn image_refs(
    registry: &str,
    version: &str,
    runtime: &str,
    node_major: u8,
) -> Result<(String, String)> {
    let row = runtime_row(runtime)?;
    if !NODE_MAJORS.contains(&node_major) && (row.manager_node_tag || row.executor_node_tag) {
        return Err(ConnectorError::BadRequest(format!(
            "node major {node_major} is not supported"
        )));
    }
    let tag = |node_tag: bool| {
        if node_tag {
            format!("{version}-node{node_major}")
        } else {
            version.to_string()
        }
    };
    Ok((
        format!("{registry}/{}:{}", row.manager, tag(row.manager_node_tag)),
        format!("{registry}/{}:{}", row.executor, tag(row.executor_node_tag)),
    ))
}

fn plan_stack(
    site: &Site,
    slot: Slot,
    git_ref: Option<&str>,
    token: &str,
    env: &StackEnv<'_>,
) -> Result<Plan> {
    plan_stack_with(
        site,
        slot,
        git_ref,
        token,
        env,
        &StackOpts::default(),
        &Limits::default(),
        &Forge::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn plan_stack_with(
    site: &Site,
    slot: Slot,
    git_ref: Option<&str>,
    token: &str,
    env: &StackEnv<'_>,
    opts: &StackOpts,
    limits: &Limits,
    forge: &Forge,
) -> Result<Plan> {
    let (registry, version) = (env.registry, env.version);
    let names = StackNames::new(&site.id, slot)?;
    let source = site.source.as_ref().ok_or_else(|| {
        ConnectorError::BadRequest(format!("site {} has no source configured", site.id))
    })?;
    validate_repo(&source.repo)?;
    validate_token(token)?;
    let branch = git_ref
        .or(source.branch.as_deref())
        .unwrap_or(DEFAULT_BRANCH);
    validate_git_ref(branch)?;
    let poll = poll_interval(source.poll_interval.as_deref())?;
    let runtime = source.runtime.as_deref().unwrap_or("node");
    let node_major = source.node_major.unwrap_or(DEFAULT_NODE_MAJOR);
    let (manager_image, executor_image) = image_refs(registry, version, runtime, node_major)?;

    // The Rust images bring their own toolchain and take no node major.
    let with_node = runtime != "rust";
    let mut manager_env = vec![
        format!("CITE_REPO={}", source.repo),
        format!("CITE_BRANCH={branch}"),
        format!("CITE_POLL_INTERVAL={poll}"),
    ];
    if with_node {
        manager_env.push(format!("CITE_NODE={node_major}"));
    }
    manager_env.push(format!("CITE_GITHUB_TOKEN={token}"));
    if let Some(url) = env.github_api_url {
        validate_github_api_url(url).map_err(ConnectorError::BadRequest)?;
        manager_env.push(format!("CITE_GITHUB_API_URL={url}"));
    }
    manager_env.extend(
        [
            "CITE_DATA_DIR=/var/lib/cite",
            "CITE_RELEASES_DIR=/var/lib/cite/releases",
            "CITE_CONTROL_DIR=/var/lib/cite/control",
            "CITE_STATUS_DIR=/var/lib/cite/status",
            "CITE_STATE_DIR=/var/lib/cite/state",
            "CITE_WORK_DIR=/var/lib/cite/work",
            "CITE_CACHE_DIR=/var/lib/cite/cache",
            "CITE_SOCKET=/run/cite/manager.sock",
            "RUST_LOG=info",
        ]
        .map(str::to_string),
    );
    forge.validate()?;
    manager_env.extend(forge.env());
    manager_env.extend(setting_env(source));
    if let Some(id) = opts.deploy_id.as_deref() {
        let ok = !id.is_empty()
            && id.len() <= MAX_DEPLOY_ID_LEN
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
        if !ok {
            return Err(ConnectorError::BadRequest(format!(
                "deploy id {id:?} is not valid"
            )));
        }
        manager_env.push(format!("{DEPLOY_ID_KEY}={id}"));
    }
    if let Some(map) = opts.build_env.as_ref() {
        manager_env.push(format!("{BUILD_ENV_KEY}={}", serde_json::to_string(map)?));
    }

    let mut executor_env = vec![
        "CITE_LISTEN=0.0.0.0:8080".to_string(),
        "CITE_DATA_DIR=/var/lib/cite".to_string(),
        "CITE_RELEASES_DIR=/var/lib/cite/releases".to_string(),
        "CITE_CONTROL_DIR=/var/lib/cite/control".to_string(),
        "CITE_STATUS_DIR=/var/lib/cite/status".to_string(),
        "RUST_LOG=info".to_string(),
    ];
    if runtime == "node" {
        executor_env.push("CITE_NODE_BIN=/nodejs/bin/node".to_string());
        executor_env.push(format!("CITE_NODE={node_major}"));
    }
    if let Some(map) = opts.runtime_env.as_ref() {
        executor_env.push(format!("{RUNTIME_ENV_KEY}={}", serde_json::to_string(map)?));
    }

    let executor_network = if env.isolate {
        names.net.clone()
    } else {
        env.edge_network.to_string()
    };
    let limits = if let Some(source) = site.source.as_ref() {
        limits.for_source(source)
    } else {
        *limits
    };
    Ok(Plan {
        manager: manager_spec(&names, &manager_image, &manager_env, &limits),
        executor: executor_spec(
            &names,
            &executor_image,
            &executor_env,
            &executor_network,
            &limits,
        ),
        init: init_spec(&names, &manager_image),
        names,
        manager_image,
        executor_image,
    })
}

// Labels never carry secrets; the token lives only in the manager's Env.
fn labels(id: &str, slot: Slot, role: &str) -> Value {
    json!({
        "cite.managed": "true",
        "cite.site": id,
        "cite.slot": slot.as_str(),
        "cite.role": role,
    })
}

fn log_config() -> Value {
    json!({ "Type": "json-file", "Config": { "max-size": "10m", "max-file": "3" } })
}

fn healthcheck(test: &[&str], start_period_ns: u64) -> Value {
    json!({
        "Test": test,
        "Interval": HEALTH_INTERVAL_NS,
        "Timeout": HEALTH_TIMEOUT_NS,
        "Retries": HEALTH_RETRIES,
        "StartPeriod": start_period_ns,
    })
}

fn volume_mount(volume: &str, target: &str, subpath: Option<&str>, read_only: bool) -> Value {
    let mut mount = json!({
        "Type": "volume",
        "Source": volume,
        "Target": target,
        "ReadOnly": read_only,
    });
    if let Some(sub) = subpath {
        mount["VolumeOptions"] = json!({ "Subpath": sub });
    }
    mount
}

// Mirrors the manager service in docker-compose.yml, on the per-stack egress network only.
fn manager_spec(names: &StackNames, image: &str, env: &[String], limits: &Limits) -> Value {
    let data = names.data.as_str();
    json!({
        "Image": image,
        "Env": env,
        "Labels": labels(&names.id, names.slot, "manager"),
        "Healthcheck": healthcheck(&["CMD", "cite-manager", "healthcheck"], MANAGER_START_NS),
        "HostConfig": {
            "Init": true,
            "ReadonlyRootfs": true,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["ALL"],
            "CapAdd": ["CHOWN", "SETUID", "SETGID", "DAC_READ_SEARCH"],
            "Tmpfs": {
                "/tmp": "size=256m,mode=1777",
                "/run/cite": "size=16m,mode=0750",
            },
            "Mounts": [
                volume_mount(data, "/var/lib/cite/releases", Some("releases"), false),
                volume_mount(data, "/var/lib/cite/control", Some("control"), false),
                volume_mount(data, "/var/lib/cite/status", Some("status"), true),
                volume_mount(data, "/var/lib/cite/state", Some("state"), false),
                volume_mount(&names.work, "/var/lib/cite/work", None, false),
                volume_mount(&names.cache, "/var/lib/cite/cache", None, false),
            ],
            "NetworkMode": names.egress,
            "Memory": limits.manager_memory,
            "MemorySwap": limits.manager_memory,
            "NanoCpus": limits.manager_nano_cpus,
            "PidsLimit": MANAGER_PIDS,
            "RestartPolicy": { "Name": "unless-stopped" },
            "LogConfig": log_config(),
        },
        "NetworkingConfig": { "EndpointsConfig": { names.egress.as_str(): {} } },
    })
}

// Mirrors the executor service in docker-compose.yml; reachable only through an internal network.
fn executor_spec(
    names: &StackNames,
    image: &str,
    env: &[String],
    network: &str,
    limits: &Limits,
) -> Value {
    let data = names.data.as_str();
    json!({
        "Image": image,
        "User": "65532:65532",
        "Env": env,
        "Labels": labels(&names.id, names.slot, "executor"),
        "Healthcheck": healthcheck(&["CMD", "/cite-executor", "healthcheck"], EXECUTOR_START_NS),
        "HostConfig": {
            "Init": true,
            "ReadonlyRootfs": true,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["ALL"],
            "Tmpfs": { "/tmp": "size=64m,mode=1777,noexec,nosuid,nodev" },
            "Mounts": [
                volume_mount(data, "/var/lib/cite/releases", Some("releases"), true),
                volume_mount(data, "/var/lib/cite/control", Some("control"), true),
                volume_mount(data, "/var/lib/cite/status", Some("status"), false),
            ],
            "NetworkMode": network,
            "Memory": limits.executor_memory,
            "MemorySwap": limits.executor_memory,
            "NanoCpus": limits.executor_nano_cpus,
            "PidsLimit": EXECUTOR_PIDS,
            "RestartPolicy": { "Name": "unless-stopped" },
            "LogConfig": log_config(),
        },
        "NetworkingConfig": {
            "EndpointsConfig": { network: { "Aliases": [names.executor.as_str()] } }
        },
    })
}

// One-shot that lays out the data volume; it has no network and only the caps chown needs.
fn init_spec(names: &StackNames, image: &str) -> Value {
    json!({
        "Image": image,
        "User": "0:0",
        "Entrypoint": ["/bin/sh", "-c"],
        "Cmd": [INIT_SCRIPT],
        "Labels": labels(&names.id, names.slot, "init"),
        "Healthcheck": { "Test": ["NONE"] },
        "HostConfig": {
            "ReadonlyRootfs": true,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["ALL"],
            "CapAdd": ["CHOWN", "FOWNER"],
            "Mounts": [volume_mount(&names.data, "/data", None, false)],
            "NetworkMode": "none",
            "Memory": INIT_MEMORY,
            "MemorySwap": INIT_MEMORY,
            "PidsLimit": INIT_PIDS,
            "RestartPolicy": { "Name": "no" },
            "LogConfig": log_config(),
        },
    })
}

#[derive(Default)]
struct StackAcc {
    manager: Option<bool>,
    executor: Option<bool>,
    healths: Vec<&'static str>,
    image: String,
}

// The list endpoint only exposes health inside the human-readable status text.
fn health_from_status(status: &str) -> &'static str {
    let s = status.to_ascii_lowercase();
    if s.contains("(unhealthy)") {
        "unhealthy"
    } else if s.contains("(healthy)") {
        "healthy"
    } else if s.contains("health: starting") {
        "starting"
    } else {
        "none"
    }
}

fn aggregate_health(healths: &[&'static str]) -> &'static str {
    if healths.contains(&"unhealthy") {
        "unhealthy"
    } else if healths.contains(&"starting") {
        "starting"
    } else if !healths.is_empty() && healths.iter().all(|h| *h == "healthy") {
        "healthy"
    } else {
        "none"
    }
}

fn collect_stacks(items: &[Value]) -> Vec<StackInfo> {
    let mut stacks: BTreeMap<(String, &'static str), (Slot, StackAcc)> = BTreeMap::new();
    for item in items {
        let label = |k: &str| item["Labels"][k].as_str();
        let (Some(site), Some(slot), Some(role)) =
            (label("cite.site"), label("cite.slot"), label("cite.role"))
        else {
            continue;
        };
        let slot = match slot {
            "blue" => Slot::Blue,
            "green" => Slot::Green,
            _ => continue,
        };
        let running = item["State"].as_str() == Some("running");
        let health = health_from_status(item["Status"].as_str().unwrap_or_default());
        let entry = stacks
            .entry((site.to_string(), slot.as_str()))
            .or_insert_with(|| (slot, StackAcc::default()));
        match role {
            "manager" => entry.1.manager = Some(running),
            "executor" => {
                entry.1.executor = Some(running);
                entry.1.image = item["Image"].as_str().unwrap_or_default().to_string();
            }
            _ => continue,
        }
        entry.1.healths.push(health);
    }
    stacks
        .into_iter()
        .map(|((site, _), (slot, acc))| StackInfo {
            site,
            slot,
            running: acc.manager == Some(true) && acc.executor == Some(true),
            health: aggregate_health(&acc.healths).to_string(),
            image: acc.image,
        })
        .collect()
}

fn net_error(e: reqwest::Error) -> ConnectorError {
    ConnectorError::Unavailable(format!("docker api unreachable: {e}"))
}

async fn read_capped(resp: &mut reqwest::Response) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(net_error)? {
        if out.len() + chunk.len() > MAX_BODY {
            return Err(ConnectorError::Internal(
                "docker api response exceeds 4 MiB".to_string(),
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn docker_error(status: u16, body: &[u8]) -> ConnectorError {
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(body).chars().take(200).collect());
    let message = format!("docker api {status}: {message}");
    match status {
        404 => ConnectorError::NotFound(message),
        409 => ConnectorError::Conflict(message),
        400..=499 => ConnectorError::Internal(message),
        _ => ConnectorError::Unavailable(message),
    }
}

fn stream_error(line: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(line.trim_ascii()).ok()?;
    let msg = v["error"]
        .as_str()
        .or_else(|| v["errorDetail"]["message"].as_str())?;
    Some(msg.chars().take(200).collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, HashSet};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use cite_edge::model::{HealthCheck, Maintenance, SiteKind, Source, Upstream};
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, body::Incoming};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use super::*;

    const TOKEN: &str = "ghp_secrettoken123";

    #[derive(Default)]
    pub(crate) struct Ctr {
        spec: Value,
        running: bool,
        // Extra keys merged into State on inspect: Health, RestartCount, ExitCode, OOMKilled, Status.
        state: Value,
        logs: Vec<u8>,
    }

    struct Net {
        labels: Value,
        internal: bool,
        members: HashSet<String>,
    }

    #[derive(Default)]
    pub(crate) struct Fake {
        images: HashSet<String>,
        volumes: BTreeMap<String, Value>,
        networks: BTreeMap<String, Net>,
        containers: BTreeMap<String, Ctr>,
        log: Vec<String>,
        pull_error: Option<String>,
        init_exit: i64,
        haproxy_missing: bool,
    }

    pub(crate) const HAPROXY: &str = "cite-node-haproxy";

    // reqwest percent-encodes query values, so the fake must decode them to match names.
    fn percent_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && i + 2 < b.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
            {
                out.push(v);
                i += 3;
            } else {
                out.push(if b[i] == b'+' { b' ' } else { b[i] });
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn query_param(query: &str, key: &str) -> Option<String> {
        query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then(|| percent_decode(v))
        })
    }

    fn container_name(path: &str) -> Option<(String, String)> {
        let rest = path.strip_prefix("/containers/")?;
        let (name, action) = rest.rsplit_once('/')?;
        Some((name.to_string(), action.to_string()))
    }

    // Minimal in-memory Docker Engine: only the endpoints the orchestrator calls.
    fn route(f: &mut Fake, method: &str, path: &str, query: &str, body: &[u8]) -> (u16, String) {
        let path = path.strip_prefix(API).unwrap_or(path);
        f.log.push(format!("{method} {path}"));
        let not_found = || (404, json!({ "message": "no such object" }).to_string());
        match (method, path) {
            ("GET", "/_ping") => (200, "OK".to_string()),
            ("POST", "/images/create") => {
                let repo = query_param(query, "fromImage").unwrap_or_default();
                let tag = query_param(query, "tag").unwrap_or_default();
                if let Some(err) = &f.pull_error {
                    return (
                        200,
                        format!("{{\"status\":\"Pulling\"}}\n{{\"error\":\"{err}\"}}\n"),
                    );
                }
                f.images.insert(format!("{repo}:{tag}"));
                (
                    200,
                    "{\"status\":\"Pulling\"}\n{\"status\":\"Done\"}\n".to_string(),
                )
            }
            ("POST", "/volumes/create") => {
                let v: Value = serde_json::from_slice(body).unwrap_or_default();
                f.volumes.insert(
                    v["Name"].as_str().unwrap_or_default().to_string(),
                    v["Labels"].clone(),
                );
                (201, "{}".to_string())
            }
            ("POST", "/networks/create") => {
                let v: Value = serde_json::from_slice(body).unwrap_or_default();
                let name = v["Name"].as_str().unwrap_or_default().to_string();
                if f.networks.contains_key(&name) {
                    return (409, json!({ "message": "network exists" }).to_string());
                }
                f.networks.insert(
                    name,
                    Net {
                        labels: v["Labels"].clone(),
                        internal: v["Internal"] == json!(true),
                        members: HashSet::new(),
                    },
                );
                (201, "{\"Id\":\"n\"}".to_string())
            }
            ("GET", p) if p.starts_with("/volumes/") => {
                match f.volumes.get(&p["/volumes/".len()..]) {
                    Some(labels) => (200, json!({ "Labels": labels }).to_string()),
                    None => not_found(),
                }
            }
            ("GET", p) if p.starts_with("/networks/") => {
                match f.networks.get(&p["/networks/".len()..]) {
                    Some(n) => {
                        let members: serde_json::Map<String, Value> = n
                            .members
                            .iter()
                            .map(|m| (format!("id-{m}"), json!({ "Name": m })))
                            .collect();
                        (
                            200,
                            json!({ "Labels": n.labels, "Internal": n.internal, "Containers": members })
                                .to_string(),
                        )
                    }
                    None => not_found(),
                }
            }
            ("POST", p) if p.starts_with("/networks/") => {
                let rest = &p["/networks/".len()..];
                let Some((name, action)) = rest.rsplit_once('/') else {
                    return not_found();
                };
                let v: Value = serde_json::from_slice(body).unwrap_or_default();
                let who = v["Container"].as_str().unwrap_or_default().to_string();
                let missing = f.haproxy_missing;
                let Some(net) = f.networks.get_mut(name) else {
                    return not_found();
                };
                match action {
                    "connect" if missing => {
                        (404, json!({ "message": "no such container" }).to_string())
                    }
                    "connect" => {
                        net.members.insert(who);
                        (200, String::new())
                    }
                    "disconnect" => {
                        net.members.remove(&who);
                        (200, String::new())
                    }
                    _ => not_found(),
                }
            }
            ("POST", "/containers/create") => {
                let name = query_param(query, "name").unwrap_or_default();
                f.log.push(format!("CREATE {name}"));
                if f.containers.contains_key(&name) {
                    return (409, json!({ "message": "name in use" }).to_string());
                }
                let spec: Value = serde_json::from_slice(body).unwrap_or_default();
                f.containers.insert(
                    name,
                    Ctr {
                        spec,
                        running: false,
                        ..Default::default()
                    },
                );
                (201, "{\"Id\":\"c\"}".to_string())
            }
            ("GET", "/containers/json") => {
                let list: Vec<Value> = f
                    .containers
                    .iter()
                    .filter(|(_, c)| c.spec["Labels"]["cite.managed"] == "true")
                    .map(|(name, c)| {
                        json!({
                            "Names": [format!("/{name}")],
                            "Labels": c.spec["Labels"],
                            "Image": c.spec["Image"],
                            "State": if c.running { "running" } else { "exited" },
                            "Status": if c.running {
                                "Up 2 minutes (healthy)"
                            } else {
                                "Exited (0) 1 minute ago"
                            },
                        })
                    })
                    .collect();
                (200, Value::Array(list).to_string())
            }
            ("GET", p) if p.starts_with("/images/") && p.ends_with("/json") => {
                let reference = &p["/images/".len()..p.len() - "/json".len()];
                if f.images.contains(reference) {
                    (200, "{}".to_string())
                } else {
                    not_found()
                }
            }
            ("GET", p) if p.starts_with("/containers/") && p.ends_with("/logs") => {
                let name = &p["/containers/".len()..p.len() - "/logs".len()];
                f.log.push(format!("LOGQ {query}"));
                match f.containers.get(name) {
                    Some(c) => (200, String::from_utf8(c.logs.clone()).unwrap()),
                    None => not_found(),
                }
            }
            ("GET", p) if p.starts_with("/containers/") && p.ends_with("/json") => {
                let name = &p["/containers/".len()..p.len() - "/json".len()];
                match f.containers.get(name) {
                    Some(c) => {
                        let mut state = json!({ "Running": c.running });
                        if let Some(extra) = c.state.as_object() {
                            for (k, v) in extra {
                                state[k] = v.clone();
                            }
                        }
                        (
                            200,
                            json!({
                                "State": state,
                                "Config": {
                                    "Image": c.spec["Image"],
                                    "Env": c.spec["Env"],
                                    "Labels": c.spec["Labels"],
                                },
                                "HostConfig": {
                                    "NetworkMode": c.spec["HostConfig"]["NetworkMode"],
                                    "Memory": c.spec["HostConfig"]["Memory"],
                                    "NanoCpus": c.spec["HostConfig"]["NanoCpus"],
                                },
                            })
                            .to_string(),
                        )
                    }
                    None => not_found(),
                }
            }
            ("POST", p) if p.starts_with("/containers/") => {
                let Some((name, action)) = container_name(p) else {
                    return not_found();
                };
                let init_exit = f.init_exit;
                let Some(c) = f.containers.get_mut(&name) else {
                    return not_found();
                };
                match action.as_str() {
                    "start" if c.running => (304, String::new()),
                    "start" => {
                        c.running = !name.ends_with("-init");
                        (204, String::new())
                    }
                    "stop" if !c.running => (304, String::new()),
                    "stop" => {
                        c.running = false;
                        (204, String::new())
                    }
                    "wait" => (200, json!({ "StatusCode": init_exit }).to_string()),
                    _ => not_found(),
                }
            }
            ("DELETE", p) if p.starts_with("/containers/") => {
                match f.containers.remove(&p["/containers/".len()..]) {
                    Some(_) => (204, String::new()),
                    None => not_found(),
                }
            }
            ("DELETE", p) if p.starts_with("/networks/") => {
                let name = &p["/networks/".len()..];
                match f.networks.get(name) {
                    Some(n) if !n.members.is_empty() => (
                        403,
                        json!({ "message": "network has active endpoints" }).to_string(),
                    ),
                    Some(_) => {
                        f.networks.remove(name);
                        (204, String::new())
                    }
                    None => not_found(),
                }
            }
            ("DELETE", p) if p.starts_with("/volumes/") => {
                match f.volumes.remove(&p["/volumes/".len()..]) {
                    Some(_) => (204, String::new()),
                    None => not_found(),
                }
            }
            _ => not_found(),
        }
    }

    pub(crate) fn drop_container(fake: &Arc<Mutex<Fake>>, name: &str) {
        fake.lock().unwrap().containers.remove(name);
    }

    // The Env array a created container was given, as text, for checking where a token ended up.
    pub(crate) fn container_env(fake: &Arc<Mutex<Fake>>, name: &str) -> String {
        fake.lock().unwrap().containers[name].spec["Env"].to_string()
    }

    pub(crate) async fn start_fake() -> (Orchestrator, Arc<Mutex<Fake>>) {
        start_fake_with(HAPROXY).await
    }

    async fn start_fake_with(haproxy: &str) -> (Orchestrator, Arc<Mutex<Fake>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fake = Arc::new(Mutex::new(Fake::default()));
        let shared = fake.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = shared.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let bytes = body
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default();
                            let (status, text) = {
                                let mut guard = state.lock().unwrap();
                                route(
                                    &mut guard,
                                    parts.method.as_str(),
                                    parts.uri.path(),
                                    parts.uri.query().unwrap_or_default(),
                                    &bytes,
                                )
                            };
                            let resp = Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(text)))
                                .unwrap();
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let orch = Orchestrator::new(
            &format!("tcp://{addr}"),
            "cite_edge",
            "0.2.0",
            "ghcr.io/seggys116",
        )
        .unwrap()
        .with_haproxy_container(haproxy)
        .unwrap();
        (orch, fake)
    }

    pub(crate) fn count(fake: &Arc<Mutex<Fake>>, entry: &str) -> usize {
        fake.lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| l.starts_with(entry))
            .count()
    }

    // Built through serde so the tests keep compiling as optional Source fields are added.
    fn source_with(runtime: Option<&str>, extra: Value) -> Source {
        let mut v = json!({ "repo": "acme/shop" });
        if let Some(r) = runtime {
            v["runtime"] = json!(r);
        }
        for (k, val) in extra.as_object().cloned().unwrap_or_default() {
            v[k] = val;
        }
        serde_json::from_value(v).unwrap()
    }

    fn site_with(id: &str, extra: Value) -> Site {
        let mut s = site(id, None);
        s.source = Some(source_with(None, extra));
        s
    }

    fn site(id: &str, runtime: Option<&str>) -> Site {
        Site {
            id: id.to_string(),
            name: id.to_string(),
            hosts: vec![format!("{id}.example.com")],
            path_regexes: Vec::new(),
            path_prefixes: Vec::new(),
            kind: SiteKind::Site,
            blue: Upstream::default(),
            green: Upstream::default(),
            active: Slot::Blue,
            maintenance: Maintenance::default(),
            health: HealthCheck::default(),
            source: Some(source_with(runtime, json!({}))),
            history: Vec::new(),
            access: Default::default(),
        }
    }

    fn stack_env<'a>(registry: &'a str, version: &'a str, isolate: bool) -> StackEnv<'a> {
        StackEnv {
            registry,
            version,
            edge_network: "cite_edge",
            isolate,
            github_api_url: None,
        }
    }

    fn plan_with(runtime: Option<&str>, git_ref: Option<&str>, isolate: bool) -> Result<Plan> {
        plan_stack(
            &site("shop", runtime),
            Slot::Blue,
            git_ref,
            TOKEN,
            &stack_env("ghcr.io/seggys116", "0.2.0", isolate),
        )
    }

    fn plan(runtime: Option<&str>, git_ref: Option<&str>) -> Result<Plan> {
        plan_with(runtime, git_ref, false)
    }

    #[test]
    fn from_host_accepts_tcp_and_http() {
        assert_eq!(
            parse_docker_host("tcp://socketproxy:2375").unwrap(),
            "http://socketproxy:2375"
        );
        assert_eq!(
            parse_docker_host("http://10.0.0.5:2375/").unwrap(),
            "http://10.0.0.5:2375"
        );
        assert!(
            Orchestrator::new("tcp://socketproxy:2375", "cite_edge", "0.2.0", "ghcr.io/x").is_ok()
        );
    }

    #[test]
    fn from_host_rejects_unix_and_malformed() {
        for bad in [
            "unix:///var/run/docker.sock",
            "/var/run/docker.sock",
            "https://proxy:2375",
            "tcp://proxy",
            "tcp://proxy:0",
            "tcp://proxy:99999",
            "tcp://:2375",
            "tcp://pro xy:2375",
            "tcp://proxy:2375/path",
            "",
        ] {
            assert!(
                matches!(parse_docker_host(bad), Err(ConnectorError::BadRequest(_))),
                "{bad}"
            );
        }
        let err = Orchestrator::new(
            "unix:///var/run/docker.sock",
            "cite_edge",
            "0.2.0",
            "ghcr.io/x",
        );
        assert!(matches!(err, Err(ConnectorError::BadRequest(_))));
    }

    #[test]
    fn new_rejects_hostile_names() {
        assert!(Orchestrator::new("tcp://p:1", "a b", "0.2.0", "ghcr.io/x").is_err());
        assert!(Orchestrator::new("tcp://p:1", "cite_edge", "0.2.0/../x", "ghcr.io/x").is_err());
        assert!(Orchestrator::new("tcp://p:1", "cite_edge", "0.2.0", "ghcr.io/../x").is_err());
    }

    #[test]
    fn git_ref_validation() {
        for ok in ["main", "release/1.2", "v1.0.0", "feat_x-y", "a"] {
            assert!(validate_git_ref(ok).is_ok(), "{ok}");
        }
        let long = "a".repeat(101);
        for bad in [
            "",
            "-rf",
            "--upload-pack=x",
            "a..b",
            "a b",
            "a;rm -rf /",
            "$(id)",
            "a\nb",
            "a`b`",
            "a&b",
            long.as_str(),
        ] {
            assert!(validate_git_ref(bad).is_err(), "{bad:?}");
        }
        assert!(plan(None, Some("--evil")).is_err());
    }

    #[test]
    fn image_table_for_each_runtime() {
        let r = "ghcr.io/seggys116";
        assert_eq!(
            image_refs(r, "0.2.0", "node", 22).unwrap(),
            (
                format!("{r}/cite-manager:0.2.0-node22"),
                format!("{r}/cite-executor-node:0.2.0-node22")
            )
        );
        assert_eq!(
            image_refs(r, "0.2.0", "node", 24).unwrap(),
            (
                format!("{r}/cite-manager:0.2.0-node24"),
                format!("{r}/cite-executor-node:0.2.0-node24")
            )
        );
        assert_eq!(
            image_refs(r, "0.2.0", "bun", 22).unwrap(),
            (
                format!("{r}/cite-manager:0.2.0-node22"),
                format!("{r}/cite-executor-bun:0.2.0")
            )
        );
        assert_eq!(
            image_refs(r, "0.2.0", "static", 22).unwrap(),
            (
                format!("{r}/cite-manager:0.2.0-node22"),
                format!("{r}/cite-executor-static:0.2.0")
            )
        );
        assert_eq!(
            image_refs(r, "0.2.0", "rust", 22).unwrap(),
            (
                format!("{r}/cite-manager-rust:0.2.0"),
                format!("{r}/cite-executor-rust:0.2.0")
            )
        );
        assert!(image_refs(r, "0.2.0", "python", 22).is_err());
        assert!(image_refs(r, "0.2.0", "node", 18).is_err());
        assert!(image_refs(r, "0.2.0", "rust", 18).is_ok());
    }

    #[test]
    fn poll_interval_defaults_and_validates() {
        assert_eq!(poll_interval(None).unwrap(), "5m");
        assert_eq!(poll_interval(Some("  ")).unwrap(), "5m");
        assert_eq!(poll_interval(Some("10m")).unwrap(), "10m");
        assert_eq!(poll_interval(Some("off")).unwrap(), "off");
        assert!(poll_interval(Some("5 minutes please")).is_err());
        assert!(poll_interval(Some("10s")).is_err());
        assert!(poll_interval(Some("1m\nCITE_X=1")).is_err());
    }

    #[test]
    fn manager_spec_is_hardened() {
        let p = plan(None, None).unwrap();
        let hc = &p.manager["HostConfig"];
        assert_eq!(hc["CapDrop"], json!(["ALL"]));
        assert_eq!(
            hc["CapAdd"],
            json!(["CHOWN", "SETUID", "SETGID", "DAC_READ_SEARCH"])
        );
        assert_eq!(hc["ReadonlyRootfs"], json!(true));
        assert_eq!(hc["SecurityOpt"], json!(["no-new-privileges:true"]));
        assert_eq!(hc["PidsLimit"], json!(2048));
        assert_eq!(hc["Memory"], json!(4 * GIB));
        assert_eq!(hc["NanoCpus"], json!(2_000_000_000i64));
        assert_eq!(hc["Tmpfs"]["/tmp"], json!("size=256m,mode=1777"));
        assert_eq!(hc["Tmpfs"]["/run/cite"], json!("size=16m,mode=0750"));
        assert_eq!(hc["NetworkMode"], json!("cite-shop-blue-egress"));
        assert_eq!(
            p.manager["Healthcheck"]["Test"],
            json!(["CMD", "cite-manager", "healthcheck"])
        );
        let mounts = hc["Mounts"].as_array().unwrap();
        let status = mounts
            .iter()
            .find(|m| m["Target"] == "/var/lib/cite/status")
            .unwrap();
        assert_eq!(status["ReadOnly"], json!(true));
        assert_eq!(status["VolumeOptions"]["Subpath"], json!("status"));
        let state = mounts
            .iter()
            .find(|m| m["Target"] == "/var/lib/cite/state")
            .unwrap();
        assert_eq!(state["ReadOnly"], json!(false));
    }

    #[test]
    fn executor_spec_is_hardened_and_isolated() {
        let p = plan(None, None).unwrap();
        let hc = &p.executor["HostConfig"];
        assert_eq!(p.executor["User"], json!("65532:65532"));
        assert_eq!(hc["CapDrop"], json!(["ALL"]));
        assert!(hc.get("CapAdd").is_none());
        assert_eq!(hc["ReadonlyRootfs"], json!(true));
        assert_eq!(hc["SecurityOpt"], json!(["no-new-privileges:true"]));
        assert_eq!(hc["PidsLimit"], json!(256));
        assert_eq!(hc["Memory"], json!(2 * GIB));
        assert_eq!(hc["NanoCpus"], json!(2_000_000_000i64));
        assert_eq!(
            hc["Tmpfs"]["/tmp"],
            json!("size=64m,mode=1777,noexec,nosuid,nodev")
        );
        assert!(hc.get("PortBindings").is_none());
        assert!(p.executor.get("ExposedPorts").is_none());
        assert_eq!(hc["NetworkMode"], json!("cite_edge"));
        let endpoints = p.executor["NetworkingConfig"]["EndpointsConfig"]
            .as_object()
            .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints["cite_edge"]["Aliases"],
            json!(["cite-shop-blue-executor"])
        );
        assert!(!p.executor.to_string().contains("egress"));
        let mounts = hc["Mounts"].as_array().unwrap();
        for target in ["/var/lib/cite/releases", "/var/lib/cite/control"] {
            let m = mounts.iter().find(|m| m["Target"] == target).unwrap();
            assert_eq!(m["ReadOnly"], json!(true), "{target}");
        }
        assert!(mounts.iter().all(|m| m["Target"] != "/var/lib/cite/state"));
    }

    #[test]
    fn init_spec_is_minimal() {
        let p = plan(None, None).unwrap();
        let hc = &p.init["HostConfig"];
        assert_eq!(p.init["User"], json!("0:0"));
        assert_eq!(hc["NetworkMode"], json!("none"));
        assert_eq!(hc["CapDrop"], json!(["ALL"]));
        assert_eq!(hc["CapAdd"], json!(["CHOWN", "FOWNER"]));
        assert_eq!(hc["ReadonlyRootfs"], json!(true));
        assert_eq!(hc["SecurityOpt"], json!(["no-new-privileges:true"]));
        assert!(hc["PidsLimit"].as_i64().unwrap() > 0);
        let script = p.init["Cmd"][0].as_str().unwrap();
        assert!(script.contains("mkdir -p /data/releases/blue /data/releases/green"));
        assert!(script.contains("chown 65532:65532 /data/status"));
        assert!(script.contains("chmod 0750 /data/state"));
    }

    #[test]
    fn specs_have_no_host_access() {
        let p = plan(None, None).unwrap();
        for spec in [&p.manager, &p.executor, &p.init] {
            let text = spec.to_string();
            assert!(!text.contains("docker.sock"));
            assert!(!text.contains("Privileged"));
            assert!(!text.contains("Devices"));
            assert!(!text.contains("PidMode"));
            assert!(!text.contains("\"host\""));
            let hc = &spec["HostConfig"];
            assert!(hc.get("Binds").is_none());
            for m in hc["Mounts"].as_array().unwrap() {
                assert_eq!(m["Type"], json!("volume"));
                assert!(!m["Source"].as_str().unwrap().starts_with('/'));
            }
        }
    }

    #[test]
    fn token_only_in_manager_env() {
        let p = plan(None, None).unwrap();
        let env = p.manager["Env"].as_array().unwrap();
        assert!(
            env.iter()
                .any(|e| e == &json!(format!("CITE_GITHUB_TOKEN={TOKEN}")))
        );
        assert!(!p.manager["Labels"].to_string().contains(TOKEN));
        assert!(!p.executor.to_string().contains(TOKEN));
        assert!(!p.init.to_string().contains(TOKEN));
        let mut without_env = p.manager.clone();
        without_env["Env"] = json!([]);
        assert!(!without_env.to_string().contains(TOKEN));
    }

    #[test]
    fn github_api_url_validator_accepts_plain_urls() {
        for ok in [
            "https://api.github.com",
            "https://ghe.example.com/api/v3",
            "http://host.docker.internal:18080",
            "http://127.0.0.1:8080/",
            "http://mock-github:8080",
        ] {
            assert_eq!(validate_github_api_url(ok), Ok(()), "{ok}");
        }
    }

    #[test]
    fn github_api_url_validator_refuses_hostile_urls() {
        let long = format!("https://{}.example.com", "a".repeat(200));
        for bad in [
            "",
            "ftp://ghe.example.com",
            "file:///etc/passwd",
            "ghe.example.com",
            "HTTPS://ghe.example.com",
            "https://",
            "https://user@ghe.example.com",
            "https://user:pw@ghe.example.com",
            "https://ghe.example.com?x=1",
            "https://ghe.example.com/a?x=1",
            "https://ghe.example.com/#frag",
            "https://ghe.example.com:abc",
            "https://ghe.example.com:0",
            "https://ghe.example.com:99999",
            "https://ghe.example.com:",
            "https://ghe example.com",
            "https://ghe.example.com/a b",
            "https://ghe.example.com\\evil.test",
            "https://ghe.example.com/%2e%2e",
            "https://ghe.example.com//x",
            "https://ghe.example.com/../x",
            "https://.example.com",
            "https://exa_mple.com:80@evil.test",
            "https://ghe.example.com\n",
            "https://ghe.example.com\"x",
            "https://ghe.example.com/\u{e9}",
            long.as_str(),
        ] {
            assert!(validate_github_api_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn github_api_url_reaches_only_the_manager_env() {
        let env = StackEnv {
            github_api_url: Some("https://ghe.example.com/api/v3"),
            ..stack_env("ghcr.io/seggys116", "0.2.0", true)
        };
        let p = plan_stack(&site("shop", None), Slot::Blue, None, TOKEN, &env).unwrap();
        let line = json!("CITE_GITHUB_API_URL=https://ghe.example.com/api/v3");
        assert!(p.manager["Env"].as_array().unwrap().contains(&line));
        assert!(!p.executor.to_string().contains("CITE_GITHUB_API_URL"));
        assert!(!p.init.to_string().contains("CITE_GITHUB_API_URL"));
        let unset = plan(None, None).unwrap();
        assert!(!unset.manager.to_string().contains("CITE_GITHUB_API_URL"));
        let bad = StackEnv {
            github_api_url: Some("https://u:p@evil.test"),
            ..stack_env("ghcr.io/seggys116", "0.2.0", true)
        };
        let err = plan_stack(&site("shop", None), Slot::Blue, None, TOKEN, &bad);
        assert!(matches!(err, Err(ConnectorError::BadRequest(_))));
    }

    #[test]
    fn orchestrator_refuses_a_bad_github_api_url() {
        let make = || Orchestrator::new("tcp://proxy:2375", "cite_edge", "0.2.0", "ghcr.io/x");
        assert!(
            make()
                .unwrap()
                .with_github_api_url(Some("https://ghe.example.com"))
                .is_ok()
        );
        assert!(make().unwrap().with_github_api_url(None).is_ok());
        assert!(
            make()
                .unwrap()
                .with_github_api_url(Some("https://u@ghe.example.com"))
                .is_err()
        );
    }

    #[test]
    fn labels_identify_the_stack() {
        let p = plan(None, None).unwrap();
        for (spec, role) in [(&p.manager, "manager"), (&p.executor, "executor")] {
            assert_eq!(spec["Labels"]["cite.managed"], json!("true"));
            assert_eq!(spec["Labels"]["cite.site"], json!("shop"));
            assert_eq!(spec["Labels"]["cite.slot"], json!("blue"));
            assert_eq!(spec["Labels"]["cite.role"], json!(role));
        }
    }

    #[test]
    fn manager_env_follows_source() {
        let mut s = site("shop", Some("node"));
        if let Some(src) = s.source.as_mut() {
            src.branch = Some("develop".to_string());
            src.poll_interval = Some("10m".to_string());
            src.node_major = Some(24);
        }
        let p = plan_stack(
            &s,
            Slot::Green,
            Some("release/1"),
            TOKEN,
            &stack_env("r.io/o", "1.0.0", false),
        )
        .unwrap();
        let env: Vec<&str> = p.manager["Env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(env.contains(&"CITE_REPO=acme/shop"));
        assert!(env.contains(&"CITE_BRANCH=release/1"));
        assert!(env.contains(&"CITE_POLL_INTERVAL=10m"));
        assert!(env.contains(&"CITE_NODE=24"));
        assert_eq!(
            p.manager["Image"],
            json!("r.io/o/cite-manager:1.0.0-node24")
        );
        assert_eq!(
            p.executor["Image"],
            json!("r.io/o/cite-executor-node:1.0.0-node24")
        );
        let rust = plan(Some("rust"), None).unwrap();
        let env = rust.manager["Env"].to_string();
        assert!(!env.contains("CITE_NODE="));
    }

    #[test]
    fn plan_rejects_bad_site_inputs() {
        let mut s = site("shop", None);
        s.id = "Bad Id".to_string();
        assert!(
            plan_stack(
                &s,
                Slot::Blue,
                None,
                TOKEN,
                &stack_env("r.io/o", "1", false)
            )
            .is_err()
        );
        let mut s = site("shop", None);
        s.source = None;
        assert!(
            plan_stack(
                &s,
                Slot::Blue,
                None,
                TOKEN,
                &stack_env("r.io/o", "1", false)
            )
            .is_err()
        );
        let mut s = site("shop", None);
        if let Some(src) = s.source.as_mut() {
            src.repo = "acme/shop; rm".to_string();
        }
        assert!(
            plan_stack(
                &s,
                Slot::Blue,
                None,
                TOKEN,
                &stack_env("r.io/o", "1", false)
            )
            .is_err()
        );
        let s = site("shop", None);
        assert!(
            plan_stack(
                &s,
                Slot::Blue,
                None,
                "tok en",
                &stack_env("r.io/o", "1", false)
            )
            .is_err()
        );
        assert!(plan_stack(&s, Slot::Blue, None, "", &stack_env("r.io/o", "1", false)).is_err());
    }

    #[test]
    fn health_status_parsing() {
        assert_eq!(health_from_status("Up 2 minutes (healthy)"), "healthy");
        assert_eq!(health_from_status("Up 2 minutes (unhealthy)"), "unhealthy");
        assert_eq!(
            health_from_status("Up 5 seconds (health: starting)"),
            "starting"
        );
        assert_eq!(health_from_status("Exited (0) 1 minute ago"), "none");
        assert_eq!(aggregate_health(&["healthy", "starting"]), "starting");
        assert_eq!(aggregate_health(&["healthy", "unhealthy"]), "unhealthy");
        assert_eq!(aggregate_health(&["healthy", "healthy"]), "healthy");
        assert_eq!(aggregate_health(&[]), "none");
    }

    #[test]
    fn docker_error_mapping() {
        let body = br#"{"message":"boom"}"#;
        assert!(
            matches!(docker_error(404, body), ConnectorError::NotFound(m) if m.contains("boom"))
        );
        assert!(matches!(
            docker_error(409, body),
            ConnectorError::Conflict(_)
        ));
        assert!(matches!(
            docker_error(400, body),
            ConnectorError::Internal(_)
        ));
        assert!(matches!(
            docker_error(500, body),
            ConnectorError::Unavailable(_)
        ));
        assert!(
            matches!(docker_error(503, b"plain text"), ConnectorError::Unavailable(m) if m.contains("plain text"))
        );
    }

    #[tokio::test]
    async fn ping_reaches_the_api() {
        let (orch, fake) = start_fake().await;
        orch.ping().await.unwrap();
        assert_eq!(count(&fake, "GET /_ping"), 1);
    }

    #[tokio::test]
    async fn ping_fails_when_unreachable() {
        let orch =
            Orchestrator::new("tcp://127.0.0.1:1", "cite_edge", "0.2.0", "ghcr.io/x").unwrap();
        assert!(matches!(
            orch.ping().await,
            Err(ConnectorError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn ensure_creates_the_whole_stack() {
        let (orch, fake) = start_fake().await;
        let targets = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(
            targets,
            vec![Target {
                addr: "cite-shop-blue-executor:8080".to_string(),
                weight: 100
            }]
        );
        let f = fake.lock().unwrap();
        assert_eq!(f.images.len(), 2);
        assert!(
            f.images
                .contains("ghcr.io/seggys116/cite-manager:0.2.0-node22")
        );
        assert!(
            f.images
                .contains("ghcr.io/seggys116/cite-executor-node:0.2.0-node22")
        );
        let volumes: HashSet<&str> = f.volumes.keys().map(String::as_str).collect();
        assert_eq!(
            volumes,
            HashSet::from([
                "cite-shop-blue-data",
                "cite-shop-blue-work",
                "cite-shop-blue-cache"
            ])
        );
        assert!(f.networks.contains_key("cite-shop-blue-egress"));
        assert!(f.networks.contains_key("cite-shop-blue-net"));
        let names: Vec<&str> = f.containers.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            vec!["cite-shop-blue-executor", "cite-shop-blue-manager"]
        );
        assert!(f.containers.values().all(|c| c.running));
        let init_create = f
            .log
            .iter()
            .position(|l| l == "CREATE cite-shop-blue-init")
            .unwrap();
        let manager_create = f
            .log
            .iter()
            .position(|l| l == "CREATE cite-shop-blue-manager")
            .unwrap();
        assert!(init_create < manager_create);
        assert!(
            f.log
                .contains(&"DELETE /containers/cite-shop-blue-init".to_string())
        );
    }

    #[tokio::test]
    async fn second_ensure_is_a_no_op() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        // Volume and network creates are idempotent probes; nothing may be created or pulled.
        let before = fake.lock().unwrap().log.len();
        let targets = orch
            .ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(targets.len(), 1);
        let f = fake.lock().unwrap();
        let after: Vec<&String> = f.log[before..].iter().collect();
        assert!(
            after.iter().all(|l| l.starts_with("GET ")
                || l.starts_with("POST /volumes")
                || l.starts_with("POST /networks")),
            "{after:?}"
        );
        assert!(!after.iter().any(|l| l.contains("/containers/create")));
        assert!(!after.iter().any(|l| l.contains("/images/create")));
        assert_eq!(f.containers.len(), 2);
    }

    #[tokio::test]
    async fn images_are_pulled_only_when_absent() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("a", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "POST /images/create"), 2);
        orch.ensure_stack(&site("b", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "POST /images/create"), 2);
    }

    #[tokio::test]
    async fn changed_token_recreates_only_the_manager() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.ensure_stack(&s, Slot::Blue, None, "ghp_rotated")
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 1);
        let f = fake.lock().unwrap();
        let env = f.containers["cite-shop-blue-manager"].spec["Env"].to_string();
        assert!(env.contains("ghp_rotated"));
        assert!(!env.contains(TOKEN));
    }

    #[tokio::test]
    async fn ensure_manager_never_touches_a_stale_executor() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let resized = site_with("shop", json!({ "memory_mb": 512, "cpus": 0.5 }));
        let orch = orch.with_limits(Limits {
            manager_memory: 3 * GIB,
            ..Limits::default()
        });
        let opts = StackOpts {
            runtime_env: Some([("API".to_string(), "v2".to_string())].into()),
            ..StackOpts::default()
        };
        let before = fake.lock().unwrap().containers["cite-shop-blue-executor"]
            .spec
            .clone();
        let log_start = fake.lock().unwrap().log.len();
        orch.ensure_manager(&resized, Slot::Blue, None, "ghp_rotated", &opts)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 1);
        {
            let f = fake.lock().unwrap();
            let executor = &f.containers["cite-shop-blue-executor"];
            assert!(executor.running);
            assert_eq!(executor.spec, before);
            let touched: Vec<&String> = f.log[log_start..]
                .iter()
                .filter(|e| e.contains("cite-shop-blue-executor"))
                .collect();
            assert!(touched.is_empty(), "{touched:?}");
            let env = f.containers["cite-shop-blue-manager"].spec["Env"].to_string();
            assert!(env.contains("ghp_rotated"));
        }
        orch.ensure_manager(&resized, Slot::Blue, None, "ghp_rotated", &opts)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
    }

    #[tokio::test]
    async fn a_spec_the_proxy_would_refuse_never_removes_the_running_containers() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let log_start = fake.lock().unwrap().log.len();
        let owned = StackOpts {
            runtime_env: Some([("NODE_ENV".to_string(), "production".to_string())].into()),
            ..StackOpts::default()
        };
        let err = orch
            .ensure_stack_with(&s, Slot::Blue, None, TOKEN, &owned)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ConnectorError::BadRequest(m) if m.contains("executor") && m.contains("NODE_ENV")),
            "{err:?}"
        );
        let reserved = StackOpts {
            build_env: Some([("SHELL".to_string(), "/bin/bash".to_string())].into()),
            ..StackOpts::default()
        };
        let err = orch
            .ensure_manager(&s, Slot::Blue, None, "ghp_rotated", &reserved)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ConnectorError::BadRequest(m) if m.contains("SHELL")),
            "{err:?}"
        );
        let legacy = site_with("shop", json!({ "cpus": 0.1 }));
        let err = orch
            .ensure_stack(&legacy, Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ConnectorError::BadRequest(m) if m.contains("cpus")),
            "{err:?}"
        );
        let f = fake.lock().unwrap();
        assert_eq!(f.log.len(), log_start, "{:?}", &f.log[log_start..]);
        assert!(f.containers["cite-shop-blue-executor"].running);
        assert!(f.containers["cite-shop-blue-manager"].running);
    }

    #[test]
    fn site_overrides_above_the_node_maximum_are_refused() {
        let node = Limits::default();
        node.check_source(&source_with(
            None,
            json!({ "memory_mb": 16384, "cpus": 8.0, "build_memory_mb": 512, "build_cpus": 0.25 }),
        ))
        .unwrap();
        let err = node
            .check_source(&source_with(None, json!({ "memory_mb": 16385 })))
            .unwrap_err();
        assert!(
            matches!(&err, ConnectorError::BadRequest(m) if m.contains("memory_mb") && m.contains("CITE_STACK_MAX_MEM")),
            "{err:?}"
        );
        let err = node
            .check_source(&source_with(None, json!({ "build_cpus": 8.5 })))
            .unwrap_err();
        assert!(
            matches!(&err, ConnectorError::BadRequest(m) if m.contains("build_cpus") && m.contains("CITE_STACK_MAX_CPUS")),
            "{err:?}"
        );
        let tight =
            Limits::from_lookup(|k| (k == "CITE_STACK_MAX_MEM").then(|| "1g".to_string())).unwrap();
        assert!(
            tight
                .check_source(&source_with(None, json!({ "build_memory_mb": 2048 })))
                .is_err()
        );
        let huge = Limits::from_lookup(|k| (k == "CITE_STACK_MAX_MEM").then(|| "2t".to_string()));
        assert!(matches!(huge, Err(ConnectorError::BadRequest(_))));
    }

    #[tokio::test]
    async fn changed_ref_recreates_the_manager() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.ensure_stack(&s, Slot::Blue, Some("release/2"), TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        let f = fake.lock().unwrap();
        let env = f.containers["cite-shop-blue-manager"].spec["Env"].to_string();
        assert!(env.contains("CITE_BRANCH=release/2"));
    }

    #[tokio::test]
    async fn slot_ref_reports_the_branch_the_manager_runs() {
        let (orch, _fake) = start_fake().await;
        let s = site("shop", None);
        assert_eq!(orch.slot_ref("shop", Slot::Green).await.unwrap(), None);
        orch.ensure_stack(&s, Slot::Green, Some("v1"), TOKEN)
            .await
            .unwrap();
        orch.stop_stack("shop", Slot::Green).await.unwrap();
        assert_eq!(
            orch.slot_ref("shop", Slot::Green).await.unwrap().as_deref(),
            Some("v1")
        );
    }

    #[tokio::test]
    async fn stopped_stack_is_restarted_without_recreate() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.stop_stack("shop", Slot::Blue).await.unwrap();
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 1);
        assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
    }

    #[tokio::test]
    async fn pull_error_is_reported() {
        let (orch, fake) = start_fake().await;
        fake.lock().unwrap().pull_error = Some("denied".to_string());
        let err = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("denied"), "{err}");
        assert!(fake.lock().unwrap().containers.is_empty());
    }

    #[tokio::test]
    async fn init_failure_aborts_and_cleans_up() {
        let (orch, fake) = start_fake().await;
        fake.lock().unwrap().init_exit = 3;
        let err = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exit code 3"), "{err}");
        assert!(fake.lock().unwrap().containers.is_empty());
    }

    #[tokio::test]
    async fn unmanaged_container_name_is_a_conflict() {
        let (orch, fake) = start_fake().await;
        fake.lock()
            .unwrap()
            .containers
            .insert("cite-shop-blue-manager".to_string(), unmanaged_ctr());
        let err = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)));
    }

    #[tokio::test]
    async fn runtime_selects_images() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("docs", Some("static")), Slot::Green, None, TOKEN)
            .await
            .unwrap();
        let f = fake.lock().unwrap();
        assert_eq!(
            f.containers["cite-docs-green-executor"].spec["Image"],
            json!("ghcr.io/seggys116/cite-executor-static:0.2.0")
        );
        assert_eq!(
            f.containers["cite-docs-green-manager"].spec["Image"],
            json!("ghcr.io/seggys116/cite-manager:0.2.0-node22")
        );
    }

    #[tokio::test]
    async fn stop_stops_executor_before_manager_and_keeps_data() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
        orch.stop_stack("shop", Slot::Blue).await.unwrap();
        assert!(!orch.stack_running("shop", Slot::Blue).await.unwrap());
        let f = fake.lock().unwrap();
        let exec = f
            .log
            .iter()
            .position(|l| l == "POST /containers/cite-shop-blue-executor/stop");
        let mgr = f
            .log
            .iter()
            .position(|l| l == "POST /containers/cite-shop-blue-manager/stop");
        assert!(exec.unwrap() < mgr.unwrap());
        assert_eq!(f.containers.len(), 2);
        assert_eq!(f.volumes.len(), 3);
    }

    #[tokio::test]
    async fn stop_and_running_tolerate_missing_stack() {
        let (orch, _fake) = start_fake().await;
        orch.stop_stack("ghost", Slot::Green).await.unwrap();
        assert!(!orch.stack_running("ghost", Slot::Green).await.unwrap());
        orch.remove_stack("ghost", true).await.unwrap();
    }

    #[tokio::test]
    async fn remove_keeps_volumes_unless_purged() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.ensure_stack(&s, Slot::Green, None, TOKEN)
            .await
            .unwrap();
        orch.remove_stack("shop", false).await.unwrap();
        {
            let f = fake.lock().unwrap();
            assert!(f.containers.is_empty());
            assert!(f.networks.is_empty());
            assert_eq!(f.volumes.len(), 6);
        }
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.remove_stack("shop", true).await.unwrap();
        let f = fake.lock().unwrap();
        assert!(f.containers.is_empty());
        assert!(f.volumes.is_empty());
    }

    #[tokio::test]
    async fn remove_leaves_other_sites_alone() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.ensure_stack(&site("docs", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.remove_stack("shop", true).await.unwrap();
        let f = fake.lock().unwrap();
        assert!(f.containers.keys().all(|n| n.starts_with("cite-docs-")));
        assert_eq!(f.containers.len(), 2);
        assert_eq!(f.volumes.len(), 3);
    }

    #[tokio::test]
    async fn list_reports_running_stacks() {
        let (orch, _fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.ensure_stack(&site("docs", Some("bun")), Slot::Green, None, TOKEN)
            .await
            .unwrap();
        orch.stop_stack("docs", Slot::Green).await.unwrap();
        let stacks = orch.list_stacks().await.unwrap();
        assert_eq!(stacks.len(), 2);
        let shop = stacks.iter().find(|s| s.site == "shop").unwrap();
        assert_eq!(shop.slot, Slot::Blue);
        assert!(shop.running);
        assert_eq!(shop.health, "healthy");
        assert_eq!(
            shop.image,
            "ghcr.io/seggys116/cite-executor-node:0.2.0-node22"
        );
        let docs = stacks.iter().find(|s| s.site == "docs").unwrap();
        assert!(!docs.running);
        assert_eq!(docs.slot, Slot::Green);
        let json = serde_json::to_value(shop).unwrap();
        assert_eq!(json["slot"], json!("blue"));
    }

    // Stands in for a recreated HAProxy: it sits on no network and the connector has not yet reconciled.
    pub(crate) fn recreate_haproxy(orch: &Orchestrator, fake: &Arc<Mutex<Fake>>) {
        for net in fake.lock().unwrap().networks.values_mut() {
            net.members.clear();
        }
        orch.reconciled.store(false, Ordering::Release);
    }

    pub(crate) fn members(fake: &Arc<Mutex<Fake>>, net: &str) -> HashSet<String> {
        fake.lock().unwrap().networks[net].members.clone()
    }

    fn unmanaged_ctr() -> Ctr {
        Ctr {
            spec: json!({ "Image": "evil", "Env": [], "Labels": {} }),
            running: true,
            ..Default::default()
        }
    }

    #[test]
    fn isolated_executor_gets_its_own_network() {
        let p = plan_with(None, None, true).unwrap();
        let hc = &p.executor["HostConfig"];
        assert_eq!(hc["NetworkMode"], json!("cite-shop-blue-net"));
        let endpoints = p.executor["NetworkingConfig"]["EndpointsConfig"]
            .as_object()
            .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints["cite-shop-blue-net"]["Aliases"],
            json!(["cite-shop-blue-executor"])
        );
        assert!(!p.executor.to_string().contains("cite_edge"));
        assert_eq!(
            p.manager["HostConfig"]["NetworkMode"],
            json!("cite-shop-blue-egress")
        );
    }

    #[test]
    fn stack_specs_list_every_resource() {
        let s = site("shop", Some("rust"));
        let specs = stack_specs(
            &s,
            Slot::Green,
            None,
            TOKEN,
            &stack_env("r.io/o", "1.0.0", true),
        )
        .unwrap();
        assert_eq!(specs.manager_name, "cite-shop-green-manager");
        assert_eq!(specs.init_name, "cite-shop-green-init");
        assert_eq!(
            specs.networks,
            vec!["cite-shop-green-egress", "cite-shop-green-net"]
        );
        assert_eq!(specs.volumes.len(), 3);
        assert_eq!(specs.executor_image, "r.io/o/cite-executor-rust:1.0.0");
        let edge = stack_specs(
            &s,
            Slot::Green,
            None,
            TOKEN,
            &stack_env("r.io/o", "1.0.0", false),
        )
        .unwrap();
        assert_eq!(edge.networks, vec!["cite-shop-green-egress"]);
    }

    #[test]
    fn haproxy_container_name_is_validated() {
        let orch = Orchestrator::new("tcp://p:1", "cite_edge", "0.2.0", "ghcr.io/x").unwrap();
        assert!(orch.with_haproxy_container("a b").is_err());
        let orch = Orchestrator::new("tcp://p:1", "cite_edge", "0.2.0", "ghcr.io/x").unwrap();
        assert!(!orch.with_haproxy_container("").unwrap().isolated());
    }

    #[tokio::test]
    async fn isolated_stack_attaches_haproxy_to_an_internal_network() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let f = fake.lock().unwrap();
        assert!(f.networks["cite-shop-blue-net"].internal);
        assert!(!f.networks["cite-shop-blue-egress"].internal);
        assert_eq!(
            f.networks["cite-shop-blue-net"].labels["cite.managed"],
            json!("true")
        );
        assert!(f.networks["cite-shop-blue-net"].members.contains(HAPROXY));
        assert_eq!(
            f.containers["cite-shop-blue-executor"].spec["HostConfig"]["NetworkMode"],
            json!("cite-shop-blue-net")
        );
        let connect = f
            .log
            .iter()
            .position(|l| l == "POST /networks/cite-shop-blue-net/connect")
            .unwrap();
        let exec = f
            .log
            .iter()
            .position(|l| l == "CREATE cite-shop-blue-executor")
            .unwrap();
        assert!(connect < exec);
    }

    #[tokio::test]
    async fn sites_do_not_share_a_network() {
        let (orch, fake) = start_fake().await;
        for id in ["shop", "docs"] {
            orch.ensure_stack(&site(id, None), Slot::Blue, None, TOKEN)
                .await
                .unwrap();
        }
        let f = fake.lock().unwrap();
        let mode = |n: &str| f.containers[n].spec["HostConfig"]["NetworkMode"].clone();
        assert_ne!(
            mode("cite-shop-blue-executor"),
            mode("cite-docs-blue-executor")
        );
        assert!(
            f.networks["cite-shop-blue-net"]
                .members
                .is_subset(&HashSet::from([HAPROXY.to_string()]))
        );
    }

    #[tokio::test]
    async fn empty_haproxy_name_falls_back_to_the_edge_network() {
        let (orch, fake) = start_fake_with("").await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let f = fake.lock().unwrap();
        assert!(!f.networks.contains_key("cite-shop-blue-net"));
        assert_eq!(
            f.containers["cite-shop-blue-executor"].spec["HostConfig"]["NetworkMode"],
            json!("cite_edge")
        );
        assert!(!f.log.iter().any(|l| l.contains("/connect")));
    }

    #[tokio::test]
    async fn stop_cuts_haproxy_off_but_keeps_the_network() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.stop_stack("shop", Slot::Blue).await.unwrap();
        assert!(members(&fake, "cite-shop-blue-net").is_empty());
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert!(members(&fake, "cite-shop-blue-net").contains(HAPROXY));
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 1);
    }

    #[tokio::test]
    async fn remove_detaches_haproxy_before_deleting_the_network() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.remove_stack("shop", false).await.unwrap();
        let f = fake.lock().unwrap();
        assert!(f.networks.is_empty());
        let detach = f
            .log
            .iter()
            .position(|l| l == "POST /networks/cite-shop-blue-net/disconnect")
            .unwrap();
        let delete = f
            .log
            .iter()
            .position(|l| l == "DELETE /networks/cite-shop-blue-net")
            .unwrap();
        assert!(detach < delete);
    }

    #[tokio::test]
    async fn reconcile_reattaches_running_stacks_only() {
        let (orch, fake) = start_fake().await;
        for id in ["shop", "docs"] {
            orch.ensure_stack(&site(id, None), Slot::Blue, None, TOKEN)
                .await
                .unwrap();
        }
        orch.stop_stack("docs", Slot::Blue).await.unwrap();
        for net in fake.lock().unwrap().networks.values_mut() {
            net.members.clear();
        }
        orch.reconcile_networks().await.unwrap();
        assert!(members(&fake, "cite-shop-blue-net").contains(HAPROXY));
        assert!(members(&fake, "cite-docs-blue-net").is_empty());
    }

    #[tokio::test]
    async fn reconcile_runs_lazily_and_only_once() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        fake.lock()
            .unwrap()
            .networks
            .get_mut("cite-shop-blue-net")
            .unwrap()
            .members
            .clear();
        orch.reconciled.store(false, Ordering::Release);
        assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
        assert!(members(&fake, "cite-shop-blue-net").contains(HAPROXY));
        let listings = count(&fake, "GET /containers/json");
        orch.stack_running("shop", Slot::Blue).await.unwrap();
        assert_eq!(count(&fake, "GET /containers/json"), listings);
    }

    #[tokio::test]
    async fn reconcile_is_a_no_op_without_isolation() {
        let (orch, fake) = start_fake_with("").await;
        orch.reconcile_networks().await.unwrap();
        assert!(fake.lock().unwrap().log.is_empty());
    }

    #[tokio::test]
    async fn missing_haproxy_container_is_reported() {
        let (orch, fake) = start_fake().await;
        fake.lock().unwrap().haproxy_missing = true;
        let err = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Unavailable(_)), "{err}");
        assert!(err.to_string().contains("CITE_HAPROXY_CONTAINER"));
    }

    #[tokio::test]
    async fn foreign_volume_is_a_conflict() {
        let (orch, fake) = start_fake().await;
        fake.lock()
            .unwrap()
            .volumes
            .insert("cite-shop-blue-data".to_string(), json!({}));
        let err = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err}");
        assert!(fake.lock().unwrap().containers.is_empty());
    }

    #[tokio::test]
    async fn foreign_network_is_a_conflict() {
        let (orch, fake) = start_fake().await;
        fake.lock().unwrap().networks.insert(
            "cite-shop-blue-egress".to_string(),
            Net {
                labels: json!({}),
                internal: false,
                members: HashSet::new(),
            },
        );
        let err = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err}");
    }

    #[tokio::test]
    async fn remove_refuses_foreign_containers() {
        let (orch, fake) = start_fake().await;
        fake.lock()
            .unwrap()
            .containers
            .insert("cite-shop-blue-executor".to_string(), unmanaged_ctr());
        let err = orch.remove_stack("shop", true).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err}");
        let f = fake.lock().unwrap();
        assert!(f.containers.contains_key("cite-shop-blue-executor"));
        assert!(!f.log.iter().any(|l| l.starts_with("DELETE /containers")));
    }

    #[tokio::test]
    async fn init_cleanup_refuses_a_foreign_container() {
        let (orch, fake) = start_fake().await;
        fake.lock()
            .unwrap()
            .containers
            .insert("cite-shop-blue-init".to_string(), unmanaged_ctr());
        let err = orch
            .ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err}");
        assert!(
            fake.lock()
                .unwrap()
                .containers
                .contains_key("cite-shop-blue-init")
        );
    }

    #[tokio::test]
    async fn legacy_edge_executor_moves_to_the_stack_network() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        let legacy = orch.with_haproxy_container("").unwrap();
        legacy
            .ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let orch = legacy.with_haproxy_container(HAPROXY).unwrap();
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 2);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 1);
        assert!(members(&fake, "cite-shop-blue-net").contains(HAPROXY));
    }

    fn env_of(spec: &Value) -> Vec<String> {
        spec["Env"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }

    fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![stream, 0, 0, 0];
        v.extend((payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    const TS: &str = "2026-01-02T03:04:05.123456789Z";

    fn set_logs(fake: &Arc<Mutex<Fake>>, name: &str, logs: Vec<u8>) {
        fake.lock().unwrap().containers.get_mut(name).unwrap().logs = logs;
    }

    fn set_state(fake: &Arc<Mutex<Fake>>, name: &str, state: Value) {
        fake.lock().unwrap().containers.get_mut(name).unwrap().state = state;
    }

    #[test]
    fn setting_env_lists_only_set_fields_in_order() {
        let all = source_with(
            None,
            json!({
                "root_dir": "web",
                "output_dir": "dist",
                "spa_fallback": "index.html",
                "package_manager": "pnpm",
                "rendering": "static",
                "framework": "vite",
                "prune": true,
                "install_command": "pnpm install",
                "build_command": "pnpm build",
                "start_command": "node server.js",
            }),
        );
        assert_eq!(
            setting_env(&all),
            vec![
                "CITE_ROOT_DIR=web",
                "CITE_OUTPUT_DIR=dist",
                "CITE_SPA_FALLBACK=index.html",
                "CITE_PACKAGE_MANAGER=pnpm",
                "CITE_RENDERING=static",
                "CITE_FRAMEWORK=vite",
                "CITE_PRUNE=true",
                "CITE_INSTALL_COMMAND=pnpm install",
                "CITE_BUILD_COMMAND=pnpm build",
                "CITE_START_COMMAND=node server.js",
            ]
        );
        assert!(setting_env(&source_with(None, json!({}))).is_empty());
        assert_eq!(
            setting_env(&source_with(
                None,
                json!({ "prune": false, "build_command": "" })
            )),
            vec!["CITE_PRUNE=false"]
        );
    }

    #[test]
    fn plan_carries_only_set_settings_on_the_manager() {
        let s = site_with("shop", json!({ "root_dir": "web", "prune": false }));
        let p = plan_stack(
            &s,
            Slot::Blue,
            None,
            TOKEN,
            &stack_env("r.io/o", "1", false),
        )
        .unwrap();
        let env = env_of(&p.manager);
        assert!(env.contains(&"CITE_ROOT_DIR=web".to_string()));
        assert!(env.contains(&"CITE_PRUNE=false".to_string()));
        assert!(!env.iter().any(|e| e.starts_with("CITE_OUTPUT_DIR")));
        assert!(!p.executor.to_string().contains("CITE_ROOT_DIR"));
    }

    #[test]
    fn stack_opts_debug_shows_env_names_only() {
        let opts = StackOpts {
            deploy_id: Some("D1".into()),
            build_env: Some([("API_KEY".to_string(), "build-secret-77".to_string())].into()),
            runtime_env: Some([("DB_PASS".to_string(), "run-secret-88".to_string())].into()),
        };
        let shown = format!("{opts:?}");
        assert!(shown.contains("API_KEY") && shown.contains("DB_PASS") && shown.contains("D1"));
        assert!(!shown.contains("build-secret-77") && !shown.contains("run-secret-88"));
    }

    #[test]
    fn default_opts_plan_is_unchanged() {
        let p = plan(None, None).unwrap();
        let dir = "/var/lib/cite";
        assert_eq!(
            env_of(&p.manager),
            vec![
                "CITE_REPO=acme/shop".to_string(),
                "CITE_BRANCH=main".to_string(),
                "CITE_POLL_INTERVAL=5m".to_string(),
                "CITE_NODE=22".to_string(),
                format!("CITE_GITHUB_TOKEN={TOKEN}"),
                format!("CITE_DATA_DIR={dir}"),
                format!("CITE_RELEASES_DIR={dir}/releases"),
                format!("CITE_CONTROL_DIR={dir}/control"),
                format!("CITE_STATUS_DIR={dir}/status"),
                format!("CITE_STATE_DIR={dir}/state"),
                format!("CITE_WORK_DIR={dir}/work"),
                format!("CITE_CACHE_DIR={dir}/cache"),
                "CITE_SOCKET=/run/cite/manager.sock".to_string(),
                "RUST_LOG=info".to_string(),
            ]
        );
        assert_eq!(
            env_of(&p.executor),
            vec![
                "CITE_LISTEN=0.0.0.0:8080".to_string(),
                format!("CITE_DATA_DIR={dir}"),
                format!("CITE_RELEASES_DIR={dir}/releases"),
                format!("CITE_CONTROL_DIR={dir}/control"),
                format!("CITE_STATUS_DIR={dir}/status"),
                "RUST_LOG=info".to_string(),
                "CITE_NODE_BIN=/nodejs/bin/node".to_string(),
                "CITE_NODE=22".to_string(),
            ]
        );
        let same = plan_stack_with(
            &site("shop", None),
            Slot::Blue,
            None,
            TOKEN,
            &stack_env("ghcr.io/seggys116", "0.2.0", false),
            &StackOpts::default(),
            &Limits::default(),
            &Forge::default(),
        )
        .unwrap();
        assert_eq!(same.manager, p.manager);
        assert_eq!(same.executor, p.executor);
        assert_eq!(same.init, p.init);
    }

    #[test]
    fn deploy_and_build_env_stay_out_of_labels_and_off_the_executor() {
        let opts = StackOpts {
            deploy_id: Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string()),
            build_env: Some(BTreeMap::from([("API_KEY".into(), "buildsecret".into())])),
            runtime_env: Some(BTreeMap::from([("DB_URL".into(), "runtimesecret".into())])),
        };
        let p = plan_stack_with(
            &site("shop", None),
            Slot::Blue,
            None,
            TOKEN,
            &stack_env("r.io/o", "1", false),
            &opts,
            &Limits::default(),
            &Forge::default(),
        )
        .unwrap();
        let mgr = env_of(&p.manager);
        assert!(mgr.contains(&"CITE_DEPLOY_ID=01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string()));
        assert!(mgr.contains(&r#"CITE_BUILD_ENV_JSON={"API_KEY":"buildsecret"}"#.to_string()));
        assert!(!mgr.iter().any(|e| e.contains("runtimesecret")));
        let exec = env_of(&p.executor);
        assert!(exec.contains(&r#"CITE_RUNTIME_ENV_JSON={"DB_URL":"runtimesecret"}"#.to_string()));
        assert!(
            !exec
                .iter()
                .any(|e| e.contains("buildsecret") || e.contains("DEPLOY_ID"))
        );
        for spec in [&p.manager, &p.executor, &p.init] {
            let labels = spec["Labels"].to_string();
            assert!(!labels.contains("secret") && !labels.contains("01ARZ3"));
        }
        assert!(!p.init.to_string().contains("secret"));
        let bad = StackOpts {
            deploy_id: Some("a b".to_string()),
            ..Default::default()
        };
        let err = plan_stack_with(
            &site("shop", None),
            Slot::Blue,
            None,
            TOKEN,
            &stack_env("r.io/o", "1", false),
            &bad,
            &Limits::default(),
            &Forge::default(),
        );
        assert!(matches!(err, Err(ConnectorError::BadRequest(_))));
    }

    #[tokio::test]
    async fn removing_a_setting_recreates_the_manager() {
        let (orch, fake) = start_fake().await;
        let with = site_with("shop", json!({ "root_dir": "web" }));
        orch.ensure_stack(&with, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.ensure_stack(&with, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 1);
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 1);
        let f = fake.lock().unwrap();
        assert!(!container_env_of(&f, "cite-shop-blue-manager").contains("CITE_ROOT_DIR"));
    }

    fn container_env_of(f: &Fake, name: &str) -> String {
        f.containers[name].spec["Env"].to_string()
    }

    #[tokio::test]
    async fn deploy_id_and_runtime_env_changes_recreate_and_removal_does_too() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        let opts = StackOpts {
            deploy_id: Some("d1".to_string()),
            build_env: Some(BTreeMap::new()),
            runtime_env: Some(BTreeMap::from([("A".into(), "1".into())])),
        };
        orch.ensure_stack_with(&s, Slot::Blue, None, TOKEN, &opts)
            .await
            .unwrap();
        orch.ensure_stack_with(&s, Slot::Blue, None, TOKEN, &opts)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 1);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 1);
        let next = StackOpts {
            deploy_id: Some("d2".to_string()),
            ..opts.clone()
        };
        orch.ensure_stack_with(&s, Slot::Blue, None, TOKEN, &next)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 1);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 3);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 2);
    }

    #[test]
    fn size_and_cpu_parsing() {
        assert_eq!(parse_memory("512m").unwrap(), 512 * MIB);
        assert_eq!(parse_memory("2g").unwrap(), 2 * GIB);
        assert_eq!(parse_memory("2GiB").unwrap(), 2 * GIB);
        assert_eq!(parse_memory(" 256MB ").unwrap(), 256 * MIB);
        assert_eq!(parse_memory("268435456").unwrap(), 256 * MIB);
        for bad in [
            "255m",
            "128m",
            "0",
            "",
            "g",
            "1.5g",
            "2x",
            "-1g",
            "99999999999t",
        ] {
            assert!(parse_memory(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_cpus("2").unwrap(), 2_000_000_000);
        assert_eq!(parse_cpus("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_cpus("0.25").unwrap(), 250_000_000);
        for bad in ["0", "0.01", "0.1", "0.24", "-1", "abc", "nan", "5000", ""] {
            assert!(parse_cpus(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn node_limits_come_from_env_with_decent_defaults() {
        let none = Limits::from_lookup(|_| None).unwrap();
        assert_eq!(none, Limits::default());
        assert_eq!(none.manager_memory, 4 * GIB);
        assert_eq!(none.executor_memory, 2 * GIB);
        assert_eq!(none.executor_nano_cpus, 2_000_000_000);
        let set = |k: &str| {
            let v = match k {
                "CITE_MANAGER_MEM" => Some("6g"),
                "CITE_MANAGER_CPUS" => Some("3"),
                "CITE_EXECUTOR_MEM" => Some("512m"),
                "CITE_EXECUTOR_CPUS" => Some("0.5"),
                "CITE_STACK_MAX_MEM" => Some("8g"),
                "CITE_STACK_MAX_CPUS" => Some("4"),
                _ => None,
            };
            v.map(str::to_string)
        };
        let l = Limits::from_lookup(set).unwrap();
        assert_eq!(l.manager_memory, 6 * GIB);
        assert_eq!(l.manager_nano_cpus, 3_000_000_000);
        assert_eq!(l.executor_memory, 512 * MIB);
        assert_eq!(l.executor_nano_cpus, 500_000_000);
        assert_eq!(l.max_memory, Some(8 * GIB));
        assert_eq!(l.max_nano_cpus, Some(4_000_000_000));
        let low = Limits::from_lookup(|k| (k == "CITE_EXECUTOR_MEM").then(|| "128m".to_string()));
        assert!(
            matches!(low, Err(ConnectorError::BadRequest(m)) if m.contains("CITE_EXECUTOR_MEM"))
        );
    }

    #[test]
    fn site_limits_override_and_clamp() {
        let node = Limits {
            max_memory: Some(3 * GIB),
            max_nano_cpus: Some(3_000_000_000),
            ..Limits::default()
        };
        let plain = node.for_source(&source_with(None, json!({})));
        assert_eq!(plain.executor_memory, 2 * GIB);
        assert_eq!(
            plain.manager_memory,
            3 * GIB,
            "node default is clamped to the maximum"
        );
        let over = node.for_source(&source_with(
            None,
            json!({ "memory_mb": 1024, "cpus": 0.5, "build_memory_mb": 99999, "build_cpus": 64.0 }),
        ));
        assert_eq!(over.executor_memory, GIB);
        assert_eq!(over.executor_nano_cpus, 500_000_000);
        assert_eq!(over.manager_memory, 3 * GIB);
        assert_eq!(over.manager_nano_cpus, 3_000_000_000);
        let tiny = node.for_source(&source_with(
            None,
            json!({ "memory_mb": 16, "cpus": 0.001 }),
        ));
        assert_eq!(tiny.executor_memory, 256 * MIB);
        assert_eq!(tiny.executor_nano_cpus, 250_000_000);
        let s = site_with("shop", json!({ "memory_mb": 768, "build_cpus": 1.5 }));
        let p = plan_stack_with(
            &s,
            Slot::Blue,
            None,
            TOKEN,
            &stack_env("r.io/o", "1", false),
            &StackOpts::default(),
            &Limits::default(),
            &Forge::default(),
        )
        .unwrap();
        assert_eq!(p.executor["HostConfig"]["Memory"], json!(768 * MIB));
        assert_eq!(p.executor["HostConfig"]["MemorySwap"], json!(768 * MIB));
        assert_eq!(p.manager["HostConfig"]["NanoCpus"], json!(1_500_000_000i64));
        assert_eq!(p.manager["HostConfig"]["Memory"], json!(4 * GIB));
    }

    #[tokio::test]
    async fn changed_limits_recreate_the_container() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let bigger = Limits {
            executor_memory: 3 * GIB,
            ..Limits::default()
        };
        let orch = orch.with_limits(bigger);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 2);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 1);
        let sized = site_with("shop", json!({ "memory_mb": 512 }));
        orch.ensure_stack(&sized, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 3);
        let cpus = site_with("shop", json!({ "memory_mb": 512, "build_cpus": 1.0 }));
        orch.ensure_stack(&cpus, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 3);
        orch.ensure_stack(&cpus, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
    }

    #[tokio::test]
    async fn inspect_slot_reads_state_health_and_report() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        let missing = orch.inspect_slot("shop", Slot::Blue).await.unwrap();
        assert_eq!(missing.state, "missing");
        assert_eq!(missing.health, "none");
        assert!(missing.manager_report.is_none() && missing.env.is_empty());
        orch.ensure_stack(&s, Slot::Blue, Some("dev"), TOKEN)
            .await
            .unwrap();
        let plain = orch.inspect_slot("shop", Slot::Blue).await.unwrap();
        assert_eq!(plain.state, "running");
        assert_eq!(plain.health, "none");
        assert_eq!(
            (plain.restart_count, plain.exit_code, plain.oom_killed),
            (0, None, false)
        );
        assert!(plain.env.contains(&"CITE_BRANCH=dev".to_string()));
        assert!(
            !plain
                .env
                .iter()
                .any(|e| e.contains("TOKEN") || e.contains(TOKEN))
        );
        let report = r#"{"v":1,"phase":"idle","since":"2026-01-01T00:00:00Z"}"#;
        set_state(
            &fake,
            "cite-shop-blue-manager",
            json!({
                "Status": "restarting",
                "Health": { "Status": "unhealthy", "Log": [
                    { "Output": "stale" },
                    { "Output": format!("{report}\n") },
                ] },
                "RestartCount": 7,
                "ExitCode": 137,
                "OOMKilled": true,
            }),
        );
        let got = orch.inspect_slot("shop", Slot::Blue).await.unwrap();
        assert_eq!(got.state, "restarting");
        assert_eq!(got.health, "unhealthy");
        assert_eq!(got.restart_count, 7);
        assert_eq!(got.exit_code, Some(137));
        assert!(got.oom_killed);
        assert!(got.manager_report.is_some());
        for output in [
            json!(""),
            json!("not json at all"),
            json!("{\"v\":"),
            json!(format!(
                "{{\"v\":1,\"pad\":\"{}\"}}",
                "x".repeat(MAX_REPORT_BYTES)
            )),
            json!(null),
        ] {
            set_state(
                &fake,
                "cite-shop-blue-manager",
                json!({ "Health": { "Status": "starting", "Log": [{ "Output": output }] } }),
            );
            let got = orch.inspect_slot("shop", Slot::Blue).await.unwrap();
            assert!(got.manager_report.is_none());
            assert_eq!(got.health, "starting");
        }
        set_state(
            &fake,
            "cite-shop-blue-manager",
            json!({ "Health": { "Log": [] } }),
        );
        assert!(
            orch.inspect_slot("shop", Slot::Blue)
                .await
                .unwrap()
                .manager_report
                .is_none()
        );
    }

    #[tokio::test]
    async fn settings_current_tracks_settings_and_limits_not_the_deploy_id() {
        let (orch, _fake) = start_fake().await;
        let s = site_with("shop", json!({ "root_dir": "web", "memory_mb": 512 }));
        let opts = StackOpts {
            deploy_id: Some("d1".to_string()),
            ..Default::default()
        };
        orch.ensure_stack_with(&s, Slot::Blue, None, TOKEN, &opts)
            .await
            .unwrap();
        let got = orch.inspect_slot("shop", Slot::Blue).await.unwrap();
        assert!(got.env.contains(&"CITE_DEPLOY_ID=d1".to_string()));
        assert!(orch.settings_current(&s, &got));
        let other = site_with("shop", json!({ "root_dir": "app", "memory_mb": 512 }));
        assert!(!orch.settings_current(&other, &got));
        let dropped = site_with("shop", json!({ "memory_mb": 512 }));
        assert!(!orch.settings_current(&dropped, &got));
        let resized = site_with("shop", json!({ "root_dir": "web", "memory_mb": 1024 }));
        assert!(!orch.settings_current(&resized, &got));
        let missing = orch.inspect_slot("shop", Slot::Green).await.unwrap();
        assert!(!orch.settings_current(&s, &missing));
    }

    #[test]
    fn demux_handles_partial_odd_and_raw_streams() {
        let mut body = frame(1, b"one\n");
        body.extend(frame(2, b"two\n"));
        body.extend(frame(1, b"spl"));
        body.extend(frame(2, b"err\n"));
        body.extend(frame(1, b"it\n"));
        body.extend(frame(1, b""));
        body.extend(frame(1, b"tail no newline"));
        assert_eq!(
            demux(&body),
            vec![
                (false, "one".to_string()),
                (true, "two".to_string()),
                (true, "err".to_string()),
                (false, "split".to_string()),
                (false, "tail no newline".to_string()),
            ]
        );
        let mut cut = frame(1, b"whole\n");
        cut.extend([1, 0, 0, 0, 0, 0, 0x7f, 0xff]);
        cut.extend(b"claims more than present");
        assert_eq!(
            demux(&cut),
            vec![
                (false, "whole".to_string()),
                (false, "claims more than present".to_string())
            ]
        );
        let mut half = frame(1, b"ok\n");
        half.extend([1, 0, 0]);
        assert_eq!(demux(&half), vec![(false, "ok".to_string())]);
        let mut corrupt = frame(1, b"ok\n");
        corrupt.extend([9, 9, 9, 9, 0, 0, 0, 1, b'x']);
        assert_eq!(demux(&corrupt), vec![(false, "ok".to_string())]);
        assert_eq!(
            demux(b"plain tty line\r\nsecond\n"),
            vec![
                (false, "plain tty line".to_string()),
                (false, "second".to_string())
            ]
        );
        assert!(demux(b"").is_empty());
        assert!(demux(&[1, 0]).len() <= 1);
    }

    #[test]
    fn ansi_and_token_redaction() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m ok\x1b[2K"), "red ok");
        assert_eq!(strip_ansi("a\x1b]0;title\x07b\x1b]8;;u\x1b\\c"), "abc");
        assert_eq!(strip_ansi("bell\x07 tab\there\r"), "bell tab\there");
        let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let pat = "github_pat_11ABCDEFG0_abcdefghijklmnop";
        let text = format!(
            "clone {token} then {pat}; gho_abcdefgh1 ghu_abcdefgh2 ghs_abcdefgh3 ghr_abcdefgh4"
        );
        let out = redact_text(&text, &[]);
        assert_eq!(
            out,
            "clone [REDACTED] then [REDACTED]; [REDACTED] [REDACTED] [REDACTED] [REDACTED]"
        );
        assert_eq!(redact_text("ghp_short and ghp_", &[]), "ghp_short and ghp_");
        let secrets = vec![
            "hunter22".to_string(),
            "abc".to_string(),
            "hunter22x".to_string(),
        ];
        assert_eq!(
            redact_text("pw hunter22x hunter22 abc", &secrets),
            "pw [REDACTED] [REDACTED] abc"
        );
    }

    #[tokio::test]
    async fn container_logs_demux_parse_redact_and_cap() {
        let (orch, fake) = start_fake().await;
        orch.ensure_stack(&site("shop", None), Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let json_line = format!(
            "{TS} {{\"ts\":\"2026-02-02T00:00:00Z\",\"level\":\"WARN\",\"msg\":\"building pw=hunter22\",\"phase\":\"build\"}}\n"
        );
        let mut body = frame(1, json_line.as_bytes());
        body.extend(frame(
            2,
            format!("{TS} \x1b[31mfailed\x1b[0m {TOKEN} hunter22\n").as_bytes(),
        ));
        body.extend(frame(1, format!("{TS} {{\"unrelated\":1}}\n").as_bytes()));
        body.extend(frame(
            1,
            format!("{TS} {}\n", "a".repeat(10_000)).as_bytes(),
        ));
        set_logs(&fake, "cite-shop-blue-manager", body.clone());
        let secrets = vec!["hunter22".to_string()];
        let batch = orch
            .container_logs(
                "shop",
                Slot::Blue,
                LogRole::Manager,
                5000,
                Some("1700000000"),
                &secrets,
            )
            .await
            .unwrap();
        assert!(!batch.truncated);
        assert_eq!(batch.lines.len(), 4);
        let first = &batch.lines[0];
        assert_eq!(first.text, "building pw=[REDACTED]");
        assert_eq!(first.level.as_deref(), Some("warn"));
        assert_eq!(first.phase.as_deref(), Some("build"));
        assert_eq!(
            first.ts.as_deref(),
            Some(TS),
            "Docker's time wins over the app's"
        );
        assert_eq!(first.stream, "stdout");
        let second = &batch.lines[1];
        assert_eq!(second.text, "failed [REDACTED] [REDACTED]");
        assert_eq!(second.stream, "stderr");
        assert_eq!(second.level.as_deref(), Some("error"));
        assert_eq!(second.ts.as_deref(), Some(TS));
        assert_eq!(batch.lines[2].text, "{\"unrelated\":1}");
        assert_eq!(batch.lines[3].text.len(), MAX_LOG_LINE);
        let query = fake
            .lock()
            .unwrap()
            .log
            .iter()
            .find(|l| l.starts_with("LOGQ"))
            .cloned()
            .unwrap();
        for part in [
            "stdout=1",
            "stderr=1",
            "tail=1000",
            "timestamps=1",
            "since=1700000000",
        ] {
            assert!(query.contains(part), "{query}");
        }
        let exec = orch
            .container_logs("shop", Slot::Blue, LogRole::Executor, 10, None, &[])
            .await
            .unwrap();
        assert!(exec.lines.is_empty());
        set_logs(
            &fake,
            "cite-shop-blue-executor",
            frame(1, format!("{TS} {{\"msg\":\"x\"}}\n").as_bytes()),
        );
        let exec = orch
            .container_logs("shop", Slot::Blue, LogRole::Executor, 10, None, &[])
            .await
            .unwrap();
        assert_eq!(
            exec.lines[0].text, "{\"msg\":\"x\"}",
            "executor lines stay plain text"
        );
        let bad = orch
            .container_logs("shop", Slot::Blue, LogRole::Manager, 10, Some("1; rm"), &[])
            .await;
        assert!(matches!(bad, Err(ConnectorError::BadRequest(_))));
        let gone = orch
            .container_logs("ghost", Slot::Green, LogRole::Manager, 10, None, &[])
            .await
            .unwrap();
        assert!(gone.lines.is_empty() && !gone.truncated);
    }

    #[test]
    fn the_cursor_follows_docker_time_not_a_skewed_app_clock() {
        let later = "2026-01-02T03:04:06.000000001Z";
        let mut body = frame(
            1,
            format!("{TS} {{\"ts\":\"2099-01-01T00:00:00Z\",\"msg\":\"ahead\"}}\n").as_bytes(),
        );
        body.extend(frame(
            2,
            format!("{later} {{\"ts\":\"2000-01-01T00:00:00Z\",\"msg\":\"behind\"}}\n").as_bytes(),
        ));
        body.extend(frame(1, b"{\"ts\":\"2026 01 01\",\"msg\":\"spaced\"}\n"));
        let batch = build_batch(&body, true, &[]);
        assert_eq!(batch.lines.len(), 3);
        assert_eq!(batch.lines[0].ts.as_deref(), Some(TS));
        assert_eq!(batch.lines[1].ts.as_deref(), Some(later));
        assert_eq!(batch.lines[2].ts, None);
        assert_eq!(batch.last_ts.as_deref(), Some(later));
        let plain = parse_log_line(
            r#"{"ts":"2026-03-03T00:00:00Z","msg":"m"}"#,
            false,
            true,
            &[],
        );
        assert_eq!(plain.ts.as_deref(), Some("2026-03-03T00:00:00Z"));
        assert!(build_batch(b"", true, &[]).last_ts.is_none());
    }

    #[test]
    fn log_batch_drops_oldest_beyond_one_mebibyte() {
        let mut body = Vec::new();
        for i in 0..400 {
            let line = format!("{TS} n{i:04} {}\n", "x".repeat(MAX_LOG_LINE - 6));
            body.extend(frame(1, line.as_bytes()));
        }
        let batch = build_batch(&body, false, &[]);
        assert!(batch.truncated);
        assert!(batch.lines.len() < 400);
        let total: usize = batch.lines.iter().map(line_cost).sum();
        assert!(total <= MAX_LOG_TOTAL);
        assert!(batch.lines.last().unwrap().text.starts_with("n0399"));
        assert!(!batch.lines.iter().any(|l| l.text.starts_with("n0000")));
        let small = build_batch(&frame(1, format!("{TS} hi\n").as_bytes()), false, &[]);
        assert!(!small.truncated && small.lines.len() == 1);
    }

    #[tokio::test]
    async fn reset_slot_volumes_drops_work_and_cache_only() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        orch.ensure_stack(&s, Slot::Green, None, TOKEN)
            .await
            .unwrap();
        orch.reset_slot_volumes("shop", Slot::Blue).await.unwrap();
        {
            let f = fake.lock().unwrap();
            assert!(!f.volumes.contains_key("cite-shop-blue-work"));
            assert!(!f.volumes.contains_key("cite-shop-blue-cache"));
            assert!(f.volumes.contains_key("cite-shop-blue-data"));
            assert!(f.volumes.contains_key("cite-shop-green-work"));
            assert!(!f.containers.contains_key("cite-shop-blue-manager"));
            assert!(f.containers.contains_key("cite-shop-blue-executor"));
        }
        orch.reset_slot_volumes("shop", Slot::Blue).await.unwrap();
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        let f = fake.lock().unwrap();
        assert!(f.volumes.contains_key("cite-shop-blue-work"));
        assert!(f.containers["cite-shop-blue-manager"].running);
    }

    #[tokio::test]
    async fn reset_refuses_a_foreign_volume() {
        let (orch, fake) = start_fake().await;
        fake.lock()
            .unwrap()
            .volumes
            .insert("cite-shop-blue-work".to_string(), json!({}));
        let err = orch
            .reset_slot_volumes("shop", Slot::Blue)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err}");
        assert!(
            fake.lock()
                .unwrap()
                .volumes
                .contains_key("cite-shop-blue-work")
        );
    }

    fn forge(name: &str, url: Option<&str>) -> Forge {
        Forge {
            name: Some(name.to_string()),
            api_url: url.map(str::to_string),
        }
    }

    #[test]
    fn forge_env_parsing_and_validation() {
        assert_eq!(Forge::from_lookup(|_| None).unwrap(), Forge::default());
        assert!(Forge::default().env().is_empty());
        let got = Forge::from_lookup(|k| match k {
            "CITE_STACK_FORGE" => Some(" gitea ".to_string()),
            "CITE_STACK_FORGE_API_URL" => Some("https://git.example.com/api/v1".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(got, forge("gitea", Some("https://git.example.com/api/v1")));
        for bad in ["Gitea", "git ea", "1git", "a".repeat(40).as_str()] {
            let r = Forge::from_lookup(|k| (k == "CITE_STACK_FORGE").then(|| bad.to_string()));
            assert!(matches!(r, Err(ConnectorError::BadRequest(_))), "{bad}");
        }
        let r = Forge::from_lookup(|k| {
            (k == "CITE_STACK_FORGE_API_URL").then(|| "https://u@evil.test".to_string())
        });
        assert!(matches!(r, Err(ConnectorError::BadRequest(_))));
        assert!(Forge::default().missing_api_url().is_none());
        assert!(forge("github", None).missing_api_url().is_none());
        assert!(
            forge("gitea", Some("https://git.example.com/api/v1"))
                .missing_api_url()
                .is_none()
        );
        let warning = forge("gitlab", None).missing_api_url().unwrap();
        assert!(warning.contains("gitlab") && warning.contains("CITE_STACK_FORGE_API_URL"));
    }

    #[test]
    fn forge_reaches_only_the_manager_env() {
        let f = forge("gitea", Some("https://git.example.com/api/v1"));
        let p = plan_stack_with(
            &site("shop", None),
            Slot::Blue,
            None,
            TOKEN,
            &stack_env("r.io/o", "1", false),
            &StackOpts::default(),
            &Limits::default(),
            &f,
        )
        .unwrap();
        let env = env_of(&p.manager);
        assert!(env.contains(&"CITE_FORGE=gitea".to_string()));
        assert!(env.contains(&"CITE_FORGE_API_URL=https://git.example.com/api/v1".to_string()));
        for spec in [&p.manager, &p.executor, &p.init] {
            assert!(!spec["Labels"].to_string().contains("gitea"));
        }
        assert!(!p.executor.to_string().contains("CITE_FORGE"));
        assert!(!p.init.to_string().contains("CITE_FORGE"));
    }

    #[tokio::test]
    async fn changed_or_removed_forge_recreates_the_manager() {
        let (orch, fake) = start_fake().await;
        let s = site("shop", None);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert!(!container_env(&fake, "cite-shop-blue-manager").contains("CITE_FORGE"));
        let orch = orch.with_forge(forge("gitea", None));
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 2);
        let orch = orch.with_forge(forge("forgejo", None));
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 3);
        let orch = orch.with_forge(Forge::default());
        orch.ensure_stack(&s, Slot::Blue, None, TOKEN)
            .await
            .unwrap();
        assert_eq!(count(&fake, "CREATE cite-shop-blue-manager"), 4);
        assert_eq!(count(&fake, "CREATE cite-shop-blue-executor"), 1);
        assert!(!container_env(&fake, "cite-shop-blue-manager").contains("CITE_FORGE"));
    }
}
