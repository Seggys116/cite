use serde_json::{Map, Value, json};

use crate::config::{EgressMode, MIN_STACK_MEMORY, MIN_STACK_NANO_CPUS};
use crate::envval;
use crate::policy::{Policy, Stack};

// Upper bounds for the resource limits a create body may ask for.
const MIB: i64 = 1 << 20;
const MAX_ENV_ENTRIES: usize = 32;
const MAX_TOKEN_LEN: usize = 512;
const MAX_REF_LEN: usize = 100;

const INIT_SCRIPT: &str = "mkdir -p /data/releases/blue /data/releases/green /data/control \
/data/status /data/state && \
chown 0:0 /data/releases /data/releases/blue /data/releases/green /data/control /data/state && \
chown 65532:65532 /data/status && \
chmod 0755 /data/releases /data/control /data/status && chmod 0750 /data/state";

// Kept byte-identical with the connector's volume_init_step; the specs tests compare both.
fn volume_init_step(name: &str) -> String {
    format!(
        " && if [ \"$(stat -c %u /vols/{name})\" != 65532 ]; then touch /vols/{name}/.cite-init && chown -R 65532:65532 /vols/{name} && chmod 0750 /vols/{name}; fi"
    )
}

const MAX_SITE_VOLUMES: usize = 8;
const MAX_MOUNT_PATH: usize = 255;
const RESERVED_MOUNT_PATHS: [&str; 19] = [
    "/var/lib/cite",
    "/cite-executor",
    "/nodejs",
    "/tmp",
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/run",
    "/var/run",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/root",
    "/boot",
];

fn path_within(inner: &str, outer: &str) -> bool {
    inner == outer
        || inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('/'))
}

// Same rule as cite-edge's mount_path_problem, restated here because the proxy trusts no caller.
pub fn mount_path_ok(p: &str) -> bool {
    (2..=MAX_MOUNT_PATH).contains(&p.len())
        && p.starts_with('/')
        && !p.ends_with('/')
        && p.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
        && !p[1..]
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        && !RESERVED_MOUNT_PATHS
            .iter()
            .any(|r| path_within(p, r) || path_within(r, p))
}

// Mounts after the fixed ones must be this site's own volumes, read-write, at distinct non-overlapping targets.
fn site_mounts(
    policy: &Policy,
    role: Role,
    c: &Stack,
    host: &Map<String, Value>,
) -> Result<Vec<(String, String)>, String> {
    let fixed = match role {
        Role::Manager | Role::EgressProxy => return Ok(Vec::new()),
        Role::Executor => 3,
        Role::Init => 1,
    };
    let Some(mounts) = host.get("Mounts").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let extra = mounts.get(fixed..).unwrap_or_default();
    if extra.len() > MAX_SITE_VOLUMES {
        return Err("HostConfig.Mounts has too many site volumes".to_string());
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for m in extra {
        if m.get("Type").and_then(Value::as_str) != Some("volume") {
            return Err("HostConfig.Mounts may only add volume mounts".to_string());
        }
        let source = m.get("Source").and_then(Value::as_str).unwrap_or_default();
        let (id, name) = policy.site_volume(source)?;
        if id != c.id {
            return Err("HostConfig.Mounts names another site's volume".to_string());
        }
        let target = m.get("Target").and_then(Value::as_str).unwrap_or_default();
        let target_ok = match role {
            Role::Init => target == format!("/vols/{name}"),
            _ => mount_path_ok(target),
        };
        if !target_ok {
            return Err("HostConfig.Mounts target is not allowed".to_string());
        }
        for (other_source, other_target) in &out {
            if *other_source == source
                || path_within(target, other_target)
                || path_within(other_target, target)
            {
                return Err("HostConfig.Mounts repeats or nests a site volume".to_string());
            }
        }
        out.push((source.to_string(), target.to_string()));
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outbound {
    None,
    // The stack's egress bridge, joined directly (CITE_STACK_EGRESS_MODE=open).
    Open,
    // The stack's internal xnet, shared only with its egress proxy (CITE_STACK_EGRESS_MODE=filtered).
    Filtered,
}

// The executor may add one of its own stack's outbound networks, and only the one the node's egress mode names.
fn executor_outbound(
    policy: &Policy,
    role: Role,
    c: &Stack,
    body: &Value,
) -> Result<Outbound, String> {
    let endpoints = body["NetworkingConfig"]["EndpointsConfig"].as_object();
    let asks = |kind: &str| {
        endpoints.is_some_and(|e| e.contains_key(&format!("cite-{}-{}-{kind}", c.id, c.slot)))
    };
    if role != Role::Executor {
        return Ok(Outbound::None);
    }
    let mode = policy.egress_mode;
    match (asks("egress"), asks("xnet")) {
        (false, false) => Ok(Outbound::None),
        (true, false) if mode == EgressMode::Open => Ok(Outbound::Open),
        (false, true) if mode == EgressMode::Filtered => Ok(Outbound::Filtered),
        (true, true) => Err("the executor may join only one outbound network".to_string()),
        _ => Err(format!(
            "this executor's outbound network does not match the node's egress mode (CITE_STACK_EGRESS_MODE={})",
            match mode {
                EgressMode::Filtered => "filtered",
                EgressMode::Open => "open",
                EgressMode::Off => "off",
            }
        )),
    }
}

/// The address every filtered executor's proxy variables point at.
fn egress_proxy_url(c: &Stack) -> String {
    format!("http://cite-{}-{}-egress-proxy:3128", c.id, c.slot)
}

const EXECUTOR_PROXY_KEYS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "NODE_USE_ENV_PROXY",
];

// A filtered executor carries every proxy variable, any other executor none of them.
fn check_executor_proxy_env(env: &Value, outbound: Outbound) -> Result<(), String> {
    let keys: Vec<&str> = env
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|e| e.split('=').next().unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    let present = EXECUTOR_PROXY_KEYS
        .iter()
        .filter(|k| keys.contains(k))
        .count();
    match (outbound, present) {
        (Outbound::Filtered, n) if n == EXECUTOR_PROXY_KEYS.len() => Ok(()),
        (Outbound::Filtered, _) => {
            Err("a filtered executor needs every egress proxy variable".to_string())
        }
        (_, 0) => Ok(()),
        _ => Err("egress proxy variables are only allowed on a filtered executor".to_string()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Manager,
    Executor,
    Init,
    EgressProxy,
}

// Fixed limits for the egress proxy; the connector's EGRESS_PROXY_* constants must match.
const EGRESS_PROXY_MEMORY: i64 = 64 * MIB;
const EGRESS_PROXY_NANO_CPUS: i64 = 250_000_000;
const EGRESS_PROXY_PIDS: i64 = 128;

struct Limits {
    memory: i64,
    nano_cpus: Option<i64>,
    pids: i64,
}

// Fixed values must match exactly; the others are checked against the same rules the orchestrator uses.
enum EnvRule {
    Fixed(&'static str),
    Repo,
    Branch,
    Poll,
    Node,
    Token,
    GithubApi,
    RelPath,
    Enum(&'static [&'static str]),
    Slug,
    Bool,
    // Runs through sh -c inside the sandboxed build helper by design, so only length and control characters are checked.
    ShellCmd,
    StartCmd,
    DeployId,
    BuildEnvJson,
    RuntimeEnvJson,
    // Both forge keys are tied to the operator's own setting, so a manager cannot point a token at another host.
    Forge,
    ForgeApi,
    // The stack's own egress proxy address, rebuilt from the container name.
    EgressProxyUrl,
    // A node-wide egress list: exactly the operator's value for this key.
    NodeEgress(&'static str),
    // A site's allow or deny list of CIDRs and host names.
    EgressRules,
}

const OUTBOUND_MODES: &[&str] = &["public", "allowlist"];

const EGRESS_ENV: [(&str, EnvRule); 8] = [
    (
        "CITE_EGRESS_ALLOW_CIDRS",
        EnvRule::NodeEgress("CITE_EGRESS_ALLOW_CIDRS"),
    ),
    (
        "CITE_EGRESS_DENY_CIDRS",
        EnvRule::NodeEgress("CITE_EGRESS_DENY_CIDRS"),
    ),
    (
        "CITE_EGRESS_DENY_HOSTS",
        EnvRule::NodeEgress("CITE_EGRESS_DENY_HOSTS"),
    ),
    (
        "CITE_EGRESS_ALLOW_PORTS",
        EnvRule::NodeEgress("CITE_EGRESS_ALLOW_PORTS"),
    ),
    ("CITE_EGRESS_MODE", EnvRule::Enum(OUTBOUND_MODES)),
    ("CITE_EGRESS_BLOCK_MAIL", EnvRule::Bool),
    ("CITE_EGRESS_ALLOW", EnvRule::EgressRules),
    ("CITE_EGRESS_DENY", EnvRule::EgressRules),
];

const PACKAGE_MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
const RENDERINGS: &[&str] = &["static", "ssr"];

const MANAGER_ENV: [(&str, EnvRule); 29] = [
    ("CITE_REPO", EnvRule::Repo),
    ("CITE_BRANCH", EnvRule::Branch),
    ("CITE_POLL_INTERVAL", EnvRule::Poll),
    ("CITE_NODE", EnvRule::Node),
    ("CITE_GITHUB_TOKEN", EnvRule::Token),
    ("CITE_GITHUB_API_URL", EnvRule::GithubApi),
    ("CITE_DATA_DIR", EnvRule::Fixed("/var/lib/cite")),
    (
        "CITE_RELEASES_DIR",
        EnvRule::Fixed("/var/lib/cite/releases"),
    ),
    ("CITE_CONTROL_DIR", EnvRule::Fixed("/var/lib/cite/control")),
    ("CITE_STATUS_DIR", EnvRule::Fixed("/var/lib/cite/status")),
    ("CITE_STATE_DIR", EnvRule::Fixed("/var/lib/cite/state")),
    ("CITE_WORK_DIR", EnvRule::Fixed("/var/lib/cite/work")),
    ("CITE_CACHE_DIR", EnvRule::Fixed("/var/lib/cite/cache")),
    ("CITE_SOCKET", EnvRule::Fixed("/run/cite/manager.sock")),
    ("RUST_LOG", EnvRule::Fixed("info")),
    ("CITE_ROOT_DIR", EnvRule::RelPath),
    ("CITE_OUTPUT_DIR", EnvRule::RelPath),
    ("CITE_SPA_FALLBACK", EnvRule::RelPath),
    ("CITE_PACKAGE_MANAGER", EnvRule::Enum(PACKAGE_MANAGERS)),
    ("CITE_RENDERING", EnvRule::Enum(RENDERINGS)),
    ("CITE_FRAMEWORK", EnvRule::Slug),
    ("CITE_PRUNE", EnvRule::Bool),
    ("CITE_INSTALL_COMMAND", EnvRule::ShellCmd),
    ("CITE_BUILD_COMMAND", EnvRule::ShellCmd),
    ("CITE_START_COMMAND", EnvRule::StartCmd),
    ("CITE_DEPLOY_ID", EnvRule::DeployId),
    ("CITE_BUILD_ENV_JSON", EnvRule::BuildEnvJson),
    ("CITE_FORGE", EnvRule::Forge),
    ("CITE_FORGE_API_URL", EnvRule::ForgeApi),
];

const EXECUTOR_ENV: [(&str, EnvRule); 15] = [
    ("HTTP_PROXY", EnvRule::EgressProxyUrl),
    ("HTTPS_PROXY", EnvRule::EgressProxyUrl),
    ("http_proxy", EnvRule::EgressProxyUrl),
    ("https_proxy", EnvRule::EgressProxyUrl),
    ("NO_PROXY", EnvRule::Fixed("localhost,127.0.0.1")),
    ("NODE_USE_ENV_PROXY", EnvRule::Fixed("1")),
    ("CITE_LISTEN", EnvRule::Fixed("0.0.0.0:8080")),
    ("CITE_DATA_DIR", EnvRule::Fixed("/var/lib/cite")),
    (
        "CITE_RELEASES_DIR",
        EnvRule::Fixed("/var/lib/cite/releases"),
    ),
    ("CITE_CONTROL_DIR", EnvRule::Fixed("/var/lib/cite/control")),
    ("CITE_STATUS_DIR", EnvRule::Fixed("/var/lib/cite/status")),
    ("RUST_LOG", EnvRule::Fixed("info")),
    ("CITE_NODE_BIN", EnvRule::Fixed("/nodejs/bin/node")),
    ("CITE_NODE", EnvRule::Node),
    ("CITE_RUNTIME_ENV_JSON", EnvRule::RuntimeEnvJson),
];

fn labels(id: &str, slot: &str, role: &str) -> Value {
    json!({
        "cite.managed": "true",
        "cite.site": id,
        "cite.slot": slot,
        "cite.role": role,
    })
}

fn log_config() -> Value {
    json!({ "Type": "json-file", "Config": { "max-size": "10m", "max-file": "3" } })
}

fn healthcheck(test: &[&str], start_period_ns: u64) -> Value {
    json!({
        "Test": test,
        "Interval": 30_000_000_000u64,
        "Timeout": 5_000_000_000u64,
        "Retries": 3,
        "StartPeriod": start_period_ns,
    })
}

fn mount(source: &str, target: &str, subpath: Option<&str>, read_only: bool) -> Value {
    let mut m =
        json!({ "Type": "volume", "Source": source, "Target": target, "ReadOnly": read_only });
    if let Some(sub) = subpath {
        m["VolumeOptions"] = json!({ "Subpath": sub });
    }
    m
}

// Rebuilds the full create body the connector would emit; only the checked variable parts come from the request.
#[allow(clippy::too_many_arguments)]
fn expected(
    role: Role,
    c: &Stack,
    image: &str,
    env: &Value,
    limits: &Limits,
    network: &str,
    name: &str,
    site: &[(String, String)],
    outbound: Outbound,
    egress_bridge: &str,
) -> Value {
    let base = format!("cite-{}-{}", c.id, c.slot);
    let (data, work, cache) = (
        format!("{base}-data"),
        format!("{base}-work"),
        format!("{base}-cache"),
    );
    let mut host = json!({
        "ReadonlyRootfs": true,
        "SecurityOpt": ["no-new-privileges:true"],
        "CapDrop": ["ALL"],
        "NetworkMode": network,
        "Memory": limits.memory,
        "MemorySwap": limits.memory,
        "PidsLimit": limits.pids,
        "LogConfig": log_config(),
    });
    let mut body = json!({ "Image": image, "Labels": labels(&c.id, &c.slot, &c.kind) });
    match role {
        Role::Manager => {
            body["Env"] = env.clone();
            body["Healthcheck"] =
                healthcheck(&["CMD", "cite-manager", "healthcheck"], 20_000_000_000);
            host["Init"] = json!(true);
            host["CapAdd"] = json!(["CHOWN", "SETUID", "SETGID", "DAC_READ_SEARCH"]);
            host["Tmpfs"] =
                json!({ "/tmp": "size=256m,mode=1777", "/run/cite": "size=16m,mode=0750" });
            host["Mounts"] = json!([
                mount(&data, "/var/lib/cite/releases", Some("releases"), false),
                mount(&data, "/var/lib/cite/control", Some("control"), false),
                mount(&data, "/var/lib/cite/status", Some("status"), true),
                mount(&data, "/var/lib/cite/state", Some("state"), false),
                mount(&work, "/var/lib/cite/work", None, false),
                mount(&cache, "/var/lib/cite/cache", None, false),
            ]);
            host["NanoCpus"] = json!(limits.nano_cpus);
            host["RestartPolicy"] = json!({ "Name": "unless-stopped" });
            body["NetworkingConfig"] = json!({ "EndpointsConfig": { network: {} } });
        }
        Role::Executor => {
            body["User"] = json!("65532:65532");
            body["Env"] = env.clone();
            body["Healthcheck"] =
                healthcheck(&["CMD", "/cite-executor", "healthcheck"], 10_000_000_000);
            host["Init"] = json!(true);
            host["Tmpfs"] = json!({ "/tmp": "size=64m,mode=1777,noexec,nosuid,nodev" });
            let mut mounts = vec![
                mount(&data, "/var/lib/cite/releases", Some("releases"), true),
                mount(&data, "/var/lib/cite/control", Some("control"), true),
                mount(&data, "/var/lib/cite/status", Some("status"), false),
            ];
            mounts.extend(site.iter().map(|(s, t)| mount(s, t, None, false)));
            host["Mounts"] = json!(mounts);
            host["NanoCpus"] = json!(limits.nano_cpus);
            host["RestartPolicy"] = json!({ "Name": "unless-stopped" });
            let mut endpoints = json!({ network: { "Aliases": [name] } });
            match outbound {
                Outbound::Open => endpoints[format!("{base}-egress")] = json!({}),
                Outbound::Filtered => endpoints[format!("{base}-xnet")] = json!({}),
                Outbound::None => {}
            }
            body["NetworkingConfig"] = json!({ "EndpointsConfig": endpoints });
        }
        Role::EgressProxy => {
            body["User"] = json!("65532:65532");
            body["Env"] = env.clone();
            host["Init"] = json!(true);
            host["NanoCpus"] = json!(limits.nano_cpus);
            host["RestartPolicy"] = json!({ "Name": "unless-stopped" });
            body["NetworkingConfig"] =
                json!({ "EndpointsConfig": { network: {}, egress_bridge: {} } });
        }
        Role::Init => {
            let mut script = INIT_SCRIPT.to_string();
            let mut mounts = vec![mount(&data, "/data", None, false)];
            for (source, target) in site {
                let vol = target.strip_prefix("/vols/").unwrap_or_default();
                script.push_str(&volume_init_step(vol));
                mounts.push(mount(source, target, None, false));
            }
            body["User"] = json!("0:0");
            body["Entrypoint"] = json!(["/bin/sh", "-c"]);
            body["Cmd"] = json!([script]);
            body["Healthcheck"] = json!({ "Test": ["NONE"] });
            host["CapAdd"] = json!(["CHOWN", "FOWNER"]);
            host["Mounts"] = json!(mounts);
            host["RestartPolicy"] = json!({ "Name": "no" });
        }
    }
    body["HostConfig"] = host;
    body
}

// Reports only the path of the first mismatch, never a value, so tokens do not reach the log.
fn first_difference(path: &str, want: &Value, got: &Value) -> Option<String> {
    match (want, got) {
        (Value::Object(w), Value::Object(g)) => {
            if let Some(k) = g.keys().find(|k| !w.contains_key(*k)) {
                return Some(format!("{path}.{k} is not allowed"));
            }
            if let Some(k) = w.keys().find(|k| !g.contains_key(*k)) {
                return Some(format!("{path}.{k} is missing"));
            }
            w.iter()
                .find_map(|(k, v)| first_difference(&format!("{path}.{k}"), v, &g[k]))
        }
        _ if want == got => None,
        _ => Some(format!("{path} has an unexpected value")),
    }
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{what} is not an object"))
}

fn within(host: &Map<String, Value>, key: &str, min: i64, max: i64) -> Result<i64, String> {
    match host.get(key).and_then(Value::as_i64) {
        Some(n) if (min..=max).contains(&n) => Ok(n),
        _ => Err(format!("HostConfig.{key} is missing or out of range")),
    }
}

// Manager and executor memory and CPU follow the operator's bounds; init and the pid caps stay fixed.
fn read_limits(policy: &Policy, role: Role, host: &Map<String, Value>) -> Result<Limits, String> {
    if role == Role::EgressProxy {
        return Ok(Limits {
            memory: EGRESS_PROXY_MEMORY,
            nano_cpus: Some(EGRESS_PROXY_NANO_CPUS),
            pids: EGRESS_PROXY_PIDS,
        });
    }
    let (memory, cpus, pids) = match role {
        Role::Manager => ((MIN_STACK_MEMORY, policy.max_memory), true, 4096),
        Role::Executor => ((MIN_STACK_MEMORY, policy.max_memory), true, 1024),
        _ => ((1, 256 * MIB), false, 128),
    };
    Ok(Limits {
        memory: within(host, "Memory", memory.0, memory.1)?,
        nano_cpus: cpus
            .then(|| within(host, "NanoCpus", MIN_STACK_NANO_CPUS, policy.max_nano_cpus))
            .transpose()?,
        pids: within(host, "PidsLimit", 1, pids)?,
    })
}

fn is_slug_part(s: &str, max: usize, extra: &[char]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

fn env_value_ok(policy: &Policy, c: &Stack, rule: &EnvRule, value: &str) -> bool {
    match rule {
        EnvRule::Fixed(want) => value == *want,
        EnvRule::Repo => match value.split_once('/') {
            Some((owner, name)) => {
                let part = |p: &str| {
                    is_slug_part(p, MAX_REF_LEN, &['.', '_', '-']) && p != "." && p != ".."
                };
                part(owner) && part(name)
            }
            None => false,
        },
        EnvRule::Branch => {
            is_slug_part(value, MAX_REF_LEN, &['.', '_', '-', '/'])
                && !value.starts_with('-')
                && !value.contains("..")
        }
        EnvRule::Poll => is_slug_part(value, 16, &[]),
        EnvRule::Node => value == "22" || value == "24",
        EnvRule::Token => {
            !value.is_empty()
                && value.len() <= MAX_TOKEN_LEN
                && value.chars().all(|c| c.is_ascii_graphic())
        }
        // The manager sends the token here, so only the operator's own setting is accepted.
        EnvRule::GithubApi => policy.github_api_url.as_deref() == Some(value),
        EnvRule::RelPath => envval::rel_path(value),
        EnvRule::Enum(options) => options.contains(&value),
        EnvRule::Slug => envval::slug(value),
        EnvRule::Bool => envval::boolean(value),
        EnvRule::ShellCmd => envval::shell_cmd(value),
        EnvRule::StartCmd => envval::start_cmd(value),
        EnvRule::DeployId => envval::deploy_id(value),
        EnvRule::BuildEnvJson => envval::build_env_json(value),
        EnvRule::RuntimeEnvJson => envval::runtime_env_json(value),
        EnvRule::Forge => policy.forge.as_deref() == Some(value),
        EnvRule::ForgeApi => policy.forge_api_url.as_deref() == Some(value),
        EnvRule::EgressProxyUrl => value == egress_proxy_url(c),
        EnvRule::NodeEgress(key) => policy.egress_env.contains(&format!("{key}={value}")),
        EnvRule::EgressRules => envval::egress_rules(value),
    }
}

// The node's own entries must all be present, and an allowlist needs something to allow.
fn check_egress_env(policy: &Policy, env: &Value) -> Result<(), String> {
    let entries: Vec<&str> = env
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(missing) = policy
        .egress_env
        .iter()
        .find(|e| !entries.contains(&e.as_str()))
    {
        let key = missing.split('=').next().unwrap_or_default();
        return Err(format!("Env key {key:?} is missing"));
    }
    let has = |key: &str| entries.iter().any(|e| e.split('=').next() == Some(key));
    for key in ["CITE_EGRESS_MODE", "CITE_EGRESS_BLOCK_MAIL"] {
        if !has(key) {
            return Err(format!("Env key {key:?} is missing"));
        }
    }
    if entries.contains(&"CITE_EGRESS_MODE=allowlist") && !has("CITE_EGRESS_ALLOW") {
        return Err("allowlist mode needs CITE_EGRESS_ALLOW".to_string());
    }
    Ok(())
}

fn check_env(policy: &Policy, c: &Stack, role: Role, env: Option<&Value>) -> Result<Value, String> {
    let rules: &[(&str, EnvRule)] = match role {
        Role::Init => {
            return match env {
                None => Ok(Value::Null),
                Some(_) => Err("Env is not allowed on init containers".to_string()),
            };
        }
        Role::Manager => &MANAGER_ENV,
        Role::Executor => &EXECUTOR_ENV,
        Role::EgressProxy => &EGRESS_ENV,
    };
    let entries = env.and_then(Value::as_array).ok_or("Env is missing")?;
    if entries.len() > MAX_ENV_ENTRIES {
        return Err("Env has too many entries".to_string());
    }
    let mut seen: Vec<&str> = Vec::new();
    for entry in entries {
        let text = entry.as_str().ok_or("Env entry is not a string")?;
        let (key, value) = text.split_once('=').ok_or("Env entry has no value")?;
        let (_, rule) = rules
            .iter()
            .find(|(k, _)| *k == key)
            .ok_or_else(|| format!("Env key {key:?} is not allowed"))?;
        if seen.contains(&key) {
            return Err(format!("Env key {key:?} is repeated"));
        }
        if !env_value_ok(policy, c, rule, value) {
            return Err(format!("Env value for {key:?} is not allowed"));
        }
        seen.push(key);
    }
    Ok(Value::Array(entries.clone()))
}

// The executor may use its stack network or the shared edge network, never another stack's.
fn check_network_mode(policy: &Policy, role: Role, c: &Stack, mode: &str) -> Result<(), String> {
    let own = |kind: &str| mode == format!("cite-{}-{}-{kind}", c.id, c.slot);
    let ok = match role {
        Role::Init => mode == "none",
        Role::Manager => own("egress"),
        Role::Executor => own("net") || mode == policy.edge,
        Role::EgressProxy => own("xnet"),
    };
    if ok {
        Ok(())
    } else {
        Err("HostConfig.NetworkMode is not allowed".to_string())
    }
}

// Exact structural equality with the rebuilt body is what rejects every key the orchestrator never sends.
pub fn validate_container(policy: &Policy, name: &str, body: &Value) -> Result<(), String> {
    let stack = policy.container(name)?;
    let role = match stack.kind.as_str() {
        "manager" => Role::Manager,
        "executor" => Role::Executor,
        "egress-proxy" => Role::EgressProxy,
        _ => Role::Init,
    };
    if role == Role::EgressProxy && policy.egress_mode != EgressMode::Filtered {
        return Err(
            "egress proxies exist only in filtered egress mode (CITE_STACK_EGRESS_MODE=filtered)"
                .to_string(),
        );
    }
    let obj = object(body, "body")?;
    let image = obj
        .get("Image")
        .and_then(Value::as_str)
        .ok_or("Image is missing")?;
    let image_ok = match role {
        Role::Executor => policy.is_executor_image(image),
        Role::EgressProxy => policy.is_egress_image(image),
        _ => policy.is_manager_image(image),
    };
    if !image_ok {
        return Err("Image is not allowed for this container".to_string());
    }
    let env = check_env(policy, &stack, role, obj.get("Env"))?;
    if role == Role::EgressProxy {
        check_egress_env(policy, &env)?;
    }
    let host = obj
        .get("HostConfig")
        .map(|h| object(h, "HostConfig"))
        .transpose()?;
    let host = host.ok_or("HostConfig is missing")?;
    let limits = read_limits(policy, role, host)?;
    let mode = host
        .get("NetworkMode")
        .and_then(Value::as_str)
        .ok_or("NetworkMode is missing")?;
    check_network_mode(policy, role, &stack, mode)?;
    let site = site_mounts(policy, role, &stack, host)?;
    let outbound = executor_outbound(policy, role, &stack, body)?;
    if role == Role::Executor {
        check_executor_proxy_env(&env, outbound)?;
    }
    let want = expected(
        role,
        &stack,
        image,
        &env,
        &limits,
        mode,
        name,
        &site,
        outbound,
        &policy.egress_bridge,
    );
    match first_difference("body", &want, body) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

fn exact_keys(obj: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if let Some(k) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("key {k:?} is not allowed"));
    }
    if let Some(k) = allowed.iter().find(|k| !obj.contains_key(**k)) {
        return Err(format!("key {k:?} is missing"));
    }
    Ok(())
}

fn check_labels(obj: &Map<String, Value>, c: &Stack, role: &str) -> Result<(), String> {
    match first_difference("Labels", &labels(&c.id, &c.slot, role), &obj["Labels"]) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

pub fn validate_volume(policy: &Policy, body: &Value) -> Result<(), String> {
    let obj = object(body, "body")?;
    exact_keys(obj, &["Name", "Labels"])?;
    let name = obj["Name"].as_str().ok_or("Name is not a string")?;
    if let Ok((id, volume)) = policy.site_volume(name) {
        let want = json!({ "cite.managed": "true", "cite.site": id, "cite.volume": volume });
        return match first_difference("Labels", &want, &obj["Labels"]) {
            Some(reason) => Err(reason),
            None => Ok(()),
        };
    }
    let stack = policy.volume(name)?;
    check_labels(obj, &stack, "volume")
}

pub fn validate_network(policy: &Policy, body: &Value) -> Result<(), String> {
    let obj = object(body, "body")?;
    if let Some(driver) = obj.get("Driver")
        && driver != "bridge"
    {
        return Err("Driver is not allowed".to_string());
    }
    let egress_bridge = obj
        .get("Name")
        .and_then(Value::as_str)
        .is_some_and(|n| policy.is_egress_bridge(n));
    let mut keys = vec!["Name", "Internal", "Labels"];
    if obj.contains_key("Driver") {
        keys.push("Driver");
    }
    if egress_bridge {
        keys.push("Options");
    }
    exact_keys(obj, &keys)?;
    let name = obj["Name"].as_str().ok_or("Name is not a string")?;
    let internal = obj["Internal"]
        .as_bool()
        .ok_or("Internal is not a boolean")?;
    // The node's egress bridge is a normal bridge that only egress proxies join, with ICC off so proxies cannot reach each other.
    if egress_bridge {
        if internal {
            return Err("the egress bridge must not be internal".to_string());
        }
        let options = json!({ "com.docker.network.bridge.enable_icc": "false" });
        if let Some(reason) = first_difference("Options", &options, &obj["Options"]) {
            return Err(reason);
        }
        let want = json!({ "cite.managed": "true", "cite.role": "egress-bridge" });
        return match first_difference("Labels", &want, &obj["Labels"]) {
            Some(reason) => Err(reason),
            None => Ok(()),
        };
    }
    let stack = policy.network(name)?;
    // The manager's egress network keeps its gateway; the executor's net and xnet never have one.
    if internal != (stack.kind != "egress") {
        return Err("Internal does not fit the network kind".to_string());
    }
    check_labels(obj, &stack, "network")
}

pub fn validate_attach(policy: &Policy, network: &str, body: &Value) -> Result<(), String> {
    policy.network(network)?;
    let obj = object(body, "body")?;
    exact_keys(obj, &["Container"])?;
    match obj["Container"].as_str() {
        Some(c) if c == policy.haproxy => Ok(()),
        _ => Err("only the haproxy container may be attached".to_string()),
    }
}
