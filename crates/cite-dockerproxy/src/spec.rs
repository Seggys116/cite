use serde_json::{Map, Value, json};

use crate::policy::{Policy, Stack};

// Upper bounds for the resource limits a create body may ask for.
const GIB: i64 = 1 << 30;
const MIB: i64 = 1 << 20;
const MAX_ENV_ENTRIES: usize = 32;
const MAX_TOKEN_LEN: usize = 512;
const MAX_REF_LEN: usize = 100;

const INIT_SCRIPT: &str = "mkdir -p /data/releases/blue /data/releases/green /data/control \
/data/status /data/state && \
chown 0:0 /data/releases /data/releases/blue /data/releases/green /data/control /data/state && \
chown 65532:65532 /data/status && \
chmod 0755 /data/releases /data/control /data/status && chmod 0750 /data/state";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Manager,
    Executor,
    Init,
}

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
}

const MANAGER_ENV: [(&str, EnvRule); 15] = [
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
];

const EXECUTOR_ENV: [(&str, EnvRule); 8] = [
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
fn expected(
    role: Role,
    c: &Stack,
    image: &str,
    env: &Value,
    limits: &Limits,
    network: &str,
    name: &str,
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
            host["Mounts"] = json!([
                mount(&data, "/var/lib/cite/releases", Some("releases"), true),
                mount(&data, "/var/lib/cite/control", Some("control"), true),
                mount(&data, "/var/lib/cite/status", Some("status"), false),
            ]);
            host["NanoCpus"] = json!(limits.nano_cpus);
            host["RestartPolicy"] = json!({ "Name": "unless-stopped" });
            body["NetworkingConfig"] =
                json!({ "EndpointsConfig": { network: { "Aliases": [name] } } });
        }
        Role::Init => {
            body["User"] = json!("0:0");
            body["Entrypoint"] = json!(["/bin/sh", "-c"]);
            body["Cmd"] = json!([INIT_SCRIPT]);
            body["Healthcheck"] = json!({ "Test": ["NONE"] });
            host["CapAdd"] = json!(["CHOWN", "FOWNER"]);
            host["Mounts"] = json!([mount(&data, "/data", None, false)]);
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

fn within(host: &Map<String, Value>, key: &str, max: i64) -> Result<i64, String> {
    match host.get(key).and_then(Value::as_i64) {
        Some(n) if (1..=max).contains(&n) => Ok(n),
        _ => Err(format!("HostConfig.{key} is missing or out of range")),
    }
}

fn read_limits(role: Role, host: &Map<String, Value>) -> Result<Limits, String> {
    let (memory, cpus, pids) = match role {
        Role::Manager => (4 * GIB, Some(4_000_000_000), 4096),
        Role::Executor => (2 * GIB, Some(2_000_000_000), 1024),
        Role::Init => (256 * MIB, None, 128),
    };
    Ok(Limits {
        memory: within(host, "Memory", memory)?,
        nano_cpus: cpus.map(|max| within(host, "NanoCpus", max)).transpose()?,
        pids: within(host, "PidsLimit", pids)?,
    })
}

fn is_slug_part(s: &str, max: usize, extra: &[char]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

fn env_value_ok(policy: &Policy, rule: &EnvRule, value: &str) -> bool {
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
    }
}

fn check_env(policy: &Policy, role: Role, env: Option<&Value>) -> Result<Value, String> {
    if role == Role::Init {
        return match env {
            None => Ok(Value::Null),
            Some(_) => Err("Env is not allowed on init containers".to_string()),
        };
    }
    let rules: &[(&str, EnvRule)] = if role == Role::Manager {
        &MANAGER_ENV
    } else {
        &EXECUTOR_ENV
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
        if !env_value_ok(policy, rule, value) {
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
        _ => Role::Init,
    };
    let obj = object(body, "body")?;
    let image = obj
        .get("Image")
        .and_then(Value::as_str)
        .ok_or("Image is missing")?;
    let image_ok = match role {
        Role::Executor => policy.is_executor_image(image),
        _ => policy.is_manager_image(image),
    };
    if !image_ok {
        return Err("Image is not allowed for this container".to_string());
    }
    let env = check_env(policy, role, obj.get("Env"))?;
    let host = obj
        .get("HostConfig")
        .map(|h| object(h, "HostConfig"))
        .transpose()?;
    let host = host.ok_or("HostConfig is missing")?;
    let limits = read_limits(role, host)?;
    let mode = host
        .get("NetworkMode")
        .and_then(Value::as_str)
        .ok_or("NetworkMode is missing")?;
    check_network_mode(policy, role, &stack, mode)?;
    let want = expected(role, &stack, image, &env, &limits, mode, name);
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
    let mut keys = vec!["Name", "Internal", "Labels"];
    if obj.contains_key("Driver") {
        keys.push("Driver");
    }
    exact_keys(obj, &keys)?;
    let name = obj["Name"].as_str().ok_or("Name is not a string")?;
    let stack = policy.network(name)?;
    let internal = obj["Internal"]
        .as_bool()
        .ok_or("Internal is not a boolean")?;
    if internal != (stack.kind == "net") {
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
