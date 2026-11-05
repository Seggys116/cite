use std::collections::BTreeMap;
use std::time::Duration;

use cite_core::parse_poll_interval;
use cite_edge::model::{Site, Slot, Target};
use cite_edge::validate::is_valid_id;
use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};

use crate::config::ConnectorConfig;
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

const GIB: i64 = 1024 * 1024 * 1024;
const MANAGER_MEMORY: i64 = 2 * GIB;
const MANAGER_NANO_CPUS: i64 = 2_000_000_000;
const MANAGER_PIDS: i64 = 2048;
const EXECUTOR_MEMORY: i64 = GIB;
const EXECUTOR_NANO_CPUS: i64 = 1_000_000_000;
const EXECUTOR_PIDS: i64 = 256;
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
    stack_version: String,
    registry: String,
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

struct Inspected {
    running: bool,
    image: String,
    env: Vec<String>,
}

impl Inspected {
    // The image adds its own env vars, so every requested entry must be present, not equal sets.
    fn matches(&self, spec: &Value) -> bool {
        let image = spec["Image"].as_str().unwrap_or_default();
        let env_ok = spec["Env"]
            .as_array()
            .map(|want| {
                want.iter()
                    .filter_map(Value::as_str)
                    .all(|e| self.env.iter().any(|have| have == e))
            })
            .unwrap_or(true);
        self.image == image && env_ok
    }
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
            Some(host) => {
                Self::new(host, &cfg.edge_network, &cfg.stack_version, &cfg.registry).map(Some)
            }
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
            stack_version: stack_version.to_string(),
            registry: registry.to_string(),
        })
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
        let plan = plan_stack(
            site,
            slot,
            git_ref,
            github_token,
            &self.registry,
            &self.stack_version,
            &self.edge_network,
        )?;
        let names = &plan.names;
        for image in [&plan.manager_image, &plan.executor_image] {
            self.ensure_image(image).await?;
        }
        for volume in names.volumes() {
            self.create_volume(volume, &names.id, names.slot).await?;
        }
        self.create_network(&names.egress, &names.id, names.slot)
            .await?;

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
        Ok(())
    }

    pub async fn remove_stack(&self, site_id: &str, purge: bool) -> Result<()> {
        for slot in [Slot::Blue, Slot::Green] {
            let names = StackNames::new(site_id, slot)?;
            for name in [&names.executor, &names.manager, &names.init] {
                self.remove_container(name).await?;
            }
            self.send(
                Method::DELETE,
                &format!("{API}/networks/{}", names.egress),
                &[],
                None,
                REQUEST_TIMEOUT,
                &[404],
            )
            .await?;
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
        let names = StackNames::new(site_id, slot)?;
        let manager = self.inspect_owned(&names.manager).await?;
        let executor = self.inspect_owned(&names.executor).await?;
        Ok(manager.is_some_and(|c| c.running) && executor.is_some_and(|c| c.running))
    }

    pub async fn list_stacks(&self) -> Result<Vec<StackInfo>> {
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

    async fn create_volume(&self, name: &str, id: &str, slot: Slot) -> Result<()> {
        let body = json!({ "Name": name, "Labels": labels(id, slot, "volume") });
        self.send(
            Method::POST,
            &format!("{API}/volumes/create"),
            &[],
            Some(&body),
            REQUEST_TIMEOUT,
            &[],
        )
        .await
        .map(|_| ())
    }

    async fn create_network(&self, name: &str, id: &str, slot: Slot) -> Result<()> {
        let body = json!({
            "Name": name,
            "Driver": "bridge",
            "Internal": false,
            "Labels": labels(id, slot, "network"),
        });
        self.send(
            Method::POST,
            &format!("{API}/networks/create"),
            &[],
            Some(&body),
            REQUEST_TIMEOUT,
            &[409],
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

    async fn remove_container(&self, name: &str) -> Result<()> {
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
    registry: &str,
    version: &str,
    edge_network: &str,
) -> Result<Plan> {
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

    Ok(Plan {
        manager: manager_spec(&names, &manager_image, &manager_env),
        executor: executor_spec(&names, &executor_image, &executor_env, edge_network),
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
fn manager_spec(names: &StackNames, image: &str, env: &[String]) -> Value {
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
            "Memory": MANAGER_MEMORY,
            "MemorySwap": MANAGER_MEMORY,
            "NanoCpus": MANAGER_NANO_CPUS,
            "PidsLimit": MANAGER_PIDS,
            "RestartPolicy": { "Name": "unless-stopped" },
            "LogConfig": log_config(),
        },
        "NetworkingConfig": { "EndpointsConfig": { names.egress.as_str(): {} } },
    })
}

// Mirrors the executor service in docker-compose.yml; reachable only through the internal edge network.
fn executor_spec(names: &StackNames, image: &str, env: &[String], edge_network: &str) -> Value {
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
            "NetworkMode": edge_network,
            "Memory": EXECUTOR_MEMORY,
            "MemorySwap": EXECUTOR_MEMORY,
            "NanoCpus": EXECUTOR_NANO_CPUS,
            "PidsLimit": EXECUTOR_PIDS,
            "RestartPolicy": { "Name": "unless-stopped" },
            "LogConfig": log_config(),
        },
        "NetworkingConfig": {
            "EndpointsConfig": { edge_network: { "Aliases": [names.executor.as_str()] } }
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
mod tests {
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

    struct Ctr {
        spec: Value,
        running: bool,
    }

    #[derive(Default)]
    struct Fake {
        images: HashSet<String>,
        volumes: HashSet<String>,
        networks: HashSet<String>,
        containers: BTreeMap<String, Ctr>,
        log: Vec<String>,
        pull_error: Option<String>,
        init_exit: i64,
    }

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
                f.volumes
                    .insert(v["Name"].as_str().unwrap_or_default().to_string());
                (201, "{}".to_string())
            }
            ("POST", "/networks/create") => {
                let v: Value = serde_json::from_slice(body).unwrap_or_default();
                let name = v["Name"].as_str().unwrap_or_default().to_string();
                if f.networks.insert(name) {
                    (201, "{\"Id\":\"n\"}".to_string())
                } else {
                    (409, json!({ "message": "network exists" }).to_string())
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
            ("GET", p) if p.starts_with("/containers/") && p.ends_with("/json") => {
                let name = &p["/containers/".len()..p.len() - "/json".len()];
                match f.containers.get(name) {
                    Some(c) => (
                        200,
                        json!({
                            "State": { "Running": c.running },
                            "Config": {
                                "Image": c.spec["Image"],
                                "Env": c.spec["Env"],
                                "Labels": c.spec["Labels"],
                            },
                        })
                        .to_string(),
                    ),
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
                match f.networks.remove(&p["/networks/".len()..]) {
                    true => (204, String::new()),
                    false => not_found(),
                }
            }
            ("DELETE", p) if p.starts_with("/volumes/") => {
                match f.volumes.remove(&p["/volumes/".len()..]) {
                    true => (204, String::new()),
                    false => not_found(),
                }
            }
            _ => not_found(),
        }
    }

    async fn start_fake() -> (Orchestrator, Arc<Mutex<Fake>>) {
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
        .unwrap();
        (orch, fake)
    }

    fn count(fake: &Arc<Mutex<Fake>>, entry: &str) -> usize {
        fake.lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| l.starts_with(entry))
            .count()
    }

    fn site(id: &str, runtime: Option<&str>) -> Site {
        Site {
            id: id.to_string(),
            name: id.to_string(),
            hosts: vec![format!("{id}.example.com")],
            path_regex: None,
            kind: SiteKind::Site,
            blue: Upstream::default(),
            green: Upstream::default(),
            active: Slot::Blue,
            maintenance: Maintenance::default(),
            health: HealthCheck::default(),
            source: Some(Source {
                repo: "acme/shop".to_string(),
                branch: None,
                runtime: runtime.map(str::to_string),
                node_major: None,
                poll_interval: None,
                secret: None,
            }),
            history: Vec::new(),
        }
    }

    fn plan(runtime: Option<&str>, git_ref: Option<&str>) -> Result<Plan> {
        plan_stack(
            &site("shop", runtime),
            Slot::Blue,
            git_ref,
            TOKEN,
            "ghcr.io/seggys116",
            "0.2.0",
            "cite_edge",
        )
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
        assert_eq!(hc["Memory"], json!(2 * GIB));
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
        assert_eq!(hc["Memory"], json!(GIB));
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
            "r.io/o",
            "1.0.0",
            "edge",
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
        assert!(plan_stack(&s, Slot::Blue, None, TOKEN, "r.io/o", "1", "edge").is_err());
        let mut s = site("shop", None);
        s.source = None;
        assert!(plan_stack(&s, Slot::Blue, None, TOKEN, "r.io/o", "1", "edge").is_err());
        let mut s = site("shop", None);
        if let Some(src) = s.source.as_mut() {
            src.repo = "acme/shop; rm".to_string();
        }
        assert!(plan_stack(&s, Slot::Blue, None, TOKEN, "r.io/o", "1", "edge").is_err());
        let s = site("shop", None);
        assert!(plan_stack(&s, Slot::Blue, None, "tok en", "r.io/o", "1", "edge").is_err());
        assert!(plan_stack(&s, Slot::Blue, None, "", "r.io/o", "1", "edge").is_err());
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
        let volumes: HashSet<&str> = f.volumes.iter().map(String::as_str).collect();
        assert_eq!(
            volumes,
            HashSet::from([
                "cite-shop-blue-data",
                "cite-shop-blue-work",
                "cite-shop-blue-cache"
            ])
        );
        assert!(f.networks.contains("cite-shop-blue-egress"));
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
        fake.lock().unwrap().containers.insert(
            "cite-shop-blue-manager".to_string(),
            Ctr {
                spec: json!({ "Image": "evil", "Env": [], "Labels": {} }),
                running: true,
            },
        );
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
}
