use std::collections::BTreeMap;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use crate::config::Config;
use crate::spec;
use crate::target::Target;

pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_LOG_RESPONSE: usize = 4 * 1024 * 1024;
const MAX_LOG_TAIL: u32 = 1000;
const MAX_LOG_SINCE: usize = 20;

// Matches the slug rule of site ids (lowercase, digits, dashes, at most 40 characters).
const ID: &str = "[a-z0-9][a-z0-9-]{0,39}";
const VERSION: &str = "[0-9]+\\.[0-9]+\\.[0-9]+";
// The underscore never occurs in a site id, so a site volume name always splits one way.
const VOLUME_NAME: &str = "[a-z0-9][a-z0-9-]{0,30}";
const MAX_STOP_GRACE: u32 = 60;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const WAIT_TIMEOUT: Duration = Duration::from_secs(300);
const PULL_TIMEOUT: Duration = Duration::from_secs(900);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    None,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Container(String),
    Volume(String),
    Network(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Ping,
    ImagePull,
    ImageInspect,
    VolumeCreate,
    VolumeList,
    VolumeInspect(String),
    VolumeDelete(String),
    NetworkCreate,
    NetworkInspect(String),
    NetworkDelete(String),
    NetworkConnect(String),
    NetworkDisconnect(String),
    ContainerCreate(String),
    ContainerStart(String),
    ContainerStop(String),
    ContainerRestart(String),
    ContainerWait(String),
    ContainerInspect(String),
    ContainerLogs(String),
    ContainerDelete(String),
    ContainerList,
}

impl Route {
    pub fn body(&self) -> BodyKind {
        match self {
            Route::VolumeCreate
            | Route::NetworkCreate
            | Route::NetworkConnect(_)
            | Route::NetworkDisconnect(_)
            | Route::ContainerCreate(_) => BodyKind::Json,
            _ => BodyKind::None,
        }
    }

    pub fn timeout(&self) -> Duration {
        match self {
            Route::ImagePull => PULL_TIMEOUT,
            Route::ContainerWait(_) => WAIT_TIMEOUT,
            _ => DEFAULT_TIMEOUT,
        }
    }

    // Routes that act on an existing object only proceed when it carries the cite.managed label.
    pub fn check(&self) -> Option<Check> {
        match self {
            Route::VolumeDelete(n) => Some(Check::Volume(n.clone())),
            Route::NetworkDelete(n) | Route::NetworkConnect(n) | Route::NetworkDisconnect(n) => {
                Some(Check::Network(n.clone()))
            }
            Route::ContainerStart(n)
            | Route::ContainerStop(n)
            | Route::ContainerRestart(n)
            | Route::ContainerWait(n)
            | Route::ContainerLogs(n)
            | Route::ContainerDelete(n) => Some(Check::Container(n.clone())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    pub id: String,
    pub slot: String,
    pub kind: String,
}

pub struct Policy {
    pub(crate) haproxy: String,
    pub(crate) edge: String,
    pub(crate) github_api_url: Option<String>,
    pub(crate) forge: Option<String>,
    pub(crate) forge_api_url: Option<String>,
    pub(crate) max_memory: i64,
    pub(crate) max_nano_cpus: i64,
    pub(crate) executor_egress: bool,
    container: Regex,
    volume: Regex,
    site_volume: Regex,
    network: Regex,
    manager_image: Regex,
    executor_image: Regex,
    pull_repo: Regex,
    pull_tag: Regex,
}

impl Policy {
    pub fn new(cfg: &Config) -> Policy {
        let reg = regex::escape(&cfg.registry);
        let build = |p: String| Regex::new(&p).expect("static pattern");
        let stack = |kinds: &str| {
            build(format!(
                "^cite-(?<id>{ID})-(?<slot>blue|green)-(?<kind>{kinds})$"
            ))
        };
        Policy {
            haproxy: cfg.haproxy_container.clone(),
            edge: cfg.edge_network.clone(),
            github_api_url: cfg.github_api_url.clone(),
            forge: cfg.forge.clone(),
            forge_api_url: cfg.forge_api_url.clone(),
            max_memory: cfg.max_memory,
            max_nano_cpus: cfg.max_nano_cpus,
            executor_egress: cfg.executor_egress,
            container: stack("manager|executor|init"),
            volume: stack("data|work|cache"),
            site_volume: build(format!(
                "^cite-vol-(?<id>{ID})_(?<name>{VOLUME_NAME})$"
            )),
            network: stack("net|egress"),
            manager_image: build(format!(
                "^{reg}/(cite-manager:{VERSION}-node(22|24)|cite-manager-rust:{VERSION})$"
            )),
            executor_image: build(format!(
                "^{reg}/(cite-executor-node:{VERSION}-node(22|24)|cite-executor-(bun|static|rust):{VERSION})$"
            )),
            pull_repo: build(format!(
                "^{reg}/(cite-manager|cite-manager-rust|cite-executor-(node|bun|static|rust))$"
            )),
            pull_tag: build(format!("^{VERSION}(-node(22|24))?$")),
        }
    }

    // Names are parsed from the right, so a site id that looks like a slot or role cannot confuse the match.
    fn parse(re: &Regex, what: &str, name: &str) -> Result<Stack, String> {
        let caps = re
            .captures(name)
            .ok_or_else(|| format!("{what} name is not a cite stack name"))?;
        Ok(Stack {
            id: caps["id"].to_string(),
            slot: caps["slot"].to_string(),
            kind: caps["kind"].to_string(),
        })
    }

    pub fn container(&self, name: &str) -> Result<Stack, String> {
        Self::parse(&self.container, "container", name)
    }

    pub fn volume(&self, name: &str) -> Result<Stack, String> {
        Self::parse(&self.volume, "volume", name)
    }

    pub fn network(&self, name: &str) -> Result<Stack, String> {
        Self::parse(&self.network, "network", name)
    }

    /// (site id, volume name) of a persistent site volume.
    pub fn site_volume(&self, name: &str) -> Result<(String, String), String> {
        let caps = self
            .site_volume
            .captures(name)
            .ok_or_else(|| "volume name is not a cite site volume name".to_string())?;
        Ok((caps["id"].to_string(), caps["name"].to_string()))
    }

    // Stack volumes and site volumes are the only volumes the connector may touch.
    fn any_volume(&self, name: &str) -> Result<(), String> {
        if name.starts_with("cite-vol-") && self.site_volume(name).is_ok() {
            return Ok(());
        }
        self.volume(name).map(|_| ())
    }

    pub fn is_manager_image(&self, image: &str) -> bool {
        self.manager_image.is_match(image)
    }

    pub fn is_executor_image(&self, image: &str) -> bool {
        self.executor_image.is_match(image)
    }

    // Route patterns spell out every method and segment; anything unlisted falls through to a denial.
    pub fn classify(&self, method: &str, target: &Target) -> Result<Route, String> {
        let segs: Vec<&str> = target.path[1..].split('/').collect();
        let q = &target.query;
        let route = match (method, segs.as_slice()) {
            ("GET", ["_ping"]) => {
                allow_keys(q, &[], &[])?;
                Route::Ping
            }
            ("POST", ["images", "create"]) => {
                self.check_pull(q)?;
                Route::ImagePull
            }
            ("GET", ["images", reference @ .., "json"]) if !reference.is_empty() => {
                allow_keys(q, &[], &[])?;
                let reference = reference.join("/");
                if !self.is_manager_image(&reference) && !self.is_executor_image(&reference) {
                    return Err("image is not a cite image".to_string());
                }
                Route::ImageInspect
            }
            ("POST", ["volumes", "create"]) => {
                allow_keys(q, &[], &[])?;
                Route::VolumeCreate
            }
            ("GET", ["volumes"]) => {
                check_label_filters(q, &[])?;
                Route::VolumeList
            }
            ("GET", ["volumes", name]) => {
                allow_keys(q, &[], &[])?;
                self.any_volume(name)?;
                Route::VolumeInspect(name.to_string())
            }
            ("DELETE", ["volumes", name]) => {
                allow_keys(q, &[], &[])?;
                self.any_volume(name)?;
                Route::VolumeDelete(name.to_string())
            }
            ("POST", ["networks", "create"]) => {
                allow_keys(q, &[], &[])?;
                Route::NetworkCreate
            }
            ("GET", ["networks", name]) => {
                allow_keys(q, &[], &[])?;
                self.network(name)?;
                Route::NetworkInspect(name.to_string())
            }
            ("DELETE", ["networks", name]) => {
                allow_keys(q, &[], &[])?;
                self.network(name)?;
                Route::NetworkDelete(name.to_string())
            }
            ("POST", ["networks", name, action @ ("connect" | "disconnect")]) => {
                allow_keys(q, &[], &[])?;
                if self.network(name)?.kind != "net" {
                    return Err("only per-stack networks can be attached".to_string());
                }
                match *action {
                    "connect" => Route::NetworkConnect(name.to_string()),
                    _ => Route::NetworkDisconnect(name.to_string()),
                }
            }
            ("GET", ["containers", "json"]) => {
                check_list(q)?;
                Route::ContainerList
            }
            ("POST", ["containers", "create"]) => {
                allow_keys(q, &["name"], &["name"])?;
                let name = &q["name"];
                self.container(name)?;
                Route::ContainerCreate(name.clone())
            }
            ("GET", ["containers", name, "json"]) => {
                allow_keys(q, &[], &[])?;
                self.container(name)?;
                Route::ContainerInspect(name.to_string())
            }
            ("GET", ["containers", name, "logs"]) => {
                check_logs(q)?;
                self.container(name)?;
                Route::ContainerLogs(name.to_string())
            }
            ("DELETE", ["containers", name]) => {
                allow_keys(q, &["force"], &[])?;
                bool_value(q, "force")?;
                self.container(name)?;
                Route::ContainerDelete(name.to_string())
            }
            (
                "POST",
                [
                    "containers",
                    name,
                    action @ ("start" | "stop" | "restart" | "wait"),
                ],
            ) => {
                self.container(name)?;
                let name = name.to_string();
                match *action {
                    "start" => {
                        allow_keys(q, &[], &[])?;
                        Route::ContainerStart(name)
                    }
                    "stop" | "restart" => {
                        allow_keys(q, &["t"], &[])?;
                        check_grace(q)?;
                        match *action {
                            "stop" => Route::ContainerStop(name),
                            _ => Route::ContainerRestart(name),
                        }
                    }
                    _ => {
                        allow_keys(q, &["condition"], &[])?;
                        if q.get("condition").is_some_and(|c| c != "not-running") {
                            return Err("wait condition is not allowed".to_string());
                        }
                        Route::ContainerWait(name)
                    }
                }
            }
            _ => return Err("route is not allowed".to_string()),
        };
        Ok(route)
    }

    // The pulled reference is rebuilt and tested against the same image patterns containers are created from.
    fn check_pull(&self, q: &BTreeMap<String, String>) -> Result<(), String> {
        allow_keys(q, &["fromImage", "tag"], &["fromImage", "tag"])?;
        let (repo, tag) = (&q["fromImage"], &q["tag"]);
        if !self.pull_repo.is_match(repo) || !self.pull_tag.is_match(tag) {
            return Err("image to pull is not a cite image".to_string());
        }
        let full = format!("{repo}:{tag}");
        if !self.is_manager_image(&full) && !self.is_executor_image(&full) {
            return Err("image tag does not fit the image".to_string());
        }
        Ok(())
    }

    pub fn validate_body(&self, route: &Route, body: &Value) -> Result<(), String> {
        match route {
            Route::VolumeCreate => spec::validate_volume(self, body),
            Route::NetworkCreate => spec::validate_network(self, body),
            Route::NetworkConnect(net) | Route::NetworkDisconnect(net) => {
                spec::validate_attach(self, net, body)
            }
            Route::ContainerCreate(name) => spec::validate_container(self, name, body),
            _ => Ok(()),
        }
    }
}

// Unknown parameters are refused rather than ignored, since the engine would honour them.
fn allow_keys(
    q: &BTreeMap<String, String>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), String> {
    if let Some(extra) = q.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("query parameter {extra:?} is not allowed"));
    }
    if let Some(missing) = required.iter().find(|k| !q.contains_key(**k)) {
        return Err(format!("query parameter {missing:?} is required"));
    }
    Ok(())
}

fn bool_value(q: &BTreeMap<String, String>, key: &str) -> Result<(), String> {
    match q.get(key).map(String::as_str) {
        None | Some("true" | "false") => Ok(()),
        Some(_) => Err(format!("query parameter {key:?} is not a boolean")),
    }
}

fn check_grace(q: &BTreeMap<String, String>) -> Result<(), String> {
    match q.get("t") {
        None => Ok(()),
        Some(t) if t.len() <= 3 && t.parse::<u32>().is_ok_and(|n| n <= MAX_STOP_GRACE) => Ok(()),
        Some(_) => Err("stop grace period is out of range".to_string()),
    }
}

// A bounded read: no follow, a mandatory line count, and at least one stream, so the engine never holds the request open.
fn check_logs(q: &BTreeMap<String, String>) -> Result<(), String> {
    allow_keys(
        q,
        &["stdout", "stderr", "tail", "since", "timestamps"],
        &["tail"],
    )?;
    let mut streams = 0;
    for key in ["stdout", "stderr"] {
        match q.get(key).map(String::as_str) {
            None => {}
            Some("1" | "true") => streams += 1,
            Some(_) => return Err(format!("query parameter {key:?} must be 1 or true")),
        }
    }
    if streams == 0 {
        return Err("logs need stdout or stderr".to_string());
    }
    let tail = &q["tail"];
    let tail_ok = tail.len() <= 4
        && tail.bytes().all(|b| b.is_ascii_digit())
        && tail
            .parse::<u32>()
            .is_ok_and(|n| (1..=MAX_LOG_TAIL).contains(&n));
    if !tail_ok {
        return Err("tail is out of range".to_string());
    }
    if let Some(since) = q.get("since") {
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let shaped = match since.split_once('.') {
            Some((whole, fraction)) => digits(whole) && digits(fraction),
            None => digits(since),
        };
        if !shaped || since.len() > MAX_LOG_SINCE {
            return Err("since is not a timestamp".to_string());
        }
    }
    match q.get("timestamps").map(String::as_str) {
        None | Some("0" | "1" | "true" | "false") => Ok(()),
        Some(_) => Err("timestamps is not a boolean".to_string()),
    }
}

// The listing must be pinned to cite-managed containers by its label filter.
fn check_list(q: &BTreeMap<String, String>) -> Result<(), String> {
    check_label_filters(q, &["all"])?;
    bool_value(q, "all")
}

// Container and volume listings both carry a mandatory label filter that includes cite.managed=true.
fn check_label_filters(q: &BTreeMap<String, String>, extra: &[&str]) -> Result<(), String> {
    let mut allowed = vec!["filters"];
    allowed.extend_from_slice(extra);
    allow_keys(q, &allowed, &["filters"])?;
    let filters: Value =
        serde_json::from_str(&q["filters"]).map_err(|_| "filters is not json".to_string())?;
    let obj = filters.as_object().ok_or("filters is not an object")?;
    if obj.len() != 1 {
        return Err("filters may only carry a label filter".to_string());
    }
    let labels = obj
        .get("label")
        .and_then(Value::as_array)
        .ok_or("filters must carry a label list")?;
    let pinned = labels.iter().all(Value::is_string)
        && labels
            .iter()
            .any(|l| l.as_str() == Some("cite.managed=true"));
    if !pinned {
        return Err("filters do not pin cite.managed=true".to_string());
    }
    Ok(())
}
