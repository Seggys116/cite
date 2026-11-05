use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use cite_edge::allow::IpAllowlist;

use crate::{ConnectorError, Result};

const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 3600;
const MIN_SESSION_TTL_SECS: u64 = 60;
const MAX_SESSION_TTL_SECS: u64 = 30 * 86_400;
const DEFAULT_MASTER_PORT: u16 = 9998;
const MAX_SANS: usize = 32;
const MAX_NODE_NAME: usize = 64;
const DEFAULT_ANALYTICS_BYTES: u64 = 128 * 1024 * 1024;
const MIN_ANALYTICS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANALYTICS_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const UNIX_PREFIX: &str = "unix:";
// sun_path is 104 bytes on the BSDs and 108 on Linux, one byte of which is the terminator.
const MAX_SOCKET_PATH: usize = 103;

// Where the connector receives HAProxy's syslog datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogListen {
    Udp(SocketAddr),
    Unix(PathBuf),
}

impl std::fmt::Display for LogListen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogListen::Udp(addr) => write!(f, "{addr}"),
            LogListen::Unix(path) => write!(f, "{UNIX_PREFIX}{}", path.display()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub listen: SocketAddr,
    pub allow: IpAllowlist,
    pub data_dir: PathBuf,
    pub node_name: String,
    pub haproxy_dir: PathBuf,
    pub maps_dir: PathBuf,
    pub pages_dir: PathBuf,
    pub haproxy_cfg: PathBuf,
    pub runtime_addr: String,
    pub master_addr: String,
    pub log_listen: LogListen,
    pub log_addr_for_haproxy: String,
    pub analytics_max_bytes: usize,
    pub haproxy_bin: String,
    pub validate_with_haproxy: bool,
    pub tls: bool,
    pub tls_sans: Vec<String>,
    pub docker_host: Option<String>,
    pub edge_network: String,
    pub haproxy_container: String,
    pub stack_version: String,
    pub registry: String,
    pub session_ttl_secs: u64,
    pub tls_dir: PathBuf,
}

// Startup misconfiguration is reported through Internal; it never reaches an HTTP response.
fn config_err(msg: String) -> ConnectorError {
    ConnectorError::Internal(msg)
}

fn get<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(|v| v.trim()).filter(|v| !v.is_empty())
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(config_err(format!("{key} must be true or false"))),
    }
}

fn parse_addr(key: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| config_err(format!("{key} must be an ip:port socket address")))
}

// The master CLI listens next to the runtime socket on the same host.
fn default_master_addr(runtime_addr: &str) -> Result<String> {
    if let Some(path) = runtime_addr.strip_prefix(UNIX_PREFIX) {
        let dir = std::path::Path::new(path)
            .parent()
            .and_then(|d| d.to_str())
            .ok_or_else(|| config_err("CITE_HAPROXY_RUNTIME has no directory".into()))?;
        return Ok(format!(
            "{UNIX_PREFIX}{}/master.sock",
            dir.trim_end_matches('/')
        ));
    }
    let (host, _) = runtime_addr
        .rsplit_once(':')
        .filter(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
        .ok_or_else(|| config_err("CITE_HAPROXY_RUNTIME must be host:port".into()))?;
    Ok(format!("{host}:{DEFAULT_MASTER_PORT}"))
}

// A socket path must be absolute and short enough for sun_path, with plain characters only.
fn check_socket_path(key: &str, path: &str) -> Result<()> {
    let plain = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'));
    let ok = path.starts_with('/')
        && path.len() > 1
        && path.len() <= MAX_SOCKET_PATH
        && !path.ends_with('/')
        && plain
        && !path.split('/').any(|part| part == "..");
    if ok {
        Ok(())
    } else {
        Err(config_err(format!(
            "{key} must be an absolute socket path of plain characters, at most {MAX_SOCKET_PATH} bytes"
        )))
    }
}

fn check_endpoint(key: &str, value: &str) -> Result<()> {
    match value.strip_prefix(UNIX_PREFIX) {
        Some(path) => check_socket_path(key, path),
        None => check_host_port(key, value),
    }
}

fn parse_log_listen(value: &str) -> Result<LogListen> {
    match value.strip_prefix(UNIX_PREFIX) {
        Some(path) => {
            check_socket_path("CITE_LOG_LISTEN", path)?;
            Ok(LogListen::Unix(PathBuf::from(path)))
        }
        None => parse_addr("CITE_LOG_LISTEN", value).map(LogListen::Udp),
    }
}

fn parse_analytics_bytes(raw: &str) -> Result<usize> {
    let bytes: u64 = raw
        .parse()
        .map_err(|_| config_err("CITE_ANALYTICS_MAX_BYTES must be a number of bytes".into()))?;
    if !(MIN_ANALYTICS_BYTES..=MAX_ANALYTICS_BYTES).contains(&bytes) {
        return Err(config_err(format!(
            "CITE_ANALYTICS_MAX_BYTES must be between {MIN_ANALYTICS_BYTES} and {MAX_ANALYTICS_BYTES}"
        )));
    }
    usize::try_from(bytes).map_err(|_| config_err("CITE_ANALYTICS_MAX_BYTES is too large".into()))
}

fn check_host_port(key: &str, value: &str) -> Result<()> {
    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0) => {
            Ok(())
        }
        _ => Err(config_err(format!("{key} must be host:port"))),
    }
}

fn bool_or(env: &HashMap<String, String>, key: &str, default: bool) -> Result<bool> {
    match get(env, key) {
        Some(v) => parse_bool(key, v),
        None => Ok(default),
    }
}

fn valid_node_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NODE_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn parse_sans(raw: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let ok = item.len() <= 253
            && item
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':' | b'_'));
        if !ok {
            return Err(config_err(format!(
                "CITE_CONNECTOR_SANS entry {item:?} is not a host name or address"
            )));
        }
        if !out.iter().any(|s| s == item) {
            out.push(item.to_string());
        }
    }
    if out.len() > MAX_SANS {
        return Err(config_err(format!(
            "CITE_CONNECTOR_SANS has more than {MAX_SANS} entries"
        )));
    }
    Ok(out)
}

fn parse_ttl(raw: &str) -> Result<u64> {
    let secs: u64 = raw
        .parse()
        .map_err(|_| config_err("CITE_SESSION_TTL must be a number of seconds".into()))?;
    // Bounds stop a typo from making sessions unusable or effectively permanent.
    if !(MIN_SESSION_TTL_SECS..=MAX_SESSION_TTL_SECS).contains(&secs) {
        return Err(config_err(format!(
            "CITE_SESSION_TTL must be between {MIN_SESSION_TTL_SECS} and {MAX_SESSION_TTL_SECS} seconds"
        )));
    }
    Ok(secs)
}

impl ConnectorConfig {
    pub fn from_process_env() -> Result<Self> {
        let env: HashMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .filter(|(k, _)| k.starts_with("CITE_") || k == "HOSTNAME")
            .collect();
        Self::from_env_map(&env)
    }

    pub fn from_env_map(env: &HashMap<String, String>) -> Result<Self> {
        let allow_raw = get(env, "CITE_CONNECTOR_ALLOW").ok_or_else(|| {
            config_err(
                "CITE_CONNECTOR_ALLOW is required: list the dashboard addresses or CIDRs that may connect"
                    .into(),
            )
        })?;
        let allow = IpAllowlist::parse(allow_raw)
            .map_err(|e| config_err(format!("CITE_CONNECTOR_ALLOW: {e}")))?;

        let listen = parse_addr(
            "CITE_CONNECTOR_LISTEN",
            get(env, "CITE_CONNECTOR_LISTEN").unwrap_or("0.0.0.0:7443"),
        )?;
        let log_listen = parse_log_listen(get(env, "CITE_LOG_LISTEN").unwrap_or("0.0.0.0:5140"))?;
        let analytics_max_bytes = match get(env, "CITE_ANALYTICS_MAX_BYTES") {
            Some(raw) => parse_analytics_bytes(raw)?,
            None => DEFAULT_ANALYTICS_BYTES as usize,
        };

        let data_dir = PathBuf::from(get(env, "CITE_CONNECTOR_DATA").unwrap_or("/conf"));
        // An explicit name must be valid; an ambient HOSTNAME that is not falls back quietly.
        let node_name = match get(env, "CITE_NODE_NAME") {
            Some(name) if valid_node_name(name) => name.to_string(),
            Some(_) => {
                return Err(config_err(
                    "CITE_NODE_NAME may use letters, digits, '-', '_' and '.' (64 characters at most)"
                        .into(),
                ));
            }
            None => get(env, "HOSTNAME")
                .filter(|h| valid_node_name(h))
                .unwrap_or("node")
                .to_string(),
        };

        let tls_sans = match get(env, "CITE_CONNECTOR_SANS") {
            Some(raw) => parse_sans(raw)?,
            None => Vec::new(),
        };
        let session_ttl_secs = match get(env, "CITE_SESSION_TTL") {
            Some(raw) => parse_ttl(raw)?,
            None => DEFAULT_SESSION_TTL_SECS,
        };

        let runtime_addr = get(env, "CITE_HAPROXY_RUNTIME")
            .unwrap_or("haproxy:9999")
            .to_string();
        check_endpoint("CITE_HAPROXY_RUNTIME", &runtime_addr)?;
        let master_addr = match get(env, "CITE_HAPROXY_MASTER") {
            Some(addr) => {
                check_endpoint("CITE_HAPROXY_MASTER", addr)?;
                addr.to_string()
            }
            None => default_master_addr(&runtime_addr)?,
        };
        let log_addr_for_haproxy = match get(env, "CITE_LOG_ADDR") {
            Some(addr) => addr.to_string(),
            None => match &log_listen {
                LogListen::Unix(path) => path.display().to_string(),
                LogListen::Udp(_) => "connector:5140".to_string(),
            },
        };

        // Everything HAProxy reads lives under one directory so it can be a single shared volume.
        let haproxy_dir = data_dir.join("haproxy");
        Ok(Self {
            listen,
            allow,
            node_name,
            maps_dir: haproxy_dir.join("maps"),
            pages_dir: haproxy_dir.join("pages"),
            haproxy_cfg: haproxy_dir.join("haproxy.cfg"),
            haproxy_dir,
            runtime_addr,
            master_addr,
            log_listen,
            log_addr_for_haproxy,
            analytics_max_bytes,
            haproxy_bin: get(env, "CITE_HAPROXY_BIN")
                .unwrap_or("haproxy")
                .to_string(),
            validate_with_haproxy: bool_or(env, "CITE_HAPROXY_VALIDATE", true)?,
            tls: bool_or(env, "CITE_CONNECTOR_TLS", true)?,
            tls_sans,
            docker_host: get(env, "CITE_DOCKER_HOST").map(str::to_string),
            edge_network: get(env, "CITE_EDGE_NETWORK")
                .unwrap_or("cite_edge")
                .to_string(),
            haproxy_container: env
                .get("CITE_HAPROXY_CONTAINER")
                .map_or("cite-node-haproxy", |v| v.trim())
                .to_string(),
            stack_version: get(env, "CITE_STACK_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            registry: get(env, "CITE_REGISTRY")
                .unwrap_or("ghcr.io/seggys116")
                .to_string(),
            session_ttl_secs,
            tls_dir: data_dir.join("tls"),
            data_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn base() -> HashMap<String, String> {
        env(&[("CITE_CONNECTOR_ALLOW", "10.0.0.0/24")])
    }

    #[test]
    fn defaults_apply_when_only_allowlist_is_set() {
        let cfg = ConnectorConfig::from_env_map(&base()).expect("config");
        assert_eq!(cfg.listen, "0.0.0.0:7443".parse().expect("addr"));
        assert_eq!(
            cfg.log_listen,
            LogListen::Udp("0.0.0.0:5140".parse().expect("addr"))
        );
        assert_eq!(cfg.analytics_max_bytes, 128 * 1024 * 1024);
        assert_eq!(cfg.data_dir, PathBuf::from("/conf"));
        assert_eq!(cfg.haproxy_dir, PathBuf::from("/conf/haproxy"));
        assert_eq!(cfg.maps_dir, PathBuf::from("/conf/haproxy/maps"));
        assert_eq!(cfg.pages_dir, PathBuf::from("/conf/haproxy/pages"));
        assert_eq!(cfg.haproxy_cfg, PathBuf::from("/conf/haproxy/haproxy.cfg"));
        assert_eq!(cfg.tls_dir, PathBuf::from("/conf/tls"));
        assert_eq!(cfg.runtime_addr, "haproxy:9999");
        assert_eq!(cfg.master_addr, "haproxy:9998");
        assert_eq!(cfg.log_addr_for_haproxy, "connector:5140");
        assert_eq!(cfg.haproxy_bin, "haproxy");
        assert!(cfg.validate_with_haproxy);
        assert!(cfg.tls);
        assert!(cfg.tls_sans.is_empty());
        assert_eq!(cfg.docker_host, None);
        assert_eq!(cfg.edge_network, "cite_edge");
        assert_eq!(cfg.haproxy_container, "cite-node-haproxy");
        assert_eq!(cfg.registry, "ghcr.io/seggys116");
        assert_eq!(cfg.session_ttl_secs, 8 * 3600);
        assert_eq!(cfg.node_name, "node");
        assert_eq!(cfg.stack_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn allowlist_is_mandatory() {
        let err = ConnectorConfig::from_env_map(&HashMap::new()).expect_err("must fail");
        assert!(err.to_string().contains("CITE_CONNECTOR_ALLOW"));
        let blank = env(&[("CITE_CONNECTOR_ALLOW", "  ")]);
        assert!(ConnectorConfig::from_env_map(&blank).is_err());
    }

    #[test]
    fn open_allowlist_needs_explicit_token() {
        let open = env(&[("CITE_CONNECTOR_ALLOW", "0.0.0.0/0")]);
        assert!(ConnectorConfig::from_env_map(&open).is_err());
        let confirmed = env(&[("CITE_CONNECTOR_ALLOW", "0.0.0.0/0,allow-all")]);
        assert!(ConnectorConfig::from_env_map(&confirmed).is_ok());
    }

    #[test]
    fn overrides_are_honoured() {
        let mut e = base();
        e.extend(env(&[
            ("CITE_CONNECTOR_LISTEN", "127.0.0.1:9000"),
            ("CITE_CONNECTOR_DATA", "/tmp/x"),
            ("CITE_NODE_NAME", "edge-1"),
            ("CITE_HAPROXY_RUNTIME", "127.0.0.1:1"),
            ("CITE_HAPROXY_VALIDATE", "false"),
            ("CITE_CONNECTOR_TLS", "0"),
            (
                "CITE_CONNECTOR_SANS",
                "a.example.com, 10.0.0.5 ,a.example.com",
            ),
            ("CITE_DOCKER_HOST", "tcp://socketproxy:2375"),
            ("CITE_SESSION_TTL", "600"),
        ]));
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.listen.port(), 9000);
        assert_eq!(cfg.haproxy_cfg, PathBuf::from("/tmp/x/haproxy/haproxy.cfg"));
        assert_eq!(cfg.node_name, "edge-1");
        assert!(!cfg.validate_with_haproxy);
        assert!(!cfg.tls);
        assert_eq!(cfg.tls_sans, vec!["a.example.com", "10.0.0.5"]);
        assert_eq!(cfg.docker_host.as_deref(), Some("tcp://socketproxy:2375"));
        assert_eq!(cfg.session_ttl_secs, 600);
    }

    #[test]
    fn haproxy_container_can_be_set_or_disabled() {
        let mut e = base();
        e.insert("CITE_HAPROXY_CONTAINER".into(), "edge-proxy".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.haproxy_container, "edge-proxy");
        e.insert("CITE_HAPROXY_CONTAINER".into(), " ".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.haproxy_container, "");
    }

    #[test]
    fn master_address_follows_the_runtime_host_unless_set() {
        let mut e = base();
        e.insert("CITE_HAPROXY_RUNTIME".into(), "172.30.250.3:9999".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.master_addr, "172.30.250.3:9998");
        e.insert("CITE_HAPROXY_MASTER".into(), "10.1.1.1:7000".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.master_addr, "10.1.1.1:7000");
        e.insert("CITE_HAPROXY_MASTER".into(), "no-port".into());
        assert!(ConnectorConfig::from_env_map(&e).is_err());
    }

    #[test]
    fn unix_socket_forms_are_accepted_and_derive_their_siblings() {
        let mut e = base();
        e.extend(env(&[
            ("CITE_HAPROXY_RUNTIME", "unix:/run/cite/admin.sock"),
            ("CITE_LOG_LISTEN", "unix:/run/cite/log.sock"),
        ]));
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.runtime_addr, "unix:/run/cite/admin.sock");
        assert_eq!(cfg.master_addr, "unix:/run/cite/master.sock");
        assert_eq!(
            cfg.log_listen,
            LogListen::Unix(PathBuf::from("/run/cite/log.sock"))
        );
        assert_eq!(cfg.log_addr_for_haproxy, "/run/cite/log.sock");
        e.extend(env(&[
            ("CITE_HAPROXY_MASTER", "unix:/run/other/m.sock"),
            ("CITE_LOG_ADDR", "/run/other/l.sock"),
        ]));
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.master_addr, "unix:/run/other/m.sock");
        assert_eq!(cfg.log_addr_for_haproxy, "/run/other/l.sock");
    }

    #[test]
    fn unsafe_socket_paths_are_rejected() {
        let long = format!("unix:/{}", "a".repeat(120));
        for (key, value) in [
            ("CITE_HAPROXY_RUNTIME", "unix:relative.sock"),
            ("CITE_HAPROXY_RUNTIME", "unix:/run/../etc/x.sock"),
            ("CITE_HAPROXY_RUNTIME", "unix:/run/cite dir/x.sock"),
            ("CITE_HAPROXY_RUNTIME", "unix:/"),
            ("CITE_HAPROXY_RUNTIME", "unix:/run/cite/"),
            ("CITE_HAPROXY_RUNTIME", long.as_str()),
            ("CITE_HAPROXY_MASTER", "unix:"),
            ("CITE_LOG_LISTEN", "unix:/run/x\ny.sock"),
        ] {
            let mut e = base();
            e.insert(key.into(), value.into());
            assert!(ConnectorConfig::from_env_map(&e).is_err(), "{key}={value}");
        }
    }

    #[test]
    fn analytics_budget_is_configurable_and_bounded() {
        let mut e = base();
        e.insert("CITE_ANALYTICS_MAX_BYTES".into(), "33554432".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.analytics_max_bytes, 32 * 1024 * 1024);
        for bad in ["abc", "0", "1024", "-5", "99999999999999"] {
            e.insert("CITE_ANALYTICS_MAX_BYTES".into(), bad.into());
            assert!(ConnectorConfig::from_env_map(&e).is_err(), "{bad}");
        }
    }

    #[test]
    fn hostname_is_used_when_node_name_is_unset() {
        let mut e = base();
        e.insert("HOSTNAME".into(), "box-7".into());
        assert_eq!(
            ConnectorConfig::from_env_map(&e).expect("config").node_name,
            "box-7"
        );
        e.insert("HOSTNAME".into(), "bad name!".into());
        assert_eq!(
            ConnectorConfig::from_env_map(&e).expect("config").node_name,
            "node"
        );
    }

    #[test]
    fn malformed_values_are_rejected() {
        for (key, value) in [
            ("CITE_CONNECTOR_LISTEN", "not-an-addr"),
            ("CITE_LOG_LISTEN", "5140"),
            ("CITE_HAPROXY_VALIDATE", "maybe"),
            ("CITE_CONNECTOR_TLS", "2"),
            ("CITE_NODE_NAME", "has space"),
            ("CITE_CONNECTOR_SANS", "bad/entry"),
            ("CITE_SESSION_TTL", "abc"),
            ("CITE_SESSION_TTL", "5"),
            ("CITE_SESSION_TTL", "99999999999"),
            ("CITE_HAPROXY_RUNTIME", "haproxy"),
            ("CITE_HAPROXY_MASTER", "haproxy:0"),
        ] {
            let mut e = base();
            e.insert(key.into(), value.into());
            assert!(ConnectorConfig::from_env_map(&e).is_err(), "{key}={value}");
        }
    }
}
