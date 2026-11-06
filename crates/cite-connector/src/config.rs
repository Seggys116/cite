use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use cite_edge::allow::IpAllowlist;

use crate::orchestrator::validate_github_api_url;
use crate::{ConnectorError, Result};

const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 3600;
const MIN_SESSION_TTL_SECS: u64 = 60;
const MAX_SESSION_TTL_SECS: u64 = 30 * 86_400;
const DEFAULT_MASTER_PORT: u16 = 9998;
const MAX_SANS: usize = 32;
const MAX_NODE_NAME: usize = 64;
const MIN_ANALYTICS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANALYTICS_BYTES: u64 = 1 << 40;
const MAX_DB_PATH: usize = 4096;
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
    pub analytics_db: PathBuf,
    pub analytics_archive_dir: PathBuf,
    // None keeps every row until age retention removes it.
    pub analytics_max_bytes: Option<u64>,
    pub haproxy_bin: String,
    pub validate_with_haproxy: bool,
    pub tls: bool,
    pub tls_sans: Vec<String>,
    pub docker_host: Option<String>,
    pub deploy_build_timeout_secs: u64,
    pub edge_network: String,
    pub haproxy_container: String,
    pub stack_version: String,
    pub registry: String,
    pub github_api_url: Option<String>,
    pub session_ttl_secs: u64,
    pub tls_dir: PathBuf,
    // The directory HAProxy loads `ssl crt` certificates from; one combined PEM per certificate.
    pub certs_dir: PathBuf,
    pub certs_mode: u32,
    // The node-wide GitHub token; sites without their own token use it. It is held in memory only.
    pub github_token: Option<NodeToken>,
    // The node-wide Doppler token, held the same way; sites bound to Doppler without their own token use it.
    pub doppler_token: Option<NodeToken>,
    pub doppler_poll_secs: u64,
}

const MAX_NODE_TOKEN_BYTES: usize = 512;
const DEFAULT_DOPPLER_POLL_SECS: u64 = 300;
const MIN_DOPPLER_POLL_SECS: u64 = 60;
const MAX_DOPPLER_POLL_SECS: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    Env,
    File,
}

impl TokenSource {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenSource::Env => "env",
            TokenSource::File => "file",
        }
    }
}

#[derive(Clone)]
pub struct NodeToken {
    value: zeroize::Zeroizing<String>,
    source: TokenSource,
}

impl NodeToken {
    pub fn new(value: &str, source: TokenSource) -> Result<Self> {
        if value.is_empty()
            || value.len() > MAX_NODE_TOKEN_BYTES
            || !value.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(config_err(
                "the token must be printable ASCII without spaces, at most 512 bytes".into(),
            ));
        }
        Ok(Self {
            value: zeroize::Zeroizing::new(value.to_string()),
            source,
        })
    }

    pub fn expose(&self) -> &str {
        &self.value
    }

    pub fn source(&self) -> TokenSource {
        self.source
    }
}

impl std::fmt::Debug for NodeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeToken(<redacted>, {})", self.source.as_str())
    }
}

// The environment variable wins over the file; an unset or blank variable means "not given".
fn node_token(env: &HashMap<String, String>, var: &str) -> Result<Option<NodeToken>> {
    if let Some(raw) = get(env, var) {
        return NodeToken::new(raw, TokenSource::Env)
            .map(Some)
            .map_err(|e| config_err(format!("{var}: {e}")));
    }
    let file_var = format!("{var}_FILE");
    let Some(path) = get(env, &file_var) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    // one byte past the limit plus room for a trailing newline, so an oversized file is refused rather than slurped
    std::fs::File::open(path)
        .and_then(|f| std::io::Read::read_to_end(&mut std::io::Read::take(f, 1024), &mut bytes))
        .map_err(|e| config_err(format!("cannot read {file_var} {path}: {e}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| config_err(format!("{file_var} is not valid text")))?;
    let text = zeroize::Zeroizing::new(text);
    NodeToken::new(text.trim(), TokenSource::File)
        .map(Some)
        .map_err(|e| config_err(format!("{file_var}: {e}")))
}

fn parse_doppler_poll(raw: &str) -> Result<u64> {
    match raw.parse::<u64>() {
        Ok(n) if (MIN_DOPPLER_POLL_SECS..=MAX_DOPPLER_POLL_SECS).contains(&n) => Ok(n),
        _ => Err(config_err(format!(
            "CITE_DOPPLER_POLL_SECS must be {MIN_DOPPLER_POLL_SECS} to {MAX_DOPPLER_POLL_SECS} seconds"
        ))),
    }
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

fn parse_analytics_bytes(raw: &str) -> Result<u64> {
    let bytes: u64 = raw
        .parse()
        .map_err(|_| config_err("CITE_ANALYTICS_MAX_BYTES must be a number of bytes".into()))?;
    if !(MIN_ANALYTICS_BYTES..=MAX_ANALYTICS_BYTES).contains(&bytes) {
        return Err(config_err(format!(
            "CITE_ANALYTICS_MAX_BYTES must be between {MIN_ANALYTICS_BYTES} and {MAX_ANALYTICS_BYTES}"
        )));
    }
    Ok(bytes)
}

// The database sits next to other private state, so only an absolute path to a file is accepted.
fn parse_analytics_db(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    let ok = path.is_absolute()
        && path.file_name().is_some()
        && !raw.ends_with('/')
        && raw.len() <= MAX_DB_PATH
        && !raw.chars().any(char::is_control)
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    if ok {
        Ok(path)
    } else {
        Err(config_err(
            "CITE_ANALYTICS_DB must be an absolute path to a file, without '..' or control characters"
                .into(),
        ))
    }
}

// Archives hold raw request history, so the directory must be an explicit absolute path that cannot climb out of where it was put.
fn parse_archive_dir(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    let ok = path.is_absolute()
        && path.file_name().is_some()
        && raw.len() <= MAX_DB_PATH
        && !raw.chars().any(char::is_control)
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    if ok {
        Ok(path)
    } else {
        Err(config_err(
            "CITE_ANALYTICS_ARCHIVE_DIR must be an absolute directory path, without '..' or control characters"
                .into(),
        ))
    }
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

// 0600 suits HAProxy running as the connector's user; 0640 lets a HAProxy in the connector's group read the keys.
fn parse_certs_mode(raw: &str) -> Result<u32> {
    match raw {
        "600" | "0600" => Ok(0o600),
        "640" | "0640" => Ok(0o640),
        _ => Err(config_err("CITE_CERTS_MODE must be 0600 or 0640".into())),
    }
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
        let log_listen = parse_log_listen(get(env, "CITE_LOG_LISTEN").unwrap_or("127.0.0.1:5140"))?;
        let analytics_max_bytes = match get(env, "CITE_ANALYTICS_MAX_BYTES") {
            Some(raw) => Some(parse_analytics_bytes(raw)?),
            None => None,
        };

        let data_dir = PathBuf::from(get(env, "CITE_CONNECTOR_DATA").unwrap_or("/conf"));
        let analytics_db = match get(env, "CITE_ANALYTICS_DB") {
            Some(raw) => parse_analytics_db(raw)?,
            None => data_dir.join("analytics").join("analytics.db"),
        };
        let analytics_archive_dir = match get(env, "CITE_ANALYTICS_ARCHIVE_DIR") {
            Some(raw) => parse_archive_dir(raw)?,
            None => data_dir.join("analytics").join("archive"),
        };
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

        let deploy_build_timeout_secs = match get(env, "CITE_DEPLOY_BUILD_TIMEOUT") {
            Some(raw) => match raw.trim().parse::<u64>() {
                Ok(n) if (60..=3600).contains(&n) => n,
                _ => {
                    return Err(config_err(
                        "CITE_DEPLOY_BUILD_TIMEOUT must be 60 to 3600 seconds".to_string(),
                    ));
                }
            },
            None => 600,
        };

        let github_api_url = match get(env, "CITE_STACK_GITHUB_API_URL") {
            Some(url) => {
                validate_github_api_url(url)
                    .map_err(|e| config_err(format!("CITE_STACK_GITHUB_API_URL: {e}")))?;
                Some(url.to_string())
            }
            None => None,
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
        let certs_mode = match get(env, "CITE_CERTS_MODE") {
            Some(raw) => parse_certs_mode(raw)?,
            None => 0o600,
        };
        let doppler_poll_secs = match get(env, "CITE_DOPPLER_POLL_SECS") {
            Some(raw) => parse_doppler_poll(raw)?,
            None => DEFAULT_DOPPLER_POLL_SECS,
        };
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
            analytics_db,
            analytics_archive_dir,
            analytics_max_bytes,
            haproxy_bin: get(env, "CITE_HAPROXY_BIN")
                .unwrap_or("haproxy")
                .to_string(),
            validate_with_haproxy: bool_or(env, "CITE_HAPROXY_VALIDATE", true)?,
            tls: bool_or(env, "CITE_CONNECTOR_TLS", true)?,
            tls_sans,
            docker_host: get(env, "CITE_DOCKER_HOST").map(str::to_string),
            deploy_build_timeout_secs,
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
            github_api_url,
            session_ttl_secs,
            tls_dir: data_dir.join("tls"),
            certs_dir: data_dir.join("certs"),
            certs_mode,
            github_token: node_token(env, "CITE_GITHUB_TOKEN")?,
            doppler_token: node_token(env, "CITE_DOPPLER_TOKEN")?,
            doppler_poll_secs,
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
    fn the_log_sink_defaults_to_loopback_so_remote_hosts_cannot_forge_lines() {
        let cfg = ConnectorConfig::from_env_map(&base()).expect("config");
        let LogListen::Udp(addr) = cfg.log_listen else {
            panic!("expected a udp sink");
        };
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 5140);
    }

    fn token_cfg(extra: &[(&str, &str)]) -> Result<Option<NodeToken>> {
        let mut e = base();
        e.extend(env(extra));
        ConnectorConfig::from_env_map(&e).map(|c| c.github_token)
    }

    #[test]
    fn the_node_github_token_comes_from_the_environment_then_a_file() {
        assert!(token_cfg(&[]).unwrap().is_none());
        assert!(token_cfg(&[("CITE_GITHUB_TOKEN", "  ")]).unwrap().is_none());
        let from_env = token_cfg(&[("CITE_GITHUB_TOKEN", "ghp_env")])
            .unwrap()
            .unwrap();
        assert_eq!(
            (from_env.expose(), from_env.source()),
            ("ghp_env", TokenSource::Env)
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "ghp_file\n").unwrap();
        let path = path.display().to_string();
        let from_file = token_cfg(&[("CITE_GITHUB_TOKEN_FILE", &path)])
            .unwrap()
            .unwrap();
        assert_eq!(
            (from_file.expose(), from_file.source()),
            ("ghp_file", TokenSource::File)
        );
        let both = token_cfg(&[
            ("CITE_GITHUB_TOKEN", "ghp_env"),
            ("CITE_GITHUB_TOKEN_FILE", &path),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            (both.expose(), both.source()),
            ("ghp_env", TokenSource::Env)
        );
    }

    #[test]
    fn a_bad_node_github_token_is_refused_without_printing_it() {
        let long = "a".repeat(513);
        for bad in ["has space", long.as_str(), "caf\u{e9}"] {
            let err = token_cfg(&[("CITE_GITHUB_TOKEN", bad)])
                .unwrap_err()
                .to_string();
            assert!(!err.contains(bad), "{err}");
        }
        assert!(token_cfg(&[("CITE_GITHUB_TOKEN_FILE", "/nonexistent/cite-token")]).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        std::fs::write(&path, "a".repeat(4096)).unwrap();
        assert!(token_cfg(&[("CITE_GITHUB_TOKEN_FILE", &path.display().to_string())]).is_err());
    }

    fn doppler_cfg(extra: &[(&str, &str)]) -> Result<ConnectorConfig> {
        let mut e = base();
        e.extend(env(extra));
        ConnectorConfig::from_env_map(&e)
    }

    #[test]
    fn the_node_doppler_token_follows_the_github_token_rules() {
        let none = doppler_cfg(&[]).unwrap();
        assert!(none.doppler_token.is_none());
        assert_eq!(none.doppler_poll_secs, 300);
        let from_env = doppler_cfg(&[("CITE_DOPPLER_TOKEN", "dp.st.prd.env")])
            .unwrap()
            .doppler_token
            .unwrap();
        assert_eq!(
            (from_env.expose(), from_env.source()),
            ("dp.st.prd.env", TokenSource::Env)
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doppler");
        std::fs::write(&path, "dp.st.prd.file\n").unwrap();
        let path = path.display().to_string();
        let from_file = doppler_cfg(&[("CITE_DOPPLER_TOKEN_FILE", &path)])
            .unwrap()
            .doppler_token
            .unwrap();
        assert_eq!(
            (from_file.expose(), from_file.source()),
            ("dp.st.prd.file", TokenSource::File)
        );
        let both = doppler_cfg(&[
            ("CITE_DOPPLER_TOKEN", "dp.st.prd.env"),
            ("CITE_DOPPLER_TOKEN_FILE", &path),
        ])
        .unwrap();
        assert_eq!(
            both.doppler_token.as_ref().unwrap().expose(),
            "dp.st.prd.env"
        );
        assert!(both.github_token.is_none(), "the tokens are independent");
        let err = doppler_cfg(&[("CITE_DOPPLER_TOKEN", "dp secret")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("CITE_DOPPLER_TOKEN") && !err.contains("dp secret"),
            "{err}"
        );
        let shown = format!("{:?}", both.doppler_token);
        assert!(!shown.contains("dp.st.prd.env"), "{shown}");
    }

    #[test]
    fn the_doppler_poll_interval_is_bounded() {
        for (raw, ok) in [
            ("60", Some(60)),
            ("300", Some(300)),
            ("86400", Some(86_400)),
            ("59", None),
            ("0", None),
            ("86401", None),
            ("5m", None),
        ] {
            let got = doppler_cfg(&[("CITE_DOPPLER_POLL_SECS", raw)])
                .ok()
                .map(|c| c.doppler_poll_secs);
            assert_eq!(got, ok, "{raw}");
        }
    }

    #[test]
    fn the_node_github_token_never_prints() {
        let cfg = token_cfg(&[("CITE_GITHUB_TOKEN", "ghp_secret_value")]).unwrap();
        assert!(!format!("{cfg:?}").contains("ghp_secret_value"));
    }

    #[test]
    fn build_wait_defaults_to_ten_minutes_and_is_bounded() {
        let cfg = ConnectorConfig::from_env_map(&base()).expect("config");
        assert_eq!(cfg.deploy_build_timeout_secs, 600);
        for (raw, ok) in [
            ("60", true),
            ("3600", true),
            ("59", false),
            ("3601", false),
            ("x", false),
        ] {
            let mut env = base();
            env.insert("CITE_DEPLOY_BUILD_TIMEOUT".into(), raw.into());
            assert_eq!(ConnectorConfig::from_env_map(&env).is_ok(), ok, "{raw}");
        }
    }

    #[test]
    fn the_certificate_file_mode_is_one_of_two_values() {
        for (raw, mode) in [
            ("0600", Some(0o600)),
            ("640", Some(0o640)),
            ("0644", None),
            ("0777", None),
            ("x", None),
        ] {
            let mut env = base();
            env.insert("CITE_CERTS_MODE".into(), raw.into());
            let parsed = ConnectorConfig::from_env_map(&env)
                .ok()
                .map(|c| c.certs_mode);
            assert_eq!(parsed, mode, "{raw}");
        }
    }

    #[test]
    fn defaults_apply_when_only_allowlist_is_set() {
        let cfg = ConnectorConfig::from_env_map(&base()).expect("config");
        assert_eq!(cfg.listen, "0.0.0.0:7443".parse().expect("addr"));
        assert_eq!(
            cfg.log_listen,
            LogListen::Udp("127.0.0.1:5140".parse().expect("addr"))
        );
        assert_eq!(cfg.analytics_max_bytes, None);
        assert_eq!(
            cfg.analytics_db,
            PathBuf::from("/conf/analytics/analytics.db")
        );
        assert_eq!(
            cfg.analytics_archive_dir,
            PathBuf::from("/conf/analytics/archive")
        );
        assert_eq!(cfg.data_dir, PathBuf::from("/conf"));
        assert_eq!(cfg.haproxy_dir, PathBuf::from("/conf/haproxy"));
        assert_eq!(cfg.maps_dir, PathBuf::from("/conf/haproxy/maps"));
        assert_eq!(cfg.pages_dir, PathBuf::from("/conf/haproxy/pages"));
        assert_eq!(cfg.haproxy_cfg, PathBuf::from("/conf/haproxy/haproxy.cfg"));
        assert_eq!(cfg.tls_dir, PathBuf::from("/conf/tls"));
        assert_eq!(cfg.certs_dir, PathBuf::from("/conf/certs"));
        assert_eq!(cfg.certs_mode, 0o600);
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
        assert_eq!(cfg.github_api_url, None);
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
    fn github_api_url_is_optional_and_validated() {
        let mut e = base();
        e.insert(
            "CITE_STACK_GITHUB_API_URL".into(),
            " https://ghe.example.com/api/v3 ".into(),
        );
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(
            cfg.github_api_url.as_deref(),
            Some("https://ghe.example.com/api/v3")
        );
        for bad in [
            "ftp://ghe.example.com",
            "https://user:pw@ghe.example.com",
            "https://ghe.example.com?x=1",
            "https://ghe.example.com/#top",
            "ghe.example.com",
        ] {
            e.insert("CITE_STACK_GITHUB_API_URL".into(), bad.into());
            let err = ConnectorConfig::from_env_map(&e).expect_err(bad);
            assert!(
                err.to_string().contains("CITE_STACK_GITHUB_API_URL"),
                "{bad}"
            );
        }
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
    fn analytics_size_cap_is_optional_and_bounded() {
        let mut e = base();
        e.insert("CITE_ANALYTICS_MAX_BYTES".into(), "33554432".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.analytics_max_bytes, Some(32 * 1024 * 1024));
        e.insert("CITE_ANALYTICS_MAX_BYTES".into(), "  ".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.analytics_max_bytes, None);
        for bad in ["abc", "0", "1024", "-5", "99999999999999"] {
            e.insert("CITE_ANALYTICS_MAX_BYTES".into(), bad.into());
            assert!(ConnectorConfig::from_env_map(&e).is_err(), "{bad}");
        }
    }

    #[test]
    fn analytics_database_path_follows_the_data_dir_unless_set() {
        let mut e = base();
        e.insert("CITE_CONNECTOR_DATA".into(), "/srv/cite".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(
            cfg.analytics_db,
            PathBuf::from("/srv/cite/analytics/analytics.db")
        );
        e.insert("CITE_ANALYTICS_DB".into(), "/var/lib/cite/a.db".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(cfg.analytics_db, PathBuf::from("/var/lib/cite/a.db"));
        for bad in [
            "relative/a.db",
            "/var/lib/",
            "/",
            "/var/../etc/a.db",
            "/a\nb.db",
        ] {
            e.insert("CITE_ANALYTICS_DB".into(), bad.into());
            let err = ConnectorConfig::from_env_map(&e).expect_err(bad);
            assert!(err.to_string().contains("CITE_ANALYTICS_DB"), "{bad}");
        }
    }

    #[test]
    fn archive_directory_follows_the_data_dir_unless_set() {
        let mut e = base();
        e.insert("CITE_CONNECTOR_DATA".into(), "/srv/cite".into());
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(
            cfg.analytics_archive_dir,
            PathBuf::from("/srv/cite/analytics/archive")
        );
        e.insert(
            "CITE_ANALYTICS_ARCHIVE_DIR".into(),
            "/mnt/backups/cite".into(),
        );
        let cfg = ConnectorConfig::from_env_map(&e).expect("config");
        assert_eq!(
            cfg.analytics_archive_dir,
            PathBuf::from("/mnt/backups/cite")
        );
        for bad in ["relative/dir", "/", "/mnt/../etc", "/mnt/a\nb"] {
            e.insert("CITE_ANALYTICS_ARCHIVE_DIR".into(), bad.into());
            let err = ConnectorConfig::from_env_map(&e).expect_err(bad);
            assert!(
                err.to_string().contains("CITE_ANALYTICS_ARCHIVE_DIR"),
                "{bad}"
            );
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
