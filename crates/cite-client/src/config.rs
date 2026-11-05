use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use cite_core::atomic::read_limited;
use cite_core::write_atomic;
use cite_edge::auth::Credentials;
use cite_edge::validate::is_valid_id;
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, Result};

pub const CONFIG_VERSION: u32 = 1;
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8088";
pub const MAX_NODES: usize = 64;

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CA_BYTES: usize = 32 * 1024;
const MAX_TOKEN_REF: usize = 128;
const FILE_MODE: u32 = 0o600;
const TOKENS_FILE: &str = "tokens.json";

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    pub token_ref: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    pub version: u32,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub admin: Option<Credentials>,
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            listen: default_listen(),
            admin: None,
            nodes: Vec::new(),
        }
    }
}

// Url::host_str keeps the brackets around IPv6 literals, so they are stripped before parsing.
pub fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

pub fn parse_node_url(raw: &str, insecure_http: bool) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw.trim())
        .map_err(|e| ConfigError::invalid(format!("invalid node url: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::invalid("node url needs a host"))?;
    match url.scheme() {
        "https" => {}
        "http" if insecure_http || is_loopback_host(host) => {}
        "http" => {
            return Err(ConfigError::invalid(
                "http:// is only allowed for loopback hosts or nodes flagged insecure_http",
            ));
        }
        _ => return Err(ConfigError::invalid("node url must start with https://")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::invalid("node url must not carry credentials"));
    }
    // Routes are appended to the origin, so any path, query or fragment would be silently dropped.
    if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err(ConfigError::invalid(
            "node url must be a bare origin such as https://host:7443",
        ));
    }
    Ok(url)
}

impl NodeConfig {
    pub fn validate(&self) -> Result<()> {
        if !is_valid_id(&self.name) {
            return Err(ConfigError::invalid(
                "node name must be lowercase letters, digits and '-', at most 40 characters",
            ));
        }
        let ref_ok = !self.token_ref.is_empty()
            && self.token_ref.len() <= MAX_TOKEN_REF
            && !self.token_ref.chars().any(char::is_control);
        if !ref_ok {
            return Err(ConfigError::invalid("node token_ref is empty or malformed"));
        }
        parse_node_url(&self.url, self.insecure_http)?;
        if let Some(pem) = &self.ca_pem {
            if pem.len() > MAX_CA_BYTES {
                return Err(ConfigError::invalid("node ca_pem is too large"));
            }
            if !pem.contains("-----BEGIN CERTIFICATE-----") {
                return Err(ConfigError::invalid(
                    "node ca_pem must be a PEM certificate",
                ));
            }
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.url.trim().trim_end_matches('/').to_string()
    }
}

impl DashboardConfig {
    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError::Version(self.version));
        }
        if self.listen.parse::<SocketAddr>().is_err() {
            return Err(ConfigError::invalid(
                "listen must be an ip:port socket address",
            ));
        }
        if self.nodes.len() > MAX_NODES {
            return Err(ConfigError::invalid(format!(
                "at most {MAX_NODES} nodes are supported"
            )));
        }
        for (i, node) in self.nodes.iter().enumerate() {
            node.validate()?;
            if self.nodes[..i].iter().any(|n| n.name == node.name) {
                return Err(ConfigError::invalid(format!(
                    "node {} is configured twice",
                    node.name
                )));
            }
        }
        Ok(())
    }

    pub fn node(&self, name: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn add_node(&mut self, node: NodeConfig) -> Result<()> {
        node.validate()?;
        if self.node(&node.name).is_some() {
            return Err(ConfigError::invalid(format!(
                "node {} already exists",
                node.name
            )));
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(ConfigError::invalid(format!(
                "at most {MAX_NODES} nodes are supported"
            )));
        }
        self.nodes.push(node);
        Ok(())
    }

    pub fn remove_node(&mut self, name: &str) -> Option<NodeConfig> {
        let at = self.nodes.iter().position(|n| n.name == name)?;
        Some(self.nodes.remove(at))
    }
}

pub struct ConfigFile;

impl ConfigFile {
    pub fn load(path: &Path) -> Result<DashboardConfig> {
        let bytes = read_limited(path, MAX_CONFIG_BYTES)?;
        let cfg: DashboardConfig = serde_json::from_slice(&bytes)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_or_default(path: &Path) -> Result<DashboardConfig> {
        match Self::load(path) {
            Err(err) if err.is_missing() => Ok(DashboardConfig::default()),
            other => other,
        }
    }

    pub fn save(path: &Path, cfg: &DashboardConfig) -> Result<()> {
        cfg.validate()?;
        // A fresh desktop profile has no directory yet; the container volume always does.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = serde_json::to_vec_pretty(cfg)?;
        bytes.push(b'\n');
        write_atomic(path, &bytes, FILE_MODE)?;
        Ok(())
    }

    pub fn tokens_path(config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .join(TOKENS_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, url: &str) -> NodeConfig {
        NodeConfig {
            name: name.to_string(),
            url: url.to_string(),
            ca_pem: None,
            token_ref: name.to_string(),
            insecure_http: false,
        }
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dashboard.json");
        let mut cfg = DashboardConfig::default();
        let mut with_ca = node("edge-1", "https://10.0.0.5:7443");
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        with_ca.ca_pem = Some(pem.to_string());
        cfg.add_node(with_ca).expect("add");
        cfg.add_node(node("edge-2", "http://127.0.0.1:7443"))
            .expect("add");
        ConfigFile::save(&path, &cfg).expect("save");
        let back = ConfigFile::load(&path).expect("load");
        assert_eq!(back.nodes, cfg.nodes);
        assert_eq!(back.listen, DEFAULT_LISTEN);
        assert!(back.admin.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dashboard.json");
        ConfigFile::save(&path, &DashboardConfig::default()).expect("save");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dashboard.json");
        std::fs::write(&path, r#"{"version":1,"surprise":true}"#).expect("write");
        assert!(matches!(ConfigFile::load(&path), Err(ConfigError::Json(_))));
        std::fs::write(
            &path,
            r#"{"version":1,"nodes":[{"name":"a","url":"https://h","token_ref":"a","extra":1}]}"#,
        )
        .expect("write");
        assert!(ConfigFile::load(&path).is_err());
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dashboard.json");
        std::fs::write(&path, r#"{"version":9}"#).expect("write");
        assert!(matches!(
            ConfigFile::load(&path),
            Err(ConfigError::Version(9))
        ));
    }

    #[test]
    fn missing_file_loads_the_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.json");
        assert!(ConfigFile::load(&path).expect_err("missing").is_missing());
        let cfg = ConfigFile::load_or_default(&path).expect("default");
        assert!(cfg.nodes.is_empty());
        assert_eq!(cfg.version, CONFIG_VERSION);
    }

    #[test]
    fn node_names_must_be_slugs() {
        let long = "a".repeat(41);
        for bad in [
            "",
            "Edge",
            "has space",
            "a/b",
            "-lead",
            long.as_str(),
            "dot.ted",
        ] {
            assert!(node(bad, "https://h:7443").validate().is_err(), "{bad:?}");
        }
        for good in ["edge-1", "a", "0x"] {
            assert!(node(good, "https://h:7443").validate().is_ok(), "{good:?}");
        }
    }

    #[test]
    fn urls_must_be_https_unless_loopback_or_flagged() {
        assert!(
            node("a", "https://node.example.com:7443")
                .validate()
                .is_ok()
        );
        assert!(
            node("a", "http://node.example.com:7443")
                .validate()
                .is_err()
        );
        assert!(node("a", "http://127.0.0.1:7443").validate().is_ok());
        assert!(node("a", "http://localhost:7443").validate().is_ok());
        assert!(node("a", "http://[::1]:7443").validate().is_ok());
        assert!(
            node("a", "http://127.0.0.1.example.com")
                .validate()
                .is_err()
        );
        let mut flagged = node("a", "http://10.0.0.5:7443");
        flagged.insecure_http = true;
        assert!(flagged.validate().is_ok());
    }

    #[test]
    fn urls_reject_credentials_paths_and_other_schemes() {
        for bad in [
            "ftp://h:7443",
            "https://user:pw@h:7443",
            "https://h:7443/api",
            "https://h:7443/?x=1",
            "https://h:7443/#frag",
            "not a url",
            "https://",
        ] {
            assert!(node("a", bad).validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn duplicate_nodes_are_rejected_and_removal_works() {
        let mut cfg = DashboardConfig::default();
        cfg.add_node(node("a", "https://h:1")).expect("add");
        assert!(cfg.add_node(node("a", "https://h:2")).is_err());
        assert!(cfg.remove_node("missing").is_none());
        assert_eq!(cfg.remove_node("a").expect("removed").url, "https://h:1");
        assert!(cfg.nodes.is_empty());
        cfg.nodes = vec![node("a", "https://h:1"), node("a", "https://h:2")];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ca_pem_must_look_like_a_certificate() {
        let mut n = node("a", "https://h:1");
        n.ca_pem = Some("hello".into());
        assert!(n.validate().is_err());
        n.ca_pem = Some("x".repeat(MAX_CA_BYTES + 1));
        assert!(n.validate().is_err());
    }

    #[test]
    fn tokens_file_sits_beside_the_config() {
        let path = Path::new("/config/dashboard.json");
        assert_eq!(
            ConfigFile::tokens_path(path),
            Path::new("/config/tokens.json")
        );
    }
}
