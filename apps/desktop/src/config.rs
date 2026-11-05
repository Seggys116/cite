use std::fmt;
use std::path::{Path, PathBuf};

use cite_client::NodeConfig;
use cite_client::fsio::{read_limited, write_atomic};
use serde::{Deserialize, Serialize};

pub const KEYCHAIN_SERVICE: &str = "dev.seggys116.cite";
pub const CONFIG_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_CA_FILE_BYTES: u64 = 32 * 1024;
const FILE_MODE: u32 = 0o600;
const PEM_MARKER: &str = "-----BEGIN CERTIFICATE-----";

#[derive(Debug)]
pub enum ConfigError {
    Invalid(String),
    Io(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) | Self::Io(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopNode {
    pub name: String,
    pub url: String,
    // Either an inline PEM certificate or the path of a PEM file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure_http: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopConfig {
    pub version: u32,
    #[serde(default)]
    pub nodes: Vec<DesktopNode>,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            nodes: Vec::new(),
        }
    }
}

impl DesktopNode {
    // Loads the CA from disk when the field holds a path, so the stored config stays small.
    pub fn resolve(&self) -> Result<NodeConfig, ConfigError> {
        let ca_pem = match self.ca_pem.as_deref() {
            Some(raw) if raw.contains(PEM_MARKER) => Some(raw.to_string()),
            Some(raw) if !raw.trim().is_empty() => Some(read_ca_file(Path::new(raw.trim()))?),
            _ => None,
        };
        let node = NodeConfig {
            name: self.name.clone(),
            url: self.url.trim().to_string(),
            ca_pem,
            token_ref: self.name.clone(),
            insecure_http: self.insecure_http,
        };
        node.validate()
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        Ok(node)
    }
}

fn read_ca_file(path: &Path) -> Result<String, ConfigError> {
    let bytes = read_limited(path, MAX_CA_FILE_BYTES)
        .map_err(|e| ConfigError::Io(format!("cannot read CA file {}: {e}", path.display())))?;
    String::from_utf8(bytes).map_err(|_| ConfigError::Invalid("CA file is not text".into()))
}

impl DesktopConfig {
    pub fn node(&self, name: &str) -> Option<&DesktopNode> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported config version {}",
                self.version
            )));
        }
        for (i, node) in self.nodes.iter().enumerate() {
            node.resolve()?;
            if self.nodes[..i].iter().any(|n| n.name == node.name) {
                return Err(ConfigError::Invalid(format!(
                    "node {} is configured twice",
                    node.name
                )));
            }
        }
        Ok(())
    }

    pub fn add_node(&mut self, node: DesktopNode) -> Result<(), ConfigError> {
        node.resolve()?;
        if self.node(&node.name).is_some() {
            return Err(ConfigError::Invalid(format!(
                "node {} already exists",
                node.name
            )));
        }
        self.nodes.push(node);
        Ok(())
    }

    pub fn remove_node(&mut self, name: &str) -> Option<DesktopNode> {
        let at = self.nodes.iter().position(|n| n.name == name)?;
        Some(self.nodes.remove(at))
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = match read_limited(path, MAX_CONFIG_BYTES) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(ConfigError::Io(e.to_string())),
        };
        let cfg: Self = serde_json::from_slice(&bytes)
            .map_err(|e| ConfigError::Invalid(format!("invalid config json: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io(e.to_string()))?;
        }
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        bytes.push(b'\n');
        write_atomic(path, &bytes, FILE_MODE).map_err(|e| ConfigError::Io(e.to_string()))
    }
}

// The platform directory is derived from the environment so no extra crate is needed.
pub fn config_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    config_path_in(home, std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
}

pub fn config_path_in(home: PathBuf, xdg: Option<PathBuf>) -> PathBuf {
    if cfg!(target_os = "macos") {
        return home
            .join("Library")
            .join("Application Support")
            .join("Cite")
            .join("desktop.json");
    }
    let base = xdg
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    base.join("cite").join("desktop.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    fn node(name: &str, url: &str) -> DesktopNode {
        DesktopNode {
            name: name.into(),
            url: url.into(),
            ca_pem: None,
            insecure_http: false,
        }
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("desktop.json");
        let mut cfg = DesktopConfig::default();
        let mut with_ca = node("edge-1", "https://10.0.0.5:7443");
        with_ca.ca_pem = Some(PEM.into());
        cfg.add_node(with_ca).expect("add");
        cfg.add_node(node("edge-2", "http://127.0.0.1:7443"))
            .expect("add");
        cfg.save(&path).expect("save");
        assert_eq!(DesktopConfig::load(&path).expect("load"), cfg);
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("desktop.json");
        DesktopConfig::default().save(&path).expect("save");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn missing_file_loads_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = DesktopConfig::load(&dir.path().join("none.json")).expect("default");
        assert!(cfg.nodes.is_empty());
        assert_eq!(cfg.version, CONFIG_VERSION);
    }

    #[test]
    fn tokens_never_reach_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("desktop.json");
        let mut cfg = DesktopConfig::default();
        cfg.add_node(node("a", "https://h:1")).expect("add");
        cfg.save(&path).expect("save");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(!text.contains("token"));
    }

    #[test]
    fn duplicates_and_bad_urls_are_rejected() {
        let mut cfg = DesktopConfig::default();
        cfg.add_node(node("a", "https://h:1")).expect("add");
        assert!(cfg.add_node(node("a", "https://h:2")).is_err());
        assert!(cfg.add_node(node("b", "http://example.com")).is_err());
        assert!(cfg.add_node(node("Bad Name", "https://h:1")).is_err());
        assert_eq!(cfg.remove_node("a").expect("removed").url, "https://h:1");
        assert!(cfg.remove_node("a").is_none());
    }

    #[test]
    fn unknown_fields_and_versions_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("desktop.json");
        std::fs::write(&path, r#"{"version":1,"token":"x"}"#).expect("write");
        assert!(DesktopConfig::load(&path).is_err());
        std::fs::write(&path, r#"{"version":7}"#).expect("write");
        assert!(DesktopConfig::load(&path).is_err());
    }

    #[test]
    fn ca_resolves_from_inline_or_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, PEM).expect("write");
        let mut n = node("a", "https://h:1");
        n.ca_pem = Some(ca_path.display().to_string());
        assert_eq!(n.resolve().expect("file").ca_pem.as_deref(), Some(PEM));
        n.ca_pem = Some(PEM.into());
        assert_eq!(n.resolve().expect("inline").ca_pem.as_deref(), Some(PEM));
        n.ca_pem = Some("/definitely/not/here.pem".into());
        assert!(n.resolve().is_err());
        n.ca_pem = Some("   ".into());
        assert!(n.resolve().expect("blank").ca_pem.is_none());
    }

    #[test]
    fn config_path_follows_platform_rules() {
        let home = PathBuf::from("/home/u");
        let p = config_path_in(home.clone(), Some(PathBuf::from("/xdg")));
        if cfg!(target_os = "macos") {
            assert!(p.ends_with("Library/Application Support/Cite/desktop.json"));
        } else {
            assert_eq!(p, PathBuf::from("/xdg/cite/desktop.json"));
            assert_eq!(
                config_path_in(home, None),
                PathBuf::from("/home/u/.config/cite/desktop.json")
            );
        }
    }
}
