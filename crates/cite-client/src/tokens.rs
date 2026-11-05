use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::fsio::{read_limited, write_atomic};
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, Result};

const MAX_TOKEN_BYTES: usize = 4096;
const MAX_KEY_BYTES: usize = 128;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const FILE_MODE: u32 = 0o600;
const FILE_VERSION: u32 = 1;

pub trait TokenStore: Send + Sync {
    fn get(&self, node: &str) -> Result<Option<String>>;
    fn set(&self, node: &str, token: &str) -> Result<()>;
    fn delete(&self, node: &str) -> Result<()>;
}

fn check_entry(node: &str, token: &str) -> Result<()> {
    if node.is_empty() || node.len() > MAX_KEY_BYTES {
        return Err(ConfigError::invalid("token key is empty or too long"));
    }
    // Tokens go into an Authorization header, so anything that is not visible ASCII is refused.
    let visible = token.bytes().all(|b| b.is_ascii_graphic());
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES || !visible {
        return Err(ConfigError::invalid(
            "token is empty or contains invalid characters",
        ));
    }
    Ok(())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFile {
    version: u32,
    #[serde(default)]
    tokens: BTreeMap<String, String>,
}

impl Default for TokenFile {
    fn default() -> Self {
        Self {
            version: FILE_VERSION,
            tokens: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct JsonTokenStore {
    path: PathBuf,
    guard: Mutex<()>,
}

impl JsonTokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            guard: Mutex::new(()),
        }
    }

    pub fn beside(config_path: &Path) -> Self {
        Self::new(crate::config::ConfigFile::tokens_path(config_path))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<TokenFile> {
        match read_limited(&self.path, MAX_FILE_BYTES) {
            Ok(bytes) => {
                let file: TokenFile = serde_json::from_slice(&bytes)?;
                if file.version != FILE_VERSION {
                    return Err(ConfigError::Version(file.version));
                }
                Ok(file)
            }
            // Only a missing file counts as empty; a corrupt one must not look like no tokens.
            Err(err) => {
                let err = ConfigError::from(err);
                if err.is_missing() {
                    Ok(TokenFile::default())
                } else {
                    Err(err)
                }
            }
        }
    }

    fn write(&self, file: &TokenFile) -> Result<()> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(file)?;
        write_atomic(&self.path, &bytes, FILE_MODE)?;
        Ok(())
    }
}

impl TokenStore for JsonTokenStore {
    fn get(&self, node: &str) -> Result<Option<String>> {
        let _held = lock(&self.guard);
        Ok(self.read()?.tokens.get(node).cloned())
    }

    fn set(&self, node: &str, token: &str) -> Result<()> {
        check_entry(node, token)?;
        // The guard serializes read-modify-write cycles so concurrent sets cannot lose entries.
        let _held = lock(&self.guard);
        let mut file = self.read()?;
        file.tokens.insert(node.to_string(), token.to_string());
        self.write(&file)
    }

    fn delete(&self, node: &str) -> Result<()> {
        let _held = lock(&self.guard);
        let mut file = self.read()?;
        if file.tokens.remove(node).is_some() {
            self.write(&file)?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for MemoryTokenStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryTokenStore")
            .field("entries", &lock(&self.tokens).len())
            .finish()
    }
}

impl TokenStore for MemoryTokenStore {
    fn get(&self, node: &str) -> Result<Option<String>> {
        Ok(lock(&self.tokens).get(node).cloned())
    }

    fn set(&self, node: &str, token: &str) -> Result<()> {
        check_entry(node, token)?;
        lock(&self.tokens).insert(node.to_string(), token.to_string());
        Ok(())
    }

    fn delete(&self, node: &str) -> Result<()> {
        lock(&self.tokens).remove(node);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_store_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = JsonTokenStore::beside(&dir.path().join("dashboard.json"));
        assert_eq!(store.path(), dir.path().join("tokens.json"));
        assert_eq!(store.get("a").expect("get"), None);
        store.set("a", "cite_aaa").expect("set");
        store.set("b", "cite_bbb").expect("set");
        assert_eq!(store.get("a").expect("get").as_deref(), Some("cite_aaa"));
        store.set("a", "cite_new").expect("overwrite");
        assert_eq!(store.get("a").expect("get").as_deref(), Some("cite_new"));
        store.delete("a").expect("delete");
        store.delete("a").expect("delete twice");
        assert_eq!(store.get("a").expect("get"), None);
        assert_eq!(store.get("b").expect("get").as_deref(), Some("cite_bbb"));
    }

    #[cfg(unix)]
    #[test]
    fn json_store_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = JsonTokenStore::new(dir.path().join("tokens.json"));
        store.set("a", "cite_aaa").expect("set");
        let mode = std::fs::metadata(store.path())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn json_store_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        JsonTokenStore::new(&path)
            .set("a", "cite_aaa")
            .expect("set");
        let reopened = JsonTokenStore::new(&path);
        assert_eq!(reopened.get("a").expect("get").as_deref(), Some("cite_aaa"));
    }

    #[test]
    fn corrupt_token_file_is_an_error_not_an_empty_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        std::fs::write(&path, "{not json").expect("write");
        assert!(JsonTokenStore::new(&path).get("a").is_err());
    }

    #[test]
    fn memory_store_round_trip_and_redacted_debug() {
        let store = MemoryTokenStore::new();
        store.set("a", "cite_secret_value").expect("set");
        assert_eq!(
            store.get("a").expect("get").as_deref(),
            Some("cite_secret_value")
        );
        assert!(!format!("{store:?}").contains("cite_secret_value"));
        store.delete("a").expect("delete");
        assert_eq!(store.get("a").expect("get"), None);
    }

    #[test]
    fn unusable_tokens_are_refused() {
        let store = MemoryTokenStore::new();
        for bad in ["", "has space", "line\nbreak", "caf\u{e9}"] {
            assert!(store.set("a", bad).is_err(), "{bad:?}");
        }
        assert!(store.set("", "cite_x").is_err());
        assert!(store.set("a", &"x".repeat(MAX_TOKEN_BYTES + 1)).is_err());
    }
}
