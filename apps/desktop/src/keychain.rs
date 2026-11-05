#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard, PoisonError};

use cite_client::{ConfigError, TokenStore};

use crate::config::KEYCHAIN_SERVICE;

// Raw secret storage, split from the token policy so tests can swap the OS keychain out.
pub trait SecretBackend: Send + Sync {
    fn read(&self, service: &str, user: &str) -> Result<Option<String>, String>;
    fn write(&self, service: &str, user: &str, secret: &str) -> Result<(), String>;
    fn remove(&self, service: &str, user: &str) -> Result<(), String>;
}

pub struct OsKeyring;

impl SecretBackend for OsKeyring {
    fn read(&self, service: &str, user: &str) -> Result<Option<String>, String> {
        let entry = keyring::Entry::new(service, user).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn write(&self, service: &str, user: &str, secret: &str) -> Result<(), String> {
        keyring::Entry::new(service, user)
            .and_then(|e| e.set_password(secret))
            .map_err(|e| e.to_string())
    }

    fn remove(&self, service: &str, user: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(service, user).map_err(|e| e.to_string())?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryBackend {
    items: Mutex<HashMap<(String, String), String>>,
}

#[cfg(test)]
impl MemoryBackend {
    fn items(&self) -> MutexGuard<'_, HashMap<(String, String), String>> {
        self.items.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
impl SecretBackend for MemoryBackend {
    fn read(&self, service: &str, user: &str) -> Result<Option<String>, String> {
        Ok(self.items().get(&(service.into(), user.into())).cloned())
    }

    fn write(&self, service: &str, user: &str, secret: &str) -> Result<(), String> {
        self.items()
            .insert((service.into(), user.into()), secret.into());
        Ok(())
    }

    fn remove(&self, service: &str, user: &str) -> Result<(), String> {
        self.items().remove(&(service.into(), user.into()));
        Ok(())
    }
}

pub struct KeychainTokenStore<B: SecretBackend = OsKeyring> {
    backend: B,
}

impl KeychainTokenStore<OsKeyring> {
    pub fn system() -> Self {
        Self { backend: OsKeyring }
    }
}

#[cfg(test)]
impl<B: SecretBackend> KeychainTokenStore<B> {
    pub fn with_backend(backend: B) -> Self {
        Self { backend }
    }
}

fn check(node: &str, token: Option<&str>) -> Result<(), ConfigError> {
    if node.is_empty() || node.len() > 128 {
        return Err(ConfigError::invalid("token key is empty or too long"));
    }
    if let Some(t) = token {
        // Tokens travel in an Authorization header, so only visible ASCII is accepted.
        if t.is_empty() || t.len() > 4096 || !t.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ConfigError::invalid(
                "token is empty or contains invalid characters",
            ));
        }
    }
    Ok(())
}

fn backend_err(msg: String) -> ConfigError {
    ConfigError::invalid(format!("keychain: {msg}"))
}

impl<B: SecretBackend> TokenStore for KeychainTokenStore<B> {
    fn get(&self, node: &str) -> Result<Option<String>, ConfigError> {
        check(node, None)?;
        self.backend
            .read(KEYCHAIN_SERVICE, node)
            .map_err(backend_err)
    }

    fn set(&self, node: &str, token: &str) -> Result<(), ConfigError> {
        check(node, Some(token))?;
        self.backend
            .write(KEYCHAIN_SERVICE, node, token)
            .map_err(backend_err)
    }

    fn delete(&self, node: &str) -> Result<(), ConfigError> {
        check(node, None)?;
        self.backend
            .remove(KEYCHAIN_SERVICE, node)
            .map_err(backend_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> KeychainTokenStore<MemoryBackend> {
        KeychainTokenStore::with_backend(MemoryBackend::default())
    }

    #[test]
    fn round_trip_overwrite_and_delete() {
        let s = store();
        assert_eq!(s.get("a").expect("get"), None);
        s.set("a", "cite_one").expect("set");
        s.set("b", "cite_two").expect("set");
        s.set("a", "cite_three").expect("overwrite");
        assert_eq!(s.get("a").expect("get").as_deref(), Some("cite_three"));
        s.delete("a").expect("delete");
        s.delete("a").expect("delete twice");
        assert_eq!(s.get("a").expect("get"), None);
        assert_eq!(s.get("b").expect("get").as_deref(), Some("cite_two"));
    }

    #[test]
    fn unusable_tokens_and_keys_are_refused() {
        let s = store();
        for bad in ["", "has space", "line\nbreak", "caf\u{e9}"] {
            assert!(s.set("a", bad).is_err(), "{bad:?}");
        }
        assert!(s.set("", "cite_x").is_err());
        assert!(s.get("").is_err());
        assert!(s.set("a", &"x".repeat(5000)).is_err());
    }

    #[test]
    fn entries_use_the_cite_service_name() {
        let backend = MemoryBackend::default();
        backend
            .write(KEYCHAIN_SERVICE, "n", "cite_t")
            .expect("write");
        let s = KeychainTokenStore::with_backend(backend);
        assert_eq!(s.get("n").expect("get").as_deref(), Some("cite_t"));
        assert_eq!(KEYCHAIN_SERVICE, "dev.seggys116.cite");
    }
}
