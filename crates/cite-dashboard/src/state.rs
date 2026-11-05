use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cite_client::{
    ConfigError, ConfigFile, DEFAULT_FAN_OUT_LIMIT, DashboardConfig, NodeClient, TokenStore,
    fan_out,
};
use cite_edge::auth::{SessionInfo, SessionStore, hash_token};
use cite_edge::ratelimit::LoginLimiter;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::configlock::{ConfigLock, FileKey, file_key};
use crate::error::ApiError;
use crate::preview::PreviewStore;
use crate::settings::Settings;

pub const PROBE_TTL: Duration = Duration::from_secs(5);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const LOGIN_CONCURRENCY: usize = 2;
const SETUP_TOKEN_BYTES: usize = 16;

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Clone)]
pub struct PendingSetup {
    pub username: String,
    pub password_hash: String,
    pub secret: String,
    pub created: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub name: String,
    pub url: String,
    pub online: bool,
    pub version: String,
}

struct Probe {
    at: Instant,
    online: bool,
    version: String,
}

pub struct AppState {
    pub settings: Settings,
    pub sessions: Mutex<SessionStore>,
    pub limiter: Mutex<LoginLimiter>,
    pub pending: Mutex<Option<PendingSetup>>,
    pub previews: Mutex<PreviewStore>,
    // Only the hash of the one-time setup token is kept; the plaintext goes to the log once.
    setup_token_hash: Mutex<Option<String>>,
    // Held across config mutations and logins so read-modify-write cycles never interleave.
    pub write_gate: tokio::sync::Mutex<()>,
    // Bounds concurrent Argon2 runs so a login burst cannot exhaust memory.
    pub login_permits: tokio::sync::Semaphore,
    tokens: Arc<dyn TokenStore>,
    config: RwLock<DashboardConfig>,
    disk_key: Mutex<Option<FileKey>>,
    refresh_gate: tokio::sync::Mutex<()>,
    clients: RwLock<HashMap<String, NodeClient>>,
    probes: Mutex<HashMap<String, Probe>>,
    probe_gate: tokio::sync::Mutex<()>,
}

impl AppState {
    pub fn new(
        settings: Settings,
        config: DashboardConfig,
        tokens: Arc<dyn TokenStore>,
    ) -> Arc<Self> {
        let mut clients = HashMap::new();
        for node in &config.nodes {
            match tokens.get(&node.token_ref) {
                Ok(Some(token)) => match NodeClient::new(node, token) {
                    Ok(client) => {
                        clients.insert(node.name.clone(), client);
                    }
                    Err(err) => {
                        tracing::warn!(node = %node.name, "cannot build node client: {err}");
                    }
                },
                Ok(None) => tracing::warn!(node = %node.name, "no stored token for node"),
                Err(err) => tracing::warn!(node = %node.name, "cannot read node token: {err}"),
            }
        }
        let sessions = SessionStore::new(settings.session_ttl_secs, settings.idle_timeout_secs());
        let disk_key = file_key(&settings.config_path);
        Arc::new(Self {
            settings,
            sessions: Mutex::new(sessions),
            limiter: Mutex::new(LoginLimiter::new()),
            pending: Mutex::new(None),
            previews: Mutex::new(PreviewStore::new()),
            setup_token_hash: Mutex::new(None),
            write_gate: tokio::sync::Mutex::new(()),
            login_permits: tokio::sync::Semaphore::new(LOGIN_CONCURRENCY),
            tokens,
            config: RwLock::new(config),
            disk_key: Mutex::new(disk_key),
            refresh_gate: tokio::sync::Mutex::new(()),
            clients: RwLock::new(clients),
            probes: Mutex::new(HashMap::new()),
            probe_gate: tokio::sync::Mutex::new(()),
        })
    }

    // Returns the plaintext exactly once; calling again replaces the previous token.
    pub fn issue_setup_token(&self) -> Result<String, ApiError> {
        let mut bytes = [0u8; SETUP_TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(ApiError::internal)?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        *lock(&self.setup_token_hash) = Some(hash_token(&token));
        Ok(token)
    }

    pub fn setup_token_matches(&self, presented: &str) -> bool {
        let stored = lock(&self.setup_token_hash).clone();
        let Some(stored) = stored else {
            return false;
        };
        let presented = hash_token(presented.trim());
        bool::from(presented.as_bytes().ct_eq(stored.as_bytes()))
    }

    pub fn clear_setup_token(&self) {
        *lock(&self.setup_token_hash) = None;
    }

    pub async fn config_snapshot(&self) -> DashboardConfig {
        self.refresh_config().await;
        self.config.read().await.clone()
    }

    pub async fn needs_onboarding(&self) -> bool {
        self.refresh_config().await;
        self.config.read().await.admin.is_none()
    }

    pub async fn validate_session(&self, token: &str, now: u64) -> Option<SessionInfo> {
        self.refresh_config().await;
        lock(&self.sessions).validate(token, now)
    }

    fn reset_sessions(&self) {
        *lock(&self.sessions) = SessionStore::new(
            self.settings.session_ttl_secs,
            self.settings.idle_timeout_secs(),
        );
    }

    // A newer generation on disk is a CLI reset: adopt the admin and drop every session and pending setup.
    async fn refresh_config(&self) {
        let _gate = self.refresh_gate.lock().await;
        let path = self.settings.config_path.clone();
        let key = file_key(&path);
        if *lock(&self.disk_key) == key {
            return;
        }
        let loaded = tokio::task::spawn_blocking(move || ConfigFile::load(&path).ok())
            .await
            .ok()
            .flatten();
        let mut config = self.config.write().await;
        *lock(&self.disk_key) = key;
        let Some(disk) = loaded.filter(|d| d.generation > config.generation) else {
            return;
        };
        config.admin = disk.admin;
        config.generation = disk.generation;
        drop(config);
        self.reset_sessions();
        *lock(&self.pending) = None;
    }

    // Callers hold `write_gate`; the file is written first so memory never runs ahead of disk, and a newer generation on disk is never overwritten.
    pub async fn commit_config(&self, mut new: DashboardConfig) -> Result<(), ApiError> {
        let running = self.config.read().await.generation;
        new.generation = running;
        let path = self.settings.config_path.clone();
        let to_save = new.clone();
        let saved = tokio::task::spawn_blocking(move || {
            let _lock = ConfigLock::acquire(&path)?;
            let on_disk = ConfigFile::load(&path).map_or(0, |c| c.generation);
            if on_disk > running {
                return Ok(None);
            }
            ConfigFile::save(&path, &to_save)?;
            Ok::<_, crate::error::Error>(Some(file_key(&path)))
        })
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
        let Some(key) = saved else {
            self.refresh_config().await;
            return Err(ApiError::conflict(
                "the configuration was reset elsewhere; sign in again",
            ));
        };
        *self.config.write().await = new;
        *lock(&self.disk_key) = key;
        Ok(())
    }

    pub async fn token_set(&self, key: &str, token: &str) -> Result<(), ApiError> {
        let store = Arc::clone(&self.tokens);
        let (key, token) = (key.to_string(), token.to_string());
        let result = tokio::task::spawn_blocking(move || store.set(&key, &token))
            .await
            .map_err(ApiError::internal)?;
        match result {
            Ok(()) => Ok(()),
            Err(ConfigError::Invalid(msg)) => Err(ApiError::bad_request(msg)),
            Err(err) => Err(ApiError::internal(err)),
        }
    }

    pub async fn token_delete(&self, key: &str) -> Result<(), ApiError> {
        let store = Arc::clone(&self.tokens);
        let key = key.to_string();
        tokio::task::spawn_blocking(move || store.delete(&key))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)
    }

    pub async fn client(&self, name: &str) -> Option<NodeClient> {
        self.clients.read().await.get(name).cloned()
    }

    pub async fn all_clients(&self) -> Vec<NodeClient> {
        let config = self.config.read().await;
        let clients = self.clients.read().await;
        config
            .nodes
            .iter()
            .filter_map(|n| clients.get(&n.name).cloned())
            .collect()
    }

    pub async fn put_client(&self, client: NodeClient, version: &str) {
        let name = client.name().to_string();
        self.clients.write().await.insert(name.clone(), client);
        lock(&self.probes).insert(
            name,
            Probe {
                at: Instant::now(),
                online: true,
                version: version.to_string(),
            },
        );
    }

    pub async fn drop_client(&self, name: &str) {
        self.clients.write().await.remove(name);
        lock(&self.probes).remove(name);
    }

    pub async fn node_statuses(&self) -> Vec<NodeStatus> {
        self.refresh_probes().await;
        let nodes: Vec<(String, String)> = {
            let config = self.config.read().await;
            config
                .nodes
                .iter()
                .map(|n| (n.name.clone(), n.url.clone()))
                .collect()
        };
        let probes = lock(&self.probes);
        nodes
            .into_iter()
            .map(|(name, url)| {
                let probe = probes.get(&name);
                NodeStatus {
                    online: probe.is_some_and(|p| p.online),
                    version: probe.map(|p| p.version.clone()).unwrap_or_default(),
                    name,
                    url,
                }
            })
            .collect()
    }

    // Probes older than the TTL are refreshed together; the gate stops concurrent callers re-probing.
    async fn refresh_probes(&self) {
        let _gate = self.probe_gate.lock().await;
        let stale: Vec<NodeClient> = {
            let clients = self.clients.read().await;
            let probes = lock(&self.probes);
            clients
                .values()
                .filter(|c| {
                    probes
                        .get(c.name())
                        .is_none_or(|p| p.at.elapsed() >= PROBE_TTL)
                })
                .cloned()
                .collect()
        };
        if stale.is_empty() {
            return;
        }
        let results = fan_out(
            &stale,
            DEFAULT_FAN_OUT_LIMIT,
            Some(PROBE_TIMEOUT),
            |c| async move { c.node_info().await },
        )
        .await;
        let mut probes = lock(&self.probes);
        for (name, result) in results {
            let probe = match result {
                Ok(info) => Probe {
                    at: Instant::now(),
                    online: true,
                    version: info.version,
                },
                Err(_) => Probe {
                    at: Instant::now(),
                    online: false,
                    version: String::new(),
                },
            };
            probes.insert(name, probe);
        }
    }
}
