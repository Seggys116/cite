use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cite_client::{
    ConfigError, ConfigFile, DEFAULT_FAN_OUT_LIMIT, DashboardConfig, NodeClient, TokenStore,
    fan_out,
};
use cite_edge::auth::SessionStore;
use cite_edge::ratelimit::LoginLimiter;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::error::ApiError;
use crate::settings::Settings;

pub const PROBE_TTL: Duration = Duration::from_secs(5);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

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
    // Held across config mutations and logins so read-modify-write cycles never interleave.
    pub write_gate: tokio::sync::Mutex<()>,
    tokens: Arc<dyn TokenStore>,
    config: RwLock<DashboardConfig>,
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
        Arc::new(Self {
            settings,
            sessions: Mutex::new(sessions),
            limiter: Mutex::new(LoginLimiter::new()),
            pending: Mutex::new(None),
            write_gate: tokio::sync::Mutex::new(()),
            tokens,
            config: RwLock::new(config),
            clients: RwLock::new(clients),
            probes: Mutex::new(HashMap::new()),
            probe_gate: tokio::sync::Mutex::new(()),
        })
    }

    pub async fn config_snapshot(&self) -> DashboardConfig {
        self.config.read().await.clone()
    }

    pub async fn needs_onboarding(&self) -> bool {
        self.config.read().await.admin.is_none()
    }

    // Callers hold `write_gate`; the file is written first so memory never runs ahead of disk.
    pub async fn commit_config(&self, new: DashboardConfig) -> Result<(), ApiError> {
        let path = self.settings.config_path.clone();
        let to_save = new.clone();
        tokio::task::spawn_blocking(move || ConfigFile::save(&path, &to_save))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?;
        *self.config.write().await = new;
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
