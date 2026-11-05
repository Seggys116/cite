use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};

use arc_swap::{ArcSwap, ArcSwapOption};
use cite_core::atomic::{ensure_dir, read_limited, write_atomic};
use cite_edge::auth::{
    ApiToken, ApiTokens, AuthError, Credentials, SessionInfo, SessionStore, authenticate,
    dummy_verify,
};
use cite_edge::model::{CONFIG_VERSION, EdgeConfig};
use cite_edge::validate::validate_config;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Mutex;

use crate::config::ConnectorConfig;
use crate::{ConnectorError, Result};

const SESSION_IDLE_SECS: u64 = 1800;
const MAX_EDGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SMALL_FILE_BYTES: u64 = 4 * 1024 * 1024;
const AUDIT_MAX_BYTES: u64 = 4 * 1024 * 1024;
const AUDIT_PRUNE_EVERY_SECS: u64 = 3600;
const AUDIT_TAIL_MAX: usize = 1000;
const AUDIT_ACTOR_MAX: usize = 128;
const AUDIT_DETAIL_MAX: usize = 1024;
const SECRET_NAME_MAX: usize = 128;
const SECRET_VALUE_MAX: usize = 16 * 1024;
const MAX_SECRETS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct AuditState {
    size: u64,
    last_prune: u64,
}

// credentials.json and tokens.json carry a generation so a running connector can tell a CLI reset from its own writes.
#[derive(Serialize, Deserialize)]
struct Stamped<T> {
    #[serde(default)]
    generation: u64,
    #[serde(flatten)]
    value: T,
}

#[derive(Deserialize)]
struct GenerationOnly {
    #[serde(default)]
    generation: u64,
}

type FileKey = (i64, i64, u64, u64);

// None for a key means the file must be read before it is trusted again.
#[derive(Default)]
struct AuthDisk {
    creds_gen: u64,
    creds_key: Option<FileKey>,
    tokens_gen: u64,
    tokens_key: Option<FileKey>,
}

pub enum LoginOutcome {
    Accepted,
    Rejected,
    Blocked(u64),
}

struct Paths {
    edge: PathBuf,
    credentials: PathBuf,
    secrets: PathBuf,
    tokens: PathBuf,
    audit: PathBuf,
}

pub struct Store {
    paths: Paths,
    session_ttl_secs: u64,
    config: ArcSwap<EdgeConfig>,
    write_lock: Mutex<()>,
    creds: ArcSwapOption<Credentials>,
    login_lock: Mutex<()>,
    secrets: Mutex<HashMap<String, String>>,
    tokens: Mutex<ApiTokens>,
    sessions: StdMutex<SessionStore>,
    audit: Mutex<AuditState>,
    disk: StdMutex<AuthDisk>,
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn unix_to_rfc3339(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

fn internal(what: &str, err: impl std::fmt::Display) -> ConnectorError {
    ConnectorError::Internal(format!("{what}: {err}"))
}

fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// Control characters become spaces so a hostile value cannot forge extra log lines.
fn clip(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for ch in s.chars() {
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(if ch.is_control() { ' ' } else { ch });
    }
    out
}

async fn write_file(path: PathBuf, bytes: Vec<u8>, mode: u32) -> Result<()> {
    tokio::task::spawn_blocking(move || write_atomic(&path, &bytes, mode))
        .await
        .map_err(|e| internal("write task", e))?
        .map_err(|e| internal("write failed", e))
}

fn read_optional(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_limited(path, max)
            .map(Some)
            .map_err(|e| internal(&format!("cannot read {}", path.display()), e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(internal(&format!("cannot stat {}", path.display()), e)),
    }
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path, max: u64) -> Result<Option<T>> {
    match read_optional(path, max)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| internal(&format!("{} is invalid", path.display()), e)),
        None => Ok(None),
    }
}

fn file_key(path: &Path) -> Option<FileKey> {
    let meta = fs::symlink_metadata(path).ok()?;
    Some((meta.mtime(), meta.mtime_nsec(), meta.size(), meta.ino()))
}

fn disk_generation(path: &Path) -> u64 {
    load_json::<GenerationOnly>(path, MAX_SMALL_FILE_BYTES)
        .ok()
        .flatten()
        .map_or(0, |g| g.generation)
}

fn make_dir(path: &Path, mode: u32) -> Result<()> {
    ensure_dir(path, mode).map_err(|e| internal(&format!("cannot prepare {}", path.display()), e))
}

fn rotated_path(path: &Path) -> PathBuf {
    path.with_extension("jsonl.1")
}

fn entry_unix(entry: &AuditEntry) -> Option<i64> {
    OffsetDateTime::parse(&entry.at, &Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

// Rewrites the log without entries older than the retention; returns the new size.
fn prune_file(path: &Path, now: u64, audit_days: u32) -> io::Result<u64> {
    let bytes = match read_limited(path, MAX_SMALL_FILE_BYTES * 2) {
        Ok(b) => b,
        Err(cite_core::Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(io::Error::other(e.to_string())),
    };
    let cutoff = i64::try_from(now)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::from(audit_days) * 86_400);
    let mut kept = Vec::with_capacity(bytes.len());
    let mut dropped = false;
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let fresh = serde_json::from_slice::<AuditEntry>(line)
            .ok()
            .and_then(|e| entry_unix(&e))
            .is_none_or(|t| t >= cutoff);
        if fresh {
            kept.extend_from_slice(line);
            kept.push(b'\n');
        } else {
            dropped = true;
        }
    }
    if dropped {
        write_atomic(path, &kept, 0o600).map_err(|e| io::Error::other(e.to_string()))?;
    }
    Ok(kept.len() as u64)
}

fn append_audit(
    path: &Path,
    line: &[u8],
    mut state: AuditState,
    now: u64,
    audit_days: u32,
) -> io::Result<AuditState> {
    // One previous generation is kept; anything older is dropped on the next rotation.
    if state.size + line.len() as u64 > AUDIT_MAX_BYTES {
        match fs::rename(path, rotated_path(path)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        state.size = 0;
    }
    if now.saturating_sub(state.last_prune) >= AUDIT_PRUNE_EVERY_SECS {
        state.size = prune_file(path, now, audit_days)?;
        prune_file(&rotated_path(path), now, audit_days)?;
        state.last_prune = now;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    file.write_all(line)?;
    state.size += line.len() as u64;
    Ok(state)
}

fn read_tail(path: &Path, limit: usize) -> Vec<AuditEntry> {
    let mut out = Vec::new();
    for file in [path.to_path_buf(), rotated_path(path)] {
        let Ok(bytes) = read_limited(&file, AUDIT_MAX_BYTES * 2) else {
            continue;
        };
        for line in bytes.split(|b| *b == b'\n').rev() {
            if let Ok(entry) = serde_json::from_slice::<AuditEntry>(line) {
                out.push(entry);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

impl Store {
    pub async fn open(cfg: &ConnectorConfig) -> Result<Arc<Store>> {
        let cfg = cfg.clone();
        let store = tokio::task::spawn_blocking(move || Self::open_blocking(&cfg))
            .await
            .map_err(|e| internal("open task", e))??;
        Ok(Arc::new(store))
    }

    fn open_blocking(cfg: &ConnectorConfig) -> Result<Store> {
        // The data directory is traversable but not listable so HAProxy can reach its subdirectory.
        make_dir(&cfg.data_dir, 0o711)?;
        for dir in [&cfg.haproxy_dir, &cfg.maps_dir, &cfg.pages_dir] {
            make_dir(dir, 0o755)?;
        }
        make_dir(&cfg.tls_dir, 0o700)?;

        let paths = Paths {
            edge: cfg.data_dir.join("edge.json"),
            credentials: cfg.data_dir.join("credentials.json"),
            secrets: cfg.data_dir.join("secrets.json"),
            tokens: cfg.data_dir.join("tokens.json"),
            audit: cfg.data_dir.join("audit.jsonl"),
        };

        let config = match load_json::<EdgeConfig>(&paths.edge, MAX_EDGE_BYTES)? {
            Some(c) => {
                if c.version != CONFIG_VERSION {
                    return Err(ConnectorError::Internal(format!(
                        "edge.json has version {}, expected {CONFIG_VERSION}",
                        c.version
                    )));
                }
                validate_config(&c).map_err(|e| internal("edge.json failed validation", e))?;
                c
            }
            None => {
                let c = EdgeConfig {
                    version: CONFIG_VERSION,
                    ..EdgeConfig::default()
                };
                let bytes = serde_json::to_vec_pretty(&c)?;
                write_atomic(&paths.edge, &bytes, 0o600)
                    .map_err(|e| internal("cannot write edge.json", e))?;
                c
            }
        };
        let creds = load_json::<Stamped<Credentials>>(&paths.credentials, MAX_SMALL_FILE_BYTES)?;
        let secrets = load_json::<HashMap<String, String>>(&paths.secrets, MAX_SMALL_FILE_BYTES)?
            .unwrap_or_default();
        let tokens = load_json::<Stamped<ApiTokens>>(&paths.tokens, MAX_SMALL_FILE_BYTES)?;
        let disk = AuthDisk {
            creds_gen: creds.as_ref().map_or(0, |c| c.generation),
            creds_key: None,
            tokens_gen: tokens.as_ref().map_or(0, |t| t.generation),
            tokens_key: None,
        };
        let audit_size = fs::symlink_metadata(&paths.audit).map_or(0, |m| m.len());

        Ok(Store {
            session_ttl_secs: cfg.session_ttl_secs,
            sessions: StdMutex::new(SessionStore::new(cfg.session_ttl_secs, SESSION_IDLE_SECS)),
            paths,
            config: ArcSwap::from_pointee(config),
            write_lock: Mutex::new(()),
            creds: ArcSwapOption::from(creds.map(|c| Arc::new(c.value))),
            login_lock: Mutex::new(()),
            secrets: Mutex::new(secrets),
            tokens: Mutex::new(tokens.map(|t| t.value).unwrap_or_default()),
            audit: Mutex::new(AuditState {
                size: audit_size,
                last_prune: 0,
            }),
            disk: StdMutex::new(disk),
        })
    }

    pub fn config(&self) -> Arc<EdgeConfig> {
        self.config.load_full()
    }

    pub async fn update<T>(
        &self,
        actor: &str,
        action: &str,
        f: impl FnOnce(&mut EdgeConfig) -> Result<T>,
    ) -> Result<T> {
        self.update_detailed(actor, action, "", f).await
    }

    pub async fn update_detailed<T>(
        &self,
        actor: &str,
        action: &str,
        detail: &str,
        f: impl FnOnce(&mut EdgeConfig) -> Result<T>,
    ) -> Result<T> {
        // Readers only ever see a config that validated and reached disk.
        let _guard = self.write_lock.lock().await;
        let current = self.config.load_full();
        let mut next = (*current).clone();
        let out = f(&mut next)?;
        validate_config(&next)?;
        let bytes = serde_json::to_vec_pretty(&next)?;
        write_file(self.paths.edge.clone(), bytes, 0o600).await?;
        self.config.store(Arc::new(next));
        self.audit(actor, action, detail).await;
        Ok(out)
    }

    pub async fn audit(&self, actor: &str, action: &str, detail: &str) {
        let entry = AuditEntry {
            at: now_rfc3339(),
            actor: clip(actor, AUDIT_ACTOR_MAX),
            action: clip(action, AUDIT_ACTOR_MAX),
            detail: clip(detail, AUDIT_DETAIL_MAX),
        };
        let mut line = match serde_json::to_vec(&entry) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "audit entry could not be serialised");
                return;
            }
        };
        line.push(b'\n');
        let audit_days = self.config.load().settings.retention.audit_days;
        let mut state = self.audit.lock().await;
        let path = self.paths.audit.clone();
        let snapshot = *state;
        let now = now_unix();
        let result = tokio::task::spawn_blocking(move || {
            append_audit(&path, &line, snapshot, now, audit_days)
        })
        .await;
        // An audit failure must not fail the action it records, so it is only logged.
        match result {
            Ok(Ok(next)) => *state = next,
            Ok(Err(e)) => tracing::error!(error = %e, "audit write failed"),
            Err(e) => tracing::error!(error = %e, "audit task failed"),
        }
    }

    pub async fn audit_tail(&self, limit: usize) -> Vec<AuditEntry> {
        let limit = limit.clamp(1, AUDIT_TAIL_MAX);
        let _state = self.audit.lock().await;
        let path = self.paths.audit.clone();
        tokio::task::spawn_blocking(move || read_tail(&path, limit))
            .await
            .unwrap_or_default()
    }

    pub async fn put_secret(&self, name: &str, value: &str) -> Result<()> {
        let name_ok = !name.is_empty()
            && name.len() <= SECRET_NAME_MAX
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
        if !name_ok {
            return Err(ConnectorError::BadRequest("invalid secret name".into()));
        }
        if value.len() > SECRET_VALUE_MAX {
            return Err(ConnectorError::BadRequest(
                "secret value is too large".into(),
            ));
        }
        let mut map = self.secrets.lock().await;
        if !map.contains_key(name) && map.len() >= MAX_SECRETS {
            return Err(ConnectorError::BadRequest("too many secrets".into()));
        }
        let mut next = map.clone();
        next.insert(name.to_string(), value.to_string());
        let bytes = serde_json::to_vec(&next)?;
        write_file(self.paths.secrets.clone(), bytes, 0o600).await?;
        *map = next;
        Ok(())
    }

    pub async fn get_secret(&self, name: &str) -> Option<String> {
        self.secrets.lock().await.get(name).cloned()
    }

    pub async fn delete_secret(&self, name: &str) {
        let mut map = self.secrets.lock().await;
        if !map.contains_key(name) {
            return;
        }
        let mut next = map.clone();
        next.remove(name);
        let written = match serde_json::to_vec(&next) {
            Ok(bytes) => write_file(self.paths.secrets.clone(), bytes, 0o600).await,
            Err(e) => Err(ConnectorError::from(e)),
        };
        match written {
            Ok(()) => *map = next,
            Err(e) => tracing::error!(error = %e, "secret removal could not be persisted"),
        }
    }

    pub fn credentials(&self) -> Option<Credentials> {
        self.refresh_creds();
        self.creds.load_full().map(|c| (*c).clone())
    }

    fn creds_generation(&self) -> u64 {
        lock(&self.disk).creds_gen
    }

    // A newer generation on disk means a CLI reset: adopt it and drop every session.
    fn refresh_creds(&self) {
        let mut disk = lock(&self.disk);
        let Some(key) = file_key(&self.paths.credentials) else {
            return;
        };
        if disk.creds_key == Some(key) {
            return;
        }
        disk.creds_key = Some(key);
        match load_json::<Stamped<Credentials>>(&self.paths.credentials, MAX_SMALL_FILE_BYTES) {
            Ok(Some(next)) if next.generation > disk.creds_gen => {
                disk.creds_gen = next.generation;
                self.creds.store(Some(Arc::new(next.value)));
                self.clear_sessions();
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "credentials.json could not be reloaded"),
        }
    }

    fn refresh_tokens(&self, tokens: &mut ApiTokens) {
        let mut disk = lock(&self.disk);
        let Some(key) = file_key(&self.paths.tokens) else {
            return;
        };
        if disk.tokens_key == Some(key) {
            return;
        }
        disk.tokens_key = Some(key);
        match load_json::<Stamped<ApiTokens>>(&self.paths.tokens, MAX_SMALL_FILE_BYTES) {
            Ok(Some(next)) if next.generation > disk.tokens_gen => {
                disk.tokens_gen = next.generation;
                *tokens = next.value;
                self.clear_sessions();
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "tokens.json could not be reloaded"),
        }
    }

    pub async fn set_credentials(&self, c: Credentials) -> Result<()> {
        let _guard = self.login_lock.lock().await;
        self.refresh_creds();
        self.persist_credentials(c).await
    }

    async fn persist_credentials(&self, c: Credentials) -> Result<()> {
        let stamped = Stamped {
            generation: self.creds_generation(),
            value: c,
        };
        let bytes = serde_json::to_vec_pretty(&stamped)?;
        write_file(self.paths.credentials.clone(), bytes, 0o600).await?;
        lock(&self.disk).creds_key = None;
        self.creds.store(Some(Arc::new(stamped.value)));
        Ok(())
    }

    // Replaces credentials and empties the token list under a generation newer than any seen, so running connectors adopt it.
    pub async fn reset_credentials(&self, c: Credentials) -> Result<()> {
        let _login = self.login_lock.lock().await;
        let mut tokens = self.tokens.lock().await;
        let generation = {
            let disk = lock(&self.disk);
            disk.creds_gen
                .max(disk.tokens_gen)
                .max(disk_generation(&self.paths.credentials))
                .max(disk_generation(&self.paths.tokens))
                .saturating_add(1)
        };
        let empty = Stamped {
            generation,
            value: ApiTokens::new(),
        };
        write_file(
            self.paths.tokens.clone(),
            serde_json::to_vec_pretty(&empty)?,
            0o600,
        )
        .await?;
        let creds = Stamped {
            generation,
            value: c,
        };
        write_file(
            self.paths.credentials.clone(),
            serde_json::to_vec_pretty(&creds)?,
            0o600,
        )
        .await?;
        {
            let mut disk = lock(&self.disk);
            disk.creds_gen = generation;
            disk.tokens_gen = generation;
            disk.creds_key = None;
            disk.tokens_key = None;
        }
        *tokens = empty.value;
        self.creds.store(Some(Arc::new(creds.value)));
        self.clear_sessions();
        Ok(())
    }

    // Logins are serialised so two requests cannot both spend the same one-time code.
    pub async fn verify_login(
        &self,
        username: &str,
        password: &str,
        totp: &str,
        now: u64,
    ) -> Result<bool> {
        let _guard = self.login_lock.lock().await;
        self.verify_locked(username, password, totp, now).await
    }

    // The gate runs inside the serialised section and a failure is recorded before the next attempt is admitted.
    pub async fn verify_login_gated(
        &self,
        username: &str,
        password: &str,
        totp: &str,
        gate: impl FnOnce(u64) -> std::result::Result<(), u64>,
        on_failure: impl FnOnce(u64),
    ) -> Result<LoginOutcome> {
        let _guard = self.login_lock.lock().await;
        let now = now_unix();
        if let Err(retry) = gate(now) {
            return Ok(LoginOutcome::Blocked(retry));
        }
        if self.verify_locked(username, password, totp, now).await? {
            Ok(LoginOutcome::Accepted)
        } else {
            on_failure(now);
            Ok(LoginOutcome::Rejected)
        }
    }

    async fn verify_locked(
        &self,
        username: &str,
        password: &str,
        totp: &str,
        now: u64,
    ) -> Result<bool> {
        let current = self.credentials();
        let generation = self.creds_generation();
        let (user, pass, code) = (username.to_string(), password.to_string(), totp.to_string());
        let outcome = tokio::task::spawn_blocking(move || match current {
            Some(mut c) => authenticate(&mut c, &user, &pass, &code, now)
                .is_ok()
                .then_some(c),
            None => {
                dummy_verify();
                None
            }
        })
        .await
        .map_err(|e| internal("login task", e))?;
        // A reset that landed during the hash was not checked against, so the result is void.
        self.refresh_creds();
        if self.creds_generation() != generation {
            return Ok(false);
        }
        match outcome {
            Some(updated) => {
                self.persist_credentials(updated).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn create_session(&self, username: &str, now: u64) -> Result<(String, u64)> {
        lock(&self.sessions)
            .create(username, now)
            .map_err(|_| ConnectorError::Internal("session creation failed".into()))
    }

    pub fn validate_session(&self, token: &str, now: u64) -> Option<SessionInfo> {
        self.refresh_creds();
        lock(&self.sessions).validate(token, now)
    }

    pub fn revoke_session(&self, token: &str) {
        lock(&self.sessions).revoke(token);
    }

    pub fn clear_sessions(&self) {
        *lock(&self.sessions) = SessionStore::new(self.session_ttl_secs, SESSION_IDLE_SECS);
    }

    async fn persist_tokens(&self, tokens: &ApiTokens) -> Result<()> {
        let stamped = Stamped {
            generation: lock(&self.disk).tokens_gen,
            value: tokens,
        };
        let bytes = serde_json::to_vec_pretty(&stamped)?;
        write_file(self.paths.tokens.clone(), bytes, 0o600).await?;
        lock(&self.disk).tokens_key = None;
        Ok(())
    }

    pub async fn create_api_token(&self, name: &str) -> Result<(ApiToken, String)> {
        // Changes go to a copy that is persisted first, so a failed write keeps the live set intact.
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        let mut next = tokens.clone();
        let created = next.create(name).map_err(|e| match e {
            AuthError::Weak(msg) => ConnectorError::Conflict(msg.to_string()),
            _ => ConnectorError::Internal("token generation failed".into()),
        })?;
        self.persist_tokens(&next).await?;
        *tokens = next;
        Ok(created)
    }

    pub async fn verify_api_token(&self, token: &str) -> Option<ApiToken> {
        // last_used_at stays in memory and reaches disk with the next token change.
        let now = now_rfc3339();
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        tokens.verify(token, &now).cloned()
    }

    pub async fn list_api_tokens(&self) -> Vec<ApiToken> {
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        tokens.list().to_vec()
    }

    pub async fn revoke_api_token(&self, id: &str) -> Result<bool> {
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        let mut next = tokens.clone();
        if !next.revoke(id) {
            return Ok(false);
        }
        self.persist_tokens(&next).await?;
        *tokens = next;
        Ok(true)
    }

    pub async fn clear_api_tokens(&self) -> Result<()> {
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        let empty = ApiTokens::new();
        self.persist_tokens(&empty).await?;
        *tokens = empty;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub fn test_config(dir: &Path) -> ConnectorConfig {
        let data = dir.display().to_string();
        let env: HashMap<String, String> = [
            ("CITE_CONNECTOR_ALLOW", "127.0.0.1"),
            ("CITE_CONNECTOR_DATA", data.as_str()),
            ("CITE_CONNECTOR_TLS", "false"),
            ("CITE_HAPROXY_VALIDATE", "false"),
            ("CITE_HAPROXY_RUNTIME", "127.0.0.1:1"),
            ("CITE_HAPROXY_MASTER", "127.0.0.1:1"),
            ("CITE_CONNECTOR_LISTEN", "127.0.0.1:0"),
            ("CITE_NODE_NAME", "test-node"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        ConnectorConfig::from_env_map(&env).expect("test config")
    }
}

#[cfg(test)]
mod tests {
    use super::testing::test_config;
    use super::*;
    use cite_edge::auth::hash_password;
    use cite_edge::model::{MaintenancePage, Retention};
    use cite_edge::totp;
    use std::os::unix::fs::PermissionsExt;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const PASSWORD: &str = "correct horse battery";
    const NOW: u64 = 1_700_000_000;

    async fn open_temp() -> (tempfile::TempDir, Arc<Store>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&test_config(dir.path())).await.expect("open");
        (dir, store)
    }

    fn page(id: &str) -> MaintenancePage {
        MaintenancePage {
            id: id.into(),
            name: "Down".into(),
            html: "<p>down</p>".into(),
            status: 503,
        }
    }

    fn creds() -> Credentials {
        Credentials {
            username: "admin".into(),
            password_hash: hash_password(PASSWORD).expect("hash"),
            totp_secret: SECRET.into(),
            totp_last_step: 0,
        }
    }

    #[tokio::test]
    async fn open_creates_layout_with_tight_permissions() {
        let (dir, store) = open_temp().await;
        let mode = |p: &Path| fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("edge.json")), 0o600);
        assert_eq!(mode(&dir.path().join("tls")), 0o700);
        assert_eq!(mode(&dir.path().join("haproxy")), 0o755);
        assert!(dir.path().join("haproxy/maps").is_dir());
        assert!(dir.path().join("haproxy/pages").is_dir());
        assert_eq!(store.config().version, CONFIG_VERSION);
        assert!(store.credentials().is_none());
    }

    #[tokio::test]
    async fn update_persists_and_survives_reopen() {
        let (dir, store) = open_temp().await;
        store
            .update("tester", "page.create", |c| {
                c.pages.push(page("down"));
                Ok(())
            })
            .await
            .expect("update");
        assert_eq!(store.config().pages.len(), 1);
        let reopened = Store::open(&test_config(dir.path())).await.expect("reopen");
        assert_eq!(reopened.config().pages[0].id, "down");
    }

    #[tokio::test]
    async fn failing_closure_changes_nothing() {
        let (_dir, store) = open_temp().await;
        let result: Result<()> = store
            .update("tester", "page.create", |c| {
                c.pages.push(page("down"));
                Err(ConnectorError::Conflict("nope".into()))
            })
            .await;
        assert!(matches!(result, Err(ConnectorError::Conflict(_))));
        assert!(store.config().pages.is_empty());
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_and_not_persisted() {
        let (dir, store) = open_temp().await;
        let result = store
            .update("tester", "page.create", |c| {
                c.pages.push(page("Bad Id"));
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(ConnectorError::BadRequest(_))));
        assert!(store.config().pages.is_empty());
        let reopened = Store::open(&test_config(dir.path())).await.expect("reopen");
        assert!(reopened.config().pages.is_empty());
    }

    #[tokio::test]
    async fn corrupt_edge_json_refuses_to_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        drop(Store::open(&cfg).await.expect("first open"));
        fs::write(dir.path().join("edge.json"), b"{not json").expect("write");
        assert!(Store::open(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn audit_entries_are_recorded_newest_first() {
        let (_dir, store) = open_temp().await;
        store.audit("alice", "one", "first").await;
        store.audit("bob", "two", "line\nbreak").await;
        let tail = store.audit_tail(10).await;
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].action, "two");
        assert_eq!(tail[0].detail, "line break");
        assert_eq!(tail[1].actor, "alice");
        assert_eq!(store.audit_tail(1).await.len(), 1);
    }

    #[tokio::test]
    async fn config_update_writes_an_audit_entry() {
        let (_dir, store) = open_temp().await;
        store
            .update_detailed("tester", "page.create", "id=down", |c| {
                c.pages.push(page("down"));
                Ok(())
            })
            .await
            .expect("update");
        let tail = store.audit_tail(5).await;
        assert_eq!(tail[0].action, "page.create");
        assert_eq!(tail[0].detail, "id=down");
    }

    #[tokio::test]
    async fn audit_file_rotates_by_size() {
        let (dir, store) = open_temp().await;
        let big = "x".repeat(AUDIT_DETAIL_MAX);
        for _ in 0..(AUDIT_MAX_BYTES as usize / AUDIT_DETAIL_MAX + 8) {
            store.audit("a", "fill", &big).await;
        }
        assert!(dir.path().join("audit.jsonl.1").exists());
        let size = fs::metadata(dir.path().join("audit.jsonl"))
            .expect("meta")
            .len();
        assert!(size < AUDIT_MAX_BYTES);
        assert!(!store.audit_tail(5).await.is_empty());
    }

    #[test]
    fn prune_drops_entries_older_than_retention() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let old = AuditEntry {
            at: unix_to_rfc3339(NOW - 40 * 86_400),
            actor: "a".into(),
            action: "old".into(),
            detail: String::new(),
        };
        let fresh = AuditEntry {
            at: unix_to_rfc3339(NOW - 86_400),
            action: "fresh".into(),
            ..old.clone()
        };
        let mut body = serde_json::to_vec(&old).expect("json");
        body.push(b'\n');
        body.extend(serde_json::to_vec(&fresh).expect("json"));
        body.push(b'\n');
        fs::write(&path, body).expect("write");
        let size = prune_file(&path, NOW, 30).expect("prune");
        let kept = read_tail(&path, 10);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].action, "fresh");
        assert_eq!(size, fs::metadata(&path).expect("meta").len());
    }

    #[tokio::test]
    async fn secrets_round_trip_with_private_permissions() {
        let (dir, store) = open_temp().await;
        store.put_secret("gh-blog", "tok").await.expect("put");
        assert_eq!(store.get_secret("gh-blog").await.as_deref(), Some("tok"));
        let mode = fs::metadata(dir.path().join("secrets.json"))
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let reopened = Store::open(&test_config(dir.path())).await.expect("reopen");
        assert_eq!(reopened.get_secret("gh-blog").await.as_deref(), Some("tok"));
        reopened.delete_secret("gh-blog").await;
        assert_eq!(reopened.get_secret("gh-blog").await, None);
        assert!(store.put_secret("bad name", "x").await.is_err());
    }

    #[tokio::test]
    async fn verify_login_accepts_once_and_rejects_replay() {
        let (dir, store) = open_temp().await;
        store.set_credentials(creds()).await.expect("set");
        let code = totp::code_at(SECRET, NOW).expect("code");
        assert!(
            store
                .verify_login("admin", PASSWORD, &code, NOW)
                .await
                .expect("ok")
        );
        assert!(
            !store
                .verify_login("admin", PASSWORD, &code, NOW)
                .await
                .expect("ok")
        );
        let reopened = Store::open(&test_config(dir.path())).await.expect("reopen");
        let step = reopened.credentials().expect("creds").totp_last_step;
        assert_eq!(step, NOW / 30);
    }

    #[tokio::test]
    async fn verify_login_without_credentials_fails_closed() {
        let (_dir, store) = open_temp().await;
        let code = totp::code_at(SECRET, NOW).expect("code");
        assert!(
            !store
                .verify_login("admin", PASSWORD, &code, NOW)
                .await
                .expect("ok")
        );
    }

    #[tokio::test]
    async fn api_tokens_persist_hashes_only_and_can_be_cleared() {
        let (dir, store) = open_temp().await;
        let (meta, plain) = store.create_api_token("ci").await.expect("create");
        let on_disk = fs::read_to_string(dir.path().join("tokens.json")).expect("read");
        assert!(!on_disk.contains(&plain));
        assert!(on_disk.contains(&meta.hash));
        assert!(store.verify_api_token(&plain).await.is_some());
        assert!(store.verify_api_token("cite_wrong").await.is_none());
        let reopened = Store::open(&test_config(dir.path())).await.expect("reopen");
        assert!(reopened.verify_api_token(&plain).await.is_some());
        reopened.clear_api_tokens().await.expect("clear");
        assert!(reopened.verify_api_token(&plain).await.is_none());
        assert!(!reopened.revoke_api_token("nothing").await.expect("revoke"));
    }

    #[tokio::test]
    async fn sessions_validate_and_can_be_revoked_or_cleared() {
        let (_dir, store) = open_temp().await;
        let (token, _) = store.create_session("admin", NOW).expect("session");
        assert!(store.validate_session(&token, NOW + 1).is_some());
        store.revoke_session(&token);
        assert!(store.validate_session(&token, NOW + 2).is_none());
        let (again, _) = store.create_session("admin", NOW).expect("session");
        store.clear_sessions();
        assert!(store.validate_session(&again, NOW + 1).is_none());
    }

    #[tokio::test]
    async fn settings_update_is_validated() {
        let (_dir, store) = open_temp().await;
        let result = store
            .update("tester", "settings.update", |c| {
                c.settings.retention = Retention {
                    audit_days: 0,
                    ..c.settings.retention.clone()
                };
                Ok(())
            })
            .await;
        assert!(result.is_err());
    }
}
