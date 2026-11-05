use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};

use arc_swap::{ArcSwap, ArcSwapOption};
use cite_core::atomic::{ensure_dir, write_atomic_in};
use cite_core::confined::{FileKey, FileName, TrustedDir};
use cite_edge::auth::{
    ApiToken, ApiTokens, AuthError, Credentials, SessionInfo, SessionStore, TokenLookup,
    authenticate, dummy_verify,
};
use cite_edge::model::{CONFIG_VERSION, EdgeConfig};
use cite_edge::validate::validate_config;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

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
const TOKEN_CHECK_CONCURRENCY: usize = 2;

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

#[derive(Clone)]
struct AuditFiles {
    current: FileName,
    rotated: FileName,
}

// Every file lives directly in the data directory, so each is a handle plus one validated name.
struct Paths {
    dir: Arc<TrustedDir>,
    auth_lock: FileName,
    edge: FileName,
    credentials: FileName,
    secrets: FileName,
    tokens: FileName,
    audit: AuditFiles,
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
    // Bounds concurrent token Argon2 runs so a burst of guesses cannot exhaust memory.
    token_permits: Arc<Semaphore>,
    // One password hash at a time; the permit lives in the blocking job so a dropped login cannot start a second.
    login_permits: Arc<Semaphore>,
    sessions: StdMutex<SessionStore>,
    audit: Mutex<AuditState>,
    disk: StdMutex<AuthDisk>,
}

pub enum TokenOutcome {
    Accepted(ApiToken),
    Rejected,
    // A well-formed token with a known id but the wrong secret, the only case worth counting against a client.
    WrongSecret,
}

// The permit moves into the blocking job, so it is held until the work ends even if the request future is dropped.
fn spawn_holding<T: Send + 'static>(
    permit: OwnedSemaphorePermit,
    work: impl FnOnce() -> T + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    tokio::task::spawn_blocking(move || {
        let out = work();
        drop(permit);
        out
    })
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
fn superseded(what: &str) -> ConnectorError {
    ConnectorError::Conflict(format!(
        "{what} were reset while this change was in flight; retry"
    ))
}

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

fn fixed_name(name: &str) -> Result<FileName> {
    FileName::new(name).map_err(|e| internal("invalid store file name", e))
}

async fn write_file(dir: Arc<TrustedDir>, name: FileName, bytes: Vec<u8>, mode: u32) -> Result<()> {
    tokio::task::spawn_blocking(move || write_atomic_in(&dir, &name, &bytes, mode))
        .await
        .map_err(|e| internal("write task", e))?
        .map_err(|e| internal("write failed", e))
}

fn read_optional(dir: &TrustedDir, name: &FileName, max: u64) -> Result<Option<Vec<u8>>> {
    match dir.read_limited(name, max) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(cite_core::Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(internal(&format!("cannot read {name}"), e)),
    }
}

fn load_json<T: serde::de::DeserializeOwned>(
    dir: &TrustedDir,
    name: &FileName,
    max: u64,
) -> Result<Option<T>> {
    match read_optional(dir, name, max)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| internal(&format!("{name} is invalid"), e)),
        None => Ok(None),
    }
}

fn disk_generation(dir: &TrustedDir, name: &FileName) -> u64 {
    load_json::<GenerationOnly>(dir, name, MAX_SMALL_FILE_BYTES)
        .ok()
        .flatten()
        .map_or(0, |g| g.generation)
}

// Held across a generation check and the rename after it, in server and CLI alike, so a reset is never overwritten by older state.
fn lock_auth(dir: &TrustedDir, name: &FileName) -> io::Result<std::fs::File> {
    dir.lock_file(name, 0o600)
}

// Writes only while the file still carries the generation the caller started from.
async fn guarded_write(
    dir: Arc<TrustedDir>,
    lock: FileName,
    target: FileName,
    seen: u64,
    bytes: Vec<u8>,
) -> Result<bool> {
    tokio::task::spawn_blocking(move || -> Result<bool> {
        let _held = lock_auth(&dir, &lock).map_err(|e| internal("auth lock failed", e))?;
        if disk_generation(&dir, &target) > seen {
            return Ok(false);
        }
        write_atomic_in(&dir, &target, &bytes, 0o600).map_err(|e| internal("write failed", e))?;
        Ok(true)
    })
    .await
    .map_err(|e| internal("write task", e))?
}

fn make_dir(path: &Path, mode: u32) -> Result<()> {
    ensure_dir(path, mode).map_err(|e| internal(&format!("cannot prepare {}", path.display()), e))
}

fn entry_unix(entry: &AuditEntry) -> Option<i64> {
    OffsetDateTime::parse(&entry.at, &Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

// Rewrites the log without entries older than the retention; returns the new size.
fn prune_file(dir: &TrustedDir, name: &FileName, now: u64, audit_days: u32) -> io::Result<u64> {
    let bytes = match dir.read_limited(name, MAX_SMALL_FILE_BYTES * 2) {
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
        write_atomic_in(dir, name, &kept, 0o600).map_err(|e| io::Error::other(e.to_string()))?;
    }
    Ok(kept.len() as u64)
}

fn append_audit(
    dir: &TrustedDir,
    files: &AuditFiles,
    line: &[u8],
    mut state: AuditState,
    now: u64,
    audit_days: u32,
) -> io::Result<AuditState> {
    // One previous generation is kept; anything older is dropped on the next rotation.
    if state.size + line.len() as u64 > AUDIT_MAX_BYTES {
        match dir.rename(&files.current, &files.rotated) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        state.size = 0;
    }
    if now.saturating_sub(state.last_prune) >= AUDIT_PRUNE_EVERY_SECS {
        state.size = prune_file(dir, &files.current, now, audit_days)?;
        prune_file(dir, &files.rotated, now, audit_days)?;
        state.last_prune = now;
    }
    dir.append(&files.current, line, 0o600)?;
    state.size += line.len() as u64;
    Ok(state)
}

fn read_tail(dir: &TrustedDir, files: &AuditFiles, limit: usize) -> Vec<AuditEntry> {
    let mut out = Vec::new();
    for file in [&files.current, &files.rotated] {
        let Ok(bytes) = dir.read_limited(file, AUDIT_MAX_BYTES * 2) else {
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

        let dir = TrustedDir::open(&cfg.data_dir)
            .map_err(|e| internal(&format!("cannot open {}", cfg.data_dir.display()), e))?;
        let paths = Paths {
            dir: Arc::new(dir),
            auth_lock: fixed_name("auth.lock")?,
            edge: fixed_name("edge.json")?,
            credentials: fixed_name("credentials.json")?,
            secrets: fixed_name("secrets.json")?,
            tokens: fixed_name("tokens.json")?,
            audit: AuditFiles {
                current: fixed_name("audit.jsonl")?,
                rotated: fixed_name("audit.jsonl.1")?,
            },
        };

        let config = match load_json::<EdgeConfig>(&paths.dir, &paths.edge, MAX_EDGE_BYTES)? {
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
                write_atomic_in(&paths.dir, &paths.edge, &bytes, 0o600)
                    .map_err(|e| internal("cannot write edge.json", e))?;
                c
            }
        };
        let creds = load_json::<Stamped<Credentials>>(
            &paths.dir,
            &paths.credentials,
            MAX_SMALL_FILE_BYTES,
        )?;
        let secrets =
            load_json::<HashMap<String, String>>(&paths.dir, &paths.secrets, MAX_SMALL_FILE_BYTES)?
                .unwrap_or_default();
        let tokens =
            load_json::<Stamped<ApiTokens>>(&paths.dir, &paths.tokens, MAX_SMALL_FILE_BYTES)?;
        let disk = AuthDisk {
            creds_gen: creds.as_ref().map_or(0, |c| c.generation),
            creds_key: None,
            tokens_gen: tokens.as_ref().map_or(0, |t| t.generation),
            tokens_key: None,
        };
        let audit_size = paths.dir.len(&paths.audit.current).unwrap_or(0);

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
            token_permits: Arc::new(Semaphore::new(TOKEN_CHECK_CONCURRENCY)),
            login_permits: Arc::new(Semaphore::new(1)),
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
        write_file(
            self.paths.dir.clone(),
            self.paths.edge.clone(),
            bytes,
            0o600,
        )
        .await?;
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
        let dir = self.paths.dir.clone();
        let files = self.paths.audit.clone();
        let snapshot = *state;
        let now = now_unix();
        let result = tokio::task::spawn_blocking(move || {
            append_audit(&dir, &files, &line, snapshot, now, audit_days)
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
        let dir = self.paths.dir.clone();
        let files = self.paths.audit.clone();
        tokio::task::spawn_blocking(move || read_tail(&dir, &files, limit))
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
        write_file(
            self.paths.dir.clone(),
            self.paths.secrets.clone(),
            bytes,
            0o600,
        )
        .await?;
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
            Ok(bytes) => {
                write_file(
                    self.paths.dir.clone(),
                    self.paths.secrets.clone(),
                    bytes,
                    0o600,
                )
                .await
            }
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
        let Some(key) = self.paths.dir.key(&self.paths.credentials) else {
            return;
        };
        if disk.creds_key == Some(key) {
            return;
        }
        disk.creds_key = Some(key);
        match load_json::<Stamped<Credentials>>(
            &self.paths.dir,
            &self.paths.credentials,
            MAX_SMALL_FILE_BYTES,
        ) {
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
        let Some(key) = self.paths.dir.key(&self.paths.tokens) else {
            return;
        };
        if disk.tokens_key == Some(key) {
            return;
        }
        disk.tokens_key = Some(key);
        match load_json::<Stamped<ApiTokens>>(
            &self.paths.dir,
            &self.paths.tokens,
            MAX_SMALL_FILE_BYTES,
        ) {
            Ok(Some(next)) if next.generation > disk.tokens_gen => {
                disk.tokens_gen = next.generation;
                *tokens = next.value;
                self.clear_sessions();
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "tokens.json could not be reloaded"),
        }
    }

    pub async fn set_credentials(self: &Arc<Self>, c: Credentials) -> Result<()> {
        let _guard = self.login_lock.lock().await;
        self.refresh_creds();
        if self.persist_credentials(c).await? {
            Ok(())
        } else {
            Err(superseded("credentials"))
        }
    }

    // False means a reset landed first: its state is adopted and nothing was written.
    async fn persist_credentials(self: &Arc<Self>, c: Credentials) -> Result<bool> {
        let stamped = Stamped {
            generation: self.creds_generation(),
            value: c,
        };
        let bytes = serde_json::to_vec_pretty(&stamped)?;
        let dir = self.paths.dir.clone();
        let lock_name = self.paths.auth_lock.clone();
        let target = self.paths.credentials.clone();
        let this = Arc::clone(self);
        // The write and the in-memory update run as one owned task, so a dropped request cannot leave the file ahead of memory.
        tokio::spawn(async move {
            let written = guarded_write(dir, lock_name, target, stamped.generation, bytes).await?;
            // A reset adopted while the write was finishing is newer than this copy, so memory must keep it.
            let stored = {
                let mut disk = lock(&this.disk);
                disk.creds_key = None;
                let current = written && disk.creds_gen <= stamped.generation;
                if current {
                    this.creds.store(Some(Arc::new(stamped.value)));
                }
                current
            };
            if !stored {
                this.refresh_creds();
            }
            Ok::<bool, ConnectorError>(written)
        })
        .await
        .map_err(|e| internal("credentials task", e))?
    }

    // Replaces credentials and empties the token list under a generation newer than any seen, so running connectors adopt it.
    pub async fn reset_credentials(&self, c: Credentials) -> Result<()> {
        let _login = self.login_lock.lock().await;
        let mut tokens = self.tokens.lock().await;
        let floor = {
            let disk = lock(&self.disk);
            disk.creds_gen.max(disk.tokens_gen)
        };
        let paths = (
            self.paths.dir.clone(),
            self.paths.auth_lock.clone(),
            self.paths.tokens.clone(),
            self.paths.credentials.clone(),
        );
        let fresh = c.clone();
        let generation = tokio::task::spawn_blocking(move || -> Result<u64> {
            let (dir, lock_name, tokens_name, creds_name) = paths;
            let _held = lock_auth(&dir, &lock_name).map_err(|e| internal("auth lock failed", e))?;
            let generation = floor
                .max(disk_generation(&dir, &creds_name))
                .max(disk_generation(&dir, &tokens_name))
                .saturating_add(1);
            let empty = Stamped {
                generation,
                value: ApiTokens::new(),
            };
            let creds = Stamped {
                generation,
                value: c,
            };
            write_atomic_in(
                &dir,
                &tokens_name,
                &serde_json::to_vec_pretty(&empty)?,
                0o600,
            )
            .map_err(|e| internal("write failed", e))?;
            write_atomic_in(
                &dir,
                &creds_name,
                &serde_json::to_vec_pretty(&creds)?,
                0o600,
            )
            .map_err(|e| internal("write failed", e))?;
            Ok(generation)
        })
        .await
        .map_err(|e| internal("reset task", e))??;
        {
            let mut disk = lock(&self.disk);
            disk.creds_gen = generation;
            disk.tokens_gen = generation;
            disk.creds_key = None;
            disk.tokens_key = None;
        }
        *tokens = ApiTokens::new();
        self.creds.store(Some(Arc::new(fresh)));
        self.clear_sessions();
        Ok(())
    }

    // Logins are serialised so two requests cannot both spend the same one-time code.
    pub async fn verify_login(
        self: &Arc<Self>,
        username: &str,
        password: &str,
        totp: &str,
        now: u64,
    ) -> Result<bool> {
        let _guard = self.login_lock.lock().await;
        self.verify_locked(username, password, totp, now).await
    }

    // `admit` runs inside the serialised section and must count the attempt as a failure before it returns Ok, so a dropped request still counts; `on_verified` takes that count back.
    pub async fn verify_login_gated(
        self: &Arc<Self>,
        username: &str,
        password: &str,
        totp: &str,
        admit: impl FnOnce(u64) -> std::result::Result<(), u64>,
        on_verified: impl FnOnce(),
    ) -> Result<LoginOutcome> {
        let _guard = self.login_lock.lock().await;
        let now = now_unix();
        if let Err(retry) = admit(now) {
            return Ok(LoginOutcome::Blocked(retry));
        }
        if self.verify_locked(username, password, totp, now).await? {
            on_verified();
            Ok(LoginOutcome::Accepted)
        } else {
            Ok(LoginOutcome::Rejected)
        }
    }

    async fn verify_locked(
        self: &Arc<Self>,
        username: &str,
        password: &str,
        totp: &str,
        now: u64,
    ) -> Result<bool> {
        let current = self.credentials();
        let generation = self.creds_generation();
        let (user, pass, code) = (username.to_string(), password.to_string(), totp.to_string());
        let permit = Arc::clone(&self.login_permits)
            .acquire_owned()
            .await
            .map_err(|e| internal("login permits", e))?;
        let outcome = spawn_holding(permit, move || match current {
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
            Some(updated) => self.persist_credentials(updated).await,
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

    // Persists `next` and swaps it in, unless a reset replaced the token list since `tokens` was read.
    async fn commit_tokens(&self, tokens: &mut ApiTokens, next: ApiTokens) -> Result<()> {
        let seen = lock(&self.disk).tokens_gen;
        let stamped = Stamped {
            generation: seen,
            value: &next,
        };
        let bytes = serde_json::to_vec_pretty(&stamped)?;
        let dir = self.paths.dir.clone();
        let lock_name = self.paths.auth_lock.clone();
        let target = self.paths.tokens.clone();
        let written = guarded_write(dir, lock_name, target, seen, bytes).await?;
        lock(&self.disk).tokens_key = None;
        if !written {
            self.refresh_tokens(tokens);
            return Err(superseded("api tokens"));
        }
        *tokens = next;
        Ok(())
    }

    pub async fn create_api_token(&self, name: &str) -> Result<(ApiToken, String)> {
        // A reset that lands while the hash is being made must still supersede this request.
        let started = {
            let mut tokens = self.tokens.lock().await;
            self.refresh_tokens(&mut tokens);
            lock(&self.disk).tokens_gen
        };
        // The Argon2 hash is made before the lock is taken and off the executor.
        let owned = name.to_string();
        let permit = Arc::clone(&self.token_permits)
            .acquire_owned()
            .await
            .map_err(|e| internal("token permits", e))?;
        let (meta, plaintext) = spawn_holding(permit, move || ApiToken::mint(&owned))
            .await
            .map_err(|e| internal("token task", e))?
            .map_err(|_| ConnectorError::Internal("token generation failed".into()))?;
        // Changes go to a copy that is persisted first, so a failed write keeps the live set intact.
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        if lock(&self.disk).tokens_gen != started {
            return Err(superseded("api tokens"));
        }
        let mut next = tokens.clone();
        next.insert(meta.clone()).map_err(|e| match e {
            AuthError::Weak(msg) => ConnectorError::Conflict(msg.to_string()),
            _ => ConnectorError::Internal("token generation failed".into()),
        })?;
        self.commit_tokens(&mut tokens, next).await?;
        Ok((meta, plaintext))
    }

    pub async fn verify_api_token(&self, token: &str) -> Option<ApiToken> {
        match self.verify_api_token_gated(token, || true, || {}).await {
            TokenOutcome::Accepted(meta) => Some(meta),
            TokenOutcome::Rejected | TokenOutcome::WrongSecret => None,
        }
    }

    // The tokens lock is held only for the cheap lookup and the final bookkeeping; Argon2 runs between them on a blocking thread.
    // `admit` must count the attempt before it returns true, and `on_verified` undoes that count once the hash passes.
    pub async fn verify_api_token_gated(
        &self,
        token: &str,
        admit: impl FnOnce() -> bool,
        on_verified: impl FnOnce(),
    ) -> TokenOutcome {
        // last_used_at stays in memory and reaches disk with the next token change.
        let now = now_rfc3339();
        let lookup = {
            let mut tokens = self.tokens.lock().await;
            self.refresh_tokens(&mut tokens);
            tokens.begin_verify(token, &now)
        };
        let pending = match lookup {
            TokenLookup::Unknown => return TokenOutcome::Rejected,
            TokenLookup::Verified(meta) => return TokenOutcome::Accepted(meta),
            TokenLookup::Pending(pending) => pending,
        };
        if !admit() {
            return TokenOutcome::Rejected;
        }
        let Ok(permit) = Arc::clone(&self.token_permits).acquire_owned().await else {
            return TokenOutcome::Rejected;
        };
        let to_check = pending.clone();
        match spawn_holding(permit, move || to_check.check()).await {
            Ok(true) => on_verified(),
            Ok(false) => return TokenOutcome::WrongSecret,
            Err(e) => {
                tracing::error!(error = %e, "token check task failed");
                return TokenOutcome::Rejected;
            }
        }
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        match tokens.complete(&pending, &now) {
            Some(meta) => TokenOutcome::Accepted(meta.clone()),
            None => TokenOutcome::Rejected,
        }
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
        self.commit_tokens(&mut tokens, next).await?;
        Ok(true)
    }

    pub async fn clear_api_tokens(&self) -> Result<()> {
        let mut tokens = self.tokens.lock().await;
        self.refresh_tokens(&mut tokens);
        self.commit_tokens(&mut tokens, ApiTokens::new()).await?;
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
    use cite_core::atomic::write_atomic;
    use cite_edge::auth::hash_password;
    use cite_edge::model::{MaintenancePage, Retention};
    use cite_edge::totp;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn root(dir: &Path) -> TrustedDir {
        TrustedDir::open(dir).expect("open dir")
    }

    fn nm(name: &str) -> FileName {
        FileName::new(name).expect("name")
    }

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn password() -> &'static str {
        static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PW.get_or_init(|| cite_edge::auth::generate_password().expect("rng"))
    }

    fn wrong_password() -> &'static str {
        static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PW.get_or_init(|| cite_edge::auth::generate_password().expect("rng"))
    }

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
            password_hash: hash_password(password()).expect("hash"),
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
        let dir_handle = root(dir.path());
        let files = AuditFiles {
            current: nm("audit.jsonl"),
            rotated: nm("audit.jsonl.1"),
        };
        let size = prune_file(&dir_handle, &files.current, NOW, 30).expect("prune");
        let kept = read_tail(&dir_handle, &files, 10);
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
                .verify_login("admin", password(), &code, NOW)
                .await
                .expect("ok")
        );
        assert!(
            !store
                .verify_login("admin", password(), &code, NOW)
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
                .verify_login("admin", password(), &code, NOW)
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
    async fn api_token_checks_run_unlocked_and_wrong_secrets_are_reported() {
        let (_dir, store) = open_temp().await;
        let (meta, plain) = store.create_api_token("ci").await.expect("create");
        let wrong = format!("cite_{}.{}", meta.id, "0".repeat(64));
        assert!(matches!(
            store.verify_api_token_gated(&wrong, || true, || {}).await,
            TokenOutcome::WrongSecret
        ));
        let mut asked = false;
        let refused = store
            .verify_api_token_gated(
                &plain,
                || {
                    asked = true;
                    false
                },
                || {},
            )
            .await;
        assert!(asked && matches!(refused, TokenOutcome::Rejected));
        let mut verified = false;
        assert!(matches!(
            store
                .verify_api_token_gated(&plain, || true, || verified = true)
                .await,
            TokenOutcome::Accepted(_)
        ));
        assert!(verified);
        // A verified token never consults the gate again.
        assert!(matches!(
            store.verify_api_token_gated(&plain, || false, || {}).await,
            TokenOutcome::Accepted(_)
        ));
        let unknown = format!("cite_{}.{}", "e".repeat(16), "0".repeat(64));
        assert!(matches!(
            store.verify_api_token_gated(&unknown, || true, || {}).await,
            TokenOutcome::Rejected
        ));
        assert!(store.revoke_api_token(&meta.id).await.expect("revoke"));
        assert!(store.verify_api_token(&plain).await.is_none());
    }

    // The attempt is counted inside the gate, so a burst cannot all pass the limiter before any failure lands.
    #[tokio::test]
    async fn concurrent_wrong_secrets_run_at_most_the_failure_limit_of_hashes() {
        use cite_edge::ratelimit::LoginLimiter;
        let (_dir, store) = open_temp().await;
        let (meta, _) = store.create_api_token("ci").await.expect("create");
        let wrong = format!("cite_{}.{}", meta.id, "0".repeat(64));
        let limiter = Arc::new(StdMutex::new(LoginLimiter::new()));
        let mut tasks = Vec::new();
        for _ in 0..24 {
            let (store, limiter, wrong) = (Arc::clone(&store), Arc::clone(&limiter), wrong.clone());
            tasks.push(tokio::spawn(async move {
                store
                    .verify_api_token_gated(
                        &wrong,
                        || {
                            let mut l = lock(&limiter);
                            if l.check("client", 100).is_err() {
                                return false;
                            }
                            l.record_provisional("client", 100);
                            true
                        },
                        || {},
                    )
                    .await
            }));
        }
        let (mut hashed, mut refused) = (0, 0);
        for task in tasks {
            match task.await.expect("join") {
                TokenOutcome::WrongSecret => hashed += 1,
                TokenOutcome::Rejected => refused += 1,
                TokenOutcome::Accepted(_) => panic!("wrong secret accepted"),
            }
        }
        assert_eq!((hashed, refused), (5, 19));
        assert!(lock(&limiter).check("client", 100).is_err());
    }

    // The attempt is counted before hashing, so a login whose connection drops mid-hash still counts against the client.
    #[tokio::test]
    async fn a_dropped_login_attempt_still_counts_as_a_failure() {
        use cite_edge::ratelimit::LoginLimiter;
        let (_dir, store) = open_temp().await;
        store.set_credentials(creds()).await.expect("set");
        let limiter = Arc::new(StdMutex::new(LoginLimiter::new()));
        let attempt = |store: Arc<Store>, limiter: Arc<StdMutex<LoginLimiter>>| async move {
            store
                .verify_login_gated(
                    "admin",
                    wrong_password(),
                    "000000",
                    |now: u64| -> std::result::Result<(), u64> {
                        let mut l = lock(&limiter);
                        l.check("client", now)?;
                        l.record_provisional("client", now);
                        Ok(())
                    },
                    || {},
                )
                .await
        };
        let dropped = tokio::spawn(attempt(Arc::clone(&store), Arc::clone(&limiter)));
        tokio::task::yield_now().await;
        dropped.abort();
        let _ = dropped.await;
        for _ in 0..4 {
            let outcome = attempt(Arc::clone(&store), Arc::clone(&limiter)).await;
            assert!(matches!(outcome, Ok(LoginOutcome::Rejected)));
        }
        let blocked = attempt(Arc::clone(&store), Arc::clone(&limiter)).await;
        assert!(matches!(blocked, Ok(LoginOutcome::Blocked(_))));
    }

    #[tokio::test]
    async fn a_dropped_request_keeps_its_permit_until_the_hash_ends() {
        let permits = Arc::new(Semaphore::new(TOKEN_CHECK_CONCURRENCY));
        let permit = Arc::clone(&permits).acquire_owned().await.expect("permit");
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let job = spawn_holding(permit, move || wait.recv().is_ok());
        drop(job);
        assert_eq!(permits.available_permits(), TOKEN_CHECK_CONCURRENCY - 1);
        release.send(()).expect("release");
        for _ in 0..200 {
            if permits.available_permits() == TOKEN_CHECK_CONCURRENCY {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("permit was never returned");
    }

    #[tokio::test]
    async fn old_format_token_records_load_but_never_verify() {
        let (dir, store) = open_temp().await;
        drop(store);
        let old = format!(
            r#"{{"generation":1,"tokens":[{{"id":"00112233445566ff","name":"legacy","hash":"{}","created_at":"2025-01-01T00:00:00Z","last_used_at":null}}]}}"#,
            "ab".repeat(32)
        );
        write_atomic(&dir.path().join("tokens.json"), old.as_bytes(), 0o600).expect("write");
        let reopened = Store::open(&test_config(dir.path())).await.expect("reopen");
        assert_eq!(reopened.list_api_tokens().await.len(), 1);
        let legacy_plain = format!("cite_{}", "cd".repeat(32));
        assert!(reopened.verify_api_token(&legacy_plain).await.is_none());
        let shaped = format!("cite_00112233445566ff.{}", "ab".repeat(32));
        assert!(reopened.verify_api_token(&shaped).await.is_none());
        assert!(
            reopened
                .revoke_api_token("00112233445566ff")
                .await
                .expect("revoke")
        );
        let (_, fresh) = reopened.create_api_token("new").await.expect("create");
        assert!(reopened.verify_api_token(&fresh).await.is_some());
    }

    // Stands in for the CLI: a reset written at a newer generation while the server holds older state.
    fn write_reset(dir: &Path, generation: u64, secret: &str) {
        let empty = Stamped {
            generation,
            value: ApiTokens::new(),
        };
        let mut reset = creds();
        reset.totp_secret = secret.into();
        let fresh = Stamped {
            generation,
            value: reset,
        };
        let tokens = serde_json::to_vec_pretty(&empty).expect("tokens");
        let creds = serde_json::to_vec_pretty(&fresh).expect("creds");
        write_atomic(&dir.join("tokens.json"), &tokens, 0o600).expect("write tokens");
        write_atomic(&dir.join("credentials.json"), &creds, 0o600).expect("write creds");
    }

    #[tokio::test]
    async fn a_server_token_write_cannot_undo_a_reset_that_landed_first() {
        let (dir, running) = open_temp().await;
        running.reset_credentials(creds()).await.expect("seed");
        let held = lock_auth(&root(dir.path()), &nm("auth.lock")).expect("lock");
        let writer = Arc::clone(&running);
        let task = tokio::spawn(async move { writer.create_api_token("backdoor").await });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        write_reset(dir.path(), 5, "MFRGGZDFMZTWQ2LK");
        drop(held);
        let outcome = task.await.expect("join");
        assert!(
            matches!(outcome, Err(ConnectorError::Conflict(_))),
            "{outcome:?}"
        );
        assert!(running.list_api_tokens().await.is_empty());
        let disk = fs::read_to_string(dir.path().join("tokens.json")).expect("tokens");
        assert!(!disk.contains("backdoor"), "{disk}");
        assert_eq!(disk_generation(&root(dir.path()), &nm("tokens.json")), 5);
        let (_, fresh) = running.create_api_token("later").await.expect("token");
        assert!(running.verify_api_token(&fresh).await.is_some());
    }

    #[tokio::test]
    async fn a_reset_landing_during_token_minting_supersedes_the_new_token() {
        let (dir, running) = open_temp().await;
        running.reset_credentials(creds()).await.expect("seed");
        let all = running
            .token_permits
            .clone()
            .acquire_many_owned(TOKEN_CHECK_CONCURRENCY as u32)
            .await
            .expect("permits");
        let writer = Arc::clone(&running);
        let task = tokio::spawn(async move { writer.create_api_token("late").await });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        write_reset(dir.path(), 5, "MFRGGZDFMZTWQ2LK");
        drop(all);
        let outcome = task.await.expect("join");
        assert!(
            matches!(outcome, Err(ConnectorError::Conflict(_))),
            "{outcome:?}"
        );
        assert!(running.list_api_tokens().await.is_empty());
    }

    // The auth lock is held so the credential write is pending when the caller is aborted; driving the write directly keeps the test independent of hash speed.
    #[tokio::test]
    async fn an_aborted_login_still_records_the_spent_totp_step() {
        let (dir, store) = open_temp().await;
        store.set_credentials(creds()).await.expect("set");
        let code = totp::code_at(SECRET, NOW).expect("code");
        let mut spent = creds();
        spent.totp_last_step = NOW / 30;
        let held = lock_auth(&root(dir.path()), &nm("auth.lock")).expect("lock");
        let attempt = Arc::clone(&store);
        let task = tokio::spawn(async move { attempt.persist_credentials(spent).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        task.abort();
        let _ = task.await;
        drop(held);
        let mut recorded = false;
        for _ in 0..500 {
            if store
                .credentials()
                .is_some_and(|c| c.totp_last_step == NOW / 30)
            {
                recorded = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(recorded, "the spent step never reached memory");
        let replay = store.verify_login("admin", password(), &code, NOW).await;
        assert!(!replay.expect("ok"));
    }

    #[tokio::test]
    async fn a_server_credential_write_cannot_undo_a_reset_that_landed_first() {
        let (dir, running) = open_temp().await;
        running.reset_credentials(creds()).await.expect("seed");
        let held = lock_auth(&root(dir.path()), &nm("auth.lock")).expect("lock");
        let writer = Arc::clone(&running);
        let task = tokio::spawn(async move { writer.set_credentials(creds()).await });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        write_reset(dir.path(), 5, "MFRGGZDFMZTWQ2LK");
        drop(held);
        let outcome = task.await.expect("join");
        assert!(
            matches!(outcome, Err(ConnectorError::Conflict(_))),
            "{outcome:?}"
        );
        let adopted = running.credentials().expect("credentials");
        assert_eq!(adopted.totp_secret, "MFRGGZDFMZTWQ2LK");
        assert_eq!(
            disk_generation(&root(dir.path()), &nm("credentials.json")),
            5
        );
    }

    #[tokio::test]
    async fn a_reset_waits_for_a_write_that_holds_the_auth_lock() {
        let (dir, store) = open_temp().await;
        let held = lock_auth(&root(dir.path()), &nm("auth.lock")).expect("lock");
        let cli = Arc::clone(&store);
        let reset = tokio::spawn(async move { cli.reset_credentials(creds()).await });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(!reset.is_finished());
        assert!(!dir.path().join("credentials.json").exists());
        drop(held);
        reset.await.expect("join").expect("reset");
        assert!(dir.path().join("credentials.json").is_file());
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
    async fn a_symlinked_store_file_is_refused_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        let target = outside.path().join("elsewhere");
        let valid = EdgeConfig {
            version: CONFIG_VERSION,
            ..EdgeConfig::default()
        };
        let body = serde_json::to_vec_pretty(&valid).expect("json");
        fs::write(&target, &body).expect("write");
        std::os::unix::fs::symlink(&target, dir.path().join("edge.json")).expect("link");
        let err = Store::open(&test_config(dir.path()))
            .await
            .err()
            .expect("open must refuse the symlink");
        let text = err.to_string();
        assert!(text.contains("cannot read edge.json"), "{text}");
        assert!(!text.contains("is invalid"), "{text}");
        assert_eq!(fs::read(&target).expect("read"), body);
    }

    #[test]
    fn audit_append_and_lock_refuse_symlinks_and_stay_in_the_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        let target = outside.path().join("victim");
        fs::write(&target, b"keep").expect("write");
        std::os::unix::fs::symlink(&target, dir.path().join("audit.jsonl")).expect("link");
        std::os::unix::fs::symlink(&target, dir.path().join("auth.lock")).expect("link");
        let handle = root(dir.path());
        let files = AuditFiles {
            current: nm("audit.jsonl"),
            rotated: nm("audit.jsonl.1"),
        };
        let state = AuditState {
            size: 0,
            last_prune: NOW,
        };
        assert!(append_audit(&handle, &files, b"x\n", state, NOW, 30).is_err());
        assert!(lock_auth(&handle, &nm("auth.lock")).is_err());
        assert_eq!(fs::read(&target).expect("read"), b"keep");
    }

    #[test]
    fn store_file_names_reject_traversal_nul_and_separators() {
        for bad in ["", ".", "..", "../edge.json", "/etc/passwd", "a/b", "a\0b"] {
            assert!(fixed_name(bad).is_err(), "{bad:?}");
        }
        assert!(fixed_name(&"x".repeat(cite_core::confined::NAME_MAX + 1)).is_err());
        assert!(fixed_name("edge.json").is_ok());
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
