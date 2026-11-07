//! Keeps the synced variables of Doppler-bound sites current and redeploys a site when they change.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use cite_edge::model::{DeployAction, DopplerBinding, Site};
use cite_edge::validate::{validate_doppler_binding, validate_site_strict};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::config::NodeToken;
use crate::deploy::{Deployer, detach, site_mut};
use crate::doppler::{
    self, DopplerClient, DopplerConfig, DopplerError, DopplerProject, DopplerSource, DopplerToken,
    Offline, Skipped,
};
use crate::error::{ConnectorError, Result};
use crate::siteops::EnvKind;
use crate::store::{now_unix, unix_to_rfc3339};

const ACTOR: &str = "doppler";
const DEPLOY_NOTE: &str = "doppler sync";
const CONCURRENCY: usize = 2;
// Pending redeploys are checked this often, and due syncs are started on the same tick.
const TICK: Duration = Duration::from_secs(10);
const MIN_BACKOFF_SECS: u64 = 60;
const MAX_BACKOFF_SECS: u64 = 3600;
const MAX_JITTER_SECS: u64 = 30;
const UNBOUND_NOTE: &str =
    "the Doppler variables stay in the running site until it is redeployed";
const UNDEPLOYED_NOTE: &str =
    "the synced Doppler variables reach the site at its next deploy";

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        now_unix()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    Syncing,
    Synced,
    Error,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Syncing => "syncing",
            Phase::Synced => "synced",
            Phase::Error => "error",
        }
    }
}

/// What the node knows about one site's sync; held in memory, so a restart starts from idle and syncs again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    pub phase: Phase,
    pub last_sync_at: Option<u64>,
    pub last_error: Option<String>,
    pub skipped: Vec<Skipped>,
    pub failures: u32,
    pub next_due: u64,
    pub pending_redeploy: bool,
    // When the synced variables last changed without a redeploy that carried them.
    pub redeploy_needed: Option<u64>,
}

impl SyncState {
    pub fn begin(&mut self) {
        self.phase = Phase::Syncing;
    }

    pub fn succeed(&mut self, now: u64, every: u64, skipped: Vec<Skipped>) {
        self.phase = Phase::Synced;
        self.last_sync_at = Some(now);
        self.failures = 0;
        self.next_due = now.saturating_add(every);
        self.last_error = doppler::skipped_note(&skipped);
        self.skipped = skipped;
    }

    // The last good snapshot is left alone; only the schedule and the message change.
    pub fn fail(&mut self, now: u64, every: u64, err: &DopplerError) {
        self.phase = Phase::Error;
        self.failures = self.failures.saturating_add(1);
        self.last_error = Some(err.to_string());
        self.next_due = now.saturating_add(backoff(self.failures, every, err.retry_after()));
    }

    pub fn is_due(&self, now: u64) -> bool {
        self.phase != Phase::Syncing && self.next_due <= now
    }
}

/// Seconds until the next try: doubling from a minute, never past the poll interval or an hour, and never sooner than Retry-After.
pub fn backoff(failures: u32, every: u64, retry_after: Option<u64>) -> u64 {
    let doubled = MIN_BACKOFF_SECS.saturating_mul(1u64 << failures.saturating_sub(1).min(16));
    let base = doubled
        .min(every.max(MIN_BACKOFF_SECS))
        .min(MAX_BACKOFF_SECS);
    match retry_after {
        Some(secs) => base.max(secs.min(MAX_BACKOFF_SECS)),
        None => base,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedeployPlan {
    Start,
    Wait,
    Unavailable,
}

// A running deploy or token change goes first, so two operations on one site never overlap.
fn plan_redeploy(orchestrated: bool, busy: bool) -> RedeployPlan {
    if busy {
        RedeployPlan::Wait
    } else if orchestrated {
        RedeployPlan::Start
    } else {
        RedeployPlan::Unavailable
    }
}

fn binding_of(site: &Site) -> Option<DopplerBinding> {
    site.source.as_ref().and_then(|s| s.doppler.clone())
}

fn feeds(binding: &DopplerBinding, kind: EnvKind) -> bool {
    match kind {
        EnvKind::Build => binding.build,
        EnvKind::Runtime => binding.runtime,
    }
}

fn not_bound(id: &str) -> ConnectorError {
    ConnectorError::BadRequest(format!("site {id} is not bound to a Doppler config"))
}

fn not_built(id: &str) -> ConnectorError {
    ConnectorError::BadRequest(format!(
        "site {id} is not built from a repository, so it has no build or runtime variables"
    ))
}

fn redeployed_since(site: &Site, since: u64) -> bool {
    let since = i64::try_from(since).unwrap_or(i64::MAX);
    site.history.iter().any(|d| {
        d.action == DeployAction::Promote
            && OffsetDateTime::parse(&d.at, &Rfc3339).is_ok_and(|t| t.unix_timestamp() >= since)
    })
}

fn jitter_secs(every: u64) -> u64 {
    let span = (every / 10).min(MAX_JITTER_SECS);
    let mut raw = [0u8; 8];
    if span == 0 || getrandom::fill(&mut raw).is_err() {
        return 0;
    }
    u64::from_le_bytes(raw) % (span + 1)
}

fn jitter(every: u64) -> Duration {
    Duration::from_secs(jitter_secs(every))
}

fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The binding as the API reports it; values never appear, only names and counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DopplerView {
    pub bound: bool,
    pub project: Option<String>,
    pub config: Option<String>,
    pub build: bool,
    pub runtime: bool,
    pub token_source: String,
    pub status: String,
    pub last_sync_at: Option<String>,
    pub last_error: Option<String>,
    pub keys: u32,
    pub redeploy_needed: bool,
    pub pending_redeploy: bool,
    pub skipped: Vec<Skipped>,
}

#[derive(Default)]
struct Fetched {
    changed: bool,
    counts: [usize; 2],
    skipped: Vec<Skipped>,
}

pub struct DopplerSync {
    deployer: Arc<Deployer>,
    source: StdMutex<Arc<dyn DopplerSource>>,
    node_token: Option<DopplerToken>,
    every: u64,
    clock: Arc<dyn Clock>,
    states: StdMutex<HashMap<String, SyncState>>,
    // Added to every next_due so sites bound together drift apart instead of syncing in step.
    spread: fn(u64) -> u64,
    // Unix time before which nothing is sent with the node token, after Doppler rate limited it.
    node_not_before: AtomicU64,
}

impl DopplerSync {
    pub fn new(deployer: Arc<Deployer>, node_token: Option<&NodeToken>, every: u64) -> Arc<Self> {
        let source: Arc<dyn DopplerSource> = match DopplerClient::new() {
            Ok(client) => Arc::new(client),
            Err(e) => {
                tracing::error!(error = %e, "the Doppler client could not be built");
                Arc::new(Offline(e.to_string()))
            }
        };
        let token = node_token.and_then(|t| DopplerToken::parse(t.expose()).ok());
        Self::with_parts(deployer, source, token, every, Arc::new(SystemClock))
    }

    pub(crate) fn with_parts(
        deployer: Arc<Deployer>,
        source: Arc<dyn DopplerSource>,
        node_token: Option<DopplerToken>,
        every: u64,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        Arc::new(Self {
            deployer,
            source: StdMutex::new(source),
            node_token,
            every,
            clock,
            states: StdMutex::default(),
            spread: jitter_secs,
            node_not_before: AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_source(&self, source: Arc<dyn DopplerSource>) {
        *lock(&self.source) = source;
    }

    fn source(&self) -> Arc<dyn DopplerSource> {
        Arc::clone(&lock(&self.source))
    }

    fn gate(&self, id: &str) -> Arc<Mutex<()>> {
        self.deployer.doppler_gate(id)
    }

    fn node_token_wait(&self) -> std::result::Result<(), DopplerError> {
        let (now, until) = (self.clock.now(), self.node_not_before.load(Ordering::SeqCst));
        if now < until {
            return Err(DopplerError::RateLimited {
                retry_after: Some(until - now),
            });
        }
        Ok(())
    }

    fn note_node_result<T>(&self, result: &std::result::Result<T, DopplerError>) {
        if let Err(err @ DopplerError::RateLimited { .. }) = result {
            let wait = err.retry_after().unwrap_or(MIN_BACKOFF_SECS).clamp(1, MAX_BACKOFF_SECS);
            let until = self.clock.now().saturating_add(wait);
            self.node_not_before.fetch_max(until, Ordering::SeqCst);
        }
    }

    fn state(&self, id: &str) -> Option<SyncState> {
        lock(&self.states).get(id).cloned()
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut SyncState)) {
        f(lock(&self.states).entry(id.to_string()).or_default());
    }

    async fn site_token(&self, id: &str) -> Option<DopplerToken> {
        let stored = self
            .deployer
            .store
            .get_secret(&doppler::token_secret(id))
            .await
            .map(Zeroizing::new)?;
        DopplerToken::parse(&stored).ok()
    }

    /// The site's own token, or the node token (the flag says which).
    async fn effective_token(
        &self,
        id: &str,
    ) -> std::result::Result<(DopplerToken, bool), DopplerError> {
        match self.site_token(id).await {
            Some(token) => Ok((token, false)),
            None => self
                .node_token
                .clone()
                .map(|t| (t, true))
                .ok_or(DopplerError::NoToken),
        }
    }

    pub async fn projects(&self) -> Result<Vec<DopplerProject>> {
        let token = self.node_token.clone().ok_or(DopplerError::NoToken)?;
        self.node_token_wait()?;
        let result = self.source().projects(&token).await;
        self.note_node_result(&result);
        Ok(result?)
    }

    pub async fn configs(&self, project: &str) -> Result<Vec<DopplerConfig>> {
        let token = self.node_token.clone().ok_or(DopplerError::NoToken)?;
        self.node_token_wait()?;
        let result = self.source().configs(&token, project).await;
        self.note_node_result(&result);
        Ok(result?)
    }

    pub async fn view(&self, id: &str) -> Result<DopplerView> {
        let site = self.deployer.get_site(id)?;
        let binding = binding_of(&site);
        let mut keys = BTreeSet::new();
        if let Some(b) = &binding {
            for kind in [EnvKind::Build, EnvKind::Runtime] {
                if feeds(b, kind) {
                    keys.extend(self.deployer.doppler_snapshot(id, kind).await.into_keys());
                }
            }
        }
        let token_source = if self.site_token(id).await.is_some() {
            "site"
        } else if self.node_token.is_some() {
            "node"
        } else {
            "none"
        };
        let state = self.state(id).unwrap_or_default();
        let redeploy_needed = state
            .redeploy_needed
            .is_some_and(|since| !redeployed_since(&site, since));
        if state.redeploy_needed.is_some() && !redeploy_needed {
            self.update(id, |s| s.redeploy_needed = None);
        }
        let note = match (&binding, redeploy_needed) {
            (None, true) => Some(UNBOUND_NOTE.to_string()),
            (Some(_), true) => Some(UNDEPLOYED_NOTE.to_string()),
            _ => None,
        };
        let (status, last_error, skipped) = if binding.is_some() {
            (
                state.phase.as_str(),
                state.last_error.clone().or(note),
                state.skipped.clone(),
            )
        } else {
            ("idle", note, Vec::new())
        };
        Ok(DopplerView {
            bound: binding.is_some(),
            project: binding
                .as_ref()
                .filter(|b| !b.token_only())
                .map(|b| b.project.clone()),
            config: binding
                .as_ref()
                .filter(|b| !b.token_only())
                .map(|b| b.config.clone()),
            build: binding.as_ref().is_some_and(|b| b.build),
            runtime: binding.as_ref().is_some_and(|b| b.runtime),
            token_source: token_source.to_string(),
            status: status.to_string(),
            last_sync_at: state.last_sync_at.map(unix_to_rfc3339),
            last_error,
            keys: u32::try_from(keys.len()).unwrap_or(u32::MAX),
            redeploy_needed,
            pending_redeploy: state.pending_redeploy,
            skipped,
        })
    }

    /// Syncs one site now; the outcome is recorded in its status either way.
    pub async fn sync_now(self: &Arc<Self>, actor: &str, id: &str) -> Result<DopplerView> {
        let (this, actor, sid) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.sync_site(&actor, &sid, false).await }).await?;
        self.view(id).await
    }

    async fn sync_site(&self, actor: &str, id: &str, force: bool) -> Result<()> {
        let gate = self.gate(id);
        let _held = gate.lock().await;
        self.sync_locked(actor, id, force).await
    }

    // A bind forces a redeploy; a poll only redeploys when the synced variables changed.
    async fn sync_locked(&self, actor: &str, id: &str, force: bool) -> Result<()> {
        let site = self.deployer.get_site(id)?;
        let Some(binding) = binding_of(&site) else {
            return Err(not_bound(id));
        };
        self.update(id, SyncState::begin);
        let outcome = self.fetch_and_store(&site, &binding).await;
        let (now, every) = (self.clock.now(), self.every);
        let spread = (self.spread)(every);
        match outcome {
            Ok(done) => {
                let detail = format!(
                    "site={id} build={} runtime={} skipped={}",
                    done.counts[0],
                    done.counts[1],
                    done.skipped.len()
                );
                self.update(id, |s| s.succeed(now, every.saturating_add(spread), done.skipped));
                if done.changed {
                    self.deployer
                        .store
                        .audit(actor, "site.doppler.sync", &detail)
                        .await;
                }
                if done.changed || force {
                    self.request_redeploy(id).await;
                }
                Ok(())
            }
            Err(err) => {
                tracing::warn!(site = %id, error = %err, "doppler sync failed");
                self.update(id, |s| {
                    s.fail(now, every, &err);
                    s.next_due = s.next_due.saturating_add(spread);
                });
                Err(err.into())
            }
        }
    }

    // Both kinds are filtered and checked before either is written, so a refused config changes nothing.
    async fn fetch_and_store(
        &self,
        site: &Site,
        binding: &DopplerBinding,
    ) -> std::result::Result<Fetched, DopplerError> {
        let id = site.id.as_str();
        let (token, node) = self.effective_token(id).await?;
        if node {
            self.node_token_wait()?;
        }
        let downloaded = self
            .source()
            .download(&token, &binding.project, &binding.config)
            .await;
        if node {
            self.note_node_result(&downloaded);
        }
        let raw = downloaded?;
        let mut out = Fetched::default();
        let mut next: Vec<(EnvKind, Option<BTreeMap<String, String>>)> = Vec::with_capacity(2);
        for (i, kind) in [EnvKind::Build, EnvKind::Runtime].into_iter().enumerate() {
            if !feeds(binding, kind) {
                next.push((kind, None));
                continue;
            }
            let filtered = doppler::filter_for(kind, &raw);
            let manual = self
                .deployer
                .env_map(id, kind)
                .await
                .map_err(|e| DopplerError::Local(e.to_string()))?;
            let merged = doppler::merge_env(filtered.vars.clone(), manual);
            doppler::env_limits(&merged, kind.label()).map_err(|m| {
                DopplerError::Limits(format!("{m} once the Doppler variables are added"))
            })?;
            out.counts[i] = filtered.vars.len();
            out.skipped.extend(filtered.skipped);
            next.push((kind, Some(filtered.vars)));
        }
        let current = self.deployer.get_site(id).ok().and_then(|s| binding_of(&s));
        if current.as_ref() != Some(binding) {
            return Err(DopplerError::Local(format!(
                "site {id} was deleted or its Doppler binding changed during the sync"
            )));
        }
        let store = &self.deployer.store;
        for (kind, vars) in next {
            let name = doppler::snapshot_secret(id, kind);
            let stored = store.get_secret(&name).await.map(Zeroizing::new);
            let Some(vars) = vars else {
                if stored.is_some() {
                    store.delete_secret(&name).await;
                    out.changed = true;
                }
                continue;
            };
            let stored_hash = stored
                .as_deref()
                .and_then(|t| serde_json::from_str::<BTreeMap<String, String>>(t).ok())
                .map(|m| doppler::snapshot_hash(&m));
            if stored_hash == Some(doppler::snapshot_hash(&vars)) {
                continue;
            }
            let text = Zeroizing::new(
                serde_json::to_string(&vars).map_err(|e| DopplerError::Local(e.to_string()))?,
            );
            store
                .put_secret(&name, &text)
                .await
                .map_err(|e| DopplerError::Local(e.to_string()))?;
            out.changed = true;
        }
        Ok(out)
    }

    async fn request_redeploy(&self, id: &str) {
        let busy = self.deployer.site_ops.ops.current(id).is_some();
        match plan_redeploy(self.deployer.orchestrator.is_some(), busy) {
            RedeployPlan::Wait => self.update(id, |s| s.pending_redeploy = true),
            RedeployPlan::Unavailable => {
                let now = self.clock.now();
                self.update(id, |s| {
                    s.pending_redeploy = false;
                    s.redeploy_needed.get_or_insert(now);
                });
            }
            RedeployPlan::Start => self.start_redeploy(id).await,
        }
    }

    async fn start_redeploy(&self, id: &str) {
        self.update(id, |s| s.pending_redeploy = false);
        let started = self
            .deployer
            .deploy(ACTOR, id, None, Some(DEPLOY_NOTE.to_string()), None, false)
            .await;
        let now = self.clock.now();
        match started {
            Ok(_) => self.update(id, |s| s.redeploy_needed = None),
            Err(err) => {
                tracing::warn!(site = %id, error = %err, "redeploy after a doppler sync was refused");
                self.update(id, |s| {
                    s.redeploy_needed.get_or_insert(now);
                });
            }
        }
    }

    // A redeploy that had to wait starts once the operation in its way has finished.
    async fn flush_pending(&self) {
        let waiting: Vec<String> = lock(&self.states)
            .iter()
            .filter(|(_, s)| s.pending_redeploy)
            .map(|(id, _)| id.clone())
            .collect();
        for id in waiting {
            if self.deployer.get_site(&id).is_err() {
                lock(&self.states).remove(&id);
                continue;
            }
            if self.deployer.site_ops.ops.current(&id).is_none() {
                self.request_redeploy(&id).await;
            }
        }
    }

    // Marks the due sites as claimed so a slow sync is never started twice, and forgets deleted sites.
    fn claim_due(&self, now: u64) -> Vec<String> {
        let sites = self.deployer.sites();
        let existing: HashSet<&str> = sites.iter().map(|s| s.id.as_str()).collect();
        self.deployer
            .retain_doppler_gates(|id| existing.contains(id));
        let mut states = lock(&self.states);
        states.retain(|id, _| existing.contains(id.as_str()));
        let mut due = Vec::new();
        for site in sites.iter().filter(|s| binding_of(s).is_some()) {
            let state = states.entry(site.id.clone()).or_default();
            if state.is_due(now) {
                state.next_due = now
                    .saturating_add(self.every)
                    .saturating_add((self.spread)(self.every));
                due.push(site.id.clone());
            }
        }
        due
    }

    pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move { this.run().await })
    }

    async fn run(self: Arc<Self>) {
        let permits = Arc::new(Semaphore::new(CONCURRENCY));
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            self.flush_pending().await;
            for id in self.claim_due(self.clock.now()) {
                let (this, permits) = (Arc::clone(&self), Arc::clone(&permits));
                let delay = jitter(self.every);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let Ok(_permit) = permits.acquire_owned().await else {
                        return;
                    };
                    if let Err(err) = this.sync_site(ACTOR, &id, false).await {
                        tracing::debug!(site = %id, error = %err, "scheduled doppler sync did not finish");
                    }
                });
            }
        }
    }

    pub async fn bind(
        self: &Arc<Self>,
        actor: &str,
        id: &str,
        binding: DopplerBinding,
        token: Option<Zeroizing<String>>,
    ) -> Result<DopplerView> {
        let (this, actor, sid) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.bind_inner(&actor, &sid, binding, token).await }).await
    }

    async fn bind_inner(
        &self,
        actor: &str,
        id: &str,
        binding: DopplerBinding,
        token: Option<Zeroizing<String>>,
    ) -> Result<DopplerView> {
        validate_doppler_binding(&binding)?;
        let token = token.filter(|t| !t.is_empty());
        if let Some(t) = &token {
            DopplerToken::parse(t)?;
        }
        if self.deployer.get_site(id)?.source.is_none() {
            return Err(not_built(id));
        }
        let gate = self.gate(id);
        let _held = gate.lock().await;
        let site = self.deployer.get_site(id)?;
        let store = &self.deployer.store;
        let token_name = doppler::token_secret(id);
        let kept_token = store.get_secret(&token_name).await.map(Zeroizing::new);
        if token.is_none() && kept_token.is_none() && self.node_token.is_none() {
            return Err(DopplerError::NoToken.into());
        }
        if binding.token_only() {
            let site_token = token.as_deref().or(kept_token.as_deref());
            let service = site_token
                .and_then(|t| DopplerToken::parse(t).ok())
                .is_some_and(|t| t.is_service_token());
            if !service {
                return Err(ConnectorError::BadRequest(
                    "a binding without a project and config needs a Doppler service token (dp.st.) for this site; create one under Project > Config > Access > Service Tokens".into(),
                ));
            }
        }
        let kept_binding = binding_of(&site);
        let kept_state = self.state(id);
        let mut kept_snapshots = Vec::with_capacity(2);
        for kind in [EnvKind::Build, EnvKind::Runtime] {
            let name = doppler::snapshot_secret(id, kind);
            let value = store.get_secret(&name).await.map(Zeroizing::new);
            kept_snapshots.push((name, value));
        }
        if let Some(t) = &token {
            store.put_secret(&token_name, t).await?;
        }
        let detail = format!(
            "site={id} project={} config={} build={} runtime={}",
            binding.project, binding.config, binding.build, binding.runtime
        );
        let bound = self
            .set_binding(actor, id, Some(binding), "site.doppler.bind", &detail, true)
            .await;
        let synced = match bound {
            Ok(()) => self.sync_locked(actor, id, true).await,
            Err(err) => Err(err),
        };
        if let Err(err) = synced {
            if token.is_some() {
                self.put_back(&token_name, kept_token.as_deref().map(String::as_str))
                    .await;
            }
            let restore = format!("site={id}");
            if let Err(e) = self
                .set_binding(actor, id, kept_binding, "site.doppler.restore", &restore, false)
                .await
            {
                tracing::warn!(site = %id, error = %e, "the previous Doppler binding could not be restored");
            }
            for (name, value) in &kept_snapshots {
                self.put_back(name, value.as_deref().map(String::as_str))
                    .await;
            }
            let mut states = lock(&self.states);
            match kept_state {
                Some(state) => states.insert(id.to_string(), state),
                None => states.remove(id),
            };
            return Err(err);
        }
        if token.is_some() {
            store
                .audit(actor, "site.doppler.token.set", &format!("site={id}"))
                .await;
        }
        self.view(id).await
    }

    async fn put_back(&self, name: &str, value: Option<&str>) {
        let store = &self.deployer.store;
        match value {
            Some(v) => {
                if let Err(e) = store.put_secret(name, v).await {
                    tracing::warn!(error = %e, "a Doppler secret could not be put back");
                }
            }
            None => store.delete_secret(name).await,
        }
    }

    // Writes through the normal config update path; a bind is strictly validated, a restore or removal is not.
    async fn set_binding(
        &self,
        actor: &str,
        id: &str,
        binding: Option<DopplerBinding>,
        action: &str,
        detail: &str,
        strict: bool,
    ) -> Result<()> {
        let _gate = self.deployer.config_lock().lock().await;
        let sid = id.to_string();
        self.deployer
            .store
            .update_detailed(actor, action, detail, move |cfg| {
                let site = site_mut(cfg, &sid)?;
                let source = site.source.as_mut().ok_or_else(|| not_built(&sid))?;
                source.doppler = binding;
                if strict {
                    validate_site_strict(site)?;
                }
                Ok(())
            })
            .await?;
        self.deployer.site_ops.invalidate(id);
        Ok(())
    }

    pub async fn unbind(self: &Arc<Self>, actor: &str, id: &str) -> Result<DopplerView> {
        let (this, actor, sid) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.unbind_inner(&actor, &sid).await }).await
    }

    // Manual variables stay; the running site keeps the synced values until its next deploy.
    async fn unbind_inner(&self, actor: &str, id: &str) -> Result<DopplerView> {
        if self.deployer.get_site(id)?.source.is_none() {
            return Err(not_built(id));
        }
        let gate = self.gate(id);
        let _held = gate.lock().await;
        let site = self.deployer.get_site(id)?;
        let store = &self.deployer.store;
        let mut had_values = false;
        for kind in [EnvKind::Build, EnvKind::Runtime] {
            let name = doppler::snapshot_secret(id, kind);
            had_values |= store.get_secret(&name).await.is_some();
        }
        if binding_of(&site).is_some() {
            let detail = format!("site={id}");
            self.set_binding(actor, id, None, "site.doppler.unbind", &detail, false)
                .await?;
        }
        for kind in [EnvKind::Build, EnvKind::Runtime] {
            store
                .delete_secret(&doppler::snapshot_secret(id, kind))
                .await;
        }
        store.delete_secret(&doppler::token_secret(id)).await;
        let now = self.clock.now();
        lock(&self.states).insert(
            id.to_string(),
            SyncState {
                redeploy_needed: had_values.then_some(now),
                ..SyncState::default()
            },
        );
        self.view(id).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use cite_edge::status::BuildEnvPatch;
    use futures_util::future::BoxFuture;
    use serde_json::json;

    use super::*;
    use crate::doppler::Downloaded;
    use crate::haproxy::Haproxy;
    use crate::store::Store;
    use crate::store::testing::test_config;

    const SITE_TOKEN: &str = "dp.st.site.secretvalue";
    const NODE_TOKEN: &str = "dp.pt.node.secretvalue";

    struct FakeClock(AtomicU64);

    impl Clock for FakeClock {
        fn now(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl FakeClock {
        fn advance(&self, secs: u64) {
            self.0.fetch_add(secs, Ordering::SeqCst);
        }
    }

    struct FakeSource {
        answer: StdMutex<std::result::Result<BTreeMap<String, String>, DopplerError>>,
        calls: AtomicUsize,
        tokens: StdMutex<Vec<String>>,
    }

    impl FakeSource {
        fn set(&self, pairs: &[(&str, &str)]) {
            *lock(&self.answer) = Ok(pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect());
        }

        fn fail(&self, err: DopplerError) {
            *lock(&self.answer) = Err(err);
        }
    }

    impl DopplerSource for FakeSource {
        fn projects<'a>(
            &'a self,
            _token: &'a DopplerToken,
        ) -> BoxFuture<'a, std::result::Result<Vec<DopplerProject>, DopplerError>> {
            Box::pin(async {
                Ok(vec![DopplerProject {
                    slug: "shop".into(),
                    name: "Shop".into(),
                }])
            })
        }

        fn configs<'a>(
            &'a self,
            _token: &'a DopplerToken,
            _project: &'a str,
        ) -> BoxFuture<'a, std::result::Result<Vec<DopplerConfig>, DopplerError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn download<'a>(
            &'a self,
            token: &'a DopplerToken,
            _project: &'a str,
            _config: &'a str,
        ) -> BoxFuture<'a, std::result::Result<Downloaded, DopplerError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                lock(&self.tokens).push(token.expose().to_string());
                lock(&self.answer).clone().map(|vars| Downloaded {
                    vars,
                    not_text: Vec::new(),
                })
            })
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        deployer: Arc<Deployer>,
        source: Arc<FakeSource>,
        clock: Arc<FakeClock>,
        sync: Arc<DopplerSync>,
    }

    async fn rig(node_token: bool) -> Rig {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        let store = Store::open(&cfg).await.expect("store");
        let haproxy = Arc::new(Haproxy::new(&cfg));
        let deployer = Arc::new(Deployer::new(Arc::clone(&store), haproxy, None));
        let site: Site = serde_json::from_value(json!({
            "id": "shop", "name": "Shop", "hosts": ["shop.example.com"],
            "blue": { "targets": [{ "addr": "10.0.0.1:8080" }] },
            "green": { "targets": [] }, "active": "blue",
            "source": { "repo": "octo/shop" }
        }))
        .expect("site");
        store
            .update("test", "seed", move |cfg| {
                cfg.sites.push(site);
                Ok(())
            })
            .await
            .expect("seed");
        let source = Arc::new(FakeSource {
            answer: StdMutex::new(Ok(BTreeMap::new())),
            calls: AtomicUsize::new(0),
            tokens: StdMutex::default(),
        });
        let clock = Arc::new(FakeClock(AtomicU64::new(1_800_000_000)));
        let token = node_token.then(|| DopplerToken::parse(NODE_TOKEN).unwrap());
        let mut sync = DopplerSync::with_parts(
            Arc::clone(&deployer),
            Arc::clone(&source) as Arc<dyn DopplerSource>,
            token,
            300,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        Arc::get_mut(&mut sync).expect("sole owner").spread = |_| 0;
        Rig {
            _dir: dir,
            deployer,
            source,
            clock,
            sync,
        }
    }

    fn binding(build: bool, runtime: bool) -> DopplerBinding {
        DopplerBinding {
            project: "shop".into(),
            config: "prd".into(),
            build,
            runtime,
        }
    }

    async fn audit_text(r: &Rig) -> String {
        serde_json::to_string(&r.deployer.store.audit_tail(200).await).unwrap()
    }

    #[test]
    fn backoff_doubles_is_capped_and_respects_retry_after() {
        assert_eq!(backoff(1, 300, None), 60);
        assert_eq!(backoff(2, 300, None), 120);
        assert_eq!(backoff(3, 300, None), 240);
        assert_eq!(backoff(4, 300, None), 300);
        assert_eq!(backoff(40, 86_400, None), 3600);
        assert_eq!(backoff(1, 300, Some(90)), 90);
        assert_eq!(backoff(3, 300, Some(10)), 240);
        assert_eq!(backoff(1, 300, Some(1_000_000)), 3600);
        assert_eq!(backoff(0, 60, None), 60);
    }

    #[test]
    fn the_state_machine_moves_through_sync_success_and_failure() {
        let mut s = SyncState::default();
        assert!(s.is_due(0));
        s.begin();
        assert_eq!(s.phase, Phase::Syncing);
        assert!(!s.is_due(u64::MAX), "a running sync is never claimed again");
        s.fail(1000, 300, &DopplerError::Rejected);
        assert_eq!((s.phase, s.failures, s.next_due), (Phase::Error, 1, 1060));
        s.fail(1100, 300, &DopplerError::RateLimited { retry_after: Some(500) });
        assert_eq!((s.failures, s.next_due), (2, 1600));
        assert!(!s.is_due(1599) && s.is_due(1600));
        let skipped = vec![Skipped {
            name: "PATH".into(),
            reason: "build env: PATH is reserved and cannot be set".into(),
        }];
        s.succeed(2000, 300, skipped);
        assert_eq!((s.phase, s.failures, s.next_due), (Phase::Synced, 0, 2300));
        assert_eq!(s.last_sync_at, Some(2000));
        assert!(s.last_error.as_deref().unwrap().contains("skipped 1 Doppler variables: PATH"));
        s.succeed(2300, 300, Vec::new());
        assert_eq!(s.last_error, None);
    }

    #[test]
    fn a_redeploy_waits_for_a_running_operation() {
        assert_eq!(plan_redeploy(true, false), RedeployPlan::Start);
        assert_eq!(plan_redeploy(true, true), RedeployPlan::Wait);
        assert_eq!(plan_redeploy(false, true), RedeployPlan::Wait);
        assert_eq!(plan_redeploy(false, false), RedeployPlan::Unavailable);
    }

    #[tokio::test]
    async fn a_bind_syncs_stores_the_snapshot_and_asks_for_a_redeploy() {
        let r = rig(false).await;
        r.source.set(&[("API_URL", "https://api"), ("DOPPLER_CONFIG", "prd"), ("PORT", "1")]);
        let token = Some(Zeroizing::new(SITE_TOKEN.to_string()));
        let view = r
            .sync
            .bind("admin", "shop", binding(true, true), token)
            .await
            .expect("bind");
        assert!(view.bound && view.build && view.runtime);
        assert_eq!(view.status, "synced");
        assert_eq!(view.token_source, "site");
        assert_eq!(view.keys, 2, "API_URL for both kinds and PORT for the build");
        assert!(view.redeploy_needed, "a bind means a redeploy; there is no orchestrator here");
        assert_eq!(*lock(&r.source.tokens), [SITE_TOKEN]);
        let build = r.deployer.doppler_snapshot("shop", EnvKind::Build).await;
        assert_eq!(build.keys().collect::<Vec<_>>(), ["API_URL", "PORT"]);
        let runtime = r.deployer.doppler_snapshot("shop", EnvKind::Runtime).await;
        assert_eq!(runtime.keys().collect::<Vec<_>>(), ["API_URL"]);
        let skipped: Vec<&str> = view.skipped.iter().map(|s| s.name.as_str()).collect();
        assert!(skipped.contains(&"DOPPLER_CONFIG") && skipped.contains(&"PORT"));
        let stored = r.deployer.get_site("shop").unwrap();
        assert_eq!(stored.source.unwrap().doppler, Some(binding(true, true)));
        let audit = audit_text(&r).await;
        assert!(audit.contains("site.doppler.bind") && audit.contains("site.doppler.sync"));
        assert!(audit.contains("site.doppler.token.set"));
        assert!(!audit.contains("https://api") && !audit.contains("secretvalue"), "{audit}");
        let shown = format!("{view:?} {}", serde_json::to_string(&view).unwrap());
        assert!(!shown.contains("https://api") && !shown.contains("secretvalue"), "{shown}");
    }

    #[tokio::test]
    async fn polls_only_store_and_audit_a_change() {
        let r = rig(true).await;
        r.source.set(&[("A", "1")]);
        r.sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .expect("bind with the node token");
        assert_eq!(*lock(&r.source.tokens), [NODE_TOKEN]);
        let syncs = |text: &str| text.matches("site.doppler.sync").count();
        let before = syncs(&audit_text(&r).await);
        r.sync.sync_site(ACTOR, "shop", false).await.expect("same");
        assert_eq!(syncs(&audit_text(&r).await), before, "no change, no audit");
        r.source.set(&[("A", "2")]);
        r.sync.sync_site(ACTOR, "shop", false).await.expect("changed");
        assert_eq!(syncs(&audit_text(&r).await), before + 1);
        let build = r.deployer.doppler_snapshot("shop", EnvKind::Build).await;
        assert_eq!(build["A"], "2");
        assert!(r
            .deployer
            .doppler_snapshot("shop", EnvKind::Runtime)
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn a_failed_sync_keeps_the_last_good_snapshot_and_backs_off() {
        let r = rig(true).await;
        r.source.set(&[("A", "1")]);
        r.sync
            .bind("admin", "shop", binding(true, true), None)
            .await
            .expect("bind");
        r.source.fail(DopplerError::RateLimited {
            retry_after: Some(120),
        });
        let err = r.sync.sync_now("admin", "shop").await.unwrap_err();
        assert_eq!(err.status(), 429);
        let view = r.sync.view("shop").await.unwrap();
        assert_eq!(view.status, "error");
        assert!(view.last_error.unwrap().contains("rate limiting"));
        assert_eq!(view.keys, 1);
        assert_eq!(
            r.deployer.doppler_snapshot("shop", EnvKind::Build).await["A"],
            "1"
        );
        let now = r.clock.now();
        assert_eq!(r.sync.state("shop").unwrap().next_due, now + 120);
        assert!(r.sync.claim_due(now + 119).is_empty());
        assert_eq!(r.sync.claim_due(now + 120), ["shop"]);
        assert!(r.sync.claim_due(now + 121).is_empty(), "a claimed site waits a full interval");
    }

    #[tokio::test]
    async fn a_config_over_the_limits_is_refused_without_touching_the_snapshot() {
        let r = rig(true).await;
        r.source.set(&[("A", "1")]);
        r.sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .expect("bind");
        let many: Vec<(String, String)> = (0..129).map(|i| (format!("K{i}"), "v".into())).collect();
        let pairs: Vec<(&str, &str)> = many.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        r.source.set(&pairs);
        let err = r.sync.sync_site(ACTOR, "shop", false).await.unwrap_err();
        assert!(err.to_string().contains("128"), "{err}");
        assert_eq!(
            r.deployer.doppler_snapshot("shop", EnvKind::Build).await.len(),
            1
        );
    }

    #[tokio::test]
    async fn a_failed_bind_leaves_nothing_behind() {
        let r = rig(false).await;
        let none = r
            .sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .unwrap_err();
        assert_eq!(none.to_string(), doppler::NO_TOKEN);
        r.source.fail(DopplerError::Rejected);
        let token = Some(Zeroizing::new(SITE_TOKEN.to_string()));
        let err = r
            .sync
            .bind("admin", "shop", binding(true, false), token)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rejected"), "{err}");
        assert!(!err.to_string().contains("secretvalue"));
        let site = r.deployer.get_site("shop").unwrap();
        assert_eq!(site.source.unwrap().doppler, None);
        assert!(r
            .deployer
            .store
            .get_secret(&doppler::token_secret("shop"))
            .await
            .is_none());
        let view = r.sync.view("shop").await.unwrap();
        assert!(!view.bound && view.status == "idle" && view.token_source == "none");
        assert!(r.sync.state("shop").is_none());
    }

    #[tokio::test]
    async fn a_failed_rebind_restores_the_previous_binding_and_values() {
        let r = rig(true).await;
        r.source.set(&[("A", "1")]);
        r.sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .expect("bind");
        r.source.fail(DopplerError::NotFound);
        let other = DopplerBinding {
            config: "stg".into(),
            ..binding(false, true)
        };
        assert!(r.sync.bind("admin", "shop", other, None).await.is_err());
        let site = r.deployer.get_site("shop").unwrap();
        assert_eq!(site.source.unwrap().doppler, Some(binding(true, false)));
        assert_eq!(
            r.deployer.doppler_snapshot("shop", EnvKind::Build).await["A"],
            "1"
        );
        assert_eq!(r.sync.view("shop").await.unwrap().status, "synced");
    }

    #[tokio::test]
    async fn manual_variables_override_the_synced_ones_at_deploy_time() {
        let r = rig(true).await;
        r.source.set(&[("A", "doppler"), ("B", "doppler")]);
        r.sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .expect("bind");
        let patch = BuildEnvPatch {
            set: [("B".to_string(), "manual".to_string())].into(),
            unset: Vec::new(),
        };
        r.deployer
            .patch_build_env("admin", "shop", patch)
            .await
            .expect("patch");
        let build = r
            .deployer
            .env_opt("shop", EnvKind::Build)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(build["A"], "doppler");
        assert_eq!(build["B"], "manual");
        assert!(r
            .deployer
            .env_opt("shop", EnvKind::Runtime)
            .await
            .unwrap()
            .is_none());
        let redact = r
            .deployer
            .redactions(&r.deployer.get_site("shop").unwrap())
            .await;
        assert!(redact.contains(&"doppler".to_string()));
    }

    #[tokio::test]
    async fn unbinding_drops_synced_values_but_keeps_manual_ones() {
        let r = rig(false).await;
        r.source.set(&[("A", "1")]);
        let token = Some(Zeroizing::new(SITE_TOKEN.to_string()));
        r.sync
            .bind("admin", "shop", binding(true, true), token)
            .await
            .expect("bind");
        let patch = BuildEnvPatch {
            set: [("MANUAL".to_string(), "kept".to_string())].into(),
            unset: Vec::new(),
        };
        r.deployer
            .patch_build_env("admin", "shop", patch)
            .await
            .expect("patch");
        let view = r.sync.unbind("admin", "shop").await.expect("unbind");
        assert!(!view.bound && view.redeploy_needed);
        assert_eq!(view.last_error.as_deref(), Some(UNBOUND_NOTE));
        assert_eq!(view.token_source, "none");
        for kind in [EnvKind::Build, EnvKind::Runtime] {
            assert!(r.deployer.doppler_snapshot("shop", kind).await.is_empty());
        }
        let manual = r.deployer.env_map("shop", EnvKind::Build).await.unwrap();
        assert_eq!(manual["MANUAL"], "kept");
        assert!(r.sync.sync_site(ACTOR, "shop", false).await.is_err());
        assert!(audit_text(&r).await.contains("site.doppler.unbind"));
    }

    #[tokio::test]
    async fn a_redeploy_that_meets_a_running_operation_waits_for_it() {
        let r = rig(true).await;
        r.source.set(&[("A", "1")]);
        let op = r
            .deployer
            .site_ops
            .ops
            .begin("shop", "deploy", None, None, "building");
        r.sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .expect("bind");
        let view = r.sync.view("shop").await.unwrap();
        assert!(view.pending_redeploy && !view.redeploy_needed);
        r.sync.flush_pending().await;
        assert!(r.sync.state("shop").unwrap().pending_redeploy, "still busy");
        drop(op);
        r.sync.flush_pending().await;
        let state = r.sync.state("shop").unwrap();
        assert!(!state.pending_redeploy);
        assert!(state.redeploy_needed.is_some(), "without an orchestrator the redeploy is only flagged");
    }

    #[tokio::test]
    async fn only_bound_sites_are_claimed_and_deleted_sites_are_forgotten() {
        let r = rig(true).await;
        let now = r.clock.now();
        assert!(r.sync.claim_due(now).is_empty());
        r.source.set(&[("A", "1")]);
        r.sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .expect("bind");
        assert!(r.sync.claim_due(now).is_empty(), "the bind just synced");
        r.clock.advance(300);
        assert_eq!(r.sync.claim_due(r.clock.now()), ["shop"]);
        r.deployer
            .store
            .update("test", "drop", |cfg| {
                cfg.sites.clear();
                Ok(())
            })
            .await
            .unwrap();
        r.clock.advance(600);
        assert!(r.sync.claim_due(r.clock.now()).is_empty());
        assert!(r.sync.state("shop").is_none());
    }

    #[tokio::test]
    async fn a_rate_limited_node_token_pauses_every_node_token_request() {
        let r = rig(true).await;
        r.source.set(&[("A", "1")]);
        r.sync
            .bind("admin", "shop", binding(true, false), None)
            .await
            .expect("bind");
        r.source.fail(DopplerError::RateLimited { retry_after: Some(120) });
        assert!(r.sync.sync_site(ACTOR, "shop", false).await.is_err());
        let calls = r.source.calls.load(Ordering::SeqCst);
        r.source.set(&[("A", "2")]);
        let err = r.sync.sync_site(ACTOR, "shop", false).await.unwrap_err();
        assert_eq!(err.status(), 429);
        assert!(r.sync.projects().await.is_err());
        assert_eq!(r.source.calls.load(Ordering::SeqCst), calls, "nothing was sent while paused");
        r.clock.advance(120);
        r.sync.sync_site(ACTOR, "shop", false).await.expect("the pause is over");
        assert_eq!(r.deployer.doppler_snapshot("shop", EnvKind::Build).await["A"], "2");
    }

    #[test]
    fn next_due_spreads_by_at_most_a_tenth_of_the_interval() {
        for _ in 0..50 {
            assert!(jitter_secs(300) <= 30);
            assert!(jitter_secs(86_400) <= MAX_JITTER_SECS);
        }
        assert_eq!(jitter_secs(5), 0);
    }

    #[tokio::test]
    async fn a_sync_does_not_write_a_snapshot_for_a_binding_that_changed() {
        let r = rig(true).await;
        r.source.set(&[("A", "1")]);
        let mut stale = r.deployer.get_site("shop").unwrap();
        stale.source.as_mut().unwrap().doppler = Some(binding(true, false));
        let err = r.sync.fetch_and_store(&stale, &binding(true, false)).await.err().unwrap();
        assert!(err.to_string().contains("binding changed"), "{err}");
        assert!(r.deployer.doppler_snapshot("shop", EnvKind::Build).await.is_empty());
    }

    #[tokio::test]
    async fn deleting_a_site_waits_for_its_running_sync() {
        let r = rig(true).await;
        let gate = r.deployer.doppler_gate("shop");
        let held = gate.lock().await;
        let deployer = Arc::clone(&r.deployer);
        let delete = tokio::spawn(async move { deployer.delete_site("admin", "shop").await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!delete.is_finished(), "the delete waits for the sync gate");
        assert!(r.deployer.get_site("shop").is_ok());
        drop(held);
        let _ = tokio::time::timeout(Duration::from_secs(10), delete)
            .await
            .expect("the delete goes ahead once the sync is done");
    }

    #[test]
    fn a_redeploy_is_seen_in_the_history() {
        let mut site: Site = serde_json::from_value(json!({
            "id": "a", "name": "a", "hosts": ["a.com"],
            "blue": { "targets": [] }, "green": { "targets": [] }, "active": "blue"
        }))
        .unwrap();
        assert!(!redeployed_since(&site, 100));
        site.history.push(cite_edge::model::Deployment {
            id: "d".into(),
            at: unix_to_rfc3339(200),
            slot: cite_edge::model::Slot::Green,
            action: DeployAction::Promote,
            note: String::new(),
        });
        assert!(redeployed_since(&site, 100) && redeployed_since(&site, 200));
        assert!(!redeployed_since(&site, 201));
    }
}
