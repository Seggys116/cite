//! Site status, logs, the per-site GitHub token and the build and runtime env secrets.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use cite_edge::model::{DeployAction, Site, Slot};
use cite_edge::runtime::BackendStat;
use cite_edge::status::{
    BuildEnvNames, BuildEnvPatch, LastFailure, LogLine, LogsResponse, ManagerReport, OperationInfo,
    SiteStatus, SlotStatus, TokenStatus,
};
use futures_util::future::BoxFuture;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::sleep;
use zeroize::Zeroizing;

use crate::deploy::{Deployer, detach, secret_name, site_mut, upstream};
use crate::doppler;
use crate::error::{ConnectorError, Result};
use crate::orchestrator::{LogRole, LogsBatch, Orchestrator, SlotInspect, StackOpts};
use crate::store::now_rfc3339;

const STATUS_TTL: Duration = Duration::from_secs(2);
const LOGS_PER_SITE: usize = 1;
const LOGS_TOTAL: usize = 4;
pub(crate) const RESTART_LOOP: u32 = 3;
const ERROR_TAIL: u32 = 200;
const ERROR_LINES: usize = 3;
const NO_RELEASE: &str = "no release ready: a build is running or failed";
const DEPLOY_ID_ENV: &str = "CITE_DEPLOY_ID=";
pub(crate) const TOKEN_RESTORE: &str = "site.github_token.restore";
// The store audits every config write; this names the token reference change it makes.
const TOKEN_REF: &str = "site.github_token.ref";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogQuery {
    pub source: LogSource,
    pub slot: Option<Slot>,
    pub tail: u32,
    pub since: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogSource {
    #[default]
    Manager,
    Executor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvKind {
    Build,
    Runtime,
}

// Maps each slot to the repository its work and cache volumes were last used with; a dot keeps it apart from token secrets.
pub(crate) fn repo_record(site_id: &str) -> String {
    format!("site-{site_id}.volume-repos")
}

impl EnvKind {
    // A dot cannot occur in a site id, so these never collide with another site's token secret.
    pub(crate) fn secret(self, site_id: &str) -> String {
        match self {
            EnvKind::Build => format!("site-{site_id}.build-env"),
            EnvKind::Runtime => format!("site-{site_id}.runtime-env"),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            EnvKind::Build => "build env",
            EnvKind::Runtime => "runtime env",
        }
    }

    // The manager and the executor refuse different names at startup, so each kind has its own rules.
    pub(crate) fn validate(
        self,
        patch: &BuildEnvPatch,
    ) -> std::result::Result<(), cite_edge::validate::ValidationError> {
        match self {
            EnvKind::Build => patch.validate(),
            EnvKind::Runtime => patch.validate_runtime(),
        }
    }
}

pub(crate) struct LogRequest<'a> {
    pub site_id: &'a str,
    pub slot: Slot,
    pub role: LogRole,
    pub tail: u32,
    pub since: Option<&'a str>,
    pub redact: &'a [String],
}

/// The container reads status, deploys and logs depend on; the orchestrator in production.
pub(crate) trait SlotProbe: Send + Sync {
    fn inspect<'a>(&'a self, site_id: &'a str, slot: Slot) -> BoxFuture<'a, Result<SlotInspect>>;
    fn logs<'a>(&'a self, req: LogRequest<'a>) -> BoxFuture<'a, Result<LogsBatch>>;
}

impl SlotProbe for Orchestrator {
    fn inspect<'a>(&'a self, site_id: &'a str, slot: Slot) -> BoxFuture<'a, Result<SlotInspect>> {
        Box::pin(self.inspect_slot(site_id, slot))
    }

    fn logs<'a>(&'a self, req: LogRequest<'a>) -> BoxFuture<'a, Result<LogsBatch>> {
        Box::pin(self.container_logs(
            req.site_id,
            req.slot,
            req.role,
            req.tail,
            req.since,
            req.redact,
        ))
    }
}

#[derive(Default)]
pub(crate) struct Operations {
    seq: AtomicU64,
    live: StdMutex<HashMap<String, (u64, OperationInfo)>>,
}

impl Operations {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, (u64, OperationInfo)>> {
        self.live.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        site: &str,
        kind: &str,
        slot: Option<Slot>,
        deploy_id: Option<&str>,
        step: &str,
    ) -> OpGuard {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let info = OperationInfo {
            kind: kind.to_string(),
            slot,
            deploy_id: deploy_id.map(str::to_string),
            step: step.to_string(),
            started_at: now_rfc3339(),
        };
        self.lock().insert(site.to_string(), (seq, info));
        OpGuard {
            ops: Arc::clone(self),
            site: site.to_string(),
            seq,
        }
    }

    pub(crate) fn current(&self, site: &str) -> Option<OperationInfo> {
        self.lock().get(site).map(|(_, info)| info.clone())
    }
}

// Dropping the guard clears the entry, so an error, a panic or an early return never leaves a stale operation.
pub(crate) struct OpGuard {
    ops: Arc<Operations>,
    site: String,
    seq: u64,
}

impl OpGuard {
    pub(crate) fn step(&self, step: &str) {
        if let Some((seq, info)) = self.ops.lock().get_mut(&self.site)
            && *seq == self.seq
        {
            info.step = step.to_string();
        }
    }
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        let mut live = self.ops.lock();
        if live
            .get(&self.site)
            .is_some_and(|(seq, _)| *seq == self.seq)
        {
            live.remove(&self.site);
        }
    }
}

#[derive(Debug, Clone)]
struct Snapshot {
    at: Instant,
    active: Slot,
    checked_at: String,
    slots: Vec<SlotStatus>,
    settings_current: bool,
}

/// Per-site state that is read without the site lock: running operations, cached slot reads and log gates.
pub(crate) struct SiteOps {
    pub(crate) ops: Arc<Operations>,
    snapshots: StdMutex<HashMap<String, Snapshot>>,
    log_site: StdMutex<HashMap<String, Arc<Semaphore>>>,
    log_all: Arc<Semaphore>,
}

impl Default for SiteOps {
    fn default() -> Self {
        SiteOps {
            ops: Arc::default(),
            snapshots: StdMutex::default(),
            log_site: StdMutex::default(),
            log_all: Arc::new(Semaphore::new(LOGS_TOTAL)),
        }
    }
}

impl SiteOps {
    fn cached(&self, id: &str, active: Slot) -> Option<Snapshot> {
        let snaps = self.snapshots.lock().unwrap_or_else(|p| p.into_inner());
        snaps
            .get(id)
            .filter(|s| s.active == active && s.at.elapsed() < STATUS_TTL)
            .cloned()
    }

    fn keep(&self, id: &str, snap: Snapshot) {
        let mut snaps = self.snapshots.lock().unwrap_or_else(|p| p.into_inner());
        snaps.insert(id.to_string(), snap);
    }

    pub(crate) fn invalidate(&self, id: &str) {
        let mut snaps = self.snapshots.lock().unwrap_or_else(|p| p.into_inner());
        snaps.remove(id);
    }

    pub(crate) fn forget(&self, id: &str) {
        self.invalidate(id);
        let mut gates = self.log_site.lock().unwrap_or_else(|p| p.into_inner());
        gates.remove(id);
    }

    pub(crate) fn log_permits(&self, id: &str) -> Result<[OwnedSemaphorePermit; 2]> {
        let gate = {
            let mut gates = self.log_site.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(
                gates
                    .entry(id.to_string())
                    .or_insert_with(|| Arc::new(Semaphore::new(LOGS_PER_SITE))),
            )
        };
        let busy = |what: &str| {
            ConnectorError::TooManyRequests(format!(
                "{what} log reads are already running; try again shortly"
            ))
        };
        let one = gate
            .try_acquire_owned()
            .map_err(|_| busy(&format!("site {id}")))?;
        let all = Arc::clone(&self.log_all)
            .try_acquire_owned()
            .map_err(|_| busy("too many"))?;
        Ok([one, all])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenVerdict {
    Accepted,
    Invalid,
    Unknown,
    Unchecked,
}

pub(crate) fn env_value(env: &[String], prefix: &str) -> Option<String> {
    env.iter()
        .find_map(|e| e.strip_prefix(prefix))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

pub(crate) fn restart_text(slot: Slot, restarts: u32, oom: bool) -> String {
    let oom = if oom {
        ", killed for running out of memory"
    } else {
        ""
    };
    format!(
        "the {} build manager keeps restarting ({restarts} restarts{oom})",
        slot.as_str()
    )
}

fn is_error_line(line: &LogLine) -> bool {
    line.level
        .as_deref()
        .is_some_and(|l| l.eq_ignore_ascii_case("error"))
        || line.text.contains("ERROR")
}

fn last_errors(lines: &[LogLine]) -> Vec<String> {
    let mut found: Vec<String> = lines
        .iter()
        .rev()
        .filter(|l| is_error_line(l))
        .map(|l| l.text.trim().to_string())
        .filter(|t| !t.is_empty())
        .take(ERROR_LINES)
        .collect();
    found.reverse();
    found
}

fn unix_text(nanos: i128) -> String {
    let secs = nanos.div_euclid(1_000_000_000);
    let frac = nanos.rem_euclid(1_000_000_000);
    format!("{secs}.{frac:09}")
}

// Docker's `since` takes Unix seconds; one nanosecond past the last line keeps that line from repeating.
fn cursor_after(ts: &str) -> Option<String> {
    OffsetDateTime::parse(ts, &Rfc3339)
        .ok()
        .map(|t| unix_text(t.unix_timestamp_nanos() + 1))
}

fn docker_since(since: &str) -> String {
    OffsetDateTime::parse(since, &Rfc3339)
        .map(|t| unix_text(t.unix_timestamp_nanos()))
        .unwrap_or_else(|_| since.to_string())
}

fn translate_check(check: &str, orchestrated: bool) -> Option<String> {
    if check.is_empty() {
        None
    } else if orchestrated && check.starts_with("L7STS") {
        Some(NO_RELEASE.to_string())
    } else {
        Some(check.to_string())
    }
}

// The worst server of the slot speaks for it, so one down target is never hidden behind a healthy one.
fn haproxy_view(
    stats: Option<&[BackendStat]>,
    site: &Site,
    slot: Slot,
    orchestrated: bool,
) -> (Option<String>, Option<String>) {
    let targets = upstream(site, slot).targets.len();
    let backend = format!("be_{}_{}", site.id, slot.as_str());
    let Some(found) = stats.and_then(|all| all.iter().find(|b| b.name == backend)) else {
        return (None, None);
    };
    let servers: Vec<_> = (1..=targets)
        .filter_map(|i| {
            let name = format!("t{i}");
            found.servers.iter().find(|s| s.name == name)
        })
        .collect();
    let pick = servers
        .iter()
        .find(|s| !s.status.starts_with("UP"))
        .or(servers.first());
    match pick {
        Some(s) => (
            Some(s.status.clone()),
            translate_check(&s.check, orchestrated),
        ),
        None => (None, None),
    }
}

fn report_error(slot: &SlotStatus) -> Option<String> {
    if slot.restart_count >= RESTART_LOOP {
        return Some(restart_text(slot.slot, slot.restart_count, slot.oom_killed));
    }
    if slot.oom_killed {
        return Some(format!(
            "the {} build manager was killed for running out of memory",
            slot.slot.as_str()
        ));
    }
    let report = slot.report.as_ref()?;
    (report.phase == "failed").then(|| {
        report
            .last_error
            .clone()
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| "the last build failed".to_string())
    })
}

fn release_error(slot: &SlotStatus) -> Option<String> {
    let executor = slot.report.as_ref()?.executor.as_ref()?;
    executor["active"]
        .is_null()
        .then(|| "the executor has no release yet".to_string())
}

fn check_error(slot: &SlotStatus) -> Option<String> {
    let up = slot.haproxy.as_deref().is_some_and(|s| s.starts_with("UP"));
    if up { None } else { slot.haproxy_check.clone() }
}

fn idle_phase(active: Option<&SlotStatus>, failing: bool) -> String {
    if let Some(phase) = active
        .and_then(|s| s.report.as_ref())
        .map(|r| r.phase.as_str())
        .filter(|p| !p.is_empty())
    {
        return phase.to_string();
    }
    let down = active
        .and_then(|s| s.haproxy.as_deref())
        .is_some_and(|s| !s.starts_with("UP"));
    if failing || down {
        "unhealthy".to_string()
    } else {
        "idle".to_string()
    }
}

fn apply_patch(
    mut current: BTreeMap<String, String>,
    patch: &BuildEnvPatch,
    label: &str,
) -> Result<BTreeMap<String, String>> {
    for key in &patch.unset {
        current.remove(key);
    }
    for (key, value) in &patch.set {
        current.insert(key.clone(), value.clone());
    }
    doppler::env_limits(&current, label).map_err(ConnectorError::BadRequest)?;
    Ok(current)
}

impl Deployer {
    pub(crate) fn probe(&self) -> Result<Arc<dyn SlotProbe>> {
        self.probe.clone().ok_or_else(|| {
            ConnectorError::BadRequest("orchestration is not enabled on this node".into())
        })
    }

    /// Answers from the store and Docker only, never behind the site lock, so a long deploy cannot block it.
    pub async fn site_status(&self, id: &str) -> Result<SiteStatus> {
        let site = self.get_site(id)?;
        let snap = self.snapshot(&site).await;
        let operation = self.site_ops.ops.current(id);
        let last_failure = site
            .history
            .iter()
            .rev()
            .find(|d| d.action == DeployAction::Failed)
            .map(|d| LastFailure {
                at: d.at.clone(),
                slot: Some(d.slot),
                note: d.note.clone(),
            });
        let unresolved = site
            .history
            .last()
            .filter(|d| d.action == DeployAction::Failed)
            .map(|d| d.note.clone());
        let active = snap.slots.iter().find(|s| s.slot == site.active);
        let error = active
            .and_then(report_error)
            .or(unresolved)
            .or_else(|| active.and_then(release_error))
            .or_else(|| active.and_then(check_error));
        let phase = match &operation {
            Some(op) => op.step.clone(),
            None => idle_phase(active, error.is_some()),
        };
        Ok(SiteStatus {
            phase,
            error,
            active: site.active,
            operation,
            last_failure,
            slots: snap.slots,
            settings_current: snap.settings_current,
            checked_at: snap.checked_at,
        })
    }

    async fn snapshot(&self, site: &Site) -> Snapshot {
        if let Some(hit) = self.site_ops.cached(&site.id, site.active) {
            return hit;
        }
        let stats = self.haproxy.stats().await.ok();
        let orchestrated = site.source.is_some();
        let probe = if orchestrated {
            self.probe.clone()
        } else {
            None
        };
        let mut settings_current = !orchestrated;
        let mut slots = Vec::with_capacity(2);
        for slot in [Slot::Blue, Slot::Green] {
            let (haproxy, haproxy_check) = haproxy_view(stats.as_deref(), site, slot, orchestrated);
            let mut status = SlotStatus {
                slot,
                haproxy,
                haproxy_check,
                ..SlotStatus::default()
            };
            if let Some(probe) = &probe {
                match probe.inspect(&site.id, slot).await {
                    Ok(seen) => {
                        if slot == site.active
                            && let Some(orch) = &self.orchestrator
                        {
                            settings_current = orch.settings_current(site, &seen);
                        }
                        status.container = seen.state;
                        status.health = seen.health;
                        status.restart_count = seen.restart_count;
                        status.exit_code = seen.exit_code;
                        status.oom_killed = seen.oom_killed;
                        status.report = seen.manager_report;
                    }
                    Err(err) => {
                        tracing::debug!("slot {}/{} unreadable: {err}", site.id, slot.as_str());
                        status.container = "unknown".to_string();
                    }
                }
            }
            slots.push(status);
        }
        let snap = Snapshot {
            at: Instant::now(),
            active: site.active,
            checked_at: now_rfc3339(),
            slots,
            settings_current,
        };
        self.site_ops.keep(&site.id, snap.clone());
        snap
    }

    /// True when the stored source settings differ from the ones the live manager runs with.
    pub async fn pending_redeploy(&self, site: &Site) -> bool {
        let (Some(_), Some(orch), Some(probe)) = (&site.source, &self.orchestrator, &self.probe)
        else {
            return false;
        };
        match probe.inspect(&site.id, site.active).await {
            Ok(seen) if seen.state != "missing" => !orch.settings_current(site, &seen),
            _ => false,
        }
    }

    pub async fn site_logs(&self, id: &str, q: LogQuery) -> Result<LogsResponse> {
        let site = self.get_site(id)?;
        let probe = self.probe()?;
        let _permits = self.site_ops.log_permits(id)?;
        let failed_slot = site
            .history
            .last()
            .filter(|d| d.action == DeployAction::Failed)
            .map(|d| d.slot);
        let slot = q
            .slot
            .or_else(|| self.site_ops.ops.current(id).and_then(|op| op.slot))
            .or(failed_slot)
            .unwrap_or(site.active);
        let role = match q.source {
            LogSource::Manager => LogRole::Manager,
            LogSource::Executor => LogRole::Executor,
        };
        let redact = self.redactions(&site).await;
        let since = q.since.as_deref().map(docker_since);
        let batch = probe
            .logs(LogRequest {
                site_id: id,
                slot,
                role,
                tail: q.tail,
                since: since.as_deref(),
                redact: &redact,
            })
            .await?;
        // Without a Docker timestamp the caller's own cursor is handed back, so nothing repeats or is skipped.
        let cursor = batch.last_ts.as_deref().and_then(cursor_after).or(since);
        Ok(LogsResponse {
            lines: batch.lines,
            cursor,
            truncated: batch.truncated,
        })
    }

    // Every value a log line could leak: the site and node tokens and both env maps.
    pub(crate) async fn redactions(&self, site: &Site) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(name) = site.source.as_ref().and_then(|s| s.secret.as_deref())
            && let Some(token) = self.store.get_secret(name).await
        {
            out.push(token);
        }
        if let Some(token) = self.orchestrator.as_ref().and_then(|o| o.default_token()) {
            out.push(token.to_string());
        }
        out.extend(self.haproxy.zones().secret_for(&site.id));
        for kind in [EnvKind::Build, EnvKind::Runtime] {
            match self.env_map(&site.id, kind).await {
                Ok(map) => out.extend(map.into_values()),
                Err(err) => tracing::warn!("{} of {} unreadable: {err}", kind.label(), site.id),
            }
            out.extend(self.doppler_snapshot(&site.id, kind).await.into_values());
        }
        out.retain(|s| !s.is_empty());
        out.sort();
        out.dedup();
        out
    }

    pub(crate) async fn restart_reason(
        &self,
        site: &Site,
        slot: Slot,
        seen: &SlotInspect,
    ) -> String {
        let base = restart_text(slot, seen.restart_count, seen.oom_killed);
        let Ok(probe) = self.probe() else {
            return base;
        };
        let redact = self.redactions(site).await;
        let lines = probe
            .logs(LogRequest {
                site_id: &site.id,
                slot,
                role: LogRole::Manager,
                tail: ERROR_TAIL,
                since: None,
                redact: &redact,
            })
            .await
            .map(|b| b.lines)
            .unwrap_or_default();
        let errors = last_errors(&lines);
        if errors.is_empty() {
            base
        } else {
            format!("{base}: {}", errors.join(" | "))
        }
    }

    // Work and cache hold one repository's checkout, so another repo needs fresh ones; volumes with no record are reset once.
    pub(crate) async fn prepare_repo_volumes(
        &self,
        orch: &Orchestrator,
        site: &Site,
        slot: Slot,
    ) -> Result<bool> {
        let Some(source) = &site.source else {
            return Ok(false);
        };
        let key = repo_record(&site.id);
        let mut repos: BTreeMap<String, String> = match self.store.get_secret(&key).await {
            Some(text) => serde_json::from_str(&text).unwrap_or_default(),
            None => BTreeMap::new(),
        };
        let recorded = repos.get(slot.as_str());
        if recorded == Some(&source.repo) {
            return Ok(false);
        }
        let stale = match recorded {
            Some(_) => true,
            None => orch.build_volumes_exist(&site.id, slot).await?,
        };
        if stale {
            orch.reset_slot_volumes(&site.id, slot).await?;
        }
        repos.insert(slot.as_str().to_string(), source.repo.clone());
        self.store
            .put_secret(&key, &serde_json::to_string(&repos)?)
            .await?;
        Ok(stale)
    }

    // A restart keeps the deploy id the manager already handled, so it never rebuilds on its own.
    pub(crate) async fn kept_opts(&self, site: &Site, slot: Slot) -> Result<StackOpts> {
        let deploy_id = match &self.probe {
            Some(probe) => probe
                .inspect(&site.id, slot)
                .await
                .ok()
                .and_then(|seen| env_value(&seen.env, DEPLOY_ID_ENV)),
            None => None,
        };
        Ok(StackOpts {
            deploy_id,
            build_env: self.env_opt(&site.id, EnvKind::Build).await?,
            runtime_env: self.env_opt(&site.id, EnvKind::Runtime).await?,
        })
    }

    pub(crate) async fn env_map(
        &self,
        id: &str,
        kind: EnvKind,
    ) -> Result<BTreeMap<String, String>> {
        match self.store.get_secret(&kind.secret(id)).await {
            None => Ok(BTreeMap::new()),
            Some(text) => serde_json::from_str(&text).map_err(|_| {
                ConnectorError::Internal(format!(
                    "the stored {} of {id} is unreadable",
                    kind.label()
                ))
            }),
        }
    }

    // An unreadable snapshot counts as none: the next sync rewrites it, and the manual variables still apply.
    pub(crate) async fn doppler_snapshot(&self, id: &str, kind: EnvKind) -> BTreeMap<String, String> {
        match self
            .store
            .get_secret(&doppler::snapshot_secret(id, kind))
            .await
        {
            Some(text) => serde_json::from_str(&text).unwrap_or_default(),
            None => BTreeMap::new(),
        }
    }

    // Only a kind the binding still feeds contributes, so turning a kind off drops its values at the next deploy.
    async fn synced_for(&self, id: &str, kind: EnvKind) -> Result<BTreeMap<String, String>> {
        let fed = self
            .get_site(id)?
            .source
            .and_then(|s| s.doppler)
            .is_some_and(|b| match kind {
                EnvKind::Build => b.build,
                EnvKind::Runtime => b.runtime,
            });
        if fed {
            Ok(self.doppler_snapshot(id, kind).await)
        } else {
            Ok(BTreeMap::new())
        }
    }

    fn merged(
        synced: BTreeMap<String, String>,
        manual: BTreeMap<String, String>,
        kind: EnvKind,
    ) -> Result<BTreeMap<String, String>> {
        let map = doppler::merge_env(synced, manual);
        doppler::env_limits(&map, kind.label()).map_err(|m| {
            ConnectorError::BadRequest(format!("{m} once the Doppler variables are added"))
        })?;
        Ok(map)
    }

    // The synced Doppler values form the base; manual variables override them.
    pub(crate) async fn env_opt(
        &self,
        id: &str,
        kind: EnvKind,
    ) -> Result<Option<BTreeMap<String, String>>> {
        let manual = self.env_map(id, kind).await?;
        let map = Self::merged(self.synced_for(id, kind).await?, manual, kind)?;
        Ok((!map.is_empty()).then_some(map))
    }

    pub async fn build_env_names(&self, id: &str) -> Result<BuildEnvNames> {
        self.env_names(id, EnvKind::Build).await
    }

    pub async fn runtime_env_names(&self, id: &str) -> Result<BuildEnvNames> {
        self.env_names(id, EnvKind::Runtime).await
    }

    async fn env_names(&self, id: &str, kind: EnvKind) -> Result<BuildEnvNames> {
        self.get_site(id)?;
        let names = self.env_map(id, kind).await?.into_keys().collect();
        Ok(BuildEnvNames { names })
    }

    // The route layer writes the audit entry for these patches, with key names only.
    pub async fn patch_build_env(
        self: &Arc<Self>,
        _actor: &str,
        id: &str,
        patch: BuildEnvPatch,
    ) -> Result<BuildEnvNames> {
        let (this, id) = (Arc::clone(self), id.to_string());
        detach(async move { this.patch_env(&id, EnvKind::Build, patch).await }).await
    }

    pub async fn patch_runtime_env(
        self: &Arc<Self>,
        _actor: &str,
        id: &str,
        patch: BuildEnvPatch,
    ) -> Result<BuildEnvNames> {
        let (this, id) = (Arc::clone(self), id.to_string());
        detach(async move { this.patch_env(&id, EnvKind::Runtime, patch).await }).await
    }

    // The values live only in secrets.json; they reach a stack on the next deploy.
    async fn patch_env(
        &self,
        id: &str,
        kind: EnvKind,
        patch: BuildEnvPatch,
    ) -> Result<BuildEnvNames> {
        kind.validate(&patch)?;
        let lock = self.site_lock(id);
        let _guard = lock.lock().await;
        let site = self.get_site(id)?;
        if site.source.is_none() {
            return Err(ConnectorError::BadRequest(format!(
                "site {id} is not built from a repository, so it has no {}",
                kind.label()
            )));
        }
        let next = apply_patch(self.env_map(id, kind).await?, &patch, kind.label())?;
        Self::merged(self.synced_for(id, kind).await?, next.clone(), kind)?;
        let name = kind.secret(id);
        if next.is_empty() {
            self.store.delete_secret(&name).await;
        } else {
            self.store
                .put_secret(&name, &serde_json::to_string(&next)?)
                .await?;
        }
        Ok(BuildEnvNames {
            names: next.into_keys().collect(),
        })
    }

    pub async fn token_status(&self, id: &str) -> Result<TokenStatus> {
        let site = self.get_site(id)?;
        if site.source.is_none() {
            return Err(ConnectorError::BadRequest(format!(
                "site {id} is not built from a repository, so it has no GitHub token"
            )));
        }
        let report = self.active_report(&site).await;
        let verified = match report.as_ref().and_then(|r| r.token.as_deref()) {
            Some("ok") => Some(true),
            Some("invalid") => Some(false),
            _ => None,
        };
        Ok(self.token_view(&site, report.as_ref(), verified).await)
    }

    pub async fn set_site_token(
        self: &Arc<Self>,
        actor: &str,
        id: &str,
        token: Zeroizing<String>,
    ) -> Result<TokenStatus> {
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.change_token(&actor, &id, Some(token)).await }).await
    }

    pub async fn clear_site_token(self: &Arc<Self>, actor: &str, id: &str) -> Result<TokenStatus> {
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.change_token(&actor, &id, None).await }).await
    }

    async fn active_report(&self, site: &Site) -> Option<ManagerReport> {
        let probe = self.probe.as_ref()?;
        probe
            .inspect(&site.id, site.active)
            .await
            .ok()
            .and_then(|seen| seen.manager_report)
    }

    async fn token_view(
        &self,
        site: &Site,
        report: Option<&ManagerReport>,
        verified: Option<bool>,
    ) -> TokenStatus {
        let own = match site.source.as_ref().and_then(|s| s.secret.as_deref()) {
            Some(name) => self
                .store
                .get_secret(name)
                .await
                .is_some_and(|t| !t.is_empty()),
            None => false,
        };
        let node = self
            .orchestrator
            .as_ref()
            .is_some_and(|o| o.default_token().is_some());
        let source = if own {
            "site"
        } else if node {
            "node"
        } else {
            "none"
        };
        TokenStatus {
            source: source.to_string(),
            site_token_set: own,
            node_token_configured: node,
            status: report.and_then(|r| r.token.clone()),
            expires_at: report.and_then(|r| r.token_expires_at.clone()),
            verified,
        }
    }

    // `None` clears the site token so the site falls back to the node token.
    async fn change_token(
        &self,
        actor: &str,
        id: &str,
        token: Option<Zeroizing<String>>,
    ) -> Result<TokenStatus> {
        let lock = self.site_lock(id);
        let _guard = lock.lock().await;
        let site = self.get_site(id)?;
        let orch = Arc::clone(self.orchestrator()?);
        let Some(source) = site.source.as_ref() else {
            return Err(ConnectorError::BadRequest(format!(
                "site {id} is not built from a repository, so it has no GitHub token"
            )));
        };
        let token = token.filter(|t| !t.is_empty());
        let kept_ref = source.secret.clone();
        if token.is_none() {
            if orch.default_token().is_none() {
                return Err(ConnectorError::Conflict(
                    "this node has no GitHub token (CITE_GITHUB_TOKEN), so the site token cannot be cleared"
                        .into(),
                ));
            }
            if kept_ref.is_none() {
                return Ok(self.token_view(&site, None, None).await);
            }
        }
        let kept_value = match kept_ref.as_deref() {
            Some(name) => self.store.get_secret(name).await,
            None => None,
        };
        let name = secret_name(id);
        let label = if token.is_some() { "site" } else { "node" };
        let op = self
            .site_ops
            .ops
            .begin(id, "token", None, None, "saving the token");
        match &token {
            Some(text) => self.store.put_secret(&name, text.as_str()).await?,
            None => self.store.delete_secret(&name).await,
        }
        let detail = format!("site={id} source={label}");
        let new_ref = token.as_ref().map(|_| name.clone());
        if let Err(err) = self.set_secret_ref(actor, id, new_ref, None, &detail).await {
            self.put_back_secret(&name, kept_ref.as_deref(), kept_value.as_deref())
                .await;
            return Err(err);
        }
        self.site_ops.invalidate(id);
        let changed = self.get_site(id)?;
        op.step("restarting the build manager");
        let verdict = match self.reensure_running(&orch, &changed).await {
            Ok(slots) => {
                op.step("verifying the token");
                self.await_token(id, &slots).await
            }
            Err(err) => {
                self.restore_token(actor, id, &orch, &name, kept_ref, kept_value)
                    .await;
                return Err(err);
            }
        };
        if verdict == TokenVerdict::Invalid {
            self.restore_token(actor, id, &orch, &name, kept_ref, kept_value)
                .await;
            let which = if token.is_some() {
                "the new token"
            } else {
                "the node token"
            };
            return Err(ConnectorError::BadRequest(format!(
                "GitHub refused {which}, so the previous token of {id} was put back"
            )));
        }
        let verified = match verdict {
            TokenVerdict::Accepted => Some(true),
            TokenVerdict::Unknown => Some(false),
            TokenVerdict::Invalid | TokenVerdict::Unchecked => None,
        };
        let report = self.active_report(&changed).await;
        Ok(self.token_view(&changed, report.as_ref(), verified).await)
    }

    async fn put_back_secret(&self, name: &str, kept_ref: Option<&str>, kept_value: Option<&str>) {
        match (kept_ref, kept_value) {
            (Some(kept), Some(value)) => {
                if let Err(err) = self.store.put_secret(kept, value).await {
                    tracing::warn!("previous token secret could not be restored: {err}");
                }
            }
            _ => self.store.delete_secret(name).await,
        }
    }

    async fn restore_token(
        &self,
        actor: &str,
        id: &str,
        orch: &Orchestrator,
        name: &str,
        kept_ref: Option<String>,
        kept_value: Option<String>,
    ) {
        self.put_back_secret(name, kept_ref.as_deref(), kept_value.as_deref())
            .await;
        let label = if kept_ref.is_some() { "site" } else { "node" };
        let detail = format!("site={id} source={label}");
        if let Err(err) = self
            .set_secret_ref(actor, id, kept_ref, Some(TOKEN_RESTORE), &detail)
            .await
        {
            tracing::warn!("token reference of {id} could not be restored: {err}");
        }
        self.site_ops.invalidate(id);
        match self.get_site(id) {
            Ok(site) => {
                if let Err(err) = self.reensure_running(orch, &site).await {
                    tracing::warn!(
                        "managers of {id} could not be restarted on the previous token: {err}"
                    );
                }
            }
            Err(err) => tracing::warn!("site {id} vanished during a token restore: {err}"),
        }
    }

    // Set and clear are audited by the route layer; details never hold the token or its length.
    async fn set_secret_ref(
        &self,
        actor: &str,
        id: &str,
        secret: Option<String>,
        audit: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        let current = self.get_site(id)?.source.and_then(|s| s.secret);
        if current == secret {
            if let Some(action) = audit {
                self.store.audit(actor, action, detail).await;
            }
            return Ok(());
        }
        let action = audit.unwrap_or(TOKEN_REF);
        let _gate = self.config_lock().lock().await;
        let sid = id.to_string();
        self.store
            .update_detailed(actor, action, detail, move |cfg| {
                if let Some(source) = site_mut(cfg, &sid)?.source.as_mut() {
                    source.secret = secret;
                }
                Ok(())
            })
            .await
    }

    // A token change converges the managers only; a drifted executor would be recreated, taking the live slot down.
    async fn reensure_running(&self, orch: &Orchestrator, site: &Site) -> Result<Vec<Slot>> {
        let token = self.token_for(site).await;
        let mut slots = Vec::new();
        for slot in [site.active, site.active.other()] {
            if !orch.stack_running(&site.id, slot).await? {
                continue;
            }
            let git_ref = orch.slot_ref(&site.id, slot).await?;
            let opts = self.kept_opts(site, slot).await?;
            // A branch of the old repository means nothing in a new one, so a reset slot takes the site's own.
            let git_ref = if self.prepare_repo_volumes(orch, site, slot).await? {
                None
            } else {
                git_ref
            };
            orch.ensure_manager(site, slot, git_ref.as_deref(), &token, &opts)
                .await?;
            slots.push(slot);
        }
        Ok(slots)
    }

    async fn await_token(&self, id: &str, slots: &[Slot]) -> TokenVerdict {
        let Ok(probe) = self.probe() else {
            return TokenVerdict::Unchecked;
        };
        if slots.is_empty() {
            return TokenVerdict::Unchecked;
        }
        let deadline = Instant::now() + self.timing.token_wait;
        loop {
            let mut accepted = true;
            for slot in slots {
                let token = probe
                    .inspect(id, *slot)
                    .await
                    .ok()
                    .and_then(|seen| seen.manager_report)
                    .and_then(|r| r.token);
                match token.as_deref() {
                    Some("invalid") => return TokenVerdict::Invalid,
                    Some("ok") => {}
                    _ => accepted = false,
                }
            }
            if accepted {
                return TokenVerdict::Accepted;
            }
            let now = Instant::now();
            if now >= deadline {
                return TokenVerdict::Unknown;
            }
            sleep(self.timing.poll.min(deadline - now)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(level: &str, text: &str) -> LogLine {
        LogLine {
            ts: None,
            stream: "stderr".into(),
            level: Some(level.into()),
            phase: None,
            text: text.into(),
        }
    }

    #[test]
    fn cursors_move_one_nanosecond_past_the_last_line() {
        assert_eq!(
            cursor_after("2026-01-01T00:00:00.000000001Z").as_deref(),
            Some("1767225600.000000002")
        );
        assert_eq!(
            cursor_after("2026-01-01T00:00:00.999999999Z").as_deref(),
            Some("1767225601.000000000")
        );
        assert_eq!(docker_since("2026-01-01T00:00:00Z"), "1767225600.000000000");
        assert_eq!(docker_since("1767225600.5"), "1767225600.5");
        assert_eq!(cursor_after("not a time"), None);
        assert_eq!(
            cursor_after("2026-01-01 00:00:00Z").as_deref(),
            Some("1767225600.000000001"),
            "the cursor is plain Unix time whatever the input spelling"
        );
    }

    #[test]
    fn only_the_last_error_lines_are_kept_in_order() {
        let lines = vec![
            line("error", "first"),
            line("info", "noise"),
            line("info", "ERROR second"),
            line("error", "third"),
            line("error", "  "),
            line("error", "fourth"),
        ];
        assert_eq!(last_errors(&lines), vec!["ERROR second", "third", "fourth"]);
        assert!(last_errors(&[line("info", "fine")]).is_empty());
    }

    #[test]
    fn env_patches_apply_unset_then_set_and_respect_the_limits() {
        let mut current = BTreeMap::new();
        current.insert("KEEP".to_string(), "1".to_string());
        current.insert("DROP".to_string(), "2".to_string());
        let patch = BuildEnvPatch {
            set: [("NEW".to_string(), "3".to_string())].into(),
            unset: vec!["DROP".into(), "ABSENT".into()],
        };
        let next = apply_patch(current, &patch, "build env").unwrap();
        assert_eq!(next.keys().collect::<Vec<_>>(), vec!["KEEP", "NEW"]);

        let many: BTreeMap<String, String> = (0..cite_edge::status::MAX_ENV_KEYS)
            .map(|i| (format!("K{i}"), "v".into()))
            .collect();
        let one_more = BuildEnvPatch {
            set: [("EXTRA".to_string(), "v".to_string())].into(),
            unset: vec![],
        };
        assert!(matches!(
            apply_patch(many, &one_more, "build env"),
            Err(ConnectorError::BadRequest(_))
        ));

        let big: BTreeMap<String, String> = (0..7)
            .map(|i| (format!("BIG{i}"), "x".repeat(4000)))
            .collect();
        let err = apply_patch(big, &BuildEnvPatch::default(), "runtime env").unwrap_err();
        assert!(err.to_string().contains("24 KiB"), "{err}");
        assert!(!err.to_string().contains("xxxx"));
    }

    #[test]
    fn env_secret_names_cannot_collide_with_a_token_secret() {
        assert_eq!(EnvKind::Build.secret("shop"), "site-shop.build-env");
        assert_eq!(EnvKind::Runtime.secret("shop"), "site-shop.runtime-env");
        assert_ne!(EnvKind::Build.secret("shop"), secret_name("shop-build-env"));
        let doppler_names = [
            doppler::token_secret("shop"),
            doppler::snapshot_secret("shop", EnvKind::Build),
            doppler::snapshot_secret("shop", EnvKind::Runtime),
        ];
        assert_eq!(
            doppler_names,
            [
                "site-shop.doppler-token",
                "site-shop.doppler-build",
                "site-shop.doppler-runtime"
            ]
        );
        for name in &doppler_names {
            assert_ne!(*name, EnvKind::Build.secret("shop"));
            assert_ne!(*name, EnvKind::Runtime.secret("shop"));
            assert_ne!(*name, secret_name("shop"));
        }
    }

    #[test]
    fn the_operation_guard_clears_only_its_own_entry() {
        let ops = Arc::new(Operations::default());
        let first = ops.begin("shop", "deploy", Some(Slot::Green), Some("D1"), "starting");
        first.step("building");
        assert_eq!(ops.current("shop").unwrap().step, "building");
        let second = ops.begin("shop", "token", None, None, "saving");
        first.step("stale");
        drop(first);
        let now = ops.current("shop").unwrap();
        assert_eq!((now.kind.as_str(), now.step.as_str()), ("token", "saving"));
        drop(second);
        assert!(ops.current("shop").is_none());
    }

    #[test]
    fn log_reads_are_limited_per_site_and_overall() {
        let ops = SiteOps::default();
        let shop = ops.log_permits("shop").unwrap();
        assert!(matches!(
            ops.log_permits("shop"),
            Err(ConnectorError::TooManyRequests(_))
        ));
        let others: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|id| ops.log_permits(id).unwrap())
            .collect();
        assert!(matches!(
            ops.log_permits("d"),
            Err(ConnectorError::TooManyRequests(_))
        ));
        drop(shop);
        assert!(ops.log_permits("d").is_ok());
        drop(others);
    }

    #[test]
    fn a_503_check_on_a_built_site_reads_as_no_release() {
        assert_eq!(translate_check("L7STS", true).as_deref(), Some(NO_RELEASE));
        assert_eq!(translate_check("L7STS", false).as_deref(), Some("L7STS"));
        assert_eq!(translate_check("", true), None);
        assert_eq!(translate_check("L4CON", true).as_deref(), Some("L4CON"));
    }
}
