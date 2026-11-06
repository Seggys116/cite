use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use cite_edge::model::{
    DeployAction, Deployment, EdgeConfig, Maintenance, Site, Slot, Target, Upstream,
};
use cite_edge::validate::validate_site_strict;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::error::{ConnectorError, Result};
use crate::haproxy::Haproxy;
use crate::orchestrator::{Orchestrator, StackOpts};
use crate::siteops::{EnvKind, OpGuard, RESTART_LOOP, SiteOps, SlotProbe, repo_record};
use crate::store::{Store, now_rfc3339};

const HISTORY_CAP: usize = 50;
const CREATE_HEALTH: Duration = Duration::from_secs(30);
const DEPLOY_HEALTH: Duration = Duration::from_secs(60);
// A repo-built site has to clone, install and compile before its executor answers.
const BUILD_HEALTH: Duration = Duration::from_secs(600);
const DRAIN_DELAY: Duration = Duration::from_secs(30);
// The manager's own build timeout (15 minutes) plus room to fetch and promote.
const RELEASE_WAIT: Duration = Duration::from_secs(20 * 60);
const RELEASE_MARGIN: Duration = Duration::from_secs(5 * 60);
const RELEASE_POLL: Duration = Duration::from_secs(2);
const TOKEN_WAIT: Duration = Duration::from_secs(60);
const SILENT_HEALTHY_PROBES: u32 = 3;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Timing {
    create_health: Duration,
    deploy_health: Duration,
    build_health: Duration,
    drain: Duration,
    pub(crate) release_wait: Duration,
    pub(crate) poll: Duration,
    pub(crate) token_wait: Duration,
}

pub struct Deployer {
    pub(crate) store: Arc<Store>,
    pub(crate) haproxy: Arc<Haproxy>,
    pub(crate) orchestrator: Option<Arc<Orchestrator>>,
    pub(crate) probe: Option<Arc<dyn SlotProbe>>,
    locks: StdMutex<HashMap<String, Arc<Mutex<()>>>>,
    // Bumped by every drain schedule so an older timer can tell a later switch happened.
    drain_gen: Arc<StdMutex<HashMap<String, u64>>>,
    config_lock: Mutex<()>,
    pub(crate) timing: Timing,
    pub(crate) site_ops: SiteOps,
}

/// Answer of a deploy that was not waited for; poll the site status for its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeployStarted {
    pub deployment_id: String,
}

/// A waited deploy serialises as its history entry, an accepted one as `{"deployment_id": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum DeployReply {
    Finished(Deployment),
    Started(DeployStarted),
}

enum Release {
    Live { sha: Option<String> },
    Failed { reason: String, sha: Option<String> },
}

// Runs to completion even when the caller is dropped, so a disconnect or the request timeout cannot stop a deploy midway.
pub(crate) async fn detach<T: Send + 'static>(
    op: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    match tokio::spawn(op).await {
        Ok(result) => result,
        Err(err) => Err(ConnectorError::Internal(format!(
            "operation task failed: {err}"
        ))),
    }
}

pub(crate) fn upstream(site: &Site, slot: Slot) -> &Upstream {
    match slot {
        Slot::Blue => &site.blue,
        Slot::Green => &site.green,
    }
}

fn upstream_mut(site: &mut Site, slot: Slot) -> &mut Upstream {
    match slot {
        Slot::Blue => &mut site.blue,
        Slot::Green => &mut site.green,
    }
}

fn not_found(id: &str) -> ConnectorError {
    ConnectorError::NotFound(format!("site {id} not found"))
}

pub(crate) fn site_mut<'a>(cfg: &'a mut EdgeConfig, id: &str) -> Result<&'a mut Site> {
    cfg.sites
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| not_found(id))
}

pub(crate) fn secret_name(site_id: &str) -> String {
    format!("site-{site_id}")
}

fn new_deploy_id() -> String {
    ulid::Ulid::generate().to_string()
}

fn deployment(id: Option<&str>, slot: Slot, action: DeployAction, note: String) -> Deployment {
    Deployment {
        id: id.map_or_else(new_deploy_id, str::to_string),
        at: now_rfc3339(),
        slot,
        action,
        note,
    }
}

fn sha_text(sha: Option<&str>) -> String {
    format!("sha {}", sha.filter(|s| !s.is_empty()).unwrap_or("unknown"))
}

// Repo-built deploys always name the commit, so the history says what went live or failed.
fn failure_note(reason: &str, note: &str, sha: Option<Option<&str>>) -> String {
    let mut text = if note.is_empty() {
        reason.to_string()
    } else {
        format!("{reason} ({note})")
    };
    if let Some(sha) = sha {
        text = format!("{text}; {}", sha_text(sha));
    }
    text
}

fn success_note(note: &str, sha: Option<Option<&str>>) -> String {
    match sha {
        None => note.to_string(),
        Some(sha) if note.is_empty() => format!("live; {}", sha_text(sha)),
        Some(sha) => format!("{note}; {}", sha_text(sha)),
    }
}

fn push_history(site: &mut Site, entry: Deployment) {
    site.history.push(entry);
    if site.history.len() > HISTORY_CAP {
        let excess = site.history.len() - HISTORY_CAP;
        site.history.drain(..excess);
    }
}

fn audit_name(action: DeployAction) -> &'static str {
    match action {
        DeployAction::Promote => "site.promote",
        DeployAction::Rollback => "site.rollback",
        DeployAction::Switch => "site.switch",
        DeployAction::Failed => "site.deploy.failed",
    }
}

impl Deployer {
    pub fn new(
        store: Arc<Store>,
        haproxy: Arc<Haproxy>,
        orchestrator: Option<Arc<Orchestrator>>,
    ) -> Deployer {
        let probe = orchestrator.clone().map(|o| o as Arc<dyn SlotProbe>);
        Deployer {
            store,
            haproxy,
            orchestrator,
            probe,
            locks: StdMutex::new(HashMap::new()),
            drain_gen: Arc::default(),
            config_lock: Mutex::new(()),
            timing: Timing {
                create_health: CREATE_HEALTH,
                deploy_health: DEPLOY_HEALTH,
                build_health: BUILD_HEALTH,
                drain: DRAIN_DELAY,
                release_wait: RELEASE_WAIT,
                poll: RELEASE_POLL,
                token_wait: TOKEN_WAIT,
            },
            site_ops: SiteOps::default(),
        }
    }

    pub fn with_timing(
        mut self,
        create_health: Duration,
        deploy_health: Duration,
        drain: Duration,
    ) -> Deployer {
        self.timing = Timing {
            create_health,
            deploy_health,
            build_health: deploy_health,
            drain,
            ..self.timing
        };
        self
    }

    pub fn with_build_wait(mut self, wait: Duration) -> Deployer {
        self.timing.build_health = wait;
        self.timing.release_wait = RELEASE_WAIT.max(wait.saturating_add(RELEASE_MARGIN));
        self
    }

    /// How long a deploy waits for the manager's verdict, how often it asks, and how long a token change waits to be verified.
    pub fn with_release_timing(
        mut self,
        release_wait: Duration,
        poll: Duration,
        token_wait: Duration,
    ) -> Deployer {
        self.timing.release_wait = release_wait;
        self.timing.poll = poll;
        self.timing.token_wait = token_wait;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_probe(mut self, probe: Arc<dyn SlotProbe>) -> Deployer {
        self.probe = Some(probe);
        self
    }

    pub fn sites(&self) -> Vec<Site> {
        self.store.config().sites.clone()
    }

    // A repo-built slot gets the long build wait, an upstream slot only the short health wait.
    fn health_wait(&self, orchestrated: bool) -> Duration {
        if orchestrated {
            self.timing.build_health
        } else {
            self.timing.deploy_health
        }
    }

    // Config changes, their apply and any restore after a failed apply share this lock, so a restore never wipes another operation's change.
    pub fn config_lock(&self) -> &Mutex<()> {
        &self.config_lock
    }

    pub(crate) fn site_lock(&self, id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        locks.entry(id.to_string()).or_default().clone()
    }

    pub(crate) fn orchestrator(&self) -> Result<&Arc<Orchestrator>> {
        self.orchestrator.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("orchestration is not enabled on this node".into())
        })
    }

    pub(crate) fn get_site(&self, id: &str) -> Result<Site> {
        self.store
            .config()
            .sites
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .ok_or_else(|| not_found(id))
    }

    // A site's own stored token wins; a site without one uses the node token, read afresh so a restart with a rotated variable reaches the next container plan.
    pub(crate) async fn token_for(&self, site: &Site) -> String {
        match site.source.as_ref().and_then(|s| s.secret.as_deref()) {
            Some(name) => self.store.get_secret(name).await.unwrap_or_default(),
            None => self
                .orchestrator
                .as_ref()
                .and_then(|o| o.default_token())
                .unwrap_or_default()
                .to_string(),
        }
    }

    // A failed apply restores the previous config so the store never holds a state HAProxy rejected; the shared helper keeps this identical to the API's own changes.
    async fn mutate_apply<T>(
        &self,
        actor: &str,
        action: &str,
        change: impl FnOnce(&mut EdgeConfig) -> Result<T>,
    ) -> Result<T> {
        let _gate = self.config_lock.lock().await;
        crate::change::mutate_and_apply(&self.store, &self.haproxy, actor, action, "", change).await
    }

    async fn record(&self, actor: &str, id: &str, entry: Deployment) {
        let action = audit_name(entry.action);
        let sid = id.to_string();
        let _gate = self.config_lock.lock().await;
        let saved = self
            .store
            .update(actor, action, move |cfg| {
                push_history(site_mut(cfg, &sid)?, entry);
                Ok(())
            })
            .await;
        if let Err(err) = saved {
            tracing::warn!("deployment record for {id} was not saved: {err}");
        }
    }

    async fn record_failure(
        &self,
        actor: &str,
        id: &str,
        slot: Slot,
        deploy_id: Option<&str>,
        text: String,
    ) {
        self.site_ops.invalidate(id);
        self.record(
            actor,
            id,
            deployment(deploy_id, slot, DeployAction::Failed, text),
        )
        .await;
    }

    async fn drop_secret(&self, name: Option<&str>) {
        if let Some(name) = name {
            self.store.delete_secret(name).await;
        }
    }

    // Polls the slot's manager until it reports this deploy id as live or failed; an older live release never counts.
    async fn await_release(
        &self,
        site: &Site,
        slot: Slot,
        deploy_id: &str,
        op: &OpGuard,
    ) -> Release {
        let probe = match self.probe() {
            Ok(probe) => probe,
            Err(err) => {
                return Release::Failed {
                    reason: err.to_string(),
                    sha: None,
                };
            }
        };
        let id = site.id.as_str();
        let deadline = Instant::now() + self.timing.release_wait;
        let mut silent = 0u32;
        loop {
            match probe.inspect(id, slot).await {
                Ok(seen) => {
                    // A healthy 0.4.0 manager always prints a report, so a silent healthy one is an older image.
                    if seen.health == "healthy" && seen.manager_report.is_none() {
                        silent += 1;
                        if silent >= SILENT_HEALTHY_PROBES {
                            return Release::Failed {
                                reason: format!(
                                    "the build manager reported no result for deploy {deploy_id}: it is healthy \
                                     but prints no status report, so its image is likely older than 0.4.0; \
                                     check CITE_STACK_VERSION on the node"
                                ),
                                sha: None,
                            };
                        }
                    } else {
                        silent = 0;
                    }
                    if let Some(report) = &seen.manager_report {
                        if let Some(outcome) = report.deploy.as_ref().filter(|d| d.id == deploy_id)
                        {
                            match outcome.result.as_str() {
                                "live" => {
                                    return Release::Live {
                                        sha: outcome
                                            .sha
                                            .clone()
                                            .or_else(|| report.live_sha.clone()),
                                    };
                                }
                                "failed" => {
                                    let reason = outcome
                                        .reason
                                        .clone()
                                        .or_else(|| report.last_error.clone())
                                        .filter(|r| !r.is_empty())
                                        .unwrap_or_else(|| "the build failed".to_string());
                                    return Release::Failed {
                                        reason,
                                        sha: outcome
                                            .sha
                                            .clone()
                                            .or_else(|| report.last_failed_sha.clone()),
                                    };
                                }
                                _ => {}
                            }
                        }
                        if !report.phase.is_empty() {
                            op.step(&report.phase);
                        }
                    }
                    if seen.restart_count >= RESTART_LOOP {
                        return Release::Failed {
                            reason: self.restart_reason(site, slot, &seen).await,
                            sha: None,
                        };
                    }
                }
                Err(err) => tracing::warn!("slot {id}/{} unreadable: {err}", slot.as_str()),
            }
            let now = Instant::now();
            if now >= deadline {
                return Release::Failed {
                    reason: format!(
                        "the build manager reported no result for deploy {deploy_id} within {}s",
                        self.timing.release_wait.as_secs()
                    ),
                    sha: None,
                };
            }
            sleep(self.timing.poll.min(deadline - now)).await;
        }
    }

    // A repo change drops the slot's old checkout and cache first, then the stack starts with this deploy id.
    async fn start_release(
        &self,
        site: &Site,
        slot: Slot,
        git_ref: Option<&str>,
        deploy_id: &str,
    ) -> Result<Vec<Target>> {
        let orch = self.orchestrator()?;
        self.prepare_repo_volumes(orch, site, slot).await?;
        let token = self.token_for(site).await;
        let opts = StackOpts {
            deploy_id: Some(deploy_id.to_string()),
            build_env: self.env_opt(&site.id, EnvKind::Build).await?,
            runtime_env: self.env_opt(&site.id, EnvKind::Runtime).await?,
        };
        orch.ensure_stack_with(site, slot, git_ref, &token, &opts)
            .await
    }

    async fn stop_stack_quietly(&self, id: &str, slot: Slot) {
        if let Some(orch) = &self.orchestrator
            && let Err(err) = orch.stop_stack(id, slot).await
        {
            tracing::warn!("stack {id}/{} could not be stopped: {err}", slot.as_str());
        }
    }

    // The old stack is stopped after the drain delay unless the site moved again in the meantime.
    fn schedule_drain(&self, id: &str, old: Slot, promoted: Slot) {
        let Some(orch) = self.orchestrator.clone() else {
            return;
        };
        let generation = {
            let mut gens = self.drain_gen.lock().unwrap_or_else(|p| p.into_inner());
            let next = gens.entry(id.to_string()).or_insert(0);
            *next += 1;
            *next
        };
        let (store, lock, delay) = (self.store.clone(), self.site_lock(id), self.timing.drain);
        let gens = Arc::clone(&self.drain_gen);
        let id = id.to_string();
        tokio::spawn(async move {
            sleep(delay).await;
            let _guard = lock.lock().await;
            let latest = gens
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&id)
                .copied();
            let current = store.config();
            let settled = latest == Some(generation)
                && current
                    .sites
                    .iter()
                    .find(|s| s.id == id)
                    .is_some_and(|s| s.active == promoted);
            if settled && let Err(err) = orch.stop_stack(&id, old).await {
                tracing::warn!(
                    "drained stack {id}/{} could not be stopped: {err}",
                    old.as_str()
                );
            }
        });
    }

    // After a restart the drain timers are gone, so idle stacks of orchestrated sites are stopped once the active slot is healthy.
    pub async fn reconcile_idle_stacks(&self) {
        let Some(orch) = self.orchestrator.clone() else {
            return;
        };
        // A recreated HAProxy reaches no stack until it is reattached, so health below cannot pass before this.
        orch.ensure_reconciled().await;
        let ids: Vec<String> = self
            .store
            .config()
            .sites
            .iter()
            .filter(|s| s.source.is_some())
            .map(|s| s.id.clone())
            .collect();
        for id in ids {
            let Ok(seen) = self.get_site(&id) else {
                continue;
            };
            // The wait happens outside the site lock so deploys are not held up by a slow health check.
            let healthy = self
                .haproxy
                .wait_healthy(&id, seen.active, self.timing.deploy_health)
                .await
                .unwrap_or(false);
            if !healthy {
                tracing::warn!("site {id} active slot is not healthy, idle stack left running");
                continue;
            }
            let lock = self.site_lock(&id);
            let _guard = lock.lock().await;
            let Ok(site) = self.get_site(&id) else {
                continue;
            };
            if site.active != seen.active {
                continue;
            }
            let idle = site.active.other();
            match orch.stack_running(&id, idle).await {
                Ok(true) => {
                    if let Err(err) = orch.stop_stack(&id, idle).await {
                        tracing::warn!(
                            "idle stack {id}/{} could not be stopped: {err}",
                            idle.as_str()
                        );
                    }
                }
                Ok(false) => {}
                Err(err) => tracing::warn!("idle stack {id}/{} unreadable: {err}", idle.as_str()),
            }
        }
    }

    pub async fn create_site(
        self: &Arc<Self>,
        actor: &str,
        site: Site,
        github_token: Option<String>,
    ) -> Result<Site> {
        let (this, actor) = (Arc::clone(self), actor.to_string());
        detach(async move { this.create_site_inner(&actor, site, github_token).await }).await
    }

    async fn create_site_inner(
        &self,
        actor: &str,
        mut site: Site,
        github_token: Option<String>,
    ) -> Result<Site> {
        site.history.clear();
        validate_site_strict(&site)?;
        let id = site.id.clone();
        let lock = self.site_lock(&id);
        let _guard = lock.lock().await;
        if self.store.config().sites.iter().any(|s| s.id == id) {
            return Err(ConnectorError::Conflict(format!(
                "site {id} already exists"
            )));
        }
        let active = site.active;
        let mut stored_secret: Option<String> = None;
        if let Some(source) = &site.source {
            let orch = self.orchestrator()?;
            orch.limits().check_source(source)?;
            let token = github_token.filter(|t| !t.is_empty());
            // The secret name is assigned here; a client-supplied one could read another site's token.
            if let Some(source) = site.source.as_mut() {
                source.secret = None;
            }
            if let Some(token) = &token {
                let name = secret_name(&id);
                self.store.put_secret(&name, token).await?;
                if let Some(source) = site.source.as_mut() {
                    source.secret = Some(name.clone());
                }
                stored_secret = Some(name);
            }
            let token_text = match token.as_deref().or_else(|| orch.default_token()) {
                Some(text) => text,
                None => {
                    return Err(ConnectorError::BadRequest(
                        "No GitHub token: set CITE_GITHUB_TOKEN on the connector (or pass github_token for this site)"
                            .into(),
                    ));
                }
            };
            let started = match self.prepare_repo_volumes(orch, &site, active).await {
                Ok(_) => orch.ensure_stack(&site, active, None, token_text).await,
                Err(err) => Err(err),
            };
            match started {
                Ok(targets) => upstream_mut(&mut site, active).targets = targets,
                Err(err) => {
                    self.drop_secret(stored_secret.as_deref()).await;
                    return Err(err);
                }
            }
        } else if upstream(&site, active).targets.is_empty() {
            return Err(ConnectorError::BadRequest(
                "a site without a source needs targets in its active slot".into(),
            ));
        }
        let orchestrated = site.source.is_some();
        let entry = site.clone();
        let inserted = self
            .mutate_apply(actor, "site.create", move |cfg| {
                if cfg.sites.iter().any(|s| s.id == entry.id) {
                    return Err(ConnectorError::Conflict(format!(
                        "site {} already exists",
                        entry.id
                    )));
                }
                cfg.sites.push(entry);
                Ok(())
            })
            .await;
        if let Err(err) = inserted {
            if orchestrated
                && let Some(orch) = &self.orchestrator
                && let Err(cleanup) = orch.remove_stack(&id, true).await
            {
                tracing::warn!("stack of {id} not removed after a failed create: {cleanup}");
            }
            self.drop_secret(stored_secret.as_deref()).await;
            return Err(err);
        }
        let healthy = self
            .haproxy
            .wait_healthy(&id, active, self.timing.create_health)
            .await
            .unwrap_or(false);
        if !healthy {
            tracing::warn!(
                "site {id} was created but its {} slot is not healthy",
                active.as_str()
            );
            let detail = format!(
                "{} slot of {id} was not healthy after create",
                active.as_str()
            );
            self.store
                .audit(actor, "site.create.unhealthy", &detail)
                .await;
        }
        self.get_site(&id)
    }

    pub async fn update_site(self: &Arc<Self>, actor: &str, site: Site) -> Result<Site> {
        let (this, actor) = (Arc::clone(self), actor.to_string());
        detach(async move { this.update_site_inner(&actor, site).await }).await
    }

    // Slots, the active choice and maintenance move only through their own endpoints, so a stale client copy cannot undo a deploy.
    async fn update_site_inner(&self, actor: &str, mut site: Site) -> Result<Site> {
        validate_site_strict(&site)?;
        let id = site.id.clone();
        let lock = self.site_lock(&id);
        let _guard = lock.lock().await;
        let existing = self.get_site(&id)?;
        if let Some(source) = &site.source {
            self.orchestrator()?.limits().check_source(source)?;
        }
        site.history = existing.history.clone();
        site.active = existing.active;
        site.blue = existing.blue.clone();
        site.green = existing.green.clone();
        site.maintenance = existing.maintenance.clone();
        if let Some(source) = site.source.as_mut() {
            source.secret = existing.source.as_ref().and_then(|s| s.secret.clone());
        }
        if site == existing {
            return Ok(existing);
        }
        // Build settings are not part of the HAProxy config, so changing only them is a store write that waits for the next deploy.
        let mut routing = site.clone();
        routing.source = existing.source.clone();
        let source_only = routing == existing && site.source.is_some() && existing.source.is_some();
        let sid = id.clone();
        if source_only {
            let _gate = self.config_lock.lock().await;
            self.store
                .update(actor, "site.update", move |cfg| {
                    *site_mut(cfg, &sid)? = site;
                    Ok(())
                })
                .await?;
        } else {
            self.mutate_apply(actor, "site.update", move |cfg| {
                *site_mut(cfg, &sid)? = site;
                Ok(())
            })
            .await?;
        }
        self.site_ops.invalidate(&id);
        self.get_site(&id)
    }

    pub async fn delete_site(self: &Arc<Self>, actor: &str, id: &str) -> Result<()> {
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.delete_site_inner(&actor, &id).await }).await
    }

    async fn delete_site_inner(&self, actor: &str, id: &str) -> Result<()> {
        let lock = self.site_lock(id);
        let guard = lock.lock().await;
        let site = self.get_site(id)?;
        let sid = id.to_string();
        self.mutate_apply(actor, "site.delete", move |cfg| {
            let scoped: Vec<&str> = cfg
                .firewall
                .iter()
                .filter(|r| r.site.as_deref() == Some(sid.as_str()))
                .map(|r| r.id.as_str())
                .collect();
            if !scoped.is_empty() {
                return Err(ConnectorError::Conflict(format!(
                    "site {sid} is used by firewall rules {}; delete or change them first",
                    scoped.join(", ")
                )));
            }
            cfg.sites.retain(|s| s.id != sid);
            Ok(())
        })
        .await?;
        if site.source.is_some()
            && let Some(orch) = &self.orchestrator
            && let Err(err) = orch.remove_stack(id, true).await
        {
            tracing::warn!("stacks of deleted site {id} could not be removed: {err}");
        }
        self.drop_secret(site.source.as_ref().and_then(|s| s.secret.as_deref()))
            .await;
        for kind in [EnvKind::Build, EnvKind::Runtime] {
            self.store.delete_secret(&kind.secret(id)).await;
        }
        self.store.delete_secret(&repo_record(id)).await;
        self.site_ops.forget(id);
        drop(guard);
        self.locks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(id);
        Ok(())
    }

    pub async fn deploy(
        self: &Arc<Self>,
        actor: &str,
        id: &str,
        targets: Option<Vec<Target>>,
        note: Option<String>,
        git_ref: Option<String>,
        wait: bool,
    ) -> Result<DeployReply> {
        if wait {
            return self
                .deploy_and_wait(actor, id, targets, note, git_ref)
                .await
                .map(DeployReply::Finished);
        }
        // The cheap refusals happen before the 202, so an accepted deploy only fails on its way.
        self.refuse_early(id, targets.as_deref())?;
        let deploy_id = new_deploy_id();
        let (this, actor, sid, did) = (
            Arc::clone(self),
            actor.to_string(),
            id.to_string(),
            deploy_id.clone(),
        );
        tokio::spawn(async move {
            if let Err(err) = this
                .deploy_inner(&actor, &sid, targets, note, git_ref, did.clone())
                .await
            {
                tracing::warn!("deploy {did} of {sid} did not go live: {err}");
            }
        });
        Ok(DeployReply::Started(DeployStarted {
            deployment_id: deploy_id,
        }))
    }

    pub async fn deploy_and_wait(
        self: &Arc<Self>,
        actor: &str,
        id: &str,
        targets: Option<Vec<Target>>,
        note: Option<String>,
        git_ref: Option<String>,
    ) -> Result<Deployment> {
        self.refuse_early(id, targets.as_deref())?;
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        let deploy_id = new_deploy_id();
        detach(async move {
            this.deploy_inner(&actor, &id, targets, note, git_ref, deploy_id)
                .await
        })
        .await
    }

    fn refuse_early(&self, id: &str, targets: Option<&[Target]>) -> Result<()> {
        let site = self.get_site(id)?;
        if site.source.is_some() {
            self.orchestrator()?;
        } else if targets.is_none_or(|t| t.is_empty()) {
            return Err(ConnectorError::BadRequest(
                "a deploy needs at least one target".into(),
            ));
        }
        Ok(())
    }

    // The deploy id is the history entry id and, for a repo-built site, the CITE_DEPLOY_ID that forces the manager to build.
    async fn deploy_inner(
        &self,
        actor: &str,
        id: &str,
        targets: Option<Vec<Target>>,
        note: Option<String>,
        git_ref: Option<String>,
        deploy_id: String,
    ) -> Result<Deployment> {
        let lock = self.site_lock(id);
        let _guard = lock.lock().await;
        let site = self.get_site(id)?;
        let (old, idle) = (site.active, site.active.other());
        let orchestrated = site.source.is_some();
        let note = note.unwrap_or_default();
        let did = Some(deploy_id.as_str());
        let op = self
            .site_ops
            .ops
            .begin(id, "deploy", Some(idle), did, "starting");
        let new_targets = if orchestrated {
            op.step("starting the build manager");
            match self
                .start_release(&site, idle, git_ref.as_deref(), &deploy_id)
                .await
            {
                Ok(started) => started,
                Err(err) => {
                    let reason = format!("stack could not be started: {err}");
                    let text = failure_note(&reason, &note, Some(None));
                    self.record_failure(actor, id, idle, did, text).await;
                    return Err(err);
                }
            }
        } else {
            match targets.filter(|t| !t.is_empty()) {
                Some(targets) => targets,
                None => {
                    let reason = "a deploy needs at least one target";
                    let text = failure_note(reason, &note, None);
                    self.record_failure(actor, id, idle, did, text).await;
                    return Err(ConnectorError::BadRequest(reason.into()));
                }
            }
        };
        let sid = id.to_string();
        let staged = self
            .mutate_apply(actor, "site.deploy.stage", move |cfg| {
                upstream_mut(site_mut(cfg, &sid)?, idle).targets = new_targets;
                Ok(())
            })
            .await;
        if let Err(err) = staged {
            // An accepted deploy has already answered with its id, so the failure must reach the history.
            let reason = format!("the new targets could not be applied: {err}");
            let sha = orchestrated.then_some(None);
            let text = failure_note(&reason, &note, sha);
            self.record_failure(actor, id, idle, did, text).await;
            self.stop_stack_quietly(id, idle).await;
            return Err(err);
        }
        // A previously used idle slot still serves its old release, so health alone would promote it before the new build.
        let mut live_sha: Option<Option<String>> = None;
        if orchestrated {
            op.step("building");
            match self.await_release(&site, idle, &deploy_id, &op).await {
                Release::Live { sha } => live_sha = Some(sha),
                Release::Failed { reason, sha } => {
                    let text = failure_note(&reason, &note, Some(sha.as_deref()));
                    self.record_failure(actor, id, idle, did, text).await;
                    self.stop_stack_quietly(id, idle).await;
                    return Err(ConnectorError::Conflict(format!(
                        "deploy {deploy_id} of {id} failed: {reason}; the {} slot still serves",
                        old.as_str()
                    )));
                }
            }
        }
        let sha = live_sha.as_ref().map(Option::as_deref);
        op.step("checking health");
        let wait = self.health_wait(orchestrated);
        let healthy = self
            .haproxy
            .wait_healthy(id, idle, wait)
            .await
            .unwrap_or(false);
        if !healthy {
            // Active stays where it was; only the stack that failed to come up is stopped.
            let reason = format!(
                "{} slot did not pass health checks within {}s",
                idle.as_str(),
                wait.as_secs()
            );
            let text = failure_note(&reason, &note, sha);
            self.record_failure(actor, id, idle, did, text).await;
            self.stop_stack_quietly(id, idle).await;
            return Err(ConnectorError::Conflict(format!(
                "deploy failed health checks: the {} slot of {id} never came up, active slot unchanged",
                idle.as_str()
            )));
        }
        op.step("switching traffic");
        let promoted = self
            .promote(
                actor,
                id,
                old,
                idle,
                DeployAction::Promote,
                success_note(&note, sha),
                did,
            )
            .await?;
        if orchestrated {
            self.schedule_drain(id, old, idle);
        }
        Ok(promoted)
    }

    // The runtime map flips before the store is updated, so a failed flip leaves the stored slot alone.
    #[allow(clippy::too_many_arguments)]
    async fn promote(
        &self,
        actor: &str,
        id: &str,
        old: Slot,
        slot: Slot,
        action: DeployAction,
        note: String,
        deploy_id: Option<&str>,
    ) -> Result<Deployment> {
        self.site_ops.invalidate(id);
        let gate = self.config_lock.lock().await;
        if let Err(err) = self.haproxy.set_active(id, slot).await {
            // Put the map file back so a later reload cannot route to the slot that never went live.
            let _ = self.haproxy.set_active(id, old).await;
            drop(gate);
            let reason = format!("switching traffic failed: {err}");
            let text = failure_note(&reason, &note, None);
            self.record_failure(actor, id, slot, deploy_id, text).await;
            return Err(err);
        }
        let entry = deployment(deploy_id, slot, action, note);
        let saved = entry.clone();
        let sid = id.to_string();
        self.store
            .update(actor, audit_name(action), move |cfg| {
                let site = site_mut(cfg, &sid)?;
                site.active = slot;
                push_history(site, saved);
                Ok(())
            })
            .await?;
        drop(gate);
        Ok(entry)
    }

    async fn activate(
        &self,
        actor: &str,
        site: &Site,
        slot: Slot,
        action: DeployAction,
        note: String,
    ) -> Result<Deployment> {
        let id = site.id.as_str();
        if site.active == slot {
            return Err(ConnectorError::Conflict(format!(
                "the {} slot is already active",
                slot.as_str()
            )));
        }
        if upstream(site, slot).targets.is_empty() {
            return Err(ConnectorError::BadRequest(format!(
                "the {} slot has no targets",
                slot.as_str()
            )));
        }
        let orchestrated = site.source.is_some();
        // A stopped stack is started again before health is checked, since its address may change.
        if orchestrated {
            self.ensure_slot_running(actor, site, slot).await?;
        }
        let healthy = self
            .haproxy
            .wait_healthy(id, slot, self.health_wait(orchestrated))
            .await?;
        if !healthy {
            return Err(ConnectorError::Conflict(format!(
                "the {} slot of {id} is not healthy, traffic was not moved",
                slot.as_str()
            )));
        }
        let moved = self
            .promote(actor, id, site.active, slot, action, note, None)
            .await?;
        if orchestrated {
            self.schedule_drain(id, site.active, slot);
        }
        Ok(moved)
    }

    async fn ensure_slot_running(&self, actor: &str, site: &Site, slot: Slot) -> Result<()> {
        let orch = self.orchestrator()?;
        if orch.stack_running(&site.id, slot).await? {
            return Ok(());
        }
        let token = self.token_for(site).await;
        // The slot comes back on the ref it last ran, not on the site's current branch.
        let git_ref = orch.slot_ref(&site.id, slot).await?;
        // The kept deploy id and the stored env keep a restart from rebuilding or dropping variables.
        let opts = self.kept_opts(site, slot).await?;
        let git_ref = if self.prepare_repo_volumes(orch, site, slot).await? {
            None
        } else {
            git_ref
        };
        let started = orch
            .ensure_stack_with(site, slot, git_ref.as_deref(), &token, &opts)
            .await?;
        if started != upstream(site, slot).targets {
            let sid = site.id.clone();
            self.mutate_apply(actor, "site.switch.retarget", move |cfg| {
                upstream_mut(site_mut(cfg, &sid)?, slot).targets = started;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    pub async fn switch(self: &Arc<Self>, actor: &str, id: &str, slot: Slot) -> Result<Deployment> {
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.switch_inner(&actor, &id, slot).await }).await
    }

    async fn switch_inner(&self, actor: &str, id: &str, slot: Slot) -> Result<Deployment> {
        let lock = self.site_lock(id);
        let _guard = lock.lock().await;
        let site = self.get_site(id)?;
        let note = format!("switched to the {} slot", slot.as_str());
        self.activate(actor, &site, slot, DeployAction::Switch, note)
            .await
    }

    pub async fn rollback(self: &Arc<Self>, actor: &str, id: &str) -> Result<Deployment> {
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.rollback_inner(&actor, &id).await }).await
    }

    async fn rollback_inner(&self, actor: &str, id: &str) -> Result<Deployment> {
        let lock = self.site_lock(id);
        let _guard = lock.lock().await;
        let site = self.get_site(id)?;
        let last = site
            .history
            .iter()
            .rev()
            .find(|d| d.action == DeployAction::Promote)
            .ok_or_else(|| {
                ConnectorError::BadRequest(format!("site {id} has no deploy to roll back"))
            })?;
        let note = format!("rolled back deploy {}", last.id);
        self.activate(
            actor,
            &site,
            last.slot.other(),
            DeployAction::Rollback,
            note,
        )
        .await
    }

    pub async fn set_maintenance(
        self: &Arc<Self>,
        actor: &str,
        id: &str,
        enabled: bool,
        page_id: Option<String>,
    ) -> Result<Site> {
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move {
            this.set_maintenance_inner(&actor, &id, enabled, page_id)
                .await
        })
        .await
    }

    async fn set_maintenance_inner(
        &self,
        actor: &str,
        id: &str,
        enabled: bool,
        page_id: Option<String>,
    ) -> Result<Site> {
        let lock = self.site_lock(id);
        let _guard = lock.lock().await;
        let site = self.get_site(id)?;
        let _gate = self.config_lock.lock().await;
        let previous = self.store.config();
        if let Some(pid) = &page_id
            && !previous.pages.iter().any(|p| &p.id == pid)
        {
            return Err(ConnectorError::BadRequest(format!(
                "maintenance page {pid} does not exist"
            )));
        }
        // Disabling without a page keeps the earlier choice so maintenance can be re-enabled as it was.
        let keep_page = !enabled && page_id.is_none();
        let page = if keep_page {
            site.maintenance.page_id.clone()
        } else {
            page_id
        };
        let page_changed = page != site.maintenance.page_id;
        let sid = id.to_string();
        self.store
            .update(actor, "site.maintenance", move |cfg| {
                site_mut(cfg, &sid)?.maintenance = Maintenance {
                    enabled,
                    page_id: page,
                };
                Ok(())
            })
            .await?;
        let pushed = if page_changed {
            self.haproxy
                .apply(&self.store.config())
                .await
                .and_then(|applied| applied.require_loaded())
        } else {
            match self.haproxy.set_maintenance(id, enabled).await {
                Err(ConnectorError::Unavailable(why)) => {
                    tracing::warn!(
                        "maintenance flag for {id} will apply on the next reload: {why}"
                    );
                    Ok(())
                }
                other => other,
            }
        };
        if let Err(err) = pushed {
            let rollback = crate::change::roll_back(
                &self.store,
                &self.haproxy,
                actor,
                "site.maintenance",
                previous,
            )
            .await;
            return Err(if rollback.failed() {
                crate::change::failure(err, false, rollback)
            } else {
                err
            });
        }
        self.get_site(id)
    }

    pub async fn live(&self, id: &str) -> Result<Value> {
        let site = self.get_site(id)?;
        let stats = self.haproxy.stats().await.ok();
        let view = |slot: Slot| -> Vec<Value> {
            let backend = format!("be_{id}_{}", slot.as_str());
            let found = stats
                .as_ref()
                .and_then(|all| all.iter().find(|b| b.name == backend));
            upstream(&site, slot)
                .targets
                .iter()
                .enumerate()
                .map(|(i, target)| {
                    let server = format!("t{}", i + 1);
                    let status = found
                        .and_then(|b| b.servers.iter().find(|s| s.name == server))
                        .map_or("UNKNOWN", |s| s.status.as_str());
                    json!({ "addr": target.addr, "status": status })
                })
                .collect()
        };
        Ok(json!({ "blue": view(Slot::Blue), "green": view(Slot::Green) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use cite_edge::model::{HealthCheck, MaintenancePage, SiteKind};
    use cite_edge::status::{BuildEnvPatch, LogLine};
    use tempfile::TempDir;

    use crate::orchestrator::SlotInspect;
    use crate::orchestrator::tests::container_env;
    use crate::siteops::{LogQuery, LogSource};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use crate::store::testing::test_config;

    const BACKENDS: [&str; 4] = [
        "be_shop_blue",
        "be_shop_green",
        "be_blog_blue",
        "be_blog_green",
    ];

    #[derive(Default)]
    struct Fake {
        commands: Vec<String>,
        down: HashSet<String>,
    }

    type SharedFake = Arc<StdMutex<Fake>>;

    fn stat_csv(down: &HashSet<String>) -> String {
        let mut out = String::from("# pxname,svname,status,scur,bin,bout,check_status\n");
        for backend in BACKENDS {
            let status = if down.contains(backend) { "DOWN" } else { "UP" };
            for server in ["t1", "t2"] {
                out.push_str(&format!("{backend},{server},{status},0,0,0,L7OK\n"));
            }
            out.push_str(&format!("{backend},BACKEND,{status},0,0,0,\n"));
        }
        out
    }

    // Answers `show stat` for the fixed backends (two servers each) and accepts any other command.
    async fn start_fake() -> (String, SharedFake) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let fake: SharedFake = Arc::default();
        let shared = fake.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let shared = shared.clone();
                tokio::spawn(async move {
                    let mut line = String::new();
                    let mut reader = BufReader::new(&mut stream);
                    if reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    let reply = {
                        let mut state = shared.lock().unwrap();
                        let reply = if line.starts_with("show stat") {
                            stat_csv(&state.down)
                        } else {
                            "\n".to_string()
                        };
                        state.commands.push(line);
                        reply
                    };
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (addr, fake)
    }

    struct Env {
        _dir: TempDir,
        deployer: Arc<Deployer>,
        store: Arc<Store>,
        fake: SharedFake,
        cfg: crate::config::ConnectorConfig,
    }

    type Docker = Arc<StdMutex<crate::orchestrator::tests::Fake>>;

    const SHA: &str = "1111111111111111111111111111111111111111";
    const OLD_SHA: &str = "0000000000000000000000000000000000000000";
    const OLD_ID: &str = "01HZX3K9M2N4P5Q6R7S8T9V0WX";

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Mode {
        // Reports whatever CITE_DEPLOY_ID the manager was started with as live.
        Auto,
        Stale,
        Fail(String),
        Silent,
    }

    #[derive(Default)]
    struct Sim {
        modes: HashMap<Slot, Mode>,
        restarts: HashMap<Slot, u32>,
        tokens: HashMap<Slot, String>,
        logs: Vec<cite_edge::status::LogLine>,
        redactions: Vec<Vec<String>>,
    }

    // Stands in for the manager's health report, reading the env the fake Docker engine holds.
    struct SimProbe {
        orch: Arc<Orchestrator>,
        docker: Docker,
        sim: StdMutex<Sim>,
    }

    impl SimProbe {
        fn set_mode(&self, slot: Slot, mode: Mode) {
            self.sim.lock().unwrap().modes.insert(slot, mode);
        }

        fn set_token(&self, slot: Slot, token: &str) {
            self.sim.lock().unwrap().tokens.insert(slot, token.into());
        }

        fn last_redactions(&self) -> Vec<String> {
            self.sim
                .lock()
                .unwrap()
                .redactions
                .last()
                .cloned()
                .unwrap_or_default()
        }

        async fn read(&self, site_id: &str, slot: Slot) -> Result<SlotInspect> {
            let limits = *self.orch.limits();
            let mut seen = SlotInspect {
                state: "missing".into(),
                health: "none".into(),
                restart_count: 0,
                exit_code: None,
                oom_killed: false,
                env: Vec::new(),
                manager_report: None,
                manager_memory: limits.manager_memory,
                manager_nano_cpus: limits.manager_nano_cpus,
                executor_memory: limits.executor_memory,
                executor_nano_cpus: limits.executor_nano_cpus,
            };
            if self.orch.slot_ref(site_id, slot).await?.is_none() {
                return Ok(seen);
            }
            let name = format!("cite-{site_id}-{}-manager", slot.as_str());
            let env: Vec<String> = serde_json::from_str(
                &crate::orchestrator::tests::container_env(&self.docker, &name),
            )
            .unwrap_or_default();
            let deploy_id = crate::siteops::env_value(&env, "CITE_DEPLOY_ID=");
            let sim = self.sim.lock().unwrap();
            let token = sim
                .tokens
                .get(&slot)
                .cloned()
                .unwrap_or_else(|| "ok".into());
            let report = match sim.modes.get(&slot).cloned().unwrap_or(Mode::Auto) {
                Mode::Auto => Some(match deploy_id {
                    Some(id) => json!({"v": 1, "phase": "idle", "token": token, "live_sha": SHA,
                        "deploy": {"id": id, "result": "live", "sha": SHA}}),
                    None => json!({"v": 1, "phase": "idle", "token": token, "live_sha": OLD_SHA}),
                }),
                Mode::Stale => Some(json!({"v": 1, "phase": "building", "token": token,
                    "live_sha": OLD_SHA, "deploy": {"id": OLD_ID, "result": "live"}})),
                Mode::Fail(reason) => Some(json!({"v": 1, "phase": "failed", "token": token,
                    "last_error": reason, "last_failed_sha": SHA,
                    "deploy": {"id": deploy_id.unwrap_or_default(), "result": "failed"}})),
                Mode::Silent => None,
            };
            seen.state = "running".into();
            seen.health = "healthy".into();
            seen.restart_count = sim.restarts.get(&slot).copied().unwrap_or(0);
            seen.env = env
                .into_iter()
                .filter(|e| !e.starts_with("CITE_GITHUB_TOKEN=") && !e.contains("_ENV_JSON="))
                .collect();
            seen.manager_report = report.map(|v| serde_json::from_value(v).unwrap());
            Ok(seen)
        }
    }

    impl SlotProbe for SimProbe {
        fn inspect<'a>(
            &'a self,
            site_id: &'a str,
            slot: Slot,
        ) -> futures_util::future::BoxFuture<'a, Result<SlotInspect>> {
            Box::pin(self.read(site_id, slot))
        }

        fn logs<'a>(
            &'a self,
            req: crate::siteops::LogRequest<'a>,
        ) -> futures_util::future::BoxFuture<'a, Result<crate::orchestrator::LogsBatch>> {
            let mut sim = self.sim.lock().unwrap();
            sim.redactions.push(req.redact.to_vec());
            let lines = sim.logs.clone();
            let last_ts = lines.last().and_then(|l| l.ts.clone());
            Box::pin(async move {
                Ok(crate::orchestrator::LogsBatch {
                    lines,
                    truncated: false,
                    last_ts,
                })
            })
        }
    }

    async fn env_with(
        tweak: impl FnOnce(&mut crate::config::ConnectorConfig),
        orchestrator: Option<Arc<Orchestrator>>,
    ) -> Env {
        env_full(tweak, orchestrator, Duration::from_millis(50), None).await
    }

    async fn env_full(
        tweak: impl FnOnce(&mut crate::config::ConnectorConfig),
        orchestrator: Option<Arc<Orchestrator>>,
        drain: Duration,
        probe: Option<Arc<SimProbe>>,
    ) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let (addr, fake) = start_fake().await;
        let mut cfg = test_config(dir.path());
        cfg.runtime_addr = addr;
        tweak(&mut cfg);
        let store = Store::open(&cfg).await.unwrap();
        let haproxy = Arc::new(Haproxy::new(&cfg));
        let short = Duration::from_millis(600);
        let mut deployer = Deployer::new(store.clone(), haproxy, orchestrator)
            .with_timing(Duration::from_millis(300), short, drain)
            .with_release_timing(
                Duration::from_secs(3),
                Duration::from_millis(20),
                Duration::from_millis(400),
            );
        if let Some(probe) = probe {
            deployer = deployer.with_probe(probe);
        }
        Env {
            _dir: dir,
            deployer: Arc::new(deployer),
            store,
            fake,
            cfg,
        }
    }

    // A fake Docker engine with a simulated manager report; the node token is optional.
    async fn docker_env(
        drain: Duration,
        node_token: Option<&str>,
        release_wait: Option<Duration>,
    ) -> (Env, Arc<Orchestrator>, Docker, Arc<SimProbe>) {
        let (orch, docker) = crate::orchestrator::tests::start_fake().await;
        let token = node_token
            .map(|t| crate::config::NodeToken::new(t, crate::config::TokenSource::Env).unwrap());
        let orch = Arc::new(orch.with_default_token(token));
        let sim = Arc::new(SimProbe {
            orch: orch.clone(),
            docker: docker.clone(),
            sim: StdMutex::default(),
        });
        let mut e = env_full(|_| {}, Some(orch.clone()), drain, Some(sim.clone())).await;
        if let Some(wait) = release_wait {
            let deployer = Arc::try_unwrap(e.deployer).ok().unwrap();
            e.deployer = Arc::new(deployer.with_release_timing(
                wait,
                Duration::from_millis(20),
                Duration::from_millis(400),
            ));
        }
        (e, orch, docker, sim)
    }

    async fn env() -> Env {
        env_with(|_| {}, None).await
    }

    fn target(addr: &str) -> Target {
        Target {
            addr: addr.into(),
            weight: 100,
        }
    }

    fn new_site(id: &str) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: vec![format!("{id}.example.com")],
            path_regexes: Vec::new(),
            path_prefixes: Vec::new(),
            kind: SiteKind::Site,
            blue: Upstream {
                targets: vec![target("10.0.0.1:8080"), target("10.0.0.2:8080")],
                label: None,
            },
            green: Upstream::default(),
            active: Slot::Blue,
            maintenance: Maintenance::default(),
            health: HealthCheck::default(),
            source: None,
            history: vec![],
            access: Default::default(),
        }
    }

    async fn created(e: &Env) -> Site {
        e.deployer
            .create_site("tester", new_site("shop"), None)
            .await
            .unwrap()
    }

    fn current(e: &Env, id: &str) -> Site {
        e.store
            .config()
            .sites
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .unwrap()
    }

    fn commands(e: &Env) -> Vec<String> {
        e.fake.lock().unwrap().commands.clone()
    }

    fn set_down(e: &Env, backend: &str) {
        e.fake.lock().unwrap().down.insert(backend.to_string());
    }

    fn green_targets() -> Vec<Target> {
        vec![target("10.0.1.1:8080")]
    }

    fn orchestrated_site(id: &str) -> Site {
        let mut site = new_site(id);
        site.source = Some(serde_json::from_value(json!({ "repo": "owner/repo" })).unwrap());
        site
    }

    fn unreachable_orchestrator() -> Arc<Orchestrator> {
        let orch = Orchestrator::new("tcp://127.0.0.1:1", "cite_edge", "0.1.0", "ghcr.io/owner");
        Arc::new(orch.unwrap())
    }

    fn history_entry(n: usize) -> Deployment {
        Deployment {
            id: format!("d{n}"),
            at: String::new(),
            slot: Slot::Green,
            action: DeployAction::Promote,
            note: String::new(),
        }
    }

    #[test]
    fn history_is_capped_and_keeps_the_newest() {
        let mut site = new_site("shop");
        for n in 0..(HISTORY_CAP + 7) {
            push_history(&mut site, history_entry(n));
        }
        assert_eq!(site.history.len(), HISTORY_CAP);
        assert_eq!(site.history[0].id, "d7");
        assert_eq!(
            site.history.last().unwrap().id,
            format!("d{}", HISTORY_CAP + 6)
        );
    }

    #[test]
    fn site_mut_reports_missing_sites() {
        let mut cfg = EdgeConfig::default();
        assert!(matches!(
            site_mut(&mut cfg, "ghost"),
            Err(ConnectorError::NotFound(_))
        ));
        cfg.sites.push(new_site("shop"));
        assert!(site_mut(&mut cfg, "shop").is_ok());
    }

    #[tokio::test]
    async fn create_stores_applies_and_returns_the_site() {
        let e = env().await;
        let site = created(&e).await;
        assert_eq!(site.id, "shop");
        assert!(site.history.is_empty());
        assert_eq!(current(&e, "shop").blue.targets.len(), 2);
        let cfg_text = std::fs::read_to_string(&e.cfg.haproxy_cfg).unwrap();
        assert!(cfg_text.contains("backend be_shop_blue"));
        let active = std::fs::read_to_string(e.cfg.maps_dir.join("active.map")).unwrap();
        assert_eq!(active, "shop be_shop_blue\n");
    }

    #[tokio::test]
    async fn create_discards_client_supplied_history() {
        let e = env().await;
        let mut site = new_site("shop");
        site.history.push(history_entry(1));
        let made = e.deployer.create_site("tester", site, None).await.unwrap();
        assert!(made.history.is_empty());
    }

    #[tokio::test]
    async fn create_rejects_duplicates_invalid_ids_and_missing_targets() {
        let e = env().await;
        created(&e).await;
        let dup = e.deployer.create_site("t", new_site("shop"), None).await;
        assert!(matches!(dup, Err(ConnectorError::Conflict(_))));
        let bad = e.deployer.create_site("t", new_site("Bad Id"), None).await;
        assert!(matches!(bad, Err(ConnectorError::BadRequest(_))));
        let mut empty = new_site("blog");
        empty.blue.targets.clear();
        let none = e.deployer.create_site("t", empty, None).await;
        assert!(matches!(none, Err(ConnectorError::BadRequest(_))));
        assert_eq!(e.store.config().sites.len(), 1);
    }

    #[tokio::test]
    async fn create_with_source_needs_orchestration() {
        let e = env().await;
        let err = e
            .deployer
            .create_site("t", orchestrated_site("shop"), Some("tok".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)));
        assert!(err.to_string().contains("orchestration is not enabled"));
        assert!(e.store.config().sites.is_empty());
        assert_eq!(e.store.get_secret("site-shop").await, None);
    }

    async fn node_token_env() -> (Env, Arc<Orchestrator>, Docker) {
        let (e, orch, fake, _sim) =
            docker_env(Duration::from_millis(50), Some("ghp_nodewide"), None).await;
        (e, orch, fake)
    }

    #[tokio::test]
    async fn a_site_without_a_token_uses_the_node_token_and_never_stores_it() {
        let (e, _orch, fake) = node_token_env().await;
        let made = e
            .deployer
            .create_site("t", orchestrated_site("shop"), None)
            .await
            .unwrap();
        assert_eq!(made.source.unwrap().secret, None);
        assert!(
            container_env(&fake, "cite-shop-blue-manager")
                .contains("CITE_GITHUB_TOKEN=ghp_nodewide")
        );
        assert_eq!(e.store.get_secret("site-shop").await, None);

        // the next deploy plans the idle slot afresh and resolves the same fallback
        e.deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap();
        assert!(
            container_env(&fake, "cite-shop-green-manager")
                .contains("CITE_GITHUB_TOKEN=ghp_nodewide")
        );

        let audit = e.store.audit_tail(100).await;
        assert!(!format!("{audit:?}").contains("ghp_nodewide"));
        for file in ["edge.json", "secrets.json", "audit.jsonl"] {
            let text = std::fs::read_to_string(e.cfg.data_dir.join(file)).unwrap_or_default();
            assert!(
                !text.contains("ghp_nodewide"),
                "{file} holds the node token"
            );
        }
    }

    #[tokio::test]
    async fn a_site_token_overrides_the_node_token() {
        let (e, _orch, fake) = node_token_env().await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_sitewide".into()))
            .await
            .unwrap();
        let env = container_env(&fake, "cite-shop-blue-manager");
        assert!(env.contains("CITE_GITHUB_TOKEN=ghp_sitewide") && !env.contains("ghp_nodewide"));
        assert_eq!(
            e.store.get_secret("site-shop").await.as_deref(),
            Some("ghp_sitewide")
        );
    }

    #[tokio::test]
    async fn a_source_site_with_no_token_anywhere_is_a_clear_400() {
        let (orch, _fake) = crate::orchestrator::tests::start_fake().await;
        let e = env_with(|_| {}, Some(Arc::new(orch))).await;
        let err = e
            .deployer
            .create_site("t", orchestrated_site("shop"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("set CITE_GITHUB_TOKEN on the connector")
        );
        assert!(e.store.config().sites.is_empty());
    }

    #[tokio::test]
    async fn failed_stack_start_on_create_leaves_no_site_or_secret() {
        let e = env_with(|_| {}, Some(unreachable_orchestrator())).await;
        let err = e
            .deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_secret".into()))
            .await;
        assert!(err.is_err());
        assert!(e.store.config().sites.is_empty());
        assert_eq!(e.store.get_secret("site-shop").await, None);
    }

    #[tokio::test]
    async fn rejected_apply_rolls_the_create_back() {
        let e = env_with(
            |cfg| {
                cfg.validate_with_haproxy = true;
                cfg.haproxy_bin = "false".into();
            },
            None,
        )
        .await;
        let err = e
            .deployer
            .create_site("t", new_site("shop"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)), "{err:?}");
        assert!(e.store.config().sites.is_empty());
    }

    // Rejects exactly one validation, and only after a delay, so a second mutation can overlap it.
    fn one_shot_rejecting_haproxy(dir: &std::path::Path) -> (String, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let armed = dir.join("armed");
        let script = dir.join("fake-haproxy");
        let body = format!(
            "#!/bin/sh\nif [ -e '{0}' ]; then rm -f '{0}'; sleep 0.4; echo rejected >&2; exit 1; fi\nexit 0\n",
            armed.display()
        );
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (script.display().to_string(), armed)
    }

    #[tokio::test]
    async fn a_failed_apply_does_not_wipe_a_concurrent_change_to_another_site() {
        let tools = tempfile::tempdir().unwrap();
        let (bin, armed) = one_shot_rejecting_haproxy(tools.path());
        let e = env_with(
            move |cfg| {
                cfg.validate_with_haproxy = true;
                cfg.haproxy_bin = bin;
            },
            None,
        )
        .await;
        created(&e).await;
        std::fs::write(&armed, b"").unwrap();
        let doomed = e.deployer.create_site("t", new_site("doomed"), None);
        let survivor = async {
            sleep(Duration::from_millis(100)).await;
            e.deployer
                .create_site("t", new_site("survivor"), None)
                .await
        };
        let (failed, kept) = tokio::join!(doomed, survivor);
        assert!(
            matches!(failed, Err(ConnectorError::BadRequest(_))),
            "{failed:?}"
        );
        assert!(kept.is_ok(), "{kept:?}");
        let ids: Vec<String> = e
            .store
            .config()
            .sites
            .iter()
            .map(|s| s.id.clone())
            .collect();
        assert!(ids.contains(&"shop".to_string()), "{ids:?}");
        assert!(ids.contains(&"survivor".to_string()), "{ids:?}");
        assert!(!ids.contains(&"doomed".to_string()), "{ids:?}");
        let text = std::fs::read_to_string(&e.cfg.haproxy_cfg).unwrap();
        assert!(text.contains("be_survivor_blue") && !text.contains("be_doomed_blue"));
    }

    #[tokio::test]
    async fn an_accepted_deploy_whose_targets_are_refused_is_recorded_as_failed() {
        let tools = tempfile::tempdir().unwrap();
        let (bin, armed) = one_shot_rejecting_haproxy(tools.path());
        let e = env_with(
            move |cfg| {
                cfg.validate_with_haproxy = true;
                cfg.haproxy_bin = bin;
            },
            None,
        )
        .await;
        created(&e).await;
        std::fs::write(&armed, b"").unwrap();
        let reply = e
            .deployer
            .deploy("t", "shop", Some(green_targets()), None, None, false)
            .await
            .unwrap();
        let DeployReply::Started(started) = reply else {
            panic!("expected an accepted deploy, got {reply:?}");
        };
        for _ in 0..100 {
            let site = current(&e, "shop");
            if let Some(entry) = site.history.iter().find(|d| d.id == started.deployment_id) {
                assert_eq!(entry.action, DeployAction::Failed);
                assert_eq!(entry.slot, Slot::Green);
                assert!(
                    entry.note.contains("could not be applied"),
                    "{}",
                    entry.note
                );
                assert_eq!(site.active, Slot::Blue);
                assert!(site.green.targets.is_empty());
                return;
            }
            sleep(Duration::from_millis(30)).await;
        }
        panic!("the refused deploy left no history entry");
    }

    #[tokio::test]
    async fn the_config_lock_is_shared_with_callers() {
        let e = env().await;
        let held = e.deployer.config_lock().lock().await;
        let blocked = tokio::time::timeout(
            Duration::from_millis(200),
            e.deployer.create_site("t", new_site("shop"), None),
        )
        .await;
        assert!(
            blocked.is_err(),
            "mutation ran while the config lock was held"
        );
        drop(held);
        // The abandoned create keeps running to completion once the lock is free.
        for _ in 0..50 {
            if e.store.config().sites.iter().any(|s| s.id == "shop") {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("the detached create never finished");
    }

    #[tokio::test]
    async fn unhealthy_create_still_succeeds_and_is_audited() {
        let e = env().await;
        set_down(&e, "be_shop_blue");
        let site = created(&e).await;
        assert_eq!(site.id, "shop");
        let tail = e.store.audit_tail(20).await;
        assert!(tail.iter().any(|a| a.action == "site.create.unhealthy"));
    }

    #[tokio::test]
    async fn deploy_promotes_the_idle_slot() {
        let e = env().await;
        created(&e).await;
        let done = e
            .deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), Some("v2".into()), None)
            .await
            .unwrap();
        assert_eq!(done.action, DeployAction::Promote);
        assert_eq!(done.slot, Slot::Green);
        assert_eq!(done.note, "v2");
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Green);
        assert_eq!(site.green.targets, green_targets());
        assert_eq!(site.blue.targets.len(), 2);
        assert_eq!(site.history, vec![done]);
        let sent = commands(&e);
        assert!(
            sent.iter()
                .any(|c| c.contains("/active.map shop be_shop_green")),
            "{sent:?}"
        );
        let map = std::fs::read_to_string(e.cfg.maps_dir.join("active.map")).unwrap();
        assert_eq!(map, "shop be_shop_green\n");
    }

    #[tokio::test]
    async fn deploy_without_targets_is_rejected() {
        let e = env().await;
        created(&e).await;
        for bad in [None, Some(vec![])] {
            let err = e
                .deployer
                .deploy_and_wait("t", "shop", bad, None, None)
                .await;
            assert!(matches!(err, Err(ConnectorError::BadRequest(_))));
        }
        assert!(current(&e, "shop").history.is_empty());
        let missing = e
            .deployer
            .deploy_and_wait("t", "ghost", Some(green_targets()), None, None)
            .await;
        assert!(matches!(missing, Err(ConnectorError::NotFound(_))));
    }

    #[tokio::test]
    async fn unhealthy_deploy_keeps_active_and_records_failure() {
        let e = env().await;
        created(&e).await;
        set_down(&e, "be_shop_green");
        let err = e
            .deployer
            .deploy_and_wait(
                "t",
                "shop",
                Some(green_targets()),
                Some("bad build".into()),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err:?}");
        assert!(err.to_string().contains("failed health checks"));
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Blue);
        assert_eq!(site.history.len(), 1);
        assert_eq!(site.history[0].action, DeployAction::Failed);
        assert_eq!(site.history[0].slot, Slot::Green);
        assert!(site.history[0].note.contains("bad build"));
        assert!(!commands(&e).iter().any(|c| c.starts_with("set map")));
        let map = std::fs::read_to_string(e.cfg.maps_dir.join("active.map")).unwrap();
        assert_eq!(map, "shop be_shop_blue\n");
    }

    #[tokio::test]
    async fn deploys_alternate_between_slots() {
        let e = env().await;
        created(&e).await;
        let first = e
            .deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None)
            .await;
        let blue = vec![target("10.0.2.1:8080")];
        let second = e
            .deployer
            .deploy_and_wait("t", "shop", Some(blue.clone()), None, None)
            .await;
        assert_eq!(first.unwrap().slot, Slot::Green);
        assert_eq!(second.unwrap().slot, Slot::Blue);
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Blue);
        assert_eq!(site.blue.targets, blue);
    }

    #[tokio::test]
    async fn concurrent_deploys_of_one_site_are_serialised() {
        let e = env().await;
        created(&e).await;
        let one = e
            .deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None);
        let two = e.deployer.deploy_and_wait(
            "t",
            "shop",
            Some(vec![target("10.0.3.1:8080")]),
            None,
            None,
        );
        let (a, b) = tokio::join!(one, two);
        assert!(a.is_ok() && b.is_ok());
        let slots: Vec<Slot> = current(&e, "shop").history.iter().map(|d| d.slot).collect();
        assert_eq!(slots.len(), 2);
        assert_ne!(slots[0], slots[1]);
    }

    #[tokio::test]
    async fn history_never_exceeds_the_cap() {
        let e = env().await;
        created(&e).await;
        for n in 0..(HISTORY_CAP + 4) {
            let t = vec![target(&format!("10.1.0.{}:8080", n % 200 + 1))];
            e.deployer
                .deploy_and_wait("t", "shop", Some(t), Some(format!("n{n}")), None)
                .await
                .unwrap();
        }
        let history = current(&e, "shop").history;
        assert_eq!(history.len(), HISTORY_CAP);
        assert_eq!(
            history.last().unwrap().note,
            format!("n{}", HISTORY_CAP + 3)
        );
        assert_eq!(history[0].note, "n4");
    }

    #[tokio::test]
    async fn switch_moves_traffic_between_populated_slots() {
        let e = env().await;
        created(&e).await;
        e.deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None)
            .await
            .unwrap();
        let moved = e.deployer.switch("t", "shop", Slot::Blue).await.unwrap();
        assert_eq!(moved.action, DeployAction::Switch);
        assert_eq!(moved.slot, Slot::Blue);
        assert_eq!(current(&e, "shop").active, Slot::Blue);
        let again = e.deployer.switch("t", "shop", Slot::Blue).await;
        assert!(matches!(again, Err(ConnectorError::Conflict(_))));
    }

    #[tokio::test]
    async fn switch_refuses_empty_or_unhealthy_slots() {
        let e = env().await;
        created(&e).await;
        let empty = e.deployer.switch("t", "shop", Slot::Green).await;
        assert!(matches!(empty, Err(ConnectorError::BadRequest(_))));
        e.deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None)
            .await
            .unwrap();
        set_down(&e, "be_shop_blue");
        let sick = e.deployer.switch("t", "shop", Slot::Blue).await;
        assert!(matches!(sick, Err(ConnectorError::Conflict(_))));
        assert_eq!(current(&e, "shop").active, Slot::Green);
    }

    #[tokio::test]
    async fn rollback_returns_to_the_previous_slot() {
        let e = env().await;
        created(&e).await;
        let none = e.deployer.rollback("t", "shop").await;
        assert!(matches!(none, Err(ConnectorError::BadRequest(_))));
        e.deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None)
            .await
            .unwrap();
        let back = e.deployer.rollback("t", "shop").await.unwrap();
        assert_eq!(back.action, DeployAction::Rollback);
        assert_eq!(back.slot, Slot::Blue);
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Blue);
        assert_eq!(site.history.last().unwrap().action, DeployAction::Rollback);
        let twice = e.deployer.rollback("t", "shop").await;
        assert!(matches!(twice, Err(ConnectorError::Conflict(_))));
    }

    #[tokio::test]
    async fn maintenance_toggle_uses_the_runtime_map() {
        let e = env().await;
        created(&e).await;
        let site = e
            .deployer
            .set_maintenance("t", "shop", true, None)
            .await
            .unwrap();
        assert!(site.maintenance.enabled);
        let sent = commands(&e);
        assert!(
            sent.iter().any(|c| c.contains("/maint.map shop on")),
            "{sent:?}"
        );
        let map = std::fs::read_to_string(e.cfg.maps_dir.join("maint.map")).unwrap();
        assert_eq!(map, "shop on\n");
        let off = e
            .deployer
            .set_maintenance("t", "shop", false, None)
            .await
            .unwrap();
        assert!(!off.maintenance.enabled);
    }

    #[tokio::test]
    async fn maintenance_page_change_reapplies_and_is_validated() {
        let e = env().await;
        created(&e).await;
        let missing = e
            .deployer
            .set_maintenance("t", "shop", true, Some("nope".into()))
            .await;
        assert!(matches!(missing, Err(ConnectorError::BadRequest(_))));
        assert!(!current(&e, "shop").maintenance.enabled);
        e.store
            .update("t", "page.create", |cfg| {
                cfg.pages.push(MaintenancePage {
                    id: "brb".into(),
                    name: "brb".into(),
                    html: "<p>brb</p>".into(),
                    status: 503,
                });
                Ok(())
            })
            .await
            .unwrap();
        let site = e
            .deployer
            .set_maintenance("t", "shop", true, Some("brb".into()))
            .await
            .unwrap();
        assert_eq!(site.maintenance.page_id.as_deref(), Some("brb"));
        let page = std::fs::read_to_string(e.cfg.pages_dir.join("brb.html")).unwrap();
        assert_eq!(page, "<p>brb</p>");
        let maint = std::fs::read_to_string(e.cfg.maps_dir.join("maint.map")).unwrap();
        assert_eq!(maint, "shop on\n");
        let off = e
            .deployer
            .set_maintenance("t", "shop", false, None)
            .await
            .unwrap();
        assert_eq!(off.maintenance.page_id.as_deref(), Some("brb"));
    }

    #[tokio::test]
    async fn update_keeps_history_and_replaces_other_fields() {
        let e = env().await;
        created(&e).await;
        e.deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None)
            .await
            .unwrap();
        let mut edit = new_site("shop");
        edit.hosts = vec!["renamed.example.com".into()];
        edit.active = Slot::Green;
        edit.green.targets = green_targets();
        let site = e.deployer.update_site("t", edit).await.unwrap();
        assert_eq!(site.hosts, vec!["renamed.example.com".to_string()]);
        assert_eq!(site.history.len(), 1);
        let cfg_text = std::fs::read_to_string(&e.cfg.haproxy_cfg).unwrap();
        assert!(cfg_text.contains("renamed.example.com"));
        let ghost = e.deployer.update_site("t", new_site("ghost")).await;
        assert!(matches!(ghost, Err(ConnectorError::NotFound(_))));
    }

    #[tokio::test]
    async fn update_ignores_stale_slots_active_and_maintenance() {
        let e = env().await;
        created(&e).await;
        e.deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None)
            .await
            .unwrap();
        let mut stale = new_site("shop");
        stale.name = "Renamed".into();
        stale.maintenance.enabled = true;
        let site = e.deployer.update_site("t", stale).await.unwrap();
        assert_eq!(site.name, "Renamed");
        assert_eq!(site.active, Slot::Green);
        assert_eq!(site.green.targets, green_targets());
        assert_eq!(site.blue.targets.len(), 2);
        assert!(!site.maintenance.enabled);
        let map = std::fs::read_to_string(e.cfg.maps_dir.join("active.map")).unwrap();
        assert_eq!(map, "shop be_shop_green\n");
    }

    #[tokio::test]
    async fn delete_is_refused_while_firewall_rules_name_the_site() {
        let e = env().await;
        created(&e).await;
        let rule = serde_json::from_value(json!({
            "id": "block-shop",
            "name": "block",
            "enabled": true,
            "action": "deny",
            "matchers": { "path_prefix": "/admin" },
            "site": "shop"
        }))
        .unwrap();
        e.store
            .update("t", "seed", move |cfg| {
                cfg.firewall.push(rule);
                Ok(())
            })
            .await
            .unwrap();
        let err = e.deployer.delete_site("t", "shop").await.unwrap_err();
        let ConnectorError::Conflict(msg) = &err else {
            panic!("expected Conflict, got {err:?}");
        };
        assert!(msg.contains("block-shop"), "{msg}");
        assert_eq!(e.store.config().sites.len(), 1);
    }

    #[tokio::test]
    async fn a_dropped_caller_does_not_cancel_a_deploy() {
        let e = env().await;
        created(&e).await;
        let held = e.deployer.config_lock().lock().await;
        let abandoned = tokio::time::timeout(
            Duration::from_millis(100),
            e.deployer
                .deploy_and_wait("t", "shop", Some(green_targets()), None, None),
        )
        .await;
        assert!(abandoned.is_err());
        drop(held);
        for _ in 0..60 {
            if current(&e, "shop").active == Slot::Green {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Green);
        assert_eq!(site.history.len(), 1);
        let map = std::fs::read_to_string(e.cfg.maps_dir.join("active.map")).unwrap();
        assert_eq!(map, "shop be_shop_green\n");
    }

    #[tokio::test]
    async fn a_changed_config_that_haproxy_refuses_rolls_the_change_back() {
        let reloads = Arc::new(StdMutex::new(0u32));
        let counter = reloads.clone();
        let master = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let master_addr = master.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = master.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut line = String::new();
                    let mut reader = BufReader::new(&mut stream);
                    let _ = reader.read_line(&mut line).await;
                    *counter.lock().unwrap() += 1;
                    let _ = stream.write_all(b"Success=0\n--\n[ALERT] refused\n").await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let e = env_with(move |cfg| cfg.master_addr = master_addr, None).await;
        let err = e
            .deployer
            .create_site("t", new_site("shop"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)), "{err:?}");
        assert!(e.store.config().sites.is_empty());
        assert!(*reloads.lock().unwrap() >= 1);
    }

    #[tokio::test]
    async fn rollback_restarts_a_drained_slot_on_the_ref_it_ran() {
        let (e, orch, _fake, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_testtoken".into()))
            .await
            .unwrap();
        e.deployer
            .deploy_and_wait("t", "shop", None, None, Some("v1".into()))
            .await
            .unwrap();
        e.deployer
            .deploy_and_wait("t", "shop", None, None, Some("v2".into()))
            .await
            .unwrap();
        for _ in 0..60 {
            if !orch.stack_running("shop", Slot::Green).await.unwrap() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(!orch.stack_running("shop", Slot::Green).await.unwrap());
        e.deployer.rollback("t", "shop").await.unwrap();
        assert_eq!(current(&e, "shop").active, Slot::Green);
        assert!(orch.stack_running("shop", Slot::Green).await.unwrap());
        let green = orch.slot_ref("shop", Slot::Green).await.unwrap();
        assert_eq!(green.as_deref(), Some("v1"));
    }

    #[tokio::test]
    async fn a_site_override_above_the_node_maximum_is_refused_at_update() {
        let (e, _orch, _docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        let mut edit = current(&e, "shop");
        edit.source.as_mut().unwrap().memory_mb = Some(64 * 1024);
        let err = e.deployer.update_site("t", edit).await.unwrap_err();
        assert!(
            matches!(&err, ConnectorError::BadRequest(m) if m.contains("CITE_STACK_MAX_MEM")),
            "{err:?}"
        );
        assert_eq!(current(&e, "shop").source.unwrap().memory_mb, None);
        let mut big = orchestrated_site("big");
        big.source.as_mut().unwrap().cpus = Some(cite_edge::model::Cpus(64.0));
        let err = e
            .deployer
            .create_site("t", big, Some("ghp_testtoken".into()))
            .await
            .unwrap_err();
        assert!(matches!(&err, ConnectorError::BadRequest(m) if m.contains("CITE_STACK_MAX_CPUS")));
    }

    async fn move_repo(e: &Env, repo: &str) {
        let mut edit = current(e, "shop");
        edit.source.as_mut().unwrap().repo = repo.to_string();
        e.deployer.update_site("t", edit).await.unwrap();
    }

    fn work_resets(docker: &Docker, slot: Slot) -> usize {
        crate::orchestrator::tests::count(
            docker,
            &format!("DELETE /volumes/cite-shop-{}-work", slot.as_str()),
        )
    }

    #[tokio::test]
    async fn a_token_change_after_a_repo_change_resets_the_build_volumes_once() {
        let (e, _orch, docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        assert_eq!(work_resets(&docker, Slot::Blue), 0);
        move_repo(&e, "owner/other").await;
        e.deployer
            .set_site_token(
                "t",
                "shop",
                zeroize::Zeroizing::new("ghp_secondtoken".into()),
            )
            .await
            .unwrap();
        assert_eq!(work_resets(&docker, Slot::Blue), 1);
        assert_eq!(
            crate::orchestrator::tests::count(&docker, "DELETE /volumes/cite-shop-blue-cache"),
            1
        );
        assert!(container_env(&docker, "cite-shop-blue-manager").contains("CITE_REPO=owner/other"));
        assert_eq!(
            crate::orchestrator::tests::count(&docker, "CREATE cite-shop-blue-executor"),
            1,
            "the live executor is never recreated"
        );
        e.deployer
            .set_site_token(
                "t",
                "shop",
                zeroize::Zeroizing::new("ghp_thirdtoken".into()),
            )
            .await
            .unwrap();
        assert_eq!(work_resets(&docker, Slot::Blue), 1);
    }

    #[tokio::test]
    async fn a_rollback_after_a_repo_change_starts_the_slot_on_fresh_build_volumes() {
        let (e, orch, docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        e.deployer
            .deploy_and_wait("t", "shop", None, None, Some("v1".into()))
            .await
            .unwrap();
        for _ in 0..60 {
            if !orch.stack_running("shop", Slot::Blue).await.unwrap() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(!orch.stack_running("shop", Slot::Blue).await.unwrap());
        move_repo(&e, "owner/other").await;
        e.deployer.rollback("t", "shop").await.unwrap();
        assert_eq!(current(&e, "shop").active, Slot::Blue);
        assert_eq!(work_resets(&docker, Slot::Blue), 1);
        assert_eq!(work_resets(&docker, Slot::Green), 0);
        let env = container_env(&docker, "cite-shop-blue-manager");
        assert!(env.contains("CITE_REPO=owner/other"), "{env}");
    }

    #[tokio::test]
    async fn build_volumes_without_a_record_are_reset_even_when_the_manager_is_gone() {
        let (e, _orch, docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        e.deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap();
        e.store.delete_secret(&repo_record("shop")).await;
        crate::orchestrator::tests::drop_container(&docker, "cite-shop-blue-manager");
        e.deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap();
        assert_eq!(work_resets(&docker, Slot::Blue), 1);
        let recorded = e.store.get_secret(&repo_record("shop")).await.unwrap();
        assert_eq!(recorded, r#"{"blue":"owner/repo"}"#);
        e.deployer.delete_site("t", "shop").await.unwrap();
        assert!(e.store.get_secret(&repo_record("shop")).await.is_none());
    }

    #[tokio::test]
    async fn an_older_drain_timer_does_not_stop_a_slot_that_went_idle_later() {
        let (e, orch, _fake, _sim) = docker_env(Duration::from_millis(600), None, None).await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_testtoken".into()))
            .await
            .unwrap();
        e.deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap();
        sleep(Duration::from_millis(200)).await;
        e.deployer.switch("t", "shop", Slot::Blue).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        e.deployer.switch("t", "shop", Slot::Green).await.unwrap();
        // The first timer fires here, only 200 ms after blue went idle.
        sleep(Duration::from_millis(400)).await;
        assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
        sleep(Duration::from_millis(900)).await;
        assert!(!orch.stack_running("shop", Slot::Blue).await.unwrap());
    }

    #[tokio::test]
    async fn startup_reconcile_stops_idle_stacks_once_the_active_slot_is_healthy() {
        let (e, orch, _fake, _sim) = docker_env(Duration::from_secs(600), None, None).await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_testtoken".into()))
            .await
            .unwrap();
        e.deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap();
        assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
        set_down(&e, "be_shop_green");
        e.deployer.reconcile_idle_stacks().await;
        assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
        e.fake.lock().unwrap().down.clear();
        e.deployer.reconcile_idle_stacks().await;
        assert!(!orch.stack_running("shop", Slot::Blue).await.unwrap());
        assert!(orch.stack_running("shop", Slot::Green).await.unwrap());
    }

    #[tokio::test]
    async fn startup_reconcile_reattaches_haproxy_even_when_the_site_is_unhealthy() {
        use crate::orchestrator::tests::{HAPROXY, members, recreate_haproxy};
        let (e, orch, fake, _sim) = docker_env(Duration::from_secs(600), None, None).await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_testtoken".into()))
            .await
            .unwrap();
        recreate_haproxy(&orch, &fake);
        set_down(&e, "be_shop_blue");
        assert!(!members(&fake, "cite-shop-blue-net").contains(HAPROXY));
        e.deployer.reconcile_idle_stacks().await;
        assert!(members(&fake, "cite-shop-blue-net").contains(HAPROXY));
    }

    #[tokio::test]
    async fn delete_removes_the_site_from_config_and_haproxy() {
        let e = env().await;
        created(&e).await;
        e.deployer.delete_site("t", "shop").await.unwrap();
        assert!(e.store.config().sites.is_empty());
        let cfg_text = std::fs::read_to_string(&e.cfg.haproxy_cfg).unwrap();
        assert!(!cfg_text.contains("be_shop_blue"));
        let again = e.deployer.delete_site("t", "shop").await;
        assert!(matches!(again, Err(ConnectorError::NotFound(_))));
        e.deployer
            .create_site("t", new_site("shop"), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn orchestrated_deploy_failure_is_recorded() {
        let e = env_with(|_| {}, Some(unreachable_orchestrator())).await;
        e.store
            .update("t", "seed", |cfg| {
                cfg.sites.push(orchestrated_site("shop"));
                Ok(())
            })
            .await
            .unwrap();
        let err = e
            .deployer
            .deploy_and_wait("t", "shop", None, Some("try".into()), Some("main".into()))
            .await;
        assert!(err.is_err());
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Blue);
        assert_eq!(site.history.len(), 1);
        assert_eq!(site.history[0].action, DeployAction::Failed);
        assert!(site.history[0].note.contains("try"));
    }

    #[tokio::test]
    async fn live_reports_target_statuses_from_haproxy() {
        let e = env().await;
        created(&e).await;
        e.deployer
            .deploy_and_wait("t", "shop", Some(green_targets()), None, None)
            .await
            .unwrap();
        set_down(&e, "be_shop_green");
        let live = e.deployer.live("shop").await.unwrap();
        assert_eq!(
            live["blue"][0],
            json!({"addr": "10.0.0.1:8080", "status": "UP"})
        );
        assert_eq!(live["blue"][1]["addr"], "10.0.0.2:8080");
        assert_eq!(
            live["green"][0],
            json!({"addr": "10.0.1.1:8080", "status": "DOWN"})
        );
        let ghost = e.deployer.live("ghost").await;
        assert!(matches!(ghost, Err(ConnectorError::NotFound(_))));
    }

    #[tokio::test]
    async fn live_is_unknown_when_haproxy_is_unreachable() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = closed.local_addr().unwrap().to_string();
        drop(closed);
        let e = env_with(move |cfg| cfg.runtime_addr = dead, None).await;
        created(&e).await;
        let live = e.deployer.live("shop").await.unwrap();
        assert_eq!(live["blue"][0]["status"], "UNKNOWN");
        assert_eq!(live["blue"][1]["status"], "UNKNOWN");
        assert_eq!(live["green"], json!([]));
    }

    async fn built(e: &Env, token: &str) {
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some(token.into()))
            .await
            .unwrap();
    }

    fn patch(key: &str, value: &str) -> BuildEnvPatch {
        BuildEnvPatch {
            set: [(key.to_string(), value.to_string())].into(),
            unset: Vec::new(),
        }
    }

    fn green_promoted(e: &Env) -> bool {
        commands(e)
            .iter()
            .any(|c| c.starts_with("set map") && c.contains("be_shop_green"))
    }

    fn error_line(text: &str) -> LogLine {
        LogLine {
            ts: Some("2026-01-01T00:00:00Z".into()),
            stream: "stderr".into(),
            level: Some("error".into()),
            phase: None,
            text: text.into(),
        }
    }

    #[tokio::test]
    async fn a_stale_release_is_not_promoted_before_the_manager_reports_the_new_deploy() {
        let (e, _orch, _docker, sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        sim.set_mode(Slot::Green, Mode::Stale);
        let deployer = e.deployer.clone();
        let running = tokio::spawn(async move {
            deployer
                .deploy_and_wait("t", "shop", None, Some("v2".into()), None)
                .await
        });
        sleep(Duration::from_millis(400)).await;
        assert_eq!(current(&e, "shop").active, Slot::Blue);
        assert!(!green_promoted(&e), "the old release went live");
        let during = e.deployer.site_status("shop").await.unwrap();
        let op = during.operation.expect("a running deploy is visible");
        assert_eq!((op.kind.as_str(), op.step.as_str()), ("deploy", "building"));
        assert_eq!(op.slot, Some(Slot::Green));
        assert_eq!(during.phase, "building");

        sim.set_mode(Slot::Green, Mode::Auto);
        let done = running.await.unwrap().unwrap();
        assert_eq!(done.slot, Slot::Green);
        assert_eq!(op.deploy_id.as_deref(), Some(done.id.as_str()));
        assert!(
            done.note.contains("v2") && done.note.contains(SHA),
            "{}",
            done.note
        );
        assert_eq!(current(&e, "shop").active, Slot::Green);
        assert!(green_promoted(&e));
        assert!(
            e.deployer
                .site_status("shop")
                .await
                .unwrap()
                .operation
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_failed_build_is_recorded_with_its_reason_and_the_active_slot_is_untouched() {
        let (e, orch, _docker, sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        sim.set_mode(Slot::Green, Mode::Fail("npm ci exited with 1".into()));
        let err = e
            .deployer
            .deploy_and_wait("t", "shop", None, Some("v2".into()), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err:?}");
        assert!(err.to_string().contains("npm ci exited with 1"));
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Blue);
        let last = site.history.last().unwrap();
        assert_eq!(
            (last.action, last.slot),
            (DeployAction::Failed, Slot::Green)
        );
        for part in ["npm ci exited with 1", "v2", SHA] {
            assert!(last.note.contains(part), "{} lacks {part}", last.note);
        }
        assert!(!green_promoted(&e));
        let map = std::fs::read_to_string(e.cfg.maps_dir.join("active.map")).unwrap();
        assert_eq!(map, "shop be_shop_blue\n");
        assert!(!orch.stack_running("shop", Slot::Green).await.unwrap());
        assert!(orch.stack_running("shop", Slot::Blue).await.unwrap());
        let status = e.deployer.site_status("shop").await.unwrap();
        assert_eq!(status.last_failure.unwrap().note, last.note);
        assert!(status.error.unwrap().contains("npm ci exited with 1"));
    }

    #[tokio::test]
    async fn a_build_that_never_reports_times_out_without_promoting() {
        let (e, _orch, _docker, sim) = docker_env(
            Duration::from_millis(50),
            None,
            Some(Duration::from_millis(300)),
        )
        .await;
        built(&e, "ghp_testtoken").await;
        sim.set_mode(Slot::Green, Mode::Silent);
        let err = e
            .deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("reported no result"), "{err}");
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Blue);
        let last = site.history.last().unwrap();
        assert_eq!(last.action, DeployAction::Failed);
        assert!(last.note.contains("sha unknown"), "{}", last.note);
        assert!(!green_promoted(&e));
    }

    #[tokio::test]
    async fn a_healthy_manager_without_a_report_fails_fast_naming_the_stack_version() {
        let (e, _orch, _docker, sim) = docker_env(
            Duration::from_millis(50),
            None,
            Some(Duration::from_secs(60)),
        )
        .await;
        built(&e, "ghp_testtoken").await;
        sim.set_mode(Slot::Green, Mode::Silent);
        let started = Instant::now();
        let err = e
            .deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        let text = err.to_string();
        assert!(text.contains("older than 0.4.0"), "{text}");
        assert!(text.contains("CITE_STACK_VERSION"), "{text}");
        let site = current(&e, "shop");
        assert_eq!(site.active, Slot::Blue);
        assert_eq!(site.history.last().unwrap().action, DeployAction::Failed);
        assert!(!green_promoted(&e));
    }

    #[tokio::test]
    async fn a_restart_loop_fails_the_deploy_with_the_last_error_lines() {
        let (e, _orch, _docker, sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        sim.set_mode(Slot::Green, Mode::Silent);
        {
            let mut state = sim.sim.lock().unwrap();
            state.restarts.insert(Slot::Green, 3);
            state.logs = vec![
                error_line("Error: Cannot find module 'next'"),
                LogLine {
                    level: Some("info".into()),
                    ..error_line("starting up")
                },
            ];
        }
        let err = e
            .deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("keeps restarting"), "{err}");
        let note = current(&e, "shop").history.last().unwrap().note.clone();
        assert!(note.contains("Cannot find module 'next'"), "{note}");
        assert!(!note.contains("starting up"), "{note}");
        assert_eq!(current(&e, "shop").active, Slot::Blue);
    }

    #[tokio::test]
    async fn an_unwaited_deploy_returns_its_id_and_finishes_in_the_background() {
        let (e, _orch, _docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        let reply = e
            .deployer
            .deploy("t", "shop", None, None, None, false)
            .await
            .unwrap();
        let DeployReply::Started(started) = reply else {
            panic!("expected an accepted deploy, got {reply:?}");
        };
        assert_eq!(started.deployment_id.len(), 26);
        assert_eq!(
            serde_json::to_value(DeployReply::Started(started.clone())).unwrap(),
            json!({ "deployment_id": started.deployment_id })
        );
        for _ in 0..100 {
            if current(&e, "shop")
                .history
                .iter()
                .any(|d| d.id == started.deployment_id && d.action == DeployAction::Promote)
            {
                return;
            }
            sleep(Duration::from_millis(30)).await;
        }
        panic!("the background deploy never promoted");
    }

    #[tokio::test]
    async fn an_unwaited_deploy_refuses_bad_requests_before_accepting() {
        let e = env().await;
        created(&e).await;
        let empty = e
            .deployer
            .deploy("t", "shop", None, None, None, false)
            .await;
        assert!(matches!(empty, Err(ConnectorError::BadRequest(_))));
        let ghost = e
            .deployer
            .deploy("t", "ghost", Some(green_targets()), None, None, false)
            .await;
        assert!(matches!(ghost, Err(ConnectorError::NotFound(_))));
        let waited = e
            .deployer
            .deploy("t", "shop", Some(green_targets()), None, None, true)
            .await
            .unwrap();
        assert!(matches!(waited, DeployReply::Finished(d) if d.slot == Slot::Green));
    }

    #[tokio::test]
    async fn a_new_token_is_stored_restarts_the_manager_and_is_verified() {
        let (e, _orch, docker, _sim) =
            docker_env(Duration::from_millis(50), Some("ghp_nodewide"), None).await;
        built(&e, "ghp_firsttoken").await;
        let status = e
            .deployer
            .set_site_token(
                "t",
                "shop",
                zeroize::Zeroizing::new("ghp_secondtoken".into()),
            )
            .await
            .unwrap();
        assert_eq!(status.source, "site");
        assert!(status.site_token_set && status.node_token_configured);
        assert_eq!(status.verified, Some(true));
        assert_eq!(status.status.as_deref(), Some("ok"));
        assert_eq!(
            e.store.get_secret("site-shop").await.as_deref(),
            Some("ghp_secondtoken")
        );
        assert!(container_env(&docker, "cite-shop-blue-manager").contains("ghp_secondtoken"));
        let audit = format!("{:?}", e.store.audit_tail(100).await);
        let edge = std::fs::read_to_string(e.cfg.data_dir.join("edge.json")).unwrap();
        for leak in ["ghp_secondtoken", "ghp_firsttoken"] {
            assert!(!audit.contains(leak) && !edge.contains(leak));
        }
    }

    #[tokio::test]
    async fn a_refused_token_is_replaced_by_the_previous_one() {
        let (e, _orch, docker, sim) =
            docker_env(Duration::from_millis(50), Some("ghp_nodewide"), None).await;
        built(&e, "ghp_firsttoken").await;
        sim.set_token(Slot::Blue, "invalid");
        let err = e
            .deployer
            .set_site_token("t", "shop", zeroize::Zeroizing::new("ghp_badtoken".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)), "{err:?}");
        assert!(!err.to_string().contains("ghp_badtoken"));
        assert_eq!(
            e.store.get_secret("site-shop").await.as_deref(),
            Some("ghp_firsttoken")
        );
        let env = container_env(&docker, "cite-shop-blue-manager");
        assert!(env.contains("ghp_firsttoken") && !env.contains("ghp_badtoken"));
        let audit = e.store.audit_tail(100).await;
        assert!(
            audit
                .iter()
                .any(|a| a.action == "site.github_token.restore")
        );
        assert!(!format!("{audit:?}").contains("ghp_"));
        assert!(
            e.deployer
                .site_status("shop")
                .await
                .unwrap()
                .operation
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_unverified_token_is_kept_and_marked_unverified() {
        let (e, _orch, _docker, sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_firsttoken").await;
        sim.set_token(Slot::Blue, "unknown");
        let status = e
            .deployer
            .set_site_token(
                "t",
                "shop",
                zeroize::Zeroizing::new("ghp_secondtoken".into()),
            )
            .await
            .unwrap();
        assert_eq!(status.verified, Some(false));
        assert_eq!(
            e.store.get_secret("site-shop").await.as_deref(),
            Some("ghp_secondtoken")
        );
    }

    #[tokio::test]
    async fn clearing_the_site_token_needs_a_node_token() {
        let (e, _orch, _docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_firsttoken").await;
        let err = e.deployer.clear_site_token("t", "shop").await.unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(_)), "{err:?}");
        assert_eq!(
            e.store.get_secret("site-shop").await.as_deref(),
            Some("ghp_firsttoken")
        );
        assert!(current(&e, "shop").source.unwrap().secret.is_some());
    }

    #[tokio::test]
    async fn clearing_the_site_token_falls_back_to_the_node_token() {
        let (e, _orch, docker, _sim) =
            docker_env(Duration::from_millis(50), Some("ghp_nodewide"), None).await;
        built(&e, "ghp_firsttoken").await;
        let status = e.deployer.clear_site_token("t", "shop").await.unwrap();
        assert_eq!(status.source, "node");
        assert!(!status.site_token_set);
        assert_eq!(e.store.get_secret("site-shop").await, None);
        assert_eq!(current(&e, "shop").source.unwrap().secret, None);
        assert!(container_env(&docker, "cite-shop-blue-manager").contains("ghp_nodewide"));
        let read = e.deployer.token_status("shop").await.unwrap();
        assert_eq!((read.source.as_str(), read.verified), ("node", Some(true)));
    }

    #[tokio::test]
    async fn build_and_runtime_env_are_stored_as_secrets_and_reach_the_next_deploy() {
        let (e, _orch, docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        let names = e
            .deployer
            .patch_build_env("t", "shop", patch("API_KEY", "build-value-0451"))
            .await
            .unwrap();
        assert_eq!(names.names, vec!["API_KEY".to_string()]);
        e.deployer
            .patch_runtime_env("t", "shop", patch("DB_PASSWORD", "runtime-value-0452"))
            .await
            .unwrap();
        assert_eq!(
            e.deployer.runtime_env_names("shop").await.unwrap().names,
            vec!["DB_PASSWORD".to_string()]
        );
        let bad = e
            .deployer
            .patch_build_env("t", "shop", patch("lower", "x"))
            .await;
        assert!(matches!(bad, Err(ConnectorError::BadRequest(_))));
        for owned in ["NODE_ENV", "PORT", "HOST", "HOSTNAME", "NITRO_HOST"] {
            let refused = e
                .deployer
                .patch_runtime_env("t", "shop", patch(owned, "production"))
                .await;
            assert!(
                matches!(&refused, Err(ConnectorError::BadRequest(m)) if m.contains(owned)),
                "{refused:?}"
            );
        }
        assert_eq!(
            e.deployer.runtime_env_names("shop").await.unwrap().names,
            vec!["DB_PASSWORD".to_string()]
        );
        let shell = e
            .deployer
            .patch_build_env("t", "shop", patch("SHELL", "/bin/bash"))
            .await;
        assert!(
            matches!(shell, Err(ConnectorError::BadRequest(_))),
            "{shell:?}"
        );
        assert!(!container_env(&docker, "cite-shop-blue-manager").contains("build-value-0451"));

        e.deployer
            .deploy_and_wait("t", "shop", None, None, None)
            .await
            .unwrap();
        assert!(container_env(&docker, "cite-shop-green-manager").contains("build-value-0451"));
        assert!(container_env(&docker, "cite-shop-green-executor").contains("runtime-value-0452"));
        let audit = format!("{:?}", e.store.audit_tail(200).await);
        for file in ["edge.json", "audit.jsonl"] {
            let text = std::fs::read_to_string(e.cfg.data_dir.join(file)).unwrap_or_default();
            for value in ["build-value-0451", "runtime-value-0452"] {
                assert!(
                    !text.contains(value) && !audit.contains(value),
                    "{file} holds {value}"
                );
            }
        }

        let cleared = BuildEnvPatch {
            set: Default::default(),
            unset: vec!["API_KEY".into()],
        };
        let names = e
            .deployer
            .patch_build_env("t", "shop", cleared)
            .await
            .unwrap();
        assert!(names.names.is_empty());
        assert_eq!(e.store.get_secret("site-shop.build-env").await, None);
        e.deployer.delete_site("t", "shop").await.unwrap();
        assert_eq!(e.store.get_secret("site-shop.runtime-env").await, None);
        assert_eq!(e.store.get_secret("site-shop").await, None);
    }

    #[tokio::test]
    async fn status_never_waits_for_the_site_lock() {
        let (e, _orch, _docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        let lock = e.deployer.site_lock("shop");
        let _held = lock.lock().await;
        let status = tokio::time::timeout(Duration::from_secs(2), e.deployer.site_status("shop"))
            .await
            .expect("status waited for the site lock")
            .unwrap();
        assert_eq!(status.active, Slot::Blue);
        assert_eq!(status.phase, "idle");
        assert_eq!(status.error, None);
        assert!(status.settings_current);
        assert_eq!(status.slots.len(), 2);
        let blue = status.slots.iter().find(|s| s.slot == Slot::Blue).unwrap();
        assert_eq!(blue.container, "running");
        assert_eq!(blue.haproxy.as_deref(), Some("UP"));
        assert!(blue.report.is_some());
        let green = status.slots.iter().find(|s| s.slot == Slot::Green).unwrap();
        assert_eq!(green.container, "missing");
        assert_eq!(green.haproxy, None);
    }

    #[tokio::test]
    async fn a_source_only_edit_is_stored_without_a_redeploy_and_shows_as_pending() {
        let (e, _orch, _docker, _sim) = docker_env(Duration::from_millis(50), None, None).await;
        built(&e, "ghp_testtoken").await;
        let site = current(&e, "shop");
        assert!(!e.deployer.pending_redeploy(&site).await);
        let mut edit = site.clone();
        edit.history.clear();
        if let Some(source) = edit.source.as_mut() {
            source.build_command = Some("npm run build".into());
            source.secret = None;
        }
        let saved = e.deployer.update_site("t", edit).await.unwrap();
        let source = saved.source.clone().unwrap();
        assert_eq!(source.build_command.as_deref(), Some("npm run build"));
        assert_eq!(source.secret.as_deref(), Some("site-shop"));
        assert_eq!(saved.history, site.history);
        assert_eq!(saved.active, Slot::Blue);
        assert!(e.deployer.pending_redeploy(&saved).await);
        assert!(
            !e.deployer
                .site_status("shop")
                .await
                .unwrap()
                .settings_current
        );
    }

    #[tokio::test]
    async fn logs_are_redacted_with_every_secret_of_the_site() {
        let (e, _orch, _docker, sim) =
            docker_env(Duration::from_millis(50), Some("ghp_nodewide"), None).await;
        built(&e, "ghp_sitetoken").await;
        e.deployer
            .patch_build_env("t", "shop", patch("API_KEY", "build-value-0451"))
            .await
            .unwrap();
        e.deployer
            .patch_runtime_env("t", "shop", patch("DB_PASSWORD", "runtime-value-0452"))
            .await
            .unwrap();
        let zone = e.deployer.haproxy.zones().rotate("shop").unwrap().secret;
        sim.sim.lock().unwrap().logs = vec![error_line("boom")];
        let query = LogQuery {
            source: LogSource::Manager,
            slot: None,
            tail: 50,
            since: Some("2026-01-01T00:00:00Z".into()),
        };
        let out = e.deployer.site_logs("shop", query).await.unwrap();
        assert_eq!(out.lines.len(), 1);
        assert_eq!(out.cursor.as_deref(), Some("1767225600.000000001"));
        let redact = sim.last_redactions();
        for secret in [
            "ghp_sitetoken",
            "ghp_nodewide",
            "build-value-0451",
            "runtime-value-0452",
            zone.as_str(),
        ] {
            assert!(
                redact.iter().any(|r| r == secret),
                "{secret} is not redacted"
            );
        }
    }
}
