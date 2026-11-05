use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use cite_edge::model::{
    DeployAction, Deployment, EdgeConfig, Maintenance, Site, Slot, Target, Upstream,
};
use cite_edge::validate::validate_site;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::error::{ConnectorError, Result};
use crate::haproxy::Haproxy;
use crate::orchestrator::Orchestrator;
use crate::store::{Store, now_rfc3339};

const HISTORY_CAP: usize = 50;
const CREATE_HEALTH: Duration = Duration::from_secs(30);
const DEPLOY_HEALTH: Duration = Duration::from_secs(60);
const DRAIN_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
struct Timing {
    create_health: Duration,
    deploy_health: Duration,
    drain: Duration,
}

pub struct Deployer {
    store: Arc<Store>,
    haproxy: Arc<Haproxy>,
    orchestrator: Option<Arc<Orchestrator>>,
    locks: StdMutex<HashMap<String, Arc<Mutex<()>>>>,
    // Bumped by every drain schedule so an older timer can tell a later switch happened.
    drain_gen: Arc<StdMutex<HashMap<String, u64>>>,
    config_lock: Mutex<()>,
    timing: Timing,
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

fn upstream(site: &Site, slot: Slot) -> &Upstream {
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

fn site_mut<'a>(cfg: &'a mut EdgeConfig, id: &str) -> Result<&'a mut Site> {
    cfg.sites
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| not_found(id))
}

fn secret_name(site_id: &str) -> String {
    format!("site-{site_id}")
}

fn deployment(slot: Slot, action: DeployAction, note: String) -> Deployment {
    Deployment {
        id: ulid::Ulid::generate().to_string(),
        at: now_rfc3339(),
        slot,
        action,
        note,
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
        Deployer {
            store,
            haproxy,
            orchestrator,
            locks: StdMutex::new(HashMap::new()),
            drain_gen: Arc::default(),
            config_lock: Mutex::new(()),
            timing: Timing {
                create_health: CREATE_HEALTH,
                deploy_health: DEPLOY_HEALTH,
                drain: DRAIN_DELAY,
            },
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
            drain,
        };
        self
    }

    // Config changes, their apply and any restore after a failed apply share this lock, so a restore never wipes another operation's change.
    pub fn config_lock(&self) -> &Mutex<()> {
        &self.config_lock
    }

    fn site_lock(&self, id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        locks.entry(id.to_string()).or_default().clone()
    }

    fn orchestrator(&self) -> Result<&Arc<Orchestrator>> {
        self.orchestrator.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("orchestration is not enabled on this node".into())
        })
    }

    fn get_site(&self, id: &str) -> Result<Site> {
        self.store
            .config()
            .sites
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .ok_or_else(|| not_found(id))
    }

    async fn token_for(&self, site: &Site) -> String {
        match site.source.as_ref().and_then(|s| s.secret.as_deref()) {
            Some(name) => self.store.get_secret(name).await.unwrap_or_default(),
            None => String::new(),
        }
    }

    async fn restore(&self, actor: &str, action: &str, previous: Arc<EdgeConfig>) {
        let snapshot = previous.clone();
        let label = format!("{action}.restore");
        let restored = self
            .store
            .update(actor, &label, move |cfg| {
                *cfg = (*snapshot).clone();
                Ok(())
            })
            .await;
        match restored {
            Ok(()) => {
                if let Err(err) = self.haproxy.apply(&previous).await {
                    tracing::warn!("haproxy could not re-apply the restored config: {err}");
                }
            }
            Err(err) => tracing::error!("config could not be restored after {action}: {err}"),
        }
    }

    // A failed apply restores the previous config so the store never holds a state HAProxy rejected.
    async fn mutate_apply<T>(
        &self,
        actor: &str,
        action: &str,
        change: impl FnOnce(&mut EdgeConfig) -> Result<T>,
    ) -> Result<T> {
        let _gate = self.config_lock.lock().await;
        let previous = self.store.config();
        let out = self.store.update(actor, action, change).await?;
        let loaded = self
            .haproxy
            .apply(&self.store.config())
            .await
            .and_then(|applied| applied.require_loaded());
        if let Err(err) = loaded {
            self.restore(actor, action, previous).await;
            return Err(err);
        }
        Ok(out)
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

    async fn record_failure(&self, actor: &str, id: &str, slot: Slot, note: &str, reason: &str) {
        let text = if note.is_empty() {
            reason.to_string()
        } else {
            format!("{reason} ({note})")
        };
        self.record(actor, id, deployment(slot, DeployAction::Failed, text))
            .await;
    }

    async fn drop_secret(&self, name: Option<&str>) {
        if let Some(name) = name {
            self.store.delete_secret(name).await;
        }
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
        validate_site(&site)?;
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
        if site.source.is_some() {
            let orch = self.orchestrator()?;
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
            let token_text = token.as_deref().unwrap_or("");
            let started = orch.ensure_stack(&site, active, None, token_text).await;
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
        validate_site(&site)?;
        let id = site.id.clone();
        let lock = self.site_lock(&id);
        let _guard = lock.lock().await;
        let existing = self.get_site(&id)?;
        if site.source.is_some() && self.orchestrator.is_none() {
            return Err(ConnectorError::BadRequest(
                "orchestration is not enabled on this node".into(),
            ));
        }
        site.history = existing.history;
        site.active = existing.active;
        site.blue = existing.blue;
        site.green = existing.green;
        site.maintenance = existing.maintenance;
        if let Some(source) = site.source.as_mut() {
            source.secret = existing.source.and_then(|s| s.secret);
        }
        let sid = id.clone();
        self.mutate_apply(actor, "site.update", move |cfg| {
            *site_mut(cfg, &sid)? = site;
            Ok(())
        })
        .await?;
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
    ) -> Result<Deployment> {
        let (this, actor, id) = (Arc::clone(self), actor.to_string(), id.to_string());
        detach(async move { this.deploy_inner(&actor, &id, targets, note, git_ref).await }).await
    }

    async fn deploy_inner(
        &self,
        actor: &str,
        id: &str,
        targets: Option<Vec<Target>>,
        note: Option<String>,
        git_ref: Option<String>,
    ) -> Result<Deployment> {
        let lock = self.site_lock(id);
        let _guard = lock.lock().await;
        let site = self.get_site(id)?;
        let (old, idle) = (site.active, site.active.other());
        let orchestrated = site.source.is_some();
        let note = note.unwrap_or_default();
        let new_targets = if orchestrated {
            let orch = self.orchestrator()?;
            let token = self.token_for(&site).await;
            match orch
                .ensure_stack(&site, idle, git_ref.as_deref(), &token)
                .await
            {
                Ok(started) => started,
                Err(err) => {
                    let reason = format!("stack could not be started: {err}");
                    self.record_failure(actor, id, idle, &note, &reason).await;
                    return Err(err);
                }
            }
        } else {
            targets.filter(|t| !t.is_empty()).ok_or_else(|| {
                ConnectorError::BadRequest("a deploy needs at least one target".into())
            })?
        };
        let sid = id.to_string();
        let staged = self
            .mutate_apply(actor, "site.deploy.stage", move |cfg| {
                upstream_mut(site_mut(cfg, &sid)?, idle).targets = new_targets;
                Ok(())
            })
            .await;
        if let Err(err) = staged {
            self.stop_stack_quietly(id, idle).await;
            return Err(err);
        }
        let wait = self.timing.deploy_health;
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
            self.record_failure(actor, id, idle, &note, &reason).await;
            self.stop_stack_quietly(id, idle).await;
            return Err(ConnectorError::Conflict(format!(
                "deploy failed health checks: the {} slot of {id} never came up, active slot unchanged",
                idle.as_str()
            )));
        }
        let promoted = self
            .promote(actor, id, old, idle, DeployAction::Promote, note)
            .await?;
        if orchestrated {
            self.schedule_drain(id, old, idle);
        }
        Ok(promoted)
    }

    // The runtime map flips before the store is updated, so a failed flip leaves the stored slot alone.
    async fn promote(
        &self,
        actor: &str,
        id: &str,
        old: Slot,
        slot: Slot,
        action: DeployAction,
        note: String,
    ) -> Result<Deployment> {
        let gate = self.config_lock.lock().await;
        if let Err(err) = self.haproxy.set_active(id, slot).await {
            // Put the map file back so a later reload cannot route to the slot that never went live.
            let _ = self.haproxy.set_active(id, old).await;
            drop(gate);
            let reason = format!("switching traffic failed: {err}");
            self.record_failure(actor, id, slot, &note, &reason).await;
            return Err(err);
        }
        let entry = deployment(slot, action, note);
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
            .wait_healthy(id, slot, self.timing.deploy_health)
            .await?;
        if !healthy {
            return Err(ConnectorError::Conflict(format!(
                "the {} slot of {id} is not healthy, traffic was not moved",
                slot.as_str()
            )));
        }
        let moved = self
            .promote(actor, id, site.active, slot, action, note)
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
        let started = orch
            .ensure_stack(site, slot, git_ref.as_deref(), &token)
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
            self.restore(actor, "site.maintenance", previous).await;
            return Err(err);
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

    use cite_edge::model::{HealthCheck, MaintenancePage, SiteKind, Source};
    use tempfile::TempDir;
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

    async fn env_with(
        tweak: impl FnOnce(&mut crate::config::ConnectorConfig),
        orchestrator: Option<Arc<Orchestrator>>,
    ) -> Env {
        env_full(tweak, orchestrator, Duration::from_millis(50)).await
    }

    async fn env_full(
        tweak: impl FnOnce(&mut crate::config::ConnectorConfig),
        orchestrator: Option<Arc<Orchestrator>>,
        drain: Duration,
    ) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let (addr, fake) = start_fake().await;
        let mut cfg = test_config(dir.path());
        cfg.runtime_addr = addr;
        tweak(&mut cfg);
        let store = Store::open(&cfg).await.unwrap();
        let haproxy = Arc::new(Haproxy::new(&cfg));
        let short = Duration::from_millis(600);
        let deployer = Arc::new(
            Deployer::new(store.clone(), haproxy, orchestrator).with_timing(
                Duration::from_millis(300),
                short,
                drain,
            ),
        );
        Env {
            _dir: dir,
            deployer,
            store,
            fake,
            cfg,
        }
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
            path_regex: None,
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
        site.source = Some(Source {
            repo: "owner/repo".into(),
            branch: None,
            runtime: None,
            node_major: None,
            poll_interval: None,
            secret: None,
        });
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
            .deploy("t", "shop", Some(green_targets()), Some("v2".into()), None)
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
            let err = e.deployer.deploy("t", "shop", bad, None, None).await;
            assert!(matches!(err, Err(ConnectorError::BadRequest(_))));
        }
        assert!(current(&e, "shop").history.is_empty());
        let missing = e
            .deployer
            .deploy("t", "ghost", Some(green_targets()), None, None)
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
            .deploy(
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
            .deploy("t", "shop", Some(green_targets()), None, None)
            .await;
        let blue = vec![target("10.0.2.1:8080")];
        let second = e
            .deployer
            .deploy("t", "shop", Some(blue.clone()), None, None)
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
            .deploy("t", "shop", Some(green_targets()), None, None);
        let two = e
            .deployer
            .deploy("t", "shop", Some(vec![target("10.0.3.1:8080")]), None, None);
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
                .deploy("t", "shop", Some(t), Some(format!("n{n}")), None)
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
            .deploy("t", "shop", Some(green_targets()), None, None)
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
            .deploy("t", "shop", Some(green_targets()), None, None)
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
            .deploy("t", "shop", Some(green_targets()), None, None)
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
            .deploy("t", "shop", Some(green_targets()), None, None)
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
            .deploy("t", "shop", Some(green_targets()), None, None)
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
                .deploy("t", "shop", Some(green_targets()), None, None),
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
        let (orch, _fake) = crate::orchestrator::tests::start_fake().await;
        let orch = Arc::new(orch);
        let e = env_with(|_| {}, Some(orch.clone())).await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_testtoken".into()))
            .await
            .unwrap();
        e.deployer
            .deploy("t", "shop", None, None, Some("v1".into()))
            .await
            .unwrap();
        e.deployer
            .deploy("t", "shop", None, None, Some("v2".into()))
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
    async fn an_older_drain_timer_does_not_stop_a_slot_that_went_idle_later() {
        let (orch, _fake) = crate::orchestrator::tests::start_fake().await;
        let orch = Arc::new(orch);
        let drain = Duration::from_millis(600);
        let e = env_full(|_| {}, Some(orch.clone()), drain).await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_testtoken".into()))
            .await
            .unwrap();
        e.deployer
            .deploy("t", "shop", None, None, None)
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
        let (orch, _fake) = crate::orchestrator::tests::start_fake().await;
        let orch = Arc::new(orch);
        let e = env_full(|_| {}, Some(orch.clone()), Duration::from_secs(600)).await;
        e.deployer
            .create_site("t", orchestrated_site("shop"), Some("ghp_testtoken".into()))
            .await
            .unwrap();
        e.deployer
            .deploy("t", "shop", None, None, None)
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
        let (orch, fake) = crate::orchestrator::tests::start_fake().await;
        let orch = Arc::new(orch);
        let e = env_full(|_| {}, Some(orch.clone()), Duration::from_secs(600)).await;
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
            .deploy("t", "shop", None, Some("try".into()), Some("main".into()))
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
            .deploy("t", "shop", Some(green_targets()), None, None)
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
}
