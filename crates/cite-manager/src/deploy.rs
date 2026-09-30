use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use cite_core::schema::{
    DeployRecord, DesiredAction, ManagerState, Outcome, Slot, now_rfc3339, read_desired,
    read_state, write_state,
};
use cite_core::{ManagerConfig, PollInterval, ensure_dir};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::build::{cleanup_job, load_build_env, make_redactor, run_build_classified, wipe_work};
use crate::github::{CommitInfo, GithubClient, PollResult};
use crate::poll::{jittered_interval, next_poll_stamp, parse_rfc3339};
use crate::promote::{
    PromoteContext, PromoteOutcome, any_sealed_release, delete_unsealed_slots, ensure_slot_dirs,
    promote, write_action,
};
use crate::reconcile::{load_or_init_state, reconcile};
use crate::{ManagerError, Result};

#[derive(Debug, Clone)]
pub enum DeployCmd {
    Poll { force: bool },
    Redeploy { sha: Option<String> },
    Rollback,
    RestartChild,
    RestartExecutor,
    Pause,
    Resume,
}

pub struct Deployer {
    pub cfg: ManagerConfig,
    pub github: GithubClient,
    pub state: Mutex<ManagerState>,
    /// Newest head seen while a build was running; built next instead of queueing each one.
    pub pending_head: Mutex<Option<CommitInfo>>,
    pub building: Mutex<bool>,
    poll_failures: AtomicU32,
    shutting_down: AtomicBool,
    rejected_token: Mutex<Option<String>>,
}

const LOG_CAPACITY: usize = 500;
const POLL_BACKOFF_START: Duration = Duration::from_secs(5);
const POLL_BACKOFF_CAP: Duration = Duration::from_secs(300);

static LOG_RING: StdMutex<VecDeque<String>> = StdMutex::new(VecDeque::new());

pub fn push_log_line(line: String) {
    let mut ring = LOG_RING.lock().unwrap_or_else(|e| e.into_inner());
    ring.push_back(line);
    while ring.len() > LOG_CAPACITY {
        ring.pop_front();
    }
}

pub fn log_lines() -> Vec<String> {
    let ring = LOG_RING.lock().unwrap_or_else(|e| e.into_inner());
    ring.iter().cloned().collect()
}

/// Copies already-redacted build output events into the ring served by `cite logs`.
pub struct BuildLogLayer;

#[derive(Default)]
struct PhaseVisitor {
    is_build: bool,
}

impl tracing::field::Visit for PhaseVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "phase" && value == "build" {
            self.is_build = true;
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for BuildLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut phase = PhaseVisitor::default();
        event.record(&mut phase);
        if !phase.is_build {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        if let Some(message) = visitor.message {
            push_log_line(message);
        }
    }
}

/// Admits only info-and-above events from the build module so other callsites stay disabled.
pub fn build_log_filter<S>() -> impl tracing_subscriber::layer::Filter<S> {
    tracing_subscriber::filter::filter_fn(|meta| {
        meta.is_event()
            && meta.target() == "cite_manager::build"
            && *meta.level() <= tracing::Level::INFO
    })
    .with_max_level_hint(tracing::level_filters::LevelFilter::INFO)
}

struct PollFailure {
    err: ManagerError,
    backoff: bool,
}

impl<E: Into<ManagerError>> From<E> for PollFailure {
    fn from(err: E) -> Self {
        Self {
            err: err.into(),
            backoff: true,
        }
    }
}

type PollDone = (serde_json::Value, Option<Duration>);

impl Deployer {
    pub async fn new(cfg: ManagerConfig) -> Result<Arc<Self>> {
        ensure_dir(&cfg.releases_dir, 0o755)?;
        ensure_dir(&cfg.control_dir, 0o755)?;
        ensure_dir(&cfg.status_dir, 0o755)?;
        ensure_dir(&cfg.state_dir, 0o755)?;
        ensure_dir(&cfg.work_dir, 0o755)?;
        ensure_dir(&cfg.cache_dir, 0o755)?;
        ensure_slot_dirs(&cfg)?;
        cite_core::sweep_atomic_temps(&cfg.control_dir)?;
        cite_core::sweep_atomic_temps(&cfg.state_dir)?;
        cite_core::sweep_atomic_temps(&cfg.slot_dir(Slot::Blue))?;
        cite_core::sweep_atomic_temps(&cfg.slot_dir(Slot::Green))?;

        // Startup janitor: reclaim build-owned leftovers first.
        if let Err(err) = wipe_work(&cfg) {
            warn!(error = %err, "startup work-dir wipe failed; continuing");
        }
        delete_unsealed_slots(&cfg)?;
        reconcile(&cfg)?;

        let github = GithubClient::new(
            &cfg.github_api_url,
            &cfg.owner,
            &cfg.name,
            &cfg.branch,
            &cfg.github_token,
        )?
        .with_max_tarball_bytes(cfg.max_source_compressed_bytes);
        let state = load_or_init_state(&cfg)?;

        Ok(Arc::new(Self {
            cfg,
            github,
            state: Mutex::new(state),
            pending_head: Mutex::new(None),
            building: Mutex::new(false),
            poll_failures: AtomicU32::new(0),
            shutting_down: AtomicBool::new(false),
            rejected_token: Mutex::new(None),
        }))
    }

    pub async fn validate_github_with_backoff(self: &Arc<Self>) {
        let mut delay = std::time::Duration::from_secs(2);
        loop {
            match self.github.validate_access().await {
                Ok(ok) => {
                    let mut state = self.state.lock().await;
                    state.token_invalid = false;
                    state.token_expires_at = ok.token_expires_at;
                    let _ = write_state(&self.cfg.state_path(), &state);
                    info!("GitHub access validated");
                    return;
                }
                Err(err) => {
                    error!(error = %err, "GitHub validation failed; retrying");
                    let mut state = self.state.lock().await;
                    if err.to_string().contains("token") {
                        state.token_invalid = true;
                    }
                    let _ = write_state(&self.cfg.state_path(), &state);
                    tokio::time::sleep(delay).await;
                    delay = next_retry_delay(delay);
                }
            }
        }
    }

    /// Stops any deploy that has not reached its build yet; the caller aborts a running build.
    pub fn request_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    /// Brings desired.json and the manager state in line with what the executor actually runs.
    pub async fn adopt_reality(self: &Arc<Self>) -> Result<bool> {
        let mut state = self.state.lock().await;
        let adopted = reconcile(&self.cfg)?;
        if adopted && let Ok(disk) = read_state(&self.cfg.state_path()) {
            *state = disk;
        }
        Ok(adopted)
    }

    pub async fn handle(self: &Arc<Self>, cmd: DeployCmd) -> Result<serde_json::Value> {
        if !matches!(cmd, DeployCmd::Pause | DeployCmd::Resume)
            && let Err(err) = self.adopt_reality().await
        {
            warn!(error = %err, "could not reconcile with executor status");
        }
        match cmd {
            DeployCmd::Pause => {
                let mut state = self.state.lock().await;
                state.paused = true;
                write_state(&self.cfg.state_path(), &state)?;
                Ok(serde_json::json!({"paused": true}))
            }
            DeployCmd::Resume => {
                let mut state = self.state.lock().await;
                state.paused = false;
                write_state(&self.cfg.state_path(), &state)?;
                Ok(serde_json::json!({"paused": false}))
            }
            DeployCmd::Rollback => self.rollback().await,
            DeployCmd::RestartChild => self.simple_action(DesiredAction::RestartChild).await,
            DeployCmd::RestartExecutor => self.simple_action(DesiredAction::RestartExecutor).await,
            DeployCmd::Poll { force } => self.poll_and_maybe_deploy(force).await,
            DeployCmd::Redeploy { sha } => self.redeploy(sha).await,
        }
    }

    async fn simple_action(self: &Arc<Self>, action: DesiredAction) -> Result<serde_json::Value> {
        let live = read_desired(&self.cfg.desired_path())
            .map(|d| d.live_slot)
            .unwrap_or(Slot::Blue);
        let mut state = self.state.lock().await;
        let base = crate::promote::generation_floor(&self.cfg, state.generation);
        let generation = write_action(&self.cfg, action, live, None, base)?;
        state.generation = generation;
        write_state(&self.cfg.state_path(), &state)?;
        Ok(serde_json::json!({"generation": generation}))
    }

    async fn rollback(self: &Arc<Self>) -> Result<serde_json::Value> {
        let status = cite_core::read_status(&self.cfg.status_path()).ok();
        let desired = read_desired(&self.cfg.desired_path()).ok();
        let live = desired
            .as_ref()
            .map(|d| d.live_slot)
            .or_else(|| status.as_ref().and_then(|s| s.active_slot))
            .unwrap_or(Slot::Blue);
        let prev = live.other();
        if !cite_core::slot_is_sealed(&self.cfg.slot_dir(prev)) {
            return Err(ManagerError::new(
                "rollback refused: previous slot is empty/unsealed",
            ));
        }
        if let Some(status) = &status {
            let st = status.slot(prev).state;
            if matches!(
                st,
                cite_core::schema::SlotState::Empty | cite_core::schema::SlotState::Failed
            ) {
                return Err(ManagerError::new(
                    "rollback refused: previous slot is empty/failed",
                ));
            }
        }
        let mut state = self.state.lock().await;
        let base = crate::promote::generation_floor(&self.cfg, state.generation);
        let generation = write_action(&self.cfg, DesiredAction::Rollback, prev, None, base)?;
        state.generation = generation;
        write_state(&self.cfg.state_path(), &state)?;
        Ok(serde_json::json!({"generation": generation, "live_slot": prev.as_str()}))
    }

    pub async fn poll_and_maybe_deploy(self: &Arc<Self>, force: bool) -> Result<serde_json::Value> {
        match self.poll_inner(force).await {
            Ok((value, wait)) => {
                self.poll_failures.store(0, Ordering::Relaxed);
                match wait {
                    Some(wait) => self.schedule_next_poll(wait).await?,
                    None => self.schedule_next_poll_default().await?,
                }
                Ok(value)
            }
            Err(fail) => {
                if fail.backoff {
                    let failures = self
                        .poll_failures
                        .fetch_add(1, Ordering::Relaxed)
                        .saturating_add(1);
                    self.schedule_next_poll(poll_backoff(failures)).await?;
                } else {
                    self.poll_failures.store(0, Ordering::Relaxed);
                    self.schedule_next_poll_default().await?;
                }
                Err(fail.err)
            }
        }
    }

    async fn poll_inner(
        self: &Arc<Self>,
        force: bool,
    ) -> std::result::Result<PollDone, PollFailure> {
        let (etag, token_invalid) = {
            let state = self.state.lock().await;
            if state.paused && !force {
                return Ok((serde_json::json!({"skipped": "paused"}), None));
            }
            (state.poll_etag.clone(), state.token_invalid)
        };

        if token_invalid && !force {
            let current = self.github.read_token()?;
            if self.rejected_token.lock().await.as_deref() == Some(current.as_str()) {
                return Ok((serde_json::json!({"skipped": "token_invalid"}), None));
            }
        }

        let (result, hints) = match self.github.poll_head(etag.as_deref()).await {
            Ok(v) => v,
            Err(err) if err.to_string().contains("token_invalid") => {
                let rejected = self.github.read_token().ok();
                *self.rejected_token.lock().await = rejected;
                let mut state = self.state.lock().await;
                state.token_invalid = true;
                write_state(&self.cfg.state_path(), &state)?;
                return Err(PollFailure {
                    err,
                    backoff: false,
                });
            }
            Err(err) => return Err(err.into()),
        };

        if let Some(wait) = hints.backoff() {
            return Ok((serde_json::json!({"rate_limited": true}), Some(wait)));
        }

        {
            let mut state = self.state.lock().await;
            state.token_invalid = false;
        }
        *self.rejected_token.lock().await = None;

        let commit = match result {
            PollResult::Unchanged => {
                let (observed, unresolved) = {
                    let state = self.state.lock().await;
                    let observed = state
                        .last_observed_sha
                        .clone()
                        .or(state.last_deployed_sha.clone());
                    let unresolved = state.last_observed_sha.clone().filter(|sha| {
                        state.last_deployed_sha.as_deref() != Some(sha.as_str())
                            && state.last_failed_sha.as_deref() != Some(sha.as_str())
                    });
                    (observed, unresolved)
                };
                if force && let Some(sha) = observed {
                    let done = self.deploy_sha(&sha, "(redeploy)", "unknown", true).await?;
                    return Ok((done, None));
                }
                if self.cfg.paths.is_empty()
                    && let Some(sha) = unresolved
                {
                    let commit = CommitInfo {
                        sha,
                        message: "(retry)".into(),
                        author: "unknown".into(),
                        etag: None,
                    };
                    let done = self.consider_deploy(commit, false).await?;
                    return Ok((done, None));
                }
                return Ok((serde_json::json!({"unchanged": true}), None));
            }
            PollResult::Changed(info) => info,
        };

        if !self.cfg.paths.is_empty() {
            let prev = self.state.lock().await.last_deployed_sha.clone();
            if let Some(prev) = prev {
                let changed = self
                    .github
                    .paths_changed(&prev, &commit.sha, &self.cfg.paths)
                    .await?;
                if !changed && !force {
                    self.settle_head(&commit).await?;
                    return Ok((serde_json::json!({"skipped": "paths"}), None));
                }
            }
        }

        let sha = commit.sha.clone();
        let deployed = self.consider_deploy(commit.clone(), force).await;
        let permanent = self.state.lock().await.last_failed_sha.as_deref() == Some(sha.as_str());
        match deployed {
            Ok(done) => {
                if done["coalesced"] != true {
                    self.settle_head(&commit).await?;
                }
                Ok((done, None))
            }
            Err(err) if permanent => {
                self.settle_head(&commit).await?;
                Err(PollFailure {
                    err,
                    backoff: false,
                })
            }
            Err(err) => Err(err.into()),
        }
    }

    /// The head is recorded as handled only once deployed, failed for good, or skipped, so a transient failure is retried.
    async fn settle_head(self: &Arc<Self>, commit: &CommitInfo) -> Result<()> {
        let mut state = self.state.lock().await;
        state.last_observed_sha = Some(commit.sha.clone());
        if let Some(tag) = &commit.etag {
            state.poll_etag = Some(tag.clone());
        }
        write_state(&self.cfg.state_path(), &state)?;
        Ok(())
    }

    async fn redeploy(self: &Arc<Self>, sha: Option<String>) -> Result<serde_json::Value> {
        let (sha, message, author) = if let Some(sha) = sha {
            (sha, "(redeploy)".into(), "operator".into())
        } else {
            let (result, _) = self.github.poll_head(None).await?;
            match result {
                PollResult::Changed(info) => (info.sha, info.message, info.author),
                PollResult::Unchanged => {
                    return Err(ManagerError::new("no head commit available"));
                }
            }
        };
        self.deploy_sha(&sha, &message, &author, true).await
    }

    async fn consider_deploy(
        self: &Arc<Self>,
        commit: CommitInfo,
        force: bool,
    ) -> Result<serde_json::Value> {
        let state = self.state.lock().await;
        let skip = !force
            && (state.last_deployed_sha.as_deref() == Some(commit.sha.as_str())
                || state.last_failed_sha.as_deref() == Some(commit.sha.as_str()));
        // A sha already deployed or already failed is skipped unless forced.
        drop(state);
        if skip {
            return Ok(serde_json::json!({"skipped": "already_seen"}));
        }

        self.deploy_sha(&commit.sha, &commit.message, &commit.author, force)
            .await
    }

    async fn deploy_sha(
        self: &Arc<Self>,
        sha: &str,
        message: &str,
        author: &str,
        _force: bool,
    ) -> Result<serde_json::Value> {
        {
            let state = self.state.lock().await;
            if state.token_invalid {
                return Err(ManagerError::new("token_invalid; deploys stopped"));
            }
        }

        let mut current = CommitInfo {
            sha: sha.to_string(),
            message: message.to_string(),
            author: author.to_string(),
            etag: None,
        };
        {
            let mut building = self.building.lock().await;
            if *building {
                *self.pending_head.lock().await = Some(current);
                return Ok(serde_json::json!({"coalesced": true}));
            }
            *building = true;
        }
        loop {
            let outcome = self
                .deploy_sha_inner(&current.sha, &current.message, &current.author)
                .await;

            let mut building = self.building.lock().await;
            let pending = self.pending_head.lock().await.take();
            match pending {
                Some(next) if next.sha != current.sha => {
                    info!(sha = %next.sha, "building coalesced head");
                    current = next;
                    // The newer head supersedes the prior outcome.
                    let _ = outcome;
                }
                _ => {
                    *building = false;
                    return outcome;
                }
            }
        }
    }

    async fn deploy_sha_inner(
        self: &Arc<Self>,
        sha: &str,
        message: &str,
        author: &str,
    ) -> Result<serde_json::Value> {
        info!(%sha, "deploy starting");
        let token = self.github.read_token()?;
        let build_env = load_build_env(&self.cfg)?;
        let redactor = make_redactor(&token, &build_env);

        let tarball = match self.github.fetch_tarball(sha).await {
            Ok(bytes) => bytes,
            Err(err) => {
                if err.to_string().contains("token_invalid") {
                    self.state.lock().await.token_invalid = true;
                }
                self.record_transient_failure(sha, &err.to_string()).await?;
                return Err(err);
            }
        };

        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(ManagerError::new("shutdown requested; build not started"));
        }

        let built = match run_build_classified(&self.cfg, &tarball, sha, message, author, &redactor)
            .await
        {
            Ok(b) => b,
            Err(failure) => {
                let err = ManagerError::from(failure.clone());
                warn!(%sha, error = %err, "build failed; live release untouched");
                push_log_line(redactor.redact_line(&format!("build failed: {err}")));
                let _ = wipe_work(&self.cfg);
                if self.shutting_down.load(Ordering::SeqCst) {
                    return Err(err);
                }
                if failure.is_transient() {
                    self.record_transient_failure(sha, &err.to_string()).await?;
                } else {
                    let mut state = self.state.lock().await;
                    state.last_failed_sha = Some(sha.to_string());
                    state.last_failed_reason = Some(err.to_string());
                    write_state(&self.cfg.state_path(), &state)?;
                }
                return Err(err);
            }
        };

        let generation = {
            let state = self.state.lock().await;
            crate::promote::generation_floor(&self.cfg, state.generation)
        };

        let promote_result = promote(PromoteContext {
            cfg: &self.cfg,
            built: &built,
            generation,
        })
        .await;

        {
            // Promote may have written generations before failing; later actions must start above them.
            let mut state = self.state.lock().await;
            state.generation = crate::promote::generation_floor(&self.cfg, state.generation);
            write_state(&self.cfg.state_path(), &state)?;
        }

        let job_dir = built.job_dir.clone();
        let _ = cleanup_job(&self.cfg, &job_dir);

        match promote_result {
            Ok(PromoteOutcome::Live) => {
                let fell_back = self.adopt_reality().await.unwrap_or_else(|err| {
                    warn!(error = %err, "could not reconcile after promote");
                    false
                });
                let mut state = self.state.lock().await;
                if fell_back {
                    warn!(%sha, "executor fell back to the previous release");
                    state.last_failed_sha = Some(sha.to_string());
                    let reason = state.last_failed_reason.clone().unwrap_or_default();
                    state.history.push(DeployRecord {
                        sha: sha.to_string(),
                        release_id: built.release_id.clone(),
                        slot: free_slot_guess(&self.cfg),
                        at: now_rfc3339(),
                        outcome: "fallback".into(),
                        reason,
                    });
                    write_state(&self.cfg.state_path(), &state)?;
                    if let Err(err) = wipe_work(&self.cfg) {
                        warn!(error = %err, "work-dir wipe failed; continuing");
                    }
                    return Ok(serde_json::json!({"outcome": "failed", "sha": sha}));
                }
                state.last_deployed_sha = Some(sha.to_string());
                state.last_failed_sha = None;
                state.last_failed_reason = None;
                state.history.push(DeployRecord {
                    sha: sha.to_string(),
                    release_id: built.release_id.clone(),
                    slot: free_slot_guess(&self.cfg),
                    at: now_rfc3339(),
                    outcome: "live".into(),
                    reason: String::new(),
                });
                if state.history.len() > 20 {
                    let drop_n = state.history.len() - 20;
                    state.history.drain(0..drop_n);
                }
                write_state(&self.cfg.state_path(), &state)?;
                if let Err(err) = wipe_work(&self.cfg) {
                    warn!(error = %err, "work-dir wipe failed; continuing");
                }
                Ok(serde_json::json!({"outcome": "live", "sha": sha}))
            }
            Ok(PromoteOutcome::FailedHealth) => {
                let mut state = self.state.lock().await;
                state.last_failed_sha = Some(sha.to_string());
                state.last_failed_reason = Some("health gate failed".into());
                state.history.push(DeployRecord {
                    sha: sha.to_string(),
                    release_id: built.release_id.clone(),
                    slot: free_slot_guess(&self.cfg),
                    at: now_rfc3339(),
                    outcome: format!("{:?}", Outcome::Failed).to_ascii_lowercase(),
                    reason: "health gate failed".into(),
                });
                write_state(&self.cfg.state_path(), &state)?;
                if let Err(err) = wipe_work(&self.cfg) {
                    warn!(error = %err, "work-dir wipe failed; continuing");
                }
                Ok(serde_json::json!({"outcome": "failed", "sha": sha}))
            }
            Err(err) => {
                // Promote errors (evict timeout, executor down) are transient, so last_failed_sha is not set.
                warn!(%sha, error = %err, "promote failed");
                self.record_transient_failure(sha, &err.to_string()).await?;
                if let Err(err) = wipe_work(&self.cfg) {
                    warn!(error = %err, "work-dir wipe failed; continuing");
                }
                Err(err)
            }
        }
    }

    async fn record_transient_failure(self: &Arc<Self>, _sha: &str, reason: &str) -> Result<()> {
        let mut state = self.state.lock().await;
        state.last_failed_reason = Some(reason.to_string());
        state.last_failed_attempts = state.last_failed_attempts.saturating_add(1);
        write_state(&self.cfg.state_path(), &state)?;
        Ok(())
    }

    async fn schedule_next_poll_default(self: &Arc<Self>) -> Result<()> {
        let wait = match self.cfg.poll {
            PollInterval::Off => return Ok(()),
            PollInterval::Every(base) => {
                let unit = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos())
                    % 1000;
                jittered_interval(base, unit)
            }
        };
        self.schedule_next_poll(wait).await
    }

    async fn schedule_next_poll(self: &Arc<Self>, wait: std::time::Duration) -> Result<()> {
        let mut state = self.state.lock().await;
        let now = time::OffsetDateTime::now_utc();
        state.next_poll_at = Some(next_poll_stamp(now, wait));
        write_state(&self.cfg.state_path(), &state)?;
        Ok(())
    }

    pub async fn status_json(self: &Arc<Self>) -> Result<serde_json::Value> {
        let state = read_state(&self.cfg.state_path()).unwrap_or_default();
        let status = cite_core::read_status(&self.cfg.status_path()).ok();
        let desired = read_desired(&self.cfg.desired_path()).ok();
        let responsive = crate::promote::executor_responsive(&self.cfg).unwrap_or(false);
        let disk_free_bytes = cite_core::filesystem_free_bytes(&self.cfg.releases_dir).ok();
        Ok(serde_json::json!({
            "paused": state.paused,
            "token_invalid": state.token_invalid,
            "token_expires_at": state.token_expires_at,
            "last_observed_sha": state.last_observed_sha,
            "last_deployed_sha": state.last_deployed_sha,
            "last_failed_sha": state.last_failed_sha,
            "last_failed_reason": state.last_failed_reason,
            "next_poll_at": state.next_poll_at,
            "history": state.history,
            "desired": desired,
            "executor": status,
            "executor_unresponsive": !responsive,
            "disk_free_bytes": disk_free_bytes,
        }))
    }

    pub async fn maybe_first_boot_deploy(self: &Arc<Self>) {
        if any_sealed_release(&self.cfg) {
            return;
        }
        info!("first boot with no sealed release; deploying branch head");
        if let Err(err) = self.poll_and_maybe_deploy(true).await {
            error!(error = %err, "first-boot deploy failed");
        }
    }

    pub fn next_poll_wait(&self, state: &ManagerState) -> crate::poll::PollDecision {
        let now = time::OffsetDateTime::now_utc();
        let next = state.next_poll_at.as_deref().and_then(parse_rfc3339);
        crate::poll::decide_poll(self.cfg.poll, next, now)
    }
}

fn free_slot_guess(cfg: &ManagerConfig) -> Slot {
    crate::promote::free_slot(cfg).unwrap_or(Slot::Green)
}

pub(crate) fn next_retry_delay(current: std::time::Duration) -> std::time::Duration {
    (current * 2).min(std::time::Duration::from_secs(300))
}

pub(crate) fn poll_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    POLL_BACKOFF_START
        .saturating_mul(1u32 << shift)
        .min(POLL_BACKOFF_CAP)
}

#[cfg(test)]
mod tests {
    use super::{BuildLogLayer, build_log_filter, log_lines, next_retry_delay, poll_backoff};
    use std::time::Duration;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn validation_backoff_doubles_and_caps_at_five_minutes() {
        let mut delay = Duration::from_secs(2);
        let mut seen = vec![delay];
        for _ in 0..10 {
            delay = next_retry_delay(delay);
            seen.push(delay);
        }
        assert_eq!(seen[1], Duration::from_secs(4));
        assert_eq!(seen[2], Duration::from_secs(8));
        assert!(seen.iter().all(|d| *d <= Duration::from_secs(300)));
        assert_eq!(*seen.last().unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn poll_retry_backoff_doubles_and_caps() {
        assert_eq!(poll_backoff(1), Duration::from_secs(5));
        assert_eq!(poll_backoff(2), Duration::from_secs(10));
        assert_eq!(poll_backoff(3), Duration::from_secs(20));
        assert_eq!(poll_backoff(7), Duration::from_secs(300));
        assert_eq!(poll_backoff(u32::MAX), Duration::from_secs(300));
    }

    #[test]
    fn build_output_events_reach_the_log_ring() {
        let subscriber = tracing_subscriber::registry().with(BuildLogLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(phase = "build", "unique-build-line-7f3a");
            tracing::info!("unrelated-event-7f3a");
        });
        let lines = log_lines();
        assert!(lines.iter().any(|l| l == "unique-build-line-7f3a"));
        assert!(!lines.iter().any(|l| l == "unrelated-event-7f3a"));
    }

    #[test]
    fn build_log_filter_admits_only_info_build_events() {
        let subscriber =
            tracing_subscriber::registry().with(BuildLogLayer.with_filter(build_log_filter()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "cite_manager::build", phase = "build", "filter-accepted-91c2");
            tracing::debug!(target: "cite_manager::build", phase = "build", "filter-debug-91c2");
            tracing::trace!(target: "cite_manager::build", phase = "build", "filter-trace-91c2");
            tracing::info!(target: "hyper::client", phase = "build", "filter-other-target-91c2");
        });
        let lines = log_lines();
        assert!(lines.iter().any(|l| l == "filter-accepted-91c2"));
        for rejected in [
            "filter-debug-91c2",
            "filter-trace-91c2",
            "filter-other-target-91c2",
        ] {
            assert!(
                !lines.iter().any(|l| l == rejected),
                "{rejected} was admitted"
            );
        }
    }

    #[tokio::test]
    async fn actions_start_above_generations_written_by_a_failed_promote() {
        use cite_core::schema::{Desired, ExecutorStatus, Slot, write_desired, write_status};
        use std::collections::HashMap;

        let tmp = tempfile::tempdir().unwrap();
        let token = tmp.path().join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert(
            "CITE_DATA_DIR".into(),
            tmp.path().join("data").display().to_string(),
        );
        env.insert(
            "CITE_WORK_DIR".into(),
            tmp.path().join("work").display().to_string(),
        );
        env.insert(
            "CITE_CACHE_DIR".into(),
            tmp.path().join("cache").display().to_string(),
        );
        env.insert("CITE_GITHUB_TOKEN_FILE".into(), token.display().to_string());
        env.insert("CITE_DEV_SAME_USER".into(), "true".into());
        env.insert("CITE_MIN_FREE_BYTES".into(), "1".into());
        env.insert("CITE_POLL_INTERVAL".into(), "off".into());
        let cfg = cite_core::ManagerConfig::load_from(&env, None).unwrap();
        let deployer = super::Deployer::new(cfg.clone()).await.unwrap();
        deployer.state.lock().await.generation = 3;

        write_desired(&cfg.desired_path(), &Desired::noop(9, Slot::Blue, 30)).unwrap();
        let mut status = ExecutorStatus::initial("test");
        status.ack_generation = 8;
        write_status(&cfg.status_path(), &status).unwrap();

        let done = deployer
            .handle(super::DeployCmd::RestartChild)
            .await
            .unwrap();
        assert_eq!(done["generation"], 10);
        assert_eq!(deployer.state.lock().await.generation, 10);
    }
}
