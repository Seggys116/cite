//! Node-to-node database transfers run by the dashboard server (design N5).
//!
//! The server drives `cite_client::transfer` between two configured nodes on behalf of a browser user, so the dump
//! never passes through a browser: the browser starts, watches, resumes, cancels, cuts over and rolls back through
//! `/api/v1/transfers`. States live in `transfers.json` next to the dashboard config (mode 0600, no secrets: the
//! generated secrets a transfer carries exist only in memory while the manifest is handed from one node to the other).
//! One task runs per active transfer and at most two run at once. A transfer that was running when the server stopped
//! comes back as `failed` and can be resumed; the nodes' own sessions are the source of truth.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use cite_client::transfer::{self, DEFAULT_POLL, TransferEnv};
use cite_client::{
    CancelFlag, ClientError, TransferPhase, TransferPlan, TransferState, TransferStore,
};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::{AppState, lock};

/// Transfers moving data at once.
pub const MAX_RUNNING: usize = 2;
/// States kept in the file; the oldest finished ones go first.
const MAX_KEPT: usize = 100;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const FILE_MODE: u32 = 0o600;
const FILE_NAME: &str = "transfers.json";
const FILE_VERSION: u32 = 1;
const INTERRUPTED: &str = "interrupted by a dashboard restart; resume to continue";

#[derive(Debug, Serialize, Deserialize)]
struct StoredFile {
    version: u32,
    #[serde(default)]
    transfers: Vec<TransferState>,
}

/// A transfer as the browser sees it.
#[derive(Debug, Clone, Serialize)]
pub struct TransferView {
    #[serde(flatten)]
    pub state: TransferState,
    /// A task of this server is working on it right now.
    pub running: bool,
    /// The data is on the target and the counts were compared: only cutover or rollback is left.
    pub awaiting_operator: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Run,
    Resume,
    Cutover,
    Rollback,
}

#[derive(Default)]
struct Inner {
    states: HashMap<String, TransferState>,
    running: HashMap<String, CancelFlag>,
}

pub struct TransferHub {
    app: Arc<AppState>,
    /// None keeps the states in memory only.
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

/// What a state reloaded from disk needs: a step that was running has no task any more.
pub(crate) fn mark_interrupted(state: &mut TransferState) -> bool {
    match state.phase {
        TransferPhase::Done | TransferPhase::RolledBack | TransferPhase::Failed => false,
        // Verified and waiting for the operator: nothing was running.
        TransferPhase::Verifying if state.counts_match.is_some() => false,
        // A cutover that stopped halfway stays a cutover so that resuming finishes it.
        TransferPhase::Cutover => {
            state.error = Some(INTERRUPTED.to_string());
            true
        }
        _ => {
            state.phase = TransferPhase::Failed;
            state.error = Some(INTERRUPTED.to_string());
            true
        }
    }
}

/// Two unfinished transfers of one database may not share a source or a target.
pub(crate) fn overlaps(a: &TransferPlan, b: &TransferPlan) -> bool {
    a.site == b.site
        && a.database == b.database
        && (a.source_node == b.source_node || a.target_node == b.target_node)
}

/// The states to keep, newest first; past the cap the oldest finished transfers are dropped.
pub(crate) fn retained(mut states: Vec<TransferState>) -> Vec<TransferState> {
    states.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    while states.len() > MAX_KEPT {
        match states.iter().rposition(|s| s.phase.is_finished()) {
            Some(at) => {
                states.remove(at);
            }
            None => break,
        }
    }
    states
}

fn internal(detail: impl std::fmt::Display) -> ApiError {
    ApiError::internal(detail)
}

impl TransferHub {
    /// Loads the states saved in `path` (a missing file is an empty list) and marks the interrupted ones failed.
    pub fn load(app: Arc<AppState>, path: Option<PathBuf>) -> Arc<TransferHub> {
        let mut states: HashMap<String, TransferState> = HashMap::new();
        if let Some(p) = &path {
            match cite_client::fsio::read_limited(p, MAX_FILE_BYTES) {
                Ok(bytes) => match serde_json::from_slice::<StoredFile>(&bytes) {
                    Ok(file) if file.version == FILE_VERSION => {
                        for s in file.transfers {
                            states.insert(s.id.clone(), s);
                        }
                    }
                    Ok(file) => tracing::warn!(
                        version = file.version,
                        "transfers.json has an unknown version; it is ignored"
                    ),
                    Err(e) => tracing::warn!("transfers.json is not valid; it is ignored: {e}"),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!("transfers.json cannot be read: {e}"),
            }
        }
        let mut changed = false;
        for s in states.values_mut() {
            changed |= mark_interrupted(s);
        }
        let hub = Arc::new(TransferHub {
            app,
            path,
            inner: Mutex::new(Inner {
                states,
                running: HashMap::new(),
            }),
        });
        if changed {
            let inner = lock(&hub.inner);
            if let Err(e) = hub.persist(&inner) {
                tracing::warn!("transfers.json cannot be updated: {e}");
            }
        }
        hub
    }

    /// `transfers.json` beside the dashboard config.
    pub fn path_beside(config_path: &std::path::Path) -> PathBuf {
        config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from(FILE_NAME), |dir| dir.join(FILE_NAME))
    }

    fn persist(&self, inner: &Inner) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = StoredFile {
            version: FILE_VERSION,
            transfers: retained(inner.states.values().cloned().collect()),
        };
        let bytes = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
        cite_client::fsio::write_atomic(path, &bytes, FILE_MODE).map_err(|e| e.to_string())
    }

    fn view(inner: &Inner, state: &TransferState) -> TransferView {
        TransferView {
            state: state.clone(),
            running: inner.running.contains_key(&state.id),
            awaiting_operator: state.awaiting_operator(),
        }
    }

    pub fn list(&self) -> Vec<TransferView> {
        let inner = lock(&self.inner);
        retained(inner.states.values().cloned().collect())
            .iter()
            .map(|s| Self::view(&inner, s))
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<TransferView> {
        let inner = lock(&self.inner);
        inner.states.get(id).map(|s| Self::view(&inner, s))
    }

    fn require(&self, id: &str) -> Result<TransferState, ApiError> {
        lock(&self.inner)
            .states
            .get(id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("transfer not found"))
    }

    /// Progress from a running task; memory only, the disk copy is written by the store on phase changes.
    fn touch(&self, state: &TransferState) {
        lock(&self.inner)
            .states
            .insert(state.id.clone(), state.clone());
    }

    /// Starts a transfer from a plan. The nodes must be configured, and at most two transfers run at once.
    pub async fn create(self: &Arc<Self>, plan: TransferPlan) -> Result<TransferView, ApiError> {
        let plan = plan
            .validated()
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        for node in [&plan.source_node, &plan.target_node] {
            if self.app.client(node).await.is_none() {
                return Err(ApiError::not_found(format!(
                    "node {node} is not configured"
                )));
            }
        }
        let state = TransferState::new(plan).map_err(|e| ApiError::bad_request(e.to_string()))?;
        {
            let mut inner = lock(&self.inner);
            if inner
                .states
                .values()
                .any(|s| !s.phase.is_finished() && overlaps(&s.plan, &state.plan))
            {
                return Err(ApiError::conflict(
                    "an unfinished transfer of this database already uses one of these nodes; finish, resume or roll it back first",
                ));
            }
            inner.states.insert(state.id.clone(), state.clone());
            self.persist(&inner).map_err(internal)?;
        }
        if let Err(e) = self.launch(&state.id, Mode::Run) {
            let mut inner = lock(&self.inner);
            inner.states.remove(&state.id);
            let _ = self.persist(&inner);
            return Err(e);
        }
        self.get(&state.id)
            .ok_or_else(|| internal("a new transfer vanished"))
    }

    /// Continues a transfer that failed or was cancelled, from what the nodes report.
    pub fn resume(self: &Arc<Self>, id: &str) -> Result<TransferView, ApiError> {
        let state = self.require(id)?;
        if state.phase.is_finished() {
            return Err(ApiError::conflict("the transfer is already finished"));
        }
        if state.awaiting_operator() {
            return Err(ApiError::conflict(
                "the data is on the target and was compared; cut over or roll back",
            ));
        }
        self.launch(id, Mode::Resume)?;
        self.get(id)
            .ok_or_else(|| ApiError::not_found("transfer not found"))
    }

    /// Asks a running transfer to stop at its next step; it ends as `failed` and can be resumed or rolled back.
    pub fn cancel(&self, id: &str) -> Result<TransferView, ApiError> {
        self.require(id)?;
        {
            let inner = lock(&self.inner);
            match inner.running.get(id) {
                Some(flag) => flag.cancel(),
                None => return Err(ApiError::conflict("the transfer is not running")),
            }
        }
        self.get(id)
            .ok_or_else(|| ApiError::not_found("transfer not found"))
    }

    /// Finishes both sides once the data is verified (or a cutover that stopped halfway).
    pub fn cutover(self: &Arc<Self>, id: &str) -> Result<TransferView, ApiError> {
        let state = self.require(id)?;
        if state.phase.is_finished() {
            return Err(ApiError::conflict("the transfer is already finished"));
        }
        let ready = state.phase == TransferPhase::Cutover
            || (state.awaiting_operator() && state.counts_match == Some(true));
        if !ready {
            return Err(ApiError::conflict(
                "the transfer can cut over once the data is on the target and the row counts match",
            ));
        }
        self.launch(id, Mode::Cutover)?;
        self.get(id)
            .ok_or_else(|| ApiError::not_found("transfer not found"))
    }

    /// Abandons a transfer that has not cut over: the target's import is aborted and the source's freeze is lifted.
    pub fn rollback(self: &Arc<Self>, id: &str) -> Result<TransferView, ApiError> {
        let state = self.require(id)?;
        if state.phase.is_finished() {
            return Err(ApiError::conflict("the transfer is already finished"));
        }
        self.launch(id, Mode::Rollback)?;
        self.get(id)
            .ok_or_else(|| ApiError::not_found("transfer not found"))
    }

    /// Registers the task and starts it; refuses a transfer that already has one and a third task.
    fn launch(self: &Arc<Self>, id: &str, mode: Mode) -> Result<(), ApiError> {
        let cancel = CancelFlag::new();
        {
            let mut inner = lock(&self.inner);
            if inner.running.contains_key(id) {
                return Err(ApiError::conflict("the transfer is already running"));
            }
            if inner.running.len() >= MAX_RUNNING {
                return Err(ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "two transfers are already running; wait for one to finish",
                ));
            }
            inner.running.insert(id.to_string(), cancel.clone());
        }
        let (hub, id) = (Arc::clone(self), id.to_string());
        tokio::spawn(async move {
            hub.drive(&id, mode, cancel).await;
            lock(&hub.inner).running.remove(&id);
        });
        Ok(())
    }

    async fn drive(self: &Arc<Self>, id: &str, mode: Mode, cancel: CancelFlag) {
        let Ok(mut state) = self.require(id) else {
            return;
        };
        let source = self.app.client(&state.plan.source_node).await;
        let target = self.app.client(&state.plan.target_node).await;
        let (Some(source), Some(target)) = (source, target) else {
            state.phase = TransferPhase::Failed;
            state.error = Some("a node of this transfer is no longer configured".to_string());
            self.touch(&state);
            let inner = lock(&self.inner);
            let _ = self.persist(&inner);
            return;
        };
        let store = HubStore(Arc::clone(self));
        let hub = Arc::clone(self);
        let progress = move |s: &TransferState| hub.touch(s);
        let env = TransferEnv {
            source: &source,
            target: &target,
            store: &store,
            cancel,
            progress: &progress,
            poll: DEFAULT_POLL,
        };
        let result = match mode {
            Mode::Run => transfer::run(&env, &mut state).await,
            Mode::Resume => transfer::resume(&env, &mut state).await,
            Mode::Cutover => transfer::cutover(&env, &mut state).await,
            Mode::Rollback => transfer::rollback(&env, &mut state).await,
        };
        if let Err(e) = result {
            // Node messages never carry secrets, so the text is safe to log.
            tracing::warn!(transfer = %id, phase = ?state.phase, "transfer step stopped: {e}");
        }
    }
}

struct HubStore(Arc<TransferHub>);

impl TransferStore for HubStore {
    fn load(&self, id: &str) -> Option<TransferState> {
        lock(&self.0.inner).states.get(id).cloned()
    }

    fn save(&self, state: &TransferState) -> Result<(), ClientError> {
        let mut inner = lock(&self.0.inner);
        inner.states.insert(state.id.clone(), state.clone());
        self.0
            .persist(&inner)
            .map_err(|e| ClientError::Config(format!("cannot save the transfer state: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_client::{DashboardConfig, MemoryTokenStore, TokenStore};
    use cite_edge::datawire::Freeze;

    fn plan(site: &str, source: &str, target: &str) -> TransferPlan {
        TransferPlan {
            source_node: source.into(),
            target_node: target.into(),
            site: site.into(),
            database: "pg:app".into(),
            freeze: Freeze::Maintenance,
            override_manual: false,
            replace: false,
            auto_cutover: false,
        }
    }

    fn state(phase: TransferPhase) -> TransferState {
        let mut s = TransferState::new(plan("shop", "a", "b")).unwrap();
        s.phase = phase;
        s
    }

    fn app(dir: &std::path::Path) -> Arc<AppState> {
        let mut env = std::collections::HashMap::new();
        env.insert(
            "CITE_DASHBOARD_CONFIG".to_string(),
            dir.join("dashboard.json").display().to_string(),
        );
        let settings = crate::Settings::from_env_map(&env).expect("settings");
        AppState::new(
            settings,
            DashboardConfig::default(),
            Arc::new(MemoryTokenStore::new()) as Arc<dyn TokenStore>,
        )
    }

    #[test]
    fn a_state_reloaded_from_disk_fails_only_when_a_step_was_running() {
        for phase in [
            TransferPhase::Pending,
            TransferPhase::Freezing,
            TransferPhase::Dumping,
            TransferPhase::Streaming,
            TransferPhase::Restoring,
        ] {
            let mut s = state(phase);
            assert!(mark_interrupted(&mut s), "{phase:?}");
            assert_eq!(s.phase, TransferPhase::Failed);
            assert!(s.error.as_deref().unwrap().contains("dashboard restart"));
        }
        for phase in [
            TransferPhase::Done,
            TransferPhase::RolledBack,
            TransferPhase::Failed,
        ] {
            let mut s = state(phase);
            assert!(!mark_interrupted(&mut s), "{phase:?}");
            assert!(s.error.is_none());
        }
        // Verifying while the target restores (no counts yet) was running; after the comparison it waits for the operator.
        let mut mid = state(TransferPhase::Verifying);
        assert!(mark_interrupted(&mut mid));
        assert_eq!(mid.phase, TransferPhase::Failed);
        let mut waiting = state(TransferPhase::Verifying);
        waiting.counts_match = Some(true);
        assert!(!mark_interrupted(&mut waiting));
        assert_eq!(waiting.phase, TransferPhase::Verifying);
        // A half-finished cutover keeps its phase so that resuming finishes it.
        let mut cut = state(TransferPhase::Cutover);
        assert!(mark_interrupted(&mut cut));
        assert_eq!(cut.phase, TransferPhase::Cutover);
        assert!(cut.error.is_some());
    }

    #[test]
    fn transfers_of_one_database_may_not_share_a_node() {
        let base = plan("shop", "a", "b");
        assert!(overlaps(&base, &plan("shop", "a", "c")), "same source");
        assert!(overlaps(&base, &plan("shop", "c", "b")), "same target");
        assert!(!overlaps(&base, &plan("shop", "c", "d")));
        assert!(!overlaps(&base, &plan("blog", "a", "b")), "another site");
        let mut other_db = plan("shop", "a", "b");
        other_db.database = "pg:billing".into();
        assert!(!overlaps(&base, &other_db));
    }

    #[test]
    fn the_cap_drops_the_oldest_finished_transfers_and_never_an_unfinished_one() {
        let mut all = Vec::new();
        for i in 0..(MAX_KEPT + 5) {
            let mut s = state(if i == 0 {
                TransferPhase::Streaming
            } else {
                TransferPhase::Done
            });
            s.updated_at = format!("2026-01-01T00:{:02}:{:02}Z", i / 60, i % 60);
            all.push(s);
        }
        let oldest_unfinished = all[0].id.clone();
        let kept = retained(all);
        assert_eq!(kept.len(), MAX_KEPT);
        assert!(
            kept.iter().any(|s| s.id == oldest_unfinished),
            "an unfinished transfer is kept"
        );
        assert!(
            kept.windows(2).all(|w| w[0].updated_at >= w[1].updated_at),
            "newest first"
        );
    }

    #[tokio::test]
    async fn states_are_saved_without_secrets_and_come_back_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = TransferHub::path_beside(&dir.path().join("dashboard.json"));
        assert_eq!(path, dir.path().join("transfers.json"));
        let hub = TransferHub::load(app(dir.path()), Some(path.clone()));
        assert!(hub.list().is_empty());

        let mut running = state(TransferPhase::Streaming);
        running.bytes_done = 10;
        running.bytes_total = 20;
        let mut waiting = state(TransferPhase::Verifying);
        waiting.counts_match = Some(true);
        waiting.plan.site = "blog".into();
        let store = HubStore(Arc::clone(&hub));
        store.save(&running).unwrap();
        store.save(&waiting).unwrap();
        assert_eq!(store.load(&running.id).unwrap().bytes_done, 10);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&running.id) && text.contains("\"version\":1"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let again = TransferHub::load(app(dir.path()), Some(path.clone()));
        let a = again
            .get(&running.id)
            .expect("the running transfer is remembered");
        assert_eq!(
            a.state.phase,
            TransferPhase::Failed,
            "it had no task after the restart"
        );
        assert!(!a.running);
        assert_eq!(a.state.bytes_done, 10);
        let w = again
            .get(&waiting.id)
            .expect("the waiting transfer is remembered");
        assert_eq!(w.state.phase, TransferPhase::Verifying);
        assert!(w.awaiting_operator && !w.running);
        // The interruption was written back, so a second restart sees the same.
        let third = TransferHub::load(app(dir.path()), Some(path));
        assert_eq!(
            third.get(&running.id).unwrap().state.phase,
            TransferPhase::Failed
        );
        assert_eq!(third.list().len(), 2);
    }

    #[tokio::test]
    async fn the_actions_check_what_the_state_allows_before_anything_runs() {
        let dir = tempfile::tempdir().unwrap();
        let hub = TransferHub::load(app(dir.path()), None);
        let store = HubStore(Arc::clone(&hub));
        let finished = state(TransferPhase::Done);
        let mut waiting = state(TransferPhase::Verifying);
        waiting.counts_match = Some(true);
        waiting.plan.site = "blog".into();
        let mut mismatch = state(TransferPhase::Verifying);
        mismatch.counts_match = Some(false);
        mismatch.plan.site = "docs".into();
        for s in [&finished, &waiting, &mismatch] {
            store.save(s).unwrap();
        }
        let code = |r: Result<TransferView, ApiError>| r.map(|_| ()).unwrap_err().status();
        assert_eq!(code(hub.resume("nope")), StatusCode::NOT_FOUND);
        assert_eq!(code(hub.resume(&finished.id)), StatusCode::CONFLICT);
        assert_eq!(
            code(hub.resume(&waiting.id)),
            StatusCode::CONFLICT,
            "waiting for the operator"
        );
        assert_eq!(code(hub.cutover(&finished.id)), StatusCode::CONFLICT);
        assert_eq!(
            code(hub.cutover(&mismatch.id)),
            StatusCode::CONFLICT,
            "counts differ"
        );
        assert_eq!(code(hub.rollback(&finished.id)), StatusCode::CONFLICT);
        assert_eq!(
            code(hub.cancel(&waiting.id)),
            StatusCode::CONFLICT,
            "nothing is running"
        );
        assert_eq!(code(hub.cancel("nope")), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_plan_is_checked_before_it_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let hub = TransferHub::load(app(dir.path()), None);
        let bad = |mut p: TransferPlan, f: fn(&mut TransferPlan)| {
            f(&mut p);
            p
        };
        let ok = plan("shop", "a", "b");
        for p in [
            bad(ok.clone(), |p| p.target_node = "a".into()),
            bad(ok.clone(), |p| p.site = "Bad Site".into()),
            bad(ok.clone(), |p| p.database = "ext:billing".into()),
        ] {
            let err = hub.create(p).await.map(|_| ()).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        }
        // Valid, but the nodes are not configured on this dashboard.
        let err = hub.create(ok).await.map(|_| ()).unwrap_err();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert!(
            hub.list().is_empty(),
            "a refused plan leaves nothing behind"
        );
    }
}
