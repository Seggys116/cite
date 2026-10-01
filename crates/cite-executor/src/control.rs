#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use cite_core::schema::Rendering;
use cite_core::{
    Desired, DesiredAction, ExecutorConfig, ExecutorStatus, LastResult, Outcome, Redactor,
    ReleaseManifest, Slot, SlotState, now_rfc3339, read_desired, read_release, slot_is_sealed,
    write_status,
};
use tokio::sync::{Mutex, Notify, Semaphore, watch};
use tracing::{error, info, warn};

use crate::route::{RouteKind, RouteTarget};
use crate::static_files::static_health_ok;
use crate::supervisor::{SlotManager, probe_http_health};

#[derive(Clone)]
pub struct SharedState {
    pub config: Arc<ExecutorConfig>,
    pub routing: Arc<ArcSwap<RouteTarget>>,
    pub status: Arc<Mutex<ExecutorStatus>>,
    pub connections: Arc<Semaphore>,
    pub draining: Arc<AtomicBool>,
    pub conn_count: Arc<AtomicU64>,
    pub slot_mgr: Arc<SlotManager>,
    pub requests: Arc<AtomicU64>,
    pub limiter: Arc<crate::limits::Limiter>,
    #[allow(dead_code)] // available to handlers / future access-log redaction
    pub redactor: Arc<Redactor>,
    pub process_exit: watch::Sender<bool>,
}

struct SlotMeta {
    state: SlotState,
    release_id: Option<String>,
    warm_until: Option<Instant>,
    switched_at: Option<Instant>,
    restart_at: Option<Instant>,
    evicted: bool,
}

struct BootRetry {
    attempt: u32,
    due: Instant,
    generation: u64,
}

enum Boot {
    Settled,
    NothingServing { generation: u64 },
}

const HEARTBEAT_EVERY: Duration = Duration::from_secs(1);
const BOOT_RETRY_MIN: Duration = Duration::from_secs(1);
const PROBE_LIMIT: Duration = Duration::from_secs(2);

impl SlotMeta {
    fn empty() -> Self {
        Self {
            state: SlotState::Empty,
            release_id: None,
            warm_until: None,
            switched_at: None,
            restart_at: None,
            evicted: false,
        }
    }
}

pub async fn run(state: SharedState, mut shutdown: watch::Receiver<bool>, _wake: Arc<Notify>) {
    let mut blue = SlotMeta::empty();
    let mut green = SlotMeta::empty();
    let heartbeat = tokio::spawn(heartbeat_loop(state.clone(), shutdown.clone()));
    let mut boot_retry = match boot_reconcile(&state, &mut blue, &mut green, None).await {
        Boot::Settled => None,
        Boot::NothingServing { generation } => Some(next_boot_retry(0, generation)),
    };

    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                poll_desired(&state, &mut blue, &mut green).await;
                check_warm_expiry(&state, &mut blue, &mut green).await;
                watch_crashes(&state, &mut blue, &mut green).await;
                retry_boot(&state, &mut blue, &mut green, &mut boot_retry).await;
            }
        }
    }
    heartbeat.abort();
}

async fn heartbeat_loop(state: SharedState, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(HEARTBEAT_EVERY);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => write_heartbeat(&state).await,
        }
    }
}

fn next_boot_retry(attempt: u32, generation: u64) -> BootRetry {
    BootRetry {
        attempt,
        due: Instant::now() + SlotManager::backoff_delay(attempt).max(BOOT_RETRY_MIN),
        generation,
    }
}

async fn retry_boot(
    state: &SharedState,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
    retry: &mut Option<BootRetry>,
) {
    let Some(pending) = retry.as_ref() else {
        return;
    };
    let superseded = state.routing.load_full().slot.is_some()
        || state.status.lock().await.ack_generation > pending.generation;
    if superseded {
        *retry = None;
        return;
    }
    if Instant::now() < pending.due {
        return;
    }
    let attempt = pending.attempt.saturating_add(1);
    *retry = match boot_reconcile(state, blue, green, Some(pending.generation)).await {
        Boot::Settled => None,
        Boot::NothingServing { generation } => Some(next_boot_retry(attempt, generation)),
    };
}

async fn mark_sealed_slots_stopped(state: &SharedState, blue: &mut SlotMeta, green: &mut SlotMeta) {
    for slot in [Slot::Blue, Slot::Green] {
        let slot_dir = state.config.slot_dir(slot);
        let meta = meta_mut(slot, blue, green);
        if meta.evicted || meta.state != SlotState::Empty || !slot_is_sealed(&slot_dir) {
            continue;
        }
        if let Ok(manifest) = read_release(&slot_dir.join("release.json")) {
            meta.state = SlotState::Stopped;
            meta.release_id = Some(manifest.release_id);
            set_slot_status(state, slot, meta).await;
        }
    }
}

async fn boot_reconcile(
    state: &SharedState,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
    ack_override: Option<u64>,
) -> Boot {
    let desired = match read_desired(&state.config.desired_path()) {
        Ok(d) => d,
        Err(err) => {
            mark_sealed_slots_stopped(state, blue, green).await;
            warn!(error = %err, "boot: no usable desired.json");
            return Boot::Settled;
        }
    };
    if desired.action == DesiredAction::Evict
        && let Some(slot) = desired.evict_slot
    {
        meta_mut(slot, blue, green).evicted = true;
    }
    mark_sealed_slots_stopped(state, blue, green).await;
    if ack_override.is_none()
        && matches!(
            desired.action,
            DesiredAction::RestartExecutor | DesiredAction::RestartChild
        )
    {
        ack_generation(state, desired.generation).await;
    }
    let generation = ack_override.unwrap_or(desired.generation);

    let live = desired.live_slot;
    if !meta_ref(live, blue, green).evicted
        && try_activate_slot(
            state,
            live,
            blue,
            green,
            generation,
            desired.warm_grace_s,
            false,
        )
        .await
    {
        return Boot::Settled;
    }
    let other = live.other();
    if !meta_ref(other, blue, green).evicted
        && slot_is_sealed(&state.config.slot_dir(other))
        && try_activate_slot(
            state,
            other,
            blue,
            green,
            generation,
            desired.warm_grace_s,
            false,
        )
        .await
    {
        info!("boot: fell back to sealed slot {}", other.as_str());
        return Boot::Settled;
    }
    warn!("boot: no healthy release; serving 503");
    Boot::NothingServing { generation }
}

async fn poll_desired(state: &SharedState, blue: &mut SlotMeta, green: &mut SlotMeta) {
    let path = state.config.desired_path();
    let desired = match read_desired(&path) {
        Ok(d) => d,
        Err(err) => {
            // Missing is fine; corrupt is logged.
            if path.is_file() {
                error!(error = %err, "corrupt or invalid desired.json; ignoring");
            }
            return;
        }
    };

    let ack = {
        let st = state.status.lock().await;
        st.ack_generation
    };
    if desired.generation <= ack {
        return;
    }

    match desired.action {
        DesiredAction::Noop => {
            ack_generation(state, desired.generation).await;
        }
        DesiredAction::Evict => {
            if let Some(slot) = desired.evict_slot {
                handle_evict(
                    state,
                    slot,
                    desired.live_slot,
                    blue,
                    green,
                    desired.generation,
                )
                .await;
            } else {
                ack_generation(state, desired.generation).await;
            }
        }
        DesiredAction::Activate => {
            handle_activate(state, &desired, blue, green).await;
        }
        DesiredAction::Rollback => {
            handle_rollback(state, &desired, blue, green).await;
        }
        DesiredAction::RestartChild => {
            handle_restart_child(state, desired.live_slot, blue, green, desired.generation).await;
        }
        DesiredAction::RestartExecutor => {
            ack_generation(state, desired.generation).await;
            let _ = state.process_exit.send(true);
        }
    }
}

async fn handle_evict(
    state: &SharedState,
    slot: Slot,
    declared_live: Slot,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
    generation: u64,
) {
    if slot != declared_live && state.routing.load_full().slot == Some(slot) {
        warn!(slot = slot.as_str(), "evict refused: slot is serving");
        let already_reported = state
            .status
            .lock()
            .await
            .last_result
            .as_ref()
            .is_some_and(|r| r.generation == generation && r.outcome == Outcome::Failed);
        if !already_reported {
            let reason = format!("evict refused: {} is serving", slot.as_str());
            set_last_result(state, generation, Outcome::Failed, reason, vec![]).await;
        }
        return;
    }
    state.slot_mgr.stop_slot(slot).await;
    if state.routing.load_full().slot == Some(slot) {
        state.routing.store(Arc::new(RouteTarget::empty()));
    }
    let meta = meta_mut(slot, blue, green);
    meta.state = SlotState::Stopped;
    meta.warm_until = None;
    meta.switched_at = None;
    meta.restart_at = None;
    meta.evicted = true;
    // Keep release_id so rollback from stopped can still find the release on disk.
    set_slot_status(state, slot, meta).await;
    let mut st = state.status.lock().await;
    st.ack_generation = generation;
    if st.active_slot == Some(slot) {
        st.active_slot = None;
        st.active_release_id = None;
    }
    st.updated_at = now_rfc3339();
    let _ = write_status(&state.config.status_path(), &st);
}

async fn handle_activate(
    state: &SharedState,
    desired: &Desired,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
) {
    let slot = desired.live_slot;
    meta_mut(slot, blue, green).evicted = false;
    let ok = try_activate_slot(
        state,
        slot,
        blue,
        green,
        desired.generation,
        desired.warm_grace_s,
        true,
    )
    .await;
    if !ok {
        if state.slot_mgr.is_shutting_down() {
            return;
        }
        let existing = state.status.lock().await.last_result.clone();
        let reason = existing
            .filter(|r| r.generation == desired.generation && r.outcome == Outcome::Failed)
            .map(|r| r.reason)
            .unwrap_or_else(|| format!("health gate failed for {}", slot.as_str()));
        let tail = state.slot_mgr.log_tail(slot).await;
        set_last_result(state, desired.generation, Outcome::Failed, reason, tail).await;
        let meta = meta_mut(slot, blue, green);
        meta.state = SlotState::Failed;
        set_slot_status(state, slot, meta).await;
        ack_generation(state, desired.generation).await;
    }
}

async fn try_activate_slot(
    state: &SharedState,
    slot: Slot,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
    generation: u64,
    warm_grace_s: u64,
    demote_previous: bool,
) -> bool {
    let slot_dir = state.config.slot_dir(slot);
    if !slot_is_sealed(&slot_dir) {
        warn!(slot = slot.as_str(), "activate: slot not sealed");
        return false;
    }
    let manifest = match read_release(&slot_dir.join("release.json")) {
        Ok(m) => m,
        Err(err) => {
            error!(error = %err, slot = slot.as_str(), "corrupt release.json; ignoring");
            return false;
        }
    };

    if let Err(reason) = state.slot_mgr.check_release(&manifest) {
        error!(%reason, "release refused");
        let meta = meta_mut(slot, blue, green);
        meta.state = SlotState::Failed;
        meta.release_id = Some(manifest.release_id.clone());
        set_slot_status(state, slot, meta).await;
        set_last_result(state, generation, Outcome::Failed, reason, vec![]).await;
        return false;
    }

    {
        let meta = meta_mut(slot, blue, green);
        meta.state = SlotState::Starting;
        meta.restart_at = None;
        meta.release_id = Some(manifest.release_id.clone());
        set_slot_status(state, slot, meta).await;
    }

    let app_root = state.slot_mgr.app_root(slot);
    let health_ok = match manifest.rendering {
        Rendering::Static => health_gate_static(state, &app_root, &manifest).await,
        Rendering::Ssr => {
            if let Err(err) = state.slot_mgr.start_ssr(slot, &manifest).await {
                error!(error = %err, "failed to start SSR child");
                park_stopped(state, slot, blue, green).await;
                return false;
            }
            health_gate_ssr(state, slot, &manifest).await
        }
    };

    if !health_ok {
        state.slot_mgr.stop_slot(slot).await;
        park_stopped(state, slot, blue, green).await;
        return false;
    }

    let previous = state.routing.load_full().slot;
    let new_route = match manifest.rendering {
        Rendering::Static => RouteTarget::static_from(&manifest, app_root),
        Rendering::Ssr => {
            let port = match slot.loopback_port(state.config.port_base) {
                Ok(p) => p,
                Err(_) => {
                    state.slot_mgr.stop_slot(slot).await;
                    park_stopped(state, slot, blue, green).await;
                    return false;
                }
            };
            RouteTarget::proxy_from(&manifest, port)
        }
    };
    state.routing.store(Arc::new(new_route));

    if demote_previous {
        if let Some(prev) = previous {
            if prev != slot {
                let grace = Duration::from_secs(warm_grace_s.max(1));
                let meta = meta_mut(prev, blue, green);
                meta.state = SlotState::Warm;
                meta.warm_until = Some(Instant::now() + grace);
                set_slot_status(state, prev, meta).await;
            }
        }
    }

    {
        let meta = meta_mut(slot, blue, green);
        meta.state = SlotState::Live;
        meta.warm_until = None;
        meta.switched_at = Some(Instant::now());
        meta.release_id = Some(manifest.release_id.clone());
        set_slot_status(state, slot, meta).await;
    }

    let tail = state.slot_mgr.log_tail(slot).await;
    {
        let mut st = state.status.lock().await;
        st.ack_generation = st.ack_generation.max(generation);
        st.active_slot = Some(slot);
        st.active_release_id = Some(manifest.release_id.clone());
        st.last_result = Some(LastResult {
            generation,
            outcome: Outcome::Live,
            reason: "activated".into(),
            log_tail: tail,
        });
        st.updated_at = now_rfc3339();
        let _ = write_status(&state.config.status_path(), &st);
    }
    true
}

async fn park_stopped(state: &SharedState, slot: Slot, blue: &mut SlotMeta, green: &mut SlotMeta) {
    let meta = meta_mut(slot, blue, green);
    meta.state = SlotState::Stopped;
    meta.warm_until = None;
    meta.restart_at = None;
    set_slot_status(state, slot, meta).await;
}

async fn health_gate_static(
    state: &SharedState,
    app_root: &std::path::Path,
    manifest: &ReleaseManifest,
) -> bool {
    let timeout = Duration::from_secs(manifest.health.timeout_s.max(1));
    let need = manifest.health.consecutive.max(1);
    let start = Instant::now();
    let mut ok = 0u32;
    while start.elapsed() < timeout {
        if state.slot_mgr.is_shutting_down() {
            return false;
        }
        if static_health_ok(app_root, &manifest.health.path) {
            ok += 1;
            if ok >= need {
                return true;
            }
        } else {
            ok = 0;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

async fn health_gate_ssr(state: &SharedState, slot: Slot, manifest: &ReleaseManifest) -> bool {
    let port = match slot.loopback_port(state.config.port_base) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let timeout = Duration::from_secs(manifest.health.timeout_s.max(1));
    let need = manifest.health.consecutive.max(1);
    let start = Instant::now();
    let mut ok = 0u32;
    while start.elapsed() < timeout {
        if state.slot_mgr.is_shutting_down() || state.slot_mgr.poll_exit(slot).await.is_some() {
            return false;
        }
        let left = timeout.saturating_sub(start.elapsed());
        let limit = left.min(PROBE_LIMIT);
        if probe_http_health(port, &manifest.health.path, manifest.health.expect, limit).await {
            ok += 1;
            if ok >= need {
                return true;
            }
        } else {
            ok = 0;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

async fn handle_rollback(
    state: &SharedState,
    desired: &Desired,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
) {
    let target = desired.live_slot;
    meta_mut(target, blue, green).evicted = false;
    let mut meta_state = meta_ref(target, blue, green).state;
    if meta_state == SlotState::Warm && !warm_runnable(state, target).await {
        meta_state = SlotState::Stopped;
    }
    match meta_state {
        SlotState::Warm => {
            if let Some(manifest) = load_manifest(state, target) {
                let previous = state.routing.load_full().slot;
                let route = build_route(state, target, &manifest);
                state.routing.store(Arc::new(route));
                {
                    let meta = meta_mut(target, blue, green);
                    meta.state = SlotState::Live;
                    meta.warm_until = None;
                    meta.switched_at = Some(Instant::now());
                    set_slot_status(state, target, meta).await;
                }
                if let Some(prev) = previous {
                    if prev != target {
                        let grace = Duration::from_secs(desired.warm_grace_s.max(1));
                        let meta = meta_mut(prev, blue, green);
                        meta.state = SlotState::Warm;
                        meta.warm_until = Some(Instant::now() + grace);
                        set_slot_status(state, prev, meta).await;
                    }
                }
                {
                    let mut st = state.status.lock().await;
                    st.ack_generation = desired.generation;
                    st.active_slot = Some(target);
                    st.active_release_id = Some(manifest.release_id);
                    st.last_result = Some(LastResult {
                        generation: desired.generation,
                        outcome: Outcome::Live,
                        reason: "rollback warm swap".into(),
                        log_tail: vec![],
                    });
                    let _ = write_status(&state.config.status_path(), &st);
                }
            } else {
                refuse_rollback(state, desired.generation, "warm slot has no release").await;
            }
        }
        SlotState::Stopped | SlotState::Starting => {
            let ok = try_activate_slot(
                state,
                target,
                blue,
                green,
                desired.generation,
                desired.warm_grace_s,
                true,
            )
            .await;
            if !ok && !state.slot_mgr.is_shutting_down() {
                refuse_rollback(state, desired.generation, "rollback health gate failed").await;
            }
        }
        SlotState::Empty | SlotState::Failed => {
            refuse_rollback(
                state,
                desired.generation,
                &format!("rollback refused: previous slot is {:?}", meta_state),
            )
            .await;
        }
        SlotState::Live => {
            ack_generation(state, desired.generation).await;
        }
    }
}

async fn refuse_rollback(state: &SharedState, generation: u64, reason: &str) {
    set_last_result(
        state,
        generation,
        Outcome::Failed,
        reason.to_string(),
        vec![],
    )
    .await;
    ack_generation(state, generation).await;
}

async fn handle_restart_child(
    state: &SharedState,
    slot: Slot,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
    generation: u64,
) {
    if state.routing.load_full().slot != Some(slot) {
        refuse_restart(state, generation, slot).await;
        return;
    }
    meta_mut(slot, blue, green).restart_at = None;
    if let Some(manifest) = load_manifest(state, slot) {
        if manifest.rendering == Rendering::Ssr {
            if let Err(err) = state.slot_mgr.start_ssr(slot, &manifest).await {
                if state.slot_mgr.is_shutting_down() {
                    return;
                }
                let reason = format!("restart failed: {err}");
                state.slot_mgr.record_crash(slot, reason.clone()).await;
                set_last_result(state, generation, Outcome::Failed, reason.clone(), vec![]).await;
                handle_crash(state, slot, reason, blue, green).await;
                ack_generation(state, generation).await;
                return;
            }
            let _ = health_gate_ssr(state, slot, &manifest).await;
        }
    }
    if !state.slot_mgr.is_shutting_down() {
        ack_generation(state, generation).await;
    }
}

async fn refuse_restart(state: &SharedState, generation: u64, slot: Slot) {
    set_last_result(
        state,
        generation,
        Outcome::Failed,
        format!("restart refused: {} is not the live slot", slot.as_str()),
        vec![],
    )
    .await;
    ack_generation(state, generation).await;
}

async fn check_warm_expiry(state: &SharedState, blue: &mut SlotMeta, green: &mut SlotMeta) {
    for slot in [Slot::Blue, Slot::Green] {
        let expired = {
            let meta = meta_ref(slot, blue, green);
            meta.state == SlotState::Warm
                && meta.warm_until.is_some_and(|until| Instant::now() >= until)
        };
        if expired {
            state.slot_mgr.stop_slot(slot).await;
            let meta = meta_mut(slot, blue, green);
            meta.state = SlotState::Stopped;
            meta.warm_until = None;
            set_slot_status(state, slot, meta).await;
        }
    }
}

async fn watch_crashes(state: &SharedState, blue: &mut SlotMeta, green: &mut SlotMeta) {
    reap_dead_warm_slots(state, blue, green).await;
    let live = state.routing.load_full().slot;
    let Some(live) = live else {
        return;
    };
    if let Some(at) = meta_ref(live, blue, green).restart_at {
        if Instant::now() >= at {
            meta_mut(live, blue, green).restart_at = None;
            if let Some(manifest) = load_manifest(state, live) {
                if manifest.rendering == Rendering::Ssr {
                    if let Err(err) = state.slot_mgr.start_ssr(live, &manifest).await {
                        let reason = format!("restart failed: {err}");
                        state.slot_mgr.record_crash(live, reason.clone()).await;
                        handle_crash(state, live, reason, blue, green).await;
                    }
                }
            }
        }
        return;
    }
    let Some(reason) = state.slot_mgr.poll_exit(live).await else {
        return;
    };
    handle_crash(state, live, reason, blue, green).await;
}

async fn warm_runnable(state: &SharedState, slot: Slot) -> bool {
    match load_manifest(state, slot) {
        Some(manifest) if manifest.rendering == Rendering::Ssr => {
            state.slot_mgr.pid(slot).await.is_some()
        }
        _ => true,
    }
}

async fn fallback_to_previous(
    state: &SharedState,
    live: Slot,
    generation: u64,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
) -> bool {
    let previous = live.other();
    let prev = meta_ref(previous, blue, green);
    if prev.evicted || !matches!(prev.state, SlotState::Warm | SlotState::Stopped) {
        return false;
    }
    let warm = prev.state == SlotState::Warm;
    let ok = if warm && warm_runnable(state, previous).await {
        match load_manifest(state, previous) {
            Some(manifest) => {
                let route = build_route(state, previous, &manifest);
                state.routing.store(Arc::new(route));
                let meta = meta_mut(previous, blue, green);
                meta.state = SlotState::Live;
                meta.warm_until = None;
                meta.switched_at = Some(Instant::now());
                set_slot_status(state, previous, meta).await;
                let mut st = state.status.lock().await;
                st.active_slot = Some(previous);
                st.active_release_id = Some(manifest.release_id);
                true
            }
            None => false,
        }
    } else {
        try_activate_slot(
            state,
            previous,
            blue,
            green,
            generation,
            state.config.warm_grace.as_secs(),
            true,
        )
        .await
    };
    if ok {
        let meta = meta_mut(live, blue, green);
        meta.state = SlotState::Failed;
        meta.warm_until = None;
        meta.restart_at = None;
        set_slot_status(state, live, meta).await;
    }
    ok
}

async fn handle_crash(
    state: &SharedState,
    live: Slot,
    reason: String,
    blue: &mut SlotMeta,
    green: &mut SlotMeta,
) {
    let switched_at = meta_ref(live, blue, green).switched_at;
    let in_watch = switched_at.is_some_and(|t| t.elapsed() < state.config.watch);
    let generation = state.status.lock().await.ack_generation;
    let tail = state.slot_mgr.log_tail(live).await;
    let crashes = state.slot_mgr.crash_count_in_window(live).await;

    let mut fallback_tried = false;
    if in_watch {
        info!(reason = %reason, "crash within watch window; falling back");
        fallback_tried = true;
        if fallback_to_previous(state, live, generation, blue, green).await {
            set_last_result(
                state,
                generation,
                Outcome::Fallback,
                format!("fallback after crash: {reason}"),
                tail,
            )
            .await;
            return;
        }
    }
    if crashes >= state.config.crash_limit {
        if !fallback_tried && fallback_to_previous(state, live, generation, blue, green).await {
            set_last_result(
                state,
                generation,
                Outcome::Fallback,
                format!("crash limit reached: {reason}"),
                tail,
            )
            .await;
        } else {
            let meta = meta_mut(live, blue, green);
            meta.state = SlotState::Failed;
            meta.warm_until = None;
            meta.restart_at = None;
            set_slot_status(state, live, meta).await;
            state.routing.store(Arc::new(RouteTarget::empty()));
            {
                let mut st = state.status.lock().await;
                st.active_slot = None;
                st.active_release_id = None;
            }
            set_last_result(
                state,
                generation,
                Outcome::Failed,
                format!("crash limit reached: {reason}"),
                tail,
            )
            .await;
        }
        return;
    }

    let delay = SlotManager::backoff_delay(crashes);
    meta_mut(live, blue, green).restart_at = Some(Instant::now() + delay);
}

async fn reap_dead_warm_slots(state: &SharedState, blue: &mut SlotMeta, green: &mut SlotMeta) {
    for slot in [Slot::Blue, Slot::Green] {
        if meta_ref(slot, blue, green).state != SlotState::Warm {
            continue;
        }
        if state.slot_mgr.poll_exit(slot).await.is_some() {
            let meta = meta_mut(slot, blue, green);
            meta.state = SlotState::Stopped;
            meta.warm_until = None;
            set_slot_status(state, slot, meta).await;
        }
    }
}

async fn write_heartbeat(state: &SharedState) {
    let active = state.status.lock().await.active_slot;
    let tail = match active {
        Some(slot) => state.slot_mgr.log_tail(slot).await,
        None => Vec::new(),
    };
    let mut st = state.status.lock().await;
    st.updated_at = now_rfc3339();
    st.requests = state.requests.load(Ordering::Relaxed);
    st.limited_requests = state.limiter.limited_requests();
    st.bans = state.limiter.bans();
    st.dropped_connections = state.limiter.dropped_connections();
    if let Some(result) = st.last_result.as_mut()
        && result.outcome == Outcome::Live
        && !tail.is_empty()
    {
        result.log_tail = tail;
    }
    let _ = write_status(&state.config.status_path(), &st);
}

async fn set_slot_status(state: &SharedState, slot: Slot, meta: &SlotMeta) {
    let pid = state.slot_mgr.pid(slot).await;
    let mut st = state.status.lock().await;
    let s = st.slot_mut(slot);
    s.state = meta.state;
    s.release_id = meta.release_id.clone();
    s.since = now_rfc3339();
    s.pid = pid;
    s.warm_until = None;
    if let Some(until) = meta.warm_until {
        let left = until.saturating_duration_since(Instant::now());
        let when = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(i64::try_from(left.as_secs()).unwrap_or(0));
        s.warm_until = when
            .format(&time::format_description::well_known::Rfc3339)
            .ok();
    }
    st.updated_at = now_rfc3339();
    let _ = write_status(&state.config.status_path(), &st);
}

async fn ack_generation(state: &SharedState, generation: u64) {
    let mut st = state.status.lock().await;
    st.ack_generation = generation;
    st.updated_at = now_rfc3339();
    let _ = write_status(&state.config.status_path(), &st);
}

async fn set_last_result(
    state: &SharedState,
    generation: u64,
    outcome: Outcome,
    reason: String,
    log_tail: Vec<String>,
) {
    let mut st = state.status.lock().await;
    st.last_result = Some(LastResult {
        generation,
        outcome,
        reason: cite_core::escape_control(&reason, false),
        log_tail: log_tail
            .iter()
            .map(|line| cite_core::escape_control(line, true))
            .collect(),
    });
    st.updated_at = now_rfc3339();
    let _ = write_status(&state.config.status_path(), &st);
}

fn meta_mut<'a>(slot: Slot, blue: &'a mut SlotMeta, green: &'a mut SlotMeta) -> &'a mut SlotMeta {
    match slot {
        Slot::Blue => blue,
        Slot::Green => green,
    }
}

fn meta_ref<'a>(slot: Slot, blue: &'a SlotMeta, green: &'a SlotMeta) -> &'a SlotMeta {
    match slot {
        Slot::Blue => blue,
        Slot::Green => green,
    }
}

fn load_manifest(state: &SharedState, slot: Slot) -> Option<ReleaseManifest> {
    let path = state.config.slot_dir(slot).join("release.json");
    match read_release(&path) {
        Ok(m) => Some(m),
        Err(err) => {
            if path.is_file() {
                error!(error = %err, "corrupt release.json; ignoring");
            }
            None
        }
    }
}

fn build_route(state: &SharedState, slot: Slot, manifest: &ReleaseManifest) -> RouteTarget {
    match manifest.rendering {
        Rendering::Static => RouteTarget::static_from(manifest, state.slot_mgr.app_root(slot)),
        Rendering::Ssr => {
            let port = slot.loopback_port(state.config.port_base).unwrap_or(3001);
            RouteTarget::proxy_from(manifest, port)
        }
    }
}

#[allow(dead_code)]
fn _route_kind(target: &RouteTarget) -> &RouteKind {
    &target.kind
}

#[allow(dead_code)]
fn _path_buf() -> PathBuf {
    PathBuf::new()
}
