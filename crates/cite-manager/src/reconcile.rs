use cite_core::ManagerConfig;
use cite_core::schema::{
    Desired, DesiredAction, ManagerState, Slot, now_rfc3339, read_desired, read_release,
    read_state, read_status, write_desired, write_state,
};
use tracing::{info, warn};

use crate::Result;

/// Returns true when the executor's active slot was adopted over the one desired.json named.
pub fn reconcile(cfg: &ManagerConfig) -> Result<bool> {
    let status = match read_status(&cfg.status_path()) {
        Ok(s) => s,
        Err(err) => {
            warn!(error = %err, "no executor status yet");
            return Ok(false);
        }
    };
    let desired = match read_desired(&cfg.desired_path()) {
        Ok(d) => d,
        Err(_) => {
            let live = status.active_slot.unwrap_or(Slot::Blue);
            let seed = Desired::noop(0, live, cfg.warm_grace.as_secs());
            write_desired(&cfg.desired_path(), &seed)?;
            return Ok(false);
        }
    };

    if status.ack_generation >= desired.generation
        && let Some(active) = status.active_slot
        && active != desired.live_slot
    {
        info!(
            from = desired.live_slot.as_str(),
            to = active.as_str(),
            "adopting executor active_slot (automatic fallback)"
        );
        let adopted = Desired {
            v: cite_core::SCHEMA_VERSION,
            generation: desired.generation.saturating_add(1),
            live_slot: active,
            action: DesiredAction::Noop,
            evict_slot: None,
            warm_grace_s: cfg.warm_grace.as_secs(),
            restart_nonce: String::new(),
            written_at: now_rfc3339(),
        };
        write_desired(&cfg.desired_path(), &adopted)?;

        let mut state = read_state(&cfg.state_path()).unwrap_or_default();
        state.generation = adopted.generation;
        if let Some(result) = &status.last_result {
            state.last_failed_reason = Some(result.reason.clone());
        }
        record_fallback(cfg, &mut state, desired.live_slot, active);
        write_state(&cfg.state_path(), &state)?;
        return Ok(true);
    }
    Ok(false)
}

fn slot_sha(cfg: &ManagerConfig, slot: Slot) -> Option<String> {
    read_release(&cfg.slot_dir(slot).join("release.json"))
        .ok()
        .map(|m| m.sha)
}

/// The slot the manager asked for did not stay live, so its sha counts as failed rather than deployed.
fn record_fallback(cfg: &ManagerConfig, state: &mut ManagerState, failed: Slot, active: Slot) {
    let Some(sha) = slot_sha(cfg, failed) else {
        return;
    };
    if state.last_deployed_sha.as_deref() == Some(sha.as_str()) {
        state.last_deployed_sha = slot_sha(cfg, active);
    }
    state.last_failed_sha = Some(sha);
}

pub fn load_or_init_state(cfg: &ManagerConfig) -> Result<ManagerState> {
    match read_state(&cfg.state_path()) {
        Ok(mut s) => {
            let floor = crate::promote::generation_floor(cfg, s.generation);
            if floor > s.generation {
                s.generation = floor;
                write_state(&cfg.state_path(), &s)?;
            }
            Ok(s)
        }
        Err(_) => {
            // Reusing a generation the executor already acked would make the next activate a no-op.
            let mut state = ManagerState::default();
            if let Ok(status) = read_status(&cfg.status_path()) {
                state.generation = state.generation.max(status.ack_generation);
            }
            if let Ok(desired) = read_desired(&cfg.desired_path()) {
                state.generation = state.generation.max(desired.generation);
            }
            write_state(&cfg.state_path(), &state)?;
            Ok(state)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{load_or_init_state, reconcile};
    use cite_core::ManagerConfig;
    use cite_core::schema::{
        Desired, ExecutorStatus, Health, HealthExpect, ManagerState, ReleaseManifest, Rendering,
        RuntimeKind, Slot, read_desired, read_state, write_desired, write_release, write_state,
        write_status,
    };
    use std::collections::HashMap;

    fn release(slot: Slot, sha: &str) -> ReleaseManifest {
        ReleaseManifest {
            v: cite_core::SCHEMA_VERSION,
            release_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            slot,
            sha: sha.into(),
            branch: "main".into(),
            commit_message: "m".into(),
            commit_author: "dev".into(),
            built_at: "2026-01-01T00:00:00Z".into(),
            rendering: Rendering::Static,
            runtime: RuntimeKind::Static,
            node_major: "22".into(),
            start_argv: Vec::new(),
            port_env: "PORT".into(),
            health: Health {
                path: "/".into(),
                expect: HealthExpect::Non2xxOk,
                timeout_s: 5,
                consecutive: 1,
            },
            spa_fallback: None,
            root: "app".into(),
            bytes: 1,
            file_count: 1,
            tree_sha256: "b".repeat(64),
        }
    }

    #[test]
    fn runtime_fallback_is_adopted_and_the_fallen_back_sha_is_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        for sub in [
            "releases/blue",
            "releases/green",
            "status",
            "state",
            "control",
        ] {
            std::fs::create_dir_all(data.join(sub)).unwrap();
        }
        let good = "a".repeat(40);
        let bad = "c".repeat(40);
        write_release(
            &data.join("releases/blue/release.json"),
            &release(Slot::Blue, &good),
        )
        .unwrap();
        write_release(
            &data.join("releases/green/release.json"),
            &release(Slot::Green, &bad),
        )
        .unwrap();

        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_DATA_DIR".into(), data.display().to_string());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();

        let desired = Desired::noop(4, Slot::Green, 30);
        write_desired(&cfg.desired_path(), &desired).unwrap();
        let mut status = ExecutorStatus::initial("test");
        status.ack_generation = 4;
        status.active_slot = Some(Slot::Blue);
        write_status(&cfg.status_path(), &status).unwrap();
        let state = ManagerState {
            last_deployed_sha: Some(bad.clone()),
            generation: 4,
            ..ManagerState::default()
        };
        write_state(&cfg.state_path(), &state).unwrap();

        assert!(reconcile(&cfg).unwrap());
        assert_eq!(
            read_desired(&cfg.desired_path()).unwrap().live_slot,
            Slot::Blue
        );
        let after = read_state(&cfg.state_path()).unwrap();
        assert_eq!(after.last_failed_sha.as_deref(), Some(bad.as_str()));
        assert_eq!(after.last_deployed_sha.as_deref(), Some(good.as_str()));
        assert!(!reconcile(&cfg).unwrap(), "adoption is idempotent");
    }

    #[test]
    fn corrupt_state_continues_past_the_executor_ack() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        std::fs::create_dir_all(data.join("status")).unwrap();
        std::fs::create_dir_all(data.join("state")).unwrap();
        let mut status = ExecutorStatus::initial("test");
        status.ack_generation = 7;
        write_status(&data.join("status/executor.json"), &status).unwrap();
        std::fs::write(data.join("state/state.json"), b"{not-json").unwrap();

        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_DATA_DIR".into(), data.display().to_string());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let state = load_or_init_state(&cfg).unwrap();
        assert!(
            state.generation >= 7,
            "recovered generation {} reused an acknowledged value",
            state.generation
        );
    }

    #[test]
    fn readable_state_is_raised_to_the_desired_and_acked_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        for sub in ["status", "state", "control"] {
            std::fs::create_dir_all(data.join(sub)).unwrap();
        }
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_DATA_DIR".into(), data.display().to_string());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        write_desired(&cfg.desired_path(), &Desired::noop(12, Slot::Blue, 30)).unwrap();
        let mut status = ExecutorStatus::initial("test");
        status.ack_generation = 11;
        write_status(&cfg.status_path(), &status).unwrap();
        let state = ManagerState {
            generation: 5,
            ..ManagerState::default()
        };
        write_state(&cfg.state_path(), &state).unwrap();

        assert_eq!(load_or_init_state(&cfg).unwrap().generation, 12);
        assert_eq!(read_state(&cfg.state_path()).unwrap().generation, 12);
    }
}
