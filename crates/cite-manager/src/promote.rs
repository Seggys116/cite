use std::path::{Path, PathBuf};
use std::time::Duration;

use cite_core::schema::{
    Desired, DesiredAction, Outcome, Slot, SlotState, now_rfc3339, read_desired, read_status,
    write_desired,
};
use cite_core::{
    ExtractLimits, ManagerConfig, ensure_dir, extract_archive, hash_tree, layout_violations,
    remove_dir_contents, slot_is_sealed,
};
use tracing::{error, info, warn};

use crate::build::{BuiltRelease, release_manifest};
use crate::{ManagerError, Result};

const EVICT_TIMEOUT: Duration = Duration::from_secs(30);
const HEARTBEAT_STALE: Duration = Duration::from_secs(6);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromoteOutcome {
    Live,
    FailedHealth,
}

pub struct PromoteContext<'a> {
    pub cfg: &'a ManagerConfig,
    pub built: &'a BuiltRelease,
    pub generation: u64,
}

/// The highest generation already written or acknowledged, so a stale recorded value can never produce an action the executor ignores.
pub fn generation_floor(cfg: &ManagerConfig, recorded: u64) -> u64 {
    let written = read_desired(&cfg.desired_path()).map_or(0, |d| d.generation);
    let acked = read_status(&cfg.status_path()).map_or(0, |s| s.ack_generation);
    recorded.max(written).max(acked)
}

pub fn free_slot(cfg: &ManagerConfig) -> Result<Slot> {
    let status = read_status(&cfg.status_path()).ok();
    let live = status
        .as_ref()
        .and_then(|s| s.active_slot)
        .or_else(|| read_desired(&cfg.desired_path()).ok().map(|d| d.live_slot))
        .unwrap_or(Slot::Blue);

    let candidate = live.other();
    Ok(candidate)
}

pub fn executor_responsive(cfg: &ManagerConfig) -> Result<bool> {
    let status = match read_status(&cfg.status_path()) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let Ok(updated) = time::OffsetDateTime::parse(
        &status.updated_at,
        &time::format_description::well_known::Rfc3339,
    ) else {
        return Ok(false);
    };
    let age = time::OffsetDateTime::now_utc() - updated;
    Ok(age < time::Duration::seconds(HEARTBEAT_STALE.as_secs() as i64))
}

/// The caller must have already validated the build; a failed build never reaches promote.
pub async fn promote(ctx: PromoteContext<'_>) -> Result<PromoteOutcome> {
    let cfg = ctx.cfg;
    let built = ctx.built;

    if !executor_responsive(cfg)? {
        return Err(ManagerError::new("executor_unresponsive"));
    }

    let slot = free_slot(cfg)?;
    let warm_grace_s = cfg.warm_grace.as_secs();

    // Evict first if the free slot is sealed or holds content the executor may still use.
    let slot_dir = cfg.slot_dir(slot);
    ensure_dir(&slot_dir, 0o755)?;
    let needs_evict =
        slot_is_sealed(&slot_dir) || slot_dir.join("app").exists() || status_slot_busy(cfg, slot);

    let mut generation = generation_floor(cfg, ctx.generation);
    if needs_evict {
        generation = generation.saturating_add(1);
        let live = read_desired(&cfg.desired_path())
            .map(|d| d.live_slot)
            .unwrap_or(slot.other());
        let desired = Desired {
            v: cite_core::SCHEMA_VERSION,
            generation,
            live_slot: live,
            action: DesiredAction::Evict,
            evict_slot: Some(slot),
            warm_grace_s,
            restart_nonce: String::new(),
            written_at: now_rfc3339(),
        };
        write_desired(&cfg.desired_path(), &desired)?;
        wait_evict_ack(cfg, generation, slot).await?;
    }

    remove_dir_contents(&slot_dir)?;
    let app = slot_dir.join("app");
    ensure_dir(&app, 0o755)?;
    let tar_bytes = std::fs::read(&built.tar_path)?;
    let limits = ExtractLimits {
        max_compressed_bytes: cfg.max_release_bytes.saturating_mul(2),
        max_extracted_bytes: cfg.max_release_bytes,
        max_entries: cfg.max_entries,
        max_file_bytes: cfg.max_release_bytes,
    };
    if let Err(err) = extract_archive(std::io::Cursor::new(tar_bytes), &app, &limits, 0) {
        let _ = remove_dir_contents(&slot_dir);
        return Err(err.into());
    }

    let hashed = match hash_tree(&app) {
        Ok(h) => h,
        Err(err) => {
            let _ = remove_dir_contents(&slot_dir);
            return Err(err.into());
        }
    };
    if hashed.tree_sha256 != built.tree_sha256 {
        let _ = remove_dir_contents(&slot_dir);
        return Err(ManagerError::new(
            "tree_sha256 mismatch after extract; slot left unsealed",
        ));
    }

    let mut manifest = release_manifest(built, slot, &cfg.branch);
    manifest.bytes = hashed.bytes;
    manifest.file_count = hashed.file_count;
    manifest.tree_sha256 = hashed.tree_sha256;
    // Seal last so a partial extract never looks like a complete release.
    cite_core::write_release(&slot_dir.join("release.json"), &manifest)?;

    // Test seam: a kill here lands after sealing but before desired.json changes.
    hold_before_activate().await;

    generation = generation.saturating_add(1);
    let desired = Desired {
        v: cite_core::SCHEMA_VERSION,
        generation,
        live_slot: slot,
        action: DesiredAction::Activate,
        evict_slot: None,
        warm_grace_s,
        restart_nonce: String::new(),
        written_at: now_rfc3339(),
    };
    write_desired(&cfg.desired_path(), &desired)?;

    let outcome = wait_activate_outcome(cfg, generation, built.health.timeout_s).await?;
    match outcome {
        Outcome::Live => info!(slot = slot.as_str(), sha = %built.sha, "promote live"),
        Outcome::Failed => {
            warn!(slot = slot.as_str(), sha = %built.sha, "promote failed health gate");
        }
        Outcome::Fallback => {
            warn!(
                slot = slot.as_str(),
                sha = %built.sha,
                "executor fell back to the previous release; treating deploy as failed"
            );
        }
    }
    Ok(promote_outcome(outcome))
}

/// A fallback means the new release never went live, so it is a failed deploy; the executor's status still names the slot actually serving.
fn promote_outcome(outcome: Outcome) -> PromoteOutcome {
    match outcome {
        Outcome::Live => PromoteOutcome::Live,
        Outcome::Failed | Outcome::Fallback => PromoteOutcome::FailedHealth,
    }
}

async fn hold_before_activate() {
    let Ok(raw) = std::env::var("CITE_FAULT_HOLD_BEFORE_ACTIVATE_MS") else {
        return;
    };
    let Ok(ms) = raw.parse::<u64>() else {
        return;
    };
    if ms > 0 {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

fn status_slot_busy(cfg: &ManagerConfig, slot: Slot) -> bool {
    let Ok(status) = read_status(&cfg.status_path()) else {
        return false;
    };
    !matches!(
        status.slot(slot).state,
        SlotState::Empty | SlotState::Stopped
    )
}

async fn wait_evict_ack(cfg: &ManagerConfig, generation: u64, slot: Slot) -> Result<()> {
    let deadline = tokio::time::Instant::now() + EVICT_TIMEOUT;
    loop {
        if !executor_responsive(cfg)? {
            return Err(ManagerError::new("executor_unresponsive during evict"));
        }
        if let Ok(status) = read_status(&cfg.status_path())
            && status.ack_generation >= generation
            && matches!(
                status.slot(slot).state,
                SlotState::Stopped | SlotState::Empty
            )
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ManagerError::new("evict ack timeout; nothing deleted"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_activate_outcome(
    cfg: &ManagerConfig,
    generation: u64,
    health_timeout_s: u64,
) -> Result<Outcome> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(health_timeout_s.saturating_add(30));
    loop {
        if let Ok(status) = read_status(&cfg.status_path())
            && let Some(result) = &status.last_result
            && result.generation == generation
        {
            return Ok(result.outcome);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ManagerError::new("activate outcome timeout"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub fn write_action(
    cfg: &ManagerConfig,
    action: DesiredAction,
    live_slot: Slot,
    evict_slot: Option<Slot>,
    generation: u64,
) -> Result<u64> {
    let generation = generation_floor(cfg, generation).saturating_add(1);
    let desired = Desired {
        v: cite_core::SCHEMA_VERSION,
        generation,
        live_slot,
        action,
        evict_slot,
        warm_grace_s: cfg.warm_grace.as_secs(),
        restart_nonce: if matches!(
            action,
            DesiredAction::RestartChild | DesiredAction::RestartExecutor
        ) {
            cite_core::new_id()
        } else {
            String::new()
        },
        written_at: now_rfc3339(),
    };
    write_desired(&cfg.desired_path(), &desired)?;
    Ok(generation)
}

pub fn ensure_slot_dirs(cfg: &ManagerConfig) -> Result<()> {
    ensure_dir(&cfg.releases_dir, 0o755)?;
    ensure_dir(&cfg.slot_dir(Slot::Blue), 0o755)?;
    ensure_dir(&cfg.slot_dir(Slot::Green), 0o755)?;
    // Never create a third slot directory.
    if let Ok(entries) = std::fs::read_dir(&cfg.releases_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "blue" && name != "green" {
                warn!(%name, "unexpected path under releases/; leaving in place for layout check");
            }
        }
    }
    if let Some(data_root) = data_root_of(cfg) {
        let scratch = scratch_names(&data_root, &[&cfg.work_dir, &cfg.cache_dir]);
        sweep_layout_strays(&data_root, &scratch)?;
    } else {
        warn!("releases/control/status/state do not share one data root; skipping layout sweep");
    }
    Ok(())
}

/// The data root is only trusted when the four managed directories are its direct children under their canonical names.
fn data_root_of(cfg: &ManagerConfig) -> Option<PathBuf> {
    let expected = [
        (&cfg.releases_dir, "releases"),
        (&cfg.control_dir, "control"),
        (&cfg.status_dir, "status"),
        (&cfg.state_dir, "state"),
    ];
    let root = cfg.releases_dir.parent()?;
    let shared = expected.iter().all(|(dir, name)| {
        dir.parent() == Some(root) && dir.file_name().is_some_and(|n| n == *name)
    });
    shared.then(|| root.to_path_buf())
}

/// Top-level names that hold scratch volumes (work, cache) mounted inside the data root.
fn scratch_names(data_root: &Path, dirs: &[&Path]) -> Vec<String> {
    dirs.iter()
        .filter_map(|dir| dir.strip_prefix(data_root).ok())
        .filter_map(|rel| rel.components().next())
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect()
}

/// Logs every layout violation and removes only stray plain files and symlinks outside the managed paths.
pub fn sweep_layout_strays(data_root: &Path, scratch: &[String]) -> Result<Vec<String>> {
    for dir in [data_root.to_path_buf(), data_root.join("releases")] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let managed = if dir == data_root {
                matches!(name.as_str(), "releases" | "control" | "status" | "state")
                    || scratch.contains(&name)
            } else {
                matches!(name.as_str(), "blue" | "green")
            };
            if managed {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {
                    warn!(path = %entry.path().display(), "removed stray file from the data layout")
                }
                Err(err) => {
                    warn!(path = %entry.path().display(), %err, "could not remove stray file from the data layout");
                }
            }
        }
    }
    let violations: Vec<String> = layout_violations(data_root)?
        .into_iter()
        .filter(|v| {
            !scratch
                .iter()
                .any(|name| *v == format!("unexpected top-level path {name}"))
        })
        .collect();
    for violation in &violations {
        error!(violation = %violation, "data layout violation; needs operator attention");
    }
    Ok(violations)
}

pub fn delete_unsealed_slots(cfg: &ManagerConfig) -> Result<()> {
    for slot in [Slot::Blue, Slot::Green] {
        let dir = cfg.slot_dir(slot);
        if dir.is_dir() && !slot_is_sealed(&dir) {
            info!(slot = slot.as_str(), "deleting unsealed slot at startup");
            remove_dir_contents(&dir)?;
        }
    }
    Ok(())
}

pub fn any_sealed_release(cfg: &ManagerConfig) -> bool {
    slot_is_sealed(&cfg.slot_dir(Slot::Blue)) || slot_is_sealed(&cfg.slot_dir(Slot::Green))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use cite_core::schema::Rendering;
    use cite_core::{
        ExecutorStatus, Health, HealthExpect, ManagerConfig, PackLimits, RuntimeKind, pack_dir,
        write_status,
    };

    use super::*;

    fn cfg_in(root: &std::path::Path) -> ManagerConfig {
        let data = root.join("cite_data");
        for sub in [
            "releases/blue",
            "releases/green",
            "control",
            "status",
            "state",
        ] {
            std::fs::create_dir_all(data.join(sub)).unwrap();
        }
        let token = root.join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        std::fs::set_permissions(&token, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let work = root.join("work");
        let cache = root.join("cache");
        let socket = root.join("manager.sock");
        let pairs = [
            ("CITE_REPO", "owner/name"),
            ("CITE_DATA_DIR", data.to_str().unwrap()),
            ("CITE_WORK_DIR", work.to_str().unwrap()),
            ("CITE_CACHE_DIR", cache.to_str().unwrap()),
            ("CITE_SOCKET", socket.to_str().unwrap()),
            ("CITE_GITHUB_TOKEN_FILE", token.to_str().unwrap()),
            ("CITE_DEV_SAME_USER", "true"),
            ("CITE_MIN_FREE_BYTES", "1"),
        ];
        let env = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>();
        ManagerConfig::load_from(&env, None).unwrap()
    }

    #[tokio::test]
    async fn tree_hash_mismatch_leaves_the_slot_unsealed() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        write_status(&cfg.status_path(), &ExecutorStatus::initial("0.1.0")).unwrap();

        let src = tmp.path().join("packed");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("index.html"), b"<html>v</html>").unwrap();
        let tar_path = tmp.path().join("app.tar");
        let mut tar = std::fs::File::create(&tar_path).unwrap();
        let report = pack_dir(&src, &mut tar, &PackLimits::default()).unwrap();
        tar.flush().unwrap();

        let built = BuiltRelease {
            release_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            sha: "a".repeat(40),
            message: "hi".into(),
            author: "dev".into(),
            rendering: Rendering::Static,
            runtime: RuntimeKind::Node,
            node_major: "22".into(),
            start_argv: Vec::new(),
            spa_fallback: None,
            bytes: report.bytes,
            file_count: report.file_count,
            tree_sha256: "0".repeat(64),
            health: Health {
                path: "/".into(),
                expect: HealthExpect::Non2xxOk,
                timeout_s: 5,
                consecutive: 1,
            },
            tar_path,
            job_dir: tmp.path().join("job"),
        };
        let err = promote(PromoteContext {
            cfg: &cfg,
            built: &built,
            generation: 1,
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("tree_sha256 mismatch"));
        let slot = cfg.slot_dir(Slot::Green);
        assert!(!slot.join("release.json").exists());
        assert!(!slot.join("app").exists());
        assert!(!slot_is_sealed(&slot));
    }

    #[test]
    fn fallback_is_a_failed_deploy_and_live_is_success() {
        assert_eq!(promote_outcome(Outcome::Live), PromoteOutcome::Live);
        assert_eq!(
            promote_outcome(Outcome::Failed),
            PromoteOutcome::FailedHealth
        );
        assert_eq!(
            promote_outcome(Outcome::Fallback),
            PromoteOutcome::FailedHealth
        );
    }

    #[test]
    fn janitor_removes_stray_files_and_reports_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let data = cfg.releases_dir.parent().unwrap().to_path_buf();
        std::fs::write(data.join("stray.bin"), b"x").unwrap();
        std::fs::write(data.join("releases/third"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc", data.join("link")).unwrap();
        std::fs::create_dir_all(data.join("stray_dir")).unwrap();
        std::fs::write(cfg.slot_dir(Slot::Blue).join("release.json"), b"{}").unwrap();

        ensure_slot_dirs(&cfg).unwrap();

        assert!(!data.join("stray.bin").exists());
        assert!(!data.join("releases/third").exists());
        assert!(std::fs::symlink_metadata(data.join("link")).is_err());
        assert!(data.join("stray_dir").is_dir());
        assert!(cfg.slot_dir(Slot::Blue).join("release.json").exists());
        for keep in [
            "control",
            "status",
            "state",
            "releases/blue",
            "releases/green",
        ] {
            assert!(data.join(keep).is_dir(), "{keep}");
        }
        let left = sweep_layout_strays(&data, &[]).unwrap();
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(left[0].contains("stray_dir"));
    }

    #[test]
    fn janitor_ignores_scratch_volumes_and_untrusted_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let data = cfg.releases_dir.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(data.join("work")).unwrap();
        std::fs::create_dir_all(data.join("cache")).unwrap();
        let scratch = scratch_names(
            &data,
            &[&data.join("work"), &data.join("cache/x"), &cfg.work_dir],
        );
        assert_eq!(scratch, ["work", "cache"]);
        assert!(sweep_layout_strays(&data, &scratch).unwrap().is_empty());

        let mut relocated = cfg.clone();
        relocated.releases_dir = tmp.path().join("srv-sites");
        assert!(data_root_of(&relocated).is_none());
        assert_eq!(data_root_of(&cfg).as_deref(), Some(data.as_path()));
    }

    #[test]
    fn generations_never_fall_behind_what_was_written_or_acked() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        assert_eq!(generation_floor(&cfg, 3), 3);
        let first =
            write_action(&cfg, DesiredAction::Evict, Slot::Blue, Some(Slot::Green), 3).unwrap();
        assert_eq!(first, 4);
        let stale = write_action(&cfg, DesiredAction::Activate, Slot::Green, None, 0).unwrap();
        assert_eq!(
            stale, 5,
            "a stale recorded generation must not reuse a written one"
        );
        let mut status = ExecutorStatus::initial("0.1.0");
        status.ack_generation = 9;
        write_status(&cfg.status_path(), &status).unwrap();
        assert_eq!(generation_floor(&cfg, 0), 9);
    }

    #[test]
    fn evict_is_written_before_activate_and_generations_increase() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_in(tmp.path());
        let evict_gen =
            write_action(&cfg, DesiredAction::Evict, Slot::Blue, Some(Slot::Green), 0).unwrap();
        let evict = read_desired(&cfg.desired_path()).unwrap();
        assert_eq!(evict.generation, evict_gen);
        assert_eq!(evict.action, DesiredAction::Evict);
        assert_eq!(evict.evict_slot, Some(Slot::Green));

        let activate_gen =
            write_action(&cfg, DesiredAction::Activate, Slot::Green, None, evict_gen).unwrap();
        assert!(activate_gen > evict_gen);
        let activate = read_desired(&cfg.desired_path()).unwrap();
        assert_eq!(activate.generation, activate_gen);
        assert_eq!(activate.action, DesiredAction::Activate);
        assert_eq!(activate.live_slot, Slot::Green);
    }
}
