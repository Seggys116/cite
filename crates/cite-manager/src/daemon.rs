use std::sync::Arc;
use std::time::Duration;

use cite_core::{ManagerConfig, PollInterval, ensure_dir};
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::Result;
use crate::deploy::Deployer;
use crate::poll::PollDecision;
use crate::socket;

pub async fn run_daemon(cfg: ManagerConfig) -> Result<()> {
    info!(config = %cfg.redacted_display(), "starting cite-manager daemon");

    let free = cite_core::filesystem_free_bytes(&cfg.work_dir).unwrap_or(0);
    if free < cfg.min_free_bytes {
        error!(
            free,
            min = cfg.min_free_bytes,
            "filesystem free bytes below CITE_MIN_FREE_BYTES; refusing to start"
        );
        return Err(crate::ManagerError::new(format!(
            "filesystem free bytes {free} < CITE_MIN_FREE_BYTES {}",
            cfg.min_free_bytes
        )));
    }

    for dir in [
        &cfg.releases_dir,
        &cfg.control_dir,
        &cfg.status_dir,
        &cfg.state_dir,
        &cfg.work_dir,
        &cfg.cache_dir,
    ] {
        ensure_dir(dir, 0o755)?;
    }
    if let Some(parent) = cfg.socket_path.parent() {
        ensure_dir(parent, 0o755)?;
    }

    let deployer = Deployer::new(cfg.clone()).await?;
    let gate = Arc::new(Mutex::new(()));

    // Validated in the background with backoff so a bad token does not crash-loop the daemon.
    {
        let d = Arc::clone(&deployer);
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            d.validate_github_with_backoff().await;
            let _guard = gate.lock().await;
            d.maybe_first_boot_deploy().await;
        });
    }

    {
        let d = Arc::clone(&deployer);
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            poller_loop(d, gate).await;
        });
    }

    // Control socket, until SIGTERM. An in-flight build is aborted and cite_work swept.
    let shutdown_handle = Arc::clone(&deployer);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = socket::serve_socket(cfg.clone(), deployer, gate) => result,
        _ = sigterm.recv() => {
            info!("SIGTERM; aborting in-flight build");
            shutdown_handle.request_shutdown();
            crate::build::abort_inflight_build();
            let _ = crate::build::cleanup_job(&cfg, &cfg.work_dir.join("job-shutdown-sweep"));
            Ok(())
        }
    }
}

const RECONCILE_EVERY: Duration = Duration::from_secs(15);
const STUCK_POLL_PAUSE: Duration = Duration::from_secs(5);

async fn poller_loop(deployer: Arc<Deployer>, gate: Arc<Mutex<()>>) {
    if matches!(deployer.cfg.poll, PollInterval::Off) {
        info!("poll interval is off; automatic polling disabled");
    }
    loop {
        {
            let _guard = gate.lock().await;
            if let Err(err) = deployer.adopt_reality().await {
                error!(error = %err, "reconcile with executor status failed");
            }
        }

        let decision = {
            let state = deployer.state.lock().await;
            deployer.next_poll_wait(&state)
        };
        match decision {
            PollDecision::IdleForever => {
                tokio::time::sleep(RECONCILE_EVERY).await;
            }
            PollDecision::Wait(dur) => {
                tokio::time::sleep(dur.min(RECONCILE_EVERY)).await;
            }
            PollDecision::PollNow => {
                let _guard = gate.lock().await;
                if let Err(err) = deployer
                    .handle(crate::deploy::DeployCmd::Poll { force: false })
                    .await
                {
                    error!(error = %err, "automatic poll/deploy failed");
                }
                let still_due = {
                    let state = deployer.state.lock().await;
                    matches!(deployer.next_poll_wait(&state), PollDecision::PollNow)
                };
                if still_due {
                    tokio::time::sleep(STUCK_POLL_PAUSE).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use cite_core::ManagerConfig;

    use super::run_daemon;

    fn test_cfg(dir: &std::path::Path, extra: &[(&str, &str)]) -> ManagerConfig {
        let token = dir.join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert(
            "CITE_DATA_DIR".into(),
            dir.join("data").display().to_string(),
        );
        env.insert(
            "CITE_WORK_DIR".into(),
            dir.join("work").display().to_string(),
        );
        env.insert(
            "CITE_CACHE_DIR".into(),
            dir.join("cache").display().to_string(),
        );
        env.insert("CITE_GITHUB_TOKEN_FILE".into(), token.display().to_string());
        env.insert("CITE_GITHUB_API_URL".into(), "http://127.0.0.1:1".into());
        env.insert("CITE_DEV_SAME_USER".into(), "true".into());
        env.insert("CITE_MIN_FREE_BYTES".into(), "1".into());
        env.insert("CITE_POLL_INTERVAL".into(), "off".into());
        env.insert("CITE_MIN_POLL".into(), "1s".into());
        for (key, value) in extra {
            env.insert((*key).to_string(), (*value).to_string());
        }
        ManagerConfig::load_from(&env, None).unwrap()
    }

    #[tokio::test]
    async fn poller_idles_when_polling_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), &[]);
        let deployer = crate::deploy::Deployer::new(cfg).await.unwrap();
        let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let task = tokio::spawn(super::poller_loop(deployer, gate));
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        task.abort();
    }

    #[tokio::test]
    async fn poller_backs_off_when_github_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), &[("CITE_POLL_INTERVAL", "1s")]);
        let deployer = crate::deploy::Deployer::new(cfg).await.unwrap();
        let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let task = tokio::spawn(super::poller_loop(std::sync::Arc::clone(&deployer), gate));
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        task.abort();
        let state = deployer.state.lock().await;
        assert!(
            state.next_poll_at.is_some(),
            "a failed poll schedules the next attempt"
        );
    }

    #[tokio::test]
    async fn paused_poller_schedules_the_next_poll_instead_of_spinning() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), &[("CITE_POLL_INTERVAL", "1s")]);
        let deployer = crate::deploy::Deployer::new(cfg).await.unwrap();
        {
            let mut state = deployer.state.lock().await;
            state.paused = true;
            state.next_poll_at = None;
        }
        let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let task = tokio::spawn(super::poller_loop(std::sync::Arc::clone(&deployer), gate));
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        task.abort();
        let state = deployer.state.lock().await;
        assert!(
            state.next_poll_at.is_some(),
            "a paused poll must schedule the next one or PollNow fires again at once"
        );
    }

    #[tokio::test]
    async fn failed_poll_retry_is_pushed_out_by_the_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path(), &[("CITE_POLL_INTERVAL", "1s")]);
        let deployer = crate::deploy::Deployer::new(cfg).await.unwrap();
        assert!(deployer.poll_and_maybe_deploy(false).await.is_err());
        let next = deployer
            .state
            .lock()
            .await
            .next_poll_at
            .clone()
            .and_then(|at| crate::poll::parse_rfc3339(&at))
            .expect("retry scheduled");
        let ahead = next - time::OffsetDateTime::now_utc();
        assert!(
            ahead > time::Duration::seconds(3),
            "retry only {ahead} away"
        );
    }

    #[tokio::test]
    async fn daemon_refuses_to_start_below_the_free_space_floor() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_DATA_DIR".into(), dir.path().display().to_string());
        env.insert(
            "CITE_WORK_DIR".into(),
            dir.path().join("work").display().to_string(),
        );
        env.insert("CITE_MIN_FREE_BYTES".into(), "9999GB".into());
        env.insert("CITE_DEV_SAME_USER".into(), "true".into());
        env.insert("CITE_POLL_INTERVAL".into(), "off".into());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let err = run_daemon(cfg).await.unwrap_err();
        assert!(err.to_string().contains("CITE_MIN_FREE_BYTES"), "{err}");
    }
}
