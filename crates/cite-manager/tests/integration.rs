use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cite_core::{
    ExecutorConfig, ManagerConfig, PollInterval, Slot, layout_violations, slot_is_sealed,
};
use cite_executor::RunningExecutor;
use cite_manager::build::{load_build_env, make_redactor};
use cite_manager::deploy::{DeployCmd, Deployer};
use cite_manager::poll::{PollDecision, decide_poll};
use cite_mock_github::MockGithub;
use tempfile::TempDir;
use time::OffsetDateTime;

#[test]
fn manager_logs_json_to_stdout_and_rust_log_sets_the_level() {
    let bin = env!("CARGO_BIN_EXE_cite-manager");
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
    let info = Command::new(bin)
        .args(["config", "check"])
        .env_clear()
        .env("PATH", &path)
        .env("RUST_LOG", "info")
        .env("CITE_REPO", "owner/name")
        .output()
        .unwrap();
    let stdout = String::from_utf8(info.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|line| line.contains("manager ready"))
        .expect("startup log on stdout");
    let parsed: serde_json::Value = serde_json::from_str(line).expect("json log line");
    assert_eq!(parsed["level"], "INFO");
    assert!(line.contains("manager ready"));

    let quiet = Command::new(bin)
        .args(["config", "check"])
        .env_clear()
        .env("PATH", &path)
        .env("RUST_LOG", "error")
        .env("CITE_REPO", "owner/name")
        .output()
        .unwrap();
    assert!(
        !String::from_utf8(quiet.stdout)
            .unwrap()
            .contains("manager ready")
    );
}

fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Polls `cite_data` for a third release slot or any other unexpected path.
struct LayoutWatch {
    stop: Arc<AtomicBool>,
    hits: Arc<Mutex<Vec<String>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl LayoutWatch {
    fn start(data: PathBuf) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::clone(&stop);
        let found = Arc::clone(&hits);
        let handle = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                record_layout(&data, &found);
                std::thread::sleep(Duration::from_millis(20));
            }
            record_layout(&data, &found);
        });
        Self {
            stop,
            hits,
            handle: Some(handle),
        }
    }

    fn stop_and_take(&mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        std::mem::take(&mut *self.hits.lock().expect("layout watch"))
    }
}

fn record_layout(data: &Path, hits: &Mutex<Vec<String>>) {
    let Ok(violations) = layout_violations(data) else {
        return;
    };
    if violations.is_empty() {
        return;
    }
    let mut guard = hits.lock().expect("layout watch");
    for violation in violations {
        if !guard.contains(&violation) {
            guard.push(violation);
        }
    }
}

struct Harness {
    watch: LayoutWatch,
    _tmp: TempDir,
    data: PathBuf,
    work: PathBuf,
    cache: PathBuf,
    token_file: PathBuf,
    build_env_file: PathBuf,
    pub cfg: ManagerConfig,
    pub mock: MockGithub,
}

impl Harness {
    async fn new() -> Self {
        Self::with_env(&[]).await
    }

    async fn with_env(extra: &[(&str, &str)]) -> Self {
        let tmp = TempDir::new().unwrap();
        let data = tmp.path().join("cite_data");
        let work = tmp.path().join("cite_work");
        let cache = tmp.path().join("cite_cache");
        for sub in [
            "releases/blue",
            "releases/green",
            "control",
            "status",
            "state",
        ] {
            std::fs::create_dir_all(data.join(sub)).unwrap();
        }
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&cache).unwrap();

        let mock = MockGithub::spawn().await.expect("mock github");
        let token_file = tmp.path().join("token");
        std::fs::write(&token_file, mock.token()).unwrap();
        let build_env_file = tmp.path().join("build.env");
        std::fs::write(&build_env_file, "SECRET_BUILD_VALUE=super-secret-build\n").unwrap();

        let socket = tmp.path().join("manager.sock");
        let mut pairs = vec![
            ("CITE_REPO", "owner/name"),
            ("CITE_BRANCH", "main"),
            ("CITE_POLL_INTERVAL", "off"),
            ("CITE_GITHUB_TOKEN_FILE", token_file.to_str().unwrap()),
            ("CITE_GITHUB_API_URL", mock.base_url()),
            ("CITE_DATA_DIR", data.to_str().unwrap()),
            ("CITE_WORK_DIR", work.to_str().unwrap()),
            ("CITE_CACHE_DIR", cache.to_str().unwrap()),
            ("CITE_SOCKET", socket.to_str().unwrap()),
            ("CITE_BUILD_ENV_FILE", build_env_file.to_str().unwrap()),
            ("CITE_DEV_SAME_USER", "true"),
            ("CITE_RENDERING", "static"),
            ("CITE_OUTPUT_DIR", "dist"),
            ("CITE_INSTALL_COMMAND", "true"),
            ("CITE_BUILD_COMMAND", "node build.js"),
            ("CITE_MIN_FREE_BYTES", "1"),
            ("CITE_HEALTH_TIMEOUT", "5s"),
            ("CITE_HEALTH_CONSECUTIVE", "1"),
            ("CITE_BUILD_TIMEOUT", "60s"),
            ("CITE_BUILD_CACHE", "off"),
            ("CITE_NODE", "22"),
        ];
        pairs.extend_from_slice(extra);
        let cfg = ManagerConfig::load_from(&env_map(&pairs), None).expect("config");
        let watch = LayoutWatch::start(data.clone());

        Self {
            watch,
            _tmp: tmp,
            data,
            work,
            cache,
            token_file,
            build_env_file,
            cfg,
            mock,
        }
    }

    async fn deployer(&self) -> std::sync::Arc<Deployer> {
        Deployer::new(self.cfg.clone()).await.expect("deployer")
    }

    async fn spawn_executor(&self) -> RunningExecutor {
        let runtime_env = self._tmp.path().join("runtime.env");
        std::fs::write(&runtime_env, "").unwrap();
        let exec_cfg = ExecutorConfig::load_from(
            &env_map(&[
                ("CITE_LISTEN", "127.0.0.1:0"),
                ("CITE_DATA_DIR", self.data.to_str().unwrap()),
                ("CITE_RUNTIME_ENV_FILE", runtime_env.to_str().unwrap()),
                ("CITE_RUNTIME", "static"),
                ("CITE_NODE", "22"),
                ("CITE_WARM_GRACE", "1h"),
                ("CITE_WATCH", "1m"),
            ]),
            None,
        )
        .expect("executor config");
        cite_executor::spawn(exec_cfg)
            .await
            .expect("executor spawn")
    }

    fn job_dirs_left(&self) -> Vec<String> {
        std::fs::read_dir(&self.work)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("job-"))
            .collect()
    }
}

impl Drop for LayoutWatch {
    fn drop(&mut self) {
        let _ = self.stop_and_take();
    }
}

impl Harness {
    async fn shutdown(mut self) {
        let violations = self.watch.stop_and_take();
        self.mock.shutdown().await;
        assert!(
            violations.is_empty(),
            "volume watcher saw an illegal cite_data path: {violations:?}"
        );
    }
}

async fn wait_sealed(cfg: &ManagerConfig, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if slot_is_sealed(&cfg.slot_dir(Slot::Blue)) || slot_is_sealed(&cfg.slot_dir(Slot::Green)) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("no sealed slot within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn first_deploy_and_second_push() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let deployer = h.deployer().await;
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("first deploy");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    assert!(
        slot_is_sealed(&h.cfg.slot_dir(Slot::Blue)) || slot_is_sealed(&h.cfg.slot_dir(Slot::Green))
    );
    assert!(
        h.job_dirs_left().is_empty(),
        "job dirs left: {:?}",
        h.job_dirs_left()
    );
    assert!(
        layout_violations(&h.data).unwrap().is_empty(),
        "layout: {:?}",
        layout_violations(&h.data).unwrap()
    );

    let live_sha = cite_core::read_state(&h.cfg.state_path())
        .unwrap()
        .last_deployed_sha
        .clone();
    assert!(live_sha.is_some());
    let sealed = [Slot::Blue, Slot::Green]
        .into_iter()
        .find(|slot| slot_is_sealed(&h.cfg.slot_dir(*slot)))
        .unwrap();
    let app = h.cfg.slot_dir(sealed).join("app");
    assert!(app.join("index.html").is_file());
    assert!(!app.join("package.json").exists());
    assert!(!app.join("build.js").exists());
    let sealed_release = std::fs::read(h.cfg.slot_dir(sealed).join("release.json")).unwrap();
    let sealed_index = std::fs::read(app.join("index.html")).unwrap();

    h.mock
        .push_files(
            "main",
            "second",
            "tester",
            vec![("index.html".into(), b"<html>v2</html>".to_vec())],
        )
        .await;
    deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("second deploy");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert_ne!(state.last_deployed_sha, live_sha);
    assert!(
        h.job_dirs_left().is_empty(),
        "job dirs left after second deploy"
    );
    assert!(layout_violations(&h.data).unwrap().is_empty());
    assert_eq!(
        std::fs::read(h.cfg.slot_dir(sealed).join("release.json")).unwrap(),
        sealed_release,
        "live slot release.json must stay unchanged"
    );
    assert_eq!(
        std::fs::read(h.cfg.slot_dir(sealed).join("app/index.html")).unwrap(),
        sealed_index,
        "live slot app bytes must stay unchanged"
    );

    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn failed_build_does_not_evict_live() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let deployer = h.deployer().await;
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("first deploy");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    let before = sealed_release_json(&h.cfg);

    h.mock
        .push_files(
            "main",
            "bad build",
            "tester",
            vec![
                ("build.js".into(), b"process.exit(1);\n".to_vec()),
                ("index.html".into(), b"<html>bad</html>".to_vec()),
            ],
        )
        .await;

    let result = deployer.handle(DeployCmd::Poll { force: false }).await;
    assert!(result.is_err(), "expected build failure, got {result:?}");

    let after = sealed_release_json(&h.cfg);
    assert_eq!(before, after, "live release must survive failed build");
    assert!(
        h.job_dirs_left().is_empty(),
        "job dirs left after failed build: {:?}",
        h.job_dirs_left()
    );
    assert!(layout_violations(&h.data).unwrap().is_empty());

    let again = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("retry of failed sha");
    let suppressed = again["skipped"] == "already_seen" || again["unchanged"] == true;
    assert!(suppressed, "failed sha was retried: {again}");
    assert_eq!(sealed_release_json(&h.cfg), after);

    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn redaction_strips_token_and_build_env() {
    let h = Harness::new().await;
    let token = std::fs::read_to_string(&h.token_file).unwrap();
    let token = token.trim().to_string();
    let build_env = load_build_env(&h.cfg).unwrap();
    let redactor = make_redactor(&token, &build_env);
    let line = format!(
        "curl -H 'Authorization: Bearer {token}' SECRET_BUILD_VALUE=super-secret-build done"
    );
    let line = format!("{line} and super-secret-build");
    let got = redactor.redact_line(&line);
    assert!(!got.contains(token.trim()), "token leaked in: {got}");
    assert!(
        !got.contains("super-secret-build"),
        "build.env value leaked in: {got}"
    );
    let _ = h.build_env_file;
    let _ = h.cache;
    h.shutdown().await;
}

#[tokio::test]
async fn second_poll_uses_etag_and_does_not_redeploy() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let deployer = h.deployer().await;
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("first deploy");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    let live = cite_core::read_state(&h.cfg.state_path())
        .unwrap()
        .last_deployed_sha;
    let again = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("second poll");
    assert_eq!(again["unchanged"], true);
    assert_eq!(
        cite_core::read_state(&h.cfg.state_path())
            .unwrap()
            .last_deployed_sha,
        live
    );
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn rate_limit_backs_off_without_deploying() {
    let h = Harness::new().await;
    h.mock.set_rate_remaining(0);
    let deployer = h.deployer().await;
    let result = deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("rate limit");
    assert_eq!(result["rate_limited"], true);
    assert!(sealed_release_json(&h.cfg).is_none());
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert!(state.next_poll_at.is_some());
    h.shutdown().await;
}

#[tokio::test]
async fn first_boot_deploys_head() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let deployer = h.deployer().await;
    deployer.maybe_first_boot_deploy().await;
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    assert!(
        cite_core::read_state(&h.cfg.state_path())
            .unwrap()
            .last_deployed_sha
            .is_some()
    );
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn startup_adopts_executor_active_slot() {
    let h = Harness::new().await;
    let desired = cite_core::Desired {
        v: cite_core::SCHEMA_VERSION,
        generation: 1,
        live_slot: Slot::Blue,
        action: cite_core::DesiredAction::Noop,
        evict_slot: None,
        warm_grace_s: 60,
        restart_nonce: String::new(),
        written_at: "2026-01-01T00:00:00Z".into(),
    };
    cite_core::write_desired(&h.cfg.desired_path(), &desired).unwrap();
    let mut status = cite_core::ExecutorStatus::initial("0.1.0");
    status.ack_generation = 1;
    status.active_slot = Some(Slot::Green);
    status.last_result = Some(cite_core::LastResult {
        generation: 1,
        outcome: cite_core::Outcome::Fallback,
        reason: "fallback after crash".into(),
        log_tail: vec![],
    });
    cite_core::write_status(&h.cfg.status_path(), &status).unwrap();
    let _deployer = h.deployer().await;
    let adopted = cite_core::read_desired(&h.cfg.desired_path()).unwrap();
    assert_eq!(adopted.live_slot, Slot::Green);
    assert!(adopted.generation > 1);
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert_eq!(
        state.last_failed_reason.as_deref(),
        Some("fallback after crash")
    );
    h.shutdown().await;
}

#[test]
fn pack_helper_stdout_is_a_tar_not_a_log_line() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), b"v1").unwrap();
    let bin = env!("CARGO_BIN_EXE_cite-manager");
    let out = Command::new(bin)
        .arg("__pack")
        .arg(dir.path())
        .env_clear()
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        )
        .env("RUST_LOG", "info")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.stdout.starts_with(b"{"),
        "pack stdout started with a log line: {}",
        String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(80)])
    );
    assert!(out.stdout.len() > 262, "tar too small");
    assert_eq!(&out.stdout[257..262], b"ustar");
}

#[test]
fn volume_watcher_records_a_third_release_slot() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("cite_data");
    std::fs::create_dir_all(data.join("releases/blue")).unwrap();
    let mut watch = LayoutWatch::start(data.clone());
    std::fs::create_dir_all(data.join("releases/staging")).unwrap();
    std::thread::sleep(Duration::from_millis(150));
    let seen = watch.stop_and_take();
    assert!(
        seen.iter().any(|violation| violation.contains("staging")),
        "{seen:?}"
    );
}

#[tokio::test]
async fn startup_sweeps_unsealed_slots_and_work() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.cfg.slot_dir(Slot::Blue).join("app")).unwrap();
    std::fs::write(h.cfg.slot_dir(Slot::Blue).join("app/index.html"), b"junk").unwrap();
    std::fs::create_dir_all(h.work.join("job-stale")).unwrap();
    std::fs::write(h.work.join("job-stale/a.txt"), b"x").unwrap();
    let _deployer = h.deployer().await;
    assert!(
        !h.cfg.slot_dir(Slot::Blue).join("app/index.html").exists(),
        "unsealed slot contents must be deleted at startup"
    );
    assert!(h.job_dirs_left().is_empty(), "work dir must be swept");
    h.shutdown().await;
}

#[tokio::test]
async fn abandoned_build_is_swept_and_the_sha_is_rebuilt() {
    let h = Harness::with_env(&[("CITE_POLL_INTERVAL", "1m")]).await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let sha = h.mock.head_sha("main").unwrap();
    std::fs::create_dir_all(h.work.join("job-abandoned")).unwrap();
    std::fs::write(h.work.join("job-abandoned/partial.txt"), b"torn").unwrap();
    let state = cite_core::ManagerState {
        last_observed_sha: Some(sha.clone()),
        next_poll_at: Some("2020-01-01T00:00:00Z".into()),
        ..cite_core::ManagerState::default()
    };
    cite_core::write_state(&h.cfg.state_path(), &state).unwrap();

    let deployer = h.deployer().await;
    assert!(
        h.job_dirs_left().is_empty(),
        "an in-flight job directory is abandoned at boot"
    );
    let loaded = deployer.state.lock().await.clone();
    assert!(loaded.last_deployed_sha.is_none());
    assert!(matches!(
        deployer.next_poll_wait(&loaded),
        PollDecision::PollNow
    ));
    drop(loaded);

    deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("unrecorded sha is rebuilt");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    let deployed = deployer.state.lock().await.last_deployed_sha.clone();
    assert_eq!(deployed.as_deref(), Some(sha.as_str()));
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn polls_during_a_build_keep_only_the_newest_head() {
    let h = Harness::new().await;
    let deployer = h.deployer().await;
    *deployer.building.lock().await = true;
    h.mock
        .push_files(
            "main",
            "mid one",
            "tester",
            vec![("notes.txt".into(), b"one".to_vec())],
        )
        .await;
    let first = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .unwrap();
    assert_eq!(first["coalesced"], true);
    let first_sha = h.mock.head_sha("main").unwrap();
    h.mock
        .push_files(
            "main",
            "mid two",
            "tester",
            vec![("notes.txt".into(), b"two".to_vec())],
        )
        .await;
    let second = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .unwrap();
    assert_eq!(second["coalesced"], true);
    let newest = h.mock.head_sha("main").unwrap();
    assert_ne!(first_sha, newest);
    let pending = deployer.pending_head.lock().await.clone().unwrap();
    assert_eq!(pending.sha, newest);
    assert!(sealed_release_json(&h.cfg).is_none());
    h.shutdown().await;
}

#[tokio::test]
async fn missing_index_html_does_not_evict_live() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let deployer = h.deployer().await;
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("first deploy");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    let before = sealed_release_json(&h.cfg);
    h.mock
        .push_files(
            "main",
            "no index",
            "tester",
            vec![
                (
                    "package.json".into(),
                    b"{\"name\":\"site\",\"scripts\":{\"build\":\"node build.js\"},\"dependencies\":{\"astro\":\"5.0.0\"}}".to_vec(),
                ),
                (
                    "build.js".into(),
                    b"const fs=require('fs');fs.mkdirSync('dist',{recursive:true});fs.writeFileSync('dist/other.txt','x');\n".to_vec(),
                ),
            ],
        )
        .await;
    let err = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect_err("missing index");
    assert!(
        err.to_string().contains("index.html"),
        "unexpected error: {err}"
    );
    assert_eq!(sealed_release_json(&h.cfg), before);
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn build_child_does_not_receive_the_token() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let token = h.mock.token().trim().to_string();
    let script = format!(
        "const fs=require('fs');const env=JSON.stringify(process.env);if(env.includes({token:?})||env.includes('GITHUB_TOKEN')||env.includes('CITE_GITHUB'))process.exit(2);fs.mkdirSync('dist',{{recursive:true}});fs.copyFileSync('index.html','dist/index.html');\n"
    );
    h.mock
        .push_files(
            "main",
            "env probe",
            "tester",
            vec![("build.js".into(), script.into_bytes())],
        )
        .await;
    let deployer = h.deployer().await;
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("build must succeed without the token in the child environment");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn github_validation_reports_branch_and_bad_token() {
    let h = Harness::new().await;
    let bad_branch = cite_manager::github::GithubClient::new(
        h.mock.base_url(),
        "owner",
        "name",
        "no-such-branch",
        &cite_core::GithubToken::File(h.token_file.clone()),
    )
    .unwrap();
    let err = bad_branch.validate_access().await.expect_err("branch");
    assert!(
        err.to_string().contains("does not exist"),
        "unexpected error: {err}"
    );

    std::fs::write(&h.token_file, "ghp_wrongtokenwrongtokenwrongtoken01\n").unwrap();
    let bad_token = cite_manager::github::GithubClient::new(
        h.mock.base_url(),
        "owner",
        "name",
        "main",
        &cite_core::GithubToken::File(h.token_file.clone()),
    )
    .unwrap();
    let err = bad_token.validate_access().await.expect_err("token");
    assert!(
        err.to_string().contains("bad token") || err.to_string().contains("invalid"),
        "unexpected error: {err}"
    );

    std::fs::write(&h.token_file, h.mock.token()).unwrap();
    h.mock.set_expiry(Some("2099-01-01T00:00:00Z".into()));
    let ok = cite_manager::github::GithubClient::new(
        h.mock.base_url(),
        "owner",
        "name",
        "main",
        &cite_core::GithubToken::File(h.token_file.clone()),
    )
    .unwrap()
    .validate_access()
    .await
    .unwrap();
    assert_eq!(ok.token_expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
    h.shutdown().await;
}

#[tokio::test]
async fn stale_executor_heartbeat_is_unresponsive() {
    let h = Harness::new().await;
    let mut status = cite_core::ExecutorStatus::initial("0.1.0");
    status.updated_at = "2020-01-01T00:00:00Z".into();
    cite_core::write_status(&h.cfg.status_path(), &status).unwrap();
    assert!(!cite_manager::promote::executor_responsive(&h.cfg).unwrap());
    let deployer = h.deployer().await;
    let json = deployer.status_json().await.unwrap();
    assert_eq!(json["executor_unresponsive"], true);
    h.shutdown().await;
}

#[tokio::test]
async fn rollback_refused_without_previous_release() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let deployer = h.deployer().await;
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("first deploy");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    let err = deployer
        .handle(DeployCmd::Rollback)
        .await
        .expect_err("rollback");
    assert!(
        err.to_string().contains("rollback refused"),
        "unexpected error: {err}"
    );
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn bad_token_stops_polling_until_the_file_is_rotated() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let deployer = h.deployer().await;
    std::fs::write(&h.token_file, "ghp_wrongtokenwrongtokenwrongtoken01\n").unwrap();
    let err = deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect_err("bad token");
    assert!(
        err.to_string().contains("token_invalid"),
        "unexpected error: {err}"
    );
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert!(state.token_invalid);

    std::fs::write(&h.token_file, h.mock.token()).unwrap();
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("rotated token");
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert!(!state.token_invalid);
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn transient_deploy_failure_is_retried_on_the_next_poll() {
    let h = Harness::with_env(&[("CITE_POLL_INTERVAL", "1m")]).await;
    let deployer = h.deployer().await;
    let sha = h.mock.head_sha("main").unwrap();
    let err = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect_err("no executor is running to take the release");
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert!(
        state.last_failed_sha.is_none(),
        "{err}: promote errors are transient"
    );
    assert!(
        state.poll_etag.is_none(),
        "an unfinished head must not be remembered as seen"
    );
    assert!(state.next_poll_at.is_some());

    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("the head is retried, not answered with 304");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    let deployed = deployer.state.lock().await.last_deployed_sha.clone();
    assert_eq!(deployed.as_deref(), Some(sha.as_str()));
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn rejected_token_is_not_retried_until_it_changes() {
    let h = Harness::with_env(&[("CITE_POLL_INTERVAL", "1m")]).await;
    let deployer = h.deployer().await;
    h.mock.set_authorized(false);
    let err = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect_err("401");
    assert!(err.to_string().contains("token_invalid"), "{err}");
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert!(state.token_invalid);
    let next = state.next_poll_at.expect("next poll scheduled after a 401");
    let next = cite_manager::poll::parse_rfc3339(&next).unwrap();
    assert!(
        next > OffsetDateTime::now_utc(),
        "a 401 must not leave the poll due"
    );

    h.mock.set_authorized(true);
    let skipped = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("same token is not sent again");
    assert_eq!(skipped["skipped"], "token_invalid");

    std::fs::write(&h.token_file, "ghp_anotherrotatedtokenvalue0000000001\n").unwrap();
    let err = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect_err("a changed token is tried and rejected");
    assert!(err.to_string().contains("token_invalid"), "{err}");

    std::fs::write(&h.token_file, h.mock.token()).unwrap();
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("valid rotated token");
    assert!(!deployer.state.lock().await.token_invalid);
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn redeploy_during_a_build_is_coalesced_not_run_concurrently() {
    let h = Harness::new().await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let sha = h.mock.head_sha("main").unwrap();
    h.mock.set_tarball_delay(Duration::from_millis(1500));
    let deployer = h.deployer().await;
    let first = {
        let d = std::sync::Arc::clone(&deployer);
        tokio::spawn(async move { d.handle(DeployCmd::Poll { force: true }).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = deployer
        .handle(DeployCmd::Redeploy {
            sha: Some(sha.clone()),
        })
        .await
        .expect("second deploy");
    assert_eq!(second["coalesced"], true, "{second}");
    let first = first.await.unwrap().expect("first deploy");
    assert_eq!(first["outcome"], "live");
    assert!(!*deployer.building.lock().await);
    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn transient_build_failure_does_not_mark_the_sha_failed_and_is_retried() {
    let h = Harness::with_env(&[("CITE_MIN_FREE_BYTES", "9999GB")]).await;
    let deployer = h.deployer().await;
    let first = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect_err("not enough free space to build");
    assert!(first.to_string().contains("CITE_MIN_FREE_BYTES"), "{first}");
    let state = cite_core::read_state(&h.cfg.state_path()).unwrap();
    assert!(
        state.last_failed_sha.is_none(),
        "environment failures are not permanent"
    );
    assert!(state.poll_etag.is_none());
    assert!(state.last_failed_attempts >= 1);

    let second = deployer.handle(DeployCmd::Poll { force: false }).await;
    assert!(second.is_err(), "the head must be retried, got {second:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn path_filter_skips_unrelated_files() {
    let h = Harness::with_env(&[("CITE_PATHS", "docs")]).await;
    let executor = h.spawn_executor().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let deployer = h.deployer().await;
    deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect("first deploy");
    wait_sealed(&h.cfg, Duration::from_secs(60)).await;
    let live = cite_core::read_state(&h.cfg.state_path())
        .unwrap()
        .last_deployed_sha;

    h.mock
        .push_files(
            "main",
            "readme only",
            "tester",
            vec![("README.md".into(), b"unrelated\n".to_vec())],
        )
        .await;
    let skipped = deployer
        .handle(DeployCmd::Poll { force: false })
        .await
        .expect("path filter");
    assert_eq!(skipped["skipped"], "paths");
    let after = cite_core::read_state(&h.cfg.state_path())
        .unwrap()
        .last_deployed_sha;
    assert_eq!(live, after);

    executor.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn malicious_tarball_does_not_escape_the_job_directory() {
    let h = Harness::new().await;
    let sha = h.mock.head_sha("main").unwrap();
    h.mock
        .set_raw_tarball(&sha, raw_tar("prefix/../../pwned", b"pwned"));

    let canary = h.work.parent().unwrap().join("pwned");
    std::fs::write(&canary, b"safe").unwrap();

    let deployer = h.deployer().await;
    let err = deployer
        .handle(DeployCmd::Poll { force: true })
        .await
        .expect_err("malicious tarball must not deploy");
    let text = err.to_string().to_lowercase();
    assert!(
        text.contains("path") || text.contains("escape") || text.contains("archive"),
        "{err}"
    );
    assert_eq!(std::fs::read(&canary).unwrap(), b"safe");
    assert!(
        !h.work.join("pwned").exists(),
        "escaped file landed in the work directory"
    );
    h.shutdown().await;
}

#[test]
fn poll_interval_off_does_not_loop() {
    let now = OffsetDateTime::now_utc();
    assert_eq!(
        decide_poll(PollInterval::Off, None, now),
        PollDecision::IdleForever
    );
    assert_eq!(
        decide_poll(PollInterval::Off, Some(now), now),
        PollDecision::IdleForever
    );
}

fn raw_tar(path: &str, body: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    let size = format!("{:011o}", body.len());
    header[124..135].copy_from_slice(size.as_bytes());
    header[156] = b'0';
    header[257..262].copy_from_slice(b"ustar");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let cksum = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(cksum.as_bytes());
    let mut out = header.to_vec();
    out.extend_from_slice(body);
    let pad = (512 - (body.len() % 512)) % 512;
    out.extend(std::iter::repeat_n(0u8, pad + 1024));
    out
}

#[test]
fn cli_talks_to_a_live_daemon_and_helpers_run() {
    let bin = env!("CARGO_BIN_EXE_cite-manager");
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
    let version = Command::new(bin)
        .arg("--version")
        .env_clear()
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "{}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(String::from_utf8_lossy(&version.stdout).contains("cite-manager"));

    let help = Command::new(bin)
        .arg("--help")
        .env_clear()
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("healthcheck"));

    let bad = Command::new(bin)
        .arg("not-a-command")
        .env_clear()
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(!bad.status.success());

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let work = dir.path().join("work");
    let cache = dir.path().join("cache");
    let token = dir.path().join("token");
    std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
    // Accept and drop. A closed port can sit until the HTTP connect timeout.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 500 No\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    let socket =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/cite-cli.sock");
    let _ = std::fs::remove_file(&socket);
    let socket_s = socket.display().to_string();
    let env = [
        ("PATH", path.as_str()),
        ("CITE_REPO", "owner/name"),
        ("CITE_DATA_DIR", data.to_str().unwrap()),
        ("CITE_WORK_DIR", work.to_str().unwrap()),
        ("CITE_CACHE_DIR", cache.to_str().unwrap()),
        ("CITE_GITHUB_TOKEN_FILE", token.to_str().unwrap()),
        ("CITE_GITHUB_API_URL", api.as_str()),
        ("CITE_SOCKET", socket_s.as_str()),
        ("CITE_DEV_SAME_USER", "true"),
        ("CITE_MIN_FREE_BYTES", "1"),
        ("CITE_POLL_INTERVAL", "off"),
        ("RUST_LOG", "error"),
    ];

    let down = Command::new(bin)
        .arg("healthcheck")
        .env_clear()
        .envs(env)
        .output()
        .unwrap();
    assert!(
        !down.status.success(),
        "healthcheck must fail before the daemon binds"
    );

    let mut daemon = Command::new(bin)
        .env_clear()
        .envs(env)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let ready = std::time::Instant::now();
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        if ready.elapsed() > Duration::from_secs(5) || daemon.try_wait().unwrap().is_some() {
            let _ = daemon.kill();
            let output = daemon.wait_with_output().unwrap();
            panic!(
                "daemon did not bind {}\nstdout {}\nstderr {}",
                socket.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let run = |args: &[&str]| {
        Command::new(bin)
            .args(args)
            .env_clear()
            .envs(env)
            .output()
            .unwrap()
    };
    let health = run(&["healthcheck"]);
    assert!(
        health.status.success(),
        "{}",
        String::from_utf8_lossy(&health.stderr)
    );
    let status = run(&["status"]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(String::from_utf8_lossy(&status.stdout).contains("live sha:"));
    let json = run(&["status", "--json"]);
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(
        String::from_utf8_lossy(&json.stdout)
            .trim_start()
            .starts_with('{')
    );
    assert!(run(&["logs"]).status.success());
    assert!(run(&["config", "check"]).status.success());
    assert!(run(&["pause"]).status.success());
    assert!(run(&["resume"]).status.success());
    assert!(run(&["restart-child"]).status.success());
    assert!(run(&["restart-executor"]).status.success());
    assert!(!run(&["rollback"]).status.success());

    let term = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert!(term.success());
    let exited = std::time::Instant::now();
    loop {
        if daemon.try_wait().unwrap().is_some() {
            break;
        }
        if exited.elapsed() > Duration::from_secs(5) {
            let _ = daemon.kill();
            panic!("daemon ignored SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_file(&socket);

    let missing = Command::new(bin)
        .env_clear()
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(!missing.status.success());

    let full = Command::new(bin)
        .env_clear()
        .env("PATH", &path)
        .env("CITE_REPO", "owner/name")
        .env("CITE_MIN_FREE_BYTES", "9999GB")
        .env("CITE_DEV_SAME_USER", "true")
        .env("CITE_POLL_INTERVAL", "off")
        .output()
        .unwrap();
    assert!(!full.status.success());
    assert!(String::from_utf8_lossy(&full.stderr).contains("CITE_MIN_FREE_BYTES"));

    let probe = Command::new(bin)
        .arg("__ptrace-probe")
        .env_clear()
        .env("PATH", &path)
        .output()
        .unwrap();
    assert!(probe.status.success());
    assert!(String::from_utf8_lossy(&probe.stdout).contains("ptrace DENIED"));
}

fn sealed_release_json(cfg: &ManagerConfig) -> Option<String> {
    for slot in [Slot::Blue, Slot::Green] {
        let path = cfg.slot_dir(slot).join("release.json");
        if path.is_file() {
            return Some(std::fs::read_to_string(path).unwrap());
        }
    }
    None
}
