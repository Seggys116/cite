#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cite_core::schema::Rendering;
use cite_core::{
    ExecutorConfig, HealthExpect, Redactor, ReleaseManifest, Result, RuntimeKind, Slot,
    validate_start_argv,
};
use http::Request;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{info, warn};

const LOG_RING: usize = 40;
const LOG_LINE_MAX: usize = 1024;
/// Bind-address variables frameworks read; forced to loopback so children stay behind the executor.
const LOOPBACK_HOST_VARS: [&str; 3] = ["HOST", "HOSTNAME", "NITRO_HOST"];

#[derive(Clone)]
pub struct SlotManager {
    config: Arc<ExecutorConfig>,
    redactor: Redactor,
    blue: Arc<Mutex<SlotRuntime>>,
    green: Arc<Mutex<SlotRuntime>>,
    shutting_down: Arc<AtomicBool>,
}

struct SlotRuntime {
    child: Option<Child>,
    release_id: Option<String>,
    log: VecDeque<String>,
    crashes: VecDeque<Instant>,
    started_at: Option<Instant>,
}

impl SlotRuntime {
    fn new() -> Self {
        Self {
            child: None,
            release_id: None,
            log: VecDeque::new(),
            crashes: VecDeque::new(),
            started_at: None,
        }
    }

    fn push_log(&mut self, line: String) {
        let mut line = cite_core::escape_control(&line, true);
        if line.len() > LOG_LINE_MAX {
            let mut end = LOG_LINE_MAX;
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
        }
        if self.log.len() >= LOG_RING {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }

    fn log_tail(&self) -> Vec<String> {
        self.log.iter().cloned().collect()
    }
}

impl SlotManager {
    pub fn new(config: ExecutorConfig, redactor: Redactor) -> Self {
        Self {
            config: Arc::new(config),
            redactor,
            blue: Arc::new(Mutex::new(SlotRuntime::new())),
            green: Arc::new(Mutex::new(SlotRuntime::new())),
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    fn runtime(&self, slot: Slot) -> Arc<Mutex<SlotRuntime>> {
        match slot {
            Slot::Blue => self.blue.clone(),
            Slot::Green => self.green.clone(),
        }
    }

    pub async fn log_tail(&self, slot: Slot) -> Vec<String> {
        self.runtime(slot).lock().await.log_tail()
    }

    pub async fn pid(&self, slot: Slot) -> Option<u32> {
        self.runtime(slot)
            .lock()
            .await
            .child
            .as_ref()
            .and_then(Child::id)
    }

    pub async fn stop_slot(&self, slot: Slot) {
        let child = {
            let rt_arc = self.runtime(slot);
            let mut rt = rt_arc.lock().await;
            rt.release_id = None;
            rt.started_at = None;
            rt.child.take()
        };
        if let Some(child) = child {
            stop_child_group(child, self.config.child_term_grace).await;
        }
    }

    pub async fn shutdown_all(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        for slot in [Slot::Blue, Slot::Green] {
            self.stop_slot(slot).await;
        }
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub async fn record_crash(&self, slot: Slot, reason: String) {
        let rt_arc = self.runtime(slot);
        let mut rt = rt_arc.lock().await;
        rt.push_log(reason);
        rt.crashes.push_back(Instant::now());
        trim_crashes(&mut rt.crashes, self.config.crash_window);
    }

    pub fn check_release(&self, manifest: &ReleaseManifest) -> std::result::Result<(), String> {
        if self.config.runtime == RuntimeKind::Static {
            if manifest.rendering != Rendering::Static {
                return Err(format!(
                    "static runtime image cannot run rendering={:?}",
                    manifest.rendering
                ));
            }
            return Ok(());
        }
        if manifest.runtime != self.config.runtime {
            return Err(format!(
                "release runtime {:?} does not match image {:?}",
                manifest.runtime, self.config.runtime
            ));
        }
        if self.config.runtime != RuntimeKind::Rust
            && manifest.rendering == Rendering::Ssr
            && manifest.node_major != self.config.node_major
        {
            return Err(format!(
                "release node_major {} does not match image {}",
                manifest.node_major, self.config.node_major
            ));
        }
        Ok(())
    }

    pub async fn start_ssr(&self, slot: Slot, manifest: &ReleaseManifest) -> Result<()> {
        self.check_release(manifest)
            .map_err(cite_core::Error::msg)?;
        validate_start_argv(&manifest.start_argv)?;

        let keep_crashes = self.runtime(slot).lock().await.release_id.as_deref()
            == Some(manifest.release_id.as_str());
        self.stop_slot(slot).await;

        let app_dir = self.config.slot_dir(slot).join("app");
        let port = slot.loopback_port(self.config.port_base)?;
        let (program, args) = resolve_argv(&self.config, &app_dir, &manifest.start_argv)?;

        let mut cmd = Command::new(&program);
        cmd.args(&args)
            .current_dir(&app_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env(
                if manifest.port_env.is_empty() {
                    "PORT"
                } else {
                    manifest.port_env.as_str()
                },
                port.to_string(),
            )
            .env("NODE_ENV", "production");

        match self.config.runtime_env.resolve() {
            Ok(vars) => {
                cmd.envs(vars);
            }
            Err(err) => warn!(error = %err, "runtime env unreadable; starting without it"),
        }
        for name in LOOPBACK_HOST_VARS {
            cmd.env(name, "127.0.0.1");
        }

        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let release_id = manifest.release_id.clone();
        let slot_name = slot.as_str().to_string();

        {
            let rt_arc = self.runtime(slot);
            let mut rt = rt_arc.lock().await;
            if self.is_shutting_down() {
                drop(rt);
                stop_child_group(child, self.config.child_term_grace).await;
                return Err(cite_core::Error::msg("executor is shutting down"));
            }
            rt.child = Some(child);
            rt.release_id = Some(release_id.clone());
            rt.started_at = Some(Instant::now());
            if !keep_crashes {
                rt.crashes.clear();
            }
        }

        let sink = self.runtime(slot);
        let redactor = self.redactor.clone();
        if let Some(out) = stdout {
            let sink = sink.clone();
            let redactor = redactor.clone();
            let slot_name = slot_name.clone();
            let release_id = release_id.clone();
            tokio::spawn(async move {
                pump_lines(out, "out", slot_name, release_id, redactor, sink).await;
            });
        }
        if let Some(err) = stderr {
            let sink = sink.clone();
            let redactor = redactor.clone();
            tokio::spawn(async move {
                pump_lines(err, "err", slot_name, release_id, redactor, sink).await;
            });
        }

        Ok(())
    }

    pub async fn poll_exit(&self, slot: Slot) -> Option<String> {
        let rt_arc = self.runtime(slot);
        let mut rt = rt_arc.lock().await;
        let child = rt.child.as_mut()?;
        let group = child.id();
        match child.try_wait() {
            Ok(Some(status)) => {
                rt.child = None;
                signal_group(group, rustix::process::Signal::KILL);
                let reason = format!("child exited with {status}");
                rt.push_log(reason.clone());
                rt.crashes.push_back(Instant::now());
                trim_crashes(&mut rt.crashes, self.config.crash_window);
                Some(reason)
            }
            Ok(None) => None,
            Err(err) => {
                rt.child = None;
                signal_group(group, rustix::process::Signal::KILL);
                let reason = format!("child exit status lost: {err}");
                rt.push_log(reason.clone());
                rt.crashes.push_back(Instant::now());
                trim_crashes(&mut rt.crashes, self.config.crash_window);
                Some(reason)
            }
        }
    }

    pub async fn crash_count_in_window(&self, slot: Slot) -> u32 {
        let rt_arc = self.runtime(slot);
        let mut rt = rt_arc.lock().await;
        trim_crashes(&mut rt.crashes, self.config.crash_window);
        u32::try_from(rt.crashes.len()).unwrap_or(u32::MAX)
    }

    #[allow(dead_code)]
    pub async fn started_at(&self, slot: Slot) -> Option<Instant> {
        self.runtime(slot).lock().await.started_at
    }

    pub fn app_root(&self, slot: Slot) -> PathBuf {
        self.config.slot_dir(slot).join("app")
    }

    pub fn backoff_delay(slot_crashes: u32) -> Duration {
        let exp = slot_crashes.min(6);
        let base = Duration::from_millis(200);
        let max = Duration::from_secs(30);
        base.saturating_mul(2u32.saturating_pow(exp)).min(max)
    }
}

fn signal_group(leader: Option<u32>, signal: rustix::process::Signal) {
    if let Some(id) = leader
        && let Ok(raw) = i32::try_from(id)
        && let Some(pgid) = rustix::process::Pid::from_raw(raw)
    {
        let _ = rustix::process::kill_process_group(pgid, signal);
    }
}

async fn stop_child_group(mut child: Child, grace: Duration) {
    let group = child.id();
    signal_group(group, rustix::process::Signal::TERM);
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        let _ = child.kill().await;
    }
    signal_group(group, rustix::process::Signal::KILL);
    let _ = child.wait().await;
}

pub(crate) fn child_log_line(
    line: &str,
    stream: &str,
    slot_name: &str,
    release_id: &str,
    redactor: &Redactor,
) -> String {
    let redacted = redactor.redact_line(line);
    format!("[{slot_name}/{release_id}] {stream}: {redacted}")
}

async fn pump_lines<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    stream: &str,
    slot_name: String,
    release_id: String,
    redactor: Redactor,
    sink: Arc<Mutex<SlotRuntime>>,
) {
    let mut reader = BufReader::new(reader);
    while let Ok(Some(line)) = next_log_line(&mut reader).await {
        let prefixed = child_log_line(&line, stream, &slot_name, &release_id, &redactor);
        info!(target: "cite_executor::child", "{prefixed}");
        {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{prefixed}");
        }
        sink.lock().await.push_log(prefixed);
    }
}

async fn next_log_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<String>> {
    let mut line = Vec::new();
    let mut saw_any = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(saw_any.then(|| lossy_line(&line)));
        }
        saw_any = true;
        let newline = chunk.iter().position(|&b| b == b'\n');
        let take = newline.unwrap_or(chunk.len());
        let room = LOG_LINE_MAX.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..take.min(room)]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(lossy_line(&line)));
        }
    }
}

fn lossy_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\r')
        .to_string()
}

fn trim_crashes(crashes: &mut VecDeque<Instant>, window: Duration) {
    let now = Instant::now();
    while crashes
        .front()
        .is_some_and(|t| now.duration_since(*t) > window)
    {
        crashes.pop_front();
    }
}

fn resolve_argv(
    config: &ExecutorConfig,
    app_dir: &Path,
    argv: &[String],
) -> Result<(PathBuf, Vec<String>)> {
    if argv.is_empty() {
        return Err(cite_core::Error::msg("empty start_argv"));
    }
    if config.runtime == RuntimeKind::Rust {
        return resolve_rust_argv(app_dir, argv);
    }
    let argv0 = argv[0].as_str();
    match argv0 {
        "node" => Ok((PathBuf::from(&config.node_bin), argv[1..].to_vec())),
        "bun" => Ok((PathBuf::from(&config.bun_bin), argv[1..].to_vec())),
        other => {
            let bin = app_dir.join("node_modules").join(".bin").join(other);
            if !bin.is_file() {
                return Err(cite_core::Error::msg(format!(
                    "start binary `{other}` not found under node_modules/.bin"
                )));
            }
            let interpreter = match config.runtime {
                RuntimeKind::Bun => PathBuf::from(&config.bun_bin),
                _ => PathBuf::from(&config.node_bin),
            };
            let mut args = vec![bin.to_string_lossy().into_owned()];
            args.extend(argv[1..].iter().cloned());
            Ok((interpreter, args))
        }
    }
}

fn resolve_rust_argv(app_dir: &Path, argv: &[String]) -> Result<(PathBuf, Vec<String>)> {
    let argv0 = argv[0].as_str();
    let rel = Path::new(argv0);
    if argv0.is_empty()
        || rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(cite_core::Error::msg(format!(
            "rust start path `{argv0}` must stay inside the app directory"
        )));
    }
    let program = app_dir.join(rel);
    if !program.is_file() {
        return Err(cite_core::Error::msg(format!(
            "rust start binary `{}` not found",
            program.display()
        )));
    }
    Ok((program, argv[1..].to_vec()))
}

pub async fn probe_http_health(
    port: u16,
    path: &str,
    expect: HealthExpect,
    limit: Duration,
) -> bool {
    tokio::time::timeout(limit, probe_once(port, path, expect))
        .await
        .unwrap_or(false)
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn probe_once(port: u16, path: &str, expect: HealthExpect) -> bool {
    let url_path = if path.is_empty() { "/" } else { path };
    let addr = format!("127.0.0.1:{port}");
    let Ok(stream) = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    else {
        return false;
    };
    let Ok(stream) = stream else {
        return false;
    };
    let io = hyper_util::rt::TokioIo::new(stream);
    let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(io).await else {
        return false;
    };
    let _conn_guard = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let Ok(req) = Request::builder()
        .method("GET")
        .uri(url_path)
        .header("host", format!("127.0.0.1:{port}"))
        .body(http_body_util::Empty::<Bytes>::new())
    else {
        return false;
    };
    let Ok(res) = sender.send_request(req).await else {
        return false;
    };
    let status = res.status().as_u16();
    match expect {
        HealthExpect::Non2xxOk => status < 500,
        HealthExpect::TwoXx => (200..300).contains(&status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_log_escapes_terminal_control_characters() {
        let mut rt = SlotRuntime::new();
        rt.push_log("a\u{1b}[31mred\u{7}\tb".into());
        let line = rt.log_tail().pop().unwrap();
        assert!(!line.contains('\u{1b}') && !line.contains('\u{7}'));
        assert!(line.contains('\t'));
        assert!(line.contains("\\u{1b}[31m"));
    }

    #[test]
    fn push_log_truncates_on_a_char_boundary() {
        let mut rt = SlotRuntime::new();
        rt.push_log("あ".repeat(600));
        let line = rt.log_tail().pop().unwrap();
        assert!(line.len() <= LOG_LINE_MAX);
        assert!(line.chars().all(|c| c == 'あ'));
    }

    #[tokio::test]
    async fn log_reader_survives_invalid_utf8_and_caps_long_lines() {
        let mut input: Vec<u8> = b"ok\n\xff\xfe bad\r\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', LOG_LINE_MAX * 3));
        input.extend_from_slice(b"\nlast");
        let mut reader = BufReader::new(input.as_slice());
        assert_eq!(next_log_line(&mut reader).await.unwrap().unwrap(), "ok");
        assert_eq!(
            next_log_line(&mut reader).await.unwrap().unwrap(),
            "\u{fffd}\u{fffd} bad"
        );
        assert_eq!(
            next_log_line(&mut reader).await.unwrap().unwrap().len(),
            LOG_LINE_MAX
        );
        assert_eq!(next_log_line(&mut reader).await.unwrap().unwrap(), "last");
        assert!(next_log_line(&mut reader).await.unwrap().is_none());
    }

    fn rust_config(releases: &Path, port: u16) -> ExecutorConfig {
        let mut env = std::collections::HashMap::new();
        env.insert("CITE_RUNTIME".into(), "rust".into());
        env.insert("CITE_RELEASES_DIR".into(), releases.display().to_string());
        env.insert("CITE_DATA_DIR".into(), releases.display().to_string());
        env.insert("CITE_PORT_BASE".into(), port.to_string());
        env.insert("CITE_LISTEN".into(), "127.0.0.1:0".into());
        env.insert("CITE_NODE".into(), "22".into());
        ExecutorConfig::load_from(&env, None).unwrap()
    }

    fn rust_manifest(node_major: &str) -> ReleaseManifest {
        ReleaseManifest {
            v: cite_core::SCHEMA_VERSION,
            release_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            slot: Slot::Blue,
            sha: "a".repeat(40),
            branch: "main".into(),
            commit_message: "hi".into(),
            commit_author: "dev".into(),
            built_at: "2026-01-01T00:00:00Z".into(),
            rendering: Rendering::Ssr,
            runtime: RuntimeKind::Rust,
            node_major: node_major.into(),
            start_argv: vec!["bin/hello".into()],
            port_env: "PORT".into(),
            health: cite_core::Health {
                path: "/".into(),
                expect: HealthExpect::TwoXx,
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
    fn rust_resolve_argv_points_at_the_app_binary() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        std::fs::create_dir_all(app.join("bin")).unwrap();
        std::fs::write(app.join("bin/my-app"), b"x").unwrap();
        let cfg = rust_config(dir.path(), 21_001);
        let (program, args) =
            resolve_argv(&cfg, &app, &["bin/my-app".into(), "--flag".into()]).unwrap();
        assert_eq!(program, app.join("bin/my-app"));
        assert_eq!(args, ["--flag"]);
        assert!(resolve_argv(&cfg, &app, &["../bin/my-app".into()]).is_err());
        assert!(resolve_argv(&cfg, &app, &[String::new()]).is_err());
        assert!(resolve_argv(&cfg, &app, &["/bin/my-app".into()]).is_err());
    }

    #[test]
    fn rust_image_skips_node_major_and_static_still_rejects_ssr() {
        let dir = tempfile::tempdir().unwrap();
        let rust = SlotManager::new(rust_config(dir.path(), 21_002), Redactor::new());
        assert!(rust.check_release(&rust_manifest("18")).is_ok());
        let mut node = rust_manifest("22");
        node.runtime = RuntimeKind::Node;
        assert!(
            rust.check_release(&node)
                .unwrap_err()
                .contains("does not match")
        );

        let mut env = std::collections::HashMap::new();
        env.insert("CITE_RUNTIME".into(), "static".into());
        env.insert("CITE_PORT_BASE".into(), "21003".into());
        env.insert("CITE_LISTEN".into(), "127.0.0.1:0".into());
        let static_mgr = SlotManager::new(
            ExecutorConfig::load_from(&env, None).unwrap(),
            Redactor::new(),
        );
        let err = static_mgr.check_release(&rust_manifest("22")).unwrap_err();
        assert!(err.contains("static runtime"), "{err}");
    }

    #[tokio::test]
    async fn rust_child_answers_probe_http_health() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/runtime-rust");
        let target = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "--release",
                "--locked",
                "--offline",
                "--manifest-path",
            ])
            .arg(fixture.join("Cargo.toml"))
            .env("CARGO_TARGET_DIR", target.path())
            .status()
            .expect("cargo");
        assert!(status.success(), "cargo build failed: {status}");
        let built = target.path().join("release/hello");
        let data = tempfile::tempdir().unwrap();
        let bin_dir = data.path().join("releases/blue/app/bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let dest = bin_dir.join("hello");
        std::fs::copy(&built, &dest).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let cfg = rust_config(&data.path().join("releases"), port);
        let mgr = SlotManager::new(cfg, Redactor::new());
        mgr.start_ssr(Slot::Blue, &rust_manifest("18"))
            .await
            .expect("start rust child");
        let mut ok = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if probe_http_health(port, "/", HealthExpect::TwoXx, Duration::from_secs(1)).await {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut body = Vec::new();
        let _ = stream.read_to_end(&mut body);
        mgr.shutdown_all().await;
        assert!(ok, "probe_http_health did not see HTTP 200");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("rust-ok true"), "{text}");
    }
}
