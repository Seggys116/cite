//! Build job helpers and privileged-helper invocation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use cite_core::schema::{Health, ReleaseManifest, Rendering, Slot};
use cite_core::{
    Detection, ExtractLimits, ManagerConfig, PackLimits, Redactor, RenderingSetting, RuntimeKind,
    detect_site, extract_archive, hash_tree, new_id, now_rfc3339, pack_dir, split_command,
    validate_start_argv,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{ManagerError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJob {
    pub job_id: String,
    pub src: PathBuf,
    pub home: PathBuf,
    pub out: PathBuf,
    pub install_command: String,
    pub build_command: String,
    pub prune_command: Option<String>,
    pub env: HashMap<String, String>,
    pub cache_dir: Option<PathBuf>,
    pub timeout_s: u64,
}

#[derive(Debug, Clone)]
pub struct BuiltRelease {
    pub release_id: String,
    pub sha: String,
    pub message: String,
    pub author: String,
    pub rendering: Rendering,
    pub runtime: RuntimeKind,
    pub node_major: String,
    pub start_argv: Vec<String>,
    pub spa_fallback: Option<String>,
    pub bytes: u64,
    pub file_count: u64,
    pub tree_sha256: String,
    pub health: Health,
    pub tar_path: PathBuf,
    pub job_dir: PathBuf,
}

/// Resolve detection + operator overrides into concrete build commands.
pub fn resolve_site(cfg: &ManagerConfig, src_root: &Path) -> Result<(Detection, Rendering)> {
    let site_root = if cfg.root_dir == "." {
        src_root.to_path_buf()
    } else {
        src_root.join(&cfg.root_dir)
    };
    let mut det = detect_site(&site_root).map_err(|err| {
        let msg = err.to_string();
        if msg.contains("ambiguous") || msg.contains("CITE_RENDERING") {
            ManagerError::new(format!("{msg} (set CITE_RENDERING)"))
        } else {
            ManagerError::from(err)
        }
    })?;

    if cfg.framework != "auto" {
        det.framework = cfg.framework.clone();
    }
    if cfg.package_manager != "auto" {
        det.package_manager = cfg.package_manager.clone();
    }
    if let Some(cmd) = &cfg.install_command {
        det.install_command = cmd.clone();
    }
    if let Some(cmd) = &cfg.build_command {
        det.build_command = cmd.clone();
    }
    if let Some(dir) = &cfg.output_dir {
        det.output_dir = dir.clone();
        det.pack_output_only = true;
    }
    if let Some(cmd) = &cfg.start_command {
        let argv = split_command(cmd)?;
        validate_start_argv(&argv)?;
        det.start_argv = argv;
        det.pack_output_only = false;
    }
    if let Some(spa) = &cfg.spa_fallback {
        det.spa_fallback = Some(spa.clone());
    }

    let rendering = match cfg.rendering {
        RenderingSetting::Auto => det.rendering,
        RenderingSetting::Static => {
            det.rendering = Rendering::Static;
            det.pack_output_only = true;
            Rendering::Static
        }
        RenderingSetting::Ssr => {
            det.rendering = Rendering::Ssr;
            det.pack_output_only = false;
            Rendering::Ssr
        }
    };

    if let Some(detected) = &det.node_major
        && detected != &cfg.node_major
    {
        return Err(ManagerError::new(format!(
            "site requires Node {detected} but this stack is CITE_NODE={} — set CITE_NODE to match",
            cfg.node_major
        )));
    }

    Ok((det, rendering))
}

pub fn cache_env(cache_dir: &Path) -> HashMap<String, String> {
    HashMap::from([
        (
            "npm_config_cache".into(),
            cache_dir.join("npm").display().to_string(),
        ),
        (
            "PNPM_STORE_PATH".into(),
            cache_dir.join("pnpm").display().to_string(),
        ),
        (
            "BUN_INSTALL_CACHE_DIR".into(),
            cache_dir.join("bun").display().to_string(),
        ),
    ])
}

pub fn prune_command(pm: &str, rendering: Rendering, prune: Option<bool>) -> Option<String> {
    let should = match prune {
        Some(true) => true,
        Some(false) => false,
        None => rendering == Rendering::Ssr,
    };
    if !should {
        return None;
    }
    match pm {
        "pnpm" => Some("pnpm prune --prod".into()),
        "bun" => None,
        _ => Some("npm prune --omit=dev".into()),
    }
}

/// `node x.js` / `bun x.js` need the script; any other program runs from `node_modules/.bin`, so its arguments are not paths.
fn start_target_problem(site_src: &Path, argv: &[String]) -> Option<String> {
    let program = argv.first()?;
    match program.as_str() {
        "node" | "bun" => {
            let script = argv.get(1)?;
            (!site_src.join(script).exists()).then(|| format!("SSR start target missing: {script}"))
        }
        name => (!site_src.join("node_modules/.bin").join(name).exists()).then(|| {
            format!(
                "SSR start binary missing: node_modules/.bin/{name} (is it a devDependency removed by the production prune? set CITE_PRUNE=false or use a node start command)"
            )
        }),
    }
}

pub fn load_build_env(cfg: &ManagerConfig) -> Result<HashMap<String, String>> {
    Ok(cfg.build_env.resolve()?.into_iter().collect())
}

pub fn make_redactor(token: &str, build_env: &HashMap<String, String>) -> Redactor {
    let mut redactor = Redactor::new();
    redactor.push_secret(token);
    for value in build_env.values() {
        redactor.push_secret(value.clone());
    }
    redactor
}

/// Whether retrying the same commit could succeed: transient failures must not mark the sha as failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildFailure {
    /// The source itself is at fault (install, build, pack, validation, limits, node mismatch).
    Permanent(String),
    /// The environment is at fault (free space, build env I/O, shutdown abort, internal I/O).
    Transient(String),
}

impl BuildFailure {
    pub fn permanent(err: impl std::fmt::Display) -> Self {
        Self::Permanent(err.to_string())
    }

    pub fn transient(err: impl std::fmt::Display) -> Self {
        Self::Transient(err.to_string())
    }

    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Permanent(msg) | Self::Transient(msg) => msg,
        }
    }
}

impl std::fmt::Display for BuildFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for BuildFailure {}

impl From<BuildFailure> for ManagerError {
    fn from(value: BuildFailure) -> Self {
        ManagerError::new(value.message())
    }
}

impl From<ManagerError> for BuildFailure {
    fn from(value: ManagerError) -> Self {
        Self::Transient(value.to_string())
    }
}

impl From<std::io::Error> for BuildFailure {
    fn from(value: std::io::Error) -> Self {
        Self::Transient(value.to_string())
    }
}

impl From<serde_json::Error> for BuildFailure {
    fn from(value: serde_json::Error) -> Self {
        Self::Transient(value.to_string())
    }
}

type BuildResult<T> = std::result::Result<T, BuildFailure>;

/// Extract tarball, run install/build, preflight-pack for promote.
pub async fn run_build(
    cfg: &ManagerConfig,
    tarball: &[u8],
    sha: &str,
    message: &str,
    author: &str,
    redactor: &Redactor,
) -> Result<BuiltRelease> {
    run_build_classified(cfg, tarball, sha, message, author, redactor)
        .await
        .map_err(ManagerError::from)
}

/// Same as `run_build`, but the error says whether the failure is transient.
pub async fn run_build_classified(
    cfg: &ManagerConfig,
    tarball: &[u8],
    sha: &str,
    message: &str,
    author: &str,
    redactor: &Redactor,
) -> BuildResult<BuiltRelease> {
    let free = cite_core::filesystem_free_bytes(&cfg.work_dir).map_err(BuildFailure::transient)?;
    if free < cfg.min_free_bytes {
        return Err(BuildFailure::transient(format!(
            "filesystem free bytes {free} < CITE_MIN_FREE_BYTES {}",
            cfg.min_free_bytes
        )));
    }

    let job_id = new_id();
    let job_dir = cfg.work_dir.join(format!("job-{job_id}"));
    for sub in ["src", "home", "out"] {
        std::fs::create_dir_all(job_dir.join(sub))?;
    }

    match build_in_job(
        cfg, tarball, sha, message, author, redactor, &job_id, &job_dir,
    )
    .await
    {
        Ok(built) => Ok(built),
        Err(err) => {
            let _ = cleanup_job(cfg, &job_dir);
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_in_job(
    cfg: &ManagerConfig,
    tarball: &[u8],
    sha: &str,
    message: &str,
    author: &str,
    redactor: &Redactor,
    job_id: &str,
    job_dir: &Path,
) -> BuildResult<BuiltRelease> {
    let src = job_dir.join("src");
    let home = job_dir.join("home");
    let out = job_dir.join("out");

    let limits = ExtractLimits {
        max_compressed_bytes: cfg.max_source_compressed_bytes,
        max_extracted_bytes: cfg.max_source_bytes,
        max_entries: cfg.max_entries,
        max_file_bytes: cfg.max_source_bytes,
    };
    extract_archive(std::io::Cursor::new(tarball), &src, &limits, 1)
        .map_err(BuildFailure::permanent)?;

    if dir_size(job_dir)? > cfg.max_work_bytes {
        return Err(BuildFailure::permanent(
            "work tree exceeded CITE_MAX_WORK_BYTES during extract",
        ));
    }

    let (det, rendering) = resolve_site(cfg, &src).map_err(BuildFailure::permanent)?;

    let build_env = load_build_env(cfg)?;
    let mut env = build_env;
    env.insert("HOME".into(), home.display().to_string());
    env.insert("TMPDIR".into(), home.display().to_string());
    env.insert("TMP".into(), home.display().to_string());
    env.insert("TEMP".into(), home.display().to_string());
    env.insert(
        "PATH".into(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
    );
    if cfg.build_cache {
        prepare_cache(cfg)?;
        env.extend(cache_env(&cfg.cache_dir));
    }

    let site_src = if cfg.root_dir == "." {
        src.clone()
    } else {
        src.join(&cfg.root_dir)
    };

    let job = BuildJob {
        job_id: job_id.to_string(),
        src: site_src.clone(),
        home: home.clone(),
        out: out.clone(),
        install_command: det.install_command.clone(),
        build_command: det.build_command.clone(),
        prune_command: prune_command(&det.package_manager, rendering, cfg.prune),
        env,
        cache_dir: cfg.build_cache.then(|| cfg.cache_dir.clone()),
        timeout_s: cfg.build_timeout.as_secs().max(1),
    };

    execute_build(cfg, &job, redactor).await?;

    if dir_size(job_dir)? > cfg.max_work_bytes {
        return Err(BuildFailure::permanent(
            "work tree exceeded CITE_MAX_WORK_BYTES after build",
        ));
    }

    let pack_root = if det.pack_output_only || rendering == Rendering::Static {
        let root = site_src.join(&det.output_dir);
        if !root.is_dir() {
            return Err(BuildFailure::permanent(format!(
                "static output_dir missing: {}",
                root.display()
            )));
        }
        if cfg.spa_fallback.is_none()
            && det.spa_fallback.is_none()
            && !root.join("index.html").is_file()
        {
            return Err(BuildFailure::permanent(
                "static release requires index.html (or set CITE_SPA_FALLBACK)",
            ));
        }
        root
    } else {
        if det.start_argv.is_empty() {
            return Err(BuildFailure::permanent(
                "SSR release requires a start command; set CITE_START_COMMAND",
            ));
        }
        if let Some(problem) = start_target_problem(&site_src, &det.start_argv) {
            return Err(BuildFailure::permanent(problem));
        }
        site_src
    };

    let tar_path = out.join("release.tar");
    let pack_limits = PackLimits {
        max_bytes: cfg.max_release_bytes,
        max_files: cfg.max_entries,
    };
    pack_release(cfg, &pack_root, &tar_path, &pack_limits, redactor).await?;
    let report = hash_tree(&pack_root).map_err(BuildFailure::permanent)?;
    if report.bytes > cfg.max_release_bytes {
        return Err(BuildFailure::permanent(
            "release exceeds CITE_MAX_RELEASE_BYTES",
        ));
    }

    Ok(BuiltRelease {
        release_id: new_id(),
        sha: sha.to_string(),
        message: message.to_string(),
        author: author.to_string(),
        rendering,
        runtime: cfg.runtime,
        node_major: cfg.node_major.clone(),
        start_argv: det.start_argv,
        spa_fallback: det.spa_fallback.or_else(|| cfg.spa_fallback.clone()),
        bytes: report.bytes,
        file_count: report.file_count,
        tree_sha256: report.tree_sha256,
        health: Health {
            path: cfg.health_path.clone(),
            expect: cfg.health_expect,
            timeout_s: cfg.health_timeout.as_secs().max(1),
            consecutive: cfg.health_consecutive,
        },
        tar_path,
        job_dir: job_dir.to_path_buf(),
    })
}

async fn execute_build(
    cfg: &ManagerConfig,
    job: &BuildJob,
    redactor: &Redactor,
) -> BuildResult<()> {
    let job_json_path = job.out.join("job.json");
    std::fs::write(&job_json_path, serde_json::to_vec(job)?)?;

    let ids = build_ids(cfg)?;
    if let Some((uid, gid)) = ids {
        // `out/` stays root-owned so the manager can create the pack tar without CAP_DAC_OVERRIDE.
        let job_dir = job.home.parent().unwrap_or(job.home.as_path());
        // umask 027 leaves these 0750 root:root; the build user must traverse them.
        allow_traverse(job_dir)?;
        allow_traverse(&job.out)?;
        give_tree(&job.src, uid, gid)?;
        give_tree(&job.home, uid, gid)?;
        std::os::unix::fs::lchown(&job_json_path, Some(uid), Some(gid))
            .map_err(|err| BuildFailure::transient(format!("chown job.json: {err}")))?;
        return run_helper_async(
            cfg,
            "__build",
            job_json_path,
            Some((uid, gid)),
            job.timeout_s,
            redactor,
            None,
        )
        .await;
    }

    // In-process so a test harness current_exe need not understand `__build`.
    let path = job_json_path.clone();
    let timeout = Duration::from_secs(job.timeout_s);
    let handle = tokio::task::spawn_blocking(move || run_build_steps(&path));
    match tokio::time::timeout(timeout, handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => Err(BuildFailure::transient(format!("build join: {err}"))),
        Err(_) => {
            // Best-effort: blocking task may still finish; surface timeout to caller.
            Err(BuildFailure::permanent("build timed out"))
        }
    }
}

async fn pack_release(
    cfg: &ManagerConfig,
    pack_root: &Path,
    tar_path: &Path,
    limits: &PackLimits,
    redactor: &Redactor,
) -> BuildResult<()> {
    if let Some(ids) = build_ids(cfg)? {
        return run_helper_async(
            cfg,
            "__pack",
            pack_root.to_path_buf(),
            Some(ids),
            120,
            redactor,
            Some(tar_path.to_path_buf()),
        )
        .await;
    }
    let file = std::fs::File::create(tar_path)?;
    pack_dir(pack_root, file, limits).map_err(BuildFailure::permanent)?;
    Ok(())
}

async fn run_helper_async(
    cfg: &ManagerConfig,
    helper: &'static str,
    arg: PathBuf,
    ids: Option<(u32, u32)>,
    timeout_s: u64,
    redactor: &Redactor,
    stdout_path: Option<PathBuf>,
) -> BuildResult<()> {
    let cfg = cfg.clone();
    let redactor = redactor.clone();
    tokio::task::spawn_blocking(move || {
        run_helper_process(
            &cfg,
            helper,
            &arg,
            ids,
            timeout_s,
            &redactor,
            stdout_path.as_deref(),
        )
    })
    .await
    .map_err(|err| BuildFailure::transient(format!("{helper} join: {err}")))?
}

/// Runs a synchronous closure without stalling a multi-thread runtime worker.
fn blocking_section<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

struct HelperRegistration;

impl HelperRegistration {
    fn new(pid: u32, ids: Option<(u32, u32)>) -> Self {
        let (uid, gid) = ids.unwrap_or((NO_ID, NO_ID));
        HELPER_UID.store(uid, std::sync::atomic::Ordering::SeqCst);
        HELPER_GID.store(gid, std::sync::atomic::Ordering::SeqCst);
        HELPER_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for HelperRegistration {
    fn drop(&mut self) {
        HELPER_PID.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

fn run_helper_process(
    _cfg: &ManagerConfig,
    helper: &str,
    arg: &Path,
    ids: Option<(u32, u32)>,
    timeout_s: u64,
    redactor: &Redactor,
    stdout_path: Option<&Path>,
) -> BuildResult<()> {
    let abortable = helper != "__clean";
    let exe = std::env::current_exe().map_err(|err| ManagerError::new(err.to_string()))?;
    let mut cmd = Command::new(&exe);
    cmd.arg(helper).arg(arg);
    if let Some(path) = stdout_path {
        let file = std::fs::File::create(path)?;
        cmd.stdout(Stdio::from(file)).stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    cmd.stdin(Stdio::null());
    apply_helper_env(&mut cmd);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if let Some((uid, gid)) = ids {
            cmd.uid(uid).gid(gid);
        }
    }

    if abortable && BUILD_ABORT.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(BuildFailure::transient(format!("{helper} aborted")));
    }
    let mut child = cmd.spawn()?;
    let registration = abortable.then(|| HelperRegistration::new(child.id(), ids));
    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_s);
    let stdout = if stdout_path.is_none() {
        child.stdout.take()
    } else {
        None
    };
    let stderr = child.stderr.take();
    let out_done = spawn_line_reader(stdout, redactor.clone(), false);
    let err_done = spawn_line_reader(stderr, redactor.clone(), true);

    let mut result = loop {
        match child.try_wait()? {
            Some(status) => {
                break if status.success() {
                    Ok(())
                } else {
                    Err(BuildFailure::permanent(format!(
                        "{helper} exited with {status}"
                    )))
                };
            }
            None if started.elapsed() > timeout => {
                terminate_child(&mut child, ids);
                break Err(BuildFailure::permanent(format!("{helper} timed out")));
            }
            None if abortable && BUILD_ABORT.load(std::sync::atomic::Ordering::SeqCst) => {
                terminate_child(&mut child, ids);
                break Err(BuildFailure::transient(format!("{helper} aborted")));
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    // A background process left by the build can hold the pipes open, so it is swept before the readers are awaited.
    if abortable
        && let Some((uid, gid)) = ids
        && !sweep_build_uid(uid, gid)
        && result.is_ok()
    {
        result = Err(BuildFailure::transient(format!(
            "{helper} left processes running that could not be stopped"
        )));
    }
    let _ = out_done.recv_timeout(READER_DRAIN_TIMEOUT);
    let _ = err_done.recv_timeout(READER_DRAIN_TIMEOUT);
    drop(registration);
    result
}

const READER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest log line kept; the rest of an over-long line is read and discarded.
const MAX_LOG_LINE: usize = 16 * 1024;

/// Reads to EOF without ever buffering more than `cap` bytes per line, decoding lossily so odd bytes never end the drain.
fn for_each_line<R: std::io::BufRead>(mut reader: R, cap: usize, mut on_line: impl FnMut(&str)) {
    let mut line: Vec<u8> = Vec::new();
    let mut pending = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if chunk.is_empty() {
            break;
        }
        let newline = chunk.iter().position(|b| *b == b'\n');
        let end = newline.unwrap_or(chunk.len());
        let room = cap.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..end.min(room)]);
        pending = true;
        let consumed = newline.map_or(chunk.len(), |at| at + 1);
        reader.consume(consumed);
        if newline.is_some() {
            on_line(String::from_utf8_lossy(&line).trim_end_matches('\r'));
            line.clear();
            pending = false;
        }
    }
    if pending {
        on_line(String::from_utf8_lossy(&line).trim_end_matches('\r'));
    }
}

/// The returned channel yields once the stream hits EOF, letting the caller bound how long it waits.
fn spawn_line_reader<R: std::io::Read + Send + 'static>(
    stream: Option<R>,
    redactor: Redactor,
    is_stderr: bool,
) -> std::sync::mpsc::Receiver<()> {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Some(stream) = stream {
            for_each_line(std::io::BufReader::new(stream), MAX_LOG_LINE, |line| {
                if is_stderr {
                    warn!(phase = "build", "{}", redactor.redact_line(line));
                } else {
                    info!(phase = "build", "{}", redactor.redact_line(line));
                }
            });
        }
        let _ = done.send(());
    });
    finished
}

/// The helper gets a minimal environment so the manager's secrets never reach the build uid.
fn apply_helper_env(cmd: &mut Command) {
    cmd.env_clear();
    cmd.env(
        "PATH",
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
    );
    cmd.env("HOME", "/tmp");
}

/// Runs the kill helper as the build uid (the manager lacks CAP_KILL); true only when the sweep helper ran and confirmed that no process of the build uid remains.
pub fn sweep_build_uid(uid: u32, gid: u32) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let mut cmd = Command::new(exe);
    cmd.arg("__clean").arg("/tmp/cite-no-such-job");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_helper_env(&mut cmd);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.uid(uid).gid(gid);
    }
    let _ = (uid, gid);
    cmd.status().is_ok_and(|status| status.success())
}

fn terminate_child(child: &mut std::process::Child, ids: Option<(u32, u32)>) {
    #[cfg(unix)]
    {
        if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
        }
    }
    let grace_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < grace_deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    #[cfg(unix)]
    {
        if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
    let _ = child.kill();
    if child.try_wait().ok().flatten().is_none()
        && let Some((uid, gid)) = ids
    {
        sweep_build_uid(uid, gid);
    }
    let _ = child.wait();
}

pub fn cleanup_job(cfg: &ManagerConfig, job_dir: &Path) -> Result<()> {
    let ids = build_ids(cfg)?;
    let swept = match ids {
        Some(ids) => blocking_section(|| {
            run_helper_process(
                cfg,
                "__clean",
                job_dir,
                Some(ids),
                60,
                &Redactor::new(),
                None,
            )
        })
        .is_ok(),
        None => true,
    };
    if ids.is_some() && !swept {
        error!("build uid sweep failed; leaving the work tree for the next startup sweep");
        return Ok(());
    }
    wipe_work_swept(cfg)?;
    // The cache is only walked once no build-uid process can still be mutating it.
    if swept && cfg.build_cache {
        blocking_section(|| prune_cache_for(cfg));
    } else if cfg.build_cache {
        warn!("build uid sweep failed; skipping cache prune");
    }
    Ok(())
}

fn allow_traverse(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::symlink_metadata(path)?.permissions().mode();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o755))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn give_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let root = open_cache_root(path)?;
    chown_dir_handle(&root, (uid, gid), false)?;
    walk_cache(
        &root,
        CacheWalk::Chown {
            owner: (uid, gid),
            tighten: false,
            strict: true,
        },
        &mut Vec::new(),
    )
}

/// Sweeps the build uid first so no live build process can race the reclaim or the removal.
pub fn wipe_work(cfg: &ManagerConfig) -> Result<()> {
    if let Some((uid, gid)) = build_ids(cfg)?
        && !blocking_section(|| sweep_build_uid(uid, gid))
    {
        return Err(ManagerError::new(
            "build uid sweep failed; work tree left untouched",
        ));
    }
    wipe_work_swept(cfg)
}

fn wipe_work_swept(cfg: &ManagerConfig) -> Result<()> {
    // Root lacks DAC_OVERRIDE, so build-owned leftovers (e.g. after SIGKILL) must be chowned back before unlink.
    if let Ok(root) = open_cache_root(&cfg.work_dir) {
        let _ = walk_cache(
            &root,
            CacheWalk::Chown {
                owner: (0, 0),
                tighten: true,
                strict: false,
            },
            &mut Vec::new(),
        );
    }
    cite_core::sweep_dir(&cfg.work_dir)?;
    Ok(())
}

fn dir_size(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    if !path.exists() {
        return Ok(0);
    }
    for entry in walkdir(path)? {
        if let Ok(meta) = std::fs::symlink_metadata(&entry)
            && meta.is_file()
        {
            total = total.saturating_add(meta.len());
        }
    }
    Ok(total)
}

fn walkdir(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() && !ft.is_symlink() {
                stack.push(path.clone());
            }
            out.push(path);
        }
    }
    Ok(out)
}

fn drops_privileges(cfg: &ManagerConfig) -> bool {
    !cfg.dev_same_user && rustix::process::geteuid().is_root()
}

/// Identity builds run as, or None when this process keeps its own user; ids that would hand the build the manager's privileges are refused.
fn build_ids(cfg: &ManagerConfig) -> Result<Option<(u32, u32)>> {
    if !drops_privileges(cfg) {
        return Ok(None);
    }
    check_build_ids(
        cfg.build_uid,
        cfg.build_gid,
        rustix::process::geteuid().as_raw(),
    )
    .map(Some)
}

fn check_build_ids(uid: u32, gid: u32, euid: u32) -> Result<(u32, u32)> {
    if uid == 0 || gid == 0 || uid == euid {
        return Err(ManagerError::new(
            "CITE_BUILD_UID and CITE_BUILD_GID must be non-root and differ from the manager user",
        ));
    }
    Ok((uid, gid))
}

/// Creates the cache and hands it to the build uid; the manager holds CHOWN but not DAC_OVERRIDE, so root-owned directories would be unwritable to the build.
fn prepare_cache(cfg: &ManagerConfig) -> Result<()> {
    std::fs::create_dir_all(&cfg.cache_dir)?;
    let Some(owner) = build_ids(cfg)? else {
        return Ok(());
    };
    let root = open_cache_root(&cfg.cache_dir)?;
    let stat = rustix::fs::fstat(&root).map_err(io_error)?;
    if stat.st_uid != owner.0 || stat.st_gid != owner.1 {
        chown_dir_handle(&root, owner, false)?;
        walk_cache(
            &root,
            CacheWalk::Chown {
                owner,
                tighten: false,
                strict: true,
            },
            &mut Vec::new(),
        )?;
    }
    Ok(())
}

/// Prunes once no build process remains; an over-cap cache is reclaimed by root first, and prepare_cache hands it back on the next build.
fn prune_cache_for(cfg: &ManagerConfig) {
    if drops_privileges(cfg) {
        prune_cache_with(&cfg.cache_dir, cfg.cache_max_bytes, Some((0, 0)));
    } else {
        prune_cache(&cfg.cache_dir, cfg.cache_max_bytes);
    }
}

struct CacheFile {
    path: Vec<std::ffi::OsString>,
    mtime: i64,
    len: u64,
}

#[derive(Clone, Copy)]
enum CacheWalk {
    Measure,
    Chown {
        owner: (u32, u32),
        tighten: bool,
        strict: bool,
    },
}

/// Directory nesting beyond this is build-controlled and is removed instead of walked.
const MAX_CACHE_DEPTH: usize = 64;

fn io_error(err: rustix::io::Errno) -> ManagerError {
    ManagerError::new(err.to_string())
}

fn dir_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC
}

fn open_cache_root(path: &Path) -> Result<std::os::fd::OwnedFd> {
    rustix::fs::openat(
        rustix::fs::CWD,
        path,
        dir_flags(),
        rustix::fs::Mode::empty(),
    )
    .map_err(|err| ManagerError::new(format!("open dir {}: {err}", path.display())))
}

/// Tightening drops group and other write bits so a build-owned directory cannot stay writable by the build uid.
fn chown_dir_handle(root: &std::os::fd::OwnedFd, owner: (u32, u32), tighten: bool) -> Result<()> {
    rustix::fs::fchown(
        root,
        Some(rustix::fs::Uid::from_raw(owner.0)),
        Some(rustix::fs::Gid::from_raw(owner.1)),
    )
    .map_err(io_error)?;
    if tighten {
        tighten_dir(root)?;
    }
    Ok(())
}

fn tighten_dir(dir: &std::os::fd::OwnedFd) -> Result<()> {
    let mode = rustix::fs::fstat(dir).map_err(io_error)?.st_mode as rustix::fs::RawMode;
    let tightened = (mode & 0o7777 & !0o022) | 0o700;
    rustix::fs::fchmod(dir, rustix::fs::Mode::from_raw_mode(tightened)).map_err(io_error)
}

struct WalkFrame {
    fd: std::os::fd::OwnedFd,
    entries: rustix::fs::Dir,
}

impl WalkFrame {
    fn open(parent: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> Result<Self> {
        let fd = rustix::fs::openat(parent, name, dir_flags(), rustix::fs::Mode::empty())
            .map_err(io_error)?;
        Self::from_fd(fd)
    }

    fn from_fd(fd: std::os::fd::OwnedFd) -> Result<Self> {
        let entries = rustix::fs::Dir::read_from(&fd).map_err(io_error)?;
        Ok(Self { fd, entries })
    }
}

/// Iterative and relative to directory handles opened without following links, so a swapped-in symlink is never traversed and depth costs heap, not stack.
fn walk_cache(
    root: &std::os::fd::OwnedFd,
    mode: CacheWalk,
    files: &mut Vec<CacheFile>,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let strict = !matches!(mode, CacheWalk::Chown { strict: false, .. });
    let top =
        rustix::fs::openat(root, ".", dir_flags(), rustix::fs::Mode::empty()).map_err(io_error)?;
    let mut stack = vec![WalkFrame::from_fd(top)?];
    let mut prefix: Vec<std::ffi::OsString> = Vec::new();
    while let Some(frame) = stack.last_mut() {
        let Some(entry) = frame.entries.next() else {
            stack.pop();
            prefix.pop();
            continue;
        };
        let step = (|| -> Result<Option<(WalkFrame, std::ffi::OsString)>> {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                return Ok(None);
            }
            let os_name = std::ffi::OsStr::from_bytes(name.to_bytes()).to_owned();
            let stat = rustix::fs::statat(&frame.fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io_error)?;
            if let CacheWalk::Chown {
                owner: (uid, gid), ..
            } = mode
            {
                rustix::fs::chownat(
                    &frame.fd,
                    name,
                    Some(rustix::fs::Uid::from_raw(uid)),
                    Some(rustix::fs::Gid::from_raw(gid)),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(io_error)?;
            }
            match rustix::fs::FileType::from_raw_mode(stat.st_mode as rustix::fs::RawMode) {
                rustix::fs::FileType::Directory if stack_depth_exceeded(&prefix) => {
                    if let Err(err) = remove_subtree(&frame.fd, name) {
                        warn!(%err, "directory nesting over the cap could not be removed");
                    }
                    Ok(None)
                }
                rustix::fs::FileType::Directory => {
                    let child = WalkFrame::open(&frame.fd, name)?;
                    let opened = rustix::fs::fstat(&child.fd).map_err(io_error)?;
                    if opened.st_ino != stat.st_ino || opened.st_dev != stat.st_dev {
                        return Ok(None);
                    }
                    if let CacheWalk::Chown { tighten: true, .. } = mode {
                        tighten_dir(&child.fd)?;
                    }
                    Ok(Some((child, os_name)))
                }
                rustix::fs::FileType::RegularFile => {
                    let mut path = prefix.clone();
                    path.push(os_name);
                    files.push(CacheFile {
                        path,
                        mtime: stat.st_mtime as i64,
                        len: stat.st_size as u64,
                    });
                    Ok(None)
                }
                _ => Ok(None),
            }
        })();
        match step {
            Ok(Some((child, name))) => {
                prefix.push(name);
                stack.push(child);
            }
            Ok(None) => {}
            Err(err) if strict => return Err(err),
            Err(_) => {}
        }
    }
    Ok(())
}

/// Takes ownership and owner-write of a directory so its entries can be unlinked without DAC_OVERRIDE; failures surface when the unlink is attempted.
fn claim_dir(dir: &std::os::fd::OwnedFd) {
    let _ = rustix::fs::fchown(
        dir,
        Some(rustix::fs::Uid::from_raw(0)),
        Some(rustix::fs::Gid::from_raw(0)),
    );
    let _ = tighten_dir(dir);
}

fn dir_identity(dir: &std::os::fd::OwnedFd) -> Result<(u64, u64)> {
    let stat = rustix::fs::fstat(dir).map_err(io_error)?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

/// Removes a tree of any depth holding one directory handle at a time; it climbs back through `..`, which is safe once no build process can rearrange the tree.
fn remove_subtree(parent: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let mut cur = rustix::fs::openat(parent, name, dir_flags(), rustix::fs::Mode::empty())
        .map_err(io_error)?;
    let mut below: Vec<std::ffi::OsString> = Vec::new();
    let mut identity = vec![dir_identity(&cur)?];
    claim_dir(&cur);
    loop {
        let mut next = None;
        for entry in rustix::fs::Dir::read_from(&cur).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let child = entry.file_name();
            if child.to_bytes() != b"." && child.to_bytes() != b".." {
                next = Some(child.to_owned());
                break;
            }
        }
        match next {
            Some(child) => {
                let stat = rustix::fs::statat(
                    &cur,
                    child.as_c_str(),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(io_error)?;
                if rustix::fs::FileType::from_raw_mode(stat.st_mode as rustix::fs::RawMode)
                    == rustix::fs::FileType::Directory
                {
                    let down = rustix::fs::openat(
                        &cur,
                        child.as_c_str(),
                        dir_flags(),
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(io_error)?;
                    claim_dir(&down);
                    identity.push(dir_identity(&down)?);
                    below.push(std::ffi::OsStr::from_bytes(child.to_bytes()).to_owned());
                    cur = down;
                } else {
                    rustix::fs::unlinkat(&cur, child.as_c_str(), rustix::fs::AtFlags::empty())
                        .map_err(io_error)?;
                }
            }
            None => {
                let Some(dir_name) = below.pop() else {
                    return rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR)
                        .map_err(io_error);
                };
                let up = rustix::fs::openat(&cur, "..", dir_flags(), rustix::fs::Mode::empty())
                    .map_err(io_error)?;
                identity.pop();
                if identity.last() != Some(&dir_identity(&up)?) {
                    return Err(ManagerError::new(
                        "directory tree changed while it was being removed",
                    ));
                }
                rustix::fs::unlinkat(&up, dir_name.as_os_str(), rustix::fs::AtFlags::REMOVEDIR)
                    .map_err(io_error)?;
                cur = up;
            }
        }
    }
}

fn stack_depth_exceeded(prefix: &[std::ffi::OsString]) -> bool {
    prefix.len() >= MAX_CACHE_DEPTH
}

fn unlink_cache_file(root: &std::os::fd::OwnedFd, path: &[std::ffi::OsString]) -> Result<()> {
    use std::os::fd::AsFd;
    let Some((name, dirs)) = path.split_last() else {
        return Ok(());
    };
    let mut held: Option<std::os::fd::OwnedFd> = None;
    for part in dirs {
        let parent = held.as_ref().map_or(root.as_fd(), |fd| fd.as_fd());
        let next = rustix::fs::openat(parent, part, dir_flags(), rustix::fs::Mode::empty())
            .map_err(io_error)?;
        held = Some(next);
    }
    let parent = held.as_ref().map_or(root.as_fd(), |fd| fd.as_fd());
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty()).map_err(io_error)
}

fn prune_cache(cache_dir: &Path, max_bytes: u64) {
    prune_cache_with(cache_dir, max_bytes, None);
}

/// With `reclaim` set the tree is first chowned to that owner so the caller can unlink without DAC_OVERRIDE.
fn prune_cache_with(cache_dir: &Path, max_bytes: u64, reclaim: Option<(u32, u32)>) {
    let Ok(root) = open_cache_root(cache_dir) else {
        return;
    };
    let mut files = Vec::new();
    if let Err(err) = walk_cache(&root, CacheWalk::Measure, &mut files) {
        warn!(%err, "cache scan failed");
        return;
    }
    let mut remaining: u64 = files.iter().map(|f| f.len).sum();
    if remaining <= max_bytes {
        return;
    }
    if let Some(owner) = reclaim {
        files.clear();
        let walk = CacheWalk::Chown {
            owner,
            tighten: true,
            strict: true,
        };
        let reclaimed =
            chown_dir_handle(&root, owner, true).and_then(|()| walk_cache(&root, walk, &mut files));
        if let Err(err) = reclaimed {
            warn!(%err, "cache reclaim failed; skipping prune");
            return;
        }
    }
    files.sort_by_key(|f| f.mtime);
    for file in files {
        if remaining <= max_bytes {
            break;
        }
        if unlink_cache_file(&root, &file.path).is_ok() {
            remaining = remaining.saturating_sub(file.len);
        }
    }
}

/// Leaves the job directory in place so a caller can inspect output before `__clean`.
pub fn supervise_build_job(cfg: &ManagerConfig, job_json: &Path) -> Result<()> {
    let text = std::fs::read_to_string(job_json)?;
    let job: BuildJob = serde_json::from_str(&text)?;
    let ids = build_ids(cfg)?;
    run_helper_process(
        cfg,
        "__build",
        job_json,
        ids,
        job.timeout_s.max(1),
        &Redactor::new(),
        None,
    )
    .map_err(ManagerError::from)
}

pub fn run_build_helper(job_json: &Path) -> Result<()> {
    run_build_steps(job_json).map_err(ManagerError::from)
}

fn run_build_steps(job_json: &Path) -> BuildResult<()> {
    let text = std::fs::read_to_string(job_json)?;
    let job: BuildJob = serde_json::from_str(&text)?;
    run_shell(&job.install_command, "install", &job.env, &job.src)?;
    run_shell(&job.build_command, "build", &job.env, &job.src)?;
    if let Some(prune) = &job.prune_command {
        run_shell(prune, "prune", &job.env, &job.src)?;
    }
    Ok(())
}

static BUILD_ABORT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static BUILD_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static HELPER_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static HELPER_UID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(NO_ID);
static HELPER_GID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(NO_ID);
const NO_ID: u32 = u32::MAX;
static BUILD_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The caller removes the job directory (`run_build` / `wipe_work`).
pub fn abort_inflight_build() {
    use std::sync::atomic::Ordering;
    BUILD_ABORT.store(true, Ordering::SeqCst);
    let pid = BUILD_PID.load(Ordering::SeqCst);
    if pid != 0 {
        signal_pid(pid, Duration::from_millis(200));
    }
    let helper = HELPER_PID.load(Ordering::SeqCst);
    if helper != 0 {
        signal_pid(helper, Duration::from_millis(200));
        let uid = HELPER_UID.load(Ordering::SeqCst);
        let gid = HELPER_GID.load(Ordering::SeqCst);
        if uid != NO_ID && gid != NO_ID {
            sweep_build_uid(uid, gid);
        }
    }
}

fn signal_pid(pid: u32, grace: Duration) {
    #[cfg(unix)]
    {
        if let Some(raw) = rustix::process::Pid::from_raw(pid as i32) {
            let _ = rustix::process::kill_process_group(raw, rustix::process::Signal::TERM);
            std::thread::sleep(grace);
            let _ = rustix::process::kill_process_group(raw, rustix::process::Signal::KILL);
        }
    }
    let _ = (pid, grace);
}

/// A closed stdout must not abort the build, so write failures are ignored.
fn emit_event(event: &serde_json::Value) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout(), "{event}");
}

fn run_shell(
    command: &str,
    phase: &str,
    env: &HashMap<String, String>,
    cwd: &Path,
) -> BuildResult<()> {
    let _gate = BUILD_GATE.lock().unwrap_or_else(|err| err.into_inner());
    emit_event(&serde_json::json!({"phase": phase, "event": "start", "command": command}));
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    cmd.current_dir(cwd);
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    cmd.env_clear();
    cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    if BUILD_ABORT.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(BuildFailure::transient(format!("{phase} aborted")));
    }
    let mut child = cmd.spawn()?;
    BUILD_PID.store(child.id(), std::sync::atomic::Ordering::SeqCst);
    let status = loop {
        if BUILD_ABORT.load(std::sync::atomic::Ordering::SeqCst) {
            signal_pid(child.id(), Duration::from_millis(200));
            let _ = child.wait();
            BUILD_PID.store(0, std::sync::atomic::Ordering::SeqCst);
            return Err(BuildFailure::transient(format!("{phase} aborted")));
        }
        match child.try_wait()? {
            Some(status) => break status,
            None => std::thread::sleep(Duration::from_millis(30)),
        }
    };
    BUILD_PID.store(0, std::sync::atomic::Ordering::SeqCst);
    if status.success() {
        emit_event(&serde_json::json!({"phase": phase, "event": "ok"}));
        Ok(())
    } else {
        Err(BuildFailure::permanent(format!(
            "{phase} command failed with {status}"
        )))
    }
}

/// Manifest builder used after a successful promote extract.
pub fn release_manifest(built: &BuiltRelease, slot: Slot, branch: &str) -> ReleaseManifest {
    ReleaseManifest {
        v: cite_core::SCHEMA_VERSION,
        release_id: built.release_id.clone(),
        slot,
        sha: built.sha.clone(),
        branch: branch.to_string(),
        commit_message: built.message.clone(),
        commit_author: built.author.clone(),
        built_at: now_rfc3339(),
        rendering: built.rendering,
        runtime: built.runtime,
        node_major: built.node_major.clone(),
        start_argv: built.start_argv.clone(),
        port_env: "PORT".into(),
        health: built.health.clone(),
        spa_fallback: built.spa_fallback.clone(),
        root: "app".into(),
        bytes: built.bytes,
        file_count: built.file_count,
        tree_sha256: built.tree_sha256.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BuildJob, BuiltRelease, cache_env, give_tree, load_build_env, make_redactor, prune_cache,
        prune_command, release_manifest, resolve_site, run_build_helper, wipe_work,
    };
    use cite_core::ManagerConfig;
    use cite_core::schema::{Rendering, Slot};
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn give_tree_chowns_nested_files_and_stops_at_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("src");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("index.html"), b"v1").unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, nested.join("link")).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        give_tree(dir.path(), uid, gid).unwrap();
        let meta = std::fs::symlink_metadata(nested.join("index.html")).unwrap();
        assert_eq!(meta.len(), 2);
    }

    #[test]
    fn wipe_work_removes_a_leftover_job_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let job = work.join("job-left");
        std::fs::create_dir_all(job.join("src")).unwrap();
        std::fs::write(job.join("src/index.html"), b"v").unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_WORK_DIR".into(), work.display().to_string());
        env.insert("CITE_DEV_SAME_USER".into(), "true".into());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        wipe_work(&cfg).unwrap();
        let left: Vec<_> = std::fs::read_dir(&work)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        assert!(left.is_empty(), "startup sweep left {left:?}");
    }

    #[test]
    fn node_mismatch_tells_the_operator_which_cite_node_to_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"devDependencies":{"vite":"5.0.0"},"engines":{"node":"18"}}"#,
        )
        .unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_NODE".into(), "22".into());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let err = resolve_site(&cfg, dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CITE_NODE"), "{msg}");
        assert!(msg.contains("18"), "{msg}");
    }

    #[test]
    fn prune_command_follows_rendering_and_package_manager() {
        use cite_core::schema::Rendering;
        assert_eq!(
            prune_command("npm", Rendering::Ssr, None).as_deref(),
            Some("npm prune --omit=dev")
        );
        assert_eq!(
            prune_command("pnpm", Rendering::Ssr, None).as_deref(),
            Some("pnpm prune --prod")
        );
        assert_eq!(prune_command("bun", Rendering::Ssr, None), None);
        assert_eq!(prune_command("npm", Rendering::Static, None), None);
        assert_eq!(
            prune_command("npm", Rendering::Static, Some(true)).as_deref(),
            Some("npm prune --omit=dev")
        );
        assert_eq!(prune_command("npm", Rendering::Ssr, Some(false)), None);
    }

    #[test]
    fn cache_env_points_at_the_cache_volume_and_prune_drops_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let env = cache_env(dir.path());
        assert!(env["npm_config_cache"].ends_with("/npm"));
        assert!(env["PNPM_STORE_PATH"].ends_with("/pnpm"));
        assert!(env["BUN_INSTALL_CACHE_DIR"].ends_with("/bun"));

        let old = dir.path().join("old.bin");
        let new = dir.path().join("new.bin");
        std::fs::write(&old, vec![1u8; 80]).unwrap();
        std::fs::write(&new, vec![2u8; 80]).unwrap();
        let old_file = std::fs::File::open(&old).unwrap();
        old_file
            .set_modified(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        prune_cache(dir.path(), 100);
        assert!(!old.exists());
        assert!(new.exists());
    }

    #[test]
    fn abort_stops_a_running_build_command() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let mut env = HashMap::new();
        env.insert(
            "PATH".into(),
            std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin".into()),
        );
        let cwd = dir.path().to_path_buf();
        let worker =
            std::thread::spawn(move || super::run_shell("sleep 30", "install", &env, &cwd));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while super::BUILD_PID.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "build child did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        super::abort_inflight_build();
        let err = worker.join().unwrap().unwrap_err();
        assert!(err.to_string().contains("aborted"), "{err}");
        assert_eq!(super::BUILD_PID.load(Ordering::SeqCst), 0);
        super::BUILD_ABORT.store(false, Ordering::SeqCst);
    }

    #[test]
    fn a_shutdown_requested_before_a_phase_starts_is_not_cleared() {
        use std::sync::atomic::Ordering;
        super::BUILD_ABORT.store(true, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);
        let result = super::run_shell("true", "install", &env, dir.path());
        super::BUILD_ABORT.store(false, Ordering::SeqCst);
        assert!(result.unwrap_err().to_string().contains("aborted"));
    }

    #[tokio::test]
    async fn source_is_extracted_under_the_job_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = tmp.path().join("tree");
        let prefix = tree.join("repo");
        std::fs::create_dir_all(&prefix).unwrap();
        std::fs::write(prefix.join("index.html"), b"<html>v</html>").unwrap();
        std::fs::write(
            prefix.join("package.json"),
            br#"{"devDependencies":{"vite":"5.0.0"}}"#,
        )
        .unwrap();
        let archive = tmp.path().join("src.tgz");
        let packed = std::process::Command::new("tar")
            .args([
                "-czf",
                archive.to_str().unwrap(),
                "-C",
                tree.to_str().unwrap(),
                "repo",
            ])
            .status()
            .unwrap();
        assert!(packed.success());
        let bytes = std::fs::read(&archive).unwrap();

        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert(
            "CITE_DATA_DIR".into(),
            tmp.path().join("data").display().to_string(),
        );
        env.insert("CITE_WORK_DIR".into(), work.display().to_string());
        env.insert("CITE_DEV_SAME_USER".into(), "true".into());
        env.insert("CITE_MIN_FREE_BYTES".into(), "1".into());
        env.insert("CITE_INSTALL_COMMAND".into(), "true".into());
        env.insert(
            "CITE_BUILD_COMMAND".into(),
            "test -f index.html && mkdir -p dist && cp index.html dist/index.html".into(),
        );
        env.insert("CITE_RENDERING".into(), "static".into());
        env.insert("CITE_OUTPUT_DIR".into(), "dist".into());
        env.insert("CITE_BUILD_CACHE".into(), "off".into());
        env.insert("CITE_NODE".into(), "22".into());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        super::run_build(
            &cfg,
            &bytes,
            &"a".repeat(40),
            "msg",
            "dev",
            &cite_core::Redactor::new(),
        )
        .await
        .expect("extract and build");

        let job = std::fs::read_dir(&work)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("job-"))
            })
            .expect("job directory");
        assert_eq!(
            std::fs::read(job.join("src/index.html")).unwrap(),
            b"<html>v</html>"
        );

        env.insert("CITE_MAX_ENTRIES".into(), "1".into());
        env.insert(
            "CITE_WORK_DIR".into(),
            tmp.path().join("work2").display().to_string(),
        );
        std::fs::create_dir_all(tmp.path().join("work2")).unwrap();
        let capped = ManagerConfig::load_from(&env, None).unwrap();
        let err = super::run_build(
            &capped,
            &bytes,
            &"b".repeat(40),
            "msg",
            "dev",
            &cite_core::Redactor::new(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("entr") || err.to_string().contains("limit"),
            "{err}"
        );
    }

    #[test]
    fn resolve_site_applies_operator_overrides() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"devDependencies":{"vite":"5.0.0"}}"#,
        )
        .unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_RENDERING".into(), "static".into());
        env.insert("CITE_FRAMEWORK".into(), "vite".into());
        env.insert("CITE_PACKAGE_MANAGER".into(), "npm".into());
        env.insert("CITE_INSTALL_COMMAND".into(), "true".into());
        env.insert("CITE_BUILD_COMMAND".into(), "true".into());
        env.insert("CITE_OUTPUT_DIR".into(), "dist".into());
        env.insert("CITE_SPA_FALLBACK".into(), "index.html".into());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let (det, rendering) = resolve_site(&cfg, dir.path()).unwrap();
        assert_eq!(rendering, Rendering::Static);
        assert_eq!(det.framework, "vite");
        assert_eq!(det.output_dir, "dist");
        assert_eq!(det.spa_fallback.as_deref(), Some("index.html"));

        env.insert("CITE_RENDERING".into(), "ssr".into());
        env.insert("CITE_START_COMMAND".into(), "node server.js".into());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let (det, rendering) = resolve_site(&cfg, dir.path()).unwrap();
        assert_eq!(rendering, Rendering::Ssr);
        assert_eq!(det.start_argv, ["node", "server.js"]);

        env.insert("CITE_START_COMMAND".into(), "npm start".into());
        let err = ManagerConfig::load_from(&env, None).unwrap_err();
        assert!(err.to_string().contains("cannot run"), "{err}");
    }

    #[test]
    fn build_env_is_loaded_and_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("build.env");
        std::fs::write(&env_file, "TOKEN=secret-value\n").unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert("CITE_BUILD_ENV_FILE".into(), env_file.display().to_string());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let loaded = load_build_env(&cfg).unwrap();
        assert_eq!(
            loaded.get("TOKEN").map(String::as_str),
            Some("secret-value")
        );
        let redactor = make_redactor("pat-value", &loaded);
        let line = redactor.redact_line("pat-value and secret-value");
        assert!(!line.contains("pat-value"));
        assert!(!line.contains("secret-value"));

        env.insert(
            "CITE_BUILD_ENV_FILE".into(),
            dir.path().join("missing.env").display().to_string(),
        );
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        assert!(load_build_env(&cfg).unwrap().is_empty());
    }

    #[test]
    fn build_helper_runs_commands_and_a_failure_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let job = BuildJob {
            job_id: "job".into(),
            src,
            home: dir.path().join("home"),
            out: dir.path().join("out"),
            install_command: "/usr/bin/true".into(),
            build_command: "/usr/bin/true".into(),
            prune_command: Some("/usr/bin/true".into()),
            env: HashMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            cache_dir: None,
            timeout_s: 5,
        };
        let path = dir.path().join("job.json");
        std::fs::write(&path, serde_json::to_vec(&job).unwrap()).unwrap();
        run_build_helper(&path).unwrap();

        let mut failed = job;
        failed.build_command = "/usr/bin/false".into();
        std::fs::write(&path, serde_json::to_vec(&failed).unwrap()).unwrap();
        let err = run_build_helper(&path).unwrap_err();
        assert!(err.to_string().contains("build command failed"), "{err}");
    }

    #[test]
    fn release_manifest_copies_the_built_release() {
        use cite_core::schema::{Health, HealthExpect};
        let built = BuiltRelease {
            release_id: "rel".into(),
            sha: "a".repeat(40),
            message: "msg".into(),
            author: "dev".into(),
            rendering: Rendering::Static,
            runtime: cite_core::RuntimeKind::Node,
            node_major: "22".into(),
            start_argv: vec![],
            spa_fallback: Some("index.html".into()),
            bytes: 4,
            file_count: 1,
            tree_sha256: "b".repeat(64),
            health: Health {
                path: "/".into(),
                expect: HealthExpect::TwoXx,
                timeout_s: 5,
                consecutive: 1,
            },
            tar_path: PathBuf::from("out.tar"),
            job_dir: PathBuf::from("job"),
        };
        let manifest = release_manifest(&built, Slot::Green, "main");
        assert_eq!(manifest.slot, Slot::Green);
        assert_eq!(manifest.sha, built.sha);
        assert_eq!(manifest.branch, "main");
        assert_eq!(manifest.spa_fallback.as_deref(), Some("index.html"));
    }

    #[test]
    fn helper_environment_never_carries_manager_secrets() {
        let mut cmd = std::process::Command::new("true");
        cmd.env("CITE_GITHUB_TOKEN", "ghp_secret");
        super::apply_helper_env(&mut cmd);
        let keys: Vec<String> = cmd
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert!(!keys.iter().any(|k| k == "CITE_GITHUB_TOKEN"), "{keys:?}");
        assert!(keys.iter().any(|k| k == "PATH"));
    }

    #[test]
    fn reclaim_makes_read_only_directories_prunable_and_ignores_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let sub = cache.join("npm");
        std::fs::create_dir_all(&sub).unwrap();
        let file = sub.join("blob");
        std::fs::write(&file, vec![1u8; 200]).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("live.bin");
        std::fs::write(&victim, vec![2u8; 200]).unwrap();
        std::os::unix::fs::symlink(&outside, cache.join("link")).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o577)).unwrap();
        let me = (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        );
        super::prune_cache_with(&cache, 100, Some(me));
        assert!(!file.exists(), "reclaimed cache must be prunable");
        assert!(victim.exists(), "a symlink must never be followed");
        let mode = std::fs::metadata(&sub).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o022,
            0,
            "directory stays writable by others: {mode:o}"
        );
    }

    #[test]
    fn build_identity_must_not_be_root_or_the_manager() {
        assert!(super::check_build_ids(0, 10002, 0).is_err());
        assert!(super::check_build_ids(10002, 0, 0).is_err());
        assert!(super::check_build_ids(1000, 1000, 1000).is_err());
        assert_eq!(
            super::check_build_ids(10002, 10003, 0).unwrap(),
            (10002, 10003)
        );
    }

    #[test]
    fn line_reader_reports_eof_and_a_held_open_pipe_can_be_abandoned() {
        let mut quick = std::process::Command::new("echo")
            .arg("hi")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let done = super::spawn_line_reader(quick.stdout.take(), cite_core::Redactor::new(), false);
        assert!(done.recv_timeout(std::time::Duration::from_secs(5)).is_ok());
        let _ = quick.wait();

        let mut held = std::process::Command::new("sleep")
            .arg("3")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let done = super::spawn_line_reader(held.stdout.take(), cite_core::Redactor::new(), false);
        assert!(
            done.recv_timeout(std::time::Duration::from_millis(200))
                .is_err()
        );
        let _ = held.kill();
        let _ = held.wait();
    }

    #[test]
    fn log_lines_are_capped_and_a_bad_byte_does_not_stop_the_drain() {
        let mut data = vec![b'a'; 100];
        data.push(b'\n');
        data.extend_from_slice(&[0xff, 0xfe, b'x', b'\n']);
        data.extend_from_slice(b"tail without newline");
        let mut seen = Vec::new();
        super::for_each_line(std::io::Cursor::new(data), 10, |l| seen.push(l.to_string()));
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], "a".repeat(10));
        assert!(seen[1].ends_with('x'));
        assert_eq!(seen[2], "tail witho");
    }

    #[tokio::test]
    async fn build_failures_are_classified_as_transient_or_permanent() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path().join("tree/repo");
        std::fs::create_dir_all(&prefix).unwrap();
        std::fs::write(prefix.join("index.html"), b"<html></html>").unwrap();
        std::fs::write(
            prefix.join("package.json"),
            br#"{"devDependencies":{"vite":"5.0.0"}}"#,
        )
        .unwrap();
        let archive = tmp.path().join("src.tgz");
        let tree = tmp.path().join("tree");
        assert!(
            std::process::Command::new("tar")
                .args([
                    "-czf",
                    archive.to_str().unwrap(),
                    "-C",
                    tree.to_str().unwrap(),
                    "repo"
                ])
                .status()
                .unwrap()
                .success()
        );
        let bytes = std::fs::read(&archive).unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut env = HashMap::new();
        env.insert("CITE_REPO".into(), "owner/name".into());
        env.insert(
            "CITE_DATA_DIR".into(),
            tmp.path().join("data").display().to_string(),
        );
        env.insert("CITE_WORK_DIR".into(), work.display().to_string());
        env.insert("CITE_DEV_SAME_USER".into(), "true".into());
        env.insert("CITE_INSTALL_COMMAND".into(), "true".into());
        env.insert("CITE_BUILD_COMMAND".into(), "false".into());
        env.insert("CITE_RENDERING".into(), "static".into());
        env.insert("CITE_OUTPUT_DIR".into(), "dist".into());
        env.insert("CITE_BUILD_CACHE".into(), "off".into());
        env.insert("CITE_NODE".into(), "22".into());
        env.insert("CITE_MIN_FREE_BYTES".into(), "1".into());
        let redactor = cite_core::Redactor::new();

        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let err = super::run_build_classified(&cfg, &bytes, &"a".repeat(40), "m", "d", &redactor)
            .await
            .expect_err("build command fails");
        assert!(!err.is_transient(), "{err}");

        env.insert("CITE_MIN_FREE_BYTES".into(), "9000000000000000".into());
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let err = super::run_build_classified(&cfg, &bytes, &"a".repeat(40), "m", "d", &redactor)
            .await
            .expect_err("not enough free space");
        assert!(err.is_transient(), "{err}");

        let aborted = super::BuildFailure::transient("install aborted");
        assert!(aborted.is_transient());
        assert_eq!(aborted.message(), "install aborted");
    }

    #[test]
    fn remove_subtree_deletes_a_nested_tree_and_only_that_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let doomed = tmp.path().join("doomed");
        std::fs::create_dir_all(doomed.join("a/b/c")).unwrap();
        std::fs::write(doomed.join("a/b/c/f"), b"f").unwrap();
        std::fs::write(doomed.join("a/g"), b"g").unwrap();
        std::fs::write(tmp.path().join("sibling"), b"s").unwrap();
        let parent = super::open_cache_root(tmp.path()).unwrap();
        super::remove_subtree(&parent, c"doomed").unwrap();
        assert!(!doomed.exists());
        assert!(tmp.path().join("sibling").exists());
    }

    #[test]
    fn remove_subtree_handles_read_only_directories() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let doomed = tmp.path().join("doomed");
        let inner = doomed.join("a/b");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("f"), b"f").unwrap();
        for dir in [&inner, &doomed.join("a"), &doomed] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        let parent = super::open_cache_root(tmp.path()).unwrap();
        super::remove_subtree(&parent, c"doomed").unwrap();
        assert!(!doomed.exists());
    }

    #[test]
    fn walk_survives_nesting_beyond_the_depth_cap_and_removes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        let mut deep = cache.clone();
        for _ in 0..(super::MAX_CACHE_DEPTH + 8) {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(cache.join("keep.bin"), vec![1u8; 10]).unwrap();
        let root = super::open_cache_root(&cache).unwrap();
        let mut files = Vec::new();
        super::walk_cache(&root, super::CacheWalk::Measure, &mut files).unwrap();
        assert_eq!(files.len(), 1);
        let mut shallow = cache.clone();
        for _ in 0..super::MAX_CACHE_DEPTH {
            shallow.push("d");
        }
        assert!(shallow.is_dir());
        assert!(
            !shallow.join("d").exists(),
            "nesting over the cap is removed"
        );
    }

    #[test]
    fn work_tree_handover_does_not_follow_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, b"x").unwrap();
        let tree = tmp.path().join("tree");
        std::fs::create_dir_all(tree.join("a")).unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("a/link")).unwrap();
        std::fs::write(tree.join("a/f"), b"f").unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        give_tree(&tree, uid, gid).unwrap();
        assert!(
            std::fs::symlink_metadata(tree.join("a/link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            give_tree(&tree.join("a/f"), uid, gid).is_err(),
            "a file is not a tree root"
        );
        assert!(
            give_tree(&tree.join("a/link"), uid, gid).is_err(),
            "a symlink root is refused"
        );
    }

    #[test]
    fn prune_cache_deletes_oldest_files_until_under_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path();
        let old = cache.join("old.tgz");
        let new = cache.join("new.tgz");
        std::fs::write(&old, vec![1u8; 100]).unwrap();
        std::fs::write(&new, vec![2u8; 100]).unwrap();
        let old_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10);
        let new_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(old_time)
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&new)
            .unwrap()
            .set_modified(new_time)
            .unwrap();
        prune_cache(cache, 100);
        assert!(!old.exists(), "oldest cache file must be pruned");
        assert!(new.exists(), "newer cache file stays under the cap");
        assert!(super::dir_size(cache).unwrap() <= 100);
    }

    #[test]
    fn start_target_check_treats_only_node_and_bun_arguments_as_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path();
        let argv = |parts: &[&str]| parts.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        assert!(super::start_target_problem(src, &argv(&["node", "server.js"])).is_some());
        std::fs::write(src.join("server.js"), "").unwrap();
        assert!(super::start_target_problem(src, &argv(&["node", "server.js"])).is_none());
        let missing = super::start_target_problem(src, &argv(&["next", "start"])).unwrap();
        assert!(missing.contains("node_modules/.bin/next"), "{missing}");
        std::fs::create_dir_all(src.join("node_modules/.bin")).unwrap();
        std::fs::write(src.join("node_modules/.bin/next"), "").unwrap();
        assert!(super::start_target_problem(src, &argv(&["next", "start"])).is_none());
    }
}
