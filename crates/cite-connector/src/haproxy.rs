use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use cite_core::atomic::{ensure_dir, write_atomic};
use cite_edge::model::{EdgeConfig, Slot};
use cite_edge::render::{RenderOptions, Rendered, config_hash, render};
use cite_edge::runtime::{
    BackendStat, all_servers_up, cmd_set_active, cmd_set_maintenance, cmd_show_stat, parse_stat_csv,
};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

use crate::config::ConnectorConfig;
use crate::error::{ConnectorError, Result};
use crate::store::now_rfc3339;

const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const RELOAD_REPLY: Duration = Duration::from_secs(15);
const MASTER_LABEL: &str = "master CLI";
const RUNTIME_LABEL: &str = "runtime socket";
const RELOAD_CONFIRM: Duration = Duration::from_secs(5);
const RELOAD_POLL: Duration = Duration::from_millis(100);
const HEALTH_POLL: Duration = Duration::from_millis(500);
const MAX_REPLY: u64 = 16 * 1024 * 1024;
const MAX_ERROR_TEXT: usize = 2000;
const STAGE_DIR: &str = ".stage";
const PUBLIC_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

#[derive(Debug, Clone, Serialize)]
pub struct ApplyOutcome {
    pub config_hash: String,
    pub reloaded: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HaproxyStatus {
    pub running: bool,
    pub config_hash: String,
    pub last_reload_at: Option<String>,
    pub last_reload_ok: bool,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct State {
    status: HaproxyStatus,
    config_text: Option<String>,
    applied: Option<String>,
}

pub struct Haproxy {
    data_dir: PathBuf,
    haproxy_dir: PathBuf,
    maps_dir: PathBuf,
    pages_dir: PathBuf,
    haproxy_cfg: PathBuf,
    runtime_addr: String,
    master_addr: String,
    log_addr: String,
    haproxy_bin: String,
    validate: bool,
    apply_lock: Mutex<()>,
    state: StdMutex<State>,
}

fn internal(err: impl std::fmt::Display) -> ConnectorError {
    ConnectorError::Internal(err.to_string())
}

fn path_str(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| internal(format!("path {} is not valid UTF-8", path.display())))
}

const UNIX_PREFIX: &str = "unix:";

// The admin and master sockets are reached over TCP (host:port) or a unix socket (unix:/path).
trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

type Conn = Box<dyn Duplex>;

pub(crate) fn stats_listen(runtime_addr: &str) -> Result<String> {
    if let Some(path) = runtime_addr.strip_prefix(UNIX_PREFIX) {
        if !path.starts_with('/') {
            return Err(internal(format!(
                "runtime socket path {path:?} must be absolute"
            )));
        }
        return Ok(format!("unix@{path}"));
    }
    let (host, port) = runtime_addr
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host, port.parse::<u16>().ok().filter(|p| *p > 0)?)))
        .ok_or_else(|| {
            internal(format!(
                "runtime address {runtime_addr:?} must be host:port"
            ))
        })?;
    // an IPv4 literal pins the admin socket to one interface, a name falls back to all
    let bind = host
        .parse::<std::net::Ipv4Addr>()
        .map_or("0.0.0.0".to_string(), |ip| ip.to_string());
    Ok(format!("ipv4@{bind}:{port}"))
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn make_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    ensure_dir(path, DIR_MODE).map_err(internal)
}

fn write_files(
    maps_dir: &Path,
    pages_dir: &Path,
    cfg_path: &Path,
    rendered: &Rendered,
) -> Result<()> {
    make_dir(maps_dir)?;
    make_dir(pages_dir)?;
    if let Some(parent) = cfg_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        make_dir(parent)?;
    }
    for (name, html) in &rendered.pages {
        write_atomic(&pages_dir.join(name), html.as_bytes(), PUBLIC_MODE).map_err(internal)?;
    }
    let maps = [
        ("active.map", &rendered.active_map),
        ("maint.map", &rendered.maint_map),
    ];
    for (name, body) in maps {
        write_atomic(&maps_dir.join(name), body.as_bytes(), PUBLIC_MODE).map_err(internal)?;
    }
    write_atomic(cfg_path, rendered.config.as_bytes(), PUBLIC_MODE).map_err(internal)
}

// Replaces the value of an existing key or appends a new line, keeping every other line as is.
fn upsert_map_line(content: &str, key: &str, value: &str) -> String {
    let mut out = String::with_capacity(content.len() + key.len() + value.len() + 2);
    let mut found = false;
    for line in content.lines() {
        if line.split_whitespace().next() == Some(key) {
            if !found {
                out.push_str(&format!("{key} {value}\n"));
            }
            found = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !found {
        out.push_str(&format!("{key} {value}\n"));
    }
    out
}

fn rewrite_map_file(file: &Path, key: &str, value: &str) -> Result<()> {
    if let Some(parent) = file.parent() {
        make_dir(parent)?;
    }
    let current = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(internal(err)),
    };
    let updated = upsert_map_line(&current, key, value);
    write_atomic(file, updated.as_bytes(), PUBLIC_MODE).map_err(internal)
}

fn reply_error(reply: &str) -> Option<String> {
    let text = reply.trim();
    let bad = ["not found", "Unknown", "No such"];
    if !text.is_empty() && bad.iter().any(|marker| text.contains(marker)) {
        return Some(text.to_string());
    }
    None
}

fn parse_info_pid(info: &str) -> Option<u64> {
    info.lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse().ok())
}

async fn connect(addr: &str) -> std::io::Result<Conn> {
    match addr.strip_prefix(UNIX_PREFIX) {
        Some(path) => Ok(Box::new(UnixStream::connect(path).await?)),
        None => Ok(Box::new(TcpStream::connect(addr).await?)),
    }
}

async fn open(addr: &str, label: &str) -> Result<Conn> {
    let fail = |why: String| ConnectorError::Unavailable(format!("haproxy {label} {addr}: {why}"));
    match timeout(CONNECT_TIMEOUT, connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(fail(err.to_string())),
        Err(_) => Err(fail("connect timed out".into())),
    }
}

// HAProxy answers one command per connection and closes it, so EOF marks the end of the reply.
async fn converse(
    mut stream: Conn,
    addr: &str,
    label: &str,
    cmd: &str,
    read_timeout: Duration,
) -> Result<String> {
    let fail = |why: String| ConnectorError::Unavailable(format!("haproxy {label} {addr}: {why}"));
    let exchange = async {
        stream.write_all(cmd.as_bytes()).await?;
        let mut out = Vec::new();
        (&mut stream).take(MAX_REPLY).read_to_end(&mut out).await?;
        Ok::<Vec<u8>, std::io::Error>(out)
    };
    match timeout(read_timeout, exchange).await {
        Ok(Ok(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Ok(Err(err)) => Err(fail(err.to_string())),
        Err(_) => Err(fail("read timed out".into())),
    }
}

// The master answers `Success=1` or `Success=0`, then a `--` line and the loader output.
fn parse_reload_reply(reply: &str) -> std::result::Result<(), String> {
    let text = reply.trim();
    match text.lines().next().map(str::trim) {
        Some("Success=1") => Ok(()),
        Some("Success=0") => {
            let detail = text.split_once("--").map_or("", |(_, rest)| rest.trim());
            Err(format!(
                "haproxy refused the reload: {}",
                truncate(detail, MAX_ERROR_TEXT)
            ))
        }
        _ => Err(format!(
            "unexpected reply to reload: {}",
            truncate(text, MAX_ERROR_TEXT)
        )),
    }
}

async fn send_reload(stream: Conn, addr: &str) -> std::result::Result<(), String> {
    let reply = converse(stream, addr, MASTER_LABEL, "reload\n", RELOAD_REPLY)
        .await
        .map_err(|err| err.to_string())?;
    parse_reload_reply(&reply)
}

async fn run_check(bin: &str, cfg_path: &Path) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.arg("-c")
        .arg("-f")
        .arg(cfg_path)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = match timeout(CHECK_TIMEOUT, cmd.output()).await {
        Err(_) => return Err(ConnectorError::Unavailable("haproxy -c timed out".into())),
        Ok(Err(err)) => return Err(internal(format!("cannot run {bin}: {err}"))),
        Ok(Ok(output)) => output,
    };
    if output.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&output.stdout).into_owned();
    }
    Err(ConnectorError::BadRequest(format!(
        "haproxy rejected the configuration: {}",
        truncate(text.trim(), MAX_ERROR_TEXT)
    )))
}

impl Haproxy {
    pub fn new(cfg: &ConnectorConfig) -> Haproxy {
        let state = State {
            config_text: fs::read_to_string(&cfg.haproxy_cfg).ok(),
            ..State::default()
        };
        Haproxy {
            data_dir: cfg.data_dir.clone(),
            haproxy_dir: cfg.haproxy_dir.clone(),
            maps_dir: cfg.maps_dir.clone(),
            pages_dir: cfg.pages_dir.clone(),
            haproxy_cfg: cfg.haproxy_cfg.clone(),
            runtime_addr: cfg.runtime_addr.clone(),
            master_addr: cfg.master_addr.clone(),
            log_addr: cfg.log_addr_for_haproxy.clone(),
            haproxy_bin: cfg.haproxy_bin.clone(),
            validate: cfg.validate_with_haproxy,
            apply_lock: Mutex::new(()),
            state: StdMutex::new(state),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn status(&self) -> HaproxyStatus {
        self.state().status.clone()
    }

    pub fn current_config_text(&self) -> Option<String> {
        self.state().config_text.clone()
    }

    fn render_options(&self, maps_dir: &Path, pages_dir: &Path) -> Result<RenderOptions> {
        let certs = self.data_dir.join("certs");
        let tls_dir = if certs.is_dir() {
            certs.to_str().map(str::to_string)
        } else {
            None
        };
        Ok(RenderOptions {
            maps_dir: path_str(maps_dir)?,
            pages_dir: path_str(pages_dir)?,
            runtime_addr: stats_listen(&self.runtime_addr)?,
            log_addr: self.log_addr.clone(),
            tls_dir,
        })
    }

    // An equal hash is not enough on its own: a file deleted from disk has to be written again.
    fn is_current(&self, hash: &str, rendered: &Rendered) -> bool {
        let same = self.state().applied.as_deref() == Some(hash);
        same && self.haproxy_cfg.is_file()
            && self.maps_dir.join("active.map").is_file()
            && self.maps_dir.join("maint.map").is_file()
            && rendered
                .pages
                .iter()
                .all(|(name, _)| self.pages_dir.join(name).is_file())
    }

    pub async fn apply(&self, edge: &EdgeConfig) -> Result<ApplyOutcome> {
        let _guard = self.apply_lock.lock().await;
        let options = self.render_options(&self.maps_dir, &self.pages_dir)?;
        let rendered = render(edge, &options)?;
        let hash = config_hash(&rendered);
        if self.is_current(&hash, &rendered) {
            return Ok(ApplyOutcome {
                config_hash: hash,
                reloaded: false,
            });
        }
        if let Err(err) = self.validate_and_install(edge, &rendered).await {
            self.state().status.last_error = Some(err.to_string());
            return Err(err);
        }
        {
            let mut st = self.state();
            st.config_text = Some(rendered.config.clone());
            st.applied = Some(hash.clone());
            st.status.config_hash = hash.clone();
        }
        let reloaded = self.reload_master().await;
        Ok(ApplyOutcome {
            config_hash: hash,
            reloaded,
        })
    }

    async fn validate_and_install(&self, edge: &EdgeConfig, rendered: &Rendered) -> Result<()> {
        if self.validate {
            self.validate_staged(edge).await?;
        }
        let (maps, pages, cfg) = (
            self.maps_dir.clone(),
            self.pages_dir.clone(),
            self.haproxy_cfg.clone(),
        );
        let rendered = rendered.clone();
        tokio::task::spawn_blocking(move || write_files(&maps, &pages, &cfg, &rendered))
            .await
            .map_err(internal)?
    }

    // The staged copy points at its own maps and pages so the check never depends on live files.
    async fn validate_staged(&self, edge: &EdgeConfig) -> Result<()> {
        let stage = self.haproxy_dir.join(STAGE_DIR);
        let stage_maps = stage.join("maps");
        let stage_pages = stage.join("pages");
        let cfg_path = stage.join("haproxy.cfg");
        let options = self.render_options(&stage_maps, &stage_pages)?;
        let staged = render(edge, &options)?;
        let write = {
            let (maps, pages, cfg) = (stage_maps, stage_pages, cfg_path.clone());
            tokio::task::spawn_blocking(move || write_files(&maps, &pages, &cfg, &staged))
        };
        let checked = match write.await.map_err(internal)? {
            Ok(()) => run_check(&self.haproxy_bin, &cfg_path).await,
            Err(err) => Err(err),
        };
        let _ = tokio::fs::remove_dir_all(&stage).await;
        checked
    }

    async fn reload_master(&self) -> bool {
        let stream = match open(&self.master_addr, MASTER_LABEL).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!("haproxy reload skipped: {err}");
                let mut st = self.state();
                st.status.running = false;
                st.status.last_reload_ok = false;
                st.status.last_error = Some(err.to_string());
                return false;
            }
        };
        self.state().status.running = true;
        let before = self.runtime_pid().await;
        let outcome = match send_reload(stream, &self.master_addr).await {
            Ok(()) => self.await_reload(before).await,
            Err(msg) => Err(msg),
        };
        let mut st = self.state();
        st.status.last_reload_at = Some(now_rfc3339());
        match &outcome {
            Ok(()) => {
                st.status.last_reload_ok = true;
                st.status.last_error = None;
            }
            Err(msg) => {
                tracing::warn!("haproxy reload failed: {msg}");
                st.status.last_reload_ok = false;
                st.status.last_error = Some(msg.clone());
            }
        }
        outcome.is_ok()
    }

    // A new worker answers with a different pid, which is what proves the reload took effect.
    async fn await_reload(&self, before: Option<u64>) -> std::result::Result<(), String> {
        let deadline = Instant::now() + RELOAD_CONFIRM;
        loop {
            if let Some(after) = self.runtime_pid().await
                && before != Some(after)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("reload was not confirmed by the runtime socket".into());
            }
            sleep(RELOAD_POLL).await;
        }
    }

    async fn runtime_pid(&self) -> Option<u64> {
        let info = self.runtime_command("show info\n").await.ok()?;
        parse_info_pid(&info)
    }

    async fn runtime_command(&self, cmd: &str) -> Result<String> {
        let stream = open(&self.runtime_addr, RUNTIME_LABEL).await?;
        converse(stream, &self.runtime_addr, RUNTIME_LABEL, cmd, READ_TIMEOUT).await
    }

    // The file is written first so a reload keeps the choice even when the socket is down.
    async fn set_map(&self, file: &str, key: &str, value: &str, cmd: &str) -> Result<()> {
        let _guard = self.apply_lock.lock().await;
        // The map on disk now differs from the last render, so the next apply must not be skipped.
        self.state().applied = None;
        let path = self.maps_dir.join(file);
        let (key_owned, value_owned) = (key.to_string(), value.to_string());
        tokio::task::spawn_blocking(move || rewrite_map_file(&path, &key_owned, &value_owned))
            .await
            .map_err(internal)??;
        match self.runtime_command(cmd).await {
            Ok(reply) => match reply_error(&reply) {
                Some(text) => Err(internal(format!("haproxy rejected {file} update: {text}"))),
                None => Ok(()),
            },
            Err(err) => {
                tracing::warn!("{file} updated on disk only: {err}");
                Err(err)
            }
        }
    }

    pub async fn set_active(&self, site: &str, slot: Slot) -> Result<()> {
        let backend = format!("be_{site}_{}", slot.as_str());
        let cmd = cmd_set_active(&path_str(&self.maps_dir)?, site, &backend)?;
        self.set_map("active.map", site, &backend, &cmd).await
    }

    pub async fn set_maintenance(&self, site: &str, on: bool) -> Result<()> {
        let cmd = cmd_set_maintenance(&path_str(&self.maps_dir)?, site, on)?;
        let value = if on { "on" } else { "off" };
        self.set_map("maint.map", site, value, &cmd).await
    }

    pub async fn stats(&self) -> Result<Vec<BackendStat>> {
        let csv = self.runtime_command(cmd_show_stat()).await?;
        Ok(parse_stat_csv(&csv))
    }

    pub async fn wait_healthy(&self, site: &str, slot: Slot, wait: Duration) -> Result<bool> {
        let backend = format!("be_{site}_{}", slot.as_str());
        let deadline = Instant::now() + wait;
        loop {
            if let Ok(stats) = self.stats().await
                && all_servers_up(&stats, &backend)
            {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            sleep(HEALTH_POLL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cite_edge::model::{
        CONFIG_VERSION, EdgeSettings, HealthCheck, Maintenance, Site, SiteKind, Target, Upstream,
    };
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::{TcpListener, UnixListener};

    const CSV_HEADER: &str = "# pxname,svname,status,scur,bin,bout,check_status\n";

    fn site(id: &str) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: vec![format!("{id}.example.com")],
            path_regex: None,
            kind: SiteKind::Site,
            blue: Upstream {
                targets: vec![Target {
                    addr: "10.0.0.1:8080".into(),
                    weight: 100,
                }],
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

    fn edge(sites: Vec<Site>) -> EdgeConfig {
        EdgeConfig {
            version: CONFIG_VERSION,
            sites,
            pages: vec![],
            firewall: vec![],
            settings: EdgeSettings::default(),
        }
    }

    fn haproxy_in(dir: &TempDir, runtime_addr: &str) -> Haproxy {
        let root = dir.path();
        Haproxy {
            data_dir: root.join("data"),
            haproxy_dir: root.join("haproxy"),
            maps_dir: root.join("haproxy/maps"),
            pages_dir: root.join("haproxy/pages"),
            haproxy_cfg: root.join("haproxy/haproxy.cfg"),
            runtime_addr: runtime_addr.into(),
            master_addr: "127.0.0.1:1".into(),
            log_addr: "127.0.0.1:5140".into(),
            haproxy_bin: "true".into(),
            validate: false,
            apply_lock: Mutex::new(()),
            state: StdMutex::new(State::default()),
        }
    }

    async fn fake_runtime(
        handler: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> (String, Arc<StdMutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let log = seen.clone();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (log, handler) = (log.clone(), handler.clone());
                tokio::spawn(async move {
                    let mut line = String::new();
                    let mut reader = BufReader::new(&mut stream);
                    if reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    let reply = handler(&line);
                    log.lock().unwrap().push(line);
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (addr, seen)
    }

    // Same behaviour as fake_runtime but listening on a unix socket at `path`.
    fn fake_unix(
        path: &Path,
        handler: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Arc<StdMutex<Vec<String>>> {
        let listener = UnixListener::bind(path).unwrap();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut line = String::new();
                let mut reader = BufReader::new(&mut stream);
                if reader.read_line(&mut line).await.is_err() {
                    continue;
                }
                let reply = handler(&line);
                log.lock().unwrap().push(line);
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        seen
    }

    fn csv(rows: &[(&str, &str, &str)]) -> String {
        let mut out = CSV_HEADER.to_string();
        for (backend, server, status) in rows {
            out.push_str(&format!("{backend},{server},{status},0,0,0,L7OK\n"));
        }
        out
    }

    #[test]
    fn stats_listen_uses_the_port_of_the_runtime_address() {
        assert_eq!(stats_listen("haproxy:9999").unwrap(), "ipv4@0.0.0.0:9999");
        assert_eq!(stats_listen("127.0.0.1:1").unwrap(), "ipv4@127.0.0.1:1");
        for bad in ["haproxy", "haproxy:0", "haproxy:x", "haproxy:70000", ""] {
            assert!(stats_listen(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn stats_listen_maps_unix_runtime_sockets() {
        assert_eq!(
            stats_listen("unix:/run/cite/admin.sock").unwrap(),
            "unix@/run/cite/admin.sock"
        );
        assert!(stats_listen("unix:relative.sock").is_err());
    }

    #[tokio::test]
    async fn unix_runtime_and_master_sockets_drive_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (admin, master) = (dir.path().join("a.sock"), dir.path().join("m.sock"));
        let reloads = Arc::new(AtomicU64::new(0));
        let counter = reloads.clone();
        let seen_master = fake_unix(&master, move |line| {
            if line.trim() == "reload" {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            "Success=1\n--\nok\n".to_string()
        });
        let seen_admin = fake_unix(&admin, move |line| {
            if line.starts_with("show info") {
                format!("Pid: {}\n", 100 + reloads.load(Ordering::SeqCst))
            } else {
                "\n".to_string()
            }
        });
        let state = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&state, &format!("{UNIX_PREFIX}{}", admin.display()));
        hp.master_addr = format!("{UNIX_PREFIX}{}", master.display());
        hp.log_addr = "/run/cite/log.sock".into();
        let outcome = hp.apply(&edge(vec![site("shop")])).await.unwrap();
        assert!(outcome.reloaded);
        assert_eq!(seen_master.lock().unwrap().as_slice(), ["reload\n"]);
        hp.set_active("shop", Slot::Green).await.unwrap();
        let sent = seen_admin.lock().unwrap().clone();
        assert!(sent.iter().any(|c| c.starts_with("set map")), "{sent:?}");
        let text = hp.current_config_text().unwrap();
        assert!(
            text.contains(&format!("unix@{}", admin.display())),
            "{text}"
        );
        assert!(text.contains("/run/cite/log.sock"));
        assert!(!text.contains("ipv4@"));
    }

    #[tokio::test]
    async fn missing_unix_socket_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let gone = dir.path().join("none.sock");
        let hp = haproxy_in(&state, &format!("{UNIX_PREFIX}{}", gone.display()));
        let err = hp.stats().await.unwrap_err();
        assert!(matches!(err, ConnectorError::Unavailable(_)), "{err:?}");
    }

    #[test]
    fn upsert_replaces_inserts_and_keeps_other_lines() {
        let before = "a be_a_blue\nb be_b_blue\n";
        assert_eq!(
            upsert_map_line(before, "b", "be_b_green"),
            "a be_a_blue\nb be_b_green\n"
        );
        assert_eq!(
            upsert_map_line(before, "c", "be_c_blue"),
            "a be_a_blue\nb be_b_blue\nc be_c_blue\n"
        );
        assert_eq!(upsert_map_line("", "a", "x"), "a x\n");
        assert_eq!(upsert_map_line("a x", "b", "y"), "a x\nb y\n");
    }

    #[test]
    fn upsert_matches_whole_keys_and_collapses_duplicates() {
        let before = "shop be_shop_blue\nshop-2 be_shop-2_blue\nshop be_shop_green\n";
        let after = upsert_map_line(before, "shop", "be_shop_green");
        assert_eq!(after, "shop be_shop_green\nshop-2 be_shop-2_blue\n");
    }

    #[test]
    fn info_pid_is_parsed() {
        assert_eq!(
            parse_info_pid("Name: HAProxy\nPid: 77\nUptime: 1d\n"),
            Some(77)
        );
        assert_eq!(parse_info_pid("Name: HAProxy\n"), None);
    }

    #[test]
    fn reload_replies_are_classified() {
        assert_eq!(
            parse_reload_reply("Success=1\n--\n[NOTICE] (1) : Loading success.\n\n"),
            Ok(())
        );
        let refused =
            parse_reload_reply("Success=0\n--\n[ALERT] bad\n[WARNING] Loading failure!\n\n")
                .unwrap_err();
        assert!(refused.contains("[ALERT] bad"), "{refused}");
        assert!(!refused.contains("Success=0"), "{refused}");
        for odd in ["", "\n", "Unknown command: 'reload'\n"] {
            let err = parse_reload_reply(odd).unwrap_err();
            assert!(err.contains("unexpected reply"), "{err}");
        }
    }

    #[test]
    fn reply_errors_are_detected() {
        assert_eq!(reply_error("\n"), None);
        assert_eq!(reply_error(""), None);
        assert_eq!(reply_error("ok\n"), None);
        assert!(reply_error("Key not found.\n").is_some());
        assert!(reply_error("Unknown map identifier.\n").is_some());
        assert!(reply_error("No such file\n").is_some());
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdef", 3), "abc...");
        assert_eq!(truncate("\u{e9}\u{e9}\u{e9}", 3), "\u{e9}...");
    }

    #[tokio::test]
    async fn apply_writes_config_maps_and_pages() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let outcome = hp.apply(&edge(vec![site("shop")])).await.unwrap();
        assert!(!outcome.reloaded);
        assert_eq!(outcome.config_hash.len(), 64);
        let cfg = fs::read_to_string(&hp.haproxy_cfg).unwrap();
        assert!(cfg.contains("backend be_shop_blue"));
        assert!(cfg.contains("stats socket ipv4@127.0.0.1:9"));
        let active = fs::read_to_string(hp.maps_dir.join("active.map")).unwrap();
        assert_eq!(active, "shop be_shop_blue\n");
        let maint = fs::read_to_string(hp.maps_dir.join("maint.map")).unwrap();
        assert_eq!(maint, "shop off\n");
        assert!(hp.pages_dir.join("_default.html").is_file());
        assert_eq!(hp.current_config_text().as_deref(), Some(cfg.as_str()));
        let status = hp.status();
        assert_eq!(status.config_hash, outcome.config_hash);
        assert!(!status.running);
        assert!(!status.last_reload_ok);
        let err = status.last_error.unwrap();
        assert!(err.contains("master CLI 127.0.0.1:1"), "{err}");
    }

    // The runtime socket reports a new pid once the master has been asked to reload.
    async fn reloading_haproxy(
        master_reply: &'static str,
    ) -> (Haproxy, Arc<StdMutex<Vec<String>>>, TempDir) {
        let reloads = Arc::new(AtomicU64::new(0));
        let counter = reloads.clone();
        let (master, seen) = fake_runtime(move |line| {
            if line.trim() == "reload" {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            master_reply.to_string()
        })
        .await;
        let (runtime, _) = fake_runtime(move |_| {
            format!(
                "Name: HAProxy\nPid: {}\n",
                100 + reloads.load(Ordering::SeqCst)
            )
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&dir, &runtime);
        hp.master_addr = master;
        (hp, seen, dir)
    }

    #[tokio::test]
    async fn apply_reloads_through_the_master_cli_and_confirms_the_new_pid() {
        let (hp, seen, _dir) =
            reloading_haproxy("Success=1\n--\n[NOTICE] Loading success.\n").await;
        let outcome = hp.apply(&edge(vec![site("shop")])).await.unwrap();
        assert!(outcome.reloaded);
        assert_eq!(seen.lock().unwrap().as_slice(), ["reload\n"]);
        let status = hp.status();
        assert!(status.running);
        assert!(status.last_reload_ok);
        assert!(status.last_reload_at.is_some());
        assert_eq!(status.last_error, None);
    }

    #[tokio::test]
    async fn refused_reload_is_reported_with_the_loader_output() {
        let reply = "Success=0\n--\n[ALERT] unknown keyword 'bogus'\n[WARNING] Loading failure!\n";
        let (hp, _seen, _dir) = reloading_haproxy(reply).await;
        let outcome = hp.apply(&edge(vec![site("shop")])).await.unwrap();
        assert!(!outcome.reloaded);
        let status = hp.status();
        assert!(status.running);
        assert!(!status.last_reload_ok);
        let err = status.last_error.unwrap();
        assert!(err.contains("refused the reload"), "{err}");
        assert!(err.contains("unknown keyword 'bogus'"), "{err}");
    }

    #[tokio::test]
    async fn unchanged_config_is_not_rewritten_until_files_go_missing() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let cfg = edge(vec![site("shop")]);
        let first = hp.apply(&cfg).await.unwrap();
        fs::write(&hp.haproxy_cfg, "SENTINEL").unwrap();
        let second = hp.apply(&cfg).await.unwrap();
        assert_eq!(first.config_hash, second.config_hash);
        assert_eq!(fs::read_to_string(&hp.haproxy_cfg).unwrap(), "SENTINEL");
        fs::remove_file(hp.pages_dir.join("_default.html")).unwrap();
        hp.apply(&cfg).await.unwrap();
        let restored = fs::read_to_string(&hp.haproxy_cfg).unwrap();
        assert!(restored.contains("backend be_shop_blue"));
        assert!(hp.pages_dir.join("_default.html").is_file());
    }

    #[tokio::test]
    async fn changed_config_changes_hash_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let one = hp.apply(&edge(vec![site("shop")])).await.unwrap();
        let two = hp
            .apply(&edge(vec![site("shop"), site("blog")]))
            .await
            .unwrap();
        assert_ne!(one.config_hash, two.config_hash);
        let cfg = fs::read_to_string(&hp.haproxy_cfg).unwrap();
        assert!(cfg.contains("backend be_blog_blue"));
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_before_touching_files() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let mut bad = site("Bad_ID");
        bad.hosts = vec![];
        let err = hp.apply(&edge(vec![bad])).await.unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)));
        assert!(!hp.haproxy_cfg.exists());
    }

    #[tokio::test]
    async fn rejected_validation_leaves_live_files_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.apply(&edge(vec![site("shop")])).await.unwrap();
        let live = fs::read_to_string(&hp.haproxy_cfg).unwrap();
        hp.validate = true;
        hp.haproxy_bin = "sh".into();
        let err = hp
            .apply(&edge(vec![site("shop"), site("blog")]))
            .await
            .unwrap_err();
        let ConnectorError::BadRequest(msg) = &err else {
            panic!("expected BadRequest, got {err:?}");
        };
        assert!(msg.contains("rejected the configuration"), "{msg}");
        assert!(msg.contains("haproxy.cfg"), "{msg}");
        assert_eq!(fs::read_to_string(&hp.haproxy_cfg).unwrap(), live);
        assert!(!hp.haproxy_dir.join(STAGE_DIR).exists());
        assert!(hp.status().last_error.is_some());
    }

    #[tokio::test]
    async fn accepted_validation_installs_files_and_cleans_stage() {
        let dir = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.validate = true;
        hp.haproxy_bin = "true".into();
        hp.apply(&edge(vec![site("shop")])).await.unwrap();
        let cfg = fs::read_to_string(&hp.haproxy_cfg).unwrap();
        assert!(cfg.contains(hp.maps_dir.to_str().unwrap()));
        assert!(!hp.haproxy_dir.join(STAGE_DIR).exists());
    }

    #[tokio::test]
    async fn missing_haproxy_binary_is_an_internal_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.validate = true;
        hp.haproxy_bin = "/nonexistent/haproxy-bin".into();
        let err = hp.apply(&edge(vec![site("shop")])).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Internal(_)), "{err:?}");
        assert!(!hp.haproxy_cfg.exists());
    }

    #[tokio::test]
    async fn set_active_sends_command_and_rewrites_the_map() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, seen) = fake_runtime(|_| "\n".to_string()).await;
        let hp = haproxy_in(&dir, &addr);
        hp.apply(&edge(vec![site("shop")])).await.unwrap();
        hp.set_active("shop", Slot::Green).await.unwrap();
        let sent = seen.lock().unwrap().clone();
        let expected = format!(
            "set map {}/active.map shop be_shop_green\n",
            hp.maps_dir.display()
        );
        assert_eq!(sent, vec![expected]);
        let active = fs::read_to_string(hp.maps_dir.join("active.map")).unwrap();
        assert_eq!(active, "shop be_shop_green\n");
    }

    #[tokio::test]
    async fn set_maintenance_sends_command_and_rewrites_the_map() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, seen) = fake_runtime(|_| String::new()).await;
        let hp = haproxy_in(&dir, &addr);
        hp.apply(&edge(vec![site("shop"), site("blog")]))
            .await
            .unwrap();
        hp.set_maintenance("blog", true).await.unwrap();
        let sent = seen.lock().unwrap().clone();
        assert!(sent[0].ends_with("/maint.map blog on\n"), "{sent:?}");
        let maint = fs::read_to_string(hp.maps_dir.join("maint.map")).unwrap();
        assert_eq!(maint, "blog on\nshop off\n");
    }

    #[tokio::test]
    async fn runtime_error_reply_fails_but_keeps_the_file_update() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, _) = fake_runtime(|_| "Unknown map identifier.\n".to_string()).await;
        let hp = haproxy_in(&dir, &addr);
        let err = hp.set_active("shop", Slot::Green).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Internal(_)), "{err:?}");
        assert!(err.to_string().contains("Unknown map identifier"));
        let active = fs::read_to_string(hp.maps_dir.join("active.map")).unwrap();
        assert_eq!(active, "shop be_shop_green\n");
    }

    #[tokio::test]
    async fn unreachable_runtime_is_unavailable_but_file_converges() {
        let dir = tempfile::tempdir().unwrap();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = free.local_addr().unwrap().to_string();
        drop(free);
        let hp = haproxy_in(&dir, &addr);
        let err = hp.set_maintenance("shop", true).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Unavailable(_)), "{err:?}");
        let maint = fs::read_to_string(hp.maps_dir.join("maint.map")).unwrap();
        assert_eq!(maint, "shop on\n");
        assert!(hp.stats().await.is_err());
    }

    #[tokio::test]
    async fn set_active_after_apply_forces_the_next_apply_to_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, _) = fake_runtime(|_| String::new()).await;
        let hp = haproxy_in(&dir, &addr);
        let cfg = edge(vec![site("shop")]);
        hp.apply(&cfg).await.unwrap();
        hp.set_active("shop", Slot::Green).await.unwrap();
        hp.apply(&cfg).await.unwrap();
        let active = fs::read_to_string(hp.maps_dir.join("active.map")).unwrap();
        assert_eq!(active, "shop be_shop_blue\n");
    }

    #[tokio::test]
    async fn stats_and_wait_healthy_follow_the_runtime_csv() {
        let dir = tempfile::tempdir().unwrap();
        let body = csv(&[
            ("be_shop_blue", "t1", "UP"),
            ("be_shop_blue", "BACKEND", "UP"),
            ("be_shop_green", "t1", "UP"),
            ("be_shop_green", "t2", "DOWN"),
            ("be_shop_green", "BACKEND", "UP"),
        ]);
        let (addr, _) = fake_runtime(move |_| body.clone()).await;
        let hp = haproxy_in(&dir, &addr);
        let stats = hp.stats().await.unwrap();
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[1].servers.len(), 2);
        let wait = Duration::from_millis(700);
        assert!(hp.wait_healthy("shop", Slot::Blue, wait).await.unwrap());
        assert!(!hp.wait_healthy("shop", Slot::Green, wait).await.unwrap());
        assert!(!hp.wait_healthy("nope", Slot::Blue, wait).await.unwrap());
    }

    #[tokio::test]
    async fn wait_healthy_notices_a_backend_coming_up() {
        let dir = tempfile::tempdir().unwrap();
        let calls = Arc::new(StdMutex::new(0u32));
        let counter = calls.clone();
        let (addr, _) = fake_runtime(move |_| {
            let mut n = counter.lock().unwrap();
            *n += 1;
            let status = if *n < 3 { "DOWN" } else { "UP" };
            csv(&[("be_shop_blue", "t1", status)])
        })
        .await;
        let hp = haproxy_in(&dir, &addr);
        let up = hp
            .wait_healthy("shop", Slot::Blue, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(up);
        assert!(*calls.lock().unwrap() >= 3);
    }
}
