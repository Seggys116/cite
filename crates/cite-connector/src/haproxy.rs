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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

use crate::config::ConnectorConfig;
use crate::error::{ConnectorError, Result};
use crate::store::now_rfc3339;

const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(3);
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
    log_addr: String,
    haproxy_bin: String,
    validate: bool,
    proc_root: PathBuf,
    apply_lock: Mutex<()>,
    state: StdMutex<State>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcEntry {
    pid: i32,
    comm: String,
    cmdline: String,
    ppid: Option<i32>,
}

fn internal(err: impl std::fmt::Display) -> ConnectorError {
    ConnectorError::Internal(err.to_string())
}

fn path_str(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| internal(format!("path {} is not valid UTF-8", path.display())))
}

fn stats_listen(runtime_addr: &str) -> Result<String> {
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

fn parse_ppid(status: &str) -> Option<i32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse().ok())
}

fn has_master_flag(cmdline: &str) -> bool {
    cmdline.split('\0').filter(|a| !a.is_empty()).any(|arg| {
        arg == "--master-worker"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('W'))
    })
}

// Workers share the master's command line, so entries whose parent is a candidate are skipped.
fn pick_master(procs: &[ProcEntry]) -> Option<i32> {
    let candidates: Vec<&ProcEntry> = procs
        .iter()
        .filter(|p| p.comm.trim() == "haproxy" && has_master_flag(&p.cmdline))
        .collect();
    candidates
        .iter()
        .filter(|p| {
            !p.ppid
                .is_some_and(|parent| candidates.iter().any(|c| c.pid == parent))
        })
        .map(|p| p.pid)
        .min()
}

fn scan_proc(root: &Path) -> Option<i32> {
    let entries = fs::read_dir(root).ok()?;
    let mut procs = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        let dir = entry.path();
        let Ok(comm) = fs::read_to_string(dir.join("comm")) else {
            continue;
        };
        if comm.trim() != "haproxy" {
            continue;
        }
        let cmdline = fs::read(dir.join("cmdline")).unwrap_or_default();
        let status = fs::read_to_string(dir.join("status")).unwrap_or_default();
        procs.push(ProcEntry {
            pid,
            comm,
            cmdline: String::from_utf8_lossy(&cmdline).into_owned(),
            ppid: parse_ppid(&status),
        });
    }
    pick_master(&procs)
}

fn signal_reload(pid: i32) -> Result<()> {
    let pid = rustix::process::Pid::from_raw(pid)
        .ok_or_else(|| internal(format!("invalid haproxy pid {pid}")))?;
    rustix::process::kill_process(pid, rustix::process::Signal::USR2)
        .map_err(|err| internal(format!("cannot signal haproxy master: {err}")))
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
            log_addr: cfg.log_addr_for_haproxy.clone(),
            haproxy_bin: cfg.haproxy_bin.clone(),
            validate: cfg.validate_with_haproxy,
            proc_root: PathBuf::from("/proc"),
            apply_lock: Mutex::new(()),
            state: StdMutex::new(state),
        }
    }

    // Tests point this at an empty directory so no real HAProxy process is ever signalled.
    #[cfg(test)]
    pub(crate) fn with_proc_root(mut self, root: PathBuf) -> Self {
        self.proc_root = root;
        self
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

    async fn find_master(&self) -> Option<i32> {
        let root = self.proc_root.clone();
        tokio::task::spawn_blocking(move || scan_proc(&root))
            .await
            .ok()
            .flatten()
    }

    async fn reload_master(&self) -> bool {
        let Some(pid) = self.find_master().await else {
            self.state().status.running = false;
            return false;
        };
        self.state().status.running = true;
        let before = self.runtime_pid().await;
        let outcome = match signal_reload(pid) {
            Ok(()) => self.await_reload(before).await,
            Err(err) => Err(err.to_string()),
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
        let addr = self.runtime_addr.as_str();
        let fail = |why: String| {
            ConnectorError::Unavailable(format!("haproxy runtime socket {addr}: {why}"))
        };
        let mut stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => return Err(fail(err.to_string())),
            Err(_) => return Err(fail("connect timed out".into())),
        };
        // HAProxy answers one command per connection and closes it, so EOF marks the end of the reply.
        let exchange = async {
            stream.write_all(cmd.as_bytes()).await?;
            let mut out = Vec::new();
            (&mut stream).take(MAX_REPLY).read_to_end(&mut out).await?;
            Ok::<Vec<u8>, std::io::Error>(out)
        };
        match timeout(READ_TIMEOUT, exchange).await {
            Ok(Ok(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
            Ok(Err(err)) => Err(fail(err.to_string())),
            Err(_) => Err(fail("read timed out".into())),
        }
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

    use cite_edge::model::{
        CONFIG_VERSION, EdgeSettings, HealthCheck, Maintenance, Site, SiteKind, Target, Upstream,
    };
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

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

    fn proc_entry(pid: i32, comm: &str, cmdline: &str, ppid: Option<i32>) -> ProcEntry {
        ProcEntry {
            pid,
            comm: comm.into(),
            cmdline: cmdline.into(),
            ppid,
        }
    }

    fn haproxy_in(dir: &TempDir, runtime_addr: &str) -> Haproxy {
        let root = dir.path();
        let empty_proc = root.join("proc");
        fs::create_dir_all(&empty_proc).unwrap();
        Haproxy {
            data_dir: root.join("data"),
            haproxy_dir: root.join("haproxy"),
            maps_dir: root.join("haproxy/maps"),
            pages_dir: root.join("haproxy/pages"),
            haproxy_cfg: root.join("haproxy/haproxy.cfg"),
            runtime_addr: runtime_addr.into(),
            log_addr: "127.0.0.1:5140".into(),
            haproxy_bin: "true".into(),
            validate: false,
            proc_root: empty_proc,
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
    fn master_is_the_lowest_matching_pid() {
        let procs = vec![
            proc_entry(900, "haproxy", "haproxy\0-W\0-f\0/c.cfg\0", None),
            proc_entry(40, "haproxy", "haproxy\0-W\0-db\0-f\0/c.cfg\0", None),
            proc_entry(7, "nginx", "nginx\0-W\0", None),
            proc_entry(5, "haproxy", "haproxy\0-f\0/c.cfg\0", None),
        ];
        assert_eq!(pick_master(&procs), Some(40));
        assert_eq!(pick_master(&[]), None);
        assert_eq!(pick_master(&procs[2..]), None);
    }

    #[test]
    fn workers_parented_by_a_master_are_skipped() {
        let procs = vec![
            proc_entry(30, "haproxy", "haproxy\0-W\0", Some(10)),
            proc_entry(50, "haproxy", "haproxy\0-W\0", Some(30)),
            proc_entry(60, "haproxy", "haproxy\0-W\0", Some(1)),
        ];
        assert_eq!(pick_master(&procs), Some(30));
        let wrapped = vec![
            proc_entry(80, "haproxy", "haproxy\0-W\0", Some(60)),
            proc_entry(60, "haproxy", "haproxy\0-W\0", Some(1)),
        ];
        assert_eq!(pick_master(&wrapped), Some(60));
    }

    #[test]
    fn master_flag_detection() {
        assert!(has_master_flag("haproxy\0-W\0-f\0/c\0"));
        assert!(has_master_flag("haproxy\0-Ws\0-f\0/c\0"));
        assert!(has_master_flag("haproxy\0--master-worker\0"));
        assert!(!has_master_flag("haproxy\0-f\0/Wdir/c.cfg\0"));
        assert!(!has_master_flag("haproxy\0-db\0-f\0/c\0"));
        assert!(!has_master_flag(""));
    }

    #[test]
    fn proc_text_parsing() {
        let status = "Name:\thaproxy\nState:\tS (sleeping)\nPPid:\t412\nUid:\t0\n";
        assert_eq!(parse_ppid(status), Some(412));
        assert_eq!(parse_ppid("Name:\tx\n"), None);
        assert_eq!(
            parse_info_pid("Name: HAProxy\nPid: 77\nUptime: 1d\n"),
            Some(77)
        );
        assert_eq!(parse_info_pid("Name: HAProxy\n"), None);
    }

    #[test]
    fn scan_proc_reads_fake_proc_tree() {
        let dir = tempfile::tempdir().unwrap();
        for (pid, comm, ppid) in [(21, "haproxy", 1), (22, "haproxy", 21), (23, "sh", 1)] {
            let p = dir.path().join(pid.to_string());
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(p.join("cmdline"), "haproxy\0-W\0-f\0/c.cfg\0").unwrap();
            fs::write(p.join("status"), format!("Name:\t{comm}\nPPid:\t{ppid}\n")).unwrap();
        }
        fs::create_dir_all(dir.path().join("self")).unwrap();
        assert_eq!(scan_proc(dir.path()), Some(21));
        assert_eq!(scan_proc(&dir.path().join("missing")), None);
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
        assert!(cfg.contains("stats socket ipv4@0.0.0.0:9"));
        let active = fs::read_to_string(hp.maps_dir.join("active.map")).unwrap();
        assert_eq!(active, "shop be_shop_blue\n");
        let maint = fs::read_to_string(hp.maps_dir.join("maint.map")).unwrap();
        assert_eq!(maint, "shop off\n");
        assert!(hp.pages_dir.join("_default.html").is_file());
        assert_eq!(hp.current_config_text().as_deref(), Some(cfg.as_str()));
        let status = hp.status();
        assert_eq!(status.config_hash, outcome.config_hash);
        assert!(!status.running);
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
