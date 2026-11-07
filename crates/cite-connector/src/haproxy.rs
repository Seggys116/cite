use std::borrow::Cow;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use cite_core::atomic::{ensure_dir, write_atomic};
use cite_edge::model::{BotPolicy, EdgeConfig, FirewallRule, SiteAccess, Slot};
use cite_edge::presets::{ZONE_HEADER, with_zone_locks};
use cite_edge::render::{RenderOptions, Rendered, config_hash, render, render_automatic_https};
use cite_edge::runtime::{
    BackendStat, all_servers_up, cmd_set_active, cmd_set_maintenance, cmd_show_stat, parse_stat_csv,
};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

use crate::certs::{self, LiveSet};
use crate::config::ConnectorConfig;
use crate::error::{ConnectorError, Result};
use crate::store::now_rfc3339;
use crate::zones::{Plan, ZoneStore};

const CLOUDFLARE_LIST: &str = "cloudflare.lst";
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
const REFUSED_PREFIX: &str = "haproxy refused the reload";
const STAGE_DIR: &str = ".stage";
const PUBLIC_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

#[derive(Debug, Clone, Serialize)]
pub struct ApplyOutcome {
    pub config_hash: String,
    // True only when HAProxy confirmed a reload during this call.
    pub reloaded: bool,
    // False when the master CLI could not be reached at all.
    pub running: bool,
    pub reload_error: Option<String>,
    pub reload_refused: bool,
}

impl ApplyOutcome {
    // A reachable HAProxy that did not take the new config is a failure; an absent one is the boot case.
    pub fn require_loaded(&self) -> Result<()> {
        match (&self.reload_error, self.running) {
            (Some(msg), true) if self.reload_refused => Err(ConnectorError::BadRequest(format!(
                "haproxy did not load the configuration: {msg}"
            ))),
            (Some(msg), true) => Err(ConnectorError::Unavailable(format!(
                "haproxy did not load the configuration: {msg}"
            ))),
            _ => Ok(()),
        }
    }

    // `strict` is for changes that add or alter a protection: they are only acknowledged once a running HAProxy loaded them.
    pub fn require(&self, strict: bool) -> Result<()> {
        if strict {
            self.require_running()
        } else {
            self.require_loaded()
        }
    }

    // Used where the caller needs the config live, so an unreachable HAProxy counts as a failure too.
    pub fn require_running(&self) -> Result<()> {
        match &self.reload_error {
            Some(msg) if !self.running => Err(ConnectorError::Unavailable(msg.clone())),
            _ => self.require_loaded(),
        }
    }
}

struct ReloadResult {
    reloaded: bool,
    running: bool,
    error: Option<String>,
    refused: bool,
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
    // Hash whose files are on disk.
    written: Option<String>,
    // Hash HAProxy confirmed it loaded.
    applied: Option<String>,
}

pub struct Haproxy {
    certs_dir: PathBuf,
    certs_mode: u32,
    haproxy_dir: PathBuf,
    maps_dir: PathBuf,
    pages_dir: PathBuf,
    haproxy_cfg: PathBuf,
    runtime_addr: String,
    master_addr: String,
    log_addr: String,
    haproxy_bin: String,
    validate: bool,
    zones: Arc<ZoneStore>,
    apply_lock: Mutex<()>,
    state: StdMutex<State>,
}

const REDACTED: &str = "<redacted>";

// True when `after` introduces or changes a protection (Cloudflare-only, zone lock, bot policy, Cloudflare ranges, a blocking or secret-header rule) that `before` did not have.
pub fn needs_live_haproxy(before: &EdgeConfig, after: &EdgeConfig) -> bool {
    if before.settings.cloudflare_ranges != after.settings.cloudflare_ranges {
        return true;
    }
    let guarded = |a: &SiteAccess| a.cloudflare_only || a.zone_lock || a.bots != BotPolicy::Allow;
    let site_changed = after.sites.iter().any(|site| {
        guarded(&site.access)
            && before
                .sites
                .iter()
                .find(|b| b.id == site.id)
                .is_none_or(|b| b.access != site.access)
    });
    let sensitive = |r: &FirewallRule| {
        r.enabled && (r.action.is_some() || r.matchers.headers.iter().any(|h| h.secret))
    };
    site_changed
        || after
            .firewall
            .iter()
            .any(|r| sensitive(r) && !before.firewall.contains(r))
}

// Only the rendered copy gets the automatic TLS port, so settings in edge.json stay exactly what the owner set; the flag says the port is automatic.
fn with_auto_https(edge: Cow<'_, EdgeConfig>) -> (Cow<'_, EdgeConfig>, bool) {
    let port = certs::effective_https_port(&edge);
    if port == edge.settings.https_port {
        return (edge, false);
    }
    let automatic = edge.settings.https_port.is_none();
    let mut owned = edge.into_owned();
    owned.settings.https_port = port;
    (Cow::Owned(owned), automatic)
}

fn render_with(
    edge: &EdgeConfig,
    options: &RenderOptions,
    automatic: bool,
) -> std::result::Result<Rendered, cite_edge::validate::ValidationError> {
    if automatic {
        render_automatic_https(edge, options)
    } else {
        render(edge, options)
    }
}

// HAProxy reports a taken port only as a reload failure, so the cause is named for the owner.
fn bind_hint(msg: &str, port: Option<u16>) -> String {
    let lower = msg.to_ascii_lowercase();
    match port {
        Some(port) if lower.contains("cannot bind") || lower.contains("address already in use") => {
            format!(
                "HAProxy could not bind the HTTPS port {port}; is another service using it? The previous configuration keeps serving. {msg}"
            )
        }
        _ => msg.to_string(),
    }
}

// Header secrets reach the rendered text and can be quoted back by HAProxy's own messages, so every text that leaves this module is scrubbed.
fn scrub(text: &str, secrets: &[String]) -> String {
    // longest first, so a secret that contains another is removed whole instead of leaving its tail behind
    let mut ordered: Vec<&String> = secrets.iter().filter(|s| !s.is_empty()).collect();
    ordered.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    ordered.dedup();
    let by_value = ordered
        .into_iter()
        .fold(text.to_string(), |acc, s| acc.replace(s.as_str(), REDACTED));
    zone_header_pattern()
        .replace_all(&by_value, format!("${{1}}{REDACTED}").as_str())
        .into_owned()
}

// The zone rule's value is also removed by shape, so a secret the store no longer knows (an unreadable store, a failed apply) cannot show through old text.
fn zone_header_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        let header = regex::escape(ZONE_HEADER);
        Regex::new(&format!(
            r"(?i)(req\.fhdr\({header}\) -m (?:str|reg) -- )\S+"
        ))
        .expect("the zone header pattern is valid")
    })
}

fn scrub_error(err: ConnectorError, secrets: &[String]) -> ConnectorError {
    match err {
        ConnectorError::BadRequest(m) => ConnectorError::BadRequest(scrub(&m, secrets)),
        ConnectorError::Unavailable(m) => ConnectorError::Unavailable(scrub(&m, secrets)),
        ConnectorError::Internal(m) => ConnectorError::Internal(scrub(&m, secrets)),
        other => other,
    }
}

// Every secret a rendered config can hold: the node's zone secrets and the values of user rules marked secret.
fn secret_values(edge: &EdgeConfig, zones: &ZoneStore) -> Vec<String> {
    let mut out = zones.all_secrets();
    for header in edge.firewall.iter().flat_map(|r| r.matchers.headers.iter()) {
        if header.secret {
            out.extend(header.equals.iter().chain(header.regex.iter()).cloned());
        }
    }
    out
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

// The render hash covers the text and maps; the Cloudflare list and the certificate files are inputs HAProxy reads too, so a change in either must change the hash and force a reload.
fn apply_hash(rendered: &Rendered, live: &LiveSet) -> String {
    let mut hasher = Sha256::new();
    let base = config_hash(rendered);
    for part in [
        base.as_bytes(),
        rendered.cloudflare_list.as_bytes(),
        live.digest.as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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

// Pages and maps rarely change between applies, and every atomic write costs file and directory syncs.
fn write_if_changed(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let current_mode = fs::metadata(path).map(|m| m.permissions().mode() & 0o7777);
    if current_mode.is_ok_and(|m| m == mode) && fs::read(path).is_ok_and(|cur| cur == bytes) {
        return Ok(());
    }
    write_atomic(path, bytes, mode).map_err(internal)
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
        write_if_changed(&pages_dir.join(name), html.as_bytes(), PUBLIC_MODE)?;
    }
    let maps = [
        ("active.map", &rendered.active_map),
        ("maint.map", &rendered.maint_map),
    ];
    for (name, body) in maps {
        write_if_changed(&maps_dir.join(name), body.as_bytes(), PUBLIC_MODE)?;
    }
    write_if_changed(
        &maps_dir.join(CLOUDFLARE_LIST),
        rendered.cloudflare_list.as_bytes(),
        PUBLIC_MODE,
    )?;
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
                "{REFUSED_PREFIX}: {}",
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
        // haproxy exits 0 on this warning, but a rule that can never match is not the protection it looks like
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        return match combined.lines().find(|l| l.contains("will never match")) {
            Some(line) => Err(ConnectorError::BadRequest(format!(
                "haproxy rejected the configuration: {}",
                truncate(line.trim(), MAX_ERROR_TEXT)
            ))),
            None => Ok(()),
        };
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
            certs_dir: cfg.certs_dir.clone(),
            certs_mode: cfg.certs_mode,
            haproxy_dir: cfg.haproxy_dir.clone(),
            maps_dir: cfg.maps_dir.clone(),
            pages_dir: cfg.pages_dir.clone(),
            haproxy_cfg: cfg.haproxy_cfg.clone(),
            runtime_addr: cfg.runtime_addr.clone(),
            master_addr: cfg.master_addr.clone(),
            log_addr: cfg.log_addr_for_haproxy.clone(),
            haproxy_bin: cfg.haproxy_bin.clone(),
            validate: cfg.validate_with_haproxy,
            zones: Arc::new(ZoneStore::open(cfg.data_dir.clone()).unwrap_or_else(|e| {
                tracing::error!(error = %e, "zone secrets unavailable; zone-locked sites will not render");
                ZoneStore::unreadable(cfg.data_dir.clone())
            })),
            apply_lock: Mutex::new(()),
            state: StdMutex::new(state),
        }
    }

    pub fn zones(&self) -> &Arc<ZoneStore> {
        &self.zones
    }

    // The config every render goes through: a zone-locked site gets its rule here, and a site without a secret fails closed.
    fn with_locks<'a>(&self, edge: &'a EdgeConfig, plan: &Plan) -> Result<Cow<'a, EdgeConfig>> {
        if !edge.sites.iter().any(|s| s.access.zone_lock) {
            return Ok(Cow::Borrowed(edge));
        }
        Ok(Cow::Owned(with_zone_locks(edge, |id| plan.secret_for(id))?))
    }

    async fn commit_plan(&self, plan: Plan) -> Result<()> {
        let zones = Arc::clone(&self.zones);
        tokio::task::spawn_blocking(move || zones.commit(plan))
            .await
            .map_err(internal)?
    }

    // Dry render for validating a change before it is stored; a locked site that has no secret yet is rendered with a stand-in.
    pub fn check_render(&self, cfg: &EdgeConfig) -> Result<()> {
        let opts = self.dry_options()?;
        let stand_in = "A".repeat(43);
        let locked = with_zone_locks(cfg, |id| {
            Some(
                self.zones
                    .secret_for(id)
                    .unwrap_or_else(|| stand_in.clone()),
            )
        })?;
        render(&locked, &opts)?;
        Ok(())
    }

    // The options a dry render uses: the real directories, and no TLS bind, since only the shape of the config is being checked.
    pub(crate) fn dry_options(&self) -> Result<RenderOptions> {
        self.render_options(&self.maps_dir, &self.pages_dir, &LiveSet::default())
    }

    // The live config text with every secret removed, for the API.
    pub fn redacted_config_text(&self, edge: &EdgeConfig) -> Option<String> {
        let text = self.current_config_text()?;
        Some(scrub(&text, &secret_values(edge, &self.zones)))
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

    // HAProxy refuses `ssl crt` on a directory without certificates, so the TLS bind is only rendered once one exists.
    fn render_options(
        &self,
        maps_dir: &Path,
        pages_dir: &Path,
        live: &LiveSet,
    ) -> Result<RenderOptions> {
        let tls_dir = if live.count > 0 {
            Some(path_str(&self.certs_dir)?)
        } else {
            None
        };
        Ok(RenderOptions {
            maps_dir: path_str(maps_dir)?,
            pages_dir: path_str(pages_dir)?,
            runtime_addr: stats_listen(&self.runtime_addr)?,
            log_addr: self.log_addr.clone(),
            tls_dir,
            cloudflare_file: Some(path_str(&maps_dir.join(CLOUDFLARE_LIST))?),
        })
    }

    // An equal hash is not enough on its own: a file deleted from disk has to be written again.
    fn files_current(&self, hash: &str, rendered: &Rendered) -> bool {
        let same = self.state().written.as_deref() == Some(hash);
        same && self.haproxy_cfg.is_file()
            && self.maps_dir.join("active.map").is_file()
            && self.maps_dir.join("maint.map").is_file()
            && self.maps_dir.join(CLOUDFLARE_LIST).is_file()
            && rendered
                .pages
                .iter()
                .all(|(name, _)| self.pages_dir.join(name).is_file())
    }

    // Skips both the write and the reload only when HAProxy already confirmed this exact config.
    pub async fn apply(&self, edge: &EdgeConfig) -> Result<ApplyOutcome> {
        self.apply_with(edge, false).await
    }

    // Reloads even when the hash is unchanged, so renewed certificates and a failed reload can be retried.
    pub async fn reload(&self, edge: &EdgeConfig) -> Result<ApplyOutcome> {
        self.apply_with(edge, true).await
    }

    async fn apply_with(&self, edge: &EdgeConfig, force: bool) -> Result<ApplyOutcome> {
        let _guard = self.apply_lock.lock().await;
        match self.apply_locked(edge, force).await {
            Ok(outcome) => Ok(outcome),
            Err(err) => {
                let err = scrub_error(err, &secret_values(edge, &self.zones));
                // a failure before the reload says nothing about HAProxy, which may well be up and enforcing the old config
                let up = self.runtime_pid().await.is_some();
                let mut st = self.state();
                st.status.last_error = Some(err.to_string());
                if up {
                    st.status.running = true;
                }
                Err(err)
            }
        }
    }

    // The node's own certificates are made first so the digest and the TLS bind see them, and they are put back if this apply fails.
    async fn apply_locked(&self, edge: &EdgeConfig, force: bool) -> Result<ApplyOutcome> {
        let store = certs::CertStore::new(self.certs_dir.clone(), self.certs_mode);
        let config = edge.clone();
        let now = i64::try_from(crate::store::now_unix()).unwrap_or(i64::MAX);
        let (store, undo) = tokio::task::spawn_blocking(move || {
            let undo = store.sync_auto(&config, now);
            (store, undo)
        })
        .await
        .map_err(internal)?;
        let undo = undo?;
        match self.apply_synced(edge, force).await {
            // a reload HAProxy refused is rolled back by the caller, so the certificates made for it go too
            Ok(out) if out.running && out.reload_error.is_some() => {
                let _ = tokio::task::spawn_blocking(move || store.rollback_auto(undo)).await;
                Ok(out)
            }
            Ok(out) => Ok(out),
            Err(err) => {
                let _ = tokio::task::spawn_blocking(move || store.rollback_auto(undo)).await;
                Err(err)
            }
        }
    }

    async fn apply_synced(&self, edge: &EdgeConfig, force: bool) -> Result<ApplyOutcome> {
        let locked: Vec<String> = edge
            .sites
            .iter()
            .filter(|s| s.access.zone_lock)
            .map(|s| s.id.clone())
            .collect();
        // nothing is stored or dropped until this config has loaded, so a failed apply and its rollback see the same secrets
        let plan = self.zones.plan(&locked)?;
        let mut secrets = secret_values(edge, &self.zones);
        secrets.extend(plan.secrets());
        let (effective, automatic) = with_auto_https(self.with_locks(edge, &plan)?);
        let edge: &EdgeConfig = &effective;
        let certs_dir = self.certs_dir.clone();
        let live = tokio::task::spawn_blocking(move || certs::live_set(&certs_dir))
            .await
            .map_err(internal)?;
        let options = self.render_options(&self.maps_dir, &self.pages_dir, &live)?;
        let rendered = render_with(edge, &options, automatic)?;
        let hash = apply_hash(&rendered, &live);
        let files_current = self.files_current(&hash, &rendered);
        let loaded = self.state().applied.as_deref() == Some(hash.as_str());
        if files_current && loaded && !force {
            self.commit_plan(plan).await?;
            return Ok(ApplyOutcome {
                config_hash: hash,
                reloaded: false,
                running: self.state().status.running,
                reload_error: None,
                reload_refused: false,
            });
        }
        if !files_current {
            if let Err(err) = self
                .validate_and_install(edge, &rendered, &live, automatic)
                .await
            {
                return Err(scrub_error(err, &secrets));
            }
            let mut st = self.state();
            // HAProxy may read these files at any moment, so what it loaded is unknown until a reload is confirmed
            st.applied = None;
            st.config_text = Some(rendered.config.clone());
            st.written = Some(hash.clone());
            st.status.config_hash = hash.clone();
        }
        let mut result = self.reload_master().await;
        if let Some(msg) = result.error.as_mut() {
            *msg = bind_hint(&scrub(msg, &secrets), edge.settings.https_port);
            self.state().status.last_error = Some(msg.clone());
        }
        if result.reloaded {
            self.state().applied = Some(hash.clone());
        }
        // an unreachable HAProxy counts as applied, as for every other change; a refused or unconfirmed reload does not
        if result.error.is_none() || !result.running {
            self.commit_plan(plan).await?;
        }
        Ok(ApplyOutcome {
            config_hash: hash,
            reloaded: result.reloaded,
            running: result.running,
            reload_error: result.error,
            reload_refused: result.refused,
        })
    }

    async fn validate_and_install(
        &self,
        edge: &EdgeConfig,
        rendered: &Rendered,
        live: &LiveSet,
        automatic: bool,
    ) -> Result<()> {
        if self.validate {
            self.validate_staged(edge, live, automatic).await?;
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

    // The staged copy points at its own maps and pages so the check never depends on live files; the certificate directory is the live one, so a bad certificate fails here.
    async fn validate_staged(
        &self,
        edge: &EdgeConfig,
        live: &LiveSet,
        automatic: bool,
    ) -> Result<()> {
        let stage = self.haproxy_dir.join(STAGE_DIR);
        let stage_maps = stage.join("maps");
        let stage_pages = stage.join("pages");
        let cfg_path = stage.join("haproxy.cfg");
        let options = self.render_options(&stage_maps, &stage_pages, live)?;
        let staged = render_with(edge, &options, automatic)?;
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

    async fn reload_master(&self) -> ReloadResult {
        let stream = match open(&self.master_addr, MASTER_LABEL).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!("haproxy reload skipped: {err}");
                let mut st = self.state();
                st.status.running = false;
                st.status.last_reload_ok = false;
                st.status.last_error = Some(err.to_string());
                return ReloadResult {
                    reloaded: false,
                    running: false,
                    error: Some(err.to_string()),
                    refused: false,
                };
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
        match outcome {
            Ok(()) => {
                st.status.last_reload_ok = true;
                st.status.last_error = None;
                ReloadResult {
                    reloaded: true,
                    running: true,
                    error: None,
                    refused: false,
                }
            }
            Err(msg) => {
                tracing::warn!("haproxy reload failed: {msg}");
                st.status.last_reload_ok = false;
                st.status.last_error = Some(msg.clone());
                ReloadResult {
                    reloaded: false,
                    running: true,
                    refused: msg.starts_with(REFUSED_PREFIX),
                    error: Some(msg),
                }
            }
        }
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
        self.state().written = None;
        let path = self.maps_dir.join(file);
        let (key_owned, value_owned) = (key.to_string(), value.to_string());
        tokio::task::spawn_blocking(move || rewrite_map_file(&path, &key_owned, &value_owned))
            .await
            .map_err(internal)??;
        let live = match self.runtime_command(cmd).await {
            Ok(reply) => match reply_error(&reply) {
                Some(text) => Err(internal(format!("haproxy rejected {file} update: {text}"))),
                None => Ok(()),
            },
            Err(err) => {
                tracing::warn!("{file} updated on disk only: {err}");
                Err(err)
            }
        };
        if live.is_err() {
            // The running process never saw the change, so only a reload can bring it in line.
            self.state().applied = None;
        }
        live
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
            path_regexes: Vec::new(),
            path_prefixes: Vec::new(),
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
            access: Default::default(),
            volumes: Vec::new(),
            outbound: true,
            outbound_rules: Default::default(),
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
            certs_dir: root.join("data/certs"),
            certs_mode: 0o600,
            haproxy_dir: root.join("haproxy"),
            maps_dir: root.join("haproxy/maps"),
            pages_dir: root.join("haproxy/pages"),
            haproxy_cfg: root.join("haproxy/haproxy.cfg"),
            runtime_addr: runtime_addr.into(),
            master_addr: "127.0.0.1:1".into(),
            log_addr: "127.0.0.1:5140".into(),
            haproxy_bin: "true".into(),
            validate: false,
            zones: Arc::new(ZoneStore::open(root.join("data")).unwrap()),
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
    async fn unchanged_maps_and_pages_are_not_rewritten_on_apply() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let mut cfg = edge(vec![site("shop")]);
        hp.apply(&cfg).await.unwrap();
        let inode = |p: &Path| fs::metadata(p).unwrap().ino();
        let active = hp.maps_dir.join("active.map");
        let page = hp.pages_dir.join("_default.html");
        let (map_ino, page_ino, cfg_ino) = (inode(&active), inode(&page), inode(&hp.haproxy_cfg));
        cfg.sites[0].blue.targets[0].weight = 50;
        hp.apply(&cfg).await.unwrap();
        assert_eq!(inode(&active), map_ino);
        assert_eq!(inode(&page), page_ino);
        assert_ne!(inode(&hp.haproxy_cfg), cfg_ino);
        fs::write(&active, "shop be_shop_green\n").unwrap();
        cfg.sites[0].blue.targets[0].weight = 60;
        hp.apply(&cfg).await.unwrap();
        assert_eq!(fs::read_to_string(&active).unwrap(), "shop be_shop_blue\n");
    }

    // Run with: cargo test -p cite-connector --release perf_apply -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn perf_apply_500_sites() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let mut cfg = edge((0..500).map(|i| site(&format!("s{i}"))).collect());
        let started = Instant::now();
        hp.apply(&cfg).await.unwrap();
        println!(
            "first apply: {:.2} ms",
            started.elapsed().as_secs_f64() * 1e3
        );
        let started = Instant::now();
        for _ in 0..20 {
            hp.apply(&cfg).await.unwrap();
        }
        println!(
            "hash-skip apply: {:.3} ms",
            started.elapsed().as_secs_f64() * 1e3 / 20.0
        );
        let started = Instant::now();
        for i in 0..20 {
            cfg.sites[0].blue.targets[0].weight = 50 + i;
            hp.apply(&cfg).await.unwrap();
        }
        println!(
            "changed apply (no haproxy -c, failing reload): {:.2} ms",
            started.elapsed().as_secs_f64() * 1e3 / 20.0
        );
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
    async fn a_refused_reload_is_not_recorded_so_the_next_apply_retries_it() {
        let reply = "Success=0\n--\n[ALERT] bad\n";
        let (hp, seen, _dir) = reloading_haproxy(reply).await;
        let cfg = edge(vec![site("shop")]);
        let first = hp.apply(&cfg).await.unwrap();
        assert!(!first.reloaded && first.running && first.reload_refused);
        assert!(matches!(
            first.require_loaded(),
            Err(ConnectorError::BadRequest(_))
        ));
        let second = hp.apply(&cfg).await.unwrap();
        assert!(!second.reloaded);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_unconfirmed_reload_is_unavailable_and_retried() {
        let (master, seen) = fake_runtime(|_| "Success=1\n--\nok\n".to_string()).await;
        let (runtime, _) = fake_runtime(|_| "Pid: 7\n".to_string()).await;
        let dir = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&dir, &runtime);
        hp.master_addr = master;
        let cfg = edge(vec![site("shop")]);
        let first = hp.apply(&cfg).await.unwrap();
        assert!(!first.reloaded && first.running && !first.reload_refused);
        assert!(matches!(
            first.require_loaded(),
            Err(ConnectorError::Unavailable(_))
        ));
        hp.apply(&cfg).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_absent_haproxy_is_tolerated_by_apply_but_not_by_a_forced_reload() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let out = hp.apply(&edge(vec![site("shop")])).await.unwrap();
        assert!(!out.running && !out.reloaded);
        assert!(out.require_loaded().is_ok());
        assert!(matches!(
            out.require_running(),
            Err(ConnectorError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn reload_forces_a_reload_of_an_already_confirmed_config() {
        let (hp, seen, _dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        let cfg = edge(vec![site("shop")]);
        assert!(hp.apply(&cfg).await.unwrap().reloaded);
        assert!(!hp.apply(&cfg).await.unwrap().reloaded);
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(hp.reload(&cfg).await.unwrap().reloaded);
        assert_eq!(seen.lock().unwrap().len(), 2);
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

    fn locked_edge() -> EdgeConfig {
        let mut shop = site("shop");
        shop.access.cloudflare_only = true;
        shop.access.zone_lock = true;
        edge(vec![shop, site("blog")])
    }

    #[tokio::test]
    async fn a_zone_locked_site_gets_a_generated_secret_in_the_rendered_config_only() {
        let (hp, seen, dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        fs::create_dir_all(dir.path().join("data")).unwrap();
        let cfg = locked_edge();
        assert!(hp.apply(&cfg).await.unwrap().reloaded);
        let secret = hp.zones().secret_for("shop").expect("generated");
        assert_eq!(secret.len(), 43);
        assert!(hp.zones().secret_for("blog").is_none());
        let text = hp.current_config_text().unwrap();
        assert!(text.contains(&secret), "the rule must be in the config");
        assert!(!hp.redacted_config_text(&cfg).unwrap().contains(&secret));
        let stored = fs::read_to_string(dir.path().join("data/zone-secrets.json")).unwrap();
        assert!(stored.contains(&secret));
        assert!(!hp.apply(&cfg).await.unwrap().reloaded);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rotating_the_secret_changes_the_hash_and_reloads() {
        let (hp, seen, dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        fs::create_dir_all(dir.path().join("data")).unwrap();
        let cfg = locked_edge();
        let first = hp.apply(&cfg).await.unwrap();
        let old = hp.zones().secret_for("shop").unwrap();
        hp.zones().rotate("shop").unwrap();
        let second = hp.apply(&cfg).await.unwrap();
        assert!(second.reloaded);
        assert_ne!(first.config_hash, second.config_hash);
        assert!(
            hp.zones().secret_for("shop").unwrap() != old,
            "the secret must change"
        );
        assert!(!hp.current_config_text().unwrap().contains(&old));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn turning_the_lock_off_or_deleting_the_site_drops_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("data")).unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.apply(&locked_edge()).await.unwrap();
        assert!(hp.zones().has_any());
        hp.apply(&edge(vec![site("shop")])).await.unwrap();
        assert!(!hp.zones().has_any());
        let stored = fs::read_to_string(dir.path().join("data/zone-secrets.json")).unwrap();
        assert_eq!(stored.trim(), "{}");
        assert!(
            !hp.current_config_text()
                .unwrap()
                .contains("X-Cite-Origin-Secret")
        );
    }

    #[tokio::test]
    async fn a_locked_site_without_a_readable_secret_store_is_never_rendered() {
        let dir = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.zones = Arc::new(ZoneStore::unreadable(dir.path().join("data")));
        let err = hp.apply(&locked_edge()).await.unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)), "{err:?}");
        assert!(!hp.haproxy_cfg.exists());
        assert!(hp.check_render(&locked_edge()).is_ok());
    }

    #[tokio::test]
    async fn an_apply_that_fails_early_still_records_the_error_and_that_haproxy_is_up() {
        let (mut hp, _seen, dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        hp.zones = Arc::new(ZoneStore::unreadable(dir.path().join("data")));
        assert!(hp.status().last_error.is_none() && !hp.status().running);
        let err = hp.apply(&locked_edge()).await.unwrap_err();
        let status = hp.status();
        assert_eq!(status.last_error.as_deref(), Some(err.to_string().as_str()));
        assert!(
            status.running,
            "the runtime socket answers, so HAProxy is up"
        );
    }

    #[tokio::test]
    async fn files_written_without_a_confirmed_reload_force_the_next_apply_to_reload() {
        let (mut hp, seen, _dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        let good = hp.master_addr.clone();
        let (one, two) = (
            edge(vec![site("shop")]),
            edge(vec![site("shop"), site("blog")]),
        );
        assert!(hp.apply(&one).await.unwrap().reloaded);
        hp.master_addr = "127.0.0.1:1".into();
        assert!(!hp.apply(&two).await.unwrap().running);
        assert!(!hp.apply(&one).await.unwrap().running);
        hp.master_addr = good;
        assert!(
            hp.apply(&one).await.unwrap().reloaded,
            "an unconfirmed write must not be skipped"
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    const REFUSED: &str = "Success=0\n--\n[ALERT] refused\n";

    #[tokio::test]
    async fn a_refused_reload_that_drops_a_lock_keeps_the_secret_for_the_rollback() {
        let (hp, _seen, dir) = reloading_haproxy(REFUSED).await;
        fs::create_dir_all(dir.path().join("data")).unwrap();
        let s1 = hp.zones().rotate("shop").unwrap().secret.to_string();
        let file = dir.path().join("data/zone-secrets.json");

        let off = hp
            .apply(&edge(vec![site("shop"), site("blog")]))
            .await
            .unwrap();
        assert!(off.running && off.reload_error.is_some());
        assert!(
            hp.zones().secret_for("shop").as_deref() == Some(s1.as_str()),
            "the stored secret changed"
        );
        assert!(fs::read_to_string(&file).unwrap().contains(&s1));

        let back = hp.apply(&locked_edge()).await.unwrap();
        assert!(back.reload_error.is_some());
        assert!(
            hp.zones().secret_for("shop").as_deref() == Some(s1.as_str()),
            "the stored secret changed"
        );
        assert!(hp.current_config_text().unwrap().contains(&s1));
        assert!(fs::read_to_string(&file).unwrap().contains(&s1));
    }

    #[tokio::test]
    async fn a_refused_reload_that_deletes_a_locked_site_keeps_its_secret() {
        let (hp, _seen, dir) = reloading_haproxy(REFUSED).await;
        fs::create_dir_all(dir.path().join("data")).unwrap();
        let s1 = hp.zones().rotate("shop").unwrap().secret.to_string();
        let gone = hp.apply(&edge(vec![site("blog")])).await.unwrap();
        assert!(gone.reload_error.is_some());
        assert!(
            hp.zones().secret_for("shop").as_deref() == Some(s1.as_str()),
            "the stored secret changed"
        );
        hp.apply(&locked_edge()).await.unwrap();
        assert!(hp.current_config_text().unwrap().contains(&s1));
    }

    #[tokio::test]
    async fn a_confirmed_reload_commits_new_secrets_and_prunes_old_ones() {
        let (hp, _seen, dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        fs::create_dir_all(dir.path().join("data")).unwrap();
        hp.zones().rotate("old").unwrap();
        assert!(hp.apply(&locked_edge()).await.unwrap().reloaded);
        assert!(hp.zones().secret_for("shop").is_some());
        assert!(hp.zones().secret_for("old").is_none());
    }

    #[tokio::test]
    async fn the_config_text_is_redacted_by_shape_even_with_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.state().config_text = Some(
            "    http-request deny if !{ req.fhdr(X-Cite-Origin-Secret) -m str -- AbCd0123-_xyz }\n    acl a req.fhdr(user-agent) -m reg -- bot\n"
                .into(),
        );
        let shown = hp.redacted_config_text(&edge(vec![])).unwrap();
        assert!(!shown.contains("AbCd0123"), "{shown}");
        assert!(shown.contains("-- <redacted> }"), "{shown}");
        assert!(shown.contains("-m reg -- bot"), "{shown}");
        let err = scrub_error(
            ConnectorError::BadRequest(
                "bad line req.fhdr(x-cite-origin-secret) -m str -- Zz9".into(),
            ),
            &[],
        );
        assert!(!err.to_string().contains("Zz9"));
    }

    #[tokio::test]
    async fn a_never_matching_rule_warning_fails_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let script = tools.path().join("fake-haproxy");
        fs::write(
            &script,
            "#!/bin/sh\nif [ -e \"$(dirname \"$0\")/warn\" ]; then echo \"[WARNING] (1) : config : anonymous acl will never match because it uses keyword 'req.fhdr'\" >&2; fi\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.validate = true;
        hp.haproxy_bin = script.display().to_string();
        hp.apply(&edge(vec![site("shop")])).await.unwrap();
        let live = fs::read_to_string(&hp.haproxy_cfg).unwrap();
        fs::write(tools.path().join("warn"), "").unwrap();
        let err = hp
            .apply(&edge(vec![site("shop"), site("blog")]))
            .await
            .unwrap_err();
        let ConnectorError::BadRequest(msg) = &err else {
            panic!("expected BadRequest, got {err:?}");
        };
        assert!(msg.contains("will never match"), "{msg}");
        assert_eq!(fs::read_to_string(&hp.haproxy_cfg).unwrap(), live);
    }

    #[test]
    fn a_secret_inside_another_secret_leaves_no_tail_behind() {
        let secrets = vec![
            "token123".to_string(),
            "token123456789".to_string(),
            "token123".to_string(),
        ];
        assert_eq!(
            scrub("v=token123456789 w=token123", &secrets),
            "v=<redacted> w=<redacted>"
        );
    }

    #[test]
    fn only_protection_changes_need_a_running_haproxy() {
        let base = edge(vec![site("shop")]);
        assert!(!needs_live_haproxy(&base, &base));
        let mut page = base.clone();
        page.sites[0].name = "renamed".into();
        assert!(!needs_live_haproxy(&base, &page));

        let changes: [fn(&mut EdgeConfig); 5] = [
            |c: &mut EdgeConfig| c.sites[0].access.cloudflare_only = true,
            |c: &mut EdgeConfig| c.sites[0].access.zone_lock = true,
            |c: &mut EdgeConfig| c.sites[0].access.bots = BotPolicy::BlockBad,
            |c: &mut EdgeConfig| c.settings.cloudflare_ranges = vec!["192.0.2.0/24".into()],
            |c: &mut EdgeConfig| {
                c.firewall.push(FirewallRule {
                    id: "deny".into(),
                    name: "deny".into(),
                    enabled: true,
                    action: Some(cite_edge::model::FirewallAction::Deny),
                    ..FirewallRule::default()
                })
            },
        ];
        for change in changes {
            let mut changed = base.clone();
            change(&mut changed);
            assert!(needs_live_haproxy(&base, &changed));
            assert!(!needs_live_haproxy(&changed, &changed));
        }
        let mut locked = base.clone();
        locked.sites[0].access.cloudflare_only = true;
        assert!(
            !needs_live_haproxy(&locked, &base),
            "removing a protection is tolerant"
        );
    }

    #[test]
    fn a_strict_apply_fails_when_haproxy_is_absent_and_a_tolerant_one_does_not() {
        let out = ApplyOutcome {
            config_hash: String::new(),
            reloaded: false,
            running: false,
            reload_error: Some("master CLI unreachable".into()),
            reload_refused: false,
        };
        assert!(out.require(false).is_ok());
        assert!(matches!(
            out.require(true),
            Err(ConnectorError::Unavailable(_))
        ));
    }

    #[test]
    fn scrubbing_removes_every_secret_from_text() {
        let secrets = vec!["s3cret-one".to_string(), String::new(), "two".to_string()];
        let text = scrub("a s3cret-one b two c s3cret-one", &secrets);
        assert_eq!(text, "a <redacted> b <redacted> c <redacted>");
    }

    fn put_cert(hp: &Haproxy, id_char: char, body: &str) {
        fs::create_dir_all(&hp.certs_dir).unwrap();
        let text = format!(
            "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
        );
        let name = format!("{}.pem", id_char.to_string().repeat(26));
        fs::write(hp.certs_dir.join(name), text).unwrap();
    }

    fn with_https(sites: Vec<Site>) -> EdgeConfig {
        let mut cfg = edge(sites);
        cfg.settings.https_port = Some(8443);
        cfg
    }

    #[tokio::test]
    async fn the_tls_bind_follows_the_certificates_in_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let cfg = with_https(vec![site("shop")]);
        let bind = format!("bind :8443 ssl crt {}", hp.certs_dir.display());

        let none = hp.apply(&cfg).await.unwrap();
        assert!(!hp.current_config_text().unwrap().contains("ssl crt"));

        fs::create_dir_all(&hp.certs_dir).unwrap();
        let empty = hp.apply(&cfg).await.unwrap();
        assert_eq!(empty.config_hash, none.config_hash);
        assert!(!hp.current_config_text().unwrap().contains("ssl crt"));

        put_cert(&hp, 'A', "one");
        let one = hp.apply(&cfg).await.unwrap();
        assert!(hp.current_config_text().unwrap().contains(&bind));
        assert_ne!(one.config_hash, none.config_hash);

        put_cert(&hp, 'A', "renewed");
        let renewed = hp.apply(&cfg).await.unwrap();
        assert_ne!(renewed.config_hash, one.config_hash);
        assert!(hp.current_config_text().unwrap().contains(&bind));

        fs::remove_file(hp.certs_dir.join(format!("{}.pem", "A".repeat(26)))).unwrap();
        let gone = hp.apply(&cfg).await.unwrap();
        assert_eq!(gone.config_hash, none.config_hash);
        assert!(!hp.current_config_text().unwrap().contains("ssl crt"));
    }

    #[tokio::test]
    async fn a_new_certificate_reloads_haproxy_although_the_site_config_is_unchanged() {
        let (hp, seen, _dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        let cfg = with_https(vec![site("shop")]);
        assert!(hp.apply(&cfg).await.unwrap().reloaded);
        assert!(!hp.apply(&cfg).await.unwrap().reloaded);
        put_cert(&hp, 'B', "fresh");
        assert!(hp.apply(&cfg).await.unwrap().reloaded);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn the_cloudflare_list_is_written_with_the_maps_and_a_change_reloads() {
        let (hp, seen, _dir) = reloading_haproxy("Success=1\n--\nok\n").await;
        let mut shop = site("shop");
        shop.access.cloudflare_only = true;
        let mut cfg = edge(vec![shop]);
        assert!(hp.apply(&cfg).await.unwrap().reloaded);
        let list = hp.maps_dir.join(CLOUDFLARE_LIST);
        let text = fs::read_to_string(&list).unwrap();
        assert!(text.lines().any(|l| l == "173.245.48.0/20"), "{text}");
        let mode = fs::metadata(&list).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, PUBLIC_MODE);
        let config = hp.current_config_text().unwrap();
        assert!(config.contains(&list.display().to_string()), "{config}");

        cfg.settings.cloudflare_ranges = vec!["192.0.2.0/24".into()];
        assert!(hp.apply(&cfg).await.unwrap().reloaded);
        assert_eq!(fs::read_to_string(&list).unwrap().trim(), "192.0.2.0/24");
        assert_eq!(seen.lock().unwrap().len(), 2);

        fs::remove_file(&list).unwrap();
        hp.apply(&cfg).await.unwrap();
        assert!(list.is_file());
    }

    #[tokio::test]
    async fn validation_checks_the_staged_config_against_the_live_certificate_directory() {
        let dir = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let script = tools.path().join("fake-haproxy");
        fs::write(
            &script,
            "#!/bin/sh\ncp \"$3\" \"$(dirname \"$0\")/capture.cfg\"\n[ -e \"$(dirname \"$0\")/fail\" ] && exit 1\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.validate = true;
        hp.haproxy_bin = script.display().to_string();
        let cfg = with_https(vec![site("shop")]);
        put_cert(&hp, 'C', "good");
        hp.apply(&cfg).await.unwrap();
        let captured = fs::read_to_string(tools.path().join("capture.cfg")).unwrap();
        assert!(
            captured.contains(&format!("ssl crt {}", hp.certs_dir.display())),
            "{captured}"
        );
        let live = fs::read_to_string(&hp.haproxy_cfg).unwrap();

        fs::write(tools.path().join("fail"), "").unwrap();
        put_cert(&hp, 'D', "bad");
        let err = hp.apply(&cfg).await.unwrap_err();
        assert!(matches!(err, ConnectorError::BadRequest(_)), "{err:?}");
        assert_eq!(fs::read_to_string(&hp.haproxy_cfg).unwrap(), live);
    }

    // The init step in docker-compose.node.yml writes these lines when no haproxy.cfg exists yet.
    const BOOTSTRAP: [&str; 10] = [
        "global",
        "    maxconn 256",
        "defaults",
        "    mode http",
        "    timeout connect 5s",
        "    timeout client 30s",
        "    timeout server 30s",
        "frontend fe_boot",
        "    bind :80",
        "    http-request return status 404 content-type text/plain string \"no sites configured yet\"",
    ];

    #[test]
    fn the_compose_bootstrap_matches_the_text_checked_here() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let compose = fs::read_to_string(root.join("docker-compose.node.yml")).unwrap();
        for line in BOOTSTRAP {
            assert!(
                compose.contains(&format!("'{line}'")),
                "missing from the init command: {line}"
            );
        }
        assert_eq!(
            compose.matches("fe_boot").count(),
            1,
            "the bootstrap text lives in one place"
        );
    }

    #[test]
    fn the_bootstrap_config_passes_haproxy_check() {
        let found = std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join("haproxy"))
                .find(|candidate| candidate.is_file())
        });
        let Some(bin) = found else {
            eprintln!("skipped: no haproxy binary in PATH");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.cfg");
        fs::write(&path, format!("{}\n", BOOTSTRAP.join("\n"))).unwrap();
        let out = std::process::Command::new(bin)
            .arg("-c")
            .arg("-f")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn behind_cloudflare(id: &str) -> Site {
        let mut s = site(id);
        s.access.cloudflare_only = true;
        s
    }

    #[tokio::test]
    async fn a_cloudflare_site_gets_an_automatic_certificate_and_the_tls_bind_without_any_setting()
    {
        let dir = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let script = tools.path().join("fake-haproxy");
        fs::write(
            &script,
            "#!/bin/sh\ncp \"$3\" \"$(dirname \"$0\")/capture.cfg\"\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.validate = true;
        hp.haproxy_bin = script.display().to_string();
        let cfg = edge(vec![behind_cloudflare("shop")]);

        hp.apply(&cfg).await.unwrap();
        let file = hp.certs_dir.join("auto-shop.pem");
        assert!(file.is_file(), "the automatic certificate is on disk");
        let bind = format!("bind :443 ssl crt {}", hp.certs_dir.display());
        assert!(hp.current_config_text().unwrap().contains(&bind));
        let checked = fs::read_to_string(tools.path().join("capture.cfg")).unwrap();
        assert!(checked.contains(&bind), "haproxy -c saw the TLS bind");
        assert!(
            cfg.settings.https_port.is_none(),
            "edge.json settings are untouched"
        );

        // a node without such a site keeps today's behaviour
        let plain = edge(vec![site("shop")]);
        hp.apply(&plain).await.unwrap();
        assert!(!file.exists());
        assert!(!hp.current_config_text().unwrap().contains("ssl crt"));
    }

    #[tokio::test]
    async fn an_explicit_https_port_wins_over_the_automatic_one() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let mut cfg = edge(vec![behind_cloudflare("shop")]);
        cfg.settings.https_port = Some(8443);
        hp.apply(&cfg).await.unwrap();
        let text = hp.current_config_text().unwrap();
        assert!(text.contains("bind :8443 ssl crt") && !text.contains("bind :443"));
    }

    #[tokio::test]
    async fn a_failed_check_puts_the_automatic_certificates_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut hp = haproxy_in(&dir, "127.0.0.1:9");
        hp.validate = true;
        hp.haproxy_bin = "false".into();
        let cfg = edge(vec![behind_cloudflare("shop")]);
        assert!(hp.apply(&cfg).await.is_err());
        assert!(!hp.certs_dir.join("auto-shop.pem").exists());
    }

    #[tokio::test]
    async fn a_refused_reload_puts_the_automatic_certificates_back() {
        let (hp, _seen, _dir) = reloading_haproxy(REFUSED).await;
        let out = hp
            .apply(&edge(vec![behind_cloudflare("shop")]))
            .await
            .unwrap();
        assert!(out.running && out.reload_error.is_some());
        assert!(!hp.certs_dir.join("auto-shop.pem").exists());
    }

    #[tokio::test]
    async fn automatic_certificates_cover_only_cloudflare_aware_sites() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let cfg = edge(vec![site("plain"), behind_cloudflare("shop")]);
        hp.apply(&cfg).await.unwrap();
        assert!(hp.certs_dir.join("auto-shop.pem").is_file());
        assert!(!hp.certs_dir.join("auto-plain.pem").exists());
    }

    #[tokio::test]
    async fn https_port_zero_never_binds_the_automatic_listener() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        let mut cfg = edge(vec![behind_cloudflare("shop")]);
        cfg.settings.https_port = Some(0);
        hp.apply(&cfg).await.unwrap();
        assert!(!hp.certs_dir.join("auto-shop.pem").exists());
        assert!(!hp.current_config_text().unwrap().contains("ssl crt"));
    }

    #[test]
    fn a_taken_https_port_is_named_in_the_reload_error() {
        let hint = bind_hint(
            "[ALERT] cannot bind socket (Address already in use) for [0.0.0.0:443]",
            Some(443),
        );
        assert!(hint.contains("HTTPS port 443") && hint.contains("keeps serving"));
        assert_eq!(bind_hint("something else", Some(443)), "something else");
        assert_eq!(bind_hint("cannot bind", None), "cannot bind");
    }

    #[tokio::test]
    async fn a_bootstrap_file_on_disk_never_counts_as_an_applied_config() {
        let dir = tempfile::tempdir().unwrap();
        let hp = haproxy_in(&dir, "127.0.0.1:9");
        fs::create_dir_all(hp.haproxy_cfg.parent().unwrap()).unwrap();
        fs::write(&hp.haproxy_cfg, format!("{}\n", BOOTSTRAP.join("\n"))).unwrap();
        let first = hp.apply(&edge(Vec::new())).await.unwrap();
        let written = fs::read_to_string(&hp.haproxy_cfg).unwrap();
        assert!(
            !written.contains("fe_boot") && written.contains("be_notfound"),
            "{written}"
        );
        // with no HAProxy to confirm a load, the same config is tried again rather than skipped
        assert!(!first.reloaded);
        let again = hp.apply(&edge(Vec::new())).await.unwrap();
        assert!(!again.reloaded && hp.state().applied.is_none());
    }
}
