use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;

use crate::argv::{split_command, validate_start_argv};
use crate::duration::{PollInterval, parse_byte_size, parse_duration, parse_poll_interval};
use crate::error::{Error, Result};
use crate::schema::{HealthExpect, RuntimeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderingSetting {
    Auto,
    Static,
    Ssr,
}

#[derive(Clone, PartialEq, Eq)]
pub enum GithubToken {
    Env(String),
    File(PathBuf),
}

impl std::fmt::Debug for GithubToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env(_) => f.write_str("Env(<redacted>)"),
            Self::File(path) => write!(f, "File({})", path.display()),
        }
    }
}

impl GithubToken {
    fn from_env(env: &HashMap<String, String>) -> Self {
        match (
            env.get("CITE_GITHUB_TOKEN"),
            env.get("CITE_GITHUB_TOKEN_FILE"),
        ) {
            (Some(token), _) if !token.trim().is_empty() => Self::Env(token.clone()),
            (_, Some(path)) if !path.trim().is_empty() => Self::File(PathBuf::from(path)),
            _ => Self::Env(String::new()),
        }
    }

    pub fn read(&self) -> Result<String> {
        let token = match self {
            Self::Env(token) => token.trim().to_string(),
            Self::File(path) => read_token_file(path)?,
        };
        if token.is_empty() {
            return Err(Error::Config(
                "no GitHub token: set CITE_GITHUB_TOKEN (or CITE_GITHUB_TOKEN_FILE)".into(),
            ));
        }
        Ok(token)
    }
}

/// The token file must be a regular file readable only by its owner, so a build uid cannot read it.
fn read_token_file(path: &Path) -> Result<String> {
    let fail = |why: &str| {
        Error::Config(format!(
            "cannot read CITE_GITHUB_TOKEN_FILE {}: {why}",
            path.display()
        ))
    };
    let (mut file, meta) =
        crate::atomic::open_regular(path).map_err(|err| fail(&err.to_string()))?;
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());
    if mode & 0o077 != 0 {
        return Err(fail(&format!(
            "mode {:04o} lets other users read it; run chmod 600",
            mode & 0o7777
        )));
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(&mut file, 65_536), &mut text)
        .map_err(|err| fail(&err.to_string()))?;
    Ok(text.trim().to_string())
}

const HOST_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "HOSTNAME",
    "TERM",
    "RUST_LOG",
    "SSL_CERT_FILE",
    "NODE_VERSION",
    "YARN_VERSION",
];

#[derive(Clone, Default, PartialEq, Eq)]
pub struct SiteEnv {
    file: PathBuf,
    vars: BTreeMap<String, String>,
}

impl std::fmt::Debug for SiteEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteEnv")
            .field("file", &self.file)
            .field("keys", &self.vars.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SiteEnv {
    fn from_env(env: &HashMap<String, String>, file: PathBuf) -> Self {
        let vars = env
            .iter()
            .filter(|(key, _)| !key.starts_with("CITE_") && !HOST_ENV.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Self { file, vars }
    }

    pub fn resolve(&self) -> Result<BTreeMap<String, String>> {
        let mut vars = self.vars.clone();
        match std::fs::read_to_string(&self.file) {
            Ok(text) => vars.extend(parse_env_file(&text)?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        Ok(vars)
    }
}

#[derive(Debug, Clone)]
pub struct ManagerConfig {
    pub repo: String,
    pub owner: String,
    pub name: String,
    pub branch: String,
    pub github_token: GithubToken,
    pub poll: PollInterval,
    pub min_poll: Duration,
    pub rendering: RenderingSetting,
    pub framework: String,
    pub root_dir: String,
    pub package_manager: String,
    pub install_command: Option<String>,
    pub build_command: Option<String>,
    pub output_dir: Option<String>,
    pub start_command: Option<String>,
    pub prune: Option<bool>,
    pub health_path: String,
    pub health_timeout: Duration,
    pub health_expect: HealthExpect,
    pub health_consecutive: u32,
    pub spa_fallback: Option<String>,
    pub warm_grace: Duration,
    pub watch: Duration,
    pub build_timeout: Duration,
    pub build_cache: bool,
    pub cache_max_bytes: u64,
    pub max_source_compressed_bytes: u64,
    pub max_source_bytes: u64,
    pub max_work_bytes: u64,
    pub max_release_bytes: u64,
    pub min_free_bytes: u64,
    pub max_entries: u64,
    pub build_env: SiteEnv,
    pub github_api_url: String,
    pub node_major: String,
    pub runtime: RuntimeKind,
    pub paths: Vec<String>,
    pub releases_dir: PathBuf,
    pub control_dir: PathBuf,
    pub status_dir: PathBuf,
    pub state_dir: PathBuf,
    pub work_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub socket_path: PathBuf,
    pub build_uid: u32,
    pub build_gid: u32,
    pub dev_same_user: bool,
}

#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub listen: SocketAddr,
    pub port_base: u16,
    pub trusted_proxies: Vec<IpNet>,
    pub allowed_hosts: Vec<String>,
    pub max_body: u64,
    pub static_headers: Vec<(String, String)>,
    pub releases_dir: PathBuf,
    pub control_dir: PathBuf,
    pub status_dir: PathBuf,
    pub runtime: RuntimeKind,
    pub node_major: String,
    pub node_bin: String,
    pub bun_bin: String,
    pub warm_grace: Duration,
    pub watch: Duration,
    pub runtime_env: SiteEnv,
    pub connect_timeout: Duration,
    pub header_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_connections: usize,
    pub access_log: bool,
    pub crash_limit: u32,
    pub crash_window: Duration,
    /// Concurrent connections allowed per client address; 0 disables the cap.
    pub max_conn_per_ip: usize,
    /// Requests per second per client; 0 disables rate limiting and bans.
    pub rate_limit: u32,
    pub rate_burst: u32,
    /// Rate-limited requests within ten seconds that trigger a ban.
    pub ban_threshold: u32,
    pub ban_duration: Duration,
    pub version: String,
    pub child_term_grace: Duration,
}

impl ManagerConfig {
    pub fn load() -> Result<Self> {
        let env: HashMap<String, String> = std::env::vars().collect();
        let toml_text = read_optional_config(&env)?;
        Self::load_from(&env, toml_text.as_deref())
    }

    pub fn load_from(env: &HashMap<String, String>, toml_text: Option<&str>) -> Result<Self> {
        let file = parse_toml(toml_text)?;
        let repo = pick(env, &file, "CITE_REPO", "repo", "");
        if repo.is_empty() {
            return Err(Error::Config("CITE_REPO is required (owner/name)".into()));
        }
        let (owner, name) = split_repo(&repo)?;
        let min_poll = parse_duration(&pick(env, &file, "CITE_MIN_POLL", "min_poll", "60s"))?;
        let poll = parse_poll_interval(
            &pick(env, &file, "CITE_POLL_INTERVAL", "poll_interval", "5m"),
            min_poll,
        )?;
        let root_dir = pick(env, &file, "CITE_ROOT_DIR", "root_dir", ".");
        check_rel_path(&root_dir)?;
        let install_command = pick_opt(env, &file, "CITE_INSTALL_COMMAND", "install_command")?;
        let build_command = pick_opt(env, &file, "CITE_BUILD_COMMAND", "build_command")?;
        let output_dir = pick_opt(env, &file, "CITE_OUTPUT_DIR", "output_dir")?;
        let start_command = pick_opt(env, &file, "CITE_START_COMMAND", "start_command")?;
        if let Some(cmd) = &install_command {
            check_shell_command(cmd)?;
        }
        if let Some(cmd) = &build_command {
            check_shell_command(cmd)?;
        }
        if let Some(dir) = &output_dir {
            check_rel_path(dir)?;
        }
        if let Some(cmd) = &start_command {
            let argv = split_command(cmd)?;
            validate_start_argv(&argv)?;
        }
        let spa = pick_opt(env, &file, "CITE_SPA_FALLBACK", "spa_fallback")?;
        if let Some(path) = &spa {
            check_rel_path(path)?;
        }
        let data = pick(env, &file, "CITE_DATA_DIR", "data_dir", "/var/lib/cite");
        let cfg = Self {
            repo,
            owner,
            name,
            branch: check_branch(&pick(env, &file, "CITE_BRANCH", "branch", "main"))?,
            github_token: GithubToken::from_env(env),
            poll,
            min_poll,
            rendering: parse_rendering(&pick(env, &file, "CITE_RENDERING", "rendering", "auto"))?,
            framework: pick(env, &file, "CITE_FRAMEWORK", "framework", "auto"),
            root_dir,
            package_manager: parse_pm(&pick(
                env,
                &file,
                "CITE_PACKAGE_MANAGER",
                "package_manager",
                "auto",
            ))?,
            install_command,
            build_command,
            output_dir,
            start_command,
            prune: pick_bool_opt(env, &file, "CITE_PRUNE", "prune")?,
            health_path: {
                let path = pick(env, &file, "CITE_HEALTH_PATH", "health_path", "/");
                if !path.starts_with('/') {
                    return Err(Error::Config("CITE_HEALTH_PATH must start with /".into()));
                }
                path
            },
            health_timeout: parse_duration(&pick(
                env,
                &file,
                "CITE_HEALTH_TIMEOUT",
                "health_timeout",
                "60s",
            ))?,
            health_expect: parse_expect(&pick(
                env,
                &file,
                "CITE_HEALTH_EXPECT",
                "health_expect",
                "non2xx-ok",
            ))?,
            health_consecutive: parse_u32(
                &pick(
                    env,
                    &file,
                    "CITE_HEALTH_CONSECUTIVE",
                    "health_consecutive",
                    "2",
                ),
                "CITE_HEALTH_CONSECUTIVE",
            )?,
            spa_fallback: spa,
            warm_grace: parse_duration(&pick(env, &file, "CITE_WARM_GRACE", "warm_grace", "24h"))?,
            watch: parse_duration(&pick(env, &file, "CITE_WATCH", "watch", "10m"))?,
            build_timeout: parse_duration(&pick(
                env,
                &file,
                "CITE_BUILD_TIMEOUT",
                "build_timeout",
                "15m",
            ))?,
            build_cache: !matches!(
                pick(env, &file, "CITE_BUILD_CACHE", "build_cache", "on")
                    .to_ascii_lowercase()
                    .as_str(),
                "off" | "false" | "0"
            ),
            cache_max_bytes: parse_byte_size(&pick(
                env,
                &file,
                "CITE_CACHE_MAX_BYTES",
                "cache_max_bytes",
                "2GB",
            ))?,
            max_source_compressed_bytes: parse_byte_size(&pick(
                env,
                &file,
                "CITE_MAX_SOURCE_COMPRESSED_BYTES",
                "max_source_compressed_bytes",
                "1GB",
            ))?,
            max_source_bytes: parse_byte_size(&pick(
                env,
                &file,
                "CITE_MAX_SOURCE_BYTES",
                "max_source_bytes",
                "2GB",
            ))?,
            max_work_bytes: parse_byte_size(&pick(
                env,
                &file,
                "CITE_MAX_WORK_BYTES",
                "max_work_bytes",
                "4GB",
            ))?,
            max_release_bytes: parse_byte_size(&pick(
                env,
                &file,
                "CITE_MAX_RELEASE_BYTES",
                "max_release_bytes",
                "1.5GB",
            ))?,
            min_free_bytes: parse_byte_size(&pick(
                env,
                &file,
                "CITE_MIN_FREE_BYTES",
                "min_free_bytes",
                "2GB",
            ))?,
            max_entries: parse_u64(
                &pick(env, &file, "CITE_MAX_ENTRIES", "max_entries", "300000"),
                "CITE_MAX_ENTRIES",
            )?,
            build_env: SiteEnv::from_env(
                env,
                PathBuf::from(pick(
                    env,
                    &file,
                    "CITE_BUILD_ENV_FILE",
                    "build_env_file",
                    "/run/cite/build.env",
                )),
            ),
            github_api_url: pick(
                env,
                &file,
                "CITE_GITHUB_API_URL",
                "github_api_url",
                "https://api.github.com",
            ),
            node_major: pick(env, &file, "CITE_NODE", "node", "22"),
            runtime: parse_runtime(&pick(env, &file, "CITE_RUNTIME", "runtime", "node"))?,
            paths: split_list(&pick(env, &file, "CITE_PATHS", "paths", "")),
            releases_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_RELEASES_DIR",
                "releases_dir",
                &format!("{data}/releases"),
            )),
            control_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_CONTROL_DIR",
                "control_dir",
                &format!("{data}/control"),
            )),
            status_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_STATUS_DIR",
                "status_dir",
                &format!("{data}/status"),
            )),
            state_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_STATE_DIR",
                "state_dir",
                &format!("{data}/state"),
            )),
            work_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_WORK_DIR",
                "work_dir",
                "/var/lib/cite-work",
            )),
            cache_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_CACHE_DIR",
                "cache_dir",
                "/var/lib/cite-cache",
            )),
            socket_path: PathBuf::from(pick(
                env,
                &file,
                "CITE_SOCKET",
                "socket",
                "/run/cite/manager.sock",
            )),
            build_uid: parse_u32(
                &pick(env, &file, "CITE_BUILD_UID", "build_uid", "10002"),
                "CITE_BUILD_UID",
            )?,
            build_gid: parse_u32(
                &pick(env, &file, "CITE_BUILD_GID", "build_gid", "10002"),
                "CITE_BUILD_GID",
            )?,
            dev_same_user: match pick_opt(env, &file, "CITE_DEV_SAME_USER", "dev_same_user")? {
                Some(value) => matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                ),
                None => !is_root(),
            },
        };
        if cfg.health_consecutive == 0 {
            return Err(Error::Config("CITE_HEALTH_CONSECUTIVE must be >= 1".into()));
        }
        if !cfg.dev_same_user && (cfg.build_uid == 0 || cfg.build_gid == 0) {
            return Err(Error::Config(
                "CITE_BUILD_UID and CITE_BUILD_GID must be non-zero so builds never run as root"
                    .into(),
            ));
        }
        if !cfg.github_api_url.starts_with("https://") && !cfg.github_api_url.starts_with("http://")
        {
            return Err(Error::Config(
                "CITE_GITHUB_API_URL must be an http(s) URL".into(),
            ));
        }
        Ok(cfg)
    }

    pub fn desired_path(&self) -> PathBuf {
        self.control_dir.join("desired.json")
    }
    pub fn status_path(&self) -> PathBuf {
        self.status_dir.join("executor.json")
    }
    pub fn state_path(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }
    pub fn slot_dir(&self, slot: crate::schema::Slot) -> PathBuf {
        self.releases_dir.join(slot.as_str())
    }

    pub fn redacted_display(&self) -> String {
        format!(
            "repo={} branch={} poll={:?} rendering={:?} framework={} node={} runtime={:?} releases={} work={}",
            self.repo,
            self.branch,
            self.poll,
            self.rendering,
            self.framework,
            self.node_major,
            self.runtime,
            self.releases_dir.display(),
            self.work_dir.display()
        )
    }
}

impl ExecutorConfig {
    pub fn load() -> Result<Self> {
        let env: HashMap<String, String> = std::env::vars().collect();
        let toml_text = read_optional_config(&env)?;
        Self::load_from(&env, toml_text.as_deref())
    }

    pub fn load_from(env: &HashMap<String, String>, toml_text: Option<&str>) -> Result<Self> {
        let file = parse_toml(toml_text)?;
        let data = pick(env, &file, "CITE_DATA_DIR", "data_dir", "/var/lib/cite");
        let listen: SocketAddr = pick(env, &file, "CITE_LISTEN", "listen", "0.0.0.0:8080")
            .parse()
            .map_err(|err| Error::Config(format!("CITE_LISTEN: {err}")))?;
        let port_base = parse_u16(
            &pick(env, &file, "CITE_PORT_BASE", "port_base", "3001"),
            "CITE_PORT_BASE",
        )?;
        if port_base == 0 || port_base == u16::MAX {
            return Err(Error::Config(
                "CITE_PORT_BASE must leave room for the green port".into(),
            ));
        }
        Ok(Self {
            listen,
            port_base,
            trusted_proxies: parse_trusted_proxies(&pick(
                env,
                &file,
                "CITE_TRUSTED_PROXIES",
                "trusted_proxies",
                "",
            ))?,
            allowed_hosts: split_list(&pick(env, &file, "CITE_ALLOWED_HOSTS", "allowed_hosts", "")),
            max_body: parse_byte_size(&pick(env, &file, "CITE_MAX_BODY", "max_body", "100MB"))?,
            static_headers: parse_headers(&pick(
                env,
                &file,
                "CITE_STATIC_HEADERS",
                "static_headers",
                "",
            ))?,
            releases_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_RELEASES_DIR",
                "releases_dir",
                &format!("{data}/releases"),
            )),
            control_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_CONTROL_DIR",
                "control_dir",
                &format!("{data}/control"),
            )),
            status_dir: PathBuf::from(pick(
                env,
                &file,
                "CITE_STATUS_DIR",
                "status_dir",
                &format!("{data}/status"),
            )),
            runtime: parse_runtime(&pick(env, &file, "CITE_RUNTIME", "runtime", "node"))?,
            node_major: pick(env, &file, "CITE_NODE", "node", "22"),
            node_bin: pick(env, &file, "CITE_NODE_BIN", "node_bin", "node"),
            bun_bin: pick(env, &file, "CITE_BUN_BIN", "bun_bin", "bun"),
            warm_grace: parse_duration(&pick(env, &file, "CITE_WARM_GRACE", "warm_grace", "24h"))?,
            watch: parse_duration(&pick(env, &file, "CITE_WATCH", "watch", "10m"))?,
            runtime_env: SiteEnv::from_env(
                env,
                PathBuf::from(pick(
                    env,
                    &file,
                    "CITE_RUNTIME_ENV_FILE",
                    "runtime_env_file",
                    "/run/cite/runtime.env",
                )),
            ),
            connect_timeout: parse_duration(&pick(
                env,
                &file,
                "CITE_CONNECT_TIMEOUT",
                "connect_timeout",
                "5s",
            ))?,
            header_timeout: parse_duration(&pick(
                env,
                &file,
                "CITE_HEADER_TIMEOUT",
                "header_timeout",
                "30s",
            ))?,
            idle_timeout: parse_duration(&pick(
                env,
                &file,
                "CITE_IDLE_TIMEOUT",
                "idle_timeout",
                "60s",
            ))?,
            max_header_bytes: parse_u64(
                &pick(
                    env,
                    &file,
                    "CITE_MAX_HEADER_BYTES",
                    "max_header_bytes",
                    "65536",
                ),
                "CITE_MAX_HEADER_BYTES",
            )? as usize,
            max_connections: parse_u64(
                &pick(
                    env,
                    &file,
                    "CITE_MAX_CONNECTIONS",
                    "max_connections",
                    "1024",
                ),
                "CITE_MAX_CONNECTIONS",
            )? as usize,
            access_log: matches!(
                pick(env, &file, "CITE_ACCESS_LOG", "access_log", "off")
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "on"
            ),
            crash_limit: parse_u32(
                &pick(env, &file, "CITE_CRASH_LIMIT", "crash_limit", "5"),
                "CITE_CRASH_LIMIT",
            )?,
            crash_window: parse_duration(&pick(
                env,
                &file,
                "CITE_CRASH_WINDOW",
                "crash_window",
                "2m",
            ))?,
            max_conn_per_ip: parse_u64(
                &pick(env, &file, "CITE_MAX_CONN_PER_IP", "max_conn_per_ip", "64"),
                "CITE_MAX_CONN_PER_IP",
            )? as usize,
            rate_limit: parse_rate_limit(&pick(
                env,
                &file,
                "CITE_RATE_LIMIT",
                "rate_limit",
                "100",
            ))?,
            rate_burst: positive_u32(
                &pick(env, &file, "CITE_RATE_BURST", "rate_burst", "200"),
                "CITE_RATE_BURST",
            )?,
            ban_threshold: positive_u32(
                &pick(env, &file, "CITE_BAN_THRESHOLD", "ban_threshold", "50"),
                "CITE_BAN_THRESHOLD",
            )?,
            ban_duration: positive_duration(
                &pick(env, &file, "CITE_BAN_DURATION", "ban_duration", "60s"),
                "CITE_BAN_DURATION",
            )?,
            version: pick(
                env,
                &file,
                "CITE_VERSION",
                "version",
                env!("CARGO_PKG_VERSION"),
            ),
            child_term_grace: parse_duration(&pick(
                env,
                &file,
                "CITE_CHILD_TERM_GRACE",
                "child_term_grace",
                "10s",
            ))?,
        })
    }

    pub fn desired_path(&self) -> PathBuf {
        self.control_dir.join("desired.json")
    }
    pub fn status_path(&self) -> PathBuf {
        self.status_dir.join("executor.json")
    }
    pub fn slot_dir(&self, slot: crate::schema::Slot) -> PathBuf {
        self.releases_dir.join(slot.as_str())
    }
}

/// `KEY=VALUE` lines. Blank lines and `#` comments are ignored. Values are not shell-expanded.
pub fn parse_env_file(text: &str) -> Result<Vec<(String, String)>> {
    if text.contains('\0') {
        return Err(Error::Config("env file contains NUL".into()));
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::Config(format!("env line `{line}` needs KEY=VALUE")));
        };
        if key.is_empty() || key.contains(char::is_whitespace) {
            return Err(Error::Config(format!("bad env key `{key}`")));
        }
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

fn read_optional_config(env: &HashMap<String, String>) -> Result<Option<String>> {
    let path = env
        .get("CITE_CONFIG")
        .cloned()
        .unwrap_or_else(|| "/etc/cite/cite.toml".into());
    let path = PathBuf::from(path);
    if path.is_file() {
        Ok(Some(std::fs::read_to_string(path)?))
    } else {
        Ok(None)
    }
}

fn parse_toml(text: Option<&str>) -> Result<toml::Value> {
    match text.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => toml::from_str(text).map_err(|err| Error::Config(err.to_string())),
        None => Ok(toml::Value::Table(toml::map::Map::new())),
    }
}

fn pick(
    env: &HashMap<String, String>,
    file: &toml::Value,
    env_key: &str,
    toml_key: &str,
    default: &str,
) -> String {
    if let Some(value) = env.get(env_key) {
        return value.clone();
    }
    if let Some(value) = file.get(toml_key).and_then(toml::Value::as_str) {
        return value.to_string();
    }
    default.to_string()
}

fn pick_opt(
    env: &HashMap<String, String>,
    file: &toml::Value,
    env_key: &str,
    toml_key: &str,
) -> Result<Option<String>> {
    if let Some(value) = env.get(env_key) {
        return Ok(Some(value.clone()));
    }
    if let Some(value) = file.get(toml_key).and_then(toml::Value::as_str) {
        return Ok(Some(value.to_string()));
    }
    Ok(None)
}

fn pick_bool_opt(
    env: &HashMap<String, String>,
    file: &toml::Value,
    env_key: &str,
    toml_key: &str,
) -> Result<Option<bool>> {
    let raw = if let Some(value) = env.get(env_key) {
        value.clone()
    } else if let Some(value) = file.get(toml_key) {
        match value {
            toml::Value::Boolean(flag) => return Ok(Some(*flag)),
            toml::Value::String(text) => text.clone(),
            _ => return Err(Error::Config(format!("{env_key} must be a boolean"))),
        }
    } else {
        return Ok(None);
    };
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(Error::Config(format!("{env_key} must be true or false"))),
    }
}

fn split_repo(repo: &str) -> Result<(String, String)> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if parts.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || !is_repo_token(owner)
        || !is_repo_token(name)
    {
        return Err(Error::Config(format!(
            "CITE_REPO must be owner/name, got `{repo}`"
        )));
    }
    Ok((owner.to_string(), name.to_string()))
}

fn is_repo_token(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.starts_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn check_branch(branch: &str) -> Result<String> {
    if branch.is_empty()
        || branch.len() > 256
        || branch.contains('\0')
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.contains("..")
        || !branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
    {
        return Err(Error::Config(format!("invalid branch `{branch}`")));
    }
    Ok(branch.to_string())
}

fn check_rel_path(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.contains('\0') || value.contains('\\') {
        return Err(Error::Config(format!("invalid path `{value}`")));
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(Error::Config(format!("path `{value}` must be relative")));
    }
    if path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(Error::Config(format!("path `{value}` must not contain ..")));
    }
    Ok(())
}

fn check_shell_command(value: &str) -> Result<()> {
    if value.len() > 2048 || value.contains('\0') {
        Err(Error::Config(
            "command is empty, too long, or contains NUL".into(),
        ))
    } else if value.is_empty() {
        Err(Error::Config("command is empty".into()))
    } else {
        Ok(())
    }
}

fn parse_rendering(value: &str) -> Result<RenderingSetting> {
    match value {
        "auto" => Ok(RenderingSetting::Auto),
        "static" => Ok(RenderingSetting::Static),
        "ssr" => Ok(RenderingSetting::Ssr),
        _ => Err(Error::Config(format!(
            "CITE_RENDERING must be auto, static, or ssr, got `{value}`"
        ))),
    }
}

fn parse_pm(value: &str) -> Result<String> {
    match value {
        "auto" | "npm" | "pnpm" | "yarn" | "bun" => Ok(value.to_string()),
        _ => Err(Error::Config(format!(
            "CITE_PACKAGE_MANAGER must be auto, npm, pnpm, yarn, or bun, got `{value}`"
        ))),
    }
}

fn parse_runtime(value: &str) -> Result<RuntimeKind> {
    match value {
        "node" => Ok(RuntimeKind::Node),
        "bun" => Ok(RuntimeKind::Bun),
        "static" => Ok(RuntimeKind::Static),
        "rust" => Ok(RuntimeKind::Rust),
        _ => Err(Error::Config(format!(
            "CITE_RUNTIME must be node, bun, static, or rust, got `{value}`"
        ))),
    }
}

fn parse_expect(value: &str) -> Result<HealthExpect> {
    match value {
        "non2xx-ok" => Ok(HealthExpect::Non2xxOk),
        "2xx" => Ok(HealthExpect::TwoXx),
        _ => Err(Error::Config(format!(
            "CITE_HEALTH_EXPECT must be non2xx-ok or 2xx, got `{value}`"
        ))),
    }
}

fn parse_rate_limit(value: &str) -> Result<u32> {
    if value.eq_ignore_ascii_case("off") {
        return Ok(0);
    }
    parse_u32(value, "CITE_RATE_LIMIT (an integer or `off`)")
}

fn positive_u32(value: &str, field: &str) -> Result<u32> {
    match parse_u32(value, field)? {
        0 => Err(Error::Config(format!("{field} must be at least 1"))),
        n => Ok(n),
    }
}

fn positive_duration(value: &str, field: &str) -> Result<Duration> {
    let dur = parse_duration(value).map_err(|err| Error::Config(format!("{field}: {err}")))?;
    if dur.is_zero() {
        return Err(Error::Config(format!("{field} must be greater than zero")));
    }
    Ok(dur)
}

fn parse_u32(value: &str, field: &str) -> Result<u32> {
    value
        .parse()
        .map_err(|_| Error::Config(format!("{field} must be an integer")))
}

fn parse_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| Error::Config(format!("{field} must be an integer")))
}

fn parse_u16(value: &str, field: &str) -> Result<u16> {
    value
        .parse()
        .map_err(|_| Error::Config(format!("{field} must be an integer")))
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Private and local ranges trusted when CITE_TRUSTED_PROXIES is unset or empty.
pub const DEFAULT_TRUSTED_PROXIES: &[&str] = &[
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    "fe80::/10",
    "169.254.0.0/16",
];

/// Unset or empty selects the private ranges, `none` trusts nobody, anything else replaces the default.
fn parse_trusted_proxies(value: &str) -> Result<Vec<IpNet>> {
    let value = value.trim();
    if value.is_empty() {
        return parse_nets(&DEFAULT_TRUSTED_PROXIES.join(","));
    }
    if value.eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    parse_nets(value)
}

fn parse_nets(value: &str) -> Result<Vec<IpNet>> {
    let mut nets = Vec::new();
    for part in split_list(value) {
        if let Ok(net) = part.parse::<IpNet>() {
            nets.push(net);
            continue;
        }
        let addr: std::net::IpAddr = part
            .parse()
            .map_err(|_| Error::Config(format!("bad proxy `{part}`")))?;
        nets.push(IpNet::from(addr));
    }
    Ok(nets)
}

fn parse_headers(value: &str) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for line in value.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, header_value)) = line.split_once(':') else {
            return Err(Error::Config(format!(
                "header `{line}` must be Name: value"
            )));
        };
        headers.push((name.trim().to_string(), header_value.trim().to_string()));
    }
    Ok(headers)
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn token_file_must_be_private_regular_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "ghp_secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let token = GithubToken::File(path.clone());
        let err = token.read().unwrap_err().to_string();
        assert!(
            err.contains("chmod 600") && !err.contains("ghp_secret"),
            "{err}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(token.read().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(token.read().unwrap(), "ghp_secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(token.read().unwrap(), "ghp_secret");

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(GithubToken::File(link).read().is_err());
        assert!(GithubToken::File(dir.path().to_path_buf()).read().is_err());
        assert_eq!(GithubToken::Env(" tok ".into()).read().unwrap(), "tok");
    }

    #[test]
    fn trusted_proxies_default_override_and_none() {
        let load = |pairs: &[(&str, &str)]| {
            ExecutorConfig::load_from(&env(pairs), None)
                .unwrap()
                .trusted_proxies
        };
        let default = load(&[]);
        assert_eq!(default.len(), DEFAULT_TRUSTED_PROXIES.len());
        let has = |nets: &[IpNet], ip: &str| {
            nets.iter()
                .any(|n| n.contains(&ip.parse::<std::net::IpAddr>().unwrap()))
        };
        for ip in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.17.0.1",
            "192.168.1.1",
            "100.64.0.9",
            "fd00::1",
            "fe80::1",
            "169.254.1.1",
        ] {
            assert!(has(&default, ip), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2001:db8::1"] {
            assert!(!has(&default, ip), "{ip}");
        }
        assert_eq!(load(&[("CITE_TRUSTED_PROXIES", "")]), default);
        let custom = load(&[("CITE_TRUSTED_PROXIES", "203.0.113.0/24, 198.51.100.7")]);
        assert_eq!(custom.len(), 2);
        assert!(!has(&custom, "10.0.0.1"));
        assert!(load(&[("CITE_TRUSTED_PROXIES", "none")]).is_empty());
        assert!(load(&[("CITE_TRUSTED_PROXIES", "NONE")]).is_empty());
        let bad =
            ExecutorConfig::load_from(&env(&[("CITE_TRUSTED_PROXIES", "10.0.0.0/8, nope")]), None);
        assert!(bad.is_err());
    }

    #[test]
    fn abuse_protection_defaults_and_validation() {
        let load = |pairs: &[(&str, &str)]| ExecutorConfig::load_from(&env(pairs), None);
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.max_conn_per_ip, 64);
        assert_eq!(cfg.rate_limit, 100);
        assert_eq!(cfg.rate_burst, 200);
        assert_eq!(cfg.ban_threshold, 50);
        assert_eq!(cfg.ban_duration, Duration::from_secs(60));

        let cfg = load(&[
            ("CITE_MAX_CONN_PER_IP", "8"),
            ("CITE_RATE_LIMIT", "5"),
            ("CITE_RATE_BURST", "10"),
            ("CITE_BAN_THRESHOLD", "3"),
            ("CITE_BAN_DURATION", "2m"),
        ])
        .unwrap();
        assert_eq!(
            (
                cfg.max_conn_per_ip,
                cfg.rate_limit,
                cfg.rate_burst,
                cfg.ban_threshold
            ),
            (8, 5, 10, 3)
        );
        assert_eq!(cfg.ban_duration, Duration::from_secs(120));

        assert_eq!(load(&[("CITE_RATE_LIMIT", "off")]).unwrap().rate_limit, 0);
        assert_eq!(load(&[("CITE_RATE_LIMIT", "0")]).unwrap().rate_limit, 0);
        assert_eq!(
            load(&[("CITE_MAX_CONN_PER_IP", "0")])
                .unwrap()
                .max_conn_per_ip,
            0
        );
        for (key, value) in [
            ("CITE_RATE_LIMIT", "fast"),
            ("CITE_RATE_BURST", "0"),
            ("CITE_BAN_THRESHOLD", "0"),
            ("CITE_BAN_DURATION", "0s"),
            ("CITE_BAN_DURATION", "soon"),
            ("CITE_MAX_CONN_PER_IP", "-1"),
        ] {
            let err = load(&[(key, value)]).unwrap_err().to_string();
            assert!(err.contains(key), "{key}: {err}");
        }
    }

    #[test]
    fn package_manager_accepts_yarn_and_rejects_unknown() {
        for pm in ["auto", "npm", "pnpm", "yarn", "bun"] {
            let cfg = ManagerConfig::load_from(
                &env(&[("CITE_REPO", "o/n"), ("CITE_PACKAGE_MANAGER", pm)]),
                None,
            )
            .unwrap();
            assert_eq!(cfg.package_manager, pm);
        }
        let err = ManagerConfig::load_from(
            &env(&[("CITE_REPO", "o/n"), ("CITE_PACKAGE_MANAGER", "deno")]),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("yarn"));
    }

    #[test]
    fn env_overrides_toml_and_validates() {
        let toml_text = "repo = \"from/toml\"\nbranch = \"dev\"\npoll_interval = \"15m\"\n";
        let cfg = ManagerConfig::load_from(
            &env(&[("CITE_REPO", "owner/name"), ("CITE_POLL_INTERVAL", "1h")]),
            Some(toml_text),
        )
        .unwrap();
        assert_eq!(cfg.repo, "owner/name");
        assert_eq!(cfg.branch, "dev");
        assert_eq!(cfg.poll, PollInterval::Every(Duration::from_secs(3600)));
        assert!(ManagerConfig::load_from(&env(&[("CITE_REPO", "../evil")]), None).is_err());
        assert!(
            ManagerConfig::load_from(
                &env(&[("CITE_REPO", "ok/name"), ("CITE_ROOT_DIR", "../outside")]),
                None
            )
            .is_err()
        );
        assert!(
            ManagerConfig::load_from(
                &env(&[("CITE_REPO", "ok/name"), ("CITE_BUILD_COMMAND", "echo \0")]),
                None
            )
            .is_err()
        );
        assert!(ExecutorConfig::load_from(&env(&[("CITE_PORT_BASE", "0")]), None).is_err());
        assert!(
            ManagerConfig::load_from(
                &env(&[
                    ("CITE_REPO", "ok/name"),
                    ("CITE_POLL_INTERVAL", "1s"),
                    ("CITE_MIN_POLL", "60s")
                ]),
                None
            )
            .is_err()
        );
        assert!(
            ManagerConfig::load_from(
                &env(&[
                    ("CITE_REPO", "ok/name"),
                    ("CITE_START_COMMAND", "npm start")
                ]),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn a_root_build_identity_is_refused_unless_dev_same_user() {
        for (key, value) in [("CITE_BUILD_UID", "0"), ("CITE_BUILD_GID", "0")] {
            let strict = env(&[
                ("CITE_REPO", "owner/name"),
                ("CITE_DEV_SAME_USER", "false"),
                (key, value),
            ]);
            let err = ManagerConfig::load_from(&strict, None).unwrap_err();
            assert!(err.to_string().contains("non-zero"), "{err}");
            let dev = env(&[
                ("CITE_REPO", "owner/name"),
                ("CITE_DEV_SAME_USER", "true"),
                (key, value),
            ]);
            assert!(ManagerConfig::load_from(&dev, None).is_ok());
        }
    }

    #[test]
    fn source_limits_default_to_the_spec_and_can_be_overridden() {
        let cfg = ManagerConfig::load_from(&env(&[("CITE_REPO", "owner/name")]), None).unwrap();
        assert_eq!(cfg.max_source_compressed_bytes, 1024 * 1024 * 1024);
        assert_eq!(cfg.max_source_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(cfg.max_entries, 300_000);

        let cfg = ManagerConfig::load_from(
            &env(&[
                ("CITE_REPO", "owner/name"),
                ("CITE_MAX_SOURCE_COMPRESSED_BYTES", "10MB"),
                ("CITE_MAX_SOURCE_BYTES", "20MB"),
                ("CITE_MAX_ENTRIES", "12"),
            ]),
            None,
        )
        .unwrap();
        assert_eq!(cfg.max_source_compressed_bytes, 10 * 1024 * 1024);
        assert_eq!(cfg.max_source_bytes, 20 * 1024 * 1024);
        assert_eq!(cfg.max_entries, 12);
    }

    #[test]
    fn executor_listens_on_all_interfaces_8080_by_default() {
        let cfg = ExecutorConfig::load_from(&env(&[]), None).unwrap();
        assert_eq!(cfg.listen.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn env_file_parser() {
        let parsed = parse_env_file("FOO=bar\n# comment\nBAR=a=b\n").unwrap();
        assert_eq!(
            parsed,
            vec![("FOO".into(), "bar".into()), ("BAR".into(), "a=b".into())]
        );
    }

    #[test]
    fn github_token_prefers_env_then_file_and_never_prints() {
        let dir = std::env::temp_dir().join(format!("cite-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("token");
        std::fs::write(&file, "from-file\n").unwrap();
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let path = file.to_str().unwrap();
        let load = |pairs: &[(&str, &str)]| {
            let mut all = vec![("CITE_REPO", "owner/name")];
            all.extend_from_slice(pairs);
            ManagerConfig::load_from(&env(&all), None)
                .unwrap()
                .github_token
        };
        let both = load(&[
            ("CITE_GITHUB_TOKEN", "ghp_fromEnv"),
            ("CITE_GITHUB_TOKEN_FILE", path),
        ]);
        assert_eq!(both.read().unwrap(), "ghp_fromEnv");
        assert!(!format!("{both:?}").contains("ghp_fromEnv"));
        let file_only = load(&[("CITE_GITHUB_TOKEN", " "), ("CITE_GITHUB_TOKEN_FILE", path)]);
        assert_eq!(file_only.read().unwrap(), "from-file");
        std::fs::write(&file, "rotated\n").unwrap();
        assert_eq!(file_only.read().unwrap(), "rotated");
        assert!(load(&[]).read().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn runtime_rust_loads_from_the_env() {
        let cfg = ManagerConfig::load_from(
            &env(&[("CITE_REPO", "owner/name"), ("CITE_RUNTIME", "rust")]),
            None,
        )
        .unwrap();
        assert_eq!(cfg.runtime, RuntimeKind::Rust);
        let cfg = ExecutorConfig::load_from(&env(&[("CITE_RUNTIME", "rust")]), None).unwrap();
        assert_eq!(cfg.runtime, RuntimeKind::Rust);
        let err = ManagerConfig::load_from(
            &env(&[("CITE_REPO", "owner/name"), ("CITE_RUNTIME", "deno")]),
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        for word in ["node", "bun", "static", "rust"] {
            assert!(msg.contains(word), "{msg}");
        }
    }

    #[test]
    fn site_env_passes_through_only_site_vars() {
        let dir = std::env::temp_dir().join(format!("cite-site-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("build.env");
        let cfg = ManagerConfig::load_from(
            &env(&[
                ("CITE_REPO", "owner/name"),
                ("CITE_GITHUB_TOKEN", "ghp_neverInSiteEnv"),
                ("CITE_BUILD_ENV_FILE", file.to_str().unwrap()),
                ("PATH", "/usr/bin"),
                ("NODE_VERSION", "22.1.0"),
                ("API_URL", "https://api.example"),
                ("SHARED", "from-env"),
            ]),
            None,
        )
        .unwrap();
        let only_env = cfg.build_env.resolve().unwrap();
        assert_eq!(
            only_env.keys().collect::<Vec<_>>(),
            vec!["API_URL", "SHARED"]
        );
        std::fs::write(&file, "SHARED=from-file\nEXTRA=1\n").unwrap();
        let merged = cfg.build_env.resolve().unwrap();
        assert_eq!(merged.get("SHARED").map(String::as_str), Some("from-file"));
        assert_eq!(merged.get("EXTRA").map(String::as_str), Some("1"));
        assert!(!merged.values().any(|v| v.contains("ghp_")));
        assert!(!format!("{cfg:?}").contains("https://api.example"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
