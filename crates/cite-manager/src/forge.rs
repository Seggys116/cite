//! Source forge seam: GitHub through the existing client, GitLab API v4, and Gitea/Forgejo API v1.

mod gitea;
mod gitlab;
mod transport;

#[cfg(test)]
mod tests;

use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{ETAG, HeaderMap};
use serde::de::DeserializeOwned;
use tracing::{info, warn};

use crate::github::{CommitInfo, GithubClient, PollResult, RateHints, ValidateOk};
use crate::{ManagerError, Result};

pub use gitea::GiteaClient;
pub use gitlab::GitlabClient;

use transport::Transport;

pub const DEFAULT_GITLAB_API_URL: &str = "https://gitlab.com/api/v4";
const MAX_API_URL_LEN: usize = 200;
const TOKEN_WARN_DAYS: i64 = 7;
const DEFAULT_RATE_LIMIT_WAIT: Duration = Duration::from_secs(60);
const EPOCH_FLOOR: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeKind {
    Github,
    Gitlab,
    Gitea,
}

impl ForgeKind {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "github" => Ok(Self::Github),
            "gitlab" => Ok(Self::Gitlab),
            "gitea" => Ok(Self::Gitea),
            _ => Err(ManagerError::new(format!(
                "CITE_FORGE must be github, gitlab or gitea, not {:?}",
                raw.trim()
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Gitea => "gitea",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Github => "GitHub",
            Self::Gitlab => "GitLab",
            Self::Gitea => "Gitea",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeSettings {
    pub kind: ForgeKind,
    pub api_url: String,
}

impl ForgeSettings {
    /// Reads `CITE_FORGE` and `CITE_FORGE_API_URL`; GitHub falls back to the existing API url setting.
    pub fn from_env(github_api_url: &str) -> Result<Self> {
        let forge = std::env::var("CITE_FORGE").ok();
        let api_url = std::env::var("CITE_FORGE_API_URL").ok();
        Self::from_values(forge.as_deref(), api_url.as_deref(), github_api_url)
    }

    pub fn from_values(
        forge: Option<&str>,
        api_url: Option<&str>,
        github_api_url: &str,
    ) -> Result<Self> {
        let kind = ForgeKind::parse(forge.unwrap_or(""))?;
        let api_url = api_url.map(str::trim).filter(|url| !url.is_empty());
        if let Some(url) = api_url {
            validate_forge_api_url(url)
                .map_err(|why| ManagerError::new(format!("CITE_FORGE_API_URL: {why}")))?;
        }
        let api_url = match (kind, api_url) {
            (_, Some(url)) => url.to_string(),
            (ForgeKind::Github, None) => github_api_url.to_string(),
            (ForgeKind::Gitlab, None) => DEFAULT_GITLAB_API_URL.to_string(),
            (ForgeKind::Gitea, None) => {
                return Err(ManagerError::new(
                    "CITE_FORGE_API_URL is required when CITE_FORGE=gitea (for example https://codeberg.org/api/v1)",
                ));
            }
        };
        Ok(Self { kind, api_url })
    }
}

/// Same shape rules as the connector's GitHub API url check, but https only.
pub fn validate_forge_api_url(url: &str) -> std::result::Result<(), String> {
    // Unit tests reach local plain-http mock servers; release builds never accept http.
    check_api_url(url, cfg!(test))
}

fn check_api_url(url: &str, loopback_http: bool) -> std::result::Result<(), String> {
    if url.len() > MAX_API_URL_LEN {
        return Err(format!(
            "forge api url is longer than {MAX_API_URL_LEN} characters"
        ));
    }
    let (rest, https) = match url.strip_prefix("https://") {
        Some(rest) => (rest, true),
        None => (
            url.strip_prefix("http://")
                .ok_or("forge api url must start with https://")?,
            false,
        ),
    };
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~' | ':' | '/'))
    {
        return Err("forge api url has characters that are not allowed".to_string());
    }
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if !valid_host(host) || port.is_some_and(|p| !valid_port(p)) {
        return Err("forge api url has no valid host and port".to_string());
    }
    if !https && !(loopback_http && matches!(host, "127.0.0.1" | "localhost")) {
        return Err("forge api url must use https".to_string());
    }
    if path.contains("//") || path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("forge api url has an empty or relative path segment".to_string());
    }
    Ok(())
}

fn valid_host(host: &str) -> bool {
    let edge_ok = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    edge_ok(host.chars().next())
        && edge_ok(host.chars().last())
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
}

/// Drop-in for `GithubClient` in the deployer: same method names, signatures and error strings.
#[derive(Debug, Clone)]
pub enum ForgeClient {
    Github(GithubClient),
    Gitlab(GitlabClient),
    Gitea(GiteaClient),
}

impl ForgeClient {
    pub fn new(
        settings: &ForgeSettings,
        owner: &str,
        name: &str,
        branch: &str,
        token: &cite_core::GithubToken,
    ) -> Result<Self> {
        let api = settings.api_url.as_str();
        Ok(match settings.kind {
            ForgeKind::Github => Self::Github(GithubClient::new(api, owner, name, branch, token)?),
            ForgeKind::Gitlab => Self::Gitlab(GitlabClient::new(api, owner, name, branch, token)?),
            ForgeKind::Gitea => Self::Gitea(GiteaClient::new(api, owner, name, branch, token)?),
        })
    }

    pub fn kind(&self) -> ForgeKind {
        match self {
            Self::Github(_) => ForgeKind::Github,
            Self::Gitlab(_) => ForgeKind::Gitlab,
            Self::Gitea(_) => ForgeKind::Gitea,
        }
    }

    #[must_use]
    pub fn with_max_tarball_bytes(self, max: u64) -> Self {
        match self {
            Self::Github(c) => Self::Github(c.with_max_tarball_bytes(max)),
            Self::Gitlab(c) => Self::Gitlab(c.with_max_tarball_bytes(max)),
            Self::Gitea(c) => Self::Gitea(c.with_max_tarball_bytes(max)),
        }
    }

    #[must_use]
    pub fn with_tarball_timeout(self, timeout: Duration) -> Self {
        match self {
            Self::Github(c) => Self::Github(c.with_tarball_timeout(timeout)),
            Self::Gitlab(c) => Self::Gitlab(c.with_tarball_timeout(timeout)),
            Self::Gitea(c) => Self::Gitea(c.with_tarball_timeout(timeout)),
        }
    }

    pub fn read_token(&self) -> Result<String> {
        match self {
            Self::Github(c) => c.read_token(),
            Self::Gitlab(c) => c.read_token(),
            Self::Gitea(c) => c.read_token(),
        }
    }

    pub async fn validate_access(&self) -> Result<ValidateOk> {
        match self {
            Self::Github(c) => c.validate_access().await,
            Self::Gitlab(c) => c.validate_access().await,
            Self::Gitea(c) => c.validate_access().await,
        }
    }

    pub async fn poll_head(&self, etag: Option<&str>) -> Result<(PollResult, RateHints)> {
        match self {
            Self::Github(c) => c.poll_head(etag).await,
            Self::Gitlab(c) => c.poll_head(etag).await,
            Self::Gitea(c) => c.poll_head(etag).await,
        }
    }

    pub async fn paths_changed(
        &self,
        base_sha: &str,
        head_sha: &str,
        paths: &[String],
    ) -> Result<bool> {
        match self {
            Self::Github(c) => c.paths_changed(base_sha, head_sha, paths).await,
            Self::Gitlab(c) => c.paths_changed(base_sha, head_sha, paths).await,
            Self::Gitea(c) => c.paths_changed(base_sha, head_sha, paths).await,
        }
    }

    /// Returns the compressed archive bytes for `cite_core::extract_archive` with one stripped component.
    pub async fn fetch_tarball(&self, sha: &str) -> Result<Vec<u8>> {
        match self {
            Self::Github(c) => c.fetch_tarball(sha).await,
            Self::Gitlab(c) => c.fetch_tarball(sha).await,
            Self::Gitea(c) => c.fetch_tarball(sha).await,
        }
    }
}

struct RepoTarget<'a> {
    kind: ForgeKind,
    owner: &'a str,
    name: &'a str,
    branch: &'a str,
    scope: &'static str,
}

struct BranchHead {
    sha: String,
    message: String,
    author: Option<String>,
}

async fn check_repo_and_branch(
    http: &Transport,
    target: &RepoTarget<'_>,
    repo_url: &str,
    branch_url: &str,
) -> Result<()> {
    let forge = target.kind.display_name();
    let resp = http.get_json(repo_url, None).await?;
    match resp.status() {
        StatusCode::OK => {
            let _: serde::de::IgnoredAny = Transport::json(resp).await?;
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err(ManagerError::new(format!(
                "{forge} token is invalid or lacks access to the repository (bad token / no access)"
            )));
        }
        StatusCode::NOT_FOUND => {
            return Err(ManagerError::new(format!(
                "repository {}/{} not found or token lacks {}",
                target.owner, target.name, target.scope
            )));
        }
        other => {
            return Err(ManagerError::new(format!(
                "{forge} repo check failed ({other}): {}",
                Transport::error_text(resp).await
            )));
        }
    }

    let resp = http.get_json(branch_url, None).await?;
    match resp.status() {
        StatusCode::OK => Ok(()),
        StatusCode::NOT_FOUND => Err(ManagerError::new(format!(
            "branch `{}` does not exist on {}/{}",
            target.branch, target.owner, target.name
        ))),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ManagerError::new(format!(
            "{forge} token is invalid or lacks access (bad token / no access)"
        ))),
        other => Err(ManagerError::new(format!(
            "{forge} branch check failed ({other}): {}",
            Transport::error_text(resp).await
        ))),
    }
}

async fn poll_branch<B: DeserializeOwned>(
    http: &Transport,
    url: &str,
    etag: Option<&str>,
    head: impl FnOnce(B) -> BranchHead,
) -> Result<(PollResult, RateHints)> {
    let resp = http.get_json(url, etag).await?;
    let hints = rate_hints(resp.status(), resp.headers());
    match resp.status() {
        StatusCode::NOT_MODIFIED => Ok((PollResult::Unchanged, hints)),
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS if hints.backoff().is_some() => {
            Ok((PollResult::Unchanged, hints))
        }
        StatusCode::UNAUTHORIZED if http.is_api(&resp) => Err(ManagerError::new("token_invalid")),
        StatusCode::OK => {
            let etag = resp
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let head = head(Transport::json(resp).await?);
            if !is_commit_id(&head.sha) {
                return Err(ManagerError::new(
                    "forge returned a branch head that is not a commit id",
                ));
            }
            Ok((
                PollResult::Changed(CommitInfo {
                    sha: head.sha.to_ascii_lowercase(),
                    message: head.message.lines().next().unwrap_or("").into(),
                    author: head
                        .author
                        .filter(|a| !a.trim().is_empty())
                        .unwrap_or_else(|| "unknown".into()),
                    etag,
                }),
                hints,
            ))
        }
        other => Err(ManagerError::new(format!(
            "poll failed ({other}): {}",
            Transport::error_text(resp).await
        ))),
    }
}

/// `None` means the compare could not be used, so the caller deploys conservatively.
async fn compare_json<T: DeserializeOwned>(http: &Transport, url: &str) -> Result<Option<T>> {
    let resp = http.get_json(url, None).await?;
    if resp.status() == StatusCode::UNAUTHORIZED && http.is_api(&resp) {
        return Err(ManagerError::new("token_invalid"));
    }
    if !resp.status().is_success() {
        warn!(status = %resp.status(), "compare API failed; deploying");
        return Ok(None);
    }
    match Transport::json(resp).await {
        Ok(body) => Ok(Some(body)),
        Err(err) => {
            warn!(error = %err, "compare API response unreadable; deploying");
            Ok(None)
        }
    }
}

fn rate_hints(status: StatusCode, headers: &HeaderMap) -> RateHints {
    let number = |names: &[&str]| {
        names.iter().find_map(|name| {
            headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
        })
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let remaining = number(&["ratelimit-remaining", "x-ratelimit-remaining"])
        .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
    // GitLab sends an epoch reset while the IETF draft headers send seconds from now.
    let reset_at = number(&["ratelimit-reset", "x-ratelimit-reset"]).map(|reset| {
        if reset >= EPOCH_FLOOR {
            reset
        } else {
            now.saturating_add(reset)
        }
    });
    let retry_after = number(&["retry-after"]).map(Duration::from_secs);
    let mut hints = RateHints {
        remaining,
        reset_at,
        retry_after,
    };
    if status == StatusCode::TOO_MANY_REQUESTS && hints.backoff().is_none() {
        hints.retry_after = Some(DEFAULT_RATE_LIMIT_WAIT);
    }
    hints
}

fn is_commit_id(sha: &str) -> bool {
    matches!(sha.len(), 40 | 64) && sha.chars().all(|c| c.is_ascii_hexdigit())
}

fn ensure_sha_ref(sha: &str) -> Result<()> {
    if (7..=64).contains(&sha.len()) && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ManagerError::new(format!(
            "{:?} is not a commit id",
            truncate(sha, 80)
        )))
    }
}

fn encode_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// GitLab reports a bare `YYYY-MM-DD`; state files store RFC 3339.
fn normalize_expiry(raw: &str) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    let raw = raw.trim();
    if let Ok(at) = time::OffsetDateTime::parse(raw, &Rfc3339) {
        return at.to_offset(time::UtcOffset::UTC).format(&Rfc3339).ok();
    }
    let format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").ok()?;
    let date = time::Date::parse(raw, &format).ok()?;
    date.midnight().assume_utc().format(&Rfc3339).ok()
}

fn warn_if_token_expiring(kind: ForgeKind, expires_at: &str) {
    if let Ok(exp) =
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
    {
        let days = (exp - time::OffsetDateTime::now_utc()).whole_days();
        if (0..=TOKEN_WARN_DAYS).contains(&days) {
            warn!(
                forge = kind.as_str(),
                expires_at,
                days_left = days,
                "forge token expires within 7 days"
            );
        }
    } else {
        info!(
            forge = kind.as_str(),
            expires_at, "forge token expiry present"
        );
    }
}

fn path_matches(paths: &[String], filename: &str) -> bool {
    paths.iter().any(|p| {
        filename == p
            || filename.starts_with(&format!("{p}/"))
            || p.strip_suffix("/*")
                .is_some_and(|prefix| filename.starts_with(prefix))
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}
