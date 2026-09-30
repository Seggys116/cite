//! GitHub API client (reqwest + rustls). Token never logged.

use std::time::Duration;

use reqwest::header::{AUTHORIZATION, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, USER_AGENT};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{ManagerError, Result};

const TOKEN_WARN_DAYS: i64 = 7;
const DEFAULT_MAX_TARBALL_BYTES: u64 = 1024 * 1024 * 1024;
const TARBALL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TARBALL_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub struct GithubClient {
    http: Client,
    download: Client,
    max_tarball_bytes: u64,
    tarball_timeout: Duration,
    api_url: String,
    owner: String,
    name: String,
    branch: String,
    token: cite_core::GithubToken,
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub sha: String,
    pub message: String,
    pub author: String,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub enum PollResult {
    Unchanged,
    Changed(CommitInfo),
}

#[derive(Debug, Clone)]
pub struct ValidateOk {
    pub token_expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RepoJson {}

#[derive(Debug, Deserialize)]
struct CommitJson {
    sha: String,
    commit: CommitBody,
}

#[derive(Debug, Deserialize)]
struct CommitBody {
    message: String,
    author: Option<CommitAuthor>,
}

#[derive(Debug, Deserialize)]
struct CommitAuthor {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompareJson {
    files: Option<Vec<CompareFile>>,
}

#[derive(Debug, Deserialize)]
struct CompareFile {
    filename: String,
}

impl GithubClient {
    pub fn new(
        api_url: &str,
        owner: &str,
        name: &str,
        branch: &str,
        token: &cite_core::GithubToken,
    ) -> Result<Self> {
        let http = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(30))
            .build()?;
        let download = Client::builder()
            .use_rustls_tls()
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(TARBALL_IDLE_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            download,
            max_tarball_bytes: DEFAULT_MAX_TARBALL_BYTES,
            tarball_timeout: TARBALL_TOTAL_TIMEOUT,
            api_url: api_url.trim_end_matches('/').to_string(),
            owner: owner.to_string(),
            name: name.to_string(),
            branch: branch.to_string(),
            token: token.clone(),
        })
    }

    /// Caps the compressed tarball download; the body is abandoned once it exceeds this.
    #[must_use]
    pub fn with_max_tarball_bytes(mut self, max: u64) -> Self {
        self.max_tarball_bytes = max;
        self
    }

    #[must_use]
    pub fn with_tarball_timeout(mut self, timeout: Duration) -> Self {
        self.tarball_timeout = timeout;
        self
    }

    pub fn read_token(&self) -> Result<String> {
        self.token
            .read()
            .map_err(|err| ManagerError::new(err.to_string()))
    }

    fn auth_headers(token: &str) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("cite-manager/0.1"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|err| ManagerError::new(format!("bad token header: {err}")))?,
        );
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        Ok(headers)
    }

    pub async fn validate_access(&self) -> Result<ValidateOk> {
        let token = self.read_token()?;
        let url = format!("{}/repos/{}/{}", self.api_url, self.owner, self.name);
        let resp = self
            .http
            .get(&url)
            .headers(Self::auth_headers(&token)?)
            .send()
            .await?;
        let expires = token_expiry_from_headers(resp.headers());
        match resp.status() {
            StatusCode::OK => {
                let _: RepoJson = resp.json().await?;
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ManagerError::new(
                    "GitHub token is invalid or lacks access to the repository (bad token / no access)",
                ));
            }
            StatusCode::NOT_FOUND => {
                return Err(ManagerError::new(format!(
                    "repository {}/{} not found or token lacks Metadata:read",
                    self.owner, self.name
                )));
            }
            other => {
                let body = resp.text().await.unwrap_or_default();
                return Err(ManagerError::new(format!(
                    "GitHub repo check failed ({other}): {}",
                    truncate(&body, 200)
                )));
            }
        }

        let branch_url = format!(
            "{}/repos/{}/{}/commits/{}",
            self.api_url, self.owner, self.name, self.branch
        );
        let resp = self
            .http
            .get(&branch_url)
            .headers(Self::auth_headers(&token)?)
            .send()
            .await?;
        match resp.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => {
                return Err(ManagerError::new(format!(
                    "branch `{}` does not exist on {}/{}",
                    self.branch, self.owner, self.name
                )));
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ManagerError::new(
                    "GitHub token is invalid or lacks access (bad token / no access)",
                ));
            }
            other => {
                let body = resp.text().await.unwrap_or_default();
                return Err(ManagerError::new(format!(
                    "GitHub branch check failed ({other}): {}",
                    truncate(&body, 200)
                )));
            }
        }

        if let Some(ref exp) = expires {
            warn_if_token_expiring(exp);
        }
        Ok(ValidateOk {
            token_expires_at: expires,
        })
    }

    pub async fn poll_head(&self, etag: Option<&str>) -> Result<(PollResult, RateHints)> {
        let token = self.read_token()?;
        let url = format!(
            "{}/repos/{}/{}/commits/{}",
            self.api_url, self.owner, self.name, self.branch
        );
        let mut req = self.http.get(&url).headers(Self::auth_headers(&token)?);
        if let Some(tag) = etag {
            req = req.header(IF_NONE_MATCH, tag);
        }
        let resp = req.send().await?;
        let hints = RateHints::from_response(&resp);
        match resp.status() {
            StatusCode::NOT_MODIFIED => Ok((PollResult::Unchanged, hints)),
            StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS if hints.backoff().is_some() => {
                Ok((PollResult::Unchanged, hints))
            }
            StatusCode::UNAUTHORIZED => Err(ManagerError::new("token_invalid")),
            StatusCode::OK => {
                let etag = resp
                    .headers()
                    .get(ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let commit: CommitJson = resp.json().await?;
                Ok((
                    PollResult::Changed(CommitInfo {
                        sha: commit.sha,
                        message: commit.commit.message.lines().next().unwrap_or("").into(),
                        author: commit
                            .commit
                            .author
                            .and_then(|a| a.name)
                            .unwrap_or_else(|| "unknown".into()),
                        etag,
                    }),
                    hints,
                ))
            }
            other => {
                let body = resp.text().await.unwrap_or_default();
                Err(ManagerError::new(format!(
                    "poll failed ({other}): {}",
                    truncate(&body, 200)
                )))
            }
        }
    }

    pub async fn paths_changed(
        &self,
        base_sha: &str,
        head_sha: &str,
        paths: &[String],
    ) -> Result<bool> {
        if paths.is_empty() {
            return Ok(true);
        }
        let token = self.read_token()?;
        let url = format!(
            "{}/repos/{}/{}/compare/{base_sha}...{head_sha}",
            self.api_url, self.owner, self.name
        );
        let resp = self
            .http
            .get(&url)
            .headers(Self::auth_headers(&token)?)
            .send()
            .await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(ManagerError::new("token_invalid"));
        }
        if !resp.status().is_success() {
            // If compare fails, deploy conservatively.
            warn!(status = %resp.status(), "compare API failed; deploying");
            return Ok(true);
        }
        let body: CompareJson = resp.json().await?;
        let files = body.files.unwrap_or_default();
        Ok(files.iter().any(|f| {
            paths.iter().any(|p| {
                f.filename == *p
                    || f.filename.starts_with(&format!("{p}/"))
                    || glob_match(p, &f.filename)
            })
        }))
    }

    /// The whole exchange, headers included, is bounded by the total timeout.
    pub async fn fetch_tarball(&self, sha: &str) -> Result<Vec<u8>> {
        match tokio::time::timeout(self.tarball_timeout, self.download_tarball(sha)).await {
            Ok(result) => result,
            Err(_) => Err(ManagerError::new("tarball download timed out")),
        }
    }

    async fn download_tarball(&self, sha: &str) -> Result<Vec<u8>> {
        let token = self.read_token()?;
        let url = format!(
            "{}/repos/{}/{}/tarball/{sha}",
            self.api_url, self.owner, self.name
        );
        let resp = self
            .download
            .get(&url)
            .headers(Self::auth_headers(&token)?)
            .send()
            .await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(ManagerError::new("token_invalid"));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ManagerError::new(format!(
                "tarball fetch failed ({status}): {}",
                truncate(&body, 200)
            )));
        }
        let max = self.max_tarball_bytes;
        if resp.content_length().is_some_and(|len| len > max) {
            return Err(tarball_too_large(max));
        }
        read_capped(resp, max).await
    }
}

fn tarball_too_large(max: u64) -> ManagerError {
    ManagerError::new(format!(
        "source tarball exceeds CITE_MAX_SOURCE_COMPRESSED_BYTES ({max})"
    ))
}

async fn read_capped(mut resp: Response, max: u64) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let chunk = match tokio::time::timeout(TARBALL_IDLE_TIMEOUT, resp.chunk()).await {
            Ok(chunk) => chunk?,
            Err(_) => return Err(ManagerError::new("tarball download stalled")),
        };
        let Some(chunk) = chunk else {
            return Ok(body);
        };
        if (body.len() as u64).saturating_add(chunk.len() as u64) > max {
            return Err(tarball_too_large(max));
        }
        body.extend_from_slice(&chunk);
    }
}

#[derive(Debug, Clone, Default)]
pub struct RateHints {
    pub remaining: Option<u32>,
    pub reset_at: Option<u64>,
    pub retry_after: Option<Duration>,
}

impl RateHints {
    fn from_response(resp: &Response) -> Self {
        let headers = resp.headers();
        let remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let reset_at = headers
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let retry_after = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs);
        Self {
            remaining,
            reset_at,
            retry_after,
        }
    }

    pub fn backoff(&self) -> Option<Duration> {
        if let Some(after) = self.retry_after {
            return Some(after);
        }
        if self.remaining == Some(0) {
            if let Some(reset) = self.reset_at {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if reset > now {
                    return Some(Duration::from_secs(reset - now + 1));
                }
            }
            return Some(Duration::from_secs(60));
        }
        None
    }
}

fn token_expiry_from_headers(headers: &HeaderMap) -> Option<String> {
    // GitHub fine-grained tokens may expose expiry via github-authentication-token-expiration
    headers
        .get("github-authentication-token-expiration")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn warn_if_token_expiring(expires_at: &str) {
    if let Ok(exp) =
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
    {
        let now = time::OffsetDateTime::now_utc();
        let days = (exp - now).whole_days();
        if (0..=TOKEN_WARN_DAYS).contains(&days) {
            warn!(
                expires_at,
                days_left = days,
                "GitHub token expires within 7 days"
            );
        }
    } else {
        info!(expires_at, "GitHub token expiry header present");
    }
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

fn glob_match(pattern: &str, path: &str) -> bool {
    // Minimal: treat trailing /* as prefix match.
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix);
    }
    pattern == path
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;

    #[test]
    fn rate_limit_backoff_honors_retry_after_and_caps_when_exhausted() {
        let hinted = RateHints {
            remaining: Some(5),
            reset_at: None,
            retry_after: Some(Duration::from_secs(12)),
        };
        assert_eq!(hinted.backoff(), Some(Duration::from_secs(12)));

        let exhausted = RateHints {
            remaining: Some(0),
            reset_at: None,
            retry_after: None,
        };
        assert_eq!(exhausted.backoff(), Some(Duration::from_secs(60)));

        let fine = RateHints {
            remaining: Some(10),
            reset_at: None,
            retry_after: None,
        };
        assert!(fine.backoff().is_none());
    }

    #[test]
    fn expiry_header_glob_and_truncate() {
        let mut headers = HeaderMap::new();
        assert!(token_expiry_from_headers(&headers).is_none());
        headers.insert(
            reqwest::header::HeaderName::from_static("github-authentication-token-expiration"),
            HeaderValue::from_static("2026-10-01T00:00:00Z"),
        );
        assert_eq!(
            token_expiry_from_headers(&headers).as_deref(),
            Some("2026-10-01T00:00:00Z")
        );
        warn_if_token_expiring("not-a-date");
        let soon = (time::OffsetDateTime::now_utc() + time::Duration::days(1))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        warn_if_token_expiring(&soon);
        let later = (time::OffsetDateTime::now_utc() + time::Duration::days(40))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        warn_if_token_expiring(&later);
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 4), "abcd…");
        assert_eq!(truncate("aé", 2), "a…");
        assert!(glob_match("src/*", "src/main.js"));
        assert!(!glob_match("src/*", "lib/main.js"));
        assert!(glob_match("README.md", "README.md"));
        assert!(!glob_match("README.md", "readme.md"));
    }

    async fn serve_once(body: Vec<u8>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let head = "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n";
            let _ = sock.write_all(head.as_bytes()).await;
            for part in body.chunks(1024) {
                let frame = format!("{:x}\r\n", part.len());
                if sock.write_all(frame.as_bytes()).await.is_err()
                    || sock.write_all(part).await.is_err()
                    || sock.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
        });
        port
    }

    fn client_for(port: u16, dir: &std::path::Path) -> GithubClient {
        let token = dir.join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        GithubClient::new(
            &format!("http://127.0.0.1:{port}"),
            "owner",
            "name",
            "main",
            &cite_core::GithubToken::File(token),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn tarball_download_is_capped_while_streaming() {
        let dir = tempfile::tempdir().unwrap();
        let port = serve_once(vec![7u8; 10_000]).await;
        let client = client_for(port, dir.path()).with_max_tarball_bytes(4096);
        let err = client.fetch_tarball(&"a".repeat(40)).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn a_peer_that_never_sends_headers_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _held = tokio::spawn(async move {
            let conn = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(conn);
        });
        let client = client_for(port, dir.path()).with_tarball_timeout(Duration::from_millis(300));
        let err = client.fetch_tarball(&"a".repeat(40)).await.unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[tokio::test]
    async fn tarball_within_the_cap_is_returned_whole() {
        let dir = tempfile::tempdir().unwrap();
        let port = serve_once(vec![7u8; 10_000]).await;
        let client = client_for(port, dir.path()).with_max_tarball_bytes(10_000);
        let bytes = client.fetch_tarball(&"a".repeat(40)).await.unwrap();
        assert_eq!(bytes.len(), 10_000);
    }

    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[tokio::test]
    async fn rustls_client_rejects_a_self_signed_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        let minted = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
            ])
            .output()
            .expect("openssl is required to mint a throwaway certificate");
        assert!(
            minted.status.success(),
            "{}",
            String::from_utf8_lossy(&minted.stderr)
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let server = KillOnDrop(
            Command::new("openssl")
                .args([
                    "s_server",
                    "-accept",
                    &format!("127.0.0.1:{port}"),
                    "-cert",
                    cert.to_str().unwrap(),
                    "-key",
                    key.to_str().unwrap(),
                    "-www",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "openssl s_server did not listen"
            );
            std::thread::sleep(Duration::from_millis(30));
        }

        let token = dir.path().join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        let client = GithubClient::new(
            &format!("https://127.0.0.1:{port}"),
            "owner",
            "name",
            "main",
            &cite_core::GithubToken::File(token),
        )
        .unwrap();
        let err = client.poll_head(None).await.unwrap_err();
        drop(server);
        let text = err.to_string().to_lowercase();
        assert!(
            text.contains("certificate") || text.contains("unknownissuer"),
            "{err}"
        );
    }
}
