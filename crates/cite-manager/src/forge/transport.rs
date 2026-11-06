//! HTTP for the non-GitHub forges: the token goes only to the configured API origin, redirects are followed by hand.

use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, IF_NONE_MATCH, LOCATION, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::{Client, Response, StatusCode, Url};
use serde::de::DeserializeOwned;

use super::{truncate, validate_forge_api_url};
use crate::{ManagerError, Result};

const MAX_REDIRECTS: usize = 5;
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: u64 = 64 * 1024;
const DEFAULT_MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const ARCHIVE_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const USER_AGENT_VALUE: &str = "cite-manager/0.1";

#[derive(Debug, Clone, Copy)]
pub(super) enum AuthScheme {
    Bearer,
    Token,
}

#[derive(Debug, Clone)]
pub(super) struct Transport {
    api: Client,
    download: Client,
    base: Url,
    base_str: String,
    token: cite_core::GithubToken,
    auth: AuthScheme,
    pub(super) max_archive_bytes: u64,
    pub(super) archive_timeout: Duration,
}

impl Transport {
    pub(super) fn new(
        api_url: &str,
        token: &cite_core::GithubToken,
        auth: AuthScheme,
    ) -> Result<Self> {
        validate_forge_api_url(api_url)
            .map_err(|why| ManagerError::new(format!("forge api url: {why}")))?;
        let base_str = api_url.trim_end_matches('/').to_string();
        let base = Url::parse(&base_str)
            .map_err(|err| ManagerError::new(format!("forge api url: {err}")))?;
        let api = Client::builder()
            .use_rustls_tls()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(30))
            .build()?;
        let download = Client::builder()
            .use_rustls_tls()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(IDLE_TIMEOUT)
            .build()?;
        Ok(Self {
            api,
            download,
            base,
            base_str,
            token: token.clone(),
            auth,
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            archive_timeout: ARCHIVE_TOTAL_TIMEOUT,
        })
    }

    pub(super) fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base_str)
    }

    pub(super) fn read_token(&self) -> Result<String> {
        self.token
            .read()
            .map_err(|err| ManagerError::new(err.to_string()))
    }

    /// True when the final response came from the API origin, so a 401 there is about our token.
    pub(super) fn is_api(&self, resp: &Response) -> bool {
        resp.url().origin() == self.base.origin()
    }

    fn auth_value(&self, token: &str) -> Result<HeaderValue> {
        let raw = match self.auth {
            AuthScheme::Bearer => format!("Bearer {token}"),
            AuthScheme::Token => format!("token {token}"),
        };
        let mut value = HeaderValue::from_str(&raw)
            .map_err(|err| ManagerError::new(format!("bad token header: {err}")))?;
        value.set_sensitive(true);
        Ok(value)
    }

    pub(super) async fn get_json(&self, url: &str, etag: Option<&str>) -> Result<Response> {
        self.send(&self.api, url, true, etag).await
    }

    async fn send(
        &self,
        client: &Client,
        url: &str,
        json: bool,
        etag: Option<&str>,
    ) -> Result<Response> {
        let auth = self.auth_value(&self.read_token()?)?;
        let mut url =
            Url::parse(url).map_err(|err| ManagerError::new(format!("bad forge url: {err}")))?;
        for _ in 0..=MAX_REDIRECTS {
            let mut req = client.get(url.clone()).header(USER_AGENT, USER_AGENT_VALUE);
            if json {
                req = req.header(ACCEPT, "application/json");
            }
            if url.origin() == self.base.origin() {
                req = req.header(AUTHORIZATION, auth.clone());
                if let Some(tag) = etag {
                    req = req.header(IF_NONE_MATCH, tag);
                }
            }
            let resp = req.send().await?;
            let status = resp.status();
            if !status.is_redirection() || status == StatusCode::NOT_MODIFIED {
                return Ok(resp);
            }
            let Some(location) = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()) else {
                return Ok(resp);
            };
            url = next_hop(&url, location)?;
        }
        Err(ManagerError::new(format!(
            "forge redirected more than {MAX_REDIRECTS} times"
        )))
    }

    pub(super) async fn json<T: DeserializeOwned>(resp: Response) -> Result<T> {
        let body = read_capped(resp, MAX_JSON_BYTES, "forge response")
            .await?
            .ok_or_else(|| {
                ManagerError::new(format!("forge response exceeds {MAX_JSON_BYTES} bytes"))
            })?;
        Ok(serde_json::from_slice(&body)?)
    }

    pub(super) async fn error_text(resp: Response) -> String {
        match read_capped(resp, MAX_ERROR_BODY_BYTES, "forge response").await {
            Ok(Some(body)) => truncate(&String::from_utf8_lossy(&body), 200),
            Ok(None) => "(response body too large)".to_string(),
            Err(_) => String::new(),
        }
    }

    /// The whole exchange, redirects and headers included, is bounded by the total timeout.
    pub(super) async fn fetch_archive(&self, url: &str) -> Result<Vec<u8>> {
        match tokio::time::timeout(self.archive_timeout, self.download_archive(url)).await {
            Ok(result) => result,
            Err(_) => Err(ManagerError::new("tarball download timed out")),
        }
    }

    async fn download_archive(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.send(&self.download, url, false, None).await?;
        if resp.status() == StatusCode::UNAUTHORIZED && self.is_api(&resp) {
            return Err(ManagerError::new("token_invalid"));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(ManagerError::new(format!(
                "tarball fetch failed ({status}): {}",
                Self::error_text(resp).await
            )));
        }
        let max = self.max_archive_bytes;
        if resp.content_length().is_some_and(|len| len > max) {
            return Err(archive_too_large(max));
        }
        read_capped(resp, max, "tarball download")
            .await?
            .ok_or_else(|| archive_too_large(max))
    }
}

/// Refuses a downgrade from https, non-http schemes and credentials embedded in the target.
pub(super) fn next_hop(current: &Url, location: &str) -> Result<Url> {
    let next = current
        .join(location)
        .map_err(|err| ManagerError::new(format!("forge sent a bad redirect: {err}")))?;
    match (current.scheme(), next.scheme()) {
        ("https", "https") | ("http", "https") | ("http", "http") => {}
        (from, to) => {
            return Err(ManagerError::new(format!(
                "forge redirect refused: {from} to {to}"
            )));
        }
    }
    if !next.username().is_empty() || next.password().is_some() {
        return Err(ManagerError::new(
            "forge redirect refused: the target carries credentials",
        ));
    }
    Ok(next)
}

fn archive_too_large(max: u64) -> ManagerError {
    ManagerError::new(format!(
        "source tarball exceeds CITE_MAX_SOURCE_COMPRESSED_BYTES ({max})"
    ))
}

/// `Ok(None)` means the body grew past `max`; reading stops there.
async fn read_capped(mut resp: Response, max: u64, what: &str) -> Result<Option<Vec<u8>>> {
    let mut body = Vec::new();
    loop {
        let chunk = match tokio::time::timeout(IDLE_TIMEOUT, resp.chunk()).await {
            Ok(chunk) => chunk?,
            Err(_) => return Err(ManagerError::new(format!("{what} stalled"))),
        };
        let Some(chunk) = chunk else {
            return Ok(Some(body));
        };
        if (body.len() as u64).saturating_add(chunk.len() as u64) > max {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
}
