//! Doppler API client and the pure rules that turn a Doppler config into site variables.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use cite_edge::status::{BuildEnvPatch, MAX_ENV_BYTES, MAX_ENV_KEYS};
use cite_edge::validate::is_valid_doppler_slug;
use futures_util::future::BoxFuture;
use reqwest::header::{self, HeaderValue};
use reqwest::{StatusCode, Url};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ConnectorError;
use crate::cfapi::remote_text;
use crate::siteops::EnvKind;

pub const DOPPLER_API: &str = "https://api.doppler.com";
const DOPPLER_HOST: &str = "api.doppler.com";
pub const TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOKEN_BYTES: usize = 512;
const PER_PAGE: usize = 100;
const MAX_PAGES: usize = 20;
// Doppler adds DOPPLER_PROJECT, DOPPLER_CONFIG and DOPPLER_ENVIRONMENT to every download.
const META_PREFIX: &str = "DOPPLER_";
const MAX_SKIPPED_SHOWN: usize = 10;
const REDACTED: &str = "[redacted]";
pub const NO_TOKEN: &str =
    "No Doppler token: set CITE_DOPPLER_TOKEN on the connector or pass a token for this site";

pub(crate) fn token_secret(site_id: &str) -> String {
    format!("site-{site_id}.doppler-token")
}

pub(crate) fn snapshot_secret(site_id: &str, kind: EnvKind) -> String {
    match kind {
        EnvKind::Build => format!("site-{site_id}.doppler-build"),
        EnvKind::Runtime => format!("site-{site_id}.doppler-runtime"),
    }
}

pub const SERVICE_TOKEN_PREFIX: &str = "dp.st.";

/// A Doppler service or personal token: wiped on drop, never printed.
#[derive(Clone)]
pub struct DopplerToken(Zeroizing<String>);

impl DopplerToken {
    pub fn parse(raw: &str) -> Result<Self, DopplerError> {
        let ok = !raw.is_empty()
            && raw.len() <= MAX_TOKEN_BYTES
            && raw.bytes().all(|b| b.is_ascii_graphic());
        if ok {
            Ok(Self(Zeroizing::new(raw.to_string())))
        } else {
            Err(DopplerError::BadToken)
        }
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// A service token is scoped to one project and config, so it alone can name what a site reads.
    pub fn is_service_token(&self) -> bool {
        self.0.starts_with(SERVICE_TOKEN_PREFIX)
    }

    fn scrub(&self, text: &str) -> String {
        text.replace(self.0.as_str(), REDACTED)
    }
}

impl fmt::Debug for DopplerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DopplerToken(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DopplerError {
    NoToken,
    BadToken,
    Rejected,
    Forbidden,
    NotFound,
    RateLimited { retry_after: Option<u64> },
    Remote { status: u16, message: String },
    Unreachable(String),
    TooLarge,
    Malformed(&'static str),
    Limits(String),
    Local(String),
}

impl DopplerError {
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            DopplerError::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }
}

impl fmt::Display for DopplerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DopplerError::NoToken => f.write_str(NO_TOKEN),
            DopplerError::BadToken => f.write_str(
                "the Doppler token must be 1 to 512 printable ASCII characters without spaces",
            ),
            DopplerError::Rejected => f.write_str("Doppler rejected the token"),
            DopplerError::Forbidden => {
                f.write_str("the Doppler token may not read this project or config")
            }
            DopplerError::NotFound => f.write_str("Doppler has no such project or config"),
            DopplerError::RateLimited {
                retry_after: Some(secs),
            } => write!(f, "Doppler is rate limiting this node; retry in {secs} seconds"),
            DopplerError::RateLimited { retry_after: None } => {
                f.write_str("Doppler is rate limiting this node; retry later")
            }
            DopplerError::Remote { status, message } if message.is_empty() => {
                write!(f, "Doppler answered with status {status}")
            }
            DopplerError::Remote { status, message } => {
                write!(f, "Doppler answered with status {status}: {message}")
            }
            DopplerError::Unreachable(msg) | DopplerError::Limits(msg) => f.write_str(msg),
            DopplerError::TooLarge => f.write_str("Doppler sent a response larger than 4 MiB"),
            DopplerError::Malformed(what) => write!(f, "Doppler sent a malformed {what}"),
            DopplerError::Local(msg) => {
                write!(f, "the synced Doppler variables could not be saved: {msg}")
            }
        }
    }
}

impl From<DopplerError> for ConnectorError {
    fn from(e: DopplerError) -> Self {
        let text = e.to_string();
        match e {
            DopplerError::RateLimited { .. } => ConnectorError::TooManyRequests(text),
            DopplerError::Unreachable(_) | DopplerError::TooLarge => {
                ConnectorError::Unavailable(text)
            }
            DopplerError::Remote { status, .. } if status >= 500 => {
                ConnectorError::Unavailable(text)
            }
            DopplerError::Local(_) => ConnectorError::Internal(text),
            _ => ConnectorError::BadRequest(text),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DopplerProject {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DopplerConfig {
    pub name: String,
    pub environment: String,
}

/// One downloaded config; the Debug output lists names only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Downloaded {
    pub vars: BTreeMap<String, String>,
    pub not_text: Vec<String>,
}

impl fmt::Debug for Downloaded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Downloaded")
            .field("names", &self.vars.keys().collect::<Vec<_>>())
            .field("not_text", &self.not_text)
            .finish()
    }
}

/// Where synced secrets come from: the Doppler API in production, a fake in tests.
pub trait DopplerSource: Send + Sync {
    fn projects<'a>(
        &'a self,
        token: &'a DopplerToken,
    ) -> BoxFuture<'a, Result<Vec<DopplerProject>, DopplerError>>;
    fn configs<'a>(
        &'a self,
        token: &'a DopplerToken,
        project: &'a str,
    ) -> BoxFuture<'a, Result<Vec<DopplerConfig>, DopplerError>>;
    fn download<'a>(
        &'a self,
        token: &'a DopplerToken,
        project: &'a str,
        config: &'a str,
    ) -> BoxFuture<'a, Result<Downloaded, DopplerError>>;
}

// Stands in when the HTTP client could not be built, so every call fails with the reason instead of panicking.
pub struct Offline(pub String);

impl DopplerSource for Offline {
    fn projects<'a>(
        &'a self,
        _token: &'a DopplerToken,
    ) -> BoxFuture<'a, Result<Vec<DopplerProject>, DopplerError>> {
        Box::pin(async move { Err(DopplerError::Unreachable(self.0.clone())) })
    }

    fn configs<'a>(
        &'a self,
        _token: &'a DopplerToken,
        _project: &'a str,
    ) -> BoxFuture<'a, Result<Vec<DopplerConfig>, DopplerError>> {
        Box::pin(async move { Err(DopplerError::Unreachable(self.0.clone())) })
    }

    fn download<'a>(
        &'a self,
        _token: &'a DopplerToken,
        _project: &'a str,
        _config: &'a str,
    ) -> BoxFuture<'a, Result<Downloaded, DopplerError>> {
        Box::pin(async move { Err(DopplerError::Unreachable(self.0.clone())) })
    }
}

pub struct DopplerClient {
    http: reqwest::Client,
    base: String,
    plain_http: bool,
}

impl DopplerClient {
    pub fn new() -> crate::Result<Self> {
        Self::build(DOPPLER_API, false)
    }

    // Points the client at a local mock over plain HTTP; only tests can build this.
    #[cfg(test)]
    pub fn local(base: &str) -> crate::Result<Self> {
        Self::build(base, true)
    }

    fn build(base: &str, plain_http: bool) -> crate::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .connect_timeout(TIMEOUT)
            .https_only(!plain_http)
            .user_agent(concat!("cite-connector/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ConnectorError::Internal(format!("cannot build the HTTP client: {e}")))?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            plain_http,
        })
    }

    // Only https://api.doppler.com is ever contacted; the test client may use plain HTTP to loopback.
    fn url(&self, path: &str, query: &[(&str, &str)]) -> Result<Url, DopplerError> {
        let refused = || DopplerError::Unreachable("refusing to contact a host other than api.doppler.com".into());
        let mut url = Url::parse(&format!("{}{path}", self.base)).map_err(|_| refused())?;
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let ok = if self.plain_http {
            url.scheme() == "http" && host == "127.0.0.1"
        } else {
            url.scheme() == "https" && host == DOPPLER_HOST && url.port().is_none()
        };
        if !ok || !url.username().is_empty() || url.password().is_some() {
            return Err(refused());
        }
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }

    async fn get(&self, token: &DopplerToken, url: Url) -> Result<Vec<u8>, DopplerError> {
        let bearer = Zeroizing::new(format!("Bearer {}", token.expose()));
        let mut auth = HeaderValue::from_str(&bearer).map_err(|_| DopplerError::BadToken)?;
        auth.set_sensitive(true);
        let mut res = self
            .http
            .get(url)
            .header(header::AUTHORIZATION, auth)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| net_error(&e))?;
        let status = res.status();
        if status.is_redirection() {
            return Err(DopplerError::Unreachable(
                "Doppler answered with a redirect, which is not followed".into(),
            ));
        }
        if res
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(DopplerError::TooLarge);
        }
        let retry_after = res
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|e| net_error(&e))? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(DopplerError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        match status {
            s if s.is_success() => Ok(body),
            StatusCode::UNAUTHORIZED => Err(DopplerError::Rejected),
            StatusCode::FORBIDDEN => Err(DopplerError::Forbidden),
            StatusCode::NOT_FOUND => Err(DopplerError::NotFound),
            StatusCode::TOO_MANY_REQUESTS => Err(DopplerError::RateLimited { retry_after }),
            s => Err(DopplerError::Remote {
                status: s.as_u16(),
                message: remote_text(&token.scrub(&remote_message(&body))),
            }),
        }
    }

    async fn pages(
        &self,
        token: &DopplerToken,
        path: &str,
        filter: &[(&str, &str)],
        field: &'static str,
    ) -> Result<Vec<Value>, DopplerError> {
        let per_page = PER_PAGE.to_string();
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let page = page.to_string();
            let mut query = filter.to_vec();
            query.extend([("page", page.as_str()), ("per_page", per_page.as_str())]);
            let body = self.get(token, self.url(path, &query)?).await?;
            let parsed: Value =
                serde_json::from_slice(&body).map_err(|_| DopplerError::Malformed(field))?;
            let items = parsed
                .get(field)
                .and_then(Value::as_array)
                .ok_or(DopplerError::Malformed(field))?;
            let count = items.len();
            out.extend(items.iter().cloned());
            if count < PER_PAGE {
                break;
            }
        }
        Ok(out)
    }
}

impl DopplerSource for DopplerClient {
    fn projects<'a>(
        &'a self,
        token: &'a DopplerToken,
    ) -> BoxFuture<'a, Result<Vec<DopplerProject>, DopplerError>> {
        Box::pin(async move {
            let items = self.pages(token, "/v3/projects", &[], "projects").await?;
            Ok(parse_projects(&items))
        })
    }

    fn configs<'a>(
        &'a self,
        token: &'a DopplerToken,
        project: &'a str,
    ) -> BoxFuture<'a, Result<Vec<DopplerConfig>, DopplerError>> {
        Box::pin(async move {
            let items = self
                .pages(token, "/v3/configs", &[("project", project)], "configs")
                .await?;
            Ok(parse_configs(&items))
        })
    }

    fn download<'a>(
        &'a self,
        token: &'a DopplerToken,
        project: &'a str,
        config: &'a str,
    ) -> BoxFuture<'a, Result<Downloaded, DopplerError>> {
        Box::pin(async move {
            // A service token is scoped to one config, so a token-only binding names neither.
            let query: &[(&str, &str)] = if project.is_empty() && config.is_empty() {
                &[("format", "json")]
            } else {
                &[("project", project), ("config", config), ("format", "json")]
            };
            let url = self.url("/v3/configs/config/secrets/download", query)?;
            let body = Zeroizing::new(self.get(token, url).await?);
            parse_download(&body)
        })
    }
}

fn net_error(e: &reqwest::Error) -> DopplerError {
    if e.is_timeout() {
        DopplerError::Unreachable(format!(
            "Doppler did not answer within {} seconds",
            TIMEOUT.as_secs()
        ))
    } else {
        tracing::debug!(error = %e, "doppler request failed");
        DopplerError::Unreachable("Doppler could not be reached".into())
    }
}

// Doppler errors carry {"messages": [...]}; the caller scrubs the token before the text is cut short.
fn remote_message(body: &[u8]) -> String {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    parsed
        .as_ref()
        .and_then(|v| v.get("messages"))
        .and_then(Value::as_array)
        .map(|m| {
            m.iter()
                .filter_map(Value::as_str)
                .take(5)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default()
}

fn text_field(item: &Value, key: &str) -> Option<String> {
    item.get(key).and_then(Value::as_str).map(str::to_string)
}

pub(crate) fn parse_projects(items: &[Value]) -> Vec<DopplerProject> {
    items
        .iter()
        .filter_map(|item| {
            let slug = text_field(item, "slug").filter(|s| is_valid_doppler_slug(s))?;
            let name = remote_text(&text_field(item, "name").unwrap_or_else(|| slug.clone()));
            Some(DopplerProject { slug, name })
        })
        .collect()
}

pub(crate) fn parse_configs(items: &[Value]) -> Vec<DopplerConfig> {
    items
        .iter()
        .filter_map(|item| {
            let name = text_field(item, "name").filter(|s| is_valid_doppler_slug(s))?;
            let environment = remote_text(&text_field(item, "environment").unwrap_or_default());
            Some(DopplerConfig { name, environment })
        })
        .collect()
}

pub(crate) fn parse_download(body: &[u8]) -> Result<Downloaded, DopplerError> {
    let parsed: serde_json::Map<String, Value> =
        serde_json::from_slice(body).map_err(|_| DopplerError::Malformed("secrets download"))?;
    let mut out = Downloaded::default();
    for (name, value) in parsed {
        match value {
            Value::String(text) => {
                out.vars.insert(name, text);
            }
            _ => out.not_text.push(name),
        }
    }
    Ok(out)
}

/// A Doppler name left out of a site's variables, and why; never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

/// The variables of one kind after filtering; the Debug output lists names only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Filtered {
    pub vars: BTreeMap<String, String>,
    pub skipped: Vec<Skipped>,
}

impl fmt::Debug for Filtered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filtered")
            .field("names", &self.vars.keys().collect::<Vec<_>>())
            .field("skipped", &self.skipped)
            .finish()
    }
}

fn shown_name(name: &str) -> String {
    remote_text(name).chars().take(64).collect()
}

/// Keeps the names the target refuses nothing of, under the same rules as a manual patch.
pub fn filter_for(kind: EnvKind, raw: &Downloaded) -> Filtered {
    let label = kind.label();
    let mut out = Filtered::default();
    for name in &raw.not_text {
        out.skipped.push(Skipped {
            name: shown_name(name),
            reason: format!("{label}: the value is not text"),
        });
    }
    for (name, value) in &raw.vars {
        if name.to_ascii_uppercase().starts_with(META_PREFIX) {
            out.skipped.push(Skipped {
                name: shown_name(name),
                reason: format!("{label}: Doppler metadata"),
            });
            continue;
        }
        let probe = BuildEnvPatch {
            set: BTreeMap::from([(name.clone(), value.clone())]),
            unset: Vec::new(),
        };
        match kind.validate(&probe) {
            Ok(()) => {
                out.vars.insert(name.clone(), value.clone());
            }
            Err(e) => out.skipped.push(Skipped {
                name: shown_name(name),
                reason: remote_text(&e.0),
            }),
        }
    }
    out
}

/// The same caps a manual patch meets: MAX_ENV_KEYS names and MAX_ENV_BYTES of JSON.
pub fn env_limits(map: &BTreeMap<String, String>, label: &str) -> Result<(), String> {
    if map.len() > MAX_ENV_KEYS {
        return Err(format!("{label}: at most {MAX_ENV_KEYS} variables"));
    }
    let size = serde_json::to_string(map).map_or(usize::MAX, |s| s.len());
    if size > MAX_ENV_BYTES {
        return Err(format!(
            "{label}: the variables are larger than {} KiB together",
            MAX_ENV_BYTES / 1024
        ));
    }
    Ok(())
}

/// Doppler values form the base and the variables set by hand override them.
pub fn merge_env(
    synced: BTreeMap<String, String>,
    manual: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = synced;
    merged.extend(manual);
    merged
}

/// SHA-256 over the sorted JSON of one map, so the same variables always give the same hash.
pub fn snapshot_hash(map: &BTreeMap<String, String>) -> String {
    let canonical = serde_json::to_string(map).unwrap_or_default();
    Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn skipped_note(skipped: &[Skipped]) -> Option<String> {
    if skipped.is_empty() {
        return None;
    }
    let shown: Vec<String> = skipped
        .iter()
        .take(MAX_SKIPPED_SHOWN)
        .map(|s| format!("{} ({})", s.name, s.reason))
        .collect();
    let more = skipped.len().saturating_sub(MAX_SKIPPED_SHOWN);
    let tail = if more > 0 {
        format!("; and {more} more")
    } else {
        String::new()
    };
    Some(format!(
        "skipped {} Doppler variables: {}{tail}",
        skipped.len(),
        shown.join("; ")
    ))
}

#[cfg(test)]
pub(crate) mod mock {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use serde_json::{Value, json};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Mode {
        Normal,
        Status(u16),
        RateLimited(u64),
        Redirect,
        Huge,
    }

    pub struct MockState {
        pub token: String,
        pub secrets: Mutex<std::collections::BTreeMap<(String, String), Value>>,
        pub mode: Mutex<Mode>,
        pub downloads: AtomicUsize,
        pub queries: Mutex<Vec<String>>,
        // The (project, config) query parameters of each download, None where a parameter was absent.
        pub download_params: Mutex<Vec<(Option<String>, Option<String>)>>,
    }

    impl MockState {
        pub fn set(&self, project: &str, config: &str, secrets: Value) {
            self.secrets
                .lock()
                .unwrap()
                .insert((project.to_string(), config.to_string()), secrets);
        }

        pub fn mode(&self, mode: Mode) {
            *self.mode.lock().unwrap() = mode;
        }

        pub fn downloads(&self) -> usize {
            self.downloads.load(Ordering::SeqCst)
        }
    }

    pub struct MockDoppler {
        pub base: String,
        pub state: Arc<MockState>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockDoppler {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    type Q = Query<std::collections::HashMap<String, String>>;

    fn gate(s: &MockState, headers: &HeaderMap) -> Option<Response> {
        let want = format!("Bearer {}", s.token);
        if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
            return Some((StatusCode::UNAUTHORIZED, json!({ "messages": ["Invalid Auth token"] }).to_string()).into_response());
        }
        match *s.mode.lock().unwrap() {
            Mode::Normal => None,
            Mode::Status(code) => Some(
                (
                    StatusCode::from_u16(code).unwrap(),
                    json!({ "messages": [format!("echo {}", s.token)] }).to_string(),
                )
                    .into_response(),
            ),
            Mode::RateLimited(secs) => Some(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, secs.to_string())],
                    "{}",
                )
                    .into_response(),
            ),
            Mode::Redirect => Some(
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "http://127.0.0.1:1/elsewhere")],
                )
                    .into_response(),
            ),
            Mode::Huge => Some("x".repeat(super::MAX_RESPONSE_BYTES + 1).into_response()),
        }
    }

    async fn projects(State(s): State<Arc<MockState>>, headers: HeaderMap, q: Q) -> Response {
        if let Some(r) = gate(&s, &headers) {
            return r;
        }
        s.queries.lock().unwrap().push(format!("projects {:?}", q.0.get("page")));
        let mut slugs: Vec<String> = s
            .secrets
            .lock()
            .unwrap()
            .keys()
            .map(|(p, _)| p.clone())
            .collect();
        slugs.dedup();
        let items: Vec<Value> = slugs
            .iter()
            .map(|p| json!({ "id": p, "slug": p, "name": format!("Project {p}") }))
            .chain([json!({ "slug": "bad slug", "name": "x" })])
            .collect();
        axum::Json(json!({ "projects": items, "page": 1, "success": true })).into_response()
    }

    async fn configs(State(s): State<Arc<MockState>>, headers: HeaderMap, q: Q) -> Response {
        if let Some(r) = gate(&s, &headers) {
            return r;
        }
        let project = q.0.get("project").cloned().unwrap_or_default();
        let items: Vec<Value> = s
            .secrets
            .lock()
            .unwrap()
            .keys()
            .filter(|(p, _)| *p == project)
            .map(|(_, c)| json!({ "name": c, "environment": "prd", "project": project }))
            .collect();
        if items.is_empty() {
            return (StatusCode::NOT_FOUND, "{}").into_response();
        }
        axum::Json(json!({ "configs": items, "page": 1 })).into_response()
    }

    async fn download(State(s): State<Arc<MockState>>, headers: HeaderMap, q: Q) -> Response {
        s.downloads.fetch_add(1, Ordering::SeqCst);
        if let Some(r) = gate(&s, &headers) {
            return r;
        }
        if q.0.get("format").map(String::as_str) != Some("json") {
            return (StatusCode::BAD_REQUEST, "{}").into_response();
        }
        s.download_params
            .lock()
            .unwrap()
            .push((q.0.get("project").cloned(), q.0.get("config").cloned()));
        let key = (
            q.0.get("project").cloned().unwrap_or_default(),
            q.0.get("config").cloned().unwrap_or_default(),
        );
        match s.secrets.lock().unwrap().get(&key) {
            Some(v) => axum::Json(v.clone()).into_response(),
            None => (StatusCode::NOT_FOUND, "{}").into_response(),
        }
    }

    pub async fn start(token: &str) -> MockDoppler {
        let state = Arc::new(MockState {
            token: token.to_string(),
            secrets: Mutex::default(),
            mode: Mutex::new(Mode::Normal),
            downloads: AtomicUsize::new(0),
            queries: Mutex::default(),
            download_params: Mutex::default(),
        });
        let app = Router::new()
            .route("/v3/projects", get(projects))
            .route("/v3/configs", get(configs))
            .route("/v3/configs/config/secrets/download", get(download))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        MockDoppler {
            base: format!("http://{addr}"),
            state,
            task,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{self, Mode};
    use super::*;
    use serde_json::json;

    const TOKEN: &str = "dp.st.prd.mocksecretvalue";

    fn token() -> DopplerToken {
        DopplerToken::parse(TOKEN).unwrap()
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn only_https_to_the_doppler_api_is_contacted() {
        let client = DopplerClient::new().unwrap();
        let url = client
            .url("/v3/configs", &[("project", "a b&c")])
            .expect("allowed");
        assert_eq!(url.host_str(), Some("api.doppler.com"));
        assert_eq!(url.query(), Some("project=a+b%26c"));
        for base in [
            "http://api.doppler.com",
            "https://api.doppler.com.evil.example",
            "https://api.doppler.com:8443",
            "https://user:pw@api.doppler.com",
            "https://127.0.0.1",
        ] {
            let other = DopplerClient::build(base, false).unwrap();
            assert!(other.url("/v3/projects", &[]).is_err(), "{base}");
        }
        let local = DopplerClient::local("http://127.0.0.1:9").unwrap();
        assert!(local.url("/v3/projects", &[]).is_ok());
        let elsewhere = DopplerClient::local("http://10.0.0.1:9").unwrap();
        assert!(elsewhere.url("/v3/projects", &[]).is_err());
    }

    #[test]
    fn tokens_are_checked_and_never_printed() {
        for bad in ["", "has space", "caf\u{e9}", &"a".repeat(513)] {
            assert_eq!(DopplerToken::parse(bad).unwrap_err(), DopplerError::BadToken);
        }
        assert!(DopplerToken::parse(&"a".repeat(512)).is_ok());
        let t = token();
        assert!(!format!("{t:?}").contains("mocksecret"));
        assert_eq!(t.scrub(&format!("x {TOKEN} y")), "x [redacted] y");
        assert!(!DopplerError::BadToken.to_string().contains(TOKEN));
    }

    #[test]
    fn errors_map_to_the_api_statuses() {
        let status = |e: DopplerError| ConnectorError::from(e).status();
        assert_eq!(status(DopplerError::NoToken), 400);
        assert_eq!(status(DopplerError::Rejected), 400);
        assert_eq!(status(DopplerError::NotFound), 400);
        assert_eq!(
            status(DopplerError::RateLimited {
                retry_after: Some(5)
            }),
            429
        );
        assert_eq!(status(DopplerError::TooLarge), 503);
        assert_eq!(
            status(DopplerError::Remote {
                status: 502,
                message: String::new()
            }),
            503
        );
        assert_eq!(
            status(DopplerError::Remote {
                status: 422,
                message: "x".into()
            }),
            400
        );
        assert_eq!(DopplerError::NoToken.to_string(), NO_TOKEN);
    }

    #[test]
    fn build_names_follow_the_build_rules_and_meta_variables_are_dropped() {
        let raw = Downloaded {
            vars: map(&[
                ("API_URL", "https://x"),
                ("DOPPLER_PROJECT", "shop"),
                ("DOPPLER_CONFIG", "prd"),
                ("doppler_environment", "prd"),
                ("PATH", "/evil"),
                ("SHELL", "/bin/sh"),
                ("PORT", "8080"),
                ("lower", "v"),
                ("BIG", &"x".repeat(4097)),
                ("CONTROL", "a\nb"),
            ]),
            not_text: vec!["NUMBER".into()],
        };
        let build = filter_for(EnvKind::Build, &raw);
        assert_eq!(build.vars.keys().collect::<Vec<_>>(), ["API_URL", "PORT"]);
        let runtime = filter_for(EnvKind::Runtime, &raw);
        assert_eq!(
            runtime.vars.keys().collect::<Vec<_>>(),
            ["API_URL", "SHELL"]
        );
        let names = |f: &Filtered| {
            let mut n: Vec<String> = f.skipped.iter().map(|s| s.name.clone()).collect();
            n.sort();
            n
        };
        assert_eq!(
            names(&build),
            [
                "BIG",
                "CONTROL",
                "DOPPLER_CONFIG",
                "DOPPLER_PROJECT",
                "NUMBER",
                "PATH",
                "SHELL",
                "doppler_environment",
                "lower"
            ]
        );
        let meta = build
            .skipped
            .iter()
            .find(|s| s.name == "DOPPLER_PROJECT")
            .unwrap();
        assert!(meta.reason.contains("metadata"), "{meta:?}");
        for f in [&build, &runtime] {
            let text = format!("{f:?} {:?}", skipped_note(&f.skipped));
            assert!(!text.contains("/evil") && !text.contains("https://x"), "{text}");
            assert!(!text.contains("xxxx"), "{text}");
        }
    }

    #[test]
    fn the_skipped_note_counts_and_names_without_values() {
        assert_eq!(skipped_note(&[]), None);
        let many: Vec<Skipped> = (0..12)
            .map(|i| Skipped {
                name: format!("N{i}"),
                reason: "r".into(),
            })
            .collect();
        let note = skipped_note(&many).unwrap();
        assert!(note.starts_with("skipped 12 Doppler variables: N0 (r)"), "{note}");
        assert!(note.ends_with("and 2 more"), "{note}");
    }

    #[test]
    fn manual_variables_override_doppler_values() {
        let merged = merge_env(
            map(&[("A", "doppler"), ("B", "doppler")]),
            map(&[("B", "manual"), ("C", "manual")]),
        );
        assert_eq!(merged, map(&[("A", "doppler"), ("B", "manual"), ("C", "manual")]));
        assert_eq!(merge_env(BTreeMap::new(), map(&[("A", "1")])), map(&[("A", "1")]));
        assert_eq!(merge_env(map(&[("A", "1")]), BTreeMap::new()), map(&[("A", "1")]));
    }

    #[test]
    fn the_limits_are_128_names_and_24_kib() {
        let many: BTreeMap<String, String> =
            (0..128).map(|i| (format!("K{i}"), "v".into())).collect();
        env_limits(&many, "build env").expect("128 fit");
        let mut over = many.clone();
        over.insert("EXTRA".into(), "v".into());
        assert!(env_limits(&over, "build env").unwrap_err().contains("128"));
        let big: BTreeMap<String, String> =
            (0..7).map(|i| (format!("B{i}"), "x".repeat(4000))).collect();
        let err = env_limits(&big, "runtime env").unwrap_err();
        assert!(err.contains("24 KiB") && !err.contains("xxxx"), "{err}");
    }

    #[test]
    fn hashes_are_stable_and_follow_the_content() {
        let a = map(&[("B", "2"), ("A", "1")]);
        let b: BTreeMap<String, String> = [("A", "1"), ("B", "2")]
            .iter()
            .rev()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(snapshot_hash(&a), snapshot_hash(&b));
        assert_eq!(snapshot_hash(&a).len(), 64);
        assert_eq!(
            snapshot_hash(&BTreeMap::new()),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        assert_ne!(snapshot_hash(&a), snapshot_hash(&map(&[("A", "1"), ("B", "3")])));
        assert_ne!(snapshot_hash(&a), snapshot_hash(&map(&[("A", "1")])));
    }

    #[test]
    fn downloads_keep_text_values_and_name_the_rest() {
        let d = parse_download(br#"{"A":"1","N":5,"O":{"x":1},"E":""}"#).unwrap();
        assert_eq!(d.vars, map(&[("A", "1"), ("E", "")]));
        let mut not_text = d.not_text.clone();
        not_text.sort();
        assert_eq!(not_text, ["N", "O"]);
        assert!(!format!("{d:?}").contains('1'));
        assert_eq!(
            parse_download(b"[1]").unwrap_err(),
            DopplerError::Malformed("secrets download")
        );
    }

    #[test]
    fn listings_keep_bindable_slugs_only() {
        let projects = parse_projects(&[
            json!({ "slug": "shop", "name": "Shop\nWeb" }),
            json!({ "slug": "bad slug", "name": "x" }),
            json!({ "name": "no slug" }),
            json!({ "slug": "api" }),
        ]);
        assert_eq!(
            projects,
            [
                DopplerProject {
                    slug: "shop".into(),
                    name: "Shop Web".into()
                },
                DopplerProject {
                    slug: "api".into(),
                    name: "api".into()
                }
            ]
        );
        let configs = parse_configs(&[
            json!({ "name": "prd", "environment": "prd" }),
            json!({ "name": "../x", "environment": "dev" }),
        ]);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "prd");
    }

    #[tokio::test]
    async fn the_client_sends_the_bearer_token_and_reads_every_endpoint() {
        let server = mock::start(TOKEN).await;
        server.state.set("shop", "prd", json!({ "API_URL": "https://x", "DOPPLER_CONFIG": "prd" }));
        server.state.set("shop", "dev", json!({}));
        let client = DopplerClient::local(&server.base).unwrap();
        let t = token();
        let projects = client.projects(&t).await.unwrap();
        assert_eq!(projects.len(), 1, "the unbindable slug is dropped");
        assert_eq!(projects[0].slug, "shop");
        let configs = client.configs(&t, "shop").await.unwrap();
        let mut names: Vec<_> = configs.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["dev", "prd"]);
        let d = client.download(&t, "shop", "prd").await.unwrap();
        assert_eq!(d.vars["API_URL"], "https://x");
        assert_eq!(
            client.download(&t, "shop", "stg").await.unwrap_err(),
            DopplerError::NotFound
        );
        let wrong = DopplerToken::parse("dp.st.wrong").unwrap();
        assert_eq!(
            client.download(&wrong, "shop", "prd").await.unwrap_err(),
            DopplerError::Rejected
        );
        let queries = server.state.queries.lock().unwrap().clone();
        assert_eq!(queries, ["projects Some(\"1\")"]);
    }

    #[tokio::test]
    async fn failures_are_classified_without_echoing_the_token() {
        let server = mock::start(TOKEN).await;
        server.state.set("shop", "prd", json!({ "A": "1" }));
        let client = DopplerClient::local(&server.base).unwrap();
        let t = token();
        server.state.mode(Mode::RateLimited(42));
        let err = client.download(&t, "shop", "prd").await.unwrap_err();
        assert_eq!(err, DopplerError::RateLimited { retry_after: Some(42) });
        assert_eq!(err.retry_after(), Some(42));
        server.state.mode(Mode::Status(500));
        let err = client.download(&t, "shop", "prd").await.unwrap_err();
        assert!(matches!(err, DopplerError::Remote { status: 500, .. }), "{err:?}");
        assert!(!err.to_string().contains("mocksecret"), "{err}");
        assert!(err.to_string().contains("[redacted]"), "{err}");
        server.state.mode(Mode::Status(403));
        assert_eq!(
            client.download(&t, "shop", "prd").await.unwrap_err(),
            DopplerError::Forbidden
        );
        server.state.mode(Mode::Redirect);
        let err = client.download(&t, "shop", "prd").await.unwrap_err();
        assert!(err.to_string().contains("redirect"), "{err}");
        server.state.mode(Mode::Huge);
        assert_eq!(
            client.download(&t, "shop", "prd").await.unwrap_err(),
            DopplerError::TooLarge
        );
        let down = DopplerClient::local("http://127.0.0.1:1").unwrap();
        let err = down.download(&t, "shop", "prd").await.unwrap_err();
        assert!(matches!(err, DopplerError::Unreachable(_)), "{err:?}");
        assert!(!err.to_string().contains("mocksecret"));
    }
}
