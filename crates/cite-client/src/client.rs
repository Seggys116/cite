use std::fmt;
use std::path::Path;
use std::time::Duration;

use cite_edge::analytics::{Summary, Timeseries, TopItem};
use cite_edge::bot::BotSummary;
use cite_edge::model::{
    Deployment, EdgeSettings, FirewallRule, LogEvent, MaintenancePage, Site, Slot, Target,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::analytics::{
    AnalyticsQuery, BotReport, Compare, Facets, RequestCursor, RequestsPage, SummaryReport,
    TimeseriesReport, TopReport, TopSort, limit_pair, page_pairs,
};
use crate::archive::{
    ArchiveEntry, ArchiveList, CutReport, CutRequest, RestoreReport, archive_download_name,
    archive_kind_from_name, validate_archive_name,
};
use crate::certificate::{
    CertificateInfo, CertificateList, CertificateSaved, CertificateUpload, CloudflareRanges,
    validate_certificate_id,
};
use crate::config::{NodeConfig, parse_node_url};
use crate::error::ClientError;
use crate::export::{
    AnalyticsStats, EXPORT_TIMEOUT, ExportQuery, ExportReport, ExportStream, validate_top_kind,
};
use crate::firewall::{BulkResult, FirewallBulk};
use crate::site_ops::{
    CloudflareToken, DeployAccepted, EnvKind, EnvNames, EnvPatch, GithubTokenBody, LogsQuery,
    TokenStatus, validate_job_id,
};
use crate::zone::{ZoneSecret, ZoneSecretStatus, validate_site_id};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

// The connector gives a deploy up to 700 s end to end; create, switch and rollback wait for health too.
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(700);
const ACTION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ERROR_CHARS: usize = 512;

type Res<T> = std::result::Result<T, ClientError>;

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    #[serde(default)]
    pub expires_at: Value,
}

impl fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginResponse")
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Whether the node holds a GitHub token of its own, and where it came from; the token itself is never reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubInfo {
    #[serde(default)]
    pub token_configured: bool,
    /// "env", "file" or "none".
    #[serde(default)]
    pub source: String,
    /// The forge API host the node fetches from, when it reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    /// Feature names the connector supports; empty on connectors that predate the list.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Absent on connectors that predate the node-level token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubInfo>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteDetail {
    pub site: Site,
    pub live: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployRequest {
    pub targets: Vec<Target>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetInfo {
    pub name: String,
    pub title: String,
    pub description: String,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: String,
    pub actor: String,
    pub action: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMeta {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreatedToken {
    pub id: String,
    pub name: String,
    pub token: String,
}

impl fmt::Debug for CreatedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedToken")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("token", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadResult {
    pub ok: bool,
    #[serde(default)]
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestQuery {
    pub limit: Option<usize>,
    pub status: Option<u16>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub ip: Option<String>,
    pub blocked: Option<bool>,
}

impl RequestQuery {
    fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(v) = self.limit {
            out.push(("limit", v.to_string()));
        }
        if let Some(v) = self.status {
            out.push(("status", v.to_string()));
        }
        if let Some(v) = &self.method {
            out.push(("method", v.clone()));
        }
        if let Some(v) = &self.path {
            out.push(("path", v.clone()));
        }
        if let Some(v) = &self.ip {
            out.push(("ip", v.clone()));
        }
        if let Some(v) = self.blocked {
            out.push(("blocked", v.to_string()));
        }
        out
    }
}

#[derive(Clone, Copy)]
struct Opts {
    auth: bool,
    timeout: Option<Duration>,
}

const DEFAULT_OPTS: Opts = Opts {
    auth: true,
    timeout: None,
};

const ACTION_OPTS: Opts = Opts {
    auth: true,
    timeout: Some(ACTION_TIMEOUT),
};

// Backups, cuts and restores copy or rewrite the whole database, so they get the export timeout.
const BULK_OPTS: Opts = Opts {
    auth: true,
    timeout: Some(EXPORT_TIMEOUT),
};

#[derive(Clone)]
pub struct NodeClient {
    name: String,
    base: String,
    token: String,
    http: reqwest::Client,
}

impl fmt::Debug for NodeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeClient")
            .field("name", &self.name)
            .field("base", &self.base)
            .field("token", &"[redacted]")
            .finish()
    }
}

// Path segments come from callers, so everything outside the unreserved set is escaped.
fn enc(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Res<T> {
    serde_json::from_slice(bytes).map_err(|e| ClientError::Decode(e.to_string()))
}

fn body_of<B: Serialize + ?Sized>(body: &B) -> Res<Option<Value>> {
    serde_json::to_value(body)
        .map(Some)
        .map_err(|e| ClientError::Config(format!("cannot encode request: {e}")))
}

fn create_site_body(site: &Site, github_token: Option<&str>) -> Res<Option<Value>> {
    let mut body = serde_json::to_value(site)
        .map_err(|e| ClientError::Config(format!("cannot encode request: {e}")))?;
    if let (Some(token), Some(obj)) = (github_token.filter(|t| !t.is_empty()), body.as_object_mut())
    {
        obj.insert("github_token".to_string(), Value::String(token.to_string()));
    }
    Ok(Some(body))
}

fn error_message(bytes: &[u8], status: reqwest::StatusCode) -> String {
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let text = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| status.canonical_reason().map(str::to_string))
        .unwrap_or_else(|| format!("status {}", status.as_u16()));
    text.chars().take(MAX_ERROR_CHARS).collect()
}

async fn read_capped(
    mut resp: reqwest::Response,
) -> Res<(reqwest::StatusCode, Option<String>, Vec<u8>)> {
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // The declared length is checked first, then the running total for chunked bodies.
    if let Some(len) = resp.content_length()
        && len > MAX_RESPONSE_BYTES as u64
    {
        return Err(ClientError::Decode(
            "response exceeds the size limit".into(),
        ));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(ClientError::from_reqwest)? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::Decode(
                "response exceeds the size limit".into(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok((status, content_type, buf))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarded {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Deserialize)]
struct TopItems {
    #[serde(default)]
    items: Vec<TopItem>,
}

async fn open_stream(req: reqwest::RequestBuilder) -> Res<ExportStream> {
    let resp = req.send().await.map_err(ClientError::from_reqwest)?;
    if resp.status().is_success() {
        return Ok(ExportStream::new(resp));
    }
    let (status, _, buf) = read_capped(resp).await?;
    Err(ClientError::Status {
        code: status.as_u16(),
        message: error_message(&buf, status),
    })
}

fn analytics_query(window: &str, site: Option<&str>) -> Vec<(&'static str, String)> {
    let mut out = vec![("window", window.to_string())];
    if let Some(site) = site {
        out.push(("site", site.to_string()));
    }
    out
}

impl NodeClient {
    pub fn new(node: &NodeConfig, token: String) -> Res<Self> {
        let url = parse_node_url(&node.url, node.insecure_http)
            .map_err(|e| ClientError::Config(e.to_string()))?;
        let mut builder = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(60))
            .tcp_keepalive(Duration::from_secs(30))
            .user_agent(concat!("cite-client/", env!("CARGO_PKG_VERSION")));
        // A pinned CA replaces the public roots entirely so no other issuer can vouch for the node.
        if let Some(pem) = &node.ca_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| ClientError::Config(format!("invalid ca_pem: {e}")))?;
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert);
        }
        let http = builder
            .build()
            .map_err(|e| ClientError::Config(format!("cannot build http client: {e}")))?;
        Ok(Self {
            name: node.name.clone(),
            base: url.as_str().trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    async fn exec(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        opts: Opts,
    ) -> Res<Vec<u8>> {
        let url = format!("{}/api/v1{path}", self.base);
        let mut req = self.http.request(method, url);
        if !query.is_empty() {
            req = req.query(query);
        }
        if opts.auth && !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        if let Some(timeout) = opts.timeout {
            req = req.timeout(timeout);
        }
        Self::finish(req).await
    }

    // For bodies that hold a secret and were serialised straight from borrowed fields.
    async fn exec_json_bytes(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        opts: Opts,
    ) -> Res<Vec<u8>> {
        let url = format!("{}/api/v1{path}", self.base);
        let mut req = self
            .http
            .request(method, url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if opts.auth && !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        if let Some(timeout) = opts.timeout {
            req = req.timeout(timeout);
        }
        Self::finish(req).await
    }

    async fn finish(req: reqwest::RequestBuilder) -> Res<Vec<u8>> {
        let resp = req.send().await.map_err(ClientError::from_reqwest)?;
        let (status, _, buf) = read_capped(resp).await?;
        if status.is_success() {
            Ok(buf)
        } else {
            Err(ClientError::Status {
                code: status.as_u16(),
                message: error_message(&buf, status),
            })
        }
    }

    // Callers must validate `rest`; the node's own status and body are returned untouched.
    pub async fn forward(
        &self,
        method: Method,
        rest: &str,
        query: Option<&str>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Res<Forwarded> {
        let mut url = format!("{}/api/v1/{rest}", self.base);
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            url.push('?');
            url.push_str(q);
        }
        let mut req = self.http.request(method, url).timeout(timeout);
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        if !body.is_empty() {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let resp = req.send().await.map_err(ClientError::from_reqwest)?;
        let (status, content_type, body) = read_capped(resp).await?;
        Ok(Forwarded {
            status: status.as_u16(),
            content_type,
            body,
        })
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Res<T> {
        let bytes = self.exec(method, path, query, body, DEFAULT_OPTS).await?;
        decode(&bytes)
    }

    async fn unit(&self, method: Method, path: &str) -> Res<()> {
        self.exec(method, path, &[], None, DEFAULT_OPTS)
            .await
            .map(|_| ())
    }

    pub async fn login(&self, username: &str, password: &str, totp: &str) -> Res<LoginResponse> {
        let body = Some(json!({ "username": username, "password": password, "totp": totp }));
        let opts = Opts {
            auth: false,
            timeout: None,
        };
        let bytes = self
            .exec(Method::POST, "/auth/login", &[], body, opts)
            .await?;
        // The body carries a live token, so a malformed one is reported without echoing it.
        serde_json::from_slice(&bytes)
            .map_err(|_| ClientError::Decode("malformed login response".into()))
    }

    pub async fn logout(&self) -> Res<()> {
        self.unit(Method::POST, "/auth/logout").await
    }

    pub async fn me(&self) -> Res<Value> {
        self.json(Method::GET, "/auth/me", &[], None).await
    }

    pub async fn healthz(&self) -> Res<()> {
        let opts = Opts {
            auth: false,
            timeout: None,
        };
        self.exec(Method::GET, "/healthz", &[], None, opts)
            .await
            .map(|_| ())
    }

    pub async fn node_info(&self) -> Res<NodeInfo> {
        self.json(Method::GET, "/node", &[], None).await
    }

    pub async fn list_sites(&self) -> Res<Vec<Site>> {
        self.json(Method::GET, "/sites", &[], None).await
    }

    pub async fn get_site(&self, id: &str) -> Res<SiteDetail> {
        let path = format!("/sites/{}", enc(id));
        let mut value: Value = self.json(Method::GET, &path, &[], None).await?;
        let live = value.as_object_mut().and_then(|o| o.remove("live"));
        let site = serde_json::from_value(value).map_err(|e| ClientError::Decode(e.to_string()))?;
        Ok(SiteDetail { site, live })
    }

    // The connector reads the GitHub token from a top-level field and never from the Site itself.
    pub async fn create_site(&self, site: &Site, github_token: Option<&str>) -> Res<Site> {
        let bytes = self
            .exec(
                Method::POST,
                "/sites",
                &[],
                create_site_body(site, github_token)?,
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn update_site(&self, id: &str, site: &Site) -> Res<Site> {
        let path = format!("/sites/{}", enc(id));
        self.json(Method::PUT, &path, &[], body_of(site)?).await
    }

    pub async fn delete_site(&self, id: &str) -> Res<()> {
        self.unit(Method::DELETE, &format!("/sites/{}", enc(id)))
            .await
    }

    pub async fn deploy(&self, id: &str, request: &DeployRequest) -> Res<Deployment> {
        let path = format!("/sites/{}/deploy", enc(id));
        // The node waits for health checks and a reload, which exceeds the default request budget.
        let opts = Opts {
            auth: true,
            timeout: Some(DEPLOY_TIMEOUT),
        };
        let bytes = self
            .exec(Method::POST, &path, &[], body_of(request)?, opts)
            .await?;
        decode(&bytes)
    }

    pub async fn switch(&self, id: &str, slot: Slot) -> Res<Deployment> {
        let path = format!("/sites/{}/switch", enc(id));
        let body = Some(json!({ "slot": slot }));
        let bytes = self
            .exec(Method::POST, &path, &[], body, ACTION_OPTS)
            .await?;
        decode(&bytes)
    }

    pub async fn rollback(&self, id: &str) -> Res<Deployment> {
        let path = format!("/sites/{}/rollback", enc(id));
        let bytes = self
            .exec(Method::POST, &path, &[], None, ACTION_OPTS)
            .await?;
        decode(&bytes)
    }

    pub async fn maintenance(&self, id: &str, enabled: bool, page_id: Option<&str>) -> Res<Site> {
        let path = format!("/sites/{}/maintenance", enc(id));
        let body = Some(json!({ "enabled": enabled, "page_id": page_id }));
        self.json(Method::POST, &path, &[], body).await
    }

    pub async fn list_pages(&self) -> Res<Vec<MaintenancePage>> {
        self.json(Method::GET, "/pages", &[], None).await
    }

    pub async fn get_page(&self, id: &str) -> Res<MaintenancePage> {
        let path = format!("/pages/{}", enc(id));
        self.json(Method::GET, &path, &[], None).await
    }

    pub async fn create_page(&self, page: &MaintenancePage) -> Res<MaintenancePage> {
        self.json(Method::POST, "/pages", &[], body_of(page)?).await
    }

    pub async fn update_page(&self, id: &str, page: &MaintenancePage) -> Res<MaintenancePage> {
        let path = format!("/pages/{}", enc(id));
        self.json(Method::PUT, &path, &[], body_of(page)?).await
    }

    pub async fn delete_page(&self, id: &str) -> Res<()> {
        self.unit(Method::DELETE, &format!("/pages/{}", enc(id)))
            .await
    }

    pub async fn list_rules(&self) -> Res<Vec<FirewallRule>> {
        self.json(Method::GET, "/firewall/rules", &[], None).await
    }

    pub async fn create_rule(&self, rule: &FirewallRule) -> Res<FirewallRule> {
        self.json(Method::POST, "/firewall/rules", &[], body_of(rule)?)
            .await
    }

    pub async fn update_rule(&self, id: &str, rule: &FirewallRule) -> Res<FirewallRule> {
        let path = format!("/firewall/rules/{}", enc(id));
        self.json(Method::PUT, &path, &[], body_of(rule)?).await
    }

    pub async fn delete_rule(&self, id: &str) -> Res<()> {
        self.unit(Method::DELETE, &format!("/firewall/rules/{}", enc(id)))
            .await
    }

    // One validation and one reload on the node, however many rules change; the rules are checked for ids and overlaps first.
    pub async fn firewall_bulk(&self, bulk: &FirewallBulk) -> Res<BulkResult> {
        bulk.validate()?;
        let bytes = self
            .exec(
                Method::POST,
                "/firewall/bulk",
                &[],
                body_of(bulk)?,
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn list_presets(&self) -> Res<Vec<PresetInfo>> {
        self.json(Method::GET, "/firewall/presets", &[], None).await
    }

    pub async fn apply_preset(&self, name: &str) -> Res<Vec<FirewallRule>> {
        let path = format!("/firewall/presets/{}/apply", enc(name));
        self.json(Method::POST, &path, &[], None).await
    }

    pub async fn analytics_summary(&self, window: &str, site: Option<&str>) -> Res<Summary> {
        let query = analytics_query(window, site);
        self.json(Method::GET, "/analytics/summary", &query, None)
            .await
    }

    pub async fn analytics_timeseries(&self, window: &str, site: Option<&str>) -> Res<Timeseries> {
        let query = analytics_query(window, site);
        self.json(Method::GET, "/analytics/timeseries", &query, None)
            .await
    }

    pub async fn analytics_requests(
        &self,
        window: &str,
        site: Option<&str>,
        filter: &RequestQuery,
    ) -> Res<Vec<LogEvent>> {
        let mut query = analytics_query(window, site);
        query.extend(filter.pairs());
        self.json(Method::GET, "/analytics/requests", &query, None)
            .await
    }

    pub async fn analytics_bots(&self, window: &str, site: Option<&str>) -> Res<BotSummary> {
        let query = analytics_query(window, site);
        self.json(Method::GET, "/analytics/bots", &query, None)
            .await
    }

    pub async fn analytics_top(
        &self,
        kind: &str,
        window: &str,
        site: Option<&str>,
        limit: Option<usize>,
    ) -> Res<Vec<TopItem>> {
        let mut query = analytics_query(window, site);
        query.push(("kind", validate_top_kind(kind)?.to_string()));
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        let wrapped: TopItems = self
            .json(Method::GET, "/analytics/top", &query, None)
            .await?;
        Ok(wrapped.items)
    }

    pub async fn analytics_summary_q(&self, q: &AnalyticsQuery) -> Res<SummaryReport> {
        self.json(Method::GET, "/analytics/summary", &q.pairs()?, None)
            .await
    }

    pub async fn analytics_timeseries_q(&self, q: &AnalyticsQuery) -> Res<TimeseriesReport> {
        self.json(Method::GET, "/analytics/timeseries", &q.pairs()?, None)
            .await
    }

    pub async fn analytics_bots_q(&self, q: &AnalyticsQuery) -> Res<BotReport> {
        self.json(Method::GET, "/analytics/bots", &q.pairs()?, None)
            .await
    }

    pub async fn analytics_top_q(
        &self,
        kind: &str,
        q: &AnalyticsQuery,
        limit: Option<usize>,
        sort: TopSort,
    ) -> Res<TopReport> {
        let mut query = q.pairs()?;
        query.push(("kind", validate_top_kind(kind)?.to_string()));
        query.extend(limit_pair(limit)?);
        query.push(("sort", sort.as_str().to_string()));
        self.json(Method::GET, "/analytics/top", &query, None).await
    }

    // Always asks for the envelope so the page carries its cursor and the partial flag.
    pub async fn analytics_requests_q(
        &self,
        q: &AnalyticsQuery,
        limit: Option<usize>,
        cursor: Option<&RequestCursor>,
    ) -> Res<RequestsPage> {
        let mut query = q.pairs()?;
        query.extend(page_pairs(limit, cursor)?);
        self.json(Method::GET, "/analytics/requests", &query, None)
            .await
    }

    pub async fn analytics_facets(&self, q: &AnalyticsQuery) -> Res<Facets> {
        self.json(Method::GET, "/analytics/facets", &q.pairs()?, None)
            .await
    }

    pub async fn analytics_compare(&self, q: &AnalyticsQuery) -> Res<Compare> {
        self.json(Method::GET, "/analytics/compare", &q.pairs()?, None)
            .await
    }

    pub async fn analytics_stats(&self) -> Res<AnalyticsStats> {
        self.json(Method::GET, "/analytics/stats", &[], None).await
    }

    // The body is not read; the caller relays or saves it chunk by chunk.
    pub async fn analytics_export_stream(&self, query: &ExportQuery) -> Res<ExportStream> {
        let pairs = query.pairs()?;
        let req = self
            .authed_get(format!("{}/api/v1/analytics/export", self.base))
            .query(&pairs)
            .timeout(EXPORT_TIMEOUT);
        open_stream(req).await
    }

    // Streams into a sibling temp file and renames on success, so memory use stays flat.
    pub async fn analytics_export_to(
        &self,
        query: &ExportQuery,
        dest: &Path,
        max_bytes: u64,
    ) -> Res<ExportReport> {
        self.analytics_export_stream(query)
            .await?
            .save(dest, max_bytes)
            .await
    }

    pub async fn analytics_archives(&self) -> Res<ArchiveList> {
        self.json(Method::GET, "/analytics/archives", &[], None)
            .await
    }

    pub async fn analytics_backup(&self) -> Res<ArchiveEntry> {
        let bytes = self
            .exec(
                Method::POST,
                "/analytics/backup",
                &[],
                Some(json!({})),
                BULK_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn analytics_cut(&self, request: &CutRequest) -> Res<CutReport> {
        request.validate()?;
        let bytes = self
            .exec(
                Method::POST,
                "/analytics/cut",
                &[],
                body_of(request)?,
                BULK_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn analytics_restore(&self, name: &str) -> Res<RestoreReport> {
        let name = validate_archive_name(name)?;
        let bytes = self
            .exec(
                Method::POST,
                "/analytics/restore",
                &[],
                Some(json!({ "name": name })),
                BULK_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn analytics_archive_delete(&self, name: &str) -> Res<()> {
        let name = validate_archive_name(name)?;
        self.unit(
            Method::DELETE,
            &format!("/analytics/archives/{}", enc(name)),
        )
        .await
    }

    // The body is not read; the caller relays or saves it chunk by chunk.
    pub async fn analytics_archive_stream(&self, name: &str) -> Res<ExportStream> {
        let name = validate_archive_name(name)?;
        let req = self
            .authed_get(format!(
                "{}/api/v1/analytics/archives/{}",
                self.base,
                enc(name)
            ))
            .timeout(EXPORT_TIMEOUT);
        open_stream(req).await
    }

    // The suggested name is rebuilt from the requested name with an allowlisted extension.
    pub async fn analytics_archive_download_to(
        &self,
        name: &str,
        dest: &Path,
        max_bytes: u64,
    ) -> Res<ExportReport> {
        let mut report = self
            .analytics_archive_stream(name)
            .await?
            .save(dest, max_bytes)
            .await?;
        report.suggested_name = Some(archive_download_name(name, archive_kind_from_name(name)));
        Ok(report)
    }

    pub async fn certificates(&self) -> Res<CertificateList> {
        self.json(Method::GET, "/certificates", &[], None).await
    }

    pub async fn certificate(&self, id: &str) -> Res<CertificateInfo> {
        let id = validate_certificate_id(id)?;
        self.json(
            Method::GET,
            &format!("/certificates/{}", enc(id)),
            &[],
            None,
        )
        .await
    }

    pub async fn certificate_create(&self, upload: &CertificateUpload) -> Res<CertificateSaved> {
        upload.validate(true)?;
        let bytes = self
            .exec_json_bytes(
                Method::POST,
                "/certificates",
                upload.body_json()?,
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn certificate_replace(
        &self,
        id: &str,
        upload: &CertificateUpload,
    ) -> Res<CertificateSaved> {
        let id = validate_certificate_id(id)?;
        upload.validate(false)?;
        let bytes = self
            .exec_json_bytes(
                Method::PUT,
                &format!("/certificates/{}", enc(id)),
                upload.body_json()?,
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn certificate_delete(&self, id: &str) -> Res<()> {
        let id = validate_certificate_id(id)?;
        self.unit(Method::DELETE, &format!("/certificates/{}", enc(id)))
            .await
    }

    pub async fn zone_secret(&self, site_id: &str) -> Res<ZoneSecretStatus> {
        let id = validate_site_id(site_id)?;
        self.json(
            Method::GET,
            &format!("/sites/{}/zone-secret", enc(id)),
            &[],
            None,
        )
        .await
    }

    // The node shows the new secret once, so a malformed body is reported without echoing any of it.
    pub async fn rotate_zone_secret(&self, site_id: &str) -> Res<ZoneSecret> {
        let id = validate_site_id(site_id)?;
        let bytes = self
            .exec(
                Method::POST,
                &format!("/sites/{}/zone-secret", enc(id)),
                &[],
                Some(json!({})),
                ACTION_OPTS,
            )
            .await?;
        serde_json::from_slice(&bytes)
            .map_err(|_| ClientError::Decode("malformed zone secret response".into()))
    }

    pub async fn site_status(&self, site_id: &str) -> Res<Value> {
        let id = validate_site_id(site_id)?;
        self.json(
            Method::GET,
            &format!("/sites/{}/status", enc(id)),
            &[],
            None,
        )
        .await
    }

    pub async fn site_logs(&self, site_id: &str, query: &LogsQuery) -> Res<Value> {
        let id = validate_site_id(site_id)?;
        let params = query.to_query()?;
        self.json(
            Method::GET,
            &format!("/sites/{}/logs", enc(id)),
            &params,
            None,
        )
        .await
    }

    pub async fn github_token_status(&self, site_id: &str) -> Res<TokenStatus> {
        let id = validate_site_id(site_id)?;
        self.json(
            Method::GET,
            &format!("/sites/{}/github-token", enc(id)),
            &[],
            None,
        )
        .await
    }

    pub async fn github_token_set(
        &self,
        site_id: &str,
        token: &GithubTokenBody,
    ) -> Res<TokenStatus> {
        let id = validate_site_id(site_id)?;
        let bytes = self
            .exec(
                Method::PUT,
                &format!("/sites/{}/github-token", enc(id)),
                &[],
                body_of(token)?,
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn github_token_clear(&self, site_id: &str) -> Res<()> {
        let id = validate_site_id(site_id)?;
        self.unit(Method::DELETE, &format!("/sites/{}/github-token", enc(id)))
            .await
    }

    pub async fn build_env_names(&self, site_id: &str) -> Res<EnvNames> {
        self.env_names(site_id, "build-env").await
    }

    pub async fn build_env_patch(&self, site_id: &str, patch: &EnvPatch) -> Res<EnvNames> {
        self.env_patch(site_id, "build-env", EnvKind::Build, patch)
            .await
    }

    pub async fn runtime_env_names(&self, site_id: &str) -> Res<EnvNames> {
        self.env_names(site_id, "runtime-env").await
    }

    pub async fn runtime_env_patch(&self, site_id: &str, patch: &EnvPatch) -> Res<EnvNames> {
        self.env_patch(site_id, "runtime-env", EnvKind::Runtime, patch)
            .await
    }

    async fn env_names(&self, site_id: &str, which: &str) -> Res<EnvNames> {
        let id = validate_site_id(site_id)?;
        self.json(
            Method::GET,
            &format!("/sites/{}/{which}", enc(id)),
            &[],
            None,
        )
        .await
    }

    async fn env_patch(
        &self,
        site_id: &str,
        which: &str,
        kind: EnvKind,
        patch: &EnvPatch,
    ) -> Res<EnvNames> {
        let id = validate_site_id(site_id)?;
        patch.validate(kind)?;
        let bytes = self
            .exec(
                Method::PATCH,
                &format!("/sites/{}/{which}", enc(id)),
                &[],
                body_of(patch)?,
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    /// Starts a source deploy without waiting for the build; poll `site_status` for the outcome.
    pub async fn deploy_source_async(
        &self,
        site_id: &str,
        git_ref: Option<&str>,
        note: Option<&str>,
    ) -> Res<DeployAccepted> {
        let id = validate_site_id(site_id)?;
        let mut body = json!({ "wait": false });
        if let Some(git_ref) = git_ref {
            body["git_ref"] = json!(git_ref);
        }
        if let Some(note) = note {
            body["note"] = json!(note);
        }
        let bytes = self
            .exec(
                Method::POST,
                &format!("/sites/{}/deploy", enc(id)),
                &[],
                Some(body),
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    /// Issues a certificate on the node; `kind` is `generate`, `origin-ca` or `acme`.
    pub async fn certificate_issue(&self, kind: &str, request: &Value) -> Res<Value> {
        if !matches!(kind, "generate" | "origin-ca" | "acme") {
            return Err(ClientError::Config(
                "kind is generate, origin-ca or acme".into(),
            ));
        }
        let bytes = self
            .exec(
                Method::POST,
                &format!("/certificates/{kind}"),
                &[],
                Some(request.clone()),
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    /// Issues an origin certificate with a Cloudflare token that is sent once and wiped afterwards.
    pub async fn certificate_origin_ca(
        &self,
        token: &CloudflareToken,
        request: &Value,
    ) -> Res<Value> {
        let mut body = request.clone();
        let Some(map) = body.as_object_mut() else {
            return Err(ClientError::Config("the request is an object".into()));
        };
        let mut sent = serde_json::to_value(token)
            .map_err(|_| ClientError::Config("cannot encode request".into()))?;
        if let Some(extra) = sent.as_object_mut() {
            map.append(extra);
        }
        let bytes = self
            .exec(
                Method::POST,
                "/certificates/origin-ca",
                &[],
                Some(body),
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn acme_jobs(&self) -> Res<Value> {
        self.json(Method::GET, "/certificates/acme", &[], None)
            .await
    }

    pub async fn acme_job(&self, job_id: &str) -> Res<Value> {
        let id = validate_job_id(job_id)?;
        self.json(
            Method::GET,
            &format!("/certificates/acme/{}", enc(id)),
            &[],
            None,
        )
        .await
    }

    pub async fn alerts_get(&self) -> Res<Value> {
        self.json(Method::GET, "/alerts", &[], None).await
    }

    pub async fn alerts_put(&self, config: &Value) -> Res<Value> {
        self.json(Method::PUT, "/alerts", &[], Some(config.clone()))
            .await
    }

    pub async fn alerts_test(&self) -> Res<Value> {
        let bytes = self
            .exec(
                Method::POST,
                "/alerts/test",
                &[],
                Some(json!({})),
                ACTION_OPTS,
            )
            .await?;
        decode(&bytes)
    }

    pub async fn cloudflare_ranges(&self) -> Res<CloudflareRanges> {
        self.json(Method::GET, "/cloudflare/ranges", &[], None)
            .await
    }

    // Callers must validate `rest`; the body is streamed back untouched.
    pub async fn forward_stream(&self, rest: &str, query: Option<&str>) -> Res<ExportStream> {
        let mut url = format!("{}/api/v1/{rest}", self.base);
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            url.push('?');
            url.push_str(q);
        }
        open_stream(self.authed_get(url).timeout(EXPORT_TIMEOUT)).await
    }

    fn authed_get(&self, url: String) -> reqwest::RequestBuilder {
        let req = self.http.get(url);
        if self.token.is_empty() {
            req
        } else {
            req.bearer_auth(&self.token)
        }
    }

    pub async fn get_settings(&self) -> Res<EdgeSettings> {
        self.json(Method::GET, "/settings", &[], None).await
    }

    pub async fn put_settings(&self, settings: &EdgeSettings) -> Res<EdgeSettings> {
        self.json(Method::PUT, "/settings", &[], body_of(settings)?)
            .await
    }

    pub async fn audit(&self, limit: Option<usize>) -> Res<Vec<AuditEntry>> {
        let query: Vec<(&str, String)> = limit
            .map(|n| ("limit", n.to_string()))
            .into_iter()
            .collect();
        self.json(Method::GET, "/audit", &query, None).await
    }

    pub async fn list_tokens(&self) -> Res<Vec<TokenMeta>> {
        self.json(Method::GET, "/tokens", &[], None).await
    }

    pub async fn create_token(&self, name: &str) -> Res<CreatedToken> {
        let body = Some(json!({ "name": name }));
        let bytes = self
            .exec(Method::POST, "/tokens", &[], body, DEFAULT_OPTS)
            .await?;
        serde_json::from_slice(&bytes)
            .map_err(|_| ClientError::Decode("malformed token response".into()))
    }

    pub async fn delete_token(&self, id: &str) -> Res<()> {
        self.unit(Method::DELETE, &format!("/tokens/{}", enc(id)))
            .await
    }

    pub async fn haproxy_reload(&self) -> Res<ReloadResult> {
        self.json(Method::POST, "/haproxy/reload", &[], None).await
    }

    pub async fn haproxy_config(&self) -> Res<String> {
        let bytes = self
            .exec(Method::GET, "/haproxy/config", &[], None, DEFAULT_OPTS)
            .await?;
        String::from_utf8(bytes).map_err(|_| ClientError::Decode("config is not utf-8".into()))
    }

    pub async fn haproxy_stats(&self) -> Res<Value> {
        self.json(Method::GET, "/haproxy/stats", &[], None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_operations_get_budgets_beyond_the_read_timeout() {
        assert!(DEPLOY_TIMEOUT >= Duration::from_secs(600));
        assert!(ACTION_TIMEOUT >= Duration::from_secs(120));
        assert!(ACTION_TIMEOUT > REQUEST_TIMEOUT);
    }

    #[test]
    fn create_switch_and_rollback_use_the_action_budget() {
        assert_eq!(ACTION_OPTS.timeout, Some(ACTION_TIMEOUT));
    }
}
