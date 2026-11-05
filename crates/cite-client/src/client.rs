use std::fmt;
use std::time::Duration;

use cite_edge::analytics::{Summary, Timeseries};
use cite_edge::model::{
    Deployment, EdgeSettings, FirewallRule, LogEvent, MaintenancePage, Site, Slot, Target,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::config::{NodeConfig, parse_node_url};
use crate::error::ClientError;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

const DEPLOY_TIMEOUT: Duration = Duration::from_secs(90);
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
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
        self.json(
            Method::POST,
            "/sites",
            &[],
            create_site_body(site, github_token)?,
        )
        .await
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
        // The node waits up to 60 s for health checks, which exceeds the default request budget.
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
        self.json(Method::POST, &path, &[], body).await
    }

    pub async fn rollback(&self, id: &str) -> Res<Deployment> {
        let path = format!("/sites/{}/rollback", enc(id));
        self.json(Method::POST, &path, &[], None).await
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
