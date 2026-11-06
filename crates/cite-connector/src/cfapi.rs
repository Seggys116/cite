use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode, Url};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{ConnectorError, Result};

pub const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";
pub const ACME_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const ACME_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ALLOWED_HOSTS: [&str; 3] = [
    "api.cloudflare.com",
    "acme-v02.api.letsencrypt.org",
    "acme-staging-v02.api.letsencrypt.org",
];
pub const TIMEOUT: Duration = Duration::from_secs(20);
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_TOKEN_BYTES: usize = 256;
const MAX_REMOTE_TEXT: usize = 300;
const MAX_REMOTE_ID: usize = 64;
const SERVICE_KEY_PREFIX: &str = "v1.0-";
const SERVICE_KEY_HEADER: &str = "x-auth-user-service-key";
const REDACTED: &str = "[redacted]";

fn unavailable(msg: impl Into<String>) -> ConnectorError {
    ConnectorError::Unavailable(msg.into())
}

// Text from a remote server is shown to the owner, so it is cut down to plain printable characters first.
pub fn remote_text(text: &str) -> String {
    let plain: String = text
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { ' ' })
        .take(MAX_REMOTE_TEXT)
        .collect();
    plain.split_whitespace().collect::<Vec<_>>().join(" ")
}

// A Cloudflare API token or legacy Origin CA key; wiped on drop and never printed.
pub struct CfToken(Zeroizing<String>);

impl CfToken {
    pub fn parse(raw: &str) -> Result<Self> {
        let ok = !raw.is_empty()
            && raw.len() <= MAX_TOKEN_BYTES
            && raw.bytes().all(|b| b.is_ascii_graphic());
        if !ok {
            return Err(ConnectorError::BadRequest(format!(
                "cloudflare_token must be 1 to {MAX_TOKEN_BYTES} printable ASCII characters without spaces"
            )));
        }
        Ok(Self(Zeroizing::new(raw.to_string())))
    }

    // Origin CA keys are the only credential sent in their own header; everything else is a bearer API token.
    pub fn is_service_key(&self) -> bool {
        self.0.starts_with(SERVICE_KEY_PREFIX)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub fn scrub(&self, text: &str) -> String {
        text.replace(self.0.as_str(), REDACTED)
    }
}

impl fmt::Debug for CfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CfToken(<redacted>)")
    }
}

// Where the node may connect when it issues certificates; anything else is refused before a socket opens.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub cloudflare: String,
    pub acme_production: String,
    pub acme_staging: String,
    pub poll_interval: Duration,
    pub dns_wait: Duration,
    pub dns_settle: Duration,
    pub acme_wait: Duration,
    hosts: Vec<String>,
    plain_http: bool,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            cloudflare: CLOUDFLARE_API.into(),
            acme_production: ACME_PRODUCTION.into(),
            acme_staging: ACME_STAGING.into(),
            poll_interval: Duration::from_secs(3),
            dns_wait: Duration::from_secs(120),
            dns_settle: Duration::from_secs(5),
            acme_wait: Duration::from_secs(180),
            hosts: ALLOWED_HOSTS.iter().map(|h| h.to_string()).collect(),
            plain_http: false,
        }
    }
}

impl Endpoints {
    // Points every service at one local mock server over plain HTTP; only tests can build this.
    #[cfg(test)]
    pub fn local(base: &str) -> Self {
        Self {
            cloudflare: format!("{base}/client/v4"),
            acme_production: format!("{base}/acme/directory"),
            acme_staging: format!("{base}/staging/directory"),
            poll_interval: Duration::from_millis(5),
            dns_wait: Duration::from_secs(2),
            dns_settle: Duration::ZERO,
            acme_wait: Duration::from_secs(5),
            hosts: vec!["127.0.0.1".into()],
            plain_http: true,
        }
    }

    pub fn check(&self, url: &str) -> Result<Url> {
        let parsed = Url::parse(url)
            .map_err(|_| unavailable("refusing to contact a URL that does not parse"))?;
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        let scheme_ok =
            parsed.scheme() == "https" || (self.plain_http && parsed.scheme() == "http");
        let host_ok = self.hosts.contains(&host);
        let port_ok = self.plain_http || parsed.port().is_none();
        let plain = parsed.username().is_empty() && parsed.password().is_none();
        if scheme_ok && host_ok && port_ok && plain {
            Ok(parsed)
        } else {
            Err(unavailable(format!(
                "refusing to contact {:?}: only https to api.cloudflare.com and the Let's Encrypt ACME servers is allowed",
                remote_text(&host)
            )))
        }
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Reply {
    pub fn header(&self, name: impl header::AsHeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    ep: Arc<Endpoints>,
}

impl Http {
    pub fn new(ep: Arc<Endpoints>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .connect_timeout(TIMEOUT)
            .https_only(!ep.plain_http)
            .user_agent(concat!("cite-connector/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ConnectorError::Internal(format!("cannot build the HTTP client: {e}")))?;
        Ok(Self { client, ep })
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.ep
    }

    // Every URL is checked against the allowlist, including ones a server handed back, and bodies stop at 1 MiB.
    pub async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<Reply> {
        let target = self.ep.check(url)?;
        let host = target.host_str().unwrap_or_default().to_string();
        let mut req = self.client.request(method, target).headers(headers);
        if let Some(body) = body {
            req = req.body(body);
        }
        let mut res = req.send().await.map_err(|e| net_error(&host, &e))?;
        let status = res.status();
        if status.is_redirection() {
            return Err(unavailable(format!(
                "{host} answered with a redirect, which is not followed"
            )));
        }
        if res
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(too_large(&host));
        }
        let headers = res.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|e| net_error(&host, &e))? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(too_large(&host));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Reply {
            status,
            headers,
            body: Bytes::from(body),
        })
    }
}

fn too_large(host: &str) -> ConnectorError {
    unavailable(format!("{host} sent a response larger than 1 MiB"))
}

fn net_error(host: &str, e: &reqwest::Error) -> ConnectorError {
    if e.is_timeout() {
        unavailable(format!(
            "{host} did not answer within {} seconds",
            TIMEOUT.as_secs()
        ))
    } else {
        tracing::debug!(%host, error = %e, "outbound request failed");
        unavailable(format!("{host} could not be reached"))
    }
}

fn is_remote_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_REMOTE_ID
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    pub id: String,
    pub name: String,
}

pub struct Cloudflare<'a> {
    http: &'a Http,
    token: &'a CfToken,
}

impl<'a> Cloudflare<'a> {
    pub fn new(http: &'a Http, token: &'a CfToken) -> Self {
        Self { http, token }
    }

    fn url(&self, path: &str) -> Result<Url> {
        let base = self.http.endpoints().cloudflare.trim_end_matches('/');
        Url::parse(&format!("{base}{path}"))
            .map_err(|e| ConnectorError::Internal(format!("Cloudflare URL: {e}")))
    }

    fn headers(&self) -> Result<HeaderMap> {
        let refused = || ConnectorError::BadRequest("cloudflare_token cannot be sent".into());
        let (name, mut value) = if self.token.is_service_key() {
            (
                header::HeaderName::from_static(SERVICE_KEY_HEADER),
                HeaderValue::from_str(self.token.expose()).map_err(|_| refused())?,
            )
        } else {
            let bearer = Zeroizing::new(format!("Bearer {}", self.token.expose()));
            (
                header::AUTHORIZATION,
                HeaderValue::from_str(&bearer).map_err(|_| refused())?,
            )
        };
        value.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(name, value);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        Ok(headers)
    }

    // Unwraps the Cloudflare envelope; its error messages are shown without any copy of the token.
    async fn call(
        &self,
        method: Method,
        url: Url,
        body: Option<&Value>,
        what: &str,
    ) -> Result<Value> {
        let bytes = body.map(serde_json::to_vec).transpose()?;
        let reply = self
            .http
            .send(method, url.as_str(), self.headers()?, bytes)
            .await?;
        let parsed: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        if reply.status.is_success() && parsed["success"].as_bool() == Some(true) {
            return Ok(parsed["result"].clone());
        }
        let messages: Vec<String> = parsed["errors"]
            .as_array()
            .map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| {
                        let msg = e["message"].as_str()?;
                        Some(match e["code"].as_i64() {
                            Some(code) => format!("{msg} (code {code})"),
                            None => msg.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let shown = remote_text(&self.token.scrub(&messages.join("; ")));
        let code = reply.status.as_u16();
        let text = if shown.is_empty() {
            format!("Cloudflare refused to {what} (HTTP {code})")
        } else {
            format!("Cloudflare refused to {what} (HTTP {code}): {shown}")
        };
        Err(match code {
            400 | 401 | 403 | 404 | 409 | 422 => ConnectorError::BadRequest(text),
            _ => unavailable(text),
        })
    }

    pub async fn origin_ca(&self, csr_pem: &str, hosts: &[String], days: u32) -> Result<String> {
        let body = json!({
            "csr": csr_pem,
            "hostnames": hosts,
            "request_type": "origin-ecc",
            "requested_validity": days,
        });
        let result = self
            .call(
                Method::POST,
                self.url("/certificates")?,
                Some(&body),
                "issue the Origin CA certificate",
            )
            .await?;
        result["certificate"]
            .as_str()
            .filter(|c| c.contains("BEGIN CERTIFICATE"))
            .map(str::to_string)
            .ok_or_else(|| unavailable("Cloudflare did not return a certificate"))
    }

    // Walks from the full name up to its registrable part, so a delegated subdomain zone wins over its parent.
    pub async fn zone_for(&self, host: &str) -> Result<Zone> {
        let name = host.strip_prefix("*.").unwrap_or(host).to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            let mut url = self.url("/zones")?;
            url.query_pairs_mut().append_pair("name", &candidate);
            let result = self.call(Method::GET, url, None, "list the zones").await?;
            let found = result.as_array().and_then(|zones| {
                zones.iter().find(|z| {
                    z["name"]
                        .as_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case(&candidate))
                })
            });
            if let Some(zone) = found {
                let id = zone["id"]
                    .as_str()
                    .filter(|id| is_remote_id(id))
                    .ok_or_else(|| unavailable("Cloudflare returned a zone without a usable id"))?;
                return Ok(Zone {
                    id: id.to_string(),
                    name: candidate,
                });
            }
        }
        Err(ConnectorError::BadRequest(format!(
            "no Cloudflare zone this token can read contains {name}; the token needs Zone:Zone:Read and Zone:DNS:Edit on that zone"
        )))
    }

    pub async fn create_txt(&self, zone: &Zone, name: &str, content: &str) -> Result<String> {
        let url = self.url(&format!("/zones/{}/dns_records", zone.id))?;
        let body = json!({ "type": "TXT", "name": name, "content": content, "ttl": 60 });
        let result = self
            .call(
                Method::POST,
                url,
                Some(&body),
                "create the challenge TXT record",
            )
            .await?;
        result["id"]
            .as_str()
            .filter(|id| is_remote_id(id))
            .map(str::to_string)
            .ok_or_else(|| unavailable("Cloudflare returned a DNS record without a usable id"))
    }

    pub async fn txt_present(&self, zone: &Zone, name: &str, content: &str) -> Result<bool> {
        let mut url = self.url(&format!("/zones/{}/dns_records", zone.id))?;
        url.query_pairs_mut()
            .append_pair("type", "TXT")
            .append_pair("name", name);
        let result = self
            .call(Method::GET, url, None, "list the challenge TXT records")
            .await?;
        Ok(result.as_array().is_some_and(|records| {
            records.iter().any(|r| {
                r["content"]
                    .as_str()
                    .is_some_and(|c| c.trim_matches('"') == content)
            })
        }))
    }

    pub async fn delete_record(&self, zone: &Zone, id: &str) -> Result<()> {
        if !is_remote_id(id) {
            return Err(ConnectorError::Internal(
                "DNS record id is not usable".into(),
            ));
        }
        let url = self.url(&format!("/zones/{}/dns_records/{id}", zone.id))?;
        self.call(Method::DELETE, url, None, "delete the challenge TXT record")
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::mock;

    #[test]
    fn only_allowlisted_https_hosts_pass() {
        let ep = Endpoints::default();
        for ok in [
            "https://api.cloudflare.com/client/v4/zones",
            "https://API.cloudflare.com/client/v4/certificates",
            "https://api.cloudflare.com:443/client/v4/zones",
            "https://acme-v02.api.letsencrypt.org/acme/new-order",
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        ] {
            assert!(ep.check(ok).is_ok(), "{ok}");
        }
        for refused in [
            "http://api.cloudflare.com/client/v4/zones",
            "https://api.cloudflare.com.evil.example/x",
            "https://evil.example/api.cloudflare.com",
            "https://user:pw@api.cloudflare.com/x",
            "https://api.cloudflare.com:8443/x",
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "file:///etc/passwd",
            "not a url",
        ] {
            let err = ep.check(refused).unwrap_err();
            assert!(err.to_string().contains("refusing"), "{refused}: {err}");
        }
    }

    #[test]
    fn tokens_are_checked_redacted_and_scrubbed() {
        assert!(CfToken::parse("").is_err());
        assert!(CfToken::parse("has space").is_err());
        assert!(CfToken::parse("tab\there").is_err());
        assert!(CfToken::parse("caf\u{e9}").is_err());
        assert!(CfToken::parse(&"a".repeat(MAX_TOKEN_BYTES + 1)).is_err());
        let token = CfToken::parse(&"a".repeat(MAX_TOKEN_BYTES)).expect("longest");
        assert!(!token.is_service_key());
        let token = CfToken::parse("v1.0-secretvalue").expect("service key");
        assert!(token.is_service_key());
        assert!(!format!("{token:?}").contains("secretvalue"));
        assert_eq!(
            token.scrub("bad v1.0-secretvalue here"),
            "bad [redacted] here"
        );
    }

    #[test]
    fn remote_text_is_plain_and_short() {
        assert_eq!(remote_text("a\nb\u{1b}[31m  c"), "a b [31m c");
        assert_eq!(remote_text(&"x".repeat(1000)).len(), MAX_REMOTE_TEXT);
    }

    #[tokio::test]
    async fn redirects_and_large_bodies_are_refused() {
        let server = mock::start().await;
        let http = Http::new(Arc::new(server.endpoints())).expect("client");
        let err = http
            .send(
                Method::GET,
                &format!("{}/redirect", server.base),
                HeaderMap::new(),
                None,
            )
            .await
            .err()
            .expect("redirect refused");
        assert!(err.to_string().contains("redirect"), "{err}");
        let err = http
            .send(
                Method::GET,
                &format!("{}/big", server.base),
                HeaderMap::new(),
                None,
            )
            .await
            .err()
            .expect("big body refused");
        assert!(err.to_string().contains("1 MiB"), "{err}");
        let other_host = server.base.replace("127.0.0.1", "localhost");
        let err = http
            .send(
                Method::GET,
                &format!("{other_host}/big"),
                HeaderMap::new(),
                None,
            )
            .await
            .err()
            .expect("other host refused");
        assert!(err.to_string().contains("refusing"), "{err}");
    }

    #[tokio::test]
    async fn zones_are_found_from_the_most_specific_name() {
        let server = mock::start().await;
        server.with(|s| {
            s.zones.push((
                "fedcba9876543210fedcba9876543210".into(),
                "deep.example.com".into(),
            ))
        });
        let http = Http::new(Arc::new(server.endpoints())).expect("client");
        let token = CfToken::parse(mock::TOKEN).expect("token");
        let cf = Cloudflare::new(&http, &token);
        assert_eq!(
            cf.zone_for("*.shop.example.com").await.expect("zone").name,
            "example.com"
        );
        assert_eq!(
            cf.zone_for("a.deep.example.com").await.expect("zone").name,
            "deep.example.com"
        );
        assert!(cf.zone_for("shop.example.org").await.is_err());
        let wrong = CfToken::parse("not-the-token").expect("token");
        let err = Cloudflare::new(&http, &wrong)
            .zone_for("shop.example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("HTTP 403"), "{err}");
    }

    #[tokio::test]
    async fn txt_records_are_created_seen_and_removed() {
        let server = mock::start().await;
        let http = Http::new(Arc::new(server.endpoints())).expect("client");
        let token = CfToken::parse(mock::TOKEN).expect("token");
        let cf = Cloudflare::new(&http, &token);
        let zone = cf.zone_for("shop.example.com").await.expect("zone");
        let name = "_acme-challenge.shop.example.com";
        assert!(!cf.txt_present(&zone, name, "value").await.expect("list"));
        let id = cf.create_txt(&zone, name, "value").await.expect("create");
        assert!(cf.txt_present(&zone, name, "value").await.expect("list"));
        assert!(!cf.txt_present(&zone, name, "other").await.expect("list"));
        cf.delete_record(&zone, &id).await.expect("delete");
        assert!(!cf.txt_present(&zone, name, "value").await.expect("list"));
        assert!(cf.delete_record(&zone, "../zones").await.is_err());
    }
}
