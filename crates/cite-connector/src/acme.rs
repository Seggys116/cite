use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Method;
use reqwest::header::{self, HeaderMap, HeaderValue};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::certs::{self, Generated};
use crate::cfapi::{CfToken, Cloudflare, Endpoints, Http, Reply, Zone, remote_text};
use crate::{ConnectorError, Result};

pub const MAX_PER_HOUR: usize = 10;
pub const ACCOUNT_KEY_FILE: &str = "acme-account.pem";
const HOUR_SECS: i64 = 3600;
const MAX_JOBS: usize = 50;
const MAX_EMAIL: usize = 254;
const MAX_EMAIL_LOCAL: usize = 64;
const MAX_NONCE: usize = 256;
const MAX_CHALLENGE_TOKEN: usize = 256;
const MAX_ACCOUNT_KEY_BYTES: u64 = 16 * 1024;
const BACKOFF_BASE_SECS: i64 = 3600;
const BACKOFF_MAX_SECS: i64 = 24 * 3600;
const KEY_MODE: u32 = 0o600;
const KEY_TAG: &str = "PRIVATE KEY";
const JOSE: &str = "application/jose+json";
const PEM_CHAIN: &str = "application/pem-certificate-chain";
const PROBLEM_PREFIX: &str = "urn:ietf:params:acme:error:";

fn unavailable(msg: impl Into<String>) -> ConnectorError {
    ConnectorError::Unavailable(msg.into())
}

fn internal(msg: impl Into<String>) -> ConnectorError {
    ConnectorError::Internal(msg.into())
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn is_b64url(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn validate_email(email: &str) -> Result<()> {
    let refused = || {
        ConnectorError::BadRequest(
            "email must be a plain address such as admin@example.com (at most 254 characters)"
                .into(),
        )
    };
    let (local, domain) = email.split_once('@').ok_or_else(refused)?;
    let local_ok = !local.is_empty()
        && local.len() <= MAX_EMAIL_LOCAL
        && !local.starts_with('.')
        && !local.ends_with('.')
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~.-".contains(&b));
    let domain_ok = certs::validate_issue_hosts(&[domain.to_string()], false)
        .is_ok_and(|names| !names[0].starts_with("*."));
    if email.len() <= MAX_EMAIL && local_ok && domain_ok {
        Ok(())
    } else {
        Err(refused())
    }
}

// The node's ACME account key: ECDSA P-256, generated on first use and kept in the data directory with mode 0600.
pub struct AccountKey {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
    x: String,
    y: String,
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountKey(<redacted>)")
    }
}

impl AccountKey {
    fn from_pkcs8(der: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|_| internal("the ACME account key cannot be read"))?;
        let point = pair.public_key().as_ref();
        if point.len() != 65 || point[0] != 4 {
            return Err(internal(
                "the ACME account key is not an uncompressed P-256 key",
            ));
        }
        let (x, y) = (b64(&point[1..33]), b64(&point[33..]));
        Ok(Self { pair, rng, x, y })
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        match cite_core::atomic::read_limited(path, MAX_ACCOUNT_KEY_BYTES) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| internal("the ACME account key file is not text"))?;
                let block = pem::parse(text)
                    .map_err(|_| internal("the ACME account key file is not PEM"))?;
                if block.tag() != KEY_TAG {
                    return Err(internal("the ACME account key file holds no PRIVATE KEY"));
                }
                let der = Zeroizing::new(block.into_contents());
                Self::from_pkcs8(&der)
            }
            Err(cite_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::create(path)
            }
            Err(e) => Err(internal(format!("cannot read the ACME account key: {e}"))),
        }
    }

    fn create(path: &Path) -> Result<Self> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| internal("cannot generate the ACME account key"))?;
        let der = Zeroizing::new(doc.as_ref().to_vec());
        let block = pem::Pem::new(KEY_TAG, der.to_vec());
        let text = Zeroizing::new(pem::encode(&block));
        drop(Zeroizing::new(block.into_contents()));
        cite_core::atomic::write_atomic(path, text.as_bytes(), KEY_MODE)
            .map_err(|e| internal(format!("cannot store the ACME account key: {e}")))?;
        Self::from_pkcs8(&der)
    }

    fn jwk(&self) -> Value {
        json!({ "crv": "P-256", "kty": "EC", "x": self.x, "y": self.y })
    }

    // RFC 7638: the required members in lexicographic order, no whitespace.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            self.x, self.y
        );
        b64(Sha256::digest(canonical.as_bytes()).as_slice())
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.pair
            .sign(&self.rng, message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| internal("cannot sign an ACME request"))
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

struct Problem {
    status: u16,
    kind: String,
    detail: String,
}

impl Problem {
    fn read(reply: &Reply) -> Self {
        let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        Self {
            status: reply.status.as_u16(),
            kind: body["type"].as_str().unwrap_or_default().to_string(),
            detail: body["detail"].as_str().unwrap_or_default().to_string(),
        }
    }

    fn is(&self, name: &str) -> bool {
        self.kind.strip_prefix(PROBLEM_PREFIX) == Some(name)
    }

    fn error(&self) -> ConnectorError {
        let kind = self.kind.strip_prefix(PROBLEM_PREFIX).unwrap_or(&self.kind);
        unavailable(format!(
            "the ACME server refused the request (HTTP {}, {}): {}",
            self.status,
            remote_text(kind),
            remote_text(&self.detail)
        ))
    }
}

fn body_json(reply: &Reply) -> Result<Value> {
    serde_json::from_slice(&reply.body)
        .map_err(|_| unavailable("the ACME server sent a response that is not JSON"))
}

fn location(reply: &Reply) -> Option<String> {
    reply.header(header::LOCATION).map(str::to_string)
}

fn urls(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// One ACME conversation: every POST is a JWS signed by the account key and carries a fresh nonce (RFC 8555 section 6).
struct Acme<'a> {
    http: &'a Http,
    key: &'a AccountKey,
    dir: Directory,
    nonce: Option<String>,
    kid: Option<String>,
}

impl<'a> Acme<'a> {
    async fn connect(http: &'a Http, key: &'a AccountKey, dir_url: &str) -> Result<Self> {
        let reply = http
            .send(Method::GET, dir_url, HeaderMap::new(), None)
            .await?;
        if !reply.status.is_success() {
            return Err(unavailable(format!(
                "the ACME directory answered HTTP {}",
                reply.status.as_u16()
            )));
        }
        let dir: Directory = serde_json::from_slice(&reply.body)
            .map_err(|_| unavailable("the ACME directory is not valid"))?;
        Ok(Self {
            http,
            key,
            dir,
            nonce: None,
            kid: None,
        })
    }

    fn keep_nonce(&mut self, reply: &Reply) {
        if let Some(nonce) = reply
            .header("replay-nonce")
            .filter(|n| !n.is_empty() && n.len() <= MAX_NONCE && is_b64url(n))
        {
            self.nonce = Some(nonce.to_string());
        }
    }

    async fn nonce(&mut self) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        let url = self.dir.new_nonce.clone();
        let reply = self
            .http
            .send(Method::HEAD, &url, HeaderMap::new(), None)
            .await?;
        self.keep_nonce(&reply);
        self.nonce
            .take()
            .ok_or_else(|| unavailable("the ACME server did not hand out a nonce"))
    }

    fn signed(&self, url: &str, nonce: &str, payload: Option<&Value>) -> Result<Vec<u8>> {
        let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
        match &self.kid {
            Some(kid) => protected["kid"] = json!(kid),
            None => protected["jwk"] = self.key.jwk(),
        }
        let protected = b64(&serde_json::to_vec(&protected)?);
        let payload = match payload {
            Some(value) => b64(&serde_json::to_vec(value)?),
            None => String::new(),
        };
        let signature = self.key.sign(format!("{protected}.{payload}").as_bytes())?;
        Ok(serde_json::to_vec(&json!({
            "protected": protected,
            "payload": payload,
            "signature": b64(&signature),
        }))?)
    }

    // `payload` None is a POST-as-GET; a rejected nonce is retried once with the fresh one the error carried.
    async fn post(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        accept: Option<&'static str>,
    ) -> Result<Reply> {
        let mut retried = false;
        loop {
            let nonce = self.nonce().await?;
            let body = self.signed(url, &nonce, payload)?;
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(JOSE));
            if let Some(accept) = accept {
                headers.insert(header::ACCEPT, HeaderValue::from_static(accept));
            }
            let reply = self
                .http
                .send(Method::POST, url, headers, Some(body))
                .await?;
            self.keep_nonce(&reply);
            if reply.status.is_success() {
                return Ok(reply);
            }
            let problem = Problem::read(&reply);
            if problem.is("badNonce") && !retried {
                retried = true;
                continue;
            }
            return Err(problem.error());
        }
    }

    async fn fetch(&mut self, url: &str) -> Result<Value> {
        let reply = self.post(url, None, None).await?;
        body_json(&reply)
    }

    // The account already agreed to the terms when the owner set agree_tos; a known key gets its existing account back.
    async fn account(&mut self, email: Option<&str>) -> Result<()> {
        let mut payload = json!({ "termsOfServiceAgreed": true });
        if let Some(email) = email {
            payload["contact"] = json!([format!("mailto:{email}")]);
        }
        let url = self.dir.new_account.clone();
        let reply = self.post(&url, Some(&payload), None).await?;
        let kid = location(&reply)
            .ok_or_else(|| unavailable("the ACME server did not return an account URL"))?;
        self.http.endpoints().check(&kid)?;
        self.kid = Some(kid);
        Ok(())
    }
}

pub struct Order<'a> {
    pub hosts: &'a [String],
    pub email: Option<&'a str>,
    pub staging: bool,
}

struct Pending {
    domain: String,
    challenge: String,
    authz: String,
    zone: Zone,
    name: String,
    value: String,
}

// Orders a certificate with DNS-01 through Cloudflare; every TXT record it created is removed whether or not the order succeeds.
pub async fn issue(
    http: &Http,
    token: &CfToken,
    key: &AccountKey,
    order: &Order<'_>,
) -> Result<Generated> {
    let ep = http.endpoints();
    let dir_url = if order.staging {
        ep.acme_staging.clone()
    } else {
        ep.acme_production.clone()
    };
    let mut acme = Acme::connect(http, key, &dir_url).await?;
    acme.account(order.email).await?;
    let cf = Cloudflare::new(http, token);
    let mut records: Vec<(Zone, String)> = Vec::new();
    let outcome = run_order(&mut acme, &cf, order.hosts, &mut records).await;
    for (zone, id) in &records {
        if let Err(e) = cf.delete_record(zone, id).await {
            tracing::warn!(zone = %zone.name, record = %id, error = %e, "an ACME challenge TXT record could not be removed; delete it in the Cloudflare dashboard");
        }
    }
    outcome
}

async fn run_order(
    acme: &mut Acme<'_>,
    cf: &Cloudflare<'_>,
    hosts: &[String],
    records: &mut Vec<(Zone, String)>,
) -> Result<Generated> {
    let http = acme.http;
    let ep = http.endpoints();
    let identifiers: Vec<Value> = hosts
        .iter()
        .map(|h| json!({ "type": "dns", "value": h }))
        .collect();
    let url = acme.dir.new_order.clone();
    let reply = acme
        .post(&url, Some(&json!({ "identifiers": identifiers })), None)
        .await?;
    let order_url = location(&reply)
        .ok_or_else(|| unavailable("the ACME server did not return an order URL"))?;
    let order = body_json(&reply)?;
    let authorizations = urls(&order["authorizations"]);
    let finalize = order["finalize"]
        .as_str()
        .ok_or_else(|| unavailable("the ACME order has no finalize URL"))?
        .to_string();
    if authorizations.len() > hosts.len() {
        return Err(unavailable(
            "the ACME server asked for more authorizations than names were ordered",
        ));
    }
    let thumbprint = acme.key.thumbprint();
    let mut pending = Vec::new();
    for authz_url in &authorizations {
        let authz = acme.fetch(authz_url).await?;
        let domain = authz["identifier"]["value"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        // the server picks the names to prove, and only names this order asked for may become DNS records
        if !hosts
            .iter()
            .any(|h| h.strip_prefix("*.").unwrap_or(h) == domain)
        {
            return Err(unavailable(format!(
                "the ACME server asked to prove an unexpected name {:?}",
                remote_text(&domain)
            )));
        }
        match authz["status"].as_str() {
            Some("valid") => continue,
            Some("pending") => {}
            other => {
                return Err(unavailable(format!(
                    "the authorization for {domain} is {}",
                    remote_text(other.unwrap_or("missing"))
                )));
            }
        }
        let challenge = authz["challenges"]
            .as_array()
            .and_then(|all| all.iter().find(|c| c["type"] == "dns-01"))
            .ok_or_else(|| {
                unavailable(format!(
                    "the ACME server offered no dns-01 challenge for {domain}"
                ))
            })?;
        let token = challenge["token"]
            .as_str()
            .filter(|t| !t.is_empty() && t.len() <= MAX_CHALLENGE_TOKEN && is_b64url(t))
            .ok_or_else(|| unavailable("the dns-01 challenge has no usable token"))?;
        let challenge_url = challenge["url"]
            .as_str()
            .ok_or_else(|| unavailable("the dns-01 challenge has no URL"))?
            .to_string();
        let value = b64(Sha256::digest(format!("{token}.{thumbprint}").as_bytes()).as_slice());
        let name = format!("_acme-challenge.{domain}");
        let zone = cf.zone_for(&domain).await?;
        let id = cf.create_txt(&zone, &name, &value).await?;
        records.push((zone.clone(), id));
        pending.push(Pending {
            domain,
            challenge: challenge_url,
            authz: authz_url.clone(),
            zone,
            name,
            value,
        });
    }
    let deadline = Instant::now() + ep.dns_wait;
    for p in &pending {
        while !cf.txt_present(&p.zone, &p.name, &p.value).await? {
            if Instant::now() >= deadline {
                return Err(unavailable(format!(
                    "the TXT record {} did not show up in Cloudflare within {} seconds",
                    p.name,
                    ep.dns_wait.as_secs()
                )));
            }
            tokio::time::sleep(ep.poll_interval).await;
        }
    }
    if !pending.is_empty() {
        tokio::time::sleep(ep.dns_settle).await;
    }
    for p in &pending {
        acme.post(&p.challenge, Some(&json!({})), None).await?;
    }
    for p in &pending {
        wait_for_authz(acme, p, ep).await?;
    }
    let csr = certs::key_and_csr(hosts)?;
    acme.post(&finalize, Some(&json!({ "csr": b64(&csr.csr_der) })), None)
        .await?;
    let cert_url = wait_for_order(acme, &order_url, ep).await?;
    let reply = acme.post(&cert_url, None, Some(PEM_CHAIN)).await?;
    let chain_pem = String::from_utf8(reply.body.to_vec())
        .map_err(|_| unavailable("the certificate chain is not text"))?;
    Ok(Generated {
        chain_pem,
        key_pem: csr.key_pem,
    })
}

async fn wait_for_authz(acme: &mut Acme<'_>, p: &Pending, ep: &Endpoints) -> Result<()> {
    let deadline = Instant::now() + ep.acme_wait;
    loop {
        let authz = acme.fetch(&p.authz).await?;
        match authz["status"].as_str() {
            Some("valid") => return Ok(()),
            Some("pending" | "processing") => {}
            other => {
                let detail = authz["challenges"]
                    .as_array()
                    .and_then(|all| all.iter().find(|c| c["type"] == "dns-01"))
                    .and_then(|c| c["error"]["detail"].as_str())
                    .or(other)
                    .unwrap_or("no status");
                return Err(unavailable(format!(
                    "the ACME server could not validate {}: {}",
                    p.domain,
                    remote_text(detail)
                )));
            }
        }
        if Instant::now() >= deadline {
            return Err(unavailable(format!(
                "the ACME server did not validate {} within {} seconds",
                p.domain,
                ep.acme_wait.as_secs()
            )));
        }
        tokio::time::sleep(ep.poll_interval).await;
    }
}

async fn wait_for_order(acme: &mut Acme<'_>, order_url: &str, ep: &Endpoints) -> Result<String> {
    let deadline = Instant::now() + ep.acme_wait;
    loop {
        let order = acme.fetch(order_url).await?;
        match order["status"].as_str() {
            Some("valid") => {
                return order["certificate"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| unavailable("the finished ACME order has no certificate URL"));
            }
            Some("pending" | "ready" | "processing") => {}
            other => {
                let detail = order["error"]["detail"]
                    .as_str()
                    .or(other)
                    .unwrap_or("no status");
                return Err(unavailable(format!(
                    "the ACME order failed: {}",
                    remote_text(detail)
                )));
            }
        }
        if Instant::now() >= deadline {
            return Err(unavailable(format!(
                "the ACME order was not finished within {} seconds",
                ep.acme_wait.as_secs()
            )));
        }
        tokio::time::sleep(ep.poll_interval).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Busy {
    Running,
    Hourly { retry_after: u64 },
}

// Held for the whole issuing operation; dropping it lets the next one start.
pub struct Ticket {
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Issued,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: String,
    pub kind: &'static str,
    pub hosts: Vec<String>,
    pub status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub staging: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_at: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

impl Job {
    pub fn pending(kind: &'static str, hosts: Vec<String>, staging: bool, at: String) -> Self {
        Self {
            id: ulid::Ulid::generate().to_string(),
            kind,
            hosts,
            status: JobStatus::Pending,
            error: None,
            staging,
            certificate_id: None,
            not_after: None,
            renew_at: None,
            created_at: at,
            finished_at: None,
        }
    }
}

pub struct Finished {
    pub certificate_id: String,
    pub not_after: String,
    pub renew_at: String,
}

struct Retry {
    failures: u32,
    next: i64,
    error: String,
}

// Process-wide state of the node's own issuing: one operation at a time, ten starts an hour, recent jobs and renewal backoff.
pub struct Issuing {
    endpoints: StdMutex<Arc<Endpoints>>,
    running: Arc<Semaphore>,
    starts: StdMutex<VecDeque<i64>>,
    jobs: StdMutex<VecDeque<Job>>,
    retries: StdMutex<HashMap<String, Retry>>,
    renewals: AtomicBool,
}

impl Default for Issuing {
    fn default() -> Self {
        Self::new()
    }
}

impl Issuing {
    pub fn new() -> Self {
        Self {
            endpoints: StdMutex::new(Arc::new(Endpoints::default())),
            running: Arc::new(Semaphore::new(1)),
            starts: StdMutex::new(VecDeque::new()),
            jobs: StdMutex::new(VecDeque::new()),
            retries: StdMutex::new(HashMap::new()),
            renewals: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub fn set_endpoints(&self, ep: Endpoints) {
        *lock(&self.endpoints) = Arc::new(ep);
    }

    pub fn http(&self) -> Result<Http> {
        let ep = Arc::clone(&lock(&self.endpoints));
        Http::new(ep)
    }

    // An operation the owner asked for: refused while another runs or once ten started within the hour.
    pub fn begin(&self, now: i64) -> std::result::Result<Ticket, Busy> {
        let mut starts = lock(&self.starts);
        while starts.front().is_some_and(|t| *t <= now - HOUR_SECS) {
            starts.pop_front();
        }
        if starts.len() >= MAX_PER_HOUR {
            let oldest = starts.front().copied().unwrap_or(now);
            let wait = (oldest + HOUR_SECS - now).max(1);
            return Err(Busy::Hourly {
                retry_after: u64::try_from(wait).unwrap_or(1),
            });
        }
        let permit = Arc::clone(&self.running)
            .try_acquire_owned()
            .map_err(|_| Busy::Running)?;
        starts.push_back(now);
        Ok(Ticket { _permit: permit })
    }

    // Renewals wait their turn instead of failing, and do not count toward the hourly limit.
    pub async fn turn(&self) -> Result<Ticket> {
        Arc::clone(&self.running)
            .acquire_owned()
            .await
            .map(|permit| Ticket { _permit: permit })
            .map_err(|_| internal("the issuing gate is closed"))
    }

    pub fn add_job(&self, job: Job) {
        let mut jobs = lock(&self.jobs);
        jobs.push_back(job);
        while jobs.len() > MAX_JOBS {
            match jobs.iter().position(|j| j.status != JobStatus::Pending) {
                Some(at) => {
                    jobs.remove(at);
                }
                None => break,
            }
        }
    }

    pub fn finish(&self, id: &str, outcome: std::result::Result<Finished, String>, at: String) {
        let mut jobs = lock(&self.jobs);
        let Some(job) = jobs.iter_mut().find(|j| j.id == id) else {
            return;
        };
        match outcome {
            Ok(done) => {
                job.status = JobStatus::Issued;
                job.certificate_id = Some(done.certificate_id);
                job.not_after = Some(done.not_after);
                job.renew_at = Some(done.renew_at);
            }
            Err(error) => {
                job.status = JobStatus::Failed;
                job.error = Some(error);
            }
        }
        job.finished_at = Some(at);
    }

    pub fn jobs(&self) -> Vec<Job> {
        lock(&self.jobs).iter().rev().cloned().collect()
    }

    pub fn job(&self, id: &str) -> Option<Job> {
        lock(&self.jobs).iter().find(|j| j.id == id).cloned()
    }

    pub fn may_retry(&self, cert_id: &str, now: i64) -> bool {
        lock(&self.retries)
            .get(cert_id)
            .is_none_or(|r| r.next <= now)
    }

    // One hour after the first failure, doubling up to a day.
    pub fn record_failure(&self, cert_id: &str, now: i64, error: &str) -> i64 {
        let mut retries = lock(&self.retries);
        let entry = retries.entry(cert_id.to_string()).or_insert(Retry {
            failures: 0,
            next: now,
            error: String::new(),
        });
        entry.failures = entry.failures.saturating_add(1);
        let shift = (entry.failures - 1).min(5);
        entry.next = now + (BACKOFF_BASE_SECS << shift).min(BACKOFF_MAX_SECS);
        entry.error = error.to_string();
        entry.next
    }

    pub fn record_success(&self, cert_id: &str) {
        lock(&self.retries).remove(cert_id);
    }

    pub fn last_failure(&self, cert_id: &str) -> Option<(i64, String)> {
        lock(&self.retries)
            .get(cert_id)
            .map(|r| (r.next, r.error.clone()))
    }

    // True for the first caller only, so the renewal task is started once per node.
    pub fn claim_renewals(&self) -> bool {
        !self.renewals.swap(true, Ordering::SeqCst)
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
pub(crate) mod mock {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm,
    };
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension};

    use crate::cfapi::Endpoints;

    pub const TOKEN: &str = "cf-test-token-Zq9X7mVb3T5kLp2W";
    pub const SERVICE_KEY: &str = "v1.0-servicekey-4f8a2c9e1b7d";
    pub const CA_NAME: &str = "Cite Mock CA";
    pub const ZONE_ID: &str = "0123456789abcdef0123456789abcdef";

    type Shared = Arc<Mutex<MockState>>;

    fn lock(state: &Shared) -> std::sync::MutexGuard<'_, MockState> {
        state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn unb64(text: &str) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(text).ok()
    }

    // A public key taken from a CSR, so the mock CA can sign for a key it never holds.
    struct ForeignKey(Vec<u8>);

    impl PublicKeyData for ForeignKey {
        fn der_bytes(&self) -> &[u8] {
            &self.0
        }

        fn algorithm(&self) -> &'static SignatureAlgorithm {
            &PKCS_ECDSA_P256_SHA256
        }
    }

    #[derive(Debug, Clone)]
    pub struct Seen {
        pub sans: Vec<String>,
        pub key_len: usize,
        pub common_name: Option<String>,
    }

    struct Ca {
        cert: rcgen::Certificate,
        key: KeyPair,
        pem: String,
    }

    impl Ca {
        fn new() -> Self {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, CA_NAME);
            params.distinguished_name = dn;
            let cert = params.self_signed(&key).expect("ca certificate");
            let pem = cert.pem();
            Self { cert, key, pem }
        }

        fn sign(&self, csr_der: &[u8], days: i64) -> Result<(String, Seen), String> {
            let (_, csr) = X509CertificationRequest::from_der(csr_der)
                .map_err(|_| "the CSR does not parse".to_string())?;
            let info = &csr.certification_request_info;
            let point = info.subject_pki.subject_public_key.data.to_vec();
            let common_name = info
                .subject
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(str::to_string);
            let mut sans = Vec::new();
            for ext in csr.requested_extensions().into_iter().flatten() {
                if let ParsedExtension::SubjectAlternativeName(san) = ext {
                    for name in &san.general_names {
                        if let GeneralName::DNSName(dns) = name {
                            sans.push(dns.to_string());
                        }
                    }
                }
            }
            if sans.is_empty() {
                return Err("the CSR names no hosts".into());
            }
            let mut params = CertificateParams::new(sans.clone()).map_err(|e| e.to_string())?;
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::days(1);
            params.not_after = now + time::Duration::days(days);
            let leaf = params
                .signed_by(&ForeignKey(point.clone()), &self.cert, &self.key)
                .map_err(|e| e.to_string())?;
            Ok((
                leaf.pem(),
                Seen {
                    sans,
                    key_len: point.len(),
                    common_name,
                },
            ))
        }
    }

    #[derive(Debug, Clone)]
    pub struct Record {
        pub id: String,
        pub zone: String,
        pub name: String,
        pub content: String,
    }

    #[derive(Debug, Clone)]
    pub struct OriginCall {
        pub auth: &'static str,
        pub hostnames: Vec<String>,
        pub request_type: String,
        pub validity: u64,
        pub csr: Seen,
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct Script {
        pub fail_origin: bool,
        pub fail_challenge: bool,
        pub hide_records: bool,
        pub foreign_new_order: bool,
        pub acme_days: i64,
    }

    struct Account {
        kid: String,
        point: Vec<u8>,
        thumbprint: String,
    }

    struct Authz {
        domain: String,
        wildcard: bool,
        token: String,
        status: &'static str,
        error: Option<String>,
        account: usize,
    }

    struct Order {
        account: usize,
        identifiers: Vec<String>,
        authz: Vec<usize>,
        status: &'static str,
        chain: Option<String>,
    }

    struct Jws {
        account: Option<usize>,
        point: Vec<u8>,
        jwk: Option<Value>,
        payload: Option<Value>,
    }

    pub struct MockState {
        base: String,
        ca: Ca,
        pub script: Script,
        pub zones: Vec<(String, String)>,
        pub records: Vec<Record>,
        pub created: usize,
        pub deleted: usize,
        pub origin_calls: Vec<OriginCall>,
        pub csrs: Vec<Seen>,
        pub directories: Vec<String>,
        pub contacts: Vec<Value>,
        nonces: HashSet<String>,
        next: u64,
        accounts: Vec<Account>,
        authzs: Vec<Authz>,
        orders: Vec<Order>,
    }

    pub struct Mock {
        pub base: String,
        state: Shared,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Mock {
        pub fn endpoints(&self) -> Endpoints {
            Endpoints::local(&self.base)
        }

        pub fn with<T>(&self, f: impl FnOnce(&mut MockState) -> T) -> T {
            f(&mut lock(&self.state))
        }
    }

    // One local server playing both the Cloudflare API and an ACME CA, sharing the DNS records the CA checks.
    pub async fn start() -> Mock {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let state = Arc::new(Mutex::new(MockState {
            base: base.clone(),
            ca: Ca::new(),
            script: Script {
                acme_days: 90,
                ..Script::default()
            },
            zones: vec![(ZONE_ID.into(), "example.com".into())],
            records: Vec::new(),
            created: 0,
            deleted: 0,
            origin_calls: Vec::new(),
            csrs: Vec::new(),
            directories: Vec::new(),
            contacts: Vec::new(),
            nonces: HashSet::new(),
            next: 0,
            accounts: Vec::new(),
            authzs: Vec::new(),
            orders: Vec::new(),
        }));
        let app = Router::new()
            .route("/client/v4/certificates", post(origin_ca))
            .route("/client/v4/zones", get(zones))
            .route(
                "/client/v4/zones/{zone}/dns_records",
                get(list_records).post(create_record),
            )
            .route(
                "/client/v4/zones/{zone}/dns_records/{id}",
                axum::routing::delete(delete_record),
            )
            .route("/acme/directory", get(directory))
            .route("/staging/directory", get(directory))
            .route("/acme/new-nonce", get(new_nonce))
            .route("/acme/{*rest}", post(acme_post))
            .route("/redirect", get(redirect))
            .route("/big", get(big))
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Mock { base, state, task }
    }

    fn cf_auth(headers: &HeaderMap) -> Option<&'static str> {
        let text = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
        if text(header::AUTHORIZATION) == Some(format!("Bearer {TOKEN}").as_str()) {
            return Some("bearer");
        }
        let key = header::HeaderName::from_static("x-auth-user-service-key");
        (text(key) == Some(SERVICE_KEY)).then_some("service-key")
    }

    fn cf_ok(result: Value) -> Response {
        Json(json!({ "success": true, "errors": [], "messages": [], "result": result }))
            .into_response()
    }

    fn cf_error(status: StatusCode, message: &str) -> Response {
        let body = json!({
            "success": false,
            "errors": [{ "code": 1000, "message": message }],
            "messages": [],
            "result": null,
        });
        (status, Json(body)).into_response()
    }

    fn sorted(names: &[String]) -> Vec<String> {
        let mut v = names.to_vec();
        v.sort();
        v
    }

    async fn origin_ca(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
        let Some(auth) = cf_auth(&headers) else {
            return cf_error(StatusCode::FORBIDDEN, "Authentication error");
        };
        let Ok(req) = serde_json::from_slice::<Value>(&body) else {
            return cf_error(StatusCode::BAD_REQUEST, "body is not JSON");
        };
        let mut s = lock(&state);
        if s.script.fail_origin {
            let echoed = if auth == "bearer" { TOKEN } else { SERVICE_KEY };
            return cf_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid request for credential {echoed}"),
            );
        }
        let der = match pem::parse(req["csr"].as_str().unwrap_or_default()) {
            Ok(block) if block.tag() == "CERTIFICATE REQUEST" => block.into_contents(),
            _ => return cf_error(StatusCode::BAD_REQUEST, "csr is not a PEM CSR"),
        };
        let validity = req["requested_validity"].as_u64().unwrap_or(0);
        let hostnames: Vec<String> = req["hostnames"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let days = i64::try_from(validity).unwrap_or(0);
        let (leaf, seen) = match s.ca.sign(&der, days) {
            Ok(pair) => pair,
            Err(e) => return cf_error(StatusCode::BAD_REQUEST, &e),
        };
        if sorted(&seen.sans) != sorted(&hostnames) {
            return cf_error(StatusCode::BAD_REQUEST, "hostnames do not match the CSR");
        }
        s.origin_calls.push(OriginCall {
            auth,
            hostnames: hostnames.clone(),
            request_type: req["request_type"].as_str().unwrap_or_default().to_string(),
            validity,
            csr: seen,
        });
        cf_ok(json!({
            "id": "1",
            "certificate": leaf,
            "hostnames": hostnames,
            "request_type": "origin-ecc",
            "requested_validity": validity,
        }))
    }

    async fn zones(
        State(state): State<Shared>,
        headers: HeaderMap,
        Query(q): Query<HashMap<String, String>>,
    ) -> Response {
        if cf_auth(&headers).is_none() {
            return cf_error(StatusCode::FORBIDDEN, "Authentication error");
        }
        let name = q.get("name").cloned().unwrap_or_default();
        let found: Vec<Value> = lock(&state)
            .zones
            .iter()
            .filter(|(_, n)| *n == name)
            .map(|(id, n)| json!({ "id": id, "name": n, "status": "active" }))
            .collect();
        cf_ok(Value::Array(found))
    }

    async fn create_record(
        State(state): State<Shared>,
        headers: HeaderMap,
        Path(zone): Path<String>,
        body: Bytes,
    ) -> Response {
        if cf_auth(&headers).is_none() {
            return cf_error(StatusCode::FORBIDDEN, "Authentication error");
        }
        let Ok(req) = serde_json::from_slice::<Value>(&body) else {
            return cf_error(StatusCode::BAD_REQUEST, "body is not JSON");
        };
        let mut s = lock(&state);
        if !s.zones.iter().any(|(id, _)| *id == zone) {
            return cf_error(StatusCode::NOT_FOUND, "zone not found");
        }
        if req["type"] != "TXT" {
            return cf_error(StatusCode::BAD_REQUEST, "only TXT records are expected");
        }
        s.next += 1;
        let id = format!("rec{:029}", s.next);
        let record = Record {
            id: id.clone(),
            zone,
            name: req["name"].as_str().unwrap_or_default().to_string(),
            content: req["content"].as_str().unwrap_or_default().to_string(),
        };
        s.records.push(record.clone());
        s.created += 1;
        cf_ok(json!({ "id": id, "type": "TXT", "name": record.name, "content": record.content }))
    }

    async fn list_records(
        State(state): State<Shared>,
        headers: HeaderMap,
        Path(zone): Path<String>,
        Query(q): Query<HashMap<String, String>>,
    ) -> Response {
        if cf_auth(&headers).is_none() {
            return cf_error(StatusCode::FORBIDDEN, "Authentication error");
        }
        let s = lock(&state);
        if s.script.hide_records {
            return cf_ok(json!([]));
        }
        let name = q.get("name").cloned().unwrap_or_default();
        let found: Vec<Value> = s
            .records
            .iter()
            .filter(|r| r.zone == zone && r.name == name)
            .map(|r| json!({ "id": r.id, "type": "TXT", "name": r.name, "content": format!("\"{}\"", r.content) }))
            .collect();
        cf_ok(Value::Array(found))
    }

    async fn delete_record(
        State(state): State<Shared>,
        headers: HeaderMap,
        Path((zone, id)): Path<(String, String)>,
    ) -> Response {
        if cf_auth(&headers).is_none() {
            return cf_error(StatusCode::FORBIDDEN, "Authentication error");
        }
        let mut s = lock(&state);
        let Some(at) = s.records.iter().position(|r| r.zone == zone && r.id == id) else {
            return cf_error(StatusCode::NOT_FOUND, "record not found");
        };
        s.records.remove(at);
        s.deleted += 1;
        cf_ok(json!({ "id": id }))
    }

    async fn redirect() -> Response {
        (
            StatusCode::FOUND,
            [(header::LOCATION, "http://localhost:1/elsewhere")],
        )
            .into_response()
    }

    async fn big() -> Response {
        vec![b'a'; 2 * 1024 * 1024].into_response()
    }

    async fn directory(State(state): State<Shared>, uri: Uri) -> Response {
        let mut s = lock(&state);
        let which = uri.path().trim_start_matches('/');
        let which = which.split('/').next().unwrap_or_default().to_string();
        s.directories.push(which);
        let base = s.base.clone();
        let order_base = if s.script.foreign_new_order {
            base.replace("127.0.0.1", "localhost")
        } else {
            base.clone()
        };
        Json(json!({
            "newNonce": format!("{base}/acme/new-nonce"),
            "newAccount": format!("{base}/acme/new-account"),
            "newOrder": format!("{order_base}/acme/new-order"),
            "meta": { "termsOfService": format!("{base}/terms") },
        }))
        .into_response()
    }

    fn with_nonce(mut res: Response, nonce: &str) -> Response {
        if let Ok(value) = HeaderValue::from_str(nonce) {
            res.headers_mut().insert("replay-nonce", value);
        }
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        res
    }

    async fn new_nonce(State(state): State<Shared>) -> Response {
        let nonce = lock(&state).nonce();
        with_nonce(StatusCode::OK.into_response(), &nonce)
    }

    async fn acme_post(State(state): State<Shared>, uri: Uri, body: Bytes) -> Response {
        let mut s = lock(&state);
        let url = format!("{}{}", s.base, uri.path());
        let res = match s.handle(&url, uri.path(), &body) {
            Ok(res) | Err(res) => res,
        };
        let nonce = s.nonce();
        with_nonce(res, &nonce)
    }

    fn problem(status: StatusCode, kind: &str, detail: &str) -> Response {
        let body =
            json!({ "type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail });
        let mut res = (status, Json(body)).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        res
    }

    fn located(status: StatusCode, location: &str, body: Value) -> Response {
        let mut res = (status, Json(body)).into_response();
        if let Ok(value) = HeaderValue::from_str(location) {
            res.headers_mut().insert(header::LOCATION, value);
        }
        res
    }

    fn point_of(jwk: &Value) -> Option<Vec<u8>> {
        if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
            return None;
        }
        let x = unb64(jwk["x"].as_str()?)?;
        let y = unb64(jwk["y"].as_str()?)?;
        if x.len() != 32 || y.len() != 32 {
            return None;
        }
        let mut point = vec![4u8];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        Some(point)
    }

    fn thumbprint_of(jwk: &Value) -> String {
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap_or_default(),
            jwk["y"].as_str().unwrap_or_default()
        );
        b64(Sha256::digest(canonical.as_bytes()).as_slice())
    }

    type Answer = Result<Response, Response>;

    impl MockState {
        fn nonce(&mut self) -> String {
            self.next += 1;
            let nonce = b64(format!("nonce-{}", self.next).as_bytes());
            self.nonces.insert(nonce.clone());
            nonce
        }

        fn handle(&mut self, url: &str, path: &str, body: &[u8]) -> Answer {
            let jws = self.verify(url, body)?;
            let rest = path.trim_start_matches("/acme/");
            let parts: Vec<&str> = rest.split('/').collect();
            match parts.as_slice() {
                ["new-account"] => self.new_account(jws),
                ["new-order"] => self.new_order(jws),
                ["authz", n] => self.authz(jws, n),
                ["chall", n] => self.challenge(jws, n),
                ["order", n] => self.order(jws, n),
                ["order", n, "finalize"] => self.finalize(jws, n),
                ["cert", n] => self.cert(jws, n),
                _ => Err(problem(
                    StatusCode::NOT_FOUND,
                    "malformed",
                    "unknown resource",
                )),
            }
        }

        // Checks what a real CA checks: ES256, the exact URL, a nonce it issued and has not seen back, and the signature.
        fn verify(&mut self, url: &str, body: &[u8]) -> Result<Jws, Response> {
            let bad = |detail: &str| problem(StatusCode::BAD_REQUEST, "malformed", detail);
            let outer: Value = serde_json::from_slice(body).map_err(|_| bad("body is not JSON"))?;
            let (Some(p64), Some(pl64), Some(s64)) = (
                outer["protected"].as_str(),
                outer["payload"].as_str(),
                outer["signature"].as_str(),
            ) else {
                return Err(bad("not a flattened JWS"));
            };
            let protected: Value = unb64(p64)
                .and_then(|b| serde_json::from_slice(&b).ok())
                .ok_or_else(|| bad("protected header does not decode"))?;
            if protected["alg"] != "ES256" {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "badSignatureAlgorithm",
                    "only ES256",
                ));
            }
            if protected["url"].as_str() != Some(url) {
                return Err(problem(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "url mismatch",
                ));
            }
            let nonce = protected["nonce"].as_str().unwrap_or_default();
            if !self.nonces.remove(nonce) {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "badNonce",
                    "unknown or reused nonce",
                ));
            }
            let (point, account, jwk) = match (protected.get("jwk"), protected.get("kid")) {
                (Some(jwk), None) => (
                    point_of(jwk).ok_or_else(|| bad("jwk is not a P-256 key"))?,
                    None,
                    Some(jwk.clone()),
                ),
                (None, Some(kid)) => {
                    let kid = kid.as_str().unwrap_or_default();
                    let at = self
                        .accounts
                        .iter()
                        .position(|a| a.kid == kid)
                        .ok_or_else(|| {
                            problem(
                                StatusCode::BAD_REQUEST,
                                "accountDoesNotExist",
                                "unknown kid",
                            )
                        })?;
                    (self.accounts[at].point.clone(), Some(at), None)
                }
                _ => return Err(bad("exactly one of jwk and kid is required")),
            };
            let signature = unb64(s64).ok_or_else(|| bad("signature does not decode"))?;
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
                .verify(format!("{p64}.{pl64}").as_bytes(), &signature)
                .map_err(|_| bad("signature does not verify"))?;
            let payload = if pl64.is_empty() {
                None
            } else {
                Some(
                    unb64(pl64)
                        .and_then(|b| serde_json::from_slice(&b).ok())
                        .ok_or_else(|| bad("payload does not decode"))?,
                )
            };
            Ok(Jws {
                account,
                point,
                jwk,
                payload,
            })
        }

        fn new_account(&mut self, jws: Jws) -> Answer {
            let Some(jwk) = jws.jwk else {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "malformed",
                    "newAccount needs jwk",
                ));
            };
            let payload = jws.payload.unwrap_or(Value::Null);
            if let Some(known) = self.accounts.iter().find(|a| a.point == jws.point) {
                return Ok(located(
                    StatusCode::OK,
                    &known.kid,
                    json!({ "status": "valid" }),
                ));
            }
            if payload["termsOfServiceAgreed"] != true {
                return Err(problem(
                    StatusCode::FORBIDDEN,
                    "userActionRequired",
                    "the terms of service must be agreed",
                ));
            }
            self.contacts.push(payload["contact"].clone());
            let kid = format!("{}/acme/acct/{}", self.base, self.accounts.len() + 1);
            self.accounts.push(Account {
                kid: kid.clone(),
                point: jws.point,
                thumbprint: thumbprint_of(&jwk),
            });
            Ok(located(
                StatusCode::CREATED,
                &kid,
                json!({ "status": "valid", "contact": payload["contact"] }),
            ))
        }

        fn signed_in(jws: &Jws) -> Result<usize, Response> {
            jws.account
                .ok_or_else(|| problem(StatusCode::BAD_REQUEST, "malformed", "kid is required"))
        }

        fn order_json(&self, n: usize) -> Value {
            let o = &self.orders[n];
            let mut v = json!({
                "status": o.status,
                "identifiers": o.identifiers.iter().map(|i| json!({ "type": "dns", "value": i })).collect::<Vec<_>>(),
                "authorizations": o.authz.iter().map(|a| format!("{}/acme/authz/{a}", self.base)).collect::<Vec<_>>(),
                "finalize": format!("{}/acme/order/{n}/finalize", self.base),
            });
            if o.chain.is_some() {
                v["certificate"] = json!(format!("{}/acme/cert/{n}", self.base));
            }
            v
        }

        fn new_order(&mut self, jws: Jws) -> Answer {
            let account = Self::signed_in(&jws)?;
            let payload = jws.payload.unwrap_or(Value::Null);
            let identifiers: Vec<String> = payload["identifiers"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .filter(|i| i["type"] == "dns")
                        .filter_map(|i| i["value"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if identifiers.is_empty() {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "malformed",
                    "no identifiers",
                ));
            }
            let mut authz = Vec::new();
            for id in &identifiers {
                let (domain, wildcard) = match id.strip_prefix("*.") {
                    Some(base) => (base.to_string(), true),
                    None => (id.clone(), false),
                };
                self.next += 1;
                self.authzs.push(Authz {
                    domain,
                    wildcard,
                    token: b64(format!("token-{}", self.next).as_bytes()),
                    status: "pending",
                    error: None,
                    account,
                });
                authz.push(self.authzs.len() - 1);
            }
            self.orders.push(Order {
                account,
                identifiers,
                authz,
                status: "pending",
                chain: None,
            });
            let n = self.orders.len() - 1;
            let at = format!("{}/acme/order/{n}", self.base);
            Ok(located(StatusCode::CREATED, &at, self.order_json(n)))
        }

        fn index(n: &str, len: usize) -> Result<usize, Response> {
            n.parse::<usize>()
                .ok()
                .filter(|i| *i < len)
                .ok_or_else(|| problem(StatusCode::NOT_FOUND, "malformed", "no such resource"))
        }

        fn authz_json(&self, n: usize) -> Value {
            let a = &self.authzs[n];
            let mut dns = json!({
                "type": "dns-01",
                "url": format!("{}/acme/chall/{n}", self.base),
                "token": a.token,
                "status": a.status,
            });
            if let Some(error) = &a.error {
                dns["error"] =
                    json!({ "type": "urn:ietf:params:acme:error:unauthorized", "detail": error });
            }
            let mut challenges = Vec::new();
            if !a.wildcard {
                challenges.push(json!({
                    "type": "http-01",
                    "url": format!("{}/acme/chall/{n}-http", self.base),
                    "token": a.token,
                    "status": "pending",
                }));
            }
            challenges.push(dns);
            json!({
                "status": a.status,
                "identifier": { "type": "dns", "value": a.domain },
                "wildcard": a.wildcard,
                "challenges": challenges,
            })
        }

        fn authz(&mut self, jws: Jws, n: &str) -> Answer {
            let account = Self::signed_in(&jws)?;
            let n = Self::index(n, self.authzs.len())?;
            if jws.payload.is_some() || self.authzs[n].account != account {
                return Err(problem(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "not yours",
                ));
            }
            Ok(Json(self.authz_json(n)).into_response())
        }

        fn challenge(&mut self, jws: Jws, n: &str) -> Answer {
            let account = Self::signed_in(&jws)?;
            let n = Self::index(n, self.authzs.len())?;
            if jws.payload != Some(json!({})) || self.authzs[n].account != account {
                return Err(problem(StatusCode::BAD_REQUEST, "malformed", "expected {}"));
            }
            let a = &self.authzs[n];
            let expected = b64(Sha256::digest(
                format!("{}.{}", a.token, self.accounts[account].thumbprint).as_bytes(),
            )
            .as_slice());
            let name = format!("_acme-challenge.{}", a.domain);
            let found = self
                .records
                .iter()
                .any(|r| r.name == name && r.content == expected);
            let ok = found && !self.script.fail_challenge;
            let a = &mut self.authzs[n];
            a.status = if ok { "valid" } else { "invalid" };
            if !ok {
                a.error = Some(format!("No TXT record found at {name}"));
            }
            for order in &mut self.orders {
                if !order.authz.contains(&n) {
                    continue;
                }
                let states: Vec<&str> =
                    order.authz.iter().map(|i| self.authzs[*i].status).collect();
                if states.contains(&"invalid") {
                    order.status = "invalid";
                } else if states.iter().all(|s| *s == "valid") {
                    order.status = "ready";
                }
            }
            let mut body = self.authz_json(n)["challenges"]
                .as_array()
                .and_then(|c| c.last().cloned())
                .unwrap_or(Value::Null);
            body["status"] = json!(self.authzs[n].status);
            Ok(Json(body).into_response())
        }

        fn order(&mut self, jws: Jws, n: &str) -> Answer {
            let account = Self::signed_in(&jws)?;
            let n = Self::index(n, self.orders.len())?;
            if jws.payload.is_some() || self.orders[n].account != account {
                return Err(problem(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "not yours",
                ));
            }
            Ok(Json(self.order_json(n)).into_response())
        }

        fn finalize(&mut self, jws: Jws, n: &str) -> Answer {
            let account = Self::signed_in(&jws)?;
            let n = Self::index(n, self.orders.len())?;
            if self.orders[n].account != account {
                return Err(problem(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "not yours",
                ));
            }
            if self.orders[n].status != "ready" {
                return Err(problem(
                    StatusCode::FORBIDDEN,
                    "orderNotReady",
                    "order is not ready",
                ));
            }
            let der = jws
                .payload
                .as_ref()
                .and_then(|p| p["csr"].as_str())
                .and_then(unb64);
            let Some(der) = der else {
                return Err(problem(StatusCode::BAD_REQUEST, "badCSR", "csr missing"));
            };
            let (leaf, seen) = self
                .ca
                .sign(&der, self.script.acme_days)
                .map_err(|e| problem(StatusCode::BAD_REQUEST, "badCSR", &e))?;
            if sorted(&seen.sans) != sorted(&self.orders[n].identifiers) {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "badCSR",
                    "names differ from the order",
                ));
            }
            self.csrs.push(seen);
            let chain = format!("{leaf}{}", self.ca.pem);
            let order = &mut self.orders[n];
            order.chain = Some(chain);
            order.status = "valid";
            Ok(Json(self.order_json(n)).into_response())
        }

        fn cert(&mut self, jws: Jws, n: &str) -> Answer {
            let account = Self::signed_in(&jws)?;
            let n = Self::index(n, self.orders.len())?;
            let order = &self.orders[n];
            let Some(chain) = order.chain.clone().filter(|_| order.account == account) else {
                return Err(problem(
                    StatusCode::NOT_FOUND,
                    "malformed",
                    "no certificate",
                ));
            };
            let mut res = chain.into_response();
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pem-certificate-chain"),
            );
            Ok(res)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn email_addresses_are_plain() {
        for ok in ["admin@example.com", "a.b+tag@mail.example.org"] {
            assert!(validate_email(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "admin",
            "@example.com",
            "admin@",
            "admin@localhost",
            "a b@example.com",
            "admin@exa mple.com",
            "admin@*.example.com",
            "a@b@example.com",
            ".a@example.com",
            "admin@example.com\nBcc: x",
        ] {
            assert!(validate_email(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}@example.com", "a".repeat(65));
        assert!(validate_email(&long).is_err());
    }

    #[test]
    fn the_account_key_is_made_once_kept_private_and_signs_verifiably() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ACCOUNT_KEY_FILE);
        let first = AccountKey::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let again = AccountKey::load_or_create(&path).unwrap();
        assert_eq!(first.thumbprint(), again.thumbprint());
        assert_eq!(first.thumbprint().len(), 43);
        assert!(!format!("{first:?}").contains(&first.x));

        let signature = first.sign(b"protected.payload").unwrap();
        assert_eq!(signature.len(), 64);
        let mut point = vec![4u8];
        point.extend(URL_SAFE_NO_PAD.decode(&first.x).unwrap());
        point.extend(URL_SAFE_NO_PAD.decode(&first.y).unwrap());
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(b"protected.payload", &signature)
            .expect("signature verifies against the published jwk");

        std::fs::write(&path, "not a key").unwrap();
        assert!(AccountKey::load_or_create(&path).is_err());
    }

    #[test]
    fn one_operation_at_a_time_and_ten_an_hour() {
        let issuing = Issuing::new();
        let now = 1_000_000;
        let first = issuing.begin(now).expect("first");
        assert_eq!(issuing.begin(now).err(), Some(Busy::Running));
        drop(first);
        for i in 1..MAX_PER_HOUR {
            drop(
                issuing
                    .begin(now + i as i64)
                    .expect("within the hourly limit"),
            );
        }
        match issuing.begin(now + 100) {
            Err(Busy::Hourly { retry_after }) => assert_eq!(retry_after, 3500),
            other => panic!("expected the hourly limit, got {:?}", other.err()),
        }
        assert!(issuing.begin(now + HOUR_SECS).is_ok());
    }

    #[tokio::test]
    async fn renewals_wait_for_a_running_operation() {
        let issuing = Arc::new(Issuing::new());
        let held = issuing.begin(0).expect("begin");
        let waiter = {
            let issuing = Arc::clone(&issuing);
            tokio::spawn(async move { issuing.turn().await.is_ok() })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(held);
        assert!(waiter.await.unwrap());
    }

    #[test]
    fn failed_renewals_back_off_exponentially_up_to_a_day() {
        let issuing = Issuing::new();
        let id = "01JD3Z8Q5V7M2K4N6P8R0T1W3Y";
        assert!(issuing.may_retry(id, 0));
        assert_eq!(issuing.record_failure(id, 0, "e1"), 3600);
        assert!(!issuing.may_retry(id, 3599));
        assert!(issuing.may_retry(id, 3600));
        assert_eq!(issuing.record_failure(id, 3600, "e2"), 3600 + 7200);
        let mut at = 10_800;
        for _ in 0..10 {
            at = issuing.record_failure(id, at, "again");
        }
        assert_eq!(
            issuing.record_failure(id, at, "last"),
            at + BACKOFF_MAX_SECS
        );
        assert_eq!(
            issuing.last_failure(id).map(|f| f.1),
            Some("last".to_string())
        );
        issuing.record_success(id);
        assert!(issuing.may_retry(id, 0));
        assert!(issuing.last_failure(id).is_none());
    }

    #[test]
    fn the_job_list_is_bounded_and_keeps_running_jobs() {
        let issuing = Issuing::new();
        let running = Job::pending("acme", vec!["a.example.com".into()], false, "t".into());
        let running_id = running.id.clone();
        issuing.add_job(running);
        for _ in 0..MAX_JOBS + 5 {
            let job = Job::pending("renew", Vec::new(), false, "t".into());
            let id = job.id.clone();
            issuing.add_job(job);
            issuing.finish(&id, Err("failed".into()), "t".into());
        }
        let jobs = issuing.jobs();
        assert!(jobs.len() <= MAX_JOBS + 1);
        assert!(issuing.job(&running_id).is_some());
        issuing.finish(
            &running_id,
            Ok(Finished {
                certificate_id: "C".into(),
                not_after: "na".into(),
                renew_at: "ra".into(),
            }),
            "done".into(),
        );
        let job = issuing.job(&running_id).unwrap();
        assert_eq!(job.status, JobStatus::Issued);
        assert_eq!(job.certificate_id.as_deref(), Some("C"));
        assert_eq!(job.finished_at.as_deref(), Some("done"));
    }

    #[test]
    fn the_renewal_task_is_claimed_once() {
        let issuing = Issuing::new();
        assert!(issuing.claim_renewals());
        assert!(!issuing.claim_renewals());
    }
}
