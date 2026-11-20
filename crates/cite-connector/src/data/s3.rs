//! A small S3 client: hand-written SigV4 over `reqwest`, `ring::hmac` and `sha2`, with multipart upload.
//!
//! The connector uses it for backup destinations. Transport rules: https only unless private endpoints are
//! allowed, the endpoint is resolved, checked against the private-address list and pinned for the whole
//! operation, redirects and proxies are off. Nothing here prints a key; errors carry the S3 error code and
//! message only.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use cite_edge::alerts::is_blocked_ip;
use cite_edge::validate::parse_s3_endpoint;
use futures_util::{Stream, StreamExt};
use reqwest::{Method, Url};
use ring::hmac;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use super::env::{percent_decode, percent_encode};

/// Objects up to this size go in one PutObject.
pub const SINGLE_PUT_MAX: u64 = 64 * 1024 * 1024;
/// Smallest multipart part the client sends.
pub const MIN_PART_SIZE: u64 = 16 * 1024 * 1024;
/// S3 allows 10 000 parts; the client aims for 9 000 to leave room.
pub const MAX_PARTS: u64 = 10_000;
const TARGET_PARTS: u64 = 9_000;
/// S3 refuses parts above 5 GiB.
const MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const ERROR_BODY_CAP: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const PART_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(6 * 3600);
/// Waits before the first, second and third retry of a transient failure.
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(4),
    Duration::from_secs(16),
];
const MAX_KEY_BYTES: usize = 1024;

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, S3Error>> + Send>>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum S3Error {
    /// Refused by policy (scheme, private address) or by the server's credentials check.
    #[error("refused: {0}")]
    Denied(String),
    #[error("not found")]
    NotFound,
    /// Worth retrying: 5xx, 429, SlowDown, timeouts, connection failures.
    #[error("temporary failure: {0}")]
    Transient(String),
    #[error("{0}")]
    Permanent(String),
}

const ADDRESS_REFUSED: &str = "the endpoint address is not allowed (loopback, link-local, unspecified, multicast, reserved, or a private range that CITE_DATA_S3_ALLOW_PRIVATE does not cover)";
const HTTP_PUBLIC_REFUSED: &str = "plain http is only allowed to an RFC 1918, ULA or CGNAT address with CITE_DATA_S3_ALLOW_PRIVATE=true";
const TLS_FAILED: &str = "the TLS connection could not be established";

/// The private ranges `CITE_DATA_S3_ALLOW_PRIVATE=true` opens: RFC 1918 (10/8, 172.16/12, 192.168/16), IPv6
/// ULA (fc00::/7) and CGNAT (100.64/10), including their IPv4-mapped forms. Nothing else that
/// `is_blocked_ip` refuses (loopback, link-local, unspecified, multicast, broadcast, documentation,
/// reserved) is covered.
pub fn is_allowed_private_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            v4.is_private() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn check_ip(ip: IpAddr, plain_http: bool, private_ok: bool) -> Result<(), S3Error> {
    if is_blocked_ip(ip) && !private_ok {
        return Err(S3Error::Denied(ADDRESS_REFUSED.into()));
    }
    if plain_http && !private_ok {
        return Err(S3Error::Denied(HTTP_PUBLIC_REFUSED.into()));
    }
    Ok(())
}

/// Whether the connector may connect to `ip` given the `allow_private` setting.
pub fn address_permitted(ip: IpAddr, allow_private: bool) -> bool {
    !is_blocked_ip(ip) || (allow_private && is_allowed_private_ip(ip))
}

impl S3Error {
    /// A fixed classification of the error that never repeats text from the server: `auth_failed`,
    /// `bucket_missing`, `unreachable`, `tls_error`, `refused_address`, `http_<status>` or `request_failed`.
    pub fn outcome(&self) -> String {
        let http = |m: &str| -> Option<(u16, Option<String>)> {
            let rest = m.strip_prefix("HTTP ")?;
            let mut parts = rest.split([' ', ':']);
            let status = parts.next()?.parse().ok()?;
            let code = parts.next().filter(|c| !c.is_empty()).map(str::to_string);
            Some((status, code))
        };
        match self {
            S3Error::Denied(m) => match http(m) {
                Some(_) => "auth_failed".into(),
                None => "refused_address".into(),
            },
            S3Error::NotFound => "bucket_missing".into(),
            S3Error::Transient(m) if m == TLS_FAILED => "tls_error".into(),
            S3Error::Transient(m) => match http(m) {
                Some((status, _)) => format!("http_{status}"),
                None => "unreachable".into(),
            },
            S3Error::Permanent(m) => match http(m) {
                Some((_, Some(code))) if code == "NoSuchBucket" => "bucket_missing".into(),
                Some((status, _)) => format!("http_{status}"),
                None => "request_failed".into(),
            },
        }
    }
}

fn permanent(msg: impl Into<String>) -> S3Error {
    S3Error::Permanent(msg.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Location {
    pub endpoint: Url,
    pub bucket: String,
    pub region: String,
    pub path_style: bool,
}

fn is_bucket(s: &str) -> bool {
    let b = s.as_bytes();
    (3..=63).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-'))
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
}

fn is_region(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

impl S3Location {
    /// Applies the address rule to an endpoint that is an IP literal (a host name is checked when it is
    /// resolved): blocked addresses are refused unless `allow_private` covers them, and plain http needs
    /// an allowed private address.
    pub fn check_literal(&self, allow_private: bool) -> Result<(), S3Error> {
        let ip = self
            .endpoint
            .host_str()
            .unwrap_or_default()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>();
        match ip {
            Ok(ip) => check_ip(
                ip,
                self.endpoint.scheme() == "http",
                allow_private && is_allowed_private_ip(ip),
            ),
            Err(_) => Ok(()),
        }
    }

    /// `endpoint` is `http(s)://host[:port]` with nothing after the authority.
    pub fn parse(
        endpoint: &str,
        bucket: &str,
        region: &str,
        path_style: bool,
    ) -> Result<Self, S3Error> {
        if endpoint.len() > 255 || !endpoint.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(permanent(
                "the endpoint must be at most 255 printable ASCII characters",
            ));
        }
        if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
            return Err(permanent(
                "the endpoint must start with https:// or http://",
            ));
        }
        let url = Url::parse(endpoint).map_err(|_| permanent("the endpoint is not a valid URL"))?;
        if !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(permanent(
                "the endpoint must be scheme://host[:port] with nothing after the host and port",
            ));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(permanent("the endpoint needs a host"));
        }
        if !is_bucket(bucket) {
            return Err(permanent(
                "the bucket name must be 3 to 63 of a-z, 0-9, '.' and '-'",
            ));
        }
        if !is_region(region) {
            return Err(permanent("the region must be 1 to 32 of a-z, 0-9 and '-'"));
        }
        Ok(S3Location {
            endpoint: url,
            bucket: bucket.to_string(),
            region: region.to_string(),
            path_style,
        })
    }
}

#[derive(Clone)]
pub struct S3Keys {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
}

impl fmt::Debug for S3Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Keys")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

pub struct S3Client {
    loc: S3Location,
    keys: S3Keys,
    allow_private: bool,
    /// Lets unit tests talk to a mock server on the loopback interface; does not exist in release builds.
    #[cfg(test)]
    loopback_ok: bool,
}

impl fmt::Debug for S3Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Client")
            .field("endpoint", &self.loc.endpoint.as_str())
            .field("bucket", &self.loc.bucket)
            .field("keys", &self.keys)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutResult {
    pub etag: String,
    pub version_id: Option<String>,
}

/// Where the single-put and multipart thresholds sit; tests shrink them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tuning {
    pub single_max: u64,
    pub min_part: u64,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            single_max: SINGLE_PUT_MAX,
            min_part: MIN_PART_SIZE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartPlan {
    pub part_size: u64,
    pub count: u64,
}

/// Part size `max(16 MiB, ceil(size / 9000))`, and how many parts that makes.
pub fn plan_parts(size: u64) -> Result<PartPlan, S3Error> {
    plan_parts_with(size, MIN_PART_SIZE)
}

pub(crate) fn plan_parts_with(size: u64, min_part: u64) -> Result<PartPlan, S3Error> {
    if size == 0 {
        return Err(permanent("an empty object is not uploaded in parts"));
    }
    let part_size = min_part.max(size.div_ceil(TARGET_PARTS));
    if part_size > MAX_PART_SIZE {
        return Err(permanent("the object is too large for S3"));
    }
    let count = size.div_ceil(part_size);
    debug_assert!(count <= MAX_PARTS);
    Ok(PartPlan { part_size, count })
}

struct Spec<'a> {
    method: Method,
    key: &'a str,
    query: Vec<(&'a str, String)>,
    headers: Vec<(String, String)>,
    body: Bytes,
    timeout: Duration,
}

impl<'a> Spec<'a> {
    fn new(method: Method, key: &'a str, timeout: Duration) -> Self {
        Spec {
            method,
            key,
            query: Vec::new(),
            headers: Vec::new(),
            body: Bytes::new(),
            timeout,
        }
    }
}

struct Reply {
    etag: Option<String>,
    version_id: Option<String>,
    body: String,
}

impl S3Client {
    /// Validates the endpoint against the transport rules; nothing is sent.
    pub fn new(loc: S3Location, keys: S3Keys, allow_private: bool) -> Result<Self, S3Error> {
        Self::new_inner(
            loc,
            keys,
            allow_private,
            #[cfg(test)]
            false,
        )
    }

    /// Test-only constructor that also accepts loopback addresses, for mock servers.
    #[cfg(test)]
    pub(crate) fn new_allowing_loopback(
        loc: S3Location,
        keys: S3Keys,
        allow_private: bool,
    ) -> Result<Self, S3Error> {
        Self::new_inner(loc, keys, allow_private, true)
    }

    fn new_inner(
        loc: S3Location,
        keys: S3Keys,
        allow_private: bool,
        #[cfg(test)] loopback_ok: bool,
    ) -> Result<Self, S3Error> {
        let https = match loc.endpoint.scheme() {
            "https" => true,
            "http" => false,
            _ => return Err(permanent("the endpoint must use http or https")),
        };
        if !https && !allow_private {
            return Err(S3Error::Denied(
                "the endpoint must use https (plain http needs CITE_DATA_S3_ALLOW_PRIVATE=true)"
                    .into(),
            ));
        }
        if !allow_private {
            parse_s3_endpoint(loc.endpoint.as_str().trim_end_matches('/'))
                .map_err(|e| S3Error::Denied(format!("the endpoint is refused: {e}")))?;
        }
        if keys.access_key_id.is_empty()
            || keys.access_key_id.len() > 128
            || !keys.access_key_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(permanent(
                "the access key id must be 1 to 128 printable characters",
            ));
        }
        if keys.secret_access_key.is_empty() || keys.secret_access_key.len() > 256 {
            return Err(permanent(
                "the secret access key must be 1 to 256 characters",
            ));
        }
        let client = S3Client {
            loc,
            keys,
            allow_private,
            #[cfg(test)]
            loopback_ok,
        };
        if let Some(ip) = client.endpoint_ip() {
            client.check_address(ip, !https)?;
        }
        Ok(client)
    }

    /// The endpoint host when it is an IP literal.
    fn endpoint_ip(&self) -> Option<IpAddr> {
        self.endpoint_host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()
    }

    /// Whether `ip` is one of the private ranges the operator opted into with `allow_private`.
    fn private_allowed(&self, ip: IpAddr) -> bool {
        #[cfg(test)]
        if self.loopback_ok && ip.to_canonical().is_loopback() {
            return true;
        }
        self.allow_private && is_allowed_private_ip(ip)
    }

    /// Refuses an address that is blocked and not an allowed private one; plain http needs an allowed
    /// private address.
    fn check_address(&self, ip: IpAddr, plain_http: bool) -> Result<(), S3Error> {
        check_ip(ip, plain_http, self.private_allowed(ip))
    }

    fn endpoint_host(&self) -> &str {
        self.loc.endpoint.host_str().unwrap_or_default()
    }

    fn host_is_ip(&self) -> bool {
        self.endpoint_host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok()
    }

    /// Bucket in the host name, unless path style is asked for. Dotted bucket names would break the
    /// wildcard certificate, and an IP endpoint has no sub-domains, so both use path style.
    fn virtual_hosted(&self) -> bool {
        !self.loc.path_style && !self.loc.bucket.contains('.') && !self.host_is_ip()
    }

    fn request_host(&self) -> String {
        if self.virtual_hosted() {
            format!("{}.{}", self.loc.bucket, self.endpoint_host())
        } else {
            self.endpoint_host().to_string()
        }
    }

    pub(crate) fn object_url(&self, key: &str, query: &[(&str, String)]) -> Result<Url, S3Error> {
        let ep = &self.loc.endpoint;
        let mut url = Url::parse(&format!("{}://{}", ep.scheme(), self.request_host()))
            .map_err(|_| permanent("the endpoint host is not usable"))?;
        if let Some(p) = ep.port() {
            url.set_port(Some(p))
                .map_err(|()| permanent("the endpoint port is not usable"))?;
        }
        {
            let mut segs = url
                .path_segments_mut()
                .map_err(|()| permanent("the endpoint cannot hold a path"))?;
            segs.clear();
            if !self.virtual_hosted() {
                segs.push(&self.loc.bucket);
            }
            segs.extend(key.split('/'));
        }
        if !query.is_empty() {
            let q: Vec<String> = query
                .iter()
                .map(|(k, v)| {
                    if v.is_empty() {
                        percent_encode(k.as_bytes())
                    } else {
                        format!(
                            "{}={}",
                            percent_encode(k.as_bytes()),
                            percent_encode(v.as_bytes())
                        )
                    }
                })
                .collect();
            url.set_query(Some(&q.join("&")));
        }
        Ok(url)
    }

    /// Resolves the request host, refuses blocked addresses (private ones only when allowed, and then only
    /// RFC 1918, ULA and CGNAT) and pins the result.
    async fn client(&self) -> Result<reqwest::Client, S3Error> {
        let host = self.request_host();
        let bare = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = self.loc.endpoint.port_or_known_default().unwrap_or(443);
        let plain_http = self.loc.endpoint.scheme() == "http";
        let mut builder = cite_tls::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(!plain_http)
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent("cite-connector");
        if let Ok(ip) = bare.parse::<IpAddr>() {
            self.check_address(ip, plain_http)?;
        } else {
            let lookup = tokio::time::timeout(
                RESOLVE_TIMEOUT,
                tokio::net::lookup_host((bare.as_str(), port)),
            )
            .await
            .map_err(|_| S3Error::Transient("resolving the endpoint timed out".into()))?
            .map_err(|_| {
                S3Error::Transient("the endpoint host name could not be resolved".into())
            })?;
            let addrs: Vec<SocketAddr> = lookup.collect();
            if addrs.is_empty() {
                return Err(S3Error::Transient(
                    "the endpoint host name has no addresses".into(),
                ));
            }
            for addr in &addrs {
                self.check_address(addr.ip(), plain_http)?;
            }
            builder = builder.resolve_to_addrs(&bare, &addrs);
        }
        builder
            .build()
            .map_err(|_| permanent("the HTTP client could not be built"))
    }

    async fn start(
        &self,
        client: &reqwest::Client,
        spec: &Spec<'_>,
    ) -> Result<reqwest::Response, S3Error> {
        let url = self.object_url(spec.key, &spec.query)?;
        let payload = sha256_hex(&spec.body);
        let mut headers = spec.headers.clone();
        sign_v4(
            spec.method.as_str(),
            &url,
            &mut headers,
            &payload,
            OffsetDateTime::now_utc(),
            &self.loc,
            &self.keys,
        );
        let mut request = client
            .request(spec.method.clone(), url)
            .timeout(spec.timeout);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request
            .body(spec.body.clone())
            .send()
            .await
            .map_err(map_send_error)
    }

    async fn once(&self, client: &reqwest::Client, spec: &Spec<'_>) -> Result<Reply, S3Error> {
        let resp = self.start(client, spec).await?;
        let status = resp.status();
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let etag = header("etag");
        let version_id = header("x-amz-version-id");
        let body = read_capped(resp).await?;
        // CompleteMultipartUpload can answer 200 with an error document.
        if !status.is_success() || body.contains("<Error>") {
            let code = if status.is_success() {
                200
            } else {
                status.as_u16()
            };
            return Err(error_from(code, &body));
        }
        Ok(Reply {
            etag,
            version_id,
            body,
        })
    }

    async fn send(&self, client: &reqwest::Client, spec: &Spec<'_>) -> Result<Reply, S3Error> {
        let mut retries = 0;
        loop {
            match self.once(client, spec).await {
                Err(S3Error::Transient(_)) if retries < RETRY_DELAYS.len() => {
                    tokio::time::sleep(RETRY_DELAYS[retries]).await;
                    retries += 1;
                }
                other => return other,
            }
        }
    }

    async fn put(
        &self,
        client: &reqwest::Client,
        key: &str,
        body: Bytes,
        timeout: Duration,
    ) -> Result<PutResult, S3Error> {
        let mut spec = Spec::new(Method::PUT, key, timeout);
        spec.body = body;
        let reply = self.send(client, &spec).await?;
        Ok(PutResult {
            etag: reply.etag.unwrap_or_default(),
            version_id: reply.version_id,
        })
    }

    /// Puts one byte and deletes it again, proving write and delete rights.
    pub async fn check(&self, probe_key: &str) -> Result<(), S3Error> {
        valid_key(probe_key)?;
        let client = self.client().await?;
        let put = self
            .put(
                &client,
                probe_key,
                Bytes::from_static(b"0"),
                REQUEST_TIMEOUT,
            )
            .await?;
        self.delete_with(&client, probe_key, put.version_id.as_deref())
            .await
    }

    pub async fn upload_file(
        &self,
        key: &str,
        path: &Path,
        size: u64,
    ) -> Result<PutResult, S3Error> {
        self.upload_file_tuned(key, path, size, Tuning::default())
            .await
    }

    pub(crate) async fn upload_file_tuned(
        &self,
        key: &str,
        path: &Path,
        size: u64,
        tuning: Tuning,
    ) -> Result<PutResult, S3Error> {
        valid_key(key)?;
        let meta = tokio::fs::metadata(path)
            .await
            .map_err(|e| permanent(format!("cannot read the file to upload: {}", e.kind())))?;
        if !meta.is_file() || meta.len() != size {
            return Err(permanent("the file to upload is not the expected size"));
        }
        let client = self.client().await?;
        if size <= tuning.single_max {
            let body = read_part(&mut open(path).await?, size).await?;
            return self.put(&client, key, body, PART_TIMEOUT).await;
        }
        let plan = plan_parts_with(size, tuning.min_part)?;
        let upload_id = self.create_multipart(&client, key).await?;
        match self
            .upload_parts(&client, key, path, size, plan, &upload_id)
            .await
        {
            Ok(done) => Ok(done),
            Err(e) => {
                // Best effort: leave no half-finished upload to be billed for.
                let mut abort = Spec::new(Method::DELETE, key, REQUEST_TIMEOUT);
                abort.query.push(("uploadId", upload_id));
                let _ = self.send(&client, &abort).await;
                Err(e)
            }
        }
    }

    async fn create_multipart(
        &self,
        client: &reqwest::Client,
        key: &str,
    ) -> Result<String, S3Error> {
        let mut spec = Spec::new(Method::POST, key, REQUEST_TIMEOUT);
        spec.query.push(("uploads", String::new()));
        let reply = self.send(client, &spec).await?;
        xml_tag(&reply.body, "UploadId")
            .map(xml_unescape)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| permanent("the server did not return an upload id"))
    }

    async fn upload_parts(
        &self,
        client: &reqwest::Client,
        key: &str,
        path: &Path,
        size: u64,
        plan: PartPlan,
        upload_id: &str,
    ) -> Result<PutResult, S3Error> {
        let mut file = open(path).await?;
        let mut etags: Vec<(u64, String)> = Vec::with_capacity(plan.count as usize);
        for number in 1..=plan.count {
            let len = plan.part_size.min(size - (number - 1) * plan.part_size);
            let body = read_part(&mut file, len).await?;
            let mut spec = Spec::new(Method::PUT, key, PART_TIMEOUT);
            spec.query.push(("partNumber", number.to_string()));
            spec.query.push(("uploadId", upload_id.to_string()));
            spec.body = body;
            let reply = self.send(client, &spec).await?;
            let etag = reply.etag.ok_or_else(|| {
                permanent(format!("the server returned no ETag for part {number}"))
            })?;
            etags.push((number, etag));
        }
        let mut spec = Spec::new(Method::POST, key, REQUEST_TIMEOUT);
        spec.query.push(("uploadId", upload_id.to_string()));
        spec.body = Bytes::from(complete_body(&etags));
        let reply = self.send(client, &spec).await?;
        let etag = xml_tag(&reply.body, "ETag")
            .map(xml_unescape)
            .or(reply.etag)
            .unwrap_or_default();
        Ok(PutResult {
            etag,
            version_id: reply.version_id,
        })
    }

    /// Reads an object, or the inclusive byte range `(first, last)`, as a stream.
    pub async fn get_range(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> Result<ByteStream, S3Error> {
        valid_key(key)?;
        let mut spec = Spec::new(Method::GET, key, DOWNLOAD_TIMEOUT);
        if let Some((first, last)) = range {
            if first > last {
                return Err(permanent("the byte range is empty"));
            }
            spec.headers
                .push(("range".into(), format!("bytes={first}-{last}")));
        }
        let client = self.client().await?;
        let resp = self.start(&client, &spec).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = read_capped(resp).await?;
            return Err(error_from(status.as_u16(), &body));
        }
        Ok(Box::pin(resp.bytes_stream().map(|chunk| {
            chunk.map_err(|e| {
                let e = e.without_url();
                S3Error::Transient(if e.is_timeout() {
                    "the download timed out".into()
                } else {
                    "the download was interrupted".into()
                })
            })
        })))
    }

    /// Deletes an object (one version when `version_id` is given). A missing object counts as deleted.
    pub async fn delete(&self, key: &str, version_id: Option<&str>) -> Result<(), S3Error> {
        valid_key(key)?;
        let client = self.client().await?;
        self.delete_with(&client, key, version_id).await
    }

    async fn delete_with(
        &self,
        client: &reqwest::Client,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<(), S3Error> {
        let mut spec = Spec::new(Method::DELETE, key, REQUEST_TIMEOUT);
        if let Some(v) = version_id.filter(|v| !v.is_empty()) {
            spec.query.push(("versionId", v.to_string()));
        }
        match self.send(client, &spec).await {
            Ok(_) | Err(S3Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

async fn open(path: &Path) -> Result<tokio::fs::File, S3Error> {
    tokio::fs::File::open(path)
        .await
        .map_err(|e| permanent(format!("cannot read the file to upload: {}", e.kind())))
}

async fn read_part(file: &mut tokio::fs::File, len: u64) -> Result<Bytes, S3Error> {
    let mut buf = Vec::with_capacity(len as usize);
    let got = file
        .take(len)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| permanent(format!("cannot read the file to upload: {}", e.kind())))?;
    if got as u64 != len {
        return Err(permanent("the file changed while it was being uploaded"));
    }
    Ok(Bytes::from(buf))
}

/// Whether a TLS handshake or certificate problem is in the error's cause chain.
fn is_tls_failure(e: &reqwest::Error) -> bool {
    let mut source = std::error::Error::source(e);
    while let Some(err) = source {
        let text = err.to_string().to_ascii_lowercase();
        if ["certificate", "tls", "handshake", "invalid peer"]
            .iter()
            .any(|w| text.contains(w))
        {
            return true;
        }
        source = std::error::Error::source(err);
    }
    false
}

fn map_send_error(e: reqwest::Error) -> S3Error {
    let e = e.without_url();
    if e.is_builder() {
        permanent("the request could not be built")
    } else if e.is_timeout() {
        S3Error::Transient("the request timed out".into())
    } else if is_tls_failure(&e) {
        S3Error::Transient(TLS_FAILED.into())
    } else if e.is_connect() {
        S3Error::Transient("could not connect to the endpoint".into())
    } else {
        S3Error::Transient("the request failed".into())
    }
}

async fn read_capped(mut resp: reqwest::Response) -> Result<String, S3Error> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| S3Error::Transient("the response was interrupted".into()))?
    {
        let room = ERROR_BODY_CAP - buf.len();
        buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if buf.len() >= ERROR_BODY_CAP {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// ---- errors ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    NotFound,
    Denied,
    Transient,
    Permanent,
}

pub(crate) fn classify(status: u16, code: Option<&str>) -> Class {
    match code {
        Some("NoSuchBucket") => return Class::Permanent,
        Some("NoSuchKey" | "NoSuchUpload") => return Class::NotFound,
        Some("SlowDown" | "RequestTimeout" | "InternalError" | "ServiceUnavailable") => {
            return Class::Transient;
        }
        _ => {}
    }
    match status {
        404 => Class::NotFound,
        401 | 403 => Class::Denied,
        408 | 429 | 500..=599 => Class::Transient,
        _ => Class::Permanent,
    }
}

fn error_from(status: u16, body: &str) -> S3Error {
    let code = xml_tag(body, "Code").map(xml_unescape);
    let message = xml_tag(body, "Message").map(xml_unescape);
    let mut detail = format!("HTTP {status}");
    if let Some(c) = &code {
        detail.push(' ');
        detail.push_str(c);
    }
    if let Some(m) = &message {
        detail.push_str(": ");
        detail.push_str(m);
    }
    let detail: String = detail
        .chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect();
    match classify(status, code.as_deref()) {
        Class::NotFound => S3Error::NotFound,
        Class::Denied => S3Error::Denied(detail),
        Class::Transient => S3Error::Transient(detail),
        Class::Permanent => S3Error::Permanent(detail),
    }
}

// ---- keys ----

fn valid_key(key: &str) -> Result<(), S3Error> {
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY_BYTES
        && key.bytes().all(|b| b.is_ascii_graphic())
        && !key.starts_with('/')
        && !key.ends_with('/')
        && key
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..");
    if ok {
        Ok(())
    } else {
        Err(permanent("the object key is not valid"))
    }
}

/// `<prefix>/<node>/<site>/<db-key>/v<version:06>-<backup-id>.cbk`, where `<db-key>` is `pg-<db>` or `ext-<name>`.
pub fn object_key(
    prefix: &str,
    node: &str,
    site: &str,
    db_key: &str,
    version: u32,
    backup_id: &str,
) -> String {
    format!(
        "{}/{node}/{site}/{}/v{version:06}-{backup_id}.cbk",
        prefix.trim_matches('/'),
        db_key.replace(':', "-")
    )
}

/// `<prefix>/<node>/_shared/<backup-id>/<part>.cbk`
pub fn shared_object_key(prefix: &str, node: &str, backup_id: &str, part: &str) -> String {
    format!(
        "{}/{node}/_shared/{backup_id}/{part}.cbk",
        prefix.trim_matches('/')
    )
}

// ---- XML ----

/// The text of the first `<tag>...</tag>`.
pub(crate) fn xml_tag<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(&body[start..end])
}

pub(crate) fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(crate) fn complete_body(parts: &[(u64, String)]) -> String {
    let mut out = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        out.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag></Part>",
            xml_escape(etag)
        ));
    }
    out.push_str("</CompleteMultipartUpload>");
    out
}

// ---- SigV4 ----

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

fn amz_date(now: OffsetDateTime) -> String {
    let t = now.to_offset(UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// RFC 3986 encoding of every segment of the decoded path; slashes stay.
fn canonical_uri(url: &Url) -> String {
    url.path()
        .split('/')
        .map(|seg| match percent_decode(seg) {
            Some(raw) => percent_encode(&raw),
            None => percent_encode(seg.as_bytes()),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn canonical_query(url: &Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (percent_encode(k.as_bytes()), percent_encode(v.as_bytes())))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

fn collapse(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Signed header names and the hex signature for one request. `signed` holds every header to sign,
/// including `host`, with lowercase names.
#[allow(clippy::too_many_arguments)]
pub(crate) fn signature_for(
    service: &str,
    region: &str,
    secret: &str,
    method: &str,
    url: &Url,
    signed: &[(String, String)],
    payload_sha256: &str,
    amz_date: &str,
) -> (String, String) {
    let mut headers: Vec<(String, String)> = signed
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), collapse(v)))
        .collect();
    headers.sort();
    let names = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let canonical_request = format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{names}\n{payload_sha256}",
        canonical_uri(url),
        canonical_query(url),
    );
    let day = &amz_date[..8];
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let seed = Zeroizing::new(format!("AWS4{secret}"));
    let k_date = Zeroizing::new(hmac_sha256(seed.as_bytes(), day.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(&k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(&k_region, service.as_bytes()));
    let k_signing = Zeroizing::new(hmac_sha256(&k_service, b"aws4_request"));
    (names, hex(&hmac_sha256(&k_signing, to_sign.as_bytes())))
}

/// Adds `x-amz-date`, `x-amz-content-sha256` and `authorization` to `headers` (lowercase names). Every
/// header already in the list is signed, together with `host`.
pub(crate) fn sign_v4(
    method: &str,
    url: &Url,
    headers: &mut Vec<(String, String)>,
    payload_sha256: &str,
    now: OffsetDateTime,
    loc: &S3Location,
    keys: &S3Keys,
) {
    const OWN: [&str; 4] = [
        "host",
        "x-amz-date",
        "x-amz-content-sha256",
        "authorization",
    ];
    for h in headers.iter_mut() {
        h.0 = h.0.to_ascii_lowercase();
    }
    headers.retain(|(k, _)| !OWN.contains(&k.as_str()));
    let date = amz_date(now);
    headers.push(("x-amz-date".into(), date.clone()));
    headers.push(("x-amz-content-sha256".into(), payload_sha256.to_string()));
    let mut signed = headers.clone();
    signed.push(("host".into(), host_header(url)));
    let (names, signature) = signature_for(
        "s3",
        &loc.region,
        &keys.secret_access_key,
        method,
        url,
        &signed,
        payload_sha256,
        &date,
    );
    headers.push((
        "authorization".into(),
        format!(
            "{ALGORITHM} Credential={}/{}/{}/s3/aws4_request, SignedHeaders={names}, Signature={signature}",
            keys.access_key_id,
            &date[..8],
            loc.region
        ),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use time::{Date, Month};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn at(y: i32, m: Month, d: u8, h: u8, mi: u8, s: u8) -> OffsetDateTime {
        Date::from_calendar_date(y, m, d)
            .unwrap()
            .with_hms(h, mi, s)
            .unwrap()
            .assume_utc()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn suite(method: &str, url: &str, payload: &str) -> String {
        let url = Url::parse(url).unwrap();
        let headers = pairs(&[
            ("host", "example.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ]);
        let (names, sig) = signature_for(
            "service",
            "us-east-1",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            method,
            &url,
            &headers,
            payload,
            "20150830T123600Z",
        );
        assert_eq!(names, "host;x-amz-date");
        sig
    }

    #[test]
    fn aws_sigv4_suite_vectors() {
        assert_eq!(
            suite("GET", "http://example.amazonaws.com/", EMPTY),
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert_eq!(
            suite(
                "GET",
                "http://example.amazonaws.com/?Param2=value2&Param1=value1",
                EMPTY
            ),
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
        assert_eq!(
            suite("GET", "http://example.amazonaws.com/?Param1=value1", EMPTY),
            "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"
        );
        assert_eq!(
            suite("POST", "http://example.amazonaws.com/", EMPTY),
            "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
        );
    }

    fn doc_loc() -> (S3Location, S3Keys) {
        (
            S3Location::parse(
                "https://examplebucket.s3.amazonaws.com",
                "examplebucket",
                "us-east-1",
                false,
            )
            .unwrap(),
            S3Keys {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                secret_access_key: Zeroizing::new(
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
                ),
            },
        )
    }

    fn signed_header(headers: &[(String, String)], name: &str) -> String {
        headers.iter().find(|(k, _)| k == name).unwrap().1.clone()
    }

    #[test]
    fn aws_s3_documentation_vectors() {
        let (loc, keys) = doc_loc();
        let now = at(2013, Month::May, 24, 0, 0, 0);

        let mut get = pairs(&[("range", "bytes=0-9")]);
        sign_v4(
            "GET",
            &Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap(),
            &mut get,
            EMPTY,
            now,
            &loc,
            &keys,
        );
        let auth = signed_header(&get, "authorization");
        assert!(
            auth.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"),
            "{auth}"
        );
        assert!(
            auth.contains(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "{auth}"
        );
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"
        ));
        assert_eq!(signed_header(&get, "x-amz-date"), "20130524T000000Z");

        let mut put = pairs(&[
            ("date", "Fri, 24 May 2013 00:00:00 GMT"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ]);
        let payload = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(
            payload,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        sign_v4(
            "PUT",
            &Url::parse("https://examplebucket.s3.amazonaws.com/test%24file.text").unwrap(),
            &mut put,
            &payload,
            now,
            &loc,
            &keys,
        );
        let auth = signed_header(&put, "authorization");
        assert!(
            auth.contains(
                "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"
            ),
            "{auth}"
        );
        assert!(
            auth.contains(
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            ),
            "{auth}"
        );

        let mut lifecycle = Vec::new();
        sign_v4(
            "GET",
            &Url::parse("https://examplebucket.s3.amazonaws.com/?lifecycle").unwrap(),
            &mut lifecycle,
            EMPTY,
            now,
            &loc,
            &keys,
        );
        assert!(signed_header(&lifecycle, "authorization").contains(
            "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        ));

        let mut list = Vec::new();
        sign_v4(
            "GET",
            &Url::parse("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J").unwrap(),
            &mut list,
            EMPTY,
            now,
            &loc,
            &keys,
        );
        assert!(signed_header(&list, "authorization").contains(
            "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        ));
    }

    #[test]
    fn signing_is_deterministic_and_replaces_stale_auth_headers() {
        let (loc, keys) = doc_loc();
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/a").unwrap();
        let now = at(2026, Month::November, 20, 3, 17, 5);
        let mut a = pairs(&[("Authorization", "stale"), ("X-Amz-Date", "stale")]);
        let mut b = Vec::new();
        sign_v4("GET", &url, &mut a, EMPTY, now, &loc, &keys);
        sign_v4("GET", &url, &mut b, EMPTY, now, &loc, &keys);
        assert_eq!(
            signed_header(&a, "authorization"),
            signed_header(&b, "authorization")
        );
        assert_eq!(a.iter().filter(|(k, _)| k == "authorization").count(), 1);
        assert_eq!(signed_header(&a, "x-amz-date"), "20261120T031705Z");
        let later = at(2026, Month::November, 20, 3, 17, 6);
        let mut c = Vec::new();
        sign_v4("GET", &url, &mut c, EMPTY, later, &loc, &keys);
        assert_ne!(
            signed_header(&a, "authorization"),
            signed_header(&c, "authorization")
        );
    }

    #[test]
    fn a_non_default_port_is_part_of_the_signed_host() {
        let url = Url::parse("http://127.0.0.1:9000/b/k").unwrap();
        assert_eq!(host_header(&url), "127.0.0.1:9000");
        assert_eq!(
            host_header(&Url::parse("https://s3.example.com/k").unwrap()),
            "s3.example.com"
        );
    }

    #[test]
    fn uri_encoding_is_rfc3986_per_segment() {
        let u = Url::parse("https://h.example.com/a%20b/c~d/e$f/%E2%82%AC").unwrap();
        assert_eq!(canonical_uri(&u), "/a%20b/c~d/e%24f/%E2%82%AC");
        assert_eq!(
            canonical_uri(&Url::parse("https://h.example.com/").unwrap()),
            "/"
        );
        let q = Url::parse("https://h.example.com/?b=2&a=1&a=0&c").unwrap();
        assert_eq!(canonical_query(&q), "a=0&a=1&b=2&c=");
        let q = Url::parse("https://h.example.com/?uploadId=UP%261&partNumber=1").unwrap();
        assert_eq!(canonical_query(&q), "partNumber=1&uploadId=UP%261");
    }

    #[test]
    fn amz_date_is_utc() {
        let t = OffsetDateTime::from_unix_timestamp(1_369_353_600).unwrap();
        assert_eq!(amz_date(t), "20130524T000000Z");
        let offset = t.to_offset(UtcOffset::from_hms(5, 30, 0).unwrap());
        assert_eq!(amz_date(offset), "20130524T000000Z");
    }

    #[test]
    fn part_planning() {
        let mib = 1024 * 1024;
        let p = plan_parts(100 * mib).unwrap();
        assert_eq!((p.part_size, p.count), (16 * mib, 7));
        let exact = plan_parts(32 * mib).unwrap();
        assert_eq!((exact.part_size, exact.count), (16 * mib, 2));
        let one = plan_parts(1).unwrap();
        assert_eq!((one.part_size, one.count), (16 * mib, 1));
        // 1 TiB: ceil(size / 9000) exceeds 16 MiB, so parts grow and the count stays at most 9000.
        let tib = 1024 * 1024 * mib;
        let big = plan_parts(tib).unwrap();
        assert_eq!(big.part_size, tib.div_ceil(9000));
        assert!(big.count <= 9000 && big.count * big.part_size >= tib);
        for size in [1, mib, 64 * mib + 1, 300 * mib, 150_000 * mib, 4 * tib] {
            let p = plan_parts(size).unwrap();
            assert!(
                p.count <= MAX_PARTS && p.part_size >= MIN_PART_SIZE,
                "{size}"
            );
            assert!(
                (p.count - 1) * p.part_size < size && p.count * p.part_size >= size,
                "{size}"
            );
        }
        assert!(plan_parts(0).is_err());
        assert!(plan_parts(u64::MAX).is_err());
    }

    #[test]
    fn xml_helpers() {
        let body =
            "<R><UploadId>a&amp;b</UploadId><ETag>&quot;abc&quot;</ETag><Code>SlowDown</Code></R>";
        assert_eq!(xml_tag(body, "UploadId"), Some("a&amp;b"));
        assert_eq!(xml_unescape(xml_tag(body, "UploadId").unwrap()), "a&b");
        assert_eq!(xml_unescape(xml_tag(body, "ETag").unwrap()), "\"abc\"");
        assert_eq!(xml_tag(body, "Missing"), None);
        assert_eq!(xml_tag("<A>unterminated", "A"), None);
        assert_eq!(xml_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
        assert_eq!(xml_unescape("&lt;&amp;lt;&gt;"), "<&lt;>");
        assert_eq!(
            complete_body(&[(1, "\"e1\"".into()), (2, "\"e2\"".into())]),
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"e2\"</ETag></Part></CompleteMultipartUpload>"
        );
    }

    #[test]
    fn error_classification() {
        assert_eq!(classify(404, None), Class::NotFound);
        assert_eq!(classify(404, Some("NoSuchBucket")), Class::Permanent);
        assert_eq!(classify(404, Some("NoSuchKey")), Class::NotFound);
        assert_eq!(classify(403, Some("AccessDenied")), Class::Denied);
        assert_eq!(classify(401, None), Class::Denied);
        assert_eq!(classify(503, Some("SlowDown")), Class::Transient);
        assert_eq!(classify(500, None), Class::Transient);
        assert_eq!(classify(502, None), Class::Transient);
        assert_eq!(classify(429, None), Class::Transient);
        assert_eq!(classify(408, None), Class::Transient);
        assert_eq!(classify(200, Some("InternalError")), Class::Transient);
        assert_eq!(classify(400, Some("InvalidPart")), Class::Permanent);
        assert_eq!(classify(409, None), Class::Permanent);
        assert_eq!(classify(200, Some("MalformedXML")), Class::Permanent);
        match error_from(
            403,
            "<Error><Code>AccessDenied</Code><Message>no\nway</Message></Error>",
        ) {
            S3Error::Denied(m) => assert_eq!(m, "HTTP 403 AccessDenied: noway"),
            other => panic!("{other:?}"),
        }
        assert_eq!(error_from(404, ""), S3Error::NotFound);
    }

    #[test]
    fn object_keys() {
        assert_eq!(
            object_key("/cite/", "node1", "shop", "pg:app", 13, "01J0A"),
            "cite/node1/shop/pg-app/v000013-01J0A.cbk"
        );
        assert_eq!(
            object_key("cite", "node1", "shop", "ext:billing", 1, "01J0B"),
            "cite/node1/shop/ext-billing/v000001-01J0B.cbk"
        );
        assert_eq!(
            shared_object_key("cite", "n", "b1", "globals"),
            "cite/n/_shared/b1/globals.cbk"
        );
        for key in ["cite/n/s/pg-app/v000001-x.cbk", "a", "a/b.c_d-e"] {
            assert!(valid_key(key).is_ok(), "{key}");
        }
        let long = "k".repeat(1025);
        for key in [
            "",
            "/a",
            "a/",
            "a//b",
            "a/../b",
            "./a",
            "a b",
            "a\nb",
            long.as_str(),
        ] {
            assert!(valid_key(key).is_err(), "{key:?}");
        }
    }

    fn keys() -> S3Keys {
        S3Keys {
            access_key_id: "AKID".into(),
            secret_access_key: Zeroizing::new("topsecret".into()),
        }
    }

    #[test]
    fn construction_enforces_the_transport_rules() {
        let https =
            S3Location::parse("https://s3.example.com", "bucket", "eu-west-1", false).unwrap();
        assert!(S3Client::new(https, keys(), false).is_ok());

        let http =
            S3Location::parse("http://s3.example.com", "bucket", "eu-west-1", false).unwrap();
        assert!(matches!(
            S3Client::new(http.clone(), keys(), false),
            Err(S3Error::Denied(_))
        ));
        assert!(S3Client::new(http, keys(), true).is_ok());

        let private = S3Location::parse("https://10.0.0.5:9000", "bucket", "eu", true).unwrap();
        assert!(matches!(
            S3Client::new(private.clone(), keys(), false),
            Err(S3Error::Denied(_))
        ));
        assert!(S3Client::new(private, keys(), true).is_ok());

        let local = S3Location::parse("https://localhost", "bucket", "eu", true).unwrap();
        assert!(matches!(
            S3Client::new(local, keys(), false),
            Err(S3Error::Denied(_))
        ));

        let ok = S3Location::parse("https://s3.example.com", "bucket", "eu", false).unwrap();
        let empty = S3Keys {
            access_key_id: String::new(),
            secret_access_key: Zeroizing::new("x".into()),
        };
        assert!(S3Client::new(ok.clone(), empty, false).is_err());
        let no_secret = S3Keys {
            access_key_id: "A".into(),
            secret_access_key: Zeroizing::new(String::new()),
        };
        assert!(S3Client::new(ok, no_secret, false).is_err());
    }

    fn literal_client(scheme: &str, host: &str, allow_private: bool) -> Result<S3Client, S3Error> {
        let loc =
            S3Location::parse(&format!("{scheme}://{host}:9000"), "bucket", "eu", true).unwrap();
        S3Client::new(loc, keys(), allow_private)
    }

    const BLOCKED_LITERALS: [&str; 14] = [
        "169.254.169.254",
        "169.254.1.1",
        "127.0.0.1",
        "127.1.2.3",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "240.0.0.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[::ffff:169.254.169.254]",
        "[fe80::1]",
        "[ff02::1]",
    ];

    const PRIVATE_LITERALS: [&str; 8] = [
        "10.0.0.5",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.10",
        "100.64.0.1",
        "100.127.255.254",
        "[fd00::1]",
        "[::ffff:192.168.1.10]",
    ];

    #[test]
    fn blocked_literals_are_refused_with_the_flag_on_and_off() {
        for host in BLOCKED_LITERALS {
            for scheme in ["https", "http"] {
                for allow in [false, true] {
                    assert!(
                        matches!(literal_client(scheme, host, allow), Err(S3Error::Denied(_))),
                        "{scheme}://{host} allow_private={allow}"
                    );
                }
            }
        }
    }

    #[test]
    fn private_literals_need_the_flag_and_http_needs_a_private_literal() {
        for host in PRIVATE_LITERALS {
            for scheme in ["https", "http"] {
                assert!(
                    matches!(literal_client(scheme, host, false), Err(S3Error::Denied(_))),
                    "{scheme}://{host} without the flag"
                );
                assert!(
                    literal_client(scheme, host, true).is_ok(),
                    "{scheme}://{host} with the flag"
                );
            }
        }
        for host in ["8.8.8.8", "[2606:4700::1111]"] {
            assert!(literal_client("https", host, true).is_ok(), "{host}");
            assert!(
                matches!(literal_client("http", host, true), Err(S3Error::Denied(_))),
                "http://{host}"
            );
        }
    }

    #[test]
    fn the_allowed_private_set_is_only_rfc1918_ula_and_cgnat() {
        for host in PRIVATE_LITERALS {
            let ip: IpAddr = host.trim_matches(['[', ']']).parse().unwrap();
            assert!(is_allowed_private_ip(ip), "{host}");
            assert!(address_permitted(ip, true), "{host}");
            assert!(!address_permitted(ip, false), "{host}");
        }
        for host in BLOCKED_LITERALS {
            let ip: IpAddr = host.trim_matches(['[', ']']).parse().unwrap();
            assert!(!is_allowed_private_ip(ip), "{host}");
            assert!(!address_permitted(ip, true), "{host}");
            assert!(!address_permitted(ip, false), "{host}");
        }
        for host in [
            "172.15.0.1",
            "172.32.0.1",
            "100.63.0.1",
            "100.128.0.1",
            "8.8.8.8",
        ] {
            let ip: IpAddr = host.parse().unwrap();
            assert!(!is_allowed_private_ip(ip), "{host}");
        }
    }

    #[tokio::test]
    async fn the_pinning_path_refuses_blocked_addresses_and_loopback_names() {
        for host in [
            "169.254.169.254",
            "127.0.0.1",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "[fe80::1]",
        ] {
            // Build without the constructor check so the resolve-and-pin path is exercised on its own.
            let loc =
                S3Location::parse(&format!("https://{host}:9000"), "bucket", "eu", true).unwrap();
            let client = S3Client {
                loc,
                keys: keys(),
                allow_private: true,
                loopback_ok: false,
            };
            assert!(
                matches!(client.client().await, Err(S3Error::Denied(_))),
                "{host}"
            );
        }
        let loc = S3Location::parse("https://localhost:9000", "bucket", "eu", true).unwrap();
        let client = S3Client::new(loc, keys(), true).unwrap();
        assert!(matches!(client.client().await, Err(S3Error::Denied(_))));
    }

    #[tokio::test]
    async fn the_pinning_path_accepts_allowed_private_literals() {
        for host in ["10.0.0.5", "[fd00::1]", "100.64.0.1"] {
            let client = literal_client("http", host, true).unwrap();
            assert!(client.client().await.is_ok(), "{host}");
        }
    }

    #[test]
    fn outcomes_are_fixed_words_without_server_text() {
        let secret = "internal-host.corp password=hunter2";
        let denied = error_from(
            403,
            &format!("<Error><Code>AccessDenied</Code><Message>{secret}</Message></Error>"),
        );
        assert_eq!(denied.outcome(), "auth_failed");
        let missing = error_from(
            404,
            &format!("<Error><Code>NoSuchBucket</Code><Message>{secret}</Message></Error>"),
        );
        assert_eq!(missing.outcome(), "bucket_missing");
        assert_eq!(error_from(404, "").outcome(), "bucket_missing");
        let bad = error_from(
            400,
            &format!("<Error><Code>Weird</Code><Message>{secret}</Message></Error>"),
        );
        assert_eq!(bad.outcome(), "http_400");
        assert_eq!(
            error_from(503, "<Code>SlowDown</Code>").outcome(),
            "http_503"
        );
        assert_eq!(
            S3Error::Transient("could not connect to the endpoint".into()).outcome(),
            "unreachable"
        );
        assert_eq!(S3Error::Transient(TLS_FAILED.into()).outcome(), "tls_error");
        assert_eq!(
            S3Error::Denied(ADDRESS_REFUSED.into()).outcome(),
            "refused_address"
        );
        assert_eq!(
            S3Error::Denied(HTTP_PUBLIC_REFUSED.into()).outcome(),
            "refused_address"
        );
        for e in [&denied, &missing, &bad] {
            let o = e.outcome();
            assert!(
                !o.contains("hunter2") && !o.contains("internal-host"),
                "{o}"
            );
        }
    }

    #[test]
    fn location_parsing_refuses_malformed_input() {
        for endpoint in [
            "ftp://s3.example.com",
            "s3.example.com",
            "https://user:pw@s3.example.com",
            "https://s3.example.com/path",
            "https://s3.example.com/?x=1",
            "https://s3.example.com/#f",
            "https://",
        ] {
            assert!(
                S3Location::parse(endpoint, "bucket", "eu", false).is_err(),
                "{endpoint}"
            );
        }
        assert!(S3Location::parse("https://s3.example.com/", "bucket", "eu", false).is_ok());
        let long_bucket = "b".repeat(64);
        for bucket in ["ab", "UPPER", "-bad", "bad-", "a_b_c", long_bucket.as_str()] {
            assert!(
                S3Location::parse("https://s3.example.com", bucket, "eu", false).is_err(),
                "{bucket}"
            );
        }
        let long_region = "r".repeat(33);
        for region in ["", "EU", "eu_west", long_region.as_str()] {
            assert!(
                S3Location::parse("https://s3.example.com", "bucket", region, false).is_err(),
                "{region}"
            );
        }
    }

    #[test]
    fn urls_use_virtual_hosts_unless_path_style_dots_or_an_ip_say_otherwise() {
        let build = |endpoint: &str, bucket: &str, path_style: bool| {
            let loc = S3Location::parse(endpoint, bucket, "eu", path_style).unwrap();
            let client = S3Client::new_allowing_loopback(loc, keys(), true).unwrap();
            client
                .object_url(
                    "cite/n/s/pg-app/v000001-x.cbk",
                    &[("partNumber", "2".into()), ("uploadId", "a b&c".into())],
                )
                .unwrap()
                .to_string()
        };
        assert_eq!(
            build("https://s3.example.com", "bucket", false),
            "https://bucket.s3.example.com/cite/n/s/pg-app/v000001-x.cbk?partNumber=2&uploadId=a%20b%26c"
        );
        assert_eq!(
            build("https://s3.example.com:8443", "bucket", true),
            "https://s3.example.com:8443/bucket/cite/n/s/pg-app/v000001-x.cbk?partNumber=2&uploadId=a%20b%26c"
        );
        assert!(
            build("https://s3.example.com", "my.bucket", false)
                .starts_with("https://s3.example.com/my.bucket/cite/")
        );
        assert!(
            build("http://127.0.0.1:9000", "bucket", false)
                .starts_with("http://127.0.0.1:9000/bucket/cite/")
        );
        assert!(
            build("http://[::1]:9000", "bucket", false)
                .starts_with("http://[::1]:9000/bucket/cite/")
        );
        let loc = S3Location::parse("https://s3.example.com", "bucket", "eu", false).unwrap();
        let client = S3Client::new(loc, keys(), false).unwrap();
        assert_eq!(
            client
                .object_url("k", &[("uploads", String::new())])
                .unwrap()
                .query(),
            Some("uploads")
        );
    }

    #[test]
    fn debug_output_hides_keys() {
        let loc = S3Location::parse("https://s3.example.com", "bucket", "eu", false).unwrap();
        let client = S3Client::new(loc, keys(), false).unwrap();
        let shown = format!("{client:?} {:?}", keys());
        assert!(
            !shown.contains("topsecret") && !shown.contains("AKID"),
            "{shown}"
        );
    }

    // ---- a small HTTP server standing in for S3 ----

    #[derive(Debug, Clone)]
    struct Logged {
        line: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Logged {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        }
    }

    #[derive(Clone, Copy, Default)]
    struct Mode {
        fail_part: Option<u64>,
        deny: bool,
    }

    struct Mock {
        port: u16,
        log: Arc<Mutex<Vec<Logged>>>,
    }

    impl Mock {
        fn lines(&self) -> Vec<String> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|l| l.line.clone())
                .collect()
        }
        fn entries(&self) -> Vec<Logged> {
            self.log.lock().unwrap().clone()
        }
    }

    async fn mock(mode: Mode) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log: Arc<Mutex<Vec<Logged>>> = Arc::default();
        let shared = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(sock, shared.clone(), mode));
            }
        });
        Mock { port, log }
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    async fn serve(mut sock: TcpStream, log: Arc<Mutex<Vec<Logged>>>, mode: Mode) {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let head_end = loop {
                if let Some(p) = find(&buf, b"\r\n\r\n") {
                    break p;
                }
                let mut tmp = [0u8; 4096];
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let mut lines = head.split("\r\n");
            let line = lines.next().unwrap_or_default().to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect();
            let len: usize = headers
                .iter()
                .find(|(k, _)| k == "content-length")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let total = head_end + 4 + len;
            while buf.len() < total {
                let mut tmp = [0u8; 65536];
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let body = buf[head_end + 4..total].to_vec();
            buf.drain(..total);
            let range = headers
                .iter()
                .find(|(k, _)| k == "range")
                .map(|(_, v)| v.clone());
            log.lock().unwrap().push(Logged {
                line: line.clone(),
                headers,
                body,
            });

            let (status, extra, payload) = respond(&line, range.as_deref(), mode);
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}\r\n",
                payload.len()
            );
            if sock.write_all(reply.as_bytes()).await.is_err()
                || sock.write_all(payload.as_bytes()).await.is_err()
            {
                return;
            }
        }
    }

    fn respond(line: &str, range: Option<&str>, mode: Mode) -> (&'static str, String, String) {
        if mode.deny {
            return (
                "403 Forbidden",
                String::new(),
                "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>".into(),
            );
        }
        let method = line.split(' ').next().unwrap_or_default();
        if method == "POST" && line.contains("?uploads ") {
            return (
                "200 OK",
                String::new(),
                "<InitiateMultipartUploadResult><UploadId>UP&amp;1</UploadId></InitiateMultipartUploadResult>".into(),
            );
        }
        if method == "PUT" && line.contains("partNumber=") {
            let number: u64 = line
                .split("partNumber=")
                .nth(1)
                .and_then(|r| r.split('&').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            if mode.fail_part == Some(number) {
                return (
                    "400 Bad Request",
                    String::new(),
                    "<Error><Code>InvalidPart</Code><Message>bad part</Message></Error>".into(),
                );
            }
            return (
                "200 OK",
                format!("ETag: \"etag-{number}\"\r\n"),
                String::new(),
            );
        }
        if method == "POST" && line.contains("uploadId=") {
            return (
                "200 OK",
                "x-amz-version-id: v-1\r\n".into(),
                "<CompleteMultipartUploadResult><ETag>&quot;final&quot;</ETag></CompleteMultipartUploadResult>".into(),
            );
        }
        match method {
            "PUT" => (
                "200 OK",
                "ETag: \"put-etag\"\r\nx-amz-version-id: ver9\r\n".into(),
                String::new(),
            ),
            "DELETE" => ("204 No Content", String::new(), String::new()),
            "GET" => {
                let all = "0123456789";
                match range
                    .and_then(|r| r.strip_prefix("bytes="))
                    .and_then(|r| r.split_once('-'))
                {
                    Some((a, b)) => {
                        let (a, b): (usize, usize) =
                            (a.parse().unwrap_or(0), b.parse().unwrap_or(9));
                        (
                            "206 Partial Content",
                            String::new(),
                            all[a..=b.min(9)].to_string(),
                        )
                    }
                    None => ("200 OK", String::new(), all.to_string()),
                }
            }
            _ => ("400 Bad Request", String::new(), String::new()),
        }
    }

    fn client_for(mock: &Mock) -> S3Client {
        let loc = S3Location::parse(
            &format!("http://127.0.0.1:{}", mock.port),
            "bkt",
            "us-east-1",
            false,
        )
        .unwrap();
        S3Client::new_allowing_loopback(loc, keys(), true).unwrap()
    }

    fn file_with(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.cbk");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn small_files_go_in_one_signed_put() {
        let mock = mock(Mode::default()).await;
        let client = client_for(&mock);
        let (_dir, path) = file_with(b"hello");
        let out = client.upload_file("pre/obj.cbk", &path, 5).await.unwrap();
        assert_eq!(
            out,
            PutResult {
                etag: "\"put-etag\"".into(),
                version_id: Some("ver9".into())
            }
        );
        assert_eq!(mock.lines(), ["PUT /bkt/pre/obj.cbk HTTP/1.1"]);
        let sent = &mock.entries()[0];
        assert_eq!(sent.body, b"hello");
        assert_eq!(
            sent.header("x-amz-content-sha256"),
            Some(sha256_hex(b"hello").as_str())
        );
        let auth = sent.header("authorization").unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"),
            "{auth}"
        );
        assert!(
            auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
            "{auth}"
        );
        assert!(!auth.contains("topsecret"));
    }

    #[tokio::test]
    async fn large_files_use_multipart_in_order_and_complete_with_the_etags() {
        let mock = mock(Mode::default()).await;
        let client = client_for(&mock);
        let data: Vec<u8> = (0..20u8).collect();
        let (_dir, path) = file_with(&data);
        let tuning = Tuning {
            single_max: 10,
            min_part: 8,
        };
        let out = client
            .upload_file_tuned("pre/obj.cbk", &path, 20, tuning)
            .await
            .unwrap();
        assert_eq!(
            out,
            PutResult {
                etag: "\"final\"".into(),
                version_id: Some("v-1".into())
            }
        );
        assert_eq!(
            mock.lines(),
            [
                "POST /bkt/pre/obj.cbk?uploads HTTP/1.1",
                "PUT /bkt/pre/obj.cbk?partNumber=1&uploadId=UP%261 HTTP/1.1",
                "PUT /bkt/pre/obj.cbk?partNumber=2&uploadId=UP%261 HTTP/1.1",
                "PUT /bkt/pre/obj.cbk?partNumber=3&uploadId=UP%261 HTTP/1.1",
                "POST /bkt/pre/obj.cbk?uploadId=UP%261 HTTP/1.1",
            ]
        );
        let entries = mock.entries();
        assert_eq!(entries[1].body, &data[..8]);
        assert_eq!(entries[2].body, &data[8..16]);
        assert_eq!(entries[3].body, &data[16..]);
        let complete = String::from_utf8(entries[4].body.clone()).unwrap();
        let first = complete
            .find("<PartNumber>1</PartNumber><ETag>\"etag-1\"</ETag>")
            .unwrap();
        let second = complete
            .find("<PartNumber>2</PartNumber><ETag>\"etag-2\"</ETag>")
            .unwrap();
        let third = complete
            .find("<PartNumber>3</PartNumber><ETag>\"etag-3\"</ETag>")
            .unwrap();
        assert!(first < second && second < third);
        assert!(entries.iter().all(|e| e.header("authorization").is_some()));
    }

    #[tokio::test]
    async fn a_failed_part_aborts_the_upload() {
        let mock = mock(Mode {
            fail_part: Some(2),
            deny: false,
        })
        .await;
        let client = client_for(&mock);
        let (_dir, path) = file_with(&[7u8; 20]);
        let tuning = Tuning {
            single_max: 10,
            min_part: 8,
        };
        let err = client
            .upload_file_tuned("pre/obj.cbk", &path, 20, tuning)
            .await
            .unwrap_err();
        match err {
            S3Error::Permanent(m) => assert!(m.contains("InvalidPart"), "{m}"),
            other => panic!("{other:?}"),
        }
        let lines = mock.lines();
        assert_eq!(
            lines.last().unwrap(),
            "DELETE /bkt/pre/obj.cbk?uploadId=UP%261 HTTP/1.1"
        );
        assert!(
            !lines.iter().any(|l| l.contains("partNumber=3")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_file_of_the_wrong_size_is_refused_before_any_request() {
        let mock = mock(Mode::default()).await;
        let client = client_for(&mock);
        let (_dir, path) = file_with(b"hello");
        assert!(client.upload_file("k", &path, 6).await.is_err());
        assert!(client.upload_file("../k", &path, 5).await.is_err());
        assert!(mock.lines().is_empty());
    }

    #[tokio::test]
    async fn check_puts_then_deletes_the_exact_version() {
        let mock = mock(Mode::default()).await;
        client_for(&mock).check("pre/.cite-probe").await.unwrap();
        assert_eq!(
            mock.lines(),
            [
                "PUT /bkt/pre/.cite-probe HTTP/1.1",
                "DELETE /bkt/pre/.cite-probe?versionId=ver9 HTTP/1.1",
            ]
        );
        assert_eq!(mock.entries()[0].body, b"0");
    }

    #[tokio::test]
    async fn delete_sends_the_version_and_credentials_errors_are_denied() {
        let ok = mock(Mode::default()).await;
        client_for(&ok)
            .delete("pre/obj.cbk", Some("abc"))
            .await
            .unwrap();
        client_for(&ok).delete("pre/obj.cbk", None).await.unwrap();
        assert_eq!(
            ok.lines(),
            [
                "DELETE /bkt/pre/obj.cbk?versionId=abc HTTP/1.1",
                "DELETE /bkt/pre/obj.cbk HTTP/1.1",
            ]
        );
        let denied = mock(Mode {
            fail_part: None,
            deny: true,
        })
        .await;
        let c = client_for(&denied);
        match c.check("pre/.p").await.unwrap_err() {
            S3Error::Denied(m) => assert!(m.contains("AccessDenied"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            c.check("pre/.p").await.unwrap_err().outcome(),
            "auth_failed"
        );
        assert!(matches!(
            c.delete("pre/obj.cbk", None).await,
            Err(S3Error::Denied(_))
        ));
        assert!(matches!(
            c.upload_file("k", &file_with(b"x").1, 1).await,
            Err(S3Error::Denied(_))
        ));
    }

    #[tokio::test]
    async fn get_range_sends_an_inclusive_range_and_streams_the_body() {
        let mock = mock(Mode::default()).await;
        let client = client_for(&mock);
        let mut stream = client.get_range("pre/obj.cbk", Some((2, 5))).await.unwrap();
        let mut got = Vec::new();
        while let Some(chunk) = stream.next().await {
            got.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(got, b"2345");
        assert_eq!(mock.entries()[0].header("range"), Some("bytes=2-5"));
        assert!(
            mock.entries()[0]
                .header("authorization")
                .unwrap()
                .contains("SignedHeaders=host;range;")
        );
        let mut whole = client.get_range("pre/obj.cbk", None).await.unwrap();
        let mut all = Vec::new();
        while let Some(chunk) = whole.next().await {
            all.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(all, b"0123456789");
        assert!(client.get_range("k", Some((5, 2))).await.is_err());
    }
}
