//! Node alerts; secrets (webhook URLs, the SMTP password) live only in `alerts.json` and memory, and logs name targets by id.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use cite_core::atomic::write_atomic_in;
use cite_core::confined::{FileName, TrustedDir};
use cite_edge::alerts::{
    AlertEvent, AlertPayload, AlertSettings, EMAIL_TARGET, EmailSettings, SettingsView, Target,
    TlsMode, Webhook, is_blocked_ip, parse_https_url, truncate_chars,
};
use cite_edge::model::{DeployAction, Site};
use cite_edge::status::SiteStatus;
use futures_util::future::BoxFuture;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::certs::{CertStore, Source};
use crate::deploy::Deployer;
use crate::store::{now_unix, unix_to_rfc3339};
use crate::{ConnectorError, Result};

const FILE: &str = "alerts.json";
const MAX_FILE_BYTES: u64 = 256 * 1024;
const WATCH_INTERVAL: Duration = Duration::from_secs(30);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(120);
const SITE_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const RETRIES: u32 = 2;
const BACKOFF: Duration = Duration::from_secs(2);
const MAX_DELIVERIES: usize = 4;
const DEBOUNCE: u8 = 2;
const CERT_WARN_DAYS: i64 = 14;
const CERT_REPEAT_SECS: u64 = 24 * 3600;
const CERT_CHECK_SECS: u64 = 600;
const SOURCE_FAILURES: u32 = 3;
const DAY_SECS: i64 = 86_400;
const NOTE_CHARS: usize = 500;
const SMTP_LINE: u64 = 2048;
const SMTP_REPLY_LINES: usize = 64;

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        now_unix()
    }
}

pub trait Resolver: Send + Sync {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>>;
}

struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, port)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

#[derive(Debug)]
struct Failure {
    retry: bool,
    message: String,
}

impl Failure {
    fn permanent(message: impl Into<String>) -> Self {
        Self {
            retry: false,
            message: message.into(),
        }
    }

    fn transient(message: impl Into<String>) -> Self {
        Self {
            retry: true,
            message: message.into(),
        }
    }
}

// Everything that decides where a message may go. Loopback and plain HTTP are reachable only through the test constructor.
#[derive(Clone)]
struct Net {
    resolver: Arc<dyn Resolver>,
    tls: Arc<rustls::ClientConfig>,
    #[cfg(test)]
    allow_local: bool,
}

impl Net {
    fn production() -> Self {
        crate::tls::install_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            resolver: Arc::new(SystemResolver),
            tls: Arc::new(tls),
            #[cfg(test)]
            allow_local: false,
        }
    }

    #[cfg(test)]
    fn for_tests(resolver: Arc<dyn Resolver>, tls: Option<Arc<rustls::ClientConfig>>) -> Self {
        let mut net = Self::production();
        net.resolver = resolver;
        if let Some(tls) = tls {
            net.tls = tls;
        }
        net.allow_local = true;
        net
    }

    #[cfg(test)]
    fn local_allowed(&self) -> bool {
        self.allow_local
    }

    #[cfg(not(test))]
    fn local_allowed(&self) -> bool {
        false
    }

    fn destination(&self, url: &str) -> std::result::Result<Target, String> {
        #[cfg(test)]
        if self.allow_local && url.starts_with("http://") {
            let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
            return Ok(Target {
                host: parsed
                    .host_str()
                    .unwrap_or("")
                    .trim_matches(['[', ']'])
                    .to_string(),
                port: parsed.port_or_known_default().unwrap_or(80),
            });
        }
        parse_https_url(url)
    }

    // Resolves now, checks every answer and returns the one address the connection must use, so a second lookup cannot rebind the name.
    async fn pin(&self, target: &Target) -> std::result::Result<IpAddr, Failure> {
        let addrs = match target.host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                let found = tokio::time::timeout(
                    LOOKUP_TIMEOUT,
                    self.resolver.lookup(&target.host, target.port),
                )
                .await;
                match found {
                    Ok(Ok(addrs)) => addrs,
                    Ok(Err(_)) => {
                        return Err(Failure::transient("the host name could not be resolved"));
                    }
                    Err(_) => return Err(Failure::transient("resolving the host name timed out")),
                }
            }
        };
        if addrs.is_empty() {
            return Err(Failure::transient("the host name has no addresses"));
        }
        if !self.local_allowed() && addrs.iter().any(|ip| is_blocked_ip(*ip)) {
            return Err(Failure::permanent(
                "the destination resolves to a private, loopback or link-local address",
            ));
        }
        Ok(addrs[0])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    Unknown,
    Sent,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raised {
    pub event: AlertEvent,
    // Cooldown key: the site id, or `cert:<id>` for certificates.
    pub scope: String,
    pub site: Option<String>,
    pub message: String,
    pub detail: String,
}

impl Raised {
    pub fn new(
        event: AlertEvent,
        site: Option<&str>,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event,
            scope: site.unwrap_or("").to_string(),
            site: site.map(str::to_string),
            message: message.into(),
            detail: detail.into(),
        }
    }
}

pub struct Alerts {
    dir: PathBuf,
    settings: Mutex<Arc<AlertSettings>>,
    // Set when alerts.json exists but could not be read: nothing is written over it.
    broken: bool,
    write: tokio::sync::Mutex<()>,
    cooldowns: Mutex<HashMap<(String, AlertEvent), u64>>,
    permits: Arc<Semaphore>,
    net: Net,
    clock: Arc<dyn Clock>,
    backoff: Duration,
    certs: OnceLock<Arc<CertStore>>,
}

impl std::fmt::Debug for Alerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Alerts")
            .field("enabled", &self.settings().enabled)
            .finish_non_exhaustive()
    }
}

fn internal(what: &str, err: impl std::fmt::Display) -> ConnectorError {
    ConnectorError::Internal(format!("{what}: {err}"))
}

fn file_name() -> Result<FileName> {
    FileName::new(FILE).map_err(|e| internal("alert file name", e))
}

fn load(dir: &Path) -> std::result::Result<AlertSettings, ()> {
    let root = match TrustedDir::open(dir) {
        Ok(root) => root,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AlertSettings::default()),
        Err(_) => return Err(()),
    };
    let name = file_name().map_err(|_| ())?;
    let bytes = match root.read_limited(&name, MAX_FILE_BYTES) {
        Ok(b) => Zeroizing::new(b),
        Err(cite_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AlertSettings::default());
        }
        Err(_) => return Err(()),
    };
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn persist(dir: &Path, settings: &AlertSettings) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(settings)?);
    let root = TrustedDir::open(dir).map_err(|e| internal("cannot open the data directory", e))?;
    write_atomic_in(&root, &file_name()?, &bytes, 0o600)
        .map_err(|e| internal("cannot write the alert settings", e))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Alerts {
    pub fn new(data_dir: &Path) -> Arc<Alerts> {
        Self::assemble(data_dir, Net::production(), Arc::new(SystemClock), BACKOFF)
    }

    fn assemble(dir: &Path, net: Net, clock: Arc<dyn Clock>, backoff: Duration) -> Arc<Alerts> {
        let (settings, broken) = match load(dir) {
            Ok(s) => (s, false),
            Err(()) => {
                tracing::error!(
                    "alerts.json could not be read; alerts stay off and the file is left untouched"
                );
                (AlertSettings::default(), true)
            }
        };
        Arc::new(Alerts {
            dir: dir.to_path_buf(),
            settings: Mutex::new(Arc::new(settings)),
            broken,
            write: tokio::sync::Mutex::new(()),
            cooldowns: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(MAX_DELIVERIES)),
            net,
            clock,
            backoff,
            certs: OnceLock::new(),
        })
    }

    #[cfg(test)]
    fn for_tests(
        dir: &Path,
        clock: Arc<dyn Clock>,
        resolver: Arc<dyn Resolver>,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Arc<Alerts> {
        Self::assemble(
            dir,
            Net::for_tests(resolver, tls),
            clock,
            Duration::from_millis(5),
        )
    }

    // Lets the watcher look at certificate expiry; without it the CertExpiring event is simply never raised.
    pub fn attach_certs(&self, certs: Arc<CertStore>) {
        let _ = self.certs.set(certs);
    }

    pub fn settings(&self) -> Arc<AlertSettings> {
        Arc::clone(&lock(&self.settings))
    }

    pub fn view(&self) -> SettingsView {
        self.settings().view()
    }

    #[cfg(test)]
    fn set_unchecked(&self, settings: AlertSettings) {
        *lock(&self.settings) = Arc::new(settings);
    }

    // Blank secrets keep the stored value; the result is what the API returns, with secrets masked.
    pub async fn update(&self, incoming: AlertSettings) -> Result<SettingsView> {
        let _gate = self.write.lock().await;
        if self.broken {
            return Err(ConnectorError::Internal(
                "alerts.json could not be read at start; fix or remove it".into(),
            ));
        }
        let stored = self.settings();
        let mut incoming = incoming;
        incoming.normalize();
        let mut next = incoming
            .merge_stored(&stored)
            .map_err(ConnectorError::BadRequest)?;
        next.normalize();
        next.validate().map_err(ConnectorError::BadRequest)?;
        let dir = self.dir.clone();
        let next = tokio::task::spawn_blocking(move || persist(&dir, &next).map(|()| next))
            .await
            .map_err(|e| internal("alert settings task failed", e))??;
        let view = next.view();
        *lock(&self.settings) = Arc::new(next);
        Ok(view)
    }

    fn admit(&self, raised: &Raised, cooldown: u64) -> bool {
        let now = self.clock.now();
        let mut map = lock(&self.cooldowns);
        let key = (raised.scope.clone(), raised.event);
        if let Some(last) = map.get(&key)
            && now.saturating_sub(*last) < cooldown
        {
            return false;
        }
        if map.len() > 1024 {
            map.retain(|_, last| now.saturating_sub(*last) < cooldown);
        }
        map.insert(key, now);
        true
    }

    fn payload(&self, raised: &Raised) -> AlertPayload {
        AlertPayload {
            event: raised.event,
            site: raised.site.clone(),
            message: raised.message.clone(),
            detail: raised.detail.clone(),
            at: unix_to_rfc3339(self.clock.now()),
        }
    }

    // Delivery runs on its own tasks so a slow endpoint never holds up the watcher; the handles are returned for tests.
    pub fn dispatch(self: &Arc<Self>, raised: Raised) -> Vec<JoinHandle<()>> {
        let settings = self.settings();
        if !settings.enabled {
            return Vec::new();
        }
        let hooks: Vec<Webhook> = settings
            .webhooks
            .iter()
            .filter(|h| h.wants(raised.event))
            .cloned()
            .collect();
        let mail = settings.email.clone().filter(|m| m.wants(raised.event));
        if hooks.is_empty() && mail.is_none() {
            return Vec::new();
        }
        if !self.admit(&raised, settings.cooldown_secs) {
            return Vec::new();
        }
        let payload = Arc::new(self.payload(&raised));
        let mut handles = Vec::new();
        for hook in hooks {
            let (this, payload) = (Arc::clone(self), Arc::clone(&payload));
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = Arc::clone(&this.permits).acquire_owned().await else {
                    return;
                };
                let sent = this.retrying(|| this.post_webhook(&hook, &payload)).await;
                if let Err(message) = sent {
                    tracing::warn!(target_id = %hook.id, error = %message, "alert webhook delivery failed");
                }
            }));
        }
        if let Some(mail) = mail {
            let (this, payload) = (Arc::clone(self), Arc::clone(&payload));
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = Arc::clone(&this.permits).acquire_owned().await else {
                    return;
                };
                let sent = this.retrying(|| this.send_mail(&mail, &payload)).await;
                if let Err(message) = sent {
                    tracing::warn!(target_id = EMAIL_TARGET, error = %message, "alert email delivery failed");
                }
            }));
        }
        handles
    }

    pub fn notify(self: &Arc<Self>, raised: Raised) {
        drop(self.dispatch(raised));
    }

    async fn retrying<F, Fut>(&self, mut attempt: F) -> std::result::Result<(), String>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::result::Result<(), Failure>>,
    {
        let mut delay = self.backoff;
        let mut tries = 0;
        loop {
            match attempt().await {
                Ok(()) => return Ok(()),
                Err(f) if f.retry && tries < RETRIES => {
                    tries += 1;
                    tokio::time::sleep(delay).await;
                    delay *= 4;
                }
                Err(f) => return Err(f.message),
            }
        }
    }

    // One attempt, bounded to ten seconds, so the caller gets an answer while the operator waits.
    pub async fn test(&self, target: &str) -> TestOutcome {
        let settings = self.settings();
        let payload = AlertPayload {
            event: AlertEvent::NodeError,
            site: None,
            message: "Test alert from your Cite node".into(),
            detail: "This is a test message; no action is needed.".into(),
            at: unix_to_rfc3339(self.clock.now()),
        };
        let work = async {
            if target == EMAIL_TARGET {
                let mail = settings.email.as_ref()?;
                return Some(self.send_mail(mail, &payload).await);
            }
            let hook = settings.webhooks.iter().find(|h| h.id == target)?;
            Some(self.post_webhook(hook, &payload).await)
        };
        match tokio::time::timeout(TEST_TIMEOUT, work).await {
            Err(_) => TestOutcome::Failed("the test timed out after 10 seconds".into()),
            Ok(None) => TestOutcome::Unknown,
            Ok(Some(Ok(()))) => TestOutcome::Sent,
            Ok(Some(Err(f))) => TestOutcome::Failed(f.message),
        }
    }

    async fn post_webhook(
        &self,
        hook: &Webhook,
        payload: &AlertPayload,
    ) -> std::result::Result<(), Failure> {
        let target = self
            .net
            .destination(&hook.url)
            .map_err(Failure::permanent)?;
        let ip = self.net.pin(&target).await?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(SEND_TIMEOUT);
        if target.host.parse::<IpAddr>().is_err() {
            builder = builder.resolve(&target.host, SocketAddr::new(ip, target.port));
        }
        let client = builder
            .build()
            .map_err(|_| Failure::permanent("the HTTP client could not be built"))?;
        let response = client
            .post(&hook.url)
            .json(&payload.body_for(hook.kind))
            .send()
            .await
            .map_err(|e| {
                let e = e.without_url();
                if e.is_timeout() {
                    Failure::transient("the webhook timed out")
                } else if e.is_connect() {
                    Failure::transient("could not connect to the webhook host")
                } else {
                    Failure::transient("the webhook request failed")
                }
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let message = format!("the webhook answered with status {}", status.as_u16());
        if status.is_server_error() || status.as_u16() == 429 {
            Err(Failure::transient(message))
        } else {
            Err(Failure::permanent(message))
        }
    }

    async fn send_mail(
        &self,
        mail: &EmailSettings,
        payload: &AlertPayload,
    ) -> std::result::Result<(), Failure> {
        let target = Target {
            host: mail.host.clone(),
            port: mail.port,
        };
        let ip = self.net.pin(&target).await?;
        let work = smtp::deliver(&self.net, mail, SocketAddr::new(ip, mail.port), payload);
        tokio::time::timeout(SEND_TIMEOUT, work)
            .await
            .unwrap_or_else(|_| Err(Failure::transient("the mail server timed out")))
    }

    async fn certificate_expiries(&self) -> Option<Vec<CertExpiry>> {
        let store = Arc::clone(self.certs.get()?);
        let now = i64::try_from(self.clock.now()).unwrap_or(i64::MAX);
        let listed = tokio::task::spawn_blocking(move || store.list())
            .await
            .ok()?
            .ok()?;
        Some(
            listed
                .iter()
                .filter(|c| c.source != Source::Auto && c.info.not_after > 0)
                .map(|c| CertExpiry {
                    id: c.id.clone(),
                    name: c.name.clone(),
                    days_left: (c.info.not_after - now).div_euclid(DAY_SECS),
                })
                .collect(),
        )
    }
}

mod smtp {
    use super::*;

    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub(super) fn base64(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let get = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
            let value = (get(0) << 16) | (get(1) << 8) | get(2);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(B64[((value >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn ascii_line(text: &str, max: usize) -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '?'
                }
            })
            .take(max)
            .collect()
    }

    pub(super) fn message(mail: &EmailSettings, payload: &AlertPayload) -> String {
        let subject = ascii_line(
            &format!("[Cite] {}", payload.text().lines().next().unwrap_or("")),
            150,
        );
        let date = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc2822)
            .unwrap_or_default();
        let domain = mail.from.rsplit('@').next().unwrap_or("localhost");
        let mut out = String::new();
        out.push_str(&format!("From: <{}>\r\n", mail.from));
        let to: Vec<String> = mail.to.iter().map(|a| format!("<{a}>")).collect();
        out.push_str(&format!("To: {}\r\n", to.join(", ")));
        out.push_str(&format!("Subject: {subject}\r\n"));
        out.push_str(&format!("Date: {date}\r\n"));
        out.push_str(&format!(
            "Message-ID: <{}@{domain}>\r\n",
            ulid::Ulid::generate()
        ));
        out.push_str("MIME-Version: 1.0\r\n");
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        let body = base64(payload.text().as_bytes());
        for line in body.as_bytes().chunks(76) {
            out.push_str(&String::from_utf8_lossy(line));
            out.push_str("\r\n");
        }
        out
    }

    struct Conn<S> {
        io: BufReader<S>,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
        fn new(io: S) -> Self {
            Self {
                io: BufReader::new(io),
            }
        }

        async fn reply(&mut self) -> std::result::Result<(u16, Vec<String>), Failure> {
            let mut lines = Vec::new();
            for _ in 0..SMTP_REPLY_LINES {
                let mut line = String::new();
                let n = (&mut self.io)
                    .take(SMTP_LINE)
                    .read_line(&mut line)
                    .await
                    .map_err(|_| Failure::transient("the mail connection failed"))?;
                if n == 0 {
                    return Err(Failure::transient("the mail server closed the connection"));
                }
                let line = line.trim_end_matches(['\r', '\n']);
                let code = line
                    .get(..3)
                    .and_then(|c| c.parse::<u16>().ok())
                    .ok_or_else(|| {
                        Failure::permanent("the mail server sent an unreadable reply")
                    })?;
                let more = line.as_bytes().get(3) == Some(&b'-');
                lines.push(line.get(4..).unwrap_or("").to_string());
                if !more {
                    return Ok((code, lines));
                }
            }
            Err(Failure::permanent("the mail server reply was too long"))
        }

        async fn expect(&mut self, want: u16) -> std::result::Result<Vec<String>, Failure> {
            let (code, lines) = self.reply().await?;
            if code == want {
                return Ok(lines);
            }
            let first = truncate_chars(
                &ascii_line(lines.first().map_or("", String::as_str), 100),
                100,
            );
            let message = format!("the mail server answered {code} {first}");
            if (400..500).contains(&code) {
                Err(Failure::transient(message))
            } else {
                Err(Failure::permanent(message))
            }
        }

        async fn send(&mut self, line: &str) -> std::result::Result<(), Failure> {
            let mut bytes = Zeroizing::new(Vec::with_capacity(line.len() + 2));
            bytes.extend_from_slice(line.as_bytes());
            bytes.extend_from_slice(b"\r\n");
            self.io
                .write_all(&bytes)
                .await
                .map_err(|_| Failure::transient("the mail connection failed"))?;
            self.io
                .flush()
                .await
                .map_err(|_| Failure::transient("the mail connection failed"))
        }

        async fn command(
            &mut self,
            line: &str,
            want: u16,
        ) -> std::result::Result<Vec<String>, Failure> {
            self.send(line).await?;
            self.expect(want).await
        }

        async fn ehlo(&mut self) -> std::result::Result<Vec<String>, Failure> {
            self.command("EHLO cite-node", 250).await
        }

        async fn transaction(
            &mut self,
            mail: &EmailSettings,
            payload: &AlertPayload,
            caps: &[String],
        ) -> std::result::Result<(), Failure> {
            if !mail.username.is_empty() {
                self.authenticate(mail, caps).await?;
            }
            self.command(&format!("MAIL FROM:<{}>", mail.from), 250)
                .await?;
            for to in &mail.to {
                self.command(&format!("RCPT TO:<{to}>"), 250).await?;
            }
            self.command("DATA", 354).await?;
            let body = message(mail, payload);
            self.io
                .write_all(body.as_bytes())
                .await
                .map_err(|_| Failure::transient("the mail connection failed"))?;
            self.command(".", 250).await?;
            let _ = self.send("QUIT").await;
            Ok(())
        }

        async fn authenticate(
            &mut self,
            mail: &EmailSettings,
            caps: &[String],
        ) -> std::result::Result<(), Failure> {
            let offers = |mech: &str| {
                caps.iter().any(|l| {
                    let upper = l.to_ascii_uppercase();
                    upper.starts_with("AUTH") && upper.split_whitespace().any(|w| w == mech)
                })
            };
            if offers("PLAIN") {
                let raw = Zeroizing::new(format!("\0{}\0{}", mail.username, mail.password));
                let encoded = Zeroizing::new(base64(raw.as_bytes()));
                self.command(&format!("AUTH PLAIN {}", encoded.as_str()), 235)
                    .await?;
            } else if offers("LOGIN") {
                self.command("AUTH LOGIN", 334).await?;
                self.command(&base64(mail.username.as_bytes()), 334).await?;
                let encoded = Zeroizing::new(base64(mail.password.as_bytes()));
                self.command(encoded.as_str(), 235).await?;
            } else {
                return Err(Failure::permanent(
                    "the mail server offers no supported login method",
                ));
            }
            Ok(())
        }
    }

    async fn upgrade(
        net: &Net,
        host: &str,
        tcp: TcpStream,
    ) -> std::result::Result<TlsStream<TcpStream>, Failure> {
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| Failure::permanent("the mail host name is not valid for TLS"))?;
        TlsConnector::from(Arc::clone(&net.tls))
            .connect(name, tcp)
            .await
            .map_err(|_| Failure::transient("the TLS handshake with the mail server failed"))
    }

    pub(super) async fn deliver(
        net: &Net,
        mail: &EmailSettings,
        addr: SocketAddr,
        payload: &AlertPayload,
    ) -> std::result::Result<(), Failure> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|_| Failure::transient("could not connect to the mail server"))?;
        match mail.tls {
            TlsMode::Tls => {
                let mut conn = Conn::new(upgrade(net, &mail.host, tcp).await?);
                conn.expect(220).await?;
                let caps = conn.ehlo().await?;
                conn.transaction(mail, payload, &caps).await
            }
            TlsMode::None => {
                let mut conn = Conn::new(tcp);
                conn.expect(220).await?;
                let caps = conn.ehlo().await?;
                conn.transaction(mail, payload, &caps).await
            }
            TlsMode::Starttls => {
                let mut conn = Conn::new(tcp);
                conn.expect(220).await?;
                let caps = conn.ehlo().await?;
                if !caps.iter().any(|l| l.eq_ignore_ascii_case("STARTTLS")) {
                    return Err(Failure::permanent(
                        "the mail server does not offer STARTTLS",
                    ));
                }
                conn.command("STARTTLS", 220).await?;
                let tcp = conn.io.into_inner();
                let mut conn = Conn::new(upgrade(net, &mail.host, tcp).await?);
                let caps = conn.ehlo().await?;
                conn.transaction(mail, payload, &caps).await
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertExpiry {
    pub id: String,
    pub name: String,
    pub days_left: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub site: String,
    // None when the state cannot be told right now (a deploy is running, or the status could not be read).
    pub unhealthy: Option<bool>,
    pub detail: String,
    // (time, note) of the newest failed build.
    pub failure: Option<(String, String)>,
    // (deployment id, note) of the newest promotion.
    pub promote: Option<(String, String)>,
}

pub trait StatusSource: Send + Sync + 'static {
    fn observe(&self) -> BoxFuture<'_, std::result::Result<Vec<Observation>, String>>;
}

#[derive(Default)]
struct SiteState {
    unhealthy: bool,
    pending: Option<(bool, u8)>,
    failure: Option<String>,
    promote: Option<String>,
    seen: bool,
}

// The decision logic of the watcher, free of clocks and I/O: a state must hold for two checks before it is reported.
#[derive(Default)]
pub struct Tracker {
    sites: HashMap<String, SiteState>,
    certs: HashMap<String, u64>,
    last_cert_check: Option<u64>,
    source_failures: u32,
    source_alerted: bool,
}

impl Tracker {
    pub fn reset(&mut self) {
        *self = Tracker::default();
    }

    pub fn observe(&mut self, observations: &[Observation]) -> Vec<Raised> {
        self.sites
            .retain(|id, _| observations.iter().any(|o| &o.site == id));
        let mut out = Vec::new();
        for obs in observations {
            let state = self.sites.entry(obs.site.clone()).or_default();
            match obs.unhealthy {
                None => state.pending = None,
                Some(bad) if bad == state.unhealthy => state.pending = None,
                Some(bad) => {
                    let held = match state.pending {
                        Some((p, n)) if p == bad => n + 1,
                        _ => 1,
                    };
                    if held >= DEBOUNCE {
                        state.unhealthy = bad;
                        state.pending = None;
                        out.push(if bad {
                            Raised::new(
                                AlertEvent::SiteUnhealthy,
                                Some(obs.site.as_str()),
                                format!("site {} is unhealthy", obs.site),
                                truncate_chars(&obs.detail, NOTE_CHARS),
                            )
                        } else {
                            Raised::new(
                                AlertEvent::SiteRecovered,
                                Some(obs.site.as_str()),
                                format!("site {} is healthy again", obs.site),
                                "",
                            )
                        });
                    } else {
                        state.pending = Some((bad, held));
                    }
                }
            }
            if let Some((at, note)) = &obs.failure {
                if state.seen && state.failure.as_deref() != Some(at.as_str()) {
                    out.push(Raised::new(
                        AlertEvent::BuildFailed,
                        Some(obs.site.as_str()),
                        format!("the build for site {} failed", obs.site),
                        truncate_chars(note, NOTE_CHARS),
                    ));
                }
                state.failure = Some(at.clone());
            }
            if let Some((id, note)) = &obs.promote {
                if state.seen && state.promote.as_deref() != Some(id.as_str()) {
                    out.push(Raised::new(
                        AlertEvent::DeploySucceeded,
                        Some(obs.site.as_str()),
                        format!("a new version of site {} is live", obs.site),
                        truncate_chars(note, NOTE_CHARS),
                    ));
                }
                state.promote = Some(id.clone());
            }
            state.seen = true;
        }
        out
    }

    pub fn certs_due(&self, now: u64) -> bool {
        self.last_cert_check
            .is_none_or(|t| now.saturating_sub(t) >= CERT_CHECK_SECS)
    }

    pub fn certs(&mut self, list: &[CertExpiry], now: u64) -> Vec<Raised> {
        self.last_cert_check = Some(now);
        self.certs.retain(|id, _| list.iter().any(|c| &c.id == id));
        let mut out = Vec::new();
        for cert in list {
            if cert.days_left > CERT_WARN_DAYS {
                self.certs.remove(&cert.id);
                continue;
            }
            let due = self
                .certs
                .get(&cert.id)
                .is_none_or(|t| now.saturating_sub(*t) >= CERT_REPEAT_SECS);
            if !due {
                continue;
            }
            self.certs.insert(cert.id.clone(), now);
            let message = if cert.days_left < 0 {
                format!("certificate {} has expired", cert.name)
            } else {
                format!(
                    "certificate {} expires in {} days",
                    cert.name, cert.days_left
                )
            };
            let mut raised = Raised::new(
                AlertEvent::CertExpiring,
                None,
                message,
                format!("id {}", cert.id),
            );
            raised.scope = format!("cert:{}", cert.id);
            out.push(raised);
        }
        out
    }

    pub fn source_ok(&mut self) {
        self.source_failures = 0;
        self.source_alerted = false;
    }

    // Reported once per streak of failures, not on every cycle.
    pub fn source_failed(&mut self, reason: &str) -> Option<Raised> {
        self.source_failures += 1;
        if self.source_failures < SOURCE_FAILURES || self.source_alerted {
            return None;
        }
        self.source_alerted = true;
        Some(Raised::new(
            AlertEvent::NodeError,
            None,
            "the node could not read its sites' status",
            truncate_chars(reason, NOTE_CHARS),
        ))
    }
}

pub async fn run_cycle(alerts: &Arc<Alerts>, tracker: &mut Tracker, source: &dyn StatusSource) {
    if !alerts.settings().enabled {
        tracker.reset();
        return;
    }
    let now = alerts.clock.now();
    let mut raised = Vec::new();
    match tokio::time::timeout(OBSERVE_TIMEOUT, source.observe()).await {
        Ok(Ok(observations)) => {
            tracker.source_ok();
            raised.extend(tracker.observe(&observations));
        }
        Ok(Err(reason)) => raised.extend(tracker.source_failed(&reason)),
        Err(_) => raised.extend(tracker.source_failed("reading the site status timed out")),
    }
    if tracker.certs_due(now)
        && let Some(list) = alerts.certificate_expiries().await
    {
        raised.extend(tracker.certs(&list, now));
    }
    for item in raised {
        alerts.notify(item);
    }
}

pub fn watch(
    alerts: Arc<Alerts>,
    source: Arc<dyn StatusSource>,
    every: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tracker = Tracker::default();
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            run_cycle(&alerts, &mut tracker, source.as_ref()).await;
        }
    })
}

pub fn spawn_watcher(alerts: Arc<Alerts>, deployer: Arc<Deployer>) -> JoinHandle<()> {
    watch(
        alerts,
        Arc::new(DeployerSource { deployer }),
        WATCH_INTERVAL,
    )
}

struct DeployerSource {
    deployer: Arc<Deployer>,
}

// A running deploy is a state change on purpose, so it never counts as unhealthy.
fn unhealthy_from(status: &SiteStatus) -> Option<(bool, String)> {
    if status.operation.is_some() {
        return None;
    }
    if let Some(error) = &status.error {
        return Some((true, error.clone()));
    }
    let active = status.slots.iter().find(|s| s.slot == status.active)?;
    let proxy = active.haproxy.as_deref().unwrap_or("").to_ascii_uppercase();
    if proxy.starts_with("DOWN") || proxy.starts_with("NOLB") {
        return Some((true, format!("HAProxy reports the live slot as {proxy}")));
    }
    if active.health.eq_ignore_ascii_case("unhealthy") {
        return Some((true, "the live container reports unhealthy".into()));
    }
    Some((false, String::new()))
}

fn history_entry(site: &Site, action: DeployAction) -> Option<(String, String, String)> {
    site.history
        .iter()
        .rev()
        .find(|d| d.action == action)
        .map(|d| (d.id.clone(), d.at.clone(), d.note.clone()))
}

impl DeployerSource {
    async fn observe_site(&self, site: &Site) -> Observation {
        let status = tokio::time::timeout(SITE_TIMEOUT, self.deployer.site_status(&site.id))
            .await
            .ok()
            .and_then(std::result::Result::ok);
        let health = match (&status, site.maintenance.enabled) {
            (Some(status), false) => unhealthy_from(status),
            _ => None,
        };
        let failure = status
            .as_ref()
            .and_then(|s| s.last_failure.as_ref())
            .map(|f| (f.at.clone(), f.note.clone()))
            .or_else(|| history_entry(site, DeployAction::Failed).map(|(_, at, note)| (at, note)));
        Observation {
            site: site.id.clone(),
            unhealthy: health.as_ref().map(|(bad, _)| *bad),
            detail: health.map(|(_, detail)| detail).unwrap_or_default(),
            failure,
            promote: history_entry(site, DeployAction::Promote).map(|(id, _, note)| (id, note)),
        }
    }
}

impl StatusSource for DeployerSource {
    fn observe(&self) -> BoxFuture<'_, std::result::Result<Vec<Observation>, String>> {
        Box::pin(async move {
            let sites = self.deployer.sites();
            let mut out = Vec::with_capacity(sites.len());
            for site in &sites {
                out.push(self.observe_site(site).await);
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests;
