//! Node alert types; reads are tolerant, and secrets exist only in the stored form, never in the views the API returns.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const MAX_BODY_BYTES: usize = 16 * 1024;
pub const MAX_WEBHOOKS: usize = 10;
pub const MAX_RECIPIENTS: usize = 5;
pub const MAX_URL_LEN: usize = 2048;
pub const MAX_COOLDOWN_SECS: u64 = 7 * 24 * 3600;
pub const DEFAULT_COOLDOWN_SECS: u64 = 900;
pub const DISCORD_LIMIT: usize = 1900;
/// The reserved target name that selects the email channel in a test request.
pub const EMAIL_TARGET: &str = "email";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertEvent {
    SiteUnhealthy,
    SiteRecovered,
    BuildFailed,
    DeploySucceeded,
    CertExpiring,
    NodeError,
}

impl AlertEvent {
    pub const ALL: [AlertEvent; 6] = [
        AlertEvent::SiteUnhealthy,
        AlertEvent::SiteRecovered,
        AlertEvent::BuildFailed,
        AlertEvent::DeploySucceeded,
        AlertEvent::CertExpiring,
        AlertEvent::NodeError,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AlertEvent::SiteUnhealthy => "site_unhealthy",
            AlertEvent::SiteRecovered => "site_recovered",
            AlertEvent::BuildFailed => "build_failed",
            AlertEvent::DeploySucceeded => "deploy_succeeded",
            AlertEvent::CertExpiring => "cert_expiring",
            AlertEvent::NodeError => "node_error",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookKind {
    #[default]
    Generic,
    Discord,
    Slack,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Starttls,
    Tls,
    None,
}

/// An empty `events` list means every event.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Webhook {
    pub id: String,
    pub name: String,
    pub kind: WebhookKind,
    pub url: String,
    pub events: Vec<AlertEvent>,
}

impl fmt::Debug for Webhook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Webhook")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("url", &"<redacted>")
            .field("events", &self.events)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailSettings {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub events: Vec<AlertEvent>,
}

impl Default for EmailSettings {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 587,
            tls: TlsMode::Starttls,
            username: String::new(),
            password: String::new(),
            from: String::new(),
            to: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl fmt::Debug for EmailSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("events", &self.events)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertSettings {
    pub enabled: bool,
    pub webhooks: Vec<Webhook>,
    pub email: Option<EmailSettings>,
    pub cooldown_secs: u64,
}

impl Default for AlertSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            webhooks: Vec::new(),
            email: None,
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebhookView {
    pub id: String,
    pub name: String,
    pub kind: WebhookKind,
    pub url: String,
    pub events: Vec<AlertEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmailView {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub username: String,
    pub password_set: bool,
    pub from: String,
    pub to: Vec<String>,
    pub events: Vec<AlertEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsView {
    pub enabled: bool,
    pub webhooks: Vec<WebhookView>,
    pub email: Option<EmailView>,
    pub cooldown_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertPayload {
    pub event: AlertEvent,
    pub site: Option<String>,
    pub message: String,
    pub detail: String,
    pub at: String,
}

impl AlertPayload {
    pub fn text(&self) -> String {
        let mut out = match &self.site {
            Some(site) => format!("[{}] {}: {}", self.event.as_str(), site, self.message),
            None => format!("[{}] {}", self.event.as_str(), self.message),
        };
        if !self.detail.is_empty() {
            out.push('\n');
            out.push_str(&self.detail);
        }
        out
    }

    pub fn body_for(&self, kind: WebhookKind) -> Value {
        match kind {
            WebhookKind::Slack => json!({ "text": self.text() }),
            WebhookKind::Discord => {
                json!({ "content": truncate_chars(&self.text(), DISCORD_LIMIT) })
            }
            WebhookKind::Generic => json!({
                "event": self.event.as_str(),
                "site": self.site,
                "message": self.message,
                "detail": self.detail,
                "at": self.at,
            }),
        }
    }
}

pub fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

/// A webhook or SMTP destination reduced to what the connection guard needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

pub fn parse_https_url(url: &str) -> Result<Target, String> {
    if url.len() > MAX_URL_LEN {
        return Err("url is too long".into());
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("url must not contain spaces, control characters or non-ASCII text".into());
    }
    let rest = match url.get(..8) {
        Some(scheme) if scheme.eq_ignore_ascii_case("https://") => &url[8..],
        _ => return Err("url must start with https://".into()),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains(['@', '\\']) {
        return Err("url must not contain credentials".into());
    }
    let (host, port) = split_host_port(authority)?;
    check_host(&host)?;
    Ok(Target { host, port })
}

fn split_host_port(authority: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, tail) = inner.split_once(']').ok_or("url host is malformed")?;
        match tail {
            "" => (host, None),
            _ => (
                host,
                Some(tail.strip_prefix(':').ok_or("url host is malformed")?),
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => 443,
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or("url port is invalid")?,
    };
    Ok((host.to_ascii_lowercase(), port))
}

/// Accepts a DNS name or an IP literal that is not itself a blocked address.
pub fn check_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("host is required".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_blocked_ip(ip) {
            Err("host must not be a private, loopback or link-local address".into())
        } else {
            Ok(())
        };
    }
    if host.len() > 253 {
        return Err("host is too long".into());
    }
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err("host is not a valid name".into());
        }
    }
    // Numeric last labels are parsed as IPv4 by some resolvers (2130706433, 0x7f.1), which would bypass the address checks.
    let last = labels.last().copied().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return Err("host is not a valid name".into());
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Err("host must not be a loopback name".into());
    }
    Ok(())
}

pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => blocked_v6(v6),
    }
}

fn blocked_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240
}

fn blocked_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let embedded = |hi: u16, lo: u16| {
        let [a, b] = hi.to_be_bytes();
        let [c, d] = lo.to_be_bytes();
        blocked_v4(Ipv4Addr::new(a, b, c, d))
    };
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] == 0)
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] && embedded(s[6], s[7]))
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1)
        || (s[0] == 0x2002 && embedded(s[1], s[2]))
}

pub fn mask_url(url: &str) -> String {
    match parse_https_url(url) {
        Ok(t) => {
            let host = if t.host.contains(':') {
                format!("[{}]", t.host)
            } else {
                t.host
            };
            if t.port == 443 {
                format!("https://{host}/...")
            } else {
                format!("https://{host}:{}/...", t.port)
            }
        }
        Err(_) => "https://...".into(),
    }
}

pub fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 64 && !s.chars().any(char::is_control)
}

pub fn valid_address(s: &str) -> bool {
    if s.is_empty() || s.len() > 254 {
        return false;
    }
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~.-".contains(&b));
    local_ok
        && domain.contains('.')
        && check_host(domain).is_ok()
        && domain.parse::<IpAddr>().is_err()
}

fn dedupe<T: PartialEq + Copy>(items: &mut Vec<T>) {
    let mut seen: Vec<T> = Vec::new();
    items.retain(|i| {
        let fresh = !seen.contains(i);
        seen.push(*i);
        fresh
    });
}

fn secret_ok(s: &str) -> bool {
    s.len() <= 256 && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

impl Webhook {
    pub fn wants(&self, event: AlertEvent) -> bool {
        self.events.is_empty() || self.events.contains(&event)
    }
}

impl EmailSettings {
    pub fn wants(&self, event: AlertEvent) -> bool {
        self.events.is_empty() || self.events.contains(&event)
    }
}

impl AlertSettings {
    /// Trims text and drops duplicates so equal settings compare equal.
    pub fn normalize(&mut self) {
        for hook in &mut self.webhooks {
            hook.id = hook.id.trim().to_string();
            hook.name = hook.name.trim().to_string();
            hook.url = hook.url.trim().to_string();
            dedupe(&mut hook.events);
        }
        if let Some(mail) = &mut self.email {
            mail.host = mail.host.trim().to_ascii_lowercase();
            mail.username = mail.username.trim().to_string();
            mail.from = mail.from.trim().to_string();
            for to in &mut mail.to {
                *to = to.trim().to_string();
            }
            mail.to.dedup();
            dedupe(&mut mail.events);
            if mail.username.is_empty() {
                mail.password.clear();
            }
        }
    }

    /// Fills secrets the client left blank (or echoed back masked) from the stored settings, matched by webhook id.
    pub fn merge_stored(mut self, stored: &AlertSettings) -> Result<AlertSettings, String> {
        for hook in &mut self.webhooks {
            let previous = stored.webhooks.iter().find(|h| h.id == hook.id);
            let keep = hook.url.trim().is_empty()
                || previous.is_some_and(|p| hook.url == mask_url(&p.url));
            if keep {
                match previous {
                    Some(p) => hook.url = p.url.clone(),
                    None => return Err(format!("webhook {:?}: url is required", hook.id)),
                }
            }
        }
        if let (Some(mail), Some(old)) = (&mut self.email, &stored.email)
            && mail.password.is_empty()
            && !old.password.is_empty()
            && !mail.username.is_empty()
        {
            // The stored password only ever goes to the server and account it was saved for.
            let same_account = mail.host.eq_ignore_ascii_case(&old.host)
                && mail.port == old.port
                && mail.tls == old.tls
                && mail.username == old.username;
            if !same_account {
                return Err("email: the server, port, tls mode or username changed, so enter the SMTP password again".into());
            }
            mail.password = old.password.clone();
        }
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.cooldown_secs > MAX_COOLDOWN_SECS {
            return Err(format!("cooldown_secs must be at most {MAX_COOLDOWN_SECS}"));
        }
        if self.webhooks.len() > MAX_WEBHOOKS {
            return Err(format!("at most {MAX_WEBHOOKS} webhooks are allowed"));
        }
        for (i, hook) in self.webhooks.iter().enumerate() {
            if !valid_slug(&hook.id) || hook.id == EMAIL_TARGET {
                return Err(format!(
                    "webhook id {:?} must be 1-32 characters of a-z, 0-9 and -, and not \"{EMAIL_TARGET}\"",
                    hook.id
                ));
            }
            if self.webhooks[..i].iter().any(|h| h.id == hook.id) {
                return Err(format!("webhook id {:?} is used twice", hook.id));
            }
            if !valid_name(&hook.name) {
                return Err(format!(
                    "webhook {:?}: name must be 1-64 characters",
                    hook.id
                ));
            }
            parse_https_url(&hook.url).map_err(|e| format!("webhook {:?}: {e}", hook.id))?;
        }
        if let Some(mail) = &self.email {
            validate_email(mail)?;
        }
        Ok(())
    }

    pub fn view(&self) -> SettingsView {
        SettingsView {
            enabled: self.enabled,
            webhooks: self
                .webhooks
                .iter()
                .map(|h| WebhookView {
                    id: h.id.clone(),
                    name: h.name.clone(),
                    kind: h.kind,
                    url: mask_url(&h.url),
                    events: h.events.clone(),
                })
                .collect(),
            email: self.email.as_ref().map(|m| EmailView {
                host: m.host.clone(),
                port: m.port,
                tls: m.tls,
                username: m.username.clone(),
                password_set: !m.password.is_empty(),
                from: m.from.clone(),
                to: m.to.clone(),
                events: m.events.clone(),
            }),
            cooldown_secs: self.cooldown_secs,
        }
    }
}

fn validate_email(mail: &EmailSettings) -> Result<(), String> {
    check_host(&mail.host).map_err(|e| format!("email: {e}"))?;
    if mail.port == 0 {
        return Err("email: port is invalid".into());
    }
    if !secret_ok(&mail.username) || !secret_ok(&mail.password) {
        return Err("email: username and password must be at most 256 characters without control characters".into());
    }
    if mail.tls == TlsMode::None && !mail.username.is_empty() {
        return Err("email: a username and password need tls to be starttls or tls".into());
    }
    if !valid_address(&mail.from) {
        return Err("email: from is not a valid address".into());
    }
    if mail.to.is_empty() || mail.to.len() > MAX_RECIPIENTS {
        return Err(format!(
            "email: between 1 and {MAX_RECIPIENTS} recipients are required"
        ));
    }
    if let Some(bad) = mail.to.iter().find(|a| !valid_address(a)) {
        return Err(format!("email: {bad:?} is not a valid address"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(id: &str, url: &str) -> Webhook {
        Webhook {
            id: id.into(),
            name: format!("Hook {id}"),
            kind: WebhookKind::Generic,
            url: url.into(),
            events: vec![],
        }
    }

    fn mail() -> EmailSettings {
        EmailSettings {
            host: "smtp.example.com".into(),
            username: "user".into(),
            password: "hunter2".into(),
            from: "alerts@example.com".into(),
            to: vec!["ops@example.com".into()],
            ..EmailSettings::default()
        }
    }

    fn settings(hooks: Vec<Webhook>) -> AlertSettings {
        AlertSettings {
            webhooks: hooks,
            ..AlertSettings::default()
        }
    }

    #[test]
    fn urls_must_be_plain_https_without_credentials() {
        assert!(parse_https_url("https://hooks.example.com/a/b?c=1").is_ok());
        assert_eq!(
            parse_https_url("HTTPS://Hooks.Example.com:8443/x").unwrap(),
            Target {
                host: "hooks.example.com".into(),
                port: 8443
            }
        );
        for bad in [
            "http://example.com/x",
            "ftp://example.com",
            "https://user:pw@example.com/",
            "https://example.com\\@evil.com/",
            "https://exa mple.com/",
            "https://example.com:0/",
            "https://example.com:99999/",
            "https:///path",
            "https://",
            "example.com",
            "https://[::1/",
            "https://exämple.com/",
        ] {
            assert!(parse_https_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn literal_private_hosts_and_numeric_tricks_are_rejected() {
        for bad in [
            "https://127.0.0.1/",
            "https://localhost/",
            "https://a.localhost/",
            "https://10.0.0.5/",
            "https://169.254.169.254/latest",
            "https://[::1]/",
            "https://[fe80::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://example.123/",
        ] {
            assert!(parse_https_url(bad).is_err(), "{bad}");
        }
        assert!(parse_https_url("https://[2606:4700::1111]/").is_ok());
        assert!(parse_https_url("https://1.1.1.1/").is_ok());
    }

    #[test]
    fn blocked_ranges_cover_private_and_special_addresses() {
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "2001::1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "64:ff9b::808:808",
        ] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn masking_keeps_only_the_host() {
        assert_eq!(
            mask_url("https://hooks.slack.com/services/T/B/secret"),
            "https://hooks.slack.com/..."
        );
        assert_eq!(
            mask_url("https://example.com:8443/a?token=x"),
            "https://example.com:8443/..."
        );
        assert_eq!(mask_url("garbage"), "https://...");
    }

    #[test]
    fn validation_enforces_ids_names_counts_and_urls() {
        assert!(
            settings(vec![hook("ops", "https://example.com/h")])
                .validate()
                .is_ok()
        );
        assert!(
            settings(vec![hook("Ops", "https://example.com/h")])
                .validate()
                .is_err()
        );
        assert!(
            settings(vec![hook("email", "https://example.com/h")])
                .validate()
                .is_err()
        );
        assert!(
            settings(vec![hook("-a", "https://example.com/h")])
                .validate()
                .is_err()
        );
        assert!(
            settings(vec![
                hook("a", "https://example.com/h"),
                hook("a", "https://example.com/i")
            ])
            .validate()
            .is_err()
        );
        assert!(
            settings(vec![hook("a", "http://example.com/h")])
                .validate()
                .is_err()
        );
        let mut nameless = hook("a", "https://example.com/h");
        nameless.name = " \u{7} ".into();
        assert!(settings(vec![nameless]).validate().is_err());
        let many: Vec<Webhook> = (0..=MAX_WEBHOOKS)
            .map(|i| hook(&format!("h{i}"), "https://example.com/h"))
            .collect();
        assert!(settings(many).validate().is_err());
        let slow = AlertSettings {
            cooldown_secs: MAX_COOLDOWN_SECS + 1,
            ..AlertSettings::default()
        };
        assert!(slow.validate().is_err());
    }

    #[test]
    fn email_validation_checks_recipients_and_addresses() {
        let mut s = AlertSettings {
            email: Some(mail()),
            ..AlertSettings::default()
        };
        assert!(s.validate().is_ok());
        s.email.as_mut().unwrap().to = (0..=MAX_RECIPIENTS)
            .map(|i| format!("a{i}@example.com"))
            .collect();
        assert!(s.validate().is_err());
        s.email.as_mut().unwrap().to = vec![];
        assert!(s.validate().is_err());
        s.email.as_mut().unwrap().to = vec!["not an address".into()];
        assert!(s.validate().is_err());
        s.email.as_mut().unwrap().to = vec!["a@example.com\r\nBcc: x@y.com".into()];
        assert!(s.validate().is_err());
        s.email = Some(EmailSettings {
            host: "127.0.0.1".into(),
            ..mail()
        });
        assert!(s.validate().is_err());
        s.email = Some(EmailSettings {
            from: "x".into(),
            ..mail()
        });
        assert!(s.validate().is_err());
        s.email = Some(EmailSettings {
            password: "a\nb".into(),
            ..mail()
        });
        assert!(s.validate().is_err());
        s.email = Some(EmailSettings {
            tls: TlsMode::None,
            ..mail()
        });
        assert!(s.validate().is_err());
        s.email = Some(EmailSettings {
            tls: TlsMode::None,
            username: String::new(),
            password: String::new(),
            ..mail()
        });
        assert!(s.validate().is_ok());
    }

    #[test]
    fn blank_or_masked_secrets_keep_the_stored_value() {
        let stored = AlertSettings {
            webhooks: vec![hook("ops", "https://example.com/secret-path")],
            email: Some(mail()),
            ..AlertSettings::default()
        };
        let mut blank = hook("ops", "");
        blank.name = "Renamed".into();
        let incoming = AlertSettings {
            webhooks: vec![blank],
            email: Some(EmailSettings {
                password: String::new(),
                ..mail()
            }),
            ..AlertSettings::default()
        };
        let merged = incoming.merge_stored(&stored).unwrap();
        assert_eq!(merged.webhooks[0].url, "https://example.com/secret-path");
        assert_eq!(merged.webhooks[0].name, "Renamed");
        assert_eq!(merged.email.unwrap().password, "hunter2");

        let echoed = AlertSettings {
            webhooks: vec![hook("ops", "https://example.com/...")],
            ..AlertSettings::default()
        };
        assert_eq!(
            echoed.merge_stored(&stored).unwrap().webhooks[0].url,
            "https://example.com/secret-path"
        );

        let fresh = AlertSettings {
            webhooks: vec![hook("new", "")],
            ..AlertSettings::default()
        };
        assert!(fresh.merge_stored(&stored).is_err());

        let replaced = AlertSettings {
            webhooks: vec![hook("ops", "https://other.example.com/x")],
            email: Some(EmailSettings {
                password: "new".into(),
                ..mail()
            }),
            ..AlertSettings::default()
        };
        let merged = replaced.merge_stored(&stored).unwrap();
        assert_eq!(merged.webhooks[0].url, "https://other.example.com/x");
        assert_eq!(merged.email.unwrap().password, "new");
    }

    #[test]
    fn a_stored_password_is_not_sent_to_another_server_or_account() {
        let stored = AlertSettings {
            email: Some(mail()),
            ..AlertSettings::default()
        };
        let blank = |change: fn(&mut EmailSettings)| {
            let mut m = EmailSettings {
                password: String::new(),
                ..mail()
            };
            change(&mut m);
            AlertSettings {
                email: Some(m),
                ..AlertSettings::default()
            }
            .merge_stored(&stored)
        };
        assert_eq!(blank(|_| {}).unwrap().email.unwrap().password, "hunter2");
        assert_eq!(
            blank(|m| m.host = "SMTP.Example.com".into())
                .unwrap()
                .email
                .unwrap()
                .password,
            "hunter2"
        );
        let changes: [fn(&mut EmailSettings); 4] = [
            |m| m.host = "evil.example.net".into(),
            |m| m.port = 2525,
            |m| m.tls = TlsMode::Tls,
            |m| m.username = "other".into(),
        ];
        for change in changes {
            let err = blank(change).unwrap_err();
            assert!(err.contains("enter the SMTP password again"), "{err}");
        }
    }

    #[test]
    fn clearing_the_username_clears_the_password() {
        let mut s = AlertSettings {
            email: Some(EmailSettings {
                username: " ".into(),
                ..mail()
            }),
            ..AlertSettings::default()
        };
        s.normalize();
        assert_eq!(s.email.unwrap().password, "");
    }

    #[test]
    fn views_and_debug_never_show_secrets() {
        let s = AlertSettings {
            enabled: true,
            webhooks: vec![hook("ops", "https://example.com/secret-path")],
            email: Some(mail()),
            ..AlertSettings::default()
        };
        let json = serde_json::to_string(&s.view()).unwrap();
        assert!(
            !json.contains("secret-path") && !json.contains("hunter2"),
            "{json}"
        );
        assert!(json.contains("\"password_set\":true"));
        assert!(json.contains("https://example.com/..."));
        let debug = format!("{s:?} {:?}", s.webhooks[0]);
        assert!(
            !debug.contains("secret-path") && !debug.contains("hunter2"),
            "{debug}"
        );
    }

    #[test]
    fn parsing_is_tolerant_of_unknown_and_missing_fields() {
        let s: AlertSettings = serde_json::from_str(
            r#"{"enabled":true,"future":1,"webhooks":[{"id":"a","url":"https://example.com/x","password_set":true}],
                "email":{"host":"h","password_set":true}}"#,
        )
        .unwrap();
        assert!(s.enabled);
        assert_eq!(s.cooldown_secs, DEFAULT_COOLDOWN_SECS);
        assert_eq!(s.webhooks[0].kind, WebhookKind::Generic);
        assert_eq!(s.email.unwrap().port, 587);
        let empty: AlertSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, AlertSettings::default());
    }

    #[test]
    fn event_filters_treat_an_empty_list_as_all() {
        let mut h = hook("a", "https://example.com/");
        assert!(h.wants(AlertEvent::NodeError));
        h.events = vec![AlertEvent::BuildFailed];
        assert!(h.wants(AlertEvent::BuildFailed));
        assert!(!h.wants(AlertEvent::NodeError));
        assert_eq!(
            serde_json::to_string(&AlertEvent::SiteUnhealthy).unwrap(),
            "\"site_unhealthy\""
        );
    }

    fn payload() -> AlertPayload {
        AlertPayload {
            event: AlertEvent::BuildFailed,
            site: Some("blog".into()),
            message: "build failed".into(),
            detail: "exit 1".into(),
            at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn payload_formats_match_each_service() {
        let p = payload();
        assert_eq!(
            p.body_for(WebhookKind::Slack)["text"],
            "[build_failed] blog: build failed\nexit 1"
        );
        assert_eq!(
            p.body_for(WebhookKind::Discord)["content"],
            "[build_failed] blog: build failed\nexit 1"
        );
        let generic = p.body_for(WebhookKind::Generic);
        assert_eq!(generic["event"], "build_failed");
        assert_eq!(generic["site"], "blog");
        assert_eq!(generic["message"], "build failed");
        assert_eq!(generic["detail"], "exit 1");
        assert_eq!(generic["at"], "2026-01-01T00:00:00Z");
        let mut nosite = payload();
        nosite.site = None;
        assert!(nosite.body_for(WebhookKind::Generic)["site"].is_null());
    }

    #[test]
    fn discord_content_is_truncated_on_char_boundaries() {
        let mut p = payload();
        p.detail = "é".repeat(5000);
        let content = p.body_for(WebhookKind::Discord)["content"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(content.chars().count(), DISCORD_LIMIT);
        assert!(content.ends_with("..."));
        assert_eq!(truncate_chars("short", 10), "short");
    }
}
