use std::fmt;
use std::sync::Mutex;

use cite_edge::alerts::{
    AlertEvent, DEFAULT_COOLDOWN_SECS, EMAIL_TARGET, MAX_COOLDOWN_SECS, MAX_RECIPIENTS,
    MAX_WEBHOOKS, TlsMode, WebhookKind, check_host, mask_url, parse_https_url, valid_address,
};
use serde_json::{Value, json};

use crate::certissue::{json_list, json_strings, json_text};
use crate::certs::wipe;
use crate::theme::Tone;

const MAX_NAME_CHARS: usize = 64;
const MAX_SECRET_CHARS: usize = 256;

pub fn event_label(event: AlertEvent) -> &'static str {
    match event {
        AlertEvent::SiteUnhealthy => "A site becomes unhealthy",
        AlertEvent::SiteRecovered => "A site recovers",
        AlertEvent::BuildFailed => "A build fails",
        AlertEvent::DeploySucceeded => "A deploy succeeds",
        AlertEvent::CertExpiring => "A certificate is about to expire",
        AlertEvent::NodeError => "The node reports an error",
    }
}

pub fn kind_label(kind: WebhookKind) -> &'static str {
    match kind {
        WebhookKind::Generic => "Generic",
        WebhookKind::Discord => "Discord",
        WebhookKind::Slack => "Slack",
    }
}

pub fn kind_wire(kind: WebhookKind) -> &'static str {
    match kind {
        WebhookKind::Generic => "generic",
        WebhookKind::Discord => "discord",
        WebhookKind::Slack => "slack",
    }
}

pub fn kind_from_wire(text: &str) -> WebhookKind {
    match text {
        "discord" => WebhookKind::Discord,
        "slack" => WebhookKind::Slack,
        _ => WebhookKind::Generic,
    }
}

pub fn tls_label(tls: TlsMode) -> &'static str {
    match tls {
        TlsMode::Starttls => "STARTTLS",
        TlsMode::Tls => "TLS",
        TlsMode::None => "None",
    }
}

pub fn tls_wire(tls: TlsMode) -> &'static str {
    match tls {
        TlsMode::Starttls => "starttls",
        TlsMode::Tls => "tls",
        TlsMode::None => "none",
    }
}

pub fn tls_from_wire(text: &str) -> TlsMode {
    match text {
        "tls" => TlsMode::Tls,
        "none" => TlsMode::None,
        _ => TlsMode::Starttls,
    }
}

pub fn default_port(tls: TlsMode) -> u16 {
    match tls {
        TlsMode::Starttls => 587,
        TlsMode::Tls => 465,
        TlsMode::None => 25,
    }
}

fn event_from_wire(text: &str) -> Option<AlertEvent> {
    AlertEvent::ALL.into_iter().find(|e| e.as_str() == text)
}

pub fn toggle_event(events: &mut Vec<AlertEvent>, event: AlertEvent) {
    if let Some(at) = events.iter().position(|e| *e == event) {
        events.remove(at);
    } else {
        events.push(event);
        events.sort_by_key(|e| AlertEvent::ALL.iter().position(|x| x == e));
    }
}

// The node treats an empty list as every event.
pub fn events_text(events: &[AlertEvent]) -> String {
    if events.is_empty() {
        return "Every event".into();
    }
    events
        .iter()
        .map(|e| event_label(*e))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn check_email(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if valid_address(t) {
        Ok(t.to_string())
    } else {
        Err("Enter a valid email address.".into())
    }
}

// Lowercase letters, digits and single hyphens, never an id already in use or the reserved email target.
pub fn new_id(name: &str, used: &[String]) -> String {
    let mut slug = String::new();
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let base: String = slug.trim_matches('-').chars().take(24).collect();
    let base = base.trim_matches('-');
    let base = if base.is_empty() { "webhook" } else { base };
    let taken = |id: &str| id == EMAIL_TARGET || used.iter().any(|u| u == id);
    if !taken(base) {
        return base.to_string();
    }
    (2u32..)
        .map(|n| format!("{base}-{n}"))
        .find(|id| !taken(id))
        .unwrap_or_else(|| base.to_string())
}

pub fn parse_cooldown(text: &str) -> Result<u64, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(DEFAULT_COOLDOWN_SECS);
    }
    let range = format!("Enter a cooldown in seconds, from 0 to {MAX_COOLDOWN_SECS} (7 days).");
    if !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(range);
    }
    match t.parse::<u64>() {
        Ok(n) if n <= MAX_COOLDOWN_SECS => Ok(n),
        _ => Err(range),
    }
}

pub fn parse_recipients(text: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let parts = text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|p| !p.is_empty());
    for part in parts {
        if !valid_address(part) {
            return Err(format!("{part} is not a valid email address."));
        }
        if !out.iter().any(|o| o.eq_ignore_ascii_case(part)) {
            out.push(part.to_string());
        }
    }
    if out.is_empty() {
        return Err("Enter at least one recipient.".into());
    }
    if out.len() > MAX_RECIPIENTS {
        return Err(format!("At most {MAX_RECIPIENTS} recipients are allowed."));
    }
    Ok(out)
}

pub fn parse_port(text: &str, tls: TlsMode) -> Result<u16, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(default_port(tls));
    }
    let range = "Enter a port number from 1 to 65535.".to_string();
    if !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(range);
    }
    match t.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(range),
    }
}

fn secret_ok(s: &str) -> bool {
    s.chars().count() <= MAX_SECRET_CHARS && !s.chars().any(char::is_control)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookInfo {
    pub id: String,
    pub name: String,
    pub kind: WebhookKind,
    pub url: String,
    pub events: Vec<AlertEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailInfo {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub username: String,
    pub password_set: bool,
    pub from: String,
    pub to: Vec<String>,
    pub events: Vec<AlertEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertsConfig {
    pub enabled: bool,
    pub webhooks: Vec<WebhookInfo>,
    pub email: Option<EmailInfo>,
    pub cooldown_secs: u64,
}

fn events_of(v: &Value) -> Vec<AlertEvent> {
    let mut out: Vec<AlertEvent> = Vec::new();
    for text in json_strings(v, "events") {
        if let Some(e) = event_from_wire(&text)
            && !out.contains(&e)
        {
            out.push(e);
        }
    }
    out
}

// Unknown events and kinds from a newer node are dropped or read as generic rather than failing the whole panel.
pub fn parse_alerts(v: &Value) -> Result<AlertsConfig, String> {
    if !v.is_object() {
        return Err("The node sent an unexpected alerts answer.".into());
    }
    let webhooks = json_list(v, "webhooks")
        .iter()
        .map(|h| WebhookInfo {
            id: json_text(h, "id"),
            name: json_text(h, "name"),
            kind: kind_from_wire(&json_text(h, "kind")),
            url: json_text(h, "url"),
            events: events_of(h),
        })
        .collect();
    let email = v.get("email").filter(|e| e.is_object()).map(|e| EmailInfo {
        host: json_text(e, "host"),
        port: e
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0),
        tls: tls_from_wire(&json_text(e, "tls")),
        username: json_text(e, "username"),
        password_set: e
            .get("password_set")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        from: json_text(e, "from"),
        to: json_strings(e, "to"),
        events: events_of(e),
    });
    Ok(AlertsConfig {
        enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        webhooks,
        email,
        cooldown_secs: v
            .get("cooldown_secs")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_COOLDOWN_SECS),
    })
}

// What the node shows for a stored address: the host only, since the path usually is the secret.
pub fn display_url(url: &str) -> String {
    mask_url(url)
}

#[derive(Clone, PartialEq, Eq)]
pub struct WebhookDraft {
    pub id: Option<String>,
    pub name: String,
    pub kind: WebhookKind,
    pub url: String,
    pub events: Vec<AlertEvent>,
}

impl fmt::Debug for WebhookDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookDraft")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("url", &"[redacted]")
            .field("events", &self.events)
            .finish()
    }
}

impl Drop for WebhookDraft {
    fn drop(&mut self) {
        wipe(&mut self.url);
    }
}

impl WebhookDraft {
    fn to_json(&self, used: &mut Vec<String>) -> Result<Value, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("Give every webhook a name.".into());
        }
        let label = format!("Webhook {name}");
        if name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
            return Err(format!(
                "{label}: the name can be at most {MAX_NAME_CHARS} characters."
            ));
        }
        let url = self.url.trim();
        if url.is_empty() {
            if self.id.is_none() {
                return Err(format!("{label}: enter the webhook address."));
            }
        } else if let Err(e) = parse_https_url(url) {
            return Err(format!("{label}: {e}."));
        }
        let id = match &self.id {
            Some(id) => id.clone(),
            None => {
                let id = new_id(name, used);
                used.push(id.clone());
                id
            }
        };
        Ok(json!({
            "id": id,
            "name": name,
            "kind": kind_wire(self.kind),
            "url": url,
            "events": wire_events(&self.events),
        }))
    }
}

fn wire_events(events: &[AlertEvent]) -> Vec<&'static str> {
    events.iter().map(|e| e.as_str()).collect()
}

#[derive(Clone, PartialEq, Eq)]
pub struct EmailDraft {
    pub host: String,
    pub port: String,
    pub tls: TlsMode,
    pub username: String,
    pub password: String,
    pub password_set: bool,
    pub from: String,
    pub to: String,
    pub events: Vec<AlertEvent>,
}

impl fmt::Debug for EmailDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailDraft")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("password_set", &self.password_set)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("events", &self.events)
            .finish()
    }
}

impl Drop for EmailDraft {
    fn drop(&mut self) {
        wipe(&mut self.password);
    }
}

impl EmailDraft {
    fn to_json(&self) -> Result<Value, String> {
        let host = self.host.trim().to_ascii_lowercase();
        check_host(&host).map_err(|e| format!("Email server: {e}."))?;
        let port = parse_port(&self.port, self.tls)?;
        let username = self.username.trim();
        if !secret_ok(username) || !secret_ok(&self.password) {
            return Err(format!(
                "The SMTP user name and password can be at most {MAX_SECRET_CHARS} characters with no control characters."
            ));
        }
        let from = self.from.trim();
        if !valid_address(from) {
            return Err("Enter a valid From address for the email alerts.".into());
        }
        let to = parse_recipients(&self.to)?;
        let password = if username.is_empty() {
            ""
        } else {
            self.password.as_str()
        };
        Ok(json!({
            "host": host,
            "port": port,
            "tls": tls_wire(self.tls),
            "username": username,
            "password": password,
            "from": from,
            "to": to,
            "events": wire_events(&self.events),
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertsDraft {
    pub enabled: bool,
    pub cooldown: String,
    pub webhooks: Vec<WebhookDraft>,
    pub email: Option<EmailDraft>,
}

impl AlertsDraft {
    // Stored addresses and the password are never loaded back, so a blank field means keep what the node holds.
    #[cfg(test)]
    pub fn from_config(cfg: &AlertsConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            cooldown: cfg.cooldown_secs.to_string(),
            webhooks: cfg
                .webhooks
                .iter()
                .map(|h| WebhookDraft {
                    id: Some(h.id.clone()),
                    name: h.name.clone(),
                    kind: h.kind,
                    url: String::new(),
                    events: h.events.clone(),
                })
                .collect(),
            email: cfg.email.as_ref().map(|e| EmailDraft {
                host: e.host.clone(),
                port: e.port.to_string(),
                tls: e.tls,
                username: e.username.clone(),
                password: String::new(),
                password_set: e.password_set,
                from: e.from.clone(),
                to: e.to.join(", "),
                events: e.events.clone(),
            }),
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.enabled && self.webhooks.is_empty() && self.email.is_none() {
            out.push(
                "Alerts are on but nothing receives them. Add a webhook or email settings.".into(),
            );
        }
        if let Some(mail) = &self.email
            && !mail.username.trim().is_empty()
            && mail.password.is_empty()
            && !mail.password_set
        {
            out.push("An SMTP user name is set without a password, so the mail server will probably refuse to send.".into());
        }
        out
    }

    pub fn to_request(&self) -> Result<AlertsRequest, String> {
        let cooldown = parse_cooldown(&self.cooldown)?;
        if self.webhooks.len() > MAX_WEBHOOKS {
            return Err(format!("At most {MAX_WEBHOOKS} webhooks are allowed."));
        }
        let mut used: Vec<String> = self.webhooks.iter().filter_map(|w| w.id.clone()).collect();
        let mut hooks = Vec::with_capacity(self.webhooks.len());
        for hook in &self.webhooks {
            hooks.push(hook.to_json(&mut used)?);
        }
        let email = match &self.email {
            Some(mail) => mail.to_json()?,
            None => Value::Null,
        };
        let body = json!({
            "enabled": self.enabled,
            "webhooks": hooks,
            "email": email,
            "cooldown_secs": cooldown,
        });
        Ok(AlertsRequest { body })
    }
}

// Holds the addresses and the password until sent; they are overwritten when the request is dropped.
pub struct AlertsRequest {
    body: Value,
}

impl AlertsRequest {
    pub fn body(&self) -> &Value {
        &self.body
    }
}

impl fmt::Debug for AlertsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AlertsRequest([redacted])")
    }
}

impl Drop for AlertsRequest {
    fn drop(&mut self) {
        if let Some(Value::Array(hooks)) = self.body.get_mut("webhooks") {
            for hook in hooks {
                if let Some(Value::String(url)) = hook.get_mut("url") {
                    wipe(url);
                }
            }
        }
        if let Some(Value::String(password)) = self
            .body
            .get_mut("email")
            .and_then(|mail| mail.get_mut("password"))
        {
            wipe(password);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestResult {
    pub ok: bool,
    pub error: Option<String>,
}

pub fn parse_test_result(v: &Value) -> TestResult {
    TestResult {
        ok: v.get("ok").and_then(Value::as_bool).unwrap_or(false),
        error: v
            .get("error")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(str::to_string),
    }
}

pub fn email_target() -> &'static str {
    EMAIL_TARGET
}

pub fn test_note(what: &str, result: &TestResult) -> (String, Tone) {
    if result.ok {
        return (format!("Test sent to {what}."), Tone::Ok);
    }
    let why = result
        .error
        .as_deref()
        .unwrap_or("The node did not say why.");
    (format!("The test to {what} failed: {why}"), Tone::Bad)
}

static DEMO: Mutex<Option<AlertsConfig>> = Mutex::new(None);

fn demo_default() -> AlertsConfig {
    AlertsConfig {
        enabled: true,
        webhooks: vec![WebhookInfo {
            id: "ops-slack".into(),
            name: "Ops Slack".into(),
            kind: WebhookKind::Slack,
            url: "https://hooks.slack.com/...".into(),
            events: vec![AlertEvent::SiteUnhealthy, AlertEvent::SiteRecovered],
        }],
        email: Some(EmailInfo {
            host: "smtp.example.com".into(),
            port: 587,
            tls: TlsMode::Starttls,
            username: "alerts@example.com".into(),
            password_set: true,
            from: "alerts@example.com".into(),
            to: vec!["ops@example.com".into()],
            events: Vec::new(),
        }),
        cooldown_secs: DEFAULT_COOLDOWN_SECS,
    }
}

pub(crate) fn demo_alerts() -> AlertsConfig {
    let stored = DEMO.lock().unwrap_or_else(|e| e.into_inner());
    stored.clone().unwrap_or_else(demo_default)
}

// Reads a save request the way the node does: blank addresses and passwords keep what was stored.
pub fn config_from_request(body: &Value, previous: &AlertsConfig) -> AlertsConfig {
    let webhooks = json_list(body, "webhooks")
        .iter()
        .map(|h| {
            let id = json_text(h, "id");
            let url = json_text(h, "url");
            let old = previous.webhooks.iter().find(|p| p.id == id);
            WebhookInfo {
                url: if url.is_empty() {
                    old.map(|p| p.url.clone())
                        .unwrap_or_else(|| "https://...".into())
                } else {
                    mask_url(&url)
                },
                id,
                name: json_text(h, "name"),
                kind: kind_from_wire(&json_text(h, "kind")),
                events: events_of(h),
            }
        })
        .collect();
    let email = body.get("email").filter(|e| e.is_object()).map(|e| {
        let sent = !json_text(e, "password").is_empty();
        let kept = previous.email.as_ref().is_some_and(|p| p.password_set);
        EmailInfo {
            host: json_text(e, "host"),
            port: e
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(0),
            tls: tls_from_wire(&json_text(e, "tls")),
            username: json_text(e, "username"),
            password_set: sent || (kept && !json_text(e, "username").is_empty()),
            from: json_text(e, "from"),
            to: json_strings(e, "to"),
            events: events_of(e),
        }
    });
    AlertsConfig {
        enabled: body
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        webhooks,
        email,
        cooldown_secs: body
            .get("cooldown_secs")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_COOLDOWN_SECS),
    }
}

pub(crate) fn demo_save(request: &AlertsRequest) -> AlertsConfig {
    let mut stored = DEMO.lock().unwrap_or_else(|e| e.into_inner());
    let previous = stored.clone().unwrap_or_else(demo_default);
    let next = config_from_request(request.body(), &previous);
    *stored = Some(next.clone());
    next
}

pub(crate) fn demo_test(target: &str) -> TestResult {
    let known = target == EMAIL_TARGET || demo_alerts().webhooks.iter().any(|w| w.id == target);
    if known {
        TestResult {
            ok: true,
            error: None,
        }
    } else {
        TestResult {
            ok: false,
            error: Some("No destination with that name.".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(id: Option<&str>, name: &str, url: &str) -> WebhookDraft {
        WebhookDraft {
            id: id.map(str::to_string),
            name: name.into(),
            kind: WebhookKind::Generic,
            url: url.into(),
            events: vec![],
        }
    }

    fn mail() -> EmailDraft {
        EmailDraft {
            host: "SMTP.example.com".into(),
            port: String::new(),
            tls: TlsMode::Starttls,
            username: "user".into(),
            password: "hunter2".into(),
            password_set: false,
            from: "alerts@example.com".into(),
            to: "ops@example.com, ops2@example.com".into(),
            events: vec![AlertEvent::NodeError],
        }
    }

    fn draft() -> AlertsDraft {
        AlertsDraft {
            enabled: true,
            cooldown: "600".into(),
            webhooks: vec![hook(None, "Ops Chat", "https://hooks.example.com/abc")],
            email: None,
        }
    }

    fn body(d: &AlertsDraft) -> Value {
        d.to_request().unwrap().body().clone()
    }

    #[test]
    fn a_new_webhook_gets_a_slug_id_and_its_address() {
        let v = body(&draft());
        assert_eq!(v["enabled"], true);
        assert_eq!(v["cooldown_secs"], 600);
        assert_eq!(v["email"], Value::Null);
        let h = &v["webhooks"][0];
        assert_eq!(h["id"], "ops-chat");
        assert_eq!(h["url"], "https://hooks.example.com/abc");
        assert_eq!(h["kind"], "generic");
        assert_eq!(h["events"], json!([]));
    }

    #[test]
    fn a_stored_webhook_with_a_blank_address_keeps_it_by_id() {
        let mut d = draft();
        d.webhooks = vec![hook(Some("ops-chat"), "Ops Chat", "  ")];
        let v = body(&d);
        assert_eq!(v["webhooks"][0]["id"], "ops-chat");
        assert_eq!(v["webhooks"][0]["url"], "");
    }

    #[test]
    fn a_new_webhook_needs_an_address() {
        let mut d = draft();
        d.webhooks = vec![hook(None, "Ops Chat", "")];
        assert!(d.to_request().unwrap_err().contains("webhook address"));
    }

    #[test]
    fn addresses_follow_the_node_rules_and_errors_do_not_echo_them() {
        for bad in [
            "http://hooks.example.com/a",
            "hooks.example.com",
            "https://user:pw@hooks.example.com/a",
            "https://127.0.0.1/a",
            "https://hooks.example.com/a b",
            "https://localhost/a",
        ] {
            let mut d = draft();
            d.webhooks = vec![hook(None, "Hook", bad)];
            let err = d.to_request().unwrap_err();
            assert!(!err.contains(bad), "{err}");
        }
    }

    #[test]
    fn webhook_names_are_required_and_bounded() {
        let mut d = draft();
        d.webhooks = vec![hook(None, "  ", "https://hooks.example.com/a")];
        assert!(d.to_request().is_err());
        d.webhooks = vec![hook(None, &"n".repeat(65), "https://hooks.example.com/a")];
        assert!(d.to_request().is_err());
    }

    #[test]
    fn at_most_ten_webhooks_are_accepted() {
        let mut d = draft();
        d.webhooks = (0..MAX_WEBHOOKS)
            .map(|i| hook(None, &format!("hook {i}"), "https://hooks.example.com/a"))
            .collect();
        assert!(d.to_request().is_ok());
        d.webhooks
            .push(hook(None, "one more", "https://hooks.example.com/a"));
        assert!(d.to_request().unwrap_err().contains("10"));
    }

    #[test]
    fn new_ids_are_unique_valid_and_never_the_email_target() {
        let mut d = draft();
        d.webhooks = vec![
            hook(Some("ops-chat"), "Ops Chat", ""),
            hook(None, "Ops Chat", "https://hooks.example.com/a"),
            hook(None, "Ops Chat", "https://hooks.example.com/b"),
            hook(None, "Email", "https://hooks.example.com/c"),
            hook(None, "!!!", "https://hooks.example.com/d"),
            hook(
                None,
                &format!("{}Long", "Long Name ".repeat(6)),
                "https://hooks.example.com/e",
            ),
        ];
        let v = body(&d);
        let ids: Vec<&str> = (0..6)
            .map(|i| v["webhooks"][i]["id"].as_str().unwrap())
            .collect();
        assert_eq!(&ids[..3], ["ops-chat", "ops-chat-2", "ops-chat-3"]);
        assert_eq!(ids[3], "email-2");
        assert_eq!(ids[4], "webhook");
        for id in &ids {
            assert!(
                cite_edge::alerts::valid_slug(id) && *id != EMAIL_TARGET,
                "{id}"
            );
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 6);
    }

    #[test]
    fn the_cooldown_defaults_and_stays_within_the_node_limit() {
        assert_eq!(parse_cooldown("").unwrap(), DEFAULT_COOLDOWN_SECS);
        assert_eq!(parse_cooldown(" 0 ").unwrap(), 0);
        assert_eq!(
            parse_cooldown(&MAX_COOLDOWN_SECS.to_string()).unwrap(),
            MAX_COOLDOWN_SECS
        );
        let over = (MAX_COOLDOWN_SECS + 1).to_string();
        for bad in ["-1", "abc", "1.5", over.as_str(), "99999999999999999999999"] {
            assert!(parse_cooldown(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn email_settings_are_normalised_and_default_the_port_from_the_mode() {
        let mut d = draft();
        d.email = Some(mail());
        let v = body(&d);
        let m = &v["email"];
        assert_eq!(m["host"], "smtp.example.com");
        assert_eq!(m["port"], 587);
        assert_eq!(m["tls"], "starttls");
        assert_eq!(m["password"], "hunter2");
        assert_eq!(m["to"], json!(["ops@example.com", "ops2@example.com"]));
        assert_eq!(m["events"], json!(["node_error"]));
        let mut tls = mail();
        tls.tls = TlsMode::Tls;
        assert_eq!(tls.to_json().unwrap()["port"], 465);
        tls.tls = TlsMode::None;
        assert_eq!(tls.to_json().unwrap()["port"], 25);
        tls.port = "2525".into();
        assert_eq!(tls.to_json().unwrap()["port"], 2525);
    }

    #[test]
    fn a_blank_password_is_sent_blank_so_the_node_keeps_the_stored_one() {
        let mut m = mail();
        m.password.clear();
        m.password_set = true;
        assert_eq!(m.to_json().unwrap()["password"], "");
        let mut d = draft();
        d.email = Some(m.clone());
        assert!(d.warnings().is_empty());
        m.password_set = false;
        d.email = Some(m);
        assert_eq!(d.warnings().len(), 1);
    }

    #[test]
    fn no_user_name_means_no_password_is_sent() {
        let mut m = mail();
        m.username.clear();
        assert_eq!(m.to_json().unwrap()["password"], "");
    }

    #[test]
    fn email_settings_are_refused_when_wrong() {
        let breakers: [fn(&mut EmailDraft); 8] = [
            |m| m.host = "localhost".into(),
            |m| m.host = String::new(),
            |m| m.port = "0".into(),
            |m| m.port = "70000".into(),
            |m| m.from = "nobody".into(),
            |m| m.to = String::new(),
            |m| m.to = "ok@example.com not-an-address".into(),
            |m| m.password = "p\nw".into(),
        ];
        for (i, f) in breakers.iter().enumerate() {
            let mut m = mail();
            f(&mut m);
            assert!(m.to_json().is_err(), "case {i}");
        }
    }

    #[test]
    fn recipients_are_deduped_and_capped_at_five() {
        let got =
            parse_recipients("a@example.com, A@example.com;b@example.com\nc@example.com").unwrap();
        assert_eq!(got, ["a@example.com", "b@example.com", "c@example.com"]);
        let six = (0..6)
            .map(|i| format!("u{i}@example.com"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_recipients(&six).unwrap_err().contains('5'));
        let five = (0..5)
            .map(|i| format!("u{i}@example.com"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(parse_recipients(&five).unwrap().len(), 5);
    }

    #[test]
    fn the_node_view_round_trips_through_the_form_without_secrets() {
        let cfg = demo_default();
        let d = AlertsDraft::from_config(&cfg);
        assert!(d.webhooks[0].url.is_empty());
        assert!(d.email.as_ref().unwrap().password.is_empty());
        assert!(d.email.as_ref().unwrap().password_set);
        let v = body(&d);
        assert_eq!(v["webhooks"][0]["id"], "ops-slack");
        assert_eq!(v["webhooks"][0]["url"], "");
        assert_eq!(v["webhooks"][0]["kind"], "slack");
        assert_eq!(
            v["webhooks"][0]["events"],
            json!(["site_unhealthy", "site_recovered"])
        );
        assert_eq!(v["email"]["password"], "");
        assert_eq!(v["cooldown_secs"], DEFAULT_COOLDOWN_SECS);
    }

    #[test]
    fn the_node_json_is_parsed_tolerantly() {
        let cfg = parse_alerts(&json!({
            "enabled": true,
            "cooldown_secs": 30,
            "webhooks": [{"id": "a", "name": "A", "kind": "weird", "url": "https://x.example.com/...", "events": ["build_failed", "bogus", "build_failed"]}],
            "email": {"host": "h.example.com", "port": 465, "tls": "tls", "username": "u", "password_set": true, "from": "f@example.com", "to": ["t@example.com"], "events": []}
        }))
        .unwrap();
        assert!(cfg.enabled && cfg.cooldown_secs == 30);
        assert_eq!(cfg.webhooks[0].kind, WebhookKind::Generic);
        assert_eq!(cfg.webhooks[0].events, [AlertEvent::BuildFailed]);
        let mail = cfg.email.unwrap();
        assert_eq!(
            (mail.port, mail.tls, mail.password_set),
            (465, TlsMode::Tls, true)
        );
        assert!(parse_alerts(&json!([])).is_err());
        let none = parse_alerts(&json!({"email": null})).unwrap();
        assert!(
            none.email.is_none() && !none.enabled && none.cooldown_secs == DEFAULT_COOLDOWN_SECS
        );
    }

    #[test]
    fn events_toggle_in_a_fixed_order() {
        let mut e = Vec::new();
        toggle_event(&mut e, AlertEvent::NodeError);
        toggle_event(&mut e, AlertEvent::SiteUnhealthy);
        assert_eq!(e, [AlertEvent::SiteUnhealthy, AlertEvent::NodeError]);
        toggle_event(&mut e, AlertEvent::NodeError);
        assert_eq!(e, [AlertEvent::SiteUnhealthy]);
        assert_eq!(events_text(&[]), "Every event");
        assert_eq!(events_text(&e), "A site becomes unhealthy");
    }

    #[test]
    fn stored_addresses_are_shown_masked_to_the_host() {
        assert_eq!(
            display_url("https://hooks.slack.com/services/T0/B0/secret"),
            "https://hooks.slack.com/..."
        );
        assert_eq!(
            display_url("https://hooks.slack.com/..."),
            "https://hooks.slack.com/..."
        );
        assert_eq!(
            display_url("https://h.example.com:8443/x"),
            "https://h.example.com:8443/..."
        );
        assert_eq!(display_url("not a url"), "https://...");
        assert!(!display_url("https://hooks.slack.com/services/T0/B0/secret").contains("secret"));
    }

    #[test]
    fn debug_output_hides_addresses_and_passwords() {
        let h = hook(None, "Hook", "https://hooks.example.com/very-secret");
        assert!(!format!("{h:?}").contains("very-secret"));
        let m = mail();
        assert!(!format!("{m:?}").contains("hunter2"));
        let mut d = draft();
        d.email = Some(m);
        assert!(!format!("{d:?}").contains("hunter2"));
        let req = d.to_request().unwrap();
        assert_eq!(format!("{req:?}"), "AlertsRequest([redacted])");
    }

    #[test]
    fn warnings_flag_alerts_with_no_destination() {
        let mut d = draft();
        d.webhooks.clear();
        assert_eq!(d.warnings().len(), 1);
        d.enabled = false;
        assert!(d.warnings().is_empty());
    }

    #[test]
    fn test_results_read_ok_and_error() {
        let ok = parse_test_result(&json!({"ok": true}));
        assert_eq!(
            test_note("Ops Chat", &ok),
            ("Test sent to Ops Chat.".to_string(), Tone::Ok)
        );
        let bad = parse_test_result(&json!({"ok": false, "error": " refused "}));
        assert_eq!(bad.error.as_deref(), Some("refused"));
        let (text, tone) = test_note("email", &bad);
        assert_eq!(tone, Tone::Bad);
        assert!(text.contains("refused"));
        assert!(
            test_note("email", &parse_test_result(&json!({})))
                .0
                .contains("did not say why")
        );
        assert_eq!(email_target(), "email");
    }

    #[test]
    fn a_demo_save_keeps_blank_secrets_and_masks_new_addresses() {
        let previous = demo_default();
        let mut d = AlertsDraft::from_config(&previous);
        d.webhooks
            .push(hook(None, "Pager", "https://pager.example.com/key/123"));
        d.cooldown = "120".into();
        let req = d.to_request().unwrap();
        let next = config_from_request(req.body(), &previous);
        assert_eq!(next.webhooks[0].url, "https://hooks.slack.com/...");
        assert_eq!(next.webhooks[1].id, "pager");
        assert_eq!(next.webhooks[1].url, "https://pager.example.com/...");
        assert_eq!(next.cooldown_secs, 120);
        assert!(next.email.unwrap().password_set);
    }

    #[test]
    fn the_demo_test_knows_its_destinations() {
        assert!(demo_test(EMAIL_TARGET).ok);
        assert!(demo_test("ops-slack").ok);
        assert!(!demo_test("missing").ok);
    }
}
