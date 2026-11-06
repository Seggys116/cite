use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 1;

// deny_unknown_fields on the config types makes a misspelled key an error instead of a silently ignored setting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    pub version: u32,
    #[serde(default)]
    pub sites: Vec<Site>,
    #[serde(default)]
    pub pages: Vec<MaintenancePage>,
    #[serde(default)]
    pub firewall: Vec<FirewallRule>,
    #[serde(default)]
    pub settings: EdgeSettings,
}

// Each site has two upstream slots; `active` names the one that serves traffic and the other is free for the next deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    Blue,
    Green,
}

impl Slot {
    pub fn other(self) -> Slot {
        match self {
            Slot::Blue => Slot::Green,
            Slot::Green => Slot::Blue,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::Blue => "blue",
            Slot::Green => "green",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub hosts: Vec<String>,
    // Fields marked default may be omitted by API clients and are filled in on load.
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub kind: SiteKind,
    pub blue: Upstream,
    pub green: Upstream,
    pub active: Slot,
    #[serde(default)]
    pub maintenance: Maintenance,
    #[serde(default)]
    pub health: HealthCheck,
    #[serde(default)]
    pub source: Option<Source>,
    #[serde(default)]
    pub history: Vec<Deployment>,
    // Left out of the JSON while it is the default so nodes that predate the field still accept the site.
    #[serde(default, skip_serializing_if = "SiteAccess::is_default")]
    pub access: SiteAccess,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteKind {
    #[default]
    Site,
    Api,
}

// Who may reach a site and how the origin is spoken to; the default is open access with the node's own TLS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteAccess {
    #[serde(default)]
    pub cloudflare_only: bool,
    #[serde(default)]
    pub tls: TlsMode,
    // Left out of the JSON while it is the default so nodes that predate the field still accept the site.
    #[serde(default, skip_serializing_if = "BotPolicy::is_allow")]
    pub bots: BotPolicy,
    /// The site refuses requests without the Cloudflare zone secret; the secret itself is injected at render time and never stored here.
    #[serde(default, skip_serializing_if = "is_false")]
    pub zone_lock: bool,
}

impl SiteAccess {
    pub fn is_default(&self) -> bool {
        *self == SiteAccess::default()
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

// What the edge does with requests whose User-Agent names a bot; blocked requests are still logged and counted in analytics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotPolicy {
    #[default]
    Allow,
    BlockBad,
    BlockAll,
}

impl BotPolicy {
    pub fn is_allow(&self) -> bool {
        *self == BotPolicy::Allow
    }
}

// Flexible means Cloudflare terminates HTTPS and reaches the origin over plain HTTP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Full,
    Flexible,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub addr: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

// Weight is relative between the targets of one slot; omitting it gives each target an equal share.
fn default_weight() -> u32 {
    100
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maintenance {
    pub enabled: bool,
    #[serde(default)]
    pub page_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub path: String,
    pub interval_ms: u32,
    pub rise: u32,
    pub fall: u32,
    pub timeout_ms: u32,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            path: "/".into(),
            interval_ms: 2000,
            rise: 2,
            fall: 3,
            timeout_ms: 1500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub repo: String,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub node_major: Option<u8>,
    #[serde(default)]
    pub poll_interval: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub id: String,
    pub at: String,
    pub slot: Slot,
    pub action: DeployAction,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployAction {
    Promote,
    Rollback,
    Switch,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenancePage {
    pub id: String,
    pub name: String,
    pub html: String,
    #[serde(default = "default_status")]
    pub status: u16,
}

// 503 tells clients and crawlers the outage is temporary.
fn default_status() -> u16 {
    503
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAction {
    Deny,
    Drop,
    Tarpit,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matchers {
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub user_agent_regex: Option<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<HeaderMatch>,
    /// "http" or "https", as the visitor connected (Cloudflare's view for Flexible sites).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referer_regex: Option<String>,
}

// Exactly one of regex and equals is set; negate inverts the test, so "unless header X equals Y" is expressible.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    pub name: String,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub negate: bool,
    /// The value still goes into edge.json and haproxy.cfg, but never into Debug output, labels or error text.
    #[serde(default)]
    pub secret: bool,
}

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for HeaderMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hide = |v: &Option<String>| -> Option<String> {
            v.as_ref().map(|v| {
                if self.secret {
                    REDACTED.to_string()
                } else {
                    v.clone()
                }
            })
        };
        f.debug_struct("HeaderMatch")
            .field("name", &self.name)
            .field("regex", &hide(&self.regex))
            .field("equals", &hide(&self.equals))
            .field("negate", &self.negate)
            .field("secret", &self.secret)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    /// Template: an absolute http(s) URL or a path starting with /, with {scheme} {host} {path} {query} {www_host} {apex_host}.
    pub to: String,
    #[serde(default = "default_redirect_status")]
    pub status: u16,
}

fn default_redirect_status() -> u16 {
    301
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderTarget {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderOpKind {
    Set,
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderOp {
    pub target: HeaderTarget,
    pub op: HeaderOpKind,
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cors {
    /// Exact origins such as https://app.example.com, or the single entry "*".
    #[serde(default)]
    pub origins: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub credentials: bool,
    #[serde(default)]
    pub max_age_secs: u32,
}

// A rule either blocks (action set) or has effects (redirect, or headers and cors); the two never mix, which validation enforces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<FirewallAction>,
    #[serde(default)]
    pub matchers: Matchers,
    #[serde(default)]
    pub site: Option<String>,
    /// Name shown in logs and the blocked-by-rule table; defaults to the rule id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Redirect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderOp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<Cors>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSettings {
    pub http_port: u16,
    pub https_port: Option<u16>,
    pub max_conn: u32,
    pub client_timeout_ms: u32,
    pub server_timeout_ms: u32,
    pub connect_timeout_ms: u32,
    pub per_ip_rate_limit: Option<u32>,
    pub max_body_bytes: Option<u64>,
    pub retention: Retention,
    /// CIDR ranges trusted as Cloudflare; empty means the built-in list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cloudflare_ranges: Vec<String>,
}

impl Default for EdgeSettings {
    fn default() -> Self {
        Self {
            http_port: 80,
            https_port: None,
            max_conn: 20000,
            client_timeout_ms: 30000,
            server_timeout_ms: 60000,
            connect_timeout_ms: 3000,
            per_ip_rate_limit: Some(600),
            max_body_bytes: None,
            retention: Retention::default(),
            cloudflare_ranges: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub recent_events: usize,
    pub minute_buckets_hours: u32,
    /// 0 keeps hourly data and stored events forever.
    pub hour_buckets_days: u32,
    pub audit_days: u32,
    pub persist_interval_secs: u32,
    pub store_user_agents: bool,
    pub store_client_ips: bool,
    /// Complete days of events are written to an archive file before age retention deletes them.
    #[serde(default = "archive_by_default")]
    pub archive_before_delete: bool,
}

fn archive_by_default() -> bool {
    true
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            recent_events: 5000,
            minute_buckets_hours: 48,
            hour_buckets_days: 0,
            audit_days: 365,
            persist_interval_secs: 60,
            store_user_agents: true,
            store_client_ips: true,
            archive_before_delete: true,
        }
    }
}

// Built from parsed HAProxy log lines rather than read from user-supplied config, so unknown fields are not denied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEvent {
    pub ts_ms: i64,
    pub client_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub query_len: u32,
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub total_ms: u32,
    pub user_agent: String,
    pub referer: String,
    pub content_type: String,
    pub backend: String,
    pub server: String,
    pub site: String,
    pub blocked: Option<String>,
    #[serde(default)]
    pub http_version: String,
    #[serde(default)]
    pub accept: String,
    #[serde(default)]
    pub accept_language: String,
    #[serde(default)]
    pub accept_encoding: String,
    #[serde(default)]
    pub sec_fetch_site: String,
    #[serde(default)]
    pub sec_fetch_mode: String,
    #[serde(default)]
    pub sec_fetch_dest: String,
    #[serde(default)]
    pub sec_ch_ua: String,
    #[serde(default)]
    pub tls_version: String,
    #[serde(default)]
    pub resp_ms: u32,
    #[serde(default)]
    pub bot_score: u8,
    #[serde(default)]
    pub bot_class: String,
    #[serde(default)]
    pub bot_signals: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_keeps_history_forever_and_archives_by_default() {
        let r = Retention::default();
        assert_eq!(r.hour_buckets_days, 0);
        assert!(r.archive_before_delete);
    }

    #[test]
    fn archive_flag_defaults_on_for_settings_saved_before_it_existed() {
        let mut value = serde_json::to_value(Retention::default()).expect("serialize");
        value
            .as_object_mut()
            .expect("object")
            .remove("archive_before_delete");
        let r: Retention = serde_json::from_value(value).expect("deserialize");
        assert!(r.archive_before_delete);
    }

    #[test]
    fn access_defaults_to_open_full_tls() {
        let a = SiteAccess::default();
        assert!(!a.cloudflare_only);
        assert_eq!(a.tls, TlsMode::Full);
        assert!(EdgeSettings::default().cloudflare_ranges.is_empty());
    }

    #[test]
    fn configs_saved_before_access_existed_still_load() {
        let site = r#"{"id": "a", "name": "a", "hosts": ["a.com"],
            "blue": {"targets": []}, "green": {"targets": []}, "active": "blue"}"#;
        let s: Site = serde_json::from_str(site).expect("old site");
        assert_eq!(s.access, SiteAccess::default());
        let mut value = serde_json::to_value(EdgeSettings::default()).expect("serialize");
        value
            .as_object_mut()
            .expect("object")
            .remove("cloudflare_ranges");
        let settings: EdgeSettings = serde_json::from_value(value).expect("old settings");
        assert!(settings.cloudflare_ranges.is_empty());
    }

    #[test]
    fn access_json_shape_and_strictness() {
        let a: SiteAccess =
            serde_json::from_str(r#"{"cloudflare_only": true, "tls": "flexible"}"#).expect("parse");
        assert!(a.cloudflare_only);
        assert_eq!(a.tls, TlsMode::Flexible);
        let back = serde_json::to_value(&a).expect("serialize");
        assert_eq!(
            back,
            serde_json::json!({"cloudflare_only": true, "tls": "flexible"})
        );
        let partial: SiteAccess = serde_json::from_str(r#"{"tls": "full"}"#).expect("parse");
        assert!(!partial.cloudflare_only);
        assert!(serde_json::from_str::<SiteAccess>(r#"{"surprise": 1}"#).is_err());
        assert!(serde_json::from_str::<SiteAccess>(r#"{"tls": "strict"}"#).is_err());
    }

    #[test]
    fn bot_policy_defaults_to_allow_serialises_snake_case_and_stays_out_of_default_json() {
        assert_eq!(BotPolicy::default(), BotPolicy::Allow);
        assert!(SiteAccess::default().bots.is_allow());
        for (policy, text) in [
            (BotPolicy::Allow, "allow"),
            (BotPolicy::BlockBad, "block_bad"),
            (BotPolicy::BlockAll, "block_all"),
        ] {
            assert_eq!(serde_json::to_value(policy).expect("ser"), text);
            let back: BotPolicy = serde_json::from_value(serde_json::json!(text)).expect("de");
            assert_eq!(back, policy);
        }
        assert!(serde_json::from_str::<BotPolicy>("\"block\"").is_err());
        assert!(serde_json::from_str::<BotPolicy>("\"BlockBad\"").is_err());
        let default_json = serde_json::to_value(SiteAccess::default()).expect("ser");
        assert_eq!(
            default_json,
            serde_json::json!({"cloudflare_only": false, "tls": "full"})
        );
        let a: SiteAccess = serde_json::from_str(r#"{"bots": "block_all"}"#).expect("parse");
        assert_eq!(a.bots, BotPolicy::BlockAll);
        assert_eq!(
            serde_json::to_value(&a).expect("ser"),
            serde_json::json!({"cloudflare_only": false, "tls": "full", "bots": "block_all"})
        );
        let old: SiteAccess = serde_json::from_str(r#"{"cloudflare_only": true}"#).expect("old");
        assert_eq!(old.bots, BotPolicy::Allow);
    }

    #[test]
    fn effect_fields_default_and_new_matchers_default_to_none() {
        let r: FirewallRule =
            serde_json::from_str(r#"{"id": "r", "name": "r", "enabled": true}"#).expect("minimal");
        assert!(r.action.is_none() && r.label.is_none() && r.redirect.is_none());
        assert!(r.headers.is_empty() && r.cors.is_none() && r.site.is_none());
        assert_eq!(r.matchers, Matchers::default());
        assert!(r.matchers.header.is_none() && r.matchers.scheme.is_none());
        assert!(r.matchers.referer_regex.is_none());
        let redirect: Redirect = serde_json::from_str(r#"{"to": "/x"}"#).expect("redirect");
        assert_eq!(redirect.status, 301);
        let cors: Cors = serde_json::from_str("{}").expect("cors");
        assert_eq!(cors, Cors::default());
        assert!(!cors.credentials && cors.max_age_secs == 0);
        let m: HeaderMatch = serde_json::from_str(r#"{"name": "X-A", "equals": "v"}"#).expect("hm");
        assert!(!m.negate && !m.secret && m.regex.is_none());
        let op: HeaderOp =
            serde_json::from_str(r#"{"target": "response", "op": "remove", "name": "Server"}"#)
                .expect("op");
        assert_eq!(
            (op.target, op.op, op.value),
            (HeaderTarget::Response, HeaderOpKind::Remove, None)
        );
    }

    #[test]
    fn new_types_reject_unknown_fields_and_bad_enums() {
        assert!(serde_json::from_str::<Redirect>(r#"{"to": "/x", "extra": 1}"#).is_err());
        assert!(serde_json::from_str::<Cors>(r#"{"origin": ["*"]}"#).is_err());
        assert!(serde_json::from_str::<HeaderMatch>(r#"{"name": "a", "value": "b"}"#).is_err());
        assert!(
            serde_json::from_str::<HeaderOp>(r#"{"target": "both", "op": "set", "name": "a"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<HeaderOp>(
                r#"{"target": "request", "op": "replace", "name": "a"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<FirewallRule>(
                r#"{"id": "r", "name": "r", "enabled": true, "surprise": 1}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<Matchers>(r#"{"scheme": "http", "x": 1}"#).is_err());
    }

    #[test]
    fn effect_rule_json_round_trips_without_null_noise() {
        let json = serde_json::json!({
            "id": "www", "name": "www", "enabled": true, "site": "a",
            "matchers": {"scheme": "http", "header": {"name": "X-A", "regex": "^v"}},
            "redirect": {"to": "https://{host}{path}", "status": 308},
            "headers": [{"target": "request", "op": "set", "name": "X-B", "value": "1"}],
            "cors": {"origins": ["https://a.example.com"], "credentials": true}
        });
        let r: FirewallRule = serde_json::from_value(json).expect("parse");
        let back = serde_json::to_value(&r).expect("ser");
        assert!(back.get("action").is_none() && back.get("label").is_none());
        assert_eq!(back["redirect"]["status"], 308);
        assert_eq!(back["matchers"]["scheme"], "http");
        assert!(back["matchers"].get("referer_regex").is_none());
        let again: FirewallRule = serde_json::from_value(back).expect("reparse");
        assert_eq!(again, r);
    }

    #[test]
    fn secret_header_values_never_reach_debug_output() {
        let needle = "value-that-must-not-leak-0123456789";
        let m = HeaderMatch {
            name: "X-Cite-Origin-Secret".into(),
            equals: Some(needle.into()),
            negate: true,
            secret: true,
            ..HeaderMatch::default()
        };
        let rule = FirewallRule {
            id: "z".into(),
            matchers: Matchers {
                header: Some(m.clone()),
                ..Matchers::default()
            },
            ..FirewallRule::default()
        };
        for text in [
            format!("{m:?}"),
            format!("{rule:?}"),
            format!("{:?}", rule.matchers),
        ] {
            assert!(!text.contains(needle), "debug output shows the value");
            assert!(text.contains("<redacted>"), "debug output is not redacted");
        }
        let plain = HeaderMatch {
            secret: false,
            ..m.clone()
        };
        assert!(
            format!("{plain:?}").contains(needle),
            "plain value is hidden"
        );
        // the value stays in the stored JSON, which is what haproxy.cfg is rendered from
        let stored = serde_json::to_value(&m).expect("ser");
        assert!(stored["equals"] == needle, "stored value differs");
    }

    #[test]
    fn default_access_and_cloudflare_ranges_stay_out_of_the_json() {
        let site = crate::validate::fixtures::site("a", "a.com");
        let value = serde_json::to_value(&site).expect("serialize");
        assert!(value.get("access").is_none());
        let settings = serde_json::to_value(EdgeSettings::default()).expect("serialize");
        assert!(settings.get("cloudflare_ranges").is_none());
        let mut open = site.clone();
        open.access.cloudflare_only = true;
        assert!(
            serde_json::to_value(&open)
                .expect("serialize")
                .get("access")
                .is_some()
        );
        let listed = EdgeSettings {
            cloudflare_ranges: vec!["173.245.48.0/20".into()],
            ..EdgeSettings::default()
        };
        assert!(
            serde_json::to_value(&listed)
                .expect("serialize")
                .get("cloudflare_ranges")
                .is_some()
        );
        let back: Site = serde_json::from_value(value).expect("old json loads");
        assert_eq!(back, site);
    }

    #[test]
    fn retention_still_rejects_unknown_fields() {
        let mut value = serde_json::to_value(Retention::default()).expect("serialize");
        value["surprise"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Retention>(value).is_err());
    }
}
