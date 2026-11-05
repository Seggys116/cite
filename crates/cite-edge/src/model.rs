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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteKind {
    #[default]
    Site,
    Api,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub action: FirewallAction,
    pub matchers: Matchers,
    #[serde(default)]
    pub site: Option<String>,
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
    fn retention_still_rejects_unknown_fields() {
        let mut value = serde_json::to_value(Retention::default()).expect("serialize");
        value["surprise"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Retention>(value).is_err());
    }
}
