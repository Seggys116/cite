//! The node's egress settings: how executors of outbound sites reach the internet, and the env of each stack's egress proxy.

use cite_edge::model::OutboundRules;
use cite_edge::validate::{MAX_EGRESS_ENTRIES, is_egress_cidr, is_egress_host};

use crate::error::{ConnectorError, Result};

pub const EGRESS_PROXY_PORT: u16 = 3128;
pub const DEFAULT_EGRESS_BRIDGE: &str = "cite-egress";
const MODE_KEY: &str = "CITE_STACK_EGRESS_MODE";
const LEGACY_KEY: &str = "CITE_STACK_EXECUTOR_EGRESS";
const BRIDGE_KEY: &str = "CITE_STACK_EGRESS_BRIDGE";
/// The node's own public addresses; they join the deny ceiling of every egress proxy.
pub const NODE_IPS_KEY: &str = "CITE_NODE_PUBLIC_IPS";
const DENY_CIDRS_ENV: &str = "CITE_EGRESS_DENY_CIDRS";
const ALLOW_CIDRS_ENV: &str = "CITE_EGRESS_ALLOW_CIDRS";

/// Node setting, key in the egress proxy and the rule each entry must pass.
type NodeKey = (&'static str, &'static str, fn(&str) -> bool);

/// In the order the Docker proxy expects them.
const NODE_KEYS: [NodeKey; 4] = [
    ("CITE_STACK_EGRESS_ALLOW_CIDRS", "CITE_EGRESS_ALLOW_CIDRS", is_egress_cidr),
    ("CITE_STACK_EGRESS_DENY_CIDRS", "CITE_EGRESS_DENY_CIDRS", is_egress_cidr),
    ("CITE_STACK_EGRESS_DENY_HOSTS", "CITE_EGRESS_DENY_HOSTS", is_egress_host),
    ("CITE_STACK_EGRESS_ALLOW_PORTS", "CITE_EGRESS_ALLOW_PORTS", is_port_range),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EgressMode {
    /// Executors reach the public internet only through their stack's egress proxy.
    #[default]
    Filtered,
    /// Executors join their stack's egress bridge directly, without filtering.
    Open,
    /// No site may make outbound requests.
    Off,
}

impl EgressMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EgressMode::Filtered => "filtered",
            EgressMode::Open => "open",
            EgressMode::Off => "off",
        }
    }
}

/// The node's egress settings; they must equal the Docker proxy's, which rebuilds every egress proxy env from its own copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    pub mode: EgressMode,
    pub bridge: String,
    /// The node-wide CITE_EGRESS_* entries, normalised, in NODE_KEYS order.
    pub node_env: Vec<String>,
}

impl Default for Egress {
    fn default() -> Self {
        Egress {
            mode: EgressMode::Filtered,
            bridge: DEFAULT_EGRESS_BRIDGE.to_string(),
            node_env: Vec::new(),
        }
    }
}

fn is_port_range(entry: &str) -> bool {
    let port = |p: &str| {
        (1..=5).contains(&p.len())
            && p.bytes().all(|b| b.is_ascii_digit())
            && !(p.len() > 1 && p.starts_with('0'))
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    };
    match entry.split_once('-') {
        Some((a, b)) => port(a) && port(b) && a.parse::<u32>().ok() <= b.parse::<u32>().ok(),
        None => port(entry),
    }
}

fn bad(msg: String) -> ConnectorError {
    ConnectorError::BadRequest(msg)
}

// Trimmed, empty entries dropped, joined with commas: the exact text the Docker proxy compares.
fn setting(key: &str, raw: &str, entry_ok: fn(&str) -> bool) -> Result<String> {
    let entries: Vec<&str> = raw.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
    if entries.len() > MAX_EGRESS_ENTRIES {
        return Err(bad(format!("{key} has more than {MAX_EGRESS_ENTRIES} entries")));
    }
    for (i, e) in entries.iter().enumerate() {
        if !entry_ok(e) {
            return Err(bad(format!("{key} entry {e:?} is not valid")));
        }
        if entries[..i].contains(e) {
            return Err(bad(format!("{key} entry {e:?} is listed twice")));
        }
    }
    Ok(entries.join(","))
}

// The Docker proxy appends CITE_NODE_PUBLIC_IPS the same way, so both sides build the same deny list.
fn with_node_ips(key: &str, deny: &str, own: &str) -> Result<String> {
    let mut entries: Vec<&str> = deny.split(',').filter(|e| !e.is_empty()).collect();
    for ip in own.split(',').filter(|e| !e.is_empty()) {
        if !entries.contains(&ip) {
            entries.push(ip);
        }
    }
    if entries.len() > MAX_EGRESS_ENTRIES {
        return Err(bad(format!(
            "{key} and {NODE_IPS_KEY} together have more than {MAX_EGRESS_ENTRIES} entries"
        )));
    }
    Ok(entries.join(","))
}

// `*.name` and `.name` mean the same, so both forms collapse to one entry.
fn site_list(entries: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    for e in entries {
        let e = e.trim();
        let e = e.strip_prefix('*').filter(|r| r.starts_with('.')).unwrap_or(e);
        if !e.is_empty() && !out.iter().any(|o| o == e) {
            out.push(e.to_string());
        }
    }
    out.join(",")
}

impl Egress {
    pub fn with_mode(mode: EgressMode) -> Egress {
        Egress {
            mode,
            ..Egress::default()
        }
    }

    pub fn from_env() -> Result<Egress> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Egress> {
        let set = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let mode = match set(MODE_KEY).as_deref() {
            Some("filtered") => EgressMode::Filtered,
            Some("open") => EgressMode::Open,
            Some("off") => EgressMode::Off,
            Some(other) => {
                return Err(bad(format!(
                    "{MODE_KEY} {other:?} must be filtered, open or off"
                )));
            }
            None => match set(LEGACY_KEY).as_deref() {
                None => EgressMode::Filtered,
                Some(v) if v.eq_ignore_ascii_case("true") || v == "1" => EgressMode::Filtered,
                Some(v) if v.eq_ignore_ascii_case("false") || v == "0" => EgressMode::Off,
                Some(_) => return Err(bad(format!("{LEGACY_KEY} must be true or false"))),
            },
        };
        let bridge = set(BRIDGE_KEY).unwrap_or_else(|| DEFAULT_EGRESS_BRIDGE.to_string());
        let bridge_ok = bridge.len() <= 128
            && bridge
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            && !bridge.starts_with("cite-vol-");
        if !bridge_ok {
            return Err(bad(format!("{BRIDGE_KEY} {bridge:?} is not valid")));
        }
        let own = setting(NODE_IPS_KEY, &get(NODE_IPS_KEY).unwrap_or_default(), is_egress_cidr)?;
        let mut node_env = Vec::new();
        for (key, env_key, entry_ok) in NODE_KEYS {
            let mut value = setting(key, &get(key).unwrap_or_default(), entry_ok)?;
            if env_key == DENY_CIDRS_ENV {
                value = with_node_ips(key, &value, &own)?;
            }
            if !value.is_empty() {
                node_env.push(format!("{env_key}={value}"));
            }
        }
        Ok(Egress {
            mode,
            bridge,
            node_env,
        })
    }

    /// The node's CITE_STACK_EGRESS_ALLOW_CIDRS entries, which may open ranges a site alone cannot.
    pub fn node_allow_cidrs(&self) -> Vec<String> {
        self.node_env
            .iter()
            .filter_map(|e| e.strip_prefix(ALLOW_CIDRS_ENV)?.strip_prefix('='))
            .flat_map(|v| v.split(','))
            .map(str::to_string)
            .collect()
    }

    /// The egress proxy env for one site: the node's entries, then the site's rules.
    pub fn proxy_env(&self, rules: &OutboundRules) -> Vec<String> {
        let mut env = self.node_env.clone();
        env.push(format!("CITE_EGRESS_MODE={}", rules.mode.as_str()));
        env.push(format!("CITE_EGRESS_BLOCK_MAIL={}", rules.block_mail));
        for (key, list) in [("CITE_EGRESS_ALLOW", &rules.allow), ("CITE_EGRESS_DENY", &rules.deny)] {
            let joined = site_list(list);
            if !joined.is_empty() {
                env.push(format!("{key}={joined}"));
            }
        }
        env
    }
}

#[cfg(test)]
mod tests {
    use cite_edge::model::OutboundMode;

    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> Result<Egress> {
        Egress::from_lookup(|k| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string()))
    }

    #[test]
    fn the_mode_defaults_to_filtered_and_falls_back_to_the_old_boolean() {
        assert_eq!(lookup(&[]).unwrap(), Egress::default());
        for (raw, want) in [
            ("filtered", EgressMode::Filtered),
            (" open ", EgressMode::Open),
            ("off", EgressMode::Off),
        ] {
            assert_eq!(lookup(&[(MODE_KEY, raw)]).unwrap().mode, want, "{raw}");
        }
        for (raw, want) in [
            ("true", EgressMode::Filtered),
            ("1", EgressMode::Filtered),
            ("FALSE", EgressMode::Off),
            ("0", EgressMode::Off),
            ("", EgressMode::Filtered),
        ] {
            assert_eq!(lookup(&[(LEGACY_KEY, raw)]).unwrap().mode, want, "{raw}");
        }
        let both = lookup(&[(MODE_KEY, "open"), (LEGACY_KEY, "false")]).unwrap();
        assert_eq!(both.mode, EgressMode::Open);
        for pairs in [[(MODE_KEY, "Open")], [(MODE_KEY, "on")], [(LEGACY_KEY, "maybe")]] {
            assert!(lookup(&pairs).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn node_lists_are_normalised_and_validated() {
        let e = lookup(&[
            ("CITE_STACK_EGRESS_ALLOW_CIDRS", " 192.168.10.0/24 , fd00::/8,"),
            ("CITE_STACK_EGRESS_DENY_HOSTS", "evil.example,.ads.example"),
            ("CITE_STACK_EGRESS_ALLOW_PORTS", "80,443,8000-8100"),
            (BRIDGE_KEY, "my-egress"),
        ])
        .unwrap();
        assert_eq!(
            e.node_env,
            vec![
                "CITE_EGRESS_ALLOW_CIDRS=192.168.10.0/24,fd00::/8",
                "CITE_EGRESS_DENY_HOSTS=evil.example,.ads.example",
                "CITE_EGRESS_ALLOW_PORTS=80,443,8000-8100",
            ]
        );
        assert_eq!(e.bridge, "my-egress");
        for pairs in [
            [("CITE_STACK_EGRESS_ALLOW_CIDRS", "10.0.0.0/33")],
            [("CITE_STACK_EGRESS_ALLOW_CIDRS", "010.0.0.0/8")],
            [("CITE_STACK_EGRESS_DENY_CIDRS", "10.0.0.1,10.0.0.1")],
            [("CITE_STACK_EGRESS_DENY_HOSTS", "Evil.example")],
            [("CITE_STACK_EGRESS_DENY_HOSTS", "2130706433")],
            [("CITE_STACK_EGRESS_ALLOW_PORTS", "443-80")],
            [("CITE_STACK_EGRESS_ALLOW_PORTS", "0")],
            [(BRIDGE_KEY, "a b")],
        ] {
            assert!(lookup(&pairs).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn node_public_ips_join_the_deny_list() {
        let alone = lookup(&[(NODE_IPS_KEY, " 203.0.113.10, 2001:db8::10 ")]).unwrap();
        assert_eq!(alone.node_env, vec!["CITE_EGRESS_DENY_CIDRS=203.0.113.10,2001:db8::10"]);
        let merged = lookup(&[
            ("CITE_STACK_EGRESS_DENY_CIDRS", "198.51.100.0/24,203.0.113.10"),
            (NODE_IPS_KEY, "203.0.113.10,203.0.113.11"),
            ("CITE_STACK_EGRESS_ALLOW_CIDRS", "192.168.10.0/24,fd00::/8"),
        ])
        .unwrap();
        assert_eq!(
            merged.node_env[1],
            "CITE_EGRESS_DENY_CIDRS=198.51.100.0/24,203.0.113.10,203.0.113.11"
        );
        assert_eq!(merged.node_allow_cidrs(), vec!["192.168.10.0/24", "fd00::/8"]);
        for bad in ["example.com", "::ffff:1.2.3.4", "1.2.3.4,1.2.3.4"] {
            assert!(lookup(&[(NODE_IPS_KEY, bad)]).is_err(), "{bad}");
        }
        let many = (0..40).map(|i| format!("10.0.{i}.1")).collect::<Vec<_>>().join(",");
        let more = (0..40).map(|i| format!("10.1.{i}.1")).collect::<Vec<_>>().join(",");
        assert!(lookup(&[("CITE_STACK_EGRESS_DENY_CIDRS", many.as_str()), (NODE_IPS_KEY, more.as_str())]).is_err());
    }

    #[test]
    fn the_proxy_env_puts_node_entries_first_then_the_site_rules() {
        let e = lookup(&[("CITE_STACK_EGRESS_DENY_CIDRS", "203.0.112.0/24")]).unwrap();
        assert_eq!(
            e.proxy_env(&OutboundRules::default()),
            vec![
                "CITE_EGRESS_DENY_CIDRS=203.0.112.0/24",
                "CITE_EGRESS_MODE=public",
                "CITE_EGRESS_BLOCK_MAIL=true",
            ]
        );
        let rules = OutboundRules {
            mode: OutboundMode::Allowlist,
            allow: vec!["api.github.com".into(), "*.apple.com".into(), ".apple.com".into()],
            deny: vec!["10.0.0.66".into()],
            block_mail: false,
        };
        assert_eq!(
            e.proxy_env(&rules)[1..],
            [
                "CITE_EGRESS_MODE=allowlist",
                "CITE_EGRESS_BLOCK_MAIL=false",
                "CITE_EGRESS_ALLOW=api.github.com,.apple.com",
                "CITE_EGRESS_DENY=10.0.0.66",
            ]
        );
    }
}
