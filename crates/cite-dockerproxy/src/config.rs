use std::net::SocketAddr;
use std::path::PathBuf;

use crate::envval;

const MAX_GITHUB_URL_LEN: usize = 200;
pub const FORGES: [&str; 3] = ["github", "gitlab", "gitea"];
pub const MIN_STACK_MEMORY: i64 = 256 << 20;
pub const MIN_STACK_NANO_CPUS: i64 = 250_000_000;
const DEFAULT_MAX_MEMORY: i64 = 16 << 30;
const DEFAULT_MAX_NANO_CPUS: i64 = 8_000_000_000;
const CEILING_MEMORY: i64 = 1 << 40;
const CEILING_NANO_CPUS: i64 = 1024 * 1_000_000_000;

#[derive(Debug, Clone)]
pub struct Config {
    pub forge: Option<String>,
    pub forge_api_url: Option<String>,
    pub max_memory: i64,
    pub max_nano_cpus: i64,
    pub listen: SocketAddr,
    pub socket: PathBuf,
    pub registry: String,
    pub haproxy_container: String,
    pub edge_network: String,
    pub max_conns: usize,
    pub github_api_url: Option<String>,
    /// How executors of outbound sites reach the internet (CITE_STACK_EGRESS_MODE, default filtered).
    pub egress_mode: EgressMode,
    /// The bridge that holds only egress proxies (CITE_STACK_EGRESS_BRIDGE, default cite-egress).
    pub egress_bridge: String,
    /// The node-wide CITE_EGRESS_* entries every egress proxy must carry, in the order the connector writes them.
    pub egress_env: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    /// Executors join an internal network and reach the internet only through their stack's egress proxy.
    Filtered,
    /// Executors join their stack's egress bridge directly.
    Open,
    /// No executor gets an outbound network.
    Off,
}

/// One node-level egress list: node setting, key in the egress proxy and the rule each entry must pass.
pub type EgressNodeKey = (&'static str, &'static str, fn(&str) -> bool);

/// The node-level lists, in the order the connector emits them.
pub const EGRESS_NODE_KEYS: [EgressNodeKey; 4] = [
    ("CITE_STACK_EGRESS_ALLOW_CIDRS", "CITE_EGRESS_ALLOW_CIDRS", envval::egress_cidr),
    ("CITE_STACK_EGRESS_DENY_CIDRS", "CITE_EGRESS_DENY_CIDRS", envval::egress_cidr),
    ("CITE_STACK_EGRESS_DENY_HOSTS", "CITE_EGRESS_DENY_HOSTS", envval::egress_host),
    ("CITE_STACK_EGRESS_ALLOW_PORTS", "CITE_EGRESS_ALLOW_PORTS", envval::egress_port_range),
];

/// Trims entries and drops empty ones; the result is what both the connector and the proxy compare.
pub fn egress_setting(key: &str, raw: &str, entry_ok: fn(&str) -> bool) -> Result<String, String> {
    let entries: Vec<&str> = raw.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
    let joined = entries.join(",");
    if joined.is_empty() || envval::egress_list(&joined, entry_ok) {
        Ok(joined)
    } else {
        Err(format!(
            "{key} must be a comma list of at most 64 distinct valid entries"
        ))
    }
}

/// The node's own public addresses, appended to CITE_EGRESS_DENY_CIDRS exactly as the connector does.
pub const NODE_IPS_KEY: &str = "CITE_NODE_PUBLIC_IPS";

fn with_node_ips(key: &str, deny: &str, own: &str) -> Result<String, String> {
    let mut entries: Vec<&str> = deny.split(',').filter(|e| !e.is_empty()).collect();
    for ip in own.split(',').filter(|e| !e.is_empty()) {
        if !entries.contains(&ip) {
            entries.push(ip);
        }
    }
    let joined = entries.join(",");
    if joined.is_empty() || envval::egress_list(&joined, envval::egress_cidr) {
        Ok(joined)
    } else {
        Err(format!(
            "{key} and {NODE_IPS_KEY} together must have at most 64 entries"
        ))
    }
}

fn egress_mode(optional: impl Fn(&str) -> Option<String>) -> Result<EgressMode, String> {
    if let Some(mode) = optional("CITE_STACK_EGRESS_MODE") {
        return match mode.as_str() {
            "filtered" => Ok(EgressMode::Filtered),
            "open" => Ok(EgressMode::Open),
            "off" => Ok(EgressMode::Off),
            other => Err(format!(
                "CITE_STACK_EGRESS_MODE {other:?} must be filtered, open or off"
            )),
        };
    }
    match optional("CITE_STACK_EXECUTOR_EGRESS").as_deref() {
        None => Ok(EgressMode::Filtered),
        Some(v) if v.eq_ignore_ascii_case("true") || v == "1" => Ok(EgressMode::Filtered),
        Some(v) if v.eq_ignore_ascii_case("false") || v == "0" => Ok(EgressMode::Off),
        Some(v) => Err(format!(
            "CITE_STACK_EXECUTOR_EGRESS {v:?} must be true or false"
        )),
    }
}

// Names end up in regexes and Docker paths, so only plain name characters are accepted.
fn chars_ok(value: &str, extra: &[char]) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') || extra.contains(&c)
        })
}

// Same rules as the connector: http(s), plain host and port, plain path, no userinfo, query or fragment.
pub fn validate_github_api_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_GITHUB_URL_LEN {
        return Err(format!("longer than {MAX_GITHUB_URL_LEN} characters"));
    }
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("must start with http:// or https://")?;
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~' | ':' | '/'))
    {
        return Err("has characters that are not allowed".to_string());
    }
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let edge_ok = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    let host_ok = edge_ok(host.chars().next())
        && edge_ok(host.chars().last())
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    let port_ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 5
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    };
    if !host_ok || port.is_some_and(|p| !port_ok(p)) {
        return Err("has no valid host and port".to_string());
    }
    if path.contains("//") || path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("has an empty or relative path segment".to_string());
    }
    Ok(())
}

// Whole bytes with an optional k, m, g or t suffix (powers of 1024), optionally followed by b or ib.
pub fn parse_memory(raw: &str) -> Result<i64, String> {
    let lower = raw.trim().to_ascii_lowercase();
    let body = lower
        .strip_suffix("ib")
        .or_else(|| lower.strip_suffix('b'))
        .unwrap_or(&lower);
    let (digits, shift) = match body.chars().last() {
        Some('k') => (&body[..body.len() - 1], 10),
        Some('m') => (&body[..body.len() - 1], 20),
        Some('g') => (&body[..body.len() - 1], 30),
        Some('t') => (&body[..body.len() - 1], 40),
        _ => (body, 0),
    };
    if digits.is_empty() || digits.len() > 15 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("is not a size like 512m or 16g".to_string());
    }
    digits
        .parse::<i64>()
        .ok()
        .and_then(|n| n.checked_mul(1 << shift))
        .ok_or_else(|| "is too large".to_string())
}

// Whole or decimal CPUs with at most nine fraction digits, returned as Docker nano CPUs.
pub fn parse_cpus(raw: &str) -> Result<i64, String> {
    let text = raw.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let shaped = !whole.is_empty()
        && whole.len() <= 4
        && digits(whole)
        && fraction.len() <= 9
        && digits(fraction)
        && (!text.contains('.') || !fraction.is_empty());
    if !shaped {
        return Err("is not a CPU count like 4 or 0.5".to_string());
    }
    let nanos = format!("{fraction:0<9}").parse::<i64>().unwrap_or(0);
    let whole = whole.parse::<i64>().unwrap_or(0);
    Ok(whole * 1_000_000_000 + nanos)
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let text = |key: &str, default: &str| {
            get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let listen_raw = text("CITE_PROXY_LISTEN", "0.0.0.0:2375");
        let listen = listen_raw
            .parse()
            .map_err(|_| format!("CITE_PROXY_LISTEN {listen_raw:?} is not host:port"))?;
        let socket = text("CITE_PROXY_SOCKET", "/var/run/docker.sock");
        if !socket.starts_with('/') {
            return Err("CITE_PROXY_SOCKET must be an absolute path".to_string());
        }
        let registry = text("CITE_PROXY_REGISTRY", "ghcr.io/seggys116");
        if !chars_ok(&registry, &['/', ':'])
            || registry.contains("..")
            || registry.starts_with('/')
            || registry.ends_with('/')
        {
            return Err(format!("CITE_PROXY_REGISTRY {registry:?} is not valid"));
        }
        let haproxy_container = text("CITE_PROXY_HAPROXY_CONTAINER", "cite-node-haproxy");
        if !chars_ok(&haproxy_container, &[]) {
            return Err(format!(
                "CITE_PROXY_HAPROXY_CONTAINER {haproxy_container:?} is not valid"
            ));
        }
        let edge_network = text("CITE_PROXY_EDGE_NETWORK", "cite_edge");
        if !chars_ok(&edge_network, &[]) {
            return Err(format!(
                "CITE_PROXY_EDGE_NETWORK {edge_network:?} is not valid"
            ));
        }
        // The cap bounds memory and file descriptors; further connections wait in the kernel backlog.
        let conns_raw = text("CITE_PROXY_MAX_CONNS", "64");
        let max_conns = conns_raw
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=1024).contains(n))
            .ok_or_else(|| format!("CITE_PROXY_MAX_CONNS {conns_raw:?} must be 1 to 1024"))?;
        let github_api_url = match get("CITE_PROXY_GITHUB_API_URL")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        {
            Some(url) => {
                validate_github_api_url(&url)
                    .map_err(|e| format!("CITE_PROXY_GITHUB_API_URL {url:?} {e}"))?;
                Some(url)
            }
            None => None,
        };
        let max_memory = match get("CITE_STACK_MAX_MEM")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        {
            Some(raw) => {
                parse_memory(&raw).map_err(|e| format!("CITE_STACK_MAX_MEM {raw:?} {e}"))?
            }
            None => DEFAULT_MAX_MEMORY,
        };
        if !(MIN_STACK_MEMORY..=CEILING_MEMORY).contains(&max_memory) {
            return Err("CITE_STACK_MAX_MEM must be between 256m and 1t".to_string());
        }
        let max_nano_cpus = match get("CITE_STACK_MAX_CPUS")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        {
            Some(raw) => {
                parse_cpus(&raw).map_err(|e| format!("CITE_STACK_MAX_CPUS {raw:?} {e}"))?
            }
            None => DEFAULT_MAX_NANO_CPUS,
        };
        if !(MIN_STACK_NANO_CPUS..=CEILING_NANO_CPUS).contains(&max_nano_cpus) {
            return Err("CITE_STACK_MAX_CPUS must be between 0.25 and 1024".to_string());
        }
        let optional = |key: &str| {
            get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let forge = optional("CITE_STACK_FORGE");
        let forge_api_url = optional("CITE_STACK_FORGE_API_URL");
        if forge.is_some() != forge_api_url.is_some() {
            return Err(
                "CITE_STACK_FORGE and CITE_STACK_FORGE_API_URL must be set together".to_string(),
            );
        }
        if let Some(kind) = &forge
            && !FORGES.contains(&kind.as_str())
        {
            return Err(format!(
                "CITE_STACK_FORGE {kind:?} must be github, gitlab or gitea"
            ));
        }
        if let Some(url) = &forge_api_url {
            if !url.starts_with("https://") {
                return Err(format!("CITE_STACK_FORGE_API_URL {url:?} must be https"));
            }
            validate_github_api_url(url)
                .map_err(|e| format!("CITE_STACK_FORGE_API_URL {url:?} {e}"))?;
        }
        let egress_mode = egress_mode(optional)?;
        let egress_bridge = text("CITE_STACK_EGRESS_BRIDGE", "cite-egress");
        if !chars_ok(&egress_bridge, &[]) || egress_bridge.starts_with("cite-vol-") {
            return Err(format!(
                "CITE_STACK_EGRESS_BRIDGE {egress_bridge:?} is not valid"
            ));
        }
        let own = egress_setting(
            NODE_IPS_KEY,
            &get(NODE_IPS_KEY).unwrap_or_default(),
            envval::egress_cidr,
        )?;
        let mut egress_env = Vec::new();
        for (key, env_key, entry_ok) in EGRESS_NODE_KEYS {
            let mut value = egress_setting(key, &get(key).unwrap_or_default(), entry_ok)?;
            if env_key == "CITE_EGRESS_DENY_CIDRS" {
                value = with_node_ips(key, &value, &own)?;
            }
            if !value.is_empty() {
                egress_env.push(format!("{env_key}={value}"));
            }
        }
        Ok(Config {
            egress_mode,
            egress_bridge,
            egress_env,
            forge,
            forge_api_url,
            max_memory,
            max_nano_cpus,
            listen,
            socket: PathBuf::from(socket),
            registry,
            haproxy_container,
            edge_network,
            max_conns,
            github_api_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, String> {
        Config::from_lookup(|k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn defaults_match_the_compose_overlay() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.listen.to_string(), "0.0.0.0:2375");
        assert_eq!(c.socket, PathBuf::from("/var/run/docker.sock"));
        assert_eq!(c.registry, "ghcr.io/seggys116");
        assert_eq!(c.haproxy_container, "cite-node-haproxy");
        assert_eq!(c.edge_network, "cite_edge");
        assert_eq!(c.max_conns, 64);
        assert_eq!(c.github_api_url, None);
        assert_eq!(c.egress_mode, EgressMode::Filtered);
        assert_eq!(c.egress_bridge, "cite-egress");
        assert!(c.egress_env.is_empty());
    }

    #[test]
    fn egress_mode_reads_the_new_setting_then_the_old_boolean() {
        for (raw, want) in [
            ("filtered", EgressMode::Filtered),
            ("open", EgressMode::Open),
            ("off", EgressMode::Off),
        ] {
            assert_eq!(cfg(&[("CITE_STACK_EGRESS_MODE", raw)]).unwrap().egress_mode, want);
        }
        for (raw, want) in [
            ("false", EgressMode::Off),
            ("0", EgressMode::Off),
            ("TRUE", EgressMode::Filtered),
            ("1", EgressMode::Filtered),
        ] {
            let c = cfg(&[("CITE_STACK_EXECUTOR_EGRESS", raw)]).unwrap();
            assert_eq!(c.egress_mode, want, "{raw}");
        }
        let both = cfg(&[
            ("CITE_STACK_EGRESS_MODE", "open"),
            ("CITE_STACK_EXECUTOR_EGRESS", "false"),
        ])
        .unwrap();
        assert_eq!(both.egress_mode, EgressMode::Open, "the new setting wins");
        assert!(cfg(&[("CITE_STACK_EXECUTOR_EGRESS", "off")]).is_err());
        assert!(cfg(&[("CITE_STACK_EGRESS_MODE", "Filtered")]).is_err());
        assert!(cfg(&[("CITE_STACK_EGRESS_MODE", "on")]).is_err());
    }

    #[test]
    fn egress_lists_are_normalised_and_validated() {
        let c = cfg(&[
            ("CITE_STACK_EGRESS_ALLOW_CIDRS", " 192.168.10.0/24 , fd00::/8,"),
            ("CITE_STACK_EGRESS_DENY_HOSTS", "evil.example,.ads.example"),
            ("CITE_STACK_EGRESS_ALLOW_PORTS", "80,443,8000-8100"),
            ("CITE_STACK_EGRESS_BRIDGE", "my-egress"),
        ])
        .unwrap();
        assert_eq!(
            c.egress_env,
            vec![
                "CITE_EGRESS_ALLOW_CIDRS=192.168.10.0/24,fd00::/8",
                "CITE_EGRESS_DENY_HOSTS=evil.example,.ads.example",
                "CITE_EGRESS_ALLOW_PORTS=80,443,8000-8100",
            ]
        );
        assert_eq!(c.egress_bridge, "my-egress");
        for pairs in [
            [("CITE_STACK_EGRESS_ALLOW_CIDRS", "10.0.0.0/33")],
            [("CITE_STACK_EGRESS_ALLOW_CIDRS", "010.0.0.0/8")],
            [("CITE_STACK_EGRESS_ALLOW_CIDRS", "example.com")],
            [("CITE_STACK_EGRESS_DENY_CIDRS", "10.0.0.1,10.0.0.1")],
            [("CITE_STACK_EGRESS_DENY_HOSTS", "Evil.example")],
            [("CITE_STACK_EGRESS_DENY_HOSTS", "10.0.0.1")],
            [("CITE_STACK_EGRESS_ALLOW_PORTS", "0")],
            [("CITE_STACK_EGRESS_ALLOW_PORTS", "443-80")],
            [("CITE_STACK_EGRESS_BRIDGE", "a b")],
        ] {
            assert!(cfg(&pairs).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn node_public_ips_join_the_deny_list_like_the_connector() {
        let c = cfg(&[
            ("CITE_STACK_EGRESS_DENY_CIDRS", "198.51.100.0/24,203.0.113.10"),
            ("CITE_NODE_PUBLIC_IPS", " 203.0.113.10 , 203.0.113.11"),
        ])
        .unwrap();
        assert_eq!(
            c.egress_env,
            vec!["CITE_EGRESS_DENY_CIDRS=198.51.100.0/24,203.0.113.10,203.0.113.11"]
        );
        let alone = cfg(&[("CITE_NODE_PUBLIC_IPS", "2001:db8::10")]).unwrap();
        assert_eq!(alone.egress_env, vec!["CITE_EGRESS_DENY_CIDRS=2001:db8::10"]);
        for bad in ["example.com", "::ffff:1.2.3.4", "1.2.3.4,1.2.3.4"] {
            assert!(cfg(&[("CITE_NODE_PUBLIC_IPS", bad)]).is_err(), "{bad}");
        }
        let many = (0..40).map(|i| format!("10.0.{i}.1")).collect::<Vec<_>>().join(",");
        let more = (0..40).map(|i| format!("10.1.{i}.1")).collect::<Vec<_>>().join(",");
        assert!(cfg(&[
            ("CITE_STACK_EGRESS_DENY_CIDRS", many.as_str()),
            ("CITE_NODE_PUBLIC_IPS", more.as_str())
        ])
        .is_err());
    }

    #[test]
    fn github_api_url_is_trimmed_and_validated() {
        let c = cfg(&[(
            "CITE_PROXY_GITHUB_API_URL",
            " https://ghe.example.com/api/v3 ",
        )])
        .unwrap();
        assert_eq!(
            c.github_api_url.as_deref(),
            Some("https://ghe.example.com/api/v3")
        );
        let blank = cfg(&[("CITE_PROXY_GITHUB_API_URL", "  ")]).unwrap();
        assert_eq!(blank.github_api_url, None);
        for bad in [
            "ftp://ghe.example.com",
            "ghe.example.com",
            "https://user:pw@ghe.example.com",
            "https://user@ghe.example.com",
            "https://ghe.example.com?x=1",
            "https://ghe.example.com/#frag",
            "https://ghe.example.com:0",
            "https://ghe.example.com:99999",
            "https://ghe.example.com/a b",
            "https://ghe.example.com/%2e%2e",
            "https://ghe.example.com//x",
            "https://ghe.example.com/../x",
            "https://",
            "https://.example.com",
            "HTTPS://ghe.example.com",
            "https://ghe.example.com\\evil.test",
            "https://ghe.example.com/\u{e9}",
        ] {
            assert!(
                cfg(&[("CITE_PROXY_GITHUB_API_URL", bad)]).is_err(),
                "{bad:?}"
            );
        }
        let long = format!("https://{}.example.com", "a".repeat(200));
        assert!(cfg(&[("CITE_PROXY_GITHUB_API_URL", &long)]).is_err());
    }

    #[test]
    fn hostile_values_are_refused() {
        for pairs in [
            [("CITE_PROXY_LISTEN", "nonsense")],
            [("CITE_PROXY_SOCKET", "relative.sock")],
            [("CITE_PROXY_REGISTRY", "ghcr.io/../x")],
            [("CITE_PROXY_REGISTRY", "/ghcr.io")],
            [("CITE_PROXY_REGISTRY", "a b")],
            [("CITE_PROXY_HAPROXY_CONTAINER", "a/b")],
            [("CITE_PROXY_EDGE_NETWORK", "x y")],
            [("CITE_PROXY_MAX_CONNS", "0")],
            [("CITE_PROXY_MAX_CONNS", "5000")],
        ] {
            assert!(cfg(&pairs).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn forge_settings_are_optional_paired_and_https_only() {
        let c = cfg(&[]).unwrap();
        assert_eq!((c.forge, c.forge_api_url), (None, None));
        let c = cfg(&[
            ("CITE_STACK_FORGE", " gitlab "),
            (
                "CITE_STACK_FORGE_API_URL",
                "https://gitlab.example.com/api/v4",
            ),
        ])
        .unwrap();
        assert_eq!(c.forge.as_deref(), Some("gitlab"));
        assert_eq!(
            c.forge_api_url.as_deref(),
            Some("https://gitlab.example.com/api/v4")
        );
        for pairs in [
            vec![("CITE_STACK_FORGE", "gitlab")],
            vec![("CITE_STACK_FORGE_API_URL", "https://gitlab.example.com")],
            vec![
                ("CITE_STACK_FORGE", "bitbucket"),
                ("CITE_STACK_FORGE_API_URL", "https://x.example.com"),
            ],
            vec![
                ("CITE_STACK_FORGE", "GitLab"),
                ("CITE_STACK_FORGE_API_URL", "https://x.example.com"),
            ],
            vec![
                ("CITE_STACK_FORGE", "gitea"),
                ("CITE_STACK_FORGE_API_URL", "http://gitea.example.com"),
            ],
            vec![
                ("CITE_STACK_FORGE", "gitea"),
                ("CITE_STACK_FORGE_API_URL", "https://user@gitea.example.com"),
            ],
        ] {
            assert!(cfg(&pairs).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn stack_limits_default_to_sixteen_gib_and_eight_cpus() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.max_memory, 16 << 30);
        assert_eq!(c.max_nano_cpus, 8_000_000_000);
    }

    #[test]
    fn stack_limits_are_read_from_the_environment() {
        let c = cfg(&[
            ("CITE_STACK_MAX_MEM", " 32G "),
            ("CITE_STACK_MAX_CPUS", "12.5"),
        ])
        .unwrap();
        assert_eq!(c.max_memory, 32 << 30);
        assert_eq!(c.max_nano_cpus, 12_500_000_000);
        let low = cfg(&[
            ("CITE_STACK_MAX_MEM", "256m"),
            ("CITE_STACK_MAX_CPUS", "0.25"),
        ])
        .unwrap();
        assert_eq!(low.max_memory, 256 << 20);
        assert_eq!(low.max_nano_cpus, 250_000_000);
        let blank = cfg(&[("CITE_STACK_MAX_MEM", " "), ("CITE_STACK_MAX_CPUS", "")]).unwrap();
        assert_eq!(blank.max_memory, 16 << 30);
    }

    #[test]
    fn stack_limit_values_outside_the_allowed_range_are_refused() {
        for pairs in [
            [("CITE_STACK_MAX_MEM", "255m")],
            [("CITE_STACK_MAX_MEM", "0")],
            [("CITE_STACK_MAX_MEM", "2t")],
            [("CITE_STACK_MAX_MEM", "lots")],
            [("CITE_STACK_MAX_MEM", "-4g")],
            [("CITE_STACK_MAX_MEM", "1.5g")],
            [("CITE_STACK_MAX_MEM", "g")],
            [("CITE_STACK_MAX_MEM", "99999999999999t")],
            [("CITE_STACK_MAX_CPUS", "0.2")],
            [("CITE_STACK_MAX_CPUS", "0")],
            [("CITE_STACK_MAX_CPUS", "1025")],
            [("CITE_STACK_MAX_CPUS", "-1")],
            [("CITE_STACK_MAX_CPUS", "4.")],
            [("CITE_STACK_MAX_CPUS", ".5")],
            [("CITE_STACK_MAX_CPUS", "1.0000000001")],
            [("CITE_STACK_MAX_CPUS", "1e1")],
            [("CITE_STACK_MAX_CPUS", "four")],
        ] {
            assert!(cfg(&pairs).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn sizes_accept_the_usual_suffixes() {
        for (text, want) in [
            ("1024", 1024),
            ("1k", 1 << 10),
            ("512m", 512 << 20),
            ("512MB", 512 << 20),
            ("16g", 16 << 30),
            ("16GiB", 16 << 30),
            ("1t", 1 << 40),
        ] {
            assert_eq!(parse_memory(text), Ok(want), "{text}");
        }
        assert_eq!(parse_cpus("4"), Ok(4_000_000_000));
        assert_eq!(parse_cpus("0.25"), Ok(250_000_000));
        assert_eq!(parse_cpus("1.000000001"), Ok(1_000_000_001));
    }
}
