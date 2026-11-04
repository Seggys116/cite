use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;
use regex::Regex;
use thiserror::Error;

use crate::model::{EdgeConfig, EdgeSettings, FirewallRule, HealthCheck, MaintenancePage, Site};

pub const MAX_PAGE_BYTES: usize = 256 * 1024;
const MAX_TARGETS: usize = 32;
const MAX_PATTERN_LEN: usize = 256;
const MAX_TEXT_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

pub(crate) fn invalid<T>(msg: String) -> Result<T, ValidationError> {
    Err(ValidationError(msg))
}

pub fn is_valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    let first_ok = b
        .first()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && b.len() <= 40
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub(crate) fn is_hostname(s: &str, allow_underscore: bool) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        let b = label.as_bytes();
        let edge_ok = |c: Option<&u8>| c.is_some_and(|c| c.is_ascii_alphanumeric());
        b.len() <= 63
            && edge_ok(b.first())
            && edge_ok(b.last())
            && b.iter().all(|c| {
                c.is_ascii_alphanumeric() || *c == b'-' || (allow_underscore && *c == b'_')
            })
    })
}

// These words end or alter an ACL pattern list in haproxy, so they cannot be used as values.
fn is_reserved_token(s: &str) -> bool {
    ["or", "and", "if", "unless", "{", "}", "||", "&&", "!"]
        .iter()
        .any(|t| s.eq_ignore_ascii_case(t))
}

pub(crate) fn validate_host(what: &str, host: &str) -> Result<(), ValidationError> {
    let name = host.strip_prefix("*.").unwrap_or(host);
    if !is_hostname(name, false) || is_reserved_token(name) {
        return invalid(format!(
            "{what}: {host:?} is not a valid hostname or *.wildcard"
        ));
    }
    Ok(())
}

// Values become bare haproxy words: printable ASCII only, no # or quotes; spell spaces as \x20.
pub(crate) fn validate_pattern(what: &str, s: &str, regex: bool) -> Result<(), ValidationError> {
    if s.is_empty() || s.len() > MAX_PATTERN_LEN {
        return invalid(format!("{what}: must be 1 to {MAX_PATTERN_LEN} characters"));
    }
    if let Some(c) = s
        .chars()
        .find(|c| !c.is_ascii_graphic() || matches!(*c, '#' | '"' | '\''))
    {
        return invalid(format!(
            "{what}: character {c:?} is not allowed (use \\x20 style escapes for spaces)"
        ));
    }
    if s.starts_with('-') || is_reserved_token(s) {
        return invalid(format!("{what}: {s:?} is not allowed as a pattern"));
    }
    // haproxy collapses a doubled backslash and strips a trailing one, changing the pattern
    if s.contains("\\\\") || s.ends_with('\\') {
        return invalid(format!("{what}: dangling or doubled backslash in {s:?}"));
    }
    // haproxy expands $NAME and ${NAME} from the environment in unquoted words
    let bytes = s.as_bytes();
    let env_like = bytes
        .windows(2)
        .any(|w| w[0] == b'$' && (w[1].is_ascii_alphanumeric() || w[1] == b'_' || w[1] == b'{'));
    if env_like {
        return invalid(format!(
            "{what}: $ followed by a name is not allowed in {s:?}"
        ));
    }
    if regex {
        if let Err(e) = Regex::new(s) {
            return invalid(format!("{what}: regex {s:?} does not compile: {e}"));
        }
    } else if !s.starts_with('/') || s.contains('\\') {
        return invalid(format!(
            "{what}: {s:?} must start with / and contain no backslash"
        ));
    }
    Ok(())
}

// Returns the normalised form so the rendered text never echoes raw user input.
pub(crate) fn parse_cidr(s: &str) -> Option<String> {
    if let Ok(net) = IpNet::from_str(s) {
        return Some(net.to_string());
    }
    IpAddr::from_str(s).ok().map(|ip| ip.to_string())
}

pub(crate) fn valid_target_addr(addr: &str) -> bool {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p > 0);
    if !port_ok {
        return false;
    }
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => inner.parse::<Ipv6Addr>().is_ok(),
        None => is_hostname(host, true),
    }
}

fn validate_text(what: &str, s: &str) -> Result<(), ValidationError> {
    if s.chars().count() > MAX_TEXT_LEN || s.chars().any(char::is_control) {
        return invalid(format!(
            "{what}: must be at most {MAX_TEXT_LEN} characters without control characters"
        ));
    }
    Ok(())
}

fn validate_id(what: &str, id: &str) -> Result<(), ValidationError> {
    if !is_valid_id(id) {
        return invalid(format!(
            "{what}: id {id:?} must match ^[a-z0-9][a-z0-9-]{{0,39}}$"
        ));
    }
    Ok(())
}

fn check_range(what: &str, v: u64, lo: u64, hi: u64) -> Result<(), ValidationError> {
    if v < lo || v > hi {
        return invalid(format!("{what}: {v} is outside {lo}..={hi}"));
    }
    Ok(())
}

fn validate_health(site_id: &str, h: &HealthCheck) -> Result<(), ValidationError> {
    let what = format!("site {site_id}: health");
    let p = &h.path;
    let path_ok = p.starts_with('/')
        && p.len() <= 512
        && p.chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '#' | '"' | '\'' | '\\' | '$'));
    if !path_ok {
        return invalid(format!(
            "{what} path {p:?} must start with / and be plain printable ASCII"
        ));
    }
    check_range(
        &format!("{what} interval_ms"),
        h.interval_ms.into(),
        100,
        600_000,
    )?;
    check_range(
        &format!("{what} timeout_ms"),
        h.timeout_ms.into(),
        100,
        60_000,
    )?;
    check_range(&format!("{what} rise"), h.rise.into(), 1, 100)?;
    check_range(&format!("{what} fall"), h.fall.into(), 1, 100)
}

pub fn validate_site(site: &Site) -> Result<(), ValidationError> {
    let what = format!("site {}", site.id);
    validate_id("site", &site.id)?;
    validate_text(&format!("{what} name"), &site.name)?;
    if site.hosts.is_empty() || site.hosts.len() > 64 {
        return invalid(format!("{what}: needs 1 to 64 hosts"));
    }
    for host in &site.hosts {
        validate_host(&format!("{what} host"), host)?;
    }
    if let Some(re) = &site.path_regex {
        validate_pattern(&format!("{what} path_regex"), re, true)?;
    }
    for (slot, up) in [("blue", &site.blue), ("green", &site.green)] {
        if up.targets.len() > MAX_TARGETS {
            return invalid(format!(
                "{what}: {slot} has more than {MAX_TARGETS} targets"
            ));
        }
        for t in &up.targets {
            if !valid_target_addr(&t.addr) {
                return invalid(format!(
                    "{what}: {slot} target {:?} must be host:port with port 1..=65535",
                    t.addr
                ));
            }
            check_range(&format!("{what} {slot} weight"), t.weight.into(), 0, 256)?;
        }
    }
    if let Some(pid) = &site.maintenance.page_id {
        validate_id(&format!("{what} maintenance page"), pid)?;
    }
    validate_health(&site.id, &site.health)
}

pub fn validate_rule(rule: &FirewallRule) -> Result<(), ValidationError> {
    let what = format!("rule {}", rule.id);
    validate_id("rule", &rule.id)?;
    validate_text(&format!("{what} name"), &rule.name)?;
    if let Some(site) = &rule.site {
        validate_id(&format!("{what} site"), site)?;
    }
    let m = &rule.matchers;
    // a rule without matchers would block every request
    if m.path_regex.is_none()
        && m.path_prefix.is_none()
        && m.methods.is_empty()
        && m.user_agent_regex.is_none()
        && m.cidrs.is_empty()
        && m.host.is_none()
    {
        return invalid(format!("{what}: needs at least one matcher"));
    }
    if let Some(re) = &m.path_regex {
        validate_pattern(&format!("{what} path_regex"), re, true)?;
    }
    if let Some(p) = &m.path_prefix {
        validate_pattern(&format!("{what} path_prefix"), p, false)?;
    }
    if let Some(re) = &m.user_agent_regex {
        validate_pattern(&format!("{what} user_agent_regex"), re, true)?;
    }
    if let Some(h) = &m.host {
        validate_host(&format!("{what} host"), h)?;
    }
    if m.methods.len() > 16 {
        return invalid(format!("{what}: at most 16 methods"));
    }
    for method in &m.methods {
        let ok = !method.is_empty()
            && method.len() <= 24
            && method.bytes().all(|c| c.is_ascii_uppercase() || c == b'-');
        if !ok {
            return invalid(format!(
                "{what}: method {method:?} must be an uppercase token"
            ));
        }
    }
    if m.cidrs.len() > 256 {
        return invalid(format!("{what}: at most 256 cidrs"));
    }
    for c in &m.cidrs {
        if parse_cidr(c).is_none() {
            return invalid(format!("{what}: {c:?} is not a CIDR or IP address"));
        }
    }
    Ok(())
}

pub fn validate_page(page: &MaintenancePage) -> Result<(), ValidationError> {
    let what = format!("page {}", page.id);
    validate_id("page", &page.id)?;
    validate_text(&format!("{what} name"), &page.name)?;
    if page.html.len() > MAX_PAGE_BYTES {
        return invalid(format!("{what}: html exceeds {MAX_PAGE_BYTES} bytes"));
    }
    check_range(&format!("{what} status"), page.status.into(), 400, 599)
}

pub fn validate_settings(s: &EdgeSettings) -> Result<(), ValidationError> {
    check_range("settings http_port", s.http_port.into(), 1, 65535)?;
    if let Some(p) = s.https_port {
        check_range("settings https_port", p.into(), 1, 65535)?;
        if p == s.http_port {
            return invalid("settings: https_port must differ from http_port".into());
        }
    }
    check_range("settings max_conn", s.max_conn.into(), 1, 1_000_000)?;
    check_range(
        "settings client_timeout_ms",
        s.client_timeout_ms.into(),
        100,
        3_600_000,
    )?;
    check_range(
        "settings server_timeout_ms",
        s.server_timeout_ms.into(),
        100,
        3_600_000,
    )?;
    check_range(
        "settings connect_timeout_ms",
        s.connect_timeout_ms.into(),
        100,
        600_000,
    )?;
    if let Some(r) = s.per_ip_rate_limit {
        check_range("settings per_ip_rate_limit", r.into(), 1, 1_000_000)?;
    }
    if let Some(b) = s.max_body_bytes {
        check_range("settings max_body_bytes", b, 1, 1 << 40)?;
    }
    let r = &s.retention;
    check_range(
        "retention recent_events",
        r.recent_events as u64,
        0,
        200_000,
    )?;
    check_range(
        "retention persist_interval_secs",
        r.persist_interval_secs.into(),
        5,
        3600,
    )?;
    check_range(
        "retention minute_buckets_hours",
        r.minute_buckets_hours.into(),
        1,
        8760,
    )?;
    check_range(
        "retention hour_buckets_days",
        r.hour_buckets_days.into(),
        1,
        3650,
    )?;
    check_range("retention audit_days", r.audit_days.into(), 1, 3650)
}

fn check_unique<'a>(
    kind: &str,
    ids: impl Iterator<Item = &'a String>,
) -> Result<HashSet<&'a str>, ValidationError> {
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            return invalid(format!("{kind} id {id:?} is used more than once"));
        }
    }
    Ok(seen)
}

pub fn validate_config(cfg: &EdgeConfig) -> Result<(), ValidationError> {
    // caps keep the rendered config and the reload time bounded
    if cfg.sites.len() > 1000 || cfg.pages.len() > 1000 || cfg.firewall.len() > 5000 {
        return invalid("config has too many sites, pages or firewall rules".into());
    }
    let site_ids = check_unique("site", cfg.sites.iter().map(|s| &s.id))?;
    let page_ids = check_unique("page", cfg.pages.iter().map(|p| &p.id))?;
    check_unique("rule", cfg.firewall.iter().map(|r| &r.id))?;
    validate_settings(&cfg.settings)?;
    for page in &cfg.pages {
        validate_page(page)?;
    }
    for site in &cfg.sites {
        validate_site(site)?;
        if let Some(pid) = &site.maintenance.page_id
            && !page_ids.contains(pid.as_str())
        {
            return invalid(format!(
                "site {}: maintenance page {pid:?} does not exist",
                site.id
            ));
        }
    }
    for rule in &cfg.firewall {
        validate_rule(rule)?;
        if let Some(sid) = &rule.site
            && !site_ids.contains(sid.as_str())
        {
            return invalid(format!("rule {}: site {sid:?} does not exist", rule.id));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use crate::model::*;

    pub fn site(id: &str, host: &str) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: vec![host.into()],
            path_regex: None,
            kind: SiteKind::Site,
            blue: Upstream {
                targets: vec![Target {
                    addr: "10.0.0.1:8080".into(),
                    weight: 100,
                }],
                label: None,
            },
            green: Upstream::default(),
            active: Slot::Blue,
            maintenance: Maintenance::default(),
            health: HealthCheck::default(),
            source: None,
            history: vec![],
        }
    }

    pub fn rule(id: &str, matchers: Matchers) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            name: id.into(),
            enabled: true,
            action: FirewallAction::Deny,
            matchers,
            site: None,
        }
    }

    pub fn config(sites: Vec<Site>) -> EdgeConfig {
        EdgeConfig {
            version: CONFIG_VERSION,
            sites,
            pages: vec![],
            firewall: vec![],
            settings: EdgeSettings::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::model::Matchers;
    use proptest::prelude::*;

    #[test]
    fn id_shape() {
        assert!(is_valid_id("a"));
        assert!(is_valid_id("my-site-1"));
        assert!(is_valid_id(&"a".repeat(40)));
        assert!(!is_valid_id(&"a".repeat(41)));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("-a"));
        assert!(!is_valid_id("A"));
        assert!(!is_valid_id("a_b"));
        assert!(!is_valid_id("a\n"));
    }

    #[test]
    fn hosts_reject_injection() {
        for bad in [
            "a.com\nbackend x",
            "a.com #x",
            "a\"b.com",
            "a b.com",
            "a.com'",
            "",
            "*.",
            "or",
        ] {
            assert!(validate_site(&site("s", bad)).is_err(), "{bad:?} accepted");
        }
        assert!(validate_site(&site("s", &format!("{}.com", "a".repeat(64)))).is_err());
    }

    #[test]
    fn hosts_accept_plain_and_wildcard() {
        for ok in [
            "example.com",
            "*.example.com",
            "a-b.c.example.org",
            "localhost",
        ] {
            assert!(validate_site(&site("s", ok)).is_ok(), "{ok:?} rejected");
        }
    }

    #[test]
    fn regex_rejects_unsafe_characters() {
        for bad in [
            "a b", "a#b", "a\"b", "a'b", "a\nb", "^/x\\", "a\\\\b", "$HOME", "${X}", "-m", "or",
        ] {
            assert!(
                validate_pattern("t", bad, true).is_err(),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn regex_must_compile_and_fit() {
        assert!(validate_pattern("t", "(unclosed", true).is_err());
        assert!(validate_pattern("t", &"a".repeat(257), true).is_err());
        assert!(validate_pattern("t", &"a".repeat(256), true).is_ok());
        assert!(validate_pattern("t", "^/api/v[0-9]+/\\.well-known$", true).is_ok());
        assert!(validate_pattern("t", "(?i)(^|/)\\.env(/|$)", true).is_ok());
    }

    #[test]
    fn path_prefix_needs_slash() {
        assert!(validate_pattern("t", "/admin", false).is_ok());
        assert!(validate_pattern("t", "admin", false).is_err());
        assert!(validate_pattern("t", "/a\\b", false).is_err());
    }

    #[test]
    fn target_addresses() {
        for ok in [
            "10.0.0.1:80",
            "app.internal:8080",
            "[::1]:3000",
            "my_app:1",
            "h:65535",
        ] {
            assert!(valid_target_addr(ok), "{ok} rejected");
        }
        for bad in [
            "10.0.0.1",
            "10.0.0.1:0",
            "10.0.0.1:65536",
            "http://a:80",
            "u@a:80",
            "a b:80",
            "a:80\nserver x",
            "[::1:80",
            "[nope]:80",
            ":80",
            "a:",
            "a/b:80",
        ] {
            assert!(!valid_target_addr(bad), "{bad:?} accepted");
        }
    }

    #[test]
    fn target_limit_and_weight() {
        let mut s = site("s", "a.com");
        s.blue.targets = (0..33)
            .map(|i| crate::model::Target {
                addr: format!("h{i}:80"),
                weight: 1,
            })
            .collect();
        assert!(validate_site(&s).is_err());
        s.blue.targets.truncate(32);
        assert!(validate_site(&s).is_ok());
        s.blue.targets[0].weight = 257;
        assert!(validate_site(&s).is_err());
    }

    #[test]
    fn health_path_checks() {
        let mut s = site("s", "a.com");
        s.health.path = "healthz".into();
        assert!(validate_site(&s).is_err());
        s.health.path = "/a b".into();
        assert!(validate_site(&s).is_err());
        s.health.path = "/healthz?x=1".into();
        assert!(validate_site(&s).is_ok());
    }

    #[test]
    fn rule_needs_a_matcher_and_valid_values() {
        assert!(validate_rule(&rule("r", Matchers::default())).is_err());
        let m = Matchers {
            cidrs: vec!["10.0.0.0/8".into(), "::1".into(), "1.2.3.4".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_ok());
        let m = Matchers {
            cidrs: vec!["10.0.0.0/33".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
        let m = Matchers {
            methods: vec!["get".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
        let m = Matchers {
            methods: vec!["GET\nX".into()],
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
        let m = Matchers {
            user_agent_regex: Some("bad agent".into()),
            ..Default::default()
        };
        assert!(validate_rule(&rule("r", m)).is_err());
    }

    #[test]
    fn config_checks_references_and_uniqueness() {
        let mut cfg = config(vec![site("a", "a.com"), site("a", "b.com")]);
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("\"a\""));
        cfg.sites[1].id = "b".into();
        assert!(validate_config(&cfg).is_ok());
        cfg.sites[0].maintenance.page_id = Some("nope".into());
        assert!(
            validate_config(&cfg)
                .unwrap_err()
                .to_string()
                .contains("nope")
        );
        cfg.sites[0].maintenance.page_id = None;
        let mut r = rule(
            "r1",
            Matchers {
                path_prefix: Some("/x".into()),
                ..Default::default()
            },
        );
        r.site = Some("ghost".into());
        cfg.firewall.push(r);
        assert!(
            validate_config(&cfg)
                .unwrap_err()
                .to_string()
                .contains("ghost")
        );
    }

    #[test]
    fn page_limits() {
        let mut p = crate::model::MaintenancePage {
            id: "p".into(),
            name: "p".into(),
            html: "x".repeat(MAX_PAGE_BYTES),
            status: 503,
        };
        assert!(validate_page(&p).is_ok());
        p.html.push('x');
        assert!(validate_page(&p).is_err());
        p.html.clear();
        p.status = 200;
        assert!(validate_page(&p).is_err());
        p.status = 503;
        p.id = "p\nq".into();
        assert!(validate_page(&p).is_err());
    }

    #[test]
    fn settings_bounds() {
        let mut s = EdgeSettings::default();
        assert!(validate_settings(&s).is_ok());
        s.https_port = Some(80);
        assert!(validate_settings(&s).is_err());
        s.https_port = None;
        s.retention.persist_interval_secs = 4;
        assert!(validate_settings(&s).is_err());
        s.retention.persist_interval_secs = 60;
        s.retention.recent_events = 200_001;
        assert!(validate_settings(&s).is_err());
        s.retention.recent_events = 5000;
        s.retention.audit_days = 3651;
        assert!(validate_settings(&s).is_err());
    }

    proptest! {
        #[test]
        fn random_hosts_never_pass_with_unsafe_chars(host in ".{0,40}") {
            if validate_site(&site("s", &host)).is_ok() {
                let name = host.strip_prefix("*.").unwrap_or(&host);
                prop_assert!(name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'));
            }
        }
    }
}
