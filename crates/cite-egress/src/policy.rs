use std::net::IpAddr;

use crate::addr::{Cidr, Class, Host, classify};

const MAX_ENTRIES: usize = 64;
/// Mail submission and relay ports, refused by default so a site cannot be turned into a spam relay.
pub const MAIL_PORTS: [u16; 3] = [25, 465, 587];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Any public destination, plus private ones the site allows explicitly.
    Public,
    /// Only destinations on the site's allow list.
    Allowlist,
}

/// Why a destination was refused; the text is what the client sees in the 403 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Internal,
    NodeDenied,
    SiteDenied,
    NotAllowlisted,
    Port,
    BadHost,
}

impl Reason {
    pub fn text(self) -> &'static str {
        match self {
            Reason::Internal => "destination is a private or internal address",
            Reason::NodeDenied => "destination is blocked by the node's egress policy",
            Reason::SiteDenied => "destination is blocked by the site's outbound rules",
            Reason::NotAllowlisted => "destination is not on the site's outbound allowlist",
            Reason::Port => "destination port is not allowed",
            Reason::BadHost => "destination host is not a valid name or address",
        }
    }
}

/// A host rule: an exact name, or with a leading dot the name and every subdomain of it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostRule {
    name: String,
    subdomains: bool,
}

impl HostRule {
    fn matches(&self, host: &str, always_suffix: bool) -> bool {
        host == self.name
            || ((self.subdomains || always_suffix)
                && host
                    .strip_suffix(self.name.as_str())
                    .is_some_and(|rest| rest.ends_with('.')))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Rules {
    cidrs: Vec<Cidr>,
    hosts: Vec<HostRule>,
}

impl Rules {
    fn cidr_hit(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }

    fn host_hit(&self, host: Option<&str>, always_suffix: bool) -> bool {
        host.is_some_and(|h| self.hosts.iter().any(|r| r.matches(h, always_suffix)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    node_allow: Vec<Cidr>,
    node_deny: Rules,
    ports: Option<Vec<(u16, u16)>>,
    mode: Mode,
    site_allow: Rules,
    site_deny: Rules,
    block_mail: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            node_allow: Vec::new(),
            node_deny: Rules::default(),
            ports: None,
            mode: Mode::Public,
            site_allow: Rules::default(),
            site_deny: Rules::default(),
            block_mail: true,
        }
    }
}

fn items(key: &str, raw: &str) -> Result<Vec<String>, String> {
    let list: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if list.len() > MAX_ENTRIES {
        return Err(format!("{key} has more than {MAX_ENTRIES} entries"));
    }
    Ok(list)
}

fn host_rule(entry: &str) -> Option<HostRule> {
    let (name, subdomains) = match entry.strip_prefix("*.").or_else(|| entry.strip_prefix('.')) {
        Some(rest) => (rest, true),
        None => (entry, false),
    };
    match crate::addr::parse_host(name)? {
        Host::Name(n) if n == name => Some(HostRule { name: n, subdomains }),
        _ => None,
    }
}

fn cidr_list(key: &str, raw: &str) -> Result<Vec<Cidr>, String> {
    items(key, raw)?
        .iter()
        .map(|e| Cidr::parse(e).ok_or_else(|| format!("{key} entry {e:?} is not an IP or CIDR")))
        .collect()
}

fn mixed_list(key: &str, raw: &str) -> Result<Rules, String> {
    let mut rules = Rules::default();
    for e in items(key, raw)? {
        if let Some(c) = Cidr::parse(&e) {
            rules.cidrs.push(c);
        } else if let Some(h) = host_rule(&e) {
            rules.hosts.push(h);
        } else {
            return Err(format!("{key} entry {e:?} is not a CIDR or host name"));
        }
    }
    Ok(rules)
}

fn port_list(key: &str, raw: &str) -> Result<Option<Vec<(u16, u16)>>, String> {
    let list = items(key, raw)?;
    if list.is_empty() {
        return Ok(None);
    }
    let port = |p: &str| crate::addr::parse_port(p);
    list.iter()
        .map(|e| {
            let range = match e.split_once('-') {
                Some((a, b)) => port(a).zip(port(b)).filter(|(a, b)| a <= b),
                None => port(e).map(|p| (p, p)),
            };
            range.ok_or_else(|| format!("{key} entry {e:?} is not a port or port range"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

impl Policy {
    pub fn from_env() -> Result<Policy, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Policy, String> {
        let text = |k: &str| get(k).unwrap_or_default();
        let mut node_deny = Rules {
            cidrs: cidr_list("CITE_EGRESS_DENY_CIDRS", &text("CITE_EGRESS_DENY_CIDRS"))?,
            hosts: Vec::new(),
        };
        for e in items("CITE_EGRESS_DENY_HOSTS", &text("CITE_EGRESS_DENY_HOSTS"))? {
            node_deny.hosts.push(
                host_rule(&e)
                    .ok_or_else(|| format!("CITE_EGRESS_DENY_HOSTS entry {e:?} is not a host name"))?,
            );
        }
        let mode = match text("CITE_EGRESS_MODE").trim() {
            "" | "public" => Mode::Public,
            "allowlist" => Mode::Allowlist,
            other => return Err(format!("CITE_EGRESS_MODE {other:?} must be public or allowlist")),
        };
        let block_mail = match text("CITE_EGRESS_BLOCK_MAIL").trim() {
            "" | "true" => true,
            "false" => false,
            other => return Err(format!("CITE_EGRESS_BLOCK_MAIL {other:?} must be true or false")),
        };
        let site_allow = mixed_list("CITE_EGRESS_ALLOW", &text("CITE_EGRESS_ALLOW"))?;
        if mode == Mode::Allowlist && site_allow.cidrs.is_empty() && site_allow.hosts.is_empty() {
            return Err("CITE_EGRESS_MODE=allowlist needs at least one CITE_EGRESS_ALLOW entry".to_string());
        }
        Ok(Policy {
            node_allow: cidr_list("CITE_EGRESS_ALLOW_CIDRS", &text("CITE_EGRESS_ALLOW_CIDRS"))?,
            node_deny,
            ports: port_list("CITE_EGRESS_ALLOW_PORTS", &text("CITE_EGRESS_ALLOW_PORTS"))?,
            mode,
            site_allow,
            site_deny: mixed_list("CITE_EGRESS_DENY", &text("CITE_EGRESS_DENY"))?,
            block_mail,
        })
    }

    pub fn check_port(&self, port: u16) -> Result<(), Reason> {
        let listed = self
            .ports
            .as_ref()
            .is_none_or(|ranges| ranges.iter().any(|(a, b)| (*a..=*b).contains(&port)));
        if !listed || (self.block_mail && MAIL_PORTS.contains(&port)) {
            return Err(Reason::Port);
        }
        Ok(())
    }

    /// The name-only part of the decision, so a denied name is never even resolved.
    pub fn check_name(&self, host: &str) -> Result<(), Reason> {
        if self.node_deny.host_hit(Some(host), true) {
            return Err(Reason::NodeDenied);
        }
        if self.site_deny.host_hit(Some(host), true) {
            return Err(Reason::SiteDenied);
        }
        Ok(())
    }

    // Node deny is a ceiling no site rule lifts; site deny beats site allow; private ranges need an explicit allow.
    pub fn check_addr(&self, name: Option<&str>, ip: IpAddr) -> Result<(), Reason> {
        let ip = crate::addr::canonical(ip);
        if self.node_deny.cidr_hit(ip) || self.node_deny.host_hit(name, true) {
            return Err(Reason::NodeDenied);
        }
        if self.site_deny.cidr_hit(ip) || self.site_deny.host_hit(name, true) {
            return Err(Reason::SiteDenied);
        }
        let site_cidr = self.site_allow.cidr_hit(ip);
        let site_host = self.site_allow.host_hit(name, false);
        if self.mode == Mode::Allowlist && !site_cidr && !site_host {
            return Err(Reason::NotAllowlisted);
        }
        let cidr_allowed = site_cidr || self.node_allow.iter().any(|c| c.contains(ip));
        match classify(ip) {
            Class::Public => Ok(()),
            Class::Private if cidr_allowed || site_host => Ok(()),
            Class::Reserved if cidr_allowed => Ok(()),
            _ => Err(Reason::Internal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(pairs: &[(&str, &str)]) -> Policy {
        Policy::from_lookup(|k| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string()))
            .unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_default_allows_public_addresses_only() {
        let p = Policy::default();
        assert_eq!(p, policy(&[]));
        assert_eq!(p.check_addr(Some("example.com"), ip("93.184.215.14")), Ok(()));
        assert_eq!(p.check_addr(None, ip("2606:4700::1111")), Ok(()));
        for bad in ["127.0.0.1", "10.0.0.5", "172.17.0.1", "169.254.169.254", "::1", "fd00::1"] {
            assert_eq!(p.check_addr(None, ip(bad)), Err(Reason::Internal), "{bad}");
        }
        assert_eq!(Reason::Internal.text(), "destination is a private or internal address");
    }

    #[test]
    fn mail_ports_are_blocked_by_default_and_the_port_list_narrows() {
        let p = Policy::default();
        for port in MAIL_PORTS {
            assert_eq!(p.check_port(port), Err(Reason::Port));
        }
        assert_eq!(p.check_port(443), Ok(()));
        assert_eq!(p.check_port(5432), Ok(()));
        let open = policy(&[("CITE_EGRESS_BLOCK_MAIL", "false")]);
        assert_eq!(open.check_port(587), Ok(()));
        let narrow = policy(&[("CITE_EGRESS_ALLOW_PORTS", "80, 443,8000-8100,25")]);
        assert_eq!(narrow.check_port(8050), Ok(()));
        assert_eq!(narrow.check_port(22), Err(Reason::Port));
        assert_eq!(narrow.check_port(25), Err(Reason::Port), "block_mail still applies");
    }

    #[test]
    fn node_allow_cidrs_open_private_and_reserved_ranges() {
        let p = policy(&[("CITE_EGRESS_ALLOW_CIDRS", "192.168.10.0/24,127.0.0.0/8")]);
        assert_eq!(p.check_addr(None, ip("192.168.10.7")), Ok(()));
        assert_eq!(p.check_addr(None, ip("192.168.11.7")), Err(Reason::Internal));
        assert_eq!(p.check_addr(None, ip("127.0.0.1")), Ok(()));
        assert_eq!(p.check_addr(None, ip("::ffff:127.0.0.1")), Ok(()));
    }

    #[test]
    fn deny_precedence_node_over_site_and_site_deny_over_site_allow() {
        let p = policy(&[
            ("CITE_EGRESS_DENY_CIDRS", "203.0.112.0/24"),
            ("CITE_EGRESS_DENY_HOSTS", "evil.example"),
            ("CITE_EGRESS_ALLOW", "203.0.112.0/24,.evil.example,db.lan,10.0.0.0/8,.corp.example"),
            ("CITE_EGRESS_DENY", "10.0.0.66,secret.corp.example"),
        ]);
        assert_eq!(p.check_addr(None, ip("203.0.112.5")), Err(Reason::NodeDenied));
        assert_eq!(p.check_name("evil.example"), Err(Reason::NodeDenied));
        assert_eq!(p.check_name("x.evil.example"), Err(Reason::NodeDenied), "node deny hosts are suffixes");
        assert_eq!(p.check_name("notevil.example"), Ok(()));
        assert_eq!(p.check_addr(None, ip("10.0.0.66")), Err(Reason::SiteDenied));
        assert_eq!(p.check_name("secret.corp.example"), Err(Reason::SiteDenied));
        assert_eq!(p.check_addr(Some("a.secret.corp.example"), ip("8.8.8.8")), Err(Reason::SiteDenied));
        assert_eq!(p.check_addr(None, ip("10.0.0.7")), Ok(()));
        assert_eq!(p.check_addr(Some("db.lan"), ip("192.168.1.5")), Ok(()), "an allowed name may be private");
        assert_eq!(p.check_addr(Some("x.db.lan"), ip("192.168.1.5")), Err(Reason::Internal), "no dot, exact only");
        assert_eq!(p.check_addr(Some("app.corp.example"), ip("172.20.0.4")), Ok(()));
        assert_eq!(p.check_addr(Some("db.lan"), ip("127.0.0.1")), Err(Reason::Internal), "names never open loopback");
        assert_eq!(p.check_addr(Some("db.lan"), ip("169.254.169.254")), Err(Reason::Internal));
    }

    #[test]
    fn allowlist_mode_permits_only_listed_destinations() {
        let p = policy(&[
            ("CITE_EGRESS_MODE", "allowlist"),
            ("CITE_EGRESS_ALLOW", "api.github.com,*.apple.com,198.51.100.0/24"),
        ]);
        assert_eq!(p.check_addr(Some("api.github.com"), ip("140.82.112.6")), Ok(()));
        assert_eq!(p.check_addr(Some("github.com"), ip("140.82.112.3")), Err(Reason::NotAllowlisted));
        assert_eq!(p.check_addr(Some("www.apple.com"), ip("17.253.144.10")), Ok(()));
        assert_eq!(p.check_addr(Some("apple.com"), ip("17.253.144.10")), Ok(()));
        assert_eq!(p.check_addr(None, ip("8.8.8.8")), Err(Reason::NotAllowlisted));
        assert_eq!(p.check_addr(None, ip("198.51.100.4")), Ok(()), "an explicit CIDR opens a reserved range");
        assert_eq!(p.check_addr(Some("api.github.com"), ip("127.0.0.1")), Err(Reason::Internal));
        let node_allowed = policy(&[
            ("CITE_EGRESS_MODE", "allowlist"),
            ("CITE_EGRESS_ALLOW", "api.github.com"),
            ("CITE_EGRESS_ALLOW_CIDRS", "10.0.0.0/8"),
        ]);
        assert_eq!(node_allowed.check_addr(None, ip("10.1.1.1")), Err(Reason::NotAllowlisted));
    }

    #[test]
    fn hostile_configuration_is_refused() {
        for pairs in [
            [("CITE_EGRESS_ALLOW_CIDRS", "10.0.0.0/33")],
            [("CITE_EGRESS_ALLOW_CIDRS", "example.com")],
            [("CITE_EGRESS_DENY_CIDRS", "0177.0.0.1")],
            [("CITE_EGRESS_DENY_HOSTS", "10.0.0.1")],
            [("CITE_EGRESS_DENY_HOSTS", "Example.com")],
            [("CITE_EGRESS_DENY_HOSTS", "a..b")],
            [("CITE_EGRESS_ALLOW_PORTS", "0")],
            [("CITE_EGRESS_ALLOW_PORTS", "443-80")],
            [("CITE_EGRESS_ALLOW_PORTS", "https")],
            [("CITE_EGRESS_MODE", "open")],
            [("CITE_EGRESS_MODE", "allowlist")],
            [("CITE_EGRESS_BLOCK_MAIL", "yes")],
            [("CITE_EGRESS_ALLOW", "exa mple.com")],
            [("CITE_EGRESS_DENY", "2130706433")],
        ] {
            assert!(
                Policy::from_lookup(|k| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())).is_err(),
                "{pairs:?}"
            );
        }
        let many = (0..65).map(|i| format!("10.0.{i}.0/24")).collect::<Vec<_>>().join(",");
        assert!(Policy::from_lookup(|k| (k == "CITE_EGRESS_ALLOW").then(|| many.clone())).is_err());
    }
}
