use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net};

const ALLOW_ALL_TOKEN: &str = "allow-all";
const MAX_ENTRIES: usize = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllowError {
    #[error("allowlist is empty")]
    Empty,
    #[error("invalid allowlist entry: {0}")]
    Invalid(String),
    #[error("{0} matches every address; add the allow-all token to confirm")]
    OpenNet(String),
    #[error("allowlist has too many entries")]
    TooMany,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAllowlist {
    nets: Vec<IpNet>,
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

pub(crate) fn normalize_net(net: IpNet) -> IpNet {
    // A v4-mapped v6 network keeps 96 bits of fixed prefix before the embedded v4 address.
    if let IpNet::V6(v6) = net
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.addr().to_ipv4_mapped()
        && let Ok(mapped) = Ipv4Net::new(v4, v6.prefix_len() - 96)
    {
        return IpNet::V4(mapped);
    }
    net
}

fn parse_entry(token: &str) -> Result<IpNet, AllowError> {
    if let Ok(net) = token.parse::<IpNet>() {
        return Ok(normalize_net(net));
    }
    match token.parse::<IpAddr>() {
        Ok(ip) => Ok(IpNet::from(normalize_ip(ip))),
        Err(_) => Err(AllowError::Invalid(token.to_string())),
    }
}

impl IpAllowlist {
    pub fn parse(s: &str) -> Result<Self, AllowError> {
        let tokens: Vec<&str> = s
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.is_empty() {
            return Err(AllowError::Empty);
        }
        if tokens.len() > MAX_ENTRIES {
            return Err(AllowError::TooMany);
        }
        // The token may appear anywhere in the list and confirms any open network in it.
        let allow_all = tokens.contains(&ALLOW_ALL_TOKEN);
        let mut nets = Vec::with_capacity(tokens.len());
        for token in tokens {
            if token == ALLOW_ALL_TOKEN {
                let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                let v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
                for addr in [v4, v6] {
                    let net = IpNet::new(addr, 0);
                    nets.push(net.map_err(|_| AllowError::Invalid(token.to_string()))?);
                }
                continue;
            }
            let net = parse_entry(token)?;
            if net.prefix_len() == 0 && !allow_all {
                return Err(AllowError::OpenNet(token.to_string()));
            }
            nets.push(net);
        }
        Ok(Self { nets })
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.nets.iter().any(|net| net.contains(&ip))
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    #[test]
    fn empty_string_is_an_error() {
        assert_eq!(IpAllowlist::parse(""), Err(AllowError::Empty));
        assert_eq!(IpAllowlist::parse("  , ,\t"), Err(AllowError::Empty));
    }

    #[test]
    fn single_addresses_match_exactly() {
        let list = IpAllowlist::parse("203.0.113.7").expect("parse");
        assert!(list.allows(ip("203.0.113.7")));
        assert!(!list.allows(ip("203.0.113.8")));
        assert!(!list.allows(ip("::1")));
    }

    #[test]
    fn v4_cidr_matches_range() {
        let list = IpAllowlist::parse("10.0.0.0/8").expect("parse");
        assert!(list.allows(ip("10.255.255.255")));
        assert!(!list.allows(ip("11.0.0.1")));
    }

    #[test]
    fn v6_cidr_matches_range() {
        let list = IpAllowlist::parse("2001:db8::/32").expect("parse");
        assert!(list.allows(ip("2001:db8:1::1")));
        assert!(!list.allows(ip("2001:db9::1")));
        assert!(!list.allows(ip("10.0.0.1")));
    }

    #[test]
    fn separators_can_be_commas_and_whitespace() {
        let list = IpAllowlist::parse("1.1.1.1, 2.2.2.2\n3.3.3.3,,  4.4.4.4/32").expect("parse");
        assert_eq!(list.len(), 4);
        assert!(!list.is_empty());
        assert!(list.allows(ip("3.3.3.3")));
        assert!(list.allows(ip("4.4.4.4")));
    }

    #[test]
    fn v4_mapped_clients_match_v4_entries() {
        let list = IpAllowlist::parse("192.0.2.0/24").expect("parse");
        assert!(list.allows(ip("::ffff:192.0.2.55")));
        assert!(!list.allows(ip("::ffff:192.0.3.55")));
    }

    #[test]
    fn v4_mapped_entries_are_normalised() {
        let single = IpAllowlist::parse("::ffff:198.51.100.9").expect("parse");
        assert!(single.allows(ip("198.51.100.9")));
        assert!(single.allows(ip("::ffff:198.51.100.9")));
        let net = IpAllowlist::parse("::ffff:198.51.100.0/120").expect("parse");
        assert!(net.allows(ip("198.51.100.200")));
        assert!(!net.allows(ip("198.51.101.1")));
    }

    #[test]
    fn open_networks_need_explicit_confirmation() {
        for entry in ["0.0.0.0/0", "::/0", "::ffff:0:0/96", "10.0.0.1, 0.0.0.0/0"] {
            assert!(
                matches!(IpAllowlist::parse(entry), Err(AllowError::OpenNet(_))),
                "{entry}"
            );
        }
    }

    #[test]
    fn allow_all_token_opens_both_families() {
        let list = IpAllowlist::parse("allow-all").expect("parse");
        assert!(list.allows(ip("8.8.8.8")));
        assert!(list.allows(ip("2606:4700::1111")));
        let with_net = IpAllowlist::parse("0.0.0.0/0 allow-all").expect("parse");
        assert!(with_net.allows(ip("9.9.9.9")));
    }

    #[test]
    fn invalid_entries_are_rejected() {
        for entry in [
            "nope",
            "1.2.3.4/33",
            "1.2.3",
            "10.0.0.0/8 junk",
            "ALLOW-ALL",
        ] {
            assert!(
                matches!(IpAllowlist::parse(entry), Err(AllowError::Invalid(_))),
                "{entry}"
            );
        }
    }

    #[test]
    fn oversized_lists_are_rejected() {
        let big = vec!["10.0.0.1"; MAX_ENTRIES + 1].join(",");
        assert_eq!(IpAllowlist::parse(&big), Err(AllowError::TooMany));
    }

    proptest! {
        #[test]
        fn parse_never_panics(s in ".*") {
            let _ = IpAllowlist::parse(&s);
        }

        #[test]
        fn parse_never_panics_on_address_like_input(s in "[0-9a-fA-F:./, -]{0,80}") {
            if let Ok(list) = IpAllowlist::parse(&s) {
                let _ = list.allows(IpAddr::V4(Ipv4Addr::LOCALHOST));
                prop_assert!(!list.is_empty());
            }
        }
    }
}
