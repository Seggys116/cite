use std::net::IpAddr;
use std::str::FromStr;

use ipnet::{IpNet, Ipv6Net};

use crate::allow::normalize_net;
use crate::model::EdgeSettings;

// Cloudflare publishes its ranges at cloudflare.com/ips-v4 and ips-v6; they change rarely, so settings can override this copy.
pub const CLOUDFLARE_RANGES_UPDATED: &str = "2026-11-06";

pub const BUILTIN_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

// Cloudflare's widest real ranges are /13 and /29, so anything wider is a mistake.
const MIN_PREFIX_V4: u8 = 12;
const MIN_PREFIX_V6: u8 = 28;

// HAProxy tests an IPv4 peer as ::ffff:a.b.c.d against IPv6 entries, so these IPv6 blocks would also match IPv4 or tunnelled clients.
const V4_EMBEDDING_BLOCKS: [&str; 4] = ["::ffff:0:0/96", "::/96", "2002::/16", "64:ff9b::/96"];

// Entries are stored as their masked network, with IPv4-mapped IPv6 turned into IPv4, so host bits cannot hide the true width.
pub(crate) fn parse_range(raw: &str) -> Option<IpNet> {
    let net = IpNet::from_str(raw)
        .ok()
        .or_else(|| IpAddr::from_str(raw).ok().map(IpNet::from))?;
    Some(normalize_net(net).trunc())
}

fn v6_overlap(a: &Ipv6Net, b: &Ipv6Net) -> bool {
    let shared = a.prefix_len().min(b.prefix_len());
    let mask = if shared == 0 {
        0
    } else {
        u128::MAX << (128 - shared)
    };
    u128::from(a.addr()) & mask == u128::from(b.addr()) & mask
}

// Takes a range already passed through parse_range.
pub(crate) fn check_width(raw: &str, net: &IpNet) -> Result<(), String> {
    let every = |what: &str| {
        format!(
            "settings cloudflare_ranges: {raw:?} matches every {what} address and would trust all clients as Cloudflare"
        )
    };
    match net {
        IpNet::V4(n) if n.prefix_len() == 0 => Err(every("IPv4")),
        IpNet::V6(n) if n.prefix_len() == 0 => Err(every("IPv6")),
        IpNet::V4(n) if n.prefix_len() < MIN_PREFIX_V4 => Err(format!(
            "settings cloudflare_ranges: {raw:?} is too wide; IPv4 ranges must be /{MIN_PREFIX_V4} or narrower"
        )),
        IpNet::V6(n) if n.prefix_len() < MIN_PREFIX_V6 => Err(format!(
            "settings cloudflare_ranges: {raw:?} is too wide; IPv6 ranges must be /{MIN_PREFIX_V6} or narrower"
        )),
        IpNet::V6(n) => {
            let clash = V4_EMBEDDING_BLOCKS
                .iter()
                .find(|b| b.parse::<Ipv6Net>().is_ok_and(|b| v6_overlap(n, &b)));
            match clash {
                Some(block) => Err(format!(
                    "settings cloudflare_ranges: {raw:?} overlaps {block}, which also covers IPv4 clients; list IPv4 ranges as IPv4"
                )),
                None => Ok(()),
            }
        }
        IpNet::V4(_) => Ok(()),
    }
}

// A non-empty custom list replaces the built-in one; entries are masked and repeats are dropped.
pub fn effective_ranges(settings: &EdgeSettings) -> Vec<String> {
    let source: Vec<&str> = if settings.cloudflare_ranges.is_empty() {
        BUILTIN_RANGES.to_vec()
    } else {
        settings
            .cloudflare_ranges
            .iter()
            .map(String::as_str)
            .collect()
    };
    let mut out: Vec<String> = Vec::with_capacity(source.len());
    for raw in source {
        if let Some(net) = parse_range(raw) {
            let cidr = net.to_string();
            if !out.contains(&cidr) {
                out.push(cidr);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(ranges: &[&str]) -> EdgeSettings {
        EdgeSettings {
            cloudflare_ranges: ranges.iter().map(|r| r.to_string()).collect(),
            ..EdgeSettings::default()
        }
    }

    fn checked(raw: &str) -> Result<(), String> {
        let net = parse_range(raw).ok_or_else(|| "unparsable".to_string())?;
        check_width(raw, &net)
    }

    #[test]
    fn every_builtin_range_parses_is_normalised_and_passes_the_width_checks() {
        for raw in BUILTIN_RANGES {
            let net = parse_range(raw).expect(raw);
            assert_eq!(net.to_string(), *raw);
            assert_eq!(check_width(raw, &net), Ok(()), "{raw}");
        }
        assert_eq!(BUILTIN_RANGES.len(), 22);
    }

    #[test]
    fn empty_setting_uses_the_builtin_list() {
        assert_eq!(effective_ranges(&EdgeSettings::default()), BUILTIN_RANGES);
    }

    #[test]
    fn custom_list_replaces_the_builtin_one_masked_and_deduplicated() {
        let s = settings(&[
            "10.0.0.0/16",
            "2001:DB8::/32",
            "10.0.1.7/16",
            "192.0.2.7",
            "not a cidr",
            "::ffff:198.51.100.0/120",
        ]);
        assert_eq!(
            effective_ranges(&s),
            [
                "10.0.0.0/16",
                "2001:db8::/32",
                "192.0.2.7/32",
                "198.51.100.0/24"
            ]
        );
    }

    #[test]
    fn host_bits_cannot_hide_the_width() {
        assert_eq!(parse_range("1.2.3.4/8").unwrap().to_string(), "1.0.0.0/8");
        assert!(checked("1.2.3.4/8").is_err());
        assert_eq!(parse_range("::1/16").unwrap().to_string(), "::/16");
    }

    #[test]
    fn width_limits_apply_per_family() {
        for ok in [
            "10.0.0.0/12",
            "10.0.0.0/32",
            "2400::/28",
            "2a06:98c0::/29",
            "1.2.3.4",
        ] {
            assert_eq!(checked(ok), Ok(()), "{ok}");
        }
        for bad in ["10.0.0.0/11", "0.0.0.0/0", "::/0", "2400::/27", "2000::/3"] {
            assert!(checked(bad).is_err(), "{bad}");
        }
        assert!(checked("0.0.0.0/0").unwrap_err().contains("every IPv4"));
        assert!(checked("::/0").unwrap_err().contains("every IPv6"));
        assert!(checked("10.0.0.0/11").unwrap_err().contains("too wide"));
    }

    #[test]
    fn ipv6_ranges_that_cover_ipv4_clients_are_refused() {
        for bad in [
            "::ffff:0:0/96",
            "::ffff:0:0/95",
            "::ffff:0:0/32",
            "::/16",
            "::1/16",
            "::/96",
            "::/28",
            "2002::/16",
            "2002::/28",
            "2002:1::/32",
            "64:ff9b::/96",
            "64:ff9b::/32",
        ] {
            assert!(checked(bad).is_err(), "{bad}");
        }
        assert!(checked("::/96").unwrap_err().contains("overlaps"));
        assert!(checked("::ffff:0:0/96").unwrap_err().contains("every IPv4"));
    }

    #[test]
    fn mapped_ipv4_entries_are_checked_as_ipv4() {
        assert_eq!(checked("::ffff:10.0.0.0/108"), Ok(()));
        assert!(checked("::ffff:10.0.0.0/104").is_err());
        assert_eq!(
            parse_range("::ffff:1.2.3.4").unwrap().to_string(),
            "1.2.3.4/32"
        );
    }

    #[test]
    fn the_update_date_is_an_iso_date() {
        let parts: Vec<&str> = CLOUDFLARE_RANGES_UPDATED.split('-').collect();
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [4, 2, 2]);
        assert!(parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit())));
    }
}
