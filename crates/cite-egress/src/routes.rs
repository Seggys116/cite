//! The proxy's own networks and gateways, read from the kernel's routing tables.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::addr::Cidr;

const MAX_LOCAL: usize = 64;

/// Every directly connected subnet and every gateway of this container; empty where /proc is not available.
pub fn local_networks() -> Vec<Cidr> {
    let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    let mut out = parse_v4_routes(&v4);
    for c in parse_v6_routes(&v6) {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out.truncate(MAX_LOCAL);
    out
}

fn push(out: &mut Vec<Cidr>, text: &str) {
    if let Some(c) = Cidr::parse(text)
        && !out.contains(&c)
    {
        out.push(c);
    }
}

// Addresses are the kernel's raw network-order words printed as native integers, hence to_ne_bytes.
fn v4_word(hex: &str) -> Option<Ipv4Addr> {
    (hex.len() == 8)
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
        .map(|n| Ipv4Addr::from(n.to_ne_bytes()))
}

/// `/proc/net/route`: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
pub fn parse_v4_routes(text: &str) -> Vec<Cidr> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (Some(dest), Some(gw), Some(mask)) = (
            cols.get(1).and_then(|h| v4_word(h)),
            cols.get(2).and_then(|h| v4_word(h)),
            cols.get(7).and_then(|h| v4_word(h)),
        ) else {
            continue;
        };
        let len = u32::from(mask).count_ones();
        if len > 0 && !dest.is_unspecified() {
            push(&mut out, &format!("{dest}/{len}"));
        }
        if !gw.is_unspecified() {
            push(&mut out, &gw.to_string());
        }
    }
    out
}

fn v6_word(hex: &str) -> Option<Ipv6Addr> {
    (hex.len() == 32)
        .then(|| u128::from_str_radix(hex, 16).ok())
        .flatten()
        .map(Ipv6Addr::from)
}

/// `/proc/net/ipv6_route`: dest dest_len src src_len next_hop metric refcnt use flags iface.
pub fn parse_v6_routes(text: &str) -> Vec<Cidr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (Some(dest), Some(len), Some(hop)) = (
            cols.first().and_then(|h| v6_word(h)),
            cols.get(1).and_then(|h| u8::from_str_radix(h, 16).ok()),
            cols.get(4).and_then(|h| v6_word(h)),
        ) else {
            continue;
        };
        if len > 0 && len <= 128 && !dest.is_multicast() {
            push(&mut out, &format!("{dest}/{len}"));
        }
        if !hop.is_unspecified() {
            push(&mut out, &hop.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(ip: &str) -> String {
        let a: Ipv4Addr = ip.parse().unwrap();
        format!("{:08X}", u32::from_ne_bytes(a.octets()))
    }

    #[test]
    fn v4_routes_yield_connected_subnets_and_gateways_but_never_the_default() {
        let table = format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             eth0\t{}\t{}\t0003\t0\t0\t0\t{}\t0\t0\t0\n\
             eth0\t{}\t{}\t0001\t0\t0\t0\t{}\t0\t0\t0\n\
             eth1\t{}\t{}\t0001\t0\t0\t0\t{}\t0\t0\t0\n",
            word("0.0.0.0"),
            word("172.18.0.1"),
            word("0.0.0.0"),
            word("172.18.0.0"),
            word("0.0.0.0"),
            word("255.255.0.0"),
            word("10.9.0.0"),
            word("0.0.0.0"),
            word("255.255.255.0"),
        );
        let got = parse_v4_routes(&table);
        let want: Vec<Cidr> = ["172.18.0.1", "172.18.0.0/16", "10.9.0.0/24"]
            .iter()
            .map(|t| Cidr::parse(t).unwrap())
            .collect();
        assert_eq!(got, want);
        assert!(parse_v4_routes("Iface\nnonsense\n").is_empty());
    }

    #[test]
    fn v6_routes_skip_multicast_and_the_default() {
        let table = "\
fd00000000000000000000000000ab00 78 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd00000000000000000000000000ab01 00000400 00000001 00000000 00000003 eth0
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
";
        let want: Vec<Cidr> = ["fd00::ab00/120", "fd00::ab01"]
            .iter()
            .map(|t| Cidr::parse(t).unwrap())
            .collect();
        assert_eq!(parse_v6_routes(table), want);
    }
}
