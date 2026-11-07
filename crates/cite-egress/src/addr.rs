use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// How reachable an address is meant to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Globally routable unicast.
    Public,
    /// Private ranges a site may opt into by CIDR or by an allowed host name: RFC 1918, CGNAT and IPv6 ULA.
    Private,
    /// Loopback, link-local (cloud metadata), unspecified, multicast, broadcast, documentation and the like; only an explicit CIDR opens them.
    Reserved,
}

const PRIVATE_V4: [([u8; 4], u8); 4] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([100, 64, 0, 0], 10),
];

const RESERVED_V4: [([u8; 4], u8); 11] = [
    ([0, 0, 0, 0], 8),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 88, 99, 0], 24),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

fn v4_in(ip: Ipv4Addr, net: [u8; 4], len: u8) -> bool {
    let mask = if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

pub fn classify_v4(ip: Ipv4Addr) -> Class {
    if RESERVED_V4.iter().any(|(n, l)| v4_in(ip, *n, *l)) {
        Class::Reserved
    } else if PRIVATE_V4.iter().any(|(n, l)| v4_in(ip, *n, *l)) {
        Class::Private
    } else {
        Class::Public
    }
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, len: u8) -> bool {
    let mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    };
    u128::from(ip) & mask == u128::from(net) & mask
}

fn v6(text: &str) -> Ipv6Addr {
    text.parse().unwrap_or(Ipv6Addr::UNSPECIFIED)
}

fn low_v4(ip: Ipv6Addr) -> Ipv4Addr {
    Ipv4Addr::from((u128::from(ip) & 0xffff_ffff) as u32)
}

/// The IPv4 address carried by a mapped, IPv4-compatible, NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address.
pub fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() {
        return None;
    }
    if (s[..5] == [0; 5] && (s[5] == 0xffff || s[5] == 0)) || v6_in(ip, v6("64:ff9b::"), 96) {
        return Some(low_v4(ip));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

// Forms that carry an IPv4 address inside are judged by that address, so a private v4 cannot hide in v6.
pub fn classify_v6(ip: Ipv6Addr) -> Class {
    if ip.is_unspecified() || ip.is_loopback() {
        return Class::Reserved;
    }
    if let Some(v4) = embedded_v4(ip) {
        return classify_v4(v4);
    }
    if v6_in(ip, v6("fc00::"), 7) {
        return Class::Private;
    }
    let reserved = [
        ("2001::", 32),
        ("2001:db8::", 32),
        ("2001:10::", 28),
        ("2001:20::", 28),
        ("3fff::", 20),
        ("64:ff9b:1::", 48),
        ("100::", 64),
    ];
    if reserved.iter().any(|(n, l)| v6_in(ip, v6(n), *l)) {
        return Class::Reserved;
    }
    if v6_in(ip, v6("2000::"), 3) {
        Class::Public
    } else {
        Class::Reserved
    }
}

pub fn classify(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(a) => classify_v4(a),
        IpAddr::V6(a) => classify_v6(a),
    }
}

/// A network range; host bits are cleared when it is parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

impl Cidr {
    /// `a.b.c.d`, `a.b.c.d/n`, `v6` or `v6/n`, with the same strict IPv4 form as host names; `::ffff:` ranges must be written as IPv4.
    pub fn parse(text: &str) -> Option<Cidr> {
        let (ip, len) = match text.split_once('/') {
            Some((ip, len)) => (ip, Some(len)),
            None => (text, None),
        };
        let ip = match parse_v4_strict(ip) {
            Some(a) => IpAddr::V4(a),
            None if ip.contains(':') => {
                let a: Ipv6Addr = ip.parse().ok()?;
                if a.to_ipv4_mapped().is_some() {
                    return None;
                }
                IpAddr::V6(a)
            }
            None => return None,
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(l) if (1..=3).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_digit()) => {
                let n: u8 = l.parse().ok()?;
                if n > max || (l.len() > 1 && l.starts_with('0')) {
                    return None;
                }
                n
            }
            Some(_) => return None,
        };
        let net = match ip {
            IpAddr::V4(a) => {
                let mask = if len == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(len))
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
            }
            IpAddr::V6(a) => {
                let mask = if len == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(len))
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
            }
        };
        Some(Cidr { net, len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, canonical(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => v4_in(a, n.octets(), self.len),
            (IpAddr::V6(n), IpAddr::V6(a)) => v6_in(a, n, self.len),
            _ => false,
        }
    }
}

/// IPv4-mapped IPv6 addresses become plain IPv4, so ranges and connections treat them alike.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_canonical(),
        v4 => v4,
    }
}

/// Exactly four decimal octets without leading zeros; shorthand, octal and hex forms are refused.
pub fn parse_v4_strict(text: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (slot, part) in octets.iter_mut().zip(&parts) {
        let digits =
            !part.is_empty() && part.len() <= 3 && part.bytes().all(|b| b.is_ascii_digit());
        if !digits || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

// A last label that is a number or 0x-prefixed makes the whole host an IPv4 attempt, as browsers read it.
fn numeric_label(label: &str) -> bool {
    let hex = label
        .strip_prefix("0x")
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_hexdigit()));
    hex || (!label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// A DNS name (lowercased, trailing dot dropped), a strict dotted IPv4 or a bracketed IPv6; anything ambiguous is None.
pub fn parse_host(text: &str) -> Option<Host> {
    if let Some(inner) = text.strip_prefix('[') {
        let inner = inner.strip_suffix(']')?;
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|a| Host::Ip(IpAddr::V6(a)));
    }
    let lower = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
    if lower.is_empty() || lower.len() > 253 {
        return None;
    }
    let last = lower.rsplit('.').next().unwrap_or_default();
    if numeric_label(last) {
        return parse_v4_strict(&lower).map(|a| Host::Ip(IpAddr::V4(a)));
    }
    let labels_ok = lower.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    });
    labels_ok.then_some(Host::Name(lower))
}

/// A port of 1 to 65535 written as plain decimal digits.
pub fn parse_port(text: &str) -> Option<u16> {
    let shaped = (1..=5).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit());
    if !shaped || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse::<u16>().ok().filter(|p| *p != 0)
}

/// `host:port` or `[v6]:port`; the port is required.
pub fn parse_authority(text: &str) -> Option<(Host, u16)> {
    let (host, port) = if text.starts_with('[') {
        let end = text.find("]:")?;
        (&text[..=end], &text[end + 2..])
    } else {
        text.rsplit_once(':')?
    };
    if !host.starts_with('[') && host.contains(':') {
        return None;
    }
    Some((parse_host(host)?, parse_port(port)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(text: &str) -> Class {
        classify(text.parse().unwrap())
    }

    #[test]
    fn the_classifier_table() {
        let table = [
            ("8.8.8.8", Class::Public),
            ("1.1.1.1", Class::Public),
            ("140.82.112.3", Class::Public),
            ("172.15.255.255", Class::Public),
            ("172.32.0.1", Class::Public),
            ("100.63.255.255", Class::Public),
            ("100.128.0.0", Class::Public),
            ("192.169.0.1", Class::Public),
            ("10.0.0.1", Class::Private),
            ("10.255.255.255", Class::Private),
            ("172.16.0.1", Class::Private),
            ("172.17.0.1", Class::Private),
            ("172.31.255.254", Class::Private),
            ("192.168.1.10", Class::Private),
            ("100.64.0.1", Class::Private),
            ("100.127.255.255", Class::Private),
            ("0.0.0.0", Class::Reserved),
            ("0.1.2.3", Class::Reserved),
            ("127.0.0.1", Class::Reserved),
            ("127.255.255.254", Class::Reserved),
            ("169.254.169.254", Class::Reserved),
            ("169.254.0.1", Class::Reserved),
            ("192.0.0.170", Class::Reserved),
            ("192.0.2.1", Class::Reserved),
            ("192.88.99.1", Class::Reserved),
            ("198.18.0.1", Class::Reserved),
            ("198.19.255.255", Class::Reserved),
            ("198.51.100.7", Class::Reserved),
            ("203.0.113.9", Class::Reserved),
            ("224.0.0.1", Class::Reserved),
            ("239.255.255.250", Class::Reserved),
            ("240.0.0.1", Class::Reserved),
            ("255.255.255.255", Class::Reserved),
            ("2606:4700:4700::1111", Class::Public),
            ("2a00:1450:4009:81f::200e", Class::Public),
            ("::", Class::Reserved),
            ("::1", Class::Reserved),
            ("fe80::1", Class::Reserved),
            ("febf::1", Class::Reserved),
            ("fec0::1", Class::Reserved),
            ("fc00::1", Class::Private),
            ("fd12:3456::1", Class::Private),
            ("ff02::1", Class::Reserved),
            ("ff05::2", Class::Reserved),
            ("::ffff:127.0.0.1", Class::Reserved),
            ("::ffff:10.0.0.1", Class::Private),
            ("::ffff:169.254.169.254", Class::Reserved),
            ("::ffff:8.8.8.8", Class::Public),
            ("::127.0.0.1", Class::Reserved),
            ("::10.1.2.3", Class::Private),
            ("::8.8.8.8", Class::Public),
            ("64:ff9b::7f00:1", Class::Reserved),
            ("64:ff9b::a9fe:a9fe", Class::Reserved),
            ("64:ff9b::c0a8:101", Class::Private),
            ("64:ff9b::808:808", Class::Public),
            ("64:ff9b:1::1", Class::Reserved),
            ("2002:7f00:1::1", Class::Reserved),
            ("2002:a00:1::1", Class::Private),
            ("2002:a9fe:a9fe::1", Class::Reserved),
            ("2002:808:808::1", Class::Public),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Class::Reserved),
            ("2001:db8::1", Class::Reserved),
            ("2001:10::1", Class::Reserved),
            ("2001:20::1", Class::Reserved),
            ("3fff::1", Class::Reserved),
            ("100::1", Class::Reserved),
            ("4000::1", Class::Reserved),
            ("1::1", Class::Reserved),
        ];
        for (text, want) in table {
            assert_eq!(class(text), want, "{text}");
        }
    }

    #[test]
    fn numeric_host_tricks_are_refused() {
        for bad in [
            "2130706433",
            "0x7f000001",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "017700000001",
            "127.1",
            "127.0.1",
            "010.0.0.1",
            "127.000.000.001",
            "1.2.3.4.5",
            "256.0.0.1",
            "1.2.3.-4",
            "1.2.3.0x4",
            "example.0x10",
            "example.123",
            "",
            ".",
            "a..b",
            "-a.com",
            "a-.com",
            "a b.com",
            "a%2ecom",
            "[::1",
            "[fe80::1%25eth0]",
            "[127.0.0.1]",
            "exa\u{e9}mple.com",
        ] {
            assert_eq!(parse_host(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_host("127.0.0.1"),
            Some(Host::Ip("127.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            parse_host("0.0.0.0"),
            Some(Host::Ip("0.0.0.0".parse().unwrap()))
        );
        assert_eq!(parse_host("[::1]"), Some(Host::Ip("::1".parse().unwrap())));
        assert_eq!(
            parse_host("Api.GitHub.com."),
            Some(Host::Name("api.github.com".into()))
        );
        assert_eq!(
            parse_host("1.2.3.4.nip.io"),
            Some(Host::Name("1.2.3.4.nip.io".into()))
        );
        assert_eq!(
            parse_host("_dmarc.example.com"),
            Some(Host::Name("_dmarc.example.com".into()))
        );
    }

    #[test]
    fn authorities_and_ports_are_strict() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some((Host::Name("example.com".into()), 443))
        );
        assert_eq!(
            parse_authority("[2606:4700::1]:8443"),
            Some((Host::Ip("2606:4700::1".parse().unwrap()), 8443))
        );
        for bad in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:+443",
            "example.com:0443",
            "example.com:443a",
            "example.com:https",
            "example.com: 443",
            "2606:4700::1:443",
            "[2606:4700::1]443",
            "user@example.com:443",
        ] {
            assert_eq!(parse_authority(bad), None, "{bad:?}");
        }
        assert_eq!(parse_port("65535"), Some(65535));
        assert_eq!(parse_port("1"), Some(1));
    }

    #[test]
    fn cidrs_parse_strictly_and_mask_host_bits() {
        let c = Cidr::parse("10.1.2.3/8").unwrap();
        assert!(c.contains("10.200.0.1".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(
            c.contains("::ffff:10.0.0.9".parse().unwrap()),
            "mapped v6 matches v4 ranges"
        );
        let one = Cidr::parse("192.168.1.20").unwrap();
        assert!(one.contains("192.168.1.20".parse().unwrap()));
        assert!(!one.contains("192.168.1.21".parse().unwrap()));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        for bad in [
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/08",
            "10.0.0.0/-1",
            "010.0.0.0/8",
            "10.0.0/8",
            "fd00::/129",
            "example.com/8",
            "10.0.0.0/8/8",
            "",
            "::ffff:127.0.0.1",
            "::ffff:0:0/96",
            "::ffff:10.0.0.0/104",
        ] {
            assert_eq!(Cidr::parse(bad), None, "{bad:?}");
        }
        assert!(Cidr::parse("::/0").is_some());
    }

    #[test]
    fn embedded_ipv4_is_extracted_from_every_carrier_form() {
        let v4 = |t: &str| Some(t.parse::<Ipv4Addr>().unwrap());
        for (text, want) in [
            ("::ffff:10.0.0.1", v4("10.0.0.1")),
            ("::10.0.0.1", v4("10.0.0.1")),
            ("64:ff9b::a00:1", v4("10.0.0.1")),
            ("2002:a00:1::1", v4("10.0.0.1")),
            ("2606:4700::1", None),
            ("::1", None),
            ("::", None),
        ] {
            assert_eq!(embedded_v4(text.parse().unwrap()), want, "{text}");
        }
    }
}
