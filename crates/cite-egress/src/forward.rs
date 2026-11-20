//! Fixed-destination TCP forwards, so a site's database client can reach one external host through the proxy.
//!
//! A forward is a listener whose destination is set by the proxy's own environment; a client never
//! chooses where it goes. Every accepted connection goes through the same resolve, judge and connect
//! step as an HTTP CONNECT, so DNS rebinding, internal-address refusal, the port list and the node
//! deny ceilings apply exactly as they do there.

use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::time::Instant;

use crate::addr::{Host, parse_host, parse_port};
use crate::policy::Policy;
use crate::proxy::{Failure, Shared, Timeouts, open, relay};

/// Ports a forward may listen on; the connector assigns them by attachment name.
pub const FORWARD_PORTS: RangeInclusive<u16> = 15432..=15439;
/// Pooled database connections sit idle for long stretches, so forwards outlive the 120 s HTTP idle limit.
pub const FORWARD_IDLE: Duration = Duration::from_secs(1800);
/// At most this many forwards per proxy, one per listen port.
pub const MAX_FORWARDS: usize = 8;
const FULL_WARN_EVERY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub listen: u16,
    pub host: Host,
    pub port: u16,
}

impl Forward {
    /// `host:port` or `[v6]:port`, for logs.
    pub fn target(&self) -> String {
        match &self.host {
            Host::Name(n) => format!("{n}:{}", self.port),
            Host::Ip(IpAddr::V6(a)) => format!("[{a}]:{}", self.port),
            Host::Ip(a) => format!("{a}:{}", self.port),
        }
    }
}

// A name must already be in the form `parse_host` produces (lowercase, no trailing dot); an IP literal
// must be strict IPv4 or bracketed IPv6. Anything else is ambiguous and refused.
fn forward_host(text: &str) -> Option<Host> {
    match parse_host(text)? {
        Host::Name(n) if n == text => Some(Host::Name(n)),
        Host::Name(_) => None,
        ip => Some(ip),
    }
}

fn parse_entry(entry: &str) -> Result<Forward, String> {
    let bad = |why: &str| format!("CITE_EGRESS_FORWARDS entry {entry:?} {why}");
    let (listen, target) = entry
        .split_once('=')
        .ok_or_else(|| bad("must be <listen>=<host>:<port>"))?;
    let listen = parse_port(listen)
        .filter(|p| FORWARD_PORTS.contains(p))
        .ok_or_else(|| {
            bad(&format!(
                "listen port must be {}..={}",
                FORWARD_PORTS.start(),
                FORWARD_PORTS.end()
            ))
        })?;
    let (host, port) = if target.starts_with('[') {
        let end = target
            .find("]:")
            .ok_or_else(|| bad("needs a destination port"))?;
        (&target[..=end], &target[end + 2..])
    } else {
        target
            .rsplit_once(':')
            .ok_or_else(|| bad("needs a destination port"))?
    };
    let port = parse_port(port).ok_or_else(|| bad("has an invalid destination port"))?;
    let host = forward_host(host).ok_or_else(|| bad("has an invalid destination host"))?;
    Ok(Forward { listen, host, port })
}

/// Parses `<listen>=<host>:<port>,...`: 1 to 8 entries, listen ports 15432..=15439 and unique, no
/// repeated destination. The Docker proxy applies the same grammar to the value it lets through.
pub fn parse_forwards(raw: &str) -> Result<Vec<Forward>, String> {
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    if entries.is_empty() {
        return Err("CITE_EGRESS_FORWARDS has no entries".to_string());
    }
    if entries.len() > MAX_FORWARDS {
        return Err(format!(
            "CITE_EGRESS_FORWARDS has more than {MAX_FORWARDS} entries"
        ));
    }
    let mut out: Vec<Forward> = Vec::with_capacity(entries.len());
    for entry in entries {
        let fwd = parse_entry(entry)?;
        if out.iter().any(|f| f.listen == fwd.listen) {
            return Err(format!(
                "CITE_EGRESS_FORWARDS listens on port {} twice",
                fwd.listen
            ));
        }
        if out.iter().any(|f| f.host == fwd.host && f.port == fwd.port) {
            return Err(format!(
                "CITE_EGRESS_FORWARDS forwards to {} twice",
                fwd.target()
            ));
        }
        out.push(fwd);
    }
    Ok(out)
}

/// Accepts clients for one forward until the listener fails. Each connection holds a permit from the
/// same pool as the HTTP listener; when the pool is empty the client is closed without a reply.
pub async fn serve_forward(
    listener: TcpListener,
    fwd: Forward,
    policy: Arc<Policy>,
    shared: Shared,
    timeouts: Timeouts,
) {
    let Shared { slots, resolver } = shared;
    let fwd = Arc::new(fwd);
    let mut last_full_warn: Option<Instant> = None;
    loop {
        let (client, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, forward = fwd.listen, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            if last_full_warn.is_none_or(|t| t.elapsed() >= FULL_WARN_EVERY) {
                tracing::warn!(
                    forward = fwd.listen,
                    "connection limit reached, refusing new clients"
                );
                last_full_warn = Some(Instant::now());
            }
            drop(client);
            continue;
        };
        let (policy, resolver, fwd) = (policy.clone(), resolver.clone(), fwd.clone());
        tokio::spawn(async move {
            let dest = fwd.target();
            match open(&policy, &resolver, &fwd.host, fwd.port, timeouts.connect).await {
                Ok(upstream) => {
                    tracing::info!(dest = %dest, verdict = "allowed", forward = fwd.listen);
                    relay(client, upstream, FORWARD_IDLE).await;
                }
                Err(Failure::Denied(reason)) => {
                    tracing::info!(
                        dest = %dest,
                        verdict = "denied",
                        reason = reason.text(),
                        forward = fwd.listen
                    );
                }
                Err(Failure::Unreachable) => {
                    tracing::info!(dest = %dest, verdict = "unreachable", forward = fwd.listen);
                }
            }
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    fn name(n: &str) -> Host {
        Host::Name(n.to_string())
    }

    #[test]
    fn the_grammar_accepts_names_and_ip_literals() {
        let got = parse_forwards(
            "15432=db.example.com:5432, 15433=10.1.2.3:6543,15439=[2606:4700::1]:5433",
        )
        .unwrap();
        assert_eq!(
            got,
            vec![
                Forward {
                    listen: 15432,
                    host: name("db.example.com"),
                    port: 5432
                },
                Forward {
                    listen: 15433,
                    host: Host::Ip("10.1.2.3".parse().unwrap()),
                    port: 6543
                },
                Forward {
                    listen: 15439,
                    host: Host::Ip("2606:4700::1".parse().unwrap()),
                    port: 5433
                },
            ]
        );
        assert_eq!(got[0].target(), "db.example.com:5432");
        assert_eq!(got[2].target(), "[2606:4700::1]:5433");
        let eight = (0..8)
            .map(|i| format!("{}=h{i}.example.com:5432", 15432 + i))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(parse_forwards(&eight).unwrap().len(), 8);
    }

    #[test]
    fn the_grammar_refuses_everything_else() {
        let nine = (0..9)
            .map(|i| format!("{}=h{i}.example.com:5432", 15432 + i))
            .collect::<Vec<_>>()
            .join(",");
        for bad in [
            "",
            " , ",
            "15431=db.example.com:5432",
            "15440=db.example.com:5432",
            "0=db.example.com:5432",
            "015432=db.example.com:5432",
            "db.example.com:5432",
            "15432=db.example.com",
            "15432=db.example.com:0",
            "15432=db.example.com:65536",
            "15432=db.example.com:0443",
            "15432=:5432",
            "15432=.db.example.com:5432",
            "15432=*.example.com:5432",
            "15432=DB.example.com:5432",
            "15432=db.example.com.:5432",
            "15432=2130706433:5432",
            "15432=0x7f.1:5432",
            "15432=010.0.0.1:5432",
            "15432=::1:5432",
            "15432=[::1:5432",
            "15432=user@db.example.com:5432",
            "15432=db.example.com:5432/x",
            "15432=a b.example.com:5432",
            "15432=db.example.com:5432,15432=other.example.com:5432",
            "15432=db.example.com:5432,15433=db.example.com:5432",
            nine.as_str(),
        ] {
            assert!(parse_forwards(bad).is_err(), "{bad:?}");
        }
    }

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    fn policy(pairs: &'static [(&'static str, &'static str)]) -> Arc<Policy> {
        Arc::new(
            Policy::from_lookup(|k| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == k)
                    .map(|(_, v)| v.to_string())
            })
            .unwrap(),
        )
    }

    // Starts a forward on an ephemeral port to the given target and returns where to connect.
    async fn start_forward(target: SocketAddr, policy: Arc<Policy>, shared: Shared) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fwd = Forward {
            listen: addr.port(),
            host: Host::Ip(target.ip()),
            port: target.port(),
        };
        tokio::spawn(serve_forward(
            listener,
            fwd,
            policy,
            shared,
            Timeouts::default(),
        ));
        addr
    }

    async fn ping(s: &mut TcpStream) -> bool {
        if s.write_all(b"ping").await.is_err() {
            return false;
        }
        let mut buf = [0u8; 4];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await,
            Ok(Ok(_))
        ) && &buf == b"ping"
    }

    // True when the peer closes without sending anything.
    async fn closed_silently(s: &mut TcpStream) -> bool {
        let mut buf = [0u8; 16];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    static LOOPBACK: &[(&str, &str)] = &[("CITE_EGRESS_ALLOW_CIDRS", "127.0.0.0/8")];

    #[tokio::test]
    async fn a_forward_relays_to_an_allowed_loopback_target() {
        let target = echo_server().await;
        let addr = start_forward(target, policy(LOOPBACK), Shared::new()).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        assert!(ping(&mut s).await);
        assert!(ping(&mut s).await, "the tunnel stays open for more traffic");
    }

    #[tokio::test]
    async fn a_forward_refuses_a_private_target_without_an_allow() {
        let target = echo_server().await;
        let addr = start_forward(target, policy(&[]), Shared::new()).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        assert!(closed_silently(&mut s).await);
        let _ = s.write_all(b"ping").await;
        assert!(!ping(&mut s).await, "nothing was relayed");
    }

    #[tokio::test]
    async fn a_forward_obeys_the_port_allowlist() {
        let target = echo_server().await;
        let narrow: &'static [(&str, &str)] = &[
            ("CITE_EGRESS_ALLOW_CIDRS", "127.0.0.0/8"),
            ("CITE_EGRESS_ALLOW_PORTS", "5432"),
        ];
        assert_ne!(target.port(), 5432);
        let addr = start_forward(target, policy(narrow), Shared::new()).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        assert!(closed_silently(&mut s).await);
    }

    #[tokio::test]
    async fn a_forward_does_not_connect_to_a_node_denied_target() {
        let target = echo_server().await;
        let denied: &'static [(&str, &str)] = &[
            ("CITE_EGRESS_ALLOW_CIDRS", "127.0.0.0/8"),
            ("CITE_EGRESS_DENY_CIDRS", "127.0.0.1"),
        ];
        let addr = start_forward(target, policy(denied), Shared::new()).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        assert!(closed_silently(&mut s).await);
    }

    #[tokio::test]
    async fn forwards_and_connect_share_one_connection_limit() {
        let target = echo_server().await;
        let shared = Shared::with_limit(1);
        let fwd_addr = start_forward(target, policy(LOOPBACK), shared.clone()).await;
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        tokio::spawn(crate::proxy::serve_with(
            http_listener,
            policy(LOOPBACK),
            Timeouts::default(),
            shared.clone(),
        ));

        let mut first = TcpStream::connect(fwd_addr).await.unwrap();
        assert!(ping(&mut first).await);

        // The one permit is held by the forward connection: a second forward client is closed...
        let mut second = TcpStream::connect(fwd_addr).await.unwrap();
        assert!(closed_silently(&mut second).await);

        // ...and a CONNECT client gets the proxy's 503.
        let mut http = TcpStream::connect(http_addr).await.unwrap();
        http.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(5), http.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(text.starts_with("HTTP/1.1 503"), "{text}");

        // Releasing the permit lets the next client through.
        drop(first);
        let mut third = None;
        for _ in 0..100 {
            let mut s = TcpStream::connect(fwd_addr).await.unwrap();
            if ping(&mut s).await {
                third = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(third.is_some(), "the permit was never released");
    }
}
