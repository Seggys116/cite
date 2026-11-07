use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::addr::{Host, parse_authority, parse_host};
use crate::policy::{Policy, Reason};

pub const LISTEN: &str = "0.0.0.0:3128";
const MAX_CONNS: usize = 256;
const MAX_HEAD: usize = 16 * 1024;
const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;
const BUF: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub header: Duration,
    pub connect: Duration,
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            header: Duration::from_secs(10),
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(120),
        }
    }
}

/// Accepts connections until the listener fails, at most MAX_CONNS at a time.
pub async fn serve(listener: TcpListener, policy: Arc<Policy>, timeouts: Timeouts) {
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    loop {
        let Ok(permit) = slots.clone().acquire_owned().await else {
            return;
        };
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let policy = policy.clone();
        tokio::spawn(async move {
            handle(stream, &policy, timeouts).await;
            drop(permit);
        });
    }
}

fn reply(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}\n",
        body.len() + 1
    )
    .into_bytes()
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    // Bytes the client sent after the header block, forwarded untouched.
    rest: Vec<u8>,
}

enum HeadError {
    Closed,
    TooLarge,
    Malformed,
}

async fn read_head(stream: &mut TcpStream) -> Result<Head, HeadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEAD {
            return Err(HeadError::TooLarge);
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(HeadError::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    if end > MAX_HEAD {
        return Err(HeadError::TooLarge);
    }
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| HeadError::Malformed)?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or_default();
    if line.len() > MAX_REQUEST_LINE {
        return Err(HeadError::TooLarge);
    }
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HeadError::Malformed);
    };
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    let target_ok = !target.is_empty() && target.bytes().all(|b| b.is_ascii_graphic());
    if !token(method) || !target_ok || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(HeadError::Malformed);
    }
    let mut headers = Vec::new();
    for l in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(HeadError::TooLarge);
        }
        let (name, value) = l.split_once(':').ok_or(HeadError::Malformed)?;
        let value_ok = value.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b));
        if !token(name) || !value_ok {
            return Err(HeadError::Malformed);
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    Ok(Head {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        rest: buf[end + 4..].to_vec(),
    })
}

async fn refuse(stream: &mut TcpStream, status: &str, body: &str) {
    let _ = stream.write_all(&reply(status, body)).await;
    let _ = stream.shutdown().await;
}

async fn handle(mut stream: TcpStream, policy: &Policy, timeouts: Timeouts) {
    let head = match tokio::time::timeout(timeouts.header, read_head(&mut stream)).await {
        Ok(Ok(head)) => head,
        Ok(Err(HeadError::Closed)) => return,
        Ok(Err(HeadError::TooLarge)) => {
            return refuse(&mut stream, "431 Request Header Fields Too Large", "request head is too large").await;
        }
        Ok(Err(HeadError::Malformed)) => {
            return refuse(&mut stream, "400 Bad Request", "malformed request").await;
        }
        Err(_) => return refuse(&mut stream, "408 Request Timeout", "request head timed out").await,
    };
    let connect = head.method == "CONNECT";
    let parsed = if connect {
        parse_authority(&head.target).map(|(h, p)| (h, p, None))
    } else {
        absolute_http(&head.target).map(|(h, p, path)| (h, p, Some(path)))
    };
    let Some((host, port, path)) = parsed else {
        return refuse(&mut stream, "400 Bad Request", Reason::BadHost.text()).await;
    };
    let shown = match &host {
        Host::Name(n) => format!("{n}:{port}"),
        Host::Ip(IpAddr::V6(a)) => format!("[{a}]:{port}"),
        Host::Ip(a) => format!("{a}:{port}"),
    };
    let mut upstream = match open(policy, &host, port, timeouts.connect).await {
        Ok(up) => up,
        Err(Failure::Denied(reason)) => {
            tracing::info!(dest = %shown, verdict = "denied", reason = reason.text());
            return refuse(&mut stream, "403 Forbidden", reason.text()).await;
        }
        Err(Failure::Unreachable) => {
            tracing::info!(dest = %shown, verdict = "unreachable");
            return refuse(&mut stream, "502 Bad Gateway", "destination could not be reached").await;
        }
    };
    let kind = if connect { "CONNECT" } else { "HTTP" };
    tracing::info!(dest = %shown, verdict = "allowed", method = kind);
    let sent = if connect {
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await
    } else {
        let request = rewrite(&head, &shown, path.as_deref().unwrap_or("/"));
        upstream.write_all(&request).await
    };
    if sent.is_err() {
        return;
    }
    if !head.rest.is_empty() && upstream.write_all(&head.rest).await.is_err() {
        return;
    }
    relay(stream, upstream, timeouts.idle).await;
}

enum Failure {
    Denied(Reason),
    Unreachable,
}

// Resolves once, judges every address, then connects only to an address that passed: no second lookup to rebind.
async fn open(policy: &Policy, host: &Host, port: u16, timeout: Duration) -> Result<TcpStream, Failure> {
    policy.check_port(port).map_err(Failure::Denied)?;
    let (name, addrs): (Option<&str>, Vec<IpAddr>) = match host {
        Host::Ip(ip) => (None, vec![*ip]),
        Host::Name(n) => {
            policy.check_name(n).map_err(Failure::Denied)?;
            let found = tokio::time::timeout(timeout, tokio::net::lookup_host((n.as_str(), port)))
                .await
                .map_err(|_| Failure::Unreachable)?
                .map_err(|_| Failure::Unreachable)?;
            (Some(n.as_str()), found.map(|a| a.ip()).collect())
        }
    };
    let mut first_denial = None;
    let mut allowed = Vec::new();
    for ip in addrs {
        match policy.check_addr(name, ip) {
            Ok(()) => allowed.push(crate::addr::canonical(ip)),
            Err(r) => {
                first_denial.get_or_insert(r);
            }
        }
    }
    if allowed.is_empty() {
        return Err(Failure::Denied(first_denial.unwrap_or(Reason::BadHost)));
    }
    for ip in allowed {
        let attempt = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port))).await;
        if let Ok(Ok(stream)) = attempt {
            return Ok(stream);
        }
    }
    Err(Failure::Unreachable)
}

/// Splits `http://host[:port]/path?query` into its parts; https and userinfo are refused.
fn absolute_http(target: &str) -> Option<(Host, u16, String)> {
    let scheme = target.get(..7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = &target[7..];
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(cut);
    if authority.contains('@') || authority.is_empty() {
        return None;
    }
    let tail = tail.split('#').next().unwrap_or_default();
    let path = match tail.chars().next() {
        Some('/') => tail.to_string(),
        Some(_) => format!("/{tail}"),
        None => "/".to_string(),
    };
    let bracketed_port = authority.starts_with('[') && authority.contains("]:");
    let has_port = bracketed_port || (!authority.starts_with('[') && authority.contains(':'));
    if has_port {
        let (host, port) = parse_authority(authority)?;
        return Some((host, port, path));
    }
    Some((parse_host(authority)?, 80, path))
}

const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
    "host",
];

// Origin-form request line, the client's end-to-end headers, and one request per upstream connection.
fn rewrite(head: &Head, authority: &str, path: &str) -> Vec<u8> {
    let named_in_connection: Vec<String> = head
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect();
    let host = authority.strip_suffix(":80").unwrap_or(authority);
    let mut out = format!("{} {path} HTTP/1.1\r\nHost: {host}\r\n", head.method);
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || named_in_connection.contains(&lower) {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

enum Side {
    Client(std::io::Result<usize>),
    Upstream(std::io::Result<usize>),
}

async fn relay(mut client: TcpStream, mut upstream: TcpStream, idle: Duration) {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();
    let mut from_client = vec![0u8; BUF];
    let mut from_upstream = vec![0u8; BUF];
    let (mut client_open, mut upstream_open) = (true, true);
    while client_open || upstream_open {
        let step = tokio::time::timeout(idle, async {
            tokio::select! {
                r = cr.read(&mut from_client), if client_open => Side::Client(r),
                r = ur.read(&mut from_upstream), if upstream_open => Side::Upstream(r),
            }
        })
        .await;
        match step {
            Err(_) => break,
            Ok(Side::Client(Ok(0) | Err(_))) => {
                client_open = false;
                let _ = uw.shutdown().await;
            }
            Ok(Side::Client(Ok(n))) => {
                if uw.write_all(&from_client[..n]).await.is_err() {
                    break;
                }
            }
            Ok(Side::Upstream(Ok(0) | Err(_))) => {
                upstream_open = false;
                let _ = cw.shutdown().await;
            }
            Ok(Side::Upstream(Ok(n))) => {
                if cw.write_all(&from_upstream[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start(policy: Policy) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(policy), Timeouts::default()));
        addr
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

    async fn ask(proxy: SocketAddr, request: &str) -> (TcpStream, String) {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        (s, String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    #[tokio::test]
    async fn a_loopback_target_is_refused() {
        let target = echo_server().await;
        let proxy = start(Policy::default()).await;
        let (_, text) = ask(proxy, &format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")).await;
        assert!(text.starts_with("HTTP/1.1 403 Forbidden"), "{text}");
        assert!(text.contains("destination is a private or internal address"), "{text}");
        let (_, text) = ask(proxy, "CONNECT localhost:80 HTTP/1.1\r\n\r\n").await;
        assert!(text.starts_with("HTTP/1.1 403"), "{text}");
        let (_, text) = ask(proxy, &format!("GET http://{target}/x?secret=1 HTTP/1.1\r\n\r\n")).await;
        assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    }

    #[tokio::test]
    async fn an_allowed_cidr_loopback_target_connects() {
        let target = echo_server().await;
        let policy = Policy::from_lookup(|k| (k == "CITE_EGRESS_ALLOW_CIDRS").then(|| "127.0.0.0/8".to_string()))
            .unwrap();
        let proxy = start(policy).await;
        let (mut s, text) = ask(proxy, &format!("CONNECT {target} HTTP/1.1\r\n\r\n")).await;
        assert_eq!(text, "HTTP/1.1 200 Connection established\r\n\r\n");
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn plain_http_is_rewritten_to_origin_form() {
        let target = echo_server().await;
        let policy = Policy::from_lookup(|k| (k == "CITE_EGRESS_ALLOW_CIDRS").then(|| "127.0.0.1".to_string()))
            .unwrap();
        let proxy = start(policy).await;
        let request = format!(
            "GET http://{target}/a?b=1 HTTP/1.1\r\nHost: wrong\r\nProxy-Authorization: x\r\nConnection: keep-alive, X-Drop\r\nX-Drop: 1\r\nAccept: */*\r\n\r\n"
        );
        let (_, text) = ask(proxy, &request).await;
        assert!(text.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{text}");
        assert!(text.contains(&format!("Host: {target}\r\n")), "{text}");
        assert!(text.contains("Accept: */*\r\n") && text.contains("Connection: close\r\n"), "{text}");
        assert!(!text.contains("Proxy-Authorization") && !text.contains("X-Drop") && !text.contains("wrong"));
    }

    #[tokio::test]
    async fn malformed_and_weird_requests_are_refused() {
        let proxy = start(Policy::default()).await;
        for (request, status) in [
            ("CONNECT example.com:https HTTP/1.1\r\n\r\n", "400"),
            ("CONNECT example.com HTTP/1.1\r\n\r\n", "400"),
            ("CONNECT 2130706433:443 HTTP/1.1\r\n\r\n", "400"),
            ("CONNECT 0x7f.1:443 HTTP/1.1\r\n\r\n", "400"),
            ("GET https://example.com/ HTTP/1.1\r\n\r\n", "400"),
            ("GET /relative HTTP/1.1\r\n\r\n", "400"),
            ("GET http://user@example.com/ HTTP/1.1\r\n\r\n", "400"),
            ("GET http://example.com/ HTTP/2\r\n\r\n", "400"),
            ("GET  http://example.com/ HTTP/1.1\r\n\r\n", "400"),
            ("GET http://example.com/ HTTP/1.1\r\n folded\r\n\r\n", "400"),
            ("CONNECT example.com:25 HTTP/1.1\r\n\r\n", "403"),
            ("CONNECT [::1]:443 HTTP/1.1\r\n\r\n", "403"),
            ("CONNECT [::ffff:169.254.169.254]:80 HTTP/1.1\r\n\r\n", "403"),
            ("CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n", "403"),
        ] {
            let (_, text) = ask(proxy, request).await;
            assert!(text.starts_with(&format!("HTTP/1.1 {status}")), "{request:?}: {text}");
        }
        let huge = format!("GET http://example.com/{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_REQUEST_LINE + 10));
        let (_, text) = ask(proxy, &huge).await;
        assert!(text.starts_with("HTTP/1.1 431"), "{text}");
    }

    #[test]
    fn absolute_targets_split_cleanly() {
        let (host, port, path) = absolute_http("http://Example.com/a/b?c=d#frag").unwrap();
        assert_eq!((host, port, path.as_str()), (Host::Name("example.com".into()), 80, "/a/b?c=d"));
        let (_, port, path) = absolute_http("HTTP://example.com:8080").unwrap();
        assert_eq!((port, path.as_str()), (8080, "/"));
        let (host, port, path) = absolute_http("http://[2606:4700::1]:81?x").unwrap();
        assert_eq!((host, port, path.as_str()), (Host::Ip("2606:4700::1".parse().unwrap()), 81, "/?x"));
        let (_, port, _) = absolute_http("http://[2606:4700::1]/").unwrap();
        assert_eq!(port, 80);
        for bad in ["https://x.com/", "http://", "http://a@b.com/", "http://x.com:0/", "ftp://x.com/"] {
            assert!(absolute_http(bad).is_none(), "{bad}");
        }
    }
}
