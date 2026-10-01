#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, header};
use http_body::Frame;
use http_body_util::{BodyExt, LengthLimitError, Limited, StreamBody};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::error_page::{self, BoxBody, full_body, page_413, page_502, page_504};

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

/// Headers apps read as the client address or origin; only a trusted proxy may set them.
const CLIENT_IDENTITY_HEADERS: &[&str] = &[
    "x-real-ip",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "true-client-ip",
    "x-client-ip",
    "cf-connecting-ip",
];

pub struct ProxyConfig<'a> {
    /// Kept alive by an upgraded tunnel so its connection permit is held until the tunnel closes.
    pub hold: Option<Arc<dyn Send + Sync>>,
    pub port: u16,
    pub peer: SocketAddr,
    pub trusted_proxies: &'a [ipnet::IpNet],
    pub allowed_hosts: &'a [String],
    pub connect_timeout: Duration,
    pub header_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_body: u64,
}

pub async fn proxy_request(mut req: Request<Incoming>, cfg: ProxyConfig<'_>) -> Response<BoxBody> {
    if let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        if !cfg.allowed_hosts.is_empty() {
            let host_only = host.split(':').next().unwrap_or(host);
            if !cfg
                .allowed_hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(host_only) || h.eq_ignore_ascii_case(host))
            {
                return error_page::page_400("bad host");
            }
        }
    }

    if declared_length_exceeds(req.headers(), cfg.max_body) {
        return page_413();
    }

    let is_upgrade = req.headers().contains_key(header::UPGRADE);
    strip_hop_by_hop(req.headers_mut(), is_upgrade);
    set_forwarded_headers_for(
        req.headers_mut(),
        cfg.peer,
        cfg.trusted_proxies,
        cfg.allowed_hosts,
    );

    let upstream: SocketAddr = ([127, 0, 0, 1], cfg.port).into();
    let connect = TcpStream::connect(upstream);
    let stream = match tokio::time::timeout(cfg.connect_timeout, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return page_502(),
        Err(_) => return page_504(),
    };
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(_) => return page_502(),
    };

    let conn_fut = conn.with_upgrades();
    tokio::spawn(async move {
        let _ = conn_fut.await;
    });

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let new_uri: Uri = match path_and_query.parse() {
        Ok(u) => u,
        Err(_) => return page_502(),
    };
    *req.uri_mut() = new_uri;

    let exceeded = Arc::new(AtomicBool::new(false));
    let req = req.map(|body| limit_request_body(body, cfg.max_body, exceeded.clone()));
    let send = sender.send_request(req);
    let res = match tokio::time::timeout(cfg.header_timeout, send).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) if exceeded.load(Ordering::SeqCst) => return page_413(),
        Ok(Err(_)) => return page_502(),
        Err(_) => return page_504(),
    };

    if is_upgrade && res.status() == StatusCode::SWITCHING_PROTOCOLS {
        return handle_upgrade(res).await;
    }

    response_from_upstream(res, cfg.idle_timeout)
}

async fn handle_upgrade(res: Response<Incoming>) -> Response<BoxBody> {
    // Only the 101 headers are returned here; the byte pipe needs the client's OnUpgrade, which lives in the other upgrade path.
    let (parts, body) = res.into_parts();
    if let Ok(upstream_upgraded) =
        hyper::upgrade::on(Response::from_parts(parts.clone(), body)).await
    {
        drop(upstream_upgraded);
    }
    let mut out = Response::new(full_body(Bytes::new()));
    *out.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    for (k, v) in parts.headers.iter() {
        if is_hop_by_hop(k) && k != header::UPGRADE && k.as_str() != "connection" {
            continue;
        }
        out.headers_mut().append(k.clone(), v.clone());
    }
    out
}

fn response_from_upstream(res: Response<Incoming>, idle_timeout: Duration) -> Response<BoxBody> {
    let (parts, body) = res.into_parts();

    let stream = stream::unfold(body, move |mut body| async move {
        match tokio::time::timeout(idle_timeout, body.frame()).await {
            Ok(Some(Ok(frame))) => Some((
                Ok::<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>(frame),
                body,
            )),
            Ok(Some(Err(err))) => Some((Err(std::io::Error::other(err).into()), body)),
            Ok(None) => None,
            Err(_) => Some((
                Err(
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream idle timeout")
                        .into(),
                ),
                body,
            )),
        }
    });
    let connection_tokens: Vec<HeaderName> = parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|token| HeaderName::try_from(token.trim()).ok())
        .collect();
    let mut out = Response::new(StreamBody::new(stream).boxed_unsync());
    *out.status_mut() = parts.status;
    *out.version_mut() = parts.version;
    for (k, v) in parts.headers.iter() {
        if is_hop_by_hop(k) || connection_tokens.iter().any(|name| name == k) {
            continue;
        }
        out.headers_mut().append(k.clone(), v.clone());
    }
    out
}

pub async fn proxy_with_upgrade(req: Request<Incoming>, cfg: ProxyConfig<'_>) -> Response<BoxBody> {
    let is_upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    if !is_upgrade {
        return proxy_request(req, cfg).await;
    }

    if declared_length_exceeds(req.headers(), cfg.max_body) {
        return page_413();
    }

    let (parts, body) = req.into_parts();
    let client_upgrade = hyper::upgrade::on(Request::from_parts(
        parts.clone(),
        http_body_util::Empty::<Bytes>::new(),
    ));

    let exceeded = Arc::new(AtomicBool::new(false));
    let body = limit_request_body(body, cfg.max_body, exceeded.clone());
    let mut upstream_req = Request::from_parts(parts, body);
    strip_hop_by_hop(upstream_req.headers_mut(), true);
    set_forwarded_headers_for(
        upstream_req.headers_mut(),
        cfg.peer,
        cfg.trusted_proxies,
        cfg.allowed_hosts,
    );

    let upstream: SocketAddr = ([127, 0, 0, 1], cfg.port).into();
    let stream = match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(upstream)).await
    {
        Ok(Ok(s)) => s,
        _ => return page_502(),
    };
    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(p) => p,
        Err(_) => return page_502(),
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let pq = upstream_req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    if let Ok(u) = pq.parse() {
        *upstream_req.uri_mut() = u;
    }

    let res =
        match tokio::time::timeout(cfg.header_timeout, sender.send_request(upstream_req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) if exceeded.load(Ordering::SeqCst) => return page_413(),
            Ok(Err(_)) => return page_502(),
            Err(_) => return page_504(),
        };

    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        return response_from_upstream(res, cfg.idle_timeout);
    }

    let (res_parts, res_body) = res.into_parts();
    let upstream_upgrade = hyper::upgrade::on(Response::from_parts(res_parts.clone(), res_body));

    let hold = cfg.hold.clone();
    let idle = cfg.idle_timeout;
    tokio::spawn(async move {
        let _hold = hold;
        let (client, upstream) = match tokio::join!(client_upgrade, upstream_upgrade) {
            (Ok(c), Ok(u)) => (c, u),
            _ => return,
        };
        let activity = Arc::new(AtomicU64::new(0));
        let mut client = Watched::new(TokioIo::new(client), activity.clone());
        let mut upstream = Watched::new(TokioIo::new(upstream), activity.clone());
        let mut copy = std::pin::pin!(tokio::io::copy_bidirectional(&mut client, &mut upstream));
        let mut seen = 0;
        loop {
            tokio::select! {
                _ = &mut copy => break,
                _ = tokio::time::sleep(idle) => {
                    let now = activity.load(Ordering::Relaxed);
                    if now == seen {
                        break;
                    }
                    seen = now;
                }
            }
        }
    });

    let mut out = Response::new(full_body(Bytes::new()));
    *out.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    for (k, v) in res_parts.headers.iter() {
        out.headers_mut().append(k.clone(), v.clone());
    }
    out
}

/// Counts bytes moved in either direction so an idle tunnel can be told from a busy one.
struct Watched<T> {
    inner: T,
    activity: Arc<AtomicU64>,
}

impl<T> Watched<T> {
    fn new(inner: T, activity: Arc<AtomicU64>) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_ready() {
            let moved = buf.filled().len().saturating_sub(before);
            self.activity.fetch_add(moved as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(moved)) = &result {
            self.activity.fetch_add(*moved as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn declared_length_exceeds(headers: &HeaderMap, max_body: u64) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|len| len > max_body)
}

fn limit_request_body(body: Incoming, max_body: u64, exceeded: Arc<AtomicBool>) -> BoxBody {
    let limit = usize::try_from(max_body).unwrap_or(usize::MAX);
    Limited::new(body, limit)
        .map_err(move |err| {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                exceeded.store(true, Ordering::SeqCst);
            }
            err
        })
        .boxed_unsync()
}

fn forwarded_for_node(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

fn scheme_token(value: &str) -> String {
    let last = value.rsplit(',').next().unwrap_or("").trim();
    let mut chars = last.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    if valid {
        last.to_ascii_lowercase()
    } else {
        "http".to_string()
    }
}

fn quote_forwarded(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn is_trusted_ip(trusted: &[ipnet::IpNet], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    trusted.iter().any(|net| net.contains(&ip))
}

/// The address a request is attributed to: the peer, or behind a trusted proxy the right-most untrusted X-Forwarded-For hop.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[ipnet::IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    if !is_trusted_ip(trusted, peer) {
        return peer;
    }
    for value in headers.get_all("x-forwarded-for").iter().rev() {
        for hop in value.as_bytes().rsplit(|byte| *byte == b',') {
            let Some(ip) = parse_hop(hop.trim_ascii()) else {
                return peer;
            };
            if !is_trusted_ip(trusted, ip) {
                return ip;
            }
        }
    }
    peer
}

fn parse_hop(hop: &[u8]) -> Option<IpAddr> {
    let hop = std::str::from_utf8(hop).ok()?;
    if let Ok(addr) = hop.parse::<SocketAddr>() {
        return Some(addr.ip().to_canonical());
    }
    let bare = hop.trim_start_matches('[');
    let ip: IpAddr = bare.split(']').next().unwrap_or(bare).parse().ok()?;
    Some(ip.to_canonical())
}

#[cfg(test)]
pub fn set_forwarded_headers(headers: &mut HeaderMap, peer: SocketAddr, trusted: &[ipnet::IpNet]) {
    set_forwarded_headers_for(headers, peer, trusted, &[]);
}

/// With a non-empty `allowed_hosts`, a trusted X-Forwarded-Host is kept only if it is allowed; otherwise the request's own Host replaces it.
pub fn set_forwarded_headers_for(
    headers: &mut HeaderMap,
    peer: SocketAddr,
    trusted: &[ipnet::IpNet],
    allowed_hosts: &[String],
) {
    let peer_ip = peer.ip().to_canonical();
    let trusted_peer = is_trusted_ip(trusted, peer_ip);

    let text_of = |headers: &HeaderMap, name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let client_xff = text_of(headers, "x-forwarded-for");
    let client_proto = text_of(headers, "x-forwarded-proto");
    let client_host = text_of(headers, "x-forwarded-host");
    let client_forwarded = text_of(headers, "forwarded");
    let own_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    if !trusted_peer {
        for name in CLIENT_IDENTITY_HEADERS {
            headers.remove(*name);
        }
    }
    headers.remove("x-forwarded-for");
    headers.remove("x-forwarded-proto");
    headers.remove("x-forwarded-host");
    headers.remove("forwarded");

    let (xff, proto, host) = if trusted_peer {
        let xff = match client_xff {
            Some(existing) => format!("{existing}, {peer_ip}"),
            None => peer_ip.to_string(),
        };
        (
            xff,
            client_proto.unwrap_or_else(|| "http".to_string()),
            client_host
                .filter(|host| cite_core::host_allowed(allowed_hosts, host))
                .unwrap_or(own_host),
        )
    } else {
        (peer_ip.to_string(), "http".to_string(), own_host)
    };

    let element = format!(
        "for=\"{}\";proto={};host=\"{}\"",
        forwarded_for_node(peer_ip),
        scheme_token(&proto),
        quote_forwarded(&host)
    );
    let forwarded = match client_forwarded {
        Some(existing) if trusted_peer => format!("{existing}, {element}"),
        _ => element,
    };

    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&proto) {
        headers.insert(HeaderName::from_static("x-forwarded-proto"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&host) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&forwarded) {
        headers.insert(HeaderName::from_static("forwarded"), v);
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    let connection_tokens: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    for name in HOP_BY_HOP {
        if keep_upgrade && (*name == "upgrade" || *name == "connection") {
            continue;
        }
        headers.remove(*name);
    }
    for token in connection_tokens {
        if keep_upgrade && (token == "upgrade" || token == "connection") {
            continue;
        }
        if let Ok(name) = HeaderName::try_from(token.as_str()) {
            headers.remove(name);
        }
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.iter().any(|h| name.as_str() == *h)
}

#[allow(dead_code)]
fn _ip_addr_str(ip: IpAddr) -> String {
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn hop_by_hop_headers_are_stripped_unless_upgrading() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("close, x-cite-hop"),
        );
        headers.insert("x-cite-hop", HeaderValue::from_static("leak"));
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert("x-keep", HeaderValue::from_static("yes"));
        strip_hop_by_hop(&mut headers, false);
        assert!(headers.get("x-cite-hop").is_none());
        assert!(headers.get(header::TE).is_none());
        assert!(headers.get(header::CONNECTION).is_none());
        assert_eq!(headers.get("x-keep").unwrap(), "yes");

        let mut upgrade = HeaderMap::new();
        upgrade.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        upgrade.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        strip_hop_by_hop(&mut upgrade, true);
        assert_eq!(upgrade.get(header::UPGRADE).unwrap(), "websocket");
        assert!(upgrade.get(header::CONNECTION).is_some());
    }

    #[test]
    fn untrusted_overwrites_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 1234));
        set_forwarded_headers(&mut headers, peer, &[]);
        assert_eq!(
            headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "10.0.0.5"
        );
    }

    #[test]
    fn untrusted_peers_lose_client_identity_headers() {
        let names = [
            "x-real-ip",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "true-client-ip",
            "x-client-ip",
            "cf-connecting-ip",
        ];
        let filled = || {
            let mut headers = HeaderMap::new();
            for name in names {
                headers.insert(name, HeaderValue::from_static("1.2.3.4"));
            }
            headers
        };
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 1234));
        let mut untrusted = filled();
        set_forwarded_headers(&mut untrusted, peer, &[]);
        assert!(names.iter().all(|name| !untrusted.contains_key(*name)));
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let mut kept = filled();
        set_forwarded_headers(&mut kept, peer, &trusted);
        assert!(names.iter().all(|name| kept.contains_key(*name)));
    }

    #[test]
    fn client_ip_uses_the_right_most_untrusted_hop_behind_trusted_proxies() {
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let proxy: IpAddr = "10.0.0.5".parse().unwrap();
        let outside: IpAddr = "198.51.100.7".parse().unwrap();
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
            headers
        };
        assert_eq!(client_ip(outside, &with("1.1.1.1"), &trusted), outside);
        assert_eq!(client_ip(proxy, &HeaderMap::new(), &trusted), proxy);
        assert_eq!(
            client_ip(proxy, &with("203.0.113.9"), &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(proxy, &with("6.6.6.6, 203.0.113.9, 10.1.1.1"), &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(proxy, &with("[2001:db8::1]:443"), &trusted),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(proxy, &with("10.2.2.2, 10.3.3.3"), &trusted),
            proxy
        );
        assert_eq!(client_ip(proxy, &with("not-an-ip"), &trusted), proxy);
        let mut raw = HeaderMap::new();
        raw.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"\xff\xfe junk, 203.0.113.9").unwrap(),
        );
        assert_eq!(
            client_ip(proxy, &raw, &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        let mapped_peer: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
        assert_eq!(
            client_ip(mapped_peer, &with("203.0.113.9"), &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert!(is_trusted_ip(&trusted, mapped_peer));
    }

    #[test]
    fn trusted_forwarded_host_must_pass_the_allowlist() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 1234));
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let allowed = vec!["example.com".to_string()];
        let run = |forwarded: &str, allowed: &[String]| {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, HeaderValue::from_static("example.com"));
            headers.insert(
                "x-forwarded-host",
                HeaderValue::from_str(forwarded).unwrap(),
            );
            set_forwarded_headers_for(&mut headers, peer, &trusted, allowed);
            headers
        };
        let evil = run("evil.example", &allowed);
        assert_eq!(evil.get("x-forwarded-host").unwrap(), "example.com");
        assert!(
            evil.get("forwarded")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("host=\"example.com\"")
        );
        assert_eq!(
            run("example.com:8443", &allowed)
                .get("x-forwarded-host")
                .unwrap(),
            "example.com:8443"
        );
        assert_eq!(
            run("evil.example", &[]).get("x-forwarded-host").unwrap(),
            "evil.example"
        );
    }

    #[test]
    fn mapped_ipv6_peer_is_trusted_and_written_canonically() {
        let mapped: SocketAddr = "[::ffff:10.0.0.5]:1234".parse().unwrap();
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
        set_forwarded_headers(&mut headers, mapped, &trusted);
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "9.9.9.9, 10.0.0.5");
        assert!(headers.contains_key("x-real-ip"));
        assert!(
            headers
                .get("forwarded")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("for=\"10.0.0.5\"")
        );
        let mut untrusted = HeaderMap::new();
        set_forwarded_headers(&mut untrusted, mapped, &[]);
        assert_eq!(untrusted.get("x-forwarded-for").unwrap(), "10.0.0.5");
    }

    #[test]
    fn trusted_appends_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 1234));
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        set_forwarded_headers(&mut headers, peer, &trusted);
        assert_eq!(
            headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "9.9.9.9, 10.0.0.5"
        );
    }
}
