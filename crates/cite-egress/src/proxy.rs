use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::addr::{Host, parse_authority, parse_host};
use crate::policy::{Policy, Reason};

pub const LISTEN: &str = "0.0.0.0:3128";
const MAX_CONNS: usize = 256;
const MAX_HEAD: usize = 16 * 1024;
const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;
const BUF: usize = 16 * 1024;
const DNS_TTL: Duration = Duration::from_secs(30);
const DNS_ENTRIES: usize = 256;
const FULL_WARN_EVERY: Duration = Duration::from_secs(10);
const MAX_CHUNK_LINE: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub header: Duration,
    /// One budget for the DNS lookup and every connect attempt together.
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

/// Accepts connections until the listener fails; past MAX_CONNS a client gets a 503 at once.
pub async fn serve(listener: TcpListener, policy: Arc<Policy>, timeouts: Timeouts) {
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    let resolver = Arc::new(Resolver::default());
    let mut last_full_warn: Option<Instant> = None;
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            if last_full_warn.is_none_or(|t| t.elapsed() >= FULL_WARN_EVERY) {
                tracing::warn!(limit = MAX_CONNS, "connection limit reached, refusing new clients");
                last_full_warn = Some(Instant::now());
            }
            let _ = stream.try_write(&reply("503 Service Unavailable", "egress proxy is at its connection limit"));
            continue;
        };
        let (policy, resolver) = (policy.clone(), resolver.clone());
        tokio::spawn(async move {
            handle(stream, &policy, &resolver, timeouts).await;
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

async fn timed<T>(limit: Duration, fut: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(limit, fut)
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")))
}

fn head_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + from)
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    // Bytes the client sent after the header block.
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
    let mut searched = 0;
    let end = loop {
        if let Some(pos) = head_end(&buf, searched) {
            break pos;
        }
        searched = buf.len().saturating_sub(3);
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
    let _ = timed(Duration::from_secs(5), stream.write_all(&reply(status, body))).await;
    let _ = timed(Duration::from_secs(5), stream.shutdown()).await;
}

async fn handle(mut stream: TcpStream, policy: &Policy, resolver: &Resolver, timeouts: Timeouts) {
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
    let body = if connect {
        None
    } else {
        match request_body(&head.headers) {
            Ok(body) => Some(body),
            Err(why) => return refuse(&mut stream, "400 Bad Request", why).await,
        }
    };
    let shown = match &host {
        Host::Name(n) => format!("{n}:{port}"),
        Host::Ip(IpAddr::V6(a)) => format!("[{a}]:{port}"),
        Host::Ip(a) => format!("{a}:{port}"),
    };
    let mut upstream = match open(policy, resolver, &host, port, timeouts.connect).await {
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
    let idle = timeouts.idle;
    match body {
        None => {
            let established = b"HTTP/1.1 200 Connection established\r\n\r\n";
            if timed(idle, stream.write_all(established)).await.is_err() {
                return;
            }
            if !head.rest.is_empty() && timed(idle, upstream.write_all(&head.rest)).await.is_err() {
                return;
            }
            relay(stream, upstream, idle).await;
        }
        Some(body) => {
            let request = rewrite(&head, &shown, path.as_deref().unwrap_or("/"));
            if timed(idle, upstream.write_all(&request)).await.is_err() {
                return;
            }
            exchange(stream, upstream, body, &head.rest, head.method == "HEAD", idle).await;
        }
    }
}

enum Failure {
    Denied(Reason),
    Unreachable,
}

/// Recent lookups, shared by every connection; the policy judges the addresses again on every use.
#[derive(Default)]
struct Resolver {
    cache: Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
}

impl Resolver {
    fn cached(&self, name: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .get(name)
            .filter(|(at, _)| at.elapsed() < DNS_TTL)
            .map(|(_, addrs)| addrs.clone())
    }

    fn remember(&self, name: &str, addrs: &[IpAddr]) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= DNS_ENTRIES && !cache.contains_key(name) {
            cache.retain(|_, (at, _)| at.elapsed() < DNS_TTL);
            if cache.len() >= DNS_ENTRIES
                && let Some(oldest) = cache.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(name.to_string(), (Instant::now(), addrs.to_vec()));
    }

    async fn lookup(&self, name: &str, port: u16, deadline: Instant) -> Option<Vec<IpAddr>> {
        if let Some(hit) = self.cached(name) {
            return Some(hit);
        }
        let found = tokio::time::timeout_at(deadline, tokio::net::lookup_host((name, port)))
            .await
            .ok()?
            .ok()?;
        let mut addrs: Vec<IpAddr> = Vec::new();
        for a in found {
            if !addrs.contains(&a.ip()) {
                addrs.push(a.ip());
            }
        }
        if addrs.is_empty() {
            return None;
        }
        self.remember(name, &addrs);
        Some(addrs)
    }
}

async fn connect_to(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    socket.set_keepalive(true)?;
    socket.connect(addr).await
}

// Resolves once, judges every address, then connects only to an address that passed: no second lookup to rebind.
async fn open(
    policy: &Policy,
    resolver: &Resolver,
    host: &Host,
    port: u16,
    budget: Duration,
) -> Result<TcpStream, Failure> {
    let deadline = Instant::now() + budget;
    policy.check_port(port).map_err(Failure::Denied)?;
    let (name, addrs): (Option<&str>, Vec<IpAddr>) = match host {
        Host::Ip(ip) => (None, vec![*ip]),
        Host::Name(n) => {
            policy.check_name(n).map_err(Failure::Denied)?;
            let found = resolver.lookup(n, port, deadline).await.ok_or(Failure::Unreachable)?;
            (Some(n.as_str()), found)
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
        match tokio::time::timeout_at(deadline, connect_to(SocketAddr::new(ip, port))).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(_)) => continue,
            Err(_) => break,
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

/// Where a message body ends.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Body {
    Length(u64),
    Chunked(Chunked),
    UntilClose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Chunked {
    Size { value: u64, digits: usize, ext: bool, cr: bool, len: usize },
    Data(u64),
    DataEnd(u8),
    Trailer { len: usize, cr: bool },
    Done,
}

impl Chunked {
    fn start() -> Chunked {
        Chunked::Size { value: 0, digits: 0, ext: false, cr: false, len: 0 }
    }

    fn step(&mut self, b: u8) -> Result<(), ()> {
        *self = match std::mem::replace(self, Chunked::Done) {
            Chunked::Size { value, digits, ext, cr, len } => {
                if len >= MAX_CHUNK_LINE {
                    return Err(());
                }
                let len = len + 1;
                match b {
                    b'\n' if cr && digits > 0 && value == 0 => Chunked::Trailer { len: 0, cr: false },
                    b'\n' if cr && digits > 0 => Chunked::Data(value),
                    _ if cr => return Err(()),
                    b'\r' => Chunked::Size { value, digits, ext, cr: true, len },
                    _ if !ext && b.is_ascii_hexdigit() => {
                        if digits >= 16 {
                            return Err(());
                        }
                        let d = u64::from(char::from(b).to_digit(16).unwrap_or(0));
                        Chunked::Size { value: value * 16 + d, digits: digits + 1, ext, cr, len }
                    }
                    b';' | b' ' | b'\t' if digits > 0 => Chunked::Size { value, digits, ext: true, cr, len },
                    _ if ext && (b == b'\t' || (b' '..=b'~').contains(&b)) => {
                        Chunked::Size { value, digits, ext, cr, len }
                    }
                    _ => return Err(()),
                }
            }
            Chunked::DataEnd(0) if b == b'\r' => Chunked::DataEnd(1),
            Chunked::DataEnd(1) if b == b'\n' => Chunked::start(),
            Chunked::Trailer { len, cr: false } if b == b'\r' => Chunked::Trailer { len, cr: true },
            Chunked::Trailer { len: 0, cr: true } if b == b'\n' => Chunked::Done,
            Chunked::Trailer { cr: true, .. } if b == b'\n' => Chunked::Trailer { len: 0, cr: false },
            Chunked::Trailer { len, cr: false } if len < MAX_HEAD => Chunked::Trailer { len: len + 1, cr: false },
            _ => return Err(()),
        };
        Ok(())
    }
}

impl Body {
    fn done(&self) -> bool {
        matches!(self, Body::Length(0) | Body::Chunked(Chunked::Done))
    }

    /// How many of these bytes belong to the body, and whether the body ends inside them.
    fn feed(&mut self, data: &[u8]) -> Result<(usize, bool), ()> {
        match self {
            Body::UntilClose => Ok((data.len(), false)),
            Body::Length(left) => {
                let take = data.len().min(usize::try_from(*left).unwrap_or(usize::MAX));
                *left -= take as u64;
                Ok((take, *left == 0))
            }
            Body::Chunked(state) => {
                let mut i = 0;
                while i < data.len() && *state != Chunked::Done {
                    if let Chunked::Data(left) = state {
                        let take = (data.len() - i).min(usize::try_from(*left).unwrap_or(usize::MAX));
                        i += take;
                        *left -= take as u64;
                        if *left == 0 {
                            *state = Chunked::DataEnd(0);
                        }
                        continue;
                    }
                    state.step(data[i])?;
                    i += 1;
                }
                Ok((i, *state == Chunked::Done))
            }
        }
    }
}

fn header_values<'a>(headers: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn content_length<'a>(values: impl Iterator<Item = &'a str>) -> Option<Option<u64>> {
    let mut found: Option<u64> = None;
    for v in values.flat_map(|v| v.split(',')).map(str::trim) {
        let shaped = !v.is_empty() && v.len() <= 19 && v.bytes().all(|b| b.is_ascii_digit());
        let n = v.parse::<u64>().ok().filter(|_| shaped)?;
        if found.is_some_and(|f| f != n) {
            return None;
        }
        found = Some(n);
    }
    Some(found)
}

// A request whose length two parsers could read differently is refused, so nothing is smuggled past the first request.
fn request_body(headers: &[(String, String)]) -> Result<Body, &'static str> {
    let te: Vec<&str> = header_values(headers, "transfer-encoding").collect();
    let has_cl = header_values(headers, "content-length").next().is_some();
    if !te.is_empty() && has_cl {
        return Err("request has both Content-Length and Transfer-Encoding");
    }
    if !te.is_empty() {
        return if te.len() == 1 && te[0].eq_ignore_ascii_case("chunked") {
            Ok(Body::Chunked(Chunked::start()))
        } else {
            Err("only chunked transfer encoding is supported")
        };
    }
    match content_length(header_values(headers, "content-length")) {
        Some(n) => Ok(Body::Length(n.unwrap_or(0))),
        None => Err("request has an invalid Content-Length"),
    }
}

fn response_body(head_request: bool, status: u16, headers: &[(String, String)]) -> Body {
    if head_request || (100..200).contains(&status) || status == 204 || status == 304 {
        return Body::Length(0);
    }
    let te: Vec<&str> = header_values(headers, "transfer-encoding").collect();
    if !te.is_empty() {
        let last = te.last().and_then(|v| v.rsplit(',').next()).unwrap_or_default().trim();
        return if last.eq_ignore_ascii_case("chunked") {
            Body::Chunked(Chunked::start())
        } else {
            Body::UntilClose
        };
    }
    match content_length(header_values(headers, "content-length")) {
        Some(Some(n)) => Body::Length(n),
        _ => Body::UntilClose,
    }
}

struct ResponseHead {
    status: u16,
    headers: Vec<(String, String)>,
    // The head as the client gets it: connection headers replaced by `Connection: close`.
    bytes: Vec<u8>,
}

fn parse_response_head(raw: &[u8]) -> Option<ResponseHead> {
    let mut lines = raw.split(|b| *b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status_line = lines.next()?;
    let text = std::str::from_utf8(status_line).ok()?;
    let mut parts = text.splitn(3, ' ');
    let version = parts.next()?;
    let code = parts.next()?;
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") || code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let status: u16 = code.parse().ok()?;
    let mut raw_headers: Vec<(&[u8], &[u8])> = Vec::new();
    for line in lines {
        let colon = line.iter().position(|b| *b == b':')?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty() || name.iter().any(|b| !b.is_ascii_graphic()) {
            return None;
        }
        raw_headers.push((name, value));
    }
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).trim().to_string();
    let headers: Vec<(String, String)> = raw_headers.iter().map(|&(n, v)| (lossy(n), lossy(v))).collect();
    let named: Vec<String> = header_values(&headers, "connection")
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let mut bytes = status_line.to_vec();
    bytes.extend_from_slice(b"\r\n");
    for (name, value) in &raw_headers {
        let lower = String::from_utf8_lossy(name).to_ascii_lowercase();
        if matches!(lower.as_str(), "connection" | "keep-alive" | "proxy-connection") || named.contains(&lower) {
            continue;
        }
        bytes.extend_from_slice(name);
        bytes.push(b':');
        bytes.extend_from_slice(value);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    Some(ResponseHead { status, headers, bytes })
}

async fn send_part<W: AsyncWrite + Unpin>(w: &mut W, body: &mut Body, data: &[u8], idle: Duration) -> io::Result<bool> {
    let (take, done) = body
        .feed(data)
        .map_err(|()| io::Error::new(io::ErrorKind::InvalidData, "bad chunked framing"))?;
    timed(idle, w.write_all(&data[..take])).await?;
    Ok(done)
}

// Forwards exactly one request body; whatever the client sends after it is never relayed.
async fn forward_body<R, W>(r: &mut R, w: &mut W, mut body: Body, first: &[u8], idle: Duration) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if body.done() || (!first.is_empty() && send_part(w, &mut body, first, idle).await?) {
        return Ok(());
    }
    let mut buf = vec![0u8; BUF];
    loop {
        let n = timed(idle, r.read(&mut buf)).await?;
        if n == 0 || send_part(w, &mut body, &buf[..n], idle).await? {
            return Ok(());
        }
    }
}

// Relays interim responses as they are, then one final response with close semantics, then closes the client.
async fn forward_response<R, W>(r: &mut R, w: &mut W, head_request: bool, idle: Duration) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; BUF];
    let mut wrote = false;
    let mut body = loop {
        let mut searched = 0;
        let end = loop {
            if let Some(pos) = head_end(&buf, searched) {
                break Some(pos);
            }
            searched = buf.len().saturating_sub(3);
            if buf.len() > MAX_HEAD {
                break None;
            }
            match timed(idle, r.read(&mut chunk)).await {
                Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                _ => break None,
            }
        };
        let Some(head) = end.and_then(|end| parse_response_head(&buf[..end]).map(|h| (end, h))) else {
            if !wrote {
                let _ = timed(idle, w.write_all(&reply("502 Bad Gateway", "destination sent no valid response"))).await;
            }
            let _ = timed(idle, w.shutdown()).await;
            return Ok(());
        };
        let (end, head) = head;
        let rest = buf.split_off(end + 4);
        let interim = (100..200).contains(&head.status) && head.status != 101;
        let out = if interim { std::mem::take(&mut buf) } else { head.bytes };
        timed(idle, w.write_all(&out)).await?;
        wrote = true;
        buf = rest;
        if !interim {
            break response_body(head_request, head.status, &head.headers);
        }
    };
    let mut done = body.done() || (!buf.is_empty() && send_part(w, &mut body, &buf, idle).await?);
    while !done {
        let n = timed(idle, r.read(&mut chunk)).await?;
        done = n == 0 || send_part(w, &mut body, &chunk[..n], idle).await?;
    }
    timed(idle, w.shutdown()).await
}

async fn exchange(mut client: TcpStream, mut upstream: TcpStream, body: Body, first: &[u8], head_request: bool, idle: Duration) {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();
    let send = forward_body(&mut cr, &mut uw, body, first, idle);
    let recv = forward_response(&mut ur, &mut cw, head_request, idle);
    tokio::pin!(send, recv);
    let mut sending = true;
    loop {
        tokio::select! {
            r = &mut send, if sending => {
                sending = false;
                if r.is_err() {
                    return;
                }
            }
            _ = &mut recv => return,
        }
    }
}

// Copies one direction until EOF; false when a write failed or stalled past `idle`.
async fn pump<R, W>(mut r: R, mut w: W, last: &AtomicU64, start: Instant, idle: Duration) -> bool
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let touch = || last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    let mut buf = vec![0u8; BUF];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        touch();
        if timed(idle, w.write_all(&buf[..n])).await.is_err() {
            return false;
        }
        touch();
    }
    let _ = timed(idle, w.shutdown()).await;
    true
}

// Both directions run at once; the tunnel ends when both close, a write stalls, or nothing moves for `idle`.
async fn relay(mut client: TcpStream, mut upstream: TcpStream, idle: Duration) {
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let (cr, cw) = client.split();
    let (ur, uw) = upstream.split();
    let up = pump(cr, uw, &last, start, idle);
    let down = pump(ur, cw, &last, start, idle);
    let watchdog = async {
        loop {
            let quiet = start.elapsed().saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed)));
            if quiet >= idle {
                return;
            }
            tokio::time::sleep(idle - quiet).await;
        }
    };
    tokio::pin!(up, down, watchdog);
    let (mut up_open, mut down_open) = (true, true);
    while up_open || down_open {
        tokio::select! {
            ok = &mut up, if up_open => {
                if !ok {
                    return;
                }
                up_open = false;
            }
            ok = &mut down, if down_open => {
                if !ok {
                    return;
                }
                down_open = false;
            }
            () = &mut watchdog => return,
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

    // Answers every request head it sees with a keep-alive response naming the request line, and records all bytes.
    async fn http_server() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        log.lock().unwrap().extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                        let line = text.lines().next().unwrap_or_default().to_string();
                        let body = format!("saw {line}");
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        if s.write_all(resp.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, seen)
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

    async fn read_all(s: &mut TcpStream) -> String {
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    // The upstream reads the body after it has answered the head, so wait for the tail to land.
    async fn upstream_text(seen: &Arc<Mutex<Vec<u8>>>, tail: &str) -> String {
        for _ in 0..100 {
            let text = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
            if text.ends_with(tail) {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        String::from_utf8_lossy(&seen.lock().unwrap()).into_owned()
    }

    fn loopback_policy() -> Policy {
        Policy::from_lookup(|k| (k == "CITE_EGRESS_ALLOW_CIDRS").then(|| "127.0.0.1".to_string())).unwrap()
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
        let (target, seen) = http_server().await;
        let proxy = start(loopback_policy()).await;
        let request = format!(
            "GET http://{target}/a?b=1 HTTP/1.1\r\nHost: wrong\r\nProxy-Authorization: x\r\nConnection: keep-alive, X-Drop\r\nX-Drop: 1\r\nAccept: */*\r\n\r\n"
        );
        let (mut s, _) = ask(proxy, &request).await;
        let _ = read_all(&mut s).await;
        let text = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        assert!(text.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{text}");
        assert!(text.contains(&format!("Host: {target}\r\n")), "{text}");
        assert!(text.contains("Accept: */*\r\n") && text.contains("Connection: close\r\n"), "{text}");
        assert!(!text.contains("Proxy-Authorization") && !text.contains("X-Drop") && !text.contains("wrong"));
    }

    #[tokio::test]
    async fn a_plain_http_connection_carries_one_request_and_then_closes() {
        let (target, seen) = http_server().await;
        let proxy = start(loopback_policy()).await;
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let two = format!(
            "POST http://{target}/one HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET http://evil.example/two HTTP/1.1\r\n\r\n"
        );
        s.write_all(two.as_bytes()).await.unwrap();
        let text = read_all(&mut s).await;
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("Connection: close\r\n"), "{text}");
        assert!(!text.contains("keep-alive") && !text.contains("Keep-Alive"), "{text}");
        assert!(text.ends_with("saw POST /one HTTP/1.1"), "{text}");
        let upstream = upstream_text(&seen, "\r\n\r\nabc").await;
        assert!(upstream.ends_with("\r\n\r\nabc"), "{upstream}");
        assert!(!upstream.contains("/two"), "the second request never reached the first host: {upstream}");
    }

    #[tokio::test]
    async fn a_chunked_request_body_ends_at_its_last_chunk() {
        let (target, seen) = http_server().await;
        let proxy = start(loopback_policy()).await;
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let req = format!(
            "POST http://{target}/c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let text = read_all(&mut s).await;
        assert!(text.contains("saw POST /c HTTP/1.1"), "{text}");
        let upstream = upstream_text(&seen, "0\r\nT: 1\r\n\r\n").await;
        assert!(upstream.ends_with("3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\n"), "{upstream}");
        assert!(!upstream.contains("smuggled"), "{upstream}");
    }

    #[tokio::test]
    async fn ambiguous_request_framing_is_refused() {
        let proxy = start(loopback_policy()).await;
        for request in [
            "POST http://127.0.0.1:9/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://127.0.0.1:9/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "POST http://127.0.0.1:9/ HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
            "POST http://127.0.0.1:9/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        ] {
            let (_, text) = ask(proxy, request).await;
            assert!(text.starts_with("HTTP/1.1 400"), "{request:?}: {text}");
        }
    }

    #[test]
    fn chunked_framing_finds_the_end_and_refuses_garbage() {
        let mut body = Body::Chunked(Chunked::start());
        assert_eq!(body.feed(b"4\r\nwi"), Ok((5, false)));
        assert_eq!(body.feed(b"ki\r\n0\r\n\r\nNEXT"), Ok((9, true)));
        for bad in [&b"x\r\n"[..], b"4\r\nwikiXX", b"\r\n", b"11111111111111111\r\n"] {
            let mut body = Body::Chunked(Chunked::start());
            assert!(body.feed(bad).is_err(), "{bad:?}");
        }
        let mut fixed = Body::Length(3);
        assert_eq!(fixed.feed(b"abcdef"), Ok((3, true)));
    }

    #[test]
    fn response_heads_lose_their_connection_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\nContent-Length: 2";
        let head = parse_response_head(raw).unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(
            String::from_utf8(head.bytes).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(response_body(false, 200, &head.headers), Body::Length(2));
        assert_eq!(response_body(true, 200, &head.headers), Body::Length(0));
        assert!(parse_response_head(b"garbage").is_none());
    }

    #[test]
    fn the_head_scan_finds_a_terminator_split_across_reads() {
        let buf = b"GET / HTTP/1.1\r\nA: b\r\n\r\n";
        assert_eq!(head_end(buf, 0), Some(20));
        assert_eq!(head_end(buf, 19), Some(20));
        assert_eq!(head_end(buf, 21), None);
        assert_eq!(head_end(buf, 99), None);
    }

    #[tokio::test]
    async fn the_resolver_cache_expires_and_stays_bounded() {
        let r = Resolver::default();
        let ip: IpAddr = "93.184.215.14".parse().unwrap();
        r.remember("example.com", &[ip]);
        assert_eq!(r.cached("example.com"), Some(vec![ip]));
        for i in 0..DNS_ENTRIES + 10 {
            r.remember(&format!("h{i}.example"), &[ip]);
        }
        assert!(r.cache.lock().unwrap().len() <= DNS_ENTRIES);
        r.cache.lock().unwrap().insert("old.example".into(), (Instant::now() - DNS_TTL, vec![ip]));
        assert_eq!(r.cached("old.example"), None);
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
