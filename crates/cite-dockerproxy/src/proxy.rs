use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName};
use http::{Method, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::config::Config;
use crate::policy::{BodyKind, Check, MAX_BODY, Policy, Route};
use crate::target::normalise;

const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_BUF: usize = 32 * 1024;
const MAX_INSPECT: usize = 1024 * 1024;
const HEALTH_TIMEOUT: Duration = Duration::from_secs(3);
// Headers that describe one connection and must not cross the proxy in either direction.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

type Out = UnsyncBoxBody<Bytes, io::Error>;

// Failures are mapped to a response in one place so no path leaks engine error text to the client.
enum Fail {
    Deny(String),
    Upstream(String),
    NotFound,
}

enum Managed {
    Missing,
    Foreign,
    Owned,
}

pub struct State {
    policy: Policy,
    socket: PathBuf,
    conns: Arc<Semaphore>,
}

impl State {
    pub fn new(cfg: &Config) -> Arc<State> {
        Arc::new(State {
            policy: Policy::new(cfg),
            socket: cfg.socket.clone(),
            conns: Arc::new(Semaphore::new(cfg.max_conns)),
        })
    }
}

struct Deadline<B> {
    inner: B,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<B: Body<Data = Bytes> + Unpin> Body for Deadline<B>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if self.sleep.as_mut().poll(cx).is_ready() {
            let timed_out = io::Error::new(io::ErrorKind::TimedOut, "response deadline exceeded");
            return Poll::Ready(Some(Err(timed_out)));
        }
        Pin::new(&mut self.inner)
            .poll_frame(cx)
            .map(|next| next.map(|frame| frame.map_err(io::Error::other)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn reply(status: StatusCode, message: &str) -> Response<Out> {
    let body = format!("{{\"message\":\"{message}\"}}");
    let mut resp = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    if status == StatusCode::FORBIDDEN {
        resp.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
    }
    resp
}

fn printable(raw: &str) -> String {
    raw.chars()
        .take(200)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

fn has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|v| {
        v.to_str()
            .is_ok_and(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    })
}

// Framing headers are refused outright; the proxy re-frames the body it forwards itself.
fn check_headers(headers: &HeaderMap) -> Result<(), String> {
    if headers.contains_key(header::UPGRADE) || has_token(headers, header::CONNECTION, "upgrade") {
        return Err("upgrade requests are not allowed".to_string());
    }
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err("transfer-encoding is not allowed".to_string());
    }
    Ok(())
}

fn declared_length(headers: &HeaderMap) -> Result<u64, String> {
    match headers.get(header::CONTENT_LENGTH) {
        None => Ok(0),
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| "content-length is invalid".to_string()),
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let lower = value.to_ascii_lowercase();
    lower == "application/json" || lower == "application/json; charset=utf-8"
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        headers.remove(name);
    }
}

impl State {
    async fn process(&self, req: Request<Incoming>) -> Result<Response<Out>, Fail> {
        let (parts, body) = req.into_parts();
        if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
            return Err(Fail::Deny("absolute-form target".to_string()));
        }
        let raw = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .ok_or_else(|| Fail::Deny("request has no path".to_string()))?;
        check_headers(&parts.headers).map_err(Fail::Deny)?;
        let target = normalise(raw).map_err(Fail::Deny)?;
        let route = self
            .policy
            .classify(parts.method.as_str(), &target)
            .map_err(Fail::Deny)?;
        let deadline = Instant::now() + route.timeout();
        let payload = read_payload(&route, &parts.headers, body).await?;
        if let Some(bytes) = &payload {
            let value: Value = serde_json::from_slice(bytes)
                .map_err(|_| Fail::Deny("body is not valid json".to_string()))?;
            self.policy
                .validate_body(&route, &value)
                .map_err(Fail::Deny)?;
        }
        if let Some(check) = route.check() {
            match self.managed(&check, deadline).await? {
                Managed::Missing => return Err(Fail::NotFound),
                Managed::Foreign => {
                    return Err(Fail::Deny("object is not managed by cite".to_string()));
                }
                Managed::Owned => {}
            }
        }
        // Only the validated target and body go upstream; no client header is copied.
        let resp = self.call(parts.method, raw, payload, deadline).await?;
        let (mut head, body) = resp.into_parts();
        strip_hop_by_hop(&mut head.headers);
        let guarded = Deadline {
            inner: body,
            sleep: Box::pin(tokio::time::sleep_until(deadline)),
        };
        Ok(Response::from_parts(head, guarded.boxed_unsync()))
    }

    async fn call(
        &self,
        method: Method,
        target: &str,
        payload: Option<Bytes>,
        deadline: Instant,
    ) -> Result<Response<Incoming>, Fail> {
        let up = |what: &str, e: &dyn std::fmt::Display| Fail::Upstream(format!("{what}: {e}"));
        let stream = tokio::time::timeout_at(deadline, UnixStream::connect(&self.socket))
            .await
            .map_err(|e| up("connect", &e))?
            .map_err(|e| up("connect", &e))?;
        let (mut sender, conn) = client_http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| up("handshake", &e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut builder = Request::builder()
            .method(method)
            .uri(target)
            .header(header::HOST, "docker");
        if payload.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let req = builder
            .body(Full::new(payload.unwrap_or_default()))
            .map_err(|e| up("request", &e))?;
        tokio::time::timeout_at(deadline, sender.send_request(req))
            .await
            .map_err(|e| up("response", &e))?
            .map_err(|e| up("response", &e))
    }

    // Looks the object up through the engine itself, so the label cannot be spoofed by the caller.
    async fn managed(&self, check: &Check, deadline: Instant) -> Result<Managed, Fail> {
        let (path, labels): (String, &[&str]) = match check {
            Check::Container(n) => (format!("/containers/{n}/json"), &["Config", "Labels"]),
            Check::Volume(n) => (format!("/volumes/{n}"), &["Labels"]),
            Check::Network(n) => (format!("/networks/{n}"), &["Labels"]),
        };
        let resp = self.call(Method::GET, &path, None, deadline).await?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(Managed::Missing);
        }
        if !status.is_success() {
            return Err(Fail::Upstream(format!("inspect returned {status}")));
        }
        let bytes = tokio::time::timeout_at(
            deadline,
            Limited::new(resp.into_body(), MAX_INSPECT).collect(),
        )
        .await
        .map_err(|_| Fail::Upstream("inspect timed out".to_string()))?
        .map_err(|_| Fail::Upstream("inspect body unreadable".to_string()))?
        .to_bytes();
        let doc: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Fail::Upstream("inspect body is not json".to_string()))?;
        let node = labels.iter().fold(&doc, |v, key| &v[*key]);
        Ok(if node["cite.managed"].as_str() == Some("true") {
            Managed::Owned
        } else {
            Managed::Foreign
        })
    }
}

// Bodies are small JSON documents, so they are buffered whole and size-limited before parsing.
async fn read_payload(
    route: &Route,
    headers: &HeaderMap,
    body: Incoming,
) -> Result<Option<Bytes>, Fail> {
    let deny = |m: &str| Fail::Deny(m.to_string());
    let length = declared_length(headers).map_err(Fail::Deny)?;
    if route.body() == BodyKind::None {
        if length > 0 || !body.is_end_stream() {
            return Err(deny("request carries a body"));
        }
        return Ok(None);
    }
    if !is_json(headers) {
        return Err(deny("content-type must be application/json"));
    }
    if length > MAX_BODY as u64 {
        return Err(deny("body is too large"));
    }
    let collected = tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, MAX_BODY).collect())
        .await
        .map_err(|_| deny("body was not received in time"))?
        .map_err(|_| deny("body is too large or unreadable"))?;
    let bytes = collected.to_bytes();
    if bytes.is_empty() {
        return Err(deny("body is empty"));
    }
    Ok(Some(bytes))
}

async fn handle(state: Arc<State>, req: Request<Incoming>) -> Result<Response<Out>, Infallible> {
    let method = req.method().to_string();
    let raw = req.uri().to_string();
    Ok(match state.process(req).await {
        Ok(resp) => resp,
        Err(Fail::Deny(reason)) => {
            tracing::warn!(method = %method, path = %printable(&raw), reason = %reason, "denied");
            reply(StatusCode::FORBIDDEN, "denied")
        }
        Err(Fail::NotFound) => reply(StatusCode::NOT_FOUND, "no such object"),
        Err(Fail::Upstream(why)) => {
            tracing::error!(method = %method, path = %printable(&raw), error = %why, "docker engine unavailable");
            reply(StatusCode::BAD_GATEWAY, "upstream unavailable")
        }
    })
}

// A permit is taken before accepting, which makes the connection cap apply backpressure.
pub async fn serve(listener: TcpListener, state: Arc<State>) {
    loop {
        let Ok(permit) = state.conns.clone().acquire_owned().await else {
            return;
        };
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(state.clone(), req));
            let conn = server_http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .max_buf_size(MAX_HEADER_BUF)
                .serve_connection(TokioIo::new(stream), svc);
            if let Err(e) = conn.await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
            drop(permit);
        });
    }
}

// Asks the running proxy for /_ping, which also proves the Docker socket answers.
pub async fn healthcheck(listen: SocketAddr) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = if listen.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], listen.port()))
    } else {
        listen
    };
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;
        stream
            .write_all(b"GET /_ping HTTP/1.1\r\nHost: healthcheck\r\nConnection: close\r\n\r\n")
            .await?;
        let mut reply = Vec::new();
        stream.take(4096).read_to_end(&mut reply).await?;
        Ok::<_, io::Error>(reply)
    };
    let reply = tokio::time::timeout(HEALTH_TIMEOUT, exchange)
        .await
        .map_err(|_| "healthcheck timed out".to_string())?
        .map_err(|e| format!("healthcheck failed: {e}"))?;
    if reply.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err("proxy did not answer /_ping with 200".to_string())
    }
}
