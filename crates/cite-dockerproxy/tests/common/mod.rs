#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use cite_dockerproxy::config::Config;
use cite_dockerproxy::policy::Policy;
use cite_dockerproxy::proxy::{State, serve};
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

pub const REGISTRY: &str = "ghcr.io/seggys116";
pub const HAPROXY: &str = "cite-node-haproxy";

pub fn config(socket: &Path) -> Config {
    let socket = socket.display().to_string();
    Config::from_lookup(|k| match k {
        "CITE_PROXY_SOCKET" => Some(socket.clone()),
        "CITE_PROXY_LISTEN" => Some("127.0.0.1:0".to_string()),
        _ => None,
    })
    .unwrap()
}

// Policy construction needs no socket, so the path is never opened.
pub fn policy() -> Policy {
    Policy::new(&config(Path::new("/unused.sock")))
}

// A policy whose operator set (or left unset) the one GitHub API URL managers may use.
pub fn policy_with_github(url: Option<&str>) -> Policy {
    let cfg = Config::from_lookup(|k| match k {
        "CITE_PROXY_GITHUB_API_URL" => url.map(str::to_string),
        _ => None,
    })
    .unwrap();
    Policy::new(&cfg)
}

// A policy built from arbitrary proxy settings.
pub fn policy_with(pairs: &[(&str, &str)]) -> Policy {
    let cfg = Config::from_lookup(|k| {
        pairs
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.to_string())
    })
    .unwrap();
    Policy::new(&cfg)
}

// A policy whose operator set the manager and executor memory and CPU maxima.
pub fn policy_with_limits(mem: &str, cpus: &str) -> Policy {
    let cfg = Config::from_lookup(|k| match k {
        "CITE_STACK_MAX_MEM" => Some(mem.to_string()),
        "CITE_STACK_MAX_CPUS" => Some(cpus.to_string()),
        _ => None,
    })
    .unwrap();
    Policy::new(&cfg)
}

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
pub struct World {
    pub images: HashSet<String>,
    pub volumes: BTreeMap<String, Value>,
    pub networks: BTreeMap<String, (Value, HashSet<String>)>,
    pub containers: BTreeMap<String, (Value, bool)>,
    pub logs: BTreeMap<String, String>,
    pub seen: Vec<Seen>,
}

impl World {
    pub fn add_container(&mut self, name: &str, labels: Value) {
        let spec = json!({ "Image": "x", "Env": [], "Labels": labels, "HostConfig": {} });
        self.containers.insert(name.to_string(), (spec, true));
    }

    pub fn log(&self) -> Vec<String> {
        self.seen
            .iter()
            .map(|s| format!("{} {}", s.method, s.uri))
            .collect()
    }
}

// Yields one frame per line so the proxy has to stream a chunked response.
struct Chunks(VecDeque<Bytes>);

impl Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
    }
}

pub struct FakeDocker {
    pub path: PathBuf,
    pub world: Arc<Mutex<World>>,
    _dir: tempfile::TempDir,
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.replace("%3A", ":").replace("%2F", "/"))
    })
}

fn route(w: &mut World, method: &str, path: &str, query: &str, body: &[u8]) -> (u16, String) {
    let path = path.strip_prefix("/v1.45").unwrap_or(path);
    let missing = || (404, json!({ "message": "no such object" }).to_string());
    let doc: Value = serde_json::from_slice(body).unwrap_or_default();
    match (method, path.split('/').skip(1).collect::<Vec<_>>().as_slice()) {
        ("GET", ["_ping"]) => (200, "OK".to_string()),
        ("POST", ["images", "create"]) => {
            let image = query_value(query, "fromImage").unwrap_or_default();
            let tag = query_value(query, "tag").unwrap_or_default();
            w.images.insert(format!("{image}:{tag}"));
            (200, "{\"status\":\"Pulling\"}\n{\"status\":\"Done\"}\n".to_string())
        }
        ("GET", ["images", reference @ .., "json"]) => {
            if w.images.contains(&reference.join("/")) { (200, "{}".to_string()) } else { missing() }
        }
        ("POST", ["volumes", "create"]) => {
            let name = doc["Name"].as_str().unwrap_or_default().to_string();
            w.volumes.insert(name, doc["Labels"].clone());
            (201, "{}".to_string())
        }
        ("GET", ["volumes", name]) => match w.volumes.get(*name) {
            Some(labels) => (200, json!({ "Labels": labels }).to_string()),
            None => missing(),
        },
        ("DELETE", ["volumes", name]) => w.volumes.remove(*name).map_or_else(missing, |_| (204, String::new())),
        ("POST", ["networks", "create"]) => {
            let name = doc["Name"].as_str().unwrap_or_default().to_string();
            w.networks.insert(name, (doc["Labels"].clone(), HashSet::new()));
            (201, "{\"Id\":\"n\"}".to_string())
        }
        ("GET", ["networks", name]) => match w.networks.get(*name) {
            Some((labels, members)) => {
                let containers: serde_json::Map<String, Value> =
                    members.iter().map(|m| (format!("id-{m}"), json!({ "Name": m }))).collect();
                (200, json!({ "Labels": labels, "Containers": containers }).to_string())
            }
            None => missing(),
        },
        ("DELETE", ["networks", name]) => match w.networks.get(*name) {
            Some((_, members)) if !members.is_empty() => (403, json!({ "message": "active endpoints" }).to_string()),
            Some(_) => {
                w.networks.remove(*name);
                (204, String::new())
            }
            None => missing(),
        },
        ("POST", ["networks", name, action]) => {
            let who = doc["Container"].as_str().unwrap_or_default().to_string();
            match w.networks.get_mut(*name) {
                Some((_, members)) => {
                    if *action == "connect" { members.insert(who); } else { members.remove(&who); }
                    (200, String::new())
                }
                None => missing(),
            }
        }
        ("POST", ["containers", "create"]) => {
            let name = query_value(query, "name").unwrap_or_default();
            w.containers.insert(name, (doc, false));
            (201, "{\"Id\":\"c\"}".to_string())
        }
        ("GET", ["containers", "json"]) => {
            let list: Vec<Value> = w
                .containers
                .iter()
                .map(|(n, (spec, up))| json!({ "Names": [format!("/{n}")], "Labels": spec["Labels"], "Image": spec["Image"], "State": if *up { "running" } else { "exited" }, "Status": "Up (healthy)" }))
                .collect();
            (200, Value::Array(list).to_string())
        }
        ("GET", ["containers", name, "json"]) => match w.containers.get(*name) {
            Some((spec, up)) => (
                200,
                json!({
                    "State": { "Running": up },
                    "Config": { "Image": spec["Image"], "Env": spec["Env"], "Labels": spec["Labels"] },
                    "HostConfig": { "NetworkMode": spec["HostConfig"]["NetworkMode"] },
                })
                .to_string(),
            ),
            None => missing(),
        },
        ("GET", ["containers", name, "logs"]) => match w.containers.get(*name) {
            Some(_) => (200, w.logs.get(*name).cloned().unwrap_or_default()),
            None => missing(),
        },
        ("POST", ["containers", name, action]) => match (w.containers.get_mut(*name), *action) {
            (Some((_, up)), "start") => {
                *up = !name.ends_with("-init");
                (204, String::new())
            }
            (Some((_, up)), "stop" | "restart") => {
                *up = false;
                (204, String::new())
            }
            (Some(_), "wait") => (200, "{\"StatusCode\":0}".to_string()),
            _ => missing(),
        },
        ("DELETE", ["containers", name]) => w.containers.remove(*name).map_or_else(missing, |_| (204, String::new())),
        _ => missing(),
    }
}

// Records every request exactly as it arrived, so tests can compare bytes.
async fn answer(
    world: Arc<Mutex<World>>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let (parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let uri = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let (status, text) = {
        let mut w = world.lock().unwrap();
        w.seen.push(Seen {
            method: parts.method.to_string(),
            uri,
            headers,
            body: bytes.to_vec(),
        });
        route(
            &mut w,
            parts.method.as_str(),
            parts.uri.path(),
            parts.uri.query().unwrap_or_default(),
            &bytes,
        )
    };
    let streamed = text.contains('\n');
    let body: BoxBody<Bytes, Infallible> = if streamed {
        let lines: VecDeque<Bytes> = text
            .split_inclusive('\n')
            .map(|l| Bytes::from(l.to_string()))
            .collect();
        Chunks(lines).boxed()
    } else {
        Full::new(Bytes::from(text)).boxed()
    };
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("api-version", "1.45")
        .header("keep-alive", "timeout=5")
        .body(body)
        .unwrap())
}

impl FakeDocker {
    pub async fn start() -> FakeDocker {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let world = Arc::new(Mutex::new(World::default()));
        let shared = world.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let world = shared.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| answer(world.clone(), req));
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        FakeDocker {
            path,
            world,
            _dir: dir,
        }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.world.lock().unwrap().seen.clone()
    }

    pub fn seen_count(&self) -> usize {
        self.world.lock().unwrap().seen.len()
    }
}

pub async fn start_proxy(socket: &Path) -> SocketAddr {
    start_proxy_with(config(socket)).await
}

pub async fn start_proxy_with(cfg: Config) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, State::new(&cfg)));
    addr
}

pub async fn proxy_and_docker() -> (SocketAddr, FakeDocker) {
    let docker = FakeDocker::start().await;
    let addr = start_proxy(&docker.path).await;
    (addr, docker)
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[..pos]).unwrap_or("0").trim(), 16)
                .unwrap_or(0);
        if size == 0 || raw.len() < pos + 2 + size {
            break;
        }
        out.extend_from_slice(&raw[pos + 2..pos + 2 + size]);
        raw = raw.get(pos + 2 + size + 2..).unwrap_or_default();
    }
    out
}

pub fn parse_reply(raw: &[u8]) -> Reply {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let rest = &raw[split + 4..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let body = if chunked {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    Reply {
        status,
        headers,
        body,
    }
}

// Sends raw bytes and reads until the proxy closes the connection.
pub async fn raw(addr: SocketAddr, request: &[u8]) -> Option<Reply> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "proxy did not close the connection");
    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
        Some(parse_reply(&buf))
    } else {
        None
    }
}

// Requests ask the proxy to close the connection so reads end at the response.
pub fn build(method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out =
        format!("{method} {target} HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n").into_bytes();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !body.is_empty()
        && !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

pub async fn call(addr: SocketAddr, method: &str, target: &str) -> Reply {
    raw(addr, &build(method, target, &[], b""))
        .await
        .expect("reply")
}

pub async fn call_json(addr: SocketAddr, method: &str, target: &str, body: &Value) -> Reply {
    let bytes = serde_json::to_vec(body).unwrap();
    let request = build(
        method,
        target,
        &[("Content-Type", "application/json")],
        &bytes,
    );
    raw(addr, &request).await.expect("reply")
}

pub async fn connect_unix(path: &Path) -> UnixStream {
    UnixStream::connect(path).await.unwrap()
}
