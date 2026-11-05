// Run with: cargo test -p cite-dockerproxy --release --test perf -- --ignored --nocapture
mod common;

use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use common::proxy_and_docker;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpStream;

const MANAGED: &str = "cite-shop-blue-manager";

async fn hammer(addr: SocketAddr, method: &str, path: &str, workers: usize, per_worker: usize) -> (f64, f64) {
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..workers {
        let (method, path) = (method.to_string(), path.to_string());
        tasks.push(tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.expect("connect");
            let (mut sender, conn) = http1::handshake(TokioIo::new(stream)).await.expect("handshake");
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut lat = Vec::with_capacity(per_worker);
            for _ in 0..per_worker {
                let req = Request::builder()
                    .method(method.as_str())
                    .uri(path.as_str())
                    .header("host", "proxy")
                    .body(Empty::<Bytes>::new())
                    .expect("request");
                let t = Instant::now();
                let resp = sender.send_request(req).await.expect("send");
                assert_eq!(resp.status(), 200);
                let _ = resp.into_body().collect().await.expect("body");
                lat.push(t.elapsed().as_secs_f64() * 1e3);
            }
            lat
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await.expect("worker"));
    }
    let secs = started.elapsed().as_secs_f64();
    all.sort_by(|a, b| a.total_cmp(b));
    (all.len() as f64 / secs, all[all.len() * 99 / 100])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn proxy_throughput() {
    let (addr, docker) = proxy_and_docker().await;
    docker.world.lock().unwrap().add_container(
        MANAGED,
        json!({ "cite.managed": "true", "cite.site": "shop", "cite.slot": "blue", "cite.role": "manager" }),
    );
    let (rate, p99) = hammer(addr, "GET", "/v1.45/_ping", 32, 1500).await;
    println!("GET /_ping (1 upstream call): {rate:.0} req/s, p99 {p99:.2} ms");
    let path = format!("/v1.45/containers/{MANAGED}/wait");
    let (rate, p99) = hammer(addr, "POST", &path, 32, 1500).await;
    println!("POST container wait (inspect + call): {rate:.0} req/s, p99 {p99:.2} ms");
}
