#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use futures_util::FutureExt;
use http::{Method, Request, Response};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::debug;

use crate::control::SharedState;
use crate::error_page::{self, BoxBody, page_503};
use crate::proxy::{ProxyConfig, proxy_with_upgrade};
use crate::route::RouteKind;
use crate::static_files;

pub async fn accept_loop(
    listener: TcpListener,
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    continue;
                };
                if state.draining.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(permit) = state.connections.clone().try_acquire_owned() else {
                    continue;
                };
                let state = state.clone();
                state.conn_count.fetch_add(1, Ordering::SeqCst);
                let header_timeout = state.config.header_timeout;
                tokio::spawn(async move {
                    let _permit = permit;
                    let io = TokioIo::new(stream);
                    let conn_state = state.clone();
                    let svc = service_fn(move |req| {
                        let state = conn_state.clone();
                        async move {
                            let result = std::panic::AssertUnwindSafe(handle(req, peer, state))
                                .catch_unwind()
                                .await;
                            Ok::<_, Infallible>(match result {
                                Ok(response) => response,
                                Err(_) => error_page::page_500(),
                            })
                        }
                    });
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(hyper_util::rt::TokioTimer::new());
                    builder.header_read_timeout(header_timeout);
                    builder.max_buf_size(state.config.max_header_bytes.max(8 * 1024));
                    let fut = builder.serve_connection(io, svc).with_upgrades();
                    let _ = fut.await;
                    state.conn_count.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }
}

async fn handle(req: Request<Incoming>, peer: SocketAddr, state: SharedState) -> Response<BoxBody> {
    #[cfg(test)]
    if req.uri().path() == "/__cite_test_panic" {
        panic!("secret-stack-frame");
    }
    state.requests.fetch_add(1, Ordering::Relaxed);

    if state.config.access_log {
        debug!(
            method = %req.method(),
            path = %req.uri().path(),
            peer = %peer,
            "access"
        );
    }

    if !state.config.allowed_hosts.is_empty() {
        if let Some(host) = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
        {
            if !cite_core::host_allowed(&state.config.allowed_hosts, host) {
                return error_page::page_400("bad host");
            }
        }
    }

    let route = state.routing.load_full();
    match &route.kind {
        RouteKind::None => page_503(),
        RouteKind::Static {
            app_root,
            spa_fallback,
        } => {
            static_files::serve_static(
                &req,
                app_root,
                spa_fallback.as_deref(),
                &state.config.static_headers,
            )
            .await
        }
        RouteKind::Proxy { port } => {
            if req.method() == Method::OPTIONS && !is_websocket(&req) {
                // Let upstream handle OPTIONS for SSR APIs; still proxy.
            }
            let cfg = ProxyConfig {
                port: *port,
                peer,
                trusted_proxies: &state.config.trusted_proxies,
                allowed_hosts: &[], // already checked
                connect_timeout: state.config.connect_timeout,
                header_timeout: state.config.header_timeout,
                idle_timeout: state.config.idle_timeout,
                max_body: state.config.max_body,
            };
            proxy_with_upgrade(req, cfg).await
        }
    }
}

fn is_websocket(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}
