#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use http::{Method, Request, Response};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, watch};
use tracing::debug;

use crate::control::SharedState;
use crate::error_page::{self, BoxBody, page_503};
use crate::limits::{Admission, ConnSlot, Verdict};
use crate::proxy::{ProxyConfig, client_ip, is_trusted_ip, proxy_with_upgrade};
use crate::route::RouteKind;
use crate::static_files;

/// Pause after a failed accept (for example EMFILE) so the loop cannot spin.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Holds a connection permit and count; an upgraded connection keeps it until the tunnel closes.
struct ConnGuard {
    _permit: OwnedSemaphorePermit,
    _slot: Option<ConnSlot>,
    count: Arc<AtomicU64>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct ConnHold(Arc<ConnGuard>);

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
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                };
                if state.draining.load(Ordering::SeqCst) {
                    continue;
                }
                let slot = if is_trusted_peer(&state, peer.ip()) {
                    None
                } else {
                    match state.limiter.admit_connection(peer.ip(), Instant::now()) {
                        Admission::Allowed(slot) => slot,
                        Admission::Banned | Admission::TooMany => continue,
                    }
                };
                let Ok(permit) = state.connections.clone().try_acquire_owned() else {
                    continue;
                };
                let state = state.clone();
                state.conn_count.fetch_add(1, Ordering::SeqCst);
                let guard = Arc::new(ConnGuard {
                    _permit: permit,
                    _slot: slot,
                    count: state.conn_count.clone(),
                });
                let header_timeout = state.config.header_timeout;
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let conn_state = state.clone();
                    let svc = service_fn(move |mut req: Request<Incoming>| {
                        let state = conn_state.clone();
                        req.extensions_mut().insert(ConnHold(guard.clone()));
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
                });
            }
        }
    }
}

fn is_trusted_peer(state: &SharedState, ip: IpAddr) -> bool {
    is_trusted_ip(&state.config.trusted_proxies, ip)
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

    let trusted = &state.config.trusted_proxies;
    let client = client_ip(peer.ip(), req.headers(), trusted);
    if !is_trusted_ip(trusted, peer.ip()) && req.headers().contains_key("x-forwarded-for") {
        state.limiter.note_untrusted_forwarded();
    }
    if !is_trusted_ip(trusted, client) {
        match state.limiter.check_request(client, Instant::now()) {
            Verdict::Allow => {}
            Verdict::Limited { retry_after } => return error_page::page_429(retry_after, false),
            Verdict::Banned { retry_after } => {
                let close = !is_trusted_ip(trusted, peer.ip());
                return error_page::page_429(retry_after, close);
            }
        }
    }

    if !state.config.allowed_hosts.is_empty() {
        let allowed = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|host| cite_core::host_allowed(&state.config.allowed_hosts, host));
        if !allowed {
            return error_page::page_400("bad host");
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
            let hold: Option<Arc<dyn Send + Sync>> = req
                .extensions()
                .get::<ConnHold>()
                .map(|hold| hold.0.clone() as Arc<dyn Send + Sync>);
            let cfg = ProxyConfig {
                hold,
                slot: route.slot,
                inflight: Arc::clone(&state.inflight),
                port: *port,
                peer,
                trusted_proxies: &state.config.trusted_proxies,
                allowed_hosts: &state.config.allowed_hosts,
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
