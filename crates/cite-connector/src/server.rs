use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{FromRequest, FromRequestParts, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use cite_edge::allow::IpAllowlist;
use cite_edge::model::EdgeConfig;
use cite_edge::ratelimit::{LoginLimiter, client_key};
use cite_edge::render::{RenderOptions, render};
use cite_edge::validate::validate_config;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::de::DeserializeOwned;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::config::ConnectorConfig;
use crate::deploy::{Deployer, detach};
use crate::haproxy::Haproxy;
use crate::logsink::{self, IngestStats};
use crate::orchestrator::Orchestrator;
use crate::store::{Store, TokenOutcome, now_unix, unix_to_rfc3339};
use crate::{ConnectorError, Result, tls};

mod archives;
mod export;
mod handlers;
mod health;
#[cfg(test)]
mod perf;
#[cfg(test)]
mod tests;

pub use health::healthcheck;

pub const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 256;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// A repo-built deploy waits for the build, so the handler may legitimately run for minutes.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(700);
const CONNECTION_MAX_AGE: Duration = Duration::from_secs(15 * 60);
const MAX_HEADER_BUF: usize = 32 * 1024;
const MAX_BEARER_LEN: usize = 200;
// Exports hold a database reader and a blocking thread each for as long as the client reads.
const MAX_EXPORTS: usize = 2;

pub type AppState = Arc<Inner>;

pub struct Inner {
    cfg: ConnectorConfig,
    store: Arc<Store>,
    haproxy: Arc<Haproxy>,
    deployer: Arc<Deployer>,
    orchestrator: Option<Arc<Orchestrator>>,
    analytics: Arc<cite_store::Store>,
    ingest: Arc<IngestStats>,
    exports: Arc<Semaphore>,
    limiter: StdMutex<LoginLimiter>,
    token_limiter: StdMutex<LoginLimiter>,
    render_opts: RenderOptions,
    started: Instant,
}

impl Inner {
    pub fn new(
        cfg: ConnectorConfig,
        store: Arc<Store>,
        haproxy: Arc<Haproxy>,
        deployer: Arc<Deployer>,
        orchestrator: Option<Arc<Orchestrator>>,
        analytics: Arc<cite_store::Store>,
        ingest: Arc<IngestStats>,
    ) -> AppState {
        let render_opts = RenderOptions {
            maps_dir: cfg.maps_dir.display().to_string(),
            pages_dir: cfg.pages_dir.display().to_string(),
            runtime_addr: crate::haproxy::stats_listen(&cfg.runtime_addr)
                .unwrap_or_else(|_| cfg.runtime_addr.clone()),
            log_addr: cfg.log_addr_for_haproxy.clone(),
            tls_dir: None,
        };
        Arc::new(Inner {
            cfg,
            store,
            haproxy,
            deployer,
            orchestrator,
            analytics,
            ingest,
            exports: Arc::new(Semaphore::new(MAX_EXPORTS)),
            limiter: StdMutex::new(LoginLimiter::new()),
            token_limiter: StdMutex::new(LoginLimiter::new()),
            render_opts,
            started: Instant::now(),
        })
    }

    // Runs to completion even when the caller goes away, so a half-applied change is never left behind.
    async fn mutate<T: Send + 'static>(
        self: &Arc<Self>,
        actor: &str,
        action: &str,
        detail: &str,
        f: impl FnOnce(&mut EdgeConfig) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let this = Arc::clone(self);
        let (actor, action, detail) = (actor.to_string(), action.to_string(), detail.to_string());
        detach(async move { this.mutate_now(&actor, &action, &detail, f).await }).await
    }

    // Validates and dry-renders before persisting, then applies; a failed apply restores the old config in store and HAProxy.
    async fn mutate_now<T>(
        &self,
        actor: &str,
        action: &str,
        detail: &str,
        f: impl FnOnce(&mut EdgeConfig) -> Result<T>,
    ) -> Result<T> {
        let _gate = self.deployer.config_lock().lock().await;
        let previous = self.store.config();
        let opts = &self.render_opts;
        let out = self
            .store
            .update_detailed(actor, action, detail, |cfg| {
                let value = f(cfg)?;
                validate_config(cfg)?;
                render(cfg, opts)?;
                Ok(value)
            })
            .await?;
        let loaded = self
            .haproxy
            .apply(&self.store.config())
            .await
            .and_then(|applied| applied.require_loaded());
        if let Err(err) = loaded {
            let restored = Arc::clone(&previous);
            let undo = self
                .store
                .update_detailed(actor, "config.rollback", action, move |cfg| {
                    *cfg = (*restored).clone();
                    Ok(())
                })
                .await;
            match undo {
                Ok(()) => {
                    let again = self
                        .haproxy
                        .apply(&previous)
                        .await
                        .and_then(|applied| applied.require_loaded());
                    if let Err(e) = again {
                        tracing::warn!(error = %e, "haproxy could not re-apply the restored configuration");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "could not restore the previous configuration")
                }
            }
            return Err(match err {
                ConnectorError::BadRequest(msg) => ConnectorError::BadRequest(msg),
                other => ConnectorError::Unavailable(format!(
                    "haproxy could not apply the change: {other}"
                )),
            });
        }
        Ok(out)
    }
}

pub fn lock_std<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn too_many(retry_after: u64) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed attempts; try again later",
            )
        }
    }
}

impl<E: Into<ConnectorError>> From<E> for ApiError {
    fn from(e: E) -> Self {
        let e: ConnectorError = e.into();
        let status = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        match e {
            ConnectorError::Internal(detail) => {
                tracing::error!(%detail, "internal error");
                Self::new(status, "internal error")
            }
            other => Self::new(status, other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = serde_json::json!({ "error": self.message });
        if let (Some(secs), Some(obj)) = (self.retry_after, body.as_object_mut()) {
            obj.insert("retry_after".into(), secs.into());
        }
        let mut res = (self.status, axum::Json(body)).into_response();
        if let Some(secs) = self.retry_after
            && let Ok(value) = HeaderValue::from_str(&secs.to_string())
        {
            res.headers_mut().insert(header::RETRY_AFTER, value);
        }
        res
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;

pub struct JsonBody<T>(pub T);

pub struct MaybeJson<T>(pub T);

async fn read_body(req: Request) -> ApiResult<bytes::Bytes> {
    axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"))
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(bytes).map_err(|e| ApiError::bad(format!("invalid json: {e}")))
}

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body(req).await?;
        if bytes.is_empty() {
            return Err(ApiError::bad("request body is required"));
        }
        parse_json(&bytes).map(JsonBody)
    }
}

impl<S, T> FromRequest<S> for MaybeJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Default,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body(req).await?;
        if bytes.is_empty() {
            return Ok(MaybeJson(T::default()));
        }
        parse_json(&bytes).map(MaybeJson)
    }
}

pub struct Params(pub HashMap<String, String>);

impl<S: Send + Sync> FromRequestParts<S> for Params {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> ApiResult<Self> {
        Query::<HashMap<String, String>>::try_from_uri(&parts.uri)
            .map(|q| Params(q.0))
            .map_err(|_| ApiError::bad("invalid query string"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub addr: SocketAddr,
    pub loopback_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Full,
    LoopbackOnly,
    Denied,
}

// Loopback peers are admitted for /healthz only so the container healthcheck works behind any allowlist.
pub fn admit(allow: &IpAllowlist, peer: IpAddr) -> Admission {
    if allow.allows(peer) {
        Admission::Full
    } else if peer.to_canonical().is_loopback() {
        Admission::LoopbackOnly
    } else {
        Admission::Denied
    }
}

fn is_health_path(path: &str) -> bool {
    path == "/healthz" || path == "/api/v1/healthz"
}

#[derive(Clone)]
pub struct Principal {
    pub name: String,
    pub kind: &'static str,
    pub expires_at: Option<String>,
    pub session_token: Option<String>,
}

impl Principal {
    pub fn actor(&self) -> String {
        if self.kind == "api" {
            format!("api:{}", self.name)
        } else {
            self.name.clone()
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    let token = rest.trim();
    let usable = scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && token.len() <= MAX_BEARER_LEN
        && token.bytes().all(|b| b.is_ascii_graphic());
    usable.then_some(token)
}

async fn principal_for(st: &Inner, token: &str, peer_key: &str) -> Option<Principal> {
    if let Some(info) = st.store.validate_session(token, now_unix()) {
        return Some(Principal {
            name: info.username,
            kind: "session",
            expires_at: Some(unix_to_rfc3339(info.expires)),
            session_token: Some(token.to_string()),
        });
    }
    // The attempt is counted in the same lock as the check and only forgiven once the hash passes, so bursts and dropped connections cannot get free guesses.
    let ticket = StdMutex::new(None);
    let admit = || {
        let now = now_unix();
        let mut limiter = lock_std(&st.token_limiter);
        if limiter.check(peer_key, now).is_err() {
            return false;
        }
        *lock_std(&ticket) = Some(limiter.record_provisional(peer_key, now));
        true
    };
    let forgive = || {
        let taken = lock_std(&ticket).take();
        if let Some(t) = taken {
            lock_std(&st.token_limiter).forgive(t);
        }
    };
    match st.store.verify_api_token_gated(token, admit, forgive).await {
        TokenOutcome::Accepted(t) => Some(Principal {
            name: t.name,
            kind: "api",
            expires_at: None,
            session_token: None,
        }),
        TokenOutcome::WrongSecret | TokenOutcome::Rejected => None,
    }
}

async fn require_auth(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let peer_key = req
        .extensions()
        .get::<Peer>()
        .map_or_else(String::new, |p| client_key(p.addr.ip()));
    // Every rejection is the same bare 401 so a caller learns nothing about why.
    let principal = match bearer(req.headers()) {
        Some(token) => principal_for(&st, token, &peer_key).await,
        None => None,
    };
    let Some(principal) = principal else {
        let mut res = ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return res;
    };
    req.extensions_mut().insert(principal);
    next.run(req).await
}

async fn loopback_gate(req: Request, next: Next) -> Response {
    let restricted = req
        .extensions()
        .get::<Peer>()
        .is_some_and(|p| p.loopback_only);
    if restricted && !is_health_path(req.uri().path()) {
        return ApiError::new(StatusCode::NOT_FOUND, "not found").into_response();
    }
    next.run(req).await
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    if res.status() == StatusCode::METHOD_NOT_ALLOWED
        && !res.headers().contains_key(header::CONTENT_TYPE)
    {
        let allow = res.headers().get(header::ALLOW).cloned();
        res = ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response();
        if let Some(value) = allow {
            res.headers_mut().insert(header::ALLOW, value);
        }
    }
    let headers = res.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    res
}

pub fn router(state: AppState) -> Router {
    use handlers as h;
    let public = Router::new()
        .route("/api/v1/auth/login", post(h::login))
        .route("/api/v1/healthz", get(h::healthz))
        .route("/healthz", get(h::healthz));
    let protected = Router::new()
        .route("/api/v1/auth/logout", post(h::logout))
        .route("/api/v1/auth/me", get(h::me))
        .route("/api/v1/tokens", get(h::list_tokens).post(h::create_token))
        .route(
            "/api/v1/tokens/{id}",
            axum::routing::delete(h::delete_token),
        )
        .route("/api/v1/node", get(h::node))
        .route("/api/v1/haproxy/reload", post(h::reload))
        .route("/api/v1/haproxy/config", get(h::haproxy_config))
        .route("/api/v1/haproxy/stats", get(h::haproxy_stats))
        .route(
            "/api/v1/settings",
            get(h::get_settings).put(h::put_settings),
        )
        .route("/api/v1/audit", get(h::audit_log))
        .route("/api/v1/sites", get(h::list_sites).post(h::create_site))
        .route(
            "/api/v1/sites/{id}",
            get(h::get_site).put(h::put_site).delete(h::delete_site),
        )
        .route("/api/v1/sites/{id}/deploy", post(h::deploy_site))
        .route("/api/v1/sites/{id}/switch", post(h::switch_site))
        .route("/api/v1/sites/{id}/rollback", post(h::rollback_site))
        .route("/api/v1/sites/{id}/maintenance", post(h::site_maintenance))
        .route("/api/v1/pages", get(h::list_pages).post(h::create_page))
        .route(
            "/api/v1/pages/{id}",
            get(h::get_page).put(h::put_page).delete(h::delete_page),
        )
        .route(
            "/api/v1/firewall/rules",
            get(h::list_rules).post(h::create_rule),
        )
        .route(
            "/api/v1/firewall/rules/{id}",
            axum::routing::put(h::put_rule).delete(h::delete_rule),
        )
        .route("/api/v1/firewall/presets", get(h::list_presets))
        .route(
            "/api/v1/firewall/presets/{name}/apply",
            post(h::apply_preset),
        )
        .route("/api/v1/analytics/summary", get(h::analytics_summary))
        .route("/api/v1/analytics/timeseries", get(h::analytics_timeseries))
        .route("/api/v1/analytics/requests", get(h::analytics_requests))
        .route("/api/v1/analytics/bots", get(h::analytics_bots))
        .route("/api/v1/analytics/top", get(h::analytics_top))
        .route("/api/v1/analytics/stats", get(h::analytics_stats))
        .route("/api/v1/analytics/export", get(export::analytics_export))
        .route("/api/v1/analytics/archives", get(archives::list_archives))
        .route(
            "/api/v1/analytics/archives/{name}",
            get(archives::download).delete(archives::delete_archive),
        )
        .route("/api/v1/analytics/backup", post(archives::backup))
        .route("/api/v1/analytics/cut", post(archives::cut))
        .route("/api/v1/analytics/restore", post(archives::restore))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Router::new()
        .merge(public)
        .merge(protected)
        .fallback(h::not_found)
        .layer(middleware::from_fn(loopback_gate))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

// Slow-header and stalled-body clients are cut off by three separate time limits.
async fn serve_io<I>(io: TokioIo<I>, peer: Peer, router: Router)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |mut req: hyper::Request<Incoming>| {
        let mut router = router.clone();
        async move {
            req.extensions_mut().insert(peer);
            match tokio::time::timeout(REQUEST_TIMEOUT, router.call(req)).await {
                Ok(res) => res,
                Err(_) => Ok(
                    ApiError::new(StatusCode::REQUEST_TIMEOUT, "request timed out").into_response(),
                ),
            }
        }
    });
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_HEADER_BUF)
        .serve_connection(io, service);
    if let Ok(Err(e)) = tokio::time::timeout(CONNECTION_MAX_AGE, conn).await {
        tracing::debug!(peer = %peer.addr, error = %e, "connection ended with an error");
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: Peer,
    router: Router,
    acceptor: Option<TlsAcceptor>,
) {
    let Some(acceptor) = acceptor else {
        serve_io(TokioIo::new(stream), peer, router).await;
        return;
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(secured)) => serve_io(TokioIo::new(secured), peer, router).await,
        Ok(Err(e)) => tracing::debug!(peer = %peer.addr, error = %e, "tls handshake failed"),
        Err(_) => tracing::debug!(peer = %peer.addr, "tls handshake timed out"),
    }
}

// The peer is checked straight after accept, before any TLS bytes or request data are read.
pub async fn serve(listener: TcpListener, state: AppState, acceptor: Option<TlsAcceptor>) {
    let router = router(state.clone());
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let admission = admit(&state.cfg.allow, addr.ip());
        if admission == Admission::Denied {
            drop(stream);
            continue;
        }
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(error = %e, "could not set TCP_NODELAY");
        }
        let peer = Peer {
            addr,
            loopback_only: admission == Admission::LoopbackOnly,
        };
        let router = router.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            handle_connection(stream, peer, router, acceptor).await;
            drop(permit);
        });
    }
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

pub async fn run(cfg: ConnectorConfig) -> Result<()> {
    tls::install_provider();
    let store = Store::open(&cfg).await?;
    let haproxy = Arc::new(Haproxy::new(&cfg));
    // HAProxy needs a config on disk to boot, so this happens even when the API cannot start.
    match haproxy.apply(&store.config()).await {
        Ok(out) => {
            let (hash, reloaded) = (&out.config_hash, out.reloaded);
            tracing::info!(%hash, reloaded, "haproxy config written");
        }
        Err(e) => tracing::warn!(error = %e, "initial haproxy config could not be applied"),
    }
    if store.credentials().is_none() {
        const MISSING: &str = "no credentials are configured; run `cite-connector init` first";
        return Err(ConnectorError::Unavailable(MISSING.into()));
    }
    let retention = store.config().settings.retention.clone();
    let days = logsink::retention_days(&retention);
    let analytics = open_analytics(&cfg, days, retention).await?;
    let ingest = Arc::new(IngestStats::default());
    let log_sink = logsink::spawn(
        &cfg,
        Arc::clone(&analytics),
        Arc::clone(&store),
        Arc::clone(&ingest),
    );
    let orchestrator = match Orchestrator::from_config(&cfg)? {
        Some(o) => {
            match o.ping().await {
                Ok(()) => tracing::info!("orchestrator reachable"),
                Err(e) => tracing::warn!(error = %e, "orchestrator is not reachable yet"),
            }
            Some(Arc::new(o))
        }
        None => None,
    };
    let deployer = Arc::new(
        Deployer::new(
            Arc::clone(&store),
            Arc::clone(&haproxy),
            orchestrator.clone(),
        )
        .with_build_wait(Duration::from_secs(cfg.deploy_build_timeout_secs)),
    );
    let reconciler = Arc::clone(&deployer);
    tokio::spawn(async move { reconciler.reconcile_idle_stacks().await });
    let acceptor = if cfg.tls {
        Some(tls::load_acceptor(&cfg.tls_dir)?)
    } else {
        tracing::warn!("TLS is disabled; serve this API only behind a trusted tunnel");
        None
    };
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| ConnectorError::Internal(format!("cannot bind {}: {e}", cfg.listen)))?;
    let (listen, node, secure) = (cfg.listen, &cfg.node_name, cfg.tls);
    tracing::info!(%listen, %node, tls = secure, "connector api listening");
    let final_analytics = Arc::clone(&analytics);
    let state = Inner::new(
        cfg,
        store,
        haproxy,
        deployer,
        orchestrator,
        analytics,
        ingest,
    );
    tokio::select! {
        () = serve(listener, state, acceptor) => {}
        () = shutdown_signal() => tracing::info!("shutting down"),
    }
    log_sink.shutdown().await;
    let folded = tokio::task::spawn_blocking(move || final_analytics.checkpoint()).await;
    match folded {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "analytics database checkpoint failed"),
        Err(e) => tracing::warn!(error = %e, "analytics checkpoint task failed"),
    }
    Ok(())
}

// Opening may migrate the schema or import an old snapshot, so it stays off the async workers.
async fn open_analytics(
    cfg: &ConnectorConfig,
    retention_days: u32,
    retention: cite_edge::model::Retention,
) -> Result<Arc<cite_store::Store>> {
    let cfg = cfg.clone();
    tokio::task::spawn_blocking(move || {
        let analytics = logsink::open_store(&cfg, retention_days)?;
        analytics.set_archive_before_delete(retention.archive_before_delete);
        logsink::migrate_snapshot(&cfg.data_dir, &analytics, &retention);
        Ok(analytics)
    })
    .await
    .map_err(|e| ConnectorError::Internal(format!("analytics open task failed: {e}")))?
}
