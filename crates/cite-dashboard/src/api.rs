use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, FromRequest, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Extension, Json, Router};
use bytes::Bytes;
use cite_client::{
    ClientError, DEFAULT_FAN_OUT_LIMIT, MAX_NODES, NodeClient, NodeConfig, NodeOutcome,
    NodeTargets, ReplicationMode, ReplicationPlan, apply_plan, fan_out,
};
use cite_edge::auth::{
    Credentials, authenticate, hash_password, validate_password_strength, validate_username,
};
use cite_edge::model::Site;
use cite_edge::totp;
use cite_edge::validate::validate_site;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::error::ApiError;
use crate::security::{self, PeerIp, SessionCtx};
use crate::state::{AppState, NodeStatus, PendingSetup, lock, now_unix};
use crate::{assets, preview, proxy, qr};

pub const MAX_BODY_BYTES: usize = 1024 * 1024;

const SETUP_TTL_SECS: u64 = 15 * 60;
const ADD_NODE_TIMEOUT: Duration = Duration::from_secs(10);
const SUMMARY_TIMEOUT: Duration = Duration::from_secs(5);
const SUMMARY_WINDOW: &str = "15m";
const TOTP_ISSUER: &str = "Cite";
const RESERVED_NODE_NAME: &str = "summary";

pub struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let bytes = Bytes::from_request(req, state).await.map_err(|_| {
            ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
        })?;
        serde_json::from_slice(&bytes)
            .map(ApiJson)
            .map_err(|e| ApiError::bad_request(format!("invalid request body: {e}")))
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/api/v1/setup", get(setup_status).post(setup_begin))
        .route("/api/v1/setup/confirm", post(setup_confirm))
        .route(
            "/api/v1/session",
            get(session_get).post(session_login).delete(session_logout),
        )
        .route("/api/v1/nodes", get(nodes_list).post(nodes_add))
        .route("/api/v1/nodes/summary", get(nodes_summary))
        .route("/api/v1/nodes/{node}", delete(nodes_remove))
        .route("/api/v1/nodes/{node}/{*rest}", any(proxy::proxy))
        .route("/api/v1/deployments", post(deployments))
        .route("/api/v1/preview", post(preview::create))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::api_guard,
        ));
    Router::new()
        .route("/healthz", get(healthz))
        .route("/preview/{id}", get(preview::serve))
        .merge(api)
        .fallback(assets::serve)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::allow_guard,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::security_headers,
        ))
        .with_state(state)
}

async fn healthz() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn setup_status(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({ "needs_onboarding": s.needs_onboarding().await, "needs_token": true }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBody {
    setup_token: String,
    username: String,
    password: String,
}

async fn setup_begin(
    State(s): State<Arc<AppState>>,
    PeerIp(ip): PeerIp,
    ApiJson(body): ApiJson<SetupBody>,
) -> Result<Json<Value>, ApiError> {
    if !s.needs_onboarding().await {
        return Err(ApiError::not_found("not found"));
    }
    let now = now_unix();
    let key = format!("setup:{}", security::limiter_key(ip));
    limiter_check(&s, &key, now)?;
    if !s.setup_token_matches(&body.setup_token) {
        lock(&s.limiter).record_failure_local(&key, now);
        return Err(ApiError::forbidden("the setup token is not valid"));
    }
    let username = body.username.trim().to_string();
    if !validate_username(&username) {
        return Err(ApiError::bad_request(
            "username must be 3 to 32 characters of a-z, 0-9, '_', '.' or '-'",
        ));
    }
    validate_password_strength(&body.password).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let password = body.password;
    // Argon2 is deliberately slow, so it runs off the async workers.
    let password_hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    let secret = totp::generate_secret().map_err(ApiError::internal)?;
    let totp_uri = totp::otpauth_uri(TOTP_ISSUER, &username, &secret);
    let qr_svg = qr::svg(&totp_uri).map_err(ApiError::internal)?;
    *lock(&s.pending) = Some(PendingSetup {
        username,
        password_hash,
        secret: secret.clone(),
        created: now_unix(),
    });
    Ok(Json(json!({
        "totp_uri": totp_uri,
        "totp_secret": secret,
        "qr_svg": qr_svg,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmBody {
    code: String,
}

fn limiter_check(s: &AppState, key: &str, now: u64) -> Result<(), ApiError> {
    lock(&s.limiter)
        .check(key, now)
        .map_err(ApiError::too_many_requests)
}

async fn setup_confirm(
    State(s): State<Arc<AppState>>,
    PeerIp(ip): PeerIp,
    ApiJson(body): ApiJson<ConfirmBody>,
) -> Result<Json<Value>, ApiError> {
    let now = now_unix();
    let key = format!("setup:{}", security::limiter_key(ip));
    limiter_check(&s, &key, now)?;
    let _gate = s.write_gate.lock().await;
    if !s.needs_onboarding().await {
        return Err(ApiError::not_found("not found"));
    }
    let pending = lock(&s.pending).clone();
    let Some(pending) = pending.filter(|p| now.saturating_sub(p.created) <= SETUP_TTL_SECS) else {
        return Err(ApiError::bad_request(
            "setup has not been started or has expired",
        ));
    };
    let mut step = 0u64;
    if !totp::verify(&pending.secret, body.code.trim(), now, &mut step) {
        lock(&s.limiter).record_failure_local(&key, now);
        return Err(ApiError::bad_request("that code is not valid"));
    }
    lock(&s.limiter).record_success(&key);
    let mut cfg = s.config_snapshot().await;
    cfg.admin = Some(Credentials {
        username: pending.username,
        password_hash: pending.password_hash,
        totp_secret: pending.secret,
        totp_last_step: step,
    });
    s.commit_config(cfg).await?;
    *lock(&s.pending) = None;
    s.clear_setup_token();
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    username: String,
    password: String,
    totp: String,
}

fn session_cookie_header(s: &AppState, token: &str, max_age: u64) -> Result<HeaderValue, ApiError> {
    let cookie = security::session_cookie(s.settings.cookie_secure(), token, max_age);
    HeaderValue::from_str(&cookie).map_err(ApiError::internal)
}

async fn session_login(
    State(s): State<Arc<AppState>>,
    PeerIp(ip): PeerIp,
    ApiJson(body): ApiJson<LoginBody>,
) -> Result<Response, ApiError> {
    let now = now_unix();
    let key = security::limiter_key(ip);
    limiter_check(&s, &key, now)?;
    let Some(mut creds) = s.config_snapshot().await.admin else {
        return Err(ApiError::conflict("onboarding is not complete"));
    };
    let LoginBody {
        username,
        password,
        totp: code,
    } = body;
    // Only attempts naming the real account count toward the global lock, so a stranger cannot arm it.
    let targets_admin = username == creds.username;
    let verified = creds.clone();
    // Argon2 runs without the write gate so slow logins never delay node changes.
    let (result, creds) = tokio::task::spawn_blocking(move || {
        let result = authenticate(&mut creds, &username, &password, &code, now);
        (result, creds)
    })
    .await
    .map_err(ApiError::internal)?;
    let reject = |s: &AppState| {
        let mut limiter = lock(&s.limiter);
        if targets_admin {
            limiter.record_failure(&key, now);
        } else {
            limiter.record_failure_local(&key, now);
        }
        ApiError::unauthorized("invalid credentials")
    };
    if result.is_err() {
        return Err(reject(&s));
    }
    // The gate serializes the TOTP step, so one code cannot be replayed by parallel logins.
    let _gate = s.write_gate.lock().await;
    let mut cfg = s.config_snapshot().await;
    let current = cfg.admin.as_ref();
    let still_valid = current.is_some_and(|c| {
        c.username == verified.username
            && c.password_hash == verified.password_hash
            && c.totp_secret == verified.totp_secret
            && c.totp_last_step < creds.totp_last_step
    });
    if !still_valid {
        return Err(reject(&s));
    }
    lock(&s.limiter).record_success(&key);
    cfg.admin = Some(creds.clone());
    s.commit_config(cfg).await?;
    let (token, expires) = lock(&s.sessions)
        .create(&creds.username, now)
        .map_err(ApiError::internal)?;
    let max_age = expires.saturating_sub(now);
    let mut resp = Json(json!({
        "ok": true,
        "username": creds.username,
        "csrf": security::csrf_for(&token),
        "expires_at": expires,
    }))
    .into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        session_cookie_header(&s, &token, max_age)?,
    );
    Ok(resp)
}

async fn session_get(Extension(ctx): Extension<SessionCtx>) -> Json<Value> {
    Json(json!({
        "username": ctx.username,
        "csrf": ctx.csrf,
        "expires_at": ctx.expires,
    }))
}

async fn session_logout(
    State(s): State<Arc<AppState>>,
    Extension(ctx): Extension<SessionCtx>,
) -> Result<Response, ApiError> {
    lock(&s.sessions).revoke(&ctx.token);
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, session_cookie_header(&s, "", 0)?);
    Ok(resp)
}

async fn nodes_list(State(s): State<Arc<AppState>>) -> Json<Vec<NodeStatus>> {
    Json(s.node_statuses().await)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddNodeBody {
    name: String,
    url: String,
    token: String,
    #[serde(default)]
    ca_pem: Option<String>,
    #[serde(default)]
    insecure_http: bool,
}

async fn nodes_add(
    State(s): State<Arc<AppState>>,
    ApiJson(body): ApiJson<AddNodeBody>,
) -> Result<Json<Value>, ApiError> {
    let name = body.name.trim().to_string();
    let token = body.token.trim().to_string();
    if name == RESERVED_NODE_NAME {
        return Err(ApiError::bad_request("that node name is reserved"));
    }
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::bad_request("a valid API token is required"));
    }
    let node = NodeConfig {
        token_ref: name.clone(),
        name,
        url: body.url.trim().to_string(),
        ca_pem: body
            .ca_pem
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
        insecure_http: body.insecure_http,
    };
    node.validate()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if s.config_snapshot().await.node(&node.name).is_some() {
        return Err(ApiError::conflict(format!(
            "node {} already exists",
            node.name
        )));
    }
    let client =
        NodeClient::new(&node, token.clone()).map_err(|e| ApiError::bad_request(e.to_string()))?;
    // The node is probed with the token before anything is saved, so a bad token never gets stored.
    let info = match tokio::time::timeout(ADD_NODE_TIMEOUT, client.node_info()).await {
        Ok(Ok(info)) => info,
        Ok(Err(ClientError::Status {
            code: 401 | 403, ..
        })) => {
            return Err(ApiError::bad_request("the node rejected that token"));
        }
        Ok(Err(err)) => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("cannot reach the node: {err}"),
            ));
        }
        Err(_) => {
            return Err(ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "the node did not answer in time",
            ));
        }
    };
    let _gate = s.write_gate.lock().await;
    let mut cfg = s.config_snapshot().await;
    cfg.add_node(node.clone())
        .map_err(|e| ApiError::conflict(e.to_string()))?;
    s.token_set(&node.token_ref, &token).await?;
    if let Err(err) = s.commit_config(cfg).await {
        let _ = s.token_delete(&node.token_ref).await;
        return Err(err);
    }
    s.put_client(client, &info.version).await;
    Ok(Json(json!({
        "ok": true,
        "name": node.name,
        "url": node.url,
        "online": true,
        "version": info.version,
    })))
}

async fn nodes_remove(
    State(s): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _gate = s.write_gate.lock().await;
    let mut cfg = s.config_snapshot().await;
    let Some(node) = cfg.remove_node(&name) else {
        return Err(ApiError::not_found(format!(
            "node {name} is not configured"
        )));
    };
    s.commit_config(cfg).await?;
    s.drop_client(&name).await;
    // The node is already gone from the config, so a leftover token is only worth a warning.
    if let Err(err) = s.token_delete(&node.token_ref).await {
        let detail = err.message();
        tracing::warn!(node = %name, "token could not be deleted: {detail}");
    }
    Ok(Json(json!({ "ok": true })))
}

async fn nodes_summary(State(s): State<Arc<AppState>>) -> Json<Value> {
    let config = s.config_snapshot().await;
    let clients = s.all_clients().await;
    // Node info is required; the summary is best effort so one slow query does not hide a node.
    let results = fan_out(
        &clients,
        DEFAULT_FAN_OUT_LIMIT,
        Some(SUMMARY_TIMEOUT),
        |c| async move {
            let (info, summary) =
                tokio::join!(c.node_info(), c.analytics_summary(SUMMARY_WINDOW, None));
            info.map(|info| (info, summary.ok()))
        },
    )
    .await;
    let mut by_name: HashMap<String, Value> = results
        .into_iter()
        .map(|(name, result)| {
            let entry = match result {
                Ok((info, summary)) => json!({
                    "name": name,
                    "online": true,
                    "node": info,
                    "summary": summary,
                }),
                Err(err) => json!({
                    "name": name,
                    "online": false,
                    "error": ApiError::from(err).message(),
                }),
            };
            (name.clone(), entry)
        })
        .collect();
    let entries: Vec<Value> = config
        .nodes
        .iter()
        .map(|n| {
            by_name.remove(&n.name).unwrap_or_else(|| {
                json!({ "name": n.name, "online": false, "error": "no stored token for this node" })
            })
        })
        .collect();
    Json(Value::Array(entries))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployBody {
    nodes: Vec<String>,
    site: Site,
    mode: ReplicationMode,
    #[serde(default)]
    per_node: BTreeMap<String, NodeTargets>,
    #[serde(default)]
    github_token: Option<String>,
}

async fn deployments(
    State(s): State<Arc<AppState>>,
    ApiJson(body): ApiJson<DeployBody>,
) -> Result<Response, ApiError> {
    let mut names: Vec<String> = Vec::new();
    for name in body.nodes {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Err(ApiError::bad_request("select at least one node"));
    }
    if names.len() > MAX_NODES {
        return Err(ApiError::bad_request("too many nodes selected"));
    }
    validate_site(&body.site).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let mut site = body.site;
    site.history.clear();
    let token = body
        .github_token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if token.is_some() && site.source.is_none() {
        return Err(ApiError::bad_request(
            "github_token needs a site with a source",
        ));
    }
    let mut clients = Vec::new();
    let mut outcomes: HashMap<String, NodeOutcome> = HashMap::new();
    for name in &names {
        match s.client(name).await {
            Some(client) => clients.push(client),
            None => {
                let message = format!("node {name} is not configured");
                outcomes.insert(name.clone(), NodeOutcome::failed(name.clone(), message));
            }
        }
    }
    let plan = ReplicationPlan {
        site,
        mode: body.mode,
        per_node: body.per_node,
        github_token: token,
    };
    for outcome in apply_plan(&clients, &plan).await {
        outcomes.insert(outcome.node.clone(), outcome);
    }
    let results: Vec<NodeOutcome> = names
        .iter()
        .filter_map(|name| outcomes.remove(name))
        .collect();
    if results.iter().any(|r| r.ok) {
        return Ok(Json(json!({ "results": results })).into_response());
    }
    let summary = results
        .iter()
        .map(|r| format!("{}: {}", r.node, r.error.as_deref().unwrap_or("failed")))
        .collect::<Vec<_>>()
        .join("; ");
    let payload = json!({ "error": summary, "results": results });
    Ok((StatusCode::CONFLICT, Json(payload)).into_response())
}
