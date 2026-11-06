use std::fmt;
use std::sync::Arc;

use axum::extract::{FromRequest, Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use cite_edge::model::EdgeConfig;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zeroize::Zeroize;

use super::{ApiError, ApiResult, AppState, Inner, Principal, parse_json, read_body_limited};
use crate::certs::{self, Cert, CertStore, MAX_BODY_BYTES, Prepared, Stored, Undo};
use crate::change::{Rollback, reason};
use crate::deploy::detach;
use crate::store::{now_rfc3339, now_unix};
use crate::{ConnectorError, Result};

const HAPROXY_DOWN: &str = "HAProxy could not be reached, so the change is stored and will be served after the next successful reload";
const HTTPS_OFF: &str = "HTTPS is not enabled on this node, so this certificate is stored but not served; set https_port in the node settings (PUT /api/v1/settings) to bind the TLS listener";

// A smaller cap than the rest of the API: a chain and a key never need more.
pub(super) struct CertBody<T>(T);

impl<S, T> FromRequest<S> for CertBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, MAX_BODY_BYTES).await?;
        if bytes.is_empty() {
            return Err(ApiError::bad("request body is required"));
        }
        parse_json(&bytes).map(CertBody)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateReq {
    name: String,
    certificate: String,
    private_key: String,
}

// The key is wiped on every exit, including early validation failures.
impl Drop for CreateReq {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl Drop for ReplaceReq {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl fmt::Debug for CreateReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateReq")
            .field("name", &self.name)
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplaceReq {
    #[serde(default)]
    name: Option<String>,
    certificate: String,
    private_key: String,
}

impl fmt::Debug for ReplaceReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplaceReq")
            .field("name", &self.name)
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

enum Op {
    Create(String),
    Replace { id: String, name: Option<String> },
    Delete(String),
}

impl Op {
    fn action(&self) -> &'static str {
        match self {
            Op::Create(_) => "certificates.create",
            Op::Replace { .. } => "certificates.replace",
            Op::Delete(_) => "certificates.delete",
        }
    }
}

fn now() -> i64 {
    i64::try_from(now_unix()).unwrap_or(i64::MAX)
}

fn site_hosts(cfg: &EdgeConfig) -> Vec<String> {
    let mut hosts: Vec<String> = cfg
        .sites
        .iter()
        .flat_map(|site| site.hosts.iter().map(|h| h.to_ascii_lowercase()))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

async fn on_store<T: Send + 'static>(
    st: &Inner,
    work: impl FnOnce(&CertStore) -> Result<T> + Send + 'static,
) -> Result<T> {
    let store = Arc::clone(&st.certs);
    tokio::task::spawn_blocking(move || work(&store))
        .await
        .map_err(|e| ConnectorError::Internal(format!("certificate task failed: {e}")))?
}

// The key text is wiped as soon as it has been parsed, whether or not it was accepted.
fn check_upload(certificate: &str, private_key: &mut String) -> Result<Prepared> {
    let prepared = certs::validate_upload(certificate, private_key, now());
    private_key.zeroize();
    prepared
}

fn detail(stored: &Stored) -> String {
    format!(
        "id={} name={:?} fingerprint={} subject={:?}",
        stored.id, stored.name, stored.info.fingerprint, stored.info.subject
    )
}

// True when a running HAProxy loaded the change; false when HAProxy could not be reached, so the files are in place but not yet served.
async fn apply(st: &Inner) -> Result<bool> {
    let applied = st.haproxy.apply(&st.store.config()).await?;
    applied.require_loaded()?;
    Ok(applied.running)
}

// Puts the files back and lets HAProxy load the old set again; a failure here is logged because the caller already has an error to report.
async fn restore(st: &Inner, undo: Undo) -> Rollback {
    match on_store(st, move |store| store.rollback(undo)).await {
        Ok(()) => match apply(st).await {
            Ok(_) => Rollback::Done,
            Err(e) => {
                tracing::warn!(error = %e, "haproxy could not re-apply the restored certificates");
                Rollback::NotConfirmed
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "could not restore the previous certificate files");
            Rollback::StoreFailed
        }
    }
}

fn missing_upload() -> ConnectorError {
    ConnectorError::Internal("certificate change without an upload".into())
}

async fn change(
    st: AppState,
    actor: String,
    op: Op,
    prepared: Option<Prepared>,
) -> Result<(Stored, bool)> {
    let _gate = st.certs.lock().await;
    let _config = st.deployer.config_lock().lock().await;
    let action = op.action();
    let created_at = now_rfc3339();
    let (stored, undo) = on_store(&st, move |store| match op {
        Op::Create(name) => store.create(&name, &prepared.ok_or_else(missing_upload)?, &created_at),
        Op::Replace { id, name } => store.replace(
            &id,
            name.as_deref(),
            &prepared.ok_or_else(missing_upload)?,
            &created_at,
        ),
        Op::Delete(id) => store.delete(&id),
    })
    .await?;
    let live = match apply(&st).await {
        Ok(live) => live,
        Err(err) => {
            return Err(rolled_back(&st, &actor, undo, err).await);
        }
    };
    let mut note = detail(&stored);
    if !live {
        note.push_str(" haproxy=unreachable");
    }
    st.store.audit(&actor, action, &note).await;
    Ok((stored, live))
}

async fn rolled_back(st: &Inner, actor: &str, undo: Undo, err: ConnectorError) -> ConnectorError {
    let id = undo.id().to_string();
    let outcome = restore(st, undo).await;
    let name = match outcome {
        Rollback::Done => "certificates.rollback",
        Rollback::StoreFailed => "certificates.rollback_failed",
        Rollback::NotConfirmed => "certificates.rollback_unconfirmed",
    };
    st.store.audit(actor, name, &format!("id={id}")).await;
    let how = outcome
        .phrase()
        .replace("the stored configuration", "the certificate files");
    match err {
        ConnectorError::BadRequest(msg) => ConnectorError::BadRequest(format!(
            "haproxy rejected the certificate change, {how}: {msg}"
        )),
        other => ConnectorError::Unavailable(format!(
            "haproxy could not apply the certificate change, {how}: {}",
            reason(&other)
        )),
    }
}

// Runs to completion even if the client disconnects, so files and HAProxy never end up half changed.
async fn run(
    st: &AppState,
    actor: String,
    op: Op,
    prepared: Option<Prepared>,
) -> Result<(Stored, bool)> {
    let this = Arc::clone(st);
    detach(async move { change(this, actor, op, prepared).await }).await
}

// `mutation` carries whether HAProxy loaded the change; an unreachable one adds a warning, since the files are stored but not served.
fn view(
    st: &Inner,
    stored: &Stored,
    status: StatusCode,
    mutation: Option<bool>,
) -> ApiResult<Response> {
    let cfg = st.store.config();
    let cert = Cert::new(stored, &site_hosts(&cfg), now());
    let mut body = serde_json::to_value(&cert)?;
    let mut warnings: Vec<&str> = Vec::new();
    if let Some(live) = mutation {
        if cfg.settings.https_port.is_none() {
            warnings.push(HTTPS_OFF);
        }
        if !live {
            warnings.push(HAPROXY_DOWN);
        }
    }
    if !warnings.is_empty()
        && let Some(obj) = body.as_object_mut()
    {
        obj.insert("warning".into(), Value::String(warnings.join("; ")));
    }
    Ok((status, Json(body)).into_response())
}

fn not_found() -> ApiError {
    ConnectorError::NotFound("certificate not found".into()).into()
}

pub(super) async fn list(State(st): State<AppState>) -> ApiResult<Response> {
    let stored = on_store(&st, |store| store.list()).await?;
    let cfg = st.store.config();
    let hosts = site_hosts(&cfg);
    let at = now();
    let items: Vec<Cert> = stored.iter().map(|s| Cert::new(s, &hosts, at)).collect();
    Ok(Json(json!({
        "items": items,
        "https_port": cfg.settings.https_port,
        "dir_ready": st.certs.dir_ready(),
        "uncovered_hosts": certs::uncovered_hosts(&stored, &hosts),
    }))
    .into_response())
}

pub(super) async fn get_one(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let stored = on_store(&st, move |store| store.get(&id))
        .await?
        .ok_or_else(not_found)?;
    view(&st, &stored, StatusCode::OK, None)
}

pub(super) async fn create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    CertBody(mut req): CertBody<CreateReq>,
) -> ApiResult<Response> {
    certs::validate_name(&req.name)?;
    let prepared = check_upload(&req.certificate, &mut req.private_key)?;
    let name = std::mem::take(&mut req.name);
    let (stored, live) = run(&st, p.actor(), Op::Create(name), Some(prepared)).await?;
    view(&st, &stored, StatusCode::CREATED, Some(live))
}

pub(super) async fn replace(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    CertBody(mut req): CertBody<ReplaceReq>,
) -> ApiResult<Response> {
    if !certs::is_cert_id(&id) {
        return Err(not_found());
    }
    if let Some(name) = &req.name {
        certs::validate_name(name)?;
    }
    let prepared = check_upload(&req.certificate, &mut req.private_key)?;
    let op = Op::Replace {
        id,
        name: req.name.take(),
    };
    let (stored, live) = run(&st, p.actor(), op, Some(prepared)).await?;
    view(&st, &stored, StatusCode::OK, Some(live))
}

pub(super) async fn delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    if !certs::is_cert_id(&id) {
        return Err(not_found());
    }
    run(&st, p.actor(), Op::Delete(id), None).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
