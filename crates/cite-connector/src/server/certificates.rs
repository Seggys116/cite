use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{FromRequest, Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use cite_edge::model::EdgeConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::{ApiError, ApiResult, AppState, Inner, Principal, parse_json, read_body_limited};
use crate::acme::{self, AccountKey, Busy, Finished, Job, MAX_PER_HOUR, Ticket};
use crate::certs::{self, Cert, CertStore, MAX_BODY_BYTES, Managed, Prepared, Stored, Undo};
use crate::cfapi::CfToken;
use crate::change::{Rollback, reason};
use crate::deploy::detach;
use crate::originca;
use crate::store::{now_rfc3339, now_unix};
use crate::{ConnectorError, Result};

const HAPROXY_DOWN: &str = "HAProxy could not be reached, so the change is stored and will be served after the next successful reload";
const HTTPS_OFF: &str = "HTTPS is not enabled on this node, so this certificate is stored but not served; set https_port in the node settings (PUT /api/v1/settings) to bind the TLS listener";
const SELF_SIGNED_NOTE: &str =
    "Self-signed: browsers do not trust it; fine behind Cloudflare Full (not strict).";
const TOKEN_KEPT: &str = "The Cloudflare token is stored on this node for this certificate only (secret cloudflare-token:<certificate id>, mode 0600) so it is renewed automatically 30 days before it expires; the tokens of other certificates are not changed.";
const TOKEN_NOT_KEPT: &str = "The Cloudflare token was not stored, so this certificate is renewed automatically only once a token is stored (remember_token, or an ACME issue).";
const TOKEN_NOT_SAVED: &str =
    "The Cloudflare token could not be stored, so automatic renewal fails until a token is stored.";
const ACME_NOTE: &str = "Issuing runs in the background and can take a few minutes; poll the job. When the certificate is issued the Cloudflare token is stored on this node for that certificate only (secret cloudflare-token:<certificate id>, mode 0600), because automatic renewal 30 days before expiry needs it; the tokens of other certificates are not changed.";
// The single secret used before tokens were kept per certificate; renewal still falls back to it.
const LEGACY_TOKEN_SECRET: &str = "cloudflare-token";
const RENEW_SKIPPED: &str = "the certificate was replaced or removed while it was being renewed, so the renewal was dropped";

fn token_secret(id: &str) -> String {
    format!("{LEGACY_TOKEN_SECRET}:{id}")
}
const ISSUE_BODY_BYTES: usize = 16 * 1024;
const DEFAULT_SELF_SIGNED_DAYS: u32 = 825;
const MAX_SELF_SIGNED_DAYS: u32 = 3650;
const SYSTEM: &str = "system";
const RENEW_FIRST_CHECK: Duration = Duration::from_secs(60);
const RENEW_INTERVAL: Duration = Duration::from_secs(3600);

// A smaller cap than the rest of the API: a chain and a key never need more, and an issue request far less.
pub(super) struct CertBody<T, const LIMIT: usize = MAX_BODY_BYTES>(T);

impl<S, T, const LIMIT: usize> FromRequest<S> for CertBody<T, LIMIT>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, LIMIT).await?;
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GenerateReq {
    hosts: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    days: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginReq {
    hosts: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    cloudflare_token: String,
    #[serde(default)]
    validity_days: Option<u32>,
    #[serde(default)]
    remember_token: bool,
}

impl Drop for OriginReq {
    fn drop(&mut self) {
        self.cloudflare_token.zeroize();
    }
}

impl fmt::Debug for OriginReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginReq")
            .field("hosts", &self.hosts)
            .field("name", &self.name)
            .field("cloudflare_token", &"<redacted>")
            .field("validity_days", &self.validity_days)
            .field("remember_token", &self.remember_token)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcmeReq {
    hosts: Vec<String>,
    email: String,
    cloudflare_token: String,
    #[serde(default)]
    agree_tos: bool,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    staging: bool,
}

impl Drop for AcmeReq {
    fn drop(&mut self) {
        self.cloudflare_token.zeroize();
    }
}

impl fmt::Debug for AcmeReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeReq")
            .field("hosts", &self.hosts)
            .field("email", &self.email)
            .field("cloudflare_token", &"<redacted>")
            .field("agree_tos", &self.agree_tos)
            .field("name", &self.name)
            .field("staging", &self.staging)
            .finish()
    }
}

enum Op {
    Create(String),
    Issued { name: String, action: &'static str },
    Replace { id: String, name: Option<String> },
    Renew { id: String, fingerprint: String },
    Delete(String),
}

impl Op {
    fn action(&self) -> &'static str {
        match self {
            Op::Create(_) => "certificates.create",
            Op::Issued { action, .. } => action,
            Op::Replace { .. } => "certificates.replace",
            Op::Renew { .. } => "certificates.renew",
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
    if let Op::Renew { id, fingerprint } = &op {
        let still_managed = on_store(&st, {
            let id = id.clone();
            move |store| store.get(&id)
        })
        .await?
        .is_some_and(|c| c.managed.is_some() && c.info.fingerprint == *fingerprint);
        if !still_managed {
            st.store
                .audit(&actor, "certificates.renew_skipped", &format!("id={id}"))
                .await;
            return Err(ConnectorError::Conflict(RENEW_SKIPPED.into()));
        }
    }
    let forget = match &op {
        Op::Replace { id, .. } | Op::Delete(id) => Some(token_secret(id)),
        _ => None,
    };
    let (stored, undo) = on_store(&st, move |store| match op {
        Op::Create(name) | Op::Issued { name, .. } => {
            store.create(&name, &prepared.ok_or_else(missing_upload)?, &created_at)
        }
        Op::Replace { id, name } => store.replace(
            &id,
            name.as_deref(),
            &prepared.ok_or_else(missing_upload)?,
            &created_at,
        ),
        Op::Renew { id, .. } => store.replace(
            &id,
            None,
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
    if let Some(secret) = forget {
        st.store.delete_secret(&secret).await;
    }
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
    notes: &[&str],
) -> ApiResult<Response> {
    let cfg = st.store.config();
    let cert = Cert::new(stored, &site_hosts(&cfg), now());
    let mut body = serde_json::to_value(&cert)?;
    let mut warnings: Vec<&str> = notes.to_vec();
    if let Some(live) = mutation {
        if certs::effective_https_port(&cfg).is_none() {
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

// The node makes and removes these itself; replacing or deleting one by hand would only be undone at the next apply.
fn refuse_automatic(id: &str) -> ApiResult<()> {
    if id.starts_with("auto:") {
        return Err(ApiError::bad(
            "automatic certificates are managed by the node",
        ));
    }
    Ok(())
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
        "https_effective_port": certs::effective_https_port(&cfg),
        "automatic": certs::auto_active(&cfg),
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
    view(&st, &stored, StatusCode::OK, None, &[])
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
    view(&st, &stored, StatusCode::CREATED, Some(live), &[])
}

pub(super) async fn replace(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    CertBody(mut req): CertBody<ReplaceReq>,
) -> ApiResult<Response> {
    refuse_automatic(&id)?;
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
    view(&st, &stored, StatusCode::OK, Some(live), &[])
}

pub(super) async fn delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    refuse_automatic(&id)?;
    if !certs::is_cert_id(&id) {
        return Err(not_found());
    }
    run(&st, p.actor(), Op::Delete(id), None).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// The routes that make certificates instead of receiving them; merged behind the same auth layer as the others.
pub(super) fn issue_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/certificates/generate", post(generate))
        .route("/api/v1/certificates/origin-ca", post(origin_ca))
        .route("/api/v1/certificates/acme", get(acme_list).post(acme_start))
        .route("/api/v1/certificates/acme/{job_id}", get(acme_job))
}

fn name_for(name: Option<String>, prefix: &str, hosts: &[String]) -> Result<String> {
    match name {
        Some(name) => certs::validate_name(&name).map(|()| name),
        None => Ok(certs::default_name(prefix, &hosts[0])),
    }
}

fn start_issuing(st: &Inner) -> ApiResult<Ticket> {
    st.certs.issuing().begin(now()).map_err(|busy| match busy {
        Busy::Running => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "another certificate is being issued on this node; try again when it has finished",
        ),
        Busy::Hourly { retry_after } => ApiError {
            retry_after: Some(retry_after),
            ..ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "at most {MAX_PER_HOUR} certificates can be issued per hour on this node; try again later"
                ),
            )
        },
    })
}

// Internal detail goes to the log only; everything else is already safe to show and never holds a token.
fn public_error(e: &ConnectorError) -> String {
    match e {
        ConnectorError::Internal(detail) => {
            tracing::error!(%detail, "internal error while issuing a certificate");
            "internal error".into()
        }
        other => other.to_string(),
    }
}

fn finished(stored: &Stored) -> Finished {
    Finished {
        certificate_id: stored.id.clone(),
        not_after: certs::rfc3339(stored.info.not_after),
        renew_at: certs::rfc3339(certs::renew_at(&stored.info)),
    }
}

async fn keep_token(st: &Inner, actor: &str, id: &str, token: &CfToken) -> bool {
    let secret = token_secret(id);
    match st.store.put_secret(&secret, token.expose()).await {
        Ok(()) => {
            st.store
                .audit(
                    actor,
                    "certificates.token_stored",
                    &format!("secret={secret}"),
                )
                .await;
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "the Cloudflare token could not be stored");
            false
        }
    }
}

async fn account_key(st: &Inner) -> Result<AccountKey> {
    let path = st.cfg.data_dir.join(acme::ACCOUNT_KEY_FILE);
    tokio::task::spawn_blocking(move || AccountKey::load_or_create(&path))
        .await
        .map_err(|e| ConnectorError::Internal(format!("account key task failed: {e}")))?
}

pub(super) async fn generate(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    CertBody(req): CertBody<GenerateReq, ISSUE_BODY_BYTES>,
) -> ApiResult<Response> {
    let hosts = certs::validate_issue_hosts(&req.hosts, true)?;
    let days = req.days.unwrap_or(DEFAULT_SELF_SIGNED_DAYS);
    if !(1..=MAX_SELF_SIGNED_DAYS).contains(&days) {
        return Err(ApiError::bad(format!(
            "days must be 1 to {MAX_SELF_SIGNED_DAYS}"
        )));
    }
    let name = name_for(req.name, "self-signed", &hosts)?;
    let at = now();
    let prepared = certs::self_signed(&hosts, days, at)?.prepare(at, &hosts, None)?;
    let op = Op::Issued {
        name,
        action: "certificates.generate",
    };
    let (stored, live) = run(&st, p.actor(), op, Some(prepared)).await?;
    view(
        &st,
        &stored,
        StatusCode::CREATED,
        Some(live),
        &[SELF_SIGNED_NOTE],
    )
}

pub(super) async fn origin_ca(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    CertBody(mut req): CertBody<OriginReq, ISSUE_BODY_BYTES>,
) -> ApiResult<Response> {
    let hosts = certs::validate_issue_hosts(&req.hosts, false)?;
    let days = req.validity_days.unwrap_or(originca::DEFAULT_VALIDITY_DAYS);
    originca::check_validity(days)?;
    let name = name_for(req.name.take(), "origin-ca", &hosts)?;
    let token = CfToken::parse(&req.cloudflare_token)?;
    req.cloudflare_token.zeroize();
    let remember = req.remember_token;
    let ticket = start_issuing(&st)?;
    let this = Arc::clone(&st);
    let actor = p.actor();
    let (stored, live, kept) = detach(async move {
        let _ticket = ticket;
        let http = this.certs.issuing().http()?;
        let generated = originca::issue(&http, &token, &hosts, days).await?;
        let managed = Some(Managed::OriginCa { days });
        let prepared = generated.prepare(now(), &hosts, managed)?;
        let op = Op::Issued {
            name,
            action: "certificates.origin_ca",
        };
        let (stored, live) = change(Arc::clone(&this), actor.clone(), op, Some(prepared)).await?;
        let kept = if remember {
            Some(keep_token(&this, &actor, &stored.id, &token).await)
        } else {
            None
        };
        spawn_renewals(Arc::clone(&this));
        Ok((stored, live, kept))
    })
    .await?;
    let note = match kept {
        Some(true) => TOKEN_KEPT,
        Some(false) => TOKEN_NOT_SAVED,
        None => TOKEN_NOT_KEPT,
    };
    view(&st, &stored, StatusCode::CREATED, Some(live), &[note])
}

struct AcmeJob {
    job_id: String,
    actor: String,
    name: String,
    hosts: Vec<String>,
    email: String,
    staging: bool,
}

pub(super) async fn acme_start(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    CertBody(mut req): CertBody<AcmeReq, ISSUE_BODY_BYTES>,
) -> ApiResult<Response> {
    if !req.agree_tos {
        return Err(ApiError::bad(
            "agree_tos must be true: issuing through Let's Encrypt means accepting its Subscriber Agreement",
        ));
    }
    let hosts = certs::validate_issue_hosts(&req.hosts, false)?;
    acme::validate_email(&req.email)?;
    let name = name_for(req.name.take(), "letsencrypt", &hosts)?;
    let token = CfToken::parse(&req.cloudflare_token)?;
    req.cloudflare_token.zeroize();
    let ticket = start_issuing(&st)?;
    let job = Job::pending("acme", hosts.clone(), req.staging, now_rfc3339());
    let order = AcmeJob {
        job_id: job.id.clone(),
        actor: p.actor(),
        name,
        hosts,
        email: std::mem::take(&mut req.email),
        staging: req.staging,
    };
    st.certs.issuing().add_job(job);
    let (job_id, staging) = (order.job_id.clone(), order.staging);
    let this = Arc::clone(&st);
    tokio::spawn(async move {
        let _ticket = ticket;
        let outcome = acme_issue(&this, &order, &token).await;
        let issuing = this.certs.issuing();
        match outcome {
            Ok(stored) => issuing.finish(&order.job_id, Ok(finished(&stored)), now_rfc3339()),
            Err(e) => {
                let text = public_error(&e);
                tracing::warn!(job = %order.job_id, error = %text, "ACME issuing failed");
                this.store
                    .audit(
                        &order.actor,
                        "certificates.acme_failed",
                        &format!("job={} error={text}", order.job_id),
                    )
                    .await;
                issuing.finish(&order.job_id, Err(text), now_rfc3339());
            }
        }
    });
    let body = json!({
        "job_id": job_id,
        "status": "pending",
        "staging": staging,
        "note": ACME_NOTE,
    });
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

async fn acme_issue(st: &AppState, order: &AcmeJob, token: &CfToken) -> Result<Stored> {
    let http = st.certs.issuing().http()?;
    let key = account_key(st).await?;
    let request = acme::Order {
        hosts: &order.hosts,
        email: Some(&order.email),
        staging: order.staging,
    };
    let generated = acme::issue(&http, token, &key, &request).await?;
    let managed = Some(Managed::Acme {
        staging: order.staging,
    });
    let prepared = generated.prepare(now(), &order.hosts, managed)?;
    let op = Op::Issued {
        name: order.name.clone(),
        action: "certificates.acme",
    };
    let (stored, _) = change(Arc::clone(st), order.actor.clone(), op, Some(prepared)).await?;
    keep_token(st, &order.actor, &stored.id, token).await;
    spawn_renewals(Arc::clone(st));
    Ok(stored)
}

#[derive(Serialize)]
struct ManagedView<'a> {
    id: &'a str,
    name: &'a str,
    kind: &'static str,
    hosts: &'a [String],
    status: &'static str,
    not_after: String,
    renew_at: String,
    staging: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_attempt: Option<String>,
}

pub(super) async fn acme_list(State(st): State<AppState>) -> ApiResult<Response> {
    let stored = on_store(&st, |store| store.list()).await?;
    let issuing = st.certs.issuing();
    let certificates: Vec<ManagedView<'_>> = stored
        .iter()
        .filter_map(|s| {
            let managed = s.managed?;
            let failure = issuing.last_failure(&s.id);
            Some(ManagedView {
                id: &s.id,
                name: &s.name,
                kind: managed.kind(),
                hosts: &s.info.sans,
                status: "issued",
                not_after: certs::rfc3339(s.info.not_after),
                renew_at: certs::rfc3339(certs::renew_at(&s.info)),
                staging: managed.staging(),
                next_attempt: failure.as_ref().map(|f| certs::rfc3339(f.0)),
                error: failure.map(|f| f.1),
            })
        })
        .collect();
    let mut token_stored = st.store.get_secret(LEGACY_TOKEN_SECRET).await.is_some();
    for s in stored.iter().filter(|s| s.managed.is_some()) {
        token_stored |= st.store.get_secret(&token_secret(&s.id)).await.is_some();
    }
    Ok(Json(json!({
        "jobs": issuing.jobs(),
        "certificates": certificates,
        "token_stored": token_stored,
    }))
    .into_response())
}

pub(super) async fn acme_job(
    State(st): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Response> {
    let job = certs::is_cert_id(&job_id)
        .then(|| st.certs.issuing().job(&job_id))
        .flatten()
        .ok_or_else(|| ApiError::from(ConnectorError::NotFound("job not found".into())))?;
    Ok(Json(job).into_response())
}

// Started once per node, from server start and again (harmlessly) after the first managed certificate is issued.
pub(crate) fn spawn_renewals(st: AppState) {
    if !st.certs.issuing().claim_renewals() {
        return;
    }
    let weak = Arc::downgrade(&st);
    drop(st);
    tokio::spawn(async move {
        tokio::time::sleep(RENEW_FIRST_CHECK).await;
        loop {
            let Some(st) = weak.upgrade() else {
                return;
            };
            renew_due(&st, now()).await;
            drop(st);
            tokio::time::sleep(RENEW_INTERVAL).await;
        }
    });
}

// `at` is the clock the due check uses, so tests can move it; a failure backs off and is shown in the job list.
pub(crate) async fn renew_due(st: &AppState, at: i64) -> usize {
    let stored = match on_store(st, |store| store.list()).await {
        Ok(stored) => stored,
        Err(e) => {
            tracing::warn!(error = %e, "managed certificates could not be listed for renewal");
            return 0;
        }
    };
    let issuing = st.certs.issuing();
    let due: Vec<Stored> = stored
        .into_iter()
        .filter(|s| {
            s.managed.is_some() && certs::renew_at(&s.info) <= at && issuing.may_retry(&s.id, at)
        })
        .collect();
    if due.is_empty() {
        return 0;
    }
    let Ok(_turn) = issuing.turn().await else {
        return 0;
    };
    let mut renewed = 0;
    for cert in due {
        let staging = cert.managed.is_some_and(Managed::staging);
        let job = Job::pending("renew", cert.info.sans.clone(), staging, now_rfc3339());
        let job_id = job.id.clone();
        issuing.add_job(job);
        match renew_one(st, &cert).await {
            Ok(stored) => {
                issuing.record_success(&cert.id);
                issuing.finish(&job_id, Ok(finished(&stored)), now_rfc3339());
                renewed += 1;
            }
            Err(e) => {
                let text = public_error(&e);
                let next = issuing.record_failure(&cert.id, at, &text);
                tracing::warn!(id = %cert.id, error = %text, next = %certs::rfc3339(next), "certificate renewal failed");
                st.store
                    .audit(
                        SYSTEM,
                        "certificates.renew_failed",
                        &format!("id={} error={text}", cert.id),
                    )
                    .await;
                issuing.finish(&job_id, Err(text), now_rfc3339());
            }
        }
    }
    renewed
}

// Issues a fresh certificate for the same names and swaps it in under the same id through the normal replace path.
async fn renew_one(st: &AppState, cert: &Stored) -> Result<Stored> {
    let managed = cert
        .managed
        .ok_or_else(|| ConnectorError::Internal("renewal of an unmanaged certificate".into()))?;
    let hosts = certs::validate_issue_hosts(&cert.info.sans, false)?;
    let own = st.store.get_secret(&token_secret(&cert.id)).await;
    let stored_token = match own {
        Some(own) => Some(own),
        None => st.store.get_secret(LEGACY_TOKEN_SECRET).await,
    }
    .map(Zeroizing::new)
    .ok_or_else(|| {
        ConnectorError::BadRequest(
            "no Cloudflare token is stored on this node; issue the certificate again with remember_token, or through ACME".into(),
            )
        })?;
    let token = CfToken::parse(&stored_token)?;
    let http = st.certs.issuing().http()?;
    let generated = match managed {
        Managed::OriginCa { days } => originca::issue(&http, &token, &hosts, days).await?,
        Managed::Acme { staging } => {
            let key = account_key(st).await?;
            let request = acme::Order {
                hosts: &hosts,
                email: None,
                staging,
            };
            acme::issue(&http, &token, &key, &request).await?
        }
    };
    let prepared = generated.prepare(now(), &hosts, Some(managed))?;
    let op = Op::Renew {
        id: cert.id.clone(),
        fingerprint: cert.info.fingerprint.clone(),
    };
    let (stored, _) = change(Arc::clone(st), SYSTEM.into(), op, Some(prepared)).await?;
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex as StdMutex;

    use axum::body::Body;
    use axum::http::{Method, header};
    use tower::Service;

    use super::*;
    use crate::acme::mock::{self, Mock};
    use crate::deploy::Deployer;
    use crate::haproxy::Haproxy;
    use crate::logsink::{self, IngestStats};
    use crate::store::Store;
    use crate::store::testing::test_config;

    const DAY: i64 = 86_400;
    const EMAIL: &str = "admin@example.com";

    struct Node {
        _dir: tempfile::TempDir,
        st: AppState,
        app: Router,
    }

    // The real state and handlers behind a router that injects the signed-in principal the auth layer would add.
    async fn node(mock: &Mock) -> Node {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        let store = Store::open(&cfg).await.expect("open");
        let haproxy = Arc::new(Haproxy::new(&cfg));
        let deployer = Arc::new(Deployer::new(
            Arc::clone(&store),
            Arc::clone(&haproxy),
            None,
        ));
        let analytics = logsink::open_store(&cfg, 30).expect("analytics");
        let ingest = Arc::new(IngestStats::default());
        let st = Inner::new(cfg, store, haproxy, deployer, None, analytics, ingest);
        st.certs.issuing().set_endpoints(mock.endpoints());
        let principal = Principal {
            name: "admin".into(),
            kind: "session",
            expires_at: None,
            session_token: None,
        };
        let app = issue_routes()
            .route("/api/v1/certificates", get(list))
            .route(
                "/api/v1/certificates/{id}",
                get(get_one).put(replace).delete(delete),
            )
            .layer(Extension(principal))
            .with_state(Arc::clone(&st));
        Node { _dir: dir, st, app }
    }

    impl Node {
        async fn call(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> (u16, Value) {
            let mut req = axum::http::Request::builder()
                .method(method)
                .uri(format!("/api/v1{path}"));
            if body.is_some() {
                req = req.header(header::CONTENT_TYPE, "application/json");
            }
            let req = req
                .body(Body::from(body.unwrap_or_default()))
                .expect("request");
            let res = self.app.clone().call(req).await.expect("router");
            let status = res.status().as_u16();
            let bytes = axum::body::to_bytes(res.into_body(), 4 << 20)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        async fn post(&self, path: &str, body: Value) -> (u16, Value) {
            let bytes = serde_json::to_vec(&body).expect("json");
            self.call(Method::POST, path, Some(bytes)).await
        }

        async fn get(&self, path: &str) -> (u16, Value) {
            self.call(Method::GET, path, None).await
        }

        fn audit_text(&self) -> String {
            std::fs::read_to_string(self.st.cfg.data_dir.join("audit.jsonl")).unwrap_or_default()
        }

        async fn wait_job(&self, id: &str) -> Value {
            for _ in 0..1000 {
                let (status, job) = self.get(&format!("/certificates/acme/{id}")).await;
                assert_eq!(status, 200, "{job}");
                if job["status"] != "pending" {
                    return job;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("job {id} did not finish");
        }

        fn not_after(&self, id: &str) -> i64 {
            self.st
                .certs
                .get(id)
                .expect("read")
                .expect("stored")
                .info
                .not_after
        }

        async fn jobs(&self) -> Vec<Value> {
            let (_, listing) = self.get("/certificates/acme").await;
            listing["jobs"].as_array().cloned().unwrap_or_default()
        }
    }

    #[derive(Clone, Default)]
    struct Logs(Arc<StdMutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Logs {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
        }
    }

    // The current-thread test runtime runs the spawned issuing tasks on this thread, so they log here too.
    fn capture() -> (Logs, tracing::subscriber::DefaultGuard) {
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("cite_connector=trace"))
            .with_writer(move || writer.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    fn key_lines(n: &Node, id: &str) -> Vec<String> {
        let path = n.st.cfg.certs_dir.join(format!("{id}.pem"));
        let text = std::fs::read_to_string(path).expect("certificate file");
        let start = text.find("-----BEGIN PRIVATE KEY").expect("key block");
        text[start..]
            .lines()
            .filter(|l| !l.starts_with("-----") && l.len() >= 16)
            .map(str::to_string)
            .collect()
    }

    fn assert_secret_free(text: &str, n: &Node, id: &str) {
        let lines = key_lines(n, id);
        assert!(!lines.is_empty());
        for line in lines {
            assert!(!text.contains(&line), "key material leaked: {text}");
        }
        for token in [mock::TOKEN, mock::SERVICE_KEY] {
            assert!(!text.contains(token), "token leaked: {text}");
        }
    }

    fn acme_body(hosts: &[&str]) -> Value {
        json!({
            "hosts": hosts,
            "email": EMAIL,
            "cloudflare_token": mock::TOKEN,
            "agree_tos": true,
        })
    }

    async fn issue_acme(n: &Node, body: Value) -> (Value, String) {
        let (status, started) = n.post("/certificates/acme", body).await;
        assert_eq!(status, 202, "{started}");
        let job_id = started["job_id"].as_str().expect("job id").to_string();
        let job = n.wait_job(&job_id).await;
        (job, job_id)
    }

    #[tokio::test]
    async fn a_self_signed_certificate_is_generated_stored_and_deletable() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let body =
            json!({ "hosts": ["Shop.Example.com", "*.example.net", "10.0.0.5"], "days": 30 });
        let (status, created) = n.post("/certificates/generate", body).await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_str().expect("id").to_string();
        assert!(certs::is_cert_id(&id));
        assert_eq!(
            created["sans"],
            json!(["shop.example.com", "*.example.net", "10.0.0.5"])
        );
        assert_eq!(created["source"], "api");
        assert_eq!(created["name"], "self-signed shop.example.com");
        assert_eq!(created["issuer"], created["subject"]);
        assert_eq!(created["key_type"], "ecdsa-p256");
        assert!(
            created["days_left"]
                .as_i64()
                .is_some_and(|d| (29..=30).contains(&d))
        );
        assert!(
            created["warning"]
                .as_str()
                .is_some_and(|w| w.starts_with(SELF_SIGNED_NOTE))
        );
        assert!(created.get("managed").is_none());
        assert!(created.get("private_key").is_none());
        assert_secret_free(&created.to_string(), &n, &id);

        let (status, one) = n.get(&format!("/certificates/{id}")).await;
        assert_eq!(status, 200);
        assert_eq!(one["fingerprint_sha256"], created["fingerprint_sha256"]);
        let audit = n.audit_text();
        assert!(audit.contains("certificates.generate"), "{audit}");
        assert_secret_free(&audit, &n, &id);

        let (status, _) = n
            .call(Method::DELETE, &format!("/certificates/{id}"), None)
            .await;
        assert_eq!(status, 204);
        let (_, list) = n.get("/certificates").await;
        assert_eq!(list["items"], json!([]));
    }

    #[tokio::test]
    async fn issue_routes_check_their_input_and_body_size() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let many: Vec<String> = (0..33).map(|i| format!("h{i}.example.com")).collect();
        for body in [
            json!({ "hosts": [] }),
            json!({ "hosts": many }),
            json!({ "hosts": ["exa mple.com"] }),
            json!({ "hosts": ["*.com"] }),
            json!({ "hosts": ["a.example.com"], "days": 0 }),
            json!({ "hosts": ["a.example.com"], "days": 3651 }),
            json!({ "hosts": ["a.example.com"], "name": "bad/name" }),
            json!({ "hosts": ["a.example.com"], "private_key": "x" }),
        ] {
            let (status, err) = n.post("/certificates/generate", body.clone()).await;
            assert_eq!(status, 400, "{body}: {err}");
        }
        let huge = "x".repeat(17 * 1024);
        for path in [
            "/certificates/generate",
            "/certificates/origin-ca",
            "/certificates/acme",
        ] {
            let body = json!({ "hosts": ["a.example.com"], "name": huge });
            assert_eq!(n.post(path, body).await.0, 413, "{path}");
        }
        let (_, list) = n.get("/certificates").await;
        assert_eq!(list["items"], json!([]));
        assert_eq!(n.get("/certificates/acme/not-a-job").await.0, 404);
        let unknown = ulid::Ulid::generate().to_string();
        assert_eq!(n.get(&format!("/certificates/acme/{unknown}")).await.0, 404);
    }

    #[test]
    fn request_bodies_never_print_the_token() {
        let origin: OriginReq = serde_json::from_value(json!({
            "hosts": ["a.example.com"],
            "cloudflare_token": mock::TOKEN,
        }))
        .expect("origin request");
        let acme: AcmeReq =
            serde_json::from_value(acme_body(&["a.example.com"])).expect("acme request");
        for text in [format!("{origin:?}"), format!("{acme:?}")] {
            assert!(!text.contains(mock::TOKEN), "{text}");
            assert!(text.contains("<redacted>"), "{text}");
        }
    }

    #[tokio::test]
    async fn an_origin_ca_certificate_is_issued_for_a_key_made_on_the_node() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let (logs, _guard) = capture();
        let hosts = ["shop.example.com", "*.shop.example.com"];
        let body = json!({ "hosts": hosts, "cloudflare_token": mock::TOKEN, "validity_days": 365 });
        let (status, created) = n.post("/certificates/origin-ca", body).await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_str().expect("id").to_string();
        assert_eq!(created["sans"], json!(hosts));
        assert_eq!(created["source"], "api");
        assert_eq!(created["managed"], "origin-ca");
        assert_eq!(created["name"], "origin-ca shop.example.com");
        assert!(
            created["issuer"]
                .as_str()
                .is_some_and(|i| i.contains(mock::CA_NAME))
        );
        assert!(
            created["warning"]
                .as_str()
                .is_some_and(|w| w.contains(TOKEN_NOT_KEPT))
        );

        let calls = mock.with(|s| s.origin_calls.clone());
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].auth, "bearer");
        assert_eq!(calls[0].request_type, "origin-ecc");
        assert_eq!(calls[0].validity, 365);
        assert_eq!(calls[0].hostnames, hosts);
        assert_eq!(calls[0].csr.sans, hosts);
        assert_eq!(calls[0].csr.key_len, 65);
        assert_eq!(
            calls[0].csr.common_name.as_deref(),
            Some("shop.example.com")
        );
        assert_eq!(n.st.store.get_secret(&token_secret(&id)).await, None);

        let audit = n.audit_text();
        assert!(audit.contains("certificates.origin_ca"), "{audit}");
        for text in [created.to_string(), audit, logs.text()] {
            assert_secret_free(&text, &n, &id);
        }
        let (_, listing) = n.get("/certificates/acme").await;
        assert_eq!(listing["certificates"][0]["kind"], "origin-ca");
        assert_eq!(listing["certificates"][0]["id"], id);
        assert_eq!(listing["token_stored"], false);
    }

    #[tokio::test]
    async fn a_remembered_origin_ca_key_is_kept_as_a_private_secret() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let body = json!({
            "hosts": ["shop.example.com"],
            "name": "Shop origin",
            "cloudflare_token": mock::SERVICE_KEY,
            "remember_token": true,
        });
        let (status, created) = n.post("/certificates/origin-ca", body).await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_str().expect("id").to_string();
        assert_eq!(created["name"], "Shop origin");
        assert!(
            created["warning"]
                .as_str()
                .is_some_and(|w| w.contains(TOKEN_KEPT))
        );
        let calls = mock.with(|s| s.origin_calls.clone());
        assert_eq!(calls[0].auth, "service-key");
        assert_eq!(
            calls[0].validity,
            u64::from(originca::DEFAULT_VALIDITY_DAYS)
        );
        assert_eq!(
            n.st.store.get_secret(&token_secret(&id)).await.as_deref(),
            Some(mock::SERVICE_KEY)
        );
        let secrets = n.st.cfg.data_dir.join("secrets.json");
        let mode = std::fs::metadata(secrets)
            .expect("secrets")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let audit = n.audit_text();
        assert!(audit.contains("certificates.token_stored"), "{audit}");
        assert_secret_free(&audit, &n, &id);
        let (_, listing) = n.get("/certificates/acme").await;
        assert_eq!(listing["token_stored"], true);
        assert_secret_free(&listing.to_string(), &n, &id);
    }

    #[tokio::test]
    async fn origin_ca_failures_store_nothing_and_never_echo_the_token() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        mock.with(|s| s.script.fail_origin = true);
        let body = json!({ "hosts": ["shop.example.com"], "cloudflare_token": mock::TOKEN, "remember_token": true });
        let (status, err) = n.post("/certificates/origin-ca", body).await;
        assert_eq!(status, 400, "{err}");
        let text = err["error"].as_str().expect("error").to_string();
        assert!(text.contains("Cloudflare refused"), "{text}");
        assert!(text.contains("[redacted]"), "{text}");
        assert!(!text.contains(mock::TOKEN), "{text}");

        for body in [
            json!({ "hosts": ["shop.example.com"], "cloudflare_token": mock::TOKEN, "validity_days": 100 }),
            json!({ "hosts": ["10.0.0.5"], "cloudflare_token": mock::TOKEN }),
            json!({ "hosts": ["shop.example.com"], "cloudflare_token": "has space" }),
            json!({ "hosts": ["shop.example.com"], "cloudflare_token": "" }),
            json!({ "hosts": ["shop.example.com"], "cloudflare_token": mock::TOKEN, "extra": 1 }),
        ] {
            let (status, err) = n.post("/certificates/origin-ca", body.clone()).await;
            assert_eq!(status, 400, "{body}: {err}");
            assert!(!err.to_string().contains(mock::TOKEN), "{err}");
        }
        let (_, list) = n.get("/certificates").await;
        assert_eq!(list["items"], json!([]));
        assert_eq!(n.st.store.get_secret(LEGACY_TOKEN_SECRET).await, None);
        assert!(!n.audit_text().contains(mock::TOKEN));
    }

    #[tokio::test]
    async fn acme_issues_through_dns01_and_removes_its_records() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let (logs, _guard) = capture();
        let hosts = ["shop.example.com", "*.shop.example.com"];
        let (status, started) = n.post("/certificates/acme", acme_body(&hosts)).await;
        assert_eq!(status, 202, "{started}");
        assert_eq!(started["status"], "pending");
        assert_eq!(started["staging"], false);
        assert!(
            started["note"]
                .as_str()
                .is_some_and(|t| t.contains("cloudflare-token:<certificate id>"))
        );
        let job_id = started["job_id"].as_str().expect("job").to_string();
        let job = n.wait_job(&job_id).await;
        assert_eq!(job["status"], "issued", "{job}");
        assert_eq!(job["kind"], "acme");
        assert_eq!(job["hosts"], json!(hosts));
        let id = job["certificate_id"]
            .as_str()
            .expect("certificate")
            .to_string();

        let (_, cert) = n.get(&format!("/certificates/{id}")).await;
        assert_eq!(cert["sans"], json!(hosts));
        assert_eq!(cert["managed"], "acme");
        assert_eq!(cert["name"], "letsencrypt shop.example.com");
        assert_eq!(cert["renew_at"], job["renew_at"]);
        assert!(
            cert["issuer"]
                .as_str()
                .is_some_and(|i| i.contains(mock::CA_NAME))
        );

        let (created, deleted, left, dirs, csrs, contacts) = mock.with(|s| {
            (
                s.created,
                s.deleted,
                s.records.len(),
                s.directories.clone(),
                s.csrs.clone(),
                s.contacts.clone(),
            )
        });
        assert_eq!((created, deleted, left), (2, 2, 0));
        assert_eq!(dirs, ["acme"]);
        assert_eq!(csrs.len(), 1);
        assert_eq!(csrs[0].sans, hosts);
        assert_eq!(csrs[0].key_len, 65);
        assert_eq!(contacts, [json!([format!("mailto:{EMAIL}")])]);

        assert_eq!(
            n.st.store.get_secret(&token_secret(&id)).await.as_deref(),
            Some(mock::TOKEN)
        );
        let key_file = n.st.cfg.data_dir.join(acme::ACCOUNT_KEY_FILE);
        let mode = std::fs::metadata(key_file)
            .expect("account key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let (_, listing) = n.get("/certificates/acme").await;
        assert_eq!(listing["token_stored"], true);
        assert_eq!(listing["jobs"][0]["id"], job_id);
        let managed = &listing["certificates"][0];
        assert_eq!(managed["id"], id);
        assert_eq!(managed["kind"], "acme");
        assert_eq!(managed["status"], "issued");
        assert_eq!(managed["staging"], false);
        assert_eq!(managed["hosts"], json!(hosts));
        assert!(managed.get("error").is_none());

        let audit = n.audit_text();
        assert!(audit.contains("certificates.acme"), "{audit}");
        assert!(audit.contains("certificates.token_stored"), "{audit}");
        for text in [
            started.to_string(),
            job.to_string(),
            cert.to_string(),
            listing.to_string(),
            audit,
            logs.text(),
        ] {
            assert_secret_free(&text, &n, &id);
        }
    }

    #[tokio::test]
    async fn acme_needs_the_terms_and_clean_input() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let mut no_tos = acme_body(&["shop.example.com"]);
        no_tos["agree_tos"] = json!(false);
        let mut missing_tos = acme_body(&["shop.example.com"]);
        missing_tos
            .as_object_mut()
            .expect("object")
            .remove("agree_tos");
        let mut bad_email = acme_body(&["shop.example.com"]);
        bad_email["email"] = json!("nobody");
        let mut bad_token = acme_body(&["shop.example.com"]);
        bad_token["cloudflare_token"] = json!("has space");
        for body in [
            no_tos,
            missing_tos,
            bad_email,
            bad_token,
            acme_body(&["10.0.0.5"]),
            acme_body(&["localhost"]),
            acme_body(&[]),
        ] {
            let (status, err) = n.post("/certificates/acme", body.clone()).await;
            assert_eq!(status, 400, "{body}: {err}");
            assert!(!err.to_string().contains(mock::TOKEN), "{err}");
        }
        assert!(n.jobs().await.is_empty());
        assert!(mock.with(|s| s.directories.is_empty()));
        assert_eq!(n.st.store.get_secret(LEGACY_TOKEN_SECRET).await, None);
    }

    #[tokio::test]
    async fn a_failed_acme_order_removes_its_records_and_stores_nothing() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        mock.with(|s| s.script.fail_challenge = true);
        let (job, job_id) = issue_acme(&n, acme_body(&["shop.example.com"])).await;
        assert_eq!(job["status"], "failed", "{job}");
        assert!(
            job["error"]
                .as_str()
                .is_some_and(|e| e.contains("could not validate shop.example.com")),
            "{job}"
        );
        assert!(job.get("certificate_id").is_none());
        let (created, deleted, left) = mock.with(|s| (s.created, s.deleted, s.records.len()));
        assert_eq!((created, deleted, left), (1, 1, 0));

        mock.with(|s| {
            s.script.fail_challenge = false;
            s.script.hide_records = true;
        });
        let (job, _) = issue_acme(&n, acme_body(&["shop.example.com"])).await;
        assert_eq!(job["status"], "failed", "{job}");
        assert!(
            job["error"]
                .as_str()
                .is_some_and(|e| e.contains("did not show up")),
            "{job}"
        );
        let (created, deleted, left) = mock.with(|s| (s.created, s.deleted, s.records.len()));
        assert_eq!((created, deleted, left), (2, 2, 0));

        let (_, list) = n.get("/certificates").await;
        assert_eq!(list["items"], json!([]));
        assert_eq!(n.st.store.get_secret(LEGACY_TOKEN_SECRET).await, None);
        let audit = n.audit_text();
        assert!(audit.contains("certificates.acme_failed"), "{audit}");
        assert!(audit.contains(&job_id), "{audit}");
        assert!(!audit.contains(mock::TOKEN));
    }

    #[tokio::test]
    async fn acme_never_follows_a_server_to_a_host_off_the_allowlist() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        mock.with(|s| s.script.foreign_new_order = true);
        let (job, _) = issue_acme(&n, acme_body(&["shop.example.com"])).await;
        assert_eq!(job["status"], "failed", "{job}");
        assert!(
            job["error"]
                .as_str()
                .is_some_and(|e| e.contains("refusing to contact")),
            "{job}"
        );
        assert_eq!(mock.with(|s| s.created), 0);
    }

    #[tokio::test]
    async fn staging_orders_use_the_staging_directory() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let mut body = acme_body(&["shop.example.com"]);
        body["staging"] = json!(true);
        let (job, _) = issue_acme(&n, body).await;
        assert_eq!(job["status"], "issued", "{job}");
        assert_eq!(job["staging"], true);
        assert_eq!(mock.with(|s| s.directories.clone()), ["staging"]);
        let (_, listing) = n.get("/certificates/acme").await;
        assert_eq!(listing["certificates"][0]["staging"], true);
    }

    #[tokio::test]
    async fn issuing_runs_one_at_a_time_and_ten_an_hour() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let origin = json!({ "hosts": ["shop.example.com"], "cloudflare_token": mock::TOKEN });
        let held = n.st.certs.issuing().begin(now()).expect("begin");
        let (status, err) = n.post("/certificates/origin-ca", origin.clone()).await;
        assert_eq!(status, 429, "{err}");
        assert!(
            err["error"]
                .as_str()
                .is_some_and(|e| e.contains("another certificate")),
            "{err}"
        );
        let (status, _) = n
            .post("/certificates/acme", acme_body(&["shop.example.com"]))
            .await;
        assert_eq!(status, 429);
        drop(held);

        for _ in 1..MAX_PER_HOUR {
            let (status, body) = n.post("/certificates/origin-ca", origin.clone()).await;
            assert_eq!(status, 201, "{body}");
        }
        let (status, err) = n.post("/certificates/origin-ca", origin).await;
        assert_eq!(status, 429, "{err}");
        assert!(err["retry_after"].as_u64().is_some_and(|s| s > 0), "{err}");
        assert!(n.jobs().await.is_empty());

        let generate = json!({ "hosts": ["shop.example.com"] });
        assert_eq!(n.post("/certificates/generate", generate).await.0, 201);
    }

    #[tokio::test]
    async fn due_origin_ca_certificates_are_renewed_in_place() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let body = json!({
            "hosts": ["shop.example.com"],
            "cloudflare_token": mock::TOKEN,
            "validity_days": 365,
            "remember_token": true,
        });
        let (status, created) = n.post("/certificates/origin-ca", body).await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_str().expect("id").to_string();
        let not_after = n.not_after(&id);

        assert_eq!(renew_due(&n.st, now()).await, 0);
        assert_eq!(renew_due(&n.st, not_after - 31 * DAY).await, 0);
        assert_eq!(mock.with(|s| s.origin_calls.len()), 1);
        assert_eq!(renew_due(&n.st, not_after - 29 * DAY).await, 1);

        let (_, after) = n.get(&format!("/certificates/{id}")).await;
        assert_eq!(after["id"], id);
        assert_eq!(after["name"], created["name"]);
        assert_eq!(after["created_at"], created["created_at"]);
        assert_eq!(after["managed"], "origin-ca");
        assert_ne!(after["fingerprint_sha256"], created["fingerprint_sha256"]);
        let calls = mock.with(|s| s.origin_calls.clone());
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].validity, 365);
        assert_eq!(calls[1].hostnames, ["shop.example.com"]);

        let jobs = n.jobs().await;
        assert_eq!(jobs[0]["kind"], "renew");
        assert_eq!(jobs[0]["status"], "issued");
        assert_eq!(jobs[0]["certificate_id"], id);
        let audit = n.audit_text();
        assert!(audit.contains("certificates.renew"), "{audit}");
        assert_secret_free(&audit, &n, &id);
        assert_eq!(renew_due(&n.st, now()).await, 0);
    }

    #[tokio::test]
    async fn due_acme_certificates_are_renewed_with_the_same_account() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let (job, _) = issue_acme(&n, acme_body(&["shop.example.com"])).await;
        assert_eq!(job["status"], "issued", "{job}");
        let id = job["certificate_id"].as_str().expect("id").to_string();
        let before = n.get(&format!("/certificates/{id}")).await.1;
        let not_after = n.not_after(&id);

        assert_eq!(renew_due(&n.st, not_after - 10 * DAY).await, 1);
        let after = n.get(&format!("/certificates/{id}")).await.1;
        assert_ne!(after["fingerprint_sha256"], before["fingerprint_sha256"]);
        assert_eq!(after["managed"], "acme");
        let (created, deleted, csrs, contacts) =
            mock.with(|s| (s.created, s.deleted, s.csrs.len(), s.contacts.len()));
        assert_eq!((created, deleted, csrs), (2, 2, 2));
        assert_eq!(contacts, 1);
        assert!(n.audit_text().contains("certificates.renew"));
    }

    #[tokio::test]
    async fn failed_renewals_are_listed_and_back_off() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let body = json!({ "hosts": ["shop.example.com"], "cloudflare_token": mock::TOKEN, "validity_days": 90 });
        let (status, created) = n.post("/certificates/origin-ca", body).await;
        assert_eq!(status, 201, "{created}");
        let id = created["id"].as_str().expect("id").to_string();
        let at = n.not_after(&id) - 29 * DAY;

        assert_eq!(renew_due(&n.st, at).await, 0);
        let jobs = n.jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0]["kind"], "renew");
        assert_eq!(jobs[0]["status"], "failed");
        assert!(
            jobs[0]["error"]
                .as_str()
                .is_some_and(|e| e.contains("no Cloudflare token")),
            "{}",
            jobs[0]
        );
        let (_, listing) = n.get("/certificates/acme").await;
        let managed = &listing["certificates"][0];
        assert!(
            managed["error"]
                .as_str()
                .is_some_and(|e| e.contains("no Cloudflare token"))
        );
        assert!(managed["next_attempt"].is_string());
        assert!(n.audit_text().contains("certificates.renew_failed"));

        assert_eq!(renew_due(&n.st, at + 60).await, 0);
        assert_eq!(n.jobs().await.len(), 1);
        assert_eq!(renew_due(&n.st, at + 3600).await, 0);
        assert_eq!(n.jobs().await.len(), 2);
        assert_eq!(renew_due(&n.st, at + 3600 + 3600).await, 0);
        assert_eq!(n.jobs().await.len(), 2);

        n.st.store
            .put_secret(LEGACY_TOKEN_SECRET, mock::TOKEN)
            .await
            .expect("store the token");
        assert_eq!(renew_due(&n.st, at + 3600 + 7200).await, 1);
        let (_, listing) = n.get("/certificates/acme").await;
        assert!(listing["certificates"][0].get("error").is_none());
        assert_eq!(mock.with(|s| s.origin_calls.len()), 2);
    }

    async fn origin_with(n: &Node, host: &str, token: &str) -> String {
        let body = json!({
            "hosts": [host],
            "cloudflare_token": token,
            "validity_days": 365,
            "remember_token": true,
        });
        let (status, created) = n.post("/certificates/origin-ca", body).await;
        assert_eq!(status, 201, "{created}");
        created["id"].as_str().expect("id").to_string()
    }

    #[tokio::test]
    async fn each_certificate_keeps_and_renews_with_its_own_token() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let first = origin_with(&n, "shop.example.com", mock::TOKEN).await;
        let second = origin_with(&n, "blog.example.com", mock::SERVICE_KEY).await;
        assert_eq!(
            n.st.store
                .get_secret(&token_secret(&first))
                .await
                .as_deref(),
            Some(mock::TOKEN)
        );
        assert_eq!(
            n.st.store
                .get_secret(&token_secret(&second))
                .await
                .as_deref(),
            Some(mock::SERVICE_KEY)
        );
        assert_eq!(n.st.store.get_secret(LEGACY_TOKEN_SECRET).await, None);

        let at = n.not_after(&first).max(n.not_after(&second)) - 29 * DAY;
        assert_eq!(renew_due(&n.st, at).await, 2);
        let auths: Vec<&str> = mock.with(|s| s.origin_calls.iter().map(|c| c.auth).collect());
        assert_eq!(auths.len(), 4);
        assert_eq!(auths.iter().filter(|a| **a == "bearer").count(), 2);
        assert_eq!(auths.iter().filter(|a| **a == "service-key").count(), 2);
    }

    #[tokio::test]
    async fn deleting_a_managed_certificate_removes_only_its_token() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let first = origin_with(&n, "shop.example.com", mock::TOKEN).await;
        let second = origin_with(&n, "blog.example.com", mock::SERVICE_KEY).await;
        let (status, _) = n
            .call(Method::DELETE, &format!("/certificates/{first}"), None)
            .await;
        assert_eq!(status, 204);
        assert_eq!(n.st.store.get_secret(&token_secret(&first)).await, None);
        assert!(
            n.st.store
                .get_secret(&token_secret(&second))
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_certificate_replaced_by_hand_during_a_renewal_is_not_overwritten() {
        let mock = mock::start().await;
        let n = node(&mock).await;
        let id = origin_with(&n, "shop.example.com", mock::TOKEN).await;
        let at = n.not_after(&id) - 29 * DAY;

        let gate = n.st.certs.lock().await;
        let renewal = tokio::spawn({
            let st = Arc::clone(&n.st);
            async move { renew_due(&st, at).await }
        });
        for _ in 0..1000 {
            if mock.with(|s| s.origin_calls.len()) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(mock.with(|s| s.origin_calls.len()), 2);
        let hosts = vec!["shop.example.com".to_string()];
        let by_hand = certs::self_signed(&hosts, 30, now())
            .expect("self-signed")
            .prepare(now(), &hosts, None)
            .expect("prepare");
        let fingerprint = by_hand.info.fingerprint.clone();
        n.st.certs
            .replace(&id, None, &by_hand, &now_rfc3339())
            .expect("replace by hand");
        drop(gate);
        assert_eq!(renewal.await.expect("renewal task"), 0);

        let (_, after) = n.get(&format!("/certificates/{id}")).await;
        assert_eq!(after["fingerprint_sha256"], fingerprint);
        assert!(after.get("managed").is_none());
        let audit = n.audit_text();
        assert!(audit.contains("certificates.renew_skipped"), "{audit}");
        assert!(audit.contains(&format!("id={id}")), "{audit}");
        assert_secret_free(&audit, &n, &id);
    }
}
