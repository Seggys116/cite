//! Routes of conversion between dedicated and shared Postgres and of staged node-to-node transfer (design N and I).
//!
//! `convert` and `retired` live under `/postgres`; `exports` run on the source node and `imports` on the target. The
//! chunk routes carry 8 MiB bodies and a sha256 header; they are never exposed through the dashboard's browser proxy.
//! Audit entries carry names and ids only, never a manifest, a secret value or a password.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequest, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use cite_edge::datawire::{
    ConvertReq, ExportReq, FinishOutcome, FinishReq, ImportReq, JobAccepted, SessionKind,
    SessionStarted, TRANSFER_CHUNK_BYTES, TransferMode,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::handlers::{check_id, find_site, json_ok};
use super::{ApiError, ApiResult, AppState, Principal, parse_json, read_body_limited};
use crate::ConnectorError;
use crate::data::DataService;
use crate::data::service::POLICY_PREFIX;
use crate::data::transfer::{CHUNK_HEADER, MAX_MANIFEST_BYTES, NO_SPACE_PREFIX};

const SMALL_LIMIT: usize = 64 * 1024;
const CHUNK_BODY_LIMIT: usize = TRANSFER_CHUNK_BYTES as usize + 64 * 1024;
const NOT_ENABLED: &str = "data services are not enabled on this node";

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        // conversion on this node
        .route(
            "/api/v1/sites/{id}/data/postgres/convert",
            post(convert_start),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/convert/{sid}",
            get(convert_get),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/convert/{sid}/cutover",
            post(convert_cutover),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/convert/{sid}/abort",
            post(convert_abort),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/retired",
            axum::routing::delete(retired_delete),
        )
        // the source of a transfer
        .route("/api/v1/sites/{id}/data/exports", post(export_create))
        .route(
            "/api/v1/sites/{id}/data/exports/{sid}",
            get(export_get).delete(export_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/exports/{sid}/chunks/{n}",
            get(export_chunk),
        )
        .route(
            "/api/v1/sites/{id}/data/exports/{sid}/manifest",
            get(export_manifest),
        )
        .route(
            "/api/v1/sites/{id}/data/exports/{sid}/finish",
            post(export_finish),
        )
        .route(
            "/api/v1/sites/{id}/data/exports/{sid}/retry",
            post(export_retry),
        )
        // the target of a transfer
        .route("/api/v1/sites/{id}/data/imports", post(import_create))
        .route(
            "/api/v1/sites/{id}/data/imports/{sid}",
            get(import_get).delete(import_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/imports/{sid}/chunks/{n}",
            put(import_chunk),
        )
        .route(
            "/api/v1/sites/{id}/data/imports/{sid}/commit",
            post(import_commit),
        )
        .route(
            "/api/v1/sites/{id}/data/imports/{sid}/finish",
            post(import_finish),
        )
}

// ---- plumbing ----

/// A JSON body of at most `N` bytes; the body is required.
struct Limited<T, const N: usize>(T);

impl<S, T, const N: usize> FromRequest<S> for Limited<T, N>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, N).await?;
        if bytes.is_empty() {
            return Err(ApiError::bad("request body is required"));
        }
        parse_json(&bytes).map(Limited)
    }
}

/// A JSON body of at most 64 KiB that may be left out.
struct OptionalSmall<T>(T);

impl<S, T> FromRequest<S> for OptionalSmall<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Default,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, SMALL_LIMIT).await?;
        if bytes.is_empty() {
            return Ok(OptionalSmall(T::default()));
        }
        parse_json(&bytes).map(OptionalSmall)
    }
}

/// `POST .../commit`; `override` replaces manual env vars of the same name when links are made.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitReq {
    #[serde(default, rename = "override")]
    override_manual: bool,
}

/// Policy refusals answer 422; everything else keeps the standard mapping.
fn api_err(e: ConnectorError) -> ApiError {
    match e {
        ConnectorError::BadRequest(m) if m.starts_with(POLICY_PREFIX) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            m[POLICY_PREFIX.len()..].to_string(),
        ),
        ConnectorError::Conflict(m) if m.starts_with(NO_SPACE_PREFIX) => ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            m[NO_SPACE_PREFIX.len()..].to_string(),
        ),
        other => other.into(),
    }
}

fn d<T>(r: crate::Result<T>) -> ApiResult<T> {
    r.map_err(api_err)
}

fn site_ctx(st: &AppState, id: &str) -> ApiResult<Arc<DataService>> {
    check_id(id)?;
    find_site(st, id)?;
    st.data
        .get()
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, NOT_ENABLED))
}

async fn audit(st: &AppState, p: &Principal, action: &str, detail: String) {
    st.store.audit(&p.actor(), action, &detail).await;
}

fn accepted(job_id: String, redeploy_needed: bool) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(JobAccepted {
            job_id,
            redeploy_needed,
        }),
    )
        .into_response()
}

fn started(status: StatusCode, session: String) -> Response {
    (status, Json(SessionStarted { session })).into_response()
}

fn outcome_name(o: FinishOutcome) -> &'static str {
    match o {
        FinishOutcome::Cutover => "cutover",
        FinishOutcome::Abort => "abort",
    }
}

fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

// ---- conversion ----

async fn convert_start(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Limited(req): Limited<ConvertReq, SMALL_LIMIT>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let sid = d(s.start_convert(&p.actor(), &id, req.to, req.freeze).await)?;
    audit(
        &st,
        &p,
        "data.convert.start",
        format!("site={id} to={} session={sid}", req.to.as_str()),
    )
    .await;
    Ok(started(StatusCode::ACCEPTED, sid))
}

async fn convert_get(
    State(st): State<AppState>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    json_ok(&d(s.get_session(&id, &sid, SessionKind::Convert).await)?)
}

async fn convert_cutover(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let session = d(s.cutover_convert(&p.actor(), &id, &sid).await)?;
    audit(
        &st,
        &p,
        "data.convert.cutover",
        format!("site={id} session={sid}"),
    )
    .await;
    json_ok(&session)
}

async fn convert_abort(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let session = d(s.abort_convert(&p.actor(), &id, &sid).await)?;
    audit(
        &st,
        &p,
        "data.convert.abort",
        format!("site={id} session={sid}"),
    )
    .await;
    json_ok(&session)
}

async fn retired_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let site = find_site(&st, &id)?;
    if site
        .data
        .postgres
        .as_ref()
        .and_then(|pg| pg.retired.as_ref())
        .is_none()
    {
        return Err(ConnectorError::Conflict("this site has no retired database".into()).into());
    }
    d(s.require_job_capacity())?;
    let (svc, actor, sid) = (Arc::clone(&s), p.actor(), id.clone());
    let job = s.spawn_task("retired", Some(&id), move |_ctx| async move {
        svc.do_delete_retired(&actor, &sid).await
    });
    audit(
        &st,
        &p,
        "data.postgres.retired.delete",
        format!("site={id}"),
    )
    .await;
    Ok(accepted(job, false))
}

// ---- exports ----

async fn export_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Limited(req): Limited<ExportReq, SMALL_LIMIT>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    if req.mode == TransferMode::Live {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "live transfer is not available in this release",
        ));
    }
    let database = req.database.clone();
    let freeze = req.freeze;
    let sid = d(s.start_export(&p.actor(), &id, req).await)?;
    audit(
        &st,
        &p,
        "data.export.create",
        format!(
            "site={id} database={database} freeze={} session={sid}",
            freeze_name(freeze)
        ),
    )
    .await;
    Ok(started(StatusCode::ACCEPTED, sid))
}

fn freeze_name(f: cite_edge::datawire::Freeze) -> &'static str {
    match f {
        cite_edge::datawire::Freeze::Maintenance => "maintenance",
        cite_edge::datawire::Freeze::ReadOnly => "read_only",
        cite_edge::datawire::Freeze::None => "none",
    }
}

async fn export_get(
    State(st): State<AppState>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    json_ok(&d(s.get_session(&id, &sid, SessionKind::Export).await)?)
}

async fn export_chunk(
    State(st): State<AppState>,
    Path((id, sid, n)): Path<(String, String, u64)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let (bytes, sha) = d(s.export_chunk(&id, &sid, n).await)?;
    let sha = HeaderValue::from_str(&sha)
        .map_err(|_| ConnectorError::Internal("a chunk hash is not a header value".into()))?;
    let mut res = Response::new(Body::from(bytes));
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(CHUNK_HEADER, sha);
    Ok(no_store(res))
}

async fn export_manifest(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let manifest = d(s.export_manifest(&id, &sid).await)?;
    audit(
        &st,
        &p,
        "data.export.manifest",
        format!(
            "site={id} session={sid} secrets={}",
            manifest.generated_secrets.len()
        ),
    )
    .await;
    Ok(no_store(json_ok(&manifest)?))
}

async fn export_finish(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
    Limited(req): Limited<FinishReq, SMALL_LIMIT>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let session = d(s.finish_export(&p.actor(), &id, &sid, req.outcome).await)?;
    audit(
        &st,
        &p,
        "data.export.finish",
        format!(
            "site={id} session={sid} outcome={}",
            outcome_name(req.outcome)
        ),
    )
    .await;
    json_ok(&session)
}

async fn export_retry(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    d(s.retry_export(&p.actor(), &id, &sid).await)?;
    audit(
        &st,
        &p,
        "data.export.retry",
        format!("site={id} session={sid}"),
    )
    .await;
    Ok(started(StatusCode::ACCEPTED, sid))
}

async fn export_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    d(s.delete_session(&id, &sid, SessionKind::Export).await)?;
    audit(
        &st,
        &p,
        "data.export.delete",
        format!("site={id} session={sid}"),
    )
    .await;
    json_ok(&serde_json::json!({ "ok": true }))
}

// ---- imports ----

async fn import_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Limited(req): Limited<ImportReq, MAX_MANIFEST_BYTES>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let replace = req.replace;
    let sid = d(s.start_import(&p.actor(), &id, req).await)?;
    let database = d(s.get_session(&id, &sid, SessionKind::Import).await)?.database;
    audit(
        &st,
        &p,
        "data.import.create",
        format!("site={id} database={database} replace={replace} session={sid}"),
    )
    .await;
    Ok(started(StatusCode::CREATED, sid))
}

async fn import_get(
    State(st): State<AppState>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    json_ok(&d(s.get_session(&id, &sid, SessionKind::Import).await)?)
}

async fn import_chunk(
    State(st): State<AppState>,
    Path((id, sid, n)): Path<(String, String, u64)>,
    headers: HeaderMap,
    req: Request,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let sha = headers
        .get(CHUNK_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad(format!("{CHUNK_HEADER} is required")))?
        .to_string();
    // The permit comes first so a flood of uploads cannot pile 8 MiB bodies up in memory.
    let _permit = d(s.chunk_permit().await)?;
    let body = read_body_limited(req, CHUNK_BODY_LIMIT).await?;
    // A first upload and an identical repeat both answer 204; a different body for a received chunk answers 409.
    d(s.put_chunk(&id, &sid, n, &sha, &body).await)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn import_commit(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
    OptionalSmall(req): OptionalSmall<CommitReq>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let job = d(s
        .start_commit(&p.actor(), &id, &sid, req.override_manual)
        .await)?;
    audit(
        &st,
        &p,
        "data.import.commit",
        format!("site={id} session={sid} override={}", req.override_manual),
    )
    .await;
    Ok(accepted(job, true))
}

async fn import_finish(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
    Limited(req): Limited<FinishReq, SMALL_LIMIT>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    let session = d(s.finish_import(&p.actor(), &id, &sid, req.outcome).await)?;
    audit(
        &st,
        &p,
        "data.import.finish",
        format!(
            "site={id} session={sid} outcome={}",
            outcome_name(req.outcome)
        ),
    )
    .await;
    json_ok(&session)
}

async fn import_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let s = site_ctx(&st, &id)?;
    d(s.delete_session(&id, &sid, SessionKind::Import).await)?;
    audit(
        &st,
        &p,
        "data.import.delete",
        format!("site={id} session={sid}"),
    )
    .await;
    json_ok(&serde_json::json!({ "ok": true }))
}
