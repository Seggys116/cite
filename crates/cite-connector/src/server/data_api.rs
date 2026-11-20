//! Site data routes: managed and external Postgres, S3 attachments, generated secrets, env links, backups, node-level
//! backup targets and the shared instance. Responses carry names, levels and limits, never a password, URL or key.
//! Audit entries carry names and ids only.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequest, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use cite_edge::datamodel::{BackupPolicy, LinkTarget};
use cite_edge::datawire::{
    BackupCreateReq, BackupCreated, BackupPatchReq, DataNodeView, DatabaseCreateReq, DeleteFrom,
    ExternalPutReq, JobAccepted, LinksReq, PresetRequest, PruneResult, PushReq, RestoreReq,
    RestoreStarted, S3PutReq, SecretCreateReq, SharedReq, TargetReq, UserCreateReq, UserPatchReq,
};
use cite_edge::model::Site;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::handlers::{check_id, find_site, json_ok};
use super::{ApiError, ApiResult, AppState, Params, Principal, parse_json, read_body_limited};
use crate::ConnectorError;
use crate::data::DataService;
use crate::data::jobs::{DbRef, stream_plaintext};
use crate::data::service::{LinkError, POLICY_PREFIX};
use crate::data::shared::merge_shared_request;
use crate::data::users::{check_create_user, check_delete_user, check_patch_user};

const BODY_LIMIT: usize = 64 * 1024;
const NOT_ENABLED: &str = "data services are not enabled on this node";

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        // node level
        .route("/api/v1/data", get(node))
        .route("/api/v1/data/jobs/{job}", get(job))
        .route(
            "/api/v1/data/targets",
            get(list_targets).post(create_target),
        )
        .route(
            "/api/v1/data/targets/{tid}",
            put(update_target).delete(delete_target),
        )
        .route("/api/v1/data/targets/{tid}/test", post(test_target))
        .route(
            "/api/v1/data/shared",
            get(shared_get).put(shared_put).delete(shared_delete),
        )
        .route("/api/v1/data/shared/restart", post(shared_restart))
        .route(
            "/api/v1/data/shared/backups",
            get(shared_backups).post(shared_backup_create),
        )
        .route(
            "/api/v1/data/shared/backups/{bid}/download",
            get(shared_backup_download),
        )
        .route(
            "/api/v1/data/shared/backups/{bid}",
            delete(shared_backup_delete),
        )
        .route("/api/v1/data/orphans", get(orphans))
        .route("/api/v1/data/orphans/{id}", delete(orphan_purge))
        // one site
        .route("/api/v1/sites/{id}/data", get(site_data))
        .route(
            "/api/v1/sites/{id}/data/postgres",
            put(postgres_put).delete(postgres_delete),
        )
        .route("/api/v1/sites/{id}/data/postgres/policy", put(policy_put))
        .route(
            "/api/v1/sites/{id}/data/postgres/databases",
            post(database_create),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/databases/{db}",
            delete(database_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/databases/{db}/users",
            post(user_create),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/databases/{db}/users/{user}",
            axum::routing::patch(user_patch).delete(user_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/postgres/databases/{db}/users/{user}/rotate",
            post(user_rotate),
        )
        .route(
            "/api/v1/sites/{id}/data/external/{name}",
            put(external_put).delete(external_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/s3/{name}",
            put(s3_put).delete(s3_delete),
        )
        .route("/api/v1/sites/{id}/data/secrets", post(secret_create))
        .route(
            "/api/v1/sites/{id}/data/secrets/{name}/rotate",
            post(secret_rotate),
        )
        .route(
            "/api/v1/sites/{id}/data/secrets/{name}",
            delete(secret_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/links",
            get(links_list).post(links_create),
        )
        .route("/api/v1/sites/{id}/data/links/preset", post(links_preset))
        .route(
            "/api/v1/sites/{id}/data/links/{target}/{var}",
            delete(link_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/backups",
            get(backups_list).post(backup_create),
        )
        .route(
            "/api/v1/sites/{id}/data/backups/{bid}",
            get(backup_get).patch(backup_patch).delete(backup_delete),
        )
        .route(
            "/api/v1/sites/{id}/data/backups/{bid}/download",
            get(backup_download),
        )
        .route(
            "/api/v1/sites/{id}/data/backups/{bid}/restore",
            post(backup_restore),
        )
        .route(
            "/api/v1/sites/{id}/data/backups/{bid}/push",
            post(backup_push),
        )
        .route("/api/v1/sites/{id}/data/prune-preview", get(prune_preview))
        .route("/api/v1/sites/{id}/data/prune", post(prune))
}

// ---- plumbing ----

/// A JSON body of at most 64 KiB; the body is required.
struct Small<T>(T);

impl<S, T> FromRequest<S> for Small<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, BODY_LIMIT).await?;
        if bytes.is_empty() {
            return Err(ApiError::bad("request body is required"));
        }
        parse_json(&bytes).map(Small)
    }
}

/// A JSON body of at most 64 KiB that may be left out.
struct MaybeSmall<T>(T);

impl<S, T> FromRequest<S> for MaybeSmall<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Default,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, BODY_LIMIT).await?;
        if bytes.is_empty() {
            return Ok(MaybeSmall(T::default()));
        }
        parse_json(&bytes).map(MaybeSmall)
    }
}

/// Policy refusals answer 422; everything else keeps the standard mapping.
fn api_err(e: ConnectorError) -> ApiError {
    match e {
        ConnectorError::BadRequest(m) if m.starts_with(POLICY_PREFIX) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            m[POLICY_PREFIX.len()..].to_string(),
        ),
        other => other.into(),
    }
}

fn d<T>(r: crate::Result<T>) -> ApiResult<T> {
    r.map_err(api_err)
}

fn svc(st: &AppState) -> ApiResult<Arc<DataService>> {
    st.data
        .get()
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, NOT_ENABLED))
}

fn site_ctx(st: &AppState, id: &str) -> ApiResult<(Arc<DataService>, Site)> {
    check_id(id)?;
    let site = find_site(st, id)?;
    Ok((svc(st)?, site))
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

fn flag(params: &Params, name: &str) -> ApiResult<bool> {
    match params.0.get(name).map(String::as_str) {
        None => Ok(false),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(ApiError::bad(format!("{name} must be true or false"))),
    }
}

fn ok_json() -> ApiResult<Response> {
    json_ok(&json!({ "ok": true }))
}

async fn audit(st: &AppState, p: &Principal, action: &str, detail: String) {
    st.store.audit(&p.actor(), action, &detail).await;
}

fn check_name(what: &str, name: &str) -> ApiResult<()> {
    if cite_edge::datamodel::is_resource_name(name) {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "{what} names must match ^[a-z][a-z0-9-]{{0,30}}$"
        )))
    }
}

fn check_ident(what: &str, name: &str) -> ApiResult<()> {
    if cite_edge::datamodel::is_pg_ident(name) {
        Ok(())
    } else {
        Err(ApiError::bad(format!("invalid {what} name")))
    }
}

// ---- node level ----

async fn node(State(st): State<AppState>) -> ApiResult<Response> {
    match st.data.get() {
        Some(s) => json_ok(&s.node_view().await),
        None => json_ok(&DataNodeView::default()),
    }
}

async fn job(State(st): State<AppState>, Path(job): Path<String>) -> ApiResult<Response> {
    let s = svc(&st)?;
    let view = s
        .job(&job)
        .ok_or_else(|| ConnectorError::NotFound("job not found".into()))?;
    json_ok(&view)
}

async fn list_targets(State(st): State<AppState>) -> ApiResult<Response> {
    let s = svc(&st)?;
    let targets = d(s.list_targets().await)?;
    json_ok(&targets.iter().map(|t| t.view()).collect::<Vec<_>>())
}

async fn create_target(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Small(req): Small<TargetReq>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let view = d(s.create_target(req).await)?;
    audit(
        &st,
        &p,
        "data.target.create",
        format!("target={} name={}", view.id, view.name),
    )
    .await;
    let mut res = json_ok(&view)?;
    *res.status_mut() = StatusCode::CREATED;
    Ok(res)
}

async fn update_target(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(tid): Path<String>,
    Small(req): Small<TargetReq>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let view = d(s.update_target(&tid, req).await)?;
    audit(&st, &p, "data.target.update", format!("target={tid}")).await;
    json_ok(&view)
}

async fn delete_target(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(tid): Path<String>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    d(s.delete_target(&tid).await)?;
    audit(&st, &p, "data.target.delete", format!("target={tid}")).await;
    ok_json()
}

async fn test_target(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(tid): Path<String>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let result = d(s.test_target(&tid).await)?;
    audit(
        &st,
        &p,
        "data.target.test",
        format!("target={tid} ok={}", result.ok),
    )
    .await;
    json_ok(&result)
}

async fn shared_get(State(st): State<AppState>) -> ApiResult<Response> {
    let s = svc(&st)?;
    json_ok(&d(s.shared_view().await)?)
}

async fn shared_put(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Small(req): Small<SharedReq>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let current = d(s.shared_settings().await)?;
    d(merge_shared_request(&current, &req))?;
    d(s.require_job_capacity())?;
    let action = if current.enabled {
        "data.shared.update"
    } else {
        "data.shared.enable"
    };
    let (svc2, req2) = (Arc::clone(&s), req);
    let id = s.spawn_task("shared", None, move |ctx| async move {
        svc2.do_shared_put(&ctx, req2).await
    });
    audit(&st, &p, action, "instance=shared".into()).await;
    Ok(accepted(id, false))
}

async fn shared_restart(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let svc2 = Arc::clone(&s);
    let id = s.spawn_task("shared", None, move |ctx| async move {
        svc2.do_shared_restart(&ctx).await
    });
    audit(&st, &p, "data.shared.restart", "instance=shared".into()).await;
    Ok(accepted(id, false))
}

async fn shared_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    params: Params,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let (force, purge) = (flag(&params, "force")?, flag(&params, "purge")?);
    d(s.check_shared_delete(force, purge))?;
    let (svc2, actor) = (Arc::clone(&s), p.actor());
    let id = s.spawn_task("shared", None, move |ctx| async move {
        svc2.do_shared_delete(&ctx, &actor, force, purge).await
    });
    audit(
        &st,
        &p,
        "data.shared.delete",
        format!("force={force} purge={purge}"),
    )
    .await;
    Ok(accepted(id, false))
}

async fn shared_backups(State(st): State<AppState>) -> ApiResult<Response> {
    let s = svc(&st)?;
    json_ok(&d(s.list_instance_backups().await)?)
}

async fn shared_backup_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let id = d(s.start_instance_backup())?;
    audit(&st, &p, "data.shared.backup", "instance=shared".into()).await;
    Ok(accepted(id, false))
}

async fn shared_backup_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(bid): Path<String>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    d(s.delete_instance_backup(&bid).await)?;
    audit(
        &st,
        &p,
        "data.shared.backup.delete",
        format!("backup={bid}"),
    )
    .await;
    ok_json()
}

async fn shared_backup_download(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(bid): Path<String>,
) -> ApiResult<Response> {
    let s = svc(&st)?;
    let permit = Arc::clone(&st.exports).try_acquire_owned().map_err(|_| {
        ConnectorError::TooManyRequests("too many downloads are running; try again shortly".into())
    })?;
    audit(
        &st,
        &p,
        "data.shared.backup.download",
        format!("backup={bid}"),
    )
    .await;
    let (len, rx) = d(s.instance_backup_tar(&bid, permit).await)?;
    let mut res = Response::new(body_from(rx));
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"shared-{bid}.tar\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(res)
}

async fn orphans(State(st): State<AppState>) -> ApiResult<Response> {
    let s = svc(&st)?;
    json_ok(&d(s.orphans().await)?)
}

async fn orphan_purge(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    let s = svc(&st)?;
    if find_site(&st, &id).is_ok() {
        return Err(ConnectorError::Conflict(format!(
            "site {id} still exists; delete it with purge_data instead"
        ))
        .into());
    }
    let (svc2, sid) = (Arc::clone(&s), id.clone());
    let job = s.spawn_task("orphan-purge", Some(&id), move |_ctx| async move {
        svc2.purge_orphan(&sid).await
    });
    audit(&st, &p, "data.orphan.purge", format!("site={id}")).await;
    Ok(accepted(job, false))
}

// ---- one site: overview and Postgres ----

async fn site_data(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    json_ok(&s.site_view(&site).await)
}

async fn postgres_put(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Small(req): Small<cite_edge::datawire::PgEnableReq>,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    d(s.check_enable(&site, &req))?;
    if site.data.postgres.is_none() && req.mode == cite_edge::datamodel::PgMode::Shared {
        d(s.check_shared_ready().await)?;
    }
    d(s.require_job_capacity())?;
    let action = if site.data.postgres.is_some() {
        "data.postgres.update"
    } else {
        "data.postgres.enable"
    };
    let detail = format!("site={id} mode={}", req.mode.as_str());
    let (svc2, actor, sid) = (Arc::clone(&s), p.actor(), id.clone());
    let job = s.spawn_task("postgres", Some(&id), move |ctx| async move {
        svc2.do_enable_postgres(&ctx, &actor, &sid, req).await
    });
    audit(&st, &p, action, detail).await;
    Ok(accepted(job, false))
}

async fn postgres_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    let purge = flag(&params, "purge")?;
    if site.data.postgres.is_none() {
        return Err(ApiError::bad(
            "managed Postgres is not enabled for this site",
        ));
    }
    let (svc2, actor, sid) = (Arc::clone(&s), p.actor(), id.clone());
    let had_links = site
        .data
        .links
        .iter()
        .any(|l| matches!(l.source, cite_edge::datamodel::LinkSource::Postgres { .. }));
    let job = s.spawn_task("postgres", Some(&id), move |ctx| async move {
        svc2.do_disable_postgres(&ctx, &actor, &sid, purge).await
    });
    let action = if purge {
        "data.postgres.purge"
    } else {
        "data.postgres.disable"
    };
    audit(&st, &p, action, format!("site={id} purge={purge}")).await;
    Ok(accepted(job, had_links))
}

async fn policy_put(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Small(policy): Small<BackupPolicy>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let view = d(s.put_policy(&p.actor(), &id, policy).await)?;
    json_ok(&view)
}

async fn database_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Small(req): Small<DatabaseCreateReq>,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    d(s.check_create_database(&site, &req.name))?;
    let (svc2, actor, sid, name) = (Arc::clone(&s), p.actor(), id.clone(), req.name.clone());
    let job = s.spawn_task("database", Some(&id), move |ctx| async move {
        svc2.do_create_database(&ctx, &actor, &sid, &name).await
    });
    audit(
        &st,
        &p,
        "data.database.create",
        format!("site={id} db={}", req.name),
    )
    .await;
    Ok(accepted(job, false))
}

async fn database_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, db)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    check_ident("database", &db)?;
    let purge = flag(&params, "purge")?;
    d(s.check_delete_database(&site, &db, purge))?;
    let (svc2, actor, sid, name) = (Arc::clone(&s), p.actor(), id.clone(), db.clone());
    let job = s.spawn_task("database", Some(&id), move |ctx| async move {
        svc2.do_delete_database(&ctx, &actor, &sid, &name, purge)
            .await
    });
    audit(
        &st,
        &p,
        "data.database.delete",
        format!("site={id} db={db} purge={purge}"),
    )
    .await;
    Ok(accepted(job, true))
}

async fn user_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, db)): Path<(String, String)>,
    Small(req): Small<UserCreateReq>,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    check_ident("database", &db)?;
    check_ident("user", &req.name)?;
    d(check_create_user(&site, &db, &req))?;
    let detail = format!("site={id} db={db} user={}", req.name);
    let (svc2, actor, sid, name) = (Arc::clone(&s), p.actor(), id.clone(), db.clone());
    let job = s.spawn_task("user", Some(&id), move |ctx| async move {
        svc2.do_create_user(&ctx, &actor, &sid, &name, req).await
    });
    audit(&st, &p, "data.user.create", detail).await;
    Ok(accepted(job, false))
}

async fn user_patch(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, db, user)): Path<(String, String, String)>,
    Small(req): Small<UserPatchReq>,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    check_ident("database", &db)?;
    check_ident("user", &user)?;
    d(check_patch_user(&site, &db, &user, &req))?;
    let only_flag = UserPatchReq {
        disabled: req.disabled,
        ..UserPatchReq::default()
    } == req;
    let action = match req.disabled {
        Some(true) if only_flag => "data.user.disable",
        Some(false) if only_flag => "data.user.enable",
        _ => "data.user.update",
    };
    let detail = format!("site={id} db={db} user={user}");
    let (svc2, actor, sid, dbn, un) = (
        Arc::clone(&s),
        p.actor(),
        id.clone(),
        db.clone(),
        user.clone(),
    );
    let job = s.spawn_task("user", Some(&id), move |ctx| async move {
        svc2.do_patch_user(&ctx, &actor, &sid, &dbn, &un, req).await
    });
    audit(&st, &p, action, detail).await;
    Ok(accepted(job, false))
}

async fn user_rotate(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, db, user)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    check_ident("database", &db)?;
    check_ident("user", &user)?;
    d(s.check_rotate(&site, &db, &user))?;
    d(s.ensure_not_rotating(&id, &db, &user).await)?;
    let redeploy = s.rotation_needs_deploy(&site, &db, &user);
    let (svc2, actor, sid, dbn, un) = (
        Arc::clone(&s),
        p.actor(),
        id.clone(),
        db.clone(),
        user.clone(),
    );
    let job = s.spawn_task("user", Some(&id), move |ctx| async move {
        svc2.do_rotate_user(&ctx, &actor, &sid, &dbn, &un).await
    });
    audit(
        &st,
        &p,
        "data.user.rotate",
        format!("site={id} db={db} user={user}"),
    )
    .await;
    Ok(accepted(job, redeploy))
}

async fn user_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, db, user)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    check_ident("database", &db)?;
    check_ident("user", &user)?;
    d(check_delete_user(&site, &db, &user))?;
    let (svc2, actor, sid, dbn, un) = (
        Arc::clone(&s),
        p.actor(),
        id.clone(),
        db.clone(),
        user.clone(),
    );
    let job = s.spawn_task("user", Some(&id), move |ctx| async move {
        svc2.do_delete_user(&ctx, &actor, &sid, &dbn, &un).await
    });
    audit(
        &st,
        &p,
        "data.user.delete",
        format!("site={id} db={db} user={user}"),
    )
    .await;
    Ok(accepted(job, false))
}

// ---- external services and secrets ----

async fn external_put(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
    Small(req): Small<ExternalPutReq>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    check_name("external database", &name)?;
    let view = d(s.put_external(&p.actor(), &id, &name, &req.url).await)?;
    audit(
        &st,
        &p,
        "data.external.put",
        format!("site={id} external={name}"),
    )
    .await;
    json_ok(&view)
}

async fn external_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    check_name("external database", &name)?;
    d(s.delete_external(&p.actor(), &id, &name).await)?;
    audit(
        &st,
        &p,
        "data.external.delete",
        format!("site={id} external={name}"),
    )
    .await;
    ok_json()
}

async fn s3_put(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
    Small(req): Small<S3PutReq>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    check_name("s3 attachment", &name)?;
    let view = d(s.put_s3(&p.actor(), &id, &name, req).await)?;
    audit(&st, &p, "data.s3.put", format!("site={id} s3={name}")).await;
    json_ok(&view)
}

async fn s3_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    check_name("s3 attachment", &name)?;
    d(s.delete_s3(&p.actor(), &id, &name).await)?;
    audit(&st, &p, "data.s3.delete", format!("site={id} s3={name}")).await;
    ok_json()
}

async fn secret_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Small(req): Small<SecretCreateReq>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let name = req.name.clone();
    let view = d(s.create_secret(&p.actor(), &id, req).await)?;
    audit(
        &st,
        &p,
        "data.secret.create",
        format!("site={id} secret={name}"),
    )
    .await;
    let mut res = json_ok(&view)?;
    *res.status_mut() = StatusCode::CREATED;
    Ok(res)
}

async fn secret_rotate(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    check_name("secret", &name)?;
    let view = d(s.rotate_secret(&p.actor(), &id, &name).await)?;
    audit(
        &st,
        &p,
        "data.secret.rotate",
        format!("site={id} secret={name}"),
    )
    .await;
    json_ok(&view)
}

async fn secret_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    check_name("secret", &name)?;
    d(s.delete_secret(&p.actor(), &id, &name).await)?;
    audit(
        &st,
        &p,
        "data.secret.delete",
        format!("site={id} secret={name}"),
    )
    .await;
    ok_json()
}

// ---- links ----

fn link_error(e: LinkError) -> ApiError {
    match e {
        LinkError::Other(e) => api_err(e),
        LinkError::Conflicts(list) => ApiError::conflicts(
            "some variables are already set by hand or by other links; resend with override to replace manual ones",
            serde_json::to_value(&list).unwrap_or(Value::Null),
        ),
    }
}

async fn links_list(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    json_ok(&s.link_views(&site).await)
}

async fn links_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Small(req): Small<LinksReq>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let vars: Vec<String> = req.links.iter().map(|l| l.var.clone()).collect();
    let views = s
        .create_links(&p.actor(), &id, req)
        .await
        .map_err(link_error)?;
    audit(
        &st,
        &p,
        "data.link.create",
        format!("site={id} vars={}", vars.join(",")),
    )
    .await;
    json_ok(&views)
}

async fn links_preset(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Small(req): Small<PresetRequest>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let preset = req.preset.as_str();
    let (resp, job) = s
        .preset(&p.actor(), &id, req.clone())
        .await
        .map_err(link_error)?;
    audit(
        &st,
        &p,
        "data.link.preset",
        format!("site={id} preset={preset}"),
    )
    .await;
    let status = if job {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(resp)).into_response())
}

async fn link_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, target, var)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let target = match target.as_str() {
        "runtime" => LinkTarget::Runtime,
        "build" => LinkTarget::Build,
        _ => return Err(ApiError::bad("the target is runtime or build")),
    };
    d(s.delete_link(&p.actor(), &id, target, &var).await)?;
    audit(
        &st,
        &p,
        "data.link.delete",
        format!("site={id} var={var} target={}", target.as_str()),
    )
    .await;
    ok_json()
}

// ---- backups ----

async fn backups_list(
    State(st): State<AppState>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let wanted = match params.0.get("database") {
        Some(k) => Some(d(DbRef::parse(k))?.key()),
        None => None,
    };
    let cat = d(s.read_catalog(&id).await)?;
    let mut out: Vec<_> = cat
        .databases
        .iter()
        .filter(|(k, _)| wanted.as_ref().is_none_or(|w| w == *k))
        .flat_map(|(_, db)| db.backups.iter().cloned())
        .collect();
    out.sort_by(|a, b| (&b.created_at, b.version).cmp(&(&a.created_at, a.version)));
    json_ok(&out)
}

async fn backup_create(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Small(req): Small<BackupCreateReq>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let key = d(DbRef::parse(&req.database))?.key();
    let (job, backup_id) = d(s
        .start_backup(&p.actor(), &id, &key, req.label, req.push_s3)
        .await)?;
    audit(
        &st,
        &p,
        "data.backup.create",
        format!("site={id} database={key} backup={backup_id}"),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(BackupCreated {
            job_id: job,
            backup_id,
        }),
    )
        .into_response())
}

async fn backup_get(
    State(st): State<AppState>,
    Path((id, bid)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    json_ok(&d(s.find_backup(&id, &bid).await)?)
}

async fn backup_patch(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, bid)): Path<(String, String)>,
    Small(req): Small<BackupPatchReq>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    if req.label.is_none() && req.pinned.is_none() {
        return Err(ApiError::bad("the patch changes nothing"));
    }
    let rec = d(s.find_backup(&id, &bid).await)?;
    let (label, pinned) = (req.label.is_some(), req.pinned);
    let out = d(s.patch_backup(&id, &rec.database, &bid, req).await)?;
    if label {
        audit(
            &st,
            &p,
            "data.backup.label",
            format!("site={id} backup={bid}"),
        )
        .await;
    }
    match pinned {
        Some(true) => {
            audit(
                &st,
                &p,
                "data.backup.pin",
                format!("site={id} backup={bid}"),
            )
            .await
        }
        Some(false) => {
            audit(
                &st,
                &p,
                "data.backup.unpin",
                format!("site={id} backup={bid}"),
            )
            .await
        }
        None => {}
    }
    json_ok(&out)
}

async fn backup_delete(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, bid)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let from = match params.0.get("from") {
        None => DeleteFrom::All,
        Some(t) => {
            DeleteFrom::parse(t).ok_or_else(|| ApiError::bad("from must be local, s3 or all"))?
        }
    };
    d(s.delete_backup(&id, &bid, from).await)?;
    audit(
        &st,
        &p,
        "data.backup.delete",
        format!("site={id} backup={bid} from={from:?}"),
    )
    .await;
    ok_json()
}

/// One `Range: bytes=a-b` request against a body of `total` bytes: `Ok(None)` for no range, `Err` for 416.
pub(super) fn parse_range(value: Option<&str>, total: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(value) = value else { return Ok(None) };
    let spec = value.trim().strip_prefix("bytes=").ok_or(())?;
    if spec.contains(',') || total == 0 {
        return Err(());
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    let last = total - 1;
    let (first, end) = match (a.trim(), b.trim()) {
        ("", n) => {
            let n: u64 = n.parse().map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            (total.saturating_sub(n), last)
        }
        (a, "") => (a.parse().map_err(|_| ())?, last),
        (a, b) => (
            a.parse().map_err(|_| ())?,
            b.parse::<u64>().map_err(|_| ())?.min(last),
        ),
    };
    if first > end || first >= total {
        return Err(());
    }
    Ok(Some((first, end)))
}

fn body_from(rx: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>) -> Body {
    Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

async fn backup_download(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, bid)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let permit = Arc::clone(&st.exports).try_acquire_owned().map_err(|_| {
        ConnectorError::TooManyRequests("too many downloads are running; try again shortly".into())
    })?;
    audit(
        &st,
        &p,
        "data.backup.download",
        format!("site={id} backup={bid}"),
    )
    .await;
    let plan = d(s.prepare_download(&id, &bid).await)?;
    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    let range = match parse_range(range_header, plan.total) {
        Ok(r) => r,
        Err(()) => {
            if let Some(c) = &plan.cleanup {
                let _ = std::fs::remove_file(c);
            }
            let mut res = ApiError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "the requested range cannot be served",
            )
            .into_response();
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{}", plan.total)) {
                res.headers_mut().insert(header::CONTENT_RANGE, v);
            }
            return Ok(res);
        }
    };
    let total = plan.total;
    let (first, last, partial) = match range {
        Some((a, b)) => (a, b, true),
        None => (0, total.saturating_sub(1), false),
    };
    let len = if total == 0 { 0 } else { last - first + 1 };
    let sha = HeaderValue::from_str(&plan.record.sha256)
        .map_err(|_| ConnectorError::Internal("the backup has no usable checksum".into()))?;
    let safe: String = format!(
        "{id}-{}-v{}",
        plan.record.database.replace(':', "-"),
        plan.record.version
    )
    .chars()
    .map(|c| {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            c
        } else {
            '_'
        }
    })
    .collect();
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{safe}.dump\""))
        .map_err(|_| ConnectorError::Internal("the download name is not usable".into()))?;
    let rx = if total == 0 {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        if let Some(c) = &plan.cleanup {
            let _ = std::fs::remove_file(c);
        }
        drop(permit);
        rx
    } else {
        stream_plaintext(plan, first, last, permit)
    };
    let mut res = Response::new(body_from(rx));
    if partial {
        *res.status_mut() = StatusCode::PARTIAL_CONTENT;
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {first}-{last}/{total}")) {
            res.headers_mut().insert(header::CONTENT_RANGE, v);
        }
    }
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(header::CONTENT_DISPOSITION, disposition);
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert("x-backup-sha256", sha);
    Ok(res)
}

async fn backup_restore(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, bid)): Path<(String, String)>,
    Small(req): Small<RestoreReq>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let (job, pre) = d(s.begin_restore(&p.actor(), &id, &bid, req).await)?;
    audit(
        &st,
        &p,
        "data.backup.restore",
        format!("site={id} backup={bid} pre_restore={pre}"),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(RestoreStarted {
            job_id: job,
            pre_restore_backup_id: pre,
        }),
    )
        .into_response())
}

async fn backup_push(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, bid)): Path<(String, String)>,
    MaybeSmall(req): MaybeSmall<PushReq>,
) -> ApiResult<Response> {
    let (s, site) = site_ctx(&st, &id)?;
    let rec = d(s.find_backup(&id, &bid).await)?;
    if rec.local.is_none() {
        return Err(ConnectorError::Conflict("the backup has no local copy to push".into()).into());
    }
    d(s.push_target(&site, req.target.as_deref()))?;
    d(s.require_job_capacity())?;
    let (svc2, sid, key, backup, target) = (
        Arc::clone(&s),
        id.clone(),
        rec.database.clone(),
        bid.clone(),
        req.target.clone(),
    );
    let job = s.spawn_task("push", Some(&id), move |_ctx| async move {
        svc2.push_s3(&sid, &key, &backup, target.as_deref()).await?;
        Ok(Value::Null)
    });
    audit(
        &st,
        &p,
        "data.backup.push",
        format!("site={id} backup={bid}"),
    )
    .await;
    Ok(accepted(job, false))
}

async fn prune_preview(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    json_ok(&d(s.prune_preview(&id).await)?)
}

async fn prune(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let (s, _) = site_ctx(&st, &id)?;
    let deleted = d(s.prune_site(&id).await)?;
    audit(
        &st,
        &p,
        "data.backup.prune",
        format!("site={id} deleted={deleted}"),
    )
    .await;
    json_ok(&PruneResult { deleted })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_headers_follow_the_single_range_rules() {
        assert_eq!(parse_range(None, 100), Ok(None));
        assert_eq!(parse_range(Some("bytes=0-9"), 100), Ok(Some((0, 9))));
        assert_eq!(parse_range(Some("bytes=90-"), 100), Ok(Some((90, 99))));
        assert_eq!(parse_range(Some("bytes=-10"), 100), Ok(Some((90, 99))));
        assert_eq!(parse_range(Some("bytes=-500"), 100), Ok(Some((0, 99))));
        assert_eq!(parse_range(Some("bytes=50-5000"), 100), Ok(Some((50, 99))));
        for bad in [
            "bytes=100-",
            "bytes=5-2",
            "bytes=0-1,4-5",
            "items=0-1",
            "bytes=-0",
            "bytes=a-b",
            "bytes=7",
        ] {
            assert_eq!(parse_range(Some(bad), 100), Err(()), "{bad}");
        }
        assert_eq!(parse_range(Some("bytes=0-0"), 0), Err(()));
    }
}
