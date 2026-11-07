use std::fmt;

use axum::extract::{FromRequest, Path, Request, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use cite_edge::model::DopplerBinding;
use cite_edge::validate::is_valid_doppler_slug;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::{Zeroize, Zeroizing};

use super::handlers::{check_id, find_site, json_ok};
use super::{ApiError, ApiResult, AppState, Principal, parse_json, read_body_limited};

// A binding is two short names, two flags and an optional token.
const MAX_BIND_BODY_BYTES: usize = 4 * 1024;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/doppler/projects", get(projects))
        .route("/api/v1/doppler/projects/{project}/configs", get(configs))
        .route(
            "/api/v1/sites/{id}/doppler",
            get(status).put(bind).delete(unbind),
        )
        .route("/api/v1/sites/{id}/doppler/sync", post(sync))
}

struct BindBody<T>(T);

impl<S, T> FromRequest<S> for BindBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, MAX_BIND_BODY_BYTES).await?;
        if bytes.is_empty() {
            return Err(ApiError::bad("request body is required"));
        }
        parse_json(&bytes).map(BindBody)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BindReq {
    project: String,
    config: String,
    #[serde(default)]
    build: bool,
    #[serde(default)]
    runtime: bool,
    #[serde(default)]
    token: Option<String>,
}

impl Drop for BindReq {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_mut() {
            token.zeroize();
        }
    }
}

impl fmt::Debug for BindReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindReq")
            .field("project", &self.project)
            .field("config", &self.config)
            .field("build", &self.build)
            .field("runtime", &self.runtime)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

// Doppler variables feed builds and runtimes, so only a repo-built site can be bound.
fn source_site(st: &AppState, id: &str) -> ApiResult<()> {
    check_id(id)?;
    if find_site(st, id)?.source.is_none() {
        return Err(ApiError::bad(
            "this site is not built from a repository, so it has no build or runtime variables",
        ));
    }
    Ok(())
}

async fn projects(State(st): State<AppState>) -> ApiResult<Response> {
    json_ok(&st.doppler.projects().await?)
}

async fn configs(State(st): State<AppState>, Path(project): Path<String>) -> ApiResult<Response> {
    if !is_valid_doppler_slug(&project) {
        return Err(ApiError::bad("invalid Doppler project"));
    }
    json_ok(&st.doppler.configs(&project).await?)
}

async fn status(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    source_site(&st, &id)?;
    json_ok(&st.doppler.view(&id).await?)
}

async fn bind(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    BindBody(mut req): BindBody<BindReq>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    let binding = DopplerBinding {
        project: std::mem::take(&mut req.project),
        config: std::mem::take(&mut req.config),
        build: req.build,
        runtime: req.runtime,
    };
    // Moving the buffer into Zeroizing wipes it once the token is stored, on every path.
    let token = req.token.take().map(Zeroizing::new);
    let view = st.doppler.bind(&p.actor(), &id, binding, token).await?;
    json_ok(&view)
}

async fn unbind(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    json_ok(&st.doppler.unbind(&p.actor(), &id).await?)
}

async fn sync(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    st.store
        .audit(
            &p.actor(),
            "site.doppler.sync.request",
            &format!("site={id}"),
        )
        .await;
    json_ok(&st.doppler.sync_now(&p.actor(), &id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bind_request_never_prints_its_token() {
        let req: BindReq = serde_json::from_str(
            r#"{"project":"shop","config":"prd","build":true,"token":"dp.st.secretvalue"}"#,
        )
        .expect("request");
        let shown = format!("{req:?}");
        assert!(
            shown.contains("shop") && !shown.contains("secretvalue"),
            "{shown}"
        );
        assert!(serde_json::from_str::<BindReq>(r#"{"project":"a","config":"b","x":1}"#).is_err());
    }
}
