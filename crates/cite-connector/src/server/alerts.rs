use std::sync::Arc;

use axum::extract::{FromRequest, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use cite_edge::alerts::{AlertSettings, EMAIL_TARGET, MAX_BODY_BYTES, valid_slug};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use super::{ApiError, ApiResult, AppState, Principal, parse_json, read_body_limited};
use crate::ConnectorError;
use crate::alerts::TestOutcome;
use crate::deploy::detach;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/alerts", get(show).put(update))
        .route("/api/v1/alerts/test", post(test))
}

// A smaller cap than the rest of the API: alert settings are a few short strings.
struct AlertBody<T>(T);

impl<S, T> FromRequest<S> for AlertBody<T>
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
        parse_json(&bytes).map(AlertBody)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReq {
    target: String,
}

async fn show(State(st): State<AppState>) -> Response {
    Json(st.alerts.view()).into_response()
}

// Only ids and flags are written to the audit log; URLs and the SMTP password never are.
async fn update(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    AlertBody(req): AlertBody<AlertSettings>,
) -> ApiResult<Response> {
    let alerts = Arc::clone(&st.alerts);
    let view = detach(async move { alerts.update(req).await }).await?;
    let ids: Vec<&str> = view.webhooks.iter().map(|h| h.id.as_str()).collect();
    let note = format!(
        "enabled={} webhooks=[{}] email={}",
        view.enabled,
        ids.join(","),
        view.email.is_some()
    );
    st.store.audit(&p.actor(), "alerts.update", &note).await;
    Ok(Json(view).into_response())
}

fn unknown_target() -> ApiError {
    ConnectorError::NotFound("alert target not found".into()).into()
}

async fn test(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    AlertBody(req): AlertBody<TestReq>,
) -> ApiResult<Response> {
    if req.target != EMAIL_TARGET && !valid_slug(&req.target) {
        return Err(unknown_target());
    }
    let outcome = st.alerts.test(&req.target).await;
    let (ok, error) = match outcome {
        TestOutcome::Unknown => return Err(unknown_target()),
        TestOutcome::Sent => (true, None),
        TestOutcome::Failed(message) => (false, Some(message)),
    };
    let note = format!("target={} ok={ok}", req.target);
    st.store.audit(&p.actor(), "alerts.test", &note).await;
    let body = match error {
        Some(error) => json!({ "ok": false, "error": error }),
        None => json!({ "ok": true }),
    };
    Ok(Json(body).into_response())
}
