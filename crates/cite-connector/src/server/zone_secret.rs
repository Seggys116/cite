use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use cite_edge::presets::ZONE_HEADER;
use serde_json::json;

use super::handlers::check_id;
use super::{ApiError, ApiResult, AppState, Inner, Principal};
use crate::change::{Rollback, failure};
use crate::deploy::detach;
use crate::{ConnectorError, Result};

// Never returns the secret; the fingerprint is enough to tell whether Cloudflare's copy is current.
pub(super) async fn status(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    lock_state(&st, &id)?;
    let meta = st.haproxy.zones().meta(&id);
    Ok(Json(json!({
        "configured": meta.is_some(),
        "readable": !st.haproxy.zones().is_broken(),
        "header": ZONE_HEADER,
        "created_at": meta.as_ref().map(|m| m.created_at.clone()),
        "fingerprint": meta.as_ref().map(|m| m.fingerprint.clone()),
    }))
    .into_response())
}

fn lock_state(st: &Inner, id: &str) -> Result<bool> {
    st.store
        .config()
        .sites
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.access.zone_lock)
        .ok_or_else(|| ConnectorError::NotFound(format!("site {id} not found")))
}

async fn rotate_now(st: AppState, actor: String, id: String) -> Result<serde_json::Value> {
    #[cfg(test)]
    st.rotations_waiting
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let _config = st.deployer.config_lock().lock().await;
    // the check in the handler ran before this lock; a site change in between must not turn into a secret for an unlocked site
    if !lock_state(&st, &id)? {
        return Err(ConnectorError::BadRequest(
            "the site stopped having access.zone_lock while the rotation waited; nothing was changed"
                .into(),
        ));
    }
    let zones = Arc::clone(st.haproxy.zones());
    let site = id.clone();
    let rotated = tokio::task::spawn_blocking(move || zones.rotate(&site))
        .await
        .map_err(|e| ConnectorError::Internal(format!("rotation task failed: {e}")))??;
    // a new secret that no running HAProxy enforces would be handed out as if it were live, so this needs a confirmed load
    let applied = st
        .haproxy
        .apply(&st.store.config())
        .await
        .and_then(|o| o.require_running());
    if let Err(err) = applied {
        let zones = Arc::clone(st.haproxy.zones());
        let site = id.clone();
        let previous = rotated.previous.clone();
        let restored = matches!(
            tokio::task::spawn_blocking(move || zones.restore(&site, previous)).await,
            Ok(Ok(()))
        );
        if !restored {
            tracing::error!(site = %id, "could not restore the previous zone secret");
        }
        // HAProxy is told again whatever the undo did, so what it enforces and what is stored are compared once more
        let confirmed = st
            .haproxy
            .apply(&st.store.config())
            .await
            .and_then(|o| o.require_loaded())
            .is_ok();
        let (name, outcome) = match (restored, confirmed) {
            (true, true) => ("zone_secret.rollback", Rollback::Done),
            (false, _) => ("zone_secret.rollback_failed", Rollback::StoreFailed),
            (true, false) => ("zone_secret.rollback_unconfirmed", Rollback::NotConfirmed),
        };
        st.store.audit(&actor, name, &format!("site={id}")).await;
        return Err(failure(err, true, outcome));
    }
    st.store
        .audit(
            &actor,
            "zone_secret.rotate",
            &format!("site={id} fingerprint={}", rotated.meta.fingerprint),
        )
        .await;
    Ok(json!({
        "secret": rotated.secret.as_str(),
        "header": ZONE_HEADER,
        "created_at": rotated.meta.created_at,
        "fingerprint": rotated.meta.fingerprint,
    }))
}

// Creates or replaces the secret and returns it once; the old value stops working as soon as HAProxy has reloaded.
pub(super) async fn rotate(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    if !lock_state(&st, &id)? {
        return Err(ApiError::bad(
            "the site does not have access.zone_lock; turn it on first",
        ));
    }
    let this = Arc::clone(&st);
    let body = detach(async move { rotate_now(this, p.actor(), id).await }).await?;
    let mut res = Json(body).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}
