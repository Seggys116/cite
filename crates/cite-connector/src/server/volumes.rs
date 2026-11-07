use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use cite_edge::validate::is_valid_volume_name;
use serde::Serialize;
use serde_json::json;

use super::handlers::{check_id, find_site, json_ok};
use super::{ApiError, ApiResult, AppState, Principal};
use crate::orchestrator::SiteVolumeInfo;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sites/{id}/volumes", get(list))
        .route(
            "/api/v1/sites/{id}/volumes/{name}",
            axum::routing::delete(remove),
        )
}

#[derive(Debug, Serialize)]
struct VolumeView {
    name: String,
    // Empty for a volume left over from an earlier volume list.
    mount_path: String,
    size_bytes: Option<u64>,
    mounted: bool,
    created_at: Option<String>,
    declared: bool,
}

// Declared volumes come first in declaration order, then leftovers; a declared volume not created yet has no Docker data.
fn join(declared: &[cite_edge::model::Volume], found: Vec<SiteVolumeInfo>) -> Vec<VolumeView> {
    let mut out: Vec<VolumeView> = declared
        .iter()
        .map(|v| {
            let seen = found.iter().find(|f| f.name == v.name);
            VolumeView {
                name: v.name.clone(),
                mount_path: v.mount_path.clone(),
                size_bytes: seen.and_then(|f| f.size_bytes),
                mounted: seen.is_some_and(|f| f.mounted),
                created_at: seen.and_then(|f| f.created_at.clone()),
                declared: true,
            }
        })
        .collect();
    out.extend(
        found
            .into_iter()
            .filter(|f| !declared.iter().any(|v| v.name == f.name))
            .map(|f| VolumeView {
                name: f.name,
                mount_path: String::new(),
                size_bytes: f.size_bytes,
                mounted: f.mounted,
                created_at: f.created_at,
                declared: false,
            }),
    );
    out
}

async fn list(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    check_id(&id)?;
    let site = find_site(&st, &id)?;
    let found = st.deployer.orchestrator()?.site_volumes(&id).await?;
    json_ok(&join(&site.volumes, found))
}

async fn remove(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Response> {
    check_id(&id)?;
    if !is_valid_volume_name(&name) {
        return Err(ApiError::bad("invalid volume name"));
    }
    find_site(&st, &id)?;
    st.deployer.delete_site_volume(&id, &name).await?;
    st.store
        .audit(
            &p.actor(),
            "site.volume.delete",
            &format!("site={id} volume={name}"),
        )
        .await;
    json_ok(&json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::Volume;

    fn info(name: &str, mounted: bool) -> SiteVolumeInfo {
        SiteVolumeInfo {
            name: name.into(),
            docker_name: format!("cite-vol-shop_{name}"),
            size_bytes: Some(10),
            created_at: Some("2026-11-01T10:00:00Z".into()),
            mounted,
        }
    }

    #[test]
    fn declared_volumes_are_joined_with_what_docker_holds() {
        let declared = vec![
            Volume {
                name: "data".into(),
                mount_path: "/data".into(),
            },
            Volume {
                name: "fresh".into(),
                mount_path: "/fresh".into(),
            },
        ];
        let views = join(&declared, vec![info("old", false), info("data", true)]);
        let names: Vec<&str> = views.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["data", "fresh", "old"]);
        assert!(views[0].declared && views[0].mounted && views[0].size_bytes == Some(10));
        assert!(views[1].declared && !views[1].mounted && views[1].size_bytes.is_none());
        assert!(!views[2].declared && views[2].mount_path.is_empty());
    }
}
