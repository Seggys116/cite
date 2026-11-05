use std::fs::File;
use std::io::{self, Read};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use bytes::Bytes;
use cite_store::ArchiveItem;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use super::handlers::{now_ms, store_failure, with_store};
use super::{ApiError, ApiResult, AppState, JsonBody, Principal};
use crate::ConnectorError;

const CHUNK: usize = 32 * 1024;
const CHANNEL_CHUNKS: usize = 4;
const DAY_MS: i64 = 86_400_000;
const MAX_CUT_DAYS: u32 = 36_500;
const MAX_AUDITED_NAME: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CutReq {
    before_ms: Option<i64>,
    before_days: Option<u32>,
    archive: Option<bool>,
    dry_run: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
struct CutPlan {
    cutoff_ms: i64,
    archive: bool,
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreReq {
    name: String,
    again: Option<bool>,
}

// A manual cut keeps a verified copy unless the caller says archive:false in so many words, and never reaches into the future.
fn plan_cut(req: &CutReq, now: i64) -> ApiResult<CutPlan> {
    let cutoff_ms = match (req.before_ms, req.before_days) {
        (Some(ms), None) => ms,
        (None, Some(days)) if (1..=MAX_CUT_DAYS).contains(&days) => {
            now.saturating_sub(i64::from(days) * DAY_MS)
        }
        (None, Some(_)) => {
            return Err(ApiError::bad(format!(
                "before_days must be between 1 and {MAX_CUT_DAYS}"
            )));
        }
        _ => {
            return Err(ApiError::bad(
                "give exactly one of before_ms and before_days",
            ));
        }
    };
    if cutoff_ms < 0 {
        return Err(ApiError::bad("before_ms must not be negative"));
    }
    if cutoff_ms > now {
        return Err(ApiError::bad("the cutoff must not be in the future"));
    }
    Ok(CutPlan {
        cutoff_ms,
        archive: req.archive.unwrap_or(true),
        dry_run: req.dry_run.unwrap_or(false),
    })
}

// The name comes from the client, so it is quoted and capped before it reaches the audit log.
fn audited(name: &str) -> String {
    let short: String = name.chars().take(MAX_AUDITED_NAME).collect();
    format!("name={short:?}")
}

pub(super) async fn list_archives(State(st): State<AppState>) -> ApiResult<Response> {
    let list = with_store(&st, |s| s.list_archives()).await?;
    Ok(Json(list).into_response())
}

pub(super) async fn backup(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Response> {
    st.store.audit(&p.actor(), "analytics.backup", "").await;
    let item = with_store(&st, |s| s.backup()).await?;
    Ok(Json(item).into_response())
}

pub(super) async fn cut(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    JsonBody(req): JsonBody<CutReq>,
) -> ApiResult<Response> {
    let plan = plan_cut(&req, now_ms())?;
    let detail = format!(
        "before_ms={} archive={} dry_run={}",
        plan.cutoff_ms, plan.archive, plan.dry_run
    );
    st.store.audit(&p.actor(), "analytics.cut", &detail).await;
    let report = with_store(&st, move |s| {
        s.cut_before(plan.cutoff_ms, plan.archive, plan.dry_run)
    })
    .await?;
    Ok(Json(report).into_response())
}

pub(super) async fn restore(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    JsonBody(req): JsonBody<RestoreReq>,
) -> ApiResult<Response> {
    st.store
        .audit(&p.actor(), "analytics.restore", &audited(&req.name))
        .await;
    let (name, again) = (req.name, req.again.unwrap_or(false));
    let rows = with_store(&st, move |s| {
        if again {
            s.restore_archive_again(&name)
        } else {
            s.restore_archive(&name)
        }
    })
    .await?;
    Ok(Json(json!({ "rows": rows })).into_response())
}

pub(super) async fn delete_archive(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(name): Path<String>,
) -> ApiResult<Response> {
    st.store
        .audit(&p.actor(), "analytics.archive.delete", &audited(&name))
        .await;
    with_store(&st, move |s| s.delete_archive(&name)).await?;
    Ok(Json(json!({ "ok": true })).into_response())
}

fn start_download(mut file: File, permit: OwnedSemaphorePermit) -> Body {
    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(CHANNEL_CHUNKS);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut buf = vec![0u8; CHUNK];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .blocking_send(Ok(Bytes::copy_from_slice(&buf[..n])))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "archive download failed");
                    // An error item aborts the response so a short read is never mistaken for a whole file.
                    let _ = tx.blocking_send(Err(io::Error::other("read failed")));
                    break;
                }
            }
        }
    });
    Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

pub(super) async fn download(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(name): Path<String>,
) -> ApiResult<Response> {
    let permit = Arc::clone(&st.exports).try_acquire_owned().map_err(|_| {
        ConnectorError::TooManyRequests("too many downloads are running; try again shortly".into())
    })?;
    st.store
        .audit(&p.actor(), "analytics.archive.download", &audited(&name))
        .await;
    let (file, item): (File, ArchiveItem) = {
        let store = Arc::clone(&st.analytics);
        tokio::task::spawn_blocking(move || store.open_archive(&name))
            .await
            .map_err(|e| ConnectorError::Internal(format!("archive task failed: {e}")))?
            .map_err(store_failure)?
    };
    let content_type = if item.kind == "backup" {
        "application/vnd.sqlite3"
    } else {
        "application/gzip"
    };
    // The name was validated to plain characters by the store, so it is safe inside the header.
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", item.name))
        .map_err(|e| ConnectorError::Internal(format!("archive file name: {e}")))?;
    let sha = HeaderValue::from_str(&item.sha256)
        .map_err(|e| ConnectorError::Internal(format!("archive checksum: {e}")))?;
    let mut res = Response::new(start_download(file, permit));
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(item.bytes));
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert("x-archive-sha256", sha);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_730_721_600_000;

    fn req(json: &str) -> CutReq {
        serde_json::from_str(json).expect("request")
    }

    fn plan(json: &str) -> ApiResult<CutPlan> {
        plan_cut(&req(json), NOW)
    }

    #[test]
    fn a_cut_archives_by_default_and_only_skips_it_when_told_to() {
        let p = plan(r#"{"before_days": 30}"#).unwrap();
        assert_eq!(
            p,
            CutPlan {
                cutoff_ms: NOW - 30 * DAY_MS,
                archive: true,
                dry_run: false
            }
        );
        let p = plan(r#"{"before_ms": 1000, "archive": false, "dry_run": true}"#).unwrap();
        assert_eq!(
            p,
            CutPlan {
                cutoff_ms: 1000,
                archive: false,
                dry_run: true
            }
        );
    }

    #[test]
    fn exactly_one_cutoff_in_range_is_required() {
        for json in [
            "{}",
            r#"{"before_ms": 1, "before_days": 1}"#,
            r#"{"before_days": 0}"#,
            r#"{"before_days": 36501}"#,
            r#"{"before_ms": -1}"#,
            r#"{"before_ms": 1730721600001}"#,
            r#"{"archive": true}"#,
        ] {
            assert!(plan(json).is_err(), "{json}");
        }
    }

    #[test]
    fn unknown_or_mistyped_fields_are_refused() {
        assert!(serde_json::from_str::<CutReq>(r#"{"before_days": 1, "force": true}"#).is_err());
        assert!(serde_json::from_str::<CutReq>(r#"{"before_days": "1"}"#).is_err());
        assert!(serde_json::from_str::<CutReq>(r#"{"before_days": 1, "archive": "no"}"#).is_err());
        assert!(serde_json::from_str::<RestoreReq>(r#"{"name": "x", "extra": 1}"#).is_err());
    }

    #[test]
    fn audited_names_are_quoted_and_capped() {
        assert_eq!(audited("a\nb"), "name=\"a\\nb\"");
        let long = "x".repeat(500);
        assert_eq!(audited(&long).len(), "name=\"\"".len() + MAX_AUDITED_NAME);
    }
}
