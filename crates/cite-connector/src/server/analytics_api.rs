use std::collections::HashMap;

use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::response::Response;
use cite_store::{AnalyticsFilter, Cursor, PageRequest, ParseOpts, SortBy};

use super::handlers::{json_ok, now_ms, parse_limit, parse_top_kind, store_failure, with_store};
use super::{ApiError, ApiResult, AppState};

/// The query string as ordered pairs, so a repeated parameter such as `site` keeps every value.
pub(super) struct RawPairs(Vec<(String, String)>);

impl<S: Send + Sync> FromRequestParts<S> for RawPairs {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> ApiResult<Self> {
        Query::<Vec<(String, String)>>::try_from_uri(&parts.uri)
            .map(|q| RawPairs(q.0))
            .map_err(|_| ApiError::bad("invalid query string"))
    }
}

fn filter_from(
    pairs: &[(String, String)],
    extras: &[&str],
    requests: bool,
) -> ApiResult<AnalyticsFilter> {
    AnalyticsFilter::parse(pairs, ParseOpts { extras, requests }).map_err(store_failure)
}

// The last value of each extra parameter, the way the original endpoints read their query.
fn extras_of(pairs: &[(String, String)], names: &[&str]) -> HashMap<String, String> {
    pairs
        .iter()
        .filter(|(k, _)| names.contains(&k.as_str()))
        .cloned()
        .collect()
}

fn flag(q: &HashMap<String, String>, key: &str) -> ApiResult<bool> {
    match q.get(key).map(String::as_str) {
        None | Some("" | "false" | "0") => Ok(false),
        Some("true" | "1") => Ok(true),
        Some(_) => Err(ApiError::bad(format!("{key} must be true or false"))),
    }
}

fn whole<T: std::str::FromStr>(
    q: &HashMap<String, String>,
    key: &str,
    what: &str,
) -> ApiResult<Option<T>> {
    match q.get(key).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(raw) => raw
            .parse::<T>()
            .map(Some)
            .map_err(|_| ApiError::bad(format!("{key} must be {what}"))),
    }
}

pub(super) async fn summary(
    State(st): State<AppState>,
    RawPairs(pairs): RawPairs,
) -> ApiResult<Response> {
    let f = filter_from(&pairs, &[], false)?;
    let out = with_store(&st, move |s| s.analytics_summary(&f, now_ms())).await?;
    json_ok(&out)
}

pub(super) async fn timeseries(
    State(st): State<AppState>,
    RawPairs(pairs): RawPairs,
) -> ApiResult<Response> {
    let f = filter_from(&pairs, &[], false)?;
    let out = with_store(&st, move |s| s.analytics_timeseries(&f, now_ms())).await?;
    json_ok(&out)
}

pub(super) async fn bots(
    State(st): State<AppState>,
    RawPairs(pairs): RawPairs,
) -> ApiResult<Response> {
    let f = filter_from(&pairs, &[], false)?;
    let out = with_store(&st, move |s| s.analytics_bots(&f, now_ms())).await?;
    json_ok(&out)
}

pub(super) async fn facets(
    State(st): State<AppState>,
    RawPairs(pairs): RawPairs,
) -> ApiResult<Response> {
    let f = filter_from(&pairs, &[], false)?;
    let out = with_store(&st, move |s| s.analytics_facets(&f, now_ms())).await?;
    json_ok(&out)
}

pub(super) async fn compare(
    State(st): State<AppState>,
    RawPairs(pairs): RawPairs,
) -> ApiResult<Response> {
    let f = filter_from(&pairs, &["against"], false)?;
    let q = extras_of(&pairs, &["against"]);
    if q.get("against")
        .is_some_and(|v| !v.is_empty() && v != "previous")
    {
        return Err(ApiError::bad("against must be previous"));
    }
    let out = with_store(&st, move |s| s.analytics_compare(&f, now_ms())).await?;
    json_ok(&out)
}

pub(super) async fn top(
    State(st): State<AppState>,
    RawPairs(pairs): RawPairs,
) -> ApiResult<Response> {
    const EXTRAS: [&str; 3] = ["kind", "limit", "sort"];
    let f = filter_from(&pairs, &EXTRAS, false)?;
    let q = extras_of(&pairs, &EXTRAS);
    let list = match q.get("kind") {
        Some(raw) => parse_top_kind(raw)?,
        None => return Err(ApiError::bad("kind is required")),
    };
    let limit = parse_limit(&q)?;
    let sort = match q.get("sort").map(String::as_str) {
        None | Some("" | "count") => SortBy::Count,
        Some("bytes") => SortBy::Bytes,
        Some(_) => return Err(ApiError::bad("sort must be count or bytes")),
    };
    let out = with_store(&st, move |s| {
        s.analytics_top(&f, list, limit, sort, now_ms())
    })
    .await?;
    json_ok(&out)
}

// `window` never limited this list and callers such as the desktop client still send it, so it counts only for a call that asks for the object form or names a range.
fn without_legacy_window(pairs: &[(String, String)], envelope: bool) -> Vec<(String, String)> {
    let ranged = pairs
        .iter()
        .any(|(k, v)| (k == "from" || k == "to") && !v.is_empty());
    pairs
        .iter()
        .filter(|(k, _)| envelope || ranged || k != "window")
        .cloned()
        .collect()
}

/// Newest-first requests. Without `envelope=true` the answer is the bare array it always was; with it, an object that carries the cursor and the filter echo.
pub(super) async fn requests(
    State(st): State<AppState>,
    RawPairs(pairs): RawPairs,
) -> ApiResult<Response> {
    const EXTRAS: [&str; 5] = ["limit", "offset", "before_ts", "before_id", "envelope"];
    let q = extras_of(&pairs, &EXTRAS);
    let envelope = flag(&q, "envelope")?;
    let limit = parse_limit(&q)?;
    let offset = whole::<usize>(&q, "offset", "a non-negative integer")?.unwrap_or(0);
    let before = match (
        whole::<i64>(&q, "before_ts", "milliseconds since the epoch")?,
        whole::<i64>(&q, "before_id", "a request id")?,
    ) {
        (None, None) => None,
        (Some(before_ts), Some(before_id)) => Some(Cursor {
            before_ts,
            before_id,
        }),
        _ => {
            return Err(ApiError::bad(
                "before_ts and before_id must be given together",
            ));
        }
    };
    let f = filter_from(&without_legacy_window(&pairs, envelope), &EXTRAS, true)?;
    let page = PageRequest {
        limit,
        offset,
        before,
    };
    let out = with_store(&st, move |s| s.analytics_requests(&f, &page, now_ms())).await?;
    if envelope {
        json_ok(&out)
    } else {
        json_ok(&out.items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn window_is_ignored_by_the_plain_request_list_only() {
        let p = pairs(&[("window", "1h"), ("limit", "5")]);
        assert_eq!(without_legacy_window(&p, false), pairs(&[("limit", "5")]));
        assert_eq!(without_legacy_window(&p, true), p);
        let ranged = pairs(&[("window", "1h"), ("from", "1000")]);
        assert_eq!(without_legacy_window(&ranged, false), ranged);
        let blank = pairs(&[("window", "1h"), ("from", "")]);
        assert_eq!(without_legacy_window(&blank, false), pairs(&[("from", "")]));
    }

    #[test]
    fn flags_and_numbers_are_checked() {
        let q: HashMap<String, String> =
            pairs(&[("envelope", "maybe"), ("offset", "-1"), ("a", "7")])
                .into_iter()
                .collect();
        assert!(flag(&q, "envelope").is_err());
        assert_eq!(flag(&q, "missing").ok(), Some(false));
        assert!(whole::<usize>(&q, "offset", "a non-negative integer").is_err());
        assert_eq!(whole::<usize>(&q, "a", "a number").ok(), Some(Some(7)));
        assert_eq!(whole::<usize>(&q, "missing", "a number").ok(), Some(None));
    }
}
