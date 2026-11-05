use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::ApiJson;
use crate::error::ApiError;
use crate::security;
use crate::state::{AppState, lock, now_unix};

pub const MAX_HTML_BYTES: usize = 256 * 1024;
pub const MAX_ENTRIES: usize = 32;
pub const TTL_SECS: u64 = 5 * 60;
const ID_BYTES: usize = 16;

// A bare sandbox blocks scripts and forms in the previewed page; only inline styles and data: assets are allowed.
pub const PREVIEW_CSP: &str =
    "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:";

struct Entry {
    html: String,
    created: u64,
}

// Bounded and short lived: expired entries go first, then the oldest one makes room.
pub struct PreviewStore {
    entries: HashMap<String, Entry>,
}

impl Default for PreviewStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PreviewStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn purge(&mut self, now: u64) {
        self.entries
            .retain(|_, e| now.saturating_sub(e.created) < TTL_SECS);
    }

    pub fn insert(&mut self, id: String, html: String, now: u64) {
        self.purge(now);
        while self.entries.len() >= MAX_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.created)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(key) => self.entries.remove(&key),
                None => break,
            };
        }
        self.entries.insert(id, Entry { html, created: now });
    }

    pub fn get(&mut self, id: &str, now: u64) -> Option<String> {
        self.purge(now);
        self.entries.get(id).map(|e| e.html.clone())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewBody {
    html: String,
}

fn new_id() -> Result<String, ApiError> {
    let mut bytes = [0u8; ID_BYTES];
    getrandom::fill(&mut bytes).map_err(ApiError::internal)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub async fn create(
    State(s): State<Arc<AppState>>,
    ApiJson(body): ApiJson<PreviewBody>,
) -> Result<Json<Value>, ApiError> {
    if body.html.len() > MAX_HTML_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the preview is larger than 256 KiB",
        ));
    }
    let id = new_id()?;
    lock(&s.previews).insert(id.clone(), body.html, now_unix());
    Ok(Json(json!({ "id": id })))
}

pub async fn serve(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let now = now_unix();
    let token = security::cookie_token(&headers, s.settings.cookie_secure());
    let signed_in = match token {
        Some(token) => s.validate_session(token, now).await.is_some(),
        None => false,
    };
    // Knowing the random id is not enough; the html is only for a signed-in session.
    if !signed_in {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(html) = lock(&s.previews).get(&id, now) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut resp = html.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(PREVIEW_CSP),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(store: &mut PreviewStore, count: usize, start: u64) {
        for i in 0..count {
            store.insert(format!("id{i}"), format!("<p>{i}</p>"), start + i as u64);
        }
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let mut store = PreviewStore::new();
        store.insert("a".into(), "<p>a</p>".into(), 100);
        assert_eq!(
            store.get("a", 100 + TTL_SECS - 1).as_deref(),
            Some("<p>a</p>")
        );
        assert_eq!(store.get("a", 100 + TTL_SECS), None);
        assert!(store.is_empty());
    }

    #[test]
    fn the_store_never_exceeds_its_bound_and_drops_the_oldest() {
        let mut store = PreviewStore::new();
        fill(&mut store, MAX_ENTRIES, 1000);
        assert_eq!(store.len(), MAX_ENTRIES);
        store.insert("new".into(), "<p>new</p>".into(), 1100);
        assert_eq!(store.len(), MAX_ENTRIES);
        assert_eq!(store.get("id0", 1100), None);
        assert!(store.get("id1", 1100).is_some());
        assert!(store.get("new", 1100).is_some());
    }

    #[test]
    fn expired_entries_are_purged_before_live_ones_are_evicted() {
        let mut store = PreviewStore::new();
        store.insert("old".into(), "x".into(), 0);
        fill(&mut store, MAX_ENTRIES - 1, TTL_SECS + 10);
        store.insert("fresh".into(), "y".into(), TTL_SECS + 100);
        assert_eq!(store.get("old", TTL_SECS + 100), None);
        assert!(store.get("id0", TTL_SECS + 100).is_some());
        assert_eq!(store.len(), MAX_ENTRIES);
    }

    #[test]
    fn ids_are_128_bit_hex_and_unique() {
        let (a, b) = (new_id().expect("id"), new_id().expect("id"));
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
