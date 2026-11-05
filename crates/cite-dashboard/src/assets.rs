use std::collections::HashMap;
use std::sync::OnceLock;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};

use crate::error::ApiError;

const NO_CACHE: &str = "no-cache";
const ASSET_CACHE: &str = "public, max-age=3600";
const INDEX: &str = "index.html";

static WEB: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/web");
static ASSETS: OnceLock<HashMap<String, Asset>> = OnceLock::new();

struct Asset {
    body: &'static [u8],
    content_type: &'static str,
    etag: String,
    cache: &'static str,
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

impl Asset {
    fn new(path: &str, body: &'static [u8]) -> Self {
        let digest = Sha256::digest(body);
        let hex: String = digest
            .as_slice()
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect();
        let kind = content_type(path);
        Self {
            body,
            content_type: kind,
            etag: format!("\"{hex}\""),
            cache: if kind.starts_with("text/html") {
                NO_CACHE
            } else {
                ASSET_CACHE
            },
        }
    }
}

fn collect(dir: &'static Dir<'static>, out: &mut HashMap<String, Asset>) {
    for file in dir.files() {
        let name = file.path().to_string_lossy().replace('\\', "/");
        let asset = Asset::new(&name, file.contents());
        out.insert(name, asset);
    }
    for sub in dir.dirs() {
        collect(sub, out);
    }
}

fn assets() -> &'static HashMap<String, Asset> {
    ASSETS.get_or_init(|| {
        let mut table = HashMap::new();
        collect(&WEB, &mut table);
        table
    })
}

// Weak validators are accepted because a 304 only needs the bytes to be equivalent.
fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|raw| {
            raw.split(',')
                .map(|candidate| candidate.trim().trim_start_matches("W/"))
                .any(|candidate| candidate == "*" || candidate == etag)
        })
}

fn has_extension(key: &str) -> bool {
    key.rsplit('/')
        .next()
        .is_some_and(|name| name.contains('.'))
}

fn respond(asset: &'static Asset, headers: &HeaderMap) -> Response {
    let mut resp = if etag_matches(headers, &asset.etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut full = Response::new(Body::from(asset.body));
        full.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(asset.content_type),
        );
        full
    };
    if let Ok(value) = HeaderValue::from_str(&asset.etag) {
        resp.headers_mut().insert(header::ETAG, value);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(asset.cache));
    resp
}

// Missing files with an extension are real 404s; extensionless paths belong to the client router.
pub async fn serve(req: Request) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, HEAD")],
        )
            .into_response();
    }
    let path = req.uri().path();
    if path == "/api" || path.starts_with("/api/") {
        return ApiError::not_found("no such api route").into_response();
    }
    let key = match path.trim_start_matches('/') {
        "" => INDEX,
        other => other,
    };
    let table = assets();
    let found = table.get(key).or_else(|| {
        if has_extension(key) {
            None
        } else {
            table.get(INDEX)
        }
    });
    match found {
        Some(asset) => respond(asset, req.headers()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_is_embedded_and_html_is_not_cached() {
        let index = assets().get(INDEX).expect("index.html is embedded");
        assert_eq!(index.cache, NO_CACHE);
        assert!(index.content_type.starts_with("text/html"));
        assert!(index.etag.starts_with('"') && index.etag.ends_with('"'));
    }

    #[test]
    fn add_node_form_can_send_a_connector_ca() {
        let nodes = assets()
            .get("js/views/nodes.js")
            .expect("nodes view is embedded");
        let source = std::str::from_utf8(nodes.body).expect("utf8 source");
        assert!(source.contains("body.ca_pem"));
    }

    #[test]
    fn content_types_cover_the_console_assets() {
        assert!(content_type("app.js").starts_with("text/javascript"));
        assert!(content_type("js/views/auth.js").starts_with("text/javascript"));
        assert!(content_type("app.css").starts_with("text/css"));
        assert_eq!(content_type("assets/logo.svg"), "image/svg+xml");
        assert_eq!(content_type("blob.bin"), "application/octet-stream");
    }

    #[test]
    fn etag_comparison_handles_lists_and_weak_tags() {
        let mut h = HeaderMap::new();
        h.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("\"zzz\", W/\"abc\""),
        );
        assert!(etag_matches(&h, "\"abc\""));
        assert!(!etag_matches(&h, "\"abd\""));
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(etag_matches(&h, "\"abd\""));
        assert!(!etag_matches(&HeaderMap::new(), "\"abc\""));
    }

    #[test]
    fn extension_rule_separates_assets_from_routes() {
        assert!(has_extension("js/app.js"));
        assert!(!has_extension("nodes/edge-1"));
        assert!(!has_extension("sites"));
    }
}
