#![forbid(unsafe_code)]

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};

pub type BoxBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// A buffered body. Streaming responses use [`crate::proxy`] instead of this helper.
pub fn full_body(bytes: impl Into<Bytes>) -> BoxBody {
    Full::new(bytes.into())
        .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
        .boxed_unsync()
}

pub fn html_response(status: StatusCode, body: &'static str) -> Response<BoxBody> {
    let mut res = Response::new(full_body(Bytes::from_static(body.as_bytes())));
    *res.status_mut() = status;
    res.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    res.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    res
}

pub fn page_500() -> Response<BoxBody> {
    html_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "<!doctype html><title>Error</title><h1>500</h1><p>Something went wrong.</p>",
    )
}

pub fn page_503() -> Response<BoxBody> {
    html_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "<!doctype html><title>Unavailable</title><h1>503</h1><p>No release ready.</p>",
    )
}

pub fn page_502() -> Response<BoxBody> {
    html_response(
        StatusCode::BAD_GATEWAY,
        "<!doctype html><title>Bad Gateway</title><h1>502</h1><p>Upstream unavailable.</p>",
    )
}

pub fn page_504() -> Response<BoxBody> {
    html_response(
        StatusCode::GATEWAY_TIMEOUT,
        "<!doctype html><title>Gateway Timeout</title><h1>504</h1><p>Upstream timed out.</p>",
    )
}

pub fn page_413() -> Response<BoxBody> {
    html_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "<!doctype html><title>Payload Too Large</title><h1>413</h1><p>Body too large.</p>",
    )
}

pub fn page_404() -> Response<BoxBody> {
    html_response(
        StatusCode::NOT_FOUND,
        "<!doctype html><title>Not Found</title><h1>404</h1><p>Not found.</p>",
    )
}

pub fn page_400(msg: &'static str) -> Response<BoxBody> {
    let mut res = html_response(StatusCode::BAD_REQUEST, msg);
    *res.body_mut() = full_body(Bytes::from_static(
        b"<!doctype html><title>Bad Request</title><h1>400</h1>",
    ));
    res
}

pub fn method_not_allowed() -> Response<BoxBody> {
    let mut res = html_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "<!doctype html><title>Method Not Allowed</title><h1>405</h1>",
    );
    res.headers_mut().insert(
        http::header::ALLOW,
        HeaderValue::from_static("GET, HEAD, OPTIONS"),
    );
    res
}

pub fn apply_security_headers(headers: &mut HeaderMap, extra: &[(String, String)]) {
    headers.insert(
        http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        http::header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    for (name, value) in extra {
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            headers.insert(n, v);
        }
    }
}
