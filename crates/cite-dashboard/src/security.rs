use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::error::ApiError;
use crate::state::{AppState, now_unix};

pub const COOKIE_NAME: &str = "cite_session";
pub const SECURE_COOKIE_NAME: &str = "__Host-cite_session";
pub const CSRF_HEADER: &str = "x-cite-csrf";

const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; \
frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; \
connect-src 'self'; object-src 'none'";
const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
magnetometer=(), microphone=(), payment=(), usb=()";
const HSTS: &str = "max-age=31536000";
const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");
const PERMISSIONS: HeaderName = HeaderName::from_static("permissions-policy");

#[derive(Clone)]
pub struct SessionCtx {
    pub username: String,
    pub csrf: String,
    pub token: String,
    pub expires: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct PeerIp(pub IpAddr);

pub fn peer_ip(parts: &http::Extensions) -> IpAddr {
    parts
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ci| {
            ci.0.ip().to_canonical()
        })
}

impl<S: Send + Sync> FromRequestParts<S> for PeerIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        Ok(PeerIp(peer_ip(&parts.extensions)))
    }
}

pub fn limiter_key(ip: IpAddr) -> String {
    cite_edge::ratelimit::client_key(ip)
}

// The __Host- prefix makes browsers refuse a copy planted by a sibling subdomain (no Domain, Path=/, Secure).
pub fn cookie_name(secure: bool) -> &'static str {
    if secure {
        SECURE_COOKIE_NAME
    } else {
        COOKIE_NAME
    }
}

pub fn session_cookie(secure: bool, token: &str, max_age: u64) -> String {
    let name = cookie_name(secure);
    let mut cookie =
        format!("{name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

// More than one cookie with the session name is treated as unauthenticated, since a planted copy could shadow the real one.
pub fn cookie_token(headers: &HeaderMap, secure: bool) -> Option<&str> {
    let name = cookie_name(secure);
    let mut matching = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(n, _)| *n == name)
        .map(|(_, value)| value);
    let first = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    Some(first).filter(|v| !v.is_empty() && v.len() <= 128)
}

fn request_host(req: &Request) -> Option<String> {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
}

fn origin_ok(req: &Request) -> bool {
    let Some(origin) = req.headers().get(header::ORIGIN) else {
        return true;
    };
    let authority = origin
        .to_str()
        .ok()
        .and_then(|o| o.split_once("://"))
        .map(|(_, rest)| rest.trim_end_matches('/'));
    match (authority, request_host(req)) {
        (Some(origin_host), Some(host)) => origin_host.eq_ignore_ascii_case(&host),
        _ => false,
    }
}

fn json_or_empty(headers: &HeaderMap) -> bool {
    match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(ct) => ct
            .split(';')
            .next()
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json")),
        None => {
            !headers.contains_key(header::TRANSFER_ENCODING)
                && headers
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .is_none_or(|v| v.trim() == "0")
        }
    }
}

// These endpoints run before a session exists, so they carry no cookie and no csrf token.
fn is_pre_auth(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/api/v1/setup")
            | (&Method::POST, "/api/v1/setup")
            | (&Method::POST, "/api/v1/setup/confirm")
            | (&Method::POST, "/api/v1/session")
    )
}

fn csrf_matches(presented: &str, session_csrf: &str) -> bool {
    bool::from(presented.as_bytes().ct_eq(session_csrf.as_bytes()))
}

pub async fn api_guard(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    if !origin_ok(&req) {
        return ApiError::forbidden("cross-origin request refused").into_response();
    }
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && !json_or_empty(req.headers()) {
        return ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "requests with a body must be application/json",
        )
        .into_response();
    }
    if is_pre_auth(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    let Some(token) =
        cookie_token(req.headers(), state.settings.cookie_secure()).map(str::to_string)
    else {
        return ApiError::unauthorized("not signed in").into_response();
    };
    let info = state.validate_session(&token, now_unix()).await;
    let Some(info) = info else {
        return ApiError::unauthorized("not signed in").into_response();
    };
    let csrf = info.csrf;
    if !safe {
        let presented = req
            .headers()
            .get(CSRF_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !csrf_matches(presented, &csrf) {
            return ApiError::forbidden("missing or invalid csrf token").into_response();
        }
    }
    req.extensions_mut().insert(SessionCtx {
        username: info.username,
        csrf,
        token,
        expires: info.expires,
    });
    next.run(req).await
}

// /healthz stays reachable from anywhere so the container healthcheck works under any allowlist.
pub async fn allow_guard(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if let Some(allow) = &state.settings.allow
        && req.uri().path() != "/healthz"
        && !allow.allows(peer_ip(req.extensions()))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

pub async fn security_headers(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    // Handlers that set their own stricter policy (the sandboxed preview) keep it.
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(COOP, HeaderValue::from_static("same-origin"));
    headers.insert(CORP, HeaderValue::from_static("same-origin"));
    headers.insert(PERMISSIONS, HeaderValue::from_static(PERMISSIONS_POLICY));
    if state.settings.tls.is_some() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        );
    }
    if is_api {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).expect("name"),
                HeaderValue::from_str(v).expect("value"),
            );
        }
        map
    }

    #[test]
    fn cookie_token_finds_the_session_among_other_cookies() {
        let h = headers(&[("cookie", "theme=dark; cite_session=cite_abc; other=1")]);
        assert_eq!(cookie_token(&h, false), Some("cite_abc"));
        assert_eq!(
            cookie_token(&headers(&[("cookie", "cite_session=")]), false),
            None
        );
        assert_eq!(
            cookie_token(&headers(&[("cookie", "xcite_session=a")]), false),
            None
        );
        assert_eq!(cookie_token(&HeaderMap::new(), false), None);
    }

    #[test]
    fn duplicate_session_cookies_are_unauthenticated() {
        let same_line = headers(&[("cookie", "cite_session=cite_a; cite_session=cite_b")]);
        assert_eq!(cookie_token(&same_line, false), None);
        let two_lines = headers(&[
            ("cookie", "cite_session=cite_a"),
            ("cookie", "cite_session=cite_b"),
        ]);
        assert_eq!(cookie_token(&two_lines, false), None);
        let secure = headers(&[(
            "cookie",
            "__Host-cite_session=cite_a; __Host-cite_session=cite_b",
        )]);
        assert_eq!(cookie_token(&secure, true), None);
    }

    #[test]
    fn secure_cookies_use_the_host_prefix_and_ignore_the_plain_name() {
        let h = headers(&[("cookie", "cite_session=cite_x; __Host-cite_session=cite_ok")]);
        assert_eq!(cookie_token(&h, true), Some("cite_ok"));
        assert_eq!(cookie_token(&h, false), Some("cite_x"));
        let secure = session_cookie(true, "t", 60);
        assert!(secure.starts_with("__Host-cite_session=t; Path=/;"));
        assert!(!secure.contains("Domain"));
        assert!(session_cookie(false, "t", 60).starts_with("cite_session=t;"));
    }

    #[test]
    fn limiter_keys_group_ipv6_by_prefix() {
        let key = |s: &str| limiter_key(s.parse().expect("ip"));
        assert_eq!(key("203.0.113.9"), "203.0.113.9");
        assert_ne!(key("203.0.113.9"), key("203.0.113.10"));
        assert_eq!(
            key("2001:db8:1:2::1"),
            key("2001:db8:1:2:ffff:ffff:ffff:ffff")
        );
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:203.0.113.9"), "203.0.113.9");
    }

    #[test]
    fn content_type_rules() {
        assert!(json_or_empty(&headers(&[(
            "content-type",
            "application/json"
        )])));
        assert!(json_or_empty(&headers(&[(
            "content-type",
            "Application/JSON; charset=utf-8"
        )])));
        assert!(!json_or_empty(&headers(&[("content-type", "text/plain")])));
        assert!(!json_or_empty(&headers(&[(
            "content-type",
            "application/x-www-form-urlencoded"
        )])));
        assert!(json_or_empty(&HeaderMap::new()));
        assert!(json_or_empty(&headers(&[("content-length", "0")])));
        assert!(!json_or_empty(&headers(&[("content-length", "12")])));
        assert!(!json_or_empty(&headers(&[(
            "transfer-encoding",
            "chunked"
        )])));
    }

    #[test]
    fn cookie_attributes_depend_on_transport() {
        let plain = session_cookie(false, "t", 60);
        assert!(plain.contains("HttpOnly") && plain.contains("SameSite=Strict"));
        assert!(!plain.contains("Secure"));
        assert!(session_cookie(true, "t", 60).ends_with("; Secure"));
    }

    #[test]
    fn csrf_tokens_are_random_per_session_and_not_the_session_secret() {
        let mut store = cite_edge::auth::SessionStore::new(100, 100);
        let (a, _) = store.create("admin", 10).expect("a");
        let (b, _) = store.create("admin", 10).expect("b");
        let csrf_a = store.validate(&a, 11).expect("a live").csrf;
        let csrf_b = store.validate(&b, 11).expect("b live").csrf;
        assert_eq!(csrf_a.len(), 64);
        assert_ne!(csrf_a, csrf_b);
        assert_eq!(store.validate(&a, 12).expect("a live").csrf, csrf_a);
        let secret = a.split_once('.').expect("token shape").1;
        assert_ne!(csrf_a, secret);
    }

    #[test]
    fn csrf_is_bound_to_its_own_session() {
        let mut store = cite_edge::auth::SessionStore::new(100, 100);
        let (a, _) = store.create("admin", 10).expect("a");
        let (b, _) = store.create("admin", 10).expect("b");
        let csrf_a = store.validate(&a, 11).expect("a live").csrf;
        let csrf_b = store.validate(&b, 11).expect("b live").csrf;
        assert!(csrf_matches(&csrf_a, &csrf_a));
        assert!(!csrf_matches(&csrf_b, &csrf_a));
        assert!(!csrf_matches("", &csrf_a));
    }
}
