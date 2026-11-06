use std::collections::HashMap;
use std::fmt;

use crate::siteops::{LogQuery, LogSource};
use axum::Extension;
use axum::extract::{FromRequest, Path, Request, State};
use axum::response::Response;
use cite_edge::model::{Site, Slot};
use cite_edge::status::{BuildEnvPatch, CAPABILITIES};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::{Zeroize, Zeroizing};

use super::handlers::{check_id, find_site, json_ok, valid_github_token};
use super::{ApiError, ApiResult, AppState, Params, Principal, parse_json, read_body_limited};

const MAX_OPS_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_TAIL: u32 = 200;
const MAX_TAIL: u32 = 1000;
const MAX_CURSOR_BYTES: usize = 256;
const DEFAULT_API_HOST: &str = "api.github.com";
// Capability names containing these need the orchestrator; certificate, alert and status ones do not.
const ORCHESTRATED: [&str; 5] = ["logs", "token", "env", "build", "doppler"];

pub(super) fn capabilities(orchestrated: bool) -> Vec<String> {
    CAPABILITIES
        .iter()
        .filter(|cap| orchestrated || !ORCHESTRATED.iter().any(|needle| cap.contains(needle)))
        .map(|cap| (*cap).to_string())
        .collect()
}

// Host only: no scheme, credentials, port or path, so nothing sensitive can ride along.
pub(super) fn github_api_host(url: Option<&str>) -> String {
    let Some(url) = url else {
        return DEFAULT_API_HOST.to_string();
    };
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    if host.is_empty() {
        DEFAULT_API_HOST.to_string()
    } else {
        host.to_ascii_lowercase()
    }
}

// A small body cap for these routes: a token or a name patch never needs more.
pub(super) struct SmallBody<T>(T);

impl<S, T> FromRequest<S> for SmallBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> ApiResult<Self> {
        let bytes = read_body_limited(req, MAX_OPS_BODY_BYTES).await?;
        if bytes.is_empty() {
            return Err(ApiError::bad("request body is required"));
        }
        parse_json(&bytes).map(SmallBody)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenReq {
    token: String,
}

impl Drop for TokenReq {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl fmt::Debug for TokenReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenReq")
            .field("token", &"<redacted>")
            .finish()
    }
}

// Every site route needs a known site; the ones that talk to the stack need a repo-built one.
fn source_site(st: &AppState, id: &str) -> ApiResult<Site> {
    check_id(id)?;
    let site = find_site(st, id)?;
    if site.source.is_none() {
        return Err(ApiError::bad(
            "this site is not built from a repository, so it has no build or runtime settings",
        ));
    }
    Ok(site)
}

pub(super) async fn status(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    find_site(&st, &id)?;
    let status = st.deployer.site_status(&id).await?;
    json_ok(&status)
}

fn parse_logs_query(q: &HashMap<String, String>) -> ApiResult<LogQuery> {
    if let Some(unknown) = q
        .keys()
        .find(|k| !matches!(k.as_str(), "source" | "slot" | "tail" | "since"))
    {
        return Err(ApiError::bad(format!(
            "unknown query parameter {unknown:?}"
        )));
    }
    let source = match q.get("source").map(String::as_str) {
        None | Some("manager") => LogSource::Manager,
        Some("executor") => LogSource::Executor,
        Some(_) => return Err(ApiError::bad("source must be manager or executor")),
    };
    let slot = match q.get("slot").map(String::as_str) {
        None => None,
        Some("blue") => Some(Slot::Blue),
        Some("green") => Some(Slot::Green),
        Some(_) => return Err(ApiError::bad("slot must be blue or green")),
    };
    let tail = match q.get("tail") {
        None => DEFAULT_TAIL,
        Some(raw) => raw
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=MAX_TAIL).contains(n))
            .ok_or_else(|| ApiError::bad(format!("tail must be between 1 and {MAX_TAIL}")))?,
    };
    let since = match q.get("since") {
        None => None,
        Some(c)
            if !c.is_empty()
                && c.len() <= MAX_CURSOR_BYTES
                && c.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            Some(c.clone())
        }
        Some(_) => return Err(ApiError::bad("since is not a valid cursor")),
    };
    Ok(LogQuery {
        source,
        slot,
        tail,
        since,
    })
}

pub(super) async fn logs(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Params(q): Params,
) -> ApiResult<Response> {
    let query = parse_logs_query(&q)?;
    source_site(&st, &id)?;
    let out = st.deployer.site_logs(&id, query).await?;
    json_ok(&out)
}

pub(super) async fn get_token(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    json_ok(&st.deployer.token_status(&id).await?)
}

pub(super) async fn put_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    SmallBody(mut req): SmallBody<TokenReq>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    if !valid_github_token(&req.token) {
        return Err(ApiError::bad("token must be a non-empty string"));
    }
    // Moving the buffer into Zeroizing wipes it once the token is stored, on every path.
    let token = Zeroizing::new(std::mem::take(&mut req.token));
    let out = st.deployer.set_site_token(&p.actor(), &id, token).await?;
    st.store
        .audit(&p.actor(), "site.token.set", &format!("site={id}"))
        .await;
    json_ok(&out)
}

pub(super) async fn delete_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    let out = st.deployer.clear_site_token(&p.actor(), &id).await?;
    st.store
        .audit(&p.actor(), "site.token.clear", &format!("site={id}"))
        .await;
    json_ok(&out)
}

pub(super) async fn get_build_env(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    json_ok(&st.deployer.build_env_names(&id).await?)
}

pub(super) async fn patch_build_env(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    SmallBody(patch): SmallBody<BuildEnvPatch>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    patch.validate().map_err(|e| ApiError::bad(e.to_string()))?;
    let out = st.deployer.patch_build_env(&p.actor(), &id, patch).await?;
    st.store
        .audit(&p.actor(), "site.build_env.patch", &format!("site={id}"))
        .await;
    json_ok(&out)
}

pub(super) async fn get_runtime_env(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    json_ok(&st.deployer.runtime_env_names(&id).await?)
}

pub(super) async fn patch_runtime_env(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    SmallBody(patch): SmallBody<BuildEnvPatch>,
) -> ApiResult<Response> {
    source_site(&st, &id)?;
    patch
        .validate_runtime()
        .map_err(|e| ApiError::bad(e.to_string()))?;
    let out = st
        .deployer
        .patch_runtime_env(&p.actor(), &id, patch)
        .await?;
    st.store
        .audit(&p.actor(), "site.runtime_env.patch", &format!("site={id}"))
        .await;
    json_ok(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_api_host_is_the_bare_lowercase_host() {
        for (url, host) in [
            (None, "api.github.com"),
            (Some("https://api.github.com"), "api.github.com"),
            (Some("https://GHE.Example.com/api/v3"), "ghe.example.com"),
            (
                Some("http://ghe.example.com:8443/api/v3/"),
                "ghe.example.com",
            ),
            (Some("https://ghe.example.com?x=1"), "ghe.example.com"),
            (Some(""), "api.github.com"),
        ] {
            assert_eq!(github_api_host(url), host, "{url:?}");
        }
    }

    #[test]
    fn logs_queries_are_validated_strictly() {
        let q = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<HashMap<_, _>>()
        };
        let ok = parse_logs_query(&q(&[])).expect("defaults");
        assert_eq!(ok.tail, 200);
        assert!(ok.slot.is_none() && ok.since.is_none());
        for bad in [
            q(&[("source", "other")]),
            q(&[("slot", "red")]),
            q(&[("tail", "0")]),
            q(&[("tail", "1001")]),
            q(&[("tail", "-1")]),
            q(&[("since", "")]),
            q(&[("since", "a b")]),
            q(&[("junk", "1")]),
        ] {
            assert!(parse_logs_query(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_logs_query(&q(&[("tail", "1000")])).unwrap().tail,
            1000
        );
    }

    #[test]
    fn the_token_request_never_prints_its_token() {
        let req = TokenReq {
            token: "ghp_secretvalue".into(),
        };
        assert!(!format!("{req:?}").contains("ghp_secretvalue"));
    }
}
