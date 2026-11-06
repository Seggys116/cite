use std::collections::HashMap;
use std::fmt::Display;

use axum::extract::{Path, Request, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use cite_edge::cloudflare::{CLOUDFLARE_RANGES_UPDATED, effective_ranges};
use cite_edge::model::{EdgeSettings, FirewallRule, MaintenancePage, Site, Slot, Target};
use cite_edge::presets::{preset, presets};
use cite_edge::ratelimit::client_key;
use cite_edge::validate::{
    is_valid_id, validate_page, validate_rule, validate_site, validate_site_strict,
};
use cite_store::TopKind;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::site_ops;
use super::{
    ApiError, ApiResult, AppState, JsonBody, MaybeJson, Params, Peer, Principal, lock_std,
    parse_json, read_body_limited,
};
use crate::store::{LoginOutcome, now_unix, unix_to_rfc3339};
use crate::{ConnectorError, logsink};

const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 1000;
const MAX_NAME_CHARS: usize = 64;
const MAX_NOTE_CHARS: usize = 256;
const MAX_GIT_REF_CHARS: usize = 128;
const MAX_GITHUB_TOKEN_BYTES: usize = 512;
const ORCHESTRATOR_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub(super) fn json_ok<T: Serialize + ?Sized>(value: &T) -> ApiResult<Response> {
    let body = serde_json::to_vec(value)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

fn ok_flag() -> Response {
    Json(json!({ "ok": true })).into_response()
}

fn missing(what: impl Display) -> ApiError {
    ConnectorError::NotFound(format!("{what} not found")).into()
}

pub(super) fn check_id(id: &str) -> ApiResult<()> {
    if is_valid_id(id) {
        Ok(())
    } else {
        Err(ApiError::bad("invalid id"))
    }
}

pub(super) fn valid_github_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_GITHUB_TOKEN_BYTES
        && token.bytes().all(|b| b.is_ascii_graphic())
}

fn clean_text(what: &str, raw: &str, max_chars: usize) -> ApiResult<String> {
    let text = raw.trim();
    if text.is_empty() || text.chars().count() > max_chars || text.chars().any(char::is_control) {
        return Err(ApiError::bad(format!(
            "{what} must be 1 to {max_chars} printable characters"
        )));
    }
    Ok(text.to_string())
}

// Oversized limits are clamped rather than rejected; zero and non-numbers are errors.
pub(super) fn parse_limit(q: &HashMap<String, String>) -> ApiResult<usize> {
    match q.get("limit") {
        None => Ok(DEFAULT_LIST_LIMIT),
        Some(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|n| *n >= 1)
            .map(|n| n.min(MAX_LIST_LIMIT))
            .ok_or_else(|| ApiError::bad("limit must be a positive integer")),
    }
}

pub(super) async fn healthz() -> Response {
    ok_flag()
}

pub(super) async fn not_found() -> Response {
    ApiError::new(axum::http::StatusCode::NOT_FOUND, "not found").into_response()
}

#[derive(Deserialize)]
pub(super) struct LoginReq {
    username: String,
    password: String,
    totp: String,
}

pub(super) async fn login(
    State(st): State<AppState>,
    Extension(peer): Extension<Peer>,
    JsonBody(req): JsonBody<LoginReq>,
) -> ApiResult<Response> {
    let ip = peer.addr.ip().to_canonical().to_string();
    let key = client_key(peer.addr.ip());
    // The attempt is counted before the hash runs, inside the store's login lock, so neither a burst nor a dropped connection gets free guesses; a correct login takes it back.
    let ticket = std::sync::Mutex::new(None);
    let admit = |now: u64| -> std::result::Result<(), u64> {
        let mut limiter = lock_std(&st.limiter);
        limiter.check(&key, now)?;
        *lock_std(&ticket) = Some(limiter.record_provisional_global(&key, now));
        Ok(())
    };
    let forgive = || {
        let taken = lock_std(&ticket).take();
        if let Some(t) = taken {
            lock_std(&st.limiter).forgive(t);
        }
    };
    let outcome = st
        .store
        .verify_login_gated(&req.username, &req.password, &req.totp, admit, forgive)
        .await?;
    match outcome {
        LoginOutcome::Blocked(retry) => return Err(ApiError::too_many(retry)),
        LoginOutcome::Rejected => {
            // The submitted username is never stored, since it may hold a pasted password.
            let known = st
                .store
                .credentials()
                .is_some_and(|c| c.username == req.username);
            let detail = format!("peer={ip} username_matched={known}");
            st.store.audit("anonymous", "login.failure", &detail).await;
            return Err(ConnectorError::Unauthorized("invalid credentials".into()).into());
        }
        LoginOutcome::Accepted => {}
    }
    lock_std(&st.limiter).record_success(&key);
    let (token, expires) = st.store.create_session(&req.username, now_unix())?;
    st.store
        .audit(&req.username, "login.success", &format!("peer={ip}"))
        .await;
    Ok(Json(json!({ "token": token, "expires_at": unix_to_rfc3339(expires) })).into_response())
}

pub(super) async fn logout(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Response> {
    if let Some(token) = &p.session_token {
        st.store.revoke_session(token);
    }
    st.store.audit(&p.actor(), "logout", "").await;
    Ok(ok_flag())
}

pub(super) async fn me(Extension(p): Extension<Principal>) -> Response {
    Json(json!({ "username": p.name, "kind": p.kind, "expires_at": p.expires_at })).into_response()
}

// API tokens must not be able to mint or revoke tokens, or a stolen one could outlive its own revocation.
fn require_session(p: &Principal) -> ApiResult<()> {
    if p.kind == "session" {
        Ok(())
    } else {
        Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "this action needs an interactive session",
        ))
    }
}

pub(super) async fn list_tokens(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Response> {
    require_session(&p)?;
    let items: Vec<Value> = st
        .store
        .list_api_tokens()
        .await
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "created_at": t.created_at,
                "last_used_at": t.last_used_at,
            })
        })
        .collect();
    json_ok(&items)
}

#[derive(Deserialize)]
pub(super) struct NameReq {
    name: String,
}

pub(super) async fn create_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    JsonBody(req): JsonBody<NameReq>,
) -> ApiResult<Response> {
    require_session(&p)?;
    let name = clean_text("name", &req.name, MAX_NAME_CHARS)?;
    let (meta, token) = st.store.create_api_token(&name).await?;
    let detail = format!("id={} name={name:?}", meta.id);
    st.store.audit(&p.actor(), "token.create", &detail).await;
    Ok(Json(json!({ "id": meta.id, "name": meta.name, "token": token })).into_response())
}

pub(super) async fn delete_token(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    require_session(&p)?;
    let well_formed = id.len() <= 32 && id.bytes().all(|b| b.is_ascii_hexdigit());
    if !well_formed || !st.store.revoke_api_token(&id).await? {
        return Err(missing("token"));
    }
    st.store
        .audit(&p.actor(), "token.revoke", &format!("id={id}"))
        .await;
    Ok(ok_flag())
}

pub(super) async fn node(State(st): State<AppState>) -> ApiResult<Response> {
    let cfg = st.store.config();
    // Probed live with a short timeout so a hung orchestrator cannot stall the node view.
    let reachable = match &st.orchestrator {
        Some(o) => matches!(
            tokio::time::timeout(ORCHESTRATOR_PING_TIMEOUT, o.ping()).await,
            Ok(Ok(()))
        ),
        None => false,
    };
    let haproxy = serde_json::to_value(st.haproxy.status())?;
    // A store that cannot be read yields null here; the failure is logged by the call.
    let analytics = analytics_overview(&st).await.ok();
    Ok(Json(json!({
        "name": st.cfg.node_name,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": st.started.elapsed().as_secs(),
        "haproxy": haproxy,
        "sites": cfg.sites.len(),
        "firewall_rules": cfg.firewall.len(),
        "orchestrator": { "enabled": st.orchestrator.is_some(), "reachable": reachable },
        "github": {
            "token_configured": st.cfg.github_token.is_some(),
            "source": st.cfg.github_token.as_ref().map_or("none", |t| t.source().as_str()),
            "api_host": site_ops::github_api_host(st.cfg.github_api_url.as_deref()),
        },
        "doppler": {
            "configured": st.cfg.doppler_token.is_some(),
            "source": st.cfg.doppler_token.as_ref().map_or("none", |t| t.source().as_str()),
        },
        "capabilities": site_ops::capabilities(st.orchestrator.is_some()),
        "executor_egress": st.orchestrator.as_ref().is_some_and(|o| o.executor_egress()),
        "analytics": analytics,
    }))
    .into_response())
}

pub(super) async fn reload(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Response> {
    // Detached like every other change, so a dropped connection cannot stop a reload halfway.
    let this = std::sync::Arc::clone(&st);
    let actor = p.actor();
    let out = crate::deploy::detach(async move {
        let _gate = this.deployer.config_lock().lock().await;
        // Forced, so certificates renewed on disk and an earlier failed reload are picked up.
        let out = this.haproxy.reload(&this.store.config()).await?;
        out.require_running()?;
        this.store
            .audit(&actor, "haproxy.reload", &out.config_hash)
            .await;
        Ok(out)
    })
    .await?;
    Ok(Json(json!({
        "ok": true,
        "config_hash": out.config_hash,
        "reloaded": out.reloaded,
    }))
    .into_response())
}

pub(super) async fn haproxy_config(State(st): State<AppState>) -> ApiResult<Response> {
    let text = st
        .haproxy
        .redacted_config_text(&st.store.config())
        .ok_or_else(|| missing("rendered configuration"))?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response())
}

#[derive(Serialize)]
struct StatsOut<'a> {
    backends: &'a [cite_edge::runtime::BackendStat],
}

pub(super) async fn haproxy_stats(State(st): State<AppState>) -> ApiResult<Response> {
    let stats = st.haproxy.stats().await?;
    json_ok(&StatsOut { backends: &stats })
}

pub(super) async fn get_settings(State(st): State<AppState>) -> ApiResult<Response> {
    let cfg = st.store.config();
    json_ok(&cfg.settings)
}

// The list HAProxy trusts as Cloudflare: the built-in copy unless the settings carry their own.
pub(super) async fn cloudflare_ranges(State(st): State<AppState>) -> ApiResult<Response> {
    let cfg = st.store.config();
    let source = if cfg.settings.cloudflare_ranges.is_empty() {
        "builtin"
    } else {
        "custom"
    };
    json_ok(&json!({
        "source": source,
        "updated": CLOUDFLARE_RANGES_UPDATED,
        "ranges": effective_ranges(&cfg.settings),
    }))
}

pub(super) async fn put_settings(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    JsonBody(settings): JsonBody<EdgeSettings>,
) -> ApiResult<Response> {
    // Retention reaches the analytics store only once the new settings were applied.
    let days = logsink::retention_days(&settings.retention);
    let archive = settings.retention.archive_before_delete;
    let before = st.store.config().settings.retention.clone();
    let (drop_ips, drop_agents) = (
        before.store_client_ips && !settings.retention.store_client_ips,
        before.store_user_agents && !settings.retention.store_user_agents,
    );
    st.mutate(&p.actor(), "settings.update", "", move |cfg| {
        cfg.settings = settings;
        Ok(())
    })
    .await?;
    st.analytics.set_retention_days(days);
    st.analytics.set_archive_before_delete(archive);
    let now_kept = st.store.config().settings.retention.clone();
    // Applied before the scrub so events still queued are stripped when they commit instead of re-creating the text.
    st.analytics
        .set_privacy(now_kept.store_client_ips, now_kept.store_user_agents);
    // Turning a field off also erases what was already stored, as the setting promises; the prune runs after it in the same task so no archive pass can read rows the scrub has not reached.
    let store = st.analytics.clone();
    let scrub = tokio::task::spawn_blocking(move || {
        let mut archives = None;
        if drop_ips || drop_agents {
            match store.scrub_fields(drop_ips, drop_agents) {
                Ok(rows) => tracing::info!(rows, "scrubbed stored analytics fields"),
                Err(e @ cite_store::Error::Incomplete(_)) => {
                    tracing::warn!(error = %e, "scrubbed analytics fields; the log fold is retried by the next retention pass");
                }
                Err(e) => tracing::warn!(error = %e, "scrubbing analytics fields failed"),
            }
            archives = Some(store.scrub_archived_fields(drop_ips, drop_agents));
        }
        // A shorter retention takes effect now instead of at the next scheduled prune.
        if let Err(e) = store.prune(now_ms()) {
            tracing::warn!(error = %e, "analytics prune after a settings change failed");
        }
        archives
    });
    let (actor, audit_state) = (p.actor(), st.clone());
    tokio::spawn(async move {
        match scrub.await {
            Ok(Some(Ok(done))) => {
                tracing::info!(
                    archives = done.archives,
                    backups = done.backups,
                    rows = done.rows,
                    failed = done.failed.len(),
                    "scrubbed archived analytics fields"
                );
                let detail = format!(
                    "archives={} backups={} rows={} failed={}",
                    done.archives,
                    done.backups,
                    done.rows,
                    done.failed.len()
                );
                audit_state
                    .store
                    .audit(&actor, "analytics.archive.scrub", &detail)
                    .await;
            }
            Ok(Some(Err(e))) => {
                tracing::warn!(error = %e, "scrubbing archived analytics fields failed");
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "analytics scrub task failed"),
        }
    });
    let cfg = st.store.config();
    json_ok(&cfg.settings)
}

pub(super) async fn audit_log(
    State(st): State<AppState>,
    Params(q): Params,
) -> ApiResult<Response> {
    let limit = parse_limit(&q)?;
    json_ok(&st.store.audit_tail(limit).await)
}

pub(super) fn find_site(st: &AppState, id: &str) -> ApiResult<Site> {
    let cfg = st.store.config();
    cfg.sites
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .ok_or_else(|| missing(format!("site {id}")))
}

pub(super) async fn list_sites(State(st): State<AppState>) -> ApiResult<Response> {
    let cfg = st.store.config();
    json_ok(&cfg.sites)
}

pub(super) async fn create_site(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    JsonBody(mut body): JsonBody<Value>,
) -> ApiResult<Response> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| ApiError::bad("site must be a JSON object"))?;
    // The token rides along with the site payload but is never stored inside the Site.
    let token = match obj.remove("github_token") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if valid_github_token(&s) => Some(s),
        Some(_) => return Err(ApiError::bad("github_token must be a non-empty string")),
    };
    obj.remove("history");
    let site: Site =
        serde_json::from_value(body).map_err(|e| ApiError::bad(format!("invalid site: {e}")))?;
    validate_site_strict(&site)?;
    if st.store.config().sites.iter().any(|s| s.id == site.id) {
        return Err(ConnectorError::Conflict(format!("site {} already exists", site.id)).into());
    }
    let created = st.deployer.create_site(&p.actor(), site, token).await?;
    json_ok(&created)
}

pub(super) async fn get_site(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    let site = find_site(&st, &id)?;
    // A stopped HAProxy must not make the site unreadable, so live state degrades to empty.
    let live = match st.deployer.live(&id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(site = %id, error = %e, "live upstream state unavailable");
            json!({ "blue": [], "green": [] })
        }
    };
    let mut value = serde_json::to_value(&site)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("live".into(), live);
    }
    json_ok(&value)
}

pub(super) async fn put_site(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(site): JsonBody<Site>,
) -> ApiResult<Response> {
    check_id(&id)?;
    if site.id != id {
        return Err(ApiError::bad("site id in the body must match the path"));
    }
    validate_site_strict(&site)?;
    find_site(&st, &id)?;
    let updated = st.deployer.update_site(&p.actor(), site).await?;
    json_ok(&updated)
}

pub(super) async fn delete_site(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Params(q): Params,
) -> ApiResult<Response> {
    check_id(&id)?;
    if let Some(unknown) = q.keys().find(|k| k.as_str() != "purge_volumes") {
        return Err(ApiError::bad(format!(
            "unknown query parameter {unknown:?}"
        )));
    }
    let purge_volumes = match q.get("purge_volumes").map(String::as_str) {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(ApiError::bad("purge_volumes must be true or false")),
    };
    find_site(&st, &id)?;
    st.deployer
        .delete_site_with(&p.actor(), &id, purge_volumes)
        .await?;
    if purge_volumes {
        st.store
            .audit(&p.actor(), "site.volumes.purge", &format!("site={id}"))
            .await;
    }
    Ok(ok_flag())
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeployReq {
    targets: Option<Vec<Target>>,
    note: Option<String>,
    git_ref: Option<String>,
    // Absent keeps the blocking behaviour; false answers 202 once the deploy is accepted.
    wait: Option<bool>,
}

fn valid_git_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_GIT_REF_CHARS
        && !s.starts_with('-')
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

pub(super) async fn deploy_site(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    MaybeJson(req): MaybeJson<DeployReq>,
) -> ApiResult<Response> {
    check_id(&id)?;
    let site = find_site(&st, &id)?;
    if let Some(targets) = &req.targets {
        if targets.is_empty() {
            return Err(ApiError::bad("targets must not be empty"));
        }
        // Targets are checked by validating a copy of the site that carries them.
        let mut probe = site.clone();
        probe.blue.targets = targets.clone();
        validate_site(&probe)?;
    }
    let note = match &req.note {
        Some(n) if !n.trim().is_empty() => Some(clean_text("note", n, MAX_NOTE_CHARS)?),
        _ => None,
    };
    if let Some(r) = &req.git_ref
        && !valid_git_ref(r)
    {
        return Err(ApiError::bad("git_ref contains unsupported characters"));
    }
    let wait = req.wait.unwrap_or(true);
    let outcome = st
        .deployer
        .deploy(&p.actor(), &id, req.targets, note, req.git_ref, wait)
        .await?;
    let mut res = json_ok(&outcome)?;
    if !wait {
        *res.status_mut() = axum::http::StatusCode::ACCEPTED;
    }
    Ok(res)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SwitchReq {
    slot: Slot,
}

pub(super) async fn switch_site(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<SwitchReq>,
) -> ApiResult<Response> {
    check_id(&id)?;
    find_site(&st, &id)?;
    let deployment = st.deployer.switch(&p.actor(), &id, req.slot).await?;
    json_ok(&deployment)
}

pub(super) async fn rollback_site(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    find_site(&st, &id)?;
    let deployment = st.deployer.rollback(&p.actor(), &id).await?;
    json_ok(&deployment)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MaintenanceReq {
    enabled: bool,
    #[serde(default)]
    page_id: Option<String>,
}

pub(super) async fn site_maintenance(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<MaintenanceReq>,
) -> ApiResult<Response> {
    check_id(&id)?;
    find_site(&st, &id)?;
    if let Some(page) = &req.page_id {
        check_id(page)?;
    }
    let site = st
        .deployer
        .set_maintenance(&p.actor(), &id, req.enabled, req.page_id)
        .await?;
    json_ok(&site)
}

pub(super) async fn list_pages(State(st): State<AppState>) -> ApiResult<Response> {
    let cfg = st.store.config();
    json_ok(&cfg.pages)
}

pub(super) async fn get_page(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    let cfg = st.store.config();
    let page = cfg
        .pages
        .iter()
        .find(|x| x.id == id)
        .ok_or_else(|| missing(format!("page {id}")))?;
    json_ok(page)
}

pub(super) async fn create_page(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    JsonBody(page): JsonBody<MaintenancePage>,
) -> ApiResult<Response> {
    validate_page(&page)?;
    let created = page.clone();
    let id = page.id.clone();
    st.mutate(&p.actor(), "page.create", &id, move |cfg| {
        if cfg.pages.iter().any(|x| x.id == page.id) {
            return Err(ConnectorError::Conflict(format!(
                "page {} already exists",
                page.id
            )));
        }
        cfg.pages.push(page);
        Ok(())
    })
    .await?;
    json_ok(&created)
}

pub(super) async fn put_page(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(page): JsonBody<MaintenancePage>,
) -> ApiResult<Response> {
    check_id(&id)?;
    if page.id != id {
        return Err(ApiError::bad("page id in the body must match the path"));
    }
    validate_page(&page)?;
    let saved = page.clone();
    st.mutate(&p.actor(), "page.update", &id, move |cfg| {
        let slot = cfg
            .pages
            .iter_mut()
            .find(|x| x.id == page.id)
            .ok_or_else(|| ConnectorError::NotFound(format!("page {} not found", page.id)))?;
        *slot = page;
        Ok(())
    })
    .await?;
    json_ok(&saved)
}

pub(super) async fn delete_page(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    // Config validation would catch a page in use too, but this names the site holding it.
    let page_id = id.clone();
    st.mutate(&p.actor(), "page.delete", &id, move |cfg| {
        let id = page_id;
        if let Some(site) = cfg
            .sites
            .iter()
            .find(|s| s.maintenance.page_id.as_deref() == Some(id.as_str()))
        {
            return Err(ConnectorError::Conflict(format!(
                "page {id} is in use by site {}",
                site.id
            )));
        }
        let before = cfg.pages.len();
        cfg.pages.retain(|x| x.id != id);
        if cfg.pages.len() == before {
            return Err(ConnectorError::NotFound(format!("page {id} not found")));
        }
        Ok(())
    })
    .await?;
    Ok(ok_flag())
}

// A header value marked secret is write-only: it is blanked in every response, and left empty in a request it means "keep the stored value".
fn redacted(rule: &FirewallRule) -> FirewallRule {
    let mut out = rule.clone();
    for header in out.matchers.headers.iter_mut().filter(|h| h.secret) {
        header.equals = header.equals.as_ref().map(|_| String::new());
        header.regex = header.regex.as_ref().map(|_| String::new());
    }
    out
}

// A blank value on a secret header takes the stored one of the same name; repeated names pair up in order.
pub(super) fn keep_stored_secret(
    rule: &mut FirewallRule,
    stored: Option<&FirewallRule>,
) -> std::result::Result<(), ConnectorError> {
    let blank = |v: &Option<String>| v.as_ref().is_some_and(String::is_empty);
    let rule_id = rule.id.clone();
    for at in 0..rule.matchers.headers.len() {
        let header = &rule.matchers.headers[at];
        if !header.secret || (!blank(&header.equals) && !blank(&header.regex)) {
            continue;
        }
        let nth = rule.matchers.headers[..at]
            .iter()
            .filter(|h| h.secret && h.name.eq_ignore_ascii_case(&header.name))
            .count();
        // a blank row only stands for a stored value when that is unambiguous: with repeated names the request cannot say which one it means
        let same_name = |r: &FirewallRule| {
            r.matchers
                .headers
                .iter()
                .filter(|h| h.secret && h.name.eq_ignore_ascii_case(&header.name))
                .count()
        };
        if stored.is_some_and(|r| same_name(r) > 1) {
            return Err(ConnectorError::BadRequest(format!(
                "rule {rule_id}: header {} has several secret values, so a blank one cannot be matched to a stored value: enter each value again",
                header.name
            )));
        }
        let old = stored.and_then(|r| {
            r.matchers
                .headers
                .iter()
                .filter(|h| h.secret && h.name.eq_ignore_ascii_case(&header.name))
                .nth(nth)
        });
        let Some(old) = old.cloned() else {
            return Err(ConnectorError::BadRequest(format!(
                "rule {rule_id}: a secret header value cannot be left empty: there is no stored value for header {} to keep",
                header.name
            )));
        };
        let header = &mut rule.matchers.headers[at];
        if blank(&header.equals) {
            header.equals = old.equals;
        }
        if blank(&header.regex) {
            header.regex = old.regex;
        }
    }
    Ok(())
}

pub(super) async fn list_rules(State(st): State<AppState>) -> ApiResult<Response> {
    let cfg = st.store.config();
    let rules: Vec<FirewallRule> = cfg.firewall.iter().map(redacted).collect();
    json_ok(&rules)
}

pub(super) async fn create_rule(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    JsonBody(rule): JsonBody<FirewallRule>,
) -> ApiResult<Response> {
    let created = redacted(&rule);
    let id = rule.id.clone();
    st.mutate(&p.actor(), "firewall.create", &id, move |cfg| {
        // the stored value is read under the config lock, so a concurrent edit cannot be overwritten with a stale one
        let mut rule = rule;
        let rule_id = rule.id.clone();
        keep_stored_secret(&mut rule, cfg.firewall.iter().find(|x| x.id == rule_id))?;
        validate_rule(&rule)?;
        if cfg.firewall.iter().any(|x| x.id == rule.id) {
            return Err(ConnectorError::Conflict(format!(
                "rule {} already exists",
                rule.id
            )));
        }
        cfg.firewall.push(rule);
        Ok(())
    })
    .await?;
    json_ok(&created)
}

pub(super) async fn put_rule(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(rule): JsonBody<FirewallRule>,
) -> ApiResult<Response> {
    check_id(&id)?;
    if rule.id != id {
        return Err(ApiError::bad("rule id in the body must match the path"));
    }
    let saved = redacted(&rule);
    st.mutate(&p.actor(), "firewall.update", &id, move |cfg| {
        let mut rule = rule;
        let slot = cfg
            .firewall
            .iter_mut()
            .find(|x| x.id == rule.id)
            .ok_or_else(|| ConnectorError::NotFound(format!("rule {} not found", rule.id)))?;
        keep_stored_secret(&mut rule, Some(&*slot))?;
        validate_rule(&rule)?;
        *slot = rule;
        Ok(())
    })
    .await?;
    json_ok(&saved)
}

pub(super) async fn delete_rule(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    check_id(&id)?;
    let rule_id = id.clone();
    st.mutate(&p.actor(), "firewall.delete", &id, move |cfg| {
        let id = rule_id;
        let before = cfg.firewall.len();
        cfg.firewall.retain(|x| x.id != id);
        if cfg.firewall.len() == before {
            return Err(ConnectorError::NotFound(format!("rule {id} not found")));
        }
        Ok(())
    })
    .await?;
    Ok(ok_flag())
}

const BULK_MAX_RULES: usize = 200;
const BULK_MAX_BODY_BYTES: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BulkReq {
    #[serde(default)]
    replace: Vec<FirewallRule>,
    #[serde(default)]
    delete: Vec<String>,
}

// Rejects what no config could satisfy, before the config lock is taken.
fn check_bulk(req: &BulkReq) -> ApiResult<()> {
    if req.replace.is_empty() && req.delete.is_empty() {
        return Err(ApiError::bad(
            "replace or delete must list at least one rule",
        ));
    }
    if req.replace.len() > BULK_MAX_RULES || req.delete.len() > BULK_MAX_RULES {
        return Err(ApiError::bad(format!(
            "replace and delete take at most {BULK_MAX_RULES} rules each"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for rule in &req.replace {
        check_id(&rule.id)?;
        if !seen.insert(rule.id.as_str()) {
            return Err(ApiError::bad(format!(
                "rule {} appears more than once in replace",
                rule.id
            )));
        }
    }
    let mut dropped = std::collections::HashSet::new();
    for id in &req.delete {
        check_id(id)?;
        if !dropped.insert(id.as_str()) {
            return Err(ApiError::bad(format!(
                "rule {id} appears more than once in delete"
            )));
        }
        if seen.contains(id.as_str()) {
            return Err(ApiError::bad(format!(
                "rule {id} is in both replace and delete"
            )));
        }
    }
    Ok(())
}

// Creates or replaces many rules and deletes others as one change: one validation of the result, one render, one apply and one audit entry.
pub(super) async fn bulk_rules(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    req: Request,
) -> ApiResult<Response> {
    let bytes = read_body_limited(req, BULK_MAX_BODY_BYTES).await?;
    if bytes.is_empty() {
        return Err(ApiError::bad("request body is required"));
    }
    let body: BulkReq = parse_json(&bytes)?;
    check_bulk(&body)?;
    let ids: Vec<&str> = body
        .replace
        .iter()
        .map(|r| r.id.as_str())
        .chain(body.delete.iter().map(String::as_str))
        .collect();
    let detail = format!(
        "replace={} delete={} ids={}",
        body.replace.len(),
        body.delete.len(),
        ids.join(",")
    );
    let (created, replaced, deleted, ignored) = st
        .mutate(&p.actor(), "firewall.bulk", &detail, move |cfg| {
            let (mut created, mut replaced) = (Vec::new(), Vec::new());
            for mut rule in body.replace {
                let at = cfg.firewall.iter().position(|x| x.id == rule.id);
                keep_stored_secret(&mut rule, at.map(|i| &cfg.firewall[i]))?;
                validate_rule(&rule).map_err(|e| {
                    ConnectorError::BadRequest(format!("rule {}: {}", rule.id, e.0))
                })?;
                let shown = redacted(&rule);
                match at {
                    Some(i) => {
                        cfg.firewall[i] = rule;
                        replaced.push(shown);
                    }
                    None => {
                        cfg.firewall.push(rule);
                        created.push(shown);
                    }
                }
            }
            let (mut deleted, mut ignored) = (0usize, 0usize);
            for id in &body.delete {
                match cfg.firewall.iter().position(|x| &x.id == id) {
                    Some(i) => {
                        cfg.firewall.remove(i);
                        deleted += 1;
                    }
                    None => ignored += 1,
                }
            }
            Ok((created, replaced, deleted, ignored))
        })
        .await?;
    json_ok(&json!({
        "created": created.len(),
        "replaced": replaced.len(),
        "deleted": deleted,
        "ignored": ignored,
        "rules": { "created": created, "replaced": replaced },
    }))
}

#[derive(Serialize)]
struct PresetOut {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    rules: Vec<FirewallRule>,
}

pub(super) async fn list_presets() -> ApiResult<Response> {
    let items: Vec<PresetOut> = presets()
        .into_iter()
        .map(|p| PresetOut {
            name: p.name,
            title: p.title,
            description: p.description,
            rules: p.rules,
        })
        .collect();
    json_ok(&items)
}

pub(super) async fn apply_preset(
    State(st): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(name): Path<String>,
) -> ApiResult<Response> {
    let chosen = preset(&name).ok_or_else(|| missing(format!("preset {name:?}")))?;
    let added = st
        .mutate(&p.actor(), "firewall.preset", chosen.name, move |cfg| {
            let mut added = Vec::new();
            for rule in chosen.rules {
                match cfg.firewall.iter().position(|x| x.id == rule.id) {
                    // a rule with the preset's id is refreshed to the current definition, keeping the owner's on/off choice and site scope
                    Some(at) => {
                        let existing = &mut cfg.firewall[at];
                        let refreshed = FirewallRule {
                            enabled: existing.enabled,
                            site: existing.site.clone(),
                            ..rule
                        };
                        if *existing != refreshed {
                            *existing = refreshed.clone();
                            added.push(refreshed);
                        }
                    }
                    None => {
                        cfg.firewall.push(rule.clone());
                        added.push(rule);
                    }
                }
            }
            Ok(added)
        })
        .await?;
    json_ok(&added)
}

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn join_failure(e: tokio::task::JoinError) -> ApiError {
    ConnectorError::Internal(format!("analytics task failed: {e}")).into()
}

// The detail is logged by the Internal mapping and the client only sees a generic 500.
pub(super) fn store_failure(e: cite_store::Error) -> ApiError {
    match e {
        cite_store::Error::Timeout => ConnectorError::Unavailable(
            "the analytics query took too long and was cancelled; try a shorter window".into(),
        )
        .into(),
        cite_store::Error::Rejected(_) => ConnectorError::BadRequest(e.to_string()).into(),
        cite_store::Error::NotFound(_) => ConnectorError::NotFound(e.to_string()).into(),
        cite_store::Error::Conflict(_) => ConnectorError::Conflict(e.to_string()).into(),
        // The archive messages are written for operators and hold no paths.
        cite_store::Error::Archive(_) => ConnectorError::Unavailable(e.to_string()).into(),
        _ => ConnectorError::Internal(format!("analytics store: {e}")).into(),
    }
}

// Queries run off the async workers so a large window cannot stall other requests.
pub(super) async fn with_store<T: Send + 'static>(
    st: &AppState,
    f: impl FnOnce(&cite_store::Store) -> cite_store::Result<T> + Send + 'static,
) -> ApiResult<T> {
    let store = st.analytics.clone();
    tokio::task::spawn_blocking(move || f(store.as_ref()))
        .await
        .map_err(join_failure)?
        .map_err(store_failure)
}

pub(super) fn parse_top_kind(raw: &str) -> ApiResult<TopKind> {
    Ok(match raw {
        "paths" => TopKind::Paths,
        "hosts" => TopKind::Hosts,
        "referers" => TopKind::Referers,
        "agents" => TopKind::UserAgents,
        "content_types" => TopKind::ContentTypes,
        "statuses" => TopKind::StatusCodes,
        "ips" => TopKind::ClientIps,
        "languages" => TopKind::Languages,
        _ => {
            return Err(ApiError::bad(
                "kind must be one of paths, hosts, referers, agents, content_types, statuses, ips, languages",
            ));
        }
    })
}

// Store counters plus the settings that shape them; fields only ever get added.
#[derive(Serialize)]
struct AnalyticsOverview {
    #[serde(flatten)]
    store: cite_store::StoreStats,
    retention_days: u32,
    archive_before_delete: bool,
    max_bytes: Option<u64>,
    ingest_stalls: u64,
}

async fn analytics_overview(st: &AppState) -> ApiResult<AnalyticsOverview> {
    let store = with_store(st, |s| {
        let stats = s.stats()?;
        Ok((
            stats,
            s.retention_days(),
            s.max_bytes(),
            s.archive_before_delete(),
        ))
    })
    .await?;
    Ok(AnalyticsOverview {
        store: store.0,
        retention_days: store.1,
        archive_before_delete: store.3,
        max_bytes: store.2,
        ingest_stalls: st.ingest.stalls(),
    })
}

pub(super) async fn analytics_stats(State(st): State<AppState>) -> ApiResult<Response> {
    json_ok(&analytics_overview(&st).await?)
}

pub(super) fn parse_method(raw: &str) -> ApiResult<String> {
    let ok = raw.len() <= 16 && raw.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-');
    if ok {
        Ok(raw.to_ascii_uppercase())
    } else {
        Err(ApiError::bad("method must be an HTTP method token"))
    }
}
