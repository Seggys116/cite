//! In-process GitHub REST API mock for Cite manager tests.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Deserialize;
use serde_json::json;
use tar::{Builder, Header};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const INITIAL_TOKEN: &str = "ghp_citeMockGithubPat00000000000000001";
const RATE_LIMIT: u32 = 5000;

const PACKAGE_JSON: &str =
    r#"{"name":"site","scripts":{"build":"node build.js"},"dependencies":{"vite":"^6"}}"#;
const INDEX_HTML: &str = "<html>v1</html>";
const BUILD_JS: &str = r#"const fs = require("fs");
fs.mkdirSync("dist", { recursive: true });
fs.copyFileSync("index.html", "dist/index.html");
"#;

/// In-process mock of the GitHub REST endpoints Cite needs.
pub struct MockGithub {
    base_url: String,
    token: String,
    state: Arc<AppState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

struct AppState {
    token: String,
    authorized: AtomicBool,
    rate_remaining: AtomicU32,
    expiry: Mutex<Option<String>>,
    repo: Mutex<RepoState>,
    /// When set, `GET .../tarball/{sha}` returns these bytes instead of a built archive.
    raw_tarballs: Mutex<HashMap<String, Vec<u8>>>,
    /// Extra wait before every tarball response. Zero in normal tests.
    tarball_delay_ms: AtomicU64,
}

struct RepoState {
    /// branch name → head sha
    branches: HashMap<String, String>,
    commits: HashMap<String, Commit>,
}

#[derive(Clone)]
struct Commit {
    sha: String,
    message: String,
    author: String,
    date: String,
    /// repo-relative path → file bytes
    files: HashMap<String, Vec<u8>>,
}

impl MockGithub {
    /// Bind `127.0.0.1:0`, seed `main` with an initial commit, and serve.
    pub async fn spawn() -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::bind("127.0.0.1:0").await
    }

    /// Bind `listen` (for example `0.0.0.0:8080`), seed `main`, and serve.
    pub async fn bind(
        listen: &str,
    ) -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let token = INITIAL_TOKEN.to_owned();
        let initial = seed_initial_commit();
        let mut branches = HashMap::new();
        branches.insert("main".to_owned(), initial.sha.clone());
        let mut commits = HashMap::new();
        commits.insert(initial.sha.clone(), initial);

        let state = Arc::new(AppState {
            token: token.clone(),
            authorized: AtomicBool::new(true),
            rate_remaining: AtomicU32::new(RATE_LIMIT),
            expiry: Mutex::new(None),
            repo: Mutex::new(RepoState { branches, commits }),
            raw_tarballs: Mutex::new(HashMap::new()),
            tarball_delay_ms: AtomicU64::new(0),
        });

        let listener = TcpListener::bind(listen).await?;
        let addr = listener.local_addr()?;
        let base_url = format!("http://{addr}");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let app = router(Arc::clone(&state));

        let join = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .ok();
        });

        Ok(Self {
            base_url,
            token,
            state,
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
        })
    }

    /// `http://127.0.0.1:PORT` with no trailing slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Mock PAT; starts with `ghp_`.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Commit `files` over the parent tree on `branch`; returns the 40-hex sha.
    pub async fn push_files(
        &self,
        branch: &str,
        message: &str,
        author: &str,
        files: Vec<(String, Vec<u8>)>,
    ) -> String {
        apply_push(&self.state, branch, message, author, files)
    }

    /// Hold every tarball response for `delay` so a caller can interrupt a fetch.
    pub fn set_tarball_delay(&self, delay: std::time::Duration) {
        self.state
            .tarball_delay_ms
            .store(delay.as_millis() as u64, Ordering::Relaxed);
    }

    /// Serve `bytes` for `GET /tarball/{sha}` instead of packing the commit tree.
    pub fn set_raw_tarball(&self, sha: &str, bytes: Vec<u8>) {
        self.state
            .raw_tarballs
            .lock()
            .expect("raw tarball lock")
            .insert(sha.to_owned(), bytes);
    }

    /// Current head sha for `branch`, if any.
    #[must_use]
    pub fn head_sha(&self, branch: &str) -> Option<String> {
        self.state
            .repo
            .lock()
            .expect("repo lock")
            .branches
            .get(branch)
            .cloned()
    }

    /// When `false`, all authenticated routes return 401.
    pub fn set_authorized(&self, ok: bool) {
        self.state.authorized.store(ok, Ordering::SeqCst);
    }

    /// Value returned in `X-RateLimit-Remaining`. `0` → 403 + `Retry-After: 1`.
    pub fn set_rate_remaining(&self, remaining: u32) {
        self.state.rate_remaining.store(remaining, Ordering::SeqCst);
    }

    /// Optional `GitHub-Authentication-Token-Expiration` header value.
    pub fn set_expiry(&self, rfc3339: Option<String>) {
        *self.state.expiry.lock().expect("expiry lock") = rfc3339;
    }

    /// Stop the server and wait for the accept loop to finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

fn seed_initial_commit() -> Commit {
    let mut files = HashMap::new();
    files.insert("package.json".to_owned(), PACKAGE_JSON.as_bytes().to_vec());
    files.insert("index.html".to_owned(), INDEX_HTML.as_bytes().to_vec());
    files.insert("build.js".to_owned(), BUILD_JS.as_bytes().to_vec());
    let message = "initial commit";
    let author = "cite-mock";
    let date = "2024-01-01T00:00:00Z".to_owned();
    let sha = compute_sha(message, author, &date, None, &files);
    Commit {
        sha,
        message: message.to_owned(),
        author: author.to_owned(),
        date,
        files,
    }
}

fn compute_sha(
    message: &str,
    author: &str,
    date: &str,
    parent: Option<&str>,
    files: &HashMap<String, Vec<u8>>,
) -> String {
    let mut paths: Vec<&String> = files.keys().collect();
    paths.sort();

    let mut h1 = std::collections::hash_map::DefaultHasher::new();
    message.hash(&mut h1);
    author.hash(&mut h1);
    date.hash(&mut h1);
    parent.hash(&mut h1);
    for p in &paths {
        p.hash(&mut h1);
        files[*p].hash(&mut h1);
    }
    let a = h1.finish();

    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    0xC1_7E_u64.hash(&mut h2);
    a.hash(&mut h2);
    for p in &paths {
        files[*p].len().hash(&mut h2);
    }
    let b = h2.finish();

    let mut h3 = std::collections::hash_map::DefaultHasher::new();
    b.hash(&mut h3);
    files.len().hash(&mut h3);
    let c = h3.finish();

    format!("{a:016x}{b:016x}{:08x}", c & 0xffff_ffff)
}

fn now_rfc3339() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("2024-01-01T00:00:{:02}.{:06}Z", n % 60, n % 1_000_000)
}

fn apply_push(
    state: &AppState,
    branch: &str,
    message: &str,
    author: &str,
    files: Vec<(String, Vec<u8>)>,
) -> String {
    let mut repo = state.repo.lock().expect("repo lock");
    let parent_sha = repo.branches.get(branch).cloned();
    let mut tree = parent_sha
        .as_ref()
        .and_then(|sha| repo.commits.get(sha))
        .map(|c| c.files.clone())
        .unwrap_or_default();
    for (path, bytes) in files {
        tree.insert(path, bytes);
    }
    let date = now_rfc3339();
    let sha = compute_sha(message, author, &date, parent_sha.as_deref(), &tree);
    let commit = Commit {
        sha: sha.clone(),
        message: message.to_owned(),
        author: author.to_owned(),
        date,
        files: tree,
    };
    repo.commits.insert(sha.clone(), commit);
    repo.branches.insert(branch.to_owned(), sha.clone());
    sha
}

#[derive(Deserialize)]
struct PushRequest {
    #[serde(default = "default_branch")]
    branch: String,
    #[serde(default = "default_message")]
    message: String,
    #[serde(default = "default_author")]
    author: String,
    files: HashMap<String, String>,
}

fn default_branch() -> String {
    "main".to_owned()
}
fn default_message() -> String {
    "update".to_owned()
}
fn default_author() -> String {
    "cite".to_owned()
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/repos/{owner}/{repo}", get(get_repo))
        .route("/repos/{owner}/{repo}/commits/{git_ref}", get(get_commit))
        .route("/repos/{owner}/{repo}/tarball/{sha}", get(get_tarball))
        .route("/repos/{owner}/{repo}/compare/{basehead}", get(get_compare))
        .route("/__cite/push", post(post_push))
        .route("/__cite/head/{branch}", get(get_head))
        .with_state(state)
}

async fn post_push(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PushRequest>,
) -> Response {
    let remaining = match check_request(&headers, &state) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let mut files = Vec::with_capacity(body.files.len());
    for (path, text) in body.files {
        if path.is_empty() || path.starts_with('/') || path.split('/').any(|p| p == "..") {
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"message":"refusing path"}"#,
            )
                .into_response();
        }
        files.push((path, text.into_bytes()));
    }
    let sha = apply_push(&state, &body.branch, &body.message, &body.author, files);
    let mut res = (StatusCode::OK, axum::Json(json!({"sha": sha}))).into_response();
    attach_rate_headers(res.headers_mut(), remaining);
    res
}

async fn get_head(
    State(state): State<Arc<AppState>>,
    Path(branch): Path<String>,
    headers: HeaderMap,
) -> Response {
    let remaining = match check_request(&headers, &state) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let sha = state
        .repo
        .lock()
        .expect("repo lock")
        .branches
        .get(&branch)
        .cloned();
    let Some(sha) = sha else {
        let mut res = (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"message":"Not Found"}"#,
        )
            .into_response();
        attach_rate_headers(res.headers_mut(), remaining);
        return res;
    };
    let mut res = (StatusCode::OK, axum::Json(json!({"sha": sha}))).into_response();
    attach_rate_headers(res.headers_mut(), remaining);
    res
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"message":"Bad credentials"}"#,
    )
        .into_response()
}

fn rate_limited(remaining: u32) -> Response {
    let mut res = (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"message":"API rate limit exceeded"}"#,
    )
        .into_response();
    attach_rate_headers(res.headers_mut(), remaining);
    res.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    res
}

fn attach_rate_headers(headers: &mut HeaderMap, remaining: u32) {
    headers.insert(
        "x-ratelimit-limit",
        HeaderValue::from_str(&RATE_LIMIT.to_string()).expect("limit"),
    );
    headers.insert(
        "x-ratelimit-remaining",
        HeaderValue::from_str(&remaining.to_string()).expect("remaining"),
    );
}

fn check_request(headers: &HeaderMap, state: &AppState) -> Result<u32, Box<Response>> {
    if !state.authorized.load(Ordering::SeqCst) {
        return Err(Box::new(unauthorized()));
    }
    let expected = state.token.as_str();
    let ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|auth| {
            auth.strip_prefix("Bearer ")
                .or_else(|| auth.strip_prefix("token "))
                .is_some_and(|t| t == expected)
        });
    if !ok {
        return Err(Box::new(unauthorized()));
    }
    let remaining = state.rate_remaining.load(Ordering::SeqCst);
    if remaining == 0 {
        return Err(Box::new(rate_limited(remaining)));
    }
    Ok(remaining)
}

async fn get_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let remaining = match check_request(&headers, &state) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let body = json!({
        "full_name": format!("{owner}/{repo}"),
        "default_branch": "main",
    });
    let mut res = (StatusCode::OK, axum::Json(body)).into_response();
    attach_rate_headers(res.headers_mut(), remaining);
    if let Some(exp) = state.expiry.lock().expect("expiry lock").as_ref()
        && let Ok(val) = HeaderValue::from_str(exp)
    {
        res.headers_mut()
            .insert("github-authentication-token-expiration", val);
    }
    res
}

async fn get_commit(
    State(state): State<Arc<AppState>>,
    Path((_owner, _repo, git_ref)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let remaining = match check_request(&headers, &state) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    let commit = {
        let repo = state.repo.lock().expect("repo lock");
        let sha = if let Some(sha) = repo.branches.get(&git_ref) {
            sha.clone()
        } else if repo.commits.contains_key(&git_ref) {
            git_ref.clone()
        } else {
            let mut res = (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"message":"Not Found"}"#,
            )
                .into_response();
            attach_rate_headers(res.headers_mut(), remaining);
            return res;
        };
        repo.commits.get(&sha).cloned()
    };

    let Some(commit) = commit else {
        let mut res = (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"message":"Not Found"}"#,
        )
            .into_response();
        attach_rate_headers(res.headers_mut(), remaining);
        return res;
    };

    let etag = format!("\"{}\"", commit.sha);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag)
    {
        let mut res = StatusCode::NOT_MODIFIED.into_response();
        attach_rate_headers(res.headers_mut(), remaining);
        if let Ok(val) = HeaderValue::from_str(&etag) {
            res.headers_mut().insert(header::ETAG, val);
        }
        return res;
    }

    let body = json!({
        "sha": commit.sha,
        "commit": {
            "message": commit.message,
            "author": {
                "name": commit.author,
                "date": commit.date,
            }
        }
    });
    let mut res = (StatusCode::OK, axum::Json(body)).into_response();
    attach_rate_headers(res.headers_mut(), remaining);
    if let Ok(val) = HeaderValue::from_str(&etag) {
        res.headers_mut().insert(header::ETAG, val);
    }
    res
}

async fn get_tarball(
    State(state): State<Arc<AppState>>,
    Path((_owner, _repo, sha)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let remaining = match check_request(&headers, &state) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    let delay_ms = state.tarball_delay_ms.load(Ordering::Relaxed);
    if delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    if let Some(bytes) = state
        .raw_tarballs
        .lock()
        .expect("raw tarball lock")
        .get(&sha)
        .cloned()
    {
        let mut res = Response::new(Body::from(bytes));
        *res.status_mut() = StatusCode::OK;
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-tar"),
        );
        attach_rate_headers(res.headers_mut(), remaining);
        return res;
    }

    let files = {
        let repo = state.repo.lock().expect("repo lock");
        repo.commits.get(&sha).map(|c| c.files.clone())
    };

    let Some(files) = files else {
        let mut res = (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"message":"Not Found"}"#,
        )
            .into_response();
        attach_rate_headers(res.headers_mut(), remaining);
        return res;
    };

    match build_tarball(&sha, &files) {
        Ok(bytes) => {
            let mut res = Response::new(Body::from(bytes));
            *res.status_mut() = StatusCode::OK;
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/gzip"),
            );
            attach_rate_headers(res.headers_mut(), remaining);
            res
        }
        Err(_) => {
            let mut res =
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to build tarball").into_response();
            attach_rate_headers(res.headers_mut(), remaining);
            res
        }
    }
}

async fn get_compare(
    State(state): State<Arc<AppState>>,
    Path((_owner, _repo, basehead)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let remaining = match check_request(&headers, &state) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    let Some((base, head)) = basehead.split_once("...") else {
        let mut res = (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"message":"Invalid compare ref"}"#,
        )
            .into_response();
        attach_rate_headers(res.headers_mut(), remaining);
        return res;
    };

    let file_entries = {
        let repo = state.repo.lock().expect("repo lock");
        let resolve = |r: &str| -> Option<&Commit> {
            if let Some(sha) = repo.branches.get(r) {
                repo.commits.get(sha)
            } else {
                repo.commits.get(r)
            }
        };
        let (Some(base_c), Some(head_c)) = (resolve(base), resolve(head)) else {
            let mut res = (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"message":"Not Found"}"#,
            )
                .into_response();
            attach_rate_headers(res.headers_mut(), remaining);
            return res;
        };

        let mut names = std::collections::BTreeSet::new();
        names.extend(base_c.files.keys().cloned());
        names.extend(head_c.files.keys().cloned());
        let mut out = Vec::new();
        for name in names {
            let b = base_c.files.get(&name);
            let h = head_c.files.get(&name);
            match (b, h) {
                (Some(bv), Some(hv)) if bv != hv => {
                    out.push(json!({"filename": name, "status": "modified"}));
                }
                (None, Some(_)) => {
                    out.push(json!({"filename": name, "status": "added"}));
                }
                (Some(_), None) => {
                    out.push(json!({"filename": name, "status": "removed"}));
                }
                _ => {}
            }
        }
        out
    };

    let body = json!({ "files": file_entries });
    let mut res = (StatusCode::OK, axum::Json(body)).into_response();
    attach_rate_headers(res.headers_mut(), remaining);
    res
}

fn build_tarball(sha: &str, files: &HashMap<String, Vec<u8>>) -> Result<Bytes, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut encoder);
        let prefix = format!("repo-{sha}");
        let mut dir_header = Header::new_gnu();
        dir_header.set_path(format!("{prefix}/"))?;
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_mode(0o755);
        dir_header.set_size(0);
        dir_header.set_cksum();
        archive.append(&dir_header, std::io::empty())?;

        let mut paths: Vec<&String> = files.keys().collect();
        paths.sort();
        for path in paths {
            let data = &files[path];
            let full = format!("{prefix}/{path}");
            let mut header = Header::new_gnu();
            header.set_path(&full)?;
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(data.len() as u64);
            header.set_cksum();
            archive.append(&header, data.as_slice())?;
        }
        archive.finish()?;
    }
    let gz = encoder.finish()?;
    Ok(Bytes::from(gz))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use serde_json::Value;
    use std::io::Read;
    use tar::Archive;

    async fn client() -> (MockGithub, reqwest::Client) {
        let mock = MockGithub::spawn().await.expect("spawn");
        let client = reqwest::Client::new();
        (mock, client)
    }

    #[tokio::test]
    async fn tarball_fetch_waits_for_the_configured_delay() {
        let (mock, client) = client().await;
        mock.set_tarball_delay(std::time::Duration::from_millis(200));
        let sha = mock.head_sha("main").expect("main head");
        let url = format!("{}/repos/acme/site/tarball/{sha}", mock.base_url());
        let started = std::time::Instant::now();
        let res = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", mock.token()))
            .send()
            .await
            .expect("tarball");
        assert!(res.status().is_success());
        assert!(started.elapsed() >= std::time::Duration::from_millis(150));
    }

    #[tokio::test]
    async fn spawn_push_commit_etag_and_tarball() {
        let (mock, client) = client().await;
        let token = mock.token().to_owned();
        let base = mock.base_url().to_owned();
        let first = mock.head_sha("main").expect("main head");
        assert_eq!(first.len(), 40);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));

        let second = mock
            .push_files(
                "main",
                "bump html",
                "tester",
                vec![("index.html".into(), b"<html>v2</html>".to_vec())],
            )
            .await;
        assert_ne!(second, first);
        assert_eq!(mock.head_sha("main").as_deref(), Some(second.as_str()));

        let url = format!("{base}/repos/acme/site/commits/main");
        let res = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("get commit");
        assert_eq!(res.status(), 200);
        let etag = res
            .headers()
            .get("etag")
            .expect("etag")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(etag, format!("\"{second}\""));
        let body: Value = res.json().await.expect("json");
        assert_eq!(body["sha"], second);
        assert_eq!(body["commit"]["message"], "bump html");
        assert_eq!(body["commit"]["author"]["name"], "tester");

        let res304 = client
            .get(&url)
            .header("Authorization", format!("token {token}"))
            .header("If-None-Match", &etag)
            .send()
            .await
            .expect("get 304");
        assert_eq!(res304.status(), 304);
        let bytes = res304.bytes().await.expect("body");
        assert!(bytes.is_empty());

        let tar_url = format!("{base}/repos/acme/site/tarball/{second}");
        let tar_res = client
            .get(&tar_url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("tarball");
        assert_eq!(tar_res.status(), 200);
        assert_eq!(
            tar_res.headers().get("content-type").unwrap(),
            "application/gzip"
        );
        let gz_bytes = tar_res.bytes().await.expect("gz");

        let decoder = GzDecoder::new(gz_bytes.as_ref());
        let mut archive = Archive::new(decoder);
        let mut found_index = false;
        let mut top_dirs = std::collections::HashSet::new();
        for entry in archive.entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let path = entry.path().expect("path").into_owned();
            let components: Vec<_> = path.components().collect();
            if let Some(std::path::Component::Normal(top)) = components.first() {
                top_dirs.insert(top.to_os_string());
            }
            if path
                .file_name()
                .is_some_and(|n| n == std::ffi::OsStr::new("index.html"))
                && components.len() == 2
            {
                let mut buf = String::new();
                entry.read_to_string(&mut buf).expect("read");
                assert_eq!(buf, "<html>v2</html>");
                found_index = true;
            }
        }
        assert!(found_index, "index.html under one top directory");
        assert_eq!(top_dirs.len(), 1, "single top-level directory");

        mock.shutdown().await;
    }

    #[tokio::test]
    async fn unauthorized_and_rate_limit() {
        let (mock, client) = client().await;
        let base = mock.base_url().to_owned();
        let token = mock.token().to_owned();

        mock.set_authorized(false);
        let res = client
            .get(format!("{base}/repos/o/r"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401);

        mock.set_authorized(true);
        let res = client
            .get(format!("{base}/repos/o/r"))
            .header("Authorization", "Bearer wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401);

        mock.set_rate_remaining(0);
        let res = client
            .get(format!("{base}/repos/o/r"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403);
        assert_eq!(res.headers().get("retry-after").unwrap(), "1");
        assert_eq!(res.headers().get("x-ratelimit-remaining").unwrap(), "0");

        mock.shutdown().await;
    }

    #[tokio::test]
    async fn repo_expiry_header_and_compare() {
        let (mock, client) = client().await;
        let base = mock.base_url().to_owned();
        let token = mock.token().to_owned();
        let first = mock.head_sha("main").unwrap();

        mock.set_expiry(Some("2099-01-01T00:00:00Z".into()));
        let res = client
            .get(format!("{base}/repos/acme/site"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(
            res.headers()
                .get("github-authentication-token-expiration")
                .unwrap(),
            "2099-01-01T00:00:00Z"
        );
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["full_name"], "acme/site");
        assert_eq!(body["default_branch"], "main");

        let second = mock
            .push_files(
                "main",
                "change",
                "a",
                vec![("index.html".into(), b"<html>v2</html>".to_vec())],
            )
            .await;

        let res = client
            .get(format!("{base}/repos/acme/site/compare/{first}...{second}"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        let files = body["files"].as_array().unwrap();
        assert!(
            files
                .iter()
                .any(|f| { f["filename"] == "index.html" && f["status"] == "modified" })
        );

        mock.shutdown().await;
    }

    #[tokio::test]
    async fn http_push_moves_the_branch_head() {
        let (mock, client) = client().await;
        let base = mock.base_url().to_owned();
        let token = mock.token().to_owned();
        let first = mock.head_sha("main").unwrap();

        let denied = client
            .post(format!("{base}/__cite/push"))
            .json(&json!({"files": {"index.html": "<html>nope</html>"}}))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 401);

        let res = client
            .post(format!("{base}/__cite/push"))
            .header("Authorization", format!("Bearer {token}"))
            .json(&json!({
                "branch": "main",
                "message": "v2",
                "author": "tester",
                "files": {"index.html": "<html>v2</html>"}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        let sha = body["sha"].as_str().unwrap().to_owned();
        assert_ne!(sha, first);
        assert_eq!(mock.head_sha("main").as_deref(), Some(sha.as_str()));

        let head = client
            .get(format!("{base}/__cite/head/main"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(head.status(), 200);
        let head: Value = head.json().await.unwrap();
        assert_eq!(head["sha"], sha);

        let escape = client
            .post(format!("{base}/__cite/push"))
            .header("Authorization", format!("Bearer {token}"))
            .json(&json!({"files": {"../etc/passwd": "x"}}))
            .send()
            .await
            .unwrap();
        assert_eq!(escape.status(), 400);

        mock.shutdown().await;
    }
}
