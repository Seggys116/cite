use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::transport::next_hop;
use super::*;

const TOKEN: &str = "tok-123";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_SHA: &str = "fedcba9876543210fedcba9876543210fedcba98";

#[derive(Debug, Clone)]
struct Seen {
    target: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    length: bool,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            length: true,
        }
    }

    fn json(status: u16, value: Value) -> Self {
        Self::bytes(status, value.to_string().into_bytes())
            .header("Content-Type", "application/json")
    }

    fn bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            body,
            ..Self::status(status)
        }
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    fn close_delimited(mut self) -> Self {
        self.length = false;
        self
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

struct Mock {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn mock(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let handler: Handler = Arc::new(handler);
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(serve(sock, handler.clone(), log.clone()));
        }
    });
    Mock {
        base: format!("http://127.0.0.1:{port}"),
        seen,
    }
}

async fn serve(mut sock: TcpStream, handler: Handler, log: Arc<Mutex<Vec<Seen>>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > 65_536 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let mut lines = text.split("\r\n");
    let target = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or("")
        .to_string();
    let headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let seen = Seen { target, headers };
    let reply = handler(&seen);
    log.lock().unwrap().push(seen);
    let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", reply.status);
    if reply.length {
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    if sock.write_all(head.as_bytes()).await.is_ok() {
        let _ = sock.write_all(&reply.body).await;
    }
    let _ = sock.shutdown().await;
}

fn token() -> cite_core::GithubToken {
    cite_core::GithubToken::Env(TOKEN.into())
}

fn gitlab(base: &str) -> GitlabClient {
    GitlabClient::new(base, "owner", "name", "main", &token()).unwrap()
}

fn gitea(base: &str) -> GiteaClient {
    GiteaClient::new(base, "owner", "name", "main", &token()).unwrap()
}

fn gitlab_branch(sha: &str) -> Value {
    json!({
        "name": "main",
        "commit": {
            "id": sha,
            "title": "Fix the header",
            "message": "Fix the header\n\nLonger body",
            "author_name": "Ada"
        }
    })
}

fn gitea_branch(sha: &str) -> Value {
    json!({
        "name": "main",
        "commit": {
            "id": sha,
            "message": "Tidy styles\n\nmore",
            "author": {"name": "Grace", "email": "g@example.com"}
        }
    })
}

const GL_PROJECT: &str = "/api/v4/projects/owner%2Fname";

#[tokio::test]
async fn gitlab_validates_access_with_bearer_auth_and_reads_token_expiry() {
    let server = mock(|req| match req.target.as_str() {
        GL_PROJECT => Reply::json(200, json!({"id": 7})),
        "/api/v4/projects/owner%2Fname/repository/branches/main" => {
            Reply::json(200, gitlab_branch(SHA))
        }
        "/api/v4/personal_access_tokens/self" => {
            Reply::json(200, json!({"expires_at": "2030-01-02"}))
        }
        _ => Reply::status(404),
    })
    .await;
    let ok = gitlab(&format!("{}/api/v4/", server.base))
        .validate_access()
        .await
        .unwrap();
    assert_eq!(ok.token_expires_at.as_deref(), Some("2030-01-02T00:00:00Z"));
    let seen = server.seen();
    assert_eq!(seen.len(), 3);
    for req in &seen {
        assert_eq!(req.header("authorization"), Some("Bearer tok-123"));
    }
}

#[tokio::test]
async fn gitlab_token_expiry_is_optional() {
    let server = mock(|req| match req.target.as_str() {
        "/personal_access_tokens/self" => Reply::status(403),
        _ => Reply::json(200, gitlab_branch(SHA)),
    })
    .await;
    let ok = gitlab(&server.base).validate_access().await.unwrap();
    assert_eq!(ok.token_expires_at, None);
}

#[tokio::test]
async fn access_failures_map_to_the_github_wording() {
    for (status, expect) in [
        (401, "bad token / no access"),
        (403, "bad token / no access"),
        (
            404,
            "repository owner/name not found or token lacks read_api",
        ),
    ] {
        let server = mock(move |_| Reply::status(status)).await;
        let err = gitlab(&server.base).validate_access().await.unwrap_err();
        assert!(err.to_string().contains(expect), "{status}: {err}");
        assert!(err.to_string().contains("token"), "{err}");
    }
    for (status, expect) in [
        (401, "Gitea token is invalid"),
        (403, "bad token / no access"),
        (
            404,
            "repository owner/name not found or token lacks read:repository",
        ),
    ] {
        let server = mock(move |_| Reply::status(status)).await;
        let err = gitea(&server.base).validate_access().await.unwrap_err();
        assert!(err.to_string().contains(expect), "{status}: {err}");
    }
    let server = mock(|req| {
        if req.target.contains("/branches/") {
            Reply::status(404)
        } else {
            Reply::json(200, json!({}))
        }
    })
    .await;
    for err in [
        gitlab(&server.base).validate_access().await.unwrap_err(),
        gitea(&server.base).validate_access().await.unwrap_err(),
    ] {
        assert!(
            err.to_string()
                .contains("branch `main` does not exist on owner/name"),
            "{err}"
        );
    }
    let server = mock(|_| Reply::status(500)).await;
    let err = gitea(&server.base).validate_access().await.unwrap_err();
    assert!(
        err.to_string().contains("Gitea repo check failed (500"),
        "{err}"
    );
    assert!(!err.to_string().contains("token"), "{err}");
}

#[tokio::test]
async fn gitlab_poll_reports_changes_and_honours_etags() {
    let server = mock(|req| {
        if req.header("if-none-match") == Some("\"e1\"") {
            Reply::status(304)
        } else {
            Reply::json(200, gitlab_branch(SHA)).header("ETag", "\"e1\"")
        }
    })
    .await;
    let client = gitlab(&server.base);
    let (result, hints) = client.poll_head(None).await.unwrap();
    assert!(hints.backoff().is_none());
    let PollResult::Changed(info) = result else {
        panic!("expected a change");
    };
    assert_eq!(info.sha, SHA);
    assert_eq!(info.message, "Fix the header");
    assert_eq!(info.author, "Ada");
    assert_eq!(info.etag.as_deref(), Some("\"e1\""));
    let (again, _) = client.poll_head(Some("\"e1\"")).await.unwrap();
    assert!(matches!(again, PollResult::Unchanged));
    assert_eq!(
        server.seen()[0].target,
        "/projects/owner%2Fname/repository/branches/main"
    );
}

#[tokio::test]
async fn gitea_poll_uses_the_token_scheme_and_first_message_line() {
    let server = mock(|req| match req.target.as_str() {
        "/repos/owner/name/branches/main" => Reply::json(200, gitea_branch(SHA)),
        _ => Reply::status(404),
    })
    .await;
    let (result, _) = gitea(&server.base).poll_head(None).await.unwrap();
    let PollResult::Changed(info) = result else {
        panic!("expected a change");
    };
    assert_eq!(info.sha, SHA);
    assert_eq!(info.message, "Tidy styles");
    assert_eq!(info.author, "Grace");
    assert_eq!(info.etag, None);
    assert_eq!(
        server.seen()[0].header("authorization"),
        Some("token tok-123")
    );
}

#[tokio::test]
async fn poll_maps_rejected_tokens_rate_limits_and_bad_heads() {
    let server = mock(|_| Reply::status(401)).await;
    let err = gitlab(&server.base).poll_head(None).await.unwrap_err();
    assert_eq!(err.to_string(), "token_invalid");
    let err = gitea(&server.base).poll_head(None).await.unwrap_err();
    assert_eq!(err.to_string(), "token_invalid");

    let server = mock(|_| {
        Reply::status(429)
            .header("RateLimit-Remaining", "0")
            .header("Retry-After", "30")
    })
    .await;
    let (result, hints) = gitlab(&server.base).poll_head(None).await.unwrap();
    assert!(matches!(result, PollResult::Unchanged));
    assert_eq!(hints.backoff(), Some(Duration::from_secs(30)));

    let server = mock(|_| Reply::status(429)).await;
    let (result, hints) = gitea(&server.base).poll_head(None).await.unwrap();
    assert!(matches!(result, PollResult::Unchanged));
    assert_eq!(hints.backoff(), Some(Duration::from_secs(60)));

    let server = mock(|_| Reply::status(403)).await;
    let err = gitlab(&server.base).poll_head(None).await.unwrap_err();
    assert!(err.to_string().starts_with("poll failed (403"), "{err}");

    let server = mock(|_| Reply::json(200, gitlab_branch("not-a-sha"))).await;
    let err = gitlab(&server.base).poll_head(None).await.unwrap_err();
    assert!(err.to_string().contains("not a commit id"), "{err}");
}

#[tokio::test]
async fn archives_are_fetched_by_sha_and_unknown_shas_fail() {
    let server = mock(|req| {
        let gl = format!("/projects/owner%2Fname/repository/archive.tar.gz?sha={SHA}");
        let gt = format!("/repos/owner/name/archive/{SHA}.tar.gz");
        if req.target == gl || req.target == gt {
            Reply::bytes(200, b"archive-bytes".to_vec())
        } else {
            Reply::json(404, json!({"message": "404 Commit Not Found"}))
        }
    })
    .await;
    assert_eq!(
        gitlab(&server.base).fetch_tarball(SHA).await.unwrap(),
        b"archive-bytes"
    );
    assert_eq!(
        gitea(&server.base).fetch_tarball(SHA).await.unwrap(),
        b"archive-bytes"
    );
    for err in [
        gitlab(&server.base)
            .fetch_tarball(OTHER_SHA)
            .await
            .unwrap_err(),
        gitea(&server.base)
            .fetch_tarball(OTHER_SHA)
            .await
            .unwrap_err(),
    ] {
        assert!(
            err.to_string()
                .contains("tarball fetch failed (404 Not Found)"),
            "{err}"
        );
        assert!(err.to_string().contains("Commit Not Found"), "{err}");
    }
    let before = server.seen().len();
    let long = "a".repeat(65);
    for bad in ["../../etc", "main", "abc", long.as_str()] {
        let err = gitlab(&server.base).fetch_tarball(bad).await.unwrap_err();
        assert!(err.to_string().contains("not a commit id"), "{err}");
        let err = gitea(&server.base).fetch_tarball(bad).await.unwrap_err();
        assert!(err.to_string().contains("not a commit id"), "{err}");
    }
    assert_eq!(server.seen().len(), before);

    let server = mock(|_| Reply::status(401)).await;
    let err = gitea(&server.base).fetch_tarball(SHA).await.unwrap_err();
    assert_eq!(err.to_string(), "token_invalid");
}

#[tokio::test]
async fn cross_host_redirects_never_carry_the_token() {
    let storage = mock(|_| Reply::bytes(200, b"from-storage".to_vec())).await;
    let target = format!("{}/blob?sig=abc", storage.base);
    let api = mock(move |_| Reply::status(302).header("Location", &target)).await;

    assert_eq!(
        gitlab(&api.base).fetch_tarball(SHA).await.unwrap(),
        b"from-storage"
    );
    assert_eq!(
        gitea(&api.base).fetch_tarball(SHA).await.unwrap(),
        b"from-storage"
    );
    for req in api.seen() {
        assert!(req.header("authorization").is_some());
    }
    let fetched = storage.seen();
    assert_eq!(fetched.len(), 2);
    for req in fetched {
        assert_eq!(req.target, "/blob?sig=abc");
        assert_eq!(req.header("authorization"), None);
        assert_eq!(req.header("private-token"), None);
        assert!(
            !req.headers.iter().any(|(_, v)| v.contains(TOKEN)),
            "{req:?}"
        );
    }
}

#[tokio::test]
async fn same_origin_redirects_keep_the_token() {
    let server = mock(|req| {
        if req.target == "/moved" {
            Reply::bytes(200, b"moved".to_vec())
        } else {
            Reply::status(301).header("Location", "/moved")
        }
    })
    .await;
    assert_eq!(
        gitea(&server.base).fetch_tarball(SHA).await.unwrap(),
        b"moved"
    );
    let seen = server.seen();
    assert_eq!(seen.len(), 2);
    for req in seen {
        assert_eq!(req.header("authorization"), Some("token tok-123"));
    }
}

#[tokio::test]
async fn a_storage_401_is_not_blamed_on_the_token_and_redirect_loops_stop() {
    let storage = mock(|_| Reply::status(401)).await;
    let target = format!("{}/blob", storage.base);
    let api = mock(move |_| Reply::status(302).header("Location", &target)).await;
    let err = gitlab(&api.base).fetch_tarball(SHA).await.unwrap_err();
    assert!(
        err.to_string().starts_with("tarball fetch failed (401"),
        "{err}"
    );

    let looping = mock(|_| Reply::status(302).header("Location", "/again")).await;
    let err = gitea(&looping.base).fetch_tarball(SHA).await.unwrap_err();
    assert!(err.to_string().contains("redirected more than"), "{err}");
}

#[test]
fn redirect_hops_cannot_downgrade_or_smuggle_credentials() {
    let https = Url::parse("https://gitlab.example.com/api/v4/x").unwrap();
    assert!(next_hop(&https, "http://storage.example.com/blob").is_err());
    assert!(next_hop(&https, "ftp://storage.example.com/blob").is_err());
    assert!(next_hop(&https, "https://user:pw@storage.example.com/blob").is_err());
    assert!(next_hop(&https, "file:///etc/passwd").is_err());
    let next = next_hop(&https, "https://storage.example.com/blob?sig=1").unwrap();
    assert_eq!(next.host_str(), Some("storage.example.com"));
    let relative = next_hop(&https, "../other").unwrap();
    assert_eq!(relative.as_str(), "https://gitlab.example.com/api/other");
}

#[tokio::test]
async fn oversized_archives_are_refused() {
    let server = mock(|_| Reply::bytes(200, vec![7u8; 10_000])).await;
    let err = gitlab(&server.base)
        .with_max_tarball_bytes(4096)
        .fetch_tarball(SHA)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceeds"), "{err}");

    let streamed = mock(|_| Reply::bytes(200, vec![7u8; 100_000]).close_delimited()).await;
    let err = gitea(&streamed.base)
        .with_max_tarball_bytes(4096)
        .fetch_tarball(SHA)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceeds"), "{err}");

    let fits = mock(|_| Reply::bytes(200, vec![7u8; 4096]).close_delimited()).await;
    let bytes = gitea(&fits.base)
        .with_max_tarball_bytes(4096)
        .fetch_tarball(SHA)
        .await
        .unwrap();
    assert_eq!(bytes.len(), 4096);
}

#[tokio::test]
async fn a_silent_archive_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _held = tokio::spawn(async move {
        let conn = listener.accept().await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(conn);
    });
    let err = gitlab(&format!("http://127.0.0.1:{port}"))
        .with_tarball_timeout(Duration::from_millis(300))
        .fetch_tarball(SHA)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err}");
}

#[tokio::test]
async fn a_gitea_archive_extracts_through_the_hardened_extractor() {
    let src = tempfile::tempdir().unwrap();
    std::fs::create_dir(src.path().join("name")).unwrap();
    std::fs::write(src.path().join("name/index.html"), "<h1>hi</h1>").unwrap();
    let mut tar = Vec::new();
    cite_core::pack_dir(src.path(), &mut tar, &cite_core::PackLimits::default()).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &tar).unwrap();
    let archive = gz.finish().unwrap();
    let server = mock(move |_| Reply::bytes(200, archive.clone())).await;

    let bytes = gitea(&server.base).fetch_tarball(SHA).await.unwrap();
    let dest = tempfile::tempdir().unwrap();
    cite_core::extract_archive(
        std::io::Cursor::new(bytes),
        dest.path(),
        &cite_core::ExtractLimits::default(),
        1,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(dest.path().join("index.html")).unwrap(),
        "<h1>hi</h1>"
    );
}

#[tokio::test]
async fn path_filters_use_the_forge_compare_apis() {
    let paths = vec!["site".to_string(), "docs/*".to_string()];
    let server = mock(|req| {
        if req.target.contains("to=") && req.target.ends_with(SHA) {
            Reply::json(
                200,
                json!({"diffs": [{"old_path": "README.md", "new_path": "site/index.html"}]}),
            )
        } else if req.target.contains("compare?") {
            Reply::json(200, json!({"diffs": [{"old_path": "lib/a", "new_path": "lib/a"}]}))
        } else if req.target.ends_with(&format!("...{SHA}")) {
            Reply::json(
                200,
                json!({"commits": [{"files": [{"filename": "docs/guide.md", "status": "modified"}]}]}),
            )
        } else if req.target.ends_with(&format!("...{OTHER_SHA}")) {
            Reply::json(200, json!({"commits": [{"files": [{"filename": "lib/a"}]}]}))
        } else {
            Reply::status(500)
        }
    })
    .await;
    let gl = gitlab(&server.base);
    assert!(gl.paths_changed(OTHER_SHA, SHA, &paths).await.unwrap());
    assert!(!gl.paths_changed(SHA, OTHER_SHA, &paths).await.unwrap());
    let gt = gitea(&server.base);
    assert!(gt.paths_changed(OTHER_SHA, SHA, &paths).await.unwrap());
    assert!(!gt.paths_changed(SHA, OTHER_SHA, &paths).await.unwrap());
    assert!(gt.paths_changed(SHA, OTHER_SHA, &[]).await.unwrap());
    assert!(
        server.seen()[0]
            .target
            .starts_with("/projects/owner%2Fname/repository/compare?from=")
    );

    let missing_files = mock(|_| Reply::json(200, json!({"commits": [{"sha": SHA}]}))).await;
    assert!(
        gitea(&missing_files.base)
            .paths_changed(OTHER_SHA, SHA, &paths)
            .await
            .unwrap()
    );
    let broken = mock(|_| Reply::status(500)).await;
    assert!(
        gitlab(&broken.base)
            .paths_changed(OTHER_SHA, SHA, &paths)
            .await
            .unwrap()
    );
    let rejected = mock(|_| Reply::status(401)).await;
    let err = gitea(&rejected.base)
        .paths_changed(OTHER_SHA, SHA, &paths)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "token_invalid");
}

#[tokio::test]
async fn the_github_variant_delegates_to_the_existing_client() {
    let server = mock(|req| {
        if req.target == format!("/repos/owner/name/tarball/{SHA}") {
            Reply::bytes(200, b"gh".to_vec())
        } else {
            Reply::status(404)
        }
    })
    .await;
    let settings = ForgeSettings::from_values(None, None, &server.base).unwrap();
    let client = ForgeClient::new(&settings, "owner", "name", "main", &token()).unwrap();
    assert_eq!(client.kind(), ForgeKind::Github);
    assert_eq!(client.read_token().unwrap(), TOKEN);
    assert_eq!(client.fetch_tarball(SHA).await.unwrap(), b"gh");
    assert_eq!(
        server.seen()[0].header("authorization"),
        Some("Bearer tok-123")
    );
}

#[tokio::test]
async fn the_forge_client_dispatches_to_the_selected_adapter() {
    let server = mock(|req| match req.target.as_str() {
        "/repos/owner/name/branches/main" => Reply::json(200, gitea_branch(SHA)),
        _ => Reply::json(200, json!({})),
    })
    .await;
    let settings = ForgeSettings::from_values(
        Some("gitea"),
        Some(server.base.as_str()),
        "https://api.github.com",
    )
    .unwrap();
    let client = ForgeClient::new(&settings, "owner", "name", "main", &token())
        .unwrap()
        .with_max_tarball_bytes(1024)
        .with_tarball_timeout(Duration::from_secs(5));
    assert_eq!(client.kind(), ForgeKind::Gitea);
    assert!(client.validate_access().await.is_ok());
    let (result, _) = client.poll_head(None).await.unwrap();
    assert!(matches!(result, PollResult::Changed(ref c) if c.sha == SHA));
}

#[test]
fn forge_selection_defaults_to_github_and_validates_urls() {
    let gh = ForgeSettings::from_values(None, None, "https://api.github.com").unwrap();
    assert_eq!(gh.kind, ForgeKind::Github);
    assert_eq!(gh.api_url, "https://api.github.com");
    let blank = ForgeSettings::from_values(Some(" "), Some(""), "https://ghe.test/api/v3").unwrap();
    assert_eq!(blank.kind, ForgeKind::Github);
    assert_eq!(blank.api_url, "https://ghe.test/api/v3");

    let gl = ForgeSettings::from_values(Some("gitlab"), None, "https://api.github.com").unwrap();
    assert_eq!(gl.api_url, DEFAULT_GITLAB_API_URL);
    let own = ForgeSettings::from_values(
        Some("GitLab"),
        Some("https://git.example.com/api/v4"),
        "https://api.github.com",
    )
    .unwrap();
    assert_eq!(own.kind, ForgeKind::Gitlab);
    assert_eq!(own.api_url, "https://git.example.com/api/v4");

    let err =
        ForgeSettings::from_values(Some("gitea"), None, "https://api.github.com").unwrap_err();
    assert!(
        err.to_string().contains("CITE_FORGE_API_URL is required"),
        "{err}"
    );
    let err =
        ForgeSettings::from_values(Some("bitbucket"), None, "https://api.github.com").unwrap_err();
    assert!(err.to_string().contains("CITE_FORGE must be"), "{err}");
    let err = ForgeSettings::from_values(
        Some("gitea"),
        Some("http://gitea.example.com/api/v1"),
        "https://api.github.com",
    )
    .unwrap_err();
    assert!(err.to_string().contains("https"), "{err}");

    for ok in [
        "https://codeberg.org/api/v1",
        "https://git.example.com:8443/api/v4/",
        "http://127.0.0.1:3000/api/v1",
        "http://localhost:8080",
    ] {
        assert_eq!(validate_forge_api_url(ok), Ok(()), "{ok}");
    }
    let long = format!("https://{}.example.com", "a".repeat(200));
    for bad in [
        "",
        "gitea.example.com",
        "ftp://gitea.example.com",
        "HTTPS://gitea.example.com",
        "http://gitea.example.com",
        "http://10.0.0.5",
        "https://",
        "https://user@gitea.example.com",
        "https://user:pw@gitea.example.com",
        "https://gitea.example.com?x=1",
        "https://gitea.example.com/#frag",
        "https://gitea.example.com:0",
        "https://gitea.example.com:99999",
        "https://gitea example.com",
        "https://gitea.example.com//x",
        "https://gitea.example.com/../x",
        "https://gitea.example.com/%2e%2e",
        "https://.example.com",
        "https://gitea.example.com\n",
        long.as_str(),
    ] {
        assert!(validate_forge_api_url(bad).is_err(), "{bad:?}");
    }
    assert!(GitlabClient::new("http://gitlab.example.com", "o", "n", "main", &token()).is_err());
}

#[test]
fn release_builds_accept_https_only_even_on_loopback() {
    for url in [
        "http://127.0.0.1:3000/api/v1",
        "http://localhost:8080",
        "http://gitea.example.com",
    ] {
        let err = check_api_url(url, false).unwrap_err();
        assert_eq!(err, "forge api url must use https", "{url}");
    }
    assert_eq!(
        check_api_url("https://127.0.0.1:3000/api/v1", false),
        Ok(())
    );
    assert_eq!(check_api_url("https://codeberg.org/api/v1", false), Ok(()));
}

#[test]
fn helpers_encode_parse_and_match() {
    assert_eq!(encode_segment("group/sub/name"), "group%2Fsub%2Fname");
    assert_eq!(encode_segment("feat/x y"), "feat%2Fx%20y");
    assert_eq!(encode_segment("a-b_c.d~e"), "a-b_c.d~e");
    assert!(is_commit_id(SHA));
    assert!(is_commit_id(&"a".repeat(64)));
    assert!(!is_commit_id("abc123"));
    assert!(!is_commit_id(&"g".repeat(40)));
    assert!(ensure_sha_ref("abc1234").is_ok());
    assert!(ensure_sha_ref("abc12").is_err());
    assert_eq!(
        normalize_expiry("2030-01-02").as_deref(),
        Some("2030-01-02T00:00:00Z")
    );
    assert_eq!(
        normalize_expiry("2030-01-02T03:04:05+02:00").as_deref(),
        Some("2030-01-02T01:04:05Z")
    );
    assert_eq!(normalize_expiry("soon"), None);
    let paths = vec!["site".to_string(), "docs/*".to_string(), "README.md".into()];
    assert!(path_matches(&paths, "site/a.html"));
    assert!(path_matches(&paths, "docs/x"));
    assert!(path_matches(&paths, "README.md"));
    assert!(!path_matches(&paths, "readme.md"));
    assert!(!path_matches(&paths, "sitemap.xml"));
    assert_eq!(truncate("aé", 2), "a…");
    assert_eq!(ForgeKind::Gitea.as_str(), "gitea");
    assert_eq!(ForgeKind::Gitlab.display_name(), "GitLab");
}

#[test]
fn rate_hints_read_gitlab_and_draft_headers() {
    use reqwest::header::HeaderValue;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut headers = HeaderMap::new();
    headers.insert("ratelimit-remaining", HeaderValue::from_static("0"));
    headers.insert(
        "ratelimit-reset",
        HeaderValue::from_str(&(now + 120).to_string()).unwrap(),
    );
    let hints = rate_hints(StatusCode::OK, &headers);
    assert_eq!(hints.remaining, Some(0));
    assert_eq!(hints.reset_at, Some(now + 120));
    assert!(hints.backoff().unwrap() >= Duration::from_secs(100));

    let mut draft = HeaderMap::new();
    draft.insert("x-ratelimit-remaining", HeaderValue::from_static("5"));
    draft.insert("x-ratelimit-reset", HeaderValue::from_static("30"));
    let hints = rate_hints(StatusCode::OK, &draft);
    assert!(hints.reset_at.unwrap() >= now + 30);
    assert!(hints.backoff().is_none());

    let limited = rate_hints(StatusCode::TOO_MANY_REQUESTS, &HeaderMap::new());
    assert_eq!(limited.backoff(), Some(Duration::from_secs(60)));
}
