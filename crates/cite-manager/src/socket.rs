use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use cite_core::{ControlRequest, ControlResponse, ManagerConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::Result;
use crate::deploy::{DeployCmd, Deployer};

#[cfg(target_os = "linux")]
use crate::ManagerError;

pub async fn serve_socket(
    cfg: ManagerConfig,
    deployer: Arc<Deployer>,
    gate: Arc<Mutex<()>>,
) -> Result<()> {
    if let Some(parent) = cfg.socket_path.parent() {
        cite_core::ensure_dir(parent, 0o755)?;
    }
    let _ = std::fs::remove_file(&cfg.socket_path);
    let listener = UnixListener::bind(&cfg.socket_path)?;
    std::fs::set_permissions(&cfg.socket_path, std::fs::Permissions::from_mode(0o600))?;
    info!(path = %cfg.socket_path.display(), "control socket listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let deployer = Arc::clone(&deployer);
                let gate = Arc::clone(&gate);
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_client(stream, deployer, gate, &cfg).await {
                        warn!(error = %err, "control client error");
                    }
                });
            }
            Err(err) => {
                warn!(error = %err, "accept failed");
            }
        }
    }
}

async fn handle_client(
    stream: UnixStream,
    deployer: Arc<Deployer>,
    gate: Arc<Mutex<()>>,
    cfg: &ManagerConfig,
) -> Result<()> {
    authorize_peer_fd(&stream)?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: ControlRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(err) => {
                let resp = ControlResponse {
                    ok: false,
                    error: Some(format!("bad request: {err}")),
                    data: None,
                };
                write_resp(&mut writer, &resp).await?;
                continue;
            }
        };
        let resp = dispatch(req, &deployer, &gate, cfg).await;
        write_resp(&mut writer, &resp).await?;
    }
    Ok(())
}

fn authorize_peer_fd(fd: impl std::os::fd::AsFd) -> Result<()> {
    let self_uid = rustix::process::geteuid();
    #[cfg(target_os = "linux")]
    {
        match rustix::net::sockopt::socket_peercred(fd) {
            Ok(cred) => {
                if cred.uid != self_uid {
                    return Err(ManagerError::new("peer uid rejected"));
                }
            }
            Err(err) => {
                return Err(ManagerError::new(format!("SO_PEERCRED failed: {err}")));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Peer cred unavailable (macOS). Socket mode 0600 already restricts to current uid.
        let _ = (fd, self_uid);
    }
    Ok(())
}

async fn write_resp(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &ControlResponse,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(resp)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    Ok(())
}

async fn dispatch(
    req: ControlRequest,
    deployer: &Arc<Deployer>,
    gate: &Arc<Mutex<()>>,
    cfg: &ManagerConfig,
) -> ControlResponse {
    match req {
        ControlRequest::Healthcheck => ControlResponse {
            ok: true,
            error: None,
            data: Some(serde_json::json!({"healthy": true})),
        },
        ControlRequest::ConfigCheck => ControlResponse {
            ok: true,
            error: None,
            data: Some(serde_json::json!({"config": cfg.redacted_display()})),
        },
        ControlRequest::Status => match deployer.status_json().await {
            Ok(data) => ControlResponse {
                ok: true,
                error: None,
                data: Some(data),
            },
            Err(err) => ControlResponse {
                ok: false,
                error: Some(err.to_string()),
                data: None,
            },
        },
        ControlRequest::Logs => {
            let logs = crate::deploy::log_lines();
            ControlResponse {
                ok: true,
                error: None,
                data: Some(serde_json::json!({"lines": logs})),
            }
        }
        other => {
            let _guard = gate.lock().await;
            let cmd = match other {
                ControlRequest::Poll => DeployCmd::Poll { force: false },
                ControlRequest::Redeploy { sha } => DeployCmd::Redeploy { sha },
                ControlRequest::Rollback => DeployCmd::Rollback,
                ControlRequest::RestartChild => DeployCmd::RestartChild,
                ControlRequest::RestartExecutor => DeployCmd::RestartExecutor,
                ControlRequest::Pause => DeployCmd::Pause,
                ControlRequest::Resume => DeployCmd::Resume,
                _ => {
                    return ControlResponse {
                        ok: false,
                        error: Some("unhandled".into()),
                        data: None,
                    };
                }
            };
            match deployer.handle(cmd).await {
                Ok(data) => ControlResponse {
                    ok: true,
                    error: None,
                    data: Some(data),
                },
                Err(err) => ControlResponse {
                    ok: false,
                    error: Some(err.to_string()),
                    data: None,
                },
            }
        }
    }
}

/// Client-side: send one request and read one response.
pub fn request(socket: &Path, req: &ControlRequest) -> Result<ControlResponse> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream as StdUnix;

    let mut stream = StdUnix::connect(socket)?;
    authorize_peer_fd(&stream)?;
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim())?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use cite_core::{ControlRequest, ManagerConfig};
    use tokio::sync::Mutex;

    use super::dispatch;
    use crate::deploy::Deployer;

    #[tokio::test]
    async fn pause_is_idempotent_and_commands_wait_on_the_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let cache = tmp.path().join("cache");
        let socket = tmp.path().join("manager.sock");
        let data = tmp.path().join("cite_data");
        let token = tmp.path().join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        std::fs::set_permissions(&token, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let pairs = [
            ("CITE_REPO", "owner/name"),
            ("CITE_DATA_DIR", data.to_str().unwrap()),
            ("CITE_WORK_DIR", work.to_str().unwrap()),
            ("CITE_CACHE_DIR", cache.to_str().unwrap()),
            ("CITE_SOCKET", socket.to_str().unwrap()),
            ("CITE_GITHUB_TOKEN_FILE", token.to_str().unwrap()),
            ("CITE_DEV_SAME_USER", "true"),
            ("CITE_MIN_FREE_BYTES", "1"),
            ("CITE_POLL_INTERVAL", "off"),
        ];
        let env = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>();
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let deployer = Deployer::new(cfg.clone()).await.unwrap();
        let gate = Arc::new(Mutex::new(()));

        let first = dispatch(ControlRequest::Pause, &deployer, &gate, &cfg).await;
        let second = dispatch(ControlRequest::Pause, &deployer, &gate, &cfg).await;
        assert!(first.ok && second.ok);
        assert_eq!(first.data.as_ref().unwrap()["paused"], true);
        assert_eq!(second.data.as_ref().unwrap()["paused"], true);
        assert!(deployer.state.lock().await.paused);

        let guard = gate.lock().await;
        let pending = {
            let deployer = Arc::clone(&deployer);
            let gate = Arc::clone(&gate);
            let cfg = cfg.clone();
            tokio::spawn(
                async move { dispatch(ControlRequest::Resume, &deployer, &gate, &cfg).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!pending.is_finished());
        drop(guard);
        let resumed = pending.await.unwrap();
        assert!(resumed.ok);
        assert!(!deployer.state.lock().await.paused);

        let again = dispatch(ControlRequest::Resume, &deployer, &gate, &cfg).await;
        assert!(again.ok);
        assert!(!deployer.state.lock().await.paused);
    }

    #[tokio::test]
    async fn control_socket_round_trips_and_rejects_a_bad_line() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let cache = tmp.path().join("cache");
        // Path exceeds the ~104-byte unix socket limit, so bind never creates the file.
        let socket = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/cite-manager.sock");
        let _ = std::fs::remove_file(&socket);
        let data = tmp.path().join("cite_data");
        let token = tmp.path().join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        std::fs::set_permissions(&token, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let pairs = [
            ("CITE_REPO", "owner/name"),
            ("CITE_DATA_DIR", data.to_str().unwrap()),
            ("CITE_WORK_DIR", work.to_str().unwrap()),
            ("CITE_CACHE_DIR", cache.to_str().unwrap()),
            ("CITE_SOCKET", socket.to_str().unwrap()),
            ("CITE_GITHUB_TOKEN_FILE", token.to_str().unwrap()),
            ("CITE_DEV_SAME_USER", "true"),
            ("CITE_MIN_FREE_BYTES", "1"),
            ("CITE_POLL_INTERVAL", "off"),
        ];
        let env = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>();
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let deployer = Deployer::new(cfg.clone()).await.unwrap();
        let gate = Arc::new(Mutex::new(()));
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = {
            let cfg = cfg.clone();
            let deployer = Arc::clone(&deployer);
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                let result = super::serve_socket(cfg, deployer, gate).await;
                let _ = done_tx.send(result.map(|_| ()));
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if socket.exists() {
                break;
            }
            if let Ok(Err(err)) = done_rx.try_recv() {
                panic!("control socket failed: {err}");
            }
            if std::time::Instant::now() >= deadline {
                panic!("control socket was not bound at {}", socket.display());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let socket_for_client = socket.clone();
        let replies = tokio::task::spawn_blocking(move || {
            let health = super::request(&socket_for_client, &ControlRequest::Healthcheck)?;
            let status = super::request(&socket_for_client, &ControlRequest::Status)?;
            let logs = super::request(&socket_for_client, &ControlRequest::Logs)?;
            let checked = super::request(&socket_for_client, &ControlRequest::ConfigCheck)?;
            let rollback = super::request(&socket_for_client, &ControlRequest::Rollback)?;
            let restart = super::request(&socket_for_client, &ControlRequest::RestartChild)?;
            use std::io::{BufRead, Write};
            let mut stream = std::os::unix::net::UnixStream::connect(&socket_for_client)?;
            stream.write_all(b"\n{not-json\n")?;
            let mut line = String::new();
            std::io::BufReader::new(stream).read_line(&mut line)?;
            Ok::<_, crate::ManagerError>((health, status, logs, checked, rollback, restart, line))
        })
        .await
        .unwrap()
        .unwrap();
        assert!(replies.0.ok && replies.1.ok && replies.2.ok && replies.3.ok);
        assert!(!replies.4.ok);
        assert!(replies.4.error.unwrap().contains("unsealed"));
        assert!(replies.5.ok);
        assert!(replies.6.contains("bad request"), "{}", replies.6);
        server.abort();
        let _ = std::fs::remove_file(&socket);
    }

    #[tokio::test]
    async fn cli_poll_follows_the_normal_rules_and_honours_pause() {
        let tmp = tempfile::tempdir().unwrap();
        let token = tmp.path().join("token");
        std::fs::write(&token, "ghp_citeMockGithubPat00000000000000001\n").unwrap();
        std::fs::set_permissions(&token, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let data = tmp.path().join("cite_data");
        let work = tmp.path().join("work");
        let cache = tmp.path().join("cache");
        let pairs = [
            ("CITE_REPO", "owner/name"),
            ("CITE_DATA_DIR", data.to_str().unwrap()),
            ("CITE_WORK_DIR", work.to_str().unwrap()),
            ("CITE_CACHE_DIR", cache.to_str().unwrap()),
            ("CITE_GITHUB_TOKEN_FILE", token.to_str().unwrap()),
            ("CITE_GITHUB_API_URL", "http://127.0.0.1:1"),
            ("CITE_DEV_SAME_USER", "true"),
            ("CITE_MIN_FREE_BYTES", "1"),
            ("CITE_POLL_INTERVAL", "1m"),
        ];
        let env = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>();
        let cfg = ManagerConfig::load_from(&env, None).unwrap();
        let deployer = Deployer::new(cfg.clone()).await.unwrap();
        let gate = Arc::new(Mutex::new(()));

        dispatch(ControlRequest::Pause, &deployer, &gate, &cfg).await;
        let polled = dispatch(ControlRequest::Poll, &deployer, &gate, &cfg).await;
        assert!(polled.ok, "{:?}", polled.error);
        assert_eq!(polled.data.unwrap()["skipped"], "paused");
    }
}
