use std::process::ExitCode;
use std::sync::Arc;

use cite_egress::forward::{Forward, parse_forwards, serve_forward};
use cite_egress::policy::Policy;
use cite_egress::proxy::{LISTEN, Shared, Timeouts, serve_with};
use cite_egress::routes;
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;

const FORWARDS_KEY: &str = "CITE_EGRESS_FORWARDS";

// Accepted sockets inherit SO_KEEPALIVE from the listener on Linux.
fn listen(addr: &str) -> std::io::Result<TcpListener> {
    let addr: std::net::SocketAddr = addr.parse().map_err(std::io::Error::other)?;
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.set_keepalive(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

fn forwards_from_env() -> Result<Vec<Forward>, String> {
    match std::env::var(FORWARDS_KEY) {
        Ok(raw) if !raw.trim().is_empty() => parse_forwards(&raw),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{FORWARDS_KEY} is not valid text")),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let policy = match Policy::from_env() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "invalid egress configuration");
            return ExitCode::FAILURE;
        }
    };
    let forwards = match forwards_from_env() {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "invalid egress configuration");
            return ExitCode::FAILURE;
        }
    };
    let local = routes::local_networks();
    tracing::info!(
        count = local.len(),
        "own networks and gateways added to the deny ceiling"
    );
    let policy = Arc::new(policy.with_local_networks(local));
    let listener = match listen(LISTEN) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "cannot listen on {LISTEN}");
            return ExitCode::FAILURE;
        }
    };
    // One connection limit and one DNS cache for the HTTP listener and every forward.
    let shared = Shared::new();
    let mut tasks = JoinSet::new();
    for fwd in forwards {
        let addr = format!("0.0.0.0:{}", fwd.listen);
        let forward_listener = match listen(&addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "cannot listen on {addr}");
                return ExitCode::FAILURE;
            }
        };
        tracing::info!(listen = fwd.listen, dest = %fwd.target(), "forward listening");
        tasks.spawn(serve_forward(
            forward_listener,
            fwd,
            policy.clone(),
            shared.clone(),
            Timeouts::default(),
        ));
    }
    tracing::info!("cite-egress listening on {LISTEN}");
    let forwards_ended = async {
        if tasks.is_empty() {
            std::future::pending::<()>().await;
        }
        let _ = tasks.join_next().await;
    };
    tokio::select! {
        () = serve_with(listener, policy, Timeouts::default(), shared) => ExitCode::FAILURE,
        () = forwards_ended => {
            tracing::error!("a forward stopped unexpectedly");
            ExitCode::FAILURE
        }
        _ = tokio::signal::ctrl_c() => ExitCode::SUCCESS,
    }
}
