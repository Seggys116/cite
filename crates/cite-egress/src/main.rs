use std::process::ExitCode;
use std::sync::Arc;

use cite_egress::policy::Policy;
use cite_egress::proxy::{LISTEN, Timeouts, serve};
use cite_egress::routes;
use tokio::net::{TcpListener, TcpSocket};
use tracing_subscriber::EnvFilter;

// Accepted sockets inherit SO_KEEPALIVE from the listener on Linux.
fn listen() -> std::io::Result<TcpListener> {
    let addr: std::net::SocketAddr = LISTEN.parse().map_err(std::io::Error::other)?;
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.set_keepalive(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
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
    let local = routes::local_networks();
    tracing::info!(
        count = local.len(),
        "own networks and gateways added to the deny ceiling"
    );
    let policy = policy.with_local_networks(local);
    let listener = match listen() {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "cannot listen on {LISTEN}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("cite-egress listening on {LISTEN}");
    tokio::select! {
        () = serve(listener, Arc::new(policy), Timeouts::default()) => ExitCode::FAILURE,
        _ = tokio::signal::ctrl_c() => ExitCode::SUCCESS,
    }
}
