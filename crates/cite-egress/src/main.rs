use std::process::ExitCode;
use std::sync::Arc;

use cite_egress::policy::Policy;
use cite_egress::proxy::{LISTEN, Timeouts, serve};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let policy = match Policy::from_env() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "invalid egress configuration");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(LISTEN).await {
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
