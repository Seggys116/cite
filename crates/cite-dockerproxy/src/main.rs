use std::process::ExitCode;

use cite_dockerproxy::config::Config;
use cite_dockerproxy::proxy::{State, healthcheck, serve};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run(cfg: Config) -> Result<(), String> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", cfg.listen))?;
    let mut term = signal(SignalKind::terminate()).map_err(|e| format!("signal handler: {e}"))?;
    tracing::info!(
        listen = %cfg.listen,
        socket = %cfg.socket.display(),
        registry = %cfg.registry,
        haproxy = %cfg.haproxy_container,
        "docker proxy started"
    );
    // Either a signal or a failed accept loop ends the process, and the supervisor restarts it.
    tokio::select! {
        () = serve(listener, State::new(&cfg)) => Ok(()),
        _ = term.recv() => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    let command = std::env::args().nth(1).unwrap_or_else(|| "run".to_string());
    let outcome = match Config::from_env() {
        Err(e) => Err(e),
        Ok(cfg) => match command.as_str() {
            "run" => run(cfg).await,
            "healthcheck" => healthcheck(cfg.listen).await,
            other => Err(format!(
                "unknown command {other:?}, expected run or healthcheck"
            )),
        },
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cite-dockerproxy: {e}");
            ExitCode::FAILURE
        }
    }
}
