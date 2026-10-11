#![forbid(unsafe_code)]
#![allow(clippy::collapsible_if)]

use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;

use cite_core::{ExecutorConfig, Result};
use cite_executor::{RunningExecutor, init_logging, spawn};
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> ExitCode {
    cite_core::set_tight_umask();
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("daemon") => match run_daemon().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("cite-executor: {err}");
                ExitCode::FAILURE
            }
        },
        Some("healthcheck") => {
            if healthcheck() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("status") => match print_status() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Some(other) => {
            eprintln!("unknown command: {other}");
            ExitCode::FAILURE
        }
    }
}

async fn run_daemon() -> Result<()> {
    let config = ExecutorConfig::load()?;
    let redactor = cite_executor::runtime_redactor(&config);
    init_logging(redactor);
    if let Some(limit) = cite_executor::raise_nofile_limit() {
        tracing::debug!(limit, "open file limit");
    }

    let mut running: RunningExecutor = spawn(config).await?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
        _ = running.exited() => {}
    }
    running.shutdown().await;
    Ok(())
}

fn healthcheck() -> bool {
    let listen = env::var("CITE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let port = listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)).is_ok()
}

fn print_status() -> Result<()> {
    let config = ExecutorConfig::load()?;
    let path = config.status_path();
    let bytes = std::fs::read(&path)?;
    let text = String::from_utf8_lossy(&bytes);
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}
