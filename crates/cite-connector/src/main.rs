#![forbid(unsafe_code)]

use std::process::ExitCode;

use cite_connector::config::ConnectorConfig;
use cite_connector::init::{self, InitOptions};
use cite_connector::{Result, server};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "cite-connector",
    version,
    about = "Authenticated node connector"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Serve the connector API (default)")]
    Run,
    #[command(about = "Create TLS material and the first set of credentials")]
    Init(InitArgs),
    #[command(about = "Probe the local API, for use as a container healthcheck")]
    Healthcheck,
    #[command(about = "Replace the credentials and revoke every API token")]
    ResetCredentials(ResetArgs),
}

#[derive(Args)]
struct InitArgs {
    #[arg(long, help = "Account name for the new credentials")]
    username: Option<String>,
    #[arg(
        long,
        help = "Never prompt; use defaults for anything not given as a flag"
    )]
    non_interactive: bool,
    #[arg(long, help = "Replace existing credentials")]
    force: bool,
    #[arg(
        long,
        help = "Re-issue the server certificate under the existing CA and exit"
    )]
    renew_tls: bool,
    #[arg(long, help = "Print the credentials as one JSON object")]
    json: bool,
}

#[derive(Args)]
struct ResetArgs {
    #[arg(long, help = "Account name; defaults to the current one")]
    username: Option<String>,
    #[arg(long, help = "Never prompt")]
    non_interactive: bool,
}

fn init_tracing(default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

async fn dispatch(command: Command) -> Result<()> {
    let cfg = ConnectorConfig::from_process_env()?;
    match command {
        Command::Run => server::run(cfg).await,
        Command::Init(args) => {
            let opts = InitOptions {
                username: args.username,
                non_interactive: args.non_interactive,
                force: args.force,
                renew_tls: args.renew_tls,
                json: args.json,
            };
            init::run_init(&cfg, opts).await
        }
        Command::Healthcheck => server::healthcheck(&cfg).await,
        Command::ResetCredentials(args) => {
            init::run_reset(&cfg, args.username, args.non_interactive).await
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let command = Cli::parse().command.unwrap_or(Command::Run);
    // Long-running serving logs at info; one-shot commands keep the terminal clean.
    let level = if matches!(command, Command::Run) {
        "info"
    } else {
        "warn"
    };
    init_tracing(level);
    match dispatch(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
