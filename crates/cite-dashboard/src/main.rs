use std::process::ExitCode;

use cite_dashboard::cli;
use cite_dashboard::error::Result;
use cite_dashboard::server;
use cite_dashboard::settings::Settings;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cite-dashboard", version, about = "Cite dashboard server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Serve the console (the default)")]
    Run,
    #[command(about = "Create the admin account from the command line")]
    Init {
        #[arg(long, help = "Replace an existing admin account")]
        force: bool,
        #[arg(long, default_value = "admin", help = "Name of the admin account")]
        username: String,
    },
    #[command(about = "Probe the local listener and exit non-zero when it is unhealthy")]
    Healthcheck,
}

// Logs go to stderr so the credentials printed by `init` stay alone on stdout.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn dispatch(command: Command) -> Result<()> {
    let settings = Settings::from_process_env()?;
    match command {
        Command::Run => server::run(settings).await,
        Command::Init { force, username } => {
            let report = cli::init_account(&settings.config_path, &username, force)?;
            cli::print_report(&report)
        }
        Command::Healthcheck => cli::healthcheck(&settings).await,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();
    match dispatch(cli.command.unwrap_or(Command::Run)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cite-dashboard: {err}");
            ExitCode::FAILURE
        }
    }
}
