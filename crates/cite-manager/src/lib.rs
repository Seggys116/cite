#![forbid(unsafe_code)]

pub mod build;
pub mod cli;
pub mod daemon;
pub mod deploy;
pub mod github;
pub mod helpers;
pub mod poll;
pub mod promote;
pub mod reconcile;
pub mod socket;

pub use cite_core::VERSION;
pub use daemon::run_daemon;
pub use helpers::{run_build_helper, run_clean_helper, run_pack_helper};
pub use poll::{PollDecision, decide_poll, jittered_interval};

use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "cite-manager",
    about = "Cite manager: poll, build, and promote one site",
    version = VERSION,
    disable_version_flag = true
)]
pub struct Args {
    #[arg(long = "version", short = 'V', action = clap::ArgAction::SetTrue)]
    pub version: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Run the manager daemon (default when no subcommand)")]
    Daemon,
    #[command(about = "Compose healthcheck: talk to the local control socket")]
    Healthcheck,
    #[command(about = "Show manager / release status")]
    Status {
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Poll GitHub now")]
    Poll,
    #[command(about = "Build and deploy the branch head (or a specific SHA)")]
    Redeploy {
        #[arg(long)]
        sha: Option<String>,
    },
    #[command(about = "Switch back to the previous slot")]
    Rollback,
    #[command(
        name = "restart-child",
        about = "Ask the executor to restart the live site process"
    )]
    RestartChild,
    #[command(
        name = "restart-executor",
        about = "Ask the executor to exit so Docker relaunches it"
    )]
    RestartExecutor,
    #[command(about = "Stop automatic deploys")]
    Pause,
    #[command(about = "Resume automatic deploys")]
    Resume,
    #[command(about = "Recent build logs")]
    Logs,
    #[command(about = "Configuration helpers")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    #[command(name = "__build", hide = true)]
    BuildHelper { job_json: String },
    #[command(name = "__pack", hide = true)]
    PackHelper { dir: String },
    #[command(name = "__clean", hide = true)]
    CleanHelper { job_dir: String },
    #[command(name = "__ptrace-probe", hide = true)]
    PtraceProbe,
    #[command(name = "__supervise", hide = true)]
    Supervise { job_json: String },
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    #[command(about = "Validate and print redacted effective config")]
    Check,
}

pub fn run() -> ExitCode {
    cite_core::set_tight_umask();
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = dispatch_helpers(&args) {
        return code;
    }

    let parsed = match Args::try_parse_from(&args) {
        Ok(v) => v,
        Err(err) => {
            let _ = err.print();
            return if err.use_stderr() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    if parsed.version {
        println!("cite-manager {VERSION}");
        return ExitCode::SUCCESS;
    }

    // Helpers use stdout for data (tar, JSON events), so the startup log must stay off it.
    if matches!(
        parsed.command,
        Some(
            Command::BuildHelper { .. }
                | Command::PackHelper { .. }
                | Command::CleanHelper { .. }
                | Command::PtraceProbe
                | Command::Supervise { .. }
        )
    ) {
        init_tracing_stderr();
    } else {
        init_tracing();
    }

    let result = match parsed.command {
        None | Some(Command::Daemon) => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    eprintln!("failed to start runtime: {err}");
                    return ExitCode::FAILURE;
                }
            };
            rt.block_on(async {
                match cite_core::ManagerConfig::load() {
                    Ok(cfg) => run_daemon(cfg).await,
                    Err(err) => Err(err.into()),
                }
            })
        }
        Some(Command::Healthcheck) => cli::healthcheck(),
        Some(Command::Status { json }) => cli::status(json),
        Some(Command::Poll) => cli::send(cite_core::ControlRequest::Poll),
        Some(Command::Redeploy { sha }) => cli::send(cite_core::ControlRequest::Redeploy { sha }),
        Some(Command::Rollback) => cli::send(cite_core::ControlRequest::Rollback),
        Some(Command::RestartChild) => cli::send(cite_core::ControlRequest::RestartChild),
        Some(Command::RestartExecutor) => cli::send(cite_core::ControlRequest::RestartExecutor),
        Some(Command::Pause) => cli::send(cite_core::ControlRequest::Pause),
        Some(Command::Resume) => cli::send(cite_core::ControlRequest::Resume),
        Some(Command::Logs) => cli::send(cite_core::ControlRequest::Logs),
        Some(Command::Config {
            action: ConfigAction::Check,
        }) => cli::config_check(),
        Some(Command::BuildHelper { job_json }) => {
            helpers::apply_build_limits();
            run_build_helper(Path::new(&job_json))
        }
        Some(Command::PackHelper { dir }) => {
            helpers::apply_build_limits();
            run_pack_helper(Path::new(&dir))
        }
        Some(Command::CleanHelper { job_dir }) => {
            helpers::apply_build_limits();
            run_clean_helper(Path::new(&job_dir))
        }
        Some(Command::PtraceProbe) => {
            helpers::probe_ptrace_pid1();
            Ok(())
        }
        Some(Command::Supervise { job_json }) => match cite_core::ManagerConfig::load() {
            Ok(cfg) => build::supervise_build_job(&cfg, Path::new(&job_json)),
            Err(err) => Err(err.into()),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch_helpers(args: &[String]) -> Option<ExitCode> {
    let argv0 = args.first().map(String::as_str).unwrap_or("cite-manager");
    let _name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("cite-manager");
    None
}

fn init_tracing() {
    install_tracing(std::io::stdout);
    info!("manager ready");
}

fn init_tracing_stderr() {
    install_tracing(std::io::stderr);
}

fn install_tracing<W>(writer: W) -> bool
where
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .json()
                .with_writer(writer)
                .with_filter(filter),
        )
        .with(deploy::BuildLogLayer.with_filter(deploy::build_log_filter()))
        .try_init()
        .is_ok()
}

#[derive(Debug)]
pub struct ManagerError(String);

impl ManagerError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ManagerError {}

impl From<cite_core::Error> for ManagerError {
    fn from(value: cite_core::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<std::io::Error> for ManagerError {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<serde_json::Error> for ManagerError {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<reqwest::Error> for ManagerError {
    fn from(value: reqwest::Error) -> Self {
        let mut msg = value.to_string();
        let mut src = std::error::Error::source(&value);
        while let Some(err) = src {
            msg.push_str(": ");
            msg.push_str(&err.to_string());
            src = err.source();
        }
        Self(msg)
    }
}

impl From<String> for ManagerError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ManagerError {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ManagerError>;

#[cfg(test)]
mod tests {
    use super::ManagerError;

    #[test]
    fn manager_error_keeps_the_source_message() {
        let from_str = ManagerError::from("plain");
        assert_eq!(from_str.to_string(), "plain");
        let from_string = ManagerError::from(String::from("owned"));
        assert_eq!(from_string.to_string(), "owned");
        let io = ManagerError::from(std::io::Error::other("disk"));
        assert!(io.to_string().contains("disk"));
        let json = ManagerError::from(serde_json::from_str::<u32>("nope").unwrap_err());
        assert!(!json.to_string().is_empty());
        let core = ManagerError::from(cite_core::Error::msg("core-fail"));
        assert!(core.to_string().contains("core-fail"));
        let err = ManagerError::new("built");
        assert_eq!(err.to_string(), "built");
        let _dyn: &dyn std::error::Error = &err;
    }
}
