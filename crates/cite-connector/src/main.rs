#![forbid(unsafe_code)]

use std::io::{IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use cite_connector::config::ConnectorConfig;
use cite_connector::data::stream::StreamReader;
use cite_connector::init::{self, InitOptions};
use cite_connector::seal::{self, FileState, Keyring, OpenMode};
use cite_connector::store::Store;
use cite_connector::{ConnectorError, Result, server};
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
    #[command(about = "Inspect, export and rotate the key that seals secrets at rest")]
    Secrets(SecretsArgs),
    #[command(about = "Work with backup files")]
    Backup(BackupArgs),
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

#[derive(Args)]
struct SecretsArgs {
    #[command(subcommand)]
    command: SecretsCommand,
}

#[derive(Subcommand)]
enum SecretsCommand {
    #[command(about = "Show the key id, where the key comes from and which files are sealed")]
    Status,
    #[command(about = "Print the node key, to be stored away from the node")]
    ExportKey(ExportKeyArgs),
    #[command(
        about = "Replace the managed key; the next start re-seals every file under the new one"
    )]
    RotateKey,
}

#[derive(Args)]
struct ExportKeyArgs {
    #[arg(long, help = "Print even when standard output is a terminal")]
    yes: bool,
}

#[derive(Args)]
struct BackupArgs {
    #[command(subcommand)]
    command: BackupCommand,
}

#[derive(Subcommand)]
enum BackupCommand {
    #[command(about = "Decrypt a backup file with the node key, on this node or anywhere")]
    Decrypt(DecryptArgs),
}

#[derive(Args)]
struct DecryptArgs {
    #[arg(long = "in", value_name = "FILE", help = "The encrypted backup file")]
    input: PathBuf,
    #[arg(
        long,
        value_name = "FILE",
        help = "Where to write the plaintext; must not exist"
    )]
    out: PathBuf,
    #[arg(long, help = "The backup id the file was made under")]
    backup_id: String,
    #[arg(
        long,
        value_name = "FILE",
        help = "A file holding the node key; without it the node's own key is used"
    )]
    key_file: Option<PathBuf>,
}

fn init_tracing(default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    // Logs go to stderr so the JSON that init prints on stdout stays machine readable.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

fn node_key(cfg: &ConnectorConfig) -> Result<Keyring> {
    Keyring::load(cfg, OpenMode::ReadOnly)?.ok_or_else(|| {
        ConnectorError::NotFound(
            "this node has no secrets key yet; it is created the first time the connector starts or init runs"
                .into(),
        )
    })
}

// What a sealed file's key is to this node, for a reader deciding whether a restore is needed.
fn key_role(ring: &Keyring, kid: &str) -> &'static str {
    if ring.kid_hex() == kid {
        "current key"
    } else if ring.older_kids().iter().any(|k| k == kid) {
        "previous key, re-sealed at the next start"
    } else {
        "KEY NOT HELD"
    }
}

fn secrets_status(cfg: &ConnectorConfig) -> Result<()> {
    let ring = Keyring::load(cfg, OpenMode::ReadOnly);
    match &ring {
        Ok(Some(ring)) => {
            println!("key id     {}", ring.kid_hex());
            println!("source     {}", ring.source().describe());
            if ring.has_older() {
                println!("previous   {}", ring.older_kids().join(", "));
            }
        }
        Ok(None) => {
            println!("key        none yet (files stay plaintext until the connector starts)")
        }
        Err(e) => println!("key        problem: {e}"),
    }
    println!();
    for (name, state) in seal::file_states(&cfg.data_dir) {
        let line = match (&state, &ring) {
            (FileState::Absent, _) => "absent".to_string(),
            (FileState::Plaintext, _) => "plaintext".to_string(),
            (FileState::Unreadable, _) => "unreadable or damaged".to_string(),
            (FileState::Sealed { kid }, Ok(Some(ring))) => {
                format!("sealed, key {kid} ({})", key_role(ring, kid))
            }
            (FileState::Sealed { kid }, _) => format!("sealed, key {kid}"),
        };
        println!("{name:<20} {line}");
    }
    ring.map(|_| ())
}

fn export_key(cfg: &ConnectorConfig, args: &ExportKeyArgs) -> Result<()> {
    if std::io::stdout().is_terminal() && !args.yes {
        return Err(ConnectorError::BadRequest(
            "refusing to print the key to a terminal; redirect standard output to a file or pass --yes"
                .into(),
        ));
    }
    let ring = node_key(cfg)?;
    println!("{}", ring.primary_text().as_str());
    Ok(())
}

async fn rotate_key(cfg: &ConnectorConfig) -> Result<()> {
    let owned = cfg.clone();
    let (old, new) = tokio::task::spawn_blocking(move || seal::rotate_managed(&owned))
        .await
        .map_err(|e| ConnectorError::Internal(format!("rotation task failed: {e}")))??;
    // The audit entry names key ids only; failing to write it must not hide that the rotation happened.
    match Store::open_read_only(cfg).await {
        Ok(store) => {
            store
                .audit(
                    "cli",
                    "secrets.key_rotated",
                    &format!("from={old} to={new}"),
                )
                .await;
        }
        Err(e) => tracing::warn!(error = %e, "the rotation could not be recorded in the audit log"),
    }
    println!("key rotated: {old} -> {new}");
    println!(
        "The old key is kept as secrets.key.previous until the next start has re-sealed everything."
    );
    println!(
        "Restart the connector to re-seal. Back up the new key: cite-connector secrets export-key > key-file"
    );
    Ok(())
}

fn backup_decrypt(args: &DecryptArgs, cfg: Option<&ConnectorConfig>) -> Result<()> {
    let ring = match (&args.key_file, cfg) {
        (Some(path), _) => Keyring::from_key_file(path)?,
        (None, Some(cfg)) => node_key(cfg)?,
        (None, None) => {
            return Err(ConnectorError::BadRequest(
                "pass --key-file, or run on the node whose key sealed the backup".into(),
            ));
        }
    };
    let mut reader = StreamReader::open(&args.input, &ring, &args.backup_id)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.out)
        .map_err(|e| {
            ConnectorError::BadRequest(format!("cannot create {}: {e}", args.out.display()))
        })?;
    let mut out = std::io::BufWriter::new(file);
    let copied = reader.copy_to(&mut out).and_then(|sha256| {
        out.flush()
            .and_then(|()| out.get_ref().sync_all())
            .map(|()| sha256)
            .map_err(|e| ConnectorError::Internal(format!("cannot finish the output: {e}")))
    });
    match copied {
        Ok(sha256) => {
            println!(
                "decrypted {} bytes to {}\nsha256 {sha256}",
                reader.plaintext_len(),
                args.out.display()
            );
            Ok(())
        }
        Err(e) => {
            // a half-written plaintext file must not be left behind
            drop(out);
            let _ = std::fs::remove_file(&args.out);
            Err(e)
        }
    }
}

async fn dispatch(command: Command) -> Result<()> {
    // Decrypting with a key file needs nothing else from the environment, so it can run on any machine.
    if let Command::Backup(BackupArgs {
        command: BackupCommand::Decrypt(args),
    }) = &command
        && args.key_file.is_some()
    {
        return backup_decrypt(args, None);
    }
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
        Command::Secrets(args) => match args.command {
            SecretsCommand::Status => secrets_status(&cfg),
            SecretsCommand::ExportKey(export) => export_key(&cfg, &export),
            SecretsCommand::RotateKey => rotate_key(&cfg).await,
        },
        Command::Backup(args) => match args.command {
            BackupCommand::Decrypt(decrypt) => backup_decrypt(&decrypt, Some(&cfg)),
        },
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use cite_connector::data::stream::StreamWriter;
    use cite_connector::seal::{KeySource, NodeKey};
    use clap::CommandFactory;

    const ID: &str = "01HZZZZZZZZZZZZZZZZZZZZZZZ";

    fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("cite-connector").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_secrets_and_backup_commands_parse() {
        assert!(matches!(
            parse(&["secrets", "status"]).unwrap().command,
            Some(Command::Secrets(SecretsArgs {
                command: SecretsCommand::Status
            }))
        ));
        assert!(matches!(
            parse(&["secrets", "rotate-key"]).unwrap().command,
            Some(Command::Secrets(SecretsArgs {
                command: SecretsCommand::RotateKey
            }))
        ));
        let export = parse(&["secrets", "export-key", "--yes"]).unwrap();
        assert!(matches!(
            export.command,
            Some(Command::Secrets(SecretsArgs {
                command: SecretsCommand::ExportKey(ExportKeyArgs { yes: true })
            }))
        ));
        let decrypt = parse(&[
            "backup",
            "decrypt",
            "--in",
            "a.cbk",
            "--out",
            "a.dump",
            "--backup-id",
            ID,
            "--key-file",
            "k",
        ])
        .unwrap();
        let Some(Command::Backup(BackupArgs {
            command: BackupCommand::Decrypt(args),
        })) = decrypt.command
        else {
            panic!("expected backup decrypt");
        };
        assert_eq!(args.input, Path::new("a.cbk"));
        assert_eq!(args.out, Path::new("a.dump"));
        assert_eq!(args.backup_id, ID);
        assert_eq!(args.key_file.as_deref(), Some(Path::new("k")));
        assert!(
            parse(&["backup", "decrypt", "--in", "a"]).is_err(),
            "out and id are required"
        );
        assert!(parse(&["secrets"]).is_err());
    }

    fn make_backup(dir: &Path, key: &NodeKey, data: &[u8]) -> PathBuf {
        let ring = Keyring::from_keys(key.clone(), KeySource::Env, Vec::new(), OpenMode::Migrating);
        let path = dir.join("a.cbk");
        let mut writer = StreamWriter::create(&path, &ring, ID).expect("create");
        writer.write_all(data).expect("write");
        writer.finish().expect("finish");
        path
    }

    fn decrypt_args(
        dir: &Path,
        input: PathBuf,
        key_file: Option<PathBuf>,
        id: &str,
    ) -> DecryptArgs {
        DecryptArgs {
            input,
            out: dir.join("out.dump"),
            backup_id: id.to_string(),
            key_file,
        }
    }

    #[test]
    fn decrypt_recovers_a_backup_anywhere_with_only_a_key_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = NodeKey::from_bytes(&[5; 32]);
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let backup = make_backup(dir.path(), &key, &data);
        let key_file = dir.path().join("node.key");
        std::fs::write(&key_file, format!("{}\n", key.text().as_str())).expect("key file");

        let args = decrypt_args(dir.path(), backup, Some(key_file), ID);
        backup_decrypt(&args, None).expect("decrypt");
        assert_eq!(std::fs::read(&args.out).expect("out"), data);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&args.out)
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let again = backup_decrypt(&args, None)
            .expect_err("never overwrites")
            .to_string();
        assert!(again.contains("cannot create"), "{again}");
    }

    #[test]
    fn decrypt_with_the_wrong_key_or_id_fails_and_leaves_no_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = NodeKey::from_bytes(&[5; 32]);
        let backup = make_backup(dir.path(), &key, b"secret dump");
        let wrong_key = dir.path().join("wrong.key");
        std::fs::write(&wrong_key, NodeKey::from_bytes(&[6; 32]).text().as_bytes()).expect("key");
        let right_key = dir.path().join("right.key");
        std::fs::write(&right_key, key.text().as_bytes()).expect("key");

        let bad_key = decrypt_args(dir.path(), backup.clone(), Some(wrong_key), ID);
        assert!(backup_decrypt(&bad_key, None).is_err());
        let bad_id = decrypt_args(
            dir.path(),
            backup.clone(),
            Some(right_key.clone()),
            "01HOTHER",
        );
        assert!(backup_decrypt(&bad_id, None).is_err());
        assert!(!bad_key.out.exists(), "no plaintext file after a failure");

        let none = decrypt_args(dir.path(), backup.clone(), None, ID);
        assert!(
            backup_decrypt(&none, None).is_err(),
            "no key file and no node"
        );

        // damage found while decrypting removes the half-written output
        let mut raw = std::fs::read(&backup).expect("read");
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(&backup, raw).expect("write");
        let damaged = decrypt_args(dir.path(), backup, Some(right_key), ID);
        assert!(backup_decrypt(&damaged, None).is_err());
        assert!(!damaged.out.exists());
    }
}
