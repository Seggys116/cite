use std::path::Path;
use std::time::Duration;

use cite_client::ConfigFile;
use cite_edge::auth::{Credentials, generate_password, hash_password, validate_username};
use cite_edge::totp;

use crate::error::{Error, Result};
use crate::qr;
use crate::settings::{DEFAULT_PORT, Settings};

const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);
const TOTP_ISSUER: &str = "Cite";

#[derive(Debug, Clone)]
pub struct InitReport {
    pub username: String,
    pub password: String,
    pub totp_secret: String,
    pub totp_uri: String,
}

fn setup_err(err: impl std::fmt::Display) -> Error {
    Error::Setup(err.to_string())
}

pub fn init_account(config_path: &Path, username: &str, force: bool) -> Result<InitReport> {
    if !validate_username(username) {
        return Err(Error::Setup(
            "username must be 3 to 32 characters of a-z, 0-9, '_', '.' or '-'".into(),
        ));
    }
    let mut config = ConfigFile::load_or_default(config_path)?;
    if config.admin.is_some() && !force {
        return Err(Error::Setup(
            "an admin account already exists; pass --force to replace it".into(),
        ));
    }
    // Only the hash is stored, so the plaintext in the report is the single copy.
    let password = generate_password().map_err(setup_err)?;
    let password_hash = hash_password(&password).map_err(setup_err)?;
    let totp_secret = totp::generate_secret().map_err(setup_err)?;
    config.admin = Some(Credentials {
        username: username.to_string(),
        password_hash,
        totp_secret: totp_secret.clone(),
        totp_last_step: 0,
    });
    ConfigFile::save(config_path, &config)?;
    let totp_uri = totp::otpauth_uri(TOTP_ISSUER, username, &totp_secret);
    Ok(InitReport {
        username: username.to_string(),
        password,
        totp_secret,
        totp_uri,
    })
}

pub fn print_report(report: &InitReport) -> Result<()> {
    let code = qr::terminal(&report.totp_uri).map_err(Error::Setup)?;
    println!("Scan this code with an authenticator app:\n\n{code}\n");
    println!("Username:    {}", report.username);
    println!("Password:    {}", report.password);
    println!("TOTP secret: {}", report.totp_secret);
    println!("TOTP URI:    {}", report.totp_uri);
    println!("\nStore the password now. It is not shown again.");
    Ok(())
}

pub async fn healthcheck(settings: &Settings) -> Result<()> {
    let port = match settings.listen {
        Some(addr) => addr.port(),
        None => ConfigFile::load_or_default(&settings.config_path)
            .ok()
            .and_then(|c| c.listen.parse::<std::net::SocketAddr>().ok())
            .map_or(DEFAULT_PORT, |a| a.port()),
    };
    let scheme = if settings.tls.is_some() {
        "https"
    } else {
        "http"
    };
    // The probe only ever talks to the loopback listener, so a self-signed certificate is fine.
    let client = reqwest::Client::builder()
        .timeout(HEALTHCHECK_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(setup_err)?;
    let resp = client
        .get(format!("{scheme}://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .map_err(setup_err)?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(Error::Setup(format!(
            "healthcheck returned {}",
            resp.status()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_client::{DashboardConfig, NodeConfig};
    use cite_edge::auth::authenticate;

    #[test]
    fn init_writes_working_credentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dashboard.json");
        let report = init_account(&path, "admin", false).expect("init");
        assert_eq!(report.password.len(), 24);
        assert!(
            report
                .totp_uri
                .starts_with("otpauth://totp/Cite:admin?secret=")
        );
        let mut creds = ConfigFile::load(&path)
            .expect("load")
            .admin
            .expect("admin saved");
        let now = 1_900_000_000;
        let code = totp::code_at(&report.totp_secret, now).expect("code");
        assert!(authenticate(&mut creds, "admin", &report.password, &code, now).is_ok());
    }

    #[test]
    fn init_refuses_to_replace_without_force_and_keeps_nodes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dashboard.json");
        let mut config = DashboardConfig::default();
        config
            .add_node(NodeConfig {
                name: "edge-1".into(),
                url: "https://10.0.0.5:7443".into(),
                ca_pem: None,
                token_ref: "edge-1".into(),
                insecure_http: false,
            })
            .expect("node");
        ConfigFile::save(&path, &config).expect("save");
        let first = init_account(&path, "admin", false).expect("init");
        assert!(init_account(&path, "admin", false).is_err());
        let second = init_account(&path, "ops", true).expect("forced");
        assert_ne!(first.password, second.password);
        let saved = ConfigFile::load(&path).expect("load");
        assert_eq!(saved.admin.expect("admin").username, "ops");
        assert_eq!(saved.nodes.len(), 1);
    }

    #[test]
    fn init_rejects_bad_usernames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dashboard.json");
        assert!(init_account(&path, "Bad Name", false).is_err());
        assert!(!path.exists());
    }
}
