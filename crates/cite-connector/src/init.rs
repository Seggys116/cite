use std::fmt;
use std::io::{BufRead, IsTerminal, Write};

use cite_edge::auth::{Credentials, generate_password, hash_password, validate_username};
use cite_edge::totp;
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

use crate::config::ConnectorConfig;
use crate::store::Store;
use crate::tls::{self, TlsOutcome};
use crate::{ConnectorError, Result};

const DEFAULT_USERNAME: &str = "admin";
const OTP_ISSUER: &str = "cite connector";
const OVERWRITE_MESSAGE: &str =
    "credentials already exist; pass --force to replace them, or run reset-credentials";

#[derive(Debug, Clone, Default)]
pub struct InitOptions {
    pub username: Option<String>,
    pub non_interactive: bool,
    pub force: bool,
    pub renew_tls: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Init { force: bool },
    Reset,
}

pub struct Provisioned {
    pub username: String,
    pub password: String,
    pub totp_secret: String,
    pub otpauth_uri: String,
    pub tls: Option<TlsOutcome>,
    pub reset: bool,
}

// Secrets are redacted so a stray {:?} cannot leak them into logs.
impl fmt::Debug for Provisioned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provisioned")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("totp_secret", &"[redacted]")
            .field("reset", &self.reset)
            .finish()
    }
}

fn auth_failure(err: impl fmt::Display) -> ConnectorError {
    ConnectorError::Internal(format!("credential generation failed: {err}"))
}

fn resolve_username(
    given: Option<String>,
    non_interactive: bool,
    existing: Option<&str>,
) -> Result<String> {
    if let Some(name) = given {
        return Ok(name);
    }
    let default = existing.unwrap_or(DEFAULT_USERNAME);
    // With no terminal nobody can answer the prompt, so scripts and containers get the default.
    if non_interactive || !std::io::stdin().is_terminal() {
        return Ok(default.to_string());
    }
    print!("Username [{default}]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let line = line.trim();
    let chosen = if line.is_empty() { default } else { line };
    Ok(chosen.to_string())
}

pub async fn provision(
    cfg: &ConnectorConfig,
    store: &Store,
    username: &str,
    mode: Mode,
) -> Result<Provisioned> {
    if mode == (Mode::Init { force: false }) && store.credentials().is_some() {
        return Err(ConnectorError::Conflict(OVERWRITE_MESSAGE.into()));
    }
    if !validate_username(username) {
        return Err(ConnectorError::BadRequest(
            "username must be 3 to 32 characters of a-z, 0-9, '.', '_' or '-'".into(),
        ));
    }
    // Certificates come first so a failure here cannot leave credentials without a way to connect.
    let tls = if cfg.tls {
        let cfg = cfg.clone();
        let outcome = tokio::task::spawn_blocking(move || tls::ensure(&cfg))
            .await
            .map_err(auth_failure)??;
        Some(outcome)
    } else {
        None
    };

    let password = generate_password().map_err(auth_failure)?;
    let totp_secret = totp::generate_secret().map_err(auth_failure)?;
    // Password hashing is deliberately slow, so it runs off the async worker threads.
    let to_hash = password.clone();
    let password_hash = tokio::task::spawn_blocking(move || hash_password(&to_hash))
        .await
        .map_err(auth_failure)?
        .map_err(auth_failure)?;
    let credentials = Credentials {
        username: username.to_string(),
        password_hash,
        totp_secret: totp_secret.clone(),
        totp_last_step: 0,
    };
    // Every provision empties the API tokens, since they were issued under the old credentials.
    store.reset_credentials(credentials).await?;

    let reset = mode == Mode::Reset;
    if reset {
        store
            .audit("cli", "credentials.reset", "api tokens revoked")
            .await;
    } else {
        store.audit("cli", "credentials.init", "").await;
    }
    let account = format!("{username}@{}", cfg.node_name);
    Ok(Provisioned {
        username: username.to_string(),
        password,
        otpauth_uri: totp::otpauth_uri(OTP_ISSUER, &account, &totp_secret),
        totp_secret,
        tls,
        reset,
    })
}

pub fn render_qr(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes())
        .map_err(|e| ConnectorError::Internal(format!("QR encoding failed: {e}")))?;
    // Colours are swapped so the code reads correctly on a dark terminal.
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

pub fn format_report(p: &Provisioned) -> Result<String> {
    let title = if p.reset {
        "cite connector credentials (reset)"
    } else {
        "cite connector credentials"
    };
    let mut out = String::new();
    out.push_str(title);
    out.push('\n');
    out.push_str(&"=".repeat(title.len()));
    out.push_str("\n\nThese are shown once and cannot be recovered. Save them now.\n\n");
    out.push_str(&format!("  username   {}\n", p.username));
    out.push_str(&format!("  password   {}\n", p.password));
    out.push_str(&format!("  totp key   {}\n", p.totp_secret));
    out.push_str(&format!("  otpauth    {}\n\n", p.otpauth_uri));
    out.push_str("Scan this with an authenticator app:\n\n");
    out.push_str(&render_qr(&p.otpauth_uri)?);
    out.push('\n');
    if let Some(t) = &p.tls {
        out.push_str("\nTLS\n");
        out.push_str(&format!("  CA certificate   {}\n", t.ca_pem.display()));
        out.push_str(&format!("  CA SHA-256       {}\n", t.fingerprint));
        out.push_str("  Copy the CA certificate to the dashboard and check this fingerprint.\n");
    }
    out.push_str(
        "\nA running connector picks up these credentials on its next request and signs out every session. No restart is needed.\n",
    );
    Ok(out)
}

// Only what a script needs; the otpauth URI and QR code stay in the human readable report.
pub fn format_json(p: &Provisioned) -> Result<String> {
    let fingerprint = p.tls.as_ref().map(|t| t.fingerprint.as_str());
    serde_json::to_string(&serde_json::json!({
        "username": p.username,
        "password": p.password,
        "totp_secret": p.totp_secret,
        "ca_fingerprint": fingerprint,
    }))
    .map_err(|e| ConnectorError::Internal(format!("JSON encoding failed: {e}")))
}

pub async fn run_init(cfg: &ConnectorConfig, opts: InitOptions) -> Result<()> {
    let store = Store::open(cfg).await?;
    if opts.renew_tls {
        if !cfg.tls {
            return Err(ConnectorError::BadRequest(
                "TLS is disabled (CITE_CONNECTOR_TLS=false); nothing to renew".into(),
            ));
        }
        let owned = cfg.clone();
        let outcome = tokio::task::spawn_blocking(move || tls::renew(&owned))
            .await
            .map_err(auth_failure)??;
        store.audit("cli", "tls.renew", "").await;
        println!("Server certificate re-issued under the existing CA.");
        println!("  CA certificate   {}", outcome.ca_pem.display());
        println!("  CA SHA-256       {}", outcome.fingerprint);
        println!("Restart the connector to load the new certificate.");
        return Ok(());
    }
    if store.credentials().is_some() && !opts.force {
        return Err(ConnectorError::Conflict(OVERWRITE_MESSAGE.into()));
    }
    let existing = store.credentials().map(|c| c.username);
    let username = resolve_username(opts.username, opts.non_interactive, existing.as_deref())?;
    let provisioned = provision(cfg, &store, &username, Mode::Init { force: opts.force }).await?;
    if opts.json {
        println!("{}", format_json(&provisioned)?);
    } else {
        print!("{}", format_report(&provisioned)?);
    }
    Ok(())
}

pub async fn run_reset(
    cfg: &ConnectorConfig,
    username: Option<String>,
    non_interactive: bool,
) -> Result<()> {
    let store = Store::open(cfg).await?;
    let existing = store.credentials().map(|c| c.username);
    let username = resolve_username(username, non_interactive, existing.as_deref())?;
    let provisioned = provision(cfg, &store, &username, Mode::Reset).await?;
    print!("{}", format_report(&provisioned)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{now_unix, testing::test_config};
    use std::os::unix::fs::PermissionsExt;

    async fn setup() -> (tempfile::TempDir, ConnectorConfig, std::sync::Arc<Store>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        let store = Store::open(&cfg).await.expect("open");
        (dir, cfg, store)
    }

    #[tokio::test]
    async fn provisioned_credentials_log_in() {
        let (_dir, cfg, store) = setup().await;
        let p = provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        assert_eq!(p.password.len(), 24);
        let now = now_unix();
        let code = totp::code_at(&p.totp_secret, now).expect("code");
        assert!(
            store
                .verify_login("admin", &p.password, &code, now)
                .await
                .expect("login")
        );
        assert!(p.otpauth_uri.starts_with("otpauth://totp/"));
        assert!(p.otpauth_uri.contains(&p.totp_secret));
        assert!(p.tls.is_none());
    }

    #[tokio::test]
    async fn json_report_carries_the_credentials() {
        let (_dir, cfg, store) = setup().await;
        let p = provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let value: serde_json::Value =
            serde_json::from_str(&format_json(&p).expect("json")).expect("parse");
        assert_eq!(value["username"], "admin");
        assert_eq!(value["password"], p.password.as_str());
        assert_eq!(value["totp_secret"], p.totp_secret.as_str());
        assert!(value["ca_fingerprint"].is_null());
    }

    #[tokio::test]
    async fn init_refuses_to_overwrite_without_force() {
        let (_dir, cfg, store) = setup().await;
        let first = provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let second = provision(&cfg, &store, "admin", Mode::Init { force: false }).await;
        assert!(matches!(second, Err(ConnectorError::Conflict(_))));
        let kept = store.credentials().expect("creds");
        assert_eq!(kept.totp_secret, first.totp_secret);
    }

    #[tokio::test]
    async fn force_replaces_credentials() {
        let (_dir, cfg, store) = setup().await;
        let first = provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("first");
        let second = provision(&cfg, &store, "admin", Mode::Init { force: true })
            .await
            .expect("second");
        assert_ne!(first.password, second.password);
        assert_ne!(first.totp_secret, second.totp_secret);
        let now = now_unix();
        let old_code = totp::code_at(&first.totp_secret, now).expect("code");
        assert!(
            !store
                .verify_login("admin", &first.password, &old_code, now)
                .await
                .expect("login")
        );
    }

    #[tokio::test]
    async fn reset_revokes_api_tokens() {
        let (_dir, cfg, store) = setup().await;
        provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let (_, token) = store.create_api_token("ci").await.expect("token");
        let reset = provision(&cfg, &store, "admin", Mode::Reset)
            .await
            .expect("reset");
        assert!(reset.reset);
        assert!(store.verify_api_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn running_store_adopts_a_cli_reset_and_cannot_overwrite_it() {
        let (dir, cfg, running) = setup().await;
        let first = provision(&cfg, &running, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let (_, api) = running.create_api_token("ci").await.expect("token");
        let (session, _) = running
            .create_session("admin", now_unix())
            .expect("session");
        assert!(running.validate_session(&session, now_unix()).is_some());

        let cli = Store::open(&cfg).await.expect("cli store");
        let second = provision(&cfg, &cli, "admin", Mode::Reset)
            .await
            .expect("reset");

        assert!(running.validate_session(&session, now_unix()).is_none());
        assert!(running.verify_api_token(&api).await.is_none());
        assert!(running.list_api_tokens().await.is_empty());
        let now = now_unix();
        let old_code = totp::code_at(&first.totp_secret, now).expect("code");
        assert!(
            !running
                .verify_login("admin", &first.password, &old_code, now)
                .await
                .expect("old login")
        );
        let new_code = totp::code_at(&second.totp_secret, now).expect("code");
        assert!(
            running
                .verify_login("admin", &second.password, &new_code, now)
                .await
                .expect("new login")
        );

        // The running store's writes keep the reset state on disk.
        let (_, fresh) = running.create_api_token("later").await.expect("token");
        let reopened = Store::open(&cfg).await.expect("reopen");
        assert!(reopened.verify_api_token(&api).await.is_none());
        assert!(reopened.verify_api_token(&fresh).await.is_some());
        let on_disk = reopened.credentials().expect("creds");
        assert_eq!(on_disk.totp_secret, second.totp_secret);
        assert!(dir.path().join("credentials.json").is_file());
    }

    #[tokio::test]
    async fn stale_login_cannot_overwrite_newer_credentials_on_disk() {
        let (_dir, cfg, running) = setup().await;
        let first = provision(&cfg, &running, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let cli = Store::open(&cfg).await.expect("cli store");
        let second = provision(&cfg, &cli, "admin", Mode::Init { force: true })
            .await
            .expect("force");
        let now = now_unix();
        let old_code = totp::code_at(&first.totp_secret, now).expect("code");
        assert!(
            !running
                .verify_login("admin", &first.password, &old_code, now)
                .await
                .expect("old login")
        );
        let reopened = Store::open(&cfg).await.expect("reopen");
        assert_eq!(
            reopened.credentials().expect("creds").totp_secret,
            second.totp_secret
        );
    }

    #[tokio::test]
    async fn invalid_usernames_are_rejected() {
        let (_dir, cfg, store) = setup().await;
        for bad in ["", "ab", "Admin", "has space"] {
            let result = provision(&cfg, &store, bad, Mode::Init { force: false }).await;
            assert!(
                matches!(result, Err(ConnectorError::BadRequest(_))),
                "{bad}"
            );
        }
        assert!(store.credentials().is_none());
    }

    #[tokio::test]
    async fn tls_material_is_created_when_enabled() {
        let (_dir, mut cfg, store) = setup().await;
        cfg.tls = true;
        let p = provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let outcome = p.tls.as_ref().expect("tls outcome");
        assert!(outcome.generated);
        assert!(cfg.tls_dir.join("server.pem").is_file());
        let mode = std::fs::metadata(cfg.tls_dir.join("ca.key"))
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let report = format_report(&p).expect("report");
        assert!(report.contains(&outcome.fingerprint));
        assert!(report.contains("ca.pem"));
    }

    #[tokio::test]
    async fn credentials_file_is_private() {
        let (dir, cfg, store) = setup().await;
        provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let mode = std::fs::metadata(dir.path().join("credentials.json"))
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn report_shows_secrets_once_and_debug_hides_them() {
        let (_dir, cfg, store) = setup().await;
        let p = provision(&cfg, &store, "admin", Mode::Init { force: false })
            .await
            .expect("provision");
        let report = format_report(&p).expect("report");
        assert!(report.contains(&p.password));
        assert!(report.contains(&p.totp_secret));
        assert!(report.contains("admin"));
        let debug = format!("{p:?}");
        assert!(!debug.contains(&p.password));
        assert!(!debug.contains(&p.totp_secret));
    }

    #[test]
    fn qr_renders_as_half_blocks() {
        let qr = render_qr("otpauth://totp/x:y?secret=ABC").expect("qr");
        assert!(qr.lines().count() > 10);
        assert!(
            qr.chars()
                .any(|c| c == '\u{2580}' || c == '\u{2584}' || c == '\u{2588}')
        );
    }
}
