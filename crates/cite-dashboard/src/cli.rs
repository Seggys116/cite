use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cite_client::ConfigFile;
use cite_edge::auth::{Credentials, generate_password, hash_password, validate_username};
use cite_edge::totp;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use subtle::ConstantTimeEq;

use crate::configlock::ConfigLock;
use crate::error::{Error, Result};
use crate::qr;
use crate::settings::{DEFAULT_PORT, Settings};

const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);
const TOTP_ISSUER: &str = "Cite";

#[derive(Clone)]
pub struct InitReport {
    pub username: String,
    pub password: String,
    pub totp_secret: String,
    pub totp_uri: String,
}

// Debug is written by hand so a stray `{:?}` can never put the password or TOTP secret in a log.
impl std::fmt::Debug for InitReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitReport")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
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
    let _lock = ConfigLock::acquire(config_path)?;
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
    // A running dashboard adopts the new admin and drops its sessions when it sees a newer generation.
    config.generation = config.generation.saturating_add(1);
    ConfigFile::save(config_path, &config)?;
    let totp_uri = totp::otpauth_uri(TOTP_ISSUER, username, &totp_secret);
    Ok(InitReport {
        username: username.to_string(),
        password,
        totp_secret,
        totp_uri,
    })
}

// The operator sees the generated credentials once, so they go straight to a locked stdout and never through tracing.
pub fn print_report(report: &InitReport) -> Result<()> {
    let code = qr::terminal(&report.totp_uri).map_err(Error::Setup)?;
    let stdout = std::io::stdout();
    write_report(&mut stdout.lock(), report, &code)?;
    Ok(())
}

fn write_report(out: &mut impl Write, report: &InitReport, code: &str) -> std::io::Result<()> {
    write!(
        out,
        "Scan this code with an authenticator app:\n\n{code}\n\n"
    )?;
    writeln!(out, "Username:    {}", report.username)?;
    writeln!(out, "Password:    {}", report.password)?;
    writeln!(out, "TOTP secret: {}", report.totp_secret)?;
    writeln!(out, "TOTP URI:    {}", report.totp_uri)?;
    writeln!(out, "\nStore the password now. It is not shown again.")?;
    out.flush()
}

// Trusts exactly the certificate the dashboard serves, so a self-signed listener passes without disabling verification.
#[derive(Debug)]
struct PinnedCert {
    pinned: CertificateDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if bool::from(end_entity.as_ref().ct_eq(self.pinned.as_ref())) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn pinned_client_config(cert_path: &Path) -> Result<rustls::ClientConfig> {
    let pinned = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| setup_err(format!("cannot read {}: {e}", cert_path.display())))?
        .next()
        .ok_or_else(|| setup_err(format!("no certificate in {}", cert_path.display())))?
        .map_err(|e| {
            setup_err(format!(
                "invalid certificate in {}: {e}",
                cert_path.display()
            ))
        })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedCert {
        pinned,
        algorithms: provider.signature_verification_algorithms,
    };
    let config =
        rustls::ClientConfig::builder_with_provider(CryptoProvider::clone(&provider).into())
            .with_safe_default_protocol_versions()
            .map_err(setup_err)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
    Ok(config)
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
    // The probe pins the listener's own certificate file, since a self-signed one has no CA to chain to.
    let mut builder = reqwest::Client::builder()
        .timeout(HEALTHCHECK_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(tls) = &settings.tls {
        builder = builder.use_preconfigured_tls(pinned_client_config(&tls.cert)?);
    }
    let client = builder.build().map_err(setup_err)?;
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

    fn pinned(der: &[u8]) -> PinnedCert {
        PinnedCert {
            pinned: CertificateDer::from(der.to_vec()),
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    fn check(verifier: &PinnedCert, presented: &[u8]) -> bool {
        let name = ServerName::try_from("127.0.0.1").expect("name");
        verifier
            .verify_server_cert(
                &CertificateDer::from(presented.to_vec()),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    #[test]
    fn pinned_verifier_accepts_only_the_exact_certificate() {
        let verifier = pinned(b"served-certificate");
        assert!(check(&verifier, b"served-certificate"));
        assert!(!check(&verifier, b"other-certificate"));
        assert!(!check(&verifier, b"served-certificate-extra"));
        assert!(!check(&verifier, b""));
    }

    #[test]
    fn pinned_config_rejects_missing_or_empty_pem() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(pinned_client_config(&dir.path().join("absent.pem")).is_err());
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").expect("write");
        assert!(pinned_client_config(&empty).is_err());
    }

    #[test]
    fn report_debug_hides_secrets_and_output_shows_them_once() {
        let report = InitReport {
            username: "admin".into(),
            password: "pw-value-123".into(),
            totp_secret: "SECRETBASE32".into(),
            totp_uri: "otpauth://totp/Cite:admin?secret=SECRETBASE32".into(),
        };
        let debug = format!("{report:?}");
        assert!(debug.contains("admin"));
        assert!(!debug.contains("pw-value-123"));
        assert!(!debug.contains("SECRETBASE32"));
        let mut out = Vec::new();
        write_report(&mut out, &report, "QR").expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("Password:    pw-value-123\n"));
        assert!(text.contains("TOTP secret: SECRETBASE32\n"));
        assert!(text.ends_with("It is not shown again.\n"));
    }

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
