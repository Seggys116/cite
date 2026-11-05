use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cite_core::atomic::{read_limited, write_atomic};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio_rustls::TlsAcceptor;

use crate::config::ConnectorConfig;
use crate::{ConnectorError, Result};

const CA_VALID_DAYS: i64 = 3650;
const LEAF_VALID_DAYS: i64 = 825;
const CA_COMMON_NAME: &str = "cite connector CA";
const MAX_PEM_BYTES: u64 = 256 * 1024;

pub struct TlsPaths {
    pub ca_pem: PathBuf,
    pub ca_key: PathBuf,
    pub server_pem: PathBuf,
    pub server_key: PathBuf,
}

impl TlsPaths {
    pub fn new(dir: &Path) -> Self {
        Self {
            ca_pem: dir.join("ca.pem"),
            ca_key: dir.join("ca.key"),
            server_pem: dir.join("server.pem"),
            server_key: dir.join("server.key"),
        }
    }
}

pub struct TlsMaterial {
    pub ca_pem: String,
    pub ca_key_pem: String,
    pub server_pem: String,
    pub server_key_pem: String,
}

pub struct TlsOutcome {
    pub ca_pem: PathBuf,
    pub fingerprint: String,
    pub generated: bool,
}

fn tls_err(what: &str, err: impl Display) -> ConnectorError {
    ConnectorError::Internal(format!("{what}: {err}"))
}

pub fn install_provider() {
    // Another component may have installed a provider already, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// Loopback names are always present so the local healthcheck can verify the certificate.
pub fn leaf_names(sans: &[String], node_name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let extras = ["localhost", "127.0.0.1", "::1", node_name];
    for name in sans.iter().map(String::as_str).chain(extras) {
        if !name.is_empty() && !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    }
    out
}

// The subject is fixed because renewal rebuilds this issuer and it must match the CA on disk.
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(CA_VALID_DAYS);
    params
}

fn issue_leaf(
    ca: &Certificate,
    ca_key: &KeyPair,
    sans: &[String],
    node_name: &str,
) -> Result<(String, String)> {
    let mut params = CertificateParams::new(leaf_names(sans, node_name))
        .map_err(|e| tls_err("invalid TLS subject alternative name", e))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, node_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(LEAF_VALID_DAYS);
    let key = KeyPair::generate().map_err(|e| tls_err("key generation failed", e))?;
    let cert = params
        .signed_by(&key, ca, ca_key)
        .map_err(|e| tls_err("certificate signing failed", e))?;
    Ok((cert.pem(), key.serialize_pem()))
}

pub fn generate(sans: &[String], node_name: &str) -> Result<TlsMaterial> {
    let ca_key = KeyPair::generate().map_err(|e| tls_err("key generation failed", e))?;
    let ca = ca_params()
        .self_signed(&ca_key)
        .map_err(|e| tls_err("CA generation failed", e))?;
    let (server_pem, server_key_pem) = issue_leaf(&ca, &ca_key, sans, node_name)?;
    Ok(TlsMaterial {
        ca_pem: ca.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        server_pem,
        server_key_pem,
    })
}

fn write_pem(path: &Path, pem: &str, mode: u32) -> Result<()> {
    write_atomic(path, pem.as_bytes(), mode)
        .map_err(|e| tls_err(&format!("cannot write {}", path.display()), e))
}

fn write_leaf(paths: &TlsPaths, server_pem: &str, server_key_pem: &str) -> Result<()> {
    write_pem(&paths.server_key, server_key_pem, 0o600)?;
    write_pem(&paths.server_pem, server_pem, 0o644)
}

pub fn write_material(paths: &TlsPaths, m: &TlsMaterial) -> Result<()> {
    write_pem(&paths.ca_key, &m.ca_key_pem, 0o600)?;
    write_pem(&paths.ca_pem, &m.ca_pem, 0o644)?;
    write_leaf(paths, &m.server_pem, &m.server_key_pem)
}

// The stored CA certificate is left untouched; the rebuilt issuer only supplies the subject and key.
pub fn renew_leaf(paths: &TlsPaths, sans: &[String], node_name: &str) -> Result<()> {
    let key_pem = read_limited(&paths.ca_key, MAX_PEM_BYTES).map_err(|_| {
        ConnectorError::Internal(format!(
            "{} is missing; run init without --renew-tls to create a new CA",
            paths.ca_key.display()
        ))
    })?;
    let key_pem = String::from_utf8(key_pem).map_err(|e| tls_err("ca.key is not text", e))?;
    let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| tls_err("ca.key is invalid", e))?;
    let issuer = ca_params()
        .self_signed(&ca_key)
        .map_err(|e| tls_err("CA rebuild failed", e))?;
    let (server_pem, server_key_pem) = issue_leaf(&issuer, &ca_key, sans, node_name)?;
    write_leaf(paths, &server_pem, &server_key_pem)
}

fn first_cert_der(pem: &[u8]) -> Result<Vec<u8>> {
    let mut reader: &[u8] = pem;
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| ConnectorError::Internal("no certificate found in PEM".into()))?
        .map_err(|e| tls_err("certificate PEM is invalid", e))?;
    Ok(cert.as_ref().to_vec())
}

pub fn ca_fingerprint(ca_pem: &[u8]) -> Result<String> {
    let der = first_cert_der(ca_pem)?;
    let digest = Sha256::digest(&der);
    let parts: Vec<String> = digest
        .as_slice()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    Ok(parts.join(":"))
}

fn outcome(paths: &TlsPaths, generated: bool) -> Result<TlsOutcome> {
    let source = if paths.ca_pem.is_file() {
        &paths.ca_pem
    } else {
        &paths.server_pem
    };
    let pem = read_limited(source, MAX_PEM_BYTES)
        .map_err(|e| tls_err(&format!("cannot read {}", source.display()), e))?;
    Ok(TlsOutcome {
        ca_pem: source.clone(),
        fingerprint: ca_fingerprint(&pem)?,
        generated,
    })
}

pub fn ensure(cfg: &ConnectorConfig) -> Result<TlsOutcome> {
    let paths = TlsPaths::new(&cfg.tls_dir);
    let have_leaf = paths.server_pem.is_file() && paths.server_key.is_file();
    let can_reissue = paths.ca_pem.is_file() && paths.ca_key.is_file();
    let generated = if have_leaf {
        false
    } else if can_reissue {
        renew_leaf(&paths, &cfg.tls_sans, &cfg.node_name)?;
        true
    } else {
        write_material(&paths, &generate(&cfg.tls_sans, &cfg.node_name)?)?;
        true
    };
    outcome(&paths, generated)
}

pub fn renew(cfg: &ConnectorConfig) -> Result<TlsOutcome> {
    let paths = TlsPaths::new(&cfg.tls_dir);
    renew_leaf(&paths, &cfg.tls_sans, &cfg.node_name)?;
    outcome(&paths, true)
}

pub fn load_acceptor(dir: &Path) -> Result<TlsAcceptor> {
    install_provider();
    let paths = TlsPaths::new(dir);
    let missing = |_| {
        ConnectorError::Internal(format!(
            "TLS certificate or key not found in {}; run `cite-connector init`",
            dir.display()
        ))
    };
    let cert_pem = read_limited(&paths.server_pem, MAX_PEM_BYTES).map_err(missing)?;
    let key_pem = read_limited(&paths.server_key, MAX_PEM_BYTES).map_err(missing)?;
    let mut cert_reader: &[u8] = &cert_pem;
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| tls_err("server.pem is invalid", e))?;
    if certs.is_empty() {
        return Err(ConnectorError::Internal(
            "server.pem has no certificate".into(),
        ));
    }
    let mut key_reader: &[u8] = &key_pem;
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| tls_err("server.key is invalid", e))?
        .ok_or_else(|| ConnectorError::Internal("server.key has no private key".into()))?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| tls_err("server certificate and key do not match", e))?;
    // Only HTTP/1.1 is served, so that is the only protocol offered.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn client_config_for_ca(ca_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>> {
    install_provider();
    let mut roots = rustls::RootCertStore::empty();
    let mut reader: &[u8] = ca_pem;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| tls_err("CA PEM is invalid", e))?;
        roots
            .add(cert)
            .map_err(|e| tls_err("CA certificate rejected", e))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::test_config;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    fn sans() -> Vec<String> {
        vec!["connector.example.com".to_string()]
    }

    async fn handshake(acceptor: TlsAcceptor, ca_pem: &str, name: &'static str) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(stream).await
            {
                let _ = tls.write_all(b"pong").await;
                let _ = tls.shutdown().await;
            }
        });
        let connector =
            TlsConnector::from(client_config_for_ca(ca_pem.as_bytes()).expect("client"));
        let stream = TcpStream::connect(addr).await.expect("connect");
        let server_name = rustls::pki_types::ServerName::try_from(name).expect("name");
        let Ok(mut tls) = connector.connect(server_name, stream).await else {
            return false;
        };
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf).await;
        buf == b"pong"
    }

    #[test]
    fn names_include_defaults_without_duplicates() {
        let names = leaf_names(&["localhost".into(), "a.example".into()], "n1");
        assert_eq!(
            names,
            vec!["localhost", "a.example", "127.0.0.1", "::1", "n1"]
        );
    }

    #[test]
    fn generated_material_is_pem_encoded() {
        let m = generate(&sans(), "n1").expect("generate");
        assert!(m.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(m.server_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(m.ca_key_pem.contains("PRIVATE KEY"));
        assert!(m.server_key_pem.contains("PRIVATE KEY"));
        assert_ne!(m.ca_pem, m.server_pem);
    }

    #[test]
    fn fingerprint_is_colon_separated_sha256() {
        let m = generate(&sans(), "n1").expect("generate");
        let fp = ca_fingerprint(m.ca_pem.as_bytes()).expect("fingerprint");
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert!(
            fp.split(':')
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
        );
        assert_eq!(fp, ca_fingerprint(m.ca_pem.as_bytes()).expect("again"));
        assert!(ca_fingerprint(b"not a pem").is_err());
    }

    #[tokio::test]
    async fn leaf_chains_to_the_generated_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        let m = generate(&sans(), "n1").expect("generate");
        let paths = TlsPaths::new(dir.path());
        write_material(&paths, &m).expect("write");
        let acceptor = load_acceptor(dir.path()).expect("acceptor");
        assert!(handshake(acceptor.clone(), &m.ca_pem, "localhost").await);
        assert!(handshake(acceptor.clone(), &m.ca_pem, "connector.example.com").await);
        assert!(!handshake(acceptor, &m.ca_pem, "evil.example").await);
    }

    #[tokio::test]
    async fn an_unrelated_ca_is_not_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let m = generate(&sans(), "n1").expect("generate");
        write_material(&TlsPaths::new(dir.path()), &m).expect("write");
        let other = generate(&sans(), "n2").expect("other");
        let acceptor = load_acceptor(dir.path()).expect("acceptor");
        assert!(!handshake(acceptor, &other.ca_pem, "localhost").await);
    }

    #[tokio::test]
    async fn renewed_leaf_still_validates_against_the_original_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        let m = generate(&sans(), "n1").expect("generate");
        let paths = TlsPaths::new(dir.path());
        write_material(&paths, &m).expect("write");
        renew_leaf(&paths, &sans(), "n1").expect("renew");
        let renewed = std::fs::read_to_string(&paths.server_pem).expect("read");
        assert_ne!(renewed, m.server_pem);
        assert_eq!(
            std::fs::read_to_string(&paths.ca_pem).expect("ca"),
            m.ca_pem
        );
        let acceptor = load_acceptor(dir.path()).expect("acceptor");
        assert!(handshake(acceptor, &m.ca_pem, "localhost").await);
    }

    #[test]
    fn renew_without_ca_key_explains_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = renew_leaf(&TlsPaths::new(dir.path()), &sans(), "n1").expect_err("must fail");
        assert!(err.to_string().contains("ca.key"));
    }

    #[test]
    fn ensure_is_idempotent_and_keys_are_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        std::fs::create_dir_all(&cfg.tls_dir).expect("mkdir");
        let first = ensure(&cfg).expect("ensure");
        assert!(first.generated);
        let second = ensure(&cfg).expect("ensure again");
        assert!(!second.generated);
        assert_eq!(first.fingerprint, second.fingerprint);
        let paths = TlsPaths::new(&cfg.tls_dir);
        for key in [&paths.ca_key, &paths.server_key] {
            let mode = std::fs::metadata(key).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let renewed = renew(&cfg).expect("renew");
        assert_eq!(renewed.fingerprint, first.fingerprint);
    }

    #[test]
    fn missing_material_points_at_init() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = load_acceptor(dir.path()).err().expect("must fail");
        assert!(err.to_string().contains("init"));
    }
}
