use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cite_core::atomic::{read_limited, write_atomic};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio_rustls::TlsAcceptor;

use crate::config::ConnectorConfig;
use crate::seal::{self, Keyring, OpenMode};
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
    issuer: &Issuer<'_, &KeyPair>,
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
    // Apple clients refuse a leaf valid for more than 825 days, counted from not_before.
    params.not_after = params.not_before + Duration::days(LEAF_VALID_DAYS);
    let key = KeyPair::generate().map_err(|e| tls_err("key generation failed", e))?;
    let cert = params
        .signed_by(&key, issuer)
        .map_err(|e| tls_err("certificate signing failed", e))?;
    Ok((cert.pem(), key.serialize_pem()))
}

pub fn generate(sans: &[String], node_name: &str) -> Result<TlsMaterial> {
    let ca_key = KeyPair::generate().map_err(|e| tls_err("key generation failed", e))?;
    let ca = ca_params()
        .self_signed(&ca_key)
        .map_err(|e| tls_err("CA generation failed", e))?;
    let issuer = Issuer::new(ca_params(), &ca_key);
    let (server_pem, server_key_pem) = issue_leaf(&issuer, sans, node_name)?;
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

// Private keys are sealed under the node key when there is one; certificates are public and stay PEM.
fn write_key(path: &Path, pem: &str, keyring: Option<&Keyring>) -> Result<()> {
    seal::write_path(keyring, path, pem.as_bytes(), 0o600)
}

fn write_leaf(
    paths: &TlsPaths,
    server_pem: &str,
    server_key_pem: &str,
    keyring: Option<&Keyring>,
) -> Result<()> {
    write_key(&paths.server_key, server_key_pem, keyring)?;
    write_pem(&paths.server_pem, server_pem, 0o644)
}

pub fn write_material(paths: &TlsPaths, m: &TlsMaterial, keyring: Option<&Keyring>) -> Result<()> {
    write_key(&paths.ca_key, &m.ca_key_pem, keyring)?;
    write_pem(&paths.ca_pem, &m.ca_pem, 0o644)?;
    write_leaf(paths, &m.server_pem, &m.server_key_pem, keyring)
}

// Files that exist from an earlier release hold their key as plain PEM; they move under the node key here, once, keeping a `.pre-seal` copy.
pub fn migrate_keys(tls_dir: &Path, keyring: &Keyring) -> Result<Vec<String>> {
    let mut sealed = Vec::new();
    for file in ["ca.key", "server.key"] {
        let path = tls_dir.join(file);
        if let Some(read) = seal::read_path(Some(keyring), &path, MAX_PEM_BYTES)?
            && seal::migrate_path(keyring, &path, &read)?
        {
            sealed.push(format!("tls/{file}"));
        }
    }
    Ok(sealed)
}

// The stored CA certificate is left untouched; the rebuilt issuer only supplies the subject and key.
pub fn renew_leaf(
    paths: &TlsPaths,
    sans: &[String],
    node_name: &str,
    keyring: Option<&Keyring>,
) -> Result<()> {
    let key_pem = seal::read_path(keyring, &paths.ca_key, MAX_PEM_BYTES)?.ok_or_else(|| {
        ConnectorError::Internal(format!(
            "{} is missing; run init without --renew-tls to create a new CA",
            paths.ca_key.display()
        ))
    })?;
    let key_pem =
        std::str::from_utf8(&key_pem.plaintext).map_err(|e| tls_err("ca.key is not text", e))?;
    let ca_key = KeyPair::from_pem(key_pem).map_err(|e| tls_err("ca.key is invalid", e))?;
    let issuer = Issuer::new(ca_params(), &ca_key);
    let (server_pem, server_key_pem) = issue_leaf(&issuer, sans, node_name)?;
    write_leaf(paths, &server_pem, &server_key_pem, keyring)
}

fn first_cert_der(pem: &[u8]) -> Result<Vec<u8>> {
    let cert = CertificateDer::pem_slice_iter(pem)
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

// Creating TLS material is part of init, which also creates the node key if the node has none.
pub fn ensure(cfg: &ConnectorConfig) -> Result<TlsOutcome> {
    let paths = TlsPaths::new(&cfg.tls_dir);
    let keyring = Keyring::load(cfg, OpenMode::Migrating)?;
    let have_leaf = paths.server_pem.is_file() && paths.server_key.is_file();
    let can_reissue = paths.ca_pem.is_file() && paths.ca_key.is_file();
    let generated = if have_leaf {
        false
    } else if can_reissue {
        renew_leaf(&paths, &cfg.tls_sans, &cfg.node_name, keyring.as_ref())?;
        true
    } else {
        write_material(
            &paths,
            &generate(&cfg.tls_sans, &cfg.node_name)?,
            keyring.as_ref(),
        )?;
        true
    };
    outcome(&paths, generated)
}

// Runs from the command line, possibly while the server is up: it uses the key if there is one and never creates it.
pub fn renew(cfg: &ConnectorConfig) -> Result<TlsOutcome> {
    let paths = TlsPaths::new(&cfg.tls_dir);
    let keyring = Keyring::load(cfg, OpenMode::ReadOnly)?;
    renew_leaf(&paths, &cfg.tls_sans, &cfg.node_name, keyring.as_ref())?;
    outcome(&paths, true)
}

// The node key is found the way the other loaders find it: from the environment, then the data directory next to `dir`.
pub fn load_acceptor(dir: &Path) -> Result<TlsAcceptor> {
    let data_dir = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let keyring = Keyring::discover(data_dir, OpenMode::ReadOnly)?;
    load_acceptor_with(dir, keyring.as_ref())
}

pub fn load_acceptor_with(dir: &Path, keyring: Option<&Keyring>) -> Result<TlsAcceptor> {
    install_provider();
    let paths = TlsPaths::new(dir);
    let missing = || {
        ConnectorError::Internal(format!(
            "TLS certificate or key not found in {}; run `cite-connector init`",
            dir.display()
        ))
    };
    let cert_pem = read_limited(&paths.server_pem, MAX_PEM_BYTES).map_err(|_| missing())?;
    let key = seal::read_path(keyring, &paths.server_key, MAX_PEM_BYTES)?.ok_or_else(missing)?;
    let key_pem = key.plaintext;
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| tls_err("server.pem is invalid", e))?;
    if certs.is_empty() {
        return Err(ConnectorError::Internal(
            "server.pem has no certificate".into(),
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| tls_err("server.key is invalid or has no private key", e))?;
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
    for cert in CertificateDer::pem_slice_iter(ca_pem) {
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
    fn leaf_lifetime_stays_within_the_825_day_cap_apple_clients_enforce() {
        let m = generate(&sans(), "node-a").expect("generate");
        let (_, pem) = x509_parser::pem::parse_x509_pem(m.server_pem.as_bytes()).expect("pem");
        let cert = pem.parse_x509().expect("x509");
        let v = cert.validity();
        let days = (v.not_after.timestamp() - v.not_before.timestamp()) / 86_400;
        assert!(days <= 825, "leaf lifetime is {days} days");
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
        write_material(&paths, &m, None).expect("write");
        let acceptor = load_acceptor_with(dir.path(), None).expect("acceptor");
        assert!(handshake(acceptor.clone(), &m.ca_pem, "localhost").await);
        assert!(handshake(acceptor.clone(), &m.ca_pem, "connector.example.com").await);
        assert!(!handshake(acceptor, &m.ca_pem, "evil.example").await);
    }

    #[tokio::test]
    async fn an_unrelated_ca_is_not_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let m = generate(&sans(), "n1").expect("generate");
        write_material(&TlsPaths::new(dir.path()), &m, None).expect("write");
        let other = generate(&sans(), "n2").expect("other");
        let acceptor = load_acceptor_with(dir.path(), None).expect("acceptor");
        assert!(!handshake(acceptor, &other.ca_pem, "localhost").await);
    }

    #[tokio::test]
    async fn renewed_leaf_still_validates_against_the_original_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        let m = generate(&sans(), "n1").expect("generate");
        let paths = TlsPaths::new(dir.path());
        write_material(&paths, &m, None).expect("write");
        renew_leaf(&paths, &sans(), "n1", None).expect("renew");
        let renewed = std::fs::read_to_string(&paths.server_pem).expect("read");
        assert_ne!(renewed, m.server_pem);
        assert_eq!(
            std::fs::read_to_string(&paths.ca_pem).expect("ca"),
            m.ca_pem
        );
        let acceptor = load_acceptor_with(dir.path(), None).expect("acceptor");
        assert!(handshake(acceptor, &m.ca_pem, "localhost").await);
    }

    #[test]
    fn renew_without_ca_key_explains_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err =
            renew_leaf(&TlsPaths::new(dir.path()), &sans(), "n1", None).expect_err("must fail");
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
        let err = load_acceptor_with(dir.path(), None)
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("init"));
    }

    fn sealed_kid(path: &Path) -> Option<[u8; 8]> {
        seal::envelope_kid(&std::fs::read(path).expect("read"))
    }

    fn tls_cfg() -> (tempfile::TempDir, ConnectorConfig) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        std::fs::create_dir_all(&cfg.tls_dir).expect("mkdir");
        (dir, cfg)
    }

    #[tokio::test]
    async fn init_seals_the_private_keys_and_the_server_still_loads_and_renews_them() {
        let (_dir, cfg) = tls_cfg();
        let first = ensure(&cfg).expect("ensure");
        let paths = TlsPaths::new(&cfg.tls_dir);
        let ring = Keyring::load(&cfg, OpenMode::ReadOnly)
            .expect("load")
            .expect("init created the key");
        for key in [&paths.ca_key, &paths.server_key] {
            assert_eq!(sealed_kid(key), Some(ring.kid()), "{}", key.display());
            let text = std::fs::read_to_string(key).expect("read");
            assert!(!text.contains("PRIVATE KEY"), "{}", key.display());
        }
        for cert in [&paths.ca_pem, &paths.server_pem] {
            let text = std::fs::read_to_string(cert).expect("read");
            assert!(text.starts_with("-----BEGIN CERTIFICATE-----"));
        }
        let ca_pem = std::fs::read_to_string(&paths.ca_pem).expect("ca");
        let acceptor = load_acceptor(&cfg.tls_dir).expect("the server finds the key by itself");
        assert!(handshake(acceptor, &ca_pem, "localhost").await);

        let renewed = renew(&cfg).expect("renew with the sealed ca key");
        assert_eq!(renewed.fingerprint, first.fingerprint);
        assert_eq!(
            sealed_kid(&paths.server_key),
            Some(ring.kid()),
            "renewal seals the new key"
        );
        let acceptor = load_acceptor(&cfg.tls_dir).expect("acceptor after renewal");
        assert!(handshake(acceptor, &ca_pem, "localhost").await);
    }

    #[test]
    fn a_sealed_key_is_refused_without_a_keyring_and_never_read_as_pem() {
        let (_dir, cfg) = tls_cfg();
        ensure(&cfg).expect("ensure");
        let err = load_acceptor_with(&cfg.tls_dir, None)
            .err()
            .expect("sealed")
            .to_string();
        assert!(err.contains("no secrets key"), "{err}");
        let renew_err = renew_leaf(&TlsPaths::new(&cfg.tls_dir), &sans(), "n1", None)
            .expect_err("sealed ca key");
        assert!(
            renew_err.to_string().contains("no secrets key"),
            "{renew_err}"
        );
    }

    #[test]
    fn the_two_sealed_keys_cannot_be_swapped() {
        let (_dir, cfg) = tls_cfg();
        ensure(&cfg).expect("ensure");
        let paths = TlsPaths::new(&cfg.tls_dir);
        let server_key = std::fs::read(&paths.server_key).expect("read");
        std::fs::write(&paths.ca_key, server_key).expect("swap");
        let err = renew(&cfg).err().expect("must refuse").to_string();
        assert!(err.contains("decrypted"), "{err}");
    }

    #[test]
    fn plaintext_keys_from_an_earlier_release_are_sealed_once_with_a_pre_seal_copy() {
        let (_dir, cfg) = tls_cfg();
        let paths = TlsPaths::new(&cfg.tls_dir);
        let material = generate(&sans(), "n1").expect("generate");
        write_material(&paths, &material, None).expect("write plain");
        let ring = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key created");

        let sealed = migrate_keys(&cfg.tls_dir, &ring).expect("migrate");
        assert_eq!(sealed, ["tls/ca.key", "tls/server.key"]);
        for (file, plain) in [
            ("ca.key", &material.ca_key_pem),
            ("server.key", &material.server_key_pem),
        ] {
            let path = cfg.tls_dir.join(file);
            assert_eq!(sealed_kid(&path), Some(ring.kid()));
            let copy = cfg.tls_dir.join(format!("{file}.pre-seal"));
            assert_eq!(std::fs::read_to_string(&copy).expect("copy"), *plain);
            let mode = std::fs::metadata(&copy).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(load_acceptor_with(&cfg.tls_dir, Some(&ring)).is_ok());

        assert!(migrate_keys(&cfg.tls_dir, &ring).expect("again").is_empty());
        for file in ["ca.key.pre-seal", "server.key.pre-seal"] {
            assert!(
                !cfg.tls_dir.join(file).exists(),
                "{file} goes at the next start"
            );
        }
        let read_only = Keyring::from_keys(
            crate::seal::NodeKey::from_bytes(&[3; 32]),
            crate::seal::KeySource::Env,
            Vec::new(),
            OpenMode::ReadOnly,
        );
        let other = tempfile::tempdir().expect("tempdir");
        let plain_paths = TlsPaths::new(other.path());
        write_material(&plain_paths, &material, None).expect("write plain");
        assert!(
            migrate_keys(other.path(), &read_only)
                .expect("noop")
                .is_empty()
        );
        assert_eq!(
            sealed_kid(&plain_paths.ca_key),
            None,
            "a read-only keyring does not rewrite"
        );
    }
}
