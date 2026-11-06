use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use cite_core::atomic::{ensure_dir, write_atomic_in};
use cite_core::confined::{FileName, TrustedDir};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::sign::CertifiedKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex, MutexGuard};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};
use x509_parser::public_key::PublicKey;
use zeroize::Zeroizing;

use crate::{ConnectorError, Result};

pub const MAX_BODY_BYTES: usize = 128 * 1024;
pub const MAX_CERTS: usize = 64;
pub const MAX_NAME: usize = 64;
const MAX_CHAIN: usize = 10;
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MIN_RSA_BITS: usize = 2048;
const MAX_FUTURE_SECS: i64 = 24 * 3600;
const DAY_SECS: i64 = 86_400;
const ID_LEN: usize = 26;
const FILE_SUFFIX: &str = ".pem";
const TEMP_MARK: &str = ".pem.tmp.";
const CERT_TAG: &str = "CERTIFICATE";
const FILE_MAGIC: &str = "# cite certificate v1";
const NAME_LINE: &str = "# name: ";
const CREATED_LINE: &str = "# created_at: ";
const DIR_MODE: u32 = 0o750;
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";

fn bad(msg: impl Into<String>) -> ConnectorError {
    ConnectorError::BadRequest(msg.into())
}

fn internal(what: &str, err: impl fmt::Display) -> ConnectorError {
    ConnectorError::Internal(format!("{what}: {err}"))
}

// A PEM label comes from the client, so it is cut down to plain characters before it is echoed.
fn label(tag: &str) -> String {
    tag.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(40)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn rfc3339(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

pub fn is_cert_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

fn new_id() -> String {
    ulid::Ulid::generate().to_string()
}

fn file_name(id: &str) -> Result<FileName> {
    if !is_cert_id(id) {
        return Err(ConnectorError::NotFound("certificate not found".into()));
    }
    FileName::new(format!("{id}{FILE_SUFFIX}")).map_err(|e| internal("certificate file name", e))
}

pub fn validate_name(name: &str) -> Result<()> {
    let plain = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'));
    // five dashes would let a name pose as a PEM boundary inside the file's comment header
    let ok = name.len() <= MAX_NAME
        && plain
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && !name.ends_with(' ')
        && !name.contains("-----");
    if ok {
        Ok(())
    } else {
        Err(bad(format!(
            "name must be 1 to {MAX_NAME} characters from letters, digits, space, '.', '_' and '-', start with a letter or digit, not end with a space and not contain five dashes in a row"
        )))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub sans: Vec<String>,
    pub issuer: String,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: String,
    pub key_type: String,
    pub rsa_bits: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Api,
    Manual,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Api => "api",
            Source::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Stored {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub info: CertInfo,
    pub source: Source,
    pub warning: Option<String>,
}

// A file the connector owns but cannot read: it still counts, and still loads in HAProxy, so it is listed and can be deleted or replaced.
fn unreadable(id: &str) -> Stored {
    Stored {
        id: id.to_string(),
        name: id.to_string(),
        created_at: String::new(),
        info: CertInfo {
            key_type: "unknown".into(),
            ..CertInfo::default()
        },
        source: Source::Api,
        warning: Some("the certificate file cannot be read; replace or delete it".into()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Cert {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub sans: Vec<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub fingerprint_sha256: String,
    pub key_type: String,
    pub created_at: String,
    pub covers: Vec<String>,
    pub uncovered_hosts: Vec<String>,
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl Cert {
    // `hosts` are the configured site hosts; the split says which of them this certificate does and does not serve.
    pub fn new(stored: &Stored, hosts: &[String], now: i64) -> Cert {
        let info = &stored.info;
        let (covers, uncovered_hosts): (Vec<String>, Vec<String>) = hosts
            .iter()
            .cloned()
            .partition(|host| info.sans.iter().any(|san| name_matches(san, host)));
        let readable = stored.warning.is_none();
        Cert {
            id: stored.id.clone(),
            name: stored.name.clone(),
            subject: info.subject.clone(),
            sans: info.sans.clone(),
            issuer: info.issuer.clone(),
            not_before: if readable {
                rfc3339(info.not_before)
            } else {
                String::new()
            },
            not_after: if readable {
                rfc3339(info.not_after)
            } else {
                String::new()
            },
            days_left: if readable {
                (info.not_after - now).div_euclid(DAY_SECS)
            } else {
                0
            },
            fingerprint_sha256: info.fingerprint.clone(),
            key_type: info.key_type.clone(),
            created_at: stored.created_at.clone(),
            covers,
            uncovered_hosts,
            source: stored.source.as_str(),
            warning: stored.warning.clone(),
        }
    }
}

// Exact match, or a single leftmost wildcard label that stands for exactly one label (RFC 6125).
pub fn name_matches(san: &str, host: &str) -> bool {
    let san = san.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if san == host {
        return true;
    }
    if let (Ok(a), Ok(b)) = (san.parse::<IpAddr>(), host.parse::<IpAddr>()) {
        return a == b;
    }
    let Some(suffix) = san.strip_prefix("*.") else {
        return false;
    };
    // a wildcard directly under a top-level label would cover a whole registry
    if !suffix.contains('.') {
        return false;
    }
    match host.split_once('.') {
        Some((first, rest)) => !first.is_empty() && first != "*" && rest == suffix,
        None => false,
    }
}

pub fn uncovered_hosts(certs: &[Stored], hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .filter(|host| {
            !certs
                .iter()
                .any(|c| c.info.sans.iter().any(|san| name_matches(san, host)))
        })
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Pkcs8,
    Sec1,
    Pkcs1,
}

impl KeyKind {
    fn tag(self) -> &'static str {
        match self {
            KeyKind::Pkcs8 => "PRIVATE KEY",
            KeyKind::Sec1 => "EC PRIVATE KEY",
            KeyKind::Pkcs1 => "RSA PRIVATE KEY",
        }
    }
}

struct KeyMaterial {
    kind: KeyKind,
    der: Zeroizing<Vec<u8>>,
}

// A validated upload; the key stays in wiped memory and is never printed.
pub struct Prepared {
    pub info: CertInfo,
    chain: Vec<Vec<u8>>,
    key: KeyMaterial,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("fingerprint", &self.info.fingerprint)
            .field("chain", &self.chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

// Replaces a PEM block's bytes with zeros before the block is dropped.
fn wipe(blocks: Vec<pem::Pem>) {
    for block in blocks {
        drop(Zeroizing::new(block.into_contents()));
    }
}

fn has_key_block(text: &str) -> bool {
    text.lines()
        .any(|l| l.trim_start().starts_with("-----BEGIN") && l.contains("PRIVATE KEY"))
}

// A stray blank line inside the base64 (a copy-paste artefact) would otherwise end the block early.
fn squeeze_blank_lines(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for line in text.lines().map(str::trim_end).filter(|l| !l.is_empty()) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn parse_chain(text: &str) -> Result<Vec<Vec<u8>>> {
    if has_key_block(text) {
        return Err(bad(
            "the certificate field contains a private key; send the key only in private_key",
        ));
    }
    let blocks =
        pem::parse_many(text).map_err(|e| bad(format!("certificate is not valid PEM: {e}")))?;
    if blocks.is_empty() {
        return Err(bad(
            "certificate must contain at least one CERTIFICATE PEM block",
        ));
    }
    if blocks.len() > MAX_CHAIN {
        wipe(blocks);
        return Err(bad(format!(
            "certificate may hold at most {MAX_CHAIN} CERTIFICATE blocks (leaf first)"
        )));
    }
    let foreign = blocks
        .iter()
        .find(|b| b.tag() != CERT_TAG)
        .map(|b| b.tag().to_string());
    if let Some(tag) = foreign {
        wipe(blocks);
        if tag.ends_with("PRIVATE KEY") {
            return Err(bad(
                "the certificate field contains a private key; send the key only in private_key",
            ));
        }
        return Err(bad(format!(
            "unsupported PEM block {:?} in certificate; only CERTIFICATE blocks are accepted",
            label(&tag)
        )));
    }
    Ok(blocks.into_iter().map(pem::Pem::into_contents).collect())
}

fn looks_encrypted(text: &str) -> bool {
    text.lines().map(str::trim).any(|line| {
        line.starts_with("-----BEGIN ENCRYPTED")
            || (line.starts_with("Proc-Type:") && line.contains("ENCRYPTED"))
    })
}

fn parse_key(text: &str) -> Result<KeyMaterial> {
    if looks_encrypted(text) {
        return Err(bad(
            "the private key is encrypted; decrypt it first (for example: openssl pkey -in key.pem -out key-plain.pem)",
        ));
    }
    // the PEM parser quotes the offending line in its errors, and for a key that line is key material
    let cleaned = squeeze_blank_lines(text);
    let mut blocks =
        pem::parse_many(cleaned.as_str()).map_err(|_| bad("private_key is not valid PEM"))?;
    if blocks.is_empty() {
        return Err(bad("private_key must contain a PRIVATE KEY PEM block"));
    }
    if blocks.len() > 1 {
        wipe(blocks);
        return Err(bad("private_key must contain exactly one PEM block"));
    }
    let block = blocks.remove(0);
    let kind = match block.tag() {
        "PRIVATE KEY" => KeyKind::Pkcs8,
        "EC PRIVATE KEY" => KeyKind::Sec1,
        "RSA PRIVATE KEY" => KeyKind::Pkcs1,
        CERT_TAG => {
            return Err(bad(
                "private_key contains a CERTIFICATE block; send the certificate in certificate",
            ));
        }
        other => {
            let shown = label(other);
            wipe(vec![block]);
            return Err(bad(format!(
                "unsupported PEM block {shown:?} in private_key; use PRIVATE KEY, EC PRIVATE KEY or RSA PRIVATE KEY"
            )));
        }
    };
    Ok(KeyMaterial {
        kind,
        der: Zeroizing::new(block.into_contents()),
    })
}

fn ip_from_bytes(raw: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(raw) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(raw).ok().map(IpAddr::from)
}

fn modulus_bits(modulus: &[u8]) -> usize {
    let start = modulus
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(modulus.len());
    let trimmed = &modulus[start..];
    match trimmed.first() {
        Some(first) => (trimmed.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
        None => 0,
    }
}

fn classify_key(cert: &X509Certificate<'_>) -> Result<(String, Option<usize>)> {
    let spki = cert.public_key();
    let oid = spki.algorithm.algorithm.to_id_string();
    match oid.as_str() {
        OID_RSA => match spki.parsed() {
            Ok(PublicKey::RSA(rsa)) => {
                let bits = modulus_bits(rsa.modulus);
                Ok((format!("rsa-{bits}"), Some(bits)))
            }
            _ => Err(bad("the RSA public key in the certificate cannot be read")),
        },
        OID_EC => {
            let name = match spki.subject_public_key.data.len() {
                65 => "ecdsa-p256",
                97 => "ecdsa-p384",
                133 => "ecdsa-p521",
                _ => "ecdsa",
            };
            Ok((name.to_string(), None))
        }
        OID_ED25519 => Ok(("ed25519".to_string(), None)),
        OID_ED448 => Ok(("ed448".to_string(), None)),
        other => Ok((format!("oid:{other}"), None)),
    }
}

fn describe(cert: &X509Certificate<'_>, der: &[u8]) -> Result<CertInfo> {
    let mut sans: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                let text = match name {
                    GeneralName::DNSName(dns) => Some(dns.to_ascii_lowercase()),
                    GeneralName::IPAddress(raw) => ip_from_bytes(raw).map(|ip| ip.to_string()),
                    _ => None,
                };
                if let Some(text) = text
                    && !sans.contains(&text)
                {
                    sans.push(text);
                }
            }
        }
    }
    let (key_type, rsa_bits) = classify_key(cert)?;
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        sans,
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        fingerprint: hex(Sha256::digest(der).as_slice()),
        key_type,
        rsa_bits,
    })
}

fn inspect(chain: &[Vec<u8>]) -> Result<CertInfo> {
    let mut leaf = None;
    for (index, der) in chain.iter().enumerate() {
        let number = index + 1;
        let (rest, cert) = X509Certificate::from_der(der).map_err(|_| {
            bad(format!(
                "certificate {number} is not a valid X.509 certificate"
            ))
        })?;
        if !rest.is_empty() {
            return Err(bad(format!(
                "certificate {number} has trailing data after the X.509 structure"
            )));
        }
        if index == 0 {
            leaf = Some(describe(&cert, der)?);
        }
    }
    leaf.ok_or_else(|| bad("certificate must contain at least one CERTIFICATE PEM block"))
}

fn check_pair(chain: &[Vec<u8>], key: &KeyMaterial) -> Result<()> {
    // borrowed, so no unwiped copy of the key is made here
    let bytes: &[u8] = &key.der;
    let der = match key.kind {
        KeyKind::Pkcs8 => PrivateKeyDer::from(PrivatePkcs8KeyDer::from(bytes)),
        KeyKind::Sec1 => PrivateKeyDer::from(PrivateSec1KeyDer::from(bytes)),
        KeyKind::Pkcs1 => PrivateKeyDer::from(PrivatePkcs1KeyDer::from(bytes)),
    };
    let signing = rustls::crypto::ring::sign::any_supported_type(&der).map_err(|_| {
        bad("the private key cannot be read or is not supported; use RSA, ECDSA P-256 or P-384, or Ed25519")
    })?;
    let certs: Vec<CertificateDer<'static>> = chain
        .iter()
        .map(|d| CertificateDer::from(d.clone()))
        .collect();
    match CertifiedKey::new(certs, signing).keys_match() {
        Ok(()) => Ok(()),
        Err(rustls::Error::InconsistentKeys(_)) => {
            Err(bad("the private key does not match the certificate"))
        }
        Err(e) => Err(bad(format!(
            "the certificate and private key could not be checked together: {e}"
        ))),
    }
}

// `now` is passed in so the time rules are testable without a clock.
pub fn validate_upload(certificate: &str, private_key: &str, now: i64) -> Result<Prepared> {
    let chain = parse_chain(certificate)?;
    let key = parse_key(private_key)?;
    let info = inspect(&chain)?;
    if info.not_after <= now {
        return Err(bad(format!(
            "the certificate expired on {}",
            rfc3339(info.not_after)
        )));
    }
    if info.not_before > now + MAX_FUTURE_SECS {
        return Err(bad(format!(
            "the certificate is not valid until {}",
            rfc3339(info.not_before)
        )));
    }
    if let Some(bits) = info.rsa_bits
        && bits < MIN_RSA_BITS
    {
        return Err(bad(format!(
            "RSA keys must be at least {MIN_RSA_BITS} bits; this one has {bits}"
        )));
    }
    check_pair(&chain, &key)?;
    Ok(Prepared { info, chain, key })
}

fn encode_block(tag: &str, der: &[u8]) -> Zeroizing<String> {
    let block = pem::Pem::new(tag, der.to_vec());
    let encoded = Zeroizing::new(pem::encode(&block));
    drop(Zeroizing::new(block.into_contents()));
    Zeroizing::new(encoded.replace("\r\n", "\n"))
}

impl Prepared {
    // HAProxy reads certificate and key from one file, chain first; the comment lines carry our metadata.
    fn file_bytes(&self, name: &str, created_at: &str) -> Zeroizing<Vec<u8>> {
        let head = format!("{FILE_MAGIC}\n{NAME_LINE}{name}\n{CREATED_LINE}{created_at}\n");
        let chain: String = self
            .chain
            .iter()
            .map(|der| encode_block(CERT_TAG, der).to_string())
            .collect();
        let key = encode_block(self.key.kind.tag(), &self.key.der);
        let mut out = Zeroizing::new(Vec::with_capacity(head.len() + chain.len() + key.len()));
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(chain.as_bytes());
        out.extend_from_slice(key.as_bytes());
        out
    }
}

// Byte range of the certificate blocks: from the first line that starts a PEM block to the first private key block, which is never decoded here.
fn chain_range(text: &str) -> (usize, usize) {
    let (mut start, mut end, mut at) = (None, text.len(), 0);
    for line in text.split_inclusive('\n') {
        if line.starts_with("-----BEGIN") {
            if line.contains("PRIVATE KEY") {
                start.get_or_insert(at);
                end = at;
                break;
            }
            start.get_or_insert(at);
        }
        at += line.len();
    }
    (start.unwrap_or(text.len()), end)
}

struct FileView {
    name: Option<String>,
    created_at: Option<String>,
    info: CertInfo,
}

fn parse_file(bytes: &[u8]) -> Result<FileView> {
    let text = std::str::from_utf8(bytes).map_err(|_| internal("certificate file", "not text"))?;
    let (start, end) = chain_range(text);
    let (mut name, mut created_at) = (None, None);
    for line in text[..start].lines() {
        if let Some(value) = line.strip_prefix(NAME_LINE) {
            name = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix(CREATED_LINE) {
            created_at = Some(value.trim().to_string());
        }
    }
    let blocks = pem::parse_many(&text[start..end]).map_err(|e| internal("certificate file", e))?;
    let chain: Vec<Vec<u8>> = blocks
        .into_iter()
        .filter(|b| b.tag() == CERT_TAG)
        .map(pem::Pem::into_contents)
        .collect();
    let info = inspect(&chain).map_err(|e| internal("certificate file", e))?;
    Ok(FileView {
        name,
        created_at,
        info,
    })
}

fn parse_stored(id: &str, bytes: &[u8]) -> Result<Stored> {
    let view = parse_file(bytes)?;
    Ok(Stored {
        id: id.to_string(),
        name: view
            .name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| id.to_string()),
        created_at: view
            .created_at
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| rfc3339(view.info.not_before)),
        info: view.info,
        source: Source::Api,
        warning: None,
    })
}

// Files put into the directory by hand are shown read-only; their id can never be mistaken for one of ours.
fn parse_manual(name: &str, bytes: &[u8]) -> Result<Stored> {
    let view = parse_file(bytes)?;
    Ok(Stored {
        id: format!("file:{name}"),
        name: name.to_string(),
        created_at: rfc3339(view.info.not_before),
        info: view.info,
        source: Source::Manual,
        warning: None,
    })
}

// Files HAProxy skips when it loads a directory: hidden files and the sidecars next to a certificate.
fn is_loaded_by_haproxy(name: &str) -> bool {
    !name.starts_with('.')
        && ![".issuer", ".ocsp", ".sctl", ".key"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

// A directory entry HAProxy can load: a regular file, or a symlink (certbot keeps `live/` this way) whose target is one.
struct LoadedEntry {
    name: String,
    symlink: bool,
}

fn loaded_entries(path: &Path) -> Vec<LoadedEntry> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    let mut out: Vec<LoadedEntry> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if !is_loaded_by_haproxy(&name) {
                return None;
            }
            let kind = e.file_type().ok()?;
            let symlink = kind.is_symlink();
            let usable = if symlink {
                std::fs::metadata(e.path()).is_ok_and(|m| m.is_file())
            } else {
                kind.is_file()
            };
            usable.then_some(LoadedEntry { name, symlink })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn loaded_names(path: &Path) -> Vec<String> {
    loaded_entries(path).into_iter().map(|e| e.name).collect()
}

// Metadata only: a renewal replaces the target or touches it, and the link itself never changes, so the digest has to follow it without reading it.
fn hash_stat(hasher: &mut Sha256, meta: &std::fs::Metadata) {
    use std::os::unix::fs::MetadataExt;
    hasher.update(meta.len().to_be_bytes());
    hasher.update(meta.mtime().to_be_bytes());
    hasher.update(meta.mtime_nsec().to_be_bytes());
    hasher.update(meta.dev().to_be_bytes());
    hasher.update(meta.ino().to_be_bytes());
}

fn is_own_file(name: &str) -> bool {
    name.strip_suffix(FILE_SUFFIX).is_some_and(is_cert_id)
}

fn list_ids(path: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(FILE_SUFFIX).map(str::to_string))
        .filter(|id| is_cert_id(id))
        .collect();
    ids.sort();
    ids
}

// A crash between create and rename can leave `.ID.pem.tmp.*` behind, and HAProxy loads every file in the directory.
fn is_temp_name(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.split_once(TEMP_MARK))
        .is_some_and(|(id, _)| is_cert_id(id))
}

fn sweep_temp(root: &TrustedDir, path: &Path) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(text) = name.to_str().filter(|t| is_temp_name(t)) else {
            continue;
        };
        if let Ok(file) = FileName::new(text) {
            let _ = root.unlink(&file);
        }
    }
}

// Creates the directory HAProxy loads and clears crash leftovers; safe to run on every start.
pub fn prepare(dir: &Path) -> Result<()> {
    ensure_dir(dir, DIR_MODE)
        .map_err(|e| internal("cannot prepare the certificate directory", e))?;
    let root =
        TrustedDir::open(dir).map_err(|e| internal("cannot open the certificate directory", e))?;
    sweep_temp(&root, dir);
    Ok(())
}

// What HAProxy would load from the directory right now, hand-placed files included; the digest changes whenever any of them does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveSet {
    pub count: usize,
    pub digest: String,
}

pub fn live_set(dir: &Path) -> LiveSet {
    let Ok(root) = TrustedDir::open(dir) else {
        return LiveSet::default();
    };
    let mut hasher = Sha256::new();
    let mut count = 0;
    for LoadedEntry { name, symlink } in loaded_entries(dir) {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        let path = dir.join(&name);
        // a key kept next to its certificate in a separate file is loaded with it; only its stat is hashed, the key is never read
        match std::fs::metadata(dir.join(format!("{name}.key"))) {
            Ok(meta) if meta.is_file() => {
                hasher.update([1u8]);
                hash_stat(&mut hasher, &meta);
            }
            _ => hasher.update([0u8]),
        }
        if symlink {
            // the content is never read through a link; its target's stat stands in for it
            match std::fs::metadata(&path) {
                Ok(meta) => hash_stat(&mut hasher, &meta),
                Err(_) => hasher.update([0xfeu8; 8]),
            }
            count += 1;
            continue;
        }
        let bytes = FileName::new(&name)
            .ok()
            .and_then(|file| root.read_limited(&file, MAX_FILE_BYTES).ok())
            .map(Zeroizing::new);
        match bytes {
            Some(bytes) => {
                hasher.update((bytes.len() as u64).to_be_bytes());
                hasher.update(&bytes[..]);
            }
            // too large to hash cheaply: its size and modification time still show a rewrite
            None => match std::fs::symlink_metadata(&path) {
                Ok(meta) => hash_stat(&mut hasher, &meta),
                Err(_) => hasher.update([0xffu8; 8]),
            },
        }
        count += 1;
    }
    let digest = if count == 0 {
        String::new()
    } else {
        hex(hasher.finalize().as_slice())
    };
    LiveSet { count, digest }
}

// Everything needed to put a certificate directory back the way it was.
pub struct Undo {
    id: String,
    previous: Option<Zeroizing<Vec<u8>>>,
}

impl Undo {
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for Undo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Undo")
            .field("id", &self.id)
            .field("previous", &self.previous.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

pub struct CertStore {
    dir: PathBuf,
    mode: u32,
    gate: Mutex<()>,
    // Test hook: the next write fails right after its rename, as a failed directory fsync would.
    #[cfg(test)]
    fail_after_rename: std::sync::atomic::AtomicBool,
}

impl CertStore {
    pub fn new(dir: PathBuf, mode: u32) -> Self {
        Self {
            dir,
            mode,
            gate: Mutex::new(()),
            #[cfg(test)]
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
        }
    }

    // Held for the whole of a mutation, so two uploads never interleave their files and reloads.
    pub async fn lock(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().await
    }

    #[cfg(test)]
    pub(crate) fn fail_next_write(&self) {
        self.fail_after_rename
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn dir_ready(&self) -> bool {
        self.dir.is_dir() && rustix::fs::access(&self.dir, rustix::fs::Access::WRITE_OK).is_ok()
    }

    fn open_existing(&self) -> Result<Option<TrustedDir>> {
        if !self.dir.is_dir() {
            return Ok(None);
        }
        TrustedDir::open(&self.dir)
            .map(Some)
            .map_err(|e| internal("cannot open the certificate directory", e))
    }

    fn open_for_write(&self) -> Result<TrustedDir> {
        prepare(&self.dir)?;
        TrustedDir::open(&self.dir)
            .map_err(|e| internal("cannot open the certificate directory", e))
    }

    fn read_raw(dir: &TrustedDir, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let name = file_name(id)?;
        match dir.read_limited(&name, MAX_FILE_BYTES) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(cite_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(internal("cannot read the certificate file", e)),
        }
    }

    pub fn list(&self) -> Result<Vec<Stored>> {
        let Some(dir) = self.open_existing()? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for id in list_ids(&self.dir) {
            let stored = Self::read_raw(&dir, &id)
                .and_then(|raw| raw.map(|bytes| parse_stored(&id, &bytes)).transpose());
            match stored {
                Ok(Some(item)) => out.push(item),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(%id, error = %e, "a certificate file cannot be read");
                    out.push(unreadable(&id));
                }
            }
        }
        for name in loaded_names(&self.dir) {
            if is_own_file(&name) {
                continue;
            }
            let parsed = FileName::new(&name)
                .map_err(|e| internal("certificate file name", e))
                .and_then(|file| {
                    dir.read_limited(&file, MAX_FILE_BYTES)
                        .map(Zeroizing::new)
                        .map_err(|e| internal("cannot read the certificate file", e))
                })
                .and_then(|bytes| parse_manual(&name, &bytes));
            match parsed {
                Ok(item) => out.push(item),
                Err(e) => {
                    tracing::warn!(file = %name, error = %e, "a hand-placed certificate file is not listed")
                }
            }
        }
        out.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Result<Option<Stored>> {
        if !is_cert_id(id) {
            return Ok(None);
        }
        let Some(dir) = self.open_existing()? else {
            return Ok(None);
        };
        match Self::read_raw(&dir, id)? {
            Some(bytes) => Ok(Some(
                parse_stored(id, &bytes).unwrap_or_else(|_| unreadable(id)),
            )),
            None => Ok(None),
        }
    }

    fn write_bytes(&self, dir: &TrustedDir, id: &str, bytes: &[u8]) -> Result<()> {
        let name = file_name(id)?;
        #[cfg(test)]
        {
            if self
                .fail_after_rename
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                let path = self.dir.join(name.as_os_str());
                return cite_core::atomic::write_atomic_failpoint(
                    &path,
                    bytes,
                    self.mode,
                    cite_core::atomic::AtomicPoint::AfterRename,
                )
                .map_err(|e| internal("cannot write the certificate file", e));
            }
        }
        write_atomic_in(dir, &name, bytes, self.mode)
            .map_err(|e| internal("cannot write the certificate file", e))
    }

    // A write can fail after its rename (the directory fsync); the new file is then live, so it is undone before the error is reported.
    fn write_or_undo(
        &self,
        dir: &TrustedDir,
        id: &str,
        bytes: &[u8],
        previous: Option<&[u8]>,
    ) -> Result<()> {
        let Err(err) = self.write_bytes(dir, id, bytes) else {
            return Ok(());
        };
        let undone = match previous {
            Some(old) => self.write_bytes(dir, id, old),
            None => file_name(id).and_then(|name| {
                dir.unlink(&name)
                    .or_else(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    })
                    .map_err(|e| internal("cannot remove the certificate file", e))
            }),
        };
        if let Err(e) = undone {
            tracing::error!(error = %e, "could not undo a failed certificate write");
        }
        Err(err)
    }

    pub fn create(
        &self,
        name: &str,
        prepared: &Prepared,
        created_at: &str,
    ) -> Result<(Stored, Undo)> {
        validate_name(name)?;
        let dir = self.open_for_write()?;
        // every file of ours counts toward the cap, readable or not
        if list_ids(&self.dir).len() >= MAX_CERTS {
            return Err(bad(format!(
                "at most {MAX_CERTS} certificates can be stored; delete one first"
            )));
        }
        check_duplicate(&self.list()?, &prepared.info.fingerprint, None)?;
        let id = new_id();
        self.write_or_undo(&dir, &id, &prepared.file_bytes(name, created_at), None)?;
        let stored = Stored {
            id: id.clone(),
            name: name.to_string(),
            created_at: created_at.to_string(),
            info: prepared.info.clone(),
            source: Source::Api,
            warning: None,
        };
        Ok((stored, Undo { id, previous: None }))
    }

    // `created_at` is used only when the file being replaced cannot be read and so has no creation time of its own.
    pub fn replace(
        &self,
        id: &str,
        name: Option<&str>,
        prepared: &Prepared,
        created_at: &str,
    ) -> Result<(Stored, Undo)> {
        if let Some(name) = name {
            validate_name(name)?;
        }
        let dir = self.open_for_write()?;
        let previous = Self::read_raw(&dir, id)?
            .ok_or_else(|| ConnectorError::NotFound("certificate not found".into()))?;
        check_duplicate(&self.list()?, &prepared.info.fingerprint, Some(id))?;
        let current = parse_stored(id, &previous).ok();
        let name = name
            .map(str::to_string)
            .or_else(|| current.as_ref().map(|c| c.name.clone()))
            .unwrap_or_else(|| id.to_string());
        let created_at = current.map_or_else(|| created_at.to_string(), |c| c.created_at);
        self.write_or_undo(
            &dir,
            id,
            &prepared.file_bytes(&name, &created_at),
            Some(&previous[..]),
        )?;
        let previous = Some(previous);
        let stored = Stored {
            id: id.to_string(),
            name,
            created_at,
            info: prepared.info.clone(),
            source: Source::Api,
            warning: None,
        };
        Ok((
            stored,
            Undo {
                id: id.to_string(),
                previous,
            },
        ))
    }

    pub fn delete(&self, id: &str) -> Result<(Stored, Undo)> {
        let not_found = || ConnectorError::NotFound("certificate not found".into());
        if !is_cert_id(id) || !self.dir.is_dir() {
            return Err(not_found());
        }
        let dir = self.open_for_write()?;
        let previous = Self::read_raw(&dir, id)?.ok_or_else(not_found)?;
        let stored = parse_stored(id, &previous).unwrap_or_else(|_| unreadable(id));
        dir.unlink(&file_name(id)?)
            .map_err(|e| internal("cannot remove the certificate file", e))?;
        let _ = dir.sync();
        Ok((
            stored,
            Undo {
                id: id.to_string(),
                previous: Some(previous),
            },
        ))
    }

    // Puts the file back as it was before the failed change: rewritten when it existed, removed when it was new.
    pub fn rollback(&self, undo: Undo) -> Result<()> {
        let dir = self.open_for_write()?;
        match undo.previous {
            Some(bytes) => self.write_bytes(&dir, &undo.id, &bytes),
            None => match dir.unlink(&file_name(&undo.id)?) {
                Ok(()) => {
                    let _ = dir.sync();
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(internal("cannot remove the certificate file", e)),
            },
        }
    }
}

fn check_duplicate(existing: &[Stored], fingerprint: &str, except: Option<&str>) -> Result<()> {
    match existing
        .iter()
        .find(|c| c.info.fingerprint == fingerprint && Some(c.id.as_str()) != except)
    {
        Some(other) => Err(ConnectorError::Conflict(format!(
            "this certificate is already stored as {:?} ({})",
            other.name, other.id
        ))),
        None => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P384_SHA384,
        PKCS_ED25519, SignatureAlgorithm,
    };
    use time::{Duration, OffsetDateTime};

    pub struct Issued {
        pub cert_pem: String,
        pub key_pem: String,
    }

    pub fn issue_with(
        sans: &[&str],
        algorithm: &'static SignatureAlgorithm,
        starts_in: Duration,
        lasts: Duration,
    ) -> Issued {
        let key = KeyPair::generate_for(algorithm).expect("key");
        let names: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut params = CertificateParams::new(names).expect("params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sans.first().copied().unwrap_or("test"));
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now + starts_in;
        params.not_after = now + starts_in + lasts;
        let cert = params.self_signed(&key).expect("certificate");
        Issued {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    pub fn issue(sans: &[&str]) -> Issued {
        issue_with(
            sans,
            &rcgen::PKCS_ECDSA_P256_SHA256,
            Duration::days(-1),
            Duration::days(90),
        )
    }

    pub fn issue_p384(sans: &[&str]) -> Issued {
        issue_with(
            sans,
            &PKCS_ECDSA_P384_SHA384,
            Duration::days(-1),
            Duration::days(90),
        )
    }

    pub fn issue_ed25519(sans: &[&str]) -> Issued {
        issue_with(sans, &PKCS_ED25519, Duration::days(-1), Duration::days(90))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{issue, issue_ed25519, issue_p384, issue_with};
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use time::Duration;

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    fn store(dir: &tempfile::TempDir) -> CertStore {
        CertStore::new(dir.path().join("certs"), 0o600)
    }

    fn prepared(sans: &[&str]) -> Prepared {
        let issued = issue(sans);
        validate_upload(&issued.cert_pem, &issued.key_pem, now()).expect("valid upload")
    }

    fn reject(cert: &str, key: &str) -> String {
        match validate_upload(cert, key, now()) {
            Err(ConnectorError::BadRequest(msg)) => msg,
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    #[test]
    fn a_good_upload_is_described() {
        let issued = issue(&["shop.example.com", "*.example.org", "10.1.2.3"]);
        let p = validate_upload(&issued.cert_pem, &issued.key_pem, now()).expect("upload");
        assert_eq!(
            p.info.sans,
            ["shop.example.com", "*.example.org", "10.1.2.3"]
        );
        assert_eq!(p.info.key_type, "ecdsa-p256");
        assert!(p.info.subject.contains("shop.example.com"));
        assert_eq!(p.info.fingerprint.len(), 64);
        assert!(p.info.not_after > now());
    }

    #[test]
    fn key_types_are_named() {
        let p384 = issue_p384(&["a.example.com"]);
        let p = validate_upload(&p384.cert_pem, &p384.key_pem, now()).expect("p384");
        assert_eq!(p.info.key_type, "ecdsa-p384");
        let ed = issue_ed25519(&["a.example.com"]);
        let p = validate_upload(&ed.cert_pem, &ed.key_pem, now()).expect("ed25519");
        assert_eq!(p.info.key_type, "ed25519");
    }

    #[test]
    fn rsa_modulus_sizes_are_measured_without_the_sign_byte() {
        let mut modulus = vec![0u8, 0xC0];
        modulus.extend(vec![0xAB; 255]);
        assert_eq!(modulus_bits(&modulus), 2048);
        assert_eq!(modulus_bits(&modulus[1..]), 2048);
        let mut small = vec![0x80];
        small.extend(vec![0x11; 127]);
        assert_eq!(modulus_bits(&small), 1024);
        assert_eq!(modulus_bits(&[0x01, 0x00]), 9);
        assert_eq!(modulus_bits(&[]), 0);
    }

    #[test]
    fn a_mismatched_key_is_refused() {
        let a = issue(&["a.example.com"]);
        let b = issue(&["a.example.com"]);
        assert!(reject(&a.cert_pem, &b.key_pem).contains("does not match"));
    }

    #[test]
    fn an_expired_or_far_future_certificate_is_refused() {
        let expired = issue_with(
            &["a.example.com"],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            Duration::days(-30),
            Duration::days(10),
        );
        assert!(reject(&expired.cert_pem, &expired.key_pem).contains("expired"));
        let future = issue_with(
            &["a.example.com"],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            Duration::days(3),
            Duration::days(30),
        );
        assert!(reject(&future.cert_pem, &future.key_pem).contains("not valid until"));
        let soon = issue_with(
            &["a.example.com"],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            Duration::hours(2),
            Duration::days(30),
        );
        assert!(validate_upload(&soon.cert_pem, &soon.key_pem, now()).is_ok());
    }

    #[test]
    fn an_encrypted_key_gets_a_clear_message() {
        let issued = issue(&["a.example.com"]);
        let pkcs8 =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(reject(&issued.cert_pem, pkcs8).contains("encrypted"));
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(reject(&issued.cert_pem, legacy).contains("encrypted"));
    }

    #[test]
    fn other_block_types_and_miscounts_are_refused() {
        let issued = issue(&["a.example.com"]);
        let crl = "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
        let with_crl = format!("{}{crl}", issued.cert_pem);
        assert!(reject(&with_crl, &issued.key_pem).contains("unsupported PEM block"));
        assert!(reject(&issued.cert_pem, crl).contains("unsupported PEM block"));
        let key_in_cert = format!("{}{}", issued.cert_pem, issued.key_pem);
        assert!(reject(&key_in_cert, &issued.key_pem).contains("private key"));
        assert!(reject(&issued.cert_pem, &issued.cert_pem).contains("CERTIFICATE block"));
        let two_keys = format!("{}{}", issued.key_pem, issued.key_pem);
        assert!(reject(&issued.cert_pem, &two_keys).contains("exactly one"));
        assert!(reject("", &issued.key_pem).contains("at least one"));
        assert!(reject(&issued.cert_pem, "").contains("PRIVATE KEY"));
        assert!(reject("not pem at all", &issued.key_pem).contains("certificate"));
        let eleven = issued.cert_pem.repeat(MAX_CHAIN + 1);
        assert!(reject(&eleven, &issued.key_pem).contains("at most"));
        let garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(reject(garbage, &issued.key_pem).contains("not a valid X.509"));
    }

    #[test]
    fn names_follow_the_rules() {
        let (longest, too_long) = ("x".repeat(MAX_NAME), "x".repeat(MAX_NAME + 1));
        for ok in ["a", "My Cert_1.2-b", longest.as_str()] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".hidden",
            " lead",
            "trail ",
            "a/b",
            "../x",
            "a\nb",
            "caf\u{e9}",
            "a;b",
            too_long.as_str(),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn wildcards_match_one_label_only() {
        assert!(name_matches("example.com", "EXAMPLE.com"));
        assert!(name_matches("*.example.com", "www.example.com"));
        assert!(!name_matches("*.example.com", "example.com"));
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        assert!(!name_matches("*.com", "example.com"));
        assert!(name_matches("*.example.com", "*.example.com"));
        assert!(!name_matches("www.example.com", "*.example.com"));
        assert!(name_matches("2001:db8::1", "2001:0db8:0:0:0:0:0:1"));
        assert!(!name_matches("10.0.0.1", "10.0.0.2"));
    }

    #[test]
    fn create_list_get_replace_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let one = prepared(&["one.example.com"]);
        let (stored, _) = store.create("first", &one, "2026-11-06T00:00:00Z").unwrap();
        assert!(is_cert_id(&stored.id));
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "first");
        assert_eq!(listed[0].created_at, "2026-11-06T00:00:00Z");
        assert_eq!(listed[0].info.sans, ["one.example.com"]);
        let file = dir.path().join("certs").join(format!("{}.pem", stored.id));
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(dir.path().join("certs"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o750);

        let two = prepared(&["two.example.com"]);
        let (replaced, _) = store
            .replace(&stored.id, Some("renamed"), &two, "t")
            .unwrap();
        assert_eq!(replaced.id, stored.id);
        assert_eq!(replaced.created_at, "2026-11-06T00:00:00Z");
        let got = store.get(&stored.id).unwrap().unwrap();
        assert_eq!(got.name, "renamed");
        assert_eq!(got.info.sans, ["two.example.com"]);
        let (kept, _) = store.replace(&stored.id, None, &two, "t").unwrap();
        assert_eq!(kept.name, "renamed");

        store.delete(&stored.id).unwrap();
        assert!(store.list().unwrap().is_empty());
        assert!(store.get(&stored.id).unwrap().is_none());
        assert!(matches!(
            store.delete(&stored.id),
            Err(ConnectorError::NotFound(_))
        ));
    }

    #[test]
    fn the_file_holds_chain_then_key_and_the_name_never_reaches_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let p = prepared(&["a.example.com"]);
        assert!(matches!(
            store.create("../../evil", &p, "now"),
            Err(ConnectorError::BadRequest(_))
        ));
        let certs = dir.path().join("certs");
        assert!(list_ids(&certs).is_empty());
        let (stored, _) = store.create("my cert", &p, "2026-11-06T00:00:00Z").unwrap();
        let names: Vec<String> = std::fs::read_dir(&certs)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, [format!("{}.pem", stored.id)]);
        let text = std::fs::read_to_string(certs.join(&names[0])).unwrap();
        assert!(text.starts_with(FILE_MAGIC));
        assert!(text.contains("# name: my cert\n"));
        let cert_at = text.find("-----BEGIN CERTIFICATE-----").unwrap();
        let key_at = text.find("-----BEGIN PRIVATE KEY-----").unwrap();
        assert!(cert_at < key_at);
        assert_eq!(text.matches("PRIVATE KEY-----").count(), 2);
        assert!(!text.contains('\r'));
    }

    #[test]
    fn duplicates_and_the_limit_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let issued = issue(&["a.example.com"]);
        let p = validate_upload(&issued.cert_pem, &issued.key_pem, now()).unwrap();
        let (first, _) = store.create("a", &p, "t").unwrap();
        let again = validate_upload(&issued.cert_pem, &issued.key_pem, now()).unwrap();
        assert!(matches!(
            store.create("b", &again, "t"),
            Err(ConnectorError::Conflict(_))
        ));
        assert!(store.replace(&first.id, None, &again, "t").is_ok());
        let other = prepared(&["b.example.com"]);
        let (second, _) = store.create("b", &other, "t").unwrap();
        assert!(matches!(
            store.replace(&second.id, None, &again, "t"),
            Err(ConnectorError::Conflict(_))
        ));
    }

    #[test]
    fn the_certificate_count_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let p = prepared(&["a.example.com"]);
        store.open_for_write().unwrap();
        for _ in 0..MAX_CERTS {
            store
                .create("c", &prepared(&["a.example.com"]), "t")
                .unwrap();
        }
        assert!(matches!(
            store.create("c", &p, "t"),
            Err(ConnectorError::BadRequest(_))
        ));
    }

    #[test]
    fn rollback_restores_the_previous_bytes_or_removes_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let one = prepared(&["one.example.com"]);
        let (stored, undo_new) = store.create("n", &one, "t").unwrap();
        let path = dir.path().join("certs").join(format!("{}.pem", stored.id));
        let before = std::fs::read(&path).unwrap();
        let two = prepared(&["two.example.com"]);
        let (_, undo_replace) = store.replace(&stored.id, None, &two, "t").unwrap();
        assert_ne!(std::fs::read(&path).unwrap(), before);
        store.rollback(undo_replace).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let (_, undo_delete) = store.delete(&stored.id).unwrap();
        assert!(!path.exists());
        store.rollback(undo_delete).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        store.rollback(undo_new).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn live_set_counts_every_file_haproxy_loads_and_tracks_changes() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let certs = dir.path().join("certs");
        assert_eq!(live_set(&certs), LiveSet::default());
        let (stored, _) = store
            .create("a", &prepared(&["a.example.com"]), "t")
            .unwrap();
        let first = live_set(&certs);
        assert_eq!(first.count, 1);
        assert_eq!(first.digest.len(), 64);
        for ignored in [
            ".hidden",
            "site.key",
            "site.ocsp",
            "site.issuer",
            "site.sctl",
        ] {
            std::fs::write(certs.join(ignored), "x").unwrap();
        }
        assert_eq!(live_set(&certs), first);
        std::fs::write(certs.join("hand.pem"), "x").unwrap();
        let with_manual = live_set(&certs);
        assert_eq!(with_manual.count, 2);
        assert_ne!(with_manual.digest, first.digest);
        std::fs::write(certs.join("hand.pem"), "y").unwrap();
        assert_ne!(live_set(&certs).digest, with_manual.digest);
        std::fs::remove_file(certs.join("hand.pem")).unwrap();
        store
            .replace(&stored.id, None, &prepared(&["b.example.com"]), "t")
            .unwrap();
        let second = live_set(&certs);
        assert_eq!(second.count, 1);
        assert_ne!(second.digest, first.digest);
        store.delete(&stored.id).unwrap();
        assert_eq!(live_set(&certs).count, 0);
    }

    #[test]
    fn a_changed_sidecar_key_changes_the_digest_but_is_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.open_for_write().unwrap();
        let certs = dir.path().join("certs");
        std::fs::write(certs.join("hand.pem"), "cert").unwrap();
        let without = live_set(&certs);
        std::fs::write(certs.join("hand.pem.key"), "k1").unwrap();
        let with = live_set(&certs);
        assert_eq!(with.count, 1);
        assert_ne!(with.digest, without.digest);
        std::fs::write(certs.join("hand.pem.key"), "key-two").unwrap();
        assert_ne!(live_set(&certs).digest, with.digest);
    }

    #[test]
    fn symlinked_certificates_follow_their_target_without_being_read() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.open_for_write().unwrap();
        let certs = dir.path().join("certs");
        let archive = dir.path().join("archive");
        std::fs::create_dir(&archive).unwrap();
        std::fs::write(archive.join("one.pem"), "one").unwrap();
        std::fs::write(archive.join("two.pem"), "two-longer").unwrap();
        symlink(archive.join("one.pem"), certs.join("site.pem")).unwrap();
        let first = live_set(&certs);
        assert_eq!(first.count, 1);

        std::fs::remove_file(certs.join("site.pem")).unwrap();
        symlink(archive.join("two.pem"), certs.join("site.pem")).unwrap();
        let retargeted = live_set(&certs);
        assert_ne!(retargeted.digest, first.digest);

        let target = std::fs::OpenOptions::new()
            .write(true)
            .open(archive.join("two.pem"))
            .unwrap();
        target
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
            .unwrap();
        let touched = live_set(&certs);
        assert_ne!(touched.digest, retargeted.digest);
        assert_eq!(touched.count, 1);

        symlink(dir.path().join("missing.pem"), certs.join("dangling.pem")).unwrap();
        symlink(&archive, certs.join("linked-dir.pem")).unwrap();
        std::fs::create_dir(certs.join("subdir.pem")).unwrap();
        assert_eq!(live_set(&certs), touched);
        assert!(
            store.list().unwrap().is_empty(),
            "a symlink is never read or listed"
        );
    }

    #[test]
    fn names_cannot_pose_as_pem_boundaries() {
        for bad in ["a-----BEGIN x", "-----BEGIN", "-lead", "a -----"] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
        assert!(validate_name("a-b--c").is_ok());
    }

    #[test]
    fn a_header_line_that_mentions_a_boundary_does_not_hide_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let (stored, _) = store
            .create("n", &prepared(&["a.example.com"]), "t")
            .unwrap();
        let path = dir.path().join("certs").join(format!("{}.pem", stored.id));
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("# name: n", "# name: x-----BEGIN y")).unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].warning.is_none());
        assert_eq!(listed[0].name, "x-----BEGIN y");
        assert!(store.get(&stored.id).unwrap().unwrap().warning.is_none());
    }

    #[test]
    fn an_unreadable_file_is_listed_deletable_replaceable_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let certs = dir.path().join("certs");
        store.open_for_write().unwrap();
        let broken = "B".repeat(26);
        std::fs::write(certs.join(format!("{broken}.pem")), "garbage").unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, broken);
        assert!(listed[0].warning.is_some());
        let json = serde_json::to_value(Cert::new(&listed[0], &[], now())).unwrap();
        assert!(json["warning"].is_string());
        assert_eq!(json["source"], "api");

        let (stored, _) = store
            .replace(
                &broken,
                Some("fixed"),
                &prepared(&["a.example.com"]),
                "2026-01-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(stored.name, "fixed");
        assert!(store.list().unwrap()[0].warning.is_none());

        std::fs::write(certs.join(format!("{broken}.pem")), "garbage").unwrap();
        store.delete(&broken).unwrap();
        assert!(list_ids(&certs).is_empty());

        std::fs::write(certs.join(format!("{broken}.pem")), "garbage").unwrap();
        for _ in 0..MAX_CERTS - 1 {
            store
                .create("c", &prepared(&["a.example.com"]), "t")
                .unwrap();
        }
        assert!(matches!(
            store.create("c", &prepared(&["a.example.com"]), "t"),
            Err(ConnectorError::BadRequest(_))
        ));
    }

    #[test]
    fn hand_placed_files_are_listed_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let certs = dir.path().join("certs");
        store.open_for_write().unwrap();
        let issued = issue(&["manual.example.com"]);
        std::fs::write(
            certs.join("manual.pem"),
            format!("{}{}", issued.cert_pem, issued.key_pem),
        )
        .unwrap();
        std::fs::write(certs.join("junk.pem"), "junk").unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "file:manual.pem");
        assert_eq!(listed[0].source, Source::Manual);
        assert_eq!(listed[0].info.sans, ["manual.example.com"]);
        assert!(store.get("file:manual.pem").unwrap().is_none());
        assert!(matches!(
            store.delete("file:manual.pem"),
            Err(ConnectorError::NotFound(_))
        ));
        assert_eq!(live_set(&certs).count, 2);
        let dup = validate_upload(&issued.cert_pem, &issued.key_pem, now()).unwrap();
        assert!(matches!(
            store.create("again", &dup, "t"),
            Err(ConnectorError::Conflict(_))
        ));
    }

    #[test]
    fn a_write_that_fails_after_its_rename_is_undone() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let certs = dir.path().join("certs");
        store.fail_after_rename.store(true, Ordering::SeqCst);
        assert!(
            store
                .create("n", &prepared(&["a.example.com"]), "t")
                .is_err()
        );
        assert!(list_ids(&certs).is_empty());
        assert_eq!(live_set(&certs), LiveSet::default());

        let (stored, _) = store
            .create("n", &prepared(&["a.example.com"]), "t")
            .unwrap();
        let path = certs.join(format!("{}.pem", stored.id));
        let before = std::fs::read(&path).unwrap();
        let digest = live_set(&certs);
        store.fail_after_rename.store(true, Ordering::SeqCst);
        assert!(
            store
                .replace(&stored.id, None, &prepared(&["b.example.com"]), "t")
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(live_set(&certs), digest);
    }

    #[test]
    fn key_errors_never_quote_the_key() {
        let issued = issue(&["a.example.com"]);
        let body: Vec<&str> = issued
            .key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let mut broken = issued
            .key_pem
            .replacen(body[0], &format!("{}!!", body[0]), 1);
        let mut messages = vec![reject(&issued.cert_pem, &broken)];
        broken = issued.key_pem.replacen(body[0], "?", 1);
        messages.push(reject(&issued.cert_pem, &broken));
        for message in messages {
            for line in &body {
                for window in line.as_bytes().windows(12) {
                    let window = std::str::from_utf8(window).unwrap();
                    assert!(!message.contains(window), "{message}");
                }
            }
        }
        let with_blank = issued.key_pem.replacen("\n-----END", "\n\n-----END", 1);
        assert!(validate_upload(&issued.cert_pem, &with_blank, now()).is_ok());
    }

    #[test]
    fn prepare_removes_crash_leftovers_only() {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs");
        std::fs::create_dir(&certs).unwrap();
        let id = "0".repeat(26);
        let leftover = certs.join(format!(".{id}.pem.tmp.12.1f"));
        let other = certs.join(".keep");
        std::fs::write(&leftover, "k").unwrap();
        std::fs::write(&other, "k").unwrap();
        prepare(&certs).unwrap();
        assert!(!leftover.exists());
        assert!(other.exists());
    }

    #[test]
    fn debug_output_never_shows_key_material() {
        let issued = issue(&["a.example.com"]);
        let p = validate_upload(&issued.cert_pem, &issued.key_pem, now()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let (_, undo) = store.create("n", &p, "t").unwrap();
        let body: String = issued
            .key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        for text in [format!("{p:?}"), format!("{undo:?}")] {
            assert!(!text.contains(&body[..20]), "{text}");
        }
    }
}
