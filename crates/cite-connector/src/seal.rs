//! Secrets at rest: a node key, a versioned file envelope, and the loaders' shared read, write and migrate helpers.
//!
//! Files are sealed with ChaCha20-Poly1305 under a 32-byte node key. The envelope names the key by id, so a
//! rotation can read old files while new writes use the new key, and the logical file name is bound as
//! associated data so one sealed file cannot be swapped for another.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cite_core::atomic::{ensure_dir, write_atomic_in};
use cite_core::confined::{FileName, TrustedDir};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::{ConnectorConfig, KeyInput, KeyInputSource, key_inputs_from_env};
use crate::{ConnectorError, Result};

pub const KEY_PREFIX: &str = "cite-key-v1:";
pub const MANAGED_KEY_FILE: &str = "secrets.key";
pub const MANAGED_PREVIOUS_FILE: &str = "secrets.key.previous";
pub const PRE_SEAL_SUFFIX: &str = ".pre-seal";
const KEY_LOCK_FILE: &str = "secrets.key.lock";
const NEW_KEY_FILE: &str = "secrets.key.new";
const ENVELOPE_ALG: &str = "chacha20poly1305";
const FILE_AAD_PREFIX: &str = "cite-seal-v1:";
const DEK_AAD_PREFIX: &str = "cite-backup-dek-v1:";
const KID_DOMAIN: &[u8] = b"cite-kid-v1";
const KEY_FILE_MAX_BYTES: u64 = 1024;
// Largest plaintext any sealed file may hold (secrets.json), used to bound the scan of candidate files.
const LARGEST_PLAINTEXT: u64 = 16 * 1024 * 1024;

/// What a keyring may do to files. `ReadOnly` (the command line) never generates a key and never rewrites
/// a file it merely read; `Migrating` (the server) creates the key on first start and re-seals old files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Migrating,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    Env,
    File(PathBuf),
    Managed(PathBuf),
}

impl KeySource {
    pub fn describe(&self) -> String {
        match self {
            KeySource::Env => "environment (CITE_SECRETS_KEY)".to_string(),
            KeySource::File(p) => format!("file {} (CITE_SECRETS_KEY_FILE)", p.display()),
            KeySource::Managed(p) => format!("managed file {}", p.display()),
        }
    }
}

fn internal(msg: impl Into<String>) -> ConnectorError {
    ConnectorError::Internal(msg.into())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| internal("the random source failed"))?;
    Ok(out)
}

fn cipher(key: &[u8; 32]) -> Result<LessSafeKey> {
    UnboundKey::new(&CHACHA20_POLY1305, key)
        .map(LessSafeKey::new)
        .map_err(|_| internal("cipher setup failed"))
}

/// Ciphertext with the 16-byte tag appended.
pub(crate) fn seal_with(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(plaintext.len() + 16);
    buf.extend_from_slice(plaintext);
    cipher(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| internal("encryption failed"))?;
    Ok(buf)
}

pub(crate) fn open_with(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plain_len = cipher(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| internal("decryption failed"))?
        .len();
    buf.truncate(plain_len);
    Ok(buf)
}

/// A 32-byte key and its id, the first 8 bytes of a domain-separated hash of the key.
#[derive(Clone)]
pub struct NodeKey {
    kid: [u8; 8],
    key: Zeroizing<[u8; 32]>,
}

impl NodeKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(KID_DOMAIN);
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut kid = [0u8; 8];
        kid.copy_from_slice(&digest[..8]);
        Self {
            kid,
            key: Zeroizing::new(*bytes),
        }
    }

    pub fn generate() -> Result<Self> {
        let raw = Zeroizing::new(random::<32>()?);
        Ok(Self::from_bytes(&raw))
    }

    /// `cite-key-v1:<base64url>`; surrounding whitespace is ignored. Errors never quote the input.
    pub fn parse(text: &str) -> Result<Self> {
        let bad = || {
            internal(format!(
                "the secrets key must look like {KEY_PREFIX}<43 characters of base64url>"
            ))
        };
        let rest = text.trim().strip_prefix(KEY_PREFIX).ok_or_else(bad)?;
        let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(rest).map_err(|_| bad())?);
        let bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(raw.as_slice().try_into().map_err(|_| bad())?);
        Ok(Self::from_bytes(&bytes))
    }

    pub fn text(&self) -> Zeroizing<String> {
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(self.key.as_slice()));
        Zeroizing::new(format!("{KEY_PREFIX}{}", encoded.as_str()))
    }

    pub fn kid(&self) -> [u8; 8] {
        self.kid
    }

    pub fn kid_hex(&self) -> String {
        hex(&self.kid)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeKey(kid {}, <redacted>)", self.kid_hex())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    cite_sealed: u64,
    alg: String,
    kid: String,
    nonce: String,
    ct: String,
}

struct Envelope {
    kid: [u8; 8],
    nonce: [u8; 12],
    ct: Vec<u8>,
}

enum Shape {
    Plain,
    Envelope(Envelope),
    // Shaped like an envelope but with fields that cannot be one: damage, not legacy plaintext.
    Malformed,
}

// An object with exactly the five envelope keys and `cite_sealed` equal to the number 1 is an envelope;
// anything else is legacy plaintext (a plaintext secrets map has only string values, so it never matches).
fn classify(bytes: &[u8]) -> Shape {
    let Ok(wire) = serde_json::from_slice::<Wire>(bytes) else {
        return Shape::Plain;
    };
    if wire.cite_sealed != 1 {
        return Shape::Plain;
    }
    let parsed = (|| {
        if wire.alg != ENVELOPE_ALG {
            return None;
        }
        let kid = unhex::<8>(&wire.kid)?;
        let nonce: [u8; 12] = URL_SAFE_NO_PAD.decode(&wire.nonce).ok()?.try_into().ok()?;
        let ct = URL_SAFE_NO_PAD.decode(&wire.ct).ok()?;
        (ct.len() >= 16).then_some(Envelope { kid, nonce, ct })
    })();
    match parsed {
        Some(env) => Shape::Envelope(env),
        None => Shape::Malformed,
    }
}

/// The key id an envelope names, or None when the bytes are not an envelope.
pub fn envelope_kid(bytes: &[u8]) -> Option<[u8; 8]> {
    match classify(bytes) {
        Shape::Envelope(env) => Some(env.kid),
        _ => None,
    }
}

pub struct Opened {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub legacy_plaintext: bool,
    /// The key the file was sealed under; None for legacy plaintext.
    pub kid: Option<[u8; 8]>,
}

/// The primary key that seals new data, plus older keys that may still open existing data.
#[derive(Clone)]
pub struct Keyring {
    primary: NodeKey,
    source: KeySource,
    older: Vec<NodeKey>,
    mode: OpenMode,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("kid", &self.primary.kid_hex())
            .field("older", &self.older_kids())
            .field("source", &self.source.describe())
            .finish()
    }
}

impl Keyring {
    pub fn from_keys(
        primary: NodeKey,
        source: KeySource,
        older: Vec<NodeKey>,
        mode: OpenMode,
    ) -> Self {
        let mut keyring = Self {
            primary,
            source,
            older: Vec::new(),
            mode,
        };
        for key in older {
            keyring.add_older(key);
        }
        keyring
    }

    fn add_older(&mut self, key: NodeKey) {
        let known = key.kid == self.primary.kid || self.older.iter().any(|k| k.kid == key.kid);
        if !known {
            self.older.push(key);
        }
    }

    /// Resolves the node key from the configuration: the environment, then a key file, then the managed
    /// file in the data directory. In `Migrating` mode a missing key is created, unless sealed files exist
    /// (then the key is lost, and nothing is regenerated). In `ReadOnly` mode a missing key is `None`
    /// and plaintext files are read as they are.
    pub fn load(cfg: &ConnectorConfig, mode: OpenMode) -> Result<Option<Keyring>> {
        resolve(
            &cfg.data_dir,
            cfg.secrets_key.as_ref(),
            cfg.secrets_key_previous.as_ref(),
            mode,
            mode == OpenMode::Migrating,
        )
    }

    /// For components that only know the data directory: reads the key settings from the process
    /// environment and never creates a key. None means no key exists, so files stay plaintext.
    pub fn discover(data_dir: &Path, mode: OpenMode) -> Result<Option<Keyring>> {
        let env: HashMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .filter(|(k, _)| k.starts_with("CITE_SECRETS_KEY"))
            .collect();
        let (primary, previous) = key_inputs_from_env(&env)?;
        resolve(data_dir, primary.as_ref(), previous.as_ref(), mode, false)
    }

    /// A keyring over a key file given on the command line, for recovery away from the node.
    pub fn from_key_file(path: &Path) -> Result<Keyring> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(KEY_FILE_MAX_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|e| internal(format!("cannot read the key file {}: {e}", path.display())))?;
        let text = Zeroizing::new(
            String::from_utf8(bytes).map_err(|_| internal("the key file is not text"))?,
        );
        let key = NodeKey::parse(&text)?;
        Ok(Keyring::from_keys(
            key,
            KeySource::File(path.to_path_buf()),
            Vec::new(),
            OpenMode::ReadOnly,
        ))
    }

    /// The same keyring plus keys that only older copies (for example in S3) still need.
    pub fn with_extra(&self, extra: Vec<NodeKey>) -> Keyring {
        let mut next = self.clone();
        for key in extra {
            next.add_older(key);
        }
        next
    }

    pub fn kid_hex(&self) -> String {
        self.primary.kid_hex()
    }

    pub fn kid(&self) -> [u8; 8] {
        self.primary.kid
    }

    pub fn source(&self) -> &KeySource {
        &self.source
    }

    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    pub fn has_older(&self) -> bool {
        !self.older.is_empty()
    }

    pub fn older_kids(&self) -> Vec<String> {
        self.older.iter().map(NodeKey::kid_hex).collect()
    }

    /// The primary key in its text form, for export. The caller decides where it may be shown.
    pub fn primary_text(&self) -> Zeroizing<String> {
        self.primary.text()
    }

    fn key_for(&self, kid: [u8; 8]) -> Option<&NodeKey> {
        std::iter::once(&self.primary)
            .chain(self.older.iter())
            .find(|k| k.kid == kid)
    }

    fn unknown_kid(&self, what: &str, kid: [u8; 8]) -> ConnectorError {
        let older = if self.older.is_empty() {
            "none".to_string()
        } else {
            self.older_kids().join(", ")
        };
        internal(format!(
            "{what} is sealed under key {}, but this node has key {} (previous keys: {older}); restore the matching key as /conf/secrets.key or in CITE_SECRETS_KEY_PREVIOUS_FILE; the connector did not start",
            hex(&kid),
            self.primary.kid_hex()
        ))
    }

    pub fn seal(&self, logical_name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = random::<12>()?;
        let aad = format!("{FILE_AAD_PREFIX}{logical_name}");
        let ct = seal_with(self.primary.bytes(), nonce, aad.as_bytes(), plaintext)?;
        let wire = Wire {
            cite_sealed: 1,
            alg: ENVELOPE_ALG.to_string(),
            kid: self.primary.kid_hex(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ct: URL_SAFE_NO_PAD.encode(&ct),
        };
        let mut out = serde_json::to_vec(&wire)?;
        out.push(b'\n');
        Ok(out)
    }

    /// Opens an envelope, or returns legacy plaintext unchanged with `legacy_plaintext` set.
    pub fn open(&self, logical_name: &str, bytes: &[u8]) -> Result<Opened> {
        match classify(bytes) {
            Shape::Plain => Ok(Opened {
                plaintext: Zeroizing::new(bytes.to_vec()),
                legacy_plaintext: true,
                kid: None,
            }),
            Shape::Malformed => Err(internal(format!(
                "{logical_name} has the shape of a sealed file but its envelope is damaged"
            ))),
            Shape::Envelope(env) => {
                let key = self
                    .key_for(env.kid)
                    .ok_or_else(|| self.unknown_kid(logical_name, env.kid))?;
                let aad = format!("{FILE_AAD_PREFIX}{logical_name}");
                let plaintext = open_with(key.bytes(), env.nonce, aad.as_bytes(), &env.ct)
                    .map_err(|_| {
                        internal(format!(
                            "{logical_name} could not be decrypted: the key is wrong, the file belongs elsewhere, or it was altered"
                        ))
                    })?;
                Ok(Opened {
                    plaintext,
                    legacy_plaintext: false,
                    kid: Some(env.kid),
                })
            }
        }
    }

    /// True when the data was read as legacy plaintext or under a key other than the primary.
    pub fn needs_reseal(&self, opened: &Opened) -> bool {
        opened.legacy_plaintext || opened.kid != Some(self.primary.kid)
    }

    /// Wraps a backup's data key under the primary key: (kid, nonce, wrapped key with tag).
    pub fn wrap_dek(
        &self,
        backup_id: &str,
        dek: &[u8; 32],
    ) -> Result<([u8; 8], [u8; 12], [u8; 48])> {
        let nonce = random::<12>()?;
        let aad = format!("{DEK_AAD_PREFIX}{backup_id}");
        let sealed = seal_with(self.primary.bytes(), nonce, aad.as_bytes(), dek)?;
        let wrapped: [u8; 48] = sealed
            .try_into()
            .map_err(|_| internal("the wrapped data key has an unexpected size"))?;
        Ok((self.primary.kid, nonce, wrapped))
    }

    pub fn unwrap_dek(
        &self,
        backup_id: &str,
        kid: [u8; 8],
        nonce: [u8; 12],
        wrapped: &[u8; 48],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let key = self
            .key_for(kid)
            .ok_or_else(|| self.unknown_kid("the backup", kid))?;
        let aad = format!("{DEK_AAD_PREFIX}{backup_id}");
        let plain = open_with(key.bytes(), nonce, aad.as_bytes(), wrapped).map_err(|_| {
            internal("the backup key could not be unwrapped: the node key is wrong or the file belongs to another backup")
        })?;
        let dek: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| internal("the unwrapped data key has an unexpected size"))?;
        Ok(Zeroizing::new(dek))
    }

    /// Call once every sealed file and local backup header has been moved to the primary key: the managed
    /// previous-key file is deleted, and an operator-supplied previous key is reported as no longer needed.
    pub fn finish_rotation(&self) -> Result<bool> {
        if self.mode == OpenMode::ReadOnly || self.older.is_empty() {
            return Ok(false);
        }
        match &self.source {
            KeySource::Managed(path) => {
                let (dir, _) = TrustedDir::split(path).map_err(core)?;
                let previous = fixed(MANAGED_PREVIOUS_FILE)?;
                match dir.unlink(&previous) {
                    Ok(()) => {
                        tracing::info!("secrets.key.previous removed after re-sealing");
                        Ok(true)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        tracing::info!("CITE_SECRETS_KEY_PREVIOUS is no longer needed; unset it");
                        Ok(false)
                    }
                    Err(e) => Err(internal(format!("cannot remove secrets.key.previous: {e}"))),
                }
            }
            KeySource::Env | KeySource::File(_) => {
                tracing::info!("CITE_SECRETS_KEY_PREVIOUS is no longer needed; unset it");
                Ok(false)
            }
        }
    }
}

fn fixed(name: &str) -> Result<FileName> {
    FileName::new(name).map_err(|e| internal(format!("invalid file name: {e}")))
}

fn core(err: cite_core::Error) -> ConnectorError {
    internal(err.to_string())
}

fn managed_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MANAGED_KEY_FILE)
}

// Reads a key file of at most KEY_FILE_MAX_BYTES; a mode wider than 0600 is a warning only.
fn read_key_file(dir: &TrustedDir, name: &FileName) -> Result<Option<Zeroizing<String>>> {
    let (file, meta) = match dir.open_regular(name) {
        Ok(opened) => opened,
        Err(cite_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => return Err(internal(format!("cannot read {name}: {e}"))),
    };
    if meta.len() > KEY_FILE_MAX_BYTES {
        return Err(internal(format!("{name} is too large to be a secrets key")));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        tracing::warn!("{name} is readable by other users; restrict it to mode 0600");
    }
    let mut bytes = Vec::new();
    file.take(KEY_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| internal(format!("cannot read {name}: {e}")))?;
    let text = String::from_utf8(bytes).map_err(|_| internal(format!("{name} is not text")))?;
    Ok(Some(Zeroizing::new(text)))
}

fn parse_named(text: &str, what: &str) -> Result<NodeKey> {
    NodeKey::parse(text).map_err(|e| internal(format!("{what}: {e}")))
}

fn input_source(input: &KeyInput) -> KeySource {
    match input.source() {
        KeyInputSource::Env => KeySource::Env,
        KeyInputSource::File(p) => KeySource::File(p.clone()),
    }
}

fn resolve(
    data_dir: &Path,
    primary: Option<&KeyInput>,
    previous: Option<&KeyInput>,
    mode: OpenMode,
    generate: bool,
) -> Result<Option<Keyring>> {
    let dir = match TrustedDir::open(data_dir) {
        Ok(dir) => Some(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && generate => {
            ensure_dir(data_dir, 0o711).map_err(core)?;
            Some(
                TrustedDir::open(data_dir)
                    .map_err(|e| internal(format!("cannot open {}: {e}", data_dir.display())))?,
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(internal(format!("cannot open {}: {e}", data_dir.display())));
        }
    };
    let managed_name = fixed(MANAGED_KEY_FILE)?;
    let found = match primary {
        Some(input) => Some((
            parse_named(input.expose(), "CITE_SECRETS_KEY")?,
            input_source(input),
        )),
        None => match dir.as_ref().map(|d| read_key_file(d, &managed_name)) {
            Some(Ok(Some(text))) => Some((
                parse_named(&text, MANAGED_KEY_FILE)?,
                KeySource::Managed(managed_path(data_dir)),
            )),
            Some(Err(e)) => return Err(e),
            _ => None,
        },
    };
    let (key, source) = match found {
        Some(found) => found,
        None => {
            if let Some((file, kid)) = first_sealed(data_dir) {
                return Err(internal(format!(
                    "sealed secrets found ({file}, key {}) but no key: restore /conf/secrets.key or set CITE_SECRETS_KEY_FILE; the connector did not start",
                    hex(&kid)
                )));
            }
            match (&dir, generate && mode == OpenMode::Migrating) {
                (Some(dir), true) => create_managed(dir, data_dir)?,
                _ => return Ok(None),
            }
        }
    };
    let previous_name = fixed(MANAGED_PREVIOUS_FILE)?;
    let older = match previous {
        Some(input) => Some(parse_named(input.expose(), "CITE_SECRETS_KEY_PREVIOUS")?),
        None => match dir.as_ref().map(|d| read_key_file(d, &previous_name)) {
            Some(Ok(Some(text))) => Some(parse_named(&text, MANAGED_PREVIOUS_FILE)?),
            Some(Err(e)) => return Err(e),
            _ => None,
        },
    };
    Ok(Some(Keyring::from_keys(
        key,
        source,
        older.into_iter().collect(),
        mode,
    )))
}

// Two processes may start together; the lock makes the second one find the first one's key.
fn create_managed(dir: &TrustedDir, data_dir: &Path) -> Result<(NodeKey, KeySource)> {
    let managed_name = fixed(MANAGED_KEY_FILE)?;
    let _held = dir
        .lock_file(&fixed(KEY_LOCK_FILE)?, 0o600)
        .map_err(|e| internal(format!("cannot lock the secrets key: {e}")))?;
    if let Some(text) = read_key_file(dir, &managed_name)? {
        return Ok((
            parse_named(&text, MANAGED_KEY_FILE)?,
            KeySource::Managed(managed_path(data_dir)),
        ));
    }
    let key = NodeKey::generate()?;
    write_atomic_in(dir, &managed_name, key.text().as_bytes(), 0o600)
        .map_err(|e| internal(format!("cannot write the secrets key: {e}")))?;
    tracing::info!(
        "secrets key created at {} (kid {})",
        managed_path(data_dir).display(),
        key.kid_hex()
    );
    Ok((key, KeySource::Managed(managed_path(data_dir))))
}

/// Replaces the managed key, keeping the old one as `secrets.key.previous` until the next start has
/// re-sealed everything. Safe while the server runs: it keeps its key in memory and the restarted server
/// reads the old kid through the previous file. Returns (old kid, new kid).
pub fn rotate_managed(cfg: &ConnectorConfig) -> Result<(String, String)> {
    if cfg.secrets_key.is_some() {
        return Err(ConnectorError::BadRequest(
            "the key comes from CITE_SECRETS_KEY or CITE_SECRETS_KEY_FILE; set the new key there and move the old one to CITE_SECRETS_KEY_PREVIOUS[_FILE]".into(),
        ));
    }
    let dir = TrustedDir::open(&cfg.data_dir)
        .map_err(|e| internal(format!("cannot open {}: {e}", cfg.data_dir.display())))?;
    let _held = dir
        .lock_file(&fixed(KEY_LOCK_FILE)?, 0o600)
        .map_err(|e| internal(format!("cannot lock the secrets key: {e}")))?;
    let (current, previous, staged) = (
        fixed(MANAGED_KEY_FILE)?,
        fixed(MANAGED_PREVIOUS_FILE)?,
        fixed(NEW_KEY_FILE)?,
    );
    let old_text = read_key_file(&dir, &current)?.ok_or_else(|| {
        ConnectorError::NotFound(format!(
            "there is no managed key at {}; nothing to rotate",
            managed_path(&cfg.data_dir).display()
        ))
    })?;
    let old = parse_named(&old_text, MANAGED_KEY_FILE)?;
    if dir.key(&previous).is_some() {
        return Err(ConnectorError::Conflict(
            "secrets.key.previous exists: restart the connector so it finishes the last rotation, then rotate again".into(),
        ));
    }
    let fresh = NodeKey::generate()?;
    write_atomic_in(&dir, &staged, fresh.text().as_bytes(), 0o600)
        .map_err(|e| internal(format!("cannot stage the new key: {e}")))?;
    dir.rename(&current, &previous)
        .map_err(|e| internal(format!("cannot keep the old key: {e}")))?;
    dir.rename(&staged, &current)
        .map_err(|e| internal(format!("cannot install the new key: {e}")))?;
    dir.sync().ok();
    Ok((old.kid_hex(), fresh.kid_hex()))
}

/// The files that may be sealed, as (logical name, path) under the data directory.
pub fn candidate_files(data_dir: &Path) -> Vec<(String, PathBuf)> {
    let tls = data_dir.join("tls");
    vec![
        ("secrets.json".into(), data_dir.join("secrets.json")),
        ("credentials.json".into(), data_dir.join("credentials.json")),
        ("alerts.json".into(), data_dir.join("alerts.json")),
        (
            "zone-secrets.json".into(),
            data_dir.join("zone-secrets.json"),
        ),
        ("acme-account.pem".into(), data_dir.join("acme-account.pem")),
        ("tls/ca.key".into(), tls.join("ca.key")),
        ("tls/server.key".into(), tls.join("server.key")),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    Absent,
    Plaintext,
    Sealed { kid: String },
    Unreadable,
}

/// Where each candidate file stands, without any key.
pub fn file_states(data_dir: &Path) -> Vec<(String, FileState)> {
    candidate_files(data_dir)
        .into_iter()
        .map(|(name, path)| {
            let state =
                match cite_core::atomic::read_limited(&path, sealed_read_cap(LARGEST_PLAINTEXT)) {
                    Ok(bytes) => match classify(&bytes) {
                        Shape::Envelope(env) => FileState::Sealed { kid: hex(&env.kid) },
                        Shape::Malformed => FileState::Unreadable,
                        Shape::Plain => FileState::Plaintext,
                    },
                    Err(cite_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        FileState::Absent
                    }
                    Err(_) => FileState::Unreadable,
                };
            (name, state)
        })
        .collect()
}

fn first_sealed(data_dir: &Path) -> Option<(String, [u8; 8])> {
    file_states(data_dir)
        .into_iter()
        .find_map(|(name, state)| match state {
            FileState::Sealed { kid } => unhex::<8>(&kid).map(|k| (name, k)),
            _ => None,
        })
}

/// Refuses when a sealed candidate file names a key the keyring does not hold.
pub fn verify_kids(keyring: &Keyring, data_dir: &Path) -> Result<()> {
    for (name, state) in file_states(data_dir) {
        if let FileState::Sealed { kid } = state
            && let Some(kid) = unhex::<8>(&kid)
            && keyring.key_for(kid).is_none()
        {
            return Err(keyring.unknown_kid(&name, kid));
        }
    }
    Ok(())
}

/// Room for the base64 and JSON overhead of a sealed file whose plaintext is at most `max_plain`.
pub const fn sealed_read_cap(max_plain: u64) -> u64 {
    max_plain + max_plain / 3 + 1024
}

/// A file as read: its plaintext, and whether it should be rewritten under the primary key.
pub struct ReadFile {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub needs_seal: bool,
}

fn not_found(err: &cite_core::Error) -> bool {
    matches!(err, cite_core::Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// Reads a file that may be sealed. Legacy plaintext is returned as is. None when the file is absent.
/// Without a keyring a sealed file is an error that says what is missing.
pub fn read_file(
    keyring: Option<&Keyring>,
    dir: &TrustedDir,
    name: &FileName,
    max_plain: u64,
) -> Result<Option<ReadFile>> {
    let raw = match dir.read_limited(name, sealed_read_cap(max_plain)) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(internal(format!("cannot read {name}: {e}"))),
    };
    let logical = name.to_string();
    let read = match keyring {
        Some(keyring) => {
            let opened = keyring.open(&logical, &raw)?;
            ReadFile {
                needs_seal: keyring.needs_reseal(&opened),
                plaintext: opened.plaintext,
            }
        }
        None => match classify(&raw) {
            Shape::Plain => ReadFile {
                plaintext: raw,
                needs_seal: false,
            },
            Shape::Envelope(env) => {
                return Err(internal(format!(
                    "{name} is sealed (key {}) but no secrets key is available: restore /conf/secrets.key or set CITE_SECRETS_KEY_FILE",
                    hex(&env.kid)
                )));
            }
            Shape::Malformed => {
                return Err(internal(format!(
                    "{name} has the shape of a sealed file but its envelope is damaged"
                )));
            }
        },
    };
    if read.plaintext.len() as u64 > max_plain {
        return Err(internal(format!("{name} is larger than {max_plain} bytes")));
    }
    Ok(Some(read))
}

/// Writes atomically, sealed when a keyring is given and as plain bytes otherwise.
pub fn write_file(
    keyring: Option<&Keyring>,
    dir: &TrustedDir,
    name: &FileName,
    plaintext: &[u8],
    mode: u32,
) -> Result<()> {
    let result = match keyring {
        Some(keyring) => write_atomic_in(
            dir,
            name,
            &keyring.seal(&name.to_string(), plaintext)?,
            mode,
        ),
        None => write_atomic_in(dir, name, plaintext, mode),
    };
    result.map_err(|e| internal(format!("cannot write {name}: {e}")))
}

pub fn read_path(
    keyring: Option<&Keyring>,
    path: &Path,
    max_plain: u64,
) -> Result<Option<ReadFile>> {
    let (dir, name) = TrustedDir::split(path).map_err(core)?;
    read_file(keyring, &dir, &name, max_plain)
}

pub fn write_path(
    keyring: Option<&Keyring>,
    path: &Path,
    plaintext: &[u8],
    mode: u32,
) -> Result<()> {
    let (dir, name) = TrustedDir::split(path).map_err(core)?;
    write_file(keyring, &dir, &name, plaintext, mode)
}

/// Moves a file that was just read to the primary key. The original is kept once as `<name>.pre-seal`
/// and removed by the next start that finds the file already sealed. Nothing happens in `ReadOnly` mode.
/// True when the file was rewritten.
pub fn migrate_file(
    keyring: &Keyring,
    dir: &TrustedDir,
    name: &FileName,
    read: &ReadFile,
) -> Result<bool> {
    if keyring.mode == OpenMode::ReadOnly {
        return Ok(false);
    }
    let pre_seal = fixed(&format!("{name}{PRE_SEAL_SUFFIX}"))?;
    if !read.needs_seal {
        match dir.unlink(&pre_seal) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("{pre_seal} could not be removed: {e}"),
        }
        return Ok(false);
    }
    // any entry of that name counts as an existing copy and is neither read nor replaced
    if dir.key(&pre_seal).is_none() {
        let original = Zeroizing::new(
            dir.read_limited(name, sealed_read_cap(LARGEST_PLAINTEXT))
                .map_err(|e| internal(format!("cannot read {name}: {e}")))?,
        );
        write_atomic_in(dir, &pre_seal, &original, 0o600)
            .map_err(|e| internal(format!("cannot keep a copy of {name}: {e}")))?;
    } else {
        tracing::warn!("{pre_seal} already exists and was left as it is");
    }
    write_file(Some(keyring), dir, name, &read.plaintext, 0o600)?;
    Ok(true)
}

pub fn migrate_path(keyring: &Keyring, path: &Path, read: &ReadFile) -> Result<bool> {
    let (dir, name) = TrustedDir::split(path).map_err(core)?;
    migrate_file(keyring, &dir, &name, read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::test_config;
    use std::fs;

    fn key(seed: u8) -> NodeKey {
        NodeKey::from_bytes(&[seed; 32])
    }

    fn ring_of(seed: u8, mode: OpenMode) -> Keyring {
        Keyring::from_keys(key(seed), KeySource::Env, Vec::new(), mode)
    }

    fn input(seed: u8) -> KeyInput {
        KeyInput::new(&key(seed).text(), KeyInputSource::Env).expect("key input")
    }

    fn name(n: &str) -> FileName {
        FileName::new(n).expect("name")
    }

    #[test]
    fn a_sealed_value_round_trips_and_is_one_line_of_json_with_exactly_the_envelope_keys() {
        let ring = ring_of(1, OpenMode::Migrating);
        let sealed = ring.seal("secrets.json", b"{\"a\":\"b\"}").expect("seal");
        assert_eq!(sealed.iter().filter(|b| **b == b'\n').count(), 1);
        assert!(sealed.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&sealed).expect("json");
        let mut keys: Vec<_> = value.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["alg", "cite_sealed", "ct", "kid", "nonce"]);
        assert_eq!(value["cite_sealed"], 1);
        assert_eq!(value["kid"], ring.kid_hex());
        let opened = ring.open("secrets.json", &sealed).expect("open");
        assert_eq!(&**opened.plaintext, b"{\"a\":\"b\"}");
        assert!(!opened.legacy_plaintext);
        assert_eq!(opened.kid, Some(ring.kid()));
        assert!(!ring.needs_reseal(&opened));
        assert!(!String::from_utf8_lossy(&sealed).contains("\"a\""));
    }

    #[test]
    fn two_seals_of_the_same_value_differ() {
        let ring = ring_of(1, OpenMode::Migrating);
        let a = ring.seal("x", b"same").expect("seal");
        let b = ring.seal("x", b"same").expect("seal");
        assert_ne!(a, b);
    }

    #[test]
    fn the_file_name_is_bound_so_sealed_files_cannot_be_swapped() {
        let ring = ring_of(1, OpenMode::Migrating);
        let sealed = ring.seal("secrets.json", b"{}").expect("seal");
        let err = ring.open("credentials.json", &sealed).err().expect("swap");
        assert!(err.to_string().contains("could not be decrypted"), "{err}");
        assert!(ring.open("secrets.json", &sealed).is_ok());
    }

    #[test]
    fn a_flipped_bit_or_truncated_ciphertext_is_refused() {
        let ring = ring_of(1, OpenMode::Migrating);
        let sealed = ring.seal("f", b"payload").expect("seal");
        let mut wire: serde_json::Value = serde_json::from_slice(&sealed).expect("json");
        let ct = URL_SAFE_NO_PAD
            .decode(wire["ct"].as_str().expect("ct"))
            .expect("b64");
        let mut flipped = ct.clone();
        flipped[0] ^= 1;
        wire["ct"] = URL_SAFE_NO_PAD.encode(&flipped).into();
        assert!(ring.open("f", wire.to_string().as_bytes()).is_err());
        wire["ct"] = URL_SAFE_NO_PAD.encode(&ct[..ct.len() - 1]).into();
        assert!(ring.open("f", wire.to_string().as_bytes()).is_err());
        wire["ct"] = URL_SAFE_NO_PAD.encode(&ct[..4]).into();
        let err = ring
            .open("f", wire.to_string().as_bytes())
            .err()
            .expect("short");
        assert!(err.to_string().contains("damaged"), "{err}");
    }

    #[test]
    fn plaintext_is_detected_as_legacy_and_an_object_with_other_keys_is_not_an_envelope() {
        let ring = ring_of(1, OpenMode::Migrating);
        for plain in [
            &br#"{"gh-blog":"tok","other":"x"}"#[..],
            br#"{}"#,
            br#"{"cite_sealed":"1","alg":"a","kid":"b","nonce":"c","ct":"d"}"#,
            br#"{"cite_sealed":2,"alg":"a","kid":"b","nonce":"c","ct":"d"}"#,
            br#"{"cite_sealed":1,"alg":"chacha20poly1305","kid":"0011223344556677","nonce":"AAAA","ct":"AAAA","extra":1}"#,
            b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        ] {
            let opened = ring.open("secrets.json", plain).expect("legacy");
            assert!(opened.legacy_plaintext, "{}", String::from_utf8_lossy(plain));
            assert_eq!(&**opened.plaintext, plain);
            assert!(opened.kid.is_none());
            assert!(ring.needs_reseal(&opened));
            assert!(envelope_kid(plain).is_none());
        }
    }

    #[test]
    fn an_unknown_key_id_is_refused_naming_both_ids() {
        let theirs = ring_of(1, OpenMode::Migrating);
        let ours = Keyring::from_keys(key(2), KeySource::Env, vec![key(3)], OpenMode::Migrating);
        let sealed = theirs.seal("secrets.json", b"{}").expect("seal");
        let err = ours.open("secrets.json", &sealed).err().expect("refuse");
        let text = err.to_string();
        assert!(text.contains(&key(1).kid_hex()), "{text}");
        assert!(text.contains(&key(2).kid_hex()), "{text}");
        assert!(text.contains(&key(3).kid_hex()), "{text}");
        assert!(text.contains("did not start"), "{text}");
    }

    #[test]
    fn a_previous_key_opens_old_data_and_flags_it_for_resealing() {
        let old = ring_of(1, OpenMode::Migrating);
        let sealed = old.seal("alerts.json", b"{\"v\":1}").expect("seal");
        let rotated = Keyring::from_keys(key(2), KeySource::Env, vec![key(1)], OpenMode::Migrating);
        let opened = rotated.open("alerts.json", &sealed).expect("open");
        assert_eq!(&**opened.plaintext, b"{\"v\":1}");
        assert_eq!(opened.kid, Some(key(1).kid()));
        assert!(rotated.needs_reseal(&opened));
        assert!(rotated.has_older());
        assert_eq!(rotated.older_kids(), [key(1).kid_hex()]);
        let again = rotated
            .seal("alerts.json", &opened.plaintext)
            .expect("seal");
        assert_eq!(
            envelope_kid(&again),
            Some(key(2).kid()),
            "new writes use the primary key"
        );
    }

    #[test]
    fn keys_parse_strictly_print_redacted_and_never_quote_bad_input() {
        let k = key(9);
        let text = k.text();
        assert!(text.starts_with(KEY_PREFIX));
        assert_eq!(
            NodeKey::parse(&format!("  {}\n", *text))
                .expect("parse")
                .kid(),
            k.kid()
        );
        assert!(!format!("{k:?}").contains(&text[KEY_PREFIX.len()..]));
        assert!(!format!("{:?}", input(9)).contains(&text[KEY_PREFIX.len()..]));
        for bad in [
            "",
            "cite-key-v1:",
            "cite-key-v1:short",
            "other-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "cite-key-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "cite-key-v1:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        ] {
            let err = NodeKey::parse(bad).expect_err(bad).to_string();
            let secret_part = bad.strip_prefix(KEY_PREFIX).unwrap_or(bad);
            assert!(
                secret_part.is_empty() || !err.contains(secret_part),
                "{err}"
            );
        }
        let kid = k.kid_hex();
        let mut hasher = Sha256::new();
        hasher.update(b"cite-kid-v1");
        hasher.update([9u8; 32]);
        assert_eq!(kid, hex(&hasher.finalize()[..8]));
    }

    #[test]
    fn data_keys_wrap_under_the_node_key_bound_to_the_backup_id() {
        let ring = ring_of(1, OpenMode::Migrating);
        let dek = [7u8; 32];
        let (kid, nonce, wrapped) = ring.wrap_dek("backup-1", &dek).expect("wrap");
        assert_eq!(kid, ring.kid());
        assert_eq!(
            *ring
                .unwrap_dek("backup-1", kid, nonce, &wrapped)
                .expect("unwrap"),
            dek
        );
        assert!(ring.unwrap_dek("backup-2", kid, nonce, &wrapped).is_err());
        let mut torn = wrapped;
        torn[0] ^= 1;
        assert!(ring.unwrap_dek("backup-1", kid, nonce, &torn).is_err());
        let other = ring_of(2, OpenMode::Migrating);
        assert!(other.unwrap_dek("backup-1", kid, nonce, &wrapped).is_err());
        let rotated = Keyring::from_keys(key(2), KeySource::Env, vec![key(1)], OpenMode::Migrating);
        assert_eq!(
            *rotated
                .unwrap_dek("backup-1", kid, nonce, &wrapped)
                .expect("older"),
            dek
        );
        let extra = other.with_extra(vec![key(1)]);
        assert!(extra.unwrap_dek("backup-1", kid, nonce, &wrapped).is_ok());
    }

    #[test]
    fn load_creates_the_managed_key_once_with_private_mode_and_reuses_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        let first = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("a key is created");
        let path = dir.path().join(MANAGED_KEY_FILE);
        let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(first.source(), &KeySource::Managed(path.clone()));
        let text = fs::read_to_string(&path).expect("read");
        assert!(text.starts_with(KEY_PREFIX));
        let second = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        assert_eq!(second.kid_hex(), first.kid_hex());
        let read_only = Keyring::load(&cfg, OpenMode::ReadOnly)
            .expect("load")
            .expect("key");
        assert_eq!(read_only.kid_hex(), first.kid_hex());
        assert_eq!(read_only.mode(), OpenMode::ReadOnly);
    }

    #[test]
    fn a_read_only_load_never_creates_a_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        assert!(
            Keyring::load(&cfg, OpenMode::ReadOnly)
                .expect("load")
                .is_none()
        );
        assert!(!dir.path().join(MANAGED_KEY_FILE).exists());
        assert!(
            Keyring::discover(dir.path(), OpenMode::Migrating)
                .expect("discover")
                .is_none()
        );
        assert!(!dir.path().join(MANAGED_KEY_FILE).exists());
    }

    #[test]
    fn sealed_files_without_a_key_refuse_and_a_key_is_never_regenerated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        let sealed = ring_of(4, OpenMode::Migrating)
            .seal("secrets.json", b"{}")
            .expect("seal");
        fs::write(dir.path().join("secrets.json"), &sealed).expect("write");
        for mode in [OpenMode::Migrating, OpenMode::ReadOnly] {
            let err = Keyring::load(&cfg, mode).expect_err("refuse").to_string();
            assert!(err.contains(&key(4).kid_hex()), "{err}");
            assert!(err.contains("secrets.key"), "{err}");
            assert!(err.contains("did not start"), "{err}");
        }
        assert!(Keyring::discover(dir.path(), OpenMode::Migrating).is_err());
        assert!(
            !dir.path().join(MANAGED_KEY_FILE).exists(),
            "no key was invented"
        );
    }

    #[test]
    fn a_sealed_tls_key_without_a_key_also_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        fs::create_dir_all(dir.path().join("tls")).expect("tls dir");
        let sealed = ring_of(4, OpenMode::Migrating)
            .seal("ca.key", b"pem")
            .expect("seal");
        fs::write(dir.path().join("tls/ca.key"), sealed).expect("write");
        let err = Keyring::load(&cfg, OpenMode::Migrating)
            .expect_err("refuse")
            .to_string();
        assert!(err.contains("tls/ca.key"), "{err}");
    }

    #[test]
    fn the_environment_key_wins_over_a_managed_file_and_a_bad_one_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = test_config(dir.path());
        let managed = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        cfg.secrets_key = Some(input(6));
        let ring = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        assert_eq!(ring.kid_hex(), key(6).kid_hex());
        assert_ne!(ring.kid_hex(), managed.kid_hex());
        assert_eq!(ring.source(), &KeySource::Env);

        let mut env = HashMap::new();
        env.insert("CITE_CONNECTOR_ALLOW".to_string(), "127.0.0.1".to_string());
        env.insert(
            "CITE_SECRETS_KEY".to_string(),
            "cite-key-v1:oops".to_string(),
        );
        let err = ConnectorConfig::from_env_map(&env)
            .expect_err("bad key")
            .to_string();
        assert!(
            err.contains("CITE_SECRETS_KEY") && !err.contains("oops"),
            "{err}"
        );
    }

    #[test]
    fn a_key_file_and_a_previous_key_are_read_from_the_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_file = dir.path().join("current.key");
        let previous_file = dir.path().join("previous.key");
        fs::write(&key_file, format!("{}\n", *key(1).text())).expect("write");
        fs::write(&previous_file, key(2).text().as_bytes()).expect("write");
        let mut env = HashMap::new();
        env.insert("CITE_CONNECTOR_ALLOW".to_string(), "127.0.0.1".to_string());
        env.insert(
            "CITE_CONNECTOR_DATA".to_string(),
            dir.path().join("data").display().to_string(),
        );
        env.insert(
            "CITE_SECRETS_KEY_FILE".to_string(),
            key_file.display().to_string(),
        );
        env.insert(
            "CITE_SECRETS_KEY_PREVIOUS_FILE".to_string(),
            previous_file.display().to_string(),
        );
        let cfg = ConnectorConfig::from_env_map(&env).expect("config");
        let ring = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        assert_eq!(ring.kid_hex(), key(1).kid_hex());
        assert_eq!(ring.older_kids(), [key(2).kid_hex()]);
        assert_eq!(ring.source(), &KeySource::File(key_file));
        assert!(
            !dir.path().join("data").join(MANAGED_KEY_FILE).exists(),
            "an explicit key never creates the managed file"
        );
    }

    #[test]
    fn the_managed_previous_file_is_picked_up_and_finish_rotation_removes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        let first = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        let (old, new) = rotate_managed(&cfg).expect("rotate");
        assert_eq!(old, first.kid_hex());
        assert_ne!(new, old);
        let again = rotate_managed(&cfg)
            .expect_err("second rotation")
            .to_string();
        assert!(again.contains("secrets.key.previous"), "{again}");

        let rotated = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        assert_eq!(rotated.kid_hex(), new);
        assert_eq!(rotated.older_kids(), std::slice::from_ref(&old));
        let sealed = first.seal("alerts.json", b"{}").expect("seal");
        assert!(rotated.open("alerts.json", &sealed).is_ok());

        let read_only = Keyring::load(&cfg, OpenMode::ReadOnly)
            .expect("load")
            .expect("key");
        assert!(!read_only.finish_rotation().expect("noop"));
        assert!(dir.path().join(MANAGED_PREVIOUS_FILE).exists());
        assert!(rotated.finish_rotation().expect("finish"));
        assert!(!dir.path().join(MANAGED_PREVIOUS_FILE).exists());
        let after = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        assert!(!after.has_older());
    }

    #[test]
    fn rotating_a_key_set_by_the_environment_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = test_config(dir.path());
        cfg.secrets_key = Some(input(1));
        assert!(rotate_managed(&cfg).is_err());
        let fresh = tempfile::tempdir().expect("tempdir");
        let err = rotate_managed(&test_config(fresh.path())).expect_err("no key");
        assert!(err.to_string().contains("nothing to rotate"), "{err}");
    }

    fn data_dir_handle(dir: &Path) -> TrustedDir {
        TrustedDir::open(dir).expect("open")
    }

    #[test]
    fn legacy_plaintext_is_migrated_once_keeping_a_pre_seal_copy_until_the_next_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = data_dir_handle(dir.path());
        let ring = ring_of(1, OpenMode::Migrating);
        let file = name("alerts.json");
        let original = br#"{"enabled":true}"#;
        fs::write(dir.path().join("alerts.json"), original).expect("write");

        let read = read_file(Some(&ring), &handle, &file, 1024)
            .expect("read")
            .expect("present");
        assert!(read.needs_seal);
        assert_eq!(&**read.plaintext, original);
        assert!(migrate_file(&ring, &handle, &file, &read).expect("migrate"));
        assert_eq!(
            fs::read(dir.path().join("alerts.json.pre-seal")).expect("copy"),
            original
        );
        let mode = fs::metadata(dir.path().join("alerts.json.pre-seal"))
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            envelope_kid(&fs::read(dir.path().join("alerts.json")).expect("sealed")),
            Some(ring.kid())
        );

        let again = read_file(Some(&ring), &handle, &file, 1024)
            .expect("read")
            .expect("present");
        assert!(!again.needs_seal);
        assert_eq!(&**again.plaintext, original);
        assert!(!migrate_file(&ring, &handle, &file, &again).expect("migrate"));
        assert!(
            !dir.path().join("alerts.json.pre-seal").exists(),
            "the next start that finds the file sealed removes the copy"
        );
    }

    #[test]
    fn an_existing_pre_seal_entry_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = data_dir_handle(dir.path());
        let ring = ring_of(1, OpenMode::Migrating);
        fs::write(dir.path().join("alerts.json"), b"{\"a\":1}").expect("write");
        fs::write(dir.path().join("alerts.json.pre-seal"), b"older copy").expect("write");
        let read = read_file(Some(&ring), &handle, &name("alerts.json"), 1024)
            .expect("read")
            .expect("present");
        assert!(migrate_file(&ring, &handle, &name("alerts.json"), &read).expect("migrate"));
        assert_eq!(
            fs::read(dir.path().join("alerts.json.pre-seal")).expect("copy"),
            b"older copy"
        );
    }

    #[test]
    fn a_read_only_keyring_never_rewrites_what_it_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = data_dir_handle(dir.path());
        let ring = ring_of(1, OpenMode::ReadOnly);
        fs::write(dir.path().join("alerts.json"), b"{\"a\":1}").expect("write");
        let read = read_file(Some(&ring), &handle, &name("alerts.json"), 1024)
            .expect("read")
            .expect("present");
        assert!(read.needs_seal);
        assert!(!migrate_file(&ring, &handle, &name("alerts.json"), &read).expect("noop"));
        assert_eq!(
            fs::read(dir.path().join("alerts.json")).expect("file"),
            b"{\"a\":1}"
        );
        assert!(!dir.path().join("alerts.json.pre-seal").exists());
    }

    #[test]
    fn a_file_under_a_previous_key_is_resealed_under_the_primary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = data_dir_handle(dir.path());
        let old = ring_of(1, OpenMode::Migrating);
        let sealed = old.seal("zone-secrets.json", b"{}").expect("seal");
        fs::write(dir.path().join("zone-secrets.json"), &sealed).expect("write");
        let ring = Keyring::from_keys(key(2), KeySource::Env, vec![key(1)], OpenMode::Migrating);
        let file = name("zone-secrets.json");
        let read = read_file(Some(&ring), &handle, &file, 1024)
            .expect("read")
            .expect("present");
        assert!(read.needs_seal);
        assert!(migrate_file(&ring, &handle, &file, &read).expect("migrate"));
        assert_eq!(
            envelope_kid(&fs::read(dir.path().join("zone-secrets.json")).expect("file")),
            Some(key(2).kid())
        );
        assert_eq!(
            fs::read(dir.path().join("zone-secrets.json.pre-seal")).expect("copy"),
            sealed
        );
    }

    #[test]
    fn reading_without_a_keyring_accepts_plaintext_and_refuses_a_sealed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = data_dir_handle(dir.path());
        assert!(
            read_file(None, &handle, &name("absent.json"), 16)
                .expect("absent")
                .is_none()
        );
        fs::write(dir.path().join("plain.json"), b"{}").expect("write");
        let plain = read_file(None, &handle, &name("plain.json"), 16)
            .expect("read")
            .expect("present");
        assert!(!plain.needs_seal);
        let sealed = ring_of(1, OpenMode::Migrating)
            .seal("sealed.json", b"{}")
            .expect("seal");
        fs::write(dir.path().join("sealed.json"), sealed).expect("write");
        let err = read_file(None, &handle, &name("sealed.json"), 16)
            .err()
            .expect("refuse");
        assert!(err.to_string().contains("no secrets key"), "{err}");
        fs::write(dir.path().join("big.json"), vec![b'x'; 64]).expect("write");
        assert!(read_file(None, &handle, &name("big.json"), 16).is_err());
    }

    #[test]
    fn write_file_seals_with_a_keyring_and_writes_plain_bytes_without() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = data_dir_handle(dir.path());
        let ring = ring_of(1, OpenMode::Migrating);
        write_file(
            Some(&ring),
            &handle,
            &name("s.json"),
            b"{\"k\":\"v\"}",
            0o600,
        )
        .expect("seal");
        let on_disk = fs::read(dir.path().join("s.json")).expect("read");
        assert!(envelope_kid(&on_disk).is_some());
        assert!(!String::from_utf8_lossy(&on_disk).contains("\"k\""));
        write_file(None, &handle, &name("p.json"), b"{\"k\":\"v\"}", 0o600).expect("plain");
        assert_eq!(
            fs::read(dir.path().join("p.json")).expect("read"),
            b"{\"k\":\"v\"}"
        );
        let mode = fs::metadata(dir.path().join("s.json"))
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn verify_kids_and_file_states_report_every_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("tls")).expect("tls");
        let theirs = ring_of(1, OpenMode::Migrating);
        fs::write(
            dir.path().join("secrets.json"),
            theirs.seal("secrets.json", b"{}").expect("seal"),
        )
        .expect("write");
        fs::write(dir.path().join("alerts.json"), b"{}").expect("write");
        let states: HashMap<_, _> = file_states(dir.path()).into_iter().collect();
        assert_eq!(
            states["secrets.json"],
            FileState::Sealed {
                kid: key(1).kid_hex()
            }
        );
        assert_eq!(states["alerts.json"], FileState::Plaintext);
        assert_eq!(states["credentials.json"], FileState::Absent);
        assert_eq!(states["tls/ca.key"], FileState::Absent);

        assert!(verify_kids(&theirs, dir.path()).is_ok());
        let ours = ring_of(2, OpenMode::Migrating);
        let err = verify_kids(&ours, dir.path())
            .expect_err("mismatch")
            .to_string();
        assert!(
            err.contains(&key(1).kid_hex()) && err.contains(&key(2).kid_hex()),
            "{err}"
        );
        assert!(err.contains("secrets.json"), "{err}");
    }

    #[test]
    fn discover_finds_the_managed_key_and_a_key_file_given_on_the_command_line_opens_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = test_config(dir.path());
        let made = Keyring::load(&cfg, OpenMode::Migrating)
            .expect("load")
            .expect("key");
        let found = Keyring::discover(dir.path(), OpenMode::Migrating)
            .expect("discover")
            .expect("key");
        assert_eq!(found.kid_hex(), made.kid_hex());
        let sealed = made.seal("secrets.json", b"{}").expect("seal");
        let from_file =
            Keyring::from_key_file(&dir.path().join(MANAGED_KEY_FILE)).expect("key file");
        assert!(from_file.open("secrets.json", &sealed).is_ok());
        assert!(Keyring::from_key_file(&dir.path().join("secrets.json")).is_err());
        assert!(Keyring::from_key_file(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn debug_output_names_no_key_material() {
        let ring = Keyring::from_keys(key(5), KeySource::Env, vec![key(6)], OpenMode::Migrating);
        let shown = format!("{ring:?} {:?}", key(5));
        for k in [key(5), key(6)] {
            let text = k.text();
            assert!(!shown.contains(&text[KEY_PREFIX.len()..]), "{shown}");
        }
        assert!(shown.contains(&key(5).kid_hex()));
    }
}
