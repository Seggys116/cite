use std::collections::HashMap;
use std::fmt;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::totp;

const MAX_SESSIONS: usize = 1024;
const MAX_API_TOKENS: usize = 64;
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 256;
const GENERATED_PASSWORD_CHARS: usize = 24;
const TOKEN_PREFIX: &str = "cite_";
const TOKEN_ID_HEX: usize = 16;
const TOKEN_SECRET_HEX: usize = 64;
const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

#[cfg(not(test))]
const MEMORY_KIB: u32 = 19 * 1024;
#[cfg(test)]
const MEMORY_KIB: u32 = 64;
#[cfg(not(test))]
const ITERATIONS: u32 = 2;
#[cfg(test)]
const ITERATIONS: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid credentials")]
    Invalid,
    #[error("weak password: {0}")]
    Weak(&'static str),
    #[error("password hashing failed")]
    Hash,
    #[error("random number generation failed")]
    Rng,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Credentials {
    pub username: String,
    pub password_hash: String,
    pub totp_secret: String,
    pub totp_last_step: u64,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password_hash", &"[redacted]")
            .field("totp_secret", &"[redacted]")
            .field("totp_last_step", &self.totp_last_step)
            .finish()
    }
}

fn hasher() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, 1, None).unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| AuthError::Rng)?;
    Ok(buf)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hash_password(pw: &str) -> Result<String, AuthError> {
    let salt_bytes = random_bytes::<16>()?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AuthError::Hash)?;
    let hash = hasher()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|_| AuthError::Hash)?;
    Ok(hash.to_string())
}

// Spends the same Argon2 cost as a real check, so an unknown user takes as long as a wrong password.
pub fn dummy_verify() {
    if let Ok(salt) = SaltString::encode_b64(&[0x5au8; 16]) {
        let _ = hasher().hash_password(b"cite-dummy-password", &salt);
    }
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => hasher().verify_password(pw.as_bytes(), &parsed).is_ok(),
        Err(_) => {
            dummy_verify();
            false
        }
    }
}

pub fn generate_password() -> Result<String, AuthError> {
    let n = PASSWORD_ALPHABET.len();
    // Bytes at or above this limit are discarded so every symbol is equally likely.
    let limit = 256 - (256 % n);
    let mut out = String::with_capacity(GENERATED_PASSWORD_CHARS);
    while out.len() < GENERATED_PASSWORD_CHARS {
        let batch = random_bytes::<48>()?;
        for &b in &batch {
            if usize::from(b) < limit && out.len() < GENERATED_PASSWORD_CHARS {
                out.push(char::from(PASSWORD_ALPHABET[usize::from(b) % n]));
            }
        }
    }
    Ok(out)
}

pub fn validate_username(u: &str) -> bool {
    (3..=32).contains(&u.len())
        && u.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

pub fn validate_password_strength(p: &str) -> Result<(), AuthError> {
    if p.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AuthError::Weak("password must be at least 12 characters"));
    }
    if p.len() > MAX_PASSWORD_BYTES {
        return Err(AuthError::Weak("password must be at most 256 bytes"));
    }
    Ok(())
}

// The id is a public lookup key; only the secret authenticates.
fn random_parts() -> Result<(String, String), AuthError> {
    Ok((
        to_hex(&random_bytes::<8>()?),
        to_hex(&random_bytes::<32>()?),
    ))
}

fn join_token(id: &str, secret: &str) -> String {
    format!("{TOKEN_PREFIX}{id}.{secret}")
}

pub fn random_token() -> Result<String, AuthError> {
    let (id, secret) = random_parts()?;
    Ok(join_token(&id, &secret))
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// Returns (id, secret) only for the exact `cite_<16 hex>.<64 hex>` shape, so malformed input is rejected before any lookup or hashing.
pub fn parse_token(token: &str) -> Option<(&str, &str)> {
    let (id, secret) = token.strip_prefix(TOKEN_PREFIX)?.split_once('.')?;
    let shaped = id.len() == TOKEN_ID_HEX
        && secret.len() == TOKEN_SECRET_HEX
        && is_lower_hex(id)
        && is_lower_hex(secret);
    shaped.then_some((id, secret))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Interactive,
}

#[derive(Clone)]
pub struct SessionInfo {
    pub username: String,
    pub kind: SessionKind,
    pub created: u64,
    pub expires: u64,
    pub last_seen: u64,
    pub csrf: String,
}

impl fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionInfo")
            .field("username", &self.username)
            .field("kind", &self.kind)
            .field("created", &self.created)
            .field("expires", &self.expires)
            .field("last_seen", &self.last_seen)
            .field("csrf", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
pub struct NewSession {
    pub token: String,
    pub expires: u64,
    pub csrf: String,
}

impl fmt::Debug for NewSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSession")
            .field("token", &"[redacted]")
            .field("expires", &self.expires)
            .field("csrf", &"[redacted]")
            .finish()
    }
}

struct SessionEntry {
    secret: String,
    info: SessionInfo,
}

pub struct SessionStore {
    ttl_secs: u64,
    idle_secs: u64,
    sessions: HashMap<String, SessionEntry>,
}

impl SessionStore {
    pub fn new(ttl_secs: u64, idle_secs: u64) -> Self {
        Self {
            ttl_secs,
            idle_secs,
            sessions: HashMap::new(),
        }
    }

    fn is_live(&self, info: &SessionInfo, now: u64) -> bool {
        now < info.expires && now.saturating_sub(info.last_seen) <= self.idle_secs
    }

    pub fn create(&mut self, username: &str, now: u64) -> Result<(String, u64), AuthError> {
        let opened = self.open(username, now)?;
        Ok((opened.token, opened.expires))
    }

    pub fn open(&mut self, username: &str, now: u64) -> Result<NewSession, AuthError> {
        let (id, secret) = random_parts()?;
        let csrf = to_hex(&random_bytes::<32>()?);
        // At capacity dead sessions go first, then the oldest live one, so a login flood cannot grow the table without bound.
        if self.sessions.len() >= MAX_SESSIONS {
            self.sweep(now);
        }
        while self.sessions.len() >= MAX_SESSIONS {
            let oldest = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.info.created)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(key) => self.sessions.remove(&key),
                None => break,
            };
        }
        let expires = now.saturating_add(self.ttl_secs);
        let info = SessionInfo {
            username: username.to_string(),
            kind: SessionKind::Interactive,
            created: now,
            expires,
            last_seen: now,
            csrf: csrf.clone(),
        };
        let token = join_token(&id, &secret);
        self.sessions.insert(id, SessionEntry { secret, info });
        Ok(NewSession {
            token,
            expires,
            csrf,
        })
    }

    // A wrong secret under a live id leaves the session untouched, so guessing cannot log anyone out.
    fn entry_for(&self, token: &str) -> Option<&SessionEntry> {
        let (id, secret) = parse_token(token)?;
        let entry = self.sessions.get(id)?;
        bool::from(entry.secret.as_bytes().ct_eq(secret.as_bytes())).then_some(entry)
    }

    pub fn validate(&mut self, token: &str, now: u64) -> Option<SessionInfo> {
        let (id, _) = parse_token(token)?;
        let live = self.is_live(&self.entry_for(token)?.info, now);
        if !live {
            self.sessions.remove(id);
            return None;
        }
        let entry = self.sessions.get_mut(id)?;
        entry.info.last_seen = now;
        Some(entry.info.clone())
    }

    pub fn revoke(&mut self, token: &str) {
        if self.entry_for(token).is_some()
            && let Some((id, _)) = parse_token(token)
        {
            self.sessions.remove(id);
        }
    }

    pub fn sweep(&mut self, now: u64) {
        let idle = self.idle_secs;
        self.sessions
            .retain(|_, s| now < s.info.expires && now.saturating_sub(s.info.last_seen) <= idle);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub hash: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

impl ApiToken {
    // Runs Argon2, so async callers should do this off the executor and before taking any lock.
    pub fn mint(name: &str) -> Result<(ApiToken, String), AuthError> {
        let (id, secret) = random_parts()?;
        let created_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let token = ApiToken {
            hash: hash_password(&secret)?,
            id: id.clone(),
            name: name.to_string(),
            created_at,
            last_used_at: None,
        };
        Ok((token, join_token(&id, &secret)))
    }
}

// Secrets that already passed Argon2, held in memory only so repeat requests skip the expensive check.
#[derive(Clone, Default)]
struct VerifiedCache(HashMap<String, String>);

impl fmt::Debug for VerifiedCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifiedCache({} entries)", self.0.len())
    }
}

impl VerifiedCache {
    fn holds(&self, id: &str, secret: &str) -> bool {
        self.0
            .get(id)
            .is_some_and(|known| bool::from(known.as_bytes().ct_eq(secret.as_bytes())))
    }

    fn remember(&mut self, id: &str, secret: &str) {
        if self.0.len() >= MAX_API_TOKENS && !self.0.contains_key(id) {
            self.0.clear();
        }
        self.0.insert(id.to_string(), secret.to_string());
    }
}

// A token that matched a stored record but still needs its Argon2 check; it owns copies so the check can run without any lock.
#[derive(Clone)]
pub struct PendingToken {
    id: String,
    secret: String,
    phc: String,
}

impl PendingToken {
    pub fn check(&self) -> bool {
        #[cfg(test)]
        ARGON_CHECKS.with(|c| c.set(c.get() + 1));
        verify_password(&self.secret, &self.phc)
    }
}

pub enum TokenLookup {
    Unknown,
    Verified(ApiToken),
    Pending(PendingToken),
}

#[cfg(test)]
thread_local! {
    static ARGON_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiTokens {
    tokens: Vec<ApiToken>,
    #[serde(skip)]
    verified: VerifiedCache,
}

impl ApiTokens {
    pub fn new() -> Self {
        Self::default()
    }

    // Test-only: it hashes inline, which async callers must never do under a lock.
    #[cfg(test)]
    fn create(&mut self, name: &str) -> Result<(ApiToken, String), AuthError> {
        self.ensure_room()?;
        let (token, plaintext) = ApiToken::mint(name)?;
        self.insert(token.clone())?;
        Ok((token, plaintext))
    }

    fn ensure_room(&self) -> Result<(), AuthError> {
        if self.tokens.len() >= MAX_API_TOKENS {
            return Err(AuthError::Weak("api token limit reached"));
        }
        Ok(())
    }

    pub fn insert(&mut self, token: ApiToken) -> Result<(), AuthError> {
        self.ensure_room()?;
        self.tokens.push(token);
        Ok(())
    }

    // Cheap and lock-friendly: malformed tokens and unknown ids end here without Argon2.
    pub fn begin_verify(&mut self, token: &str, now_rfc3339: &str) -> TokenLookup {
        let Some((id, secret)) = parse_token(token) else {
            return TokenLookup::Unknown;
        };
        let Some(entry) = self.tokens.iter_mut().find(|t| t.id == id) else {
            return TokenLookup::Unknown;
        };
        if self.verified.holds(id, secret) {
            entry.last_used_at = Some(now_rfc3339.to_string());
            return TokenLookup::Verified(entry.clone());
        }
        TokenLookup::Pending(PendingToken {
            id: entry.id.clone(),
            secret: secret.to_string(),
            phc: entry.hash.clone(),
        })
    }

    // Re-checks that the same record is still present, since it may have been revoked while Argon2 ran unlocked.
    pub fn complete(&mut self, pending: &PendingToken, now_rfc3339: &str) -> Option<&ApiToken> {
        let entry = self
            .tokens
            .iter_mut()
            .find(|t| t.id == pending.id && t.hash == pending.phc)?;
        entry.last_used_at = Some(now_rfc3339.to_string());
        self.verified.remember(&pending.id, &pending.secret);
        Some(&*entry)
    }

    #[cfg(test)]
    fn verify(&mut self, token: &str, now_rfc3339: &str) -> Option<&ApiToken> {
        let pending = match self.begin_verify(token, now_rfc3339) {
            TokenLookup::Unknown => return None,
            TokenLookup::Verified(hit) => {
                return self.tokens.iter().find(|t| t.id == hit.id);
            }
            TokenLookup::Pending(pending) => pending,
        };
        if !pending.check() {
            return None;
        }
        self.complete(&pending, now_rfc3339)
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        self.verified.0.remove(id);
        let before = self.tokens.len();
        self.tokens.retain(|t| t.id != id);
        self.tokens.len() != before
    }

    pub fn list(&self) -> &[ApiToken] {
        &self.tokens
    }
}

pub fn authenticate(
    creds: &mut Credentials,
    username: &str,
    password: &str,
    totp: &str,
    now_unix: u64,
) -> Result<(), AuthError> {
    // Constant-time compare plus a dummy hash on failure keep timing alike for every failure, and the length cap stops a huge password from burning CPU.
    let user_ok = bool::from(username.as_bytes().ct_eq(creds.username.as_bytes()));
    let password_ok = if user_ok && password.len() <= MAX_PASSWORD_BYTES {
        verify_password(password, &creds.password_hash)
    } else {
        dummy_verify();
        false
    };
    // The step is only committed once all three factors pass, so a wrong password cannot burn a valid code.
    let mut step = creds.totp_last_step;
    let totp_ok = totp::verify(&creds.totp_secret, totp, now_unix, &mut step);
    if user_ok & password_ok & totp_ok {
        creds.totp_last_step = step;
        Ok(())
    } else {
        Err(AuthError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const NOW: u64 = 1_700_000_000;

    fn password() -> &'static str {
        static PW: OnceLock<String> = OnceLock::new();
        PW.get_or_init(|| generate_password().expect("rng"))
    }

    fn wrong_password() -> &'static str {
        static PW: OnceLock<String> = OnceLock::new();
        PW.get_or_init(|| generate_password().expect("rng"))
    }

    fn creds() -> Credentials {
        Credentials {
            username: "admin".to_string(),
            password_hash: hash_password(password()).expect("hash"),
            totp_secret: SECRET.to_string(),
            totp_last_step: 0,
        }
    }

    fn code(t: u64) -> String {
        totp::code_at(SECRET, t).expect("code")
    }

    #[test]
    fn password_round_trip() {
        let hash = hash_password(password()).expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(password(), &hash));
        assert!(!verify_password("wrong password!!", &hash));
    }

    #[test]
    fn hashes_use_distinct_salts() {
        assert_ne!(
            hash_password(password()).expect("a"),
            hash_password(password()).expect("b")
        );
    }

    #[test]
    fn malformed_hash_never_verifies() {
        assert!(!verify_password(password(), ""));
        assert!(!verify_password(password(), "not a phc string"));
        assert!(!verify_password(
            password(),
            "$argon2id$v=19$m=64,t=1,p=1$bad"
        ));
    }

    #[test]
    fn weak_passwords_are_rejected() {
        assert_eq!(
            validate_password_strength("short"),
            Err(AuthError::Weak("password must be at least 12 characters"))
        );
        assert!(validate_password_strength(&"a".repeat(257)).is_err());
        assert!(validate_password_strength("exactly12chr").is_ok());
        assert!(validate_password_strength(&"a".repeat(256)).is_ok());
    }

    #[test]
    fn generated_password_has_expected_shape() {
        let pw = generate_password().expect("rng");
        assert_eq!(pw.len(), 24);
        assert!(pw.bytes().all(|b| PASSWORD_ALPHABET.contains(&b)));
        assert!(validate_password_strength(&pw).is_ok());
        assert_ne!(pw, generate_password().expect("rng"));
    }

    #[test]
    fn password_alphabet_has_no_ambiguous_characters() {
        for ch in b"0O1lI" {
            assert!(!PASSWORD_ALPHABET.contains(ch));
        }
    }

    #[test]
    fn usernames_are_validated() {
        assert!(validate_username("admin"));
        assert!(validate_username("a.b-c_9"));
        assert!(validate_username(&"a".repeat(32)));
        assert!(!validate_username("ab"));
        assert!(!validate_username(&"a".repeat(33)));
        assert!(!validate_username("Admin"));
        assert!(!validate_username("a b c"));
        assert!(!validate_username("adm\u{e9}n"));
    }

    fn argon_checks() -> usize {
        ARGON_CHECKS.with(std::cell::Cell::get)
    }

    const NOW_TS: &str = "2026-01-01T00:00:00Z";

    #[test]
    fn tokens_have_id_and_secret_parts() {
        let token = random_token().expect("rng");
        assert!(token.starts_with("cite_"));
        assert_eq!(token.len(), 5 + 16 + 1 + 64);
        assert_ne!(token, random_token().expect("rng"));
        let (id, secret) = parse_token(&token).expect("parses");
        assert_eq!(id.len(), 16);
        assert_eq!(secret.len(), 64);
    }

    #[test]
    fn parse_token_accepts_only_the_exact_shape() {
        let id = "0123456789abcdef";
        let secret = "0123456789abcdef".repeat(4);
        assert_eq!(
            parse_token(&format!("cite_{id}.{secret}")),
            Some((id, secret.as_str()))
        );
        let bad = [
            String::new(),
            "cite_".to_string(),
            format!("tok_{id}.{secret}"),
            format!("{id}.{secret}"),
            format!("cite_{id}{secret}"),
            format!("cite_{}.{secret}", &id[..15]),
            format!("cite_{id}0.{secret}"),
            format!("cite_{id}.{}", &secret[..63]),
            format!("cite_{id}.{secret}0"),
            format!("cite_{}.{secret}", id.to_uppercase()),
            format!("cite_{id}.{}", secret.to_uppercase()),
            format!("cite_{id}.{}.{}", &secret[..32], &secret[32..]),
            format!("cite_{id}..{}", &secret[..63]),
            format!("cite_{id}.{secret} "),
            format!("cite_{}g.{secret}", &id[..15]),
        ];
        for token in bad {
            assert!(parse_token(&token).is_none(), "{token:?}");
        }
    }

    #[test]
    fn session_validates_and_tracks_activity() {
        let mut store = SessionStore::new(100, 30);
        let (token, expires) = store.create("admin", 1000).expect("create");
        assert_eq!(expires, 1100);
        let info = store.validate(&token, 1010).expect("live");
        assert_eq!(info.username, "admin");
        assert_eq!(info.created, 1000);
        assert_eq!(info.last_seen, 1010);
        assert!(store.validate("cite_unknown", 1010).is_none());
    }

    #[test]
    fn session_tokens_are_not_derived_from_stored_values() {
        let mut store = SessionStore::new(100, 30);
        let opened = store.open("admin", 1000).expect("open");
        let (id, secret) = parse_token(&opened.token).expect("shape");
        assert_eq!(opened.csrf.len(), 64);
        assert!(is_lower_hex(&opened.csrf));
        assert_ne!(opened.csrf, secret);
        assert_ne!(opened.csrf, id);
        assert_eq!(
            store.validate(&opened.token, 1001).expect("live").csrf,
            opened.csrf
        );
    }

    #[test]
    fn session_debug_output_hides_secrets() {
        let mut store = SessionStore::new(100, 30);
        let opened = store.open("admin", 1000).expect("open");
        let (_, secret) = parse_token(&opened.token).expect("shape");
        let info = store.validate(&opened.token, 1001).expect("live");
        for shown in [format!("{opened:?}"), format!("{info:?}")] {
            assert!(!shown.contains(secret), "{shown}");
            assert!(!shown.contains(&opened.csrf), "{shown}");
            assert!(!shown.contains(&opened.token), "{shown}");
        }
        assert!(format!("{info:?}").contains("admin"));
    }

    #[test]
    fn session_csrf_differs_between_sessions() {
        let mut store = SessionStore::new(100, 30);
        let a = store.open("admin", 1000).expect("a");
        let b = store.open("admin", 1000).expect("b");
        assert_ne!(a.csrf, b.csrf);
    }

    #[test]
    fn session_with_wrong_secret_or_unknown_id_is_rejected_and_kept() {
        let mut store = SessionStore::new(100, 30);
        let (token, _) = store.create("admin", 1000).expect("create");
        let (id, secret) = parse_token(&token).expect("shape");
        let first = if secret.starts_with('0') { '1' } else { '0' };
        let flipped = format!("{first}{}", &secret[1..]);
        let forged = format!("cite_{id}.{flipped}");
        assert!(store.validate(&forged, 1001).is_none());
        store.revoke(&forged);
        assert!(store.validate(&token, 1002).is_some());
        let other = format!("cite_{}.{secret}", "f".repeat(16));
        assert!(store.validate(&other, 1002).is_none());
    }

    #[test]
    fn session_expires_at_ttl_even_when_active() {
        let mut store = SessionStore::new(100, 30);
        let (token, _) = store.create("admin", 1000).expect("create");
        for t in [1020, 1040, 1060, 1080] {
            assert!(store.validate(&token, t).is_some(), "t={t}");
        }
        assert!(store.validate(&token, 1100).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn session_expires_when_idle() {
        let mut store = SessionStore::new(1000, 30);
        let (token, _) = store.create("admin", 1000).expect("create");
        assert!(store.validate(&token, 1030).is_some());
        assert!(store.validate(&token, 1061).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn session_revoke_invalidates() {
        let mut store = SessionStore::new(100, 30);
        let (token, _) = store.create("admin", 1000).expect("create");
        store.revoke(&token);
        assert!(store.validate(&token, 1001).is_none());
    }

    #[test]
    fn session_sweep_drops_only_dead_sessions() {
        let mut store = SessionStore::new(100, 30);
        let (old, _) = store.create("a", 1000).expect("create");
        let (fresh, _) = store.create("b", 1090).expect("create");
        store.sweep(1095);
        assert_eq!(store.len(), 1);
        assert!(store.validate(&old, 1096).is_none());
        assert!(store.validate(&fresh, 1096).is_some());
    }

    #[test]
    fn session_store_is_bounded_and_evicts_oldest() {
        let mut store = SessionStore::new(1_000_000, 1_000_000);
        let (first, _) = store.create("u", 0).expect("create");
        let mut last = String::new();
        for i in 1..=MAX_SESSIONS as u64 + 5 {
            last = store.create("u", i).expect("create").0;
        }
        assert_eq!(store.len(), MAX_SESSIONS);
        assert!(store.validate(&first, 2000).is_none());
        assert!(store.validate(&last, 2000).is_some());
    }

    #[test]
    fn api_token_create_verify_revoke() {
        let mut tokens = ApiTokens::new();
        let (meta, plaintext) = tokens.create("ci").expect("create");
        let (id, secret) = parse_token(&plaintext).expect("shape");
        assert_eq!(meta.id, id);
        assert!(meta.hash.starts_with("$argon2id$"));
        assert!(verify_password(secret, &meta.hash));
        assert!(!meta.hash.contains(secret));
        let json = serde_json::to_string(&tokens).expect("json");
        assert!(!json.contains(secret));
        assert!(!json.contains(&plaintext));

        let hit = tokens.verify(&plaintext, NOW_TS).expect("match");
        assert_eq!(hit.id, meta.id);
        assert_eq!(hit.last_used_at.as_deref(), Some(NOW_TS));
        assert!(tokens.verify("cite_wrong", NOW_TS).is_none());

        assert!(tokens.revoke(&meta.id));
        assert!(!tokens.revoke(&meta.id));
        assert!(tokens.verify(&plaintext, NOW_TS).is_none());
        assert!(tokens.list().is_empty());
    }

    #[test]
    fn api_token_with_wrong_secret_fails_and_is_not_cached() {
        let mut tokens = ApiTokens::new();
        let (meta, _) = tokens.create("ci").expect("create");
        let wrong = join_token(&meta.id, &"0".repeat(64));
        let before = argon_checks();
        assert!(tokens.verify(&wrong, NOW_TS).is_none());
        assert!(tokens.verify(&wrong, NOW_TS).is_none());
        assert_eq!(argon_checks() - before, 2);
        assert!(tokens.list()[0].last_used_at.is_none());
    }

    #[test]
    fn verified_tokens_skip_argon2_until_revoked() {
        let mut tokens = ApiTokens::new();
        let (meta, plaintext) = tokens.create("ci").expect("create");
        let before = argon_checks();
        assert!(tokens.verify(&plaintext, NOW_TS).is_some());
        assert_eq!(argon_checks() - before, 1);
        let again = tokens
            .verify(&plaintext, "2026-02-02T00:00:00Z")
            .expect("hit");
        assert_eq!(again.last_used_at.as_deref(), Some("2026-02-02T00:00:00Z"));
        assert_eq!(argon_checks() - before, 1);

        assert!(tokens.revoke(&meta.id));
        assert!(tokens.verify(&plaintext, NOW_TS).is_none());
        assert_eq!(argon_checks() - before, 1);
    }

    #[test]
    fn cached_secret_does_not_admit_a_different_secret() {
        let mut tokens = ApiTokens::new();
        let (meta, plaintext) = tokens.create("ci").expect("create");
        assert!(tokens.verify(&plaintext, NOW_TS).is_some());
        let wrong = join_token(&meta.id, &"1".repeat(64));
        let before = argon_checks();
        assert!(tokens.verify(&wrong, NOW_TS).is_none());
        assert_eq!(argon_checks() - before, 1);
    }

    #[test]
    fn unknown_ids_and_malformed_tokens_never_reach_argon2() {
        let mut tokens = ApiTokens::new();
        let (_, plaintext) = tokens.create("ci").expect("create");
        let (_, secret) = parse_token(&plaintext).expect("shape");
        let before = argon_checks();
        assert!(tokens.verify("", NOW_TS).is_none());
        assert!(tokens.verify("garbage", NOW_TS).is_none());
        assert!(
            tokens
                .verify(&format!("cite_{}", "ab".repeat(32)), NOW_TS)
                .is_none()
        );
        assert!(
            tokens
                .verify(&join_token(&"e".repeat(16), secret), NOW_TS)
                .is_none()
        );
        assert_eq!(argon_checks(), before);
    }

    #[test]
    fn old_format_records_load_but_never_verify() {
        let old_plain = format!("cite_{}", "ab".repeat(32));
        let json = format!(
            r#"{{"tokens":[{{"id":"00112233445566ff","name":"legacy","hash":"{}","created_at":"2025-01-01T00:00:00Z","last_used_at":null}}]}}"#,
            "cd".repeat(32)
        );
        let mut tokens: ApiTokens = serde_json::from_str(&json).expect("loads");
        assert_eq!(tokens.list().len(), 1);
        assert!(tokens.verify(&old_plain, NOW_TS).is_none());
        let shaped = join_token("00112233445566ff", &"cd".repeat(32));
        assert!(tokens.verify(&shaped, NOW_TS).is_none());
        assert!(tokens.list()[0].last_used_at.is_none());
        assert!(tokens.revoke("00112233445566ff"));
    }

    #[test]
    fn completing_a_revoked_token_fails() {
        let mut tokens = ApiTokens::new();
        let (meta, plaintext) = tokens.create("ci").expect("create");
        let TokenLookup::Pending(pending) = tokens.begin_verify(&plaintext, NOW_TS) else {
            panic!("fresh token must need an argon2 check");
        };
        assert!(pending.check());
        assert!(tokens.revoke(&meta.id));
        assert!(tokens.complete(&pending, NOW_TS).is_none());
        assert!(matches!(
            tokens.begin_verify(&plaintext, NOW_TS),
            TokenLookup::Unknown
        ));
    }

    #[test]
    fn verified_cache_is_not_serialised_or_printed() {
        let mut tokens = ApiTokens::new();
        let (_, plaintext) = tokens.create("ci").expect("create");
        let (_, secret) = parse_token(&plaintext).expect("shape");
        assert!(tokens.verify(&plaintext, NOW_TS).is_some());
        assert!(
            !serde_json::to_string(&tokens)
                .expect("json")
                .contains(secret)
        );
        assert!(!format!("{tokens:?}").contains(secret));
        let json = serde_json::to_string(&tokens).expect("json");
        let mut reloaded: ApiTokens = serde_json::from_str(&json).expect("parse");
        let before = argon_checks();
        assert!(reloaded.verify(&plaintext, NOW_TS).is_some());
        assert_eq!(argon_checks() - before, 1);
    }

    #[test]
    fn verified_cache_stays_bounded() {
        let mut cache = VerifiedCache::default();
        for i in 0..MAX_API_TOKENS * 2 {
            cache.remember(&format!("id{i}"), "secret");
            assert!(cache.0.len() <= MAX_API_TOKENS);
        }
        assert!(cache.holds("id127", "secret"));
        assert!(!cache.holds("id127", "other"));
    }

    #[test]
    fn api_tokens_are_capped_at_64() {
        let mut tokens = ApiTokens::new();
        for i in 0..MAX_API_TOKENS {
            tokens.create(&format!("t{i}")).expect("create");
        }
        assert!(tokens.create("one too many").is_err());
        assert_eq!(tokens.list().len(), 64);
        let id = tokens.list()[0].id.clone();
        assert!(tokens.revoke(&id));
        assert!(tokens.create("fits again").is_ok());
    }

    #[test]
    fn authenticate_happy_path_records_step() {
        let mut c = creds();
        assert_eq!(
            authenticate(&mut c, "admin", password(), &code(NOW), NOW),
            Ok(())
        );
        assert_eq!(c.totp_last_step, NOW / 30);
    }

    #[test]
    fn every_failure_mode_gives_the_same_error() {
        let good = code(NOW);
        let attempts = [
            ("nobody", password(), good.as_str()),
            ("admin", wrong_password(), good.as_str()),
            ("admin", password(), "000000"),
            ("admin", password(), ""),
            ("nobody", wrong_password(), "000000"),
        ];
        for (user, pw, otp) in attempts {
            let mut c = creds();
            let before = c.totp_last_step;
            assert_eq!(
                authenticate(&mut c, user, pw, otp, NOW),
                Err(AuthError::Invalid)
            );
            assert_eq!(c.totp_last_step, before);
        }
    }

    #[test]
    fn authenticate_rejects_totp_replay() {
        let mut c = creds();
        let otp = code(NOW);
        assert!(authenticate(&mut c, "admin", password(), &otp, NOW).is_ok());
        assert_eq!(
            authenticate(&mut c, "admin", password(), &otp, NOW),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn wrong_password_does_not_burn_the_totp_code() {
        let mut c = creds();
        let otp = code(NOW);
        assert!(authenticate(&mut c, "admin", wrong_password(), &otp, NOW).is_err());
        assert!(authenticate(&mut c, "admin", password(), &otp, NOW).is_ok());
    }

    #[test]
    fn oversized_password_is_rejected() {
        let mut c = creds();
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert_eq!(
            authenticate(&mut c, "admin", &long, &code(NOW), NOW),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn credentials_debug_redacts_secrets() {
        let c = creds();
        let shown = format!("{c:?}");
        assert!(shown.contains("admin"));
        assert!(!shown.contains(SECRET));
        assert!(!shown.contains("argon2"));
    }

    #[test]
    fn credentials_serde_round_trip() {
        let c = creds();
        let json = serde_json::to_string(&c).expect("json");
        let back: Credentials = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.username, c.username);
        assert_eq!(back.password_hash, c.password_hash);
        assert_eq!(back.totp_secret, c.totp_secret);
    }
}
