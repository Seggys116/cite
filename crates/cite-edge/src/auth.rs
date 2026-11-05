use std::collections::HashMap;
use std::fmt;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::totp;

const MAX_SESSIONS: usize = 1024;
const MAX_API_TOKENS: usize = 64;
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 256;
const GENERATED_PASSWORD_CHARS: usize = 24;
const TOKEN_PREFIX: &str = "cite_";
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

pub fn random_token() -> Result<String, AuthError> {
    let bytes = random_bytes::<32>()?;
    Ok(format!("{TOKEN_PREFIX}{}", to_hex(&bytes)))
}

// Tokens carry 256 random bits, so a fast hash is enough to keep a leaked table from being usable as credentials.
pub fn hash_token(token: &str) -> String {
    let digest = Blake2b::<U32>::digest(token.as_bytes());
    to_hex(digest.as_slice())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Interactive,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub username: String,
    pub kind: SessionKind,
    pub created: u64,
    pub expires: u64,
    pub last_seen: u64,
}

pub struct SessionStore {
    ttl_secs: u64,
    idle_secs: u64,
    sessions: HashMap<String, SessionInfo>,
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
        let token = random_token()?;
        // At capacity dead sessions go first, then the oldest live one, so a login flood cannot grow the table without bound.
        if self.sessions.len() >= MAX_SESSIONS {
            self.sweep(now);
        }
        while self.sessions.len() >= MAX_SESSIONS {
            let oldest = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.created)
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
        };
        self.sessions.insert(hash_token(&token), info);
        Ok((token, expires))
    }

    pub fn validate(&mut self, token: &str, now: u64) -> Option<SessionInfo> {
        let key = hash_token(token);
        let live = self.is_live(self.sessions.get(&key)?, now);
        if !live {
            self.sessions.remove(&key);
            return None;
        }
        let info = self.sessions.get_mut(&key)?;
        info.last_seen = now;
        Some(info.clone())
    }

    pub fn revoke(&mut self, token: &str) {
        self.sessions.remove(&hash_token(token));
    }

    pub fn sweep(&mut self, now: u64) {
        let idle = self.idle_secs;
        self.sessions
            .retain(|_, s| now < s.expires && now.saturating_sub(s.last_seen) <= idle);
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiTokens {
    tokens: Vec<ApiToken>,
}

impl ApiTokens {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&mut self, name: &str) -> Result<(ApiToken, String), AuthError> {
        if self.tokens.len() >= MAX_API_TOKENS {
            return Err(AuthError::Weak("api token limit reached"));
        }
        let plaintext = random_token()?;
        let id = to_hex(&random_bytes::<8>()?);
        let created_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let token = ApiToken {
            id,
            name: name.to_string(),
            hash: hash_token(&plaintext),
            created_at,
            last_used_at: None,
        };
        self.tokens.push(token.clone());
        Ok((token, plaintext))
    }

    pub fn verify(&mut self, token: &str, now_rfc3339: &str) -> Option<&ApiToken> {
        let presented = hash_token(token);
        let mut found: Option<usize> = None;
        // Every stored hash is compared so the match position is not revealed by timing.
        for (i, stored) in self.tokens.iter().enumerate() {
            if bool::from(stored.hash.as_bytes().ct_eq(presented.as_bytes())) {
                found = Some(i);
            }
        }
        let entry = self.tokens.get_mut(found?)?;
        entry.last_used_at = Some(now_rfc3339.to_string());
        Some(&*entry)
    }

    pub fn revoke(&mut self, id: &str) -> bool {
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

    #[test]
    fn tokens_have_prefix_and_hash_to_blake2b_hex() {
        let token = random_token().expect("rng");
        assert!(token.starts_with("cite_"));
        assert_eq!(token.len(), 5 + 64);
        assert_ne!(token, random_token().expect("rng"));
        assert_eq!(
            hash_token("abc"),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
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
        assert!(plaintext.starts_with("cite_"));
        assert_eq!(meta.hash, hash_token(&plaintext));
        assert!(
            !serde_json::to_string(&tokens)
                .expect("json")
                .contains(&plaintext)
        );

        let hit = tokens
            .verify(&plaintext, "2026-01-01T00:00:00Z")
            .expect("match");
        assert_eq!(hit.id, meta.id);
        assert_eq!(hit.last_used_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert!(
            tokens
                .verify("cite_wrong", "2026-01-01T00:00:00Z")
                .is_none()
        );

        assert!(tokens.revoke(&meta.id));
        assert!(!tokens.revoke(&meta.id));
        assert!(tokens.verify(&plaintext, "2026-01-01T00:00:00Z").is_none());
        assert!(tokens.list().is_empty());
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
