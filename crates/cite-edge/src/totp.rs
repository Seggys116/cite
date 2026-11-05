use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::auth::AuthError;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECS: u64 = 30;
const SECRET_BYTES: usize = 20;

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buf >> bits) & 31) as usize]));
        }
        buf &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.trim_end_matches('=').bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

pub fn generate_secret() -> Result<String, AuthError> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Rng)?;
    Ok(base32_encode(&bytes))
}

fn hotp(key: &[u8], counter: u64) -> Option<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation: the low nibble of the last byte selects a 4-byte window.
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let word = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    Some(word % 1_000_000)
}

fn code_for_step(key: &[u8], step: u64) -> Option<String> {
    hotp(key, step).map(|n| format!("{n:06}"))
}

fn decode_key(secret_b32: &str) -> Option<Vec<u8>> {
    base32_decode(secret_b32).filter(|k| !k.is_empty())
}

pub fn code_at(secret_b32: &str, unix_secs: u64) -> Option<String> {
    let key = decode_key(secret_b32)?;
    code_for_step(&key, unix_secs / STEP_SECS)
}

pub fn verify(secret_b32: &str, code: &str, unix_secs: u64, last_used_step: &mut u64) -> bool {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(key) = decode_key(secret_b32) else {
        return false;
    };
    let current = unix_secs / STEP_SECS;
    let mut accepted: Option<u64> = None;
    // Every candidate is compared so timing does not reveal which step matched.
    for step in current.saturating_sub(1)..=current.saturating_add(1) {
        let Some(expected) = code_for_step(&key, step) else {
            return false;
        };
        let equal = bool::from(expected.as_bytes().ct_eq(code.as_bytes()));
        if equal && step > *last_used_step {
            accepted = Some(step);
        }
    }
    match accepted {
        Some(step) => {
            *last_used_step = step;
            true
        }
        None => false,
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let issuer = percent_encode(issuer);
    let account = percent_encode(account);
    let secret = percent_encode(secret_b32);
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}\
         &algorithm=SHA1&digits=6&period=30"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const RFC_KEY: &[u8] = b"12345678901234567890";

    fn rfc_secret() -> String {
        base32_encode(RFC_KEY)
    }

    #[test]
    fn rfc_key_encodes_to_known_base32() {
        assert_eq!(rfc_secret(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        // Last six digits of the published 8-digit values.
        let cases: [(u64, &str); 6] = [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ];
        for (time, expected) in cases {
            assert_eq!(
                code_at(&rfc_secret(), time).as_deref(),
                Some(expected),
                "t={time}"
            );
        }
    }

    #[test]
    fn code_at_rejects_bad_secret() {
        assert_eq!(code_at("not base32!", 59), None);
        assert_eq!(code_at("", 59), None);
    }

    #[test]
    fn base32_known_vectors() {
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI"), Some(b"foobar".to_vec()));
        assert_eq!(base32_decode("mzxw6ytboi="), Some(b"foobar".to_vec()));
    }

    #[test]
    fn base32_decode_rejects_invalid_characters() {
        assert_eq!(base32_decode("MZXW1"), None);
        assert_eq!(base32_decode("MZ XW"), None);
    }

    #[test]
    fn generated_secret_is_20_bytes_of_base32() {
        let secret = generate_secret().expect("rng");
        assert_eq!(secret.len(), 32);
        assert_eq!(base32_decode(&secret).map(|k| k.len()), Some(20));
        assert_ne!(secret, generate_secret().expect("rng"));
    }

    #[test]
    fn verify_accepts_current_code_and_records_step() {
        let mut last = 0;
        assert!(verify(&rfc_secret(), "287082", 59, &mut last));
        assert_eq!(last, 1);
    }

    #[test]
    fn verify_accepts_one_step_of_skew_either_way() {
        let secret = rfc_secret();
        let mut last = 0;
        assert!(verify(&secret, "287082", 59 + 30, &mut last));
        let mut last = 0;
        assert!(verify(&secret, "287082", 59 - 30, &mut last));
    }

    #[test]
    fn verify_rejects_two_steps_of_skew() {
        let mut last = 0;
        assert!(!verify(&rfc_secret(), "287082", 59 + 90, &mut last));
        assert_eq!(last, 0);
    }

    #[test]
    fn verify_rejects_replay_of_same_step() {
        let secret = rfc_secret();
        let mut last = 0;
        assert!(verify(&secret, "287082", 59, &mut last));
        assert!(!verify(&secret, "287082", 59, &mut last));
        assert!(!verify(&secret, "287082", 70, &mut last));
    }

    #[test]
    fn verify_rejects_older_step_after_newer_used() {
        let secret = rfc_secret();
        let newer = code_at(&secret, 1_000_030).expect("code");
        let older = code_at(&secret, 1_000_000).expect("code");
        let mut last = 0;
        assert!(verify(&secret, &newer, 1_000_030, &mut last));
        assert!(!verify(&secret, &older, 1_000_030, &mut last));
    }

    #[test]
    fn verify_rejects_malformed_codes() {
        let secret = rfc_secret();
        for code in [
            "",
            "28708",
            "2870822",
            "28708a",
            " 87082",
            "+87082",
            "٢٨٧٠٨٢",
        ] {
            let mut last = 0;
            assert!(!verify(&secret, code, 59, &mut last), "{code:?}");
        }
    }

    #[test]
    fn verify_rejects_wrong_code_without_touching_state() {
        let mut last = 7;
        assert!(!verify(&rfc_secret(), "000000", 59 + 30 * 10, &mut last));
        assert_eq!(last, 7);
    }

    #[test]
    fn verify_rejects_invalid_secret() {
        let mut last = 0;
        assert!(!verify("!!!!", "287082", 59, &mut last));
    }

    #[test]
    fn otpauth_uri_is_percent_encoded() {
        let uri = otpauth_uri("Cite Node", "admin@host", "ABC234");
        assert_eq!(
            uri,
            "otpauth://totp/Cite%20Node:admin%40host?secret=ABC234&issuer=Cite%20Node\
             &algorithm=SHA1&digits=6&period=30"
        );
    }

    proptest! {
        #[test]
        fn base32_round_trips(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let encoded = base32_encode(&data);
            prop_assert!(encoded.bytes().all(|b| ALPHABET.contains(&b)));
            prop_assert_eq!(base32_decode(&encoded), Some(data));
        }
    }
}
