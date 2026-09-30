use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

static TOKEN_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"ghp_[A-Za-z0-9]{36}",
        r"gho_[A-Za-z0-9]{36}",
        r"ghu_[A-Za-z0-9]{36}",
        r"ghs_[A-Za-z0-9]{36}",
        r"ghr_[A-Za-z0-9]{36}",
        r"github_pat_[A-Za-z0-9_]{22,82}",
    ]
    .into_iter()
    .map(|p| Regex::new(p).expect("token regex"))
    .collect()
});

/// Redacts GitHub token shapes and exact secret values before a line is logged.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
        }
    }

    pub fn push_secret(&mut self, secret: impl Into<String>) {
        let secret = secret.into();
        if secret.len() >= 4 && !self.secrets.iter().any(|s| s == &secret) {
            self.secrets.push(secret);
            self.secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }

    pub fn redact_line(&self, line: &str) -> String {
        let mut out = line.to_string();
        for secret in &self.secrets {
            out = replace_bounded(&out, secret, "[REDACTED]");
        }
        redact_token_patterns(&out)
    }
}

pub fn redact_token_patterns(line: &str) -> String {
    let mut out = line.to_string();
    for re in TOKEN_RES.iter() {
        out = replace_regex_bounded(&out, re, "[REDACTED]");
    }
    out
}

/// Compare two secrets without short-circuiting on the first differing byte.
pub fn secrets_equal(a: &[u8], b: &[u8]) -> bool {
    let ha = Sha256::digest(a);
    let hb = Sha256::digest(b);
    bool::from(ha.ct_eq(hb.as_slice()))
}

fn replace_bounded(hay: &str, needle: &str, repl: &str) -> String {
    if needle.is_empty() {
        return hay.to_string();
    }
    let mut out = String::with_capacity(hay.len());
    let bytes = hay.as_bytes();
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) && bounded(bytes, i, i + needle.len()) {
            out.push_str(repl);
            i += needle.len();
        } else {
            let ch = hay[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn replace_regex_bounded(hay: &str, re: &Regex, repl: &str) -> String {
    let bytes = hay.as_bytes();
    let mut out = String::with_capacity(hay.len());
    let mut last = 0;
    for m in re.find_iter(hay) {
        if !bounded(bytes, m.start(), m.end()) {
            continue;
        }
        out.push_str(&hay[last..m.start()]);
        out.push_str(repl);
        last = m.end();
    }
    out.push_str(&hay[last..]);
    out
}

fn bounded(bytes: &[u8], start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            return false;
        }
    }
    if end < bytes.len() {
        let next = bytes[end];
        if next.is_ascii_alphanumeric() || next == b'_' {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat() -> String {
        format!("ghp_{}", "A".repeat(36))
    }

    #[test]
    fn redacts_token_shapes_and_exact_values() {
        let token = pat();
        let mut redactor = Redactor::new();
        redactor.push_secret("super-secret-value");
        let line = format!("using {token} and super-secret-value now");
        let got = redactor.redact_line(&line);
        assert!(!got.contains(&token));
        assert!(!got.contains("super-secret-value"));
        assert!(got.contains("[REDACTED]"));
    }

    #[test]
    fn does_not_eat_adjacent_identifiers() {
        let token = pat();
        let glued = format!("x{token}y");
        assert_eq!(redact_token_patterns(&glued), glued);
        let line = format!("pre {token} post");
        let got = redact_token_patterns(&line);
        assert_eq!(got, "pre [REDACTED] post");
    }

    #[test]
    fn multiline() {
        let mut redactor = Redactor::new();
        redactor.push_secret("build-env-secret");
        let text = "line one\nbuild-env-secret\nline three";
        let got = redactor.redact_line(text);
        assert!(got.starts_with("line one\n"));
        assert!(got.contains("[REDACTED]"));
        assert!(got.ends_with("line three"));
        assert!(!got.contains("build-env-secret"));
    }

    #[test]
    fn secrets_equal_is_exact() {
        assert!(secrets_equal(b"abc", b"abc"));
        assert!(!secrets_equal(b"abc", b"abd"));
        assert!(!secrets_equal(b"abc", b"abcd"));
    }
}
