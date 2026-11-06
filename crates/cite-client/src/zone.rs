use std::fmt;

use serde::Deserialize;
use zeroize::Zeroize;

use crate::error::ClientError;

type Res<T> = std::result::Result<T, ClientError>;

const MAX_SITE_ID_CHARS: usize = 40;

/// Whether a site has a zone secret, and its public traits; the secret itself is never part of this.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ZoneSecretStatus {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// False when the node could not read its secret store at start, so `configured` is unknown. Older nodes omit it.
    #[serde(default = "default_readable")]
    pub readable: bool,
}

fn default_readable() -> bool {
    true
}

impl Default for ZoneSecretStatus {
    fn default() -> Self {
        Self {
            configured: false,
            header: String::new(),
            created_at: None,
            fingerprint: None,
            readable: true,
        }
    }
}

/// A freshly rotated secret. It is shown once, so Debug redacts it and Drop overwrites it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct ZoneSecret {
    secret: String,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl ZoneSecret {
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for ZoneSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneSecret")
            .field("secret", &"[redacted]")
            .field("header", &self.header)
            .field("created_at", &self.created_at)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl Drop for ZoneSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Same shape as the node's site ids, so an id can never be a path.
pub fn validate_site_id(id: &str) -> Res<&str> {
    let mut bytes = id.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if first_ok && rest_ok && id.len() <= MAX_SITE_ID_CHARS {
        Ok(id)
    } else {
        Err(ClientError::Config(
            "site id must be lowercase letters, digits and dashes, up to 40 characters".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_ids_match_the_node_shape() {
        let longest = "a".repeat(40);
        for ok in ["shop", "a", "0abc-9", longest.as_str()] {
            assert_eq!(validate_site_id(ok).expect("valid"), ok);
        }
        let long = "a".repeat(41);
        for bad in [
            "",
            "-a",
            "A",
            "a_b",
            "a/b",
            "..",
            "a b",
            "a\n",
            "é",
            long.as_str(),
        ] {
            assert!(
                matches!(validate_site_id(bad), Err(ClientError::Config(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn debug_never_prints_the_secret() {
        // Built at run time so no secret-looking literal sits in the source
        let value = "xyz".repeat(12);
        let json = format!(
            r#"{{"secret":"{value}","header":"X-Cite-Origin-Secret","created_at":"2026-11-06T10:00:00Z","fingerprint":"ab12"}}"#
        );
        let secret: ZoneSecret = serde_json::from_str(&json).expect("decode");
        assert!(secret.secret() == value, "values differ");
        let shown = format!("{secret:?}");
        assert!(!shown.contains(&value[..12]));
        assert!(shown.contains("[redacted]") && shown.contains("X-Cite-Origin-Secret"));
    }

    #[test]
    fn status_decodes_with_and_without_a_secret_configured() {
        let on: ZoneSecretStatus = serde_json::from_str(
            r#"{"configured":true,"header":"X-Cite-Origin-Secret","created_at":"2026-11-06T10:00:00Z","fingerprint":"ab12"}"#,
        )
        .expect("on");
        assert!(on.configured && on.fingerprint.as_deref() == Some("ab12"));
        let off: ZoneSecretStatus =
            serde_json::from_str(r#"{"configured":false,"header":"X-Cite-Origin-Secret","created_at":null,"fingerprint":null}"#)
                .expect("off");
        assert!(!off.configured && off.created_at.is_none());
        assert!(on.readable && off.readable, "older nodes omit readable");
    }

    #[test]
    fn an_unreadable_secret_store_is_reported() {
        let status: ZoneSecretStatus = serde_json::from_str(
            r#"{"configured":false,"header":"X-Cite-Origin-Secret","created_at":null,"fingerprint":null,"readable":false}"#,
        )
        .expect("status");
        assert!(!status.readable && !status.configured);
        assert!(ZoneSecretStatus::default().readable);
    }
}
