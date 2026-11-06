use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::ClientError;

type Res<T> = std::result::Result<T, ClientError>;

pub const MAX_CERT_NAME_CHARS: usize = 64;
// The connector caps the whole JSON body at 128 KiB; the PEM text must leave room for escaping and field names.
pub const MAX_PEM_BYTES: usize = 100 * 1024;
const ID_CHARS: usize = 26;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub sans: Vec<String>,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
    #[serde(default)]
    pub days_left: i64,
    #[serde(default)]
    pub fingerprint_sha256: String,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub covers: Vec<String>,
    /// "api" for certificates uploaded through the API, "manual" for files placed on the node by hand (read-only, ids like `file:<name>`).
    #[serde(default = "default_source")]
    pub source: String,
    /// Set when the node could not read the certificate, for example an unreadable file.
    #[serde(default)]
    pub warning: Option<String>,
}

fn default_source() -> String {
    "api".to_string()
}

impl Default for CertificateInfo {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            subject: String::new(),
            sans: Vec::new(),
            issuer: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            days_left: 0,
            fingerprint_sha256: String::new(),
            key_type: String::new(),
            created_at: String::new(),
            covers: Vec::new(),
            source: default_source(),
            warning: None,
        }
    }
}

impl CertificateInfo {
    pub fn is_manual(&self) -> bool {
        self.source == "manual"
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateList {
    #[serde(default)]
    pub items: Vec<CertificateInfo>,
    #[serde(default)]
    pub https_port: Option<u16>,
    #[serde(default)]
    pub dir_ready: bool,
    #[serde(default)]
    pub uncovered_hosts: Vec<String>,
}

/// An uploaded or replaced certificate as the node returns it, with its optional advisory.
/// The advisory is the JSON key `warning`, which this struct reads before the flattened info does, so `certificate.warning` stays empty here.
/// It is decode-only, because serialising both would write the key twice.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CertificateSaved {
    #[serde(flatten)]
    pub certificate: CertificateInfo,
    #[serde(default)]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRanges {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub ranges: Vec<String>,
}

/// Carries a private key, so it has no Serialize, its Debug output redacts the key and the key is overwritten when it is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificateUpload {
    name: Option<String>,
    certificate: String,
    private_key: String,
}

impl fmt::Debug for CertificateUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateUpload")
            .field("name", &self.name)
            .field("certificate_bytes", &self.certificate.len())
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl CertificateUpload {
    /// A new certificate; the name is required by the node on create.
    pub fn new(
        name: impl Into<String>,
        certificate: impl Into<String>,
        private_key: impl Into<String>,
    ) -> Self {
        Self {
            name: Some(name.into()),
            certificate: certificate.into(),
            private_key: private_key.into(),
        }
    }

    /// New PEM material for an existing certificate, keeping its name.
    pub fn replacement(certificate: impl Into<String>, private_key: impl Into<String>) -> Self {
        Self {
            name: None,
            certificate: certificate.into(),
            private_key: private_key.into(),
        }
    }

    /// Renames the certificate as part of a replacement.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn validate(&self, require_name: bool) -> Res<()> {
        match &self.name {
            Some(name) => {
                validate_certificate_name(name)?;
            }
            None if require_name => return Err(invalid("certificate name must not be empty")),
            None => {}
        }
        validate_pem_size(&self.certificate, "certificate")?;
        validate_pem_size(&self.private_key, "private key")?;
        if self.certificate.len() + self.private_key.len() > MAX_PEM_BYTES {
            return Err(invalid(format!(
                "certificate and private key together are larger than {} KiB",
                MAX_PEM_BYTES / 1024
            )));
        }
        if !self.certificate.contains("-----BEGIN CERTIFICATE-----") {
            return Err(invalid("certificate must be PEM with a CERTIFICATE block"));
        }
        if !has_private_key_marker(&self.private_key) {
            return Err(invalid("private key must be PEM with a PRIVATE KEY block"));
        }
        Ok(())
    }

    // Serialised straight from the borrowed fields, so the key is never copied into a long-lived JSON value.
    pub(crate) fn body_json(&self) -> Res<Vec<u8>> {
        #[derive(Serialize)]
        struct Body<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<&'a str>,
            certificate: &'a str,
            private_key: &'a str,
        }
        serde_json::to_vec(&Body {
            name: self.name.as_deref(),
            certificate: &self.certificate,
            private_key: &self.private_key,
        })
        .map_err(|e| invalid(format!("cannot encode request: {e}")))
    }
}

impl Drop for CertificateUpload {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

fn has_private_key_marker(pem: &str) -> bool {
    pem.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-----BEGIN ") && line.ends_with("PRIVATE KEY-----")
    })
}

fn validate_pem_size(pem: &str, what: &str) -> Res<()> {
    if pem.trim().is_empty() {
        return Err(invalid(format!("{what} must not be empty")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

/// 1 to 64 characters from [A-Za-z0-9 ._-], starting with a letter or digit, without edge spaces
/// or `-----`, so a pasted PEM header can never be a name.
pub fn validate_certificate_name(name: &str) -> Res<&str> {
    if name.trim().is_empty() {
        return Err(invalid("certificate name must not be empty"));
    }
    if name.len() > MAX_CERT_NAME_CHARS {
        return Err(invalid("certificate name is too long"));
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(invalid(
            "certificate name must start with a letter or digit",
        ));
    }
    if name.ends_with(' ') {
        return Err(invalid("certificate name must not end with a space"));
    }
    if name.contains("-----") {
        return Err(invalid("certificate name must not contain -----"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'))
    {
        return Err(invalid("certificate name has unsupported characters"));
    }
    Ok(name)
}

/// Exactly the 26 uppercase ULID characters the connector issues, so an id can never be a path.
pub fn validate_certificate_id(id: &str) -> Res<&str> {
    let ok = id.len() == ID_CHARS && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'Z'));
    if ok {
        Ok(id)
    } else {
        Err(invalid(
            "certificate id must be 26 uppercase letters or digits",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Assembled at run time so no complete key block sits in the source
    fn pem(label: &[&str], body: &str) -> String {
        let name = label.join(" ");
        format!("-----BEGIN {name}-----\n{body}\n-----END {name}-----\n")
    }

    fn cert() -> String {
        pem(&["CERTIFICATE"], "AAAA")
    }

    fn key() -> String {
        pem(&["PRIVATE", "KEY"], "BBBB")
    }

    #[test]
    fn ids_are_26_character_ulids() {
        for ok in ["01JC9ZQ7M3X8V4N2B6T5R0WHYA", "00000000000000000000000000"] {
            assert_eq!(validate_certificate_id(ok).expect("valid"), ok);
        }
        let bad_ids = [
            "",
            "01JC9ZQ7M3X8V4N2B6T5R0WHY",
            "01JC9ZQ7M3X8V4N2B6T5R0WHYAA",
            "01jc9zq7m3x8v4n2b6t5r0whya",
            "0123456789abcdef0123456789",
            "0123456789abcdef0123456789abcdef",
            "../JC9ZQ7M3X8V4N2B6T5R0WHYA",
            "01JC9ZQ7M3X8V4N2B6T5R0WHY\n",
        ];
        for bad in bad_ids {
            assert!(
                matches!(validate_certificate_id(bad), Err(ClientError::Config(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn names_are_short_plain_labels() {
        let longest = "a".repeat(64);
        for ok in ["site.example.com", "My cert_2026-11", longest.as_str()] {
            assert!(validate_certificate_name(ok).is_ok(), "{ok:?}");
        }
        let long = "a".repeat(65);
        let bad_names = [
            "",
            "   ",
            "a/b",
            "a\n",
            "é",
            "a%20b",
            " lead",
            "trail ",
            ".dot",
            "-dash",
            "_under",
            "a-----b",
            "-----BEGIN CERTIFICATE-----",
            long.as_str(),
        ];
        for bad in bad_names {
            assert!(
                matches!(validate_certificate_name(bad), Err(ClientError::Config(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn uploads_check_markers_and_size_before_sending() {
        let (cert, key) = (cert(), key());
        CertificateUpload::new("main", &cert, &key)
            .validate(true)
            .expect("valid");
        let rsa = pem(&["RSA", "PRIVATE", "KEY"], "x");
        CertificateUpload::new("main", &cert, &rsa)
            .validate(true)
            .expect("rsa key");
        CertificateUpload::replacement(&cert, &key)
            .validate(false)
            .expect("replacement without a name");
        assert!(
            CertificateUpload::replacement(&cert, &key)
                .validate(true)
                .is_err()
        );
        let big = format!("{cert}{}", "A".repeat(MAX_PEM_BYTES));
        let half = format!("{cert}{}", "A".repeat(MAX_PEM_BYTES / 2));
        let half_key = format!("{key}{}", "B".repeat(MAX_PEM_BYTES / 2));
        let bad = [
            CertificateUpload::new("main", &half, &half_key),
            CertificateUpload::new("main", "", &key),
            CertificateUpload::new("main", "not pem", &key),
            CertificateUpload::new("main", &cert, &cert),
            CertificateUpload::new("main", &cert, ""),
            CertificateUpload::new("main", &big, &key),
            CertificateUpload::new("main", &cert, &big),
            CertificateUpload::new("bad/name", &cert, &key),
        ];
        for upload in &bad {
            assert!(
                matches!(upload.validate(true), Err(ClientError::Config(_))),
                "{upload:?}"
            );
        }
    }

    #[test]
    fn debug_never_prints_the_key_or_pem() {
        let upload = CertificateUpload::new("main", cert(), key());
        let shown = format!("{upload:?}");
        assert!(!shown.contains("BBBB") && !shown.contains("PRIVATE"));
        assert!(!shown.contains("AAAA"));
        assert!(shown.contains("[redacted]"));
    }

    #[test]
    fn bodies_carry_the_name_only_when_set() {
        let parse = |upload: &CertificateUpload| -> serde_json::Value {
            serde_json::from_slice(&upload.body_json().expect("body")).expect("json")
        };
        let (cert, key) = (cert(), key());
        let create = parse(&CertificateUpload::new("main", &cert, &key));
        assert_eq!(create["name"], "main");
        assert_eq!(create["certificate"], cert.as_str());
        assert!(create["private_key"] == key.as_str(), "key differs");
        let replace = parse(&CertificateUpload::replacement(&cert, &key));
        assert!(replace.get("name").is_none());
        assert_eq!(replace.as_object().expect("object").len(), 2);
        let renamed = parse(&CertificateUpload::replacement(&cert, &key).named("new"));
        assert_eq!(renamed["name"], "new");
    }

    #[test]
    fn clones_and_drops_keep_working_with_the_zeroizing_drop() {
        let upload = CertificateUpload::new("main", cert(), key());
        let copy = upload.clone();
        drop(upload);
        assert!(
            copy == CertificateUpload::new("main", cert(), key()),
            "copies differ"
        );
        copy.validate(true).expect("still valid");
    }

    #[test]
    fn saved_certificates_decode_with_and_without_a_warning() {
        let with: CertificateSaved = serde_json::from_str(
            r#"{"id":"01JC9ZQ7M3X8V4N2B6T5R0WHYA","name":"main","days_left":12,"covers":["a.com"],"warning":"expires soon"}"#,
        )
        .expect("saved");
        assert_eq!(with.certificate.days_left, 12);
        assert_eq!(with.warning.as_deref(), Some("expires soon"));
        let without: CertificateSaved =
            serde_json::from_str(r#"{"id":"01JC9ZQ7M3X8V4N2B6T5R0WHYA"}"#).expect("saved");
        assert_eq!(without.warning, None);
        let list: CertificateList =
            serde_json::from_str(r#"{"items":[],"https_port":null,"dir_ready":true}"#)
                .expect("list");
        assert!(list.dir_ready && list.https_port.is_none());
    }

    #[test]
    fn hand_placed_certificates_carry_a_source_and_a_warning() {
        let list: CertificateList = serde_json::from_str(
            r#"{"items":[
                {"id":"01JC9ZQ7M3X8V4N2B6T5R0WHYA","name":"api cert"},
                {"id":"file:legacy.pem","name":"legacy.pem","source":"manual","warning":"cannot read the file"}
            ]}"#,
        )
        .expect("list");
        assert_eq!(list.items[0].source, "api");
        assert!(!list.items[0].is_manual() && list.items[0].warning.is_none());
        assert!(list.items[1].is_manual());
        assert_eq!(
            list.items[1].warning.as_deref(),
            Some("cannot read the file")
        );
        assert_eq!(CertificateInfo::default().source, "api");
        let saved: CertificateSaved =
            serde_json::from_str(r#"{"id":"01JC9ZQ7M3X8V4N2B6T5R0WHYA","warning":"w"}"#)
                .expect("saved");
        assert_eq!(saved.warning.as_deref(), Some("w"));
        assert_eq!(saved.certificate.source, "api");
    }
}
