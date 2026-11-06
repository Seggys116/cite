use std::collections::BTreeMap;
use std::fmt;

use cite_edge::status::BuildEnvPatch;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::ClientError;

type Res<T> = std::result::Result<T, ClientError>;

pub const MAX_GITHUB_TOKEN_BYTES: usize = 512;
// These mirror BuildEnvPatch::validate on the node, which the runtime environment shares.
pub const MAX_ENV_BYTES: usize = 12 * 1024;
pub const MAX_ENV_ENTRIES: usize = 64;
pub const MAX_ENV_NAME_CHARS: usize = 64;
pub const MAX_ENV_VALUE_BYTES: usize = 4096;
pub const MAX_LOG_TAIL: u32 = 1000;

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

/// A per-site GitHub token on its way to the node: wiped on drop, never printed.
#[derive(Serialize)]
pub struct GithubTokenBody {
    token: String,
}

impl GithubTokenBody {
    pub fn new(token: &str) -> Res<Self> {
        let t = token.trim();
        if t.is_empty() {
            return Err(invalid("the GitHub token is empty"));
        }
        if t.len() > MAX_GITHUB_TOKEN_BYTES || !t.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(invalid("the GitHub token is not a valid token"));
        }
        Ok(Self {
            token: t.to_string(),
        })
    }
}

impl fmt::Debug for GithubTokenBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubTokenBody")
            .field("token", &"[redacted]")
            .finish()
    }
}

impl Drop for GithubTokenBody {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Where a site's GitHub token comes from; the value is never reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenStatus {
    /// "site", "node" or "none".
    pub source: String,
    pub site_token_set: bool,
    pub node_token_configured: bool,
    pub status: Option<String>,
    pub expires_at: Option<String>,
    pub verified: Option<bool>,
}

/// Names of build or runtime variables; values are write-only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvNames {
    #[serde(default)]
    pub names: Vec<String>,
}

/// Variables to set and names to remove. Values are wiped on drop and never printed.
#[derive(Default, Serialize)]
pub struct EnvPatch {
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub unset: Vec<String>,
}

impl fmt::Debug for EnvPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvPatch")
            .field("set", &self.set.keys().collect::<Vec<_>>())
            .field("unset", &self.unset)
            .finish()
    }
}

impl Drop for EnvPatch {
    fn drop(&mut self) {
        for value in self.set.values_mut() {
            value.zeroize();
        }
    }
}

pub fn validate_env_name(name: &str) -> Res<&str> {
    let mut bytes = name.bytes();
    let first = bytes
        .next()
        .is_some_and(|b| b.is_ascii_uppercase() || b == b'_');
    let rest = bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if first && rest && name.len() <= MAX_ENV_NAME_CHARS {
        Ok(name)
    } else {
        Err(invalid(
            "a variable name is capital letters, digits and underscores, not starting with a digit, up to 64 characters",
        ))
    }
}

/// Which environment a patch is for; the node refuses a different set of names for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvKind {
    Build,
    Runtime,
}

impl EnvPatch {
    pub fn validate(&self, kind: EnvKind) -> Res<()> {
        if self.set.is_empty() && self.unset.is_empty() {
            return Err(invalid("nothing to change"));
        }
        if self.set.len() + self.unset.len() > MAX_ENV_ENTRIES {
            return Err(invalid(format!(
                "at most {MAX_ENV_ENTRIES} variables can change at once"
            )));
        }
        let mut total = 0;
        for (name, value) in &self.set {
            validate_env_name(name)?;
            if value.len() > MAX_ENV_VALUE_BYTES || value.chars().any(char::is_control) {
                return Err(invalid(format!("the value of {name} is not valid")));
            }
            total += name.len() + value.len();
        }
        for name in &self.unset {
            validate_env_name(name)?;
            if self.set.contains_key(name) {
                return Err(invalid(format!("{name} is both set and removed")));
            }
            total += name.len();
        }
        if total > MAX_ENV_BYTES {
            return Err(invalid("the change is too large"));
        }
        // The node's own rules decide which names are reserved, so the two cannot drift apart.
        let check = BuildEnvPatch {
            set: self.set.clone(),
            unset: self.unset.clone(),
        };
        let verdict = match kind {
            EnvKind::Build => check.validate(),
            EnvKind::Runtime => check.validate_runtime(),
        };
        verdict.map_err(|e| invalid(e.0))
    }
}

/// Which log stream to read and from where.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogsQuery {
    /// "manager" or "executor".
    pub source: String,
    pub slot: Option<String>,
    pub tail: Option<u32>,
    pub since: Option<String>,
}

impl LogsQuery {
    pub fn to_query(&self) -> Res<Vec<(&'static str, String)>> {
        if self.source != "manager" && self.source != "executor" {
            return Err(invalid("source is manager or executor"));
        }
        let mut out = vec![("source", self.source.clone())];
        if let Some(slot) = &self.slot {
            if slot != "blue" && slot != "green" {
                return Err(invalid("slot is blue or green"));
            }
            out.push(("slot", slot.clone()));
        }
        if let Some(tail) = self.tail {
            if tail == 0 || tail > MAX_LOG_TAIL {
                return Err(invalid(format!("tail is 1 to {MAX_LOG_TAIL}")));
            }
            out.push(("tail", tail.to_string()));
        }
        if let Some(since) = &self.since {
            if since.is_empty()
                || since.len() > 64
                || !since
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
            {
                return Err(invalid("since is a cursor from an earlier reply"));
            }
            out.push(("since", since.clone()));
        }
        Ok(out)
    }
}

/// The node's answer to a deploy that was not waited for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployAccepted {
    #[serde(default)]
    pub deployment_id: String,
}

/// Cloudflare API tokens used to issue origin certificates: wiped on drop, never printed.
#[derive(Serialize)]
pub struct CloudflareToken {
    cloudflare_token: String,
}

impl CloudflareToken {
    pub fn new(token: &str) -> Res<Self> {
        let t = token.trim();
        if t.is_empty() || t.len() > 512 || !t.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(invalid("the Cloudflare token is not a valid token"));
        }
        Ok(Self {
            cloudflare_token: t.to_string(),
        })
    }
}

impl fmt::Debug for CloudflareToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareToken")
            .field("cloudflare_token", &"[redacted]")
            .finish()
    }
}

impl Drop for CloudflareToken {
    fn drop(&mut self) {
        self.cloudflare_token.zeroize();
    }
}

/// An ACME job id is a short token from letters, digits, dash and underscore.
pub fn validate_job_id(id: &str) -> Res<&str> {
    if !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(id)
    } else {
        Err(invalid("not a valid job id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bodies_never_print_or_accept_junk() {
        let value = ["ghp", "_", "abcdef123456"].concat();
        let body = GithubTokenBody::new(&format!(" {value} ")).expect("valid");
        let shown = format!("{body:?}");
        assert!(!shown.contains(&value), "debug leaks");
        assert!(shown.contains("redacted"));
        for bad in ["", "   ", "has space", "tab\there", "\u{e9}"] {
            assert!(GithubTokenBody::new(bad).is_err(), "{bad:?}");
        }
        assert!(GithubTokenBody::new(&"a".repeat(513)).is_err());
        assert!(GithubTokenBody::new(&"a".repeat(512)).is_ok());
        let cf = CloudflareToken::new(&value).expect("valid");
        assert!(!format!("{cf:?}").contains(&value), "debug leaks");
        assert!(CloudflareToken::new("a b").is_err());
    }

    #[test]
    fn env_patches_are_checked_and_never_print_values() {
        let value = ["sec", "ret", "-value"].concat();
        let mut patch = EnvPatch::default();
        assert!(patch.validate(EnvKind::Build).is_err());
        patch.set.insert("API_KEY".into(), value.clone());
        patch.unset.push("OLD_ONE".into());
        patch.validate(EnvKind::Build).expect("valid");
        patch.validate(EnvKind::Runtime).expect("valid");
        assert!(!format!("{patch:?}").contains(&value), "debug leaks");
        assert!(format!("{patch:?}").contains("API_KEY"));
        let long = "A".repeat(65);
        for bad in ["", "1X", "A-B", "A B", "lower", long.as_str()] {
            assert!(validate_env_name(bad).is_err(), "{bad:?}");
        }
        for reserved in [
            "PATH",
            "NODE_OPTIONS",
            "GIT_DIR",
            "CITE_TOKEN",
            "NPM_CONFIG_X",
            "XDG_HOME",
        ] {
            let mut p = EnvPatch::default();
            p.set.insert(reserved.into(), "1".into());
            assert!(p.validate(EnvKind::Build).is_err(), "{reserved}");
            assert!(p.validate(EnvKind::Runtime).is_err(), "{reserved}");
        }
        for kind in [EnvKind::Build, EnvKind::Runtime] {
            let mut both = EnvPatch::default();
            both.set.insert("A".into(), "1".into());
            both.unset.push("A".into());
            assert!(both.validate(kind).is_err());
            let mut big = EnvPatch::default();
            big.set
                .insert("A".into(), "x".repeat(MAX_ENV_VALUE_BYTES + 1));
            assert!(big.validate(kind).is_err());
            let mut nul = EnvPatch::default();
            nul.set.insert("A".into(), "a\0b".into());
            assert!(nul.validate(kind).is_err());
            let mut many = EnvPatch::default();
            for i in 0..=MAX_ENV_ENTRIES {
                many.set.insert(format!("V{i}"), "1".into());
            }
            assert!(many.validate(kind).is_err());
        }
    }

    #[test]
    fn env_kinds_match_the_node_rules() {
        let names = [
            "API_KEY",
            "PORT",
            "NODE_ENV",
            "HOST",
            "HOSTNAME",
            "NITRO_HOST",
            "SHELL",
            "BASH_ENV",
            "NODE_PATH",
            "TMP",
            "CARGO_HOME",
            "LD_X",
            "DYLD_X",
            "GIT_X",
            "CITE_X",
            "PATH",
            "NODE_OPTIONS",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "YARN_CACHE_FOLDER",
            "COREPACK_HOME",
            "NPM_CONFIG_X",
            "RUST_LOG",
            "ENV",
            "USER",
            "TERM",
        ];
        for name in names {
            let mut patch = EnvPatch::default();
            patch.set.insert(name.into(), "1".into());
            let node = BuildEnvPatch {
                set: patch.set.clone(),
                unset: Vec::new(),
            };
            assert_eq!(
                patch.validate(EnvKind::Build).is_ok(),
                node.validate().is_ok(),
                "build {name}"
            );
            assert_eq!(
                patch.validate(EnvKind::Runtime).is_ok(),
                node.validate_runtime().is_ok(),
                "runtime {name}"
            );
        }
        let mut node_env = EnvPatch::default();
        node_env.set.insert("NODE_ENV".into(), "production".into());
        assert!(node_env.validate(EnvKind::Runtime).is_err());
        let mut shell = EnvPatch::default();
        shell.set.insert("SHELL".into(), "x".into());
        assert!(shell.validate(EnvKind::Build).is_err());
    }

    #[test]
    fn log_queries_are_checked() {
        let q = LogsQuery {
            source: "executor".into(),
            slot: Some("blue".into()),
            tail: Some(200),
            since: Some("c-17".into()),
        };
        assert_eq!(q.to_query().expect("valid").len(), 4);
        for bad in [
            LogsQuery {
                source: "x".into(),
                ..LogsQuery::default()
            },
            LogsQuery {
                source: "manager".into(),
                slot: Some("red".into()),
                ..LogsQuery::default()
            },
            LogsQuery {
                source: "manager".into(),
                tail: Some(0),
                ..LogsQuery::default()
            },
            LogsQuery {
                source: "manager".into(),
                tail: Some(MAX_LOG_TAIL + 1),
                ..LogsQuery::default()
            },
            LogsQuery {
                source: "manager".into(),
                since: Some("a b&x=1".into()),
                ..LogsQuery::default()
            },
        ] {
            assert!(bad.to_query().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn job_ids_and_status_decode() {
        assert!(validate_job_id("job_1-A").is_ok());
        let long = "a".repeat(65);
        for bad in ["", "../x", "a/b", long.as_str()] {
            assert!(validate_job_id(bad).is_err(), "{bad:?}");
        }
        let status: TokenStatus = serde_json::from_str(
            r#"{"source":"node","site_token_set":false,"node_token_configured":true,"verified":true,"extra":1}"#,
        )
        .expect("json");
        assert!(status.node_token_configured && !status.site_token_set);
        assert_eq!(status.source, "node");
        assert_eq!(
            serde_json::from_str::<TokenStatus>("{}").expect("json"),
            TokenStatus::default()
        );
    }
}
