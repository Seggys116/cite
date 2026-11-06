//! Wire types for site status, logs and build settings; reads are tolerant so nodes and clients of different versions interoperate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Slot;
use crate::validate::{ValidationError, invalid};

/// Features a node advertises so a client can hide controls the node cannot serve.
pub const CAPABILITIES: [&str; 13] = [
    "site-status",
    "site-logs",
    "source-build",
    "site-github-token",
    "site-build-env",
    "site-runtime-env",
    "deploy-async",
    "cert-generate",
    "cert-origin-ca",
    "cert-acme",
    "alerts",
    "forges",
    "analytics-filters",
];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteStatus {
    pub phase: String,
    pub error: Option<String>,
    pub active: Slot,
    pub operation: Option<OperationInfo>,
    pub last_failure: Option<LastFailure>,
    pub slots: Vec<SlotStatus>,
    pub settings_current: bool,
    pub checked_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OperationInfo {
    pub kind: String,
    pub slot: Option<Slot>,
    pub deploy_id: Option<String>,
    pub step: String,
    pub started_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LastFailure {
    pub at: String,
    pub slot: Option<Slot>,
    pub note: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SlotStatus {
    pub slot: Slot,
    pub container: String,
    pub health: String,
    pub restart_count: u32,
    pub exit_code: Option<i32>,
    pub oom_killed: bool,
    pub report: Option<ManagerReport>,
    pub haproxy: Option<String>,
    pub haproxy_check: Option<String>,
}

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ManagerReport {
    pub v: u32,
    pub phase: String,
    pub since: Option<String>,
    pub deploy: Option<DeployOutcome>,
    pub head_sha: Option<String>,
    pub live_sha: Option<String>,
    pub last_build_secs: Option<u64>,
    pub last_failed_sha: Option<String>,
    pub last_error: Option<String>,
    pub token: Option<String>,
    pub token_expires_at: Option<String>,
    pub detected: Option<serde_json::Value>,
    pub executor: Option<serde_json::Value>,
}

impl std::fmt::Debug for ManagerReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerReport")
            .field("v", &self.v)
            .field("phase", &self.phase)
            .field("since", &self.since)
            .field("deploy", &self.deploy)
            .field("head_sha", &self.head_sha)
            .field("live_sha", &self.live_sha)
            .field("last_build_secs", &self.last_build_secs)
            .field("last_failed_sha", &self.last_failed_sha)
            .field("last_error", &self.last_error)
            .field("token", &self.token.as_ref().map(|_| REDACTED))
            .field("token_expires_at", &self.token_expires_at)
            .field("detected", &self.detected)
            .field("executor", &self.executor)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DeployOutcome {
    pub id: String,
    pub result: String,
    pub sha: Option<String>,
    pub reason: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogLine {
    pub ts: Option<String>,
    pub stream: String,
    pub level: Option<String>,
    pub phase: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogsResponse {
    pub lines: Vec<LogLine>,
    pub cursor: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenStatus {
    pub source: String,
    pub site_token_set: bool,
    pub node_token_configured: bool,
    pub status: Option<String>,
    pub expires_at: Option<String>,
    pub verified: Option<bool>,
}

/// Names only: build variable values are write-only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildEnvNames {
    pub names: Vec<String>,
}

const REDACTED: &str = "<redacted>";
const MAX_ENV_KEYS: usize = 64;
const MAX_ENV_BYTES: usize = 12 * 1024;
const MAX_ENV_VALUE: usize = 4096;
const DENIED_ENV: [&str; 16] = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "NODE_OPTIONS",
    "NODE_EXTRA_CA_CERTS",
    "HOME",
    "PATH",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "PNPM_HOME",
    "NPM_CONFIG_PREFIX",
];
const DENIED_ENV_PREFIXES: [&str; 4] = ["XDG_", "GIT_", "NPM_CONFIG_", "CITE_"];
// The manager refuses these build names at startup, so they must never be stored; keep in step with cite-core RESERVED_BUILD_KEYS.
const RESERVED_BUILD_ENV: [&str; 39] = [
    "PATH",
    "HOME",
    "HOSTNAME",
    "TERM",
    "SHELL",
    "USER",
    "LOGNAME",
    "BASH_ENV",
    "ENV",
    "RUST_LOG",
    "NODE_VERSION",
    "YARN_VERSION",
    "TMPDIR",
    "TMP",
    "TEMP",
    "PNPM_HOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "NPM_CONFIG_CACHE",
    "NPM_CONFIG_STORE_DIR",
    "PNPM_CONFIG_STORE_DIR",
    "COREPACK_HOME",
    "COREPACK_ENABLE_DOWNLOAD_PROMPT",
    "BUN_INSTALL_CACHE_DIR",
    "YARN_CACHE_FOLDER",
    "YARN_GLOBAL_FOLDER",
    "YARN_ENABLE_GLOBAL_CACHE",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
];
const RESERVED_BUILD_ENV_PREFIXES: [&str; 5] = ["CITE_", "LD_", "DYLD_", "GIT_", "XDG_"];
/// Names the executor sets for the app itself; the proxy (EXECUTOR_OWN_KEYS) and the executor refuse them.
pub const EXECUTOR_OWN_ENV: [&str; 5] = ["PORT", "NODE_ENV", "HOST", "HOSTNAME", "NITRO_HOST"];

struct EnvRules {
    label: &'static str,
    denied: &'static [&'static str],
    prefixes: &'static [&'static str],
}

const BUILD_RULES: EnvRules = EnvRules {
    label: "build env",
    denied: &RESERVED_BUILD_ENV,
    prefixes: &RESERVED_BUILD_ENV_PREFIXES,
};

const RUNTIME_RULES: EnvRules = EnvRules {
    label: "runtime env",
    denied: &EXECUTOR_OWN_ENV,
    prefixes: &[],
};

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BuildEnvPatch {
    pub set: BTreeMap<String, String>,
    pub unset: Vec<String>,
}

impl std::fmt::Debug for BuildEnvPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden: BTreeMap<&String, &str> = self.set.keys().map(|k| (k, REDACTED)).collect();
        f.debug_struct("BuildEnvPatch")
            .field("set", &hidden)
            .field("unset", &self.unset)
            .finish()
    }
}

fn valid_env_name(k: &str) -> bool {
    let b = k.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

impl BuildEnvPatch {
    /// Rules for the build env the manager reads; errors name keys, never values.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.check(&BUILD_RULES)
    }

    /// Rules for the runtime env the executor reads, which also owns PORT, NODE_ENV and the host names.
    pub fn validate_runtime(&self) -> Result<(), ValidationError> {
        self.check(&RUNTIME_RULES)
    }

    fn check(&self, rules: &EnvRules) -> Result<(), ValidationError> {
        let label = rules.label;
        if self.set.len() > MAX_ENV_KEYS || self.unset.len() > MAX_ENV_KEYS {
            return invalid(format!("{label}: at most {MAX_ENV_KEYS} keys"));
        }
        for (k, v) in &self.set {
            if !valid_env_name(k) {
                return invalid(format!("{label}: {k:?} must match [A-Z_][A-Z0-9_]{{0,63}}"));
            }
            let upper = k.to_ascii_uppercase();
            let upper = upper.as_str();
            if DENIED_ENV.contains(&upper)
                || rules.denied.contains(&upper)
                || DENIED_ENV_PREFIXES
                    .iter()
                    .chain(rules.prefixes)
                    .any(|p| upper.starts_with(p))
            {
                return invalid(format!("{label}: {k} is reserved and cannot be set"));
            }
            if v.len() > MAX_ENV_VALUE || v.chars().any(char::is_control) {
                return invalid(format!(
                    "{label}: the value of {k} must be at most {MAX_ENV_VALUE} bytes without control characters"
                ));
            }
        }
        for k in &self.unset {
            if !valid_env_name(k) {
                return invalid(format!("{label}: {k:?} must match [A-Z_][A-Z0-9_]{{0,63}}"));
            }
            if self.set.contains_key(k) {
                return invalid(format!("{label}: {k} is both set and unset"));
            }
        }
        let size = serde_json::to_string(self).map_or(usize::MAX, |s| s.len());
        if size > MAX_ENV_BYTES {
            return invalid(format!("{label}: the change is larger than 12 KiB"));
        }
        Ok(())
    }
}
