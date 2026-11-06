use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::ClientError;

type Res<T> = std::result::Result<T, ClientError>;

pub const MAX_DOPPLER_SLUG_CHARS: usize = 100;
pub const MAX_DOPPLER_TOKEN_BYTES: usize = 512;

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

/// Whether the node holds a Doppler token of its own, and where it came from; the token itself is never reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DopplerInfo {
    pub configured: bool,
    /// "env", "file" or "none".
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DopplerProject {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DopplerConfig {
    pub name: String,
    pub environment: String,
}

/// A site's Doppler binding and the state of its sync; values and tokens are never reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DopplerBinding {
    pub bound: bool,
    pub project: Option<String>,
    pub config: Option<String>,
    pub build: bool,
    pub runtime: bool,
    /// "site", "node" or "none".
    pub token_source: String,
    /// "synced", "syncing", "error" or "idle".
    pub status: String,
    pub last_sync_at: Option<String>,
    pub last_error: Option<String>,
    pub keys: u32,
}

/// Binds a site to a Doppler project and config. The token is wiped on drop and never printed.
#[derive(Serialize)]
pub struct DopplerBindRequest {
    pub project: String,
    pub config: String,
    pub build: bool,
    pub runtime: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl fmt::Debug for DopplerBindRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DopplerBindRequest")
            .field("project", &self.project)
            .field("config", &self.config)
            .field("build", &self.build)
            .field("runtime", &self.runtime)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl Drop for DopplerBindRequest {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_mut() {
            token.zeroize();
        }
    }
}

/// A Doppler project or config name: 1 to 100 of letters, digits, '.', '_' and '-'.
pub fn validate_doppler_slug(slug: &str) -> Res<&str> {
    let ok = (1..=MAX_DOPPLER_SLUG_CHARS).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(slug)
    } else {
        Err(invalid(
            "a Doppler project or config is 1 to 100 letters, digits, '.', '_' and '-'",
        ))
    }
}

impl DopplerBindRequest {
    pub fn validate(&self) -> Res<()> {
        validate_doppler_slug(&self.project)?;
        validate_doppler_slug(&self.config)?;
        if !self.build && !self.runtime {
            return Err(invalid(
                "choose the build variables, the runtime variables or both",
            ));
        }
        if let Some(token) = &self.token {
            let ok = !token.is_empty()
                && token.len() <= MAX_DOPPLER_TOKEN_BYTES
                && token.bytes().all(|b| (0x21..=0x7e).contains(&b));
            if !ok {
                return Err(invalid("the Doppler token is not a valid token"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(token: Option<&str>) -> DopplerBindRequest {
        DopplerBindRequest {
            project: "shop".into(),
            config: "prd".into(),
            build: true,
            runtime: false,
            token: token.map(str::to_string),
        }
    }

    #[test]
    fn bind_requests_are_checked_and_never_print_the_token() {
        let value = ["dp.st.", "prd.", "secretvalue"].concat();
        let req = request(Some(&value));
        req.validate().expect("valid");
        let shown = format!("{req:?}");
        assert!(shown.contains("shop") && !shown.contains("secretvalue"), "{shown}");
        let body = serde_json::to_value(&req).expect("json");
        assert_eq!(body["token"], value.as_str());
        let without = serde_json::to_value(request(None)).expect("json");
        assert!(without.get("token").is_none());
        request(None).validate().expect("the node token is used");
        for bad in ["", "has space", "caf\u{e9}"] {
            assert!(request(Some(bad)).validate().is_err(), "{bad:?}");
        }
        assert!(request(Some(&"a".repeat(513))).validate().is_err());
        let mut neither = request(None);
        neither.build = false;
        assert!(neither.validate().is_err());
    }

    #[test]
    fn slugs_are_checked_before_they_reach_a_path() {
        for ok in ["shop", "prd_personal", "a.b-c", &"a".repeat(100)] {
            assert!(validate_doppler_slug(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "a/b", "..%2F", "sh\u{f6}p", &"a".repeat(101)] {
            assert!(validate_doppler_slug(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn bindings_decode_tolerantly() {
        let empty: DopplerBinding = serde_json::from_str("{}").expect("empty");
        assert_eq!(empty, DopplerBinding::default());
        let full: DopplerBinding = serde_json::from_str(
            r#"{"bound":true,"project":"shop","config":"prd","build":true,"runtime":false,
                "token_source":"node","status":"synced","last_sync_at":"2026-11-06T10:00:00Z",
                "last_error":null,"keys":3,"redeploy_needed":false,"skipped":[]}"#,
        )
        .expect("full");
        assert!(full.bound && full.build && !full.runtime);
        assert_eq!(full.project.as_deref(), Some("shop"));
        assert_eq!((full.keys, full.status.as_str()), (3, "synced"));
        let info: DopplerInfo =
            serde_json::from_str(r#"{"configured":true,"source":"file","x":1}"#).expect("info");
        assert!(info.configured && info.source == "file");
        let project: DopplerProject = serde_json::from_str(r#"{"slug":"shop"}"#).expect("p");
        assert_eq!(project.name, "");
        let config: DopplerConfig = serde_json::from_str(r#"{"name":"prd"}"#).expect("c");
        assert_eq!(config.environment, "");
    }
}
