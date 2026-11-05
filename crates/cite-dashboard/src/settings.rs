use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use cite_edge::allow::IpAllowlist;

use crate::error::{Error, Result};

pub const DEFAULT_CONFIG_PATH: &str = "/config/dashboard.json";
pub const DEFAULT_PORT: u16 = 8088;

const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 3600;
const MIN_SESSION_TTL_SECS: u64 = 60;
const MAX_SESSION_TTL_SECS: u64 = 30 * 86_400;
const IDLE_TIMEOUT_SECS: u64 = 3600;

#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub listen: Option<SocketAddr>,
    pub config_path: PathBuf,
    pub allow: Option<IpAllowlist>,
    pub tls: Option<TlsFiles>,
    pub cookie_secure: Option<bool>,
    pub session_ttl_secs: u64,
}

fn setup_err(msg: impl Into<String>) -> Error {
    Error::Setup(msg.into())
}

fn get<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(|v| v.trim()).filter(|v| !v.is_empty())
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(setup_err(format!("{key} must be true or false"))),
    }
}

impl Settings {
    pub fn from_process_env() -> Result<Self> {
        let env: HashMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .filter(|(k, _)| k.starts_with("CITE_DASHBOARD_"))
            .collect();
        Self::from_env_map(&env)
    }

    pub fn from_env_map(env: &HashMap<String, String>) -> Result<Self> {
        let listen = match get(env, "CITE_DASHBOARD_LISTEN") {
            Some(raw) => Some(raw.parse::<SocketAddr>().map_err(|_| {
                setup_err("CITE_DASHBOARD_LISTEN must be an ip:port socket address")
            })?),
            None => None,
        };
        let allow = match get(env, "CITE_DASHBOARD_ALLOW") {
            Some(raw) => Some(
                IpAllowlist::parse(raw)
                    .map_err(|e| setup_err(format!("CITE_DASHBOARD_ALLOW: {e}")))?,
            ),
            None => None,
        };
        let tls = match (
            get(env, "CITE_DASHBOARD_TLS_CERT"),
            get(env, "CITE_DASHBOARD_TLS_KEY"),
        ) {
            (Some(cert), Some(key)) => Some(TlsFiles {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
            }),
            (None, None) => None,
            _ => {
                return Err(setup_err(
                    "CITE_DASHBOARD_TLS_CERT and CITE_DASHBOARD_TLS_KEY must be set together",
                ));
            }
        };
        let cookie_secure = match get(env, "CITE_DASHBOARD_COOKIE_SECURE") {
            Some(raw) => Some(parse_bool("CITE_DASHBOARD_COOKIE_SECURE", raw)?),
            None => None,
        };
        let session_ttl_secs = match get(env, "CITE_DASHBOARD_SESSION_TTL") {
            Some(raw) => {
                let secs: u64 = raw.parse().map_err(|_| {
                    setup_err("CITE_DASHBOARD_SESSION_TTL must be a number of seconds")
                })?;
                if !(MIN_SESSION_TTL_SECS..=MAX_SESSION_TTL_SECS).contains(&secs) {
                    return Err(setup_err(format!(
                        "CITE_DASHBOARD_SESSION_TTL must be between {MIN_SESSION_TTL_SECS} and {MAX_SESSION_TTL_SECS} seconds"
                    )));
                }
                secs
            }
            None => DEFAULT_SESSION_TTL_SECS,
        };
        Ok(Self {
            listen,
            config_path: PathBuf::from(
                get(env, "CITE_DASHBOARD_CONFIG").unwrap_or(DEFAULT_CONFIG_PATH),
            ),
            allow,
            tls,
            cookie_secure,
            session_ttl_secs,
        })
    }

    // Plain-http listeners drop the Secure attribute so browsers keep the cookie on http://localhost.
    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure.unwrap_or(self.tls.is_some())
    }

    // Sessions idle out after an hour at most, even when the absolute lifetime is longer.
    pub fn idle_timeout_secs(&self) -> u64 {
        self.session_ttl_secs.min(IDLE_TIMEOUT_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn defaults_apply_with_an_empty_environment() {
        let s = Settings::from_env_map(&HashMap::new()).expect("settings");
        assert_eq!(s.listen, None);
        assert_eq!(s.config_path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert!(s.allow.is_none());
        assert!(s.tls.is_none());
        assert!(!s.cookie_secure());
        assert_eq!(s.session_ttl_secs, 8 * 3600);
        assert_eq!(s.idle_timeout_secs(), 3600);
    }

    #[test]
    fn overrides_are_honoured() {
        let s = Settings::from_env_map(&env(&[
            ("CITE_DASHBOARD_LISTEN", "127.0.0.1:9000"),
            ("CITE_DASHBOARD_CONFIG", "/tmp/d.json"),
            ("CITE_DASHBOARD_ALLOW", "10.0.0.0/8"),
            ("CITE_DASHBOARD_TLS_CERT", "/c.pem"),
            ("CITE_DASHBOARD_TLS_KEY", "/k.pem"),
            ("CITE_DASHBOARD_SESSION_TTL", "600"),
        ]))
        .expect("settings");
        assert_eq!(s.listen, Some("127.0.0.1:9000".parse().expect("addr")));
        assert!(s.allow.is_some());
        assert!(s.cookie_secure());
        assert_eq!(s.idle_timeout_secs(), 600);
    }

    #[test]
    fn cookie_secure_override_wins_over_tls() {
        let off = Settings::from_env_map(&env(&[
            ("CITE_DASHBOARD_TLS_CERT", "/c.pem"),
            ("CITE_DASHBOARD_TLS_KEY", "/k.pem"),
            ("CITE_DASHBOARD_COOKIE_SECURE", "false"),
        ]))
        .expect("settings");
        assert!(!off.cookie_secure());
        let on = Settings::from_env_map(&env(&[("CITE_DASHBOARD_COOKIE_SECURE", "1")]))
            .expect("settings");
        assert!(on.cookie_secure());
    }

    #[test]
    fn malformed_values_are_rejected() {
        for (key, value) in [
            ("CITE_DASHBOARD_LISTEN", "8088"),
            ("CITE_DASHBOARD_ALLOW", "not-an-ip"),
            ("CITE_DASHBOARD_TLS_CERT", "/only-cert.pem"),
            ("CITE_DASHBOARD_COOKIE_SECURE", "maybe"),
            ("CITE_DASHBOARD_SESSION_TTL", "5"),
            ("CITE_DASHBOARD_SESSION_TTL", "abc"),
        ] {
            assert!(
                Settings::from_env_map(&env(&[(key, value)])).is_err(),
                "{key}={value}"
            );
        }
    }
}
