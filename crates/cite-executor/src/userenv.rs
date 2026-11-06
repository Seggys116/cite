#![forbid(unsafe_code)]

//! The owner's runtime variables, handed over as one JSON object and merged into the SSR child only.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cite_core::{Error, Result};
use serde::Deserialize;
use serde::de::{Deserializer, MapAccess, Visitor};

pub const ENV_NAME: &str = "CITE_RUNTIME_ENV_JSON";
const MAX_JSON_BYTES: usize = 24 * 1024;
const MAX_KEYS: usize = 128;
const MAX_NAME_LEN: usize = 64;
const MAX_VALUE_BYTES: usize = 4096;
/// Names the child must not control: loader, TLS, proxy and home hooks, plus every key the supervisor sets itself.
const DENIED: [&str; 20] = [
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
    "PORT",
    "NODE_ENV",
    "HOST",
    "HOSTNAME",
    "NITRO_HOST",
];
const DENIED_PREFIXES: [&str; 4] = ["XDG_", "GIT_", "NPM_CONFIG_", "CITE_"];

/// Validated owner variables; the Debug output lists names only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UserEnv(BTreeMap<String, String>);

impl fmt::Debug for UserEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserEnv")
            .field("keys", &self.0.keys().collect::<Vec<_>>())
            .finish()
    }
}

struct Pairs(Vec<(String, String)>);

impl<'de> Deserialize<'de> for Pairs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct PairVisitor;
        impl<'de> Visitor<'de> for PairVisitor {
            type Value = Pairs;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object of string values")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Pairs, A::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, String>()? {
                    pairs.push(pair);
                }
                Ok(Pairs(pairs))
            }
        }
        deserializer.deserialize_map(PairVisitor)
    }
}

fn reject(why: &str) -> Error {
    Error::Config(format!("{ENV_NAME} rejected: {why}"))
}

fn name_denied(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    DENIED.contains(&upper.as_str()) || DENIED_PREFIXES.iter().any(|p| upper.starts_with(p))
}

fn name_shape_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_NAME_LEN
        && (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

impl UserEnv {
    /// Parses and validates the JSON; errors name the rule that failed and never echo a name or value.
    pub fn from_json(text: &str) -> Result<Self> {
        if text.len() > MAX_JSON_BYTES {
            return Err(reject("the document is larger than 24 KiB"));
        }
        let Pairs(pairs) = serde_json::from_str(text)
            .map_err(|_| reject("expected one JSON object whose values are all strings"))?;
        if pairs.len() > MAX_KEYS {
            return Err(reject("more than 128 variables"));
        }
        let mut seen = BTreeSet::new();
        let mut vars = BTreeMap::new();
        for (name, value) in pairs {
            if !name_shape_ok(&name) {
                return Err(reject("a variable name is not [A-Z_][A-Z0-9_]{0,63}"));
            }
            if name_denied(&name) {
                return Err(reject("a variable name is reserved"));
            }
            if !seen.insert(name.clone()) {
                return Err(reject("a variable name appears twice"));
            }
            if value.len() > MAX_VALUE_BYTES {
                return Err(reject("a value is longer than 4096 bytes"));
            }
            if value.chars().any(char::is_control) {
                return Err(reject("a value contains a control character"));
            }
            vars.insert(name, value);
        }
        Ok(Self(vars))
    }

    /// Reads the entry from the process environment; unset or blank means no variables.
    pub fn from_process_env() -> Result<Self> {
        match std::env::var(ENV_NAME) {
            Ok(text) if text.trim().is_empty() => Ok(Self::default()),
            Ok(text) => Self::from_json(&text),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => Err(reject("the value is not valid UTF-8")),
        }
    }

    pub fn vars(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    #[cfg(test)]
    pub fn unchecked(vars: BTreeMap<String, String>) -> Self {
        Self(vars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_text(text: &str) -> String {
        UserEnv::from_json(text).unwrap_err().to_string()
    }

    #[test]
    fn accepts_a_plain_object_and_the_empty_object() {
        let env = UserEnv::from_json(r#"{"API_URL":"https://x.test","_A1":"b c"}"#).unwrap();
        assert_eq!(env.vars().len(), 2);
        assert_eq!(env.vars()["API_URL"], "https://x.test");
        assert!(UserEnv::from_json("{}").unwrap().vars().is_empty());
    }

    #[test]
    fn rejects_every_denied_name_in_any_case() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "NODE_OPTIONS",
            "NODE_EXTRA_CA_CERTS",
            "HOME",
            "PATH",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "GIT_SSH_COMMAND",
            "PNPM_HOME",
            "NPM_CONFIG_REGISTRY",
            "PORT",
            "NODE_ENV",
            "HOST",
            "HOSTNAME",
            "NITRO_HOST",
            "CITE_ANYTHING",
        ] {
            let json = format!(r#"{{"{name}":"v"}}"#);
            assert!(UserEnv::from_json(&json).is_err(), "{name} was accepted");
        }
        assert!(name_denied("http_proxy"));
        assert!(name_denied("npm_config_registry"));
        assert!(name_denied("Ld_Preload"));
    }

    #[test]
    fn rejects_malformed_names_and_shapes() {
        for json in [
            r#"{"lower":"v"}"#,
            r#"{"1A":"v"}"#,
            r#"{"A-B":"v"}"#,
            r#"{"":"v"}"#,
            r#"[]"#,
            r#""text""#,
            r#"{"A":1}"#,
            r#"{"A":null}"#,
            r#"{"A":{"b":"c"}}"#,
            r#"{"A":"1","A":"2"}"#,
            "not json",
            "",
        ] {
            assert!(UserEnv::from_json(json).is_err(), "{json} was accepted");
        }
        let long = "A".repeat(65);
        assert!(UserEnv::from_json(&format!(r#"{{"{long}":"v"}}"#)).is_err());
        let edge = "A".repeat(64);
        assert!(UserEnv::from_json(&format!(r#"{{"{edge}":"v"}}"#)).is_ok());
    }

    #[test]
    fn enforces_the_size_and_count_limits() {
        let many = |n: usize| {
            let body: Vec<String> = (0..n).map(|i| format!(r#""K{i}":"v""#)).collect();
            format!("{{{}}}", body.join(","))
        };
        assert!(UserEnv::from_json(&many(128)).is_ok());
        assert!(UserEnv::from_json(&many(129)).is_err());

        let value = |n: usize| format!(r#"{{"A":"{}"}}"#, "x".repeat(n));
        assert!(UserEnv::from_json(&value(4096)).is_ok());
        assert!(UserEnv::from_json(&value(4097)).is_err());

        let padded = format!(r#"{{"A":"v"}}{}"#, " ".repeat(MAX_JSON_BYTES));
        assert!(UserEnv::from_json(&padded).is_err());
    }

    #[test]
    fn rejects_control_characters_in_values() {
        for escaped in [r"\n", r"\t", r"\u0000", r"\u007f", r"\r"] {
            let json = format!(r#"{{"A":"a{escaped}b"}}"#);
            assert!(UserEnv::from_json(&json).is_err(), "{escaped} was accepted");
        }
        assert!(UserEnv::from_json(r#"{"A":"café ✓"}"#).is_ok());
    }

    #[test]
    fn errors_and_debug_never_echo_names_or_values() {
        let secret = "hunter2-very-secret";
        for json in [
            format!(r#"{{"LD_PRELOAD":"{secret}"}}"#),
            format!(r#"{{"lower_{secret}":"v"}}"#),
            format!(r#"{{"A":"{secret}\n"}}"#),
            format!(r#"{{"A":"{}{secret}"}}"#, "x".repeat(5000)),
            format!(r#"{{"A":["{secret}"]}}"#),
            format!(r#"{{"A":7,"B":"{secret}"}}"#),
            format!(r#"{{"A":"{secret}","A":"{secret}"}}"#),
            format!("{secret} not json"),
        ] {
            let text = err_text(&json);
            assert!(!text.contains(secret), "{text}");
            assert!(!text.contains("LD_PRELOAD"), "{text}");
        }
        let ok = UserEnv::from_json(&format!(r#"{{"TOKEN":"{secret}"}}"#)).unwrap();
        let shown = format!("{ok:?}");
        assert!(
            shown.contains("TOKEN") && !shown.contains(secret),
            "{shown}"
        );
    }
}
