use serde_json::Value;

use crate::strict;

const MAX_REL_PATH: usize = 255;
const MAX_COMMAND: usize = 1024;
const MAX_FRAMEWORK: usize = 32;
const DEPLOY_ID_LEN: usize = 26;
const MAX_BUILD_ENV_JSON: usize = 12 * 1024;
const MAX_BUILD_ENV_KEYS: usize = 64;
const MAX_BUILD_ENV_KEY: usize = 64;
const MAX_BUILD_ENV_VALUE: usize = 4096;

// Same set the start command parser in cite-core refuses everywhere, quoted or not.
const START_META: [char; 7] = ['|', '&', ';', '<', '>', '`', '$'];
const UNQUOTED_META: [char; 10] = ['(', ')', '{', '}', '*', '?', '~', '!', '#', '\\'];
const NOT_RUNNABLE: [&str; 10] = [
    "npm", "npx", "pnpm", "yarn", "corepack", "cargo", "rustc", "sh", "bash", "env",
];
const DENIED_KEYS: [&str; 15] = [
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
];
const DENIED_PREFIXES: [&str; 3] = ["XDG_", "GIT_", "NPM_CONFIG_"];

pub fn rel_path(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_REL_PATH
        && !v.starts_with('/')
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && !v.split('/').any(|segment| segment == "..")
}

pub fn slug(v: &str) -> bool {
    (1..=MAX_FRAMEWORK).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn boolean(v: &str) -> bool {
    v == "true" || v == "false"
}

pub fn deploy_id(v: &str) -> bool {
    v.len() == DEPLOY_ID_LEN
        && v.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

fn command_text(v: &str) -> bool {
    (1..=MAX_COMMAND).contains(&v.len()) && !v.chars().any(char::is_control)
}

pub fn shell_cmd(v: &str) -> bool {
    command_text(v)
}

// Splits the way cite-core does, then refuses what a shell would treat specially and the package managers.
pub fn start_cmd(v: &str) -> bool {
    if !command_text(v) || v.chars().any(|c| START_META.contains(&c)) {
        return false;
    }
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            Some(_) => match c {
                '"' => quote = None,
                '\\' => match chars.next() {
                    Some(n @ ('\\' | '"' | '\'')) => cur.push(n),
                    Some(n) => {
                        cur.push('\\');
                        cur.push(n);
                    }
                    None => return false,
                },
                c => cur.push(c),
            },
            None => match c {
                '\'' | '"' => quote = Some(c),
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        args.push(std::mem::take(&mut cur));
                    }
                }
                c if UNQUOTED_META.contains(&c) => return false,
                c => cur.push(c),
            },
        }
    }
    if quote.is_some() {
        return false;
    }
    if !cur.is_empty() {
        args.push(cur);
    }
    match args.first() {
        Some(argv0) => !NOT_RUNNABLE.contains(&argv0.rsplit('/').next().unwrap_or_default()),
        None => false,
    }
}

// Names the executor sets itself and refuses at startup, so the proxy must not let them through.
const EXECUTOR_OWN_KEYS: [&str; 5] = ["PORT", "NODE_ENV", "HOST", "HOSTNAME", "NITRO_HOST"];

// Copy of cite-core RESERVED_BUILD_KEYS and RESERVED_BUILD_PREFIXES: the manager refuses these build names at startup.
const RESERVED_BUILD_KEYS: [&str; 39] = [
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
const RESERVED_BUILD_PREFIXES: [&str; 4] = ["LD_", "DYLD_", "GIT_", "XDG_"];

fn build_env_key(key: &str, extra_denied: &[&str], extra_prefixes: &[&str]) -> bool {
    let b = key.as_bytes();
    if b.is_empty()
        || b.len() > MAX_BUILD_ENV_KEY
        || !(b[0].is_ascii_uppercase() || b[0] == b'_')
        || !b
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        || key.starts_with("CITE_")
    {
        return false;
    }
    let upper = key.to_ascii_uppercase();
    !DENIED_KEYS.contains(&upper.as_str())
        && !extra_denied.contains(&upper.as_str())
        && !DENIED_PREFIXES
            .iter()
            .chain(extra_prefixes)
            .any(|p| upper.starts_with(p))
}

pub fn build_env_json(v: &str) -> bool {
    env_json(v, &RESERVED_BUILD_KEYS, &RESERVED_BUILD_PREFIXES)
}

pub fn runtime_env_json(v: &str) -> bool {
    env_json(v, &EXECUTOR_OWN_KEYS, &[])
}

fn env_json(v: &str, extra_denied: &[&str], extra_prefixes: &[&str]) -> bool {
    if v.len() > MAX_BUILD_ENV_JSON || v.chars().any(char::is_control) {
        return false;
    }
    let Ok(Value::Object(map)) = strict::parse(v.as_bytes()) else {
        return false;
    };
    map.len() <= MAX_BUILD_ENV_KEYS
        && map.iter().all(|(key, value)| {
            build_env_key(key, extra_denied, extra_prefixes)
                && value.as_str().is_some_and(|s| {
                    s.len() <= MAX_BUILD_ENV_VALUE && !s.chars().any(char::is_control)
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_paths_are_plain_relative_paths() {
        for ok in [
            "dist",
            "apps/web/dist",
            ".",
            "./out",
            "a.b_c-d/e",
            "...",
            "x..y",
        ] {
            assert!(rel_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/",
            "/etc",
            "..",
            "../x",
            "a/../b",
            "a/..",
            "a b",
            "a\nb",
            "a\0b",
            "a\\b",
            "a;b",
            "$(id)",
            "`id`",
            "a'b",
            "a\"b",
            "dist/*",
            "~/x",
            "a:b",
            "\u{ff44}ist",
            "d\u{0456}st",
            "\u{2024}\u{2024}/x",
            "a\u{2215}b",
        ] {
            assert!(!rel_path(bad), "{bad:?}");
        }
        assert!(rel_path(&"a".repeat(255)));
        assert!(!rel_path(&"a".repeat(256)));
    }

    #[test]
    fn slugs_are_lowercase_alphanumerics_and_dashes() {
        for ok in ["next", "react-router", "a", "svelte-kit2"] {
            assert!(slug(ok), "{ok}");
        }
        for bad in [
            "",
            "Next",
            "a_b",
            "a b",
            "a/b",
            "re\u{0430}ct",
            "a\n",
            "x;y",
        ] {
            assert!(!slug(bad), "{bad:?}");
        }
        assert!(slug(&"a".repeat(32)));
        assert!(!slug(&"a".repeat(33)));
    }

    #[test]
    fn booleans_and_deploy_ids_are_exact() {
        assert!(boolean("true") && boolean("false"));
        for bad in ["", "True", "1", "yes", "true ", "true\n"] {
            assert!(!boolean(bad), "{bad:?}");
        }
        assert!(deploy_id("01HZX3K9M2N4P5Q6R7S8T9V0WX"));
        for bad in [
            "",
            "01HZX3K9M2N4P5Q6R7S8T9V0W",
            "01HZX3K9M2N4P5Q6R7S8T9V0WXY",
            "01hzx3k9m2n4p5q6r7s8t9v0wx",
            "01HZX3K9M2N4P5Q6R7S8T9V0W\n",
            "01HZX3K9M2N4P5Q6R7S8T9V0W-",
            "\u{ff10}\u{ff11}HZX3K9M2N4P5Q6R7S8T9V0W",
        ] {
            assert!(!deploy_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn shell_commands_allow_shell_syntax_but_no_control_characters() {
        for ok in [
            "npm ci",
            "pnpm install --frozen-lockfile && pnpm build",
            "echo \"a b\" | tee out",
            "echo caf\u{e9}",
        ] {
            assert!(shell_cmd(ok), "{ok}");
        }
        for bad in [
            "", "a\nb", "a\rb", "a\0b", "a\tb", "a\x1bb", "a\x7fb", "a\u{85}b",
        ] {
            assert!(!shell_cmd(bad), "{bad:?}");
        }
        assert!(shell_cmd(&"a".repeat(1024)));
        assert!(!shell_cmd(&"a".repeat(1025)));
    }

    #[test]
    fn start_commands_are_plain_argv() {
        for ok in [
            "node server.js",
            "node \"my server.js\"",
            "node 'my server.js'",
            "react-router-serve build/server/index.js",
            "./bin/app --port 8080",
            "node 'a(b)*?.js'",
            "node \"a#b\"",
            "node --flag=a=b",
            "bun run start.ts",
            "node server\u{ff1b}.js",
        ] {
            assert!(start_cmd(ok), "{ok}");
        }
        for bad in [
            "",
            "   ",
            "\"\"",
            "node server.js; id",
            "node server.js && id",
            "node a | b",
            "node a > b",
            "node a < b",
            "node `id`",
            "node $(id)",
            "node $HOME",
            "node \"$HOME\"",
            "node '$HOME'",
            "node (a)",
            "node {a,b}",
            "node *.js",
            "node a?",
            "node ~/x",
            "node !x",
            "node #x",
            "node a\\ b",
            "node a\nb",
            "node a\0b",
            "node \"unterminated",
            "node 'unterminated",
            "node \"a\\",
            "npm start",
            "npx serve",
            "pnpm start",
            "yarn start",
            "cargo run",
            "sh -c id",
            "bash -c id",
            "env FOO=1 node x.js",
            "/usr/bin/env node x.js",
            "/bin/sh x",
            "\"np\"m start",
            "'sh' -c id",
        ] {
            assert!(!start_cmd(bad), "{bad:?}");
        }
        assert!(start_cmd(&format!("node {}", "a".repeat(1019))));
        assert!(!start_cmd(&format!("node {}", "a".repeat(1020))));
    }

    #[test]
    fn build_env_keys_follow_the_pattern_and_deny_list() {
        for ok in ["A", "_X", "API_URL", "NEXT_PUBLIC_X1"] {
            assert!(build_env_key(ok, &[], &[]), "{ok}");
        }
        assert!(build_env_key(&"A".repeat(64), &[], &[]));
        for bad in [
            "",
            "1A",
            "a",
            "Api",
            "A-B",
            "A B",
            "A=B",
            "CITE_X",
            "CITE_",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "NODE_OPTIONS",
            "NODE_EXTRA_CA_CERTS",
            "HOME",
            "PATH",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "all_proxy",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "PNPM_HOME",
            "npm_config_registry",
            "NPM_CONFIG_REGISTRY",
            "\u{ff21}",
        ] {
            assert!(!build_env_key(bad, &[], &[]), "{bad:?}");
        }
        assert!(!build_env_key(&"A".repeat(65), &[], &[]));
    }

    #[test]
    fn build_env_json_refuses_the_managers_reserved_names_in_any_case() {
        for name in RESERVED_BUILD_KEYS {
            let text = format!("{{\"{name}\":\"x\"}}");
            assert!(!build_env_json(&text), "{name}");
        }
        for name in [
            "SHELL",
            "BASH_ENV",
            "NODE_PATH",
            "TMP",
            "CARGO_HOME",
            "LD_X",
            "DYLD_X",
        ] {
            assert!(!build_env_json(&format!("{{\"{name}\":\"x\"}}")), "{name}");
            let lower = name.to_ascii_lowercase();
            assert!(
                !build_env_json(&format!("{{\"{lower}\":\"x\"}}")),
                "{lower}"
            );
        }
        assert!(runtime_env_json("{\"SHELL\":\"x\",\"LD_X\":\"1\"}"));
    }

    #[test]
    fn runtime_env_json_also_refuses_the_names_the_executor_sets() {
        for name in ["PORT", "NODE_ENV", "HOST", "HOSTNAME", "NITRO_HOST"] {
            let text = format!("{{\"{name}\":\"x\"}}");
            assert!(!runtime_env_json(&text), "{name}");
        }
        for name in ["PORT", "NODE_ENV", "HOST", "NITRO_HOST"] {
            assert!(build_env_json(&format!("{{\"{name}\":\"x\"}}")), "{name}");
        }
        assert!(runtime_env_json("{\"API_URL\":\"x\",\"PORTAL\":\"y\"}"));
        assert!(!runtime_env_json("{\"LD_PRELOAD\":\"x\"}"));
        assert!(!runtime_env_json("{\"CITE_X\":\"x\"}"));
        assert!(!runtime_env_json("{\"A\":\"1\",\"A\":\"2\"}"));
        assert!(!runtime_env_json("{\"A\":\"nul\\u0000\"}"));
    }

    #[test]
    fn build_env_json_is_a_bounded_object_of_safe_strings() {
        for ok in [
            "{}",
            "{\"A\":\"1\"}",
            "{ \"A\": \"1\", \"B_2\": \"x y\" }",
            "{\"A\":\"caf\u{e9} \\\" \\\\ quote\"}",
        ] {
            assert!(build_env_json(ok), "{ok}");
        }
        for bad in [
            "",
            "[]",
            "null",
            "\"A\"",
            "{\"A\":1}",
            "{\"A\":null}",
            "{\"A\":[\"x\"]}",
            "{\"A\":{\"B\":\"x\"}}",
            "{\"A\":true}",
            "{\"a\":\"1\"}",
            "{\"CITE_X\":\"1\"}",
            "{\"LD_PRELOAD\":\"/x.so\"}",
            "{\"NODE_OPTIONS\":\"--require x\"}",
            "{\"GIT_SSH_COMMAND\":\"x\"}",
            "{\"A\":\"1\",\"A\":\"2\"}",
            "{\"A\":\"line\\nbreak\"}",
            "{\"A\":\"nul\\u0000byte\"}",
            "{\"A\":\"tab\\tchar\"}",
            "{\"A\":\"esc\\u001b\"}",
            "{\"A\":\"1\"}\n",
            "{\"A\":\"1\"} x",
            "{\"A\":\"1\"",
            "{\"A\\u0000\":\"1\"}",
        ] {
            assert!(!build_env_json(bad), "{bad:?}");
        }
        let value = |n: usize| format!("{{\"A\":\"{}\"}}", "x".repeat(n));
        assert!(build_env_json(&value(4096)));
        assert!(!build_env_json(&value(4097)));
        let keys = |n: usize| {
            let items: Vec<String> = (0..n).map(|i| format!("\"K{i}\":\"v\"")).collect();
            format!("{{{}}}", items.join(","))
        };
        assert!(build_env_json(&keys(64)));
        assert!(!build_env_json(&keys(65)));
    }

    #[test]
    fn build_env_json_size_limit_is_twelve_kib() {
        let of_size = |total: usize| {
            let rest = total - 8192 - 22;
            format!(
                "{{\"A\":\"{}\",\"B\":\"{}\",\"C\":\"{}\"}}",
                "x".repeat(4096),
                "y".repeat(4096),
                "z".repeat(rest)
            )
        };
        let exact = of_size(MAX_BUILD_ENV_JSON);
        assert_eq!(exact.len(), MAX_BUILD_ENV_JSON);
        assert!(build_env_json(&exact));
        let over = of_size(MAX_BUILD_ENV_JSON + 1);
        assert_eq!(over.len(), MAX_BUILD_ENV_JSON + 1);
        assert!(!build_env_json(&over));
    }
}
