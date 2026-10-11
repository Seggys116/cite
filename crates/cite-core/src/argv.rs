use crate::error::{Error, Result};

const METACHAR: &[char] = &['|', '&', ';', '<', '>', '`', '$', '\n', '\r'];

/// Shell metacharacters are rejected so the executor never receives a shell string.
pub fn split_command(input: &str) -> Result<Vec<String>> {
    if input.len() > 2048 {
        return Err(Error::Config("start command longer than 2048 bytes".into()));
    }
    if input.contains('\0') {
        return Err(Error::Config("start command contains NUL".into()));
    }
    if input.chars().any(|c| METACHAR.contains(&c)) {
        return Err(Error::Config(
            "start command contains shell metacharacters; pass argv only".into(),
        ));
    }

    let mut args = Vec::new();
    let mut cur = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut any = false;

    while let Some(c) = chars.next() {
        any = true;
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        if in_double {
            if c == '\\' {
                match chars.next() {
                    Some(n @ ('\\' | '"' | '\'')) => cur.push(n),
                    Some(n) => {
                        cur.push('\\');
                        cur.push(n);
                    }
                    None => {
                        return Err(Error::Config("trailing backslash in start command".into()));
                    }
                }
                continue;
            }
            if c == '"' {
                in_double = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\\' => match chars.next() {
                Some(n) => cur.push(n),
                None => return Err(Error::Config("trailing backslash in start command".into())),
            },
            '\'' => in_single = true,
            '"' => in_double = true,
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    args.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if in_single || in_double {
        return Err(Error::Config("unterminated quote in start command".into()));
    }
    if !cur.is_empty() {
        args.push(cur);
    }
    if !any || args.is_empty() {
        return Err(Error::Config("start command is empty".into()));
    }
    for arg in &args {
        if arg.chars().any(|c| METACHAR.contains(&c) || c == '\0') {
            return Err(Error::Config("argv contains shell metacharacters".into()));
        }
    }
    Ok(args)
}

/// Reject package-manager argv. The executor image has no npm/pnpm/yarn.
pub fn validate_start_argv(argv: &[String]) -> Result<()> {
    if argv.is_empty() {
        return Err(Error::Config("start argv is empty".into()));
    }
    let argv0 = argv[0].as_str();
    if matches!(
        argv0,
        "npm" | "npx" | "pnpm" | "yarn" | "corepack" | "cargo" | "rustc"
    ) || argv0.ends_with("/npm")
        || argv0.ends_with("/npx")
        || argv0.ends_with("/pnpm")
        || argv0.ends_with("/yarn")
        || argv0.ends_with("/cargo")
        || argv0.ends_with("/rustc")
    {
        return Err(Error::Config(format!(
            "`{argv0}` cannot run in the executor; use node, bun, or a release binary"
        )));
    }
    Ok(())
}

/// Render argv back to a single command line. Round-trips through [`split_command`].
pub fn render_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if arg.is_empty()
                || arg
                    .chars()
                    .any(|c| c.is_whitespace() || c == '\'' || c == '"')
            {
                format!("'{}'", arg.replace('\'', "'\\''"))
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_plain_and_quotes() {
        assert_eq!(
            split_command("node server.js").unwrap(),
            vec!["node", "server.js"]
        );
        assert_eq!(
            split_command("node \"my server.js\"").unwrap(),
            vec!["node", "my server.js"]
        );
        assert_eq!(
            split_command("node 'my server.js'").unwrap(),
            vec!["node", "my server.js"]
        );
        assert_eq!(
            split_command(r"node server\ name.js").unwrap(),
            vec!["node", "server name.js"]
        );
        assert_eq!(
            split_command("react-router-serve build/server/index.js").unwrap(),
            vec!["react-router-serve", "build/server/index.js"]
        );
    }

    #[test]
    fn rejects_cargo_and_rustc() {
        for argv0 in ["cargo", "rustc", "/usr/bin/cargo", "bin/rustc"] {
            let err = validate_start_argv(&[argv0.into()]).unwrap_err();
            assert!(err.to_string().contains("cannot run"), "{argv0}: {err}");
        }
        assert!(validate_start_argv(&["bin/hello".into()]).is_ok());
    }

    #[test]
    fn rejects_shell() {
        for sample in [
            "node server.js && curl evil",
            "node $(whoami)",
            "node server.js | tee /tmp/x",
            "node server.js; id",
            "node server.js > /tmp/x",
            "node `id`",
            "node $HOME/x",
            "npm start",
        ] {
            if sample.starts_with("npm ") {
                let argv = split_command(sample).unwrap();
                assert!(validate_start_argv(&argv).is_err());
            } else {
                assert!(split_command(sample).is_err(), "{sample}");
            }
        }
    }

    proptest! {
        #[test]
        fn render_parse_roundtrip(argv in prop::collection::vec("[A-Za-z0-9_./:@+-]{1,24}", 1..6usize)) {
            let rendered = render_argv(&argv);
            let parsed = split_command(&rendered).unwrap();
            prop_assert_eq!(parsed.clone(), argv);
            for arg in &parsed {
                prop_assert!(!arg.chars().any(|c| "|;&<>`$".contains(c)));
            }
        }
    }
}
