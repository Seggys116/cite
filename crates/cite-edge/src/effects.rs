// Redirect target templates are parsed once for validation and again for rendering, so both agree on what each placeholder means.
pub(crate) const MAX_TEMPLATE_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Piece {
    Lit(String),
    Scheme,
    Host,
    WwwHost,
    ApexHost,
    Path,
    Query,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Relative,
    Absolute {
        https: bool,
        // the host part is built from the requested host, so the redirect stays on this edge
        own_host: bool,
        // the host part is exactly {host}
        same_host: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    pub pieces: Vec<Piece>,
    pub target: Target,
}

impl Template {
    pub fn uses_www(&self) -> bool {
        self.pieces.contains(&Piece::WwwHost)
    }

    pub fn uses_apex(&self) -> bool {
        self.pieces.contains(&Piece::ApexHost)
    }

    // An upgrade to this edge's own HTTPS listener is pointless without one and wrong behind Flexible SSL.
    pub fn is_own_https(&self) -> bool {
        matches!(
            self.target,
            Target::Absolute {
                https: true,
                own_host: true,
                ..
            }
        )
    }
}

fn unsafe_char(c: char) -> bool {
    !c.is_ascii_graphic() || matches!(c, '"' | '\'' | '\\' | '#' | '$' | '`' | '<' | '>')
}

fn split_pieces(to: &str) -> Result<Vec<Piece>, String> {
    let mut pieces = Vec::new();
    let mut lit = String::new();
    let mut rest = to;
    while let Some(i) = rest.find(['{', '}']) {
        let (head, tail) = rest.split_at(i);
        lit.push_str(head);
        if tail.starts_with('}') {
            return Err("unmatched }".to_string());
        }
        let Some(end) = tail.find('}') else {
            return Err("unclosed {".to_string());
        };
        let piece = match &tail[1..end] {
            "scheme" => Piece::Scheme,
            "host" => Piece::Host,
            "www_host" => Piece::WwwHost,
            "apex_host" => Piece::ApexHost,
            "path" => Piece::Path,
            "query" => Piece::Query,
            other => {
                return Err(format!(
                    "unknown placeholder {{{other}}}; use {{scheme}} {{host}} {{www_host}} {{apex_host}} {{path}} {{query}}"
                ));
            }
        };
        if !lit.is_empty() {
            pieces.push(Piece::Lit(std::mem::take(&mut lit)));
        }
        pieces.push(piece);
        rest = &tail[end + 1..];
    }
    lit.push_str(rest);
    if !lit.is_empty() {
        pieces.push(Piece::Lit(lit));
    }
    Ok(pieces)
}

const SHAPE: &str = "must be an absolute http or https URL or a path starting with /";

// Splits "scheme://" off the front; returns whether it was https and the pieces that follow.
fn strip_scheme(pieces: &[Piece]) -> Result<(bool, Vec<Piece>), String> {
    let with_tail = |tail: &str, more: &[Piece]| {
        let mut after = Vec::new();
        if !tail.is_empty() {
            after.push(Piece::Lit(tail.to_string()));
        }
        after.extend(more.iter().cloned());
        after
    };
    match pieces {
        [Piece::Lit(l), more @ ..] if l.starts_with("https://") => {
            Ok((true, with_tail(&l["https://".len()..], more)))
        }
        [Piece::Lit(l), more @ ..] if l.starts_with("http://") => {
            Ok((false, with_tail(&l["http://".len()..], more)))
        }
        [Piece::Scheme, Piece::Lit(l), more @ ..] if l.starts_with("://") => {
            Ok((false, with_tail(&l["://".len()..], more)))
        }
        _ => Err(SHAPE.to_string()),
    }
}

// The host part ends at the first literal / or ?, or where {path} or {query} begins; only host-safe characters may appear in it.
fn authority(after: &[Piece]) -> Result<Vec<Piece>, String> {
    let mut out = Vec::new();
    for piece in after {
        match piece {
            Piece::Lit(l) => {
                let cut = l.find(['/', '?']);
                let host = &l[..cut.unwrap_or(l.len())];
                if !host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b':'))
                {
                    return Err(
                        "the host part may contain only letters, digits, . - and :".to_string()
                    );
                }
                if !host.is_empty() {
                    out.push(Piece::Lit(host.to_string()));
                }
                if cut.is_some() {
                    break;
                }
            }
            Piece::Host | Piece::WwwHost | Piece::ApexHost => out.push(piece.clone()),
            Piece::Path | Piece::Query => break,
            Piece::Scheme => return Err("{scheme} can only start the URL".to_string()),
        }
    }
    if out.is_empty() {
        return Err("the URL has no host".to_string());
    }
    Ok(out)
}

fn classify(pieces: &[Piece]) -> Result<Target, String> {
    if let Some(Piece::Lit(l)) = pieces.first()
        && l.starts_with('/')
    {
        // // would be read as a protocol-relative URL, and a leading / before {path} makes one
        let doubled = l.starts_with("//") || (l == "/" && pieces.get(1) == Some(&Piece::Path));
        if doubled {
            return Err("a path target must not start with // or /{path}".to_string());
        }
        return Ok(Target::Relative);
    }
    let (https, after) = strip_scheme(pieces)?;
    let host = authority(&after)?;
    Ok(Target::Absolute {
        https,
        own_host: host
            .iter()
            .any(|p| matches!(p, Piece::Host | Piece::WwwHost | Piece::ApexHost)),
        same_host: host == [Piece::Host],
    })
}

pub(crate) fn parse_template(to: &str) -> Result<Template, String> {
    if to.is_empty() || to.len() > MAX_TEMPLATE_LEN {
        return Err(format!("must be 1 to {MAX_TEMPLATE_LEN} characters"));
    }
    if let Some(c) = to.chars().find(|c| unsafe_char(*c)) {
        return Err(format!(
            "character {c:?} is not allowed (no spaces, control characters, quotes, backslash, # or $)"
        ));
    }
    let pieces = split_pieces(to)?;
    let target = classify(&pieces)?;
    let identity = matches!(
        pieces.as_slice(),
        [Piece::Scheme, Piece::Lit(l), Piece::Host, Piece::Path]
            | [Piece::Scheme, Piece::Lit(l), Piece::Host, Piece::Path, Piece::Query]
            if l.as_str() == "://"
    );
    if identity {
        return Err("redirects every request to the URL it asked for".to_string());
    }
    if pieces.contains(&Piece::WwwHost) && pieces.contains(&Piece::ApexHost) {
        return Err("cannot use {www_host} and {apex_host} together".to_string());
    }
    Ok(Template { pieces, target })
}

// Each placeholder becomes one HAProxy log-format expression; a literal % is doubled so request data can never be read as a format.
pub(crate) fn render_location(pieces: &[Piece]) -> String {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            Piece::Lit(l) => out.push_str(&l.replace('%', "%%")),
            Piece::Scheme => out.push_str("%[req.fhdr(x-forwarded-proto)]"),
            Piece::Host => out.push_str("%[req.fhdr(host),lower]"),
            Piece::WwwHost => out.push_str("www.%[req.fhdr(host),lower]"),
            Piece::ApexHost => out.push_str("%[req.fhdr(host),lower,regsub(^www[.],,i)]"),
            Piece::Path => out.push_str("%[path]"),
            Piece::Query => out.push_str("%[url,regsub(^[^?]*,,i)]"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(to: &str) -> Template {
        parse_template(to).unwrap_or_else(|e| panic!("{to}: {e}"))
    }

    #[test]
    fn accepts_absolute_urls_and_paths() {
        for to in [
            "https://example.com/",
            "http://example.com",
            "https://example.com:8443/x?y=1",
            "{scheme}://{www_host}{path}{query}",
            "{scheme}://{apex_host}{path}{query}",
            "https://{host}{path}{query}",
            "https://www.{host}/home",
            "/new",
            "/new/{path}",
            "/a%20b",
        ] {
            ok(to);
        }
    }

    #[test]
    fn rejects_injection_and_unsafe_shapes() {
        for to in [
            "",
            "javascript:alert(1)",
            "data:text/html,x",
            "//evil.example.com/x",
            "/{path}",
            "relative/path",
            "ftp://example.com/",
            "HTTP://example.com/",
            "https://exam ple.com/",
            "https://example.com/a\r\nSet-Cookie: x=1",
            "https://example.com/a\nb",
            "https://example.com/\"",
            "https://example.com/'",
            "https://example.com/\\x",
            "https://example.com/#frag",
            "https://example.com/$HOME",
            "https://example.com/`id`",
            "https://user@example.com/",
            "https:///x",
            "https://{path}",
            "https://{host}x{scheme}/",
            "{scheme}/{host}",
            "{host}",
            "{scheme}://{host}{path}",
            "{scheme}://{host}{path}{query}",
            "https://{www_host}{apex_host}/",
        ] {
            assert!(parse_template(to).is_err(), "{to:?} accepted");
        }
        assert!(parse_template(&format!("/{}", "a".repeat(MAX_TEMPLATE_LEN))).is_err());
        assert!(parse_template(&format!("/{}", "a".repeat(MAX_TEMPLATE_LEN - 1))).is_ok());
    }

    #[test]
    fn rejects_unknown_and_unbalanced_placeholders() {
        for to in [
            "https://example.com/{nope}",
            "https://example.com/{HOST}",
            "https://example.com/{{host}}",
            "https://example.com/{host",
            "https://example.com/host}",
            "https://example.com/{}",
            "https://example.com/{ host}",
            "https://example.com/{env.HOME}",
        ] {
            assert!(parse_template(to).is_err(), "{to:?} accepted");
        }
        let err = parse_template("https://example.com/{nope}").unwrap_err();
        assert!(err.contains("{nope}"), "{err}");
    }

    #[test]
    fn classifies_targets() {
        assert_eq!(ok("/x").target, Target::Relative);
        assert_eq!(
            ok("https://{host}{path}").target,
            Target::Absolute {
                https: true,
                own_host: true,
                same_host: true
            }
        );
        assert_eq!(
            ok("{scheme}://{www_host}{path}").target,
            Target::Absolute {
                https: false,
                own_host: true,
                same_host: false
            }
        );
        assert_eq!(
            ok("https://other.example.org/x").target,
            Target::Absolute {
                https: true,
                own_host: false,
                same_host: false
            }
        );
        assert!(ok("https://{host}{path}").is_own_https());
        assert!(ok("https://www.{host}").is_own_https());
        assert!(!ok("https://other.example.org/").is_own_https());
        assert!(!ok("http://{host}{path}").is_own_https());
        assert!(ok("{scheme}://{www_host}{path}").uses_www());
        assert!(ok("{scheme}://{apex_host}{path}").uses_apex());
    }

    #[test]
    fn locations_encode_every_placeholder_and_double_percent_signs() {
        let t = ok("{scheme}://{www_host}{path}{query}");
        assert_eq!(
            render_location(&t.pieces),
            "%[req.fhdr(x-forwarded-proto)]://www.%[req.fhdr(host),lower]%[path]%[url,regsub(^[^?]*,,i)]"
        );
        let t = ok("{scheme}://{apex_host}{path}");
        assert_eq!(
            render_location(&t.pieces),
            "%[req.fhdr(x-forwarded-proto)]://%[req.fhdr(host),lower,regsub(^www[.],,i)]%[path]"
        );
        let t = ok("https://example.com/a%20b/100%");
        assert_eq!(
            render_location(&t.pieces),
            "https://example.com/a%%20b/100%%"
        );
        let t = ok("/new?x={path}");
        assert_eq!(render_location(&t.pieces), "/new?x=%[path]");
    }

    #[test]
    fn rendered_locations_are_one_config_word_without_directive_characters() {
        for to in [
            "https://{host}{path}{query}",
            "{scheme}://{www_host}{path}{query}",
            "{scheme}://{apex_host}{path}{query}",
            "/a/{path}",
        ] {
            let loc = render_location(&ok(to).pieces);
            assert!(
                loc.chars()
                    .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '\'' | '\\' | '#' | '$')),
                "{loc}"
            );
        }
    }
}
