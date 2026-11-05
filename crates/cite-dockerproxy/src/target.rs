use std::collections::BTreeMap;

// Volume subpath mounts are silently ignored below API 1.45, which would widen what a mount exposes.
const MIN_API_MINOR: u32 = 45;
const MAX_API_MINOR: u32 = 99;
const MAX_QUERY_LEN: usize = 2048;
const MAX_QUERY_PAIRS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub path: String,
    pub query: BTreeMap<String, String>,
}

// Turns a raw request target into a canonical path and decoded query, or the reason it is refused.
pub fn normalise(raw: &str) -> Result<Target, String> {
    if !raw.starts_with('/') {
        return Err("target is not origin-form".to_string());
    }
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    check_path_chars(path)?;
    let path = strip_version(path)?;
    for segment in path[1..].split('/') {
        match segment {
            "" => return Err("empty path segment".to_string()),
            "." | ".." => return Err("dot segment in path".to_string()),
            _ => {}
        }
    }
    Ok(Target {
        path: path.to_string(),
        query: parse_query(query.unwrap_or_default())?,
    })
}

// Docker names and image references need only these characters, so everything else is refused.
fn check_path_chars(path: &str) -> Result<(), String> {
    for b in path.bytes() {
        match b {
            b'%' => return Err("percent-encoding in path".to_string()),
            b'\\' => return Err("backslash in path".to_string()),
            0 => return Err("NUL in path".to_string()),
            b'#' => return Err("fragment in target".to_string()),
            b if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-') => {}
            _ => return Err("illegal character in path".to_string()),
        }
    }
    Ok(())
}

fn strip_version(path: &str) -> Result<&str, String> {
    let rest = &path[1..];
    let (first, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let Some(version) = first
        .strip_prefix('v')
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
    else {
        return Ok(path);
    };
    let bad = || "unsupported api version".to_string();
    let (major, minor) = version.split_once('.').ok_or_else(bad)?;
    let digits = |s: &str| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(major) || !digits(minor) || tail.is_empty() {
        return Err(bad());
    }
    let minor: u32 = minor.parse().map_err(|_| bad())?;
    if major != "1" || !(MIN_API_MINOR..=MAX_API_MINOR).contains(&minor) {
        return Err(bad());
    }
    Ok(tail)
}

// Duplicate keys are refused because the engine and this parser could pick different values.
fn parse_query(q: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    if q.is_empty() {
        return Ok(out);
    }
    if q.len() > MAX_QUERY_LEN {
        return Err("query too long".to_string());
    }
    for pair in q.split('&') {
        if out.len() >= MAX_QUERY_PAIRS {
            return Err("too many query parameters".to_string());
        }
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| "query parameter without value".to_string())?;
        let key = decode(k)?;
        if key.is_empty() {
            return Err("empty query key".to_string());
        }
        if out.insert(key, decode(v)?).is_some() {
            return Err("duplicate query key".to_string());
        }
    }
    Ok(out)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// Percent-decoding happens only here, in the query, where the orchestrator's client encodes values.
fn decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hi = b.get(i + 1).copied().and_then(hex);
                let lo = b.get(i + 2).copied().and_then(hex);
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err("bad percent-encoding in query".to_string());
                };
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b';' => return Err("semicolon in query".to_string()),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    let text = String::from_utf8(out).map_err(|_| "query is not utf-8".to_string())?;
    if text.chars().any(char::is_control) {
        return Err("control character in query".to_string());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(raw: &str) -> String {
        normalise(raw).unwrap_err()
    }

    #[test]
    fn plain_path_is_canonical() {
        let t = normalise("/containers/json").unwrap();
        assert_eq!(t.path, "/containers/json");
        assert!(t.query.is_empty());
    }

    #[test]
    fn version_prefix_is_stripped() {
        assert_eq!(normalise("/v1.45/_ping").unwrap().path, "/_ping");
        assert_eq!(normalise("/v1.99/_ping").unwrap().path, "/_ping");
    }

    #[test]
    fn unsupported_versions_are_refused() {
        for raw in [
            "/v1.44/_ping",
            "/v2.45/_ping",
            "/v1.100/_ping",
            "/v1/_ping",
            "/v1.45",
            "/v1.4x/_ping",
        ] {
            assert_eq!(err(raw), "unsupported api version", "{raw}");
        }
    }

    #[test]
    fn names_starting_with_v_are_not_versions() {
        assert_eq!(
            normalise("/volumes/create").unwrap().path,
            "/volumes/create"
        );
        assert_eq!(
            normalise("/v1.45/volumes/create").unwrap().path,
            "/volumes/create"
        );
    }

    #[test]
    fn non_origin_form_is_refused() {
        for raw in [
            "http://docker/_ping",
            "*",
            "containers/json",
            "",
            "//host/_ping",
        ] {
            assert!(normalise(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn dot_segments_are_refused() {
        for raw in [
            "/containers/create/../../..",
            "/containers/./json",
            "/containers/../volumes",
            "/v1.45/containers/..",
        ] {
            assert_eq!(err(raw), "dot segment in path", "{raw}");
        }
    }

    #[test]
    fn empty_segments_are_refused() {
        for raw in [
            "/",
            "/containers//json",
            "/containers/json/",
            "//containers/json",
        ] {
            assert_eq!(err(raw), "empty path segment", "{raw}");
        }
    }

    #[test]
    fn percent_encoding_in_path_is_refused() {
        for raw in [
            "/containers%2Fjson",
            "/containers/%2e%2e/json",
            "/containers/%252e%252e",
            "/%63ontainers/json",
            "/containers/%2f",
            "/containers/json%00",
        ] {
            assert_eq!(err(raw), "percent-encoding in path", "{raw}");
        }
    }

    #[test]
    fn hostile_bytes_in_path_are_refused() {
        assert_eq!(err("/containers\\json"), "backslash in path");
        assert_eq!(err("/containers/js\0on"), "NUL in path");
        assert_eq!(err("/containers/json#x"), "fragment in target");
        for raw in [
            "/containers/js on",
            "/containers/json\n",
            "/containers/jsön",
            "/containers/j;son",
        ] {
            assert_eq!(err(raw), "illegal character in path", "{raw:?}");
        }
    }

    #[test]
    fn query_is_decoded_and_case_insensitive_in_hex() {
        let t =
            normalise("/containers/json?all=true&filters=%7B%22label%22%3A%5B%22a%3Db%22%5D%7D")
                .unwrap();
        assert_eq!(t.query["all"], "true");
        assert_eq!(t.query["filters"], "{\"label\":[\"a=b\"]}");
        let lower = normalise("/x?f=%7b%7d").unwrap();
        let upper = normalise("/x?f=%7B%7D").unwrap();
        assert_eq!(lower, upper);
        assert_eq!(normalise("/x?f=a+b").unwrap().query["f"], "a b");
    }

    #[test]
    fn hostile_queries_are_refused() {
        for raw in [
            "/x?a=1&a=2",
            "/x?a",
            "/x?=1",
            "/x?a=%zz",
            "/x?a=%4",
            "/x?a=%00",
            "/x?a=%ff",
            "/x?a=1;b=2",
            "/x?a=1&&b=2",
            "/x?a=%0a",
        ] {
            assert!(normalise(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn query_size_is_capped() {
        let long = format!("/x?a={}", "b".repeat(3000));
        assert_eq!(err(&long), "query too long");
        let many: Vec<String> = (0..17).map(|i| format!("k{i}=v")).collect();
        assert_eq!(
            err(&format!("/x?{}", many.join("&"))),
            "too many query parameters"
        );
    }

    #[test]
    fn empty_query_marker_is_accepted() {
        assert!(normalise("/_ping?").unwrap().query.is_empty());
    }

    #[test]
    fn image_reference_paths_keep_their_slashes() {
        let t =
            normalise("/v1.45/images/ghcr.io/seggys116/cite-manager:0.2.0-node22/json").unwrap();
        assert_eq!(
            t.path,
            "/images/ghcr.io/seggys116/cite-manager:0.2.0-node22/json"
        );
    }
}
