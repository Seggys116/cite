use std::net::SocketAddr;
use std::path::PathBuf;

const MAX_GITHUB_URL_LEN: usize = 200;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub socket: PathBuf,
    pub registry: String,
    pub haproxy_container: String,
    pub edge_network: String,
    pub max_conns: usize,
    pub github_api_url: Option<String>,
}

// Names end up in regexes and Docker paths, so only plain name characters are accepted.
fn chars_ok(value: &str, extra: &[char]) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') || extra.contains(&c)
        })
}

// Same rules as the connector: http(s), plain host and port, plain path, no userinfo, query or fragment.
pub fn validate_github_api_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_GITHUB_URL_LEN {
        return Err(format!("longer than {MAX_GITHUB_URL_LEN} characters"));
    }
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("must start with http:// or https://")?;
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~' | ':' | '/'))
    {
        return Err("has characters that are not allowed".to_string());
    }
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let edge_ok = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    let host_ok = edge_ok(host.chars().next())
        && edge_ok(host.chars().last())
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    let port_ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 5
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    };
    if !host_ok || port.is_some_and(|p| !port_ok(p)) {
        return Err("has no valid host and port".to_string());
    }
    if path.contains("//") || path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("has an empty or relative path segment".to_string());
    }
    Ok(())
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let text = |key: &str, default: &str| {
            get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let listen_raw = text("CITE_PROXY_LISTEN", "0.0.0.0:2375");
        let listen = listen_raw
            .parse()
            .map_err(|_| format!("CITE_PROXY_LISTEN {listen_raw:?} is not host:port"))?;
        let socket = text("CITE_PROXY_SOCKET", "/var/run/docker.sock");
        if !socket.starts_with('/') {
            return Err("CITE_PROXY_SOCKET must be an absolute path".to_string());
        }
        let registry = text("CITE_PROXY_REGISTRY", "ghcr.io/seggys116");
        if !chars_ok(&registry, &['/', ':'])
            || registry.contains("..")
            || registry.starts_with('/')
            || registry.ends_with('/')
        {
            return Err(format!("CITE_PROXY_REGISTRY {registry:?} is not valid"));
        }
        let haproxy_container = text("CITE_PROXY_HAPROXY_CONTAINER", "cite-node-haproxy");
        if !chars_ok(&haproxy_container, &[]) {
            return Err(format!(
                "CITE_PROXY_HAPROXY_CONTAINER {haproxy_container:?} is not valid"
            ));
        }
        let edge_network = text("CITE_PROXY_EDGE_NETWORK", "cite_edge");
        if !chars_ok(&edge_network, &[]) {
            return Err(format!(
                "CITE_PROXY_EDGE_NETWORK {edge_network:?} is not valid"
            ));
        }
        // The cap bounds memory and file descriptors; further connections wait in the kernel backlog.
        let conns_raw = text("CITE_PROXY_MAX_CONNS", "64");
        let max_conns = conns_raw
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=1024).contains(n))
            .ok_or_else(|| format!("CITE_PROXY_MAX_CONNS {conns_raw:?} must be 1 to 1024"))?;
        let github_api_url = match get("CITE_PROXY_GITHUB_API_URL")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        {
            Some(url) => {
                validate_github_api_url(&url)
                    .map_err(|e| format!("CITE_PROXY_GITHUB_API_URL {url:?} {e}"))?;
                Some(url)
            }
            None => None,
        };
        Ok(Config {
            listen,
            socket: PathBuf::from(socket),
            registry,
            haproxy_container,
            edge_network,
            max_conns,
            github_api_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, String> {
        Config::from_lookup(|k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn defaults_match_the_compose_overlay() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.listen.to_string(), "0.0.0.0:2375");
        assert_eq!(c.socket, PathBuf::from("/var/run/docker.sock"));
        assert_eq!(c.registry, "ghcr.io/seggys116");
        assert_eq!(c.haproxy_container, "cite-node-haproxy");
        assert_eq!(c.edge_network, "cite_edge");
        assert_eq!(c.max_conns, 64);
        assert_eq!(c.github_api_url, None);
    }

    #[test]
    fn github_api_url_is_trimmed_and_validated() {
        let c = cfg(&[(
            "CITE_PROXY_GITHUB_API_URL",
            " https://ghe.example.com/api/v3 ",
        )])
        .unwrap();
        assert_eq!(
            c.github_api_url.as_deref(),
            Some("https://ghe.example.com/api/v3")
        );
        let blank = cfg(&[("CITE_PROXY_GITHUB_API_URL", "  ")]).unwrap();
        assert_eq!(blank.github_api_url, None);
        for bad in [
            "ftp://ghe.example.com",
            "ghe.example.com",
            "https://user:pw@ghe.example.com",
            "https://user@ghe.example.com",
            "https://ghe.example.com?x=1",
            "https://ghe.example.com/#frag",
            "https://ghe.example.com:0",
            "https://ghe.example.com:99999",
            "https://ghe.example.com/a b",
            "https://ghe.example.com/%2e%2e",
            "https://ghe.example.com//x",
            "https://ghe.example.com/../x",
            "https://",
            "https://.example.com",
            "HTTPS://ghe.example.com",
            "https://ghe.example.com\\evil.test",
            "https://ghe.example.com/\u{e9}",
        ] {
            assert!(
                cfg(&[("CITE_PROXY_GITHUB_API_URL", bad)]).is_err(),
                "{bad:?}"
            );
        }
        let long = format!("https://{}.example.com", "a".repeat(200));
        assert!(cfg(&[("CITE_PROXY_GITHUB_API_URL", &long)]).is_err());
    }

    #[test]
    fn hostile_values_are_refused() {
        for pairs in [
            [("CITE_PROXY_LISTEN", "nonsense")],
            [("CITE_PROXY_SOCKET", "relative.sock")],
            [("CITE_PROXY_REGISTRY", "ghcr.io/../x")],
            [("CITE_PROXY_REGISTRY", "/ghcr.io")],
            [("CITE_PROXY_REGISTRY", "a b")],
            [("CITE_PROXY_HAPROXY_CONTAINER", "a/b")],
            [("CITE_PROXY_EDGE_NETWORK", "x y")],
            [("CITE_PROXY_MAX_CONNS", "0")],
            [("CITE_PROXY_MAX_CONNS", "5000")],
        ] {
            assert!(cfg(&pairs).is_err(), "{pairs:?}");
        }
    }
}
