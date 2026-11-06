use crate::model::branch_problem;

pub const GITHUB_HOST: &str = "github.com";
pub const HOST_HINT: &str = "The node fetches from its configured GitHub API (github.com unless CITE_GITHUB_API_URL is set). Other git hosts are not supported yet.";
const MAX_PART: usize = 100;
const MAX_HOST: usize = 253;

// What a pasted repository address resolves to: the owner/name the node wants, the host it named and a branch from a /tree/ link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoRef {
    pub name: String,
    pub host: String,
    pub branch: Option<String>,
}

impl RepoRef {
    // Only a host other than github.com needs a warning, because the node decides where it really fetches from.
    pub fn host_hint(&self) -> Option<&'static str> {
        (self.host != GITHUB_HOST).then_some(HOST_HINT)
    }
}

fn part_problem(part: &str, what: &str) -> Option<String> {
    let ok = !part.is_empty()
        && part.len() <= MAX_PART
        && part != "."
        && part != ".."
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    (!ok).then(|| {
        format!("The {what} {part:?} may only use letters, digits, '.', '_' and '-' (up to {MAX_PART} characters).")
    })
}

fn host_problem(host: &str) -> Option<String> {
    let label_ok = |l: &str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    let ok = !host.is_empty() && host.len() <= MAX_HOST && host.split('.').all(label_ok);
    (!ok).then(|| format!("{host:?} is not a valid host name."))
}

fn port_problem(port: &str) -> Option<String> {
    let ok = !port.is_empty()
        && port.len() <= 5
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p));
    (!ok).then(|| format!("The port {port:?} must be a number from 1 to 65535."))
}

// Splits "host" or "host:port" and checks both.
fn host_and_port(authority: &str) -> Result<String, String> {
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(p) = port.and_then(port_problem) {
        return Err(p);
    }
    let host = host.to_ascii_lowercase();
    if let Some(p) = host_problem(&host) {
        return Err(p);
    }
    Ok(host
        .strip_prefix("www.")
        .map_or(host.clone(), str::to_string))
}

// The path part after the host: owner, name, then optionally tree/<branch>.
fn from_path(host: String, path: &str) -> Result<RepoRef, String> {
    let trimmed = path.trim_matches('/');
    if trimmed.contains("//") {
        return Err("The address has an empty path segment (a doubled slash).".into());
    }
    let segs: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    if segs.iter().any(|s| *s == "." || *s == "..") {
        return Err("The address contains a relative path segment ('.' or '..').".into());
    }
    if segs.len() < 2 {
        return Err("Name the owner and the repository, like owner/name.".into());
    }
    let (owner, raw_name) = (segs[0], segs[1]);
    let name = raw_name.strip_suffix(".git").unwrap_or(raw_name);
    if let Some(p) = part_problem(owner, "owner") {
        return Err(p);
    }
    if let Some(p) = part_problem(name, "repository name") {
        return Err(p);
    }
    let extras = &segs[2..];
    let branch = match extras {
        [] => None,
        ["tree"] => return Err("The address ends at /tree without a branch name.".into()),
        ["tree", rest @ ..] => {
            let branch = rest.join("/");
            if let Some(p) = branch_problem(&branch) {
                return Err(format!("The branch in the address is not valid: {p}"));
            }
            Some(branch)
        }
        [page, ..] => {
            return Err(format!(
                "The address points at a page inside the repository ({page}); use the repository address, like https://github.com/{owner}/{name}."
            ));
        }
    };
    Ok(RepoRef {
        name: format!("{owner}/{name}"),
        host,
        branch,
    })
}

// scp-like ssh form: git@github.com:owner/name.git
fn from_scp(text: &str) -> Option<Result<RepoRef, String>> {
    let (user_host, path) = text.split_once(':')?;
    let (user, host) = user_host.split_once('@')?;
    if text.contains("://") || user.is_empty() || user.contains('/') || host.contains('/') {
        return None;
    }
    Some(host_and_port(host).and_then(|h| from_path(h, path)))
}

// Accepts owner/name and the addresses people paste: https, http and ssh forms, with or without .git, a trailing slash, www., a port, a query, a fragment or a /tree/<branch> suffix.
pub fn parse_repo(input: &str) -> Result<RepoRef, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("Enter the repository as owner/name or paste its GitHub address.".into());
    }
    if let Some(c) = text.chars().find(|c| !c.is_ascii()) {
        return Err(format!(
            "The address contains {c:?}, which is not an ASCII character. Retype it; look-alike letters are not accepted."
        ));
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("The repository cannot contain spaces.".into());
    }
    let text = text.split(['?', '#']).next().unwrap_or(text);
    if text.contains('%') {
        return Err("Percent-encoded characters are not accepted; type the plain name.".into());
    }
    if let Some(found) = from_scp(text) {
        return found;
    }
    if let Some((scheme, rest)) = text.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "https" | "http" | "ssh") {
            return Err(format!(
                "Only https, http and ssh addresses are supported, not {scheme}://."
            ));
        }
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let host_part = match authority.rsplit_once('@') {
            Some((user, host)) => {
                if scheme != "ssh" || user.contains(':') {
                    return Err(
                        "Remove the credentials from the address; the token has its own field."
                            .into(),
                    );
                }
                host
            }
            None => authority,
        };
        return host_and_port(host_part).and_then(|h| from_path(h, path));
    }
    let first = text.trim_start_matches('/').split('/').next().unwrap_or("");
    let segments = text.trim_matches('/').split('/').count();
    if first.contains('.') && segments >= 3 {
        let (authority, path) = text
            .trim_start_matches('/')
            .split_at(text.trim_start_matches('/').find('/').unwrap_or(text.len()));
        return host_and_port(authority).and_then(|h| from_path(h, path));
    }
    from_path(GITHUB_HOST.to_string(), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> String {
        parse_repo(text)
            .unwrap_or_else(|e| panic!("{text}: {e}"))
            .name
    }

    #[test]
    fn plain_owner_and_name_pass_through() {
        assert_eq!(name("acme/shop"), "acme/shop");
        assert_eq!(name("  acme/shop  "), "acme/shop");
        assert_eq!(name("Acme/Shop"), "Acme/Shop");
        assert_eq!(name("acme/shop.git"), "acme/shop");
        assert_eq!(name("acme/shop/"), "acme/shop");
        assert_eq!(name("/acme/shop"), "acme/shop");
        assert_eq!(name("acme/.github"), "acme/.github");
        assert_eq!(name("a.b/c_d-e"), "a.b/c_d-e");
        let r = parse_repo("acme/shop").unwrap();
        assert_eq!((r.host.as_str(), r.branch.clone()), ("github.com", None));
        assert!(r.host_hint().is_none());
    }

    #[test]
    fn https_addresses_resolve_to_owner_and_name() {
        for text in [
            "https://github.com/acme/shop",
            "https://github.com/acme/shop.git",
            "https://github.com/acme/shop/",
            "https://github.com/acme/shop.git/",
            "https://www.github.com/acme/shop",
            "HTTPS://GitHub.com/acme/shop",
            "http://github.com/acme/shop",
            "https://github.com:443/acme/shop",
            "https://github.com/acme/shop?tab=readme-ov-file",
            "https://github.com/acme/shop#readme",
            "https://github.com/acme/shop/?a=b#c",
            "  https://github.com/acme/shop  ",
            "github.com/acme/shop",
            "www.github.com/acme/shop.git",
        ] {
            let r = parse_repo(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(r.name, "acme/shop", "{text}");
            assert_eq!(r.host, "github.com", "{text}");
            assert!(r.branch.is_none(), "{text}");
            assert!(r.host_hint().is_none(), "{text}");
        }
    }

    #[test]
    fn ssh_forms_resolve_too() {
        for text in [
            "git@github.com:acme/shop.git",
            "git@github.com:acme/shop",
            "git@github.com:/acme/shop.git",
            "ssh://git@github.com/acme/shop.git",
            "ssh://git@github.com:22/acme/shop.git",
            "ssh://github.com/acme/shop",
        ] {
            assert_eq!(name(text), "acme/shop", "{text}");
        }
        assert_eq!(
            parse_repo("git@ghe.example.com:acme/shop.git")
                .unwrap()
                .host,
            "ghe.example.com"
        );
    }

    #[test]
    fn a_tree_link_offers_its_branch() {
        let r = parse_repo("https://github.com/acme/shop/tree/release/1.2").unwrap();
        assert_eq!(r.name, "acme/shop");
        assert_eq!(r.branch.as_deref(), Some("release/1.2"));
        let r = parse_repo("https://github.com/acme/shop.git/tree/main/").unwrap();
        assert_eq!(r.branch.as_deref(), Some("main"));
        let r = parse_repo("https://github.com/acme/shop/tree/dev?x=1#y").unwrap();
        assert_eq!(r.branch.as_deref(), Some("dev"));
        assert!(
            parse_repo("https://github.com/acme/shop/tree")
                .unwrap_err()
                .contains("/tree")
        );
        assert!(
            parse_repo("https://github.com/acme/shop/tree/")
                .unwrap_err()
                .contains("/tree")
        );
        assert!(
            parse_repo("https://github.com/acme/shop/tree/a..b")
                .unwrap_err()
                .contains("branch")
        );
    }

    #[test]
    fn other_hosts_are_accepted_with_a_hint() {
        let r = parse_repo("https://ghe.example.com/acme/shop").unwrap();
        assert_eq!(
            (r.name.as_str(), r.host.as_str()),
            ("acme/shop", "ghe.example.com")
        );
        assert_eq!(r.host_hint(), Some(HOST_HINT));
        let r = parse_repo("https://git.corp.example:8443/acme/shop.git").unwrap();
        assert_eq!(r.host, "git.corp.example");
        assert!(r.host_hint().is_some());
        let r = parse_repo("gitlab.com/acme/shop").unwrap();
        assert_eq!(r.host, "gitlab.com");
        assert!(
            HOST_HINT.contains("CITE_GITHUB_API_URL") && HOST_HINT.contains("not supported yet")
        );
    }

    #[test]
    fn other_schemes_and_credentials_are_refused_precisely() {
        for text in [
            "ftp://github.com/acme/shop",
            "git://github.com/acme/shop",
            "file:///etc/passwd",
            "javascript://github.com/acme/shop",
        ] {
            assert!(
                parse_repo(text)
                    .unwrap_err()
                    .contains("Only https, http and ssh"),
                "{text}"
            );
        }
        assert!(
            parse_repo("https://user:pw@github.com/acme/shop")
                .unwrap_err()
                .contains("credentials")
        );
        assert!(
            parse_repo("https://token@github.com/acme/shop")
                .unwrap_err()
                .contains("credentials")
        );
        assert!(
            parse_repo("ssh://user:pw@github.com/acme/shop")
                .unwrap_err()
                .contains("credentials")
        );
    }

    #[test]
    fn pages_inside_a_repository_are_not_repositories() {
        for text in [
            "https://github.com/acme/shop/blob/main/README.md",
            "https://github.com/acme/shop/issues/3",
            "https://github.com/acme/shop/pull/9",
            "https://github.com/acme/shop/releases",
            "acme/shop/extra",
        ] {
            assert!(
                parse_repo(text).unwrap_err().contains("page inside"),
                "{text}"
            );
        }
        for text in [
            "https://github.com/acme",
            "https://github.com/",
            "https://github.com",
            "acme",
            "/",
            "acme/",
        ] {
            assert!(parse_repo(text).is_err(), "{text}");
        }
    }

    #[test]
    fn ports_are_checked() {
        assert!(
            parse_repo("https://github.com:99999/acme/shop")
                .unwrap_err()
                .contains("port")
        );
        assert!(
            parse_repo("https://github.com:0/acme/shop")
                .unwrap_err()
                .contains("port")
        );
        assert!(
            parse_repo("https://github.com:abc/acme/shop")
                .unwrap_err()
                .contains("port")
        );
        assert!(parse_repo("https://github.com:/acme/shop").is_err());
        assert!(parse_repo("https://:443/acme/shop").is_err());
    }

    #[test]
    fn path_traversal_and_hostile_segments_are_refused() {
        for text in [
            "https://github.com/../../etc/passwd",
            "https://github.com/acme/..",
            "https://github.com/acme/shop/../x",
            "../shop",
            "acme/..",
            "./acme/shop",
            "https://github.com/acme//shop",
            "https://github.com/acme/%2e%2e",
            "https://github.com/acme/sh%6fp",
            "https://github.com/acme/shop;rm",
            "https://github.com/acme/sh op",
            "acme/sh\u{0}op",
            "https://github.com/acme/shop\\evil",
            "acme/shop:evil",
        ] {
            assert!(parse_repo(text).is_err(), "{text:?}");
        }
        assert!(
            parse_repo("https://github.com/../../etc/passwd")
                .unwrap_err()
                .contains("relative")
        );
        assert!(
            parse_repo("https://github.com/acme/%2e%2e")
                .unwrap_err()
                .contains("Percent")
        );
    }

    #[test]
    fn whitespace_and_lookalikes_are_refused() {
        assert!(parse_repo("").unwrap_err().contains("Enter the repository"));
        assert!(
            parse_repo("   ")
                .unwrap_err()
                .contains("Enter the repository")
        );
        assert!(parse_repo("acme /shop").unwrap_err().contains("spaces"));
        assert!(parse_repo("acme/sh op").unwrap_err().contains("spaces"));
        assert!(parse_repo("acme/shop\nrm").unwrap_err().contains("spaces"));
        // Cyrillic small letter byelorussian-ukrainian i in the host, and a fullwidth solidus.
        assert!(
            parse_repo("https://g\u{456}thub.com/acme/shop")
                .unwrap_err()
                .contains("not an ASCII")
        );
        assert!(
            parse_repo("acme\u{ff0f}shop")
                .unwrap_err()
                .contains("not an ASCII")
        );
        assert!(
            parse_repo("acme/sh\u{43e}p")
                .unwrap_err()
                .contains("not an ASCII")
        );
        assert!(
            parse_repo("acme/caf\u{e9}")
                .unwrap_err()
                .contains("not an ASCII")
        );
    }

    #[test]
    fn name_parts_follow_the_nodes_rules() {
        assert!(parse_repo("acme/.git").is_err());
        assert!(parse_repo("acme/a*b").is_err());
        assert!(parse_repo("ac!me/shop").is_err());
        let long = "a".repeat(101);
        assert!(parse_repo(&format!("{long}/shop")).is_err());
        assert!(parse_repo(&format!("acme/{long}")).is_err());
        let ok = "a".repeat(100);
        assert!(parse_repo(&format!("{ok}/{ok}")).is_ok());
    }

    #[test]
    fn host_names_are_checked() {
        for text in [
            "https://-bad.com/acme/shop",
            "https://bad-.com/acme/shop",
            "https://a..b/acme/shop",
            "https://exa_mple.com/acme/shop",
            "https://[::1]/acme/shop",
        ] {
            assert!(parse_repo(text).is_err(), "{text}");
        }
        assert_eq!(
            parse_repo("https://GHE.Example.COM/a/b").unwrap().host,
            "ghe.example.com"
        );
    }
}
