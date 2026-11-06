use sha2::{Digest, Sha256};

use crate::bot::scanner_regex;
use crate::model::{EdgeConfig, FirewallAction, FirewallRule, HeaderMatch, Matchers, Redirect};
use crate::validate::{ValidationError, invalid, validate_config};

/// Header a Cloudflare Transform Rule adds to prove a request came through the owner's zone.
pub const ZONE_HEADER: &str = "X-Cite-Origin-Secret";
/// Label under which zone-lock denials are logged and counted.
pub const ZONE_LABEL: &str = "cloudflare-zone";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub rules: Vec<FirewallRule>,
}

fn path_rule(
    preset: &str,
    n: usize,
    title: &str,
    action: FirewallAction,
    re: &str,
) -> FirewallRule {
    FirewallRule {
        id: format!("preset-{preset}-{n}"),
        name: title.to_string(),
        enabled: true,
        action: Some(action),
        matchers: Matchers {
            path_regexes: vec![re.to_string()],
            ..Default::default()
        },
        ..FirewallRule::default()
    }
}

fn ua_rule(preset: &str, n: usize, title: &str, action: FirewallAction, re: &str) -> FirewallRule {
    FirewallRule {
        id: format!("preset-{preset}-{n}"),
        name: title.to_string(),
        enabled: true,
        action: Some(action),
        matchers: Matchers {
            user_agent_regexes: vec![re.to_string()],
            ..Default::default()
        },
        ..FirewallRule::default()
    }
}

// The whole site id when it fits in a rule id, otherwise a prefix plus a stable hash of the id, so long ids never collide.
fn zone_rule_id(site_id: &str) -> String {
    let full = format!("zone-{site_id}");
    if full.chars().count() <= 40 {
        return full;
    }
    let digest = Sha256::digest(site_id.as_bytes());
    let hash: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let prefix: String = site_id.chars().take(26).collect();
    format!("zone-{prefix}-{hash}")
}

// Not a static preset because the secret is the owner's; the rule is scoped to one site and denies unless the header equals it.
pub fn zone_lock_rule(site_id: &str, secret: &str) -> FirewallRule {
    FirewallRule {
        id: zone_rule_id(site_id),
        name: "Cloudflare zone lock".to_string(),
        enabled: true,
        action: Some(FirewallAction::Deny),
        matchers: Matchers {
            headers: vec![HeaderMatch {
                name: ZONE_HEADER.to_string(),
                equals: Some(secret.to_string()),
                negate: true,
                secret: true,
                ..HeaderMatch::default()
            }],
            ..Default::default()
        },
        site: Some(site_id.to_string()),
        label: Some(ZONE_LABEL.to_string()),
        ..FirewallRule::default()
    }
}

// Fails closed: a site with zone_lock and no secret is an error, so it can never be rendered without its lock.
pub fn with_zone_locks(
    cfg: &EdgeConfig,
    secret_for: impl Fn(&str) -> Option<String>,
) -> Result<EdgeConfig, ValidationError> {
    let mut out = cfg.clone();
    for site in cfg.sites.iter().filter(|s| s.access.zone_lock) {
        let Some(secret) = secret_for(&site.id) else {
            return invalid(format!(
                "site {}: zone_lock is on but the node has no zone secret for it",
                site.id
            ));
        };
        out.firewall.push(zone_lock_rule(&site.id, &secret));
    }
    validate_config(&out)?;
    Ok(out)
}

fn redirect_rule(preset: &str, title: &str, to: &str, matchers: Matchers) -> FirewallRule {
    FirewallRule {
        id: format!("preset-{preset}-1"),
        name: title.to_string(),
        enabled: true,
        matchers,
        redirect: Some(Redirect {
            to: to.to_string(),
            status: 301,
        }),
        ..FirewallRule::default()
    }
}

// The www guard comes from {www_host} itself: rendering only fires the rule when the host does not already start with www.
fn redirect_to_www() -> Preset {
    let p = "redirect-to-www";
    Preset {
        name: p,
        title: "Redirect to www",
        description: "Sends visitors of the bare domain to www with a 301. Apply it to one site, not node-wide.",
        rules: vec![redirect_rule(
            p,
            "Add www",
            "{scheme}://{www_host}{path}{query}",
            Matchers::default(),
        )],
    }
}

fn redirect_to_apex() -> Preset {
    let p = "redirect-to-apex";
    Preset {
        name: p,
        title: "Redirect to the bare domain",
        description: "Sends www visitors to the bare domain with a 301. Apply it to one site, not node-wide.",
        rules: vec![redirect_rule(
            p,
            "Remove www",
            "{scheme}://{apex_host}{path}{query}",
            Matchers::default(),
        )],
    }
}

// Rendering skips this rule on nodes without HTTPS on port 443 and for Flexible sites, where Cloudflare already owns the scheme.
fn force_https() -> Preset {
    let p = "force-https";
    Preset {
        name: p,
        title: "Force HTTPS",
        description: "Redirects plain HTTP requests to HTTPS with a 301. Needs HTTPS on port 443; skipped for Flexible SSL sites.",
        rules: vec![redirect_rule(
            p,
            "HTTP to HTTPS",
            "https://{host}{path}{query}",
            Matchers {
                scheme: Some("http".to_string()),
                ..Default::default()
            },
        )],
    }
}

// A trailing (;|$) stands for the old (;[^/]*)?$ path-parameter tail, which needed a second unbounded repeat: after a ; anything may follow.
const SENSITIVE_KEYS: &str = r"(?i)((^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*$|(privkey|private)[^/]*\.pem(;|$)|\.(key|p12|pfx|jks|keystore)(;|$))";
const SENSITIVE_BACKUPS: &str = r"(?i)(\.(sql|bak|swp|swo|orig|old|save)|~)(;|$)";
const SENSITIVE_ARCHIVES: &str = r"(?i)(^|/)(backup|backups|dump|dumps|db|database|www|site|public_html)[^/]*\.(zip|tar|tgz|gz|7z|rar)(;|$)";
const SENSITIVE_MANIFESTS: &str =
    r"(?i)(^|/)(docker-compose[^/]*\.ya?ml(;|$)|dockerfile[^/]*$|composer\.(json|lock)(;|$))";
const CMS_DB_TOOLS: &str = r"(?i)/(phpmyadmin|pma|myadmin|mysqladmin)(;|/|$)";
const CMS_CONSOLES: &str = r"(?i)/(actuator|solr|manager(;[^/]*)?/html)(;|/|$)";

fn sensitive_files() -> Preset {
    let drop = FirewallAction::Drop;
    let p = "sensitive-files";
    // (?i) needs a PCRE-enabled haproxy build; (;[^/]*)? tolerates path parameters, which servlet containers strip from every segment. The dotfile rule has no terminator on purpose, so .env~, .env-prod, .env.local and .gitignore all match
    Preset {
        name: p,
        title: "Sensitive files",
        description: "Drops requests for dotfiles, keys, config files, dumps and backup archives.",
        rules: vec![
            path_rule(
                p,
                1,
                "Dotfiles",
                drop,
                r"(?i)(^|/)\.(env|git|svn|hg|htaccess|htpasswd|ds_store|npmrc|netrc|pypirc|dockerenv|dockerignore|bash_history|aws|ssh)",
            ),
            path_rule(p, 2, "Private keys and keystores", drop, SENSITIVE_KEYS),
            path_rule(
                p,
                3,
                "WordPress config",
                drop,
                r"(?i)(^|/)wp-config(\.php)?(\.|~|;|$)",
            ),
            path_rule(
                p,
                4,
                "Database, backup and editor files",
                drop,
                SENSITIVE_BACKUPS,
            ),
            path_rule(p, 5, "Backup archives", drop, SENSITIVE_ARCHIVES),
            path_rule(
                p,
                6,
                "Build and dependency manifests",
                drop,
                SENSITIVE_MANIFESTS,
            ),
        ],
    }
}

fn cms_probes() -> Preset {
    // A site that really serves one of these paths, such as WordPress, must not enable this preset
    let drop = FirewallAction::Drop;
    // ids are derived from the preset name and position, so they stay stable across releases
    let p = "cms-probes";
    Preset {
        name: p,
        title: "CMS and admin probes",
        description: "Drops probes for WordPress, phpMyAdmin, PHPUnit, Spring actuator and similar.",
        rules: vec![
            path_rule(
                p,
                1,
                "WordPress endpoints",
                drop,
                r"(?i)/(wp-login\.php|wp-admin|xmlrpc\.php)",
            ),
            path_rule(p, 2, "Database admin tools", drop, CMS_DB_TOOLS),
            path_rule(
                p,
                3,
                "Known exploit paths",
                drop,
                r"(?i)/(vendor/phpunit|cgi-bin|boaform|HNAP1)",
            ),
            path_rule(p, 4, "Java and router consoles", drop, CMS_CONSOLES),
        ],
    }
}

fn scanners() -> Preset {
    let tar = FirewallAction::Tarpit;
    let p = "scanners";
    // Tarpit holds the connection for the 5s tarpit timeout instead of closing it, which ties up the scanner's slot
    Preset {
        name: p,
        title: "Scanners",
        description: "Tarpits well-known scanner user agents and requests with an empty user agent.",
        rules: vec![
            ua_rule(p, 1, "Scanner user agents", tar, &scanner_regex()),
            ua_rule(p, 2, "Empty user agent", tar, "^$"),
        ],
    }
}

fn odd_methods() -> Preset {
    let p = "odd-methods";
    // TRACE and TRACK echo request headers back and CONNECT asks for a tunnel; none belong on a website
    Preset {
        name: p,
        title: "Unusual HTTP methods",
        description: "Denies TRACE, TRACK, CONNECT and DEBUG requests.",
        rules: vec![FirewallRule {
            id: format!("preset-{p}-1"),
            name: "Unusual methods".to_string(),
            enabled: true,
            action: Some(FirewallAction::Deny),
            matchers: Matchers {
                methods: ["TRACE", "TRACK", "CONNECT", "DEBUG"]
                    .map(String::from)
                    .to_vec(),
                ..Default::default()
            },
            ..FirewallRule::default()
        }],
    }
}

pub fn presets() -> Vec<Preset> {
    vec![
        sensitive_files(),
        cms_probes(),
        scanners(),
        odd_methods(),
        redirect_to_www(),
        redirect_to_apex(),
        force_https(),
    ]
}

pub fn preset(name: &str) -> Option<Preset> {
    presets().into_iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::validate_rule;
    use regex::Regex;
    use std::collections::HashSet;

    #[test]
    fn every_preset_rule_validates() {
        for p in presets() {
            assert!(!p.rules.is_empty(), "{} has no rules", p.name);
            for r in &p.rules {
                validate_rule(r).unwrap_or_else(|e| panic!("{}: {e}", r.id));
            }
        }
    }

    #[test]
    fn rule_ids_are_unique_and_prefixed() {
        let mut seen = HashSet::new();
        for p in presets() {
            for r in &p.rules {
                assert!(r.id.starts_with(&format!("preset-{}-", p.name)), "{}", r.id);
                assert!(seen.insert(r.id.clone()), "duplicate {}", r.id);
            }
        }
    }

    #[test]
    fn lookup_by_name() {
        assert_eq!(preset("scanners").map(|p| p.title), Some("Scanners"));
        assert!(preset("missing").is_none());
        assert_eq!(presets().len(), 7);
        let names: Vec<&str> = presets().iter().map(|p| p.name).collect();
        assert_eq!(
            names[4..],
            ["redirect-to-www", "redirect-to-apex", "force-https"]
        );
    }

    #[test]
    fn actions_follow_the_design() {
        let action = |n: &str| {
            preset(n).map(|p| p.rules.iter().filter_map(|r| r.action).collect::<Vec<_>>())
        };
        assert!(
            action("sensitive-files").is_some_and(|a| a.iter().all(|x| *x == FirewallAction::Drop))
        );
        assert!(action("cms-probes").is_some_and(|a| a.iter().all(|x| *x == FirewallAction::Drop)));
        assert!(action("scanners").is_some_and(|a| a.iter().all(|x| *x == FirewallAction::Tarpit)));
        assert_eq!(action("odd-methods"), Some(vec![FirewallAction::Deny]));
        for name in ["redirect-to-www", "redirect-to-apex", "force-https"] {
            let p = preset(name).expect("preset");
            assert!(
                p.rules
                    .iter()
                    .all(|r| r.action.is_none() && r.redirect.is_some()),
                "{name}"
            );
        }
    }

    // (name, rewritten regex, the regex it replaced)
    fn old_new_pairs() -> [(&'static str, &'static str, &'static str); 6] {
        [
            (
                "KEYS",
                SENSITIVE_KEYS,
                r"(?i)((^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*|(^|/)[^/]*(privkey|private)[^/]*\.pem|\.(key|p12|pfx|jks|keystore))(;[^/]*)?$",
            ),
            (
                "BACKUPS",
                SENSITIVE_BACKUPS,
                r"(?i)(\.(sql|bak|swp|swo|orig|old|save)|~)(;[^/]*)?$",
            ),
            (
                "ARCHIVES",
                SENSITIVE_ARCHIVES,
                r"(?i)(^|/)(backup|backups|dump|dumps|db|database|www|site|public_html)[^/]*\.(zip|tar|tgz|gz|7z|rar)(;[^/]*)?$",
            ),
            (
                "MANIFESTS",
                SENSITIVE_MANIFESTS,
                r"(?i)(^|/)(docker-compose[^/]*\.ya?ml|dockerfile[^/]*|composer\.(json|lock))(;[^/]*)?$",
            ),
            (
                "DB_TOOLS",
                CMS_DB_TOOLS,
                r"(?i)/(phpmyadmin|pma|myadmin|mysqladmin)(;[^/]*)?(/|$)",
            ),
            (
                "CONSOLES",
                CMS_CONSOLES,
                r"(?i)/(actuator|solr|manager(;[^/]*)?/html)(;[^/]*)?(/|$)",
            ),
        ]
    }

    // Every shape the canonical path can take around a sensitive name: prefixes, case, suffixes, encoded slashes, query-looking text, path parameters, dot segments.
    fn large_corpus() -> Vec<String> {
        let names = [
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "id_rsa.pub",
            "server.key",
            "ca.p12",
            "site.pfx",
            "store.jks",
            "app.keystore",
            "privkey.pem",
            "my-private-key.pem",
            "ca.pem",
            "private",
            "dump.sql",
            "a.bak",
            "x.swp",
            "x.swo",
            "a.orig",
            "a.php.old",
            "a.save",
            "x~",
            "~alice",
            "backup.zip",
            "backups.tar",
            "dump.tar.gz",
            "db.7z",
            "database.rar",
            "www.tgz",
            "site.gz",
            "public_html.zip",
            "photo.zip.png",
            "docker-compose.yml",
            "docker-compose.prod.yaml",
            "Dockerfile",
            "dockerfile.dev",
            "composer.json",
            "composer.lock",
            "composer.jsonx",
            "package.json",
            "phpmyadmin",
            "pma",
            "myadmin",
            "mysqladmin",
            "pmail",
            "actuator",
            "actuators",
            "solr",
            "manager/html",
            "manager/status",
            "managers/html",
            "index.html",
            "readme.txt",
        ];
        let prefixes = ["/", "/a/", "/a/b/c/", "//", "/a;b/", "/..;/", "/x.y/"];
        let suffixes = [
            "",
            ";x",
            ";jsessionid=1",
            "/",
            "/x",
            "?q=1",
            "/?a=b",
            "%2f",
            "%2fx",
            "%2Fx",
            ".png",
            "//",
            "/.",
            ";",
        ];
        let mut out = Vec::new();
        for name in names {
            for prefix in prefixes {
                for suffix in suffixes {
                    out.push(format!("{prefix}{name}{suffix}"));
                }
            }
            out.push(format!("/{}", name.to_uppercase()));
            out.push(format!("/{}/x", name.to_uppercase()));
            out.push(format!("/{name}%2f{name}"));
            out.push(format!("/{name}?/{name}"));
            out.push(format!("/x?{name}"));
            out.push(format!("/a/../{name}"));
            out.push(format!("/./{name}"));
            out.push(name.to_string());
        }
        out
    }

    // Paths where the new regex matches and the old one did not: a path parameter that is followed by a slash, which the canonical path never contains in front of a name.
    const WIDENED: [(&str, &str); 8] = [
        ("BACKUPS", "/a.sql;x/b"),
        ("BACKUPS", "/x~;y/z"),
        ("BACKUPS", "/a.bak;x/id_rsa"),
        ("ARCHIVES", "/backup.zip;x/b"),
        ("KEYS", "/certs/server.key;v=1/x"),
        ("KEYS", "/ssl/privkey.pem;x/b"),
        ("MANIFESTS", "/docker-compose.yml;x/b"),
        ("MANIFESTS", "/composer.json;x/b"),
    ];

    #[test]
    fn rewritten_preset_regexes_never_lose_a_match_on_a_large_corpus() {
        let mut corpus = large_corpus();
        corpus.extend(WIDENED.iter().map(|(_, p)| p.to_string()));
        corpus.extend(
            [
                "/id_rsa;x/b",
                "/pma;x/b",
                "/actuator;x/b",
                "/manager;x/html;y/z",
            ]
            .map(String::from),
        );
        let distinct: HashSet<&String> = corpus.iter().collect();
        assert!(
            distinct.len() >= 300,
            "only {} distinct paths",
            distinct.len()
        );
        let mut widened = HashSet::new();
        for (name, new, old) in old_new_pairs() {
            let (n, o) = (Regex::new(new).expect("new"), Regex::new(old).expect("old"));
            for path in &corpus {
                let (was, is) = (o.is_match(path), n.is_match(path));
                assert!(!was || is, "{name} lost a match the old regex had: {path}");
                if is && !was {
                    widened.insert((name.to_string(), path.clone()));
                }
            }
        }
        let allowed: HashSet<(String, String)> = WIDENED
            .iter()
            .map(|(n, p)| (n.to_string(), p.to_string()))
            .collect();
        let mut extra: Vec<_> = widened.difference(&allowed).collect();
        extra.sort();
        assert!(
            extra.is_empty(),
            "matches the old regexes did not have: {extra:?}"
        );
        let mut stale: Vec<_> = allowed.difference(&widened).collect();
        stale.sort();
        assert!(
            stale.is_empty(),
            "allowlist entries that no longer widen: {stale:?}"
        );
    }

    #[test]
    fn rewritten_preset_regexes_detect_what_the_old_ones_did() {
        let pairs = old_new_pairs().map(|(_, new, old)| (new, old));
        let corpus = [
            "/",
            "/index.html",
            "/id_rsa",
            "/id_rsa;x",
            "/id_rsa.bak",
            "/id_rsa/x",
            "/home/id_ed25519",
            "/certs/server.key",
            "/certs/server.key;v=1",
            "/ssl/privkey.pem",
            "/ssl/my-private-key.pem",
            "/private/readme.txt",
            "/private/x.pem",
            "/certs/ca.pem",
            "/db/dump.sql",
            "/db/dump.sql;jsessionid=1",
            "/a.php.old",
            "/config.php~",
            "/~alice/",
            "/x~",
            "/backup-2024.zip",
            "/backup.zip;x",
            "/images/photo.zip.png",
            "/dump.tar.gz",
            "/www.zip",
            "/site.rar;a",
            "/docker-compose.yml",
            "/docker-compose.prod.yaml;x",
            "/Dockerfile",
            "/dockerfile.dev",
            "/composer.json",
            "/composer.lock;x",
            "/composer.jsonx",
            "/package.json",
            "/phpmyadmin/index.php",
            "/pma",
            "/pma;x",
            "/pmail",
            "/phpmyadmin;x/",
            "/phpmyadminx",
            "/actuator/env",
            "/actuator;x/env",
            "/actuators-info",
            "/solr/admin",
            "/manager/html",
            "/manager;x/html",
            "/manager;x/other",
            "/managers/html",
            "/WP-ADMIN/",
            "/ID_RSA",
        ];
        for (new, old) in pairs {
            let (n, o) = (Regex::new(new).expect("new"), Regex::new(old).expect("old"));
            for path in corpus {
                assert_eq!(n.is_match(path), o.is_match(path), "{new} on {path}");
            }
        }
        // the only widening is a path parameter followed by a slash, which the canonical path removes anyway
        let widened = [
            (SENSITIVE_BACKUPS, "/a.sql;x/b"),
            (SENSITIVE_ARCHIVES, "/backup.zip;x/b"),
        ];
        for (new, path) in widened {
            assert!(Regex::new(new).expect("new").is_match(path), "{path}");
        }
    }

    #[test]
    fn scanner_preset_regex_comes_from_the_shared_token_list() {
        let re = preset("scanners").map(|p| p.rules[0].matchers.user_agent_regexes.clone());
        assert_eq!(re, Some(vec![scanner_regex()]));
        assert_eq!(
            scanner_regex(),
            "(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|havij)"
        );
    }

    #[test]
    fn redirect_presets_use_the_documented_templates() {
        let to =
            |n: &str| preset(n).and_then(|p| p.rules[0].redirect.clone().map(|r| (r.to, r.status)));
        assert_eq!(
            to("redirect-to-www"),
            Some(("{scheme}://{www_host}{path}{query}".to_string(), 301))
        );
        assert_eq!(
            to("redirect-to-apex"),
            Some(("{scheme}://{apex_host}{path}{query}".to_string(), 301))
        );
        assert_eq!(
            to("force-https"),
            Some(("https://{host}{path}{query}".to_string(), 301))
        );
        let https = preset("force-https").map(|p| p.rules[0].matchers.scheme.clone());
        assert_eq!(https, Some(Some("http".to_string())));
    }

    #[test]
    fn zone_lock_rule_denies_unless_the_secret_header_matches() {
        let secret = "s".repeat(40);
        let rule = zone_lock_rule("shop", &secret);
        validate_rule(&rule).expect("valid");
        assert_eq!(rule.action, Some(FirewallAction::Deny));
        assert_eq!(rule.site.as_deref(), Some("shop"));
        assert_eq!(rule.label.as_deref(), Some(ZONE_LABEL));
        assert_eq!(ZONE_HEADER, "X-Cite-Origin-Secret");
        let h = rule
            .matchers
            .headers
            .first()
            .expect("header matcher")
            .clone();
        assert_eq!(h.name, ZONE_HEADER);
        assert_eq!(h.equals.as_deref(), Some(secret.as_str()));
        assert!(h.negate && h.secret && h.regex.is_none());
        let long = zone_lock_rule(&"a".repeat(40), &secret);
        assert!(crate::validate::is_valid_id(&long.id), "{}", long.id);
    }

    fn matches(preset_name: &str, path: &str) -> bool {
        preset(preset_name).is_some_and(|p| {
            p.rules
                .iter()
                .flat_map(|r| r.matchers.path_regexes.iter())
                .any(|re| Regex::new(re.as_str()).is_ok_and(|re| re.is_match(path)))
        })
    }

    #[test]
    fn sensitive_paths_match_and_normal_paths_do_not() {
        for hit in [
            "/.env",
            "/app/.git/config",
            "/.ENV.local",
            "/id_rsa",
            "/db/dump.sql",
            "/wp-config.php",
            "/backup-2024.zip",
            "/.env;x",
            "/.git;a=b/config",
            "/id_rsa;x",
            "/db/dump.sql;jsessionid=1",
            "/backup.zip;x",
            "/wp-config;x",
            "/.env~",
            "/.env-prod",
            "/.env.local",
            "/.env.bak",
            "/.gitignore",
            "/.aws/credentials",
            "/.npmrc",
            "/.dockerenv",
            "/id_rsa.bak",
            "/certs/server.key",
            "/ssl/privkey.pem",
            "/config.php~",
            "/a.php.old",
            "/docker-compose.yml",
            "/docker-compose.prod.yaml",
            "/Dockerfile",
            "/composer.json",
            "/composer.lock;x",
        ] {
            assert!(matches("sensitive-files", hit), "{hit} not matched");
        }
        for miss in [
            "/",
            "/index.html",
            "/environment",
            "/assets/app.js",
            "/docs/git-guide",
            "/images/photo.zip.png",
            "/a%20b",
            "/api/v1/users",
            "/static/app.js",
            "/docs/environment.html",
            "/blog/dotenv-guide",
            "/certs/ca.pem",
            "/~alice/",
            "/package.json",
        ] {
            assert!(!matches("sensitive-files", miss), "{miss} wrongly matched");
        }
    }

    #[test]
    fn cms_probe_paths_match_and_normal_paths_do_not() {
        for hit in [
            "/wp-login.php",
            "/WP-Admin/",
            "/xmlrpc.php",
            "/phpmyadmin/index.php",
            "/pma",
            "/vendor/phpunit/x",
            "/actuator/env",
            "/actuator;x/env",
            "/phpmyadmin;x/",
            "/manager;x/html",
            "/pma;x",
        ] {
            assert!(matches("cms-probes", hit), "{hit} not matched");
        }
        for miss in ["/", "/pmail", "/blog/post", "/actuators-info-page-not"] {
            assert!(!matches("cms-probes", miss), "{miss} wrongly matched");
        }
    }

    #[test]
    fn the_empty_user_agent_preset_renders_a_condition_that_fires_without_the_header() {
        let rules = preset("scanners").map(|p| p.rules).unwrap_or_default();
        let empty = rules
            .iter()
            .find(|r| r.name == "Empty user agent")
            .map(|r| r.matchers.user_agent_regexes.clone());
        assert_eq!(empty, Some(vec!["^$".to_string()]));
    }

    #[test]
    fn scanner_user_agents() {
        let p = preset("scanners");
        let re = p.and_then(|p| p.rules[0].matchers.user_agent_regexes.first().cloned());
        let re = re.and_then(|r| Regex::new(&r).ok());
        assert!(
            re.as_ref()
                .is_some_and(|r| r.is_match("Mozilla/5.0 SQLMap/1.7"))
        );
        assert!(
            re.as_ref()
                .is_some_and(|r| !r.is_match("Mozilla/5.0 (Macintosh) Safari/605"))
        );
    }
}
