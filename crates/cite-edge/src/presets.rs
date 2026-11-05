use crate::model::{FirewallAction, FirewallRule, Matchers};

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
        action,
        matchers: Matchers {
            path_regex: Some(re.to_string()),
            ..Default::default()
        },
        site: None,
    }
}

fn ua_rule(preset: &str, n: usize, title: &str, action: FirewallAction, re: &str) -> FirewallRule {
    FirewallRule {
        id: format!("preset-{preset}-{n}"),
        name: title.to_string(),
        enabled: true,
        action,
        matchers: Matchers {
            user_agent_regex: Some(re.to_string()),
            ..Default::default()
        },
        site: None,
    }
}

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
            path_rule(
                p,
                2,
                "Private keys and keystores",
                drop,
                r"(?i)((^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*|(^|/)[^/]*(privkey|private)[^/]*\.pem|\.(key|p12|pfx|jks|keystore))(;[^/]*)?$",
            ),
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
                r"(?i)(\.(sql|bak|swp|swo|orig|old|save)|~)(;[^/]*)?$",
            ),
            path_rule(
                p,
                5,
                "Backup archives",
                drop,
                r"(?i)(^|/)(backup|backups|dump|dumps|db|database|www|site|public_html)[^/]*\.(zip|tar|tgz|gz|7z|rar)(;[^/]*)?$",
            ),
            path_rule(
                p,
                6,
                "Build and dependency manifests",
                drop,
                r"(?i)(^|/)(docker-compose[^/]*\.ya?ml|dockerfile[^/]*|composer\.(json|lock))(;[^/]*)?$",
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
            path_rule(
                p,
                2,
                "Database admin tools",
                drop,
                r"(?i)/(phpmyadmin|pma|myadmin|mysqladmin)(;[^/]*)?(/|$)",
            ),
            path_rule(
                p,
                3,
                "Known exploit paths",
                drop,
                r"(?i)/(vendor/phpunit|cgi-bin|boaform|HNAP1)",
            ),
            path_rule(
                p,
                4,
                "Java and router consoles",
                drop,
                r"(?i)/(actuator|solr|manager(;[^/]*)?/html)(;[^/]*)?(/|$)",
            ),
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
            ua_rule(
                p,
                1,
                "Scanner user agents",
                tar,
                "(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|havij)",
            ),
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
            action: FirewallAction::Deny,
            matchers: Matchers {
                methods: ["TRACE", "TRACK", "CONNECT", "DEBUG"]
                    .map(String::from)
                    .to_vec(),
                ..Default::default()
            },
            site: None,
        }],
    }
}

pub fn presets() -> Vec<Preset> {
    vec![sensitive_files(), cms_probes(), scanners(), odd_methods()]
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
        assert_eq!(presets().len(), 4);
    }

    #[test]
    fn actions_follow_the_design() {
        let action =
            |n: &str| preset(n).map(|p| p.rules.iter().map(|r| r.action).collect::<Vec<_>>());
        assert!(
            action("sensitive-files").is_some_and(|a| a.iter().all(|x| *x == FirewallAction::Drop))
        );
        assert!(action("cms-probes").is_some_and(|a| a.iter().all(|x| *x == FirewallAction::Drop)));
        assert!(action("scanners").is_some_and(|a| a.iter().all(|x| *x == FirewallAction::Tarpit)));
        assert_eq!(action("odd-methods"), Some(vec![FirewallAction::Deny]));
    }

    fn matches(preset_name: &str, path: &str) -> bool {
        preset(preset_name).is_some_and(|p| {
            p.rules
                .iter()
                .filter_map(|r| r.matchers.path_regex.as_deref())
                .any(|re| Regex::new(re).is_ok_and(|re| re.is_match(path)))
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
            .map(|r| r.matchers.user_agent_regex.clone());
        assert_eq!(empty, Some(Some("^$".to_string())));
    }

    #[test]
    fn scanner_user_agents() {
        let p = preset("scanners");
        let re = p.and_then(|p| p.rules[0].matchers.user_agent_regex.clone());
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
