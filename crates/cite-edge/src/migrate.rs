// Brings a config saved by an earlier release in line with the current regex grammar, so a node never fails to start over rules it saved itself.
use std::collections::HashMap;

use crate::model::{EdgeConfig, FirewallRule};
use crate::pattern::Subject;
use crate::presets::presets;
use crate::validate::{validate_regex, validate_rule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationKind {
    /// One regex field that held a pattern of an earlier release was rewritten to the current preset's.
    Replaced,
    /// A rule the current validation refuses was switched off and left in the file.
    Disabled,
    /// A site path_regex the current grammar refuses; the site is left untouched.
    SiteRegexInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationNote {
    /// The rule id, or the site id for SiteRegexInvalid.
    pub id: String,
    pub what: MigrationKind,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Path,
}

impl Field {
    fn name(self) -> &'static str {
        match self {
            Field::Path => "path_regex",
        }
    }

    fn slot(self, rule: &mut FirewallRule) -> &mut Option<String> {
        match self {
            Field::Path => &mut rule.matchers.path_regex,
        }
    }
}

// (preset rule id, field, the exact regex an earlier release stored). Their repeats are too costly for the current limits; the current preset holds the equivalent.
const KNOWN_OLD_REGEXES: [(&str, Field, &str); 6] = [
    (
        "preset-sensitive-files-2",
        Field::Path,
        r"(?i)((^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*|(^|/)[^/]*(privkey|private)[^/]*\.pem|\.(key|p12|pfx|jks|keystore))(;[^/]*)?$",
    ),
    (
        "preset-sensitive-files-4",
        Field::Path,
        r"(?i)(\.(sql|bak|swp|swo|orig|old|save)|~)(;[^/]*)?$",
    ),
    (
        "preset-sensitive-files-5",
        Field::Path,
        r"(?i)(^|/)(backup|backups|dump|dumps|db|database|www|site|public_html)[^/]*\.(zip|tar|tgz|gz|7z|rar)(;[^/]*)?$",
    ),
    (
        "preset-sensitive-files-6",
        Field::Path,
        r"(?i)(^|/)(docker-compose[^/]*\.ya?ml|dockerfile[^/]*|composer\.(json|lock))(;[^/]*)?$",
    ),
    (
        "preset-cms-probes-2",
        Field::Path,
        r"(?i)/(phpmyadmin|pma|myadmin|mysqladmin)(;[^/]*)?(/|$)",
    ),
    (
        "preset-cms-probes-4",
        Field::Path,
        r"(?i)/(actuator|solr|manager(;[^/]*)?/html)(;[^/]*)?(/|$)",
    ),
];

/// Rewrites only regex fields holding a known earlier-release pattern, disables other enabled rules that fail validation and reports bad site regexes; valid owner edits are never touched.
pub fn migrate_loaded_config(cfg: &mut EdgeConfig) -> Vec<MigrationNote> {
    let current: HashMap<String, FirewallRule> = presets()
        .into_iter()
        .flat_map(|p| p.rules)
        .map(|r| (r.id.clone(), r))
        .collect();
    let mut notes = Vec::new();
    for rule in &mut cfg.firewall {
        for (id, field, old) in KNOWN_OLD_REGEXES {
            if rule.id != id || field.slot(rule).as_deref() != Some(old) {
                continue;
            }
            let Some(mut now) = current.get(id).cloned() else {
                continue;
            };
            *field.slot(rule) = field.slot(&mut now).take();
            notes.push(MigrationNote {
                id: rule.id.clone(),
                what: MigrationKind::Replaced,
                reason: format!(
                    "{} was updated to the current preset's pattern",
                    field.name()
                ),
            });
        }
        if rule.enabled
            && let Err(e) = validate_rule(rule)
        {
            rule.enabled = false;
            notes.push(MigrationNote {
                id: rule.id.clone(),
                what: MigrationKind::Disabled,
                reason: e.to_string(),
            });
        }
    }
    for site in &cfg.sites {
        if let Some(re) = &site.path_regex
            && let Err(e) =
                validate_regex(&format!("site {} path_regex", site.id), re, Subject::Path)
        {
            notes.push(MigrationNote {
                id: site.id.clone(),
                what: MigrationKind::SiteRegexInvalid,
                reason: e.to_string(),
            });
        }
    }
    notes
}

/// True when migrate_loaded_config would change or report something.
pub fn needs_migration(cfg: &EdgeConfig) -> bool {
    !migrate_loaded_config(&mut cfg.clone()).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Matchers;
    use crate::presets::preset;
    use crate::validate::fixtures::{config, rule, site};
    use crate::validate::validate_config;

    // The regexes of main's presets.rs, by preset rule id.
    const MAIN_REGEXES: [(&str, &str); 6] = [
        (
            "preset-sensitive-files-2",
            r"(?i)((^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*|(^|/)[^/]*(privkey|private)[^/]*\.pem|\.(key|p12|pfx|jks|keystore))(;[^/]*)?$",
        ),
        (
            "preset-sensitive-files-4",
            r"(?i)(\.(sql|bak|swp|swo|orig|old|save)|~)(;[^/]*)?$",
        ),
        (
            "preset-sensitive-files-5",
            r"(?i)(^|/)(backup|backups|dump|dumps|db|database|www|site|public_html)[^/]*\.(zip|tar|tgz|gz|7z|rar)(;[^/]*)?$",
        ),
        (
            "preset-sensitive-files-6",
            r"(?i)(^|/)(docker-compose[^/]*\.ya?ml|dockerfile[^/]*|composer\.(json|lock))(;[^/]*)?$",
        ),
        (
            "preset-cms-probes-2",
            r"(?i)/(phpmyadmin|pma|myadmin|mysqladmin)(;[^/]*)?(/|$)",
        ),
        (
            "preset-cms-probes-4",
            r"(?i)/(actuator|solr|manager(;[^/]*)?/html)(;[^/]*)?(/|$)",
        ),
    ];

    fn current_rule(id: &str) -> FirewallRule {
        presets()
            .into_iter()
            .flat_map(|p| p.rules)
            .find(|r| r.id == id)
            .expect("preset rule")
    }

    // The two presets as main stored them: current rules with the old regexes put back.
    fn main_saved_rules() -> Vec<FirewallRule> {
        let mut rules = Vec::new();
        for name in ["sensitive-files", "cms-probes"] {
            for mut r in preset(name).expect("preset").rules {
                if let Some((_, old)) = MAIN_REGEXES.iter().find(|(id, _)| *id == r.id) {
                    r.matchers.path_regex = Some(old.to_string());
                }
                rules.push(r);
            }
        }
        rules
    }

    fn user_rule(id: &str, ua: &str) -> FirewallRule {
        rule(
            id,
            Matchers {
                user_agent_regex: Some(ua.to_string()),
                ..Matchers::default()
            },
        )
    }

    #[test]
    fn the_table_matches_main_and_points_at_the_current_presets() {
        assert_eq!(KNOWN_OLD_REGEXES.len(), MAIN_REGEXES.len());
        for (id, field, old) in KNOWN_OLD_REGEXES {
            assert!(MAIN_REGEXES.contains(&(id, old)), "{id}");
            let now = current_rule(id);
            assert!(field == Field::Path && now.matchers.path_regex.is_some());
            assert_ne!(now.matchers.path_regex.as_deref(), Some(old));
        }
    }

    #[test]
    fn exact_old_regexes_are_replaced_and_nothing_else_changes() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall = main_saved_rules();
        for r in &mut cfg.firewall {
            r.matchers.host = Some("a.com".to_string());
            r.matchers.cidrs = vec!["10.0.0.0/8".to_string()];
            r.site = Some("a".to_string());
            r.label = Some("mine".to_string());
        }
        cfg.firewall[1].enabled = false;
        let before = cfg.clone();
        let notes = migrate_loaded_config(&mut cfg);
        assert!(notes.iter().all(|n| n.what == MigrationKind::Replaced));
        assert_eq!(notes.len(), MAIN_REGEXES.len());
        for (was, now) in before.firewall.iter().zip(&cfg.firewall) {
            let mut expected = was.clone();
            if MAIN_REGEXES.iter().any(|(id, _)| *id == was.id) {
                expected.matchers.path_regex = current_rule(&was.id).matchers.path_regex;
            }
            assert!(now == &expected, "{} changed beyond its regex", was.id);
        }
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn plain_main_presets_become_the_current_presets() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall = main_saved_rules();
        migrate_loaded_config(&mut cfg);
        assert!(validate_config(&cfg).is_ok());
        for r in &cfg.firewall {
            assert!(
                r == &current_rule(&r.id),
                "{} differs from the preset",
                r.id
            );
        }
    }

    #[test]
    fn an_owner_edited_preset_is_never_touched() {
        let mut edited = current_rule("preset-scanners-1");
        edited.matchers.user_agent_regex = Some("(?i)(sqlmap|nikto|curl)".to_string());
        edited.matchers.host = Some("a.com".to_string());
        edited.matchers.cidrs = vec!["10.0.0.0/8".to_string()];
        let mut keys = current_rule("preset-sensitive-files-2");
        keys.matchers.path_regex = Some("(?i)\\.(key|pem)$".to_string());
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall = vec![edited, keys];
        let before = cfg.clone();
        for _ in 0..3 {
            assert!(migrate_loaded_config(&mut cfg).is_empty());
            assert_eq!(cfg, before);
        }
        assert!(!needs_migration(&cfg));
    }

    #[test]
    fn a_repurposed_preset_id_is_untouched() {
        let mut deny = rule(
            "preset-redirect-to-www-1",
            Matchers {
                path_prefix: Some("/admin".to_string()),
                ..Matchers::default()
            },
        );
        deny.site = Some("a".to_string());
        let mut other = rule(
            "preset-sensitive-files-2",
            Matchers {
                methods: vec!["PUT".to_string()],
                ..Matchers::default()
            },
        );
        other.enabled = false;
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall = vec![deny, other];
        let before = cfg.clone();
        assert!(migrate_loaded_config(&mut cfg).is_empty());
        assert_eq!(cfg, before);
    }

    #[test]
    fn custom_rules_the_grammar_refuses_are_disabled_not_deleted() {
        let bad = [".*bot.*", "[[:space:]]", "a{1001}", "(a+)+b"];
        let mut cfg = config(vec![site("a", "a.com")]);
        for (i, re) in bad.iter().enumerate() {
            cfg.firewall.push(user_rule(&format!("user-{i}"), re));
        }
        cfg.firewall.push(user_rule("fine", "(?i)badbot"));
        assert!(validate_config(&cfg).is_err());
        assert!(needs_migration(&cfg));
        let notes = migrate_loaded_config(&mut cfg);
        assert_eq!(notes.len(), bad.len());
        for (i, re) in bad.iter().enumerate() {
            let n = &notes[i];
            assert_eq!(n.id, format!("user-{i}"));
            assert_eq!(n.what, MigrationKind::Disabled);
            assert!(!n.reason.is_empty());
            let r = &cfg.firewall[i];
            assert!(!r.enabled);
            assert_eq!(r.matchers.user_agent_regex.as_deref(), Some(*re));
        }
        assert!(cfg.firewall[bad.len()].enabled);
        assert_eq!(cfg.firewall.len(), bad.len() + 1);
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn a_site_regex_the_grammar_refuses_is_reported_and_kept() {
        let mut s = site("a", "a.com");
        s.path_regex = Some("[[:alpha:]]+".to_string());
        let mut cfg = config(vec![s, site("b", "b.com")]);
        let before = cfg.sites.clone();
        let notes = migrate_loaded_config(&mut cfg);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, "a");
        assert_eq!(notes[0].what, MigrationKind::SiteRegexInvalid);
        assert_eq!(cfg.sites, before);
    }

    #[test]
    fn the_second_run_changes_nothing() {
        let mut cfg = config(vec![site("a", "a.com")]);
        cfg.firewall = main_saved_rules();
        cfg.firewall.push(user_rule("bad", ".*bot.*"));
        assert!(needs_migration(&cfg));
        let first = migrate_loaded_config(&mut cfg);
        assert_eq!(first.len(), MAIN_REGEXES.len() + 1);
        let after = cfg.clone();
        assert!(migrate_loaded_config(&mut cfg).is_empty());
        assert_eq!(cfg, after);
        assert!(!needs_migration(&cfg));
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn current_presets_and_valid_rules_are_a_no_op() {
        let mut cfg = config(vec![site("a", "a.com")]);
        for p in presets() {
            cfg.firewall.extend(p.rules);
        }
        cfg.firewall.push(user_rule("mine", "(?i)badbot"));
        let before = cfg.clone();
        assert!(!needs_migration(&cfg));
        assert!(migrate_loaded_config(&mut cfg).is_empty());
        assert_eq!(cfg, before);
    }

    #[test]
    fn a_disabled_rule_with_a_refused_regex_loads_but_enabling_it_is_validated() {
        let mut cfg = config(vec![site("a", "a.com")]);
        let mut r = user_rule("off", ".*bot.*");
        r.enabled = false;
        cfg.firewall.push(r);
        assert!(validate_config(&cfg).is_ok());
        assert!(validate_rule(&cfg.firewall[0]).is_err());
        cfg.firewall[0].enabled = true;
        assert!(validate_config(&cfg).is_err());
    }
}
