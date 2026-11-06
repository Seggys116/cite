use std::collections::{BTreeMap, BTreeSet};

use cite_client::{EnvPatch, TokenStatus};
use cite_edge::model::{Site, Slot};
use cite_edge::status::{
    DeployOutcome, LastFailure, LogLine, LogsResponse, ManagerReport, SiteStatus, SlotStatus,
};
use serde_json::json;

use crate::demo::iso;

const DEMO_FAILURE: &str = "green slot did not pass health checks within 60s";
const BASE_LINES: u64 = 120;

// The docs site is the one whose last build failed, so the status panel has a failure to explain.
pub fn is_failing(site: &Site) -> bool {
    site.id == "docs" && site.source.is_some()
}

fn short_hash(text: &str) -> String {
    let h = text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |a, b| {
        (a ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{h:016x}{:024x}", h.rotate_left(17))
}

fn detected() -> serde_json::Value {
    json!({
        "package_manager": "pnpm",
        "framework": "astro",
        "rendering": "static",
        "root_dir": ".",
        "output_dir": "dist",
        "install_command": "pnpm install --frozen-lockfile",
        "build_command": "pnpm build",
        "prune": true,
    })
}

fn slot_status(site: &Site, slot: Slot, failing: bool, now_ms: i64) -> SlotStatus {
    let live = site.active == slot;
    let bad = failing && !live;
    let sha = short_hash(&format!("{}{}", site.id, slot.as_str()));
    let outcome = DeployOutcome {
        id: format!("d-{}-{}", site.id, slot.as_str()),
        result: if bad { "failed" } else { "ok" }.into(),
        sha: Some(sha.clone()),
        reason: bad.then(|| DEMO_FAILURE.to_string()),
        started_at: Some(iso(now_ms - 9 * 60_000)),
        finished_at: Some(iso(now_ms - 8 * 60_000)),
    };
    SlotStatus {
        slot,
        container: format!("cite-{}-{}-manager", site.id, slot.as_str()),
        health: if bad { "unhealthy" } else { "healthy" }.into(),
        restart_count: if bad { 4 } else { 0 },
        exit_code: bad.then_some(1),
        oom_killed: false,
        report: Some(ManagerReport {
            v: 1,
            phase: if bad { "failed" } else { "idle" }.into(),
            deploy: Some(outcome),
            head_sha: Some(short_hash(&format!("{}head", site.id))),
            live_sha: (!bad).then_some(sha),
            last_build_secs: Some(74),
            last_error: bad.then(|| DEMO_FAILURE.to_string()),
            token: Some("node".into()),
            detected: Some(detected()),
            ..ManagerReport::default()
        }),
        haproxy: Some(if bad { "DOWN" } else { "UP" }.into()),
        haproxy_check: Some(if bad { "L4CON" } else { "L7OK" }.into()),
    }
}

pub fn status_for(site: &Site, now_ms: i64) -> SiteStatus {
    if site.source.is_none() {
        return SiteStatus {
            phase: "idle".into(),
            active: site.active,
            settings_current: true,
            checked_at: iso(now_ms),
            ..SiteStatus::default()
        };
    }
    let failing = is_failing(site);
    SiteStatus {
        phase: if failing { "failed" } else { "idle" }.into(),
        error: failing.then(|| DEMO_FAILURE.to_string()),
        active: site.active,
        operation: None,
        last_failure: failing.then(|| LastFailure {
            at: iso(now_ms - 8 * 60_000),
            slot: Some(site.active.other()),
            note: DEMO_FAILURE.into(),
        }),
        slots: [Slot::Blue, Slot::Green]
            .into_iter()
            .map(|s| slot_status(site, s, failing, now_ms))
            .collect(),
        settings_current: !failing,
        checked_at: iso(now_ms),
    }
}

fn manager_line(i: u64, failing: bool) -> (String, Option<&'static str>, &'static str) {
    const PHASES: [&str; 4] = ["fetch", "install", "build", "pack"];
    let phase = PHASES[(i / 30 % 4) as usize];
    match i % 6 {
        0 => (
            format!("\u{1b}[32mok\u{1b}[0m step {i} finished"),
            Some("info"),
            phase,
        ),
        1 => (format!("resolving packages ({i})"), None, phase),
        2 if failing => (
            format!("\u{1b}[33mwarning:\u{1b}[0m slow registry response at {i}"),
            Some("warn"),
            phase,
        ),
        3 if failing && i % 12 == 3 => (
            format!("\u{1b}[31merror:\u{1b}[0m health check failed (attempt {i})"),
            Some("error"),
            phase,
        ),
        _ => (format!("compiling module {i}"), None, phase),
    }
}

fn executor_line(i: u64) -> (String, Option<&'static str>, &'static str) {
    (
        format!("GET /docs/page-{} 200 {}ms", i % 17, 4 + i % 23),
        None,
        "serve",
    )
}

// Lines are numbered from zero; a cursor is "c" and the number of the next line, so a poll asks for exactly what came after.
pub fn logs_for(
    failing: bool,
    source: &str,
    tail: Option<u32>,
    since: Option<&str>,
    total: u64,
) -> LogsResponse {
    let first = match since
        .and_then(|s| s.strip_prefix('c'))
        .and_then(|n| n.parse::<u64>().ok())
    {
        Some(n) => n.min(total),
        None => total.saturating_sub(u64::from(tail.unwrap_or(200))),
    };
    let lines = (first..total)
        .map(|i| {
            let (text, level, phase) = if source == "executor" {
                executor_line(i)
            } else {
                manager_line(i, failing)
            };
            LogLine {
                ts: Some(iso(1_700_000_000_000 + i as i64 * 1000)),
                stream: if level == Some("error") {
                    "stderr"
                } else {
                    "stdout"
                }
                .into(),
                level: level.map(str::to_string),
                phase: Some(phase.to_string()),
                text,
            }
        })
        .collect();
    LogsResponse {
        lines,
        cursor: Some(format!("c{total}")),
        truncated: false,
    }
}

// The log grows by one line every two seconds from the moment the node started.
pub fn log_total(elapsed_secs: u64) -> u64 {
    BASE_LINES + elapsed_secs / 2
}

#[derive(Default)]
pub struct DemoOps {
    site_tokens: BTreeSet<String>,
    build_env: BTreeMap<String, BTreeSet<String>>,
    runtime_env: BTreeMap<String, BTreeSet<String>>,
}

impl DemoOps {
    pub fn seeded() -> Self {
        let names = |list: &[&str]| list.iter().map(|n| n.to_string()).collect::<BTreeSet<_>>();
        Self {
            site_tokens: BTreeSet::new(),
            build_env: BTreeMap::from([("docs".to_string(), names(&["PUBLIC_SITE_URL"]))]),
            runtime_env: BTreeMap::from([("docs".to_string(), names(&["SEARCH_INDEX"]))]),
        }
    }

    pub fn token_status(&self, site: &str, node_token: bool) -> TokenStatus {
        let own = self.site_tokens.contains(site);
        TokenStatus {
            source: if own {
                "site"
            } else if node_token {
                "node"
            } else {
                "none"
            }
            .into(),
            site_token_set: own,
            node_token_configured: node_token,
            status: (own || node_token).then(|| "valid".to_string()),
            expires_at: own.then(|| "2027-03-01".to_string()),
            verified: (own || node_token).then_some(true),
        }
    }

    pub fn set_token(&mut self, site: &str) {
        self.site_tokens.insert(site.to_string());
    }

    pub fn clear_token(&mut self, site: &str) {
        self.site_tokens.remove(site);
    }

    fn env(&mut self, runtime: bool) -> &mut BTreeMap<String, BTreeSet<String>> {
        if runtime {
            &mut self.runtime_env
        } else {
            &mut self.build_env
        }
    }

    pub fn names(&self, site: &str, runtime: bool) -> Vec<String> {
        let map = if runtime {
            &self.runtime_env
        } else {
            &self.build_env
        };
        map.get(site)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    // Values are never kept: like the node, the demo remembers names only.
    pub fn patch(&mut self, site: &str, runtime: bool, patch: &EnvPatch) -> Vec<String> {
        let set = self.env(runtime).entry(site.to_string()).or_default();
        set.extend(patch.set.keys().cloned());
        for name in &patch.unset {
            set.remove(name);
        }
        self.names(site, runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::Source;

    fn site(id: &str, source: bool) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: vec![format!("{id}.example.com")],
            path_prefixes: Vec::new(),
            path_regexes: Vec::new(),
            kind: cite_edge::model::SiteKind::Site,
            blue: Default::default(),
            green: Default::default(),
            active: Slot::Blue,
            maintenance: Default::default(),
            health: Default::default(),
            source: source.then(|| Source {
                repo: "acme/x".into(),
                ..Default::default()
            }),
            history: Vec::new(),
            access: Default::default(),
        }
    }

    #[test]
    fn only_the_docs_source_site_is_failing() {
        assert!(is_failing(&site("docs", true)));
        assert!(!is_failing(&site("docs", false)));
        assert!(!is_failing(&site("shop", true)));
    }

    #[test]
    fn a_failing_site_reports_its_idle_slot_down() {
        let st = status_for(&site("docs", true), 1_700_000_000_000);
        assert_eq!(st.phase, "failed");
        assert!(!st.settings_current);
        assert_eq!(st.error.as_deref(), Some(DEMO_FAILURE));
        let bad = st
            .slots
            .iter()
            .find(|s| s.slot == Slot::Green)
            .expect("green");
        assert_eq!(
            (bad.health.as_str(), bad.exit_code, bad.restart_count),
            ("unhealthy", Some(1), 4)
        );
        assert_eq!(bad.container, "cite-docs-green-manager");
        let good = st
            .slots
            .iter()
            .find(|s| s.slot == Slot::Blue)
            .expect("blue");
        assert_eq!(good.health, "healthy");
        assert!(good.report.as_ref().is_some_and(|r| r.live_sha.is_some()));
    }

    #[test]
    fn healthy_and_plain_sites_are_idle() {
        let ok = status_for(&site("shop", true), 0);
        assert_eq!(ok.phase, "idle");
        assert!(ok.settings_current && ok.error.is_none() && ok.slots.len() == 2);
        let plain = status_for(&site("api", false), 0);
        assert!(plain.slots.is_empty() && plain.phase == "idle");
    }

    #[test]
    fn logs_tail_then_follow_the_cursor() {
        let first = logs_for(false, "manager", Some(10), None, 130);
        assert_eq!(first.lines.len(), 10);
        assert_eq!(first.cursor.as_deref(), Some("c130"));
        let next = logs_for(false, "manager", None, first.cursor.as_deref(), 133);
        assert_eq!(next.lines.len(), 3);
        assert_eq!(next.cursor.as_deref(), Some("c133"));
        let none = logs_for(false, "manager", None, Some("c133"), 133);
        assert!(none.lines.is_empty());
        let ahead = logs_for(false, "manager", None, Some("c999"), 133);
        assert!(ahead.lines.is_empty());
        assert_eq!(logs_for(false, "manager", None, None, 500).lines.len(), 200);
        assert_eq!(logs_for(false, "manager", Some(5), None, 2).lines.len(), 2);
    }

    #[test]
    fn manager_logs_have_colour_and_failures_have_errors() {
        let ok = logs_for(false, "manager", Some(60), None, 130);
        assert!(ok.lines.iter().any(|l| l.text.contains('\u{1b}')));
        assert!(ok.lines.iter().all(|l| l.level.as_deref() != Some("error")));
        let bad = logs_for(true, "manager", Some(60), None, 130);
        assert!(
            bad.lines
                .iter()
                .any(|l| l.level.as_deref() == Some("error") && l.stream == "stderr")
        );
        let exec = logs_for(false, "executor", Some(5), None, 130);
        assert!(exec.lines.iter().all(|l| l.text.starts_with("GET ")));
        assert_eq!(log_total(0), BASE_LINES);
        assert_eq!(log_total(10), BASE_LINES + 5);
    }

    #[test]
    fn tokens_and_environments_remember_names_only() {
        let mut ops = DemoOps::seeded();
        assert_eq!(ops.token_status("docs", false).source, "none");
        assert_eq!(ops.token_status("docs", true).source, "node");
        ops.set_token("docs");
        let own = ops.token_status("docs", true);
        assert!(own.site_token_set && own.source == "site" && own.verified == Some(true));
        ops.clear_token("docs");
        assert_eq!(ops.token_status("docs", true).source, "node");
        assert_eq!(ops.names("docs", false), vec!["PUBLIC_SITE_URL"]);
        let mut patch = EnvPatch::default();
        patch.set.insert("API_BASE".into(), "x".into());
        patch.unset.push("PUBLIC_SITE_URL".into());
        assert_eq!(ops.patch("docs", false, &patch), vec!["API_BASE"]);
        assert_eq!(ops.names("docs", true), vec!["SEARCH_INDEX"]);
        assert!(ops.names("shop", true).is_empty());
    }
}
