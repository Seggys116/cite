use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use cite_client::{
    DopplerBindRequest, DopplerBinding, DopplerConfig, DopplerInfo, DopplerProject, EnvPatch,
    TokenStatus, VolumeInfo,
};
use cite_edge::model::{Site, Slot, Volume};
use cite_edge::status::{
    DeployOutcome, LastFailure, LogLine, LogsResponse, ManagerReport, SiteStatus, SlotStatus,
};
use serde_json::json;

use crate::demo::iso;

const DEMO_FAILURE: &str = "green slot did not pass health checks within 60s";
// The last lines of build output the node appends to a failure note, one per line after the reason.
const DEMO_BUILD_TAIL: &str = "> docs@1.4.0 start\n> astro preview --port 3000\n[astro] Starting preview server\nError: listen EADDRINUSE: address already in use :::3000\n    at Server.setupListenHandle (node:net:1817:16)\n    at listenInCluster (node:net:1865:12)\nprocess exited with code 1";
const BASE_LINES: u64 = 120;

fn demo_failure_note() -> String {
    format!("{DEMO_FAILURE}\n{DEMO_BUILD_TAIL}")
}

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
        error: failing.then(demo_failure_note),
        active: site.active,
        operation: None,
        last_failure: failing.then(|| LastFailure {
            at: iso(now_ms - 8 * 60_000),
            slot: Some(site.active.other()),
            note: demo_failure_note(),
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

// A volume the demo node holds data for, whether or not the site still declares it.
#[derive(Clone, Debug)]
struct DemoVolume {
    name: String,
    mount_path: String,
    size_bytes: u64,
    created_ms: i64,
}

#[derive(Default)]
pub struct DemoOps {
    site_tokens: BTreeSet<String>,
    build_env: BTreeMap<String, BTreeSet<String>>,
    runtime_env: BTreeMap<String, BTreeSet<String>>,
    volumes: BTreeMap<String, Vec<DemoVolume>>,
}

const MIB: u64 = 1024 * 1024;

impl DemoOps {
    pub fn seeded() -> Self {
        let names = |list: &[&str]| list.iter().map(|n| n.to_string()).collect::<BTreeSet<_>>();
        let now = crate::demo::now_ms();
        let day = 86_400_000;
        let volume = |name: &str, path: &str, size: u64, days: i64| DemoVolume {
            name: name.into(),
            mount_path: path.into(),
            size_bytes: size,
            created_ms: now - days * day,
        };
        Self {
            site_tokens: BTreeSet::new(),
            build_env: BTreeMap::from([("docs".to_string(), names(&["PUBLIC_SITE_URL"]))]),
            runtime_env: BTreeMap::from([("docs".to_string(), names(&["SEARCH_INDEX"]))]),
            volumes: BTreeMap::from([(
                "docs".to_string(),
                vec![
                    volume("data", "/data", 148 * MIB, 12),
                    volume("old-cache", "/cache", 12 * MIB, 40),
                ],
            )]),
        }
    }

    // What the node reports: every volume it holds, mounted when the site declares it.
    pub fn volume_infos(&self, site: &str, declared: &[Volume]) -> Vec<VolumeInfo> {
        self.volumes
            .get(site)
            .map(|list| {
                list.iter()
                    .map(|v| {
                        let live = declared.iter().find(|d| d.name == v.name);
                        VolumeInfo {
                            name: v.name.clone(),
                            mount_path: live
                                .map_or_else(|| v.mount_path.clone(), |d| d.mount_path.clone()),
                            size_bytes: Some(v.size_bytes),
                            mounted: live.is_some(),
                            created_at: Some(iso(v.created_ms)),
                            declared: live.is_some(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // Saving a site creates the volumes it newly declares and updates the paths of the ones it keeps.
    pub fn declare_volumes(&mut self, site: &str, declared: &[Volume], now_ms: i64) {
        let list = self.volumes.entry(site.to_string()).or_default();
        for d in declared {
            match list.iter_mut().find(|v| v.name == d.name) {
                Some(v) => v.mount_path = d.mount_path.clone(),
                None => list.push(DemoVolume {
                    name: d.name.clone(),
                    mount_path: d.mount_path.clone(),
                    size_bytes: 0,
                    created_ms: now_ms,
                }),
            }
        }
        list.sort_by(|a, b| a.name.cmp(&b.name));
    }

    // Like the node, data of a volume the site still declares cannot be deleted.
    pub fn delete_volume(
        &mut self,
        site: &str,
        declared: &[Volume],
        name: &str,
    ) -> Result<(), String> {
        if declared.iter().any(|d| d.name == name) {
            return Err(format!("volume {name} is still declared by the site"));
        }
        let list = self.volumes.entry(site.to_string()).or_default();
        let before = list.len();
        list.retain(|v| v.name != name);
        if list.len() == before {
            return Err(format!("volume {name} not found"));
        }
        Ok(())
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

pub fn doppler_info() -> DopplerInfo {
    DopplerInfo {
        configured: true,
        source: "env".into(),
    }
}

pub fn doppler_projects() -> Vec<DopplerProject> {
    [
        ("docs-site", "Docs site"),
        ("storefront", "Storefront"),
        ("shared", "Shared"),
    ]
    .into_iter()
    .map(|(slug, name)| DopplerProject {
        slug: slug.into(),
        name: name.into(),
    })
    .collect()
}

pub fn doppler_configs(project: &str) -> Vec<DopplerConfig> {
    let envs: &[(&str, &str)] = match project {
        "shared" => &[("prd", "Production")],
        _ => &[
            ("dev", "Development"),
            ("stg", "Staging"),
            ("prd", "Production"),
        ],
    };
    envs.iter()
        .map(|(name, environment)| DopplerConfig {
            name: (*name).into(),
            environment: (*environment).into(),
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DemoBinding {
    project: String,
    config: String,
    build: bool,
    runtime: bool,
    own_token: bool,
    synced_at: i64,
}

// The demo node keeps its bindings for the life of the app, keyed by node and site; tokens are never kept.
fn bindings() -> &'static Mutex<BTreeMap<(String, String), DemoBinding>> {
    static STORE: OnceLock<Mutex<BTreeMap<(String, String), DemoBinding>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

// A pretend variable count that differs per config, so switching config visibly changes it.
fn demo_keys(project: &str, config: &str) -> u32 {
    let h = short_hash(&format!("{project}/{config}"));
    6 + u32::from(h.as_bytes()[0] % 10)
}

fn render(b: Option<&DemoBinding>) -> DopplerBinding {
    match b {
        Some(b) => DopplerBinding {
            bound: true,
            project: Some(b.project.clone()).filter(|p| !p.is_empty()),
            config: Some(b.config.clone()).filter(|c| !c.is_empty()),
            build: b.build,
            runtime: b.runtime,
            token_source: if b.own_token { "site" } else { "node" }.into(),
            status: "synced".into(),
            last_sync_at: Some(iso(b.synced_at)),
            last_error: None,
            keys: demo_keys(&b.project, &b.config),
        },
        None => DopplerBinding {
            bound: false,
            project: None,
            config: None,
            build: false,
            runtime: false,
            token_source: "none".into(),
            status: "idle".into(),
            last_sync_at: None,
            last_error: None,
            keys: 0,
        },
    }
}

fn store_key(node: &str, site: &str) -> (String, String) {
    (node.to_string(), site.to_string())
}

pub fn doppler_binding(node: &str, site: &str) -> DopplerBinding {
    let store = bindings().lock().unwrap_or_else(|e| e.into_inner());
    render(store.get(&store_key(node, site)))
}

// Like the node: a blank project and config are taken from a service token (dp.st.), so only one will do.
pub fn doppler_bind(
    node: &str,
    site: &str,
    req: &DopplerBindRequest,
    now_ms: i64,
) -> Result<DopplerBinding, String> {
    let mut store = bindings().lock().unwrap_or_else(|e| e.into_inner());
    let typed = req
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let token_only = req.project.trim().is_empty() && req.config.trim().is_empty();
    let kept_token = store
        .get(&store_key(node, site))
        .is_some_and(|b| b.own_token);
    let token_ok = match typed {
        Some(t) => t.starts_with("dp.st."),
        None => kept_token,
    };
    if token_only && !token_ok {
        return Err("a blank project and config need a service token (dp.st.)".into());
    }
    if req.project.trim().is_empty() != req.config.trim().is_empty() {
        return Err("project and config must be given together, or both left blank".into());
    }
    let own_token = typed.is_some() || kept_token;
    let b = DemoBinding {
        project: req.project.clone(),
        config: req.config.clone(),
        build: req.build,
        runtime: req.runtime,
        own_token,
        synced_at: now_ms,
    };
    store.insert(store_key(node, site), b.clone());
    Ok(render(Some(&b)))
}

pub fn doppler_clear(node: &str, site: &str) -> DopplerBinding {
    let mut store = bindings().lock().unwrap_or_else(|e| e.into_inner());
    store.remove(&store_key(node, site));
    render(None)
}

pub fn doppler_sync(node: &str, site: &str, now_ms: i64) -> DopplerBinding {
    let mut store = bindings().lock().unwrap_or_else(|e| e.into_inner());
    let found = store.get_mut(&store_key(node, site));
    match found {
        Some(b) => {
            b.synced_at = now_ms;
            render(Some(&*b))
        }
        None => render(None),
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
            volumes: Vec::new(),
            outbound: true,
            outbound_rules: Default::default(),
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
        let note = st.error.clone().expect("error");
        assert!(note.starts_with(DEMO_FAILURE) && note.lines().count() > 3);
        assert_eq!(crate::diagnose::split_note(&note).reason, DEMO_FAILURE);
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
    fn demo_doppler_binds_syncs_and_clears_per_node_and_site() {
        let node = "demo-doppler-test";
        assert!(!doppler_binding(node, "docs").bound);
        assert!(doppler_info().configured);
        assert_eq!(doppler_projects().len(), 3);
        assert_eq!(doppler_configs("shared").len(), 1);
        assert_eq!(doppler_configs("docs-site")[2].name, "prd");
        let req = DopplerBindRequest {
            project: "docs-site".into(),
            config: "prd".into(),
            build: true,
            runtime: false,
            token: None,
        };
        let b = doppler_bind(node, "docs", &req, 1_700_000_000_000).unwrap();
        assert!(b.bound && b.build && !b.runtime && b.status == "synced");
        assert_eq!(b.token_source, "node");
        assert!(b.keys >= 6);
        assert!(!doppler_binding(node, "shop").bound);
        assert!(!doppler_binding("other-node", "docs").bound);
        let later = doppler_sync(node, "docs", 1_700_000_060_000);
        assert_eq!(later.last_sync_at, Some(iso(1_700_000_060_000)));
        let own = DopplerBindRequest {
            project: "docs-site".into(),
            config: "prd".into(),
            build: true,
            runtime: false,
            token: Some("dp.st.x".into()),
        };
        assert_eq!(
            doppler_bind(node, "docs", &own, 0).unwrap().token_source,
            "site"
        );
        assert!(!doppler_clear(node, "docs").bound);
        assert!(!doppler_sync(node, "docs", 0).bound);
    }

    #[test]
    fn demo_doppler_takes_project_and_config_from_a_service_token() {
        let node = "demo-doppler-token-only";
        let req = |project: &str, config: &str, token: Option<&str>| DopplerBindRequest {
            project: project.into(),
            config: config.into(),
            build: true,
            runtime: true,
            token: token.map(str::to_string),
        };
        assert!(doppler_bind(node, "docs", &req("", "", None), 0).is_err());
        assert!(doppler_bind(node, "docs", &req("", "", Some("dp.pt.x")), 0).is_err());
        assert!(doppler_bind(node, "docs", &req("web", "", Some("dp.st.x")), 0).is_err());
        assert!(!doppler_binding(node, "docs").bound);
        let b = doppler_bind(node, "docs", &req("", "", Some("dp.st.x")), 5).unwrap();
        assert!(b.bound && b.project.is_none() && b.config.is_none());
        assert_eq!(b.token_source, "site");
        assert!(b.keys >= 6);
        let again = doppler_bind(node, "docs", &req("", "", None), 6).unwrap();
        assert_eq!(again.token_source, "site");
        assert!(!doppler_clear(node, "docs").bound);
    }

    #[test]
    fn demo_volumes_are_created_kept_and_deleted_like_the_node_does() {
        let mut ops = DemoOps::seeded();
        let data = Volume {
            name: "data".into(),
            mount_path: "/data".into(),
        };
        let infos = ops.volume_infos("docs", std::slice::from_ref(&data));
        let by = |n: &str| infos.iter().position(|i| i.name == n).expect(n);
        assert!(infos[by("data")].mounted && infos[by("data")].size_bytes.is_some());
        assert!(!infos[by("old-cache")].mounted);
        assert!(ops.volume_infos("shop", &[]).is_empty());
        let fresh = Volume {
            name: "uploads".into(),
            mount_path: "/srv/uploads".into(),
        };
        ops.declare_volumes("shop", std::slice::from_ref(&fresh), 1_700_000_000_000);
        let shop = ops.volume_infos("shop", std::slice::from_ref(&fresh));
        assert_eq!(
            (shop.len(), shop[0].size_bytes, shop[0].mounted),
            (1, Some(0), true)
        );
        assert_eq!(shop[0].created_at, Some(iso(1_700_000_000_000)));
        assert!(
            ops.delete_volume("docs", std::slice::from_ref(&data), "data")
                .unwrap_err()
                .contains("still declared")
        );
        assert!(
            ops.delete_volume("docs", &[], "missing")
                .unwrap_err()
                .contains("not found")
        );
        assert!(ops.delete_volume("docs", &[], "old-cache").is_ok());
        let after = ops.volume_infos("docs", std::slice::from_ref(&data));
        assert_eq!(after.len(), 1);
        let moved = Volume {
            name: "data".into(),
            mount_path: "/srv/data".into(),
        };
        ops.declare_volumes("docs", std::slice::from_ref(&moved), 0);
        assert_eq!(
            ops.volume_infos("docs", std::slice::from_ref(&moved))[0].mount_path,
            "/srv/data"
        );
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
