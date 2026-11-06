//! Build progress and the one-line health report Docker stores in `State.Health.Log[].Output`.

use std::time::Instant;

use cite_core::schema::{ExecutorStatus, ManagerState, Rendering, now_rfc3339};
use cite_core::{Detection, Redactor};
use serde::Serialize;
use serde_json::{Map, Value, json};

/// Docker keeps 4096 bytes of health output; the margin leaves room for the newline and the shell.
pub const REPORT_MAX_BYTES: usize = 3500;
const ERROR_FLOOR_BYTES: usize = 64;
const DETECTED_FIELD_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Fetching,
    Building,
    Packing,
    Promoting,
    Idle,
    Failed,
}

/// What detection and the operator overrides settled on for the current or latest attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detected {
    pub framework: String,
    pub package_manager: String,
    pub rendering: String,
    pub node: Option<String>,
    pub install_command: String,
    pub build_command: String,
}

impl Detected {
    pub fn from_detection(det: &Detection, rendering: Rendering) -> Self {
        Self {
            framework: det.framework.clone(),
            package_manager: det.package_manager.clone(),
            rendering: match rendering {
                Rendering::Static => "static",
                Rendering::Ssr => "ssr",
            }
            .into(),
            node: det.node_major.clone(),
            install_command: det.install_command.clone(),
            build_command: det.build_command.clone(),
        }
    }
}

/// Steps inside a build that the deployer turns into phases.
#[derive(Debug, Clone)]
pub enum BuildEvent {
    Detected(Detected),
    Packing,
}

#[derive(Debug, Clone)]
pub struct Progress {
    pub phase: Phase,
    pub since: String,
    pub sha: Option<String>,
    pub detected: Option<Detected>,
    pub last_build_secs: Option<u64>,
    attempt_started: Option<Instant>,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            since: now_rfc3339(),
            sha: None,
            detected: None,
            last_build_secs: None,
            attempt_started: None,
        }
    }
}

impl Progress {
    /// A new attempt starts at fetching and forgets the previous detection.
    pub fn begin(&mut self, sha: &str) {
        self.sha = Some(sha.to_string());
        self.detected = None;
        self.attempt_started = Some(Instant::now());
        self.enter(Phase::Fetching);
    }

    /// `since` only moves when the phase actually changes.
    pub fn enter(&mut self, phase: Phase) {
        if self.phase != phase {
            self.phase = phase;
            self.since = now_rfc3339();
        }
    }

    /// Ends the attempt in `phase`; the sha and detection stay for the report.
    pub fn end(&mut self, phase: Phase) {
        if let Some(started) = self.attempt_started.take() {
            self.last_build_secs = Some(started.elapsed().as_secs());
        }
        self.enter(phase);
    }
}

pub struct ReportParts<'a> {
    pub progress: &'a Progress,
    pub state: &'a ManagerState,
    pub status: Option<&'a ExecutorStatus>,
    pub token_verified: bool,
    /// Fingerprint of the token configured now; `None` when it cannot be read.
    pub token_fingerprint: Option<&'a str>,
}

/// One line of compact JSON, never longer than `REPORT_MAX_BYTES`.
pub fn build_report(parts: &ReportParts<'_>, redactor: &Redactor) -> String {
    fit_report(report_map(parts, redactor), REPORT_MAX_BYTES)
}

fn report_map(parts: &ReportParts<'_>, redactor: &Redactor) -> Map<String, Value> {
    let ReportParts {
        progress,
        state,
        status,
        token_verified,
        token_fingerprint,
    } = parts;
    let mut map = Map::new();
    map.insert("v".into(), json!(1));
    map.insert("phase".into(), json!(progress.phase));
    map.insert("since".into(), json!(progress.since));
    if progress.phase != Phase::Idle
        && let Some(sha) = &progress.sha
    {
        map.insert("sha".into(), json!(sha));
    }
    if let Some(outcome) = &state.last_outcome {
        map.insert(
            "deploy".into(),
            json!({"id": outcome.deploy_id, "result": outcome.result}),
        );
    }
    let optional = [
        (
            "head_sha",
            state.last_observed_sha.as_ref().map(|s| json!(s)),
        ),
        (
            "live_sha",
            state.last_deployed_sha.as_ref().map(|s| json!(s)),
        ),
        (
            "last_build_secs",
            progress.last_build_secs.map(|n| json!(n)),
        ),
        (
            "last_failed_sha",
            state.last_failed_sha.as_ref().map(|s| json!(s)),
        ),
        (
            "token_expires_at",
            state.token_expires_at.as_ref().map(|s| json!(s)),
        ),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            map.insert(key.into(), value);
        }
    }
    if let Some(reason) = state
        .last_failed_reason
        .as_deref()
        .filter(|r| !r.is_empty())
    {
        map.insert("last_error".into(), json!(redactor.redact_line(reason)));
    }
    // A persisted rejection only counts for the token it was recorded against.
    let rejected_current = state.token_invalid
        && token_fingerprint.is_some()
        && state.token_invalid_fingerprint.as_deref() == *token_fingerprint;
    let token = if rejected_current {
        "invalid"
    } else if *token_verified {
        "ok"
    } else {
        "unknown"
    };
    map.insert("token".into(), json!(token));
    if let Some(detected) = &progress.detected {
        map.insert("detected".into(), json!(detected));
    }
    if let Some(status) = status {
        map.insert(
            "executor".into(),
            json!({
                "active": status.active_slot,
                "blue": status.slots.blue.state,
                "green": status.slots.green.state,
            }),
        );
    }
    map
}

/// Shrinks the report until it fits: last_error first, then detected, then optional fields.
pub fn fit_report(mut map: Map<String, Value>, cap: usize) -> String {
    let fits = |map: &Map<String, Value>| rendered_len(map) <= cap;

    if let Some(Value::String(full)) = map.get("last_error").cloned() {
        let mut budget = full.len();
        loop {
            map.insert("last_error".into(), json!(ellipsize(&full, budget)));
            let len = rendered_len(&map);
            if len <= cap {
                return render(&map);
            }
            if budget <= ERROR_FLOOR_BYTES {
                break;
            }
            // Escapes can make a byte cost more than one on the wire, so the loop re-measures.
            budget = budget.saturating_sub(len - cap + 3).max(ERROR_FLOOR_BYTES);
        }
    }

    if let Some(Value::Object(mut detected)) = map.get("detected").cloned() {
        for value in detected.values_mut() {
            if let Value::String(text) = value {
                *text = ellipsize(text, DETECTED_FIELD_BYTES);
            }
        }
        map.insert("detected".into(), Value::Object(detected.clone()));
        if fits(&map) {
            return render(&map);
        }
        detected.remove("install_command");
        detected.remove("build_command");
        map.insert("detected".into(), Value::Object(detected));
        if fits(&map) {
            return render(&map);
        }
        map.remove("detected");
        if fits(&map) {
            return render(&map);
        }
    }

    for key in [
        "executor",
        "sha",
        "last_build_secs",
        "token_expires_at",
        "last_failed_sha",
        "last_error",
        "head_sha",
        "live_sha",
        "deploy",
    ] {
        if map.remove(key).is_some() && fits(&map) {
            break;
        }
    }
    render(&map)
}

fn rendered_len(map: &Map<String, Value>) -> usize {
    serde_json::to_string(map).map_or(usize::MAX, |line| line.len())
}

fn render(map: &Map<String, Value>) -> String {
    serde_json::to_string(map).unwrap_or_else(|_| "{\"v\":1}".into())
}

/// Keeps the start and the end of `text` with `...` between when it is longer than `max_bytes`.
pub fn ellipsize(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    if max_bytes <= 3 {
        return "...".chars().take(max_bytes).collect();
    }
    let keep = max_bytes - 3;
    let tail_len = keep / 2;
    let mut head_end = keep - tail_len;
    while !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = text.len() - tail_len;
    while !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!("{}...{}", &text[..head_end], &text[tail_start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_core::schema::{DeployOutcome, DeployResult, SlotState};

    fn detected(size: usize) -> Detected {
        Detected {
            framework: "f".repeat(size),
            package_manager: "pnpm".into(),
            rendering: "ssr".into(),
            node: Some("22".into()),
            install_command: "i".repeat(size),
            build_command: "b".repeat(size),
        }
    }

    fn parts_with(
        progress: &Progress,
        state: &ManagerState,
        status: Option<&ExecutorStatus>,
    ) -> String {
        build_report(
            &ReportParts {
                progress,
                state,
                status,
                token_verified: true,
                token_fingerprint: None,
            },
            &Redactor::new(),
        )
    }

    fn outcome(id: &str) -> DeployOutcome {
        DeployOutcome {
            deploy_id: id.into(),
            result: DeployResult::Failed,
            sha: Some("a".repeat(40)),
            reason: "boom".into(),
            started_at: "2026-01-01T00:00:00Z".into(),
            finished_at: "2026-01-01T00:01:00Z".into(),
        }
    }

    #[test]
    fn progress_walks_the_phases_and_keeps_detection_after_the_attempt() {
        let mut progress = Progress::default();
        assert_eq!(progress.phase, Phase::Idle);
        progress.begin(&"a".repeat(40));
        assert_eq!(progress.phase, Phase::Fetching);
        assert!(progress.detected.is_none());
        progress.enter(Phase::Building);
        progress.detected = Some(detected(5));
        progress.enter(Phase::Packing);
        progress.enter(Phase::Promoting);
        assert_eq!(progress.phase, Phase::Promoting);
        progress.end(Phase::Idle);
        assert_eq!(progress.phase, Phase::Idle);
        assert!(progress.detected.is_some(), "kept for the report");
        assert!(progress.last_build_secs.is_some());
        progress.begin(&"b".repeat(40));
        assert!(progress.detected.is_none(), "a new attempt starts clean");
        assert_eq!(progress.sha.as_deref(), Some("b".repeat(40).as_str()));
        progress.end(Phase::Failed);
        assert_eq!(progress.phase, Phase::Failed);
    }

    #[test]
    fn since_only_moves_when_the_phase_changes() {
        let mut progress = Progress {
            since: "2020-01-01T00:00:00Z".into(),
            ..Progress::default()
        };
        progress.enter(Phase::Idle);
        assert_eq!(progress.since, "2020-01-01T00:00:00Z");
        progress.enter(Phase::Building);
        assert_ne!(progress.since, "2020-01-01T00:00:00Z");
    }

    #[test]
    fn small_report_has_the_documented_fields() {
        let mut progress = Progress::default();
        progress.begin(&"c".repeat(40));
        progress.enter(Phase::Building);
        progress.detected = Some(detected(3));
        let state = ManagerState {
            last_observed_sha: Some("a".repeat(40)),
            last_deployed_sha: Some("b".repeat(40)),
            last_failed_reason: Some("install failed".into()),
            last_outcome: Some(outcome("01ARZ3NDEKTSV4RRFFQ69G5FAV")),
            ..ManagerState::default()
        };
        let mut status = ExecutorStatus::initial("t");
        status.slots.blue.state = SlotState::Live;
        status.active_slot = Some(cite_core::Slot::Blue);
        let line = parts_with(&progress, &state, Some(&status));
        assert!(!line.contains('\n'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["phase"], "building");
        assert_eq!(v["sha"], "c".repeat(40));
        assert_eq!(v["deploy"]["id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(v["deploy"]["result"], "failed");
        assert_eq!(v["head_sha"], "a".repeat(40));
        assert_eq!(v["live_sha"], "b".repeat(40));
        assert_eq!(v["last_error"], "install failed");
        assert_eq!(v["token"], "ok");
        assert_eq!(v["detected"]["package_manager"], "pnpm");
        assert_eq!(v["executor"]["blue"], "live");
        assert_eq!(v["executor"]["green"], "empty");
        assert_eq!(v["executor"]["active"], "blue");
    }

    #[test]
    fn token_state_is_ok_invalid_or_unknown() {
        let progress = Progress::default();
        let render = |invalid: bool, verified: bool| {
            let state = ManagerState {
                token_invalid: invalid,
                ..ManagerState::default()
            };
            let line = build_report(
                &ReportParts {
                    progress: &progress,
                    state: &state,
                    status: None,
                    token_verified: verified,
                    token_fingerprint: None,
                },
                &Redactor::new(),
            );
            serde_json::from_str::<Value>(&line).unwrap()["token"].clone()
        };
        assert_eq!(render(false, true), "ok");
        assert_eq!(render(false, false), "unknown");
    }

    #[test]
    fn a_persisted_rejection_is_invalid_only_for_the_same_token() {
        let progress = Progress::default();
        let render = |recorded: Option<&str>, current: Option<&str>, verified: bool| {
            let state = ManagerState {
                token_invalid: true,
                token_invalid_fingerprint: recorded.map(String::from),
                ..ManagerState::default()
            };
            let line = build_report(
                &ReportParts {
                    progress: &progress,
                    state: &state,
                    status: None,
                    token_verified: verified,
                    token_fingerprint: current,
                },
                &Redactor::new(),
            );
            serde_json::from_str::<Value>(&line).unwrap()["token"].clone()
        };
        assert_eq!(render(Some("aa"), Some("aa"), false), "invalid");
        assert_eq!(render(Some("aa"), Some("bb"), false), "unknown");
        assert_eq!(render(None, Some("bb"), false), "unknown");
        assert_eq!(render(Some("aa"), None, false), "unknown");
        assert_eq!(render(Some("aa"), Some("bb"), true), "ok");
    }

    #[test]
    fn report_stays_under_the_cap_on_every_truncation_path() {
        let errors = [
            String::new(),
            "x".repeat(10),
            "e".repeat(5_000),
            "line\nwith \"quotes\" and \\ slashes\t".repeat(2_000),
            "\u{1}\u{2}control".repeat(3_000),
            "caf\u{e9}\u{4e16}\u{754c}".repeat(4_000),
        ];
        for error in &errors {
            for size in [0usize, 10, 70, 500, 2_000, 6_000] {
                for with_detected in [false, true] {
                    for with_status in [false, true] {
                        let mut progress = Progress::default();
                        progress.begin(&"d".repeat(40));
                        progress.last_build_secs = Some(12);
                        if with_detected {
                            progress.detected = Some(detected(size));
                        }
                        let state = ManagerState {
                            last_observed_sha: Some("a".repeat(40)),
                            last_deployed_sha: Some("b".repeat(40)),
                            last_failed_sha: Some("c".repeat(40)),
                            last_failed_reason: Some(error.clone()),
                            token_expires_at: Some("2027-01-01T00:00:00Z".into()),
                            last_outcome: Some(outcome("01ARZ3NDEKTSV4RRFFQ69G5FAV")),
                            ..ManagerState::default()
                        };
                        let status = ExecutorStatus::initial("t");
                        let line = parts_with(&progress, &state, with_status.then_some(&status));
                        assert!(
                            line.len() <= REPORT_MAX_BYTES,
                            "{} bytes for error {} detected {size}",
                            line.len(),
                            error.len()
                        );
                        let v: Value = serde_json::from_str(&line).unwrap();
                        assert_eq!(v["v"], 1);
                        assert_eq!(v["phase"], "fetching");
                        assert!(v.get("token").is_some());
                    }
                }
            }
        }
    }

    #[test]
    fn long_errors_keep_the_start_and_the_end() {
        let error = format!("START-MARK{}END-MARK", "m".repeat(20_000));
        let mut progress = Progress::default();
        progress.begin(&"d".repeat(40));
        let state = ManagerState {
            last_failed_reason: Some(error),
            ..ManagerState::default()
        };
        let line = parts_with(&progress, &state, None);
        assert!(line.len() <= REPORT_MAX_BYTES);
        let v: Value = serde_json::from_str(&line).unwrap();
        let kept = v["last_error"].as_str().unwrap();
        assert!(kept.starts_with("START-MARK"), "{kept}");
        assert!(kept.ends_with("END-MARK"), "{kept}");
        assert!(kept.contains("..."));
    }

    #[test]
    fn last_error_shrinks_before_detected_and_detected_before_other_fields() {
        let mut progress = Progress::default();
        progress.begin(&"d".repeat(40));
        progress.detected = Some(detected(40));
        let state = ManagerState {
            last_observed_sha: Some("a".repeat(40)),
            last_failed_reason: Some("z".repeat(10_000)),
            last_outcome: Some(outcome("01ARZ3NDEKTSV4RRFFQ69G5FAV")),
            ..ManagerState::default()
        };
        let line = parts_with(&progress, &state, None);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["detected"]["install_command"], "i".repeat(40));
        assert!(v["last_error"].as_str().unwrap().len() < 10_000);
        assert!(v.get("head_sha").is_some() && v.get("deploy").is_some());
    }

    #[test]
    fn huge_detected_is_cut_back_then_dropped() {
        let mut progress = Progress::default();
        progress.begin(&"d".repeat(40));
        progress.detected = Some(detected(100_000));
        let line = parts_with(&progress, &ManagerState::default(), None);
        assert!(line.len() <= REPORT_MAX_BYTES);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert!(v.get("detected").is_some());
        assert!(v["detected"]["framework"].as_str().unwrap().len() <= DETECTED_FIELD_BYTES);
    }

    #[test]
    fn the_report_masks_build_env_values_and_tokens() {
        let mut redactor = Redactor::new();
        redactor.push_secret("super-secret-build-value");
        let token = format!("ghp_{}", "A".repeat(36));
        redactor.push_secret(token.clone());
        let mut progress = Progress::default();
        progress.begin(&"d".repeat(40));
        let state = ManagerState {
            last_failed_reason: Some(format!(
                "build failed: super-secret-build-value leaked next to {token}"
            )),
            ..ManagerState::default()
        };
        let line = build_report(
            &ReportParts {
                progress: &progress,
                state: &state,
                status: None,
                token_verified: true,
                token_fingerprint: None,
            },
            &redactor,
        );
        assert!(!line.contains("super-secret-build-value"), "{line}");
        assert!(!line.contains(&token), "{line}");
        assert!(line.contains("[REDACTED]"));
    }

    #[test]
    fn ellipsize_respects_char_boundaries_and_the_byte_budget() {
        let text = "\u{4e16}".repeat(100);
        for max in 0..120 {
            assert!(ellipsize(&text, max).len() <= max, "max {max}");
        }
        assert_eq!(ellipsize("short", 10), "short");
        let cut = ellipsize("abcdefghijklmnop", 9);
        assert_eq!(cut, "abc...nop");
    }
}
