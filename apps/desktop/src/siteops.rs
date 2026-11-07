use std::collections::VecDeque;

use cite_client::{EnvPatch, LogsQuery, TokenStatus};
use cite_edge::model::{BotPolicy, FirewallRule, Slot};
use cite_edge::status::{BuildEnvPatch, LogLine, LogsResponse, SiteStatus, SlotStatus};
use serde_json::Value;

use crate::theme::Tone;

pub const CAP_STATUS: &str = "site-status";
pub const CAP_LOGS: &str = "site-logs";
pub const CAP_TOKEN: &str = "site-github-token";
pub const CAP_BUILD_ENV: &str = "site-build-env";
pub const CAP_RUNTIME_ENV: &str = "site-runtime-env";
pub const CAP_ASYNC_DEPLOY: &str = "deploy-async";
pub const CAP_SOURCE_BUILD: &str = "source-build";
pub const CAP_FORGES: &str = "forges";
pub const CAP_DOPPLER: &str = "doppler";
pub const CAP_VOLUMES: &str = "volumes";
pub const CAP_OUTBOUND: &str = "outbound";

// A feature is offered only when the node says it has it, so nodes older than 0.4.0 show none of the new cards.
pub fn has_cap(caps: &[String], name: &str) -> bool {
    caps.iter().any(|c| c == name)
}

// Everything the site page learns from the node beyond the site itself; each part is absent on nodes without the capability.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeExtras {
    pub caps: Vec<String>,
    pub api_host: Option<String>,
    // Whether the node lets site containers reach the internet; None when it does not say.
    pub executor_egress: Option<bool>,
    // "filtered", "open" or "off"; None when the node does not say.
    pub egress_mode: Option<String>,
    pub status: Option<SiteStatus>,
    pub status_error: Option<String>,
    pub token: Option<TokenStatus>,
    pub build_env: Option<Vec<String>>,
    pub runtime_env: Option<Vec<String>>,
    // None when the rule list could not be read, so the bot note never claims more than is known.
    pub rules: Option<Vec<FirewallRule>>,
}

// A git ref the node can check out: no spaces or control characters, at most 100 characters (the node's own limit).
pub fn ref_problem(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return Some("Type a branch, tag or commit to deploy.".into());
    }
    if t.chars().count() > 100 {
        return Some("A git ref is at most 100 characters.".into());
    }
    if t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Some("A git ref has no spaces.".into());
    }
    None
}

// The time of day of an RFC 3339 timestamp, which is all a log row needs.
pub fn clock(ts: &str) -> String {
    match (ts.get(11..19), ts.len() >= 19) {
        (Some(t), true) => t.to_string(),
        _ => ts.to_string(),
    }
}

// Known facts lead in this order, anything else follows alphabetically.
const FACT_ORDER: [&str; 6] = [
    "framework",
    "package_manager",
    "rendering",
    "node",
    "install_command",
    "build_command",
];

// Removes terminal colour and cursor sequences (CSI, OSC and two-byte escapes) so a log line is plain text.
pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                for n in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                while let Some(n) = chars.next() {
                    if n == '\u{7}' {
                        break;
                    }
                    if n == '\u{1b}' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Other,
}

impl LogLevel {
    pub fn tone(self) -> Tone {
        match self {
            LogLevel::Error => Tone::Bad,
            LogLevel::Warn => Tone::Warn,
            LogLevel::Info => Tone::Info,
            LogLevel::Debug => Tone::Muted,
            LogLevel::Other => Tone::Muted,
        }
    }
}

// The level the node gave, or stderr as a warning when it gave none.
pub fn level_of(line: &LogLine) -> LogLevel {
    match line
        .level
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("error" | "err" | "fatal" | "critical") => LogLevel::Error,
        Some("warn" | "warning") => LogLevel::Warn,
        Some("info" | "notice") => LogLevel::Info,
        Some("debug" | "trace") => LogLevel::Debug,
        _ if line.stream == "stderr" => LogLevel::Warn,
        _ => LogLevel::Other,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRow {
    pub ts: String,
    pub level: LogLevel,
    pub phase: String,
    pub text: String,
}

pub const LOG_CAP: usize = 5000;
pub const LOG_FIRST_TAIL: u32 = 500;
// The poll runs every fourth half-second tick, which is every two seconds.
pub const LOG_POLL_TICKS: u64 = 4;

// The newest lines of one stream; older lines fall off the front once the cap is reached.
#[derive(Clone, Debug, Default)]
pub struct LogBuffer {
    rows: VecDeque<LogRow>,
    cursor: Option<String>,
    truncated: bool,
}

impl LogBuffer {
    pub fn push(&mut self, reply: LogsResponse) -> usize {
        let added = reply.lines.len();
        for line in &reply.lines {
            self.rows.push_back(LogRow {
                ts: line.ts.clone().unwrap_or_default(),
                level: level_of(line),
                phase: line.phase.clone().unwrap_or_default(),
                text: strip_ansi(&line.text),
            });
        }
        while self.rows.len() > LOG_CAP {
            self.rows.pop_front();
        }
        if reply.cursor.is_some() {
            self.cursor = reply.cursor;
        }
        self.truncated = reply.truncated;
        added
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    // Rows whose text or phase contains the search text, ignoring case; an empty search keeps every row.
    pub fn matching(&self, needle: &str) -> Vec<&LogRow> {
        let n = needle.trim().to_lowercase();
        self.rows
            .iter()
            .filter(|r| {
                n.is_empty()
                    || r.text.to_lowercase().contains(&n)
                    || r.phase.to_lowercase().contains(&n)
            })
            .collect()
    }

    // What the Copy button puts on the clipboard: the matching lines, one per line.
    pub fn copy_text(&self, needle: &str) -> String {
        self.matching(needle)
            .iter()
            .map(|r| {
                if r.ts.is_empty() {
                    r.text.clone()
                } else {
                    format!("{} {}", r.ts, r.text)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// The first request asks for a tail; every later one asks only for what came after the cursor.
pub fn log_query(source: &str, slot: Slot, cursor: Option<&str>) -> LogsQuery {
    LogsQuery {
        source: source.to_string(),
        slot: Some(slot.as_str().to_string()),
        tail: cursor.is_none().then_some(LOG_FIRST_TAIL),
        since: cursor.map(str::to_string),
    }
}

// Follow polls only while the site page is on screen, the window is active and the last poll has finished.
pub fn should_poll_logs(
    follow: bool,
    on_site_page: bool,
    window_active: bool,
    in_flight: bool,
    tick: u64,
) -> bool {
    follow && on_site_page && window_active && !in_flight && tick.is_multiple_of(LOG_POLL_TICKS)
}

pub fn phase_tone(phase: &str) -> Tone {
    match phase {
        "idle" => Tone::Ok,
        "fetching" | "building" | "packing" | "promoting" => Tone::Info,
        "failed" | "unhealthy" => Tone::Bad,
        _ => Tone::Muted,
    }
}

// While a build runs the status panel refreshes itself; once it settles it stops asking.
pub fn is_busy_phase(phase: &str) -> bool {
    matches!(phase, "fetching" | "building" | "packing" | "promoting")
}

pub const STATUS_TICKS: u64 = 6;

// One line per fact a manager reports beyond the table columns; empty facts are left out.
pub fn report_lines(s: &SlotStatus) -> Vec<String> {
    let Some(r) = s.report.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(secs) = r.last_build_secs {
        out.push(format!("Last build took {secs}s"));
    }
    if let Some(sha) = r.last_failed_sha.as_deref().filter(|s| !s.is_empty()) {
        out.push(format!("Last failed commit {}", short_sha(sha)));
    }
    if let Some(e) = r.last_error.as_deref().filter(|e| !e.is_empty()) {
        out.push(format!("Last error: {e}"));
    }
    if let Some(t) = r.token.as_deref().filter(|t| !t.is_empty()) {
        match r.token_expires_at.as_deref().filter(|e| !e.is_empty()) {
            Some(e) => out.push(format!("GitHub token: {t}, expires {e}")),
            None => out.push(format!("GitHub token: {t}")),
        }
    }
    if let Some(Value::Object(map)) = r.detected.as_ref() {
        let mut entries: Vec<(&String, &Value)> = map.iter().collect();
        entries.sort_by_key(|(k, _)| {
            let rank = FACT_ORDER
                .iter()
                .position(|known| known == k)
                .unwrap_or(FACT_ORDER.len());
            (rank, k.to_string())
        });
        let facts: Vec<String> = entries
            .into_iter()
            .filter_map(|(k, v)| match v {
                Value::String(t) if !t.is_empty() => Some(format!("{k} {t}")),
                Value::Number(n) => Some(format!("{k} {n}")),
                Value::Bool(b) => Some(format!("{k} {b}")),
                _ => None,
            })
            .collect();
        if !facts.is_empty() {
            out.push(format!("Detected: {}", facts.join(", ")));
        }
    }
    out
}

// Read-only: the forge is chosen by the node's own configuration, not per request.
pub fn forge_note(api_host: Option<&str>) -> Option<String> {
    api_host
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(|h| format!("This node fetches repositories from {h}. The host is set on the node."))
}

pub fn phase_label(phase: &str) -> String {
    let mut chars = phase.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Unknown".to_string(),
    }
}

// The reason shown in the red banner: the node's error, or the note of the last failure while the phase says so.
pub fn status_reason(st: &SiteStatus) -> Option<String> {
    st.error
        .clone()
        .filter(|e| !e.trim().is_empty())
        .or_else(|| {
            matches!(st.phase.as_str(), "failed" | "unhealthy")
                .then(|| st.last_failure.as_ref().map(|f| f.note.clone()))
                .flatten()
                .filter(|n| !n.trim().is_empty())
        })
}

pub fn short_sha(sha: &str) -> String {
    sha.chars().take(7).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotRow {
    pub slot: Slot,
    pub container: String,
    pub health: String,
    pub restarts: u32,
    pub exit: String,
    pub phase: String,
    pub live: String,
    pub head: String,
    pub haproxy: String,
}

fn dash(text: Option<String>) -> String {
    text.filter(|t| !t.is_empty()).unwrap_or_else(|| "-".into())
}

fn slot_row(s: &SlotStatus) -> SlotRow {
    let report = s.report.as_ref();
    let exit = match (s.exit_code, s.oom_killed) {
        (_, true) => "out of memory".to_string(),
        (Some(code), false) => format!("exit {code}"),
        (None, false) => "-".to_string(),
    };
    SlotRow {
        slot: s.slot,
        container: dash(Some(s.container.clone())),
        health: dash(Some(s.health.clone())),
        restarts: s.restart_count,
        exit,
        phase: dash(report.map(|r| r.phase.clone())),
        live: dash(report.and_then(|r| r.live_sha.as_deref().map(short_sha))),
        head: dash(report.and_then(|r| r.head_sha.as_deref().map(short_sha))),
        haproxy: dash(match (&s.haproxy, &s.haproxy_check) {
            (Some(a), Some(b)) => Some(format!("{a} ({b})")),
            (Some(a), None) => Some(a.clone()),
            (None, b) => b.clone(),
        }),
    }
}

pub fn slot_rows(st: &SiteStatus) -> Vec<SlotRow> {
    st.slots.iter().map(slot_row).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeRow {
    pub slot: Slot,
    pub result: String,
    pub sha: String,
    pub reason: String,
    pub finished: String,
}

// The last deploy each slot's manager reports: commit, result and the reason it gave.
pub fn outcome_rows(st: &SiteStatus) -> Vec<OutcomeRow> {
    st.slots
        .iter()
        .filter_map(|s| {
            let d = s.report.as_ref()?.deploy.as_ref()?;
            Some(OutcomeRow {
                slot: s.slot,
                result: d.result.clone(),
                sha: dash(d.sha.as_deref().map(short_sha)),
                reason: dash(d.reason.clone()),
                finished: dash(d.finished_at.clone()),
            })
        })
        .collect()
}

// The value the manager detected for a build setting, taken from the active slot first.
pub fn detected_value(st: &SiteStatus, key: &str) -> Option<String> {
    let mut order: Vec<&SlotStatus> = st.slots.iter().filter(|s| s.slot == st.active).collect();
    order.extend(st.slots.iter().filter(|s| s.slot != st.active));
    order.into_iter().find_map(|s| {
        let found = s.report.as_ref()?.detected.as_ref()?.get(key)?;
        match found {
            Value::String(t) if !t.is_empty() => Some(t.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    })
}

// What an empty build field shows: the detected value when the node knows one, otherwise plain Auto.
pub fn auto_placeholder(detected: Option<&str>) -> String {
    match detected {
        Some(v) => format!("Auto (detected: {v})"),
        None => "Auto".to_string(),
    }
}

pub fn token_summary(t: &TokenStatus) -> String {
    match t.source.as_str() {
        "site" => "This site uses its own GitHub token.".to_string(),
        "node" => "This site uses the node's GitHub token.".to_string(),
        _ if t.node_token_configured => {
            "No token is in use for this site, but the node has one available.".to_string()
        }
        _ => "No GitHub token is set: private repositories cannot be fetched.".to_string(),
    }
}

// Verification and expiry as the node reports them, or nothing when it reports neither.
pub fn token_detail(t: &TokenStatus) -> Option<String> {
    let mut parts = Vec::new();
    match t.verified {
        Some(true) => parts.push("verified against the forge".to_string()),
        Some(false) => parts.push("the forge rejected it".to_string()),
        None => {}
    }
    if let Some(s) = t.status.as_deref().filter(|s| !s.is_empty()) {
        parts.push(format!("status {s}"));
    }
    if let Some(e) = t.expires_at.as_deref().filter(|e| !e.is_empty()) {
        parts.push(format!("expires {e}"));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

// Names are upper-cased because the node accepts only upper-case variable names.
pub fn env_name(text: &str) -> String {
    text.trim().to_ascii_uppercase()
}

// The change to send, checked with the node's own rules; the error names keys and never shows a value.
pub fn env_patch(
    runtime: bool,
    rows: &[(String, String)],
    unset: &[String],
) -> Result<EnvPatch, String> {
    let mut check = BuildEnvPatch::default();
    let mut patch = EnvPatch::default();
    for (name, value) in rows {
        let name = env_name(name);
        if name.is_empty() && value.is_empty() {
            continue;
        }
        check.set.insert(name.clone(), value.clone());
        patch.set.insert(name, value.clone());
    }
    for name in unset {
        let name = env_name(name);
        check.unset.push(name.clone());
        patch.unset.push(name);
    }
    if check.set.is_empty() && check.unset.is_empty() {
        return Err("Add a variable or mark one for removal.".into());
    }
    let verdict = if runtime {
        check.validate_runtime()
    } else {
        check.validate()
    };
    verdict.map_err(|e| e.0)?;
    Ok(patch)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotTrust {
    pub message: String,
    pub rules: Vec<String>,
}

// Makes the bot policy trustworthy: says plainly when nothing blocks bots, and lists every rule that could.
pub fn bot_trust(policy: BotPolicy, rules: &[FirewallRule], site_id: &str) -> BotTrust {
    let relevant: Vec<&FirewallRule> = rules
        .iter()
        .filter(|r| !r.matchers.user_agent_regexes.is_empty())
        .filter(|r| r.action.is_some())
        .filter(|r| r.site.as_deref().is_none_or(|s| s == site_id))
        .collect();
    let listed: Vec<String> = relevant
        .iter()
        .map(|r| {
            let scope = if r.site.is_some() {
                "this site"
            } else {
                "all sites"
            };
            let state = if r.enabled { "on" } else { "off" };
            format!("{} ({scope}, {state})", r.name)
        })
        .collect();
    let active = relevant.iter().filter(|r| r.enabled).count();
    let message = match (policy, active) {
        (BotPolicy::Allow, 0) => "No bot blocking is active for this site.".to_string(),
        (BotPolicy::Allow, n) => format!(
            "The bot policy allows every visitor, but {n} firewall rule{} that match user agents can still block requests.",
            if n == 1 { "" } else { "s" }
        ),
        (_, 0) => "Bots are blocked by this site's bot policy only.".to_string(),
        (_, n) => format!(
            "Bots are blocked by this site's bot policy and by {n} firewall rule{} that match user agents.",
            if n == 1 { "" } else { "s" }
        ),
    };
    BotTrust {
        message,
        rules: listed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::{FirewallAction, Matchers};
    use cite_edge::status::{DeployOutcome, LastFailure, ManagerReport};
    use serde_json::json;

    fn line(level: Option<&str>, stream: &str, text: &str) -> LogLine {
        LogLine {
            ts: Some("2025-01-01T00:00:00Z".into()),
            stream: stream.into(),
            level: level.map(str::to_string),
            phase: Some("build".into()),
            text: text.into(),
        }
    }

    fn reply(lines: Vec<LogLine>, cursor: Option<&str>) -> LogsResponse {
        LogsResponse {
            lines,
            cursor: cursor.map(str::to_string),
            truncated: false,
        }
    }

    #[test]
    fn capabilities_gate_each_feature() {
        let caps = vec!["site-status".to_string(), "forges".to_string()];
        assert!(has_cap(&caps, CAP_STATUS) && has_cap(&caps, CAP_FORGES));
        assert!(!has_cap(&caps, CAP_LOGS) && !has_cap(&[], CAP_STATUS));
        for name in [
            CAP_STATUS,
            CAP_LOGS,
            CAP_TOKEN,
            CAP_BUILD_ENV,
            CAP_RUNTIME_ENV,
            CAP_ASYNC_DEPLOY,
            CAP_SOURCE_BUILD,
            CAP_FORGES,
        ] {
            assert!(cite_edge::status::CAPABILITIES.contains(&name), "{name}");
        }
    }

    #[test]
    fn ansi_sequences_are_removed() {
        assert_eq!(strip_ansi("\u{1b}[31merror\u{1b}[0m: boom"), "error: boom");
        assert_eq!(strip_ansi("\u{1b}[1;38;5;196mred\u{1b}[m"), "red");
        assert_eq!(strip_ansi("a\u{1b}]0;title\u{7}b"), "ab");
        assert_eq!(
            strip_ansi("a\u{1b}]8;;http://x\u{1b}\\link\u{1b}]8;;\u{1b}\\"),
            "alink"
        );
        assert_eq!(strip_ansi("x\u{1b}My"), "xy");
        assert_eq!(
            strip_ansi("plain text, no escapes"),
            "plain text, no escapes"
        );
        assert_eq!(strip_ansi("cut\u{1b}"), "cut");
        assert_eq!(strip_ansi("cut\u{1b}[31"), "cut");
        assert_eq!(strip_ansi(""), "");
    }

    #[test]
    fn levels_come_from_the_node_or_the_stream() {
        assert_eq!(
            level_of(&line(Some("ERROR"), "stdout", "")),
            LogLevel::Error
        );
        assert_eq!(
            level_of(&line(Some("warning"), "stdout", "")),
            LogLevel::Warn
        );
        assert_eq!(level_of(&line(Some("info"), "stdout", "")), LogLevel::Info);
        assert_eq!(
            level_of(&line(Some("trace"), "stdout", "")),
            LogLevel::Debug
        );
        assert_eq!(level_of(&line(None, "stderr", "")), LogLevel::Warn);
        assert_eq!(level_of(&line(None, "stdout", "")), LogLevel::Other);
        assert_eq!(
            level_of(&line(Some("weird"), "stdout", "")),
            LogLevel::Other
        );
        assert_eq!(LogLevel::Error.tone(), Tone::Bad);
        assert_eq!(LogLevel::Warn.tone(), Tone::Warn);
        assert_eq!(LogLevel::Info.tone(), Tone::Info);
        assert_eq!(LogLevel::Debug.tone(), Tone::Muted);
    }

    #[test]
    fn the_buffer_keeps_the_newest_five_thousand_lines_and_the_cursor() {
        let mut buf = LogBuffer::default();
        assert_eq!(
            buf.push(reply(
                vec![line(None, "stdout", "\u{1b}[32mhello\u{1b}[0m")],
                Some("c1")
            )),
            1
        );
        assert_eq!(buf.matching("")[0].text, "hello");
        assert_eq!(buf.cursor(), Some("c1"));
        let many: Vec<LogLine> = (0..LOG_CAP + 10)
            .map(|i| line(None, "stdout", &format!("line {i}")))
            .collect();
        buf.push(reply(many, Some("c2")));
        assert_eq!(buf.matching("").len(), LOG_CAP);
        assert_eq!(buf.matching("")[0].text, "line 10");
        assert_eq!(
            buf.matching("")[LOG_CAP - 1].text,
            format!("line {}", LOG_CAP + 9)
        );
        assert_eq!(buf.cursor(), Some("c2"));
        buf.push(reply(Vec::new(), None));
        assert_eq!(buf.cursor(), Some("c2"));
        let mut cut = reply(Vec::new(), None);
        cut.truncated = true;
        buf.push(cut);
        assert!(buf.truncated());
        buf.clear();
        assert_eq!(
            (buf.matching("").len(), buf.cursor(), buf.truncated()),
            (0, None, false)
        );
    }

    #[test]
    fn search_ignores_case_and_copy_returns_what_matches() {
        let mut buf = LogBuffer::default();
        buf.push(reply(
            vec![
                line(Some("error"), "stderr", "Build FAILED: missing script"),
                line(None, "stdout", "installing packages"),
                line(None, "stdout", "failed to fetch registry"),
            ],
            None,
        ));
        assert_eq!(buf.matching("failed").len(), 2);
        assert_eq!(buf.matching("  INSTALL ").len(), 1);
        assert_eq!(buf.matching("build").len(), 3);
        assert_eq!(buf.matching("zzz").len(), 0);
        assert_eq!(buf.matching("").len(), 3);
        let text = buf.copy_text("installing");
        assert_eq!(text, "2025-01-01T00:00:00Z installing packages");
        assert_eq!(buf.copy_text("").lines().count(), 3);
        let mut bare = LogBuffer::default();
        let mut l = line(None, "stdout", "no time");
        l.ts = None;
        bare.push(reply(vec![l], None));
        assert_eq!(bare.copy_text(""), "no time");
    }

    #[test]
    fn the_first_query_tails_and_later_ones_follow_the_cursor() {
        let first = log_query("manager", Slot::Green, None);
        assert_eq!(
            (first.source.as_str(), first.slot.as_deref()),
            ("manager", Some("green"))
        );
        assert_eq!(
            (first.tail, first.since.clone()),
            (Some(LOG_FIRST_TAIL), None)
        );
        assert!(first.to_query().is_ok());
        let next = log_query("executor", Slot::Blue, Some("abc-1"));
        assert_eq!((next.tail, next.since.as_deref()), (None, Some("abc-1")));
        assert!(next.to_query().is_ok());
    }

    #[test]
    fn following_polls_only_when_the_page_is_shown_and_idle() {
        assert!(should_poll_logs(true, true, true, false, 8));
        assert!(!should_poll_logs(true, true, true, false, 9));
        assert!(!should_poll_logs(false, true, true, false, 8));
        assert!(!should_poll_logs(true, false, true, false, 8));
        assert!(!should_poll_logs(true, true, false, false, 8));
        assert!(!should_poll_logs(true, true, true, true, 8));
    }

    fn status() -> SiteStatus {
        SiteStatus {
            phase: "failed".into(),
            error: None,
            active: Slot::Blue,
            last_failure: Some(LastFailure {
                at: "t".into(),
                slot: Some(Slot::Green),
                note: "build failed: exit 1".into(),
            }),
            slots: vec![
                SlotStatus {
                    slot: Slot::Blue,
                    container: "cite-docs-blue-manager".into(),
                    health: "healthy".into(),
                    report: Some(ManagerReport {
                        phase: "idle".into(),
                        live_sha: Some("0123456789abcdef".into()),
                        head_sha: Some("fedcba9876543210".into()),
                        deploy: Some(DeployOutcome {
                            id: "d1".into(),
                            result: "ok".into(),
                            sha: Some("0123456789abcdef".into()),
                            reason: None,
                            started_at: None,
                            finished_at: Some("2025-01-01T00:00:00Z".into()),
                        }),
                        detected: Some(
                            json!({"package_manager": "pnpm", "framework": "vite", "prune": true, "x": 3}),
                        ),
                        ..ManagerReport::default()
                    }),
                    haproxy: Some("UP".into()),
                    haproxy_check: Some("L7OK".into()),
                    ..SlotStatus::default()
                },
                SlotStatus {
                    slot: Slot::Green,
                    container: "cite-docs-green-manager".into(),
                    health: "unhealthy".into(),
                    restart_count: 3,
                    exit_code: Some(137),
                    oom_killed: true,
                    report: Some(ManagerReport {
                        phase: "building".into(),
                        detected: Some(json!({"framework": "next"})),
                        ..ManagerReport::default()
                    }),
                    ..SlotStatus::default()
                },
            ],
            ..SiteStatus::default()
        }
    }

    #[test]
    fn phases_have_tones_and_labels() {
        for (p, t) in [
            ("idle", Tone::Ok),
            ("fetching", Tone::Info),
            ("building", Tone::Info),
            ("packing", Tone::Info),
            ("promoting", Tone::Info),
            ("failed", Tone::Bad),
            ("unhealthy", Tone::Bad),
            ("???", Tone::Muted),
        ] {
            assert_eq!(phase_tone(p), t, "{p}");
        }
        assert_eq!(phase_label("building"), "Building");
        assert_eq!(phase_label(""), "Unknown");
    }

    #[test]
    fn the_banner_reason_prefers_the_nodes_error_then_the_last_failure() {
        let mut st = status();
        assert_eq!(status_reason(&st).as_deref(), Some("build failed: exit 1"));
        st.error = Some("registry unreachable".into());
        assert_eq!(status_reason(&st).as_deref(), Some("registry unreachable"));
        st.error = Some("  ".into());
        assert_eq!(status_reason(&st).as_deref(), Some("build failed: exit 1"));
        st.phase = "idle".into();
        assert_eq!(status_reason(&st), None);
        st.phase = "failed".into();
        st.last_failure = None;
        assert_eq!(status_reason(&st), None);
    }

    #[test]
    fn refs_and_clock_times() {
        assert!(ref_problem("main").is_none() && ref_problem(" v1.2.3 ").is_none());
        assert!(ref_problem("0123456789abcdef").is_none());
        assert!(ref_problem("").unwrap().contains("Type"));
        assert!(ref_problem("my branch").unwrap().contains("spaces"));
        assert!(ref_problem(&"a".repeat(101)).unwrap().contains("100"));
        assert!(ref_problem(&"a".repeat(100)).is_none());
        assert_eq!(clock("2025-01-02T03:04:05Z"), "03:04:05");
        assert_eq!(clock("soon"), "soon");
        assert_eq!(clock(""), "");
    }

    #[test]
    fn builds_in_flight_keep_the_panel_refreshing() {
        for p in ["fetching", "building", "packing", "promoting"] {
            assert!(is_busy_phase(p), "{p}");
        }
        for p in ["idle", "failed", "unhealthy", ""] {
            assert!(!is_busy_phase(p), "{p}");
        }
    }

    #[test]
    fn manager_facts_become_readable_lines() {
        let st = status();
        let mut blue = report_lines(&st.slots[0]);
        blue.retain(|l| l.starts_with("Detected"));
        assert_eq!(
            blue,
            vec!["Detected: framework vite, package_manager pnpm, prune true, x 3"]
        );
        let mut s = SlotStatus::default();
        assert!(report_lines(&s).is_empty());
        s.report = Some(ManagerReport {
            last_build_secs: Some(74),
            last_failed_sha: Some("0123456789".into()),
            last_error: Some("boom".into()),
            token: Some("site".into()),
            token_expires_at: Some("2027-01-01".into()),
            ..ManagerReport::default()
        });
        assert_eq!(
            report_lines(&s),
            vec![
                "Last build took 74s",
                "Last failed commit 0123456",
                "Last error: boom",
                "GitHub token: site, expires 2027-01-01",
            ]
        );
        s.report = Some(ManagerReport {
            token: Some("node".into()),
            last_error: Some(String::new()),
            ..ManagerReport::default()
        });
        assert_eq!(report_lines(&s), vec!["GitHub token: node"]);
    }

    #[test]
    fn the_forge_note_names_the_nodes_host() {
        assert!(
            forge_note(Some("api.github.com"))
                .unwrap()
                .contains("api.github.com")
        );
        assert_eq!(forge_note(Some("  ")), None);
        assert_eq!(forge_note(None), None);
    }

    #[test]
    fn slot_rows_summarise_containers_and_commits() {
        let rows = slot_rows(&status());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].live, "0123456");
        assert_eq!(rows[0].head, "fedcba9");
        assert_eq!(rows[0].haproxy, "UP (L7OK)");
        assert_eq!(rows[0].exit, "-");
        assert_eq!(rows[1].exit, "out of memory");
        assert_eq!(rows[1].restarts, 3);
        assert_eq!(rows[1].live, "-");
        assert_eq!(rows[1].haproxy, "-");
        let mut st = status();
        st.slots[1].oom_killed = false;
        assert_eq!(slot_rows(&st)[1].exit, "exit 137");
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn outcomes_come_from_the_managers_reports() {
        let rows = outcome_rows(&status());
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].slot, rows[0].result.as_str()), (Slot::Blue, "ok"));
        assert_eq!(
            (rows[0].sha.as_str(), rows[0].reason.as_str()),
            ("0123456", "-")
        );
        assert!(outcome_rows(&SiteStatus::default()).is_empty());
    }

    #[test]
    fn detected_values_prefer_the_active_slot() {
        let st = status();
        assert_eq!(detected_value(&st, "framework").as_deref(), Some("vite"));
        assert_eq!(
            detected_value(&st, "package_manager").as_deref(),
            Some("pnpm")
        );
        assert_eq!(detected_value(&st, "prune").as_deref(), Some("true"));
        assert_eq!(detected_value(&st, "x").as_deref(), Some("3"));
        assert_eq!(detected_value(&st, "missing"), None);
        let mut other = status();
        other.active = Slot::Green;
        assert_eq!(detected_value(&other, "framework").as_deref(), Some("next"));
        assert_eq!(detected_value(&SiteStatus::default(), "framework"), None);
        assert_eq!(auto_placeholder(Some("pnpm")), "Auto (detected: pnpm)");
        assert_eq!(auto_placeholder(None), "Auto");
    }

    #[test]
    fn the_token_card_says_where_the_token_comes_from() {
        let site = TokenStatus {
            source: "site".into(),
            site_token_set: true,
            node_token_configured: true,
            ..TokenStatus::default()
        };
        assert!(token_summary(&site).contains("its own"));
        let node = TokenStatus {
            source: "node".into(),
            node_token_configured: true,
            ..TokenStatus::default()
        };
        assert!(token_summary(&node).contains("node's"));
        let none_but = TokenStatus {
            source: "none".into(),
            node_token_configured: true,
            ..TokenStatus::default()
        };
        assert!(token_summary(&none_but).contains("node has one available"));
        assert!(token_summary(&TokenStatus::default()).contains("private repositories"));
        assert_eq!(token_detail(&TokenStatus::default()), None);
        let full = TokenStatus {
            verified: Some(true),
            status: Some("ok".into()),
            expires_at: Some("2026-01-01".into()),
            ..TokenStatus::default()
        };
        assert_eq!(
            token_detail(&full).unwrap(),
            "verified against the forge, status ok, expires 2026-01-01"
        );
        let bad = TokenStatus {
            verified: Some(false),
            ..TokenStatus::default()
        };
        assert!(token_detail(&bad).unwrap().contains("rejected"));
    }

    #[test]
    fn environment_changes_use_the_nodes_rules_and_never_echo_values() {
        let value = crate::testkit::joined(&["env", "-secret", "-value"]);
        let patch = env_patch(
            false,
            &[(" api_key ".into(), value.clone())],
            &["old_var".into()],
        )
        .expect("valid");
        assert!(patch.set.get("API_KEY").is_some_and(|v| v == &value));
        assert_eq!(patch.unset, vec!["OLD_VAR"]);
        assert!(!format!("{patch:?}").contains(value.as_str()));
        for runtime in [false, true] {
            assert!(
                env_patch(runtime, &[], &[])
                    .unwrap_err()
                    .contains("Add a variable")
            );
            assert!(env_patch(runtime, &[("".into(), "".into())], &[]).is_err());
            let reserved =
                env_patch(runtime, &[("NODE_OPTIONS".into(), "x".into())], &[]).unwrap_err();
            assert!(reserved.contains("NODE_OPTIONS") && reserved.contains("reserved"));
            assert!(env_patch(runtime, &[("CITE_X".into(), "x".into())], &[]).is_err());
            assert!(env_patch(runtime, &[("1BAD".into(), "x".into())], &[]).is_err());
            let both = env_patch(runtime, &[("A".into(), "1".into())], &["a".into()]).unwrap_err();
            assert!(both.contains("both set and unset"));
            let long = "x".repeat(5000);
            let err = env_patch(runtime, &[("BIG".into(), long.clone())], &[]).unwrap_err();
            assert!(err.contains("BIG") && !err.contains(&long));
        }
        assert_eq!(env_name("  token_1 "), "TOKEN_1");
    }

    #[test]
    fn build_and_runtime_environments_refuse_different_names() {
        let set = |runtime: bool, name: &str| env_patch(runtime, &[(name.into(), "x".into())], &[]);
        for name in [
            "SHELL",
            "BASH_ENV",
            "NODE_PATH",
            "TMP",
            "CARGO_HOME",
            "LD_X",
            "DYLD_X",
        ] {
            assert!(set(false, name).is_err(), "build {name}");
        }
        assert!(set(true, "SHELL").is_ok());
        for name in ["PORT", "NODE_ENV", "HOST", "HOSTNAME", "NITRO_HOST"] {
            let err = set(true, name).unwrap_err();
            assert!(
                err.contains(name) && err.contains("reserved"),
                "runtime {name}"
            );
        }
        assert!(set(false, "PORT").is_ok());
        assert!(set(false, "NODE_ENV").is_ok());
    }

    fn rule(name: &str, site: Option<&str>, enabled: bool, ua: &[&str]) -> FirewallRule {
        FirewallRule {
            id: name.to_lowercase(),
            name: name.into(),
            enabled,
            action: Some(FirewallAction::Deny),
            site: site.map(str::to_string),
            matchers: Matchers {
                user_agent_regexes: ua.iter().map(|u| u.to_string()).collect(),
                ..Matchers::default()
            },
            ..FirewallRule::default()
        }
    }

    #[test]
    fn allow_is_only_trusted_when_no_rule_can_block_bots() {
        let none = bot_trust(BotPolicy::Allow, &[], "shop");
        assert_eq!(none.message, "No bot blocking is active for this site.");
        assert!(none.rules.is_empty());
        let rules = vec![
            rule("Scanners", None, true, &["(sqlmap|nikto)"]),
            rule("Other site", Some("blog"), true, &["curl"]),
            rule("Mine off", Some("shop"), false, &["wget"]),
            rule("No agent", None, true, &[]),
        ];
        let t = bot_trust(BotPolicy::Allow, &rules, "shop");
        assert!(
            t.message.contains("1 firewall rule that match"),
            "{}",
            t.message
        );
        assert_eq!(
            t.rules,
            vec!["Scanners (all sites, on)", "Mine off (this site, off)"]
        );
        let only_off = bot_trust(
            BotPolicy::Allow,
            &[rule("Off", None, false, &["x"])],
            "shop",
        );
        assert_eq!(only_off.message, "No bot blocking is active for this site.");
        assert_eq!(only_off.rules.len(), 1);
        let blocked = bot_trust(BotPolicy::BlockBad, &[], "shop");
        assert!(blocked.message.contains("bot policy only"));
        let both = bot_trust(BotPolicy::BlockAll, &rules, "shop");
        assert!(both.message.contains("and by 1 firewall rule"));
        let two = bot_trust(
            BotPolicy::Allow,
            &[rule("A", None, true, &["a"]), rule("B", None, true, &["b"])],
            "shop",
        );
        assert!(two.message.contains("2 firewall rules"));
    }
}
