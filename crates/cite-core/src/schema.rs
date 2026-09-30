use std::path::Path;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::atomic::{read_json_limited, write_atomic};
use crate::error::{Error, Result};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_JSON_BYTES: u64 = 512 * 1024;
const MAX_HISTORY: usize = 20;
const MAX_LOG_LINES: usize = 40;
const MAX_LOG_LINE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    Blue,
    Green,
}

impl Slot {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blue => "blue",
            Self::Green => "green",
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::Blue => Self::Green,
            Self::Green => Self::Blue,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "blue" => Ok(Self::Blue),
            "green" => Ok(Self::Green),
            _ => Err(Error::msg(format!("unknown slot `{value}`"))),
        }
    }

    pub fn loopback_port(self, base: u16) -> Result<u16> {
        let offset = match self {
            Self::Blue => 0,
            Self::Green => 1,
        };
        base.checked_add(offset)
            .ok_or_else(|| Error::Config("CITE_PORT_BASE overflows".into()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rendering {
    Static,
    Ssr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Node,
    Bun,
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthExpect {
    #[serde(rename = "non2xx-ok")]
    Non2xxOk,
    #[serde(rename = "2xx")]
    TwoXx,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub path: String,
    pub expect: HealthExpect,
    pub timeout_s: u64,
    pub consecutive: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub v: u32,
    pub release_id: String,
    pub slot: Slot,
    pub sha: String,
    pub branch: String,
    pub commit_message: String,
    pub commit_author: String,
    pub built_at: String,
    pub rendering: Rendering,
    pub runtime: RuntimeKind,
    pub node_major: String,
    pub start_argv: Vec<String>,
    pub port_env: String,
    pub health: Health,
    #[serde(default)]
    pub spa_fallback: Option<String>,
    pub root: String,
    pub bytes: u64,
    pub file_count: u64,
    pub tree_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredAction {
    Activate,
    Evict,
    Rollback,
    RestartChild,
    RestartExecutor,
    Noop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Desired {
    pub v: u32,
    pub generation: u64,
    pub live_slot: Slot,
    pub action: DesiredAction,
    #[serde(default)]
    pub evict_slot: Option<Slot>,
    pub warm_grace_s: u64,
    pub restart_nonce: String,
    pub written_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotState {
    Warm,
    Live,
    Stopped,
    Failed,
    Starting,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotStatus {
    #[serde(default)]
    pub release_id: Option<String>,
    pub state: SlotState,
    pub since: String,
    #[serde(default)]
    pub warm_until: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotPair {
    pub blue: SlotStatus,
    pub green: SlotStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Live,
    Failed,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastResult {
    pub generation: u64,
    pub outcome: Outcome,
    pub reason: String,
    pub log_tail: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorStatus {
    pub v: u32,
    pub executor_version: String,
    pub updated_at: String,
    pub boot_id: String,
    pub ack_generation: u64,
    #[serde(default)]
    pub active_slot: Option<Slot>,
    #[serde(default)]
    pub active_release_id: Option<String>,
    pub slots: SlotPair,
    #[serde(default)]
    pub last_result: Option<LastResult>,
    /// Requests handled since boot. Exposed only through executor status.
    #[serde(default)]
    pub requests: u64,
}

impl ExecutorStatus {
    pub fn initial(version: &str) -> Self {
        let now = now_rfc3339();
        let empty = SlotStatus {
            release_id: None,
            state: SlotState::Empty,
            since: now.clone(),
            warm_until: None,
            pid: None,
        };
        Self {
            v: SCHEMA_VERSION,
            executor_version: version.to_string(),
            updated_at: now,
            boot_id: new_id(),
            ack_generation: 0,
            active_slot: None,
            active_release_id: None,
            slots: SlotPair {
                blue: empty.clone(),
                green: empty,
            },
            last_result: None,
            requests: 0,
        }
    }

    pub fn slot(&self, slot: Slot) -> &SlotStatus {
        match slot {
            Slot::Blue => &self.slots.blue,
            Slot::Green => &self.slots.green,
        }
    }

    pub fn slot_mut(&mut self, slot: Slot) -> &mut SlotStatus {
        match slot {
            Slot::Blue => &mut self.slots.blue,
            Slot::Green => &mut self.slots.green,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployRecord {
    pub sha: String,
    pub release_id: String,
    pub slot: Slot,
    pub at: String,
    pub outcome: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerState {
    pub v: u32,
    #[serde(default)]
    pub last_observed_sha: Option<String>,
    #[serde(default)]
    pub poll_etag: Option<String>,
    #[serde(default)]
    pub last_deployed_sha: Option<String>,
    #[serde(default)]
    pub last_failed_sha: Option<String>,
    #[serde(default)]
    pub last_failed_reason: Option<String>,
    #[serde(default)]
    pub last_failed_attempts: u32,
    #[serde(default)]
    pub next_poll_at: Option<String>,
    #[serde(default)]
    pub history: Vec<DeployRecord>,
    pub generation: u64,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub token_invalid: bool,
    #[serde(default)]
    pub token_expires_at: Option<String>,
}

impl Default for ManagerState {
    fn default() -> Self {
        Self {
            v: SCHEMA_VERSION,
            last_observed_sha: None,
            poll_etag: None,
            last_deployed_sha: None,
            last_failed_sha: None,
            last_failed_reason: None,
            last_failed_attempts: 0,
            next_poll_at: None,
            history: Vec::new(),
            generation: 0,
            paused: false,
            token_invalid: false,
            token_expires_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    Status,
    Poll,
    Redeploy { sha: Option<String> },
    Rollback,
    RestartChild,
    RestartExecutor,
    Pause,
    Resume,
    Logs,
    Healthcheck,
    ConfigCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub fn new_id() -> String {
    ulid::Ulid::new().to_string()
}

pub fn decode_release(bytes: &[u8]) -> Result<ReleaseManifest> {
    let value: ReleaseManifest = decode_raw(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn decode_desired(bytes: &[u8]) -> Result<Desired> {
    let value: Desired = decode_raw(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn decode_status(bytes: &[u8]) -> Result<ExecutorStatus> {
    let value: ExecutorStatus = decode_raw(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn decode_state(bytes: &[u8]) -> Result<ManagerState> {
    let mut value: ManagerState = decode_raw(bytes)?;
    value.validate()?;
    if value.history.len() > MAX_HISTORY {
        let drop_n = value.history.len() - MAX_HISTORY;
        value.history.drain(0..drop_n);
    }
    Ok(value)
}

pub fn read_release(path: &Path) -> Result<ReleaseManifest> {
    decode_release(&read_json_limited(path)?)
}

pub fn read_desired(path: &Path) -> Result<Desired> {
    decode_desired(&read_json_limited(path)?)
}

pub fn read_status(path: &Path) -> Result<ExecutorStatus> {
    decode_status(&read_json_limited(path)?)
}

pub fn read_state(path: &Path) -> Result<ManagerState> {
    decode_state(&read_json_limited(path)?)
}

pub fn write_release(path: &Path, value: &ReleaseManifest) -> Result<()> {
    value.validate()?;
    write_json(path, value, 0o644)
}

pub fn write_desired(path: &Path, value: &Desired) -> Result<()> {
    value.validate()?;
    write_json(path, value, 0o644)
}

pub fn write_status(path: &Path, value: &ExecutorStatus) -> Result<()> {
    let mut value = value.clone();
    if let Some(result) = value.last_result.as_mut() {
        trim_log_tail(&mut result.log_tail);
    }
    value.validate()?;
    write_json(path, &value, 0o644)
}

pub fn write_state(path: &Path, value: &ManagerState) -> Result<()> {
    let mut value = value.clone();
    if value.history.len() > MAX_HISTORY {
        let drop_n = value.history.len() - MAX_HISTORY;
        value.history.drain(0..drop_n);
    }
    value.v = SCHEMA_VERSION;
    value.validate()?;
    write_json(path, &value, 0o640)
}

impl ReleaseManifest {
    fn validate(&self) -> Result<()> {
        check_version(self.v)?;
        check_id(&self.release_id)?;
        check_sha(&self.sha)?;
        check_time(&self.built_at)?;
        check_text("branch", &self.branch, 256)?;
        check_text("commit_message", &self.commit_message, 4096)?;
        check_text("commit_author", &self.commit_author, 512)?;
        check_text("node_major", &self.node_major, 8)?;
        check_text("port_env", &self.port_env, 64)?;
        check_text("root", &self.root, 64)?;
        if self.root != "app" {
            return Err(Error::msg("release root must be `app`"));
        }
        check_sha256(&self.tree_sha256)?;
        check_health(&self.health)?;
        if self.start_argv.len() > 32 {
            return Err(Error::msg("start_argv too long"));
        }
        for arg in &self.start_argv {
            check_text("argv", arg, 1024)?;
        }
        if let Some(fallback) = &self.spa_fallback {
            check_text("spa_fallback", fallback, 256)?;
        }
        Ok(())
    }
}

impl Desired {
    pub fn noop(generation: u64, live_slot: Slot, warm_grace_s: u64) -> Self {
        Self {
            v: SCHEMA_VERSION,
            generation,
            live_slot,
            action: DesiredAction::Noop,
            evict_slot: None,
            warm_grace_s,
            restart_nonce: String::new(),
            written_at: now_rfc3339(),
        }
    }

    fn validate(&self) -> Result<()> {
        check_version(self.v)?;
        check_time(&self.written_at)?;
        check_text("restart_nonce", &self.restart_nonce, 128)?;
        if self.action == DesiredAction::Evict && self.evict_slot.is_none() {
            return Err(Error::msg("evict action requires evict_slot"));
        }
        Ok(())
    }
}

impl ExecutorStatus {
    fn validate(&self) -> Result<()> {
        check_version(self.v)?;
        check_time(&self.updated_at)?;
        check_id(&self.boot_id)?;
        check_text("executor_version", &self.executor_version, 64)?;
        self.slots.blue.validate()?;
        self.slots.green.validate()?;
        if let Some(result) = &self.last_result {
            check_text("reason", &result.reason, 4096)?;
            if result.log_tail.len() > MAX_LOG_LINES {
                return Err(Error::msg("log tail too long"));
            }
            for line in &result.log_tail {
                if line.len() > MAX_LOG_LINE {
                    return Err(Error::msg("log line too long"));
                }
            }
        }
        Ok(())
    }
}

impl SlotStatus {
    fn validate(&self) -> Result<()> {
        check_time(&self.since)?;
        if let Some(until) = &self.warm_until {
            check_time(until)?;
        }
        if let Some(id) = &self.release_id {
            check_id(id)?;
        }
        Ok(())
    }
}

impl ManagerState {
    fn validate(&self) -> Result<()> {
        check_version(self.v)?;
        if let Some(sha) = &self.last_observed_sha {
            check_sha(sha)?;
        }
        if let Some(sha) = &self.last_deployed_sha {
            check_sha(sha)?;
        }
        if let Some(sha) = &self.last_failed_sha {
            check_sha(sha)?;
        }
        if let Some(at) = &self.next_poll_at {
            check_time(at)?;
        }
        if let Some(at) = &self.token_expires_at {
            check_time(at)?;
        }
        for record in &self.history {
            check_sha(&record.sha)?;
            check_id(&record.release_id)?;
            check_time(&record.at)?;
            check_text("outcome", &record.outcome, 64)?;
        }
        Ok(())
    }
}

fn write_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(Error::TooLarge {
            len: bytes.len() as u64,
            max: MAX_JSON_BYTES,
        });
    }
    write_atomic(path, &bytes, mode)
}

fn decode_raw<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(Error::TooLarge {
            len: bytes.len() as u64,
            max: MAX_JSON_BYTES,
        });
    }
    if bytes.is_empty() {
        return Err(Error::msg("empty json"));
    }
    Ok(serde_json::from_slice(bytes)?)
}

fn trim_log_tail(lines: &mut Vec<String>) {
    if lines.len() > MAX_LOG_LINES {
        let drop_n = lines.len() - MAX_LOG_LINES;
        lines.drain(0..drop_n);
    }
    for line in lines {
        if line.len() > MAX_LOG_LINE {
            line.truncate(MAX_LOG_LINE);
        }
    }
}

fn check_version(v: u32) -> Result<()> {
    if v != SCHEMA_VERSION {
        Err(Error::Version { found: v })
    } else {
        Ok(())
    }
}

fn check_id(value: &str) -> Result<()> {
    if (8..=64).contains(&value.len()) && value.chars().all(|c| c.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(Error::msg(format!("bad id `{value}`")))
    }
}

fn check_sha(value: &str) -> Result<()> {
    if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Error::msg(format!(
            "sha must be 40 hex chars, got `{value}`"
        )))
    }
}

fn check_sha256(value: &str) -> Result<()> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Error::msg("tree_sha256 must be 64 hex chars"))
    }
}

fn check_time(value: &str) -> Result<()> {
    if value.len() > 64 {
        return Err(Error::msg("timestamp too long"));
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|err| Error::msg(err.to_string()))?;
    Ok(())
}

fn check_text(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max || value.contains('\0') {
        return Err(Error::msg(format!("{field} is invalid")));
    }
    Ok(())
}

fn check_health(health: &Health) -> Result<()> {
    check_text("health.path", &health.path, 512)?;
    if !health.path.starts_with('/') {
        return Err(Error::msg("health path must start with /"));
    }
    if health.timeout_s == 0 || health.timeout_s > 3600 || health.consecutive == 0 {
        return Err(Error::msg("health timeout or consecutive is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn slot_ports_are_base_and_base_plus_one() {
        assert_eq!(Slot::Blue.loopback_port(3001).unwrap(), 3001);
        assert_eq!(Slot::Green.loopback_port(3001).unwrap(), 3002);
        assert!(Slot::Green.loopback_port(u16::MAX).is_err());
    }

    fn sample_release() -> ReleaseManifest {
        ReleaseManifest {
            v: 1,
            release_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            slot: Slot::Blue,
            sha: "a".repeat(40),
            branch: "main".into(),
            commit_message: "hello".into(),
            commit_author: "dev".into(),
            built_at: "2026-01-01T00:00:00Z".into(),
            rendering: Rendering::Ssr,
            runtime: RuntimeKind::Node,
            node_major: "22".into(),
            start_argv: vec!["node".into(), "server.js".into()],
            port_env: "PORT".into(),
            health: Health {
                path: "/".into(),
                expect: HealthExpect::Non2xxOk,
                timeout_s: 60,
                consecutive: 2,
            },
            spa_fallback: None,
            root: "app".into(),
            bytes: 12,
            file_count: 1,
            tree_sha256: "b".repeat(64),
        }
    }

    #[test]
    fn release_roundtrip_and_unknown_field() {
        let release = sample_release();
        let bytes = serde_json::to_vec(&release).unwrap();
        let back = decode_release(&bytes).unwrap();
        assert_eq!(back, release);
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(decode_release(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("extra");
        value["v"] = serde_json::json!(2);
        assert!(matches!(
            decode_release(&serde_json::to_vec(&value).unwrap()),
            Err(Error::Version { found: 2 })
        ));
    }

    #[test]
    fn desired_and_status_roundtrip() {
        let desired = Desired {
            v: 1,
            generation: 42,
            live_slot: Slot::Green,
            action: DesiredAction::Activate,
            evict_slot: None,
            warm_grace_s: 86_400,
            restart_nonce: "n".into(),
            written_at: "2026-01-01T00:00:00Z".into(),
        };
        assert_eq!(
            decode_desired(&serde_json::to_vec(&desired).unwrap()).unwrap(),
            desired
        );
        let status = ExecutorStatus::initial("0.1.0");
        let back = decode_status(&serde_json::to_vec(&status).unwrap()).unwrap();
        assert_eq!(back.ack_generation, 0);
        assert_eq!(back.slots.blue.state, SlotState::Empty);
    }

    #[test]
    fn torn_json_is_an_error() {
        assert!(decode_desired(br#"{"v":1,"generation":"#).is_err());
        assert!(decode_state(b"").is_err());
    }

    #[test]
    fn history_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = ManagerState::default();
        for i in 0..30 {
            state.history.push(DeployRecord {
                sha: format!("{i:040x}"),
                release_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                slot: Slot::Blue,
                at: "2026-01-01T00:00:00Z".into(),
                outcome: "live".into(),
                reason: String::new(),
            });
        }
        write_state(&path, &state).unwrap();
        let got = read_state(&path).unwrap();
        assert_eq!(got.history.len(), 20);
        assert!(got.history[0].sha.ends_with("a"));
    }

    #[test]
    fn desired_json_stays_parseable_at_every_failpoint() {
        use crate::atomic::{AtomicPoint, write_atomic, write_atomic_failpoint};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desired.json");
        let old = Desired::noop(1, Slot::Blue, 30);
        let new = Desired::noop(2, Slot::Green, 30);
        write_desired(&path, &old).unwrap();
        let old_bytes = std::fs::read(&path).unwrap();
        let new_bytes = serde_json::to_vec(&new).unwrap();
        for point in [
            AtomicPoint::AfterTmpWrite,
            AtomicPoint::AfterFsyncFile,
            AtomicPoint::AfterRename,
            AtomicPoint::AfterFsyncDir,
        ] {
            write_atomic(&path, &old_bytes, 0o644).unwrap();
            let _ = write_atomic_failpoint(&path, &new_bytes, 0o644, point);
            let bytes = std::fs::read(&path).unwrap();
            let decoded = decode_desired(&bytes).expect("desired.json must stay whole");
            assert!(decoded.generation == 1 || decoded.generation == 2);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn arbitrary_bytes_do_not_panic(bytes in prop::collection::vec(any::<u8>(), 0..128)) {
            let panicked = catch_unwind(AssertUnwindSafe(|| {
                let _ = decode_desired(&bytes);
                let _ = decode_release(&bytes);
                let _ = decode_status(&bytes);
                let _ = decode_state(&bytes);
            }))
            .is_err();
            prop_assert!(!panicked);
        }
    }
}
