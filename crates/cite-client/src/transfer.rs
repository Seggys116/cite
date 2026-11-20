//! Node-to-node database transfer: the client side of the export and import routes, and the driver that moves one
//! database between two nodes (design N4).
//!
//! The driver runs in the dashboard server and in the desktop app; browsers never relay the bytes. It is resumable
//! because both connectors keep durable sessions: `resume` reads what they report and continues from there, and
//! trusts them over its own saved copy. A chunk is read from the source, checked against its hash, written to the
//! target and forgotten, so at most four chunks (8 MiB each) are in memory at once however large the dump is.
//!
//! Generated secrets travel in the export manifest. This module holds them only between the manifest call and the
//! import call and wipes them after, never logs them and never writes them into a transfer state.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cite_edge::datawire::{
    ExportReq, FinishOutcome, FinishReq, Freeze, ImportReq, JobAccepted, Session, SessionStarted,
    SessionState, TRANSFER_CHUNK_BYTES, TableCount, TransferManifest, TransferMode, chunk_count,
    has_received,
};
use futures_util::StreamExt;
use futures_util::stream;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::client::{NodeClient, decode, enc, error_message, read_capped};
use crate::data::{validate_database_ref, validate_pg_name};
use crate::error::ClientError;
use crate::fsio::new_id;
use crate::site_ops::validate_job_id;
use crate::zone::validate_site_id;

type Res<T> = std::result::Result<T, ClientError>;

/// Header that carries a chunk's hex sha256, in both directions.
pub const CHUNK_SHA256_HEADER: &str = "x-chunk-sha256";
/// How often a session is polled while a node works.
pub const DEFAULT_POLL: Duration = Duration::from_secs(2);
/// Chunks moving at once.
pub const CONCURRENCY: usize = 4;
const RETRIES: u32 = 3;
const RETRY_BASE: Duration = Duration::from_millis(500);
const SAVE_EVERY: u64 = 64;
const CHUNK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_ERROR_CHARS: usize = 512;

// ---- the node client: export and import routes ----

/// One chunk read from the source, already checked against the hash the node sent with it.
#[derive(Debug)]
pub struct ExportChunk {
    pub data: Vec<u8>,
    pub sha256: String,
}

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

fn data_path(site_id: &str, rest: &str) -> Res<String> {
    let id = validate_site_id(site_id)?;
    Ok(format!("/sites/{}/data{rest}", enc(id)))
}

fn session_path(site_id: &str, kind: &str, sid: &str, rest: &str) -> Res<String> {
    let sid = validate_job_id(sid)?;
    data_path(site_id, &format!("/{kind}/{}{rest}", enc(sid)))
}

fn is_lower_hex_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl NodeClient {
    /// Polling a conversion; the start, cutover and abort calls are in `data`.
    pub async fn site_pg_convert_get(&self, site_id: &str, session_id: &str) -> Res<Session> {
        let path = session_path(site_id, "postgres/convert", session_id, "")?;
        self.json(Method::GET, &path, &[], None).await
    }

    pub async fn site_export_create(&self, site_id: &str, req: &ExportReq) -> Res<SessionStarted> {
        validate_database_ref(&req.database)?;
        let path = data_path(site_id, "/exports")?;
        self.exec_json(Method::POST, &path, json_body(req)?).await
    }

    pub async fn site_export_get(&self, site_id: &str, session_id: &str) -> Res<Session> {
        let path = session_path(site_id, "exports", session_id, "")?;
        self.json(Method::GET, &path, &[], None).await
    }

    /// The manifest of a ready export. It carries generated secrets, so it is not logged and not kept.
    pub async fn site_export_manifest(
        &self,
        site_id: &str,
        session_id: &str,
    ) -> Res<TransferManifest> {
        let path = session_path(site_id, "exports", session_id, "/manifest")?;
        self.json(Method::GET, &path, &[], None).await
    }

    /// Chunk `n` of a ready export. The node's hash header is required and must match the bytes.
    pub async fn site_export_chunk(
        &self,
        site_id: &str,
        session_id: &str,
        n: u64,
    ) -> Res<ExportChunk> {
        let path = session_path(site_id, "exports", session_id, &format!("/chunks/{n}"))?;
        let url = format!("{}/api/v1{path}", self.base_url());
        let resp = self
            .authed_get(url)
            .timeout(CHUNK_TIMEOUT)
            .send()
            .await
            .map_err(ClientError::from_reqwest)?;
        if !resp.status().is_success() {
            let (status, _, buf) = read_capped(resp).await?;
            return Err(ClientError::Status {
                code: status.as_u16(),
                message: error_message(&buf, status),
            });
        }
        let claimed = resp
            .headers()
            .get(CHUNK_SHA256_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase)
            .filter(|v| is_lower_hex_sha256(v))
            .ok_or_else(|| ClientError::Decode("the node sent no valid chunk checksum".into()))?;
        let limit = u64::from(TRANSFER_CHUNK_BYTES);
        if resp.content_length().is_some_and(|len| len > limit) {
            return Err(ClientError::Decode("a chunk is larger than 8 MiB".into()));
        }
        let mut resp = resp;
        let mut data: Vec<u8> = Vec::new();
        while let Some(piece) = resp.chunk().await.map_err(ClientError::from_reqwest)? {
            if data.len() as u64 + piece.len() as u64 > limit {
                return Err(ClientError::Decode("a chunk is larger than 8 MiB".into()));
            }
            data.extend_from_slice(&piece);
        }
        if sha_hex(&data) != claimed {
            return Err(ClientError::Decode(
                "a chunk does not match the checksum the node sent".into(),
            ));
        }
        Ok(ExportChunk {
            data,
            sha256: claimed,
        })
    }

    pub async fn site_export_finish(
        &self,
        site_id: &str,
        session_id: &str,
        req: &FinishReq,
    ) -> Res<Session> {
        let path = session_path(site_id, "exports", session_id, "/finish")?;
        self.exec_json(Method::POST, &path, json_body(req)?).await
    }

    /// Runs a failed export again from its freeze.
    pub async fn site_export_retry(&self, site_id: &str, session_id: &str) -> Res<SessionStarted> {
        let path = session_path(site_id, "exports", session_id, "/retry")?;
        self.exec_json(Method::POST, &path, b"{}".to_vec()).await
    }

    pub async fn site_export_delete(&self, site_id: &str, session_id: &str) -> Res<()> {
        let path = session_path(site_id, "exports", session_id, "")?;
        self.unit(Method::DELETE, &path).await
    }

    /// Starts an import. The request carries generated secrets, so it goes out as bytes and is never echoed.
    pub async fn site_import_create(&self, site_id: &str, req: &ImportReq) -> Res<SessionStarted> {
        validate_database_ref(&req.manifest.database)?;
        let path = data_path(site_id, "/imports")?;
        self.exec_json(Method::POST, &path, json_body(req)?).await
    }

    pub async fn site_import_get(&self, site_id: &str, session_id: &str) -> Res<Session> {
        let path = session_path(site_id, "imports", session_id, "")?;
        self.json(Method::GET, &path, &[], None).await
    }

    /// Uploads one chunk. Sending a received chunk again is harmless; a different body for it is a 409.
    pub async fn site_import_chunk(
        &self,
        site_id: &str,
        session_id: &str,
        n: u64,
        sha256: &str,
        data: Vec<u8>,
    ) -> Res<()> {
        if !is_lower_hex_sha256(sha256) {
            return Err(invalid("a chunk checksum is 64 lowercase hex digits"));
        }
        let path = session_path(site_id, "imports", session_id, &format!("/chunks/{n}"))?;
        let url = format!("{}/api/v1{path}", self.base_url());
        // The request builder of this client only offers authenticated GETs; the method, body and header are set on the
        // built request, which keeps the bearer token and the connection settings.
        let (client, built) = self.authed_get(url).build_split();
        let mut request = built.map_err(ClientError::from_reqwest)?;
        *request.method_mut() = Method::PUT;
        *request.body_mut() = Some(reqwest::Body::from(data));
        *request.timeout_mut() = Some(CHUNK_TIMEOUT);
        let value = reqwest::header::HeaderValue::from_str(sha256)
            .map_err(|_| invalid("a chunk checksum is not a header value"))?;
        request.headers_mut().insert(CHUNK_SHA256_HEADER, value);
        request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/octet-stream"),
        );
        let resp = client
            .execute(request)
            .await
            .map_err(ClientError::from_reqwest)?;
        let (status, _, buf) = read_capped(resp).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(ClientError::Status {
                code: status.as_u16(),
                message: error_message(&buf, status),
            })
        }
    }

    /// Starts the commit (checksum, restore, row counts) as a job on the target.
    pub async fn site_import_commit(
        &self,
        site_id: &str,
        session_id: &str,
        override_manual: bool,
    ) -> Res<JobAccepted> {
        let path = session_path(site_id, "imports", session_id, "/commit")?;
        self.exec_json(
            Method::POST,
            &path,
            serde_json::to_vec(&json!({ "override": override_manual }))
                .map_err(|_| invalid("cannot encode request"))?,
        )
        .await
    }

    pub async fn site_import_finish(
        &self,
        site_id: &str,
        session_id: &str,
        req: &FinishReq,
    ) -> Res<Session> {
        let path = session_path(site_id, "imports", session_id, "/finish")?;
        self.exec_json(Method::POST, &path, json_body(req)?).await
    }

    pub async fn site_import_delete(&self, site_id: &str, session_id: &str) -> Res<()> {
        let path = session_path(site_id, "imports", session_id, "")?;
        self.unit(Method::DELETE, &path).await
    }

    async fn exec_json<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Res<T> {
        let bytes = self
            .exec_json_bytes(method, path, body, crate::client::ACTION_OPTS)
            .await?;
        decode(&bytes)
    }
}

fn json_body<B: Serialize>(body: &B) -> Res<Vec<u8>> {
    serde_json::to_vec(body).map_err(|_| invalid("cannot encode request"))
}

// ---- cancellation ----

/// A shared flag that asks a running transfer to stop at its next step.
#[derive(Debug, Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

// ---- state ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferPlan {
    pub source_node: String,
    pub target_node: String,
    pub site: String,
    /// `pg:<name>`; a bare name is accepted and normalised.
    pub database: String,
    #[serde(default)]
    pub freeze: Freeze,
    /// Replace manual env vars of the same name when the links are created on the target.
    #[serde(default)]
    pub override_manual: bool,
    /// Replace an existing database of the same name on the target (a pre_restore backup is taken first).
    #[serde(default)]
    pub replace: bool,
    /// Finish both sides as soon as the row counts match; otherwise the transfer waits at `verifying` for the operator.
    #[serde(default)]
    pub auto_cutover: bool,
}

impl TransferPlan {
    /// Checks every name and returns the plan with the database as `pg:<name>`.
    pub fn validated(mut self) -> Res<TransferPlan> {
        if self.source_node.is_empty() || self.target_node.is_empty() {
            return Err(invalid("choose a source and a target node"));
        }
        if self.source_node == self.target_node {
            return Err(invalid("the source and the target must be different nodes"));
        }
        validate_site_id(&self.site)?;
        let db = self.database.strip_prefix("pg:").unwrap_or(&self.database);
        validate_pg_name(db)?;
        self.database = format!("pg:{db}");
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPhase {
    Pending,
    Freezing,
    Dumping,
    Streaming,
    Restoring,
    Verifying,
    Cutover,
    Done,
    Failed,
    RolledBack,
}

impl TransferPhase {
    pub fn is_finished(self) -> bool {
        matches!(self, TransferPhase::Done | TransferPhase::RolledBack)
    }
}

/// A table whose row count differs between the two sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountDiff {
    pub schema: String,
    pub table: String,
    /// None: the table is not on the source.
    pub source: Option<u64>,
    /// None: the table is not on the target.
    pub target: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferState {
    pub id: String,
    pub plan: TransferPlan,
    pub phase: TransferPhase,
    #[serde(default)]
    pub export_id: Option<String>,
    #[serde(default)]
    pub import_id: Option<String>,
    #[serde(default)]
    pub bytes_done: u64,
    #[serde(default)]
    pub bytes_total: u64,
    #[serde(default)]
    pub counts_match: Option<bool>,
    #[serde(default)]
    pub mismatches: Vec<CountDiff>,
    #[serde(default)]
    pub error: Option<String>,
    pub updated_at: String,
}

impl TransferState {
    /// The data is on the target and the counts were compared: only the operator's cutover or rollback is left.
    pub fn awaiting_operator(&self) -> bool {
        self.phase == TransferPhase::Verifying && self.counts_match.is_some()
    }

    pub fn new(plan: TransferPlan) -> Res<TransferState> {
        Ok(TransferState {
            id: new_id(),
            plan: plan.validated()?,
            phase: TransferPhase::Pending,
            export_id: None,
            import_id: None,
            bytes_done: 0,
            bytes_total: 0,
            counts_match: None,
            mismatches: Vec::new(),
            error: None,
            updated_at: rfc3339_now(),
        })
    }
}

/// Where transfer states are kept between runs. `save` is called after every phase change and every 64 chunks.
pub trait TransferStore: Send + Sync {
    fn load(&self, id: &str) -> Option<TransferState>;
    fn save(&self, state: &TransferState) -> Res<()>;
}

/// A store that keeps states in memory only.
#[derive(Debug, Default)]
pub struct MemoryTransferStore {
    states: Mutex<HashMap<String, TransferState>>,
}

impl MemoryTransferStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TransferStore for MemoryTransferStore {
    fn load(&self, id: &str) -> Option<TransferState> {
        self.states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned()
    }

    fn save(&self, state: &TransferState) -> Res<()> {
        self.states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(state.id.clone(), state.clone());
        Ok(())
    }
}

// ---- errors ----

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("the transfer was cancelled")]
    Cancelled,
    #[error("{0}")]
    Node(#[from] ClientError),
    /// A node reported a failed step, or a check of the data did not pass.
    #[error("{0}")]
    Failed(String),
    #[error("the transfer state could not be saved: {0}")]
    Store(String),
}

impl TransferError {
    fn retryable(&self) -> bool {
        match self {
            TransferError::Node(ClientError::Transport { .. } | ClientError::Decode(_)) => true,
            TransferError::Node(ClientError::Status { code, .. }) => {
                *code >= 500 || matches!(*code, 429 | 409)
            }
            _ => false,
        }
    }
}

// ---- the driver ----

/// What a run needs besides the state itself.
pub struct TransferEnv<'a> {
    pub source: &'a NodeClient,
    pub target: &'a NodeClient,
    pub store: &'a dyn TransferStore,
    pub cancel: CancelFlag,
    /// Called after every change of the state (a chunk, a phase). It must be quick.
    pub progress: &'a (dyn Fn(&TransferState) + Send + Sync),
    /// How often a session is polled while a node works.
    pub poll: Duration,
}

fn rfc3339_now() -> String {
    rfc3339_at(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

fn rfc3339_at(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

fn expected_chunk_len(n: u64, size: u64) -> u64 {
    let chunk = u64::from(TRANSFER_CHUNK_BYTES);
    chunk.min(size.saturating_sub(n.saturating_mul(chunk)))
}

/// Tables whose counts differ, are missing on one side or exist on one side only.
pub fn compare_counts(source: &[TableCount], target: &[TableCount]) -> Vec<CountDiff> {
    let index = |list: &[TableCount]| -> BTreeMap<(String, String), u64> {
        list.iter()
            .map(|c| ((c.schema.clone(), c.table.clone()), c.rows))
            .collect()
    };
    let (s, t) = (index(source), index(target));
    let mut out = Vec::new();
    for (key, rows) in &s {
        if t.get(key) != Some(rows) {
            out.push(CountDiff {
                schema: key.0.clone(),
                table: key.1.clone(),
                source: Some(*rows),
                target: t.get(key).copied(),
            });
        }
    }
    for (key, rows) in &t {
        if !s.contains_key(key) {
            out.push(CountDiff {
                schema: key.0.clone(),
                table: key.1.clone(),
                source: None,
                target: Some(*rows),
            });
        }
    }
    out
}

fn record(env: &TransferEnv<'_>, state: &mut TransferState) -> Result<(), TransferError> {
    state.updated_at = rfc3339_now();
    env.store
        .save(state)
        .map_err(|e| TransferError::Store(e.to_string()))?;
    (env.progress)(state);
    Ok(())
}

fn set_phase(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
    phase: TransferPhase,
) -> Result<(), TransferError> {
    if state.phase == phase {
        return Ok(());
    }
    state.phase = phase;
    record(env, state)
}

fn check_cancel(env: &TransferEnv<'_>) -> Result<(), TransferError> {
    if env.cancel.is_cancelled() {
        Err(TransferError::Cancelled)
    } else {
        Ok(())
    }
}

fn failure(what: &str, session: &Session) -> TransferError {
    TransferError::Failed(format!(
        "{what}: {}",
        session.error.as_deref().unwrap_or("no reason was given")
    ))
}

/// Starts a transfer, or carries on one that has not run yet. A step that fails stops the run with an error and leaves
/// the state at `failed`; `resume` tries again.
pub async fn run(env: &TransferEnv<'_>, state: &mut TransferState) -> Result<(), TransferError> {
    guarded(env, state, false).await
}

/// Reads what both nodes report and continues from there. A step a node marked failed is retried once.
pub async fn resume(env: &TransferEnv<'_>, state: &mut TransferState) -> Result<(), TransferError> {
    guarded(env, state, true).await
}

async fn guarded(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
    retry_failed: bool,
) -> Result<(), TransferError> {
    if state.phase.is_finished() {
        return Ok(());
    }
    state.error = None;
    let outcome = if state.phase == TransferPhase::Cutover {
        cutover(env, state).await
    } else {
        drive(env, state, retry_failed).await
    };
    if let Err(e) = &outcome {
        state.error = Some(clip(&e.to_string()));
        // A cutover that stopped halfway stays a cutover, so that repeating it finishes the job.
        if state.phase != TransferPhase::Cutover {
            state.phase = TransferPhase::Failed;
        }
        let _ = record(env, state);
    }
    outcome
}

async fn drive(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
    mut retry_failed: bool,
) -> Result<(), TransferError> {
    let site = state.plan.site.clone();
    check_cancel(env)?;
    // 1. the export on the source
    let export_id = match state.export_id.clone() {
        Some(id) => id,
        None => {
            set_phase(env, state, TransferPhase::Freezing)?;
            let started = env
                .source
                .site_export_create(
                    &site,
                    &ExportReq {
                        database: state.plan.database.clone(),
                        freeze: state.plan.freeze,
                        mode: TransferMode::Staged,
                    },
                )
                .await?;
            state.export_id = Some(started.session.clone());
            record(env, state)?;
            started.session
        }
    };
    let export = wait_export(env, state, &site, &export_id, &mut retry_failed).await?;

    // 2. the import on the target
    let import_id = match state.import_id.clone() {
        Some(id) => id,
        None => {
            check_cancel(env)?;
            let manifest = env.source.site_export_manifest(&site, &export_id).await?;
            check_manifest(&manifest, &export)?;
            state.bytes_total = manifest.size_bytes;
            let mut request = ImportReq {
                manifest,
                replace: state.plan.replace,
            };
            let created = env.target.site_import_create(&site, &request).await;
            // The carried secrets are wiped whatever the answer was.
            for secret in &mut request.manifest.generated_secrets {
                secret.value.zeroize();
            }
            let created = created?;
            state.import_id = Some(created.session.clone());
            record(env, state)?;
            created.session
        }
    };

    // 3. stream, commit, wait
    let mut import;
    loop {
        check_cancel(env)?;
        import = env.target.site_import_get(&site, &import_id).await?;
        match import.state {
            SessionState::Receiving => {
                stream_chunks(env, state, &site, &export_id, &import_id, &import).await?;
                set_phase(env, state, TransferPhase::Restoring)?;
                env.target
                    .site_import_commit(&site, &import_id, state.plan.override_manual)
                    .await?;
            }
            SessionState::Verifying => set_phase(env, state, TransferPhase::Verifying)?,
            SessionState::Restoring => set_phase(env, state, TransferPhase::Restoring)?,
            SessionState::AwaitingCutover => break,
            SessionState::Failed => {
                if retry_failed {
                    retry_failed = false;
                    set_phase(env, state, TransferPhase::Restoring)?;
                    env.target
                        .site_import_commit(&site, &import_id, state.plan.override_manual)
                        .await?;
                } else {
                    return Err(failure("the import failed on the target", &import));
                }
            }
            SessionState::Done => {
                set_phase(env, state, TransferPhase::Done)?;
                return Ok(());
            }
            SessionState::RolledBack => {
                set_phase(env, state, TransferPhase::RolledBack)?;
                return Ok(());
            }
            other => {
                return Err(TransferError::Failed(format!(
                    "the import is in an unexpected state ({other:?})"
                )));
            }
        }
        tokio::time::sleep(env.poll).await;
    }

    // 4. compare the row counts of both sides
    let source_counts = export.counts.clone().unwrap_or_default();
    let target_counts = import.counts.clone().unwrap_or_default();
    state.mismatches = compare_counts(&source_counts, &target_counts);
    state.counts_match = Some(state.mismatches.is_empty());
    state.bytes_done = state.bytes_total;
    set_phase(env, state, TransferPhase::Verifying)?;
    record(env, state)?;
    if state.counts_match == Some(true) && state.plan.auto_cutover {
        return cutover(env, state).await;
    }
    Ok(())
}

fn check_manifest(manifest: &TransferManifest, export: &Session) -> Result<(), TransferError> {
    let consistent = manifest.size_bytes == export.size_bytes
        && manifest.sha256 == export.sha256
        && manifest.chunks == export.chunks
        && manifest.chunk_size == export.chunk_size
        && manifest.chunk_size == TRANSFER_CHUNK_BYTES
        && manifest.chunks == chunk_count(manifest.size_bytes, manifest.chunk_size);
    if consistent {
        Ok(())
    } else {
        Err(TransferError::Failed(
            "the source's manifest disagrees with its export session".into(),
        ))
    }
}

async fn wait_export(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
    site: &str,
    export_id: &str,
    retry_failed: &mut bool,
) -> Result<Session, TransferError> {
    loop {
        check_cancel(env)?;
        let session = env.source.site_export_get(site, export_id).await?;
        match session.state {
            SessionState::Ready => return Ok(session),
            SessionState::Pending | SessionState::Freezing => {
                set_phase(env, state, TransferPhase::Freezing)?
            }
            SessionState::Dumping => set_phase(env, state, TransferPhase::Dumping)?,
            SessionState::Failed => {
                if *retry_failed {
                    *retry_failed = false;
                    set_phase(env, state, TransferPhase::Freezing)?;
                    env.source.site_export_retry(site, export_id).await?;
                } else {
                    return Err(failure("the export failed on the source", &session));
                }
            }
            SessionState::Done | SessionState::RolledBack => {
                return Err(TransferError::Failed(
                    "the export on the source was already finished".into(),
                ));
            }
            other => {
                return Err(TransferError::Failed(format!(
                    "the export is in an unexpected state ({other:?})"
                )));
            }
        }
        tokio::time::sleep(env.poll).await;
    }
}

async fn stream_chunks(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
    site: &str,
    export_id: &str,
    import_id: &str,
    import: &Session,
) -> Result<(), TransferError> {
    let size = import.size_bytes;
    let missing: Vec<u64> = (0..import.chunks)
        .filter(|n| !has_received(&import.received, *n))
        .collect();
    let mut done: u64 = (0..import.chunks)
        .filter(|n| has_received(&import.received, *n))
        .map(|n| expected_chunk_len(n, size))
        .sum();
    state.bytes_total = size;
    state.bytes_done = done;
    set_phase(env, state, TransferPhase::Streaming)?;
    record(env, state)?;
    let (source, target) = (env.source, env.target);
    let mut moving = stream::iter(missing)
        .map(|n| async move {
            move_chunk(source, target, site, export_id, import_id, n, size)
                .await
                .map(|len| (n, len))
        })
        .buffer_unordered(CONCURRENCY);
    let mut since_save = 0u64;
    while let Some(result) = moving.next().await {
        let (_, len) = result?;
        done += len;
        state.bytes_done = done;
        since_save += 1;
        if since_save >= SAVE_EVERY {
            since_save = 0;
            record(env, state)?;
        } else {
            (env.progress)(state);
        }
        check_cancel(env)?;
    }
    record(env, state)
}

/// Reads chunk `n` from the source and writes it to the target, retrying a transient failure three times.
async fn move_chunk(
    source: &NodeClient,
    target: &NodeClient,
    site: &str,
    export_id: &str,
    import_id: &str,
    n: u64,
    size: u64,
) -> Result<u64, TransferError> {
    let want = expected_chunk_len(n, size);
    let mut attempt = 0u32;
    loop {
        let moved: Result<u64, TransferError> = async {
            let chunk = source.site_export_chunk(site, export_id, n).await?;
            if chunk.data.len() as u64 != want {
                return Err(TransferError::Failed(format!(
                    "chunk {n} has {} bytes, expected {want}",
                    chunk.data.len()
                )));
            }
            target
                .site_import_chunk(site, import_id, n, &chunk.sha256, chunk.data)
                .await?;
            Ok(want)
        }
        .await;
        match moved {
            Ok(len) => return Ok(len),
            Err(e) if attempt < RETRIES && e.retryable() => {
                attempt += 1;
                tokio::time::sleep(RETRY_BASE * 2u32.pow(attempt - 1)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Finishes both sessions with `cutover`: the target keeps the imported data, the source stays frozen until it is
/// deleted. Allowed only when the row counts matched. Safe to repeat after a failure between the two calls.
pub async fn cutover(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
) -> Result<(), TransferError> {
    let outcome = cutover_steps(env, state).await;
    if let Err(e) = &outcome {
        state.error = Some(clip(&e.to_string()));
        let _ = record(env, state);
    }
    outcome
}

async fn cutover_steps(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
) -> Result<(), TransferError> {
    if state.phase.is_finished() {
        return Ok(());
    }
    if state.counts_match != Some(true) && state.phase != TransferPhase::Cutover {
        return Err(TransferError::Failed(
            "the row counts of the two databases do not match; roll the transfer back or compare the tables first".into(),
        ));
    }
    let site = state.plan.site.clone();
    let (Some(export_id), Some(import_id)) = (state.export_id.clone(), state.import_id.clone())
    else {
        return Err(TransferError::Failed(
            "the transfer has not reached the target yet".into(),
        ));
    };
    set_phase(env, state, TransferPhase::Cutover)?;
    let finish = FinishReq {
        outcome: FinishOutcome::Cutover,
        override_manual: false,
    };
    let import = env.target.site_import_get(&site, &import_id).await?;
    match import.state {
        SessionState::AwaitingCutover => {
            env.target
                .site_import_finish(&site, &import_id, &finish)
                .await?;
        }
        SessionState::Done => {}
        other => {
            return Err(TransferError::Failed(format!(
                "the import cannot be finished while it is {other:?}"
            )));
        }
    }
    let export = env.source.site_export_get(&site, &export_id).await?;
    match export.state {
        SessionState::Ready => {
            env.source
                .site_export_finish(&site, &export_id, &finish)
                .await?;
        }
        SessionState::Done => {}
        other => {
            return Err(TransferError::Failed(format!(
                "the export cannot be finished while it is {other:?}"
            )));
        }
    }
    set_phase(env, state, TransferPhase::Done)
}

/// Abandons a transfer that has not cut over: the target's import is aborted (the pre-restore data comes back) and the
/// source's freeze is lifted. A step that is still running is waited for first.
pub async fn rollback(
    env: &TransferEnv<'_>,
    state: &mut TransferState,
) -> Result<(), TransferError> {
    if state.phase.is_finished() {
        return Ok(());
    }
    let site = state.plan.site.clone();
    let abort = FinishReq {
        outcome: FinishOutcome::Abort,
        override_manual: false,
    };
    let outcome: Result<(), TransferError> = async {
        if let Some(import_id) = state.import_id.clone() {
            loop {
                check_cancel(env)?;
                let import = env.target.site_import_get(&site, &import_id).await?;
                match import.state {
                    SessionState::Receiving
                    | SessionState::AwaitingCutover
                    | SessionState::Failed => {
                        env.target
                            .site_import_finish(&site, &import_id, &abort)
                            .await?;
                        break;
                    }
                    SessionState::RolledBack => break,
                    SessionState::Done => {
                        return Err(TransferError::Failed(
                            "the import was already finished; it cannot be rolled back".into(),
                        ));
                    }
                    _ => tokio::time::sleep(env.poll).await,
                }
            }
        }
        if let Some(export_id) = state.export_id.clone() {
            loop {
                check_cancel(env)?;
                let export = env.source.site_export_get(&site, &export_id).await?;
                match export.state {
                    SessionState::Ready | SessionState::Failed => {
                        env.source
                            .site_export_finish(&site, &export_id, &abort)
                            .await?;
                        break;
                    }
                    SessionState::RolledBack => break,
                    SessionState::Done => {
                        return Err(TransferError::Failed(
                            "the export was already finished; it cannot be rolled back".into(),
                        ));
                    }
                    _ => tokio::time::sleep(env.poll).await,
                }
            }
        }
        Ok(())
    }
    .await;
    match outcome {
        Ok(()) => {
            state.error = None;
            set_phase(env, state, TransferPhase::RolledBack)
        }
        Err(e) => {
            state.error = Some(clip(&e.to_string()));
            let _ = record(env, state);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> TransferPlan {
        TransferPlan {
            source_node: "a".into(),
            target_node: "b".into(),
            site: "shop".into(),
            database: "app".into(),
            freeze: Freeze::Maintenance,
            override_manual: false,
            replace: false,
            auto_cutover: false,
        }
    }

    #[test]
    fn a_plan_is_checked_and_the_database_is_normalised() {
        let ok = plan().validated().unwrap();
        assert_eq!(ok.database, "pg:app");
        let mut p = plan();
        p.database = "pg:blog".into();
        assert_eq!(p.validated().unwrap().database, "pg:blog");
        let breakers: [fn(&mut TransferPlan); 6] = [
            |p| p.target_node = "a".into(),
            |p| p.source_node.clear(),
            |p| p.site = "Bad Site".into(),
            |p| p.database = "pg:Bad".into(),
            |p| p.database = "ext:billing".into(),
            |p| p.database = "a;b".into(),
        ];
        for breaker in breakers {
            let mut p = plan();
            breaker(&mut p);
            assert!(p.validated().is_err());
        }
    }

    #[test]
    fn plans_and_states_read_back_what_was_saved_and_refuse_unknown_fields() {
        let state = TransferState::new(plan()).unwrap();
        assert_eq!(state.phase, TransferPhase::Pending);
        assert!(state.updated_at.ends_with('Z') && state.updated_at.len() == 20);
        let text = serde_json::to_string(&state).unwrap();
        let back: TransferState = serde_json::from_str(&text).unwrap();
        assert_eq!(back, state);
        assert!(
            serde_json::from_str::<TransferPlan>(
                r#"{"source_node":"a","target_node":"b","site":"s","database":"pg:app","x":1}"#
            )
            .is_err()
        );
        let minimal: TransferPlan = serde_json::from_str(
            r#"{"source_node":"a","target_node":"b","site":"s","database":"pg:app"}"#,
        )
        .unwrap();
        assert_eq!(minimal.freeze, Freeze::Maintenance);
        assert!(!minimal.auto_cutover && !minimal.replace && !minimal.override_manual);
    }

    #[test]
    fn the_memory_store_keeps_the_last_save() {
        let store = MemoryTransferStore::new();
        let mut state = TransferState::new(plan()).unwrap();
        assert!(store.load(&state.id).is_none());
        store.save(&state).unwrap();
        state.phase = TransferPhase::Streaming;
        store.save(&state).unwrap();
        assert_eq!(
            store.load(&state.id).unwrap().phase,
            TransferPhase::Streaming
        );
    }

    #[test]
    fn counts_are_compared_table_by_table() {
        let c = |t: &str, rows: u64| TableCount {
            schema: "public".into(),
            table: t.into(),
            rows,
        };
        assert!(compare_counts(&[c("a", 1), c("b", 2)], &[c("b", 2), c("a", 1)]).is_empty());
        let diffs = compare_counts(&[c("a", 1), c("b", 2)], &[c("a", 1), c("b", 3), c("c", 9)]);
        assert_eq!(diffs.len(), 2);
        assert_eq!(
            diffs[0],
            CountDiff {
                schema: "public".into(),
                table: "b".into(),
                source: Some(2),
                target: Some(3)
            }
        );
        assert_eq!(diffs[1].table, "c");
        assert_eq!(diffs[1].source, None);
        let missing = compare_counts(&[c("a", 1)], &[]);
        assert_eq!(missing[0].target, None);
    }

    #[test]
    fn chunk_lengths_and_dates_are_right() {
        let c = u64::from(TRANSFER_CHUNK_BYTES);
        assert_eq!(expected_chunk_len(0, 5), 5);
        assert_eq!(expected_chunk_len(1, c + 3), 3);
        assert_eq!(expected_chunk_len(1, 2 * c), c);
        assert_eq!(rfc3339_at(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_at(951_868_800), "2000-03-01T00:00:00Z");
        assert_eq!(rfc3339_at(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_at(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_at(1_709_164_800 + 86_399), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn only_transient_failures_are_retried() {
        let status = |code| {
            TransferError::Node(ClientError::Status {
                code,
                message: String::new(),
            })
        };
        for code in [500, 502, 503, 429, 409] {
            assert!(status(code).retryable(), "{code}");
        }
        for code in [400, 401, 404, 413] {
            assert!(!status(code).retryable(), "{code}");
        }
        assert!(TransferError::Node(ClientError::timeout()).retryable());
        assert!(TransferError::Node(ClientError::Decode("x".into())).retryable());
        assert!(!TransferError::Failed("x".into()).retryable());
        assert!(!TransferError::Cancelled.retryable());
    }

    #[test]
    fn the_cancel_flag_is_shared_between_clones() {
        let a = CancelFlag::new();
        let b = a.clone();
        assert!(!b.is_cancelled());
        a.cancel();
        assert!(b.is_cancelled());
    }

    #[test]
    fn a_manifest_that_disagrees_with_its_session_is_refused() {
        let manifest = TransferManifest {
            site: "shop".into(),
            database: "pg:app".into(),
            server_version: "18.1".into(),
            size_bytes: 10,
            sha256: "ab".repeat(32),
            chunk_size: TRANSFER_CHUNK_BYTES,
            chunks: 1,
            counts: Vec::new(),
            users: Vec::new(),
            links: Vec::new(),
            generated_secrets: Vec::new(),
        };
        let session = |size: u64| Session {
            id: "x".into(),
            kind: cite_edge::datawire::SessionKind::Export,
            site: "shop".into(),
            database: "pg:app".into(),
            state: SessionState::Ready,
            freeze: Freeze::None,
            created_at: String::new(),
            updated_at: String::new(),
            backup_id: None,
            size_bytes: size,
            sha256: "ab".repeat(32),
            chunk_size: TRANSFER_CHUNK_BYTES,
            chunks: 1,
            received: Vec::new(),
            counts: None,
            peer_counts: None,
            pre_restore_backup: None,
            error: None,
            actor: String::new(),
        };
        assert!(check_manifest(&manifest, &session(10)).is_ok());
        assert!(check_manifest(&manifest, &session(11)).is_err());
    }
}
