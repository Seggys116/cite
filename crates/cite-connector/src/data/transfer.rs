//! Conversion between dedicated and shared Postgres, and staged node-to-node transfer (design section N).
//!
//! Both are sessions: small JSON files under `sites/<site>/sessions/` that survive a restart. A session that was
//! running a step when the connector stopped becomes `failed`; the ones that wait (`ready`, `receiving`,
//! `awaiting_cutover`) keep their data on disk and carry on. Neither a transfer nor a conversion ever drops the
//! source database.
//!
//! Freezes are durable and survive a connector restart:
//! - `maintenance` sets the site's maintenance flag and records whether it was already set.
//! - `read_only` sets `default_transaction_read_only` on the source database and switches every tenant login of it
//!   that could log in to NOLOGIN, ending its sessions; a login setting alone could be overridden by any session.
//!   Which logins were switched off is recorded on the server itself (a role comment only a superuser can change,
//!   written in the same transaction), so lifting the freeze gives LOGIN back to exactly those, also after a
//!   restart, and a rotation during the freeze keeps its new login switched off until then.
//!
//! What lifts them:
//! - Export abort: both are lifted. Export cutover (node to node): both stay, the source is frozen for good until
//!   its database or the site is deleted.
//! - Import: nothing is frozen on the target.
//! - Conversion abort: both are lifted. Conversion cutover (on this node): the maintenance flag returns to its
//!   earlier value because the site now runs on the new server; a `read_only` freeze stays on the retired source,
//!   whose data is stale from then on, until the retired database is deleted.
//!
//! An export is a backup version (trigger `transfer`) read back in 8 MiB chunks with one sha256 per chunk. An import
//! stores every chunk as its own small sealed stream under `imports/<session>/` (so a chunk survives a restart and an
//! idempotent re-send is a file lookup) and assembles them into a normal backup version on commit.
//!
//! Generated secrets travel in the export manifest. The values are served once, never logged, and an import keeps
//! them only in the sealed secret store, never in the session file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cite_edge::datamodel::{
    Alt, EnvLink, GeneratedSecret, LinkSource, PgDatabase, PgGroup, PgMode, PgUser,
    RetiredPostgres, SecretEncoding, generated_secret_name, is_pg_ident, is_resource_name,
    pg_db_name, pg_group, pg_retired_secret_name, pg_superuser_secret_name, pg_user_secret_name,
};
use cite_edge::datawire::{
    BackupPatchReq, BackupRecord, BackupStatus, BackupTrigger, EncryptionInfo, ExportReq,
    FinishOutcome, Freeze, ImportReq, LocalCopy, ManifestSecret, ManifestUser, Session,
    SessionKind, SessionState, TRANSFER_CHUNK_BYTES, TableCount, TransferManifest, TransferMode,
    TransferSource, TransferSummary, add_received, chunk_count, has_received,
};
use cite_edge::model::Site;
use cite_edge::validate::{
    MAX_GENERATED_SECRETS, MAX_PG_DATABASES, MAX_PG_USERS_PER_DATABASE, is_valid_id,
    validate_site_data,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit};
use ulid::Ulid;

use super::catalog::{BackupDirs, pg_key};
use super::env as denv;
use super::jobs::{DbRef, PgTarget, TenantJob, server_major};
use super::service::{
    DataService, GenSecret, JobCtx, cat_err, encoded_len, join_err, lk, public_error,
    valid_database_name,
};
use super::stream::{StreamReader, StreamSummary, StreamWriter};
use super::users::UserSecret;
use crate::orchestrator::data::JobOp;
use crate::seal::Keyring;
use crate::store::now_rfc3339;
use crate::{ConnectorError, Result};

/// Header that carries the hex sha256 of a chunk, in both directions.
pub const CHUNK_HEADER: &str = "x-chunk-sha256";
/// Chunks (8 MiB each) read or received at once on a node.
pub const CHUNK_PERMITS: usize = 4;
/// Largest dump a node accepts for import.
pub const MAX_TRANSFER_BYTES: u64 = 2 << 40;
/// Largest manifest body of an import.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_COUNTS: usize = 20_000;
const MAX_SESSION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_COUNTS_FILE: u64 = 8 * 1024 * 1024;
const MAX_UNRESOLVED_IMPORTS: usize = 2;
const PERMIT_WAIT: Duration = Duration::from_secs(60);
const RESTART_NOTE: &str = "interrupted by a connector restart; resume to retry this step";
const SCHEME: &str = "cite-stream-v1";
const FORMAT: &str = "pg_dump-custom";
const LABEL_EXPORT: &str = "node transfer";
const LABEL_CONVERT: &str = "mode conversion";
/// Free space an import leaves on the backup volume beyond the room it needs.
pub const SPACE_MARGIN_BYTES: u64 = 1 << 30;
/// Marks a refusal for lack of disk space; the API answers it with 507.
pub const NO_SPACE_PREFIX: &str = "not enough space: ";

#[cfg(test)]
thread_local! {
    /// Test hook: pretend the backup volume has this much room.
    pub(crate) static FREE_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// An import holds the received chunks and the assembled dump side by side, so it needs twice the dump plus a margin.
pub(crate) fn check_space(size: u64, free: u64) -> Result<()> {
    // A size whose requirement overflows can never fit, whatever the volume reports.
    let needed = size
        .checked_mul(2)
        .and_then(|n| n.checked_add(SPACE_MARGIN_BYTES))
        .unwrap_or(u64::MAX);
    if needed < u64::MAX && free >= needed {
        return Ok(());
    }
    Err(ConnectorError::Conflict(format!(
        "{NO_SPACE_PREFIX}the import needs about {} MiB on the backup volume (twice the dump while it is assembled, plus a margin) and {} MiB are free",
        needed >> 20,
        free >> 20
    )))
}

fn free_bytes(path: &Path) -> Result<u64> {
    #[cfg(test)]
    {
        if let Some(v) = FREE_OVERRIDE.with(|c| c.get()) {
            return Ok(v);
        }
    }
    let stat = rustix::fs::statvfs(path).map_err(|e| {
        ConnectorError::Internal(format!(
            "cannot read the free space of the backup volume: {e}"
        ))
    })?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize.max(1)))
}

/// `Session.database` of a conversion, which covers every database of the site.
pub const CONVERT_DATABASE: &str = "pg:*";

// ---- stored sessions ----

/// A session as it sits on disk: the wire `Session` plus what only this node needs to carry on or undo it.
/// Nothing secret lives here; carried generated secrets stay in the sealed secret store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredSession {
    #[serde(flatten)]
    pub session: Session,
    /// Whether the site was already in maintenance when a maintenance freeze began.
    #[serde(default)]
    pub prior_maintenance: Option<bool>,
    /// Import: replace an existing database (a pre_restore backup is taken first).
    #[serde(default)]
    pub replace: bool,
    /// Import: replace manual env vars of the same name when links are created.
    #[serde(default)]
    pub override_manual: bool,
    /// Import: the manifest with the secret values blanked.
    #[serde(default)]
    pub manifest: Option<TransferManifest>,
    /// Import: steps of the commit that are done, so a retry skips them.
    #[serde(default)]
    pub done: Vec<String>,
    /// Import: the commit created the database.
    #[serde(default)]
    pub created_db: bool,
    /// Import: the links the commit creates, checked by `import_link_plan` (only resources the import creates).
    #[serde(default)]
    pub links: Vec<EnvLink>,
    /// Convert: the mode the site moves to.
    #[serde(default)]
    pub convert_to: Option<PgMode>,
    /// Convert: the databases being moved.
    #[serde(default)]
    pub databases: Vec<String>,
    /// Convert: `(database, backup id)` of the dumps.
    #[serde(default)]
    pub backups: Vec<(String, String)>,
    /// Convert: the two sides' row counts differ, so cutover is refused.
    #[serde(default)]
    pub counts_differ: bool,
}

fn new_stored(
    kind: SessionKind,
    site: &str,
    database: String,
    freeze: Freeze,
    actor: &str,
    state: SessionState,
) -> StoredSession {
    let now = now_rfc3339();
    StoredSession {
        session: Session {
            id: Ulid::generate().to_string(),
            kind,
            site: site.to_string(),
            database,
            state,
            freeze,
            created_at: now.clone(),
            updated_at: now,
            backup_id: None,
            size_bytes: 0,
            sha256: String::new(),
            chunk_size: TRANSFER_CHUNK_BYTES,
            chunks: 0,
            received: Vec::new(),
            counts: None,
            peer_counts: None,
            pre_restore_backup: None,
            error: None,
            actor: actor.to_string(),
        },
        prior_maintenance: None,
        replace: false,
        override_manual: false,
        manifest: None,
        done: Vec::new(),
        created_db: false,
        links: Vec::new(),
        convert_to: None,
        databases: Vec::new(),
        backups: Vec::new(),
        counts_differ: false,
    }
}

/// Session ids are ULIDs; anything else never reaches a path.
pub(crate) fn valid_sid(sid: &str) -> bool {
    sid.len() == 26
        && sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

fn name_of<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn clip(text: &str, max: usize) -> String {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn sha_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub(crate) fn is_lower_hex_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn chunk_aad(sid: &str, n: u64) -> String {
    format!("import-{sid}-{n}")
}

/// Plaintext length of chunk `n` of a stream of `size` bytes.
pub(crate) fn expected_chunk_len(n: u64, size: u64) -> u64 {
    let chunk = u64::from(TRANSFER_CHUNK_BYTES);
    chunk.min(size.saturating_sub(n.saturating_mul(chunk)))
}

// ---- the session state machine (pure) ----

/// The moves a session may make. `Failed` is reachable from every step that can fail; the rest is the flow of N1.
pub(crate) fn transition_ok(kind: SessionKind, from: SessionState, to: SessionState) -> bool {
    use SessionState::*;
    if to == Failed {
        return !matches!(from, Failed | Done | RolledBack);
    }
    match kind {
        SessionKind::Export => matches!(
            (from, to),
            (Pending, Freezing)
                | (Freezing, Dumping)
                | (Dumping, Ready)
                | (Ready, Done)
                | (Ready, RolledBack)
                | (Failed, Freezing)
                | (Failed, RolledBack)
        ),
        SessionKind::Import => matches!(
            (from, to),
            (Receiving, Verifying)
                | (Verifying, Restoring)
                | (Restoring, Verifying)
                | (Verifying, AwaitingCutover)
                | (Failed, Verifying)
                | (AwaitingCutover, Done)
                | (AwaitingCutover, RolledBack)
                | (Receiving, RolledBack)
                | (Failed, RolledBack)
        ),
        SessionKind::Convert => matches!(
            (from, to),
            (Pending, Freezing)
                | (Freezing, Dumping)
                | (Dumping, Restoring)
                | (Restoring, Verifying)
                | (Verifying, AwaitingCutover)
                | (AwaitingCutover, Cutover)
                | (Cutover, Done)
                | (AwaitingCutover, RolledBack)
                | (Failed, RolledBack)
        ),
    }
}

/// True for a session that still holds a freeze, a half-made database or chunks: it is not `done` or `rolled_back`.
pub(crate) fn unresolved(s: &Session) -> bool {
    !matches!(s.state, SessionState::Done | SessionState::RolledBack)
}

/// A connector restart ends the steps that were running; returns whether the session changed.
pub(crate) fn recover_session(s: &mut Session) -> bool {
    if s.state.is_interrupted_by_restart() {
        s.state = SessionState::Failed;
        s.error = Some(RESTART_NOTE.to_string());
        true
    } else {
        false
    }
}

/// Whether a session in its current state may be finished the given way.
pub(crate) fn check_finish(s: &Session, outcome: FinishOutcome) -> Result<()> {
    use SessionState::*;
    let ok = match (s.kind, outcome) {
        (SessionKind::Export, FinishOutcome::Cutover) => s.state == Ready,
        (SessionKind::Export, FinishOutcome::Abort) => matches!(s.state, Ready | Failed),
        (SessionKind::Import, FinishOutcome::Cutover) => s.state == AwaitingCutover,
        (SessionKind::Import, FinishOutcome::Abort) => {
            matches!(s.state, Receiving | AwaitingCutover | Failed)
        }
        (SessionKind::Convert, FinishOutcome::Cutover) => {
            matches!(s.state, AwaitingCutover | Cutover)
        }
        (SessionKind::Convert, FinishOutcome::Abort) => matches!(s.state, AwaitingCutover | Failed),
    };
    if ok {
        Ok(())
    } else {
        Err(ConnectorError::Conflict(format!(
            "the session is {}; it cannot be finished with {} now",
            name_of(s.state),
            name_of(outcome)
        )))
    }
}

fn deletable(s: &Session) -> bool {
    matches!(s.state, SessionState::Done | SessionState::RolledBack)
        || (s.kind == SessionKind::Import && s.state == SessionState::Receiving)
}

// ---- row counts ----

/// The counts job writes `schema<TAB>table<TAB>rows` per line.
pub(crate) fn parse_counts(text: &str) -> Result<Vec<TableCount>> {
    let bad = || ConnectorError::Unavailable("the counts job wrote a malformed result".into());
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let mut parts = line.splitn(3, '\t');
        let (Some(schema), Some(table), Some(rows)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        let rows: u64 = rows.trim().parse().map_err(|_| bad())?;
        out.push(TableCount {
            schema: schema.to_string(),
            table: table.to_string(),
            rows,
        });
        if out.len() > MAX_COUNTS {
            return Err(bad());
        }
    }
    Ok(out)
}

/// One line per table whose count differs, is missing on either side or exists on one side only.
pub(crate) fn diff_counts(source: &[TableCount], target: &[TableCount]) -> Vec<String> {
    let index = |list: &[TableCount]| -> BTreeMap<(String, String), u64> {
        list.iter()
            .map(|c| ((c.schema.clone(), c.table.clone()), c.rows))
            .collect()
    };
    let (s, t) = (index(source), index(target));
    let mut out = Vec::new();
    for ((schema, table), rows) in &s {
        match t.get(&(schema.clone(), table.clone())) {
            Some(other) if other == rows => {}
            Some(other) => out.push(format!(
                "{schema}.{table}: {rows} rows on the source, {other} on the target"
            )),
            None => out.push(format!("{schema}.{table}: missing on the target")),
        }
    }
    for (schema, table) in t.keys() {
        if !s.contains_key(&(schema.clone(), table.clone())) {
            out.push(format!("{schema}.{table}: only on the target"));
        }
    }
    out
}

fn prefixed(db: &str, counts: Vec<TableCount>) -> Vec<TableCount> {
    counts
        .into_iter()
        .map(|c| TableCount {
            schema: format!("{db}.{}", c.schema),
            ..c
        })
        .collect()
}

// ---- manifest checks (the manifest comes from another node, so every part is untrusted) ----

/// What an import will create, derived from a checked manifest.
#[derive(Debug)]
pub(crate) struct ImportShape {
    pub db: String,
    pub exists: bool,
}

fn manifest_users(m: &TransferManifest) -> Vec<PgUser> {
    m.users
        .iter()
        .map(|u| PgUser {
            name: u.name.clone(),
            level: u.level,
            connection_limit: u.connection_limit,
            statement_timeout_ms: Some(u.statement_timeout_ms),
            idle_in_transaction_timeout_ms: Some(u.idle_in_transaction_timeout_ms),
            disabled: false,
        })
        .collect()
}

fn secret_alphabet_ok(value: &str, encoding: SecretEncoding) -> bool {
    match encoding {
        SecretEncoding::Base64url => value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        SecretEncoding::Hex => value.bytes().all(|b| b.is_ascii_hexdigit()),
    }
}

fn plain_text_ok(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

/// Checks a manifest against the target site and returns the database it names. The whole result is validated the way
/// the strict model would see it, so nothing is accepted here that the commit could not store.
pub(crate) fn check_manifest(
    m: &TransferManifest,
    site: &Site,
    replace: bool,
) -> Result<ImportShape> {
    let bad = |what: &str| ConnectorError::BadRequest(format!("manifest: {what}"));
    let pg = site.data.postgres.as_ref().ok_or_else(|| {
        ConnectorError::Conflict(
            "managed Postgres is not enabled for this site; enable it before importing".into(),
        )
    })?;
    if !is_valid_id(&m.site) {
        return Err(bad("the site id is not valid"));
    }
    let DbRef::Pg(db) = DbRef::parse(&m.database)? else {
        return Err(bad("only managed databases (pg:<name>) can be transferred"));
    };
    if !valid_database_name(&db) {
        return Err(bad("the database name is not valid"));
    }
    if m.chunk_size != TRANSFER_CHUNK_BYTES {
        return Err(bad("the chunk size must be 8388608"));
    }
    if m.size_bytes > MAX_TRANSFER_BYTES {
        return Err(bad("the dump is larger than this node accepts"));
    }
    if m.chunks != chunk_count(m.size_bytes, m.chunk_size) {
        return Err(bad("the chunk count does not match the size"));
    }
    if !is_lower_hex_sha256(&m.sha256) {
        return Err(bad("the checksum must be 64 lowercase hex digits"));
    }
    if !plain_text_ok(&m.server_version, 64) {
        return Err(bad("the server version is not valid"));
    }
    match server_major(&m.server_version) {
        Some(major) if major <= pg.major => {}
        Some(major) => {
            return Err(ConnectorError::Conflict(format!(
                "the dump comes from Postgres {major}, newer than this site's database ({})",
                pg.major
            )));
        }
        None => return Err(bad("the server version has no major number")),
    }
    if m.counts.len() > MAX_COUNTS
        || m.counts
            .iter()
            .any(|c| !plain_text_ok(&c.schema, 128) || !plain_text_ok(&c.table, 128))
    {
        return Err(bad("the table counts are not valid"));
    }
    if m.users.is_empty() || m.users.len() > MAX_PG_USERS_PER_DATABASE {
        return Err(bad("a database needs 1 to 8 users"));
    }
    let mut seen = BTreeSet::new();
    for u in &m.users {
        if !is_pg_ident(&u.name) || !seen.insert(u.name.as_str()) {
            return Err(bad("a user name is not valid or appears twice"));
        }
    }
    let exists = pg.databases.iter().any(|d| d.name == db);
    if exists && !replace {
        return Err(ConnectorError::Conflict(format!(
            "database {db} exists on this site; import with replace to overwrite it"
        )));
    }
    if !exists && pg.databases.len() >= MAX_PG_DATABASES {
        return Err(ConnectorError::BadRequest(format!(
            "a site has at most {MAX_PG_DATABASES} databases"
        )));
    }
    if m.generated_secrets.len() > MAX_GENERATED_SECRETS {
        return Err(bad("too many generated secrets"));
    }
    let mut secret_names = BTreeSet::new();
    for s in &m.generated_secrets {
        if !is_resource_name(&s.name)
            || !(32..=128).contains(&s.bytes)
            || s.value.len() != encoded_len(s.bytes, s.encoding)
            || !secret_alphabet_ok(&s.value, s.encoding)
            || !secret_names.insert(s.name.as_str())
        {
            return Err(bad("a generated secret is malformed"));
        }
    }
    for l in &m.links {
        let ok = match &l.source {
            LinkSource::Postgres { database, user, .. } => {
                *database == db && seen.contains(user.as_str())
            }
            LinkSource::Secret { name } => secret_names.contains(name.as_str()),
            _ => false,
        };
        if !ok {
            return Err(bad(
                "a link refers to something other than this database or a carried secret",
            ));
        }
    }
    // The strict validation of the site as it would look after the commit.
    let mut candidate = site.clone();
    if let Some(p) = candidate.data.postgres.as_mut() {
        let users = manifest_users(m);
        match p.databases.iter_mut().find(|d| d.name == db) {
            Some(existing) => {
                for u in users {
                    if !existing.users.iter().any(|e| e.name == u.name) {
                        existing.users.push(u);
                    }
                }
            }
            None => p.databases.push(PgDatabase {
                name: db.clone(),
                users,
            }),
        }
    }
    for s in &m.generated_secrets {
        if !candidate.data.secrets.iter().any(|e| e.name == s.name) {
            candidate.data.secrets.push(GeneratedSecret {
                name: s.name.clone(),
                bytes: s.bytes,
                encoding: s.encoding,
                rotated_at: now_rfc3339(),
            });
        }
    }
    for l in &m.links {
        if !candidate
            .data
            .links
            .iter()
            .any(|e| e.var == l.var && e.target == l.target)
        {
            candidate.data.links.push(l.clone());
        }
    }
    validate_site_data(&candidate)?;
    Ok(ImportShape { db, exists })
}

/// The links an import creates on the target. The manifest comes from another node, so a link may only reference
/// what the import itself creates here: a user the import adds to the database, or a carried secret the target does
/// not have yet (the target's own value is kept for those it has). A link to anything the target already had would
/// hand its credentials or secret value to a variable the source chose, perhaps a public build variable, so the
/// import is refused with every such link named. The one exception is a link the target already carries exactly
/// (same variable, target and source): it changes nothing, which keeps a `replace` import of a database whose
/// links are already in place working.
pub(crate) fn import_link_plan(
    m: &TransferManifest,
    site: &Site,
    db: &str,
) -> Result<Vec<EnvLink>> {
    let existing_users: BTreeSet<&str> = site
        .data
        .postgres
        .as_ref()
        .and_then(|p| p.databases.iter().find(|d| d.name == db))
        .map(|d| d.users.iter().map(|u| u.name.as_str()).collect())
        .unwrap_or_default();
    let created_users: BTreeSet<&str> = m
        .users
        .iter()
        .map(|u| u.name.as_str())
        .filter(|n| !existing_users.contains(n))
        .collect();
    let created_secrets: BTreeSet<&str> = m
        .generated_secrets
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !site.data.secrets.iter().any(|g| g.name == *n))
        .collect();
    let mut create = Vec::new();
    let mut refused = Vec::new();
    for l in &m.links {
        let own = match &l.source {
            LinkSource::Postgres { database, user, .. } => {
                *database == db && created_users.contains(user.as_str())
            }
            LinkSource::Secret { name } => created_secrets.contains(name.as_str()),
            _ => false,
        };
        if own {
            create.push(l.clone());
            continue;
        }
        if site.data.links.iter().any(|e| e == l) {
            continue;
        }
        let what = match &l.source {
            LinkSource::Postgres { database, user, .. } => {
                format!("the existing user {database}/{user}")
            }
            LinkSource::Secret { name } => format!("the existing secret {name}"),
            _ => "a resource the import does not create".to_string(),
        };
        refused.push(format!("{} ({}) -> {what}", l.var, l.target.as_str()));
    }
    if !refused.is_empty() {
        return Err(ConnectorError::Conflict(format!(
            "the manifest links variables to resources this site already had, which an import may not expose: {}",
            refused.join(", ")
        )));
    }
    Ok(create)
}

/// What the sealed secret store holds for an import: the carried generated secrets, by name.
#[derive(Serialize, Deserialize)]
struct CarriedSecrets {
    secrets: Vec<(String, String)>,
}

fn carried_name(site: &str, sid: &str) -> String {
    format!("site-{site}.data.xfer.{sid}")
}

fn next_secret_name(site: &str, db: &str, user: &str) -> String {
    format!("site-{site}.data.pg-next.{db}.{user}")
}

fn db_of(s: &Session) -> Result<String> {
    match DbRef::parse(&s.database)? {
        DbRef::Pg(db) => Ok(db),
        DbRef::Ext(_) => Err(ConnectorError::Internal(
            "a session names an external database".into(),
        )),
    }
}

// ---- chunk files (blocking helpers) ----

fn chunk_dir(dirs: &BackupDirs, site: &str, sid: &str) -> Result<PathBuf> {
    Ok(dirs.imports_dir(site).map_err(cat_err)?.join(sid))
}

/// The stored chunk `n` of an import, with the hash it was received under: files are `<n>.<sha256>.chunk`.
fn find_chunk(dir: &Path, n: u64) -> Option<(PathBuf, String)> {
    let prefix = format!("{n}.");
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        if let Some(sha) = rest.strip_suffix(".chunk")
            && is_lower_hex_sha256(sha)
        {
            return Some((entry.path(), sha.to_string()));
        }
    }
    None
}

fn store_chunk(
    dir: &Path,
    keyring: &Keyring,
    sid: &str,
    n: u64,
    sha: &str,
    data: &[u8],
) -> Result<()> {
    cite_core::atomic::ensure_dir(dir, 0o700).map_err(|e| {
        ConnectorError::Internal(format!("cannot create the import directory: {e}"))
    })?;
    let part = dir.join(format!("{n}.{sha}.part"));
    let done = dir.join(format!("{n}.{sha}.chunk"));
    let _ = std::fs::remove_file(&part);
    let written = (|| -> Result<()> {
        let mut writer = StreamWriter::create(&part, keyring, &chunk_aad(sid, n))?;
        writer.write_all(data)?;
        writer.finish()?;
        std::fs::rename(&part, &done)
            .map_err(|e| ConnectorError::Internal(format!("cannot store the chunk: {e}")))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    written
}

/// Decrypts the chunks in order into one sealed backup file and checks the whole against the manifest.
#[allow(clippy::too_many_arguments)]
fn assemble_chunks(
    dirs: &BackupDirs,
    keyring: &Keyring,
    site: &str,
    sid: &str,
    backup_id: &str,
    chunks: u64,
    size: u64,
    want_sha: &str,
) -> Result<StreamSummary> {
    let dir = chunk_dir(dirs, site, sid)?;
    let partial = dirs.partial_file(site, backup_id).map_err(cat_err)?;
    let target = dirs.backup_file(site, backup_id).map_err(cat_err)?;
    let built = (|| -> Result<StreamSummary> {
        let mut writer = StreamWriter::create(&partial, keyring, backup_id)?;
        let mut buf: Vec<u8> = Vec::with_capacity(TRANSFER_CHUNK_BYTES as usize);
        for n in 0..chunks {
            let (path, sha) = find_chunk(&dir, n)
                .ok_or_else(|| ConnectorError::Conflict(format!("chunk {n} has not arrived")))?;
            let want_len = expected_chunk_len(n, size);
            let mut reader = StreamReader::open(&path, keyring, &chunk_aad(sid, n))?;
            if reader.plaintext_len() != want_len {
                return Err(ConnectorError::Conflict(format!(
                    "chunk {n} has the wrong length"
                )));
            }
            buf.clear();
            reader.read_range(0, want_len, &mut buf)?;
            if sha_hex(&buf) != sha {
                return Err(ConnectorError::Internal(
                    "a stored chunk no longer matches its hash".into(),
                ));
            }
            writer.write_all(&buf)?;
        }
        let summary = writer.finish()?;
        if summary.plaintext_len != size || summary.sha256 != want_sha {
            return Err(ConnectorError::Conflict(
                "the assembled dump does not match the checksum in the manifest".into(),
            ));
        }
        Ok(summary)
    })();
    match built {
        Ok(summary) => {
            std::fs::rename(&partial, &target).map_err(|e| {
                ConnectorError::Internal(format!("cannot move the dump into place: {e}"))
            })?;
            if let Some(parent) = target.parent()
                && let Ok(d) = std::fs::File::open(parent)
            {
                let _ = d.sync_all();
            }
            Ok(summary)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            Err(e)
        }
    }
}

/// Plaintext of chunk `n` of a finished export and its sha256.
fn read_export_chunk(
    path: &Path,
    keyring: &Keyring,
    backup_id: &str,
    n: u64,
    size: u64,
) -> Result<(Vec<u8>, String)> {
    let len = expected_chunk_len(n, size);
    let offset = n.saturating_mul(u64::from(TRANSFER_CHUNK_BYTES));
    let mut reader = StreamReader::open(path, keyring, backup_id)?;
    if reader.plaintext_len() != size {
        return Err(ConnectorError::Conflict(
            "the exported dump changed since the session was made".into(),
        ));
    }
    let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    reader.read_range(offset, len, &mut buf)?;
    let sha = sha_hex(&buf);
    Ok((buf, sha))
}

/// How a chunk upload ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkOutcome {
    Stored,
    /// The chunk was there already, with the same hash.
    Duplicate,
}

// ---- the service ----

impl DataService {
    pub(crate) fn session_lock(&self, site: &str, sid: &str) -> Arc<AsyncMutex<()>> {
        lk(&self.transfer_locks)
            .entry(format!("{site}/{sid}"))
            .or_default()
            .clone()
    }

    pub(crate) async fn chunk_permit(&self) -> Result<OwnedSemaphorePermit> {
        tokio::time::timeout(
            PERMIT_WAIT,
            Arc::clone(&self.transfer_chunks).acquire_owned(),
        )
        .await
        .map_err(|_| {
            ConnectorError::TooManyRequests("too many chunks are in flight; retry shortly".into())
        })?
        .map_err(|_| ConnectorError::Internal("the chunk semaphore closed".into()))
    }

    fn session_path(&self, site: &str, sid: &str) -> Result<PathBuf> {
        if !valid_sid(sid) {
            return Err(ConnectorError::BadRequest("not a valid session id".into()));
        }
        Ok(self
            .dirs
            .sessions_dir(site)
            .map_err(cat_err)?
            .join(format!("{sid}.json")))
    }

    pub(crate) async fn load_session(&self, site: &str, sid: &str) -> Result<StoredSession> {
        let path = self.session_path(site, sid)?;
        let sid = sid.to_string();
        tokio::task::spawn_blocking(move || read_session(&path, &sid))
            .await
            .map_err(join_err)?
    }

    async fn save_session(&self, s: &mut StoredSession) -> Result<()> {
        s.session.updated_at = now_rfc3339();
        self.dirs.ensure_site(&s.session.site).map_err(cat_err)?;
        let path = self.session_path(&s.session.site, &s.session.id)?;
        let bytes = serde_json::to_vec(&*s)?;
        tokio::task::spawn_blocking(move || {
            cite_core::atomic::write_atomic(&path, &bytes, 0o600)
                .map_err(|e| ConnectorError::Internal(format!("cannot write the session: {e}")))
        })
        .await
        .map_err(join_err)?
    }

    async fn list_sessions(&self, site: &str) -> Result<Vec<StoredSession>> {
        let dir = self.dirs.sessions_dir(site).map_err(cat_err)?;
        tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            let Ok(entries) = std::fs::read_dir(&dir) else {
                return Ok(out);
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let Some(sid) = name.strip_suffix(".json") else {
                    continue;
                };
                if !valid_sid(sid) {
                    continue;
                }
                match read_session(&entry.path(), sid) {
                    Ok(s) => out.push(s),
                    Err(e) => tracing::warn!(session = %sid, error = %e, "a transfer session could not be read"),
                }
            }
            out.sort_by(|a, b| a.session.created_at.cmp(&b.session.created_at));
            Ok(out)
        })
        .await
        .map_err(join_err)?
    }

    /// Read-modify-write of one session under its lock; nothing is written when `f` fails.
    pub(crate) async fn mutate_session<T>(
        &self,
        site: &str,
        sid: &str,
        f: impl FnOnce(&mut StoredSession) -> Result<T>,
    ) -> Result<T> {
        let lock = self.session_lock(site, sid);
        let _g = lock.lock().await;
        let mut s = self.load_session(site, sid).await?;
        let out = f(&mut s)?;
        self.save_session(&mut s).await?;
        Ok(out)
    }

    async fn set_state(&self, site: &str, sid: &str, to: SessionState) -> Result<()> {
        self.mutate_session(site, sid, move |s| {
            let from = s.session.state;
            if from != to && !transition_ok(s.session.kind, from, to) {
                return Err(ConnectorError::Conflict(format!(
                    "a {} session cannot go from {} to {}",
                    name_of(s.session.kind),
                    name_of(from),
                    name_of(to)
                )));
            }
            s.session.state = to;
            if to != SessionState::Failed {
                s.session.error = None;
            }
            Ok(())
        })
        .await
    }

    async fn fail_session(&self, site: &str, sid: &str, error: &ConnectorError) {
        let message = clip(&public_error(error), 1024);
        let marked = self
            .mutate_session(site, sid, move |s| {
                if !matches!(
                    s.session.state,
                    SessionState::Done | SessionState::RolledBack
                ) {
                    s.session.state = SessionState::Failed;
                    s.session.error = Some(message);
                }
                Ok(())
            })
            .await;
        if let Err(e) = marked {
            tracing::warn!(site = %site, session = %sid, error = %e, "a failed transfer step could not be recorded");
        }
    }

    /// Startup: steps that were running when the connector stopped fail with a note; waiting sessions stay.
    pub(crate) async fn recover_transfers(&self) {
        for site in self.dirs.sites() {
            let Ok(list) = self.list_sessions(&site).await else {
                continue;
            };
            for mut stored in list {
                if recover_session(&mut stored.session)
                    && let Err(e) = self.save_session(&mut stored).await
                {
                    tracing::warn!(site = %site, error = %e, "a transfer session could not be marked interrupted");
                }
            }
        }
    }

    pub(crate) async fn get_session(
        &self,
        site: &str,
        sid: &str,
        kind: SessionKind,
    ) -> Result<Session> {
        let stored = self.load_session(site, sid).await?;
        if stored.session.kind != kind {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        Ok(stored.session)
    }

    // ---- pieces both flows use ----

    /// Puts the site in maintenance mode, remembering whether it already was. Runs without the site lock: the
    /// deployer takes its own locks, and deleting a site takes theirs before ours.
    async fn freeze_maintenance(&self, actor: &str, site_id: &str, sid: &str) -> Result<()> {
        let prior = self.site(site_id)?.maintenance.enabled;
        self.mutate_session(site_id, sid, move |s| {
            if s.prior_maintenance.is_none() {
                s.prior_maintenance = Some(prior);
            }
            Ok(())
        })
        .await?;
        if !prior {
            self.deployer
                .set_maintenance(actor, site_id, true, None)
                .await?;
        }
        Ok(())
    }

    async fn restore_maintenance(
        &self,
        actor: &str,
        site_id: &str,
        st: &StoredSession,
    ) -> Result<()> {
        if st.session.freeze == Freeze::Maintenance && st.prior_maintenance == Some(false) {
            self.deployer
                .set_maintenance(actor, site_id, false, None)
                .await?;
        }
        Ok(())
    }

    /// Sets or clears the read-only flag of the databases on the site's current server. The site lock is held.
    async fn run_freeze_jobs(&self, site: &Site, dbs: &[String], on: bool) -> Result<()> {
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        let target = self.pg_target(site).await?;
        let (op, name) = if on {
            (JobOp::Freeze, "freeze")
        } else {
            (JobOp::Unfreeze, "unfreeze")
        };
        for db in dbs {
            let (_, spec) = self.build_spec(
                &target,
                op,
                false,
                vec![
                    ("PGDATABASE", pg_db_name(pg.mode, &site.id, db)),
                    ("CITE_LOGIN_ROLE", pg_group(&site.id, db, PgGroup::Login)),
                ],
            );
            let redact = self.job_redactions(site, &[]).await;
            self.run_ok(name, spec, &redact).await?;
        }
        Ok(())
    }

    /// Dumps one database as a pinned backup version (trigger `transfer`). The site lock is held.
    async fn dump_database(
        &self,
        site: &Site,
        db: &str,
        actor: &str,
        label: &str,
    ) -> Result<BackupRecord> {
        let rec = self
            .begin_backup(
                &site.id,
                &pg_key(db),
                BackupTrigger::Transfer,
                Some(label.to_string()),
                actor,
            )
            .await?;
        let done = self.complete_backup(site, &rec).await?;
        // Pinned so retention cannot remove the dump while a session still reads it.
        self.patch_backup(
            &site.id,
            &done.database,
            &done.id,
            BackupPatchReq {
                pinned: Some(true),
                ..BackupPatchReq::default()
            },
        )
        .await
    }

    async fn unpin(&self, site_id: &str, key: &str, id: &str) {
        let _ = self
            .patch_backup(
                site_id,
                key,
                id,
                BackupPatchReq {
                    pinned: Some(false),
                    ..BackupPatchReq::default()
                },
            )
            .await;
    }

    /// Exact row counts of every table of a database through a counts job. The site lock is held.
    async fn count_tables(
        &self,
        site: &Site,
        target: &PgTarget,
        mode: PgMode,
        db: &str,
    ) -> Result<Vec<TableCount>> {
        let tj = TenantJob::new(mode, &site.id, db);
        let (job_id, spec) = self.build_spec(
            target,
            JobOp::Counts,
            false,
            vec![
                ("PGDATABASE", tj.database.clone()),
                ("CITE_ROLE_TAG", tj.tag.clone()),
            ],
        );
        let redact = self.job_redactions(site, &[target.password.as_str()]).await;
        let run = self
            .run_tenant_ok("counts", target, &tj, spec, &redact)
            .await;
        let text = match run {
            Ok(_) => self.read_counts_file(&site.id, &job_id).await,
            Err(e) => Err(e),
        };
        self.clear_job_files(&site.id, &job_id).await;
        parse_counts(&text?)
    }

    async fn read_counts_file(&self, site_id: &str, job_id: &str) -> Result<String> {
        let path = self
            .dirs
            .staging_dir(site_id)
            .map_err(cat_err)?
            .join(format!("{job_id}.counts"));
        let bytes = tokio::task::spawn_blocking(move || {
            cite_core::atomic::read_limited(&path, MAX_COUNTS_FILE)
                .map_err(|_| ConnectorError::Unavailable("the counts job left no result".into()))
        })
        .await
        .map_err(join_err)??;
        String::from_utf8(bytes)
            .map_err(|_| ConnectorError::Unavailable("the counts job wrote malformed text".into()))
    }

    /// Restores a stored dump into a database of the given server. `site` carries the mode the server runs in.
    async fn restore_dump(
        &self,
        site: &Site,
        target: &PgTarget,
        mode: PgMode,
        db: &str,
        rec: &BackupRecord,
    ) -> Result<()> {
        self.dirs.ensure_site(&site.id).map_err(cat_err)?;
        let mut tj = TenantJob::new(mode, &site.id, db);
        tj.lock = true;
        let (job_id, spec) = self.build_spec(
            target,
            JobOp::Restore,
            true,
            vec![
                ("PGDATABASE", tj.database.clone()),
                ("CITE_OWNER_ROLE", pg_group(&site.id, db, PgGroup::Owner)),
                ("CITE_LOGIN_ROLE", pg_group(&site.id, db, PgGroup::Login)),
            ],
        );
        let run = async {
            self.stage_plain_dump(&site.id, rec, &job_id).await?;
            let redact = self.job_redactions(site, &[target.password.as_str()]).await;
            self.run_tenant_ok("restore", target, &tj, spec, &redact)
                .await
        }
        .await;
        self.clear_job_files(&site.id, &job_id).await;
        run.map(|_| ())
    }

    // ---- export ----

    async fn check_export(&self, site: &Site, req: &ExportReq) -> Result<String> {
        let DbRef::Pg(db) = DbRef::parse(&req.database)? else {
            return Err(ConnectorError::BadRequest(
                "only managed databases (pg:<name>) can be exported".into(),
            ));
        };
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        if !pg.databases.iter().any(|d| d.name == db) {
            return Err(ConnectorError::NotFound(format!("database {db} not found")));
        }
        let wanted = format!("pg:{db}");
        if self.list_sessions(&site.id).await?.iter().any(|s| {
            s.session.kind == SessionKind::Export
                && s.session.database == wanted
                && unresolved(&s.session)
        }) {
            return Err(ConnectorError::Conflict(format!(
                "database {db} already has an export in progress; finish or abort it first"
            )));
        }
        Ok(db)
    }

    /// Creates an export session and starts it. Returns the session id.
    pub(crate) async fn start_export(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        req: ExportReq,
    ) -> Result<String> {
        if req.mode == TransferMode::Live {
            return Err(ConnectorError::BadRequest(
                "live transfer is not available in this release".into(),
            ));
        }
        let site = self.site(site_id)?;
        let create_lock = self.session_lock(site_id, "*");
        let _g = create_lock.lock().await;
        let db = self.check_export(&site, &req).await?;
        self.require_job_capacity()?;
        let mut stored = new_stored(
            SessionKind::Export,
            site_id,
            format!("pg:{db}"),
            req.freeze,
            actor,
            SessionState::Pending,
        );
        self.save_session(&mut stored).await?;
        let sid = stored.session.id.clone();
        self.spawn_export(actor, site_id, &sid);
        Ok(sid)
    }

    fn spawn_export(self: &Arc<Self>, actor: &str, site_id: &str, sid: &str) {
        let (svc, actor, site, sid) = (
            Arc::clone(self),
            actor.to_string(),
            site_id.to_string(),
            sid.to_string(),
        );
        self.spawn_task("export", Some(site_id), move |_ctx| async move {
            let result = svc.export_steps(&actor, &site, &sid).await;
            if let Err(e) = &result {
                svc.fail_session(&site, &sid, e).await;
            }
            result.map(|_| Value::Null)
        });
    }

    /// Runs the failed step of an export again, from the freeze on.
    pub(crate) async fn retry_export(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        sid: &str,
    ) -> Result<()> {
        let stored = self.load_session(site_id, sid).await?;
        if stored.session.kind != SessionKind::Export
            || stored.session.state != SessionState::Failed
        {
            return Err(ConnectorError::Conflict(
                "only a failed export can be retried".into(),
            ));
        }
        self.require_job_capacity()?;
        // The state moves before the job starts, so a client that polls right away does not see the old failure.
        self.set_state(site_id, sid, SessionState::Freezing).await?;
        self.spawn_export(actor, site_id, sid);
        Ok(())
    }

    async fn export_steps(&self, actor: &str, site_id: &str, sid: &str) -> Result<()> {
        let stored = self.load_session(site_id, sid).await?;
        let db = db_of(&stored.session)?;
        self.set_state(site_id, sid, SessionState::Freezing).await?;
        if stored.session.freeze == Freeze::Maintenance {
            self.freeze_maintenance(actor, site_id, sid).await?;
        }
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let mode =
            site.data.postgres.as_ref().map(|p| p.mode).ok_or_else(|| {
                ConnectorError::BadRequest("managed Postgres is not enabled".into())
            })?;
        if stored.session.freeze == Freeze::ReadOnly {
            self.run_freeze_jobs(&site, std::slice::from_ref(&db), true)
                .await?;
        }
        self.set_state(site_id, sid, SessionState::Dumping).await?;
        let rec = self.dump_database(&site, &db, actor, LABEL_EXPORT).await?;
        let target = self.pg_target(&site).await?;
        let counts = self.count_tables(&site, &target, mode, &db).await?;
        self.mutate_session(site_id, sid, move |s| {
            s.session.backup_id = Some(rec.id.clone());
            s.session.size_bytes = rec.size_bytes;
            s.session.sha256 = rec.sha256.clone();
            s.session.chunk_size = TRANSFER_CHUNK_BYTES;
            s.session.chunks = chunk_count(rec.size_bytes, TRANSFER_CHUNK_BYTES);
            s.session.counts = Some(counts);
            s.session.state = SessionState::Ready;
            s.session.error = None;
            Ok(())
        })
        .await
    }

    /// Plaintext of one chunk of a ready export and its sha256.
    pub(crate) async fn export_chunk(
        &self,
        site_id: &str,
        sid: &str,
        n: u64,
    ) -> Result<(Vec<u8>, String)> {
        let stored = self.load_session(site_id, sid).await?;
        let s = &stored.session;
        if s.kind != SessionKind::Export {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        if s.state != SessionState::Ready {
            return Err(ConnectorError::Conflict(format!(
                "the export is {}; chunks can be read when it is ready",
                name_of(s.state)
            )));
        }
        if n >= s.chunks {
            return Err(ConnectorError::NotFound("no such chunk".into()));
        }
        let backup_id = s
            .backup_id
            .clone()
            .ok_or_else(|| ConnectorError::Internal("a ready export has no dump".into()))?;
        let path = self
            .dirs
            .backup_file(site_id, &backup_id)
            .map_err(cat_err)?;
        let keyring = (*self.keyring).clone();
        let size = s.size_bytes;
        let _permit = self.chunk_permit().await?;
        tokio::task::spawn_blocking(move || read_export_chunk(&path, &keyring, &backup_id, n, size))
            .await
            .map_err(join_err)?
    }

    /// The manifest of a ready export, with the generated secrets it carries.
    pub(crate) async fn export_manifest(
        &self,
        site_id: &str,
        sid: &str,
    ) -> Result<TransferManifest> {
        let stored = self.load_session(site_id, sid).await?;
        let s = &stored.session;
        if s.kind != SessionKind::Export {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        if s.state != SessionState::Ready {
            return Err(ConnectorError::Conflict(format!(
                "the export is {}; the manifest is served while it is ready",
                name_of(s.state)
            )));
        }
        let db = db_of(s)?;
        let backup_id = s
            .backup_id
            .clone()
            .ok_or_else(|| ConnectorError::Internal("a ready export has no dump".into()))?;
        let site = self.site(site_id)?;
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        let database = pg
            .databases
            .iter()
            .find(|d| d.name == db)
            .ok_or_else(|| ConnectorError::NotFound(format!("database {db} not found")))?;
        let rec = self.find_backup(site_id, &backup_id).await?;
        let users = database
            .users
            .iter()
            .map(|u| ManifestUser {
                name: u.name.clone(),
                level: u.level,
                connection_limit: u.connection_limit,
                statement_timeout_ms: u.effective_statement_timeout_ms(),
                idle_in_transaction_timeout_ms: u.effective_idle_in_transaction_ms(),
            })
            .collect();
        // Links to this database, and links of generated secrets so a carried secret is usable on the target.
        let links: Vec<EnvLink> = site
            .data
            .links
            .iter()
            .filter(|l| match &l.source {
                LinkSource::Postgres { database, .. } => *database == db,
                LinkSource::Secret { name } => site.data.secrets.iter().any(|g| g.name == *name),
                _ => false,
            })
            .cloned()
            .collect();
        let mut carried: Vec<ManifestSecret> = Vec::new();
        for l in &links {
            let LinkSource::Secret { name } = &l.source else {
                continue;
            };
            if carried.iter().any(|c| c.name == *name) {
                continue;
            }
            let Some(entry) = site.data.secrets.iter().find(|g| g.name == *name) else {
                continue;
            };
            let value: GenSecret = self
                .secret_get(&generated_secret_name(site_id, name))
                .await?
                .ok_or_else(|| {
                    ConnectorError::Unavailable(format!("the value of secret {name} is missing"))
                })?;
            carried.push(ManifestSecret {
                name: entry.name.clone(),
                bytes: entry.bytes,
                encoding: entry.encoding,
                value: value.value,
            });
        }
        Ok(TransferManifest {
            site: site_id.to_string(),
            database: s.database.clone(),
            server_version: rec.server_version,
            size_bytes: s.size_bytes,
            sha256: s.sha256.clone(),
            chunk_size: s.chunk_size,
            chunks: s.chunks,
            counts: s.counts.clone().unwrap_or_default(),
            users,
            links,
            generated_secrets: carried,
        })
    }

    /// Finishes an export. Abort lifts the freeze; cutover leaves the source frozen for good (A40).
    pub(crate) async fn finish_export(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        sid: &str,
        outcome: FinishOutcome,
    ) -> Result<Session> {
        let stored = self.load_session(site_id, sid).await?;
        if stored.session.kind != SessionKind::Export {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        check_finish(&stored.session, outcome)?;
        let db = db_of(&stored.session)?;
        if outcome == FinishOutcome::Abort {
            if stored.session.freeze == Freeze::ReadOnly {
                let lock = self.site_lock(site_id);
                let _g = lock.lock().await;
                let site = self.site(site_id)?;
                self.run_freeze_jobs(&site, std::slice::from_ref(&db), false)
                    .await?;
            }
            self.restore_maintenance(actor, site_id, &stored).await?;
        }
        if let Some(id) = &stored.session.backup_id {
            self.unpin(site_id, &pg_key(&db), id).await;
        }
        let to = match outcome {
            FinishOutcome::Cutover => SessionState::Done,
            FinishOutcome::Abort => SessionState::RolledBack,
        };
        self.set_state(site_id, sid, to).await?;
        Ok(self.load_session(site_id, sid).await?.session)
    }

    /// Removes a finished session's file; the backup version stays.
    pub(crate) async fn delete_session(
        &self,
        site_id: &str,
        sid: &str,
        kind: SessionKind,
    ) -> Result<()> {
        let lock = self.session_lock(site_id, sid);
        let _g = lock.lock().await;
        let stored = self.load_session(site_id, sid).await?;
        if stored.session.kind != kind {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        if !deletable(&stored.session) {
            return Err(ConnectorError::Conflict(format!(
                "the session is {}; finish it before deleting it",
                name_of(stored.session.state)
            )));
        }
        self.drop_import_files(site_id, sid, &stored).await;
        let path = self.session_path(site_id, sid)?;
        tokio::task::spawn_blocking(move || {
            std::fs::remove_file(&path)
                .map_err(|e| ConnectorError::Internal(format!("cannot remove the session: {e}")))
        })
        .await
        .map_err(join_err)?
    }

    // ---- import ----

    /// Creates an import session from a manifest. Returns the session id.
    pub(crate) async fn start_import(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        req: ImportReq,
    ) -> Result<String> {
        let site = self.site(site_id)?;
        let shape = check_manifest(&req.manifest, &site, req.replace)?;
        let links = import_link_plan(&req.manifest, &site, &shape.db)?;
        check_space(req.manifest.size_bytes, free_bytes(self.dirs.root())?)?;
        let create_lock = self.session_lock(site_id, "*");
        let _g = create_lock.lock().await;
        let open: Vec<Session> = self
            .list_sessions(site_id)
            .await?
            .into_iter()
            .map(|s| s.session)
            .filter(|s| s.kind == SessionKind::Import && unresolved(s))
            .collect();
        let wanted = format!("pg:{}", shape.db);
        if open.iter().any(|s| s.database == wanted) {
            return Err(ConnectorError::Conflict(format!(
                "database {} already has an import in progress; finish or abort it first",
                shape.db
            )));
        }
        if open.len() >= MAX_UNRESOLVED_IMPORTS {
            return Err(ConnectorError::Conflict(
                "two imports are already open on this site; finish or abort one first".into(),
            ));
        }
        let m = &req.manifest;
        let mut stored = new_stored(
            SessionKind::Import,
            site_id,
            wanted,
            Freeze::None,
            actor,
            SessionState::Receiving,
        );
        stored.session.size_bytes = m.size_bytes;
        stored.session.sha256 = m.sha256.clone();
        stored.session.chunk_size = m.chunk_size;
        stored.session.chunks = m.chunks;
        stored.session.peer_counts = Some(m.counts.clone());
        // Replacing only means something when the database is there now; if it appears later the commit refuses.
        stored.replace = shape.exists && req.replace;
        stored.links = links;
        let mut blanked = m.clone();
        for secret in &mut blanked.generated_secrets {
            secret.value.clear();
        }
        stored.manifest = Some(blanked);
        let sid = stored.session.id.clone();
        if !m.generated_secrets.is_empty() {
            let carried = CarriedSecrets {
                secrets: m
                    .generated_secrets
                    .iter()
                    .map(|s| (s.name.clone(), s.value.clone()))
                    .collect(),
            };
            self.secret_put(Some(site_id), &carried_name(site_id, &sid), &carried)
                .await?;
        }
        if let Err(e) = self.save_session(&mut stored).await {
            self.secret_del(Some(site_id), &carried_name(site_id, &sid))
                .await;
            return Err(e);
        }
        Ok(sid)
    }

    /// Stores one received chunk. A chunk that is there already is a no-op when its hash agrees and a conflict when not.
    pub(crate) async fn put_chunk(
        &self,
        site_id: &str,
        sid: &str,
        n: u64,
        claimed_sha: &str,
        body: &[u8],
    ) -> Result<ChunkOutcome> {
        let claimed = claimed_sha.trim().to_ascii_lowercase();
        if !is_lower_hex_sha256(&claimed) {
            return Err(ConnectorError::BadRequest(format!(
                "{CHUNK_HEADER} must be the 64 hex digits of the chunk's sha256"
            )));
        }
        if sha_hex(body) != claimed {
            return Err(ConnectorError::Conflict(
                "the chunk does not match its sha256; send it again".into(),
            ));
        }
        let lock = self.session_lock(site_id, sid);
        let _g = lock.lock().await;
        let mut stored = self.load_session(site_id, sid).await?;
        let s = &stored.session;
        if s.kind != SessionKind::Import {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        if s.state != SessionState::Receiving {
            return Err(ConnectorError::Conflict(format!(
                "the import is {}; it is not receiving chunks",
                name_of(s.state)
            )));
        }
        if n >= s.chunks {
            return Err(ConnectorError::BadRequest("no such chunk".into()));
        }
        if body.len() as u64 != expected_chunk_len(n, s.size_bytes) {
            return Err(ConnectorError::BadRequest(format!(
                "chunk {n} must be {} bytes",
                expected_chunk_len(n, s.size_bytes)
            )));
        }
        let dir = chunk_dir(&self.dirs, site_id, sid)?;
        let existing = {
            let dir = dir.clone();
            tokio::task::spawn_blocking(move || find_chunk(&dir, n).map(|(_, sha)| sha))
                .await
                .map_err(join_err)?
        };
        let outcome = match existing {
            Some(sha) if sha == claimed => ChunkOutcome::Duplicate,
            Some(_) => {
                return Err(ConnectorError::Conflict(format!(
                    "chunk {n} was already received with a different hash"
                )));
            }
            None => {
                let (keyring, sid2, sha, data) = (
                    (*self.keyring).clone(),
                    sid.to_string(),
                    claimed.clone(),
                    body.to_vec(),
                );
                tokio::task::spawn_blocking(move || {
                    store_chunk(&dir, &keyring, &sid2, n, &sha, &data)
                })
                .await
                .map_err(join_err)??;
                ChunkOutcome::Stored
            }
        };
        if !has_received(&stored.session.received, n) {
            add_received(&mut stored.session.received, n);
            self.save_session(&mut stored).await?;
        }
        Ok(outcome)
    }

    /// Checks a commit may start and runs it as a job. Returns the job id.
    pub(crate) async fn start_commit(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        sid: &str,
        override_manual: bool,
    ) -> Result<String> {
        let lock = self.session_lock(site_id, sid);
        let g = lock.lock().await;
        let mut stored = self.load_session(site_id, sid).await?;
        let s = &stored.session;
        if s.kind != SessionKind::Import {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        if !matches!(s.state, SessionState::Receiving | SessionState::Failed) {
            return Err(ConnectorError::Conflict(format!(
                "the import is {}; it cannot be committed now",
                name_of(s.state)
            )));
        }
        if !stored.done.iter().any(|d| d == "assembled") {
            let missing = (0..s.chunks).find(|n| !has_received(&s.received, *n));
            if let Some(n) = missing {
                return Err(ConnectorError::Conflict(format!(
                    "chunk {n} has not arrived; send every chunk before committing"
                )));
            }
        }
        self.require_job_capacity()?;
        stored.override_manual = override_manual;
        // The state moves before the job starts, so a second commit or a poll cannot see the old one.
        stored.session.state = SessionState::Verifying;
        stored.session.error = None;
        self.save_session(&mut stored).await?;
        drop(g);
        let (svc, actor, site, sid) = (
            Arc::clone(self),
            actor.to_string(),
            site_id.to_string(),
            sid.to_string(),
        );
        Ok(
            self.spawn_task("import", Some(site_id), move |ctx| async move {
                let result = svc.commit_steps(&ctx, &actor, &site, &sid).await;
                if let Err(e) = &result {
                    svc.fail_session(&site, &sid, e).await;
                }
                result.map(|_| Value::Null)
            }),
        )
    }

    async fn step_done(&self, site_id: &str, sid: &str, step: &'static str) -> Result<()> {
        self.mutate_session(site_id, sid, move |s| {
            if !s.done.iter().any(|d| d == step) {
                s.done.push(step.to_string());
            }
            Ok(())
        })
        .await
    }

    async fn commit_steps(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        sid: &str,
    ) -> Result<()> {
        let stored = self.load_session(site_id, sid).await?;
        let manifest = stored
            .manifest
            .clone()
            .ok_or_else(|| ConnectorError::Internal("an import session has no manifest".into()))?;
        let db = db_of(&stored.session)?;
        let key = pg_key(&db);
        self.set_state(site_id, sid, SessionState::Verifying)
            .await?;
        let is_done = |s: &StoredSession, step: &str| s.done.iter().any(|d| d == step);

        // 1. the dump becomes a backup version
        let mut backup_id = stored.session.backup_id.clone();
        if !is_done(&stored, "assembled") {
            ctx.step("checking the dump");
            let rec = self
                .begin_backup(
                    site_id,
                    &key,
                    BackupTrigger::Import,
                    Some("imported from another node".to_string()),
                    actor,
                )
                .await?;
            let assembled = {
                let (dirs, keyring, site, sid2, bid, sha) = (
                    self.dirs.clone(),
                    (*self.keyring).clone(),
                    site_id.to_string(),
                    sid.to_string(),
                    rec.id.clone(),
                    manifest.sha256.clone(),
                );
                let (chunks, size) = (manifest.chunks, manifest.size_bytes);
                tokio::task::spawn_blocking(move || {
                    assemble_chunks(&dirs, &keyring, &site, &sid2, &bid, chunks, size, &sha)
                })
                .await
                .map_err(join_err)?
            };
            let summary = match assembled {
                Ok(s) => s,
                Err(e) => {
                    let (k, id, msg) = (key.clone(), rec.id.clone(), clip(&public_error(&e), 1024));
                    let _ = self
                        .with_catalog(site_id, move |cat| {
                            if let Some(r) = cat.find_mut(&k, &id) {
                                r.status = BackupStatus::Failed;
                                r.error = Some(msg);
                                r.completed_at = Some(now_rfc3339());
                            }
                            Ok(())
                        })
                        .await;
                    return Err(e);
                }
            };
            let (k, id, kid, source, version) = (
                key.clone(),
                rec.id.clone(),
                self.keyring.kid_hex(),
                TransferSource {
                    node: "remote".to_string(),
                    site: manifest.site.clone(),
                    backup_id: String::new(),
                    version: 0,
                },
                manifest.server_version.clone(),
            );
            let file = format!("{}.cbk", rec.id);
            self.with_catalog(site_id, move |cat| {
                let r = cat
                    .find_mut(&k, &id)
                    .ok_or_else(|| ConnectorError::Internal("the import record vanished".into()))?;
                r.status = BackupStatus::Ok;
                r.completed_at = Some(now_rfc3339());
                r.size_bytes = summary.plaintext_len;
                r.sha256 = summary.sha256;
                r.server_version = version;
                r.format = FORMAT.to_string();
                r.encryption = Some(EncryptionInfo {
                    scheme: SCHEME.to_string(),
                    kid,
                });
                r.local = Some(LocalCopy {
                    file,
                    stored_bytes: summary.stored_len,
                });
                r.source = Some(source);
                Ok(())
            })
            .await?;
            let bid = rec.id.clone();
            self.mutate_session(site_id, sid, move |s| {
                s.session.backup_id = Some(bid);
                s.done.push("assembled".to_string());
                Ok(())
            })
            .await?;
            backup_id = Some(rec.id);
            self.drop_chunk_files(site_id, sid).await;
        }
        let backup_id = backup_id
            .ok_or_else(|| ConnectorError::Internal("the import has no assembled dump".into()))?;
        let rec = self.find_backup(site_id, &backup_id).await?;

        // 2. the database, its users, the carried secrets and the links
        self.set_state(site_id, sid, SessionState::Restoring)
            .await?;
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let mut stored = self.load_session(site_id, sid).await?;
        if !is_done(&stored, "provisioned") {
            // The site may have changed since the session was created: decide again, before anything is created,
            // which links the import makes. After provisioning the users it created exist, so the decision stays.
            let links = import_link_plan(&manifest, &self.site(site_id)?, &db)?;
            let keep = links.clone();
            self.mutate_session(site_id, sid, move |s| {
                s.links = keep;
                Ok(())
            })
            .await?;
            stored.links = links;
            ctx.step("creating the database and its users");
            self.provision_import(ctx, actor, site_id, sid, &db, &manifest, &stored)
                .await?;
            self.step_done(site_id, sid, "provisioned").await?;
        }
        if !is_done(&stored, "secrets") {
            ctx.step("creating the carried secrets");
            self.import_secrets(actor, site_id, sid, &manifest).await?;
            self.step_done(site_id, sid, "secrets").await?;
        }
        if !is_done(&stored, "links") {
            ctx.step("linking environment variables");
            self.import_links(actor, site_id, &stored.links, stored.override_manual)
                .await?;
            self.step_done(site_id, sid, "links").await?;
        }

        // 3. the data
        let site = self.site(site_id)?;
        let (mode, target) = self.current_target(&site).await?;
        if !is_done(&stored, "restored") {
            ctx.step("restoring the dump");
            self.restore_dump(&site, &target, mode, &db, &rec).await?;
            self.step_done(site_id, sid, "restored").await?;
        }
        self.set_state(site_id, sid, SessionState::Verifying)
            .await?;
        ctx.step("counting rows");
        let counts = self.count_tables(&site, &target, mode, &db).await?;
        self.mutate_session(site_id, sid, move |s| {
            s.session.counts = Some(counts);
            s.session.state = SessionState::AwaitingCutover;
            s.session.error = None;
            Ok(())
        })
        .await?;
        self.drop_carried_secrets(site_id, sid).await;
        Ok(())
    }

    async fn current_target(&self, site: &Site) -> Result<(PgMode, PgTarget)> {
        let mode =
            site.data.postgres.as_ref().map(|p| p.mode).ok_or_else(|| {
                ConnectorError::BadRequest("managed Postgres is not enabled".into())
            })?;
        Ok((mode, self.pg_target(site).await?))
    }

    #[allow(clippy::too_many_arguments)]
    async fn provision_import(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        sid: &str,
        db: &str,
        manifest: &TransferManifest,
        stored: &StoredSession,
    ) -> Result<()> {
        let site = self.site(site_id)?;
        let exists = site
            .data
            .postgres
            .as_ref()
            .is_some_and(|p| p.databases.iter().any(|d| d.name == db));
        let users = manifest_users(manifest);
        if !exists {
            self.provision_database(actor, site_id, db, &users).await?;
            self.mutate_session(site_id, sid, |s| {
                s.created_db = true;
                Ok(())
            })
            .await?;
            return Ok(());
        }
        if !stored.replace {
            return Err(ConnectorError::Conflict(format!(
                "database {db} exists on this site; import with replace to overwrite it"
            )));
        }
        ctx.step("backing up the current data first");
        let pre = self
            .begin_backup(
                site_id,
                &pg_key(db),
                BackupTrigger::PreRestore,
                Some("before an import".to_string()),
                actor,
            )
            .await?;
        let pre = self.complete_backup(&site, &pre).await?;
        let pre_id = pre.id.clone();
        self.mutate_session(site_id, sid, move |s| {
            s.session.pre_restore_backup = Some(pre_id);
            Ok(())
        })
        .await?;
        let present: BTreeSet<String> = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .map(|d| d.users.iter().map(|u| u.name.clone()).collect())
            .unwrap_or_default();
        for user in users.into_iter().filter(|u| !present.contains(&u.name)) {
            ctx.step(&format!("creating user {db}/{}", user.name));
            self.add_user_locked(actor, site_id, db, user).await?;
        }
        Ok(())
    }

    async fn import_secrets(
        &self,
        actor: &str,
        site_id: &str,
        sid: &str,
        manifest: &TransferManifest,
    ) -> Result<()> {
        if manifest.generated_secrets.is_empty() {
            return Ok(());
        }
        let carried: CarriedSecrets = self
            .secret_get(&carried_name(site_id, sid))
            .await?
            .ok_or_else(|| {
                ConnectorError::Unavailable("the carried secrets are no longer stored".into())
            })?;
        let values: BTreeMap<String, String> = carried.secrets.into_iter().collect();
        for entry in &manifest.generated_secrets {
            let site = self.site(site_id)?;
            // A secret the site already has keeps its own value.
            if site.data.secrets.iter().any(|g| g.name == entry.name) {
                continue;
            }
            let value = values
                .get(&entry.name)
                .ok_or_else(|| ConnectorError::Unavailable("a carried secret is missing".into()))?;
            let secret_name = generated_secret_name(site_id, &entry.name);
            self.secret_put(
                Some(site_id),
                &secret_name,
                &GenSecret {
                    value: value.clone(),
                    previous: None,
                },
            )
            .await?;
            let record = GeneratedSecret {
                name: entry.name.clone(),
                bytes: entry.bytes,
                encoding: entry.encoding,
                rotated_at: now_rfc3339(),
            };
            let detail = format!("site={site_id} secret={}", entry.name);
            let saved = self
                .update_site(actor, "data.import.secret", &detail, site_id, move |s| {
                    s.data.secrets.push(record);
                    Ok(())
                })
                .await;
            if let Err(e) = saved {
                self.secret_del(Some(site_id), &secret_name).await;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Creates the links `import_link_plan` let through; never the manifest's list as such.
    async fn import_links(
        &self,
        actor: &str,
        site_id: &str,
        links: &[EnvLink],
        override_manual: bool,
    ) -> Result<()> {
        if links.is_empty() {
            return Ok(());
        }
        let site = self.site(site_id)?;
        let wanted: Vec<EnvLink> = links.to_vec();
        match self.plan_links(&site, wanted, override_manual).await {
            Ok(plan) if plan.add.is_empty() && plan.unset.is_empty() => Ok(()),
            Ok(plan) => {
                self.apply_links(actor, site_id, plan, "data.import.link")
                    .await
            }
            Err(super::service::LinkError::Other(e)) => Err(e),
            Err(super::service::LinkError::Conflicts(list)) => {
                let vars: Vec<String> = list
                    .iter()
                    .map(|c| format!("{} ({})", c.var, c.target.as_str()))
                    .collect();
                Err(ConnectorError::Conflict(format!(
                    "these variables are already set on this site: {}; commit again with override to replace manual ones",
                    vars.join(", ")
                )))
            }
        }
    }

    async fn drop_chunk_files(&self, site_id: &str, sid: &str) {
        if let Ok(dir) = chunk_dir(&self.dirs, site_id, sid) {
            let _ = tokio::task::spawn_blocking(move || {
                if dir.is_dir() {
                    let _ = std::fs::remove_dir_all(&dir);
                }
            })
            .await;
        }
    }

    async fn drop_carried_secrets(&self, site_id: &str, sid: &str) {
        self.secret_del(Some(site_id), &carried_name(site_id, sid))
            .await;
    }

    async fn drop_import_files(&self, site_id: &str, sid: &str, stored: &StoredSession) {
        if stored.session.kind == SessionKind::Import {
            self.drop_chunk_files(site_id, sid).await;
            self.drop_carried_secrets(site_id, sid).await;
        }
    }

    /// Finishes an import. Cutover keeps the imported data; abort puts back the pre_restore backup (replace) or removes
    /// the database the import created.
    pub(crate) async fn finish_import(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        sid: &str,
        outcome: FinishOutcome,
    ) -> Result<Session> {
        let stored = self.load_session(site_id, sid).await?;
        if stored.session.kind != SessionKind::Import {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        check_finish(&stored.session, outcome)?;
        let db = db_of(&stored.session)?;
        if outcome == FinishOutcome::Abort && stored.session.state != SessionState::Receiving {
            if let Some(pre) = stored.session.pre_restore_backup.clone() {
                let lock = self.site_lock(site_id);
                let _g = lock.lock().await;
                let site = self.site(site_id)?;
                let rec = self.find_backup(site_id, &pre).await?;
                let (mode, target) = self.current_target(&site).await?;
                self.restore_dump(&site, &target, mode, &db, &rec).await?;
            } else if stored.created_db {
                // Takes the site lock itself.
                let ctx = JobCtx {
                    svc: Arc::clone(self),
                    id: String::new(),
                };
                self.do_delete_database(&ctx, actor, site_id, &db, true)
                    .await?;
            }
        }
        self.drop_import_files(site_id, sid, &stored).await;
        let to = match outcome {
            FinishOutcome::Cutover => SessionState::Done,
            FinishOutcome::Abort => SessionState::RolledBack,
        };
        self.set_state(site_id, sid, to).await?;
        Ok(self.load_session(site_id, sid).await?.session)
    }

    // ---- conversion between dedicated and shared ----

    async fn check_convert(&self, site: &Site, to: PgMode) -> Result<()> {
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        if pg.mode == to {
            return Err(ConnectorError::Conflict(format!(
                "this site's database is already {}",
                to.as_str()
            )));
        }
        if pg.retired.is_some() {
            return Err(ConnectorError::Conflict(
                "a database from an earlier conversion is still retired; delete it first".into(),
            ));
        }
        if to == PgMode::Shared {
            self.require_shared_running().await?;
            let shared = self.shared_settings().await?;
            if shared.major != pg.major {
                return Err(ConnectorError::Conflict(format!(
                    "the shared instance runs Postgres {}; this database is {}",
                    shared.major, pg.major
                )));
            }
            let tag = cite_edge::datamodel::pg_site_tag(&site.id);
            if self.deployer.sites().iter().any(|o| {
                o.id != site.id
                    && o.data
                        .postgres
                        .as_ref()
                        .is_some_and(|p| p.mode == PgMode::Shared)
                    && cite_edge::datamodel::pg_site_tag(&o.id) == tag
            }) {
                return Err(ConnectorError::Conflict(
                    "another site on the shared instance has the same tag; pick another site id"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// Creates a conversion session and starts it. Returns the session id.
    pub(crate) async fn start_convert(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        to: PgMode,
        freeze: Freeze,
    ) -> Result<String> {
        let site = self.site(site_id)?;
        let create_lock = self.session_lock(site_id, "*");
        let _g = create_lock.lock().await;
        self.check_convert(&site, to).await?;
        if self
            .list_sessions(site_id)
            .await?
            .iter()
            .any(|s| s.session.kind == SessionKind::Convert && unresolved(&s.session))
        {
            return Err(ConnectorError::Conflict(
                "a conversion is already in progress; finish or abort it first".into(),
            ));
        }
        self.require_job_capacity()?;
        let mut stored = new_stored(
            SessionKind::Convert,
            site_id,
            CONVERT_DATABASE.to_string(),
            freeze,
            actor,
            SessionState::Pending,
        );
        stored.convert_to = Some(to);
        stored.databases = site
            .data
            .postgres
            .as_ref()
            .map(|p| p.databases.iter().map(|d| d.name.clone()).collect())
            .unwrap_or_default();
        self.save_session(&mut stored).await?;
        let sid = stored.session.id.clone();
        let (svc, actor, site, sid2) = (
            Arc::clone(self),
            actor.to_string(),
            site_id.to_string(),
            sid.clone(),
        );
        self.spawn_task("convert", Some(site_id), move |_ctx| async move {
            let result = svc.convert_steps(&actor, &site, &sid2).await;
            if let Err(e) = &result {
                svc.fail_session(&site, &sid2, e).await;
            }
            result.map(|_| Value::Null)
        });
        Ok(sid)
    }

    async fn convert_steps(&self, actor: &str, site_id: &str, sid: &str) -> Result<()> {
        let stored = self.load_session(site_id, sid).await?;
        let to = stored
            .convert_to
            .ok_or_else(|| ConnectorError::Internal("a conversion has no target mode".into()))?;
        self.set_state(site_id, sid, SessionState::Freezing).await?;
        if stored.session.freeze == Freeze::Maintenance {
            self.freeze_maintenance(actor, site_id, sid).await?;
        }
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let from =
            site.data.postgres.as_ref().map(|p| p.mode).ok_or_else(|| {
                ConnectorError::BadRequest("managed Postgres is not enabled".into())
            })?;
        let dbs = stored.databases.clone();
        if stored.session.freeze == Freeze::ReadOnly {
            self.run_freeze_jobs(&site, &dbs, true).await?;
        }

        // the source, frozen: dump and count every database
        self.set_state(site_id, sid, SessionState::Dumping).await?;
        let source = self.pg_target(&site).await?;
        let mut backups: Vec<(String, String)> = Vec::new();
        let mut before: Vec<TableCount> = Vec::new();
        for db in &dbs {
            let rec = self.dump_database(&site, db, actor, LABEL_CONVERT).await?;
            before.extend(prefixed(
                db,
                self.count_tables(&site, &source, from, db).await?,
            ));
            backups.push((db.clone(), rec.id));
        }
        {
            let (b, c) = (backups.clone(), before.clone());
            self.mutate_session(site_id, sid, move |s| {
                s.backups = b;
                s.session.counts = Some(c);
                Ok(())
            })
            .await?;
        }

        // the target server, with the same databases and users under new passwords
        self.set_state(site_id, sid, SessionState::Restoring)
            .await?;
        let mut candidate = site.clone();
        if let Some(p) = candidate.data.postgres.as_mut() {
            p.mode = to;
        }
        let major = candidate.data.postgres.as_ref().map_or(0, |p| p.major);
        let su = self.ensure_su_secret(&candidate, to).await?;
        if to == PgMode::Shared {
            self.require_shared_running().await?;
        }
        self.engine.ensure_site_database(&candidate, &su).await?;
        if to == PgMode::Shared {
            let _sg = self.shared_lock.lock().await;
            self.write_hba(Some(&candidate), true).await?;
        }
        let target = self.pg_target_for(site_id, to, major).await?;
        let pg = candidate.data.postgres.clone().ok_or_else(|| {
            ConnectorError::Internal("the candidate site lost its Postgres settings".into())
        })?;
        for database in &pg.databases {
            self.provision_db_job(&candidate, &database.name).await?;
            for user in &database.users {
                self.provision_next_login(&candidate, &database.name, user)
                    .await?;
            }
        }
        for (db, backup_id) in &backups {
            let rec = self.find_backup(site_id, backup_id).await?;
            self.restore_dump(&candidate, &target, to, db, &rec).await?;
        }

        // compare
        self.set_state(site_id, sid, SessionState::Verifying)
            .await?;
        let mut after: Vec<TableCount> = Vec::new();
        for db in &dbs {
            after.extend(prefixed(
                db,
                self.count_tables(&candidate, &target, to, db).await?,
            ));
        }
        let differences = diff_counts(&before, &after);
        let note = (!differences.is_empty()).then(|| {
            format!(
                "row counts differ on {} table(s): {}",
                differences.len(),
                differences
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        });
        self.mutate_session(site_id, sid, move |s| {
            s.session.peer_counts = Some(after);
            s.counts_differ = note.is_some();
            s.session.error = note.map(|n| clip(&n, 1024));
            s.session.state = SessionState::AwaitingCutover;
            Ok(())
        })
        .await
    }

    /// New credentials for the target side of a conversion, kept apart until the cutover swaps them in.
    async fn provision_next_login(&self, candidate: &Site, db: &str, user: &PgUser) -> Result<()> {
        let name = next_secret_name(&candidate.id, db, &user.name);
        let password = denv::generate_password().map_err(ConnectorError::Internal)?;
        let mut secret = UserSecret::fresh(password.to_string(), &now_rfc3339());
        self.secret_put(Some(&candidate.id), &name, &secret).await?;
        self.upsert_login(candidate, db, user, Alt::A, &password)
            .await?;
        if user.disabled {
            self.login_action(candidate, db, user, Alt::A, "disable", None)
                .await?;
        }
        secret.mark_created(Alt::A);
        self.secret_put(Some(&candidate.id), &name, &secret).await
    }

    /// Switches the site to the new mode: credentials first, then the stored mode, so a repeat finishes the job.
    pub(crate) async fn cutover_convert(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        sid: &str,
    ) -> Result<Session> {
        let stored = self.load_session(site_id, sid).await?;
        if stored.session.kind != SessionKind::Convert {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        check_finish(&stored.session, FinishOutcome::Cutover)?;
        if stored.counts_differ {
            return Err(ConnectorError::Conflict(
                "the row counts of the two databases differ; abort the conversion and look at the counts".into(),
            ));
        }
        let to = stored
            .convert_to
            .ok_or_else(|| ConnectorError::Internal("a conversion has no target mode".into()))?;
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let pg = site.data.postgres.clone().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        let first_attempt = stored.session.state == SessionState::AwaitingCutover;
        if first_attempt && pg.mode == to {
            return Err(ConnectorError::Conflict(
                "the site is already converted".into(),
            ));
        }
        if first_attempt {
            // Users added while the conversion waited have no login on the new server.
            for database in &pg.databases {
                for user in &database.users {
                    let have = self
                        .secret_get::<UserSecret>(&next_secret_name(
                            site_id,
                            &database.name,
                            &user.name,
                        ))
                        .await?
                        .is_some();
                    if !have {
                        return Err(ConnectorError::Conflict(
                            "the users of the site changed after the conversion started; abort it and start again".into(),
                        ));
                    }
                }
            }
            self.set_state(site_id, sid, SessionState::Cutover).await?;
        }
        let result = self.cutover_steps(actor, site_id, &pg, to).await;
        if let Err(e) = &result {
            let message = clip(&public_error(e), 1024);
            let _ = self
                .mutate_session(site_id, sid, move |s| {
                    s.session.error = Some(message);
                    Ok(())
                })
                .await;
        }
        result?;
        for (db, id) in &stored.backups {
            self.unpin(site_id, &pg_key(db), id).await;
        }
        // The site now runs on the new server, so a maintenance freeze ends here (the deployer takes its own locks,
        // so the site lock goes first). The retired source keeps its read-only freeze and locked logins: its data is
        // stale from now on and nothing may write to it until it is deleted.
        drop(_g);
        self.restore_maintenance(actor, site_id, &stored).await?;
        self.set_state(site_id, sid, SessionState::Done).await?;
        Ok(self.load_session(site_id, sid).await?.session)
    }

    async fn cutover_steps(
        &self,
        actor: &str,
        site_id: &str,
        pg: &cite_edge::datamodel::ManagedPostgres,
        to: PgMode,
    ) -> Result<()> {
        for database in &pg.databases {
            for user in &database.users {
                self.swap_user_secret(site_id, &database.name, &user.name)
                    .await?;
            }
        }
        let current = self.site(site_id)?;
        let already = current.data.postgres.as_ref().is_some_and(|p| p.mode == to);
        if !already {
            let (from, major) = (pg.mode, pg.major);
            let detail = format!("site={site_id} from={} to={}", from.as_str(), to.as_str());
            self.update_site(actor, "data.convert.cutover", &detail, site_id, move |s| {
                if let Some(p) = s.data.postgres.as_mut() {
                    p.mode = to;
                    p.retired = Some(RetiredPostgres {
                        mode: from,
                        major,
                        since: now_rfc3339(),
                    });
                }
                Ok(())
            })
            .await?;
        }
        self.index_edit(site_id, move |i| i.mode = Some(to)).await?;
        self.refresh_access_rules().await;
        Ok(())
    }

    /// The old credentials move to the retired name, the new ones take their place. Safe to repeat.
    async fn swap_user_secret(&self, site_id: &str, db: &str, user: &str) -> Result<()> {
        let next_name = next_secret_name(site_id, db, user);
        let Some(next) = self.secret_get::<UserSecret>(&next_name).await? else {
            return Ok(());
        };
        let current_name = pg_user_secret_name(site_id, db, user);
        let retired_name = pg_retired_secret_name(site_id, db, user);
        if let Some(current) = self.secret_get::<UserSecret>(&current_name).await?
            && self
                .secret_get::<UserSecret>(&retired_name)
                .await?
                .is_none()
        {
            self.secret_put(Some(site_id), &retired_name, &current)
                .await?;
        }
        self.secret_put(Some(site_id), &current_name, &next).await?;
        self.secret_del(Some(site_id), &next_name).await;
        Ok(())
    }

    /// Rewrites pg_hba.conf for the tenants the config now lists; a failure is logged, not fatal.
    async fn refresh_access_rules(&self) {
        let enabled = self.shared_settings().await.is_ok_and(|s| s.enabled);
        if !enabled {
            return;
        }
        let _sg = self.shared_lock.lock().await;
        if let Err(e) = self.write_hba(None, true).await {
            tracing::warn!(error = %e, "the shared instance's access rules could not be refreshed");
        }
    }

    /// Abandons a conversion that has not cut over: the new databases go, the freeze is lifted.
    pub(crate) async fn abort_convert(
        self: &Arc<Self>,
        actor: &str,
        site_id: &str,
        sid: &str,
    ) -> Result<Session> {
        let stored = self.load_session(site_id, sid).await?;
        if stored.session.kind != SessionKind::Convert {
            return Err(ConnectorError::NotFound("session not found".into()));
        }
        check_finish(&stored.session, FinishOutcome::Abort)?;
        let to = stored
            .convert_to
            .ok_or_else(|| ConnectorError::Internal("a conversion has no target mode".into()))?;
        {
            let lock = self.site_lock(site_id);
            let _g = lock.lock().await;
            let site = self.site(site_id)?;
            self.rollback_target(&site, to, &stored.databases).await?;
            if stored.session.freeze == Freeze::ReadOnly {
                self.run_freeze_jobs(&site, &stored.databases, false)
                    .await?;
            }
            for database in &stored.databases {
                if let Some(pg) = site.data.postgres.as_ref()
                    && let Some(d) = pg.databases.iter().find(|d| d.name == *database)
                {
                    for u in &d.users {
                        self.secret_del(
                            Some(site_id),
                            &next_secret_name(site_id, database, &u.name),
                        )
                        .await;
                    }
                }
            }
            for (db, id) in &stored.backups {
                self.unpin(site_id, &pg_key(db), id).await;
            }
        }
        self.restore_maintenance(actor, site_id, &stored).await?;
        self.set_state(site_id, sid, SessionState::RolledBack)
            .await?;
        Ok(self.load_session(site_id, sid).await?.session)
    }

    /// Removes what a conversion made on the target server. The site lock is held and the config still names the old mode.
    async fn rollback_target(&self, site: &Site, to: PgMode, dbs: &[String]) -> Result<()> {
        match to {
            PgMode::Shared => {
                if !self.shared_settings().await.is_ok_and(|s| s.enabled) {
                    return Ok(());
                }
                self.deprovision_shared(
                    &site.id,
                    site.data.postgres.as_ref().map_or(0, |p| p.major),
                    dbs,
                )
                .await?;
                let _ = self.engine.disconnect_shared(&site.id).await;
                self.refresh_access_rules().await;
                Ok(())
            }
            PgMode::Dedicated => self.drop_dedicated_instance(site).await,
        }
    }

    async fn deprovision_shared(&self, site_id: &str, major: u8, dbs: &[String]) -> Result<()> {
        let su = self.shared_password().await?;
        for db in dbs {
            let spec = self
                .shared_site_job_for(site_id, major, su.as_str(), db)
                .await?;
            self.run_ok("deprovision", spec, std::slice::from_ref(&*su))
                .await?;
        }
        Ok(())
    }

    /// The unfinished conversion of a site (the newest one) and its unfinished exports and imports, oldest first, for the
    /// site data view. Sessions that cannot be read are left out.
    pub(crate) async fn open_sessions(
        &self,
        site_id: &str,
    ) -> (Option<Session>, Vec<TransferSummary>) {
        let Ok(list) = self.list_sessions(site_id).await else {
            return (None, Vec::new());
        };
        let mut conversion = None;
        let mut transfers = Vec::new();
        for stored in list.into_iter().map(|s| s.session) {
            if !unresolved(&stored) {
                continue;
            }
            if stored.kind == SessionKind::Convert {
                conversion = Some(stored);
            } else {
                transfers.push(TransferSummary {
                    id: stored.id,
                    kind: stored.kind,
                    state: stored.state,
                    database: stored.database,
                    updated_at: stored.updated_at,
                });
            }
        }
        (conversion, transfers)
    }

    /// Refuses to turn Postgres off (or purge it) while a database from a conversion is still retired or a conversion,
    /// export or import of the site has not been finished: either would be left behind with nothing to manage it.
    pub(crate) async fn ensure_no_open_transfer(&self, site: &Site) -> Result<()> {
        if site
            .data
            .postgres
            .as_ref()
            .is_some_and(|p| p.retired.is_some())
        {
            return Err(ConnectorError::Conflict(
                "a database from an earlier conversion is still retired; delete it before turning Postgres off".into(),
            ));
        }
        if let Some(open) = self
            .list_sessions(&site.id)
            .await?
            .into_iter()
            .find(|s| unresolved(&s.session))
        {
            return Err(ConnectorError::Conflict(format!(
                "a {} session is still open ({}); finish or abort it before turning Postgres off",
                name_of(open.session.kind),
                name_of(open.session.state)
            )));
        }
        Ok(())
    }

    /// Removes a site's dedicated container and volume only; the site's network and the shared instance's attachment to
    /// it stay, because a site on the shared instance still needs them.
    async fn drop_dedicated_instance(&self, site: &Site) -> Result<()> {
        self.engine.remove_dedicated_database(&site.id, true).await
    }

    /// Deletes the database a conversion left behind (the old mode's), once the operator is sure.
    pub(crate) async fn do_delete_retired(&self, actor: &str, site_id: &str) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let pg = site.data.postgres.clone().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        let retired = pg
            .retired
            .clone()
            .ok_or_else(|| ConnectorError::Conflict("this site has no retired database".into()))?;
        let names: Vec<String> = pg.databases.iter().map(|d| d.name.clone()).collect();
        match retired.mode {
            PgMode::Dedicated => {
                self.drop_dedicated_instance(&site).await?;
                self.secret_del(Some(site_id), &pg_superuser_secret_name(site_id))
                    .await;
            }
            PgMode::Shared => {
                if self.shared_settings().await.is_ok_and(|s| s.enabled) {
                    self.deprovision_shared(site_id, retired.major, &names)
                        .await?;
                    if pg.mode == PgMode::Dedicated {
                        let _ = self.engine.disconnect_shared(site_id).await;
                    }
                    self.refresh_access_rules().await;
                }
            }
        }
        for database in &pg.databases {
            for u in &database.users {
                self.secret_del(
                    Some(site_id),
                    &pg_retired_secret_name(site_id, &database.name, &u.name),
                )
                .await;
            }
        }
        let detail = format!("site={site_id} mode={}", retired.mode.as_str());
        self.update_site(
            actor,
            "data.postgres.retired.delete",
            &detail,
            site_id,
            |s| {
                if let Some(p) = s.data.postgres.as_mut() {
                    p.retired = None;
                }
                Ok(())
            },
        )
        .await?;
        Ok(json!({ "deleted": retired.mode.as_str() }))
    }
}

fn read_session(path: &Path, sid: &str) -> Result<StoredSession> {
    match cite_core::atomic::read_limited(path, MAX_SESSION_BYTES) {
        Ok(bytes) => {
            let stored: StoredSession = serde_json::from_slice(&bytes)
                .map_err(|_| ConnectorError::Internal(format!("the session {sid} is damaged")))?;
            if stored.session.id != sid {
                return Err(ConnectorError::Internal(format!(
                    "the session file {sid} holds another session"
                )));
            }
            Ok(stored)
        }
        Err(_) if !path.exists() => Err(ConnectorError::NotFound("session not found".into())),
        Err(e) => Err(ConnectorError::Internal(format!(
            "cannot read the session: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::datamodel::PgLevel;

    fn session(kind: SessionKind, state: SessionState) -> Session {
        let mut s = new_stored(kind, "shop", "pg:app".into(), Freeze::None, "t", state).session;
        s.state = state;
        s
    }

    fn site_with_postgres() -> Site {
        serde_json::from_value(json!({
            "id": "shop", "name": "Shop", "hosts": ["shop.example.com"],
            "blue": { "targets": [{ "addr": "10.0.0.1:8080" }] },
            "green": { "targets": [] }, "active": "blue",
            "source": { "repo": "octo/site" },
            "data": { "postgres": {
                "mode": "dedicated", "major": 18,
                "databases": [{ "name": "app", "users": [
                    { "name": "app", "level": "readwrite" },
                    { "name": "migrate", "level": "owner" }
                ] }]
            } }
        }))
        .expect("site")
    }

    fn manifest() -> TransferManifest {
        TransferManifest {
            site: "shop".into(),
            database: "pg:app".into(),
            server_version: "18.1".into(),
            size_bytes: u64::from(TRANSFER_CHUNK_BYTES) + 5,
            sha256: "ab".repeat(32),
            chunk_size: TRANSFER_CHUNK_BYTES,
            chunks: 2,
            counts: vec![TableCount {
                schema: "public".into(),
                table: "t".into(),
                rows: 3,
            }],
            users: vec![
                ManifestUser {
                    name: "app".into(),
                    level: PgLevel::Readwrite,
                    connection_limit: 20,
                    statement_timeout_ms: 30_000,
                    idle_in_transaction_timeout_ms: 60_000,
                },
                ManifestUser {
                    name: "migrate".into(),
                    level: PgLevel::Owner,
                    connection_limit: 20,
                    statement_timeout_ms: 0,
                    idle_in_transaction_timeout_ms: 60_000,
                },
            ],
            links: Vec::new(),
            generated_secrets: Vec::new(),
        }
    }

    fn refuses(m: &TransferManifest, replace: bool) -> String {
        check_manifest(m, &site_with_postgres(), replace)
            .expect_err("must be refused")
            .to_string()
    }

    #[test]
    fn every_flow_has_its_documented_moves_and_no_others() {
        use SessionState::*;
        let export = [
            (Pending, Freezing),
            (Freezing, Dumping),
            (Dumping, Ready),
            (Ready, Done),
            (Ready, RolledBack),
            (Failed, Freezing),
            (Failed, RolledBack),
        ];
        for (from, to) in export {
            assert!(
                transition_ok(SessionKind::Export, from, to),
                "{from:?} {to:?}"
            );
        }
        let import = [
            (Receiving, Verifying),
            (Verifying, Restoring),
            (Restoring, Verifying),
            (Verifying, AwaitingCutover),
            (AwaitingCutover, Done),
            (AwaitingCutover, RolledBack),
            (Receiving, RolledBack),
            (Failed, Verifying),
            (Failed, RolledBack),
        ];
        for (from, to) in import {
            assert!(
                transition_ok(SessionKind::Import, from, to),
                "{from:?} {to:?}"
            );
        }
        let convert = [
            (Pending, Freezing),
            (Freezing, Dumping),
            (Dumping, Restoring),
            (Restoring, Verifying),
            (Verifying, AwaitingCutover),
            (AwaitingCutover, Cutover),
            (Cutover, Done),
            (AwaitingCutover, RolledBack),
            (Failed, RolledBack),
        ];
        for (from, to) in convert {
            assert!(
                transition_ok(SessionKind::Convert, from, to),
                "{from:?} {to:?}"
            );
        }
        // Nothing leaves a finished session, a ready export never rewinds, a conversion cannot skip its dump.
        for kind in [
            SessionKind::Export,
            SessionKind::Import,
            SessionKind::Convert,
        ] {
            for to in [
                Pending,
                Freezing,
                Dumping,
                Ready,
                Receiving,
                Restoring,
                Verifying,
                AwaitingCutover,
                Cutover,
                Done,
                Failed,
                RolledBack,
            ] {
                assert!(!transition_ok(kind, Done, to), "{kind:?} done -> {to:?}");
                assert!(
                    !transition_ok(kind, RolledBack, to),
                    "{kind:?} rolled_back -> {to:?}"
                );
            }
        }
        assert!(!transition_ok(SessionKind::Export, Ready, Dumping));
        assert!(!transition_ok(SessionKind::Convert, Freezing, Restoring));
        assert!(!transition_ok(
            SessionKind::Import,
            Receiving,
            AwaitingCutover
        ));
        assert!(!transition_ok(SessionKind::Convert, Failed, Cutover));
        assert!(!transition_ok(SessionKind::Export, Failed, Failed));
    }

    #[test]
    fn a_restart_fails_only_the_steps_that_were_running() {
        use SessionState::*;
        for state in [Freezing, Dumping, Restoring, Verifying] {
            let mut s = session(SessionKind::Import, state);
            assert!(recover_session(&mut s), "{state:?}");
            assert_eq!(s.state, Failed);
            assert!(s.error.as_deref().unwrap().contains("connector restart"));
        }
        for state in [
            Pending,
            Ready,
            Receiving,
            AwaitingCutover,
            Cutover,
            Done,
            Failed,
            RolledBack,
        ] {
            let mut s = session(SessionKind::Export, state);
            assert!(!recover_session(&mut s), "{state:?}");
            assert_eq!(s.state, state);
            assert!(s.error.is_none());
        }
    }

    #[test]
    fn finishing_follows_the_state_of_the_session() {
        use FinishOutcome::{Abort, Cutover};
        use SessionState::*;
        let ok = |kind, state, outcome| check_finish(&session(kind, state), outcome).is_ok();
        assert!(ok(SessionKind::Export, Ready, Cutover));
        assert!(ok(SessionKind::Export, Ready, Abort));
        assert!(ok(SessionKind::Export, Failed, Abort));
        assert!(!ok(SessionKind::Export, Failed, Cutover));
        assert!(!ok(SessionKind::Export, Dumping, Abort));
        assert!(!ok(SessionKind::Export, Done, Abort));
        assert!(ok(SessionKind::Import, AwaitingCutover, Cutover));
        assert!(ok(SessionKind::Import, Receiving, Abort));
        assert!(!ok(SessionKind::Import, Receiving, Cutover));
        assert!(!ok(SessionKind::Import, Restoring, Abort));
        assert!(
            ok(SessionKind::Convert, SessionState::Cutover, Cutover),
            "a cutover that stopped halfway can repeat"
        );
        assert!(!ok(SessionKind::Convert, Failed, Cutover));
        assert!(ok(SessionKind::Convert, Failed, Abort));
        let err = check_finish(
            &session(SessionKind::Import, SessionState::Restoring),
            Abort,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("restoring") && err.contains("abort"), "{err}");
    }

    #[test]
    fn only_resolved_or_never_committed_sessions_can_be_deleted() {
        use SessionState::*;
        assert!(deletable(&session(SessionKind::Export, Done)));
        assert!(deletable(&session(SessionKind::Export, RolledBack)));
        assert!(!deletable(&session(SessionKind::Export, Ready)));
        assert!(!deletable(&session(SessionKind::Export, Failed)));
        assert!(deletable(&session(SessionKind::Import, Receiving)));
        assert!(!deletable(&session(SessionKind::Import, AwaitingCutover)));
        assert!(unresolved(&session(SessionKind::Export, Failed)));
        assert!(!unresolved(&session(SessionKind::Export, Done)));
    }

    #[test]
    fn stored_sessions_round_trip_with_the_wire_fields_flat() {
        let mut stored = new_stored(
            SessionKind::Convert,
            "shop",
            CONVERT_DATABASE.into(),
            Freeze::ReadOnly,
            "admin",
            SessionState::Pending,
        );
        stored.convert_to = Some(PgMode::Shared);
        stored.backups = vec![("app".into(), "B1".into())];
        stored.session.received = vec![(0, 3), (5, 5)];
        let text = serde_json::to_string(&stored).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["state"], "pending");
        assert_eq!(value["freeze"], "read_only");
        assert_eq!(value["convert_to"], "shared");
        let back: StoredSession = serde_json::from_str(&text).unwrap();
        assert_eq!(back.session, stored.session);
        assert_eq!(back.convert_to, Some(PgMode::Shared));
        assert_eq!(back.backups, stored.backups);
        // A session written by an older build has none of the private fields.
        let wire = serde_json::to_string(&stored.session).unwrap();
        let plain: StoredSession = serde_json::from_str(&wire).unwrap();
        assert!(plain.done.is_empty() && !plain.replace && plain.manifest.is_none());
    }

    #[test]
    fn session_ids_are_ulids_and_nothing_else_reaches_a_path() {
        assert!(valid_sid(&Ulid::generate().to_string()));
        for bad in [
            "",
            "short",
            "../../etc/passwd0000000000",
            "01JC9ZQ7M3X8V4N2B6T5R0WHy!",
            "01jc9zq7m3x8v4n2b6t5r0whya",
        ] {
            assert!(!valid_sid(bad), "{bad}");
        }
    }

    #[test]
    fn chunk_lengths_follow_the_dump_size() {
        let c = u64::from(TRANSFER_CHUNK_BYTES);
        assert_eq!(expected_chunk_len(0, 10), 10);
        assert_eq!(expected_chunk_len(0, c), c);
        assert_eq!(expected_chunk_len(0, c + 7), c);
        assert_eq!(expected_chunk_len(1, c + 7), 7);
        assert_eq!(expected_chunk_len(1, 2 * c), c);
        assert_eq!(expected_chunk_len(5, c), 0);
    }

    #[test]
    fn an_import_needs_twice_its_size_plus_a_margin_free() {
        let gib = 1u64 << 30;
        assert!(check_space(gib, 3 * gib).is_ok(), "exactly enough");
        let err = check_space(gib, 3 * gib - 1).unwrap_err().to_string();
        assert!(err.starts_with(NO_SPACE_PREFIX), "{err}");
        assert!(check_space(0, gib).is_ok());
        assert!(check_space(0, gib - 1).is_err());
        assert!(check_space(u64::MAX, u64::MAX).is_err(), "no overflow");
    }

    #[test]
    fn counts_parse_and_compare_exactly() {
        let parsed = parse_counts("public\tusers\t42\npublic\torders\t0\n").unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].table, "users");
        assert_eq!(parsed[0].rows, 42);
        for bad in ["public\tusers\n", "public\tusers\tmany\n", "onlyone\n"] {
            assert!(parse_counts(bad).is_err(), "{bad:?}");
        }
        assert!(parse_counts("").unwrap().is_empty());
        let a = parsed.clone();
        assert!(diff_counts(&a, &parsed).is_empty());
        let mut b = parsed.clone();
        b[0].rows = 41;
        let diff = diff_counts(&a, &b);
        assert_eq!(diff.len(), 1);
        assert!(
            diff[0].contains("public.users") && diff[0].contains("42") && diff[0].contains("41")
        );
        b.remove(1);
        b.push(TableCount {
            schema: "public".into(),
            table: "extra".into(),
            rows: 1,
        });
        let diff = diff_counts(&a, &b);
        assert!(
            diff.iter()
                .any(|d| d.contains("public.orders") && d.contains("missing"))
        );
        assert!(
            diff.iter()
                .any(|d| d.contains("public.extra") && d.contains("only on the target"))
        );
        let multi = prefixed("app", parsed);
        assert_eq!(multi[0].schema, "app.public");
    }

    #[test]
    fn a_good_manifest_is_accepted_and_names_the_database() {
        let shape = check_manifest(&manifest(), &site_with_postgres(), true).expect("accepted");
        assert_eq!(shape.db, "app");
        assert!(shape.exists);
        let mut fresh = manifest();
        fresh.database = "pg:blog".into();
        let shape = check_manifest(&fresh, &site_with_postgres(), false).expect("accepted");
        assert!(!shape.exists);
    }

    #[test]
    fn a_manifest_is_refused_for_each_way_it_can_be_wrong() {
        let mut m = manifest();
        assert!(
            refuses(&m, false).contains("replace"),
            "an existing database needs replace"
        );
        m.chunk_size = 1024;
        assert!(refuses(&m, true).contains("chunk size"));
        let mut m = manifest();
        m.chunks = 3;
        assert!(refuses(&m, true).contains("chunk count"));
        let mut m = manifest();
        m.sha256 = "AB".repeat(32);
        assert!(refuses(&m, true).contains("checksum"));
        let mut m = manifest();
        m.size_bytes = MAX_TRANSFER_BYTES + 1;
        m.chunks = chunk_count(m.size_bytes, m.chunk_size);
        assert!(refuses(&m, true).contains("larger"));
        let mut m = manifest();
        m.server_version = "19.0".into();
        assert!(refuses(&m, true).contains("newer"));
        let mut m = manifest();
        m.server_version = "junk".into();
        assert!(refuses(&m, true).contains("major"));
        let mut m = manifest();
        m.database = "ext:billing".into();
        assert!(refuses(&m, true).contains("managed"));
        let mut m = manifest();
        m.database = "pg:postgres".into();
        assert!(refuses(&m, true).contains("database name"));
        let mut m = manifest();
        m.site = "Bad Site".into();
        assert!(refuses(&m, true).contains("site id"));
        let mut m = manifest();
        m.users[0].name = "App;drop".into();
        assert!(refuses(&m, true).contains("user name"));
        let mut m = manifest();
        m.users.push(m.users[0].clone());
        assert!(refuses(&m, true).contains("twice"));
        let mut m = manifest();
        m.users.clear();
        assert!(refuses(&m, true).contains("1 to 8"));
        let mut m = manifest();
        m.counts[0].table = "bad\nname".into();
        assert!(refuses(&m, true).contains("counts"));
    }

    #[test]
    fn carried_secrets_and_links_are_checked_before_anything_is_stored() {
        let secret = |value: &str| ManifestSecret {
            name: "auth-secret".into(),
            bytes: 32,
            encoding: SecretEncoding::Base64url,
            value: value.into(),
        };
        let good = "A".repeat(43);
        let mut m = manifest();
        m.generated_secrets = vec![secret(&good)];
        assert!(check_manifest(&m, &site_with_postgres(), true).is_ok());
        let too_long = "A".repeat(44);
        let punctuated = format!("{}!", "A".repeat(42));
        for bad in ["short", too_long.as_str(), punctuated.as_str()] {
            let mut m = manifest();
            m.generated_secrets = vec![secret(bad)];
            assert!(refuses(&m, true).contains("generated secret"), "{bad}");
        }
        let mut m = manifest();
        let mut s = secret(&good);
        s.bytes = 8;
        m.generated_secrets = vec![s];
        assert!(refuses(&m, true).contains("generated secret"));
        let link = |source: LinkSource| EnvLink {
            var: "DATABASE_URL".into(),
            target: cite_edge::datamodel::LinkTarget::Runtime,
            source,
        };
        let mut m = manifest();
        m.links = vec![link(LinkSource::External {
            name: "billing".into(),
            field: cite_edge::datamodel::PgField::Url,
        })];
        assert!(refuses(&m, true).contains("link"));
        let mut m = manifest();
        m.links = vec![link(LinkSource::Secret {
            name: "unknown".into(),
        })];
        assert!(refuses(&m, true).contains("link"));
        let mut m = manifest();
        m.links = vec![link(LinkSource::Postgres {
            database: "other".into(),
            user: "app".into(),
            field: cite_edge::datamodel::PgField::Url,
        })];
        assert!(refuses(&m, true).contains("link"));
        let mut m = manifest();
        m.links = vec![EnvLink {
            var: "NEW_URL".into(),
            target: cite_edge::datamodel::LinkTarget::Build,
            source: LinkSource::Postgres {
                database: "app".into(),
                user: "migrate".into(),
                field: cite_edge::datamodel::PgField::Url,
            },
        }];
        assert!(check_manifest(&m, &site_with_postgres(), true).is_ok());
    }

    #[test]
    fn imported_links_may_only_reference_what_the_import_creates() {
        use cite_edge::datamodel::{LinkTarget, PgField};
        let secret = ManifestSecret {
            name: "auth-secret".into(),
            bytes: 32,
            encoding: SecretEncoding::Base64url,
            value: "A".repeat(43),
        };
        let to_secret = |var: &str, target: LinkTarget| EnvLink {
            var: var.into(),
            target,
            source: LinkSource::Secret {
                name: "auth-secret".into(),
            },
        };
        let to_user = |var: &str, user: &str| EnvLink {
            var: var.into(),
            target: LinkTarget::Build,
            source: LinkSource::Postgres {
                database: "app".into(),
                user: user.into(),
                field: PgField::Url,
            },
        };

        // A new database: every user and every carried secret is the import's own.
        let mut m = manifest();
        m.database = "pg:fresh".into();
        m.generated_secrets = vec![secret.clone()];
        m.links = vec![to_secret("AUTH_SECRET", LinkTarget::Runtime)];
        let fresh = import_link_plan(&m, &site_with_postgres(), "fresh").expect("own links");
        assert_eq!(fresh, m.links);

        // The target already has the secret: its real value stays, so a link the source chose is refused.
        let mut site = site_with_postgres();
        site.data.secrets.push(GeneratedSecret {
            name: "auth-secret".into(),
            bytes: 32,
            encoding: SecretEncoding::Base64url,
            rotated_at: "2026-01-01T00:00:00Z".into(),
        });
        let mut planted = m.clone();
        planted.links = vec![to_secret("NEXT_PUBLIC_X", LinkTarget::Build)];
        let err = import_link_plan(&planted, &site, "fresh")
            .expect_err("refused")
            .to_string();
        assert!(
            err.contains("NEXT_PUBLIC_X (build)") && err.contains("auth-secret"),
            "{err}"
        );
        // Unless the target carries exactly that link already: then nothing changes and nothing is created.
        site.data
            .links
            .push(to_secret("NEXT_PUBLIC_X", LinkTarget::Build));
        assert!(
            import_link_plan(&planted, &site, "fresh")
                .expect("unchanged")
                .is_empty()
        );

        // Replace: the users already on the target are not the import's, so links to them are refused...
        let mut replace = manifest();
        replace.links = vec![to_user("LEAK_URL", "migrate")];
        let err = import_link_plan(&replace, &site_with_postgres(), "app")
            .expect_err("refused")
            .to_string();
        assert!(
            err.contains("LEAK_URL (build)") && err.contains("app/migrate"),
            "{err}"
        );
        // ...but a user the import adds to the existing database may be linked.
        replace.users.push(ManifestUser {
            name: "report".into(),
            level: PgLevel::Readonly,
            connection_limit: 5,
            statement_timeout_ms: 0,
            idle_in_transaction_timeout_ms: 60_000,
        });
        replace.links = vec![to_user("REPORT_URL", "report")];
        assert_eq!(
            import_link_plan(&replace, &site_with_postgres(), "app").expect("own user"),
            replace.links
        );
        // Every offending link is named, not only the first.
        replace.links = vec![to_user("A_URL", "app"), to_user("B_URL", "migrate")];
        let err = import_link_plan(&replace, &site_with_postgres(), "app")
            .expect_err("refused")
            .to_string();
        assert!(err.contains("A_URL") && err.contains("B_URL"), "{err}");
    }

    #[test]
    fn chunk_files_are_found_by_number_and_carry_their_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = "cd".repeat(32);
        std::fs::write(tmp.path().join(format!("0.{sha}.chunk")), b"x").unwrap();
        std::fs::write(tmp.path().join(format!("10.{sha}.chunk")), b"x").unwrap();
        std::fs::write(tmp.path().join(format!("2.{sha}.part")), b"x").unwrap();
        std::fs::write(tmp.path().join("3.nothex.chunk"), b"x").unwrap();
        assert_eq!(find_chunk(tmp.path(), 0).unwrap().1, sha);
        assert_eq!(find_chunk(tmp.path(), 10).unwrap().1, sha);
        assert!(find_chunk(tmp.path(), 1).is_none(), "0. is not 1.");
        assert!(
            find_chunk(tmp.path(), 2).is_none(),
            "a part file is not a chunk"
        );
        assert!(
            find_chunk(tmp.path(), 3).is_none(),
            "a malformed hash is not a chunk"
        );
    }

    #[test]
    fn the_stored_manifest_never_keeps_a_secret_value_and_debug_hides_it() {
        let m = TransferManifest {
            generated_secrets: vec![ManifestSecret {
                name: "auth-secret".into(),
                bytes: 32,
                encoding: SecretEncoding::Hex,
                value: "topsecretvalue".into(),
            }],
            ..manifest()
        };
        let shown = format!("{m:?}");
        assert!(!shown.contains("topsecretvalue"), "{shown}");
        assert!(shown.contains("redacted"));
    }
}
