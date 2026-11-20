//! Wire types of the site data routes, shared by the connector, `cite-client` and the desktop app.
//!
//! Request bodies refuse unknown fields. Views read tolerantly (unknown fields ignored, missing ones defaulted) so a client and a node of
//! different versions interoperate, and they carry no secrets: passwords, external URLs and S3 keys are write-only.

use serde::{Deserialize, Serialize};

use crate::datamodel::{
    BackupPolicy, EnvLink, LinkSource, LinkTarget, PgLevel, PgMode, SecretEncoding,
};

// ---- backups ----

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupTrigger {
    #[default]
    Manual,
    Scheduled,
    PreRestore,
    Transfer,
    Import,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    #[default]
    Running,
    Ok,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionInfo {
    /// `cite-stream-v1`
    pub scheme: String,
    /// Hex id of the node key that wrapped the file key.
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCopy {
    /// `<id>.cbk`
    pub file: String,
    pub stored_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3CopyInfo {
    pub target: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    pub uploaded_at: String,
    /// Set while the object could not be deleted yet; the scheduler retries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_error: Option<String>,
}

/// Where an imported version came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferSource {
    pub node: String,
    pub site: String,
    pub backup_id: String,
    pub version: u32,
}

/// One immutable numbered dump version; stored verbatim in the catalog and served by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecord {
    /// ULID
    pub id: String,
    /// `pg:<db>` or `ext:<name>`
    pub database: String,
    /// Monotonic per database, from 1.
    pub version: u32,
    /// RFC3339 UTC, job start.
    pub created_at: String,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub trigger: BackupTrigger,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub pinned: bool,
    /// Plaintext dump size.
    #[serde(default)]
    pub size_bytes: u64,
    /// Hex sha256 of the plaintext dump.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub server_version: String,
    /// `pg_dump-custom`
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub encryption: Option<EncryptionInfo>,
    #[serde(default)]
    pub local: Option<LocalCopy>,
    #[serde(default)]
    pub s3: Option<S3CopyInfo>,
    #[serde(default)]
    pub status: BackupStatus,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub source: Option<TransferSource>,
}

pub const MAX_LABEL_CHARS: usize = 100;

/// Longest backup error the catalog keeps.
pub const MAX_BACKUP_ERROR_CHARS: usize = 1024;

/// True for a label the API accepts: at most 100 characters, no control characters.
pub fn is_valid_backup_label(label: &str) -> bool {
    label.chars().count() <= MAX_LABEL_CHARS && !label.chars().any(char::is_control)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCreateReq {
    /// `pg:<db>` or `ext:<name>`
    pub database: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub push_s3: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCreated {
    pub job_id: String,
    pub backup_id: String,
}

/// `label` distinguishes an absent field (keep) from `null` (clear).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPatchReq {
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
}

fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteFrom {
    Local,
    S3,
    #[default]
    All,
}

impl DeleteFrom {
    pub fn parse(text: &str) -> Option<DeleteFrom> {
        match text {
            "local" => Some(DeleteFrom::Local),
            "s3" => Some(DeleteFrom::S3),
            "all" => Some(DeleteFrom::All),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReq {
    /// Must equal the site id.
    pub confirm: String,
    /// `pg:<db>`; defaults to the database of the backup.
    #[serde(default)]
    pub database: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreStarted {
    pub job_id: String,
    pub pre_restore_backup_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushReq {
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PruneTier {
    Local,
    S3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneKeep {
    pub id: String,
    /// `pinned`, `newest`, `recent`, `pre_restore`, `daily`, `weekly`, `monthly` or `undated`.
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrunePlanView {
    pub keep: Vec<PruneKeep>,
    pub delete: Vec<String>,
}

/// Prune preview of one database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrunePreview {
    pub database: String,
    pub local: PrunePlanView,
    pub s3: PrunePlanView,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PruneResult {
    pub deleted: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceBackupPart {
    pub database: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InstanceBackupRecord {
    pub id: String,
    pub created_at: String,
    pub parts: Vec<InstanceBackupPart>,
    pub status: BackupStatus,
}

// ---- jobs ----

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    #[default]
    Running,
    Ok,
    Failed,
}

/// `GET /api/v1/data/jobs/{job}`
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobView {
    pub id: String,
    pub kind: String,
    pub site: Option<String>,
    pub state: JobState,
    pub step: Option<String>,
    pub error: Option<String>,
    pub result: Option<serde_json::Value>,
}

/// Body of every 202 answer that starts a connector job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobAccepted {
    pub job_id: String,
    /// Set when the change needs a new deploy before running containers see it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub redeploy_needed: bool,
}

// ---- node level (I2) ----

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyView {
    pub kid: String,
    /// `env`, `file` or `managed`
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DataNodeView {
    pub enabled: bool,
    pub backup_volume_ok: bool,
    pub key: KeyView,
    pub pg_majors: Vec<u8>,
    pub shared: Option<SharedView>,
    pub targets: u32,
    pub orphans: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantDatabaseView {
    pub name: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantView {
    pub site: String,
    pub databases: Vec<TenantDatabaseView>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SharedView {
    pub enabled: bool,
    pub major: u8,
    pub memory_mb: u32,
    pub nano_cpus: i64,
    pub max_connections: u32,
    pub health: String,
    pub size_bytes: u64,
    pub tenants: Vec<TenantView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedReq {
    /// Chosen when the instance is created; later updates must repeat it or omit it.
    #[serde(default)]
    pub major: Option<u8>,
    pub memory_mb: u32,
    pub cpus: f64,
    pub max_connections: u32,
}

/// A node-level S3 backup destination; the keys are never part of a view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TargetView {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub path_style: bool,
    pub prefix: String,
    pub encrypt: bool,
}

/// Keys are required on create; on update, omitted keys keep the stored ones.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReq {
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub encrypt: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
}

impl std::fmt::Debug for TargetReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetReq")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field(
                "access_key_id",
                &self.access_key_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TargetTestResult {
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrphanView {
    pub site: String,
    pub dedicated_volume: Option<String>,
    pub shared_databases: Vec<String>,
    pub backups: u32,
    pub secrets: u32,
}

// ---- site level (I3) ----

/// A managed user as listed; the password is never part of it (A11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PgUserView {
    pub name: String,
    pub level: Option<PgLevel>,
    pub connection_limit: u32,
    pub statement_timeout_ms: u32,
    pub idle_in_transaction_timeout_ms: u32,
    pub disabled: bool,
    /// Active login alternate, `a` or `b`.
    pub active: String,
    /// Alternate still waiting to be retired after a rotation.
    pub retiring: Option<String>,
    pub rotated_at: Option<String>,
    pub linked_by: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PgDatabaseView {
    pub name: String,
    pub users: Vec<PgUserView>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PgView {
    pub mode: PgMode,
    pub major: u8,
    pub memory_mb: u32,
    pub max_connections: u32,
    pub databases: Vec<PgDatabaseView>,
    pub backup: BackupPolicy,
    pub health: Option<String>,
    pub retired: Option<crate::datamodel::RetiredPostgres>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExternalView {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub sslmode: Option<String>,
    pub forward_port: Option<u16>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct S3View {
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub path_style: bool,
    pub has_keys: bool,
    pub linked_by: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretView {
    pub name: String,
    pub bytes: u16,
    pub encoding: SecretEncoding,
    pub rotated_at: String,
    pub linked_by: Vec<String>,
    /// Set on the answer to a rotation.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub redeploy_needed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkView {
    pub var: String,
    pub target: LinkTarget,
    pub source: LinkSource,
    /// Human text such as `postgres app/app url`.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub shadows_doppler: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowedVar {
    pub var: String,
    pub target: Option<LinkTarget>,
    /// Always `doppler` in this release.
    pub by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteDataView {
    pub postgres: Option<PgView>,
    pub external: Vec<ExternalView>,
    pub s3: Vec<S3View>,
    pub secrets: Vec<SecretView>,
    pub links: Vec<LinkView>,
    pub redeploy_needed: bool,
    pub shadowed: Vec<ShadowedVar>,
    pub capabilities: Vec<String>,
    /// The conversion between dedicated and shared that is not finished yet (running, waiting for cutover, or failed
    /// and still holding its freeze), if there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversion: Option<Session>,
    /// Exports and imports of this site that are not finished yet, oldest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<TransferSummary>,
}

/// One open export or import in the site data view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSummary {
    pub id: String,
    pub kind: SessionKind,
    pub state: SessionState,
    /// `pg:<db>`
    pub database: String,
    pub updated_at: String,
}

/// `PUT /postgres`: enable, or update an enabled instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgEnableReq {
    pub mode: PgMode,
    /// 17 or 18; defaults to 18 on enable.
    #[serde(default)]
    pub major: Option<u8>,
    #[serde(default)]
    pub memory_mb: Option<u32>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    /// `generic` creates the default database, users and links in the same step.
    #[serde(default)]
    pub preset: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConvertReq {
    pub to: PgMode,
    #[serde(default)]
    pub freeze: Freeze,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStarted {
    pub session: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseCreateReq {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserCreateReq {
    pub name: String,
    pub level: PgLevel,
    #[serde(default)]
    pub connection_limit: Option<u32>,
    #[serde(default)]
    pub statement_timeout_ms: Option<u32>,
    #[serde(default)]
    pub idle_in_transaction_timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPatchReq {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<PgLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_in_transaction_timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

impl UserPatchReq {
    pub fn is_empty(&self) -> bool {
        *self == UserPatchReq::default()
    }
}

/// The URL carries the credentials; it is accepted and stored, never returned.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalPutReq {
    pub url: String,
}

impl std::fmt::Debug for ExternalPutReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalPutReq")
            .field("url", &"<redacted>")
            .finish()
    }
}

/// Keys are required when the attachment is new; omitted keys keep the stored ones.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3PutReq {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
}

impl std::fmt::Debug for S3PutReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3PutReq")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .field(
                "access_key_id",
                &self.access_key_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCreateReq {
    pub name: String,
    #[serde(default)]
    pub bytes: Option<u16>,
    #[serde(default)]
    pub encoding: Option<SecretEncoding>,
}

/// The target of a link request; `both` expands to one link per target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkTargetSel {
    Runtime,
    Build,
    Both,
}

impl LinkTargetSel {
    pub fn targets(self) -> &'static [LinkTarget] {
        match self {
            LinkTargetSel::Runtime => &[LinkTarget::Runtime],
            LinkTargetSel::Build => &[LinkTarget::Build],
            LinkTargetSel::Both => &[LinkTarget::Runtime, LinkTarget::Build],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvLinkReq {
    pub var: String,
    pub target: LinkTargetSel,
    pub source: LinkSource,
}

impl EnvLinkReq {
    /// One stored link per selected target.
    pub fn expand(&self) -> Vec<EnvLink> {
        self.target
            .targets()
            .iter()
            .map(|t| EnvLink {
                var: self.var.clone(),
                target: *t,
                source: self.source.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksReq {
    pub links: Vec<EnvLinkReq>,
    /// Replace a manual var of the same name and target in the same update.
    #[serde(default, rename = "override")]
    pub override_manual: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictSetBy {
    Manual,
    Link,
}

/// One entry of the 409 answer to a link request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkConflict {
    pub var: String,
    pub target: LinkTarget,
    pub set_by: ConflictSetBy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    Generic,
    Prisma,
    Drizzle,
    Authjs,
    BetterAuth,
}

impl Preset {
    pub const ALL: [Preset; 5] = [
        Preset::Generic,
        Preset::Prisma,
        Preset::Drizzle,
        Preset::Authjs,
        Preset::BetterAuth,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Generic => "generic",
            Preset::Prisma => "prisma",
            Preset::Drizzle => "drizzle",
            Preset::Authjs => "authjs",
            Preset::BetterAuth => "better-auth",
        }
    }
}

/// `POST /links/preset`. Missing databases and users are created with the defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetRequest {
    pub preset: Preset,
    /// Database the runtime and migrate users belong to.
    #[serde(default = "default_preset_database")]
    pub database: String,
    #[serde(default = "default_runtime_user")]
    pub runtime_user: String,
    #[serde(default = "default_migrate_user")]
    pub migrate_user: String,
    /// authjs only; defaults to a separate database `auth`.
    #[serde(default)]
    pub auth_database: Option<String>,
    #[serde(default)]
    pub override_manual: bool,
}

fn default_preset_database() -> String {
    "app".into()
}
fn default_runtime_user() -> String {
    "app".into()
}
fn default_migrate_user() -> String {
    "migrate".into()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PresetResponse {
    pub links: Vec<LinkView>,
    /// `<database>/<user>`
    pub created_users: Vec<String>,
    pub created_secrets: Vec<String>,
    pub job_id: Option<String>,
}

// ---- conversion and transfer (N) ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Convert,
    Export,
    Import,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Pending,
    Freezing,
    Dumping,
    /// Export: the dump is staged and its chunks can be read.
    Ready,
    /// Import: chunks are arriving.
    Receiving,
    Restoring,
    Verifying,
    AwaitingCutover,
    Cutover,
    Done,
    Failed,
    RolledBack,
}

impl SessionState {
    /// States a connector restart turns into `Failed`; the others survive because their data is on disk.
    pub fn is_interrupted_by_restart(self) -> bool {
        matches!(
            self,
            SessionState::Freezing
                | SessionState::Dumping
                | SessionState::Restoring
                | SessionState::Verifying
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SessionState::Done | SessionState::Failed | SessionState::RolledBack
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freeze {
    #[default]
    Maintenance,
    ReadOnly,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableCount {
    pub schema: String,
    pub table: String,
    pub rows: u64,
}

pub const TRANSFER_CHUNK_BYTES: u32 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub kind: SessionKind,
    pub site: String,
    /// `pg:<db>`
    pub database: String,
    pub state: SessionState,
    #[serde(default)]
    pub freeze: Freeze,
    pub created_at: String,
    pub updated_at: String,
    /// Export and convert: the dump. Import: the imported version.
    #[serde(default)]
    pub backup_id: Option<String>,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: u32,
    #[serde(default)]
    pub chunks: u64,
    /// Import: received chunk index ranges `[first, last]`, merged.
    #[serde(default)]
    pub received: Vec<(u64, u64)>,
    #[serde(default)]
    pub counts: Option<Vec<TableCount>>,
    #[serde(default)]
    pub peer_counts: Option<Vec<TableCount>>,
    #[serde(default)]
    pub pre_restore_backup: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub actor: String,
}

fn default_chunk_size() -> u32 {
    TRANSFER_CHUNK_BYTES
}

/// Number of chunks a stream of `size_bytes` splits into; an empty stream has none.
pub fn chunk_count(size_bytes: u64, chunk_size: u32) -> u64 {
    if chunk_size == 0 {
        return 0;
    }
    size_bytes.div_ceil(u64::from(chunk_size))
}

/// Adds chunk `n` to a merged range list, keeping it sorted and merged.
pub fn add_received(ranges: &mut Vec<(u64, u64)>, n: u64) {
    ranges.push((n, n));
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges.drain(..) {
        match merged.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    *ranges = merged;
}

/// True when chunk `n` lies in a merged range list.
pub fn has_received(ranges: &[(u64, u64)], n: u64) -> bool {
    ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&n))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    #[default]
    Staged,
    /// Reserved; the routes answer 501 in this release.
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReq {
    pub database: String,
    #[serde(default)]
    pub freeze: Freeze,
    #[serde(default)]
    pub mode: TransferMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUser {
    pub name: String,
    pub level: PgLevel,
    pub connection_limit: u32,
    pub statement_timeout_ms: u32,
    pub idle_in_transaction_timeout_ms: u32,
}

/// A generated secret carried across; the value exists in the manifest only, only for the session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSecret {
    pub name: String,
    pub bytes: u16,
    pub encoding: SecretEncoding,
    pub value: String,
}

impl std::fmt::Debug for ManifestSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestSecret")
            .field("name", &self.name)
            .field("bytes", &self.bytes)
            .field("encoding", &self.encoding)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferManifest {
    pub site: String,
    pub database: String,
    pub server_version: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub chunk_size: u32,
    pub chunks: u64,
    #[serde(default)]
    pub counts: Vec<TableCount>,
    #[serde(default)]
    pub users: Vec<ManifestUser>,
    /// Links that reference this database.
    #[serde(default)]
    pub links: Vec<EnvLink>,
    #[serde(default)]
    pub generated_secrets: Vec<ManifestSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportReq {
    pub manifest: TransferManifest,
    /// Replace an existing database of the same name after a pre_restore backup.
    #[serde(default)]
    pub replace: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishOutcome {
    #[default]
    Cutover,
    Abort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishReq {
    pub outcome: FinishOutcome,
    /// Import commit and finish: replace manual vars of the same name (A16).
    #[serde(default, rename = "override")]
    pub override_manual: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datamodel::{PgField, S3Field};
    use serde_json::json;

    fn from<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, serde_json::Error> {
        serde_json::from_value(v)
    }

    #[test]
    fn enums_use_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_value(BackupTrigger::PreRestore).unwrap(),
            json!("pre_restore")
        );
        assert_eq!(
            serde_json::to_value(SessionState::AwaitingCutover).unwrap(),
            json!("awaiting_cutover")
        );
        assert_eq!(
            serde_json::to_value(Freeze::ReadOnly).unwrap(),
            json!("read_only")
        );
        assert_eq!(
            serde_json::to_value(Preset::BetterAuth).unwrap(),
            json!("better-auth")
        );
        assert_eq!(
            serde_json::to_value(LinkTargetSel::Both).unwrap(),
            json!("both")
        );
        for p in Preset::ALL {
            assert_eq!(serde_json::to_value(p).unwrap(), json!(p.as_str()));
        }
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        assert!(from::<PgEnableReq>(json!({"mode": "shared", "extra": 1})).is_err());
        assert!(from::<UserCreateReq>(json!({"name": "a", "level": "owner", "x": 1})).is_err());
        assert!(from::<UserPatchReq>(json!({"disabled": true, "x": 1})).is_err());
        assert!(from::<RestoreReq>(json!({"confirm": "shop", "x": 1})).is_err());
        assert!(from::<ExternalPutReq>(json!({"url": "postgres://u:p@h/d", "x": 1})).is_err());
        assert!(from::<LinksReq>(json!({"links": [], "x": 1})).is_err());
        assert!(from::<PresetRequest>(json!({"preset": "prisma", "x": 1})).is_err());
        assert!(from::<ExportReq>(json!({"database": "pg:app", "x": 1})).is_err());
        assert!(from::<BackupCreateReq>(json!({"database": "pg:app", "x": 1})).is_err());
    }

    #[test]
    fn views_tolerate_unknown_and_missing_fields() {
        let v: SiteDataView = from(json!({"future": true})).unwrap();
        assert!(v.postgres.is_none() && v.links.is_empty() && !v.redeploy_needed);
        let e: ExternalView =
            from(json!({"name": "billing", "host": "db.example.com", "port": 5432, "newer": 1}))
                .unwrap();
        assert_eq!(e.name, "billing");
        assert!(e.forward_port.is_none());
    }

    #[test]
    fn link_requests_expand_per_target() {
        let req: EnvLinkReq = from(json!({
            "var": "DATABASE_URL",
            "target": "both",
            "source": {"kind": "postgres", "database": "app", "user": "app", "field": "url"}
        }))
        .unwrap();
        let links = req.expand();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].target, LinkTarget::Runtime);
        assert_eq!(links[1].target, LinkTarget::Build);
        assert!(links.iter().all(|l| l.var == "DATABASE_URL"));
        let one: EnvLinkReq =
            from(json!({"var": "X", "target": "build", "source": {"kind": "site_url"}})).unwrap();
        assert_eq!(one.expand().len(), 1);
        assert!(
            from::<EnvLinkReq>(
                json!({"var": "X", "target": "bogus", "source": {"kind": "site_url"}})
            )
            .is_err()
        );
    }

    #[test]
    fn links_request_reads_override() {
        let r: LinksReq = from(json!({"links": [], "override": true})).unwrap();
        assert!(r.override_manual);
        let r: LinksReq = from(json!({"links": []})).unwrap();
        assert!(!r.override_manual);
    }

    #[test]
    fn link_sources_round_trip_with_their_kind_tag() {
        let all = [
            (
                json!({"kind": "postgres", "database": "app", "user": "app", "field": "password"}),
                LinkSource::Postgres {
                    database: "app".into(),
                    user: "app".into(),
                    field: PgField::Password,
                },
            ),
            (
                json!({"kind": "external", "name": "billing", "field": "tls_servername"}),
                LinkSource::External {
                    name: "billing".into(),
                    field: PgField::TlsServername,
                },
            ),
            (
                json!({"kind": "s3", "name": "media", "field": "secret_access_key"}),
                LinkSource::S3 {
                    name: "media".into(),
                    field: S3Field::SecretAccessKey,
                },
            ),
            (
                json!({"kind": "secret", "name": "auth-secret"}),
                LinkSource::Secret {
                    name: "auth-secret".into(),
                },
            ),
            (json!({"kind": "site_url"}), LinkSource::SiteUrl),
        ];
        for (value, expected) in all {
            let parsed: LinkSource = from(value.clone()).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        }
        assert!(from::<LinkSource>(json!({"kind": "secret", "name": "a", "x": 1})).is_err());
        assert!(from::<LinkSource>(json!({"kind": "nope"})).is_err());
    }

    #[test]
    fn backup_patch_tells_absent_from_null() {
        let p: BackupPatchReq = from(json!({})).unwrap();
        assert_eq!(p.label, None);
        let p: BackupPatchReq = from(json!({"label": null})).unwrap();
        assert_eq!(p.label, Some(None));
        let p: BackupPatchReq = from(json!({"label": "before upgrade", "pinned": true})).unwrap();
        assert_eq!(p.label, Some(Some("before upgrade".into())));
        assert_eq!(p.pinned, Some(true));
        assert!(from::<BackupPatchReq>(json!({"x": 1})).is_err());
    }

    #[test]
    fn backup_record_round_trips_and_defaults_are_tolerant() {
        let json = json!({
            "id": "01J0000000000000000000000A",
            "database": "pg:app",
            "version": 3,
            "created_at": "2026-11-20T03:17:00Z",
            "completed_at": "2026-11-20T03:17:09Z",
            "trigger": "scheduled",
            "label": null,
            "pinned": false,
            "size_bytes": 1024,
            "sha256": "ab",
            "server_version": "18.1",
            "format": "pg_dump-custom",
            "encryption": {"scheme": "cite-stream-v1", "kid": "0a"},
            "local": {"file": "x.cbk", "stored_bytes": 1100},
            "s3": null,
            "status": "ok",
            "error": null,
            "actor": "admin",
            "source": null
        });
        let rec: BackupRecord = from(json.clone()).unwrap();
        assert_eq!(rec.trigger, BackupTrigger::Scheduled);
        assert_eq!(rec.status, BackupStatus::Ok);
        assert_eq!(serde_json::to_value(&rec).unwrap(), json);
        let minimal: BackupRecord =
            from(json!({"id": "i", "database": "pg:a", "version": 1, "created_at": "t"})).unwrap();
        assert_eq!(minimal.status, BackupStatus::Running);
        assert!(
            from::<BackupRecord>(
                json!({"id": "i", "database": "pg:a", "version": 1, "created_at": "t", "zzz": 1})
            )
            .is_err()
        );
    }

    #[test]
    fn labels_are_bounded_and_free_of_control_characters() {
        assert!(is_valid_backup_label("before the migration"));
        assert!(is_valid_backup_label(&"x".repeat(100)));
        assert!(!is_valid_backup_label(&"x".repeat(101)));
        assert!(!is_valid_backup_label("a\nb"));
        assert!(!is_valid_backup_label("a\u{7}"));
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let t = TargetReq {
            name: "n".into(),
            endpoint: "https://s3.example.com".into(),
            bucket: "bucket".into(),
            region: "eu".into(),
            path_style: false,
            prefix: None,
            encrypt: None,
            access_key_id: Some("AKIAEXAMPLE".into()),
            secret_access_key: Some("wJalrSECRET".into()),
        };
        let s = format!("{t:?}");
        assert!(
            !s.contains("AKIAEXAMPLE") && !s.contains("wJalrSECRET"),
            "{s}"
        );
        let e = ExternalPutReq {
            url: "postgres://user:hunter2@db.example.com/app".into(),
        };
        assert!(!format!("{e:?}").contains("hunter2"));
        let p = S3PutReq {
            endpoint: "https://s3.example.com".into(),
            bucket: "bucket".into(),
            region: "eu".into(),
            path_style: true,
            access_key_id: Some("AKIAEXAMPLE".into()),
            secret_access_key: Some("wJalrSECRET".into()),
        };
        let s = format!("{p:?}");
        assert!(
            !s.contains("AKIAEXAMPLE") && !s.contains("wJalrSECRET"),
            "{s}"
        );
        let m = ManifestSecret {
            name: "auth-secret".into(),
            bytes: 32,
            encoding: SecretEncoding::Hex,
            value: "deadbeef-value".into(),
        };
        assert!(!format!("{m:?}").contains("deadbeef-value"));
    }

    #[test]
    fn views_have_no_field_that_could_hold_a_secret() {
        let v = serde_json::to_value(S3View::default()).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        for k in keys {
            assert!(
                !k.contains("secret_access_key") && !k.contains("password") && k != "url",
                "{k}"
            );
        }
        let u = serde_json::to_value(PgUserView::default()).unwrap();
        assert!(
            u.as_object()
                .unwrap()
                .keys()
                .all(|k| !k.contains("password"))
        );
    }

    #[test]
    fn chunk_arithmetic() {
        let c = TRANSFER_CHUNK_BYTES;
        assert_eq!(chunk_count(0, c), 0);
        assert_eq!(chunk_count(1, c), 1);
        assert_eq!(chunk_count(u64::from(c), c), 1);
        assert_eq!(chunk_count(u64::from(c) + 1, c), 2);
        assert_eq!(chunk_count(10, 0), 0);
    }

    #[test]
    fn received_ranges_merge_and_stay_sorted() {
        let mut r = Vec::new();
        for n in [5, 1, 3, 2, 9, 4, 5] {
            add_received(&mut r, n);
        }
        assert_eq!(r, vec![(1, 5), (9, 9)]);
        assert!(has_received(&r, 1) && has_received(&r, 5) && has_received(&r, 9));
        assert!(!has_received(&r, 0) && !has_received(&r, 6) && !has_received(&r, 10));
        add_received(&mut r, 8);
        add_received(&mut r, 6);
        add_received(&mut r, 7);
        assert_eq!(r, vec![(1, 9)]);
        let mut edge = vec![(u64::MAX, u64::MAX)];
        add_received(&mut edge, u64::MAX - 1);
        assert_eq!(edge, vec![(u64::MAX - 1, u64::MAX)]);
    }

    #[test]
    fn session_restart_semantics() {
        for s in [
            SessionState::Freezing,
            SessionState::Dumping,
            SessionState::Restoring,
            SessionState::Verifying,
        ] {
            assert!(s.is_interrupted_by_restart(), "{s:?}");
        }
        for s in [
            SessionState::Ready,
            SessionState::Receiving,
            SessionState::AwaitingCutover,
            SessionState::Pending,
        ] {
            assert!(!s.is_interrupted_by_restart(), "{s:?}");
        }
        assert!(SessionState::Done.is_terminal() && !SessionState::Ready.is_terminal());
    }

    #[test]
    fn session_round_trips_with_defaults() {
        let s: Session = from(json!({
            "id": "s1", "kind": "import", "site": "shop", "database": "pg:app", "state": "receiving",
            "created_at": "t", "updated_at": "t", "received": [[0, 3], [5, 5]]
        }))
        .unwrap();
        assert_eq!(s.chunk_size, TRANSFER_CHUNK_BYTES);
        assert_eq!(s.freeze, Freeze::Maintenance);
        assert_eq!(s.received, vec![(0, 3), (5, 5)]);
        let back: Session = from(serde_json::to_value(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn transfer_mode_defaults_to_staged_and_live_is_representable() {
        let r: ExportReq = from(json!({"database": "pg:app"})).unwrap();
        assert_eq!(r.mode, TransferMode::Staged);
        let r: ExportReq = from(json!({"database": "pg:app", "mode": "live"})).unwrap();
        assert_eq!(r.mode, TransferMode::Live);
    }

    #[test]
    fn preset_request_defaults_match_the_documented_users() {
        let r: PresetRequest = from(json!({"preset": "authjs"})).unwrap();
        assert_eq!(
            (
                r.database.as_str(),
                r.runtime_user.as_str(),
                r.migrate_user.as_str()
            ),
            ("app", "app", "migrate")
        );
        assert_eq!(r.auth_database, None);
        assert!(!r.override_manual);
    }

    #[test]
    fn delete_from_parses_the_query_values() {
        assert_eq!(DeleteFrom::parse("local"), Some(DeleteFrom::Local));
        assert_eq!(DeleteFrom::parse("s3"), Some(DeleteFrom::S3));
        assert_eq!(DeleteFrom::parse("all"), Some(DeleteFrom::All));
        assert_eq!(DeleteFrom::parse("both"), None);
        assert_eq!(DeleteFrom::default(), DeleteFrom::All);
    }
}
