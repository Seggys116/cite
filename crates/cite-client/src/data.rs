//! Typed calls for the site data routes (design section I): node-level shared instance, S3 targets and orphans, and the per-site
//! Postgres, external database, S3, secret, link and backup routes. Wire types come from `cite_edge::datawire`.
//!
//! Node-to-node transfer (`exports` and `imports`) is not here; it has its own module that drives those routes.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use cite_edge::datamodel::{BackupPolicy, LinkTarget, is_pg_ident, is_resource_name};
use cite_edge::datawire::{
    BackupCreateReq, BackupCreated, BackupPatchReq, BackupRecord, ConvertReq, DataNodeView,
    DatabaseCreateReq, DeleteFrom, ExternalPutReq, ExternalView, InstanceBackupRecord, JobAccepted,
    JobView, LinkConflict, LinkView, LinksReq, OrphanView, PgEnableReq, PgView, PresetRequest,
    PresetResponse, PrunePreview, PruneResult, PushReq, RestoreReq, RestoreStarted, S3PutReq,
    S3View, SecretCreateReq, SecretView, Session, SessionStarted, SharedReq, SharedView,
    SiteDataView, TargetReq, TargetTestResult, TargetView, UserCreateReq, UserPatchReq,
    is_valid_backup_label,
};
use cite_edge::validate::{MAX_ENV_LINKS, PG_MAJORS, validate_backup_policy};
use futures_util::{Stream, StreamExt};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::client::{ACTION_OPTS, NodeClient, decode, enc, error_message, read_capped};
use crate::error::ClientError;
use crate::export::{EXPORT_TIMEOUT, ExportReport};
use crate::fsio::new_id;
use crate::site_ops::{validate_env_name, validate_job_id};
use crate::zone::validate_site_id;

type Res<T> = std::result::Result<T, ClientError>;

/// The header a connector sets on a backup download with the hex sha256 of the whole plaintext dump.
pub const BACKUP_SHA256_HEADER: &str = "x-backup-sha256";

const BACKUP_ID_CHARS: usize = 26;
const MAX_ID_CHARS: usize = 64;

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

/// A backup id is a ULID: 26 characters of Crockford base32 (no I, L, O or U), uppercase.
pub fn validate_backup_id(id: &str) -> Res<&str> {
    let ok = id.len() == BACKUP_ID_CHARS
        && id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z'));
    if ok {
        Ok(id)
    } else {
        Err(invalid("a backup id is 26 uppercase letters and digits"))
    }
}

/// External database, S3 attachment and generated secret names: `^[a-z][a-z0-9-]{0,30}$`.
pub fn validate_data_name(name: &str) -> Res<&str> {
    if is_resource_name(name) {
        Ok(name)
    } else {
        Err(invalid(
            "a name is 1 to 31 lowercase letters, digits and '-', starting with a letter",
        ))
    }
}

/// Database and user names: `^[a-z][a-z0-9]{0,15}$`, because they end up inside Postgres role names.
pub fn validate_pg_name(name: &str) -> Res<&str> {
    if is_pg_ident(name) {
        Ok(name)
    } else {
        Err(invalid(
            "a database or user name is 1 to 16 lowercase letters and digits, starting with a letter",
        ))
    }
}

/// Ids the node mints for backup targets: plain path-safe tokens.
pub fn validate_target_id(id: &str) -> Res<&str> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(id)
    } else {
        Err(invalid("not a valid target id"))
    }
}

/// `pg:<database>` or `ext:<name>`, the way backups name their source.
pub fn validate_database_ref(database: &str) -> Res<&str> {
    let ok = match database.split_once(':') {
        Some(("pg", name)) => is_pg_ident(name),
        Some(("ext", name)) => is_resource_name(name),
        _ => false,
    };
    if ok {
        Ok(database)
    } else {
        Err(invalid("a database is `pg:<name>` or `ext:<name>`"))
    }
}

/// The file name offered for a downloaded dump, built from validated parts only: `<site>-<database>-v<version>.dump`.
/// Anything outside letters, digits and `-` is dropped, so a node can never influence it.
pub fn backup_download_name(site: &str, database: &str, version: u32) -> String {
    let db = database
        .strip_prefix("pg:")
        .or_else(|| database.strip_prefix("ext:"))
        .unwrap_or(database);
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(40)
            .collect()
    };
    format!("{}-{}-v{version}.dump", clean(site), clean(db))
}

/// The file name offered for a downloaded whole-instance backup.
pub fn instance_backup_download_name(backup_id: &str) -> String {
    let id: String = backup_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(BACKUP_ID_CHARS)
        .collect();
    format!("cite-pg-shared-{id}.tar")
}

// Bodies that carry credentials are serialised straight to bytes, so no `Value` copy of them lingers.
fn secret_body<B: Serialize>(body: &B) -> Res<Vec<u8>> {
    serde_json::to_vec(body).map_err(|_| invalid("cannot encode request"))
}

fn site_data_path(site_id: &str, rest: &str) -> Res<String> {
    let id = validate_site_id(site_id)?;
    Ok(format!("/sites/{}/data{rest}", enc(id)))
}

fn database_path(site_id: &str, db: &str, rest: &str) -> Res<String> {
    let db = validate_pg_name(db)?;
    site_data_path(site_id, &format!("/postgres/databases/{}{rest}", enc(db)))
}

fn user_path(site_id: &str, db: &str, user: &str, rest: &str) -> Res<String> {
    let user = validate_pg_name(user)?;
    database_path(site_id, db, &format!("/users/{}{rest}", enc(user)))
}

fn backup_path(site_id: &str, bid: &str, rest: &str) -> Res<String> {
    let bid = validate_backup_id(bid)?;
    site_data_path(site_id, &format!("/backups/{}{rest}", enc(bid)))
}

fn link_target_segment(target: LinkTarget) -> &'static str {
    match target {
        LinkTarget::Runtime => "runtime",
        LinkTarget::Build => "build",
    }
}

fn validate_label(label: &str) -> Res<()> {
    if is_valid_backup_label(label) {
        Ok(())
    } else {
        Err(invalid(
            "a label is at most 100 characters without control characters",
        ))
    }
}

/// The answer to adding links or applying a preset: either it was stored (the links, or the preset's response), or some
/// variables collide with existing ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinksOutcome<T = Vec<LinkView>> {
    Applied(T),
    /// The node refused with 409 and named the variables in the way.
    Conflicts(Vec<LinkConflict>),
}

/// A backup download, unread, so a caller can relay it or save it chunk by chunk.
#[derive(Debug)]
pub struct BackupStream {
    response: reqwest::Response,
}

impl BackupStream {
    pub fn status(&self) -> u16 {
        self.response.status().as_u16()
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header(reqwest::header::CONTENT_TYPE.as_str())
    }

    pub fn content_length(&self) -> Option<u64> {
        self.response.content_length()
    }

    /// Set on a ranged answer; the value is only relayed after the caller checked its shape.
    pub fn content_range(&self) -> Option<&str> {
        self.header(reqwest::header::CONTENT_RANGE.as_str())
    }

    /// The hex sha256 of the whole dump, when the node sent a well-formed one.
    pub fn sha256(&self) -> Option<&str> {
        self.header(BACKUP_SHA256_HEADER)
            .filter(|v| is_hex_sha256(v))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
    }

    pub fn into_body_stream(self) -> impl Stream<Item = Res<Bytes>> + Send + 'static {
        self.response
            .bytes_stream()
            .map(|chunk| chunk.map_err(ClientError::from_reqwest))
    }

    // Writes beside `dest` and renames only when the byte count and the sha256 are right, so a bad download leaves nothing behind.
    async fn save(
        mut self,
        dest: &Path,
        max_bytes: u64,
        catalog_sha256: Option<&str>,
    ) -> Res<ExportReport> {
        if self.status() != 200 {
            return Err(ClientError::Decode(
                "the node did not send the whole backup".into(),
            ));
        }
        let Some(expected) = self.sha256().map(str::to_string) else {
            return Err(ClientError::Decode(
                "the node did not send a backup checksum".into(),
            ));
        };
        if let Some(known) = catalog_sha256.filter(|s| !s.is_empty())
            && !known.eq_ignore_ascii_case(&expected)
        {
            return Err(ClientError::Decode(
                "the node's checksum differs from the backup record".into(),
            ));
        }
        let declared = self.content_length();
        if declared.is_some_and(|len| len > max_bytes) {
            return Err(too_large(max_bytes));
        }
        let content_type = self.content_type().map(str::to_string);
        let dir = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = dest
            .file_name()
            .ok_or_else(|| invalid("destination has no file name"))?;
        let tmp = dir.join(format!(".{}.{}.tmp", name.to_string_lossy(), new_id()));
        // Declared before the file so the handle closes first when the guard removes the path.
        let mut guard = TmpGuard(Some(tmp.clone()));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // A backup holds the whole database, so the file must not follow a permissive umask.
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).await.map_err(io_error)?;
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        while let Some(chunk) = self
            .response
            .chunk()
            .await
            .map_err(ClientError::from_reqwest)?
        {
            written += chunk.len() as u64;
            if written > max_bytes {
                return Err(too_large(max_bytes));
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(io_error)?;
        }
        file.flush().await.map_err(io_error)?;
        file.sync_all().await.map_err(io_error)?;
        drop(file);
        if declared.is_some_and(|len| len != written) {
            return Err(ClientError::Decode(
                "the backup download ended early".into(),
            ));
        }
        let actual: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !actual.eq_ignore_ascii_case(&expected) {
            return Err(ClientError::Decode(
                "the downloaded backup does not match its sha256".into(),
            ));
        }
        tokio::fs::rename(&tmp, dest).await.map_err(io_error)?;
        guard.0 = None;
        Ok(ExportReport {
            path: dest.to_path_buf(),
            bytes: written,
            content_type,
            suggested_name: None,
        })
    }
}

struct TmpGuard(Option<PathBuf>);

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn io_error(err: std::io::Error) -> ClientError {
    ClientError::Config(format!("cannot write backup: {err}"))
}

fn too_large(max: u64) -> ClientError {
    ClientError::Decode(format!("backup exceeds the {max} byte limit"))
}

async fn open_backup_stream(req: reqwest::RequestBuilder) -> Res<BackupStream> {
    let resp = req.send().await.map_err(ClientError::from_reqwest)?;
    if resp.status().is_success() {
        return Ok(BackupStream { response: resp });
    }
    let (status, _, buf) = read_capped(resp).await?;
    Err(ClientError::Status {
        code: status.as_u16(),
        message: error_message(&buf, status),
    })
}

impl NodeClient {
    // Every data mutation that touches Docker answers 202 with a job, so the action budget is plenty.
    async fn data_write<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Res<T> {
        let bytes = self.exec(method, path, query, body, ACTION_OPTS).await?;
        decode(&bytes)
    }

    async fn data_write_unit(&self, method: Method, path: &str) -> Res<()> {
        self.exec(method, path, &[], None, ACTION_OPTS)
            .await
            .map(|_| ())
    }

    async fn data_write_secret<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Res<T> {
        let bytes = self
            .exec_json_bytes(method, path, body, ACTION_OPTS)
            .await?;
        decode(&bytes)
    }

    // ---- node level ----

    pub async fn data_node(&self) -> Res<DataNodeView> {
        self.json(Method::GET, "/data", &[], None).await
    }

    pub async fn data_job(&self, job_id: &str) -> Res<JobView> {
        let id = validate_job_id(job_id)?;
        self.json(Method::GET, &format!("/data/jobs/{}", enc(id)), &[], None)
            .await
    }

    pub async fn data_targets(&self) -> Res<Vec<TargetView>> {
        self.json(Method::GET, "/data/targets", &[], None).await
    }

    pub async fn data_target_create(&self, target: &TargetReq) -> Res<TargetView> {
        self.data_write_secret(Method::POST, "/data/targets", secret_body(target)?)
            .await
    }

    pub async fn data_target_update(&self, target_id: &str, target: &TargetReq) -> Res<TargetView> {
        let id = validate_target_id(target_id)?;
        self.data_write_secret(
            Method::PUT,
            &format!("/data/targets/{}", enc(id)),
            secret_body(target)?,
        )
        .await
    }

    pub async fn data_target_delete(&self, target_id: &str) -> Res<()> {
        let id = validate_target_id(target_id)?;
        self.data_write_unit(Method::DELETE, &format!("/data/targets/{}", enc(id)))
            .await
    }

    pub async fn data_target_test(&self, target_id: &str) -> Res<TargetTestResult> {
        let id = validate_target_id(target_id)?;
        self.data_write(
            Method::POST,
            &format!("/data/targets/{}/test", enc(id)),
            &[],
            Some(json!({})),
        )
        .await
    }

    pub async fn data_shared(&self) -> Res<SharedView> {
        self.json(Method::GET, "/data/shared", &[], None).await
    }

    pub async fn data_shared_put(&self, req: &SharedReq) -> Res<JobAccepted> {
        if let Some(major) = req.major
            && !PG_MAJORS.contains(&major)
        {
            return Err(invalid(format!("Postgres major {major} is not offered")));
        }
        self.data_write(
            Method::PUT,
            "/data/shared",
            &[],
            crate::client::body_of(req)?,
        )
        .await
    }

    pub async fn data_shared_restart(&self) -> Res<JobAccepted> {
        self.data_write(Method::POST, "/data/shared/restart", &[], Some(json!({})))
            .await
    }

    /// The node refuses while sites still have databases on the instance unless both flags are set.
    pub async fn data_shared_delete(&self, force: bool, purge: bool) -> Res<JobAccepted> {
        let query = [("force", force.to_string()), ("purge", purge.to_string())];
        self.data_write(Method::DELETE, "/data/shared", &query, None)
            .await
    }

    pub async fn data_shared_backups(&self) -> Res<Vec<InstanceBackupRecord>> {
        self.json(Method::GET, "/data/shared/backups", &[], None)
            .await
    }

    pub async fn data_shared_backup(&self) -> Res<JobAccepted> {
        self.data_write(Method::POST, "/data/shared/backups", &[], Some(json!({})))
            .await
    }

    pub async fn data_shared_backup_delete(&self, backup_id: &str) -> Res<()> {
        let id = validate_backup_id(backup_id)?;
        self.data_write_unit(Method::DELETE, &format!("/data/shared/backups/{}", enc(id)))
            .await
    }

    /// The tar of a whole-instance backup; `range` is one `bytes=a-b` range, passed on as given.
    pub async fn data_shared_backup_stream(
        &self,
        backup_id: &str,
        range: Option<&str>,
    ) -> Res<BackupStream> {
        let id = validate_backup_id(backup_id)?;
        self.open_backup(&format!("/data/shared/backups/{}/download", enc(id)), range)
            .await
    }

    pub async fn data_orphans(&self) -> Res<Vec<OrphanView>> {
        self.json(Method::GET, "/data/orphans", &[], None).await
    }

    /// Removes everything a deleted site left behind: its volume, databases, backups and secrets.
    pub async fn data_orphan_purge(&self, site_id: &str) -> Res<()> {
        let id = validate_site_id(site_id)?;
        self.data_write_unit(Method::DELETE, &format!("/data/orphans/{}", enc(id)))
            .await
    }

    // ---- site level: overview and Postgres ----

    pub async fn site_data(&self, site_id: &str) -> Res<SiteDataView> {
        let path = site_data_path(site_id, "")?;
        self.json(Method::GET, &path, &[], None).await
    }

    /// Deletes the site and, unlike `delete_site`, its databases, backups and generated secrets too.
    pub async fn delete_site_purging_data(&self, site_id: &str) -> Res<()> {
        let id = validate_site_id(site_id)?;
        self.exec(
            Method::DELETE,
            &format!("/sites/{}", enc(id)),
            &[("purge_data", "true".to_string())],
            None,
            ACTION_OPTS,
        )
        .await
        .map(|_| ())
    }

    /// Enables Postgres or updates an enabled instance; the work runs as a job.
    pub async fn site_pg_enable(&self, site_id: &str, req: &PgEnableReq) -> Res<JobAccepted> {
        let path = site_data_path(site_id, "/postgres")?;
        if let Some(major) = req.major
            && !PG_MAJORS.contains(&major)
        {
            return Err(invalid(format!("Postgres major {major} is not offered")));
        }
        if req.preset.as_deref().is_some_and(|p| p != "generic") {
            return Err(invalid("the only preset on enable is `generic`"));
        }
        self.data_write(Method::PUT, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_pg_disable(&self, site_id: &str, purge: bool) -> Res<JobAccepted> {
        let path = site_data_path(site_id, "/postgres")?;
        self.data_write(Method::DELETE, &path, &[("purge", purge.to_string())], None)
            .await
    }

    pub async fn site_pg_policy(&self, site_id: &str, policy: &BackupPolicy) -> Res<PgView> {
        let path = site_data_path(site_id, "/postgres/policy")?;
        validate_backup_policy("backup policy", policy).map_err(|e| invalid(e.to_string()))?;
        self.data_write(Method::PUT, &path, &[], crate::client::body_of(policy)?)
            .await
    }

    pub async fn site_pg_convert(&self, site_id: &str, req: &ConvertReq) -> Res<SessionStarted> {
        let path = site_data_path(site_id, "/postgres/convert")?;
        self.data_write(Method::POST, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_pg_convert_cutover(&self, site_id: &str, session_id: &str) -> Res<Session> {
        let path = self.convert_path(site_id, session_id, "cutover")?;
        self.data_write(Method::POST, &path, &[], Some(json!({})))
            .await
    }

    pub async fn site_pg_convert_abort(&self, site_id: &str, session_id: &str) -> Res<Session> {
        let path = self.convert_path(site_id, session_id, "abort")?;
        self.data_write(Method::POST, &path, &[], Some(json!({})))
            .await
    }

    fn convert_path(&self, site_id: &str, session_id: &str, action: &str) -> Res<String> {
        let sid = validate_job_id(session_id)?;
        site_data_path(site_id, &format!("/postgres/convert/{}/{action}", enc(sid)))
    }

    /// Removes the old database left after a conversion.
    pub async fn site_pg_retired_delete(&self, site_id: &str) -> Res<JobAccepted> {
        let path = site_data_path(site_id, "/postgres/retired")?;
        self.data_write(Method::DELETE, &path, &[], None).await
    }

    // ---- site level: databases and users ----

    pub async fn site_db_create(&self, site_id: &str, req: &DatabaseCreateReq) -> Res<JobAccepted> {
        validate_pg_name(&req.name)?;
        let path = site_data_path(site_id, "/postgres/databases")?;
        self.data_write(Method::POST, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_db_delete(&self, site_id: &str, db: &str, purge: bool) -> Res<JobAccepted> {
        let path = database_path(site_id, db, "")?;
        self.data_write(Method::DELETE, &path, &[("purge", purge.to_string())], None)
            .await
    }

    pub async fn site_db_user_create(
        &self,
        site_id: &str,
        db: &str,
        req: &UserCreateReq,
    ) -> Res<JobAccepted> {
        validate_pg_name(&req.name)?;
        let path = database_path(site_id, db, "/users")?;
        self.data_write(Method::POST, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_db_user_update(
        &self,
        site_id: &str,
        db: &str,
        user: &str,
        req: &UserPatchReq,
    ) -> Res<JobAccepted> {
        if req.is_empty() {
            return Err(invalid("nothing to change"));
        }
        let path = user_path(site_id, db, user, "")?;
        self.data_write(Method::PATCH, &path, &[], crate::client::body_of(req)?)
            .await
    }

    /// Issues a new password; it is never returned, and `redeploy_needed` says whether running containers still hold the old one.
    pub async fn site_db_user_rotate(
        &self,
        site_id: &str,
        db: &str,
        user: &str,
    ) -> Res<JobAccepted> {
        let path = user_path(site_id, db, user, "/rotate")?;
        self.data_write(Method::POST, &path, &[], Some(json!({})))
            .await
    }

    pub async fn site_db_user_delete(
        &self,
        site_id: &str,
        db: &str,
        user: &str,
    ) -> Res<JobAccepted> {
        let path = user_path(site_id, db, user, "")?;
        self.data_write(Method::DELETE, &path, &[], None).await
    }

    // ---- site level: external databases, S3 and secrets ----

    /// The URL carries the credentials; it is stored on the node and never returned.
    pub async fn site_external_put(
        &self,
        site_id: &str,
        name: &str,
        req: &ExternalPutReq,
    ) -> Res<ExternalView> {
        let name = validate_data_name(name)?;
        let path = site_data_path(site_id, &format!("/external/{}", enc(name)))?;
        self.data_write_secret(Method::PUT, &path, secret_body(req)?)
            .await
    }

    pub async fn site_external_delete(&self, site_id: &str, name: &str) -> Res<()> {
        let name = validate_data_name(name)?;
        let path = site_data_path(site_id, &format!("/external/{}", enc(name)))?;
        self.data_write_unit(Method::DELETE, &path).await
    }

    pub async fn site_s3_put(&self, site_id: &str, name: &str, req: &S3PutReq) -> Res<S3View> {
        let name = validate_data_name(name)?;
        let path = site_data_path(site_id, &format!("/s3/{}", enc(name)))?;
        self.data_write_secret(Method::PUT, &path, secret_body(req)?)
            .await
    }

    pub async fn site_s3_delete(&self, site_id: &str, name: &str) -> Res<()> {
        let name = validate_data_name(name)?;
        let path = site_data_path(site_id, &format!("/s3/{}", enc(name)))?;
        self.data_write_unit(Method::DELETE, &path).await
    }

    pub async fn site_secret_create(
        &self,
        site_id: &str,
        req: &SecretCreateReq,
    ) -> Res<SecretView> {
        validate_data_name(&req.name)?;
        let path = site_data_path(site_id, "/secrets")?;
        self.data_write(Method::POST, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_secret_rotate(&self, site_id: &str, name: &str) -> Res<SecretView> {
        let name = validate_data_name(name)?;
        let path = site_data_path(site_id, &format!("/secrets/{}/rotate", enc(name)))?;
        self.data_write(Method::POST, &path, &[], Some(json!({})))
            .await
    }

    pub async fn site_secret_delete(&self, site_id: &str, name: &str) -> Res<()> {
        let name = validate_data_name(name)?;
        let path = site_data_path(site_id, &format!("/secrets/{}", enc(name)))?;
        self.data_write_unit(Method::DELETE, &path).await
    }

    // ---- site level: env links ----

    pub async fn site_links(&self, site_id: &str) -> Res<Vec<LinkView>> {
        let path = site_data_path(site_id, "/links")?;
        self.json(Method::GET, &path, &[], None).await
    }

    /// A 409 whose body lists the colliding variables comes back as `Conflicts`; any other refusal is an error.
    pub async fn site_links_add(&self, site_id: &str, req: &LinksReq) -> Res<LinksOutcome> {
        if req.links.is_empty() || req.links.len() > MAX_ENV_LINKS {
            return Err(invalid(format!("give 1 to {MAX_ENV_LINKS} links")));
        }
        for link in &req.links {
            validate_env_name(&link.var)?;
        }
        let path = site_data_path(site_id, "/links")?;
        let (status, bytes) = self
            .exec_status(
                Method::POST,
                &path,
                crate::client::body_of(req)?,
                ACTION_OPTS,
            )
            .await?;
        if status.is_success() {
            return decode(&bytes).map(LinksOutcome::Applied);
        }
        if status.as_u16() == 409
            && let Some(conflicts) = conflicts_of(&bytes)
        {
            return Ok(LinksOutcome::Conflicts(conflicts));
        }
        Err(ClientError::Status {
            code: status.as_u16(),
            message: error_message(&bytes, status),
        })
    }

    pub async fn site_link_delete(&self, site_id: &str, target: LinkTarget, var: &str) -> Res<()> {
        let var = validate_env_name(var)?;
        let path = site_data_path(
            site_id,
            &format!("/links/{}/{}", link_target_segment(target), enc(var)),
        )?;
        self.data_write_unit(Method::DELETE, &path).await
    }

    pub async fn site_links_preset(
        &self,
        site_id: &str,
        req: &PresetRequest,
    ) -> Res<LinksOutcome<PresetResponse>> {
        validate_pg_name(&req.database)?;
        validate_pg_name(&req.runtime_user)?;
        validate_pg_name(&req.migrate_user)?;
        if let Some(auth) = &req.auth_database {
            validate_pg_name(auth)?;
        }
        let path = site_data_path(site_id, "/links/preset")?;
        // The node answers 200 (done) or 202 (a job runs) with the response, or 409 with the conflicting variables.
        let (status, bytes) = self
            .exec_status(
                Method::POST,
                &path,
                crate::client::body_of(req)?,
                ACTION_OPTS,
            )
            .await?;
        if status.is_success() {
            return decode(&bytes).map(LinksOutcome::Applied);
        }
        if status.as_u16() == 409
            && let Some(conflicts) = conflicts_of(&bytes)
        {
            return Ok(LinksOutcome::Conflicts(conflicts));
        }
        Err(ClientError::Status {
            code: status.as_u16(),
            message: error_message(&bytes, status),
        })
    }

    // ---- site level: backups ----

    /// Newest first; `database` (`pg:<db>`) narrows the list.
    pub async fn site_backups(
        &self,
        site_id: &str,
        database: Option<&str>,
    ) -> Res<Vec<BackupRecord>> {
        let path = site_data_path(site_id, "/backups")?;
        let mut query = Vec::new();
        if let Some(database) = database {
            query.push(("database", validate_database_ref(database)?.to_string()));
        }
        self.json(Method::GET, &path, &query, None).await
    }

    pub async fn site_backup(&self, site_id: &str, backup_id: &str) -> Res<BackupRecord> {
        let path = backup_path(site_id, backup_id, "")?;
        self.json(Method::GET, &path, &[], None).await
    }

    pub async fn site_backup_create(
        &self,
        site_id: &str,
        req: &BackupCreateReq,
    ) -> Res<BackupCreated> {
        validate_database_ref(&req.database)?;
        if let Some(label) = &req.label {
            validate_label(label)?;
        }
        let path = site_data_path(site_id, "/backups")?;
        self.data_write(Method::POST, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_backup_patch(
        &self,
        site_id: &str,
        backup_id: &str,
        req: &BackupPatchReq,
    ) -> Res<BackupRecord> {
        if req.label.is_none() && req.pinned.is_none() {
            return Err(invalid("nothing to change"));
        }
        if let Some(Some(label)) = &req.label {
            validate_label(label)?;
        }
        let path = backup_path(site_id, backup_id, "")?;
        self.data_write(Method::PATCH, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_backup_delete(
        &self,
        site_id: &str,
        backup_id: &str,
        from: DeleteFrom,
    ) -> Res<()> {
        let path = backup_path(site_id, backup_id, "")?;
        let from = match from {
            DeleteFrom::Local => "local",
            DeleteFrom::S3 => "s3",
            DeleteFrom::All => "all",
        };
        self.exec(
            Method::DELETE,
            &path,
            &[("from", from.to_string())],
            None,
            ACTION_OPTS,
        )
        .await
        .map(|_| ())
    }

    /// Takes a pre-restore backup first and drops connections; `confirm` must repeat the site id.
    pub async fn site_backup_restore(
        &self,
        site_id: &str,
        backup_id: &str,
        req: &RestoreReq,
    ) -> Res<RestoreStarted> {
        let id = validate_site_id(site_id)?;
        if req.confirm != id {
            return Err(invalid("confirm must repeat the site id"));
        }
        if let Some(database) = &req.database {
            validate_database_ref(database)?;
        }
        let path = backup_path(site_id, backup_id, "/restore")?;
        self.data_write(Method::POST, &path, &[], crate::client::body_of(req)?)
            .await
    }

    pub async fn site_backup_push(
        &self,
        site_id: &str,
        backup_id: &str,
        req: &PushReq,
    ) -> Res<JobAccepted> {
        if let Some(target) = &req.target {
            validate_target_id(target)?;
        }
        let path = backup_path(site_id, backup_id, "/push")?;
        self.data_write(Method::POST, &path, &[], crate::client::body_of(req)?)
            .await
    }

    /// The decrypted dump; `range` is one `bytes=a-b` range, passed on as given.
    pub async fn site_backup_stream(
        &self,
        site_id: &str,
        backup_id: &str,
        range: Option<&str>,
    ) -> Res<BackupStream> {
        let path = backup_path(site_id, backup_id, "/download")?;
        self.open_backup(&path, range).await
    }

    /// Saves the whole dump beside `dest` and renames it into place only after its length and sha256 check out against the node's
    /// `x-backup-sha256` header (and the record's own checksum when it has one). A mismatch deletes the partial file.
    /// The suggested name is rebuilt from the record, never taken from the node.
    pub async fn site_backup_download_to(
        &self,
        site_id: &str,
        backup: &BackupRecord,
        dest: &Path,
        max_bytes: u64,
    ) -> Res<ExportReport> {
        let stream = self.site_backup_stream(site_id, &backup.id, None).await?;
        let mut report = stream
            .save(dest, max_bytes, Some(backup.sha256.as_str()))
            .await?;
        report.suggested_name = Some(backup_download_name(
            site_id,
            &backup.database,
            backup.version,
        ));
        Ok(report)
    }

    /// Saves a whole-instance backup tar the same way, checked against the node's `x-backup-sha256` header.
    pub async fn data_shared_backup_download_to(
        &self,
        backup_id: &str,
        dest: &Path,
        max_bytes: u64,
    ) -> Res<ExportReport> {
        let stream = self.data_shared_backup_stream(backup_id, None).await?;
        let mut report = stream.save(dest, max_bytes, None).await?;
        report.suggested_name = Some(instance_backup_download_name(backup_id));
        Ok(report)
    }

    async fn open_backup(&self, path: &str, range: Option<&str>) -> Res<BackupStream> {
        let mut req = self
            .authed_get(format!("{}/api/v1{path}", self.base_url()))
            .timeout(EXPORT_TIMEOUT);
        if let Some(range) = range {
            req = req.header(reqwest::header::RANGE, range);
        }
        open_backup_stream(req).await
    }

    pub async fn site_prune_preview(&self, site_id: &str) -> Res<Vec<PrunePreview>> {
        let path = site_data_path(site_id, "/prune-preview")?;
        self.json(Method::GET, &path, &[], None).await
    }

    pub async fn site_prune(&self, site_id: &str) -> Res<PruneResult> {
        let path = site_data_path(site_id, "/prune")?;
        self.data_write(Method::POST, &path, &[], Some(json!({})))
            .await
    }
}

fn conflicts_of(body: &[u8]) -> Option<Vec<LinkConflict>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let list = value.get("conflicts")?.clone();
    let parsed: Vec<LinkConflict> = serde_json::from_value(list).ok()?;
    (!parsed.is_empty()).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_ids_are_ulids() {
        assert!(validate_backup_id("01JC9ZQ7M3X8V4N2B6T5R0WHYA").is_ok());
        for bad in [
            "",
            "01jc9zq7m3x8v4n2b6t5r0whya",
            "01JC9ZQ7M3X8V4N2B6T5R0WHY",
            "01JC9ZQ7M3X8V4N2B6T5R0WHYAA",
            "01JC9ZQ7M3X8V4N2B6T5R0WHIA",
            "../JC9ZQ7M3X8V4N2B6T5R0WHYA",
            "01JC9ZQ7M3X8V4N2B6T5R0WH/A",
        ] {
            assert!(validate_backup_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn name_validators_match_the_documented_shapes() {
        for ok in ["a", "billing-db", "a1-b2"] {
            assert!(validate_data_name(ok).is_ok(), "{ok}");
        }
        let long = "a".repeat(32);
        for bad in ["", "1a", "-a", "A", "a_b", "a.b", long.as_str()] {
            assert!(validate_data_name(bad).is_err(), "{bad}");
        }
        for ok in ["app", "a1", "abcdefghijklmnop"] {
            assert!(validate_pg_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "1a", "a-b", "App", "abcdefghijklmnopq", "a b"] {
            assert!(validate_pg_name(bad).is_err(), "{bad}");
        }
        for ok in ["pg:app", "ext:billing-db"] {
            assert!(validate_database_ref(ok).is_ok(), "{ok}");
        }
        for bad in ["app", "pg:", "pg:a-b", "ext:A", "x:app", "pg:app:x"] {
            assert!(validate_database_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn download_names_are_rebuilt_from_safe_parts() {
        assert_eq!(
            backup_download_name("shop", "pg:app", 3),
            "shop-app-v3.dump"
        );
        assert_eq!(
            backup_download_name("shop", "ext:billing-db", 12),
            "shop-billing-db-v12.dump"
        );
        assert_eq!(
            backup_download_name("../shop", "pg:a\"b", 1),
            "shop-ab-v1.dump"
        );
        assert_eq!(
            instance_backup_download_name("01JC9ZQ7M3X8V4N2B6T5R0WHYA"),
            "cite-pg-shared-01JC9ZQ7M3X8V4N2B6T5R0WHYA.tar"
        );
        assert_eq!(
            instance_backup_download_name("a/../b"),
            "cite-pg-shared-ab.tar"
        );
    }

    #[test]
    fn conflicts_are_read_from_the_409_body() {
        let body = br#"{"error":"conflict","conflicts":[{"var":"DATABASE_URL","target":"runtime","set_by":"manual"}]}"#;
        let got = conflicts_of(body).expect("conflicts");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].var, "DATABASE_URL");
        assert!(conflicts_of(br#"{"error":"conflict"}"#).is_none());
        assert!(conflicts_of(br#"{"conflicts":[]}"#).is_none());
        assert!(conflicts_of(b"not json").is_none());
    }

    #[test]
    fn only_well_formed_checksums_count() {
        assert!(is_hex_sha256(&"a".repeat(64)));
        assert!(!is_hex_sha256(&"a".repeat(63)));
        assert!(!is_hex_sha256(&"g".repeat(64)));
    }
}
