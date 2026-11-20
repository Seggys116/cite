// The node wrappers for the data services live here because their routes are used by the Data tab and the Databases page only.
// A live node goes through cite-client, a demo node through the in-memory services of demo_data.rs.

use std::path::{Path, PathBuf};

use cite_client::{ClientError, ExportReport, LinksOutcome};
use cite_edge::datamodel::{BackupPolicy, LinkTarget};
use cite_edge::datawire::{
    BackupCreateReq, BackupCreated, BackupPatchReq, BackupRecord, ConvertReq, DataNodeView,
    DatabaseCreateReq, DeleteFrom, ExternalPutReq, ExternalView, InstanceBackupRecord, JobAccepted,
    JobView, LinksReq, OrphanView, PgEnableReq, PgView, PresetRequest, PresetResponse,
    PrunePreview, PruneResult, PushReq, RestoreReq, RestoreStarted, S3PutReq, S3View,
    SecretCreateReq, SecretView, Session, SessionStarted, SharedReq, SharedView, SiteDataView,
    TargetReq, TargetTestResult, TargetView, UserCreateReq, UserPatchReq,
};

use crate::api::{NodeHandle, Res};

// A backup holds a whole database, so the cap is generous; the save refuses anything larger.
pub const BACKUP_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

impl NodeHandle {
    // ---- node level ----

    pub(crate) async fn data_node(&self) -> Res<DataNodeView> {
        match self {
            Self::Live(c) => c.data_node().await,
            Self::Demo(_, d) => d.dd_node(),
        }
    }

    pub(crate) async fn data_job(&self, id: &str) -> Res<JobView> {
        match self {
            Self::Live(c) => c.data_job(id).await,
            Self::Demo(_, d) => d.dd_job(id),
        }
    }

    pub(crate) async fn data_targets(&self) -> Res<Vec<TargetView>> {
        match self {
            Self::Live(c) => c.data_targets().await,
            Self::Demo(_, d) => d.dd_targets(),
        }
    }

    pub(crate) async fn data_target_create(&self, req: &TargetReq) -> Res<TargetView> {
        match self {
            Self::Live(c) => c.data_target_create(req).await,
            Self::Demo(_, d) => d.dd_target_create(req),
        }
    }

    pub(crate) async fn data_target_update(&self, id: &str, req: &TargetReq) -> Res<TargetView> {
        match self {
            Self::Live(c) => c.data_target_update(id, req).await,
            Self::Demo(_, d) => d.dd_target_update(id, req),
        }
    }

    pub(crate) async fn data_target_delete(&self, id: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.data_target_delete(id).await,
            Self::Demo(_, d) => d.dd_target_delete(id),
        }
    }

    pub(crate) async fn data_target_test(&self, id: &str) -> Res<TargetTestResult> {
        match self {
            Self::Live(c) => c.data_target_test(id).await,
            Self::Demo(_, d) => d.dd_target_test(id),
        }
    }

    pub(crate) async fn data_shared(&self) -> Res<SharedView> {
        match self {
            Self::Live(c) => c.data_shared().await,
            Self::Demo(_, d) => d.dd_shared(),
        }
    }

    pub(crate) async fn data_shared_put(&self, req: &SharedReq) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.data_shared_put(req).await,
            Self::Demo(_, d) => d.dd_shared_put(req),
        }
    }

    pub(crate) async fn data_shared_restart(&self) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.data_shared_restart().await,
            Self::Demo(_, d) => d.dd_shared_restart(),
        }
    }

    pub(crate) async fn data_shared_delete(&self, force: bool, purge: bool) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.data_shared_delete(force, purge).await,
            Self::Demo(_, d) => d.dd_shared_delete(force, purge),
        }
    }

    pub(crate) async fn data_shared_backups(&self) -> Res<Vec<InstanceBackupRecord>> {
        match self {
            Self::Live(c) => c.data_shared_backups().await,
            Self::Demo(_, d) => d.dd_shared_backups(),
        }
    }

    pub(crate) async fn data_shared_backup(&self) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.data_shared_backup().await,
            Self::Demo(_, d) => d.dd_shared_backup(),
        }
    }

    pub(crate) async fn data_shared_backup_delete(&self, id: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.data_shared_backup_delete(id).await,
            Self::Demo(_, d) => d.dd_shared_backup_delete(id),
        }
    }

    pub(crate) async fn data_shared_backup_download_to(
        &self,
        id: &str,
        dest: &Path,
    ) -> Res<ExportReport> {
        match self {
            Self::Live(c) => {
                c.data_shared_backup_download_to(id, dest, BACKUP_MAX_BYTES)
                    .await
            }
            Self::Demo(_, d) => d.dd_shared_backup_download(id, dest),
        }
    }

    pub(crate) async fn data_orphans(&self) -> Res<Vec<OrphanView>> {
        match self {
            Self::Live(c) => c.data_orphans().await,
            Self::Demo(_, d) => d.dd_orphans(),
        }
    }

    pub(crate) async fn data_orphan_purge(&self, site: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.data_orphan_purge(site).await,
            Self::Demo(_, d) => d.dd_orphan_purge(site),
        }
    }

    // ---- site level ----

    pub(crate) async fn site_data(&self, site: &str) -> Res<SiteDataView> {
        match self {
            Self::Live(c) => c.site_data(site).await,
            Self::Demo(_, d) => d.dd_site(site),
        }
    }

    pub(crate) async fn site_pg_enable(&self, site: &str, req: &PgEnableReq) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_pg_enable(site, req).await,
            Self::Demo(_, d) => d.dd_pg_enable(site, req),
        }
    }

    pub(crate) async fn site_pg_disable(&self, site: &str, purge: bool) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_pg_disable(site, purge).await,
            Self::Demo(_, d) => d.dd_pg_disable(site, purge),
        }
    }

    pub(crate) async fn site_pg_policy(&self, site: &str, policy: &BackupPolicy) -> Res<PgView> {
        match self {
            Self::Live(c) => c.site_pg_policy(site, policy).await,
            Self::Demo(_, d) => d.dd_pg_policy(site, policy),
        }
    }

    pub(crate) async fn site_pg_convert(
        &self,
        site: &str,
        req: &ConvertReq,
    ) -> Res<SessionStarted> {
        match self {
            Self::Live(c) => c.site_pg_convert(site, req).await,
            Self::Demo(_, d) => d.dd_pg_convert(site, req),
        }
    }

    pub(crate) async fn site_pg_convert_cutover(&self, site: &str, session: &str) -> Res<Session> {
        match self {
            Self::Live(c) => c.site_pg_convert_cutover(site, session).await,
            Self::Demo(_, d) => d.dd_pg_convert_cutover(site, session),
        }
    }

    pub(crate) async fn site_pg_convert_abort(&self, site: &str, session: &str) -> Res<Session> {
        match self {
            Self::Live(c) => c.site_pg_convert_abort(site, session).await,
            Self::Demo(_, d) => d.dd_pg_convert_abort(site, session),
        }
    }

    pub(crate) async fn site_pg_retired_delete(&self, site: &str) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_pg_retired_delete(site).await,
            Self::Demo(_, d) => d.dd_pg_retired_delete(site),
        }
    }

    pub(crate) async fn site_db_create(
        &self,
        site: &str,
        req: &DatabaseCreateReq,
    ) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_db_create(site, req).await,
            Self::Demo(_, d) => d.dd_db_create(site, req),
        }
    }

    pub(crate) async fn site_db_delete(
        &self,
        site: &str,
        db: &str,
        purge: bool,
    ) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_db_delete(site, db, purge).await,
            Self::Demo(_, d) => d.dd_db_delete(site, db, purge),
        }
    }

    pub(crate) async fn site_db_user_create(
        &self,
        site: &str,
        db: &str,
        req: &UserCreateReq,
    ) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_db_user_create(site, db, req).await,
            Self::Demo(_, d) => d.dd_user_create(site, db, req),
        }
    }

    pub(crate) async fn site_db_user_update(
        &self,
        site: &str,
        db: &str,
        user: &str,
        req: &UserPatchReq,
    ) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_db_user_update(site, db, user, req).await,
            Self::Demo(_, d) => d.dd_user_update(site, db, user, req),
        }
    }

    pub(crate) async fn site_db_user_rotate(
        &self,
        site: &str,
        db: &str,
        user: &str,
    ) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_db_user_rotate(site, db, user).await,
            Self::Demo(_, d) => d.dd_user_rotate(site, db, user),
        }
    }

    pub(crate) async fn site_db_user_delete(
        &self,
        site: &str,
        db: &str,
        user: &str,
    ) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_db_user_delete(site, db, user).await,
            Self::Demo(_, d) => d.dd_user_delete(site, db, user),
        }
    }

    pub(crate) async fn site_external_put(
        &self,
        site: &str,
        name: &str,
        req: &ExternalPutReq,
    ) -> Res<ExternalView> {
        match self {
            Self::Live(c) => c.site_external_put(site, name, req).await,
            Self::Demo(_, d) => d.dd_external_put(site, name, req),
        }
    }

    pub(crate) async fn site_external_delete(&self, site: &str, name: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.site_external_delete(site, name).await,
            Self::Demo(_, d) => d.dd_external_delete(site, name),
        }
    }

    pub(crate) async fn site_s3_put(&self, site: &str, name: &str, req: &S3PutReq) -> Res<S3View> {
        match self {
            Self::Live(c) => c.site_s3_put(site, name, req).await,
            Self::Demo(_, d) => d.dd_s3_put(site, name, req),
        }
    }

    pub(crate) async fn site_s3_delete(&self, site: &str, name: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.site_s3_delete(site, name).await,
            Self::Demo(_, d) => d.dd_s3_delete(site, name),
        }
    }

    pub(crate) async fn site_secret_create(
        &self,
        site: &str,
        req: &SecretCreateReq,
    ) -> Res<SecretView> {
        match self {
            Self::Live(c) => c.site_secret_create(site, req).await,
            Self::Demo(_, d) => d.dd_secret_create(site, req),
        }
    }

    pub(crate) async fn site_secret_rotate(&self, site: &str, name: &str) -> Res<SecretView> {
        match self {
            Self::Live(c) => c.site_secret_rotate(site, name).await,
            Self::Demo(_, d) => d.dd_secret_rotate(site, name),
        }
    }

    pub(crate) async fn site_secret_delete(&self, site: &str, name: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.site_secret_delete(site, name).await,
            Self::Demo(_, d) => d.dd_secret_delete(site, name),
        }
    }

    pub(crate) async fn site_link_delete(
        &self,
        site: &str,
        target: LinkTarget,
        var: &str,
    ) -> Res<()> {
        match self {
            Self::Live(c) => c.site_link_delete(site, target, var).await,
            Self::Demo(_, d) => d.dd_link_delete(site, target, var),
        }
    }

    // A 409 that names the colliding variables comes back as Conflicts, not as an error.
    pub(crate) async fn site_links_add(&self, site: &str, req: &LinksReq) -> Res<LinksOutcome> {
        match self {
            Self::Live(c) => c.site_links_add(site, req).await,
            Self::Demo(_, d) => d.dd_links_add(site, req),
        }
    }

    // A 409 that lists the colliding variables comes back as Conflicts, like adding one link.
    pub(crate) async fn site_links_preset(
        &self,
        site: &str,
        req: &PresetRequest,
    ) -> Res<LinksOutcome<PresetResponse>> {
        match self {
            Self::Live(c) => c.site_links_preset(site, req).await,
            Self::Demo(_, d) => d.dd_links_preset(site, req),
        }
    }

    pub(crate) async fn site_backups(
        &self,
        site: &str,
        database: Option<&str>,
    ) -> Res<Vec<BackupRecord>> {
        match self {
            Self::Live(c) => c.site_backups(site, database).await,
            Self::Demo(_, d) => d.dd_backups(site, database),
        }
    }

    pub(crate) async fn site_backup_create(
        &self,
        site: &str,
        req: &BackupCreateReq,
    ) -> Res<BackupCreated> {
        match self {
            Self::Live(c) => c.site_backup_create(site, req).await,
            Self::Demo(_, d) => d.dd_backup_create(site, req),
        }
    }

    pub(crate) async fn site_backup_patch(
        &self,
        site: &str,
        id: &str,
        req: &BackupPatchReq,
    ) -> Res<BackupRecord> {
        match self {
            Self::Live(c) => c.site_backup_patch(site, id, req).await,
            Self::Demo(_, d) => d.dd_backup_patch(site, id, req),
        }
    }

    pub(crate) async fn site_backup_delete(
        &self,
        site: &str,
        id: &str,
        from: DeleteFrom,
    ) -> Res<()> {
        match self {
            Self::Live(c) => c.site_backup_delete(site, id, from).await,
            Self::Demo(_, d) => d.dd_backup_delete(site, id, from),
        }
    }

    pub(crate) async fn site_backup_restore(
        &self,
        site: &str,
        id: &str,
        req: &RestoreReq,
    ) -> Res<RestoreStarted> {
        match self {
            Self::Live(c) => c.site_backup_restore(site, id, req).await,
            Self::Demo(_, d) => d.dd_backup_restore(site, id, req),
        }
    }

    pub(crate) async fn site_backup_push(
        &self,
        site: &str,
        id: &str,
        req: &PushReq,
    ) -> Res<JobAccepted> {
        match self {
            Self::Live(c) => c.site_backup_push(site, id, req).await,
            Self::Demo(_, d) => d.dd_backup_push(site, id, req),
        }
    }

    // The sha256 of the saved file is checked against the node's own before it is renamed into place.
    pub(crate) async fn site_backup_download_to(
        &self,
        site: &str,
        rec: &BackupRecord,
        dest: &Path,
    ) -> Res<ExportReport> {
        match self {
            Self::Live(c) => {
                c.site_backup_download_to(site, rec, dest, BACKUP_MAX_BYTES)
                    .await
            }
            Self::Demo(_, d) => d.dd_backup_download(site, rec, dest),
        }
    }

    pub(crate) async fn site_prune_preview(&self, site: &str) -> Res<Vec<PrunePreview>> {
        match self {
            Self::Live(c) => c.site_prune_preview(site).await,
            Self::Demo(_, d) => d.dd_prune_preview(site),
        }
    }

    pub(crate) async fn site_prune(&self, site: &str) -> Res<PruneResult> {
        match self {
            Self::Live(c) => c.site_prune(site).await,
            Self::Demo(_, d) => d.dd_prune(site),
        }
    }
}

// The file lands in the Downloads folder under a name rebuilt from the record, never one the node chose, and never over an
// existing file.
pub async fn run_backup_download(
    handle: NodeHandle,
    site: String,
    rec: BackupRecord,
    dir: PathBuf,
) -> Res<ExportReport> {
    let name = cite_client::backup_download_name(&site, &rec.database, rec.version);
    let dest = prepare_dest(&dir, &name)?;
    handle.site_backup_download_to(&site, &rec, &dest).await
}

pub async fn run_instance_backup_download(
    handle: NodeHandle,
    id: String,
    dir: PathBuf,
) -> Res<ExportReport> {
    let name = cite_client::instance_backup_download_name(&id);
    let dest = prepare_dest(&dir, &name)?;
    handle.data_shared_backup_download_to(&id, &dest).await
}

fn prepare_dest(dir: &Path, name: &str) -> Result<PathBuf, ClientError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| ClientError::Config(format!("cannot create {}: {e}", dir.display())))?;
    Ok(crate::bots::unique_path(dir, name))
}
