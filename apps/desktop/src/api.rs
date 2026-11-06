use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use cite_client::{
    AnalyticsStats, ArchiveEntry, ArchiveList, ClientError, CreatedToken, CutReport, DeployRequest,
    ExportQuery, ExportReport, NodeClient, NodeConfig, NodeInfo, PresetInfo, RequestQuery,
    RestoreReport, SiteDetail, TokenMeta,
};
use cite_edge::analytics::{Summary, Timeseries, TopItem};
use cite_edge::bot::BotSummary;
use cite_edge::model::{
    Deployment, EdgeSettings, FirewallRule, LogEvent, MaintenancePage, Site, Slot,
};

use crate::archive::CutSpec;
use crate::certs::{CertItem, CertListing, RangesListing, UploadOutcome, UploadRequest};
use crate::demo::DemoNode;
use crate::zone::{ZoneReveal, ZoneStatus};

pub type Res<T> = Result<T, ClientError>;

static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

fn runtime() -> Result<&'static tokio::runtime::Runtime, ClientError> {
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("cite-io")
                .build()
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| ClientError::Config(format!("cannot start network runtime: {e}")))
}

// Network futures need a tokio reactor, so they run there and the UI awaits the join handle.
pub fn spawn_io<T, F>(fut: F) -> impl Future<Output = Res<T>> + use<T, F>
where
    T: Send + 'static,
    F: Future<Output = Res<T>> + Send + 'static,
{
    let handle = runtime().map(|rt| rt.spawn(fut));
    async move {
        match handle {
            Ok(h) => h.await.unwrap_or_else(|e| {
                Err(ClientError::Config(format!("background task failed: {e}")))
            }),
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone)]
pub enum NodeHandle {
    Live(NodeClient),
    Demo(String, Arc<DemoNode>),
}

impl NodeHandle {
    pub fn name(&self) -> &str {
        match self {
            Self::Live(c) => c.name(),
            Self::Demo(n, _) => n,
        }
    }

    pub async fn node_info(&self) -> Res<NodeInfo> {
        match self {
            Self::Live(c) => c.node_info().await,
            Self::Demo(_, d) => d.info(),
        }
    }

    pub async fn list_sites(&self) -> Res<Vec<Site>> {
        match self {
            Self::Live(c) => c.list_sites().await,
            Self::Demo(_, d) => d.list_sites(),
        }
    }

    pub async fn get_site(&self, id: &str) -> Res<SiteDetail> {
        match self {
            Self::Live(c) => c.get_site(id).await,
            Self::Demo(_, d) => d.get_site(id),
        }
    }

    pub async fn create_site(&self, site: &Site, github_token: Option<&str>) -> Res<Site> {
        match self {
            Self::Live(c) => c.create_site(site, github_token).await,
            Self::Demo(_, d) => d.create_site(site),
        }
    }

    pub async fn delete_site(&self, id: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.delete_site(id).await,
            Self::Demo(_, d) => d.delete_site(id),
        }
    }

    pub async fn update_site(&self, id: &str, site: &Site) -> Res<Site> {
        match self {
            Self::Live(c) => c.update_site(id, site).await,
            Self::Demo(_, d) => d.update_site(id, site),
        }
    }

    pub async fn deploy(&self, id: &str, req: &DeployRequest) -> Res<Deployment> {
        match self {
            Self::Live(c) => c.deploy(id, req).await,
            Self::Demo(_, d) => d.deploy(id, req),
        }
    }

    pub async fn switch(&self, id: &str, slot: Slot) -> Res<Deployment> {
        match self {
            Self::Live(c) => c.switch(id, slot).await,
            Self::Demo(_, d) => d.switch(id, slot),
        }
    }

    pub async fn rollback(&self, id: &str) -> Res<Deployment> {
        match self {
            Self::Live(c) => c.rollback(id).await,
            Self::Demo(_, d) => d.rollback(id),
        }
    }

    pub async fn maintenance(&self, id: &str, enabled: bool, page: Option<&str>) -> Res<Site> {
        match self {
            Self::Live(c) => c.maintenance(id, enabled, page).await,
            Self::Demo(_, d) => d.maintenance(id, enabled, page),
        }
    }

    pub async fn list_pages(&self) -> Res<Vec<MaintenancePage>> {
        match self {
            Self::Live(c) => c.list_pages().await,
            Self::Demo(_, d) => d.list_pages(),
        }
    }

    pub async fn create_page(&self, page: &MaintenancePage) -> Res<MaintenancePage> {
        match self {
            Self::Live(c) => c.create_page(page).await,
            Self::Demo(_, d) => d.create_page(page),
        }
    }

    pub async fn update_page(&self, id: &str, page: &MaintenancePage) -> Res<MaintenancePage> {
        match self {
            Self::Live(c) => c.update_page(id, page).await,
            Self::Demo(_, d) => d.update_page(id, page),
        }
    }

    pub async fn delete_page(&self, id: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.delete_page(id).await,
            Self::Demo(_, d) => d.delete_page(id),
        }
    }

    pub async fn list_rules(&self) -> Res<Vec<FirewallRule>> {
        match self {
            Self::Live(c) => c.list_rules().await,
            Self::Demo(_, d) => d.list_rules(),
        }
    }

    pub async fn create_rule(&self, rule: &FirewallRule) -> Res<FirewallRule> {
        match self {
            Self::Live(c) => c.create_rule(rule).await,
            Self::Demo(_, d) => d.create_rule(rule),
        }
    }

    pub async fn update_rule(&self, id: &str, rule: &FirewallRule) -> Res<FirewallRule> {
        match self {
            Self::Live(c) => c.update_rule(id, rule).await,
            Self::Demo(_, d) => d.update_rule(id, rule),
        }
    }

    pub async fn delete_rule(&self, id: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.delete_rule(id).await,
            Self::Demo(_, d) => d.delete_rule(id),
        }
    }

    pub async fn list_presets(&self) -> Res<Vec<PresetInfo>> {
        match self {
            Self::Live(c) => c.list_presets().await,
            Self::Demo(_, d) => d.list_presets(),
        }
    }

    pub async fn apply_preset(&self, name: &str) -> Res<Vec<FirewallRule>> {
        match self {
            Self::Live(c) => c.apply_preset(name).await,
            Self::Demo(_, d) => d.apply_preset(name),
        }
    }

    pub async fn summary(&self, window: &str) -> Res<Summary> {
        match self {
            Self::Live(c) => c.analytics_summary(window, None).await,
            Self::Demo(_, d) => d.summary(window),
        }
    }

    pub async fn series(&self, window: &str) -> Res<Timeseries> {
        match self {
            Self::Live(c) => c.analytics_timeseries(window, None).await,
            Self::Demo(_, d) => d.series(window),
        }
    }

    pub async fn requests(&self, window: &str, limit: usize) -> Res<Vec<LogEvent>> {
        let query = RequestQuery {
            limit: Some(limit),
            ..RequestQuery::default()
        };
        match self {
            Self::Live(c) => c.analytics_requests(window, None, &query).await,
            Self::Demo(_, d) => d.requests(None, &query),
        }
    }

    pub async fn bots(&self, window: &str) -> Res<BotSummary> {
        match self {
            Self::Live(c) => c.analytics_bots(window, None).await,
            Self::Demo(_, d) => d.bots(window),
        }
    }

    pub async fn top(&self, kind: &str, window: &str, limit: usize) -> Res<Vec<TopItem>> {
        match self {
            Self::Live(c) => c.analytics_top(kind, window, None, Some(limit)).await,
            Self::Demo(_, d) => d.top(kind, window, Some(limit)),
        }
    }

    pub async fn stats(&self) -> Res<AnalyticsStats> {
        match self {
            Self::Live(c) => c.analytics_stats().await,
            Self::Demo(_, d) => d.stats(),
        }
    }

    // Demo nodes write a generated file with the same no-overwrite rule the live download follows.
    pub async fn export_to(
        &self,
        query: &ExportQuery,
        dest: &Path,
        max_bytes: u64,
    ) -> Res<ExportReport> {
        match self {
            Self::Live(c) => c.analytics_export_to(query, dest, max_bytes).await,
            Self::Demo(_, d) => {
                let pairs = query.pairs()?;
                let body = d.export_body(&pairs);
                let written = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(dest)
                    .and_then(|mut f| f.write_all(body.as_bytes()));
                written.map_err(|e| ClientError::Config(format!("cannot write export: {e}")))?;
                Ok(ExportReport {
                    path: dest.to_path_buf(),
                    bytes: body.len() as u64,
                    content_type: None,
                    suggested_name: Some(crate::demo::demo_export_name(&pairs)),
                })
            }
        }
    }

    pub async fn archives(&self) -> Res<ArchiveList> {
        match self {
            Self::Live(c) => c.analytics_archives().await,
            Self::Demo(_, d) => d.archives(),
        }
    }

    pub async fn backup(&self) -> Res<ArchiveEntry> {
        match self {
            Self::Live(c) => c.analytics_backup().await,
            Self::Demo(_, d) => d.backup(),
        }
    }

    // Demo nodes need the plain spec, so the request is built here for live nodes only.
    pub async fn cut(&self, spec: &CutSpec, dry_run: bool) -> Res<CutReport> {
        match self {
            Self::Live(c) => {
                let req = spec.request(dry_run).map_err(ClientError::Config)?;
                c.analytics_cut(&req).await
            }
            Self::Demo(_, d) => d.cut(spec, dry_run),
        }
    }

    pub async fn restore(&self, name: &str) -> Res<RestoreReport> {
        match self {
            Self::Live(c) => c.analytics_restore(name).await,
            Self::Demo(_, d) => d.restore(name),
        }
    }

    pub async fn delete_archive(&self, name: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.analytics_archive_delete(name).await,
            Self::Demo(_, d) => d.delete_archive(name),
        }
    }

    pub async fn download_archive(
        &self,
        name: &str,
        dest: &Path,
        max_bytes: u64,
    ) -> Res<ExportReport> {
        match self {
            Self::Live(c) => c.analytics_archive_download_to(name, dest, max_bytes).await,
            Self::Demo(_, d) => {
                let body = d.archive_body(name)?;
                let written = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(dest)
                    .and_then(|mut f| f.write_all(body.as_bytes()));
                written.map_err(|e| ClientError::Config(format!("cannot write download: {e}")))?;
                Ok(ExportReport {
                    path: dest.to_path_buf(),
                    bytes: body.len() as u64,
                    content_type: None,
                    suggested_name: None,
                })
            }
        }
    }

    pub async fn get_settings(&self) -> Res<EdgeSettings> {
        match self {
            Self::Live(c) => c.get_settings().await,
            Self::Demo(_, d) => d.get_settings(),
        }
    }

    pub async fn put_settings(&self, s: &EdgeSettings) -> Res<EdgeSettings> {
        match self {
            Self::Live(c) => c.put_settings(s).await,
            Self::Demo(_, d) => d.put_settings(s),
        }
    }

    pub async fn certificates(&self) -> Res<CertListing> {
        match self {
            Self::Live(c) => c.certificates().await.map(cert_listing),
            Self::Demo(_, d) => d.certificates(),
        }
    }

    pub async fn certificate_upload(&self, req: &UploadRequest) -> Res<UploadOutcome> {
        match self {
            Self::Live(c) => c
                .certificate_create(&create_upload(req))
                .await
                .map(uploaded),
            Self::Demo(_, d) => d.certificate_upload(req),
        }
    }

    pub async fn certificate_replace(&self, id: &str, req: &UploadRequest) -> Res<UploadOutcome> {
        match self {
            Self::Live(c) => c
                .certificate_replace(id, &replace_upload(req))
                .await
                .map(uploaded),
            Self::Demo(_, d) => d.certificate_replace(id, req),
        }
    }

    pub async fn certificate_delete(&self, id: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.certificate_delete(id).await,
            Self::Demo(_, d) => d.certificate_delete(id),
        }
    }

    pub async fn zone_secret(&self, site: &str) -> Res<ZoneStatus> {
        match self {
            Self::Live(c) => c.zone_secret(site).await.map(|s| ZoneStatus {
                configured: s.configured,
                readable: s.readable,
                header: s.header,
                created_at: s.created_at,
                fingerprint: s.fingerprint,
            }),
            Self::Demo(_, d) => d.zone_secret(site),
        }
    }

    // The secret is copied out of the client type, which wipes its own copy when it drops.
    pub async fn rotate_zone_secret(&self, site: &str) -> Res<ZoneReveal> {
        match self {
            Self::Live(c) => {
                let z = c.rotate_zone_secret(site).await?;
                Ok(ZoneReveal::new(
                    c.name(),
                    site,
                    z.secret(),
                    z.header.clone(),
                    z.created_at.clone(),
                    z.fingerprint.clone(),
                ))
            }
            Self::Demo(name, d) => d.rotate_zone_secret(name, site),
        }
    }

    pub async fn cloudflare_ranges(&self) -> Res<RangesListing> {
        match self {
            Self::Live(c) => c.cloudflare_ranges().await.map(|r| RangesListing {
                source: r.source,
                updated: r.updated,
                ranges: r.ranges,
            }),
            Self::Demo(_, d) => d.cloudflare_ranges(),
        }
    }

    pub async fn list_tokens(&self) -> Res<Vec<TokenMeta>> {
        match self {
            Self::Live(c) => c.list_tokens().await,
            Self::Demo(_, d) => d.list_tokens(),
        }
    }

    pub async fn create_token(&self, name: &str) -> Res<CreatedToken> {
        match self {
            Self::Live(c) => c.create_token(name).await,
            Self::Demo(_, d) => d.create_token(name),
        }
    }

    pub async fn delete_token(&self, id: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.delete_token(id).await,
            Self::Demo(_, d) => d.delete_token(id),
        }
    }
}

// The only place that reads the client's certificate types, so a signature change stays local.
fn cert_item(info: cite_client::CertificateInfo) -> CertItem {
    CertItem {
        id: info.id,
        name: info.name,
        subject: info.subject,
        sans: info.sans,
        issuer: info.issuer,
        not_before: info.not_before,
        not_after: info.not_after,
        days_left: info.days_left,
        fingerprint: info.fingerprint_sha256,
        key_type: info.key_type,
        created_at: info.created_at,
        covers: info.covers,
        source: info.source,
        warning: info.warning,
    }
}

fn cert_listing(list: cite_client::CertificateList) -> CertListing {
    CertListing {
        items: list.items.into_iter().map(cert_item).collect(),
        https_port: list.https_port,
        dir_ready: list.dir_ready,
        uncovered_hosts: list.uncovered_hosts,
    }
}

fn create_upload(req: &UploadRequest) -> cite_client::CertificateUpload {
    cite_client::CertificateUpload::new(&req.name, &req.certificate, &req.private_key)
}

fn replace_upload(req: &UploadRequest) -> cite_client::CertificateUpload {
    cite_client::CertificateUpload::replacement(&req.certificate, &req.private_key).named(&req.name)
}

fn uploaded(saved: cite_client::CertificateSaved) -> UploadOutcome {
    UploadOutcome {
        cert: cert_item(saved.certificate),
        warning: saved.warning,
    }
}

// Downloads under a free local name, then takes the node's suggested name when that one is free too.
pub async fn run_export(
    handle: NodeHandle,
    query: ExportQuery,
    dir: PathBuf,
    fallback: String,
) -> Res<ExportReport> {
    std::fs::create_dir_all(&dir)
        .map_err(|e| ClientError::Config(format!("cannot create {}: {e}", dir.display())))?;
    let dest = crate::bots::unique_path(&dir, &fallback);
    let mut report = handle
        .export_to(&query, &dest, cite_client::DEFAULT_EXPORT_MAX_BYTES)
        .await?;
    if let Some(name) = report.suggested_name.clone()
        && report.path.file_name().is_none_or(|n| n != name.as_str())
    {
        let target = crate::bots::unique_path(&dir, &name);
        if std::fs::rename(&report.path, &target).is_ok() {
            report.path = target;
        }
    }
    Ok(report)
}

// The local name comes from the fixed extension list, and a free numeric suffix keeps existing files safe.
pub async fn run_archive_download(
    handle: NodeHandle,
    name: String,
    dir: PathBuf,
    local_name: String,
) -> Res<ExportReport> {
    std::fs::create_dir_all(&dir)
        .map_err(|e| ClientError::Config(format!("cannot create {}: {e}", dir.display())))?;
    let dest = crate::bots::unique_path(&dir, &local_name);
    handle
        .download_archive(&name, &dest, crate::archive::ARCHIVE_MAX_BYTES)
        .await
}

#[derive(Clone)]
pub enum Credential {
    Token(String),
    Login {
        username: String,
        password: String,
        totp: String,
    },
}

// A password login is exchanged for a long-lived API token; only that token is returned.
pub async fn enroll(
    node: NodeConfig,
    credential: Credential,
    token_name: String,
) -> Res<(String, NodeInfo)> {
    let token = match credential {
        Credential::Token(t) => t,
        Credential::Login {
            username,
            password,
            totp,
        } => {
            let anon = NodeClient::new(&node, String::new())?;
            let session = anon.login(&username, &password, &totp).await?;
            let authed = NodeClient::new(&node, session.token)?;
            let created = authed.create_token(&token_name).await;
            // The session is no longer needed; a failed logout only leaves it to expire.
            let _ = authed.logout().await;
            created?.token
        }
    };
    let info = NodeClient::new(&node, token.clone())?.node_info().await?;
    Ok((token, info))
}

// Runs the futures concurrently on the network runtime and returns results in input order.
pub async fn join_all<T, F>(futs: Vec<F>) -> Vec<Option<T>>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let Ok(rt) = runtime() else {
        return futs.iter().map(|_| None).collect();
    };
    let handles: Vec<_> = futs.into_iter().map(|f| rt.spawn(f)).collect();
    let mut out = Vec::with_capacity(handles.len());
    for handle in handles {
        out.push(handle.await.ok());
    }
    out
}

// Live nodes go through the shared fleet helper; demo nodes follow the same create or update rules.
pub async fn apply_to_handles(
    handles: Vec<NodeHandle>,
    plan: cite_client::ReplicationPlan,
) -> Vec<cite_client::NodeOutcome> {
    let mut live = Vec::new();
    let mut demo = Vec::new();
    for h in handles {
        match h {
            NodeHandle::Live(c) => live.push(c),
            other => demo.push(other),
        }
    }
    let mut outcomes = cite_client::apply_plan(&live, &plan).await;
    for h in demo {
        let mut site = plan.site_for(h.name());
        let result = match plan.mode {
            cite_client::ReplicationMode::Each => {
                h.create_site(&site, None).await.map(|_| "created")
            }
            cite_client::ReplicationMode::Replicate => match h.get_site(&site.id).await {
                Ok(existing) => {
                    site.history = existing.site.history;
                    h.update_site(&site.id, &site).await.map(|_| "updated")
                }
                Err(_) => h.create_site(&site, None).await.map(|_| "created"),
            },
        };
        outcomes.push(match result {
            Ok(action) => cite_client::NodeOutcome {
                node: h.name().to_string(),
                ok: true,
                action: Some(action.to_string()),
                error: None,
            },
            Err(e) => cite_client::NodeOutcome::failed(h.name(), e.to_string()),
        });
    }
    outcomes
}
