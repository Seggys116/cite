// Demo data services: the same calls the connector answers for databases, backups, env links and the shared instance,
// served from memory so the Data tab and the Databases page show realistic content without a node.
// Declared from demo.rs, so it sees the demo node's private parts.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::{MutexGuard, PoisonError};

use cite_client::{ClientError, ExportReport, LinksOutcome};
use cite_edge::datamodel::{
    BackupPolicy, BackupRetention, BackupSchedule, LinkSource, LinkTarget, PgLevel, PgMode,
    RetiredPostgres, S3Copy, S3Field, SecretEncoding,
};
use cite_edge::datawire::{
    BackupCreateReq, BackupCreated, BackupPatchReq, BackupRecord, BackupStatus, BackupTrigger,
    ConflictSetBy, DataNodeView, DatabaseCreateReq, DeleteFrom, ExternalPutReq, ExternalView,
    InstanceBackupPart, InstanceBackupRecord, JobAccepted, JobState, JobView, KeyView,
    LinkConflict, LinkView, LinksReq, LocalCopy, OrphanView, PgDatabaseView, PgEnableReq,
    PgUserView, PgView, PresetRequest, PresetResponse, PruneKeep, PrunePlanView, PrunePreview,
    PruneResult, PushReq, RestoreReq, RestoreStarted, S3CopyInfo, S3PutReq, S3View,
    SecretCreateReq, SecretView, SharedReq, SharedView, SiteDataView, TargetReq, TargetTestResult,
    TargetView, TenantDatabaseView, TenantView, UserCreateReq, UserPatchReq,
};
use cite_edge::datawire::{
    ConvertReq, Freeze, Session, SessionKind, SessionStarted, SessionState, TRANSFER_CHUNK_BYTES,
    TableCount,
};
use cite_edge::validate::{
    MAX_EXTERNAL_POSTGRES, MAX_GENERATED_SECRETS, MAX_PG_DATABASES, MAX_PG_USERS_PER_DATABASE,
    MAX_S3_ATTACHMENTS,
};

use super::{DemoNode, HOUR_MS, Res, demo_sha, find, iso, now_ms, status_err};
use crate::archive::DAY_MS;
use crate::ui::dataview::{preset_spec, source_label};

const MIB: u64 = 1024 * 1024;
const TARGET_OFFSITE: &str = "tgt-offsite";

fn not_found(what: &str) -> ClientError {
    status_err(404, format!("{what} not found"))
}

fn conflict(message: impl Into<String>) -> ClientError {
    status_err(409, message)
}

// A valid backup id: 26 characters of Crockford base32.
fn demo_ulid(n: u64) -> String {
    format!("01K{n:023}")
}

struct DemoJob {
    id: String,
    kind: &'static str,
    site: Option<String>,
    polls_left: u8,
}

pub struct DemoData {
    sites: BTreeMap<String, SiteDataView>,
    // Every version, with the site it belongs to.
    backups: Vec<(String, BackupRecord)>,
    targets: Vec<TargetView>,
    shared: SharedView,
    instance_backups: Vec<InstanceBackupRecord>,
    orphans: Vec<OrphanView>,
    jobs: Vec<DemoJob>,
    converts: Vec<DemoConvert>,
    counter: u64,
}

// An on-node conversion between dedicated and shared, as a session that advances one step per read.
struct DemoConvert {
    id: String,
    site: String,
    to: PgMode,
    state: SessionState,
    polls_left: u8,
}

fn user(name: &str, level: PgLevel, limit: u32, rotated_days: i64, now: i64) -> PgUserView {
    PgUserView {
        name: name.into(),
        level: Some(level),
        connection_limit: limit,
        statement_timeout_ms: level.default_statement_timeout_ms(),
        idle_in_transaction_timeout_ms: 60_000,
        disabled: false,
        active: "a".into(),
        retiring: None,
        rotated_at: Some(iso(now - rotated_days * DAY_MS)),
        linked_by: Vec::new(),
    }
}

fn database(name: &str, size_mib: u64, users: Vec<PgUserView>) -> PgDatabaseView {
    PgDatabaseView {
        name: name.into(),
        users,
        size_bytes: Some(size_mib * MIB),
    }
}

fn link(var: &str, target: LinkTarget, source: LinkSource) -> LinkView {
    LinkView {
        var: var.into(),
        target,
        label: source_label(&source),
        source,
        shadows_doppler: false,
    }
}

fn pg_url(database: &str, user: &str) -> LinkSource {
    LinkSource::Postgres {
        database: database.into(),
        user: user.into(),
        field: cite_edge::datamodel::PgField::Url,
    }
}

// What uses each user, secret and attachment, read off the links.
fn relink(view: &mut SiteDataView) {
    let links = view.links.clone();
    let vars = |wanted: &dyn Fn(&LinkSource) -> bool| -> Vec<String> {
        let mut out: Vec<String> = links
            .iter()
            .filter(|l| wanted(&l.source))
            .map(|l| l.var.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    };
    if let Some(pg) = view.postgres.as_mut() {
        for db in &mut pg.databases {
            for u in &mut db.users {
                let (dn, un) = (db.name.clone(), u.name.clone());
                u.linked_by = vars(
                    &|s| matches!(s, LinkSource::Postgres { database, user, .. } if *database == dn && *user == un),
                );
            }
        }
    }
    for s in &mut view.secrets {
        let name = s.name.clone();
        s.linked_by = vars(&|src| matches!(src, LinkSource::Secret { name: n } if *n == name));
    }
    for s in &mut view.s3 {
        let name = s.name.clone();
        s.linked_by = vars(&|src| matches!(src, LinkSource::S3 { name: n, .. } if *n == name));
    }
}

fn backup(
    n: u64,
    db: &str,
    version: u32,
    created_ms: i64,
    trigger: BackupTrigger,
    size_mib: u64,
) -> BackupRecord {
    BackupRecord {
        id: demo_ulid(n),
        database: db.into(),
        version,
        created_at: iso(created_ms),
        completed_at: Some(iso(created_ms + 40_000)),
        trigger,
        label: None,
        pinned: false,
        size_bytes: size_mib * MIB,
        sha256: demo_sha(n),
        server_version: "18.1".into(),
        format: "pg_dump-custom".into(),
        encryption: Some(cite_edge::datawire::EncryptionInfo {
            scheme: "cite-stream-v1".into(),
            kid: "a1b2c3d4e5f60718".into(),
        }),
        local: Some(LocalCopy {
            file: format!("{}.cbk", demo_ulid(n)),
            stored_bytes: size_mib * MIB / 2,
        }),
        s3: None,
        status: BackupStatus::Ok,
        error: None,
        actor: "desktop".into(),
        source: None,
    }
}

fn s3_copy(rec: &BackupRecord, target: &str) -> S3CopyInfo {
    S3CopyInfo {
        target: target.into(),
        key: format!("edge/{}/{}.cbk", rec.database.replace(':', "-"), rec.id),
        etag: None,
        version_id: None,
        uploaded_at: rec.completed_at.clone().unwrap_or_default(),
        delete_error: None,
    }
}

impl DemoData {
    pub fn seeded(now: i64) -> Self {
        let mut docs = SiteDataView {
            postgres: Some(PgView {
                mode: PgMode::Dedicated,
                major: 18,
                memory_mb: 512,
                max_connections: 100,
                databases: vec![
                    database(
                        "app",
                        38,
                        vec![
                            user("app", PgLevel::Readwrite, 20, 9, now),
                            user("migrate", PgLevel::Owner, 5, 9, now),
                        ],
                    ),
                    database(
                        "auth",
                        4,
                        vec![
                            user("app", PgLevel::Readwrite, 10, 3, now),
                            user("migrate", PgLevel::Owner, 5, 3, now),
                        ],
                    ),
                ],
                backup: BackupPolicy {
                    schedule: Some(BackupSchedule {
                        every_hours: 6,
                        minute: 17,
                    }),
                    local: BackupRetention::default(),
                    s3: Some(S3Copy {
                        target: TARGET_OFFSITE.into(),
                        retention: BackupRetention::default(),
                    }),
                },
                health: Some("healthy".into()),
                retired: None,
            }),
            s3: vec![S3View {
                name: "assets".into(),
                endpoint: "https://s3.eu-west-1.amazonaws.com".into(),
                bucket: "docs-assets".into(),
                region: "eu-west-1".into(),
                path_style: false,
                has_keys: true,
                linked_by: Vec::new(),
            }],
            secrets: vec![SecretView {
                name: "auth-secret".into(),
                bytes: 32,
                encoding: SecretEncoding::Base64url,
                rotated_at: iso(now - 20 * DAY_MS),
                linked_by: Vec::new(),
                redeploy_needed: false,
            }],
            links: vec![
                link("DATABASE_URL", LinkTarget::Runtime, pg_url("app", "app")),
                link(
                    "MIGRATION_DATABASE_URL",
                    LinkTarget::Build,
                    pg_url("app", "migrate"),
                ),
                link(
                    "AUTH_SECRET",
                    LinkTarget::Runtime,
                    LinkSource::Secret {
                        name: "auth-secret".into(),
                    },
                ),
                link(
                    "AUTH_DATABASE_URL",
                    LinkTarget::Runtime,
                    pg_url("auth", "app"),
                ),
                link(
                    "AUTH_MIGRATION_DATABASE_URL",
                    LinkTarget::Build,
                    pg_url("auth", "migrate"),
                ),
                link(
                    "S3_BUCKET",
                    LinkTarget::Runtime,
                    LinkSource::S3 {
                        name: "assets".into(),
                        field: S3Field::Bucket,
                    },
                ),
            ],
            ..SiteDataView::default()
        };
        // A var a Doppler config also sets, so the shadow badge shows.
        docs.links[3].shadows_doppler = true;
        relink(&mut docs);
        let mut shop = SiteDataView {
            postgres: Some(PgView {
                mode: PgMode::Shared,
                major: 18,
                memory_mb: 1024,
                max_connections: 200,
                databases: vec![database(
                    "app",
                    61,
                    vec![
                        user("app", PgLevel::Readwrite, 20, 14, now),
                        user("migrate", PgLevel::Owner, 5, 14, now),
                    ],
                )],
                backup: BackupPolicy {
                    schedule: Some(BackupSchedule {
                        every_hours: 24,
                        minute: 17,
                    }),
                    ..BackupPolicy::default()
                },
                health: Some("healthy".into()),
                retired: None,
            }),
            links: vec![
                link("DATABASE_URL", LinkTarget::Runtime, pg_url("app", "app")),
                link(
                    "MIGRATION_DATABASE_URL",
                    LinkTarget::Build,
                    pg_url("app", "migrate"),
                ),
            ],
            ..SiteDataView::default()
        };
        relink(&mut shop);
        let mut api = SiteDataView {
            external: vec![ExternalView {
                name: "billing".into(),
                host: "billing-db.example.net".into(),
                port: 5432,
                database: "billing".into(),
                sslmode: Some("require".into()),
                forward_port: Some(15432),
                warnings: vec![
                    "sslmode require works through the egress forward; verify-full would fail the host name check."
                        .into(),
                ],
            }],
            links: vec![link(
                "BILLING_DATABASE_URL",
                LinkTarget::Runtime,
                LinkSource::External {
                    name: "billing".into(),
                    field: cite_edge::datamodel::PgField::Url,
                },
            )],
            ..SiteDataView::default()
        };
        relink(&mut api);

        let mut n = 100;
        let mut next = || {
            n += 1;
            n
        };
        let hours = |h: i64| now - h * HOUR_MS;
        let mut app = vec![
            backup(
                next(),
                "pg:app",
                1,
                hours(24 * 30),
                BackupTrigger::Manual,
                30,
            ),
            backup(
                next(),
                "pg:app",
                2,
                hours(24 * 20),
                BackupTrigger::Scheduled,
                34,
            ),
            backup(
                next(),
                "pg:app",
                3,
                hours(30),
                BackupTrigger::PreRestore,
                35,
            ),
            backup(next(), "pg:app", 4, hours(9), BackupTrigger::Manual, 37),
            backup(next(), "pg:app", 5, hours(2), BackupTrigger::Scheduled, 38),
        ];
        app[0].label = Some("first release".into());
        app[0].pinned = true;
        app[3].label = Some("before the schema migration".into());
        for i in [1, 4] {
            let copy = s3_copy(&app[i], TARGET_OFFSITE);
            app[i].s3 = Some(copy);
        }
        let mut failed = backup(next(), "pg:app", 6, hours(1), BackupTrigger::Scheduled, 0);
        failed.status = BackupStatus::Failed;
        failed.local = None;
        failed.sha256.clear();
        failed.error = Some("pg_dump: error: connection to server was lost".into());
        app.push(failed);
        let auth = vec![backup(
            next(),
            "pg:auth",
            1,
            hours(5),
            BackupTrigger::Scheduled,
            4,
        )];
        let billing = vec![backup(
            next(),
            "ext:billing",
            1,
            hours(48),
            BackupTrigger::Manual,
            12,
        )];
        let mut backups: Vec<(String, BackupRecord)> = Vec::new();
        backups.extend(app.into_iter().map(|r| ("docs".to_string(), r)));
        backups.extend(auth.into_iter().map(|r| ("docs".to_string(), r)));
        backups.extend(billing.into_iter().map(|r| ("api".to_string(), r)));
        let instance_part = |db: &str, size: u64, seed: u64| InstanceBackupPart {
            database: db.into(),
            size_bytes: size * MIB,
            sha256: demo_sha(seed),
        };
        Self {
            sites: BTreeMap::from([
                ("docs".to_string(), docs),
                ("shop".to_string(), shop),
                ("api".to_string(), api),
            ]),
            backups,
            targets: vec![TargetView {
                id: TARGET_OFFSITE.into(),
                name: "Offsite archive".into(),
                endpoint: "https://s3.eu-central-1.amazonaws.com".into(),
                bucket: "cite-backups".into(),
                region: "eu-central-1".into(),
                path_style: false,
                prefix: "edge-fra".into(),
                encrypt: true,
            }],
            shared: SharedView {
                enabled: true,
                major: 18,
                memory_mb: 1024,
                nano_cpus: 1_000_000_000,
                max_connections: 200,
                health: "healthy".into(),
                size_bytes: 212 * MIB,
                tenants: Vec::new(),
            },
            instance_backups: vec![
                InstanceBackupRecord {
                    id: demo_ulid(900),
                    created_at: iso(now - 3 * DAY_MS),
                    parts: vec![instance_part("t1a2b3c_app", 61, 901)],
                    status: BackupStatus::Ok,
                },
                InstanceBackupRecord {
                    id: demo_ulid(902),
                    created_at: iso(now - 10 * DAY_MS),
                    parts: vec![instance_part("t1a2b3c_app", 58, 903)],
                    status: BackupStatus::Ok,
                },
            ],
            orphans: vec![OrphanView {
                site: "old-blog".into(),
                dedicated_volume: Some("cite-old-blog-db-data".into()),
                shared_databases: Vec::new(),
                backups: 3,
                secrets: 2,
            }],
            jobs: Vec::new(),
            converts: Vec::new(),
            counter: 1000,
        }
    }

    fn bump(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    // A job the page can follow: it reads as running for two polls, then done.
    fn new_job(&mut self, kind: &'static str, site: Option<&str>) -> String {
        let id = format!("demojob-{}", self.bump());
        self.jobs.push(DemoJob {
            id: id.clone(),
            kind,
            site: site.map(str::to_string),
            polls_left: 2,
        });
        id
    }

    fn accepted(&mut self, kind: &'static str, site: Option<&str>, redeploy: bool) -> JobAccepted {
        JobAccepted {
            job_id: self.new_job(kind, site),
            redeploy_needed: redeploy,
        }
    }

    fn site_mut(&mut self, site: &str) -> &mut SiteDataView {
        self.sites.entry(site.to_string()).or_default()
    }

    fn tenants(&self) -> Vec<TenantView> {
        self.sites
            .iter()
            .filter_map(|(site, view)| {
                let pg = view
                    .postgres
                    .as_ref()
                    .filter(|p| p.mode == PgMode::Shared)?;
                Some(TenantView {
                    site: site.clone(),
                    databases: pg
                        .databases
                        .iter()
                        .map(|d| TenantDatabaseView {
                            name: d.name.clone(),
                            size_bytes: d.size_bytes.unwrap_or(0),
                        })
                        .collect(),
                })
            })
            .collect()
    }

    fn shared_view(&self) -> SharedView {
        SharedView {
            tenants: self.tenants(),
            ..self.shared.clone()
        }
    }
}

fn pg_mut(view: &mut SiteDataView) -> Res<&mut PgView> {
    view.postgres
        .as_mut()
        .ok_or_else(|| conflict("Postgres is not enabled for this site"))
}

fn db_mut<'a>(pg: &'a mut PgView, name: &str) -> Res<&'a mut PgDatabaseView> {
    pg.databases
        .iter_mut()
        .find(|d| d.name == name)
        .ok_or_else(|| not_found(&format!("database {name}")))
}

fn default_users(now: i64) -> Vec<PgUserView> {
    vec![
        user("app", PgLevel::Readwrite, 20, 0, now),
        user("migrate", PgLevel::Owner, 5, 0, now),
    ]
}

impl DemoNode {
    fn dt(&self) -> MutexGuard<'_, DemoData> {
        self.data.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // The data services exist on the first demo node only; the second plays a release from before them.
    fn require_data(&self) -> Res<()> {
        if self.index == 0 {
            Ok(())
        } else {
            Err(not_found("route"))
        }
    }

    fn data_site(&self, site: &str) -> Res<()> {
        self.require_data()?;
        let st = self.st();
        find(&st.sites, site).map(|_| ())
    }

    // ---- node level ----

    pub fn dd_node(&self) -> Res<DataNodeView> {
        self.require_data()?;
        let d = self.dt();
        Ok(DataNodeView {
            enabled: true,
            backup_volume_ok: true,
            key: KeyView {
                kid: "a1b2c3d4e5f60718".into(),
                source: "managed".into(),
            },
            pg_majors: vec![17, 18],
            shared: d.shared.enabled.then(|| d.shared_view()),
            targets: d.targets.len() as u32,
            orphans: d.orphans.len() as u32,
        })
    }

    pub fn dd_job(&self, id: &str) -> Res<JobView> {
        self.require_data()?;
        let mut d = self.dt();
        let job = d
            .jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| not_found("job"))?;
        let running = job.polls_left > 0;
        job.polls_left = job.polls_left.saturating_sub(1);
        let step = match job.kind {
            "backup" => "dumping",
            "restore" => "restoring",
            _ => "working",
        };
        Ok(JobView {
            id: job.id.clone(),
            kind: job.kind.into(),
            site: job.site.clone(),
            state: if running {
                JobState::Running
            } else {
                JobState::Ok
            },
            step: running.then(|| step.to_string()),
            error: None,
            result: None,
        })
    }

    pub fn dd_targets(&self) -> Res<Vec<TargetView>> {
        self.require_data()?;
        Ok(self.dt().targets.clone())
    }

    fn target_from(id: String, req: &TargetReq, old: Option<&TargetView>) -> TargetView {
        TargetView {
            id,
            name: req.name.clone(),
            endpoint: req.endpoint.clone(),
            bucket: req.bucket.clone(),
            region: req.region.clone(),
            path_style: req.path_style,
            prefix: req.prefix.clone().unwrap_or_default(),
            encrypt: req.encrypt.unwrap_or(old.is_none_or(|o| o.encrypt)),
        }
    }

    pub fn dd_target_create(&self, req: &TargetReq) -> Res<TargetView> {
        self.require_data()?;
        let mut d = self.dt();
        if req.access_key_id.is_none() || req.secret_access_key.is_none() {
            return Err(status_err(400, "a new target needs both keys"));
        }
        let id = format!("tgt-{}", d.bump());
        let view = Self::target_from(id, req, None);
        d.targets.push(view.clone());
        Ok(view)
    }

    pub fn dd_target_update(&self, id: &str, req: &TargetReq) -> Res<TargetView> {
        self.require_data()?;
        let mut d = self.dt();
        let slot = d
            .targets
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| not_found("target"))?;
        let old = slot.clone();
        *slot = Self::target_from(id.to_string(), req, Some(&old));
        Ok(slot.clone())
    }

    pub fn dd_target_delete(&self, id: &str) -> Res<()> {
        self.require_data()?;
        let mut d = self.dt();
        let in_use = d
            .sites
            .values()
            .filter_map(|v| v.postgres.as_ref()?.backup.s3.as_ref())
            .any(|c| c.target == id);
        if in_use {
            return Err(conflict("a site's backup policy still uses this target"));
        }
        let before = d.targets.len();
        d.targets.retain(|t| t.id != id);
        if d.targets.len() == before {
            return Err(not_found("target"));
        }
        Ok(())
    }

    pub fn dd_target_test(&self, id: &str) -> Res<TargetTestResult> {
        self.require_data()?;
        let d = self.dt();
        let target = d
            .targets
            .iter()
            .find(|t| t.id == id)
            .ok_or_else(|| not_found("target"))?;
        let bad = target.endpoint.contains("unreachable");
        Ok(TargetTestResult {
            ok: !bad,
            error: bad.then(|| "could not reach the endpoint: connection timed out".to_string()),
        })
    }

    pub fn dd_shared(&self) -> Res<SharedView> {
        self.require_data()?;
        Ok(self.dt().shared_view())
    }

    pub fn dd_shared_put(&self, req: &SharedReq) -> Res<JobAccepted> {
        self.require_data()?;
        let mut d = self.dt();
        if !d.shared.enabled {
            d.shared.enabled = true;
            d.shared.major = req.major.unwrap_or(18);
            d.shared.health = "starting".into();
        } else if req.major.is_some_and(|m| m != d.shared.major) {
            return Err(status_err(
                400,
                "the Postgres major is fixed once the instance exists",
            ));
        }
        d.shared.memory_mb = req.memory_mb;
        d.shared.nano_cpus = (req.cpus * 1e9).round() as i64;
        d.shared.max_connections = req.max_connections;
        Ok(d.accepted("shared-put", None, false))
    }

    pub fn dd_shared_restart(&self) -> Res<JobAccepted> {
        self.require_data()?;
        let mut d = self.dt();
        if !d.shared.enabled {
            return Err(conflict("the shared instance is not enabled"));
        }
        Ok(d.accepted("shared-restart", None, false))
    }

    pub fn dd_shared_delete(&self, force: bool, purge: bool) -> Res<JobAccepted> {
        self.require_data()?;
        let mut d = self.dt();
        let tenants = d.tenants().len();
        if tenants > 0 && !(force && purge) {
            return Err(conflict(format!(
                "{tenants} sites still have databases on the shared instance"
            )));
        }
        d.shared.enabled = false;
        Ok(d.accepted("shared-delete", None, false))
    }

    pub fn dd_shared_backups(&self) -> Res<Vec<InstanceBackupRecord>> {
        self.require_data()?;
        let mut list = self.dt().instance_backups.clone();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(list)
    }

    pub fn dd_shared_backup(&self) -> Res<JobAccepted> {
        self.require_data()?;
        let mut d = self.dt();
        if !d.shared.enabled {
            return Err(conflict("the shared instance is not enabled"));
        }
        let n = d.bump();
        let parts = d
            .tenants()
            .iter()
            .flat_map(|t| t.databases.iter())
            .enumerate()
            .map(|(i, db)| InstanceBackupPart {
                database: format!("t1a2b3c_{}", db.name),
                size_bytes: db.size_bytes / 2,
                sha256: demo_sha(n + i as u64),
            })
            .collect();
        d.instance_backups.push(InstanceBackupRecord {
            id: demo_ulid(n),
            created_at: iso(now_ms()),
            parts,
            status: BackupStatus::Ok,
        });
        Ok(d.accepted("shared-backup", None, false))
    }

    pub fn dd_shared_backup_delete(&self, id: &str) -> Res<()> {
        self.require_data()?;
        let mut d = self.dt();
        let before = d.instance_backups.len();
        d.instance_backups.retain(|b| b.id != id);
        if d.instance_backups.len() == before {
            return Err(not_found("backup"));
        }
        Ok(())
    }

    pub fn dd_shared_backup_download(&self, id: &str, dest: &Path) -> Res<ExportReport> {
        self.require_data()?;
        if !self.dt().instance_backups.iter().any(|b| b.id == id) {
            return Err(not_found("backup"));
        }
        write_demo_file(dest, &format!("demo instance backup {id}\n"))
    }

    pub fn dd_orphans(&self) -> Res<Vec<OrphanView>> {
        self.require_data()?;
        Ok(self.dt().orphans.clone())
    }

    // ---- conversion ----

    fn convert_session(c: &DemoConvert) -> Session {
        let count = |rows| TableCount {
            schema: "public".into(),
            table: "orders".into(),
            rows,
        };
        let ready = matches!(c.state, SessionState::AwaitingCutover | SessionState::Done);
        let now = iso(now_ms());
        Session {
            id: c.id.clone(),
            kind: SessionKind::Convert,
            site: c.site.clone(),
            database: "pg:app".into(),
            state: c.state,
            freeze: Freeze::Maintenance,
            created_at: now.clone(),
            updated_at: now,
            backup_id: None,
            size_bytes: 38 * MIB,
            sha256: String::new(),
            chunk_size: TRANSFER_CHUNK_BYTES,
            chunks: 0,
            received: Vec::new(),
            counts: ready.then(|| vec![count(1840)]),
            peer_counts: ready.then(|| vec![count(1840)]),
            pre_restore_backup: None,
            error: None,
            actor: "desktop".into(),
        }
    }

    pub fn dd_pg_convert(&self, site: &str, req: &ConvertReq) -> Res<SessionStarted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let shared_on = d.shared.enabled;
        let running = d
            .converts
            .iter()
            .any(|c| c.site == site && !c.state.is_terminal());
        let pg = pg_mut(d.site_mut(site))?;
        if pg.mode == req.to {
            return Err(conflict("the database is already there"));
        }
        if req.to == PgMode::Shared && !shared_on {
            return Err(conflict("the node's shared instance is not enabled"));
        }
        if running {
            return Err(conflict("a conversion of this site is already running"));
        }
        let id = format!("democonv-{}", d.bump());
        d.converts.push(DemoConvert {
            id: id.clone(),
            site: site.to_string(),
            to: req.to,
            state: SessionState::Freezing,
            polls_left: 3,
        });
        Ok(SessionStarted { session: id })
    }

    pub fn dd_pg_convert_cutover(&self, site: &str, id: &str) -> Res<Session> {
        self.data_site(site)?;
        let mut d = self.dt();
        let c = d
            .converts
            .iter_mut()
            .find(|c| c.id == id && c.site == site)
            .ok_or_else(|| not_found("conversion"))?;
        if c.state != SessionState::AwaitingCutover {
            return Err(conflict("the conversion is not waiting for a cutover"));
        }
        c.state = SessionState::Done;
        let (to, session) = (c.to, Self::convert_session(c));
        let pg = pg_mut(d.site_mut(site))?;
        pg.retired = Some(RetiredPostgres {
            mode: pg.mode,
            major: pg.major,
            since: iso(now_ms()),
        });
        pg.mode = to;
        d.site_mut(site).redeploy_needed = true;
        Ok(session)
    }

    pub fn dd_pg_convert_abort(&self, site: &str, id: &str) -> Res<Session> {
        self.data_site(site)?;
        let mut d = self.dt();
        let c = d
            .converts
            .iter_mut()
            .find(|c| c.id == id && c.site == site)
            .ok_or_else(|| not_found("conversion"))?;
        if c.state.is_terminal() {
            return Err(conflict("the conversion is already over"));
        }
        c.state = SessionState::RolledBack;
        Ok(Self::convert_session(c))
    }

    pub fn dd_pg_retired_delete(&self, site: &str) -> Res<JobAccepted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let pg = pg_mut(d.site_mut(site))?;
        if pg.retired.take().is_none() {
            return Err(conflict("there is no retired database to delete"));
        }
        Ok(d.accepted("retired-delete", Some(site), false))
    }

    pub fn dd_orphan_purge(&self, site: &str) -> Res<()> {
        self.require_data()?;
        let mut d = self.dt();
        let before = d.orphans.len();
        d.orphans.retain(|o| o.site != site);
        if d.orphans.len() == before {
            return Err(not_found("orphan"));
        }
        Ok(())
    }

    // ---- site level ----

    pub fn dd_site(&self, site: &str) -> Res<SiteDataView> {
        self.data_site(site)?;
        let mut d = self.dt();
        // An open conversion moves one step each time the site is read, like a node working in the background.
        for c in d
            .converts
            .iter_mut()
            .filter(|c| c.site == site && c.polls_left > 0 && !c.state.is_terminal())
        {
            c.polls_left -= 1;
            c.state = match c.polls_left {
                2 => SessionState::Dumping,
                1 => SessionState::Restoring,
                _ => SessionState::AwaitingCutover,
            };
        }
        let conversion = d
            .converts
            .iter()
            .rev()
            .find(|c| c.site == site && !c.state.is_terminal())
            .map(Self::convert_session);
        let mut view = d.site_mut(site).clone();
        view.conversion = conversion;
        view.capabilities = cite_edge::status::CAPABILITIES
            .iter()
            .filter(|c| c.starts_with("data-"))
            .map(|c| c.to_string())
            .collect();
        Ok(view)
    }

    pub fn dd_pg_enable(&self, site: &str, req: &PgEnableReq) -> Res<JobAccepted> {
        self.data_site(site)?;
        let now = now_ms();
        let mut d = self.dt();
        let shared = d.shared.clone();
        if req.mode == PgMode::Shared && !shared.enabled {
            return Err(conflict("the node's shared instance is not enabled"));
        }
        let view = d.site_mut(site);
        if let Some(pg) = view.postgres.as_mut() {
            if pg.mode != req.mode {
                return Err(conflict(
                    "converting between dedicated and shared is not offered here",
                ));
            }
            if let Some(m) = req.memory_mb {
                pg.memory_mb = m;
            }
            if let Some(c) = req.max_connections {
                pg.max_connections = c;
            }
        } else {
            let shared_mode = req.mode == PgMode::Shared;
            view.postgres = Some(PgView {
                mode: req.mode,
                major: if shared_mode {
                    shared.major
                } else {
                    req.major.unwrap_or(18)
                },
                memory_mb: if shared_mode {
                    shared.memory_mb
                } else {
                    req.memory_mb.unwrap_or(512)
                },
                max_connections: if shared_mode {
                    shared.max_connections
                } else {
                    req.max_connections.unwrap_or(100)
                },
                databases: vec![database("app", 0, default_users(now))],
                backup: BackupPolicy::default(),
                health: Some("healthy".into()),
                retired: None,
            });
            let spec = preset_spec(cite_edge::datawire::Preset::Generic, &Default::default());
            view.links.extend(
                spec.links
                    .into_iter()
                    .map(|l| link(l.var, l.target, l.source)),
            );
            relink(view);
        }
        view.redeploy_needed = true;
        Ok(d.accepted("pg-enable", Some(site), true))
    }

    pub fn dd_pg_disable(&self, site: &str, _purge: bool) -> Res<JobAccepted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        if view.postgres.take().is_none() {
            return Err(conflict("Postgres is not enabled for this site"));
        }
        view.links
            .retain(|l| !matches!(l.source, LinkSource::Postgres { .. }));
        relink(view);
        view.redeploy_needed = true;
        Ok(d.accepted("pg-disable", Some(site), true))
    }

    pub fn dd_pg_policy(&self, site: &str, policy: &BackupPolicy) -> Res<PgView> {
        self.data_site(site)?;
        let mut d = self.dt();
        if let Some(copy) = &policy.s3
            && !d.targets.iter().any(|t| t.id == copy.target)
        {
            return Err(status_err(400, "unknown backup target"));
        }
        let pg = pg_mut(d.site_mut(site))?;
        pg.backup = policy.clone();
        Ok(pg.clone())
    }

    pub fn dd_db_create(&self, site: &str, req: &DatabaseCreateReq) -> Res<JobAccepted> {
        self.data_site(site)?;
        let now = now_ms();
        let mut d = self.dt();
        let pg = pg_mut(d.site_mut(site))?;
        if pg.databases.iter().any(|db| db.name == req.name) {
            return Err(conflict(format!("database {} already exists", req.name)));
        }
        if pg.databases.len() >= MAX_PG_DATABASES {
            return Err(conflict(format!(
                "a site can have at most {MAX_PG_DATABASES} databases"
            )));
        }
        pg.databases
            .push(database(&req.name, 0, default_users(now)));
        Ok(d.accepted("db-create", Some(site), false))
    }

    pub fn dd_db_delete(&self, site: &str, db: &str, _purge: bool) -> Res<JobAccepted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let pg = pg_mut(d.site_mut(site))?;
        let found = db_mut(pg, db)?;
        let linked: Vec<String> = found
            .users
            .iter()
            .flat_map(|u| u.linked_by.clone())
            .collect();
        if !linked.is_empty() {
            return Err(conflict(format!(
                "database {db} is linked by {}",
                linked.join(", ")
            )));
        }
        pg.databases.retain(|x| x.name != db);
        Ok(d.accepted("db-delete", Some(site), false))
    }

    pub fn dd_user_create(&self, site: &str, db: &str, req: &UserCreateReq) -> Res<JobAccepted> {
        self.data_site(site)?;
        let now = now_ms();
        let mut d = self.dt();
        let found = db_mut(pg_mut(d.site_mut(site))?, db)?;
        if found.users.iter().any(|u| u.name == req.name) {
            return Err(conflict(format!("user {} already exists", req.name)));
        }
        if found.users.len() >= MAX_PG_USERS_PER_DATABASE {
            return Err(conflict(format!(
                "a database can have at most {MAX_PG_USERS_PER_DATABASE} users"
            )));
        }
        let mut created = user(
            &req.name,
            req.level,
            req.connection_limit.unwrap_or(20),
            0,
            now,
        );
        if let Some(ms) = req.statement_timeout_ms {
            created.statement_timeout_ms = ms;
        }
        found.users.push(created);
        Ok(d.accepted("user-create", Some(site), false))
    }

    fn user_of<'a>(view: &'a mut SiteDataView, db: &str, name: &str) -> Res<&'a mut PgUserView> {
        db_mut(pg_mut(view)?, db)?
            .users
            .iter_mut()
            .find(|u| u.name == name)
            .ok_or_else(|| not_found(&format!("user {name}")))
    }

    pub fn dd_user_update(
        &self,
        site: &str,
        db: &str,
        name: &str,
        req: &UserPatchReq,
    ) -> Res<JobAccepted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let u = Self::user_of(d.site_mut(site), db, name)?;
        if let Some(level) = req.level {
            u.level = Some(level);
        }
        if let Some(limit) = req.connection_limit {
            u.connection_limit = limit;
        }
        if let Some(ms) = req.statement_timeout_ms {
            u.statement_timeout_ms = ms;
        }
        if let Some(ms) = req.idle_in_transaction_timeout_ms {
            u.idle_in_transaction_timeout_ms = ms;
        }
        if let Some(disabled) = req.disabled {
            u.disabled = disabled;
        }
        Ok(d.accepted("user-update", Some(site), false))
    }

    pub fn dd_user_rotate(&self, site: &str, db: &str, name: &str) -> Res<JobAccepted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        let u = Self::user_of(view, db, name)?;
        if u.retiring.is_some() {
            return Err(conflict("the previous rotation is still in progress"));
        }
        let previous = u.active.clone();
        u.active = if previous == "a" { "b" } else { "a" }.into();
        u.retiring = Some(previous);
        u.rotated_at = Some(iso(now_ms()));
        let runtime = !u.linked_by.is_empty();
        view.redeploy_needed |= runtime;
        Ok(d.accepted("user-rotate", Some(site), runtime))
    }

    pub fn dd_user_delete(&self, site: &str, db: &str, name: &str) -> Res<JobAccepted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let found = db_mut(pg_mut(d.site_mut(site))?, db)?;
        let target = found
            .users
            .iter()
            .find(|u| u.name == name)
            .ok_or_else(|| not_found(&format!("user {name}")))?;
        if !target.linked_by.is_empty() {
            return Err(conflict(format!(
                "user {name} is linked by {}",
                target.linked_by.join(", ")
            )));
        }
        let owners = found
            .users
            .iter()
            .filter(|u| u.level == Some(PgLevel::Owner))
            .count();
        if target.level == Some(PgLevel::Owner) && owners <= 1 {
            return Err(conflict("the last owner of a database cannot be deleted"));
        }
        found.users.retain(|u| u.name != name);
        Ok(d.accepted("user-delete", Some(site), false))
    }

    pub fn dd_external_put(
        &self,
        site: &str,
        name: &str,
        req: &ExternalPutReq,
    ) -> Res<ExternalView> {
        self.data_site(site)?;
        let rest = req
            .url
            .split_once("://")
            .map(|(_, r)| r)
            .ok_or_else(|| status_err(400, "not a postgres URL"))?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().unwrap_or(5432)),
            None => (host_port, 5432),
        };
        let query = path.split_once('?');
        let mut d = self.dt();
        let view = d.site_mut(site);
        let slot = view.external.iter().position(|e| e.name == name);
        if slot.is_none() && view.external.len() >= MAX_EXTERNAL_POSTGRES {
            return Err(conflict(format!(
                "a site can have at most {MAX_EXTERNAL_POSTGRES} external databases"
            )));
        }
        let forward = 15432 + slot.unwrap_or(view.external.len()) as u16;
        let ext = ExternalView {
            name: name.into(),
            host: host.into(),
            port,
            database: path.split(['?', '#']).next().unwrap_or("").into(),
            sslmode: query.and_then(|(_, q)| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("sslmode=").map(str::to_string))
            }),
            forward_port: Some(forward),
            warnings: Vec::new(),
        };
        match slot {
            Some(i) => view.external[i] = ext.clone(),
            None => view.external.push(ext.clone()),
        }
        Ok(ext)
    }

    pub fn dd_external_delete(&self, site: &str, name: &str) -> Res<()> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        if view
            .links
            .iter()
            .any(|l| matches!(&l.source, LinkSource::External { name: n, .. } if n == name))
        {
            return Err(conflict(format!(
                "{name} is still linked; remove its links first"
            )));
        }
        let before = view.external.len();
        view.external.retain(|e| e.name != name);
        if view.external.len() == before {
            return Err(not_found("external database"));
        }
        Ok(())
    }

    pub fn dd_s3_put(&self, site: &str, name: &str, req: &S3PutReq) -> Res<S3View> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        let slot = view.s3.iter().position(|s| s.name == name);
        let had_keys = slot.is_some_and(|i| view.s3[i].has_keys);
        if slot.is_none() && view.s3.len() >= MAX_S3_ATTACHMENTS {
            return Err(conflict(format!(
                "a site can have at most {MAX_S3_ATTACHMENTS} S3 attachments"
            )));
        }
        let has_keys = req.access_key_id.is_some() && req.secret_access_key.is_some();
        if !had_keys && !has_keys {
            return Err(status_err(400, "a new attachment needs both keys"));
        }
        let att = S3View {
            name: name.into(),
            endpoint: req.endpoint.clone(),
            bucket: req.bucket.clone(),
            region: req.region.clone(),
            path_style: req.path_style,
            has_keys: true,
            linked_by: slot
                .map(|i| view.s3[i].linked_by.clone())
                .unwrap_or_default(),
        };
        match slot {
            Some(i) => view.s3[i] = att.clone(),
            None => view.s3.push(att.clone()),
        }
        Ok(att)
    }

    pub fn dd_s3_delete(&self, site: &str, name: &str) -> Res<()> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        let found = view
            .s3
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| not_found("S3 attachment"))?;
        if !found.linked_by.is_empty() {
            return Err(conflict(format!(
                "{name} is linked by {}",
                found.linked_by.join(", ")
            )));
        }
        view.s3.retain(|s| s.name != name);
        Ok(())
    }

    pub fn dd_secret_create(&self, site: &str, req: &SecretCreateReq) -> Res<SecretView> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        if view.secrets.iter().any(|s| s.name == req.name) {
            return Err(conflict(format!("secret {} already exists", req.name)));
        }
        if view.secrets.len() >= MAX_GENERATED_SECRETS {
            return Err(conflict(format!(
                "a site can have at most {MAX_GENERATED_SECRETS} generated secrets"
            )));
        }
        let secret = SecretView {
            name: req.name.clone(),
            bytes: req.bytes.unwrap_or(32),
            encoding: req.encoding.unwrap_or_default(),
            rotated_at: iso(now_ms()),
            linked_by: Vec::new(),
            redeploy_needed: false,
        };
        view.secrets.push(secret.clone());
        Ok(secret)
    }

    pub fn dd_secret_rotate(&self, site: &str, name: &str) -> Res<SecretView> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        let secret = view
            .secrets
            .iter_mut()
            .find(|s| s.name == name)
            .ok_or_else(|| not_found("secret"))?;
        secret.rotated_at = iso(now_ms());
        let mut answer = secret.clone();
        answer.redeploy_needed = !answer.linked_by.is_empty();
        view.redeploy_needed |= answer.redeploy_needed;
        Ok(answer)
    }

    pub fn dd_secret_delete(&self, site: &str, name: &str) -> Res<()> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        let found = view
            .secrets
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| not_found("secret"))?;
        if !found.linked_by.is_empty() {
            return Err(conflict(format!(
                "{name} is linked by {}",
                found.linked_by.join(", ")
            )));
        }
        view.secrets.retain(|s| s.name != name);
        Ok(())
    }

    pub fn dd_link_delete(&self, site: &str, target: LinkTarget, var: &str) -> Res<()> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        let before = view.links.len();
        view.links.retain(|l| !(l.var == var && l.target == target));
        if view.links.len() == before {
            return Err(not_found("link"));
        }
        relink(view);
        view.redeploy_needed = true;
        Ok(())
    }

    // Like the node: a variable another link owns is a conflict listed back, nothing is stored then.
    pub fn dd_links_add(&self, site: &str, req: &LinksReq) -> Res<LinksOutcome> {
        self.data_site(site)?;
        let mut d = self.dt();
        let view = d.site_mut(site);
        let mut conflicts = Vec::new();
        let mut added = Vec::new();
        for want in &req.links {
            for target in want.target.targets() {
                match view
                    .links
                    .iter()
                    .find(|l| l.var == want.var && l.target == *target)
                {
                    Some(e) if e.source == want.source => {}
                    Some(_) => conflicts.push(LinkConflict {
                        var: want.var.clone(),
                        target: *target,
                        set_by: ConflictSetBy::Link,
                    }),
                    None => added.push(link(&want.var, *target, want.source.clone())),
                }
            }
        }
        if !conflicts.is_empty() {
            return Ok(LinksOutcome::Conflicts(conflicts));
        }
        view.links.extend(added);
        relink(view);
        view.redeploy_needed = true;
        Ok(LinksOutcome::Applied(view.links.clone()))
    }

    pub fn dd_links_preset(
        &self,
        site: &str,
        req: &PresetRequest,
    ) -> Res<LinksOutcome<PresetResponse>> {
        self.data_site(site)?;
        let now = now_ms();
        let opts = crate::ui::dataview::PresetOpts {
            database: req.database.clone(),
            runtime_user: req.runtime_user.clone(),
            migrate_user: req.migrate_user.clone(),
            auth_database: req
                .auth_database
                .clone()
                .unwrap_or_else(|| "auth".to_string()),
        };
        let spec = preset_spec(req.preset, &opts);
        let mut d = self.dt();
        let view = d.site_mut(site);
        // Nothing is stored while another link owns a variable the preset needs; the node lists them all.
        let in_the_way: Vec<LinkConflict> = spec
            .links
            .iter()
            .filter(|planned| {
                view.links.iter().any(|l| {
                    l.var == planned.var && l.target == planned.target && l.source != planned.source
                })
            })
            .map(|planned| LinkConflict {
                var: planned.var.to_string(),
                target: planned.target,
                set_by: ConflictSetBy::Link,
            })
            .collect();
        if !in_the_way.is_empty() {
            return Ok(LinksOutcome::Conflicts(in_the_way));
        }
        let mut created_users = Vec::new();
        let mut created_secrets = Vec::new();
        {
            let pg = pg_mut(view)?;
            for (db, user_name, level) in &spec.users {
                if !pg.databases.iter().any(|x| x.name == *db) {
                    if pg.databases.len() >= MAX_PG_DATABASES {
                        return Err(conflict(format!(
                            "a site can have at most {MAX_PG_DATABASES} databases"
                        )));
                    }
                    pg.databases.push(database(db, 0, Vec::new()));
                }
                let found = db_mut(pg, db)?;
                if !found.users.iter().any(|u| u.name == *user_name) {
                    found.users.push(user(user_name, *level, 20, 0, now));
                    created_users.push(format!("{db}/{user_name}"));
                }
            }
        }
        for name in &spec.secrets {
            if !view.secrets.iter().any(|s| s.name == *name) {
                view.secrets.push(SecretView {
                    name: (*name).into(),
                    bytes: 32,
                    encoding: SecretEncoding::Base64url,
                    rotated_at: iso(now),
                    linked_by: Vec::new(),
                    redeploy_needed: false,
                });
                created_secrets.push((*name).to_string());
            }
        }
        for planned in spec.links {
            let existing = view
                .links
                .iter()
                .position(|l| l.var == planned.var && l.target == planned.target);
            match existing {
                Some(_) => {}
                None => view
                    .links
                    .push(link(planned.var, planned.target, planned.source)),
            }
        }
        relink(view);
        view.redeploy_needed = true;
        let links = view.links.clone();
        Ok(LinksOutcome::Applied(PresetResponse {
            links,
            created_users,
            created_secrets,
            job_id: Some(d.new_job("preset", Some(site))),
        }))
    }

    // ---- backups ----

    pub fn dd_backups(&self, site: &str, database: Option<&str>) -> Res<Vec<BackupRecord>> {
        self.data_site(site)?;
        let d = self.dt();
        let mut rows: Vec<BackupRecord> = d
            .backups
            .iter()
            .filter(|(s, r)| s == site && database.is_none_or(|db| r.database == db))
            .map(|(_, r)| r.clone())
            .collect();
        rows.sort_by(|a, b| (&b.created_at, b.version).cmp(&(&a.created_at, a.version)));
        Ok(rows)
    }

    fn next_version(d: &DemoData, site: &str, db: &str) -> u32 {
        d.backups
            .iter()
            .filter(|(s, r)| s == site && r.database == db)
            .map(|(_, r)| r.version)
            .max()
            .unwrap_or(0)
            + 1
    }

    fn take_backup(
        d: &mut DemoData,
        site: &str,
        db: &str,
        trigger: BackupTrigger,
        label: Option<String>,
        push_s3: bool,
    ) -> Res<BackupRecord> {
        let size_mib = {
            let view = d.site_mut(site);
            match db.strip_prefix("pg:") {
                Some(name) => {
                    let pg = pg_mut(view)?;
                    db_mut(pg, name)?.size_bytes.unwrap_or(0) / MIB / 2
                }
                None => {
                    let name = db.strip_prefix("ext:").unwrap_or(db);
                    if !view.external.iter().any(|e| e.name == name) {
                        return Err(not_found(&format!("database {db}")));
                    }
                    10
                }
            }
        };
        let target = d
            .site_mut(site)
            .postgres
            .as_ref()
            .and_then(|p| p.backup.s3.as_ref().map(|c| c.target.clone()));
        let n = d.bump();
        let version = Self::next_version(d, site, db);
        let mut rec = backup(n, db, version, now_ms(), trigger, size_mib.max(1));
        rec.label = label;
        if push_s3 {
            let target =
                target.ok_or_else(|| conflict("the site's backup policy has no S3 target"))?;
            rec.s3 = Some(s3_copy(&rec, &target));
        }
        d.backups.push((site.to_string(), rec.clone()));
        Ok(rec)
    }

    pub fn dd_backup_create(&self, site: &str, req: &BackupCreateReq) -> Res<BackupCreated> {
        self.data_site(site)?;
        let mut d = self.dt();
        let rec = Self::take_backup(
            &mut d,
            site,
            &req.database,
            BackupTrigger::Manual,
            req.label.clone().filter(|l| !l.is_empty()),
            req.push_s3,
        )?;
        let job = d.new_job("backup", Some(site));
        Ok(BackupCreated {
            job_id: job,
            backup_id: rec.id,
        })
    }

    fn record_mut<'a>(d: &'a mut DemoData, site: &str, id: &str) -> Res<&'a mut BackupRecord> {
        d.backups
            .iter_mut()
            .find(|(s, r)| s == site && r.id == id)
            .map(|(_, r)| r)
            .ok_or_else(|| not_found("backup"))
    }

    pub fn dd_backup_patch(&self, site: &str, id: &str, req: &BackupPatchReq) -> Res<BackupRecord> {
        self.data_site(site)?;
        let mut d = self.dt();
        let rec = Self::record_mut(&mut d, site, id)?;
        if let Some(label) = &req.label {
            rec.label = label.clone().filter(|l| !l.is_empty());
        }
        if let Some(pinned) = req.pinned {
            rec.pinned = pinned;
        }
        Ok(rec.clone())
    }

    pub fn dd_backup_delete(&self, site: &str, id: &str, from: DeleteFrom) -> Res<()> {
        self.data_site(site)?;
        let mut d = self.dt();
        let rec = Self::record_mut(&mut d, site, id)?;
        if rec.pinned {
            return Err(conflict(
                "a pinned version cannot be deleted; unpin it first",
            ));
        }
        if matches!(from, DeleteFrom::Local | DeleteFrom::All) {
            rec.local = None;
        }
        if matches!(from, DeleteFrom::S3 | DeleteFrom::All) {
            rec.s3 = None;
        }
        d.backups
            .retain(|(s, r)| !(s == site && r.id == id && r.local.is_none() && r.s3.is_none()));
        Ok(())
    }

    pub fn dd_backup_restore(&self, site: &str, id: &str, req: &RestoreReq) -> Res<RestoreStarted> {
        self.data_site(site)?;
        if req.confirm != site {
            return Err(status_err(400, "confirm must repeat the site id"));
        }
        let mut d = self.dt();
        let db = Self::record_mut(&mut d, site, id)?.database.clone();
        if db.starts_with("ext:") {
            return Err(conflict(
                "a backup of an external database cannot be restored into it",
            ));
        }
        let before = Self::take_backup(&mut d, site, &db, BackupTrigger::PreRestore, None, false)?;
        let job = d.new_job("restore", Some(site));
        Ok(RestoreStarted {
            job_id: job,
            pre_restore_backup_id: before.id,
        })
    }

    pub fn dd_backup_push(&self, site: &str, id: &str, req: &PushReq) -> Res<JobAccepted> {
        self.data_site(site)?;
        let mut d = self.dt();
        let policy_target = d
            .site_mut(site)
            .postgres
            .as_ref()
            .and_then(|p| p.backup.s3.as_ref().map(|c| c.target.clone()));
        let target = req
            .target
            .clone()
            .or(policy_target)
            .ok_or_else(|| conflict("no backup target is chosen"))?;
        let rec = Self::record_mut(&mut d, site, id)?;
        if rec.local.is_none() {
            return Err(conflict("this version has no copy on the node to push"));
        }
        rec.s3 = Some(s3_copy(rec, &target));
        Ok(d.accepted("backup-push", Some(site), false))
    }

    pub fn dd_backup_download(
        &self,
        site: &str,
        rec: &BackupRecord,
        dest: &Path,
    ) -> Res<ExportReport> {
        self.data_site(site)?;
        let mut d = self.dt();
        Self::record_mut(&mut d, site, &rec.id)?;
        write_demo_file(
            dest,
            &format!("demo dump of {} version {}\n", rec.database, rec.version),
        )
    }

    // A simplified GFS plan for the demo: pinned, newest, recent, one a day inside the daily window; the rest goes.
    fn plan(records: &[&BackupRecord], retention: &BackupRetention, now: i64) -> PrunePlanView {
        let mut sorted: Vec<&BackupRecord> = records.to_vec();
        sorted.sort_by(|a, b| (&b.created_at, b.version).cmp(&(&a.created_at, a.version)));
        let mut plan = PrunePlanView::default();
        let mut days: Vec<String> = Vec::new();
        for (i, r) in sorted.iter().enumerate() {
            let age_ms = crate::model::parse_rfc3339_ms(&r.created_at).map_or(0, |t| now - t);
            let day = r.created_at.get(..10).unwrap_or("").to_string();
            let reason = if r.pinned {
                Some("pinned")
            } else if i == 0 {
                Some("newest")
            } else if age_ms < i64::from(retention.keep_all_hours) * HOUR_MS {
                Some("recent")
            } else if r.trigger == BackupTrigger::PreRestore
                && age_ms < i64::from(retention.pre_restore_days) * DAY_MS
            {
                Some("pre_restore")
            } else if !days.contains(&day) && age_ms < i64::from(retention.daily_days) * DAY_MS {
                days.push(day);
                Some("daily")
            } else {
                None
            };
            match reason {
                Some(reason) => plan.keep.push(PruneKeep {
                    id: r.id.clone(),
                    reason: reason.into(),
                }),
                None => plan.delete.push(r.id.clone()),
            }
        }
        plan
    }

    pub fn dd_prune_preview(&self, site: &str) -> Res<Vec<PrunePreview>> {
        self.data_site(site)?;
        let mut d = self.dt();
        let now = now_ms();
        let policy = d
            .site_mut(site)
            .postgres
            .as_ref()
            .map(|p| p.backup.clone())
            .unwrap_or_default();
        let mut databases: Vec<String> = d
            .backups
            .iter()
            .filter(|(s, _)| s == site)
            .map(|(_, r)| r.database.clone())
            .collect();
        databases.sort();
        databases.dedup();
        let previews = databases
            .into_iter()
            .map(|db| {
                let of_db: Vec<&BackupRecord> = d
                    .backups
                    .iter()
                    .filter(|(s, r)| s == site && r.database == db && r.status == BackupStatus::Ok)
                    .map(|(_, r)| r)
                    .collect();
                let local: Vec<&BackupRecord> = of_db
                    .iter()
                    .copied()
                    .filter(|r| r.local.is_some())
                    .collect();
                let s3: Vec<&BackupRecord> =
                    of_db.iter().copied().filter(|r| r.s3.is_some()).collect();
                PrunePreview {
                    database: db.clone(),
                    local: Self::plan(&local, &policy.local, now),
                    s3: policy
                        .s3
                        .as_ref()
                        .map(|c| Self::plan(&s3, &c.retention, now))
                        .unwrap_or_default(),
                }
            })
            .collect();
        Ok(previews)
    }

    pub fn dd_prune(&self, site: &str) -> Res<PruneResult> {
        let previews = self.dd_prune_preview(site)?;
        let mut d = self.dt();
        let mut deleted = 0;
        for preview in previews {
            for id in &preview.local.delete {
                if let Some((_, r)) = d.backups.iter_mut().find(|(s, r)| s == site && r.id == *id) {
                    r.local = None;
                    deleted += 1;
                }
            }
            for id in &preview.s3.delete {
                if let Some((_, r)) = d.backups.iter_mut().find(|(s, r)| s == site && r.id == *id) {
                    r.s3 = None;
                    deleted += 1;
                }
            }
        }
        d.backups
            .retain(|(_, r)| r.status != BackupStatus::Ok || r.local.is_some() || r.s3.is_some());
        Ok(PruneResult { deleted })
    }
}

// Demo nodes write a small generated file with the same no-overwrite rule the live download follows.
fn write_demo_file(dest: &Path, body: &str) -> Res<ExportReport> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .and_then(|mut f| f.write_all(body.as_bytes()))
        .map_err(|e| ClientError::Config(format!("cannot write backup: {e}")))?;
    Ok(ExportReport {
        path: dest.to_path_buf(),
        bytes: body.len() as u64,
        content_type: None,
        suggested_name: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::demo_nodes;

    fn node() -> std::sync::Arc<DemoNode> {
        demo_nodes().remove(0).1
    }

    #[test]
    fn the_docs_site_has_databases_links_and_versions() {
        let n = node();
        let view = n.dd_site("docs").expect("view");
        let pg = view.postgres.expect("postgres");
        assert_eq!(pg.databases.len(), 2);
        assert_eq!(pg.major, 18);
        assert!(
            view.links
                .iter()
                .any(|l| l.var == "DATABASE_URL" && l.target == LinkTarget::Runtime)
        );
        let linked = &pg.databases[0].users[0].linked_by;
        assert_eq!(linked, &vec!["DATABASE_URL".to_string()]);
        assert!(view.links.iter().any(|l| l.shadows_doppler));
        let backups = n.dd_backups("docs", Some("pg:app")).expect("backups");
        assert!(backups.len() >= 5);
        assert!(
            backups
                .windows(2)
                .all(|w| w[0].created_at >= w[1].created_at)
        );
        assert!(backups.iter().any(|b| b.pinned));
        assert!(backups.iter().any(|b| b.status == BackupStatus::Failed));
        assert!(backups.iter().any(|b| b.s3.is_some()));
    }

    #[test]
    fn the_second_node_offers_no_data_services() {
        let nodes = demo_nodes();
        let old = &nodes[1].1;
        assert_eq!(old.dd_node().expect_err("old").status_code(), Some(404));
        assert_eq!(
            old.dd_site("docs").expect_err("old").status_code(),
            Some(404)
        );
    }

    #[test]
    fn a_job_runs_for_two_reads_then_finishes() {
        let n = node();
        let created = n
            .dd_backup_create(
                "docs",
                &BackupCreateReq {
                    database: "pg:app".into(),
                    label: Some("manual".into()),
                    push_s3: false,
                },
            )
            .expect("create");
        assert_eq!(n.dd_job(&created.job_id).unwrap().state, JobState::Running);
        assert_eq!(n.dd_job(&created.job_id).unwrap().state, JobState::Running);
        assert_eq!(n.dd_job(&created.job_id).unwrap().state, JobState::Ok);
        let rows = n.dd_backups("docs", Some("pg:app")).unwrap();
        assert_eq!(rows[0].id, created.backup_id);
        assert_eq!(rows[0].version, 7);
        assert_eq!(rows[0].label.as_deref(), Some("manual"));
    }

    #[test]
    fn a_pinned_version_is_not_deleted_and_an_external_one_is_not_restored() {
        let n = node();
        let rows = n.dd_backups("docs", Some("pg:app")).unwrap();
        let pinned = rows.iter().find(|r| r.pinned).expect("pinned");
        let err = n
            .dd_backup_delete("docs", &pinned.id, DeleteFrom::All)
            .expect_err("pinned");
        assert_eq!(err.status_code(), Some(409));
        let ext = n.dd_backups("api", Some("ext:billing")).unwrap();
        let err = n
            .dd_backup_restore(
                "api",
                &ext[0].id,
                &RestoreReq {
                    confirm: "api".into(),
                    database: None,
                },
            )
            .expect_err("external");
        assert_eq!(err.status_code(), Some(409));
        let unpinned = n
            .dd_backup_patch(
                "docs",
                &pinned.id,
                &BackupPatchReq {
                    label: None,
                    pinned: Some(false),
                },
            )
            .unwrap();
        assert!(!unpinned.pinned);
        n.dd_backup_delete("docs", &pinned.id, DeleteFrom::All)
            .expect("delete");
        assert!(
            n.dd_backups("docs", None)
                .unwrap()
                .iter()
                .all(|r| r.id != pinned.id)
        );
    }

    #[test]
    fn a_restore_takes_a_before_restore_version_first() {
        let n = node();
        let rows = n.dd_backups("docs", Some("pg:app")).unwrap();
        let target = rows.iter().find(|r| r.status == BackupStatus::Ok).unwrap();
        let wrong = n.dd_backup_restore(
            "docs",
            &target.id,
            &RestoreReq {
                confirm: "shop".into(),
                database: None,
            },
        );
        assert_eq!(wrong.expect_err("confirm").status_code(), Some(400));
        let started = n
            .dd_backup_restore(
                "docs",
                &target.id,
                &RestoreReq {
                    confirm: "docs".into(),
                    database: None,
                },
            )
            .expect("restore");
        let after = n.dd_backups("docs", Some("pg:app")).unwrap();
        let before = after
            .iter()
            .find(|r| r.id == started.pre_restore_backup_id)
            .expect("pre-restore");
        assert_eq!(before.trigger, BackupTrigger::PreRestore);
    }

    #[test]
    fn enabling_a_preset_creates_what_it_needs_and_refuses_a_foreign_link() {
        let n = node();
        n.dd_pg_disable("shop", false).expect("disable");
        assert!(n.dd_site("shop").unwrap().postgres.is_none());
        let enable = PgEnableReq {
            mode: PgMode::Dedicated,
            major: Some(17),
            memory_mb: None,
            max_connections: None,
            preset: Some("generic".into()),
        };
        let job = n.dd_pg_enable("shop", &enable).expect("enable");
        assert!(job.redeploy_needed);
        let view = n.dd_site("shop").unwrap();
        assert_eq!(view.postgres.as_ref().unwrap().major, 17);
        assert!(view.links.iter().any(|l| l.var == "PGPASSWORD"));
        let req = crate::ui::dataview::preset_request(
            cite_edge::datawire::Preset::Authjs,
            &Default::default(),
            false,
        );
        let LinksOutcome::Applied(out) = n.dd_links_preset("shop", &req).expect("authjs") else {
            panic!("authjs conflicted");
        };
        assert_eq!(out.created_secrets, ["auth-secret"]);
        assert!(out.created_users.contains(&"auth/migrate".to_string()));
        let blocked = crate::ui::dataview::preset_request(
            cite_edge::datawire::Preset::Prisma,
            &crate::ui::dataview::PresetOpts {
                runtime_user: "migrate".into(),
                migrate_user: "app".into(),
                ..Default::default()
            },
            false,
        );
        // The node lists the variable another link owns and stores nothing.
        let LinksOutcome::Conflicts(found) = n.dd_links_preset("shop", &blocked).expect("answer")
        else {
            panic!("expected conflicts");
        };
        assert!(
            found
                .iter()
                .any(|c| c.var == "DATABASE_URL" && c.set_by == ConflictSetBy::Link)
        );
    }

    #[test]
    fn a_user_that_a_link_uses_cannot_be_deleted_and_rotation_asks_for_a_redeploy() {
        let n = node();
        let err = n.dd_user_delete("docs", "app", "app").expect_err("linked");
        assert_eq!(err.status_code(), Some(409));
        let rotated = n.dd_user_rotate("docs", "app", "app").expect("rotate");
        assert!(rotated.redeploy_needed);
        assert_eq!(
            n.dd_user_rotate("docs", "app", "app")
                .expect_err("again")
                .status_code(),
            Some(409)
        );
        assert!(n.dd_site("docs").unwrap().redeploy_needed);
        n.dd_user_create(
            "docs",
            "app",
            &UserCreateReq {
                name: "reports".into(),
                level: PgLevel::Readonly,
                connection_limit: Some(3),
                statement_timeout_ms: None,
                idle_in_transaction_timeout_ms: None,
            },
        )
        .expect("create");
        n.dd_user_delete("docs", "app", "reports").expect("delete");
    }

    #[test]
    fn the_shared_instance_cannot_go_while_a_tenant_remains() {
        let n = node();
        let shared = n.dd_shared().unwrap();
        assert_eq!(shared.tenants.len(), 1);
        assert_eq!(shared.tenants[0].site, "shop");
        let err = n.dd_shared_delete(false, false).expect_err("tenants");
        assert_eq!(err.status_code(), Some(409));
        assert!(n.dd_node().unwrap().shared.is_some());
        n.dd_pg_disable("shop", false).unwrap();
        n.dd_shared_delete(false, false).expect("delete");
        assert!(n.dd_node().unwrap().shared.is_none());
    }

    #[test]
    fn targets_can_be_tested_and_the_one_a_policy_uses_stays() {
        let n = node();
        let err = n.dd_target_delete(TARGET_OFFSITE).expect_err("in use");
        assert_eq!(err.status_code(), Some(409));
        let req = TargetReq {
            name: "second".into(),
            endpoint: "https://unreachable.example.com".into(),
            bucket: "b".into(),
            region: "r".into(),
            path_style: false,
            prefix: None,
            encrypt: Some(true),
            access_key_id: Some("id".into()),
            secret_access_key: Some("secret".into()),
        };
        let created = n.dd_target_create(&req).expect("create");
        assert!(!n.dd_target_test(&created.id).unwrap().ok);
        assert!(n.dd_target_test(TARGET_OFFSITE).unwrap().ok);
        n.dd_target_delete(&created.id).expect("delete");
    }

    #[test]
    fn prune_never_deletes_pinned_or_the_newest_version() {
        let n = node();
        let previews = n.dd_prune_preview("docs").unwrap();
        let app = previews
            .iter()
            .find(|p| p.database == "pg:app")
            .expect("app");
        let rows = n.dd_backups("docs", Some("pg:app")).unwrap();
        let pinned = rows.iter().find(|r| r.pinned).unwrap();
        assert!(!app.local.delete.contains(&pinned.id));
        assert!(
            app.local
                .keep
                .iter()
                .any(|k| k.id == pinned.id && k.reason == "pinned")
        );
        assert!(app.local.keep.iter().any(|k| k.reason == "newest"));
        // The 20 day old scheduled version is outside every window on both tiers.
        let old = rows.iter().find(|r| r.version == 2).unwrap();
        assert!(app.local.delete.contains(&old.id) && app.s3.delete.contains(&old.id));
        let result = n.dd_prune("docs").unwrap();
        assert_eq!(result.deleted, 2);
        let after = n.dd_backups("docs", Some("pg:app")).unwrap();
        assert!(after.iter().all(|r| r.id != old.id));
        assert!(after.iter().any(|r| r.id == pinned.id));
        assert_eq!(after.len(), rows.len() - 1);
    }

    #[test]
    fn a_conversion_runs_to_a_cutover_and_leaves_a_retired_database_to_delete() {
        let n = node();
        let to = |mode| ConvertReq {
            to: mode,
            freeze: Freeze::Maintenance,
        };
        // shop is a shared tenant: converting to shared is refused, to dedicated runs.
        assert_eq!(
            n.dd_pg_convert("shop", &to(PgMode::Shared))
                .expect_err("same")
                .status_code(),
            Some(409)
        );
        let id = n
            .dd_pg_convert("shop", &to(PgMode::Dedicated))
            .expect("start")
            .session;
        assert_eq!(
            n.dd_pg_convert("shop", &to(PgMode::Dedicated))
                .expect_err("twice")
                .status_code(),
            Some(409)
        );
        assert_eq!(
            n.dd_pg_convert_cutover("shop", &id)
                .expect_err("early")
                .status_code(),
            Some(409)
        );
        // The site's own data view reports the open conversion, one step per read.
        let read = || {
            n.dd_site("shop")
                .unwrap()
                .conversion
                .expect("open conversion")
        };
        let states: Vec<SessionState> = (0..3).map(|_| read().state).collect();
        assert_eq!(
            states,
            [
                SessionState::Dumping,
                SessionState::Restoring,
                SessionState::AwaitingCutover
            ]
        );
        let ready = read();
        assert_eq!(ready.id, id);
        assert!(ready.counts.is_some() && ready.peer_counts.is_some());
        let done = n.dd_pg_convert_cutover("shop", &id).expect("cutover");
        assert_eq!(done.state, SessionState::Done);
        let pg = n.dd_site("shop").unwrap().postgres.expect("postgres");
        assert_eq!(pg.mode, PgMode::Dedicated);
        assert_eq!(pg.retired.expect("retired").mode, PgMode::Shared);
        n.dd_pg_retired_delete("shop").expect("delete retired");
        assert_eq!(
            n.dd_pg_retired_delete("shop")
                .expect_err("gone")
                .status_code(),
            Some(409)
        );
        assert!(
            n.dd_site("shop")
                .unwrap()
                .postgres
                .unwrap()
                .retired
                .is_none()
        );
    }

    #[test]
    fn an_aborted_conversion_changes_nothing() {
        let n = node();
        let req = ConvertReq {
            to: PgMode::Shared,
            freeze: Freeze::ReadOnly,
        };
        let id = n.dd_pg_convert("docs", &req).expect("start").session;
        let aborted = n.dd_pg_convert_abort("docs", &id).expect("abort");
        assert_eq!(aborted.state, SessionState::RolledBack);
        assert_eq!(
            n.dd_pg_convert_abort("docs", &id)
                .expect_err("over")
                .status_code(),
            Some(409)
        );
        let pg = n.dd_site("docs").unwrap().postgres.unwrap();
        assert_eq!(pg.mode, PgMode::Dedicated);
        assert!(pg.retired.is_none());
    }

    #[test]
    fn downloads_write_a_new_file_and_never_overwrite() {
        let n = node();
        let dir = tempfile::tempdir().expect("dir");
        let rows = n.dd_backups("docs", Some("pg:app")).unwrap();
        let dest = dir.path().join("docs-app-v5.dump");
        let report = n
            .dd_backup_download("docs", &rows[1], &dest)
            .expect("download");
        assert!(report.bytes > 0 && dest.exists());
        assert!(n.dd_backup_download("docs", &rows[1], &dest).is_err());
    }
}
