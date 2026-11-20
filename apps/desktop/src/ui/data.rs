// The site Data tab: Postgres mode, databases and their users, env links and presets, generated secrets, external Postgres and
// S3 attachments, backups with their retention policy, and the progress of the connector jobs these start. Passwords, external
// URLs and S3 keys are write-only: nothing here ever shows one, and the inputs that take them are masked and emptied after use.

use std::future::Future;

use cite_client::{ClientError, LinksOutcome};
use cite_edge::datamodel::{LinkTarget, PgLevel, PgMode, SecretEncoding};
use cite_edge::datawire::{
    BackupCreateReq, BackupPatchReq, BackupRecord, DatabaseCreateReq, DeleteFrom, ExternalView,
    JobAccepted, JobView, LinkConflict, LinkTargetSel, PgDatabaseView, PgView, Preset,
    PrunePreview, PushReq, RestoreReq, S3View, SecretView, SiteDataView, TargetView,
};
use gpui::{AnyElement, Context, Div, ElementId, Entity, div, prelude::*, px};

use crate::api::NodeHandle;
use crate::app::{Confirm, Console, new_input};
use crate::bots::downloads_dir;
use crate::demo::now_ms;
use crate::model::{fmt_bytes, parse_rfc3339_ms, rel_time};
use crate::scope::{Sequence, foreign_notice};
use crate::siteops::has_cap;
use crate::theme::{Tone, c, font};
use crate::ui::chart::wide;
use crate::ui::datahandle::run_backup_download;
use crate::ui::dataview::{
    self as dv, JobTrack, JobUpdate, LinkDraft, LinkKind, PgChoice, PolicyDraft, PresetOpts, S3Form,
};
use crate::ui::detail::Data;
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, checkbox, dot, empty_state, field, form_grid, id, mono,
    notice, pill, seg_item, seg_row, skeleton, strong, table, text_dim, tip,
};

// What the page learned from the node about one site's data.
pub struct Loaded {
    pub view: SiteDataView,
    pub backups: Vec<BackupRecord>,
    pub targets: Vec<TargetView>,
    pub caps: Vec<String>,
}

pub enum DataLoad {
    Idle,
    Loading,
    // The node offers no data service, so the tab says so and offers nothing.
    Absent,
    Failed(String),
    Ready(Box<Loaded>),
}

impl DataLoad {
    pub fn ready(&self) -> Option<&Loaded> {
        match self {
            DataLoad::Ready(l) => Some(l),
            _ => None,
        }
    }
}

// What an accepted change says, and the job it started when it started one.
pub struct Done {
    pub message: String,
    pub job: Option<String>,
}

impl Done {
    pub fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            job: None,
        }
    }

    pub fn job(accepted: &JobAccepted, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            job: Some(accepted.job_id.clone()).filter(|j| !j.is_empty()),
        }
    }
}

pub struct SiteDataState {
    pub for_site: (String, String),
    pub load: DataLoad,
    pub seq: Sequence,
    pub busy: bool,
    pub error: Option<String>,
    // Connector jobs being followed, for this page and for the Databases page.
    pub jobs: Vec<JobTrack>,
    pub pick: PgChoice,
    pub major: u8,
    pub memory_in: Entity<TextInput>,
    pub conns_in: Entity<TextInput>,
    pub db_in: Entity<TextInput>,
    pub user_in: Entity<TextInput>,
    pub user_limit_in: Entity<TextInput>,
    // The database whose add-user form is open.
    pub user_db: Option<String>,
    pub user_level: PgLevel,
    pub limit_in: Entity<TextInput>,
    // (database, user) whose connection limit is being edited.
    pub limit_edit: Option<(String, String)>,
    pub preset: Option<Preset>,
    pub override_manual: bool,
    // The add-link form: what to link, its picks (an empty pick means the first choice), the variable and the target.
    pub link_open: bool,
    pub link_kind: LinkKind,
    pub link_db: String,
    pub link_user: String,
    pub link_name: String,
    pub link_field: String,
    pub link_var_in: Entity<TextInput>,
    pub link_target: LinkTargetSel,
    pub link_override: bool,
    // The variables the node or the pre-check found in the way of the last attempt.
    pub link_conflicts: Vec<LinkConflict>,
    pub secret_in: Entity<TextInput>,
    pub secret_bytes_in: Entity<TextInput>,
    pub secret_enc: SecretEncoding,
    pub ext_name_in: Entity<TextInput>,
    pub ext_url_in: Entity<TextInput>,
    pub s3_name_in: Entity<TextInput>,
    pub s3_endpoint_in: Entity<TextInput>,
    pub s3_bucket_in: Entity<TextInput>,
    pub s3_region_in: Entity<TextInput>,
    pub s3_key_in: Entity<TextInput>,
    pub s3_secret_in: Entity<TextInput>,
    pub s3_path_style: bool,
    // The attachment being edited: its keys may stay blank to keep the stored ones.
    pub s3_editing: Option<String>,
    pub backup_db: Option<String>,
    pub backup_sel: Option<String>,
    pub backup_label_in: Entity<TextInput>,
    pub backup_push: bool,
    pub label_edit: Option<String>,
    pub label_in: Entity<TextInput>,
    pub policy_open: bool,
    pub policy: Option<PolicyDraft>,
    pub minute_in: Entity<TextInput>,
    pub local_in: Vec<Entity<TextInput>>,
    pub s3_ret_in: Vec<Entity<TextInput>>,
    pub prune: Option<Vec<PrunePreview>>,
}

impl SiteDataState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        let local_in = (0..5)
            .map(|_| new_input(cx, "0", |i| i.mono()))
            .collect::<Vec<_>>();
        let s3_ret_in = (0..5)
            .map(|_| new_input(cx, "0", |i| i.mono()))
            .collect::<Vec<_>>();
        Self {
            for_site: (String::new(), String::new()),
            load: DataLoad::Idle,
            seq: Sequence::default(),
            busy: false,
            error: None,
            jobs: Vec::new(),
            pick: PgChoice::Dedicated,
            major: dv::DEFAULT_MAJOR,
            memory_in: new_input(cx, "512 (default)", |i| i.mono()),
            conns_in: new_input(cx, "100 (default)", |i| i.mono()),
            db_in: new_input(cx, "auth", |i| i.mono()),
            user_in: new_input(cx, "reports", |i| i.mono()),
            user_limit_in: new_input(cx, "20 (default)", |i| i.mono()),
            user_db: None,
            user_level: PgLevel::Readwrite,
            limit_in: new_input(cx, "20", |i| i.mono()),
            limit_edit: None,
            preset: None,
            override_manual: false,
            link_open: false,
            link_kind: LinkKind::Postgres,
            link_db: String::new(),
            link_user: String::new(),
            link_name: String::new(),
            link_field: String::new(),
            link_var_in: new_input(cx, "DATABASE_URL (blank suggests one)", |i| i.mono()),
            link_target: LinkTargetSel::Runtime,
            link_override: false,
            link_conflicts: Vec::new(),
            secret_in: new_input(cx, "webhook-key", |i| i.mono()),
            secret_bytes_in: new_input(cx, "32 to 128 (default 32)", |i| i.mono()),
            secret_enc: SecretEncoding::Base64url,
            ext_name_in: new_input(cx, "billing", |i| i.mono()),
            ext_url_in: new_input(cx, "postgres://user:password@host:5432/database", |i| {
                i.masked().mono()
            }),
            s3_name_in: new_input(cx, "assets", |i| i.mono()),
            s3_endpoint_in: new_input(cx, "https://s3.eu-west-1.amazonaws.com", |i| i.mono()),
            s3_bucket_in: new_input(cx, "my-bucket", |i| i.mono()),
            s3_region_in: new_input(cx, "eu-west-1", |i| i.mono()),
            s3_key_in: new_input(cx, "Access key id", |i| i.masked().mono()),
            s3_secret_in: new_input(cx, "Secret access key", |i| i.masked().mono()),
            s3_path_style: false,
            s3_editing: None,
            backup_db: None,
            backup_sel: None,
            backup_label_in: new_input(cx, "Label (optional)", |i| i),
            backup_push: false,
            label_edit: None,
            label_in: new_input(cx, "Label (empty clears it)", |i| i),
            policy_open: false,
            policy: None,
            minute_in: new_input(cx, "17", |i| i.mono()),
            local_in,
            s3_ret_in,
            prune: None,
        }
    }

    fn inputs(&self) -> Vec<Entity<TextInput>> {
        let mut all = vec![
            self.memory_in.clone(),
            self.conns_in.clone(),
            self.db_in.clone(),
            self.user_in.clone(),
            self.user_limit_in.clone(),
            self.limit_in.clone(),
            self.link_var_in.clone(),
            self.secret_in.clone(),
            self.secret_bytes_in.clone(),
            self.ext_name_in.clone(),
            self.ext_url_in.clone(),
            self.s3_name_in.clone(),
            self.s3_endpoint_in.clone(),
            self.s3_bucket_in.clone(),
            self.s3_region_in.clone(),
            self.s3_key_in.clone(),
            self.s3_secret_in.clone(),
            self.backup_label_in.clone(),
            self.label_in.clone(),
            self.minute_in.clone(),
        ];
        all.extend(self.local_in.iter().cloned());
        all.extend(self.s3_ret_in.iter().cloned());
        all
    }
}

pub(crate) fn kv(label: &str, value: impl IntoElement) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(12.))
        .child(
            div()
                .w(px(140.))
                .flex_none()
                .child(text_dim(label.to_string()).text_size(px(font::SM))),
        )
        .child(value)
}

pub(crate) fn note(text: &str) -> Div {
    text_dim(text.to_string()).text_size(px(font::SM))
}

pub(crate) fn cell_text(text: impl Into<String>) -> AnyElement {
    text_dim(text.into())
        .text_size(px(font::SM))
        .into_any_element()
}

pub(crate) fn cell_mono(text: impl Into<String>) -> AnyElement {
    mono(text.into()).into_any_element()
}

pub(crate) fn stack(gap: f32) -> Div {
    div().flex().flex_col().gap(px(gap))
}

pub(crate) fn wrap_row() -> Div {
    div().flex().flex_wrap().items_center().gap(px(8.))
}

// A button that runs `on` when pressed and a muted one while a change is in flight.
pub(crate) fn act(
    busy: bool,
    key: ElementId,
    label: &str,
    kind: BtnKind,
    on: impl Fn(&mut Console, &mut Context<Console>) + 'static,
    cx: &mut Context<Console>,
) -> AnyElement {
    if busy {
        return btn_off(label).into_any_element();
    }
    btn(key, label, kind)
        .on_click(cx.listener(move |this, _, _, cx| {
            on(this, cx);
            cx.notify();
        }))
        .into_any_element()
}

// A button that cannot be pressed, with the reason on hover.
pub(crate) fn blocked(key: ElementId, label: &str, reason: &str) -> AnyElement {
    tip(btn_off(label), key, reason.to_string()).into_any_element()
}

// The dedicated and shared columns of the trade-off table, shown where the choice is made.
pub(crate) fn tradeoff_table(key: &'static str) -> AnyElement {
    let rows: Vec<Vec<AnyElement>> = dv::TRADEOFFS
        .iter()
        .map(|(aspect, dedicated, shared)| {
            vec![
                strong(aspect.to_string())
                    .text_size(px(font::SM))
                    .into_any_element(),
                cell_text(*dedicated),
                cell_text(*shared),
            ]
        })
        .collect();
    let cols = [
        Col::fixed("", 130.),
        Col::flex("Dedicated").min(220.),
        Col::flex("Shared").min(220.),
    ];
    wide(id(key, "tradeoffs"), 640., table(&cols, rows, None)).into_any_element()
}

impl Console {
    pub fn data_reset(&mut self, cx: &mut Context<Self>) {
        for input in self.site_data.inputs() {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        let s = &mut self.site_data;
        s.busy = false;
        s.error = None;
        s.pick = PgChoice::Dedicated;
        s.major = dv::DEFAULT_MAJOR;
        s.user_db = None;
        s.user_level = PgLevel::Readwrite;
        s.limit_edit = None;
        s.preset = None;
        s.override_manual = false;
        s.link_open = false;
        s.link_kind = LinkKind::Postgres;
        s.link_db.clear();
        s.link_user.clear();
        s.link_name.clear();
        s.link_field.clear();
        s.link_target = LinkTargetSel::Runtime;
        s.link_override = false;
        s.link_conflicts.clear();
        s.secret_enc = SecretEncoding::Base64url;
        s.s3_path_style = false;
        s.s3_editing = None;
        s.backup_db = None;
        s.backup_sel = None;
        s.backup_push = false;
        s.label_edit = None;
        s.policy_open = false;
        s.policy = None;
        s.prune = None;
        s.load = DataLoad::Idle;
    }

    // Everything the data services show for the site on screen, read together. A node that offers no data service answers with None.
    pub fn load_site_data(&mut self, node: String, site: String, cx: &mut Context<Self>) {
        let Some(h) = self.handle_named(&node) else {
            return;
        };
        let key = (node, site.clone());
        if self.site_data.for_site != key {
            self.data_reset(cx);
            self.site_data.for_site = key.clone();
        }
        // A reload keeps the last answer on screen until the new one arrives.
        if !matches!(self.site_data.load, DataLoad::Ready(_)) {
            self.site_data.load = DataLoad::Loading;
        }
        let seq = self.site_data.seq.issue();
        self.fetch_scoped(cx, read_site_data(h, site), move |this, res, cx| {
            if this.site_data.for_site != key || !this.site_data.seq.accept(seq) {
                return;
            }
            this.site_data.load = match res {
                Ok(Some(loaded)) => {
                    this.settle_picks(&loaded);
                    DataLoad::Ready(Box::new(loaded))
                }
                Ok(None) => DataLoad::Absent,
                Err(e) => DataLoad::Failed(e.to_string()),
            };
            cx.notify();
        });
    }

    // Keeps the database and version picks pointing at things that still exist.
    fn settle_picks(&mut self, loaded: &Loaded) {
        let keys = dv::backup_databases(&loaded.view);
        let s = &mut self.site_data;
        if s.backup_db.as_ref().is_none_or(|k| !keys.contains(k)) {
            s.backup_db = keys.first().cloned();
        }
        if s.backup_sel
            .as_ref()
            .is_some_and(|id| !loaded.backups.iter().any(|b| b.id == *id))
        {
            s.backup_sel = None;
            s.label_edit = None;
        }
        if s.user_db.as_ref().is_some_and(|db| {
            !loaded
                .view
                .postgres
                .as_ref()
                .is_some_and(|pg| pg.databases.iter().any(|d| d.name == *db))
        }) {
            s.user_db = None;
        }
        s.prune = None;
    }

    pub(crate) fn data_ctx(&self) -> Option<(NodeHandle, String)> {
        if self.detail.site_id.is_empty() {
            return None;
        }
        Some((
            self.handle_named(&self.detail.node)?,
            self.detail.site_id.clone(),
        ))
    }

    fn data_loaded(&self) -> Option<&Loaded> {
        self.site_data.load.ready()
    }

    // Runs one change on the node. The message and the job it started come from `done`; `then` runs only when the
    // node accepted the change for the page still on screen (it clears the typed inputs).
    pub(crate) fn data_run<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        what: &'static str,
        fut: F,
        done: impl FnOnce(&T) -> Done + 'static,
        then: impl FnOnce(&mut Self, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        self.site_data.busy = true;
        self.site_data.error = None;
        let (node, site) = (self.detail.node.clone(), self.detail.site_id.clone());
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            this.site_data.busy = false;
            match res {
                Ok(value) => {
                    let finished = done(&value);
                    if let Some(job) = &finished.job {
                        this.track_job(&node, Some(&site), job, what);
                    }
                    if here {
                        this.say(finished.message, Tone::Ok);
                        then(this, cx);
                        this.load_site_data(node, site, cx);
                    } else {
                        this.say(foreign_notice(what, origin, &finished.message), Tone::Ok);
                    }
                }
                Err(e) => {
                    let message = e.to_string();
                    if here {
                        this.site_data.error = Some(message);
                    } else {
                        this.say(foreign_notice(what, origin, &message), Tone::Bad);
                    }
                }
            }
            cx.notify();
        });
    }

    // ---- jobs ----

    pub(crate) fn track_job(&mut self, node: &str, site: Option<&str>, job_id: &str, what: &str) {
        let tick = self.tick;
        self.site_data
            .jobs
            .push(JobTrack::new(job_id, node, site, what, tick));
    }

    // Runs on the half-second tick: each followed job is read about once a second, never twice at once.
    pub fn data_tick(&mut self, cx: &mut Context<Self>) {
        if self.site_data.jobs.is_empty() || !self.window_active {
            return;
        }
        // Followed by id, because reading a job that is gone can remove entries while this loop runs.
        let due: Vec<String> = dv::jobs_due(&self.site_data.jobs, self.tick)
            .into_iter()
            .map(|index| self.site_data.jobs[index].id.clone())
            .collect();
        for id in due {
            let Some(job) = self.site_data.jobs.iter_mut().find(|j| j.id == id) else {
                continue;
            };
            job.in_flight = true;
            let node = job.node.clone();
            let Some(h) = self.handle_named(&node) else {
                self.on_job_read(
                    id,
                    Err(ClientError::Config(format!("{node} is not connected."))),
                    cx,
                );
                continue;
            };
            let read = id.clone();
            self.fetch(
                cx,
                async move { h.data_job(&read).await },
                move |this, res, cx| this.on_job_read(id, res, cx),
            );
        }
    }

    fn on_job_read(
        &mut self,
        id: String,
        res: Result<JobView, ClientError>,
        cx: &mut Context<Self>,
    ) {
        let Some(index) = self.site_data.jobs.iter().position(|j| j.id == id) else {
            return;
        };
        let tick = self.tick;
        let update = dv::apply_job_read(
            &mut self.site_data.jobs[index],
            res.map_err(|e| dv::read_error(&e)),
            tick,
        );
        match update {
            JobUpdate::Running => {}
            JobUpdate::Finished => {
                let job = self.site_data.jobs.remove(index);
                self.say(format!("{} finished on {}", job.what, job.node), Tone::Ok);
                self.after_job(&job, cx);
            }
            JobUpdate::Failed(message) => {
                let job = self.site_data.jobs.remove(index);
                self.say(
                    format!("{} failed on {}: {message}", job.what, job.node),
                    Tone::Bad,
                );
                self.after_job(&job, cx);
            }
        }
        cx.notify();
    }

    // The page that showed the job's subject reads again, so sizes, versions and health are current.
    fn after_job(&mut self, job: &JobTrack, cx: &mut Context<Self>) {
        let on_site = match (&self.view, job.site.as_deref()) {
            (crate::app::View::SiteDetail { node, id }, Some(site)) => {
                *node == job.node && id == site
            }
            _ => false,
        };
        let on_databases = self.view == crate::app::View::Databases
            && self.dbs_node().as_deref() == Some(job.node.as_str());
        if on_site && let Some(site) = &job.site {
            self.load_site_data(job.node.clone(), site.clone(), cx);
        } else if on_databases {
            self.load_databases(cx);
        }
    }

    // The banners of the jobs running for this node and, when given, this site.
    pub(crate) fn job_banners(&self, node: &str, site: Option<&str>) -> Vec<AnyElement> {
        self.site_data
            .jobs
            .iter()
            .filter(|j| j.node == node && j.site.as_deref() == site)
            .map(|j| notice(&format!("{}...", dv::job_step_text(j)), Tone::Info).into_any_element())
            .collect()
    }

    // ---- the Environment tab ----

    // The variables a data resource produces for one target, which that tab shows read-only.
    pub(crate) fn linked_env(&self, runtime: bool) -> Vec<dv::LinkedRow> {
        let here = (self.detail.node.clone(), self.detail.site_id.clone());
        if self.site_data.for_site != here {
            return Vec::new();
        }
        let target = if runtime {
            LinkTarget::Runtime
        } else {
            LinkTarget::Build
        };
        self.data_loaded()
            .map(|l| dv::linked_rows(&l.view.links, target))
            .unwrap_or_default()
    }

    // ---- actions: Postgres ----

    fn data_enable(&mut self, choice: PgChoice, cx: &mut Context<Self>) {
        let Some(mode) = choice.mode() else {
            return;
        };
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let memory = self.site_data.memory_in.read(cx).text().to_string();
        let conns = self.site_data.conns_in.read(cx).text().to_string();
        let req = match dv::pg_enable_req(mode, self.site_data.major, &memory, &conns) {
            Ok(r) => r,
            Err(e) => {
                self.site_data.error = Some(e);
                return;
            }
        };
        let fut = async move { h.site_pg_enable(&site, &req).await };
        self.data_run(
            cx,
            "Enabling Postgres",
            fut,
            |a: &JobAccepted| Done::job(a, "Postgres is being enabled"),
            |this, cx| {
                this.site_data
                    .memory_in
                    .update(cx, |i, cx| i.set_text("", cx));
                this.site_data
                    .conns_in
                    .update(cx, |i, cx| i.set_text("", cx));
            },
        );
    }

    fn data_disable(&mut self, purge: bool, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let fut = async move { h.site_pg_disable(&site, purge).await };
        self.data_run(
            cx,
            "Disabling Postgres",
            fut,
            |a: &JobAccepted| Done::job(a, "Postgres is being disabled"),
            |_, _| {},
        );
    }

    fn data_db_create(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let existing: Vec<String> = self
            .data_loaded()
            .and_then(|l| l.view.postgres.as_ref())
            .map(|pg| pg.databases.iter().map(|d| d.name.clone()).collect())
            .unwrap_or_default();
        let name = self.site_data.db_in.read(cx).text().trim().to_string();
        if let Some(p) = dv::database_create_problem(&name, &existing) {
            self.site_data.error = Some(p);
            return;
        }
        let shown = name.clone();
        let fut = async move { h.site_db_create(&site, &DatabaseCreateReq { name }).await };
        self.data_run(
            cx,
            "Adding a database",
            fut,
            move |a: &JobAccepted| Done::job(a, format!("Database {shown} is being created")),
            |this, cx| this.site_data.db_in.update(cx, |i, cx| i.set_text("", cx)),
        );
    }

    fn data_db_delete(&mut self, db: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let shown = db.clone();
        let fut = async move { h.site_db_delete(&site, &db, false).await };
        self.data_run(
            cx,
            "Deleting a database",
            fut,
            move |a: &JobAccepted| Done::job(a, format!("Database {shown} is being deleted")),
            |_, _| {},
        );
    }

    fn data_user_create(&mut self, db: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let existing: Vec<String> = self
            .data_loaded()
            .and_then(|l| l.view.postgres.as_ref())
            .and_then(|pg| pg.databases.iter().find(|d| d.name == db))
            .map(|d| d.users.iter().map(|u| u.name.clone()).collect())
            .unwrap_or_default();
        let name = self.site_data.user_in.read(cx).text().to_string();
        let limit = self.site_data.user_limit_in.read(cx).text().to_string();
        let req = match dv::user_create_req(&name, self.site_data.user_level, &limit, &existing) {
            Ok(r) => r,
            Err(e) => {
                self.site_data.error = Some(e);
                return;
            }
        };
        let shown = req.name.clone();
        let fut = async move { h.site_db_user_create(&site, &db, &req).await };
        self.data_run(
            cx,
            "Adding a user",
            fut,
            move |a: &JobAccepted| Done::job(a, format!("User {shown} is being created")),
            |this, cx| {
                this.site_data
                    .user_in
                    .update(cx, |i, cx| i.set_text("", cx));
                this.site_data
                    .user_limit_in
                    .update(cx, |i, cx| i.set_text("", cx));
                this.site_data.user_db = None;
            },
        );
    }

    fn data_user_limit(&mut self, db: String, user: String, current: u32, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let text = self.site_data.limit_in.read(cx).text().to_string();
        let patch = match dv::limit_patch(&text, current) {
            Ok(p) => p,
            Err(e) => {
                self.site_data.error = Some(e);
                return;
            }
        };
        let shown = user.clone();
        let fut = async move { h.site_db_user_update(&site, &db, &user, &patch).await };
        self.data_run(
            cx,
            "Changing the connection limit",
            fut,
            move |a: &JobAccepted| Done::job(a, format!("The limit of {shown} is being changed")),
            |this, _| this.site_data.limit_edit = None,
        );
    }

    fn data_user_disable(
        &mut self,
        db: String,
        user: String,
        disabled: bool,
        cx: &mut Context<Self>,
    ) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let patch = dv::disable_patch(disabled);
        let shown = user.clone();
        let fut = async move { h.site_db_user_update(&site, &db, &user, &patch).await };
        self.data_run(
            cx,
            if disabled {
                "Disabling a user"
            } else {
                "Enabling a user"
            },
            fut,
            move |a: &JobAccepted| {
                Done::job(
                    a,
                    format!(
                        "{shown} is being {}",
                        if disabled { "disabled" } else { "enabled" }
                    ),
                )
            },
            |_, _| {},
        );
    }

    fn data_user_rotate(&mut self, db: String, user: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let shown = user.clone();
        let fut = async move { h.site_db_user_rotate(&site, &db, &user).await };
        self.data_run(
            cx,
            "Rotating a password",
            fut,
            move |a: &JobAccepted| {
                let tail = if a.redeploy_needed {
                    ". Redeploy so the running site picks it up"
                } else {
                    ""
                };
                Done::job(a, format!("A new password is issued for {shown}{tail}"))
            },
            |_, _| {},
        );
    }

    fn data_user_delete(&mut self, db: String, user: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let shown = user.clone();
        let fut = async move { h.site_db_user_delete(&site, &db, &user).await };
        self.data_run(
            cx,
            "Deleting a user",
            fut,
            move |a: &JobAccepted| Done::job(a, format!("User {shown} is being deleted")),
            |_, _| {},
        );
    }

    // ---- actions: links, presets, secrets ----

    fn data_link_delete(&mut self, target: LinkTarget, var: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let shown = var.clone();
        let fut = async move { h.site_link_delete(&site, target, &var).await };
        self.data_run(
            cx,
            "Removing a link",
            fut,
            move |_: &()| {
                Done::plain(format!(
                    "{shown} is no longer linked. It applies on the next redeploy."
                ))
            },
            |_, _| {},
        );
    }

    fn manual_env(&self) -> (Vec<String>, Vec<String>) {
        let ex = &self.ops.extras;
        (
            ex.runtime_env.clone().unwrap_or_default(),
            ex.build_env.clone().unwrap_or_default(),
        )
    }

    fn data_apply_preset(&mut self, preset: Preset, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let Some(view) = self.data_loaded().map(|l| l.view.clone()) else {
            return;
        };
        let opts = PresetOpts::default();
        let (runtime, build) = self.manual_env();
        let preview = dv::preset_preview(preset, &opts, &view, &runtime, &build);
        if let Some(p) = &preview.problem {
            self.site_data.error = Some(p.clone());
            return;
        }
        if preview.needs_override() && !self.site_data.override_manual {
            self.site_data.error = Some(
                "Tick the override to replace the manual variables this preset would shadow."
                    .into(),
            );
            return;
        }
        let req = dv::preset_request(preset, &opts, self.site_data.override_manual);
        let label = dv::preset_label(preset);
        // Our own pre-check ran first; if the node still finds variables in the way, its list is shown as it gave it.
        let fut = async move {
            match h.site_links_preset(&site, &req).await? {
                LinksOutcome::Applied(done) => Ok(done),
                LinksOutcome::Conflicts(found) => Err(ClientError::Status {
                    code: 409,
                    message: format!(
                        "The node refused the preset: {}. {}",
                        dv::conflict_lines(&found).join("; "),
                        dv::conflict_summary(&found)
                    ),
                }),
            }
        };
        self.data_run(
            cx,
            "Applying a preset",
            fut,
            move |r: &cite_edge::datawire::PresetResponse| Done {
                message: format!("{label} preset applied. It applies on the next redeploy."),
                job: r.job_id.clone().filter(|j| !j.is_empty()),
            },
            |this, _| {
                this.site_data.preset = None;
                this.site_data.override_manual = false;
            },
        );
    }

    // What each pick of the add-link form offers for the loaded site, with the choice in effect (an empty pick means the first).
    fn link_options(&self, l: &Loaded) -> LinkOptions {
        let s = &self.site_data;
        let view = &l.view;
        let mut kinds = Vec::new();
        if view.postgres.is_some() {
            kinds.push(LinkKind::Postgres);
        }
        if !view.external.is_empty() {
            kinds.push(LinkKind::External);
        }
        if !view.s3.is_empty() {
            kinds.push(LinkKind::S3);
        }
        if !view.secrets.is_empty() {
            kinds.push(LinkKind::Secret);
        }
        kinds.push(LinkKind::SiteUrl);
        let kind = if kinds.contains(&s.link_kind) {
            s.link_kind
        } else {
            LinkKind::SiteUrl
        };
        let pg = view.postgres.as_ref();
        let databases: Vec<String> = pg
            .map(|p| p.databases.iter().map(|d| d.name.clone()).collect())
            .unwrap_or_default();
        let db = pick(&s.link_db, &databases);
        let users: Vec<String> = pg
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .map(|d| d.users.iter().map(|u| u.name.clone()).collect())
            .unwrap_or_default();
        let user = pick(&s.link_user, &users);
        let names: Vec<String> = match kind {
            LinkKind::External => view.external.iter().map(|e| e.name.clone()).collect(),
            LinkKind::S3 => view.s3.iter().map(|a| a.name.clone()).collect(),
            LinkKind::Secret => view.secrets.iter().map(|x| x.name.clone()).collect(),
            _ => Vec::new(),
        };
        let name = pick(&s.link_name, &names);
        let fields: Vec<String> = dv::fields_for(kind)
            .into_iter()
            .map(str::to_string)
            .collect();
        let field = pick(&s.link_field, &fields);
        LinkOptions {
            kinds,
            kind,
            databases,
            db,
            users,
            user,
            names,
            name,
            fields,
            field,
        }
    }

    fn data_link_add(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let typed = self
            .site_data
            .link_var_in
            .read(cx)
            .text()
            .trim()
            .to_string();
        let (draft, links) = {
            let Some(l) = self.data_loaded() else {
                return;
            };
            let o = self.link_options(l);
            (
                LinkDraft {
                    kind: o.kind,
                    database: o.db,
                    user: o.user,
                    name: o.name,
                    field: o.field,
                    var: typed,
                    target: self.site_data.link_target,
                },
                l.view.links.clone(),
            )
        };
        let mut draft = draft;
        let source = match dv::source_from_draft(&draft) {
            Ok(s) => s,
            Err(e) => {
                self.site_data.error = Some(e);
                return;
            }
        };
        if draft.var.is_empty() {
            draft.var = dv::suggested_var(&source);
        }
        if let Some(p) = dv::link_draft_problem(&draft, &links) {
            self.site_data.error = Some(p);
            return;
        }
        let (runtime, build) = self.manual_env();
        let manual = dv::manual_link_conflicts(&draft, &links, &runtime, &build);
        if !manual.is_empty() && !self.site_data.link_override {
            self.site_data.error = Some(dv::conflict_summary(&manual));
            self.site_data.link_conflicts = manual;
            return;
        }
        self.site_data.link_conflicts.clear();
        let req = dv::link_request(&draft, source, self.site_data.link_override);
        let var = draft.var.clone();
        self.site_data.busy = true;
        self.site_data.error = None;
        let (node, site_id) = (self.detail.node.clone(), self.detail.site_id.clone());
        let fut = async move { h.site_links_add(&site, &req).await };
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            this.site_data.busy = false;
            let failure = match res {
                Ok(LinksOutcome::Applied(_)) => {
                    let message = format!("{var} is linked. It applies on the next redeploy.");
                    if here {
                        this.say(message, Tone::Ok);
                        this.site_data.link_open = false;
                        this.site_data.link_override = false;
                        this.site_data
                            .link_var_in
                            .update(cx, |i, cx| i.set_text("", cx));
                        this.load_site_data(node, site_id, cx);
                    } else {
                        this.say(foreign_notice("Adding a link", origin, &message), Tone::Ok);
                    }
                    None
                }
                Ok(LinksOutcome::Conflicts(found)) => {
                    let message = format!(
                        "The node refused the link: {}. {}",
                        dv::conflict_lines(&found).join("; "),
                        dv::conflict_summary(&found)
                    );
                    if here {
                        this.site_data.link_conflicts = found;
                    }
                    Some(message)
                }
                Err(e) => Some(e.to_string()),
            };
            if let Some(message) = failure {
                if here {
                    this.site_data.error = Some(message);
                } else {
                    this.say(foreign_notice("Adding a link", origin, &message), Tone::Bad);
                }
            }
            cx.notify();
        });
    }

    fn data_secret_create(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let existing: Vec<SecretView> = self
            .data_loaded()
            .map(|l| l.view.secrets.clone())
            .unwrap_or_default();
        let name = self.site_data.secret_in.read(cx).text().to_string();
        let bytes = self.site_data.secret_bytes_in.read(cx).text().to_string();
        let req = match dv::secret_create_req(&name, &bytes, self.site_data.secret_enc, &existing) {
            Ok(r) => r,
            Err(e) => {
                self.site_data.error = Some(e);
                return;
            }
        };
        let fut = async move { h.site_secret_create(&site, &req).await };
        self.data_run(
            cx,
            "Creating a secret",
            fut,
            |s: &SecretView| Done::plain(format!("Secret {} created", s.name)),
            |this, cx| {
                this.site_data
                    .secret_in
                    .update(cx, |i, cx| i.set_text("", cx));
                this.site_data
                    .secret_bytes_in
                    .update(cx, |i, cx| i.set_text("", cx));
            },
        );
    }

    fn data_secret_rotate(&mut self, name: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let fut = async move { h.site_secret_rotate(&site, &name).await };
        self.data_run(
            cx,
            "Rotating a secret",
            fut,
            |s: &SecretView| {
                let tail = if s.redeploy_needed {
                    ". Redeploy so the running site picks it up"
                } else {
                    ""
                };
                Done::plain(format!("Secret {} rotated{tail}", s.name))
            },
            |_, _| {},
        );
    }

    fn data_secret_delete(&mut self, name: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let shown = name.clone();
        let fut = async move { h.site_secret_delete(&site, &name).await };
        self.data_run(
            cx,
            "Deleting a secret",
            fut,
            move |_: &()| Done::plain(format!("Secret {shown} deleted")),
            |_, _| {},
        );
    }

    // ---- actions: external Postgres and S3 ----

    fn data_external_put(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let name = self
            .site_data
            .ext_name_in
            .read(cx)
            .text()
            .trim()
            .to_string();
        let mut url = self.site_data.ext_url_in.read(cx).text().to_string();
        let problem =
            dv::resource_name_problem(&name, "name").or_else(|| dv::external_url_problem(&url));
        if let Some(p) = problem {
            crate::certs::wipe(&mut url);
            self.site_data.error = Some(p);
            return;
        }
        let req = dv::external_put_req(&url);
        crate::certs::wipe(&mut url);
        let shown = name.clone();
        let fut = async move { h.site_external_put(&site, &name, &req).await };
        self.data_run(
            cx,
            "Attaching an external database",
            fut,
            move |_: &ExternalView| Done::plain(format!("External database {shown} saved")),
            |this, cx| {
                this.site_data
                    .ext_name_in
                    .update(cx, |i, cx| i.set_text("", cx));
                this.site_data
                    .ext_url_in
                    .update(cx, |i, cx| i.set_text("", cx));
            },
        );
    }

    fn data_external_delete(&mut self, name: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let shown = name.clone();
        let fut = async move { h.site_external_delete(&site, &name).await };
        self.data_run(
            cx,
            "Removing an external database",
            fut,
            move |_: &()| Done::plain(format!("External database {shown} removed")),
            |_, _| {},
        );
    }

    fn read_s3_form(&self, cx: &Context<Self>) -> S3Form {
        let s = &self.site_data;
        let text = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        S3Form {
            name: text(&s.s3_name_in).trim().to_string(),
            endpoint: text(&s.s3_endpoint_in),
            bucket: text(&s.s3_bucket_in),
            region: text(&s.s3_region_in),
            prefix: String::new(),
            path_style: s.s3_path_style,
            encrypt: false,
            access_key_id: text(&s.s3_key_in),
            secret_access_key: text(&s.s3_secret_in),
        }
    }

    fn clear_s3_form(&mut self, cx: &mut Context<Self>) {
        let s = &mut self.site_data;
        s.s3_path_style = false;
        s.s3_editing = None;
        for input in [
            s.s3_name_in.clone(),
            s.s3_endpoint_in.clone(),
            s.s3_bucket_in.clone(),
            s.s3_region_in.clone(),
            s.s3_key_in.clone(),
            s.s3_secret_in.clone(),
        ] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    // Puts an attachment's public fields into the form; the keys stay blank and the node keeps the stored ones.
    fn data_s3_edit(&mut self, att: &S3View, cx: &mut Context<Self>) {
        self.clear_s3_form(cx);
        let s = &mut self.site_data;
        s.s3_editing = Some(att.name.clone());
        s.s3_path_style = att.path_style;
        for (input, text) in [
            (s.s3_name_in.clone(), att.name.clone()),
            (s.s3_endpoint_in.clone(), att.endpoint.clone()),
            (s.s3_bucket_in.clone(), att.bucket.clone()),
            (s.s3_region_in.clone(), att.region.clone()),
        ] {
            input.update(cx, |i, cx| i.set_text(&text, cx));
        }
    }

    fn data_s3_put(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let mut form = self.read_s3_form(cx);
        let has_keys = self
            .data_loaded()
            .is_some_and(|l| l.view.s3.iter().any(|a| a.name == form.name && a.has_keys));
        if let Some(p) = dv::s3_problem(&form, has_keys) {
            form.wipe();
            self.site_data.error = Some(p);
            return;
        }
        let name = form.name.clone();
        let req = dv::s3_put_req(&form);
        form.wipe();
        let fut = async move { h.site_s3_put(&site, &name, &req).await };
        self.data_run(
            cx,
            "Saving an S3 attachment",
            fut,
            |a: &S3View| Done::plain(format!("S3 attachment {} saved", a.name)),
            |this, cx| this.clear_s3_form(cx),
        );
    }

    fn data_s3_delete(&mut self, name: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let shown = name.clone();
        let fut = async move { h.site_s3_delete(&site, &name).await };
        self.data_run(
            cx,
            "Removing an S3 attachment",
            fut,
            move |_: &()| Done::plain(format!("S3 attachment {shown} removed")),
            |_, _| {},
        );
    }

    // ---- actions: backups ----

    fn backup_record(&self, id: &str) -> Option<BackupRecord> {
        self.data_loaded()
            .and_then(|l| l.backups.iter().find(|b| b.id == id).cloned())
    }

    fn data_backup_create(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let Some(database) = self.site_data.backup_db.clone() else {
            return;
        };
        let label = self
            .site_data
            .backup_label_in
            .read(cx)
            .text()
            .trim()
            .to_string();
        if let Some(p) = dv::label_problem(&label) {
            self.site_data.error = Some(p);
            return;
        }
        let req = BackupCreateReq {
            database: database.clone(),
            label: Some(label).filter(|l| !l.is_empty()),
            push_s3: self.site_data.backup_push,
        };
        let shown = dv::database_name(&database).to_string();
        let fut = async move { h.site_backup_create(&site, &req).await };
        self.data_run(
            cx,
            "Backup",
            fut,
            move |c: &cite_edge::datawire::BackupCreated| Done {
                message: format!("A backup of {shown} started"),
                job: Some(c.job_id.clone()).filter(|j| !j.is_empty()),
            },
            |this, cx| {
                this.site_data
                    .backup_label_in
                    .update(cx, |i, cx| i.set_text("", cx));
            },
        );
    }

    fn data_backup_pin(&mut self, id: String, pinned: bool, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let req = BackupPatchReq {
            label: None,
            pinned: Some(pinned),
        };
        let fut = async move { h.site_backup_patch(&site, &id, &req).await };
        self.data_run(
            cx,
            "Pinning a version",
            fut,
            move |r: &BackupRecord| {
                Done::plain(format!(
                    "Version {} {}",
                    r.version,
                    if pinned { "pinned" } else { "unpinned" }
                ))
            },
            |_, _| {},
        );
    }

    fn data_backup_label(&mut self, id: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let text = self.site_data.label_in.read(cx).text().trim().to_string();
        if let Some(p) = dv::label_problem(&text) {
            self.site_data.error = Some(p);
            return;
        }
        let req = BackupPatchReq {
            label: Some(Some(text).filter(|t| !t.is_empty())),
            pinned: None,
        };
        let fut = async move { h.site_backup_patch(&site, &id, &req).await };
        self.data_run(
            cx,
            "Labelling a version",
            fut,
            |r: &BackupRecord| Done::plain(format!("Version {} labelled", r.version)),
            |this, cx| {
                this.site_data.label_edit = None;
                this.site_data
                    .label_in
                    .update(cx, |i, cx| i.set_text("", cx));
            },
        );
    }

    fn data_backup_delete(&mut self, rec: BackupRecord, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let version = rec.version;
        let fut = async move { h.site_backup_delete(&site, &rec.id, DeleteFrom::All).await };
        self.data_run(
            cx,
            "Deleting a version",
            fut,
            move |_: &()| Done::plain(format!("Version {version} deleted")),
            |this, _| this.site_data.backup_sel = None,
        );
    }

    fn data_backup_restore(&mut self, rec: BackupRecord, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let req = RestoreReq {
            confirm: site.clone(),
            database: None,
        };
        let version = rec.version;
        let fut = async move { h.site_backup_restore(&site, &rec.id, &req).await };
        self.data_run(
            cx,
            "Restore",
            fut,
            move |r: &cite_edge::datawire::RestoreStarted| Done {
                message: format!(
                    "Restoring version {version}. A backup of the current data was taken first"
                ),
                job: Some(r.job_id.clone()).filter(|j| !j.is_empty()),
            },
            |_, _| {},
        );
    }

    fn data_backup_push(&mut self, rec: BackupRecord, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let version = rec.version;
        let fut = async move {
            h.site_backup_push(&site, &rec.id, &PushReq::default())
                .await
        };
        self.data_run(
            cx,
            "Push to S3",
            fut,
            move |a: &JobAccepted| Done::job(a, format!("Version {version} is being copied to S3")),
            |_, _| {},
        );
    }

    // The file goes to the Downloads folder under a name rebuilt from the record, and its checksum is verified before it is kept.
    fn data_backup_download(&mut self, rec: BackupRecord, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let Some(dir) = downloads_dir() else {
            self.site_data.error = Some(
                "Cannot find your home directory, so there is nowhere to save the file.".into(),
            );
            return;
        };
        let node = self.detail.node.clone();
        let fut = run_backup_download(h, site, rec, dir);
        self.data_run(
            cx,
            "Backup download",
            fut,
            move |report: &cite_client::ExportReport| {
                Done::plain(format!(
                    "Saved {} from {node} to {}",
                    fmt_bytes(report.bytes),
                    report.path.display()
                ))
            },
            |_, _| {},
        );
    }

    fn data_prune_preview(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let key = self.site_data.for_site.clone();
        let fut = async move { h.site_prune_preview(&site).await };
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            if here && this.site_data.for_site == key {
                match res {
                    Ok(previews) => this.site_data.prune = Some(previews),
                    Err(e) => this.site_data.error = Some(e.to_string()),
                }
            } else if let Err(e) = res {
                this.say(
                    foreign_notice("Prune preview", origin, &e.to_string()),
                    Tone::Bad,
                );
            }
            cx.notify();
        });
    }

    fn data_prune(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let fut = async move { h.site_prune(&site).await };
        self.data_run(
            cx,
            "Prune",
            fut,
            |r: &cite_edge::datawire::PruneResult| {
                Done::plain(format!(
                    "Deleted {} {}",
                    r.deleted,
                    if r.deleted == 1 { "copy" } else { "copies" }
                ))
            },
            |this, _| this.site_data.prune = None,
        );
    }

    // Opens the retention editor on the stored policy.
    fn data_policy_open(
        &mut self,
        policy: &cite_edge::datamodel::BackupPolicy,
        cx: &mut Context<Self>,
    ) {
        let draft = PolicyDraft::from_policy(policy);
        let s = &self.site_data;
        let pairs: Vec<(Entity<TextInput>, String)> =
            std::iter::once((s.minute_in.clone(), draft.minute.clone()))
                .chain(s.local_in.iter().cloned().zip(draft.local.iter().cloned()))
                .chain(s.s3_ret_in.iter().cloned().zip(draft.s3.iter().cloned()))
                .collect();
        for (input, text) in pairs {
            input.update(cx, |i, cx| i.set_text(&text, cx));
        }
        self.site_data.policy = Some(draft);
        self.site_data.policy_open = true;
    }

    fn data_policy_save(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let Some(mut draft) = self.site_data.policy.clone() else {
            return;
        };
        let s = &self.site_data;
        draft.minute = s.minute_in.read(cx).text().to_string();
        for (i, input) in s.local_in.iter().enumerate() {
            draft.local[i] = input.read(cx).text().to_string();
        }
        for (i, input) in s.s3_ret_in.iter().enumerate() {
            draft.s3[i] = input.read(cx).text().to_string();
        }
        let policy = match draft.to_policy() {
            Ok(p) => p,
            Err(e) => {
                self.site_data.error = Some(e);
                return;
            }
        };
        let fut = async move { h.site_pg_policy(&site, &policy).await };
        self.data_run(
            cx,
            "Saving the backup policy",
            fut,
            |_: &PgView| Done::plain("Backup policy saved"),
            |this, _| {
                this.site_data.policy_open = false;
                this.site_data.policy = None;
            },
        );
    }

    // ---- render ----

    pub(crate) fn data_tab(&self, data: &Data, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let mut out: Vec<AnyElement> = Vec::new();
        let node = self.detail.node.as_str();
        let loaded = match &self.site_data.load {
            DataLoad::Idle | DataLoad::Loading => {
                out.push(skeleton(240.).into_any_element());
                return out;
            }
            DataLoad::Absent => {
                out.push(
                    notice("This node does not offer database services.", Tone::Info)
                        .into_any_element(),
                );
                return out;
            }
            DataLoad::Failed(message) => {
                out.push(self.error_block(cx, message));
                return out;
            }
            DataLoad::Ready(loaded) => loaded,
        };
        out.extend(self.job_banners(node, Some(&data.site.id)));
        if let Some(e) = &self.site_data.error {
            out.push(notice(e, Tone::Bad).into_any_element());
        }
        if loaded.view.redeploy_needed {
            out.push(self.redeploy_banner(cx));
        }
        out.push(self.data_pg_card(loaded, cx));
        if let Some(pg) = &loaded.view.postgres {
            out.push(self.data_db_card(pg, cx));
        }
        if has_cap(&loaded.caps, dv::CAP_DATA_LINKS) {
            out.push(self.data_links_card(loaded, cx));
            out.push(self.data_secrets_card(loaded, cx));
        }
        if has_cap(&loaded.caps, dv::CAP_DATA_EXTERNAL) {
            out.push(self.data_external_card(loaded, cx));
        }
        if has_cap(&loaded.caps, dv::CAP_DATA_S3) {
            out.push(self.data_s3_card(loaded, cx));
        }
        if has_cap(&loaded.caps, dv::CAP_DATA_BACKUPS)
            && !dv::backup_databases(&loaded.view).is_empty()
        {
            out.push(self.data_backups_card(loaded, &data.site.id, cx));
        }
        if has_cap(&loaded.caps, dv::CAP_DATA_TRANSFER) {
            out.extend(self.convert_card(loaded, cx));
            out.push(self.transfer_card(loaded, cx));
        }
        out
    }

    fn redeploy_banner(&self, cx: &mut Context<Self>) -> AnyElement {
        let action = act(
            self.detail.busy,
            id("dt", "redeploy"),
            "Redeploy",
            BtnKind::Primary,
            |this, cx| this.do_deploy(cx),
            cx,
        );
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .justify_between()
            .gap(px(12.))
            .child(
                div().flex().flex_col().flex_1().min_w_0().child(notice(
                    "Linked variables or passwords changed. A running site picks them up on its next deploy.",
                    Tone::Warn,
                )),
            )
            .child(action)
            .into_any_element()
    }

    fn data_pg_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.site_data;
        let busy = s.busy;
        let (title, sub) = ("Postgres", "A managed database for this site, or none.");
        let Some(pg) = &l.view.postgres else {
            return card(Some(title), Some(sub), self.pg_chooser(l, cx)).into_any_element();
        };
        let size: u64 = pg.databases.iter().filter_map(|d| d.size_bytes).sum();
        let health = pg.health.clone().unwrap_or_default();
        let health_row = div()
            .flex()
            .items_center()
            .gap(px(6.))
            .child(dot(dv::health_tone(&health)))
            .child(text_dim(if health.is_empty() {
                "unknown".to_string()
            } else {
                health
            }));
        let mut rows = stack(8.)
            .child(kv(
                "Mode",
                pill(dv::current_choice(&l.view).label(), Tone::Info),
            ))
            .child(kv("Postgres major", mono(pg.major.to_string())))
            .child(kv("Health", health_row))
            .child(kv("Size", text_dim(fmt_bytes(size))));
        if pg.mode == PgMode::Dedicated {
            rows = rows
                .child(kv("Memory", text_dim(format!("{} MiB", pg.memory_mb))))
                .child(kv("Connections", text_dim(pg.max_connections.to_string())));
        } else {
            rows = rows.child(note(
                "A tenant of the node's shared instance. Its limits are set on the Databases page.",
            ));
        }
        let keep = act(
            busy,
            id("dt", "pg-disable"),
            "Disable",
            BtnKind::Danger,
            |this, _| {
                this.ask(Confirm {
                    title: "Disable Postgres".into(),
                    message: "The site loses its database links. The data is kept on the node until you delete it.".into(),
                    label: "Disable".into(),
                    danger: true,
                    action: Box::new(|this, cx| this.data_disable(false, cx)),
                });
            },
            cx,
        );
        let purge = act(
            busy,
            id("dt", "pg-purge"),
            "Disable and delete data",
            BtnKind::Danger,
            |this, _| {
                this.ask(Confirm {
                    title: "Delete the database".into(),
                    message: "Permanently deletes every database of this site and its data. Backups are kept. This cannot be undone.".into(),
                    label: "Delete data".into(),
                    danger: true,
                    action: Box::new(|this, cx| this.data_disable(true, cx)),
                });
            },
            cx,
        );
        let body = rows.child(wrap_row().child(keep).child(purge));
        card(Some(title), Some(sub), body).into_any_element()
    }

    // What a site without a database can pick, with the trade-off between a dedicated and the shared database.
    fn pg_chooser(&self, l: &Loaded, cx: &mut Context<Self>) -> Div {
        let s = &self.site_data;
        let can_pg = has_cap(&l.caps, dv::CAP_DATA_POSTGRES);
        let allowed: Vec<PgChoice> = PgChoice::ENABLE
            .into_iter()
            .filter(|c| match c {
                PgChoice::Dedicated => can_pg,
                PgChoice::Shared => can_pg && has_cap(&l.caps, dv::CAP_DATA_SHARED),
                PgChoice::External => has_cap(&l.caps, dv::CAP_DATA_EXTERNAL),
                PgChoice::Off => false,
            })
            .collect();
        let Some(choice) = (if allowed.contains(&s.pick) {
            Some(s.pick)
        } else {
            allowed.first().copied()
        }) else {
            return stack(8.).child(note("This node offers no Postgres for sites."));
        };
        let mut items = Vec::new();
        for c in &allowed {
            let picked = *c;
            items.push(
                seg_item(
                    id("dt-pick", picked.label()),
                    picked.label(),
                    picked == choice,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.site_data.pick = picked;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let mut body = stack(12.)
            .child(note(&format!(
                "Mode: {}. No managed database is attached to this site.",
                dv::current_choice(&l.view).label()
            )))
            .child(seg_row(items))
            .child(note(choice.summary()));
        match choice {
            PgChoice::Dedicated | PgChoice::Shared => {
                body = body.child(tradeoff_table("dt-pg"));
                if choice == PgChoice::Dedicated {
                    let mut majors = Vec::new();
                    for major in [18u8, 17] {
                        majors.push(
                            seg_item(
                                id("dt-major", major),
                                &format!("Postgres {major}"),
                                s.major == major,
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.site_data.major = major;
                                cx.notify();
                            }))
                            .into_any_element(),
                        );
                    }
                    body = body
                        .child(note("The major is fixed once the database exists: changing it later means dump and restore."))
                        .child(seg_row(majors))
                        .child(form_grid(vec![
                            field("Memory (MiB)", Some("256 to 65536. Blank keeps the default."), s.memory_in.clone()).into_any_element(),
                            field("Max connections", Some("10 to 1000. Blank keeps the default."), s.conns_in.clone()).into_any_element(),
                        ]));
                }
                body = body
                    .child(note("Enabling creates a database named app with an app user (read and write) and a migrate user (owner), and links their URLs into the site."))
                    .child(wrap_row().child(act(
                        s.busy,
                        id("dt", "pg-enable"),
                        "Enable Postgres",
                        BtnKind::Primary,
                        move |this, cx| this.data_enable(choice, cx),
                        cx,
                    )));
            }
            PgChoice::External | PgChoice::Off => {
                body = body.child(note(
                    "Attach it under External databases below. The node stores the URL and never shows it again.",
                ));
            }
        }
        body
    }

    fn data_db_card(&self, pg: &PgView, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.site_data;
        let busy = s.busy;
        let now = now_ms();
        let mut body = stack(16.).child(note(dv::WRITE_ONLY_PASSWORDS));
        for db in &pg.databases {
            body = body.child(self.data_db_block(db, busy, now, cx));
        }
        let names: Vec<String> = pg.databases.iter().map(|d| d.name.clone()).collect();
        let add = act(
            busy,
            id("dt", "db-add"),
            "Add database",
            BtnKind::Primary,
            |this, cx| this.data_db_create(cx),
            cx,
        );
        let hint = if names.len() >= cite_edge::validate::MAX_PG_DATABASES {
            format!(
                "A site can have at most {} databases.",
                cite_edge::validate::MAX_PG_DATABASES
            )
        } else {
            "Lowercase letters and digits. It starts with an app and a migrate user.".to_string()
        };
        body = body.child(
            div()
                .flex()
                .items_end()
                .gap(px(12.))
                .child(div().flex().flex_col().flex_1().min_w_0().child(field(
                    "New database",
                    Some(&hint),
                    s.db_in.clone(),
                )))
                .child(div().flex().flex_col().pb(px(18.)).child(add)),
        );
        card(
            Some("Databases and users"),
            Some(
                "Levels: owner for migrations, read and write for the app, read only for reports.",
            ),
            body,
        )
        .into_any_element()
    }

    fn data_db_block(
        &self,
        db: &PgDatabaseView,
        busy: bool,
        now: i64,
        cx: &mut Context<Self>,
    ) -> Div {
        let s = &self.site_data;
        let name = db.name.clone();
        let linked: Vec<String> = db.users.iter().flat_map(|u| u.linked_by.clone()).collect();
        let delete = match dv::delete_blocked_reason(&linked) {
            Some(reason) => blocked(id("dt-db-del", &name), "Delete database", &reason),
            None => {
                let db_name = name.clone();
                act(
                    busy,
                    id("dt-db-del", &name),
                    "Delete database",
                    BtnKind::Danger,
                    move |this, _| {
                        let victim = db_name.clone();
                        this.ask(Confirm {
                            title: format!("Delete database {victim}"),
                            message: format!(
                                "Deletes {victim} from the site. Take a backup first if you need the data."
                            ),
                            label: "Delete".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.data_db_delete(victim, cx)),
                        });
                    },
                    cx,
                )
            }
        };
        let open_form = s.user_db.as_deref() == Some(name.as_str());
        let form_name = name.clone();
        let add_user = act(
            busy,
            id("dt-user-add", &name),
            if open_form { "Close" } else { "Add user" },
            BtnKind::Plain,
            move |this, _| {
                this.site_data.user_db = if open_form {
                    None
                } else {
                    Some(form_name.clone())
                };
            },
            cx,
        );
        let head = div()
            .flex()
            .flex_wrap()
            .items_center()
            .justify_between()
            .gap(px(8.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(strong(name.clone()))
                    .child(
                        text_dim(
                            db.size_bytes
                                .map_or("size not read yet".to_string(), fmt_bytes),
                        )
                        .text_size(px(font::SM)),
                    )
                    .child(pill(&format!("{} users", db.users.len()), Tone::Muted)),
            )
            .child(wrap_row().child(add_user).child(delete));
        let mut rows: Vec<Vec<AnyElement>> = Vec::new();
        for u in &db.users {
            rows.push(self.user_row(&name, u, busy, now, cx));
        }
        let cols = [
            Col::fixed("User", 110.),
            Col::fixed("Level", 120.),
            Col::fixed("Limit", 60.),
            Col::fixed("State", 90.),
            Col::fixed("Rotated", 90.),
            Col::flex("Linked by").min(150.),
            Col::fixed("", 350.),
        ];
        let mut block = stack(8.).child(head).child(wide(
            id("dt-users", &name),
            960.,
            table(&cols, rows, Some(empty_state("No users", "Add one below."))),
        ));
        if open_form {
            block = block.child(self.user_form(&name, cx));
        }
        if let Some((edit_db, edit_user)) = &s.limit_edit
            && *edit_db == name
        {
            let current = db
                .users
                .iter()
                .find(|u| u.name == *edit_user)
                .map_or(0, |u| u.connection_limit);
            block = block.child(self.limit_form(&name, edit_user, current, cx));
        }
        block.pb(px(8.))
    }

    fn user_row(
        &self,
        db: &str,
        u: &cite_edge::datawire::PgUserView,
        busy: bool,
        now: i64,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let key = format!("{db}-{}", u.name);
        let (state_text, tone) = dv::user_state(u);
        let level = u.level.map_or("unknown", dv::level_label);
        let rotated = u
            .rotated_at
            .as_deref()
            .and_then(parse_rfc3339_ms)
            .map_or_else(|| "-".to_string(), |t| rel_time(now, t));
        let (d1, n1) = (db.to_string(), u.name.clone());
        let rotate = act(
            busy,
            id("dt-rotate", &key),
            "Rotate",
            BtnKind::Plain,
            move |this, _| {
                let (db, user) = (d1.clone(), n1.clone());
                this.ask(Confirm {
                    title: format!("Rotate the password of {user}"),
                    message: dv::ROTATE_TEXT.to_string(),
                    label: "Rotate".into(),
                    danger: false,
                    action: Box::new(move |this, cx| this.data_user_rotate(db, user, cx)),
                });
            },
            cx,
        );
        let (d2, n2, limit) = (db.to_string(), u.name.clone(), u.connection_limit);
        let edit = act(
            busy,
            id("dt-limit", &key),
            "Limit",
            BtnKind::Plain,
            move |this, cx| {
                this.site_data.limit_edit = Some((d2.clone(), n2.clone()));
                this.site_data
                    .limit_in
                    .update(cx, |i, cx| i.set_text(&limit.to_string(), cx));
            },
            cx,
        );
        let (d3, n3, disabled) = (db.to_string(), u.name.clone(), u.disabled);
        let toggle = act(
            busy,
            id("dt-disable", &key),
            if disabled { "Enable" } else { "Disable" },
            BtnKind::Plain,
            move |this, cx| this.data_user_disable(d3.clone(), n3.clone(), !disabled, cx),
            cx,
        );
        let delete = match dv::delete_blocked_reason(&u.linked_by) {
            Some(reason) => blocked(id("dt-user-del", &key), "Delete", &reason),
            None => {
                let (d4, n4) = (db.to_string(), u.name.clone());
                act(
                    busy,
                    id("dt-user-del", &key),
                    "Delete",
                    BtnKind::Danger,
                    move |this, _| {
                        let (db, user) = (d4.clone(), n4.clone());
                        this.ask(Confirm {
                            title: format!("Delete user {user}"),
                            message: format!(
                                "Drops the login {user}. The node refuses to delete the last owner."
                            ),
                            label: "Delete".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.data_user_delete(db, user, cx)),
                        });
                    },
                    cx,
                )
            }
        };
        vec![
            cell_mono(u.name.clone()),
            cell_text(level),
            cell_text(u.connection_limit.to_string()),
            pill(state_text, tone).into_any_element(),
            cell_text(rotated),
            cell_text(if u.linked_by.is_empty() {
                "-".to_string()
            } else {
                u.linked_by.join(", ")
            }),
            wrap_row()
                .gap(px(6.))
                .child(rotate)
                .child(edit)
                .child(toggle)
                .child(delete)
                .into_any_element(),
        ]
    }

    fn user_form(&self, db: &str, cx: &mut Context<Self>) -> Div {
        let s = &self.site_data;
        let mut levels = Vec::new();
        for level in dv::LEVELS {
            levels.push(
                seg_item(
                    id("dt-level", level.as_str()),
                    dv::level_label(level),
                    s.user_level == level,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.site_data.user_level = level;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let target = db.to_string();
        stack(10.)
            .p(px(12.))
            .child(strong(format!("New user in {db}")).text_size(px(font::SM)))
            .child(form_grid(vec![
                field(
                    "User name",
                    Some("Lowercase letters and digits."),
                    s.user_in.clone(),
                )
                .into_any_element(),
                field(
                    "Connection limit",
                    Some("1 to 500. Blank keeps the default."),
                    s.user_limit_in.clone(),
                )
                .into_any_element(),
            ]))
            .child(seg_row(levels))
            .child(note(dv::level_text(s.user_level)))
            .child(wrap_row().child(act(
                s.busy,
                id("dt", "user-create"),
                "Create user",
                BtnKind::Primary,
                move |this, cx| this.data_user_create(target.clone(), cx),
                cx,
            )))
    }

    fn limit_form(&self, db: &str, user: &str, current: u32, cx: &mut Context<Self>) -> Div {
        let (d, u) = (db.to_string(), user.to_string());
        div()
            .flex()
            .items_end()
            .gap(px(12.))
            .p(px(12.))
            .child(div().flex().flex_col().flex_1().min_w_0().child(field(
                &format!("Connection limit of {db}/{user}"),
                Some("1 to 500. Passwords and level are untouched."),
                self.site_data.limit_in.clone(),
            )))
            .child(
                div()
                    .flex()
                    .gap(px(8.))
                    .pb(px(18.))
                    .child(act(
                        self.site_data.busy,
                        id("dt", "limit-save"),
                        "Save",
                        BtnKind::Primary,
                        move |this, cx| this.data_user_limit(d.clone(), u.clone(), current, cx),
                        cx,
                    ))
                    .child(act(
                        false,
                        id("dt", "limit-cancel"),
                        "Cancel",
                        BtnKind::Plain,
                        |this, _| this.site_data.limit_edit = None,
                        cx,
                    )),
            )
    }

    fn data_links_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.site_data;
        let busy = s.busy;
        let rows: Vec<Vec<AnyElement>> = dv::link_rows(&l.view.links)
            .into_iter()
            .map(|link| {
                let (target, var) = (link.target, link.var.clone());
                let remove = act(
                    busy,
                    id("dt-link-del", format!("{}-{}", link.target.as_str(), link.var)),
                    "Remove",
                    BtnKind::Plain,
                    move |this, _| {
                        let victim = var.clone();
                        this.ask(Confirm {
                            title: "Remove link".into(),
                            message: format!(
                                "Remove {victim} ({}) from the site? It stops applying on the next redeploy.",
                                target.as_str()
                            ),
                            label: "Remove".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.data_link_delete(target, victim, cx)),
                        });
                    },
                    cx,
                );
                vec![
                    cell_mono(link.var.clone()),
                    cell_text(dv::target_label(link.target)),
                    cell_text(dv::link_label(&link)),
                    if link.shadows_doppler {
                        tip(
                            pill("shadows Doppler", Tone::Warn),
                            id("dt-shadow", format!("{}-{}", link.target.as_str(), link.var)),
                            "A Doppler variable with this name is replaced by the link.",
                        )
                        .into_any_element()
                    } else {
                        cell_text("")
                    },
                    remove,
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Variable", 230.),
            Col::fixed("Target", 80.),
            Col::flex("Source").min(200.),
            Col::fixed("Note", 140.),
            Col::fixed("", 90.),
        ];
        let mut body = stack(14.).child(wide(
            id("dt-links", "table"),
            760.,
            table(
                &cols,
                rows,
                Some(empty_state(
                    "No linked variables",
                    "Apply a preset below to link a database into the site.",
                )),
            ),
        ));
        let open = s.link_open;
        body = body.child(wrap_row().child(act(
            false,
            id("dt", "link-open"),
            if open { "Close form" } else { "Add link" },
            BtnKind::Plain,
            move |this, _| {
                this.site_data.link_open = !open;
                this.site_data.link_conflicts.clear();
                this.site_data.error = None;
            },
            cx,
        )));
        if open {
            body = body.child(self.link_form(l, cx));
        }
        body = body.child(self.preset_picker(l, cx));
        card(
            Some("Env links"),
            Some("Variables the node fills from a data resource at deploy time. Values are never shown."),
            body,
        )
        .into_any_element()
    }

    // Links one resource field to one variable: resource, user where it applies, field, variable name and target.
    fn link_form(&self, l: &Loaded, cx: &mut Context<Self>) -> Div {
        let s = &self.site_data;
        let o = self.link_options(l);
        let mut kinds = Vec::new();
        for kind in &o.kinds {
            let picked = *kind;
            kinds.push(
                seg_item(id("dt-lkind", kind.label()), kind.label(), picked == o.kind)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let s = &mut this.site_data;
                        s.link_kind = picked;
                        s.link_name.clear();
                        s.link_field.clear();
                        s.link_conflicts.clear();
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut col = stack(10.)
            .p(px(12.))
            .child(strong("Add link").text_size(px(font::SM)))
            .child(note("Delivers one value of a resource to an env variable. Nothing is shown, only linked."))
            .child(seg_row(kinds));
        match o.kind {
            LinkKind::Postgres => {
                col = col
                    .child(note("Database"))
                    .child(pick_row(
                        "dt-ldb",
                        &o.databases,
                        &o.db,
                        |s, v| {
                            s.link_db = v;
                            s.link_user.clear();
                        },
                        cx,
                    ))
                    .child(note("User (its level decides what the app may do)"))
                    .child(pick_row(
                        "dt-luser",
                        &o.users,
                        &o.user,
                        |s, v| s.link_user = v,
                        cx,
                    ));
            }
            LinkKind::External | LinkKind::S3 | LinkKind::Secret => {
                col = col.child(note("Resource")).child(pick_row(
                    "dt-lname",
                    &o.names,
                    &o.name,
                    |s, v| s.link_name = v,
                    cx,
                ));
            }
            LinkKind::SiteUrl => {
                col = col.child(note(
                    "Links https:// followed by the first host of the site.",
                ));
            }
        }
        if !o.fields.is_empty() {
            col = col.child(note("Field")).child(pick_row(
                "dt-lfield",
                &o.fields,
                &o.field,
                |s, v| s.link_field = v,
                cx,
            ));
        }
        let mut targets = Vec::new();
        for sel in [
            LinkTargetSel::Runtime,
            LinkTargetSel::Build,
            LinkTargetSel::Both,
        ] {
            targets.push(
                seg_item(
                    id("dt-ltarget", dv::target_sel_label(sel)),
                    dv::target_sel_label(sel),
                    s.link_target == sel,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.site_data.link_target = sel;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        col = col
            .child(note("Target"))
            .child(seg_row(targets))
            .child(field(
                "Variable",
                Some("Capital letters, digits and underscores. Blank suggests a name."),
                s.link_var_in.clone(),
            ));
        if !s.link_conflicts.is_empty() {
            col = col
                .child(notice(&dv::conflict_summary(&s.link_conflicts), Tone::Warn))
                .child(note(&dv::conflict_lines(&s.link_conflicts).join("; ")));
            if dv::can_override(&s.link_conflicts) {
                col = col.child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .child(
                            checkbox(id("dt", "link-override"), s.link_override).on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.site_data.link_override = !this.site_data.link_override;
                                    cx.notify();
                                }),
                            ),
                        )
                        .child(div().child("Override: delete the manual values named above")),
                );
            }
        }
        col.child(wrap_row().child(act(
            s.busy,
            id("dt", "link-add"),
            "Add link",
            BtnKind::Primary,
            |this, cx| this.data_link_add(cx),
            cx,
        )))
    }

    fn preset_picker(&self, l: &Loaded, cx: &mut Context<Self>) -> Div {
        let s = &self.site_data;
        if l.view.postgres.is_none() {
            return stack(6.).child(note("Presets need Postgres. Enable it above first."));
        }
        let mut items = Vec::new();
        for (preset, label, _) in dv::PRESETS {
            let active = s.preset == Some(preset);
            items.push(
                seg_item(id("dt-preset", label), label, active)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.site_data.preset = if active { None } else { Some(preset) };
                        this.site_data.override_manual = false;
                        this.site_data.error = None;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut col = stack(10.)
            .child(strong("Presets").text_size(px(font::SM)))
            .child(seg_row(items));
        let Some(preset) = s.preset else {
            return col.child(note(
                "Pick a preset to preview the links, users and secrets it would create.",
            ));
        };
        let opts = PresetOpts::default();
        let (runtime, build) = self.manual_env();
        let preview = dv::preset_preview(preset, &opts, &l.view, &runtime, &build);
        col = col.child(note(dv::preset_summary(preset)));
        if let Some(problem) = &preview.problem {
            col = col.child(notice(problem, Tone::Bad));
        }
        let mut creates: Vec<String> = Vec::new();
        creates.extend(preview.databases.iter().map(|d| format!("database {d}")));
        creates.extend(preview.users.iter().map(|u| {
            format!(
                "user {}/{} ({})",
                u.database,
                u.user,
                dv::level_label(u.level).to_lowercase()
            )
        }));
        creates.extend(preview.secrets.iter().map(|n| format!("secret {n}")));
        if !creates.is_empty() {
            col = col.child(note(&format!("Creates {}.", creates.join(", "))));
        }
        let rows: Vec<Vec<AnyElement>> = preview
            .links
            .iter()
            .map(|(link, state)| {
                let (text, tone) = dv::link_state_text(*state);
                vec![
                    cell_mono(dv::spec_link_text(link)),
                    pill(text, tone).into_any_element(),
                ]
            })
            .collect();
        let cols = [Col::flex("Link").min(260.), Col::fixed("State", 130.)];
        col = col.child(wide(
            id("dt-preview", "table"),
            440.,
            table(&cols, rows, None),
        ));
        if preview.needs_override() {
            col = col
                .child(notice(
                    &dv::conflict_summary(&preview.conflicts),
                    Tone::Warn,
                ))
                .child(note(&dv::conflict_lines(&preview.conflicts).join("; ")));
            col =
                col.child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .child(checkbox(id("dt", "override"), s.override_manual).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.site_data.override_manual = !this.site_data.override_manual;
                                cx.notify();
                            }),
                        ))
                        .child(div().child("Override: delete the manual values named above")),
                );
        }
        let ready = preview.problem.is_none()
            && !preview.is_noop()
            && (!preview.needs_override() || s.override_manual);
        let apply = if ready {
            act(
                s.busy,
                id("dt", "preset-apply"),
                "Apply preset",
                BtnKind::Primary,
                move |this, cx| this.data_apply_preset(preset, cx),
                cx,
            )
        } else {
            btn_off("Apply preset").into_any_element()
        };
        col.child(wrap_row().child(apply).child(act(
            false,
            id("dt", "preset-cancel"),
            "Cancel",
            BtnKind::Plain,
            |this, _| this.site_data.preset = None,
            cx,
        )))
    }

    fn data_secrets_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.site_data;
        let busy = s.busy;
        let rows: Vec<Vec<AnyElement>> = l
            .view
            .secrets
            .iter()
            .map(|secret| {
                let name = secret.name.clone();
                let rotate = {
                    let name = name.clone();
                    act(
                        busy,
                        id("dt-secret-rot", &name),
                        "Rotate",
                        BtnKind::Plain,
                        move |this, _| {
                            let target = name.clone();
                            this.ask(Confirm {
                                title: format!("Rotate {target}"),
                                message: dv::rotate_secret_text(&target),
                                label: "Rotate".into(),
                                danger: dv::is_auth_secret(&target),
                                action: Box::new(move |this, cx| {
                                    this.data_secret_rotate(target, cx)
                                }),
                            });
                        },
                        cx,
                    )
                };
                let delete = match dv::delete_blocked_reason(&secret.linked_by) {
                    Some(reason) => blocked(id("dt-secret-del", &name), "Delete", &reason),
                    None => {
                        let name = name.clone();
                        act(
                            busy,
                            id("dt-secret-del", &name),
                            "Delete",
                            BtnKind::Danger,
                            move |this, _| {
                                let victim = name.clone();
                                this.ask(Confirm {
                                    title: format!("Delete {victim}"),
                                    message: "The generated value is deleted for good.".into(),
                                    label: "Delete".into(),
                                    danger: true,
                                    action: Box::new(move |this, cx| {
                                        this.data_secret_delete(victim, cx)
                                    }),
                                });
                            },
                            cx,
                        )
                    }
                };
                vec![
                    cell_mono(secret.name.clone()),
                    cell_text(format!("{} bytes", secret.bytes)),
                    cell_text(secret.encoding.as_str()),
                    cell_text(
                        parse_rfc3339_ms(&secret.rotated_at)
                            .map_or_else(|| "-".to_string(), |t| rel_time(now_ms(), t)),
                    ),
                    cell_text(if secret.linked_by.is_empty() {
                        "-".to_string()
                    } else {
                        secret.linked_by.join(", ")
                    }),
                    wrap_row()
                        .gap(px(6.))
                        .child(rotate)
                        .child(delete)
                        .into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Name", 170.),
            Col::fixed("Size", 90.),
            Col::fixed("Encoding", 100.),
            Col::fixed("Rotated", 100.),
            Col::flex("Linked by").min(150.),
            Col::fixed("", 190.),
        ];
        let mut encodings = Vec::new();
        for enc in [SecretEncoding::Base64url, SecretEncoding::Hex] {
            encodings.push(
                seg_item(
                    id("dt-enc", enc.as_str()),
                    enc.as_str(),
                    s.secret_enc == enc,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.site_data.secret_enc = enc;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let body = stack(14.)
            .child(wide(
                id("dt-secrets", "table"),
                820.,
                table(
                    &cols,
                    rows,
                    Some(empty_state(
                        "No generated secrets",
                        "Create one for AUTH_SECRET or a webhook key, then link it to a variable.",
                    )),
                ),
            ))
            .child(form_grid(vec![
                field(
                    "Name",
                    Some("Lowercase letters, digits and dashes."),
                    s.secret_in.clone(),
                )
                .into_any_element(),
                field(
                    "Size in bytes",
                    Some("32 to 128. Blank keeps 32."),
                    s.secret_bytes_in.clone(),
                )
                .into_any_element(),
            ]))
            .child(wrap_row().child(seg_row(encodings)).child(act(
                busy,
                id("dt", "secret-create"),
                "Create secret",
                BtnKind::Primary,
                |this, cx| this.data_secret_create(cx),
                cx,
            )));
        card(
            Some("Generated secrets"),
            Some("Random values the node holds and never shows. Link one to a variable to use it."),
            body,
        )
        .into_any_element()
    }

    fn data_external_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.site_data;
        let busy = s.busy;
        let mut list = stack(10.);
        if l.view.external.is_empty() {
            list = list.child(note("No external database is attached."));
        }
        for ext in &l.view.external {
            let linked: Vec<String> = l
                .view
                .links
                .iter()
                .filter(|k| matches!(&k.source, cite_edge::datamodel::LinkSource::External { name, .. } if *name == ext.name))
                .map(|k| k.var.clone())
                .collect();
            list = list.child(self.external_row(ext, &linked, busy, cx));
        }
        let body = list
            .child(form_grid(vec![
                field(
                    "Name",
                    Some("Saving the same name again replaces its URL."),
                    s.ext_name_in.clone(),
                )
                .into_any_element(),
                field(
                    "Connection URL",
                    Some(dv::WRITE_ONLY_CREDENTIALS),
                    s.ext_url_in.clone(),
                )
                .into_any_element(),
            ]))
            .child(wrap_row().child(act(
                busy,
                id("dt", "ext-save"),
                "Attach database",
                BtnKind::Primary,
                |this, cx| this.data_external_put(cx),
                cx,
            )))
            .child(note(dv::EXTERNAL_EGRESS_NOTE))
            .child(note(dv::EXTERNAL_BACKUP_NOTE));
        card(
            Some("External databases"),
            Some("Postgres you run elsewhere. The URL carries credentials, so it is write-only."),
            body,
        )
        .into_any_element()
    }

    fn external_row(
        &self,
        ext: &ExternalView,
        linked: &[String],
        busy: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let remove = match dv::delete_blocked_reason(linked) {
            Some(reason) => blocked(id("dt-ext-del", &ext.name), "Remove", &reason),
            None => {
                let name = ext.name.clone();
                act(
                    busy,
                    id("dt-ext-del", &ext.name),
                    "Remove",
                    BtnKind::Danger,
                    move |this, _| {
                        let victim = name.clone();
                        this.ask(Confirm {
                            title: format!("Remove {victim}"),
                            message:
                                "The node forgets the URL. The database itself is not touched."
                                    .into(),
                            label: "Remove".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.data_external_delete(victim, cx)),
                        });
                    },
                    cx,
                )
            }
        };
        let mut details = stack(2.).child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(8.))
                .child(strong(ext.name.clone()))
                .child(mono(format!("{}:{}/{}", ext.host, ext.port, ext.database)))
                .children(
                    ext.sslmode
                        .iter()
                        .map(|m| pill(&format!("sslmode {m}"), Tone::Muted)),
                )
                .children(
                    ext.forward_port
                        .iter()
                        .map(|p| pill(&format!("forward port {p}"), Tone::Info)),
                ),
        );
        for warning in &ext.warnings {
            details = details.child(note(warning).text_color(c(Tone::Warn.color())));
        }
        div()
            .flex()
            .items_start()
            .justify_between()
            .gap(px(12.))
            .child(div().flex().flex_col().flex_1().min_w_0().child(details))
            .child(remove)
    }

    fn data_s3_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.site_data;
        let busy = s.busy;
        let mut list = stack(10.);
        if l.view.s3.is_empty() {
            list = list.child(note("No S3 attachment is set."));
        }
        for att in &l.view.s3 {
            list = list.child(self.s3_row(att, busy, cx));
        }
        let editing = s.s3_editing.clone();
        let path_style = s.s3_path_style;
        let body = list
            .child(form_grid(vec![
                field(
                    "Name",
                    Some(if editing.is_some() {
                        "Editing: leave the keys blank to keep the stored ones."
                    } else {
                        "Lowercase letters, digits and dashes."
                    }),
                    s.s3_name_in.clone(),
                )
                .into_any_element(),
                field("Endpoint", None, s.s3_endpoint_in.clone()).into_any_element(),
                field("Bucket", None, s.s3_bucket_in.clone()).into_any_element(),
                field("Region", None, s.s3_region_in.clone()).into_any_element(),
                field(
                    "Access key id",
                    Some(dv::WRITE_ONLY_CREDENTIALS),
                    s.s3_key_in.clone(),
                )
                .into_any_element(),
                field(
                    "Secret access key",
                    Some(dv::WRITE_ONLY_CREDENTIALS),
                    s.s3_secret_in.clone(),
                )
                .into_any_element(),
            ]))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(
                        checkbox(id("dt", "s3-path-style"), path_style).on_click(cx.listener(
                            |this, _, _, cx| {
                                this.site_data.s3_path_style = !this.site_data.s3_path_style;
                                cx.notify();
                            },
                        )),
                    )
                    .child(div().child("Path-style addressing (MinIO and similar)")),
            )
            .child(
                wrap_row()
                    .child(act(
                        busy,
                        id("dt", "s3-save"),
                        if editing.is_some() {
                            "Save changes"
                        } else {
                            "Add attachment"
                        },
                        BtnKind::Primary,
                        |this, cx| this.data_s3_put(cx),
                        cx,
                    ))
                    .children(editing.map(|_| {
                        act(
                            false,
                            id("dt", "s3-cancel"),
                            "Cancel",
                            BtnKind::Plain,
                            |this, cx| this.clear_s3_form(cx),
                            cx,
                        )
                    })),
            );
        card(
            Some("S3 attachments"),
            Some("Object storage the site can use. The keys are write-only and linked into the site by variable."),
            body,
        )
        .into_any_element()
    }

    fn s3_row(&self, att: &S3View, busy: bool, cx: &mut Context<Self>) -> Div {
        let edit = {
            let att = att.clone();
            act(
                busy,
                id("dt-s3-edit", &att.name),
                "Edit",
                BtnKind::Plain,
                move |this, cx| this.data_s3_edit(&att, cx),
                cx,
            )
        };
        let remove = match dv::delete_blocked_reason(&att.linked_by) {
            Some(reason) => blocked(id("dt-s3-del", &att.name), "Remove", &reason),
            None => {
                let name = att.name.clone();
                act(
                    busy,
                    id("dt-s3-del", &att.name),
                    "Remove",
                    BtnKind::Danger,
                    move |this, _| {
                        let victim = name.clone();
                        this.ask(Confirm {
                            title: format!("Remove {victim}"),
                            message: "The node forgets the keys. The bucket itself is not touched."
                                .into(),
                            label: "Remove".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.data_s3_delete(victim, cx)),
                        });
                    },
                    cx,
                )
            }
        };
        let details = stack(2.)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.))
                    .child(strong(att.name.clone()))
                    .child(mono(format!("{} / {}", att.bucket, att.region)))
                    .child(pill(
                        if att.has_keys {
                            "keys stored"
                        } else {
                            "no keys"
                        },
                        if att.has_keys { Tone::Ok } else { Tone::Warn },
                    ))
                    .children(att.path_style.then(|| pill("path style", Tone::Muted))),
            )
            .child(note(&att.endpoint));
        div()
            .flex()
            .items_start()
            .justify_between()
            .gap(px(12.))
            .child(div().flex().flex_col().flex_1().min_w_0().child(details))
            .child(wrap_row().child(edit).child(remove))
    }

    fn data_backups_card(&self, l: &Loaded, site: &str, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.site_data;
        let busy = s.busy;
        let keys = dv::backup_databases(&l.view);
        let mut dbs = Vec::new();
        for key in &keys {
            let (picked, shown) = (key.clone(), dv::database_name(key).to_string());
            dbs.push(
                seg_item(
                    id("dt-bdb", key),
                    &shown,
                    s.backup_db.as_deref() == Some(key.as_str()),
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.site_data.backup_db = Some(picked.clone());
                    this.site_data.backup_sel = None;
                    this.site_data.label_edit = None;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let current = s.backup_db.clone();
        let external = current.as_deref().is_some_and(dv::is_external_key);
        let policy = l.view.postgres.as_ref().map(|pg| pg.backup.clone());
        let s3_target = policy.as_ref().and_then(|p| p.s3.as_ref()).is_some();
        let mut body = stack(14.)
            .child(note(dv::KEY_BACKUP_NOTE))
            .child(seg_row(dbs));
        if external {
            body = body.child(note(dv::EXTERNAL_BACKUP_NOTE));
        }
        let mut create = wrap_row().child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(220.))
                .child(s.backup_label_in.clone()),
        );
        if s3_target {
            let on = s.backup_push;
            create = create.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(checkbox(id("dt", "backup-push"), on).on_click(cx.listener(
                        |this, _, _, cx| {
                            this.site_data.backup_push = !this.site_data.backup_push;
                            cx.notify();
                        },
                    )))
                    .child(div().child("Also copy to S3")),
            );
        }
        create = create.child(act(
            busy,
            id("dt", "backup-now"),
            "Back up now",
            BtnKind::Primary,
            |this, cx| this.data_backup_create(cx),
            cx,
        ));
        body = body.child(create);
        let records = dv::backup_rows(&l.backups, current.as_deref());
        let now = now_ms();
        let mut rows: Vec<Vec<AnyElement>> = Vec::new();
        for rec in &records {
            let selected = s.backup_sel.as_deref() == Some(rec.id.as_str());
            let pick = rec.id.clone();
            let version = div()
                .flex()
                .items_center()
                .gap(px(6.))
                .child(mono(format!("v{}", rec.version)))
                .children(rec.pinned.then(|| pill("pinned", Tone::Info)))
                .into_any_element();
            let where_ = dv::locations(rec).join(", ");
            let select = act(
                false,
                id("dt-bsel", &rec.id),
                if selected { "Selected" } else { "Select" },
                if selected {
                    BtnKind::Primary
                } else {
                    BtnKind::Plain
                },
                move |this, _| {
                    this.site_data.backup_sel = if selected { None } else { Some(pick.clone()) };
                    this.site_data.label_edit = None;
                },
                cx,
            );
            rows.push(vec![
                version,
                cell_text(
                    parse_rfc3339_ms(&rec.created_at)
                        .map_or_else(|| rec.created_at.clone(), |t| rel_time(now, t)),
                ),
                cell_text(dv::trigger_label(rec.trigger)),
                cell_text(rec.label.clone().unwrap_or_default()),
                cell_text(fmt_bytes(rec.size_bytes)),
                cell_mono(dv::short_sha(&rec.sha256)),
                pill(dv::status_text(rec.status), dv::status_tone(rec.status)).into_any_element(),
                cell_text(if where_.is_empty() {
                    "-".to_string()
                } else {
                    where_
                }),
                select,
            ]);
        }
        let cols = [
            Col::fixed("Version", 100.),
            Col::fixed("Created", 90.),
            Col::fixed("Trigger", 110.),
            Col::flex("Label").min(150.),
            Col::fixed("Size", 80.),
            Col::fixed("SHA-256", 90.),
            Col::fixed("Status", 100.),
            Col::fixed("Where", 90.),
            Col::fixed("", 100.),
        ];
        body = body.child(wide(
            id("dt-backups", "table"),
            1000.,
            table(
                &cols,
                rows,
                Some(empty_state(
                    "No backups yet",
                    "Back up now to create version 1.",
                )),
            ),
        ));
        if let Some(rec) = s.backup_sel.as_deref().and_then(|b| self.backup_record(b)) {
            body = body.child(self.backup_actions(&rec, site, !l.targets.is_empty(), cx));
        }
        if let Some(p) = &policy {
            body = body.child(self.policy_editor(p, l, cx));
        }
        card(
            Some("Backups"),
            Some("Numbered, encrypted versions of each database, kept on the node and optionally in S3."),
            body,
        )
        .into_any_element()
    }

    fn backup_actions(
        &self,
        rec: &BackupRecord,
        site: &str,
        has_target: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let s = &self.site_data;
        let busy = s.busy;
        let mut bar = wrap_row();
        let key = rec.id.clone();
        if dv::can_download(rec) {
            let r = rec.clone();
            bar = bar.child(act(
                busy,
                id("dt-bdl", &key),
                "Download",
                BtnKind::Plain,
                move |this, cx| this.data_backup_download(r.clone(), cx),
                cx,
            ));
        }
        if dv::can_restore(rec) {
            let (r, site) = (rec.clone(), site.to_string());
            bar = bar.child(act(
                busy,
                id("dt-brs", &key),
                "Restore",
                BtnKind::Plain,
                move |this, _| {
                    let rec = r.clone();
                    this.ask(Confirm {
                        title: format!("Restore version {}", rec.version),
                        message: dv::restore_text(&rec, &site),
                        label: "Restore".into(),
                        danger: true,
                        action: Box::new(move |this, cx| this.data_backup_restore(rec, cx)),
                    });
                },
                cx,
            ));
        }
        if dv::can_push(rec, has_target) {
            let r = rec.clone();
            bar = bar.child(act(
                busy,
                id("dt-bpush", &key),
                "Push to S3",
                BtnKind::Plain,
                move |this, cx| this.data_backup_push(r.clone(), cx),
                cx,
            ));
        }
        let (pin_id, pinned) = (rec.id.clone(), rec.pinned);
        bar = bar.child(act(
            busy,
            id("dt-bpin", &key),
            if pinned { "Unpin" } else { "Pin" },
            BtnKind::Plain,
            move |this, cx| this.data_backup_pin(pin_id.clone(), !pinned, cx),
            cx,
        ));
        let (label_id, label_now) = (rec.id.clone(), rec.label.clone().unwrap_or_default());
        bar = bar.child(act(
            busy,
            id("dt-blabel", &key),
            "Label",
            BtnKind::Plain,
            move |this, cx| {
                this.site_data.label_edit = Some(label_id.clone());
                this.site_data
                    .label_in
                    .update(cx, |i, cx| i.set_text(&label_now, cx));
            },
            cx,
        ));
        let delete = match dv::delete_backup_block(rec) {
            Some(reason) => blocked(id("dt-bdel", &key), "Delete", reason),
            None => {
                let r = rec.clone();
                act(
                    busy,
                    id("dt-bdel", &key),
                    "Delete",
                    BtnKind::Danger,
                    move |this, _| {
                        let rec = r.clone();
                        this.ask(Confirm {
                            title: format!("Delete version {}", rec.version),
                            message: dv::delete_backup_text(&rec),
                            label: "Delete".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.data_backup_delete(rec, cx)),
                        });
                    },
                    cx,
                )
            }
        };
        bar = bar.child(delete);
        let mut col = stack(10.).p(px(12.)).child(
            strong(format!(
                "Version {} of {}",
                rec.version,
                dv::database_name(&rec.database)
            ))
            .text_size(px(font::SM)),
        );
        if let Some(error) = &rec.error {
            col = col.child(notice(error, Tone::Bad));
        }
        col = col.child(bar);
        if s.label_edit.as_deref() == Some(rec.id.as_str()) {
            let id_now = rec.id.clone();
            col = col.child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(12.))
                    .child(div().flex().flex_col().flex_1().min_w_0().child(field(
                        "Label",
                        Some("At most 100 characters. Empty clears it."),
                        s.label_in.clone(),
                    )))
                    .child(div().pb(px(18.)).child(act(
                        busy,
                        id("dt", "label-save"),
                        "Save label",
                        BtnKind::Primary,
                        move |this, cx| this.data_backup_label(id_now.clone(), cx),
                        cx,
                    ))),
            );
        }
        col
    }

    fn policy_editor(
        &self,
        policy: &cite_edge::datamodel::BackupPolicy,
        l: &Loaded,
        cx: &mut Context<Self>,
    ) -> Div {
        let s = &self.site_data;
        let busy = s.busy;
        let mut col = stack(10.)
            .child(strong("Schedule and retention").text_size(px(font::SM)))
            .child(note(&dv::schedule_text(policy.schedule.as_ref())))
            .child(note(&format!(
                "Node copies: {}",
                dv::retention_text(&policy.local)
            )));
        if let Some(copy) = &policy.s3 {
            col = col.child(note(&format!(
                "S3 copies in {}: {}",
                target_name(&l.targets, &copy.target),
                dv::retention_text(&copy.retention)
            )));
        }
        let policy_clone = policy.clone();
        let edit = act(
            busy,
            id("dt", "policy-edit"),
            if s.policy_open {
                "Close editor"
            } else {
                "Edit policy"
            },
            BtnKind::Plain,
            move |this, cx| {
                if this.site_data.policy_open {
                    this.site_data.policy_open = false;
                    this.site_data.policy = None;
                } else {
                    this.data_policy_open(&policy_clone, cx);
                }
            },
            cx,
        );
        let preview = act(
            busy,
            id("dt", "prune-preview"),
            "Preview prune",
            BtnKind::Plain,
            |this, cx| this.data_prune_preview(cx),
            cx,
        );
        col = col.child(wrap_row().child(edit).child(preview));
        if let Some(previews) = &s.prune {
            let mut lines = stack(4.).child(notice(&dv::prune_summary(previews), Tone::Info));
            for p in previews {
                for line in dv::prune_lines(p, &l.backups) {
                    lines = lines.child(note(&line));
                }
            }
            let nothing = dv::prune_total(previews, false) + dv::prune_total(previews, true) == 0;
            let run = if nothing {
                btn_off("Prune now").into_any_element()
            } else {
                act(
                    busy,
                    id("dt", "prune-run"),
                    "Prune now",
                    BtnKind::Danger,
                    |this, _| {
                        this.ask(Confirm {
                            title: "Prune backups".into(),
                            message: "Deletes the versions the preview listed, on the node and in S3. Pinned and the newest complete versions are kept.".into(),
                            label: "Prune".into(),
                            danger: true,
                            action: Box::new(|this, cx| this.data_prune(cx)),
                        });
                    },
                    cx,
                )
            };
            col = col.child(lines).child(wrap_row().child(run));
        }
        if s.policy_open
            && let Some(draft) = &s.policy
        {
            col = col.child(self.policy_form(draft, l, cx));
        }
        col
    }

    fn policy_form(&self, draft: &PolicyDraft, l: &Loaded, cx: &mut Context<Self>) -> Div {
        let s = &self.site_data;
        let scheduled = draft.scheduled;
        let mut hours = Vec::new();
        for h in cite_edge::datamodel::BACKUP_EVERY_HOURS {
            hours.push(
                seg_item(id("dt-every", h), &format!("{h}h"), draft.every_hours == h)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(d) = this.site_data.policy.as_mut() {
                            d.every_hours = h;
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut col = stack(10.).p(px(12.)).child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(
                    checkbox(id("dt", "policy-scheduled"), scheduled).on_click(cx.listener(
                        |this, _, _, cx| {
                            if let Some(d) = this.site_data.policy.as_mut() {
                                d.scheduled = !d.scheduled;
                            }
                            cx.notify();
                        },
                    )),
                )
                .child(div().child("Back up on a schedule")),
        );
        if scheduled {
            col = col
                .child(note("Every how many hours (UTC), at the minute below."))
                .child(seg_row(hours))
                .child(form_grid(vec![
                    field("Minute", Some("0 to 59"), s.minute_in.clone()).into_any_element(),
                ]));
        }
        col = col
            .child(strong("Node copies").text_size(px(font::SM)))
            .child(retention_grid(&s.local_in))
            .child(note(dv::BUCKET_EXPLANATION));
        let on_s3 = draft.s3_target.is_some();
        let mut targets = vec![
            seg_item(id("dt-s3t", "none"), "No S3 copies", !on_s3)
                .on_click(cx.listener(|this, _, _, cx| {
                    if let Some(d) = this.site_data.policy.as_mut() {
                        d.s3_target = None;
                    }
                    cx.notify();
                }))
                .into_any_element(),
        ];
        for t in &l.targets {
            let picked = t.id.clone();
            targets.push(
                seg_item(
                    id("dt-s3t", &t.id),
                    &t.name,
                    draft.s3_target.as_deref() == Some(t.id.as_str()),
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(d) = this.site_data.policy.as_mut() {
                        d.s3_target = Some(picked.clone());
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        col = col
            .child(strong("S3 copies").text_size(px(font::SM)))
            .child(seg_row(targets));
        if l.targets.is_empty() {
            col = col.child(note(
                "Add a backup target on the Databases page to keep copies in S3.",
            ));
        }
        if on_s3 {
            col = col.child(retention_grid(&s.s3_ret_in));
        }
        col.child(wrap_row().child(act(
            s.busy,
            id("dt", "policy-save"),
            "Save policy",
            BtnKind::Primary,
            |this, cx| this.data_policy_save(cx),
            cx,
        )))
    }
}

// The picks of the add-link form with the one in effect for each.
struct LinkOptions {
    kinds: Vec<LinkKind>,
    kind: LinkKind,
    databases: Vec<String>,
    db: String,
    users: Vec<String>,
    user: String,
    names: Vec<String>,
    name: String,
    fields: Vec<String>,
    field: String,
}

// The wanted pick when it is on offer, else the first choice, else nothing.
fn pick(want: &str, list: &[String]) -> String {
    if list.iter().any(|x| x == want) {
        want.to_string()
    } else {
        list.first().cloned().unwrap_or_default()
    }
}

// One segment per choice; `set` stores the one pressed.
fn pick_row(
    key: &'static str,
    items: &[String],
    current: &str,
    set: fn(&mut SiteDataState, String),
    cx: &mut Context<Console>,
) -> AnyElement {
    let mut row = Vec::new();
    for item in items {
        let value = item.clone();
        row.push(
            seg_item(id(key, item), item, item == current)
                .on_click(cx.listener(move |this, _, _, cx| {
                    set(&mut this.site_data, value.clone());
                    cx.notify();
                }))
                .into_any_element(),
        );
    }
    seg_row(row).into_any_element()
}

fn target_name(targets: &[TargetView], id: &str) -> String {
    targets
        .iter()
        .find(|t| t.id == id)
        .map_or_else(|| id.to_string(), |t| t.name.clone())
}

// The five retention numbers of one tier, labelled as the node validates them.
fn retention_grid(inputs: &[Entity<TextInput>]) -> Div {
    let cells: Vec<AnyElement> = dv::RETENTION_FIELDS
        .iter()
        .zip(inputs)
        .map(|(f, input)| {
            field(
                f.label,
                Some(&format!("{} to {}", f.min, f.max)),
                input.clone(),
            )
            .into_any_element()
        })
        .collect();
    form_grid(cells)
}

// Reads what the node offers and, when it offers data services, everything the tab shows. None means the node has none.
async fn read_site_data(h: NodeHandle, site: String) -> Result<Option<Loaded>, ClientError> {
    let caps = h
        .node_info()
        .await
        .ok()
        .map(|i| i.capabilities)
        .unwrap_or_default();
    if !dv::data_tab_offered(&caps) {
        return Ok(None);
    }
    let view = h.site_data(&site).await?;
    let backups_on = has_cap(&caps, dv::CAP_DATA_BACKUPS);
    let (backups, targets) = tokio::join!(
        async {
            if backups_on {
                h.site_backups(&site, None).await.unwrap_or_default()
            } else {
                Vec::new()
            }
        },
        async {
            if backups_on {
                h.data_targets().await.unwrap_or_default()
            } else {
                Vec::new()
            }
        }
    );
    Ok(Some(Loaded {
        view,
        backups,
        targets,
        caps,
    }))
}
