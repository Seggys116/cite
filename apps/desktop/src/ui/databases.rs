// The node-level Databases page: the shared Postgres instance and its tenants, whole-instance backups, the S3 targets backups are
// copied to, and the leftovers of deleted sites. Like the Data tab, nothing secret is ever shown: target keys are write-only.

use std::collections::BTreeMap;
use std::future::Future;

use cite_client::ClientError;
use cite_edge::datawire::{
    DataNodeView, InstanceBackupRecord, JobAccepted, OrphanView, SharedView, TargetView,
};
use gpui::{AnyElement, Context, Div, Entity, div, prelude::*, px};

use crate::api::NodeHandle;
use crate::app::{Confirm, Console, View, new_input};
use crate::bots::downloads_dir;
use crate::demo::now_ms;
use crate::model::{fmt_bytes, parse_rfc3339_ms, rel_time};
use crate::scope::Sequence;
use crate::siteops::has_cap;
use crate::theme::{Tone, font};
use crate::ui::chart::wide;
use crate::ui::datahandle::run_instance_backup_download;
use crate::ui::dataview::{self as dv, S3Form};
use crate::ui::detail::data::{
    Done, act, blocked, cell_mono, cell_text, kv, note, stack, tradeoff_table, wrap_row,
};
use crate::ui::input::TextInput;
use crate::ui::nodescope::{NodeScope, choose_node_notice, failed_on, no_node_notice, on_node};
use crate::ui::widgets::{
    BtnKind, Col, card, checkbox, dot, empty_state, field, form_grid, id, mono, notice,
    page_header, pill, seg_item, seg_row, skeleton, strong, table, text_dim,
};

// Moving a database between nodes and converting it on one node: the store, the driver glue and the cards.
#[path = "transfers.rs"]
pub(crate) mod transfers;

// What the page learned from the node.
pub struct Loaded {
    pub node: DataNodeView,
    // The shared instance with its tenants, when the node has one.
    pub shared: Option<SharedView>,
    pub targets: Vec<TargetView>,
    pub orphans: Vec<OrphanView>,
    pub backups: Vec<InstanceBackupRecord>,
    pub caps: Vec<String>,
}

impl Loaded {
    fn shared_on(&self) -> Option<&SharedView> {
        self.shared.as_ref().filter(|s| s.enabled)
    }
}

pub enum DbLoad {
    Idle,
    Loading,
    // The node offers no database service.
    Absent,
    Failed(String),
    Ready(Box<Loaded>),
}

pub struct State {
    pub scope: NodeScope,
    pub load: DbLoad,
    pub for_node: String,
    pub seq: Sequence,
    pub busy: bool,
    pub error: Option<String>,
    pub major: u8,
    pub memory_in: Entity<TextInput>,
    pub cpus_in: Entity<TextInput>,
    pub conns_in: Entity<TextInput>,
    pub limits_open: bool,
    pub t_form_open: bool,
    pub t_name_in: Entity<TextInput>,
    pub t_endpoint_in: Entity<TextInput>,
    pub t_bucket_in: Entity<TextInput>,
    pub t_region_in: Entity<TextInput>,
    pub t_prefix_in: Entity<TextInput>,
    pub t_key_in: Entity<TextInput>,
    pub t_secret_in: Entity<TextInput>,
    pub t_path_style: bool,
    pub t_encrypt: bool,
    // The target being edited: its keys may stay blank to keep the stored ones.
    pub t_editing: Option<String>,
    // The last test of each target: whether it passed, and what to say.
    pub tests: BTreeMap<String, (bool, String)>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            scope: NodeScope::default(),
            load: DbLoad::Idle,
            for_node: String::new(),
            seq: Sequence::default(),
            busy: false,
            error: None,
            major: dv::DEFAULT_MAJOR,
            memory_in: new_input(cx, "1024", |i| i.mono()),
            cpus_in: new_input(cx, "1", |i| i.mono()),
            conns_in: new_input(cx, "200", |i| i.mono()),
            limits_open: false,
            t_form_open: false,
            t_name_in: new_input(cx, "Offsite archive", |i| i),
            t_endpoint_in: new_input(cx, "https://s3.eu-central-1.amazonaws.com", |i| i.mono()),
            t_bucket_in: new_input(cx, "cite-backups", |i| i.mono()),
            t_region_in: new_input(cx, "eu-central-1", |i| i.mono()),
            t_prefix_in: new_input(cx, "edge-fra (optional)", |i| i.mono()),
            t_key_in: new_input(cx, "Access key id", |i| i.masked().mono()),
            t_secret_in: new_input(cx, "Secret access key", |i| i.masked().mono()),
            t_path_style: false,
            t_encrypt: true,
            t_editing: None,
            tests: BTreeMap::new(),
        }
    }

    fn target_inputs(&self) -> [Entity<TextInput>; 7] {
        [
            self.t_name_in.clone(),
            self.t_endpoint_in.clone(),
            self.t_bucket_in.clone(),
            self.t_region_in.clone(),
            self.t_prefix_in.clone(),
            self.t_key_in.clone(),
            self.t_secret_in.clone(),
        ]
    }
}

impl Console {
    // The node the page acts on, and its connection when it is reachable.
    pub(crate) fn dbs_node(&self) -> Option<String> {
        self.scoped_node(&self.dbs.scope)
    }

    fn dbs_handle(&self) -> Option<NodeHandle> {
        self.scoped_handle(&self.dbs.scope)
    }

    // Picking a node on the bar drops everything loaded for the old one and loads the new one.
    fn choose_dbs_node(&mut self, name: String, cx: &mut Context<Self>) {
        if self.dbs_node().as_deref() == Some(name.as_str()) {
            return;
        }
        let selected = self.selected.clone();
        self.dbs.scope.choose(&name, selected.as_deref());
        self.dbs_reset(cx);
        self.scope.advance();
        self.load_databases(cx);
    }

    pub fn dbs_reset(&mut self, cx: &mut Context<Self>) {
        self.clear_target_form(cx);
        let d = &mut self.dbs;
        d.load = DbLoad::Idle;
        d.for_node.clear();
        d.busy = false;
        d.error = None;
        d.major = dv::DEFAULT_MAJOR;
        d.limits_open = false;
        d.t_form_open = false;
        d.tests.clear();
    }

    pub fn load_databases(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            self.dbs.load = DbLoad::Idle;
            return;
        };
        let node = h.name().to_string();
        if self.dbs.for_node != node {
            self.dbs_reset(cx);
            self.dbs.for_node = node.clone();
        }
        if !matches!(self.dbs.load, DbLoad::Ready(_)) {
            self.dbs.load = DbLoad::Loading;
        }
        let seq = self.dbs.seq.issue();
        self.fetch_scoped(cx, read_node(h), move |this, res, cx| {
            if this.dbs.for_node != node || !this.dbs.seq.accept(seq) {
                return;
            }
            this.dbs.load = match res {
                Ok(Some(loaded)) => {
                    if !this.dbs.limits_open {
                        this.fill_shared_inputs(loaded.shared_on(), cx);
                    }
                    DbLoad::Ready(Box::new(loaded))
                }
                Ok(None) => DbLoad::Absent,
                Err(e) => DbLoad::Failed(e.to_string()),
            };
            cx.notify();
        });
    }

    // The limit inputs show what the instance runs with, or sensible values to create it with.
    fn fill_shared_inputs(&mut self, shared: Option<&SharedView>, cx: &mut Context<Self>) {
        let (memory, cpus, conns) = match shared {
            Some(s) => (
                s.memory_mb,
                dv::cpus_of(s.nano_cpus).max(0.25),
                s.max_connections,
            ),
            None => (1024, 1.0, 200),
        };
        let d = &self.dbs;
        for (input, text) in [
            (d.memory_in.clone(), memory.to_string()),
            (d.cpus_in.clone(), cpus.to_string()),
            (d.conns_in.clone(), conns.to_string()),
        ] {
            input.update(cx, |i, cx| i.set_text(&text, cx));
        }
    }

    // Runs one change on the node the page shows; the toast names the node and the page reloads only if it is still on it.
    fn dbs_run<T, F>(
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
        let Some(node) = self.dbs_node() else {
            return;
        };
        self.dbs.busy = true;
        self.dbs.error = None;
        let name = node.clone();
        self.fetch_on(
            cx,
            &node,
            Self::dbs_node,
            fut,
            move |this, res, here, cx| {
                this.dbs.busy = false;
                match res {
                    Ok(value) => {
                        let finished = done(&value);
                        if let Some(job) = &finished.job {
                            this.track_job(&name, None, job, what);
                        }
                        this.say(on_node(&finished.message, &name), Tone::Ok);
                        if here {
                            then(this, cx);
                            this.load_databases(cx);
                        }
                    }
                    Err(e) => {
                        let message = e.to_string();
                        if here {
                            this.dbs.error = Some(message);
                        } else {
                            this.say(failed_on(what, &name, &message), Tone::Bad);
                        }
                    }
                }
                cx.notify();
            },
        );
    }

    // ---- actions: the shared instance ----

    fn dbs_shared_save(&mut self, creating: bool, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let d = &self.dbs;
        let memory = d.memory_in.read(cx).text().to_string();
        let cpus = d.cpus_in.read(cx).text().to_string();
        let conns = d.conns_in.read(cx).text().to_string();
        let major = creating.then_some(d.major);
        let req = match dv::shared_req(major, &memory, &cpus, &conns) {
            Ok(r) => r,
            Err(e) => {
                self.dbs.error = Some(e);
                return;
            }
        };
        let fut = async move { h.data_shared_put(&req).await };
        self.dbs_run(
            cx,
            if creating {
                "Enabling the shared instance"
            } else {
                "Changing the limits"
            },
            fut,
            move |a: &JobAccepted| {
                Done::job(
                    a,
                    if creating {
                        "The shared instance is being created"
                    } else {
                        "The limits are being applied"
                    },
                )
            },
            |this, _| this.dbs.limits_open = false,
        );
    }

    fn dbs_shared_restart(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let fut = async move { h.data_shared_restart().await };
        self.dbs_run(
            cx,
            "Restarting the shared instance",
            fut,
            |a: &JobAccepted| Done::job(a, "The shared instance is restarting"),
            |_, _| {},
        );
    }

    fn dbs_shared_delete(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let fut = async move { h.data_shared_delete(false, false).await };
        self.dbs_run(
            cx,
            "Deleting the shared instance",
            fut,
            |a: &JobAccepted| Done::job(a, "The shared instance is being removed"),
            |_, _| {},
        );
    }

    fn dbs_instance_backup(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let fut = async move { h.data_shared_backup().await };
        self.dbs_run(
            cx,
            "Instance backup",
            fut,
            |a: &JobAccepted| Done::job(a, "A whole-instance backup started"),
            |_, _| {},
        );
    }

    fn dbs_instance_backup_delete(&mut self, backup_id: String, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let fut = async move { h.data_shared_backup_delete(&backup_id).await };
        self.dbs_run(
            cx,
            "Deleting an instance backup",
            fut,
            |_: &()| Done::plain("Instance backup deleted"),
            |_, _| {},
        );
    }

    fn dbs_instance_backup_download(&mut self, backup_id: String, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let Some(dir) = downloads_dir() else {
            self.dbs.error = Some(
                "Cannot find your home directory, so there is nowhere to save the file.".into(),
            );
            return;
        };
        let fut = run_instance_backup_download(h, backup_id, dir);
        self.dbs_run(
            cx,
            "Instance backup download",
            fut,
            |report: &cite_client::ExportReport| {
                Done::plain(format!(
                    "Saved {} to {}",
                    fmt_bytes(report.bytes),
                    report.path.display()
                ))
            },
            |_, _| {},
        );
    }

    // ---- actions: backup targets ----

    fn clear_target_form(&mut self, cx: &mut Context<Self>) {
        for input in self.dbs.target_inputs() {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        self.dbs.t_path_style = false;
        self.dbs.t_encrypt = true;
        self.dbs.t_editing = None;
    }

    fn read_target_form(&self, cx: &Context<Self>) -> S3Form {
        let d = &self.dbs;
        let text = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        S3Form {
            name: text(&d.t_name_in),
            endpoint: text(&d.t_endpoint_in),
            bucket: text(&d.t_bucket_in),
            region: text(&d.t_region_in),
            prefix: text(&d.t_prefix_in),
            path_style: d.t_path_style,
            encrypt: d.t_encrypt,
            access_key_id: text(&d.t_key_in),
            secret_access_key: text(&d.t_secret_in),
        }
    }

    // Puts a target's public fields into the form; the keys stay blank and the node keeps the stored ones.
    fn dbs_target_edit(&mut self, target: &TargetView, cx: &mut Context<Self>) {
        self.clear_target_form(cx);
        let d = &mut self.dbs;
        d.t_form_open = true;
        d.t_editing = Some(target.id.clone());
        d.t_path_style = target.path_style;
        d.t_encrypt = target.encrypt;
        for (input, text) in [
            (d.t_name_in.clone(), target.name.clone()),
            (d.t_endpoint_in.clone(), target.endpoint.clone()),
            (d.t_bucket_in.clone(), target.bucket.clone()),
            (d.t_region_in.clone(), target.region.clone()),
            (d.t_prefix_in.clone(), target.prefix.clone()),
        ] {
            input.update(cx, |i, cx| i.set_text(&text, cx));
        }
    }

    fn dbs_target_save(&mut self, has_keys: bool, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let mut form = self.read_target_form(cx);
        if let Some(p) = dv::target_problem(&form, has_keys) {
            form.wipe();
            self.dbs.error = Some(p);
            return;
        }
        let req = dv::target_req(&form);
        form.wipe();
        let editing = self.dbs.t_editing.clone();
        let shown = req.name.clone();
        let fut = async move {
            match editing {
                Some(target_id) => h.data_target_update(&target_id, &req).await,
                None => h.data_target_create(&req).await,
            }
        };
        self.dbs_run(
            cx,
            "Saving a backup target",
            fut,
            move |_: &TargetView| Done::plain(format!("Backup target {shown} saved")),
            |this, cx| {
                this.clear_target_form(cx);
                this.dbs.t_form_open = false;
            },
        );
    }

    fn dbs_target_delete(&mut self, target_id: String, name: String, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let fut = async move { h.data_target_delete(&target_id).await };
        self.dbs_run(
            cx,
            "Deleting a backup target",
            fut,
            move |_: &()| Done::plain(format!("Backup target {name} deleted")),
            |_, _| {},
        );
    }

    fn dbs_target_test(&mut self, target_id: String, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let node = h.name().to_string();
        self.dbs.tests.remove(&target_id);
        let key = target_id.clone();
        self.fetch_on(
            cx,
            &node,
            Self::dbs_node,
            async move { h.data_target_test(&target_id).await },
            move |this, res, here, cx| {
                if here {
                    let result = match res {
                        Ok(r) => (r.ok, dv::target_test_text(&r)),
                        Err(e) => (false, format!("Test failed: {e}")),
                    };
                    this.dbs.tests.insert(key, result);
                }
                cx.notify();
            },
        );
    }

    fn dbs_orphan_purge(&mut self, site: String, cx: &mut Context<Self>) {
        let Some(h) = self.dbs_handle() else {
            return;
        };
        let shown = site.clone();
        let fut = async move { h.data_orphan_purge(&site).await };
        self.dbs_run(
            cx,
            "Purging leftovers",
            fut,
            move |_: &()| Done::plain(format!("The leftovers of {shown} were purged")),
            |_, _| {},
        );
    }

    // ---- render ----

    pub fn render_databases(&self, cx: &mut Context<Self>) -> AnyElement {
        let node = self.dbs_node();
        let subtitle = match &node {
            Some(n) => format!("Postgres, backups and S3 targets of {n}"),
            None => "Postgres, backups and S3 targets of one node".to_string(),
        };
        let bar = self.scope_bar_for("dbs-node", &self.dbs.scope, Self::choose_dbs_node, cx);
        let mut col = stack(16.).child(page_header(
            "Databases",
            &subtitle,
            bar.into_iter().collect(),
        ));
        let Some(node) = node else {
            return col.child(choose_node_notice()).into_any_element();
        };
        if self.dbs_handle().is_none() {
            return col.child(no_node_notice(Some(&node))).into_any_element();
        }
        col = col.children(self.job_banners(&node, None));
        if let Some(e) = &self.dbs.error {
            col = col.child(notice(e, Tone::Bad));
        }
        let loaded = match &self.dbs.load {
            DbLoad::Idle | DbLoad::Loading => {
                return col.child(skeleton(240.)).into_any_element();
            }
            DbLoad::Absent => {
                return col
                    .child(notice(
                        "This node does not offer database services.",
                        Tone::Info,
                    ))
                    .into_any_element();
            }
            DbLoad::Failed(message) => {
                return col.child(self.error_block(cx, message)).into_any_element();
            }
            DbLoad::Ready(loaded) => loaded,
        };
        col = col.child(self.dbs_status_card(loaded, &node));
        if has_cap(&loaded.caps, dv::CAP_DATA_SHARED) {
            col = col.child(self.shared_card(loaded, cx));
            if let Some(shared) = loaded.shared_on() {
                col = col.child(self.tenants_card(shared, &node, cx));
                col = col.child(self.instance_backups_card(loaded, cx));
            }
        }
        if has_cap(&loaded.caps, dv::CAP_DATA_BACKUPS) {
            col = col.child(self.targets_card(loaded, cx));
        }
        col = col.child(self.orphans_card(loaded, cx));
        if has_cap(&loaded.caps, dv::CAP_DATA_TRANSFER) {
            col = col.child(self.transfers_list_card(&node, cx));
        }
        col.into_any_element()
    }

    fn dbs_status_card(&self, l: &Loaded, node: &str) -> AnyElement {
        let n = &l.node;
        let majors = n
            .pg_majors
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let key = if n.key.kid.is_empty() {
            "not created yet".to_string()
        } else {
            format!("{} ({})", n.key.kid, n.key.source)
        };
        let body = stack(8.)
            .child(kv(
                "Data services",
                pill(
                    if n.enabled { "enabled" } else { "off" },
                    if n.enabled { Tone::Ok } else { Tone::Warn },
                ),
            ))
            .child(kv(
                "Backup volume",
                pill(
                    if n.backup_volume_ok {
                        "ready"
                    } else {
                        "not writable"
                    },
                    if n.backup_volume_ok {
                        Tone::Ok
                    } else {
                        Tone::Bad
                    },
                ),
            ))
            .child(kv("Postgres majors", text_dim(majors)))
            .child(kv("Node key", mono(key)))
            .child(note(dv::KEY_BACKUP_NOTE));
        card(
            Some("Data services"),
            Some(&format!("State of {node}")),
            body,
        )
        .into_any_element()
    }

    fn shared_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let d = &self.dbs;
        let sub = "One Postgres instance of the node that sites can use instead of a container of their own.";
        let Some(shared) = l.shared_on() else {
            let body = stack(12.)
                .child(note("The shared instance is not enabled. Sites can only get a dedicated database until you enable it."))
                .child(tradeoff_table("dbs"))
                .child(self.shared_form(true, cx));
            return card(Some("Shared instance"), Some(sub), body).into_any_element();
        };
        let health = if shared.health.is_empty() {
            "unknown".to_string()
        } else {
            shared.health.clone()
        };
        let rows = stack(8.)
            .child(kv(
                "Status",
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .child(dot(dv::health_tone(&shared.health)))
                    .child(text_dim(health)),
            ))
            .child(kv("Postgres major", mono(shared.major.to_string())))
            .child(kv("Memory", text_dim(format!("{} MiB", shared.memory_mb))))
            .child(kv("CPUs", text_dim(dv::cpus_text(shared.nano_cpus))))
            .child(kv(
                "Max connections",
                text_dim(shared.max_connections.to_string()),
            ))
            .child(kv("Size", text_dim(fmt_bytes(shared.size_bytes))))
            .child(kv("Tenants", text_dim(shared.tenants.len().to_string())));
        let open = d.limits_open;
        let limits = act(
            d.busy,
            id("dbs", "limits"),
            if open { "Close" } else { "Edit limits" },
            BtnKind::Plain,
            move |this, _| this.dbs.limits_open = !open,
            cx,
        );
        let restart = act(
            d.busy,
            id("dbs", "restart"),
            "Restart",
            BtnKind::Plain,
            |this, _| {
                this.ask(Confirm {
                    title: "Restart the shared instance".into(),
                    message: "An instance restart interrupts every tenant for a moment.".into(),
                    label: "Restart".into(),
                    danger: true,
                    action: Box::new(|this, cx| this.dbs_shared_restart(cx)),
                });
            },
            cx,
        );
        let delete = match dv::shared_delete_block(shared) {
            Some(reason) => blocked(id("dbs", "delete"), "Delete instance", &reason),
            None => act(
                d.busy,
                id("dbs", "delete"),
                "Delete instance",
                BtnKind::Danger,
                |this, _| {
                    this.ask(Confirm {
                        title: "Delete the shared instance".into(),
                        message: dv::shared_delete_text().to_string(),
                        label: "Delete".into(),
                        danger: true,
                        action: Box::new(|this, cx| this.dbs_shared_delete(cx)),
                    });
                },
                cx,
            ),
        };
        let mut body = rows.child(wrap_row().child(limits).child(restart).child(delete));
        if open {
            body = body.child(self.shared_form(false, cx));
        }
        card(Some("Shared instance"), Some(sub), body).into_any_element()
    }

    // The limits of the shared instance; the major is chosen only when it is created.
    fn shared_form(&self, creating: bool, cx: &mut Context<Self>) -> Div {
        let d = &self.dbs;
        let mut col = stack(10.);
        if creating {
            let mut majors = Vec::new();
            for major in [18u8, 17] {
                majors.push(
                    seg_item(
                        id("dbs-major", major),
                        &format!("Postgres {major}"),
                        d.major == major,
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.dbs.major = major;
                        cx.notify();
                    }))
                    .into_any_element(),
                );
            }
            col = col
                .child(note(
                    "One major for every tenant, fixed once the instance exists.",
                ))
                .child(seg_row(majors));
        }
        col = col.child(form_grid(vec![
            field("Memory (MiB)", Some("256 to 65536"), d.memory_in.clone()).into_any_element(),
            field("CPUs", Some("0.25 to 64"), d.cpus_in.clone()).into_any_element(),
            field("Max connections", Some("10 to 1000"), d.conns_in.clone()).into_any_element(),
        ]));
        if !creating {
            col = col.child(note(dv::SHARED_UPDATE_TEXT));
        }
        let action = if creating {
            act(
                d.busy,
                id("dbs", "enable"),
                "Enable shared instance",
                BtnKind::Primary,
                |this, cx| this.dbs_shared_save(true, cx),
                cx,
            )
        } else {
            act(
                d.busy,
                id("dbs", "apply"),
                "Apply limits",
                BtnKind::Primary,
                |this, _| {
                    this.ask(Confirm {
                        title: "Change the limits".into(),
                        message: dv::SHARED_UPDATE_TEXT.to_string(),
                        label: "Apply".into(),
                        danger: true,
                        action: Box::new(|this, cx| this.dbs_shared_save(false, cx)),
                    });
                },
                cx,
            )
        };
        col.child(wrap_row().child(action))
    }

    fn tenants_card(&self, shared: &SharedView, node: &str, cx: &mut Context<Self>) -> AnyElement {
        let rows: Vec<Vec<AnyElement>> = dv::tenant_rows(shared)
            .into_iter()
            .map(|t| {
                let databases = if t.databases.is_empty() {
                    "-".to_string()
                } else {
                    t.databases
                        .iter()
                        .map(|(name, size)| format!("{name} ({})", fmt_bytes(*size)))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let (node, site) = (node.to_string(), t.site.clone());
                vec![
                    cell_mono(t.site.clone()),
                    cell_text(databases),
                    cell_text(fmt_bytes(t.size_bytes)),
                    act(
                        false,
                        id("dbs-open", &t.site),
                        "Open site",
                        BtnKind::Plain,
                        move |this, cx| {
                            this.navigate(
                                View::SiteDetail {
                                    node: node.clone(),
                                    id: site.clone(),
                                },
                                cx,
                            )
                        },
                        cx,
                    ),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Site", 160.),
            Col::flex("Databases").min(220.),
            Col::fixed("Size", 100.),
            Col::fixed("", 120.),
        ];
        card(
            Some("Tenants"),
            Some("Sites with a database on the shared instance."),
            wide(
                id("dbs-tenants", "table"),
                620.,
                table(
                    &cols,
                    rows,
                    Some(empty_state(
                        "No tenants",
                        "No site uses the shared instance yet.",
                    )),
                ),
            ),
        )
        .into_any_element()
    }

    fn instance_backups_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let busy = self.dbs.busy;
        let now = now_ms();
        let rows: Vec<Vec<AnyElement>> = l
            .backups
            .iter()
            .map(|b| {
                let total: u64 = b.parts.iter().map(|p| p.size_bytes).sum();
                let names = b
                    .parts
                    .iter()
                    .map(|p| p.database.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                let (download_id, delete_id) = (b.id.clone(), b.id.clone());
                let actions = wrap_row()
                    .gap(px(6.))
                    .child(act(
                        busy,
                        id("dbs-ibdl", &b.id),
                        "Download",
                        BtnKind::Plain,
                        move |this, cx| this.dbs_instance_backup_download(download_id.clone(), cx),
                        cx,
                    ))
                    .child(act(
                        busy,
                        id("dbs-ibdel", &b.id),
                        "Delete",
                        BtnKind::Danger,
                        move |this, _| {
                            let victim = delete_id.clone();
                            this.ask(Confirm {
                                title: "Delete instance backup".into(),
                                message: "Deletes this whole-instance backup from the node. This cannot be undone.".into(),
                                label: "Delete".into(),
                                danger: true,
                                action: Box::new(move |this, cx| {
                                    this.dbs_instance_backup_delete(victim, cx)
                                }),
                            });
                        },
                        cx,
                    ))
                    .into_any_element();
                vec![
                    cell_text(
                        parse_rfc3339_ms(&b.created_at)
                            .map_or_else(|| b.created_at.clone(), |t| rel_time(now, t)),
                    ),
                    cell_text(if names.is_empty() { "-".to_string() } else { names }),
                    cell_text(fmt_bytes(total)),
                    pill(dv::status_text(b.status), dv::status_tone(b.status)).into_any_element(),
                    actions,
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Created", 100.),
            Col::flex("Databases").min(220.),
            Col::fixed("Size", 90.),
            Col::fixed("Status", 100.),
            Col::fixed("", 190.),
        ];
        let body = stack(12.)
            .child(note("Every tenant database in one archive. Restoring one is manual; a site's own backups restore a single database."))
            .child(wrap_row().child(act(
                busy,
                id("dbs", "ibackup"),
                "Back up the instance",
                BtnKind::Primary,
                |this, cx| this.dbs_instance_backup(cx),
                cx,
            )))
            .child(wide(
                id("dbs-ib", "table"),
                720.,
                table(
                    &cols,
                    rows,
                    Some(empty_state("No instance backups", "Back up the instance to create one.")),
                ),
            ));
        card(Some("Instance backups"), None, body).into_any_element()
    }

    fn targets_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let d = &self.dbs;
        let busy = d.busy;
        let rows: Vec<Vec<AnyElement>> = l
            .targets
            .iter()
            .map(|t| {
                let test_id = t.id.clone();
                let edit = t.clone();
                let (delete_id, delete_name) = (t.id.clone(), t.name.clone());
                let actions = wrap_row()
                    .gap(px(6.))
                    .child(act(
                        busy,
                        id("dbs-ttest", &t.id),
                        "Test",
                        BtnKind::Plain,
                        move |this, cx| this.dbs_target_test(test_id.clone(), cx),
                        cx,
                    ))
                    .child(act(
                        busy,
                        id("dbs-tedit", &t.id),
                        "Edit",
                        BtnKind::Plain,
                        move |this, cx| this.dbs_target_edit(&edit, cx),
                        cx,
                    ))
                    .child(act(
                        busy,
                        id("dbs-tdel", &t.id),
                        "Delete",
                        BtnKind::Danger,
                        move |this, _| {
                            let (victim_id, victim_name) = (delete_id.clone(), delete_name.clone());
                            this.ask(Confirm {
                                title: format!("Delete {victim_name}"),
                                message: "The node forgets the keys. Copies already in the bucket stay there. A site policy that uses the target must be changed first.".into(),
                                label: "Delete".into(),
                                danger: true,
                                action: Box::new(move |this, cx| {
                                    this.dbs_target_delete(victim_id, victim_name, cx)
                                }),
                            });
                        },
                        cx,
                    ))
                    .into_any_element();
                let mut flags = wrap_row().gap(px(4.));
                if t.encrypt {
                    flags = flags.child(pill("encrypted", Tone::Ok));
                }
                if t.path_style {
                    flags = flags.child(pill("path style", Tone::Muted));
                }
                vec![
                    cell_text(t.name.clone()),
                    cell_mono(t.endpoint.clone()),
                    cell_mono(t.bucket.clone()),
                    cell_text(t.region.clone()),
                    cell_text(if t.prefix.is_empty() { "-".to_string() } else { t.prefix.clone() }),
                    flags.into_any_element(),
                    actions,
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Name", 140.),
            Col::flex("Endpoint").min(200.),
            Col::fixed("Bucket", 130.),
            Col::fixed("Region", 110.),
            Col::fixed("Prefix", 90.),
            Col::fixed("Options", 150.),
            Col::fixed("", 240.),
        ];
        let mut body = stack(12.)
            .child(note("S3 destinations that site backups are copied to. They are kept apart from a site's own S3 attachments, so an app's keys can never delete a backup."))
            .child(wide(
                id("dbs-targets", "table"),
                1040.,
                table(
                    &cols,
                    rows,
                    Some(empty_state("No backup targets", "Add one to keep backup copies off the node.")),
                ),
            ));
        for target in &l.targets {
            if let Some((ok, text)) = d.tests.get(&target.id) {
                body = body.child(notice(
                    &format!("{}: {text}", target.name),
                    if *ok { Tone::Ok } else { Tone::Bad },
                ));
            }
        }
        let open = d.t_form_open;
        body = body.child(wrap_row().child(act(
            false,
            id("dbs", "target-add"),
            if open { "Close form" } else { "Add target" },
            BtnKind::Plain,
            move |this, cx| {
                if open {
                    this.clear_target_form(cx);
                    this.dbs.t_form_open = false;
                } else {
                    this.dbs.t_form_open = true;
                }
            },
            cx,
        )));
        if open {
            let has_keys = d.t_editing.is_some();
            body = body.child(self.target_form(has_keys, cx));
        }
        card(Some("Backup targets"), None, body).into_any_element()
    }

    fn target_form(&self, has_keys: bool, cx: &mut Context<Self>) -> Div {
        let d = &self.dbs;
        let editing = d.t_editing.is_some();
        stack(10.)
            .p(px(12.))
            .child(
                strong(if editing { "Edit target" } else { "New target" }).text_size(px(font::SM)),
            )
            .child(form_grid(vec![
                field("Name", None, d.t_name_in.clone()).into_any_element(),
                field("Endpoint", Some("Must be https."), d.t_endpoint_in.clone())
                    .into_any_element(),
                field("Bucket", None, d.t_bucket_in.clone()).into_any_element(),
                field("Region", None, d.t_region_in.clone()).into_any_element(),
                field(
                    "Prefix",
                    Some("Folder inside the bucket."),
                    d.t_prefix_in.clone(),
                )
                .into_any_element(),
                field(
                    "Access key id",
                    Some(if editing {
                        "Leave both keys blank to keep the stored ones."
                    } else {
                        dv::WRITE_ONLY_CREDENTIALS
                    }),
                    d.t_key_in.clone(),
                )
                .into_any_element(),
                field(
                    "Secret access key",
                    Some(dv::WRITE_ONLY_CREDENTIALS),
                    d.t_secret_in.clone(),
                )
                .into_any_element(),
            ]))
            .child(
                wrap_row()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(checkbox(id("dbs", "t-encrypt"), d.t_encrypt).on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.dbs.t_encrypt = !this.dbs.t_encrypt;
                                    cx.notify();
                                }),
                            ))
                            .child(div().child("Encrypt copies with the node key")),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(checkbox(id("dbs", "t-path"), d.t_path_style).on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.dbs.t_path_style = !this.dbs.t_path_style;
                                    cx.notify();
                                }),
                            ))
                            .child(div().child("Path-style addressing")),
                    ),
            )
            .child(wrap_row().child(act(
                d.busy,
                id("dbs", "target-save"),
                if editing {
                    "Save changes"
                } else {
                    "Add target"
                },
                BtnKind::Primary,
                move |this, cx| this.dbs_target_save(has_keys, cx),
                cx,
            )))
    }

    fn orphans_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let busy = self.dbs.busy;
        let rows: Vec<Vec<AnyElement>> = l
            .orphans
            .iter()
            .map(|o| {
                let site = o.site.clone();
                vec![
                    cell_mono(o.site.clone()),
                    cell_text(dv::orphan_text(o)),
                    act(
                        busy,
                        id("dbs-purge", &o.site),
                        "Purge",
                        BtnKind::Danger,
                        move |this, _| {
                            let victim = site.clone();
                            this.ask(Confirm {
                                title: format!("Purge {victim}"),
                                message: format!("Permanently deletes everything {victim} left behind: its database volume, databases, backups and stored secrets. This cannot be undone."),
                                label: "Purge".into(),
                                danger: true,
                                action: Box::new(move |this, cx| this.dbs_orphan_purge(victim, cx)),
                            });
                        },
                        cx,
                    ),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Site", 170.),
            Col::flex("Left behind").min(260.),
            Col::fixed("", 100.),
        ];
        card(
            Some("Leftovers of deleted sites"),
            Some("Data a deleted site left on the node. Nothing is removed until you purge it."),
            wide(
                id("dbs-orphans", "table"),
                560.,
                table(
                    &cols,
                    rows,
                    Some(empty_state(
                        "Nothing left behind",
                        "Every database on this node belongs to a site.",
                    )),
                ),
            ),
        )
        .into_any_element()
    }
}

// Reads what the node offers and, when it offers database services, everything the page shows. None means it has none.
async fn read_node(h: NodeHandle) -> Result<Option<Loaded>, ClientError> {
    let caps = h
        .node_info()
        .await
        .ok()
        .map(|i| i.capabilities)
        .unwrap_or_default();
    if !dv::databases_page_offered(&caps) {
        return Ok(None);
    }
    let node = h.data_node().await?;
    let shared_on = has_cap(&caps, dv::CAP_DATA_SHARED);
    let backups_on = has_cap(&caps, dv::CAP_DATA_BACKUPS);
    let enabled = shared_on && node.shared.as_ref().is_some_and(|s| s.enabled);
    let (shared, targets, orphans, backups) = tokio::join!(
        async {
            if enabled {
                h.data_shared().await.ok()
            } else {
                None
            }
        },
        async {
            if backups_on {
                h.data_targets().await.unwrap_or_default()
            } else {
                Vec::new()
            }
        },
        async { h.data_orphans().await.unwrap_or_default() },
        async {
            if enabled {
                h.data_shared_backups().await.unwrap_or_default()
            } else {
                Vec::new()
            }
        },
    );
    let shared = shared.or_else(|| node.shared.clone());
    Ok(Some(Loaded {
        node,
        shared,
        targets,
        orphans,
        backups,
        caps,
    }))
}
