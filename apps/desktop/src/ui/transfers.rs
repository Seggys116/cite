// Moving a database between nodes and converting it between dedicated and shared, for the Data tab and the Databases page.
//
// A move is driven by this app through cite-client::transfer: the driver runs on the IO runtime, writes its state to a file after
// every phase (so a move survives a restart and can be resumed) and reports progress through the shared store the screens read.
// A conversion runs on the node; the screens follow it through the site's data view. Demo mode walks a simulated move through
// the same phases without touching a network.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cite_client::transfer::{self, DEFAULT_POLL};
use cite_client::{
    CancelFlag, ClientError, NodeClient, TransferEnv, TransferPhase, TransferState, TransferStore,
};
use cite_edge::datamodel::PgMode;
use cite_edge::datawire::{ConvertReq, Freeze, JobAccepted, Session};
use gpui::{AnyElement, Context, Div, div, prelude::*, px};
use serde::{Deserialize, Serialize};

use crate::api::NodeHandle;
use crate::app::{Confirm, Console, View};
use crate::demo::{iso, now_ms};
use crate::siteops::has_cap;
use crate::theme::{Tone, c, font, tint};
use crate::ui::chart::wide;
use crate::ui::dataview::{self as dv, XferAction};
use crate::ui::detail::data::{
    Done, Loaded, act, blocked, cell_mono, cell_text, kv, note, stack, wrap_row,
};
use crate::ui::widgets::{
    BtnKind, Col, card, checkbox, empty_state, id, notice, pill, seg_item, seg_row, strong, table,
    text_dim,
};

const FILE_MODE: u32 = 0o600;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
struct FileBody {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    transfers: Vec<TransferState>,
}

// Where the driver keeps its state. A transfer state holds names, counts and phases only (never a secret), so the file is plain
// JSON, written beside itself and renamed into place with mode 0600. Without a path the store lives in memory (demo mode).
pub struct FileTransferStore {
    path: Option<PathBuf>,
    states: Mutex<BTreeMap<String, TransferState>>,
}

impl FileTransferStore {
    pub fn memory() -> Self {
        Self {
            path: None,
            states: Mutex::new(BTreeMap::new()),
        }
    }

    // Reads the file if there is one; a missing or unreadable file starts empty and is replaced on the next save.
    pub fn open(path: PathBuf) -> Self {
        let body: FileBody = cite_client::fsio::read_limited(&path, MAX_FILE_BYTES)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let states = body
            .transfers
            .into_iter()
            .map(|t| (t.id.clone(), t))
            .collect();
        Self {
            path: Some(path),
            states: Mutex::new(states),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, TransferState>> {
        self.states.lock().unwrap_or_else(|p| p.into_inner())
    }

    // Newest first.
    pub fn all(&self) -> Vec<TransferState> {
        let mut list: Vec<TransferState> = self.lock().values().cloned().collect();
        list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        list
    }

    // Progress between saves: what the screens show, not written to the file.
    pub fn put_live(&self, state: &TransferState) {
        self.lock().insert(state.id.clone(), state.clone());
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        let mut map = self.lock();
        map.remove(id);
        self.persist(&map)
    }

    fn persist(&self, map: &BTreeMap<String, TransferState>) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let body = FileBody {
            version: 1,
            transfers: map.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&body).map_err(|e| e.to_string())?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        cite_client::fsio::write_atomic(path, &bytes, FILE_MODE).map_err(|e| e.to_string())
    }
}

impl TransferStore for FileTransferStore {
    fn load(&self, id: &str) -> Option<TransferState> {
        self.lock().get(id).cloned()
    }

    fn save(&self, state: &TransferState) -> Result<(), ClientError> {
        let mut map = self.lock();
        map.insert(state.id.clone(), state.clone());
        self.persist(&map)
            .map_err(|e| ClientError::Config(format!("cannot save the transfer state: {e}")))
    }
}

pub fn transfers_path() -> PathBuf {
    crate::config::config_path().with_file_name("transfers.json")
}

// Everything the screens keep about moves and conversions.
pub struct XferState {
    pub store: Arc<FileTransferStore>,
    // The store as of the last refresh, newest first.
    pub view: Vec<TransferState>,
    // Transfers this app is driving right now, with the flag that stops each.
    pub running: BTreeMap<String, CancelFlag>,
    // Simulated transfers still advancing (demo mode).
    pub demo: BTreeSet<String>,
    pub target: Option<String>,
    pub database: Option<String>,
    pub freeze: Freeze,
    pub replace: bool,
    pub override_manual: bool,
    pub auto_cutover: bool,
    pub error: Option<String>,
    pub convert_freeze: Freeze,
}

impl XferState {
    pub fn new(demo: bool) -> Self {
        let store = if demo {
            let store = FileTransferStore::memory();
            for state in demo_seed() {
                store.put_live(&state);
            }
            store
        } else {
            FileTransferStore::open(transfers_path())
        };
        let store = Arc::new(store);
        Self {
            view: store.all(),
            store,
            running: BTreeMap::new(),
            demo: BTreeSet::new(),
            target: None,
            database: None,
            freeze: Freeze::Maintenance,
            replace: false,
            override_manual: false,
            auto_cutover: false,
            error: None,
            convert_freeze: Freeze::Maintenance,
        }
    }
}

// One move waiting for the operator with a row count that differs, and one that finished days ago.
fn demo_seed() -> Vec<TransferState> {
    let now = now_ms();
    let make = |site: &str, db: &str, from: &str, to: &str, ago_ms: i64| {
        let plan =
            dv::transfer_plan(from, to, site, db, Freeze::Maintenance, false, false, false).ok()?;
        let mut state = TransferState::new(plan).ok()?;
        state.updated_at = iso(now - ago_ms);
        state.bytes_total = 48 * 1024 * 1024;
        state.bytes_done = state.bytes_total;
        Some(state)
    };
    let mut out = Vec::new();
    if let Some(mut waiting) = make("docs", "auth", "edge-fra", "edge-iad", 20 * 60_000) {
        waiting.phase = TransferPhase::Verifying;
        waiting.mismatches = vec![cite_client::CountDiff {
            schema: "public".into(),
            table: "sessions".into(),
            source: Some(120),
            target: Some(118),
        }];
        waiting.counts_match = Some(false);
        out.push(waiting);
    }
    if let Some(mut done) = make("shop", "app", "edge-iad", "edge-fra", 3 * 86_400_000) {
        done.phase = TransferPhase::Done;
        done.counts_match = Some(true);
        out.push(done);
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Run,
    Resume,
    Cutover,
    Rollback,
}

fn live_client(handle: Option<NodeHandle>) -> Option<NodeClient> {
    match handle {
        Some(NodeHandle::Live(client)) => Some(client),
        _ => None,
    }
}

// The wanted entry when it is on offer, else the first.
fn pick_opt(want: Option<&str>, list: &[String]) -> Option<String> {
    want.filter(|w| list.iter().any(|x| x == w))
        .map(str::to_string)
        .or_else(|| list.first().cloned())
}

// Runs the driver on the IO runtime. Progress goes through the store, so the screens see it without any callback into the UI.
async fn drive(
    store: Arc<FileTransferStore>,
    source: NodeClient,
    target: NodeClient,
    mut state: TransferState,
    cancel: CancelFlag,
    kind: Kind,
) -> Result<TransferState, ClientError> {
    let live = store.clone();
    let progress = move |s: &TransferState| live.put_live(s);
    let env = TransferEnv {
        source: &source,
        target: &target,
        store: &*store,
        cancel,
        progress: &progress,
        poll: DEFAULT_POLL,
    };
    let outcome = match kind {
        Kind::Run => transfer::run(&env, &mut state).await,
        Kind::Resume => transfer::resume(&env, &mut state).await,
        Kind::Cutover => transfer::cutover(&env, &mut state).await,
        Kind::Rollback => transfer::rollback(&env, &mut state).await,
    };
    outcome
        .map(|()| state)
        .map_err(|e| ClientError::Config(e.to_string()))
}

// Refuses a target that does not offer transfers before anything is frozen.
async fn check_target(target: &NodeClient, name: &str) -> Result<(), ClientError> {
    let caps = target.node_info().await?.capabilities;
    if has_cap(&caps, dv::CAP_DATA_TRANSFER) {
        Ok(())
    } else {
        Err(ClientError::Config(format!(
            "{name} does not offer database transfers"
        )))
    }
}

impl Console {
    pub fn xfer_refresh(&mut self) {
        self.xfer.view = self.xfer.store.all();
    }

    // ---- driving a move ----

    pub(crate) fn xfer_start(&mut self, cx: &mut Context<Self>) {
        let node = self.detail.node.clone();
        let site = self.detail.site_id.clone();
        let databases: Vec<String> = self
            .site_data
            .load
            .ready()
            .and_then(|l| l.view.postgres.as_ref())
            .map(|pg| pg.databases.iter().map(|d| d.name.clone()).collect())
            .unwrap_or_default();
        let candidates = dv::target_candidates(&self.node_infos(), &node);
        let x = &self.xfer;
        let (Some(database), Some(target)) = (
            pick_opt(x.database.as_deref(), &databases),
            pick_opt(x.target.as_deref(), &candidates),
        ) else {
            self.xfer.error = Some("Pick a database and a node to move it to.".into());
            return;
        };
        let plan = dv::transfer_plan(
            &node,
            &target,
            &site,
            &database,
            x.freeze,
            x.replace,
            x.override_manual,
            x.auto_cutover,
        );
        let state = plan.and_then(|p| TransferState::new(p).map_err(|e| e.to_string()));
        let state = match state {
            Ok(s) => s,
            Err(e) => {
                self.xfer.error = Some(e);
                return;
            }
        };
        self.xfer.error = None;
        if let Err(e) = self.xfer.store.save(&state) {
            self.xfer.error = Some(e.to_string());
            return;
        }
        self.xfer_refresh();
        if self.demo {
            self.xfer.demo.insert(state.id.clone());
            self.say(format!("Moving {database} to {target}"), Tone::Ok);
        } else {
            self.spawn_transfer(state, Kind::Run, cx);
        }
    }

    // Starts the driver for a state, for a first run, a resume, a cutover or a rollback.
    fn spawn_transfer(&mut self, state: TransferState, kind: Kind, cx: &mut Context<Self>) {
        let source = live_client(self.handle_named(&state.plan.source_node));
        let target = live_client(self.handle_named(&state.plan.target_node));
        let (Some(source), Some(target)) = (source, target) else {
            self.xfer.error = Some(format!(
                "{} and {} must both be connected.",
                state.plan.source_node, state.plan.target_node
            ));
            return;
        };
        let id = state.id.clone();
        if self.xfer.running.contains_key(&id) {
            return;
        }
        let cancel = CancelFlag::new();
        self.xfer.running.insert(id.clone(), cancel.clone());
        let store = self.xfer.store.clone();
        let target_name = state.plan.target_node.clone();
        let fut = async move {
            if kind == Kind::Run {
                check_target(&target, &target_name).await?;
            }
            drive(store, source, target, state, cancel, kind).await
        };
        self.fetch(cx, fut, move |this, res, cx| {
            this.xfer_finished(id, res, cx)
        });
    }

    fn xfer_finished(
        &mut self,
        id: String,
        res: Result<TransferState, ClientError>,
        cx: &mut Context<Self>,
    ) {
        self.xfer.running.remove(&id);
        self.xfer_refresh();
        match res {
            Ok(state) => {
                let text = match state.phase {
                    TransferPhase::Done => {
                        "The transfer finished. The source database is untouched."
                    }
                    TransferPhase::RolledBack => "The transfer was rolled back.",
                    _ if state.awaiting_operator() && state.counts_match == Some(true) => {
                        "Copied and verified: cut over or roll back."
                    }
                    _ if state.awaiting_operator() => {
                        "Copied, but row counts differ: review the table, then roll back."
                    }
                    _ => "The transfer stopped.",
                };
                self.say(text, Tone::Ok);
            }
            Err(e) => {
                self.xfer.error = Some(e.to_string());
                self.say(format!("Transfer: {e}"), Tone::Bad);
            }
        }
        // A finished move changes what both nodes hold, so the page on screen reads again.
        match self.view.clone() {
            View::SiteDetail { node, id: site } => self.load_site_data(node, site, cx),
            View::Databases => self.load_databases(cx),
            _ => {}
        }
        cx.notify();
    }

    pub(crate) fn xfer_action(&mut self, id: String, action: XferAction, cx: &mut Context<Self>) {
        match action {
            XferAction::Cancel => {
                if let Some(flag) = self.xfer.running.get(&id) {
                    flag.cancel();
                    self.say(
                        "Stopping after the current step. Resume continues from there.",
                        Tone::Info,
                    );
                }
            }
            XferAction::Forget => {
                if self.xfer.running.contains_key(&id) {
                    return;
                }
                if let Err(e) = self.xfer.store.remove(&id) {
                    self.xfer.error = Some(format!("cannot save the transfer list: {e}"));
                }
                self.xfer_refresh();
            }
            XferAction::Resume | XferAction::Cutover | XferAction::Rollback => {
                let Some(state) = self.xfer.store.load(&id) else {
                    return;
                };
                self.xfer.error = None;
                if self.demo {
                    self.demo_action(state, action);
                    return;
                }
                let kind = match action {
                    XferAction::Cutover => Kind::Cutover,
                    XferAction::Rollback => Kind::Rollback,
                    _ => Kind::Resume,
                };
                self.spawn_transfer(state, kind, cx);
            }
        }
    }

    fn demo_action(&mut self, mut state: TransferState, action: XferAction) {
        let id = state.id.clone();
        match action {
            XferAction::Resume => {
                self.xfer.demo.insert(id);
                return;
            }
            XferAction::Cutover => {
                if let Err(e) = dv::demo_cutover(&mut state) {
                    self.xfer.error = Some(e);
                    return;
                }
                self.say(
                    "The transfer finished. The source database is untouched.",
                    Tone::Ok,
                );
            }
            _ => {
                dv::demo_rollback(&mut state);
                self.say("The transfer was rolled back.", Tone::Ok);
            }
        }
        let _ = self.xfer.store.save(&state);
        self.xfer_refresh();
    }

    // Runs on the half-second tick: simulated moves advance about once a second, a live move's progress is read from the store,
    // and a conversion that is working is read again from its site.
    pub fn xfer_tick(&mut self, cx: &mut Context<Self>) {
        if !self.tick.is_multiple_of(2) {
            return;
        }
        let ids: Vec<String> = self.xfer.demo.iter().cloned().collect();
        for id in ids {
            let more = match self.xfer.store.load(&id) {
                Some(mut state) => {
                    let more = dv::demo_step(&mut state);
                    let _ = self.xfer.store.save(&state);
                    more
                }
                None => false,
            };
            if !more {
                self.xfer.demo.remove(&id);
            }
        }
        if !self.xfer.demo.is_empty() || !self.xfer.running.is_empty() {
            let fresh = self.xfer.store.all();
            if fresh != self.xfer.view {
                self.xfer.view = fresh;
                cx.notify();
            }
        } else if self.xfer.view != self.xfer.store.all() {
            self.xfer_refresh();
            cx.notify();
        }
        if self.tick.is_multiple_of(4) && self.window_active {
            self.poll_conversion(cx);
        }
    }

    fn poll_conversion(&mut self, cx: &mut Context<Self>) {
        let View::SiteDetail { node, id: site } = self.view.clone() else {
            return;
        };
        let working = self
            .site_data
            .load
            .ready()
            .and_then(|l| l.view.conversion.as_ref())
            .is_some_and(dv::session_working);
        if working
            && self.site_data.for_site == (node.clone(), site.clone())
            && !self.site_data.busy
        {
            self.load_site_data(node, site, cx);
        }
    }

    // ---- actions: on-node conversion ----

    pub(crate) fn data_convert_start(&mut self, to: PgMode, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let req = ConvertReq {
            to,
            freeze: self.xfer.convert_freeze,
        };
        let fut = async move { h.site_pg_convert(&site, &req).await };
        self.data_run(
            cx,
            "Conversion",
            fut,
            move |_: &cite_edge::datawire::SessionStarted| {
                Done::plain(format!("{} started", dv::convert_to_label(to)))
            },
            |_, _| {},
        );
    }

    pub(crate) fn data_convert_finish(
        &mut self,
        session: String,
        cutover: bool,
        cx: &mut Context<Self>,
    ) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let fut = async move {
            if cutover {
                h.site_pg_convert_cutover(&site, &session).await
            } else {
                h.site_pg_convert_abort(&site, &session).await
            }
        };
        self.data_run(
            cx,
            if cutover { "Cutover" } else { "Abort" },
            fut,
            move |_: &Session| {
                Done::plain(if cutover {
                    "The site now uses the converted database. The old one is kept until you delete it."
                } else {
                    "The conversion was aborted. The site keeps its database."
                })
            },
            |_, _| {},
        );
    }

    pub(crate) fn data_retired_delete(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.data_ctx() else {
            return;
        };
        let fut = async move { h.site_pg_retired_delete(&site).await };
        self.data_run(
            cx,
            "Deleting the retired database",
            fut,
            |a: &JobAccepted| Done::job(a, "The retired database is being deleted"),
            |_, _| {},
        );
    }

    // ---- render ----

    fn xfer_bar(fraction: f32) -> Div {
        div()
            .w_full()
            .h(px(6.))
            .rounded_full()
            .bg(tint(0xffffff, 0.08))
            .child(
                div()
                    .h_full()
                    .w(gpui::relative(fraction))
                    .rounded_full()
                    .bg(c(Tone::Info.color())),
            )
    }

    // One move: its phase and progress, the verification result with the table of differing row counts, and what the operator can do.
    pub(crate) fn xfer_card(&self, t: &TransferState, cx: &mut Context<Self>) -> Div {
        let running = self.xfer.running.contains_key(&t.id);
        let mut head = wrap_row().child(strong(dv::transfer_title(t)).text_size(px(font::SM)));
        head = head.child(pill(dv::phase_label(t.phase), dv::phase_tone(t.phase)));
        if running {
            head = head.child(pill("running", Tone::Info));
        }
        let mut col = stack(8.).p(px(12.)).child(head);
        if t.bytes_total > 0 || running {
            col = col
                .child(Self::xfer_bar(dv::progress_fraction(
                    t.bytes_done,
                    t.bytes_total,
                )))
                .child(note(&dv::progress_text(t.bytes_done, t.bytes_total)));
        }
        if let Some(e) = &t.error {
            col = col.child(notice(e, Tone::Bad));
        }
        match t.counts_match {
            Some(true) => {
                col = col.child(notice(
                    "Verified: every table has the same number of rows on both nodes.",
                    Tone::Ok,
                ));
            }
            Some(false) => {
                let rows: Vec<Vec<AnyElement>> = t
                    .mismatches
                    .iter()
                    .map(|d| {
                        let side = |n: Option<u64>| {
                            n.map_or_else(|| "missing".to_string(), |n| n.to_string())
                        };
                        vec![
                            cell_mono(format!("{}.{}", d.schema, d.table)),
                            cell_text(side(d.source)),
                            cell_text(side(d.target)),
                        ]
                    })
                    .collect();
                let cols = [
                    Col::flex("Table").min(180.),
                    Col::fixed("Rows on the source", 150.),
                    Col::fixed("Rows on the target", 150.),
                ];
                col = col
                    .child(notice(
                        "Not verified: these tables have a different number of rows on the two nodes.",
                        Tone::Warn,
                    ))
                    .child(wide(
                        id("xfer-mismatch", &t.id),
                        520.,
                        table(&cols, rows, Some(empty_state("No tables listed", ""))),
                    ));
            }
            None => {}
        }
        let mut bar = wrap_row();
        for action in dv::xfer_actions(t, running) {
            bar = bar.child(self.xfer_button(t, action, cx));
        }
        col.child(bar)
            .debug_selector(|| format!("xfer-card-{}", t.id))
    }

    fn xfer_button(
        &self,
        t: &TransferState,
        action: XferAction,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let tid = t.id.clone();
        let key = |what: &str| id(what, &t.id);
        match action {
            XferAction::Cancel => act(
                false,
                key("xfer-cancel"),
                "Cancel",
                BtnKind::Plain,
                move |this, cx| this.xfer_action(tid.clone(), XferAction::Cancel, cx),
                cx,
            ),
            XferAction::Resume => act(
                false,
                key("xfer-resume"),
                "Resume",
                BtnKind::Plain,
                move |this, cx| this.xfer_action(tid.clone(), XferAction::Resume, cx),
                cx,
            ),
            XferAction::Forget => act(
                false,
                key("xfer-forget"),
                "Remove from the list",
                BtnKind::Plain,
                move |this, cx| this.xfer_action(tid.clone(), XferAction::Forget, cx),
                cx,
            ),
            XferAction::Cutover => match dv::cutover_block(t) {
                Some(reason) => blocked(key("xfer-cutover"), "Cut over", reason),
                None => {
                    let source = t.plan.source_node.clone();
                    act(
                        false,
                        key("xfer-cutover"),
                        "Cut over",
                        BtnKind::Primary,
                        move |this, _| {
                            let tid = tid.clone();
                            this.ask(Confirm {
                                title: "Cut over".into(),
                                message: format!(
                                    "Finishes the transfer: the target keeps the copied database. The source database is not deleted; it stays frozen on {source} until you delete it."
                                ),
                                label: "Cut over".into(),
                                danger: false,
                                action: Box::new(move |this, cx| {
                                    this.xfer_action(tid, XferAction::Cutover, cx)
                                }),
                            });
                        },
                        cx,
                    )
                }
            },
            XferAction::Rollback => act(
                false,
                key("xfer-rollback"),
                "Roll back",
                BtnKind::Danger,
                move |this, _| {
                    let tid = tid.clone();
                    this.ask(Confirm {
                        title: "Roll back the transfer".into(),
                        message: "Aborts the copy on the target and lifts the freeze on the source. The source database is untouched."
                            .into(),
                        label: "Roll back".into(),
                        danger: true,
                        action: Box::new(move |this, cx| {
                            this.xfer_action(tid, XferAction::Rollback, cx)
                        }),
                    });
                },
                cx,
            ),
        }
    }

    // The Data tab section that moves one database of the site to another connected node.
    pub(crate) fn transfer_card(&self, l: &Loaded, cx: &mut Context<Self>) -> AnyElement {
        let node = self.detail.node.clone();
        let site = self.detail.site_id.clone();
        let x = &self.xfer;
        let mut body = stack(12.)
            .child(note("Copies one database of this site to another connected node in checked chunks, then compares the row count of every table. Nothing changes for visitors until you cut over."))
            .child(note(dv::SOURCE_KEPT_NOTE));
        let databases: Vec<String> = l
            .view
            .postgres
            .as_ref()
            .map(|pg| pg.databases.iter().map(|d| d.name.clone()).collect())
            .unwrap_or_default();
        let candidates = dv::target_candidates(&self.node_infos(), &node);
        if databases.is_empty() {
            body = body.child(note("This site has no managed database to move."));
        } else if candidates.is_empty() {
            body = body.child(note("Connect another node to move a database there."));
        } else {
            body = body.child(self.xfer_form(&databases, &candidates, cx));
        }
        if let Some(e) = &x.error {
            body = body.child(notice(e, Tone::Bad));
        }
        if !l.view.transfers.is_empty() {
            let lines: Vec<String> = l
                .view
                .transfers
                .iter()
                .map(|t| {
                    format!(
                        "{} of {} on this node: {}",
                        match t.kind {
                            cite_edge::datawire::SessionKind::Export => "export",
                            cite_edge::datawire::SessionKind::Import => "import",
                            cite_edge::datawire::SessionKind::Convert => "conversion",
                        },
                        t.database,
                        dv::session_state_label(t.state).to_lowercase()
                    )
                })
                .collect();
            body = body.child(note(&format!("Open sessions: {}.", lines.join("; "))));
        }
        let mine: Vec<&TransferState> = x
            .view
            .iter()
            .filter(|t| {
                t.plan.site == site && (t.plan.source_node == node || t.plan.target_node == node)
            })
            .collect();
        for t in mine {
            body = body.child(self.xfer_card(t, cx));
        }
        card(
            Some("Move to another node"),
            Some("Transfer a database to a different node and cut the site over when it is verified."),
            body,
        )
        .into_any_element()
    }

    fn xfer_form(
        &self,
        databases: &[String],
        candidates: &[String],
        cx: &mut Context<Self>,
    ) -> Div {
        let x = &self.xfer;
        let database = pick_opt(x.database.as_deref(), databases).unwrap_or_default();
        let target = pick_opt(x.target.as_deref(), candidates).unwrap_or_default();
        let choice = |key: &'static str,
                      items: &[String],
                      current: &str,
                      set: fn(&mut XferState, String),
                      cx: &mut Context<Console>| {
            let mut row = Vec::new();
            for item in items {
                let value = item.clone();
                row.push(
                    seg_item(id(key, item), item, item == current)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            set(&mut this.xfer, value.clone());
                            cx.notify();
                        }))
                        .into_any_element(),
                );
            }
            seg_row(row)
        };
        let mut freezes = Vec::new();
        for freeze in dv::FREEZES {
            freezes.push(
                seg_item(
                    id("xfer-freeze", dv::freeze_label(freeze)),
                    dv::freeze_label(freeze),
                    x.freeze == freeze,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.xfer.freeze = freeze;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let toggle = |key: &'static str,
                      on: bool,
                      text: &str,
                      flip: fn(&mut XferState),
                      cx: &mut Context<Console>| {
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(checkbox(id("xfer", key), on).on_click(cx.listener(
                    move |this, _, _, cx| {
                        flip(&mut this.xfer);
                        cx.notify();
                    },
                )))
                .child(div().child(text.to_string()))
        };
        stack(10.)
            .child(note("Database"))
            .child(choice(
                "xfer-db",
                databases,
                &database,
                |x, v| x.database = Some(v),
                cx,
            ))
            .child(note("Move it to"))
            .child(choice(
                "xfer-target",
                candidates,
                &target,
                |x, v| x.target = Some(v),
                cx,
            ))
            .child(note("While the final copy runs"))
            .child(seg_row(freezes))
            .child(note(dv::freeze_text(x.freeze)))
            .child(toggle(
                "replace",
                x.replace,
                "Replace a database of the same name on the target (a backup of it is taken first)",
                |x| x.replace = !x.replace,
                cx,
            ))
            .child(toggle(
                "override",
                x.override_manual,
                "Replace manual env vars of the same name on the target when the links are created",
                |x| x.override_manual = !x.override_manual,
                cx,
            ))
            .child(toggle(
                "auto",
                x.auto_cutover,
                "Cut over automatically when every row count matches",
                |x| x.auto_cutover = !x.auto_cutover,
                cx,
            ))
            .child(wrap_row().child(act(
                false,
                id("xfer", "start"),
                "Start the move",
                BtnKind::Primary,
                |this, cx| this.xfer_start(cx),
                cx,
            )))
    }

    // The Data tab section that converts the managed database between dedicated and shared on the same node.
    pub(crate) fn convert_card(&self, l: &Loaded, cx: &mut Context<Self>) -> Option<AnyElement> {
        let pg = l.view.postgres.as_ref()?;
        let mut body = stack(12.).child(note(dv::CONVERT_NOTE));
        if let Some(retired) = &pg.retired {
            body = body
                .child(notice(&dv::retired_text(retired), Tone::Info))
                .child(wrap_row().child(act(
                    self.site_data.busy,
                    id("cv", "retired-delete"),
                    "Delete retired database",
                    BtnKind::Danger,
                    |this, _| {
                        this.ask(Confirm {
                            title: "Delete the retired database".into(),
                            message: "Permanently deletes the database the site used before the conversion. The site keeps using the converted one. This cannot be undone.".into(),
                            label: "Delete".into(),
                            danger: true,
                            action: Box::new(|this, cx| this.data_retired_delete(cx)),
                        });
                    },
                    cx,
                )));
        }
        match &l.view.conversion {
            Some(session) => body = body.child(self.convert_status(session, cx)),
            None => {
                let to = dv::other_mode(pg.mode);
                if to == PgMode::Shared && !has_cap(&l.caps, dv::CAP_DATA_SHARED) {
                    body = body.child(note("This node has no shared instance to convert to."));
                } else {
                    let mut freezes = Vec::new();
                    for freeze in dv::FREEZES {
                        freezes.push(
                            seg_item(
                                id("cv-freeze", dv::freeze_label(freeze)),
                                dv::freeze_label(freeze),
                                self.xfer.convert_freeze == freeze,
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.xfer.convert_freeze = freeze;
                                cx.notify();
                            }))
                            .into_any_element(),
                        );
                    }
                    body = body
                        .child(note("While the final copy runs"))
                        .child(seg_row(freezes))
                        .child(note(dv::freeze_text(self.xfer.convert_freeze)))
                        .child(wrap_row().child(act(
                            self.site_data.busy,
                            id("cv", "start"),
                            dv::convert_to_label(to),
                            BtnKind::Primary,
                            move |this, cx| this.data_convert_start(to, cx),
                            cx,
                        )));
                }
            }
        }
        Some(
            card(
                Some("Convert"),
                Some("Switch this site's database between a dedicated container and the node's shared instance."),
                body,
            )
            .into_any_element(),
        )
    }

    fn convert_status(&self, session: &Session, cx: &mut Context<Self>) -> Div {
        let mismatches = dv::convert_mismatches(session);
        let mut col = stack(8.)
            .p(px(12.))
            .child(
                wrap_row()
                    .child(strong("Conversion").text_size(px(font::SM)))
                    .child(pill(
                        dv::session_state_label(session.state),
                        dv::session_tone(session.state),
                    )),
            )
            .child(note(dv::freeze_text(session.freeze)));
        if let (Some(a), Some(b)) = (&session.counts, &session.peer_counts) {
            col = col.child(kv(
                "Rows",
                text_dim(format!(
                    "{} in the current database, {} in the converted one",
                    dv::count_rows(a),
                    dv::count_rows(b)
                )),
            ));
        }
        if let Some(e) = &session.error {
            col = col.child(notice(e, Tone::Bad));
        }
        if !mismatches.is_empty() {
            let lines: Vec<String> = mismatches.iter().map(dv::mismatch_text).collect();
            col = col
                .child(notice(
                    "These tables differ between the two databases.",
                    Tone::Warn,
                ))
                .child(note(&lines.join("; ")));
        }
        let busy = self.site_data.busy;
        let mut bar = wrap_row();
        for action in dv::convert_actions(session) {
            let sid = session.id.clone();
            bar = bar.child(match action {
                dv::ConvertAction::Cutover if !mismatches.is_empty() => blocked(
                    id("cv", "cutover"),
                    "Cut over",
                    "The row counts differ. Abort, then convert again.",
                ),
                dv::ConvertAction::Cutover => act(
                    busy,
                    id("cv", "cutover"),
                    "Cut over",
                    BtnKind::Primary,
                    move |this, _| {
                        let sid = sid.clone();
                        this.ask(Confirm {
                            title: "Cut over".into(),
                            message: "The site switches to the converted database. The old one is kept, frozen, until you delete it.".into(),
                            label: "Cut over".into(),
                            danger: false,
                            action: Box::new(move |this, cx| this.data_convert_finish(sid, true, cx)),
                        });
                    },
                    cx,
                ),
                dv::ConvertAction::Abort => act(
                    busy,
                    id("cv", "abort"),
                    "Abort",
                    BtnKind::Danger,
                    move |this, _| {
                        let sid = sid.clone();
                        this.ask(Confirm {
                            title: "Abort the conversion".into(),
                            message: "Drops the copy and lifts the freeze. The site keeps its database.".into(),
                            label: "Abort".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.data_convert_finish(sid, false, cx)),
                        });
                    },
                    cx,
                ),
            });
        }
        col.child(bar)
    }

    // The Databases page list of every move that starts or ends on this node.
    pub(crate) fn transfers_list_card(&self, node: &str, cx: &mut Context<Self>) -> AnyElement {
        let mut body = stack(10.).child(note(dv::SOURCE_KEPT_NOTE));
        let mine: Vec<&TransferState> = self
            .xfer
            .view
            .iter()
            .filter(|t| t.plan.source_node == node || t.plan.target_node == node)
            .collect();
        if mine.is_empty() {
            body = body.child(empty_state(
                "No transfers",
                "Move a database from a site's Data tab.",
            ));
        }
        for t in mine {
            body = body.child(self.xfer_card(t, cx));
        }
        if let Some(e) = &self.xfer.error {
            body = body.child(notice(e, Tone::Bad));
        }
        card(
            Some("Transfers"),
            Some("Databases moving to or from this node, with their verification."),
            body,
        )
        .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_client::TransferPlan;

    fn state(site: &str, db: &str) -> TransferState {
        let plan = TransferPlan {
            source_node: "edge-fra".into(),
            target_node: "edge-iad".into(),
            site: site.into(),
            database: db.into(),
            freeze: Freeze::ReadOnly,
            override_manual: true,
            replace: false,
            auto_cutover: false,
        };
        TransferState::new(plan).expect("state")
    }

    #[test]
    fn the_store_round_trips_through_a_private_file_and_survives_a_restart() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("nested").join("transfers.json");
        let store = FileTransferStore::open(path.clone());
        assert!(store.all().is_empty());
        let mut s = state("docs", "app");
        s.phase = TransferPhase::Streaming;
        s.bytes_total = 100;
        s.bytes_done = 40;
        store.save(&s).expect("save");
        let first_id = s.id.clone();
        let mut other = state("shop", "auth");
        other.updated_at = "2099-01-01T00:00:00Z".into();
        store.save(&other).expect("save other");
        // A restart reads the file back, newest first, with every field.
        let again = FileTransferStore::open(path.clone());
        let all = again.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, other.id);
        assert_eq!(again.load(&first_id), Some(s.clone()));
        assert!(again.load("nothing").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Removing one is written too, and no temporary file is left beside it.
        again.remove(&first_id).expect("remove");
        assert_eq!(FileTransferStore::open(path.clone()).all().len(), 1);
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .expect("dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn live_progress_is_visible_without_being_written() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("transfers.json");
        let store = FileTransferStore::open(path.clone());
        let mut s = state("docs", "app");
        store.save(&s).expect("save");
        s.bytes_done = 7;
        store.put_live(&s);
        assert_eq!(store.all()[0].bytes_done, 7);
        assert_eq!(FileTransferStore::open(path).all()[0].bytes_done, 0);
    }

    #[test]
    fn an_unreadable_file_starts_empty_and_is_replaced_by_the_next_save() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("transfers.json");
        std::fs::write(&path, b"{ not json").expect("write");
        let store = FileTransferStore::open(path.clone());
        assert!(store.all().is_empty());
        store.save(&state("docs", "app")).expect("save");
        assert_eq!(FileTransferStore::open(path).all().len(), 1);
    }

    #[test]
    fn a_memory_store_never_touches_the_disk() {
        let store = FileTransferStore::memory();
        store.save(&state("docs", "app")).expect("save");
        assert_eq!(store.all().len(), 1);
        store.remove(&store.all()[0].id).expect("remove");
        assert!(store.all().is_empty());
    }

    #[test]
    fn the_demo_store_has_a_move_waiting_on_a_difference_and_a_finished_one() {
        let x = XferState::new(true);
        assert_eq!(x.view.len(), 2);
        let waiting = x.view.iter().find(|t| t.plan.site == "docs").expect("docs");
        assert!(waiting.awaiting_operator() && waiting.counts_match == Some(false));
        assert!(dv::cutover_block(waiting).is_some());
        let done = x.view.iter().find(|t| t.plan.site == "shop").expect("shop");
        assert_eq!(done.phase, TransferPhase::Done);
    }

    #[test]
    fn a_choice_falls_back_to_the_first_entry() {
        let list = vec!["a".to_string(), "b".to_string()];
        assert_eq!(pick_opt(Some("b"), &list).as_deref(), Some("b"));
        assert_eq!(pick_opt(Some("zzz"), &list).as_deref(), Some("a"));
        assert_eq!(pick_opt(None, &list).as_deref(), Some("a"));
        assert_eq!(pick_opt(None, &[]), None);
    }
}
