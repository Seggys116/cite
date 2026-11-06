use std::collections::BTreeMap;

use cite_client::{
    AnalyticsQuery, BOT_CLASSES, ClientError, ExportFormat, ExportKind, FacetValue, Facets,
    RequestCursor,
};
use cite_edge::model::LogEvent;
use gpui::{AnyElement, ClipboardItem, Context, Entity, div, prelude::*, px};

use crate::analyticsq::{
    BlockedMode, CAP_ANALYTICS, Chip, ChipKey, Data, Field, Filter, METHOD_CHIPS, NodeResult,
    PAGE_SIZE, Pick, STATUS_CHIPS, TOP_ROWS, combine, export_gaps, export_query, kpis, merge_pages,
    pick_for, upsert_preset,
};
use crate::api::{NodeHandle, join_all, run_export};
use crate::app::{Console, Load, new_input};
use crate::bots::downloads_dir;
use crate::config::SavedPreset;
use crate::demo::{iso, now_ms};
use crate::model::{WINDOWS, fmt_bytes, fmt_clock, fmt_int, fmt_ms, fmt_pct};
use crate::scope::Sequence;
use crate::siteops::has_cap;
use crate::theme::{BLUE, DIM, GREEN, MONO, RED, Tone, YELLOW, c, tint};
use crate::ui::bots::{ExportRun, bot_badge, request_detail};
use crate::ui::chart::{FIELD_MIN, Line, STAT_MIN, clip_tip, hbar, line_chart, wide, x_axis};
use crate::ui::input::TextInput;
use crate::ui::scroll::scroll_area;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, empty_state, field, grid, grid_min, id, mono, notice,
    page_header, pill, seg_item, seg_row, skeleton, stat, table, text_dim, toggle,
    tone_for_status,
};
const AUTO_TICKS: u64 = 20;

pub struct FieldInput {
    pub field: Field,
    pub input: Entity<TextInput>,
}

#[derive(Default)]
pub struct LogState {
    pub rows: Vec<(String, LogEvent)>,
    // Per node: where its next page starts, and whether it has no more.
    pub cursors: Vec<(String, Option<RequestCursor>, bool)>,
    pub loading: bool,
    pub paged: bool,
    pub error: Option<String>,
    pub inspect: Option<(String, LogEvent)>,
    pub seq: Sequence,
}

pub struct State {
    pub filter: Filter,
    pub node: Option<String>,
    pub data: Load<Data>,
    pub failed: Vec<String>,
    pub modern_any: bool,
    pub node_modern: BTreeMap<String, bool>,
    pub in_flight: bool,
    pub seq: Sequence,
    pub auto: bool,
    pub error: Option<String>,
    pub note: Option<(String, Tone)>,
    pub inputs: Vec<FieldInput>,
    pub from: Entity<TextInput>,
    pub to: Entity<TextInput>,
    pub preset_name: Entity<TextInput>,
    pub preset_text: Entity<TextInput>,
    pub log: LogState,
    pub export: ExportRun,
    pub ndjson: bool,
}

fn field_hint(f: Field) -> &'static str {
    match f {
        Field::Host => "shop.example.com",
        Field::PathPrefix => "/api",
        Field::PathExact => "/pricing",
        Field::ClientIp => "203.0.113.7 or 10.0.0.0/8",
        Field::UserAgent => "curl (3 characters or more)",
        Field::Referer => "google.com",
        Field::ContentType => "text/",
        Field::Status => "404",
        Field::MinDuration => "250",
    }
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            filter: Filter::default(),
            node: None,
            data: Load::Idle,
            failed: Vec::new(),
            modern_any: true,
            node_modern: BTreeMap::new(),
            in_flight: false,
            seq: Sequence::default(),
            auto: false,
            error: None,
            note: None,
            inputs: Field::ALL
                .iter()
                .map(|f| FieldInput {
                    field: *f,
                    input: new_input(cx, field_hint(*f), |i| i.mono()),
                })
                .collect(),
            from: new_input(cx, "2026-11-01", |i| i.mono()),
            to: new_input(cx, "now", |i| i.mono()),
            preset_name: new_input(cx, "Name for this filter", |i| i),
            preset_text: new_input(cx, "Paste a shared filter", |i| i.mono()),
            log: LogState::default(),
            export: ExportRun::Idle,
            ndjson: false,
        }
    }
}

// One node's answers for the filter, or the reason it gave none.
async fn node_load(
    h: NodeHandle,
    filter: Filter,
    now: i64,
) -> (String, Result<NodeResult, String>) {
    let name = h.name().to_string();
    let res = node_load_inner(&h, &filter, now)
        .await
        .map_err(|e| e.to_string());
    (name, res)
}

// The site list ignores the site filter, so more sites can still be picked after one is chosen.
async fn site_facets(
    h: &NodeHandle,
    q: &AnalyticsQuery,
    modern: bool,
) -> Result<Facets, ClientError> {
    if modern {
        let mut open = q.clone();
        open.sites.clear();
        return h.an_facets(&open).await;
    }
    let sites = h.list_sites().await?;
    Ok(Facets {
        site: sites
            .into_iter()
            .map(|s| FacetValue {
                key: s.id,
                count: 0,
            })
            .collect(),
        ..Facets::default()
    })
}

async fn node_load_inner(
    h: &NodeHandle,
    filter: &Filter,
    now: i64,
) -> Result<NodeResult, ClientError> {
    let modern = h
        .node_info()
        .await
        .map(|i| has_cap(&i.capabilities, CAP_ANALYTICS))
        .unwrap_or(false);
    let scoped = if modern {
        filter.clone()
    } else {
        filter.restricted()
    };
    let q = scoped.query(now).map_err(ClientError::Config)?;
    let (compare, series, bots, paths, hosts, referers, agents, ips, statuses, facets) = tokio::join!(
        h.an_compare(&q, modern),
        h.an_series(&q, modern),
        h.an_bots(&q, modern),
        h.an_top("paths", &q, TOP_ROWS, modern),
        h.an_top("hosts", &q, TOP_ROWS, modern),
        h.an_top("referers", &q, TOP_ROWS, modern),
        h.an_top("agents", &q, TOP_ROWS, modern),
        h.an_top("ips", &q, TOP_ROWS, modern),
        h.an_top("statuses", &q, TOP_ROWS, modern),
        site_facets(h, &q, modern),
    );
    let (current, previous) = compare?;
    let series = series?;
    let tops = [
        ("paths", paths),
        ("hosts", hosts),
        ("referers", referers),
        ("agents", agents),
        ("ips", ips),
        ("statuses", statuses),
    ]
    .into_iter()
    .filter_map(|(kind, r)| r.ok().map(|t| (kind.to_string(), t.items)))
    .collect();
    Ok(NodeResult {
        node: h.name().to_string(),
        modern,
        partial: current.meta.partial || series.meta.partial,
        current: current.summary,
        previous: previous.map(|p| p.summary),
        series: series.series,
        bots: bots.ok().map(|b| b.bots),
        tops,
        facets: facets.ok(),
    })
}

impl Console {
    fn analytics_handles(&self) -> Vec<NodeHandle> {
        match &self.analytics.node {
            Some(name) => self.handle_named(name).into_iter().collect(),
            None => self.handles.clone(),
        }
    }

    // `quiet` keeps the numbers on screen while a background refresh runs.
    pub fn load_analytics(&mut self, quiet: bool, cx: &mut Context<Self>) {
        let handles = self.analytics_handles();
        if handles.is_empty() {
            self.analytics.data = Load::Failed("No node is connected.".into());
            return;
        }
        if !quiet {
            self.analytics.data = Load::Loading;
        }
        let (filter, now) = (self.analytics.filter.clone(), now_ms());
        let seq = self.analytics.seq.issue();
        self.analytics.in_flight = true;
        let fut = async move {
            let all = join_all(
                handles
                    .into_iter()
                    .map(|h| node_load(h, filter.clone(), now))
                    .collect(),
            )
            .await;
            Ok::<_, ClientError>(all.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch(cx, fut, move |this, res, cx| {
            this.analytics.in_flight = false;
            if !this.analytics.seq.accept(seq) {
                return;
            }
            let mut oks = Vec::new();
            let mut failed = Vec::new();
            let mut first_err = None;
            for (name, r) in res.unwrap_or_default() {
                match r {
                    Ok(n) => oks.push(n),
                    Err(e) => {
                        first_err.get_or_insert(e);
                        failed.push(name);
                    }
                }
            }
            if oks.is_empty() {
                let msg = first_err.unwrap_or_else(|| "No node answered.".into());
                this.analytics.data = Load::Failed(msg);
                cx.notify();
                return;
            }
            this.analytics.node_modern = oks.iter().map(|n| (n.node.clone(), n.modern)).collect();
            this.analytics.modern_any = oks.iter().any(|n| n.modern);
            this.analytics.failed = failed;
            this.analytics.data = Load::Ready(combine(oks));
            if !(quiet && this.analytics.log.paged) {
                this.load_log(true, cx);
            }
            cx.notify();
        });
    }

    // The request list pages by node: each node keeps its own cursor and the pages are merged newest first.
    pub fn load_log(&mut self, reset: bool, cx: &mut Context<Self>) {
        let now = now_ms();
        if reset {
            let log = &mut self.analytics.log;
            log.cursors = self
                .analytics
                .node
                .clone()
                .map(|n| vec![n])
                .unwrap_or_else(|| self.handles.iter().map(|h| h.name().to_string()).collect())
                .into_iter()
                .map(|n| (n, None, false))
                .collect();
            log.paged = false;
            log.inspect = None;
        } else {
            self.analytics.log.paged = true;
        }
        let jobs: Vec<(NodeHandle, bool, Option<RequestCursor>)> = self
            .analytics
            .log
            .cursors
            .iter()
            .filter(|(_, _, done)| !done)
            .filter_map(|(name, cursor, _)| {
                let h = self.handle_named(name)?;
                let modern = self
                    .analytics
                    .node_modern
                    .get(name)
                    .copied()
                    .unwrap_or(false);
                Some((h, modern, *cursor))
            })
            .collect();
        if jobs.is_empty() {
            return;
        }
        let filter = self.analytics.filter.clone();
        let seq = self.analytics.log.seq.issue();
        self.analytics.log.loading = true;
        let fut = async move {
            let pages = join_all(
                jobs.into_iter()
                    .map(|(h, modern, cursor)| {
                        let filter = filter.clone();
                        async move {
                            let name = h.name().to_string();
                            let scoped = if modern { filter } else { filter.restricted() };
                            let page = match scoped.query(now) {
                                Ok(q) => h
                                    .an_requests(&q, PAGE_SIZE, cursor, modern)
                                    .await
                                    .map_err(|e| e.to_string()),
                                Err(e) => Err(e),
                            };
                            (name, page)
                        }
                    })
                    .collect(),
            )
            .await;
            Ok::<_, ClientError>(pages.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch(cx, fut, move |this, res, cx| {
            if !this.analytics.log.seq.accept(seq) {
                return;
            }
            let log = &mut this.analytics.log;
            log.loading = false;
            log.error = None;
            if reset {
                log.rows.clear();
            }
            let mut pages = Vec::new();
            for (name, page) in res.unwrap_or_default() {
                match page {
                    Ok(p) => {
                        if let Some(slot) = log.cursors.iter_mut().find(|(n, _, _)| *n == name) {
                            slot.1 = p.next_cursor;
                            slot.2 = p.next_cursor.is_none();
                        }
                        pages.push((name, p.items));
                    }
                    Err(e) => {
                        if let Some(slot) = log.cursors.iter_mut().find(|(n, _, _)| *n == name) {
                            slot.2 = true;
                        }
                        log.error = Some(format!("{name}: {e}"));
                    }
                }
            }
            merge_pages(&mut log.rows, pages);
            cx.notify();
        });
    }

    // Pulls the typed values into the filter (unless a chip or click already set them), checks it and reloads.
    fn analytics_apply(&mut self, read_inputs: bool, cx: &mut Context<Self>) {
        if read_inputs {
            let texts: Vec<(Field, String)> = self
                .analytics
                .inputs
                .iter()
                .map(|fi| (fi.field, fi.input.read(cx).text().to_string()))
                .collect();
            if self.analytics.modern_any {
                for (f, t) in texts {
                    self.analytics.filter.set_text(f, &t);
                }
            }
            if self.analytics.filter.custom_range() {
                self.analytics.filter.from = self.analytics.from.read(cx).text().trim().to_string();
                self.analytics.filter.to = self.analytics.to.read(cx).text().trim().to_string();
            }
        }
        match self.analytics.filter.query(now_ms()) {
            Err(e) => self.analytics.error = Some(e),
            Ok(_) => {
                self.analytics.error = None;
                self.load_analytics(false, cx);
            }
        }
    }

    // Writes the filter back into the typed fields, after a preset or a clear.
    fn analytics_sync_inputs(&mut self, cx: &mut Context<Self>) {
        let f = self.analytics.filter.clone();
        for fi in &self.analytics.inputs {
            let text = f.text(fi.field).to_string();
            fi.input.update(cx, |i, cx| i.set_text(&text, cx));
        }
        self.analytics
            .from
            .update(cx, |i, cx| i.set_text(&f.from, cx));
        self.analytics.to.update(cx, |i, cx| i.set_text(&f.to, cx));
    }

    fn analytics_pick(&mut self, kind: &str, key: &str, cx: &mut Context<Self>) {
        match pick_for(kind, key) {
            Some(Pick::Class(class)) => {
                self.analytics.filter.status_classes =
                    crate::analyticsq::toggled(&self.analytics.filter.status_classes, &class);
            }
            Some(Pick::Text(field, value)) => {
                self.analytics.filter.set_text(field, &value);
                if let Some(fi) = self.analytics.inputs.iter().find(|fi| fi.field == field) {
                    fi.input.update(cx, |i, cx| i.set_text(&value, cx));
                }
            }
            None => return,
        }
        self.analytics_apply(false, cx);
    }

    // Runs on the half-second tick: refreshes only while the page is on screen, the window is active and nothing is loading.
    pub fn analytics_tick(&mut self, cx: &mut Context<Self>) {
        let ready = self.view == crate::app::View::Analytics
            && self.analytics.auto
            && self.window_active
            && !self.analytics.in_flight
            && matches!(self.analytics.data, Load::Ready(_));
        if ready && self.tick.is_multiple_of(AUTO_TICKS) {
            self.load_analytics(true, cx);
        }
    }

    fn start_analytics_export(&mut self, kind: ExportKind, cx: &mut Context<Self>) {
        if matches!(self.analytics.export, ExportRun::Running { .. }) {
            return;
        }
        let Some(handle) = self
            .analytics
            .node
            .as_deref()
            .and_then(|n| self.handle_named(n))
            .or_else(|| self.active_handle())
        else {
            self.analytics.export = ExportRun::Failed("No node is connected.".into());
            return;
        };
        let now = now_ms();
        let modern = self
            .analytics
            .node_modern
            .get(handle.name())
            .copied()
            .unwrap_or(false);
        let scoped = if modern {
            self.analytics.filter.clone()
        } else {
            self.analytics.filter.restricted()
        };
        let format = if self.analytics.ndjson {
            ExportFormat::Ndjson
        } else {
            ExportFormat::Csv
        };
        let query = scoped
            .query(now)
            .and_then(|q| export_query(&q, now, kind, format));
        let query = match query {
            Ok(q) => q,
            Err(msg) => {
                self.analytics.export = ExportRun::Failed(msg);
                return;
            }
        };
        let Some(dir) = downloads_dir() else {
            self.analytics.export = ExportRun::Failed(
                "Cannot find your home directory, so there is nowhere to save the file.".into(),
            );
            return;
        };
        let ext = if self.analytics.ndjson {
            "ndjson"
        } else {
            "csv"
        };
        let stamp = iso(now)[..16].replace(['-', ':'], "").replace('T', "-");
        let name = format!("cite-analytics-{}-{stamp}.{ext}", kind.as_str());
        self.analytics.export = ExportRun::Running {
            since_tick: self.tick,
        };
        self.fetch(cx, run_export(handle, query, dir, name), |this, res, cx| {
            this.analytics.export = match res {
                Ok(report) => {
                    this.say("Export saved", Tone::Ok);
                    ExportRun::Done {
                        path: report.path,
                        bytes: report.bytes,
                    }
                }
                Err(e) => ExportRun::Failed(e.to_string()),
            };
            cx.notify();
        });
    }

    fn persist_presets(&mut self) -> Result<(), String> {
        if self.demo {
            return Ok(());
        }
        self.config
            .save(&self.config_path)
            .map_err(|e| e.to_string())
    }

    fn save_preset(&mut self, cx: &mut Context<Self>) {
        let name = self.analytics.preset_name.read(cx).text().to_string();
        let filter = self.analytics.filter.clone();
        let outcome = upsert_preset(&mut self.config.analytics_presets, &name, &filter)
            .and_then(|()| self.persist_presets());
        self.analytics.note = Some(match outcome {
            Ok(()) => {
                self.analytics
                    .preset_name
                    .update(cx, |i, cx| i.set_text("", cx));
                ("Filter saved.".to_string(), Tone::Ok)
            }
            Err(e) => (e, Tone::Bad),
        });
    }

    fn use_preset(&mut self, query: &str, cx: &mut Context<Self>) {
        match Filter::decode(query) {
            Ok(f) => {
                self.analytics.filter = f;
                self.analytics.note = None;
                self.analytics_sync_inputs(cx);
                self.analytics_apply(false, cx);
            }
            Err(e) => self.analytics.note = Some((e, Tone::Bad)),
        }
    }

    fn import_preset(&mut self, cx: &mut Context<Self>) {
        let text = self.analytics.preset_text.read(cx).text().to_string();
        self.use_preset(&text, cx);
        if self.analytics.note.is_none() {
            self.analytics
                .preset_text
                .update(cx, |i, cx| i.set_text("", cx));
        }
    }

    fn delete_preset(&mut self, index: usize) {
        if index < self.config.analytics_presets.len() {
            self.config.analytics_presets.remove(index);
        }
        if let Err(e) = self.persist_presets() {
            self.analytics.note = Some((e, Tone::Bad));
        }
    }

    pub fn render_analytics(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let subtitle = match &self.analytics.node {
            Some(n) => format!("Filtered traffic of {n}"),
            None => "Filtered traffic of every node".to_string(),
        };
        let auto = div()
            .flex()
            .items_center()
            .gap(px(8.))
            .child(
                toggle(id("an", "auto"), self.analytics.auto).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.analytics.auto = !this.analytics.auto;
                        cx.notify();
                    },
                )),
            )
            .child(text_dim("Refresh every 10 seconds").text_size(px(12.)));
        let refresh = btn(id("an", "refresh"), "Refresh", BtnKind::Plain).on_click(cx.listener(
            |this, _, _, cx| {
                this.analytics_apply(true, cx);
                cx.notify();
            },
        ));
        let mut col = div().flex().flex_col().gap(px(16.)).child(page_header(
            "Analytics",
            &subtitle,
            vec![auto.into_any_element(), refresh.into_any_element()],
        ));
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        col = col.child(self.filter_card(cx));
        col = col.children(self.chips_row(cx));
        col = col.child(self.analytics_presets_card(cx));
        match &self.analytics.data {
            Load::Idle | Load::Loading => {
                col = col
                    .child(skeleton(86.))
                    .child(skeleton(240.))
                    .child(skeleton(180.))
            }
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                if data.partial {
                    col = col.child(notice(
                        "Partial result: the node read only the newest part of this range. Narrow the range or the filter for exact numbers.",
                        Tone::Warn,
                    ));
                }
                if !data.restricted.is_empty() {
                    col = col.child(notice(
                        &format!(
                            "{} only understand a time window and one site, so the other filters do not apply there.",
                            data.restricted.join(", ")
                        ),
                        Tone::Info,
                    ));
                }
                if !self.analytics.failed.is_empty() {
                    col = col.child(notice(
                        &format!("No answer from {}.", self.analytics.failed.join(", ")),
                        Tone::Warn,
                    ));
                }
                col = col.child(self.analytics_body(data, cx));
            }
        }
        col = col.child(self.log_card(cx));
        col.child(self.analytics_export_card(cx)).into_any_element()
    }

    fn filter_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let a = &self.analytics;
        let f = &a.filter;
        let modern = a.modern_any;
        let mut nodes = vec![
            seg_item(id("an-node", "all"), "All nodes", a.node.is_none())
                .on_click(cx.listener(|this, _, _, cx| {
                    this.analytics.node = None;
                    this.analytics_apply(true, cx);
                    cx.notify();
                }))
                .into_any_element(),
        ];
        for h in &self.handles {
            let (name, label) = (h.name().to_string(), h.name().to_string());
            nodes.push(
                seg_item(
                    id("an-node", &label),
                    &label,
                    a.node.as_deref() == Some(name.as_str()),
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.analytics.node = Some(name.clone());
                    this.analytics_apply(true, cx);
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let mut range = Vec::new();
        for w in WINDOWS {
            range.push(
                seg_item(id("an-window", w), w, f.window == w)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics.filter.window = w.to_string();
                        this.analytics_apply(true, cx);
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        if modern {
            range.push(
                seg_item(id("an-window", "custom"), "Custom", f.custom_range())
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.analytics.filter.window.clear();
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("Node", None, div().flex().child(seg_row(nodes))))
            .child(field(
                "Time range",
                None,
                div().flex().child(seg_row(range)),
            ));
        if modern && f.custom_range() {
            body = body.child(grid_min(
                FIELD_MIN,
                vec![
                    field(
                        "From (UTC)",
                        Some("2026-11-01 or 2026-11-01 08:30"),
                        a.from.clone(),
                    )
                    .into_any_element(),
                    field("To (UTC)", Some("Blank means now"), a.to.clone()).into_any_element(),
                ],
            ));
        }
        body = body.child(field(
            "Sites",
            Some("Pick none for every site."),
            self.site_chips(cx),
        ));
        if modern {
            body = body.child(self.modern_controls(cx));
        }
        let apply = btn(id("an", "apply"), "Apply", BtnKind::Primary).on_click(cx.listener(
            |this, _, _, cx| {
                this.analytics_apply(true, cx);
                cx.notify();
            },
        ));
        let clear = btn(id("an", "clear"), "Clear all", BtnKind::Plain).on_click(cx.listener(
            |this, _, _, cx| {
                this.analytics.filter = Filter::default();
                this.analytics_sync_inputs(cx);
                this.analytics_apply(false, cx);
                cx.notify();
            },
        ));
        body = body.child(div().flex().gap(px(8.)).child(apply).child(clear));
        if let Some(e) = &a.error {
            body = body.child(notice(e, Tone::Bad));
        }
        card(
            Some("Filter"),
            Some("Every set field narrows the numbers below."),
            body,
        )
        .into_any_element()
    }

    fn site_chips(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.analytics.filter;
        let mut names: Vec<String> = match &self.analytics.data {
            Load::Ready(d) => d.facets.site.iter().map(|v| v.key.clone()).collect(),
            _ => Vec::new(),
        };
        for s in &f.sites {
            if !names.contains(s) {
                names.push(s.clone());
            }
        }
        if names.is_empty() {
            return text_dim("Sites appear once the numbers have loaded.")
                .text_size(px(12.))
                .into_any_element();
        }
        let mut row = div().flex().flex_wrap().gap(px(6.));
        for name in names {
            let on = f.sites.contains(&name);
            let count = match &self.analytics.data {
                Load::Ready(d) => d
                    .facets
                    .site
                    .iter()
                    .find(|v| v.key == name)
                    .map(|v| v.count)
                    .filter(|n| *n > 0),
                _ => None,
            };
            let label = match count {
                Some(n) => format!("{name} ({})", crate::model::fmt_num(n)),
                None => name.clone(),
            };
            row = row.child(seg_row(vec![
                seg_item(id("an-site", &name), &label, on)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics.filter.sites =
                            crate::analyticsq::toggled(&this.analytics.filter.sites, &name);
                        this.analytics_apply(true, cx);
                        cx.notify();
                    }))
                    .into_any_element(),
            ]));
        }
        row.into_any_element()
    }

    // Chips for method, status class, bot class and blocked, plus the typed fields; older nodes ignore all of these.
    fn modern_controls(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.analytics.filter;
        let mut methods = div().flex().flex_wrap().gap(px(6.));
        for m in METHOD_CHIPS {
            methods = methods.child(seg_row(vec![
                seg_item(id("an-method", m), m, f.methods.iter().any(|v| v == m))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics.filter.methods =
                            crate::analyticsq::toggled(&this.analytics.filter.methods, m);
                        this.analytics_apply(true, cx);
                        cx.notify();
                    }))
                    .into_any_element(),
            ]));
        }
        let mut classes = div().flex().flex_wrap().gap(px(6.));
        for s in STATUS_CHIPS {
            classes = classes.child(seg_row(vec![
                seg_item(
                    id("an-class", s),
                    s,
                    f.status_classes.iter().any(|v| v == s),
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.analytics.filter.status_classes =
                        crate::analyticsq::toggled(&this.analytics.filter.status_classes, s);
                    this.analytics_apply(true, cx);
                    cx.notify();
                }))
                .into_any_element(),
            ]));
        }
        let mut bots = div().flex().flex_wrap().gap(px(6.));
        for b in BOT_CLASSES {
            bots = bots.child(seg_row(vec![
                seg_item(id("an-bot", b), b, f.bot_classes.iter().any(|v| v == b))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics.filter.bot_classes =
                            crate::analyticsq::toggled(&this.analytics.filter.bot_classes, b);
                        this.analytics_apply(true, cx);
                        cx.notify();
                    }))
                    .into_any_element(),
            ]));
        }
        let mut blocked = Vec::new();
        for (mode, label) in [
            (BlockedMode::Any, "Any"),
            (BlockedMode::Blocked, "Blocked"),
            (BlockedMode::Unblocked, "Not blocked"),
        ] {
            blocked.push(
                seg_item(id("an-blocked", label), label, f.blocked == mode)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics.filter.blocked = mode;
                        this.analytics_apply(true, cx);
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let typed = grid_min(
            FIELD_MIN,
            self.analytics
                .inputs
                .iter()
                .map(|fi| field(fi.field.label(), None, fi.input.clone()).into_any_element())
                .collect(),
        );
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("Methods", None, methods))
            .child(field("Status classes", None, classes))
            .child(field("Bot classes", None, bots))
            .child(field(
                "Firewall",
                None,
                div().flex().child(seg_row(blocked)),
            ))
            .child(typed)
            .into_any_element()
    }

    fn chips_row(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let chips: Vec<Chip> = self.analytics.filter.chips();
        if chips.is_empty() {
            return None;
        }
        let mut row = div().flex().flex_wrap().items_center().gap(px(6.));
        for (i, chip) in chips.into_iter().enumerate() {
            let key: ChipKey = chip.key.clone();
            row = row.child(
                div()
                    .id(id("an-chip", i))
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .px(px(9.))
                    .py(px(3.))
                    .rounded(px(7.))
                    .border_1()
                    .border_color(tint(BLUE, 0.5))
                    .bg(tint(BLUE, 0.1))
                    .text_size(px(12.))
                    .cursor_pointer()
                    .child(chip.label)
                    .child(text_dim("x"))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics.filter.remove(&key);
                        this.analytics_sync_inputs(cx);
                        this.analytics_apply(false, cx);
                        cx.notify();
                    })),
            );
        }
        Some(row.into_any_element())
    }

    fn analytics_presets_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut list = div().flex().flex_col().gap(px(6.));
        let presets: &[SavedPreset] = &self.config.analytics_presets;
        if presets.is_empty() {
            list = list.child(text_dim("No saved filters yet.").text_size(px(12.)));
        }
        for (i, p) in presets.iter().enumerate() {
            let (apply_q, copy_q) = (p.query.clone(), p.query.clone());
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(
                        div().flex_1().min_w_0().child(
                            clip_tip(id("an-preset-name", i), p.name.clone())
                                .font_weight(gpui::FontWeight::SEMIBOLD),
                        ),
                    )
                    .child(btn(id("an-preset-use", i), "Use", BtnKind::Plain).on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.use_preset(&apply_q, cx);
                            cx.notify();
                        }),
                    ))
                    .child(
                        btn(id("an-preset-copy", i), "Copy", BtnKind::Plain).on_click(cx.listener(
                            move |this, _, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(copy_q.clone()));
                                this.say("Filter copied", Tone::Ok);
                                cx.notify();
                            },
                        )),
                    )
                    .child(
                        btn(id("an-preset-del", i), "Delete", BtnKind::Danger).on_click(
                            cx.listener(move |this, _, _, cx| {
                                this.delete_preset(i);
                                cx.notify();
                            }),
                        ),
                    ),
            );
        }
        let save = btn(
            id("an", "preset-save"),
            "Save current filter",
            BtnKind::Plain,
        )
        .on_click(cx.listener(|this, _, _, cx| {
            this.save_preset(cx);
            cx.notify();
        }));
        let import = btn(
            id("an", "preset-import"),
            "Use pasted filter",
            BtnKind::Plain,
        )
        .on_click(cx.listener(|this, _, _, cx| {
            this.import_preset(cx);
            cx.notify();
        }));
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(list)
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(8.))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(self.analytics.preset_name.clone()),
                    )
                    .child(save),
            )
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(8.))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(self.analytics.preset_text.clone()),
                    )
                    .child(import),
            );
        if let Some((msg, tone)) = &self.analytics.note {
            body = body.child(notice(msg, *tone));
        }
        card(
            Some("Saved filters"),
            Some("Stored on this computer as plain text without secrets. Copy one to share it."),
            body,
        )
        .into_any_element()
    }

    fn analytics_body(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let sm = &data.summary;
        let mut tiles = Vec::new();
        for k in kpis(sm, data.previous.as_ref()) {
            let mut tile = stat(k.label, k.value, k.sub, Tone::Muted)
                .min_w_0()
                .h_full();
            if let Some((text, tone)) = k.delta {
                tile = tile.child(
                    text_dim(text)
                        .text_size(px(11.))
                        .text_color(c(tone.color())),
                );
            }
            tiles.push(tile.into_any_element());
        }
        let tiles = grid_min(STAT_MIN, tiles);
        let pts = &data.series.points;
        let axis = x_axis(
            "an-axis",
            pts.iter()
                .map(|p| crate::bots::fmt_stamp(p.ts * 1000))
                .collect(),
        );
        let legend = div()
            .flex()
            .flex_wrap()
            .gap(px(14.))
            .text_size(px(12.))
            .child(legend_item("Requests", BLUE))
            .child(legend_item("Errors", RED))
            .child(legend_item("Blocked", YELLOW));
        let traffic = card(
            Some("Requests over time"),
            Some(&format!("{} second buckets", data.series.step_secs)),
            div()
                .flex()
                .flex_col()
                .gap(px(8.))
                .child(legend)
                .child(line_chart(
                    vec![
                        Line {
                            values: pts.iter().map(|p| p.requests).collect(),
                            color: BLUE,
                            area: true,
                        },
                        Line {
                            values: pts.iter().map(|p| p.errors).collect(),
                            color: RED,
                            area: false,
                        },
                        Line {
                            values: pts.iter().map(|p| p.blocked).collect(),
                            color: YELLOW,
                            area: false,
                        },
                    ],
                    190.,
                    true,
                ))
                .child(axis),
        );
        let bandwidth = card(
            Some("Bandwidth out"),
            None,
            line_chart(
                vec![Line {
                    values: pts.iter().map(|p| p.bytes_out).collect(),
                    color: GREEN,
                    area: true,
                }],
                110.,
                true,
            ),
        );
        let half = |card: gpui::Div| card.flex_1().min_w_0().into_any_element();
        let row_a = grid(
            vec![
                half(card(Some("Status classes"), None, status_bars(data))),
                half(card(Some("Methods"), None, method_bars(data))),
                half(card(
                    Some("Latency"),
                    Some("Total time per request"),
                    latency_bars(data),
                )),
            ],
        );
        let tops = grid(
            data.tops
                .iter()
                .map(|(kind, items)| half(self.top_card(kind, items, cx)))
                .collect(),
        );
        div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(tiles)
            .child(traffic)
            .child(bandwidth)
            .child(row_a)
            .child(tops)
            .child(self.bots_card(data, cx))
            .into_any_element()
    }

    // Each row filters the page to its key when clicked.
    fn top_card(
        &self,
        kind: &str,
        items: &[cite_edge::analytics::TopItem],
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let title = match kind {
            "paths" => "Top paths",
            "hosts" => "Top hosts",
            "referers" => "Top referers",
            "agents" => "Top user agents",
            "ips" => "Top client IPs",
            _ => "Top statuses",
        };
        let mut list = div().flex().flex_col().gap(px(2.));
        if items.is_empty() {
            list = list.child(text_dim("Nothing recorded for this filter.").text_size(px(12.)));
        }
        for (i, item) in items.iter().enumerate() {
            let (kind_owned, key) = (kind.to_string(), item.key.clone());
            list = list.child(
                div()
                    .id(id("an-top", format!("{kind}-{i}")))
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .px(px(6.))
                    .py(px(3.))
                    .rounded(px(6.))
                    .cursor_pointer()
                    .hover(|s| s.bg(tint(0xffffff, 0.05)))
                    .child(
                        div().flex_1().min_w_0().child(
                            clip_tip(id("an-top-key", format!("{kind}-{i}")), item.key.clone())
                                .font_family(MONO)
                                .text_size(px(12.)),
                        ),
                    )
                    .child(mono(fmt_int(item.count)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics_pick(&kind_owned, &key, cx);
                        cx.notify();
                    })),
            );
        }
        card(Some(title), Some("Click a row to filter by it"), list)
    }

    fn bots_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let Some(bots) = &data.bots else {
            return card(
                Some("Bots"),
                None,
                text_dim("This node did not report bot data.").text_size(px(12.)),
            )
            .into_any_element();
        };
        let total = bots
            .classes
            .iter()
            .map(|c| c.count)
            .max()
            .unwrap_or(0)
            .max(1);
        let mut rows = div().flex().flex_col().gap(px(8.));
        for (i, class) in bots.classes.iter().enumerate() {
            let key = class.key.clone();
            let share = if bots.total_requests == 0 {
                0.0
            } else {
                class.count as f64 / bots.total_requests as f64
            };
            rows = rows.child(
                div()
                    .id(id("an-botclass", i))
                    .cursor_pointer()
                    .child(hbar(
                        &class.key,
                        class.count,
                        total,
                        BLUE,
                        fmt_pct(share, 1),
                    ))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.analytics.filter.bot_classes =
                            crate::analyticsq::toggled(&this.analytics.filter.bot_classes, &key);
                        this.analytics_apply(false, cx);
                        cx.notify();
                    })),
            );
        }
        card(
            Some("Bots"),
            Some(&format!(
                "{} of {} requests came from bots ({:.1}%). Click a class to filter.",
                fmt_int(bots.bot_requests),
                fmt_int(bots.total_requests),
                bots.bot_share_pct
            )),
            rows,
        )
        .into_any_element()
    }

    fn log_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let log = &self.analytics.log;
        let several = self.analytics.node.is_none() && self.handles.len() > 1;
        let rows: Vec<Vec<AnyElement>> = log
            .rows
            .iter()
            .enumerate()
            .map(|(i, (node, e))| {
                let picked = (node.clone(), e.clone());
                let mut cells = vec![
                    mono(format!("{} {}", &iso(e.ts_ms)[5..10], fmt_clock(e.ts_ms)))
                        .text_color(c(DIM))
                        .into_any_element(),
                ];
                if several {
                    cells.push(mono(node.clone()).into_any_element());
                }
                cells.extend([
                    pill(&e.status.to_string(), tone_for_status(e.status)).into_any_element(),
                    mono(e.method.clone()).into_any_element(),
                    clip_tip(id("an-log-path", i), e.path.clone())
                        .font_family(MONO)
                        .text_size(px(12.))
                        .into_any_element(),
                    clip_tip(id("an-log-host", i), e.host.clone())
                        .text_size(px(12.))
                        .text_color(c(DIM))
                        .into_any_element(),
                    clip_tip(id("an-log-ip", i), e.client_ip.clone())
                        .font_family(MONO)
                        .text_size(px(12.))
                        .text_color(c(DIM))
                        .into_any_element(),
                    mono(fmt_ms(f64::from(e.total_ms))).into_any_element(),
                    bot_badge(e),
                    div()
                        .id(id("an-detail", i))
                        .cursor_pointer()
                        .text_size(px(12.))
                        .text_color(c(BLUE))
                        .hover(|s| s.opacity(0.7))
                        .child("Details")
                        .on_click(cx.listener(move |this, _, _, cx| {
                            let same = this.analytics.log.inspect.as_ref() == Some(&picked);
                            this.analytics.log.inspect = (!same).then(|| picked.clone());
                            cx.notify();
                        }))
                        .into_any_element(),
                ]);
                cells
            })
            .collect();
        let mut cols = vec![Col::fixed("Time", 120.)];
        if several {
            cols.push(Col::fixed("Node", 90.));
        }
        cols.extend([
            Col::fixed("Status", 64.),
            Col::fixed("Method", 60.),
            Col::flex("Path"),
            Col::fixed("Host", 130.),
            Col::fixed("Client", 120.),
            Col::fixed("Took", 72.),
            Col::fixed("Bot", 130.),
            Col::fixed("", 60.),
        ]);
        let more = log.cursors.iter().any(|(_, _, done)| !done);
        let mut body = div().flex().flex_col().gap(px(10.));
        if let Some((_, event)) = &log.inspect {
            let close = btn(id("an-inspect", "close"), "Close", BtnKind::Plain).on_click(
                cx.listener(|this, _, _, cx| {
                    this.analytics.log.inspect = None;
                    cx.notify();
                }),
            );
            body = body.child(request_detail(event, close.into_any_element()));
        }
        let min_width = cols.iter().filter_map(|col| col.width).sum::<f32>() + 220.;
        body = body.child(scroll_area("an-log").max_h(px(560.)).child(wide(
            id("an", "log-table"),
            min_width,
            table(
                &cols,
                rows,
                Some(empty_state(
                    if log.loading {
                        "Loading"
                    } else {
                        "No requests match"
                    },
                    "Requests that match the filter are listed here, newest first.",
                )),
            ),
        )));
        if let Some(e) = &log.error {
            body = body.child(notice(e, Tone::Warn));
        }
        let footer = if log.loading {
            btn_off("Loading...").into_any_element()
        } else if more && !log.rows.is_empty() {
            btn(id("an", "more"), "Load more", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.load_log(false, cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            text_dim(format!("{} requests listed", log.rows.len()))
                .text_size(px(12.))
                .into_any_element()
        };
        card(
            Some("Requests"),
            Some("Pages of fifty, newest first"),
            body.child(div().flex().child(footer)),
        )
        .into_any_element()
    }

    fn analytics_export_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let a = &self.analytics;
        let gaps = a
            .filter
            .query(now_ms())
            .map(|q| export_gaps(&q))
            .unwrap_or_default();
        let running = matches!(a.export, ExportRun::Running { .. });
        let formats = seg_row(vec![
            seg_item(id("an-format", "csv"), "CSV", !a.ndjson)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.analytics.ndjson = false;
                    cx.notify();
                }))
                .into_any_element(),
            seg_item(id("an-format", "ndjson"), "NDJSON", a.ndjson)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.analytics.ndjson = true;
                    cx.notify();
                }))
                .into_any_element(),
        ]);
        let go = |kind: ExportKind, label: &str, key: &'static str, cx: &mut Context<Self>| {
            if running {
                btn_off(label).into_any_element()
            } else {
                btn(id("an-export", key), label, BtnKind::Primary)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.start_analytics_export(kind, cx);
                        cx.notify();
                    }))
                    .into_any_element()
            }
        };
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(field("Format", None, div().flex().child(formats)))
            .child(
                div()
                    .flex()
                    .gap(px(8.))
                    .child(go(ExportKind::Requests, "Export requests", "requests", cx))
                    .child(go(ExportKind::Hourly, "Export hourly totals", "hourly", cx)),
            );
        if !gaps.is_empty() {
            body = body.child(notice(
                &format!(
                    "The export route cannot apply: {}. The file will hold more than the page shows.",
                    gaps.join(", ")
                ),
                Tone::Warn,
            ));
        }
        match &a.export {
            ExportRun::Idle => {}
            ExportRun::Running { since_tick } => {
                let secs = self.tick.saturating_sub(*since_tick) / 2;
                body = body.child(notice(&format!("Exporting... {secs}s"), Tone::Info));
            }
            ExportRun::Done { path, bytes } => {
                body = body.child(notice(
                    &format!("Saved {} ({})", path.display(), fmt_bytes(*bytes)),
                    Tone::Ok,
                ));
            }
            ExportRun::Failed(msg) => body = body.child(notice(msg, Tone::Bad)),
        }
        card(
            Some("Export"),
            Some("Saved to your Downloads folder from the selected node, or the first one when all nodes are shown."),
            body,
        )
        .into_any_element()
    }
}

fn legend_item(label: &str, color: u32) -> AnyElement {
    div()
        .flex()
        .items_center()
        .gap(px(6.))
        .child(div().size(px(8.)).rounded_full().bg(c(color)))
        .child(text_dim(label.to_string()))
        .into_any_element()
}

fn status_bars(data: &Data) -> gpui::Div {
    let sm = &data.summary;
    let total: u64 = sm.status.values().sum();
    let mut col = div().flex().flex_col().gap(px(10.));
    for class in ["2xx", "3xx", "4xx", "5xx"] {
        let n = sm.status.get(class).copied().unwrap_or(0);
        let color = match class {
            "2xx" => GREEN,
            "3xx" => BLUE,
            "4xx" => YELLOW,
            _ => RED,
        };
        let share = if total == 0 {
            0.0
        } else {
            n as f64 / total as f64
        };
        col = col.child(hbar(class, n, total, color, fmt_pct(share, 1)));
    }
    col
}

fn method_bars(data: &Data) -> gpui::Div {
    let mut methods: Vec<(&String, &u64)> = data.summary.methods.iter().collect();
    methods.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let total: u64 = methods.iter().map(|m| *m.1).sum();
    let mut col = div().flex().flex_col().gap(px(10.));
    if methods.is_empty() {
        col = col.child(text_dim("Nothing recorded for this filter.").text_size(px(12.)));
    }
    for (name, n) in methods.into_iter().take(6) {
        let share = if total == 0 {
            0.0
        } else {
            *n as f64 / total as f64
        };
        col = col.child(hbar(name, *n, total, BLUE, fmt_pct(share, 1)));
    }
    col
}

fn latency_bars(data: &Data) -> gpui::Div {
    let sm = &data.summary;
    let max = sm.p99_ms.max(1);
    let mut col = div().flex().flex_col().gap(px(10.));
    for (label, v) in [
        ("Average", sm.avg_ms),
        ("p50", sm.p50_ms as f64),
        ("p95", sm.p95_ms as f64),
        ("p99", sm.p99_ms as f64),
    ] {
        col = col.child(hbar(label, v as u64, max, BLUE, fmt_ms(v)));
    }
    col
}
