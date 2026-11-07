use std::path::PathBuf;

use cite_client::{AnalyticsStats, BOT_CLASSES, ClientError, ExportFormat, ExportKind, TOP_KINDS};
use cite_edge::analytics::TopItem;
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;
use gpui::{AnyElement, Context, Entity, div, prelude::*, px, relative};

use crate::api::{join_all, run_export};
use crate::app::{Console, Load, View, new_input};
use crate::bots::{
    EXPORT_KINDS, ExportForm, METHOD_HELP, METHODS, band_color, build_query, class_breakdown,
    class_color, class_help, class_label, downloads_dir, export_file_name, export_kind_help,
    export_kind_label, fmt_share, fmt_stamp, format_label, friendly_error, is_unsupported,
    merge_bot_summaries, parse_signals, score_color, score_histogram, share_of, signal_help,
    signal_label, top_kind_label,
};
use crate::demo::now_ms;
use crate::model::{WINDOWS, fmt_bytes, fmt_int, fmt_num, fmt_pct, merge_top};
use crate::theme::{BORDER, DIM, SURFACE, Tone, c, tint};
use crate::ui::chart::{PANE_MIN, STAT_MIN, clip_tip, wide};
use crate::ui::input::TextInput;
use crate::ui::traffic::top_table;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, clip, field, grid_min, id, mono, notice, pill, pill_color, seg_item,
    seg_row, skeleton, stat, strong, table, text_dim,
};

const TOP_LIMIT: usize = 25;
// The tick loop runs twice a second, so two ticks make one elapsed second.
const TICKS_PER_SECOND: u64 = 2;

pub struct NodeStorage {
    pub node: String,
    pub outcome: StorageOutcome,
}

pub enum StorageOutcome {
    Stats(AnalyticsStats),
    Unsupported,
    Failed(String),
}

pub enum ExportRun {
    Idle,
    // Console tick at which the export began; the elapsed-seconds display is derived from it.
    Running { since_tick: u64 },
    Done { path: PathBuf, bytes: u64 },
    Failed(String),
}

pub struct ExportState {
    pub kind: ExportKind,
    pub format: ExportFormat,
    pub top_kind: usize,
    pub custom_range: bool,
    pub bot_class: Option<usize>,
    pub method: Option<usize>,
    pub run: ExportRun,
    pub site: Entity<TextInput>,
    pub from: Entity<TextInput>,
    pub to: Entity<TextInput>,
    pub status_min: Entity<TextInput>,
    pub status_max: Entity<TextInput>,
    pub min_score: Entity<TextInput>,
    pub host: Entity<TextInput>,
    pub path_prefix: Entity<TextInput>,
    pub client_ip: Entity<TextInput>,
    pub limit: Entity<TextInput>,
}

pub struct State {
    pub bots: Load<BotSummary>,
    pub top_kind: usize,
    pub top: Load<Vec<TopItem>>,
    pub storage: Load<Vec<NodeStorage>>,
    pub export: ExportState,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            bots: Load::Idle,
            top_kind: 0,
            top: Load::Idle,
            storage: Load::Idle,
            export: ExportState {
                kind: ExportKind::Requests,
                format: ExportFormat::Csv,
                top_kind: 0,
                custom_range: false,
                bot_class: None,
                method: None,
                run: ExportRun::Idle,
                site: new_input(cx, "All sites", |i| i.mono()),
                from: new_input(cx, "2026-11-05 14:30", |i| i.mono()),
                to: new_input(cx, "2026-11-05 15:30", |i| i.mono()),
                status_min: new_input(cx, "100", |i| i.mono()),
                status_max: new_input(cx, "599", |i| i.mono()),
                min_score: new_input(cx, "0", |i| i.mono()),
                host: new_input(cx, "shop.example.com", |i| i.mono()),
                path_prefix: new_input(cx, "/api", |i| i.mono()),
                client_ip: new_input(cx, "203.0.113.7", |i| i.mono()),
                limit: new_input(cx, "No limit", |i| i.mono()),
            },
        }
    }
}

// Succeeds when at least one node answered, so one old or unreachable node does not blank the view.
fn gather<T>(results: Vec<Option<Result<T, ClientError>>>) -> Result<Vec<T>, ClientError> {
    let mut parts = Vec::new();
    let mut first_err = None;
    for r in results.into_iter().flatten() {
        match r {
            Ok(p) => parts.push(p),
            Err(e) => {
                // Only the first error is kept, and it is surfaced only when no node answered.
                first_err.get_or_insert(e);
            }
        }
    }
    if parts.is_empty() {
        return Err(
            first_err.unwrap_or_else(|| ClientError::Config("no nodes are connected".into()))
        );
    }
    Ok(parts)
}

fn settle<T>(res: Result<T, ClientError>) -> Load<T> {
    match res {
        Ok(v) => Load::Ready(v),
        Err(e) => Load::Failed(friendly_error(&e)),
    }
}

impl Console {
    pub fn load_bots(&mut self, cx: &mut Context<Self>) {
        self.bots.bots = Load::Loading;
        let handles = self.selected_handles();
        let window = WINDOWS[self.traffic.window];
        let fut = async move {
            let results = join_all(
                handles
                    .into_iter()
                    .map(|h| async move { h.bots(window).await })
                    .collect(),
            )
            .await;
            Ok(merge_bot_summaries(&gather(results)?))
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.bots.bots = settle(res);
            cx.notify();
        });
    }

    pub fn load_top(&mut self, cx: &mut Context<Self>) {
        self.bots.top = Load::Loading;
        let handles = self.selected_handles();
        let window = WINDOWS[self.traffic.window];
        let kind = TOP_KINDS[self.bots.top_kind];
        let fut = async move {
            let results = join_all(
                handles
                    .into_iter()
                    .map(|h| async move { h.top(kind, window, TOP_LIMIT).await })
                    .collect(),
            )
            .await;
            let parts = gather(results)?;
            Ok(merge_top(parts.iter().collect(), TOP_LIMIT))
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.bots.top = settle(res);
            cx.notify();
        });
    }

    // Each node reports on its own, because an older node answers 404 while its neighbours do not.
    pub fn load_storage(&mut self, cx: &mut Context<Self>) {
        self.bots.storage = Load::Loading;
        let handles = self.selected_handles();
        let fut = async move {
            let results = join_all(
                handles
                    .into_iter()
                    .map(|h| async move {
                        let outcome = match h.stats().await {
                            Ok(s) => StorageOutcome::Stats(s),
                            Err(e) if is_unsupported(&e) => StorageOutcome::Unsupported,
                            Err(e) => StorageOutcome::Failed(e.to_string()),
                        };
                        NodeStorage {
                            node: h.name().to_string(),
                            outcome,
                        }
                    })
                    .collect(),
            )
            .await;
            Ok::<_, ClientError>(results.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.bots.storage = settle(res);
            cx.notify();
        });
    }

    pub fn load_explore(&mut self, cx: &mut Context<Self>) {
        self.load_top(cx);
        self.load_storage(cx);
        self.load_archives(cx);
    }

    fn export_form(&self, cx: &Context<Self>) -> ExportForm {
        let e = &self.bots.export;
        let text = |i: &Entity<TextInput>| i.read(cx).text().to_string();
        ExportForm {
            kind: e.kind,
            format: e.format,
            top: TOP_KINDS[e.top_kind].to_string(),
            custom_range: e.custom_range,
            from: text(&e.from),
            to: text(&e.to),
            site: text(&e.site),
            status_min: text(&e.status_min),
            status_max: text(&e.status_max),
            min_score: text(&e.min_score),
            bot_class: e
                .bot_class
                .map(|i| BOT_CLASSES[i].to_string())
                .unwrap_or_default(),
            host: text(&e.host),
            path_prefix: text(&e.path_prefix),
            client_ip: text(&e.client_ip),
            method: e.method.map(|i| METHODS[i].to_string()).unwrap_or_default(),
            limit: text(&e.limit),
            ..ExportForm::new(WINDOWS[self.traffic.window])
        }
    }

    // The file goes to the Downloads folder: the app has no native save dialog to defer to.
    pub fn start_export(&mut self, cx: &mut Context<Self>) {
        if matches!(self.bots.export.run, ExportRun::Running { .. }) {
            return;
        }
        let Some(handle) = self.active_handle() else {
            self.bots.export.run = ExportRun::Failed("No node is connected.".into());
            return;
        };
        let now = now_ms();
        let form = self.export_form(cx);
        let query = match build_query(&form, now) {
            Ok(q) => q,
            Err(msg) => {
                self.bots.export.run = ExportRun::Failed(msg);
                return;
            }
        };
        let Some(dir) = downloads_dir() else {
            self.bots.export.run = ExportRun::Failed(
                "Cannot find your home directory, so there is nowhere to save the file.".into(),
            );
            return;
        };
        let name = export_file_name(&form, now);
        self.bots.export.run = ExportRun::Running {
            since_tick: self.tick,
        };
        self.fetch(cx, run_export(handle, query, dir, name), |this, res, cx| {
            let next = match res {
                Ok(report) => {
                    this.say("Export saved", Tone::Ok);
                    ExportRun::Done {
                        path: report.path,
                        bytes: report.bytes,
                    }
                }
                Err(e) => ExportRun::Failed(friendly_error(&e)),
            };
            this.bots.export.run = next;
            cx.notify();
        });
    }

    fn scope_subtitle(&self, what: &str) -> String {
        match &self.selected {
            Some(n) => format!("{what} for {n}"),
            None => format!("{what} across every node"),
        }
    }

    pub fn render_bots(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let subtitle = self.scope_subtitle("Bot traffic");
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(self.traffic_header(cx, &View::Bots, &subtitle));
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        match &self.bots.bots {
            Load::Idle | Load::Loading => {
                col = col
                    .child(skeleton(86.))
                    .child(skeleton(220.))
                    .child(skeleton(220.))
            }
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(summary) => col = col.child(bots_body(summary)),
        }
        col.into_any_element()
    }

    pub fn render_explore(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let subtitle = self.scope_subtitle("Top values and storage");
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(self.traffic_header(cx, &View::Explore, &subtitle));
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        let mut kinds = Vec::new();
        for (i, kind) in TOP_KINDS.iter().enumerate() {
            kinds.push(
                seg_item(
                    id("top-kind", kind),
                    top_kind_label(kind),
                    i == self.bots.top_kind,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.bots.top_kind = i;
                    this.load_top(cx);
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let body = match &self.bots.top {
            Load::Idle | Load::Loading => skeleton(240.).into_any_element(),
            Load::Failed(msg) => {
                let msg = msg.clone();
                self.error_block(cx, &msg)
            }
            Load::Ready(items) => top_explorer(items),
        };
        col = col.child(card(
            Some("Top explorer"),
            Some("The most frequent values of one field in this window"),
            div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(div().flex().child(seg_row(kinds)))
                .child(body),
        ));
        col = match &self.bots.storage {
            Load::Idle | Load::Loading => col.child(skeleton(120.)),
            Load::Failed(msg) => col.child(notice(msg, Tone::Bad)),
            Load::Ready(nodes) => col.child(storage_card(nodes)),
        };
        col = col.child(self.archive_card(cx));
        col.into_any_element()
    }

    pub fn render_export(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let subtitle = self.scope_subtitle("Download analytics");
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(self.traffic_header(cx, &View::Export, &subtitle));
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        col = col.children(self.scope_note());
        col.child(self.export_card(cx)).into_any_element()
    }

    fn export_card(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let e = &self.bots.export;
        let mut kinds = Vec::new();
        for k in EXPORT_KINDS {
            kinds.push(
                seg_item(
                    id("exp-kind", k.as_str()),
                    export_kind_label(k),
                    e.kind == k,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.bots.export.kind = k;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let mut formats = Vec::new();
        for f in [ExportFormat::Csv, ExportFormat::Ndjson] {
            formats.push(
                seg_item(
                    id("exp-format", format_label(f)),
                    format_label(f),
                    e.format == f,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.bots.export.format = f;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let window = WINDOWS[self.traffic.window];
        let ranges = [
            (false, format!("Current window ({window})")),
            (true, "Custom range".to_string()),
        ];
        let mut range_items = Vec::new();
        for (custom, label) in ranges {
            range_items.push(
                seg_item(id("exp-range", custom), &label, e.custom_range == custom)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.bots.export.custom_range = custom;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let half = |label: &str, hint: Option<&str>, input: &Entity<TextInput>| {
            div()
                .flex_1()
                .min_w(px(180.))
                .child(field(label, hint, input.clone()))
        };
        let mut form = div().flex().flex_col().gap(px(14.)).child(field(
            "What to export",
            Some(export_kind_help(e.kind)),
            div().flex().child(seg_row(kinds)),
        ));
        if e.kind == ExportKind::Top {
            let mut tops = Vec::new();
            for (i, kind) in TOP_KINDS.iter().enumerate() {
                tops.push(
                    seg_item(id("exp-top", kind), top_kind_label(kind), i == e.top_kind)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.bots.export.top_kind = i;
                            cx.notify();
                        }))
                        .into_any_element(),
                );
            }
            form = form.child(field("Field", None, div().flex().child(seg_row(tops))));
        }
        form = form
            .child(field(
                "Format",
                Some("CSV opens in a spreadsheet; NDJSON is one JSON object per line."),
                div().flex().child(seg_row(formats)),
            ))
            .child(field(
                "Time range",
                None,
                div().flex().child(seg_row(range_items)),
            ));
        if e.custom_range {
            form = form.child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(12.))
                    .child(half("From (UTC)", Some("YYYY-MM-DD HH:MM"), &e.from))
                    .child(half("To (UTC)", Some("YYYY-MM-DD HH:MM"), &e.to)),
            );
        }
        form = form.child(
            div()
                .flex()
                .flex_wrap()
                .gap(px(12.))
                .child(half("Site", Some("Leave empty for every site"), &e.site))
                .child(half(
                    "Row limit",
                    Some("Leave empty for no limit"),
                    &e.limit,
                )),
        );
        if matches!(e.kind, ExportKind::Requests | ExportKind::Bots) {
            let mut classes = vec![
                seg_item(id("exp-class", "any"), "Any", e.bot_class.is_none())
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.bots.export.bot_class = None;
                        cx.notify();
                    }))
                    .into_any_element(),
            ];
            for (i, class) in BOT_CLASSES.iter().enumerate() {
                classes.push(
                    seg_item(
                        id("exp-class", class),
                        &class_label(class),
                        e.bot_class == Some(i),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.bots.export.bot_class = Some(i);
                        cx.notify();
                    }))
                    .into_any_element(),
                );
            }
            let mut methods = vec![
                seg_item(id("exp-method", "any"), "Any", e.method.is_none())
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.bots.export.method = None;
                        cx.notify();
                    }))
                    .into_any_element(),
            ];
            for (i, method) in METHODS.iter().enumerate() {
                methods.push(
                    seg_item(id("exp-method", method), method, e.method == Some(i))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.bots.export.method = Some(i);
                            cx.notify();
                        }))
                        .into_any_element(),
                );
            }
            form = form
                .child(strong("Filters").text_size(px(13.)))
                .child(field(
                    "Bot class",
                    None,
                    div().flex().child(seg_row(classes)),
                ))
                .child(field("Method", None, div().flex().child(seg_row(methods))))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap(px(12.))
                        .child(half("Minimum status", None, &e.status_min))
                        .child(half("Maximum status", None, &e.status_max))
                        .child(half("Minimum bot score", Some("0 to 100"), &e.min_score)),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap(px(12.))
                        .child(half("Host", None, &e.host))
                        .child(half("Path prefix", None, &e.path_prefix))
                        .child(half("Client IP", None, &e.client_ip)),
                );
        } else {
            form = form.child(
                text_dim("Request filters apply to request and bot exports only.")
                    .text_size(px(12.)),
            );
        }
        let running = matches!(e.run, ExportRun::Running { .. });
        let status = match &e.run {
            ExportRun::Idle => None,
            ExportRun::Running { since_tick } => {
                let secs = self.tick.saturating_sub(*since_tick) / TICKS_PER_SECOND;
                Some(notice(
                    &format!("Exporting, {secs}s elapsed. Large exports can take several minutes."),
                    Tone::Info,
                ))
            }
            ExportRun::Done { path, bytes } => Some(notice(
                &format!("Saved {} to {}", fmt_bytes(*bytes), path.display()),
                Tone::Ok,
            )),
            ExportRun::Failed(msg) => Some(notice(msg, Tone::Bad)),
        };
        let destination = match downloads_dir() {
            Some(dir) => text_dim(format!(
                "Saves into {}. An existing file is never replaced.",
                dir.display()
            )),
            None => {
                text_dim("Your home directory could not be found.").text_color(c(Tone::Bad.color()))
            }
        };
        let save = btn(
            id("exp", "save"),
            if running {
                "Exporting..."
            } else {
                "Save export"
            },
            BtnKind::Primary,
        )
        .on_click(cx.listener(|this, _, _, cx| {
            this.start_export(cx);
            cx.notify();
        }));
        let footer = div()
            .flex()
            .items_center()
            .gap(px(12.))
            .child(save)
            .child(destination.text_size(px(12.)));
        form = form.child(footer).children(status);
        card(
            Some("Export"),
            Some("Stream a file from the node to this computer"),
            form,
        )
        .into_any_element()
    }
}

fn help_note(title: &str, text: &str) -> AnyElement {
    div()
        .flex()
        .flex_col()
        .gap(px(4.))
        .px(px(14.))
        .py(px(10.))
        .rounded(px(crate::theme::CARD_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(SURFACE))
        .child(strong(title.to_string()).text_size(px(12.)))
        .child(text_dim(text.to_string()).text_size(px(12.)))
        .into_any_element()
}

fn bots_body(s: &BotSummary) -> AnyElement {
    let tone = if s.bot_share_pct >= 25.0 {
        Tone::Warn
    } else {
        Tone::Muted
    };
    let tiles = [
        stat(
            "Bot share",
            fmt_share(s.bot_share_pct),
            format!(
                "{} of {} requests",
                fmt_int(s.bot_requests),
                fmt_int(s.total_requests)
            ),
            tone,
        ),
        stat(
            "Bot requests",
            fmt_num(s.bot_requests),
            "flagged by the detector".into(),
            Tone::Muted,
        ),
        stat(
            "Total requests",
            fmt_num(s.total_requests),
            "in this window".into(),
            Tone::Muted,
        ),
    ];
    let stats = grid_min(
        STAT_MIN,
        tiles
            .into_iter()
            .map(|t| t.min_w_0().h_full().into_any_element())
            .collect(),
    );
    let half = |card: gpui::Div| card.flex_1().min_w_0().into_any_element();
    let row_a = grid_min(
        PANE_MIN,
        vec![
            half(card(
                Some("Traffic by class"),
                Some("Segment width is the share of requests"),
                class_panel(s),
            )),
            half(card(
                Some("Score distribution"),
                Some("Requests per bot score band"),
                score_panel(s),
            )),
        ],
    );
    let row_b = grid_min(
        PANE_MIN,
        vec![
            half(card(
                Some("Top signals"),
                Some("What the detector noticed"),
                signals_table(&s.signals),
            )),
            half(card(
                Some("Top bot agents"),
                None,
                top_table(&s.agents, false),
            )),
        ],
    );
    div()
        .flex()
        .flex_col()
        .gap(px(16.))
        .child(help_note("How detection works", METHOD_HELP))
        .child(stats)
        .child(row_a)
        .child(row_b)
        .into_any_element()
}

// A single segmented bar shows the mix; the rows below name each class and explain it.
fn class_panel(s: &BotSummary) -> AnyElement {
    let slices = class_breakdown(&s.classes);
    let total: u64 = slices.iter().map(|x| x.count).sum();
    let mut bar = div()
        .flex()
        .w_full()
        .h(px(14.))
        .rounded_full()
        .overflow_hidden()
        .bg(tint(0xffffff, 0.06));
    // Empty classes get no bar segment but still appear in the rows below.
    for slice in slices.iter().filter(|x| x.count > 0) {
        bar = bar.child(
            div()
                .h_full()
                .w(relative(share_of(slice.count, total) as f32))
                .bg(c(slice.color)),
        );
    }
    let mut rows = div().flex().flex_col().gap(px(10.));
    for slice in &slices {
        rows = rows.child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(
                    div()
                        .flex_none()
                        .size(px(10.))
                        .rounded_full()
                        .bg(c(slice.color)),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w_0()
                        .child(strong(slice.label.clone()))
                        .child(text_dim(class_help(&slice.key)).text_size(px(11.))),
                )
                .child(
                    mono(fmt_int(slice.count))
                        .flex_none()
                        .min_w(px(56.))
                        .flex()
                        .justify_end(),
                )
                .child(
                    mono(fmt_share(share_of(slice.count, total) * 100.0))
                        .flex_none()
                        .min_w(px(48.))
                        .flex()
                        .justify_end()
                        .text_color(c(DIM)),
                ),
        );
    }
    div()
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(bar)
        .child(rows)
        .into_any_element()
}

fn score_panel(s: &BotSummary) -> AnyElement {
    let hist = score_histogram(&s.score_buckets);
    // Floored at 1 so an empty histogram never scales against zero.
    let max = hist.iter().map(|(_, n)| *n).max().unwrap_or(0).max(1);
    let mut cols = div().flex().items_end().gap(px(10.)).h(px(180.));
    for (i, (label, count)) in hist.iter().enumerate() {
        // The tallest bar is 140 px; any non-zero count gets at least 3 px so it stays visible.
        let height = if *count == 0 {
            0.0
        } else {
            (140.0 * share_of(*count, max) as f32).max(3.0)
        };
        cols = cols.child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .justify_end()
                .flex_1()
                .h_full()
                .gap(px(4.))
                .child(text_dim(fmt_num(*count)).text_size(px(11.)))
                .child(
                    div()
                        .w_full()
                        .h(px(height))
                        .rounded(px(3.))
                        .bg(c(band_color(i))),
                )
                .child(text_dim(label.to_string()).text_size(px(11.))),
        );
    }
    cols.into_any_element()
}

fn signals_table(items: &[TopItem]) -> AnyElement {
    let rows: Vec<Vec<AnyElement>> = items
        .iter()
        .take(8)
        .map(|t| {
            vec![
                div()
                    .flex()
                    .flex_col()
                    .min_w_0()
                    .child(mono(signal_label(&t.key)))
                    .child(
                        clip(signal_help(&t.key))
                            .text_size(px(11.))
                            .text_color(c(DIM)),
                    )
                    .into_any_element(),
                mono(fmt_int(t.count)).into_any_element(),
            ]
        })
        .collect();
    table(
        &[Col::flex("Signal"), Col::fixed("Requests", 90.).right()],
        rows,
        Some(text_dim("No signals raised in this window.").p(px(12.))),
    )
    .into_any_element()
}

fn top_explorer(items: &[TopItem]) -> AnyElement {
    let sum: u64 = items.iter().map(|t| t.count).sum();
    // Not every top kind carries byte totals, so the column appears only when some item has them.
    let with_bytes = items.iter().any(|t| t.bytes > 0);
    let rows: Vec<Vec<AnyElement>> = items
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut cells = vec![
                clip_tip(id("bots-top-key", i), t.key.clone())
                    .font_family(crate::theme::MONO)
                    .text_size(px(12.))
                    .into_any_element(),
                mono(fmt_int(t.count)).into_any_element(),
                mono(fmt_pct(share_of(t.count, sum), 1))
                    .text_color(c(DIM))
                    .into_any_element(),
            ];
            if with_bytes {
                cells.push(
                    mono(fmt_bytes(t.bytes))
                        .text_color(c(DIM))
                        .into_any_element(),
                );
            }
            cells
        })
        .collect();
    let mut cols = vec![
        Col::flex("Value"),
        Col::fixed("Requests", 100.).right(),
        Col::fixed("Share of list", 100.).right(),
    ];
    if with_bytes {
        cols.push(Col::fixed("Bytes", 90.).right());
    }
    table(
        &cols,
        rows,
        Some(text_dim("Nothing recorded in this window.").p(px(12.))),
    )
    .into_any_element()
}

fn storage_card(nodes: &[NodeStorage]) -> AnyElement {
    let stamp = |ts: Option<i64>| ts.map_or_else(|| "-".to_string(), fmt_stamp);
    let rows: Vec<Vec<AnyElement>> = nodes
        .iter()
        .map(|n| {
            let name = strong(n.node.clone()).into_any_element();
            match &n.outcome {
                StorageOutcome::Stats(s) => vec![
                    name,
                    mono(fmt_int(s.rows)).into_any_element(),
                    mono(fmt_bytes(s.db_bytes)).into_any_element(),
                    mono(stamp(s.oldest_ts_ms)).into_any_element(),
                    mono(stamp(s.newest_ts_ms)).into_any_element(),
                    (if s.write_errors > 0 {
                        pill(
                            &format!("{} write errors", fmt_int(s.write_errors)),
                            Tone::Bad,
                        )
                    } else {
                        pill("healthy", Tone::Ok)
                    })
                    .into_any_element(),
                ],
                // Dash cells keep these rows aligned with the six columns of the Stats row.
                StorageOutcome::Unsupported => vec![
                    name,
                    text_dim("-").into_any_element(),
                    text_dim("-").into_any_element(),
                    text_dim("-").into_any_element(),
                    text_dim("-").into_any_element(),
                    pill("needs an update", Tone::Warn).into_any_element(),
                ],
                StorageOutcome::Failed(msg) => vec![
                    name,
                    text_dim("-").into_any_element(),
                    text_dim("-").into_any_element(),
                    text_dim("-").into_any_element(),
                    clip(msg.clone()).text_size(px(12.)).into_any_element(),
                    pill("error", Tone::Bad).into_any_element(),
                ],
            }
        })
        .collect();
    let cols = [
        Col::flex("Node"),
        Col::fixed("Rows", 100.).right(),
        Col::fixed("Database", 90.).right(),
        Col::fixed("Oldest", 170.),
        Col::fixed("Newest", 170.),
        Col::fixed("Status", 150.),
    ];
    let any_old = nodes
        .iter()
        .any(|n| matches!(n.outcome, StorageOutcome::Unsupported));
    let mut body = div().flex().flex_col().gap(px(10.)).child(wide(
        id("bots", "storage-table"),
        cols.iter().filter_map(|col| col.width).sum::<f32>() + 160.,
        table(&cols, rows, Some(text_dim("No nodes reported.").p(px(12.)))),
    ));
    if any_old {
        body = body.child(
            text_dim("Nodes marked as needing an update predate the storage endpoint and report nothing here.")
                .text_size(px(12.)),
        );
    }
    card(
        Some("Storage"),
        Some("Analytics database on each node"),
        body,
    )
    .into_any_element()
}

// Class and score together, or a dash for events recorded before bot detection existed.
pub fn bot_badge(e: &LogEvent) -> AnyElement {
    if e.bot_class.is_empty() {
        return text_dim("-").into_any_element();
    }
    div()
        .flex()
        .items_center()
        .gap(px(6.))
        .child(pill_color(
            &class_label(&e.bot_class),
            class_color(&e.bot_class),
        ))
        .child(mono(e.bot_score.to_string()).text_color(c(score_color(e.bot_score))))
        .into_any_element()
}

fn kv(label: &str, value: &str, missing: &str) -> AnyElement {
    let shown = if value.is_empty() {
        text_dim(missing.to_string())
            .text_size(px(12.))
            .into_any_element()
    } else {
        mono(value.to_string()).into_any_element()
    };
    div()
        .flex()
        .gap(px(12.))
        .child(
            text_dim(label.to_string())
                .flex_none()
                .w(px(140.))
                .text_size(px(12.)),
        )
        .child(div().flex_1().min_w_0().child(shown))
        .into_any_element()
}

// Headers are listed with their absence made explicit, since a missing header is itself the evidence.
pub fn request_detail(e: &LogEvent, close: AnyElement) -> AnyElement {
    let has_verdict = !e.bot_class.is_empty();
    // Events stored before bot detection existed carry no headers, so "not sent" would be a false claim for them.
    let missing = if has_verdict {
        "not sent"
    } else {
        "not captured"
    };
    let verdict = if has_verdict {
        div()
            .flex()
            .items_center()
            .gap(px(10.))
            .child(pill_color(
                &class_label(&e.bot_class),
                class_color(&e.bot_class),
            ))
            .child(
                mono(format!("score {} of 100", e.bot_score))
                    .text_color(c(score_color(e.bot_score))),
            )
            .child(text_dim(class_help(&e.bot_class)).text_size(px(12.)))
    } else {
        div().child(text_dim("This request was recorded without a bot verdict."))
    };
    let mut signals = div().flex().flex_col().gap(px(6.));
    let parsed = parse_signals(&e.bot_signals);
    for key in &parsed {
        signals = signals.child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(pill(&signal_label(key), Tone::Warn))
                .child(text_dim(signal_help(key)).text_size(px(12.))),
        );
    }
    if parsed.is_empty() && has_verdict {
        signals = signals.child(text_dim("No signals were raised.").text_size(px(12.)));
    }
    let timing = if has_verdict {
        format!("{} ms to respond, {} ms in total", e.resp_ms, e.total_ms)
    } else {
        format!("{} ms in total", e.total_ms)
    };
    let headers = div()
        .flex()
        .flex_col()
        .gap(px(6.))
        .child(kv("User agent", &e.user_agent, "empty"))
        .child(kv("Accept", &e.accept, missing))
        .child(kv("Accept-Language", &e.accept_language, missing))
        .child(kv("Accept-Encoding", &e.accept_encoding, missing))
        .child(kv("Sec-Fetch-Site", &e.sec_fetch_site, missing))
        .child(kv("Sec-Fetch-Mode", &e.sec_fetch_mode, missing))
        .child(kv("Sec-Fetch-Dest", &e.sec_fetch_dest, missing))
        .child(kv("Sec-CH-UA", &e.sec_ch_ua, missing))
        .child(kv("Referer", &e.referer, "none"))
        .child(kv("HTTP version", &e.http_version, "not captured"))
        .child(kv("TLS version", &e.tls_version, "not captured"))
        .child(kv("Client", &e.client_ip, "unknown"))
        .child(kv("Backend", &e.backend, "none"))
        .child(kv("Timing", &timing, "unknown"));
    card(
        Some("Request detail"),
        Some(&format!("{} {} on {}", e.method, e.path, e.host)),
        div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(12.))
                    .child(verdict)
                    .child(close),
            )
            .child(signals)
            .child(headers),
    )
    .into_any_element()
}
