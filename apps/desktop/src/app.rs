use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cite_client::{ClientError, MemoryTokenStore, NodeClient, TokenStore};
use gpui::{
    AnyElement, App, Context, Entity, IntoElement, Render, Window, deferred, div, prelude::*, px,
};

use crate::api::{NodeHandle, spawn_io};
use crate::config::{DesktopConfig, DesktopNode};
use crate::demo::{demo_config, demo_nodes};
use crate::keychain::KeychainTokenStore;
use crate::theme::{
    ACCENT, BG, BLUE, BORDER, CARD_RADIUS, CHIP_RADIUS, DIM, DIVIDER, GREEN, INPUT, RED,
    ROW_RADIUS, SIDEBAR, SURFACE, TEXT, TOPBAR, Tone, c, chip_fill, chip_stroke, tint,
};
use crate::ui::input::TextInput;
use crate::ui::widgets::{BtnKind, btn, id, strong, text_dim};
use crate::ui::{
    bots, create, detail, firewall, maintenance, nodes, overview, settings, sites, storage, traffic,
};

const TICK: Duration = Duration::from_millis(500);
const LOGO_FLIP_TICKS: u64 = 5;
const REFRESH_TICKS: u64 = 6;
const TOAST_TICKS: u64 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    Overview,
    Nodes,
    Sites,
    SiteDetail { node: String, id: String },
    SiteNew,
    Traffic,
    Bots,
    Explore,
    Export,
    Firewall,
    Maintenance,
    Settings,
}

impl View {
    pub fn parse(name: &str) -> Option<View> {
        Some(match name {
            "overview" => View::Overview,
            "nodes" => View::Nodes,
            "sites" => View::Sites,
            "site-detail" => View::SiteDetail {
                node: String::new(),
                id: "shop".into(),
            },
            "site-new" => View::SiteNew,
            "traffic" => View::Traffic,
            "bots" => View::Bots,
            "explore" => View::Explore,
            "export" => View::Export,
            "firewall" => View::Firewall,
            "maintenance" => View::Maintenance,
            "settings" => View::Settings,
            _ => return None,
        })
    }

    pub fn section(&self) -> &'static str {
        match self {
            View::Overview => "Overview",
            View::Nodes => "Nodes",
            View::Sites | View::SiteDetail { .. } | View::SiteNew => "Sites",
            View::Traffic | View::Bots | View::Explore | View::Export => "Traffic",
            View::Firewall => "Firewall",
            View::Maintenance => "Maintenance",
            View::Settings => "Settings",
        }
    }

    fn target(label: &str) -> View {
        match label {
            "Nodes" => View::Nodes,
            "Sites" => View::Sites,
            "Traffic" => View::Traffic,
            "Firewall" => View::Firewall,
            "Maintenance" => View::Maintenance,
            "Settings" => View::Settings,
            _ => View::Overview,
        }
    }
}

const NAV: [&str; 7] = [
    "Overview",
    "Nodes",
    "Sites",
    "Traffic",
    "Firewall",
    "Maintenance",
    "Settings",
];

pub enum Load<T> {
    Idle,
    Loading,
    Ready(T),
    Failed(String),
}

impl<T> Load<T> {
    pub fn ready(&self) -> Option<&T> {
        match self {
            Load::Ready(v) => Some(v),
            _ => None,
        }
    }

    pub fn from_result(res: Result<T, ClientError>) -> Self {
        match res {
            Ok(v) => Load::Ready(v),
            Err(e) => Load::Failed(e.to_string()),
        }
    }
}

pub struct Toast {
    pub text: String,
    pub tone: Tone,
    pub until: u64,
}

pub struct Confirm {
    pub title: String,
    pub message: String,
    pub label: String,
    pub danger: bool,
    pub action: Box<dyn FnOnce(&mut Console, &mut Context<Console>)>,
}

#[derive(Debug)]
pub struct Options {
    pub demo: bool,
    pub view: Option<View>,
    pub select: Option<String>,
    pub inspect: bool,
}

pub struct Console {
    pub demo: bool,
    pub config: DesktopConfig,
    pub config_path: PathBuf,
    pub tokens: Arc<dyn TokenStore>,
    pub handles: Vec<NodeHandle>,
    pub connect_errors: BTreeMap<String, String>,
    pub view: View,
    pub selected: Option<String>,
    pub switcher_open: bool,
    pub toast: Option<Toast>,
    pub confirm: Option<Confirm>,
    pub tick: u64,
    pub overview: overview::State,
    pub nodes: nodes::State,
    pub sites: sites::State,
    pub detail: detail::State,
    pub create: create::State,
    pub traffic: traffic::State,
    pub bots: bots::State,
    pub archives: storage::State,
    pub firewall: firewall::State,
    pub maintenance: maintenance::State,
    pub settings: settings::State,
}

impl Console {
    pub fn new(opts: Options, cx: &mut Context<Self>) -> Self {
        let (config, config_path, tokens): (DesktopConfig, PathBuf, Arc<dyn TokenStore>) =
            if opts.demo {
                (
                    demo_config(),
                    PathBuf::new(),
                    Arc::new(MemoryTokenStore::new()),
                )
            } else {
                let path = crate::config::config_path();
                let cfg = DesktopConfig::load(&path).unwrap_or_default();
                (cfg, path, Arc::new(KeychainTokenStore::system()))
            };
        let mut console = Console {
            demo: opts.demo,
            config,
            config_path,
            tokens,
            handles: Vec::new(),
            connect_errors: BTreeMap::new(),
            view: opts.view.unwrap_or(View::Overview),
            selected: opts.select,
            switcher_open: false,
            toast: None,
            confirm: None,
            tick: 0,
            overview: overview::State::default(),
            nodes: nodes::State::new(cx),
            sites: sites::State::new(cx),
            detail: detail::State::new(cx),
            create: create::State::new(cx),
            traffic: traffic::State {
                auto_inspect: opts.inspect,
                ..traffic::State::default()
            },
            bots: bots::State::new(cx),
            archives: storage::State::new(cx),
            firewall: firewall::State::new(cx),
            maintenance: maintenance::State::new(cx),
            settings: settings::State::new(cx),
        };
        console.connect();
        if let View::SiteDetail { node, .. } = &mut console.view
            && node.is_empty()
        {
            *node = console
                .handles
                .first()
                .map(|h| h.name().to_string())
                .unwrap_or_default();
        }
        console.load_current(cx);
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(TICK).await;
                if this.update(cx, |this, cx| this.on_tick(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        console
    }

    // Rebuilds the per-node clients from the config, recording why a node could not be reached.
    pub fn connect(&mut self) {
        self.handles.clear();
        self.connect_errors.clear();
        if self.demo {
            self.handles = demo_nodes()
                .into_iter()
                .map(|(name, node)| NodeHandle::Demo(name, node))
                .collect();
            return;
        }
        for node in &self.config.nodes {
            match build_client(node, self.tokens.as_ref()) {
                Ok(client) => self.handles.push(NodeHandle::Live(client)),
                Err(msg) => {
                    self.connect_errors.insert(node.name.clone(), msg);
                }
            }
        }
    }

    pub fn node_names(&self) -> Vec<String> {
        self.config.nodes.iter().map(|n| n.name.clone()).collect()
    }

    // Fan-out views use this; single-node views use active_handle instead.
    pub fn selected_handles(&self) -> Vec<NodeHandle> {
        match &self.selected {
            Some(name) => self
                .handles
                .iter()
                .filter(|h| h.name() == name)
                .cloned()
                .collect(),
            None => self.handles.clone(),
        }
    }

    // Views that act on one node use the selected node, falling back to the first one.
    pub fn active_handle(&self) -> Option<NodeHandle> {
        match &self.selected {
            Some(name) => self.handles.iter().find(|h| h.name() == name).cloned(),
            None => self.handles.first().cloned(),
        }
    }

    pub fn active_name(&self) -> Option<String> {
        self.active_handle().map(|h| h.name().to_string())
    }

    pub fn handle_named(&self, name: &str) -> Option<NodeHandle> {
        self.handles.iter().find(|h| h.name() == name).cloned()
    }

    pub fn fetch<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        fut: F,
        apply: impl FnOnce(&mut Self, Result<T, ClientError>, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        let task = spawn_io(fut);
        cx.spawn(async move |this, cx| {
            let res = task.await;
            let _ = this.update(cx, |this, cx| apply(this, res, cx));
        })
        .detach();
    }

    // Toasts expire on the tick loop so no timer is held per message.
    pub fn say(&mut self, text: impl Into<String>, tone: Tone) {
        self.toast = Some(Toast {
            text: text.into(),
            tone,
            until: self.tick + TOAST_TICKS,
        });
    }

    pub fn ask(&mut self, confirm: Confirm) {
        self.confirm = Some(confirm);
    }

    // Switching view always reloads, so stale data from an earlier visit never shows.
    pub fn navigate(&mut self, view: View, cx: &mut Context<Self>) {
        self.view = view;
        self.switcher_open = false;
        self.load_current(cx);
        cx.notify();
    }

    pub fn select_node(&mut self, name: Option<String>, cx: &mut Context<Self>) {
        self.selected = name;
        self.switcher_open = false;
        self.load_current(cx);
        cx.notify();
    }

    // Each view owns its loader; the switcher and navigation both funnel through here.
    pub fn load_current(&mut self, cx: &mut Context<Self>) {
        match self.view.clone() {
            View::Overview | View::Nodes => self.load_overview(cx),
            View::Sites => self.load_sites(cx),
            View::SiteDetail { node, id } => self.load_detail(node, id, cx),
            View::SiteNew => self.reset_create(cx),
            View::Traffic => self.load_traffic(cx),
            View::Bots => self.load_bots(cx),
            View::Explore => self.load_explore(cx),
            View::Export => {}
            View::Firewall => self.load_firewall(cx),
            View::Maintenance => self.load_maintenance(cx),
            View::Settings => self.load_settings(cx),
        }
    }

    pub fn logo_flipped(&self) -> bool {
        (self.tick / LOGO_FLIP_TICKS) % 2 == 1
    }

    // Runs every half second: flips the logo colours, expires toasts and refreshes live traffic.
    fn on_tick(&mut self, cx: &mut Context<Self>) {
        self.tick += 1;
        let mut dirty = self.tick.is_multiple_of(LOGO_FLIP_TICKS);
        if self.toast.as_ref().is_some_and(|t| t.until <= self.tick) {
            self.toast = None;
            dirty = true;
        }
        if self.view == View::Traffic && self.tick.is_multiple_of(REFRESH_TICKS) {
            self.refresh_recent(cx);
        }
        // The export panel counts elapsed seconds, so it repaints while a download runs.
        if self.view == View::Export
            && matches!(self.bots.export.run, bots::ExportRun::Running { .. })
        {
            dirty = true;
        }
        if dirty {
            cx.notify();
        }
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let section = self.view.section();
        let mut nav = div().flex().flex_col().gap(px(2.)).mt(px(20.));
        for label in NAV {
            let active = label == section;
            nav = nav.child(
                div()
                    .id(id("nav", label))
                    .flex()
                    .items_center()
                    .h(px(32.))
                    .px(px(10.))
                    .rounded(px(ROW_RADIUS))
                    .cursor_pointer()
                    .text_size(px(13.))
                    .when(active, |d| d.bg(chip_fill()).text_color(c(0xffffff)))
                    .when(!active, |d| {
                        d.text_color(c(DIM)).hover(|s| s.bg(tint(0xffffff, 0.04)))
                    })
                    .child(label)
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.navigate(View::target(label), cx)),
                    ),
            );
        }
        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(240.))
            .h_full()
            .px(px(10.))
            .py(px(14.))
            .bg(c(SIDEBAR))
            .border_r_1()
            .border_color(c(DIVIDER))
            .child(
                div()
                    .px(px(10.))
                    .pt(px(4.))
                    .child(logo(self.logo_flipped())),
            )
            .child(nav)
            .child(div().flex_1())
            .child(
                text_dim(if self.demo {
                    "Demo data"
                } else {
                    "Keychain-backed"
                })
                .px(px(10.))
                .text_size(px(11.)),
            )
    }

    fn topbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let label = self.selected.clone().unwrap_or_else(|| "All nodes".into());
        let mut switcher = div().relative().child(
            div()
                .id("switcher")
                .flex()
                .items_center()
                .gap(px(8.))
                .h(px(28.))
                .px(px(10.))
                .rounded(px(CHIP_RADIUS))
                .border_1()
                .border_color(chip_stroke())
                .bg(c(INPUT))
                .cursor_pointer()
                .text_size(px(12.))
                .child(text_dim("Node"))
                .child(strong(label))
                .child(text_dim("\u{25be}"))
                .on_click(cx.listener(|this, _, _, cx| {
                    this.switcher_open = !this.switcher_open;
                    cx.notify();
                })),
        );
        if self.switcher_open {
            let mut menu = div()
                .absolute()
                .top(px(32.))
                .right(px(0.))
                .w(px(220.))
                .p(px(4.))
                .rounded(px(CARD_RADIUS))
                .border_1()
                .border_color(c(BORDER))
                .bg(c(SURFACE))
                .occlude()
                .flex()
                .flex_col()
                .child(self.switch_row(cx, None));
            for name in self.node_names() {
                menu = menu.child(self.switch_row(cx, Some(name)));
            }
            switcher = switcher.child(deferred(menu).with_priority(10));
        }
        div()
            .flex()
            .flex_none()
            .items_center()
            .justify_between()
            .h(px(36.))
            .px(px(24.))
            .border_b_1()
            .border_color(c(DIVIDER))
            .bg(c(TOPBAR))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(strong(self.view.section()).text_size(px(13.)))
                    .when_some(self.breadcrumb(), |d, crumb| {
                        d.child(text_dim("/")).child(text_dim(crumb))
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(
                        btn(id("topbar", "refresh"), "Refresh", BtnKind::Plain).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.load_current(cx);
                                cx.notify();
                            }),
                        ),
                    )
                    .child(switcher),
            )
    }

    fn breadcrumb(&self) -> Option<String> {
        match &self.view {
            View::SiteDetail { id, .. } => Some(id.clone()),
            View::SiteNew => Some("New site".into()),
            _ => None,
        }
    }

    fn switch_row(&self, cx: &mut Context<Self>, name: Option<String>) -> impl IntoElement {
        let active = self.selected == name;
        let text = name.clone().unwrap_or_else(|| "All nodes".into());
        div()
            .id(id("switch", &text))
            .flex()
            .items_center()
            .justify_between()
            .h(px(32.))
            .px(px(10.))
            .rounded(px(ROW_RADIUS))
            .cursor_pointer()
            .text_size(px(13.))
            .when(active, |d| d.bg(chip_fill()).text_color(c(0xffffff)))
            .when(!active, |d| {
                d.text_color(c(DIM)).hover(|s| s.bg(tint(0xffffff, 0.04)))
            })
            .child(text)
            .on_click(cx.listener(move |this, _, _, cx| this.select_node(name.clone(), cx)))
    }

    // Modal and toast layers are deferred so they paint above the scrolling content.
    fn overlays(&mut self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let mut out = Vec::new();
        if let Some(confirm) = &self.confirm {
            let kind = if confirm.danger {
                BtnKind::Danger
            } else {
                BtnKind::Primary
            };
            let dialog = div()
                .w(px(420.))
                .p(px(20.))
                .flex()
                .flex_col()
                .gap(px(12.))
                .rounded(px(CARD_RADIUS))
                .border_1()
                .border_color(c(BORDER))
                .bg(c(SURFACE))
                .child(strong(confirm.title.clone()).text_size(px(16.)))
                .child(text_dim(confirm.message.clone()).text_size(px(13.)))
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap(px(8.))
                        .child(
                            btn(id("confirm", "cancel"), "Cancel", BtnKind::Plain).on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.confirm = None;
                                    cx.notify();
                                }),
                            ),
                        )
                        .child(btn(id("confirm", "ok"), &confirm.label, kind).on_click(
                            cx.listener(|this, _, _, cx| {
                                if let Some(confirm) = this.confirm.take() {
                                    (confirm.action)(this, cx);
                                }
                                cx.notify();
                            }),
                        )),
                );
            let scrim = div()
                .absolute()
                .top(px(0.))
                .left(px(0.))
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .bg(tint(0x000000, 0.6))
                .occlude()
                .child(dialog);
            out.push(deferred(scrim).with_priority(50).into_any_element());
        }
        if let Some(toast) = &self.toast {
            let color = toast.tone.color();
            let body = div()
                .absolute()
                .bottom(px(20.))
                .right(px(20.))
                .max_w(px(420.))
                .px(px(14.))
                .py(px(10.))
                .rounded(px(CARD_RADIUS))
                .border_1()
                .border_color(tint(color, 0.5))
                .bg(c(SURFACE))
                .text_size(px(13.))
                .child(toast.text.clone());
            out.push(deferred(body).with_priority(60).into_any_element());
        }
        out
    }
}

impl Render for Console {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = match self.view.clone() {
            View::Overview => self.render_overview(cx),
            View::Nodes => self.render_nodes(cx),
            View::Sites => self.render_sites(cx),
            View::SiteDetail { .. } => self.render_detail(cx),
            View::SiteNew => self.render_create(cx),
            View::Traffic => self.render_traffic(cx),
            View::Bots => self.render_bots(cx),
            View::Explore => self.render_explore(cx),
            View::Export => self.render_export(cx),
            View::Firewall => self.render_firewall(cx),
            View::Maintenance => self.render_maintenance(cx),
            View::Settings => self.render_settings(cx),
        };
        let scroll_key = format!("scroll-{:?}", self.view);
        let main = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .h_full()
            .child(self.topbar(cx))
            .child(
                div()
                    .id(gpui::SharedString::from(scroll_key))
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(16.))
                            .p(px(24.))
                            .max_w(px(1180.))
                            .child(content),
                    ),
            );
        div()
            .relative()
            .flex()
            .size_full()
            .bg(c(BG))
            .text_color(c(TEXT))
            .text_size(px(13.))
            .child(self.sidebar(cx))
            .child(main)
            .children(self.overlays(cx))
    }
}

pub fn new_input(
    cx: &mut App,
    placeholder: &str,
    shape: impl FnOnce(TextInput) -> TextInput,
) -> Entity<TextInput> {
    cx.new(|icx| shape(TextInput::new(icx, placeholder)))
}

// Tokens come only from the token store; the config file never holds one.
fn build_client(node: &DesktopNode, tokens: &dyn TokenStore) -> Result<NodeClient, String> {
    let cfg = node.resolve().map_err(|e| e.to_string())?;
    let token = tokens
        .get(&node.name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no API token in the keychain for this node".to_string())?;
    NodeClient::new(&cfg, token).map_err(|e| e.to_string())
}

// The wordmark is drawn from the same 15 by 5 pixel grid as the web logo.
pub fn logo(flipped: bool) -> impl IntoElement {
    const UNIT: f32 = 5.0;
    let (blue, green) = if flipped {
        (GREEN, BLUE)
    } else {
        (BLUE, GREEN)
    };
    let rects: [(u32, &[(f32, f32, f32, f32)]); 4] = [
        (
            ACCENT,
            &[(1., 0., 3., 1.), (0., 1., 1., 3.), (1., 4., 3., 1.)],
        ),
        (
            ACCENT,
            &[
                (8., 0., 1., 1.),
                (7., 1., 3., 1.),
                (8., 2., 1., 2.),
                (8., 4., 2., 1.),
            ],
        ),
        (blue, &[(5., 0., 1., 1.), (5., 2., 1., 3.)]),
        (
            green,
            &[
                (12., 0., 2., 1.),
                (11., 1., 1., 1.),
                (14., 1., 1., 1.),
                (11., 2., 4., 1.),
                (11., 3., 1., 1.),
                (12., 4., 3., 1.),
            ],
        ),
    ];
    let mut root = div().relative().w(px(15. * UNIT)).h(px(5. * UNIT));
    for (color, group) in rects {
        for (x, y, w, h) in group {
            root = root.child(
                div()
                    .absolute()
                    .left(px(x * UNIT))
                    .top(px(y * UNIT))
                    .w(px(w * UNIT))
                    .h(px(h * UNIT))
                    .bg(c(color)),
            );
        }
    }
    root
}

impl Console {
    pub fn error_block(&self, cx: &mut Context<Self>, message: &str) -> AnyElement {
        div()
            .flex()
            .items_center()
            .justify_between()
            .gap(px(12.))
            .px(px(14.))
            .py(px(12.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(tint(RED, 0.5))
            .bg(tint(RED, 0.08))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .child(strong("Could not load this view").text_color(c(RED)))
                    .child(text_dim(message.to_string()).text_size(px(12.))),
            )
            .child(
                btn(id("retry", "load"), "Retry", BtnKind::Plain).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.load_current(cx);
                        cx.notify();
                    },
                )),
            )
            .into_any_element()
    }

    pub fn no_nodes_block(&self, cx: &mut Context<Self>) -> AnyElement {
        crate::ui::widgets::card(
            None,
            None,
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap(px(10.))
                .py(px(30.))
                .child(strong("No nodes yet").text_size(px(16.)))
                .child(text_dim("Add a node to start managing sites."))
                .child(
                    btn(id("empty", "add"), "Add a node", BtnKind::Primary)
                        .on_click(cx.listener(|this, _, _, cx| this.navigate(View::Nodes, cx))),
                ),
        )
        .into_any_element()
    }

    // Per-node views say which node they are showing when "All nodes" is selected.
    pub fn scope_note(&self) -> Option<AnyElement> {
        if self.selected.is_none() && self.handles.len() > 1 {
            let name = self.active_name()?;
            return Some(
                text_dim(format!(
                    "Showing {name}. Pick a node in the switcher to change it."
                ))
                .text_size(px(12.))
                .into_any_element(),
            );
        }
        None
    }
}

impl Console {
    // Runs a change on a node, reports the outcome in a toast and reloads the current view.
    pub fn mutate<T, F>(&mut self, cx: &mut Context<Self>, fut: F, done: String)
    where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        self.fetch(cx, fut, move |this, res, cx| {
            match res {
                Ok(_) => this.say(done, Tone::Ok),
                Err(e) => this.say(e.to_string(), Tone::Bad),
            }
            this.load_current(cx);
            cx.notify();
        });
    }
}
