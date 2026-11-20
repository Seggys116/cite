use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cite_client::{ClientError, MemoryTokenStore, NodeClient, TokenStore};
use gpui::{
    AnyElement, App, ClickEvent, Context, Entity, FocusHandle, IntoElement, KeyDownEvent, Render,
    Subscription, Window, WindowBounds, actions, deferred, div, prelude::*, px,
};

use crate::api::{NodeHandle, spawn_io};
use crate::config::{DesktopConfig, DesktopNode};
use crate::demo::{demo_config, demo_nodes, demo_offline};
use crate::keychain::KeychainTokenStore;
use crate::scope::{Origin, Scope, apply_if_current};
use crate::targets::NodeInfo;
use crate::theme::{
    ACCENT, BG, BLUE, BORDER, CARD_RADIUS, CHIP_RADIUS, DIM, DIVIDER, GREEN, INPUT, PANEL_RADIUS,
    RED, ROW_RADIUS, SIDEBAR, SURFACE, TEXT, Tone, WINDOW, c, chip_fill, chip_stroke, font, layout,
    space, tint,
};
use crate::ui::input::TextInput;
use crate::ui::scroll::scroll_area;
use crate::ui::widgets::{
    BtnKind, btn, btn_off, checkbox, float_shadow, id, pill, strong, text_dim,
};
use crate::ui::{
    alertspanel, analytics, bots, certs, certtools, create, databases, detail, firewall,
    maintenance, nodes, ops, overview, settings, sites, storage, topology, traffic,
};
use crate::window_state::{Frame, WindowState, window_state_path};
use crate::zone::keep_for_site;

actions!(cite_shell, [ToggleSidebar]);

const TICK: Duration = Duration::from_millis(500);
const LOGO_FLIP_TICKS: u64 = 5;
const REFRESH_TICKS: u64 = 6;
// The topology redraws its load about every 10 seconds.
const TOPOLOGY_REFRESH_TICKS: u64 = 20;
const TOAST_TICKS: u64 = 8;
const ERROR_TOAST_TICKS: u64 = 24;
const MAX_TOASTS: usize = 4;
// Window moves arrive in bursts, so the state file is written once they settle.
const SAVE_DELAY_TICKS: u64 = 2;
const NARROW_CONTENT_W: f32 = 760.0;

// Successes and notes go after about 4 seconds, errors after about 12.
fn toast_until(tone: Tone, tick: u64) -> u64 {
    if tone == Tone::Bad {
        tick + ERROR_TOAST_TICKS
    } else {
        tick + TOAST_TICKS
    }
}

// The root view repaints whole on any notify, so the logo flips only while it is on screen in an active window.
fn logo_flip_due(tick: u64, window_active: bool, sidebar_collapsed: bool) -> bool {
    window_active && !sidebar_collapsed && tick.is_multiple_of(LOGO_FLIP_TICKS)
}

// The topology polls only while it is on screen in an active window.
fn topology_refresh_due(tick: u64, on_topology: bool, window_active: bool) -> bool {
    on_topology && window_active && tick.is_multiple_of(TOPOLOGY_REFRESH_TICKS)
}

// A hovered toast is held until a moment after the pointer leaves it.
fn expire_toasts(toasts: &mut Vec<Toast>, hovered: Option<u64>, tick: u64) -> bool {
    let before = toasts.len();
    for t in toasts.iter_mut() {
        if Some(t.id) == hovered {
            t.until = t.until.max(tick + 2);
        }
    }
    toasts.retain(|t| t.until > tick);
    toasts.len() != before
}

#[cfg(test)]
mod toast_tests {
    use super::*;

    fn toast(id: u64, tone: Tone, until: u64) -> Toast {
        Toast {
            id,
            text: String::new(),
            tone,
            until,
        }
    }

    #[test]
    fn errors_last_longer_than_other_toasts() {
        assert_eq!(toast_until(Tone::Bad, 10), 10 + ERROR_TOAST_TICKS);
        assert_eq!(toast_until(Tone::Ok, 10), 10 + TOAST_TICKS);
        assert_eq!(toast_until(Tone::Warn, 0), TOAST_TICKS);
        assert_eq!(TICK.as_millis() as u64 * TOAST_TICKS, 4_000);
        assert_eq!(TICK.as_millis() as u64 * ERROR_TOAST_TICKS, 12_000);
    }

    #[test]
    fn expired_toasts_go_and_a_hovered_one_stays() {
        let mut list = vec![
            toast(1, Tone::Ok, 5),
            toast(2, Tone::Bad, 5),
            toast(3, Tone::Ok, 9),
        ];
        assert!(expire_toasts(&mut list, Some(2), 5));
        assert_eq!(list.iter().map(|t| t.id).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(list[0].until, 7);
        assert!(!expire_toasts(&mut list, None, 6));
        assert!(expire_toasts(&mut list, None, 7));
        assert_eq!(list.iter().map(|t| t.id).collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn the_logo_repaints_only_when_it_can_be_seen() {
        assert!(logo_flip_due(LOGO_FLIP_TICKS, true, false));
        assert!(!logo_flip_due(LOGO_FLIP_TICKS + 1, true, false));
        assert!(!logo_flip_due(LOGO_FLIP_TICKS, false, false));
        assert!(!logo_flip_due(LOGO_FLIP_TICKS, true, true));
    }

    #[test]
    fn the_topology_polls_about_every_ten_seconds_and_only_while_visible() {
        assert_eq!(TICK.as_millis() as u64 * TOPOLOGY_REFRESH_TICKS, 10_000);
        assert!(topology_refresh_due(TOPOLOGY_REFRESH_TICKS, true, true));
        assert!(topology_refresh_due(TOPOLOGY_REFRESH_TICKS * 3, true, true));
        assert!(!topology_refresh_due(
            TOPOLOGY_REFRESH_TICKS + 1,
            true,
            true
        ));
        assert!(!topology_refresh_due(TOPOLOGY_REFRESH_TICKS, false, true));
        assert!(!topology_refresh_due(TOPOLOGY_REFRESH_TICKS, true, false));
    }

    #[test]
    fn the_topology_view_has_a_name_a_section_and_a_sidebar_entry() {
        assert_eq!(View::parse("topology"), Some(View::Topology));
        assert_eq!(View::Topology.section(), "Topology");
        assert_eq!(View::target("Topology"), View::Topology);
        let sites = NAV.iter().position(|l| *l == "Sites");
        let topology = NAV.iter().position(|l| *l == "Topology");
        assert_eq!(topology, sites.map(|i| i + 1));
    }

    #[test]
    fn the_databases_view_has_a_name_a_section_and_a_sidebar_entry() {
        assert_eq!(View::parse("databases"), Some(View::Databases));
        assert_eq!(View::Databases.section(), "Databases");
        assert_eq!(View::target("Databases"), View::Databases);
        // Every sidebar label leads to its own section, and Databases sits with the other node pages before Traffic.
        for label in NAV {
            assert_eq!(View::target(label).section(), label);
        }
        let databases = NAV.iter().position(|l| *l == "Databases");
        let traffic = NAV.iter().position(|l| *l == "Traffic");
        assert!(databases.is_some() && databases < traffic);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    Overview,
    Nodes,
    Sites,
    SiteDetail { node: String, id: String },
    SiteNew,
    Topology,
    Databases,
    Traffic,
    Analytics,
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
            "topology" => View::Topology,
            "databases" => View::Databases,
            "traffic" => View::Traffic,
            "analytics" => View::Analytics,
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
            View::Topology => "Topology",
            View::Databases => "Databases",
            View::Traffic | View::Bots | View::Explore | View::Export => "Traffic",
            View::Analytics => "Analytics",
            View::Firewall => "Firewall",
            View::Maintenance => "Maintenance",
            View::Settings => "Settings",
        }
    }

    fn target(label: &str) -> View {
        match label {
            "Nodes" => View::Nodes,
            "Sites" => View::Sites,
            "Topology" => View::Topology,
            "Databases" => View::Databases,
            "Traffic" => View::Traffic,
            "Analytics" => View::Analytics,
            "Firewall" => View::Firewall,
            "Maintenance" => View::Maintenance,
            "Settings" => View::Settings,
            _ => View::Overview,
        }
    }
}

const NAV: [&str; 10] = [
    "Overview",
    "Nodes",
    "Sites",
    "Topology",
    "Databases",
    "Traffic",
    "Analytics",
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
    pub id: u64,
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

// A write that lands on nodes the person ticks. `selected` is the live tick state; the action
// receives the confirmed targets, in node order.
#[allow(dead_code)] // Built by the views that fan a write out to several nodes.
pub struct TargetPicker {
    pub title: String,
    pub message: String,
    // The confirm button reads "<verb> for <target>".
    pub verb: String,
    pub nodes: Vec<NodeInfo>,
    pub selected: Vec<String>,
    pub danger: bool,
    pub action: Box<dyn FnOnce(&mut Console, &mut Context<Console>, Vec<String>)>,
}

#[derive(Debug)]
pub struct Options {
    pub demo: bool,
    pub view: Option<View>,
    pub select: Option<String>,
    pub inspect: bool,
    pub scroll_end: bool,
}

pub struct Console {
    pub demo: bool,
    // Set only by the --scroll preview flag so a screenshot can reach content below the fold.
    pub preview_scroll: Option<gpui::ScrollHandle>,
    pub config: DesktopConfig,
    pub config_path: PathBuf,
    pub tokens: Arc<dyn TokenStore>,
    pub handles: Vec<NodeHandle>,
    pub connect_errors: BTreeMap<String, String>,
    pub view: View,
    pub selected: Option<String>,
    pub switcher_open: bool,
    // Newest last; drawn as a stack in the bottom-right corner.
    pub toasts: Vec<Toast>,
    toast_seq: u64,
    hovered_toast: Option<u64>,
    pub confirm: Option<Confirm>,
    pub picker: Option<TargetPicker>,
    pub tick: u64,
    pub sidebar_collapsed: bool,
    // Width of the page column inside its padding, measured on every paint for views that adapt.
    pub content_width: f32,
    window_state: WindowState,
    window_state_changed: Option<u64>,
    focus: FocusHandle,
    _subs: Vec<Subscription>,
    // Set on every paint, so timers can stay quiet while the window is in the background.
    pub window_active: bool,
    pub scope: Scope,
    pub overview: overview::State,
    pub nodes: nodes::State,
    pub sites: sites::State,
    pub topology: topology::State,
    pub detail: detail::State,
    pub ops: ops::OpsState,
    // What the Data tab of the site on screen shows, and the connector jobs being followed.
    pub site_data: detail::data::SiteDataState,
    pub dbs: databases::State,
    // Database moves between nodes: the saved list, the ones this app is driving, and the form.
    pub xfer: databases::transfers::XferState,
    pub create: create::State,
    pub traffic: traffic::State,
    pub analytics: analytics::State,
    pub bots: bots::State,
    pub archives: storage::State,
    pub certs: certs::State,
    pub(crate) certtools: certtools::CertToolsState,
    pub(crate) alerts: alertspanel::AlertsState,
    pub firewall: firewall::State,
    pub maintenance: maintenance::State,
    pub settings: settings::State,
}

impl Console {
    pub fn new(
        opts: Options,
        window_state: WindowState,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
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
            preview_scroll: opts.scroll_end.then(gpui::ScrollHandle::new),
            config,
            config_path,
            tokens,
            handles: Vec::new(),
            connect_errors: BTreeMap::new(),
            view: opts.view.unwrap_or(View::Overview),
            selected: opts.select,
            switcher_open: false,
            toasts: Vec::new(),
            toast_seq: 0,
            hovered_toast: None,
            confirm: None,
            picker: None,
            tick: 0,
            sidebar_collapsed: window_state.sidebar_collapsed,
            content_width: layout::CONTENT_MAX_W,
            window_state,
            window_state_changed: None,
            focus: cx.focus_handle(),
            _subs: Vec::new(),
            window_active: true,
            scope: Scope::default(),
            overview: overview::State::default(),
            nodes: nodes::State::new(cx),
            sites: sites::State::new(cx),
            topology: topology::State::default(),
            detail: detail::State::new(cx),
            ops: ops::OpsState::new(cx),
            site_data: detail::data::SiteDataState::new(cx),
            dbs: databases::State::new(cx),
            xfer: databases::transfers::XferState::new(opts.demo),
            create: create::State::new(cx),
            traffic: traffic::State {
                auto_inspect: opts.inspect,
                ..traffic::State::default()
            },
            analytics: analytics::State::new(cx),
            bots: bots::State::new(cx),
            archives: storage::State::new(cx),
            certs: certs::State::new(cx),
            certtools: Default::default(),
            alerts: Default::default(),
            firewall: firewall::State::new(cx),
            maintenance: maintenance::State::new(cx),
            settings: settings::State::new(cx),
        };
        console.connect();
        console.analytics.node = console.selected.clone();
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
        // Demo runs never write the window state, so screenshots cannot change a real user's layout.
        if !console.demo {
            console
                ._subs
                .push(cx.observe_window_bounds(window, |this, window, _| {
                    this.record_bounds(window);
                }));
            console._subs.push(cx.on_app_quit(|this, _| {
                if this.window_state_changed.is_some() {
                    this.save_window_state();
                }
                async {}
            }));
        }
        window.focus(&console.focus);
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
        self.scope.advance();
        self.reset_node_data();
        self.handles.clear();
        self.connect_errors.clear();
        if self.demo {
            self.handles = demo_nodes()
                .into_iter()
                .map(|(name, node)| NodeHandle::Demo(name, node))
                .collect();
            // The demo node that cannot be reached is a config entry without a client, as a real one would be.
            self.connect_errors.extend(demo_offline());
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

    // Where the user is right now, in the terms an action is tagged with.
    pub fn origin(&self) -> Origin {
        match &self.view {
            View::SiteDetail { .. } => {
                Origin::new(&self.detail.node, Some(&self.detail.site_id), &self.view)
            }
            _ => Origin::new(
                self.active_name().as_deref().unwrap_or(""),
                None,
                &self.view,
            ),
        }
    }

    pub fn still_here(&self, origin: &Origin) -> bool {
        self.origin() == *origin
    }

    // Actions use this: the completion learns whether the user is still where the action was issued.
    pub fn fetch_origin<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        fut: F,
        apply: impl FnOnce(&mut Self, Result<T, ClientError>, bool, &Origin, &mut Context<Self>)
        + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        let origin = self.origin();
        self.toasts.retain(|t| t.tone != Tone::Bad);
        self.fetch(cx, fut, move |this, res, cx| {
            let here = this.still_here(&origin);
            apply(this, res, here, &origin, cx);
        });
    }

    // Loaders use this: a result that finishes after a node or view change belongs to the old scope and is dropped.
    pub fn fetch_scoped<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        fut: F,
        apply: impl FnOnce(&mut Self, Result<T, ClientError>, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        let issued = self.scope;
        self.fetch(cx, fut, move |this, res, cx| {
            apply_if_current(this.scope, issued, res, |res| apply(this, res, cx));
        });
    }

    // Data loaded for one node must not stay on screen, or be saved back, once another node is selected.
    pub fn reset_node_data(&mut self) {
        self.settings.data = Load::Idle;
        self.settings.data_node.clear();
        self.settings.error = None;
        self.certs.note = None;
        self.certs.ranges_note = None;
        self.certs.list = Load::Idle;
        self.certs.ranges = Load::Idle;
        self.certs.unsupported = false;
        self.certs.ranges_unsupported = false;
        self.archives.list = Load::Idle;
        // Data loaded for one node, and the jobs followed on it, mean nothing on another.
        self.site_data.load = detail::data::DataLoad::Idle;
        self.site_data.for_site = (String::new(), String::new());
        self.site_data.jobs.clear();
        self.dbs.load = databases::DbLoad::Idle;
        self.dbs.for_node.clear();
        self.analytics.data = Load::Idle;
        self.analytics.node_modern.clear();
        self.analytics.modern_any = true;
        self.analytics.log.rows.clear();
        self.analytics.log.cursors.clear();
        self.analytics.log.inspect = None;
    }

    // Toasts expire on the tick loop so no timer is held per message; a new action also clears earlier errors.
    pub fn say(&mut self, text: impl Into<String>, tone: Tone) {
        let text = text.into();
        self.toasts.retain(|t| t.text != text);
        self.toast_seq += 1;
        self.toasts.push(Toast {
            id: self.toast_seq,
            text,
            tone,
            until: toast_until(tone, self.tick),
        });
        if self.toasts.len() > MAX_TOASTS {
            let extra = self.toasts.len() - MAX_TOASTS;
            self.toasts.drain(..extra);
        }
    }

    pub fn dismiss_toast(&mut self, toast_id: u64, cx: &mut Context<Self>) {
        self.toasts.retain(|t| t.id != toast_id);
        if self.hovered_toast == Some(toast_id) {
            self.hovered_toast = None;
        }
        cx.notify();
    }

    pub fn toggle_sidebar(&mut self, cx: &mut Context<Self>) {
        self.sidebar_collapsed = !self.sidebar_collapsed;
        if !self.demo {
            self.window_state.sidebar_collapsed = self.sidebar_collapsed;
            self.window_state_changed = Some(self.tick);
        }
        cx.notify();
    }

    // Views can stack their columns when this is true.
    pub fn narrow(&self) -> bool {
        self.content_width < NARROW_CONTENT_W
    }

    fn record_bounds(&mut self, window: &Window) {
        let (bounds, maximized) = match window.window_bounds() {
            WindowBounds::Windowed(b) => (b, false),
            WindowBounds::Maximized(b) => (b, true),
            // A full-screen window keeps the frame it will return to.
            WindowBounds::Fullscreen(b) => (b, self.window_state.maximized),
        };
        let frame = Frame {
            x: f32::from(bounds.origin.x),
            y: f32::from(bounds.origin.y),
            width: f32::from(bounds.size.width),
            height: f32::from(bounds.size.height),
        };
        if self.window_state.frame != Some(frame) || self.window_state.maximized != maximized {
            self.window_state.frame = Some(frame);
            self.window_state.maximized = maximized;
            self.window_state_changed = Some(self.tick);
        }
    }

    // A failed write only loses the remembered layout, so it is reported on stderr and not as a toast.
    fn save_window_state(&mut self) {
        self.window_state_changed = None;
        if let Err(err) = self.window_state.save(&window_state_path()) {
            eprintln!("cannot save the window state: {err}");
        }
    }

    pub fn ask(&mut self, confirm: Confirm) {
        self.confirm = Some(confirm);
    }

    // An offline node cannot be ticked, so none starts selected.
    #[allow(dead_code)]
    pub fn ask_targets(&mut self, mut picker: TargetPicker) {
        let online: Vec<NodeInfo> = picker.nodes.iter().filter(|n| n.online).cloned().collect();
        picker.selected = crate::targets::normalize_targets(&picker.selected, &online);
        self.picker = Some(picker);
    }

    // A node is online when it connected and has no connect error.
    pub fn node_infos(&self) -> Vec<NodeInfo> {
        self.config
            .nodes
            .iter()
            .map(|n| NodeInfo {
                name: n.name.clone(),
                online: !self.connect_errors.contains_key(&n.name)
                    && self.handles.iter().any(|h| h.name() == n.name),
            })
            .collect()
    }

    // The nodes ticked when a picker opens: the selected node, or none under All nodes.
    #[allow(dead_code)]
    pub fn initial_targets(&self) -> Vec<String> {
        crate::targets::initial_targets(self.selected.as_deref(), &self.node_infos())
    }

    // Switching view always reloads, so stale data from an earlier visit never shows.
    pub fn navigate(&mut self, view: View, cx: &mut Context<Self>) {
        // A zone secret is shown once and only on its own site page, so leaving that page drops it.
        let keep = match &view {
            View::SiteDetail { id, .. } => Some(id.clone()),
            _ => None,
        };
        keep_for_site(&mut self.detail.reveals, keep.as_deref());
        self.detail.busy = false;
        // A key typed on the certificate panel must not outlive the visit to Settings.
        self.close_panel(cx);
        self.certtools_close(cx);
        // Arriving on a site page starts without the error of an earlier visit.
        self.detail.error = None;
        self.detail.site_id.clear();
        self.view = view;
        self.switcher_open = false;
        self.load_current(cx);
        cx.notify();
    }

    // Every change of the selected node goes through here, so nothing loaded for the old node survives.
    pub fn set_node(&mut self, name: Option<String>, cx: &mut Context<Self>) {
        self.selected = name;
        self.close_panel(cx);
        self.detail.error = None;
        self.detail.busy = false;
        self.detail.site_id.clear();
        self.scope.advance();
        self.reset_node_data();
        self.certs
            .ranges_input
            .update(cx, |input, cx| input.set_text("", cx));
        self.certtools_reset(cx);
        self.alerts_reset(cx);
        self.ops_reset(cx);
        self.data_reset(cx);
        self.dbs_reset(cx);
        self.analytics.node = self.selected.clone();
    }

    pub fn select_node(&mut self, name: Option<String>, cx: &mut Context<Self>) {
        self.set_node(name, cx);
        self.switcher_open = false;
        self.load_current(cx);
        cx.notify();
    }

    // Each view owns its loader; the switcher and navigation both funnel through here.
    pub fn load_current(&mut self, cx: &mut Context<Self>) {
        self.scope.advance();
        match self.view.clone() {
            View::Overview | View::Nodes => self.load_overview(cx),
            View::Sites => self.load_sites(cx),
            View::SiteDetail { node, id } => self.load_detail(node, id, cx),
            View::SiteNew => self.reset_create(cx),
            View::Topology => self.load_topology(cx),
            View::Databases => self.load_databases(cx),
            View::Traffic => self.load_traffic(cx),
            View::Analytics => self.load_analytics(false, cx),
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

    // Runs every half second: flips the logo colours, expires toasts and refreshes live data.
    fn on_tick(&mut self, cx: &mut Context<Self>) {
        self.tick += 1;
        let mut dirty = logo_flip_due(self.tick, self.window_active, self.sidebar_collapsed);
        self.ops_tick(cx);
        self.data_tick(cx);
        self.xfer_tick(cx);
        self.analytics_tick(cx);
        if expire_toasts(&mut self.toasts, self.hovered_toast, self.tick) {
            dirty = true;
        }
        if self
            .window_state_changed
            .is_some_and(|at| self.tick >= at + SAVE_DELAY_TICKS)
        {
            self.save_window_state();
        }
        if self.view == View::Traffic && self.tick.is_multiple_of(REFRESH_TICKS) {
            self.refresh_recent(cx);
        }
        if topology_refresh_due(self.tick, self.view == View::Topology, self.window_active) {
            self.refresh_topology(cx);
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

    // Term's sidebar glyph: a rounded frame with a bar down its left side.
    fn sidebar_toggle(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("sidebar-toggle")
            .flex()
            .items_center()
            .justify_center()
            .flex_none()
            .size(px(layout::CONTROL_H))
            .rounded(px(ROW_RADIUS))
            .cursor_pointer()
            .hover(|s| s.bg(tint(0xffffff, 0.06)))
            .child(
                div()
                    .flex()
                    .w(px(16.))
                    .h(px(13.))
                    .rounded(px(3.))
                    .border_1()
                    .border_color(c(DIM))
                    .child(div().w(px(5.)).h_full().border_r_1().border_color(c(DIM))),
            )
            .on_click(cx.listener(|this, _, _, cx| this.toggle_sidebar(cx)))
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let section = self.view.section();
        let mut nav = div()
            .flex()
            .flex_col()
            .gap(px(space::XXS))
            .mt(px(space::LG));
        for label in NAV {
            let active = label == section;
            nav = nav.child(
                div()
                    .id(id("nav", label))
                    .flex()
                    .items_center()
                    .h(px(layout::ROW_H))
                    .px(px(10.))
                    .rounded(px(ROW_RADIUS))
                    .cursor_pointer()
                    .text_size(px(font::BASE))
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
            .id("sidebar")
            .flex()
            .flex_col()
            .flex_none()
            .w(px(layout::SIDEBAR_W))
            .h_full()
            .rounded(px(PANEL_RADIUS))
            .border_1()
            .border_color(tint(0xffffff, 0.08))
            .bg(c(SIDEBAR))
            .child(
                div()
                    .id("sidebar-top")
                    .flex()
                    .flex_none()
                    .items_center()
                    .justify_end()
                    .h(px(layout::TOP_ROW_H))
                    .pl(px(layout::TRAFFIC_LIGHTS_W))
                    .pr(px(space::XS))
                    .on_click(cx.listener(zoom_on_double_click))
                    .child(self.sidebar_toggle(cx)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .px(px(10.))
                    .pb(px(space::MD))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .px(px(10.))
                            .pt(px(space::XS))
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
                        .text_size(px(font::XS)),
                    ),
            )
    }

    fn topbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let label = self.selected.clone().unwrap_or_else(|| "All nodes".into());
        let mut switcher = div().relative().child(
            div()
                .id("switcher")
                .flex()
                .items_center()
                .gap(px(space::SM))
                .h(px(layout::CONTROL_H))
                .px(px(10.))
                .rounded(px(CHIP_RADIUS))
                .border_1()
                .border_color(chip_stroke())
                .bg(c(INPUT))
                .cursor_pointer()
                .text_size(px(font::SM))
                .when(!self.narrow(), |d| d.child(text_dim("Node")))
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
                .top(px(layout::ROW_H))
                .right(px(0.))
                .w(px(220.))
                .p(px(space::XS))
                .rounded(px(CARD_RADIUS))
                .border_1()
                .border_color(c(BORDER))
                .bg(c(SURFACE))
                .shadow(float_shadow())
                .occlude()
                .flex()
                .flex_col()
                .child(self.switch_row(cx, None));
            for name in self.node_names() {
                menu = menu.child(self.switch_row(cx, Some(name)));
            }
            switcher = switcher.child(deferred(menu).with_priority(10));
        }
        // The panel's own header row, not a window strip: it shares the panel surface and clears the traffic lights when the sidebar is hidden.
        let collapsed = self.sidebar_collapsed;
        div()
            .id("panel-top")
            .flex()
            .flex_none()
            .items_center()
            .justify_between()
            .gap(px(space::MD))
            .h(px(layout::TOP_ROW_H + space::XS))
            .pr(px(space::MD))
            .pl(px(if collapsed {
                layout::TRAFFIC_LIGHTS_W - layout::WINDOW_INSET
            } else {
                space::LG
            }))
            .border_b_1()
            .border_color(c(DIVIDER))
            .on_click(cx.listener(zoom_on_double_click))
            .child(
                div()
                    .flex()
                    .items_center()
                    .min_w_0()
                    .gap(px(space::SM))
                    .when(collapsed, |d| d.child(self.sidebar_toggle(cx)))
                    .child(strong(self.view.section()).text_size(px(font::BASE)))
                    .when_some(self.breadcrumb(), |d, crumb| {
                        d.child(text_dim("/"))
                            .child(crate::ui::widgets::clip(crumb).text_color(c(DIM)))
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(px(space::SM))
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
                .max_w(gpui::relative(1.))
                .p(px(space::XL))
                .flex()
                .flex_col()
                .gap(px(space::MD))
                .rounded(px(CARD_RADIUS))
                .border_1()
                .border_color(c(BORDER))
                .bg(c(SURFACE))
                .shadow(float_shadow())
                .child(strong(confirm.title.clone()).text_size(px(font::LG)))
                .child(text_dim(confirm.message.clone()).text_size(px(font::BASE)))
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap(px(space::SM))
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
        if let Some(picker) = &self.picker {
            out.push(Self::picker_overlay(picker, cx));
        }
        if !self.toasts.is_empty() {
            let mut stack = div()
                .absolute()
                .bottom(px(space::XL))
                .right(px(space::XL))
                .flex()
                .flex_col()
                .items_end()
                .gap(px(space::SM));
            for toast in &self.toasts {
                stack = stack.child(self.toast_card(toast, cx));
            }
            out.push(deferred(stack).with_priority(60).into_any_element());
        }
        out
    }

    // The node picker: a checkbox row per node, a status line naming what changes, and a confirm
    // button that stays disabled until at least one node is ticked.
    fn picker_overlay(picker: &TargetPicker, cx: &mut Context<Self>) -> AnyElement {
        let chosen = crate::targets::normalize_targets(&picker.selected, &picker.nodes);
        let can_confirm = crate::targets::can_confirm(&picker.selected, &picker.nodes);
        let mut rows = scroll_area("picker-nodes")
            .max_h(px(240.))
            .flex()
            .flex_col()
            .gap(px(space::XXS));
        for node in &picker.nodes {
            let name = node.name.clone();
            let on = chosen.iter().any(|n| n == &node.name);
            let mut row = div()
                .id(id("pick-row", &node.name))
                .flex()
                .items_center()
                .gap(px(space::MD))
                .flex_none()
                .h(px(layout::ROW_H))
                .px(px(space::MD))
                .rounded(px(ROW_RADIUS))
                .child(checkbox(id("pick-box", &node.name), on))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w_0()
                        .text_color(c(if node.online { TEXT } else { DIM }))
                        .child(node.name.clone()),
                );
            if node.online {
                row = row
                    .cursor_pointer()
                    .when(on, |d| d.bg(chip_fill()))
                    .hover(|s| s.bg(tint(0xffffff, 0.05)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(p) = this.picker.as_mut() {
                            p.selected = crate::targets::toggle_target(&p.selected, &name);
                        }
                        cx.notify();
                    }));
            } else {
                row = row.child(pill("Offline", Tone::Muted));
            }
            rows = rows.child(row);
        }
        let (status, status_tone) = if can_confirm {
            let mut line = format!(
                "Will change {}.",
                crate::targets::target_summary(&picker.selected, &picker.nodes)
            );
            let rest = crate::targets::not_targeted(&picker.selected, &picker.nodes);
            if !rest.is_empty() {
                line.push_str(&format!(" Not changed: {}.", rest.join(", ")));
            }
            (line, Tone::Muted)
        } else {
            ("Pick at least one node.".to_string(), Tone::Warn)
        };
        let kind = if picker.danger {
            BtnKind::Danger
        } else {
            BtnKind::Primary
        };
        let label = crate::targets::confirm_label(&picker.verb, &picker.selected, &picker.nodes);
        let confirm = if can_confirm {
            btn(id("picker", "ok"), &label, kind)
                .on_click(cx.listener(|this, _, _, cx| {
                    if let Some(p) = this.picker.take() {
                        let targets = crate::targets::normalize_targets(&p.selected, &p.nodes);
                        (p.action)(this, cx, targets);
                    }
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off(&label).into_any_element()
        };
        let dialog = div()
            .w(px(440.))
            .max_w(gpui::relative(1.))
            .p(px(space::XL))
            .flex()
            .flex_col()
            .gap(px(space::MD))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(c(BORDER))
            .bg(c(SURFACE))
            .shadow(float_shadow())
            .child(strong(picker.title.clone()).text_size(px(font::LG)))
            .child(text_dim(picker.message.clone()).text_size(px(font::BASE)))
            .child(rows)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .text_size(px(font::SM))
                    .text_color(c(status_tone.color()))
                    .child(status),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(px(space::SM))
                    .child(
                        btn(id("picker", "cancel"), "Cancel", BtnKind::Plain).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.picker = None;
                                cx.notify();
                            }),
                        ),
                    )
                    .child(confirm),
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
        deferred(scrim).with_priority(50).into_any_element()
    }

    fn toast_card(&self, toast: &Toast, cx: &mut Context<Self>) -> impl IntoElement {
        let color = toast.tone.color();
        let toast_id = toast.id;
        div()
            .id(id("toast", toast_id))
            .flex()
            .items_start()
            .gap(px(space::SM))
            .w(px(360.))
            .px(px(space::MD))
            .py(px(10.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(tint(color, 0.5))
            .bg(c(SURFACE))
            .shadow(float_shadow())
            .occlude()
            .text_size(px(font::BASE))
            .cursor_pointer()
            .on_hover(cx.listener(move |this, hovered: &bool, _, _| {
                if *hovered {
                    this.hovered_toast = Some(toast_id);
                } else if this.hovered_toast == Some(toast_id) {
                    this.hovered_toast = None;
                }
            }))
            .on_click(cx.listener(move |this, _, _, cx| this.dismiss_toast(toast_id, cx)))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .mt(px(5.))
                    .child(crate::ui::widgets::dot(toast.tone)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .child(toast.text.clone()),
            )
            .child(text_dim("\u{00d7}").text_size(px(font::MD)))
    }
}

impl Render for Console {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.window_active = window.is_window_active();
        let panel_width = f32::from(window.viewport_size().width)
            - layout::WINDOW_INSET * 2.0
            - if self.sidebar_collapsed {
                0.0
            } else {
                layout::SIDEBAR_W + layout::WINDOW_INSET
            };
        let padding = layout::page_padding(panel_width);
        // Measured before the views render so they can adapt in the same frame.
        self.content_width = (panel_width - padding * 2.0).min(layout::CONTENT_MAX_W);
        let content = match self.view.clone() {
            View::Overview => self.render_overview(cx),
            View::Nodes => self.render_nodes(cx),
            View::Sites => self.render_sites(cx),
            View::SiteDetail { .. } => self.render_detail(cx),
            View::SiteNew => self.render_create(cx),
            View::Topology => self.render_topology(cx),
            View::Databases => self.render_databases(cx),
            View::Traffic => self.render_traffic(cx),
            View::Analytics => self.render_analytics(cx),
            View::Bots => self.render_bots(cx),
            View::Explore => self.render_explore(cx),
            View::Export => self.render_export(cx),
            View::Firewall => self.render_firewall(cx),
            View::Maintenance => self.render_maintenance(cx),
            View::Settings => self.render_settings(cx),
        };
        let scroll_key = format!("scroll-{:?}", self.view);
        let mut scroller = div()
            .id(gpui::SharedString::from(scroll_key))
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll();
        if let Some(handle) = &self.preview_scroll {
            handle.scroll_to_bottom();
            scroller = scroller.track_scroll(handle);
        }
        // The column is centred with equal margins and stops growing at CONTENT_MAX_W.
        let column = div()
            .flex()
            .flex_col()
            .w_full()
            .min_w_0()
            .max_w(px(layout::CONTENT_MAX_W))
            .gap(px(space::LG))
            .child(content);
        let main = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .h_full()
            .rounded(px(PANEL_RADIUS))
            .border_1()
            .border_color(c(DIVIDER))
            .bg(c(BG))
            .child(self.topbar(cx))
            .child(
                scroller.child(
                    div()
                        .flex()
                        .justify_center()
                        .w_full()
                        .px(px(padding))
                        .pt(px(space::XL))
                        .pb(px(space::XXL))
                        .child(column),
                ),
            );
        div()
            .relative()
            .flex()
            .size_full()
            .gap(px(layout::WINDOW_INSET))
            .p(px(layout::WINDOW_INSET))
            .bg(c(WINDOW))
            .text_color(c(TEXT))
            .text_size(px(font::BASE))
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &ToggleSidebar, _, cx| this.toggle_sidebar(cx)))
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, _, cx| {
                if event.keystroke.key == "escape" && this.picker.take().is_some() {
                    cx.notify();
                }
            }))
            .when(!self.sidebar_collapsed, |d| d.child(self.sidebar(cx)))
            .child(main)
            .children(self.overlays(cx))
    }
}

fn zoom_on_double_click(
    _: &mut Console,
    event: &ClickEvent,
    window: &mut Window,
    _: &mut Context<Console>,
) {
    if event.click_count() >= 2 {
        window.titlebar_double_click();
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
            .gap(px(space::MD))
            .px(px(space::LG))
            .py(px(space::MD))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(tint(RED, 0.5))
            .bg(tint(RED, 0.08))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap(px(space::XXS))
                    .child(strong("Could not load this view").text_color(c(RED)))
                    .child(text_dim(message.to_string()).text_size(px(font::SM))),
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
                .gap(px(space::MD))
                .py(px(space::XXL))
                .child(strong("No nodes yet").text_size(px(font::LG)))
                .child(text_dim("Add a node to start managing sites."))
                .child(
                    btn(id("empty", "add"), "Add a node", BtnKind::Primary)
                        .on_click(cx.listener(|this, _, _, cx| this.navigate(View::Nodes, cx))),
                ),
        )
        .into_any_element()
    }
}
