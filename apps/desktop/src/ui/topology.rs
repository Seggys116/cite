// topology: how hosts reach sites through the nodes, with the load on every path.

use std::collections::{BTreeMap, HashSet};

use cite_client::{AnalyticsQuery, ClientError, Facets};
use cite_edge::model::{Site, SiteKind};
use gpui::{
    AnyElement, Context, Div, ElementId, FontWeight, Hsla, PathBuilder, Pixels, Point, Stateful,
    Window, canvas, div, point, prelude::*, px,
};

use crate::api::{NodeHandle, join_all};
use crate::app::{Console, Load, View};
use crate::diagnose::last_deploy_failed;
use crate::scope::{Scope, apply_if_current};
use crate::theme::{
    ACCENT, BORDER, DIM, FAINT, MONO, ROW_RADIUS, SURFACE_HI, Tone, c, font, space, tint,
};
use crate::topology::{
    CubicPath, EntryBox, LOAD_WINDOW_SECS, Layout, LinkGeom, LinkStage, NodeBox, SiteBox, SiteOut,
    SiteState as TopoState, TopoNode, TopoSite, Topology, VIEW_WIDTH, build_topology, fmt_rps,
    layout_topology, links_through, load_from_facets, site_kind_label,
};
use crate::ui::chart::{clip_tip, wide};
use crate::ui::widgets::{
    BtnKind, btn, card, dot, empty_state, id, notice, page_header, pill, raise_shadow, skeleton,
    text_dim,
};

// The load is the facet counts of this window; its length in seconds is LOAD_WINDOW_SECS.
const LOAD_WINDOW: &str = "15m";
// Padding and border of the card around the graph, both sides.
const CARD_PAD: f32 = 34.0;
// A link that does not lead through the picked node, and one with no traffic, fade by this much.
const DIM_ALPHA: f32 = 0.18;
const STANDBY_ALPHA: f32 = 0.75;
// Boxes off the picked route.
const DIM_OPACITY: f32 = 0.4;
const ARROW_LEN: f32 = 9.0;
const ARROW_HALF: f32 = 5.5;
const DASH: f32 = 6.0;
const DASH_GAP: f32 = 5.0;
const PICKED_FILL: u32 = 0x2c2d34;

pub struct Data {
    pub nodes: Vec<TopoNode>,
}

pub struct State {
    pub data: Load<Data>,
    // The node whose routes stay bright; everything else dims.
    pub selected: Option<String>,
    // The scope of the request on the wire, so a refresh never starts while one is still running.
    in_flight: Option<Scope>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            data: Load::Idle,
            selected: None,
            in_flight: None,
        }
    }
}

impl State {
    fn running(&self, scope: Scope) -> bool {
        self.in_flight == Some(scope)
    }
}

// What a site is as the graph knows it. The failure flag follows the Sites page: the newest entry of
// the history is a failure.
pub fn topo_site(site: &Site) -> TopoSite {
    TopoSite {
        id: site.id.clone(),
        name: site.name.clone(),
        kind_is_api: site.kind == SiteKind::Api,
        runtime: site.source.as_ref().and_then(|s| s.runtime.clone()),
        hosts: site.hosts.clone(),
        path_prefixes: site.path_prefixes.clone(),
        path_regexes: site.path_regexes.clone(),
        maintenance: site.maintenance.enabled,
        failed: last_deploy_failed(&site.history),
        active: Some(site.active.as_str().to_string()),
    }
}

// Requests per second of every site, from the site facet counts of the load window.
pub fn load_of(facets: &Facets) -> BTreeMap<String, f64> {
    let counts: Vec<(String, u64)> = facets
        .site
        .iter()
        .map(|v| (v.key.clone(), v.count))
        .collect();
    load_from_facets(&counts, LOAD_WINDOW_SECS)
}

// One facets call covers every site on the node; None when the node would not give figures.
pub async fn site_load(h: &NodeHandle) -> Option<BTreeMap<String, f64>> {
    let facets = h
        .an_facets(&AnalyticsQuery::new().window(LOAD_WINDOW))
        .await
        .ok()?;
    Some(load_of(&facets))
}

fn offline_node(name: String) -> TopoNode {
    TopoNode {
        name,
        online: false,
        sites: None,
        load: BTreeMap::new(),
    }
}

// A node that cannot list its sites is kept as offline, so it still shows on the graph.
async fn load_node(h: NodeHandle) -> TopoNode {
    let name = h.name().to_string();
    let (sites, load) = tokio::join!(h.list_sites(), site_load(&h));
    TopoNode {
        name,
        online: sites.is_ok(),
        sites: sites.ok().map(|list| list.iter().map(topo_site).collect()),
        load: load.unwrap_or_default(),
    }
}

// The node a click on a site or host opens: the first that holds the site.
fn home_of(graph: &Topology, site_id: &str) -> Option<String> {
    graph
        .sites
        .iter()
        .find(|s| s.id == site_id)
        .and_then(|s| s.nodes.first().cloned())
}

// Picking the picked node again clears the pick.
fn toggle_pick(current: Option<&str>, name: &str) -> Option<String> {
    if current == Some(name) {
        None
    } else {
        Some(name.to_string())
    }
}

// The hosts and sites that a picked node routes, so the rest can dim. None when nothing is picked or the
// pick is not on the graph.
struct Route {
    picked: String,
    entries: HashSet<String>,
    sites: HashSet<String>,
}

fn route_through(graph: &Topology, picked: Option<&str>) -> Option<Route> {
    let name = picked.filter(|n| graph.nodes.iter().any(|x| x.name == *n))?;
    let through = links_through(graph, name);
    Some(Route {
        picked: name.to_string(),
        entries: through.iter().map(|l| l.from.clone()).collect(),
        sites: through.iter().map(|l| l.to.clone()).collect(),
    })
}

fn site_pill(state: TopoState) -> (&'static str, Tone) {
    match state {
        TopoState::Serving => ("Serving", Tone::Ok),
        TopoState::Failed => ("Deploy failed", Tone::Bad),
        TopoState::Maintenance => ("Maintenance", Tone::Warn),
    }
}

pub fn unreachable_notice(names: &[&str]) -> String {
    let who = if names.len() == 1 {
        "It is"
    } else {
        "They are"
    };
    format!(
        "Could not read {}. {who} shown as offline.",
        names.join(", ")
    )
}

// Spreads the three columns over a wider view: the entries stay left, the nodes centre and the sites
// move to the right edge, and every link follows the boxes it joins. A narrower width changes nothing.
pub fn fit_width(layout: &Layout, width: f64) -> Layout {
    let extra = (width - layout.width).max(0.0);
    let (mid, far) = (extra / 2.0, extra);
    let mut out = layout.clone();
    out.width = layout.width + extra;
    for node in &mut out.nodes {
        node.x += mid;
    }
    for site in &mut out.sites {
        site.x += far;
    }
    for link in &mut out.links {
        let (from, to) = match link.stage {
            LinkStage::In => (0.0, mid),
            LinkStage::Out => (mid, far),
        };
        link.path.x1 += from;
        link.path.c1x += from;
        link.path.c2x += to;
        link.path.x2 += to;
    }
    out
}

// How one link is drawn: the busiest in the accent, the rest quiet; no traffic is dashed and faint.
#[derive(Clone, Copy, Debug, PartialEq)]
struct LinkStyle {
    color: u32,
    alpha: f32,
    width: f32,
    dashed: bool,
}

fn link_style(link: &LinkGeom, dimmed: bool) -> LinkStyle {
    let alpha = if dimmed {
        DIM_ALPHA
    } else if link.standby {
        STANDBY_ALPHA
    } else {
        1.0
    };
    LinkStyle {
        color: if link.busiest { ACCENT } else { FAINT },
        alpha,
        width: link.width as f32,
        dashed: link.standby,
    }
}

struct LinkPaint {
    path: CubicPath,
    style: LinkStyle,
    busiest: bool,
}

// Links are drawn under the boxes, the busiest last so it is never hidden by a quieter one.
fn link_paints(layout: &Layout, route: Option<&Route>) -> Vec<LinkPaint> {
    let mut paints: Vec<LinkPaint> = layout
        .links
        .iter()
        .map(|l| LinkPaint {
            path: l.path,
            style: link_style(l, route.is_some_and(|r| r.picked != l.via)),
            busiest: l.busiest,
        })
        .collect();
    paints.sort_by_key(|p| p.busiest);
    paints
}

// The line stops where the arrowhead starts, so a thick line never pokes out past the tip.
fn paint_link(origin: Point<Pixels>, link: &LinkPaint, window: &mut Window) {
    let at = |x: f64, y: f64| point(origin.x + px(x as f32), origin.y + px(y as f32));
    let p = link.path;
    let end = p.x2 - f64::from(ARROW_LEN);
    let color = Hsla::from(tint(link.style.color, link.style.alpha));
    let base = PathBuilder::stroke(px(link.style.width));
    let mut stroke = if link.style.dashed {
        base.dash_array(&[px(DASH), px(DASH_GAP)])
    } else {
        base
    };
    stroke.move_to(at(p.x1, p.y1));
    stroke.cubic_bezier_to(at(end, p.y2), at(p.c1x, p.c1y), at(p.c2x, p.c2y));
    if let Ok(path) = stroke.build() {
        window.paint_path(path, color);
    }
    let half = f64::from(ARROW_HALF);
    let mut arrow = PathBuilder::fill();
    arrow.move_to(at(p.x2, p.y2));
    arrow.line_to(at(end, p.y2 - half));
    arrow.line_to(at(end, p.y2 + half));
    arrow.close();
    if let Ok(path) = arrow.build() {
        window.paint_path(path, color);
    }
}

// A box of the graph: placed by the layout, with the shared surface and edge.
fn boxed(key: ElementId, x: f64, y: f64, w: f64, h: f64) -> Stateful<Div> {
    div()
        .id(key)
        .absolute()
        .left(px(x as f32))
        .top(px(y as f32))
        .w(px(w as f32))
        .h(px(h as f32))
        .flex()
        .flex_col()
        .justify_center()
        .gap(px(space::XXS))
        .px(px(space::MD))
        .py(px(6.))
        .rounded(px(ROW_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(SURFACE_HI))
        .overflow_hidden()
}

fn entry_box(
    b: &EntryBox,
    home: Option<String>,
    dimmed: bool,
    cx: &mut Context<Console>,
) -> AnyElement {
    let mut el = boxed(id("topo-entry", &b.id), b.x, b.y, b.w, b.h)
        .when(dimmed, |d| d.opacity(DIM_OPACITY))
        .child(clip_tip(id("topo-host", &b.id), b.host.clone()).font_weight(FontWeight::SEMIBOLD))
        .child(
            clip_tip(id("topo-path", &b.id), b.path.clone())
                .font_family(MONO)
                .text_size(px(font::XS))
                .text_color(c(DIM)),
        );
    if let Some(node) = home {
        el = open_site(el, node, b.site_id.clone(), cx);
    }
    el.into_any_element()
}

// Clicking a box opens its site on the node that holds it.
fn open_site(
    el: Stateful<Div>,
    node: String,
    site: String,
    cx: &mut Context<Console>,
) -> Stateful<Div> {
    el.cursor_pointer()
        .hover(|s| s.border_color(tint(0xffffff, 0.3)))
        .on_click(cx.listener(move |this, _, _, cx| {
            this.navigate(
                View::SiteDetail {
                    node: node.clone(),
                    id: site.clone(),
                },
                cx,
            );
        }))
}

fn node_box(
    b: &NodeBox,
    online: bool,
    rps: f64,
    picked: bool,
    dimmed: bool,
    cx: &mut Context<Console>,
) -> AnyElement {
    let name = b.name.clone();
    let mut el = boxed(id("topo-node", &b.id), b.x, b.y, b.w, b.h)
        .shadow(raise_shadow())
        .cursor_pointer()
        .when(dimmed, |d| d.opacity(DIM_OPACITY))
        .on_click(cx.listener(move |this, _, _, cx| {
            this.topology.selected = toggle_pick(this.topology.selected.as_deref(), &name);
            cx.notify();
        }))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(6.))
                .child(
                    clip_tip(id("topo-node-name", &b.id), b.name.clone())
                        .flex_1()
                        .font_weight(FontWeight::SEMIBOLD),
                )
                .child(dot(if online { Tone::Ok } else { Tone::Bad })),
        )
        .child(if online {
            div()
                .font_family(MONO)
                .text_size(px(font::SM))
                .child(fmt_rps(rps))
        } else {
            text_dim("Offline").text_size(px(font::SM))
        });
    if !online {
        el = el.border_dashed().border_color(c(FAINT));
    }
    if picked {
        el = el.bg(c(PICKED_FILL)).border_color(tint(0xffffff, 0.55));
    }
    el.into_any_element()
}

fn site_box(
    b: &SiteBox,
    site: &SiteOut,
    home: Option<String>,
    dimmed: bool,
    cx: &mut Context<Console>,
) -> AnyElement {
    let (label, tone) = site_pill(site.state);
    let mut el = boxed(id("topo-site", &b.id), b.x, b.y, b.w, b.h)
        .when(dimmed, |d| d.opacity(DIM_OPACITY))
        .child(
            clip_tip(id("topo-site-name", &b.id), site.name.clone())
                .font_weight(FontWeight::SEMIBOLD),
        )
        .child(
            clip_tip(id("topo-site-kind", &b.id), site_kind_label(site))
                .text_size(px(font::XS))
                .text_color(c(DIM)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(6.))
                .child(
                    div()
                        .font_family(MONO)
                        .text_size(px(font::SM))
                        .child(fmt_rps(site.rps)),
                )
                .child(pill(label, tone)),
        );
    if let Some(node) = home {
        el = open_site(el, node, b.id.clone(), cx);
    }
    el.into_any_element()
}

// The graph: links on a canvas under absolutely placed boxes, all in the layout's own coordinates.
fn graph_view(
    graph: &Topology,
    layout: &Layout,
    picked: Option<&str>,
    cx: &mut Context<Console>,
) -> AnyElement {
    let route = route_through(graph, picked);
    let paints = link_paints(layout, route.as_ref());
    let entry_dim = |key: &str| route.as_ref().is_some_and(|r| !r.entries.contains(key));
    let site_dim = |key: &str| route.as_ref().is_some_and(|r| !r.sites.contains(key));
    let mut root = div()
        .relative()
        .flex_none()
        .w(px(layout.width as f32))
        .h(px(layout.height as f32))
        .child(
            canvas(
                |_, _, _| (),
                move |bounds, _, window, _| {
                    for link in &paints {
                        paint_link(bounds.origin, link, window);
                    }
                },
            )
            .absolute()
            .top_0()
            .left_0()
            .size_full(),
        );
    for b in &layout.entries {
        let home = home_of(graph, &b.site_id);
        root = root.child(entry_box(b, home, entry_dim(&b.id), cx));
    }
    for b in &layout.nodes {
        let info = graph.nodes.iter().find(|n| n.name == b.name);
        let picked_here = route.as_ref().is_some_and(|r| r.picked == b.name);
        let dimmed = route.as_ref().is_some_and(|r| r.picked != b.name);
        root = root.child(node_box(
            b,
            info.is_some_and(|n| n.online),
            info.map_or(0.0, |n| n.rps),
            picked_here,
            dimmed,
            cx,
        ));
    }
    for b in &layout.sites {
        let Some(site) = graph.sites.iter().find(|s| s.id == b.id) else {
            continue;
        };
        root = root.child(site_box(
            b,
            site,
            home_of(graph, &b.id),
            site_dim(&b.id),
            cx,
        ));
    }
    root.into_any_element()
}

fn legend() -> Div {
    let item = |swatch: Div, text: &str| {
        div()
            .flex()
            .items_center()
            .gap(px(space::SM))
            .child(swatch)
            .child(text_dim(text.to_string()).text_size(px(font::SM)))
    };
    let bar = |h: f32| div().w(px(22.)).h(px(h)).rounded_full().bg(c(FAINT));
    let dashes = div()
        .flex()
        .gap(px(4.))
        .children((0..3).map(|_| div().w(px(6.)).h(px(3.)).bg(c(FAINT))));
    div()
        .flex()
        .flex_wrap()
        .gap_x(px(space::XL))
        .gap_y(px(space::XS))
        .child(item(
            div().w(px(22.)).h(px(4.)).rounded_full().bg(c(ACCENT)),
            "Busiest path",
        ))
        .child(item(
            div()
                .flex()
                .flex_col()
                .gap(px(2.))
                .child(bar(2.))
                .child(bar(5.)),
            "Width follows requests per second",
        ))
        .child(item(dashes, "Dashed: failover or no traffic now"))
}

fn chart_card(
    graph: &Topology,
    picked: Option<&str>,
    content_width: f32,
    cx: &mut Context<Console>,
) -> AnyElement {
    let avail = (content_width - CARD_PAD).max(VIEW_WIDTH as f32);
    let layout = fit_width(&layout_topology(graph), f64::from(avail));
    let body = div()
        .flex()
        .flex_col()
        .gap(px(space::MD))
        .child(wide(
            id("topology", "scroll"),
            VIEW_WIDTH as f32,
            graph_view(graph, &layout, picked, cx),
        ))
        .child(legend());
    card(None, None, body).into_any_element()
}

fn topology_body(
    nodes: &[TopoNode],
    picked: Option<&str>,
    content_width: f32,
    cx: &mut Context<Console>,
) -> AnyElement {
    let graph = build_topology(nodes);
    let unreachable: Vec<&str> = nodes
        .iter()
        .filter(|n| n.sites.is_none())
        .map(|n| n.name.as_str())
        .collect();
    let mut col = div().flex().flex_col().gap(px(space::LG));
    if !unreachable.is_empty() {
        col = col.child(notice(&unreachable_notice(&unreachable), Tone::Warn));
    }
    if graph.sites.is_empty() {
        let all_down = unreachable.len() == nodes.len();
        let text = if all_down {
            "No node answered, so there is nothing to draw yet."
        } else {
            "Create a site to route a host through a node."
        };
        let empty = div()
            .flex()
            .flex_col()
            .items_center()
            .gap(px(space::MD))
            .child(empty_state("No sites to show", text))
            .when(!all_down, |d| {
                d.child(
                    btn(id("topology", "create"), "Create site", BtnKind::Primary)
                        .on_click(cx.listener(|this, _, _, cx| this.navigate(View::SiteNew, cx))),
                )
            });
        return col.child(card(None, None, empty)).into_any_element();
    }
    col.child(chart_card(&graph, picked, content_width, cx))
        .into_any_element()
}

impl Console {
    // A fresh load shows the skeleton until every node has answered or failed.
    pub fn load_topology(&mut self, cx: &mut Context<Self>) {
        self.topology.data = Load::Loading;
        self.run_topology(cx);
    }

    // The timer's refresh keeps the picture on screen and never starts while a request is running.
    pub fn refresh_topology(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.topology.data, Load::Ready(_)) || self.topology.running(self.scope) {
            return;
        }
        self.run_topology(cx);
    }

    // Every configured node is asked at once; one without a client is drawn as offline.
    fn run_topology(&mut self, cx: &mut Context<Self>) {
        let issued = self.scope;
        self.topology.in_flight = Some(issued);
        let jobs: Vec<(String, Option<NodeHandle>)> = self
            .config
            .nodes
            .iter()
            .map(|n| (n.name.clone(), self.handle_named(&n.name)))
            .collect();
        let fut = async move {
            let all = join_all(
                jobs.into_iter()
                    .map(|(name, handle)| async move {
                        match handle {
                            Some(h) => load_node(h).await,
                            None => offline_node(name),
                        }
                    })
                    .collect(),
            )
            .await;
            all.into_iter()
                .collect::<Option<Vec<TopoNode>>>()
                .ok_or_else(|| {
                    ClientError::Config(
                        "the network task stopped before every node answered".into(),
                    )
                })
        };
        self.fetch(cx, fut, move |this, res, cx| {
            if this.topology.in_flight == Some(issued) {
                this.topology.in_flight = None;
            }
            apply_if_current(this.scope, issued, res, |res| this.apply_topology(res, cx));
        });
    }

    fn apply_topology(&mut self, res: Result<Vec<TopoNode>, ClientError>, cx: &mut Context<Self>) {
        match res {
            Ok(nodes) => {
                if self
                    .topology
                    .selected
                    .as_ref()
                    .is_some_and(|pick| !nodes.iter().any(|n| n.name == *pick))
                {
                    self.topology.selected = None;
                }
                // The window repaints whole on a notify, so a refresh that changed nothing stays quiet.
                let same = matches!(&self.topology.data, Load::Ready(d) if d.nodes == nodes);
                if !same {
                    self.topology.data = Load::Ready(Data { nodes });
                    cx.notify();
                }
            }
            Err(e) => {
                // A failed refresh leaves the picture it has.
                if !matches!(self.topology.data, Load::Ready(_)) {
                    self.topology.data = Load::Failed(e.to_string());
                    cx.notify();
                }
            }
        }
    }

    pub fn render_topology(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let sites = btn(id("topology", "sites"), "Sites", BtnKind::Plain)
            .on_click(cx.listener(|this, _, _, cx| this.navigate(View::Sites, cx)));
        let header = page_header(
            "Topology",
            "Hosts, nodes and sites, with live load",
            vec![sites.into_any_element()],
        );
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
        if self.config.nodes.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        match &self.topology.data {
            Load::Idle | Load::Loading => col = col.child(skeleton(320.)),
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                col = col.child(topology_body(
                    &data.nodes,
                    self.topology.selected.as_deref(),
                    self.content_width,
                    cx,
                ));
            }
        }
        col.into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_client::FacetValue;
    use cite_edge::model::{DeployAction, Deployment, Slot, Source};

    fn site(id: &str) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: vec![format!("{id}.example.com")],
            path_prefixes: Vec::new(),
            path_regexes: Vec::new(),
            kind: SiteKind::Site,
            blue: Default::default(),
            green: Default::default(),
            active: Slot::Blue,
            maintenance: Default::default(),
            health: Default::default(),
            source: None,
            history: Vec::new(),
            access: Default::default(),
            volumes: Vec::new(),
            outbound: true,
            outbound_rules: Default::default(),
            data: Default::default(),
        }
    }

    fn topo(id: &str) -> TopoSite {
        topo_site(&site(id))
    }

    fn node(
        name: &str,
        online: bool,
        sites: Option<Vec<TopoSite>>,
        load: &[(&str, f64)],
    ) -> TopoNode {
        TopoNode {
            name: name.into(),
            online,
            sites,
            load: load.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    // fra serves shop and api, iad serves shop only; the api carries the most traffic.
    fn graph() -> Topology {
        build_topology(&[
            node(
                "fra",
                true,
                Some(vec![topo("shop"), topo("api")]),
                &[("shop", 10.0), ("api", 40.0)],
            ),
            node("iad", true, Some(vec![topo("shop")]), &[("shop", 0.0)]),
        ])
    }

    #[test]
    fn a_site_becomes_a_graph_site_with_its_runtime_paths_and_state() {
        let mut s = site("api");
        s.kind = SiteKind::Api;
        s.path_regexes = vec!["^/v1/(quote|price)$".into()];
        s.source = Some(Source {
            repo: "acme/api".into(),
            runtime: Some("rust".into()),
            ..Default::default()
        });
        let t = topo_site(&s);
        assert!(t.kind_is_api);
        assert_eq!(t.runtime.as_deref(), Some("rust"));
        assert_eq!(t.path_regexes, s.path_regexes);
        assert_eq!(t.active.as_deref(), Some("blue"));
        assert!(!t.maintenance && !t.failed);
        s.maintenance.enabled = true;
        s.history = vec![Deployment {
            id: "d".into(),
            at: "2026-11-05T09:00:00Z".into(),
            slot: Slot::Green,
            action: DeployAction::Failed,
            note: String::new(),
        }];
        let t = topo_site(&s);
        assert!(t.maintenance && t.failed);
    }

    #[test]
    fn facet_counts_over_the_window_are_requests_per_second() {
        let facets = Facets {
            site: vec![
                FacetValue {
                    key: "shop".into(),
                    count: 900,
                },
                FacetValue {
                    key: "api".into(),
                    count: 90,
                },
            ],
            ..Facets::default()
        };
        let load = load_of(&facets);
        assert_eq!(load.get("shop"), Some(&1.0));
        assert_eq!(load.get("api"), Some(&0.1));
        assert!(load_of(&Facets::default()).is_empty());
        assert_eq!(LOAD_WINDOW, "15m");
        assert_eq!(LOAD_WINDOW_SECS, 15 * 60);
    }

    #[test]
    fn picking_a_node_twice_clears_the_pick() {
        assert_eq!(toggle_pick(None, "fra").as_deref(), Some("fra"));
        assert_eq!(toggle_pick(Some("fra"), "iad").as_deref(), Some("iad"));
        assert_eq!(toggle_pick(Some("fra"), "fra"), None);
    }

    #[test]
    fn a_picked_node_keeps_only_its_own_hosts_and_sites_bright() {
        let g = graph();
        assert!(route_through(&g, None).is_none());
        assert!(route_through(&g, Some("ams")).is_none());
        let iad = route_through(&g, Some("iad")).expect("route");
        assert_eq!(iad.picked, "iad");
        assert_eq!(iad.sites, HashSet::from(["shop".to_string()]));
        assert_eq!(iad.entries.len(), 1);
        let fra = route_through(&g, Some("fra")).expect("route");
        assert_eq!(fra.sites.len(), 2);
        assert_eq!(fra.entries.len(), 2);
    }

    #[test]
    fn links_off_the_picked_route_fade_and_the_rest_keep_their_look() {
        let g = graph();
        let lay = layout_topology(&g);
        let plain = link_paints(&lay, None);
        assert_eq!(plain.len(), lay.links.len());
        assert!(plain.iter().all(|p| p.style.alpha >= STANDBY_ALPHA));
        let route = route_through(&g, Some("iad"));
        let picked = link_paints(&lay, route.as_ref());
        assert!(picked.iter().any(|p| p.style.alpha == DIM_ALPHA));
        let bright = lay.links.iter().filter(|l| l.via == "iad").count();
        assert_eq!(
            picked.iter().filter(|p| p.style.alpha != DIM_ALPHA).count(),
            bright
        );
    }

    #[test]
    fn only_the_busiest_link_is_accent_and_idle_links_are_dashed() {
        let g = graph();
        let lay = layout_topology(&g);
        for l in &lay.links {
            let s = link_style(l, false);
            assert_eq!(s.color == ACCENT, l.busiest, "{}", l.id);
            assert_eq!(s.dashed, l.standby, "{}", l.id);
            assert_eq!(s.width, l.width as f32);
        }
        let idle = lay
            .links
            .iter()
            .find(|l| l.id == "out:iad>shop")
            .expect("link");
        assert!(idle.standby);
        let s = link_style(idle, false);
        assert_eq!((s.color, s.alpha), (FAINT, STANDBY_ALPHA));
        assert_eq!(link_style(idle, true).alpha, DIM_ALPHA);
        let busiest = lay.links.iter().find(|l| l.busiest).expect("busiest");
        assert_eq!(link_style(busiest, false).alpha, 1.0);
    }

    #[test]
    fn the_busiest_link_is_painted_last() {
        let lay = layout_topology(&graph());
        let paints = link_paints(&lay, None);
        let first_busiest = paints.iter().position(|p| p.busiest).expect("busiest");
        assert!(paints[first_busiest..].iter().all(|p| p.busiest));
    }

    #[test]
    fn a_wider_view_moves_the_nodes_to_the_middle_and_the_sites_to_the_edge() {
        let lay = layout_topology(&graph());
        let spread = fit_width(&lay, 1000.0);
        assert_eq!(spread.width, 1000.0);
        assert_eq!(spread.height, lay.height);
        assert!(
            spread
                .entries
                .iter()
                .zip(&lay.entries)
                .all(|(a, b)| a.x == b.x)
        );
        assert!(spread.nodes.iter().all(|n| n.x == 288.0 + 152.0));
        for s in &spread.sites {
            assert_eq!(s.x + s.w, 1000.0 - 8.0, "sites keep the right margin");
        }
        for l in &spread.links {
            match l.stage {
                LinkStage::In => {
                    let n = spread.nodes.iter().find(|n| n.name == l.via).expect("node");
                    assert_eq!(l.path.x2, n.x, "{}", l.id);
                }
                LinkStage::Out => {
                    let n = spread.nodes.iter().find(|n| n.name == l.via).expect("node");
                    let s = spread
                        .sites
                        .iter()
                        .find(|s| s.id == l.site_id)
                        .expect("site");
                    assert_eq!(l.path.x1, n.x + n.w, "{}", l.id);
                    assert_eq!(l.path.x2, s.x, "{}", l.id);
                }
            }
            assert!(l.path.c1x > l.path.x1 && l.path.c2x < l.path.x2, "{}", l.id);
        }
    }

    #[test]
    fn a_view_narrower_than_the_layout_is_left_alone() {
        let lay = layout_topology(&graph());
        assert_eq!(fit_width(&lay, 400.0), lay);
        assert_eq!(fit_width(&lay, VIEW_WIDTH), lay);
    }

    #[test]
    fn a_click_opens_the_first_node_that_holds_the_site() {
        let g = graph();
        assert_eq!(home_of(&g, "shop").as_deref(), Some("fra"));
        assert_eq!(home_of(&g, "api").as_deref(), Some("fra"));
        assert_eq!(home_of(&g, "ghost"), None);
    }

    #[test]
    fn site_states_read_as_pills() {
        assert_eq!(site_pill(TopoState::Serving), ("Serving", Tone::Ok));
        assert_eq!(site_pill(TopoState::Failed), ("Deploy failed", Tone::Bad));
        assert_eq!(
            site_pill(TopoState::Maintenance),
            ("Maintenance", Tone::Warn)
        );
    }

    #[test]
    fn the_notice_names_unreadable_nodes_and_says_they_are_offline() {
        assert_eq!(
            unreachable_notice(&["ams"]),
            "Could not read ams. It is shown as offline."
        );
        assert_eq!(
            unreachable_notice(&["ams", "sin"]),
            "Could not read ams, sin. They are shown as offline."
        );
    }

    #[test]
    fn an_unreadable_node_stays_on_the_graph_as_offline() {
        let g = build_topology(&[
            node("fra", true, Some(vec![topo("shop")]), &[("shop", 1.0)]),
            offline_node("ams".into()),
        ]);
        let ams = g.nodes.iter().find(|n| n.name == "ams").expect("ams");
        assert!(!ams.online && !ams.readable);
        assert_eq!(layout_topology(&g).nodes.len(), 2);
    }

    #[test]
    fn a_refresh_is_held_while_a_request_of_the_same_scope_is_running() {
        let mut state = State::default();
        let mut scope = Scope::default();
        assert!(!state.running(scope));
        state.in_flight = Some(scope);
        assert!(state.running(scope));
        // A view or node change moves the scope on, and the old request no longer holds the refresh.
        scope.advance();
        assert!(!state.running(scope));
    }
}
