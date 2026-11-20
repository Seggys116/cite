use std::collections::{BTreeMap, BTreeSet};

use cite_client::{AnalyticsQuery, ClientError};
use cite_edge::model::{DeployAction, Site, SiteKind};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, join_all};
use crate::app::{Console, Load, View, new_input};
use crate::diagnose::{newest_failure, split_note};
use crate::model::parse_rfc3339_ms;
use crate::siteops::is_busy_phase;
use crate::theme::{
    BLUE, BORDER, DIM, DIVIDER, MONO, PILL_RADIUS, Tone, c, chip_fill, chip_stroke, font, space,
    tint,
};
use crate::topology::{fmt_rps, path_label};
use crate::ui::chart::{Line, clip_tip, line_chart, wide};
use crate::ui::input::TextInput;
use crate::ui::topology::{site_load, topo_site};
use crate::ui::widgets::{
    BtnKind, Col, btn, card, dot, empty_state, id, notice, page_header, pill, seg_item, seg_row,
    skeleton, text_dim, tip,
};

// Sparklines are fetched for the rows on screen in batches of this size.
const SERIES_BATCH: usize = 24;
// More hosts than this are summed up on a last line, so a row stays short.
const MAX_HOST_LINES: usize = 4;
const LOAD_COL_W: f32 = 132.0;
const STATE_COL_W: f32 = 140.0;
const SPARK_W: f32 = 56.0;
const SPARK_H: f32 = 18.0;

pub struct Row {
    pub node: String,
    pub site: Site,
    pub health: Vec<(String, String)>,
    // Build phase from the site status, fetched only for source-built sites.
    pub phase: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteState {
    Building,
    Redeploying,
    Failed,
    Maintenance,
    Down,
    Serving,
}

impl SiteState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Building => "Building",
            Self::Redeploying => "Redeploying",
            Self::Failed => "Deploy failed",
            Self::Maintenance => "Maintenance",
            Self::Down => "Needs attention",
            Self::Serving => "Serving",
        }
    }

    pub fn tone(self) -> Tone {
        match self {
            Self::Building | Self::Redeploying => Tone::Info,
            Self::Failed | Self::Down => Tone::Bad,
            Self::Maintenance => Tone::Warn,
            Self::Serving => Tone::Ok,
        }
    }

    pub fn pill(self) -> gpui::Div {
        pill(self.label(), self.tone())
    }

    // Lower is worse, so a site shows the most serious thing any node reports.
    fn rank(self) -> u8 {
        match self {
            Self::Down => 0,
            Self::Failed => 1,
            Self::Building => 2,
            Self::Redeploying => 3,
            Self::Maintenance => 4,
            Self::Serving => 5,
        }
    }

    // The sites someone has to look at: targets failing or the last deploy failed.
    pub fn needs_attention(self) -> bool {
        matches!(self, Self::Down | Self::Failed)
    }
}

// A running build wins, then maintenance, the node's own failed phase, red health and finally a failed last deploy.
pub fn site_state(site: &Site, health: &[(String, String)], phase: Option<&str>) -> SiteState {
    let last_failed = last_deploy(site).is_some_and(|(a, _)| a == DeployAction::Failed);
    if phase.is_some_and(is_busy_phase) {
        let served_before = site
            .history
            .iter()
            .any(|d| d.action != DeployAction::Failed);
        return if served_before {
            SiteState::Redeploying
        } else {
            SiteState::Building
        };
    }
    if site.maintenance.enabled {
        SiteState::Maintenance
    } else if phase == Some("failed") {
        SiteState::Failed
    } else if phase == Some("unhealthy")
        || (!health.is_empty() && health.iter().all(|(_, s)| health_tone(s) == Tone::Bad))
    {
        SiteState::Down
    } else if last_failed {
        SiteState::Failed
    } else {
        SiteState::Serving
    }
}

pub struct Data {
    // One row per site and node; the list groups them by site id when it draws.
    pub rows: Vec<Row>,
    // Nodes that did not answer, by name.
    pub failed: Vec<String>,
    // Nodes that answered, in connection order.
    pub nodes: Vec<String>,
    // True until the health pass has answered, so a dot that has not arrived is not read as "no data".
    pub health_pending: bool,
    // Requests per second of every site, by node. A node that gave no figures is absent.
    pub loads: BTreeMap<String, BTreeMap<String, f64>>,
    pub load_pending: bool,
    // The last hour of requests per site id, summed over its nodes.
    pub series: BTreeMap<String, Vec<u64>>,
    pub series_asked: BTreeSet<String>,
}

// Which sites the list shows: everything, those on one node, or those that need attention.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Show {
    #[default]
    All,
    Node(String),
    Attention,
}

pub struct State {
    pub data: Load<Data>,
    pub filter: Entity<TextInput>,
    pub show: Show,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            filter: new_input(cx, "Filter sites by name or host", |i| i),
            show: Show::All,
        }
    }
}

pub fn health_tone(status: &str) -> Tone {
    let up = status.to_uppercase();
    if up.starts_with("UP") || up == "OK" {
        Tone::Ok
    } else if up.contains("DOWN") || up.contains("FAIL") {
        Tone::Bad
    } else if up.contains("MAINT") || up.contains("DRAIN") {
        Tone::Warn
    } else {
        Tone::Muted
    }
}

// One site on one node, as that node reports it: the dot colour and the sentence that explains it.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeStatus {
    pub node: String,
    pub state: SiteState,
    pub tone: Tone,
    pub reason: String,
}

fn failure_reason(site: &Site) -> String {
    match newest_failure(&site.history) {
        Some(d) => {
            let reason = split_note(&d.note).reason;
            if reason.is_empty() {
                format!("The last deployment to {} failed", d.slot.as_str())
            } else {
                format!(
                    "The last deployment to {} failed: {reason}",
                    d.slot.as_str()
                )
            }
        }
        None => "The build failed".to_string(),
    }
}

pub fn node_status(row: &Row, health_pending: bool) -> NodeStatus {
    let state = site_state(&row.site, &row.health, row.phase.as_deref());
    let some_down = row.health.iter().any(|(_, s)| health_tone(s) != Tone::Ok);
    let (tone, reason) = match state {
        SiteState::Down if row.phase.as_deref() == Some("unhealthy") => (
            Tone::Bad,
            "The node reports the site as unhealthy".to_string(),
        ),
        SiteState::Down => (
            Tone::Bad,
            "Every server in the active slot is down".to_string(),
        ),
        SiteState::Failed => (Tone::Warn, failure_reason(&row.site)),
        SiteState::Maintenance => (Tone::Warn, "Maintenance page is being served".to_string()),
        SiteState::Building => (Tone::Info, "The first build is running".to_string()),
        SiteState::Redeploying => (Tone::Info, "A new build is running".to_string()),
        SiteState::Serving if row.health.is_empty() && health_pending => {
            (Tone::Muted, "Checking health".to_string())
        }
        SiteState::Serving if row.health.is_empty() => (Tone::Muted, "No health data".to_string()),
        SiteState::Serving if some_down => (
            Tone::Warn,
            "Some servers in the active slot are down".to_string(),
        ),
        SiteState::Serving => (Tone::Ok, String::new()),
    };
    NodeStatus {
        node: row.node.clone(),
        state,
        tone,
        reason,
    }
}

// The sentence a node chip shows on hover.
pub fn chip_title(status: &NodeStatus) -> String {
    if status.reason.is_empty() {
        format!("{}: healthy", status.node)
    } else {
        format!("{}: {}", status.node, status.reason)
    }
}

// What the State column says about a site that may be on several nodes.
#[derive(Clone, Debug, PartialEq)]
pub struct LineStatus {
    pub state: SiteState,
    pub reason: String,
}

// The worst node decides; the first one wins a tie, so the node order stays the tie-break.
pub fn combine_status(statuses: &[NodeStatus]) -> LineStatus {
    let Some(worst) = statuses.iter().min_by_key(|s| s.state.rank()) else {
        return LineStatus {
            state: SiteState::Serving,
            reason: String::new(),
        };
    };
    let reason = if worst.reason.is_empty() || statuses.len() == 1 {
        worst.reason.clone()
    } else {
        format!("{}: {}", worst.node, worst.reason)
    };
    LineStatus {
        state: worst.state,
        reason,
    }
}

// A node that carries a site, and where its row sits in `Data::rows`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub node: String,
    pub row: usize,
}

// One site id, however many nodes hold it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteLine {
    pub id: String,
    pub name: String,
    pub api: bool,
    pub hosts: Vec<String>,
    // The path match of each distinct restriction; sites that take any path add nothing.
    pub paths: Vec<String>,
    pub members: Vec<Member>,
}

// One line per site id, by name, with its nodes in the order the rows came in.
pub fn group_rows(rows: &[Row]) -> Vec<SiteLine> {
    let mut lines: Vec<SiteLine> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let at = match lines.iter().position(|l| l.id == row.site.id) {
            Some(at) => at,
            None => {
                lines.push(SiteLine {
                    id: row.site.id.clone(),
                    name: row.site.name.clone(),
                    api: false,
                    hosts: Vec::new(),
                    paths: Vec::new(),
                    members: Vec::new(),
                });
                lines.len() - 1
            }
        };
        let line = &mut lines[at];
        line.api |= row.site.kind == SiteKind::Api;
        for host in &row.site.hosts {
            if !line.hosts.contains(host) {
                line.hosts.push(host.clone());
            }
        }
        if !row.site.path_prefixes.is_empty() || !row.site.path_regexes.is_empty() {
            let label = path_label(&topo_site(&row.site));
            if !line.paths.contains(&label) {
                line.paths.push(label);
            }
        }
        line.members.push(Member {
            node: row.node.clone(),
            row: i,
        });
    }
    lines.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
    lines
}

fn statuses_of(line: &SiteLine, rows: &[Row], health_pending: bool) -> Vec<NodeStatus> {
    line.members
        .iter()
        .filter_map(|m| rows.get(m.row))
        .map(|row| node_status(row, health_pending))
        .collect()
}

// A scope naming a node that is gone after a reload falls back to every node.
pub fn effective_show(show: &Show, nodes: &[String]) -> Show {
    match show {
        Show::Node(name) if !nodes.contains(name) => Show::All,
        other => other.clone(),
    }
}

// `attention` says whether a line needs attention; the caller owns what it knows about health.
pub fn scope_lines<'a>(
    lines: &'a [SiteLine],
    show: &Show,
    attention: &dyn Fn(&SiteLine) -> bool,
) -> Vec<&'a SiteLine> {
    lines
        .iter()
        .filter(|line| match show {
            Show::All => true,
            Show::Attention => attention(line),
            Show::Node(name) => line.members.iter().any(|m| m.node == *name),
        })
        .collect()
}

// Matches name, id or any host, case insensitively.
pub fn line_matches(line: &SiteLine, needle: &str) -> bool {
    let q = needle.trim().to_lowercase();
    q.is_empty()
        || line.name.to_lowercase().contains(&q)
        || line.id.to_lowercase().contains(&q)
        || line.hosts.iter().any(|h| h.to_lowercase().contains(&q))
}

// The node whose page a row opens: the scoped node when it holds the site, else the first node that does.
pub fn home_node<'a>(line: &'a SiteLine, show: &Show) -> Option<&'a str> {
    if let Show::Node(name) = show
        && let Some(m) = line.members.iter().find(|m| m.node == *name)
    {
        return Some(m.node.as_str());
    }
    line.members.first().map(|m| m.node.as_str())
}

// Requests per second over all the nodes that gave a figure; None when none did.
pub fn line_rps(line: &SiteLine, loads: &BTreeMap<String, BTreeMap<String, f64>>) -> Option<f64> {
    let mut total: Option<f64> = None;
    for member in &line.members {
        if let Some(per_site) = loads.get(&member.node) {
            *total.get_or_insert(0.0) += per_site.get(&line.id).copied().unwrap_or(0.0);
        }
    }
    total
}

// Adds request series from several nodes point by point, aligned on the newest end.
pub fn merge_points(list: &[Vec<u64>]) -> Vec<u64> {
    let len = list.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = vec![0u64; len];
    for series in list {
        let offset = len - series.len();
        for (i, value) in series.iter().enumerate() {
            out[offset + i] += value;
        }
    }
    out
}

// "4 across 2 nodes"
pub fn subtitle_for(sites: usize, nodes: usize) -> String {
    format!(
        "{sites} across {nodes} node{}",
        if nodes == 1 { "" } else { "s" }
    )
}

pub fn unreachable_note(nodes: &[String]) -> String {
    let who = if nodes.len() == 1 { "Its" } else { "Their" };
    format!(
        "Could not reach {}. {who} sites are not listed.",
        nodes.join(", ")
    )
}

fn empty_text(total: usize, show: &Show, needle: &str) -> (&'static str, &'static str) {
    if total == 0 {
        (
            "No sites yet",
            "Create a site to build a GitHub repository or route a host to servers you run.",
        )
    } else if *show == Show::Attention && needle.trim().is_empty() {
        ("Nothing needs attention", "Every site is serving.")
    } else {
        ("No sites match", "Try a different name or host.")
    }
}

// Rows come from the list route alone; health arrives afterwards from one stats call per node.
async fn node_rows(h: NodeHandle) -> (String, Result<Vec<Row>, String>) {
    let name = h.name().to_string();
    match h.list_sites().await {
        Ok(sites) => {
            let rows = sites
                .into_iter()
                .map(|site| Row {
                    node: name.clone(),
                    site,
                    health: Vec::new(),
                    phase: None,
                })
                .collect();
            (name, Ok(rows))
        }
        Err(e) => (name, Err(e.to_string())),
    }
}

// The stats list every backend as be_<site>_<slot>; only the active slot's servers are reported, as (server, status).
pub fn health_from_stats(stats: &serde_json::Value, site: &Site) -> Vec<(String, String)> {
    let want = format!("be_{}_{}", site.id, site.active.as_str());
    let text = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    stats
        .get("backends")
        .and_then(serde_json::Value::as_array)
        .and_then(|list| list.iter().find(|b| text(b, "name") == want))
        .and_then(|b| b.get("servers"))
        .and_then(serde_json::Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .map(|s| (text(s, "name"), text(s, "status")))
                .collect()
        })
        .unwrap_or_default()
}

impl Console {
    pub fn load_sites(&mut self, cx: &mut Context<Self>) {
        self.sites.data = Load::Loading;
        let handles = self.selected_handles();
        let total = handles.len();
        // Nodes that never connected are unreachable too, though no request is made to them.
        let unconnected: Vec<String> = self
            .connect_errors
            .keys()
            .filter(|name| self.selected.as_ref().is_none_or(|s| s == *name))
            .cloned()
            .collect();
        let fut = async move {
            let results = join_all(handles.into_iter().map(node_rows).collect()).await;
            let (mut rows, mut failed, mut nodes, mut first_err) =
                (Vec::new(), Vec::new(), Vec::new(), None);
            for (name, res) in results.into_iter().flatten() {
                match res {
                    Ok(r) => {
                        rows.extend(r);
                        nodes.push(name);
                    }
                    Err(e) => {
                        first_err.get_or_insert(e);
                        failed.push(name);
                    }
                }
            }
            if total > 0 && failed.len() == total {
                return Err(ClientError::Config(first_err.unwrap_or_default()));
            }
            failed.extend(unconnected);
            Ok(Data {
                rows,
                failed,
                nodes,
                health_pending: true,
                loads: BTreeMap::new(),
                load_pending: true,
                series: BTreeMap::new(),
                series_asked: BTreeSet::new(),
            })
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            let loaded = res.is_ok();
            this.sites.data = Load::from_result(res);
            cx.notify();
            if loaded {
                this.load_site_health(cx);
                this.load_site_phases(cx);
                this.load_site_load(cx);
            }
        });
    }

    // One status call per source-built site, once per load; sites without a build never need it.
    fn load_site_phases(&mut self, cx: &mut Context<Self>) {
        let Load::Ready(data) = &self.sites.data else {
            return;
        };
        let jobs: Vec<(NodeHandle, String)> = data
            .rows
            .iter()
            .filter(|r| r.site.source.is_some())
            .filter_map(|r| Some((self.handle_named(&r.node)?, r.site.id.clone())))
            .collect();
        if jobs.is_empty() {
            return;
        }
        let fut = async move {
            let all = join_all(
                jobs.into_iter()
                    .map(|(h, site)| async move {
                        let phase = h.site_status(&site).await.ok().map(|s| s.phase);
                        (h.name().to_string(), site, phase)
                    })
                    .collect(),
            )
            .await;
            Ok::<_, ClientError>(all.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            if let (Load::Ready(data), Ok(phases)) = (&mut this.sites.data, res) {
                for (node, site, phase) in phases {
                    if let Some(row) = data
                        .rows
                        .iter_mut()
                        .find(|r| r.node == node && r.site.id == site)
                    {
                        row.phase = phase;
                    }
                }
            }
            cx.notify();
        });
    }

    // One stats call per node fills in every health dot; the table is already on screen by then.
    fn load_site_health(&mut self, cx: &mut Context<Self>) {
        let handles = self.selected_handles();
        let fut = async move {
            let all = join_all(
                handles
                    .into_iter()
                    .map(|h| async move { (h.name().to_string(), h.haproxy_stats().await.ok()) })
                    .collect(),
            )
            .await;
            Ok::<_, ClientError>(all.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            if let (Load::Ready(data), Ok(stats)) = (&mut this.sites.data, res) {
                for row in &mut data.rows {
                    let found = stats.iter().find(|(n, _)| *n == row.node);
                    if let Some((_, Some(s))) = found {
                        row.health = health_from_stats(s, &row.site);
                    }
                }
                data.health_pending = false;
            }
            cx.notify();
        });
    }

    // One facets call per node covers the load of every site on it; the list is on screen before it answers.
    fn load_site_load(&mut self, cx: &mut Context<Self>) {
        let handles = self.selected_handles();
        let fut = async move {
            let all = join_all(
                handles
                    .into_iter()
                    .map(|h| async move { (h.name().to_string(), site_load(&h).await) })
                    .collect(),
            )
            .await;
            Ok::<_, ClientError>(all.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            if let (Load::Ready(data), Ok(loads)) = (&mut this.sites.data, res) {
                data.loads = loads
                    .into_iter()
                    .filter_map(|(node, load)| Some((node, load?)))
                    .collect();
                data.load_pending = false;
            }
            cx.notify();
        });
    }

    // Sparklines come per site and only for rows the list is showing, so a long list is not asked for everything at once.
    fn request_series(&mut self, wanted: Vec<(String, Vec<String>)>, cx: &mut Context<Self>) {
        if wanted.is_empty() {
            return;
        }
        if let Load::Ready(data) = &mut self.sites.data {
            data.series_asked
                .extend(wanted.iter().map(|(site, _)| site.clone()));
        }
        let jobs: Vec<(String, NodeHandle)> = wanted
            .into_iter()
            .flat_map(|(site, nodes)| {
                nodes
                    .into_iter()
                    .filter_map(|n| self.handle_named(&n))
                    .map(move |h| (site.clone(), h))
                    .collect::<Vec<_>>()
            })
            .collect();
        let fut = async move {
            let all = join_all(
                jobs.into_iter()
                    .map(|(site, h)| async move {
                        let mut q = AnalyticsQuery::new().window("1h");
                        q.sites = vec![site.clone()];
                        let points = h.an_series(&q, false).await.ok().map(|report| {
                            report
                                .series
                                .points
                                .iter()
                                .map(|p| p.requests)
                                .collect::<Vec<u64>>()
                        });
                        (site, points)
                    })
                    .collect(),
            )
            .await;
            let mut per_site: BTreeMap<String, Vec<Vec<u64>>> = BTreeMap::new();
            for (site, points) in all.into_iter().flatten() {
                let lists = per_site.entry(site).or_default();
                lists.extend(points);
            }
            Ok::<_, ClientError>(
                per_site
                    .into_iter()
                    .map(|(site, lists)| (site, merge_points(&lists)))
                    .collect::<Vec<_>>(),
            )
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            if let (Load::Ready(data), Ok(series)) = (&mut this.sites.data, res) {
                data.series.extend(series);
            }
            cx.notify();
        });
    }

    pub fn render_sites(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let ready = matches!(self.sites.data, Load::Ready(_));
        let subtitle = match &self.sites.data {
            Load::Ready(data) => subtitle_for(group_rows(&data.rows).len(), data.nodes.len()),
            Load::Failed(_) => "Could not load sites".to_string(),
            Load::Idle | Load::Loading => "Loading sites".to_string(),
        };
        let topology = btn(id("sites", "topology"), "Topology", BtnKind::Plain)
            .on_click(cx.listener(|this, _, _, cx| this.navigate(View::Topology, cx)));
        let create = btn(id("sites", "new"), "Create site", BtnKind::Primary)
            .on_click(cx.listener(|this, _, _, cx| this.navigate(View::SiteNew, cx)));
        let header = page_header(
            "Sites",
            &subtitle,
            vec![topology.into_any_element(), create.into_any_element()],
        );
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        if ready {
            let (body, wanted) = self.sites_ready(cx);
            self.request_series(wanted, cx);
            return col.children(body).into_any_element();
        }
        match &self.sites.data {
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            _ => col = col.child(skeleton(60.)).child(skeleton(220.)),
        }
        col.into_any_element()
    }

    // The notice, scope bar and table of a loaded list, and the sites whose sparkline still has to be asked for.
    fn sites_ready(&self, cx: &mut Context<Self>) -> (Vec<AnyElement>, Vec<(String, Vec<String>)>) {
        let Load::Ready(data) = &self.sites.data else {
            return (Vec::new(), Vec::new());
        };
        let needle = self.sites.filter.read(cx).text().to_string();
        let lines = group_rows(&data.rows);
        let show = effective_show(&self.sites.show, &data.nodes);
        let attention = |line: &SiteLine| line_status_of(line, data).state.needs_attention();
        let attention_count = lines.iter().filter(|l| attention(l)).count();
        let shown: Vec<&SiteLine> = scope_lines(&lines, &show, &attention)
            .into_iter()
            .filter(|l| line_matches(l, &needle))
            .collect();
        let wanted: Vec<(String, Vec<String>)> = shown
            .iter()
            .filter(|l| !data.series_asked.contains(&l.id))
            .take(SERIES_BATCH)
            .map(|l| {
                (
                    l.id.clone(),
                    l.members.iter().map(|m| m.node.clone()).collect(),
                )
            })
            .collect();

        let mut out: Vec<AnyElement> = Vec::new();
        if !data.failed.is_empty() {
            out.push(notice(&unreachable_note(&data.failed), Tone::Warn).into_any_element());
        }
        let mut options = vec![(Show::All, "All nodes".to_string())];
        if data.nodes.len() > 1 {
            options.extend(
                data.nodes
                    .iter()
                    .map(|n| (Show::Node(n.clone()), n.clone())),
            );
        }
        options.push((
            Show::Attention,
            format!("Needs attention {attention_count}"),
        ));
        let segments: Vec<AnyElement> = options
            .into_iter()
            .map(|(target, label)| {
                let active = target == show;
                seg_item(id("sites-show", &label), &label, active)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.sites.show = target.clone();
                        cx.notify();
                    }))
                    .into_any_element()
            })
            .collect();
        let count = if shown.len() == lines.len() {
            format!("{} sites", lines.len())
        } else {
            format!("{} of {} sites", shown.len(), lines.len())
        };
        out.push(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(space::MD))
                .child(seg_row(segments))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(180.))
                        .max_w(px(360.))
                        .child(self.sites.filter.clone()),
                )
                .child(text_dim(count).text_size(px(font::SM)))
                .into_any_element(),
        );

        let rows: Vec<Vec<AnyElement>> = shown.iter().map(|l| line_cells(l, data, cx)).collect();
        let targets: Vec<(String, String)> = shown
            .iter()
            .filter_map(|l| Some((home_node(l, &show)?.to_string(), l.id.clone())))
            .collect();
        let cols = [
            Col::flex("Site"),
            Col::flex("Hosts"),
            Col::flex("Nodes"),
            Col::fixed("Load", LOAD_COL_W),
            Col::fixed("State", STATE_COL_W),
        ];
        let (title, text) = empty_text(lines.len(), &show, &needle);
        let table = click_table(&cols, rows, targets, empty_state(title, text), cx);
        out.push(card(None, None, wide(id("sites", "table"), 760., table)).into_any_element());
        (out, wanted)
    }
}

fn line_status_of(line: &SiteLine, data: &Data) -> LineStatus {
    combine_status(&statuses_of(line, &data.rows, data.health_pending))
}

// A chip for one node holding the site: a health dot and the node's name. Clicking it opens the site on that node.
fn node_chip(line: &SiteLine, status: &NodeStatus, cx: &mut Context<Console>) -> AnyElement {
    let key = format!("{}-{}", line.id, status.node);
    let (node, site) = (status.node.clone(), line.id.clone());
    let chip = div()
        .id(id("site-chip", &key))
        .flex()
        .items_center()
        .gap(px(6.))
        .px(px(space::SM))
        .py(px(space::XXS))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .border_color(chip_stroke())
        .bg(chip_fill())
        .cursor_pointer()
        .font_family(MONO)
        .text_size(px(font::SM))
        .hover(|s| s.bg(tint(0xffffff, 0.14)))
        .child(dot(status.tone))
        .child(status.node.clone())
        .on_click(cx.listener(move |this, _, _, cx| {
            // The row behind the chip opens the site too; this click is the chip's alone.
            cx.stop_propagation();
            this.navigate(
                View::SiteDetail {
                    node: node.clone(),
                    id: site.clone(),
                },
                cx,
            );
        }));
    tip(chip, id("site-chip-tip", &key), chip_title(status)).into_any_element()
}

fn host_lines(line: &SiteLine) -> AnyElement {
    let mut lines = div().flex().flex_col().min_w_0().gap(px(1.));
    if line.hosts.is_empty() {
        lines = lines.child(text_dim("-"));
    }
    for (i, host) in line.hosts.iter().take(MAX_HOST_LINES).enumerate() {
        lines = lines.child(
            clip_tip(id("site-host", format!("{}-{i}", line.id)), host.clone())
                .font_family(MONO)
                .text_size(px(font::SM)),
        );
    }
    let extra = line.hosts.len().saturating_sub(MAX_HOST_LINES);
    if extra > 0 {
        lines = lines.child(
            text_dim(format!("+{extra} more"))
                .font_family(MONO)
                .text_size(px(font::XS)),
        );
    }
    for (i, path) in line.paths.iter().enumerate() {
        lines = lines.child(
            clip_tip(id("site-path", format!("{}-{i}", line.id)), path.clone())
                .font_family(MONO)
                .text_size(px(font::XS))
                .text_color(c(DIM)),
        );
    }
    lines.into_any_element()
}

// The small request chart and the rate beside it.
fn load_cell(line: &SiteLine, data: &Data) -> AnyElement {
    let spark = match data.series.get(&line.id).filter(|v| !v.is_empty()) {
        Some(values) => div().w(px(SPARK_W)).flex_none().child(line_chart(
            vec![Line {
                values: values.clone(),
                color: BLUE,
                area: false,
            }],
            SPARK_H,
            false,
        )),
        None => div().w(px(SPARK_W)).h(px(SPARK_H)).flex_none(),
    };
    let rate = match line_rps(line, &data.loads) {
        Some(rps) => div()
            .font_family(MONO)
            .text_size(px(font::SM))
            .whitespace_nowrap()
            .child(fmt_rps(rps)),
        // Nothing while the figures are still on their way; a dash once it is clear there are none.
        None if data.load_pending => div(),
        None => div().text_color(c(DIM)).child("-"),
    };
    div()
        .flex()
        .items_center()
        .gap(px(space::SM))
        .child(spark)
        .child(rate)
        .into_any_element()
}

fn line_cells(line: &SiteLine, data: &Data, cx: &mut Context<Console>) -> Vec<AnyElement> {
    let statuses = statuses_of(line, &data.rows, data.health_pending);
    let status = combine_status(&statuses);
    let name = div()
        .flex()
        .flex_col()
        .min_w_0()
        .gap(px(2.))
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(6.))
                .min_w_0()
                .child(
                    clip_tip(id("site-name", &line.id), line.name.clone())
                        .font_weight(gpui::FontWeight::SEMIBOLD),
                )
                .when(line.api, |d| d.child(pill("API", Tone::Muted))),
        )
        .child(
            clip_tip(id("site-id", &line.id), line.id.clone())
                .font_family(MONO)
                .text_size(px(font::XS))
                .text_color(c(DIM)),
        );
    let chips = div()
        .flex()
        .flex_wrap()
        .gap(px(space::XS))
        .children(statuses.iter().map(|s| node_chip(line, s, cx)));
    let state = if status.reason.is_empty() {
        status.state.pill().into_any_element()
    } else {
        tip(
            status.state.pill(),
            id("site-state-tip", &line.id),
            status.reason.clone(),
        )
        .into_any_element()
    };
    vec![
        name.into_any_element(),
        host_lines(line),
        chips.into_any_element(),
        load_cell(line, data),
        state,
    ]
}

// The newest entry of the site's deploy history by timestamp, whatever order the node returned.
pub fn last_deploy(site: &Site) -> Option<(DeployAction, i64)> {
    site.history
        .iter()
        .map(|d| (d.action, parse_rfc3339_ms(&d.at).unwrap_or(0)))
        .max_by_key(|(_, at)| *at)
}

// Same columns as the shared table, but every row is one click target that opens the site.
fn click_table(
    cols: &[Col],
    rows: Vec<Vec<AnyElement>>,
    targets: Vec<(String, String)>,
    empty: gpui::Div,
    cx: &mut Context<Console>,
) -> AnyElement {
    let cell = |col: &Col, child: AnyElement| {
        let base = div()
            .flex()
            .items_center()
            .min_w_0()
            .overflow_hidden()
            .px(px(6.));
        let sized = match col.width {
            Some(w) => base.w(px(w)).flex_none(),
            None => base.flex_1(),
        };
        sized.child(child)
    };
    let mut head = div()
        .flex()
        .px(px(10.))
        .py(px(space::SM))
        .border_b_1()
        .border_color(c(BORDER))
        .text_size(px(font::SM))
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(c(DIM));
    for col in cols {
        head = head.child(cell(col, col.label.into_any_element()));
    }
    let mut root = div().flex().flex_col().w_full().child(head);
    if rows.is_empty() {
        return root.child(empty).into_any_element();
    }
    for (row, (node, site_id)) in rows.into_iter().zip(targets) {
        let mut line = div()
            .id(id("site-row", &site_id))
            .flex()
            .items_center()
            .min_h(px(44.))
            .px(px(10.))
            .py(px(6.))
            .text_size(px(font::BASE))
            .border_b_1()
            .border_color(c(DIVIDER))
            .cursor_pointer()
            .hover(|s| s.bg(tint(0xffffff, 0.035)))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.navigate(
                    View::SiteDetail {
                        node: node.clone(),
                        id: site_id.clone(),
                    },
                    cx,
                );
            }));
        for (col, child) in cols.iter().zip(row) {
            line = line.child(cell(col, child));
        }
        root = root.child(line);
    }
    root.into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::Slot;
    use serde_json::json;

    fn site(id: &str, active: Slot) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: Vec::new(),
            path_prefixes: Vec::new(),
            path_regexes: Vec::new(),
            kind: SiteKind::Site,
            blue: Default::default(),
            green: Default::default(),
            active,
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

    fn row(node: &str, site: Site) -> Row {
        Row {
            node: node.into(),
            site,
            health: Vec::new(),
            phase: None,
        }
    }

    fn health(list: &[&str]) -> Vec<(String, String)> {
        list.iter()
            .map(|s| ("t".to_string(), s.to_string()))
            .collect()
    }

    fn names(lines: &[&SiteLine]) -> Vec<String> {
        lines.iter().map(|l| l.id.clone()).collect()
    }

    #[test]
    fn health_dots_come_from_the_active_slots_backend() {
        let stats = json!({"backends": [
            {"name": "be_shop_blue", "servers": [{"name": "t1", "status": "UP"}, {"name": "t2", "status": "DOWN"}]},
            {"name": "be_shop_green", "servers": [{"name": "t1", "status": "MAINT"}]},
            {"name": "be_shop-2_blue", "servers": [{"name": "t1", "status": "UP"}]},
        ]});
        let blue = health_from_stats(&stats, &site("shop", Slot::Blue));
        assert_eq!(
            blue,
            vec![
                ("t1".to_string(), "UP".to_string()),
                ("t2".to_string(), "DOWN".to_string())
            ]
        );
        let green = health_from_stats(&stats, &site("shop", Slot::Green));
        assert_eq!(green.len(), 1);
        assert_eq!(green[0].1, "MAINT");
        assert!(health_from_stats(&stats, &site("other", Slot::Blue)).is_empty());
        assert!(health_from_stats(&json!({}), &site("shop", Slot::Blue)).is_empty());
        let bare = json!({"backends": [{"name": "be_shop_blue"}]});
        assert!(health_from_stats(&bare, &site("shop", Slot::Blue)).is_empty());
    }

    #[test]
    fn site_state_follows_phase_maintenance_health_and_history() {
        use cite_edge::model::Deployment;
        let entry = |at: &str, action| Deployment {
            id: at.into(),
            at: at.into(),
            slot: Slot::Blue,
            action,
            note: String::new(),
        };
        let mut s = site("shop", Slot::Blue);
        assert_eq!(site_state(&s, &[], None), SiteState::Serving);
        assert_eq!(site_state(&s, &health(&["UP"]), None), SiteState::Serving);
        assert_eq!(
            site_state(&s, &health(&["DOWN", "UP"]), None),
            SiteState::Serving
        );
        assert_eq!(
            site_state(&s, &health(&["DOWN", "DOWN"]), None),
            SiteState::Down
        );
        assert_eq!(site_state(&s, &[], Some("building")), SiteState::Building);
        assert_eq!(site_state(&s, &[], Some("idle")), SiteState::Serving);
        assert_eq!(site_state(&s, &[], Some("unhealthy")), SiteState::Down);
        assert_eq!(site_state(&s, &[], Some("failed")), SiteState::Failed);
        s.history = vec![entry("2026-11-02T10:00:00Z", DeployAction::Promote)];
        assert_eq!(site_state(&s, &[], Some("packing")), SiteState::Redeploying);
        s.history
            .push(entry("2026-11-03T10:00:00Z", DeployAction::Failed));
        assert_eq!(site_state(&s, &[], None), SiteState::Failed);
        s.maintenance.enabled = true;
        assert_eq!(site_state(&s, &[], None), SiteState::Maintenance);
        assert_eq!(
            site_state(&s, &[], Some("building")),
            SiteState::Redeploying
        );
        assert_eq!(SiteState::Building.tone(), Tone::Info);
        assert_eq!(SiteState::Maintenance.tone(), Tone::Warn);
        assert_eq!(SiteState::Serving.tone(), Tone::Ok);
    }

    #[test]
    fn last_deploy_is_the_newest_entry_regardless_of_order() {
        use cite_edge::model::{DeployAction, Deployment};
        let mut s = site("shop", Slot::Blue);
        assert!(last_deploy(&s).is_none());
        let entry = |at: &str, action| Deployment {
            id: at.into(),
            at: at.into(),
            slot: Slot::Blue,
            action,
            note: String::new(),
        };
        s.history = vec![
            entry("2026-11-02T10:00:00Z", DeployAction::Promote),
            entry("2026-11-05T09:00:00Z", DeployAction::Failed),
            entry("2026-11-01T08:00:00Z", DeployAction::Rollback),
        ];
        let (action, at) = last_deploy(&s).unwrap();
        assert_eq!(action, DeployAction::Failed);
        assert_eq!(Some(at), parse_rfc3339_ms("2026-11-05T09:00:00Z"));
    }

    #[test]
    fn the_list_has_one_row_per_site_id_whatever_the_node_count() {
        let mut shop_fra = site("shop", Slot::Blue);
        shop_fra.name = "Storefront".into();
        shop_fra.hosts = vec!["shop.example.com".into(), "www.example.com".into()];
        let mut shop_iad = shop_fra.clone();
        shop_iad.hosts = vec!["shop.example.com".into(), "eu.example.com".into()];
        let mut api = site("api", Slot::Green);
        api.name = "Public API".into();
        api.kind = SiteKind::Api;
        api.hosts = vec!["api.example.com".into()];
        api.path_regexes = vec!["^/v1/(quote|price)$".into()];
        let rows = vec![
            row("fra", shop_fra),
            row("fra", api.clone()),
            row("iad", shop_iad),
            row("iad", api),
        ];
        let lines = group_rows(&rows);
        assert_eq!(lines.len(), 2);
        // Sorted by name: Public API before Storefront.
        assert_eq!(lines[0].id, "api");
        assert!(lines[0].api && !lines[1].api);
        assert_eq!(lines[0].paths, vec!["~ ^/v1/(quote|price)$".to_string()]);
        assert!(lines[1].paths.is_empty(), "any path adds no line");
        assert_eq!(
            lines[1].hosts,
            vec![
                "shop.example.com".to_string(),
                "www.example.com".to_string(),
                "eu.example.com".to_string()
            ]
        );
        let nodes: Vec<&str> = lines[1].members.iter().map(|m| m.node.as_str()).collect();
        assert_eq!(nodes, vec!["fra", "iad"]);
        assert_eq!(lines[1].members[1].row, 2);
        assert!(group_rows(&[]).is_empty());
    }

    #[test]
    fn a_site_on_several_nodes_lists_each_distinct_path_match_once() {
        let mut a = site("api", Slot::Blue);
        a.path_prefixes = vec!["/v2/".into()];
        let mut b = a.clone();
        let mut c = a.clone();
        b.path_regexes = vec!["^/v1/$".into()];
        c.path_prefixes = vec!["/v2/".into()];
        let lines = group_rows(&[row("fra", a), row("iad", b), row("ams", c)]);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].paths,
            vec!["/v2/".to_string(), "/v2/  ~ ^/v1/$".to_string()]
        );
    }

    #[test]
    fn scopes_pick_all_one_node_or_the_sites_that_need_attention() {
        let rows = vec![
            row("fra", site("a", Slot::Blue)),
            row("fra", site("b", Slot::Blue)),
            row("iad", site("b", Slot::Blue)),
            row("iad", site("c", Slot::Blue)),
        ];
        let lines = group_rows(&rows);
        let attention = |l: &SiteLine| l.id == "c";
        assert_eq!(
            names(&scope_lines(&lines, &Show::All, &attention)),
            ["a", "b", "c"]
        );
        assert_eq!(
            names(&scope_lines(&lines, &Show::Node("fra".into()), &attention)),
            ["a", "b"]
        );
        assert_eq!(
            names(&scope_lines(&lines, &Show::Node("iad".into()), &attention)),
            ["b", "c"]
        );
        assert_eq!(
            names(&scope_lines(&lines, &Show::Attention, &attention)),
            ["c"]
        );
        assert!(scope_lines(&lines, &Show::Node("ams".into()), &attention).is_empty());
    }

    #[test]
    fn a_scope_on_a_node_that_is_gone_falls_back_to_all() {
        let nodes = vec!["fra".to_string(), "iad".to_string()];
        assert_eq!(effective_show(&Show::Node("ams".into()), &nodes), Show::All);
        assert_eq!(
            effective_show(&Show::Node("iad".into()), &nodes),
            Show::Node("iad".into())
        );
        assert_eq!(effective_show(&Show::Attention, &nodes), Show::Attention);
    }

    #[test]
    fn only_failing_targets_and_a_failed_deploy_need_attention() {
        assert!(SiteState::Down.needs_attention());
        assert!(SiteState::Failed.needs_attention());
        for calm in [
            SiteState::Serving,
            SiteState::Maintenance,
            SiteState::Building,
            SiteState::Redeploying,
        ] {
            assert!(!calm.needs_attention(), "{calm:?}");
        }
        assert_eq!(SiteState::Down.label(), "Needs attention");
        assert_eq!(SiteState::Failed.label(), "Deploy failed");
    }

    #[test]
    fn the_worst_node_decides_the_state_and_names_itself_in_the_reason() {
        let ok = NodeStatus {
            node: "fra".into(),
            state: SiteState::Serving,
            tone: Tone::Ok,
            reason: String::new(),
        };
        let down = NodeStatus {
            node: "iad".into(),
            state: SiteState::Down,
            tone: Tone::Bad,
            reason: "Every server in the active slot is down".into(),
        };
        let maint = NodeStatus {
            node: "ams".into(),
            state: SiteState::Maintenance,
            tone: Tone::Warn,
            reason: "Maintenance page is being served".into(),
        };
        let both = combine_status(&[ok.clone(), maint.clone(), down.clone()]);
        assert_eq!(both.state, SiteState::Down);
        assert_eq!(both.reason, "iad: Every server in the active slot is down");
        let alone = combine_status(std::slice::from_ref(&maint));
        assert_eq!(alone.reason, "Maintenance page is being served");
        let calm = combine_status(&[ok.clone(), ok]);
        assert_eq!((calm.state, calm.reason.as_str()), (SiteState::Serving, ""));
        assert_eq!(combine_status(&[]).state, SiteState::Serving);
    }

    #[test]
    fn a_node_chip_reads_healthy_partly_down_or_the_reason() {
        let mut s = site("shop", Slot::Blue);
        let mut r = row("fra", s.clone());
        r.health = health(&["UP", "UP"]);
        let healthy = node_status(&r, false);
        assert_eq!(healthy.tone, Tone::Ok);
        assert_eq!(chip_title(&healthy), "fra: healthy");
        r.health = health(&["UP", "DOWN"]);
        let partly = node_status(&r, false);
        assert_eq!(
            (partly.tone, partly.state),
            (Tone::Warn, SiteState::Serving)
        );
        assert_eq!(
            chip_title(&partly),
            "fra: Some servers in the active slot are down"
        );
        r.health = health(&["DOWN", "DOWN"]);
        assert_eq!(node_status(&r, false).tone, Tone::Bad);
        r.health.clear();
        assert_eq!(node_status(&r, true).reason, "Checking health");
        assert_eq!(node_status(&r, false).reason, "No health data");
        s.maintenance.enabled = true;
        let m = node_status(&row("fra", s), false);
        assert_eq!((m.tone, m.state), (Tone::Warn, SiteState::Maintenance));
    }

    #[test]
    fn a_failed_deploy_explains_itself_with_the_first_line_of_the_note() {
        use cite_edge::model::Deployment;
        let mut s = site("docs", Slot::Blue);
        s.history = vec![Deployment {
            id: "d".into(),
            at: "2026-11-05T09:00:00Z".into(),
            slot: Slot::Green,
            action: DeployAction::Failed,
            note: "green slot did not pass health checks\nlast build output".into(),
        }];
        let status = node_status(&row("fra", s.clone()), false);
        assert_eq!(status.state, SiteState::Failed);
        assert_eq!(
            status.reason,
            "The last deployment to green failed: green slot did not pass health checks"
        );
        s.history[0].note.clear();
        assert_eq!(
            node_status(&row("fra", s), false).reason,
            "The last deployment to green failed"
        );
    }

    #[test]
    fn the_filter_matches_name_id_or_any_host_in_any_case() {
        let mut s = site("shop", Slot::Blue);
        s.name = "Storefront".into();
        s.hosts = vec!["Www.Example.com".into()];
        let line = &group_rows(&[row("fra", s)])[0];
        assert!(line_matches(line, ""));
        assert!(line_matches(line, "  store "));
        assert!(line_matches(line, "SHOP"));
        assert!(line_matches(line, "www.example"));
        assert!(!line_matches(line, "docs"));
    }

    #[test]
    fn a_row_opens_the_scoped_node_when_it_holds_the_site_else_the_first() {
        let rows = vec![
            row("fra", site("a", Slot::Blue)),
            row("iad", site("a", Slot::Blue)),
        ];
        let line = &group_rows(&rows)[0];
        assert_eq!(home_node(line, &Show::All), Some("fra"));
        assert_eq!(home_node(line, &Show::Node("iad".into())), Some("iad"));
        assert_eq!(home_node(line, &Show::Node("ams".into())), Some("fra"));
        assert_eq!(home_node(line, &Show::Attention), Some("fra"));
    }

    #[test]
    fn load_adds_up_over_the_nodes_that_answered() {
        let rows = vec![
            row("fra", site("a", Slot::Blue)),
            row("iad", site("a", Slot::Blue)),
        ];
        let line = &group_rows(&rows)[0];
        let mut loads: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
        assert_eq!(line_rps(line, &loads), None);
        loads.insert("fra".into(), BTreeMap::from([("a".to_string(), 1.5)]));
        assert_eq!(line_rps(line, &loads), Some(1.5));
        loads.insert("iad".into(), BTreeMap::from([("a".to_string(), 2.0)]));
        assert_eq!(line_rps(line, &loads), Some(3.5));
        // A node that answered without the site counts as zero, not as missing.
        loads.insert("iad".into(), BTreeMap::new());
        assert_eq!(line_rps(line, &loads), Some(1.5));
    }

    #[test]
    fn series_from_several_nodes_add_up_aligned_on_the_newest_end() {
        assert_eq!(
            merge_points(&[vec![1, 2, 3], vec![10, 20]]),
            vec![1, 12, 23]
        );
        assert_eq!(merge_points(&[vec![4, 5]]), vec![4, 5]);
        assert!(merge_points(&[]).is_empty());
        assert!(merge_points(&[Vec::new(), Vec::new()]).is_empty());
    }

    #[test]
    fn the_subtitle_counts_sites_and_nodes() {
        assert_eq!(subtitle_for(4, 2), "4 across 2 nodes");
        assert_eq!(subtitle_for(1, 1), "1 across 1 node");
        assert_eq!(subtitle_for(0, 0), "0 across 0 nodes");
    }

    #[test]
    fn the_unreachable_notice_names_every_node_in_one_line() {
        assert_eq!(
            unreachable_note(&["ams".to_string()]),
            "Could not reach ams. Its sites are not listed."
        );
        assert_eq!(
            unreachable_note(&["ams".to_string(), "sin".to_string()]),
            "Could not reach ams, sin. Their sites are not listed."
        );
    }

    #[test]
    fn an_empty_list_says_why() {
        assert_eq!(empty_text(0, &Show::All, "").0, "No sites yet");
        assert_eq!(
            empty_text(3, &Show::Attention, "").0,
            "Nothing needs attention"
        );
        assert_eq!(empty_text(3, &Show::Attention, "zz").0, "No sites match");
        assert_eq!(empty_text(3, &Show::All, "zz").0, "No sites match");
    }
}
