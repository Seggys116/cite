#![allow(dead_code)] // The views use these helpers.
//! Builds the topology graph: entries (host plus path match) -> nodes -> sites, with load on
//! every link. Pure data in, plain graph and geometry out. Port of the dashboard's
//! `topologylib.js`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const LOAD_WINDOW_SECS: u64 = 15 * 60;

/// Requests per second per site id, from the site facet counts of a window. A zero-length
/// window has no rate, so it yields nothing.
pub fn load_from_facets(site_counts: &[(String, u64)], window_secs: u64) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    if window_secs == 0 {
        return out;
    }
    for (key, count) in site_counts {
        out.insert(key.clone(), *count as f64 / window_secs as f64);
    }
    out
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TopoSite {
    pub id: String,
    pub name: String,
    pub kind_is_api: bool,
    pub runtime: Option<String>,
    pub hosts: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub path_regexes: Vec<String>,
    pub maintenance: bool,
    /// The last deploy failed or the site reports a failed status.
    pub failed: bool,
    pub active: Option<String>,
}

/// `sites` is `None` when the node could not be read; `load` maps site id to requests per
/// second.
#[derive(Clone, Debug, PartialEq)]
pub struct TopoNode {
    pub name: String,
    pub online: bool,
    pub sites: Option<Vec<TopoSite>>,
    pub load: BTreeMap<String, f64>,
}

/// Worst last: a failure or maintenance on any node shows on the site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SiteState {
    Serving,
    Failed,
    Maintenance,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: String,
    pub host: String,
    pub path: String,
    pub site_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeOut {
    pub name: String,
    pub online: bool,
    pub readable: bool,
    pub rps: f64,
    pub site_count: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SiteOut {
    pub id: String,
    pub name: String,
    pub kind_is_api: bool,
    pub active: Option<String>,
    pub runtime: Option<String>,
    pub state: SiteState,
    pub rps: f64,
    pub nodes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    /// The entry id.
    pub from: String,
    /// The node name.
    pub via: String,
    /// The site id.
    pub to: String,
    pub rps: f64,
    pub standby: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Topology {
    pub entries: Vec<Entry>,
    pub nodes: Vec<NodeOut>,
    pub sites: Vec<SiteOut>,
    pub links: Vec<Link>,
    pub peak: f64,
}

/// Approximates `String.prototype.localeCompare`: case-insensitive first, then lowercase
/// before uppercase when the letters are otherwise equal.
fn locale_cmp(a: &str, b: &str) -> Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| b.cmp(a))
}

/// What a request path has to look like to reach a site, in the words the person used.
pub fn path_label(site: &TopoSite) -> String {
    if site.path_prefixes.is_empty() && site.path_regexes.is_empty() {
        return "any path".to_string();
    }
    let mut parts: Vec<String> = site.path_prefixes.clone();
    parts.extend(site.path_regexes.iter().map(|r| format!("~ {r}")));
    parts.join("  ")
}

fn site_state(site: &TopoSite) -> SiteState {
    if site.maintenance {
        SiteState::Maintenance
    } else if site.failed {
        SiteState::Failed
    } else {
        SiteState::Serving
    }
}

fn non_empty(value: &Option<String>) -> Option<String> {
    value.clone().filter(|v| !v.is_empty())
}

pub fn build_topology(nodes: &[TopoNode]) -> Topology {
    let mut entries: Vec<Entry> = Vec::new();
    let mut entry_ids: HashSet<String> = HashSet::new();
    let mut sites: Vec<SiteOut> = Vec::new();
    let mut node_out: Vec<NodeOut> = Vec::new();
    let mut links: Vec<Link> = Vec::new();

    for node in nodes {
        let list: &[TopoSite] = node.sites.as_deref().unwrap_or(&[]);
        let mut node_rps = 0.0;
        for site in list {
            let rps = match node.load.get(&site.id).copied() {
                Some(v) if !v.is_nan() => v,
                _ => 0.0,
            };
            node_rps += rps;
            let state = site_state(site);
            let idx = match sites.iter().position(|s| s.id == site.id) {
                Some(i) => i,
                None => {
                    sites.push(SiteOut {
                        id: site.id.clone(),
                        name: site.name.clone(),
                        kind_is_api: site.kind_is_api,
                        active: non_empty(&site.active),
                        runtime: non_empty(&site.runtime),
                        state,
                        rps: 0.0,
                        nodes: Vec::new(),
                    });
                    sites.len() - 1
                }
            };
            let s = &mut sites[idx];
            s.rps += rps;
            s.nodes.push(node.name.clone());
            if state > s.state {
                s.state = state;
            }
            let path = path_label(site);
            for host in &site.hosts {
                let key = format!("{host}|{path}|{}", site.id);
                if entry_ids.insert(key.clone()) {
                    entries.push(Entry {
                        id: key.clone(),
                        host: host.clone(),
                        path: path.clone(),
                        site_id: site.id.clone(),
                    });
                }
                links.push(Link {
                    from: key,
                    via: node.name.clone(),
                    to: site.id.clone(),
                    rps,
                    standby: !node.online || rps == 0.0,
                });
            }
        }
        node_out.push(NodeOut {
            name: node.name.clone(),
            online: node.online,
            readable: node.sites.is_some(),
            rps: node_rps,
            site_count: list.len(),
        });
    }

    // One link per entry and node, so a host listed on two sites is not counted twice
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let merged: Vec<Link> = links
        .into_iter()
        .filter(|l| seen.insert((l.from.clone(), l.via.clone(), l.to.clone())))
        .collect();
    let peak = merged.iter().fold(0.0_f64, |m, l| m.max(l.rps));

    entries.sort_by(|a, b| locale_cmp(&a.host, &b.host).then_with(|| locale_cmp(&a.path, &b.path)));
    sites.sort_by(|a, b| locale_cmp(&a.name, &b.name));
    Topology {
        entries,
        nodes: node_out,
        sites,
        links: merged,
        peak,
    }
}

pub const MIN_LINE_WIDTH: f64 = 1.5;
pub const MAX_LINE_WIDTH: f64 = 8.0;

/// Line width in pixels for a link: idle links stay visible, the busiest gets the thickest line.
pub fn line_width(rps: f64, peak: f64) -> f64 {
    line_width_between(rps, peak, MIN_LINE_WIDTH, MAX_LINE_WIDTH)
}

pub fn line_width_between(rps: f64, peak: f64, min: f64, max: f64) -> f64 {
    if peak.is_nan() || peak <= 0.0 || rps.is_nan() || rps <= 0.0 {
        return min;
    }
    min + (max - min) * (rps / peak).min(1.0).sqrt()
}

/// "0/s", "4.3/s" below ten, whole numbers from ten up.
pub fn fmt_rps(rps: f64) -> String {
    if rps.is_nan() || rps <= 0.0 {
        return "0/s".to_string();
    }
    if rps < 10.0 {
        // `toFixed` rounds an exact tie up while Rust rounds it to even. A tie at one
        // decimal is exactly a quarter value with an odd count of quarters.
        let quarters = rps * 4.0;
        if quarters.fract() == 0.0 && quarters as u64 % 2 == 1 {
            return format!("{:.1}/s", (rps * 10.0).ceil() / 10.0);
        }
        return format!("{rps:.1}/s");
    }
    format!("{}/s", rps.round() as u64)
}

/// The links that pass through a node, for dimming everything else when a node is picked.
pub fn links_through<'a>(graph: &'a Topology, node_name: &str) -> Vec<&'a Link> {
    graph.links.iter().filter(|l| l.via == node_name).collect()
}

/// Shortens text for a fixed-width box; the full text belongs in a tooltip.
pub fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(1).max(1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('…');
    out
}

fn capital(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// What a site is, in the box's second line: the runtime for a built site, "one endpoint"
/// for an API.
pub fn site_kind_label(site: &SiteOut) -> String {
    let runtime = capital(site.runtime.as_deref().unwrap_or(""));
    match (site.kind_is_api, runtime.is_empty()) {
        (true, false) => format!("{runtime}, one endpoint"),
        (true, true) => "API".to_string(),
        (false, false) => format!("{runtime} site"),
        (false, true) => "Site".to_string(),
    }
}

pub const VIEW_WIDTH: f64 = 696.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Column {
    pub x: f64,
    pub w: f64,
    pub h: f64,
}

pub const ENTRY_COLUMN: Column = Column {
    x: 8.0,
    w: 162.0,
    h: 46.0,
};
pub const NODE_COLUMN: Column = Column {
    x: 288.0,
    w: 116.0,
    h: 58.0,
};
pub const SITE_COLUMN: Column = Column {
    x: 516.0,
    w: 172.0,
    h: 74.0,
};

const ROW_GAP: f64 = 14.0;
const PAD_Y: f64 = 12.0;
const CURVE: f64 = 60.0;

#[derive(Clone, Debug, PartialEq)]
pub struct EntryBox {
    pub id: String,
    pub host: String,
    pub path: String,
    pub site_id: String,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeBox {
    /// The node name.
    pub id: String,
    pub name: String,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SiteBox {
    pub id: String,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkStage {
    /// Entry to node.
    In,
    /// Node to site.
    Out,
}

/// A cubic bezier: start, first control point, second control point, end.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CubicPath {
    pub x1: f64,
    pub y1: f64,
    pub c1x: f64,
    pub c1y: f64,
    pub c2x: f64,
    pub c2y: f64,
    pub x2: f64,
    pub y2: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LinkGeom {
    pub id: String,
    pub stage: LinkStage,
    pub via: String,
    pub entry_id: Option<String>,
    pub site_id: String,
    pub rps: f64,
    pub standby: bool,
    pub path: CubicPath,
    pub width: f64,
    pub busiest: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Layout {
    pub width: f64,
    pub height: f64,
    pub entries: Vec<EntryBox>,
    pub nodes: Vec<NodeBox>,
    pub sites: Vec<SiteBox>,
    pub links: Vec<LinkGeom>,
}

/// Even anchor points down a box edge so several links do not pile onto one spot.
fn anchor(y: f64, h: f64, index: usize, count: usize) -> f64 {
    y + (h * (index + 1) as f64) / (count + 1) as f64
}

fn round1(n: f64) -> f64 {
    (n * 10.0).round() / 10.0
}

fn curve(x1: f64, y1: f64, x2: f64, y2: f64) -> CubicPath {
    CubicPath {
        x1: round1(x1),
        y1: round1(y1),
        c1x: round1(x1 + CURVE),
        c1y: round1(y1),
        c2x: round1(x2 - CURVE),
        c2y: round1(y2),
        x2: round1(x2),
        y2: round1(y2),
    }
}

fn column_height(count: usize, box_h: f64) -> f64 {
    if count == 0 {
        0.0
    } else {
        count as f64 * box_h + (count - 1) as f64 * ROW_GAP
    }
}

fn column_ys(count: usize, col: &Column, inner: f64) -> Vec<f64> {
    let top = PAD_Y + (inner - column_height(count, col.h)) / 2.0;
    (0..count)
        .map(|n| top + n as f64 * (col.h + ROW_GAP))
        .collect()
}

/// Order the anchors by where the other end sits, so links fan out without crossing at the
/// box. Returns each link's (index, count) among the links sharing its box key.
fn slots(keys: &[&str], ranks: &[usize]) -> Vec<(usize, usize)> {
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        match groups.iter().position(|group| group.0 == *key) {
            Some(g) => groups[g].1.push(i),
            None => groups.push((*key, vec![i])),
        }
    }
    let mut out = vec![(0, 0); keys.len()];
    for (_, mut members) in groups {
        members.sort_by_key(|&i| ranks[i]);
        let count = members.len();
        for (index, &i) in members.iter().enumerate() {
            out[i] = (index, count);
        }
    }
    out
}

/// Turns the graph into drawable geometry: boxes in three columns and a bezier per link.
/// Pure so the drawing code only has to put elements where this says.
pub fn layout_topology(graph: &Topology) -> Layout {
    let inner = column_height(graph.entries.len(), ENTRY_COLUMN.h)
        .max(column_height(graph.nodes.len(), NODE_COLUMN.h))
        .max(column_height(graph.sites.len(), SITE_COLUMN.h));

    let entries: Vec<EntryBox> = graph
        .entries
        .iter()
        .zip(column_ys(graph.entries.len(), &ENTRY_COLUMN, inner))
        .map(|(e, y)| EntryBox {
            id: e.id.clone(),
            host: e.host.clone(),
            path: e.path.clone(),
            site_id: e.site_id.clone(),
            x: ENTRY_COLUMN.x,
            y,
            w: ENTRY_COLUMN.w,
            h: ENTRY_COLUMN.h,
        })
        .collect();
    let nodes: Vec<NodeBox> = graph
        .nodes
        .iter()
        .zip(column_ys(graph.nodes.len(), &NODE_COLUMN, inner))
        .map(|(n, y)| NodeBox {
            id: n.name.clone(),
            name: n.name.clone(),
            x: NODE_COLUMN.x,
            y,
            w: NODE_COLUMN.w,
            h: NODE_COLUMN.h,
        })
        .collect();
    let sites: Vec<SiteBox> = graph
        .sites
        .iter()
        .zip(column_ys(graph.sites.len(), &SITE_COLUMN, inner))
        .map(|(s, y)| SiteBox {
            id: s.id.clone(),
            x: SITE_COLUMN.x,
            y,
            w: SITE_COLUMN.w,
            h: SITE_COLUMN.h,
        })
        .collect();

    // Box index by id; the position in a column is also the rank used to order anchors.
    let entry_at: HashMap<&str, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id.as_str(), i))
        .collect();
    let node_at: HashMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, b)| (b.name.as_str(), i))
        .collect();
    let site_at: HashMap<&str, usize> = sites
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id.as_str(), i))
        .collect();

    let in_links: Vec<&Link> = graph
        .links
        .iter()
        .filter(|l| entry_at.contains_key(l.from.as_str()) && node_at.contains_key(l.via.as_str()))
        .collect();
    let mut out_seen: HashSet<(&str, &str)> = HashSet::new();
    let mut out_links: Vec<&Link> = Vec::new();
    for l in &graph.links {
        if node_at.contains_key(l.via.as_str())
            && site_at.contains_key(l.to.as_str())
            && out_seen.insert((l.via.as_str(), l.to.as_str()))
        {
            out_links.push(l);
        }
    }

    let rank = |map: &HashMap<&str, usize>, key: &str| map.get(key).copied().unwrap_or(usize::MAX);
    let in_keys: Vec<&str> = in_links.iter().map(|l| l.via.as_str()).collect();
    let in_ranks: Vec<usize> = in_links.iter().map(|l| rank(&entry_at, &l.from)).collect();
    let in_at_node = slots(&in_keys, &in_ranks);

    let out_via: Vec<&str> = out_links.iter().map(|l| l.via.as_str()).collect();
    let out_to: Vec<&str> = out_links.iter().map(|l| l.to.as_str()).collect();
    let out_site_ranks: Vec<usize> = out_links.iter().map(|l| rank(&site_at, &l.to)).collect();
    let out_node_ranks: Vec<usize> = out_links.iter().map(|l| rank(&node_at, &l.via)).collect();
    let out_at_node = slots(&out_via, &out_site_ranks);
    let in_at_site = slots(&out_to, &out_node_ranks);

    let mut links: Vec<LinkGeom> = Vec::new();
    for (i, l) in in_links.iter().enumerate() {
        let (Some(&from_ix), Some(&to_ix)) =
            (entry_at.get(l.from.as_str()), node_at.get(l.via.as_str()))
        else {
            continue;
        };
        let from = &entries[from_ix];
        let to = &nodes[to_ix];
        let (index, count) = in_at_node[i];
        links.push(LinkGeom {
            id: format!("in:{}>{}", l.from, l.via),
            stage: LinkStage::In,
            via: l.via.clone(),
            entry_id: Some(l.from.clone()),
            site_id: l.to.clone(),
            rps: l.rps,
            standby: l.standby,
            path: curve(
                from.x + from.w,
                from.y + from.h / 2.0,
                to.x,
                anchor(to.y, to.h, index, count),
            ),
            width: 0.0,
            busiest: false,
        });
    }
    for (i, l) in out_links.iter().enumerate() {
        let (Some(&from_ix), Some(&to_ix)) =
            (node_at.get(l.via.as_str()), site_at.get(l.to.as_str()))
        else {
            continue;
        };
        let from = &nodes[from_ix];
        let to = &sites[to_ix];
        let (a_index, a_count) = out_at_node[i];
        let (b_index, b_count) = in_at_site[i];
        links.push(LinkGeom {
            id: format!("out:{}>{}", l.via, l.to),
            stage: LinkStage::Out,
            via: l.via.clone(),
            entry_id: None,
            site_id: l.to.clone(),
            rps: l.rps,
            standby: l.standby,
            path: curve(
                from.x + from.w,
                anchor(from.y, from.h, a_index, a_count),
                to.x,
                anchor(to.y, to.h, b_index, b_count),
            ),
            width: 0.0,
            busiest: false,
        });
    }
    for l in &mut links {
        l.width = line_width(l.rps, graph.peak);
        l.busiest = graph.peak > 0.0 && l.rps == graph.peak;
    }
    Layout {
        width: VIEW_WIDTH,
        height: inner + PAD_Y * 2.0,
        entries,
        nodes,
        sites,
        links,
    }
}

/// Changes only when boxes or links come or go, so a refresh that moves numbers can update
/// in place.
pub fn shape_key(graph: &Topology) -> String {
    let entries: Vec<&str> = graph.entries.iter().map(|e| e.id.as_str()).collect();
    let nodes: Vec<(&str, bool)> = graph
        .nodes
        .iter()
        .map(|n| (n.name.as_str(), n.online))
        .collect();
    let sites: Vec<&str> = graph.sites.iter().map(|s| s.id.as_str()).collect();
    let links: Vec<String> = graph
        .links
        .iter()
        .map(|l| format!("{}>{}>{}", l.from, l.via, l.to))
        .collect();
    format!("{:?}", (entries, nodes, sites, links))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shop() -> TopoSite {
        TopoSite {
            id: "shop".to_string(),
            name: "Storefront".to_string(),
            hosts: vec!["shop.example.com".to_string()],
            ..TopoSite::default()
        }
    }

    fn api() -> TopoSite {
        TopoSite {
            id: "api".to_string(),
            name: "Public API".to_string(),
            kind_is_api: true,
            hosts: vec!["api.example.com".to_string()],
            path_regexes: vec!["^/v1/(quote|price)$".to_string()],
            runtime: Some("rust".to_string()),
            ..TopoSite::default()
        }
    }

    fn node(
        name: &str,
        online: bool,
        sites: Option<Vec<TopoSite>>,
        load: &[(&str, f64)],
    ) -> TopoNode {
        TopoNode {
            name: name.to_string(),
            online,
            sites,
            load: load.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    fn counts(items: &[(&str, u64)]) -> Vec<(String, u64)> {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn facet_counts_become_requests_per_second() {
        let load = load_from_facets(&counts(&[("shop", 900), ("api", 90)]), 900);
        let mut expected = BTreeMap::new();
        expected.insert("shop".to_string(), 1.0);
        expected.insert("api".to_string(), 0.1);
        assert_eq!(load, expected);
        assert!(load_from_facets(&[], LOAD_WINDOW_SECS).is_empty());
        assert!(load_from_facets(&counts(&[("shop", 5)]), 0).is_empty());
    }

    #[test]
    fn the_path_label_says_what_reaches_the_site() {
        assert_eq!(path_label(&shop()), "any path");
        assert_eq!(path_label(&api()), "~ ^/v1/(quote|price)$");
        let both = TopoSite {
            path_prefixes: vec!["/blog".to_string()],
            path_regexes: vec!["^/a$".to_string()],
            ..TopoSite::default()
        };
        assert_eq!(path_label(&both), "/blog  ~ ^/a$");
    }

    fn two_nodes() -> Topology {
        build_topology(&[
            node("fra", true, Some(vec![shop()]), &[("shop", 41.0)]),
            node(
                "nyc",
                true,
                Some(vec![shop(), api()]),
                &[("shop", 0.0), ("api", 128.0)],
            ),
        ])
    }

    #[test]
    fn entries_nodes_and_sites_are_linked_with_load() {
        let g = two_nodes();
        assert_eq!(g.nodes.iter().find(|n| n.name == "nyc").unwrap().rps, 128.0);
        assert_eq!(g.nodes.iter().find(|n| n.name == "fra").unwrap().rps, 41.0);
        let shop_out = g.sites.iter().find(|s| s.id == "shop").unwrap();
        assert_eq!(shop_out.rps, 41.0);
        assert_eq!(shop_out.nodes, vec!["fra".to_string(), "nyc".to_string()]);
        assert_eq!(g.entries.len(), 2);
        let idle = g
            .links
            .iter()
            .find(|l| l.via == "nyc" && l.to == "shop")
            .unwrap();
        assert!(idle.standby);
        let busy = g
            .links
            .iter()
            .find(|l| l.via == "fra" && l.to == "shop")
            .unwrap();
        assert!(!busy.standby);
        assert_eq!(g.peak, 128.0);
    }

    #[test]
    fn an_offline_or_unreadable_node_is_shown_never_dropped() {
        let g = build_topology(&[
            node("fra", true, Some(vec![shop()]), &[]),
            node("ams", false, None, &[]),
        ]);
        let ams = g.nodes.iter().find(|n| n.name == "ams").unwrap();
        assert!(!ams.online);
        assert!(!ams.readable);
        assert_eq!(ams.rps, 0.0);
    }

    #[test]
    fn maintenance_on_any_node_shows_on_the_site() {
        let down = TopoSite {
            maintenance: true,
            ..shop()
        };
        let g = build_topology(&[
            node("fra", true, Some(vec![shop()]), &[]),
            node("nyc", true, Some(vec![down]), &[]),
        ]);
        assert_eq!(g.sites[0].state, SiteState::Maintenance);
        // A failure outranks serving but not maintenance.
        let failed = TopoSite {
            failed: true,
            ..shop()
        };
        let g = build_topology(&[
            node("fra", true, Some(vec![shop()]), &[]),
            node("nyc", true, Some(vec![failed]), &[]),
        ]);
        assert_eq!(g.sites[0].state, SiteState::Failed);
    }

    #[test]
    fn a_host_listed_twice_is_one_link() {
        let twice = TopoSite {
            hosts: vec![
                "shop.example.com".to_string(),
                "shop.example.com".to_string(),
            ],
            ..shop()
        };
        let g = build_topology(&[node("fra", true, Some(vec![twice]), &[])]);
        assert_eq!(g.entries.len(), 1);
        assert_eq!(g.links.len(), 1);
    }

    #[test]
    fn line_width_grows_with_load_and_stays_within_bounds() {
        assert_eq!(line_width(0.0, 100.0), 1.5);
        assert_eq!(line_width(100.0, 100.0), 8.0);
        let mid = line_width(25.0, 100.0);
        assert!(mid > 1.5 && mid < 8.0);
        assert_eq!(line_width(5.0, 0.0), 1.5);
        assert_eq!(line_width(500.0, 100.0), 8.0);
    }

    #[test]
    fn line_width_is_monotonic_and_within_bounds() {
        for peak in [0.0, 0.5, 1.0, 100.0, 1e6] {
            let mut last = f64::NEG_INFINITY;
            for step in 0..=400 {
                let rps = step as f64 * 0.75;
                let w = line_width(rps, peak);
                assert!(
                    (MIN_LINE_WIDTH..=MAX_LINE_WIDTH).contains(&w),
                    "width {w} for rps {rps} peak {peak}"
                );
                assert!(w >= last, "width fell at rps {rps} peak {peak}");
                last = w;
            }
        }
        assert_eq!(line_width_between(10.0, 10.0, 2.0, 4.0), 4.0);
    }

    #[test]
    fn rates_read_cleanly() {
        assert_eq!(fmt_rps(0.0), "0/s");
        assert_eq!(fmt_rps(0.04), "0.0/s");
        assert_eq!(fmt_rps(4.26), "4.3/s");
        assert_eq!(fmt_rps(128.4), "128/s");
        // A tie rounds up as toFixed does.
        assert_eq!(fmt_rps(0.25), "0.3/s");
        assert_eq!(fmt_rps(0.75), "0.8/s");
        assert_eq!(fmt_rps(9.96), "10.0/s");
    }

    #[test]
    fn links_through_a_node() {
        let g = build_topology(&[
            node("fra", true, Some(vec![shop()]), &[("shop", 1.0)]),
            node("nyc", true, Some(vec![api()]), &[("api", 2.0)]),
        ]);
        let through = links_through(&g, "nyc");
        let to: Vec<&str> = through.iter().map(|l| l.to.as_str()).collect();
        assert_eq!(to, vec!["api"]);
    }

    #[test]
    fn clip_keeps_short_text_and_shortens_long_text_with_an_ellipsis() {
        assert_eq!(clip("shop.example.com", 20), "shop.example.com");
        assert_eq!(clip("abcdefghij", 6), "abcde…");
        assert_eq!(clip("abc", 1), "a…");
        assert_eq!(clip("abc", 0), "a…");
    }

    fn kind(is_api: bool, runtime: Option<&str>) -> SiteOut {
        SiteOut {
            id: "x".to_string(),
            name: "X".to_string(),
            kind_is_api: is_api,
            active: None,
            runtime: runtime.map(str::to_string),
            state: SiteState::Serving,
            rps: 0.0,
            nodes: Vec::new(),
        }
    }

    #[test]
    fn the_kind_line_names_the_runtime_of_an_api_as_one_endpoint() {
        assert_eq!(
            site_kind_label(&kind(true, Some("rust"))),
            "Rust, one endpoint"
        );
        assert_eq!(site_kind_label(&kind(true, None)), "API");
        assert_eq!(site_kind_label(&kind(false, Some("node"))), "Node site");
        assert_eq!(site_kind_label(&kind(false, None)), "Site");
        assert_eq!(site_kind_label(&kind(false, Some(""))), "Site");
    }

    #[test]
    fn layout_puts_boxes_in_three_columns_inside_the_view_and_sizes_the_height_from_the_rows() {
        let g = two_nodes();
        let lay = layout_topology(&g);
        assert_eq!(lay.width, VIEW_WIDTH);
        assert_eq!(lay.entries.len(), 2);
        assert_eq!(lay.nodes.len(), 2);
        assert_eq!(lay.sites.len(), 2);
        assert!(lay.entries.iter().all(|b| b.x == ENTRY_COLUMN.x));
        assert!(lay.nodes.iter().all(|b| b.x == NODE_COLUMN.x));
        assert!(lay.sites.iter().all(|b| b.x == SITE_COLUMN.x));
        let boxes: Vec<(f64, f64, f64, f64)> = lay
            .entries
            .iter()
            .map(|b| (b.x, b.y, b.w, b.h))
            .chain(lay.nodes.iter().map(|b| (b.x, b.y, b.w, b.h)))
            .chain(lay.sites.iter().map(|b| (b.x, b.y, b.w, b.h)))
            .collect();
        for (x, y, w, h) in boxes {
            assert!(y >= 0.0 && y + h <= lay.height, "box inside the view");
            assert!(x + w <= lay.width);
        }
        let ys: Vec<f64> = lay.nodes.iter().map(|b| b.y).collect();
        assert!(
            ys[1] - ys[0] >= NODE_COLUMN.h,
            "boxes in a column do not overlap"
        );
        let many_sites: Vec<TopoSite> = (0..12)
            .map(|i| TopoSite {
                id: format!("s{i}"),
                name: format!("Site {i}"),
                hosts: vec![format!("h{i}.example.com")],
                ..TopoSite::default()
            })
            .collect();
        let many = build_topology(&[node("fra", true, Some(many_sites), &[])]);
        assert!(layout_topology(&many).height > lay.height);
    }

    #[test]
    fn every_link_is_a_cubic_path_from_one_box_edge_to_the_next_drawn_once() {
        let g = two_nodes();
        let lay = layout_topology(&g);
        let into: Vec<&LinkGeom> = lay
            .links
            .iter()
            .filter(|l| l.stage == LinkStage::In)
            .collect();
        let out: Vec<&LinkGeom> = lay
            .links
            .iter()
            .filter(|l| l.stage == LinkStage::Out)
            .collect();
        assert_eq!(into.len(), g.links.len());
        assert_eq!(out.len(), 3);
        let ids: HashSet<&str> = lay.links.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(ids.len(), lay.links.len());
        for l in &lay.links {
            let p = l.path;
            assert_eq!(p.c1x, round1(p.x1 + CURVE));
            assert_eq!(p.c1y, p.y1);
            assert_eq!(p.c2x, round1(p.x2 - CURVE));
            assert_eq!(p.c2y, p.y2);
        }
        let fra = lay.nodes.iter().find(|b| b.name == "fra").unwrap();
        let first_in = into.iter().find(|l| l.via == "fra").unwrap();
        assert_eq!(first_in.path.x2, fra.x);
        assert_eq!(
            first_in.path.y2,
            fra.y + fra.h / 2.0,
            "a lone link ends at the middle of the node edge"
        );
    }

    #[test]
    fn several_links_into_a_node_get_distinct_anchors() {
        let lay = layout_topology(&two_nodes());
        let nyc_ends: Vec<f64> = lay
            .links
            .iter()
            .filter(|l| l.stage == LinkStage::In && l.via == "nyc")
            .map(|l| l.path.y2)
            .collect();
        assert_eq!(nyc_ends.len(), 2);
        assert_ne!(nyc_ends[0], nyc_ends[1]);
    }

    #[test]
    fn the_busiest_link_is_marked_and_the_idle_one_is_a_thin_standby() {
        let lay = layout_topology(&two_nodes());
        let busiest: Vec<&LinkGeom> = lay.links.iter().filter(|l| l.busiest).collect();
        assert!(!busiest.is_empty());
        assert!(busiest.iter().all(|l| l.via == "nyc" && l.site_id == "api"));
        let idle = lay.links.iter().find(|l| l.id == "out:nyc>shop").unwrap();
        assert!(idle.standby);
        assert_eq!(idle.width, 1.5);
        assert_eq!(
            lay.links
                .iter()
                .find(|l| l.id == "out:nyc>api")
                .unwrap()
                .width,
            8.0
        );
    }

    #[test]
    fn with_no_traffic_nothing_is_busiest_and_every_link_is_standby() {
        let g = build_topology(&[node("fra", true, Some(vec![shop()]), &[])]);
        let lay = layout_topology(&g);
        assert!(lay.links.iter().all(|l| !l.busiest && l.standby));
    }

    #[test]
    fn the_shape_key_ignores_load_but_notices_boxes_and_links_coming_and_going() {
        let a = two_nodes();
        let b = build_topology(&[
            node("fra", true, Some(vec![shop()]), &[("shop", 5.0)]),
            node(
                "nyc",
                true,
                Some(vec![shop(), api()]),
                &[("shop", 9.0), ("api", 1.0)],
            ),
        ]);
        assert_eq!(shape_key(&a), shape_key(&b));
        let c = build_topology(&[
            node("fra", true, Some(vec![shop()]), &[]),
            node("nyc", true, Some(vec![shop()]), &[]),
        ]);
        assert_ne!(shape_key(&a), shape_key(&c));
        let offline = build_topology(&[
            node("fra", true, Some(vec![shop()]), &[]),
            node("nyc", false, Some(vec![shop(), api()]), &[]),
        ]);
        assert_ne!(shape_key(&a), shape_key(&offline));
    }
}
