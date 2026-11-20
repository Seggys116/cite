#![allow(dead_code)] // The views use these helpers.
//! Maintenance pages as one library across nodes, and the site by node maintenance matrix.
//! Each node still stores its own copy, so a node keeps serving when the console is offline.
//! These helpers only compare the copies and plan the writes. Port of the dashboard's
//! `pageslib.js`.

use std::cmp::Ordering;

use crate::targets::NodeResult;

#[derive(Clone, Debug, PartialEq)]
pub struct Page {
    pub id: String,
    pub name: String,
    pub html: String,
    pub status: u16,
}

/// The pages one node holds; `None` when the node could not be read.
#[derive(Clone, Debug, PartialEq)]
pub struct NodePages {
    pub node: String,
    pub pages: Option<Vec<Page>>,
}

/// One version of a page and the nodes that hold it.
#[derive(Clone, Debug, PartialEq)]
pub struct Variant {
    pub page: Page,
    pub nodes: Vec<String>,
}

/// One page id across nodes. `id`, `name`, `html` and `status` are the winning version.
#[derive(Clone, Debug, PartialEq)]
pub struct UnionPage {
    pub id: String,
    pub name: String,
    pub html: String,
    pub status: u16,
    /// Readable nodes that hold the page, in the order the holders were seen.
    pub nodes: Vec<String>,
    /// Readable nodes that do not hold the page.
    pub missing: Vec<String>,
    pub drift: bool,
    /// Winning version first.
    pub variants: Vec<Variant>,
}

impl UnionPage {
    fn page(&self) -> Page {
        Page {
            id: self.id.clone(),
            name: self.name.clone(),
            html: self.html.clone(),
            status: self.status,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PagesUnion {
    pub pages: Vec<UnionPage>,
    pub unreadable: Vec<String>,
    /// Readable nodes, in input order.
    pub nodes: Vec<String>,
}

/// A page to write to a node.
#[derive(Clone, Debug, PartialEq)]
pub struct PageWrite {
    pub node: String,
    pub page: Page,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncSummary {
    pub in_sync: bool,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveMethod {
    Put,
    Post,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaveStep {
    pub node: String,
    pub method: SaveMethod,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteMaint {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub page_id: Option<String>,
}

/// The sites one node holds; `sites` is `None` when the node could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSites {
    pub node: String,
    pub online: bool,
    pub sites: Option<Vec<SiteMaint>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixNode {
    pub name: String,
    pub online: bool,
    pub readable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub present: bool,
    pub enabled: bool,
    pub page_id: Option<String>,
}

impl Cell {
    fn absent() -> Self {
        Cell {
            present: false,
            enabled: false,
            page_id: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixRow {
    pub id: String,
    pub name: String,
    /// One cell per node, keyed by node name, in node order.
    pub cells: Vec<(String, Cell)>,
}

impl MatrixRow {
    pub fn cell(&self, node: &str) -> Option<&Cell> {
        self.cells.iter().find(|(n, _)| n == node).map(|(_, c)| c)
    }

    fn set_cell(&mut self, node: &str, cell: Cell) {
        match self.cells.iter_mut().find(|(n, _)| n == node) {
            Some(slot) => slot.1 = cell,
            None => self.cells.push((node.to_string(), cell)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteMatrix {
    pub nodes: Vec<MatrixNode>,
    pub rows: Vec<MatrixRow>,
}

/// Approximates `String.prototype.localeCompare`: case-insensitive first, then lowercase
/// before uppercase when the letters are otherwise equal.
fn locale_cmp(a: &str, b: &str) -> Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| b.cmp(a))
}

/// A node that could not be read is never reported as missing a page, so an outage cannot
/// trigger writes.
pub fn union_pages(per_node: &[NodePages]) -> PagesUnion {
    let readable: Vec<(&str, &[Page])> = per_node
        .iter()
        .filter_map(|n| n.pages.as_deref().map(|p| (n.node.as_str(), p)))
        .collect();
    let unreadable: Vec<String> = per_node
        .iter()
        .filter(|n| n.pages.is_none())
        .map(|n| n.node.clone())
        .collect();
    let readable_names: Vec<String> = readable.iter().map(|(n, _)| (*n).to_string()).collect();

    let mut by_id: Vec<(&str, Vec<(&str, &Page)>)> = Vec::new();
    for &(node, pages) in &readable {
        for page in pages {
            match by_id.iter_mut().find(|(id, _)| *id == page.id) {
                Some((_, holders)) => holders.push((node, page)),
                None => by_id.push((page.id.as_str(), vec![(node, page)])),
            }
        }
    }

    let first_index = |node: &str| {
        readable_names
            .iter()
            .position(|n| n == node)
            .unwrap_or(usize::MAX)
    };

    let mut pages: Vec<UnionPage> = Vec::new();
    for (id, holders) in &by_id {
        let mut variants: Vec<Variant> = Vec::new();
        for &(node, page) in holders {
            match variants.iter_mut().find(|v| v.page == *page) {
                Some(v) => v.nodes.push(node.to_string()),
                None => variants.push(Variant {
                    page: page.clone(),
                    nodes: vec![node.to_string()],
                }),
            }
        }
        // The version held by most nodes wins; a tie goes to the node listed first.
        variants.sort_by(|a, b| {
            b.nodes
                .len()
                .cmp(&a.nodes.len())
                .then_with(|| first_index(&a.nodes[0]).cmp(&first_index(&b.nodes[0])))
        });
        let Some(canonical) = variants.first() else {
            continue;
        };
        let present: Vec<String> = holders.iter().map(|(n, _)| (*n).to_string()).collect();
        let missing: Vec<String> = readable_names
            .iter()
            .filter(|n| !present.contains(n))
            .cloned()
            .collect();
        pages.push(UnionPage {
            id: (*id).to_string(),
            name: canonical.page.name.clone(),
            html: canonical.page.html.clone(),
            status: canonical.page.status,
            nodes: present,
            missing,
            drift: variants.len() > 1,
            variants,
        });
    }
    pages.sort_by(|a, b| locale_cmp(&a.name, &b.name).then_with(|| locale_cmp(&a.id, &b.id)));
    PagesUnion {
        pages,
        unreadable,
        nodes: readable_names,
    }
}

/// Pages to create so every readable node has every page.
pub fn missing_plan(union: &PagesUnion) -> Vec<PageWrite> {
    let mut plan = Vec::new();
    for page in &union.pages {
        for node in &page.missing {
            plan.push(PageWrite {
                node: node.clone(),
                page: page.page(),
            });
        }
    }
    plan
}

/// Nodes that hold a different version of a page than the winning one.
pub fn drift_plan(union: &PagesUnion) -> Vec<PageWrite> {
    let mut plan = Vec::new();
    for page in &union.pages {
        if !page.drift {
            continue;
        }
        for variant in page.variants.iter().skip(1) {
            for node in &variant.nodes {
                plan.push(PageWrite {
                    node: node.clone(),
                    page: page.page(),
                });
            }
        }
    }
    plan
}

/// One short line for the page header: in sync, or what is missing where.
pub fn sync_summary(union: &PagesUnion) -> SyncSummary {
    let missing = missing_plan(union);
    let drift = drift_plan(union);
    let mut parts: Vec<String> = Vec::new();
    if !missing.is_empty() {
        let mut per_node: Vec<(&str, usize)> = Vec::new();
        for m in &missing {
            match per_node.iter_mut().find(|(n, _)| *n == m.node) {
                Some(slot) => slot.1 += 1,
                None => per_node.push((m.node.as_str(), 1)),
            }
        }
        for (node, n) in per_node {
            parts.push(format!(
                "{node} is missing {n} page{}",
                if n == 1 { "" } else { "s" }
            ));
        }
    }
    if !drift.is_empty() {
        let n = drift.len();
        parts.push(format!(
            "{n} cop{} between nodes",
            if n == 1 { "y differs" } else { "ies differ" }
        ));
    }
    if !union.unreadable.is_empty() {
        parts.push(format!("{} could not be read", union.unreadable.join(", ")));
    }
    SyncSummary {
        in_sync: missing.is_empty() && drift.is_empty() && union.unreadable.is_empty(),
        text: if parts.is_empty() {
            "In sync on every node".to_string()
        } else {
            parts.join(". ")
        },
    }
}

/// How to write one page to the nodes that can take it: PUT where the node already holds the
/// id, POST where it does not.
pub fn save_plan(union: &PagesUnion, page_id: &str, nodes: &[String]) -> Vec<SaveStep> {
    let held: &[String] = union
        .pages
        .iter()
        .find(|p| p.id == page_id)
        .map(|p| p.nodes.as_slice())
        .unwrap_or(&[]);
    nodes
        .iter()
        .map(|node| SaveStep {
            node: node.clone(),
            method: if held.contains(node) {
                SaveMethod::Put
            } else {
                SaveMethod::Post
            },
        })
        .collect()
}

/// One line per node before a save: what the save does there, and a warning where it replaces a
/// copy that differs. `plan` is the result of `save_plan`; `name` is the name being saved.
pub fn save_confirm_lines(
    union: &PagesUnion,
    page_id: &str,
    plan: &[SaveStep],
    name: &str,
) -> Vec<String> {
    let differing: Vec<&String> = union
        .pages
        .iter()
        .find(|p| p.id == page_id)
        .map(|p| {
            p.variants
                .iter()
                .skip(1)
                .flat_map(|v| v.nodes.iter())
                .collect()
        })
        .unwrap_or_default();
    plan.iter()
        .map(|step| match step.method {
            SaveMethod::Post => format!("{}: add {name}", step.node),
            SaveMethod::Put if differing.contains(&&step.node) => format!(
                "{}: update {name} (its copy differs and will be replaced)",
                step.node
            ),
            SaveMethod::Put => format!("{}: update {name}", step.node),
        })
        .collect()
}

/// One line per node for a confirm dialog: "edge-nyc: add Scheduled, Incident; update Sale"
pub fn plan_lines(missing: &[PageWrite], drift: &[PageWrite]) -> Vec<String> {
    struct Change<'a> {
        node: &'a str,
        add: Vec<&'a str>,
        update: Vec<&'a str>,
    }
    fn note<'a>(per_node: &mut Vec<Change<'a>>, write: &'a PageWrite, add: bool) {
        let node = write.node.as_str();
        let idx = match per_node.iter().position(|c| c.node == node) {
            Some(i) => i,
            None => {
                per_node.push(Change {
                    node,
                    add: Vec::new(),
                    update: Vec::new(),
                });
                per_node.len() - 1
            }
        };
        let name = write.page.name.as_str();
        if add {
            per_node[idx].add.push(name);
        } else {
            per_node[idx].update.push(name);
        }
    }
    let mut per_node: Vec<Change> = Vec::new();
    for m in missing {
        note(&mut per_node, m, true);
    }
    for d in drift {
        note(&mut per_node, d, false);
    }
    per_node
        .iter()
        .map(|change| {
            let mut parts: Vec<String> = Vec::new();
            if !change.add.is_empty() {
                parts.push(format!("add {}", change.add.join(", ")));
            }
            if !change.update.is_empty() {
                parts.push(format!("update {}", change.update.join(", ")));
            }
            format!("{}: {}", change.node, parts.join("; "))
        })
        .collect()
}

/// A toast line for Drain or Restore on one node. Each result's `node` field holds a site id.
/// "Maintenance on for Shop, Docs on edge-nyc. Failed for Blog: <reason>"
pub fn bulk_message(state: &str, node: &str, rows: &[MatrixRow], results: &[NodeResult]) -> String {
    let name = |id: &str| -> String {
        rows.iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| id.to_string())
    };
    let mut parts: Vec<String> = Vec::new();
    let ok: Vec<String> = results
        .iter()
        .filter(|r| r.outcome.is_ok())
        .map(|r| name(&r.node))
        .collect();
    if !ok.is_empty() {
        parts.push(format!(
            "Maintenance {state} for {} on {node}",
            ok.join(", ")
        ));
    }
    for r in results {
        if let Err(reason) = &r.outcome {
            parts.push(format!("Failed for {}: {reason}", name(&r.node)));
        }
    }
    parts.join(". ")
}

/// One row per site id and one cell per node.
pub fn site_matrix(per_node: &[NodeSites]) -> SiteMatrix {
    let nodes: Vec<MatrixNode> = per_node
        .iter()
        .map(|n| MatrixNode {
            name: n.node.clone(),
            online: n.online,
            readable: n.sites.is_some(),
        })
        .collect();
    let mut rows: Vec<MatrixRow> = Vec::new();
    for entry in per_node {
        let Some(sites) = &entry.sites else {
            continue;
        };
        for site in sites {
            let idx = match rows.iter().position(|r| r.id == site.id) {
                Some(i) => i,
                None => {
                    rows.push(MatrixRow {
                        id: site.id.clone(),
                        name: site.name.clone(),
                        cells: Vec::new(),
                    });
                    rows.len() - 1
                }
            };
            rows[idx].set_cell(
                &entry.node,
                Cell {
                    present: true,
                    enabled: site.enabled,
                    page_id: site.page_id.clone().filter(|p| !p.is_empty()),
                },
            );
        }
    }
    rows.sort_by(|a, b| locale_cmp(&a.name, &b.name));
    for row in &mut rows {
        for n in &nodes {
            if row.cell(&n.name).is_none() {
                row.set_cell(&n.name, Cell::absent());
            }
        }
    }
    SiteMatrix { nodes, rows }
}

/// The page a row uses: the first one a node sets.
pub fn row_page(row: &MatrixRow) -> Option<String> {
    row.cells.iter().find_map(|(_, c)| c.page_id.clone())
}

fn rows_where(matrix: &SiteMatrix, node: &str, enabled: bool) -> Vec<String> {
    matrix
        .rows
        .iter()
        .filter(|r| {
            r.cell(node)
                .is_some_and(|c| c.present && c.enabled == enabled)
        })
        .map(|r| r.id.clone())
        .collect()
}

/// Site ids on a node that are not in maintenance yet.
pub fn drain_plan(matrix: &SiteMatrix, node: &str) -> Vec<String> {
    rows_where(matrix, node, false)
}

/// Site ids on a node that are in maintenance now.
pub fn restore_plan(matrix: &SiteMatrix, node: &str) -> Vec<String> {
    rows_where(matrix, node, true)
}

/// A node cannot serve a maintenance page it does not hold: the nodes that need the page
/// created first.
pub fn nodes_needing_page(union: &PagesUnion, page_id: &str, nodes: &[String]) -> Vec<String> {
    let Some(entry) = union.pages.iter().find(|p| p.id == page_id) else {
        return Vec::new();
    };
    nodes
        .iter()
        .filter(|n| union.nodes.contains(n) && entry.missing.contains(n))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(id: &str) -> Page {
        page_with(id, &format!("<p>{id}</p>"))
    }

    fn page_with(id: &str, html: &str) -> Page {
        Page {
            id: id.to_string(),
            name: id.to_uppercase(),
            html: html.to_string(),
            status: 503,
        }
    }

    fn np(node: &str, pages: Option<Vec<Page>>) -> NodePages {
        NodePages {
            node: node.to_string(),
            pages,
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_page_held_by_one_node_is_missing_from_the_other() {
        let u = union_pages(&[
            np("a", Some(vec![page("soon"), page("incident")])),
            np("b", Some(vec![page("soon")])),
        ]);
        assert_eq!(u.pages.len(), 2);
        let incident = u.pages.iter().find(|p| p.id == "incident").unwrap();
        assert_eq!(incident.missing, strs(&["b"]));
        let plan: Vec<(String, String)> = missing_plan(&u)
            .into_iter()
            .map(|m| (m.node, m.page.id))
            .collect();
        assert_eq!(plan, vec![("b".to_string(), "incident".to_string())]);
        assert!(!sync_summary(&u).in_sync);
        assert_eq!(sync_summary(&u).text, "b is missing 1 page");
    }

    #[test]
    fn a_node_that_could_not_be_read_is_never_reported_as_missing_pages() {
        let u = union_pages(&[np("a", Some(vec![page("soon")])), np("b", None)]);
        assert!(missing_plan(&u).is_empty());
        assert_eq!(u.unreadable, strs(&["b"]));
        assert!(!sync_summary(&u).in_sync);
    }

    #[test]
    fn differing_copies_are_drift_and_the_majority_wins() {
        let u = union_pages(&[
            np("a", Some(vec![page("soon")])),
            np("b", Some(vec![page_with("soon", "<p>old</p>")])),
            np("c", Some(vec![page("soon")])),
        ]);
        let soon = &u.pages[0];
        assert!(soon.drift);
        assert_eq!(soon.html, "<p>soon</p>");
        let nodes: Vec<String> = drift_plan(&u).into_iter().map(|d| d.node).collect();
        assert_eq!(nodes, strs(&["b"]));
    }

    #[test]
    fn a_tie_goes_to_the_node_listed_first() {
        let u = union_pages(&[
            np("a", Some(vec![page_with("soon", "A")])),
            np("b", Some(vec![page_with("soon", "B")])),
        ]);
        assert_eq!(u.pages[0].html, "A");
        let nodes: Vec<String> = drift_plan(&u).into_iter().map(|d| d.node).collect();
        assert_eq!(nodes, strs(&["b"]));
        // Listing the other node first flips the winner.
        let flipped = union_pages(&[
            np("b", Some(vec![page_with("soon", "B")])),
            np("a", Some(vec![page_with("soon", "A")])),
        ]);
        assert_eq!(flipped.pages[0].html, "B");
    }

    #[test]
    fn identical_copies_are_in_sync() {
        let u = union_pages(&[
            np("a", Some(vec![page("soon")])),
            np("b", Some(vec![page("soon")])),
        ]);
        assert_eq!(
            sync_summary(&u),
            SyncSummary {
                in_sync: true,
                text: "In sync on every node".to_string()
            }
        );
    }

    #[test]
    fn a_node_that_needs_a_page_before_maintenance_can_use_it() {
        let u = union_pages(&[np("a", Some(vec![page("soon")])), np("b", Some(vec![]))]);
        assert_eq!(
            nodes_needing_page(&u, "soon", &strs(&["a", "b"])),
            strs(&["b"])
        );
        assert_eq!(
            nodes_needing_page(&u, "nope", &strs(&["a", "b"])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn saving_a_page_puts_where_the_node_holds_it_and_posts_where_it_does_not() {
        let u = union_pages(&[np("a", Some(vec![page("soon")])), np("b", Some(vec![]))]);
        let step = |node: &str, method| SaveStep {
            node: node.to_string(),
            method,
        };
        assert_eq!(
            save_plan(&u, "soon", &strs(&["a", "b"])),
            vec![step("a", SaveMethod::Put), step("b", SaveMethod::Post)]
        );
        assert_eq!(
            save_plan(&u, "fresh", &strs(&["a", "b"])),
            vec![step("a", SaveMethod::Post), step("b", SaveMethod::Post)]
        );
    }

    #[test]
    fn save_confirm_lines_say_add_update_and_warn_where_a_differing_copy_is_replaced() {
        let u = union_pages(&[
            np("a", Some(vec![page("soon")])),
            np("b", Some(vec![page("soon")])),
            np("c", Some(vec![page_with("soon", "<p>old</p>")])),
            np("d", Some(vec![])),
        ]);
        let plan = save_plan(&u, "soon", &strs(&["a", "c", "d"]));
        assert_eq!(
            save_confirm_lines(&u, "soon", &plan, "Soon"),
            strs(&[
                "a: update Soon",
                "c: update Soon (its copy differs and will be replaced)",
                "d: add Soon",
            ])
        );
        let fresh = save_plan(&u, "new", &strs(&["a"]));
        assert_eq!(
            save_confirm_lines(&u, "new", &fresh, "New"),
            strs(&["a: add New"])
        );
    }

    #[test]
    fn plan_lines_group_additions_and_updates_per_node() {
        let u = union_pages(&[
            np(
                "a",
                Some(vec![page("soon"), page("incident"), page("sale")]),
            ),
            np("b", Some(vec![page_with("soon", "old"), page("sale")])),
            np(
                "c",
                Some(vec![page("soon"), page("incident"), page("sale")]),
            ),
        ]);
        assert_eq!(
            plan_lines(&missing_plan(&u), &drift_plan(&u)),
            strs(&["b: add INCIDENT; update SOON"])
        );
        assert_eq!(plan_lines(&[], &[]), Vec::<String>::new());
    }

    fn row(id: &str, name: &str) -> MatrixRow {
        MatrixRow {
            id: id.to_string(),
            name: name.to_string(),
            cells: Vec::new(),
        }
    }

    #[test]
    fn a_bulk_message_names_the_node_the_sites_that_changed_and_the_ones_that_failed() {
        let rows = vec![row("shop", "Storefront"), row("docs", "Docs")];
        let results = vec![
            NodeResult {
                node: "shop".to_string(),
                outcome: Ok(()),
            },
            NodeResult {
                node: "docs".to_string(),
                outcome: Err("page in use".to_string()),
            },
        ];
        assert_eq!(
            bulk_message("on", "edge-nyc", &rows, &results),
            "Maintenance on for Storefront on edge-nyc. Failed for Docs: page in use"
        );
        assert_eq!(
            bulk_message("off", "edge-nyc", &rows, &results[..1]),
            "Maintenance off for Storefront on edge-nyc"
        );
        // An id with no row is shown as the id.
        let unknown = vec![NodeResult {
            node: "ghost".to_string(),
            outcome: Err("gone".to_string()),
        }];
        assert_eq!(
            bulk_message("on", "edge-nyc", &rows, &unknown),
            "Failed for ghost: gone"
        );
    }

    fn site(id: &str, enabled: bool, page_id: Option<&str>) -> SiteMaint {
        SiteMaint {
            id: id.to_string(),
            name: id.to_string(),
            enabled,
            page_id: page_id.map(str::to_string),
        }
    }

    fn ns(node: &str, sites: Option<Vec<SiteMaint>>) -> NodeSites {
        NodeSites {
            node: node.to_string(),
            online: true,
            sites,
        }
    }

    #[test]
    fn the_matrix_has_one_row_per_site_and_a_cell_per_node() {
        let m = site_matrix(&[
            ns(
                "a",
                Some(vec![
                    site("shop", false, Some("soon")),
                    site("api", false, None),
                ]),
            ),
            ns("b", Some(vec![site("shop", true, Some("soon"))])),
        ]);
        let ids: Vec<&str> = m.rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["api", "shop"]);
        let shop = m.rows.iter().find(|r| r.id == "shop").unwrap();
        assert!(shop.cell("b").unwrap().enabled);
        assert!(!m.rows[0].cell("b").unwrap().present);
        assert_eq!(row_page(shop), Some("soon".to_string()));
    }

    #[test]
    fn the_matrix_marks_unreadable_nodes_and_leaves_their_cells_absent() {
        let m = site_matrix(&[
            ns("a", Some(vec![site("shop", false, None)])),
            ns("b", None),
        ]);
        assert!(m.nodes[0].readable);
        assert!(!m.nodes[1].readable);
        assert!(!m.rows[0].cell("b").unwrap().present);
        assert_eq!(drain_plan(&m, "b"), Vec::<String>::new());
        assert_eq!(drain_plan(&m, "nope"), Vec::<String>::new());
    }

    #[test]
    fn drain_lists_the_sites_not_yet_in_maintenance_on_that_node_only() {
        let m = site_matrix(&[
            ns(
                "a",
                Some(vec![
                    site("shop", false, None),
                    site("api", true, Some("soon")),
                ]),
            ),
            ns("b", Some(vec![site("shop", false, None)])),
        ]);
        assert_eq!(drain_plan(&m, "a"), strs(&["shop"]));
        assert_eq!(restore_plan(&m, "a"), strs(&["api"]));
        assert_eq!(drain_plan(&m, "b"), strs(&["shop"]));
    }

    #[test]
    fn an_unreadable_node_is_never_listed_as_missing_for_any_input() {
        let readable_sets: Vec<Option<Vec<Page>>> = vec![
            None,
            Some(vec![]),
            Some(vec![page("soon")]),
            Some(vec![page("soon"), page("incident")]),
            Some(vec![page_with("soon", "old")]),
        ];
        for a in &readable_sets {
            for b in &readable_sets {
                for c in &readable_sets {
                    let u =
                        union_pages(&[np("a", a.clone()), np("b", b.clone()), np("c", c.clone())]);
                    for p in &u.pages {
                        for node in &u.unreadable {
                            assert!(!p.missing.contains(node), "{node} listed as missing");
                            assert!(!p.nodes.contains(node));
                        }
                    }
                    for write in missing_plan(&u) {
                        assert!(!u.unreadable.contains(&write.node));
                    }
                    for write in drift_plan(&u) {
                        assert!(!u.unreadable.contains(&write.node));
                    }
                }
            }
        }
    }
}
