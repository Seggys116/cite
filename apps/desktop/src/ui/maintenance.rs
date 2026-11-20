use std::collections::BTreeMap;

use cite_client::ClientError;
use cite_edge::model::{MaintenancePage, Site};
use cite_edge::validate::{MAX_PAGE_BYTES, validate_page};
use gpui::{AnyElement, Context, Div, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, join_all};
use crate::app::{Confirm, Console, Load, new_input};
use crate::model::{fmt_bytes, slugify};
use crate::pages_union::{
    MatrixNode, MatrixRow, NodePages, NodeSites, Page, PageWrite, PagesUnion, SaveMethod, SaveStep,
    SiteMaint, SiteMatrix, UnionPage, bulk_message, drain_plan, drift_plan, missing_plan,
    nodes_needing_page, plan_lines, restore_plan, row_page, save_confirm_lines, save_plan,
    site_matrix, sync_summary, union_pages,
};
use crate::targets::{NodeResult, result_message};
use crate::theme::{
    BORDER, DIM, DIVIDER, FAINT, INPUT, ROW_RADIUS, TEXT, Tone, YELLOW, c, font, tint,
};
use crate::ui::firewall::{chip, reporter, run_each, settled, write_tone};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, btn, btn_off, card, empty_state, field, grid_min, id, mono, notice, page_header, pill,
    seg_item, skeleton, strong, text_dim, tip, toggle, tone_for_status,
};

// Everything the page shows, read from every node at once.
pub struct Data {
    pub union: PagesUnion,
    pub matrix: SiteMatrix,
    // Online nodes that answered badly, with the reason. Their column stays but nothing is written to them.
    pub failed: Vec<(String, String)>,
}

pub struct State {
    pub data: Load<Data>,
    pub editing: bool,
    pub saving: bool,
    pub existing: Option<String>,
    pub error: Option<String>,
    // The page picked in each site row (a site id to a page id, empty for the built-in page), used
    // the next time maintenance is turned on for that site.
    pub row_pages: BTreeMap<String, String>,
    pub name: Entity<TextInput>,
    pub page_id: Entity<TextInput>,
    pub status: Entity<TextInput>,
    pub html: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            editing: false,
            saving: false,
            existing: None,
            error: None,
            row_pages: BTreeMap::new(),
            name: new_input(cx, "Scheduled maintenance", |i| i),
            page_id: new_input(cx, "scheduled", |i| i.mono()),
            status: new_input(cx, "503", |i| i.mono()),
            html: new_input(cx, "<!doctype html>", |i| i.mono().multiline(12)),
        }
    }
}

// New pages start from a minimal valid document.
const STARTER_HTML: &str = "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>Back soon</title></head>\n<body>\n  <h1>Back soon</h1>\n  <p>We are making improvements and will be right back.</p>\n</body>\n</html>\n";

// Width of the site column; the node columns share the rest.
const SITE_COL_W: f32 = 170.0;

// Builds the page the editor describes, applying the same checks the connector will.
pub fn page_from_form(
    name: &str,
    id_text: &str,
    status: &str,
    html: &str,
) -> Result<MaintenancePage, String> {
    let code = status
        .trim()
        .parse::<u16>()
        .map_err(|_| "The status must be a number such as 503.".to_string())?;
    let page = MaintenancePage {
        id: id_text.trim().to_string(),
        name: name.trim().to_string(),
        html: html.to_string(),
        status: code,
    };
    if page.name.is_empty() {
        return Err("Give the page a name.".into());
    }
    validate_page(&page).map_err(|e| e.to_string())?;
    Ok(page)
}

// ---- Pure helpers between the wire types and the library the page works on.

fn to_page(p: &MaintenancePage) -> Page {
    Page {
        id: p.id.clone(),
        name: p.name.clone(),
        html: p.html.clone(),
        status: p.status,
    }
}

fn to_wire(p: &Page) -> MaintenancePage {
    MaintenancePage {
        id: p.id.clone(),
        name: p.name.clone(),
        html: p.html.clone(),
        status: p.status,
    }
}

fn to_site(s: &Site) -> SiteMaint {
    SiteMaint {
        id: s.id.clone(),
        name: s.name.clone(),
        enabled: s.maintenance.enabled,
        page_id: s.maintenance.page_id.clone(),
    }
}

// The winning version of a page that nodes may hold in several versions.
fn page_of(u: &UnionPage) -> Page {
    Page {
        id: u.id.clone(),
        name: u.name.clone(),
        html: u.html.clone(),
        status: u.status,
    }
}

// What one node answered while the page loaded.
struct NodeRead {
    node: String,
    online: bool,
    pages: Option<Vec<Page>>,
    sites: Option<Vec<SiteMaint>>,
    error: Option<String>,
}

impl NodeRead {
    fn lost(node: String) -> Self {
        Self {
            node,
            online: true,
            pages: None,
            sites: None,
            error: Some("the background task failed".to_string()),
        }
    }
}

// An offline node is not asked. A node that fails is passed on as unreadable, never as empty, so
// it cannot be mistaken for one that lacks pages.
async fn read_node(node: String, handle: Option<NodeHandle>) -> NodeRead {
    let Some(h) = handle else {
        return NodeRead {
            node,
            online: false,
            pages: None,
            sites: None,
            error: None,
        };
    };
    let pages = h.list_pages().await;
    let sites = h.list_sites().await;
    let error = [pages.as_ref().err(), sites.as_ref().err()]
        .into_iter()
        .flatten()
        .next()
        .map(ToString::to_string);
    NodeRead {
        node,
        online: true,
        pages: pages.ok().map(|p| p.iter().map(to_page).collect()),
        sites: sites.ok().map(|s| s.iter().map(to_site).collect()),
        error,
    }
}

fn build(reads: Vec<NodeRead>) -> Data {
    let per_pages: Vec<NodePages> = reads
        .iter()
        .map(|r| NodePages {
            node: r.node.clone(),
            pages: r.pages.clone(),
        })
        .collect();
    let per_sites: Vec<NodeSites> = reads
        .iter()
        .map(|r| NodeSites {
            node: r.node.clone(),
            online: r.online,
            sites: r.sites.clone(),
        })
        .collect();
    Data {
        union: union_pages(&per_pages),
        matrix: site_matrix(&per_sites),
        failed: reads
            .into_iter()
            .filter_map(|r| r.error.map(|e| (r.node, e)))
            .collect(),
    }
}

// A slug of the name, kept unique across the library so a new page never overwrites another.
fn fresh_page_id(name: &str, taken: &[String], suffix: &str) -> String {
    let slug = slugify(name);
    if !slug.is_empty() && !taken.contains(&slug) {
        return slug;
    }
    let short: String = slug.chars().take(33).collect();
    let base = short.trim_end_matches('-');
    let base = if base.is_empty() { "page" } else { base };
    format!("{base}-{suffix}")
}

// The page a row would serve: the one picked in the row, else the one a node already uses, and
// only when the library still holds it. An empty pick means the built-in page.
fn chosen_page(picked: Option<&str>, row: &MatrixRow, union: &PagesUnion) -> Option<String> {
    let page = match picked {
        Some(p) => Some(p.to_string()),
        None => row_page(row),
    };
    page.filter(|p| union.pages.iter().any(|u| u.id == *p))
}

// Turning maintenance on uses the chosen page; turning it off keeps the page the node had.
fn page_for_change(
    row: &MatrixRow,
    node: &str,
    on: bool,
    picked: Option<&str>,
    union: &PagesUnion,
) -> Option<String> {
    let chosen = chosen_page(picked, row, union);
    if on {
        chosen
    } else {
        row.cell(node).and_then(|c| c.page_id.clone()).or(chosen)
    }
}

// A node refuses a page it does not hold, so these pages are created on it first, once each.
fn pages_to_create(union: &PagesUnion, node: &str, wanted: &[String]) -> Vec<Page> {
    let mut out: Vec<Page> = Vec::new();
    for page_id in wanted {
        if out.iter().any(|p| p.id == *page_id) {
            continue;
        }
        if nodes_needing_page(union, page_id, &[node.to_string()]).is_empty() {
            continue;
        }
        if let Some(u) = union.pages.iter().find(|u| u.id == *page_id) {
            out.push(page_of(u));
        }
    }
    out
}

// The toast for one switch: names the site and the node, and says why it failed when it did.
fn flip_message(on: bool, site: &str, node: &str, outcome: &Result<(), String>) -> (String, Tone) {
    let state = if on { "on" } else { "off" };
    match outcome {
        Ok(()) => (
            format!("Maintenance {state} for {site} on {node}"),
            Tone::Ok,
        ),
        Err(e) => (
            format!("Could not turn maintenance {state} for {site} on {node}: {e}"),
            Tone::Bad,
        ),
    }
}

// Per node, the pages to write: create what is missing, overwrite what differs.
fn line_up_work(
    missing: &[PageWrite],
    drift: &[PageWrite],
) -> Vec<(String, Vec<(Page, SaveMethod)>)> {
    let mut work: Vec<(String, Vec<(Page, SaveMethod)>)> = Vec::new();
    let all = missing
        .iter()
        .map(|w| (w, SaveMethod::Post))
        .chain(drift.iter().map(|w| (w, SaveMethod::Put)));
    for (write, method) in all {
        let slot = match work.iter().position(|(n, _)| *n == write.node) {
            Some(i) => i,
            None => {
                work.push((write.node.clone(), Vec::new()));
                work.len() - 1
            }
        };
        work[slot].1.push((write.page.clone(), method));
    }
    work
}

// The toast for a page save: what was written, then the nodes that were left out.
fn save_message(results: &[NodeResult], skipped: &[String]) -> String {
    let mut parts = Vec::new();
    let written = result_message("Saved", results);
    if !written.is_empty() {
        parts.push(written);
    }
    if !skipped.is_empty() {
        parts.push(format!("Not updated: {}", skipped.join(", ")));
    }
    parts.join(". ")
}

// A page save that has been checked and is ready to send.
struct SaveWrite {
    page: MaintenancePage,
    plan: Vec<SaveStep>,
    targets: Vec<String>,
    skipped: Vec<String>,
}

// What to confirm before a save, as (title, message, label), or None when nothing needs asking.
// A new page gets one line. An edit that reaches several nodes, or replaces a copy that differs,
// lists every change first.
fn save_confirm(
    existing: bool,
    union: &PagesUnion,
    page_id: &str,
    name: &str,
    plan: &[SaveStep],
) -> Option<(String, String, String)> {
    let count = format!(
        "{} node{}",
        plan.len(),
        if plan.len() == 1 { "" } else { "s" }
    );
    if !existing {
        let nodes: Vec<&str> = plan.iter().map(|s| s.node.as_str()).collect();
        return Some((
            "Create page".to_string(),
            format!("Create {name} on {}.", nodes.join(", ")),
            format!("Create on {count}"),
        ));
    }
    let drift = union.pages.iter().any(|p| p.id == page_id && p.drift);
    if !drift && plan.len() <= 1 {
        return None;
    }
    Some((
        "Save page".to_string(),
        save_confirm_lines(union, page_id, plan, name).join("\n"),
        format!("Save on {count}"),
    ))
}

// ---- Writes that run on the network runtime.

async fn save_one(
    h: NodeHandle,
    page: MaintenancePage,
    method: Option<SaveMethod>,
) -> Result<(), String> {
    match method {
        Some(SaveMethod::Put) => settled(h.update_page(&page.id, &page).await),
        Some(SaveMethod::Post) => settled(h.create_page(&page).await),
        None => Err("no way to save the page here".to_string()),
    }
}

// Writes each page in turn; a failure is kept and the rest still go.
async fn line_up_node(h: NodeHandle, writes: Vec<(Page, SaveMethod)>) -> Result<(), String> {
    let mut failed = Vec::new();
    for (page, method) in writes {
        if let Err(e) = save_one(h.clone(), to_wire(&page), Some(method)).await {
            failed.push(format!("{} ({e})", page.name));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join(", "))
    }
}

// Sets maintenance for sites on one node. Pages the node lacks are created first, once each, and a
// site whose page could not be created fails with that reason instead of being sent to a node that
// would refuse it. Each result is keyed by site id.
async fn set_maintenance(
    h: NodeHandle,
    create: Vec<Page>,
    jobs: Vec<(String, Option<String>)>,
    on: bool,
) -> Vec<NodeResult> {
    let mut refused: Vec<(String, String)> = Vec::new();
    for page in &create {
        if let Err(e) = h.create_page(&to_wire(page)).await {
            refused.push((page.id.clone(), e.to_string()));
        }
    }
    let sites: Vec<String> = jobs.iter().map(|(site, _)| site.clone()).collect();
    run_each(sites, move |site: String| {
        let page = jobs
            .iter()
            .find(|(s, _)| *s == site)
            .and_then(|(_, p)| p.clone());
        let refusal = page
            .as_ref()
            .and_then(|p| refused.iter().find(|(id, _)| id == p))
            .map(|(_, why)| format!("could not create the page: {why}"));
        let h = h.clone();
        async move {
            if let Some(why) = refusal {
                return Err(why);
            }
            settled(h.maintenance(&site, on, page.as_deref()).await)
        }
    })
    .await
}

impl Console {
    // Every configured node is read, whichever one is selected, so the matrix always shows them all.
    pub fn load_maintenance(&mut self, cx: &mut Context<Self>) {
        if self.handles.is_empty() {
            self.maintenance.data = Load::Idle;
            return;
        }
        // The data does not depend on the selected node, so a refresh keeps the page on screen.
        if !matches!(self.maintenance.data, Load::Ready(_)) {
            self.maintenance.data = Load::Loading;
        }
        let jobs: Vec<(String, Option<NodeHandle>)> = self
            .node_infos()
            .into_iter()
            .map(|n| {
                let handle = if n.online {
                    self.handle_named(&n.name)
                } else {
                    None
                };
                (n.name, handle)
            })
            .collect();
        let fut = async move {
            let names: Vec<String> = jobs.iter().map(|(n, _)| n.clone()).collect();
            let done = join_all(jobs.into_iter().map(|(n, h)| read_node(n, h)).collect()).await;
            let reads = names
                .into_iter()
                .zip(done)
                .map(|(node, read)| read.unwrap_or_else(|| NodeRead::lost(node)))
                .collect();
            Ok::<_, ClientError>(build(reads))
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.maintenance.data = Load::from_result(res);
            cx.notify();
        });
    }

    fn open_editor(&mut self, page: Option<&Page>, cx: &mut Context<Self>) {
        let m = &self.maintenance;
        let (name, pid, status, html) = match page {
            Some(p) => (
                p.name.clone(),
                p.id.clone(),
                p.status.to_string(),
                p.html.clone(),
            ),
            None => (
                String::new(),
                String::new(),
                "503".into(),
                STARTER_HTML.to_string(),
            ),
        };
        m.name.update(cx, |i, cx| i.set_text(&name, cx));
        m.page_id.update(cx, |i, cx| i.set_text(&pid, cx));
        m.status.update(cx, |i, cx| i.set_text(&status, cx));
        m.html.update(cx, |i, cx| i.set_text(&html, cx));
        self.maintenance.existing = page.map(|p| p.id.clone());
        self.maintenance.editing = true;
        self.maintenance.error = None;
    }

    // A short random tail keeps generated page ids unique.
    fn page_suffix() -> String {
        cite_client::fsio::new_id()
            .chars()
            .rev()
            .filter(char::is_ascii_alphanumeric)
            .take(6)
            .collect::<String>()
            .to_lowercase()
    }

    // The page is written to every online node: PUT where the node holds it, POST where it does
    // not. Nodes that could not be read are named in the toast as not updated.
    fn save_page(&mut self, cx: &mut Context<Self>) {
        let m = &self.maintenance;
        let name = m.name.read(cx).text().to_string();
        let typed_id = m.page_id.read(cx).text().trim().to_string();
        let status = m.status.read(cx).text().to_string();
        let html = m.html.read(cx).text().to_string();
        let existing = m.existing.clone();
        let Some(data) = m.data.ready() else {
            self.maintenance.error =
                Some("The nodes are still loading. Try again in a moment.".into());
            return;
        };
        let taken: Vec<String> = data.union.pages.iter().map(|p| p.id.clone()).collect();
        let targets = data.union.nodes.clone();
        let page_id = match (&existing, typed_id.is_empty()) {
            (Some(old), _) => old.clone(),
            (None, true) => fresh_page_id(&name, &taken, &Self::page_suffix()),
            (None, false) => typed_id,
        };
        let plan = save_plan(&data.union, &page_id, &targets);
        let confirm = save_confirm(
            existing.is_some(),
            &data.union,
            &page_id,
            name.trim(),
            &plan,
        );
        let skipped: Vec<String> = self
            .node_infos()
            .into_iter()
            .map(|n| n.name)
            .filter(|n| !targets.contains(n))
            .collect();
        if existing.is_none() && taken.contains(&page_id) {
            self.maintenance.error = Some(format!(
                "A page with the id {page_id} already exists. Pick another id."
            ));
            return;
        }
        let page = match page_from_form(&name, &page_id, &status, &html) {
            Ok(page) => page,
            Err(e) => {
                self.maintenance.error = Some(e);
                return;
            }
        };
        if targets.is_empty() {
            self.maintenance.error = Some("No node is online to save to.".into());
            return;
        }
        self.maintenance.error = None;
        let write = SaveWrite {
            page,
            plan,
            targets,
            skipped,
        };
        match confirm {
            // Cancelling leaves the editor and its text as they are.
            Some((title, message, label)) => self.ask(Confirm {
                title,
                message,
                label,
                danger: false,
                action: Box::new(move |this, cx| this.write_page(write, cx)),
            }),
            None => self.write_page(write, cx),
        }
    }

    // Sends the page to the planned nodes and reports each one.
    fn write_page(&mut self, write: SaveWrite, cx: &mut Context<Self>) {
        let SaveWrite {
            page,
            plan,
            targets,
            skipped,
        } = write;
        self.maintenance.saving = true;
        let methods: Vec<(String, SaveMethod)> =
            plan.into_iter().map(|s| (s.node, s.method)).collect();
        self.fan_out(
            cx,
            targets,
            move |h| {
                let method = methods.iter().find(|(n, _)| n == h.name()).map(|(_, m)| *m);
                save_one(h, page.clone(), method)
            },
            move |this, cx, results| {
                this.maintenance.saving = false;
                let message = save_message(&results, &skipped);
                if !results.iter().any(|r| r.outcome.is_ok()) {
                    this.maintenance.error = Some(if results.is_empty() {
                        "Nothing was saved.".to_string()
                    } else {
                        message
                    });
                    return;
                }
                this.maintenance.editing = false;
                // Every written node took it but some were left out: worth noticing, not an error.
                let tone = match write_tone(&results) {
                    Tone::Ok if !skipped.is_empty() => Tone::Info,
                    other => other,
                };
                this.report_writes(cx, message, tone);
            },
        );
    }

    // Deleting asks which of the nodes that hold the page lose it.
    fn delete_page(&mut self, page: &UnionPage) {
        let (page_id, name) = (page.id.clone(), page.name.clone());
        self.pick_nodes(
            "Delete page".to_string(),
            format!("Delete {name} from the nodes you pick."),
            "Delete page",
            &page.nodes,
            true,
            move |this, cx, nodes| {
                this.fan_out(
                    cx,
                    nodes,
                    move |h| {
                        let page_id = page_id.clone();
                        async move { settled(h.delete_page(&page_id).await) }
                    },
                    reporter(format!("Deleted {name}")),
                );
            },
        );
    }

    // Creates the missing pages and overwrites the copies that differ, after listing every change.
    fn bring_in_line(&mut self) {
        let Some(data) = self.maintenance.data.ready() else {
            return;
        };
        let (missing, drift) = (missing_plan(&data.union), drift_plan(&data.union));
        if missing.is_empty() && drift.is_empty() {
            return;
        }
        let message = plan_lines(&missing, &drift).join("\n");
        let work = line_up_work(&missing, &drift);
        self.ask(Confirm {
            title: "Bring nodes in line".into(),
            message,
            label: "Apply changes".into(),
            danger: false,
            action: Box::new(move |this, cx| {
                let nodes: Vec<String> = work.iter().map(|(n, _)| n.clone()).collect();
                this.fan_out(
                    cx,
                    nodes,
                    move |h| {
                        let writes = work
                            .iter()
                            .find(|(n, _)| n == h.name())
                            .map(|(_, w)| w.clone())
                            .unwrap_or_default();
                        line_up_node(h, writes)
                    },
                    reporter("Updated".to_string()),
                );
            }),
        });
    }

    // One switch: maintenance for one site on one node, and no other node.
    fn flip_maintenance(&mut self, site: &str, node: &str, on: bool, cx: &mut Context<Self>) {
        let Some(data) = self.maintenance.data.ready() else {
            return;
        };
        let Some(row) = data.matrix.rows.iter().find(|r| r.id == site) else {
            return;
        };
        let picked = self.maintenance.row_pages.get(site).map(String::as_str);
        let page = page_for_change(row, node, on, picked, &data.union);
        let wanted: Vec<String> = page.iter().cloned().collect();
        let create = if on {
            pages_to_create(&data.union, node, &wanted)
        } else {
            Vec::new()
        };
        let site_name = row.name.clone();
        let Some(handle) = self.handle_named(node) else {
            self.say(format!("{node} is not connected"), Tone::Bad);
            return;
        };
        let node = node.to_string();
        let work = set_maintenance(handle, create, vec![(site.to_string(), page)], on);
        self.settle(cx, work, move |this, cx, results| {
            let (text, tone) = results.first().map_or((String::new(), Tone::Bad), |r| {
                flip_message(on, &site_name, &node, &r.outcome)
            });
            this.report_writes(cx, text, tone);
        });
    }

    // Drain puts every site on the node into maintenance, Restore takes them out; both ask first.
    fn bulk_maintenance(&mut self, node: &str, drain: bool) {
        let Some(data) = self.maintenance.data.ready() else {
            return;
        };
        let ids = if drain {
            drain_plan(&data.matrix, node)
        } else {
            restore_plan(&data.matrix, node)
        };
        let rows: Vec<MatrixRow> = data
            .matrix
            .rows
            .iter()
            .filter(|r| ids.contains(&r.id))
            .cloned()
            .collect();
        if rows.is_empty() {
            return;
        }
        let jobs: Vec<(String, Option<String>)> = rows
            .iter()
            .map(|r| {
                let picked = self.maintenance.row_pages.get(&r.id).map(String::as_str);
                (
                    r.id.clone(),
                    page_for_change(r, node, drain, picked, &data.union),
                )
            })
            .collect();
        let create = if drain {
            let wanted: Vec<String> = jobs.iter().filter_map(|(_, p)| p.clone()).collect();
            pages_to_create(&data.union, node, &wanted)
        } else {
            Vec::new()
        };
        let names = rows
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let (title, message) = if drain {
            (
                format!("Drain {node}"),
                format!("Puts {names} into maintenance on {node}. Other nodes keep serving."),
            )
        } else {
            (
                format!("Restore {node}"),
                format!("Takes {names} out of maintenance on {node}."),
            )
        };
        let node = node.to_string();
        self.ask(Confirm {
            label: title.clone(),
            title,
            message,
            danger: drain,
            action: Box::new(move |this, cx| {
                let Some(handle) = this.handle_named(&node) else {
                    this.say(format!("{node} is not connected"), Tone::Bad);
                    return;
                };
                let state = if drain { "on" } else { "off" };
                let work = set_maintenance(handle, create, jobs, drain);
                this.settle(cx, work, move |this, cx, results| {
                    let message = bulk_message(state, &node, &rows, &results);
                    this.report_writes(cx, message, write_tone(&results));
                });
            }),
        });
    }

    pub fn render_maintenance(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let new = btn(id("mt", "new"), "New page", BtnKind::Primary).on_click(cx.listener(
            |this, _, _, cx| {
                this.open_editor(None, cx);
                cx.notify();
            },
        ));
        let mut col = div().flex().flex_col().gap(px(16.)).child(page_header(
            "Maintenance",
            "One set of pages for every node",
            vec![new.into_any_element()],
        ));
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        if self.maintenance.editing {
            col = col.child(self.editor_card(cx));
        }
        match &self.maintenance.data {
            Load::Idle | Load::Loading => col = col.child(skeleton(180.)),
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                if !data.failed.is_empty() {
                    let note = data
                        .failed
                        .iter()
                        .map(|(node, why)| format!("Could not read {node}: {why}"))
                        .collect::<Vec<_>>()
                        .join(". ");
                    col = col.child(notice(&note, Tone::Warn));
                }
                col = col
                    .child(self.library_card(data, cx))
                    .child(self.matrix_card(data, cx));
            }
        }
        col.into_any_element()
    }

    fn editor_card(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let m = &self.maintenance;
        let size = m.html.read(cx).text().len();
        let id_hint = if m.existing.is_some() {
            "Fixed once saved"
        } else {
            "Defaults to the name"
        };
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex().flex_col().flex_1().child(field(
                        "Name",
                        None,
                        m.name.clone(),
                    )))
                    .child(div().flex().flex_col().w(px(200.)).child(field(
                        "Id",
                        Some(id_hint),
                        m.page_id.clone(),
                    )))
                    .child(div().flex().flex_col().w(px(100.)).child(field(
                        "Status",
                        None,
                        m.status.clone(),
                    ))),
            )
            .child(field(
                "HTML",
                Some(&format!(
                    "{} of {} used. Served exactly as written.",
                    fmt_bytes(size as u64),
                    fmt_bytes(MAX_PAGE_BYTES as u64)
                )),
                m.html.clone(),
            ));
        if let Some(err) = &m.error {
            form = form.child(notice(err, Tone::Bad));
        }
        form =
            form.child(
                div()
                    .flex()
                    .gap(px(8.))
                    .child(
                        btn(id("mt", "save"), "Save page", BtnKind::Primary).on_click(cx.listener(
                            |this, _, _, cx| {
                                if !this.maintenance.saving {
                                    this.save_page(cx);
                                }
                                cx.notify();
                            },
                        )),
                    )
                    .child(btn(id("mt", "cancel"), "Cancel", BtnKind::Plain).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.maintenance.editing = false;
                            cx.notify();
                        }),
                    )),
            );
        let title = if self.maintenance.existing.is_some() {
            "Edit page"
        } else {
            "New maintenance page"
        };
        card(Some(title), Some("Saved to every online node."), form).into_any_element()
    }

    // One card per page id, with a chip for each node that holds it.
    fn library_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let sync = sync_summary(&data.union);
        let pending = !missing_plan(&data.union).is_empty() || !drift_plan(&data.union).is_empty();
        let mut body = div().flex().flex_col().gap(px(12.));
        if pending {
            body = body.child(div().flex().child(
                btn(id("mt", "align"), "Bring nodes in line", BtnKind::Plain).on_click(
                    cx.listener(|this, _, _, cx| {
                        this.bring_in_line();
                        cx.notify();
                    }),
                ),
            ));
        }
        if data.union.pages.is_empty() {
            body = body.child(empty_state(
                "No maintenance pages",
                "Create a page to show visitors during maintenance.",
            ));
        } else {
            let cards = data
                .union
                .pages
                .iter()
                .map(|p| self.page_card(p, cx))
                .collect();
            body = body.child(grid_min(300., cards));
        }
        card(Some("Pages"), Some(sync.text.as_str()), body).into_any_element()
    }

    fn page_card(&self, page: &UnionPage, cx: &mut Context<Self>) -> AnyElement {
        let differing: Vec<&String> = page
            .variants
            .iter()
            .skip(1)
            .flat_map(|v| v.nodes.iter())
            .collect();
        let mut chips = div().flex().flex_wrap().gap(px(4.));
        for node in &page.nodes {
            chips = if differing.contains(&node) {
                chips.child(tip(
                    chip(node, YELLOW),
                    id("mt-differs", format!("{}-{node}", page.id)),
                    format!("{node} holds a different version"),
                ))
            } else {
                chips.child(chip(node, TEXT))
            };
        }
        for node in &page.missing {
            chips = chips.child(chip(&format!("missing on {node}"), FAINT));
        }
        let mut head = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(6.))
            .child(strong(page.name.clone()))
            .child(pill(&page.status.to_string(), tone_for_status(page.status)));
        if page.drift {
            head = head.child(pill("differs", Tone::Warn));
        }
        let (edit_page, del_page) = (page_of(page), page.clone());
        let edit = btn(id("page-edit", &page.id), "Edit", BtnKind::Plain).on_click(cx.listener(
            move |this, _, _, cx| {
                this.open_editor(Some(&edit_page), cx);
                cx.notify();
            },
        ));
        let del = btn(id("page-del", &page.id), "Delete", BtnKind::Danger).on_click(cx.listener(
            move |this, _, _, cx| {
                this.delete_page(&del_page);
                cx.notify();
            },
        ));
        div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .p(px(12.))
            .rounded(px(crate::theme::CARD_RADIUS))
            .border_1()
            .border_color(c(BORDER))
            .child(head)
            .child(mono(page.id.clone()).text_color(c(DIM)))
            .child(chips)
            .child(div().flex().gap(px(6.)).child(edit).child(del))
            .into_any_element()
    }

    // A row per site and a column per node. The selected node's column is highlighted, not filtered.
    fn matrix_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let matrix = &data.matrix;
        if matrix.rows.is_empty() {
            return card(
                Some("Sites by node"),
                Some("Maintenance is set per node."),
                empty_state("No sites yet", "Sites appear here once a node has them."),
            )
            .into_any_element();
        }
        let mut head = div().flex().items_start().gap(px(4.)).child(
            div()
                .flex_none()
                .w(px(SITE_COL_W))
                .px(px(8.))
                .child(strong("Site").text_size(px(font::SM)).text_color(c(DIM))),
        );
        for node in &matrix.nodes {
            head = head.child(self.node_header(node, matrix, cx));
        }
        let mut body = div().flex().flex_col().child(head);
        for row in &matrix.rows {
            let mut line = div().flex().items_center().gap(px(4.)).child(
                div()
                    .flex()
                    .flex_col()
                    .flex_none()
                    .w(px(SITE_COL_W))
                    .min_w_0()
                    .px(px(8.))
                    .child(strong(row.name.clone()))
                    .child(mono(row.id.clone()).text_color(c(DIM))),
            );
            for node in &matrix.nodes {
                line = line.child(self.matrix_cell(row, node, cx));
            }
            body = body.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .py(px(8.))
                    .border_t_1()
                    .border_color(c(DIVIDER))
                    .child(line)
                    .child(self.page_chooser(row, data, cx)),
            );
        }
        card(
            Some("Sites by node"),
            Some("Maintenance is set per node."),
            body,
        )
        .into_any_element()
    }

    fn is_current(&self, node: &str) -> bool {
        self.selected.as_deref() == Some(node)
    }

    // A node column: the same width in the header and in every row, tinted when it is the selected node.
    fn node_column(&self, node: &str, child: impl IntoElement) -> AnyElement {
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w(px(130.))
            .gap(px(6.))
            .px(px(8.))
            .py(px(6.))
            .rounded(px(ROW_RADIUS))
            .when(self.is_current(node), |d| d.bg(tint(0xffffff, 0.04)))
            .child(child)
            .into_any_element()
    }

    fn node_header(
        &self,
        node: &MatrixNode,
        matrix: &SiteMatrix,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let usable = node.online && node.readable;
        let can_drain = usable && !drain_plan(matrix, &node.name).is_empty();
        let can_restore = usable && !restore_plan(matrix, &node.name).is_empty();
        let mut title = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(6.))
            .child(mono(node.name.clone()).font_weight(gpui::FontWeight::SEMIBOLD));
        if !node.online {
            title = title.child(pill("Offline", Tone::Warn));
        } else if !node.readable {
            title = title.child(pill("Unreadable", Tone::Warn));
        }
        let mut actions = div().flex().flex_wrap().gap(px(6.));
        actions = actions.child(if can_drain {
            let name = node.name.clone();
            btn(id("mt-drain", &node.name), "Drain", BtnKind::Plain)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.bulk_maintenance(&name, true);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Drain").into_any_element()
        });
        if can_restore {
            let name = node.name.clone();
            actions = actions.child(
                btn(id("mt-restore", &node.name), "Restore", BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.bulk_maintenance(&name, false);
                        cx.notify();
                    },
                )),
            );
        }
        self.node_column(
            &node.name,
            div()
                .flex()
                .flex_col()
                .gap(px(6.))
                .child(title)
                .child(actions),
        )
    }

    fn matrix_cell(
        &self,
        row: &MatrixRow,
        node: &MatrixNode,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let key = format!("{}-{}", row.id, node.name);
        let body: AnyElement = match row.cell(&node.name).filter(|cell| cell.present) {
            None => {
                let why = if !node.online {
                    format!("{} is offline", node.name)
                } else if node.readable {
                    format!("Not on {}", node.name)
                } else {
                    format!("{} could not be read", node.name)
                };
                tip(text_dim("-"), id("mt-dash", &key), why).into_any_element()
            }
            Some(cell) => {
                let (site, name, on) = (row.id.clone(), node.name.clone(), cell.enabled);
                let sw =
                    toggle(id("mt-on", &key), on).on_click(cx.listener(move |this, _, _, cx| {
                        this.flip_maintenance(&site, &name, !on, cx);
                        cx.notify();
                    }));
                let label = if on {
                    div()
                        .flex()
                        .flex_col()
                        .text_size(px(font::SM))
                        .text_color(c(YELLOW))
                        .child("Maintenance")
                } else {
                    text_dim("Live").text_size(px(font::SM))
                };
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(sw)
                    .child(label)
                    .into_any_element()
            }
        };
        self.node_column(&node.name, body)
    }

    // The page a site serves the next time maintenance is turned on for it.
    fn page_chooser(&self, row: &MatrixRow, data: &Data, cx: &mut Context<Self>) -> Div {
        let picked = self.maintenance.row_pages.get(&row.id).map(String::as_str);
        let chosen = chosen_page(picked, row, &data.union);
        let mut options = vec![(String::new(), "Built-in".to_string())];
        options.extend(
            data.union
                .pages
                .iter()
                .map(|p| (p.id.clone(), p.name.clone())),
        );
        let mut items = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(2.))
            .p(px(2.))
            .rounded(px(ROW_RADIUS))
            .border_1()
            .border_color(c(BORDER))
            .bg(c(INPUT));
        for (page_id, label) in options {
            let active = chosen.as_deref().unwrap_or("") == page_id;
            let site = row.id.clone();
            let pick = page_id.clone();
            items = items.child(
                seg_item(
                    id("mt-page", format!("{}-{}", row.id, page_id)),
                    &label,
                    active,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.maintenance
                        .row_pages
                        .insert(site.clone(), pick.clone());
                    cx.notify();
                })),
            );
        }
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .px(px(8.))
            .child(text_dim("Page when on").text_size(px(font::SM)))
            .child(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(id: &str, html: &str) -> Page {
        Page {
            id: id.to_string(),
            name: id.to_uppercase(),
            html: html.to_string(),
            status: 503,
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn read(node: &str, online: bool, pages: Option<Vec<Page>>, error: Option<&str>) -> NodeRead {
        NodeRead {
            node: node.to_string(),
            online,
            pages,
            sites: Some(Vec::new()),
            error: error.map(str::to_string),
        }
    }

    #[test]
    fn an_unreadable_node_is_named_and_never_planned_for() {
        let data = build(vec![
            read("a", true, Some(vec![page("soon", "x")]), None),
            read("b", true, None, Some("node unreachable: refused")),
            read("c", false, None, None),
        ]);
        assert_eq!(
            data.failed,
            vec![("b".to_string(), "node unreachable: refused".to_string())]
        );
        assert_eq!(data.union.unreadable, strs(&["b", "c"]));
        assert!(missing_plan(&data.union).is_empty());
        assert_eq!(data.matrix.nodes.len(), 3);
        assert!(!data.matrix.nodes[2].online);
    }

    #[test]
    fn a_generated_page_id_stays_unique_and_valid() {
        assert_eq!(fresh_page_id("Back soon", &[], "abc123"), "back-soon");
        assert_eq!(
            fresh_page_id("Back soon", &strs(&["back-soon"]), "abc123"),
            "back-soon-abc123"
        );
        assert_eq!(fresh_page_id("!!!", &[], "abc123"), "page-abc123");
        let long = "x".repeat(60);
        let id = fresh_page_id(&long, &[slugify(&long)], "abc123");
        assert!(id.len() <= 40, "{id}");
        assert!(cite_edge::validate::is_valid_id(&id), "{id}");
    }

    fn matrix_row() -> (MatrixRow, PagesUnion) {
        let union = union_pages(&[
            NodePages {
                node: "a".to_string(),
                pages: Some(vec![page("soon", "x"), page("sale", "y")]),
            },
            NodePages {
                node: "b".to_string(),
                pages: Some(vec![page("sale", "y")]),
            },
        ]);
        let site = |enabled, page_id: Option<&str>| SiteMaint {
            id: "shop".to_string(),
            name: "Shop".to_string(),
            enabled,
            page_id: page_id.map(str::to_string),
        };
        let matrix = site_matrix(&[
            NodeSites {
                node: "a".to_string(),
                online: true,
                sites: Some(vec![site(true, Some("soon"))]),
            },
            NodeSites {
                node: "b".to_string(),
                online: true,
                sites: Some(vec![site(false, None)]),
            },
        ]);
        (matrix.rows[0].clone(), union)
    }

    #[test]
    fn the_chosen_page_is_the_pick_then_the_one_in_use_and_must_exist() {
        let (row, union) = matrix_row();
        assert_eq!(chosen_page(None, &row, &union), Some("soon".to_string()));
        assert_eq!(
            chosen_page(Some("sale"), &row, &union),
            Some("sale".to_string())
        );
        assert_eq!(chosen_page(Some(""), &row, &union), None);
        assert_eq!(chosen_page(Some("gone"), &row, &union), None);
    }

    #[test]
    fn turning_off_keeps_the_page_the_node_had() {
        let (row, union) = matrix_row();
        assert_eq!(
            page_for_change(&row, "a", true, Some("sale"), &union),
            Some("sale".to_string())
        );
        assert_eq!(
            page_for_change(&row, "a", false, Some("sale"), &union),
            Some("soon".to_string())
        );
        assert_eq!(
            page_for_change(&row, "b", false, Some("sale"), &union),
            Some("sale".to_string())
        );
    }

    #[test]
    fn a_page_is_created_on_a_node_that_lacks_it_once() {
        let (_, union) = matrix_row();
        let wanted = strs(&["soon", "soon", "sale"]);
        let create = pages_to_create(&union, "b", &wanted);
        let ids: Vec<&str> = create.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["soon"]);
        assert!(pages_to_create(&union, "a", &wanted).is_empty());
        assert!(pages_to_create(&union, "ghost", &wanted).is_empty());
    }

    #[test]
    fn a_switch_toast_names_the_site_and_the_node() {
        assert_eq!(
            flip_message(true, "Shop", "edge-nyc", &Ok(())),
            ("Maintenance on for Shop on edge-nyc".to_string(), Tone::Ok)
        );
        assert_eq!(
            flip_message(false, "Shop", "edge-nyc", &Err("refused".to_string())),
            (
                "Could not turn maintenance off for Shop on edge-nyc: refused".to_string(),
                Tone::Bad
            )
        );
    }

    #[test]
    fn bringing_nodes_in_line_creates_missing_pages_and_overwrites_drift() {
        let union = union_pages(&[
            NodePages {
                node: "a".to_string(),
                pages: Some(vec![page("soon", "x"), page("sale", "y")]),
            },
            NodePages {
                node: "b".to_string(),
                pages: Some(vec![page("sale", "old")]),
            },
            NodePages {
                node: "c".to_string(),
                pages: Some(vec![page("soon", "x"), page("sale", "y")]),
            },
        ]);
        let work = line_up_work(&missing_plan(&union), &drift_plan(&union));
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].0, "b");
        let steps: Vec<(&str, SaveMethod)> =
            work[0].1.iter().map(|(p, m)| (p.id.as_str(), *m)).collect();
        assert_eq!(
            steps,
            [("soon", SaveMethod::Post), ("sale", SaveMethod::Put)]
        );
    }

    #[test]
    fn a_save_toast_names_what_was_written_and_what_was_left_out() {
        let ok = NodeResult {
            node: "a".to_string(),
            outcome: Ok(()),
        };
        assert_eq!(save_message(std::slice::from_ref(&ok), &[]), "Saved on a");
        assert_eq!(
            save_message(&[ok], &strs(&["b", "c"])),
            "Saved on a. Not updated: b, c"
        );
        assert_eq!(save_message(&[], &strs(&["b"])), "Not updated: b");
    }

    fn union_of(copies: &[(&str, &str)]) -> PagesUnion {
        let per_node: Vec<NodePages> = copies
            .iter()
            .map(|(node, html)| NodePages {
                node: node.to_string(),
                pages: Some(vec![page("soon", html)]),
            })
            .collect();
        union_pages(&per_node)
    }

    #[test]
    fn a_single_node_edit_without_drift_needs_no_confirm() {
        let union = union_of(&[("a", "x")]);
        let plan = save_plan(&union, "soon", &strs(&["a"]));
        assert_eq!(save_confirm(true, &union, "soon", "Soon", &plan), None);
    }

    #[test]
    fn an_edit_reaching_several_nodes_lists_every_change() {
        let union = union_of(&[("a", "x"), ("b", "x")]);
        let plan = save_plan(&union, "soon", &strs(&["a", "b", "c"]));
        assert_eq!(
            save_confirm(true, &union, "soon", "Soon", &plan),
            Some((
                "Save page".to_string(),
                "a: update Soon\nb: update Soon\nc: add Soon".to_string(),
                "Save on 3 nodes".to_string()
            ))
        );
    }

    #[test]
    fn replacing_a_differing_copy_is_confirmed_even_on_one_node() {
        let union = union_of(&[("a", "x"), ("b", "x"), ("c", "old")]);
        let plan = save_plan(&union, "soon", &strs(&["c"]));
        assert_eq!(
            save_confirm(true, &union, "soon", "Soon", &plan),
            Some((
                "Save page".to_string(),
                "c: update Soon (its copy differs and will be replaced)".to_string(),
                "Save on 1 node".to_string()
            ))
        );
    }

    #[test]
    fn a_new_page_is_confirmed_in_one_line() {
        let union = union_of(&[("a", "x")]);
        let plan = save_plan(&union, "fresh", &strs(&["a", "b"]));
        assert_eq!(
            save_confirm(false, &union, "fresh", "Fresh", &plan),
            Some((
                "Create page".to_string(),
                "Create Fresh on a, b.".to_string(),
                "Create on 2 nodes".to_string()
            ))
        );
    }

    #[test]
    fn the_form_checks_the_name_and_the_status() {
        assert!(page_from_form("Soon", "soon", "503", "<p>x</p>").is_ok());
        assert_eq!(
            page_from_form("  ", "soon", "503", "x").unwrap_err(),
            "Give the page a name."
        );
        assert_eq!(
            page_from_form("Soon", "soon", "abc", "x").unwrap_err(),
            "The status must be a number such as 503."
        );
        assert!(page_from_form("Soon", "soon", "200", "x").is_err());
    }
}
