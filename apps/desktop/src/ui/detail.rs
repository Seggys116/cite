use std::future::Future;

use cite_client::{ClientError, DeployRequest};
use cite_edge::model::{Deployment, MaintenancePage, Site, SiteKind, Slot, TlsMode};
use gpui::{AnyElement, ClipboardItem, Context, Div, Entity, div, prelude::*, px};
use serde_json::Value;

use crate::api::{NodeHandle, join_all};
use crate::app::{Confirm, Console, Load, TargetPicker, View, new_input};
use crate::certs::zone_newly_enabled;
use crate::demo::now_ms;
use crate::diagnose::{
    Banner, NOTE_PREVIEW, banner, deploy_outcome, failure_text, shown_output, slot_lines,
    split_note, started_deployment,
};
use crate::model::{
    SiteChange, draft_from_site, edit_site, fmt_targets, parse_rfc3339_ms, parse_targets, rel_time,
    site_change, source_deploy_request,
};
use crate::pages_union::{NodePages, Page, PagesUnion, UnionPage, nodes_needing_page, union_pages};
use crate::scope::{Sequence, error_survives, foreign_notice};
use crate::siteops::{
    CAP_BUILD_ENV, CAP_LOGS, CAP_RUNTIME_ENV, CAP_VOLUMES, has_cap, is_busy_phase,
};
use crate::targets::{NodeInfo, NodeResult, result_message};
use crate::theme::{
    BORDER, CARD_RADIUS, DIM, PILL_RADIUS, ROW_RADIUS, SURFACE, TEXT, Tone, c, chip_fill,
    chip_stroke, tint,
};
use crate::ui::certs::{access_body, access_controls};
use crate::ui::dataview;
use crate::ui::input::TextInput;
use crate::ui::overview::{action_pill, slot_pill};
use crate::ui::paths::PathRow;
use crate::ui::siteform::{Home, SiteFields, basics, domains, health_fields, source_fields};
use crate::ui::sites::health_tone;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, code_block, dot, empty_state, field, form_grid, id, mono,
    notice, page_header, pill, seg_item, seg_row, skeleton, strong, table, text_dim, tip, toggle,
};
use crate::wizard::{FieldProblems, field_problems};
use crate::zone::{
    CLOUDFLARE_STEPS, NOT_SHOWN_AGAIN, ROTATE_WARNING, ZoneReveal, ZoneStatus, reveal_meta,
    reveal_nodes_elsewhere, reveals_for, rotation_failed, status_text,
};

// The site page's own parts live beside this file; they are declared here so the page stays one module tree.
#[path = "data.rs"]
pub(crate) mod data;
#[path = "doppler.rs"]
pub(crate) mod doppler;
#[path = "env.rs"]
pub(crate) mod env;
#[path = "logs.rs"]
pub(crate) mod logs;
#[path = "outbound.rs"]
pub(crate) mod outbound;
#[path = "tabs.rs"]
pub(crate) mod tabs;
#[path = "volumes.rs"]
pub(crate) mod volumes;

use self::tabs::{SiteTab, TabMemory, TabOffer, shown_tab, visible_tabs};

pub struct Data {
    pub site: Site,
    pub live: Option<Value>,
    pub pages: Vec<MaintenancePage>,
    pub zone: Option<ZoneStatus>,
}

// What another node says about the site on screen and the maintenance pages it holds.
pub struct Peer {
    pub node: String,
    // None when the node does not hold the site or could not be read; it then never counts as a holder.
    pub site: Option<Site>,
    // None when the node's pages could not be read.
    pub pages: Option<Vec<MaintenancePage>>,
}

// The other nodes' view of the site on screen, read beside the page so a slow node never holds it back.
pub struct Cross {
    // The node and site id the peers were read for.
    pub key: (String, String),
    pub peers: Vec<Peer>,
    // False until the other nodes have answered.
    pub ready: bool,
}

impl Cross {
    fn pending(node: &str, site: &str) -> Self {
        Self {
            key: (node.to_string(), site.to_string()),
            peers: Vec::new(),
            ready: false,
        }
    }
}

pub struct State {
    pub data: Load<Data>,
    pub node: String,
    pub site_id: String,
    pub targets: Entity<TextInput>,
    pub note: Entity<TextInput>,
    pub busy: bool,
    pub busy_what: &'static str,
    pub error: Option<String>,
    // The slot whose build log explains the error on screen, when it came from a deploy.
    pub error_slot: Option<Slot>,
    pub cross: Cross,
    pub cross_seq: Sequence,
    // The page the owner picked for maintenance: None until picked, then Some(None) for the built-in page.
    pub maint_pick: Option<Option<String>>,
    // Nodes with a maintenance change in flight, whose switches are inert until it settles.
    pub maint_busy: Vec<String>,
    // The edit form, built from the same fields as the create wizard.
    pub edit: SiteFields,
    // The site the form was last filled from, to tell a reload apart from unsaved edits.
    pub edit_base: Option<Site>,
    // The node and site id the form belongs to, so edits never carry over to another site.
    pub edit_for: (String, String),
    pub reveals: Vec<ZoneReveal>,
    pub tabs: TabMemory,
    // Keys of the multi-line notes the owner has opened in full.
    pub open_notes: Vec<&'static str>,
}

fn edit_fields(c: &mut Console) -> &mut SiteFields {
    &mut c.detail.edit
}

fn edit_paths(c: &mut Console) -> &mut Vec<PathRow> {
    &mut c.detail.edit.paths
}

const HOME: Home = Home {
    key: "edit-form",
    fields: edit_fields,
    paths: edit_paths,
};

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            node: String::new(),
            site_id: String::new(),
            targets: new_input(cx, "10.0.0.12:8080, 10.0.0.13:8080 50", |i| i.mono()),
            note: new_input(cx, "Release notes (optional)", |i| i),
            busy: false,
            busy_what: "",
            error: None,
            error_slot: None,
            cross: Cross::pending("", ""),
            cross_seq: Sequence::default(),
            maint_pick: None,
            maint_busy: Vec::new(),
            edit: SiteFields::new(cx),
            edit_base: None,
            edit_for: (String::new(), String::new()),
            reveals: Vec::new(),
            tabs: TabMemory::default(),
            open_notes: Vec::new(),
        }
    }
}

// Where Open takes the owner: the first host that names one machine, over https.
pub fn open_url(hosts: &[String]) -> Option<String> {
    hosts
        .iter()
        .map(|h| h.trim())
        .find(|h| !h.is_empty() && !h.contains('*'))
        .map(|h| format!("https://{h}"))
}

fn keeps_page(same_place: bool, shown_site: Option<&str>, next_site: &str) -> bool {
    same_place && shown_site == Some(next_site)
}

// Online nodes other than the one the page belongs to; an offline node is never asked.
fn peer_names(nodes: &[NodeInfo], current: &str) -> Vec<String> {
    nodes
        .iter()
        .filter(|n| n.online && n.name != current)
        .map(|n| n.name.clone())
        .collect()
}

// One node's entry, from what its site and page lists returned (None where a list could not be read).
fn peer_from(
    node: &str,
    site_id: &str,
    sites: Option<Vec<Site>>,
    pages: Option<Vec<MaintenancePage>>,
) -> Peer {
    Peer {
        node: node.to_string(),
        site: sites.and_then(|list| list.into_iter().find(|s| s.id == site_id)),
        pages,
    }
}

// The nodes that hold the site, in the order of `order` and then any other. The node the page was opened from always counts.
fn holder_nodes(current: &str, peers: &[Peer], order: &[String]) -> Vec<String> {
    let held =
        |name: &str| name == current || peers.iter().any(|p| p.node == name && p.site.is_some());
    let mut out: Vec<String> = order.iter().filter(|n| held(n.as_str())).cloned().collect();
    if !out.iter().any(|n| n == current) {
        out.push(current.to_string());
    }
    for p in peers.iter().filter(|p| p.site.is_some()) {
        if !out.contains(&p.node) {
            out.push(p.node.clone());
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Same,
    Different,
}

// Ids default to a slug of the name, so two unrelated sites can share one. Two copies are the same site when their host sets
// overlap or they build from the same repository (both compared without regard to case); otherwise a shared edit would overwrite an unrelated site.
fn site_relation(current: &Site, other: &Site) -> Relation {
    let mine: Vec<String> = current.hosts.iter().map(|h| h.to_lowercase()).collect();
    if other.hosts.iter().any(|h| mine.contains(&h.to_lowercase())) {
        return Relation::Same;
    }
    match (&current.source, &other.source) {
        (Some(a), Some(b)) if !a.repo.is_empty() && a.repo.eq_ignore_ascii_case(&b.repo) => {
            Relation::Same
        }
        _ => Relation::Different,
    }
}

// The holders other than this node whose copy has this id but is a different site, with that copy's hosts.
fn different_holders(
    current_site: &Site,
    current: &str,
    peers: &[Peer],
    holders: &[String],
) -> Vec<(String, Vec<String>)> {
    peers
        .iter()
        .filter(|p| p.node != current && holders.contains(&p.node))
        .filter_map(|p| {
            let theirs = p.site.as_ref()?;
            (site_relation(current_site, theirs) == Relation::Different)
                .then(|| (p.node.clone(), theirs.hosts.clone()))
        })
        .collect()
}

// "edge-iad has a site with this id but different hosts (api.example.org)."
fn different_note(node: &str, hosts: &[String]) -> String {
    let shown = if hosts.is_empty() {
        "none".to_string()
    } else {
        hosts.join(", ")
    };
    format!("{node} has a site with this id but different hosts ({shown}).")
}

// The body to save on a node other than the one on screen: that node's own stored site with only the shared fields replaced.
// Its upstream targets, active slot, source, volumes and stored GitHub token stay as it has them.
fn shared_body(stored: &Site, edited: &Site) -> Site {
    let mut body = stored.clone();
    body.name = edited.name.clone();
    body.kind = edited.kind;
    body.hosts = edited.hosts.clone();
    body.path_prefixes = edited.path_prefixes.clone();
    body.path_regexes = edited.path_regexes.clone();
    body.health = edited.health.clone();
    body.access = edited.access.clone();
    body
}

// One line for a save that went to one or more nodes, with the redeploy on this node when one was asked for.
// It is an error as soon as any node or the redeploy failed, so the page shows it where it stays.
fn save_message(
    results: &[NodeResult],
    deploy: Option<&Result<Deployment, String>>,
) -> Result<String, String> {
    let mut text = result_message("Saved", results);
    let mut failed = results.iter().any(|r| r.outcome.is_err());
    let tail = match deploy {
        Some(Ok(d)) => match deploy_outcome(d) {
            Ok(t) => Some(t),
            Err(t) => {
                failed = true;
                Some(t)
            }
        },
        Some(Err(e)) => {
            failed = true;
            Some(format!("The redeploy failed: {e}"))
        }
        None => None,
    };
    if let Some(t) = tail {
        text = if text.is_empty() {
            t
        } else {
            format!("{text}. {t}")
        };
    }
    if failed { Err(text) } else { Ok(text) }
}

// A node's answer named first, so a toast about this node never reads as being about another.
fn named(node: &str, message: &str) -> String {
    format!("{node}: {message}")
}

fn to_union_page(p: &MaintenancePage) -> Page {
    Page {
        id: p.id.clone(),
        name: p.name.clone(),
        html: p.html.clone(),
        status: p.status,
    }
}

fn page_from_union(p: &UnionPage) -> MaintenancePage {
    MaintenancePage {
        id: p.id.clone(),
        name: p.name.clone(),
        html: p.html.clone(),
        status: p.status,
    }
}

// Every node's pages as one library; the node on screen is listed first, so its copy wins a tie.
fn union_for(current: &str, own: &[MaintenancePage], peers: &[Peer]) -> PagesUnion {
    let mut per_node = vec![NodePages {
        node: current.to_string(),
        pages: Some(own.iter().map(to_union_page).collect()),
    }];
    per_node.extend(peers.iter().map(|p| {
        NodePages {
            node: p.node.clone(),
            pages: p
                .pages
                .as_ref()
                .map(|list| list.iter().map(to_union_page).collect()),
        }
    }));
    union_pages(&per_node)
}

// One node's maintenance state as its switch shows it.
struct MaintRow {
    node: String,
    enabled: bool,
    page_id: Option<String>,
}

fn maint_rows(holders: &[String], current: &str, site: &Site, peers: &[Peer]) -> Vec<MaintRow> {
    holders
        .iter()
        .map(|node| {
            let state = if node == current {
                Some(&site.maintenance)
            } else {
                peers
                    .iter()
                    .find(|p| p.node == *node)
                    .and_then(|p| p.site.as_ref())
                    .map(|s| &s.maintenance)
            };
            MaintRow {
                node: node.clone(),
                enabled: state.is_some_and(|m| m.enabled),
                page_id: state.and_then(|m| m.page_id.clone()),
            }
        })
        .collect()
}

// The page the chooser shows: the owner's pick, else the first page a node already serves; never one no node holds.
fn effective_page(
    pick: &Option<Option<String>>,
    rows: &[MaintRow],
    union: &PagesUnion,
) -> Option<String> {
    let wanted = match pick {
        Some(choice) => choice.clone(),
        None => rows.iter().find_map(|r| r.page_id.clone()),
    };
    wanted.filter(|id| union.pages.iter().any(|p| p.id == *id))
}

// Turning on uses the chosen page; turning off keeps the page the node already serves.
fn maint_page_for(enabled: bool, chosen: Option<&str>, node_page: Option<&str>) -> Option<String> {
    let page = if enabled {
        chosen
    } else {
        node_page.or(chosen)
    };
    page.map(str::to_string)
}

// "Maintenance enabled on edge-fra, edge-nyc. Failed on edge-ams: reason"
fn maint_message(enabled: bool, results: &[NodeResult]) -> String {
    let state = if enabled { "enabled" } else { "disabled" };
    result_message(&format!("Maintenance {state}"), results)
}

// One node's part of a save: the body it takes and what follows the write.
struct SaveJob {
    handle: NodeHandle,
    // Set only for the node on screen, whose stored copy is already loaded; any other node is read first.
    stored: Option<Site>,
    edited: Site,
    redeploy: Option<(DeployRequest, Slot)>,
}

struct NodeSave {
    node: String,
    here: bool,
    saved: Result<(), String>,
    reveal: Option<Result<ZoneReveal, String>>,
    deploy: Option<Result<Deployment, String>>,
}

// The node on screen takes the whole edited site; another node takes only the shared fields on top of its own copy.
// Turning the zone lock on rotates in a secret right after the write, because the node only shows it when asked.
async fn save_on_node(job: SaveJob) -> NodeSave {
    let SaveJob {
        handle: h,
        stored,
        edited,
        redeploy,
    } = job;
    let node = h.name().to_string();
    let here = stored.is_some();
    let failed = |node: String, e: String| NodeSave {
        node,
        here,
        saved: Err(e),
        reveal: None,
        deploy: None,
    };
    let stored = match stored {
        Some(s) => s,
        None => match h.get_site(&edited.id).await {
            Ok(d) => d.site,
            Err(e) => return failed(node, e.to_string()),
        },
    };
    let body = if here {
        edited
    } else {
        shared_body(&stored, &edited)
    };
    if let Err(e) = h.update_site(&body.id, &body).await {
        return failed(node, e.to_string());
    }
    let reveal = if zone_newly_enabled(&stored.access, &body.access) {
        Some(
            h.rotate_zone_secret(&body.id)
                .await
                .map_err(|e| e.to_string()),
        )
    } else {
        None
    };
    let deploy = match redeploy {
        Some((req, idle)) => {
            let started = if body.source.is_some() {
                h.deploy_async(&body.id, None, req.note.as_deref())
                    .await
                    .map(|id| started_deployment(id, idle))
            } else {
                h.deploy(&body.id, &req).await
            };
            Some(started.map_err(|e| e.to_string()))
        }
        None => None,
    };
    NodeSave {
        node,
        here,
        saved: Ok(()),
        reveal,
        deploy,
    }
}

// One node's part of a maintenance change; a node that lacks the chosen page gets it first, because it refuses a page it does not hold.
struct MaintJob {
    handle: NodeHandle,
    site: String,
    enabled: bool,
    page: Option<String>,
    create: Option<MaintenancePage>,
}

async fn run_maintenance(job: MaintJob) -> NodeResult {
    let node = job.handle.name().to_string();
    let outcome = async {
        if let Some(page) = &job.create {
            job.handle.create_page(page).await?;
        }
        job.handle
            .maintenance(&job.site, job.enabled, job.page.as_deref())
            .await?;
        Ok::<(), ClientError>(())
    }
    .await
    .map_err(|e| e.to_string());
    NodeResult { node, outcome }
}

// The form as typed, checked, and compared with the stored site.
struct FormState {
    problems: FieldProblems,
    change: SiteChange,
    blocker: Option<String>,
}

impl Console {
    // The site and its maintenance pages load together so the form is complete on first paint.
    pub fn load_detail(&mut self, node: String, site_id: String, cx: &mut Context<Self>) {
        let same = error_survives(&self.detail.node, &self.detail.site_id, &node, &site_id);
        // A reload of the site on screen keeps it there until the reply, so the page neither blanks nor jumps to the top.
        if !keeps_page(
            same,
            self.detail.data.ready().map(|d| d.site.id.as_str()),
            &site_id,
        ) {
            self.detail.data = Load::Loading;
        }
        // An action's error must still be on screen after the reload that follows it, so it is cleared only for another site.
        if !same {
            self.clear_error();
        }
        self.detail.node = node.clone();
        self.detail.site_id = site_id.clone();
        let Some(h) = self.handle_named(&node) else {
            self.detail.data = Load::Failed(format!("Node {node} is not connected."));
            return;
        };
        self.load_peers(&node, &site_id, cx);
        let (ops_node, ops_site) = (node.clone(), site_id.clone());
        // The three reads do not depend on each other, so they run together.
        let fut = async move {
            let (detail, pages, zone) = tokio::join!(
                h.get_site(&site_id),
                h.list_pages(),
                h.zone_secret(&site_id)
            );
            let detail = detail?;
            Ok(Data {
                site: detail.site,
                live: detail.live,
                pages: pages.unwrap_or_default(),
                zone: zone.ok(),
            })
        };
        self.fetch_scoped(cx, fut, move |this, res, cx| {
            if let Ok(data) = &res {
                this.refill_edit(&data.site, cx);
                this.load_ops(
                    ops_node.clone(),
                    ops_site.clone(),
                    data.site.source.is_some(),
                    cx,
                );
                // The Environment tab shows linked variables read-only, so the data is read with the site, not with its tab.
                if volumes::source_serves(data.site.source.as_ref()) {
                    this.load_site_data(ops_node, ops_site, cx);
                }
            }
            this.detail.data = Load::from_result(res);
            cx.notify();
        });
    }

    // Reads the site list and page list of every other online node, all at once and apart from the page's own load.
    // A reload keeps the last answer on screen until the new one arrives; another site starts from this node alone.
    fn load_peers(&mut self, node: &str, site_id: &str, cx: &mut Context<Self>) {
        let key = (node.to_string(), site_id.to_string());
        if self.detail.cross.key != key {
            self.detail.cross = Cross::pending(node, site_id);
            self.detail.maint_pick = None;
        }
        let seq = self.detail.cross_seq.issue();
        let jobs: Vec<NodeHandle> = peer_names(&self.node_infos(), node)
            .iter()
            .filter_map(|n| self.handle_named(n))
            .collect();
        if jobs.is_empty() {
            self.detail.cross.peers.clear();
            self.detail.cross.ready = true;
            return;
        }
        let site = site_id.to_string();
        let fut = async move {
            let all = join_all(
                jobs.into_iter()
                    .map(|h| {
                        let site = site.clone();
                        async move {
                            let (sites, pages) = tokio::join!(h.list_sites(), h.list_pages());
                            peer_from(h.name(), &site, sites.ok(), pages.ok())
                        }
                    })
                    .collect(),
            )
            .await;
            Ok::<_, ClientError>(all.into_iter().flatten().collect::<Vec<Peer>>())
        };
        self.fetch(cx, fut, move |this, res, cx| {
            if this.detail.cross.key != key || !this.detail.cross_seq.accept(seq) {
                return;
            }
            if let Ok(peers) = res {
                this.detail.cross.peers = peers;
                this.detail.cross.ready = true;
            }
            cx.notify();
        });
    }

    // The nodes that hold the site on screen: this one, and every other online node whose site list has its id.
    fn holders(&self) -> Vec<String> {
        let order: Vec<String> = self.node_infos().into_iter().map(|n| n.name).collect();
        holder_nodes(&self.detail.node, &self.detail.cross.peers, &order)
    }

    fn fail(&mut self, msg: String, slot: Option<Slot>) {
        self.detail.error = Some(msg);
        self.detail.error_slot = slot;
    }

    fn clear_error(&mut self) {
        self.detail.error = None;
        self.detail.error_slot = None;
    }

    fn tab_offer(&self, data: &Data) -> TabOffer {
        let source = data.site.source.is_some();
        // Until the node has said what it offers, a remembered tab stays open instead of jumping to Overview.
        if !self.ops.loaded {
            let remembered = self.detail.tabs.get(&self.detail.node, &data.site.id);
            return TabOffer {
                source,
                env: true,
                logs: true,
                volumes: volumes::volumes_apply(&data.site),
                // Only a remembered Data tab is kept open: a node without data services must not flash one.
                data: remembered == Some(SiteTab::Data) && volumes::volumes_apply(&data.site),
            };
        }
        let caps = &self.ops.extras.caps;
        TabOffer {
            source,
            env: has_cap(caps, CAP_BUILD_ENV)
                || has_cap(caps, CAP_RUNTIME_ENV)
                || self.ops.doppler.offered,
            logs: has_cap(caps, CAP_LOGS),
            volumes: has_cap(caps, CAP_VOLUMES) && volumes::volumes_apply(&data.site),
            data: dataview::data_tab_offered(caps) && volumes::volumes_apply(&data.site),
        }
    }

    pub(crate) fn site_tab(&self) -> SiteTab {
        let Some(data) = self.detail.data.ready() else {
            return SiteTab::Overview;
        };
        let tabs = visible_tabs(self.tab_offer(data));
        shown_tab(
            self.detail.tabs.get(&self.detail.node, &data.site.id),
            &tabs,
        )
    }

    pub(crate) fn remember_tab(&mut self, tab: SiteTab) {
        let Some(site) = self.detail.data.ready().map(|d| d.site.id.clone()) else {
            return;
        };
        let node = self.detail.node.clone();
        self.detail.tabs.set(&node, &site, tab);
    }

    pub(crate) fn select_tab(&mut self, tab: SiteTab, cx: &mut Context<Self>) {
        self.remember_tab(tab);
        if tab == SiteTab::Logs {
            self.open_logs(cx);
        }
        // Opening the tab reads the data again, so it is current when it is shown.
        if tab == SiteTab::Data {
            let (node, site) = (self.detail.node.clone(), self.detail.site_id.clone());
            self.load_site_data(node, site, cx);
        }
    }

    pub(crate) fn logs_offered(&self, data: &Data) -> bool {
        data.site.source.is_some() && self.ops.loaded && has_cap(&self.ops.extras.caps, CAP_LOGS)
    }

    // Runs a mutation, then reloads the site so the page always shows the node's own state.
    // If the user has moved to another site or node by the time the node answers, the outcome is a toast naming the place and the page is left alone.
    fn site_action<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        what: &'static str,
        fut: F,
        logs_slot: Option<Slot>,
        outcome: impl FnOnce(&T) -> Result<String, String> + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        self.detail.busy = true;
        self.detail.busy_what = busy_text(what);
        self.clear_error();
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            let result = res.map_err(|e| e.to_string()).and_then(|v| outcome(&v));
            this.detail.busy = false;
            if !here {
                let (msg, tone) = match result {
                    Ok(m) => (m, Tone::Ok),
                    Err(m) => (m, Tone::Bad),
                };
                this.say(foreign_notice(what, origin, &msg), tone);
                cx.notify();
                return;
            }
            this.detail.busy = false;
            match result {
                Ok(msg) => this.say(msg, Tone::Ok),
                Err(msg) => this.fail(msg, logs_slot),
            }
            this.reload_detail(cx);
            cx.notify();
        });
    }

    // Actions need both the node client and the loaded site.
    fn site_handle(&self) -> Option<(crate::api::NodeHandle, Site)> {
        let site = self.detail.data.ready()?.site.clone();
        Some((self.handle_named(&self.detail.node)?, site))
    }

    fn do_switch(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let target = site.active.other();
        let node = self.detail.node.clone();
        let fut = async move { h.switch(&site.id, target).await };
        self.site_action(cx, "Switch", fut, None, move |_| {
            Ok(format!("{} is now active on {node}", target.as_str()))
        });
    }

    fn do_rollback(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let node = self.detail.node.clone();
        let fut = async move { h.rollback(&site.id).await };
        self.site_action(cx, "Rollback", fut, None, move |_| {
            Ok(format!("Rolled back on {node}"))
        });
    }

    // Deploy waits on health checks, so the busy notice stays up until the node answers.
    pub(super) fn do_deploy(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let note =
            Some(self.detail.note.read(cx).text().trim().to_string()).filter(|n| !n.is_empty());
        // A site built from GitHub takes no targets: the node builds the idle slot itself.
        let req = if site.source.is_some() {
            source_deploy_request(note)
        } else {
            match parse_targets(self.detail.targets.read(cx).text()) {
                Ok(t) if !t.is_empty() => DeployRequest { targets: t, note },
                Ok(_) => {
                    self.fail("Add at least one target to deploy.".into(), None);
                    return;
                }
                Err(e) => {
                    self.fail(e, None);
                    return;
                }
            }
        };
        let idle = site.active.other();
        let logs_slot = site.source.is_some().then_some(idle);
        let from_source = site.source.is_some();
        let node = self.detail.node.clone();
        let fut = async move {
            if from_source {
                let note = req.note.clone();
                let id = h.deploy_async(&site.id, None, note.as_deref()).await?;
                Ok(started_deployment(id, idle))
            } else {
                h.deploy(&site.id, &req).await
            }
        };
        self.site_action(cx, "Deploy", fut, logs_slot, move |d| {
            deploy_outcome(d)
                .map(|m| named(&node, &m))
                .map_err(|m| named(&node, &m))
        });
    }

    // The form follows the node: it is refilled after every load unless the owner has unsaved edits in it.
    fn refill_edit(&mut self, site: &Site, cx: &mut Context<Self>) {
        let draft = self.detail.edit.draft(cx);
        // The form reads as a site when it produces exactly that site.
        let reads_as = |s: &Site| edit_site(s, &draft).is_ok_and(|e| e == *s);
        let here = (self.detail.node.clone(), site.id.clone());
        let edited = self.detail.edit_for == here
            && self
                .detail
                .edit_base
                .as_ref()
                .is_some_and(|base| !reads_as(site) && !reads_as(base));
        if !edited {
            self.detail.edit.load(&draft_from_site(site), cx);
            self.detail.edit_base = Some(site.clone());
            self.detail.edit_for = here;
        }
    }

    // Puts the stored values back into the form.
    fn discard_edits(&mut self, cx: &mut Context<Self>) {
        if let Some(site) = self.detail.data.ready().map(|d| d.site.clone()) {
            self.detail.edit.load(&draft_from_site(&site), cx);
            self.detail.edit_base = Some(site);
        }
        self.ops.volumes.clear_edits();
        self.clear_error();
    }

    // Checks the form, then saves it: straight to this node when it holds the site alone, otherwise after asking which of the holders to update.
    // The stored GitHub token is never sent: the node keeps it.
    fn do_save(&mut self, redeploy: bool, cx: &mut Context<Self>) {
        let Some((_, existing)) = self.site_handle() else {
            return;
        };
        let draft = self.detail.edit.draft(cx);
        let edited = match edit_site(&existing, &draft) {
            Ok(s) => self.ops.volumes.apply_to(s),
            Err(e) => {
                self.fail(e, None);
                return;
            }
        };
        let node = self.detail.node.clone();
        let holders = self.holders();
        if holders.len() < 2 {
            self.save_to(redeploy, existing, edited, vec![node], cx);
            return;
        }
        let nodes: Vec<NodeInfo> = self
            .node_infos()
            .into_iter()
            .filter(|n| holders.contains(&n.name))
            .collect();
        // Only this node is ticked; a node holding an unrelated site with this id stays unticked and is called out.
        let mut message = format!(
            "{} is on {} nodes. Pick where to save these changes.",
            existing.name,
            holders.len()
        );
        for (other, hosts) in
            different_holders(&existing, &node, &self.detail.cross.peers, &holders)
        {
            message.push_str(&format!(
                " {} Check before saving there.",
                different_note(&other, &hosts)
            ));
        }
        self.ask_targets(TargetPicker {
            title: "Save changes".into(),
            message,
            verb: "Save".into(),
            nodes,
            selected: vec![node],
            danger: false,
            action: Box::new(move |this, cx, targets| {
                this.save_to(redeploy, existing, edited, targets, cx)
            }),
        });
    }

    // Writes the form to the chosen nodes at once. This node takes the whole edited site, another node only the shared fields on top of its own copy.
    // With redeploy, this node then starts a deploy so a source change takes effect; the redeploy never runs elsewhere.
    fn save_to(
        &mut self,
        redeploy: bool,
        existing: Site,
        edited: Site,
        targets: Vec<String>,
        cx: &mut Context<Self>,
    ) {
        let here_node = self.detail.node.clone();
        // A saved source change is not in the running build, so the owner is asked about a rebuild afterwards.
        let ask_rebuild = !redeploy
            && existing.source.is_some()
            && site_change(&existing, &edited).needs_redeploy;
        let req = source_deploy_request(
            Some(self.detail.note.read(cx).text().trim().to_string()).filter(|n| !n.is_empty()),
        );
        let idle = existing.active.other();
        let jobs: Vec<SaveJob> = targets
            .iter()
            .filter_map(|name| {
                let on_screen = *name == here_node;
                Some(SaveJob {
                    handle: self.handle_named(name)?,
                    stored: on_screen.then(|| existing.clone()),
                    edited: edited.clone(),
                    redeploy: (redeploy && on_screen).then(|| (req.clone(), idle)),
                })
            })
            .collect();
        if jobs.is_empty() {
            self.fail("None of the chosen nodes is connected.".into(), None);
            return;
        }
        self.detail.busy = true;
        self.detail.busy_what = if redeploy {
            "Saving, then starting a build"
        } else {
            "Saving the site"
        };
        self.clear_error();
        let fut = async move {
            let all = join_all(jobs.into_iter().map(save_on_node).collect()).await;
            Ok::<_, ClientError>(all.into_iter().flatten().collect::<Vec<NodeSave>>())
        };
        self.fetch_origin(
            cx,
            fut,
            move |this, res: Result<Vec<NodeSave>, ClientError>, here, origin, cx| {
                const WHAT: &str = "Save site";
                let saves = match res {
                    Ok(saves) => saves,
                    Err(e) => {
                        this.detail.busy = false;
                        if here {
                            this.fail(e.to_string(), None);
                            this.reload_detail(cx);
                        } else {
                            this.say(foreign_notice(WHAT, origin, &e.to_string()), Tone::Bad);
                        }
                        cx.notify();
                        return;
                    }
                };
                let results: Vec<NodeResult> = saves
                    .iter()
                    .map(|s| NodeResult {
                        node: s.node.clone(),
                        outcome: s.saved.clone(),
                    })
                    .collect();
                let screen = saves.iter().find(|s| s.here);
                let saved_here = screen.is_some_and(|s| s.saved.is_ok());
                let deploy = screen.and_then(|s| s.deploy.clone());
                let deploy_slot = match &deploy {
                    Some(Ok(d)) => Some(d.slot),
                    Some(Err(_)) => Some(idle),
                    None => None,
                };
                let outcome = save_message(&results, deploy.as_ref());
                if here && saved_here {
                    this.ops.volumes.clear_edits();
                    if ask_rebuild {
                        this.ops.rebuild_prompt = true;
                    }
                }
                // A secret for another place is kept under its own node and site and shown only there.
                let mut warns = Vec::new();
                for save in saves {
                    match save.reveal {
                        Some(Ok(r)) => this.keep_reveal(r),
                        Some(Err(e)) => warns.push(named(&save.node, &rotation_failed(&e))),
                        None => {}
                    }
                }
                let warn = (!warns.is_empty()).then(|| warns.join(" "));
                this.detail.busy = false;
                if !here {
                    let (mut text, tone) = match outcome {
                        Ok(t) => (t, Tone::Ok),
                        Err(t) => (t, Tone::Bad),
                    };
                    if let Some(w) = warn {
                        text = format!("{text} {w}");
                    }
                    this.say(foreign_notice(WHAT, origin, &text), tone);
                    cx.notify();
                    return;
                }
                match (outcome, warn) {
                    (Ok(t), None) => this.say(t, Tone::Ok),
                    (Ok(t), Some(w)) => this.fail(format!("{t} {w}"), None),
                    (Err(t), w) => this.fail(
                        match w {
                            Some(w) => format!("{t} {w}"),
                            None => t,
                        },
                        deploy_slot,
                    ),
                }
                this.reload_detail(cx);
                cx.notify();
            },
        );
    }

    fn form_state(&self, data: &Data, cx: &mut Context<Self>) -> FormState {
        let draft = self.detail.edit.draft(cx);
        let problems = field_problems(&draft, false);
        let edited = edit_site(&data.site, &draft).map(|e| self.ops.volumes.apply_to(e));
        let change = edited
            .as_ref()
            .map(|e| site_change(&data.site, e))
            .unwrap_or(SiteChange {
                dirty: true,
                needs_redeploy: false,
            });
        let blocker = problems
            .first()
            .cloned()
            .or_else(|| edited.as_ref().err().cloned())
            .or_else(|| {
                edited
                    .as_ref()
                    .ok()
                    .and_then(|e| outbound::rules_problem(&e.outbound_rules))
            });
        FormState {
            problems,
            change,
            blocker,
        }
    }

    // One Save for the whole form, shown at the foot of every tab that holds part of it.
    fn save_bar(&self, data: &Data, form: &FormState, cx: &mut Context<Self>) -> AnyElement {
        let change = &form.change;
        let busy = self.detail.busy;
        let can_save = !busy && change.dirty && form.blocker.is_none();
        let mut buttons = div().flex().items_center().gap(px(8.));
        if change.dirty && !busy {
            buttons = buttons.child(
                btn(id("detail", "discard"), "Discard", BtnKind::Plain).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.discard_edits(cx);
                        cx.notify();
                    },
                )),
            );
        }
        buttons = buttons.child(if can_save {
            btn(id("detail", "save"), "Save", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.do_save(false, cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Save").into_any_element()
        });
        if data.site.source.is_some() {
            buttons = buttons.child(if can_save {
                btn(
                    id("detail", "save-redeploy"),
                    "Save and redeploy",
                    BtnKind::Primary,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.do_save(true, cx);
                    cx.notify();
                }))
                .into_any_element()
            } else {
                btn_off("Save and redeploy").into_any_element()
            });
        }
        let state = if busy {
            text_dim("Saving...").text_size(px(12.)).into_any_element()
        } else if change.dirty {
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(pill("Unsaved changes", Tone::Warn))
                .children(
                    change
                        .needs_redeploy
                        .then(|| text_dim("Takes effect on the next deploy").text_size(px(12.))),
                )
                .into_any_element()
        } else {
            text_dim("All changes saved")
                .text_size(px(12.))
                .into_any_element()
        };
        let mut bar = div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .px(px(16.))
            .py(px(12.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(c(BORDER))
            .bg(c(SURFACE))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(12.))
                    .child(state)
                    .child(buttons),
            );
        if let Some(b) = form.blocker.as_ref().filter(|_| change.dirty) {
            bar = bar.child(
                text_dim(b.clone())
                    .text_size(px(12.))
                    .text_color(c(Tone::Bad.color())),
            );
        }
        let explain = if self.holders().len() > 1 {
            "Saving asks which nodes to update. Build settings and volumes apply to this node only."
        } else if data.site.source.is_some() {
            "Repository and build changes take effect on the next deploy."
        } else {
            "To change the targets, deploy on the Overview tab."
        };
        bar.child(text_dim(explain).text_size(px(11.)))
            .into_any_element()
    }

    // A newer secret for the same node and site replaces the older one, so only the valid value is ever on screen.
    fn keep_reveal(&mut self, reveal: ZoneReveal) {
        self.detail
            .reveals
            .retain(|r| !r.is_for(&reveal.node, &reveal.site));
        self.detail.reveals.push(reveal);
    }

    pub(super) fn reload_detail(&mut self, cx: &mut Context<Self>) {
        if let View::SiteDetail { node, id } = self.view.clone() {
            self.load_detail(node, id, cx);
        }
    }

    fn do_rotate_zone(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        self.detail.busy = true;
        self.detail.busy_what = "Rotating the zone secret";
        self.clear_error();
        self.fetch_origin(
            cx,
            async move { h.rotate_zone_secret(&site.id).await },
            |this, res, here, origin, cx| {
                this.detail.busy = false;
                if !here {
                    let (text, tone) = match res {
                        Ok(reveal) => {
                            this.keep_reveal(reveal);
                            (
                                "rotated; open the site to copy the new secret".to_string(),
                                Tone::Ok,
                            )
                        }
                        Err(e) => (e.to_string(), Tone::Bad),
                    };
                    this.say(foreign_notice("Zone secret", origin, &text), tone);
                    cx.notify();
                    return;
                }
                this.detail.busy = false;
                match res {
                    Ok(reveal) => {
                        let node = reveal.node.clone();
                        this.keep_reveal(reveal);
                        this.say(format!("Zone secret rotated on {node}"), Tone::Ok);
                    }
                    Err(e) => this.fail(e.to_string(), None),
                }
                this.reload_detail(cx);
                cx.notify();
            },
        );
    }

    // Turns maintenance on or off on the given nodes at once; every node is written on its own, and the page is created first where it is missing.
    fn set_maintenance(&mut self, nodes: Vec<String>, enabled: bool, cx: &mut Context<Self>) {
        let Some(data) = self.detail.data.ready() else {
            return;
        };
        let (site_id, site_name) = (data.site.id.clone(), data.site.name.clone());
        let current = self.detail.node.clone();
        let peers = &self.detail.cross.peers;
        let rows = maint_rows(&self.holders(), &current, &data.site, peers);
        let union = union_for(&current, &data.pages, peers);
        let chosen = effective_page(&self.detail.maint_pick, &rows, &union);
        let jobs: Vec<MaintJob> = nodes
            .iter()
            .filter_map(|name| {
                let node_page = rows
                    .iter()
                    .find(|r| r.node == *name)
                    .and_then(|r| r.page_id.as_deref());
                let page = maint_page_for(enabled, chosen.as_deref(), node_page);
                let create = page
                    .as_deref()
                    .filter(|_| enabled)
                    .filter(|p| {
                        !nodes_needing_page(&union, p, std::slice::from_ref(name)).is_empty()
                    })
                    .and_then(|p| union.pages.iter().find(|u| u.id == p))
                    .map(page_from_union);
                Some(MaintJob {
                    handle: self.handle_named(name)?,
                    site: site_id.clone(),
                    enabled,
                    page,
                    create,
                })
            })
            .collect();
        if jobs.is_empty() {
            return;
        }
        let busy: Vec<String> = jobs.iter().map(|j| j.handle.name().to_string()).collect();
        self.detail.maint_busy.extend(busy.iter().cloned());
        let fut = async move {
            let all = join_all(jobs.into_iter().map(run_maintenance).collect()).await;
            Ok::<_, ClientError>(all.into_iter().flatten().collect::<Vec<NodeResult>>())
        };
        self.fetch_origin(cx, fut, move |this, res, here, _origin, cx| {
            this.detail.maint_busy.retain(|n| !busy.contains(n));
            let results = res.unwrap_or_else(|e| {
                busy.iter()
                    .map(|node| NodeResult {
                        node: node.clone(),
                        outcome: Err(e.to_string()),
                    })
                    .collect()
            });
            let text = maint_message(enabled, &results);
            let tone = if results.iter().all(|r| r.outcome.is_ok()) {
                Tone::Ok
            } else {
                Tone::Bad
            };
            if here {
                this.say(text, tone);
                this.reload_detail(cx);
            } else {
                this.say(named(&site_name, &text), tone);
            }
            cx.notify();
        });
    }

    // Asks before changing every node that is not already in the wanted state.
    fn ask_everywhere(&mut self, enabled: bool) {
        let Some(data) = self.detail.data.ready() else {
            return;
        };
        let holders = self.holders();
        let peers = &self.detail.cross.peers;
        let rows = maint_rows(&holders, &self.detail.node, &data.site, peers);
        // A holder with an unrelated site of this id is skipped: it has its own switch.
        let different = different_holders(&data.site, &self.detail.node, peers, &holders);
        let names: Vec<String> = rows
            .iter()
            .filter(|r| r.enabled != enabled && !different.iter().any(|(n, _)| *n == r.node))
            .map(|r| r.node.clone())
            .collect();
        if names.is_empty() {
            return;
        }
        let skipped: Vec<&str> = different.iter().map(|(n, _)| n.as_str()).collect();
        let (title, mut message) = if enabled {
            (
                "Turn on everywhere",
                format!(
                    "Puts {} into maintenance on {}.",
                    data.site.name,
                    names.join(", ")
                ),
            )
        } else {
            (
                "Turn off everywhere",
                format!(
                    "Takes {} out of maintenance on {}.",
                    data.site.name,
                    names.join(", ")
                ),
            )
        };
        if !skipped.is_empty() {
            message.push_str(&format!(
                " Skips {}, which has a site with this id but different hosts; use its own switch.",
                skipped.join(", ")
            ));
        }
        self.ask(Confirm {
            title: title.into(),
            message,
            label: title.into(),
            danger: enabled,
            action: Box::new(move |this, cx| this.set_maintenance(names, enabled, cx)),
        });
    }

    // Deleting leaves the page, so it navigates instead of reloading. It removes the site from this node only.
    fn do_delete(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let name = site.name.clone();
        let node = self.detail.node.clone();
        self.detail.busy = true;
        self.detail.busy_what = "Deleting the site";
        self.fetch_origin(
            cx,
            async move { h.delete_site(&site.id).await },
            move |this, res, here, origin, cx| {
                this.detail.busy = false;
                if !here {
                    let (text, tone) = match res {
                        Ok(()) => (format!("Site {name} deleted from {node}"), Tone::Ok),
                        Err(e) => (e.to_string(), Tone::Bad),
                    };
                    this.say(foreign_notice("Delete", origin, &text), tone);
                    cx.notify();
                    return;
                }
                this.detail.busy = false;
                match res {
                    Ok(()) => {
                        this.say(format!("Site {name} deleted from {node}"), Tone::Ok);
                        this.navigate(View::Sites, cx);
                    }
                    Err(e) => this.fail(e.to_string(), None),
                }
                cx.notify();
            },
        );
    }

    pub fn render_detail(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let back = btn(id("detail", "back"), "Back", BtnKind::Plain)
            .on_click(cx.listener(|this, _, _, cx| this.navigate(View::Sites, cx)));
        match &self.detail.data {
            Load::Idle | Load::Loading => div()
                .flex()
                .flex_col()
                .gap(px(16.))
                .child(page_header(
                    "Site",
                    "Loading",
                    vec![back.into_any_element()],
                ))
                .child(skeleton(120.))
                .child(skeleton(220.))
                .into_any_element(),
            Load::Failed(msg) => {
                let msg = msg.clone();
                div()
                    .flex()
                    .flex_col()
                    .gap(px(16.))
                    .child(page_header(
                        "Site",
                        "Could not load",
                        vec![back.into_any_element()],
                    ))
                    .child(self.error_block(cx, &msg))
                    .into_any_element()
            }
            Load::Ready(data) => self.detail_body(data, back, cx),
        }
    }

    pub(crate) fn view_logs_button(
        &self,
        key: &'static str,
        slot: Slot,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        btn(id("view-logs", key), "View build logs", BtnKind::Plain)
            .on_click(cx.listener(move |this, _, _, cx| {
                this.show_build_logs(slot, cx);
                cx.notify();
            }))
            .into_any_element()
    }

    // A node note: the reason on one monospace line, and any build output under it, newest lines first in view and the rest a click away.
    pub(crate) fn note_block(
        &self,
        key: &'static str,
        note: &str,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let parts = split_note(note);
        let open = self.detail.open_notes.contains(&key);
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(mono(parts.reason.clone()));
        if parts.output.is_empty() {
            return col.into_any_element();
        }
        let shown = shown_output(&parts.output, open);
        let hidden = parts.output.len() - shown.len();
        if hidden > 0 {
            col = col.child(text_dim(format!("{hidden} earlier lines hidden")).text_size(px(11.)));
        }
        let scope = format!("note-{key}-{}-{}", self.detail.node, self.detail.site_id);
        col = col.child(code_block(scope, shown.join("\n"), 320.));
        if parts.output.len() > NOTE_PREVIEW {
            let label = if open {
                "Show fewer lines".to_string()
            } else {
                format!("Show all {} lines", parts.output.len())
            };
            col = col.child(div().flex().child(
                btn(id("note-toggle", key), &label, BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        let notes = &mut this.detail.open_notes;
                        if notes.contains(&key) {
                            notes.retain(|k| *k != key);
                        } else {
                            notes.push(key);
                        }
                        cx.notify();
                    },
                )),
            ));
        }
        col.into_any_element()
    }

    fn header(&self, data: &Data, back: impl IntoElement, cx: &mut Context<Self>) -> AnyElement {
        let site = &data.site;
        let idle = site.active.other();
        let pills = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .child(pill(
                if site.kind == SiteKind::Api {
                    "API"
                } else {
                    "Site"
                },
                Tone::Muted,
            ))
            .child(slot_pill(site.active))
            .child(if site.maintenance.enabled {
                pill("Maintenance", Tone::Warn)
            } else {
                pill("Serving", Tone::Ok)
            })
            .children(
                site.access
                    .cloudflare_only
                    .then(|| pill("Cloudflare only", Tone::Info)),
            )
            .children(
                (site.access.tls == TlsMode::Flexible).then(|| pill("Flexible SSL", Tone::Warn)),
            );
        let mut health = div().flex().items_center().gap(px(12.));
        for line in slot_lines(site, data.live.as_ref()) {
            health = health.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(5.))
                    .child(dot(line.state.tone()))
                    .child(
                        text_dim(format!("{} {}", line.slot.as_str(), line.state.label()))
                            .text_size(px(11.)),
                    ),
            );
        }
        let hosts = if site.hosts.is_empty() {
            "No hosts".to_string()
        } else {
            site.hosts.join(", ")
        };
        let busy = self.detail.busy
            || self
                .ops
                .extras
                .status
                .as_ref()
                .is_some_and(|s| is_busy_phase(&s.phase));
        let holders = self.holders();
        let place = if holders.len() > 1 {
            let mut chips = div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(6.))
                .child(mono(site.id.clone()).text_size(px(11.)).text_color(c(DIM)))
                .child(text_dim("on").text_size(px(11.)));
            let different =
                different_holders(site, &self.detail.node, &self.detail.cross.peers, &holders);
            for name in &holders {
                let differs = different.iter().any(|(n, _)| n == name);
                chips = chips.child(self.holder_chip(name, &site.id, differs, cx));
            }
            chips
        } else {
            div().flex().child(
                mono(format!("{} on {}", site.id, self.detail.node))
                    .text_size(px(11.))
                    .text_color(c(DIM)),
            )
        };
        let mut actions = div().flex().items_center().gap(px(8.)).child(back);
        if let Some(url) = open_url(&site.hosts) {
            actions = actions.child(
                btn(id("detail", "open"), "Open", BtnKind::Plain)
                    .on_click(cx.listener(move |_, _, _, cx| cx.open_url(&url))),
            );
        }
        actions = actions.child(
            btn(
                id("detail", "switch"),
                &format!("Switch to {}", idle.as_str()),
                BtnKind::Plain,
            )
            .on_click(cx.listener(move |this, _, _, cx| {
                let name = this
                    .detail
                    .data
                    .ready()
                    .map(|d| d.site.name.clone())
                    .unwrap_or_default();
                let node = this.detail.node.clone();
                this.ask(Confirm {
                    title: format!("Switch active slot on {node}"),
                    message: format!(
                        "Send all traffic for {name} on {node} to the {} slot now?",
                        idle.as_str()
                    ),
                    label: "Switch".into(),
                    danger: false,
                    action: Box::new(|this, cx| this.do_switch(cx)),
                });
                cx.notify();
            })),
        );
        if site.source.is_some() {
            actions = actions.child(if busy {
                btn_off("Redeploy").into_any_element()
            } else {
                btn(id("detail", "redeploy"), "Redeploy", BtnKind::Primary)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.do_deploy(cx);
                        cx.notify();
                    }))
                    .into_any_element()
            });
        }
        div()
            .flex()
            .items_start()
            .justify_between()
            .gap(px(16.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .min_w_0()
                    .child(strong(site.name.clone()).text_size(px(22.)))
                    .child(mono(hosts).text_color(c(DIM)))
                    .child(pills)
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(12.))
                            .child(health)
                            .child(place),
                    ),
            )
            .child(actions)
            .into_any_element()
    }

    // A node that holds this site: this one is marked, another opens its own page for the same site.
    // `differs` marks a node whose site only shares the id, in a warn tone, so it is not mistaken for another copy of this site.
    fn holder_chip(
        &self,
        name: &str,
        site_id: &str,
        differs: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        if name == self.detail.node {
            return tip(
                pill(name, Tone::Info),
                id("holder-tip", name),
                "This page shows this node",
            )
            .into_any_element();
        }
        let (node, site) = (name.to_string(), site_id.to_string());
        let chip = div()
            .id(id("holder", name))
            .flex()
            .items_center()
            .px(px(10.))
            .py(px(2.))
            .rounded(px(PILL_RADIUS))
            .border_1()
            .border_color(if differs {
                tint(Tone::Warn.color(), 0.5)
            } else {
                chip_stroke()
            })
            .bg(if differs {
                tint(Tone::Warn.color(), 0.12)
            } else {
                chip_fill()
            })
            .text_color(c(if differs { Tone::Warn.color() } else { DIM }))
            .text_size(px(11.))
            .cursor_pointer()
            .hover(|s| s.text_color(c(TEXT)))
            .child(name.to_string())
            .on_click(cx.listener(move |this, _, _, cx| {
                // The other node's page opens on the tab being read here.
                let tab = this.site_tab();
                this.detail.tabs.set(&node, &site, tab);
                this.navigate(
                    View::SiteDetail {
                        node: node.clone(),
                        id: site.clone(),
                    },
                    cx,
                );
            }));
        let hint = if differs {
            format!("Open on {name}: a different site with the same id")
        } else {
            format!("Open on {name}")
        };
        tip(chip, id("holder-tip", name), hint).into_any_element()
    }

    // The error of the last action, compact: the node's words, a way to its build log, and the form stays below.
    fn error_notice(&self, msg: &str, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let red = Tone::Bad.color();
        let mut actions = div().flex().items_center().gap(px(8.));
        if let Some(slot) = self.detail.error_slot.filter(|_| self.logs_offered(data)) {
            actions = actions.child(self.view_logs_button("error", slot, cx));
        }
        let text = msg.to_string();
        actions = actions
            .child(
                btn(id("detail", "error-copy"), "Copy", BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                        this.say("Copied", Tone::Ok);
                        cx.notify();
                    },
                )),
            )
            .child(
                btn(id("detail", "error-dismiss"), "Dismiss", BtnKind::Plain).on_click(
                    cx.listener(|this, _, _, cx| {
                        this.clear_error();
                        cx.notify();
                    }),
                ),
            );
        div()
            .flex()
            .items_start()
            .gap(px(12.))
            .px(px(12.))
            .py(px(10.))
            .rounded(px(ROW_RADIUS))
            .border_1()
            .border_color(tint(red, 0.5))
            .bg(tint(red, 0.08))
            .text_color(c(red))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .child(self.note_block("error-note", msg, cx)),
            )
            .child(actions)
            .into_any_element()
    }

    fn detail_body(
        &self,
        data: &Data,
        back: impl IntoElement,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let site = &data.site;
        let source = site.source.is_some();
        let form = self.form_state(data, cx);
        let tabs = visible_tabs(self.tab_offer(data));
        let tab = shown_tab(self.detail.tabs.get(&self.detail.node, &site.id), &tabs);
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(self.header(data, back, cx));
        if self.detail.busy {
            col = col.child(notice(&format!("{}...", self.detail.busy_what), Tone::Info));
        }
        if let Some(err) = &self.detail.error {
            col = col.child(self.error_notice(err, data, cx));
        }
        if let Some(e) = &self.ops.error {
            col = col.child(notice(e, Tone::Bad));
        }
        col = col.children(self.rebuild_prompt_card(cx));
        col = col.children(self.reveal_panels(&site.id, cx));
        col = col.child(self.tab_strip(&tabs, tab, source, form.change.dirty, cx));
        let mut body: Vec<AnyElement> = Vec::new();
        match tab {
            SiteTab::Overview => {
                if let Some(found) = banner(site, data.live.as_ref()) {
                    body.push(self.failure_banner(&found, self.logs_offered(data), cx));
                }
                body.extend(self.status_card(data, cx));
                body.push(
                    div()
                        .flex()
                        .gap(px(16.))
                        .child(self.slot_card(data, Slot::Blue))
                        .child(self.slot_card(data, Slot::Green))
                        .into_any_element(),
                );
                body.push(self.deploy_card(site, cx));
                body.extend(self.builds_card(data, cx));
                body.push(self.history_card(site, cx));
            }
            SiteTab::Build => {
                if source {
                    body.push(
                        card(
                            Some("Source"),
                            Some("Takes effect on the next deploy."),
                            source_fields(&self.detail.edit, HOME, &form.problems, cx),
                        )
                        .into_any_element(),
                    );
                    body.extend(self.build_cards(data, cx));
                }
                body.push(
                    card(
                        Some("Health check"),
                        Some("How the node decides a target is ready"),
                        health_fields(&self.detail.edit, &form.problems),
                    )
                    .into_any_element(),
                );
                body.push(self.save_bar(data, &form, cx));
            }
            SiteTab::Environment => body.extend(self.env_tab(data, cx)),
            SiteTab::Data => body.extend(self.data_tab(data, cx)),
            SiteTab::Volumes => {
                let bar = self.save_bar(data, &form, cx);
                body.extend(self.volumes_tab(data, bar, cx));
            }
            SiteTab::Logs => {
                if self.ops.loaded {
                    body.push(self.logs_panel(data, cx));
                } else {
                    body.push(skeleton(320.).into_any_element());
                }
            }
            SiteTab::Domains => {
                body.push(
                    card(
                        Some("General"),
                        Some("Name and kind of the site"),
                        basics(&self.detail.edit, HOME, &form.problems, true, cx),
                    )
                    .into_any_element(),
                );
                body.push(
                    card(
                        Some("Domains and routing"),
                        Some("The hosts and paths this site answers for"),
                        domains(&self.detail.edit, HOME, &form.problems, true, cx),
                    )
                    .into_any_element(),
                );
                body.push(self.save_bar(data, &form, cx));
            }
            SiteTab::Access => {
                body.push(self.access_card(data, cx));
                body.extend(self.token_card(data, cx));
                body.extend(self.outbound_card(data, cx));
                body.push(self.save_bar(data, &form, cx));
            }
            SiteTab::Danger => {
                body.push(self.maintenance_card(data, cx));
                body.push(self.danger_card(site, cx));
            }
        }
        col.child(div().flex().flex_col().gap(px(16.)).children(body))
            .into_any_element()
    }

    // The live block maps each slot to its targets, joined here by address.
    fn slot_card(&self, data: &Data, slot: Slot) -> AnyElement {
        let site = &data.site;
        let (upstream, tone) = match slot {
            Slot::Blue => (&site.blue, Tone::Blue),
            Slot::Green => (&site.green, Tone::Green),
        };
        let active = site.active == slot;
        let statuses: Vec<(String, String)> = data
            .live
            .as_ref()
            .and_then(|l| l.get(slot.as_str()))
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|e| {
                        let t =
                            |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                        (t("addr"), t("status"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut list = div().flex().flex_col().gap(px(6.));
        if upstream.targets.is_empty() {
            list = list.child(text_dim("No targets in this slot."));
        }
        for t in &upstream.targets {
            let status = statuses
                .iter()
                .find(|(a, _)| *a == t.addr)
                .map(|s| s.1.clone())
                .unwrap_or_default();
            let status_tone = if status.is_empty() {
                Tone::Muted
            } else {
                health_tone(&status)
            };
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(dot(status_tone))
                    .child(mono(t.addr.clone()).flex_1())
                    .child(text_dim(format!("weight {}", t.weight)).text_size(px(11.)))
                    .child(
                        text_dim(if status.is_empty() {
                            "unknown".into()
                        } else {
                            status
                        })
                        .text_size(px(11.)),
                    ),
            );
        }
        let title = div()
            .flex()
            .items_center()
            .gap(px(8.))
            .child(pill(slot.as_str(), tone))
            .child(
                upstream
                    .label
                    .clone()
                    .map(|l| mono(l).text_color(c(DIM)))
                    .unwrap_or_else(|| div()),
            )
            .child(div().flex_1())
            .child(if active {
                pill("Live", Tone::Ok)
            } else {
                pill("idle", Tone::Muted)
            });
        let body = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(title)
            .child(list);
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .child(card(None, None, body))
            .into_any_element()
    }

    fn deploy_card(&self, site: &Site, cx: &mut Context<Self>) -> AnyElement {
        let idle = site.active.other();
        let current = match idle {
            Slot::Blue => fmt_targets(&site.blue.targets),
            Slot::Green => fmt_targets(&site.green.targets),
        };
        let source = site.source.as_ref();
        let label = if source.is_some() {
            "Redeploy"
        } else {
            "Deploy"
        };
        let deploy = if self.detail.busy {
            btn_off(label).into_any_element()
        } else {
            btn(id("detail", "deploy"), label, BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.do_deploy(cx);
                    cx.notify();
                }))
                .into_any_element()
        };
        if let Some(src) = source {
            let branch = src.branch.clone().unwrap_or_else(|| "main".into());
            return card(
                Some("Redeploy from GitHub"),
                Some(&format!(
                    "Builds {branch} of {} into the idle {} slot on {} only, then flips traffic.",
                    src.repo,
                    idle.as_str(),
                    self.detail.node
                )),
                div()
                    .flex()
                    .items_end()
                    .gap(px(12.))
                    .child(div().flex().flex_col().flex_1().min_w_0().child(field(
                        "Note",
                        None,
                        self.detail.note.clone(),
                    )))
                    .child(deploy),
            )
            .into_any_element();
        }
        let body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(form_grid(vec![
                field(
                    "Targets for the new version",
                    Some(&format!(
                        "host:port with an optional weight, separated by commas. Idle slot: {}",
                        if current.is_empty() {
                            "empty".into()
                        } else {
                            current
                        }
                    )),
                    self.detail.targets.clone(),
                )
                .into_any_element(),
                field("Note", None, self.detail.note.clone()).into_any_element(),
            ]))
            .child(div().flex().child(deploy));
        card(
            Some("Deploy new version"),
            Some(&format!(
                "Writes the targets to the idle {} slot on {} only, then flips traffic.",
                idle.as_str(),
                self.detail.node
            )),
            body,
        )
        .into_any_element()
    }

    // Shown on Overview whenever the last deploy failed or the live slot is unhealthy; compact, with the node's note kept whole and copyable.
    fn failure_banner(&self, b: &Banner, logs_ok: bool, cx: &mut Context<Self>) -> AnyElement {
        let red = Tone::Bad.color();
        let mut head = div().flex().items_center().gap(px(8.)).child(
            div().flex().flex_col().flex_1().min_w_0().child(
                strong(b.headline.clone())
                    .text_size(px(14.))
                    .text_color(c(red)),
            ),
        );
        if logs_ok {
            head = head.child(self.view_logs_button("banner", b.logs_slot, cx));
        }
        if let Some(f) = &b.failure {
            let text = failure_text(f);
            head = head.child(
                btn(id("banner-copy", "note"), "Copy", BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                        this.say("Copied", Tone::Ok);
                        cx.notify();
                    },
                )),
            );
        }
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .p(px(14.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(tint(red, 0.6))
            .bg(tint(red, 0.08))
            .child(head);
        if let Some(f) = &b.failure {
            let when = rel_time(now_ms(), parse_rfc3339_ms(&f.at).unwrap_or(0));
            col = col
                .child(text_dim(format!("{when}, {} slot", f.slot.as_str())).text_size(px(12.)))
                .child(self.note_block("banner-note", &f.note, cx));
        }
        let mut chips = div().flex().flex_wrap().items_center().gap(px(6.));
        for line in &b.slots {
            chips = chips.child(pill(
                &format!(
                    "{} {}: {}",
                    line.slot.as_str(),
                    if line.active { "live" } else { "idle" },
                    line.state.label()
                ),
                line.state.tone(),
            ));
        }
        col.child(chips).into_any_element()
    }

    // Both choices are staged locally and only sent by Save.
    fn access_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let draft = self.detail.edit.access;
        let mut body = access_body(
            access_controls(cx, "access", draft, |c| &mut c.detail.edit.access),
            draft,
        );
        if data.site.access.zone_lock {
            body = body.child(self.zone_status_line(data.zone.as_ref()));
        }
        let busy = self.detail.busy;
        let rotate = if data.site.access.zone_lock && !busy {
            btn(
                id("detail", "rotate-zone"),
                "Rotate zone secret",
                BtnKind::Plain,
            )
            .on_click(cx.listener(|this, _, _, cx| {
                let node = this.detail.node.clone();
                this.ask(Confirm {
                    title: format!("Rotate zone secret on {node}"),
                    message: ROTATE_WARNING.into(),
                    label: "Rotate".into(),
                    danger: true,
                    action: Box::new(|this, cx| this.do_rotate_zone(cx)),
                });
                cx.notify();
            }))
            .into_any_element()
        } else {
            btn_off("Rotate zone secret").into_any_element()
        };
        body = body.child(div().flex().gap(px(8.)).child(rotate));
        body = body.children(self.bot_trust_block(data));
        card(
            Some("Access"),
            Some("Older nodes reject these fields; update the node if saving fails."),
            body,
        )
        .into_any_element()
    }

    // What the node says about the saved secret; the value itself is only ever shown right after a rotation.
    fn zone_status_line(&self, zone: Option<&ZoneStatus>) -> Div {
        let text = match zone {
            Some(z) => status_text(z),
            None => "This node does not report zone secrets.".to_string(),
        };
        let mut line = div()
            .flex()
            .flex_col()
            .gap(px(2.))
            .child(text_dim(text).text_size(px(12.)));
        if let Some(z) = zone.filter(|z| !z.header.is_empty()) {
            line = line.child(
                text_dim("Header")
                    .text_size(px(11.))
                    .child(mono(format!(" {}", z.header))),
            );
        }
        line
    }

    // One panel per rotated secret; dismissing it drops the stored value, which zeroes that copy.
    fn reveal_panels(&self, site_id: &str, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let mut panels = Vec::new();
        for reveal in reveals_for(&self.detail.reveals, &self.detail.node, site_id) {
            let (node, site) = (reveal.node.clone(), reveal.site.clone());
            let (copy_node, copy_site) = (node.clone(), site.clone());
            let steps = CLOUDFLARE_STEPS.iter().enumerate().fold(
                div().flex().flex_col().gap(px(2.)),
                |col, (i, step)| {
                    col.child(text_dim(format!("{}. {step}", i + 1)).text_size(px(12.)))
                },
            );
            let body = div()
                .flex()
                .flex_col()
                .gap(px(10.))
                .child(notice(NOT_SHOWN_AGAIN, Tone::Warn))
                .child(field("Header name", None, mono(reveal.header.clone())))
                .child(field(
                    "Secret value",
                    None,
                    mono(reveal.secret().to_string()),
                ))
                .child(steps)
                .child(
                    div()
                        .flex()
                        .gap(px(8.))
                        .child(
                            btn(
                                id("zone-copy", &reveal.node),
                                "Copy secret",
                                BtnKind::Primary,
                            )
                            .on_click(cx.listener(
                                move |this, _, _, cx| {
                                    // The value is read from the panel's state at click time, so no closure holds a copy.
                                    let found = this
                                        .detail
                                        .reveals
                                        .iter()
                                        .find(|r| r.is_for(&copy_node, &copy_site))
                                        .map(|r| r.secret().to_string());
                                    if let Some(secret) = found {
                                        cx.write_to_clipboard(gpui::ClipboardItem::new_string(
                                            secret,
                                        ));
                                        this.say("Zone secret copied", Tone::Ok);
                                    }
                                    cx.notify();
                                },
                            )),
                        )
                        .child(
                            btn(
                                id("zone-done", &reveal.node),
                                "I have saved it",
                                BtnKind::Plain,
                            )
                            .on_click(cx.listener(
                                move |this, _, _, cx| {
                                    this.detail.reveals.retain(|r| !r.is_for(&node, &site));
                                    cx.notify();
                                },
                            )),
                        ),
                );
            panels.push(
                card(
                    Some("New zone secret"),
                    Some(reveal_meta(reveal).as_str()),
                    body,
                )
                .into_any_element(),
            );
        }
        for other in reveal_nodes_elsewhere(&self.detail.reveals, &self.detail.node, site_id) {
            let (node, site) = (other.clone(), site_id.to_string());
            panels.push(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(
                        text_dim(format!(
                            "A new zone secret for this site is waiting on {other}."
                        ))
                        .text_size(px(12.)),
                    )
                    .child(
                        btn(id("zone-open", &other), "Open", BtnKind::Plain).on_click(cx.listener(
                            move |this, _, _, cx| {
                                this.navigate(
                                    View::SiteDetail {
                                        node: node.clone(),
                                        id: site.clone(),
                                    },
                                    cx,
                                );
                            },
                        )),
                    )
                    .into_any_element(),
            );
        }
        panels
    }

    // One switch per node that holds the site. Each switch writes only its own node, so one node can be taken down while another serves.
    fn maintenance_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let node = &self.detail.node;
        let peers = &self.detail.cross.peers;
        let holders = self.holders();
        let rows = maint_rows(&holders, node, &data.site, peers);
        let union = union_for(node, &data.pages, peers);
        let chosen = effective_page(&self.detail.maint_pick, &rows, &union);
        let mut options = vec![
            seg_item(id("mpage", "default"), "Built-in default", chosen.is_none())
                .on_click(cx.listener(|this, _, _, cx| {
                    this.detail.maint_pick = Some(None);
                    cx.notify();
                }))
                .into_any_element(),
        ];
        for p in &union.pages {
            let pid = p.id.clone();
            options.push(
                seg_item(
                    id("mpage", &p.id),
                    &format!("{} ({})", p.name, p.status),
                    chosen.as_deref() == Some(p.id.as_str()),
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.detail.maint_pick = Some(Some(pid.clone()));
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let different = different_holders(&data.site, node, peers, &holders);
        let is_different = |name: &str| different.iter().any(|(n, _)| n == name);
        let mut list = div().flex().flex_col().gap(px(10.));
        for row in &rows {
            let (label, tone) = if row.enabled {
                ("Maintenance", Tone::Warn)
            } else {
                ("Live", Tone::Ok)
            };
            let name = row.node.clone();
            let next = !row.enabled;
            let switch = toggle(id("maint", &row.node), row.enabled);
            let switch = if self.detail.maint_busy.contains(&row.node) {
                switch.opacity(0.5)
            } else {
                switch.on_click(cx.listener(move |this, _, _, cx| {
                    this.set_maintenance(vec![name.clone()], next, cx);
                    cx.notify();
                }))
            };
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .child(tip(
                        switch,
                        id("maint-tip", &row.node),
                        format!(
                            "Turn maintenance {} on {}",
                            if row.enabled { "off" } else { "on" },
                            row.node
                        ),
                    ))
                    .child(
                        div()
                            .flex()
                            .w(px(96.))
                            .flex_none()
                            .text_size(px(12.))
                            .text_color(c(tone.color()))
                            .child(label),
                    )
                    .child(mono(row.node.clone()))
                    .children(is_different(&row.node).then(|| {
                        tip(
                            pill("Different site", Tone::Warn),
                            id("maint-diff-tip", &row.node),
                            "It has a site with this id but different hosts. Its own switch still works.",
                        )
                    })),
            );
        }
        let mut body = div().flex().flex_col().gap(px(12.));
        if !self.detail.cross.ready {
            body = body.child(text_dim("Checking the other nodes...").text_size(px(12.)));
        }
        body = body
            .child(list)
            .child(field("Page", None, div().flex().child(seg_row(options))));
        // The everywhere buttons cover only holders that are the same site.
        let covered: Vec<&MaintRow> = rows.iter().filter(|r| !is_different(&r.node)).collect();
        if covered.len() > 1 {
            let on = covered.iter().filter(|r| r.enabled).count();
            let mut every = div().flex().gap(px(8.));
            if on < covered.len() {
                every = every.child(
                    btn(id("maint", "all-on"), "Turn on everywhere", BtnKind::Plain).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.ask_everywhere(true);
                            cx.notify();
                        }),
                    ),
                );
            }
            if on > 0 {
                every = every.child(
                    btn(
                        id("maint", "all-off"),
                        "Turn off everywhere",
                        BtnKind::Plain,
                    )
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.ask_everywhere(false);
                        cx.notify();
                    })),
                );
            }
            body = body.child(every);
        }
        card(
            Some("Maintenance"),
            Some("Each switch changes only its own node."),
            body,
        )
        .into_any_element()
    }

    // History is shown newest first.
    fn history_card(&self, site: &Site, cx: &mut Context<Self>) -> AnyElement {
        let rows: Vec<Vec<AnyElement>> = site
            .history
            .iter()
            .rev()
            .map(|d| {
                vec![
                    text_dim(rel_time(now_ms(), parse_rfc3339_ms(&d.at).unwrap_or(0)))
                        .into_any_element(),
                    action_pill(d.action),
                    slot_pill(d.slot),
                    div()
                        .flex()
                        .flex_col()
                        .child(if d.note.is_empty() {
                            "-".to_string()
                        } else {
                            split_note(&d.note).reason
                        })
                        .into_any_element(),
                    mono(d.id.clone()).text_color(c(DIM)).into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("When", 100.),
            Col::fixed("Action", 100.),
            Col::fixed("Slot", 80.),
            Col::flex("Note"),
            Col::fixed("Id", 120.),
        ];
        let rollback = btn(id("detail", "rollback"), "Roll back", BtnKind::Danger)
            .on_click(cx.listener(|this, _, _, cx| {
            let other = this
                .detail
                .data
                .ready()
                .map(|d| d.site.active.other().as_str())
                .unwrap_or("previous");
            let node = this.detail.node.clone();
            this.ask(Confirm {
                title: format!("Roll back on {node}"),
                message: format!(
                    "Return traffic on {node} to the previous version? The {other} slot becomes active again."
                ),
                label: "Roll back".into(),
                danger: true,
                action: Box::new(|this, cx| this.do_rollback(cx)),
            });
            cx.notify();
        }));
        let table = table(
            &cols,
            rows,
            Some(empty_state(
                "No deployments yet",
                "Deploy a version to start the history.",
            )),
        );
        let head = div()
            .flex()
            .items_center()
            .justify_between()
            .child(strong("Deployment history").text_size(px(14.)))
            .child(rollback);
        card(
            None,
            None,
            div()
                .flex()
                .flex_col()
                .gap(px(10.))
                .child(head)
                .child(table),
        )
        .into_any_element()
    }

    fn danger_card(&self, site: &Site, cx: &mut Context<Self>) -> AnyElement {
        let name = site.name.clone();
        let del = btn(id("detail", "delete"), "Delete site", BtnKind::Danger)
            .on_click(cx.listener(move |this, _, _, cx| {
            let node = this.detail.node.clone();
            this.ask(Confirm {
                title: format!("Delete site from {node}"),
                message: format!(
                    "This removes {name} from {node} only and stops routing its hosts there. Deployment history is lost."
                ),
                label: "Delete site".into(),
                danger: true,
                action: Box::new(|this, cx| this.do_delete(cx)),
            });
            cx.notify();
        }));
        let body = div()
            .flex()
            .items_center()
            .justify_between()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(strong(format!(
                        "Delete this site from {}",
                        self.detail.node
                    )))
                    .child(
                        text_dim("Hosts stop routing there at once. This cannot be undone.")
                            .text_size(px(12.)),
                    ),
            )
            .child(del);
        card(Some("Delete"), None, body).into_any_element()
    }
}

// What the page is waiting for, in words the owner would use.
fn busy_text(what: &str) -> &'static str {
    match what {
        "Deploy" => "Starting a build",
        "Switch" => "Switching the active slot",
        "Rollback" => "Rolling back",
        _ => "Waiting for the node",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::{DeployAction, Source, Target};
    use serde_json::json;

    fn site(id: &str, name: &str) -> Site {
        serde_json::from_value(json!({
            "id": id,
            "name": name,
            "hosts": ["a.example.com"],
            "blue": { "targets": [{ "addr": "10.0.0.1:80", "weight": 100 }] },
            "green": {},
            "active": "blue",
        }))
        .unwrap()
    }

    fn peer(node: &str, held: Option<Site>, pages: Option<Vec<MaintenancePage>>) -> Peer {
        Peer {
            node: node.into(),
            site: held,
            pages,
        }
    }

    fn page(id: &str, html: &str) -> MaintenancePage {
        MaintenancePage {
            id: id.into(),
            name: id.into(),
            html: html.into(),
            status: 503,
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn result(node: &str, outcome: Result<(), &str>) -> NodeResult {
        NodeResult {
            node: node.into(),
            outcome: outcome.map_err(str::to_string),
        }
    }

    #[test]
    fn only_other_online_nodes_are_asked() {
        let nodes = vec![
            NodeInfo {
                name: "edge-fra".into(),
                online: true,
            },
            NodeInfo {
                name: "edge-nyc".into(),
                online: true,
            },
            NodeInfo {
                name: "edge-ams".into(),
                online: false,
            },
        ];
        assert_eq!(peer_names(&nodes, "edge-fra"), names(&["edge-nyc"]));
        assert!(peer_names(&[], "edge-fra").is_empty());
    }

    #[test]
    fn a_peer_holds_the_site_only_when_its_list_names_the_id() {
        let listed = vec![site("blog", "Blog"), site("shop", "Shop")];
        let found = peer_from("edge-nyc", "shop", Some(listed.clone()), None);
        assert_eq!(found.site.map(|s| s.name), Some("Shop".to_string()));
        assert!(
            peer_from("edge-nyc", "docs", Some(listed), None)
                .site
                .is_none()
        );
        // An unreadable list is not the same as a node without the site, but neither makes it a holder.
        assert!(peer_from("edge-nyc", "shop", None, None).site.is_none());
    }

    #[test]
    fn holders_follow_the_node_order_and_always_include_this_node() {
        let peers = vec![
            peer("edge-nyc", Some(site("shop", "Shop")), None),
            peer("edge-ams", None, None),
            peer("edge-sin", Some(site("shop", "Shop")), None),
        ];
        let order = names(&["edge-sin", "edge-fra", "edge-ams", "edge-nyc"]);
        assert_eq!(
            holder_nodes("edge-fra", &peers, &order),
            names(&["edge-sin", "edge-fra", "edge-nyc"])
        );
        // Before the others answer, the page's own node is the only holder.
        assert_eq!(holder_nodes("edge-fra", &[], &order), names(&["edge-fra"]));
        // A node missing from the configured order is still listed after the rest.
        assert_eq!(
            holder_nodes("edge-fra", &peers, &names(&["edge-fra"])),
            names(&["edge-fra", "edge-nyc", "edge-sin"])
        );
    }

    fn with_hosts(hosts: &[&str], repo: Option<&str>) -> Site {
        let mut s = site("blog", "Blog");
        s.hosts = names(hosts);
        s.source = repo.map(|r| Source {
            repo: r.into(),
            ..Default::default()
        });
        s
    }

    #[test]
    fn sites_are_the_same_when_hosts_overlap_or_the_repository_matches() {
        let mine = with_hosts(&["Blog.Example.com"], Some("Acme/Blog"));
        let overlap = with_hosts(&["blog.example.com", "x.example.com"], None);
        assert_eq!(site_relation(&mine, &overlap), Relation::Same);
        let same_repo = with_hosts(&["other.example.org"], Some("acme/blog"));
        assert_eq!(site_relation(&mine, &same_repo), Relation::Same);
        let unrelated = with_hosts(&["api.example.org"], Some("acme/api"));
        assert_eq!(site_relation(&mine, &unrelated), Relation::Different);
        // Without hosts in common or two repositories to compare, nothing says they are the same site.
        let no_source = with_hosts(&["api.example.org"], None);
        assert_eq!(site_relation(&mine, &no_source), Relation::Different);
        assert_eq!(
            site_relation(&with_hosts(&[], None), &with_hosts(&[], None)),
            Relation::Different
        );
    }

    #[test]
    fn only_holders_with_an_unrelated_site_are_called_out() {
        let mine = with_hosts(&["blog.example.com"], None);
        let peers = vec![
            peer(
                "edge-nyc",
                Some(with_hosts(&["blog.example.com"], None)),
                None,
            ),
            peer(
                "edge-iad",
                Some(with_hosts(&["api.example.org"], None)),
                None,
            ),
            peer(
                "edge-ams",
                Some(with_hosts(&["zzz.example.org"], None)),
                None,
            ),
        ];
        // edge-ams is not a holder here, so it is not listed.
        let holders = names(&["edge-fra", "edge-nyc", "edge-iad"]);
        let found = different_holders(&mine, "edge-fra", &peers, &holders);
        assert_eq!(
            found,
            vec![("edge-iad".to_string(), names(&["api.example.org"]))]
        );
        assert_eq!(
            different_note("edge-iad", &names(&["api.example.org"])),
            "edge-iad has a site with this id but different hosts (api.example.org)."
        );
        assert!(different_note("edge-iad", &[]).contains("(none)"));
    }

    #[test]
    fn another_nodes_save_replaces_only_the_shared_fields() {
        let mut stored = site("shop", "Shop");
        stored.hosts = vec!["old.example.com".into()];
        stored.active = Slot::Green;
        stored.green.targets = vec![Target {
            addr: "10.9.9.9:80".into(),
            weight: 50,
        }];
        stored.source = Some(Source {
            repo: "acme/shop-fra".into(),
            ..Default::default()
        });
        stored.maintenance.enabled = true;
        let mut edited = site("shop", "Storefront");
        edited.kind = SiteKind::Api;
        edited.hosts = vec!["shop.example.com".into(), "www.example.com".into()];
        edited.path_prefixes = vec!["/api".into()];
        edited.path_regexes = vec!["^/v[0-9]+$".into()];
        edited.health.path = "/healthz".into();
        edited.access.cloudflare_only = true;
        // None of these may reach another node.
        edited.active = Slot::Blue;
        edited.blue.targets = vec![Target {
            addr: "10.1.1.1:80".into(),
            weight: 100,
        }];
        edited.source = Some(Source {
            repo: "acme/shop-nyc".into(),
            ..Default::default()
        });
        edited.volumes = vec![cite_edge::model::Volume {
            name: "data".into(),
            mount_path: "/data".into(),
        }];

        let body = shared_body(&stored, &edited);

        assert_eq!(body.name, "Storefront");
        assert_eq!(body.kind, SiteKind::Api);
        assert_eq!(body.hosts, edited.hosts);
        assert_eq!(body.path_prefixes, edited.path_prefixes);
        assert_eq!(body.path_regexes, edited.path_regexes);
        assert_eq!(body.health, edited.health);
        assert_eq!(body.access, edited.access);
        assert_eq!(body.active, Slot::Green);
        assert_eq!(body.blue, stored.blue);
        assert_eq!(body.green, stored.green);
        assert_eq!(body.source, stored.source);
        assert_eq!(body.volumes, stored.volumes);
        assert_eq!(body.maintenance, stored.maintenance);
        assert_eq!(body.history, stored.history);
    }

    #[test]
    fn saving_what_is_already_stored_changes_nothing() {
        let stored = site("shop", "Shop");
        assert_eq!(shared_body(&stored, &stored), stored);
    }

    #[test]
    fn a_save_names_every_node_and_fails_loudly_when_one_failed() {
        let ok = [result("edge-fra", Ok(())), result("edge-nyc", Ok(()))];
        assert_eq!(
            save_message(&ok, None),
            Ok("Saved on edge-fra, edge-nyc".to_string())
        );
        let mixed = [
            result("edge-fra", Ok(())),
            result("edge-nyc", Err("refused")),
        ];
        assert_eq!(
            save_message(&mixed, None),
            Err("Saved on edge-fra. Failed on edge-nyc: refused".to_string())
        );
    }

    #[test]
    fn a_redeploy_is_reported_after_the_save() {
        let ok = [result("edge-fra", Ok(()))];
        let started = Ok(started_deployment("d1".into(), Slot::Green));
        let text = save_message(&ok, Some(&started)).unwrap();
        assert!(text.starts_with("Saved on edge-fra. Build started on the green slot"));
        let refused: Result<Deployment, String> = Err("no capacity".into());
        assert_eq!(
            save_message(&ok, Some(&refused)),
            Err("Saved on edge-fra. The redeploy failed: no capacity".to_string())
        );
        let failed = Ok(Deployment {
            id: "d2".into(),
            at: "2026-01-02T03:04:05Z".into(),
            slot: Slot::Green,
            action: DeployAction::Failed,
            note: "boom".into(),
        });
        let text = save_message(&ok, Some(&failed)).unwrap_err();
        assert!(text.starts_with("Saved on edge-fra. The deploy failed: boom"));
    }

    #[test]
    fn each_nodes_maintenance_state_comes_from_its_own_copy() {
        let mut here = site("shop", "Shop");
        here.maintenance.enabled = true;
        here.maintenance.page_id = Some("soon".into());
        let mut there = site("shop", "Shop");
        there.maintenance.page_id = Some("sale".into());
        let peers = vec![
            peer("edge-nyc", Some(there), None),
            peer("edge-ams", None, None),
        ];
        let holders = names(&["edge-fra", "edge-nyc"]);
        let rows = maint_rows(&holders, "edge-fra", &here, &peers);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].node, "edge-fra");
        assert!(rows[0].enabled);
        assert_eq!(rows[0].page_id.as_deref(), Some("soon"));
        assert!(!rows[1].enabled);
        assert_eq!(rows[1].page_id.as_deref(), Some("sale"));
    }

    #[test]
    fn the_page_chooser_shows_the_pick_or_the_page_already_served() {
        let union = union_for(
            "edge-fra",
            &[page("soon", "a")],
            &[peer("edge-nyc", None, Some(vec![page("sale", "b")]))],
        );
        let row = |node: &str, page_id: Option<&str>| MaintRow {
            node: node.into(),
            enabled: false,
            page_id: page_id.map(str::to_string),
        };
        let rows = [row("edge-fra", None), row("edge-nyc", Some("sale"))];
        assert_eq!(
            effective_page(&None, &rows, &union).as_deref(),
            Some("sale")
        );
        assert_eq!(
            effective_page(&Some(Some("soon".into())), &rows, &union).as_deref(),
            Some("soon")
        );
        // Picking the built-in page wins over a page a node already serves.
        assert_eq!(effective_page(&Some(None), &rows, &union), None);
        // A page no node holds any more is never shown as chosen.
        assert_eq!(
            effective_page(&Some(Some("gone".into())), &rows, &union),
            None
        );
    }

    #[test]
    fn turning_off_keeps_the_page_the_node_serves() {
        assert_eq!(
            maint_page_for(true, Some("soon"), Some("sale")).as_deref(),
            Some("soon")
        );
        assert_eq!(
            maint_page_for(false, Some("soon"), Some("sale")).as_deref(),
            Some("sale")
        );
        assert_eq!(
            maint_page_for(false, Some("soon"), None).as_deref(),
            Some("soon")
        );
        assert_eq!(maint_page_for(true, None, Some("sale")), None);
    }

    #[test]
    fn a_node_without_the_chosen_page_is_found_across_all_nodes_pages() {
        let peers = vec![
            peer("edge-nyc", None, Some(vec![])),
            peer("edge-ams", None, None),
        ];
        let union = union_for("edge-fra", &[page("soon", "<p>soon</p>")], &peers);
        assert_eq!(union.pages.len(), 1);
        assert_eq!(
            nodes_needing_page(
                &union,
                "soon",
                &names(&["edge-fra", "edge-nyc", "edge-ams"])
            ),
            names(&["edge-nyc"])
        );
        let entry = &union.pages[0];
        let created = page_from_union(entry);
        assert_eq!(created, page("soon", "<p>soon</p>"));
    }

    #[test]
    fn the_maintenance_toast_names_the_nodes_and_the_failures() {
        let results = [
            result("edge-fra", Ok(())),
            result("edge-nyc", Ok(())),
            result("edge-ams", Err("page refused")),
        ];
        assert_eq!(
            maint_message(true, &results),
            "Maintenance enabled on edge-fra, edge-nyc. Failed on edge-ams: page refused"
        );
        assert_eq!(
            maint_message(false, &results[..1]),
            "Maintenance disabled on edge-fra"
        );
    }

    #[test]
    fn open_goes_to_the_first_concrete_host() {
        let hosts = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            open_url(&hosts(&["*.example.com", " docs.example.com "])).as_deref(),
            Some("https://docs.example.com")
        );
        assert_eq!(open_url(&hosts(&["*.example.com"])), None);
        assert_eq!(open_url(&[]), None);
    }

    #[test]
    fn a_reload_of_the_shown_site_keeps_the_page() {
        assert!(keeps_page(true, Some("blog"), "blog"));
        assert!(!keeps_page(true, None, "blog"));
        assert!(!keeps_page(false, Some("blog"), "blog"));
        assert!(!keeps_page(true, Some("shop"), "blog"));
    }
}
