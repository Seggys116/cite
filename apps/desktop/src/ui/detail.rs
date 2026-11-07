use std::future::Future;

use cite_client::{ClientError, DeployRequest};
use cite_edge::model::{Deployment, MaintenancePage, Site, SiteKind, Slot, TlsMode};
use gpui::{AnyElement, ClipboardItem, Context, Div, Entity, div, prelude::*, px};
use serde_json::Value;

use crate::app::{Confirm, Console, Load, View, new_input};
use crate::certs::zone_newly_enabled;
use crate::demo::now_ms;
use crate::diagnose::{
    started_deployment,
    Banner, NOTE_PREVIEW, banner, deploy_outcome, failure_text, save_outcome, shown_output,
    slot_lines, split_note,
};
use crate::model::{
    SiteChange, draft_from_site, edit_site, fmt_targets, parse_rfc3339_ms, parse_targets, rel_time,
    site_change, source_deploy_request,
};
use crate::scope::{error_survives, foreign_notice};
use crate::siteops::{
    CAP_BUILD_ENV, CAP_LOGS, CAP_RUNTIME_ENV, CAP_VOLUMES, has_cap, is_busy_phase,
};
use crate::theme::{BORDER, CARD_RADIUS, DIM, ROW_RADIUS, SURFACE, Tone, c, tint};
use crate::ui::certs::{access_body, access_controls};
use crate::ui::input::TextInput;
use crate::ui::overview::{action_pill, slot_pill};
use crate::ui::paths::PathRow;
use crate::ui::siteform::{Home, SiteFields, basics, domains, health_fields, source_fields};
use crate::ui::sites::health_tone;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, code_block, dot, empty_state, field, form_grid, id, mono,
    notice, page_header, pill, seg_item, seg_row, skeleton, strong, table, text_dim, toggle,
};
use crate::wizard::{FieldProblems, field_problems};
use crate::zone::{
    CLOUDFLARE_STEPS, NOT_SHOWN_AGAIN, ROTATE_WARNING, ZoneReveal, ZoneStatus, reveal_meta,
    reveal_nodes_elsewhere, reveals_for, rotation_failed, status_text,
};

// The site page's own parts live beside this file; they are declared here so the page stays one module tree.
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

// A new zone secret (or why none came) and the outcome of a redeploy, when one was asked for.
type SaveDone = (
    Option<Result<ZoneReveal, String>>,
    Option<Result<Deployment, String>>,
);

pub struct Data {
    pub site: Site,
    pub live: Option<Value>,
    pub pages: Vec<MaintenancePage>,
    pub zone: Option<ZoneStatus>,
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
    pub maint_enabled: bool,
    pub maint_page: Option<String>,
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
            maint_enabled: false,
            maint_page: None,
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
                this.detail.maint_enabled = data.site.maintenance.enabled;
                this.detail.maint_page = data.site.maintenance.page_id.clone();
                this.refill_edit(&data.site, cx);
                this.load_ops(ops_node, ops_site, data.site.source.is_some(), cx);
            }
            this.detail.data = Load::from_result(res);
            cx.notify();
        });
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
            return TabOffer {
                source,
                env: true,
                logs: true,
                volumes: volumes::volumes_apply(&data.site),
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
        let fut = async move { h.switch(&site.id, target).await };
        self.site_action(cx, "Switch", fut, None, move |_| {
            Ok(format!("{} is now active", target.as_str()))
        });
    }

    fn do_rollback(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let fut = async move { h.rollback(&site.id).await };
        self.site_action(cx, "Rollback", fut, None, |_| Ok("Rolled back".into()));
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
        let fut = async move {
            if from_source {
                let note = req.note.clone();
                let id = h.deploy_async(&site.id, None, note.as_deref()).await?;
                Ok(started_deployment(id, idle))
            } else {
                h.deploy(&site.id, &req).await
            }
        };
        self.site_action(cx, "Deploy", fut, logs_slot, deploy_outcome);
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

    // Saves the whole form through the normal site update; with redeploy it then starts a deploy so a source change takes effect.
    // Turning the zone lock on rotates in a secret right after the save, because the node only shows it when asked.
    // The stored GitHub token is never sent: the node keeps it.
    fn do_save(&mut self, redeploy: bool, cx: &mut Context<Self>) {
        let Some((h, existing)) = self.site_handle() else {
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
        let rotate = zone_newly_enabled(&existing.access, &edited.access);
        // A saved source change is not in the running build, so the owner is asked about a rebuild afterwards.
        let ask_rebuild = !redeploy
            && existing.source.is_some()
            && site_change(&existing, &edited).needs_redeploy;
        let req = source_deploy_request(
            Some(self.detail.note.read(cx).text().trim().to_string()).filter(|n| !n.is_empty()),
        );
        let idle = existing.active.other();
        self.detail.busy = true;
        self.detail.busy_what = if redeploy { "Saving, then starting a build" } else { "Saving the site" };
        self.clear_error();
        let fut = async move {
            h.update_site(&edited.id, &edited).await?;
            let reveal = if rotate {
                Some(
                    h.rotate_zone_secret(&edited.id)
                        .await
                        .map_err(|e| e.to_string()),
                )
            } else {
                None
            };
            let deploy = if redeploy {
                let started = if edited.source.is_some() {
                    h.deploy_async(&edited.id, None, req.note.as_deref())
                        .await
                        .map(|id| started_deployment(id, idle))
                } else {
                    h.deploy(&edited.id, &req).await
                };
                Some(started.map_err(|e| e.to_string()))
            } else {
                None
            };
            Ok((reveal, deploy))
        };
        self.fetch_origin(
            cx,
            fut,
            move |this, res: Result<SaveDone, ClientError>, here, origin, cx| {
                const WHAT: &str = "Save site";
                let saved = res.is_ok();
                let deploy_slot = match &res {
                    Ok((_, Some(Ok(d)))) => Some(d.slot),
                    Ok((_, Some(Err(_)))) => Some(idle),
                    _ => None,
                };
                let (reveal, outcome) = match res {
                    Ok((reveal, deploy)) => (reveal, save_outcome(deploy.as_ref())),
                    Err(e) => (None, Err(e.to_string())),
                };
                if here && saved {
                    this.ops.volumes.clear_edits();
                }
                if here && saved && ask_rebuild {
                    this.ops.rebuild_prompt = true;
                }
                let mut warn = None;
                match reveal {
                    Some(Ok(r)) => this.keep_reveal(r),
                    Some(Err(e)) => warn = Some(rotation_failed(&e)),
                    None => {}
                }
                this.detail.busy = false;
                if !here {
                    // A secret for another place is kept under its own node and site and shown only there.
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
                this.detail.busy = false;
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
        let explain = if data.site.source.is_some() {
            "Routing, health check and access apply at once. Repository, build settings and resources take effect on the next deploy; Save and redeploy builds the branch again. The stored GitHub token is kept."
        } else {
            "Saved settings apply to routing at once. To change the targets, deploy new ones on the Overview tab."
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
                        this.keep_reveal(reveal);
                        this.say("Zone secret rotated", Tone::Ok);
                    }
                    Err(e) => this.fail(e.to_string(), None),
                }
                this.reload_detail(cx);
                cx.notify();
            },
        );
    }

    fn do_maintenance(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let (enabled, page) = (self.detail.maint_enabled, self.detail.maint_page.clone());
        let fut = async move { h.maintenance(&site.id, enabled, page.as_deref()).await };
        self.site_action(cx, "Maintenance change", fut, None, move |_| {
            Ok(if enabled {
                "Maintenance mode enabled".into()
            } else {
                "Maintenance mode disabled".into()
            })
        });
    }

    // Deleting leaves the page, so it navigates instead of reloading.
    fn do_delete(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let name = site.name.clone();
        self.detail.busy = true;
        self.detail.busy_what = "Deleting the site";
        self.fetch_origin(
            cx,
            async move { h.delete_site(&site.id).await },
            move |this, res, here, origin, cx| {
                this.detail.busy = false;
                if !here {
                    let (text, tone) = match res {
                        Ok(()) => (format!("Site {name} deleted"), Tone::Ok),
                        Err(e) => (e.to_string(), Tone::Bad),
                    };
                    this.say(foreign_notice("Delete", origin, &text), tone);
                    cx.notify();
                    return;
                }
                this.detail.busy = false;
                match res {
                    Ok(()) => {
                        this.say(format!("Site {name} deleted"), Tone::Ok);
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
                this.ask(Confirm {
                    title: "Switch active slot".into(),
                    message: format!(
                        "Send all traffic for {name} to the {} slot now?",
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
                            .child(
                                mono(format!("{} on {}", site.id, self.detail.node))
                                    .text_size(px(11.))
                                    .text_color(c(DIM)),
                            ),
                    ),
            )
            .child(actions)
            .into_any_element()
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
                            Some("Where the node builds this site from. Changes take effect on the next deploy."),
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
                pill("LIVE", Tone::Ok)
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
                    "The node fetches {} of {} again, builds it in the idle {} slot, health checks it, then flips traffic over.",
                    branch,
                    src.repo,
                    idle.as_str()
                )),
                div()
                    .flex()
                    .items_end()
                    .gap(px(12.))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(field("Note", None, self.detail.note.clone())),
                    )
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
                    Some(&format!("host:port with an optional weight, separated by commas. Idle slot now holds: {}", if current.is_empty() { "nothing".into() } else { current })),
                    self.detail.targets.clone(),
                )
                .into_any_element(),
                field("Note", None, self.detail.note.clone()).into_any_element(),
            ]))
            .child(div().flex().child(deploy));
        card(
            Some("Deploy new version"),
            Some(&format!(
                "Targets are written to the idle {} slot, health checked, then traffic flips over.",
                idle.as_str()
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
                this.ask(Confirm {
                    title: "Rotate zone secret".into(),
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
            Some("Saved with the Save bar below. Older nodes reject these fields: if saving fails, update the node."),
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

    // The toggle and page choice are staged locally and only sent by Apply.
    fn maintenance_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let enabled = self.detail.maint_enabled;
        let mut options = vec![
            seg_item(
                id("mpage", "default"),
                "Built-in default",
                self.detail.maint_page.is_none(),
            )
            .on_click(cx.listener(|this, _, _, cx| {
                this.detail.maint_page = None;
                cx.notify();
            }))
            .into_any_element(),
        ];
        for p in &data.pages {
            let pid = p.id.clone();
            options.push(
                seg_item(
                    id("mpage", &p.id),
                    &format!("{} ({})", p.name, p.status),
                    self.detail.maint_page.as_deref() == Some(&p.id),
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.detail.maint_page = Some(pid.clone());
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let switch =
            toggle(id("detail", "maint"), enabled).on_click(cx.listener(|this, _, _, cx| {
                this.detail.maint_enabled = !this.detail.maint_enabled;
                cx.notify();
            }));
        let apply = btn(id("detail", "apply-maint"), "Apply", BtnKind::Primary).on_click(
            cx.listener(|this, _, _, cx| {
                this.do_maintenance(cx);
                cx.notify();
            }),
        );
        let current = if data.site.maintenance.enabled {
            "Currently enabled"
        } else {
            "Currently disabled"
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .child(switch)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(strong("Serve the maintenance page"))
                            .child(text_dim(current).text_size(px(12.))),
                    ),
            )
            .child(field("Page", None, div().flex().child(seg_row(options))))
            .child(div().flex().child(apply));
        card(
            Some("Maintenance mode"),
            Some(
                "Visitors see the chosen page with its status code while upstreams stay untouched.",
            ),
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
            this.ask(Confirm {
                title: "Roll back".into(),
                message: format!(
                    "Return traffic to the previous version? The {other} slot becomes active again."
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
            this.ask(Confirm {
                title: "Delete site".into(),
                message: format!(
                    "This removes {name} and stops routing its hosts. Deployment history is lost."
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
                    .child(strong("Delete this site"))
                    .child(
                        text_dim("Hosts stop routing immediately. This cannot be undone.")
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
        "Maintenance change" => "Changing maintenance mode",
        _ => "Waiting for the node",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
