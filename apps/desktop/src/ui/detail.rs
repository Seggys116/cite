use std::future::Future;

use cite_client::{ClientError, DeployRequest};
use cite_edge::model::{Deployment, MaintenancePage, Site, SiteKind, Slot, TlsMode};
use gpui::{AnyElement, ClipboardItem, Context, Div, Entity, div, prelude::*, px};
use serde_json::Value;

use crate::app::{Confirm, Console, Load, View, new_input};
use crate::certs::zone_newly_enabled;
use crate::demo::now_ms;
use crate::diagnose::{Banner, NO_REASON_NOTE, banner, deploy_outcome, failure_text, save_outcome};
use crate::model::{
    draft_from_site, edit_site, fmt_targets, parse_rfc3339_ms, parse_targets, rel_time,
    site_change, source_deploy_request,
};
use crate::scope::{error_survives, foreign_notice};
use crate::theme::{CARD_RADIUS, DIM, Tone, c, tint};
use crate::ui::certs::{access_body, access_controls};
use crate::ui::input::TextInput;
use crate::ui::overview::{action_pill, slot_pill};
use crate::ui::paths::PathRow;
use crate::ui::siteform::{Home, SiteFields, basics, domains, health_fields, source_fields};
use crate::ui::sites::health_tone;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, dot, empty_state, field, id, mono, notice, page_header, pill,
    seg_item, seg_row, skeleton, strong, table, text_dim, toggle,
};
use crate::wizard::field_problems;
use crate::zone::{
    CLOUDFLARE_STEPS, NOT_SHOWN_AGAIN, ROTATE_WARNING, ZoneReveal, ZoneStatus, reveal_meta,
    reveal_nodes_elsewhere, reveals_for, rotation_failed, status_text,
};

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
    pub error: Option<String>,
    pub maint_enabled: bool,
    pub maint_page: Option<String>,
    // The edit form, built from the same fields as the create wizard.
    pub edit: SiteFields,
    // The site the form was last filled from, to tell a reload apart from unsaved edits.
    pub edit_base: Option<Site>,
    // The node and site id the form belongs to, so edits never carry over to another site.
    pub edit_for: (String, String),
    pub reveals: Vec<ZoneReveal>,
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
            error: None,
            maint_enabled: false,
            maint_page: None,
            edit: SiteFields::new(cx),
            edit_base: None,
            edit_for: (String::new(), String::new()),
            reveals: Vec::new(),
        }
    }
}

impl Console {
    // The site and its maintenance pages load together so the form is complete on first paint.
    pub fn load_detail(&mut self, node: String, site_id: String, cx: &mut Context<Self>) {
        self.detail.data = Load::Loading;
        // An action's error must still be on screen after the reload that follows it, so it is cleared only for another site.
        if !error_survives(&self.detail.node, &self.detail.site_id, &node, &site_id) {
            self.detail.error = None;
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

    // Runs a mutation, then reloads the site so the page always shows the node's own state.
    // If the user has moved to another site or node by the time the node answers, the outcome is a toast naming the place and the page is left alone.
    fn site_action<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        what: &'static str,
        fut: F,
        outcome: impl FnOnce(&T) -> Result<String, String> + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        self.detail.busy = true;
        self.detail.error = None;
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            let result = res.map_err(|e| e.to_string()).and_then(|v| outcome(&v));
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
                Err(msg) => this.detail.error = Some(msg),
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
        self.site_action(cx, "Switch", fut, move |_| {
            Ok(format!("{} is now active", target.as_str()))
        });
    }

    fn do_rollback(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let fut = async move { h.rollback(&site.id).await };
        self.site_action(cx, "Rollback", fut, |_| Ok("Rolled back".into()));
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
                    self.detail.error = Some("Add at least one target to deploy.".into());
                    return;
                }
                Err(e) => {
                    self.detail.error = Some(e);
                    return;
                }
            }
        };
        let fut = async move { h.deploy(&site.id, &req).await };
        self.site_action(cx, "Deploy", fut, deploy_outcome);
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
        self.detail.error = None;
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
            Ok(s) => s,
            Err(e) => {
                self.detail.error = Some(e);
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
        self.detail.busy = true;
        self.detail.error = None;
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
                Some(h.deploy(&edited.id, &req).await.map_err(|e| e.to_string()))
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
                let (reveal, outcome) = match res {
                    Ok((reveal, deploy)) => (reveal, save_outcome(deploy.as_ref())),
                    Err(e) => (None, Err(e.to_string())),
                };
                if here && saved && ask_rebuild {
                    this.ops.rebuild_prompt = true;
                }
                let mut warn = None;
                match reveal {
                    Some(Ok(r)) => this.keep_reveal(r),
                    Some(Err(e)) => warn = Some(rotation_failed(&e)),
                    None => {}
                }
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
                    (Ok(t), Some(w)) => this.detail.error = Some(format!("{t} {w}")),
                    (Err(t), w) => {
                        this.detail.error = Some(match w {
                            Some(w) => format!("{t} {w}"),
                            None => t,
                        })
                    }
                }
                this.reload_detail(cx);
                cx.notify();
            },
        );
    }

    // Everything the node accepts on a site, from the same fields the create wizard uses.
    fn edit_cards(&self, data: &Data, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let f = &self.detail.edit;
        let draft = f.draft(cx);
        let problems = field_problems(&draft, false);
        let mut cards = vec![
            card(
                Some("General"),
                Some("Name, kind and the domains and paths this site answers for"),
                div()
                    .flex()
                    .flex_col()
                    .gap(px(16.))
                    .child(basics(f, HOME, &problems, true, cx))
                    .child(domains(f, HOME, &problems, true, cx)),
            )
            .into_any_element(),
        ];
        if data.site.source.is_some() {
            cards.push(
                card(
                    Some("Source"),
                    Some("Where the node builds this site from. Changes take effect on the next deploy."),
                    source_fields(f, HOME, &problems, cx),
                )
                .into_any_element(),
            );
            cards.extend(self.build_card(data, cx));
        }
        cards.push(
            card(
                Some("Health check"),
                Some("How the node decides a target is ready"),
                health_fields(f, &problems),
            )
            .into_any_element(),
        );
        cards.push(self.access_card(data, cx));
        cards.push(self.save_bar(data, &draft, &problems, cx));
        cards
    }

    // One Save for the whole form, with what it will do spelled out under the buttons.
    fn save_bar(
        &self,
        data: &Data,
        draft: &crate::model::SiteDraft,
        problems: &crate::wizard::FieldProblems,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let edited = edit_site(&data.site, draft);
        let change = edited
            .as_ref()
            .map(|e| site_change(&data.site, e))
            .unwrap_or(crate::model::SiteChange {
                dirty: true,
                needs_redeploy: false,
            });
        let blocker = problems
            .first()
            .cloned()
            .or_else(|| edited.as_ref().err().cloned());
        let busy = self.detail.busy;
        let can_save = !busy && change.dirty && blocker.is_none();
        let save = if can_save {
            btn(id("detail", "save"), "Save", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.do_save(false, cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Save").into_any_element()
        };
        let mut row = div().flex().items_center().gap(px(8.)).child(save);
        let redeploy = data.site.source.is_some() && change.needs_redeploy;
        if redeploy {
            row = row.child(if can_save {
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
        if change.dirty && !busy {
            row = row.child(pill("Unsaved changes", Tone::Warn)).child(
                btn(id("detail", "discard"), "Discard changes", BtnKind::Plain).on_click(
                    cx.listener(|this, _, _, cx| {
                        this.discard_edits(cx);
                        cx.notify();
                    }),
                ),
            );
        }
        let explain = if data.site.source.is_some() {
            "Save stores the settings on the node. Routing, health check and access apply at once; a change to the repository, branch, runtime, Node version, poll interval, build settings or resources only takes effect on the next deploy. Save and redeploy stores everything and then builds the branch again. The stored GitHub token is kept."
        } else {
            "Save stores the settings on the node and they apply to routing at once. To change the targets, deploy new ones below."
        };
        let mut col = div().flex().flex_col().gap(px(8.)).child(row);
        if let Some(b) = blocker.filter(|_| change.dirty) {
            col = col.child(
                text_dim(b)
                    .text_size(px(12.))
                    .text_color(c(Tone::Bad.color())),
            );
        }
        card(None, None, col.child(text_dim(explain).text_size(px(12.)))).into_any_element()
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
        self.detail.error = None;
        self.fetch_origin(
            cx,
            async move { h.rotate_zone_secret(&site.id).await },
            |this, res, here, origin, cx| {
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
                    Err(e) => this.detail.error = Some(e.to_string()),
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
        self.site_action(cx, "Maintenance change", fut, move |_| {
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
        self.fetch_origin(
            cx,
            async move { h.delete_site(&site.id).await },
            move |this, res, here, origin, cx| {
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
                    Err(e) => this.detail.error = Some(e.to_string()),
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

    fn detail_body(
        &self,
        data: &Data,
        back: impl IntoElement,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let site = &data.site;
        let idle = site.active.other();
        let busy = self.detail.busy;
        let switch = btn(
            id("detail", "switch"),
            &format!("Switch to {}", idle.as_str()),
            BtnKind::Primary,
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
        }));
        let pills = div()
            .flex()
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
            )
            .child(mono(format!("{} on {}", site.id, self.detail.node)).text_color(c(DIM)));
        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(strong(site.name.clone()).text_size(px(22.)))
                    .child(pills),
            )
            .child(div().flex().gap(px(8.)).child(back).child(switch));
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
        if busy {
            col = col.child(notice("Working on the node...", Tone::Info));
        }
        if let Some(err) = &self.detail.error {
            col = col.child(notice(err, Tone::Bad));
        }
        if let Some(found) = banner(site, data.live.as_ref()) {
            col = col.child(self.failure_banner(&found, cx));
        }
        col = col.children(self.status_card(data, cx));
        col = col.children(self.rebuild_prompt_card(cx));
        col = col.children(self.reveal_panels(&site.id, cx));
        col = col
            .child(
                div()
                    .flex()
                    .gap(px(16.))
                    .child(self.slot_card(data, Slot::Blue))
                    .child(self.slot_card(data, Slot::Green)),
            )
            .child(self.deploy_card(site, cx))
            .children(self.edit_cards(data, cx))
            .children(self.ops_cards(data, cx))
            .child(self.maintenance_card(data, cx))
            .child(self.history_card(site, cx))
            .child(self.danger_card(site, cx));
        col.into_any_element()
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
        let deploy = btn(id("detail", "deploy"), label, BtnKind::Primary).on_click(cx.listener(
            |this, _, _, cx| {
                this.do_deploy(cx);
                cx.notify();
            },
        ));
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
                    .flex_col()
                    .gap(px(12.))
                    .child(field("Note", None, self.detail.note.clone()))
                    .child(div().flex().child(deploy)),
            )
            .into_any_element();
        }
        let body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field(
                "Targets for the new version",
                Some(&format!("host:port with an optional weight, separated by commas. Idle slot now holds: {}", if current.is_empty() { "nothing".into() } else { current })),
                self.detail.targets.clone(),
            ))
            .child(field("Note", None, self.detail.note.clone()))
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

    // A Copy button that puts the given text on the clipboard.
    fn copy_button(
        &self,
        key: String,
        label: &str,
        text: String,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        btn(id("banner-copy", key), label, BtnKind::Plain)
            .on_click(cx.listener(move |this, _, _, cx| {
                cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                this.say("Copied", Tone::Ok);
                cx.notify();
            }))
            .into_any_element()
    }

    // Shown first whenever the last deploy failed or the live slot is unhealthy; the node's note is kept whole and copyable.
    fn failure_banner(&self, b: &Banner, cx: &mut Context<Self>) -> AnyElement {
        let red = Tone::Bad.color();
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .p(px(14.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(tint(red, 0.6))
            .bg(tint(red, 0.08))
            .child(
                strong(b.headline.clone())
                    .text_size(px(15.))
                    .text_color(c(red)),
            );
        if let Some(f) = &b.failure {
            let when = rel_time(now_ms(), parse_rfc3339_ms(&f.at).unwrap_or(0));
            col = col.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(
                        text_dim(format!("{when} - the {} slot", f.slot.as_str()))
                            .text_size(px(12.)),
                    )
                    .child(mono(f.note.clone()))
                    .child(div().flex().child(self.copy_button(
                        "note".into(),
                        "Copy the node's note",
                        failure_text(f),
                        cx,
                    ))),
            );
        }
        let mut slots = div().flex().flex_col().gap(px(6.));
        for line in &b.slots {
            let mut row = div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(8.))
                .child(slot_pill(line.slot))
                .child(text_dim(format!(
                    "{}: {}",
                    if line.active { "active" } else { "idle" },
                    line.state.label()
                )));
            for t in &line.targets {
                row = row.child(pill(
                    &format!("{} {}", t.addr, t.status),
                    health_tone(&t.status),
                ));
            }
            slots = slots.child(row);
        }
        col = col
            .child(slots)
            .child(text_dim(NO_REASON_NOTE).text_size(px(12.)));
        if !b.checks.is_empty() {
            let mut list = div().flex().flex_col().gap(px(4.));
            for (i, check) in b.checks.iter().enumerate() {
                list = list.child(text_dim(format!("{}. {check}", i + 1)).text_size(px(12.)));
            }
            col = col
                .child(strong("What to check").text_size(px(13.)))
                .child(list);
        }
        for (i, cmd) in b.commands.iter().enumerate() {
            col = col.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(strong(format!(
                                "{} ({} slot)",
                                cmd.label,
                                cmd.slot.as_str()
                            )))
                            .child(text_dim(cmd.explains).text_size(px(12.))),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(div().flex_1().child(mono(cmd.command.clone())))
                            .child(self.copy_button(
                                format!("cmd-{i}"),
                                "Copy",
                                cmd.command.clone(),
                                cx,
                            )),
                    ),
            );
        }
        col.into_any_element()
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
            Some("Saved with the rest of the form. Older nodes reject these fields: if saving fails, update the node."),
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
                        .child(if d.note.is_empty() {
                            "-".to_string()
                        } else {
                            d.note.clone()
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
        let rollback = btn(id("detail", "rollback"), "Roll back", BtnKind::Danger).on_click(
            cx.listener(|this, _, _, cx| {
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
            }),
        );
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
            .child(strong("History").text_size(px(14.)))
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
        let del = btn(id("detail", "delete"), "Delete site", BtnKind::Danger).on_click(
            cx.listener(move |this, _, _, cx| {
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
            }),
        );
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
        card(Some("Danger zone"), None, body).into_any_element()
    }
}
