use std::future::Future;

use cite_client::{ClientError, DeployRequest};
use cite_edge::model::{MaintenancePage, Site, SiteKind, Slot};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};
use serde_json::Value;

use crate::app::{Confirm, Console, Load, View, new_input};
use crate::demo::now_ms;
use crate::model::{fmt_targets, parse_rfc3339_ms, parse_targets, rel_time};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::overview::{action_pill, slot_pill};
use crate::ui::sites::health_tone;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, dot, empty_state, field, id, mono, notice, page_header, pill,
    seg_item, seg_row, skeleton, strong, table, text_dim, toggle,
};

pub struct Data {
    pub site: Site,
    pub live: Option<Value>,
    pub pages: Vec<MaintenancePage>,
}

pub struct State {
    pub data: Load<Data>,
    pub node: String,
    pub targets: Entity<TextInput>,
    pub note: Entity<TextInput>,
    pub busy: bool,
    pub error: Option<String>,
    pub maint_enabled: bool,
    pub maint_page: Option<String>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            node: String::new(),
            targets: new_input(cx, "10.0.0.12:8080, 10.0.0.13:8080 50", |i| i.mono()),
            note: new_input(cx, "Release notes (optional)", |i| i),
            busy: false,
            error: None,
            maint_enabled: false,
            maint_page: None,
        }
    }
}

impl Console {
    // The site and its maintenance pages load together so the form is complete on first paint.
    pub fn load_detail(&mut self, node: String, site_id: String, cx: &mut Context<Self>) {
        self.detail.data = Load::Loading;
        self.detail.node = node.clone();
        self.detail.error = None;
        let Some(h) = self.handle_named(&node) else {
            self.detail.data = Load::Failed(format!("Node {node} is not connected."));
            return;
        };
        let fut = async move {
            let detail = h.get_site(&site_id).await?;
            let pages = h.list_pages().await.unwrap_or_default();
            Ok(Data {
                site: detail.site,
                live: detail.live,
                pages,
            })
        };
        self.fetch(cx, fut, |this, res, cx| {
            if let Ok(data) = &res {
                this.detail.maint_enabled = data.site.maintenance.enabled;
                this.detail.maint_page = data.site.maintenance.page_id.clone();
            }
            this.detail.data = Load::from_result(res);
            cx.notify();
        });
    }

    // Runs a mutation, then reloads the site so the page always shows the node's own state.
    fn site_action<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        fut: F,
        outcome: impl FnOnce(&T) -> Result<String, String> + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        self.detail.busy = true;
        self.detail.error = None;
        self.fetch(cx, fut, move |this, res, cx| {
            this.detail.busy = false;
            match res.map_err(|e| e.to_string()).and_then(|v| outcome(&v)) {
                Ok(msg) => this.say(msg, Tone::Ok),
                Err(msg) => this.detail.error = Some(msg),
            }
            if let View::SiteDetail { node, id } = this.view.clone() {
                this.load_detail(node, id, cx);
            }
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
        self.site_action(cx, fut, move |_| {
            Ok(format!("{} is now active", target.as_str()))
        });
    }

    fn do_rollback(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let fut = async move { h.rollback(&site.id).await };
        self.site_action(cx, fut, |_| Ok("Rolled back".into()));
    }

    // Deploy waits on health checks, so the busy notice stays up until the node answers.
    fn do_deploy(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let targets = match parse_targets(self.detail.targets.read(cx).text()) {
            Ok(t) if !t.is_empty() => t,
            Ok(_) => {
                self.detail.error = Some("Add at least one target to deploy.".into());
                return;
            }
            Err(e) => {
                self.detail.error = Some(e);
                return;
            }
        };
        let note = self.detail.note.read(cx).text().trim().to_string();
        let idle = site.active.other();
        let req = DeployRequest {
            targets,
            note: Some(note).filter(|n| !n.is_empty()),
        };
        let fut = async move { h.deploy(&site.id, &req).await };
        self.site_action(cx, fut, move |dep| {
            if dep.action == cite_edge::model::DeployAction::Failed {
                Err("Health checks did not pass. The active slot was left untouched.".into())
            } else {
                Ok(format!("Deployed. {} is now active.", idle.as_str()))
            }
        });
    }

    fn do_maintenance(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.site_handle() else {
            return;
        };
        let (enabled, page) = (self.detail.maint_enabled, self.detail.maint_page.clone());
        let fut = async move { h.maintenance(&site.id, enabled, page.as_deref()).await };
        self.site_action(cx, fut, move |_| {
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
        self.fetch(
            cx,
            async move { h.delete_site(&site.id).await },
            move |this, res, cx| {
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
        col = col
            .child(
                div()
                    .flex()
                    .gap(px(16.))
                    .child(self.slot_card(data, Slot::Blue))
                    .child(self.slot_card(data, Slot::Green)),
            )
            .child(self.deploy_card(site, cx))
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
        let deploy = btn(id("detail", "deploy"), "Deploy", BtnKind::Primary).on_click(cx.listener(
            |this, _, _, cx| {
                this.do_deploy(cx);
                cx.notify();
            },
        ));
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
