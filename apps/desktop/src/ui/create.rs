use std::collections::{BTreeMap, BTreeSet};

use cite_client::{ClientError, NodeOutcome};
use gpui::{AnyElement, Context, Div, div, prelude::*, px};

use crate::api::apply_to_handles;
use crate::app::{Console, View};
use crate::model::{
    Placement, SiteDraft, SourceKind, build_site, draft_github_token, node_has_github_token,
    plan_placement, slugify,
};
use crate::theme::{ACCENT, DIM, Tone, c};
use crate::ui::certs::{access_body, access_controls};
use crate::ui::paths::PathRow;
use crate::ui::siteform::{
    Home, SiteFields, basics, blank_draft, domains, health_fields, servers_fields, source_fields,
};
use crate::wizard::{
    FieldProblems, STEPS, Step, TOKEN_TOGGLE, TokenView, effective_token, field_problems,
    first_blocked, review_rows, step_problem, token_view,
};
use crate::zone::{ZoneReveal, create_verdict};

type CreateDone = (Vec<NodeOutcome>, Vec<ZoneReveal>, Vec<String>);
use crate::ui::input::InputEvent;
use crate::ui::widgets::{
    BtnKind, btn, btn_off, card, field, id, mono, notice, page_header, pill, seg_item, seg_row,
    text_dim, toggle,
};

fn create_fields(c: &mut Console) -> &mut SiteFields {
    &mut c.create.fields
}

fn create_paths(c: &mut Console) -> &mut Vec<PathRow> {
    &mut c.create.fields.paths
}

const HOME: Home = Home {
    key: "create-form",
    fields: create_fields,
    paths: create_paths,
};

pub struct State {
    pub fields: SiteFields,
    pub step: Step,
    pub own_token: bool,
    // Whether each node already holds a GitHub token of its own, learned when the form opens.
    pub tokens: BTreeMap<String, bool>,
    pub placement: Placement,
    pub picked: BTreeSet<String>,
    pub busy: bool,
    pub error: Option<String>,
    pub last_auto_id: String,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        let fields = SiteFields::new(cx);
        cx.subscribe(&fields.name, |this, _, _: &InputEvent, cx| {
            this.autofill_id(cx)
        })
        .detach();
        Self {
            fields,
            step: Step::Source,
            own_token: false,
            tokens: BTreeMap::new(),
            placement: Placement::Selected,
            picked: BTreeSet::new(),
            busy: false,
            error: None,
            last_auto_id: String::new(),
        }
    }
}

impl Console {
    // The id follows the name until the user types their own value.
    fn autofill_id(&mut self, cx: &mut Context<Self>) {
        let slug = slugify(self.create.fields.name.read(cx).text());
        let current = self.create.fields.id.read(cx).text().to_string();
        if current.is_empty() || current == self.create.last_auto_id {
            self.create.last_auto_id = slug.clone();
            self.create
                .fields
                .id
                .update(cx, |i, cx| i.set_text(&slug, cx));
        }
    }

    // Opening the form always starts clean with the active node preselected.
    pub fn reset_create(&mut self, cx: &mut Context<Self>) {
        self.create.fields.load(&blank_draft(), cx);
        self.create.last_auto_id.clear();
        self.create.step = Step::Source;
        self.create.own_token = false;
        self.create.tokens.clear();
        self.create.error = None;
        self.create.busy = false;
        self.create.picked = self.active_name().into_iter().collect();
        self.load_node_tokens(cx);
    }

    // Which nodes already hold a GitHub token decides whether the token field is offered or required.
    fn load_node_tokens(&mut self, cx: &mut Context<Self>) {
        let handles = self.handles.clone();
        let fut = async move {
            let mut out = Vec::new();
            for h in handles {
                let has = h
                    .node_info()
                    .await
                    .map(|i| node_has_github_token(&i))
                    .unwrap_or(false);
                out.push((h.name().to_string(), has));
            }
            Ok::<_, ClientError>(out)
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            if let Ok(found) = res {
                this.create.tokens = found.into_iter().collect();
                cx.notify();
            }
        });
    }

    // The nodes the site would be placed on with the current choice.
    fn chosen_nodes(&self) -> Vec<String> {
        match self.create.placement {
            Placement::ReplicateAll => self.node_names(),
            Placement::Selected => self.create.picked.iter().cloned().collect(),
        }
    }

    fn token_state(&self, cx: &Context<Self>) -> TokenView {
        let flags: Vec<bool> = self
            .chosen_nodes()
            .iter()
            .map(|n| self.create.tokens.get(n).copied().unwrap_or(false))
            .collect();
        token_view(
            &flags,
            self.create.own_token,
            self.create.fields.gh_token.read(cx).text(),
        )
    }

    fn draft(&self, cx: &Context<Self>) -> SiteDraft {
        let f = &self.create.fields;
        let mut d = f.draft(cx);
        // A source-built site keeps the node's default health check; the timing fields belong to the servers step.
        if d.source == SourceKind::Github {
            d.health_path = "/".into();
            d.health_interval.clear();
            d.health_timeout.clear();
            d.health_rise.clear();
            d.health_fall.clear();
        }
        let typed = f.gh_token.read(cx).text().to_string();
        d.github_token = effective_token(&self.token_state(cx), &typed);
        d
    }

    // Validation runs locally with the connector's own checks before any request is sent.
    fn submit_site(&mut self, cx: &mut Context<Self>) {
        if self.create.busy {
            return;
        }
        let draft = self.draft(cx);
        let picked = self.chosen_nodes().len();
        if let Some((step, problem)) = first_blocked(&draft, picked, &self.token_state(cx)) {
            self.create.step = step;
            self.create.error = Some(problem);
            return;
        }
        let github_token = draft_github_token(&draft);
        let site = match build_site(&draft) {
            Ok(s) => s,
            Err(e) => {
                self.create.error = Some(e);
                return;
            }
        };
        let all = self.node_names();
        let selected: Vec<String> = self.create.picked.iter().cloned().collect();
        let planned = plan_placement(
            &site,
            &self.create.placement,
            &selected,
            &all,
            &Default::default(),
            github_token,
        );
        let (nodes, plan) = match planned {
            Ok(v) => v,
            Err(e) => {
                self.create.error = Some(e);
                return;
            }
        };
        let handles: Vec<_> = nodes.iter().filter_map(|n| self.handle_named(n)).collect();
        if handles.len() != nodes.len() {
            self.create.error = Some("One of the chosen nodes is not connected.".into());
            return;
        }
        self.create.busy = true;
        self.create.error = None;
        let name = site.name.clone();
        let (lock, site_id) = (site.access.zone_lock, site.id.clone());
        let rotate_on = handles.clone();
        // A new zone lock has no visible secret yet, so one is rotated in on every node that took the site.
        let fut = async move {
            let outcomes = apply_to_handles(handles, plan).await;
            let (mut reveals, mut problems) = (Vec::new(), Vec::new());
            if lock {
                for h in rotate_on
                    .iter()
                    .filter(|h| outcomes.iter().any(|o| o.ok && o.node == h.name()))
                {
                    match h.rotate_zone_secret(&site_id).await {
                        Ok(r) => reveals.push(r),
                        Err(e) => problems.push(format!("{}: {e}", h.name())),
                    }
                }
            }
            Ok((outcomes, reveals, problems))
        };
        let reveal_site = site.id.clone();
        self.fetch_origin(
            cx,
            fut,
            move |this, res: Result<CreateDone, ClientError>, here, _origin, cx| {
                this.create.busy = false;
                match res {
                    Ok((outcomes, reveals, problems)) => {
                        let failed: Vec<String> = outcomes
                            .iter()
                            .filter(|o| !o.ok)
                            .map(|o| {
                                format!(
                                    "{}: {}",
                                    o.node,
                                    o.error.clone().unwrap_or_else(|| "failed".into())
                                )
                            })
                            .collect();
                        let created = outcomes.iter().filter(|o| o.ok).count();
                        let nodes: Vec<String> = reveals.iter().map(|r| r.node.clone()).collect();
                        let verdict = create_verdict(&name, created, &failed, &problems, &nodes);
                        let has_secrets = !reveals.is_empty();
                        this.detail.reveals.extend(reveals);
                        if !here {
                            // The user moved on: the outcome is a toast, and secrets wait on their own site page.
                            let mut text = verdict
                                .toast
                                .map(|(t, _)| t)
                                .or(verdict.error)
                                .unwrap_or_default();
                            if has_secrets {
                                text.push_str(" Open the site to copy its zone secret.");
                            }
                            this.say(text, Tone::Warn);
                            cx.notify();
                            return;
                        }
                        if let Some((text, ok)) = verdict.toast {
                            this.say(text, if ok { Tone::Ok } else { Tone::Warn });
                        }
                        this.create.error = verdict.error;
                        if this.create.error.is_none() {
                            match verdict.open_node {
                                Some(node) => this.navigate(
                                    View::SiteDetail {
                                        node,
                                        id: reveal_site.clone(),
                                    },
                                    cx,
                                ),
                                None => this.navigate(View::Sites, cx),
                            }
                        }
                    }
                    Err(e) if here => this.create.error = Some(e.to_string()),
                    Err(e) => this.say(format!("Create site {name}: {e}"), Tone::Bad),
                }
                cx.notify();
            },
        );
    }

    // Regex validity is recomputed on every render so feedback is immediate.
    pub fn render_create(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let header = page_header(
            "Create site",
            "Choose where the site comes from and which domains reach it",
            Vec::new(),
        );
        if self.handles.is_empty() {
            return div()
                .flex()
                .flex_col()
                .gap(px(16.))
                .child(header)
                .child(self.no_nodes_block(cx))
                .into_any_element();
        }
        let draft = self.draft(cx);
        let problems = field_problems(&draft, true);
        let step = self.create.step;
        let kind = self.create.fields.source;
        let body: AnyElement = match step {
            Step::Source => self.source_choice(cx),
            Step::Setup if kind == SourceKind::Github => self.github_body(&problems, cx),
            Step::Setup => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(servers_fields(&self.create.fields))
                .child(health_fields(&self.create.fields, &problems))
                .into_any_element(),
            Step::Domains => div()
                .flex()
                .flex_col()
                .gap(px(16.))
                .child(basics(&self.create.fields, HOME, &problems, false, cx))
                .child(domains(&self.create.fields, HOME, &problems, false, cx))
                .into_any_element(),
            Step::Protection => {
                let access = self.create.fields.access;
                access_body(
                    access_controls(cx, "create-access", access, |c| &mut c.create.fields.access),
                    access,
                )
                .into_any_element()
            }
            Step::Where => self.where_body(cx),
        };
        let problem = step_problem(
            step,
            &draft,
            self.chosen_nodes().len(),
            &self.token_state(cx),
        );
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(header)
            .child(self.step_indicator())
            .child(card(Some(step.heading(kind)), None, body));
        if let Some(err) = &self.create.error {
            col = col.child(notice(err, Tone::Bad));
        }
        col.child(self.wizard_nav(step, problem, cx))
            .into_any_element()
    }

    // Done steps show a check colour, the current one the accent, the rest stay muted.
    fn step_indicator(&self) -> Div {
        let current = self.create.step;
        let mut row = div().flex().items_center().gap(px(8.));
        for s in STEPS {
            let label = format!("{}  {}", s.index() + 1, s.title(self.create.fields.source));
            let tone = if s == current {
                Tone::Info
            } else if s.index() < current.index() {
                Tone::Ok
            } else {
                Tone::Muted
            };
            row = row.child(pill(&label, tone));
        }
        row
    }

    // Back and Next move one step; Next stays off until the visible step is valid.
    fn wizard_nav(
        &self,
        step: Step,
        problem: Option<String>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mut row = div().flex().items_center().justify_end().gap(px(8.));
        if let Some(p) = &problem {
            row = row.child(div().flex_1().child(text_dim(p.clone()).text_size(px(12.))));
        }
        row = row.child(
            btn(id("create", "cancel"), "Cancel", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| this.navigate(View::Sites, cx))),
        );
        if step != Step::Source {
            row = row.child(btn(id("create", "back"), "Back", BtnKind::Plain).on_click(
                cx.listener(|this, _, _, cx| {
                    this.create.step = this.create.step.prev();
                    this.create.error = None;
                    cx.notify();
                }),
            ));
        }
        let ready = problem.is_none() && !self.create.busy;
        row.child(match (step.is_last(), ready) {
            (_, false) if self.create.busy => btn_off("Creating...").into_any_element(),
            (true, true) => btn(id("create", "submit"), "Create site", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.submit_site(cx);
                    cx.notify();
                }))
                .into_any_element(),
            (false, true) => btn(id("create", "next"), "Next", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.create.step = this.create.step.next();
                    this.create.error = None;
                    cx.notify();
                }))
                .into_any_element(),
            (last, false) => btn_off(if last { "Create site" } else { "Next" }).into_any_element(),
        })
        .into_any_element()
    }

    // Two cards, one decision; GitHub comes first because building from a repository is the main path.
    fn source_choice(&self, cx: &mut Context<Self>) -> AnyElement {
        let pick = |key: &'static str,
                    title: &str,
                    text: &str,
                    kind: SourceKind,
                    cx: &mut Context<Self>| {
            let on = self.create.fields.source == kind;
            let mut item = card(Some(title), Some(text), div())
                .id(id("source", key))
                .cursor_pointer()
                .flex_1();
            if on {
                item = item.border_color(c(ACCENT));
            }
            item.on_click(cx.listener(move |this, _, _, cx| {
                this.create.fields.source = kind;
                this.create.error = None;
                cx.notify();
            }))
        };
        div()
            .flex()
            .gap(px(12.))
            .child(pick(
                "github",
                "Build from a GitHub repository",
                "The node pulls the code, builds it and redeploys when the branch changes.",
                SourceKind::Github,
                cx,
            ))
            .child(pick(
                "servers",
                "Serve servers I already run",
                "Route traffic to existing host:port addresses you manage yourself.",
                SourceKind::Servers,
                cx,
            ))
            .into_any_element()
    }

    // Only the repository fields and the token control; nothing about upstream slots.
    fn github_body(&self, problems: &FieldProblems, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.create;
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(source_fields(&s.fields, HOME, problems, cx));
        let view = self.token_state(cx);
        if view.offer_toggle {
            body =
                body.child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .child(toggle(id("create", "own-token"), s.own_token).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.create.own_token = !this.create.own_token;
                                cx.notify();
                            }),
                        ))
                        .child(div().child(TOKEN_TOGGLE)),
                );
            if !view.show_field {
                body = body.child(text_dim(view.help).text_size(px(12.)));
            }
        }
        if view.show_field {
            body = body.child(field(
                "GitHub token",
                Some(view.help),
                s.fields.gh_token.clone(),
            ));
        }
        body.into_any_element()
    }

    // The last step: nodes first, then a plain summary of everything chosen.
    fn where_body(&self, cx: &mut Context<Self>) -> AnyElement {
        let draft = self.draft(cx);
        let mut review = div().flex().flex_col().gap(px(6.));
        for (label, value) in review_rows(&draft, &self.chosen_nodes()) {
            review = review.child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().w(px(100.)).child(text_dim(label)))
                    .child(div().flex_1().child(value)),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(self.placement_body(cx))
            .child(card(Some("Review"), None, review))
            .into_any_element()
    }

    // Replicate mode ignores the per-node switches, as the fleet helper does.
    fn placement_body(&self, cx: &mut Context<Self>) -> AnyElement {
        let replicate = self.create.placement == Placement::ReplicateAll;
        let mode = seg_row(vec![
            seg_item(id("place", "selected"), "Place on selected", !replicate)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.create.placement = Placement::Selected;
                    cx.notify();
                }))
                .into_any_element(),
            seg_item(id("place", "all"), "Replicate to all", replicate)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.create.placement = Placement::ReplicateAll;
                    cx.notify();
                }))
                .into_any_element(),
        ]);
        let hint = if replicate {
            format!(
                "Create the same site on all {} connected nodes.",
                self.handles.len()
            )
        } else {
            "Create the site only on the nodes switched on below.".to_string()
        };
        let mut list = div().flex().flex_col().gap(px(8.));
        for name in self.node_names() {
            let on = replicate || self.create.picked.contains(&name);
            let n = name.clone();
            let mut row = div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(toggle(id("pick", &name), on).on_click(cx.listener(
                    move |this, _, _, cx| {
                        if this.create.placement == Placement::Selected
                            && !this.create.picked.remove(&n)
                        {
                            this.create.picked.insert(n.clone());
                        }
                        cx.notify();
                    },
                )))
                .child(mono(name.clone()));
            if replicate {
                row = row.opacity(0.5);
            }
            list = list.child(row);
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().flex().child(mode))
            .child(text_dim(hint).text_size(px(12.)).text_color(c(DIM)))
            .child(list)
            .into_any_element()
    }
}
