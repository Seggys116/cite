use std::collections::{BTreeMap, BTreeSet};

use cite_client::{ClientError, NodeOutcome};
use gpui::{AnyElement, Context, Div, Entity, div, prelude::*, px};

use crate::api::apply_to_handles;
use crate::app::{Console, View, new_input};
use crate::certs::AccessDraft;
use crate::model::{
    DEFAULT_POLL, DEFAULT_RUNTIME, NODE_MAJORS, Placement, RUNTIMES, SiteDraft, SourceKind,
    build_site, draft_github_token, node_has_github_token, plan_placement, slugify,
};
use crate::theme::{ACCENT, DIM, Tone, c};
use crate::ui::certs::{access_body, access_controls};
use crate::ui::paths::{PathRow, clear_rows, path_editor, read_paths};
use crate::wizard::{
    STEPS, Step, TOKEN_TOGGLE, TokenView, effective_token, first_blocked, review_rows,
    step_problem, token_view,
};
use crate::zone::{ZoneReveal, create_verdict};

type CreateDone = (Vec<NodeOutcome>, Vec<ZoneReveal>, Vec<String>);
use crate::ui::input::{InputEvent, TextInput};
use crate::ui::widgets::{
    BtnKind, btn, btn_off, card, field, id, mono, notice, page_header, pill, seg_item, seg_row,
    text_dim, toggle,
};

pub struct State {
    pub api: bool,
    pub step: Step,
    pub source: SourceKind,
    pub runtime: String,
    pub node_major: u8,
    pub own_token: bool,
    // Whether each node already holds a GitHub token of its own, learned when the form opens.
    pub tokens: BTreeMap<String, bool>,
    pub poll: Entity<TextInput>,
    pub access: AccessDraft,
    pub placement: Placement,
    pub picked: BTreeSet<String>,
    pub busy: bool,
    pub error: Option<String>,
    pub last_auto_id: String,
    pub name: Entity<TextInput>,
    pub id: Entity<TextInput>,
    pub hosts: Entity<TextInput>,
    pub paths: Vec<PathRow>,
    pub sample: Entity<TextInput>,
    pub blue: Entity<TextInput>,
    pub green: Entity<TextInput>,
    pub health: Entity<TextInput>,
    pub repo: Entity<TextInput>,
    pub branch: Entity<TextInput>,
    pub gh_token: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        let name = new_input(cx, "Storefront", |i| i);
        let state = Self {
            api: false,
            step: Step::Source,
            source: SourceKind::Github,
            runtime: DEFAULT_RUNTIME.into(),
            node_major: NODE_MAJORS[0],
            own_token: false,
            tokens: BTreeMap::new(),
            poll: new_input(cx, DEFAULT_POLL, |i| i.mono()),
            access: AccessDraft::default(),
            placement: Placement::Selected,
            picked: BTreeSet::new(),
            busy: false,
            error: None,
            last_auto_id: String::new(),
            name: name.clone(),
            id: new_input(cx, "storefront", |i| i.mono()),
            hosts: new_input(cx, "shop.example.com, www.example.com", |i| i.mono()),
            paths: Vec::new(),
            sample: new_input(cx, "/api/v1/users", |i| i.mono()),
            blue: new_input(cx, "10.0.0.11:8080, 10.0.0.12:8080", |i| i.mono()),
            green: new_input(cx, "10.0.0.21:8080 (optional)", |i| i.mono()),
            health: new_input(cx, "/", |i| i.mono()),
            repo: new_input(cx, "acme/shop", |i| i.mono()),
            branch: new_input(cx, "main", |i| i.mono()),
            gh_token: new_input(cx, "GitHub token for private repositories", |i| {
                i.masked().mono()
            }),
        };
        cx.subscribe(&name, |this, _, _: &InputEvent, cx| this.autofill_id(cx))
            .detach();
        state
    }
}

impl Console {
    // The id follows the name until the user types their own value.
    fn autofill_id(&mut self, cx: &mut Context<Self>) {
        let slug = slugify(self.create.name.read(cx).text());
        let current = self.create.id.read(cx).text().to_string();
        if current.is_empty() || current == self.create.last_auto_id {
            self.create.last_auto_id = slug.clone();
            self.create.id.update(cx, |i, cx| i.set_text(&slug, cx));
        }
    }

    // Opening the form always starts clean with the active node preselected.
    pub fn reset_create(&mut self, cx: &mut Context<Self>) {
        let c = &self.create;
        for input in [
            &c.name,
            &c.id,
            &c.hosts,
            &c.sample,
            &c.blue,
            &c.green,
            &c.repo,
            &c.gh_token,
        ] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        c.health.update(cx, |i, cx| i.set_text("/", cx));
        c.branch.update(cx, |i, cx| i.set_text("main", cx));
        c.poll.update(cx, |i, cx| i.set_text(DEFAULT_POLL, cx));
        clear_rows(&mut self.create.paths, cx);
        self.create.last_auto_id.clear();
        self.create.access = AccessDraft::default();
        self.create.step = Step::Source;
        self.create.source = SourceKind::Github;
        self.create.runtime = DEFAULT_RUNTIME.into();
        self.create.node_major = NODE_MAJORS[0];
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
            self.create.gh_token.read(cx).text(),
        )
    }

    fn draft(&self, cx: &Context<Self>) -> SiteDraft {
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        let c = &self.create;
        let github = c.source == SourceKind::Github;
        let typed = t(&c.gh_token);
        let (prefixes, regexes) = read_paths(&c.paths, cx);
        SiteDraft {
            api: c.api,
            source: c.source,
            name: t(&c.name),
            id: t(&c.id),
            hosts: t(&c.hosts),
            path_prefixes: prefixes,
            path_regexes: regexes,
            blue: t(&c.blue),
            green: t(&c.green),
            // A source-built site always probes its root.
            health_path: if github { "/".into() } else { t(&c.health) },
            repo: t(&c.repo),
            branch: t(&c.branch),
            runtime: c.runtime.clone(),
            node_major: c.node_major,
            poll_interval: t(&c.poll),
            github_token: effective_token(&self.token_state(cx), &typed),
            access: c.access,
        }
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
        let s = &self.create;
        let kind = seg_row(vec![
            seg_item(id("kind", "site"), "Site", !s.api)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.create.api = false;
                    cx.notify();
                }))
                .into_any_element(),
            seg_item(id("kind", "api"), "API", s.api)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.create.api = true;
                    cx.notify();
                }))
                .into_any_element(),
        ]);
        let basics = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field(
                "Kind",
                Some("APIs usually route by path prefix; sites by host name."),
                div().flex().child(kind),
            ))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex_1().child(field("Name", None, s.name.clone())))
                    .child(div().flex_1().child(field(
                        "Id",
                        Some("Lowercase letters, digits and dashes. Cannot change later."),
                        s.id.clone(),
                    ))),
            );
        let paths = path_editor(
            &s.paths,
            "create-path",
            Some(&s.sample),
            |c| &mut c.create.paths,
            cx,
        );
        let routing = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field(
                "Hosts",
                Some("Requests with these Host headers go to this site. Separate with commas."),
                s.hosts.clone(),
            ))
            .child(field("Routing paths", None, paths));
        let upstreams = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex_1().child(field(
                        "Blue targets",
                        Some("host:port with an optional weight, separated by commas."),
                        s.blue.clone(),
                    )))
                    .child(div().flex_1().child(field(
                        "Green targets",
                        Some("Green is where the first deploy lands."),
                        s.green.clone(),
                    ))),
            )
            .child(field(
                "Health check path",
                Some("Probed on every target to decide readiness."),
                s.health.clone(),
            ));
        let access = access_body(
            access_controls(cx, "create-access", s.access, |c| &mut c.create.access),
            s.access,
        );
        let source_step = self.source_choice(cx);
        let github = self.github_body(cx);
        let routing_step = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(basics)
            .child(routing);
        let step = self.create.step;
        let kind = self.create.source;
        let body: AnyElement = match step {
            Step::Source => source_step,
            Step::Setup if kind == SourceKind::Github => github,
            Step::Setup => upstreams.into_any_element(),
            Step::Domains => routing_step.into_any_element(),
            Step::Protection => access.into_any_element(),
            Step::Where => self.where_body(cx),
        };
        let draft = self.draft(cx);
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
            let label = format!("{}  {}", s.index() + 1, s.title(self.create.source));
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
            let on = self.create.source == kind;
            let mut item = card(Some(title), Some(text), div())
                .id(id("source", key))
                .cursor_pointer()
                .flex_1();
            if on {
                item = item.border_color(c(ACCENT));
            }
            item.on_click(cx.listener(move |this, _, _, cx| {
                this.create.source = kind;
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
    fn github_body(&self, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.create;
        let runtime = seg_row(
            RUNTIMES
                .iter()
                .map(|r| {
                    let name = r.to_string();
                    seg_item(id("runtime", r), r, s.runtime == *r)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.create.runtime = name.clone();
                            cx.notify();
                        }))
                        .into_any_element()
                })
                .collect(),
        );
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex_1().child(field(
                        "Repository",
                        Some("GitHub owner/name, for example acme/shop."),
                        s.repo.clone(),
                    )))
                    .child(
                        div()
                            .w(px(180.))
                            .child(field("Branch", None, s.branch.clone())),
                    ),
            )
            .child(field(
                "Runtime",
                Some("Picks the build and run images."),
                div().flex().child(runtime),
            ));
        if s.runtime != "rust" {
            let majors = seg_row(
                NODE_MAJORS
                    .iter()
                    .map(|m| {
                        let major = *m;
                        seg_item(id("major", m), &format!("Node {m}"), s.node_major == major)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.create.node_major = major;
                                cx.notify();
                            }))
                            .into_any_element()
                    })
                    .collect(),
            );
            body = body.child(field("Node version", None, div().flex().child(majors)));
        }
        body = body.child(field(
            "Poll interval",
            Some("How often the node checks the branch for new commits, such as 30s, 5m or 1h."),
            s.poll.clone(),
        ));
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
            body = body.child(field("GitHub token", Some(view.help), s.gh_token.clone()));
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
