use std::collections::BTreeSet;

use cite_client::NodeOutcome;
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::apply_to_handles;
use crate::app::{Console, View, new_input};
use crate::model::{
    Placement, SiteDraft, build_site, draft_github_token, plan_placement, regex_matches,
    regex_problem, slugify,
};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::{InputEvent, TextInput};
use crate::ui::widgets::{
    BtnKind, btn, card, field, id, mono, notice, page_header, pill, seg_item, seg_row, text_dim,
    toggle,
};

pub struct State {
    pub api: bool,
    pub placement: Placement,
    pub picked: BTreeSet<String>,
    pub busy: bool,
    pub error: Option<String>,
    pub last_auto_id: String,
    pub name: Entity<TextInput>,
    pub id: Entity<TextInput>,
    pub hosts: Entity<TextInput>,
    pub path: Entity<TextInput>,
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
            placement: Placement::Selected,
            picked: BTreeSet::new(),
            busy: false,
            error: None,
            last_auto_id: String::new(),
            name: name.clone(),
            id: new_input(cx, "storefront", |i| i.mono()),
            hosts: new_input(cx, "shop.example.com, www.example.com", |i| i.mono()),
            path: new_input(cx, "^/api/ (optional)", |i| i.mono()),
            sample: new_input(cx, "/api/v1/users", |i| i.mono()),
            blue: new_input(cx, "10.0.0.11:8080, 10.0.0.12:8080", |i| i.mono()),
            green: new_input(cx, "10.0.0.21:8080 (optional)", |i| i.mono()),
            health: new_input(cx, "/", |i| i.mono()),
            repo: new_input(cx, "https://github.com/acme/shop (optional)", |i| i.mono()),
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
            &c.path,
            &c.sample,
            &c.blue,
            &c.green,
            &c.repo,
            &c.branch,
            &c.gh_token,
        ] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        c.health.update(cx, |i, cx| i.set_text("/", cx));
        self.create.last_auto_id.clear();
        self.create.error = None;
        self.create.busy = false;
        self.create.picked = self.active_name().into_iter().collect();
    }

    fn draft(&self, cx: &Context<Self>) -> SiteDraft {
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        let c = &self.create;
        SiteDraft {
            api: c.api,
            name: t(&c.name),
            id: t(&c.id),
            hosts: t(&c.hosts),
            path_regex: t(&c.path),
            blue: t(&c.blue),
            green: t(&c.green),
            health_path: t(&c.health),
            repo: t(&c.repo),
            branch: t(&c.branch),
            github_token: t(&c.gh_token),
        }
    }

    // Validation runs locally with the connector's own checks before any request is sent.
    fn submit_site(&mut self, cx: &mut Context<Self>) {
        if self.create.busy {
            return;
        }
        let draft = self.draft(cx);
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
        let fut = async move { Ok(apply_to_handles(handles, plan).await) };
        self.fetch(
            cx,
            fut,
            move |this, res: Result<Vec<NodeOutcome>, _>, cx| {
                this.create.busy = false;
                match res {
                    Ok(outcomes) => {
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
                        if failed.is_empty() {
                            this.say(
                                format!("Site {name} created on {} node(s)", outcomes.len()),
                                Tone::Ok,
                            );
                            this.navigate(View::Sites, cx);
                        } else {
                            this.create.error = Some(failed.join("; "));
                        }
                    }
                    Err(e) => this.create.error = Some(e.to_string()),
                }
                cx.notify();
            },
        );
    }

    // Regex validity is recomputed on every render so feedback is immediate.
    pub fn render_create(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let header = page_header(
            "Create site",
            "Define routing and upstreams, then place it on your nodes",
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
        let pattern = s.path.read(cx).text().to_string();
        let sample = s.sample.read(cx).text().to_string();
        let status: AnyElement = if pattern.is_empty() {
            pill("Matches every path", Tone::Muted).into_any_element()
        } else if let Some(problem) = regex_problem(&pattern) {
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(pill("Invalid", Tone::Bad))
                .child(
                    text_dim(problem)
                        .text_size(px(12.))
                        .text_color(c(Tone::Bad.color())),
                )
                .into_any_element()
        } else {
            let verdict = match regex_matches(&pattern, &sample) {
                Some(true) => Some(pill("Sample matches", Tone::Ok)),
                Some(false) => Some(pill("Sample does not match", Tone::Warn)),
                None => None,
            };
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(pill("Valid regex", Tone::Ok))
                .children(verdict)
                .into_any_element()
        };
        let routing = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field(
                "Hosts",
                Some("Requests with these Host headers go to this site. Separate with commas."),
                s.hosts.clone(),
            ))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex_1().child(field(
                        "Path regex",
                        Some("Optional. Leave empty to route every path."),
                        s.path.clone(),
                    )))
                    .child(
                        div()
                            .flex_1()
                            .child(field("Test a path", None, s.sample.clone())),
                    ),
            )
            .child(status);
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
        let source = div()
            .flex()
            .gap(px(12.))
            .child(
                div()
                    .flex_1()
                    .child(field("Repository", None, s.repo.clone())),
            )
            .child(
                div()
                    .w(px(160.))
                    .child(field("Branch", None, s.branch.clone())),
            )
            .child(
                div()
                    .flex_1()
                    .child(field("GitHub token", None, s.gh_token.clone())),
            );
        let placement = self.placement_body(cx);
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(header)
            .child(card(Some("Basics"), None, basics))
            .child(card(Some("Routing"), None, routing))
            .child(card(
                Some("Upstreams"),
                Some("Both slots can be filled now."),
                upstreams,
            ))
            .child(card(
                Some("Source"),
                Some("Optional. Build and deploy from a repository."),
                source,
            ))
            .child(card(Some("Place on"), None, placement));
        if let Some(err) = &self.create.error {
            col = col.child(notice(err, Tone::Bad));
        }
        let label = if self.create.busy {
            "Creating..."
        } else {
            "Create site"
        };
        col.child(
            div()
                .flex()
                .justify_end()
                .gap(px(8.))
                .child(
                    btn(id("create", "cancel"), "Cancel", BtnKind::Plain)
                        .on_click(cx.listener(|this, _, _, cx| this.navigate(View::Sites, cx))),
                )
                .child(
                    btn(id("create", "submit"), label, BtnKind::Primary).on_click(cx.listener(
                        |this, _, _, cx| {
                            this.submit_site(cx);
                            cx.notify();
                        },
                    )),
                ),
        )
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
