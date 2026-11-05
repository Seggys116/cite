use cite_client::PresetInfo;
use cite_edge::model::{FirewallAction, FirewallRule};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::app::{Confirm, Console, Load, new_input};
use crate::model::{RuleDraft, action_label, build_rule, matcher_summary};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, clip, empty_state, field, id, mono, notice, page_header, pill,
    seg_item, seg_row, skeleton, strong, table, text_dim, toggle,
};

pub struct Data {
    pub rules: Vec<FirewallRule>,
    pub presets: Vec<PresetInfo>,
}

pub struct State {
    pub data: Load<Data>,
    pub adding: bool,
    pub action: FirewallAction,
    pub error: Option<String>,
    pub name: Entity<TextInput>,
    pub path_regex: Entity<TextInput>,
    pub path_prefix: Entity<TextInput>,
    pub methods: Entity<TextInput>,
    pub ua: Entity<TextInput>,
    pub cidrs: Entity<TextInput>,
    pub host: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            adding: false,
            action: FirewallAction::Deny,
            error: None,
            name: new_input(cx, "Block WordPress probes", |i| i),
            path_regex: new_input(cx, "^/wp-(login|admin)", |i| i.mono()),
            path_prefix: new_input(cx, "/phpmyadmin", |i| i.mono()),
            methods: new_input(cx, "TRACE, CONNECT", |i| i.mono()),
            ua: new_input(cx, "(sqlmap|nikto)", |i| i.mono()),
            cidrs: new_input(cx, "203.0.113.0/24", |i| i.mono()),
            host: new_input(cx, "shop.example.com", |i| i.mono()),
        }
    }
}

pub fn action_tone(a: FirewallAction) -> Tone {
    match a {
        FirewallAction::Deny => Tone::Bad,
        FirewallAction::Drop => Tone::Warn,
        FirewallAction::Tarpit => Tone::Info,
    }
}

// Wording matches the web dashboard so both clients describe actions identically.
fn action_help(a: FirewallAction) -> &'static str {
    match a {
        FirewallAction::Deny => {
            "Answer with 403 Forbidden. Clear to the client and cheap for the edge."
        }
        FirewallAction::Drop => {
            "Close the connection with no reply at all, so scanners learn nothing."
        }
        FirewallAction::Tarpit => {
            "Hold the connection open and answer slowly to waste the scanner's time."
        }
    }
}

impl Console {
    pub fn load_firewall(&mut self, cx: &mut Context<Self>) {
        self.firewall.data = Load::Loading;
        let Some(h) = self.active_handle() else {
            self.firewall.data = Load::Idle;
            return;
        };
        let fut = async move {
            let rules = h.list_rules().await?;
            let presets = h.list_presets().await.unwrap_or_default();
            Ok(Data { rules, presets })
        };
        self.fetch(cx, fut, |this, res, cx| {
            this.firewall.data = Load::from_result(res);
            cx.notify();
        });
    }

    // A short random tail keeps generated rule ids unique per node.
    fn rule_suffix() -> String {
        cite_core::new_id().chars().rev().take(6).collect()
    }

    fn submit_rule(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        let f = &self.firewall;
        let draft = RuleDraft {
            name: t(&f.name),
            action: Some(f.action),
            path_regex: t(&f.path_regex),
            path_prefix: t(&f.path_prefix),
            methods: t(&f.methods),
            user_agent_regex: t(&f.ua),
            cidrs: t(&f.cidrs),
            host: t(&f.host),
            site: String::new(),
        };
        match build_rule(&draft, &Self::rule_suffix()) {
            Ok(rule) => {
                self.firewall.error = None;
                self.firewall.adding = false;
                for input in [
                    &self.firewall.name,
                    &self.firewall.path_regex,
                    &self.firewall.path_prefix,
                    &self.firewall.methods,
                    &self.firewall.ua,
                    &self.firewall.cidrs,
                    &self.firewall.host,
                ] {
                    input.update(cx, |i, cx| i.set_text("", cx));
                }
                let name = rule.name.clone();
                self.mutate(
                    cx,
                    async move { h.create_rule(&rule).await },
                    format!("Rule {name} added"),
                );
            }
            Err(e) => self.firewall.error = Some(e),
        }
    }

    pub fn render_firewall(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let add = btn(
            id("fw", "add"),
            if self.firewall.adding {
                "Cancel"
            } else {
                "Add rule"
            },
            BtnKind::Primary,
        )
        .on_click(cx.listener(|this, _, _, cx| {
            this.firewall.adding = !this.firewall.adding;
            this.firewall.error = None;
            cx.notify();
        }));
        let subtitle = match self.active_name() {
            Some(n) => format!("Rules enforced by {n}"),
            None => "Block, drop or tarpit unwanted traffic".into(),
        };
        let header = page_header("Firewall", &subtitle, vec![add.into_any_element()]);
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        col = col.children(self.scope_note());
        if self.firewall.adding {
            col = col.child(self.rule_form(cx));
        }
        match &self.firewall.data {
            Load::Idle | Load::Loading => col = col.child(skeleton(200.)),
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                col = col
                    .child(self.rules_card(data, cx))
                    .child(self.presets_card(data, cx));
            }
        }
        col.into_any_element()
    }

    // The switch flips only the enabled flag and sends the full rule back.
    fn rules_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let rows: Vec<Vec<AnyElement>> = data
            .rules
            .iter()
            .map(|r| {
                let (flip_rule, del_name, del_id) = (r.clone(), r.name.clone(), r.id.clone());
                let sw = toggle(id("rule-on", &r.id), r.enabled).on_click(cx.listener(
                    move |this, _, _, cx| {
                        let Some(h) = this.active_handle() else {
                            return;
                        };
                        let mut next = flip_rule.clone();
                        next.enabled = !next.enabled;
                        let (rid, label) = (next.id.clone(), next.name.clone());
                        let msg = if next.enabled {
                            format!("{label} enabled")
                        } else {
                            format!("{label} disabled")
                        };
                        this.mutate(cx, async move { h.update_rule(&rid, &next).await }, msg);
                        cx.notify();
                    },
                ));
                let del = btn(id("rule-del", &r.id), "Delete", BtnKind::Danger).on_click(
                    cx.listener(move |this, _, _, cx| {
                        let (rid, label) = (del_id.clone(), del_name.clone());
                        this.ask(Confirm {
                            title: "Delete rule".into(),
                            message: format!(
                                "Delete {label}? Matching traffic will pass through again."
                            ),
                            label: "Delete rule".into(),
                            danger: true,
                            action: Box::new(move |this, cx| {
                                if let Some(h) = this.active_handle() {
                                    this.mutate(
                                        cx,
                                        async move { h.delete_rule(&rid).await },
                                        format!("Rule {label} deleted"),
                                    );
                                }
                            }),
                        });
                        cx.notify();
                    }),
                );
                let matches = matcher_summary(&r.matchers).join("  ");
                vec![
                    sw.into_any_element(),
                    div()
                        .flex()
                        .flex_col()
                        .child(strong(r.name.clone()))
                        .child(mono(r.id.clone()).text_color(c(DIM)))
                        .into_any_element(),
                    pill(action_label(r.action), action_tone(r.action)).into_any_element(),
                    clip(matches)
                        .font_family(crate::theme::MONO)
                        .text_size(px(12.))
                        .into_any_element(),
                    match &r.site {
                        Some(s) => mono(s.clone()).into_any_element(),
                        None => text_dim("All sites").into_any_element(),
                    },
                    del.into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("On", 60.),
            Col::flex("Rule"),
            Col::fixed("Action", 120.),
            Col::flex("Matches"),
            Col::fixed("Scope", 100.),
            Col::fixed("", 90.),
        ];
        let body = table(
            &cols,
            rows,
            Some(empty_state(
                "No firewall rules",
                "Add a rule or apply a preset below.",
            )),
        );
        card(
            Some("Rules"),
            Some("Evaluated in order; the first match wins"),
            body,
        )
        .into_any_element()
    }

    // Applying a preset only adds rules the node does not already have.
    fn presets_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let mut list = div().flex().flex_wrap().gap(px(12.));
        for p in &data.presets {
            let name = p.name.clone();
            let title = p.title.clone();
            let apply = btn(id("preset", &p.name), "Apply", BtnKind::Plain).on_click(cx.listener(
                move |this, _, _, cx| {
                    if let Some(h) = this.active_handle() {
                        let (n, t) = (name.clone(), title.clone());
                        this.mutate(
                            cx,
                            async move { h.apply_preset(&n).await },
                            format!("Preset {t} applied"),
                        );
                    }
                    cx.notify();
                },
            ));
            list = list.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .w(px(340.))
                    .p(px(12.))
                    .rounded(px(8.))
                    .border_1()
                    .border_color(c(crate::theme::BORDER))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(strong(p.title.clone()))
                            .child(pill(&format!("{} rules", p.rules.len()), Tone::Muted)),
                    )
                    .child(text_dim(p.description.clone()).text_size(px(12.)))
                    .child(div().flex().child(apply)),
            );
        }
        if data.presets.is_empty() {
            list = list.child(text_dim("This node offers no presets."));
        }
        card(
            Some("Presets"),
            Some("Curated rule sets you can add in one click."),
            list,
        )
        .into_any_element()
    }

    fn rule_form(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let mut actions = Vec::new();
        for a in [
            FirewallAction::Deny,
            FirewallAction::Drop,
            FirewallAction::Tarpit,
        ] {
            actions.push(
                seg_item(
                    id("fw-action", action_label(a)),
                    action_label(a),
                    f.action == a,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.firewall.action = a;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let half = |label: &str, hint: Option<&str>, e: &Entity<TextInput>| {
            div().flex_1().child(field(label, hint, e.clone()))
        };
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("Name", None, f.name.clone()))
            .child(field(
                "Action",
                Some(action_help(f.action)),
                div().flex().child(seg_row(actions)),
            ))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Path regex", None, &f.path_regex))
                    .child(half("Path prefix", None, &f.path_prefix)),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Methods", Some("Comma separated"), &f.methods))
                    .child(half("User agent regex", None, &f.ua)),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half(
                        "Client CIDR ranges",
                        Some("Comma separated"),
                        &f.cidrs,
                    ))
                    .child(half("Host", None, &f.host)),
            );
        if let Some(err) = &f.error {
            form = form.child(notice(err, Tone::Bad));
        }
        form = form.child(div().flex().child(
            btn(id("fw", "save"), "Add rule", BtnKind::Primary).on_click(cx.listener(
                |this, _, _, cx| {
                    this.submit_rule(cx);
                    cx.notify();
                },
            )),
        ));
        card(
            Some("Add firewall rule"),
            Some("Every filled matcher must match for the rule to fire."),
            form,
        )
        .into_any_element()
    }
}
