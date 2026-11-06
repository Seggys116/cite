use cite_client::PresetInfo;
use cite_edge::model::{FirewallAction, FirewallRule, HeaderOpKind, HeaderTarget};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::app::{Confirm, Console, Load, new_input};
use crate::model::{action_label, matcher_summary};
use crate::rules::{
    CorsDraft, HeaderOpDraft, MAX_HEADER_OPS, REDIRECT_EXAMPLES, REDIRECT_PLACEHOLDERS,
    REDIRECT_STATUSES, RuleDraft, RuleKind, build_rule, effect_detail, effect_pill, op_label,
    target_label,
};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, checkbox, clip, empty_state, field, id, mono, notice, page_header,
    pill, seg_item, seg_row, skeleton, strong, table, text_dim, toggle,
};

pub struct Data {
    pub rules: Vec<FirewallRule>,
    pub presets: Vec<PresetInfo>,
}

// One header change in the editor; its text lives in inputs so typing needs no state round trip.
pub struct OpRow {
    pub target: HeaderTarget,
    pub op: HeaderOpKind,
    pub name: Entity<TextInput>,
    pub value: Entity<TextInput>,
}

pub struct State {
    pub data: Load<Data>,
    pub adding: bool,
    pub kind: RuleKind,
    pub action: FirewallAction,
    pub error: Option<String>,
    pub scheme: Option<&'static str>,
    pub header_regex: bool,
    pub header_negate: bool,
    pub header_secret: bool,
    pub redirect_status: u16,
    pub cors_on: bool,
    pub cors_credentials: bool,
    pub ops: Vec<OpRow>,
    pub name: Entity<TextInput>,
    pub label: Entity<TextInput>,
    pub site: Entity<TextInput>,
    pub path_regex: Entity<TextInput>,
    pub path_prefix: Entity<TextInput>,
    pub methods: Entity<TextInput>,
    pub ua: Entity<TextInput>,
    pub cidrs: Entity<TextInput>,
    pub host: Entity<TextInput>,
    pub header_name: Entity<TextInput>,
    pub header_value: Entity<TextInput>,
    pub header_secret_value: Entity<TextInput>,
    pub referer: Entity<TextInput>,
    pub redirect_to: Entity<TextInput>,
    pub cors_origins: Entity<TextInput>,
    pub cors_methods: Entity<TextInput>,
    pub cors_allow: Entity<TextInput>,
    pub cors_expose: Entity<TextInput>,
    pub cors_max_age: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            adding: false,
            kind: RuleKind::Block,
            action: FirewallAction::Deny,
            error: None,
            scheme: None,
            header_regex: false,
            header_negate: false,
            header_secret: false,
            redirect_status: 301,
            cors_on: false,
            cors_credentials: false,
            ops: Vec::new(),
            name: new_input(cx, "Block WordPress probes", |i| i),
            label: new_input(cx, "wp-probe (optional)", |i| i.mono()),
            site: new_input(cx, "shop (optional, empty means every site)", |i| i.mono()),
            path_regex: new_input(cx, "^/wp-(login|admin)", |i| i.mono()),
            path_prefix: new_input(cx, "/phpmyadmin", |i| i.mono()),
            methods: new_input(cx, "TRACE, CONNECT", |i| i.mono()),
            ua: new_input(cx, "(sqlmap|nikto)", |i| i.mono()),
            cidrs: new_input(cx, "203.0.113.0/24", |i| i.mono()),
            host: new_input(cx, "shop.example.com", |i| i.mono()),
            header_name: new_input(cx, "X-Beta-Key", |i| i.mono()),
            header_value: new_input(cx, "value to compare", |i| i.mono()),
            header_secret_value: new_input(cx, "secret value (hidden)", |i| i.masked().mono()),
            referer: new_input(cx, "spam\\.example", |i| i.mono()),
            redirect_to: new_input(cx, "{scheme}://{www_host}{path}{query}", |i| i.mono()),
            cors_origins: new_input(cx, "https://app.example.com, or *", |i| i.mono()),
            cors_methods: new_input(cx, "GET, POST", |i| i.mono()),
            cors_allow: new_input(cx, "Authorization, Content-Type", |i| i.mono()),
            cors_expose: new_input(cx, "X-Total-Count", |i| i.mono()),
            cors_max_age: new_input(cx, "600 (seconds, up to 86400)", |i| i.mono()),
        }
    }

    fn text_inputs(&self) -> Vec<&Entity<TextInput>> {
        vec![
            &self.name,
            &self.label,
            &self.site,
            &self.path_regex,
            &self.path_prefix,
            &self.methods,
            &self.ua,
            &self.cidrs,
            &self.host,
            &self.header_name,
            &self.header_value,
            &self.header_secret_value,
            &self.referer,
            &self.redirect_to,
            &self.cors_origins,
            &self.cors_methods,
            &self.cors_allow,
            &self.cors_expose,
            &self.cors_max_age,
        ]
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
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.firewall.data = Load::from_result(res);
            cx.notify();
        });
    }

    // A short random tail keeps generated rule ids unique per node.
    fn rule_suffix() -> String {
        cite_client::fsio::new_id().chars().rev().take(6).collect()
    }

    fn rule_draft(&self, cx: &Context<Self>) -> RuleDraft {
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        let f = &self.firewall;
        let header_value = if f.header_secret {
            t(&f.header_secret_value)
        } else {
            t(&f.header_value)
        };
        RuleDraft {
            name: t(&f.name),
            label: t(&f.label),
            site: t(&f.site),
            kind: f.kind,
            action: f.action,
            path_regex: t(&f.path_regex),
            path_prefix: t(&f.path_prefix),
            methods: t(&f.methods),
            user_agent_regex: t(&f.ua),
            cidrs: t(&f.cidrs),
            host: t(&f.host),
            header_name: t(&f.header_name),
            header_value,
            header_regex: f.header_regex,
            header_negate: f.header_negate,
            header_secret: f.header_secret,
            scheme: f.scheme.map(str::to_string),
            referer_regex: t(&f.referer),
            redirect_to: t(&f.redirect_to),
            redirect_status: f.redirect_status,
            header_ops: f
                .ops
                .iter()
                .map(|r| HeaderOpDraft {
                    target: r.target,
                    op: r.op,
                    name: t(&r.name),
                    value: t(&r.value),
                })
                .collect(),
            cors_on: f.cors_on,
            cors: CorsDraft {
                origins: t(&f.cors_origins),
                methods: t(&f.cors_methods),
                allow_headers: t(&f.cors_allow),
                expose_headers: t(&f.cors_expose),
                credentials: f.cors_credentials,
                max_age: t(&f.cors_max_age),
            },
        }
    }

    // A saved or closed form keeps nothing, least of all a secret header value.
    fn reset_rule_form(&mut self, cx: &mut Context<Self>) {
        let inputs: Vec<Entity<TextInput>> =
            self.firewall.text_inputs().into_iter().cloned().collect();
        for input in inputs {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        let f = &mut self.firewall;
        for row in f.ops.drain(..) {
            for input in [row.name, row.value] {
                input.update(cx, |i, cx| i.set_text("", cx));
            }
        }
        f.kind = RuleKind::Block;
        f.action = FirewallAction::Deny;
        f.scheme = None;
        f.header_regex = false;
        f.header_negate = false;
        f.header_secret = false;
        f.redirect_status = 301;
        f.cors_on = false;
        f.cors_credentials = false;
        f.error = None;
    }

    // The secret flag decides which input holds the value, and the text moves with it.
    fn set_header_secret(&mut self, on: bool, cx: &mut Context<Self>) {
        if self.firewall.header_secret == on {
            return;
        }
        let (plain, hidden) = (
            self.firewall.header_value.clone(),
            self.firewall.header_secret_value.clone(),
        );
        let (from, to) = if on { (plain, hidden) } else { (hidden, plain) };
        let text = from.read(cx).text().to_string();
        to.update(cx, |i, cx| i.set_text(&text, cx));
        from.update(cx, |i, cx| i.set_text("", cx));
        self.firewall.header_secret = on;
    }

    fn submit_rule(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        match build_rule(&self.rule_draft(cx), &Self::rule_suffix()) {
            Ok(rule) => {
                self.reset_rule_form(cx);
                self.firewall.adding = false;
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
            if this.firewall.adding {
                this.reset_rule_form(cx);
            }
            this.firewall.adding = !this.firewall.adding;
            this.firewall.error = None;
            cx.notify();
        }));
        let subtitle = match self.active_name() {
            Some(n) => format!("Rules enforced by {n}"),
            None => "Block, redirect or adjust traffic".into(),
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
                let (effect, tone) = effect_pill(r);
                let mut name_cell = div()
                    .flex()
                    .flex_col()
                    .child(strong(r.name.clone()))
                    .child(mono(r.id.clone()).text_color(c(DIM)));
                if let Some(label) = &r.label {
                    name_cell =
                        name_cell.child(text_dim(format!("label {label}")).text_size(px(11.)));
                }
                let mut match_cell = div().flex().flex_col().min_w_0().child(
                    clip(if matches.is_empty() {
                        "every request".to_string()
                    } else {
                        matches
                    })
                    .font_family(crate::theme::MONO)
                    .text_size(px(12.)),
                );
                if let Some(detail) = effect_detail(r) {
                    match_cell =
                        match_cell.child(clip(detail).text_size(px(11.)).text_color(c(DIM)));
                }
                vec![
                    sw.into_any_element(),
                    name_cell.into_any_element(),
                    div().flex().child(pill(&effect, tone)).into_any_element(),
                    match_cell.into_any_element(),
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
            Col::fixed("Effect", 150.),
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
                    .rounded(px(crate::theme::CARD_RADIUS))
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
        let half = |label: &str, hint: Option<&str>, e: &Entity<TextInput>| {
            div().flex_1().child(field(label, hint, e.clone()))
        };
        let mut kinds = Vec::new();
        for kind in [RuleKind::Block, RuleKind::Redirect, RuleKind::Effects] {
            kinds.push(
                seg_item(id("fw-kind", kind.label()), kind.label(), f.kind == kind)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.firewall.kind = kind;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Name", None, &f.name))
                    .child(half(
                        "Label",
                        Some("Shown in logs and the blocked-by-rule table"),
                        &f.label,
                    )),
            )
            .child(field(
                "Site",
                Some("A site id. Leave empty to apply the rule to every site on the node."),
                f.site.clone(),
            ))
            .child(field(
                "Rule type",
                Some(f.kind.help()),
                div().flex().child(seg_row(kinds)),
            ));
        form = match f.kind {
            RuleKind::Block => form.child(self.block_section(cx)),
            RuleKind::Redirect => form.child(self.redirect_section(cx)),
            RuleKind::Effects => form.child(self.effects_section(cx)),
        };
        form = form
            .child(strong("Matchers").text_size(px(13.)))
            .child(
                text_dim("Every filled matcher must match for the rule to fire.")
                    .text_size(px(12.)),
            )
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
            )
            .child(self.header_matcher_section(cx))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex_1().child(self.scheme_field(cx)))
                    .child(half("Referer regex", None, &self.firewall.referer)),
            );
        if let Some(err) = &self.firewall.error {
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
            Some("Block, redirect or adjust matching requests."),
            form,
        )
        .into_any_element()
    }

    fn block_section(&self, cx: &mut Context<Self>) -> AnyElement {
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
                    self.firewall.action == a,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.firewall.action = a;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        field(
            "Action",
            Some(action_help(self.firewall.action)),
            div().flex().child(seg_row(actions)),
        )
        .into_any_element()
    }

    fn redirect_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut statuses = Vec::new();
        for status in REDIRECT_STATUSES {
            statuses.push(
                seg_item(
                    id("fw-status", status),
                    &status.to_string(),
                    self.firewall.redirect_status == status,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.firewall.redirect_status = status;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let mut examples = div().flex().flex_wrap().items_center().gap(px(6.));
        examples = examples.child(text_dim("Examples").text_size(px(11.)));
        for (i, example) in REDIRECT_EXAMPLES.iter().enumerate() {
            let text = (*example).to_string();
            examples = examples.child(btn(id("fw-example", i), example, BtnKind::Plain).on_click(
                cx.listener(move |this, _, _, cx| {
                    let value = text.clone();
                    this.firewall
                        .redirect_to
                        .update(cx, |input, cx| input.set_text(&value, cx));
                    cx.notify();
                }),
            ));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(field(
                "Redirect to",
                Some(&format!(
                    "An absolute http(s) URL or a path starting with /. Placeholders: {REDIRECT_PLACEHOLDERS}"
                )),
                self.firewall.redirect_to.clone(),
            ))
            .child(examples)
            .child(field(
                "Status",
                Some("301 and 308 are permanent; 302 and 307 are temporary."),
                div().flex().child(seg_row(statuses)),
            ))
            .into_any_element()
    }

    fn effects_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let mut ops = div().flex().flex_col().gap(px(8.));
        for (i, row) in f.ops.iter().enumerate() {
            ops = ops.child(self.op_row(i, row, cx));
        }
        if f.ops.is_empty() {
            ops = ops.child(text_dim("No header changes yet.").text_size(px(12.)));
        }
        let can_add = f.ops.len() < MAX_HEADER_OPS;
        let add = if can_add {
            btn(id("fw-op", "add"), "Add header change", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| {
                    let row = OpRow {
                        target: HeaderTarget::Response,
                        op: HeaderOpKind::Set,
                        name: new_input(cx, "X-Frame-Options", |i| i.mono()),
                        value: new_input(cx, "DENY", |i| i.mono()),
                    };
                    this.firewall.ops.push(row);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            text_dim(format!("At most {MAX_HEADER_OPS} header changes."))
                .text_size(px(12.))
                .into_any_element()
        };
        let cors_box =
            checkbox(id("fw-cors", "on"), f.cors_on).on_click(cx.listener(|this, _, _, cx| {
                this.firewall.cors_on = !this.firewall.cors_on;
                cx.notify();
            }));
        let mut cors = div().flex().flex_col().gap(px(10.)).child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(cors_box)
                .child(div().child("Answer CORS requests")),
        );
        if f.cors_on {
            cors = cors.child(self.cors_fields(cx));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field(
                "Header changes",
                Some("Set, add or remove request or response headers. Proxy-managed and identity headers are refused."),
                ops,
            ))
            .child(div().flex().child(add))
            .child(cors)
            .into_any_element()
    }

    fn op_row(&self, i: usize, row: &OpRow, cx: &mut Context<Self>) -> AnyElement {
        let mut targets = Vec::new();
        for t in [HeaderTarget::Request, HeaderTarget::Response] {
            targets.push(
                seg_item(
                    id("fw-op-target", format!("{i}-{}", target_label(t))),
                    target_label(t),
                    row.target == t,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(r) = this.firewall.ops.get_mut(i) {
                        r.target = t;
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let mut kinds = Vec::new();
        for op in [HeaderOpKind::Set, HeaderOpKind::Add, HeaderOpKind::Remove] {
            kinds.push(
                seg_item(
                    id("fw-op-kind", format!("{i}-{}", op_label(op))),
                    op_label(op),
                    row.op == op,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(r) = this.firewall.ops.get_mut(i) {
                        r.op = op;
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let value: AnyElement = if row.op == HeaderOpKind::Remove {
            text_dim("No value needed")
                .text_size(px(12.))
                .into_any_element()
        } else {
            row.value.clone().into_any_element()
        };
        div()
            .flex()
            .items_center()
            .gap(px(8.))
            .child(seg_row(targets))
            .child(seg_row(kinds))
            .child(div().w(px(200.)).child(row.name.clone()))
            .child(div().flex_1().child(value))
            .child(
                btn(id("fw-op-del", i), "Remove", BtnKind::Danger).on_click(cx.listener(
                    move |this, _, _, cx| {
                        if i < this.firewall.ops.len() {
                            let gone = this.firewall.ops.remove(i);
                            for input in [gone.name, gone.value] {
                                input.update(cx, |t, cx| t.set_text("", cx));
                            }
                        }
                        cx.notify();
                    },
                )),
            )
            .into_any_element()
    }

    fn cors_fields(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let half = |label: &str, hint: Option<&str>, e: &Entity<TextInput>| {
            div().flex_1().child(field(label, hint, e.clone()))
        };
        let creds = checkbox(id("fw-cors", "creds"), f.cors_credentials).on_click(cx.listener(
            |this, _, _, cx| {
                this.firewall.cors_credentials = !this.firewall.cors_credentials;
                cx.notify();
            },
        ));
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(field(
                "Allowed origins",
                Some("Exact origins such as https://app.example.com, separated by spaces or commas, or a single *. At most 32."),
                f.cors_origins.clone(),
            ))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Methods", Some("Comma separated"), &f.cors_methods))
                    .child(half("Allowed headers", Some("Comma separated"), &f.cors_allow)),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Exposed headers", Some("Comma separated"), &f.cors_expose))
                    .child(half("Max age (seconds)", Some("0 to 86400"), &f.cors_max_age)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(creds)
                    .child(div().child("Allow credentials")),
            );
        if f.cors_credentials {
            col = col.child(
                text_dim(
                    "Credentials need exact origins: the origin * is refused together with them.",
                )
                .text_size(px(12.)),
            );
        }
        col.into_any_element()
    }

    fn header_matcher_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let mut modes = Vec::new();
        for (regex, label) in [(false, "Equals"), (true, "Regex")] {
            modes.push(
                seg_item(id("fw-hmode", label), label, f.header_regex == regex)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.firewall.header_regex = regex;
                        if regex {
                            this.set_header_secret(false, cx);
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let value = if f.header_secret {
            f.header_secret_value.clone()
        } else {
            f.header_value.clone()
        };
        let negate = checkbox(id("fw-header", "negate"), f.header_negate).on_click(cx.listener(
            |this, _, _, cx| {
                this.firewall.header_negate = !this.firewall.header_negate;
                cx.notify();
            },
        ));
        let secret = checkbox(id("fw-header", "secret"), f.header_secret).on_click(cx.listener(
            |this, _, _, cx| {
                let on = !this.firewall.header_secret;
                if on && this.firewall.header_regex {
                    this.firewall.error =
                        Some("A secret header value can only be compared for equality.".into());
                } else {
                    this.set_header_secret(on, cx);
                }
                cx.notify();
            },
        ));
        let toggles = div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(negate)
                    .child(div().child("Match when the header is not this value")),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(secret)
                    .child(div().child("Secret value")),
            )
            .child(
                text_dim("A secret value is hidden while you type, is never shown in the rule list and cannot be read back.")
                    .text_size(px(11.)),
            );
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex_1().child(field(
                        "Header name",
                        Some("Optional. Letters, digits, - and _."),
                        f.header_name.clone(),
                    )))
                    .child(div().flex_1().child(field("Header value", None, value)))
                    .child(div().child(field(
                        "Compare as",
                        None,
                        div().flex().child(seg_row(modes)),
                    ))),
            )
            .child(toggles)
            .into_any_element()
    }

    fn scheme_field(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut items = Vec::new();
        for (value, label) in [
            (None, "Any"),
            (Some("http"), "HTTP"),
            (Some("https"), "HTTPS"),
        ] {
            items.push(
                seg_item(id("fw-scheme", label), label, self.firewall.scheme == value)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.firewall.scheme = value;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        field(
            "Scheme",
            Some("How the visitor connected (Cloudflare's view on Flexible sites)"),
            div().flex().child(seg_row(items)),
        )
        .into_any_element()
    }
}
