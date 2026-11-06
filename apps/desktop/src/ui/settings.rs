use cite_client::TokenMeta;
use cite_edge::model::EdgeSettings;
use gpui::{AnyElement, ClipboardItem, Context, Div, Entity, FontWeight, div, prelude::*, px};

use crate::app::{Confirm, Console, Load, new_input};
use crate::archive::retention_warning;
use crate::certs::ensure_same_node;
use crate::config::KEYCHAIN_SERVICE;
use crate::demo::now_ms;
use crate::model::{SettingsDraft, parse_rfc3339_ms, rel_time};
use crate::scope::{TokenShelf, foreign_notice};
use crate::theme::{CARD_RADIUS, DIM, DIVIDER, MONO, SURFACE, TEXT, Tone, c, chip_stroke};
use crate::ui::chart::{FIELD_MIN, clip_tip, wide};
use crate::ui::input::TextInput;
use crate::ui::nodes::hostname;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, empty_state, field, grid_min, id, mono, notice, page_header, seg_item,
    seg_row, skeleton, strong, tab_bar, tab_item, table, text_dim, toggle,
};

pub struct Data {
    pub settings: EdgeSettings,
    pub tokens: Vec<TokenMeta>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Tab {
    #[default]
    General,
    Nodes,
    Certificates,
    Alerts,
    Retention,
    Tokens,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::General,
        Tab::Nodes,
        Tab::Certificates,
        Tab::Alerts,
        Tab::Retention,
        Tab::Tokens,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tab::General => "General",
            Tab::Nodes => "Nodes",
            Tab::Certificates => "Certificates",
            Tab::Alerts => "Alerts",
            Tab::Retention => "Retention and ranges",
            Tab::Tokens => "Tokens",
        }
    }

    // Tabs that show one node's configuration and so need a connected node and its loaded settings.
    pub fn needs_node(self) -> bool {
        !matches!(self, Tab::General | Tab::Nodes)
    }
}

pub struct State {
    pub tab: Tab,
    pub data: Load<Data>,
    // The node the loaded data came from; saves are refused for any other node.
    pub data_node: String,
    pub error: Option<String>,
    pub store_ua: bool,
    pub store_ip: bool,
    pub keep_forever: bool,
    pub archive_before_delete: bool,
    // New API tokens by node; each is shown only while its node is selected and stays until dismissed.
    pub created: TokenShelf,
    pub recent: Entity<TextInput>,
    pub minutes: Entity<TextInput>,
    pub hours: Entity<TextInput>,
    pub audit: Entity<TextInput>,
    pub persist: Entity<TextInput>,
    pub rate: Entity<TextInput>,
    pub token_name: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            tab: Tab::default(),
            data: Load::Idle,
            data_node: String::new(),
            error: None,
            store_ua: true,
            store_ip: true,
            keep_forever: true,
            archive_before_delete: true,
            created: TokenShelf::default(),
            recent: new_input(cx, "5000", |i| i.mono()),
            minutes: new_input(cx, "48", |i| i.mono()),
            hours: new_input(cx, "365", |i| i.mono()),
            audit: new_input(cx, "365", |i| i.mono()),
            persist: new_input(cx, "60", |i| i.mono()),
            rate: new_input(cx, "600 (empty disables the limit)", |i| i.mono()),
            token_name: new_input(cx, "ci-pipeline", |i| i),
        }
    }
}

impl Console {
    pub fn load_settings(&mut self, cx: &mut Context<Self>) {
        self.settings.data = Load::Loading;
        let Some(h) = self.active_handle() else {
            self.settings.data = Load::Idle;
            return;
        };
        let node = h.name().to_string();
        let fut = async move {
            let settings = h.get_settings().await?;
            let tokens = h.list_tokens().await.unwrap_or_default();
            Ok(Data { settings, tokens })
        };
        self.fetch_scoped(cx, fut, move |this, res, cx| {
            if let Ok(data) = &res {
                this.fill_settings(&SettingsDraft::from_settings(&data.settings), cx);
                this.settings.data_node = node;
            }
            this.settings.data = Load::from_result(res);
            cx.notify();
        });
        self.load_certs(cx);
    }

    // Inputs mirror the node's values so unchanged fields round trip untouched.
    fn fill_settings(&mut self, d: &SettingsDraft, cx: &mut Context<Self>) {
        let s = &self.settings;
        let pairs = [
            (&s.recent, &d.recent_events),
            (&s.minutes, &d.minute_buckets_hours),
            (&s.hours, &d.hour_buckets_days),
            (&s.audit, &d.audit_days),
            (&s.persist, &d.persist_interval_secs),
            (&s.rate, &d.per_ip_rate_limit),
        ];
        for (input, text) in pairs {
            input.update(cx, |i, cx| i.set_text(text, cx));
        }
        self.settings.store_ua = d.store_user_agents;
        self.settings.store_ip = d.store_client_ips;
        self.settings.keep_forever = d.keep_forever;
        self.settings.archive_before_delete = d.archive_before_delete;
    }

    fn current_draft(&self, cx: &Context<Self>) -> SettingsDraft {
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        let s = &self.settings;
        SettingsDraft {
            recent_events: t(&s.recent),
            minute_buckets_hours: t(&s.minutes),
            keep_forever: s.keep_forever,
            hour_buckets_days: t(&s.hours),
            archive_before_delete: s.archive_before_delete,
            audit_days: t(&s.audit),
            persist_interval_secs: t(&s.persist),
            per_ip_rate_limit: t(&s.rate),
            store_user_agents: s.store_ua,
            store_client_ips: s.store_ip,
        }
    }

    // The draft is applied over the loaded settings and validated before sending.
    fn save_settings(&mut self, cx: &mut Context<Self>) {
        let (Some(h), Some(data)) = (self.active_handle(), self.settings.data.ready()) else {
            return;
        };
        if let Err(msg) = ensure_same_node(&self.settings.data_node, self.active_name().as_deref())
        {
            self.settings.error = Some(msg);
            return;
        }
        match self.current_draft(cx).apply(&data.settings) {
            Ok(next) => {
                self.settings.error = None;
                self.mutate(
                    cx,
                    async move { h.put_settings(&next).await },
                    "Settings saved".into(),
                );
            }
            Err(e) => self.settings.error = Some(e),
        }
    }

    // The token value is kept in memory only until the user dismisses the notice.
    fn create_token(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        let name = self.settings.token_name.read(cx).text().trim().to_string();
        if name.is_empty() {
            self.settings.error = Some("Give the token a name.".into());
            return;
        }
        self.settings.error = None;
        self.settings
            .token_name
            .update(cx, |i, cx| i.set_text("", cx));
        let node = h.name().to_string();
        self.fetch_origin(
            cx,
            async move { h.create_token(&name).await },
            move |this, res, here, origin, cx| {
                match res {
                    Ok(created) => {
                        this.settings.created.put(&node, created.token);
                        if here {
                            this.load_settings(cx);
                        } else {
                            this.say(
                                format!(
                                    "API token created on {node}: open its Settings page to copy it"
                                ),
                                Tone::Ok,
                            );
                        }
                    }
                    Err(e) if here => this.say(e.to_string(), Tone::Bad),
                    Err(e) => this.say(
                        foreign_notice("Create token", origin, &e.to_string()),
                        Tone::Bad,
                    ),
                }
                cx.notify();
            },
        );
    }

    pub fn render_settings(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let subtitle = match self.active_name() {
            Some(n) => format!("Configuration of {n}"),
            None => "Console preferences".into(),
        };
        let tab = self.settings.tab;
        let mut strip = Vec::new();
        for t in Tab::ALL {
            strip.push(
                tab_item(id("set-tab", t.label()), t.label(), t == tab)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.settings.tab = t;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let col = div()
            .flex()
            .flex_col()
            .gap(px(SPACE))
            .child(page_header("Settings", &subtitle, Vec::new()))
            .child(tab_bar(strip));
        let body = self.settings_tab_body(tab, cx);
        col.child(body).into_any_element()
    }

    fn settings_tab_body(&mut self, tab: Tab, cx: &mut Context<Self>) -> AnyElement {
        let mut col = div().flex().flex_col().gap(px(SPACE));
        if !tab.needs_node() {
            let body = if tab == Tab::General {
                self.general_tab()
            } else {
                self.nodes_panel(cx)
            };
            return col.child(body).into_any_element();
        }
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        col = col.children(self.scope_note());
        match &self.settings.data {
            Load::Idle | Load::Loading => {
                return col
                    .child(skeleton(220.))
                    .child(skeleton(160.))
                    .into_any_element();
            }
            Load::Failed(msg) => {
                let msg = msg.clone();
                return col.child(self.error_block(cx, &msg)).into_any_element();
            }
            Load::Ready(_) => {}
        }
        col = match tab {
            Tab::Certificates => {
                let tools = self.certtools_card(cx);
                col.child(self.certs_card(cx)).child(tools)
            }
            Tab::Alerts => col.child(self.alerts_card(cx)),
            Tab::Retention => col
                .child(self.retention_card(cx))
                .child(self.ranges_card(cx)),
            Tab::Tokens => {
                let tokens = match &self.settings.data {
                    Load::Ready(data) => self.tokens_card(data, cx),
                    _ => skeleton(160.).into_any_element(),
                };
                col.child(tokens)
            }
            Tab::General | Tab::Nodes => col,
        };
        col.into_any_element()
    }

    // Shows where credentials live so the storage model is never a surprise.
    fn general_tab(&self) -> AnyElement {
        let path = if self.demo {
            "In-memory demo data".to_string()
        } else {
            self.config_path.display().to_string()
        };
        let value = |key: &str, text: String| {
            clip_tip(id("set-general", key), text)
                .font_family(MONO)
                .text_size(px(12.))
                .text_color(c(DIM))
                .into_any_element()
        };
        let desktop = group(vec![
            form_row(
                "Config file",
                Some("Nodes and saved filters; never holds a token."),
                value("config", path),
            ),
            form_row(
                "Keychain service",
                Some("Node tokens live in the operating system keychain."),
                value("keychain", KEYCHAIN_SERVICE.to_string()),
            ),
        ]);
        let about = group(vec![
            form_row(
                "Computer",
                Some("Names the tokens this console mints."),
                value("host", hostname()),
            ),
            form_row(
                "Version",
                None,
                value("version", env!("CARGO_PKG_VERSION").to_string()),
            ),
            form_row(
                "Appearance",
                Some("The console follows a single dark theme."),
                value("theme", "Dark".to_string()),
            ),
        ]);
        div()
            .flex()
            .flex_col()
            .gap(px(SPACE))
            .child(section("Desktop configuration", desktop))
            .child(section("This computer", about))
            .into_any_element()
    }

    fn retention_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.settings;
        let cell = |label: &str, hint: &str, e: &Entity<TextInput>| {
            field(label, Some(hint), e.clone()).into_any_element()
        };
        let switch = |key: &str,
                      on: bool,
                      label: &str,
                      detail: &str,
                      f: fn(&mut Console) -> &mut bool,
                      cx: &mut Context<Self>| {
            form_row(
                label,
                Some(detail),
                toggle(id("ret", key), on)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let flag = f(this);
                        *flag = !*flag;
                        cx.notify();
                    }))
                    .into_any_element(),
            )
        };
        let (ua, ip) = (s.store_ua, s.store_ip);
        let mut keep = Vec::new();
        for (forever, label) in [(true, "Forever"), (false, "Delete data older than N days")] {
            keep.push(
                seg_item(id("ret-keep", label), label, s.keep_forever == forever)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.settings.keep_forever = forever;
                        if !forever && this.settings.hours.read(cx).text().trim().is_empty() {
                            this.settings
                                .hours
                                .update(cx, |i, cx| i.set_text("365", cx));
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut history_rows = vec![form_row(
            "Keep data",
            Some("Hourly history is kept forever unless you choose a limit."),
            seg_row(keep).into_any_element(),
        )];
        if !s.keep_forever {
            history_rows.push(form_row(
                "Days to keep",
                Some("1 to 3650"),
                div()
                    .w(px(140.))
                    .flex_shrink()
                    .min_w(px(80.))
                    .child(s.hours.clone())
                    .into_any_element(),
            ));
        }
        history_rows.push(switch(
            "archive",
            s.archive_before_delete,
            "Archive before deleting",
            "Saves a copy of old data before it is removed.",
            |c| &mut c.settings.archive_before_delete,
            cx,
        ));
        let mut history = div()
            .flex()
            .flex_col()
            .gap(px(GAP))
            .child(group(history_rows));
        let days_text = s.hours.read(cx).text().to_string();
        if let Some(warning) =
            retention_warning(s.keep_forever, s.archive_before_delete, &days_text)
        {
            history = history.child(notice(&warning, Tone::Bad));
        }
        let limits = grid_min(
            FIELD_MIN,
            vec![
                cell("Recent events", "Kept in memory", &s.recent),
                cell(
                    "Minute buckets (hours)",
                    "Fine-grained history",
                    &s.minutes,
                ),
                cell(
                    "Audit log (days)",
                    "How long changes are kept",
                    &s.audit,
                ),
                cell(
                    "Persist interval (s)",
                    "How often stats hit disk",
                    &s.persist,
                ),
                cell("Per-IP rate limit", "Requests per minute", &s.rate),
            ],
        );
        let privacy = group(vec![
            switch(
                "ua",
                ua,
                "Store user agents",
                "Needed for bot detection detail and the agent lists.",
                |c| &mut c.settings.store_ua,
                cx,
            ),
            switch(
                "ip",
                ip,
                "Store client IPs",
                "Needed for the client lists and IP filters.",
                |c| &mut c.settings.store_ip,
                cx,
            ),
        ]);
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(SPACE))
            .child(section("History", history))
            .child(section("Limits", limits))
            .child(section("Privacy", privacy));
        if let Some(err) = &self.settings.error {
            body = body.child(notice(err, Tone::Bad));
        }
        body = body.child(
            div()
                .flex()
                .gap(px(8.))
                .child(
                    btn(id("set", "save"), "Save settings", BtnKind::Primary).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.save_settings(cx);
                            cx.notify();
                        }),
                    ),
                )
                .child(
                    btn(id("set", "defaults"), "Reset to defaults", BtnKind::Plain).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.fill_settings(&SettingsDraft::defaults(), cx);
                            cx.notify();
                        }),
                    ),
                ),
        );
        div()
            .flex()
            .flex_col()
            .gap(px(GAP))
            .child(
                text_dim(
                    "History is kept forever by default. Choose a limit only if old data may be removed, and keep archiving on to save a copy first.",
                )
                .text_size(px(12.)),
            )
            .child(body)
            .into_any_element()
    }

    // A created token is displayed once with a copy button, as the node never shows it again.
    fn tokens_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let rows: Vec<Vec<AnyElement>> = data
            .tokens
            .iter()
            .map(|t| {
                let (tid, name) = (t.id.clone(), t.name.clone());
                let revoke = btn(id("tok-del", &t.id), "Revoke", BtnKind::Danger).on_click(
                    cx.listener(move |this, _, _, cx| {
                        let (tid, label) = (tid.clone(), name.clone());
                        this.ask(Confirm {
                            title: "Revoke token".into(),
                            message: format!(
                                "Revoke {label}? Anything using it stops working immediately."
                            ),
                            label: "Revoke".into(),
                            danger: true,
                            action: Box::new(move |this, cx| {
                                if let Some(h) = this.active_handle() {
                                    this.mutate(
                                        cx,
                                        async move { h.delete_token(&tid).await },
                                        format!("Token {label} revoked"),
                                    );
                                }
                            }),
                        });
                        cx.notify();
                    }),
                );
                let when = |text: &str| rel_time(now_ms(), parse_rfc3339_ms(text).unwrap_or(0));
                vec![
                    strong(t.name.clone()).into_any_element(),
                    mono(t.id.clone()).text_color(c(DIM)).into_any_element(),
                    text_dim(when(&t.created_at)).into_any_element(),
                    text_dim(t.last_used_at.as_deref().map_or("never".to_string(), when))
                        .into_any_element(),
                    revoke.into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::flex("Name"),
            Col::fixed("Id", 140.),
            Col::fixed("Created", 110.),
            Col::fixed("Last used", 110.),
            Col::fixed("", 90.),
        ];
        let mut body = div().flex().flex_col().gap(px(12.));
        let active = self.active_name().unwrap_or_default();
        let shown = self.settings.created.for_node(&active).map(str::to_string);
        if let Some(token) = shown {
            let (copy_node, done_node) = (active.clone(), active.clone());
            body = body.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(12.))
                    .p(px(12.))
                    .rounded(px(crate::theme::ROW_RADIUS))
                    .border_1()
                    .border_color(c(Tone::Warn.color()))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(strong("Copy your new token"))
                            .child(
                                text_dim("It is shown once and cannot be retrieved later.")
                                    .text_size(px(12.)),
                            )
                            .child(
                                clip_tip(id("tok", "value"), token)
                                    .font_family(MONO)
                                    .text_size(px(12.)),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .gap(px(8.))
                            .child(btn(id("tok", "copy"), "Copy", BtnKind::Primary).on_click(
                                cx.listener(move |this, _, _, cx| {
                                    let found = this
                                        .settings
                                        .created
                                        .for_node(&copy_node)
                                        .map(str::to_string);
                                    if let Some(token) = found {
                                        cx.write_to_clipboard(ClipboardItem::new_string(token));
                                    }
                                }),
                            ))
                            .child(btn(id("tok", "dismiss"), "Done", BtnKind::Plain).on_click(
                                cx.listener(move |this, _, _, cx| {
                                    this.settings.created.dismiss(&done_node);
                                    cx.notify();
                                }),
                            )),
                    ),
            );
        }
        body = body
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(10.))
                    .child(div().flex_1().min_w_0().max_w(px(420.)).child(field(
                        "New token name",
                        None,
                        self.settings.token_name.clone(),
                    )))
                    .child(
                        btn(id("tok", "create"), "Create token", BtnKind::Primary).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.create_token(cx);
                                cx.notify();
                            }),
                        ),
                    ),
            )
            .child(wide(
                id("tok", "table"),
                560.,
                table(
                    &cols,
                    rows,
                    Some(empty_state(
                        "No API tokens",
                        "Create a long-lived token for scripts and CI pipelines.",
                    )),
                ),
            ));
        if let Some(err) = &self.settings.error {
            body = body.child(notice(err, Tone::Bad));
        }
        card(
            Some("API tokens"),
            Some("Long-lived tokens for scripts and CI pipelines on this node."),
            body,
        )
        .into_any_element()
    }
}

// The spacing rhythm shared by settings and the setup flows: SPACE between sections, GAP inside them.
pub(crate) const SPACE: f32 = 20.0;
pub(crate) const GAP: f32 = 12.0;

pub(crate) fn section(title: &str, body: impl IntoElement) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(8.))
        .min_w_0()
        .child(
            div()
                .pl(px(4.))
                .text_size(px(11.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(c(DIM))
                .child(title.to_string()),
        )
        .child(body)
}

// Rows of one settings group share a rounded panel and are split by hairlines.
pub(crate) fn group(rows: Vec<AnyElement>) -> Div {
    let mut root = div()
        .flex()
        .flex_col()
        .w_full()
        .min_w_0()
        .overflow_hidden()
        .rounded(px(CARD_RADIUS + 2.))
        .border_1()
        .border_color(chip_stroke())
        .bg(c(SURFACE));
    for (i, row) in rows.into_iter().enumerate() {
        if i > 0 {
            root = root.child(div().h(px(1.)).w_full().bg(c(DIVIDER)));
        }
        root = root.child(row);
    }
    root
}

// A title and optional detail on the left, the control on the right; the text column shrinks first.
pub(crate) fn form_row(title: &str, detail: Option<&str>, control: AnyElement) -> AnyElement {
    let mut text = div()
        .flex()
        .flex_col()
        .gap(px(2.))
        .flex_1()
        .min_w(px(120.))
        .child(
            div()
                .text_size(px(13.))
                .font_weight(FontWeight::MEDIUM)
                .text_color(c(TEXT))
                .child(title.to_string()),
        );
    if let Some(d) = detail {
        text = text.child(text_dim(d.to_string()).text_size(px(11.)));
    }
    div()
        .flex()
        .flex_wrap()
        .items_center()
        .justify_between()
        .gap(px(16.))
        .min_h(px(52.))
        .px(px(16.))
        .py(px(12.))
        .child(text)
        .child(
            div()
                .flex()
                .justify_end()
                .flex_shrink()
                .min_w_0()
                .max_w_full()
                .child(control),
        )
        .into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tabs_are_listed_once_with_distinct_labels() {
        let labels: Vec<&str> = Tab::ALL.iter().map(|t| t.label()).collect();
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), labels.len());
        assert_eq!(Tab::default(), Tab::General);
    }

    #[test]
    fn only_node_scoped_tabs_need_a_node() {
        assert!(!Tab::General.needs_node());
        assert!(!Tab::Nodes.needs_node());
        for t in [Tab::Certificates, Tab::Alerts, Tab::Retention, Tab::Tokens] {
            assert!(t.needs_node());
        }
    }
}
