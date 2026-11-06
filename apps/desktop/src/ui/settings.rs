use cite_client::TokenMeta;
use cite_edge::model::EdgeSettings;
use gpui::{AnyElement, ClipboardItem, Context, Entity, div, prelude::*, px};

use crate::app::{Confirm, Console, Load, new_input};
use crate::archive::retention_warning;
use crate::certs::ensure_same_node;
use crate::config::KEYCHAIN_SERVICE;
use crate::demo::now_ms;
use crate::model::{SettingsDraft, parse_rfc3339_ms, rel_time};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::nodes::hostname;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, empty_state, field, id, mono, notice, page_header, seg_item, seg_row,
    skeleton, strong, table, text_dim, toggle,
};

pub struct Data {
    pub settings: EdgeSettings,
    pub tokens: Vec<TokenMeta>,
}

pub struct State {
    pub data: Load<Data>,
    // The node the loaded data came from; saves are refused for any other node.
    pub data_node: String,
    pub error: Option<String>,
    pub store_ua: bool,
    pub store_ip: bool,
    pub keep_forever: bool,
    pub archive_before_delete: bool,
    // A new API token with the node it belongs to; it is shown only while that node is selected.
    pub created: Option<(String, String)>,
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
            data: Load::Idle,
            data_node: String::new(),
            error: None,
            store_ua: true,
            store_ip: true,
            keep_forever: true,
            archive_before_delete: true,
            created: None,
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
        self.fetch(
            cx,
            async move { h.create_token(&name).await },
            move |this, res, cx| {
                match res {
                    Ok(created) => {
                        this.settings.created = Some((node, created.token));
                        this.load_settings(cx);
                    }
                    Err(e) => this.say(e.to_string(), Tone::Bad),
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
        let mut col = div().flex().flex_col().gap(px(16.)).child(page_header(
            "Settings",
            &subtitle,
            Vec::new(),
        ));
        col = col.child(self.desktop_card());
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        col = col.children(self.scope_note());
        match &self.settings.data {
            Load::Idle | Load::Loading => col = col.child(skeleton(220.)).child(skeleton(160.)),
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                col = col
                    .child(self.retention_card(cx))
                    .child(self.certs_card(cx))
                    .child(self.ranges_card(cx))
                    .child(self.tokens_card(data, cx));
            }
        }
        col.into_any_element()
    }

    // Shows where credentials live so the storage model is never a surprise.
    fn desktop_card(&self) -> AnyElement {
        let path = if self.demo {
            "In-memory demo data".to_string()
        } else {
            self.config_path.display().to_string()
        };
        let row = |label: &str, value: String| {
            div()
                .flex()
                .gap(px(12.))
                .child(div().w(px(140.)).child(text_dim(label.to_string())))
                .child(mono(value))
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(row("Config file", path))
            .child(row("Keychain service", KEYCHAIN_SERVICE.to_string()))
            .child(row("Computer", hostname()))
            .child(row("Version", env!("CARGO_PKG_VERSION").to_string()));
        card(
            Some("This computer"),
            Some("Node tokens live in the operating system keychain and never in the config file."),
            body,
        )
        .into_any_element()
    }

    fn retention_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.settings;
        let cell = |label: &str, hint: &str, e: &Entity<TextInput>| {
            div()
                .flex_1()
                .min_w(px(160.))
                .child(field(label, Some(hint), e.clone()))
        };
        let switch = |key: &str,
                      on: bool,
                      label: &str,
                      f: fn(&mut Console) -> &mut bool,
                      cx: &mut Context<Self>| {
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(
                    toggle(id("ret", key), on).on_click(cx.listener(move |this, _, _, cx| {
                        let flag = f(this);
                        *flag = !*flag;
                        cx.notify();
                    })),
                )
                .child(div().child(label.to_string()))
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
        let mut history = div().flex().flex_col().gap(px(10.)).child(field(
            "Keep data",
            Some("Hourly history is kept forever unless you choose a limit."),
            div().flex().child(seg_row(keep)),
        ));
        if !s.keep_forever {
            history = history.child(div().w(px(220.)).child(field(
                "Days to keep",
                Some("1 to 3650"),
                s.hours.clone(),
            )));
        }
        history = history.child(switch(
            "archive",
            s.archive_before_delete,
            "Archive old data before deleting it",
            |c| &mut c.settings.archive_before_delete,
            cx,
        ));
        let days_text = s.hours.read(cx).text().to_string();
        if let Some(warning) =
            retention_warning(s.keep_forever, s.archive_before_delete, &days_text)
        {
            history = history.child(notice(&warning, Tone::Bad));
        }
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(history)
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(cell("Recent events", "Kept in memory", &s.recent))
                    .child(cell(
                        "Minute buckets (hours)",
                        "Fine-grained history",
                        &s.minutes,
                    )),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(cell(
                        "Audit log (days)",
                        "How long changes are kept",
                        &s.audit,
                    ))
                    .child(cell(
                        "Persist interval (s)",
                        "How often stats hit disk",
                        &s.persist,
                    ))
                    .child(cell("Per-IP rate limit", "Requests per minute", &s.rate)),
            )
            .child(switch(
                "ua",
                ua,
                "Store user agents",
                |c| &mut c.settings.store_ua,
                cx,
            ))
            .child(switch(
                "ip",
                ip,
                "Store client IPs",
                |c| &mut c.settings.store_ip,
                cx,
            ));
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
        card(
            Some("Data retention and limits"),
            Some(
                "History is kept forever by default. Choose a limit only if old data may be removed, and keep archiving on to save a copy first.",
            ),
            body,
        )
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
        let active = self.active_name();
        let shown = self
            .settings
            .created
            .as_ref()
            .filter(|(node, _)| ensure_same_node(node, active.as_deref()).is_ok())
            .map(|(_, token)| token.clone());
        if let Some(token) = shown {
            let copy_value = token.clone();
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
                            .child(strong("Copy your new token"))
                            .child(
                                text_dim("It is shown once and cannot be retrieved later.")
                                    .text_size(px(12.)),
                            )
                            .child(mono(token)),
                    )
                    .child(
                        div()
                            .flex()
                            .gap(px(8.))
                            .child(btn(id("tok", "copy"), "Copy", BtnKind::Primary).on_click(
                                cx.listener(move |_, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(
                                        copy_value.clone(),
                                    ));
                                }),
                            ))
                            .child(btn(id("tok", "dismiss"), "Done", BtnKind::Plain).on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.settings.created = None;
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
                    .child(div().w(px(300.)).child(field(
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
            .child(table(
                &cols,
                rows,
                Some(empty_state(
                    "No API tokens",
                    "Create a long-lived token for scripts and CI pipelines.",
                )),
            ));
        card(Some("API tokens"), None, body).into_any_element()
    }
}
