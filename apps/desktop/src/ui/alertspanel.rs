use std::future::Future;

use cite_client::ClientError;
use cite_edge::alerts::{AlertEvent, MAX_WEBHOOKS, TlsMode, WebhookKind};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::alertcfg::{
    AlertsConfig, AlertsDraft, EmailDraft, EmailInfo, WebhookDraft, default_port, display_url,
    email_target, event_label, events_text, kind_label, test_note, tls_label, toggle_event,
};
use crate::app::{Console, new_input};
use crate::bots::is_unsupported;
use crate::certs::ensure_same_node;
use crate::scope::{Sequence, foreign_notice};
use crate::theme::{BORDER, ROW_RADIUS, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, btn, btn_off, card, checkbox, field, id, notice, pill, section_title, seg_item,
    seg_row, skeleton, strong, text_dim, toggle,
};

struct HookRow {
    id: Option<String>,
    stored_url: String,
    name: Entity<TextInput>,
    url: Entity<TextInput>,
    kind: WebhookKind,
    events: Vec<AlertEvent>,
}

struct EmailRow {
    host: Entity<TextInput>,
    port: Entity<TextInput>,
    username: Entity<TextInput>,
    password: Entity<TextInput>,
    from: Entity<TextInput>,
    to: Entity<TextInput>,
    tls: TlsMode,
    password_set: bool,
    stored: bool,
    events: Vec<AlertEvent>,
}

// The node the form was loaded for; a save or test for any other node is refused.
struct Form {
    node: String,
    enabled: bool,
    cooldown: Entity<TextInput>,
    hooks: Vec<HookRow>,
    email: Option<EmailRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Busy {
    Saving,
    Testing(String),
}

impl Busy {
    fn label(&self) -> String {
        match self {
            Busy::Saving => "Saving the alert settings...".into(),
            Busy::Testing(what) => format!("Sending a test to {what}..."),
        }
    }
}

#[derive(Clone, Copy)]
enum EventsOf {
    Hook(usize),
    Email,
}

#[derive(Default)]
pub(crate) struct AlertsState {
    requested: bool,
    unsupported: bool,
    load_error: Option<String>,
    form: Option<Form>,
    busy: Option<Busy>,
    note: Option<(String, Tone)>,
    seq: Sequence,
}

fn op_error(err: &ClientError) -> String {
    match err {
        ClientError::Config(msg) => msg.clone(),
        other => other.to_string(),
    }
}

// The name the user gave it, or the stored id when the name box was emptied.
fn test_label(name: &str, stored_id: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        stored_id.to_string()
    } else {
        name.to_string()
    }
}

fn text_input(
    cx: &mut Context<Console>,
    placeholder: &str,
    text: &str,
    shape: impl FnOnce(TextInput) -> TextInput,
) -> Entity<TextInput> {
    let input = new_input(cx, placeholder, shape);
    if !text.is_empty() {
        input.update(cx, |i, cx| i.set_text(text, cx));
    }
    input
}

fn make_hook(
    cx: &mut Context<Console>,
    stored_id: Option<String>,
    name: &str,
    kind: WebhookKind,
    stored_url: String,
    events: Vec<AlertEvent>,
) -> HookRow {
    HookRow {
        id: stored_id,
        stored_url,
        name: text_input(cx, "Ops chat", name, |i| i),
        url: text_input(cx, "https://hooks.example.com/...", "", |i| {
            i.mono().masked()
        }),
        kind,
        events,
    }
}

fn make_email(cx: &mut Context<Console>, info: Option<&EmailInfo>) -> EmailRow {
    let text = |v: Option<String>| v.unwrap_or_default();
    EmailRow {
        host: text_input(
            cx,
            "smtp.example.com",
            &text(info.map(|e| e.host.clone())),
            |i| i.mono(),
        ),
        port: text_input(cx, "587", &text(info.map(|e| e.port.to_string())), |i| {
            i.mono()
        }),
        username: text_input(
            cx,
            "alerts@example.com",
            &text(info.map(|e| e.username.clone())),
            |i| i,
        ),
        password: text_input(cx, "SMTP password", "", |i| i.mono().masked()),
        from: text_input(
            cx,
            "alerts@example.com",
            &text(info.map(|e| e.from.clone())),
            |i| i,
        ),
        to: text_input(
            cx,
            "ops@example.com, oncall@example.com",
            &text(info.map(|e| e.to.join(", "))),
            |i| i,
        ),
        tls: info.map(|e| e.tls).unwrap_or(TlsMode::Starttls),
        password_set: info.is_some_and(|e| e.password_set),
        stored: info.is_some(),
        events: info.map(|e| e.events.clone()).unwrap_or_default(),
    }
}

impl Form {
    fn from_config(cfg: &AlertsConfig, node: &str, cx: &mut Context<Console>) -> Self {
        let hooks = cfg
            .webhooks
            .iter()
            .map(|h| {
                make_hook(
                    cx,
                    Some(h.id.clone()),
                    &h.name,
                    h.kind,
                    h.url.clone(),
                    h.events.clone(),
                )
            })
            .collect();
        let email = cfg.email.as_ref().map(|e| make_email(cx, Some(e)));
        Self {
            node: node.to_string(),
            enabled: cfg.enabled,
            cooldown: text_input(cx, "900", &cfg.cooldown_secs.to_string(), |i| i.mono()),
            hooks,
            email,
        }
    }

    // Typed addresses and the password are overwritten before the inputs are dropped.
    fn clear_secrets(&self, cx: &mut Context<Console>) {
        for hook in &self.hooks {
            hook.url.update(cx, |i, cx| i.set_text("", cx));
        }
        if let Some(mail) = &self.email {
            mail.password.update(cx, |i, cx| i.set_text("", cx));
        }
    }
}

impl Console {
    fn al_note(&mut self, text: impl Into<String>, tone: Tone) {
        self.alerts.note = Some((text.into(), tone));
    }

    fn al_clear_secrets(&mut self, cx: &mut Context<Self>) {
        if let Some(form) = self.alerts.form.take() {
            form.clear_secrets(cx);
        }
    }

    // Drops the form and everything typed into it, so nothing loaded for one node outlives a node switch.
    pub(crate) fn alerts_reset(&mut self, cx: &mut Context<Self>) {
        self.al_clear_secrets(cx);
        let seq = self.alerts.seq;
        self.alerts = AlertsState::default();
        self.alerts.seq = seq;
    }

    fn load_alerts(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        self.alerts.requested = true;
        self.alerts.load_error = None;
        let node = h.name().to_string();
        let seq = self.alerts.seq.issue();
        self.fetch(
            cx,
            async move { h.tools_alerts_load().await },
            move |this, res, cx| {
                if this.active_name().as_deref() != Some(node.as_str())
                    || !this.alerts.seq.accept(seq)
                {
                    return;
                }
                this.alerts.unsupported = false;
                match res {
                    Ok(cfg) => this.apply_alerts(&cfg, &node, cx),
                    Err(e) if is_unsupported(&e) => {
                        this.al_clear_secrets(cx);
                        this.alerts.unsupported = true;
                    }
                    Err(e) => this.alerts.load_error = Some(op_error(&e)),
                }
                cx.notify();
            },
        );
    }

    fn apply_alerts(&mut self, cfg: &AlertsConfig, node: &str, cx: &mut Context<Self>) {
        self.al_clear_secrets(cx);
        self.alerts.form = Some(Form::from_config(cfg, node, cx));
    }

    fn alerts_draft(&self, cx: &Context<Self>) -> Option<AlertsDraft> {
        let form = self.alerts.form.as_ref()?;
        let text = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        Some(AlertsDraft {
            enabled: form.enabled,
            cooldown: text(&form.cooldown),
            webhooks: form
                .hooks
                .iter()
                .map(|r| WebhookDraft {
                    id: r.id.clone(),
                    name: text(&r.name),
                    kind: r.kind,
                    url: text(&r.url),
                    events: r.events.clone(),
                })
                .collect(),
            email: form.email.as_ref().map(|m| EmailDraft {
                host: text(&m.host),
                port: text(&m.port),
                tls: m.tls,
                username: text(&m.username),
                password: text(&m.password),
                password_set: m.password_set,
                from: text(&m.from),
                to: text(&m.to),
                events: m.events.clone(),
            }),
        })
    }

    // One operation at a time; a result that arrives after the user moved on is reported as a toast.
    fn run_alert_op<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        busy: Busy,
        noun: String,
        fut: F,
        done: impl FnOnce(&mut Self, T, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        if self.alerts.busy.is_some() {
            return;
        }
        self.alerts.busy = Some(busy);
        self.alerts.note = None;
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            this.alerts.busy = None;
            match (res, here) {
                (Ok(v), true) => done(this, v, cx),
                (Err(e), true) => this.al_note(op_error(&e), Tone::Bad),
                (Ok(_), false) => {
                    this.alerts.requested = false;
                    this.say(foreign_notice(&noun, origin, "done"), Tone::Ok);
                }
                (Err(e), false) => {
                    this.say(foreign_notice(&noun, origin, &op_error(&e)), Tone::Bad)
                }
            }
            cx.notify();
        });
    }

    fn form_still_here(&mut self) -> bool {
        let Some(form) = self.alerts.form.as_ref() else {
            return false;
        };
        match ensure_same_node(&form.node, self.active_name().as_deref()) {
            Ok(()) => true,
            Err(msg) => {
                self.al_note(msg, Tone::Bad);
                false
            }
        }
    }

    fn save_alerts(&mut self, cx: &mut Context<Self>) {
        if self.alerts.busy.is_some() {
            return;
        }
        let Some(h) = self.active_handle() else {
            return;
        };
        if !self.form_still_here() {
            return;
        }
        let Some(draft) = self.alerts_draft(cx) else {
            return;
        };
        let request = match draft.to_request() {
            Ok(r) => r,
            Err(msg) => {
                self.al_note(msg, Tone::Bad);
                return;
            }
        };
        drop(draft);
        let node = h.name().to_string();
        self.run_alert_op(
            cx,
            Busy::Saving,
            "Saving alert settings".into(),
            async move { h.tools_alerts_save(request).await },
            move |this, cfg, cx| {
                this.apply_alerts(&cfg, &node, cx);
                this.al_note("Alert settings saved.", Tone::Ok);
            },
        );
    }

    // The node tests what it has stored, so unsaved edits are not part of a test.
    fn test_alert(&mut self, target: String, label: String, cx: &mut Context<Self>) {
        if self.alerts.busy.is_some() {
            return;
        }
        let Some(h) = self.active_handle() else {
            return;
        };
        if !self.form_still_here() {
            return;
        }
        let noun = format!("Alert test to {label}");
        let busy = Busy::Testing(label.clone());
        self.run_alert_op(
            cx,
            busy,
            noun,
            async move { h.tools_alerts_test(&target).await },
            move |this, result, _| {
                let (text, tone) = test_note(&label, &result);
                this.al_note(text, tone);
            },
        );
    }

    fn al_discard(&mut self, cx: &mut Context<Self>) {
        self.al_clear_secrets(cx);
        self.alerts.requested = false;
        self.alerts.note = None;
    }

    fn al_add_hook(&mut self, cx: &mut Context<Self>) {
        let row = make_hook(
            cx,
            None,
            "",
            WebhookKind::Generic,
            String::new(),
            Vec::new(),
        );
        if let Some(form) = self.alerts.form.as_mut()
            && form.hooks.len() < MAX_WEBHOOKS
        {
            form.hooks.push(row);
        }
    }

    fn al_remove_hook(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(form) = self.alerts.form.as_mut() else {
            return;
        };
        if index >= form.hooks.len() {
            return;
        }
        let row = form.hooks.remove(index);
        row.url.update(cx, |i, cx| i.set_text("", cx));
    }

    fn al_add_email(&mut self, cx: &mut Context<Self>) {
        let row = make_email(cx, None);
        if let Some(form) = self.alerts.form.as_mut() {
            form.email = Some(row);
        }
    }

    fn al_remove_email(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.alerts.form.as_mut().and_then(|f| f.email.take()) else {
            return;
        };
        row.password.update(cx, |i, cx| i.set_text("", cx));
    }

    fn al_toggle_event(&mut self, of: EventsOf, event: AlertEvent) {
        let Some(form) = self.alerts.form.as_mut() else {
            return;
        };
        match of {
            EventsOf::Hook(i) => {
                if let Some(row) = form.hooks.get_mut(i) {
                    toggle_event(&mut row.events, event);
                }
            }
            EventsOf::Email => {
                if let Some(row) = form.email.as_mut() {
                    toggle_event(&mut row.events, event);
                }
            }
        }
    }

    pub(crate) fn alerts_card(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        if !self.alerts.requested && self.active_handle().is_some() {
            self.load_alerts(cx);
        }
        let subtitle = format!(
            "Webhook and email messages {} sends when something needs attention",
            self.active_name().unwrap_or_default()
        );
        let s = &self.alerts;
        if s.unsupported {
            return card(
                Some("Alerts"),
                Some(subtitle.as_str()),
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(pill("needs an update", Tone::Warn))
                    .child(
                        text_dim("This node predates alerts. Update it to use them.")
                            .text_size(px(12.)),
                    ),
            )
            .into_any_element();
        }
        if let Some(err) = &s.load_error {
            let retry = btn(id("al", "retry"), "Retry", BtnKind::Plain).on_click(cx.listener(
                |this, _, _, cx| {
                    this.alerts.requested = false;
                    cx.notify();
                },
            ));
            let body = div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(12.))
                .child(div().flex_1().child(notice(err, Tone::Bad)))
                .child(retry);
            return card(Some("Alerts"), Some(subtitle.as_str()), body).into_any_element();
        }
        let Some(form) = &s.form else {
            return skeleton(160.).into_any_element();
        };
        let idle = s.busy.is_none();
        let mut body = div().flex().flex_col().gap(px(14.)).child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(
                    toggle(id("al", "enabled"), form.enabled).on_click(cx.listener(
                        |this, _, _, cx| {
                            if let Some(f) = this.alerts.form.as_mut() {
                                f.enabled = !f.enabled;
                            }
                            cx.notify();
                        },
                    )),
                )
                .child(div().child("Send alerts")),
        );
        body = body.child(div().w_full().max_w(px(260.)).child(field(
            "Cooldown (seconds)",
            Some("How long to wait before the same alert is sent again. 900 is 15 minutes."),
            form.cooldown.clone(),
        )));
        body = body.child(section_title(&format!(
            "Webhooks ({} of {MAX_WEBHOOKS})",
            form.hooks.len()
        )));
        if form.hooks.is_empty() {
            body = body.child(text_dim("No webhooks yet.").text_size(px(12.)));
        }
        for (i, row) in form.hooks.iter().enumerate() {
            body = body.child(self.hook_card(i, row, idle, cx));
        }
        body = body.child(if idle && form.hooks.len() < MAX_WEBHOOKS {
            div()
                .flex()
                .child(
                    btn(id("al", "add-hook"), "Add webhook", BtnKind::Plain).on_click(cx.listener(
                        |this, _, _, cx| {
                            this.al_add_hook(cx);
                            cx.notify();
                        },
                    )),
                )
                .into_any_element()
        } else {
            div()
                .flex()
                .child(btn_off("Add webhook"))
                .into_any_element()
        });
        body = body.child(section_title("Email"));
        body = body.child(match &form.email {
            Some(mail) => self.email_card(mail, idle, cx),
            None => div()
                .flex()
                .child(
                    btn(id("al", "add-email"), "Set up email alerts", BtnKind::Plain).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.al_add_email(cx);
                            cx.notify();
                        }),
                    ),
                )
                .into_any_element(),
        });
        if let Some(draft) = self.alerts_draft(cx) {
            for warning in draft.warnings() {
                body = body.child(notice(&warning, Tone::Warn));
            }
        }
        let save = if idle {
            btn(id("al", "save"), "Save alerts", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.save_alerts(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Save alerts").into_any_element()
        };
        let discard = if idle {
            btn(id("al", "discard"), "Discard changes", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.al_discard(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Discard changes").into_any_element()
        };
        body = body.child(div().flex().gap(px(8.)).child(save).child(discard));
        if let Some(busy) = &s.busy {
            body = body.child(notice(&busy.label(), Tone::Info));
        }
        if let Some((text, tone)) = &s.note {
            body = body.child(notice(text, *tone));
        }
        card(Some("Alerts"), Some(subtitle.as_str()), body).into_any_element()
    }

    fn panel_shell() -> gpui::Div {
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .p(px(12.))
            .rounded(px(ROW_RADIUS))
            .border_1()
            .border_color(c(BORDER))
    }

    fn event_boxes(
        &self,
        cx: &mut Context<Self>,
        of: EventsOf,
        key: String,
        events: &[AlertEvent],
    ) -> AnyElement {
        let mut list = div().flex().flex_col().gap(px(6.)).child(
            text_dim(format!(
                "Sends: {}. Tick events to limit it.",
                events_text(events)
            ))
            .text_size(px(11.)),
        );
        for event in AlertEvent::ALL {
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(
                        checkbox(id(&key, event.as_str()), events.contains(&event)).on_click(
                            cx.listener(move |this, _, _, cx| {
                                this.al_toggle_event(of, event);
                                cx.notify();
                            }),
                        ),
                    )
                    .child(div().child(event_label(event))),
            );
        }
        list.into_any_element()
    }

    fn hook_card(
        &self,
        index: usize,
        row: &HookRow,
        idle: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mut kinds = Vec::new();
        for kind in [
            WebhookKind::Generic,
            WebhookKind::Discord,
            WebhookKind::Slack,
        ] {
            kinds.push(
                seg_item(
                    id(&format!("al-kind-{index}"), kind_label(kind)),
                    kind_label(kind),
                    row.kind == kind,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(r) = this
                        .alerts
                        .form
                        .as_mut()
                        .and_then(|f| f.hooks.get_mut(index))
                    {
                        r.kind = kind;
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let url_hint = match &row.id {
            Some(_) => format!(
                "Stored as {}. Leave blank to keep it, or paste a new address to replace it.",
                display_url(&row.stored_url)
            ),
            None => {
                "Where Cite posts the message. Must start with https://. It is hidden once saved."
                    .to_string()
            }
        };
        let mut actions = div().flex().gap(px(8.));
        if let (Some(stored), true) = (&row.id, idle) {
            let target = stored.clone();
            let label = test_label(row.name.read(cx).text(), stored);
            actions = actions.child(
                btn(id("al-test", index), "Send test", BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.test_alert(target.clone(), label.clone(), cx);
                        cx.notify();
                    },
                )),
            );
        }
        actions = actions.child(if idle {
            btn(id("al-rm", index), "Remove", BtnKind::Danger)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.al_remove_hook(index, cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Remove").into_any_element()
        });
        Self::panel_shell()
            .child(
                div()
                    .w_full()
                    .max_w(px(420.))
                    .child(field("Name", None, row.name.clone())),
            )
            .child(field(
                "Type",
                Some("Discord and Slack get a message in their own format."),
                div().flex().child(seg_row(kinds)),
            ))
            .child(field(
                "Webhook address",
                Some(url_hint.as_str()),
                row.url.clone(),
            ))
            .child(self.event_boxes(
                cx,
                EventsOf::Hook(index),
                format!("al-hook-ev-{index}"),
                &row.events,
            ))
            .child(actions)
            .into_any_element()
    }

    fn email_card(&self, mail: &EmailRow, idle: bool, cx: &mut Context<Self>) -> AnyElement {
        let mut modes = Vec::new();
        for tls in [TlsMode::Starttls, TlsMode::Tls, TlsMode::None] {
            modes.push(
                seg_item(
                    id("al-tls", tls_label(tls)),
                    tls_label(tls),
                    mail.tls == tls,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(m) = this.alerts.form.as_mut().and_then(|f| f.email.as_mut()) {
                        m.tls = tls;
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let port_hint = format!(
            "Leave blank for {} with this security setting.",
            default_port(mail.tls)
        );
        let password_hint = if mail.password_set {
            "A password is stored on the node. Leave blank to keep it, or type a new one to replace it."
        } else {
            "Hidden here and sent once. The node never shows it again."
        };
        let mut actions = div().flex().gap(px(8.));
        if idle && mail.stored {
            actions = actions.child(
                btn(id("al", "test-email"), "Send test email", BtnKind::Plain).on_click(
                    cx.listener(|this, _, _, cx| {
                        this.test_alert(email_target().to_string(), "email".to_string(), cx);
                        cx.notify();
                    }),
                ),
            );
        }
        actions = actions.child(if idle {
            btn(id("al", "rm-email"), "Remove email", BtnKind::Danger)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.al_remove_email(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Remove email").into_any_element()
        });
        Self::panel_shell()
            .child(strong("Email"))
            .child(field(
                "Mail server",
                Some("The SMTP host that sends the message."),
                mail.host.clone(),
            ))
            .child(div().w_full().max_w(px(200.)).child(field(
                "Port",
                Some(port_hint.as_str()),
                mail.port.clone(),
            )))
            .child(field("Security", None, div().flex().child(seg_row(modes))))
            .child(field(
                "User name",
                Some("Leave blank if the server needs no login."),
                mail.username.clone(),
            ))
            .child(field(
                "Password",
                Some(password_hint),
                mail.password.clone(),
            ))
            .child(field("From", None, mail.from.clone()))
            .child(field(
                "Send to",
                Some("Up to 5 addresses, separated by commas."),
                mail.to.clone(),
            ))
            .child(self.event_boxes(cx, EventsOf::Email, "al-email-ev".to_string(), &mail.events))
            .child(actions)
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_states_describe_what_is_running() {
        assert_eq!(Busy::Saving.label(), "Saving the alert settings...");
        assert_eq!(
            Busy::Testing("Ops chat".into()).label(),
            "Sending a test to Ops chat..."
        );
    }

    #[test]
    fn a_test_is_labelled_by_name_or_else_by_id() {
        assert_eq!(test_label(" Ops chat ", "ops"), "Ops chat");
        assert_eq!(test_label("  ", "ops"), "ops");
    }

    #[test]
    fn client_side_problems_keep_their_wording() {
        assert_eq!(op_error(&ClientError::Config("no".into())), "no");
        assert!(op_error(&ClientError::Decode("odd".into())).contains("odd"));
    }

    #[test]
    fn the_default_state_has_no_form_and_is_idle() {
        let s = AlertsState::default();
        assert!(s.form.is_none() && s.busy.is_none() && !s.requested && !s.unsupported);
    }
}
