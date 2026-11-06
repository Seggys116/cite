use std::future::Future;

use cite_client::ClientError;
use cite_edge::model::{BotPolicy, EdgeSettings};
use gpui::{AnyElement, Context, Div, Entity, div, prelude::*, px};

use crate::app::{Confirm, Console, Load, new_input};
use crate::bots::is_unsupported;
use crate::certs::{
    AccessDraft, BOTS_NOTE, CertBusy, CertItem, CertListing, ClearOn, FLEXIBLE_HELP, FULL_HELP,
    MANUAL_NOTE, RangesListing, UploadForm, bots_help, bots_label, bots_warning, classify_expiry,
    clears_for, coverage_text, date_text, days_text, delete_message, ensure_same_node,
    flexible_warning, is_custom_source, parse_port, parse_range_list, ranges_summary, ranges_text,
    sans_text, short_fingerprint, uncovered_note, uploaded_text, validity_text, zone_lock_help,
};
use crate::scope::{Sequence, foreign_notice};
use crate::theme::{BORDER, DIM, MONO, ROW_RADIUS, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, checkbox, clip, field, id, mono, notice, pill, seg_item,
    seg_row, skeleton, strong, table, text_dim,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Panel {
    Upload {
        node: String,
    },
    Replace {
        node: String,
        id: String,
        name: String,
    },
}

impl Panel {
    // The node the panel was opened for; a submit for any other node is refused.
    pub fn node(&self) -> &str {
        match self {
            Panel::Upload { node } | Panel::Replace { node, .. } => node,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Card {
    Certs,
    Ranges,
}

pub struct State {
    pub list: Load<CertListing>,
    pub unsupported: bool,
    pub busy: CertBusy,
    pub note: Option<(String, Tone)>,
    pub panel: Option<Panel>,
    pub files: bool,
    pub name: Entity<TextInput>,
    pub cert_text: Entity<TextInput>,
    pub key_text: Entity<TextInput>,
    pub cert_path: Entity<TextInput>,
    pub key_path: Entity<TextInput>,
    pub port: Entity<TextInput>,
    pub ranges: Load<RangesListing>,
    pub list_seq: Sequence,
    pub ranges_seq: Sequence,
    // The node the ranges and the editor text came from.
    pub ranges_node: String,
    pub ranges_unsupported: bool,
    pub ranges_note: Option<(String, Tone)>,
    pub ranges_input: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            list: Load::Idle,
            unsupported: false,
            busy: CertBusy::Idle,
            note: None,
            panel: None,
            files: false,
            name: new_input(cx, "storefront", |i| i),
            cert_text: new_input(cx, "-----BEGIN CERTIFICATE-----", |i| i.mono().multiline(6)),
            key_text: new_input(cx, "-----BEGIN PRIVATE KEY-----", |i| {
                i.mono().masked().multiline(4)
            }),
            cert_path: new_input(cx, "/path/to/fullchain.pem", |i| i.mono()),
            key_path: new_input(cx, "/path/to/privkey.pem", |i| i.mono()),
            port: new_input(cx, "443", |i| i.mono()),
            ranges: Load::Idle,
            list_seq: Sequence::default(),
            ranges_seq: Sequence::default(),
            ranges_node: String::new(),
            ranges_unsupported: false,
            ranges_note: None,
            ranges_input: new_input(cx, "173.245.48.0/20", |i| i.mono().multiline(8)),
        }
    }
}

// Shown when a node answers the certificate routes with 404, 405 or 501.
fn needs_update(title: &str, subtitle: &str, text: &str) -> AnyElement {
    card(
        Some(title),
        Some(subtitle),
        div()
            .flex()
            .items_center()
            .gap(px(10.))
            .child(pill("needs an update", Tone::Warn))
            .child(text_dim(text.to_string()).text_size(px(12.))),
    )
    .into_any_element()
}

// Client-side problems carry their own wording; the "invalid node settings" prefix would mislead.
fn op_error(err: &ClientError) -> String {
    match err {
        ClientError::Config(msg) => msg.clone(),
        other => other.to_string(),
    }
}

impl Console {
    pub fn load_certs(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            self.certs.list = Load::Idle;
            self.certs.ranges = Load::Idle;
            return;
        };
        if !matches!(self.certs.list, Load::Ready(_)) {
            self.certs.list = Load::Loading;
        }
        if !matches!(self.certs.ranges, Load::Ready(_)) {
            self.certs.ranges = Load::Loading;
        }
        let list_handle = h.clone();
        let ranges_node = h.name().to_string();
        let (list_seq, ranges_seq) = (self.certs.list_seq.issue(), self.certs.ranges_seq.issue());
        self.fetch_scoped(
            cx,
            async move { list_handle.certificates().await },
            move |this, res, cx| {
                if !this.certs.list_seq.accept(list_seq) {
                    return;
                }
                this.certs.unsupported = false;
                this.certs.list = match res {
                    Ok(list) => Load::Ready(list),
                    Err(e) if is_unsupported(&e) => {
                        this.certs.unsupported = true;
                        Load::Idle
                    }
                    Err(e) => Load::Failed(e.to_string()),
                };
                cx.notify();
            },
        );
        self.fetch_scoped(
            cx,
            async move { h.cloudflare_ranges().await },
            move |this, res, cx| {
                if !this.certs.ranges_seq.accept(ranges_seq) {
                    return;
                }
                this.certs.ranges_unsupported = false;
                this.certs.ranges = match res {
                    Ok(r) => {
                        let text = ranges_text(&r.ranges);
                        this.certs.ranges_node = ranges_node;
                        this.certs
                            .ranges_input
                            .update(cx, |i, cx| i.set_text(&text, cx));
                        Load::Ready(r)
                    }
                    Err(e) if is_unsupported(&e) => {
                        this.certs.ranges_unsupported = true;
                        Load::Idle
                    }
                    Err(e) => Load::Failed(e.to_string()),
                };
                cx.notify();
            },
        );
    }

    fn cert_note(&mut self, card: Card, text: impl Into<String>, tone: Tone) {
        let note = Some((text.into(), tone));
        match card {
            Card::Certs => self.certs.note = note,
            Card::Ranges => self.certs.ranges_note = note,
        }
    }

    // One operation at a time: a second click while one runs is ignored.
    fn run_cert_op<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        card: Card,
        busy: CertBusy,
        fut: F,
        done: impl FnOnce(&mut Self, T, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        if !self.certs.busy.is_idle() {
            return;
        }
        let noun = busy.noun();
        self.certs.busy = busy;
        self.certs.note = None;
        self.certs.ranges_note = None;
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            // Only one operation runs at a time, so the lock is released wherever the user is now.
            this.certs.busy = CertBusy::Idle;
            match (res, here) {
                (Ok(v), true) => done(this, v, cx),
                (Err(e), true) => this.cert_note(card, op_error(&e), Tone::Bad),
                (Ok(_), false) => this.say(foreign_notice(&noun, origin, "done"), Tone::Ok),
                (Err(e), false) => {
                    this.say(foreign_notice(&noun, origin, &op_error(&e)), Tone::Bad)
                }
            }
            cx.notify();
        });
    }

    // The key is dropped from every input when the panel closes, whether or not the upload worked.
    pub fn close_panel(&mut self, cx: &mut Context<Self>) {
        self.clear_inputs(ClearOn::Cancel, cx);
        self.certs.panel = None;
    }

    fn clear_inputs(&mut self, on: ClearOn, cx: &mut Context<Self>) {
        let (s, c) = (&self.certs, clears_for(on));
        let inputs = [
            (c.name, &s.name),
            (c.cert_text, &s.cert_text),
            (c.key_text, &s.key_text),
            (c.cert_path, &s.cert_path),
            (c.key_path, &s.key_path),
        ];
        for (clear, input) in inputs {
            if clear {
                input.update(cx, |i, cx| i.set_text("", cx));
            }
        }
    }

    fn open_upload(&mut self, cx: &mut Context<Self>) {
        self.close_panel(cx);
        self.certs.files = false;
        self.certs.note = None;
        self.certs.panel = Some(Panel::Upload {
            node: self.active_name().unwrap_or_default(),
        });
    }

    fn open_replace(&mut self, item: &CertItem, cx: &mut Context<Self>) {
        if item.read_only() {
            return;
        }
        self.close_panel(cx);
        self.certs.files = false;
        self.certs.note = None;
        let name = item.name.clone();
        self.certs.name.update(cx, |i, cx| i.set_text(&name, cx));
        self.certs.panel = Some(Panel::Replace {
            node: self.active_name().unwrap_or_default(),
            id: item.id.clone(),
            name,
        });
    }

    fn upload_form(&self, cx: &Context<Self>) -> UploadForm {
        let s = &self.certs;
        let text = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        UploadForm {
            name: text(&s.name),
            files: s.files,
            cert_text: text(&s.cert_text),
            key_text: text(&s.key_text),
            cert_path: text(&s.cert_path),
            key_path: text(&s.key_path),
        }
    }

    // Files are read on the network runtime, never on the UI thread, and the key lives only in this request.
    fn submit_cert(&mut self, cx: &mut Context<Self>) {
        if !self.certs.busy.is_idle() {
            return;
        }
        let (Some(panel), Some(h)) = (self.certs.panel.clone(), self.active_handle()) else {
            return;
        };
        if let Err(msg) = ensure_same_node(panel.node(), self.active_name().as_deref()) {
            self.close_panel(cx);
            self.cert_note(Card::Certs, msg, Tone::Bad);
            return;
        }
        let plan = match self.upload_form(cx).plan() {
            Ok(p) => p,
            Err(msg) => {
                self.cert_note(Card::Certs, msg, Tone::Bad);
                return;
            }
        };
        self.clear_inputs(ClearOn::Submit, cx);
        let (busy, replace_id) = match panel {
            Panel::Upload { .. } => (CertBusy::Upload, None),
            Panel::Replace { id, name, .. } => (CertBusy::Replace(name), Some(id)),
        };
        let replaced = replace_id.is_some();
        let fut = async move {
            let req = plan.load().map_err(ClientError::Config)?;
            match replace_id {
                Some(cert_id) => h.certificate_replace(&cert_id, &req).await,
                None => h.certificate_upload(&req).await,
            }
        };
        self.run_cert_op(cx, Card::Certs, busy, fut, move |this, out, cx| {
            this.clear_inputs(ClearOn::Success, cx);
            this.certs.panel = None;
            let done = uploaded_text(&out.cert.name, replaced);
            match out.warning {
                Some(warning) => {
                    this.cert_note(Card::Certs, format!("{done} {warning}"), Tone::Warn)
                }
                None => this.cert_note(Card::Certs, done, Tone::Ok),
            }
            this.load_certs(cx);
        });
    }

    fn confirm_delete_cert(&mut self, item: CertItem) {
        if item.read_only() {
            return;
        }
        let asked_on = self.active_name().unwrap_or_default();
        self.ask(Confirm {
            title: "Delete certificate".into(),
            message: delete_message(&item.name, &item.covers),
            label: "Delete".into(),
            danger: true,
            action: Box::new(move |this, cx| {
                let Some(h) = this.active_handle() else {
                    return;
                };
                if let Err(msg) = ensure_same_node(&asked_on, this.active_name().as_deref()) {
                    this.cert_note(Card::Certs, msg, Tone::Bad);
                    return;
                }
                let (cert_id, label) = (item.id.clone(), item.name.clone());
                this.run_cert_op(
                    cx,
                    Card::Certs,
                    CertBusy::Delete(item.name.clone()),
                    async move { h.certificate_delete(&cert_id).await },
                    move |this, _, cx| {
                        this.cert_note(Card::Certs, format!("Deleted {label}."), Tone::Ok);
                        this.load_certs(cx);
                    },
                );
            }),
        });
    }

    // Port and ranges live in the node settings, so both go through the loaded settings and the connector's own checks.
    fn save_node_settings(
        &mut self,
        cx: &mut Context<Self>,
        card: Card,
        busy: CertBusy,
        done_text: &str,
        change: impl FnOnce(&mut EdgeSettings),
    ) {
        let (Some(h), Some(data)) = (self.active_handle(), self.settings.data.ready()) else {
            return;
        };
        let active = self.active_name();
        let mut owners = vec![self.settings.data_node.as_str()];
        if card == Card::Ranges {
            owners.push(self.certs.ranges_node.as_str());
        }
        if let Some(msg) = owners
            .into_iter()
            .find_map(|owner| ensure_same_node(owner, active.as_deref()).err())
        {
            self.cert_note(card, msg, Tone::Bad);
            return;
        }
        let mut next = data.settings.clone();
        change(&mut next);
        if let Err(e) = cite_edge::validate::validate_settings(&next) {
            self.cert_note(card, e.to_string(), Tone::Bad);
            return;
        }
        let text = done_text.to_string();
        self.run_cert_op(
            cx,
            card,
            busy,
            async move { h.put_settings(&next).await },
            move |this, _, cx| {
                this.cert_note(card, text, Tone::Ok);
                this.load_settings(cx);
            },
        );
    }

    fn save_https_port(&mut self, cx: &mut Context<Self>) {
        let port = match parse_port(self.certs.port.read(cx).text()) {
            Ok(p) => p,
            Err(msg) => {
                self.cert_note(Card::Certs, msg, Tone::Bad);
                return;
            }
        };
        self.save_node_settings(
            cx,
            Card::Certs,
            CertBusy::Port,
            "HTTPS port saved.",
            move |s| {
                s.https_port = Some(port);
            },
        );
    }

    fn save_ranges(&mut self, cx: &mut Context<Self>) {
        let ranges = match parse_range_list(self.certs.ranges_input.read(cx).text()) {
            Ok(r) => r,
            Err(msg) => {
                self.cert_note(Card::Ranges, msg, Tone::Bad);
                return;
            }
        };
        self.save_node_settings(
            cx,
            Card::Ranges,
            CertBusy::Ranges,
            "Cloudflare ranges saved.",
            move |s| s.cloudflare_ranges = ranges,
        );
    }

    fn use_builtin_ranges(&mut self, cx: &mut Context<Self>) {
        self.save_node_settings(
            cx,
            Card::Ranges,
            CertBusy::Ranges,
            "Using the built-in Cloudflare list.",
            |s| s.cloudflare_ranges.clear(),
        );
    }

    pub fn certs_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.certs;
        if s.unsupported {
            return needs_update(
                "Certificates",
                "TLS certificates the node serves over HTTPS",
                "This node predates certificate management. Update it to use it.",
            );
        }
        let list = match &s.list {
            Load::Idle | Load::Loading => return skeleton(120.).into_any_element(),
            Load::Failed(msg) => {
                let msg = msg.clone();
                return self.error_block(cx, &msg);
            }
            Load::Ready(list) => list,
        };
        let idle = s.busy.is_idle();
        let upload = if idle && list.dir_ready {
            btn(id("cert", "upload"), "Upload certificate", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.open_upload(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Upload certificate").into_any_element()
        };
        let noun = if list.items.len() == 1 {
            "certificate"
        } else {
            "certificates"
        };
        let mut body = div().flex().flex_col().gap(px(12.)).child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(upload)
                .child(text_dim(format!("{} {noun}", list.items.len())).text_size(px(12.))),
        );
        if !list.dir_ready {
            body = body.child(notice(
                "The node cannot store certificates yet because its certificate directory is not ready. Uploads are off until it is.",
                Tone::Warn,
            ));
        }
        body = body.child(self.https_row(list, cx));
        if let Some(text) = uncovered_note(&list.uncovered_hosts) {
            body = body.child(notice(&text, Tone::Warn));
        }
        if s.panel.is_some() {
            body = body.child(self.cert_panel(cx));
        }
        let working = matches!(
            s.busy,
            CertBusy::Upload | CertBusy::Replace(_) | CertBusy::Delete(_) | CertBusy::Port
        );
        if let Some(label) = s.busy.label().filter(|_| working) {
            body = body.child(notice(&label, Tone::Info));
        }
        if let Some((text, tone)) = &s.note {
            body = body.child(notice(text, *tone));
        }
        body = body.child(self.cert_table(list, cx));
        let subtitle = format!(
            "TLS certificates {} serves over HTTPS",
            self.active_name().unwrap_or_default()
        );
        card(Some("Certificates"), Some(subtitle.as_str()), body).into_any_element()
    }

    // Without an HTTPS port the node stores certificates but serves nothing over TLS.
    fn https_row(&self, list: &CertListing, cx: &mut Context<Self>) -> AnyElement {
        if let Some(port) = list.https_port {
            return text_dim(format!("HTTPS is served on port {port}."))
                .text_size(px(12.))
                .into_any_element();
        }
        let save = if self.certs.busy.is_idle() {
            btn(id("cert", "port"), "Enable HTTPS", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.save_https_port(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Enable HTTPS").into_any_element()
        };
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(notice(
                "HTTPS is off: the node has no HTTPS port, so certificates are stored but not served. Set a port to turn it on.",
                Tone::Warn,
            ))
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(10.))
                    .child(div().w(px(160.)).child(field(
                        "HTTPS port",
                        Some("Usually 443"),
                        self.certs.port.clone(),
                    )))
                    .child(save),
            )
            .into_any_element()
    }

    fn cert_table(&self, list: &CertListing, cx: &mut Context<Self>) -> AnyElement {
        let idle = self.certs.busy.is_idle();
        let mut rows: Vec<Vec<AnyElement>> = Vec::new();
        for item in &list.items {
            let mut name_cell = div()
                .flex()
                .flex_col()
                .min_w_0()
                .child(clip(item.name.clone()))
                .child(
                    clip(item.subject.clone())
                        .font_family(MONO)
                        .text_size(px(11.))
                        .text_color(c(DIM)),
                )
                .child(
                    clip(format!(
                        "{}, added {}",
                        sans_text(&item.sans),
                        date_text(&item.created_at)
                    ))
                    .text_size(px(11.))
                    .text_color(c(DIM)),
                )
                .child(
                    clip(coverage_text(&item.covers))
                        .text_size(px(11.))
                        .text_color(c(DIM)),
                );
            if item.read_only() {
                name_cell = name_cell.child(
                    clip(MANUAL_NOTE)
                        .text_size(px(11.))
                        .text_color(c(Tone::Info.color())),
                );
            }
            if let Some(warning) = item.warning.as_deref().filter(|w| !w.trim().is_empty()) {
                name_cell = name_cell.child(
                    clip(warning.to_string())
                        .text_size(px(11.))
                        .text_color(c(Tone::Warn.color())),
                );
            }
            let tone = classify_expiry(item.days_left).tone();
            let valid_cell = div()
                .flex()
                .flex_col()
                .gap(px(3.))
                .child(
                    text_dim(validity_text(&item.not_before, &item.not_after)).text_size(px(11.)),
                )
                .child(div().flex().child(pill(&days_text(item.days_left), tone)));
            let actions = if item.read_only() {
                text_dim("Read-only").text_size(px(12.)).into_any_element()
            } else if idle {
                self.cert_actions(item, cx)
            } else {
                div()
                    .flex()
                    .gap(px(6.))
                    .child(btn_off("Replace"))
                    .child(btn_off("Delete"))
                    .into_any_element()
            };
            rows.push(vec![
                name_cell.into_any_element(),
                clip(item.issuer.clone()).into_any_element(),
                valid_cell.into_any_element(),
                text_dim(item.key_type.clone()).into_any_element(),
                mono(short_fingerprint(&item.fingerprint))
                    .text_color(c(DIM))
                    .into_any_element(),
                actions,
            ]);
        }
        let cols = [
            Col::flex("Certificate"),
            Col::fixed("Issuer", 130.),
            Col::fixed("Valid", 190.),
            Col::fixed("Key", 90.),
            Col::fixed("SHA-256", 110.),
            Col::fixed("", 150.),
        ];
        table(
            &cols,
            rows,
            Some(text_dim("No certificates yet.").p(px(12.))),
        )
        .into_any_element()
    }

    fn cert_actions(&self, item: &CertItem, cx: &mut Context<Self>) -> AnyElement {
        let replace = item.clone();
        let delete = item.clone();
        div()
            .flex()
            .gap(px(6.))
            .child(
                btn(id("cert-rp", &item.id), "Replace", BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.open_replace(&replace, cx);
                        cx.notify();
                    },
                )),
            )
            .child(
                btn(id("cert-rm", &item.id), "Delete", BtnKind::Danger).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.confirm_delete_cert(delete.clone());
                        cx.notify();
                    },
                )),
            )
            .into_any_element()
    }

    // The same panel serves upload and replace; only the title, the prefilled name and the request differ.
    fn cert_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.certs;
        let (title, submit) = match &s.panel {
            Some(Panel::Replace { name, .. }) => (format!("Replace {name}"), "Replace"),
            _ => ("Upload a certificate".to_string(), "Upload"),
        };
        let mode = seg_row(vec![
            seg_item(id("cert-mode", "paste"), "Paste text", !s.files)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.certs.files = false;
                    this.clear_inputs(ClearOn::ToPaste, cx);
                    cx.notify();
                }))
                .into_any_element(),
            seg_item(id("cert-mode", "files"), "Read from files", s.files)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.certs.files = true;
                    this.clear_inputs(ClearOn::ToFiles, cx);
                    cx.notify();
                }))
                .into_any_element(),
        ]);
        let mut inputs = div().flex().flex_col().gap(px(12.));
        if s.files {
            inputs = inputs
                .child(field(
                    "Certificate file",
                    Some("Full path to a PEM file with the certificate and its chain. Regular files; the certificate and key together up to 100 KiB."),
                    s.cert_path.clone(),
                ))
                .child(field(
                    "Private key file",
                    Some("Full path to the unencrypted PEM key. It is read once and sent to the node."),
                    s.key_path.clone(),
                ));
        } else {
            inputs = inputs
                .child(field(
                    "Certificate chain",
                    Some("PEM text: the certificate first, then any intermediates."),
                    s.cert_text.clone(),
                ))
                .child(field(
                    "Private key",
                    Some("Unencrypted PEM text. It is hidden here, sent once and cleared afterwards."),
                    s.key_text.clone(),
                ));
        }
        let submit_btn = if s.busy.is_idle() {
            btn(id("cert", "submit"), submit, BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.submit_cert(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off(submit).into_any_element()
        };
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .p(px(12.))
            .rounded(px(ROW_RADIUS))
            .border_1()
            .border_color(c(BORDER))
            .child(strong(title))
            .child(div().w(px(320.)).child(field("Name", None, s.name.clone())))
            .child(div().flex().child(mode))
            .child(inputs)
            .child(div().flex().gap(px(8.)).child(submit_btn).child(
                btn(id("cert", "cancel"), "Cancel", BtnKind::Plain).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.close_panel(cx);
                        cx.notify();
                    },
                )),
            ))
            .into_any_element()
    }

    pub fn ranges_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let s = &self.certs;
        if s.ranges_unsupported {
            return needs_update(
                "Cloudflare ranges",
                "Addresses trusted as Cloudflare",
                "This node predates the Cloudflare options. Update it to use them.",
            );
        }
        let listing = match &s.ranges {
            Load::Idle | Load::Loading => return skeleton(160.).into_any_element(),
            Load::Failed(msg) => {
                let msg = msg.clone();
                return self.error_block(cx, &msg);
            }
            Load::Ready(listing) => listing,
        };
        let idle = s.busy.is_idle();
        let save = if idle {
            btn(id("cf", "save"), "Save ranges", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.save_ranges(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Save ranges").into_any_element()
        };
        let builtin = if idle && is_custom_source(&listing.source) {
            btn(id("cf", "builtin"), "Use built-in list", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.use_builtin_ranges(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Use built-in list").into_any_element()
        };
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(text_dim(ranges_summary(listing)).text_size(px(12.)))
            .child(field(
                "Trusted ranges",
                Some("One CIDR range per line. Saving a list replaces the built-in one for this node."),
                s.ranges_input.clone(),
            ))
            .child(div().flex().gap(px(8.)).child(save).child(builtin));
        if matches!(s.busy, CertBusy::Ranges)
            && let Some(label) = s.busy.label()
        {
            body = body.child(notice(&label, Tone::Info));
        }
        if let Some((text, tone)) = &s.ranges_note {
            body = body.child(notice(text, *tone));
        }
        card(
            Some("Cloudflare ranges"),
            Some("Sites set to only accept traffic from Cloudflare allow just these addresses"),
            body,
        )
        .into_any_element()
    }
}

// The controls carry the click handlers of whichever page builds them; the text around them is shared.
pub struct AccessControls {
    pub cloudflare_box: AnyElement,
    pub zone_box: AnyElement,
    pub ssl_mode: Div,
    pub bots: Div,
}

// Shared by the create form and the site page so both explain the options the same way.
pub fn access_body(controls: AccessControls, draft: AccessDraft) -> Div {
    let help = if draft.flexible {
        FLEXIBLE_HELP
    } else {
        FULL_HELP
    };
    let mut body = div()
        .flex()
        .flex_col()
        .gap(px(12.))
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(controls.cloudflare_box)
                .child(div().child("Only accept traffic from Cloudflare")),
        )
        .child(
            text_dim("Requests from other addresses are refused, using the ranges in Settings.")
                .text_size(px(12.)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(controls.zone_box)
                .child(div().child("Only my Cloudflare zone"))
                .when(!draft.cloudflare_only, |d| d.opacity(0.5)),
        )
        .child(text_dim(zone_lock_help(draft.cloudflare_only)).text_size(px(12.)))
        .child(field(
            "SSL mode",
            Some(help),
            div().flex().child(controls.ssl_mode),
        ))
        .child(field(
            "Bots",
            Some(bots_help(draft.bots)),
            div().flex().child(controls.bots),
        ))
        .child(text_dim(BOTS_NOTE).text_size(px(11.)));
    if let Some(warning) = bots_warning(draft.bots) {
        body = body.child(notice(warning, Tone::Warn));
    }
    if let Some(warning) = flexible_warning(draft.cloudflare_only, draft.flexible) {
        body = body.child(notice(warning, Tone::Warn));
    }
    body
}

// Builds the four Access controls for a page; get says where that page keeps its draft.
pub fn access_controls(
    cx: &mut Context<Console>,
    prefix: &'static str,
    draft: AccessDraft,
    get: fn(&mut Console) -> &mut AccessDraft,
) -> AccessControls {
    let cloudflare_box = checkbox(id(prefix, "cf"), draft.cloudflare_only)
        .on_click(cx.listener(move |this, _, _, cx| {
            let d = get(this);
            d.set_cloudflare_only(!d.cloudflare_only);
            cx.notify();
        }))
        .into_any_element();
    let mut zone = zone_box(id(prefix, "zone"), draft);
    if draft.cloudflare_only {
        zone = zone.on_click(cx.listener(move |this, _, _, cx| {
            let d = get(this);
            d.set_zone_lock(!d.zone_lock);
            cx.notify();
        }));
    }
    let ssl_key = format!("{prefix}-ssl");
    let mut ssl = Vec::new();
    for (flexible, label) in [(false, "Full"), (true, "Flexible")] {
        ssl.push(
            seg_item(id(&ssl_key, label), label, draft.flexible == flexible)
                .on_click(cx.listener(move |this, _, _, cx| {
                    get(this).flexible = flexible;
                    cx.notify();
                }))
                .into_any_element(),
        );
    }
    let bots_key = format!("{prefix}-bots");
    let mut bots = Vec::new();
    for policy in [BotPolicy::Allow, BotPolicy::BlockBad, BotPolicy::BlockAll] {
        bots.push(
            seg_item(
                id(&bots_key, bots_label(policy)),
                bots_label(policy),
                draft.bots == policy,
            )
            .on_click(cx.listener(move |this, _, _, cx| {
                get(this).bots = policy;
                cx.notify();
            }))
            .into_any_element(),
        );
    }
    AccessControls {
        cloudflare_box,
        zone_box: zone.into_any_element(),
        ssl_mode: seg_row(ssl),
        bots: seg_row(bots),
    }
}

// A tick box that only reacts while Cloudflare only is on; otherwise it is drawn as unavailable.
pub fn zone_box(key: gpui::ElementId, draft: AccessDraft) -> gpui::Stateful<Div> {
    let boxed = checkbox(key, draft.zone_lock && draft.cloudflare_only);
    if draft.cloudflare_only {
        boxed
    } else {
        boxed.cursor_default()
    }
}
