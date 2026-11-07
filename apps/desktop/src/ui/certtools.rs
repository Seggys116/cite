use cite_client::ClientError;
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::spawn_io;
use crate::api_issue::IssueReply;
use crate::app::{Console, Load, View, new_input};
use crate::bots::is_unsupported;
use crate::certissue::{
    AcmeListing, DEFAULT_ORIGIN_DAYS, IssueForm, MAX_HOSTS, Mode, ORIGIN_VALIDITY_DAYS, POLL_EVERY,
    PollStep, Stage, add_hosts, candidates, check_hosts, gives_up_after_errors, issued_text,
    managed_text, normalize_host, origin_days_label, poll_step, step_note, toggle_host,
};
use crate::certs::ensure_same_node;
use crate::scope::{Sequence, foreign_notice};
use crate::theme::{BORDER, ROW_RADIUS, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, checkbox, field, id, mono, notice, pill, seg_item, seg_row,
    strong, table, text_dim,
};

const LOST_CONTACT: &str = "Lost contact with the node while waiting. The request may still finish; open Settings again to check.";

#[derive(Clone)]
struct Inputs {
    host: Entity<TextInput>,
    name: Entity<TextInput>,
    days: Entity<TextInput>,
    email: Entity<TextInput>,
    token: Entity<TextInput>,
}

impl Inputs {
    fn new(cx: &mut Context<Console>) -> Self {
        Self {
            host: new_input(cx, "shop.example.com", |i| i.mono()),
            name: new_input(cx, "storefront", |i| i),
            days: new_input(cx, "365", |i| i.mono()),
            email: new_input(cx, "you@example.com", |i| i),
            token: new_input(cx, "Cloudflare API token", |i| i.mono().masked()),
        }
    }

    fn all(&self) -> [&Entity<TextInput>; 5] {
        [&self.host, &self.name, &self.days, &self.email, &self.token]
    }
}

// The node the panel was opened for; a submit for any other node is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Panel {
    node: String,
    mode: Mode,
    stage: Stage,
    hosts: Vec<String>,
    origin_days: u32,
    remember_token: bool,
    agree_tos: bool,
    staging: bool,
}

#[derive(Clone, Debug)]
struct Job {
    node: String,
    id: String,
    hosts: Vec<String>,
    polls: u32,
    errors: u32,
}

#[derive(Default)]
pub(crate) struct CertToolsState {
    inputs: Option<Inputs>,
    panel: Option<Panel>,
    busy: bool,
    note: Option<(String, Tone)>,
    listing: Option<AcmeListing>,
    list_error: Option<String>,
    unsupported: bool,
    requested: bool,
    list_seq: Sequence,
    job: Option<Job>,
    poll_epoch: u64,
}

fn op_error(err: &ClientError) -> String {
    match err {
        ClientError::Config(msg) => msg.clone(),
        other => other.to_string(),
    }
}

fn managed_tone(status: &str, failed: bool) -> Tone {
    if failed {
        return Tone::Bad;
    }
    match status {
        "issued" | "active" | "valid" => Tone::Ok,
        "failed" | "error" => Tone::Bad,
        _ => Tone::Info,
    }
}

impl Console {
    fn ct_inputs(&mut self, cx: &mut Context<Self>) -> Inputs {
        if let Some(inputs) = &self.certtools.inputs {
            return inputs.clone();
        }
        let inputs = Inputs::new(cx);
        self.certtools.inputs = Some(inputs.clone());
        inputs
    }

    fn clear_ct_inputs(&mut self, cx: &mut Context<Self>) {
        let Some(inputs) = self.certtools.inputs.clone() else {
            return;
        };
        for input in inputs.all() {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    fn ct_note(&mut self, text: impl Into<String>, tone: Tone) {
        self.certtools.note = Some((text.into(), tone));
    }

    // Closes the panel and drops everything typed into it, token included.
    pub(crate) fn certtools_close(&mut self, cx: &mut Context<Self>) {
        self.clear_ct_inputs(cx);
        self.certtools.panel = None;
    }

    // Everything loaded for one node is dropped, and any job still being followed stops being polled.
    pub(crate) fn certtools_reset(&mut self, cx: &mut Context<Self>) {
        self.certtools_close(cx);
        let s = &mut self.certtools;
        s.poll_epoch += 1;
        s.job = None;
        s.note = None;
        s.listing = None;
        s.list_error = None;
        s.unsupported = false;
        s.requested = false;
    }

    fn load_acme(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        self.certtools.requested = true;
        let node = h.name().to_string();
        let seq = self.certtools.list_seq.issue();
        let hint = self.certtools.job.as_ref().map(|j| j.id.clone());
        self.fetch(
            cx,
            async move { h.tools_acme_listing(hint.as_deref()).await },
            move |this, res, cx| {
                if this.active_name().as_deref() != Some(node.as_str())
                    || !this.certtools.list_seq.accept(seq)
                {
                    return;
                }
                this.certtools.unsupported = false;
                this.certtools.list_error = None;
                match res {
                    Ok(listing) => {
                        this.certtools.listing = Some(listing);
                        this.adopt_pending(&node, cx);
                    }
                    Err(e) if is_unsupported(&e) => {
                        this.certtools.unsupported = true;
                        this.certtools.listing = None;
                    }
                    Err(e) => this.certtools.list_error = Some(op_error(&e)),
                }
                cx.notify();
            },
        );
    }

    // A request started earlier, or from another window, is picked up so its outcome still shows.
    fn adopt_pending(&mut self, node: &str, cx: &mut Context<Self>) {
        if self.certtools.job.is_some() {
            return;
        }
        let Some(pending) = self
            .certtools
            .listing
            .as_ref()
            .and_then(|l| l.pending().cloned())
        else {
            return;
        };
        self.certtools.job = Some(Job {
            node: node.to_string(),
            id: pending.job_id,
            hosts: pending.hosts,
            polls: 0,
            errors: 0,
        });
        self.start_polling(cx);
    }

    fn start_polling(&mut self, cx: &mut Context<Self>) {
        if self.certtools.job.is_none() {
            return;
        }
        self.certtools.poll_epoch += 1;
        let epoch = self.certtools.poll_epoch;
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(POLL_EVERY).await;
                let target = this.update(cx, |this, _| this.poll_target(epoch));
                let Ok(Some((handle, job_id))) = target else {
                    break;
                };
                let res =
                    spawn_io(async move { handle.tools_acme_listing(Some(&job_id)).await }).await;
                let keep = this
                    .update(cx, |this, cx| this.poll_applied(epoch, res, cx))
                    .unwrap_or(false);
                if !keep {
                    break;
                }
            }
        })
        .detach();
    }

    fn poll_target(&self, epoch: u64) -> Option<(crate::api::NodeHandle, String)> {
        if epoch != self.certtools.poll_epoch {
            return None;
        }
        let job = self.certtools.job.as_ref()?;
        Some((self.handle_named(&job.node)?, job.id.clone()))
    }

    // Returns whether the polling loop should go on.
    fn poll_applied(
        &mut self,
        epoch: u64,
        res: Result<AcmeListing, ClientError>,
        cx: &mut Context<Self>,
    ) -> bool {
        if epoch != self.certtools.poll_epoch {
            return false;
        }
        let Some(job) = self.certtools.job.as_mut() else {
            return false;
        };
        let listing = match res {
            Ok(l) => l,
            Err(_) => {
                job.errors += 1;
                if gives_up_after_errors(job.errors) {
                    self.finish_job(LOST_CONTACT.to_string(), Tone::Warn, false, cx);
                    return false;
                }
                return true;
            }
        };
        job.errors = 0;
        job.polls += 1;
        let step = poll_step(&job.id, &listing, job.polls);
        let hosts = job.hosts.clone();
        self.certtools.listing = Some(listing);
        match step_note(&step, &hosts) {
            None => {
                cx.notify();
                true
            }
            Some((text, tone)) => {
                self.finish_job(text, tone, step == PollStep::Issued, cx);
                false
            }
        }
    }

    fn finish_job(&mut self, text: String, tone: Tone, issued: bool, cx: &mut Context<Self>) {
        self.certtools.job = None;
        if self.view != View::Settings {
            self.say(text.clone(), tone);
        }
        self.ct_note(text, tone);
        if issued {
            self.load_certs(cx);
        }
        cx.notify();
    }

    fn ct_open(&mut self, mode: Mode, cx: &mut Context<Self>) {
        if self.certtools.busy {
            return;
        }
        self.certtools_close(cx);
        let hosts: Vec<String> = self
            .certs
            .list
            .ready()
            .map(|l| l.uncovered_hosts.clone())
            .unwrap_or_default()
            .iter()
            .filter_map(|h| normalize_host(h).ok())
            .take(MAX_HOSTS)
            .collect();
        self.certtools.note = None;
        self.certtools.panel = Some(Panel {
            node: self.active_name().unwrap_or_default(),
            mode,
            stage: Stage::Hosts,
            hosts,
            origin_days: DEFAULT_ORIGIN_DAYS,
            remember_token: false,
            agree_tos: false,
            staging: false,
        });
    }

    fn ct_add_host(&mut self, cx: &mut Context<Self>) {
        let inputs = self.ct_inputs(cx);
        let text = inputs.host.read(cx).text().to_string();
        let Some(panel) = self.certtools.panel.as_mut() else {
            return;
        };
        match add_hosts(&mut panel.hosts, &text) {
            Ok(_) => {
                self.certtools.note = None;
                inputs.host.update(cx, |i, cx| i.set_text("", cx));
            }
            Err(msg) => self.ct_note(msg, Tone::Bad),
        }
    }

    fn ct_next(&mut self) {
        let Some(panel) = self.certtools.panel.as_mut() else {
            return;
        };
        match check_hosts(&panel.hosts) {
            Ok(()) => {
                panel.stage = Stage::Details;
                self.certtools.note = None;
            }
            Err(msg) => self.ct_note(msg, Tone::Bad),
        }
    }

    // The token leaves the input the moment the request is built, whether or not the node accepts it.
    fn submit_ct(&mut self, cx: &mut Context<Self>) {
        if self.certtools.busy {
            return;
        }
        let (Some(panel), Some(h)) = (self.certtools.panel.clone(), self.active_handle()) else {
            return;
        };
        if let Err(msg) = ensure_same_node(&panel.node, self.active_name().as_deref()) {
            self.certtools_close(cx);
            self.ct_note(msg, Tone::Bad);
            return;
        }
        let inputs = self.ct_inputs(cx);
        let form = IssueForm {
            mode: panel.mode,
            hosts: panel.hosts.clone(),
            name: inputs.name.read(cx).text().to_string(),
            days: inputs.days.read(cx).text().to_string(),
            email: inputs.email.read(cx).text().to_string(),
            token: inputs.token.read(cx).text().to_string(),
            origin_days: panel.origin_days,
            remember_token: panel.remember_token,
            agree_tos: panel.agree_tos,
            staging: panel.staging,
        };
        let request = match form.request() {
            Ok(r) => r,
            Err(msg) => {
                self.ct_note(msg, Tone::Bad);
                return;
            }
        };
        drop(form);
        inputs.token.update(cx, |i, cx| i.set_text("", cx));
        let (mode, hosts) = (panel.mode, panel.hosts);
        self.certtools.busy = true;
        self.certtools.note = None;
        self.fetch_origin(
            cx,
            async move { h.tools_issue(request).await },
            move |this, res, here, origin, cx| {
                this.certtools.busy = false;
                match (res, here) {
                    (Ok(reply), true) => this.issue_done(mode, reply, hosts, cx),
                    (Err(e), true) => this.ct_note(op_error(&e), Tone::Bad),
                    (Ok(_), false) => {
                        this.certtools.requested = false;
                        this.say(foreign_notice(mode.noun(), origin, "done"), Tone::Ok);
                    }
                    (Err(e), false) => this.say(
                        foreign_notice(mode.noun(), origin, &op_error(&e)),
                        Tone::Bad,
                    ),
                }
                cx.notify();
            },
        );
    }

    fn issue_done(
        &mut self,
        mode: Mode,
        reply: IssueReply,
        hosts: Vec<String>,
        cx: &mut Context<Self>,
    ) {
        self.certtools_close(cx);
        match reply {
            IssueReply::Saved(outcome) => {
                let done = issued_text(mode, &outcome);
                match outcome.warning {
                    Some(warning) => self.ct_note(format!("{done} {warning}"), Tone::Warn),
                    None => self.ct_note(done, Tone::Ok),
                }
                self.load_certs(cx);
            }
            IssueReply::Job(job_id) => {
                self.certtools.job = Some(Job {
                    node: self.active_name().unwrap_or_default(),
                    id: job_id,
                    hosts,
                    polls: 0,
                    errors: 0,
                });
                self.ct_note(
                    "Request sent. Let's Encrypt usually needs a minute or two to check the domain.",
                    Tone::Info,
                );
                self.start_polling(cx);
            }
        }
    }

    fn ct_candidates(&self, selected: &[String]) -> Vec<String> {
        let uncovered = self
            .certs
            .list
            .ready()
            .map(|l| l.uncovered_hosts.clone())
            .unwrap_or_default();
        let node = self.active_name().unwrap_or_default();
        let mut site_hosts: Vec<String> = Vec::new();
        if let Load::Ready(data) = &self.sites.data {
            for row in data.rows.iter().filter(|r| r.node == node) {
                site_hosts.extend(row.site.hosts.iter().cloned());
            }
        }
        candidates(&uncovered, &site_hosts, selected)
    }

    pub(crate) fn certtools_card(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let inputs = self.ct_inputs(cx);
        if !self.certtools.requested && self.active_handle().is_some() {
            self.load_acme(cx);
        }
        let subtitle = "Create, request or issue a certificate for the hosts a node serves";
        if self.certtools.unsupported {
            return card(
                Some("Get a certificate"),
                Some(subtitle),
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(pill("needs an update", Tone::Warn))
                    .child(
                        text_dim("This node predates certificate issuing. Update it to use it.")
                            .text_size(px(12.)),
                    ),
            )
            .into_any_element();
        }
        let s = &self.certtools;
        let mut starters = div().flex().flex_wrap().gap(px(8.));
        for mode in Mode::ALL {
            let open = s.panel.as_ref().is_some_and(|p| p.mode == mode);
            let kind = if open {
                BtnKind::Primary
            } else {
                BtnKind::Plain
            };
            starters = starters.child(if s.busy {
                btn_off(mode.title()).into_any_element()
            } else {
                btn(id("ct-mode", mode.title()), mode.title(), kind)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.ct_open(mode, cx);
                        cx.notify();
                    }))
                    .into_any_element()
            });
        }
        let mut body = div().flex().flex_col().gap(px(12.)).child(starters);
        if s.panel.is_some() {
            body = body.child(self.ct_panel(&inputs, cx));
        }
        if s.busy {
            let label = s
                .panel
                .as_ref()
                .map(|p| p.mode.busy_label())
                .unwrap_or("Working...");
            body = body.child(notice(label, Tone::Info));
        }
        let here = self.active_name().unwrap_or_default();
        if let Some(job) = s.job.as_ref().filter(|j| j.node == here) {
            let text = format!(
                "Waiting for Let's Encrypt to issue the certificate for {} ({} checks so far)...",
                job.hosts.join(", "),
                job.polls
            );
            body = body.child(notice(&text, Tone::Info));
        }
        if let Some((text, tone)) = &s.note {
            body = body.child(notice(text, *tone));
        }
        if let Some(err) = &s.list_error {
            body = body.child(notice(
                &format!("Could not load the Let's Encrypt list: {err}"),
                Tone::Warn,
            ));
        }
        if let Some(listing) = &s.listing {
            body = body.child(self.acme_table(listing));
        }
        card(Some("Get a certificate"), Some(subtitle), body).into_any_element()
    }

    fn acme_table(&self, listing: &AcmeListing) -> AnyElement {
        let mut rows: Vec<Vec<AnyElement>> = Vec::new();
        for job in &listing.jobs {
            let detail = match &job.error {
                Some(err) => format!("Request {}: {err}", job.job_id),
                None => format!("Request started {}", job.started_at),
            };
            rows.push(vec![
                mono(job.hosts.join(", ")).into_any_element(),
                div()
                    .flex()
                    .child(pill(job.status.label(), job.status.tone()))
                    .into_any_element(),
                text_dim(detail).text_size(px(12.)).into_any_element(),
            ]);
        }
        for m in &listing.managed {
            let detail = match &m.error {
                Some(err) => err.clone(),
                None => managed_text(m),
            };
            rows.push(vec![
                mono(m.hosts.join(", ")).into_any_element(),
                div()
                    .flex()
                    .child(pill(&m.status, managed_tone(&m.status, m.error.is_some())))
                    .into_any_element(),
                text_dim(detail).text_size(px(12.)).into_any_element(),
            ]);
        }
        let cols = [
            Col::flex("Let's Encrypt requests and managed certificates"),
            Col::fixed("Status", 120.),
            Col::flex("Details"),
        ];
        table(
            &cols,
            rows,
            Some(text_dim("No Let's Encrypt certificates yet.").p(px(12.))),
        )
        .into_any_element()
    }

    fn ct_flag(
        &self,
        cx: &mut Context<Self>,
        key: &'static str,
        on: bool,
        label: &str,
        flip: fn(&mut Panel),
    ) -> AnyElement {
        div()
            .flex()
            .items_center()
            .gap(px(10.))
            .child(
                checkbox(id("ct-flag", key), on).on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(panel) = this.certtools.panel.as_mut() {
                        flip(panel);
                    }
                    cx.notify();
                })),
            )
            .child(div().child(label.to_string()))
            .into_any_element()
    }

    fn ct_panel(&self, inputs: &Inputs, cx: &mut Context<Self>) -> AnyElement {
        let Some(panel) = self.certtools.panel.as_ref() else {
            return div().into_any_element();
        };
        let mode = panel.mode;
        let mut shell = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .p(px(12.))
            .rounded(px(ROW_RADIUS))
            .border_1()
            .border_color(c(BORDER))
            .child(strong(mode.title()))
            .child(text_dim(mode.blurb()).text_size(px(12.)))
            .child(text_dim(panel.stage.label()).text_size(px(11.)));
        shell = match panel.stage {
            Stage::Hosts => shell.child(self.ct_hosts_step(panel, inputs, cx)),
            Stage::Details => shell.child(self.ct_details_step(panel, inputs, cx)),
        };
        shell.into_any_element()
    }

    fn ct_cancel(&self, cx: &mut Context<Self>) -> AnyElement {
        btn(id("ct", "cancel"), "Cancel", BtnKind::Plain)
            .on_click(cx.listener(|this, _, _, cx| {
                this.certtools_close(cx);
                this.certtools.note = None;
                cx.notify();
            }))
            .into_any_element()
    }

    fn ct_hosts_step(&self, panel: &Panel, inputs: &Inputs, cx: &mut Context<Self>) -> AnyElement {
        let mut list = div().flex().flex_col().gap(px(8.));
        let shown = self.ct_candidates(&panel.hosts);
        if shown.is_empty() {
            list = list.child(
                text_dim("No hosts yet. Type one below, like shop.example.com.").text_size(px(12.)),
            );
        }
        for host in shown {
            let on = panel.hosts.contains(&host);
            let pick = host.clone();
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(checkbox(id("ct-host", &host), on).on_click(cx.listener(
                        move |this, _, _, cx| {
                            if let Some(p) = this.certtools.panel.as_mut() {
                                toggle_host(&mut p.hosts, &pick);
                            }
                            cx.notify();
                        },
                    )))
                    .child(mono(host)),
            );
        }
        let next = if panel.hosts.is_empty() {
            btn_off("Next").into_any_element()
        } else {
            btn(id("ct", "next"), "Next", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.ct_next();
                    cx.notify();
                }))
                .into_any_element()
        };
        let count = format!(
            "{} of up to {MAX_HOSTS} hosts selected. Hosts without a certificate are ticked for you.",
            panel.hosts.len()
        );
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(list)
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(10.))
                    .child(div().flex_1().min_w_0().max_w(px(420.)).child(field(
                        "Add a host",
                        Some("A name like shop.example.com, or *.example.com for every subdomain."),
                        inputs.host.clone(),
                    )))
                    .child(
                        btn(id("ct", "add-host"), "Add", BtnKind::Plain).on_click(cx.listener(
                            |this, _, _, cx| {
                                this.ct_add_host(cx);
                                cx.notify();
                            },
                        )),
                    ),
            )
            .child(text_dim(count).text_size(px(11.)))
            .child(
                div()
                    .flex()
                    .gap(px(8.))
                    .child(next)
                    .child(self.ct_cancel(cx)),
            )
            .into_any_element()
    }

    fn ct_details_step(
        &self,
        panel: &Panel,
        inputs: &Inputs,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mode = panel.mode;
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(text_dim(format!("For {}", panel.hosts.join(", "))).min_w_0());
        form = form.child(div().w_full().max_w(px(420.)).child(field(
            "Name",
            Some("Optional. Shown in the certificate list."),
            inputs.name.clone(),
        )));
        if mode == Mode::Generate {
            form = form.child(div().w_full().max_w(px(200.)).child(field(
                "Days valid",
                Some("Leave blank for 365."),
                inputs.days.clone(),
            )));
        }
        if mode == Mode::Acme {
            form = form.child(div().w_full().max_w(px(420.)).child(field(
                "Email",
                Some("Let's Encrypt sends expiry warnings here."),
                inputs.email.clone(),
            )));
        }
        if mode == Mode::OriginCa {
            let mut items = Vec::new();
            for days in ORIGIN_VALIDITY_DAYS {
                items.push(
                    seg_item(
                        id("ct-valid", days),
                        &origin_days_label(days),
                        panel.origin_days == days,
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(p) = this.certtools.panel.as_mut() {
                            p.origin_days = days;
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
                );
            }
            form = form.child(field("Valid for", None, div().flex().child(seg_row(items))));
        }
        if mode.needs_token() {
            let hint = if mode == Mode::Acme {
                "Needs permission to edit DNS records for the domain. It is hidden here, sent once and cleared afterwards."
            } else {
                "A token that can create Origin CA certificates. It is hidden here, sent once and cleared afterwards."
            };
            form = form.child(field(
                "Cloudflare API token",
                Some(hint),
                inputs.token.clone(),
            ));
        }
        if mode == Mode::OriginCa {
            form = form.child(self.ct_flag(
                cx,
                "remember",
                panel.remember_token,
                "Keep the token on the node so I do not have to paste it next time",
                |p| p.remember_token = !p.remember_token,
            ));
        }
        if mode == Mode::Acme {
            form = form
                .child(self.ct_flag(
                    cx,
                    "staging",
                    panel.staging,
                    "Use the Let's Encrypt test service (the certificate is not trusted by browsers)",
                    |p| p.staging = !p.staging,
                ))
                .child(self.ct_flag(
                    cx,
                    "tos",
                    panel.agree_tos,
                    "I have read and agree to the Let's Encrypt Subscriber Agreement (letsencrypt.org/repository)",
                    |p| p.agree_tos = !p.agree_tos,
                ));
        }
        let submit = if self.certtools.busy {
            btn_off(mode.submit_label()).into_any_element()
        } else {
            btn(id("ct", "submit"), mode.submit_label(), BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.submit_ct(cx);
                    cx.notify();
                }))
                .into_any_element()
        };
        let back = btn(id("ct", "back"), "Back", BtnKind::Plain)
            .on_click(cx.listener(|this, _, _, cx| {
                if let Some(p) = this.certtools.panel.as_mut() {
                    p.stage = Stage::Hosts;
                }
                this.certtools.note = None;
                cx.notify();
            }))
            .into_any_element();
        form.child(
            div()
                .flex()
                .gap(px(8.))
                .child(submit)
                .child(back)
                .child(self.ct_cancel(cx)),
        )
        .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_tones() {
        assert_eq!(managed_tone("issued", false), Tone::Ok);
        assert_eq!(managed_tone("issued", true), Tone::Bad);
        assert_eq!(managed_tone("failed", false), Tone::Bad);
        assert_eq!(managed_tone("renewing", false), Tone::Info);
    }

    #[test]
    fn a_client_side_problem_keeps_its_own_wording() {
        assert_eq!(op_error(&ClientError::Config("no".into())), "no");
        assert!(op_error(&ClientError::Decode("odd".into())).contains("odd"));
    }

    #[test]
    fn the_default_state_holds_nothing_secret_or_busy() {
        let s = CertToolsState::default();
        assert!(s.inputs.is_none() && s.panel.is_none() && !s.busy && s.job.is_none());
        assert!(!s.requested && !s.unsupported);
    }

    #[test]
    fn a_panel_belongs_to_the_node_it_was_opened_for() {
        let panel = Panel {
            node: "edge-fra".into(),
            mode: Mode::Acme,
            stage: Stage::Hosts,
            hosts: Vec::new(),
            origin_days: DEFAULT_ORIGIN_DAYS,
            remember_token: false,
            agree_tos: false,
            staging: false,
        };
        assert!(ensure_same_node(&panel.node, Some("edge-fra")).is_ok());
        assert!(ensure_same_node(&panel.node, Some("edge-iad")).is_err());
        assert!(ensure_same_node(&panel.node, None).is_err());
    }
}
