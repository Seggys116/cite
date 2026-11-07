use std::future::Future;

use cite_client::{ClientError, VolumeInfo};
use cite_edge::model::BotPolicy;
use cite_edge::status::SiteStatus;
use gpui::{AnyElement, ClipboardItem, Context, Div, Entity, div, prelude::*, px};

use crate::api::NodeHandle;
use crate::app::{Console, View, new_input};
use crate::certs::wipe;
use crate::model::{
    BUILD_RESOURCE_HINT, PACKAGE_MANAGERS, RENDERINGS, RESOURCE_NOTE, SERVE_RESOURCE_HINT,
};
use crate::scope::{Sequence, foreign_notice};
use crate::siteops::{
    CAP_ASYNC_DEPLOY, CAP_BUILD_ENV, CAP_FORGES, CAP_LOGS, CAP_RUNTIME_ENV, CAP_SOURCE_BUILD,
    CAP_STATUS, CAP_TOKEN, CAP_VOLUMES, NodeExtras, STATUS_TICKS, auto_placeholder, bot_trust,
    clock, detected_value, forge_note, has_cap, is_busy_phase, outcome_rows, phase_label,
    phase_tone, ref_problem, report_lines, should_poll_logs, slot_rows, status_reason,
    token_detail, token_summary,
};
use crate::theme::{CARD_RADIUS, Tone, c, tint};
use crate::ui::detail::Data;
use crate::ui::detail::doppler::{DopplerLoad, DopplerState, load_doppler};
use crate::ui::detail::env::EnvState;
use crate::ui::detail::logs::LogView;
use crate::ui::detail::tabs::SiteTab;
use crate::ui::detail::volumes::VolumeState;
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, empty_state, field, form_grid, id, mono, notice, pill,
    seg_item, seg_row, strong, table, text_dim,
};

// Everything the site page learns beyond the site itself, for the one site it is showing.
pub struct OpsState {
    pub for_site: (String, String),
    pub loaded: bool,
    pub extras: NodeExtras,
    pub busy: bool,
    pub error: Option<String>,
    pub rebuild_prompt: bool,
    pub status_in_flight: bool,
    pub seq: Sequence,
    // Status polls are numbered apart so a poll never makes a full load's reply look stale.
    pub status_seq: Sequence,
    pub logs: LogView,
    pub token: Entity<TextInput>,
    pub git_ref: Entity<TextInput>,
    pub env: EnvState,
    pub doppler: DopplerState,
    pub volumes: VolumeState,
}

impl OpsState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            for_site: (String::new(), String::new()),
            loaded: false,
            extras: NodeExtras::default(),
            busy: false,
            error: None,
            rebuild_prompt: false,
            status_in_flight: false,
            seq: Sequence::default(),
            status_seq: Sequence::default(),
            logs: LogView::new(cx),
            token: new_input(cx, "GitHub token for this site", |i| i.masked().mono()),
            git_ref: new_input(cx, "main, a tag or a commit", |i| i.mono()),
            env: EnvState::new(cx),
            doppler: DopplerState::new(cx),
            volumes: VolumeState::new(cx),
        }
    }
}

struct Loaded {
    extras: NodeExtras,
    doppler: DopplerLoad,
    volumes: Option<Result<Vec<VolumeInfo>, String>>,
}

// Reads what the node offers for one site. Anything a node cannot serve is left out instead of failing the page.
async fn load_extras(h: NodeHandle, site: String, has_source: bool) -> Result<Loaded, ClientError> {
    let info = h.node_info().await.ok();
    let caps = info
        .as_ref()
        .map(|i| i.capabilities.clone())
        .unwrap_or_default();
    let api_host = info
        .as_ref()
        .and_then(|i| i.github.as_ref())
        .and_then(|g| g.api_host.clone());
    let executor_egress = info.as_ref().and_then(|i| i.executor_egress);
    let egress_mode = info.as_ref().and_then(|i| i.egress_mode.clone());
    let dp_offered = has_source && h.offers_doppler(&caps);
    let dp_node = h.doppler_node(info);
    let want = |cap: &str| has_source && has_cap(&caps, cap);
    let (status, token, build_env, runtime_env, rules, doppler, volumes) = tokio::join!(
        async {
            if want(CAP_STATUS) {
                Some(h.site_status(&site).await)
            } else {
                None
            }
        },
        async {
            if want(CAP_TOKEN) {
                h.github_token_status(&site).await.ok()
            } else {
                None
            }
        },
        async {
            if want(CAP_BUILD_ENV) {
                h.env_names(&site, false).await.ok()
            } else {
                None
            }
        },
        async {
            if want(CAP_RUNTIME_ENV) {
                h.env_names(&site, true).await.ok()
            } else {
                None
            }
        },
        async { h.list_rules().await.ok() },
        load_doppler(&h, &site, dp_offered, dp_node),
        async {
            if want(CAP_VOLUMES) {
                Some(h.vol_list(&site).await.map_err(|e| e.to_string()))
            } else {
                None
            }
        },
    );
    let (status, status_error) = match status {
        Some(Ok(s)) => (Some(s), None),
        Some(Err(e)) => (None, Some(e.to_string())),
        None => (None, None),
    };
    Ok(Loaded {
        extras: NodeExtras {
            caps,
            api_host,
            executor_egress,
            egress_mode,
            status,
            status_error,
            token,
            build_env,
            runtime_env,
            rules,
        },
        doppler,
        volumes,
    })
}

fn copy_button(key: String, label: &str, text: String, cx: &mut Context<Console>) -> AnyElement {
    btn(id("ops-copy", key), label, BtnKind::Plain)
        .on_click(cx.listener(move |this, _, _, cx| {
            cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
            this.say("Copied", Tone::Ok);
            cx.notify();
        }))
        .into_any_element()
}

// The help under a build field, with what the node detected appended so a long value is never cut.
pub fn help_with(base: Option<&str>, detected: Option<&str>) -> Option<String> {
    match (base, detected.filter(|d| !d.is_empty())) {
        (Some(b), Some(d)) => Some(format!("{b} Detected: {d}.")),
        (Some(b), None) => Some(b.to_string()),
        (None, Some(d)) => Some(format!("Detected: {d}.")),
        (None, None) => None,
    }
}

// Two fields side by side that fill their columns and stack on a narrow window.
fn pair(left: impl IntoElement, right: impl IntoElement) -> Div {
    form_grid(vec![left.into_any_element(), right.into_any_element()])
}

impl Console {
    pub fn ops_reset(&mut self, cx: &mut Context<Self>) {
        self.ops.for_site = (String::new(), String::new());
        self.ops.loaded = false;
        self.ops.extras = NodeExtras::default();
        self.ops.busy = false;
        self.ops.error = None;
        self.ops.rebuild_prompt = false;
        self.ops.status_in_flight = false;
        self.ops.logs.reset();
        for input in [
            self.ops.logs.search.clone(),
            self.ops.token.clone(),
            self.ops.git_ref.clone(),
        ] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        self.ops.env.build.reset(cx);
        self.ops.env.runtime.reset(cx);
        self.ops.doppler.reset(cx);
        self.ops.volumes.reset(cx);
        self.detail.edit.build.show_detected(None, cx);
    }

    // Called after the site itself has loaded; the extras arrive separately so the page paints first.
    pub fn load_ops(
        &mut self,
        node: String,
        site: String,
        has_source: bool,
        cx: &mut Context<Self>,
    ) {
        let Some(h) = self.handle_named(&node) else {
            return;
        };
        let key = (node, site.clone());
        if self.ops.for_site != key {
            self.ops_reset(cx);
            self.ops.for_site = key.clone();
        }
        let seq = self.ops.seq.issue();
        self.fetch(
            cx,
            load_extras(h, site, has_source),
            move |this, res, cx| {
                if this.ops.for_site != key || !this.ops.seq.accept(seq) {
                    return;
                }
                let Ok(loaded) = res else {
                    return;
                };
                this.detail
                    .edit
                    .build
                    .show_detected(loaded.extras.status.as_ref(), cx);
                this.ops.extras = loaded.extras;
                this.ops.doppler.apply(loaded.doppler);
                this.ops.volumes.existing = loaded.volumes;
                this.ops.loaded = true;
                if this.site_tab() == SiteTab::Logs {
                    this.open_logs(cx);
                }
                cx.notify();
            },
        );
    }

    fn reload_ops(&mut self, cx: &mut Context<Self>) {
        let Some(data) = self.detail.data.ready() else {
            return;
        };
        let (node, site, has_source) = (
            self.detail.node.clone(),
            data.site.id.clone(),
            data.site.source.is_some(),
        );
        self.load_ops(node, site, has_source, cx);
    }

    // Only the status is fetched again; used while a build runs.
    fn refresh_status(&mut self, cx: &mut Context<Self>) {
        let View::SiteDetail { node, id: site } = self.view.clone() else {
            return;
        };
        let Some(h) = self.handle_named(&node) else {
            return;
        };
        if self.ops.status_in_flight {
            return;
        }
        self.ops.status_in_flight = true;
        let key = (node, site.clone());
        let seq = self.ops.status_seq.issue();
        self.fetch(
            cx,
            async move { h.site_status(&site).await },
            move |this, res, cx| {
                this.ops.status_in_flight = false;
                if this.ops.for_site != key || !this.ops.status_seq.accept(seq) {
                    return;
                }
                let was_busy = this
                    .ops
                    .extras
                    .status
                    .as_ref()
                    .is_some_and(|s| is_busy_phase(&s.phase));
                if let Ok(st) = res {
                    let settled = was_busy && !is_busy_phase(&st.phase);
                    this.detail.edit.build.show_detected(Some(&st), cx);
                    this.ops.extras.status = Some(st);
                    this.ops.extras.status_error = None;
                    if settled {
                        this.reload_detail(cx);
                    }
                }
                cx.notify();
            },
        );
    }

    // Runs on the half-second tick: log polling runs only while the Logs tab is open, and both stop when the page is not on screen.
    pub fn ops_tick(&mut self, cx: &mut Context<Self>) {
        let on_site = matches!(self.view, View::SiteDetail { .. });
        let ready = self.ops.loaded && on_site;
        let caps = &self.ops.extras.caps;
        let logs_on = ready && has_cap(caps, CAP_LOGS) && self.site_tab() == SiteTab::Logs;
        if logs_on
            && should_poll_logs(
                self.ops.logs.follow,
                on_site,
                self.window_active,
                self.ops.logs.in_flight,
                self.tick,
            )
        {
            self.poll_logs(cx);
        }
        let building = self
            .ops
            .extras
            .status
            .as_ref()
            .is_some_and(|s| is_busy_phase(&s.phase));
        if ready && building && self.window_active && self.tick.is_multiple_of(STATUS_TICKS) {
            self.refresh_status(cx);
        }
    }

    // A change on the site page that is not the site itself: the page reloads its extras afterwards.
    pub(crate) fn ops_action<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        what: &'static str,
        fut: F,
        outcome: impl FnOnce(&T) -> String + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        self.ops_action_then(cx, what, fut, outcome, |_, _| {});
    }

    // As ops_action, with a step that runs only when the node accepted the change for the page on screen.
    pub(crate) fn ops_action_then<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        what: &'static str,
        fut: F,
        outcome: impl FnOnce(&T) -> String + 'static,
        on_success: impl FnOnce(&mut Self, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        self.ops.busy = true;
        self.ops.error = None;
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            let result = res.map_err(|e| e.to_string()).map(|v| outcome(&v));
            if !here {
                let (msg, tone) = match result {
                    Ok(m) => (m, Tone::Ok),
                    Err(m) => (m, Tone::Bad),
                };
                this.ops.busy = false;
                this.say(foreign_notice(what, origin, &msg), tone);
                cx.notify();
                return;
            }
            this.ops.busy = false;
            match result {
                Ok(msg) => {
                    this.say(msg, Tone::Ok);
                    on_success(this, cx);
                }
                Err(msg) => this.ops.error = Some(msg),
            }
            this.reload_ops(cx);
            cx.notify();
        });
    }

    fn ops_handle(&self) -> Option<(NodeHandle, String)> {
        let site = self.detail.data.ready()?.site.id.clone();
        Some((self.handle_named(&self.detail.node)?, site))
    }

    fn set_site_token(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.ops_handle() else {
            return;
        };
        let mut token = self.ops.token.read(cx).text().to_string();
        self.ops.token.update(cx, |i, cx| i.set_text("", cx));
        let fut = async move {
            let res = h.github_token_set(&site, &token).await;
            wipe(&mut token);
            res
        };
        self.ops_action(cx, "GitHub token", fut, |_| {
            "This site now uses its own GitHub token".to_string()
        });
    }

    fn clear_site_token(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.ops_handle() else {
            return;
        };
        let fut = async move { h.github_token_clear(&site).await };
        self.ops_action(cx, "GitHub token", fut, |_| {
            "This site uses the node's GitHub token".to_string()
        });
    }

    fn deploy_ref(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.ops_handle() else {
            return;
        };
        let git_ref = self.ops.git_ref.read(cx).text().trim().to_string();
        if let Some(p) = ref_problem(&git_ref) {
            self.ops.error = Some(p);
            return;
        }
        let shown = git_ref.clone();
        let fut = async move { h.deploy_async(&site, Some(git_ref.as_str()), None).await };
        self.ops_action(cx, "Deploy", fut, move |_| {
            format!("Deploy of {shown} started")
        });
    }

    // The red box on the status panel: the node's reason, whole and copyable, with any build output under it.
    fn reason_box(
        &self,
        reason: String,
        logs_slot: Option<cite_edge::model::Slot>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let red = Tone::Bad.color();
        let mut actions = div().flex().gap(px(8.));
        if let Some(slot) = logs_slot {
            actions = actions.child(self.view_logs_button("status-logs", slot, cx));
        }
        actions = actions.child(copy_button("reason".into(), "Copy", reason.clone(), cx));
        div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .p(px(12.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(tint(red, 0.6))
            .bg(tint(red, 0.08))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(8.))
                    .child(strong("The last deploy failed").text_color(c(red)))
                    .child(actions),
            )
            .child(self.note_block("status-note", &reason, cx))
            .into_any_element()
    }

    pub(super) fn status_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        if data.site.source.is_none() || !has_cap(&ex.caps, CAP_STATUS) {
            return None;
        }
        let mut body = div().flex().flex_col().gap(px(12.));
        match (&ex.status, &ex.status_error) {
            (Some(st), _) => body = body.child(self.status_body(st, data, cx)),
            (None, Some(e)) => {
                body = body.child(notice(&format!("Status unavailable: {e}"), Tone::Warn))
            }
            (None, None) => body = body.child(text_dim("Reading the status from the node...")),
        }
        Some(
            card(
                Some("Status"),
                Some("What the node reports about the build and the two slots"),
                body,
            )
            .into_any_element(),
        )
    }

    fn status_body(&self, st: &SiteStatus, data: &Data, cx: &mut Context<Self>) -> Div {
        let mut head = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .child(pill(&phase_label(&st.phase), phase_tone(&st.phase)));
        if !st.settings_current {
            head = head.child(pill("Pending changes", Tone::Warn));
        }
        if let Some(op) = &st.operation {
            head = head.child(text_dim(format!("{}: {}", op.kind, op.step)).text_size(px(12.)));
        }
        if !st.checked_at.is_empty() {
            head = head
                .child(text_dim(format!("checked {}", clock(&st.checked_at))).text_size(px(11.)));
        }
        let busy = self.detail.busy || is_busy_phase(&st.phase);
        head = head.child(div().flex_1()).child(if busy {
            btn_off("Redeploy").into_any_element()
        } else {
            btn(id("ops", "redeploy"), "Redeploy", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.do_deploy(cx);
                    cx.notify();
                }))
                .into_any_element()
        });
        let mut col = div().flex().flex_col().gap(px(12.)).child(head);
        if let Some(reason) = status_reason(st) {
            let slot = st
                .last_failure
                .as_ref()
                .and_then(|f| f.slot)
                .filter(|_| self.logs_offered(data));
            col = col.child(self.reason_box(reason, slot, cx));
        }
        if !st.settings_current {
            col = col.child(
                text_dim("Settings were saved after the last build. Redeploy to apply them.")
                    .text_size(px(12.)),
            );
        }
        let rows: Vec<Vec<AnyElement>> = slot_rows(st)
            .into_iter()
            .map(|r| {
                let live = r.slot == data.site.active;
                vec![
                    div()
                        .flex()
                        .gap(px(6.))
                        .child(mono(r.slot.as_str()))
                        .children(live.then(|| pill("live", Tone::Ok)))
                        .into_any_element(),
                    mono(r.container).into_any_element(),
                    div().child(r.health).into_any_element(),
                    div().child(r.restarts.to_string()).into_any_element(),
                    div().child(r.exit).into_any_element(),
                    div().child(r.phase).into_any_element(),
                    mono(r.live).into_any_element(),
                    mono(r.head).into_any_element(),
                    div().child(r.haproxy).into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Slot", 90.),
            Col::flex("Container"),
            Col::fixed("Health", 80.),
            Col::fixed("Restarts", 70.),
            Col::fixed("Exit", 100.),
            Col::fixed("Phase", 80.),
            Col::fixed("Live", 70.),
            Col::fixed("Head", 70.),
            Col::fixed("HAProxy", 110.),
        ];
        col = col.child(table(
            &cols,
            rows,
            Some(empty_state(
                "No slots reported",
                "The node has not reported a slot yet.",
            )),
        ));
        for s in &st.slots {
            let lines = report_lines(s);
            if lines.is_empty() {
                continue;
            }
            col = col.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .child(strong(format!("{} slot", s.slot.as_str())).text_size(px(12.)))
                    .children(lines.into_iter().map(|l| text_dim(l).text_size(px(12.)))),
            );
        }
        col
    }

    // The rebuild question after saving a change the running build does not have yet.
    pub(super) fn rebuild_prompt_card(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.ops.rebuild_prompt {
            return None;
        }
        let now = btn(id("ops", "rebuild-now"), "Redeploy now", BtnKind::Primary).on_click(
            cx.listener(|this, _, _, cx| {
                this.ops.rebuild_prompt = false;
                this.do_deploy(cx);
                cx.notify();
            }),
        );
        let later = btn(id("ops", "rebuild-later"), "Later", BtnKind::Plain).on_click(cx.listener(
            |this, _, _, cx| {
                this.ops.rebuild_prompt = false;
                cx.notify();
            },
        ));
        Some(
            card(
                Some("This change needs a rebuild"),
                Some("The settings are saved, but the running version was built without them."),
                div().flex().gap(px(8.)).child(now).child(later),
            )
            .into_any_element(),
        )
    }

    fn choice_row(
        &self,
        key: &'static str,
        options: &[&'static str],
        current: String,
        set: fn(&mut Console, String),
        cx: &mut Context<Self>,
    ) -> Div {
        let mut items = vec![
            seg_item(id(key, "auto"), "Auto", current.is_empty())
                .on_click(cx.listener(move |this, _, _, cx| {
                    set(this, String::new());
                    cx.notify();
                }))
                .into_any_element(),
        ];
        for o in options {
            let value = o.to_string();
            items.push(
                seg_item(id(key, o), o, current == *o)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        set(this, value.clone());
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        div().flex().child(seg_row(items))
    }

    // Build commands, serving mode and resource limits of a source-built site, as a two-column grid; every blank field is detected or defaulted by the node.
    pub(super) fn build_cards(&self, data: &Data, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let ex = &self.ops.extras;
        if data.site.source.is_none() || !has_cap(&ex.caps, CAP_SOURCE_BUILD) {
            return Vec::new();
        }
        let b = &self.detail.edit.build;
        let st = ex.status.as_ref();
        let found = |key: &str| st.and_then(|s| detected_value(s, key));
        let text = |label: &str, base: Option<&str>, key: &str, input: &Entity<TextInput>| {
            let help = help_with(base, found(key).as_deref());
            field(label, help.as_deref(), input.clone())
        };
        let pm = self.choice_row(
            "build-pm",
            &PACKAGE_MANAGERS,
            b.package_manager.clone(),
            |this, v| this.detail.edit.build.package_manager = v,
            cx,
        );
        let render = self.choice_row(
            "build-render",
            &RENDERINGS,
            b.rendering.clone(),
            |this, v| this.detail.edit.build.rendering = v,
            cx,
        );
        let prune = self.choice_row(
            "build-prune",
            &["yes", "no"],
            b.prune.clone(),
            |this, v| this.detail.edit.build.prune = v,
            cx,
        );
        let choice_help = |key: &str, base: Option<&str>| {
            let detected = auto_placeholder(found(key).as_deref());
            match base {
                Some(b) => format!("{b} Blank is {detected}."),
                None => format!("Blank is {detected}."),
            }
        };
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(18.))
            .child(pair(
                text(
                    "Root directory",
                    Some("Folder of the project inside the repository."),
                    "root_dir",
                    &b.root_dir,
                ),
                text(
                    "Output directory",
                    Some("Folder the build writes the site to."),
                    "output_dir",
                    &b.output_dir,
                ),
            ))
            .child(pair(
                text(
                    "Install command",
                    None,
                    "install_command",
                    &b.install_command,
                ),
                text("Build command", None, "build_command", &b.build_command),
            ))
            .child(pair(
                field(
                    "Package manager",
                    Some(choice_help("package_manager", None).as_str()),
                    pm,
                ),
                field(
                    "Rendering",
                    Some(choice_help("rendering", None).as_str()),
                    render,
                ),
            ))
            .child(pair(
                text(
                    "Start command",
                    Some("Only for server-rendered sites."),
                    "start_command",
                    &b.start_command,
                ),
                text(
                    "Single-page fallback",
                    Some("File served for unknown paths, such as index.html."),
                    "spa_fallback",
                    &b.spa_fallback,
                ),
            ))
            .child(pair(
                text("Framework", None, "framework", &b.framework),
                field(
                    "Prune dependencies",
                    Some(
                        choice_help(
                            "prune",
                            Some("Remove development packages after the build."),
                        )
                        .as_str(),
                    ),
                    prune,
                ),
            ));
        if has_cap(&ex.caps, CAP_FORGES)
            && let Some(note) = forge_note(ex.api_host.as_deref())
        {
            body = body.child(text_dim(note).text_size(px(12.)));
        }
        let resources = div()
            .flex()
            .flex_col()
            .gap(px(18.))
            .child(pair(
                field(
                    "Serving memory (MiB)",
                    Some(SERVE_RESOURCE_HINT),
                    b.memory_mb.clone(),
                ),
                field("Serving CPUs", None, b.cpus.clone()),
            ))
            .child(pair(
                field(
                    "Build memory (MiB)",
                    Some(BUILD_RESOURCE_HINT),
                    b.build_memory_mb.clone(),
                ),
                field("Build CPUs", None, b.build_cpus.clone()),
            ))
            .child(text_dim(RESOURCE_NOTE).text_size(px(12.)));
        vec![
            card(
                Some("Build settings"),
                Some("Blank fields are detected by the node from your repository."),
                body,
            )
            .into_any_element(),
            card(
                Some("Resources"),
                Some("Memory and CPU limits of the build and serving containers."),
                resources,
            )
            .into_any_element(),
        ]
    }

    pub(super) fn token_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        if data.site.source.is_none() || !has_cap(&ex.caps, CAP_TOKEN) {
            return None;
        }
        let status = ex.token.as_ref()?;
        let typed = !self.ops.token.read(cx).text().trim().is_empty();
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(strong(token_summary(status)));
        if let Some(d) = token_detail(status) {
            body = body.child(text_dim(d).text_size(px(12.)));
        }
        body = body.child(
            text_dim(if status.node_token_configured {
                "The node has a GitHub token of its own."
            } else {
                "The node has no GitHub token of its own."
            })
            .text_size(px(12.)),
        );
        let label = if status.site_token_set {
            "Change token"
        } else {
            "Set token"
        };
        let set = if typed && !self.ops.busy {
            btn(id("ops", "token-set"), label, BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.set_site_token(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off(label).into_any_element()
        };
        let mut row = div().flex().gap(px(8.)).child(set);
        if status.site_token_set && !self.ops.busy {
            row = row.child(
                btn(
                    id("ops", "token-clear"),
                    "Use the node token",
                    BtnKind::Plain,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.clear_site_token(cx);
                    cx.notify();
                })),
            );
        }
        body = body
            .child(field(
                "Token for this site",
                Some("Write-only: it is sent once and never shown again."),
                self.ops.token.clone(),
            ))
            .child(row);
        Some(
            card(
                Some("GitHub token"),
                Some("Used to fetch this site's repository"),
                body,
            )
            .into_any_element(),
        )
    }

    // Builds, redeploys and deploying one commit for a source-built site.
    pub(super) fn builds_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        let st = ex.status.as_ref()?;
        if data.site.source.is_none() || !has_cap(&ex.caps, CAP_STATUS) {
            return None;
        }
        let rows: Vec<Vec<AnyElement>> = outcome_rows(st)
            .into_iter()
            .map(|r| {
                let tone = if r.result == "ok" {
                    Tone::Ok
                } else {
                    Tone::Bad
                };
                vec![
                    mono(r.slot.as_str()).into_any_element(),
                    pill(&r.result, tone).into_any_element(),
                    mono(r.sha).into_any_element(),
                    div()
                        .child(crate::diagnose::split_note(&r.reason).reason)
                        .into_any_element(),
                    text_dim(clock(&r.finished)).into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Slot", 70.),
            Col::fixed("Result", 90.),
            Col::fixed("Commit", 80.),
            Col::flex("Reason"),
            Col::fixed("Finished", 90.),
        ];
        let mut body = div().flex().flex_col().gap(px(12.)).child(table(
            &cols,
            rows,
            Some(empty_state(
                "No builds reported",
                "A build appears here once a manager has finished one.",
            )),
        ));
        if has_cap(&ex.caps, CAP_ASYNC_DEPLOY) {
            let typed = self.ops.git_ref.read(cx).text().to_string();
            let problem = ref_problem(&typed);
            let go = if problem.is_none() && !self.ops.busy {
                btn(
                    id("ops", "deploy-ref"),
                    "Deploy this commit",
                    BtnKind::Primary,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.deploy_ref(cx);
                    cx.notify();
                }))
                .into_any_element()
            } else {
                btn_off("Deploy this commit").into_any_element()
            };
            body = body.child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(12.))
                    .child(div().flex_1().min_w_0().child(field(
                        "Deploy a branch, tag or commit",
                        Some("Builds this ref into the idle slot without waiting here; watch the status above."),
                        self.ops.git_ref.clone(),
                    )))
                    .child(div().pb(px(18.)).child(go)),
            );
        }
        Some(
            card(
                Some("Builds"),
                Some("The last build each slot's manager reports"),
                body,
            )
            .into_any_element(),
        )
    }

    // Under the bot policy: says whether Allow really means nothing blocks bots, and lists the rules that could.
    pub(super) fn bot_trust_block(&self, data: &Data) -> Option<AnyElement> {
        let rules = self.ops.extras.rules.as_ref()?;
        let policy: BotPolicy = data.site.access.bots;
        let trust = bot_trust(policy, rules, &data.site.id);
        let tone = if policy == BotPolicy::Allow && trust.rules.is_empty() {
            Tone::Info
        } else {
            Tone::Warn
        };
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(notice(&trust.message, tone));
        if !trust.rules.is_empty() {
            col = col
                .child(text_dim("Firewall rules that match user agents:").text_size(px(12.)))
                .children(trust.rules.into_iter().map(mono));
        }
        Some(col.into_any_element())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_help_carries_the_detected_value_whole() {
        let long = "pnpm install --frozen-lockfile --prefer-offline";
        assert_eq!(
            help_with(Some("Folder of the project."), Some(".")).as_deref(),
            Some("Folder of the project. Detected: .."),
        );
        assert_eq!(
            help_with(None, Some(long)),
            Some(format!("Detected: {long}."))
        );
        assert_eq!(help_with(Some("Base."), Some("")).as_deref(), Some("Base."));
        assert_eq!(help_with(None, None), None);
    }
}
