use std::future::Future;

use cite_client::ClientError;
use cite_edge::model::{BotPolicy, Slot};
use cite_edge::status::SiteStatus;
use gpui::{AnyElement, ClipboardItem, Context, Div, Entity, div, prelude::*, px};

use crate::api::NodeHandle;
use crate::app::{Confirm, Console, View, new_input};
use crate::certs::wipe;
use crate::model::{
    BUILD_RESOURCE_HINT, PACKAGE_MANAGERS, RENDERINGS, RESOURCE_NOTE, SERVE_RESOURCE_HINT,
};
use crate::scope::{Sequence, foreign_notice};
use crate::siteops::{
    CAP_ASYNC_DEPLOY, CAP_BUILD_ENV, CAP_FORGES, CAP_LOGS, CAP_RUNTIME_ENV, CAP_SOURCE_BUILD,
    CAP_STATUS, CAP_TOKEN, LogBuffer, NodeExtras, STATUS_TICKS, auto_placeholder, bot_trust, clock,
    detected_value, env_patch, forge_note, has_cap, is_busy_phase, log_query, outcome_rows,
    phase_label, phase_tone, ref_problem, report_lines, should_poll_logs, slot_rows, status_reason,
    token_detail, token_summary,
};
use crate::theme::{CARD_RADIUS, Tone, c, tint};
use crate::ui::detail::Data;
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, empty_state, field, id, mono, notice, pill, seg_item,
    seg_row, strong, table, text_dim, toggle,
};

// Most rows the log view paints at once; the buffer behind it keeps more.
const SHOWN_LOG_ROWS: usize = 300;

pub struct EnvEditor {
    pub name: Entity<TextInput>,
    pub value: Entity<TextInput>,
}

pub struct LogView {
    pub source: &'static str,
    pub slot: Slot,
    pub follow: bool,
    pub in_flight: bool,
    // Bumped whenever the stream changes, so a late reply for the old stream is dropped.
    pub generation: u64,
    pub buf: LogBuffer,
    pub error: Option<String>,
    pub search: Entity<TextInput>,
}

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
    pub logs: LogView,
    pub token: Entity<TextInput>,
    pub git_ref: Entity<TextInput>,
    pub build_env: EnvEditor,
    pub runtime_env: EnvEditor,
}

impl OpsState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        let env = |cx: &mut Context<Console>| EnvEditor {
            name: new_input(cx, "API_BASE_URL", |i| i.mono()),
            value: new_input(cx, "Value (never shown again)", |i| i.masked().mono()),
        };
        Self {
            for_site: (String::new(), String::new()),
            loaded: false,
            extras: NodeExtras::default(),
            busy: false,
            error: None,
            rebuild_prompt: false,
            status_in_flight: false,
            seq: Sequence::default(),
            logs: LogView {
                source: "manager",
                slot: Slot::Blue,
                follow: true,
                in_flight: false,
                generation: 0,
                buf: LogBuffer::default(),
                error: None,
                search: new_input(cx, "Search the log", |i| i),
            },
            token: new_input(cx, "GitHub token for this site", |i| i.masked().mono()),
            git_ref: new_input(cx, "main, a tag or a commit", |i| i.mono()),
            build_env: env(cx),
            runtime_env: env(cx),
        }
    }
}

// Reads what the node offers for one site. Anything a node cannot serve is left out instead of failing the page.
async fn load_extras(
    h: NodeHandle,
    site: String,
    has_source: bool,
) -> Result<NodeExtras, ClientError> {
    let info = h.node_info().await.ok();
    let caps = info
        .as_ref()
        .map(|i| i.capabilities.clone())
        .unwrap_or_default();
    let api_host = info.and_then(|i| i.github).and_then(|g| g.api_host);
    let want = |cap: &str| has_source && has_cap(&caps, cap);
    let (status, token, build_env, runtime_env, rules) = tokio::join!(
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
    );
    let (status, status_error) = match status {
        Some(Ok(s)) => (Some(s), None),
        Some(Err(e)) => (None, Some(e.to_string())),
        None => (None, None),
    };
    Ok(NodeExtras {
        caps,
        api_host,
        status,
        status_error,
        token,
        build_env,
        runtime_env,
        rules,
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

fn problem_line(text: &str) -> Div {
    text_dim(text.to_string())
        .text_size(px(12.))
        .text_color(c(Tone::Bad.color()))
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
        self.ops.logs.buf.clear();
        self.ops.logs.in_flight = false;
        self.ops.logs.error = None;
        self.ops.logs.generation += 1;
        self.ops.logs.follow = true;
        self.ops.logs.source = "manager";
        self.ops.logs.slot = Slot::Blue;
        for input in [
            self.ops.logs.search.clone(),
            self.ops.token.clone(),
            self.ops.git_ref.clone(),
            self.ops.build_env.name.clone(),
            self.ops.build_env.value.clone(),
            self.ops.runtime_env.name.clone(),
            self.ops.runtime_env.value.clone(),
        ] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
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
                let Ok(extras) = res else {
                    return;
                };
                if !this.ops.loaded
                    && let Some(st) = &extras.status
                {
                    this.ops.logs.slot = st.active;
                }
                this.detail
                    .edit
                    .build
                    .show_detected(extras.status.as_ref(), cx);
                this.ops.extras = extras;
                this.ops.loaded = true;
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
        let seq = self.ops.seq.issue();
        self.fetch(
            cx,
            async move { h.site_status(&site).await },
            move |this, res, cx| {
                this.ops.status_in_flight = false;
                if this.ops.for_site != key || !this.ops.seq.accept(seq) {
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

    pub fn poll_logs(&mut self, cx: &mut Context<Self>) {
        let View::SiteDetail { node, id: site } = self.view.clone() else {
            return;
        };
        let Some(h) = self.handle_named(&node) else {
            return;
        };
        if self.ops.logs.in_flight {
            return;
        }
        self.ops.logs.in_flight = true;
        let query = log_query(
            self.ops.logs.source,
            self.ops.logs.slot,
            self.ops.logs.buf.cursor(),
        );
        let (key, generation) = ((node, site.clone()), self.ops.logs.generation);
        self.fetch(
            cx,
            async move { h.site_logs(&site, &query).await },
            move |this, res, cx| {
                if this.ops.for_site != key || this.ops.logs.generation != generation {
                    return;
                }
                this.ops.logs.in_flight = false;
                match res {
                    Ok(reply) => {
                        this.ops.logs.error = None;
                        if this.ops.logs.buf.push(reply) > 0 {
                            cx.notify();
                        }
                    }
                    Err(e) => {
                        this.ops.logs.error = Some(e.to_string());
                        cx.notify();
                    }
                }
            },
        );
    }

    // Moving to another log stream starts from an empty buffer and its own cursor.
    fn switch_log_stream(&mut self, source: &'static str, slot: Slot, cx: &mut Context<Self>) {
        let logs = &mut self.ops.logs;
        logs.source = source;
        logs.slot = slot;
        logs.buf.clear();
        logs.error = None;
        logs.in_flight = false;
        logs.generation += 1;
        self.poll_logs(cx);
    }

    // Runs on the half-second tick: follow polling and the status refresh stop whenever the page is not on screen.
    pub fn ops_tick(&mut self, cx: &mut Context<Self>) {
        let on_site = matches!(self.view, View::SiteDetail { .. });
        let ready = self.ops.loaded && on_site;
        let caps = &self.ops.extras.caps;
        let logs_on = ready && has_cap(caps, CAP_LOGS) && self.ops.extras.status.is_some();
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
    fn ops_action<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        what: &'static str,
        fut: F,
        outcome: impl FnOnce(&T) -> String + 'static,
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
                Ok(msg) => this.say(msg, Tone::Ok),
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

    fn set_env(&mut self, runtime: bool, cx: &mut Context<Self>) {
        let Some((h, site)) = self.ops_handle() else {
            return;
        };
        let editor = if runtime {
            &self.ops.runtime_env
        } else {
            &self.ops.build_env
        };
        let (name_in, value_in) = (editor.name.clone(), editor.value.clone());
        let name = name_in.read(cx).text().to_string();
        let mut value = value_in.read(cx).text().to_string();
        let patch = match env_patch(runtime, &[(name.clone(), value.clone())], &[]) {
            Ok(p) => p,
            Err(e) => {
                wipe(&mut value);
                self.ops.error = Some(e);
                return;
            }
        };
        wipe(&mut value);
        name_in.update(cx, |i, cx| i.set_text("", cx));
        value_in.update(cx, |i, cx| i.set_text("", cx));
        let label = if runtime {
            "Runtime variable"
        } else {
            "Build variable"
        };
        let key = crate::siteops::env_name(&name);
        let fut = async move { h.env_patch(&site, runtime, &patch).await };
        self.ops_action(cx, label, fut, move |_| {
            format!("{key} saved. It applies on the next redeploy.")
        });
    }

    fn remove_env(&mut self, runtime: bool, name: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.ops_handle() else {
            return;
        };
        let patch = match env_patch(runtime, &[], std::slice::from_ref(&name)) {
            Ok(p) => p,
            Err(e) => {
                self.ops.error = Some(e);
                return;
            }
        };
        let label = if runtime {
            "Runtime variable"
        } else {
            "Build variable"
        };
        let fut = async move { h.env_patch(&site, runtime, &patch).await };
        self.ops_action(cx, label, fut, move |_| {
            format!("{name} removed. It applies on the next redeploy.")
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

    // The red box on the status panel: the node's reason, whole and copyable.
    fn reason_box(&self, reason: String, cx: &mut Context<Self>) -> AnyElement {
        let red = Tone::Bad.color();
        div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .p(px(12.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(tint(red, 0.6))
            .bg(tint(red, 0.08))
            .child(strong("The last deploy failed").text_color(c(red)))
            .child(mono(reason.clone()))
            .child(
                div()
                    .flex()
                    .child(copy_button("reason".into(), "Copy the reason", reason, cx)),
            )
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
            col = col.child(self.reason_box(reason, cx));
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

    // Build commands, serving mode and resource limits of a source-built site; every blank field is detected or defaulted by the node.
    pub(super) fn build_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        if data.site.source.is_none() || !has_cap(&ex.caps, CAP_SOURCE_BUILD) {
            return None;
        }
        let b = &self.detail.edit.build;
        let st = ex.status.as_ref();
        let hint = |key: &str| auto_placeholder(st.and_then(|s| detected_value(s, key)).as_deref());
        let small = |label: &str, help: Option<&str>, input: &Entity<TextInput>| {
            div().flex_1().child(field(label, help, input.clone()))
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
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(small(
                        "Root directory",
                        Some("Folder of the project inside the repository."),
                        &b.root_dir,
                    ))
                    .child(small(
                        "Output directory",
                        Some("Folder the build writes the site to."),
                        &b.output_dir,
                    )),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(small("Install command", None, &b.install_command))
                    .child(small("Build command", None, &b.build_command)),
            )
            .child(field(
                "Package manager",
                Some(hint("package_manager").as_str()),
                pm,
            ))
            .child(field("Rendering", Some(hint("rendering").as_str()), render))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(small(
                        "Start command",
                        Some("Only for server-rendered sites."),
                        &b.start_command,
                    ))
                    .child(small(
                        "Single-page fallback",
                        Some("File served for unknown paths, such as index.html."),
                        &b.spa_fallback,
                    )),
            )
            .child(small("Framework", None, &b.framework))
            .child(field(
                "Prune dependencies",
                Some("Remove development packages after the build."),
                prune,
            ));
        if has_cap(&ex.caps, CAP_FORGES)
            && let Some(note) = forge_note(ex.api_host.as_deref())
        {
            body = body.child(text_dim(note).text_size(px(12.)));
        }
        body = body
            .child(strong("Resources").text_size(px(13.)))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(small(
                        "Serving memory (MiB)",
                        Some(SERVE_RESOURCE_HINT),
                        &b.memory_mb,
                    ))
                    .child(small("Serving CPUs", None, &b.cpus)),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(small(
                        "Build memory (MiB)",
                        Some(BUILD_RESOURCE_HINT),
                        &b.build_memory_mb,
                    ))
                    .child(small("Build CPUs", None, &b.build_cpus)),
            )
            .child(text_dim(RESOURCE_NOTE).text_size(px(12.)));
        Some(
            card(
                Some("Build settings"),
                Some("Blank fields are detected by the node from your repository. Saved with the form below."),
                body,
            )
            .into_any_element(),
        )
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

    fn env_card(&self, data: &Data, runtime: bool, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        let cap = if runtime {
            CAP_RUNTIME_ENV
        } else {
            CAP_BUILD_ENV
        };
        if data.site.source.is_none() || !has_cap(&ex.caps, cap) {
            return None;
        }
        let names = if runtime {
            ex.runtime_env.as_ref()?
        } else {
            ex.build_env.as_ref()?
        };
        let editor = if runtime {
            &self.ops.runtime_env
        } else {
            &self.ops.build_env
        };
        let key = if runtime { "runtime-env" } else { "build-env" };
        let mut list = div().flex().flex_col().gap(px(6.));
        if names.is_empty() {
            list = list.child(text_dim("No variables are set.").text_size(px(12.)));
        }
        for name in names {
            let drop_name = name.clone();
            list =
                list.child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .child(div().flex_1().child(mono(name.clone())))
                        .child(text_dim("value hidden").text_size(px(11.)))
                        .child(btn(id(key, name), "Remove", BtnKind::Danger).on_click(
                            cx.listener(move |this, _, _, cx| {
                                let victim = drop_name.clone();
                                this.ask(Confirm {
                                    title: "Remove variable".into(),
                                    message: format!(
                                        "Remove {victim}? It stops applying on the next redeploy."
                                    ),
                                    label: "Remove".into(),
                                    danger: true,
                                    action: Box::new(move |this, cx| {
                                        this.remove_env(runtime, victim, cx)
                                    }),
                                });
                                cx.notify();
                            }),
                        )),
                );
        }
        let ready = !self.ops.busy && !editor.name.read(cx).text().trim().is_empty();
        let add = if ready {
            btn(id(key, "set"), "Set variable", BtnKind::Primary)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.set_env(runtime, cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Set variable").into_any_element()
        };
        let (title, sub) = if runtime {
            (
                "Runtime environment",
                "Variables the running site can read. Values are never shown again.",
            )
        } else {
            (
                "Build environment",
                "Variables available while the site builds. Values are never shown again.",
            )
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(list)
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex_1().child(field(
                        "Name",
                        Some("Upper case letters, digits and _"),
                        editor.name.clone(),
                    )))
                    .child(
                        div()
                            .flex_1()
                            .child(field("Value", None, editor.value.clone())),
                    ),
            )
            .child(div().flex().child(add))
            .child(text_dim("Changes apply on the next redeploy.").text_size(px(12.)));
        Some(card(Some(title), Some(sub), body).into_any_element())
    }

    pub(super) fn logs_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        if data.site.source.is_none() || !has_cap(&ex.caps, CAP_LOGS) || ex.status.is_none() {
            return None;
        }
        let logs = &self.ops.logs;
        let mut sources = Vec::new();
        for source in ["manager", "executor"] {
            sources.push(
                seg_item(id("logs-source", source), source, logs.source == source)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let slot = this.ops.logs.slot;
                        this.switch_log_stream(source, slot, cx);
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut slots = Vec::new();
        for slot in [Slot::Blue, Slot::Green] {
            slots.push(
                seg_item(
                    id("logs-slot", slot.as_str()),
                    slot.as_str(),
                    logs.slot == slot,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    let source = this.ops.logs.source;
                    this.switch_log_stream(source, slot, cx);
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let needle = logs.search.read(cx).text().to_string();
        let matching = logs.buf.matching(&needle);
        let total = matching.len();
        let mut lines = div().flex().flex_col().gap(px(1.));
        for row in matching.iter().rev().take(SHOWN_LOG_ROWS) {
            lines = lines.child(
                div()
                    .flex()
                    .gap(px(8.))
                    .child(
                        text_dim(clock(&row.ts))
                            .text_size(px(11.))
                            .w(px(60.))
                            .flex_none(),
                    )
                    .child(
                        mono(row.text.clone())
                            .text_color(c(row.level.tone().color()))
                            .flex_1()
                            .min_w_0(),
                    ),
            );
        }
        if total == 0 {
            lines = lines.child(text_dim("No log lines yet.").text_size(px(12.)));
        }
        let follow =
            toggle(id("logs", "follow"), logs.follow).on_click(cx.listener(|this, _, _, cx| {
                this.ops.logs.follow = !this.ops.logs.follow;
                cx.notify();
            }));
        let refresh = btn(id("logs", "refresh"), "Refresh now", BtnKind::Plain).on_click(
            cx.listener(|this, _, _, cx| {
                this.poll_logs(cx);
                cx.notify();
            }),
        );
        let copy = btn(id("logs", "copy"), "Copy", BtnKind::Plain).on_click(cx.listener(
            |this, _, _, cx| {
                let needle = this.ops.logs.search.read(cx).text().to_string();
                let text = this.ops.logs.buf.copy_text(&needle);
                cx.write_to_clipboard(ClipboardItem::new_string(text));
                this.say("Copied", Tone::Ok);
                cx.notify();
            },
        ));
        let mut head = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(10.))
            .child(seg_row(sources))
            .child(seg_row(slots))
            .child(follow)
            .child(text_dim("Follow").text_size(px(12.)))
            .child(refresh)
            .child(copy);
        if needle.trim().is_empty() {
            head = head.child(text_dim(format!("{total} lines")).text_size(px(11.)));
        } else {
            head = head.child(text_dim(format!("{total} matching lines")).text_size(px(11.)));
        }
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(head)
            .child(div().w(px(320.)).child(logs.search.clone()));
        if let Some(e) = &logs.error {
            body = body.child(problem_line(e));
        }
        if logs.buf.truncated() {
            body = body.child(text_dim("Older lines were cut by the node.").text_size(px(12.)));
        }
        body = body.child(
            div()
                .id("log-lines")
                .max_h(px(360.))
                .overflow_y_scroll()
                .p(px(8.))
                .rounded(px(CARD_RADIUS))
                .border_1()
                .border_color(tint(0xffffff, 0.08))
                .child(lines),
        );
        Some(
            card(
                Some("Logs"),
                Some("Newest lines first. Colour follows the level; the last 5000 lines are kept."),
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
                    div().child(r.reason).into_any_element(),
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
            body = body
                .child(field(
                    "Deploy a branch, tag or commit",
                    Some("Builds this ref into the idle slot without waiting here; watch the status above."),
                    self.ops.git_ref.clone(),
                ))
                .child(div().flex().child(go));
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

    pub(super) fn ops_cards(&self, data: &Data, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let mut cards = Vec::new();
        cards.extend(self.token_card(data, cx));
        cards.extend(self.env_card(data, false, cx));
        cards.extend(self.env_card(data, true, cx));
        cards.extend(self.builds_card(data, cx));
        cards.extend(self.logs_card(data, cx));
        if let Some(e) = &self.ops.error {
            cards.insert(0, notice(e, Tone::Bad).into_any_element());
        }
        cards
    }
}
