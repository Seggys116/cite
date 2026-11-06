use cite_client::{
    DopplerBindRequest, DopplerBinding, DopplerConfig, DopplerInfo, DopplerProject, NodeInfo,
};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, Res};
use crate::app::{Confirm, Console, new_input};
use crate::certs::wipe;
use crate::demo_ops;
use crate::siteops::{CAP_DOPPLER, clock, has_cap};
use crate::theme::{Tone, c};
use crate::ui::detail::Data;
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, btn, btn_off, card, code_block, field, form_grid, id, notice, seg_item, strong,
    text_dim, toggle,
};

// The node wrappers live here because the Doppler routes are used by this card only.
impl NodeHandle {
    pub(crate) fn offers_doppler(&self, caps: &[String]) -> bool {
        matches!(self, Self::Demo(..)) || has_cap(caps, CAP_DOPPLER)
    }

    pub(crate) fn doppler_node(&self, info: Option<NodeInfo>) -> Option<DopplerInfo> {
        match self {
            Self::Live(_) => info.and_then(|i| i.doppler),
            Self::Demo(..) => Some(demo_ops::doppler_info()),
        }
    }

    pub(crate) async fn dp_projects(&self) -> Res<Vec<DopplerProject>> {
        match self {
            Self::Live(c) => c.doppler_projects().await,
            Self::Demo(..) => Ok(demo_ops::doppler_projects()),
        }
    }

    pub(crate) async fn dp_configs(&self, project: &str) -> Res<Vec<DopplerConfig>> {
        match self {
            Self::Live(c) => c.doppler_configs(project).await,
            Self::Demo(..) => Ok(demo_ops::doppler_configs(project)),
        }
    }

    pub(crate) async fn dp_binding(&self, site: &str) -> Res<DopplerBinding> {
        match self {
            Self::Live(c) => c.site_doppler(site).await,
            Self::Demo(n, _) => Ok(demo_ops::doppler_binding(n, site)),
        }
    }

    pub(crate) async fn dp_bind(&self, site: &str, req: &DopplerBindRequest) -> Res<DopplerBinding> {
        match self {
            Self::Live(c) => c.site_doppler_set(site, req).await,
            Self::Demo(n, _) => Ok(demo_ops::doppler_bind(n, site, req, crate::demo::now_ms())),
        }
    }

    pub(crate) async fn dp_clear(&self, site: &str) -> Res<DopplerBinding> {
        match self {
            Self::Live(c) => c.site_doppler_clear(site).await,
            Self::Demo(n, _) => Ok(demo_ops::doppler_clear(n, site)),
        }
    }

    pub(crate) async fn dp_sync(&self, site: &str) -> Res<DopplerBinding> {
        match self {
            Self::Live(c) => c.site_doppler_sync(site).await,
            Self::Demo(n, _) => Ok(demo_ops::doppler_sync(n, site, crate::demo::now_ms())),
        }
    }
}

// What the node told the card when the site loaded; each list is absent when it could not be read.
pub struct DopplerLoad {
    pub offered: bool,
    pub node: Option<DopplerInfo>,
    pub binding: Option<Result<DopplerBinding, String>>,
    pub projects: Option<Result<Vec<DopplerProject>, String>>,
    pub configs: Option<Result<Vec<DopplerConfig>, String>>,
}

impl DopplerLoad {
    pub fn none() -> Self {
        Self {
            offered: false,
            node: None,
            binding: None,
            projects: None,
            configs: None,
        }
    }
}

pub async fn load_doppler(h: &NodeHandle, site: &str, offered: bool, node: Option<DopplerInfo>) -> DopplerLoad {
    if !offered {
        return DopplerLoad::none();
    }
    let (binding, projects) = tokio::join!(h.dp_binding(site), h.dp_projects());
    let binding = binding.map_err(|e| e.to_string());
    let project = binding
        .as_ref()
        .ok()
        .filter(|b| b.bound)
        .and_then(|b| b.project.clone());
    let configs = match project {
        Some(p) => Some(h.dp_configs(&p).await.map_err(|e| e.to_string())),
        None => None,
    };
    DopplerLoad {
        offered,
        node,
        binding: Some(binding),
        projects: Some(projects.map_err(|e| e.to_string())),
        configs,
    }
}

pub struct DopplerState {
    pub offered: bool,
    pub node: Option<DopplerInfo>,
    pub binding: Option<DopplerBinding>,
    pub error: Option<String>,
    pub projects: Option<Vec<DopplerProject>>,
    pub projects_error: Option<String>,
    pub configs: Option<Vec<DopplerConfig>>,
    pub configs_error: Option<String>,
    pub project: Option<String>,
    pub config: Option<String>,
    pub build: bool,
    pub runtime: bool,
    pub busy: bool,
    // Bumped on every config list request, so an answer for a project picked earlier is dropped.
    pub configs_gen: u64,
    pub token: Entity<TextInput>,
    pub project_in: Entity<TextInput>,
    pub config_in: Entity<TextInput>,
}

impl DopplerState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            offered: false,
            node: None,
            binding: None,
            error: None,
            projects: None,
            projects_error: None,
            configs: None,
            configs_error: None,
            project: None,
            config: None,
            build: true,
            runtime: true,
            busy: false,
            configs_gen: 0,
            token: new_input(cx, "Doppler service token (optional)", |i| i.masked().mono()),
            project_in: new_input(cx, "Project slug", |i| i.mono()),
            config_in: new_input(cx, "Config name, such as prd", |i| i.mono()),
        }
    }

    pub fn reset(&mut self, cx: &mut Context<Console>) {
        self.offered = false;
        self.node = None;
        self.binding = None;
        self.error = None;
        self.projects = None;
        self.projects_error = None;
        self.configs = None;
        self.configs_error = None;
        self.project = None;
        self.config = None;
        self.build = true;
        self.runtime = true;
        self.busy = false;
        self.configs_gen += 1;
        for input in [self.token.clone(), self.project_in.clone(), self.config_in.clone()] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    // A fresh load replaces what the node reported; the picks follow the saved binding.
    pub fn apply(&mut self, load: DopplerLoad) {
        self.offered = load.offered;
        self.node = load.node;
        match load.binding {
            Some(Ok(b)) => {
                if b.bound {
                    self.project = b.project.clone();
                    self.config = b.config.clone();
                    self.build = b.build;
                    self.runtime = b.runtime;
                }
                self.binding = Some(b);
                self.error = None;
            }
            Some(Err(e)) => {
                self.binding = None;
                self.error = Some(e);
            }
            None => self.binding = None,
        }
        match load.projects {
            Some(Ok(p)) => {
                self.projects = Some(p);
                self.projects_error = None;
            }
            Some(Err(e)) => {
                self.projects = None;
                self.projects_error = Some(e);
            }
            None => {
                self.projects = None;
                self.projects_error = None;
            }
        }
        if let Some(c) = load.configs {
            self.set_configs(c);
        }
    }

    fn set_configs(&mut self, res: Result<Vec<DopplerConfig>, String>) {
        match res {
            Ok(c) => {
                self.configs = Some(c);
                self.configs_error = None;
            }
            Err(e) => {
                self.configs = None;
                self.configs_error = Some(e);
            }
        }
    }
}

// The one line under the card title: how the last sync went, with the node's error kept whole.
pub fn sync_line(b: &DopplerBinding) -> (String, Tone) {
    let noun = if b.keys == 1 { "variable" } else { "variables" };
    match b.status.as_str() {
        "synced" => match b.last_sync_at.as_deref().filter(|t| !t.is_empty()) {
            Some(at) => (
                format!("Synced {} {noun} at {}", b.keys, clock(at)),
                Tone::Ok,
            ),
            None => (format!("Synced {} {noun}", b.keys), Tone::Ok),
        },
        "syncing" => ("Syncing with Doppler...".to_string(), Tone::Info),
        "error" => (
            match b.last_error.as_deref().filter(|e| !e.trim().is_empty()) {
                Some(e) => format!("The last sync failed: {e}"),
                None => "The last sync failed.".to_string(),
            },
            Tone::Bad,
        ),
        _ => ("Not synced yet.".to_string(), Tone::Muted),
    }
}

pub fn token_line(source: &str) -> &'static str {
    match source {
        "site" => "Uses the service token saved for this site.",
        "node" => "Uses the node's Doppler token.",
        _ => "No Doppler token is available for this site.",
    }
}

// Why the binding cannot be saved yet, or None when it can.
pub fn bind_problem(
    project: &str,
    config: &str,
    build: bool,
    runtime: bool,
    has_token: bool,
) -> Option<&'static str> {
    if project.trim().is_empty() {
        return Some("Pick a project.");
    }
    if config.trim().is_empty() {
        return Some("Pick a config.");
    }
    if !build && !runtime {
        return Some("Sync build variables, runtime variables or both.");
    }
    if !has_token {
        return Some("The node has no Doppler token: paste a service token for this site.");
    }
    None
}

impl Console {
    fn doppler_handle(&self) -> Option<(NodeHandle, String)> {
        let site = self.detail.data.ready()?.site.id.clone();
        Some((self.handle_named(&self.detail.node)?, site))
    }

    // Picks come from the lists when the node can list them, otherwise from the typed fields.
    fn doppler_picks(&self, cx: &Context<Self>) -> (String, String) {
        let d = &self.ops.doppler;
        let project = match &d.projects {
            Some(_) => d.project.clone().unwrap_or_default(),
            None => d.project_in.read(cx).text().trim().to_string(),
        };
        let config = match &d.configs {
            Some(_) if d.projects.is_some() => d.config.clone().unwrap_or_default(),
            _ => d.config_in.read(cx).text().trim().to_string(),
        };
        (project, config)
    }

    fn doppler_has_token(&self, cx: &Context<Self>) -> bool {
        let d = &self.ops.doppler;
        d.node.as_ref().is_some_and(|n| n.configured)
            || d.binding.as_ref().is_some_and(|b| b.token_source == "site")
            || !d.token.read(cx).text().trim().is_empty()
    }

    fn pick_project(&mut self, project: String, cx: &mut Context<Self>) {
        let d = &mut self.ops.doppler;
        if d.project.as_deref() == Some(project.as_str()) {
            return;
        }
        d.project = Some(project.clone());
        d.config = None;
        d.configs = None;
        d.configs_error = None;
        d.configs_gen += 1;
        let generation = d.configs_gen;
        let Some((h, _)) = self.doppler_handle() else {
            return;
        };
        let key = self.ops.for_site.clone();
        self.fetch(
            cx,
            async move { h.dp_configs(&project).await },
            move |this, res, cx| {
                if this.ops.for_site != key || this.ops.doppler.configs_gen != generation {
                    return;
                }
                this.ops.doppler.set_configs(res.map_err(|e| e.to_string()));
                cx.notify();
            },
        );
    }

    // Binding, syncing and removing share one path: the card shows the binding the node answers with.
    fn doppler_action<F>(&mut self, what: &'static str, fut: F, done: &'static str, cx: &mut Context<Self>)
    where
        F: std::future::Future<Output = Res<DopplerBinding>> + Send + 'static,
    {
        self.ops.doppler.busy = true;
        self.ops.doppler.error = None;
        let key = self.ops.for_site.clone();
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            this.ops.doppler.busy = false;
            if !here || this.ops.for_site != key {
                let (msg, tone) = match res {
                    Ok(_) => (done.to_string(), Tone::Ok),
                    Err(e) => (e.to_string(), Tone::Bad),
                };
                this.say(crate::scope::foreign_notice(what, origin, &msg), tone);
                cx.notify();
                return;
            }
            match res {
                Ok(b) => {
                    if !b.bound {
                        this.ops.doppler.project = None;
                        this.ops.doppler.config = None;
                    }
                    this.ops.doppler.binding = Some(b);
                    this.say(done, Tone::Ok);
                }
                Err(e) => this.ops.doppler.error = Some(e.to_string()),
            }
            cx.notify();
        });
    }

    fn doppler_bind(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.doppler_handle() else {
            return;
        };
        let (project, config) = self.doppler_picks(cx);
        let (build, runtime) = (self.ops.doppler.build, self.ops.doppler.runtime);
        if let Some(p) = bind_problem(&project, &config, build, runtime, self.doppler_has_token(cx)) {
            self.ops.doppler.error = Some(p.to_string());
            return;
        }
        let typed = self.ops.doppler.token.read(cx).text().trim().to_string();
        self.ops.doppler.token.update(cx, |i, cx| i.set_text("", cx));
        let req = DopplerBindRequest {
            project,
            config,
            build,
            runtime,
            token: Some(typed).filter(|t| !t.is_empty()),
        };
        let fut = async move {
            let mut req = req;
            let res = h.dp_bind(&site, &req).await;
            if let Some(t) = req.token.as_mut() {
                wipe(t);
            }
            res
        };
        self.doppler_action("Doppler", fut, "Doppler connected. Variables sync now and on every change.", cx);
    }

    fn doppler_sync(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.doppler_handle() else {
            return;
        };
        let fut = async move { h.dp_sync(&site).await };
        self.doppler_action("Doppler sync", fut, "Doppler sync started", cx);
    }

    fn doppler_remove(&mut self, cx: &mut Context<Self>) {
        let Some((h, site)) = self.doppler_handle() else {
            return;
        };
        let fut = async move { h.dp_clear(&site).await };
        self.doppler_action("Doppler", fut, "Doppler disconnected from this site", cx);
    }

    fn chip_list<T>(
        &self,
        key: &'static str,
        items: &[T],
        label: impl Fn(&T) -> String,
        value: impl Fn(&T) -> String,
        current: Option<&str>,
        pick: fn(&mut Console, String, &mut Context<Console>),
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mut row = div().flex().flex_wrap().gap(px(6.));
        for item in items {
            let v = value(item);
            let on = current == Some(v.as_str());
            row = row.child(
                seg_item(id(key, &v), &label(item), on)
                    .rounded(px(crate::theme::CHIP_RADIUS))
                    .border_1()
                    .border_color(crate::theme::chip_stroke())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        pick(this, v.clone(), cx);
                        cx.notify();
                    })),
            );
        }
        row.into_any_element()
    }

    pub(crate) fn doppler_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let d = &self.ops.doppler;
        if data.site.source.is_none() || !d.offered {
            return None;
        }
        let mut body = div().flex().flex_col().gap(px(14.));
        match &d.node {
            Some(n) if n.configured => {
                body = body.child(
                    text_dim(format!("The node has a Doppler token ({}).", n.source)).text_size(px(12.)),
                );
            }
            _ => {
                body = body.child(notice(
                    "The node has no Doppler token. Set CITE_DOPPLER_TOKEN on the node, or paste a service token for this site below: it is write-only and never shown again.",
                    Tone::Warn,
                ));
            }
        }
        if let Some(b) = d.binding.as_ref().filter(|b| b.bound) {
            let (line, tone) = sync_line(b);
            let mut status = div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .child(
                    strong(format!(
                        "{} / {}",
                        b.project.as_deref().unwrap_or("-"),
                        b.config.as_deref().unwrap_or("-")
                    ))
                    .text_size(px(13.)),
                )
                .child(div().text_size(px(12.)).text_color(c(tone.color())).child(line))
                .child(text_dim(token_line(&b.token_source)).text_size(px(11.)));
            if b.status == "error"
                && let Some(e) = b.last_error.as_deref().filter(|e| e.contains('\n'))
            {
                let key = format!("dp-error-{}-{}", self.detail.node, data.site.id);
                status = status.child(code_block(key, e.to_string(), 200.));
            }
            body = body.child(status);
        }
        let mut picker = div().flex().flex_col().gap(px(12.));
        match (&d.projects, &d.projects_error) {
            (Some(list), _) if !list.is_empty() => {
                picker = picker.child(field(
                    "Project",
                    None,
                    self.chip_list(
                        "dp-project",
                        list,
                        |p: &DopplerProject| p.name.clone(),
                        |p: &DopplerProject| p.slug.clone(),
                        d.project.as_deref(),
                        |this, v, cx| this.pick_project(v, cx),
                        cx,
                    ),
                ));
            }
            (Some(_), _) => {
                picker = picker.child(text_dim("The token can see no Doppler projects.").text_size(px(12.)));
            }
            (None, err) => {
                if let Some(e) = err {
                    picker = picker.child(
                        text_dim(format!("Projects could not be listed: {e}"))
                            .text_size(px(12.))
                            .text_color(c(Tone::Warn.color())),
                    );
                }
                picker = picker.child(form_grid(vec![
                    field("Project", None, d.project_in.clone()).into_any_element(),
                    field("Config", None, d.config_in.clone()).into_any_element(),
                ]));
            }
        }
        if d.projects.is_some() && d.project.is_some() {
            match (&d.configs, &d.configs_error) {
                (Some(list), _) if !list.is_empty() => {
                    picker = picker.child(field(
                        "Config",
                        None,
                        self.chip_list(
                            "dp-config",
                            list,
                            |c: &DopplerConfig| format!("{} ({})", c.name, c.environment),
                            |c: &DopplerConfig| c.name.clone(),
                            d.config.as_deref(),
                            |this, v, _| this.ops.doppler.config = Some(v),
                            cx,
                        ),
                    ));
                }
                (Some(_), _) => {
                    picker = picker.child(text_dim("This project has no configs.").text_size(px(12.)));
                }
                (None, Some(e)) => {
                    picker = picker.child(
                        text_dim(format!("Configs could not be listed: {e}"))
                            .text_size(px(12.))
                            .text_color(c(Tone::Warn.color())),
                    );
                }
                (None, None) => {
                    picker = picker.child(text_dim("Reading the configs...").text_size(px(12.)));
                }
            }
        }
        let switch = |key: &'static str, label: &'static str, on: bool, flip: fn(&mut Console), cx: &mut Context<Self>| {
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(toggle(id("dp", key), on).on_click(cx.listener(move |this, _, _, cx| {
                    flip(this);
                    cx.notify();
                })))
                .child(div().text_size(px(12.)).child(label))
        };
        picker = picker.child(
            div()
                .flex()
                .flex_wrap()
                .gap(px(20.))
                .child(switch("build", "Sync build variables", d.build, |t| t.ops.doppler.build = !t.ops.doppler.build, cx))
                .child(switch("runtime", "Sync runtime variables", d.runtime, |t| t.ops.doppler.runtime = !t.ops.doppler.runtime, cx)),
        );
        picker = picker.child(field(
            "Service token for this site",
            Some("Optional when the node has a token. Write-only: it is sent once and never shown again."),
            d.token.clone(),
        ));
        body = body.child(picker);
        let (project, config) = self.doppler_picks(cx);
        let problem = bind_problem(&project, &config, d.build, d.runtime, self.doppler_has_token(cx));
        let bound = d.binding.as_ref().is_some_and(|b| b.bound);
        let label = if bound { "Save" } else { "Connect" };
        let mut actions = div().flex().flex_wrap().items_center().gap(px(8.));
        actions = actions.child(if problem.is_none() && !d.busy {
            btn(id("dp", "bind"), label, BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.doppler_bind(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off(label).into_any_element()
        });
        if bound {
            actions = actions.child(if d.busy {
                btn_off("Sync now").into_any_element()
            } else {
                btn(id("dp", "sync"), "Sync now", BtnKind::Plain)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.doppler_sync(cx);
                        cx.notify();
                    }))
                    .into_any_element()
            });
            actions = actions.child(
                btn(id("dp", "remove"), "Remove", BtnKind::Danger).on_click(cx.listener(|this, _, _, cx| {
                    this.ask(Confirm {
                        title: "Disconnect Doppler".into(),
                        message: "Stop syncing variables from Doppler? Variables already synced stay on the node until you remove them.".into(),
                        label: "Remove".into(),
                        danger: true,
                        action: Box::new(|this, cx| this.doppler_remove(cx)),
                    });
                    cx.notify();
                })),
            );
        }
        if let Some(p) = problem.filter(|_| !d.busy) {
            actions = actions.child(text_dim(p).text_size(px(12.)));
        }
        body = body.child(actions);
        if let Some(e) = &d.error {
            body = body.child(
                div()
                    .text_size(px(12.))
                    .text_color(c(Tone::Bad.color()))
                    .child(e.clone()),
            );
        }
        Some(
            card(
                Some("Doppler"),
                Some("Pull this site's variables from a Doppler config. When they change in Doppler, the node syncs them and redeploys the site automatically."),
                body,
            )
            .into_any_element(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(status: &str, keys: u32) -> DopplerBinding {
        DopplerBinding {
            bound: true,
            project: Some("web".into()),
            config: Some("prd".into()),
            build: true,
            runtime: false,
            token_source: "node".into(),
            status: status.into(),
            last_sync_at: Some("2026-01-02T03:04:05Z".into()),
            last_error: Some("401: token revoked".into()),
            keys,
        }
    }

    #[test]
    fn the_sync_line_says_how_the_last_sync_went() {
        assert_eq!(sync_line(&binding("synced", 12)), ("Synced 12 variables at 03:04:05".to_string(), Tone::Ok));
        assert_eq!(sync_line(&binding("synced", 1)).0, "Synced 1 variable at 03:04:05");
        let failed = sync_line(&binding("error", 0));
        assert_eq!(failed, ("The last sync failed: 401: token revoked".to_string(), Tone::Bad));
        assert_eq!(sync_line(&binding("syncing", 0)).1, Tone::Info);
        assert_eq!(sync_line(&binding("idle", 0)).0, "Not synced yet.");
        let mut quiet = binding("synced", 3);
        quiet.last_sync_at = None;
        assert_eq!(sync_line(&quiet).0, "Synced 3 variables");
    }

    #[test]
    fn a_binding_needs_a_project_a_config_a_target_and_a_token() {
        assert_eq!(bind_problem("", "prd", true, true, true), Some("Pick a project."));
        assert_eq!(bind_problem("web", " ", true, true, true), Some("Pick a config."));
        assert!(bind_problem("web", "prd", false, false, true).unwrap().contains("both"));
        assert!(bind_problem("web", "prd", true, false, false).unwrap().contains("service token"));
        assert_eq!(bind_problem("web", "prd", false, true, true), None);
        assert!(token_line("site").contains("this site"));
        assert!(token_line("node").contains("node"));
        assert!(token_line("none").contains("No Doppler token"));
    }
}
