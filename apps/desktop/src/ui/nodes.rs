use cite_client::NodeConfig;
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{Credential, enroll};
use crate::app::{Confirm, Console, Load, new_input};
use crate::config::DesktopNode;
use crate::model::token_name;
use crate::theme::{DIM, DIVIDER, MONO, Tone, c, chip_fill, chip_stroke};
use crate::ui::chart::{FIELD_MIN, clip_tip, split, wide};
use crate::ui::input::TextInput;
use crate::ui::settings::{GAP, SPACE};
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, empty_state, field, grid_min, id, mono, notice, page_header,
    pill, seg_item, seg_row, strong, table, text_dim,
};

pub struct State {
    pub adding: bool,
    pub login_mode: bool,
    pub busy: bool,
    pub error: Option<String>,
    pub name: Entity<TextInput>,
    pub url: Entity<TextInput>,
    pub ca: Entity<TextInput>,
    pub token: Entity<TextInput>,
    pub user: Entity<TextInput>,
    pub pass: Entity<TextInput>,
    pub totp: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            adding: false,
            login_mode: false,
            busy: false,
            error: None,
            name: new_input(cx, "edge-fra", |i| i),
            url: new_input(cx, "https://node.example.com:7443", |i| i.mono()),
            ca: new_input(cx, "/path/to/ca.pem (optional)", |i| i.mono()),
            token: new_input(cx, "cite_...", |i| i.masked().mono()),
            user: new_input(cx, "admin", |i| i),
            pass: new_input(cx, "Password", |i| i.masked()),
            totp: new_input(cx, "123456", |i| i.mono()),
        }
    }
}

fn read(e: &Entity<TextInput>, cx: &Context<Console>) -> String {
    e.read(cx).text().trim().to_string()
}

impl Console {
    // Nothing is stored until the node answers node_info with the supplied credential.
    pub fn submit_node(&mut self, cx: &mut Context<Self>) {
        if self.nodes.busy {
            return;
        }
        if self.demo {
            self.nodes.error = Some("Adding nodes is disabled in demo mode.".into());
            return;
        }
        let n = &self.nodes;
        let (name, url, ca) = (read(&n.name, cx), read(&n.url, cx), read(&n.ca, cx));
        let node = DesktopNode {
            name: name.clone(),
            url,
            ca_pem: Some(ca).filter(|c| !c.is_empty()),
            insecure_http: false,
        };
        let resolved: Result<NodeConfig, _> = node.resolve();
        let config = match resolved {
            Ok(cfg) => cfg,
            Err(e) => {
                self.nodes.error = Some(e.to_string());
                return;
            }
        };
        if self.config.node(&name).is_some() {
            self.nodes.error = Some(format!("A node named {name} already exists."));
            return;
        }
        let credential = if self.nodes.login_mode {
            let (user, pass, totp) = (
                read(&n.user, cx),
                n.pass.read(cx).text().to_string(),
                read(&n.totp, cx),
            );
            if user.is_empty() || pass.is_empty() || totp.is_empty() {
                self.nodes.error = Some("Enter the username, password and TOTP code.".into());
                return;
            }
            Credential::Login {
                username: user,
                password: pass,
                totp,
            }
        } else {
            let token = read(&n.token, cx);
            if token.is_empty() {
                self.nodes.error = Some("Paste an API token or switch to username login.".into());
                return;
            }
            Credential::Token(token)
        };
        self.nodes.busy = true;
        self.nodes.error = None;
        let label = token_name(&hostname());
        self.fetch(
            cx,
            enroll(config, credential, label),
            move |this, res, cx| {
                this.nodes.busy = false;
                match res {
                    Ok((token, _info)) => this.finish_add(node, &token, cx),
                    Err(e) => this.nodes.error = Some(e.to_string()),
                }
                cx.notify();
            },
        );
    }

    // The keychain write comes first so a failure never leaves a config entry without a token.
    fn finish_add(&mut self, node: DesktopNode, token: &str, cx: &mut Context<Self>) {
        let name = node.name.clone();
        if let Err(e) = self.tokens.set(&name, token) {
            self.nodes.error = Some(format!("Could not store the token in the keychain: {e}"));
            return;
        }
        let saved = self
            .config
            .add_node(node)
            .and_then(|()| self.config.save(&self.config_path));
        if let Err(e) = saved {
            self.config.remove_node(&name);
            let _ = self.tokens.delete(&name);
            self.nodes.error = Some(e.to_string());
            return;
        }
        for input in [
            &self.nodes.name,
            &self.nodes.url,
            &self.nodes.ca,
            &self.nodes.token,
            &self.nodes.user,
            &self.nodes.pass,
            &self.nodes.totp,
        ] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        self.nodes.adding = false;
        self.connect();
        self.load_overview(cx);
        self.say(format!("Node {name} added"), Tone::Ok);
    }

    // Removal forgets the keychain entry as well; the node itself is untouched.
    fn remove_node(&mut self, name: &str, cx: &mut Context<Self>) {
        let _ = self.tokens.delete(name);
        self.config.remove_node(name);
        if let Err(e) = self.config.save(&self.config_path) {
            self.say(format!("Could not save the config: {e}"), Tone::Bad);
        }
        if self.selected.as_deref() == Some(name) {
            self.set_node(None, cx);
        }
        self.connect();
        self.load_overview(cx);
        self.say(format!("Node {name} removed"), Tone::Ok);
    }

    fn add_toggle(&self, key: &str, cx: &mut Context<Self>) -> AnyElement {
        let (label, kind) = if self.nodes.adding {
            ("Cancel", BtnKind::Plain)
        } else {
            ("Add node", BtnKind::Primary)
        };
        btn(id("nodes-add", key), label, kind)
            .on_click(cx.listener(|this, _, _, cx| {
                this.nodes.adding = !this.nodes.adding;
                this.nodes.error = None;
                cx.notify();
            }))
            .into_any_element()
    }

    pub fn render_nodes(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let header = page_header(
            "Nodes",
            "Connectors this console manages",
            vec![self.add_toggle("page", cx)],
        );
        div()
            .flex()
            .flex_col()
            .gap(px(SPACE))
            .child(header)
            .child(self.nodes_body(cx))
            .into_any_element()
    }

    // The Nodes tab of Settings: the same list and form, with the add action inline since there is no page header.
    pub fn nodes_panel(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let bar = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(px(GAP))
            .child(
                text_dim("Connectors are stored in the config file; their tokens in the keychain.")
                    .text_size(px(12.))
                    .flex_1()
                    .min_w_0(),
            )
            .child(self.add_toggle("tab", cx));
        div()
            .flex()
            .flex_col()
            .gap(px(SPACE))
            .child(bar)
            .child(self.nodes_body(cx))
            .into_any_element()
    }

    fn nodes_body(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut col = div().flex().flex_col().gap(px(SPACE));
        if self.nodes.adding {
            col = col.child(self.add_form(cx));
        }
        let status = |name: &str| -> Option<(bool, String)> {
            let data = self.overview.data.as_ref()?.ready()?;
            data.snaps
                .iter()
                .find(|s| s.name == name)
                .map(|s| (s.online, s.version.clone()))
        };
        let loading = !matches!(self.overview.data, Some(Load::Ready(_)));
        let rows: Vec<Vec<AnyElement>> = self
            .config
            .nodes
            .iter()
            .map(|n| {
                let name = n.name.clone();
                let state = match status(&n.name) {
                    Some((true, _)) => pill("Online", Tone::Ok),
                    Some((false, _)) => pill("Offline", Tone::Bad),
                    None => pill(if loading { "Checking" } else { "Unknown" }, Tone::Muted),
                };
                let version = status(&n.name).map(|s| s.1).filter(|v| !v.is_empty()).map_or("-".to_string(), |v| format!("v{v}"));
                let remove = btn(id("remove-node", &name), "Remove", BtnKind::Danger).on_click(cx.listener(
                    move |this, _, _, cx| {
                        let target = name.clone();
                        this.ask(Confirm {
                            title: "Remove node".into(),
                            message: format!("Forget {target} and delete its token from the keychain? The node itself is untouched."),
                            label: "Remove".into(),
                            danger: true,
                            action: Box::new(move |this, cx| this.remove_node(&target, cx)),
                        });
                        cx.notify();
                    },
                ));
                vec![
                    clip_tip(id("node-name", &n.name), n.name.clone())
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .into_any_element(),
                    clip_tip(id("node-url", &n.name), n.url.clone())
                        .font_family(MONO)
                        .text_size(px(12.))
                        .text_color(c(DIM))
                        .into_any_element(),
                    state.into_any_element(),
                    mono(version).into_any_element(),
                    remove.into_any_element(),
                ]
            })
            .collect();
        if rows.is_empty() && !self.nodes.adding {
            return col.child(self.nodes_empty(cx)).into_any_element();
        }
        let cols = [
            Col::fixed("Name", 160.),
            Col::flex("Connector"),
            Col::fixed("Status", 100.),
            Col::fixed("Version", 90.),
            Col::fixed("", 100.),
        ];
        let body = wide(
            id("nodes", "table"),
            640.,
            table(
                &cols,
                rows,
                Some(empty_state(
                    "No nodes yet",
                    "Fill in the form above to connect the first one.",
                )),
            ),
        );
        col = col.child(card(None, None, body));
        if loading && !self.config.nodes.is_empty() {
            col = col.child(text_dim("Checking each node...").text_size(px(12.)));
        }
        col.into_any_element()
    }

    fn nodes_empty(&self, cx: &mut Context<Self>) -> AnyElement {
        card(
            None,
            None,
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap(px(GAP))
                .py(px(36.))
                .px(px(SPACE))
                .child(strong("No nodes yet").text_size(px(16.)))
                .child(
                    text_dim(
                        "A node is a Cite connector running on a server. Add one with its URL and an API token or your username, password and TOTP code.",
                    )
                    .text_size(px(12.))
                    .max_w(px(460.))
                    .text_center(),
                )
                .child(
                    btn(id("nodes-add", "empty"), "Add your first node", BtnKind::Primary)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.nodes.adding = true;
                            this.nodes.error = None;
                            cx.notify();
                        })),
                ),
        )
        .into_any_element()
    }

    fn add_form(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let n = &self.nodes;
        let login = n.login_mode;
        let mode = seg_row(vec![
            seg_item(id("auth", "token"), "API token", !login)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.nodes.login_mode = false;
                    cx.notify();
                }))
                .into_any_element(),
            seg_item(id("auth", "login"), "Username and password", login)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.nodes.login_mode = true;
                    cx.notify();
                }))
                .into_any_element(),
        ]);
        let creds: AnyElement = if login {
            div()
                .flex()
                .flex_col()
                .gap(px(GAP))
                .child(grid_min(
                    FIELD_MIN,
                    vec![
                        field("Username", None, n.user.clone()).into_any_element(),
                        field("Password", None, n.pass.clone()).into_any_element(),
                    ],
                ))
                .child(field(
                    "TOTP code",
                    Some("The app signs in once, mints a token named for this computer and discards the password."),
                    n.totp.clone(),
                ))
                .into_any_element()
        } else {
            field(
                "API token",
                Some("Stored only in the operating system keychain, never in the config file."),
                n.token.clone(),
            )
            .into_any_element()
        };
        let connector = split(
            "nodes-connector",
            560.,
            GAP,
            field(
                "Name",
                Some("Lowercase letters, digits and dashes."),
                n.name.clone(),
            )
            .into_any_element(),
            field(
                "Connector URL",
                Some("The node's API address, including the port."),
                n.url.clone(),
            )
            .into_any_element(),
        );
        let step_one = div()
            .flex()
            .flex_col()
            .gap(px(GAP))
            .child(connector)
            .child(field(
                "CA certificate",
                Some("Path to a PEM file, or leave empty to trust public roots."),
                n.ca.clone(),
            ));
        let step_two = div()
            .flex()
            .flex_col()
            .gap(px(GAP))
            .child(div().flex().child(mode))
            .child(creds);
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(SPACE))
            .child(step(1, "Connector", "Where the node listens.", step_one))
            .child(step(2, "Sign in", "How this console proves who it is.", step_two));
        if let Some(err) = &n.error {
            form = form.child(notice(err, Tone::Bad));
        }
        let save = if n.busy {
            btn_off("Connecting...").into_any_element()
        } else {
            btn(id("nodes", "save"), "Validate and save", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.submit_node(cx);
                    cx.notify();
                }))
                .into_any_element()
        };
        form = form.child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(GAP))
                .pt(px(GAP))
                .border_t_1()
                .border_color(c(DIVIDER))
                .child(save)
                .child(
                    text_dim("Nothing is saved until the node answers with these details.")
                        .text_size(px(12.)),
                ),
        );
        card(
            Some("Add node"),
            Some("Register a connector the console can manage."),
            form,
        )
        .into_any_element()
    }
}

// A numbered step of a setup form: badge and title on top, the step's fields indented beneath.
pub(crate) fn step(n: usize, title: &str, detail: &str, body: impl IntoElement) -> AnyElement {
    let badge = div()
        .flex()
        .items_center()
        .justify_center()
        .flex_none()
        .size(px(22.))
        .rounded_full()
        .border_1()
        .border_color(chip_stroke())
        .bg(chip_fill())
        .text_size(px(11.))
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .child(n.to_string());
    div()
        .flex()
        .flex_col()
        .gap(px(GAP))
        .min_w_0()
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(badge)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w_0()
                        .child(strong(title.to_string()).text_size(px(13.)))
                        .child(text_dim(detail.to_string()).text_size(px(11.))),
                ),
        )
        .child(div().pl(px(32.)).min_w_0().child(body))
        .into_any_element()
}

// The host name only labels the minted token, so a failed lookup is harmless.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}
