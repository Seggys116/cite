use cite_client::NodeConfig;
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{Credential, enroll};
use crate::app::{Confirm, Console, Load, new_input};
use crate::config::DesktopNode;
use crate::model::token_name;
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, empty_state, field, id, mono, notice, page_header, pill, seg_item,
    seg_row, skeleton, strong, table,
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
            self.selected = None;
        }
        self.connect();
        self.load_overview(cx);
        self.say(format!("Node {name} removed"), Tone::Ok);
    }

    pub fn render_nodes(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let add = btn(
            id("nodes", "add"),
            if self.nodes.adding {
                "Cancel"
            } else {
                "Add node"
            },
            BtnKind::Primary,
        )
        .on_click(cx.listener(|this, _, _, cx| {
            this.nodes.adding = !this.nodes.adding;
            this.nodes.error = None;
            cx.notify();
        }));
        let header = page_header(
            "Nodes",
            "Connectors this console manages",
            vec![add.into_any_element()],
        );
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
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
                    strong(n.name.clone()).into_any_element(),
                    mono(n.url.clone()).text_color(c(DIM)).into_any_element(),
                    state.into_any_element(),
                    mono(version).into_any_element(),
                    remove.into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::fixed("Name", 160.),
            Col::flex("Connector"),
            Col::fixed("Status", 100.),
            Col::fixed("Version", 90.),
            Col::fixed("", 100.),
        ];
        let body = table(
            &cols,
            rows,
            Some(empty_state(
                "No nodes yet",
                "Add a node to start managing sites.",
            )),
        );
        col = col.child(card(None, None, body));
        if loading && !self.config.nodes.is_empty() {
            col = col.child(skeleton(30.));
        }
        col.into_any_element()
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
                .gap(px(12.))
                .child(div().flex().gap(px(12.)).child(div().flex_1().child(field("Username", None, n.user.clone()))).child(div().flex_1().child(field("Password", None, n.pass.clone()))))
                .child(field("TOTP code", Some("The app signs in once, mints a token named for this computer and discards the password."), n.totp.clone()))
                .into_any_element()
        } else {
            field(
                "API token",
                Some("Stored only in the operating system keychain, never in the config file."),
                n.token.clone(),
            )
            .into_any_element()
        };
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().w(px(220.)).child(field(
                        "Name",
                        Some("Lowercase letters, digits and dashes."),
                        n.name.clone(),
                    )))
                    .child(
                        div()
                            .flex_1()
                            .child(field("Connector URL", None, n.url.clone())),
                    ),
            )
            .child(field(
                "CA certificate",
                Some("Path to a PEM file or leave empty to trust public roots."),
                n.ca.clone(),
            ))
            .child(field("Authentication", None, mode))
            .child(creds);
        if let Some(err) = &n.error {
            form = form.child(notice(err, Tone::Bad));
        }
        let label = if n.busy {
            "Connecting..."
        } else {
            "Validate and save"
        };
        form = form.child(div().flex().child(
            btn(id("nodes", "save"), label, BtnKind::Primary).on_click(cx.listener(
                |this, _, _, cx| {
                    this.submit_node(cx);
                    cx.notify();
                },
            )),
        ));
        card(
            Some("Add node"),
            Some("Register a connector the console can manage."),
            form,
        )
        .into_any_element()
    }
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
