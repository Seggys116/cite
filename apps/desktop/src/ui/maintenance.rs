use cite_edge::model::{MaintenancePage, Site};
use cite_edge::validate::{MAX_PAGE_BYTES, validate_page};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::app::{Confirm, Console, Load, new_input};
use crate::model::{fmt_bytes, slugify};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, empty_state, field, id, mono, notice, page_header, pill, seg_item,
    seg_row, skeleton, strong, table, text_dim, toggle,
};

pub struct Data {
    pub pages: Vec<MaintenancePage>,
    pub sites: Vec<Site>,
}

pub struct State {
    pub data: Load<Data>,
    pub editing: bool,
    pub existing: Option<String>,
    pub error: Option<String>,
    pub name: Entity<TextInput>,
    pub page_id: Entity<TextInput>,
    pub status: Entity<TextInput>,
    pub html: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            editing: false,
            existing: None,
            error: None,
            name: new_input(cx, "Scheduled maintenance", |i| i),
            page_id: new_input(cx, "scheduled", |i| i.mono()),
            status: new_input(cx, "503", |i| i.mono()),
            html: new_input(cx, "<!doctype html>", |i| i.mono().multiline(12)),
        }
    }
}

// New pages start from a minimal valid document.
const STARTER_HTML: &str = "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>Back soon</title></head>\n<body>\n  <h1>Back soon</h1>\n  <p>We are making improvements and will be right back.</p>\n</body>\n</html>\n";

// Builds the page the editor describes, applying the same checks the connector will.
pub fn page_from_form(
    name: &str,
    id_text: &str,
    status: &str,
    html: &str,
) -> Result<MaintenancePage, String> {
    let code = status
        .trim()
        .parse::<u16>()
        .map_err(|_| "The status must be a number such as 503.".to_string())?;
    let page = MaintenancePage {
        id: id_text.trim().to_string(),
        name: name.trim().to_string(),
        html: html.to_string(),
        status: code,
    };
    if page.name.is_empty() {
        return Err("Give the page a name.".into());
    }
    validate_page(&page).map_err(|e| e.to_string())?;
    Ok(page)
}

impl Console {
    pub fn load_maintenance(&mut self, cx: &mut Context<Self>) {
        self.maintenance.data = Load::Loading;
        let Some(h) = self.active_handle() else {
            self.maintenance.data = Load::Idle;
            return;
        };
        let fut = async move {
            let pages = h.list_pages().await?;
            let sites = h.list_sites().await.unwrap_or_default();
            Ok(Data { pages, sites })
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.maintenance.data = Load::from_result(res);
            cx.notify();
        });
    }

    fn open_editor(&mut self, page: Option<&MaintenancePage>, cx: &mut Context<Self>) {
        let m = &self.maintenance;
        let (name, pid, status, html) = match page {
            Some(p) => (
                p.name.clone(),
                p.id.clone(),
                p.status.to_string(),
                p.html.clone(),
            ),
            None => (
                String::new(),
                String::new(),
                "503".into(),
                STARTER_HTML.to_string(),
            ),
        };
        m.name.update(cx, |i, cx| i.set_text(&name, cx));
        m.page_id.update(cx, |i, cx| i.set_text(&pid, cx));
        m.status.update(cx, |i, cx| i.set_text(&status, cx));
        m.html.update(cx, |i, cx| i.set_text(&html, cx));
        self.maintenance.existing = page.map(|p| p.id.clone());
        self.maintenance.editing = true;
        self.maintenance.error = None;
    }

    // The id defaults to a slug of the name when left empty.
    fn save_page(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        let m = &self.maintenance;
        let name = m.name.read(cx).text().to_string();
        let typed_id = m.page_id.read(cx).text().to_string();
        let pid = if typed_id.trim().is_empty() {
            slugify(&name)
        } else {
            typed_id
        };
        let page = match page_from_form(
            &name,
            &pid,
            m.status.read(cx).text(),
            m.html.read(cx).text(),
        ) {
            Ok(p) => p,
            Err(e) => {
                self.maintenance.error = Some(e);
                return;
            }
        };
        let existing = self.maintenance.existing.clone();
        self.maintenance.editing = false;
        let label = page.name.clone();
        match existing {
            Some(old) => self.mutate(
                cx,
                async move { h.update_page(&old, &page).await },
                format!("Page {label} saved"),
            ),
            None => self.mutate(
                cx,
                async move { h.create_page(&page).await },
                format!("Page {label} created"),
            ),
        }
    }

    pub fn render_maintenance(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let new = btn(id("mt", "new"), "New page", BtnKind::Primary).on_click(cx.listener(
            |this, _, _, cx| {
                this.open_editor(None, cx);
                cx.notify();
            },
        ));
        let subtitle = match self.active_name() {
            Some(n) => format!("Pages served by {n}"),
            None => "Pages shown during maintenance".into(),
        };
        let mut col = div().flex().flex_col().gap(px(16.)).child(page_header(
            "Maintenance pages",
            &subtitle,
            vec![new.into_any_element()],
        ));
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        col = col.children(self.scope_note());
        if self.maintenance.editing {
            col = col.child(self.editor_card(cx));
        }
        match &self.maintenance.data {
            Load::Idle | Load::Loading => col = col.child(skeleton(180.)),
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                col = col
                    .child(self.pages_card(data, cx))
                    .child(self.assign_card(data, cx));
            }
        }
        col.into_any_element()
    }

    fn editor_card(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let m = &self.maintenance;
        let size = m.html.read(cx).text().len();
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex().flex_col().flex_1().child(field(
                        "Name",
                        None,
                        m.name.clone(),
                    )))
                    .child(div().flex().flex_col().w(px(200.)).child(field(
                        "Id",
                        Some("Defaults to the name"),
                        m.page_id.clone(),
                    )))
                    .child(div().flex().flex_col().w(px(100.)).child(field(
                        "Status",
                        None,
                        m.status.clone(),
                    ))),
            )
            .child(field(
                "HTML",
                Some(&format!(
                    "{} of {} used. Served exactly as written.",
                    fmt_bytes(size as u64),
                    fmt_bytes(MAX_PAGE_BYTES as u64)
                )),
                m.html.clone(),
            ));
        if let Some(err) = &m.error {
            form = form.child(notice(err, Tone::Bad));
        }
        form =
            form.child(
                div()
                    .flex()
                    .gap(px(8.))
                    .child(
                        btn(id("mt", "save"), "Save page", BtnKind::Primary).on_click(cx.listener(
                            |this, _, _, cx| {
                                this.save_page(cx);
                                cx.notify();
                            },
                        )),
                    )
                    .child(btn(id("mt", "cancel"), "Cancel", BtnKind::Plain).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.maintenance.editing = false;
                            cx.notify();
                        }),
                    )),
            );
        let title = if self.maintenance.existing.is_some() {
            "Edit page"
        } else {
            "New maintenance page"
        };
        card(
            Some(title),
            Some("Shown in place of a site while maintenance mode is on."),
            form,
        )
        .into_any_element()
    }

    fn pages_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let rows: Vec<Vec<AnyElement>> = data
            .pages
            .iter()
            .map(|p| {
                let (edit_page, del_id, del_name) = (p.clone(), p.id.clone(), p.name.clone());
                let used = data
                    .sites
                    .iter()
                    .filter(|s| s.maintenance.page_id.as_deref() == Some(&p.id))
                    .count();
                let edit = btn(id("page-edit", &p.id), "Edit", BtnKind::Plain).on_click(
                    cx.listener(move |this, _, _, cx| {
                        this.open_editor(Some(&edit_page), cx);
                        cx.notify();
                    }),
                );
                let del = btn(id("page-del", &p.id), "Delete", BtnKind::Danger).on_click(
                    cx.listener(move |this, _, _, cx| {
                        let (pid, label) = (del_id.clone(), del_name.clone());
                        this.ask(Confirm {
                            title: "Delete page".into(),
                            message: format!(
                                "Delete {label}? A page that a site still uses cannot be removed."
                            ),
                            label: "Delete page".into(),
                            danger: true,
                            action: Box::new(move |this, cx| {
                                if let Some(h) = this.active_handle() {
                                    this.mutate(
                                        cx,
                                        async move { h.delete_page(&pid).await },
                                        format!("Page {label} deleted"),
                                    );
                                }
                            }),
                        });
                        cx.notify();
                    }),
                );
                vec![
                    strong(p.name.clone()).into_any_element(),
                    mono(p.id.clone()).text_color(c(DIM)).into_any_element(),
                    pill(&p.status.to_string(), Tone::Muted).into_any_element(),
                    text_dim(fmt_bytes(p.html.len() as u64)).into_any_element(),
                    text_dim(format!("{used} site(s)")).into_any_element(),
                    div()
                        .flex()
                        .gap(px(6.))
                        .child(edit)
                        .child(del)
                        .into_any_element(),
                ]
            })
            .collect();
        let cols = [
            Col::flex("Page"),
            Col::fixed("Id", 150.),
            Col::fixed("Status", 80.),
            Col::fixed("Size", 80.),
            Col::fixed("Used by", 90.),
            Col::fixed("", 170.),
        ];
        let body = table(
            &cols,
            rows,
            Some(empty_state(
                "No maintenance pages",
                "Create a page to show visitors while a site is under maintenance.",
            )),
        );
        card(Some("Pages"), None, body).into_any_element()
    }

    // Each change sends the whole maintenance block, so the other half is carried over.
    fn assign_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let mut list = div().flex().flex_col().gap(px(12.));
        for site in &data.sites {
            let (sid, enabled, current) = (
                site.id.clone(),
                site.maintenance.enabled,
                site.maintenance.page_id.clone(),
            );
            let mut opts = Vec::new();
            let pick = |this: &mut Console,
                        cx: &mut Context<Console>,
                        sid: String,
                        page: Option<String>,
                        on: bool| {
                if let Some(h) = this.active_handle() {
                    this.mutate(
                        cx,
                        async move { h.maintenance(&sid, on, page.as_deref()).await },
                        "Maintenance page assigned".into(),
                    );
                }
            };
            let (s1, c1) = (sid.clone(), enabled);
            opts.push(
                seg_item(
                    id("assign", format!("{}-default", site.id)),
                    "Built-in",
                    current.is_none(),
                )
                .on_click(cx.listener(move |this, _, _, cx| pick(this, cx, s1.clone(), None, c1)))
                .into_any_element(),
            );
            for p in &data.pages {
                let (s2, p2) = (sid.clone(), p.id.clone());
                opts.push(
                    seg_item(
                        id("assign", format!("{}-{}", site.id, p.id)),
                        &p.name,
                        current.as_deref() == Some(&p.id),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        pick(this, cx, s2.clone(), Some(p2.clone()), enabled)
                    }))
                    .into_any_element(),
                );
            }
            let (s3, c3) = (sid.clone(), current.clone());
            let sw = toggle(id("assign-on", &sid), enabled).on_click(
                cx.listener(move |this, _, _, cx| pick(this, cx, s3.clone(), c3.clone(), !enabled)),
            );
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(14.))
                    .child(sw)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .w(px(180.))
                            .flex_none()
                            .child(strong(site.name.clone())),
                    )
                    .child(seg_row(opts)),
            );
        }
        if data.sites.is_empty() {
            list = list.child(text_dim("This node has no sites yet."));
        }
        card(Some("Assign to sites"), Some("The switch turns maintenance mode on or off for the site; the buttons pick the page it serves."), list).into_any_element()
    }
}
