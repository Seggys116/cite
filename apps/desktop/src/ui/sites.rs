use cite_edge::model::{Site, SiteKind};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, join_all};
use crate::app::{Console, Load, View, new_input};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
use crate::ui::overview::slot_pill;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, dot, empty_state, id, mono, notice, page_header, pill, skeleton,
    strong, table, text_dim,
};

pub struct Row {
    pub node: String,
    pub site: Site,
    pub health: Vec<(String, String)>,
}

pub struct Data {
    pub rows: Vec<Row>,
    pub failed: Vec<String>,
}

pub struct State {
    pub data: Load<Data>,
    pub filter: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            filter: new_input(cx, "Filter sites by name or host", |i| i),
        }
    }
}

pub fn health_tone(status: &str) -> Tone {
    let up = status.to_uppercase();
    if up.starts_with("UP") || up == "OK" {
        Tone::Ok
    } else if up.contains("DOWN") || up.contains("FAIL") {
        Tone::Bad
    } else if up.contains("MAINT") || up.contains("DRAIN") {
        Tone::Warn
    } else {
        Tone::Muted
    }
}

// Matches name, id or any host, case insensitively.
pub fn matches_filter(row: &Row, needle: &str) -> bool {
    let q = needle.trim().to_lowercase();
    q.is_empty()
        || row.site.name.to_lowercase().contains(&q)
        || row.site.id.contains(&q)
        || row.site.hosts.iter().any(|h| h.to_lowercase().contains(&q))
}

// Health comes from a per-site detail call because the list route omits live state.
async fn node_rows(h: NodeHandle) -> (String, Result<Vec<Row>, String>) {
    let name = h.name().to_string();
    let sites = match h.list_sites().await {
        Ok(s) => s,
        Err(e) => return (name, Err(e.to_string())),
    };
    let mut rows = Vec::new();
    for site in sites {
        let health = match h.get_site(&site.id).await {
            Ok(detail) => live_for(&detail.live, &site),
            Err(_) => Vec::new(),
        };
        rows.push(Row {
            node: name.clone(),
            site,
            health,
        });
    }
    (name, Ok(rows))
}

// The live block maps each slot to its targets, so only the active slot is reported.
pub fn live_for(live: &Option<serde_json::Value>, site: &Site) -> Vec<(String, String)> {
    let slot = site.active.as_str();
    live.as_ref()
        .and_then(|l| l.get(slot))
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .map(|e| {
                    let text =
                        |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    (text("addr"), text("status"))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl Console {
    pub fn load_sites(&mut self, cx: &mut Context<Self>) {
        self.sites.data = Load::Loading;
        let handles = self.selected_handles();
        let total = handles.len();
        let fut = async move {
            let results = join_all(handles.into_iter().map(node_rows).collect()).await;
            let (mut rows, mut failed, mut first_err) = (Vec::new(), Vec::new(), None);
            for (name, res) in results.into_iter().flatten() {
                match res {
                    Ok(r) => rows.extend(r),
                    Err(e) => {
                        first_err.get_or_insert(e);
                        failed.push(name);
                    }
                }
            }
            if total > 0 && failed.len() == total {
                return Err(cite_client::ClientError::Config(
                    first_err.unwrap_or_default(),
                ));
            }
            Ok(Data { rows, failed })
        };
        self.fetch(cx, fut, |this, res, cx| {
            this.sites.data = Load::from_result(res);
            cx.notify();
        });
    }

    pub fn render_sites(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let subtitle = match &self.selected {
            Some(n) => format!("Sites on {n}"),
            None => "Every site on every node".to_string(),
        };
        let create = btn(id("sites", "new"), "Create site", BtnKind::Primary)
            .on_click(cx.listener(|this, _, _, cx| this.navigate(View::SiteNew, cx)));
        let header = page_header("Sites", &subtitle, vec![create.into_any_element()]);
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        match &self.sites.data {
            Load::Idle | Load::Loading => col = col.child(skeleton(60.)).child(skeleton(220.)),
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                if !data.failed.is_empty() {
                    col = col.child(notice(
                        &format!("Could not load sites from {}.", data.failed.join(", ")),
                        Tone::Warn,
                    ));
                }
                col = col.child(div().w(px(360.)).child(self.sites.filter.clone()));
                col = col.child(self.sites_table(data, cx));
            }
        }
        col.into_any_element()
    }

    fn sites_table(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let needle = self.sites.filter.read(cx).text().to_string();
        let show_node = self.selected.is_none();
        let rows: Vec<Vec<AnyElement>> = data
            .rows
            .iter()
            .filter(|r| matches_filter(r, &needle))
            .map(|r| {
                let (node, site_id) = (r.node.clone(), r.site.id.clone());
                let hosts = r
                    .site
                    .hosts
                    .iter()
                    .take(2)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let extra = r.site.hosts.len().saturating_sub(2);
                let hosts = if extra > 0 {
                    format!("{hosts} +{extra}")
                } else {
                    hosts
                };
                let dots = if r.health.is_empty() {
                    text_dim("no data").into_any_element()
                } else {
                    div()
                        .flex()
                        .gap(px(4.))
                        .children(r.health.iter().map(|(_, s)| dot(health_tone(s))))
                        .into_any_element()
                };
                let state = if r.site.maintenance.enabled {
                    pill("Maintenance", Tone::Warn)
                } else {
                    pill("Serving", Tone::Ok)
                };
                let kind = pill(
                    if r.site.kind == SiteKind::Api {
                        "API"
                    } else {
                        "Site"
                    },
                    Tone::Muted,
                );
                let open = btn(
                    id("open-site", format!("{}-{}", r.node, r.site.id)),
                    "Open",
                    BtnKind::Plain,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.navigate(
                        View::SiteDetail {
                            node: node.clone(),
                            id: site_id.clone(),
                        },
                        cx,
                    );
                }));
                let mut cells = vec![
                    div()
                        .flex()
                        .flex_col()
                        .child(strong(r.site.name.clone()))
                        .child(mono(r.site.id.clone()).text_color(c(DIM)))
                        .into_any_element(),
                ];
                if show_node {
                    cells.push(mono(r.node.clone()).into_any_element());
                }
                cells.extend([
                    kind.into_any_element(),
                    div().text_size(px(12.)).child(hosts).into_any_element(),
                    slot_pill(r.site.active),
                    dots,
                    state.into_any_element(),
                    open.into_any_element(),
                ]);
                cells
            })
            .collect();
        let mut cols = vec![Col::flex("Site")];
        if show_node {
            cols.push(Col::fixed("Node", 110.));
        }
        cols.extend([
            Col::fixed("Kind", 70.),
            Col::flex("Hosts"),
            Col::fixed("Active", 80.),
            Col::fixed("Health", 90.),
            Col::fixed("State", 110.),
            Col::fixed("", 80.),
        ]);
        let empty = if data.rows.is_empty() {
            empty_state(
                "No sites yet",
                "Create a site to route a host to a blue/green pair of upstreams.",
            )
        } else {
            empty_state("No sites match", "Try a different name or host.")
        };
        card(None, None, table(&cols, rows, Some(empty))).into_any_element()
    }
}
