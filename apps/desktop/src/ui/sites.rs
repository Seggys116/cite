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
    // True until the health pass has answered, so a dot that has not arrived is not read as "no data".
    pub health_pending: bool,
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

// Rows come from the list route alone; health arrives afterwards from one stats call per node.
async fn node_rows(h: NodeHandle) -> (String, Result<Vec<Row>, String>) {
    let name = h.name().to_string();
    match h.list_sites().await {
        Ok(sites) => {
            let rows = sites
                .into_iter()
                .map(|site| Row {
                    node: name.clone(),
                    site,
                    health: Vec::new(),
                })
                .collect();
            (name, Ok(rows))
        }
        Err(e) => (name, Err(e.to_string())),
    }
}

// The stats list every backend as be_<site>_<slot>; only the active slot's servers are reported, as (server, status).
pub fn health_from_stats(stats: &serde_json::Value, site: &Site) -> Vec<(String, String)> {
    let want = format!("be_{}_{}", site.id, site.active.as_str());
    let text = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    stats
        .get("backends")
        .and_then(serde_json::Value::as_array)
        .and_then(|list| list.iter().find(|b| text(b, "name") == want))
        .and_then(|b| b.get("servers"))
        .and_then(serde_json::Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .map(|s| (text(s, "name"), text(s, "status")))
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
            Ok(Data {
                rows,
                failed,
                health_pending: true,
            })
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            let loaded = res.is_ok();
            this.sites.data = Load::from_result(res);
            cx.notify();
            if loaded {
                this.load_site_health(cx);
            }
        });
    }

    // One stats call per node fills in every health dot; the table is already on screen by then.
    fn load_site_health(&mut self, cx: &mut Context<Self>) {
        let handles = self.selected_handles();
        let fut = async move {
            let all = join_all(
                handles
                    .into_iter()
                    .map(|h| async move { (h.name().to_string(), h.haproxy_stats().await.ok()) })
                    .collect(),
            )
            .await;
            Ok::<_, cite_client::ClientError>(all.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            if let (Load::Ready(data), Ok(stats)) = (&mut this.sites.data, res) {
                for row in &mut data.rows {
                    let found = stats.iter().find(|(n, _)| *n == row.node);
                    if let Some((_, Some(s))) = found {
                        row.health = health_from_stats(s, &row.site);
                    }
                }
                data.health_pending = false;
            }
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
                    text_dim(if data.health_pending {
                        "checking"
                    } else {
                        "no data"
                    })
                    .into_any_element()
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

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::Slot;
    use serde_json::json;

    fn site(id: &str, active: Slot) -> Site {
        Site {
            id: id.into(),
            name: id.into(),
            hosts: Vec::new(),
            path_prefixes: Vec::new(),
            path_regexes: Vec::new(),
            kind: SiteKind::Site,
            blue: Default::default(),
            green: Default::default(),
            active,
            maintenance: Default::default(),
            health: Default::default(),
            source: None,
            history: Vec::new(),
            access: Default::default(),
        }
    }

    #[test]
    fn health_dots_come_from_the_active_slots_backend() {
        let stats = json!({"backends": [
            {"name": "be_shop_blue", "servers": [{"name": "t1", "status": "UP"}, {"name": "t2", "status": "DOWN"}]},
            {"name": "be_shop_green", "servers": [{"name": "t1", "status": "MAINT"}]},
            {"name": "be_shop-2_blue", "servers": [{"name": "t1", "status": "UP"}]},
        ]});
        let blue = health_from_stats(&stats, &site("shop", Slot::Blue));
        assert_eq!(
            blue,
            vec![
                ("t1".to_string(), "UP".to_string()),
                ("t2".to_string(), "DOWN".to_string())
            ]
        );
        let green = health_from_stats(&stats, &site("shop", Slot::Green));
        assert_eq!(green.len(), 1);
        assert_eq!(green[0].1, "MAINT");
        assert!(health_from_stats(&stats, &site("other", Slot::Blue)).is_empty());
        assert!(health_from_stats(&json!({}), &site("shop", Slot::Blue)).is_empty());
        let bare = json!({"backends": [{"name": "be_shop_blue"}]});
        assert!(health_from_stats(&bare, &site("shop", Slot::Blue)).is_empty());
    }
}
