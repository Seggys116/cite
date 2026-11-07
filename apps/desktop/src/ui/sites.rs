use cite_edge::model::{DeployAction, Site, SiteKind};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, join_all};
use crate::app::{Console, Load, View, new_input};
use crate::demo::now_ms;
use crate::model::{parse_rfc3339_ms, rel_time};
use crate::siteops::is_busy_phase;
use crate::theme::{BORDER, DIM, DIVIDER, MONO, Tone, c, tint};
use crate::ui::chart::{clip_tip, clip_tip_full, wide};
use crate::ui::input::TextInput;
use crate::ui::overview::slot_pill;
use crate::ui::widgets::{
    BtnKind, Col, btn, card, dot, empty_state, id, notice, page_header, pill, skeleton, text_dim,
};

pub struct Row {
    pub node: String,
    pub site: Site,
    pub health: Vec<(String, String)>,
    // Build phase from the site status, fetched only for source-built sites.
    pub phase: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteState {
    Building,
    Redeploying,
    Failed,
    Maintenance,
    Down,
    Serving,
}

impl SiteState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Building => "Building",
            Self::Redeploying => "Redeploying",
            Self::Failed => "Failed",
            Self::Maintenance => "Maintenance",
            Self::Down => "Down",
            Self::Serving => "Serving",
        }
    }

    pub fn tone(self) -> Tone {
        match self {
            Self::Building | Self::Redeploying => Tone::Info,
            Self::Failed | Self::Down => Tone::Bad,
            Self::Maintenance => Tone::Warn,
            Self::Serving => Tone::Ok,
        }
    }

    pub fn pill(self) -> gpui::Div {
        pill(self.label(), self.tone())
    }
}

// A running build wins, then maintenance, the node's own failed phase, red health and finally a failed last deploy.
pub fn site_state(site: &Site, health: &[(String, String)], phase: Option<&str>) -> SiteState {
    let last_failed = last_deploy(site).is_some_and(|(a, _)| a == DeployAction::Failed);
    if phase.is_some_and(is_busy_phase) {
        let served_before = site.history.iter().any(|d| d.action != DeployAction::Failed);
        return if served_before {
            SiteState::Redeploying
        } else {
            SiteState::Building
        };
    }
    if site.maintenance.enabled {
        SiteState::Maintenance
    } else if phase == Some("failed") {
        SiteState::Failed
    } else if phase == Some("unhealthy")
        || (!health.is_empty() && health.iter().all(|(_, s)| health_tone(s) == Tone::Bad))
    {
        SiteState::Down
    } else if last_failed {
        SiteState::Failed
    } else {
        SiteState::Serving
    }
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
                    phase: None,
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
                this.load_site_phases(cx);
            }
        });
    }

    // One status call per source-built site, once per load; sites without a build never need it.
    fn load_site_phases(&mut self, cx: &mut Context<Self>) {
        let Load::Ready(data) = &self.sites.data else {
            return;
        };
        let jobs: Vec<(NodeHandle, String)> = data
            .rows
            .iter()
            .filter(|r| r.site.source.is_some())
            .filter_map(|r| Some((self.handle_named(&r.node)?, r.site.id.clone())))
            .collect();
        if jobs.is_empty() {
            return;
        }
        let fut = async move {
            let all = join_all(
                jobs.into_iter()
                    .map(|(h, site)| async move {
                        let phase = h.site_status(&site).await.ok().map(|s| s.phase);
                        (h.name().to_string(), site, phase)
                    })
                    .collect(),
            )
            .await;
            Ok::<_, cite_client::ClientError>(all.into_iter().flatten().collect::<Vec<_>>())
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            if let (Load::Ready(data), Ok(phases)) = (&mut this.sites.data, res) {
                for (node, site, phase) in phases {
                    if let Some(row) = data
                        .rows
                        .iter_mut()
                        .find(|r| r.node == node && r.site.id == site)
                    {
                        row.phase = phase;
                    }
                }
            }
            cx.notify();
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
                let needle = self.sites.filter.read(cx).text().to_string();
                let shown = data
                    .rows
                    .iter()
                    .filter(|r| matches_filter(r, &needle))
                    .count();
                let count = if shown == data.rows.len() {
                    format!("{} sites", data.rows.len())
                } else {
                    format!("{shown} of {} sites", data.rows.len())
                };
                col = col.child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(12.))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w_0()
                                .max_w(px(420.))
                                .child(self.sites.filter.clone()),
                        )
                        .child(text_dim(count).text_size(px(12.))),
                );
                col = col.child(self.sites_table(data, cx));
            }
        }
        col.into_any_element()
    }

    fn sites_table(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let needle = self.sites.filter.read(cx).text().to_string();
        let show_node = self.selected.is_none();
        let now = now_ms();
        let rows: Vec<Vec<AnyElement>> = data
            .rows
            .iter()
            .filter(|r| matches_filter(r, &needle))
            .map(|r| {
                let key = format!("{}-{}", r.node, r.site.id);
                let hosts = hosts_label(&r.site.hosts);
                let all_hosts = r.site.hosts.join(", ");
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
                        .flex_wrap()
                        .gap(px(4.))
                        .children(r.health.iter().map(|(_, s)| dot(health_tone(s))))
                        .into_any_element()
                };
                let state = site_state(&r.site, &r.health, r.phase.as_deref()).pill();
                let kind = pill(
                    if r.site.kind == SiteKind::Api {
                        "API"
                    } else {
                        "Site"
                    },
                    Tone::Muted,
                );
                let deploy = match last_deploy(&r.site) {
                    Some((_, at)) => text_dim(rel_time(now, at))
                        .text_size(px(12.))
                        .whitespace_nowrap()
                        .into_any_element(),
                    None => text_dim("never").text_size(px(12.)).into_any_element(),
                };
                let mut cells = vec![
                    div()
                        .flex()
                        .flex_col()
                        .min_w_0()
                        .child(
                            clip_tip(id("site-name", &key), r.site.name.clone())
                                .font_weight(gpui::FontWeight::SEMIBOLD),
                        )
                        .child(
                            clip_tip(id("site-id", &key), r.site.id.clone())
                                .font_family(MONO)
                                .text_size(px(11.))
                                .text_color(c(DIM)),
                        )
                        .into_any_element(),
                ];
                if show_node {
                    cells.push(
                        clip_tip(id("site-node", &key), r.node.clone())
                            .font_family(MONO)
                            .text_size(px(12.))
                            .into_any_element(),
                    );
                }
                cells.extend([
                    dots,
                    kind.into_any_element(),
                    clip_tip_full(id("site-hosts", &key), hosts, all_hosts)
                        .text_size(px(12.))
                        .into_any_element(),
                    slot_pill(r.site.active),
                    deploy,
                    state.into_any_element(),
                ]);
                cells
            })
            .collect();
        let targets: Vec<(String, String)> = data
            .rows
            .iter()
            .filter(|r| matches_filter(r, &needle))
            .map(|r| (r.node.clone(), r.site.id.clone()))
            .collect();
        let mut cols = vec![Col::flex("Site")];
        if show_node {
            cols.push(Col::fixed("Node", 110.));
        }
        cols.extend([
            Col::fixed("Health", 80.),
            Col::fixed("Kind", 64.),
            Col::flex("Hosts"),
            Col::fixed("Active", 76.),
            Col::fixed("Last deploy", 150.),
            Col::fixed("State", 110.),
        ]);
        let empty = if data.rows.is_empty() {
            empty_state(
                "No sites yet",
                "Create a site to build a GitHub repository or route a host to servers you run.",
            )
        } else {
            empty_state("No sites match", "Try a different name or host.")
        };
        let min_width = cols.iter().filter_map(|col| col.width).sum::<f32>() + 360.;
        let table = click_table(&cols, rows, targets, empty, cx);
        card(None, None, wide(id("sites", "table"), min_width, table)).into_any_element()
    }
}

// Shows up to two hosts and counts the rest, so the cell stays one line.
pub fn hosts_label(hosts: &[String]) -> String {
    if hosts.is_empty() {
        return "-".to_string();
    }
    let shown = hosts.iter().take(2).cloned().collect::<Vec<_>>().join(", ");
    match hosts.len().saturating_sub(2) {
        0 => shown,
        extra => format!("{shown} +{extra}"),
    }
}

// The newest entry of the site's deploy history by timestamp, whatever order the node returned.
pub fn last_deploy(site: &Site) -> Option<(DeployAction, i64)> {
    site.history
        .iter()
        .map(|d| (d.action, parse_rfc3339_ms(&d.at).unwrap_or(0)))
        .max_by_key(|(_, at)| *at)
}

// Same columns as the shared table, but every row is one click target that opens the site.
fn click_table(
    cols: &[Col],
    rows: Vec<Vec<AnyElement>>,
    targets: Vec<(String, String)>,
    empty: gpui::Div,
    cx: &mut Context<Console>,
) -> AnyElement {
    let cell = |col: &Col, child: AnyElement| {
        let base = div()
            .flex()
            .items_center()
            .min_w_0()
            .overflow_hidden()
            .px(px(6.));
        let sized = match col.width {
            Some(w) => base.w(px(w)).flex_none(),
            None => base.flex_1(),
        };
        sized.child(child)
    };
    let mut head = div()
        .flex()
        .px(px(10.))
        .py(px(8.))
        .border_b_1()
        .border_color(c(BORDER))
        .text_size(px(10.))
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(c(DIM));
    for col in cols {
        head = head.child(cell(col, col.label.to_uppercase().into_any_element()));
    }
    let mut root = div().flex().flex_col().w_full().child(head);
    if rows.is_empty() {
        return root.child(empty).into_any_element();
    }
    for (row, (node, site_id)) in rows.into_iter().zip(targets) {
        let mut line = div()
            .id(id("site-row", format!("{node}-{site_id}")))
            .flex()
            .items_center()
            .min_h(px(44.))
            .px(px(10.))
            .py(px(6.))
            .text_size(px(13.))
            .border_b_1()
            .border_color(c(DIVIDER))
            .cursor_pointer()
            .hover(|s| s.bg(tint(0xffffff, 0.035)))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.navigate(
                    View::SiteDetail {
                        node: node.clone(),
                        id: site_id.clone(),
                    },
                    cx,
                );
            }));
        for (col, child) in cols.iter().zip(row) {
            line = line.child(cell(col, child));
        }
        root = root.child(line);
    }
    root.into_any_element()
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
            volumes: Vec::new(),
            outbound: true,
            outbound_rules: Default::default(),
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

    #[test]
    fn hosts_label_shows_two_and_counts_the_rest() {
        let hosts = |list: &[&str]| list.iter().map(|h| h.to_string()).collect::<Vec<_>>();
        assert_eq!(hosts_label(&[]), "-");
        assert_eq!(hosts_label(&hosts(&["a.com"])), "a.com");
        assert_eq!(hosts_label(&hosts(&["a.com", "b.com"])), "a.com, b.com");
        assert_eq!(
            hosts_label(&hosts(&["a.com", "b.com", "c.com", "d.com"])),
            "a.com, b.com +2"
        );
    }

    #[test]
    fn site_state_follows_phase_maintenance_health_and_history() {
        use cite_edge::model::Deployment;
        let entry = |at: &str, action| Deployment {
            id: at.into(),
            at: at.into(),
            slot: Slot::Blue,
            action,
            note: String::new(),
        };
        let health = |s: &[&str]| -> Vec<(String, String)> {
            s.iter().map(|x| ("t".to_string(), x.to_string())).collect()
        };
        let mut s = site("shop", Slot::Blue);
        assert_eq!(site_state(&s, &[], None), SiteState::Serving);
        assert_eq!(site_state(&s, &health(&["UP"]), None), SiteState::Serving);
        assert_eq!(
            site_state(&s, &health(&["DOWN", "UP"]), None),
            SiteState::Serving
        );
        assert_eq!(
            site_state(&s, &health(&["DOWN", "DOWN"]), None),
            SiteState::Down
        );
        assert_eq!(site_state(&s, &[], Some("building")), SiteState::Building);
        assert_eq!(site_state(&s, &[], Some("idle")), SiteState::Serving);
        assert_eq!(site_state(&s, &[], Some("unhealthy")), SiteState::Down);
        assert_eq!(site_state(&s, &[], Some("failed")), SiteState::Failed);
        s.history = vec![entry("2026-11-02T10:00:00Z", DeployAction::Promote)];
        assert_eq!(
            site_state(&s, &[], Some("packing")),
            SiteState::Redeploying
        );
        s.history.push(entry("2026-11-03T10:00:00Z", DeployAction::Failed));
        assert_eq!(site_state(&s, &[], None), SiteState::Failed);
        s.maintenance.enabled = true;
        assert_eq!(site_state(&s, &[], None), SiteState::Maintenance);
        assert_eq!(
            site_state(&s, &[], Some("building")),
            SiteState::Redeploying
        );
        assert_eq!(SiteState::Building.tone(), Tone::Info);
        assert_eq!(SiteState::Maintenance.tone(), Tone::Warn);
        assert_eq!(SiteState::Serving.tone(), Tone::Ok);
    }

    #[test]
    fn last_deploy_is_the_newest_entry_regardless_of_order() {
        use cite_edge::model::{DeployAction, Deployment};
        let mut s = site("shop", Slot::Blue);
        assert!(last_deploy(&s).is_none());
        let entry = |at: &str, action| Deployment {
            id: at.into(),
            at: at.into(),
            slot: Slot::Blue,
            action,
            note: String::new(),
        };
        s.history = vec![
            entry("2026-11-02T10:00:00Z", DeployAction::Promote),
            entry("2026-11-05T09:00:00Z", DeployAction::Failed),
            entry("2026-11-01T08:00:00Z", DeployAction::Rollback),
        ];
        let (action, at) = last_deploy(&s).unwrap();
        assert_eq!(action, DeployAction::Failed);
        assert_eq!(Some(at), parse_rfc3339_ms("2026-11-05T09:00:00Z"));
    }
}
