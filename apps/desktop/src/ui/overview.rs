use cite_edge::model::{DeployAction, Slot};
use gpui::{AnyElement, Context, div, prelude::*, px};

use crate::api::{NodeHandle, join_all};
use crate::app::{Console, Load, View};
use crate::demo::now_ms;
use crate::model::{
    NodeSnapshot, OVERVIEW_WINDOW_MINUTES, aggregate, fmt_int, fmt_num, fmt_pct, fmt_uptime,
    parse_rfc3339_ms, read_info, rel_time,
};
use crate::theme::{BORDER, DIM, GREEN, MONO, Tone, c};
use crate::ui::chart::{STAT_MIN, clip_tip, spark, wide};
use crate::ui::widgets::{
    BtnKind, Col, btn, card, empty_state, grid, grid_min, id, mono, page_header, pill,
    section_title, skeleton, stat, table, text_dim,
};

pub struct DeployRow {
    pub at_ms: i64,
    pub node: String,
    pub site: String,
    pub action: DeployAction,
    pub slot: Slot,
    pub note: String,
}

pub struct Data {
    pub snaps: Vec<NodeSnapshot>,
    pub deploys: Vec<DeployRow>,
}

#[derive(Default)]
pub struct State {
    pub data: Option<Load<Data>>,
}

// One node's failure degrades to an offline card instead of failing the page.
async fn collect(h: NodeHandle) -> (NodeSnapshot, Vec<DeployRow>) {
    let name = h.name().to_string();
    let info = match h.node_info().await {
        Ok(i) => i,
        Err(e) => return (offline(&name, e.to_string()), Vec::new()),
    };
    let view = read_info(&info);
    let (summary, series, sites) = tokio::join!(h.summary("15m"), h.series("1h"), h.list_sites());
    let (summary, series, sites) = (summary.ok(), series.ok(), sites.unwrap_or_default());
    let deploys = sites
        .iter()
        .flat_map(|s| {
            s.history.iter().map(|d| DeployRow {
                at_ms: parse_rfc3339_ms(&d.at).unwrap_or(0),
                node: name.clone(),
                site: s.name.clone(),
                action: d.action,
                slot: d.slot,
                note: d.note.clone(),
            })
        })
        .collect();
    let snap = NodeSnapshot {
        name,
        online: true,
        error: String::new(),
        version: info.version.clone(),
        uptime_secs: view.uptime_secs,
        sites: sites.len().max(view.sites),
        rules: view.rules,
        haproxy: view.haproxy,
        summary,
        series,
    };
    (snap, deploys)
}

fn offline(name: &str, error: String) -> NodeSnapshot {
    NodeSnapshot {
        name: name.to_string(),
        online: false,
        error,
        version: String::new(),
        uptime_secs: 0,
        sites: 0,
        rules: 0,
        haproxy: None,
        summary: None,
        series: None,
    }
}

pub fn action_pill(action: DeployAction) -> AnyElement {
    let (text, tone) = match action {
        DeployAction::Promote => ("Promote", Tone::Ok),
        DeployAction::Rollback => ("Rollback", Tone::Warn),
        DeployAction::Switch => ("Switch", Tone::Info),
        DeployAction::Failed => ("Failed", Tone::Bad),
    };
    pill(text, tone).into_any_element()
}

pub fn slot_pill(slot: Slot) -> AnyElement {
    match slot {
        Slot::Blue => pill("blue", Tone::Blue),
        Slot::Green => pill("green", Tone::Green),
    }
    .into_any_element()
}

impl Console {
    // Nodes without a usable client are shown offline with the reason.
    pub fn load_overview(&mut self, cx: &mut Context<Self>) {
        self.overview.data = Some(Load::Loading);
        let handles = self.handles.clone();
        let missing: Vec<(String, String)> = self
            .connect_errors
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let order = self.node_names();
        let fut = async move {
            let results = join_all(handles.into_iter().map(collect).collect()).await;
            let mut snaps = Vec::new();
            let mut deploys = Vec::new();
            for (snap, dep) in results.into_iter().flatten() {
                snaps.push(snap);
                deploys.extend(dep);
            }
            for (name, err) in missing {
                snaps.push(offline(&name, err));
            }
            snaps.sort_by_key(|s| {
                order
                    .iter()
                    .position(|n| *n == s.name)
                    .unwrap_or(usize::MAX)
            });
            deploys.sort_by_key(|d| std::cmp::Reverse(d.at_ms));
            deploys.truncate(8);
            Ok(Data { snaps, deploys })
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.overview.data = Some(Load::from_result(res));
            cx.notify();
        });
    }

    pub fn render_overview(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let header = page_header(
            "Overview",
            "Health and traffic across every connected node",
            Vec::new(),
        );
        let body: AnyElement = match &self.overview.data {
            None | Some(Load::Idle | Load::Loading) => div()
                .flex()
                .flex_col()
                .gap(px(16.))
                .child(skeleton(86.))
                .child(skeleton(170.))
                .child(skeleton(200.))
                .into_any_element(),
            Some(Load::Failed(msg)) => {
                let msg = msg.clone();
                self.error_block(cx, &msg)
            }
            Some(Load::Ready(data)) if data.snaps.is_empty() => self.no_nodes_block(cx),
            Some(Load::Ready(data)) => overview_body(data, cx),
        };
        div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(header)
            .child(body)
            .into_any_element()
    }
}

// Totals count only online nodes so a dead node cannot skew the rates.
fn overview_body(data: &Data, cx: &mut Context<Console>) -> AnyElement {
    let t = aggregate(&data.snaps, OVERVIEW_WINDOW_MINUTES);
    let all_up = t.nodes_online == t.nodes_total;
    let rate_tone = if t.error_rate > 0.05 {
        Tone::Bad
    } else {
        Tone::Muted
    };
    let tiles = vec![
        stat(
            "Nodes online",
            format!("{}/{}", t.nodes_online, t.nodes_total),
            if all_up {
                "All nodes reachable".into()
            } else {
                format!("{} unreachable", t.nodes_total - t.nodes_online)
            },
            if all_up { Tone::Muted } else { Tone::Warn },
        ),
        stat(
            "Sites",
            fmt_int(t.sites as u64),
            "Across all nodes".into(),
            Tone::Muted,
        ),
        stat(
            "Requests / min",
            fmt_num(t.req_per_min.round() as u64),
            "Averaged over 15 minutes".into(),
            Tone::Muted,
        ),
        stat(
            "Error rate",
            fmt_pct(t.error_rate, 2),
            format!("{} 4xx and 5xx responses", fmt_int(t.errors)),
            rate_tone,
        ),
        stat(
            "Blocked",
            fmt_num(t.blocked),
            "Stopped by the firewall".into(),
            Tone::Muted,
        ),
    ];
    let stats = grid_min(
        STAT_MIN,
        tiles
            .into_iter()
            .map(|t| t.min_w_0().h_full().into_any_element())
            .collect(),
    );
    let cards = grid(
        data.snaps.iter().map(|snap| node_card(snap, cx)).collect(),
    );
    let rows: Vec<Vec<AnyElement>> = data
        .deploys
        .iter()
        .enumerate()
        .map(|(i, d)| {
            vec![
                text_dim(rel_time(now_ms(), d.at_ms)).into_any_element(),
                clip_tip(id("ov-dep-node", i), d.node.clone())
                    .font_family(MONO)
                    .text_size(px(12.))
                    .into_any_element(),
                clip_tip(id("ov-dep-site", i), d.site.clone()).into_any_element(),
                action_pill(d.action),
                slot_pill(d.slot),
                clip_tip(
                    id("ov-dep-note", i),
                    if d.note.is_empty() {
                        "-".to_string()
                    } else {
                        d.note.clone()
                    },
                )
                .text_color(c(DIM))
                .into_any_element(),
            ]
        })
        .collect();
    let cols = [
        Col::fixed("When", 90.),
        Col::fixed("Node", 110.),
        Col::flex("Site"),
        Col::fixed("Action", 90.),
        Col::fixed("Slot", 70.),
        Col::flex("Note"),
    ];
    let recent = card(
        Some("Recent deployments"),
        Some("Latest activity across nodes"),
        wide(
            id("ov", "deploys"),
            620.,
            table(
                &cols,
                rows,
                Some(empty_state(
                    "No deployments yet",
                    "Deploys, switches and rollbacks are listed here.",
                )),
            ),
        ),
    );
    div()
        .flex()
        .flex_col()
        .gap(px(16.))
        .child(stats)
        .child(section_title("Node health"))
        .child(cards)
        .child(recent)
        .into_any_element()
}

// The sparkline shows the last hour of request counts.
fn node_card(snap: &NodeSnapshot, cx: &mut Context<Console>) -> AnyElement {
    let name = snap.name.clone();
    let (tone, label) = if snap.online {
        (Tone::Ok, "Online")
    } else {
        (Tone::Bad, "Offline")
    };
    let version = if snap.version.is_empty() {
        "version unknown".to_string()
    } else {
        format!("v{}", snap.version)
    };
    let head = div()
        .flex()
        .items_center()
        .justify_between()
        .gap(px(12.))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .child(
                    clip_tip(id("ov-node-name", &name), snap.name.clone())
                        .font_weight(gpui::FontWeight::SEMIBOLD),
                )
                .child(mono(version).text_color(c(DIM))),
        )
        .child(pill(label, tone));
    let body: AnyElement = if snap.online {
        let metric = |label: &str, value: AnyElement| {
            div()
                .flex()
                .flex_col()
                .gap(px(2.))
                .child(text_dim(label.to_string()).text_size(px(11.)))
                .child(value)
        };
        let haproxy = match snap.haproxy {
            Some(true) => pill("running", Tone::Ok),
            Some(false) => pill("stopped", Tone::Bad),
            None => pill("unknown", Tone::Muted),
        };
        let points: Vec<u64> = snap
            .series
            .as_ref()
            .map(|s| s.points.iter().map(|p| p.requests).collect())
            .unwrap_or_default();
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_x(px(22.))
                    .gap_y(px(10.))
                    .child(metric(
                        "Uptime",
                        mono(fmt_uptime(snap.uptime_secs)).into_any_element(),
                    ))
                    .child(metric(
                        "Sites",
                        mono(snap.sites.to_string()).into_any_element(),
                    ))
                    .child(metric(
                        "Rules",
                        mono(snap.rules.to_string()).into_any_element(),
                    ))
                    .child(metric("HAProxy", haproxy.into_any_element())),
            )
            .child(spark(points, GREEN))
            .child(text_dim("requests, last hour").text_size(px(11.)))
            .into_any_element()
    } else {
        text_dim(if snap.error.is_empty() {
            "The connector did not respond.".to_string()
        } else {
            snap.error.clone()
        })
        .text_size(px(12.))
        .min_w_0()
        .into_any_element()
    };
    let open = btn(id("open-sites", &name), "Open sites", BtnKind::Plain).on_click(cx.listener(
        move |this, _, _, cx| {
            this.set_node(Some(name.clone()), cx);
            this.navigate(View::Sites, cx);
        },
    ));
    div()
        .flex()
        .flex_col()
        .gap(px(12.))
        .w_full()
        .h_full()
        .min_w_0()
        .p(px(16.))
        .rounded(px(crate::theme::CARD_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(crate::theme::SURFACE))
        .child(head)
        .child(body)
        .child(div().flex().child(open))
        .into_any_element()
}
