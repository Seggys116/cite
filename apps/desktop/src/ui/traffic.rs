use cite_edge::analytics::{Summary, Timeseries, TopItem};
use cite_edge::model::LogEvent;
use gpui::{AnyElement, Context, div, prelude::*, px};

use crate::api::join_all;
use crate::app::{Console, Load};
use crate::model::{
    WINDOWS, fmt_bytes, fmt_clock, fmt_int, fmt_ms, fmt_num, fmt_pct, merge_series,
    merge_summaries, per_bucket_sizes,
};
use crate::theme::{ACCENT, BLUE, DIM, GREEN, Tone, YELLOW, c};
use crate::ui::chart::{Line, hbar, line_chart};
use crate::ui::widgets::{
    Col, card, clip, dot, empty_state, id, mono, page_header, pill, seg_item, seg_row, skeleton,
    stat, table, text_dim, tone_for_status,
};

const RECENT_LIMIT: usize = 30;

pub struct Data {
    pub summary: Summary,
    pub series: Timeseries,
    pub recent: Vec<LogEvent>,
}

pub struct State {
    pub window: usize,
    pub data: Load<Data>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            window: 1,
            data: Load::Idle,
        }
    }
}

impl Console {
    // Per-node results are merged so All nodes shows one combined picture.
    pub fn load_traffic(&mut self, cx: &mut Context<Self>) {
        self.traffic.data = Load::Loading;
        let handles = self.selected_handles();
        let window = WINDOWS[self.traffic.window];
        let fut = async move {
            let one = |h: crate::api::NodeHandle| async move {
                let summary = h.summary(window).await?;
                let series = h.series(window).await?;
                let recent = h.requests(window, RECENT_LIMIT).await?;
                Ok::<_, cite_client::ClientError>((summary, series, recent))
            };
            let results = join_all(handles.into_iter().map(one).collect()).await;
            let mut parts = Vec::new();
            let mut first_err = None;
            for r in results.into_iter().flatten() {
                match r {
                    Ok(p) => parts.push(p),
                    Err(e) => {
                        first_err.get_or_insert(e);
                    }
                }
            }
            if parts.is_empty() {
                return Err(first_err.unwrap_or_else(|| {
                    cite_client::ClientError::Config("no nodes are connected".into())
                }));
            }
            let summary = merge_summaries(&parts.iter().map(|p| p.0.clone()).collect::<Vec<_>>());
            let series = merge_series(&parts.iter().map(|p| p.1.clone()).collect::<Vec<_>>());
            let mut recent: Vec<LogEvent> = parts.into_iter().flat_map(|p| p.2).collect();
            recent.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
            recent.truncate(RECENT_LIMIT);
            Ok(Data {
                summary,
                series,
                recent,
            })
        };
        self.fetch(cx, fut, |this, res, cx| {
            this.traffic.data = Load::from_result(res);
            cx.notify();
        });
    }

    // Only the recent list refreshes on the timer; the aggregates stay put.
    pub fn refresh_recent(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.traffic.data, Load::Ready(_)) {
            return;
        }
        let handles = self.selected_handles();
        let window = WINDOWS[self.traffic.window];
        let fut = async move {
            let results = join_all(
                handles
                    .into_iter()
                    .map(|h| async move { h.requests(window, RECENT_LIMIT).await })
                    .collect(),
            )
            .await;
            let mut recent: Vec<LogEvent> = results
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .flatten()
                .collect();
            recent.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));
            recent.truncate(RECENT_LIMIT);
            Ok(recent)
        };
        self.fetch(cx, fut, |this, res, cx| {
            if let (Ok(recent), Load::Ready(data)) = (res, &mut this.traffic.data) {
                data.recent = recent;
                cx.notify();
            }
        });
    }

    pub fn render_traffic(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut items = Vec::new();
        for (i, w) in WINDOWS.iter().enumerate() {
            items.push(
                seg_item(id("window", w), w, i == self.traffic.window)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.traffic.window = i;
                        this.load_traffic(cx);
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let subtitle = match &self.selected {
            Some(n) => format!("Requests handled by {n}"),
            None => "Requests handled by every node".to_string(),
        };
        let header = page_header(
            "Traffic",
            &subtitle,
            vec![seg_row(items).into_any_element()],
        );
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        match &self.traffic.data {
            Load::Idle | Load::Loading => {
                col = col
                    .child(skeleton(86.))
                    .child(skeleton(240.))
                    .child(skeleton(180.))
            }
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => col = col.child(traffic_body(data, WINDOWS[self.traffic.window])),
        }
        col.into_any_element()
    }
}

// Top lists show six rows to keep the cards level.
fn top_table(items: &[TopItem], with_bytes: bool) -> AnyElement {
    let rows: Vec<Vec<AnyElement>> = items
        .iter()
        .take(6)
        .map(|t| {
            let mut cells = vec![
                clip(t.key.clone())
                    .font_family(crate::theme::MONO)
                    .text_size(px(12.))
                    .into_any_element(),
                mono(fmt_int(t.count)).into_any_element(),
            ];
            if with_bytes {
                cells.push(
                    mono(fmt_bytes(t.bytes))
                        .text_color(c(DIM))
                        .into_any_element(),
                );
            }
            cells
        })
        .collect();
    let mut cols = vec![Col::flex("Key"), Col::fixed("Requests", 80.).right()];
    if with_bytes {
        cols.push(Col::fixed("Bytes", 80.).right());
    }
    table(
        &cols,
        rows,
        Some(text_dim("Nothing recorded in this window.").p(px(12.))),
    )
    .into_any_element()
}

// Error and blocked lines share the request scale so their size reads honestly.
fn traffic_body(data: &Data, window: &str) -> AnyElement {
    let sm = &data.summary;
    let errors = sm.errors_4xx + sm.errors_5xx;
    let stats = div()
        .flex()
        .flex_wrap()
        .gap(px(12.))
        .child(stat(
            "Requests",
            fmt_num(sm.requests),
            format!("{} in this window", fmt_int(sm.requests)),
            Tone::Muted,
        ))
        .child(stat(
            "Bandwidth out",
            fmt_bytes(sm.bytes_out),
            format!("{} received", fmt_bytes(sm.bytes_in)),
            Tone::Muted,
        ))
        .child(stat(
            "Errors",
            fmt_num(errors),
            if sm.requests > 0 {
                format!(
                    "{} of requests",
                    fmt_pct(errors as f64 / sm.requests as f64, 2)
                )
            } else {
                "no traffic".into()
            },
            if errors * 20 > sm.requests && sm.requests > 0 {
                Tone::Bad
            } else {
                Tone::Muted
            },
        ))
        .child(stat(
            "Blocked",
            fmt_num(sm.blocked),
            "stopped by the firewall".into(),
            Tone::Muted,
        ));
    let pts = &data.series.points;
    let legend = div()
        .flex()
        .gap(px(14.))
        .text_size(px(12.))
        .child(legend_item("Requests", BLUE))
        .child(legend_item("Errors", ACCENT))
        .child(legend_item("Blocked", YELLOW));
    let chart = line_chart(
        vec![
            Line {
                values: pts.iter().map(|p| p.requests).collect(),
                color: BLUE,
                area: true,
            },
            Line {
                values: pts.iter().map(|p| p.errors).collect(),
                color: ACCENT,
                area: false,
            },
            Line {
                values: pts.iter().map(|p| p.blocked).collect(),
                color: YELLOW,
                area: false,
            },
        ],
        190.,
        true,
    );
    let axis = div()
        .flex()
        .justify_between()
        .text_size(px(11.))
        .text_color(c(DIM))
        .child(match pts.first() {
            Some(p) if window == "15m" || window == "1h" || window == "24h" => {
                format!("{} UTC", fmt_clock(p.ts * 1000))
            }
            _ => format!("{window} ago"),
        })
        .child("now");
    let series_card = card(
        Some("Requests over time"),
        Some(&format!("{} second buckets", data.series.step_secs)),
        div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .child(legend)
            .child(chart)
            .child(axis),
    );
    let total_status: u64 = sm.status.values().sum();
    let mut status = div().flex().flex_col().gap(px(10.));
    for class in ["2xx", "3xx", "4xx", "5xx"] {
        let n = sm.status.get(class).copied().unwrap_or(0);
        let color = match class {
            "2xx" => GREEN,
            "3xx" => BLUE,
            "4xx" => YELLOW,
            _ => ACCENT,
        };
        let share = if total_status == 0 {
            0.0
        } else {
            n as f64 / total_status as f64
        };
        status = status.child(hbar(class, n, total_status, color, fmt_pct(share, 1)));
    }
    let latency_max = sm.p99_ms.max(1);
    let mut latency = div().flex().flex_col().gap(px(10.));
    for (label, v) in [
        ("Average", sm.avg_ms),
        ("p50", sm.p50_ms as f64),
        ("p95", sm.p95_ms as f64),
        ("p99", sm.p99_ms as f64),
    ] {
        latency = latency.child(hbar(label, v as u64, latency_max, BLUE, fmt_ms(v)));
    }
    let sizes = per_bucket_sizes(&sm.sizes);
    let sizes_max = sizes.iter().map(|b| b.count).max().unwrap_or(0).max(1);
    let mut size_bars = div().flex().flex_col().gap(px(10.));
    for b in &sizes {
        let label = b.le.map_or_else(
            || "larger".to_string(),
            |le| format!("up to {}", fmt_bytes(le)),
        );
        size_bars = size_bars.child(hbar(&label, b.count, sizes_max, BLUE, fmt_int(b.count)));
    }
    let half = |card: gpui::Div| card.flex_1().min_w(px(300.));
    let row_a = div()
        .flex()
        .flex_wrap()
        .gap(px(16.))
        .child(half(card(Some("Status classes"), None, status)))
        .child(half(card(
            Some("Latency"),
            Some("Total time per request"),
            latency,
        )))
        .child(half(card(Some("Response sizes"), None, size_bars)));
    let row_b = div()
        .flex()
        .flex_wrap()
        .gap(px(16.))
        .child(half(card(
            Some("Top paths"),
            None,
            top_table(&sm.top_paths, true),
        )))
        .child(half(card(
            Some("Top client IPs"),
            None,
            top_table(&sm.top_ips, false),
        )))
        .child(half(card(
            Some("Top user agents"),
            None,
            top_table(&sm.top_user_agents, false),
        )));
    div()
        .flex()
        .flex_col()
        .gap(px(16.))
        .child(stats)
        .child(series_card)
        .child(row_a)
        .child(row_b)
        .child(recent_card(&data.recent))
        .into_any_element()
}

fn legend_item(label: &str, color: u32) -> AnyElement {
    div()
        .flex()
        .items_center()
        .gap(px(6.))
        .child(div().size(px(8.)).rounded_full().bg(c(color)))
        .child(text_dim(label.to_string()))
        .into_any_element()
}

// Rows are newest first and trimmed to the most recent thirty.
fn recent_card(events: &[LogEvent]) -> AnyElement {
    let rows: Vec<Vec<AnyElement>> = events
        .iter()
        .map(|e| {
            vec![
                mono(fmt_clock(e.ts_ms))
                    .text_color(c(DIM))
                    .into_any_element(),
                pill(&e.status.to_string(), tone_for_status(e.status)).into_any_element(),
                mono(e.method.clone()).into_any_element(),
                clip(e.path.clone())
                    .font_family(crate::theme::MONO)
                    .text_size(px(12.))
                    .into_any_element(),
                clip(e.host.clone())
                    .text_size(px(12.))
                    .text_color(c(DIM))
                    .into_any_element(),
                mono(e.client_ip.clone())
                    .text_color(c(DIM))
                    .into_any_element(),
                mono(format!("{} ms", e.total_ms)).into_any_element(),
                match &e.blocked {
                    Some(_) => pill("blocked", Tone::Bad).into_any_element(),
                    None => div().into_any_element(),
                },
            ]
        })
        .collect();
    let cols = [
        Col::fixed("Time", 80.),
        Col::fixed("Status", 70.),
        Col::fixed("Method", 70.),
        Col::flex("Path"),
        Col::fixed("Host", 150.),
        Col::fixed("Client", 130.),
        Col::fixed("Time", 80.),
        Col::fixed("", 80.),
    ];
    let live = div()
        .flex()
        .items_center()
        .gap(px(6.))
        .child(dot(Tone::Ok))
        .child(text_dim("Refreshing every 3 seconds").text_size(px(11.)));
    card(
        Some("Recent requests"),
        None,
        div().flex().flex_col().gap(px(8.)).child(live).child(table(
            &cols,
            rows,
            Some(empty_state(
                "No requests yet",
                "Requests appear here as they arrive.",
            )),
        )),
    )
    .into_any_element()
}
