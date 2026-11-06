use cite_edge::model::Slot;
use gpui::{AnyElement, ClipboardItem, Context, Entity, ScrollHandle, div, prelude::*, px};

use crate::app::{Console, View, new_input};
use crate::diagnose::default_log_slot;
use crate::siteops::{LogBuffer, LogLevel, clock, log_query};
use crate::theme::{BORDER, CARD_RADIUS, DIM, INPUT, Tone, c};
use crate::ui::detail::Data;
use crate::ui::input::TextInput;
use crate::ui::scroll::scroll_area_with;
use crate::ui::widgets::{BtnKind, btn, id, mono, seg_item, seg_row, text_dim, toggle};

// Most rows the viewer paints at once; the buffer behind it keeps more.
const SHOWN_LOG_ROWS: usize = 400;
const VIEWER_HEIGHT: f32 = 560.;

pub const SOURCES: [(&str, &str); 2] = [("manager", "Build"), ("executor", "Runtime")];

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
    pub scroll: ScrollHandle,
    // False until the viewer has opened once for this site, when it picks the slot of the latest failure.
    pub chosen: bool,
}

impl LogView {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            source: "manager",
            slot: Slot::Blue,
            follow: true,
            in_flight: false,
            generation: 0,
            buf: LogBuffer::default(),
            error: None,
            search: new_input(cx, "Search the log", |i| i),
            scroll: ScrollHandle::new(),
            chosen: false,
        }
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.in_flight = false;
        self.error = None;
        self.generation += 1;
        self.follow = true;
        self.source = "manager";
        self.slot = Slot::Blue;
        self.chosen = false;
    }
}

fn level_tag(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "ERR",
        LogLevel::Warn => "WRN",
        LogLevel::Info => "INF",
        LogLevel::Debug => "DBG",
        LogLevel::Other => "",
    }
}

// Rows the viewer paints: the newest that match, oldest first so the newest sit at the bottom.
pub fn window_start(matching: usize) -> usize {
    matching.saturating_sub(SHOWN_LOG_ROWS)
}

impl Console {
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
                            if this.ops.logs.follow {
                                this.ops.logs.scroll.scroll_to_bottom();
                            }
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
    pub(crate) fn switch_log_stream(
        &mut self,
        source: &'static str,
        slot: Slot,
        cx: &mut Context<Self>,
    ) {
        let logs = &mut self.ops.logs;
        logs.source = source;
        logs.slot = slot;
        logs.chosen = true;
        logs.buf.clear();
        logs.error = None;
        logs.in_flight = false;
        logs.generation += 1;
        self.poll_logs(cx);
    }

    // Runs whenever the Logs tab comes on screen: the first time it picks the failed slot, and it loads at once.
    pub(crate) fn open_logs(&mut self, cx: &mut Context<Self>) {
        if !self.ops.loaded {
            return;
        }
        if !self.ops.logs.chosen {
            let Some(data) = self.detail.data.ready() else {
                return;
            };
            let status_failure = self
                .ops
                .extras
                .status
                .as_ref()
                .and_then(|s| s.last_failure.as_ref())
                .and_then(|f| f.slot);
            let slot = default_log_slot(&data.site.history, status_failure, data.site.active);
            self.switch_log_stream("manager", slot, cx);
            return;
        }
        if self.ops.logs.buf.cursor().is_none() {
            self.poll_logs(cx);
        }
    }

    // The banner's and the save notice's action: the build log of the slot that failed.
    pub(crate) fn show_build_logs(&mut self, slot: Slot, cx: &mut Context<Self>) {
        self.remember_tab(super::tabs::SiteTab::Logs);
        self.ops.logs.follow = true;
        self.switch_log_stream("manager", slot, cx);
    }

    pub(crate) fn logs_panel(&self, _data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let logs = &self.ops.logs;
        let mut sources = Vec::new();
        for (source, label) in SOURCES {
            sources.push(
                seg_item(id("logs-source", source), label, logs.source == source)
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
        for row in &matching[window_start(total)..] {
            let tone = row.level.tone();
            let color = if tone == Tone::Muted {
                c(0xc8c8c8)
            } else {
                c(tone.color())
            };
            lines = lines.child(
                div()
                    .flex()
                    .gap(px(10.))
                    .child(
                        mono(clock(&row.ts))
                            .text_color(c(DIM))
                            .w(px(64.))
                            .flex_none(),
                    )
                    .child(
                        mono(level_tag(row.level))
                            .text_color(color)
                            .w(px(28.))
                            .flex_none(),
                    )
                    .child(mono(row.text.clone()).text_color(color).flex_1().min_w_0()),
            );
        }
        if total == 0 {
            let empty = if logs.in_flight || (logs.buf.cursor().is_none() && logs.error.is_none())
            {
                "Loading the log..."
            } else if needle.trim().is_empty() {
                "No log lines yet."
            } else {
                "No lines match the search."
            };
            lines = lines.child(text_dim(empty).text_size(px(12.)));
        }
        let follow =
            toggle(id("logs", "follow"), logs.follow).on_click(cx.listener(|this, _, _, cx| {
                this.ops.logs.follow = !this.ops.logs.follow;
                if this.ops.logs.follow {
                    this.ops.logs.scroll.scroll_to_bottom();
                }
                cx.notify();
            }));
        let refresh = btn(id("logs", "refresh"), "Refresh", BtnKind::Plain).on_click(cx.listener(
            |this, _, _, cx| {
                this.poll_logs(cx);
                cx.notify();
            },
        ));
        let copy = btn(id("logs", "copy"), "Copy", BtnKind::Plain).on_click(cx.listener(
            |this, _, _, cx| {
                let needle = this.ops.logs.search.read(cx).text().to_string();
                let text = this.ops.logs.buf.copy_text(&needle);
                cx.write_to_clipboard(ClipboardItem::new_string(text));
                this.say("Copied", Tone::Ok);
                cx.notify();
            },
        ));
        let count = if needle.trim().is_empty() {
            format!("{total} lines")
        } else {
            format!("{total} matching")
        };
        let toolbar = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(10.))
            .child(seg_row(sources))
            .child(seg_row(slots))
            .child(div().w(px(240.)).child(logs.search.clone()))
            .child(div().flex_1())
            .child(text_dim(count).text_size(px(11.)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .child(follow)
                    .child(text_dim("Follow").text_size(px(12.))),
            )
            .child(refresh)
            .child(copy);
        let mut col = div().flex().flex_col().gap(px(10.)).child(toolbar);
        if let Some(e) = &logs.error {
            col = col.child(
                text_dim(e.clone())
                    .text_size(px(12.))
                    .text_color(c(Tone::Bad.color())),
            );
        }
        if logs.buf.truncated() {
            col = col.child(text_dim("Older lines were cut by the node.").text_size(px(12.)));
        }
        let key = format!("log-lines-{}-{}", self.ops.for_site.0, self.ops.for_site.1);
        let viewer = scroll_area_with(key, &logs.scroll)
            .h(px(VIEWER_HEIGHT))
            .p(px(10.))
            .rounded(px(CARD_RADIUS))
            .border_1()
            .border_color(c(BORDER))
            .bg(c(INPUT))
            .child(lines);
        col.child(viewer)
            .child(
                text_dim(
                    "Build is the manager that fetches and builds the repository; Runtime is the running site. The last 5000 lines are kept.",
                )
                .text_size(px(11.)),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_viewer_paints_the_newest_rows() {
        assert_eq!(window_start(0), 0);
        assert_eq!(window_start(SHOWN_LOG_ROWS), 0);
        assert_eq!(window_start(SHOWN_LOG_ROWS + 25), 25);
        assert_eq!(level_tag(LogLevel::Error), "ERR");
        assert_eq!(level_tag(LogLevel::Other), "");
        assert_eq!(SOURCES[0].0, "manager");
    }
}
