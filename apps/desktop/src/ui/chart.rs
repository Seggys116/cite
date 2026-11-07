use std::cell::RefCell;
use std::collections::HashMap;

use gpui::{
    AnyElement, AnyView, App, Bounds, Div, ElementId, PathBuilder, Pixels, SharedString, Stateful,
    Window, canvas, div, fill, point, prelude::*, px, size,
};

use crate::model::{fmt_num, nice_max, scale_points};
use crate::theme::{BORDER, DIM, SURFACE_HI, TEXT, c, chip_stroke, tint};

// Width of the left gutter that holds the value labels of a gridded chart.
pub const Y_GUTTER: f32 = 44.0;
// Space one time label needs before the next one is allowed on the axis.
const X_LABEL_SPACE: f32 = 96.0;
// Narrowest a KPI tile may get before the tile grid drops a column.
pub const STAT_MIN: f32 = 160.0;
pub const FIELD_MIN: f32 = 220.0;
pub const PANE_MIN: f32 = 300.0;
// Fewest pixels per plotted point before neighbouring buckets are merged.
const PX_PER_POINT: f32 = 2.0;

pub struct Line {
    pub values: Vec<u64>,
    pub color: u32,
    pub area: bool,
}

thread_local! {
    static WIDTHS: RefCell<HashMap<SharedString, f32>> = RefCell::new(HashMap::new());
}

// The width a probe with this key saw on the last frame, if it has been laid out yet.
pub fn measured_width(key: &str) -> Option<f32> {
    WIDTHS.with(|m| m.borrow().get(key).copied())
}

// An invisible layer that fills its relative parent and redraws the view when that parent's width changes.
pub fn width_probe(key: impl Into<SharedString>) -> impl IntoElement {
    let key = key.into();
    canvas(
        move |bounds, window, _| {
            let w: f32 = bounds.size.width.into();
            let changed = WIDTHS.with(|m| {
                let prev = m.borrow_mut().insert(key.clone(), w);
                prev.is_none_or(|p| (p - w).abs() > 0.5)
            });
            if changed {
                window.request_animation_frame();
            }
        },
        |_, _, _, _| {},
    )
    .absolute()
    .top_0()
    .left_0()
    .size_full()
}

// The width used before the first measurement, so the first frame already looks like a desktop layout.
fn width_or_default(key: &str) -> f32 {
    measured_width(key).unwrap_or(960.0)
}

// True when the measured width is below the breakpoint, used to stack side-by-side panes.
pub fn narrower_than(key: &str, breakpoint: f32) -> bool {
    width_or_default(key) < breakpoint
}

// Two panes side by side, stacked when the measured width is below `breakpoint`.
pub fn split(key: &str, breakpoint: f32, gap: f32, left: AnyElement, right: AnyElement) -> Div {
    let stacked = narrower_than(key, breakpoint);
    let root = div()
        .relative()
        .w_full()
        .min_w_0()
        .flex()
        .gap(px(gap))
        .child(width_probe(key.to_string()));
    let pane = || div().flex().flex_col().flex_1().min_w_0();
    let row = || div().flex().flex_col().w_full().min_w_0();
    if stacked {
        root.flex_col()
            .child(row().child(left))
            .child(row().child(right))
    } else {
        root.child(pane().child(left)).child(pane().child(right))
    }
}

// Merges neighbouring buckets by their maximum so no more than `max_points` are drawn and peaks survive.
pub fn fit_series(values: &[u64], max_points: usize) -> Vec<u64> {
    let max_points = max_points.max(2);
    if values.len() <= max_points {
        return values.to_vec();
    }
    let n = values.len();
    (0..max_points)
        .map(|i| {
            let start = i * n / max_points;
            let end = ((i + 1) * n / max_points).max(start + 1);
            values[start..end].iter().copied().max().unwrap_or(0)
        })
        .collect()
}

// Indices of the labels an axis of `width` can show without overlap, always including both ends.
pub fn axis_ticks(points: usize, width: f32) -> Vec<usize> {
    if points == 0 {
        return Vec::new();
    }
    if points == 1 {
        return vec![0];
    }
    let room = ((width / X_LABEL_SPACE).floor() as usize).clamp(2, points);
    (0..room).map(|i| i * (points - 1) / (room - 1)).collect()
}

// The value labels of the y axis from top to bottom: ceiling, half and zero.
pub fn y_labels(ceiling: u64) -> [String; 3] {
    [fmt_num(ceiling), fmt_num(ceiling / 2), "0".to_string()]
}

fn px_point(origin: gpui::Point<Pixels>, p: (f32, f32)) -> gpui::Point<Pixels> {
    point(origin.x + px(p.0), origin.y + px(p.1))
}

// The area fill is a closed path under the polyline; the stroke follows it.
fn paint_line(bounds: Bounds<Pixels>, line: &Line, ceiling: u64, window: &mut Window) {
    let w: f32 = bounds.size.width.into();
    let h: f32 = bounds.size.height.into();
    if w < 1.0 || h < 1.0 {
        return;
    }
    let values = fit_series(&line.values, (w / PX_PER_POINT) as usize);
    let pts = scale_points(&values, ceiling, w, h);
    let Some((first, rest)) = pts.split_first() else {
        return;
    };
    if line.area && pts.len() > 1 {
        let mut area = PathBuilder::fill();
        area.move_to(px_point(bounds.origin, (first.0, h)));
        area.line_to(px_point(bounds.origin, *first));
        for p in rest {
            area.line_to(px_point(bounds.origin, *p));
        }
        let last = pts[pts.len() - 1];
        area.line_to(px_point(bounds.origin, (last.0, h)));
        area.close();
        if let Ok(path) = area.build() {
            window.paint_path(path, gpui::Hsla::from(tint(line.color, 0.16)));
        }
    }
    let mut stroke = PathBuilder::stroke(px(1.6));
    stroke.move_to(px_point(bounds.origin, *first));
    for p in rest {
        stroke.line_to(px_point(bounds.origin, *p));
    }
    if rest.is_empty() {
        stroke.line_to(px_point(bounds.origin, (first.0 + 1.0, first.1)));
    }
    if let Ok(path) = stroke.build() {
        window.paint_path(path, gpui::Hsla::from(c(line.color)));
    }
}

fn plot(lines: Vec<Line>, ceiling: u64, grid: bool) -> impl IntoElement {
    canvas(
        |bounds, _, _| bounds,
        move |bounds, _, window, _| {
            if grid {
                let h: f32 = bounds.size.height.into();
                for i in 0..=4 {
                    let y = h * i as f32 / 4.0;
                    window.paint_quad(fill(
                        Bounds::new(
                            point(bounds.origin.x, bounds.origin.y + px(y.min(h - 1.0))),
                            size(bounds.size.width, px(1.)),
                        ),
                        tint(BORDER, 0.7),
                    ));
                }
            }
            for line in &lines {
                paint_line(bounds, line, ceiling, window);
            }
        },
    )
    .size_full()
}

// Draws series on a shared scale; the plot takes whatever width it is given and the value labels sit in a fixed gutter.
pub fn line_chart(lines: Vec<Line>, height: f32, grid: bool) -> Div {
    let max = lines
        .iter()
        .flat_map(|l| l.values.iter().copied())
        .max()
        .unwrap_or(0);
    let ceiling = nice_max(max);
    let area = div()
        .relative()
        .flex_1()
        .min_w_0()
        .h_full()
        .overflow_hidden()
        .child(plot(lines, ceiling, grid));
    let root = div().flex().w_full().min_w_0().h(px(height));
    if !grid {
        return root.child(area);
    }
    let labels = y_labels(ceiling);
    let gutter = div()
        .flex()
        .flex_col()
        .justify_between()
        .flex_none()
        .w(px(Y_GUTTER))
        .h_full()
        .pr(px(6.))
        .text_size(px(10.))
        .text_color(c(DIM))
        .font_family(crate::theme::MONO)
        .children(
            labels
                .into_iter()
                .map(|l| div().flex().justify_end().whitespace_nowrap().child(l)),
        );
    root.child(gutter).child(area)
}

// Time labels under a gridded chart: as many as the measured width fits, aligned past the value gutter.
pub fn x_axis(key: &str, stamps: Vec<String>) -> Div {
    let width = (width_or_default(key) - Y_GUTTER).max(0.0);
    let ticks = axis_ticks(stamps.len(), width);
    let single = ticks.len() == 1;
    let labels = ticks.into_iter().filter_map(|i| stamps.get(i).cloned());
    div()
        .relative()
        .w_full()
        .min_w_0()
        .child(width_probe(key.to_string()))
        .child(
            div()
                .flex()
                .when(single, |d| d.justify_center())
                .when(!single, |d| d.justify_between())
                .gap(px(8.))
                .ml(px(Y_GUTTER))
                .overflow_hidden()
                .text_size(px(11.))
                .text_color(c(DIM))
                .children(labels.map(|l| div().flex_none().whitespace_nowrap().child(l))),
        )
}

pub fn spark(values: Vec<u64>, color: u32) -> Div {
    line_chart(
        vec![Line {
            values,
            color,
            area: true,
        }],
        40.0,
        false,
    )
}

// The label column shrinks and clips before the bar does, so long keys never push the value off the card.
pub fn hbar(label: &str, value: u64, max: u64, color: u32, text: String) -> Div {
    let frac = if max == 0 {
        0.0
    } else {
        (value as f32 / max as f32).clamp(0.0, 1.0)
    };
    div()
        .flex()
        .items_center()
        .gap(px(10.))
        .w_full()
        .min_w_0()
        .child(
            div()
                .w(px(70.))
                .flex_shrink()
                .min_w(px(36.))
                .overflow_hidden()
                .text_ellipsis()
                .whitespace_nowrap()
                .text_size(px(12.))
                .text_color(c(DIM))
                .child(label.to_string()),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(24.))
                .h(px(8.))
                .rounded_full()
                .bg(tint(0xffffff, 0.06))
                .child(
                    div()
                        .h_full()
                        .w(gpui::relative(frac))
                        .rounded_full()
                        .bg(c(color)),
                ),
        )
        .child(
            div()
                .flex_none()
                .min_w(px(56.))
                .flex()
                .justify_end()
                .whitespace_nowrap()
                .text_size(px(12.))
                .font_family(crate::theme::MONO)
                .child(text),
        )
}

struct Tip(SharedString);

impl Render for Tip {
    fn render(&mut self, _: &mut Window, _: &mut gpui::Context<Self>) -> impl IntoElement {
        div()
            .max_w(px(520.))
            .px(px(8.))
            .py(px(5.))
            .rounded(px(6.))
            .border_1()
            .border_color(chip_stroke())
            .bg(c(SURFACE_HI))
            .text_color(c(TEXT))
            .text_size(px(12.))
            .font_family(crate::theme::MONO)
            .child(self.0.clone())
    }
}

fn tip_view(text: SharedString, cx: &mut App) -> AnyView {
    cx.new(|_| Tip(text)).into()
}

// Single-line text that ends in an ellipsis when it does not fit and shows the whole value on hover.
pub fn clip_tip(key: ElementId, text: impl Into<SharedString>) -> Stateful<Div> {
    let text: SharedString = text.into();
    clip_tip_full(key, text.clone(), text)
}

// Like clip_tip, but the hover shows `full`, for cells that display a summary of a longer value.
pub fn clip_tip_full(
    key: ElementId,
    text: impl Into<SharedString>,
    full: impl Into<SharedString>,
) -> Stateful<Div> {
    let text: SharedString = text.into();
    let tip: SharedString = full.into();
    div()
        .id(key)
        .min_w_0()
        .overflow_hidden()
        .text_ellipsis()
        .whitespace_nowrap()
        .tooltip(move |_, cx| tip_view(tip.clone(), cx))
        .child(text)
}

// Lets a table keep its column widths on narrow windows by scrolling sideways instead of overlapping.
pub fn wide(key: ElementId, min_width: f32, body: impl IntoElement) -> Stateful<Div> {
    let mut table = div()
        .id(key)
        .w_full()
        .min_w_0()
        .overflow_x_scroll()
        .child(div().min_w(px(min_width)).w_full().child(body));
    // A vertical wheel must reach the page scroller instead of panning the table sideways.
    table.style().restrict_scroll_to_axis = Some(true);
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_series_keeps_short_series_and_pools_long_ones_by_max() {
        assert_eq!(fit_series(&[1, 2, 3], 10), vec![1, 2, 3]);
        let long: Vec<u64> = (0..100).collect();
        let fitted = fit_series(&long, 10);
        assert_eq!(fitted.len(), 10);
        assert_eq!(fitted[0], 9);
        assert_eq!(*fitted.last().unwrap(), 99);
        let spike = {
            let mut v = vec![0u64; 1000];
            v[537] = 42;
            v
        };
        assert_eq!(fit_series(&spike, 50).into_iter().max(), Some(42));
    }

    #[test]
    fn axis_ticks_fit_the_width_and_include_both_ends() {
        assert!(axis_ticks(0, 500.0).is_empty());
        assert_eq!(axis_ticks(1, 500.0), vec![0]);
        assert_eq!(axis_ticks(60, 100.0), vec![0, 59]);
        let wide = axis_ticks(60, 600.0);
        assert_eq!(wide.len(), 6);
        assert_eq!(wide.first(), Some(&0));
        assert_eq!(wide.last(), Some(&59));
        assert!(wide.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(axis_ticks(3, 2000.0), vec![0, 1, 2]);
    }

    #[test]
    fn y_labels_run_from_ceiling_to_zero() {
        let [top, mid, bottom] = y_labels(nice_max(870));
        assert_eq!(top, fmt_num(1000));
        assert_eq!(mid, fmt_num(500));
        assert_eq!(bottom, "0");
    }

    #[test]
    fn grid_breakpoint_reads_the_measured_width() {
        WIDTHS.with(|m| m.borrow_mut().insert("test-split".into(), 500.0));
        assert!(narrower_than("test-split", 720.0));
        assert!(!narrower_than("test-split", 400.0));
        assert_eq!(measured_width("test-split"), Some(500.0));
        assert_eq!(measured_width("never-measured"), None);
    }
}
