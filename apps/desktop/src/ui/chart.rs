use gpui::{Bounds, PathBuilder, Pixels, Window, canvas, div, fill, point, prelude::*, px, size};

use crate::model::{fmt_num, nice_max, scale_points};
use crate::theme::{BORDER, DIM, c, tint};

pub struct Line {
    pub values: Vec<u64>,
    pub color: u32,
    pub area: bool,
}

fn px_point(origin: gpui::Point<Pixels>, p: (f32, f32)) -> gpui::Point<Pixels> {
    point(origin.x + px(p.0), origin.y + px(p.1))
}

// The area fill is a closed path under the polyline; the stroke follows it.
fn paint_line(bounds: Bounds<Pixels>, line: &Line, ceiling: u64, window: &mut Window) {
    let w: f32 = bounds.size.width.into();
    let h: f32 = bounds.size.height.into();
    let pts = scale_points(&line.values, ceiling, w, h);
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

// Draws one or more series on a shared scale with horizontal grid lines and a top label.
pub fn line_chart(lines: Vec<Line>, height: f32, grid: bool) -> gpui::Div {
    let max = lines
        .iter()
        .flat_map(|l| l.values.iter().copied())
        .max()
        .unwrap_or(0);
    let ceiling = nice_max(max);
    let canvas = canvas(
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
    .size_full();
    let mut root = div().relative().w_full().h(px(height)).child(canvas);
    if grid {
        root = root
            .child(
                div()
                    .absolute()
                    .top(px(2.))
                    .left(px(4.))
                    .text_size(px(10.))
                    .text_color(c(DIM))
                    .child(fmt_num(ceiling)),
            )
            .child(
                div()
                    .absolute()
                    .bottom(px(2.))
                    .left(px(4.))
                    .text_size(px(10.))
                    .text_color(c(DIM))
                    .child("0"),
            );
    }
    root
}

pub fn spark(values: Vec<u64>, color: u32) -> gpui::Div {
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

pub fn hbar(label: &str, value: u64, max: u64, color: u32, text: String) -> gpui::Div {
    let frac = if max == 0 {
        0.0
    } else {
        (value as f32 / max as f32).clamp(0.0, 1.0)
    };
    div()
        .flex()
        .items_center()
        .gap(px(10.))
        .child(
            div()
                .w(px(70.))
                .flex_none()
                .text_size(px(12.))
                .text_color(c(DIM))
                .child(label.to_string()),
        )
        .child(
            div()
                .flex_1()
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
                .w(px(70.))
                .flex_none()
                .text_size(px(12.))
                .font_family(crate::theme::MONO)
                .child(text),
        )
}
