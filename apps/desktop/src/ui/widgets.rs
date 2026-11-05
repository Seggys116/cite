use gpui::{
    AnyElement, Div, ElementId, FontWeight, Hsla, SharedString, Stateful, div, prelude::*, px,
};

use crate::theme::{
    ACCENT, BG, BLUE, BORDER, DIM, GREEN, MONO, SURFACE, SURFACE_HI, TEXT, Tone, c, tint,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BtnKind {
    Plain,
    Primary,
    Danger,
}

// Dynamic element ids are built from a prefix and a key so repeated rows stay distinct.
pub fn id(prefix: &str, key: impl std::fmt::Display) -> ElementId {
    ElementId::Name(SharedString::from(format!("{prefix}-{key}")))
}

pub fn text_dim(s: impl Into<SharedString>) -> Div {
    div().text_color(c(DIM)).child(s.into())
}

pub fn mono(s: impl Into<SharedString>) -> Div {
    div().font_family(MONO).text_size(px(12.)).child(s.into())
}

pub fn strong(s: impl Into<SharedString>) -> Div {
    div().font_weight(FontWeight::SEMIBOLD).child(s.into())
}

// Single-line text that clips with an ellipsis instead of wrapping inside narrow cells.
pub fn clip(s: impl Into<SharedString>) -> Div {
    div()
        .overflow_hidden()
        .text_ellipsis()
        .whitespace_nowrap()
        .child(s.into())
}

pub fn btn(key: ElementId, label: &str, kind: BtnKind) -> Stateful<Div> {
    let (bg, fg, border): (Hsla, Hsla, Hsla) = match kind {
        BtnKind::Primary => (c(ACCENT).into(), c(0xffffff).into(), c(ACCENT).into()),
        BtnKind::Danger => (
            tint(ACCENT, 0.12).into(),
            c(ACCENT).into(),
            tint(ACCENT, 0.6).into(),
        ),
        BtnKind::Plain => (c(SURFACE_HI).into(), c(TEXT).into(), c(BORDER).into()),
    };
    div()
        .id(key)
        .flex()
        .items_center()
        .justify_center()
        .flex_none()
        .h(px(30.))
        .px(px(12.))
        .rounded(px(6.))
        .border_1()
        .border_color(border)
        .bg(bg)
        .text_color(fg)
        .text_size(px(13.))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .whitespace_nowrap()
        .hover(|s| s.opacity(0.85))
        .active(|s| s.opacity(0.7))
        .child(label.to_string())
}

pub fn pill(text: &str, tone: Tone) -> Div {
    pill_color(text, tone.color())
}

// Same shape as pill for palette colours that have no Tone, such as the bot classes.
pub fn pill_color(text: &str, color: u32) -> Div {
    div()
        .flex()
        .items_center()
        .flex_none()
        .px(px(8.))
        .py(px(2.))
        .rounded(px(10.))
        .bg(tint(color, 0.16))
        .text_color(c(color))
        .text_size(px(11.))
        .font_weight(FontWeight::SEMIBOLD)
        .whitespace_nowrap()
        .child(text.to_string())
}

pub fn dot(tone: Tone) -> Div {
    div()
        .flex_none()
        .size(px(8.))
        .rounded_full()
        .bg(c(tone.color()))
}

pub fn card(title: Option<&str>, subtitle: Option<&str>, body: impl IntoElement) -> Div {
    let mut head = div().flex().flex_col().gap(px(2.));
    if let Some(t) = title {
        head = head.child(strong(t.to_string()).text_size(px(14.)));
    }
    if let Some(s) = subtitle {
        head = head.child(text_dim(s.to_string()).text_size(px(12.)));
    }
    let mut root = div()
        .flex()
        .flex_col()
        .gap(px(12.))
        .p(px(16.))
        .rounded(px(8.))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(SURFACE));
    if title.is_some() {
        root = root.child(head);
    }
    root.child(body)
}

pub fn stat(label: &str, value: String, sub: String, tone: Tone) -> Div {
    let value_color = if tone == Tone::Muted {
        TEXT
    } else {
        tone.color()
    };
    div()
        .flex()
        .flex_col()
        .gap(px(4.))
        .flex_1()
        .min_w(px(150.))
        .p(px(14.))
        .rounded(px(8.))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(SURFACE))
        .child(text_dim(label.to_string()).text_size(px(12.)))
        .child(
            mono(value)
                .text_size(px(24.))
                .text_color(c(value_color))
                .font_weight(FontWeight::SEMIBOLD),
        )
        .child(text_dim(sub).text_size(px(11.)))
}

pub fn field(label: &str, hint: Option<&str>, child: impl IntoElement) -> Div {
    let mut root = div()
        .flex()
        .flex_col()
        .gap(px(5.))
        .child(
            strong(label.to_string())
                .text_size(px(12.))
                .text_color(c(DIM)),
        )
        .child(child);
    if let Some(h) = hint {
        root = root.child(text_dim(h.to_string()).text_size(px(11.)));
    }
    root
}

pub fn page_header(title: &str, subtitle: &str, actions: Vec<AnyElement>) -> Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap(px(12.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.))
                .child(strong(title.to_string()).text_size(px(22.)))
                .child(text_dim(subtitle.to_string()).text_size(px(13.))),
        )
        .child(div().flex().items_center().gap(px(8.)).children(actions))
}

pub fn section_title(text: &str) -> Div {
    strong(text.to_string()).text_size(px(15.)).mt(px(6.))
}

pub fn skeleton(height: f32) -> Div {
    div()
        .w_full()
        .h(px(height))
        .rounded(px(8.))
        .bg(c(SURFACE))
        .border_1()
        .border_color(c(BORDER))
        .flex()
        .items_center()
        .px(px(16.))
        .child(text_dim("Loading...").text_size(px(12.)))
}

pub fn notice(message: &str, tone: Tone) -> Div {
    let color = tone.color();
    div()
        .px(px(12.))
        .py(px(8.))
        .rounded(px(6.))
        .border_1()
        .border_color(tint(color, 0.5))
        .bg(tint(color, 0.1))
        .text_color(c(color))
        .text_size(px(13.))
        .child(message.to_string())
}

pub fn empty_state(title: &str, text: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap(px(4.))
        .py(px(28.))
        .child(strong(title.to_string()))
        .child(text_dim(text.to_string()).text_size(px(12.)))
}

// A drawn switch: the knob sits at the end that matches the state.
pub fn toggle(key: ElementId, on: bool) -> Stateful<Div> {
    let knob = div().size(px(14.)).rounded_full().bg(c(0xffffff));
    let mut track = div()
        .id(key)
        .flex()
        .items_center()
        .flex_none()
        .w(px(34.))
        .h(px(20.))
        .px(px(3.))
        .rounded_full()
        .cursor_pointer()
        .border_1();
    track = if on {
        track.bg(c(GREEN)).border_color(c(GREEN)).justify_end()
    } else {
        track.bg(c(BG)).border_color(c(BORDER)).justify_start()
    };
    track.child(knob)
}

pub fn seg_item(key: ElementId, label: &str, active: bool) -> Stateful<Div> {
    let mut item = div()
        .id(key)
        .px(px(11.))
        .py(px(5.))
        .text_size(px(12.))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .whitespace_nowrap();
    item = if active {
        item.bg(c(BLUE)).text_color(c(0xffffff))
    } else {
        item.text_color(c(DIM)).hover(|s| s.bg(c(SURFACE_HI)))
    };
    item.child(label.to_string())
}

pub fn seg_row(items: Vec<AnyElement>) -> Div {
    div()
        .flex()
        .flex_none()
        .items_center()
        .overflow_hidden()
        .rounded(px(6.))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(BG))
        .children(items)
}

#[derive(Clone)]
pub struct Col {
    pub label: &'static str,
    pub width: Option<f32>,
    pub right: bool,
}

impl Col {
    pub fn flex(label: &'static str) -> Self {
        Self {
            label,
            width: None,
            right: false,
        }
    }

    pub fn fixed(label: &'static str, width: f32) -> Self {
        Self {
            label,
            width: Some(width),
            right: false,
        }
    }

    pub fn right(mut self) -> Self {
        self.right = true;
        self
    }
}

fn cell(col: &Col, child: AnyElement) -> Div {
    let mut cell = div()
        .flex()
        .items_center()
        .min_w_0()
        .overflow_hidden()
        .px(px(6.));
    cell = match col.width {
        Some(w) => cell.w(px(w)).flex_none(),
        None => cell.flex_1(),
    };
    if col.right {
        cell = cell.justify_end();
    }
    cell.child(child)
}

// Tables use flex rows so cells can clip long values instead of wrapping.
pub fn table(cols: &[Col], rows: Vec<Vec<AnyElement>>, empty: Option<Div>) -> Div {
    let mut head = div()
        .flex()
        .px(px(10.))
        .py(px(8.))
        .border_b_1()
        .border_color(c(BORDER))
        .text_size(px(11.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(c(DIM));
    for col in cols {
        head = head.child(cell(col, col.label.to_uppercase().into_any_element()));
    }
    let mut root = div().flex().flex_col().w_full().child(head);
    if rows.is_empty() {
        if let Some(e) = empty {
            root = root.child(e);
        }
        return root;
    }
    for (i, row) in rows.into_iter().enumerate() {
        let mut line = div()
            .flex()
            .items_center()
            .min_h(px(40.))
            .px(px(10.))
            .py(px(6.))
            .text_size(px(13.))
            .border_b_1()
            .border_color(tint(BORDER, 0.6));
        if i % 2 == 1 {
            line = line.bg(tint(0xffffff, 0.015));
        }
        for (col, child) in cols.iter().zip(row) {
            line = line.child(cell(col, child));
        }
        root = root.child(line);
    }
    root
}

pub fn tone_for_status(code: u16) -> Tone {
    match code {
        500..=599 => Tone::Bad,
        400..=499 => Tone::Warn,
        300..=399 => Tone::Info,
        _ => Tone::Ok,
    }
}
