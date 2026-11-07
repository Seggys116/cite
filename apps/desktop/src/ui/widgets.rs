use gpui::{
    AnyElement, Div, ElementId, FontWeight, Hsla, SharedString, Stateful, div, prelude::*, px,
};

use crate::theme::{
    ACCENT, BORDER, CARD_RADIUS, CHIP_RADIUS, DIM, DIVIDER, GREEN, INPUT, MONO, RED, ROW_RADIUS,
    SURFACE, SURFACE_HI, TEXT, Tone, c, chip_fill, chip_stroke, font, layout, space, tint,
};
use crate::ui::scroll::scroll_area;

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
    div()
        .font_family(MONO)
        .text_size(px(font::SM))
        .child(s.into())
}

pub fn strong(s: impl Into<SharedString>) -> Div {
    div().font_weight(FontWeight::SEMIBOLD).child(s.into())
}

// Single-line text that clips with an ellipsis instead of wrapping inside narrow cells.
pub fn clip(s: impl Into<SharedString>) -> Div {
    div()
        .min_w_0()
        .overflow_hidden()
        .text_ellipsis()
        .whitespace_nowrap()
        .child(s.into())
}

pub fn btn(key: ElementId, label: &str, kind: BtnKind) -> Stateful<Div> {
    let (bg, fg, border): (Hsla, Hsla, Hsla) = match kind {
        BtnKind::Primary => (c(ACCENT).into(), c(0xffffff).into(), c(ACCENT).into()),
        BtnKind::Danger => (tint(RED, 0.12).into(), c(RED).into(), tint(RED, 0.5).into()),
        BtnKind::Plain => (chip_fill().into(), c(TEXT).into(), chip_stroke().into()),
    };
    div()
        .id(key)
        .flex()
        .items_center()
        .justify_center()
        .flex_none()
        .h(px(layout::CONTROL_H))
        .px(px(space::MD))
        .rounded(px(CHIP_RADIUS))
        .border_1()
        .border_color(border)
        .bg(bg)
        .text_color(fg)
        .text_size(px(font::SM))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .whitespace_nowrap()
        .hover(|s| s.opacity(0.85))
        .active(|s| s.opacity(0.7))
        .child(label.to_string())
}

// A button that cannot be pressed: same footprint as btn, muted, and without a click target.
pub fn btn_off(label: &str) -> Div {
    div()
        .flex()
        .items_center()
        .justify_center()
        .flex_none()
        .h(px(layout::CONTROL_H))
        .px(px(space::MD))
        .rounded(px(CHIP_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(INPUT))
        .text_color(c(DIM))
        .text_size(px(font::SM))
        .font_weight(FontWeight::MEDIUM)
        .whitespace_nowrap()
        .child(label.to_string())
}

// A square tick box: the chip fill and an inner square mark the checked state.
pub fn checkbox(key: ElementId, on: bool) -> Stateful<Div> {
    let mut boxed = div()
        .id(key)
        .flex()
        .items_center()
        .justify_center()
        .flex_none()
        .size(px(18.))
        .rounded(px(5.))
        .border_1()
        .cursor_pointer();
    boxed = if on {
        boxed
            .bg(chip_fill())
            .border_color(chip_stroke())
            .child(div().size(px(space::SM)).rounded(px(2.)).bg(c(0xffffff)))
    } else {
        boxed.bg(c(INPUT)).border_color(c(BORDER))
    };
    boxed
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
        .px(px(space::SM))
        .py(px(space::XXS))
        .rounded(px(CHIP_RADIUS))
        .border_1()
        .border_color(tint(color, 0.3))
        .bg(tint(color, 0.12))
        .text_color(c(color))
        .text_size(px(font::XS))
        .font_weight(FontWeight::SEMIBOLD)
        .whitespace_nowrap()
        .child(text.to_string())
}

pub fn dot(tone: Tone) -> Div {
    div()
        .flex_none()
        .size(px(space::SM))
        .rounded_full()
        .bg(c(tone.color()))
}

pub fn card(title: Option<&str>, subtitle: Option<&str>, body: impl IntoElement) -> Div {
    let mut head = div().flex().flex_col().gap(px(space::XXS));
    if let Some(t) = title {
        head = head.child(strong(t.to_string()).text_size(px(font::MD)));
    }
    if let Some(s) = subtitle {
        head = head.child(text_dim(s.to_string()).text_size(px(font::SM)));
    }
    let mut root = div()
        .flex()
        .flex_col()
        .gap(px(space::MD))
        .min_w_0()
        .p(px(space::LG))
        .rounded(px(CARD_RADIUS))
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
        .gap(px(space::XS))
        .flex_1()
        .min_w(px(150.))
        .p(px(space::MD))
        .rounded(px(CARD_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(SURFACE))
        .child(text_dim(label.to_string()).text_size(px(font::SM)))
        .child(
            mono(value)
                .text_size(px(24.))
                .text_color(c(value_color))
                .font_weight(FontWeight::SEMIBOLD),
        )
        .child(text_dim(sub).text_size(px(font::XS)))
}

// Fills its container and shares a row equally with its siblings, so an input inside is never sized to its text.
pub fn field(label: &str, hint: Option<&str>, child: impl IntoElement) -> Div {
    let mut root = div()
        .flex()
        .flex_col()
        .flex_1()
        .w_full()
        .min_w(px(layout::FIELD_MIN_W))
        .gap(px(space::XS))
        .child(
            strong(label.to_string())
                .text_size(px(font::SM))
                .text_color(c(DIM)),
        )
        .child(child);
    if let Some(h) = hint {
        root = root.child(text_dim(h.to_string()).text_size(px(font::XS)));
    }
    root
}

// Equal columns that wrap onto new lines once each would be narrower than COLUMN_MIN_W.
pub fn grid(children: Vec<AnyElement>) -> Div {
    grid_min(layout::COLUMN_MIN_W, children)
}

pub fn grid_min(min_width: f32, children: Vec<AnyElement>) -> Div {
    let mut root = div().flex().flex_wrap().w_full().gap(px(space::MD));
    for child in children {
        root = root.child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(min_width))
                .child(child),
        );
    }
    root
}

// Form rows: fields side by side on wide pages, stacked on narrow ones.
pub fn form_grid(children: Vec<AnyElement>) -> Div {
    grid_min(220.0, children)
}

pub fn page_header(title: &str, subtitle: &str, actions: Vec<AnyElement>) -> Div {
    div()
        .flex()
        .flex_wrap()
        .items_center()
        .justify_between()
        .gap(px(space::MD))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(220.))
                .gap(px(space::XXS))
                .child(strong(title.to_string()).text_size(px(font::XL)))
                .child(text_dim(subtitle.to_string()).text_size(px(font::BASE))),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(space::SM))
                .children(actions),
        )
}

pub fn section_title(text: &str) -> Div {
    strong(text.to_string())
        .text_size(px(15.))
        .mt(px(space::SM))
}

pub fn skeleton(height: f32) -> Div {
    div()
        .w_full()
        .h(px(height))
        .rounded(px(CARD_RADIUS))
        .bg(c(SURFACE))
        .border_1()
        .border_color(c(BORDER))
        .flex()
        .items_center()
        .px(px(space::LG))
        .child(text_dim("Loading...").text_size(px(font::SM)))
}

pub fn notice(message: &str, tone: Tone) -> Div {
    let color = tone.color();
    div()
        .px(px(space::MD))
        .py(px(space::SM))
        .rounded(px(ROW_RADIUS))
        .border_1()
        .border_color(tint(color, 0.4))
        .bg(tint(color, 0.1))
        .text_color(c(color))
        .text_size(px(font::BASE))
        .child(message.to_string())
}

pub fn empty_state(title: &str, text: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap(px(space::XS))
        .py(px(28.))
        .child(strong(title.to_string()))
        .child(text_dim(text.to_string()).text_size(px(font::SM)))
}

// Monospace text in an inset box that scrolls on its own and only hands the wheel to the page at its ends.
pub fn code_block(
    key: impl Into<SharedString>,
    text: impl Into<SharedString>,
    max_height: f32,
) -> Div {
    div()
        .w_full()
        .min_w_0()
        .rounded(px(ROW_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(INPUT))
        .overflow_hidden()
        .child(
            scroll_area(key)
                .max_h(px(max_height))
                .p(px(space::MD))
                .child(mono(text).text_color(c(TEXT))),
        )
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
        track.bg(c(INPUT)).border_color(c(BORDER)).justify_start()
    };
    track.child(knob)
}

pub fn seg_item(key: ElementId, label: &str, active: bool) -> Stateful<Div> {
    let mut item = div()
        .id(key)
        .px(px(11.))
        .py(px(5.))
        .text_size(px(font::SM))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .whitespace_nowrap();
    item = if active {
        item.bg(chip_fill()).text_color(c(0xffffff))
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
        .rounded(px(CHIP_RADIUS))
        .border_1()
        .border_color(chip_stroke())
        .bg(c(INPUT))
        .children(items)
}

// Term-style page tab: a rounded chip that fills when selected.
pub fn tab_item(key: ElementId, label: &str, active: bool) -> Stateful<Div> {
    let mut item = div()
        .id(key)
        .flex()
        .items_center()
        .flex_none()
        .h(px(layout::CONTROL_H))
        .px(px(space::MD))
        .rounded(px(ROW_RADIUS))
        .border_1()
        .text_size(px(font::BASE))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .whitespace_nowrap();
    item = if active {
        item.bg(chip_fill())
            .border_color(chip_stroke())
            .text_color(c(0xffffff))
    } else {
        item.border_color(tint(0xffffff, 0.0))
            .text_color(c(DIM))
            .hover(|s| s.bg(tint(0xffffff, 0.04)))
    };
    item.child(label.to_string())
}

// The strip of tab_item chips above a tabbed page; wraps rather than clipping on narrow windows.
pub fn tab_bar(items: Vec<AnyElement>) -> Div {
    div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap(px(space::XS))
        .pb(px(space::SM))
        .border_b_1()
        .border_color(c(DIVIDER))
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
        .py(px(space::SM))
        .border_b_1()
        .border_color(c(BORDER))
        .text_size(px(10.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(c(DIM));
    for col in cols {
        head = head.child(cell(col, col.label.to_uppercase().into_any_element()));
    }
    let mut root = div().flex().flex_col().w_full().min_w_0().child(head);
    if rows.is_empty() {
        if let Some(e) = empty {
            root = root.child(e);
        }
        return root;
    }
    for row in rows {
        let mut line = div()
            .flex()
            .items_center()
            .min_h(px(34.))
            .px(px(10.))
            .py(px(6.))
            .text_size(px(font::BASE))
            .border_b_1()
            .border_color(c(DIVIDER))
            .hover(|s| s.bg(tint(0xffffff, 0.025)));
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
