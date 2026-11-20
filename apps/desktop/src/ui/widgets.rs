use std::cell::RefCell;
use std::rc::Rc;

use gpui::{
    AnyElement, App, AvailableSpace, Bounds, BoxShadow, Div, Element, ElementId, Fill, Font,
    FontWeight, GlobalElementId, Hsla, InspectorElementId, LayoutId, PathBuilder, Pixels,
    ShapedLine, SharedString, Stateful, Style, TextRun, Window, canvas, div, hsla,
    linear_color_stop, linear_gradient, point, prelude::*, px, size,
};

use crate::theme::{
    ACCENT, BORDER, CARD_RADIUS, DIM, DIVIDER, FAINT, INPUT, MONO, ON_ACCENT, PILL_RADIUS, RED,
    ROW_RADIUS, SURFACE, SURFACE_HI, TEXT, Tone, c, chip_fill, chip_stroke, font, layout, space,
    tint,
};
use crate::ui::chart::{TipBody, tip_body_view};
use crate::ui::scroll::scroll_area;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BtnKind {
    Plain,
    // The paper bevel: the strongest call to action on a page.
    Primary,
    // The one accent-coloured control, for a single confirming action.
    #[allow(dead_code)] // Offered to the views; none use it yet.
    Accent,
    Danger,
}

// Dynamic element ids are built from a prefix and a key so repeated rows stay distinct.
pub fn id(prefix: &str, key: impl std::fmt::Display) -> ElementId {
    ElementId::Name(SharedString::from(format!("{prefix}-{key}")))
}

// One neutral drop shadow layer. Shadows are always black at some alpha: no coloured glows.
fn drop_shadow(dy: f32, blur: f32, spread: f32, alpha: f32) -> BoxShadow {
    BoxShadow {
        color: hsla(0., 0., 0., alpha),
        offset: point(px(0.), px(dy)),
        blur_radius: px(blur),
        spread_radius: px(spread),
    }
}

// Cards and tiles: a tight contact shadow under a soft long one.
pub fn card_shadow() -> Vec<BoxShadow> {
    vec![
        drop_shadow(1., 2., 0., 0.4),
        drop_shadow(14., 36., -10., 0.5),
    ]
}

// Small raised controls: buttons, the active segment, the active tab.
pub fn raise_shadow() -> Vec<BoxShadow> {
    vec![drop_shadow(1., 1., 0., 0.5), drop_shadow(2., 6., -1., 0.35)]
}

// Things that float above the page: tooltips and dialogs.
pub fn float_shadow() -> Vec<BoxShadow> {
    vec![
        drop_shadow(2., 6., 0., 0.4),
        drop_shadow(24., 56., -12., 0.7),
    ]
}

// A top-to-bottom two-stop gradient, the bevel of a raised control.
fn bevel(top: u32, bottom: u32) -> Fill {
    Fill::from(linear_gradient(
        180.,
        linear_color_stop(c(top), 0.),
        linear_color_stop(c(bottom), 1.),
    ))
}

pub fn text_dim(s: impl Into<SharedString>) -> Div {
    div().flex().flex_col().text_color(c(DIM)).child(s.into())
}

pub fn mono(s: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .font_family(MONO)
        .text_size(px(font::SM))
        .child(s.into())
}

pub fn strong(s: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .font_weight(FontWeight::SEMIBOLD)
        .child(s.into())
}

// Single-line text that clips with an ellipsis instead of wrapping inside narrow cells.
pub fn clip(s: impl Into<SharedString>) -> Div {
    clip_with(ClipText::new(s))
}

// The box `clip` puts its text in; it may shrink below the text, which then ellipsizes.
pub fn clip_with(text: ClipText) -> Div {
    div()
        .flex()
        .flex_col()
        .min_w_0()
        .overflow_hidden()
        .child(text)
}

// One line of text that ellipsizes at the width it is finally given.
// gpui's own text element cannot do this: with `whitespace_nowrap` it keeps the result of its
// first measurement for the rest of the frame, and the flex pass first measures it at the
// narrowest width, so `text_ellipsis` there leaves only the ellipsis. This element measures at
// full width, reports min(text, available), and truncates once its bounds are known.
pub struct ClipText {
    text: SharedString,
    layout: ClipLayout,
}

// What a ClipText showed in its last layout: the text after truncation and its bounds.
#[derive(Clone, Default)]
pub struct ClipLayout(Rc<RefCell<Option<(SharedString, Bounds<Pixels>)>>>);

impl ClipLayout {
    #[allow(dead_code)] // Read by the layout tests.
    pub fn shown(&self) -> Option<(SharedString, Bounds<Pixels>)> {
        self.0.borrow().clone()
    }
}

impl ClipText {
    pub fn new(s: impl Into<SharedString>) -> Self {
        let s: SharedString = s.into();
        // A shaped line cannot hold a line break, and the text is one line by design.
        let text = if s.contains(['\n', '\r']) {
            SharedString::from(s.replace(['\n', '\r'], " "))
        } else {
            s
        };
        Self {
            text,
            layout: ClipLayout::default(),
        }
    }

    #[allow(dead_code)] // Read by the layout tests.
    pub fn layout(&self) -> &ClipLayout {
        &self.layout
    }
}

pub struct ClipMeasure {
    full: ShapedLine,
    runs: Vec<TextRun>,
    font: Font,
    font_size: Pixels,
    line_height: Pixels,
}

impl Element for ClipText {
    type RequestLayoutState = ClipMeasure;
    type PrepaintState = ShapedLine;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        _cx: &mut App,
    ) -> (LayoutId, ClipMeasure) {
        let style = window.text_style();
        let font_size = style.font_size.to_pixels(window.rem_size());
        let line_height = style
            .line_height
            .to_pixels(font_size.into(), window.rem_size());
        let runs = vec![style.to_run(self.text.len())];
        let full = window
            .text_system()
            .shape_line(self.text.clone(), font_size, &runs, None);
        let width = full.width.ceil();
        let layout_id =
            window.request_measured_layout(Style::default(), move |known, avail, _, _| {
                let w = known.width.unwrap_or(match avail.width {
                    AvailableSpace::Definite(x) => width.min(x),
                    // It may shrink to nothing; the ellipsis covers what does not fit.
                    AvailableSpace::MinContent => px(0.),
                    AvailableSpace::MaxContent => width,
                });
                size(w, known.height.unwrap_or(line_height))
            });
        let measure = ClipMeasure {
            full,
            runs,
            font: style.font(),
            font_size,
            line_height,
        };
        (layout_id, measure)
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        m: &mut ClipMeasure,
        window: &mut Window,
        cx: &mut App,
    ) -> ShapedLine {
        let room = bounds.size.width;
        let line = if m.full.width.floor() <= room {
            m.full.clone()
        } else {
            let mut runs = m.runs.clone();
            let mut wrapper = cx.text_system().line_wrapper(m.font.clone(), m.font_size);
            let text = wrapper.truncate_line(self.text.clone(), room, "\u{2026}", &mut runs);
            window
                .text_system()
                .shape_line(text, m.font_size, &runs, None)
        };
        self.layout
            .0
            .borrow_mut()
            .replace((line.text.clone(), bounds));
        line
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        m: &mut ClipMeasure,
        line: &mut ShapedLine,
        window: &mut Window,
        cx: &mut App,
    ) {
        line.paint(bounds.origin, m.line_height, window, cx).ok();
    }
}

impl IntoElement for ClipText {
    type Element = Self;

    fn into_element(self) -> Self {
        self
    }
}

// Fill, hover fill, pressed fill, label colour and edge colour of a pill button.
struct BtnLook {
    fill: Fill,
    hover: Fill,
    press: Fill,
    fg: Hsla,
    border: Hsla,
}

fn btn_look(kind: BtnKind) -> BtnLook {
    match kind {
        BtnKind::Primary => BtnLook {
            fill: bevel(0xffffff, 0xdcdce0),
            hover: bevel(0xffffff, 0xececef),
            press: bevel(0xe6e6ea, 0xd0d0d5),
            fg: c(ON_ACCENT).into(),
            border: tint(0x000000, 0.35).into(),
        },
        BtnKind::Accent => BtnLook {
            fill: bevel(0xf17a63, ACCENT),
            hover: bevel(0xf48a75, 0xf0705a),
            press: bevel(0xdf5f48, 0xd9593f),
            fg: c(ON_ACCENT).into(),
            border: tint(0x000000, 0.3).into(),
        },
        BtnKind::Danger => BtnLook {
            fill: Fill::from(tint(RED, 0.12)),
            hover: Fill::from(tint(RED, 0.2)),
            press: Fill::from(tint(RED, 0.07)),
            fg: c(RED).into(),
            border: tint(RED, 0.4).into(),
        },
        BtnKind::Plain => BtnLook {
            fill: bevel(0x2a2b32, SURFACE_HI),
            hover: bevel(0x32333b, 0x282930),
            press: bevel(0x1a1b1f, SURFACE_HI),
            fg: c(TEXT).into(),
            border: c(BORDER).into(),
        },
    }
}

// A fully rounded pill. Pressing flattens the shadow and darkens the bevel; the control itself
// never moves, because a layout offset is not applied to an element that is being pressed.
pub fn btn(key: ElementId, label: &str, kind: BtnKind) -> Stateful<Div> {
    let look = btn_look(kind);
    let raised = kind != BtnKind::Danger;
    let mut button = div()
        .id(key)
        .flex()
        .items_center()
        .justify_center()
        .flex_none()
        .h(px(layout::CONTROL_H))
        .px(px(space::LG))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .border_color(look.border)
        .bg(look.fill)
        .text_color(look.fg)
        .text_size(px(font::SM))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .whitespace_nowrap();
    if raised {
        button = button.shadow(raise_shadow());
    }
    let (hover, press) = (look.hover, look.press);
    button
        .hover(move |s| s.bg(hover))
        .active(move |s| s.bg(press).shadow_none())
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
        .px(px(space::LG))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(INPUT))
        .text_color(c(FAINT))
        .text_size(px(font::SM))
        .font_weight(FontWeight::MEDIUM)
        .whitespace_nowrap()
        .child(label.to_string())
}

// The tick drawn inside a checked checkbox.
fn check_mark() -> impl IntoElement {
    canvas(
        |_, _, _| (),
        |bounds, _, window, _| {
            let w: f32 = bounds.size.width.into();
            let h: f32 = bounds.size.height.into();
            let at =
                |x: f32, y: f32| point(bounds.origin.x + px(w * x), bounds.origin.y + px(h * y));
            let mut stroke = PathBuilder::stroke(px(2.));
            stroke.move_to(at(0.1, 0.54));
            stroke.line_to(at(0.4, 0.82));
            stroke.line_to(at(0.9, 0.2));
            if let Ok(path) = stroke.build() {
                window.paint_path(path, Hsla::from(c(ON_ACCENT)));
            }
        },
    )
    .size(px(12.))
}

// A rounded tick box: accent fill with a drawn check when on, an inset well when off.
pub fn checkbox(key: ElementId, on: bool) -> Stateful<Div> {
    let mut boxed = div()
        .id(key)
        .flex()
        .items_center()
        .justify_center()
        .flex_none()
        .size(px(18.))
        .rounded(px(6.))
        .border_1()
        .cursor_pointer();
    boxed = if on {
        boxed
            .bg(c(ACCENT))
            .border_color(tint(0x000000, 0.3))
            .child(check_mark())
    } else {
        boxed.bg(c(INPUT)).border_color(c(BORDER))
    };
    boxed
}

pub fn pill(text: &str, tone: Tone) -> Div {
    pill_color(text, tone.color())
}

// Same shape as pill for palette colours that have no Tone, such as the bot classes. The text
// is the tone colour on a 12 percent tint of itself, which stays above 4.5:1 for every tone.
pub fn pill_color(text: &str, color: u32) -> Div {
    div()
        .flex()
        .items_center()
        .flex_none()
        .px(px(10.))
        .py(px(space::XXS))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .border_color(tint(color, 0.28))
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
        .bg(c(SURFACE))
        .shadow(card_shadow());
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
        .px(px(space::LG))
        .py(px(space::MD))
        .rounded(px(CARD_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(SURFACE))
        .shadow(card_shadow())
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
                .child(
                    strong(title.to_string())
                        .text_size(px(font::XL))
                        .font_weight(FontWeight::BOLD),
                )
                .child(
                    text_dim(subtitle.to_string())
                        .text_size(px(font::BASE))
                        .text_color(c(DIM)),
                ),
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
        .flex()
        .flex_col()
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
        .flex()
        .flex_col()
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

// A drawn switch: accent track when on, an inset well when off; the knob sits at the end that matches the state.
pub fn toggle(key: ElementId, on: bool) -> Stateful<Div> {
    let knob = div()
        .size(px(14.))
        .rounded_full()
        .bg(c(if on { 0xffffff } else { DIM }))
        .shadow(raise_shadow());
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
        track
            .bg(c(ACCENT))
            .border_color(tint(0x000000, 0.3))
            .justify_end()
    } else {
        track.bg(c(INPUT)).border_color(c(BORDER)).justify_start()
    };
    track.child(knob)
}

// One segment of a seg_row. Every segment carries a 1px edge so the active one does not shift the row.
pub fn seg_item(key: ElementId, label: &str, active: bool) -> Stateful<Div> {
    seg_item_look(key, label, active, true)
}

// A segment that cannot be chosen, such as an offline node: same look, no hover and no pointer.
pub fn seg_item_off(key: ElementId, label: &str, active: bool) -> Stateful<Div> {
    seg_item_look(key, label, active, false)
}

fn seg_item_look(key: ElementId, label: &str, active: bool, live: bool) -> Stateful<Div> {
    let mut item = div()
        .flex()
        .flex_col()
        .id(key)
        .px(px(space::MD))
        .py(px(space::XS))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .text_size(px(font::SM))
        .font_weight(FontWeight::MEDIUM)
        .whitespace_nowrap();
    if live {
        item = item.cursor_pointer();
    }
    item = if active {
        item.bg(bevel(0x2c2d34, SURFACE_HI))
            .border_color(c(BORDER))
            .text_color(c(TEXT))
            .shadow(raise_shadow())
    } else {
        let idle = item.border_color(tint(0xffffff, 0.0)).text_color(c(DIM));
        // gpui allows one hover style per element, so a segment that cannot be chosen never sets it.
        if live {
            idle.hover(|s| s.bg(tint(0xffffff, 0.05)).text_color(c(TEXT)))
        } else {
            idle
        }
    };
    item.child(label.to_string())
}

// The pill track that holds the segments; its padding and the segment radius are both full, so the curves stay concentric.
pub fn seg_row(items: Vec<AnyElement>) -> Div {
    div()
        .flex()
        .flex_none()
        .items_center()
        .gap(px(space::XXS))
        .p(px(space::XXS))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .border_color(c(BORDER))
        .bg(c(INPUT))
        .children(items)
}

// Page tab: a pill that rises when selected.
pub fn tab_item(key: ElementId, label: &str, active: bool) -> Stateful<Div> {
    let mut item = div()
        .id(key)
        .flex()
        .items_center()
        .flex_none()
        .h(px(layout::CONTROL_H))
        .px(px(space::LG))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .text_size(px(font::BASE))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .whitespace_nowrap();
    item = if active {
        item.bg(bevel(0x2c2d34, SURFACE_HI))
            .border_color(c(BORDER))
            .text_color(c(TEXT))
            .shadow(raise_shadow())
    } else {
        item.border_color(tint(0xffffff, 0.0))
            .text_color(c(DIM))
            .hover(|s| s.bg(tint(0xffffff, 0.05)).text_color(c(TEXT)))
    };
    item.child(label.to_string())
}

// The strip of tab_item pills above a tabbed page; wraps rather than clipping on narrow windows.
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
    // Narrowest a flex column may get; wrap the table in `wide` so narrow windows scroll instead.
    pub min: Option<f32>,
    pub right: bool,
}

impl Col {
    pub fn flex(label: &'static str) -> Self {
        Self {
            label,
            width: None,
            min: None,
            right: false,
        }
    }

    pub fn fixed(label: &'static str, width: f32) -> Self {
        Self {
            label,
            width: Some(width),
            min: None,
            right: false,
        }
    }

    pub fn right(mut self) -> Self {
        self.right = true;
        self
    }

    pub fn min(mut self, width: f32) -> Self {
        self.min = Some(width);
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
        None => match col.min {
            Some(m) => cell.flex_1().min_w(px(m)),
            None => cell.flex_1(),
        },
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
        .text_size(px(font::SM))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(c(DIM));
    for col in cols {
        head = head.child(cell(col, col.label.into_any_element()));
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

// Wraps `el` so hovering it shows `text`; a newline in the text starts a new line of the tooltip.
#[allow(dead_code)] // The tooltip helpers are offered to the views; none use them yet.
pub fn tip(el: impl IntoElement, key: ElementId, text: impl Into<SharedString>) -> Stateful<Div> {
    tip_with(
        el,
        key,
        TipBody::Text {
            text: text.into(),
            mono: false,
        },
    )
}

// Like tip, with the text in the monospace face, for values such as hashes, paths and patterns.
#[allow(dead_code)]
pub fn tip_mono(
    el: impl IntoElement,
    key: ElementId,
    text: impl Into<SharedString>,
) -> Stateful<Div> {
    tip_with(
        el,
        key,
        TipBody::Text {
            text: text.into(),
            mono: true,
        },
    )
}

// Like tip, but the hover shows a pop_list of the given (title, badge, detail) rows.
#[allow(dead_code)]
pub fn tip_rows(
    el: impl IntoElement,
    key: ElementId,
    rows: Vec<(String, Option<String>, String)>,
) -> Stateful<Div> {
    tip_with(el, key, TipBody::Rows(rows))
}

fn tip_with(el: impl IntoElement, key: ElementId, body: TipBody) -> Stateful<Div> {
    div()
        .id(key)
        .flex()
        .items_center()
        .min_w_0()
        .tooltip(move |_, cx| tip_body_view(body.clone(), cx))
        .child(el)
}

// A tooltip body listing rows: a bold title with an optional small badge, then the detail in
// monospace, wrapped rather than cut off.
pub fn pop_list(rows: Vec<(String, Option<String>, String)>) -> Div {
    let mut list = div().flex().flex_col().min_w_0().gap(px(space::MD));
    for (title, badge, detail) in rows {
        let mut head = div()
            .flex()
            .items_center()
            .gap(px(space::SM))
            .child(strong(title).text_size(px(font::SM)).text_color(c(TEXT)));
        if let Some(badge) = badge {
            head = head.child(
                div()
                    .flex()
                    .items_center()
                    .flex_none()
                    .px(px(6.))
                    .py(px(1.))
                    .rounded(px(PILL_RADIUS))
                    .border_1()
                    .border_color(chip_stroke())
                    .bg(chip_fill())
                    .text_color(c(DIM))
                    .text_size(px(font::XS))
                    .whitespace_nowrap()
                    .child(badge),
            );
        }
        let mut row = div()
            .flex()
            .flex_col()
            .min_w_0()
            .gap(px(space::XXS))
            .child(head);
        if !detail.is_empty() {
            row = row.child(mono(detail).min_w_0().text_color(c(DIM)));
        }
        list = list.child(row);
    }
    list
}
