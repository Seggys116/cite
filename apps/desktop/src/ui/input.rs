use std::ops::Range;

use gpui::{
    App, Bounds, ClipboardItem, Context, CursorStyle, ElementId, ElementInputHandler, Entity,
    EntityInputHandler, EventEmitter, FocusHandle, Focusable, GlobalElementId, KeyBinding,
    LayoutId, MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, Pixels, Point,
    ShapedLine, SharedString, Style, TextRun, UTF16Selection, UnderlineStyle, Window, actions, div,
    fill, point, prelude::*, px, relative, size,
};
use unicode_segmentation::UnicodeSegmentation;

use crate::theme::{
    ACCENT, BLUE, BORDER, CHIP_RADIUS, DIM, INPUT, MONO, TEXT, c, font, layout, space, tint,
};

actions!(
    cite_input,
    [
        Backspace,
        Delete,
        Left,
        Right,
        Up,
        Down,
        SelectLeft,
        SelectRight,
        SelectAll,
        Home,
        End,
        Paste,
        Cut,
        Copy,
        Enter,
    ]
);

const LINE_HEIGHT: f32 = 18.0;

// A focused single-line field scrolls to keep the caret visible; an unfocused one shows its start.
fn scroll_for(cursor_x: Pixels, scroll: Pixels, width: Pixels, focused: bool) -> Pixels {
    if !focused {
        return px(0.);
    }
    let mut scroll = scroll;
    if cursor_x - scroll > width - px(4.) {
        scroll = cursor_x - width + px(4.);
    }
    if cursor_x < scroll {
        scroll = cursor_x;
    }
    scroll.max(px(0.))
}

// Bindings are scoped to the TextInput context so they never fire elsewhere.
pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("backspace", Backspace, Some("TextInput")),
        KeyBinding::new("delete", Delete, Some("TextInput")),
        KeyBinding::new("left", Left, Some("TextInput")),
        KeyBinding::new("right", Right, Some("TextInput")),
        KeyBinding::new("up", Up, Some("TextInput")),
        KeyBinding::new("down", Down, Some("TextInput")),
        KeyBinding::new("shift-left", SelectLeft, Some("TextInput")),
        KeyBinding::new("shift-right", SelectRight, Some("TextInput")),
        KeyBinding::new("home", Home, Some("TextInput")),
        KeyBinding::new("end", End, Some("TextInput")),
        KeyBinding::new("enter", Enter, Some("TextInput")),
        KeyBinding::new("cmd-a", SelectAll, Some("TextInput")),
        KeyBinding::new("cmd-v", Paste, Some("TextInput")),
        KeyBinding::new("cmd-c", Copy, Some("TextInput")),
        KeyBinding::new("cmd-x", Cut, Some("TextInput")),
        KeyBinding::new("ctrl-a", SelectAll, Some("TextInput")),
        KeyBinding::new("ctrl-v", Paste, Some("TextInput")),
        KeyBinding::new("ctrl-c", Copy, Some("TextInput")),
        KeyBinding::new("ctrl-x", Cut, Some("TextInput")),
    ]);
}

#[derive(Clone, Debug)]
pub enum InputEvent {
    Changed,
    Submit,
}

struct LineLayout {
    start: usize,
    shaped: ShapedLine,
}

pub struct TextInput {
    focus_handle: FocusHandle,
    content: String,
    placeholder: SharedString,
    min_lines: usize,
    masked: bool,
    mono: bool,
    selected_range: Range<usize>,
    selection_reversed: bool,
    marked_range: Option<Range<usize>>,
    layout: Vec<LineLayout>,
    bounds: Option<Bounds<Pixels>>,
    scroll_x: Pixels,
    is_selecting: bool,
}

impl EventEmitter<InputEvent> for TextInput {}

impl TextInput {
    pub fn new(cx: &mut Context<Self>, placeholder: &str) -> Self {
        Self {
            focus_handle: cx.focus_handle(),
            content: String::new(),
            placeholder: SharedString::from(placeholder.to_string()),
            min_lines: 1,
            masked: false,
            mono: false,
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            layout: Vec::new(),
            bounds: None,
            scroll_x: px(0.),
            is_selecting: false,
        }
    }

    pub fn multiline(mut self, lines: usize) -> Self {
        self.min_lines = lines.max(2);
        self
    }

    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }

    pub fn mono(mut self) -> Self {
        self.mono = true;
        self
    }

    pub fn text(&self) -> &str {
        &self.content
    }

    pub fn is_multiline(&self) -> bool {
        self.min_lines > 1
    }

    // Only repaints when the hint really changes, so calling it on every load is cheap.
    pub fn set_placeholder(&mut self, text: &str, cx: &mut Context<Self>) {
        if self.placeholder.as_ref() != text {
            self.placeholder = SharedString::from(text.to_string());
            cx.notify();
        }
    }

    pub fn set_text(&mut self, text: &str, cx: &mut Context<Self>) {
        self.content = text.to_string();
        let end = self.content.len();
        self.selected_range = end..end;
        self.marked_range = None;
        self.scroll_x = px(0.);
        cx.emit(InputEvent::Changed);
        cx.notify();
    }

    fn line_ranges(&self) -> Vec<Range<usize>> {
        let mut out = Vec::new();
        let mut start = 0;
        for line in self.content.split('\n') {
            out.push(start..start + line.len());
            start += line.len() + 1;
        }
        out
    }

    fn visible_lines(&self) -> usize {
        self.line_ranges().len().max(self.min_lines)
    }

    fn cursor_offset(&self) -> usize {
        if self.selection_reversed {
            self.selected_range.start
        } else {
            self.selected_range.end
        }
    }

    // Masked fields draw one bullet per character, so offsets are counted in characters.
    fn to_display(&self, text_start: usize, offset: usize) -> usize {
        if self.masked {
            self.content[text_start..offset].chars().count()
        } else {
            offset - text_start
        }
    }

    fn offset_for_display(&self, line: &Range<usize>, display: usize) -> usize {
        if self.masked {
            let text = &self.content[line.clone()];
            line.start
                + text
                    .char_indices()
                    .nth(display)
                    .map_or(text.len(), |(i, _)| i)
        } else {
            line.start + display.min(line.len())
        }
    }

    fn line_of(&self, offset: usize) -> usize {
        self.content[..offset.min(self.content.len())]
            .matches('\n')
            .count()
    }

    fn move_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        self.selected_range = offset..offset;
        self.selection_reversed = false;
        cx.notify();
    }

    fn select_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        if self.selection_reversed {
            self.selected_range.start = offset;
        } else {
            self.selected_range.end = offset;
        }
        if self.selected_range.end < self.selected_range.start {
            self.selection_reversed = !self.selection_reversed;
            self.selected_range = self.selected_range.end..self.selected_range.start;
        }
        cx.notify();
    }

    fn previous_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .rev()
            .find_map(|(i, _)| (i < offset).then_some(i))
            .unwrap_or(0)
    }

    fn next_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .find_map(|(i, _)| (i > offset).then_some(i))
            .unwrap_or(self.content.len())
    }

    fn left(&mut self, _: &Left, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.previous_boundary(self.cursor_offset()), cx);
        } else {
            self.move_to(self.selected_range.start, cx);
        }
    }

    fn right(&mut self, _: &Right, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.next_boundary(self.selected_range.end), cx);
        } else {
            self.move_to(self.selected_range.end, cx);
        }
    }

    // Up and down keep the cursor near the same x position on the neighbouring line.
    fn vertical(&mut self, delta: isize, cx: &mut Context<Self>) {
        let ranges = self.line_ranges();
        let cur = self.cursor_offset();
        let line = self.line_of(cur);
        let target = line as isize + delta;
        if target < 0 || target as usize >= ranges.len() {
            return;
        }
        let x = self
            .layout
            .get(line)
            .map_or(px(0.), |l| l.shaped.x_for_index(cur - l.start));
        let range = ranges[target as usize].clone();
        let local = self
            .layout
            .get(target as usize)
            .map_or(0, |l| l.shaped.closest_index_for_x(x));
        self.move_to(self.offset_for_display(&range, local), cx);
    }

    fn up(&mut self, _: &Up, _: &mut Window, cx: &mut Context<Self>) {
        self.vertical(-1, cx);
    }

    fn down(&mut self, _: &Down, _: &mut Window, cx: &mut Context<Self>) {
        self.vertical(1, cx);
    }

    fn select_left(&mut self, _: &SelectLeft, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.previous_boundary(self.cursor_offset()), cx);
    }

    fn select_right(&mut self, _: &SelectRight, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.next_boundary(self.cursor_offset()), cx);
    }

    fn select_all(&mut self, _: &SelectAll, _: &mut Window, cx: &mut Context<Self>) {
        self.selected_range = 0..self.content.len();
        self.selection_reversed = false;
        cx.notify();
    }

    fn home(&mut self, _: &Home, _: &mut Window, cx: &mut Context<Self>) {
        let ranges = self.line_ranges();
        let line = self.line_of(self.cursor_offset());
        self.move_to(ranges[line].start, cx);
    }

    fn end(&mut self, _: &End, _: &mut Window, cx: &mut Context<Self>) {
        let ranges = self.line_ranges();
        let line = self.line_of(self.cursor_offset());
        self.move_to(ranges[line].end, cx);
    }

    fn backspace(&mut self, _: &Backspace, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.select_to(self.previous_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn delete(&mut self, _: &Delete, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.select_to(self.next_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn enter(&mut self, _: &Enter, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_multiline() {
            self.replace_text_in_range(None, "\n", window, cx);
        } else {
            cx.emit(InputEvent::Submit);
        }
    }

    fn paste(&mut self, _: &Paste, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            let text = if self.is_multiline() {
                text
            } else {
                text.replace(['\n', '\r'], " ")
            };
            self.replace_text_in_range(None, text.trim_end_matches('\r'), window, cx);
        }
    }

    fn copy(&mut self, _: &Copy, _: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() && !self.masked {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
        }
    }

    fn cut(&mut self, _: &Cut, window: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() && !self.masked {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
            self.replace_text_in_range(None, "", window, cx);
        }
    }

    // Hit testing accounts for the horizontal scroll of single-line fields.
    fn index_for_position(&self, position: Point<Pixels>) -> usize {
        let Some(bounds) = self.bounds else { return 0 };
        let ranges = self.line_ranges();
        let row = ((position.y - bounds.top()) / px(LINE_HEIGHT))
            .floor()
            .max(0.0) as usize;
        let row = row.min(ranges.len() - 1);
        let x = position.x - bounds.left() + self.scroll_x;
        let local = self
            .layout
            .get(row)
            .map_or(0, |l| l.shaped.closest_index_for_x(x));
        self.offset_for_display(&ranges[row], local)
    }

    fn on_mouse_down(&mut self, ev: &MouseDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus_handle);
        self.is_selecting = true;
        let index = self.index_for_position(ev.position);
        if ev.modifiers.shift {
            self.select_to(index, cx);
        } else {
            self.move_to(index, cx);
        }
    }

    fn on_mouse_up(&mut self, _: &MouseUpEvent, _: &mut Window, _: &mut Context<Self>) {
        self.is_selecting = false;
    }

    fn on_mouse_move(&mut self, ev: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.is_selecting {
            self.select_to(self.index_for_position(ev.position), cx);
        }
    }

    fn offset_from_utf16(&self, offset: usize) -> usize {
        let (mut utf8, mut utf16) = (0, 0);
        for ch in self.content.chars() {
            if utf16 >= offset {
                break;
            }
            utf16 += ch.len_utf16();
            utf8 += ch.len_utf8();
        }
        utf8
    }

    fn offset_to_utf16(&self, offset: usize) -> usize {
        let (mut utf8, mut utf16) = (0, 0);
        for ch in self.content.chars() {
            if utf8 >= offset {
                break;
            }
            utf8 += ch.len_utf8();
            utf16 += ch.len_utf16();
        }
        utf16
    }

    fn range_to_utf16(&self, r: &Range<usize>) -> Range<usize> {
        self.offset_to_utf16(r.start)..self.offset_to_utf16(r.end)
    }

    fn range_from_utf16(&self, r: &Range<usize>) -> Range<usize> {
        self.offset_from_utf16(r.start)..self.offset_from_utf16(r.end)
    }

    // Every edit goes through here so listeners hear exactly one Changed event.
    fn apply(&mut self, range: Range<usize>, text: &str, cx: &mut Context<Self>) {
        self.content.replace_range(range.clone(), text);
        let end = range.start + text.len();
        self.selected_range = end..end;
        self.selection_reversed = false;
        cx.emit(InputEvent::Changed);
        cx.notify();
    }
}

// This lets the platform input method drive composition, dead keys and emoji pickers.
impl EntityInputHandler for TextInput {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<String> {
        let range = self.range_from_utf16(&range_utf16);
        actual_range.replace(self.range_to_utf16(&range));
        Some(self.content[range].to_string())
    }

    fn selected_text_range(
        &mut self,
        _: bool,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.range_to_utf16(&self.selected_range),
            reversed: self.selection_reversed,
        })
    }

    fn marked_text_range(&self, _: &mut Window, _: &mut Context<Self>) -> Option<Range<usize>> {
        self.marked_range.as_ref().map(|r| self.range_to_utf16(r))
    }

    fn unmark_text(&mut self, _: &mut Window, _: &mut Context<Self>) {
        self.marked_range = None;
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        self.marked_range = None;
        self.apply(range, new_text, cx);
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_utf16: Option<Range<usize>>,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        let start = range.start;
        self.apply(range, new_text, cx);
        self.marked_range = (!new_text.is_empty()).then(|| start..start + new_text.len());
        if let Some(sel) = new_selected_utf16 {
            let r = self.range_from_utf16(&sel);
            self.selected_range = r.start + start..r.end + start;
        }
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        bounds: Bounds<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let range = self.range_from_utf16(&range_utf16);
        let line = self.layout.get(self.line_of(range.start))?;
        let x0 = line
            .shaped
            .x_for_index(range.start.saturating_sub(line.start));
        let x1 = line
            .shaped
            .x_for_index(range.end.saturating_sub(line.start));
        Some(Bounds::from_corners(
            point(bounds.left() + x0 - self.scroll_x, bounds.top()),
            point(bounds.left() + x1 - self.scroll_x, bounds.bottom()),
        ))
    }

    fn character_index_for_point(
        &mut self,
        pt: Point<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<usize> {
        let index = self.index_for_position(pt);
        Some(self.offset_to_utf16(index))
    }
}

impl Focusable for TextInput {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

struct TextElement {
    input: Entity<TextInput>,
}

struct Prepaint {
    lines: Vec<LineLayout>,
    cursor: Option<PaintQuad>,
    selections: Vec<PaintQuad>,
    scroll_x: Pixels,
}

impl IntoElement for TextElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for TextElement {
    type RequestLayoutState = ();
    type PrepaintState = Prepaint;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&gpui::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let rows = self.input.read(cx).visible_lines();
        let mut style = Style::default();
        style.size.width = relative(1.).into();
        style.size.height = (window.line_height() * rows as f32).into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let input = self.input.read(cx);
        let style = window.text_style();
        let font_size = style.font_size.to_pixels(window.rem_size());
        let line_height = window.line_height();
        let showing_placeholder = input.content.is_empty();
        let color = if showing_placeholder {
            tint(DIM, 0.7).into()
        } else {
            style.color
        };
        let ranges = input.line_ranges();
        let mut lines = Vec::with_capacity(ranges.len());
        for range in &ranges {
            let text: String = if showing_placeholder {
                input.placeholder.to_string()
            } else if input.masked {
                "\u{2022}".repeat(input.content[range.clone()].chars().count())
            } else {
                input.content[range.clone()].to_string()
            };
            let mut runs = Vec::new();
            let base = TextRun {
                len: text.len(),
                font: style.font(),
                color,
                background_color: None,
                underline: None,
                strikethrough: None,
            };
            match input
                .marked_range
                .as_ref()
                .filter(|_| !input.masked && !showing_placeholder)
            {
                Some(m) if m.start >= range.start && m.end <= range.end => {
                    let (a, b) = (m.start - range.start, m.end - range.start);
                    let underline = UnderlineStyle {
                        color: Some(color),
                        thickness: px(1.0),
                        wavy: false,
                    };
                    runs.push(TextRun {
                        len: a,
                        ..base.clone()
                    });
                    runs.push(TextRun {
                        len: b - a,
                        underline: Some(underline),
                        ..base.clone()
                    });
                    runs.push(TextRun {
                        len: text.len() - b,
                        ..base.clone()
                    });
                    runs.retain(|r| r.len > 0);
                }
                _ if base.len > 0 => runs.push(base),
                _ => {}
            }
            let shaped = window
                .text_system()
                .shape_line(text.into(), font_size, &runs, None);
            lines.push(LineLayout {
                start: range.start,
                shaped,
            });
        }
        let cursor = input.cursor_offset();
        let cursor_line = input.line_of(cursor);
        let cursor_x = if showing_placeholder {
            px(0.)
        } else {
            let l = &lines[cursor_line];
            l.shaped.x_for_index(input.to_display(l.start, cursor))
        };
        let mut scroll_x = input.scroll_x;
        if !input.is_multiline() {
            let focused = input.focus_handle.is_focused(window);
            scroll_x = scroll_for(cursor_x, scroll_x, bounds.size.width, focused);
        }
        let mut selections = Vec::new();
        let sel = &input.selected_range;
        if !sel.is_empty() && !showing_placeholder {
            for (row, range) in ranges.iter().enumerate() {
                let (a, b) = (sel.start.max(range.start), sel.end.min(range.end));
                let spans_break = sel.start <= range.end && sel.end > range.end;
                if a > b || (a == b && !spans_break) {
                    continue;
                }
                let l = &lines[row];
                let x0 = l.shaped.x_for_index(input.to_display(l.start, a));
                let mut x1 = l.shaped.x_for_index(input.to_display(l.start, b));
                if spans_break {
                    x1 += px(6.);
                }
                let top = bounds.top() + line_height * row as f32;
                selections.push(fill(
                    Bounds::from_corners(
                        point(bounds.left() + x0 - scroll_x, top),
                        point(bounds.left() + x1 - scroll_x, top + line_height),
                    ),
                    tint(BLUE, 0.4),
                ));
            }
        }
        let top = bounds.top() + line_height * cursor_line as f32;
        let cursor_quad = sel.is_empty().then(|| {
            fill(
                Bounds::new(
                    point(bounds.left() + cursor_x - scroll_x, top),
                    size(px(1.5), line_height),
                ),
                c(TEXT),
            )
        });
        Prepaint {
            lines,
            cursor: cursor_quad,
            selections,
            scroll_x,
        }
    }

    fn paint(
        &mut self,
        _: Option<&GlobalElementId>,
        _: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _: &mut Self::RequestLayoutState,
        pre: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus = self.input.read(cx).focus_handle.clone();
        window.handle_input(
            &focus,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );
        for quad in pre.selections.drain(..) {
            window.paint_quad(quad);
        }
        let line_height = window.line_height();
        for (row, line) in pre.lines.iter().enumerate() {
            let origin = point(
                bounds.left() - pre.scroll_x,
                bounds.top() + line_height * row as f32,
            );
            // A glyph failure only drops this line for one frame, so painting carries on.
            let _ = line.shaped.paint(origin, line_height, window, cx);
        }
        if focus.is_focused(window)
            && let Some(cursor) = pre.cursor.take()
        {
            window.paint_quad(cursor);
        }
        let lines = std::mem::take(&mut pre.lines);
        let scroll_x = pre.scroll_x;
        self.input.update(cx, |input, _| {
            input.layout = lines;
            input.bounds = Some(bounds);
            input.scroll_x = scroll_x;
        });
    }
}

impl Render for TextInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus_handle.is_focused(window);
        let mut root = div()
            .key_context("TextInput")
            .track_focus(&self.focus_handle)
            .cursor(CursorStyle::IBeam)
            .on_action(cx.listener(Self::backspace))
            .on_action(cx.listener(Self::delete))
            .on_action(cx.listener(Self::left))
            .on_action(cx.listener(Self::right))
            .on_action(cx.listener(Self::up))
            .on_action(cx.listener(Self::down))
            .on_action(cx.listener(Self::select_left))
            .on_action(cx.listener(Self::select_right))
            .on_action(cx.listener(Self::select_all))
            .on_action(cx.listener(Self::home))
            .on_action(cx.listener(Self::end))
            .on_action(cx.listener(Self::enter))
            .on_action(cx.listener(Self::paste))
            .on_action(cx.listener(Self::cut))
            .on_action(cx.listener(Self::copy))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .w_full()
            .min_w(px(layout::INPUT_MIN_W))
            .bg(c(INPUT))
            .border_1()
            .border_color(if focused { c(ACCENT) } else { c(BORDER) })
            .rounded(px(CHIP_RADIUS))
            .px(px(10.))
            .py(px(space::XS + space::XXS))
            .overflow_hidden()
            .text_size(px(font::BASE))
            .line_height(px(LINE_HEIGHT))
            .text_color(c(TEXT));
        if self.mono {
            root = root.font_family(MONO);
        }
        // Clipping on the inner box keeps scrolled text out of the padding.
        root.child(
            div()
                .w_full()
                .overflow_hidden()
                .child(TextElement { input: cx.entity() }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unfocused_field_always_shows_its_start() {
        assert_eq!(scroll_for(px(300.), px(120.), px(100.), false), px(0.));
    }

    #[test]
    fn a_focused_field_keeps_the_caret_in_view() {
        assert_eq!(scroll_for(px(50.), px(0.), px(100.), true), px(0.));
        assert_eq!(scroll_for(px(300.), px(0.), px(100.), true), px(204.));
        assert_eq!(scroll_for(px(10.), px(204.), px(100.), true), px(10.));
        assert_eq!(scroll_for(px(250.), px(204.), px(100.), true), px(204.));
    }
}
