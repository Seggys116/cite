use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::app::{Console, new_input};
use crate::model::{PATHS_HINT, PATHS_LIMITS, clean_list, paths_match, paths_problem};
use crate::theme::{Tone, c};
use crate::ui::input::TextInput;
use crate::ui::widgets::{BtnKind, btn, id, pill, seg_item, seg_row, text_dim};

pub const MAX_PATH_ROWS: usize = 32;

// One routing path in the editor: a prefix or a regex, with its text in an input.
pub struct PathRow {
    pub regex: bool,
    pub input: Entity<TextInput>,
}

pub fn path_row(cx: &mut Context<Console>, regex: bool, text: &str) -> PathRow {
    let hint = if regex { "^/blog/[0-9]+$" } else { "/api" };
    let input = new_input(cx, hint, |i| i.mono());
    if !text.is_empty() {
        input.update(cx, |i, cx| i.set_text(text, cx));
    }
    PathRow { regex, input }
}

pub fn rows_from(
    cx: &mut Context<Console>,
    prefixes: &[String],
    regexes: &[String],
) -> Vec<PathRow> {
    let mut rows: Vec<PathRow> = prefixes.iter().map(|p| path_row(cx, false, p)).collect();
    rows.extend(regexes.iter().map(|r| path_row(cx, true, r)));
    rows
}

pub fn read_paths(rows: &[PathRow], cx: &Context<Console>) -> (Vec<String>, Vec<String>) {
    let (mut prefixes, mut regexes) = (Vec::new(), Vec::new());
    for row in rows {
        let text = row.input.read(cx).text().to_string();
        if row.regex {
            regexes.push(text);
        } else {
            prefixes.push(text);
        }
    }
    (prefixes, regexes)
}

pub fn clear_rows(rows: &mut Vec<PathRow>, cx: &mut Context<Console>) {
    for row in rows.drain(..) {
        row.input.update(cx, |i, cx| i.set_text("", cx));
    }
}

// Shared by the create wizard and the site page; `get` says where the page keeps its rows.
pub fn path_editor(
    rows: &[PathRow],
    key: &'static str,
    sample: Option<&Entity<TextInput>>,
    get: fn(&mut Console) -> &mut Vec<PathRow>,
    cx: &mut Context<Console>,
) -> AnyElement {
    let mut list = div().flex().flex_col().gap(px(8.));
    for (i, row) in rows.iter().enumerate() {
        let toggles = seg_row(vec![
            seg_item(id(key, format!("p{i}")), "Starts with", !row.regex)
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(r) = get(this).get_mut(i) {
                        r.regex = false;
                    }
                    cx.notify();
                }))
                .into_any_element(),
            seg_item(id(key, format!("r{i}")), "Matches regex", row.regex)
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(r) = get(this).get_mut(i) {
                        r.regex = true;
                    }
                    cx.notify();
                }))
                .into_any_element(),
        ]);
        list = list.child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(toggles)
                .child(div().flex_1().child(row.input.clone()))
                .child(
                    btn(id(key, format!("del{i}")), "Remove", BtnKind::Plain).on_click(
                        cx.listener(move |this, _, _, cx| {
                            let list = get(this);
                            if i < list.len() {
                                let gone = list.remove(i);
                                gone.input.update(cx, |t, cx| t.set_text("", cx));
                            }
                            cx.notify();
                        }),
                    ),
                ),
        );
    }
    if rows.is_empty() {
        list = list.child(text_dim("Every path is routed.").text_size(px(12.)));
    }
    let (prefixes, regexes) = read_paths(rows, cx);
    let (prefixes, regexes) = (clean_list(prefixes), clean_list(regexes));
    let mut col = div().flex().flex_col().gap(px(10.)).child(list);
    let add = if rows.len() < MAX_PATH_ROWS {
        btn(id(key, "add"), "Add path", BtnKind::Plain)
            .on_click(cx.listener(move |this, _, _, cx| {
                let row = path_row(cx, false, "");
                get(this).push(row);
                cx.notify();
            }))
            .into_any_element()
    } else {
        text_dim(format!("At most {MAX_PATH_ROWS} paths.")).into_any_element()
    };
    col = col.child(div().flex().child(add));
    if let Some(problem) = paths_problem(&prefixes, &regexes) {
        col = col.child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(pill("Invalid", Tone::Bad))
                .child(
                    text_dim(problem)
                        .text_size(px(12.))
                        .text_color(c(Tone::Bad.color())),
                ),
        );
    } else if let Some(sample) = sample {
        let text = sample.read(cx).text().to_string();
        let verdict = match paths_match(&prefixes, &regexes, &text) {
            Some(true) => Some(pill("Sample is routed", Tone::Ok)),
            Some(false) => Some(pill("Sample is not routed", Tone::Warn)),
            None => None,
        };
        col = col.child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(div().flex_1().child(sample.clone()))
                .children(verdict),
        );
    }
    col.child(text_dim(PATHS_HINT).text_size(px(12.)))
        .child(text_dim(PATHS_LIMITS).text_size(px(11.)))
        .into_any_element()
}
