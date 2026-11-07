use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::app::{Confirm, Console, new_input};
use crate::certs::wipe;
use crate::siteops::{CAP_BUILD_ENV, CAP_RUNTIME_ENV, env_name, env_patch, has_cap};
use crate::theme::{DIVIDER, Tone, c};
use crate::ui::detail::Data;
use crate::ui::input::TextInput;
use crate::ui::widgets::{BtnKind, btn, btn_off, card, id, mono, strong, text_dim};

pub struct EnvRow {
    pub name: Entity<TextInput>,
    pub value: Entity<TextInput>,
}

impl EnvRow {
    fn new(cx: &mut Context<Console>) -> Self {
        Self {
            name: new_input(cx, "API_BASE_URL", |i| i.mono()),
            value: new_input(cx, "Value (never shown again)", |i| i.masked().mono()),
        }
    }
}

// The rows typed for one set of variables; they are sent together by one Save.
pub struct EnvRows {
    pub rows: Vec<EnvRow>,
}

impl EnvRows {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            rows: vec![EnvRow::new(cx)],
        }
    }

    // Back to one empty row; the dropped inputs take their typed values with them.
    pub fn reset(&mut self, cx: &mut Context<Console>) {
        self.rows.truncate(1);
        if self.rows.is_empty() {
            self.rows.push(EnvRow::new(cx));
        }
        for row in &self.rows {
            row.name.update(cx, |i, cx| i.set_text("", cx));
            row.value.update(cx, |i, cx| i.set_text("", cx));
        }
    }
}

pub struct EnvState {
    pub build: EnvRows,
    pub runtime: EnvRows,
}

impl EnvState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            build: EnvRows::new(cx),
            runtime: EnvRows::new(cx),
        }
    }

    pub fn rows(&mut self, runtime: bool) -> &mut EnvRows {
        if runtime {
            &mut self.runtime
        } else {
            &mut self.build
        }
    }

    fn rows_ref(&self, runtime: bool) -> &EnvRows {
        if runtime { &self.runtime } else { &self.build }
    }
}

// A name typed twice would silently keep only the last value, so it is refused before anything is sent.
pub fn duplicate_name(names: &[String]) -> Option<String> {
    let mut seen: Vec<String> = Vec::new();
    for n in names.iter().map(|n| env_name(n)).filter(|n| !n.is_empty()) {
        if seen.contains(&n) {
            return Some(n);
        }
        seen.push(n);
    }
    None
}

// The rows that will be sent: a row counts once it has a name.
pub fn named_rows(names: &[String]) -> usize {
    names.iter().filter(|n| !n.trim().is_empty()).count()
}

impl Console {
    fn env_handle(&self) -> Option<(crate::api::NodeHandle, String)> {
        let site = self.detail.data.ready()?.site.id.clone();
        Some((self.handle_named(&self.detail.node)?, site))
    }

    fn save_env_rows(&mut self, runtime: bool, cx: &mut Context<Self>) {
        let Some((h, site)) = self.env_handle() else {
            return;
        };
        let inputs: Vec<(Entity<TextInput>, Entity<TextInput>)> = self
            .ops
            .env
            .rows_ref(runtime)
            .rows
            .iter()
            .map(|r| (r.name.clone(), r.value.clone()))
            .collect();
        let names: Vec<String> = inputs
            .iter()
            .map(|(n, _)| n.read(cx).text().to_string())
            .collect();
        if let Some(twice) = duplicate_name(&names) {
            self.ops.error = Some(format!("{twice} is listed twice."));
            return;
        }
        let mut pairs: Vec<(String, String)> = inputs
            .iter()
            .zip(&names)
            .map(|((_, v), n)| (n.clone(), v.read(cx).text().to_string()))
            .collect();
        let patch = env_patch(runtime, &pairs, &[]);
        for (_, value) in pairs.iter_mut() {
            wipe(value);
        }
        let patch = match patch {
            Ok(p) => p,
            Err(e) => {
                self.ops.error = Some(e);
                return;
            }
        };
        let count = patch.set.len();
        let label = if runtime {
            "Runtime variables"
        } else {
            "Build variables"
        };
        let fut = async move { h.env_patch(&site, runtime, &patch).await };
        // The typed rows stay until the node has the values, so a failed save can be retried as typed.
        self.ops_action_then(
            cx,
            label,
            fut,
            move |_| {
                if count == 1 {
                    "1 variable saved. It applies on the next redeploy.".to_string()
                } else {
                    format!("{count} variables saved. They apply on the next redeploy.")
                }
            },
            move |this, cx| this.ops.env.rows(runtime).reset(cx),
        );
    }

    fn remove_env(&mut self, runtime: bool, name: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.env_handle() else {
            return;
        };
        let patch = match env_patch(runtime, &[], std::slice::from_ref(&name)) {
            Ok(p) => p,
            Err(e) => {
                self.ops.error = Some(e);
                return;
            }
        };
        let label = if runtime {
            "Runtime variable"
        } else {
            "Build variable"
        };
        let fut = async move { h.env_patch(&site, runtime, &patch).await };
        self.ops_action(cx, label, fut, move |_| {
            format!("{name} removed. It applies on the next redeploy.")
        });
    }

    fn env_section(&self, runtime: bool, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        let cap = if runtime {
            CAP_RUNTIME_ENV
        } else {
            CAP_BUILD_ENV
        };
        if !has_cap(&ex.caps, cap) {
            return None;
        }
        let names = if runtime {
            ex.runtime_env.as_ref()
        } else {
            ex.build_env.as_ref()
        };
        let key = if runtime { "runtime-env" } else { "build-env" };
        let mut list = div().flex().flex_col();
        match names {
            None => {
                list = list
                    .child(text_dim("The node did not list these variables.").text_size(px(12.)))
            }
            Some(n) if n.is_empty() => {
                list = list.child(text_dim("No variables are set.").text_size(px(12.)))
            }
            Some(n) => {
                for name in n {
                    let drop_name = name.clone();
                    list = list.child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(10.))
                            .py(px(6.))
                            .border_b_1()
                            .border_color(c(DIVIDER))
                            .child(div().flex_1().min_w_0().child(mono(name.clone())))
                            .child(text_dim("value hidden").text_size(px(11.)))
                            .child(btn(id(key, name), "Remove", BtnKind::Danger).on_click(
                                cx.listener(move |this, _, _, cx| {
                                    let victim = drop_name.clone();
                                    this.ask(Confirm {
                                        title: "Remove variable".into(),
                                        message: format!(
                                            "Remove {victim}? It stops applying on the next redeploy."
                                        ),
                                        label: "Remove".into(),
                                        danger: true,
                                        action: Box::new(move |this, cx| {
                                            this.remove_env(runtime, victim, cx)
                                        }),
                                    });
                                    cx.notify();
                                }),
                            )),
                    );
                }
            }
        }
        let rows = &self.ops.env.rows_ref(runtime).rows;
        let typed: Vec<String> = rows
            .iter()
            .map(|r| r.name.read(cx).text().to_string())
            .collect();
        let mut editor = div().flex().flex_col().gap(px(8.)).child(
            div()
                .flex()
                .gap(px(12.))
                .child(div().flex_1().child(strong("Name").text_size(px(12.))))
                .child(div().flex_1().child(strong("Value").text_size(px(12.))))
                .child(div().w(px(76.)).flex_none()),
        );
        let single = rows.len() == 1;
        for (i, row) in rows.iter().enumerate() {
            let drop = if single {
                btn_off("Remove").into_any_element()
            } else {
                btn(id(&format!("{key}-row-drop"), i), "Remove", BtnKind::Plain)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let rows = &mut this.ops.env.rows(runtime).rows;
                        if i < rows.len() && rows.len() > 1 {
                            rows.remove(i);
                        }
                        cx.notify();
                    }))
                    .into_any_element()
            };
            editor = editor.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .child(div().flex_1().min_w_0().child(row.name.clone()))
                    .child(div().flex_1().min_w_0().child(row.value.clone()))
                    .child(div().w(px(76.)).flex_none().child(drop)),
            );
        }
        let ready = !self.ops.busy && named_rows(&typed) > 0;
        let save = if ready {
            btn(id(key, "save"), "Save variables", BtnKind::Primary)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.save_env_rows(runtime, cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Save variables").into_any_element()
        };
        let add = btn(id(key, "add-row"), "Add row", BtnKind::Plain).on_click(cx.listener(
            move |this, _, _, cx| {
                let row = EnvRow::new(cx);
                this.ops.env.rows(runtime).rows.push(row);
                cx.notify();
            },
        ));
        let (title, sub) = if runtime {
            (
                "Runtime variables",
                "Read by the running site. Names are listed; values are write-only and never shown again.",
            )
        } else {
            (
                "Build variables",
                "Available while the site installs and builds. Names are listed; values are write-only and never shown again.",
            )
        };
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(list)
            .child(editor)
            .child(div().flex().gap(px(8.)).child(add).child(save))
            .child(
                text_dim("Upper case letters, digits and _. Changes apply on the next redeploy.")
                    .text_size(px(11.)),
            );
        Some(card(Some(title), Some(sub), body).into_any_element())
    }

    pub(crate) fn env_tab(&self, data: &Data, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let mut out = Vec::new();
        out.extend(self.env_section(false, cx));
        out.extend(self.env_section(true, cx));
        if let Some(card) = self.doppler_card(data, cx) {
            out.push(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .pt(px(8.))
                    .child(strong("Doppler").text_size(px(16.)))
                    .child(
                        text_dim("Sync this site's variables from a Doppler config with a service token instead of typing them.")
                            .text_size(px(12.)),
                    )
                    .into_any_element(),
            );
            out.push(card);
        }
        if out.is_empty() {
            out.push(
                text_dim("This node does not offer build or runtime variables.")
                    .text_color(c(Tone::Muted.color()))
                    .into_any_element(),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_typed_twice_is_found_whatever_its_case() {
        let names = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            duplicate_name(&names(&["API", " api "])),
            Some("API".into())
        );
        assert_eq!(duplicate_name(&names(&["A", "B", ""])), None);
        assert_eq!(duplicate_name(&names(&["", ""])), None);
        assert_eq!(named_rows(&names(&["A", " ", ""])), 1);
        assert_eq!(named_rows(&[]), 0);
    }
}
