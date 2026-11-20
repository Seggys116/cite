use std::future::Future;

use cite_client::{ArchiveEntry, ArchiveKind, ArchiveList, ClientError};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, run_archive_download};
use crate::app::{Confirm, Console, Load, View, new_input};
use crate::archive::{
    Busy, CutBasis, CutForm, CutGate, CutSpec, Preview, cut_done_text, download_name, fmt_dir,
    fmt_range, fmt_rows, kind_label, needs_confirm, preview_text, short_sha,
};
use crate::bots::{downloads_dir, fmt_stamp, is_unsupported};
use crate::demo::now_ms;
use crate::model::{fmt_bytes, fmt_int};
use crate::scope::Sequence;
use crate::theme::{DIM, Tone, c};
use crate::ui::bots::ExportRun;
use crate::ui::input::TextInput;
use crate::ui::nodescope::{choose_node_notice, failed_on, no_node_notice, on_node};
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, checkbox, clip, field, id, mono, notice, pill, seg_item,
    seg_row, skeleton, table, text_dim, toggle,
};

pub struct State {
    pub list: Load<ArchiveList>,
    pub list_seq: Sequence,
    pub unsupported: bool,
    pub busy: Busy,
    pub note: Option<(String, Tone)>,
    pub cut_open: bool,
    pub basis: CutBasis,
    pub archive: bool,
    pub understood: bool,
    pub gate: CutGate,
    pub days: Entity<TextInput>,
    pub date: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            list: Load::Idle,
            list_seq: Sequence::default(),
            unsupported: false,
            busy: Busy::Idle,
            note: None,
            cut_open: false,
            basis: CutBasis::Days,
            archive: true,
            understood: false,
            gate: CutGate::default(),
            days: new_input(cx, "365", |i| i.mono()),
            date: new_input(cx, "2026-01-31 12:00", |i| i.mono()),
        }
    }
}

fn op_error(err: &ClientError) -> String {
    if is_unsupported(err) {
        "This node does not support archives and backups yet. Update the node to a newer release."
            .to_string()
    } else {
        err.to_string()
    }
}

// What an operation is called in a message that names the node it ran on.
fn busy_noun(busy: &Busy) -> &'static str {
    match busy {
        Busy::Idle => "Operation",
        Busy::Backup => "Backup",
        Busy::Preview => "Cut preview",
        Busy::Cut => "Cut",
        Busy::Restore(_) => "Restore",
        Busy::Delete(_) => "Archive deletion",
        Busy::Download(_) => "Download",
    }
}

impl Console {
    // The node the Explore and Export tabs act on, and its connection when it is reachable.
    pub(crate) fn explore_node(&self) -> Option<String> {
        self.scoped_node(&self.bots.scope)
    }

    pub(crate) fn explore_handle(&self) -> Option<NodeHandle> {
        self.scoped_handle(&self.bots.scope)
    }

    // Picking a node on the bar drops what was loaded or previewed for the old one.
    pub(crate) fn choose_explore_node(&mut self, name: String, cx: &mut Context<Self>) {
        if self.explore_node().as_deref() == Some(name.as_str()) {
            return;
        }
        let selected = self.selected.clone();
        self.bots.scope.choose(&name, selected.as_deref());
        self.archives.list = Load::Idle;
        self.archives.unsupported = false;
        self.archives.note = None;
        self.archives.gate.clear();
        self.archives.understood = false;
        if !matches!(self.bots.export.run, ExportRun::Running { .. }) {
            self.bots.export.run = ExportRun::Idle;
        }
        // Nothing on the Explore tab loads until a node is chosen, so a pick loads all of it.
        if self.view == View::Explore {
            self.load_explore(cx);
        }
    }

    pub fn load_archives(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.explore_handle() else {
            self.archives.list = Load::Idle;
            return;
        };
        if !matches!(self.archives.list, Load::Ready(_)) {
            self.archives.list = Load::Loading;
        }
        let node = h.name().to_string();
        let seq = self.archives.list_seq.issue();
        self.fetch_scoped(
            cx,
            async move { h.archives().await },
            move |this, res, cx| {
                if this.explore_node().as_deref() != Some(node.as_str())
                    || !this.archives.list_seq.accept(seq)
                {
                    return;
                }
                this.archives.unsupported = false;
                this.archives.list = match res {
                    Ok(list) => Load::Ready(list),
                    Err(e) if is_unsupported(&e) => {
                        this.archives.unsupported = true;
                        Load::Idle
                    }
                    Err(e) => Load::Failed(e.to_string()),
                };
                cx.notify();
            },
        );
    }

    // One operation at a time: a second click while one runs is ignored.
    fn run_archive_op<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        node: &str,
        busy: Busy,
        fut: F,
        done: impl FnOnce(&mut Self, T, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        if !self.archives.busy.is_idle() {
            return;
        }
        let (noun, name) = (busy_noun(&busy), node.to_string());
        self.archives.busy = busy;
        self.archives.note = None;
        self.fetch_on(
            cx,
            node,
            Self::explore_node,
            fut,
            move |this, res, here, cx| {
                this.archives.busy = Busy::Idle;
                if !here {
                    let (text, tone) = match res {
                        Ok(_) => (on_node(&format!("{noun} finished"), &name), Tone::Ok),
                        Err(e) => (failed_on(noun, &name, &op_error(&e)), Tone::Bad),
                    };
                    this.say(text, tone);
                    cx.notify();
                    return;
                }
                match res {
                    Ok(v) => done(this, v, cx),
                    Err(e) => {
                        this.archives.note =
                            Some((failed_on(noun, &name, &op_error(&e)), Tone::Bad))
                    }
                }
                cx.notify();
            },
        );
    }

    fn archive_note(&mut self, text: impl Into<String>, tone: Tone) {
        self.archives.note = Some((text.into(), tone));
    }

    fn refresh_storage(&mut self, cx: &mut Context<Self>) {
        self.load_storage(cx);
        self.load_archives(cx);
    }

    fn cut_form(&self, cx: &Context<Self>) -> CutForm {
        let a = &self.archives;
        CutForm {
            basis: a.basis,
            days: a.days.read(cx).text().to_string(),
            date: a.date.read(cx).text().to_string(),
            archive: a.archive,
        }
    }

    fn start_backup(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.explore_handle() else {
            return;
        };
        let node = h.name().to_string();
        let target = node.clone();
        self.run_archive_op(
            cx,
            &target,
            Busy::Backup,
            async move { h.backup().await },
            move |this, entry, cx| {
                this.archive_note(
                    format!(
                        "Backup {} created on {node} ({}).",
                        entry.name,
                        fmt_bytes(entry.bytes)
                    ),
                    Tone::Ok,
                );
                this.load_archives(cx);
            },
        );
    }

    fn preview_cut(&mut self, cx: &mut Context<Self>) {
        let spec = match self.cut_form(cx).spec(now_ms()) {
            Ok(s) => s,
            Err(msg) => {
                self.archive_note(msg, Tone::Bad);
                return;
            }
        };
        let Some(h) = self.explore_handle() else {
            return;
        };
        let node = h.name().to_string();
        self.archives.gate.clear();
        self.run_archive_op(
            cx,
            &node,
            Busy::Preview,
            async move { h.cut(&spec, true).await },
            move |this, report, _| {
                this.archives.gate.record(Preview {
                    spec,
                    rows: report.rows,
                    oldest_ms: report.oldest_ms,
                });
            },
        );
    }

    fn run_cut(&mut self, cx: &mut Context<Self>) {
        let now = now_ms();
        let Ok(spec) = self.cut_form(cx).spec(now) else {
            return;
        };
        if let Err(block) = self.archives.gate.check(&spec, self.archives.understood) {
            self.archive_note(block.hint(), Tone::Warn);
            return;
        }
        let Some(node) = self.explore_node() else {
            return;
        };
        if !needs_confirm(&spec) {
            self.do_cut(spec, node, cx);
            return;
        }
        let rows = self.archives.gate.preview().map_or(0, |p| p.rows);
        self.ask(Confirm {
            title: "Delete old data permanently".into(),
            message: format!(
                "{} rows older than {} will be deleted from {node} and no copy is kept. This cannot be undone.",
                fmt_int(rows),
                fmt_stamp(spec.cutoff_ms(now))
            ),
            label: "Delete data".into(),
            danger: true,
            action: Box::new(move |this, cx| this.do_cut(spec, node, cx)),
        });
    }

    // The node is the one the preview and any confirmation named, looked up by name.
    fn do_cut(&mut self, spec: CutSpec, node: String, cx: &mut Context<Self>) {
        let Some(h) = self.handle_named(&node) else {
            self.say(format!("{node} is not connected."), Tone::Bad);
            return;
        };
        let named = node.clone();
        self.run_archive_op(
            cx,
            &node,
            Busy::Cut,
            async move { h.cut(&spec, false).await },
            move |this, report, cx| {
                let text = cut_done_text(
                    report.rows,
                    report.archived_rows,
                    &report.files,
                    report.archive,
                );
                this.archive_note(on_node(&text, &named), Tone::Ok);
                this.archives.gate.clear();
                this.archives.understood = false;
                this.refresh_storage(cx);
            },
        );
    }

    fn confirm_restore(&mut self, entry: ArchiveEntry) {
        let Some(node) = self.explore_node() else {
            return;
        };
        let name = entry.name.clone();
        let message = if entry.kind == ArchiveKind::Backup {
            format!(
                "Restore the analytics database on {node} from {name}? Data recorded after the backup was made may be lost."
            )
        } else {
            format!(
                "Restore {name} on {node}? Its {} rows are added back to the analytics database.",
                fmt_rows(entry.rows)
            )
        };
        self.ask(Confirm {
            title: "Restore analytics data".into(),
            message,
            label: "Restore".into(),
            danger: false,
            action: Box::new(move |this, cx| {
                let Some(h) = this.handle_named(&node) else {
                    this.say(format!("{node} is not connected."), Tone::Bad);
                    return;
                };
                let (call, label) = (name.clone(), name.clone());
                let named = node.clone();
                this.run_archive_op(
                    cx,
                    &node,
                    Busy::Restore(name),
                    async move { h.restore(&call).await },
                    move |this, report, cx| {
                        this.archive_note(
                            format!(
                                "Restored {} rows from {label} on {named}.",
                                fmt_int(report.rows)
                            ),
                            Tone::Ok,
                        );
                        this.refresh_storage(cx);
                    },
                );
            }),
        });
    }

    fn confirm_delete(&mut self, name: String) {
        let Some(node) = self.explore_node() else {
            return;
        };
        self.ask(Confirm {
            title: "Delete archive".into(),
            message: format!(
                "Delete {name} from {node}? The file is removed and cannot be recovered."
            ),
            label: "Delete".into(),
            danger: true,
            action: Box::new(move |this, cx| {
                let Some(h) = this.handle_named(&node) else {
                    this.say(format!("{node} is not connected."), Tone::Bad);
                    return;
                };
                let (call, label) = (name.clone(), name.clone());
                let named = node.clone();
                this.run_archive_op(
                    cx,
                    &node,
                    Busy::Delete(name),
                    async move { h.delete_archive(&call).await },
                    move |this, _, cx| {
                        this.archive_note(format!("Deleted {label} from {named}."), Tone::Ok);
                        this.load_archives(cx);
                    },
                );
            }),
        });
    }

    // The file goes to the Downloads folder under a name built from the kind, never from the node's extension.
    fn start_download(&mut self, entry: ArchiveEntry, cx: &mut Context<Self>) {
        let Some(h) = self.explore_handle() else {
            return;
        };
        let node = h.name().to_string();
        let local = download_name(entry.kind, &entry.name);
        let Some(dir) = downloads_dir() else {
            self.archive_note(
                "Cannot find your home directory, so there is nowhere to save the file.",
                Tone::Bad,
            );
            return;
        };
        let name = entry.name.clone();
        let target = node.clone();
        self.run_archive_op(
            cx,
            &target,
            Busy::Download(name.clone()),
            run_archive_download(h, name, dir, local),
            move |this, report, _| {
                this.archive_note(
                    format!(
                        "Saved {} from {node} to {}",
                        fmt_bytes(report.bytes),
                        report.path.display()
                    ),
                    Tone::Ok,
                );
            },
        );
    }

    pub fn archive_card(&self, cx: &mut Context<Self>) -> AnyElement {
        let a = &self.archives;
        let Some(node) = self.explore_node() else {
            return choose_node_notice().into_any_element();
        };
        if self.explore_handle().is_none() {
            return no_node_notice(Some(&node)).into_any_element();
        }
        if a.unsupported {
            return card(
                Some("Backups and archives"),
                None,
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(pill("needs an update", Tone::Warn))
                    .child(
                        text_dim("This node predates backups and archives. Update it to use them.")
                            .text_size(px(12.)),
                    ),
            )
            .into_any_element();
        }
        let list = match &a.list {
            Load::Idle | Load::Loading => return skeleton(120.).into_any_element(),
            Load::Failed(msg) => {
                let msg = msg.clone();
                return self.error_block(cx, &msg);
            }
            Load::Ready(list) => list,
        };
        let idle = a.busy.is_idle();
        let backup = if idle {
            btn(id("arc", "backup"), "Back up now", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.start_backup(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Back up now").into_any_element()
        };
        let cut_label = if a.cut_open {
            "Hide cut options"
        } else {
            "Cut old data"
        };
        let cut = btn(id("arc", "cut-toggle"), cut_label, BtnKind::Plain).on_click(cx.listener(
            |this, _, _, cx| {
                this.archives.cut_open = !this.archives.cut_open;
                cx.notify();
            },
        ));
        let mut body = div().flex().flex_col().gap(px(12.)).child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(backup)
                .child(cut)
                .child(text_dim(fmt_dir(list.items.len(), list.dir_bytes)).text_size(px(12.))),
        );
        if a.cut_open {
            body = body.child(self.cut_panel(cx));
        }
        if let Some(label) = a.busy.label() {
            body = body.child(notice(&label, Tone::Info));
        }
        if let Some((text, tone)) = &a.note {
            body = body.child(notice(text, *tone));
        }
        body = body.child(self.archive_table(list, cx));
        let subtitle = format!("Stored on {node}");
        card(Some("Backups and archives"), Some(subtitle.as_str()), body).into_any_element()
    }

    fn archive_table(&self, list: &ArchiveList, cx: &mut Context<Self>) -> AnyElement {
        let idle = self.archives.busy.is_idle();
        let mut rows: Vec<Vec<AnyElement>> = Vec::new();
        for entry in &list.items {
            let name_cell = div()
                .flex()
                .flex_col()
                .min_w_0()
                .child(
                    clip(entry.name.clone())
                        .font_family(crate::theme::MONO)
                        .text_size(px(12.)),
                )
                .children(
                    fmt_range(entry.from_ms, entry.to_ms)
                        .map(|r| text_dim(format!("covers {r}")).text_size(px(11.))),
                );
            let actions = if idle {
                self.entry_actions(entry, cx)
            } else {
                div()
                    .flex()
                    .gap(px(6.))
                    .child(btn_off("Download"))
                    .child(btn_off("Restore"))
                    .child(btn_off("Delete"))
                    .into_any_element()
            };
            rows.push(vec![
                name_cell.into_any_element(),
                text_dim(kind_label(entry.kind)).into_any_element(),
                mono(fmt_bytes(entry.bytes)).into_any_element(),
                text_dim(fmt_stamp(entry.created_ms)).into_any_element(),
                mono(short_sha(&entry.sha256))
                    .text_color(c(DIM))
                    .into_any_element(),
                mono(fmt_rows(entry.rows)).into_any_element(),
                actions,
            ]);
        }
        let cols = [
            Col::flex("Name"),
            Col::fixed("Kind", 70.),
            Col::fixed("Size", 80.).right(),
            Col::fixed("Created", 150.),
            Col::fixed("SHA-256", 110.),
            Col::fixed("Rows", 90.).right(),
            Col::fixed("", 250.),
        ];
        table(
            &cols,
            rows,
            Some(text_dim("No backups or archives yet.").p(px(12.))),
        )
        .into_any_element()
    }

    fn entry_actions(&self, entry: &ArchiveEntry, cx: &mut Context<Self>) -> AnyElement {
        let dl = entry.clone();
        let e = entry.clone();
        let name = entry.name.clone();
        div()
            .flex()
            .gap(px(6.))
            .child(
                btn(id("arc-dl", &entry.name), "Download", BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.start_download(dl.clone(), cx);
                        cx.notify();
                    },
                )),
            )
            .child(
                btn(id("arc-rs", &entry.name), "Restore", BtnKind::Plain).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.confirm_restore(e.clone());
                        cx.notify();
                    },
                )),
            )
            .child(
                btn(id("arc-rm", &entry.name), "Delete", BtnKind::Danger).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.confirm_delete(name.clone());
                        cx.notify();
                    },
                )),
            )
            .into_any_element()
    }

    fn cut_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let a = &self.archives;
        let now = now_ms();
        let spec = self.cut_form(cx).spec(now);
        let mut basis = Vec::new();
        for (which, label) in [
            (CutBasis::Days, "Older than N days"),
            (CutBasis::Date, "Before a date"),
        ] {
            basis.push(
                seg_item(id("cut-basis", label), label, a.basis == which)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.archives.basis = which;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let input = match a.basis {
            CutBasis::Days => field("Days to keep", Some("1 to 3650."), a.days.clone()),
            CutBasis::Date => field(
                "Cut data before (UTC)",
                Some("YYYY-MM-DD or YYYY-MM-DD HH:MM"),
                a.date.clone(),
            ),
        };
        let archive_row = div()
            .flex()
            .items_center()
            .gap(px(10.))
            .child(
                toggle(id("cut", "archive"), a.archive).on_click(cx.listener(|this, _, _, cx| {
                    this.archives.archive = !this.archives.archive;
                    cx.notify();
                })),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child("Archive old data before deleting it"),
            );
        let mut panel = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("Cut by", None, div().flex().child(seg_row(basis))))
            .child(div().flex().flex_col().w(px(280.)).child(input))
            .child(archive_row);
        if !a.archive {
            panel = panel
                .child(notice(
                    "Without an archive, the data that is cut is deleted for good.",
                    Tone::Bad,
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .child(checkbox(id("cut", "understood"), a.understood).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.archives.understood = !this.archives.understood;
                                cx.notify();
                            }),
                        ))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child("I understand this deletes data permanently"),
                        ),
                );
        }
        let mut hint = None;
        match &spec {
            Ok(spec) => {
                if let Some(p) = a.gate.preview().filter(|p| p.spec == *spec) {
                    panel = panel.child(notice(
                        &preview_text(p.rows, p.oldest_ms, spec.cutoff_ms(now), spec.archive),
                        Tone::Info,
                    ));
                }
                if let Err(block) = a.gate.check(spec, a.understood) {
                    hint = Some(block.hint().to_string());
                }
            }
            Err(msg) => hint = Some(msg.clone()),
        }
        let idle = a.busy.is_idle();
        let preview = if idle && spec.is_ok() {
            btn(id("cut", "preview"), "Preview", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.preview_cut(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Preview").into_any_element()
        };
        let can_cut = idle && spec.is_ok() && hint.is_none();
        let cut = if can_cut {
            let kind = if a.archive {
                BtnKind::Primary
            } else {
                BtnKind::Danger
            };
            btn(id("cut", "run"), "Cut", kind)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.run_cut(cx);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            btn_off("Cut").into_any_element()
        };
        panel
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(preview)
                    .child(cut)
                    .children(hint.map(|h| text_dim(h).text_size(px(12.)))),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_has_a_name_for_messages() {
        let all = [
            Busy::Backup,
            Busy::Preview,
            Busy::Cut,
            Busy::Restore("a".into()),
            Busy::Delete("a".into()),
            Busy::Download("a".into()),
        ];
        let mut nouns: Vec<&str> = all.iter().map(busy_noun).collect();
        nouns.sort_unstable();
        nouns.dedup();
        assert_eq!(nouns.len(), all.len());
        assert_eq!(busy_noun(&Busy::Idle), "Operation");
    }

    #[test]
    fn a_failed_operation_names_the_node_it_ran_on() {
        let text = failed_on(busy_noun(&Busy::Cut), "edge-fra", "refused");
        assert_eq!(text, "Cut failed on edge-fra: refused");
    }
}
