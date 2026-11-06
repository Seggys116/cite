use std::future::Future;

use cite_client::{ArchiveEntry, ArchiveKind, ArchiveList, ClientError};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::run_archive_download;
use crate::app::{Confirm, Console, Load, new_input};
use crate::archive::{
    Busy, CutBasis, CutForm, CutGate, CutSpec, Preview, cut_done_text, download_name, fmt_dir,
    fmt_range, fmt_rows, kind_label, needs_confirm, preview_text, short_sha,
};
use crate::bots::{downloads_dir, fmt_stamp, is_unsupported};
use crate::demo::now_ms;
use crate::model::{fmt_bytes, fmt_int};
use crate::scope::{Sequence, foreign_notice};
use crate::theme::{DIM, Tone, c};
use crate::ui::input::TextInput;
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

impl Console {
    pub fn load_archives(&mut self, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            self.archives.list = Load::Idle;
            return;
        };
        if !matches!(self.archives.list, Load::Ready(_)) {
            self.archives.list = Load::Loading;
        }
        let seq = self.archives.list_seq.issue();
        self.fetch_scoped(
            cx,
            async move { h.archives().await },
            move |this, res, cx| {
                if !this.archives.list_seq.accept(seq) {
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
        self.archives.busy = busy;
        self.archives.note = None;
        self.fetch_origin(cx, fut, move |this, res, here, origin, cx| {
            this.archives.busy = Busy::Idle;
            if !here {
                let (text, tone) = match res {
                    Ok(_) => ("done".to_string(), Tone::Ok),
                    Err(e) => (op_error(&e), Tone::Bad),
                };
                this.say(
                    foreign_notice("Backup or archive task", origin, &text),
                    tone,
                );
                cx.notify();
                return;
            }
            match res {
                Ok(v) => done(this, v, cx),
                Err(e) => this.archives.note = Some((op_error(&e), Tone::Bad)),
            }
            cx.notify();
        });
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
        let Some(h) = self.active_handle() else {
            return;
        };
        self.run_archive_op(
            cx,
            Busy::Backup,
            async move { h.backup().await },
            |this, entry, cx| {
                this.archive_note(
                    format!(
                        "Backup {} created ({}).",
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
        let Some(h) = self.active_handle() else {
            return;
        };
        self.archives.gate.clear();
        self.run_archive_op(
            cx,
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
        if !needs_confirm(&spec) {
            self.do_cut(spec, cx);
            return;
        }
        let rows = self.archives.gate.preview().map_or(0, |p| p.rows);
        self.ask(Confirm {
            title: "Delete old data permanently".into(),
            message: format!(
                "{} rows older than {} will be deleted and no copy is kept. This cannot be undone.",
                fmt_int(rows),
                fmt_stamp(spec.cutoff_ms(now))
            ),
            label: "Delete data".into(),
            danger: true,
            action: Box::new(move |this, cx| this.do_cut(spec, cx)),
        });
    }

    fn do_cut(&mut self, spec: CutSpec, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        self.run_archive_op(
            cx,
            Busy::Cut,
            async move { h.cut(&spec, false).await },
            |this, report, cx| {
                let text = cut_done_text(
                    report.rows,
                    report.archived_rows,
                    &report.files,
                    report.archive,
                );
                this.archive_note(text, Tone::Ok);
                this.archives.gate.clear();
                this.archives.understood = false;
                this.refresh_storage(cx);
            },
        );
    }

    fn confirm_restore(&mut self, entry: ArchiveEntry) {
        let name = entry.name.clone();
        let message = if entry.kind == ArchiveKind::Backup {
            format!(
                "Restore the analytics database from {name}? Data recorded after the backup was made may be lost."
            )
        } else {
            format!(
                "Restore {name}? Its {} rows are added back to the analytics database.",
                fmt_rows(entry.rows)
            )
        };
        self.ask(Confirm {
            title: "Restore analytics data".into(),
            message,
            label: "Restore".into(),
            danger: false,
            action: Box::new(move |this, cx| {
                let Some(h) = this.active_handle() else {
                    return;
                };
                let (call, label) = (name.clone(), name.clone());
                this.run_archive_op(
                    cx,
                    Busy::Restore(name),
                    async move { h.restore(&call).await },
                    move |this, report, cx| {
                        this.archive_note(
                            format!("Restored {} rows from {label}.", fmt_int(report.rows)),
                            Tone::Ok,
                        );
                        this.refresh_storage(cx);
                    },
                );
            }),
        });
    }

    fn confirm_delete(&mut self, name: String) {
        self.ask(Confirm {
            title: "Delete from the node".into(),
            message: format!(
                "Delete {name} from the node? The file is removed and cannot be recovered."
            ),
            label: "Delete".into(),
            danger: true,
            action: Box::new(move |this, cx| {
                let Some(h) = this.active_handle() else {
                    return;
                };
                let (call, label) = (name.clone(), name.clone());
                this.run_archive_op(
                    cx,
                    Busy::Delete(name),
                    async move { h.delete_archive(&call).await },
                    move |this, _, cx| {
                        this.archive_note(format!("Deleted {label}."), Tone::Ok);
                        this.load_archives(cx);
                    },
                );
            }),
        });
    }

    // The file goes to the Downloads folder under a name built from the kind, never from the node's extension.
    fn start_download(&mut self, entry: ArchiveEntry, cx: &mut Context<Self>) {
        let Some(h) = self.active_handle() else {
            return;
        };
        let local = download_name(entry.kind, &entry.name);
        let Some(dir) = downloads_dir() else {
            self.archive_note(
                "Cannot find your home directory, so there is nowhere to save the file.",
                Tone::Bad,
            );
            return;
        };
        let name = entry.name.clone();
        self.run_archive_op(
            cx,
            Busy::Download(name.clone()),
            run_archive_download(h, name, dir, local),
            |this, report, _| {
                this.archive_note(
                    format!(
                        "Saved {} to {}",
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
        if a.unsupported {
            return card(
                Some("Backups and archives"),
                Some("Keep copies of old analytics data"),
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
        let subtitle = format!(
            "Copies of the analytics database and of data cut from it, on {}",
            self.active_name().unwrap_or_default()
        );
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
            CutBasis::Days => field(
                "Days to keep",
                Some("Data older than this is cut. 1 to 3650."),
                a.days.clone(),
            ),
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
            .child(div().child("Archive old data before deleting it"));
        let mut panel = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("Cut by", None, div().flex().child(seg_row(basis))))
            .child(div().w(px(280.)).child(input))
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
                        .child(div().child("I understand this deletes data permanently")),
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
