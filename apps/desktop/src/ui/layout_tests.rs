// Headless layout checks on the demo console: the text area of every input must span its box.

use std::time::{Duration, Instant};

use gpui::{
    Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, TestAppContext,
    VisualTestContext, Window, div, px, size,
};

use cite_client::TransferPhase;
use cite_edge::datamodel::PgMode;
use cite_edge::datawire::SessionState;

use crate::app::{Console, Options, View};
use crate::theme::space;
use crate::ui::databases::DbLoad;
use crate::ui::dataview::XferAction;
use crate::ui::detail::data::DataLoad;
use crate::ui::detail::tabs::SiteTab;
use crate::ui::input::TextInput;
use crate::ui::widgets::{ClipLayout, ClipText, clip_with};
use crate::window_state::WindowState;

// Input padding and border on both sides.
const INSET: f32 = 22.0;

fn open_docs(cx: &mut TestAppContext, width: f32) -> (Entity<Console>, &mut VisualTestContext) {
    open_site(cx, "", width)
}

// The docs page of a named demo node; an empty name is the first node.
fn open_site<'a>(
    cx: &'a mut TestAppContext,
    node: &str,
    width: f32,
) -> (Entity<Console>, &'a mut VisualTestContext) {
    cx.update(crate::ui::init);
    let opts = Options {
        demo: true,
        view: Some(View::SiteDetail {
            node: node.to_string(),
            id: "docs".into(),
        }),
        select: None,
        inspect: false,
        scroll_end: false,
    };
    let (console, cx) =
        cx.add_window_view(|w, cx| Console::new(opts, WindowState::default(), w, cx));
    cx.simulate_resize(size(px(width), px(900.)));
    // Demo replies come from the IO runtime's threads, so the test waits on them for real.
    cx.executor().allow_parking();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        cx.run_until_parked();
        let ready = console.read_with(cx, |c, _| c.detail.data.ready().is_some() && c.ops.loaded);
        if ready {
            break;
        }
        assert!(Instant::now() < deadline, "demo site never loaded");
        std::thread::sleep(Duration::from_millis(10));
    }
    (console, cx)
}

fn text_width(cx: &mut VisualTestContext, input: &Entity<TextInput>) -> f32 {
    input.update(cx, |i, _| i.take_bounds());
    cx.update(|w, cx| w.draw(cx).clear());
    let bounds = input.update(cx, |i, _| i.take_bounds());
    f32::from(bounds.expect("input painted").size.width)
}

fn assert_near(a: f32, b: f32, what: &str) {
    assert!((a - b).abs() <= 1.0, "{what}: {a} vs {b}");
}

#[gpui::test]
fn build_tab_inputs_span_their_boxes(cx: &mut TestAppContext) {
    for width in [1000.0, 1280.0, 1600.0] {
        let (console, cx) = open_docs(cx, width);
        console.update(cx, |c, cx| c.select_tab(SiteTab::Build, cx));
        cx.run_until_parked();
        let (repo, branch, health, interval, root_dir, memory, cpus) =
            console.read_with(cx, |c, _| {
                let e = &c.detail.edit;
                (
                    e.repo.clone(),
                    e.branch.clone(),
                    e.health.clone(),
                    e.health_interval.clone(),
                    e.build.root_dir.clone(),
                    e.build.memory_mb.clone(),
                    e.build.cpus.clone(),
                )
            });
        // Two form_grid cells and their gap span the card, which gives the column width.
        let pair = text_width(cx, &memory);
        assert_near(text_width(cx, &cpus), pair, "grid cells");
        assert!(
            text_width(cx, &root_dir) >= pair - 1.0,
            "root dir narrower than a grid cell"
        );
        let column = 2.0 * (pair + INSET) + space::MD;
        let full = column - INSET;
        assert_near(text_width(cx, &repo), full, "repository");
        assert_near(text_width(cx, &branch), full, "branch");
        assert_near(text_width(cx, &health), full, "health path");
        // Four equal cells with 12px gaps share the health row.
        let cell = (column - 3.0 * 12.0) / 4.0 - INSET;
        assert_near(text_width(cx, &interval), cell, "health interval");
    }
}

#[gpui::test]
fn overview_inputs_beside_buttons_fill_their_rows(cx: &mut TestAppContext) {
    for width in [1000.0, 1280.0, 1600.0] {
        let (console, cx) = open_docs(cx, width);
        let (memory, note, git_ref) = console.read_with(cx, |c, _| {
            (
                c.detail.edit.build.memory_mb.clone(),
                c.detail.note.clone(),
                c.ops.git_ref.clone(),
            )
        });
        let note_w = text_width(cx, &note);
        let ref_w = text_width(cx, &git_ref);
        console.update(cx, |c, cx| c.select_tab(SiteTab::Build, cx));
        cx.run_until_parked();
        let column = 2.0 * (text_width(cx, &memory) + INSET) + space::MD;
        // A row keeps room only for its button, so the input takes well over half the card.
        assert!(
            note_w > column * 0.6,
            "release note input is {note_w} of {column}"
        );
        assert!(ref_w > column * 0.6, "ref input is {ref_w} of {column}");
    }
}

// A clipped line in a 300px cell: the node card's flex column, and a table cell.
struct ClipProbe {
    text: &'static str,
    table_cell: bool,
    shown: Option<ClipLayout>,
}

impl Render for ClipProbe {
    fn render(&mut self, _w: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let text = ClipText::new(self.text);
        self.shown = Some(text.layout().clone());
        let cell = if self.table_cell {
            div()
                .flex()
                .items_center()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
        } else {
            div().flex().flex_col().flex_1().min_w_0()
        };
        div()
            .size_full()
            .child(div().flex().w(px(300.)).child(cell.child(clip_with(text))))
    }
}

fn shown_clip(
    cx: &mut TestAppContext,
    text: &'static str,
    table_cell: bool,
) -> (SharedString, f32, f32) {
    let (probe, cx) = cx.add_window_view(|_, _| ClipProbe {
        text,
        table_cell,
        shown: None,
    });
    cx.update(|w, cx| w.draw(cx).clear());
    let (shown, bounds) = probe
        .read_with(cx, |p, _| p.shown.clone())
        .and_then(|l| l.shown())
        .expect("clip painted");
    let natural = cx.update(|w, _| {
        let style = w.text_style();
        let font_size = style.font_size.to_pixels(w.rem_size());
        let run = style.to_run(text.len());
        f32::from(
            w.text_system()
                .shape_line(text.into(), font_size, &[run], None)
                .width,
        )
    });
    (shown, f32::from(bounds.size.width), natural)
}

#[gpui::test]
fn clip_shows_text_up_to_its_cell(cx: &mut TestAppContext) {
    for table_cell in [false, true] {
        let short = "edge-fra";
        let (shown, width, natural) = shown_clip(cx, short, table_cell);
        assert_eq!(shown.as_ref(), short, "short text in cell {table_cell}");
        assert!(natural > 20.0 && natural < 300.0);
        assert!(
            width >= natural - 1.0,
            "short text box {width} of {natural}"
        );
        if table_cell {
            assert_near(width, natural.ceil(), "content-sized clip");
        }

        let long = "a-very-long-hostname-that-does-not-fit.example.com";
        let (shown, width, natural) = shown_clip(cx, long, table_cell);
        assert!(natural > 300.0);
        assert_near(width, 300.0, "long text box");
        assert!(shown.ends_with('\u{2026}'), "long text {shown:?}");
        // Everything that fits is kept: far more than the ellipsis alone.
        assert!(shown.chars().count() > 20, "long text {shown:?}");
        assert!(long.starts_with(shown.trim_end_matches('\u{2026}')));
    }
}

// The firewall rules table keeps its flex columns readable at the default and at a narrow window.
#[gpui::test]
fn firewall_columns_stay_readable(cx: &mut TestAppContext) {
    use crate::ui::firewall::{MATCHES_MIN, RULE_MIN};
    // Cell padding on both sides.
    const PAD: f32 = 12.0;
    for width in [900.0, 1280.0] {
        cx.update(crate::ui::init);
        let opts = Options {
            demo: true,
            view: Some(View::Firewall),
            select: None,
            inspect: false,
            scroll_end: false,
        };
        let (_console, cx) =
            cx.add_window_view(|w, cx| Console::new(opts, WindowState::default(), w, cx));
        cx.simulate_resize(size(px(width), px(820.)));
        cx.executor().allow_parking();
        let deadline = Instant::now() + Duration::from_secs(20);
        let bounds = |cx: &mut VisualTestContext, sel: &'static str| {
            cx.update(|w, cx| w.draw(cx).clear());
            cx.debug_bounds(sel)
        };
        while bounds(cx, "fw-matches-r-wp-login").is_none() {
            cx.run_until_parked();
            assert!(Instant::now() < deadline, "firewall rules never loaded");
            std::thread::sleep(Duration::from_millis(10));
        }
        let name = bounds(cx, "fw-name-r-wp-login").expect("rule cell");
        let title = bounds(cx, "fw-title-r-wp-login").expect("rule name");
        let matches = bounds(cx, "fw-matches-r-wp-login").expect("matches");
        assert!(
            f32::from(name.size.width) >= RULE_MIN - PAD - 1.0,
            "rule column {name:?} at {width}"
        );
        // The name wraps inside its cell rather than running past it and being cut.
        assert!(
            title.size.width <= name.size.width,
            "name {title:?} in {name:?}"
        );
        assert!(
            f32::from(matches.size.width) >= MATCHES_MIN - PAD - 1.0,
            "matches column {matches:?} at {width}"
        );
        for chip in [
            "fw-match-r-wp-login-0",
            "fw-match-r-wp-login-1",
            "fw-match-r-scanner-ua-0",
        ] {
            let b = bounds(cx, chip).expect("chip");
            // Whole chips on one line each: never a stripe of single characters.
            assert!(f32::from(b.size.width) > 80.0, "{chip} {b:?} at {width}");
            assert!(f32::from(b.size.height) < 30.0, "{chip} {b:?} at {width}");
            assert!(
                b.size.width <= matches.size.width,
                "{chip} {b:?} in {matches:?}"
            );
        }
    }
}

// Waits on the IO threads that answer the demo console, as open_docs does.
fn settle(
    cx: &mut VisualTestContext,
    console: &Entity<Console>,
    what: &str,
    ready: impl Fn(&Console) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        cx.run_until_parked();
        if console.read_with(cx, |c, _| ready(c)) {
            return;
        }
        assert!(Instant::now() < deadline, "{what} never loaded");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[gpui::test]
fn data_tab_renders_the_demo_data_and_its_inputs_span_their_boxes(cx: &mut TestAppContext) {
    for width in [1000.0, 1280.0, 1600.0] {
        let (console, cx) = open_docs(cx, width);
        console.update(cx, |c, cx| c.select_tab(SiteTab::Data, cx));
        settle(cx, &console, "site data", |c| {
            c.site_data.load.ready().is_some()
        });
        // The tab is offered on this node and site, so the choice sticks instead of falling back to Overview.
        assert_eq!(console.read_with(cx, |c, _| c.site_tab()), SiteTab::Data);
        console.read_with(cx, |c, _| {
            let loaded = c.site_data.load.ready().expect("loaded");
            let pg = loaded.view.postgres.as_ref().expect("postgres");
            assert_eq!(pg.databases.len(), 2, "app and auth");
            assert!(loaded.backups.len() >= 5);
            assert!(loaded.view.links.len() >= 4);
        });
        let (secret, secret_bytes, ext_name, ext_url, add_db, s3_name, s3_endpoint) = console
            .read_with(cx, |c, _| {
                let s = &c.site_data;
                (
                    s.secret_in.clone(),
                    s.secret_bytes_in.clone(),
                    s.ext_name_in.clone(),
                    s.ext_url_in.clone(),
                    s.db_in.clone(),
                    s.s3_name_in.clone(),
                    s.s3_endpoint_in.clone(),
                )
            });
        // Two form_grid cells and their gap span the card, which gives the column width.
        let pair = text_width(cx, &secret);
        assert_near(text_width(cx, &secret_bytes), pair, "secret grid cells");
        assert_near(
            text_width(cx, &ext_url),
            text_width(cx, &ext_name),
            "external grid cells",
        );
        assert_near(
            text_width(cx, &s3_endpoint),
            text_width(cx, &s3_name),
            "s3 grid cells",
        );
        let column = 2.0 * (pair + INSET) + space::MD;
        // An input beside its button keeps room only for the button.
        let add = text_width(cx, &add_db);
        assert!(
            add > column * 0.6,
            "new database input is {add} of {column}"
        );
    }
}

#[gpui::test]
fn databases_page_renders_the_demo_node_and_its_forms_span_their_boxes(cx: &mut TestAppContext) {
    for width in [1000.0, 1280.0, 1600.0] {
        cx.update(crate::ui::init);
        let opts = Options {
            demo: true,
            view: Some(View::Databases),
            select: Some("edge-fra".into()),
            inspect: false,
            scroll_end: false,
        };
        let (console, cx) =
            cx.add_window_view(|w, cx| Console::new(opts, WindowState::default(), w, cx));
        cx.simulate_resize(size(px(width), px(900.)));
        cx.executor().allow_parking();
        settle(cx, &console, "databases", |c| {
            matches!(c.dbs.load, DbLoad::Ready(_))
        });
        console.read_with(cx, |c, _| {
            let DbLoad::Ready(loaded) = &c.dbs.load else {
                panic!("not loaded");
            };
            let shared = loaded.shared.as_ref().expect("shared instance");
            assert!(shared.enabled && shared.tenants.len() == 1);
            assert_eq!(loaded.targets.len(), 1);
            assert_eq!(loaded.orphans.len(), 1);
            assert_eq!(loaded.backups.len(), 2);
        });
        console.update(cx, |c, cx| {
            c.dbs.limits_open = true;
            c.dbs.t_form_open = true;
            cx.notify();
        });
        cx.run_until_parked();
        let (memory, cpus, name, endpoint) = console.read_with(cx, |c, _| {
            let d = &c.dbs;
            (
                d.memory_in.clone(),
                d.cpus_in.clone(),
                d.t_name_in.clone(),
                d.t_endpoint_in.clone(),
            )
        });
        // The first two cells of a form_grid row share the row equally at every width.
        assert_near(
            text_width(cx, &cpus),
            text_width(cx, &memory),
            "limit cells",
        );
        assert_near(
            text_width(cx, &endpoint),
            text_width(cx, &name),
            "target cells",
        );
    }
}

#[gpui::test]
fn the_environment_tab_lists_linked_variables_read_only(cx: &mut TestAppContext) {
    let (console, cx) = open_docs(cx, 1280.0);
    settle(cx, &console, "site data", |c| {
        c.site_data.load.ready().is_some()
    });
    let (runtime, build) = console.read_with(cx, |c, _| (c.linked_env(true), c.linked_env(false)));
    let url = runtime
        .iter()
        .find(|r| r.var == "DATABASE_URL")
        .expect("runtime DATABASE_URL");
    assert_eq!(url.text, "linked from postgres app/app url");
    assert!(runtime.iter().any(|r| r.var == "AUTH_SECRET"));
    assert!(build.iter().any(|r| r.var == "MIGRATION_DATABASE_URL"));
    assert!(build.iter().all(|r| r.var != "DATABASE_URL"));
    console.update(cx, |c, cx| c.select_tab(SiteTab::Environment, cx));
    cx.run_until_parked();
    cx.update(|w, cx| w.draw(cx).clear());
}

// Ticks the simulated driver until it stops, which is when the move waits for the operator.
fn drive_demo(c: &mut Console, cx: &mut Context<Console>) {
    for i in 0..60 {
        c.tick = 100 + 2 * i;
        c.xfer_tick(cx);
        if c.xfer.demo.is_empty() {
            return;
        }
    }
    panic!("the simulated transfer never settled");
}

fn started_transfer(c: &mut Console, cx: &mut Context<Console>) -> String {
    let before: Vec<String> = c.xfer.view.iter().map(|t| t.id.clone()).collect();
    c.xfer_start(cx);
    c.xfer
        .view
        .iter()
        .find(|t| !before.contains(&t.id))
        .expect("a transfer was started")
        .id
        .clone()
}

fn phase_of(c: &Console, id: &str) -> Option<TransferPhase> {
    c.xfer.view.iter().find(|t| t.id == id).map(|t| t.phase)
}

#[gpui::test]
fn a_demo_transfer_runs_to_verification_and_is_cut_over(cx: &mut TestAppContext) {
    let (console, cx) = open_docs(cx, 1280.0);
    settle(cx, &console, "site data", |c| {
        c.site_data.load.ready().is_some()
    });
    console.update(cx, |c, cx| {
        let id = started_transfer(c, cx);
        let t = c
            .xfer
            .view
            .iter()
            .find(|t| t.id == id)
            .expect("listed")
            .clone();
        assert_eq!(t.plan.database, "pg:app");
        assert_eq!(t.plan.target_node, "edge-iad");
        assert_eq!(t.phase, TransferPhase::Pending);
        drive_demo(c, cx);
        let t = c
            .xfer
            .view
            .iter()
            .find(|t| t.id == id)
            .expect("listed")
            .clone();
        assert!(t.awaiting_operator(), "stops for the operator");
        assert_eq!(t.counts_match, Some(true));
        assert_eq!(t.bytes_done, t.bytes_total);
        c.xfer_action(id.clone(), XferAction::Cutover, cx);
        assert_eq!(phase_of(c, &id), Some(TransferPhase::Done));
        c.xfer_action(id.clone(), XferAction::Forget, cx);
        assert_eq!(phase_of(c, &id), None);
    });
}

#[gpui::test]
fn a_demo_transfer_with_a_row_count_difference_cannot_be_cut_over(cx: &mut TestAppContext) {
    let (console, cx) = open_docs(cx, 1280.0);
    settle(cx, &console, "site data", |c| {
        c.site_data.load.ready().is_some()
    });
    console.update(cx, |c, cx| {
        c.xfer.database = Some("auth".into());
        let id = started_transfer(c, cx);
        drive_demo(c, cx);
        let t = c
            .xfer
            .view
            .iter()
            .find(|t| t.id == id)
            .expect("listed")
            .clone();
        assert_eq!(t.counts_match, Some(false));
        assert_eq!(t.mismatches.len(), 1);
        c.xfer_action(id.clone(), XferAction::Cutover, cx);
        assert_eq!(phase_of(c, &id), Some(TransferPhase::Verifying));
        assert!(
            c.xfer
                .error
                .as_deref()
                .is_some_and(|e| e.contains("differ"))
        );
        c.xfer_action(id.clone(), XferAction::Rollback, cx);
        assert_eq!(phase_of(c, &id), Some(TransferPhase::RolledBack));
    });
}

#[gpui::test]
fn a_demo_conversion_runs_from_the_site_view_to_a_retired_database(cx: &mut TestAppContext) {
    let (console, cx) = open_docs(cx, 1280.0);
    settle(cx, &console, "site data", |c| {
        c.site_data.load.ready().is_some()
    });
    let state_now = |c: &Console| {
        c.site_data
            .load
            .ready()
            .and_then(|l| l.view.conversion.as_ref())
            .map(|s| s.state)
    };
    console.update(cx, |c, cx| c.data_convert_start(PgMode::Shared, cx));
    settle(cx, &console, "the conversion", |c| state_now(c).is_some());
    // Each read of the site moves the conversion on; it ends waiting for the operator.
    for _ in 0..6 {
        if console.read_with(cx, |c, _| state_now(c)) == Some(SessionState::AwaitingCutover) {
            break;
        }
        let before = console.read_with(cx, |c, _| state_now(c));
        console.update(cx, |c, cx| {
            let (node, site) = (c.detail.node.clone(), c.detail.site_id.clone());
            c.load_site_data(node, site, cx);
        });
        settle(cx, &console, "the next step", |c| state_now(c) != before);
    }
    assert_eq!(
        console.read_with(cx, |c, _| state_now(c)),
        Some(SessionState::AwaitingCutover)
    );
    let session = console.read_with(cx, |c, _| {
        c.site_data
            .load
            .ready()
            .and_then(|l| l.view.conversion.clone())
            .expect("open")
    });
    console.update(cx, |c, cx| {
        c.data_convert_finish(session.id.clone(), true, cx)
    });
    settle(cx, &console, "the cutover", |c| {
        c.site_data.load.ready().is_some_and(|l| {
            l.view.conversion.is_none()
                && l.view
                    .postgres
                    .as_ref()
                    .is_some_and(|pg| pg.mode == PgMode::Shared && pg.retired.is_some())
        })
    });
    console.update(cx, |c, cx| c.data_retired_delete(cx));
    settle(cx, &console, "the retired database to go", |c| {
        c.site_data.load.ready().is_some_and(|l| {
            l.view
                .postgres
                .as_ref()
                .is_some_and(|pg| pg.retired.is_none())
        })
    });
}

#[gpui::test]
fn transfer_cards_fit_the_data_tab_and_the_databases_page(cx: &mut TestAppContext) {
    for width in [1000.0, 1280.0, 1600.0] {
        let (console, cx) = open_docs(cx, width);
        console.update(cx, |c, cx| c.select_tab(SiteTab::Data, cx));
        settle(cx, &console, "site data", |c| {
            c.site_data.load.ready().is_some()
        });
        cx.run_until_parked();
        let (docs_id, shop_id, column) = console.read_with(cx, |c, _| {
            let id_of = |site: &str| {
                c.xfer
                    .view
                    .iter()
                    .find(|t| t.plan.site == site)
                    .map(|t| t.id.clone())
                    .expect("seeded transfer")
            };
            (id_of("docs"), id_of("shop"), c.content_width)
        });
        let selector =
            |id: &str| -> &'static str { Box::leak(format!("xfer-card-{id}").into_boxed_str()) };
        cx.update(|w, cx| w.draw(cx).clear());
        // The move waiting on a row count difference is on the site's own Data tab, inside its column.
        let card = cx.debug_bounds(selector(&docs_id)).expect("transfer card");
        let w = f32::from(card.size.width);
        assert!(
            w > 280.0 && w <= column + 1.0,
            "card {w} in {column} at {width}"
        );
        assert!(f32::from(card.size.height) > 80.0);
        // Another site's move is not listed here.
        assert!(cx.debug_bounds(selector(&shop_id)).is_none());
    }
    for width in [1000.0, 1280.0, 1600.0] {
        cx.update(crate::ui::init);
        let opts = Options {
            demo: true,
            view: Some(View::Databases),
            select: Some("edge-fra".into()),
            inspect: false,
            scroll_end: false,
        };
        let (console, cx) =
            cx.add_window_view(|w, cx| Console::new(opts, WindowState::default(), w, cx));
        cx.simulate_resize(size(px(width), px(900.)));
        cx.executor().allow_parking();
        settle(cx, &console, "databases", |c| {
            matches!(c.dbs.load, DbLoad::Ready(_))
        });
        let (ids, column) = console.read_with(cx, |c, _| {
            (
                c.xfer.view.iter().map(|t| t.id.clone()).collect::<Vec<_>>(),
                c.content_width,
            )
        });
        cx.update(|w, cx| w.draw(cx).clear());
        assert_eq!(ids.len(), 2);
        for id in ids {
            let card = cx
                .debug_bounds(Box::leak(format!("xfer-card-{id}").into_boxed_str()))
                .expect("listed on the Databases page");
            assert!(f32::from(card.size.width) <= column + 1.0);
        }
    }
}

#[gpui::test]
fn a_node_without_data_services_gets_no_data_tab(cx: &mut TestAppContext) {
    let (console, cx) = open_site(cx, "edge-iad", 1280.0);
    console.update(cx, |c, cx| c.select_tab(SiteTab::Data, cx));
    settle(cx, &console, "the data answer", |c| {
        matches!(c.site_data.load, DataLoad::Absent)
    });
    assert_ne!(console.read_with(cx, |c, _| c.site_tab()), SiteTab::Data);
    // Nothing linked is shown either: the Environment tab has no data rows.
    assert!(console.read_with(cx, |c, _| c.linked_env(true)).is_empty());
}
