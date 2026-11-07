// Headless layout checks on the demo console: the text area of every input must span its box.

use std::time::{Duration, Instant};

use gpui::{Entity, TestAppContext, VisualTestContext, px, size};

use crate::app::{Console, Options, View};
use crate::theme::space;
use crate::ui::detail::tabs::SiteTab;
use crate::ui::input::TextInput;
use crate::window_state::WindowState;

// Input padding and border on both sides.
const INSET: f32 = 22.0;

fn open_docs(cx: &mut TestAppContext, width: f32) -> (Entity<Console>, &mut VisualTestContext) {
    cx.update(crate::ui::init);
    let opts = Options {
        demo: true,
        view: Some(View::SiteDetail {
            node: String::new(),
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
