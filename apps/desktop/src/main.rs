mod alertcfg;
mod analyticsq;
mod api;
mod api_issue;
mod app;
mod archive;
mod bots;
mod certissue;
mod certs;
mod cli;
mod config;
mod demo;
mod demo_analytics;
mod demo_ops;
mod diagnose;
mod keychain;
mod model;
mod repo;
mod rules;
mod scope;
mod siteops;
#[cfg(test)]
mod testkit;
mod theme;
mod ui;
mod window_state;
mod wizard;
mod zone;

use gpui::{
    App, AppContext, Application, Bounds, KeyBinding, TitlebarOptions, WindowBounds, WindowOptions,
    actions, point, px, size,
};

use crate::theme::layout::{
    WINDOW_DEFAULT_H, WINDOW_DEFAULT_W, WINDOW_INSET, WINDOW_MIN_H, WINDOW_MIN_W,
};
use crate::window_state::WindowState;

// Saved bounds are used only while some part of them is still on a connected display.
fn initial_bounds(state: &WindowState, cx: &App) -> WindowBounds {
    let fallback = Bounds::centered(None, size(px(WINDOW_DEFAULT_W), px(WINDOW_DEFAULT_H)), cx);
    let Some(frame) = state.restorable_frame() else {
        return WindowBounds::Windowed(fallback);
    };
    let saved = Bounds::new(
        point(px(frame.x), px(frame.y)),
        size(px(frame.width), px(frame.height)),
    );
    if !cx.displays().iter().any(|d| d.bounds().intersects(&saved)) {
        return WindowBounds::Windowed(fallback);
    }
    if state.maximized {
        WindowBounds::Maximized(saved)
    } else {
        WindowBounds::Windowed(saved)
    }
}

// Quit is bound at the application level so it works from every view.
actions!(cite, [Quit]);

fn main() {
    let opts = match cli::parse(std::env::args().skip(1)) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    let focus = cli::takes_focus(&opts);
    Application::new().run(move |cx: &mut App| {
        ui::init(cx);
        cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
        cx.on_action(|_: &Quit, cx| cx.quit());
        // Demo and preview runs always open at the default size so screenshots stay comparable.
        let state = if opts.demo {
            WindowState::default()
        } else {
            WindowState::load(&window_state::window_state_path())
        };
        let window = cx.open_window(
            WindowOptions {
                focus,
                window_bounds: Some(initial_bounds(&state, cx)),
                window_min_size: Some(size(px(WINDOW_MIN_W), px(WINDOW_MIN_H))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Cite".into()),
                    appears_transparent: true,
                    traffic_light_position: Some(point(
                        px(WINDOW_INSET + 10.),
                        px(WINDOW_INSET + 10.),
                    )),
                }),
                ..Default::default()
            },
            |window, cx| cx.new(|cx| app::Console::new(opts, state, window, cx)),
        );
        if let Err(err) = window {
            eprintln!("cannot open the window: {err}");
            cx.quit();
            return;
        }
        if focus {
            cx.activate(true);
        }
    });
}
