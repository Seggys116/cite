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
mod wizard;
mod zone;

use gpui::{
    App, AppContext, Application, Bounds, KeyBinding, TitlebarOptions, WindowBounds, WindowOptions,
    actions, px, size,
};

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
        let bounds = Bounds::centered(None, size(px(1320.), px(840.)), cx);
        let window = cx.open_window(
            WindowOptions {
                focus,
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Cite".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |_, cx| cx.new(|cx| app::Console::new(opts, cx)),
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
