mod api;
mod app;
mod bots;
mod cli;
mod config;
mod demo;
mod keychain;
mod model;
mod theme;
mod ui;

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
    Application::new().run(move |cx: &mut App| {
        ui::init(cx);
        cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
        cx.on_action(|_: &Quit, cx| cx.quit());
        let bounds = Bounds::centered(None, size(px(1320.), px(840.)), cx);
        let window = cx.open_window(
            WindowOptions {
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
        cx.activate(true);
    });
}
