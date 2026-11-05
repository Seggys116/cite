// Each view lives in its own module and extends Console with loaders and a render method.
pub mod chart;
pub mod create;
pub mod detail;
pub mod firewall;
pub mod input;
pub mod maintenance;
pub mod nodes;
pub mod overview;
pub mod settings;
pub mod sites;
pub mod traffic;
pub mod widgets;

use gpui::App;

pub fn init(cx: &mut App) {
    input::bind_keys(cx);
    cx.on_window_closed(|cx| {
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();
}
