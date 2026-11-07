// Each view lives in its own module and extends Console with loaders and a render method.
pub mod alertspanel;
pub mod analytics;
pub mod bots;
pub mod certs;
pub mod certtools;
pub mod chart;
pub mod create;
pub mod detail;
pub mod firewall;
pub mod input;
#[cfg(test)]
mod layout_tests;
pub mod maintenance;
pub mod nodes;
pub mod ops;
pub mod overview;
pub mod paths;
pub mod scroll;
pub mod settings;
pub mod siteform;
pub mod sites;
pub mod storage;
pub mod traffic;
pub mod widgets;

use gpui::{App, KeyBinding};

pub fn init(cx: &mut App) {
    input::bind_keys(cx);
    cx.bind_keys([KeyBinding::new("cmd-b", crate::app::ToggleSidebar, None)]);
    cx.on_window_closed(|cx| {
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();
}
