#![forbid(unsafe_code)]

pub mod api;
pub mod assets;
pub mod cli;
pub mod error;
pub mod preview;
pub mod proxy;
pub mod qr;
pub mod security;
pub mod server;
pub mod settings;
pub mod state;

pub use api::router;
pub use error::{ApiError, Error, Result};
pub use settings::Settings;
pub use state::AppState;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
