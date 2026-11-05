#![forbid(unsafe_code)]
//! Embedded SQLite store for HAProxy request events. Every event is kept forever unless age retention is set, and then each complete day is archived to a verified gzip file before its rows are deleted; a size budget is opt-in and trims the oldest rows only. Repetitive text lives in a dictionary table, hourly rollups serve long windows, minute rollups serve windows of up to six hours, and the request log reads raw rows. Reads go through a small connection pool so queries never wait on ingest.

mod archive;
mod error;
mod export;
mod fold;
mod gc;
mod hist;
mod ingest;
mod limits;
mod queries;
mod retention;
mod rollup;
mod schema;
mod scrub;
mod store;
mod util;
mod writer;

#[cfg(test)]
mod archive_tests;
#[cfg(test)]
mod tests;

pub use archive::{ArchiveItem, ArchiveList, CutReport};
pub use error::{Error, Result};
pub use export::{
    BOT_COLUMNS, ExportFilter, ExportKind, HOURLY_COLUMNS, REQUEST_COLUMNS, TOP_COLUMNS,
};
pub use limits::{DEFAULT_EXPORT_LIMIT, MAX_REQUEST_LIMIT, MAX_TOP_LIMIT};
pub use queries::TopKind;
pub use retention::PruneReport;
pub use schema::SCHEMA_VERSION;
pub use store::{Store, StoreOptions, StoreStats};
pub use writer::Writer;
