#![forbid(unsafe_code)]
//! Embedded SQLite store for HAProxy request events. Every event is kept forever unless age retention is set, and then each complete day is archived to a verified gzip file before its rows are deleted; a size budget is opt-in and trims the oldest rows only. Repetitive text lives in a dictionary table, hourly rollups serve long windows, minute rollups serve windows of up to six hours, and the request log reads raw rows. Reads go through a small connection pool so queries never wait on ingest.

mod analytics;
mod archive;
mod error;
mod export;
mod filter;
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
mod analytics_tests;
#[cfg(test)]
mod archive_tests;
#[cfg(test)]
mod tests;

pub use analytics::{
    Answer, Compare, Cursor, DeltaValue, FacetValue, Facets, PageRequest, RequestPage, SCAN_CAP,
    TopList,
};
pub use archive::{ArchiveItem, ArchiveList, ArchiveScrub, CutReport};
pub use error::{Error, Result};
pub use export::{
    BOT_COLUMNS, ExportFilter, ExportKind, HOURLY_COLUMNS, REQUEST_COLUMNS, TOP_COLUMNS,
};
pub use filter::{
    AnalyticsFilter, Blocked, DEFAULT_WINDOW_SECS, MAX_FILTER_SITES, MAX_OFFSET, MAX_PAGE,
    MAX_SPAN_DAYS, ParseOpts,
};
pub use limits::{DEFAULT_EXPORT_LIMIT, MAX_REQUEST_LIMIT, MAX_TOP_LIMIT};
pub use queries::{SortBy, TopKind};
pub use retention::PruneReport;
pub use schema::SCHEMA_VERSION;
pub use store::{Store, StoreOptions, StoreStats};
pub use writer::Writer;
