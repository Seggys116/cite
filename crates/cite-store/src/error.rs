use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database directory {0} does not exist")]
    MissingDir(PathBuf),
    #[error("cannot open database {path}: {source}")]
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    #[error("database schema version {found} is newer than the supported version {supported}")]
    NewerSchema { found: i64, supported: i64 },
    #[error("sqlite: {0}")]
    Sqlite(rusqlite::Error),
    #[error("query exceeded its time limit and was cancelled")]
    Timeout,
    #[error("operation incomplete: {0}")]
    Incomplete(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("writer is closed")]
    Closed,
    #[error("integrity check failed: {0}")]
    Integrity(String),
    /// The request itself is unusable: a bad archive name, no archive directory, a backup passed to restore.
    #[error("{0}")]
    Rejected(String),
    #[error("{0} not found")]
    NotFound(String),
    /// The request is valid but repeats work already done, such as restoring an archive twice.
    #[error("{0}")]
    Conflict(String),
    /// An archive or backup could not be written or did not verify; nothing was deleted because of it.
    #[error("archive failed: {0}")]
    Archive(String),
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::OperationInterrupted) => Error::Timeout,
            _ => Error::Sqlite(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
