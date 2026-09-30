use std::io;
use std::path::PathBuf;

/// Recoverable Cite error. Library paths return this; they do not panic on bad input.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported schema version {found}")]
    Version { found: u32 },
    #[error("input exceeds size limit ({len} > {max})")]
    TooLarge { len: u64, max: u64 },
    #[error("path escapes root: {0}")]
    PathEscape(String),
    #[error("rejected archive entry: {0}")]
    Archive(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl Error {
    pub fn msg(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

impl From<PathBuf> for Error {
    fn from(path: PathBuf) -> Self {
        Self::Message(path.display().to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
