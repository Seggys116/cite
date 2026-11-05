use std::error::Error as StdError;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
    #[error("unsupported config version {0}")]
    Version(u32),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Atomic(#[from] cite_core::Error),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

impl ConfigError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    pub fn is_missing(&self) -> bool {
        match self {
            Self::Io(err) | Self::Atomic(cite_core::Error::Io(err)) => {
                err.kind() == io::ErrorKind::NotFound
            }
            _ => false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("node unreachable: {message}")]
    Transport { message: String, timeout: bool },
    #[error("node returned {code}: {message}")]
    Status { code: u16, message: String },
    #[error("unexpected node response: {0}")]
    Decode(String),
    #[error("invalid node settings: {0}")]
    Config(String),
}

impl ClientError {
    pub fn timeout() -> Self {
        Self::Transport {
            message: "request timed out".to_string(),
            timeout: true,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Status { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Transport { timeout: true, .. })
    }

    pub(crate) fn from_reqwest(err: reqwest::Error) -> Self {
        let message = chain(&err);
        if err.is_decode() {
            return Self::Decode(message);
        }
        Self::Transport {
            message,
            timeout: err.is_timeout(),
        }
    }
}

// Transport failures hide their useful cause (TLS, DNS, refused) in the source chain.
fn chain(err: &(dyn StdError + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(next) = source {
        out.push_str(": ");
        out.push_str(&next.to_string());
        source = next.source();
    }
    out
}
