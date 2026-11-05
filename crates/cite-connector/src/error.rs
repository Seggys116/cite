use cite_edge::validate::ValidationError;

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    TooManyRequests(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ConnectorError>;

impl ConnectorError {
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::TooManyRequests(_) => 429,
            Self::Unavailable(_) => 503,
            Self::Internal(_) => 500,
        }
    }
}

// Validation failures are caused by the request, so they map to 400, not 500.
impl From<ValidationError> for ConnectorError {
    fn from(e: ValidationError) -> Self {
        Self::BadRequest(e.0)
    }
}

impl From<std::io::Error> for ConnectorError {
    fn from(e: std::io::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<serde_json::Error> for ConnectorError {
    fn from(e: serde_json::Error) -> Self {
        Self::Internal(e.to_string())
    }
}
