use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SidestepError {
    #[error("authentication: {0}")]
    Auth(String),

    #[error("operation '{0}' not found in spec")]
    UnknownOperation(String),

    #[error("missing required parameter '{0}' for operation '{1}'")]
    MissingParam(String, String),

    #[error("invalid parameter '{0}': {1}")]
    InvalidParam(String, String),

    #[error("HTTP {status}: {body}")]
    Http { status: u16, body: String },

    #[error("network: {0}")]
    Network(String),

    #[error("spec: {0}")]
    Spec(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SidestepError>;

impl From<reqwest::Error> for SidestepError {
    fn from(e: reqwest::Error) -> Self {
        SidestepError::Network(e.to_string())
    }
}
