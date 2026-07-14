use thiserror::Error;

#[derive(Error, Debug)]
pub enum PspmError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Import error: {0}")]
    Import(String),

    #[error("Export error: {0}")]
    Export(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("AI error: {0}")]
    Ai(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Custom(String),
}

pub type Result<T> = std::result::Result<T, PspmError>;
