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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_database() {
        let err = PspmError::Database(rusqlite::Error::InvalidParameterName("test".into()));
        assert!(err.to_string().contains("Database error"));
    }

    #[test]
    fn test_error_display_import() {
        let err = PspmError::Import("Invalid format".into());
        assert_eq!(err.to_string(), "Import error: Invalid format");
    }

    #[test]
    fn test_error_display_not_found() {
        let err = PspmError::NotFound("vault".into());
        assert_eq!(err.to_string(), "Not found: vault");
    }

    #[test]
    fn test_error_display_custom() {
        let err = PspmError::Custom("something went wrong".into());
        assert_eq!(err.to_string(), "something went wrong");
    }

    #[test]
    fn test_error_display_network() {
        let err = PspmError::Network("timeout".into());
        assert_eq!(err.to_string(), "Network error: timeout");
    }

    #[test]
    fn test_error_display_crypto() {
        let err = PspmError::Crypto("key error".into());
        assert_eq!(err.to_string(), "Crypto error: key error");
    }
}
