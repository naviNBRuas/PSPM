use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub db_path: String,
    pub db_password: Option<String>,
    pub ai_provider: AiProvider,
    pub ai_model: String,
    pub ai_endpoint: String,
    pub hibp_api_key: Option<String>,
    pub check_live_logins: bool,
    pub auto_rotate_passwords: bool,
    pub export_format: ExportFormat,
    pub theme: Theme,
    pub language: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            db_path: "~/.pspm/vault.db".to_string(),
            db_password: None,
            ai_provider: AiProvider::Ollama,
            ai_model: "llama3.2".to_string(),
            ai_endpoint: "http://localhost:11434".to_string(),
            hibp_api_key: None,
            check_live_logins: false,
            auto_rotate_passwords: false,
            export_format: ExportFormat::BitwardenJson,
            theme: Theme::System,
            language: "en".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum AiProvider {
    #[default]
    Ollama,
    OpenAI,
    Anthropic,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum ExportFormat {
    #[default]
    BitwardenJson,
    BitwardenCsv,
    KeePass,
    EncryptedBackup,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.ai_provider, AiProvider::Ollama);
        assert_eq!(config.ai_model, "llama3.2");
        assert_eq!(config.ai_endpoint, "http://localhost:11434");
        assert_eq!(config.export_format, ExportFormat::BitwardenJson);
        assert_eq!(config.theme, Theme::System);
        assert_eq!(config.language, "en");
        assert!(config.db_password.is_none());
        assert!(config.hibp_api_key.is_none());
        assert!(!config.check_live_logins);
        assert!(!config.auto_rotate_passwords);
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ai_model, config.ai_model);
        assert_eq!(deserialized.ai_endpoint, config.ai_endpoint);
    }
}
