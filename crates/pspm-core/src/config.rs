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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum AiProvider {
    #[default]
    Ollama,
    OpenAI,
    Anthropic,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ExportFormat {
    #[default]
    BitwardenJson,
    BitwardenCsv,
    KeePass,
    EncryptedBackup,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}
