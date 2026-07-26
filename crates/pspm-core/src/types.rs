use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Vault Types ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub source: ImportSource,
    pub item_count: u32,
    pub folder_count: u32,
    pub organization_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub name: String,
    pub username: Option<String>,
    pub password_hash: Option<String>,
    pub password_encrypted: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub fields: Vec<CustomField>,
    pub totp_secret_encrypted: Option<String>,
    pub totp_uri: Option<String>,
    pub passkey: bool,
    pub mfa_enabled: bool,
    pub item_type: ItemType,
    pub favorite: bool,
    pub reprompt: RepromptType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub name: String,
    pub domain: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value_encrypted: Option<String>,
    pub field_type: FieldType,
    pub linked_item_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Uuid,
    pub item_id: Uuid,
    pub filename: String,
    pub size_bytes: u64,
    pub content_encrypted: Option<Vec<u8>>,
}

// ─── Enums ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ItemType {
    #[default]
    Login,
    Card,
    Identity,
    Note,
    SshKey,
    ApiCredential,
    Database,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum RepromptType {
    #[default]
    None,
    Password,
    Pin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldType {
    Text,
    Hidden,
    Boolean,
    Linked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ImportSource {
    BitwardenJson,
    BitwardenCsv,
    KeePass,
    OnePassword,
    ProtonPass,
    LastPass,
    Dashlane,
    Chrome,
    Firefox,
    Custom(String),
}

impl std::fmt::Display for ImportSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportSource::BitwardenJson => write!(f, "BitwardenJson"),
            ImportSource::BitwardenCsv => write!(f, "BitwardenCsv"),
            ImportSource::KeePass => write!(f, "KeePass"),
            ImportSource::OnePassword => write!(f, "OnePassword"),
            ImportSource::ProtonPass => write!(f, "ProtonPass"),
            ImportSource::LastPass => write!(f, "LastPass"),
            ImportSource::Dashlane => write!(f, "Dashlane"),
            ImportSource::Chrome => write!(f, "Chrome"),
            ImportSource::Firefox => write!(f, "Firefox"),
            ImportSource::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

impl std::str::FromStr for ImportSource {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "BitwardenJson" => Ok(ImportSource::BitwardenJson),
            "BitwardenCsv" => Ok(ImportSource::BitwardenCsv),
            "KeePass" => Ok(ImportSource::KeePass),
            "OnePassword" => Ok(ImportSource::OnePassword),
            "ProtonPass" => Ok(ImportSource::ProtonPass),
            "LastPass" => Ok(ImportSource::LastPass),
            "Dashlane" => Ok(ImportSource::Dashlane),
            "Chrome" => Ok(ImportSource::Chrome),
            "Firefox" => Ok(ImportSource::Firefox),
            _ if s.starts_with("Custom(") && s.ends_with(')') => {
                Ok(ImportSource::Custom(s[7..s.len()-1].to_string()))
            }
            _ => Err(format!("Unknown import source: {s}")),
        }
    }
}

// ─── Analysis / Report Types ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultReport {
    pub vault_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub total_logins: u32,
    pub passwords_reused: u32,
    pub weak_passwords: u32,
    pub old_passwords: u32,
    pub compromised_passwords: u32,
    pub duplicate_entries: u32,
    pub unused_accounts: u32,
    pub accounts_without_mfa: u32,
    pub accounts_with_passkeys: u32,
    pub accounts_with_totp: u32,
    pub overall_score: u8,
    pub password_age_distribution: PasswordAgeDistribution,
    pub items: Vec<ItemReport>,
}

impl VaultReport {
    pub fn accounts_with_mfa(&self) -> u32 {
        self.total_logins - self.accounts_without_mfa
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemReport {
    pub item_id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub website: Option<String>,
    pub folder: Option<String>,
    pub strength_score: PasswordGrade,
    pub entropy: f64,
    pub length: u32,
    pub has_lowercase: bool,
    pub has_uppercase: bool,
    pub has_digits: bool,
    pub has_symbols: bool,
    pub breached: bool,
    pub reused: bool,
    pub duplicate: bool,
    pub old_password: bool,
    pub mfa_enabled: bool,
    pub passkey_enabled: bool,
    pub days_since_modified: i64,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordAgeDistribution {
    pub less_than_30_days: u32,
    pub one_to_three_months: u32,
    pub three_to_six_months: u32,
    pub six_months_to_year: u32,
    pub more_than_year: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PasswordGrade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

// ─── Strength Types ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrength {
    pub entropy: f64,
    pub length: u32,
    pub charset_size: u32,
    pub has_lowercase: bool,
    pub has_uppercase: bool,
    pub has_digits: bool,
    pub has_symbols: bool,
    pub contains_dictionary_word: bool,
    pub contains_leaked_pattern: bool,
    pub contains_keyboard_walk: bool,
    pub contains_date: bool,
    pub contains_name: bool,
    pub grade: PasswordGrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub max_length: u32,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
    pub no_ambiguous: bool,
    pub min_entropy: f64,
    pub avoid_common: bool,
}

// ─── Breach Types ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachCheck {
    pub item_id: Uuid,
    pub password_breached: bool,
    pub email_breached: bool,
    pub username_leaked: bool,
    pub domain_compromised: bool,
    pub breach_count: u32,
    pub breach_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HibpResponse {
    pub prefix: String,
    pub suffixes: Vec<String>,
}

// ─── Duplicate Types ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub canonical_item_id: Uuid,
    pub duplicate_item_ids: Vec<Uuid>,
    pub match_reason: DuplicateMatchReason,
    pub can_merge: bool,
    pub merge_suggestion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DuplicateMatchReason {
    SameWebsite,
    SameUsername,
    SamePasswordHash,
    SameUri,
    SameTitle,
    SameWebsiteAndUsername,
}

// ─── AI Types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPermission {
    pub level: AiPermissionLevel,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum AiPermissionLevel {
    #[default]
    Level0,
    Level1,
    Level2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSuggestion {
    pub item_id: Uuid,
    pub suggestion_type: AiSuggestionType,
    pub description: String,
    pub confidence: f32,
    pub applies: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AiSuggestionType {
    MoveToFolder,
    RenameTitle,
    DeleteDuplicate,
    Archive,
    Merge,
    Tag,
    CreateFolderStructure,
    IdentifyObsolete,
    SecurityImprovement,
}

// ─── Rotation Types ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecipe {
    pub domain: String,
    pub url: String,
    pub login_selector: Option<String>,
    pub password_selector: Option<String>,
    pub current_password_selector: Option<String>,
    pub new_password_selector: Option<String>,
    pub confirm_selector: Option<String>,
    pub submit_selector: Option<String>,
    pub success_indicator: Option<String>,
    pub known_working: bool,
    pub last_success: Option<DateTime<Utc>>,
    pub recipe_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationStatus {
    Success,
    Failed,
    ManualRequired,
    SiteChanged,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationHistory {
    pub id: Uuid,
    pub item_id: Uuid,
    pub old_password_hash: Option<String>,
    pub new_password_hash: String,
    pub status: RotationStatus,
    pub domain: Option<String>,
    pub rotated_at: DateTime<Utc>,
}

// ─── Checker Types ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCheckResult {
    pub item_id: Uuid,
    pub url: String,
    pub status: LoginStatus,
    pub message: String,
    pub requires_mfa: bool,
    pub requires_captcha: bool,
    pub account_locked: bool,
    pub password_expired: bool,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LoginStatus {
    Success,
    WrongPassword,
    WrongUsername,
    MfaRequired,
    CaptchaRequired,
    AccountLocked,
    PasswordExpired,
    SiteChanged,
    ManualIntervention,
    NetworkError,
    Unknown,
}

// ─── Dashboard Types ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub overall_security_score: u8,
    pub total_items: u32,
    pub password_reuse_percentage: f64,
    pub weak_password_percentage: f64,
    pub breached_password_percentage: f64,
    pub mfa_coverage_percentage: f64,
    pub passkey_adoption_percentage: f64,
    pub duplicate_percentage: f64,
    pub last_audit_date: Option<DateTime<Utc>>,
    pub password_age_avg_days: f64,
    pub grade_distribution: GradeDistribution,
}

impl Default for DashboardMetrics {
    fn default() -> Self {
        Self {
            overall_security_score: 0,
            total_items: 0,
            password_reuse_percentage: 0.0,
            weak_password_percentage: 0.0,
            breached_password_percentage: 0.0,
            mfa_coverage_percentage: 0.0,
            passkey_adoption_percentage: 0.0,
            duplicate_percentage: 0.0,
            last_audit_date: None,
            password_age_avg_days: 0.0,
            grade_distribution: GradeDistribution::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GradeDistribution {
    pub a_plus: u32,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub f: u32,
}

// ─── Generator Types ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GenerationPolicy {
    pub length: u32,
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
    pub no_ambiguous: bool,
    pub min_numbers: u32,
    pub min_symbols: u32,
    pub style: PasswordStyle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum PasswordStyle {
    #[default]
    Random,
    Diceware,
    Pin,
    Memorable,
}
