use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

use crate::error::Result;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path, password: Option<&str>) -> Result<Self> {
        let conn = if let Some(pwd) = password {
            let conn = Connection::open(path)?;
            conn.execute_batch(&format!("PRAGMA key = '{pwd}';"))?;
            conn
        } else {
            Connection::open(path)?
        };

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vaults (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                item_count INTEGER DEFAULT 0,
                folder_count INTEGER DEFAULT 0,
                organization_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL REFERENCES vaults(id),
                name TEXT NOT NULL,
                parent_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL REFERENCES vaults(id),
                name TEXT NOT NULL,
                domain TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL REFERENCES vaults(id),
                folder_id TEXT REFERENCES folders(id),
                organization_id TEXT REFERENCES organizations(id),
                name TEXT NOT NULL,
                username TEXT,
                password_hash TEXT,
                password_encrypted TEXT,
                uris TEXT DEFAULT '[]',
                notes TEXT,
                fields TEXT DEFAULT '[]',
                totp_secret_encrypted TEXT,
                totp_uri TEXT,
                passkey INTEGER DEFAULT 0,
                mfa_enabled INTEGER DEFAULT 0,
                item_type TEXT DEFAULT 'Login',
                favorite INTEGER DEFAULT 0,
                reprompt TEXT DEFAULT 'None',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used TEXT
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                item_id TEXT NOT NULL REFERENCES items(id),
                filename TEXT NOT NULL,
                size_bytes INTEGER DEFAULT 0,
                content_encrypted BLOB
            );

            CREATE TABLE IF NOT EXISTS breach_checks (
                item_id TEXT PRIMARY KEY REFERENCES items(id),
                password_breached INTEGER DEFAULT 0,
                email_breached INTEGER DEFAULT 0,
                username_leaked INTEGER DEFAULT 0,
                domain_compromised INTEGER DEFAULT 0,
                breach_count INTEGER DEFAULT 0,
                breach_sources TEXT DEFAULT '[]',
                checked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS strength_scores (
                item_id TEXT PRIMARY KEY REFERENCES items(id),
                entropy REAL NOT NULL,
                length INTEGER NOT NULL,
                charset_size INTEGER NOT NULL,
                grade TEXT NOT NULL,
                scored_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS duplicate_groups (
                id TEXT PRIMARY KEY,
                canonical_item_id TEXT NOT NULL REFERENCES items(id),
                duplicate_item_ids TEXT NOT NULL DEFAULT '[]',
                match_reason TEXT NOT NULL,
                can_merge INTEGER DEFAULT 0,
                merge_suggestion TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_check_results (
                id TEXT PRIMARY KEY,
                item_id TEXT NOT NULL REFERENCES items(id),
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                requires_mfa INTEGER DEFAULT 0,
                requires_captcha INTEGER DEFAULT 0,
                account_locked INTEGER DEFAULT 0,
                password_expired INTEGER DEFAULT 0,
                checked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rotation_recipes (
                domain TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                login_selector TEXT,
                password_selector TEXT,
                current_password_selector TEXT,
                new_password_selector TEXT,
                confirm_selector TEXT,
                submit_selector TEXT,
                success_indicator TEXT,
                known_working INTEGER DEFAULT 0,
                last_success TEXT,
                recipe_version INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS ai_suggestions (
                id TEXT PRIMARY KEY,
                item_id TEXT NOT NULL REFERENCES items(id),
                suggestion_type TEXT NOT NULL,
                description TEXT NOT NULL,
                confidence REAL NOT NULL,
                applies INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                item_id TEXT REFERENCES items(id),
                details TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_items_vault ON items(vault_id);
            CREATE INDEX IF NOT EXISTS idx_items_folder ON items(folder_id);
            CREATE INDEX IF NOT EXISTS idx_items_organization ON items(organization_id);
            CREATE INDEX IF NOT EXISTS idx_folders_vault ON folders(vault_id);
            CREATE INDEX IF NOT EXISTS idx_attachments_item ON attachments(item_id);
            CREATE INDEX IF NOT EXISTS idx_breach_item ON breach_checks(item_id);
            CREATE INDEX IF NOT EXISTS idx_strength_item ON strength_scores(item_id);
            CREATE INDEX IF NOT EXISTS idx_duplicate_canonical ON duplicate_groups(canonical_item_id);
            CREATE INDEX IF NOT EXISTS idx_checker_item ON login_check_results(item_id);
            CREATE INDEX IF NOT EXISTS idx_ai_item ON ai_suggestions(item_id);
            CREATE INDEX IF NOT EXISTS idx_audit_item ON audit_log(item_id);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            ",
        )?;
        Ok(())
    }
}
