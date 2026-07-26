use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

use crate::error::Result;
use crate::types::{
    BreachCheck, DuplicateGroup, Folder, Item, ItemType,
    RepromptType, RotationRecipe, Vault,
};

type AuditLogRow = (String, String, Option<String>, Option<String>, String);
type RotationHistoryRow = (String, String, Option<String>, String, String, Option<String>, String);

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
            CREATE TABLE IF NOT EXISTS rotation_history (
                id TEXT PRIMARY KEY,
                item_id TEXT NOT NULL REFERENCES items(id),
                old_password_hash TEXT,
                new_password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Success',
                domain TEXT,
                rotated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_item ON audit_log(item_id);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            CREATE INDEX IF NOT EXISTS idx_rotation_history_item ON rotation_history(item_id);
            CREATE INDEX IF NOT EXISTS idx_rotation_history_domain ON rotation_history(domain);
            ",
        )?;
        Ok(())
    }

    // ─── Vault CRUD ─────────────────────────────────────────────

    pub fn insert_vault(&self, vault: &Vault) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO vaults (id, name, description, source, created_at, updated_at, item_count, folder_count, organization_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                vault.id.to_string(),
                vault.name,
                vault.description,
                vault.source.to_string(),
                vault.created_at.to_rfc3339(),
                vault.updated_at.to_rfc3339(),
                vault.item_count,
                vault.folder_count,
                vault.organization_count,
            ],
        )?;
        Ok(())
    }

    pub fn get_vault(&self, vault_id: &str) -> Result<Option<Vault>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, source, created_at, updated_at, item_count, folder_count, organization_count FROM vaults WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![vault_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Vault {
                id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                name: row.get(1)?,
                description: row.get(2)?,
                source: row.get::<_, String>(3)?.parse().unwrap_or(crate::types::ImportSource::BitwardenJson),
                created_at: row.get::<_, String>(4)?.parse().unwrap_or_default(),
                updated_at: row.get::<_, String>(5)?.parse().unwrap_or_default(),
                item_count: row.get::<_, i32>(6)? as u32,
                folder_count: row.get::<_, i32>(7)? as u32,
                organization_count: row.get::<_, i32>(8)? as u32,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_vaults(&self) -> Result<Vec<Vault>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, source, created_at, updated_at, item_count, folder_count, organization_count FROM vaults ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Vault {
                id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                name: row.get(1)?,
                description: row.get(2)?,
                source: row.get::<_, String>(3)?.parse().unwrap_or(crate::types::ImportSource::BitwardenJson),
                created_at: row.get::<_, String>(4)?.parse().unwrap_or_default(),
                updated_at: row.get::<_, String>(5)?.parse().unwrap_or_default(),
                item_count: row.get::<_, i32>(6)? as u32,
                folder_count: row.get::<_, i32>(7)? as u32,
                organization_count: row.get::<_, i32>(8)? as u32,
            })
        })?;
        let mut vaults = Vec::new();
        for row in rows {
            vaults.push(row?);
        }
        Ok(vaults)
    }

    pub fn delete_vault(&self, vault_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM items WHERE vault_id = ?1", params![vault_id])?;
        conn.execute("DELETE FROM folders WHERE vault_id = ?1", params![vault_id])?;
        conn.execute("DELETE FROM organizations WHERE vault_id = ?1", params![vault_id])?;
        conn.execute("DELETE FROM vaults WHERE id = ?1", params![vault_id])?;
        Ok(())
    }

    // ─── Item CRUD ──────────────────────────────────────────────

    pub fn insert_item(&self, item: &Item) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO items (id, vault_id, folder_id, organization_id, name, username, password_hash, password_encrypted, uris, notes, fields, totp_secret_encrypted, totp_uri, passkey, mfa_enabled, item_type, favorite, reprompt, created_at, updated_at, last_used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            params![
                item.id.to_string(),
                item.vault_id.to_string(),
                item.folder_id.map(|f| f.to_string()),
                item.organization_id.map(|o| o.to_string()),
                item.name,
                item.username,
                item.password_hash,
                item.password_encrypted,
                serde_json::to_string(&item.uris).unwrap_or_default(),
                item.notes,
                serde_json::to_string(&item.fields).unwrap_or_default(),
                item.totp_secret_encrypted,
                item.totp_uri,
                item.passkey as i32,
                item.mfa_enabled as i32,
                format!("{:?}", item.item_type),
                item.favorite as i32,
                format!("{:?}", item.reprompt),
                item.created_at.to_rfc3339(),
                item.updated_at.to_rfc3339(),
                item.last_used.map(|d| d.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub fn insert_items_batch(&self, items: &[Item]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        for item in items {
            tx.execute(
                "INSERT OR REPLACE INTO items (id, vault_id, folder_id, organization_id, name, username, password_hash, password_encrypted, uris, notes, fields, totp_secret_encrypted, totp_uri, passkey, mfa_enabled, item_type, favorite, reprompt, created_at, updated_at, last_used)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    item.id.to_string(),
                    item.vault_id.to_string(),
                    item.folder_id.map(|f| f.to_string()),
                    item.organization_id.map(|o| o.to_string()),
                    item.name,
                    item.username,
                    item.password_hash,
                    item.password_encrypted,
                    serde_json::to_string(&item.uris).unwrap_or_default(),
                    item.notes,
                    serde_json::to_string(&item.fields).unwrap_or_default(),
                    item.totp_secret_encrypted,
                    item.totp_uri,
                    item.passkey as i32,
                    item.mfa_enabled as i32,
                    format!("{:?}", item.item_type),
                    item.favorite as i32,
                    format!("{:?}", item.reprompt),
                    item.created_at.to_rfc3339(),
                    item.updated_at.to_rfc3339(),
                    item.last_used.map(|d| d.to_rfc3339()),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_item(&self, item_id: &str) -> Result<Option<Item>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, folder_id, organization_id, name, username, password_hash, password_encrypted, uris, notes, fields, totp_secret_encrypted, totp_uri, passkey, mfa_enabled, item_type, favorite, reprompt, created_at, updated_at, last_used FROM items WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![item_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(map_row_to_item(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_items(&self, vault_id: &str) -> Result<Vec<Item>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, folder_id, organization_id, name, username, password_hash, password_encrypted, uris, notes, fields, totp_secret_encrypted, totp_uri, passkey, mfa_enabled, item_type, favorite, reprompt, created_at, updated_at, last_used FROM items WHERE vault_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![vault_id], map_row_to_item)?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn list_all_items(&self) -> Result<Vec<Item>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, folder_id, organization_id, name, username, password_hash, password_encrypted, uris, notes, fields, totp_secret_encrypted, totp_uri, passkey, mfa_enabled, item_type, favorite, reprompt, created_at, updated_at, last_used FROM items ORDER BY name",
        )?;
        let rows = stmt.query_map([], map_row_to_item)?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn delete_item(&self, item_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM items WHERE id = ?1", params![item_id])?;
        Ok(())
    }

    // ─── Folder CRUD ────────────────────────────────────────────

    pub fn insert_folder(&self, folder: &Folder) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO folders (id, vault_id, name, parent_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                folder.id.to_string(),
                folder.vault_id.to_string(),
                folder.name,
                folder.parent_id.map(|p| p.to_string()),
                folder.created_at.to_rfc3339(),
                folder.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_folder(&self, folder_id: &str) -> Result<Option<Folder>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, name, parent_id, created_at, updated_at FROM folders WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![folder_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Folder {
                id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                vault_id: uuid::Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                name: row.get(2)?,
                parent_id: row.get::<_, Option<String>>(3)?.and_then(|s| uuid::Uuid::parse_str(&s).ok()),
                created_at: row.get::<_, String>(4)?.parse().unwrap_or_default(),
                updated_at: row.get::<_, String>(5)?.parse().unwrap_or_default(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_folders(&self, vault_id: &str) -> Result<Vec<Folder>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, name, parent_id, created_at, updated_at FROM folders WHERE vault_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![vault_id], |row| {
            Ok(Folder {
                id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                vault_id: uuid::Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                name: row.get(2)?,
                parent_id: row.get::<_, Option<String>>(3)?.and_then(|s| uuid::Uuid::parse_str(&s).ok()),
                created_at: row.get::<_, String>(4)?.parse().unwrap_or_default(),
                updated_at: row.get::<_, String>(5)?.parse().unwrap_or_default(),
            })
        })?;
        let mut folders = Vec::new();
        for row in rows {
            folders.push(row?);
        }
        Ok(folders)
    }

    pub fn update_folder(&self, folder: &Folder) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE folders SET name=?1, parent_id=?2, updated_at=?3 WHERE id=?4",
            params![
                folder.name,
                folder.parent_id.map(|p| p.to_string()),
                folder.updated_at.to_rfc3339(),
                folder.id.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn delete_folder(&self, folder_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE items SET folder_id=NULL WHERE folder_id=?1", params![folder_id])?;
        conn.execute("DELETE FROM folders WHERE id=?1", params![folder_id])?;
        Ok(())
    }

    pub fn insert_folders_batch(&self, vault_id: &str, folders: &[Folder]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        for folder in folders {
            tx.execute(
                "INSERT OR REPLACE INTO folders (id, vault_id, name, parent_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    folder.id.to_string(),
                    vault_id,
                    folder.name,
                    folder.parent_id.map(|p| p.to_string()),
                    folder.created_at.to_rfc3339(),
                    folder.updated_at.to_rfc3339(),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ─── Strength Scores ────────────────────────────────────────

    pub fn insert_strength_score(
        &self,
        item_id: &str,
        entropy: f64,
        length: u32,
        charset_size: u32,
        grade: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO strength_scores (item_id, entropy, length, charset_size, grade, scored_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![item_id, entropy, length, charset_size, grade, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_strength_score(&self, item_id: &str) -> Result<Option<(f64, u32, u32, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT entropy, length, charset_size, grade FROM strength_scores WHERE item_id = ?1",
        )?;
        let mut rows = stmt.query(params![item_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        } else {
            Ok(None)
        }
    }

    // ─── Breach Checks ──────────────────────────────────────────

    pub fn insert_breach_check(&self, check: &BreachCheck) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO breach_checks (item_id, password_breached, email_breached, username_leaked, domain_compromised, breach_count, breach_sources, checked_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                check.item_id.to_string(),
                check.password_breached as i32,
                check.email_breached as i32,
                check.username_leaked as i32,
                check.domain_compromised as i32,
                check.breach_count,
                serde_json::to_string(&check.breach_sources).unwrap_or_default(),
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn update_breach_check(&self, check: &BreachCheck) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE breach_checks SET password_breached=?1, email_breached=?2, username_leaked=?3, domain_compromised=?4, breach_count=?5, breach_sources=?6 WHERE item_id=?7",
            params![
                check.password_breached as i32,
                check.email_breached as i32,
                check.username_leaked as i32,
                check.domain_compromised as i32,
                check.breach_count,
                serde_json::to_string(&check.breach_sources).unwrap_or_default(),
                check.item_id.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn get_breach_check(&self, item_id: &str) -> Result<Option<BreachCheck>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT item_id, password_breached, email_breached, username_leaked, domain_compromised, breach_count, breach_sources FROM breach_checks WHERE item_id = ?1",
        )?;
        let mut rows = stmt.query(params![item_id])?;
        if let Some(row) = rows.next()? {
            let sources_str: String = row.get(6)?;
            Ok(Some(BreachCheck {
                item_id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                password_breached: row.get::<_, i32>(1)? != 0,
                email_breached: row.get::<_, i32>(2)? != 0,
                username_leaked: row.get::<_, i32>(3)? != 0,
                domain_compromised: row.get::<_, i32>(4)? != 0,
                breach_count: row.get::<_, i32>(5)? as u32,
                breach_sources: serde_json::from_str(&sources_str).unwrap_or_default(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_breach_checks(&self) -> Result<Vec<BreachCheck>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT item_id, password_breached, email_breached, username_leaked, domain_compromised, breach_count, breach_sources FROM breach_checks ORDER BY breach_count DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let sources_str: String = row.get(6)?;
            Ok(BreachCheck {
                item_id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                password_breached: row.get::<_, i32>(1)? != 0,
                email_breached: row.get::<_, i32>(2)? != 0,
                username_leaked: row.get::<_, i32>(3)? != 0,
                domain_compromised: row.get::<_, i32>(4)? != 0,
                breach_count: row.get::<_, i32>(5)? as u32,
                breach_sources: serde_json::from_str(&sources_str).unwrap_or_default(),
            })
        })?;
        let mut checks = Vec::new();
        for row in rows {
            checks.push(row?);
        }
        Ok(checks)
    }

    pub fn update_vault(&self, vault: &Vault) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE vaults SET name=?1, description=?2, source=?3, updated_at=?4, item_count=?5, folder_count=?6, organization_count=?7 WHERE id=?8",
            params![
                vault.name,
                vault.description,
                vault.source.to_string(),
                vault.updated_at.to_rfc3339(),
                vault.item_count,
                vault.folder_count,
                vault.organization_count,
                vault.id.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn list_audit_logs(&self, limit: u32) -> Result<Vec<AuditLogRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, action, item_id, details, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut logs = Vec::new();
        for row in rows {
            logs.push(row?);
        }
        Ok(logs)
    }

    pub fn get_items_by_folder(&self, folder_id: &str) -> Result<Vec<Item>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, folder_id, organization_id, name, username, password_hash, password_encrypted, uris, notes, fields, totp_secret_encrypted, totp_uri, passkey, mfa_enabled, item_type, favorite, reprompt, created_at, updated_at, last_used FROM items WHERE folder_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![folder_id], map_row_to_item)?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn search_items(&self, query: &str) -> Result<Vec<Item>> {
        let conn = self.conn.lock().unwrap();
        let pattern = format!("%{}%", query);
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, folder_id, organization_id, name, username, password_hash, password_encrypted, uris, notes, fields, totp_secret_encrypted, totp_uri, passkey, mfa_enabled, item_type, favorite, reprompt, created_at, updated_at, last_used FROM items WHERE name LIKE ?1 OR username LIKE ?1 OR notes LIKE ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![pattern], map_row_to_item)?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn get_recipe_by_domain(&self, domain: &str) -> Result<Option<RotationRecipe>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT domain, url, login_selector, password_selector, current_password_selector, new_password_selector, confirm_selector, submit_selector, success_indicator, known_working, last_success, recipe_version FROM rotation_recipes WHERE domain = ?1",
        )?;
        let mut rows = stmt.query(params![domain])?;
        if let Some(row) = rows.next()? {
            Ok(Some(RotationRecipe {
                domain: row.get(0)?,
                url: row.get(1)?,
                login_selector: row.get(2)?,
                password_selector: row.get(3)?,
                current_password_selector: row.get(4)?,
                new_password_selector: row.get(5)?,
                confirm_selector: row.get(6)?,
                submit_selector: row.get(7)?,
                success_indicator: row.get(8)?,
                known_working: row.get::<_, i32>(9)? != 0,
                last_success: row.get::<_, Option<String>>(10)?.and_then(|s| s.parse().ok()),
                recipe_version: row.get::<_, i32>(11)? as u32,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn update_rotation_recipe(&self, recipe: &RotationRecipe) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE rotation_recipes SET url=?1, login_selector=?2, password_selector=?3, current_password_selector=?4, new_password_selector=?5, confirm_selector=?6, submit_selector=?7, success_indicator=?8, known_working=?9, last_success=?10, recipe_version=?11 WHERE domain=?12",
            params![
                recipe.url,
                recipe.login_selector,
                recipe.password_selector,
                recipe.current_password_selector,
                recipe.new_password_selector,
                recipe.confirm_selector,
                recipe.submit_selector,
                recipe.success_indicator,
                recipe.known_working as i32,
                recipe.last_success.map(|d| d.to_rfc3339()),
                recipe.recipe_version,
                recipe.domain,
            ],
        )?;
        Ok(())
    }

    pub fn delete_rotation_recipe(&self, domain: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM rotation_recipes WHERE domain=?1", params![domain])?;
        Ok(())
    }

    // ─── Rotation Recipes ───────────────────────────────────────

    pub fn insert_rotation_recipe(&self, recipe: &RotationRecipe) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO rotation_recipes (domain, url, login_selector, password_selector, current_password_selector, new_password_selector, confirm_selector, submit_selector, success_indicator, known_working, last_success, recipe_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                recipe.domain,
                recipe.url,
                recipe.login_selector,
                recipe.password_selector,
                recipe.current_password_selector,
                recipe.new_password_selector,
                recipe.confirm_selector,
                recipe.submit_selector,
                recipe.success_indicator,
                recipe.known_working as i32,
                recipe.last_success.map(|d| d.to_rfc3339()),
                recipe.recipe_version,
            ],
        )?;
        Ok(())
    }

    pub fn list_recipes(&self) -> Result<Vec<RotationRecipe>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT domain, url, login_selector, password_selector, current_password_selector, new_password_selector, confirm_selector, submit_selector, success_indicator, known_working, last_success, recipe_version FROM rotation_recipes ORDER BY domain",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RotationRecipe {
                domain: row.get(0)?,
                url: row.get(1)?,
                login_selector: row.get(2)?,
                password_selector: row.get(3)?,
                current_password_selector: row.get(4)?,
                new_password_selector: row.get(5)?,
                confirm_selector: row.get(6)?,
                submit_selector: row.get(7)?,
                success_indicator: row.get(8)?,
                known_working: row.get::<_, i32>(9)? != 0,
                last_success: row.get::<_, Option<String>>(10)?.and_then(|s| s.parse().ok()),
                recipe_version: row.get::<_, i32>(11)? as u32,
            })
        })?;
        let mut recipes = Vec::new();
        for row in rows {
            recipes.push(row?);
        }
        Ok(recipes)
    }

    // ─── Duplicate Groups ───────────────────────────────────────

    pub fn insert_duplicate_group(&self, group: &DuplicateGroup) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO duplicate_groups (id, canonical_item_id, duplicate_item_ids, match_reason, can_merge, merge_suggestion, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                uuid::Uuid::new_v4().to_string(),
                group.canonical_item_id.to_string(),
                serde_json::to_string(&group.duplicate_item_ids).unwrap_or_default(),
                format!("{:?}", group.match_reason),
                group.can_merge as i32,
                group.merge_suggestion,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn clear_duplicate_groups(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM duplicate_groups", [])?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn list_duplicate_groups(&self) -> Result<Vec<(String, String, String, bool, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT canonical_item_id, duplicate_item_ids, match_reason, can_merge, merge_suggestion FROM duplicate_groups ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i32>(3)? != 0,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut groups = Vec::new();
        for row in rows {
            groups.push(row?);
        }
        Ok(groups)
    }

    // ─── Audit Log ──────────────────────────────────────────────

    pub fn append_audit_log(&self, action: &str, item_id: Option<&str>, details: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (id, action, item_id, details, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                uuid::Uuid::new_v4().to_string(),
                action,
                item_id,
                details,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    // ─── Item Update ────────────────────────────────────────────

    pub fn update_item_vault_id(&self, old_id: &str, new_vault_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE items SET vault_id = ?1 WHERE id = ?2",
            params![new_vault_id, old_id],
        )?;
        Ok(())
    }

    pub fn update_item(&self, item: &Item) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE items SET folder_id=?1, organization_id=?2, name=?3, username=?4, password_hash=?5, password_encrypted=?6, uris=?7, notes=?8, fields=?9, totp_secret_encrypted=?10, totp_uri=?11, passkey=?12, mfa_enabled=?13, item_type=?14, favorite=?15, reprompt=?16, updated_at=?17, last_used=?18 WHERE id=?19",
            params![
                item.folder_id.map(|f| f.to_string()),
                item.organization_id.map(|o| o.to_string()),
                item.name,
                item.username,
                item.password_hash,
                item.password_encrypted,
                serde_json::to_string(&item.uris).unwrap_or_default(),
                item.notes,
                serde_json::to_string(&item.fields).unwrap_or_default(),
                item.totp_secret_encrypted,
                item.totp_uri,
                item.passkey as i32,
                item.mfa_enabled as i32,
                format!("{:?}", item.item_type),
                item.favorite as i32,
                format!("{:?}", item.reprompt),
                item.updated_at.to_rfc3339(),
                item.last_used.map(|d| d.to_rfc3339()),
                item.id.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn update_item_password(&self, item_id: &str, password_hash: Option<&str>, password_encrypted: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE items SET password_hash=?1, password_encrypted=?2, updated_at=?3 WHERE id=?4",
            params![password_hash, password_encrypted, chrono::Utc::now().to_rfc3339(), item_id],
        )?;
        Ok(())
    }

    pub fn delete_items_batch(&self, item_ids: &[String]) -> Result<()> {
        if item_ids.is_empty() { return Ok(()); }
        let placeholders: Vec<String> = item_ids.iter().enumerate().map(|(i, _)| format!("?{}", i + 1)).collect();
        let sql = format!("DELETE FROM items WHERE id IN ({})", placeholders.join(","));
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = item_ids.iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();
        stmt.execute(rusqlite::params_from_iter(params))?;
        Ok(())
    }

    pub fn move_items_to_folder(&self, item_ids: &[String], folder_id: Option<&str>) -> Result<()> {
        if item_ids.is_empty() { return Ok(()); }
        let conn = self.conn.lock().unwrap();
        for id in item_ids {
            conn.execute(
                "UPDATE items SET folder_id=?1, updated_at=?2 WHERE id=?3",
                params![folder_id, chrono::Utc::now().to_rfc3339(), id],
            )?;
        }
        Ok(())
    }

    pub fn move_items_to_vault(&self, item_ids: &[String], vault_id: &str) -> Result<()> {
        if item_ids.is_empty() { return Ok(()); }
        let conn = self.conn.lock().unwrap();
        for id in item_ids {
            conn.execute(
                "UPDATE items SET vault_id=?1, updated_at=?2 WHERE id=?3",
                params![vault_id, chrono::Utc::now().to_rfc3339(), id],
            )?;
        }
        Ok(())
    }

    pub fn count_items(&self, vault_id: &str) -> Result<u32> {
        let conn = self.conn.lock().unwrap();
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM items WHERE vault_id = ?1",
            params![vault_id],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    pub fn update_vault_counts(&self, vault_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM items WHERE vault_id = ?1",
            params![vault_id],
            |row| row.get(0),
        )?;
        let folder_count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM folders WHERE vault_id = ?1",
            params![vault_id],
            |row| row.get(0),
        )?;
        conn.execute(
            "UPDATE vaults SET item_count = ?1, folder_count = ?2 WHERE id = ?3",
            params![count, folder_count, vault_id],
        )?;
        Ok(())
    }

    // ─── Rotation History ──────────────────────────────────────

    pub fn insert_rotation_history(&self, item_id: &str, old_hash: Option<&str>, new_hash: &str, status: &str, domain: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO rotation_history (id, item_id, old_password_hash, new_password_hash, status, domain, rotated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                uuid::Uuid::new_v4().to_string(),
                item_id,
                old_hash,
                new_hash,
                status,
                domain,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_rotation_history(&self, limit: u32) -> Result<Vec<RotationHistoryRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, item_id, old_password_hash, new_password_hash, status, domain, rotated_at FROM rotation_history ORDER BY rotated_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut history = Vec::new();
        for row in rows {
            history.push(row?);
        }
        Ok(history)
    }
}

fn map_row_to_item(row: &rusqlite::Row) -> rusqlite::Result<Item> {
    let id_str: String = row.get(0)?;
    let vault_id_str: String = row.get(1)?;
    let uris_str: String = row.get(8)?;
    let fields_str: String = row.get(10)?;
    let item_type_str: String = row.get(15)?;
    let reprompt_str: String = row.get(17)?;

    let item_type = match item_type_str.as_str() {
        "Login" => ItemType::Login,
        "Card" => ItemType::Card,
        "Identity" => ItemType::Identity,
        "Note" => ItemType::Note,
        "SshKey" => ItemType::SshKey,
        "ApiCredential" => ItemType::ApiCredential,
        "Database" => ItemType::Database,
        _ => ItemType::Login,
    };

    let reprompt = match reprompt_str.as_str() {
        "Password" => RepromptType::Password,
        "Pin" => RepromptType::Pin,
        _ => RepromptType::None,
    };

    Ok(Item {
        id: uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        vault_id: uuid::Uuid::parse_str(&vault_id_str).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        folder_id: row.get::<_, Option<String>>(2)?.and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        organization_id: row.get::<_, Option<String>>(3)?.and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        name: row.get(4)?,
        username: row.get(5)?,
        password_hash: row.get(6)?,
        password_encrypted: row.get(7)?,
        uris: serde_json::from_str(&uris_str).unwrap_or_default(),
        notes: row.get(9)?,
        fields: serde_json::from_str(&fields_str).unwrap_or_default(),
        totp_secret_encrypted: row.get(11)?,
        totp_uri: row.get(12)?,
        passkey: row.get::<_, i32>(13)? != 0,
        mfa_enabled: row.get::<_, i32>(14)? != 0,
        item_type,
        favorite: row.get::<_, i32>(16)? != 0,
        reprompt,
        created_at: row.get::<_, String>(18)?.parse().unwrap_or_default(),
        updated_at: row.get::<_, String>(19)?.parse().unwrap_or_default(),
        last_used: row.get::<_, Option<String>>(20)?.and_then(|s| s.parse().ok()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BreachCheck, DuplicateGroup, DuplicateMatchReason, Folder, Item, ItemType, RepromptType};

    fn create_test_item(vault_id: &str) -> Item {
        let now = chrono::Utc::now();
        Item {
            id: uuid::Uuid::new_v4(),
            vault_id: uuid::Uuid::parse_str(vault_id).unwrap_or_default(),
            folder_id: None,
            organization_id: None,
            name: "Test Item".into(),
            username: Some("user@test.com".into()),
            password_hash: Some("hash123".into()),
            password_encrypted: Some("password123".into()),
            uris: vec!["https://example.com".into()],
            notes: None,
            fields: vec![],
            totp_secret_encrypted: None,
            totp_uri: None,
            passkey: false,
            mfa_enabled: false,
            item_type: ItemType::Login,
            favorite: false,
            reprompt: RepromptType::None,
            created_at: now,
            updated_at: now,
            last_used: None,
        }
    }

    fn create_test_vault() -> Vault {
        let now = chrono::Utc::now();
        Vault {
            id: uuid::Uuid::new_v4(),
            name: "Test Vault".into(),
            description: None,
            created_at: now,
            updated_at: now,
            source: crate::types::ImportSource::BitwardenJson,
            item_count: 0,
            folder_count: 0,
            organization_count: 0,
        }
    }

    #[test]
    fn test_open_in_memory() {
        let db = Database::open_in_memory().unwrap();
        // Should not panic — database initializes with all tables
        let vaults = db.list_vaults().unwrap();
        assert!(vaults.is_empty());
    }

    #[test]
    fn test_vault_crud() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();

        db.insert_vault(&vault).unwrap();
        let fetched = db.get_vault(&vault.id.to_string()).unwrap().unwrap();
        assert_eq!(fetched.id, vault.id);
        assert_eq!(fetched.name, vault.name);

        let vaults = db.list_vaults().unwrap();
        assert_eq!(vaults.len(), 1);
    }

    #[test]
    fn test_vault_delete() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        db.delete_vault(&vault.id.to_string()).unwrap();
        assert!(db.get_vault(&vault.id.to_string()).unwrap().is_none());
    }

    #[test]
    fn test_item_crud() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        let fetched = db.get_item(&item.id.to_string()).unwrap().unwrap();
        assert_eq!(fetched.id, item.id);
        assert_eq!(fetched.name, item.name);
        assert_eq!(fetched.username, item.username);
        assert_eq!(fetched.uris, item.uris);

        // Should appear in vault listing
        let items = db.list_items(&vault.id.to_string()).unwrap();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn test_list_all_items() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let item1 = create_test_item(&vault.id.to_string());
        let item2 = create_test_item(&vault.id.to_string());
        db.insert_item(&item1).unwrap();
        db.insert_item(&item2).unwrap();

        let all = db.list_all_items().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_delete_item() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();
        db.delete_item(&item.id.to_string()).unwrap();

        assert!(db.get_item(&item.id.to_string()).unwrap().is_none());
    }

    #[test]
    fn test_batch_insert_items() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let items: Vec<Item> = (0..5).map(|_| create_test_item(&vault.id.to_string())).collect();
        db.insert_items_batch(&items).unwrap();

        let all = db.list_items(&vault.id.to_string()).unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_strength_scores() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        db.insert_strength_score(&item.id.to_string(), 80.0, 16, 95, "A").unwrap();
        let score = db.get_strength_score(&item.id.to_string()).unwrap().unwrap();
        assert!((score.0 - 80.0).abs() < 0.001);
        assert_eq!(score.1, 16);
        assert_eq!(score.2, 95);
        assert_eq!(score.3, "A");
    }

    #[test]
    fn test_insert_folders_batch() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let now = chrono::Utc::now();
        let folders = vec![Folder {
            id: uuid::Uuid::new_v4(),
            vault_id: vault.id,
            name: "Social".into(),
            parent_id: None,
            created_at: now,
            updated_at: now,
        }];

        db.insert_folders_batch(&vault.id.to_string(), &folders).unwrap();
    }

    #[test]
    fn test_breach_check() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();
        let check = BreachCheck {
            item_id: item.id,
            password_breached: true,
            email_breached: false,
            username_leaked: false,
            domain_compromised: false,
            breach_count: 1,
            breach_sources: vec!["HaveIBeenPwned".into()],
        };
        db.insert_breach_check(&check).unwrap();
    }

    #[test]
    fn test_rotation_recipe() {
        let db = Database::open_in_memory().unwrap();
        let recipe = RotationRecipe {
            domain: "example.com".into(),
            url: "https://example.com/login".into(),
            login_selector: Some("#username".into()),
            password_selector: Some("#password".into()),
            current_password_selector: None,
            new_password_selector: None,
            confirm_selector: None,
            submit_selector: None,
            success_indicator: None,
            known_working: true,
            last_success: None,
            recipe_version: 1,
        };
        db.insert_rotation_recipe(&recipe).unwrap();

        let recipes = db.list_recipes().unwrap();
        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].domain, "example.com");
    }

    #[test]
    fn test_duplicate_groups() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();
        let group = DuplicateGroup {
            canonical_item_id: item.id,
            duplicate_item_ids: vec![uuid::Uuid::new_v4()],
            match_reason: DuplicateMatchReason::SamePasswordHash,
            can_merge: true,
            merge_suggestion: "Keep the first".into(),
        };
        db.insert_duplicate_group(&group).unwrap();

        let groups = db.list_duplicate_groups().unwrap();
        assert_eq!(groups.len(), 1);

        db.clear_duplicate_groups().unwrap();
        let groups = db.list_duplicate_groups().unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[test]
    fn test_audit_log() {
        let db = Database::open_in_memory().unwrap();
        db.append_audit_log("test_action", None, Some("test details")).unwrap();
    }

    #[test]
    fn test_update_item_vault_id() {
        let db = Database::open_in_memory().unwrap();
        let vault1 = create_test_vault();
        let vault2 = create_test_vault();
        db.insert_vault(&vault1).unwrap();
        db.insert_vault(&vault2).unwrap();

        let item = create_test_item(&vault1.id.to_string());
        db.insert_item(&item).unwrap();

        db.update_item_vault_id(&item.id.to_string(), &vault2.id.to_string()).unwrap();
        let updated = db.get_item(&item.id.to_string()).unwrap().unwrap();
        assert_eq!(updated.vault_id, vault2.id);
    }

    #[test]
    fn test_count_items() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        let count = db.count_items(&vault.id.to_string()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_update_vault_counts() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        db.update_vault_counts(&vault.id.to_string()).unwrap();
        let updated = db.get_vault(&vault.id.to_string()).unwrap().unwrap();
        assert_eq!(updated.item_count, 1);
    }

    #[test]
    fn test_vault_not_found() {
        let db = Database::open_in_memory().unwrap();
        let result = db.get_vault("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_item_not_found() {
        let db = Database::open_in_memory().unwrap();
        let result = db.get_item("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_list_vaults() {
        let db = Database::open_in_memory().unwrap();
        let vaults = db.list_vaults().unwrap();
        assert!(vaults.is_empty());
    }

    #[test]
    fn test_empty_list_items() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();

        let items = db.list_items(&vault.id.to_string()).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_db_multiple_vaults() {
        let db = Database::open_in_memory().unwrap();
        let v1 = create_test_vault();
        let v2 = create_test_vault();
        db.insert_vault(&v1).unwrap();
        db.insert_vault(&v2).unwrap();

        let vaults = db.list_vaults().unwrap();
        assert_eq!(vaults.len(), 2);
    }

    #[test]
    fn test_strength_score_not_found() {
        let db = Database::open_in_memory().unwrap();
        let result = db.get_strength_score("nonexistent").unwrap();
        assert!(result.is_none());
    }

    // ─── New DB method tests ────────────────────────────────────

    #[test]
    fn test_update_item() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let mut item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        item.name = "Updated Name".into();
        item.updated_at = chrono::Utc::now();
        db.update_item(&item).unwrap();

        let fetched = db.get_item(&item.id.to_string()).unwrap().unwrap();
        assert_eq!(fetched.name, "Updated Name");
    }

    #[test]
    fn test_update_item_password() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        db.update_item_password(&item.id.to_string(), Some("new_hash"), Some("new_encrypted")).unwrap();
        let fetched = db.get_item(&item.id.to_string()).unwrap().unwrap();
        assert_eq!(fetched.password_hash.as_deref(), Some("new_hash"));
        assert_eq!(fetched.password_encrypted.as_deref(), Some("new_encrypted"));
    }

    #[test]
    fn test_delete_items_batch() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let items: Vec<Item> = (0..3).map(|_| create_test_item(&vault.id.to_string())).collect();
        db.insert_items_batch(&items).unwrap();

        db.delete_items_batch(&[items[0].id.to_string(), items[1].id.to_string()]).unwrap();
        assert_eq!(db.count_items(&vault.id.to_string()).unwrap(), 1);
    }

    #[test]
    fn test_move_items_to_folder() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let now = chrono::Utc::now();
        let folder = Folder { id: uuid::Uuid::new_v4(), vault_id: vault.id, name: "Test".into(), parent_id: None, created_at: now, updated_at: now };
        db.insert_folder(&folder).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        db.move_items_to_folder(&[item.id.to_string()], Some(&folder.id.to_string())).unwrap();
        let fetched = db.get_item(&item.id.to_string()).unwrap().unwrap();
        assert_eq!(fetched.folder_id, Some(folder.id));
    }

    #[test]
    fn test_folder_crud() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let now = chrono::Utc::now();
        let folder = Folder { id: uuid::Uuid::new_v4(), vault_id: vault.id, name: "My Folder".into(), parent_id: None, created_at: now, updated_at: now };

        db.insert_folder(&folder).unwrap();
        let fetched = db.get_folder(&folder.id.to_string()).unwrap().unwrap();
        assert_eq!(fetched.name, "My Folder");

        let folders = db.list_folders(&vault.id.to_string()).unwrap();
        assert_eq!(folders.len(), 1);

        let mut updated = folder.clone();
        updated.name = "Renamed".into();
        updated.updated_at = chrono::Utc::now();
        db.update_folder(&updated).unwrap();
        assert_eq!(db.get_folder(&folder.id.to_string()).unwrap().unwrap().name, "Renamed");

        db.delete_folder(&folder.id.to_string()).unwrap();
        assert!(db.get_folder(&folder.id.to_string()).unwrap().is_none());
    }

    #[test]
    fn test_get_breach_check() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();
        let check = BreachCheck {
            item_id: item.id, password_breached: true, email_breached: true,
            username_leaked: false, domain_compromised: false, breach_count: 2,
            breach_sources: vec!["HIBP".into()],
        };
        db.insert_breach_check(&check).unwrap();
        let fetched = db.get_breach_check(&item.id.to_string()).unwrap().unwrap();
        assert!(fetched.password_breached);
        assert_eq!(fetched.breach_count, 2);
    }

    #[test]
    fn test_update_vault() {
        let db = Database::open_in_memory().unwrap();
        let mut vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        vault.name = "Renamed Vault".into();
        vault.updated_at = chrono::Utc::now();
        db.update_vault(&vault).unwrap();
        assert_eq!(db.get_vault(&vault.id.to_string()).unwrap().unwrap().name, "Renamed Vault");
    }

    #[test]
    fn test_list_audit_logs() {
        let db = Database::open_in_memory().unwrap();
        db.append_audit_log("action1", None, None).unwrap();
        db.append_audit_log("action2", None, Some("detail")).unwrap();
        let logs = db.list_audit_logs(10).unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].1, "action2"); // newest first
    }

    #[test]
    fn test_get_items_by_folder() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let now = chrono::Utc::now();
        let folder = Folder { id: uuid::Uuid::new_v4(), vault_id: vault.id, name: "F".into(), parent_id: None, created_at: now, updated_at: now };
        db.insert_folder(&folder).unwrap();
        let mut item = create_test_item(&vault.id.to_string());
        item.folder_id = Some(folder.id);
        db.insert_item(&item).unwrap();

        let items = db.get_items_by_folder(&folder.id.to_string()).unwrap();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn test_search_items() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        let results = db.search_items("Test").unwrap();
        assert_eq!(results.len(), 1);
        let no_results = db.search_items("NonExistent").unwrap();
        assert!(no_results.is_empty());
    }

    #[test]
    fn test_rotation_history() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();

        db.insert_rotation_history(&item.id.to_string(), Some("old_hash"), "new_hash", "Success", Some("example.com")).unwrap();
        let history = db.list_rotation_history(10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].1, item.id.to_string());
    }

    #[test]
    fn test_recipe_update_delete() {
        let db = Database::open_in_memory().unwrap();
        let mut recipe = RotationRecipe {
            domain: "test.com".into(), url: "https://test.com".into(),
            login_selector: None, password_selector: None,
            current_password_selector: None, new_password_selector: None,
            confirm_selector: None, submit_selector: None,
            success_indicator: None, known_working: true,
            last_success: None, recipe_version: 1,
        };
        db.insert_rotation_recipe(&recipe).unwrap();
        assert!(db.get_recipe_by_domain("test.com").unwrap().is_some());

        recipe.known_working = false;
        db.update_rotation_recipe(&recipe).unwrap();
        assert!(!db.get_recipe_by_domain("test.com").unwrap().unwrap().known_working);

        db.delete_rotation_recipe("test.com").unwrap();
        assert!(db.get_recipe_by_domain("test.com").unwrap().is_none());
    }

    #[test]
    fn test_update_breach_check() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();
        let check = BreachCheck {
            item_id: item.id, password_breached: true, email_breached: false,
            username_leaked: false, domain_compromised: false, breach_count: 1,
            breach_sources: vec![],
        };
        db.insert_breach_check(&check).unwrap();

        let mut updated = check.clone();
        updated.password_breached = false;
        updated.breach_count = 0;
        db.update_breach_check(&updated).unwrap();

        let fetched = db.get_breach_check(&item.id.to_string()).unwrap().unwrap();
        assert!(!fetched.password_breached);
        assert_eq!(fetched.breach_count, 0);
    }

    #[test]
    fn test_list_breach_checks() {
        let db = Database::open_in_memory().unwrap();
        let vault = create_test_vault();
        db.insert_vault(&vault).unwrap();
        let item = create_test_item(&vault.id.to_string());
        db.insert_item(&item).unwrap();
        let check = BreachCheck {
            item_id: item.id, password_breached: true, email_breached: false,
            username_leaked: false, domain_compromised: false, breach_count: 1,
            breach_sources: vec![],
        };
        db.insert_breach_check(&check).unwrap();
        let checks = db.list_breach_checks().unwrap();
        assert_eq!(checks.len(), 1);
    }
}
