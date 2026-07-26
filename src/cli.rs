use clap::{Parser, Subcommand};
use pspm_core::db::Database;
use pspm_core::config::AppConfig;
use pspm_core::types::Folder;

#[derive(Parser)]
#[command(name = "pspm", about = "Password Security Posture Management")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Rotate passwords for all items or specific ones
    Rotate {
        /// Comma-separated item IDs to rotate (omit to rotate all)
        #[arg(short, long)]
        ids: Option<String>,
        /// Vault ID (default: first vault)
        #[arg(short, long)]
        vault: Option<String>,
    },
    /// Scan for duplicate items and print groups
    Dupscan,
    /// Organize vault items into domain-based folders
    Organize {
        /// Vault ID (default: first vault)
        #[arg(short, long)]
        vault: Option<String>,
    },
}

pub fn run(cli: &Cli, db: &Database, _config: &AppConfig) {
    if let Some(cmd) = &cli.command { match cmd {
        Commands::Rotate { ids, vault } => cmd_rotate(db, ids.as_deref(), vault.as_deref()),
        Commands::Dupscan => cmd_dupscan(db),
        Commands::Organize { vault } => cmd_organize(db, vault.as_deref()),
    } }
}

fn cmd_rotate(db: &Database, ids: Option<&str>, vault: Option<&str>) {
    let vault_id = vault.map(|v| v.to_string()).unwrap_or_else(|| {
        db.list_vaults().ok().and_then(|v| v.first().map(|v| v.id.to_string()))
            .expect("No vaults found")
    });

    let items = db.list_items(&vault_id).expect("Failed to list items");
    let target_ids: Vec<String> = match ids {
        Some(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
        None => items.iter().map(|i| i.id.to_string()).collect(),
    };

    let to_rotate: Vec<_> = items.iter().filter(|i| target_ids.contains(&i.id.to_string())).collect();
    if to_rotate.is_empty() {
        eprintln!("No matching items found");
        return;
    }

    println!("Rotating {} passwords in vault {}...", to_rotate.len(), vault_id);
    let mut succeeded = 0;
    for item in &to_rotate {
        let item_id = item.id.to_string();
        let result = pspm_rotation::RotationEngine::rotate(item);
        match db.update_item_password(&item_id, Some(&result.new_password_hash), Some(&result.new_password)) {
            Ok(()) => {
                let _ = db.append_audit_log("cli_rotate", Some(&item_id), Some(&format!("Rotated password via CLI for {}", item.name)));
                let _ = db.insert_rotation_history(&item_id, item.password_hash.as_deref(), &result.new_password_hash, "completed", item.uris.first().map(|s| s.as_str()));
                println!("  ✓ {} ({}) — new password: {}", item.name, item_id, result.new_password);
                succeeded += 1;
            }
            Err(e) => {
                let _ = db.insert_rotation_history(&item_id, item.password_hash.as_deref(), &result.new_password_hash, "failed", item.uris.first().map(|s| s.as_str()));
                eprintln!("  ✗ {} ({}): {e}", item.name, item_id);
            }
        }
    }
    println!("\n{succeeded}/{} passwords rotated", to_rotate.len());
}

fn cmd_dupscan(db: &Database) {
    let items = db.list_all_items().expect("Failed to list items");
    let groups = pspm_duplicate::DuplicateDetector::find_duplicates(&items);

    let item_map: std::collections::HashMap<uuid::Uuid, &pspm_core::types::Item> = items.iter().map(|i| (i.id, i)).collect();

    println!("Duplicate Analysis");
    println!("==================");
    if groups.is_empty() {
        println!("No duplicates found.");
        return;
    }
    for (i, group) in groups.iter().enumerate() {
        println!("\nGroup {} — {:?}", i + 1, group.match_reason);
        let all_ids = std::iter::once(&group.canonical_item_id).chain(group.duplicate_item_ids.iter());
        for (j, id) in all_ids.enumerate() {
            match item_map.get(id) {
                Some(item) => {
                    let length = item.password_hash.as_deref().map(|h| h.len()).unwrap_or(0);
                    let strength = if length < 20 { "weak" } else { "ok" };
                    println!("  {}. {} [{}] — {} ({})", j + 1, item.name, item.username.as_deref().unwrap_or("?"), strength, id);
                }
                None => println!("  {}. (unknown item: {})", j + 1, id),
            }
        }
        if !group.duplicate_item_ids.is_empty() {
            let rest: Vec<String> = group.duplicate_item_ids.iter().map(|id| id.to_string()).collect();
            println!("  → Merge: `pspm merge {} {}`", group.canonical_item_id, rest.join(","));
        }
    }
    println!("\nTotal duplicate groups: {}", groups.len());
}

fn cmd_organize(db: &Database, vault: Option<&str>) {
    let vault_id_str = vault.map(|v| v.to_string()).unwrap_or_else(|| {
        db.list_vaults().ok().and_then(|v| v.first().map(|v| v.id.to_string()))
            .expect("No vaults found")
    });
    let vault_uuid: uuid::Uuid = vault_id_str.parse().expect("Invalid vault ID");

    let items = db.list_items(&vault_id_str).expect("Failed to list items");
    let mut created: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut moved = 0u32;

    for item in &items {
        let domain = item.uris.first()
            .and_then(|u| url_host(u))
            .or_else(|| {
                let name = item.name.split('.').next_back()?;
                if name.len() >= 2 && name.len() <= 20 { Some(name.to_lowercase()) } else { None }
            });

        if let Some(ref domain) = domain {
            if item.folder_id.is_none() {
                let folders = db.list_folders(&vault_id_str).unwrap_or_default();
                let existing = folders.iter().find(|f| f.name == *domain);
                let folder_id_str = match existing {
                    Some(f) => f.id.to_string(),
                    None => {
                        if !created.contains(domain.as_str()) {
                            let folder = Folder {
                                id: uuid::Uuid::new_v4(),
                                vault_id: vault_uuid,
                                name: domain.clone(),
                                parent_id: None,
                                created_at: chrono::Utc::now(),
                                updated_at: chrono::Utc::now(),
                            };
                            match db.insert_folder(&folder) {
                                Ok(()) => {
                                    created.insert(domain.clone());
                                    println!("  + Created folder \"{domain}\"");
                                    folder.id.to_string()
                                }
                                Err(e) => {
                                    eprintln!("  ✗ Failed to create folder \"{domain}\": {e}");
                                    continue;
                                }
                            }
                        } else {
                            let f = folders.iter().find(|f| f.name == *domain).unwrap();
                            f.id.to_string()
                        }
                    }
                };
                if db.move_items_to_folder(&[item.id.to_string()], Some(&folder_id_str)).is_ok() {
                    moved += 1;
                }
            }
        }
    }

    println!("Organized {moved} items into {} folders", created.len());
    for folder in &created {
        println!("  📁 {folder}");
    }
}

fn url_host(uri: &str) -> Option<String> {
    uri.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .map(|h| h.trim_start_matches("www.").to_lowercase())
}
