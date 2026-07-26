mod api;
mod cli;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
    Router,
};
use clap::Parser;
use pspm_core::config::AppConfig;
use pspm_core::db::Database;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

pub struct AppState {
    pub db: Database,
    pub config: AppConfig,
}

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,pspm=debug")),
        )
        .init();

    let config_dir = dirs_data_dir();
    tokio::fs::create_dir_all(&config_dir).await.ok();

    let config = AppConfig::default();

    let db_path = config_dir.join("pspm.db");
    let db = Database::open(&db_path, config.db_password.as_deref())
        .expect("Failed to open database");

    // If CLI subcommand given, run it and exit
    if cli.command.is_some() {
        cli::run(&cli, &db, &config);
        return;
    }

    let state = Arc::new(AppState { db, config });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Health
        .route("/api/health", get(health))
        // Vault CRUD
        .route("/api/vault/import", post(api::vault::import_vault))
        .route("/api/vault/export", get(api::vault::export_vault))
        .route("/api/vault/list", get(api::vault::list_vaults))
        .route("/api/vault/{id}", delete(api::vault::delete_vault))
        // Item CRUD
        .route("/api/vault/items", get(api::vault::list_items))
        .route("/api/vault/items/update", post(api::vault::update_item))
        .route("/api/vault/items/delete", post(api::vault::delete_item))
        .route("/api/vault/items/move", post(api::vault::move_items))
        // Folder CRUD
        .route("/api/vault/folders/{vault_id}", get(api::vault::list_folders))
        .route("/api/vault/folders", post(api::vault::create_folder))
        .route("/api/vault/folders/{folder_id}", put(api::vault::update_folder))
        .route("/api/vault/folders/{folder_id}", delete(api::vault::delete_folder))
        // Analysis & Strength & Breach
        .route("/api/analysis/report", get(api::analysis::get_report))
        .route("/api/strength/check", post(api::strength::check_password))
        .route("/api/breach/check", post(api::breach::check_breach))
        .route("/api/breach/checks", get(api::breach::list_breach_checks))
        // Duplicates
        .route("/api/duplicates", get(api::duplicates::find_duplicates))
        .route("/api/duplicates/merge", post(api::duplicates::merge_duplicates))
        // Dashboard
        .route("/api/dashboard/metrics", get(api::dashboard::get_metrics))
        // Generator
        .route("/api/generator/generate", post(api::generator::generate_password))
        // AI
        .route("/api/ai/suggest", post(api::ai::get_suggestions))
        // Checker
        .route("/api/checker/prepare", post(api::checker::prepare_check))
        // Rotation
        .route("/api/rotation/recipes", get(api::rotation::list_recipes))
        .route("/api/rotation/recipes", post(api::rotation::create_recipe))
        .route("/api/rotation/rotate", post(api::rotation::rotate_password))
        .route("/api/rotation/rotate-bulk", post(api::rotation::rotate_bulk))
        .route("/api/rotation/history", get(api::rotation::list_rotation_history))
        // Audit
        .route("/api/audit/logs", get(api::audit::list_audit_logs))
        // Static frontend
        .route("/", get(api::frontend::index))
        .route("/assets/{*path}", get(api::frontend::assets))
        .fallback(get(api::frontend::spa_fallback))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("PSPM server starting on http://pspm.localhost:8080");
    tracing::info!("Add to /etc/hosts: 127.0.0.1 pspm.localhost");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn dirs_data_dir() -> PathBuf {
    std::env::var("PSPM_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".pspm")
        })
}

async fn health() -> &'static str {
    "PSPM running"
}
