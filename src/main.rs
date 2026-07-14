mod api;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
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

    let state = Arc::new(AppState { db, config });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/vault/import", post(api::vault::import_vault))
        .route("/api/vault/export", get(api::vault::export_vault))
        .route("/api/vault/items", get(api::vault::list_items))
        .route("/api/analysis/report", get(api::analysis::get_report))
        .route("/api/strength/check", post(api::strength::check_password))
        .route("/api/breach/check", post(api::breach::check_breach))
        .route("/api/duplicates", get(api::duplicates::find_duplicates))
        .route("/api/dashboard/metrics", get(api::dashboard::get_metrics))
        .route("/api/generator/generate", post(api::generator::generate_password))
        .route("/api/ai/suggest", post(api::ai::get_suggestions))
        .route("/api/checker/prepare", post(api::checker::prepare_check))
        .route("/api/rotation/recipes", get(api::rotation::list_recipes))
        .route(
            "/api/rotation/recipes",
            post(api::rotation::create_recipe),
        )
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
    let base = std::env::var("PSPM_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".pspm")
        });
    base
}

async fn health() -> &'static str {
    "PSPM running"
}
