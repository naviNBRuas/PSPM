use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::Response,
};
use std::path::PathBuf;
use tokio::fs;

pub async fn index() -> Response {
    serve_file("index.html").await
}

pub async fn assets(uri: Uri) -> Response {
    let path = uri.path().strip_prefix("/assets/").unwrap_or("");
    serve_file(&format!("assets/{path}")).await
}

pub async fn spa_fallback() -> Response {
    serve_file("index.html").await
}

async fn serve_file(path: &str) -> Response {
    let dist = frontend_dist_dir();
    let file_path = dist.join(path);

    match fs::read(&file_path).await {
        Ok(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_else(|| mime_guess::mime::APPLICATION_OCTET_STREAM);

            Response::builder()
                .header(header::CONTENT_TYPE, mime.to_string())
                .header(header::CACHE_CONTROL, "public, max-age=3600")
                .body(Body::from(content))
                .unwrap()
        }
        Err(_) => {
            // Fallback: serve index.html for SPA routing
            if path != "index.html" {
                if let Ok(index) = fs::read(&dist.join("index.html")).await {
                    return Response::builder()
                        .header(header::CONTENT_TYPE, "text/html")
                        .body(Body::from(index))
                        .unwrap();
                }
            }
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not found"))
                .unwrap()
        }
    }
}

fn frontend_dist_dir() -> PathBuf {
    // Check several locations for the built frontend
    let candidates = vec![
        PathBuf::from("frontend/dist"),
        PathBuf::from("../frontend/dist"),
        dirs_data_dir().join("frontend"),
    ];

    for path in &candidates {
        if path.exists() {
            return path.clone();
        }
    }

    // Default fallback
    PathBuf::from("frontend/dist")
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
