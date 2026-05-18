use axum::{extract::Query, routing::get, Router};
use serde::Deserialize;
use std::path::PathBuf;
use tokio::fs;

const BASE_DIR: &str = "/var/data/uploads";

#[derive(Deserialize)]
struct FileQuery {
    name: String,
}

async fn serve_file(Query(q): Query<FileQuery>) -> String {
    // REACHABLE: user-controlled `name` joined into base dir and read.
    let mut p = PathBuf::from(BASE_DIR);
    p.push(&q.name);
    fs::read_to_string(&p).await.unwrap_or_default()
}

async fn serve_index() -> String {
    // UNREACHABLE: constant filename.
    fs::read_to_string(format!("{}/index.html", BASE_DIR))
        .await
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/file", get(serve_file))
        .route("/", get(serve_index));
    let _ = axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await;
}
