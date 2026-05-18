use axum::extract::Query;
use serde::Deserialize;
use std::path::Path;

mod file_loader;

#[derive(Deserialize)]
struct FileQuery {
    name: String,
}

async fn download(query: Query<FileQuery>) -> Vec<u8> {
    let q = query.into_inner();
    let raw = q.name;
    // Strip directory components — only the final file name reaches the loader.
    let safe = Path::new(&raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    file_loader::read_user_file(&safe)
}
