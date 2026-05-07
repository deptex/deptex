use axum::extract::Query;
use serde::Deserialize;

mod file_loader;

#[derive(Deserialize)]
struct FileQuery {
    name: String,
}

async fn download(query: Query<FileQuery>) -> Vec<u8> {
    let q = query.into_inner();
    file_loader::read_user_file(&q.name)
}
