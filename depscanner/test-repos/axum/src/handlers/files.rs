use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ReadQuery {
    path: String,
}

// REACHABLE: path_traversal — user `path` read directly off disk.
pub async fn read_file(query: Query<ReadQuery>) -> String {
    let q = query.into_inner();
    std::fs::read_to_string(&q.path).unwrap_or_default()
}

#[derive(Deserialize)]
pub struct OpenQuery {
    name: String,
}

// REACHABLE: path_traversal — user `name` opened directly as a file path.
pub async fn open_file(query: Query<OpenQuery>) -> String {
    let q = query.into_inner();
    let _f = std::fs::File::open(&q.name).expect("open failed");
    String::from("opened")
}
