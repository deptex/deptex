use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct UploadQuery {
    dest: String,
}

// REACHABLE: path_traversal — user `dest` chosen as the write target.
pub async fn save(query: Query<UploadQuery>) -> String {
    let q = query.into_inner();
    std::fs::write(&q.dest, b"data").expect("write failed");
    String::from("saved")
}
