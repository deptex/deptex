use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct BlobQuery {
    payload: String,
}

// REACHABLE: deserialization — untrusted JSON deserialized into a dynamic value.
pub async fn load_blob(query: Query<BlobQuery>) -> String {
    let q = query.into_inner();
    let _v: serde_json::Value = serde_json::from_str(&q.payload).unwrap_or_default();
    String::from("loaded")
}
