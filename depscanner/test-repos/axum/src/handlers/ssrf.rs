use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct FetchQuery {
    url: String,
}

// REACHABLE: ssrf — user `url` fetched server-side with no allowlist.
pub async fn fetch(query: Query<FetchQuery>) -> String {
    let q = query.into_inner();
    let _resp = reqwest::get(&q.url).await;
    String::from("fetched")
}
