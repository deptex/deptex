use axum::{extract::Query, routing::get, Router};
use std::collections::HashMap;
use std::fs;

// CVE-2024-32650 (proxy) — axum 0.6.x via hyper 0.14 transitive request smuggling.
// We pair with a path-traversal sink driven by a query param to give a
// concrete reachable flow.
async fn read(Query(q): Query<HashMap<String, String>>) -> String {
    let p = q.get("p").cloned().unwrap_or_default();
    // Sink: read user-controlled file path.
    fs::read_to_string(p).unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/read", get(read));
    let _ = axum::Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await;
}
