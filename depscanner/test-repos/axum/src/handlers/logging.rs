use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct EventQuery {
    message: String,
}

// REACHABLE: log_injection — raw user `message` written to the log stream.
pub async fn record_event(query: Query<EventQuery>) -> String {
    let q = query.into_inner();
    tracing::info!("user event: {}", q.message);
    String::from("logged")
}
