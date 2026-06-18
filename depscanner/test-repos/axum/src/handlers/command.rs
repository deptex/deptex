use axum::extract::Query;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct PingQuery {
    host: String,
}

// REACHABLE: command_injection — user `host` passed as an argv element to ping.
pub async fn ping(query: Query<PingQuery>) -> String {
    let q = query.into_inner();
    let output = Command::new("ping").arg(&q.host).output().expect("spawn failed");
    format!("exit: {:?}", output.status.code())
}
