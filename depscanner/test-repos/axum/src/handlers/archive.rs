use axum::extract::Query;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct ArchiveQuery {
    file: String,
}

// REACHABLE: command_injection — user `file` passed as an argv element to tar.
pub async fn archive(query: Query<ArchiveQuery>) -> String {
    let q = query.into_inner();
    let _ = Command::new("tar").arg("-czf").arg("/tmp/out.tgz").arg(&q.file).output();
    String::from("archived")
}
