use actix_web::{get, web, App, HttpServer, Responder};
use std::process::Command;

// RUSTSEC-2020-0071 / CVE-2020-26235 — time <= 0.1.43 segfault risk.
// We pair it with a command-injection sink driven by an actix handler
// to give the dataflow analysis a concrete reachable flow.
#[get("/run")]
async fn run(q: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let cmd = q.get("cmd").cloned().unwrap_or_default();
    // Sink: spawn shell with attacker-controlled command string.
    let _ = Command::new("sh").arg("-c").arg(cmd).output();
    "ok"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(run))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
