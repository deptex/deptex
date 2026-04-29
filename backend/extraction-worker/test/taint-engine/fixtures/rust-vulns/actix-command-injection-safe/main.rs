use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use shell_escape;
use std::borrow::Cow;
use std::process::Command;

#[derive(Deserialize)]
struct Params {
    cmd: String,
}

async fn run(query: web::Query<Params>) -> impl Responder {
    let params = query.into_inner();
    let escaped: Cow<str> = shell_escape::escape(Cow::from(params.cmd));
    let output = Command::new("sh")
        .arg("-c")
        .arg(escaped.as_ref())
        .output()
        .expect("failed to execute");
    HttpResponse::Ok().body(format!("{:?}", output))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().route("/run", web::get().to(run)))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
