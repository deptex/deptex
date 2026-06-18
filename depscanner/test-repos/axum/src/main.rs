use axum::{
    extract::Query,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use sqlx::postgres::PgPool;
use std::path::PathBuf;
use tokio::fs;

mod handlers;
mod repo;

const BASE_DIR: &str = "/var/data/uploads";

#[derive(Deserialize)]
struct FileQuery {
    name: String,
}

async fn serve_file(Query(q): Query<FileQuery>) -> String {
    // REACHABLE: user-controlled `name` joined into base dir and read.
    let mut p = PathBuf::from(BASE_DIR);
    p.push(&q.name);
    fs::read_to_string(&p).await.unwrap_or_default()
}

async fn serve_index() -> String {
    // UNREACHABLE: constant filename.
    fs::read_to_string(format!("{}/index.html", BASE_DIR))
        .await
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/app".into());
    let pool = PgPool::connect_lazy(&database_url).expect("invalid database url");

    let app = Router::new()
        .route("/file", get(serve_file))
        .route("/", get(serve_index))
        .route("/users", get(handlers::sql::list_users))
        .route("/search", get(handlers::search::search))
        .route("/ping", get(handlers::command::ping))
        .route("/archive", get(handlers::archive::archive))
        .route("/read", get(handlers::files::read_file))
        .route("/open", get(handlers::files::open_file))
        .route("/save", post(handlers::upload::save))
        .route("/fetch", get(handlers::ssrf::fetch))
        .route("/go", get(handlers::redirect::go))
        .route("/match", get(handlers::redos::match_input))
        .route("/load", post(handlers::deser::load_blob))
        .route("/config", get(handlers::config::parse_config))
        .route("/event", post(handlers::logging::record_event))
        .with_state(pool);
    let _ = axum::Server::bind(&"0.0.0.0:4008".parse().unwrap())
        .serve(app.into_make_service())
        .await;
}
