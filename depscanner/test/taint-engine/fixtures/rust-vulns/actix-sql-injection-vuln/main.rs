use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use sqlx::postgres::PgPool;

#[derive(Deserialize)]
struct UserQuery {
    name: String,
}

async fn list_users(
    query: web::Query<UserQuery>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    let q = query.into_inner();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", q.name);
    let rows = sqlx::query(&sql)
        .fetch_all(pool.get_ref())
        .await
        .expect("query failed");
    HttpResponse::Ok().body(format!("{} rows", rows.len()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = PgPool::connect("postgres://localhost/test")
        .await
        .expect("pool");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/users", web::get().to(list_users))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
