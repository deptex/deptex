use axum::extract::Query;
use serde::Deserialize;
use sqlx::postgres::PgPool;

mod user_repo;

#[derive(Deserialize)]
struct UserQuery {
    name: String,
}

async fn list_users(query: Query<UserQuery>, pool: PgPool) -> String {
    let q = query.into_inner();
    let rows = user_repo::find_by_name(&q.name, &pool).await;
    format!("{} rows", rows)
}
