use axum::extract::{Query, State};
use serde::Deserialize;
use sqlx::postgres::PgPool;

#[derive(Deserialize)]
pub struct UserQuery {
    name: String,
}

// REACHABLE: sql_injection — user `name` flows into a raw SQL query.
pub async fn list_users(query: Query<UserQuery>, State(pool): State<PgPool>) -> String {
    let q = query.into_inner();
    let rows = sqlx::query(&q.name).fetch_all(&pool).await.expect("query failed");
    format!("{} rows", rows.len())
}
