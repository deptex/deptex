use axum::extract::{Query, State};
use serde::Deserialize;
use sqlx::postgres::PgPool;

use crate::repo;

#[derive(Deserialize)]
pub struct SearchQuery {
    term: String,
}

// REACHABLE: sql_injection — user `term` flows cross-module into a raw query.
pub async fn search(query: Query<SearchQuery>, State(pool): State<PgPool>) -> String {
    let q = query.into_inner();
    let n = repo::find_by_term(&q.term, &pool).await;
    format!("{} hits", n)
}
