use sqlx::postgres::PgPool;

// Sink lives here; the tainted `term` arrives from handlers::search across modules.
pub async fn find_by_term(term: &str, pool: &PgPool) -> usize {
    let sql = format!("SELECT * FROM items WHERE term = '{}'", term);
    let rows = sqlx::query(&sql).fetch_all(pool).await.expect("query failed");
    rows.len()
}
