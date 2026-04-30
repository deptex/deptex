use sqlx::postgres::PgPool;

pub async fn find_by_name(name: &str, pool: &PgPool) -> usize {
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    let rows = sqlx::query(&sql).fetch_all(pool).await.expect("query failed");
    rows.len()
}
