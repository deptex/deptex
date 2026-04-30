use sqlx::postgres::PgPool;

pub async fn find_by_name_safe(name: &str, pool: &PgPool) -> usize {
    let rows = sqlx::query("SELECT * FROM users WHERE name = $1")
        .bind(name)
        .fetch_all(pool)
        .await
        .expect("query failed");
    rows.len()
}
