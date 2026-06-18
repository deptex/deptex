use axum::extract::Query;
use axum::response::Redirect;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RedirectQuery {
    next: String,
}

// REACHABLE: open_redirect — user `next` used as the Location target.
pub async fn go(query: Query<RedirectQuery>) -> Redirect {
    let q = query.into_inner();
    Redirect::to(&q.next)
}
