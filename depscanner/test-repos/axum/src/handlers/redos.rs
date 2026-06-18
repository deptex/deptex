use axum::extract::Query;
use regex::Regex;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct MatchQuery {
    pattern: String,
}

// REACHABLE: redos — user-supplied regex compiled directly.
pub async fn match_input(query: Query<MatchQuery>) -> String {
    let q = query.into_inner();
    let _re = Regex::new(&q.pattern).expect("bad regex");
    String::from("compiled")
}
