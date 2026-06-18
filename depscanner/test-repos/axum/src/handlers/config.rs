use axum::extract::Query;
use serde::Deserialize;
use yaml_rust::YamlLoader;

#[derive(Deserialize)]
pub struct ConfigQuery {
    doc: String,
}

// REACHABLE: redos (RUSTSEC-2018-0006) — user-supplied YAML parsed by yaml-rust,
// whose recursive descent over crafted nesting drives stack-exhaustion DoS.
pub async fn parse_config(query: Query<ConfigQuery>) -> String {
    let q = query.into_inner();
    let _docs = YamlLoader::load_from_str(&q.doc).unwrap_or_default();
    String::from("parsed")
}
