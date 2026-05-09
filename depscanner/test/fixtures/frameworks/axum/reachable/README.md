# axum / reachable — CVE-2024-32650 (axum / hyper transitive)

- **Vulnerable dep:** `axum = "0.6.0"` (transitive `hyper@0.14.x`).
- **Sink:** `src/main.rs:11` — `fs::read_to_string(p)` where `p` is from query.
- **Entry point:** `Router::new().route("/read", get(read))` + `axum::Server`.
- **Expected verdict:** `data_flow`.
