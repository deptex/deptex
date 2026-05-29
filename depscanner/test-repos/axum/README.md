# axum

Axum handler that opens a user-supplied path via `tokio::fs::read`,
without normalisation. Stand-alone copy of upstream taint-engine
fixture `depscanner/fixtures/test-rust-axum-traversal/` layered with
dogfood categories.

- **Ecosystem:** cargo
- **Framework:** axum + tokio
- **Reachable vuln dep:** `axum 0.6.18` + `tokio 1.28.0`.
- **Unreachable vuln dep:** `time 0.1.43` — declared but never imported.
- **Reachable handler:** `src/main.rs::serve_file()`.
- **Unreachable handler:** `src/main.rs::serve_index()`.

Note: Rust framework spec coverage is in early state per
`docs/contributor-test-infra-plan.md` §7; this fixture locks the cargo
SBOM shape so a parser regression on `Cargo.toml` surfaces immediately.

See `.deptex/SOURCE.md` for provenance.
