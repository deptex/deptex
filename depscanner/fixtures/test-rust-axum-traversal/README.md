# test-rust-axum-traversal

Axum handler that opens a user-supplied path via `tokio::fs::read`,
without normalisation.

- **Ecosystem:** cargo
- **Framework:** axum + tokio
- **Vulnerable shape:** request path concatenated into a base dir and
  read; no `Path::starts_with` check.
- **Reachable handler:** `src/main.rs::serve_file()`.
- **Unreachable handler:** `src/main.rs::serve_index()` — constant
  filename.

Expected snapshot: cargo deps in `deps.json`, semgrep / taint-engine
finding on `serve_file`.

Note: Rust framework spec coverage is in early state per
`docs/contributor-test-infra-plan.md` §7; this fixture locks the cargo
SBOM shape so a parser regression on `Cargo.toml` surfaces immediately.
