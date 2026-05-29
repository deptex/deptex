# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-rust-axum-traversal/`
- **Upstream tree SHA at copy time:** `7b785f581dd1fcfffde3f10bf54ec4fea70eff6c`
- **Files copied:** `Cargo.toml` (modified: package renamed to
  `deptex-dogfood-axum`, time unreachable dep + serde appended) +
  `src/main.rs` (modified: listening port 8080→4008).

Added for the dogfood: Dockerfile + k8s.yaml + .env.example,
`.deptex/{expected.yaml,deploy.sh,SOURCE.md}`, README rewritten. No
malicious-pkg seed for cargo — iterated in M4 walkthrough.

Upstream fixture stays byte-stable per Patch B.
