# actix / unreachable — RUSTSEC-2020-0071

- **Vulnerable dep:** `time = "0.1.43"` (declared, not imported in source).
- **Why unreachable:** no actix `#[get]/#[post]` handlers, no command execution.
- **Expected verdict:** `module`.
