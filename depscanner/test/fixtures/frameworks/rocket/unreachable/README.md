# rocket / unreachable

- **Vulnerable dep:** `rocket = "0.5.0-rc.1"` (declared, not imported).
- **Why unreachable:** no `#[launch]`, no `rocket::build()`, no handlers.
- **Expected verdict:** `module` or `unreachable`.
