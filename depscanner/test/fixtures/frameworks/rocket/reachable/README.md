# rocket / reachable — command injection demo on rocket 0.5.0-rc.1

- **Vulnerable dep:** `rocket = "0.5.0-rc.1"` (release-candidate; advisory coverage varies).
- **Sink:** `src/main.rs:10` — `Command::new("sh").arg("-c").arg(cmd)`.
- **Entry point:** `#[post("/run?<cmd>")]` mounted via `rocket::build().mount`.
- **Expected verdict:** `data_flow`.
