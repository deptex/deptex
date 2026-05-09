# actix / reachable — RUSTSEC-2020-0071 (time crate) + command injection demo

- **Vulnerable dep:** `time = "0.1.43"`
- **Sink:** `src/main.rs:11` — `Command::new("sh").arg("-c").arg(cmd)` from query param.
- **Entry point:** `#[get("/run")]` actix handler.
- **Expected verdict:** `data_flow` (command injection); `module` for the time CVE since `time` API is not directly invoked.
