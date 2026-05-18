# warp / reachable — CVE-2023-26964 (transitive h2 DoS)

- **Vulnerable dep:** `warp = "0.3.3"` (transitive `h2`).
- **Sink:** `src/main.rs:13` — body-bytes filter exposes the HTTP/2 attack surface.
- **Entry point:** `warp::serve(echo).run(...)`.
- **Expected verdict:** `data_flow`.
