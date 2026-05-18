# gorilla-mux / unreachable — CVE-2023-39325 (transitive x/net)

- **Vulnerable dep:** `golang.org/x/net v0.16.0` via `github.com/gorilla/mux v1.8.0`.
- **Why unreachable:** no routes, no listener — the HTTP/2 attack surface is never exposed.
- **Expected verdict:** `module`.
