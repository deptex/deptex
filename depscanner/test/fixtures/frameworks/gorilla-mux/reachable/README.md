# gorilla-mux / reachable — CVE-2023-39325 (transitive x/net rapid reset)

- **Vulnerable dep:** `golang.org/x/net v0.16.0` via `github.com/gorilla/mux v1.8.0`.
- **Sink:** `main.go:19` — `os.ReadFile("./uploads/" + name)` (path traversal); also any HTTP/2 surface served by the router.
- **Entry point:** `r.HandleFunc("/file/{name}", ...)` + `http.ListenAndServe`.
- **Expected verdict:** `data_flow` for the path-traversal flow; transitive CVE pinned via x/net.
