# chi / reachable — CVE-2023-44487 + reflected XSS demonstration

- **Vulnerable dep:** `github.com/go-chi/chi/v5 v5.0.10`
- **Sink:** `main.go:18` — `w.Write([]byte("<h1>" + q + "</h1>"))` after content-type forced to HTML.
- **Entry point:** `r.Get("/echo", ...)`.
- **Expected verdict:** `data_flow`.
