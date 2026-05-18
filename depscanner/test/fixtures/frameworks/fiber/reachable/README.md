# fiber / reachable — CVE-2023-45141 (open redirect)

- **Vulnerable dep:** `github.com/gofiber/fiber/v2 v2.49.0`
- **Sink:** `main.go:13` — `c.Redirect(c.Query("u"))`.
- **Entry point:** `app.Get("/go", ...)`.
- **Expected verdict:** `data_flow`.
