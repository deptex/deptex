# echo / reachable — CVE-2022-40083 (open redirect)

- **Vulnerable dep:** `github.com/labstack/echo/v4 v4.6.3`
- **Sink:** `main.go:14` — `c.Redirect(302, c.QueryParam("u"))`.
- **Entry point:** `e.GET("/go", ...)`.
- **Expected verdict:** `data_flow`.
