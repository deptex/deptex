# gin / reachable — CVE-2023-26125 (gin path traversal via Query → os.ReadFile)

- **Vulnerable dep:** `github.com/gin-gonic/gin v1.9.0`
- **Sink:** `main.go:18` — `os.ReadFile(p)` where `p := c.Query("p")`.
- **Entry point:** `r.GET("/file", ...)`.
- **Expected verdict:** `data_flow`.
