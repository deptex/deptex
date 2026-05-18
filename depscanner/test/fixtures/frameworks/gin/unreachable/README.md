# gin / unreachable — CVE-2023-26125

- **Vulnerable dep:** `github.com/gin-gonic/gin v1.9.0` (engine constructed, never served).
- **Why unreachable:** no `r.GET` / `r.POST` / `r.Run` invocations.
- **Expected verdict:** `module`.
