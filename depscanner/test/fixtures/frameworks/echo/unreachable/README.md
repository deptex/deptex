# echo / unreachable — CVE-2022-40083

- **Vulnerable dep:** `github.com/labstack/echo/v4 v4.6.3` (used, no Redirect).
- **Why unreachable:** only `c.JSON` is called from handlers.
- **Expected verdict:** `module`.
