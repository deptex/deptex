# koa / reachable — CVE-2017-16026 (request SSRF)

- **Vulnerable dep:** `request@2.81.0`
- **Sink:** `index.js:13` — `request(ctx.query.url, ...)`.
- **Entry point:** `router.get('/fetch', ...)`.
- **Expected verdict:** `data_flow`.
