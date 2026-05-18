# aiohttp / reachable — CVE-2024-23334 (path traversal via web.static)

- **Vulnerable dep:** `aiohttp==3.9.1`
- **Sink:** `app.py:18` — `web.static(..., follow_symlinks=True)` (and a manual `open` traversal sink at line 11).
- **Entry point:** `app.router.add_get("/files/{name}", fetch)` and `add_static("/assets/", ...)`.
- **Expected verdict:** `data_flow`.
