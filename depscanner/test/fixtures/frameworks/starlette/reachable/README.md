# starlette / reachable — CVE-2023-29159 (open redirect)

- **Vulnerable dep:** `starlette==0.27.0`
- **Sink:** `app.py:9` — `RedirectResponse(url=target)` from `request.query_params`.
- **Entry point:** `Route("/go", go)`.
- **Expected verdict:** `data_flow`.
