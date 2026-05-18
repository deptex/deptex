# flask / reachable — CVE-2023-30861 (cookie cache leak)

- **Vulnerable dep:** `Flask==2.2.2`
- **Sink:** `app.py:16` — `make_response` returning user-controlled body without explicit cache headers.
- **Entry point:** `@app.route("/profile")`.
- **Expected verdict:** `data_flow`.
