# fastapi / reachable — CVE-2024-24762 (python-multipart ReDoS)

- **Vulnerable dep:** `python-multipart==0.0.6`
- **Sink:** `app.py:10` — `@app.post("/upload")` with `Form(...)` triggers the vulnerable Content-Type parser.
- **Entry point:** FastAPI POST route `/upload`.
- **Expected verdict:** `data_flow`.
