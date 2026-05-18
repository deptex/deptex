# flask / unreachable — CVE-2023-30861

- **Vulnerable dep:** `Flask==2.2.2` (instantiated, no routes registered).
- **Why unreachable:** zero `@app.route` decorators; no response surface.
- **Expected verdict:** `module`.
