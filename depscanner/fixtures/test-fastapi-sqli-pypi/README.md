# test-fastapi-sqli-pypi

FastAPI app with one reachable raw-SQL injection via SQLAlchemy
`text()`.

- **Ecosystem:** pypi
- **Framework:** FastAPI + SQLAlchemy
- **Vulnerable dep:** `sqlalchemy==1.3.0` (also pinned `fastapi==0.65.0`
  for known CVE-2024-24762 path).
- **Reachable handler:** `main.py:lookup_user()` — `request.query` flows
  into `text()` concatenation.
- **Unreachable handler:** `main.py:list_users()` — pure ORM query with
  no user-controlled string.

Expected snapshot: SQLAlchemy + FastAPI vulns in `vulns.json`, one
reachable flow.
