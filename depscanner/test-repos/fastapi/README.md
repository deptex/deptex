# fastapi

FastAPI app with one reachable raw-SQL injection via SQLAlchemy `text()`.
Stand-alone copy of upstream taint-engine fixture
`depscanner/fixtures/test-fastapi-sqli-pypi/` layered with dogfood
categories.

- **Ecosystem:** pypi
- **Framework:** FastAPI + SQLAlchemy
- **Reachable vuln dep:** `sqlalchemy==1.3.0` (also pinned `fastapi==0.65.0`).
- **Unreachable vuln dep:** `pyyaml==5.1` — declared but never imported.
- **Reachable handler:** `main.py:lookup_user()` — `request.query` flows
  into `text()` concatenation.
- **Unreachable handler:** `main.py:list_users()` — pure ORM query with
  no user-controlled string.
- **Malicious-pkg (deferred):** `ctx==0.1.2` was seeded but is removed from
  PyPI (404) — removed from `requirements.txt`. Malicious-package detection
  is exercised separately.

See `.deptex/SOURCE.md` for provenance, `.deptex/expected.yaml` for the
canonical expected-finding list, and `.deptex/deploy.sh` to boot the
fixture for DAST.
