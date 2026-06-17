# flask

Minimal Flask app that exercises path traversal through a vulnerable
`werkzeug` version. Stand-alone copy of upstream taint-engine fixture
`depscanner/fixtures/test-flask-traversal-pypi/` layered with dogfood
categories.

- **Ecosystem:** pypi
- **Framework:** Flask + Werkzeug
- **Reachable vuln dep:** `werkzeug==0.15.3` (path-traversal
  CVE-2019-14322 in `safe_join`).
- **Unreachable vuln dep:** `pyyaml==5.1` — declared but never imported.
- **Reachable handler:** `app.py:read_file()` — `request.args.get('p')`
  flows into `send_from_directory` via vulnerable `safe_join`.
- **Unreachable handler:** `app.py:internal_dump()` — guarded by a
  hardcoded path constant.
- **Malicious-pkg (deferred):** `ctx==0.1.2` was seeded but is removed from
  PyPI (404) — removed from `requirements.txt`. Malicious-package detection
  is exercised separately.

See `.deptex/SOURCE.md` for provenance, `.deptex/expected.yaml`, and
`.deptex/deploy.sh` to boot for DAST.
