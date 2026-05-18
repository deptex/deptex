# test-flask-traversal-pypi

Minimal Flask app that exercises path traversal through a vulnerable
`werkzeug` version.

- **Ecosystem:** pypi
- **Framework:** Flask + Werkzeug
- **Vulnerable dep:** `werkzeug==0.15.3` (path-traversal CVE-2019-14322
  in `safe_join`)
- **Reachable handler:** `app.py:read_file()` — `request.args.get('p')`
  flows into `send_from_directory` via the vulnerable `safe_join`.
- **Unreachable handler:** `app.py:internal_dump()` — guarded by a
  hardcoded path constant; user input never reaches the sink.

Expected snapshot pinning: `reachable_flows.json` should contain one
flow for `read_file`; the `vulns.json` row for werkzeug should show
`reachability_level=function` or higher.
