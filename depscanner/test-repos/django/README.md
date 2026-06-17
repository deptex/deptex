# django

Minimal Django view with one reachable XSS sink and one unreachable
counterpart. Stand-alone copy of upstream taint-engine fixture
`depscanner/fixtures/test-django-xss-pypi/` layered with dogfood
categories.

- **Ecosystem:** pypi
- **Framework:** Django
- **Reachable vuln dep:** `django==2.2.0`
- **Unreachable vuln dep:** `pyyaml==5.1` — declared but never imported.
- **Reachable handler:** `views.py:render_message()` — `request.GET['msg']`
  through `mark_safe()` into an HTTP response.
- **Unreachable handler:** `views.py:render_static()` — wraps a constant
  string in `mark_safe`; no user taint.
- **Malicious-pkg (deferred):** `ctx==0.1.2` was seeded but is removed from
  PyPI (404) — removed from `requirements.txt`. Malicious-package detection
  is exercised separately.

See `.deptex/SOURCE.md` for upstream provenance, `.deptex/expected.yaml`
for the canonical expected-finding list, and `.deptex/deploy.sh` to
boot the fixture for DAST.
