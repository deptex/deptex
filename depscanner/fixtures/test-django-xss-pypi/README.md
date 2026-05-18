# test-django-xss-pypi

Minimal Django view with one reachable XSS sink (`mark_safe(user_input)`)
and one unreachable counterpart (template auto-escape preserved).

- **Ecosystem:** pypi
- **Framework:** Django
- **Vulnerable dep:** `django==2.2.0` (multiple CVEs; the focus here
  is the dev-error of bypassing auto-escape with user input)
- **Reachable handler:** `views.py:render_message()` — `request.GET['msg']`
  through `mark_safe()` into an HTTP response.
- **Unreachable handler:** `views.py:render_static()` — wraps a constant
  string in `mark_safe`; no user taint.

Expected snapshot pinning: one `entry_points` row per view; one
reachable flow on `render_message`.
