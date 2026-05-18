# django / unreachable — CVE-2022-28346

- **Vulnerable dep:** `Django==4.0.3` (models declared, no views).
- **Why unreachable:** `urls.py` has no `urlpatterns`; no view function reaches `annotate()`.
- **Expected verdict:** `module`.
