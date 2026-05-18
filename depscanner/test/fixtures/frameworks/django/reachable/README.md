# django / reachable — CVE-2022-28346 (QuerySet.annotate SQL injection)

- **Vulnerable dep:** `Django==4.0.3`
- **Sink:** `views.py:14` — `Article.objects.annotate(**annotations)` with attacker-controlled keys/values.
- **Entry point:** `urls.py` exposes `articles/` route to `list_articles`.
- **Expected verdict:** `data_flow`.
