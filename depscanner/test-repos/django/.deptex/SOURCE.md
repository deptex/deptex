# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-django-xss-pypi/`
- **Upstream tree SHA at copy time:** `8fcbaf1bb089b910dc9410749758ed3d2bd2c972`
- **Files copied verbatim:** `requirements.txt`, `views.py`, `urls.py`.

The upstream fixture stays byte-stable per Patch B of the dogfood plan.
This copy adds:

- `pyyaml==5.1` (declared but never imported → unreachable)
- `ctx==0.1.2` (historical-malicious pypi pkg)
- `Dockerfile` + `k8s.yaml` for IaC + container scanner coverage
- `.env.example` for TruffleHog secrets coverage
- `.deptex/{expected.yaml,deploy.sh,SOURCE.md}` for the dogfood harness
- README rewritten for dogfood framing
