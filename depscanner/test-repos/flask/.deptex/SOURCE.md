# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-flask-traversal-pypi/`
- **Upstream tree SHA at copy time:** `e21c7d92eb0dade85688aa54e3577d7040dd31cf`
- **Files copied verbatim:** `requirements.txt`, `app.py`.

Added for the dogfood: pyyaml unreachable dep, ctx malicious-pkg seed,
Dockerfile + k8s.yaml + .env.example, `.deptex/{expected.yaml,deploy.sh,
SOURCE.md}`, README rewritten.

Upstream fixture stays byte-stable per Patch B.
