# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-fastapi-sqli-pypi/`
- **Upstream tree SHA at copy time:** `7be08280a70ff4239564754eb2876691766af89e`
- **Files copied verbatim:** `requirements.txt`, `main.py`.

Added for the dogfood: pyyaml unreachable dep, ctx malicious-pkg seed,
Dockerfile + k8s.yaml + .env.example, `.deptex/{expected.yaml,deploy.sh,
SOURCE.md}`, README rewritten.

Upstream fixture stays byte-stable per Patch B.
