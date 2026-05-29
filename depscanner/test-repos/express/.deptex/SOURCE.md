# SOURCE

Greenfield — no upstream taint-engine fixture.

This fixture was authored from scratch for the dogfood corpus because no
existing `depscanner/fixtures/test-*` Express fixture exists; the
taint-engine uses `test-npm` as its generic JS reference, which is a flat
dep manifest rather than a real router app.

The intentional seeds in this fixture mirror the categories the dogfood
walkthrough is supposed to validate:

- Reachable vuln (lodash@4.17.20 → CVE-2021-23337)
- Unreachable vuln (minimist@1.2.5 → CVE-2021-44906)
- Historical-malicious (event-stream@3.3.6)
- Semgrep SAST (tainted SQL string concat)
- Dockerfile IaC (USER root, no healthcheck, base image CVEs)
- k8s.yaml IaC (privileged, hostPath, runAsNonRoot=false)
- Secrets (fake AWS test key in .env.example)
- DAST (intentionally-vulnerable endpoints under /api/*)
