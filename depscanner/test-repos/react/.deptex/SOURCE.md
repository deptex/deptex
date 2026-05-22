# SOURCE

Greenfield SPA reference — no upstream taint-engine fixture.

There is no upstream `depscanner/fixtures/test-react-*` for a pure SPA;
the JS-side taint-engine fixtures are server-framework shaped (next, express,
fastify, hono, nestjs). The dogfood corpus needs a representative
client-only fixture so the M2 npm batch exercises both the SSR
(next) and CSR (react) reachability shapes.

Seeded categories mirror the express/nextjs fixtures for uniformity:

- Reachable vuln (`lodash@4.17.20` → CVE-2021-23337 via `_.template`)
- Unreachable vuln (`moment@2.29.1` — declared but never imported)
- Historical-malicious (`event-stream@3.3.6`)
- IaC misconfigs (Dockerfile USER root + no HEALTHCHECK, k8s privileged
  / runAsNonRoot=false / hostPath / allowPrivilegeEscalation)
- Container os-package CVEs (nginx:1.19.0 base image)
- Secrets (fake AWS test key in `.env.example`)
- Semgrep SAST (lodash template-injection rule on `_.template`)

No DAST cell — see fixture README.
