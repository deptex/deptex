# express — dogfood fixture

Greenfield Express.js reference fixture for the depscanner dogfood corpus.
Seeded with intentional findings across every scanner category so a real
end-to-end walkthrough exercises the full pipeline.

## What's seeded

- **Reachable vulnerable dep:** `lodash@4.17.20` — CVE-2021-23337 (command
  injection via `_.template`), called directly from `routes/api.js`.
- **Unreachable vulnerable dep:** `minimist@1.2.5` — CVE-2021-44906
  (prototype pollution), present in `package.json` but never imported.
- **Historical-malicious dep:** `event-stream@3.3.6` — the 2018 supply-chain
  incident. Listed for the malicious-package scanner; `.github/dependabot.yml`
  in repo root excludes `depscanner/test-repos/**` so Dependabot does not
  open a real PR against this seed.
- **SQL-injection sink:** `routes/api.js` concatenates `req.query.id` into a
  raw query string — canonical Semgrep injection signature.
- **Dockerfile misconfigs:** `USER root` (CKV_DOCKER_8), `:latest` tag
  (CKV_DOCKER_7), no `HEALTHCHECK` (CKV_DOCKER_2).
- **Container CVEs:** `node:14.0` base image — many `os_package`-level CVEs
  surface via Trivy / dep-scan container layer.
- **k8s misconfigs:** `privileged: true`, `runAsNonRoot: false`, hostPath
  mount.
- **Secret leak:** fake AWS test key in `.env.example` matching TruffleHog's
  AWS detector pattern.

## Why greenfield (not a copy)

No upstream Express fixture exists in `depscanner/fixtures/` — the
taint-engine corpus uses `test-npm` as its generic JS reference, but the
dogfood needs a realistic minimal app (router + entry point + middleware)
rather than a flat dep manifest.

## Local sanity check

```bash
# (Optional) install + run for DAST walkthrough.
cd depscanner/test-repos/express
docker compose -f .deptex/docker-compose.yml up
# Server boots on :4001.
```

## Verification

```bash
cd depscanner
npm run dogfood:check -- --fixture express --project-id <uuid>
```

See `.deptex/expected.yaml` for the full expected-findings contract and
`docs/runbooks/depscanner-dogfood.md` for the walkthrough.
