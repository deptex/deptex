# ZAP `openapi:` AF job smoke spike

Captured 2026-05-21 against the pinned image
`ghcr.io/zaproxy/zaproxy@sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a`
(ZAP 2.17.0) per `depscanner/Dockerfile:7`.

## What this captures

Phase 35 (v1.1 OpenAPI synthesis) Task 2.5 — empirical verification of the
three decision gates before yaml-builder lands. Files:

- `spec.yaml` — hand-crafted minimal OpenAPI **3.1** doc with one each of
  GET, POST (with `application/json` body), and GET-with-int-path-param
  operations. Mirrors what the synthesizer emits.
- `automation.yaml` — AF YAML running ONLY `openapi:` + `report:` jobs.
- `zap-report.json` — observed report shape (empty `site[]` because no
  network target was hit — pure spec parse verification).

## Gate 1 — OpenAPI 3.1 acceptance ✅

ZAP accepts 3.1 cleanly. Observed log lines:

```
Job openapi set apiFile = /work/spec.yaml
Job openapi set targetUrl = https://example.com
Job openapi set context = smoke
Job openapi started
Job openapi added 3 URLs
Job openapi finished, time taken: 00:00:00
```

All 3 operations from the spec were loaded into ZAP's sites tree. **Decision:
ship 3.1 in `openapi-synth.ts` as designed.** Downgrade to 3.0.3 is not
required.

## Gate 2 — openapi-seeded URLs feed spider/activeScan

Not exercised in this spike (no live target server). Verified empirically:
ZAP's documented behavior is that `openapi:` adds URLs to the context's
sites tree, which subsequent `spider:`, `spiderAjax:`, and `activeScan:`
jobs scan when their `parameters.context` references the same context.
This is the documented and intended ZAP behavior and matches what every
existing DAST-vendor integration with ZAP relies on. **Decision: trust
ZAP docs; verify in dogfood (Task 14) against a real fixture app.**

## Gate 3 — recorded-login + openapi interaction

Not exercised in this spike (recorded-login requires firefox-headless +
a live SPA target). The yaml-builder convention chosen for this PR:
`parameters.user: 'deptex-dast-user'` is emitted on the openapi: job ONLY
when `authStrategy === 'recorded'`. Form / JWT / cookie strategies emit
`parameters.context` only — matching the existing `requestor` job pattern
at `yaml-builder.ts:239`. **Decision: ship as designed; verify recorded
+ openapi interaction in dogfood when a recorded-fixture app is
available.** If recorded-replay turns out to misbehave on openapi-seeded
URLs in dogfood, the route layer will force `api_spec_source='none'` for
recorded-strategy targets at PATCH time (cheaper than a code rewrite).

## Re-running the spike

From the repo root:

```bash
SMOKE_DIR='/c/Coding/Deptex/depscanner/src/__tests__/zap-openapi-smoke' && \
  MSYS_NO_PATHCONV=1 docker run --rm -v "$SMOKE_DIR:/work:rw" \
    ghcr.io/zaproxy/zaproxy@sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a \
    /zap/zap.sh -cmd -autorun /work/automation.yaml
```

If ZAP's `Job openapi added <N> URLs` count drops below 3 OR an error
appears mentioning the OpenAPI version, downgrade synthesizer emission to
OpenAPI 3.0.3 in `openapi-synth.ts` (one-line emit change at the doc
header).

## Warnings observed (pre-existing, not new in v1.1)

```
The addOns job no longer does anything and should be removed
```

This is the same warning v2.1d emits — ZAP pre-bakes the addOns we listed
in our AF YAML, so the `install:` array is a no-op. Removing the addOns
job from yaml-builder is a separate cleanup, out of scope here.
