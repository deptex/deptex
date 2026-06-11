# DAST Spec Parameter Enrichment (v1 — deterministic) — Implementation Plan

> **Revised 2026-06-08 after `/review-plan` → REVISE** (report: `review-dast-spec-param-enrichment.md`).
> Applied amendments: M4 (LLM pass) split out to `dast-spec-param-llm-enrich.plan.md`; added the router **mount-prefix** fix (P0); reframed M2 to **extend the framework detectors** (in-memory, during detection) instead of forking a parallel subsystem; replaced the manual-ZAP gate with a **CI-runnable seam test**; added the per-framework / negative / determinism / spec-validity test matrix; scoped v1 to **express + flask**.

## Overview
The DAST OpenAPI synthesizer (`depscanner/src/dast/openapi-synth.ts`, `api_spec_source='synthesized'`) emits a spec from `project_entry_points`, but it's thin: paths + methods + path params only — **no query parameters**. ZAP only injects into spec-declared params, so query-string injection points (express `/api/users?id=` SQLi, `/api/render?tpl=` RCE) are never attacked. This v1 recovers **query parameters** per route **deterministically** during extraction — by extending the existing framework detectors (which already walk each handler's CST during detection) — persists them as a `request_params` JSONB column on `project_entry_points`, and teaches the synthesizer to emit them. It also fixes a pre-existing blocker the feature surfaces: the detectors drop the router **mount prefix** (`app.use('/api', router)`), so the synth currently emits `/users` instead of `/api/users`. No LLM, no new AI on the extraction hot path. The LLM enrichment (validation-schema/body params) + the other 6 frameworks + body-schema are a separate fast-follow.

## Competitive Research & Design Rationale
StackHawk/Aikido Code2Swagger recover params via an LLM reading source; ZAP injects into spec-declared query params + body fields. We match the param-capture outcome **deterministically** for the common case (direct request reads), which is reproducible, AI-free, and grounds the feature in the same source the taint engine already models. The LLM pass (the incumbents' approach) is the fast-follow for validation-schema / dynamic params. Reachable-target provisioning is out of scope (user-provided URL / existing `project_dast_targets`).

## Codebase Analysis (verified)
- **Consumer:** `dast/openapi-synth.ts` — `synthesizeOpenApi()`. `buildParameters()` (L95-110) maps only `translatePathPattern().params` (all `in:'path'`); `ParamForEmit.in` is typed `'path'`. We widen this + append query params from `request_params`.
- `dast/openapi-path-translate.ts` — owns **path** params (unchanged; harvest emits query only, synth dedupes by `(name,in)`).
- `dast/cross-link.ts` — `EntryPointRow` (L13-29) + `loadEntryPoints()` SELECT (L270-284). Widen both to pull `request_params`.
- **Detectors (where the harvest runs):** `framework-rules/detectors/express.ts`, `flask.ts`. They walk the handler CST during detection with `source`+`tree` live (`DetectorContext`), already emit `EntryPoint{routePattern, handlerName, lineNumber, ...}`. The harvest is an extension here — the handler node is in hand, so read-scoping is free.
- **Mount prefix (P0):** `express.ts` stores the bare `router.get('/users')` literal; `server.js` does `app.use('/api', apiRouter)` (a *different file*). The mount prefix is dropped. Needs a resolution pass (see M2).
- **Persist:** `framework-rules/storage.ts` `storeEntryPoints()` — direct `.upsert` (NOT the `commit_extraction` RPC); both stores operate on the in-memory `result.files`. Add `request_params` to the rows object. `onConflict` unchanged. Reapers DELETE the whole row per run → the new column rides along (no reaper change; verified active-run-pointer model).
- `framework-rules/types.ts` — `EntryPoint` interface; add `requestParams`.
- `pipeline-steps/usage-extraction.ts` — detectors populate `result.files[*].entryPoints` during `extractUsage`; `storeUsageExtractionResults` then `storeEntryPoints` run as sequential statements inside one `runStage({timeoutMs:5*60_000})`. The deterministic harvest runs **inside detection**, so no new pipeline step + no LLM + no re-read.
- **Migration:** highest is `phase47` → new is **phase48**.
- **Snapshots:** CLI/PGLite snapshot suite runs vs `schema.sql`; deterministic params are stable (no AI), so fixtures just regen once. NOTE the 5-fixture snapshot suite is structurally blind to express/flask route params (`test-npm/snapshots/entry_points.json` is `[]`; `fixtures/test-*` are byte-stable/forbidden) — so per-framework coverage lives in **unit tests**, not snapshots.

## Data Model
### Migration: `backend/database/phase48_entry_points_request_params.sql`
```sql
-- Phase 48: project_entry_points query-parameter enrichment (deterministic v1).
-- Populated during usage-extraction by the framework detectors' param harvest;
-- consumed by the DAST OpenAPI synthesizer to emit query params so ZAP injects
-- into real injection points. Rides along the existing whole-row reap of
-- project_entry_points (active-run-pointer model) — no reaper change.
ALTER TABLE project_entry_points
  ADD COLUMN IF NOT EXISTS request_params JSONB;  -- OpenAPI parameter[] (query/header/cookie)
```
Apply via Supabase MCP, then `cd depscanner && npm run schema:dump`. (No partial index — the synth reads via the existing per-run `(project_id, extraction_run_id)` SELECT. `request_body_schema` deferred to the fast-follow.)

### `request_params` shape (`param-harvest/types.ts`, mirrored on `EntryPoint.requestParams`)
```ts
interface RequestParam {
  name: string;
  in: 'query' | 'header' | 'cookie';   // path stays owned by translatePathPattern
  required: boolean;                    // query params default false
  schema: { type: 'string' | 'integer' | 'number' | 'boolean' };
  provenance: 'ast';                    // enum reserves 'decorator' | 'llm' for the fast-follow
}
```
Canonically sorted by `(in, name)` and deduped before persist (determinism).

## API Design
**No new HTTP endpoints / RBAC.** Types: extend `EntryPoint` (`requestParams`); new `param-harvest/types.ts`; extend `cross-link.EntryPointRow` + the `loadEntryPoints` SELECT.

## Frontend Design
No required UI. (Optional "params recovered" indicator deferred.)

## Implementation Tasks
### M1 — Data model + plumbing (S/M)
1. `phase48_entry_points_request_params.sql` (above); apply via MCP; `npm run schema:dump`.
2. `param-harvest/types.ts` — `RequestParam` + a `canonicalizeParams(params)` helper (sort `(in,name)` + dedup by `(name,in)`).
3. `framework-rules/types.ts` — add `requestParams?: RequestParam[] | null` to `EntryPoint`.
4. `framework-rules/storage.ts` — add `request_params: canonicalizeParams(ep.requestParams) ?? null` to the rows object.
5. `dast/cross-link.ts` — add `request_params?` to `EntryPointRow`; widen the `loadEntryPoints` SELECT.
- *Accept:* migration live, tsc green both sides, a row round-trips `request_params: null`.

### M2 — Deterministic query-param harvest + mount-prefix fix (L)
6. **Harvest (express):** in `express.ts`, while visiting each route handler (node in hand), walk the handler subtree for request-input reads and emit `RequestParam[]`:
   - member-access `req.query.<name>` / `req.query['<name>']` → `{name, in:'query'}`.
   - call-shaped `req.query.<name>` not applicable; handle `req.get('<h>')`/`req.header('<h>')` → `in:'header'`, `req.cookies.<name>` → `in:'cookie'` (cheap, same walk).
   - Scope strictly to the handler's CST node range (no leakage across routes in one file).
   - Reuse the taint-engine source catalog (`framework-models/express.yaml`) as the *receiver* allowlist (`req.query`/`req.body`/`req.params`) via a small shared loader; the **name** comes from the CST.
7. **Harvest (flask):** in `flask.ts`, recover `request.args.get('<name>')` / `request.args['<name>']` → query; `request.values`/`request.form` deferred (body). Scoped to the decorated view function body.
8. **Mount-prefix resolution (P0):** add a post-detection composition so `route_pattern` reflects the served path. Implement a global pass over the JS/TS extracted files that (a) collects `app.use('<prefix>', <routerVar>)` / `router.use('<prefix>', <sub>)` mounts, (b) resolves `<routerVar>` to its defining file via the existing import/`require` mapping (the extractor already resolves imports), (c) prepends the prefix to that router's route literals. Same-file mounts compose directly; cross-file (the dogfood case: `server.js` mounts `require('./routes/api')`) resolves through the import map. If a router can't be resolved, leave the bare literal + log. Unit-test both same-file and cross-file (the express dogfood shape).
9. **Fixtures + unit matrix** (new harvest-only fixtures under `param-harvest/__tests__/`, NOT the byte-stable `fixtures/test-*`):
   - express: `req.query.id` → `id:query`; `_.template(req.query.tpl)` → `tpl:query`; mount `/api` + `/users` → served `/api/users`.
   - flask: `request.args.get('q')` → `q:query`.
   - **Negative/precision:** paramless route → `[]`; a `req.query.x` read *outside* the handler span doesn't attach; two handlers in one file stay separated; `/health` stays param-free.
   - **Determinism:** run the harvester twice on the same input → byte-identical `request_params` (canonical sort).
- *Accept:* express fixture recovers `id`+`tpl` as query params AND resolves to `/api/*`; flask recovers `q`; negative + determinism tests green.

### M3 — Synthesizer emits query params + CI seam test (M)
10. `dast/openapi-synth.ts`: widen `ParamForEmit.in` to `'query'|'path'|'header'|'cookie'`; after building path params, append `ep.request_params` (dedupe by `(name,in)` against path); leave the body as today's open-object (body deferred).
11. Keep health-filter + dedupe + operationId logic intact; provenance stays internal (optionally `x-deptex-*`).
12. **Unit tests:** an entry point with `request_params:[{name:'id',in:'query'}]` on `/api/users` GET produces a spec whose op has an `id` query parameter; assert the emitted doc is **valid OpenAPI 3.1** (schema-validate the parsed YAML — ZAP silently drops malformed param blocks, so this guards a false pass).
13. **CI seam e2e** (`depscanner/test/e2e/` + `npm run e2e:dast-param-enrich`): drive the synth from a fixture entry-point set (express `/api/users?id=`, `/api/render?tpl=`) → assert the synthesized spec contains the `id`/`tpl` query params on the correct `/api/*` paths and that the ZAP automation YAML threads the spec (reuse the `dast-openapi.ts` in-process pattern; **no live target**). This is the real CI gate.
- *Accept:* synthesized YAML for the express fixture has the `id` query param on `GET /api/users`; spec is valid 3.1; seam e2e green in CI.

### M4 — Regression + dogfood acceptance (M)
14. Regenerate snapshots (`npm run test:fixtures:update` via Docker) — deterministic params appear where a fixture has param-bearing routes; verify the diff is only `request_params`. `schema:dump` already done in M1.
15. Full gate: tsc (both), depscanner unit + PGLite integration, taint-engine preflight, backend tests; confirm no regression in `openapi-synth`/`cross-link`/`dast-yaml-builder` tests; paramless routes unchanged.
16. **Manual acceptance (flagged to Henry, NOT a CI gate):** boot the express fixture via `.deptex/deploy.sh` (`localhost:4001`), point a `project_dast_targets` (`synthesized`) row at it, run a DAST scan, confirm ZAP flags the `/api/users?id=` SQLi + `/api/render?tpl=` RCE. Deliver a runbook checklist; PR merge does not depend on it.
- *Accept:* CI seam (M3) + snapshot suite green; manual acceptance runbook handed to Henry.

## Testing & Validation Strategy
Unit (per-framework harvest matrix express+flask; negative/precision; determinism byte-stability; synth query-param emission; OpenAPI-3.1 validity). Integration PGLite (extraction populates `request_params`; cross-link reads back). CI seam e2e (synth→spec→YAML, no live target) = the real gate. Snapshot (deterministic params stable, regen once). Manual DAST acceptance (live ZAP) = flagged, non-CI. Regression (existing synth/cross-link tests; paramless route unchanged).

## Risks & Open Questions
- **Mount-prefix cross-file resolution** is the load-bearing new work; if the import map can't resolve a router (dynamic mounts, re-exports), fall back to the bare literal + log, and the manual acceptance covers the dogfood shape explicitly.
- **Freshness:** synthesized-spec DAST reflects the last extraction's params (re-extract after route changes). State in docs.
- Open [defer to fast-follow]: body params (`request_body_schema`), the other 6 frameworks, LLM enrichment, decorator/signature frameworks (FastAPI/Spring/NestJS).

## Dependencies
`synthesizeOpenApi` + `openapi-path-translate` (extend); `project_entry_points` + reapers + `storeEntryPoints`; taint-engine `framework-models/*.yaml` source catalog (receiver allowlist only); the extractor's import/`require` mapping (mount resolution); `schema:dump`; express dogfood fixture + `deploy.sh` (manual acceptance).

## Success Criteria
1. **CI:** the synthesized spec for the express fixture contains the `id`/`tpl` query params on the correct `/api/*` paths, is valid OpenAPI 3.1, and the seam e2e asserts it (the real gate).
2. **Determinism:** harvested `request_params` byte-identical across repeated extractions; CI AI-free + stable.
3. **No regression:** paramless routes unchanged; existing synth/cross-link/snapshot suites green.
4. **Manual acceptance (flagged):** live ZAP flags the express `?id=` SQLi + `?tpl=` RCE via the enriched synthesized spec.

## Recommended Next Step
`/implement` (M1→M4, no milestone stops per Henry). The LLM enrichment + breadth land via `dast-spec-param-llm-enrich.plan.md`.
