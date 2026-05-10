# DAST OpenAPI/GraphQL Spec Import Plan

**Status:** Plan-only. No code changes proposed in this document — every PR-class change below is a separate ship that follows Section 8's roadmap.
**Audience:** Henry. Decisions queued in Section 9.
**Worktree:** `C:\Coding\Deptex\.claude\worktrees\depscanner-hardening\`
**Owning thesis:** Per `docs/depscanner-hardening-report.md:344-376`, the highest-leverage DAST gap vs StackHawk / Snyk DAST / Probely / Aikido / Veracode / Bright is **API spec import**, and the wedge that no competitor has matched is **synthesizing the spec from `project_entry_points` instead of asking the customer for one**. ZAP's Automation Framework already supports an `openapi:` job natively (verified — `/zap/zap-api-scan.py` ships in the image at `depscanner/Dockerfile:170`). We have the entry-point data (`backend/database/phase20_entry_points.sql:14-46`, populated by 30 framework detectors at `depscanner/src/framework-rules/detectors/*`). The missing piece is the spec-synthesis bridge plus the `openapi:` AF job emit. ~1-2 weeks of work for the OpenAPI lane; GraphQL is Phase B.

---

## Section 0 — Grounding (every reference grep-verified 2026-05-09)

| Claim | File:line |
|---|---|
| `project_entry_points` schema with route_pattern + http_method + handler_name + classification + middleware_chain + metadata | `backend/database/phase20_entry_points.sql:14-46`; `backend/database/schema.sql:1148-1165` |
| 30 framework detectors live at `framework-rules/detectors/` (express, flask, fastapi, django, spring, gin, echo, fiber, rails, sinatra, laravel, symfony, slim, axum, actix, rocket, aspnet-core, etc.) | `depscanner/src/framework-rules/detectors/` (directory listing) |
| Detector emits `EntryPoint` with `routePattern`, `httpMethod`, `handlerName`, `authMechanism`, `metadata` per call | `depscanner/src/framework-rules/types.ts:25-39`; `depscanner/src/framework-rules/detectors/express.ts:74-88`; `depscanner/src/framework-rules/detectors/flask.ts:66-80` |
| DAST v2.1a/b shipped — `runDastPipeline` orchestrates ZAP via control-plane.spawnExternal | `depscanner/src/dast/pipeline.ts:696-902` |
| ZAP AF YAML builder in place — `buildAutomationYaml` emits `addOns / passiveScan-config / replacer / spider | spiderAjax / activeScan / report` | `depscanner/src/dast/yaml-builder.ts:79-236` |
| ZAP runner profiles: `'auto' \| 'quick' \| 'full' \| 'api'` | `depscanner/src/dast/runner.ts:21` |
| `'api'` profile is currently aliased to `'auto'` — never reaches a real `openapi:` job | `depscanner/src/dast/pipeline.ts:760` (`scanProfile === 'api' ? 'auto' : ...`) |
| `scan_jobs.type` enum: `extraction / dast / dast_zap / dast_nuclei` (single worker, type-aware dispatch) | `backend/database/schema.sql:6122`; `depscanner/src/index.ts:78-106` |
| ZAP image bakes Alpha+Beta passive packs + ships `zap-api-scan.py`, `zap-baseline.py`, `zap-full-scan.py` | `depscanner/Dockerfile:140-170` |
| `project_dast_targets` already has `target_url`, `detected_runtime`, `enabled`, `active_dast_run_id` — sufficient for spec attachment | `backend/database/schema.sql:1042-1057` |
| `project_dast_findings` has `endpoint_url`, `http_method`, `handler_*`, `linked_sca_*`, `cross_link_methods[]` — sufficient to record OpenAPI-discovered findings | `backend/database/schema.sql:1009-1041` |
| Hardening report calls out spec-import as #1 DAST gap and entry-point-driven synthesis as the novel wedge | `docs/depscanner-hardening-report.md:349,353,372,376,419,421` |
| `loadEntryPoints` already loads entry points for an active extraction run during DAST cross-link | `depscanner/src/dast/pipeline.ts:743-755` (calls `loadEntryPoints` from `cross-link.ts`) |

**What does NOT exist today:**
- No OpenAPI / Swagger emitter. Grep for `openapi|swagger` across the depscanner returned only the Dockerfile (zap-api-scan.py reference). Greenfield code.
- No `openapi:` AF job in `yaml-builder.ts:125-216`. The AF job array stops at `report`.
- No `api_spec` field on `project_dast_targets` or scan request body. The route at `backend/src/routes/dast.ts:670-745` accepts `target_id` only.
- No Phase B GraphQL introspection client. Greenfield.
- No baseURL discovery from CI / runtime. Out of scope (Section 10 Future).

---

## Section 1 — Why this is the wedge (3 bullets, all from `docs/depscanner-hardening-report.md:344-376`)

1. **Every DAST competitor demands an OpenAPI doc; we synthesize it.** StackHawk's HawkAI, Endor's API discovery, Snyk DAST, Probely, Aikido, Bright all require the customer to upload or auto-fetch an OpenAPI spec. Most teams either don't maintain one or maintain a stale one. We extract `project_entry_points` from source on every extraction (30 frameworks across 8 languages — `framework-rules/detectors/`), so we already have the route inventory the customer didn't write down.
2. **No LLM in the synthesis path.** HawkAI's wedge is "AI-driven API testing" — they spend prompt tokens to *guess* endpoints. We read tree-sitter ASTs deterministically. Cheaper, faster, reproducible, no model-gen drift. Crucially, this means the feature works in airgapped self-host without any AI key configured.
3. **ZAP already supports it natively.** `zap-api-scan.py` ships in the image (`Dockerfile:170`). The AF YAML accepts an `openapi` job out of the box. The integration cost is ~120 LOC of YAML emitter + ~150 LOC of synthesizer; the *moat* is the entry-point data we already extract.

---

## Section 2 — Architecture

```
Extraction pipeline (existing, untouched)
  └─ tree-sitter framework detectors (30 detectors in framework-rules/detectors/)
     └─ EntryPoint[] → project_entry_points rows
        (file_path, line_number, framework, http_method, route_pattern,
         handler_name, classification, auth_mechanism, middleware_chain, metadata)

DAST scan request (NEW api_spec_source field)
  POST /:projectId/dast/scan
    body: { target_id, api_spec_source: 'synthesized' | 'url' | 'inline' | 'none' }
  └─ queue_scan_job(p_type='dast_zap', payload.api_spec_source)

Worker dispatch (depscanner/src/index.ts:78-106 — unchanged)
  └─ runDastPipeline(job, supabase)
     └─ NEW Step 3.5: SPEC SYNTHESIS (when api_spec_source='synthesized' OR profile='api')
        ├─ loadEntryPoints(supabase, projectId, extractionRunId)   [already loaded for cross-link]
        ├─ filterToHttpRoutes(entryPoints)                         [drop graphql_resolver/cli/cron]
        ├─ synthesizeOpenApi(entryPoints, target.target_url)       [NEW: openapi-synth.ts]
        │  └─ emit OpenAPI 3.1 YAML (operationId, path, method,
        │     parameters, requestBody, x-deptex-handler extension)
        └─ write /zap/wrk/<jobid>/openapi.yaml
     └─ Step 4 (existing, with NEW openapi: job appended)
        buildAutomationYaml({ ..., openApiSpecPath })
        └─ AF jobs[]:
             addOns
             passiveScan-config
             replacer
             openapi (NEW — feeds the spider with seeded URLs)
             spider | spiderAjax
             activeScan (full only)
             report
     └─ ZAP active scan walks every synthesized endpoint
     └─ parseZapReport → findings
     └─ crossLinkFinding maps endpoint_url → handler_file_path
        via the x-deptex-handler extension we baked into the spec
        (deterministic — no fuzzy URL match needed)
     └─ project_dast_findings rows persist
```

**Two architectural notes:**

1. **Spec synthesis runs in the worker, not the backend.** The entry-point data is already loaded into the worker for cross-link (`pipeline.ts:743-755`); synthesizing the YAML there avoids a second round-trip. The synthesized YAML is a transient artifact — written to `/zap/wrk/<jobid>/openapi.yaml`, unlinked at end-of-run alongside `automation.yaml` (`pipeline.ts:543`).
2. **The `x-deptex-handler` extension closes the cross-link gap.** Today `crossLinkFinding` (`dast/cross-link.ts`) does best-effort URL→handler matching by route-pattern regex. When we synthesize the spec, we emit `x-deptex-handler: { file_path, line_number, function_name }` on every operation. ZAP doesn't pass extension fields through to the report, but our synthesizer **also** writes a sidecar `endpoint_to_handler.json` keyed on `(method, path)`; the post-scan cross-link reads it for exact handler attribution. Eliminates the URL-encoding / trailing-slash class of false-negative cross-links.

---

## Section 3 — Data model

**No new tables.** The plan leans entirely on existing schema.

| Existing surface | Use |
|---|---|
| `project_entry_points` (`schema.sql:1148-1165`) | Source of truth. Every row whose `entry_point_type='http_route'` becomes one OpenAPI operation. |
| `project_dast_targets` (`schema.sql:1042-1057`) | Already has `target_url` (the baseURL) and `detected_runtime`. Reuse. |
| `project_dast_findings` (`schema.sql:1009-1041`) | Already has `handler_file_path`, `handler_function_name`, `handler_line`. Cross-link populates them — already populated today by `crossLinkFinding`, just gets *more accurate* under spec-driven scans. |
| `scan_jobs` (`schema.sql:6122`) | Existing types `dast_zap`, `dast_nuclei` cover this. No new type. |
| `scan_jobs.payload` (jsonb) | Stash `api_spec_source: 'synthesized' \| 'url' \| 'none'` and (for `'url'`) `api_spec_url` here. No column add. |

**One additive column proposed (separate small migration):**

```sql
-- phase24c_dast_api_spec.sql (additive; ~5 lines)
ALTER TABLE project_dast_targets
  ADD COLUMN IF NOT EXISTS api_spec_source TEXT NOT NULL DEFAULT 'synthesized'
  CHECK (api_spec_source IN ('synthesized', 'url', 'none')),
  ADD COLUMN IF NOT EXISTS api_spec_url TEXT;
```

This lets the per-target setting persist (a target can be configured "always synthesize" vs "always fetch from this URL" vs "skip API mode") without churning `scan_jobs.payload` defaults. Project-level scan-time overrides still go through payload.

**What the `api_spec_source` values mean:**
- `'synthesized'` — worker walks `project_entry_points`, emits OpenAPI YAML, feeds to ZAP. **Default.**
- `'url'` — worker fetches `api_spec_url` (validated through `lib/url-guard.ts` SSRF check), feeds raw to ZAP. Customer-managed spec path.
- `'none'` — skip OpenAPI mode; spider-only baseline scan (today's behavior, fully back-compat).

---

## Section 4 — OpenAPI synthesis design

**Output spec version: OpenAPI 3.1.0.** ZAP's `openapi:` AF job accepts 2.0 / 3.0 / 3.1 (verified via `zap-api-scan.py -f` flag). 3.1 is the current spec; emit 3.1 unless we hit ZAP-version compat issues during PR 3 smoke testing.

### 4.1 Field mapping: `EntryPoint` → OpenAPI operation

Reading `framework-rules/types.ts:25-39` (the canonical EntryPoint shape):

| `EntryPoint` field | OpenAPI 3.1 emit |
|---|---|
| `routePattern` | `paths.<path>` — translated framework-pattern → OpenAPI braces (see §4.2) |
| `httpMethod` | `paths.<path>.<method>` — lowercased verb key |
| `handlerName` | `operationId` (sanitized; e.g. `getUserById`) |
| `framework` + `metadata.instance` | `tags: [<framework>]` |
| `classification` (`PUBLIC_UNAUTH` / `AUTH_INTERNAL` / `OFFLINE_WORKER` / `UNKNOWN`) | When `AUTH_INTERNAL`, attach `security: [{ deptexAuth: [] }]`; the ZAP context's auth credentials apply automatically. `OFFLINE_WORKER` rows are filtered OUT (not HTTP-reachable). |
| `authMechanism` (`bearer_jwt` / `session_cookie` / etc.) | `components.securitySchemes.deptexAuth` — emitted once at top level; type derived from authMechanism |
| `filePath`, `lineNumber`, `handlerName` | `x-deptex-handler: { file_path, line_number, function_name }` extension on the operation |
| `middlewareChain` | `x-deptex-middleware: ['authMiddleware', 'cors', ...]` extension (debugging aid; ZAP ignores) |

### 4.2 Path-pattern translation per framework

This is the synthesizer's hardest job. Each framework uses its own pattern syntax; OpenAPI uses `{paramName}`. The mapping is deterministic per framework.

| Framework | Source pattern | OpenAPI emit | Source detector |
|---|---|---|---|
| Express | `/users/:id` | `/users/{id}` | `framework-rules/detectors/express.ts:67` (`stringLiteralValue`) |
| Express | `/files/:path*` (wildcard) | `/files/{path}` + `parameters[].schema.type=string` (note as wildcard via `x-deptex-wildcard: true`) | same |
| Flask | `/users/<int:id>` | `/users/{id}` + `parameters[].schema.type=integer` | `framework-rules/detectors/flask.ts:54` |
| Flask | `/files/<path:rest>` | `/files/{rest}` + wildcard tag | same |
| FastAPI | `/users/{id}` | `/users/{id}` (already OpenAPI-shaped) | `framework-rules/detectors/fastapi.ts` |
| Spring | `/users/{id:\\d+}` (regex) | `/users/{id}` + `pattern: '\\d+'` | `framework-rules/detectors/spring.ts` |
| Gin | `/users/:id` | `/users/{id}` | `framework-rules/detectors/gin.ts` |
| Gin | `/files/*path` (catch-all) | `/files/{path}` + wildcard tag | same |
| Rails | `/users/:id` (often `/users/:id(.:format)`) | `/users/{id}` (drop `.:format` group) | `framework-rules/detectors/rails.ts` |
| Laravel | `/users/{id?}` (optional) | `/users/{id}` + `parameters[].required=false` | `framework-rules/detectors/laravel.ts` |
| ASP.NET Core | `/users/{id:int}` | `/users/{id}` + `parameters[].schema.type=integer` | `framework-rules/detectors/aspnet-core.ts` |
| Echo / Fiber / Chi / Gorilla / Hono | `:id` / `{id}` / `{id:[0-9]+}` | `/users/{id}` (drop regex) | respective detector files |

A single `translatePathPattern(framework, routePattern)` function in the new `openapi-synth.ts` handles this with a per-framework translator table. **Defensive default:** any unknown pattern goes through unchanged with a `{param}`-shape regex applied; the spec stays valid even if the param-type hints are missing.

### 4.3 What entry points DON'T tell us (gaps)

These are unavoidable — `project_entry_points` doesn't have the data:

1. **Request body schema.** Detectors record the route + method but not the body shape. **Emit `requestBody.content['application/json'].schema = { type: 'object' }` (open object).** ZAP's active scan will still mutate. Lossy but correct.
2. **Response schema.** Same. Emit `responses.default.description = 'Default response'` and call it.
3. **Query parameters not in the path.** A handler that reads `req.query.userId` is invisible at the route-registration site. **Acceptable v1 loss.** Phase B candidate: extend detectors to walk handler bodies and surface query/header reads. Out of scope for this plan.
4. **Path parameter type.** Most frameworks don't type-tag in the route pattern (Express `:id` is untyped). Default to `type: string`. Where the framework *does* tag (Flask `<int:id>`, Spring `{id:\\d+}`, ASP.NET `{id:int}`), respect the tag.
5. **Authentication scheme details.** `authMechanism` tells us "bearer_jwt" but not the issuer URL or scope set. Emit a generic `securitySchemes.deptexAuth = { type: 'http', scheme: 'bearer' }` etc. ZAP's context-level auth still applies and overrides at runtime; the spec's security requirement just tells ZAP "this op needs auth context".
6. **Request content types beyond JSON.** Most tree-sitter detectors don't capture `consumes`/content-type metadata. Emit `application/json` always; ZAP works with it. Phase B: detect `multipart/form-data` from middleware presence.

### 4.4 Operation-level pre-emit filtering

Drop these before emitting:
- `entry_point_type !== 'http_route'` (skip graphql_resolver / websocket / cli_command / cron_job / serverless_handler — handled in Phase B or out of scope).
- `classification === 'OFFLINE_WORKER'` (background queue handlers — not externally callable).
- `metadata.is_health_check === true` (some detectors tag health probes; skip — Trivia: `/health`, `/_status`, `/livez` should not pollute active scan results).
- Duplicate `(method, path)` keys (Flask emits one row per HTTP method on `methods=['GET','POST']` — those are already separate rows; but de-dupe defensively).

### 4.5 Synthesizer file layout

```
depscanner/src/dast/openapi/
  index.ts              [public API: synthesizeOpenApi()]
  path-translate.ts     [per-framework path-pattern translator table]
  schema-defaults.ts    [requestBody / responses / parameter defaults]
  handler-sidecar.ts    [emits endpoint_to_handler.json]
  __tests__/
    synth.test.ts        [unit tests: 30 detectors × 3 fixtures each]
    path-translate.test.ts
```

~250 LOC total for the synthesizer + ~400 LOC of tests across the framework matrix.

---

## Section 5 — GraphQL secondary lane (Phase B)

**Brief.** GraphQL accounts for a single-digit % of customer code per memory `extraction_worker_fixes.md`; ship OpenAPI first.

**The shape:**
1. **Source:** `entry_point_type='graphql_resolver'` rows (already an enum value at `phase20_entry_points.sql:34`). Detectors don't currently emit them — that's Phase B step 1.
2. **Spec format:** GraphQL SDL (`.graphql` schema file). ZAP's AF supports `graphql:` job that takes a schema URL OR a schema file. We synthesize the SDL.
3. **Synthesis:** harder than OpenAPI because GraphQL requires *type definitions*, not just operation lists. Either (a) emit a minimal SDL with `Query.unknown`/`Mutation.unknown` placeholders that ZAP fuzzes, or (b) fetch the introspection endpoint (`POST /graphql {query: __schema}`) at scan time and pass the result to ZAP. **Recommend (b)** — most GraphQL servers ship introspection in non-prod environments, and the introspection result is canonical.
4. **Phase B ship gate:** wait until ≥3 customers ask for it. Until then, GraphQL targets fall through to the spider-only path.

**Concretely deferred:**
- The `entry_point_type='graphql_resolver'` detector (would need to handle Apollo / Hot Chocolate / graphql-ruby / Strawberry / async-graphql).
- Introspection-vs-synthesis decision (2 options, ~2 days of comparison work).
- The `graphql:` AF job emit (~30 LOC parallel to the openapi: emit).

---

## Section 6 — ZAP integration mechanics

The depscanner Docker image already ships ZAP (`Dockerfile:140-170`). The AF YAML builder at `yaml-builder.ts:79-236` already orchestrates jobs; we add ONE new job type.

### 6.1 The `openapi` AF job

ZAP's documented job shape:
```yaml
- type: openapi
  parameters:
    apiFile: /zap/wrk/<jobid>/openapi.yaml   # local path
    targetUrl: https://api.example.com        # baseURL override (optional)
    context: deptex-dast                       # share the existing context
```

**Insertion point in `yaml-builder.ts:125-216`:** between job 3 (replacer) and job 4 (spider). Reasoning: replacer rewrites need to apply to OpenAPI-discovered URLs, and spider can use the OpenAPI-seeded URL set as additional crawl seeds. Concretely the new job order is:

```
addOns
passiveScan-config
replacer
openapi             [NEW — only when openApiSpecPath provided]
spider | spiderAjax
activeScan (full only)
report
```

**API change to `BuildAutomationYamlOptions`:** add `openApiSpecPath?: string`. When set, emit the openapi job. When unset, behave exactly as today.

### 6.2 Profile semantics

Today: `'auto' | 'quick' | 'full' | 'api'` — but `'api'` is silently aliased to `'auto'` (`pipeline.ts:760`). The plan promotes `'api'` to a real first-class profile:

| Profile | Spider | Active scan | Spec source | Use case |
|---|---|---|---|---|
| `auto` | yes | no | none (ignore api_spec_source even if set) | **Today's default; back-compat.** Passive only. |
| `quick` | yes | no (passive only, but with shorter timeout) | none | Fast smoke baseline. |
| `full` | yes | yes | none (URL discovery via spider) | Full active scan; today's behavior. |
| `api` | yes | yes | per `target.api_spec_source` (synthesized / url / none) | **NEW load-bearing.** Spec-first active scan. |

**The `api` profile is what changes.** Customers who set their target's `api_spec_source='synthesized'` (the default) and run a scan with profile=`api` get the OpenAPI lane. Customers on profile=`auto` or `full` get today's spider-only behavior unchanged.

### 6.3 BaseURL + auth reuse

The synthesizer takes `target.target_url` (already validated through SSRF guard at `routes/dast.ts:699-702`) as the OpenAPI `servers[0].url`. ZAP's context auth (form / jwt / cookie — `auth-config.ts:16-40`) applies to spec-discovered URLs without further wiring; that's the whole point of declaring the operation `security: [{ deptexAuth: [] }]` in §4.1.

### 6.4 What stays unchanged

- The cross-link layer (`dast/cross-link.ts`). The new `endpoint_to_handler.json` sidecar is *additive* — existing best-effort URL→handler matching stays for non-spec scans.
- The control plane (`dast/control-plane.ts`). Same `spawnExternal` invocation; ZAP just reads one more file from `/zap/wrk`.
- The redaction layer (`dast/runner.ts:27-50`). OpenAPI YAML doesn't contain credentials; auth still flows through context.users / replacer.
- The tenant-guard (`pipeline.ts:205-295`). Spec synthesis happens AFTER the tenant guard fires; cannot leak cross-tenant entry points.

---

## Section 7 — PR-by-PR roadmap

Six PRs, smallest-first. Each PR is independently mergeable; later PRs assume earlier ones merged.

| # | PR title | Effort | Depends on | Risk | Notes |
|---|---|---|---|---|---|
| 1 | `feat(depscanner): openapi synthesizer (lib only, no wiring)` | M (~2-3d) | nothing | Low | Pure-function library. No DAST changes. Tested in isolation against 30 detector outputs. |
| 2 | `feat(depscanner): emit openapi: AF job from yaml-builder` | S (~1d) | PR 1 merged | Low | Mechanical addition to `yaml-builder.ts:125-216`. Behind `openApiSpecPath` opt-in flag — zero behaviour change without it. |
| 3 | `feat(depscanner): wire spec synthesis into runDastPipeline (api profile)` | M (~2-3d) | PR 1+2 | Med | First user-visible behavior. Risks: empty-entry-points fallback, ZAP rejecting spec, cross-link sidecar correctness. |
| 4 | `feat(backend): api_spec_source on project_dast_targets + scan body` | S (~1d) | PR 3 | Low | Migration `phase24c_dast_api_spec.sql` (5 LOC) + route change at `routes/dast.ts:670-745` + schema:dump. Default value `'synthesized'` makes new targets opt-in to spec mode automatically. |
| 5 | `feat(frontend): API mode toggle on DAST target settings` | S (~1d) | PR 4 | Low | Two new fields on the target form (radio + URL input). Mirrors existing scope/headers settings UX. |
| 6 | `feat(depscanner): graphql introspection lane (Phase B)` | L (~5-7d) | PR 1-5; gated on demand | Med-High | Defer until ≥3 customers ask. Includes graphql_resolver detectors for top GraphQL servers + introspection client + graphql: AF job. |

**Total path-to-OpenAPI-publish (PRs 1-5):** ~8-10 dev-days. PR 6 is a separate scope.

---

## Section 8 — Open questions for Henry

These need answers before PR 3 ships.

### 8.1 OpenAPI 3.1 vs 3.0?

ZAP's `zap-api-scan.py -f` accepts `openapi`, `swagger` (2.0 alias), and (newer ZAP versions) explicit 3.1. Our pinned ZAP image is `ghcr.io/zaproxy/zaproxy:stable` (`Dockerfile:7`). Plan recommends 3.1 because it's the current spec, but if PR 3 smoke testing shows ZAP's import-into-context choking on 3.1-specific shapes (`webhooks`, `examples`, `null` handling), drop to 3.0.3. Cheap to swap. **Question:** start with 3.1 and downgrade-on-failure, or play it safe and emit 3.0.3 from day one?

### 8.2 Default behavior on empty entry points?

A project with zero `project_entry_points` rows (extraction never ran, framework not detected, fresh integration) has nothing to synthesize. Three options:
- **(a) Fall back to spider-only.** API-mode scan runs as if profile=`auto`. Silent. Risk: customer thinks API mode worked, gets spider-only results.
- **(b) Hard-fail the scan job.** `error_category='no_entry_points_for_api_mode'`. Loud. Risk: blocks customers whose framework we don't yet detect.
- **(c) Soft-warn with surfaced banner.** Run anyway as spider-only; record a warning on `scan_jobs.error_payload` that the UI surfaces ("API mode requested but no entry points detected; ran spider-only").

**Recommend (c).** Spider-only is still useful, and the warning is the right loudness for "your detector probably doesn't cover this framework yet."

### 8.3 Spec-source override precedence?

Three sources of truth for "what spec do I use?":
- `project_dast_targets.api_spec_source` (per-target persistent)
- Scan-time payload `api_spec_source` (per-job override)
- Per-org default (does this exist? — does NOT exist today)

Plan defaults to scan payload > target row > implicit `'synthesized'`. **Question:** add a per-org default (in `organization_dast_settings` or similar) at PR 4? Or leave per-org as a future feature?

Recommend **leave per-org as future**. Two surfaces is plenty for v1.

### 8.4 OperationId collision strategy?

Two Express handlers both named `getUser` in different files produce the same `operationId`. OpenAPI 3.1 requires unique operationIds across the spec. Options:
- **(a)** Suffix with file basename: `getUser_userController`. Readable, deterministic.
- **(b)** Suffix with line number: `getUser_42`. Always unique, less readable.
- **(c)** Suffix with framework prefix only when ambiguous: `getUser`, `express_getUser` (only when needed).

**Recommend (a).** Most readable, deterministic enough for ZAP's internal use.

### 8.5 What about `entry_point_type='websocket'`?

Phase 20 schema reserves `websocket` as a value. ZAP doesn't support WebSocket in OpenAPI mode. **Recommend skip silently** (filter out at §4.4). WebSocket DAST is out of scope for v1 — ZAP has a separate WebSocket panel that's not in AF.

### 8.6 Should we publish the synthesized spec back to the customer?

A real customer-facing question: when we synthesize a 200-route spec, that's potentially valuable to the customer as "here's the API doc you didn't write." Three postures:
- **(a) Internal-only.** Spec is a transient artifact in `/zap/wrk`; gone after scan.
- **(b) Stash on scan run.** Save as a blob on `scan_jobs.payload.synthesized_spec_url` (Supabase storage bucket).
- **(c) Stash on target.** Persist the latest synthesis on `project_dast_targets.last_synthesized_spec_url`. Customer downloads via UI.

**Recommend (a) for v1, (c) for v2.** Persisting specs has retention/PII questions (handler names + paths are ~not~ PII but customers may treat them as sensitive). Get the scan-pipeline shipping first; surface the spec as a download in a follow-up.

---

## Section 9 — Future work (not in this plan)

- **Recorded HAR replay.** v2.1d as designed in `aegis_roadmap.md` — replay browser session HARs through ZAP for SPA / OAuth flows. Spec-first DAST and recorded HAR are complementary, not competing.
- **GraphQL introspection client.** Per Section 5; Phase B gate.
- **BaseURL discovery from CI.** When we receive a webhook or PR, discover staging URL from the env (e.g. Vercel preview URL) and run a per-PR DAST scan with the synthesized spec. Closes the StackHawk PR-comment moat.
- **Live-API fingerprinting.** Compare synthesized spec against actual server `OPTIONS` responses to detect drift (real endpoint exists that synthesizer missed → detector gap signal).
- **Query / header parameter inference from handler bodies.** Walk handler ASTs for `req.query.X` / `req.headers['X']` reads; surface as OpenAPI parameters. Big detector-side investment but big synthesis-quality payoff.
- **AI-assisted body schema inference.** When a handler reads `req.body.user.email`, infer schema. Tier-1 task (Gemini Flash); we pay; ~$0.0001/operation. Defer until manual mode is proven first.
- **SARIF DAST output.** Cross-cuts with `docs/depscanner-hardening-report.md:422`. Independent of OpenAPI lane.
- **Multipart / non-JSON content types.** Current synthesis assumes JSON. Phase B for file upload endpoints.

---

## Appendix — files referenced (grep-verified)

**Will create:**
- `depscanner/src/dast/openapi/index.ts` (synthesizer entry; ~80 LOC)
- `depscanner/src/dast/openapi/path-translate.ts` (~120 LOC)
- `depscanner/src/dast/openapi/schema-defaults.ts` (~40 LOC)
- `depscanner/src/dast/openapi/handler-sidecar.ts` (~30 LOC)
- `depscanner/src/dast/openapi/__tests__/synth.test.ts` (~250 LOC)
- `depscanner/src/dast/openapi/__tests__/path-translate.test.ts` (~150 LOC)
- `backend/database/phase24c_dast_api_spec.sql` (~5 LOC; additive only)

**Will edit:**
- `depscanner/src/dast/yaml-builder.ts:42-216` (add `openApiSpecPath` to options + new openapi job between replacer and spider — ~25 LOC)
- `depscanner/src/dast/pipeline.ts:743-793` (call synthesizer between cross-link prep and ZAP spawn; pass spec path through to runZapWithControlPlane — ~40 LOC)
- `depscanner/src/dast/cross-link.ts` (read sidecar `endpoint_to_handler.json` for exact handler attribution — ~30 LOC)
- `backend/src/routes/dast.ts:670-745` (accept `api_spec_source` override on POST scan body; pass through queue_scan_job payload — ~15 LOC)
- `frontend/src/components/dast/TargetSettings.tsx` (or wherever target settings UI lives — verify path during PR 5; ~80 LOC)

**Will read (no edits):**
- `depscanner/src/framework-rules/types.ts:25-39` (EntryPoint shape)
- `depscanner/src/framework-rules/detectors/*.ts` (×30 — to confirm metadata fields per framework before path-translate.ts)
- `depscanner/src/dast/cross-link.ts` (loadEntryPoints contract)
- `backend/database/schema.sql:1148-1165` (project_entry_points columns)
- `backend/database/schema.sql:1009-1057` (project_dast_findings + project_dast_targets columns)
- `docs/depscanner-hardening-report.md:344-376` (DAST competitive context, already pre-read)

**Total expected diff:** ~600 LOC of new code, ~110 LOC of existing-file edits, 1 new 5-line migration.
