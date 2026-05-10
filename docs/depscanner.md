# Depscanner — contributor reference

Depscanner is the unified scanner worker that backs every Deptex project. This
document is the long-form contributor reference: pipeline architecture, how to
run it locally, and how to extend each of the load-bearing surfaces (pipeline
steps, framework detectors, framework specs, CVE-targeted rules, taint engine
languages). The companion living document
[`depscanner-hardening-report.md`](./depscanner-hardening-report.md) catalogues
the in-flight hardening sprint findings and competitive analysis — it is
deliberately not duplicated here.

The reader is assumed to know TypeScript and Postgres; no prior Deptex
exposure is required. Filenames are given relative to the repository root.

> **Caveat.** This subsystem is moving fast. Where current behaviour is
> aspirational (e.g. cross-ecosystem recall, framework-spec coverage), this
> document says so. Numbers are accurate at the time of writing; the
> reachability scoreboard at `docs/88-cve-scoreboard-plan.md` is the source of
> truth for current recall.

---

## 1. Overview

`depscanner/` is the single Fly.io worker app (`deptex-depscanner`) that
performs every long-running scan in Deptex. A scan is whatever the API calls
"queue a job" — extraction (`type='extraction'`) is the dominant case today;
DAST (`type='dast'`, `dast_zap`, `dast_nuclei`) is the second dispatch path.
IaC + container, malicious-package, and SAST/secrets all run inside the
extraction pipeline rather than as separate job types.

In one paragraph: the worker polls `scan_jobs`, claims a row for a `type` it
supports, and runs a typed pipeline. For extraction the pipeline clones the
repo, generates a CycloneDX SBOM, syncs dependencies into Postgres, parses the
source with tree-sitter, runs `dep-scan` for known-CVE matches, generates +
runs reachability rules (a per-CVE FrameworkSpec generator backed by AI plus
the cross-file taint engine), classifies reachability, runs IaC + container +
malicious + SAST + secrets sub-scanners, then atomically commits the run.
Logs stream to `extraction_logs` (Supabase Realtime) the entire time. On
Fly.io the worker scales to zero — when no jobs exist for 60s the process
exits, and `claim_scan_job` boots a new machine on the next enqueue.

The worker is intentionally a thin orchestrator over a fleet of pinned CLI
tools (cdxgen, dep-scan, Semgrep, TruffleHog, Trivy, Checkov, GuardDog, ZAP).
Most "Deptex logic" lives in the post-processing: matching reachability flows
back to PURLs, dispatching framework-aware taint rules, and feeding contextual
EPD scoring. The Dockerfile (`depscanner/Dockerfile`) is the source of truth
for runtime tool versions.

### How depscanner relates to the rest of Deptex

```
backend (Express)         API + Supabase clients + Aegis tools.
  └─ queueExtractionJob -> inserts scan_jobs row, boots a Fly machine.

depscanner (this worker)  Pipeline + sub-scanners + storage writes.

fix-worker                Aegis Fix Agent. Plan-then-execute coding agent.
                          NOT a depscanner mode.

frontend (React)          Reads the same Supabase tables depscanner writes.
                          Subscribes to extraction_logs for realtime UI.
```

The boundary between `backend/` and `depscanner/` is firm: the API never
reaches into a worker process; the worker never serves HTTP. They communicate
exclusively via Supabase tables (`scan_jobs`, `extraction_logs`,
`project_*` rows, etc.).

---

## 2. Pipeline architecture

The extraction pipeline runs 15 stages in order. Each stage owns a module
under `depscanner/src/pipeline-steps/`; the orchestrator
`depscanner/src/pipeline.ts` is intentionally a thin top-to-bottom listing
that you can read in a minute. Look up `pipeline.ts` to see the order; jump
to the per-step module to change a body.

### 2.1 Stage list (post-refactor #1)

| # | Stage             | Module (`pipeline-steps/`)    | Severity | Notes                                          |
|---|-------------------|-------------------------------|----------|------------------------------------------------|
| 1 | clone             | `clone.ts`                    | error    | Clones repo or accepts `localWorkspacePath`.   |
| 2 | resolve           | `resolve.ts`                  | warn     | Ecosystem-specific install pre-SBOM (npm, pip, mvn). |
| 3 | sbom              | `sbom.ts`                     | error    | cdxgen `--profile research --deep`. Hard-fails. |
| 4 | deps_sync         | `deps-sync.ts`                | error    | Upserts `project_dependencies` + `*_versions`. |
| 5 | usage_extraction  | `usage-extraction.ts`         | warn     | tree-sitter parse + framework entry-point detection. |
| 6 | (asset_tier hydrate) | `asset-tier.ts`            | n/a      | Loads `assetTier` + `tierMultiplier` into ctx. |
| 7 | dep_scan          | `dep-scan.ts`                 | warn     | OWASP `dep-scan` runs the CVE match. PDV upsert. |
| 8 | rule_generation   | `rule-generation.ts`          | warn     | Phase 5 AI rule generation (per-CVE).          |
| 9 | taint_engine      | `taint-engine.ts`             | error    | Cross-file taint engine. Hard-fail by policy.  |
|10 | reachability + EPD | `reachability.ts`            | warn     | Classifier + depscore recalc + EPD scoring.    |
|11 | iac_container     | `iac-container.ts`            | warn     | Trivy + Checkov.                               |
|12 | malicious_scan    | `malicious.ts`                | warn     | Feeds + GuardDog.                              |
|13 | semgrep           | `semgrep.ts`                  | warn     | SAST. Optional registry-default ruleset.       |
|14 | trufflehog        | `trufflehog.ts`               | warn     | Secret scan.                                   |
|15 | finalize          | `finalize.ts`                 | error    | Atomic Phase 19.3 commit RPC. Flips active run. |

"Severity" follows the convention `runStage` enforces: `error` rethrows and
aborts the extraction; `warn` logs to `extraction_step_errors` and continues.
Hard-fail stages abort the whole run on exception; soft-fail stages let the
extraction complete with degraded output. The `taint_engine` stage is unusual
in that it treats engine exceptions as hard-fail by deliberate policy — the
fleet-wide rollout pct + circuit breaker do the soft-degradation upstream of
the engine itself (see `pipeline-steps/taint-engine.ts:13`).

The pipeline is cancellation-aware. A `checkCancelled()` callback is passed
in by the worker (`src/index.ts`) and consulted between every stage; the
heartbeat callback is fired by an interval timer in the same file so the
60-second job heartbeat survives even when a long subprocess is running.

### 2.2 The shared context

`PipelineContext` (`depscanner/src/pipeline-types.ts`) is the mutable bag of
state that every stage receives. Only fields that legitimately cross stage
boundaries belong on it: `runId`, `workspaceRoot`, `assetTier`,
`projectDepsCount`, `newDepsToPopulate`, `astParsedSuccessfully`. Stage-local
scratch (parsed SBOM rows, VDR file lists, taint flows pre-write) stays
inside the stage module.

If you find yourself wanting to pass a fourth argument to `doFoo()`, the
right answer is usually "this is a step boundary and the value belongs on
the context", not "add a parameter".

### 2.3 `runStage()` — the boilerplate-eating helper (post-refactor #3)

Every stage previously hand-rolled the same five-line dance: `withTimeout`,
`classifyError`, `logStepError`, `setError`, decide rethrow-vs-continue.
`runStage` (in `depscanner/src/pipeline-stage-runner.ts`) consolidates the
ceremony and gives stages a single `onError` hook to keep their bespoke
post-failure behaviour (CDXgen → user-friendly message, finalize → atomic
rollback signal, etc.).

Minimum viable usage:

```ts
await runStage({
  name: 'malicious_scan',
  severity: 'warn',
  supabase: ctx.supabase,
  jobId: ctx.job.jobId,
  projectId: ctx.projectId,
  log: ctx.log,
  fn: async () => {
    // ... step body ...
  },
  onError: async ({ err }) => {
    await ctx.log.warn('malicious_scan', `Failed: ${(err as Error).message}`);
  },
});
```

Key options (all defined in `pipeline-stage-runner.ts:38`):

- `name` — used as `extraction_step_errors.step` and the `withTimeout` label.
- `timeoutMs` — when set, the body runs inside `withTimeout` and the body
  receives an `AbortSignal`. Subprocess callers MUST forward the signal so
  the child actually dies on timeout (`signal.addEventListener('abort',
  () => child.kill('SIGTERM'))`).
- `severity` — `'error'` (default) rethrows; `'warn'` swallows and returns
  `undefined`.
- `omitDuration` — when true, the persisted error row omits `duration_ms`.
  Used by stages that historically only persisted `code/message/stack`
  (rule_generation, iac_container_scan). Telemetry parity matters for
  downstream queries.
- `onError({ err, code, message, stack, durationMs, persisted })` — runs
  AFTER the helper has classified the error and (if `jobId` is set)
  persisted the row. Return `{ rethrow: false }` to override the severity
  default; return `{ throwAs: customError }` to rewrite what gets thrown.
  If the hook itself throws, the thrown value replaces `err`.

### 2.4 Atomic commit

`finalize` is the only mutating stage that promises atomicity. It calls the
`finalize_extraction` RPC (Phase 19.3), which in a single transaction:

- marks deps missing from this run as `removed_at = NOW()`,
- carries forward PDV user state (status, suppressed, SLA, re-review reasons)
  by `(dep_name, osv_id)`,
- detects re-review triggers (depscore/severity/reachability/KEV/EPSS deltas),
- writes `'detected'` / `'reopened'` / `'rereview_triggered'` events,
- carries forward Semgrep + secret status by fingerprint,
- computes SLA deadlines for newly-detected findings,
- flips `project_repositories.active_extraction_run_id` to this run,
- reaps finding rows whose `run_id` is neither (new active, previous active),
- returns the summary JSONB the CLI persists into `summary.json`.

Everything written before `finalize` lives under the pending `extraction_run_id`
and is invisible to API consumers (which read `active_extraction_run_id`). This
makes a partial run safe — if the worker dies at stage 9, the user sees the
prior run, not a half-populated UI.

---

## 3. Local development

### 3.1 Docker-only

Depscanner is **Docker-only** for local runs. The pipeline depends on cdxgen,
dep-scan, Semgrep, Trivy, Checkov, GuardDog, TruffleHog, atom, JDK 21, Maven,
Go, plus a pinned Python venv layout — reproducing that on a contributor's
laptop is a non-starter. Tests that need to exercise the real pipeline use
the same image. Pure unit tests (typescript-only, no shell-out) run via
`backend/`'s jest setup against PGLite. See `docs/contributor-test-infra-plan.md`
for the rationale.

### 3.2 Build the image

From `depscanner/`:

```bash
npm run docker:build
```

Behind the scenes this runs `docker:prepare` (which copies
`backend/database/schema.sql` into `depscanner/.schema/` so PGLite local-mode
can find it) and then `docker build -t deptex-cli:local .`. The build is
~3GB. Subsequent rebuilds with no source changes hit the layer cache and
finish in seconds.

### 3.3 Run a scan locally

The CLI runs the same pipeline as the Fly worker, but writes to PGLite
instead of Supabase. The host wrapper is `depscanner/bin/deptex-scan` (a
bash script that mounts the workspace + output dir into the container);
the in-container entrypoint is `depscanner/src/cli/index.ts`.

```bash
./bin/deptex-scan run /path/to/your/repo \
  --output=./extraction-results \
  --ecosystem=npm \
  --fail-on=high \
  --format=table
```

Exit codes: `0` (clean), `1` (findings at or above `--fail-on`), `2`
(pipeline error). The CLI writes `summary.json`, per-finding JSON files, and
a host-readable directory you can `cat`. PGLite state lives in
`.pglite-buckets/` inside the output dir — wipe between runs.

The CLI mode skips the worker dispatch loop entirely; it constructs an
`ExtractionJob` from CLI args and calls `runPipeline()` directly. The
pipeline doesn't care which `Storage` it's handed.

### 3.4 The snapshot test suite

Snapshot tests live under `depscanner/test/snapshot.ts` and exercise the
real CLI against fixtures under `depscanner/fixtures/`. The runner spawns
`./bin/deptex-scan` (so it catches CLI-level regressions — arg parsing, exit
codes, stdout shape — alongside pipeline changes), then diffs each JSON
output file against the committed snapshot under
`fixtures/<name>/snapshots/`.

Day-to-day:

```bash
cd depscanner
npm run test:fixtures             # all fixtures
npm run test:fixtures -- --fixture=test-minimal-npm
npm run test:fixtures:update      # accept new outputs
npm run test:fixtures -- --diff-only   # dry run; never write
```

Bootstrap behavior: a missing snapshot file (or fixture with no `snapshots/`
dir) is **not** a failure — the runner writes the file and reports it as a
bootstrap. The contributor commits it in the same PR. This matches jest's
`toMatchSnapshot()` UX. Only mismatches against an existing snapshot fail.

The default ignore list (`DEFAULT_IGNORE_FIELDS` in `test/snapshot.ts:68`)
strips fields that change every run by design — UUIDs, timestamps,
extraction_run_id, absolute paths. Per-fixture extras can be added via
`fixtures/<name>/snapshot-ignore.json`.

To add a new fixture:

1. Create `depscanner/fixtures/<name>/` containing the manifest the pipeline
   should scan (`package.json`, `requirements.txt`, `go.mod`, etc.).
2. Add an entry to the `FIXTURES` array in `test/snapshot.ts`. Mark `slow:
   true` if the run exceeds ~30s (these are skipped by default and require
   `--fixture` or `--only` to opt in).
3. Run `npm run test:fixtures:update` to bootstrap the snapshot directory.
4. `git add fixtures/<name>` (manifest + the new `snapshots/`).

### 3.5 Unit tests

Most TypeScript-only logic (pipeline helpers, classifiers, depscore math,
EPD math, taint engine invariants, FP filter, propagators, callgraph
builder) runs as jest tests under `backend/src/__tests__/` — depscanner does
not have its own jest project. Reason: the code under test is mostly
imported back into `backend/` for shared use, and a single jest project
keeps coverage honest.

```bash
cd backend
npm test                      # jest, all tests
npm test -- pipeline          # filter by file name
npm test -- --watch           # watch mode
```

Depscanner-specific PGLite integration tests live under `depscanner/test/`
and are tsx scripts, not jest. Each is wired into a `test:*` npm script in
`depscanner/package.json` — search there for the surface you're touching.
Examples:

- `npm run test:taint-engine-all` — full taint-engine preflight (callgraph
  + propagator + per-language fixtures + invariants + integration).
- `npm run test:storage` — PGLite Storage abstraction conformance.
- `npm run smoke:pglite` — end-to-end PGLite smoke (loads schema.sql,
  inserts representative rows, asserts the query builder shape).
- `npm run test:rule-generation-step-pglite` — per-CVE rule generation
  against a seeded PGLite instance.

CI runs the unit tests + the snapshot suite + the taint-engine preflight on
every PR. PRs that touch a migration also trigger
`.github/workflows/schema-check.yml`, which fails if `schema.sql` wasn't
re-dumped (`cd depscanner && npm run schema:dump`).

---

## 4. Adding a new pipeline stage

The most common kind of change. Concretely: create `pipeline-steps/<name>.ts`
exporting `do<Name>(ctx)`, add the call in `pipeline.ts` at the right
position, decide hard-fail vs soft-fail, and persist any cross-stage state
on `PipelineContext`.

Concrete checklist:

1. **Pick a position.** The stage list above is canonical. Earlier stages
   run before SBOM is parsed and have no dependency rows; mid-pipeline
   stages run after `assetTier` is loaded; finalize is always last.
2. **Create `depscanner/src/pipeline-steps/<name>.ts`.** Export a single
   `async function do<Name>(ctx: PipelineContext): Promise<...>`. The first
   line of the file should be a doc-comment block stating the contract:
   what state it reads from `ctx`, what state it writes to the DB, and
   whether it's hard-fail or soft-fail. Mirror existing stage doc-comments
   in tone (the `sbom.ts` and `taint-engine.ts` headers are good models).
3. **Wrap the body in `runStage()`.** Pick `severity: 'error'` for hard-fail,
   `'warn'` for soft-fail. If the body shells out to a subprocess, set
   `timeoutMs` and forward the AbortSignal into the child. If you need
   bespoke post-failure behavior (transform error message, hard-fail when
   normally soft, write a bespoke telemetry row), use `onError`.
4. **Update `PipelineContext`** if your stage needs to expose state to a
   later stage. Add the field with a meaningful default in `pipeline.ts`'s
   context construction (`pipeline.ts:63-80`); add it to
   `pipeline-types.ts`'s `PipelineContext` interface with a doc-comment
   explaining ownership. Don't piggyback on a near-synonym field.
5. **Wire the call.** Add `import { do<Name> } from './pipeline-steps/<name>';`
   at the top of `pipeline.ts` and add the call in the correct slot of the
   `runPipeline()` body. Match the surrounding cancellation + heartbeat
   pattern (see `pipeline.ts:86-160`).
6. **Tests.** Add a unit test under `backend/src/__tests__/` covering the
   classifier logic. Add a fixture under `depscanner/fixtures/` only if the
   stage produces visible output in `summary.json` or the per-finding
   files. Run `npm run test:fixtures:update` to refresh snapshots.
7. **Logging.** Use `ctx.log.info('<step>', '...')` for normal progress and
   `ctx.log.warn('<step>', '...')` for soft failures. The first arg is the
   step name; the API filters extraction logs by it. Don't `console.log` —
   the worker mode discards stdout in favour of `extraction_logs`.

A common pitfall: **don't add a heavy Postgres read at the top of every
stage.** Stages share `ctx`, so cache the read once at the stage where it's
first needed and propagate via `ctx`. The `loadAssetTier` step
(`pipeline-steps/asset-tier.ts`) is a deliberate example — every depscore-
touching stage was reading the same row before refactor #1.

---

## 5. Adding a framework detector

A "framework detector" is a flat rule-pack that walks a parsed AST and
emits `EntryPoint` rows (HTTP routes, serverless handlers, message
consumers, etc.) into `project_entry_points`. Entry points feed EPD
contextual scoring, which flows into `depscore`.

Today there are **34 detectors** covering 8 languages. They live under
`depscanner/src/framework-rules/detectors/`:

```
JS / TS  express, fastify, koa, nestjs, nextjs, aws-lambda
Python   flask, fastapi, starlette, django, tornado, aiohttp
Java     spring, jaxrs, quarkus, micronaut
Go       nethttp, gin, echo, fiber, chi, gorilla-mux
Ruby     sinatra, rails, grape
PHP      laravel, symfony, slim
Rust     actix, rocket, axum, warp
C#       aspnet-core, minimal-apis
```

The detector contract is a single interface
(`depscanner/src/framework-rules/types.ts:57`):

```ts
export interface FrameworkDetector {
  name: string;                              // stored in project_entry_points.framework
  displayName: string;                       // shown in the UI
  language: SupportedLanguageId;
  triggerImports: readonly string[];         // file skipped if none match
  detect(ctx: DetectorContext): EntryPoint[];
}
```

`DetectorContext` (same file) carries the source text, the parsed tree, and
the language module's `ExtractedFile` output (imports + usages). The
detector returns zero or more `EntryPoint` rows.

Adding one is a two-step change. The walking guide at
`depscanner/docs/framework-rule-pack-guide.md` covers patterns and helpers
in depth; the bare-minimum recipe is:

1. **Create `depscanner/src/framework-rules/detectors/<name>.ts`** exporting
   a `FrameworkDetector`. Pick the closest existing detector by language +
   pattern (instance-based / decorator-based / convention-based) and copy
   its skeleton. The shared utilities under
   `depscanner/src/framework-rules/util/` cover ~80% of tree-walking work
   — use `walkTree`, `findInstancesOfImport`, `detectAuthMechanism`,
   `classifyFromAuth`, `lineOf`, `stringLiteralValue`, `handlerDescriptor`,
   etc., rather than reinventing them.
2. **Register it in `depscanner/src/framework-rules/registry.ts`.** Import
   the detector and append it to the `ALL_DETECTORS` array. The registry is
   a flat list — no class hierarchies, no auto-loading.
3. **Tests.** Add a fixture under `depscanner/fixtures/` if you want the
   snapshot suite to cover it; otherwise a unit test under
   `backend/src/__tests__/` calling `detect()` against a parsed tree is
   sufficient.

Detector throws are caught and swallowed at the call site — a bug in one
detector must not take down the whole extractor — but you should still
write defensively. `lineNumber` is 1-based to match the DB.

---

## 6. Adding a framework spec (taint engine)

A FrameworkSpec describes how a single framework introduces tainted data
(`sources`), where untrusted data must not flow (`sinks`), and what cleans
it (`sanitizers`). Specs are loaded by the cross-file taint engine
(`depscanner/src/taint-engine/`) at the start of every extraction.

The spec types live in `depscanner/src/taint-engine/spec.ts`. There are two
classes of spec:

- **Bundled framework-generic specs** — YAML files at
  `depscanner/src/taint-engine/framework-models/*.yaml`. Loaded for every
  scan in the matching ecosystem. 23 specs ship today (`actix-web.yaml`,
  `aspnet-core.yaml`, `axum.yaml`, `django.yaml`, `dotnet-stdlib.yaml`,
  `echo.yaml`, `express.yaml`, `fastapi.yaml`, `fastify.yaml`, `flask.yaml`,
  `gin.yaml`, `go-stdlib.yaml`, `hono.yaml`, `java-stdlib.yaml`,
  `laravel.yaml`, `nestjs.yaml`, `nextjs.yaml`, `node-stdlib.yaml`,
  `rails.yaml`, `rust-stdlib.yaml`, `sinatra.yaml`, `spring-boot.yaml`,
  `symfony.yaml`).
- **CVE-targeted specs** — JSONB rows in `organization_generated_rules`
  with `spec_format = 'framework_spec'`. Generated at scan time by the AI
  rule-generation step (§8) for the specific CVEs detected in this scan.

### 6.1 Spec schema

```yaml
framework: express
version: "*"

sources:
  - pattern: req.body.*           # prefix match
    taint_kind: http_input
    description: Express request body
  - pattern: req.query.*
    taint_kind: http_input
    description: Express request query string

sinks:
  - pattern: res.send(*)          # call expression with this callee text
    vuln_class: xss
    argument_indices: [0]
    description: Express response body

sanitizers:
  - pattern: validator.escape(*)
    description: HTML-escape user-supplied strings
```

Pattern grammar (M2 — see `spec.ts:65-76`):

- `Foo.bar` — exact match against the AST node's source text
- `Foo.bar.*` — prefix match (matches `Foo.bar`, `Foo.bar.x`, …)
- `Foo.bar(*)` — call expression where the callee text is `Foo.bar`

`vuln_class` must be one of the closed taxonomy in
`spec.ts:32-44`: `sql_injection`, `ssrf`, `xss`, `path_traversal`,
`command_injection`, `prototype_pollution`, `deserialization`, `redos`,
`file_upload`, `open_redirect`, `log_injection`, `code_injection`. The
generator's `vuln_class_out_of_scope` failure code is reserved for vuln
classes that genuinely fall outside taint flow (DoS, XML expansion,
HTTP/2 reset attacks).

`argument_indices` is the set of zero-based positional argument slots that
trigger the sink when tainted. Empty array means "any tainted argument
triggers" — used for variadic logging helpers and for functions where
every argument is unsafe.

### 6.2 Adding a bundled spec

1. Drop the YAML at `depscanner/src/taint-engine/framework-models/<name>.yaml`.
2. The runner discovers it automatically at engine startup
   (`taint-engine/runner.ts:18`). No registry edit required.
3. The build step (`npm run build` in `depscanner/`) copies the YAML tree
   into `dist/taint-engine/framework-models/` so the bundled spec is
   reachable from compiled output.
4. Add a unit test under `backend/src/__tests__/` covering at least one
   source/sink pair and at least one sanitizer.

If a spec ships with `osv_id` set on a sink (CVE-targeted bundled spec —
rare), the propagator stamps that osv_id onto every flow that hits the
sink, so the classifier can promote the matching PDV to `confirmed`. The
framework-generic specs (`express.yaml` etc.) leave `osv_id` undefined.

The convention `framework_spec_osv_matches_cve` enforces that any sink
carrying an `osv_id` corresponds to a real CVE the dep-scan run produced.
The validator `taint-engine/spec-loader.ts` rejects mismatched ids.

---

## 7. Adding a CVE rule pack

CVE rule packs are no longer file-shaped. They live in
`organization_generated_rules` as JSONB rows produced by the per-org AI
rule generator at scan time (§8). The legacy `depscanner/reachability-rules/`
directory of hand-authored Semgrep YAMLs was retired in Phase 6.5/M5 (see
the `pipeline.ts:113-125` comment) and is no longer consulted.

> **Inconsistency to flag.** The repo-wide `CLAUDE.md` still references
> `depscanner/reachability-rules/` and a `scripts/validate-reachability-rules.ts`
> CI gate — neither exists in the post-Phase-6.5 tree. The note belongs in
> the same cleanup pass that retired the directory.

To add a CVE rule pack today:

1. **Make sure the CVE is in dep-scan's database.** Rule generation is
   triggered only for CVEs that dep-scan emits as a PDV in the run. If
   the CVE is too new to have an OSV / GHSA entry, it won't be a candidate.
2. **Tune the org's rule-generation settings.** The `auto_generate_enabled`
   flag and the per-severity / per-tier trigger policy live on
   `organization_reachability_settings`. The generator filters candidates
   through `applyTriggerPolicy` (`cve-generation/trigger-filter.ts`) before
   spending budget.
3. **Manual override.** Operators can insert hand-authored
   `organization_generated_rules` rows with `validation_status =
   'manual_override'`; these load alongside `validated` rows. Use this for
   high-value CVEs where the AI keeps producing schema-invalid output.
4. **Fixtures + verification.** End-to-end CVE coverage tests live under
   `depscanner/test/cve-targeted-flow-fixtures/`. Add a fixture (vulnerable
   + sanitized + suppressed variants) and run
   `npm run test:taint-engine-cve-targeted-fixtures`.

The 88-CVE scoreboard at `docs/88-cve-scoreboard-plan.md` is the operator-
facing dashboard for which CVEs the per-org generator currently covers.

---

## 8. AI rule generation (Phase 5 / 6.5)

The AI rule generator drafts and validates a FrameworkSpec for each CVE in
the run that matches the org's trigger policy and isn't already covered by
a platform or org-existing rule. The validated spec lands in
`organization_generated_rules` and the next stage (taint engine) loads it.

### 8.1 The funnel

`CveGenerationCoordinator` (`depscanner/src/cve-generation/coordinator.ts`)
holds per-scan state and walks one canonical funnel:

```
loadSettings()
  → applyTriggerPolicy()        (severity / asset-tier gate)
  → subtractCoveredCves()       (org-existing rules)
  → resolveApiKey()             (platform key only — BYOK retired)
  → applyBudgetCap()            (per-month per-org dollar cap)
  → generateBatch()             (p-limit(5), per-CVE retry, rate-limit gate)
  → persistResults()            (validated + failed-validation stub rows)
  → persistJobTelemetry()       (scan_jobs.reachability_*)
```

Behavioural contract (preserved verbatim from the pre-decomposition file):

- Any short-circuit returns `ZERO_RESULT` so the pipeline continues with
  whatever rules existed before. **The generator never aborts the
  extraction.**
- Read failures on org-existing-coverage and `ai_usage_logs` are
  fail-closed (skip generation). A Supabase blip must not silently
  regenerate every CVE or disable the budget cap.
- Failed-validation, `prompt_injection_suspect`, and pre-attempt-bail
  rows are persisted as **stub rows** so the org-settings UI can render
  "uncoverable because <reason>".
- Per-CVE provider-error retry sits OUTSIDE the inner
  `withRateLimitRetry`. A global rate-limit cool-down keeps concurrent
  slots from racing into 429s.
- Telemetry is written to `scan_jobs.reachability_*` when `jobId` is set.

The class is instantiated per-scan; there is no caching across scans.

### 8.2 Fallback ordering

When the primary provider (configured at the org level) fails, the
generator does NOT try a different provider — it surfaces a stub row with
`failure_reason = 'provider_error_after_retries'` and moves on. The
fallback is operator-driven (re-run after fixing the provider key), not
in-scan.

The single in-scan fallback is the **Anthropic fallback for EPD scoring**
(distinct from rule generation, but shares the burn-breaker ceiling). When
the OpenAI EPD pass returns inconclusive verdicts on a flow, EPD optionally
calls Anthropic for a second opinion. The cost is gated by the
fp-filter cost cap (`taint-engine/cost-cap.ts:DEFAULT_MONTHLY_AI_COST_CAP_USD`)
and surfaced in `epd_status` as `ai_verified_anthropic_fallback*` (see
`epd.ts:39-43`).

### 8.3 Recall today

Honest number: the per-org one-shot AI generator tops out around 26.1%
recall on the 88-CVE Qwen benchmark (62% npm, 9% pypi, 0% on
gem/golang/maven). The bottleneck is FrameworkSpec ecosystem coverage, not
the generator itself — the npm framework specs (Express + node-stdlib)
cover most of the reachable sinks, while the equivalent specs for Python
/ Ruby / Go are sparse. See the scoreboard at
`docs/88-cve-scoreboard-plan.md` for breakdown.

A feedback-loop retry mode (Phase 5c — "show the model its previous
output and the validator's complaint, ask for a corrected spec") could
push that to 40-60% but is not yet implemented.

---

## 9. Cross-file taint engine (Phase 6)

The taint engine is a deterministic, language-aware forward propagator. It
runs in stage 9 of the pipeline (`pipeline-steps/taint-engine.ts`). The
public surface is `runEngine()` in `taint-engine/runner.ts`; the public
re-exports are in `taint-engine/index.ts`.

### 9.1 Architecture

```
buildCallgraph()        Per-language. TS Compiler API for JS/TS;
                        tree-sitter walks for the others.

propagate()             Generic worklist propagator. JS-only.
propagatePython()       Per-language entry points specialised for the
propagateJava()         language's calling conventions, receiver shapes,
propagateGo()           and stdlib aliases. Each lives under its own
propagateRuby()         subdirectory: taint-engine/python/, java/, go/,
propagatePhp()          ruby/, php/, rust/, csharp/.
propagateRust()
propagateCSharp()

filterFlow()            AI false-positive filter. Optional second pass
                        scoring each flow on (sanitization, endpoint
                        classification, exploitability) — gated by
                        cost-cap.
```

### 9.2 Languages

The 8 supported languages, in order of FrameworkSpec coverage maturity:

| Lang     | Propagator                  | Bundled specs                                              | Coverage |
|----------|-----------------------------|-----------------------------------------------------------|----------|
| JS / TS  | `propagator.ts`             | `node-stdlib`, `express`, `fastify`, `nestjs`, `nextjs`, `hono` | mature   |
| Python   | `python/propagate.ts`       | `flask`, `django`, `fastapi`                              | partial  |
| Java     | `java/propagate.ts`         | `java-stdlib`, `spring-boot`                              | partial  |
| Go       | `go/propagate.ts`           | `go-stdlib`, `gin`, `echo`                                | partial  |
| Ruby     | `ruby/propagate.ts`         | `rails`, `sinatra`                                        | partial  |
| PHP      | `php/propagate.ts`          | `laravel`, `symfony`                                      | partial  |
| Rust     | `rust/propagate.ts`         | `rust-stdlib`, `actix-web`, `axum`                        | partial  |
| C#       | `csharp/propagate.ts`       | `dotnet-stdlib`, `aspnet-core`                            | partial  |

"Partial" = framework specs cover web frameworks but miss long tails of
ORMs, template engines, deserialization libraries, etc. Closing those is
ongoing.

### 9.3 IR + worklist propagator

Every language reduces source files to a per-language IR
(`taint-engine/ir.ts`) of `FunctionNode`s + `CallEdge`s + `TaintSource` /
`TaintSink` markers. The propagator is then language-agnostic in shape:

1. Seed every parameter / return / reachable-from-IR node that matches a
   `FrameworkSource` pattern with a TaintTrace.
2. Worklist over the callgraph. For each function, propagate taint
   through assignments, parameter binding, and return values. Collapse
   sanitizer hits.
3. Every time a tainted value flows into a `FrameworkSink` argument
   matched by `argument_indices`, emit a `Flow`.
4. Halt when the worklist is empty or `maxIterations` (default 50× the
   function count) is reached. The latter is a safety circuit; reaching
   it is logged as `propagator_iteration_cap` in
   `taint_engine_runs.error_code`.

### 9.4 Receiver conventions

Pattern matching is text-based prefix / exact match against the call /
access expression's source text. This is intentionally simple in M2 — it
gets us most of the way without a full type-resolution engine. Known
caveats:

- `req.body.foo` matches `req.body.*` even if `req` is shadowed by an
  inner scope. The shadow case is rare in practice; tracking it would
  require type-aware matching (M3+).
- Wildcard receivers (`*.execute(*)`) work for *some* AST shapes — see
  `taint-engine/propagate-core.ts`'s wildcard handling. Cross-language
  sanitizer leak (where a propagator missed a `sanitizer` registered in
  a different file's spec) was fixed during Phase 6 hardening.
- PHP `new ClassName($arg)` constructor sources/sinks were missing in
  Phase 6 and have since been added; if you spot a similar gap, check
  `php/propagate.ts`'s `objectCreation` handler first.

### 9.5 Operational gates

The taint engine stage in `pipeline-steps/taint-engine.ts` is wrapped in
three operational gates BEFORE the engine runs:

1. **Rollout pct** (`shouldRunForOrg`) — a `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT`
   env var + per-org override. Skipped runs write a row with
   `error_code='rollout_gate'`.
2. **Circuit breaker** (`checkCircuitBreaker`) — org-scoped failure-rate
   killswitch. Skipped if more than 5% of last 60min failed (≥5-run minimum
   sample). Skipped runs write `error_code='circuit_breaker'`.
3. **Cost cap** (`assertWithinCostCap`) — monthly USD ceiling for the
   AI fp-filter. Triggered after the engine produces flows; flows beyond
   the cap have their AI verdict skipped. The fp-filter cost is returned
   to the pipeline and the EPD step subtracts it from the burn-breaker
   ceiling so fp-filter + Anthropic don't compound past the 25%-of-monthly-
   cap per-extraction ceiling.

Engine exceptions are HARD-FAIL by deliberate policy. Soft degradation only
happens via the gates above.

### 9.6 Validation scripts

A handful of tsx scripts under `depscanner/scripts/` are useful when
diagnosing engine output:

- `taint-engine-callgraph.ts` — dump the callgraph for a workspace.
- `taint-engine-propagate.ts` — run the propagator and print every flow.
- `taint-engine-validate.ts` — run the spec-loader against every YAML +
  every `framework_spec` row in PGLite.
- `taint-engine-recall.ts` — run the engine over the 88-CVE corpus and
  print recall.
- `taint-engine-shadow-monitor.ts` — diff engine output vs the legacy
  Semgrep taint pack (kept for transitional comparisons; the Semgrep pack
  was retired in Phase 6.5).
- `taint-engine-sanitizer-audit.ts` — list every sanitizer pattern that
  fired or didn't fire in a given run.

---

## 10. EPD scoring

Execution-Path-Dominance (EPD) scoring is the contextual layer on top of
depscore. It runs in stage 10 (`pipeline-steps/reachability.ts`) for
`confirmed` and `data_flow` PDVs; `function` and `module` are heuristic-only
(`epd.ts:aiEligible`). Module: `depscanner/src/epd.ts`.

### 10.1 Per-flow status

Every taint flow surfaces an `EpdStatus` (`epd.ts:27-43`). The aggregator
picks the worst status per PDV using the precedence ordering:

```
ai_truncated
> kept_on_error
> ai_verified_anthropic_fallback_failed
> ai_verified_anthropic_fallback_skipped_cost_cap
> ai_verified_anthropic_fallback_skipped_burn_breaker
> ai_verified_anthropic_fallback
> flow_aggregated
```

Adding a new status requires updating BOTH `frontend/src/lib/api.ts`'s
`EpdStatus` union AND `EntryPointBadge.tsx`'s `STATUS_HINT` Record — the
worker writes the string and the UI consumes it raw.

### 10.2 Cost cap path

EPD shares the fp-filter cost cap (`taint-engine/cost-cap.ts`). The
per-extraction burn-breaker ceiling is 25% of the monthly cap; the EPD
stage subtracts the fp-filter cost already burned in stage 9 before
deciding whether to attempt the Anthropic fallback. Three "skipped" status
codes distinguish the reason: hit the org's cost cap, hit the per-extraction
burn breaker, or the run-time provider refused.

### 10.3 Tier multiplier

`tierMultiplier` flows in via `loadAssetTier` (stage 6) and is propagated
to every depscore call. EPD's `entry_point_weight` is multiplied by the
tier weight at scoring time so a public unauthenticated entry point on a
crown-jewels project scores higher than the same path on a
non-production project.

---

## 11. Reachability classifier

After the taint engine, the classifier `updateReachabilityLevels`
(`depscanner/src/reachability.ts`) sets `project_dependency_vulnerabilities.
reachability_level` on every PDV based on the available evidence. Levels +
weights are defined in `depscore.ts:35-40`:

| Level         | Weight | Source of evidence                                              |
|---------------|--------|-----------------------------------------------------------------|
| `confirmed`   | 1.0    | A taint-engine flow with an `osv_id` matching this CVE.        |
| `data_flow`   | 0.9    | A taint-engine flow without a CVE-specific osv_id (framework-generic). |
| `function`    | 0.7    | tree-sitter usage slice imports the vulnerable function.       |
| `module`      | 0.5    | tree-sitter usage slice imports the package, no function-level evidence. |
| `unreachable` | 0.0    | Project imports nothing from the package (transitive-only).   |

The "tiered weight" feeds depscore: `depscore = base × tierWeight ×
reachabilityWeight × packageReputationWeight × threatMultiplier`. Legacy
`isReachable === false` (pre-Phase-2 callers) gets a softer 0.2 dampening
rather than 0.0 — we haven't *confirmed* unreachability, we just didn't
detect a reachable path.

Defense in depth: when `taint_engine` promotes a PDV to `confirmed`, the
classifier validates that the flow's `osv_id` matches a real loaded
FrameworkSpec (the `validOsvIds` set returned from stage 9). A flow with a
stale or hallucinated osv_id is dropped to `data_flow`. This catches AI
generation drift.

---

## 12. DAST / IaC / Malicious-pkg / Container

Pointer sections — each subsystem deserves its own doc; this is a
contributor reference for "where do I go to learn more?".

- **DAST** lives at `depscanner/src/dast/`. Primary entry point is
  `dast/pipeline.ts` (`runDastPipeline`). Dispatch via
  `scan_jobs.type='dast'` (or the v2.1c-reserved `dast_zap` /
  `dast_nuclei`). Backed by OWASP ZAP, with auth via the `target` table's
  encrypted credential payload. v2.1a engine + v2.1b destructive cleanup
  shipped; v2.1c (Nuclei split) and v2.1d (recorded login HAR) are future
  work. The OpenAPI spec under design is at `docs/dast-openapi-plan.md`.
- **IaC + Container** is integrated INTO the extraction pipeline as stage
  11 (`pipeline-steps/iac-container.ts`), backed by Trivy (image +
  config) and Checkov (TF/K8s/Dockerfile policy). The orchestrator
  (`scanners/orchestrator.ts`) handles credential decrypt + registry auth
  for private images. Custom-rules plan: `docs/iac-custom-rules-plan.md`.
- **Malicious-package scan** (stage 12, `pipeline-steps/malicious.ts`) is
  the v2 implementation: feeds-lookup against curated malicious-package
  intel, plus GuardDog (`guarddog/`) for source-code analysis on the
  resolved tarball cache. Builds its own per-project tree-sitter index for
  reachability classification on supported ecosystems. Self-contained — no
  taint-engine dependency.
- **Container scanning** is the same code path as IaC (`scanners/`),
  invoked when `detectInfraTypes` finds Dockerfiles. The cache layer
  (`scanners/storage.ts:upsertContainerScanCache`) keys on image digest
  so the same image scanned across N projects in the same org is cheaper.

---

## 13. Worker lifecycle

The worker is a long-poll process. Source: `depscanner/src/index.ts`.

```
runWorker()
  └─ loop:
      claim_scan_job(machine_id, supported_types)   RPC
        ├─ none for 60s   → process.exit(0)         (Fly scales the machine to zero)
        └─ row claimed    → processJob()
                              ├─ dispatch on job.type
                              ├─ heartbeat every 60s (interval timer)
                              └─ writes status='completed' or 'failed'
```

Key invariants:

- **Atomic claim.** `claim_scan_job` is a single RPC using `FOR UPDATE SKIP
  LOCKED` so two machines claiming concurrently never collide. Source of
  truth: the SQL function in `backend/database/schema.sql`.
- **60s heartbeat.** A `setInterval` in `processJob()` calls
  `sendHeartbeat()` every 60 seconds. Long-running subprocesses (Trivy,
  cdxgen, ZAP) are independent of stdout chunks, so the heartbeat never
  starves.
- **5min stuck detection.** A backend cron (`backend/src/routes/`)
  notices a job whose `heartbeat_at` is older than 5 minutes and marks it
  failed. The `recover_stuck_jobs` cron runs every minute.
- **Max 3 attempts.** `claim_scan_job` increments `attempts` on each
  claim; once it exceeds `max_attempts` (default 3), the row is marked
  `status='failed'` permanently and the next scan operator-triggers a
  fresh job rather than retrying the dead one.
- **Job-type dispatch.** The worker probes its environment at startup
  (`getSupportedJobTypes()` in `job-db.ts:29`) and only claims types it
  can serve. DAST claims are gated on `DAST_CREDENTIAL_KEY` being set;
  without it, the worker silently won't pull DAST rows from the queue
  (the silent-anonymous-fallback invariant — see plan §Task 7).
- **Cancellation.** `isJobCancelled(jobId)` is consulted between every
  pipeline stage. A user clicking "Cancel" on the project page flips
  `scan_jobs.status='cancelled'` and the next stage boundary aborts.
- **Cleanup.** The `finally` block in `runPipeline` always runs
  `cleanupRepository` to delete the cloned workspace UNLESS
  `KEEP_EXTRACT_WORKSPACE=1` is set or the worker was handed a
  `localWorkspacePath` by the CLI (in which case it's the user's tree).

---

## 14. Tooling stack

The Dockerfile (`depscanner/Dockerfile`) is the source of truth. Pinned
versions, all hardened against curl-pipe-sh supply-chain risk wherever
possible:

| Tool        | Version           | Purpose                              | Pin source                          |
|-------------|-------------------|--------------------------------------|-------------------------------------|
| Node.js     | 20-slim           | Worker runtime                        | `node:20-slim` base image           |
| Java        | Temurin JDK 21.0.6+7 | atom + Maven                       | Direct tarball, version-pinned URL  |
| Maven       | 3.9.9             | JVM build resolution                  | Direct tarball                      |
| Go          | 1.22.10           | gomod build resolution                | Direct tarball                      |
| Python      | 3 (debian-default) | dep-scan + Semgrep + Checkov + GuardDog | Debian package                  |
| dep-scan    | 6.* (major-pinned) | CVE matching                         | pip                                 |
| Semgrep     | 1.160.0 (exact)   | SAST + rule validation                | pip (exact-pinned — frequent breaking changes) |
| cdxgen      | ^11.0.0           | CycloneDX SBOM                        | npm dep                             |
| atom        | latest            | Java reachability slices              | npm global                          |
| Checkov     | 3.2.420           | IaC policy                            | venv at /opt/checkov-venv (conflicts with depscan packageurl-python pin) |
| Trivy       | 0.69.3            | Container CVE + Dockerfile config     | Direct tarball                      |
| Crane       | v0.20.2           | HEAD-only manifest digest probe       | Direct tarball + sha256sum -c       |
| TruffleHog  | 3.83.6            | Secret scanning                       | Direct tarball (replaces curl-pipe-sh installer) |
| GuardDog    | 2.9.0             | Malicious-package source analysis     | venv at /opt/guarddog-venv (Semgrep version conflict) |
| OWASP ZAP   | stable            | DAST                                  | `ghcr.io/zaproxy/zaproxy:stable` (stage-1 image) |
| ZAP rules   | pscanrulesAlpha-v47, pscanrulesBeta-v47 | Passive scan rules     | Direct tarball + sha256sum -c       |
| ipaddr.js   | ^2.3.0            | Host validation in scanner-host-guard | Direct npm dep                      |

Three patterns recur:

1. **Direct tarball + sha256sum -c**, never `curl | sh`. The supply-chain
   shape of "pipe a remote script into a shell" is unacceptable on a worker
   that holds decrypted AWS root keys + GCP service-account JSON + Azure SP
   secrets across customers. See the long Dockerfile comment at line 79-110
   on Crane for the rationale; the same logic applies to TruffleHog and the
   ZAP rules.
2. **Isolated venvs** for Python tools that have transitive-pin conflicts.
   Checkov pins `packageurl-python<0.14.0` while owasp-depscan pins
   `>=0.16.0`; they cannot share an environment. Same story for GuardDog's
   Semgrep version pin. The malicious-scan worker invokes
   `/opt/guarddog-venv/bin/guarddog` explicitly — never the global PATH.
3. **Major-version pin for dep-scan** (`6.*`), allowing patch uptake for
   security but blocking the 6→7 breaking-change class. Exact-pin for
   Semgrep because their releases regularly ship breaking parser changes.

Bumping a CRANE / TRUFFLEHOG SHA without updating the Dockerfile pins is
caught by `.github/workflows/crane-pin-check.yml`.

---

## 15. Storage abstraction

The pipeline was historically coupled to `@supabase/supabase-js` via
`SupabaseClient`. The Storage abstraction
(`depscanner/src/storage/index.ts`) narrows that coupling to a structural
subset of the Supabase query builder plus the Storage (object) bucket API.
Two implementations alongside the interface:

- **`SupabaseStorage`** (`storage/supabase.ts`) — wraps `createClient()`.
  Production worker mode. The Fly machine reads `SUPABASE_URL` +
  `SUPABASE_SERVICE_ROLE_KEY` from env.
- **`PGLiteStorage`** (`storage/pglite.ts`) — wraps `@electric-sql/pglite`
  with a local filesystem bucket. Used by the CLI (so contributors with no
  Supabase project can run the pipeline locally), by the snapshot suite,
  and by the PGLite integration tests under `depscanner/test/`.

The interface (`storage/index.ts:68-75`):

```ts
export interface Storage {
  from<T>(table: string): QueryBuilder<T>;
  rpc<T>(name: string, args?: Record<string, unknown>): Thenable<StorageResult<T>>;
  storage: StorageBuckets;
}
```

This is intentionally a structural subset — the pipeline's Storage handle
accepts a real `SupabaseClient` directly because the SupabaseClient already
satisfies the structural shape. No adapter layer.

PGLite-specific gotchas (documented in `storage/pglite.ts:14-23`):

1. Extensions must be passed to the PGlite constructor AND activated via
   `CREATE EXTENSION`. Both are required.
2. `pgcrypto` is not available in PGLite; `gen_random_uuid()` is in PG13+
   core.
3. Supabase `auth` schema + `auth.users` + `auth.uid/role/email()` stubs
   must exist before `schema.sql` is loaded (triggers reference them).
4. An `aegis_memory` stub must exist (a dropped table is still referenced
   by `match_aegis_memories()`).
5. RLS is intentionally omitted from `schema.sql` — local mode has no
   auth context; enabling RLS without policies would hide all rows.

The PGLite bootstrap helper is the same `STUB_SQL` constant in
`storage/pglite.ts`. If you add a migration that introduces a new auth-
referencing trigger or a new `match_*` function pointing at a dropped
table, update the stubs.

---

## 16. Test strategy

Four kinds of tests, each catching a different bug class. The matrix:

| Test kind             | Command                                        | What it catches                                          |
|-----------------------|-----------------------------------------------|----------------------------------------------------------|
| jest (TS-only)        | `cd backend && npm test`                       | Pure logic: depscore math, EPD math, classifier, helpers, framework detectors against a parsed tree. |
| Snapshot              | `cd depscanner && npm run test:fixtures`       | End-to-end CLI shape: arg parsing, exit codes, summary.json structure, finding rows. |
| Taint-engine invariants | `cd depscanner && npm run test:taint-engine-all` | Callgraph correctness, propagator termination, per-language fixtures, FP filter triples. |
| PGLite integration    | `cd depscanner && npm run smoke:pglite` and the `test:*-pglite` family | Storage abstraction conformance, Phase 19 atomic commit, rule-generation persistence. |

The split is load-bearing:

- **Jest covers logic in isolation.** Fastest feedback loop. Keep these
  hermetic — no shell-out, no real AI calls. Mock provider responses
  through the `getPlatformProvider`-shaped factories.
- **Snapshot tests cover the CLI shape.** These run the real Docker image,
  so they catch regressions in arg parsing, log routing, exit codes, and
  summary.json field stability that no jest test will. Slower to run; not
  intended for every feature change.
- **Taint engine has its own preflight** because the engine is
  self-contained and has its own invariants (callgraph reachability,
  propagator termination under cycles, sanitizer hits collapse traces,
  cost-cap enforcement) that don't show up in pipeline-level tests.
- **PGLite integration is the only realistic way to test atomic commits
  + RPC behaviour** without a live Supabase. The `finalize-extraction`
  test in `depscanner/test/finalize-extraction.test.ts` is the canonical
  example — it boots PGLite, loads schema.sql, seeds two extraction runs
  worth of rows, and asserts the post-RPC active/previous/run pointer
  state matches the spec.

Honest gap: **PGLite e2e misses Docker bugs.** The Dockerfile build copies
`schema.sql` via `docker:prepare`; if a contributor edits a migration but
forgets to re-dump the schema, PGLite tests pass and the Docker image
fails. The CI job at `.github/workflows/schema-check.yml` plugs that
specific hole, but other Docker-only issues (binary versions, env var
plumbing, FS permissions) require an actual `docker:build` round-trip.

---

## 17. Failure-mode taxonomy

Every soft + hard failure produces a structured row in
`extraction_step_errors`. The schema (see `backend/database/schema.sql:279`):

```
extraction_step_errors
  id, extraction_job_id, project_id,
  step (text — the stage name),
  code (text — see classifier below),
  message (text), stack (text),
  machine_id, duration_ms,
  severity (CHECK 'warn' | 'error'),
  created_at
```

The error classifier is `classifyError()` in
`depscanner/src/with-timeout.ts:317`. It produces a small closed taxonomy:

| Code              | Triggered by                                               | Severity hint        |
|-------------------|------------------------------------------------------------|----------------------|
| `timeout`         | `StepTimeoutError` (the stage's `timeoutMs` budget fired)  | error                |
| `oom`             | `ENOMEM` / "out of memory" / "heap" in the message         | error (worker died)  |
| `network_error`   | `ECONNRESET` / `ETIMEDOUT` / `ENOTFOUND` / `fetch failed`  | varies               |
| `subprocess_failed` | "exited with code" / "subprocess" in the message         | varies               |
| `unexpected`      | Anything else                                              | varies               |

Stages augment this with their own bespoke codes via the `onError` hook —
e.g. `clone` adds `auth_failed` / `repo_not_found`; `iac_container_scan`
adds `tenant_drift_detected` / `dast_credential_key_missing` /
`dast_credential_rotated` / `dast_credential_key_stale`; `taint_engine`
adds `rollout_gate` / `circuit_breaker` / `cost_cap_exceeded`.

### Fallback persistence

When `extraction_step_errors` itself can't be written (Supabase down), a
last-ditch `[LOGSTEPERROR_FALLBACK]` JSON line is written to stderr
(`with-timeout.ts:121`). Operators grep Fly logs for that marker to
recover swallowed errors.

### How errors reach the UI

The admin page `/admin/extraction-failures` aggregates
`extraction_step_errors` rows for the latest run per project. The pipeline
also writes a top-level `setError(projectId, message)` (see
`pipeline-helpers.ts`) on hard-fail; that surfaces as the project's
top-level "failed" status banner in the UI. Soft-fail stages do NOT call
`setError` — they just log a step-error row, and the project stays
`status='ready'` with degraded data.

User-facing error messages are **always** generic. Raw backend errors are
never surfaced; the message thrown into `setError` is the user-friendly
transform produced by the stage's `onError` hook (see
`pipeline-steps/sbom.ts`'s `userMsg` for an example). Real causes go to
`console.error` for operator debugging.

---

## 18. Where to go from here

- New pipeline stage → §4
- New framework detector → §5
- New framework spec → §6
- Adding a CVE rule for an underperforming CVE → §7 + the scoreboard at
  `docs/88-cve-scoreboard-plan.md`
- New language for the taint engine → not a casual contribution. Start by
  reading `taint-engine/javascript`'s propagator + IR build, then
  `taint-engine/python`'s as the simplest "second language" port. Open an
  issue first.
- New scanner subsystem (a la malicious-pkg v2) → mirror
  `depscanner/src/malicious/` as a peer module, add a `pipeline-steps/<name>.ts`
  stage that calls into it, and decide whether to add a new
  `scan_jobs.type` (only if the work is independent of extraction; in-line
  stages are simpler when the dep-scan output is needed).
- Operations / on-call → `docs/runbooks/`.
- Reachability sprint state → `docs/depscanner-hardening-report.md` and
  the `MEMORY.md` Track A entries.

If you find an inconsistency between this document and the code, the code
wins — please file a PR with the fix. The repo's `CLAUDE.md` summary +
some older `docs/` references still mention the retired
`depscanner/reachability-rules/` directory; that wiring is gone since
Phase 6.5/M5.
