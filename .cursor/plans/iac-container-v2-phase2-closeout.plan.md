# IaC + Container v2 — Phase 2 Close-out — Implementation Plan

## Overview

A single PR that finishes Phase 2: it makes the static OS-package reachability verdict actually re-prioritise triage (today it is a display-only chip), fixes two permission-gate bugs, and clears the robustness / observability / UI loose ends a 13-persona critical review flagged. No new tables, columns, routes-with-new-shape, or migrations — it is a recompute plus correctness fixes. Brief: `.cursor/plans/feature-brief-iac-container-v2-phase2-closeout.md`.

## Competitive Research & Design Rationale

Folding reachability into the priority score is table-stakes: [Snyk](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/risk-score) treats it as one of 12+ Risk Score factors (reachable → higher); [Endor Labs](https://appsecsanta.com/endor-labs-vs-snyk) downweights proven-unreachable findings (~97% noise reduction). Nobody ships reachability as a non-load-bearing display field. Deptex's own code-dependency depscore (`depscanner/src/depscore.ts → calculateDepscore`) already takes reachability — container findings are the inconsistent outlier. We adopt Endor's direction (**downweight `unreachable`**, leave everything else alone) because it is fail-closed: an unanalyzed (`null`) or fail-closed-default (`module`) finding is never demoted, so the change cannot hide a real risk.

### Relationship to `depscore.ts` (why ×0.4, not ×0.0)

`depscanner/src/depscore.ts` defines `REACHABILITY_WEIGHT_UNREACHABLE = 0.0` ("drops out of the depscore ranking entirely") and `module = 0.5` for **code-dependency** findings. Container findings are deliberately *not* run through `calculateDepscore` — they use a separate severity→90/70/50/30/10 scale, and there is no per-finding CVSS/EPSS/tier context to feed the code-dep model. So this close-out cannot literally reuse `calculateDepscore`; it applies a multiplier to the container severity scale instead.

The container `unreachable` weight is **×0.4, not ×0.0**, on purpose: static OS-package reachability is a *weaker* signal than code-dependency call-graph reachability. The `binutils`-absent fallback and the `exec "$@"`-wrapper fallback both fail closed to `module`, and an `unreachable` verdict is itself a static inference — so we downweight it hard but never zero it. This divergence from the code-dep `0.0` is intentional and must be documented in a code comment on the constant. ×0.4 is **locked** (was an open question; the named constant exists for future tuning, not a deferred decision).

## Codebase Analysis

All facts below verified against `origin/main` (`9bbca08`).

- **Container depscore is severity-only.** `depscanner/src/scanners/storage.ts:64` `severityToDepscore()` maps CRITICAL/HIGH/MEDIUM/LOW/INFO → 90/70/50/30/10/null. `upsertContainerFindings` (`storage.ts:165`) writes `depscore: severityToDepscore(f.severity)`. `ContainerRow` already has `reachability_level` (`storage.ts:52`).
- **Reachability is set before upsert.** `orchestrator.ts:944` calls `decorateContainerFindingsWithReachability(result.findings, …)` which mutates the finding objects in place; those same objects are pushed to `dockerfileFindings`/`configuredFindings` and later upserted at `orchestrator.ts:1218/1225`. So `f.reachability_level` is populated when `storage.ts` computes `depscore`. ✓
- **`scanner-findings.ts` sorts container findings by the `depscore` column** (`.order('depscore', …)` at lines 112/248; `.gte('depscore', …)` at 105-107). `reachabilityRollup` (lines 383-389) only counts reachability for a display chip — it does not feed scoring.
- **Permission gates** (`backend/src/routes/base-image-recommendations.ts`): `dismiss` uses `checkOrgManageIntegrations(userId, id)` (the registry-secrets permission); `base-image-suggestions` POST is gated only by `checkProjectAccess` (view-level). The sibling container/IaC-finding `ignore` + `risk-accept` routes in `scanner-findings.ts:120-170` use the pattern `checkProjectAccess` → `checkProjectManagePermission(userId, id, projectId)` → 403 `'No permission to manage findings'`.
- **`checkProjectManagePermission(userId, organizationId, projectId)`** (`backend/src/lib/project-access.ts:200`) returns `Promise<boolean>`, and internally runs `projectBelongsToOrg` first.
- **`runBaseImageAdvisor`** (`orchestrator.ts:999-1043`): `generateRecommendation()` is a **synchronous** row-builder called once per Dockerfile in a loop, with **no try/catch**; only `upsertBaseImageRecommendations` is wrapped. `generateRecommendation → loadCatalog()` throws `CatalogValidationError` on a bad/missing catalog YAML — and because the catalog is a single per-run resource, that throw is a **deterministic whole-run failure**, identical for every Dockerfile. So the fix is *not* a per-iteration wrapper (that would emit N identical warnings) — it is a single catalog pre-flight (see Task 2).
- **Reachability budget** (`orchestrator.ts:944`): `decorateContainerFindingsWithReachability` is called with no `budgetMs`, so it uses the 30 s default `REACHABILITY_PER_IMAGE_TIMEOUT_MS`. The orchestrator's own comment notes this cost is "naturally charged against `CONTAINER_SCAN_TOTAL_BUDGET_MS`" via the pre-`scanOneImage` budget check — so this is **not** an unbounded hazard. The precise residual gap: the *last* image admitted just under the 25-min total can still run a full 30 s reachability pass, overshooting the total budget by **≤30 s**. A minor tightening, not a correctness bug.
- **`depscore.ts` reachability weights**: `REACHABILITY_WEIGHT_UNREACHABLE = 0.0`, `module = 0.5` — for code-dependency findings only. Container findings do not use `calculateDepscore` (see "Relationship to `depscore.ts`" above).
- **Reachability log** (`orchestrator.ts:951-955`): logs only `module`/`unreachable` counts + optional `fallbackReason`; the `DecorateSummary` also carries `total`, `classified`, `fallback`.
- **`catalogHash()`** (`base-image-catalog.ts:233`): defined, **zero callers**.
- **Reaper RPC** `cleanup_dismissed_base_image_recommendations(retention_days INTEGER DEFAULT 90)` (phase28c) — **zero callers**. Template for wiring it: `backend/src/routes/scanner-cache-reaper.ts` — a `POST /api/workers/scanner-cache-reap` route (QStash-signature OR `X-Internal-Api-Key` auth) that calls `cleanup_container_image_scan_cache`, registered in `index.ts:134` under `/api/workers`, driven by a manually-created QStash schedule.
- **`--list-all-pkgs`** (`trivy.ts:531`, with a 5-line comment above): nothing reads `Results[].Packages[]`. `trivy-image-args.test.ts` pins the flag with 3 assertions.

## Data Model

**No migration.** `project_container_findings.depscore` is an existing column — only the value `storage.ts` writes changes. The `cleanup_dismissed_base_image_recommendations` RPC already exists. No `schema:dump` needed (no migration touched).

**Required one-time backfill.** Existing rows would otherwise keep their old severity-only `depscore` until re-scanned, and `scanner-findings.ts` sorts the security tab purely by `depscore` — so without a backfill the ranking is inconsistent across runs (a fresh project's `unreachable` HIGH at 28 sorts below a stale project's `unreachable` HIGH at 70) and Success Criterion 1 is false until every project re-scans. Because `reachability_level` is already populated on every existing row, the backfill is a single idempotent statement, run via Supabase MCP as a step of Task 1:
```sql
UPDATE public.project_container_findings
   SET depscore = ROUND(depscore * 0.4)
 WHERE reachability_level = 'unreachable' AND depscore IS NOT NULL;
```
The `0.4` here MUST equal the code constant `CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER` (Task 1). Apply it after the worker code is merged, so the column is consistent for both pre- and post-PR rows.

## API Design

### Endpoints

No new routes. Two existing handlers in `base-image-recommendations.ts` change their permission check; the existing `scanner-cache-reap` worker route gains one extra RPC call (see Task 5).

| Method | Route | Auth | Permission | Change |
|---|---|---|---|---|
| POST | `…/base-image-recommendations/:recId/dismiss` | JWT | `checkProjectManagePermission` | was `checkOrgManageIntegrations` |
| POST | `…/base-image-suggestions` | JWT | `checkProjectManagePermission` | was view-level only |
| POST | `/api/workers/scanner-cache-reap` | QStash sig OR `X-Internal-Api-Key` | internal | **extended** — also reaps dismissed recommendations |

### Types

No new request/response types. `scanner-cache-reap`'s response shape widens to `{ ok, cache_rows_deleted, recommendation_rows_deleted, retention_days }`.

## Frontend Design

### `ScannersPanel.tsx` — recommendations loading / error states

The recommendations `useEffect` (`ScannersPanel.tsx:60-75`) currently has no loading state and swallows failures with `.catch(() => setRecommendations([]))`. Add, mirroring the summary fetch's existing `loading`/`error` pattern (lines 33-58):

- `recsLoading: boolean` (init `true`) and `recsError: string | null` state.
- The `useEffect` sets `recsLoading` false in a `finally`, and `recsError` in `catch` (keep `recommendations` empty on error).
- Render in the recommendations section: **loading** → a skeleton block matching the `BaseImageRecommendationCard` shape (`rounded-lg border border-border bg-background-card` with `animate-pulse` lines — follow `frontend/src/components/security/` skeleton precedent); **error** → `text-sm text-destructive` message + an outline "Retry" button that re-runs the fetch; **empty** (loaded, no error, zero recs) → unchanged (section simply absent, as today).

No new components, routes, or pages. Component tree unchanged apart from the two new state branches.

## Implementation Tasks

1. **(A) Container reachability → depscore** — S — `depscanner/src/scanners/storage.ts`
   - Add `const CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER = 0.4;` with a code comment noting the deliberate divergence from `depscore.ts`'s `REACHABILITY_WEIGHT_UNREACHABLE = 0.0` (static OS-package reachability is a weaker signal than code-dep call-graph reachability — see plan §"Relationship to `depscore.ts`"). Add a `containerDepscore(f: ContainerFinding): number | null` helper: `base = severityToDepscore(f.severity)`; if `base === null` return `null`; if `f.reachability_level === 'unreachable'` return `Math.round(base * CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER)`; else return `base`.
   - In `upsertContainerFindings`, change `depscore: severityToDepscore(f.severity)` → `depscore: containerDepscore(f)`. Leave `upsertIaCFindings` untouched (IaC has no reachability).
   - **Run the one-time backfill** (see Data Model) via Supabase MCP after the worker code is merged — the `0.4` literal in the SQL must match the constant.
   - Acceptance: `module`/`null` findings keep the severity score; `unreachable` HIGH → 28, CRITICAL → 36, MEDIUM → 20.

2. **(C+D) Orchestrator hardening + observability** — S — `depscanner/src/scanners/orchestrator.ts`
   - **Budget clamp** (minor tightening — see Codebase Analysis): import `REACHABILITY_PER_IMAGE_TIMEOUT_MS` from `./container-reachability`. Extract the clamp into a small pure helper `reachabilityBudgetMs(elapsedMs: number): number` = `Math.min(REACHABILITY_PER_IMAGE_TIMEOUT_MS, Math.max(1, CONTAINER_SCAN_TOTAL_BUDGET_MS - elapsedMs))`, and pass its result as `budgetMs` at the `decorateContainerFindingsWithReachability` call. The pure helper is so the boundary (floor at 1, never ≤0) is unit-testable.
   - Expand the `container_scan.reachability` log line to include `total`, `classified`, and `fallback` count from the `DecorateSummary` (this only *extends* the existing already-try/caught log call — no new error handling).
   - **Catalog pre-flight** (correct granularity — the catalog throw is whole-run, not per-Dockerfile): in `runBaseImageAdvisor`, call `loadCatalog()` once in a try/catch *before* the Dockerfile loop — on `CatalogValidationError` push one `base_image_advisor_catalog_unavailable:<msg>` warning and return early (skip the advisor). Inside the loop, keep a per-Dockerfile try/catch only for per-file failures (`parseDockerfileFinalStage` / file read), pushing `base_image_advisor_failed:<relPath>:<msg>` and `continue`. Verify `loadCatalog`'s memoization in `base-image-catalog.ts` at implement time to confirm the pre-flight + later calls share one parse.
   - Call `catalogHash()` once in `runBaseImageAdvisor` and log it via `ctx.logger.info('base_image_advisor', …)` as a structured `{ catalog_hash, dockerfile_count }` payload. Import `catalogHash` from `./base-image-catalog`.
   - Acceptance: a bad catalog yields exactly one `…catalog_unavailable` warning and the advisor is skipped (no uncaught error, no N-warning spam); a single bad Dockerfile yields one `…failed` warning and the others still produce recommendations; the per-image log shows the fallback distribution; logs carry the catalog hash.

3. **(F2) Remove the inert `--list-all-pkgs` flag** — S — `depscanner/src/scanners/trivy.ts`, `depscanner/src/scanners/__tests__/trivy-image-args.test.ts`
   - Delete the `'--list-all-pkgs',` arg (`trivy.ts:531`) and its 5-line comment.
   - Update `trivy-image-args.test.ts`: remove the 3 `--list-all-pkgs` assertions; keep/adjust a test asserting the image args are `['image','--format','json','--scanners=vuln','--platform','linux/amd64', <imageRef>]`.
   - Acceptance: Trivy image scan args no longer contain `--list-all-pkgs`; the test suite reflects it.

4. **(B) Permission-gate fixes** — S — `backend/src/routes/base-image-recommendations.ts`, `backend/src/routes/__tests__/base-image-recommendations.test.ts`
   - `dismiss`: replace step (4) `checkOrgManageIntegrations(userId, id)` with `checkProjectManagePermission(userId, id, projectId)`. Update the import (drop `checkOrgManageIntegrations` from `../lib/rbac`; add `checkProjectManagePermission` to the existing `../lib/project-access` import).
   - `base-image-suggestions`: after the existing `checkProjectAccess` block, add `if (!(await checkProjectManagePermission(userId, id, projectId))) return res.status(403).json({ error: 'No permission to manage base-image recommendations' });`.
   - Update `base-image-recommendations.test.ts`: add 403 cases for both endpoints with a view-only role; adjust any existing dismiss test that assumed `manage_integrations`.
   - Acceptance: both mutations 403 for a view-only member, 200 for a project manager.

5. **(F1) Reap dismissed recommendations via the existing cron** — S — `backend/src/routes/scanner-cache-reaper.ts`, `backend/src/routes/__tests__/scanner-cache-reaper.test.ts`
   - Do **not** add a new route. The existing `POST /api/workers/scanner-cache-reap` handler already has QStash-signature/internal-key auth and an already-created daily QStash schedule. Add a second RPC call inside it: `supabase.rpc('cleanup_dismissed_base_image_recommendations', { retention_days })`. (phase28c's RPC is `RETURNS INTEGER` — verified — so the row count is real.) `cleanup_dismissed_base_image_recommendations` defaults to 90-day retention vs the cache reaper's 30; pass the same `retention_days` the handler already parses, OR use a separate body field if the two retentions should differ — default to one shared `retention_days` for simplicity.
   - Widen the response to `{ ok, cache_rows_deleted, recommendation_rows_deleted, retention_days }`; update the handler's docstring (it currently describes only the cache reap).
   - This satisfies brief item F's "wire into an existing maintenance cron" literally — **no new file, no new route, no new QStash schedule for Henry to create.** The reaper runs the moment this merges.
   - Acceptance: the existing reaper test still passes; one new assertion that `cleanup_dismissed_base_image_recommendations` is invoked and `recommendation_rows_deleted` is in the response.

6. **(E) ScannersPanel loading / error states** — S — `frontend/src/components/security/ScannersPanel.tsx`
   - Add `recsLoading` / `recsError` state; wire the recommendations `useEffect` to set them; render loading-skeleton / error-with-retry / (unchanged) empty branches in the recommendations section.
   - Acceptance: a slow/failed `getBaseImageRecommendations` shows a skeleton then an error+retry, distinct from the empty state.

7. **Validation** — S — see Testing & Validation.

## Testing & Validation Strategy

- **Backend routes (jest):**
  - `base-image-recommendations.test.ts` — new 403 cases for **both** `dismiss` and `base-image-suggestions` with a view-only role, and a **cross-tenant** case for each (an org-A manager passing an org-B project / a project not under the path `:id` → 403, exercising `checkProjectManagePermission`'s `projectBelongsToOrg`). 200 cases for a project manager. Adjust any existing dismiss test that assumed `manage_integrations`.
  - `scanner-cache-reaper.test.ts` — the existing 401/200/400 + RPC-error→500 cases stay; add one assertion that `cleanup_dismissed_base_image_recommendations` is invoked and `recommendation_rows_deleted` appears in the response. Mock both RPCs via `setRpcResponse`.
- **Depscanner (jest):**
  - `storage.ts` — `unreachable` HIGH upserts `depscore` 28; `module` HIGH stays 70; `null`-reachability HIGH stays 70; `null`-severity stays `null`.
  - `orchestrator.ts` — (a) `runBaseImageAdvisor` with `loadCatalog` mocked to throw `CatalogValidationError` → exactly one `base_image_advisor_catalog_unavailable` warning, advisor skipped, **no exception escapes**; (b) a per-Dockerfile failure on file #1 of 2 → one `base_image_advisor_failed:<path>` warning and file #2 still produces a recommendation; (c) `reachabilityBudgetMs` pure helper — floors at 1 when `elapsedMs` ≥ the total budget, equals `REACHABILITY_PER_IMAGE_TIMEOUT_MS` with ample remaining; (d) a logger spy asserting the `container_scan.reachability` line carries `total`/`classified`/`fallback` and `runBaseImageAdvisor` emits one `base_image_advisor` log with a non-empty `catalog_hash`.
  - Update `trivy-image-args.test.ts` for the removed flag.
- **Frontend (vitest):** `ScannersPanel.test.tsx` — mock `getBaseImageRecommendations` (from `../../lib/api`) and assert **all three** states: (1) pending → recommendations skeleton present; (2) rejected → error message + a "Retry" button whose click re-issues the fetch; (3) resolved `[]` → no skeleton, no error, recommendations section absent (Success Criterion 6's "distinct from empty" needs all three). If no `ScannersPanel.test.tsx` exists, this is a new file.
- **e2e:** `npm run e2e:container-reachability` must still pass 3/3 (no change to the classifier itself).
- **Full suites:** backend `jest`, frontend `vitest`, `tsc --noEmit` on all three packages — 0 regressions.
- **Performance:** none affected — the depscore change is arithmetic in an existing write path; logging adds one line per image.
- **Regression watch:** `scanner-findings.ts` sorts container findings by `depscore` *and* filters them with `.gte('depscore', depscoreMin)` — confirm the new non-multiple-of-10 values sort correctly, and note that a saved `depscore_min` filter (e.g. ≥30) will now **exclude** downweighted `unreachable` findings (28). That exclusion is the intended triage behavior, not a regression — but it is a behavior change worth stating. `severityToDepscore` is still used unchanged by `upsertIaCFindings`.

## Risks & Open Questions

- **`unreachable` multiplier — LOCKED at ×0.4.** HIGH→28 (just below LOW 30), CRITICAL→36 (above LOW), MEDIUM→20. The named constant exists for future tuning; this is not a deferred decision. Rationale in §"Relationship to `depscore.ts`".
- **KEV / high-EPSS downweighting** — an `unreachable` finding is downweighted regardless of `is_kev` / `epss_score`. This is intentional: static reachability is precisely the signal that contextualizes a KEV — "the vulnerable library is not loaded in this image" genuinely lowers urgency for *this* finding. The verdict is conservative (fail-closed to `module` on any uncertainty), so a downweighted finding is one we positively determined is not loaded. No KEV exemption. *Informational — flagged so it is a conscious choice, not an oversight.*
- **`base-image-suggestions` permission** — locked to `checkProjectManagePermission` for consistency with `dismiss`. If any member should be able to *request* a hardened-image suggestion (it is a low-stakes feedback log), relax to view-level. *Deferrable to `/implement`.*
- **`scanner-cache-reap` retention** — the close-out reuses the handler's single `retention_days`; the cache reaper defaults to 30 days and `cleanup_dismissed_base_image_recommendations` to 90. If a 30-day reap of dismissed recommendations is undesirable, add a separate body field. *Deferrable to `/implement` — default is one shared value.*

## Dependencies

None. Phase 2 is merged; every touched file exists in `main`. No prerequisite migrations.

## Success Criteria

1. In the security tab, an `unreachable` container finding sorts **below** a `module`/unclassified finding of equal severity — true immediately for all existing rows (the Task 1 backfill), not only after a re-scan.
2. `dismiss` and `base-image-suggestions` return 403 for a view-only member and for a cross-tenant project/org pair, 200 for a project manager.
3. A bad/missing base-image catalog YAML degrades the advisor to exactly one `base_image_advisor_catalog_unavailable` warning (no uncaught error, no per-Dockerfile warning spam); the scan completes.
4. Per-image reachability logs include the fallback-reason distribution; the catalog hash is logged once per scan.
5. The existing `scanner-cache-reap` cron deletes dismissed recommendations past retention with no new QStash schedule; 401 without auth.
6. `ScannersPanel` shows distinct loading / error / empty states for recommendations.
7. Trivy image args no longer contain `--list-all-pkgs`; `e2e:container-reachability` still 3/3; full backend + frontend + e2e suites green.

## Recommended Next Step

`/review-plan` has run (verdict REVISE) and all 5 P1 amendments are applied: backfill promoted to a required Task 1 step; the reaper folded into the existing `scanner-cache-reap` cron (no new route/file/schedule); catalog pre-flighted once instead of per-Dockerfile; the ×0.4 multiplier justified vs `depscore.ts` and locked; orchestrator-layer tests named. Proceed to `/create-worktree iac-container-v2-phase2-closeout` → `/implement`.
