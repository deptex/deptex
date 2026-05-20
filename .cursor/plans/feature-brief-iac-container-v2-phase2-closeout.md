# IaC + Container v2 — Phase 2 Close-out — Feature Brief

## Problem Statement

Phase 2 (the "Reachability Moat") shipped static OS-package CVE reachability and a base-image upgrade advisor, but a 13-persona critical review found the feature is not fully finished: the reachability verdict is computed and displayed but **does not influence triage priority**, two permission gates are wrong, and several robustness/observability/UI loose ends were deferred. This close-out makes Phase 2 actually do what it claims — and corrects the bugs — in one focused PR.

## Current State in Deptex

Phase 2 is merged (`origin/main`). Verified against the merged code:

- **Reachability is display-only.** `depscanner/src/scanners/storage.ts:165` sets a container finding's `depscore` to `severityToDepscore(f.severity)` — severity alone. The `reachability_level` column (`module` / `unreachable` / `null`) is set by `decorateContainerFindingsWithReachability` but read by nothing in `depscore.ts` or `storage.ts`. `scanner-findings.ts` sorts container findings by `depscore` and rolls reachability up only for a display chip (`reachabilityRollup`). Deptex's *code-dependency* depscore (`depscanner/src/depscore.ts` → `calculateDepscore`) already takes reachability — container findings are the inconsistent outlier.
- **Two permission-gate bugs in `backend/src/routes/base-image-recommendations.ts`:**
  - `POST .../base-image-suggestions` (a mutation — writes an activity-log row) is gated only by `checkProjectAccess`, the view-level gate. A read-only Member can call it.
  - `POST .../:recId/dismiss` is gated by `checkOrgManageIntegrations` (the *registry-secrets* permission). The sibling container-finding ignore/risk-accept routes in `scanner-findings.ts` use `checkProjectManagePermission` — dismiss diverges.
- **Robustness gaps:** `runBaseImageAdvisor` (`orchestrator.ts`) calls `generateRecommendation()` → `loadCatalog()` (which throws `CatalogValidationError` on a bad/missing YAML) with no try/catch — one bad file aborts the advisor for every Dockerfile. The per-image reachability budget is not clamped to the container-scan loop's remaining time.
- **Observability gaps:** the reachability classifier returns a `DecorateSummary` (total / classified / fallback / fallbackReason) but the orchestrator logs only loaded/unreachable counts — the fallback-reason distribution is dropped, so "how often is it failing closed?" is unanswerable from logs. `catalogHash()` (`base-image-catalog.ts:233`) has a docstring promising a logged catalog version but **zero callers** — dead code.
- **UI gap:** `ScannersPanel.tsx` fetches base-image recommendations with no loading state and no error state — a failed fetch is indistinguishable from "no recommendations."
- **Loose ends:** `cleanup_dismissed_base_image_recommendations` reaper RPC (phase28c) has **zero callers** — no cron drives it, so dismissed rows accumulate forever. The `--list-all-pkgs` Trivy flag (`trivy.ts`) produces `Results[].Packages[]` that **nothing reads** (the classifier uses the image's own dpkg/apk DB) — inert, with a comment that wrongly claims the classifier consumes it.

## Competitive Landscape

### Snyk
- Reachability analysis is one of **12+ factors** in its Risk Score; a reachable vulnerability scores materially higher. Reachability is an input to the score, never a standalone display field. Source: https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/risk-score , https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability-analysis
- Table-stakes: reachability changes priority order.

### Endor Labs
- Uses reachability in the opposite direction — proving findings *unreachable* to filter/downweight them, claiming up to ~97% alert-noise reduction. Source: https://appsecsanta.com/endor-labs-vs-snyk
- Confirms the same principle: an `unreachable` verdict must lower the finding's effective priority.

## Landscape Synthesis

- **Table-stakes:** reachability folded into the priority score (Snyk boosts reachable; Endor downweights unreachable). No serious vendor ships it as a non-load-bearing display field.
- **Frontier / whitespace:** N/A — this close-out is internal correctness, not a market-positioning feature. Phase 2 already staked the whitespace (static OS-package reachability existing at all).
- **Deptex position:** ahead on *having* static OS-package reachability; **behind its own bar** by not scoring it — and inconsistent with its own code-dependency depscore.
- **Feasibility verdict:** trivial, no novel technique. The `ContainerFinding` object already carries `reachability_level` at the moment `storage.ts` computes `depscore`, so the scoring fix is local. **Risks:** (1) `binutils`/readelf is not in the deployed worker image until the next deploy, and `exec "$@"` wrapper images fail closed to `module` — so `module` is the practical default today; a weight scheme that downweights `module` would wrongly demote most findings. (2) `unreachable` is a fail-closed-conservative verdict — downweighting it must not zero it out.

## User Stories

- As a **security engineer**, I want CVEs on shared libraries my container entrypoint actually loads to rank above CVEs on installed-but-unreachable packages, so I triage the exploitable ones first.
- As an **org owner**, I want only project managers to dismiss base-image recommendations and request catalog additions, so the security tab's state isn't changed by read-only members.
- As an **operator**, I want the reachability classifier's fallback-reason distribution in logs, so I can tell whether reachability is genuinely working or silently failing closed.

## Locked Scope Decisions

1. **Scope = full close-out (items A–F below).** Reason: every item is small and the explicit goal is to *finish* Phase 2; a core-only PR would leave it half-done. (User decision.)
2. **Reachability → depscore: downweight `unreachable` only.** `module` and `null` (unclassified) keep the full severity-based `depscore`; `unreachable` is multiplied down by a single factor (starting point **×0.4**, tunable in `/plan-feature`). Reason: (a) fail-closed — an unanalyzed/uncertain finding (`null`) and the fail-closed-default (`module`) are never demoted, so the close-out can never *hide* a real risk; (b) matches Endor's "downweight what's proven unreachable" model; (c) avoids the code-dep weight table's `module=0.5`, which would halve the fail-closed-default majority of findings. ×0.4 demotes a HIGH `unreachable` finding into roughly LOW–MEDIUM range without zeroing it. (User deferred the choice; locked by analysis.)
3. **`base-image-suggestions` + `dismiss` both gated by `checkProjectManagePermission`.** Reason: makes both mutations consistent with each other and with the sibling container-finding ignore/risk-accept routes in `scanner-findings.ts`. (See Open Questions for the suggest-endpoint relax option.)
4. **Remove the `--list-all-pkgs` Trivy flag** and its misleading comment. Reason: nothing reads `Results[].Packages[]`; the classifier uses the image's own dpkg/apk database. Trivy runs marginally lighter. (User decision.)
5. **No new tables, columns, routes, or migrations.** The depscore change is a recompute of an existing column; the reaper cron uses an existing RPC; the permission fixes edit existing handlers.

## Items A–F (the close-out)

- **A — Reachability → depscore.** In `storage.ts`, container findings' `depscore` becomes severity-score × reachability-multiplier (`unreachable` → ×0.4; `module`/`null` → ×1.0). The finding already carries `reachability_level` at upsert time. No backfill — scores refresh on the next extraction.
- **B — Permission gates.** `dismiss` → `checkProjectManagePermission`; `base-image-suggestions` → add `checkProjectManagePermission` after `checkProjectAccess`.
- **C — Robustness.** Wrap `generateRecommendation()` in `runBaseImageAdvisor` in try/catch (one bad catalog YAML must not abort the advisor for all Dockerfiles, and should surface a `base_image_advisor_failed` warning, not a generic `container_failed`). Clamp the per-image reachability budget to the container-scan loop's remaining time.
- **D — Observability.** Log the full `DecorateSummary` (including the fallback-reason) per image. Call `catalogHash()` once per scan in `runBaseImageAdvisor` and log it (the catalog version it ran against).
- **E — UI.** `ScannersPanel` recommendations fetch gets a loading state (skeleton matching the card shape) and an error state (message + retry), distinct from the genuine empty result.
- **F — Loose ends.** Wire `cleanup_dismissed_base_image_recommendations` into an existing maintenance cron. Remove the `--list-all-pkgs` flag (Decision 4).

## Data Model

No changes. `project_container_findings.depscore` is an existing column — only the value `storage.ts` writes changes. The `cleanup_dismissed_base_image_recommendations(retention_days)` RPC already exists (phase28c); the close-out only adds a caller.

## API Endpoints

No new endpoints. Two existing handlers in `base-image-recommendations.ts` change their permission check (Decision 3).

| Method | Route | Auth | Permission (after) | Change |
|---|---|---|---|---|
| POST | `.../base-image-recommendations/:recId/dismiss` | JWT | `checkProjectManagePermission` | was `checkOrgManageIntegrations` |
| POST | `.../base-image-suggestions` | JWT | `checkProjectManagePermission` | was view-level `checkProjectAccess` only |

## Frontend Surface

`frontend/src/components/security/ScannersPanel.tsx` only — add loading + error states to the existing base-image-recommendations fetch. No new pages or components. Follow the existing skeleton pattern in `frontend/src/components/security/` (e.g. `OrganizationVulnerabilitiesTableSkeleton`).

## User Flows

1. Extraction runs → container findings classified → `storage.ts` writes `depscore` with the reachability multiplier → security tab sorts `unreachable` findings below `module`/unclassified ones of equal severity.
2. A project manager dismisses a recommendation / requests a catalog addition → allowed; a read-only member → 403.
3. Maintenance cron fires → `cleanup_dismissed_base_image_recommendations` deletes dismissed rows past retention.

## Edge Cases & Failure-Mode Policy

- **All findings `module`** (readelf absent pre-deploy, or `exec "$@"` wrapper images): close-out has near-zero scoring effect — correct, nothing was *proven* unreachable.
- **`null` / unclassified** (language packages, classifier could not run): score unchanged — `null` means "unknown," not "unreachable."
- **`reachability_level` flips between scans:** `depscore` recomputed on every upsert — self-correcting.
- **Bad/missing catalog YAML:** advisor degrades to a `base_image_advisor_failed` warning (item C); the scan continues.
- **Recommendations fetch fails:** ScannersPanel shows an error + retry (item E), not a silent empty state.

## Non-Functional Requirements

No new performance surface. The depscore multiplier is arithmetic in an existing write path. Logging additions are one line per image. No AI. No data-volume change.

## RBAC Requirements

`checkProjectManagePermission` (org `manage_teams_and_projects` OR team-role `manage_projects`) gates both `dismiss` and `base-image-suggestions`.

## Dependencies

None. Phase 2 is merged; all touched files exist in `main`.

## Success Criteria

1. After a re-scan, an `unreachable` container finding sorts **below** a `module`/unclassified finding of the same severity in the security tab (depscore-ordered).
2. `dismiss` and `base-image-suggestions` return 403 for a view-only member; 200 for a project manager — covered by route tests.
3. Per-image logs include the reachability fallback-reason; the catalog hash is logged once per scan.
4. A maintenance cron deletes dismissed recommendations past retention.
5. `ScannersPanel` shows distinct loading / error / empty states.
6. The container-reachability e2e (`npm run e2e:container-reachability`) still passes 3/3.
7. Full backend + frontend test suites green; no regressions.

## Open Questions

- **`base-image-suggestions` permission level** (can defer to `/implement`): locked to `checkProjectManagePermission` for consistency, but "request a hardened-image suggestion" is a low-stakes feedback action — if any member should be able to request one, relax it back to `checkProjectAccess`. Henry's call at implement time.
- **`unreachable` multiplier value** (can defer to `/plan-feature`): ×0.4 is the locked starting point; `/plan-feature` should check `severityToDepscore`'s actual mapping and confirm ×0.4 lands a HIGH `unreachable` finding in the intended LOW–MEDIUM band.
- **Reaper cron cadence/location** (can defer to `/plan-feature`): wire into whichever existing maintenance cron is the right home; `/plan-feature` to identify it.

## Recommended Next Step

`/plan-feature iac-container-v2-phase2-closeout` — scope is locked and verified; the only implement-time judgment calls are captured as deferrable open questions.
