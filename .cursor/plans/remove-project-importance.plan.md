# Remove Project Importance (UI) — Implementation Plan

## Overview
Park the project-importance feature ([[feature-parking-garage]]) by removing its **frontend
UI entry points** and leaving the `projects.importance` column at its `1.0` default. With
importance `= 1.0` everywhere, `tierWeight = clampImportance(1.0) = 1.0` is a neutral
multiplier, so the depscore math is an exact no-op and **the backend, pipeline, and scoring
formula stay completely untouched.** Verified by a full cross-stack reference sweep.

## Hypothesis check (Henry: "just settings + create flow, leave the rest at 1.0")
**Confirmed** — with one addition:
- Backend/pipeline/DB need **zero** changes. Column default `1.0` + `clampImportance`
  fallback fully neutralize it. The depscore is computed at scan time with `importance`; at
  `1.0` it's transparent.
- **Addition:** importance isn't shown in only two places — there's a **third UI surface**:
  the org-overview **project graph tiles** (`VulnProjectNode.tsx`) render an importance
  dot + label subtext. If we remove the settings + create UIs but leave the tile showing an
  importance value the user can no longer edit, that's inconsistent. So the tile display
  comes out too.

## Scope

### REMOVE (frontend only)
1. **`frontend/src/components/ImportanceSlider.tsx`** — delete the file. Only two importers
   (both edited below); nothing else references it.
2. **`frontend/src/app/pages/ProjectSettingsContent.tsx`** (the General-tab card):
   - import of `ImportanceSlider, IMP_DEFAULT` (line 24)
   - `onImportanceSaved?` prop on the props interface (line 249) + its destructure (line 578)
   - state `importance` / `setImportance` (line 598) and `isSavingImportance` (line 600)
   - the `setImportance(project.importance)` line **inside** the project-sync `useEffect`
     (≈ line 769) — keep the effect, drop only the importance line
   - `handleSaveImportance` (lines ≈ 1687–1703)
   - the entire **Importance card** JSX block (lines ≈ 2001–2025)
3. **`frontend/src/app/pages/OrganizationOverviewPage.tsx`**:
   - `handleProjectImportanceSaved` callback (lines ≈ 1593–1595)
   - the `onImportanceSaved={handleProjectImportanceSaved}` prop pass (line ≈ 3912)
4. **`frontend/src/app/pages/NewProjectPage.tsx`** (create-project flow):
   - import of `ImportanceSlider, IMP_DEFAULT` (line 6)
   - state `importance` + `importanceExpanded` (lines 61–62)
   - the importance slider card JSX (the expandable "Importance" section) + its expand toggle
   - `importance` field in `createPayload` (line ≈ 446)
5. **`frontend/src/components/vulnerabilities-graph/VulnProjectNode.tsx`** (graph tiles):
   - `showImportanceSubtext` / `importanceLabel` / `importanceColors` computations (≈ 176–185)
   - the two JSX blocks rendering the importance dot + label (≈ 360–367 and ≈ 439–445)
6. **`frontend/src/lib/api.ts`** (client signatures — no caller passes importance after the
   above):
   - `importance?: number` from `createProject` data param (line 761)
   - `importance?: number` from `updateProject` data param (line 809)

### KEEP (the no-op plumbing — do NOT touch)
- `projects.importance` column: `numeric(3,2) NOT NULL DEFAULT 1.0` + `chk_importance_range`
  CHECK [0.5, 2.0] (schema.sql / `phase41_drop_asset_tiers.sql`).
- Backend `POST` + `PUT /projects` importance accept/validate/insert/update (defensive;
  rejects bad values from any future caller; harmless with no UI sending it).
- Backend `GET` routes + `get_vulnerability_detail_bundle` RPC returning `importance`
  (API contract).
- Full depscanner pipeline: `pipeline-steps/importance.ts` (`loadImportance`), and every
  `calculateDepscore` / `calculateSecretDepscore` / `calculateSemgrepDepscore` call in
  `dep-scan.ts` / `reachability.ts` / `semgrep.ts` / `trufflehog.ts`. **Load-bearing** — at
  `1.0` it's a no-op, but the calls must stay.
- `calculateDepscore` + `clampImportance` in both `depscanner/src/depscore.ts` and
  `frontend/src/lib/scoring/depscore.ts`.
- `Project.importance` type field (api.ts) + `VulnProjectNodeData.importance` prop (becomes
  an unused-but-harmless data field) + `SupplyChainSections.rowDepscore` fallback (passes
  `projectImportance`, transparent at 1.0).
- All backend tests asserting depscore with `importance: 1.0` / `1.5`.

## Open decisions (need Henry's call before / during implementation)
1. **Reset existing non-`1.0` rows?** Default is `1.0`, but any project already set to e.g.
   `1.5` would keep silently multiplying its depscores on every future scan with no UI to see
   or change it. A one-line migration `UPDATE projects SET importance = 1.0 WHERE importance <> 1.0`
   makes the feature *truly* inert (matches the "do nothing" intent). **Recommend: yes** (it's
   the honest version of "park it"), but it's the only DB touch and it's optional — in practice
   most/all rows are already `1.0`. *(If yes: add migration + `npm run schema:dump` per repo rule.)*
2. **`api.ts` client params** — recommend removing `importance?` from `createProject` /
   `updateProject` (no callers remain; keeps the client honest). Backend still accepts it.
3. **Test mocks** — the 5 `ProjectSettingsContent.*.test.tsx` + `SupplyChainSections.test.tsx`
   mock `importance: 1.0`; harmless, leave them. **But** check `ProjectSettingsContent.general.test.tsx`
   for any importance-card-specific test and delete it if present.
4. **`VulnProjectNodeData.importance` prop** — leave (harmless) vs fully thread out of the
   graph-layout population. Recommend leave; not worth the layout churn.

## Implementation order
1. Delete `ImportanceSlider.tsx`.
2. `ProjectSettingsContent.tsx` edits (import → props → state → effect line → handler → card).
3. `OrganizationOverviewPage.tsx` edits (callback + prop pass).
4. `NewProjectPage.tsx` edits (import → state → JSX → payload).
5. `VulnProjectNode.tsx` edits (computations + two JSX blocks).
6. `api.ts` signature trims.
7. (If decided) reset migration + `schema:dump`.
8. Test cleanup (only if an importance-specific test exists).

## Verification
- `npx tsc --noEmit` (frontend) — catches every dangling reference (this is the real safety net).
- `npx vitest run` on the 5 `ProjectSettingsContent.*` files + `SupplyChainSections.test.tsx`,
  then the full frontend suite.
- **No backend test run needed** — backend is untouched. (If the optional migration is added,
  the schema-check CI rule requires the `schema.sql` refresh.)
- Browser: General tab has no Importance card; create-project flow has no importance control;
  graph tiles show no importance subtext; depscores unchanged (still 1.0-multiplied).

## Risk
Lowest-risk kind of change — pure deletion of leaf UI, guarded by tsc. The only non-trivial
judgment is decision #1 (reset migration). Revival stays cheap: column + formula + pipeline
all intact, so re-enabling is "re-add a UI + build recompute-on-change" (see parking-garage entry).
