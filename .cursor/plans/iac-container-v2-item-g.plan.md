# Item G — Composed IaC↔Code Reachability — Implementation Plan (Rev 4)

**Slug:** `iac-container-v2-item-g`
**Source brief:** `.cursor/plans/feature-brief-iac-container-v2-item-g.md`
**Prior reviews:** Rev 1 + Rev 2 REWORK (schema-grounding errors); Rev 3 substantively REVISE (epd.ts mechanism wrong; pipeline ordering bug). All 8 patches from the Rev 3 review applied here.
**Rev 4 written:** 2026-05-21
**Branch target:** new worktree `iac-container-v2-item-g` off `origin/main`
**Estimated scope:** **4-6 days**

## What Rev 4 changes from Rev 3

The Rev 3 review caught two real issues plus several scope/quality items. Rev 4 patches all 8:

| # | Patch | Effect |
|---|---|---|
| 1 | **Drop the epd.ts edit entirely.** composeFindings writes both `composition_factor` AND `contextual_depscore = contextual_depscore × composition_factor` in ONE SQL UPDATE. | Sidesteps the 4-compute-site issue, the pure-helper-no-PDV-row issue, and the pipeline-ordering bug. No epd.ts changes. |
| 2 | **Drop the Math.max scoring blend.** `composition_factor` is purely a multiplier on PDV's existing `contextual_depscore`. PCF severity used only for the pairing decision. | Fixes non-commensurate scales between hardcoded severityToDepscore and tier-weighted base_depscore_no_reachability. |
| 3 | **Weaken M4 acceptance** to a pair-count assertion instead of the ≥35% floor on a curated N=1 case. | Removes the M0-transitively-blocks-merge concern + the unfalsifiable-metric concern. |
| 4 | **Drop M3 (Aegis ORDER BY audit)** from this plan. | Aegis flip is unrelated to IaC+Container epic; goes to a separate chore branch. |
| 5 | **Drop `composed_partner` JSONB from RPC.** Additive `composition_factor numeric` only on the RPC return shape. | No v1 consumer (frontend deferred); avoids destructive RPC recreation. |
| 6 | **Export `severityToDepscore`** | Moot after Patch 2 (composition no longer uses it). Drop. |
| 7 | **Lock multi-partner aggregation as `MIN(composition_factor)`** per PDV. | Names the semantics; "most-suppressing edge wins." |
| 8 | **`os_family` enum, not `os_bindings_supported` boolean**, in the composeFindings log line. | Already detected from `/etc/os-release` ID; informs v2 ecosystem priority directly. |

Net: no epd.ts changes, no Math.max blend, no Aegis coupling, smaller RPC change. Plan is 3 milestones (M1, M2, M4) — M0 collapses into M1 step 1 (pragmatist-f1), M3 dropped.

## Verified codebase facts (Rev 4 grounding — re-grep-verified)

Each claim has a file:line + verbatim snippet. Rev 3 missed epd.ts internals; Rev 4 captures them correctly even though epd.ts is no longer modified.

### A) Where `contextual_depscore` is written

Four sites in `depscanner/src/epd.ts`, all inside helper functions with primitive args:
- Line 628 (inside `computeAggregate`)
- Line 667 (inside `zeroAggregate`)
- Line 1318 (Anthropic fallback path)
- Line 1390 (heuristic fallback path)

All four write via `supabase.from('project_dependency_vulnerabilities').update({ contextual_depscore })` at the end of `runEpdScoring`.

**For Item G:** composition.ts also writes `contextual_depscore` via the same supabase `.update()` pattern, BUT only on rows partnered in `project_composition_partners`. Since composition runs AFTER `doReachabilityAndEpd` finishes (composition lives in `pipeline-steps/composition.ts` inserted between `doIaCContainer` and `doMaliciousScan`), every paired PDV row already has its EPD-computed `contextual_depscore` persisted. Composition reads that value, multiplies by `composition_factor`, writes back. **No race because EPD has already finalized.**

### B) PDV schema (verified)

`backend/database/schema.sql:1119+`. Relevant columns:
- `aliases text[]` (line 1126) — nullable; carries CVE aliases from OSV/GHSA backfill
- `reachability_level text` — populated by Phase 6 in `doReachabilityAndEpd`
- `base_depscore_no_reachability numeric(6,2)`
- `contextual_depscore numeric(10,4)` — written by epd.ts
- `epd_factor numeric` — written by epd.ts

No `cve_id`, no `package_purl` on PDV. Package identity via FK `project_dependency_id → project_dependencies(ecosystem, name, version)`.

No `vulnerability_records` table exists. Aliases live directly on PDV.

### C) Pipeline structure

`depscanner/src/pipeline.ts` is 201 lines. Step order at lines 140-172:
```
doClone → doResolve → doSbom → doDepsSync → doUsageExtraction → loadAssetTier
  → doDepScan → doRuleGeneration → doTaintEngine → doReachabilityAndEpd
  → doIaCContainer → doMaliciousScan → doSemgrep → doTruffleHog → doFinalize
```

`pipeline-steps/` directory exists. Each step is `await do<Stage>(ctx)`. No `runStage` wrapper.

**For Item G:** new file `depscanner/src/pipeline-steps/composition.ts` exports `doComposition(ctx)`. Insert at pipeline.ts:170 (between `doIaCContainer` at 167 and `doMaliciousScan` at 171).

At that point in the pipeline:
- PDV.reachability_level: ✓ written by Phase 6 in doReachabilityAndEpd
- PDV.contextual_depscore: ✓ written by epd.ts in doReachabilityAndEpd
- PCF rows + reachability_level: ✓ written by doIaCContainer
- project_native_bindings rows: ✓ written by extractLanguageBindings/extractOsBindings (also in doIaCContainer extension — see M1)

### D) Dockerfile — binutils present

`depscanner/Dockerfile:23-31`:
```dockerfile
RUN apt-get update && apt-get install -y \
  git curl unzip binutils python3 ...
```

readelf works on the worker today. M0 sanity check folds into M1 step 1 (5-minute pre-flight, no longer a standalone milestone).

### E) PDV vulnerabilities RPC

Latest: `backend/database/phase24_2_vuln_rpc_epd_fields.sql`. `LANGUAGE sql STABLE`, 25-column RETURNS TABLE. Pattern is `DROP FUNCTION IF EXISTS … (uuid); CREATE FUNCTION …` because `CREATE OR REPLACE` can't change RETURNS TABLE shape.

**For Item G (Rev 4):** Add `composition_factor numeric` to RETURNS TABLE — additive append. No `composed_partner` JSONB (Patch 5 deferred to frontend follow-up). Still need `DROP + CREATE` because RETURNS TABLE shape changes.

### F) elf-analyzer

`depscanner/src/scanners/elf-analyzer.ts:95-98` — `extractDtNeeded` returns DT_NEEDED (deps), not DT_SONAME. No SONAME extractor exists today.

**For Item G:** add `extractDtSoname(binaryPath, runner)` next to `extractDtNeeded`, ~30 lines. Parses `(SONAME)  Library soname: [name]`. Tri-state result mirroring `extractDtNeeded`. Pin LC_ALL=C for spawn to avoid locale parsing surprises.

### G) Phase 25 trigger pattern

`backend/database/phase25_iac_container_scanning.sql:140-158` — `enforce_finding_org_id()` derives `organization_id` from `projects` table; trigger is `BEFORE INSERT OR UPDATE OF project_id, organization_id`. Reused for new tables.

### H) Container findings route (unchanged)

`backend/src/routes/scanner-findings.ts:207-249` — straight `.from('project_container_findings').select('*')`. No changes in Rev 4.

### I) Storage layer (unchanged on main)

`storage.ts:31` `CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER = 0.4`. `storage.ts:107-112` `containerDepscore`. Composition uses these for the PCF side multiplier value only — not for score blending.

### J) Migration number

Latest: `phase29_scan_jobs_recovery_hardening.sql`. **Item G uses phase30.**

### K) Multi-partner aggregation (Patch 7 — locked semantics)

Per PDV with N partner PCFs, `composition_factor = MIN(per-edge factor)`. Rationale: most-suppressing edge wins. Alternative considered: MAX or AVG. MIN is the most conservative noise-reduction choice — if any partnered PCF says "this is unreachable in container," the PDV's composed reachability claim leans toward the suppression.

### L) Existing direct-table PDV SELECTs (verified per skeptic-r3-f8)

`backend/src/routes/projects.ts:10204` and `backend/src/routes/teams.ts:2336` use `.from('project_dependency_vulnerabilities').select('id, ..., contextual_depscore, ...')` lists directly — these bypass the RPC. They'll automatically pick up the new `composition_factor` value through the existing `contextual_depscore` column (multiplied by Item G). To surface `composition_factor` as a separate field for the eventual frontend follow-up, those routes will need their SELECT lists extended at that point — not in this PR.

## Data Model

### New table: `project_native_bindings`

```sql
-- backend/database/phase30_iac_code_composition.sql

CREATE TABLE IF NOT EXISTS public.project_native_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,

  scope TEXT NOT NULL CHECK (scope IN ('language', 'os')),
  package_identifier TEXT NOT NULL,
  package_ecosystem TEXT,
  soname TEXT NOT NULL,
  install_path TEXT NOT NULL DEFAULT '',  -- sentinel '' avoids UNIQUE-with-NULL bug
  link_method TEXT NOT NULL CHECK (link_method IN (
    'elf_needed',     -- v1 language side
    'dpkg_soname',    -- v1 OS side
    'elf_dlopen',     -- v2 reserved
    'ctypes_grep',    -- v2 reserved
    'apk_provided',   -- v2 reserved
    'rpm_provided'    -- v2 reserved
  )),

  extractor_version TEXT NOT NULL DEFAULT 'v1',
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (extraction_run_id, scope, package_identifier, soname, install_path)
);

CREATE INDEX idx_pnb_run_language_pkg ON public.project_native_bindings(extraction_run_id, package_identifier) WHERE scope = 'language';
CREATE INDEX idx_pnb_run_os_pkg ON public.project_native_bindings(extraction_run_id, package_identifier) WHERE scope = 'os';
CREATE INDEX idx_pnb_run_soname ON public.project_native_bindings(extraction_run_id, soname text_pattern_ops);

CREATE TRIGGER project_native_bindings_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON public.project_native_bindings
  FOR EACH ROW EXECUTE FUNCTION public.enforce_finding_org_id();
```

### New table: `project_composition_partners`

```sql
CREATE TABLE IF NOT EXISTS public.project_composition_partners (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,

  container_finding_id UUID NOT NULL REFERENCES public.project_container_findings(id) ON DELETE CASCADE,
  pdv_id UUID NOT NULL REFERENCES public.project_dependency_vulnerabilities(id) ON DELETE CASCADE,

  container_reachability_multiplier NUMERIC(4,3) NOT NULL,
  code_reachability_multiplier NUMERIC(4,3) NOT NULL,
  composition_factor NUMERIC(4,3) NOT NULL,
  -- composed_depscore omitted in v1 (no UI consumer); compute at read time when needed

  bindings_evidence JSONB NOT NULL,
    -- Locked typed shape (max 20 entries):
    -- [{ soname: string, link_method: 'elf_needed' | 'dpkg_soname',
    --    language_install_path?: string, os_install_path?: string,
    --    extractor_version: string }]
    -- Composition.ts emits this contract; frontend follow-up consumes it.

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (extraction_run_id, container_finding_id, pdv_id)
);

CREATE INDEX idx_pcp_run_pcf ON public.project_composition_partners(extraction_run_id, container_finding_id);
CREATE INDEX idx_pcp_run_pdv ON public.project_composition_partners(extraction_run_id, pdv_id);
CREATE INDEX idx_pcp_pdv_factor ON public.project_composition_partners(pdv_id, composition_factor);  -- for MIN(factor) lookup

CREATE TRIGGER project_composition_partners_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON public.project_composition_partners
  FOR EACH ROW EXECUTE FUNCTION public.enforce_finding_org_id();

-- Same-project enforcement (CHECK both finding_ids belong to NEW.project_id)
CREATE OR REPLACE FUNCTION public.enforce_composition_same_project() RETURNS TRIGGER AS $$
DECLARE pcf_project UUID; pdv_project UUID;
BEGIN
  SELECT project_id INTO pcf_project FROM public.project_container_findings WHERE id = NEW.container_finding_id;
  SELECT project_id INTO pdv_project FROM public.project_dependency_vulnerabilities WHERE id = NEW.pdv_id;
  IF pcf_project IS NULL OR pdv_project IS NULL THEN RAISE EXCEPTION 'composition partner finding not found'; END IF;
  IF pcf_project != pdv_project OR pcf_project != NEW.project_id THEN
    RAISE EXCEPTION 'composition partner findings must belong to same project';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;  -- NOT SECURITY DEFINER (per architect-r3-f4)

CREATE TRIGGER project_composition_partners_enforce_same_project
  BEFORE INSERT OR UPDATE OF container_finding_id, pdv_id, project_id ON public.project_composition_partners
  FOR EACH ROW EXECUTE FUNCTION public.enforce_composition_same_project();
```

### ALTER PDV: add `composition_factor`

```sql
ALTER TABLE public.project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS composition_factor NUMERIC(4,3);
```

NULL = no partner. Existing rows untouched → `contextual_depscore` preserved bit-identically (compose only ever multiplies, never overwrites without multiplying).

### New RPC: `apply_composition_results` (P0 patch — supabase-js client can't express multi-row `UPDATE … FROM (VALUES …)`)

```sql
CREATE OR REPLACE FUNCTION public.apply_composition_results(
  p_project_id uuid,
  p_run_id text,
  p_updates jsonb  -- [{pdv_id: uuid, factor: numeric}, ...] — JS pre-aggregates MIN per PDV
)
RETURNS integer  -- count of rows updated
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  updated_count integer;
BEGIN
  WITH updates AS (
    SELECT (e->>'pdv_id')::uuid AS pdv_id,
           (e->>'factor')::numeric AS factor
      FROM jsonb_array_elements(p_updates) e
  ),
  result AS (
    UPDATE project_dependency_vulnerabilities pdv
       SET composition_factor = u.factor,
           contextual_depscore = ROUND(pdv.contextual_depscore * u.factor, 4)
      FROM updates u
     WHERE pdv.id = u.pdv_id
       AND pdv.project_id = p_project_id
       AND pdv.extraction_run_id = p_run_id
    RETURNING 1
  )
  SELECT count(*) INTO updated_count FROM result;
  RETURN updated_count;
END;
$$;
```

composeFindings calls this RPC ONCE per scan after computing per-PDV MIN factors in JS. Atomic single-statement UPDATE server-side; one round-trip from client.

### Recreate `get_project_vulnerabilities_from_pdv` RPC (additive, Rev 4 minimal)

Drop + create with `composition_factor numeric` appended to the existing 25-column RETURNS TABLE. No `composed_partner` JSON (Patch 5).

```sql
DROP FUNCTION IF EXISTS public.get_project_vulnerabilities_from_pdv(uuid);

CREATE FUNCTION public.get_project_vulnerabilities_from_pdv(p_project_id uuid)
RETURNS TABLE(
  -- [25 columns from phase24_2:14-35 verbatim — id, dependency_id, osv_id, severity, summary,
  --  details, aliases, fixed_versions, published_at, modified_at, created_at, dependency_name,
  --  dependency_version, is_reachable, reachability_level, reachability_details, epss_score,
  --  cvss_score, cisa_kev, depscore, contextual_depscore, entry_point_classification,
  --  epd_status, sla_status, sla_deadline_at]
  composition_factor numeric
)
LANGUAGE sql STABLE AS $$
  SELECT
    -- [25 projections from phase24_2:45-69 verbatim]
    pdv.composition_factor
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd ON pd.id = pdv.project_dependency_id AND pd.project_id = pdv.project_id
  WHERE pdv.project_id = p_project_id;
$$;

NOTIFY pgrst, 'reload schema';
```

(M1 task copies the 25 verbatim columns + projections from phase24_2 lines 14-35 + 45-69 — don't paraphrase.)

### Schema dump

`cd depscanner && npm run schema:dump` in the same commit per CLAUDE.md.

## API Design

**No new endpoints. No modified route handlers.** The PDV RPC's appended `composition_factor` field flows through the existing dispatch at `projects.ts:6835-6837` automatically. The two direct-table SELECTs at `projects.ts:10204` and `teams.ts:10204`-class routes don't see the new field, but they DO see the new `contextual_depscore` value (post-composition multiplication) — which is what the Security tab orders by today. **The frontend follow-up extends those SELECT lists when it ships.**

## Frontend Design

**Deferred to a follow-up after `worktree-org-security-tab` merges.**

Rev 4 user-visible impact post-merge: composed-unreachable findings drop in priority on the Security tab (the existing ORDER BY `contextual_depscore` automatically reflects composition via the multiplied value). No side-by-side breakdown UI in v1.

## Implementation Tasks

### Milestone 1 — Migration + native-bindings worker (2-3 days)

1. **(XS)** Pre-flight: SQL probe via Supabase MCP `execute_sql` against `extraction_logs` for recent `container_reachability` events, OR `SELECT reachability_details FROM project_container_findings WHERE reachability_details->>'dt_needed' IS NOT NULL LIMIT 5`. Confirm Phase 2 readelf is firing in prod. If status is widely `unavailable`, block Item G until Phase 2 is fixed. (Replaces standalone M0.)

2. **(M)** Write `backend/database/phase30_iac_code_composition.sql` per Data Model. Apply via `mcp__claude_ai_Supabase__apply_migration`. Contents:
   - CREATE TABLE `project_native_bindings` + triggers + indexes
   - CREATE TABLE `project_composition_partners` + triggers + indexes
   - ALTER PDV ADD COLUMN `composition_factor`
   - Recreate `get_project_vulnerabilities_from_pdv` RPC (DROP + CREATE; LANGUAGE sql STABLE; 25 verbatim columns + composition_factor)
   - `NOTIFY pgrst, 'reload schema';`
3. **(S)** Run `cd depscanner && npm run schema:dump`. Commit in same change.
4. **(S)** Add `extractDtSoname` to `depscanner/src/scanners/elf-analyzer.ts`. ~30 lines. Tri-state result type. Pin `LC_ALL=C` on the spawn to match locale invariance.
5. **(M)** Create `depscanner/src/scanners/native-bindings.ts`:
   - `extractLanguageBindings(opts: { rootDir, sbomPackages, runner? })` — for each Python/Node SBOM entry with native artifacts: locate install dir via `*.dist-info/RECORD` + `top_level.txt` (Python) OR `node_modules/<pkg>/` (Node); walk `.so`/`.node` files; call `extractDtNeeded`. Emit `{ purl, soname, install_path, link_method: 'elf_needed' }`.
   - `extractOsBindings(opts: { rootDir, runner? })` — detect `/etc/os-release` ID for `os_family` reporting. Read `/var/lib/dpkg/info/<pkg>.list` files; for each `.so*` regular file (skip symlinks), call `extractDtSoname`; emit `{ os_package_name, soname, install_path, link_method: 'dpkg_soname' }`. If `/var/lib/dpkg/` absent, return `[]` and log with detected `os_family`.
   - Skip upsert when extractor returns `status !== 'ok'`.
6. **(S)** Add `upsertNativeBindings(supabase, ...)` storage helper.
7. **(S)** Plumb into orchestrator: `runIaCAndContainerScans` in `depscanner/src/scanners/orchestrator.ts` calls `extractLanguageBindings` + `extractOsBindings` + `upsertNativeBindings` after `upsertContainerFindings`.
8. **(M)** Unit tests `__tests__/native-bindings.test.ts`:
   - Mock readelf returning fixture DT_NEEDED + DT_SONAME for libssl.so.3 / cryptography's `_rust.abi3.so`
   - Python install discovery hits `python:3.11-slim`, `uv`-managed, `pip --target` paths (dist-info-based walker)
   - Node `.node` walker hits multiple node_modules paths
   - OS extractor parses `/var/lib/dpkg/info/libssl3.list` fixture, recovers `libssl.so.3` via DT_SONAME
   - Returns [] + emits `os_family` log when `/var/lib/dpkg/` absent
   - Fixture coverage per test-r3-f2: `libssl3`, `libssl1.1`, `libxml2`, `libjpeg`, `libcrypto3`, `libz`, plus a stripped/whitespace-padded `readelf -d` sample
   - Skips upsert when extractor returns `status: 'unavailable'`

**Acceptance:** pre-flight passes; unit tests green; integration probe against `python:3.11-slim` writes ≥1 language binding (cryptography→libssl.so.3) AND ≥1 OS binding (libssl3→libssl.so.3).

### Milestone 2 — Composition logic + inline contextual_depscore update (1-2 days)

1. **(S)** Create `depscanner/src/pipeline-steps/composition.ts` exporting `doComposition(ctx)`. Inserted in `pipeline.ts` AFTER line 167 (`scannerSummary = await doIaCContainer(ctx)`) and BEFORE the next `checkCancelled` guard that precedes `doMaliciousScan` — inside the `if (!skipOptionalScans)` block at lines 162-179. **doComposition early-returns if `scannerSummary === null` OR no PCF rows exist for `runId`** (avoids needless DB round-trip on `DEPTEX_SKIP_OPTIONAL_SCANS=1` corpus harness runs). Mirrors existing soft-fail pattern; errors don't abort the scan.

2. **(M)** Create `depscanner/src/scanners/composition.ts` exporting `composeFindings(opts: { supabase, projectId, organizationId, runId, logger })`:
   - **Step A — load partnerable findings.**
     - PCF: SELECT for `runId` where `reachability_level IS NOT NULL`.
     - PDV: SELECT for `runId` where `reachability_level IS NOT NULL AND osv_id IS NOT NULL`, JOINed to `project_dependencies` for `(ecosystem, name)`.
   - **Step B — derive CVE set per PDV** (inline, no JOIN to anything else):
     - Effective CVE set = `[pdv.osv_id, ...pdv.aliases.filter(a => /^CVE-/.test(a))]`
   - **Step C — match PCF×PDV** by shared SONAME via bindings:
     - For each candidate `(PCF, PDV)` where PCF.cve_id ∈ PDV's CVE set (or PCF.osv_id === PDV.osv_id), query `project_native_bindings` for the runId. Language bindings matching PDV's `(ecosystem, name)`; OS bindings matching `os_package_name = PCF.os_package_name`. Intersect by `soname` exact-string. If non-empty: edge confirmed; collect bindings_evidence (capped 20).
     - If PCF has both `cve_id` AND `osv_id` NULL, skip the edge and emit `pcfs_skipped_no_identifier` counter.
   - **Step D — compute composition_factor per edge** (Patch 2: pure multiplier, no score blending):
     - `container_mult = pcf.reachability_level === 'unreachable' ? 0.4 : 1.0`
     - `code_mult = REACHABILITY_LEVEL_WEIGHTS[pdv.reachability_level]` from `depscore.ts:36-50` (confirmed=1.0/data_flow=0.9/function=0.7/module=0.5/unreachable=0.0)
     - If `code_mult` is undefined (unknown reachability_level value), **skip the edge** + emit `edges_skipped_unknown_reachability` counter (don't default to 1.0).
     - `composition_factor = Number((container_mult * code_mult).toFixed(3))`
   - **Step E — batched write via RPC.**
     - INSERT all `project_composition_partners` rows in one statement (multi-row VALUES; supabase-js supports `.insert(rowsArray)`)
     - For each PDV with ≥1 partner, compute `min_factor = Math.min(...partner factors)` in JS (Patch 7 — JS pre-aggregates MIN)
     - Build `updates = [{ pdv_id, factor: min_factor }, ...]` and call `supabase.rpc('apply_composition_results', { p_project_id, p_run_id: runId, p_updates: updates })` — one round-trip, atomic server-side multi-row UPDATE
     - **Sole-writer invariant (within depscanner pipeline):** after `doReachabilityAndEpd`, only composition.ts mutates `contextual_depscore`. composition.ts header comment documents this. Out-of-band: DAST v2.1c's `confirm_pdvs_from_dast_run` RPC at `phase25a:117-136` updates `reachability_level` to 'confirmed' WITHOUT recomputing `contextual_depscore` — pre-existing tech debt, tracked separately. The invariant test in step 8 enforces the within-depscanner scope.
   - **Step F — observability** (Patch 8 + opp-scout adds):
     - Emit one structured log line per scan:
       ```
       composeFindings.summary {
         runId, partnerable_pcf, partnerable_pdv,
         edges_written, suppressions_to_zero,
         os_family: 'dpkg' | 'apk' | 'rpm' | 'none',
         bindings_by_ecosystem: { pypi: N, npm: N },
         pdvs_skipped_by_reason: { no_reachability_level, no_osv_id, no_alias_match, unknown_reachability_level },
         composition_coverage_pct: edges_distinct_pdv / partnerable_pdv,
         duration_ms
       }
       ```
     - Mirror to `extraction_logs` so it surfaces in the scan log UI.

3. **(M)** Unit tests `__tests__/composition.test.ts`:
   - Both reachable → factor=1.0, contextual_depscore unchanged
   - Container unreachable + code data_flow → factor=0.36, contextual_depscore × 0.36
   - Container reachable + code unreachable → factor=0, contextual_depscore=0
   - Both unreachable → factor=0
   - **MIN aggregation** (Patch 7): PDV with 2 partners at factors 0.4 and 1.0 → PDV.composition_factor = 0.4, contextual_depscore × 0.4
   - **MIN aggregation tie-break**: 2 partners both at 0.5 → factor=0.5 deterministically
   - Unknown reachability_level → edge skipped
   - No bridge in bindings → no edge written, no PDV mutation
   - PCF with both identifiers NULL → counter incremented, no edge
   - **Empty bindings (Alpine simulation)**: language bindings non-empty, OS bindings = [] → 0 edges, observability log `os_family: 'apk'` (or 'none' if no os-release detected), no exception

4. **(M)** PGLite integration test `composition.pglite.test.ts`:
   - Apply phase30 to PGLite
   - Seed 3 PCF + 2 PDV + 4 native_bindings configured for: (PDV-A partners PCF-1 + PCF-2 with different factors; PDV-B partners PCF-3 only)
   - Run `composeFindings()`
   - Assert: 3 rows in `project_composition_partners`; PDV-A.composition_factor = MIN of the two partner factors; PDV-A.contextual_depscore = (pre-composition value) × MIN
   - Snapshot a 4th, UNPAIRED PDV-C's pre-composition contextual_depscore; assert bit-identical after composeFindings (no UPDATE touched it)
   - Call the recreated RPC with project_id; assert response includes `composition_factor` field

5. **(S)** **Numeric fold-math test** (test-r3-f1): unit test with exact values:
   - PDV pre-composition: `contextual_depscore = 70.0000`, `composition_factor = NULL`
   - Compose with single edge factor = 0.7
   - Assert post: `contextual_depscore = 49.0000` (= ROUND(70 × 0.7, 4)), `composition_factor = 0.700`

6. **(S)** **Backfill invariant test** (test-r3-f6):
   - PGLite test seeds 50 PDV rows with realistic `contextual_depscore` distributions and `composition_factor = NULL`
   - Apply phase30
   - Read all 50 `contextual_depscore` values
   - Assert all bit-identical to pre-migration (since composition_factor stays NULL, no PDV is UPDATEd)

7. **(S)** **Cross-tenant probe** (architect-r3-f4): seed bindings + composition_partners for org A and org B. Trigger-time enforcement: try cross-project INSERT → expect exception. RPC-level: call RPC with project_A's id → assert no rows from project B leak.

8. **(S)** **Sole-writer enforcement test** (P1 patch from Rev 4 review): create `depscanner/src/__tests__/contextual-depscore-writers.test.ts` (~15 lines) using grep:
   ```typescript
   test('contextual_depscore is only written by epd.ts and composition.ts', async () => {
     const matches = grepRepo(/\.update\(\{[^}]*contextual_depscore/g, 'depscanner/src/**/*.ts');
     const files = new Set(matches.map(m => m.file));
     expect(files).toEqual(new Set([
       'depscanner/src/epd.ts',
       'depscanner/src/scanners/composition.ts',
     ]));
     const epdCount = matches.filter(m => m.file.endsWith('epd.ts')).length;
     expect(epdCount).toBe(4);  // sites at lines 628, 667, 1318, 1390
   });
   ```
   Turns the documented sole-writer invariant into an enforced regression guard. Catches the exact class of bug Patch 1 sidesteps.

**Acceptance:** all tests green; composeFindings runs against M1's integration fixture and writes ≥1 composition partner; pre/post EPD numeric invariant test passes.

### Milestone 4 — Corpus + e2e + hardening (1-2 days)

(Renumbered from Rev 3's M4; M3 dropped per Patch 4.)

1. **(M)** Extend corpus with ONE curated co-occurrence case: pick a JS or Python repo from the existing 4-repo set whose Dockerfile (or pinned base image) ships a `libssl3`/`libxml2`/`libjpeg`-class CVE-affected version overlapping with a language-side CVE in the existing 49-CVE corpus.

2. **(M)** `depscanner/scripts/e2e-iac-code-composition.ts`:
   - **Pre-flight** (test-r3-f5, fenced BEFORE pipeline): seed corpus, then query `(PCF×PDV co-occurrence)` count from staged data. Fail with `CORPUS_MISCURATED` if 0.
   - **Run full pipeline** including `doComposition`.
   - **Acceptance assertion** (Patch 3, replacing the ≥35% floor): `≥1 PCF×PDV edge written AND ≥1 PDV's contextual_depscore drops below the HIGH threshold (70) from above 70`. Tracks 35% as an aspirational secondary metric in the log output.
   - Record actuals to committed `corpus-composition-baseline.json` for run-over-run drift visibility.

3. **(S)** Add `e2e:iac-code-composition` script to `depscanner/package.json`.

4. **(M)** `/criticalreview` — focused 5-persona pass (composition-correctness, data-model, multi-tenancy, regression-hunter, opportunity-scout).

5. **(M)** Apply review patches.

6. **(S)** `/push-changes` to open PR.

**Acceptance:** Pre-flight passes; pair-count assertion met; /criticalreview verdict ≥ REVISE with no remaining P0/P1; PR open.

## Testing & Validation Strategy (compact)

- **Unit**: native-bindings.test.ts (Python/Node/dpkg discovery + tri-state + fixtures for 6 sonames); composition.test.ts (10+ branches incl. MIN aggregation, unknown level skip, empty bindings, PCF identifier NULL)
- **PGLite mandatory**: composition.pglite.test.ts exercises real schema + the recreated RPC's return shape + multi-partner MIN; verifies unpaired PDVs untouched
- **Numeric fold-math test**: exact 70.0000 → 49.0000 assertion
- **Backfill invariant**: 50 unpaired PDVs bit-identical post-migration
- **Cross-tenant**: trigger + RPC scoping
- **Regression**: existing `e2e:container-reachability`, Phase 6 corpus, EPD tests all still pass (EPD code unchanged — no edits to epd.ts)
- **Performance**: composition.ts perf bound — perf assertion in PGLite test on 50-pair fixture completes < 2s; full-scan budget < 10s extra

## Risks & Open Questions

### Risks

1. **Alpine/musl/distroless images** produce no OS bindings. v1 logs `os_family: 'apk'` (or 'none') and writes no edges. Documented limit. Composition fires on apt/dpkg-based Python+Node images only.
2. **Version-suffix soname mismatch** (libxml2.so vs libxml2.so.2) — v1 uses exact-string match. v2 normalize-and-prefix-match.
3. **GHSA→CVE alias backfill latency** — fresh advisories may have empty `pdv.aliases`. Step C falls back to direct `pcf.osv_id == pdv.osv_id`.
4. **Multi-partner PDV (Patch 7 LOCKED as MIN)** — PDV.composition_factor stores `MIN(per-edge factor)`. Join table keeps all edges for forensics. **Known false-suppression class:** when the CVE is bound to one soname but the PDV partners with multiple sonames including an unreachable one unrelated to the CVE (e.g., CVE in libssl path but container's libcrypto3 is unreachable → MIN picks libcrypto factor=0.4, incorrectly suppressing the libssl-relevant signal). The `bindings_evidence` JSONB capture makes this auditable in the join table. v2 needs CVE→soname mapping (reusable from `reachability-rules/` packs) to gate edges by CVE-relevance. UI follow-up can surface "PDV has N partners; this is the most-suppressing one" once frontend ships.
5. **PCF with both `cve_id` and `osv_id` NULL** (generated `vulnerability_id` from md5 hash) — counter tracks the skip; documented gap.

### Open questions (none block /implement)

1. **(informational)** Frontend follow-up: build `ComposedFindingRow` + `pairFindingsForDisplay` when `worktree-org-security-tab` merges. Will need to extend `projects.ts:10204` + `teams.ts:2336` SELECT lists to surface `composition_factor`. No DB migration at that point.
2. **(informational)** v2 ecosystem expansion (apk/rpm/wolfi) when customer signal materializes.
3. **(informational)** Aegis ORDER BY flip (depscore→contextual_depscore) — separate chore branch (Patch 4 deferred from this plan).
4. **(informational)** Anonymized public `project_native_bindings` aggregation as future open-source artifact — schema doesn't preclude it; `install_path` would need stripping pre-publish.

## Dependencies

- ✅ Phase 2 — shipped on main `8f2ccda`. binutils present.
- ✅ Phase 6 — shipped via PR #19.
- ✅ Phase 6.5 — merged.
- ✅ v3 reachability — pushed (per active sprint).
- **NO frontend coordination needed** (frontend cut entirely from this plan).
- **NO Aegis coordination needed** (M3 dropped).

## Success Criteria

1. **Composition fires correctly** for matched (PCF, PDV) pairs in the curated corpus. Verified by SQL probe + PGLite integration.
2. **Pair-count assertion met** (per Patch 3): ≥1 edge written + ≥1 PDV's contextual_depscore drops below HIGH threshold post-composition. Hard CI floor.
3. **Backfill invariant**: existing PDVs with `composition_factor = NULL` have bit-identical `contextual_depscore` post-phase30.
4. **Latency**: per-scan increase < 10s.
5. **`/criticalreview` verdict ≥ REVISE** with no remaining P0/P1.
6. **PR merged into main.** Frontend follow-up, Aegis ORDER BY chore, v2 ecosystem expansion all tracked as separate items.

## Recommended Next Step

`/review-plan iac-container-v2-item-g` once more. With all 8 patches applied and grounding re-verified, expected verdict: READY.

If READY: `/create-worktree iac-container-v2-item-g`, then `/implement`.
