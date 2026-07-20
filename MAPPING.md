# DB Naming Realignment — Rename Mapping

Branch: `chore/db-name-realignment`. Pure rename, no behavior change. The app's
umbrella noun is **Findings**; six of seven finding families already live in
`project_*_findings` tables. This change moves the SCA family (the last
holdout, still on the pre-Findings "vulnerabilities" noun) onto the same
convention, ahead of the open-source release.

Migration: `backend/database/phase74_rename_dependency_findings.sql`
(forward-only, idempotent, safe to re-run). `backend/database/schema.sql` was
hand-edited to match (schema:dump not run — it pulls prod drift).

---

## 1. Renames

### Tables

| Old | New |
|---|---|
| `project_dependency_vulnerabilities` | `project_dependency_findings` |
| `project_vulnerability_events` | `project_dependency_finding_events` |

### RPCs / functions (renamed)

| Old | New |
|---|---|
| `get_project_vulnerabilities(uuid)` | `get_project_dependency_findings(uuid)` |
| `get_project_vulnerabilities_from_pdv(uuid)` | `get_project_dependency_findings_from_pdv(uuid)` |
| `get_vulnerability_detail_bundle(uuid, text)` | `get_dependency_finding_detail_bundle(uuid, text)` |
| `commit_extraction(... p_vulnerabilities ...)` | `commit_extraction(... p_dependency_findings ...)` — same function name; the parameter rename requires DROP + CREATE (Postgres cannot rename input parameters via CREATE OR REPLACE) |

Note: `get_project_dependency_findings` (the legacy non-`_from_pdv` RPC)
reads the global `dependency_vulnerabilities` catalog, not the renamed table —
it is renamed for the caller-facing noun only; its body is unchanged.
`commit_extraction` currently has **no live caller** (the worker inserts rows
directly and calls `finalize_extraction`); it is renamed-in-place, not removed —
removal is a separate cleanup decision.

### Constraints (only names that spell out an old table name)

| Old | New |
|---|---|
| `project_dependency_vulnerabilities_pkey` | `project_dependency_findings_pkey` |
| `project_dependency_vulnerabilities_project_dependency_id_fkey` | `project_dependency_findings_project_dependency_id_fkey` |
| `project_dependency_vulnerabilities_project_id_fkey` | `project_dependency_findings_project_id_fkey` |
| `project_dependency_vulnerabilities_runtime_confirmed_dast_findi` (63-char truncation artifact) | `project_dependency_findings_runtime_confirmed_dast_fkey` (deliberate, fits) |
| `project_vulnerability_events_pkey` | `project_dependency_finding_events_pkey` |
| `project_vulnerability_events_project_dependency_id_fkey` | `project_dependency_finding_events_project_dependency_id_fkey` |
| `project_vulnerability_events_project_id_fkey` | `project_dependency_finding_events_project_id_fkey` |

### Indexes

| Old | New |
|---|---|
| `idx_project_dependency_vulnerabilities_osv_id` | `idx_project_dependency_findings_osv_id` |
| `idx_project_dependency_vulnerabilities_project_dependency_id` | `idx_project_dependency_findings_project_dependency_id` |
| `idx_project_dependency_vulnerabilities_project_id` | `idx_project_dependency_findings_project_id` |
| `idx_project_dependency_vulnerabilities_severity` | `idx_project_dependency_findings_severity` |
| `project_dependency_vulnerabilities_runtime_confirmed_fk` | `project_dependency_findings_runtime_confirmed_fk` |

### Trivial (also in phase74)

`ai_usage_logs_tier_check` drops the dead `'byok'` value (BYOK retired in
`phase29_drop_byok.sql`): now `CHECK (tier = 'platform') NOT VALID`.
`NOT VALID` is deliberate — historical `byok` rows may exist in prod and must
survive; only new writes are checked. The TS type in
`backend/src/lib/ai/logging.ts` keeps `'byok'` in its union for reading those
historical rows (its own comment already says new writes are always
`'platform'`).

---

## 2. The `pdv` decision: RETAINED as a documented historical abbreviation

`pdv` ("project dependency vulnerability") is the pervasive shorthand for a
row of the renamed table: `project_composition_partners.pdv_id`,
`silence_events.pdv_id`, trigger + function `trg_pdv_finding_status`,
`confirm_pdvs_from_dast_run`, ~10 `idx_pdv_*` indexes, `chk_pdv_*` checks,
`pdv_extraction_run_unique`, `_pdv_reachability_rank`/`_pdv_severity_rank`,
the `pdv_id` JSON key in the composition RPC payload, and hundreds of
`pdv`-named identifiers across worker + backend code.

**Decision: keep `pdv` everywhere, as an opaque legacy token.** Rationale:

1. The natural successor initialism for `project_dependency_findings` is
   `pdf`, which collides head-on with the document format — actively worse
   for readability and grep-ability than a documented legacy token.
2. Expanding instead (e.g. `dep_finding_id`) would ripple through column
   renames wired into ingestion (composition partners, silence events), the
   ON-CONFLICT/unique constraint surface, and hundreds of TS identifiers —
   a large, risky diff for zero functional gain, in a change whose whole
   point is to be a safe pure rename.
3. A short, stable, unique abbreviation for "a row of the SCA findings table"
   is genuinely useful; `pdv` stays unambiguous precisely because nothing
   else claims it.

The same policy applies to `pve` (`idx_pve_*`, for the events table) and
`pcp` (`idx_pcp_*`, composition partners). The rule that emerges — and that
future contributors should follow — is:

> Object names that **spell out a table name in full** track the current
> table name; the short abbreviations `pdv` / `pve` / `pcp` are **frozen
> historical tokens**, documented via `COMMENT ON TABLE` (added in phase74)
> and this file.

This is also why `get_project_dependency_findings_from_pdv` keeps its
`_from_pdv` suffix: it distinguishes the modern RPC (reads the pdv table)
from the legacy catalog-join RPC, and `pdv` remains meaningful under the
frozen-token rule.

---

## 3. Explicitly KEPT (and why)

- **`dependency_vulnerabilities` (global catalog)** — it stores
  vulnerabilities/advisories (facts about CVEs), not findings (observations
  in a project). "Vulnerabilities" is the correct noun there.
- **`finding_type = 'vulnerability'` (polymorphic subtype value)** — the
  legitimate subtype label; "Dependency vulnerabilities" is still the UI
  category name. Tables are renamed, this string value is not. (Same for the
  detail-bundle response key `'vulnerabilities'` — it is API payload shape,
  consistent with the subtype label, and renaming it would churn the
  frontend contract for no DB-naming gain.)
- **Aegis AI tool name `get_project_vulnerabilities`** (v2 + v3) — this is
  the agent's tool surface (referenced in system prompts, tool registries,
  and potentially in stored task plans), not a DB identifier. It merely
  coincides with the old RPC name. Renaming AI tool names is a separate,
  behavior-adjacent decision.
- **Internal engine codenames `watchtower_*`, `taint_engine_*`** — zero
  user-facing presence; fine as internal names.
- **`project_semgrep_findings`** — already on the convention.
- **Historic migrations in `backend/database/`** — immutable history. Fresh
  installs run them in filename order and phase74 renames at the end.
- **Dated/historical docs** (`docs/depscanner-hardening-report.md`,
  `docs/snapshot-coverage-audit-2026-05-10.md`,
  `docs/runbooks/dast-v2-1c-deploy.md`) — records of their time; the old
  names in them were correct when written. Living docs were updated
  (`docs/adding-a-new-ecosystem.md`, `docs/depscanner.md`,
  `.claude/commands/evaluate-findings.md`).

## 4. Deferred follow-ups (deliberately not half-done)

- **`project_dast_findings.vulnerability_type`** and
  **`project_container_findings.vulnerability_id`** — column renames embedded
  in unique indexes and worker ingestion paths. Low value relative to risk;
  each deserves its own small, tested change if wanted.
- `backend/src/lib/aegis/tools/get-project-vulnerabilities.ts` is **dead
  code** (exported, never imported — the v2 tool was superseded). Its table
  reference was updated like everything else, but removing it is a cleanup
  decision outside a pure rename.
- `finalize_extraction`'s returned summary keys (`vulns_new`, …) keep the
  `vulns` shorthand — stats-key naming, not object naming.
- Pre-existing (NOT from this change; verified identical on the unmodified
  baseline): `depscanner test:dast-v2-1c-migration-pglite` fails later in
  section [B] on `projects.asset_tier_id` (stale since phase41 dropped asset
  tiers; local-only script, not in CI). Backend `tsc` emits 26 TS2742
  non-portable-inferred-type errors and depscanner `tsc` one TS7016
  (@types/semver) — both worktree-environment artifacts, byte-identical
  before/after this change.

## 5. Touchpoints

- **DB (phase74 + schema.sql):** 2 table renames, 7 constraint renames,
  5 index renames, 3 RPC renames + 1 parameter rename (DROP+CREATE), 14
  functions recreated verbatim under their existing names because their
  bodies reference the renamed tables (`apply_composition_results`,
  `backfill_sla_for_organization`, `confirm_pdvs_from_dast_run`,
  `enforce_composition_same_project`, `finalize_extraction`,
  `get_sla_approaching_warning`, `get_sla_newly_breached`,
  `project_stats_counts`, `reap_old_extractions`,
  `reap_orphaned_extractions`, `resume_sla_shift_deadlines`,
  `security_summary_counts`, `team_stats_counts`, `team_top_vulns`),
  2 `COMMENT ON TABLE` docs, 1 CHECK swap. (`trg_pdv_finding_status` needs no
  recreation: its body references no renamed table; the trigger follows the
  table by OID.)
- **Code:** ~95 files across `backend/src` (+`backend/scripts`),
  `frontend/src`, `depscanner/{src,test,scripts}` — query strings
  (`.from('…')`), RPC names, raw SQL in PGLite tests, and comments. No
  REST route paths, no TS identifier renames (application-layer naming is a
  separate concern from DB naming).
- **Test-harness accommodations (2):**
  `depscanner/test/findings-status-migration-pglite.ts` replays the historic
  phase55 migration onto the current schema — it now maps the old table name
  forward before exec (the backfill logic under test is unchanged);
  `depscanner/test/dast-v2-1c-migration-pglite.ts` asserts the
  runtime-confirmed FK by name and now expects the new deliberate constraint
  name.

## 6. Verification (all from inside the worktree)

- **Migration ≡ schema.sql equivalence proof (PGLite, real Postgres wasm):**
  old schema.sql (git HEAD) + phase74 produces a catalog **byte-identical**
  to the hand-edited schema.sql — 1376 objects compared via the in-DB
  `pg_catalog_dump_v1()` DDL generator, with `check_function_bodies` ON (so
  every recreated function body compiled against the renamed tables).
- `backend`: `npx tsc --noEmit` — no new errors (26 pre-existing TS2742
  environment artifacts, byte-identical to the unmodified baseline).
- `frontend`: `npx tsc --noEmit -p tsconfig.json` — clean.
- `backend`: `npx jest --no-coverage` — **220/220 suites, 3507 passed,
  12 skipped, 0 failures** (includes the depscanner/src and fix-worker suites
  via cross-package roots).
- `frontend`: `npx vitest run` — **57 files passed / 1 skipped, 564 tests
  passed / 23 skipped, 0 failures**.
- `depscanner`: `npm run test:integration-pglite` — all 18 sub-suites green
  (smoke, storage, finalize, composition, findings-status 67/67,
  stats-counts, security-summary, silence-events, silence-drift, dual-scope,
  claim-fairness, fleet-snapshot, container-cache, malicious-feeds, DAST
  migration + scoring gates, rule-generation).
