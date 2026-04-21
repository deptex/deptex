# Phase 1 Atomic Commit — Design Note

Working doc for the hybrid atomic-commit refactor. Go/no-go artifact before writing `phase19_atomic_commit.sql`. References the main plan at `.cursor/plans/reachability-analysis.plan.md`.

**Architecture:** **Hybrid** — `project_dependencies` upserted in place (UUIDs stable), all downstream findings tables soft-switched under `extraction_run_id` with atomic pointer flip.

---

## Summary

- `project_dependencies` becomes upsert-by-`(project_id, name, version)`. UUIDs stable across re-extractions. Removed deps soft-deleted via `removed_at`. All FKs to project_dependencies survive (notes, fixes, etc.).
- 7 findings tables get `extraction_run_id TEXT` column. Pipeline writes new generation under fresh `extraction_run_id`, atomic pointer flip on `projects.active_extraction_run_id`.
- Existing `extraction_run_id` on 4 tables → renamed to `extraction_run_id` (concept unification).
- Carry-forward state on PDV / secret / semgrep findings via stable identifiers in `commit_extraction` RPC.
- `dependency_notes`, `is_watching`, `watchtower_cleared_at`, `ai_usage_summary` on project_dependencies all survive naturally (no carry-forward needed).
- Smart re-review on context change: **deferred** (memory: `future_smart_rereview.md`).
- Aegis learning fix, admin rollback UI: **deferred**.
- New `extraction_step_errors` table + `/admin/extraction-failures` page (Henry-only).
- Existing projects require re-extraction (Henry is sole user, acceptable).

---

## Table Treatment

### Upsert (project_dependencies)

```
project_dependencies
  + removed_at TIMESTAMPTZ NULL          -- soft-delete; NULL = still in latest extraction
  + last_seen_extraction_run_id TEXT         -- the extraction that last confirmed this dep exists
```

Behavior on extraction:
- New deps in SBOM → INSERT with new UUID, `removed_at = NULL`
- Existing deps still in SBOM → UPDATE pipeline-derived columns (`is_outdated`, `versions_behind`, `files_importing_count`, `dependency_id`, `environment`), set `last_seen_extraction_run_id = $new_extraction_run_id`, leave user state alone (`is_watching`, `watchtower_cleared_at`, `ai_usage_summary`, `ai_usage_analyzed_at`, `_id`, `created_at` all preserved)
- Deps no longer in SBOM → SET `removed_at = NOW()` (don't delete; preserves notes / fix history)

Read queries that want "current deps" add `.is('removed_at', null)`.

### Soft-Switch (7 findings tables)

| Table | Current | After |
|---|---|---|
| `project_dependency_vulnerabilities` | `project_id`, `project_dependency_id` FK, no extraction column | + `extraction_run_id TEXT` |
| `project_semgrep_findings` | `extraction_run_id` exists | rename → `extraction_run_id` |
| `project_secret_findings` | `extraction_run_id` exists | rename → `extraction_run_id` |
| `project_reachable_flows` | `extraction_run_id` exists | rename → `extraction_run_id` |
| `project_usage_slices` | `extraction_run_id` exists | rename → `extraction_run_id` |
| `project_dependency_files` | `project_dependency_id` FK | + `extraction_run_id` |
| `project_dependency_functions` | `project_dependency_id` FK | + `extraction_run_id` |

Each table gets composite index `(project_id, extraction_run_id)`.

### Tables NOT touched (PERSISTENT_CONFIG)

`project_vulnerability_events`, `project_policy_exceptions`, `project_notification_rules`, `project_integrations`, `project_pr_guardrails`, `project_roles`, `project_members`, `project_permissions`, `project_teams_junction`, `project_commits`, `project_pull_requests`, `project_repositories`, `dependency_notes`, `dependency_note_reactions`, `extraction_jobs`, `extraction_logs`.

---

## `projects` Table Changes

```sql
ALTER TABLE projects
  ADD COLUMN active_extraction_run_id TEXT,
  ADD COLUMN previous_extraction_run_id TEXT;  -- backend-only rollback capability
```

- `active_extraction_run_id` — what findings reads filter by
- `previous_extraction_run_id` — one-back generation kept for SQL-level rollback (no UI button)

Both nullable. Projects without a completed extraction post-migration show "no findings yet" until next extraction.

---

## State Carry-Forward (in `commit_extraction` RPC)

Because findings tables get fresh UUIDs each extraction, mutable user/system state on those rows must be carried forward. project_dependencies stays UUID-stable so notes, watchtower flags, ai cache survive without carry-forward.

| Table | Columns to carry | Stable identifier |
|---|---|---|
| `project_dependency_vulnerabilities` | `status`, `suppressed`, `suppressed_by`, `suppressed_at`, `sla_status`, `sla_exempt_reason`, `sla_deadline_at`, `sla_warning_at`, `sla_breached_at`, `sla_met_at`, `sla_warning_notified_at`, `sla_breach_notified_at`, `detected_at` | `(project_id, project_dependency_id, osv_id)` — `project_dependency_id` is now stable! |
| `project_secret_findings` | `status` | `(project_id, detector_type, file_path, redacted_value)` |
| `project_semgrep_findings` | `status` | `(project_id, rule_id, file_path, start_line)` |

Hybrid wins here: PDV's stable identifier becomes `(project_id, project_dependency_id, osv_id)` because project_dependency_id is now stable across extractions. No need for the awkward `(project_id, dep_name, dep_version, osv_id)` join through project_dependencies that pure soft-switch would have required.

Implementation in `commit_extraction` RPC: after inserting new findings under fresh extraction_run_id, run UPDATE statements joining new rows to old rows on stable identifiers, copying state columns.

**Smart re-review on context change is deferred** — see `future_smart_rereview.md` memory. Phase 1 ships with naive carry-forward (suppressions stick regardless of severity changes).

---

## FK Insert Order (Findings)

Inside `commit_extraction` RPC transaction:

1. `project_dependency_vulnerabilities` (FK → already-stable project_dependencies)
2. `project_dependency_files` (FK → project_dependencies)
3. `project_dependency_functions` (FK → project_dependencies)
4. `project_reachable_flows` (FK → project_dependencies via purl match, or just project_id)
5. `project_usage_slices` (FK → project_dependencies via purl match, or just project_id)
6. `project_semgrep_findings` (project_id only)
7. `project_secret_findings` (project_id only)

Then:
8. State carry-forward UPDATEs for PDV / secret / semgrep
9. Pointer flip: `UPDATE projects SET previous_extraction_run_id = active_extraction_run_id, active_extraction_run_id = $new_extraction_run_id`

Steps 1-9 in a single transaction. project_dependencies upsert happens BEFORE the transaction (or at the start of it) since it's idempotent.

---

## Read Query Update Strategy

Two filter patterns to apply:

**For findings reads (~70 query sites in 7 routes):**
```ts
.eq('project_id', projectId)
.eq('extraction_run_id', activeExtractionId)
```

**For dependency reads (~55 query sites in projects.ts and others):**
```ts
.eq('project_id', projectId)
.is('removed_at', null)
```

New helper `backend/src/lib/active-extraction.ts`:
```ts
export async function getActiveExtractionId(
  supabase: SupabaseClient,
  projectId: string
): Promise<string | null>
```

Called once per request at the top of any route that reads findings.

**Edit strategy:** mechanical, one route file at a time. ~1 day total:
- `routes/projects.ts` (~80 queries) — ~4 hours
- `routes/organizations.ts` (~30 queries) — ~2 hours
- `routes/activities.ts` (~10 queries) — ~30 min
- `routes/aegis.ts`, `internal.ts`, `recovery.ts`, `learning.ts` — ~1 hour total

---

## Timeout Enforcement

| Step | Today | Target | Action |
|---|---|---|---|
| Clone | none | 2 min | **Add** |
| Dep resolution (npm) | 300s | 10 min (600s) | Increase |
| Dep resolution (maven) | 600s | 10 min | Keep |
| SBOM (cdxgen) | none | 5 min | **Add** |
| Tree-sitter | n/a (Phase 2) | 2 min | Added in Phase 2 |
| dep-scan | 180s | 10 min | Increase |
| atom reachables | 600s | 15 min (900s) | Increase |
| atom usages | 600s | 15 min | Increase |
| Semgrep | 120s | 15 min | Increase |
| TruffleHog | 120s | 5 min (300s) | Increase |
| AI stitching | 30s/call (epd.ts) | 5 min total budget | Already capped |
| Commit | none | 2 min | **Add** |

Implementation: shared `withTimeout(fn, ms, stepName)` helper that logs to `extraction_step_errors` on timeout and throws typed `StepTimeoutError`.

---

## `extraction_step_errors` Table

```sql
CREATE TABLE extraction_step_errors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  extraction_job_id UUID NOT NULL REFERENCES extraction_jobs(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  step TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  stack TEXT,
  machine_id TEXT,
  duration_ms INT,
  severity TEXT NOT NULL DEFAULT 'error',  -- 'warn' | 'error'
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON extraction_step_errors(created_at DESC);
CREATE INDEX ON extraction_step_errors(step, code);
CREATE INDEX ON extraction_step_errors(project_id, created_at DESC);
```

Error codes (extend as needed): `timeout`, `oom`, `subprocess_failed`, `parse_error`, `fk_violation`, `network_error`, `rule_parse_error`, `unexpected`.

---

## Admin Page

`GET /api/admin/extraction-failures` (platform-admin only). Frontend `/admin/extraction-failures` — table view, filters by step/code/severity/since, click-through to stack trace + extraction logs. Bare-bones, scoped to Phase 1.

**Rollback UI deferred.** Schema keeps `previous_extraction_run_id` so backend-level rollback exists (manual SQL pointer flip), no admin button.

---

## Draft `phase19_atomic_commit.sql`

```sql
-- Phase 19: Hybrid atomic commit (upsert deps + soft-switch findings)

-- 1. project pointer columns
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS active_extraction_run_id TEXT,
  ADD COLUMN IF NOT EXISTS previous_extraction_run_id TEXT;

-- 2. project_dependencies: soft-delete + tracking
ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_seen_extraction_run_id TEXT;

CREATE INDEX IF NOT EXISTS idx_pd_active
  ON project_dependencies(project_id) WHERE removed_at IS NULL;

-- 3. Findings tables: add extraction_run_id where missing
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS extraction_run_id TEXT;
CREATE INDEX IF NOT EXISTS idx_pdv_project_extraction
  ON project_dependency_vulnerabilities(project_id, extraction_run_id);

ALTER TABLE project_dependency_files
  ADD COLUMN IF NOT EXISTS extraction_run_id TEXT;
CREATE INDEX IF NOT EXISTS idx_pdf_project_extraction
  ON project_dependency_files(project_id, extraction_run_id);

ALTER TABLE project_dependency_functions
  ADD COLUMN IF NOT EXISTS extraction_run_id TEXT;
CREATE INDEX IF NOT EXISTS idx_pdfn_project_extraction
  ON project_dependency_functions(project_id, extraction_run_id);

-- 4. Rename extraction_run_id → extraction_run_id (4 tables)
ALTER TABLE project_semgrep_findings RENAME COLUMN extraction_run_id TO extraction_run_id;
ALTER TABLE project_secret_findings RENAME COLUMN extraction_run_id TO extraction_run_id;
ALTER TABLE project_reachable_flows RENAME COLUMN extraction_run_id TO extraction_run_id;
ALTER TABLE project_usage_slices RENAME COLUMN extraction_run_id TO extraction_run_id;

-- 5. Structured error logging
CREATE TABLE IF NOT EXISTS extraction_step_errors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  extraction_job_id UUID NOT NULL REFERENCES extraction_jobs(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  step TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  stack TEXT,
  machine_id TEXT,
  duration_ms INT,
  severity TEXT NOT NULL DEFAULT 'error',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX ON extraction_step_errors(created_at DESC);
CREATE INDEX ON extraction_step_errors(step, code);
CREATE INDEX ON extraction_step_errors(project_id, created_at DESC);
```

No data backfill — existing projects re-extract.

---

## Pipeline.ts Refactor Outline

Current shape: streamed writes as data is produced. Target shape: accumulate in `PipelineState`, commit atomically.

```ts
type PipelineState = {
  extractionId: string;        // pre-generated UUID
  projectId: string;
  jobId: string;
  // Upsert target — UUIDs may be assigned during pipeline as new deps insert
  dependencies: Map<DepKey, ProjectDependencyRow>;  // keyed by (name, version)
  // Soft-switch outputs
  vulnerabilities: NewVulnerability[];
  reachableFlows: NewReachableFlow[];
  usageSlices: NewUsageSlice[];
  semgrepFindings: NewSemgrepFinding[];
  secretFindings: NewSecretFinding[];
  dependencyFiles: NewDependencyFile[];
  dependencyFunctions: NewDependencyFunction[];
  stepErrors: StepError[];
};
```

Each pipeline step: `(state: PipelineState, ctx) => Promise<PipelineState>`. No DB writes until commit.

`commit_extraction` Postgres RPC handles the transactional commit:
- Step 1: upsert deps via `INSERT ... ON CONFLICT (project_id, name, version) DO UPDATE`
- Step 2: mark removed deps (`UPDATE ... SET removed_at = NOW() WHERE last_seen_extraction_run_id != $new`)
- Step 3: insert findings under new extraction_run_id (FK order enforced)
- Step 4: state carry-forward UPDATEs (PDV, secret, semgrep)
- Step 5: pointer flip `UPDATE projects SET previous = active, active = $new`

Single transaction. Async reaper (separate cron) deletes findings rows where `extraction_run_id NOT IN (active, previous)`.

---

## Rollout Order

1. **Write + apply migration SQL** (`phase19_atomic_commit.sql`)
2. **Write `commit_extraction` Postgres RPC** with upsert + soft-delete + carry-forward + pointer flip
3. **Add `getActiveExtractionId` + `withTimeout` helpers** to `backend/src/lib/`
4. **Update read query sites** — findings get `.eq('extraction_run_id', ...)`, deps get `.is('removed_at', null)`
5. **Refactor `pipeline.ts`** to accumulate PipelineState, call `commit_extraction` RPC
6. **Add `extraction_step_errors` logging** to every step + step timeouts
7. **Build admin page** (`/admin/extraction-failures`) backend route + frontend view
8. **QStash cron** for async reaper
9. **End-to-end test** against all 4 `deptex-test-*` repos:
   - Re-extraction populates new generation, pointer flip looks instant
   - User decisions (suppress, ignore, SLA exemption) survive re-extraction via carry-forward
   - dependency_notes survive re-extraction (no carry-forward needed, FKs stable)
   - is_watching, watchtower_cleared_at, ai_usage_summary survive
   - Removed deps disappear from UI but notes remain queryable
   - Step errors logged on simulated failures
   - Timeouts fire and log `warn` severity

Estimated: **~1.5 weeks** (down from 1.5-2 weeks for pure soft-switch — hybrid is simpler).

**Out of scope for Phase 1:**
- Aegis learning fix
- Admin rollback UI
- Smart re-review on context change (memory: `future_smart_rereview.md`)
- Per-project rollback in project settings

---

## Resolved Questions

1. ✅ `project_vulnerability_events` is fine (events are history-only; status lives on finding rows). Carry-forward in commit RPC handles state.
2. ✅ `claim_extraction_job` doesn't dedupe by project_id but soft-switch handles concurrent races gracefully (last pointer flip wins). Optional follow-up: partial unique index.
3. ✅ Aegis learning: deferred (code not actively running).
4. ✅ Rollback UI: deferred (schema kept for backend SQL-level rollback).
5. ✅ Architecture: **hybrid** (upsert deps, soft-switch findings) — simpler than pure soft-switch, fewer FK headaches.
6. ✅ Carry-forward scope: full (status + suppressed + all SLA columns + detected_at).
7. ✅ Smart re-review on context change: deferred to future feature.

## Remaining Open Questions

1. **Reaper cadence** — every 15 min is a guess. Tune based on DB storage pressure.
2. **`organizations.sla_paused_at` interaction with carry-forward** — verify SLA pause/resume logic doesn't double-shift deadlines on re-extraction. Quick check during commit RPC implementation.
3. **Removed-deps reaper** — at what point do we hard-delete `project_dependencies` with `removed_at` older than X? Eventually, dependency_notes attached to long-removed deps become orphans. Probably never delete unless DB pressure demands it.

---

## Go / No-Go

**Go.** Hybrid architecture finalized. All major design questions resolved. Carry-forward scope is contained and uses stable identifiers throughout.

Next step: write `phase19_atomic_commit.sql` + the `commit_extraction` RPC.
