# Malicious Packages — Implementation Plan (v1, post-review)

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

> **Revision history:** original plan reviewed by 12-persona swarm 2026-04-29; verdict REWORK (unanimous). This v1 plan applies all 14 patches from `.cursor/plans/review-malicious-packages.md` — most resolutions are scope cuts rather than fixes, dropping v1 from 4 milestones to 2.

## Overview

A first-class malicious-package detection layer in the extraction pipeline that brings Deptex to **Socket-tier parity** using open-source tooling: multi-feed lookup (OSV.dev + GHSA `MALWARE`) and GuardDog source-code heuristics across 6 ecosystems. AI explainer is **on-demand** (user clicks "Explain this finding"), not eager at scan time. Findings surface as new rows in the existing unified `VulnerabilityExpandableTable` (`type: 'malicious'`).

Sequenced as **two shippable milestones** over ~3 weeks: M1 Detection (schema + GuardDog + feeds + project view + soft-fail pipeline) and M2 Continuous-light (chained QStash feed-sync workflow with staleness watchdog + on-demand AI Explain button + Aegis read-side integration). No feature flag — solo-pre-launch context.

**Cut from v1 (deferred to v1.1+):** capability detection (M3), org-wide allowlist tables, rescan-existing cron, org rollup card, default notification trigger templates, full maintained benchmark harness, eager AI narrative generation, Aikido Intel feed (pending legal artifact verification), Datadog as live feed (it's benchmark fixture only).

Source brief: `.cursor/plans/feature-brief-malicious-packages.md`. Source research: `.cursor/plans/research-malicious-packages.md`. Review report: `.cursor/plans/review-malicious-packages.md`.

---

## Multi-Tenant Invariants

This feature has multiple tenant-scoping surfaces (worker, cron, cache, AI bridge, notification dispatcher, Aegis tool). Implementer MUST preserve every invariant listed here; each has a corresponding test in M1 acceptance.

1. Every `project_malicious_findings` row is reachable from exactly one organization via the FK chain `project_dependency_id → project_dependencies → projects.organization_id` AND via the denormalized `organization_id` column (trigger-enforced consistency).
2. `package_security_cache` rows contain no org-derived data (no project paths, repo URLs, project names, branch names, or local filesystem paths). Cache is global by design; PII would leak cross-tenant.
3. Every public route MUST verify `organization_members` membership against `:orgId` URL param BEFORE any DB read or write. Mutation handlers MUST write `organization_id` from URL param only — never trust body fields.
4. Worker queries against per-org tables (none in v1, but pattern documented for v1.1) MUST scope by the project's `organization_id` resolved from `projects` row, never global.
5. All `emitEvent('malicious_package_detected', ...)` payloads MUST carry `organization_id` derived from `projects.organization_id`.
6. `deduplicationKey` for `malicious_package_detected` MUST be `sha256(orgId || project_id || project_dependency_id || rule_id)` — orgId first; namespaces are per-tenant by construction.
7. Cross-tenant route tests (org-A user → 403 on every org-B URL) for every public route, INCLUDING with `:orgId` from one org and a body field claiming a different org.
8. Aegis `analyze_package_security` derives `organization_id` from chat execution context, never from tool arguments (prompt-injection cross-reference).
9. AI Explain endpoint receives `organization_id` from URL param; per-org rate limit applies; spend logged to `ai_usage_logs` with org attribution.

---

## Competitive Research & Design Rationale

Full research in `.cursor/plans/research-malicious-packages.md`. Key decisions reaffirmed after review:

- **Why GuardDog as the scanning engine** — Apache-2.0, 6 ecosystems, v2.9.0 active Feb 2026, Semgrep+YARA rules + per-ecosystem metadata heuristics. Only OSS tool covering Socket's signal breadth without a vendor research team.
- **Why on-demand AI explainer (not eager)** — eliminates the worker-AI bridge service-boundary problem entirely (worker doesn't make AI calls), bounds prompt-injection surface (only triggered by user click), bounds cost (no eager spend on novel-but-clean packages), bounds rescan amplification (no feed-driven AI fanout), and the global cache still amortizes (second viewer of same package reads cache).
- **Why soft-fail (not hard-fail at 5%)** — hard-fail interacted catastrophically with `extraction_jobs.max_attempts=3` retries during transient registry hiccups; cascading failure across the fleet on monthly npm/PyPI blips. The user-facing invariant ("no findings shown means scanned and clean") is preserved by `scan_status='partial'` UI banner.
- **Why drop Datadog + Aikido from v1 sources** — Datadog dataset is encrypted-ZIP samples for benchmarking, not a live coordinate feed. Aikido Intel licensing is unverified (data feed under permissive license vs SDK under AGPL §13). v1 ships with OSV.dev (covers OSSF malicious-packages + others) and GHSA — both already established in Deptex.
- **Why cut capability detection from v1** — 9-tag taxonomy still undecided in plan; tag-set drift is exactly the kind of "polish before user signal" pre-launch should defer. Add when first user reports needing it.
- **Why cut org-wide allowlist from v1** — feature attracted 6 distinct concerns from 6 personas (permission gate doesn't exist, audit trail loss, retroactive-resolve has no UNDO, NULLS-NOT-DISTINCT bug, cross-org scoping unspecified, ARCH-05 substrate question). Per-finding ignore + accept-risk covers v1 needs. Revisit by extending `project_policy_exceptions` if real demand surfaces.
- **Why cut rescan-existing cron from v1** — largest blast radius, smallest pre-launch user value. New malicious feed entries get detected on next extraction-time scan via the feed-lookup step. Daily feed-sync still keeps `known_malicious_packages` current.

---

## Codebase Analysis

### Existing patterns we are following (verified)

**Database:**
- Canonical per-project dep-keyed finding shape: `project_dependency_vulnerabilities` (`schema.sql:794-829`) — uses `project_dependency_id NOT NULL REFERENCES project_dependencies(id) ON DELETE CASCADE` plus `UNIQUE (project_id, project_dependency_id, osv_id, extraction_run_id)` plus paired booleans `suppressed/risk_accepted` with `*_by/*_at/*_reason` audit columns. **NOT** the `project_semgrep_findings`/`project_secret_findings` shape — those are file-keyed, not dep-keyed.
- `project_security_fixes` (`schema.sql:1062`) already has `semgrep_finding_id` and `secret_finding_id` columns; we add `malicious_finding_id` symmetrically.
- `dependencies.is_malicious` flag (`add_is_malicious_to_dependencies.sql`) — kept as fast denormalized flag, recomputed by RPC at end of malicious-scan.
- `dependencies` table has TWO conflicting UNIQUE constraints: legacy `dependencies_new_name_key UNIQUE (name)` and current `idx_dependencies_ecosystem_name UNIQUE (ecosystem, name)`. Plan's migration drops the legacy constraint to enable `lodash` existing as both `npm` AND `pypi` rows.

**Backend — finding routes:**
- Canonical paths mount under `/api/organizations/:id/projects/:projectId/...` (NOT `/api/projects/...`). See `backend/src/routes/projects.ts:9499` for semgrep findings. Confirmed via `backend/src/index.ts:128` mount.
- Read access pattern: `checkProjectAccess(userId, organizationId, projectId)`.
- Mutation access pattern: `checkProjectManagePermission(userId, orgId, projectId)` → checks `manage_projects` (team/project role) OR `manage_teams_and_projects` (org role).

**Backend — RBAC verified active permission keys** (per `schema.sql` defaults + `backend/src/routes/organizations.ts` runtime checks):
- Org permissions: `manage_security, manage_compliance, manage_statuses, manage_billing, view_settings, edit_settings, view_overview, view_activity, manage_integrations, manage_notifications, manage_members, manage_teams_and_projects, view_all_teams`.
- Pattern: routes use `organizationsHelpers.checkOrgPermission(userId, orgId, key)` which preserves owner/admin auto-grant.
- **Note: CLAUDE.md drift** — CLAUDE.md lists `manage_organization_settings`, `manage_policies`, `view_activities`, `view_all_teams_and_projects` which do NOT exist in main. CLAUDE.md fix is out-of-scope for this PR (separate small chore).

**Backend — event bus:**
- `backend/src/lib/event-bus.ts:27` already lists `'malicious_package_detected'` in `CRITICAL_EVENT_TYPES`. Pre-wired.

**Backend — AI provider:**
- `getPlatformProvider()` from `backend/src/lib/ai/provider.ts` uses `GOOGLE_AI_API_KEY` (Tier-1). Lives in `backend/src/`; **NOT importable from extraction-worker** (separate Fly.io app, separate package.json). v1 design avoids this boundary entirely by routing AI through a backend HTTP route only at user-click time.
- `cost-cap.ts:checkMonthlyCostCap` only handles BYOK Tier-2 today. v1 ships a new `lib/ai/platform-cost-cap.ts` (Patch 5) for Tier-1 platform-spend gating.

**Worker — pipeline pattern:**
- `backend/extraction-worker/src/pipeline.ts:1420-1540` (Semgrep step) is the canonical template: `checkCancelled` at step entry, `binaryAvailable()` check, `withTimeout()` wrapper, `execSync(... || true)`, output upload to `project-imports` Storage bucket, batch upsert (100 at a time), `logStepError(severity: 'warn')` on catch, **soft-fail per step** (warn, continue).
- `withTimeout()`, `binaryAvailable()`, `INSTALL_HINTS` (in `pipeline.ts:331`, NOT `index.ts`), `logStepError()`, `extraction_step_errors` table — all leveraged.
- Heartbeat: extraction worker runs 60s heartbeat / 5min stuck detection. New step must extend heartbeat between packages.

**Frontend — security table:**
- `VulnerabilityExpandableTable.tsx` uses discriminated union `SecurityTableRow` with field `type:` (NOT `kind:`). Existing variants include `vuln`, `secret`, `semgrep`, `license`. We add `'malicious'`.
- `PackageOverview.tsx:413` already renders the malicious badge from `analysis?.is_malicious`. Click flows into the new finding card.

### Files we will create

| Path | Purpose |
|---|---|
| `backend/database/malicious_packages_v1.sql` | Single migration: 2 new tables + 1 column + 1 RPC + drop legacy UNIQUE |
| `backend/src/routes/malicious.ts` | Public + internal HTTP routes (mounted under `/api/organizations`) |
| `backend/src/lib/malicious/types.ts` | Shared TS types between routes, lib, worker (via internal HTTP), and frontend |
| `backend/src/lib/malicious/severity.ts` | GuardDog severity → Deptex severity mapping (3 effective levels) |
| `backend/src/lib/malicious/explain.ts` | API-side AI Explain handler (Tier-1 Gemini Flash, prompt-injection-hardened, cached globally) |
| `backend/src/lib/malicious/feed-sync.ts` | Per-source ingestion (OSV.dev + GHSA), called from chained QStash workflow |
| `backend/src/lib/malicious/staleness-watchdog.ts` | Independent watchdog over `malicious_feed_sync_runs` |
| `backend/src/lib/ai/platform-cost-cap.ts` | NEW: Tier-1 platform-spend gate (Redis token bucket); prerequisite to Tier-1 features |
| `backend/extraction-worker/src/malicious-scan.ts` | Pipeline step entrypoint: feed lookup + GuardDog scan |
| `backend/extraction-worker/src/malicious/guarddog.ts` | GuardDog invocation via `/opt/guarddog-venv/bin/guarddog` + JSON parsing |
| `backend/extraction-worker/src/malicious/feeds.ts` | Worker-side feed lookup against `known_malicious_packages` |
| `backend/extraction-worker/src/malicious/insert-finding.ts` | Single shared insertion path (idempotent UPSERT honoring UNIQUE) |
| `backend/extraction-worker/src/malicious/tarball-cache.ts` | Per-job ephemeral tarball cache; sandbox boundary owner |
| `scripts/bench-malicious-once.ts` | Throwaway smoke benchmark — run once before merge, not maintained |
| `frontend/src/components/security/MaliciousFindingCard.tsx` | Expanded-row content for `type: 'malicious'` rows |
| `frontend/src/components/security/EmptyMaliciousState.tsx` | Empty state with feed list + scanner version + last-scan timestamp |

### Files we will modify

| Path | Change |
|---|---|
| `backend/database/schema.sql` | Refreshed via `npm run schema:dump` after migration |
| `backend/src/index.ts` | Mount new `malicious.ts` router |
| `backend/extraction-worker/Dockerfile` | Install `guarddog==2.9.0` into `/opt/guarddog-venv` (Patch 13) |
| `backend/extraction-worker/src/pipeline.ts` | (a) Insert `malicious-scan` step after tree-sitter, before Semgrep; (b) add `INSTALL_HINTS.guarddog`; (c) call `recompute_dependency_is_malicious` post-step; (d) heartbeat between packages |
| `backend/src/lib/aegis/tools/intelligence.ts:165` | `analyze_package_security` reads new tables, scoped to chat's `organization_id` |
| `backend/src/lib/aegis/pr-review.ts:79` | PR review reads new tables |
| `backend/src/routes/projects.ts` | Project security summary aggregations include malicious counts |
| `backend/src/lib/notification-dispatcher.ts:498` | Extend `dep.malicious_indicator` with `scanner` + `severity` + `top_finding_id` (additive only; preserves existing `source/confidence/reason` keys) |
| `frontend/src/lib/api.ts` | Add `MaliciousFinding`, `MaliciousIndicator` types + `api.maliciousFindings` methods |
| `frontend/src/components/security/VulnerabilityExpandableTable.tsx` | Extend `SecurityTableRow` union with `type: 'malicious'`; extend every `switch (row.type)` site (TypeIcon, getRowTitle, severity sort, expand-content dispatch, filter chip mapping) |
| `frontend/src/components/PackageOverview.tsx` | Link malicious banner into MaliciousFindingCard |

---

## Data Model

### Migration: `backend/database/malicious_packages_v1.sql`

Apply via Supabase MCP. After apply, run `cd backend/extraction-worker && npm run schema:dump`.

```sql
-- =============================================================================
-- Malicious Packages v1
-- =============================================================================
-- Adds:
--   1. known_malicious_packages           — global, ingested from OSV + GHSA
--   2. package_security_cache             — global, per-(package, version, scanner)
--   3. project_malicious_findings         — per-project finding records
--   4. malicious_finding_id column on project_security_fixes
--   5. malicious_feed_sync_runs           — per-source state for watchdog
--   6. RPC recompute_dependency_is_malicious
--   7. RPC insert_malicious_findings_with_recompute (atomic insert + recompute)
-- Also drops legacy dependencies UNIQUE(name) constraint that blocks
-- cross-ecosystem rows (lodash both npm AND pypi).
-- =============================================================================

-- 0. Drop legacy UNIQUE that blocks cross-ecosystem dep rows
ALTER TABLE public.dependencies DROP CONSTRAINT IF EXISTS dependencies_new_name_key;

-- 1. Global feed lookup table
CREATE TABLE IF NOT EXISTS public.known_malicious_packages (
  id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  package_name    text NOT NULL,
  version         text,                       -- null = all versions
  ecosystem       text NOT NULL,              -- canonical lowercase: npm, pypi, maven, golang, rubygems
  source          text NOT NULL,              -- 'osv' | 'ghsa'
  source_id       text NOT NULL,
  severity        text,                       -- critical | high | medium | low | info
  description     text,
  first_seen_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),
  withdrawn_at    timestamptz,                -- non-null = withdrawn / FP
  CONSTRAINT known_malicious_packages_source_id_key UNIQUE (source, source_id),
  CONSTRAINT known_malicious_packages_ecosystem_chk CHECK
    (ecosystem IN ('npm','pypi','maven','golang','rubygems','github-actions','vscode'))
);
CREATE INDEX IF NOT EXISTS idx_known_malicious_packages_lookup
  ON public.known_malicious_packages (package_name, ecosystem)
  WHERE withdrawn_at IS NULL;

-- 2. Global per-(package, version, scanner) cache
-- scanner_version stored as plain telemetry column, NOT in UNIQUE — UPSERT on
-- (package_name, version, ecosystem, scanner) replaces in place on scanner upgrade.
CREATE TABLE IF NOT EXISTS public.package_security_cache (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  package_name        text NOT NULL,
  version             text NOT NULL,
  ecosystem           text NOT NULL,
  scanner             text NOT NULL,                       -- 'guarddog' | 'ai_review'
  scanner_version     text NOT NULL,                       -- e.g. 'guarddog@2.9.0'
  prompt_version      text,                                -- non-null only for scanner='ai_review'
  model_version       text,                                -- non-null only for scanner='ai_review'
  prompt_input_sha256 text,                                -- non-null only for scanner='ai_review' (poisoning trace)
  findings            jsonb NOT NULL DEFAULT '[]'::jsonb,  -- [{rule_id, severity, message, evidence}]
  ai_narrative        text,                                -- non-null only for scanner='ai_review'
  risk_level          text,                                -- critical|high|medium|low|info|none
  scanned_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT package_security_cache_key UNIQUE
    (package_name, version, ecosystem, scanner),
  CONSTRAINT package_security_cache_ecosystem_chk CHECK
    (ecosystem IN ('npm','pypi','maven','golang','rubygems','github-actions','vscode')),
  CONSTRAINT package_security_cache_scanner_chk CHECK
    (scanner IN ('guarddog','ai_review'))
);
CREATE INDEX IF NOT EXISTS idx_package_security_cache_lookup
  ON public.package_security_cache (package_name, version, ecosystem, scanner);

-- NOTE: cache is global by design. If per-org GuardDog rules ever land
-- (e.g., Phase 5 reachability per-org rules pattern extends here), the
-- scanner='guarddog' rows MUST grow an organization_id column added to
-- the UNIQUE — global cache breaks for org-derived inputs.
-- Cache rows MUST contain no org-derived data: file paths are tarball-rooted,
-- never project-rooted; ai_narrative does not name project or repo URL.

-- 3. Per-project finding records — mirrors project_dependency_vulnerabilities
CREATE TABLE IF NOT EXISTS public.project_malicious_findings (
  id                    uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id            uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id       uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  extraction_run_id     text NOT NULL,
  project_dependency_id uuid NOT NULL REFERENCES public.project_dependencies(id) ON DELETE CASCADE,
  dependency_id         uuid NOT NULL REFERENCES public.dependencies(id),  -- denorm for recompute RPC
  rule_id               text NOT NULL,
  scanner               text NOT NULL CHECK (scanner IN ('feed','guarddog')),
  severity              text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  message               text,
  depscore              integer,
  suppressed            boolean NOT NULL DEFAULT false,
  suppressed_by         uuid REFERENCES auth.users(id),
  suppressed_at         timestamptz,
  suppressed_reason     text,
  risk_accepted         boolean NOT NULL DEFAULT false,
  risk_accepted_by      uuid REFERENCES auth.users(id),
  risk_accepted_at      timestamptz,
  risk_accepted_reason  text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pmf_dedup UNIQUE NULLS NOT DISTINCT
    (project_id, project_dependency_id, rule_id, scanner, extraction_run_id)
);
CREATE INDEX IF NOT EXISTS idx_pmf_project_run
  ON public.project_malicious_findings (project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_pmf_project_open
  ON public.project_malicious_findings (project_id, suppressed, risk_accepted);
CREATE INDEX IF NOT EXISTS idx_pmf_org
  ON public.project_malicious_findings (organization_id);
CREATE INDEX IF NOT EXISTS idx_pmf_dep
  ON public.project_malicious_findings (dependency_id);

-- Trigger: enforce organization_id consistency with projects.organization_id
CREATE OR REPLACE FUNCTION public.enforce_pmf_org_consistency()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  expected_org uuid;
BEGIN
  SELECT organization_id INTO expected_org FROM public.projects WHERE id = NEW.project_id;
  IF expected_org IS NULL THEN
    RAISE EXCEPTION 'project % does not exist', NEW.project_id;
  END IF;
  IF NEW.organization_id != expected_org THEN
    RAISE EXCEPTION 'organization_id % does not match project organization_id %',
      NEW.organization_id, expected_org;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER pmf_enforce_org_consistency
  BEFORE INSERT OR UPDATE OF organization_id, project_id ON public.project_malicious_findings
  FOR EACH ROW EXECUTE FUNCTION public.enforce_pmf_org_consistency();

-- 4. Add malicious_finding_id to fix tracking
ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS malicious_finding_id uuid
    REFERENCES public.project_malicious_findings(id) ON DELETE SET NULL;

-- 5. Per-source state for staleness watchdog
CREATE TABLE IF NOT EXISTS public.malicious_feed_sync_runs (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  source              text NOT NULL,                       -- 'osv' | 'ghsa'
  state               text NOT NULL DEFAULT 'pending',     -- pending | running | completed | failed | dlq
  started_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),  -- heartbeat
  completed_at        timestamptz,
  entries_added       integer DEFAULT 0,
  entries_withdrawn   integer DEFAULT 0,
  error_message       text,
  CONSTRAINT mfsr_state_chk CHECK
    (state IN ('pending','running','completed','failed','dlq'))
);
CREATE INDEX IF NOT EXISTS idx_mfsr_source_state
  ON public.malicious_feed_sync_runs (source, state, completed_at DESC);

-- 6. Recompute dependencies.is_malicious for affected rows
-- Joins on canonical lowercase ecosystem; feed-sync.ts MUST canonicalize at ingest.
CREATE OR REPLACE FUNCTION public.recompute_dependency_is_malicious(p_dependency_ids uuid[])
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  -- Lock dependency rows to prevent cross-extraction race per FMH-07
  PERFORM 1 FROM public.dependencies WHERE id = ANY(p_dependency_ids) FOR UPDATE;

  UPDATE public.dependencies d
  SET is_malicious = (
    EXISTS (
      SELECT 1 FROM public.project_malicious_findings f
      WHERE f.dependency_id = d.id
        AND f.suppressed = false
        AND f.risk_accepted = false
    )
    OR EXISTS (
      SELECT 1 FROM public.known_malicious_packages k
      WHERE k.package_name = d.name
        AND k.ecosystem = lower(d.ecosystem)
        AND k.withdrawn_at IS NULL
    )
  )
  WHERE d.id = ANY(p_dependency_ids);
END;
$$;

-- 7. Atomic batch-insert findings + recompute is_malicious
-- Worker calls this once per scan with all findings; RPC handles dedup via UPSERT
-- and recompute in single transaction so partial failures don't leave is_malicious
-- inconsistent with project_malicious_findings.
CREATE OR REPLACE FUNCTION public.insert_malicious_findings_with_recompute(p_findings jsonb)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_inserted integer := 0;
  v_dep_ids uuid[];
BEGIN
  -- Insert findings (idempotent via UNIQUE)
  WITH inserted AS (
    INSERT INTO public.project_malicious_findings (
      project_id, organization_id, extraction_run_id, project_dependency_id,
      dependency_id, rule_id, scanner, severity, message, depscore
    )
    SELECT
      (f->>'project_id')::uuid,
      (f->>'organization_id')::uuid,
      f->>'extraction_run_id',
      (f->>'project_dependency_id')::uuid,
      (f->>'dependency_id')::uuid,
      f->>'rule_id',
      f->>'scanner',
      f->>'severity',
      f->>'message',
      (f->>'depscore')::integer
    FROM jsonb_array_elements(p_findings) AS f
    ON CONFLICT (project_id, project_dependency_id, rule_id, scanner, extraction_run_id)
      DO NOTHING
    RETURNING dependency_id
  )
  SELECT array_agg(DISTINCT dependency_id), count(*)::integer
    INTO v_dep_ids, v_inserted FROM inserted;

  IF v_dep_ids IS NOT NULL AND array_length(v_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_dep_ids);
  END IF;

  RETURN v_inserted;
END;
$$;
```

### Volume / index strategy

- `known_malicious_packages`: bounded by all known malicious advisories from OSV + GHSA. Year-1 estimate ~30k rows. Lookup index covers `(package_name, ecosystem)` with partial WHERE on `withdrawn_at IS NULL`.
- `package_security_cache`: 2 rows per (package, version) max (one for `guarddog`, one for `ai_review` if ever explained). At ~100k unique (package, version) pairs observed, bounded ~200k rows. UPSERT semantics replace in place on scanner upgrade — no row multiplier on version bumps.
- `project_malicious_findings`: per-extraction-run row creation. Daily extraction × 50 weeks × 50 projects × 5 findings/project = ~62k rows year 1 (pre-launch scale). Open findings only retained beyond N runs back; resolved findings purged via daily cron in v1.1. For now: no retention cron in v1.
- `malicious_feed_sync_runs`: one row per source per cron run; ~700 rows/year. Trivial.

---

## API Design

All public routes mounted on the existing organizations router pattern under `/api/organizations`. Route file: `backend/src/routes/malicious.ts` (mounted via `app.use('/api/organizations', maliciousRouter)` in `backend/src/index.ts`, OR imported into existing organizations router — implementation choice).

### Public endpoints

| Method | Route | Auth | Permission gate | Tenant filter |
|---|---|---|---|---|
| GET | `/api/organizations/:id/projects/:projectId/malicious-findings` | `authenticateUser` | `checkProjectAccess(userId, id, projectId)` | `WHERE project_id=:projectId AND organization_id=:id` |
| GET | `/api/organizations/:id/projects/:projectId/malicious-findings/:findingId` | `authenticateUser` | same | same + `id=:findingId` |
| PATCH | `/api/organizations/:id/projects/:projectId/malicious-findings/:findingId` | `authenticateUser` | `checkProjectManagePermission(userId, id, projectId)` | same + verify `finding.project_id=:projectId` defense-in-depth |
| POST | `/api/organizations/:id/projects/:projectId/malicious-findings/:findingId/explain` | `authenticateUser` | `checkProjectAccess` | same; per-org rate limit; per-user rate limit |

### Internal endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/internal/malicious/feed-sync/:source` | `INTERNAL_API_KEY` | One step in chained QStash workflow; runs source-specific ingestion |
| POST | `/api/internal/malicious/staleness-watchdog` | `INTERNAL_API_KEY` | Watchdog cron (every 6h); emits `feed_sync_stale` critical event when stale |

### TypeScript types — `backend/src/lib/malicious/types.ts`

```typescript
export type MaliciousScanner = 'feed' | 'guarddog';
export type MaliciousSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type MaliciousFeedSource = 'osv' | 'ghsa';

export interface MaliciousFinding {
  id: string;
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  project_dependency_id: string;
  dependency_id: string;
  rule_id: string;
  scanner: MaliciousScanner;
  severity: MaliciousSeverity;
  message: string | null;
  depscore: number | null;
  suppressed: boolean;
  suppressed_by: string | null;
  suppressed_at: string | null;
  suppressed_reason: string | null;
  risk_accepted: boolean;
  risk_accepted_by: string | null;
  risk_accepted_at: string | null;
  risk_accepted_reason: string | null;
  created_at: string;
  // Hydrated from package_security_cache on detail fetch:
  evidence?: { file_path: string; lines: [number, number]; snippet: string }[];
  ai_narrative?: string | null;       // null until user clicks Explain
  ai_narrative_cached_at?: string | null;
  // Hydrated from dependencies join:
  package_name?: string;
  ecosystem?: string;
  package_version?: string;
}

export interface MaliciousIndicator {
  // Backwards-compatible shape: existing keys preserved, new keys additive.
  source: 'deptex';
  confidence: 'high';
  reason: string;                     // existing
  scanner?: MaliciousScanner;         // additive
  severity?: MaliciousSeverity;       // additive
  top_finding_id?: string | null;     // additive
}

export interface ExplainResult {
  narrative: string;
  risk_level: MaliciousSeverity | 'none';
  cached: boolean;
}
```

### Error cases

| Case | Status | Body |
|---|---|---|
| User not member of `:id` org | 403 | `{ error: 'Insufficient permissions' }` |
| Project not in `:id` org | 403 | `{ error: 'Project not accessible' }` |
| Finding `:findingId` not in `:projectId` | 404 | `{ error: 'Finding not found' }` |
| PATCH from user without `manage_projects`/`manage_teams_and_projects` | 403 | `{ error: 'Insufficient permissions' }` |
| Internal route without `INTERNAL_API_KEY` | 401 | `{ error: 'Unauthorized' }` |
| Explain rate-limited (per-user 50/min OR per-org 200/day unique findings) | 429 | `{ error: 'Rate limit exceeded' }` |
| Tier-1 platform budget exhausted | 503 | `{ error: 'AI explainer temporarily paused — daily limit', narrative: null }` |

---

## RBAC + Tenant Scoping

For every route handler, implementer MUST follow this verified-keys-only pattern:

| Route | Permission key (verified active) | Owner/admin auto-grant | Tenant filter |
|---|---|---|---|
| `GET …/malicious-findings` | `checkProjectAccess` | yes (via helper) | `eq('project_id', projectId).eq('organization_id', orgId)` |
| `GET …/malicious-findings/:findingId` | `checkProjectAccess` | yes | + verify `finding.project_id=:projectId` defense-in-depth |
| `PATCH …/malicious-findings/:findingId` | `checkProjectManagePermission` (`manage_projects` OR `manage_teams_and_projects`) | yes | + verify `finding.project_id=:projectId` |
| `POST …/malicious-findings/:findingId/explain` | `checkProjectAccess` | yes | + per-org rate limit + per-user rate limit |
| `POST /api/internal/malicious/feed-sync/:source` | `INTERNAL_API_KEY` | N/A | N/A (writes to global table) |
| `POST /api/internal/malicious/staleness-watchdog` | `INTERNAL_API_KEY` | N/A | N/A (read-only watchdog) |

**No new permission keys introduced.** All gates use existing `organizationsHelpers.checkOrgPermission(...)` / `checkProjectAccess(...)` / `checkProjectManagePermission(...)` helpers (verified active in `organizations.ts` and `projects.ts`). All POST/DELETE handlers MUST verify `organization_members` membership against `:id` URL param BEFORE any DB read or write, and MUST write `organization_id` from URL param ONLY (never from request body).

---

## Frontend Design

### Pages & routes

No new routes. Findings appear inside the existing project security view (project sidebar `vulnerabilities` sub-tab) via the existing `VulnerabilityExpandableTable` extended with a new `type: 'malicious'` row variant.

### Component tree

```
OrganizationOverviewPage
└── projectSidebar (when projectSidebarTab === 'vulnerabilities')
    └── VulnerabilityExpandableTable (extended)
        ├── SecurityTableRow (type: vuln | secret | semgrep | license — existing)
        ├── SecurityTableRow (type: 'malicious') — NEW
        │   └── MaliciousFindingCard (expanded content) — NEW
        │       ├── Severity badge + scanner badge ('feed' | 'guarddog')
        │       ├── Reason text (from finding.message)
        │       ├── Code snippet panel (if guarddog with evidence — reuses existing pattern)
        │       ├── 'Explain this finding' button (NEW) — triggers POST .../explain
        │       │   - Loading state: 'Generating explanation...' (shows cache miss)
        │       │   - Loaded: AI narrative section appears inline, with 'Cached' indicator if hit
        │       │   - Error: 'Explainer temporarily unavailable — try again later'
        │       │   - Rate-limited: 'Daily explainer limit reached'
        │       └── Action buttons: Suppress (with reason) / Accept Risk (with reason)
        └── EmptyMaliciousState (when no rows of type 'malicious') — NEW
            ├── Green check + "0 malicious packages detected"
            ├── "Scanned across 2 feeds (OSV + GHSA) + GuardDog v2.9.0"
            └── "Last scanned [run_id] at [timestamp]"
```

**Permission-driven rendering:**
- Finding card actions visible to all project members (read access).
- Suppress / Accept Risk buttons enabled only if user has `manage_projects` OR `manage_teams_and_projects`. Otherwise disabled with tooltip "Requires project-manage permission."

### Design specifications

Per `.cursor/skills/frontend-design/SKILL.md`:

- `MaliciousFindingCard` uses card pattern: `rounded-lg border border-border bg-background-card`. Inner sections divided by `border-t border-border`.
- Severity badges reuse `getIssueBadgeVariant` and existing severity tokens.
- "Explain this finding" button: `<Button variant="outline" size="sm">` with `Sparkles` icon (Lucide). Disabled state when budget exhausted.
- AI narrative section renders in `text-sm text-foreground-secondary` with `text-xs font-semibold uppercase tracking-wider` "Why this is malicious" header. "Cached • [date]" text-xs indicator below.

---

## Implementation Tasks

### Milestone 1 — Detection (~2 weeks)

**M1.1** — DB migration ⟦ M ⟧
- File: `backend/database/malicious_packages_v1.sql` (full SQL above).
- Apply via Supabase MCP. Run `cd backend/extraction-worker && npm run schema:dump`.
- Acceptance: tables exist; trigger enforces org consistency; legacy `dependencies_new_name_key` dropped; both RPCs callable; CI schema-check passes.

**M1.2** — Types + severity mapping + ecosystem normalization ⟦ S ⟧
- Files: `backend/src/lib/malicious/types.ts`, `backend/src/lib/malicious/severity.ts`, `backend/src/lib/malicious/ecosystem.ts`.
- Severity mapping (3 effective levels, schema CHECK stays 5-wide for forward compat):
  - feed match → `critical`
  - GuardDog ERROR → `high`
  - GuardDog WARNING → `medium`
- Ecosystem normalization: parameterized helper canonicalizing OSV `'PyPI'`/`'npm'`, GHSA uppercase, GuardDog lowercase → canonical lowercase per CHECK constraint.
- Acceptance: severity mapping unit-tested; ecosystem normalization parameterized over 6+ source-casing combinations.

**M1.3** — Tier-1 platform-AI cost-cap gate (prerequisite) ⟦ S ⟧
- File: `backend/src/lib/ai/platform-cost-cap.ts`.
- Redis token bucket keyed `ai:platform:cost:YYYY-MM` and `ai:platform:feature:malicious_explainer:YYYY-MM-DD`.
- Per-feature limits config: `{ malicious_explainer: { daily_calls: 5000, monthly_cost_usd: 50 } }`.
- Public function `checkPlatformAiBudget(feature, estimatedCostUsd)` returns `{ allowed: boolean, reason?: string }`.
- Acceptance: budget exhaustion test returns `{ allowed: false }`; counter increments on success path; expiry cleanup works.

**M1.4** — Public + internal HTTP routes ⟦ M ⟧
- File: `backend/src/routes/malicious.ts`. Mount in `backend/src/index.ts`.
- Routes per API table above. Mirror semgrep-findings list query pattern (`projects.ts:9520`).
- All public routes call `checkProjectAccess` / `checkProjectManagePermission` BEFORE DB access; all writes use `organization_id` from URL param ONLY.
- Acceptance: route tests cover (i) cross-org 403 (user-in-orgA → 403 on orgB URL); (ii) project-not-in-org 403; (iii) PATCH without manage permission 403; (iv) finding-id-from-different-project 404.

**M1.5** — GuardDog Dockerfile pin (Python venv isolated) ⟦ S ⟧
- File: `backend/extraction-worker/Dockerfile`.
- Add: `RUN python3 -m venv /opt/guarddog-venv && /opt/guarddog-venv/bin/pip install --no-cache-dir guarddog==2.9.0 && /opt/guarddog-venv/bin/guarddog --version`.
- Worker invokes `/opt/guarddog-venv/bin/guarddog` explicitly.
- Acceptance: `docker build` succeeds; venv-isolated guarddog reports v2.9.0; semgrep/depscan version pins unchanged in main `pip3 list` (drift CI test).

**M1.6** — Worker pipeline step + tarball cache + sandbox ⟦ L ⟧
- Files: `backend/extraction-worker/src/malicious-scan.ts`, `backend/extraction-worker/src/malicious/{guarddog,feeds,tarball-cache,insert-finding}.ts`.
- Insert step in `pipeline.ts` after tree-sitter, before Semgrep.
- Step body:
  1. `checkCancelled()` at entry; loop also checks before claiming next package.
  2. For each (package, version, ecosystem): canonicalize ecosystem; lookup `known_malicious_packages` via `feeds.ts` (feed match → record finding immediately).
  3. Cache miss: download tarball via `tarball-cache.ts` (pacote `--ignore-scripts` / pip download `--no-deps`) into per-job ephemeral `/tmp/<jobid>/<package>-<version>/`; reject zip-slip (entry path escapes root) and decompression bombs (>500MB or ratio >100:1) before extract.
  4. Run `/opt/guarddog-venv/bin/guarddog <ecosystem> scan --json --no-exec <dir>`; parse output; persist to `package_security_cache` via UPSERT.
  5. Filter findings against severity threshold; build finding rows (with org+project+project_dependency_id resolved from current job context).
  6. Heartbeat every 30s during scan; concurrency-pool worker checks `checkCancelled` before claiming next package.
  7. **Soft-fail mode (Patch 3):** per-package error caught → write to `extraction_step_errors` with severity `'warn'`, mark package as scan-failed, continue. Compute `scan_status`: `'complete'` (0 failures) | `'partial'` (1 ≤ failures < 100%) | `'failed'` (100% failures). If `'failed'`, throw — extraction job marked failed (clear infrastructure outage).
  8. Post-loop: call `insert_malicious_findings_with_recompute(p_findings)` RPC atomically; emit one batched `malicious_package_detected` event with all finding IDs (NOT one event per finding — see M1.10).
- Tarball-cache module: per-job ephemeral; Fly machine recycled on job completion; subprocess uid isolation if available; outbound network restricted from extraction subprocess where Fly egress firewall supports.
- Per-package timeout 60s. Step total budget 5 min. Concurrency 8.
- Acceptance: full extraction on `deptex-test-npm` produces findings; cache populated; second run hits cache (≥95% hit rate target); soft-fail on injected package error preserves other findings; zip-slip fixture rejected; cancellation mid-scan releases worker within 5s.

**M1.7** — Feed-sync (synchronous, single-source v1) ⟦ S ⟧
- File: `backend/src/lib/malicious/feed-sync.ts`.
- Single QStash daily cron POSTs `/api/internal/malicious/feed-sync/osv` and `/api/internal/malicious/feed-sync/ghsa` (chained, via QStash workflow — full chained design lands in M2.1).
- Per source: paginate, upsert into `known_malicious_packages` (canonical lowercase ecosystem); record run state in `malicious_feed_sync_runs`.
- v1: single-shot synchronous handler if both sources fit under 2-min QStash invocation timeout. If timing requires it, M2.1 promotes to checkpointed workflow.
- Acceptance: cron run produces new rows; idempotent across runs (UNIQUE on `(source, source_id)`); withdrawn entries marked.

**M1.8** — Frontend types + table extension ⟦ M ⟧
- Files: `frontend/src/lib/api.ts`, `frontend/src/components/security/VulnerabilityExpandableTable.tsx`, `frontend/src/components/security/MaliciousFindingCard.tsx`, `frontend/src/components/security/EmptyMaliciousState.tsx`.
- Add `MaliciousFinding` type + `api.maliciousFindings.{list,get,updateStatus,explain}` methods.
- Extend `SecurityTableRow` union with `type: 'malicious'`; update every `switch (row.type)` site (TypeIcon, getRowTitle, severity sort, expand-content dispatch, filter chip mapping).
- `MaliciousFindingCard`: severity badge + scanner badge + reason + code snippet (if guarddog with evidence) + Explain button (initially "Click to generate" / "Cached" / "Generating..." states) + Suppress + Accept Risk action buttons.
- Permission-aware rendering: Suppress/Accept Risk disabled with tooltip when user lacks `manage_projects`/`manage_teams_and_projects`.
- `EmptyMaliciousState`: green check + feed list + scanner version + last-scan timestamp.
- Acceptance: existing security tab renders malicious rows alongside vulns/secrets/semgrep; expand-on-click works; Explain button triggers POST and renders narrative; suppress/accept-risk persist; empty state renders cleanly.

**M1.9** — Project security summary integration ⟦ S ⟧
- File: `backend/src/routes/projects.ts`.
- Add malicious findings count to project security summary aggregation (analogous to existing semgrep+secret rollup).
- Acceptance: existing project sidebar summary shows total malicious count.

**M1.10** — Event emission + dedup ⟦ S ⟧
- Inside `malicious-scan.ts`: post-loop, emit ONE batched `malicious_package_detected` event with all newly-inserted finding IDs.
- `deduplicationKey = sha256(orgId || project_id || extraction_run_id)` — one event per (org, project, extraction run) at most. Re-extraction with same findings deduplicates.
- Already pre-registered as critical event type in `event-bus.ts:27`.
- Acceptance: second extraction of same project with same findings → ZERO new events; new finding in re-extraction → ONE event with the new finding ID.

**M1.11** — Soft-fail UI banner ⟦ S ⟧
- Frontend: when `extraction_runs.scan_status` (or equivalent extraction-run-level malicious-scan status) is `'partial'`, render banner above security tab: "Scan ran with N% coverage gap — N packages not scanned. View extraction step errors."
- Acceptance: simulated 5% scan failures → banner renders; 0% → no banner; 100% → extraction marked failed (no banner needed because the extraction-failed UI already shows).

**M1.12** — Smoke benchmark (throwaway script) ⟦ S ⟧
- File: `scripts/bench-malicious-once.ts`.
- Loads 50-sample fixture from Datadog malicious-packages-dataset (manifest sha256-pinned, gitignored fixture dir).
- Runs malicious-scan in test mode, prints detection rate.
- Run once before merging M1; do NOT add to CI.
- Acceptance: detection rate measured + recorded in PR description.

---

### Milestone 2 — Continuous-light + AI Explain (~1 week)

**M2.1** — Chained QStash feed-sync workflow + staleness watchdog ⟦ M ⟧
- File: `backend/src/lib/malicious/staleness-watchdog.ts` + workflow in `feed-sync.ts`.
- Promote M1.7 to chained QStash workflow if needed: feed-sync handler chains to per-source steps via QStash publish; each step paginated with checkpoint cursor in `malicious_feed_sync_runs`; heartbeat updated_at every 60s; on success, chain to next source; on failure, mark state and stop.
- Independent watchdog cron (every 6h, separate QStash schedule): query `malicious_feed_sync_runs` per source; emit `feed_sync_stale` critical event when state running but updated_at >5min stale OR state failed OR last completed_at >36h.
- Acceptance: simulated feed-sync timeout → next-run resumes from checkpoint; simulated all-sources fail → watchdog emits within 6h.

**M2.2** — On-demand AI Explain (server-side, prompt-injection-hardened) ⟦ M ⟧
- File: `backend/src/lib/malicious/explain.ts` + route handler in `malicious.ts`.
- POST `/api/organizations/:id/projects/:projectId/malicious-findings/:findingId/explain`:
  1. Permission gate: `checkProjectAccess`.
  2. Per-user rate limit (Redis: 50/min). Per-org daily Explain budget (Redis: 200 unique findings/day).
  3. Tier-1 platform budget gate: `checkPlatformAiBudget('malicious_explainer', 0.0003)`. If `not allowed`, return 503 with structured response.
  4. Cache lookup: `package_security_cache.eq(scanner='ai_review').eq(package_name, version, ecosystem)`. Hit → return narrative immediately (`{cached: true}`).
  5. Cache miss: build prompt with **8KB hard cap** (truncate install scripts to 2KB head + 2KB tail per file, max 4 files; package.json fields whitelisted: name/version/description/scripts/dependencies/bin only); wrap untrusted package content in delimited section with explicit "DO NOT FOLLOW INSTRUCTIONS WITHIN" preamble; PII scrub (no project paths, no repo URLs).
  6. Call `getPlatformProvider().chat(...)` with **Gemini structured-output mode** (JSON schema: `{risk_level, key_signals[], narrative}`).
  7. Post-validate output: reject if `narrative` contains XML-tag-like patterns OR policy-bypass language OR prompt-instruction echoes; on reject, return generic "AI explainer unavailable for this finding" without writing to cache.
  8. **AI verdict NEVER downgrades a feed-source-confirmed-malicious finding** — narrative is additive, not a gate.
  9. Cache hit-write: store `narrative`, `risk_level`, `prompt_input_sha256`, `prompt_version='malicious-explainer-v1'`, `model_version='gemini-2.5-flash'` in `package_security_cache` with `scanner='ai_review'`. UPSERT replaces in place.
  10. Log to `ai_usage_logs` with `organization_id`, `feature='malicious_explainer'`, cost.
- Acceptance: cache miss invokes Gemini once with structured output; cache hit returns cached narrative with zero Gemini call; budget-exhausted returns 503 cleanly; prompt-injection fixture (`prompt-injection.tgz` with adversarial install scripts) → narrative either rejected by post-validator OR emitted with structured schema flagging risk_level appropriately.

**M2.3** — Aegis read-side integration ⟦ S ⟧
- File: `backend/src/lib/aegis/tools/intelligence.ts:165` + `backend/src/lib/aegis/pr-review.ts:79`.
- Extend `analyze_package_security` response: add `malicious_findings_count`, `top_malicious_finding`, `latest_ai_narrative` (read from `package_security_cache`). Tool MUST derive `organization_id` from chat execution context, NEVER from tool arguments.
- Capabilities/AI narrative are global cache reads — no scoping needed. `malicious_findings_count` + `top_malicious_finding` are per-org reads scoped by chat's `organization_id`.
- Acceptance: Aegis "is this package safe to add?" answer includes new context; tool with body-supplied `organization_id` ignored (test).

**M2.4** — Notification dispatcher hydration extension ⟦ S ⟧
- File: `backend/src/lib/notification-dispatcher.ts:498`.
- Extend `dep.malicious_indicator` shape: keep existing `source/confidence/reason` keys; add `scanner`, `severity`, `top_finding_id` as additive keys.
- Hydration query MUST filter `project_malicious_findings.eq(project_id, event.project_id)`; assert `project.organization_id == event.organization_id` defense-in-depth; drop event with tenant-mismatch log if assertion fails.
- Acceptance: snapshot test on dependency context shape (additive only); legacy trigger code reading `dep.malicious_indicator.reason` still resolves; two-org integration test (Org A and Org B both have findings; event for Org A → dispatched payload contains zero references to Org B).

**M2.5** — Documentation note in DEVELOPERS.md ⟦ S ⟧
- One-paragraph addition explaining the new pipeline step + GuardDog binary requirement + worker venv pattern.
- Acceptance: review-pass only; no content-heavy docs (per `feedback_docs_content` memory).

---

## Testing & Validation Strategy

### Backend tests

**Tenant-isolation suite** (`backend/src/__tests__/malicious-tenant-isolation.test.ts`):
- User-in-org-A → 403 on org-B's `/malicious-findings` list.
- User-in-org-A → 403 on org-B's `/malicious-findings/:id` GET.
- User-in-org-A → 403 on PATCH against org-B finding ID.
- User-in-org-A → 403 on Explain endpoint with org-B URL even with valid org-A finding ID in body.
- Two-org integration: notification dispatcher event for Org A → dispatched payload contains zero Org B references.

**RBAC suite** (`backend/src/__tests__/malicious-rbac.test.ts`):
- Owner → 200 on Suppress/Accept-Risk PATCH.
- Admin with `manage_teams_and_projects` → 200.
- Member without `manage_projects` → 403.
- Anonymous → 401.
- Helper-import test: `malicious.ts` imports `checkProjectAccess` and `checkProjectManagePermission` from same source as semgrep route (catches future drift).

**AI Explain suite** (`backend/src/lib/malicious/__tests__/explain.test.ts`):
- Cache miss invokes Gemini exactly once.
- Cache hit returns narrative with zero Gemini call.
- Budget exhaustion (`checkPlatformAiBudget` → not allowed) returns 503 cleanly.
- Per-user rate limit (51st call/min) returns 429.
- Per-org daily budget (201st unique finding/day) returns 429.
- Prompt-injection fixture (`prompt-injection.tgz` with adversarial install scripts) → narrative rejected by post-validator OR risk_level not downgraded.
- 8KB byte-cap test: 50MB obfuscated install script → input truncated, total prompt bytes ≤8192, `truncated=true` flag in `ai_usage_logs.context_type`.
- Cost-cap integration: 100 simulated calls → counter caps at configured limit.

**Feed-sync suite** (`backend/src/lib/malicious/__tests__/feed-sync.test.ts`):
- Idempotent across runs (re-run produces zero duplicates).
- Withdrawn entries marked correctly.
- Concurrent invocation: parallel runs do not double-insert (UNIQUE catches).
- Ecosystem normalization: parameterized over (osv, 'PyPI'), (osv, 'npm'), (ghsa, 'PIP'), etc., asserting all → canonical lowercase.
- Watchdog: all sources fresh → no event; one source >36h stale → critical event; all sources stale → single aggregated event (not N events).

**Worker tests** (`backend/extraction-worker/src/__tests__/malicious-scan.test.ts`):
- Cache hit/miss flow.
- Soft-fail behavior: 5% scan failures → step completes with `scan_status='partial'`, no exception thrown.
- 100% scan failures → throws, extraction marked failed.
- Cancellation propagation: `checkCancelled` returns true mid-loop → step exits within 5s, no further package claims.
- Heartbeat extension: 90s package doesn't trigger stuck-job recovery.
- Concurrent-extraction race: 2 simulated runs of same project → `is_malicious` lands at OR of both runs (not last-writer); UNIQUE prevents duplicate findings.
- Tarball sandbox: zip-slip fixture rejected; zip-bomb fixture (10MB → 1GB) aborted with size-cap error within budget; postinstall script not executed.
- Dockerfile drift CI: `pip3 list` between main image and PR image shows ONLY guarddog-venv changes.

**Migration suite** (`backend/src/__tests__/migrations/malicious_packages_v1.test.ts`):
- After migration: `dependencies(name='lodash', ecosystem='npm')` AND `dependencies(name='lodash', ecosystem='pypi')` both insert (legacy UNIQUE dropped).
- `recompute_dependency_is_malicious` correctly flags only matching ecosystem rows.
- Trigger rejects `project_malicious_findings` insert where `organization_id != projects.organization_id`.

### Frontend tests

`frontend/src/__tests__/malicious-finding-card.test.tsx`:
- Renders severity badge + reason + scanner badge.
- Explain button: cache hit shows "Cached" indicator; cache miss shows loading then narrative.
- Permission rendering: admin sees Suppress + Accept Risk buttons enabled; member sees them disabled with tooltip.
- Empty state renders with feed list + scanner version.

### Performance targets

- Findings list endpoint: <200ms p50 at 50 findings/page.
- Extraction added latency: +1-2 min p50 / +5 min p95 on dogfood projects (steady state, mostly cache hits).
- AI cost: <$30/year platform-wide at expected pre-launch volume; per-org budget caps at $50/month even if abused.
- Cache hit rate: ≥95% steady-state once popular packages cached (measure via `package_security_cache` cache_hits/misses telemetry).

### Smoke benchmark

- Run `scripts/bench-malicious-once.ts` against curated 50-sample fixture from Datadog malicious-packages-dataset before M1 merge; record detection rate in PR description.
- Top-100 npm + top-100 PyPI snapshot fetched once and committed: assert ZERO findings on these packages (FP gate).

### Regression checks

- Existing semgrep/secret findings continue to render in `VulnerabilityExpandableTable` after `type: 'malicious'` extension.
- Existing `dependencies.is_malicious` flag continues to flow through depscore + Aegis correctly (golden test on `analyze_package_security` output).
- `notification-dispatcher.ts` shape: snapshot test asserts additions to `malicious_indicator` are additive only (legacy keys preserved).

---

## Risks & Open Questions

### Technical risks

- **Tarball download reliability for niche ecosystems.** Go and Ruby package source download patterns are less battle-tested than npm/PyPI in pacote/pip. Soft-fail design lets us measure first-encounter failure rates per ecosystem in production and tune retry/fallback later.
- **OSV.dev availability** — single point of failure for feed lookup. Watchdog (M2.1) catches >36h stale; in-pipeline graceful degrades to GHSA-only lookup if OSV cache miss.
- **Tarball cache subprocess RCE surface.** GuardDog runs Semgrep+YARA against untrusted source. Pacote `--ignore-scripts` + decompression bounds + per-job ephemeral tempdir + `guarddog --no-exec` make code execution unlikely but not impossible. v1 accepts residual risk with documented sandbox boundary; v1.1 considers Fly Machine recycling per job (already partially the case via scale-to-zero).

### Production risk surface

- **First-extraction onboarding latency.** Cold-cache org with 300+ first-encounter packages × ~5s/scan = ~25-30 min added to initial extraction. Mitigation: deferred-malicious-scan mode (defer to v1.1) where first extraction emits feed-only findings synchronously and queues GuardDog scan as separate QStash job. v1 ships with synchronous scan; if onboarding latency >10min observed in dogfood, promote deferred mode to v1.1 priority.
- **Tier-1 budget exhaustion under abuse.** `checkPlatformAiBudget` caps Tier-1 spend; runaway abuse (someone scripting Explain clicks) returns 503 cleanly. Per-user rate limit (50/min) bounds.
- **AGPL contamination.** Mitigated by exclusion: v1 ships with OSV + GHSA only. No Aikido Intel until legal artifact verification.

### Design decisions needing user input

1. **Capability tag set v1 — N/A** (M3 cut from v1).
2. **Severity mapping precise thresholds** — proposed in M1.2: feed→critical, GuardDog ERROR→high, GuardDog WARNING→medium. Confirm.
3. **GuardDog rule disable mechanism** — if FP found on top-100 npm/PyPI before launch, options: (a) maintain a `--exclude-rule` flag in worker code with FP rule list (hardcoded); (b) `deptex_guarddog_disabled_rules` org-scoped table consulted at scan time. v1 ships with (a) (simplest); promote to (b) when first FP requires per-org granularity.
4. **Allowlist version semantics — N/A** (allowlist cut).
5. **AI Explain rate limits** — proposed: 50/min per user, 200/day per org for unique findings. Tunable via env. Confirm initial limits.

---

## Dependencies

**Already shipped (we leverage):**
- Tree-sitter extraction (`backend/extraction-worker/src/tree-sitter-extractor/`) — reused by capability detection in v1.1, NOT in v1.
- Platform AI provider (`backend/src/lib/ai/provider.ts:getPlatformProvider`) — accessed only from BACKEND in v1 (Explain endpoint), NOT from worker.
- `ai_usage_logs` table for cost telemetry.
- Event bus + `malicious_package_detected` already-registered critical type (`event-bus.ts:27`).
- Notification dispatcher (`notification-dispatcher.ts:498` already references `is_malicious`).
- Existing `withTimeout()`, `binaryAvailable()`, `INSTALL_HINTS`, `logStepError()`, `extraction_step_errors`.
- `VulnerabilityExpandableTable` + `SecurityTableRow` discriminated union on field `type:`.
- `PackageOverview` drawer (already shows `is_malicious` badge).
- `organizationsHelpers.checkOrgPermission`, `checkProjectAccess`, `checkProjectManagePermission` helpers.

**Built in this plan as prerequisite:**
- `backend/src/lib/ai/platform-cost-cap.ts` (M1.3) — Tier-1 platform-spend gate.

**External:**
- GuardDog v2.9.0 (Apache-2.0) — pip-installed into `/opt/guarddog-venv`.
- OSV.dev API (free, public).
- GitHub Advisory Database via existing GHSA query path.

**Not depended on (deferred to v1.1+):**
- Aikido Intel feed (pending legal artifact verification).
- Datadog malicious-packages dataset as live feed (kept as smoke-benchmark fixture only).
- `project_policy_exceptions` extension for malicious allowlist (when allowlist need surfaces post-launch).

---

## Success Criteria

v1 is "done" when **all** are true:

1. **Detection ≥80%** on a 50-sample subset of Datadog malicious-package dataset, measured by `scripts/bench-malicious-once.ts` once before M1 merge. (Lower target than original 90% because v1 ships with feed lookup + GuardDog only — the AI overlay is on-demand and doesn't contribute to detection rate.)
2. **Zero false positives** on top-100 npm + top-100 PyPI most-downloaded packages (committed snapshot fixture), measured by the same harness.
3. **Extraction p50 latency adds <2 min** on dogfood projects with cache warm, measured over the week post-launch via existing extraction telemetry.
4. **Cross-tenant route tests all pass** — every entry in the M1.4 tenant-isolation suite green.

Aegis tool integration (M2.3) and notification dispatcher hydration (M2.4) are required for v1 completeness but not gating success metrics.

---

## Recommended Next Step

Open `worktree-malicious-packages` worktree. Apply M1.1 migration via Supabase MCP. Walk through M1.2-M1.12 in order; the chain (M1.1 schema → M1.2 types → M1.3 cost-cap gate → M1.4 routes with tests → M1.5 Dockerfile → M1.6 worker → M1.7 feed-sync → M1.8 frontend → M1.9 summary → M1.10 events → M1.11 banner → M1.12 smoke) is independently shippable per task; merge M1 to main after dogfood pass before starting M2.

---

## Cuts from this plan (deferred to v1.1+)

Documented here so the deferred set is explicit and can be re-prioritized after v1 ships:

- **Capability detection** (was M3): tree-sitter pass producing capability tags; UI badges; capability filter chips on dependencies table.
- **Org-wide allowlist** (was M1.6 + dedicated table + 3 routes): new table OR project_policy_exceptions extension; retroactive resolve; preview/undo flow; audit table; permission gate.
- **Rescan-existing cron** (was M4.2): per-org-grouped iteration over feed-delta × dep-prevalence; aggregate burst events; checkpoint table; claim/heartbeat pattern.
- **Org rollup card** (was M4.6): MaliciousPackagesRollupCard with severity breakdown / top 5 projects / 24h trend; "View all" inline table.
- **Default notification trigger templates** (was M4.4): seed migration with critical-malicious → org-admin Slack template.
- **Aegis Quarantine Agent** (was deferred originally): auto-PR remove + suggest alternative; project_security_fixes integration via the malicious_finding_id column added in M1.1 stays unused in v1 but ready for v1.1+.
- **Reachability filtering of malicious findings** (Endor-tier): re-points Phase 5/6 reachability at malicious sinks. Depends on Phase 5/6 settling.
- **Aikido Intel feed source**: pending legal artifact verification.
- **Public threat-intel feed publication** (`/feed/malicious/recent.json`): pending threat-model + abuse-policy doc.
- **Maintained CI benchmark harness with hold-out corpus**: replace M1.12 throwaway script.
- **Full capability-as-filter UI**.
- **IOC fields on `known_malicious_packages`** (exfil_url, c2_domain, etc.).
- **Retention pruner cron** for `project_malicious_findings`.
- **Deferred-malicious-scan mode for cold-start onboarding** (if v1 onboarding latency >10min observed in dogfood).
