# Reachability-Coupled DAST — Implementation Plan (v3 unified-jobs)

## Overview

Add Dynamic Application Security Testing (DAST) as a fourth signal in the unified Security tab and use Deptex's tree-sitter handler map to mark DAST hits with linked SCA findings (Confirmed Exploitable badge) when they share an entry-point handler. MVP ships ZAP-only, anon-scan, user-provided URL, manual trigger.

**Architecture:** single worker, single job table.
- Worker `extraction-worker` is renamed to `depscanner` (reflects broader scope).
- Job table `extraction_jobs` is renamed to `scan_jobs` with a `type TEXT` discriminator (`'extraction' | 'dast'` in v1; extensible to `'malicious_pkg' | 'iac' | 'container'` later as 1-line CHECK constraint updates).
- One `claim_scan_job(machine_id, supported_types TEXT[])` RPC, one `queue_scan_job(...)`, one recovery RPC pair, one Realtime channel. Single shared heartbeat regardless of job type.
- Worker poll loop makes ONE claim call per iteration with `supported_types=['extraction','dast']`; dispatches to extraction-pipeline or dast-pipeline based on `job.type`.
- Machine sizing differs per job type via Fly Machines API at start: `performance-8x` 65GB for extraction jobs, `shared-cpu-4x` 8GB for DAST jobs. Same Fly app `deptex-depscanner`, different machine configs picked at start time.

This v3 of the plan post-dates the `/review-plan` round (`.cursor/plans/review-dast.md`). It folds in the consensus non-architectural fixes AND consolidates the worker/table architecture: `spawn` not `execSync`, atomic-commit semantics, stable-identity cross-link FKs, SAST cross-link cut from v1, SSRF validation at three layers, RLS preserved on rename, Aegis tool deferred to phase 2, Confirmed Exploitable badge in v1 (card deferred), 15+ phase-2 columns stripped from v1 schema, status enum aligned with `extraction_jobs` convention, frontend split into 3 PRs.

References: brief at `.cursor/plans/feature-brief-dast.md`, research at `.cursor/plans/research-dast.md`, review at `.cursor/plans/review-dast.md`.

## Competitive Research & Design Rationale

Full detail in `research-dast.md`. v1 differentiator: the **stable-identity cross-link from DAST hits to SCA findings via `project_reachable_flows.entry_point_*`**. Snyk's Code-Informed Dynamic Testing (April 2025) gestures at this; nobody has shipped it cleanly. SAST cross-link is deferred to v2 because `project_semgrep_findings` doesn't yet store `containing_function_name` — without it, line-window heuristics over-merge.

Engine: OWASP ZAP. Mature browser-auth, automation API, Docker, March 2026 MCP server. Single tool fits the simplicity bias; Nuclei deferred to phase 2.

Scan profile routing: when `project_entry_points` has API routes for the project, run ZAP `api-scan.py` with a synthesized OpenAPI stub from those routes. Otherwise `full-scan.py` against the URL. No user-facing config in v1.

## Codebase Analysis

### Three corrections to the brief, folded in

1. **`project_entry_points` already exists** (migration `phase20_entry_points.sql`). It is the table the brief proposed creating as `project_routes`. Already populated by `storeEntryPoints()` in `backend/extraction-worker/src/framework-rules/storage.ts:11-59` during the existing `framework_detection` step. **No new route-materialization migration needed.** DAST cross-link joins against this table directly.
2. **Job-table column conventions:** `machine_id` / `heartbeat_at` / `started_at`. Status enum `queued|processing|completed|failed|cancelled` (no `'timeout'` — use `error_category='timeout'` per project_security_fixes precedent). Single `error TEXT` column (not `error_message`).
3. **Encrypted credentials** would store as TEXT in format `nonce_b64:ciphertext_b64:authTag_b64` per `encryptApiKey` in `backend/src/lib/ai/encryption.ts`. (Phase 2 only — encrypted_credentials columns are NOT in v1 schema per scope strip.)

### Architectural shape — single-worker single-table

Henry's locked direction: keep one worker, broaden its scope; keep one job table, add `type` discriminator. The architectural rationale:

- **DAST is a Node-based subprocess invocation** (Node spawns ZAP), structurally identical to extraction's existing subprocess pattern (Node spawns cdxgen/dep-scan/Semgrep/TruffleHog/tree-sitter). Aider's runtime is genuinely different (Python + Aider runtime + git-PR creation); aider keeps its own table. DAST does not.
- **Unified logs are operationally valuable.** One Fly app means one log stream, one set of metrics, one pool to monitor. As the worker grows to handle malicious-package + IaC + container scanning, the job table also grows by adding type values, not by spawning sibling tables.
- **One claim RPC** with `supported_types TEXT[]` is one round-trip per poll. Workers self-declare which types they handle; later a specialized worker (e.g. ZAP-only fly machine pool) can call `claim_scan_job(id, ['dast'])` exclusively.
- **Image bloat** (ZAP ~1.5GB on top of ~2GB extraction image, total ~3.5GB) is manageable. Fly scale-to-zero pools keep machines stopped (not destroyed), so the image is cached on the host between starts. Cold-start = machine boot (seconds), not image pull.
- **Different machine sizing per job type** is supported by Fly Machines API: extraction jobs start `performance-8x` 65GB machines; DAST jobs start `shared-cpu-4x` 8GB machines. Same Fly app, different machine configs picked at start time.

### Key existing surfaces

| Surface | Location | Notes |
|---|---|---|
| Worker entry | `backend/extraction-worker/src/index.ts` (`runWorker()`) | 60s heartbeat via `setInterval`. To be moved to `backend/depscanner/`. |
| Job claim RPC | `claim_extraction_job(p_machine_id)` in `backend/database/extraction_jobs_schema.sql:39-55` | Replaced by `claim_scan_job(p_machine_id, p_supported_types TEXT[])`. |
| Job table | `extraction_jobs` | Renamed to `scan_jobs`. RLS preserved on rename. |
| Pipeline | `backend/extraction-worker/src/pipeline.ts` | Existing extraction pipeline runs unchanged when `job.type='extraction'`. New DAST pipeline runs when `job.type='dast'`. |
| Framework detection | `backend/extraction-worker/src/framework-rules/registry.ts` + `storage.ts` | Emits `EntryPoint[]`, persists to `project_entry_points`. DAST cross-link reads this table filtered by `projects.active_extraction_run_id`. |
| Existing finding tables | `phase6_security_tables.sql`, `project_dependency_vulnerabilities_schema.sql`, `phase6b_reachability_tables.sql` | `project_reachable_flows.entry_point_file/method/line` is the SCA cross-link key. |
| Atomic commit | `projects.active_extraction_run_id` (TEXT) + `commit_extraction` RPC | Mirror with `projects.active_dast_run_id` (TEXT) + new `commit_dast_run` RPC. |
| Aider-worker | `backend/aider-worker/`, `project_security_fixes` table | Stays separate (different runtime: Python + Aider + git-PR). Not consolidated. |
| Fly machines | `backend/src/lib/fly-machines.ts` | `startFlyMachine(config)` + `EXTRACTION_CONFIG` (performance-8x, 65GB) + `AIDER_CONFIG`. Add `DAST_CONFIG` (shared-cpu-4x, 8GB). EXTRACTION_CONFIG and DAST_CONFIG both point to Fly app `deptex-depscanner`. |
| RBAC permission helper | `checkProjectManagePermission()` in `backend/src/routes/projects.ts:576-615` | Reuse for DAST writes. No new helper, no new permission. |
| Phase 19 RPCs | `commit_extraction`, orphan reaper | Reference `extraction_jobs` by name internally; RPC text needs updating in the same migration that renames the table. |
| Realtime hook pattern | `frontend/src/hooks/useRealtimeStatus.ts` | Subscribe filtered by project_id + 5s polling fallback. RLS enforces tenant scope server-side. |

## Data Model

### 1. `scan_jobs_consolidation.sql` — rename + add type + DAST columns + replace RPCs

This is the load-bearing migration. It does the table rename, adds the `type` column with backfill, adds DAST-specific sparse columns, replaces `claim_extraction_job` with `claim_scan_job`, and replaces `queue_extraction_job` (if used) with `queue_scan_job`. Recovery RPCs are also consolidated.

```sql
-- Rename the table.
ALTER TABLE extraction_jobs RENAME TO scan_jobs;

-- Add the type discriminator. v1 supports extraction + dast; extensible to malicious_pkg/iac/container later.
ALTER TABLE scan_jobs
  ADD COLUMN type TEXT NOT NULL DEFAULT 'extraction'
    CHECK (type IN ('extraction', 'dast'));

-- DAST-specific sparse columns (NULL for extraction-type rows).
ALTER TABLE scan_jobs
  ADD COLUMN target_url TEXT,
  ADD COLUMN scan_profile TEXT
    CHECK (scan_profile IS NULL OR scan_profile IN ('auto', 'quick', 'full', 'api')),
  ADD COLUMN timeout_minutes INTEGER,
  ADD COLUMN trigger_source TEXT
    CHECK (trigger_source IS NULL OR trigger_source IN ('manual', 'scheduled', 'on_extraction', 'aegis')),
  ADD COLUMN triggered_by UUID REFERENCES auth.users(id),
  ADD COLUMN error_category TEXT,
  ADD COLUMN findings_count INTEGER,
  ADD COLUMN duration_seconds INTEGER;

-- Type-aware invariants: DAST rows must have target_url + trigger_source; extraction rows must have repo info in payload.
ALTER TABLE scan_jobs
  ADD CONSTRAINT scan_jobs_dast_required CHECK (
    type <> 'dast' OR (target_url IS NOT NULL AND trigger_source IS NOT NULL AND scan_profile IS NOT NULL)
  );

-- Indexes (existing extraction indexes auto-renamed to scan_jobs_*; add new ones for type-aware queries).
CREATE INDEX IF NOT EXISTS idx_scan_jobs_type_queued ON scan_jobs(type, created_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_scan_jobs_org_type ON scan_jobs(organization_id, type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_recovery ON scan_jobs(type, heartbeat_at, attempts, max_attempts) WHERE status = 'processing';

-- Replace claim_extraction_job with claim_scan_job. Drop old RPC.
DROP FUNCTION IF EXISTS claim_extraction_job(TEXT);

CREATE OR REPLACE FUNCTION claim_scan_job(p_machine_id TEXT, p_supported_types TEXT[])
RETURNS SETOF scan_jobs
LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY
  WITH candidate AS (
    SELECT id FROM scan_jobs
    WHERE status = 'queued'
      AND type = ANY(p_supported_types)
    ORDER BY created_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  )
  UPDATE scan_jobs SET
    status = 'processing',
    machine_id = p_machine_id,
    started_at = NOW(),
    heartbeat_at = NOW(),
    attempts = attempts + 1
  FROM candidate
  WHERE scan_jobs.id = candidate.id
  RETURNING scan_jobs.*;
END;
$$;

-- queue_scan_job: type-aware, DAST path includes SSRF check + concurrency caps.
CREATE OR REPLACE FUNCTION queue_scan_job(
  p_type TEXT,
  p_project_id UUID,
  p_organization_id UUID,
  p_payload JSONB DEFAULT '{}'::jsonb,
  p_target_url TEXT DEFAULT NULL,
  p_scan_profile TEXT DEFAULT NULL,
  p_trigger_source TEXT DEFAULT NULL,
  p_triggered_by UUID DEFAULT NULL,
  p_timeout_minutes INTEGER DEFAULT NULL,
  p_max_attempts INTEGER DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql AS $$
DECLARE
  v_job_id UUID;
  v_org_count INTEGER;
  v_project_count INTEGER;
  v_max_attempts INTEGER;
BEGIN
  IF p_type = 'dast' THEN
    -- Defense-in-depth SSRF: blocked-host CHECK at the DB layer.
    IF p_target_url IS NULL OR p_target_url ~* '(^|//)(localhost|127\.|::1|169\.254\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)|\.internal($|/)|(^|//)\[?fdaa:|(^|/)(file|gopher|javascript):' THEN
      RAISE EXCEPTION 'blocked_target_url' USING ERRCODE = 'P0001';
    END IF;

    -- Org-level concurrency cap (mirroring queue_fix_job pattern).
    PERFORM 1 FROM organizations WHERE id = p_organization_id FOR UPDATE;
    SELECT COUNT(*) INTO v_org_count FROM scan_jobs
      WHERE organization_id = p_organization_id AND type = 'dast' AND status IN ('queued', 'processing');
    IF v_org_count >= 3 THEN
      RAISE EXCEPTION 'org_concurrent_dast_cap' USING ERRCODE = 'P0001';
    END IF;

    -- Per-project concurrency cap.
    SELECT COUNT(*) INTO v_project_count FROM scan_jobs
      WHERE project_id = p_project_id AND type = 'dast' AND status IN ('queued', 'processing');
    IF v_project_count > 0 THEN
      RAISE EXCEPTION 'project_concurrent_dast_blocked' USING ERRCODE = 'P0001';
    END IF;
  END IF;

  v_max_attempts := COALESCE(p_max_attempts, CASE WHEN p_type = 'dast' THEN 1 ELSE 3 END);

  INSERT INTO scan_jobs (
    type, project_id, organization_id, payload,
    target_url, scan_profile, trigger_source, triggered_by, timeout_minutes,
    max_attempts
  ) VALUES (
    p_type, p_project_id, p_organization_id, p_payload,
    p_target_url, p_scan_profile, p_trigger_source, p_triggered_by, p_timeout_minutes,
    v_max_attempts
  ) RETURNING id INTO v_job_id;

  RETURN v_job_id;
END;
$$;

-- Recovery RPCs: type-aware thresholds (extraction 5min, dast 32min = 30min timeout + 2min grace).
CREATE OR REPLACE FUNCTION recover_stuck_scan_jobs()
RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE v_recovered INTEGER;
BEGIN
  UPDATE scan_jobs SET
    status = 'queued', machine_id = NULL, started_at = NULL, heartbeat_at = NULL
  WHERE status = 'processing'
    AND attempts < max_attempts
    AND (
      (type = 'extraction' AND heartbeat_at < NOW() - INTERVAL '5 minutes')
      OR (type = 'dast' AND heartbeat_at < NOW() - INTERVAL '32 minutes')
    );
  GET DIAGNOSTICS v_recovered = ROW_COUNT;
  RETURN v_recovered;
END;
$$;

CREATE OR REPLACE FUNCTION fail_exhausted_scan_jobs()
RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE v_failed INTEGER;
BEGIN
  UPDATE scan_jobs SET
    status = 'failed', error = 'heartbeat_timeout', error_category = 'timeout', completed_at = NOW()
  WHERE status = 'processing'
    AND attempts >= max_attempts
    AND (
      (type = 'extraction' AND heartbeat_at < NOW() - INTERVAL '5 minutes')
      OR (type = 'dast' AND heartbeat_at < NOW() - INTERVAL '32 minutes')
    );
  GET DIAGNOSTICS v_failed = ROW_COUNT;
  RETURN v_failed;
END;
$$;

-- Drop the old extraction-only recovery RPCs if they exist.
DROP FUNCTION IF EXISTS recover_stuck_extraction_jobs();
DROP FUNCTION IF EXISTS fail_exhausted_extraction_jobs();
```

### 2. `phase19_rpc_rename.sql` — update Phase 19 RPCs to reference `scan_jobs`

Phase 19's `commit_extraction` RPC and the orphan reaper reference `extraction_jobs` by name in their function bodies. After the table rename, those RPCs must be redefined. Read the current RPC text (`backend/database/phase19_2_commit_extraction_rpc.sql`, `phase19_5_orphan_reaper.sql`) and recreate with `scan_jobs` substituted for `extraction_jobs`.

### 3. `project_dast_config.sql`

```sql
CREATE TABLE IF NOT EXISTS project_dast_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  enabled BOOLEAN NOT NULL DEFAULT false,
  target_url TEXT, -- v1: single. Phase 2 ALTERs to TEXT[] for multi-env.
  scan_profile TEXT NOT NULL DEFAULT 'auto' CHECK (scan_profile IN ('auto', 'quick', 'full', 'api')),
  scan_timeout_minutes INTEGER NOT NULL DEFAULT 30 CHECK (scan_timeout_minutes BETWEEN 5 AND 60),

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id)
);

CREATE INDEX IF NOT EXISTS idx_project_dast_config_org ON project_dast_config(organization_id);

ALTER TABLE project_dast_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY project_dast_config_org_select ON project_dast_config FOR SELECT
  USING (organization_id IN (SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()));
```

**Stripped from v1**: `target_urls TEXT[]`, `default_target_url`, `scan_engines TEXT[]`, `auth_strategy`, `encrypted_credentials`, `encryption_key_version`, `scan_on_extraction`, `scan_concurrent_max`. Phase 2 reintroduces.

### 4. `project_dast_findings.sql`

```sql
CREATE TABLE IF NOT EXISTS project_dast_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  dast_run_id TEXT NOT NULL,

  endpoint_url TEXT NOT NULL,
  http_method TEXT NOT NULL,
  vulnerability_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  cwe_id TEXT,
  owasp_top10_ref TEXT,
  rule_id TEXT,
  message TEXT,

  payload_redacted TEXT,
  response_evidence_redacted TEXT,
  confidence TEXT NOT NULL DEFAULT 'medium' CHECK (confidence IN ('confirmed', 'high', 'medium', 'low')),

  handler_file_path TEXT,
  handler_function_name TEXT,
  handler_line INTEGER,

  -- Stable-identity SCA cross-link (v1 ships SCA only; SAST cross-link deferred to v2).
  linked_sca_osv_id TEXT,
  linked_sca_project_dependency_id UUID REFERENCES project_dependencies(id) ON DELETE SET NULL,
  cross_link_metadata JSONB DEFAULT '{}'::jsonb,

  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'suppressed', 'risk_accepted', 'fixed')),
  risk_accepted_by UUID REFERENCES auth.users(id),
  risk_accepted_at TIMESTAMPTZ,
  risk_accepted_reason TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Atomic-commit pattern: UNIQUE includes dast_run_id; visibility gated by projects.active_dast_run_id.
CREATE UNIQUE INDEX project_dast_findings_resolved
  ON project_dast_findings(project_id, dast_run_id, rule_id, handler_file_path, handler_function_name, vulnerability_type)
  WHERE handler_file_path IS NOT NULL;

CREATE UNIQUE INDEX project_dast_findings_unresolved
  ON project_dast_findings(project_id, dast_run_id, rule_id, endpoint_url, http_method, vulnerability_type)
  WHERE handler_file_path IS NULL;

CREATE INDEX idx_project_dast_findings_run ON project_dast_findings(project_id, dast_run_id);
CREATE INDEX idx_project_dast_findings_org_severity ON project_dast_findings(organization_id, severity, status) WHERE status = 'open';
CREATE INDEX idx_project_dast_findings_handler ON project_dast_findings(project_id, handler_file_path, handler_function_name) WHERE handler_file_path IS NOT NULL;
CREATE INDEX idx_project_dast_findings_sca_link ON project_dast_findings(linked_sca_project_dependency_id) WHERE linked_sca_project_dependency_id IS NOT NULL;

ALTER TABLE project_dast_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY project_dast_findings_org_select ON project_dast_findings FOR SELECT
  USING (organization_id IN (SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()));

ALTER PUBLICATION supabase_realtime ADD TABLE project_dast_findings;
```

**Stripped from v1**: `linked_sast_*` columns (SAST cross-link cut from v1; phase 2 adds after `containing_function_name` lands on Semgrep findings). `suppressed BOOLEAN`, `risk_accepted BOOLEAN` — `status` enum is the single source of truth. `depscore` — no v1 writer.

### 5. `projects_active_dast_run.sql`

```sql
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS active_dast_run_id TEXT,
  ADD COLUMN IF NOT EXISTS previous_dast_run_id TEXT;

CREATE INDEX IF NOT EXISTS idx_projects_active_dast_run ON projects(active_dast_run_id) WHERE active_dast_run_id IS NOT NULL;
```

### 6. `commit_dast_run.sql`

```sql
CREATE OR REPLACE FUNCTION commit_dast_run(p_project_id UUID, p_dast_run_id TEXT)
RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE v_prior_run_id TEXT;
BEGIN
  SELECT active_dast_run_id INTO v_prior_run_id FROM projects WHERE id = p_project_id;

  -- Carry forward suppression / risk-accepted state by stable identity.
  IF v_prior_run_id IS NOT NULL THEN
    UPDATE project_dast_findings new
    SET status = old.status,
        risk_accepted_by = old.risk_accepted_by,
        risk_accepted_at = old.risk_accepted_at,
        risk_accepted_reason = old.risk_accepted_reason
    FROM project_dast_findings old
    WHERE new.project_id = p_project_id
      AND new.dast_run_id = p_dast_run_id
      AND old.project_id = p_project_id
      AND old.dast_run_id = v_prior_run_id
      AND old.rule_id = new.rule_id
      AND old.vulnerability_type = new.vulnerability_type
      AND ((old.handler_file_path IS NOT NULL AND new.handler_file_path IS NOT NULL
            AND old.handler_file_path = new.handler_file_path
            AND old.handler_function_name = new.handler_function_name)
           OR (old.handler_file_path IS NULL AND new.handler_file_path IS NULL
               AND old.endpoint_url = new.endpoint_url
               AND old.http_method = new.http_method))
      AND old.status <> 'open';
  END IF;

  -- Atomic pointer flip.
  UPDATE projects
  SET previous_dast_run_id = active_dast_run_id,
      active_dast_run_id = p_dast_run_id
  WHERE id = p_project_id;
END;
$$;
```

Stale-run reaping (deleting findings rows from `previous_dast_run_id` and earlier) follows the existing extraction-orphan-reaper pattern in a follow-up cron.

### Schema dump

After applying all migrations via Supabase MCP per `feedback_apply_migrations_via_mcp`, run `cd backend/depscanner && npm run schema:dump`. CI fails PRs that touch a migration without refreshing the dump.

## API Design

All under `authenticateUser` middleware. RBAC: reuse existing `checkProjectManagePermission`. No new permission helper.

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| GET | `/api/projects/:projectId/dast/config` | JWT | view (project member) | Read DAST config row |
| PUT | `/api/projects/:projectId/dast/config` | JWT | `manage_projects` | Upsert config (target URL, scan profile). URL via `validateExternalUrl()`. |
| POST | `/api/projects/:projectId/dast/scan` | JWT | `manage_projects` | Trigger scan. Calls `validateExternalUrl()` + `queue_scan_job(type='dast', ...)` + `startFlyMachine(DAST_CONFIG)`. Returns `{ jobId }`. |
| GET | `/api/projects/:projectId/dast/jobs` | JWT | view | Paginated DAST job history (filters `scan_jobs WHERE type='dast'`). |
| GET | `/api/projects/:projectId/dast/findings` | JWT | view | Paginated findings. Filters: severity, status, linked. Returns `confirmed_exploitable` boolean computed from `linked_sca_osv_id IS NOT NULL`. |

All routes in `backend/src/routes/dast.ts`, mounted in `backend/src/index.ts`.

### `validateExternalUrl()` helper

New file `backend/src/lib/url-guard.ts`:

```ts
export function validateExternalUrl(url: string): { valid: true } | { valid: false; reason: string };
```

Rejects: loopback, RFC1918, link-local, IMDS (169.254.169.254), Fly internal (`*.internal`, `fdaa::/16`), non-http(s) schemes. Resolves the hostname pre-validation (DNS-rebind defense). Three-layer enforcement: PUT /config, `queue_scan_job` plpgsql defense-in-depth, dast pipeline pre-flight in worker.

### Error cases

- 422 `invalid_target_url` from PUT /config or POST /scan
- 409 `project_concurrent_dast_blocked` or `org_concurrent_dast_cap` from POST /scan
- 403 from RBAC failures
- 404 from missing project / job

### TypeScript types

`backend/src/types/dast.ts`:

```ts
export type ScanJobStatus = 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled';
export type ScanJobType = 'extraction' | 'dast'; // extensible later
export type DastTriggerSource = 'manual' | 'scheduled' | 'on_extraction' | 'aegis';
export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';
export type DastSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DastFindingStatus = 'open' | 'suppressed' | 'risk_accepted' | 'fixed';

export interface DastConfigDTO {
  enabled: boolean;
  target_url: string | null;
  scan_profile: DastScanProfile;
  scan_timeout_minutes: number;
}

export interface DastJobDTO {
  id: string;
  status: ScanJobStatus;
  trigger_source: DastTriggerSource;
  target_url: string;
  scan_profile: DastScanProfile;
  findings_count: number | null;
  duration_seconds: number | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  error_category: string | null;
  created_at: string;
}

export interface DastFindingDTO {
  id: string;
  endpoint_url: string;
  http_method: string;
  vulnerability_type: string;
  severity: DastSeverity;
  cwe_id: string | null;
  message: string | null;
  payload_redacted: string | null;
  response_evidence_redacted: string | null;
  confidence: 'confirmed' | 'high' | 'medium' | 'low';
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  confirmed_exploitable: boolean;
  status: DastFindingStatus;
  created_at: string;
}
```

## Frontend Design

### Pages & Routes

No new top-level routes. Two existing pages get new content:

1. **Project Settings → "Scanning" tab** (new tab inside `ProjectSettingsContent`).
2. **Security tab** — new `<DastChip>` filter, last-scan strip, `<Badge>Confirmed Exploitable</Badge>` on rows where `confirmed_exploitable=true`.

### Component tree (slim)

```
frontend/src/components/dast/
  DastScanningTab.tsx              -- top-level for Project Settings tab
                                      (config form + scan button + history all inline)
  DastChip.tsx                     -- source=DAST chip for Security tab filters
  DastEmptyState.tsx               -- "DAST not configured" inline card
```

### Confirmed Exploitable as a Badge, not a card

When a DAST finding row has `confirmed_exploitable: true`, render `<Badge variant="warning">Confirmed Exploitable</Badge>` inline on the row and a small "Linked: SCA · {osv_id}" chip. Don't hide constituent rows. Don't merge. Defer the merged card to v2 once cross-link FP rate is measured.

### State + data fetching

- Config: standard fetch on tab mount. Cache invalidated on PUT.
- Jobs list: paginated, refetch on Realtime tick or manual reload.
- Realtime: subscribe to `scan_jobs` filtered by `project_id AND type='dast'`. RLS enforces tenant scope server-side.
- Findings: server pre-joins `confirmed_exploitable` boolean. No client-side merge logic.

### Design specifications

Per `frontend-design` SKILL:

- **Scanning tab card layout:** `rounded-lg border border-border bg-background-card`. Header `px-4 py-3 border-b border-border`. Content `p-4`.
- **Target URL input:** `h-9 px-3 bg-background-card border border-border rounded-md`, placeholder `https://staging.example.com`.
- **Scan Now button:** `<Button variant="outline" size="sm">` per `feedback_button_style`.
- **Run history table:** reuse polished `<RunRow>` from project-settings activity table per `project_settings_activity_table` memory.
- **DastChip filter:** matches existing severity/source chip pattern in unified findings table.
- **Confirmed Exploitable Badge:** `<Badge variant="warning">` with full-contrast text per `feedback_vercel_typography`.
- **Empty state:** inline card, single CTA `<Button variant="outline" size="sm">Configure DAST</Button>`.

## Implementation Tasks

Ordered, each independently testable. Estimates: S = 1-2 days, M = 3-5 days, L = 6-10 days.

### Foundation (PR 1) — worker + table consolidation

This is the largest PR. It renames worker AND table AND introduces type discriminator AND replaces RPCs AND updates all consumers. **Validate end-to-end on existing extraction before stacking PR 2.**

1. **Rename worker `extraction-worker` → `depscanner`** (M)
   - Rename `backend/extraction-worker/` → `backend/depscanner/`. Sweep imports across backend, scripts, CI workflows.
   - Rename Fly app `deptex-extraction-worker` → `deptex-depscanner`: create new app, deploy, dual-run for one cycle, point env vars, drain old app.
   - `EXTRACTION_CONFIG` constant in `backend/src/lib/fly-machines.ts` keeps name but `app: 'deptex-depscanner'`. Add `DAST_CONFIG` pointing at same app with `guest: { cpus: 4, memory_mb: 8192, cpu_kind: 'shared' }`.
   - Env-var rename `FLY_EXTRACTION_APP` → `FLY_DEPSCANNER_APP` with backward-compat alias period (read both).
   - Update CLAUDE.md, `.github/workflows/schema-check.yml`.

2. **Rename table `extraction_jobs` → `scan_jobs` + add `type` + DAST columns** (M)
   - Apply migration 1 (`scan_jobs_consolidation.sql`) via Supabase MCP. Schema dump refresh.
   - Apply migration 2 (`phase19_rpc_rename.sql`) — read existing Phase 19 RPC text, recreate with `scan_jobs` substituted.
   - Update every TypeScript reference: change `from('extraction_jobs')` → `from('scan_jobs')` plus a `.eq('type', 'extraction')` filter where appropriate.
   - Update worker: `claim_extraction_job` callsite → `claim_scan_job(machineId, ['extraction'])` initially (DAST type added in Task 3).
   - Update backend recovery cron: `recover_stuck_extraction_jobs` → `recover_stuck_scan_jobs`. The new RPCs handle both types; the cron call signature simplifies.
   - Update test suite mocks per `backend_test_mock_patterns` (any `setTableResponse('extraction_jobs', ...)` → `scan_jobs`).
   - **Acceptance for PR 1 combined:**
     - Existing extraction pipeline ships findings end-to-end on a test project against the renamed Fly app. CI grep verifies no `extraction-worker` literal strings remain (except in CHANGELOG/migration history). Recovery cron rerun + QStash dispatch smoke pass.
     - Per `feedback_audit_vs_grep`: run a parallel file-audit subagent alongside grep for the table-name sweep. The grep+audit combo catches different bug classes — extraction_jobs is referenced indirectly through helpers.
     - Per `feedback_docker_vs_source_e2e`: build the renamed Docker image and run extraction acceptance against the built image, not source tree.

### DAST schema + worker dispatch (PR 2)

3. **Apply DAST-specific migrations** (S)
   - `project_dast_config.sql`, `project_dast_findings.sql`, `projects_active_dast_run.sql`, `commit_dast_run.sql`. All via MCP. Schema dump refresh.
   - **Acceptance:** RLS enabled on both new tables. Realtime publication includes `project_dast_findings`. `commit_dast_run` callable from psql.

4. **Worker poll loop accepts DAST jobs** (S)
   - In `backend/depscanner/src/index.ts`, change the claim call from `claim_scan_job(machineId, ['extraction'])` to `claim_scan_job(machineId, ['extraction', 'dast'])`.
   - Add dispatcher: `if (job.type === 'extraction') runExtractionPipeline(job)`; `else if (job.type === 'dast') runDastPipeline(job)` (latter implemented in Task 8).
   - Single shared `setInterval` heartbeat updates `scan_jobs.heartbeat_at` regardless of type.
   - **Acceptance:** worker dispatches both types correctly within 30s of insert. Dispatcher unit-tested.

### Backend (PR 2 cont'd)

5. **`backend/src/lib/url-guard.ts`** (S)
   - Implement `validateExternalUrl(url: string)` per spec. DNS resolution + IP-class checks + scheme allowlist.
   - Unit test corpus: ≥12 hostile URLs (loopback IPv4/IPv6, RFC1918 each block, link-local, IMDS, Fly internal hostname, Fly 6PN, file://, gopher://, javascript:, DNS-rebind via short-TTL host).
   - **Acceptance:** all 12+ hostile URLs return `{valid: false}`; legitimate URLs return `{valid: true}`.

6. **DAST routes in `backend/src/routes/dast.ts`** (M)
   - Implement 5 routes: GET/PUT config, POST scan, GET jobs, GET findings.
   - PUT /config + POST /scan validate via `validateExternalUrl()`.
   - POST /scan calls `queue_scan_job('dast', ...)` then `startFlyMachine(DAST_CONFIG)`.
   - GET /jobs filters `scan_jobs WHERE type='dast' AND project_id=$1`.
   - GET /findings returns rows with computed `confirmed_exploitable` boolean.
   - Mount in `backend/src/index.ts`.
   - **Acceptance:** curl-test happy path → scan_jobs row with type='dast' created → Fly machine boots. RBAC: read-only member 403s on writes. Concurrent scan returns 409. Hostile target_url returns 422.

### Worker DAST pipeline (PR 3)

7. **ZAP container in Dockerfile** (M)
   - Multi-stage Dockerfile: `FROM ghcr.io/zaproxy/zaproxy:stable AS zap` → copy ZAP binaries into existing depscanner image. Image size budget: < 4GB total.
   - **Acceptance:** built image runs `zap-baseline.py --version` successfully. Image size measured and recorded.

8. **DAST runner module** (M)
   - New file `backend/depscanner/src/dast/runner.ts`. Function `runZap(targetUrl, scanProfile, routes): Promise<DastFindingRaw[]>`.
   - **Use `child_process.spawn` with stdio piped, awaited via Promise wrapper. NEVER `execSync`.** Heartbeat setInterval must remain alive during scan.
   - Profile routing: if `scanProfile === 'auto'` and `routes.length > 0` → `zap-api-scan.py` with synthesized OpenAPI stub. Else → `zap-full-scan.py` (or `zap-baseline.py` for `quick`).
   - Output JSON parsed; redaction pass strips known credential patterns from response evidence (regex MVP).
   - **Acceptance:** against OWASP Juice Shop on localhost, returns ≥10 findings. Heartbeat verification: 25-min scan against slow target shows `scan_jobs.heartbeat_at` advancing every 60s.

9. **DAST pipeline + cross-link** (M)
   - New file `backend/depscanner/src/dast/pipeline.ts`. Function `runDastPipeline(job, supabase)`.
   - Steps: clone (reuse `cloneRepo()`); read `project_entry_points` filtered by `projects.active_extraction_run_id` (skip with clear log line if NULL); run `runZap()`; cross-link.
   - **Cross-link (v1: SCA only):** for each DAST finding, normalize `endpoint_url` against `project_entry_points.route_pattern` via `lib/route-matcher.ts` (Task 10). Match populates `handler_file_path/handler_function_name/handler_line`. JOIN against `project_reachable_flows` on `(entry_point_file = handler_file_path AND entry_point_method = handler_function_name)` to find reachable dep. Populate `linked_sca_osv_id` and `linked_sca_project_dependency_id` from `project_dependency_vulnerabilities`.
   - Insert findings under fresh `dast_run_id` (= `'dast_' || gen_random_uuid()::text`). After all findings written, call `commit_dast_run(project_id, dast_run_id)` to atomically swap active pointer.
   - Update scan_jobs row: `status='completed', findings_count=N, duration_seconds=D, completed_at=NOW()`.
   - **Acceptance:** against test project with known SCA findings on a vulnerable dep, DAST scan against instrumented test target produces a finding with `linked_sca_osv_id` populated and `confirmed_exploitable=true`.

10. **`lib/route-matcher.ts`** (M)
    - Framework-aware route normalizer. `normalizeRoute(framework, pattern): RegExp`. Handles Express/Fastify/FastAPI/Spring/Rails/Gin/Sinatra/Laravel.
    - `matchRoute(zapUrl, pattern, framework): boolean`.
    - **Acceptance:** unit-test corpus of ≥20 (concrete URL, route pattern, framework) tuples. Negatives: `/users/123` does NOT match `/users/:id/posts`; `/usersextra/123` does NOT match `/users/:id`.

### Recovery cron extension (PR 3 cont'd)

11. **Recovery cron handles DAST type** (S)
    - Existing recovery route is now type-agnostic (Task 2 already replaced RPCs with `recover_stuck_scan_jobs` / `fail_exhausted_scan_jobs` that branch on `type`).
    - Extend the route handler: when a row is marked failed via the recovery RPC, call `stopFlyMachine(machine_id)` (best-effort, log on Fly API errors).
    - **Acceptance:** simulated stale `processing` DAST row with `attempts < max_attempts` is requeued; with `attempts >= max_attempts` marked failed; `stopFlyMachine` called for failed-rows.

### Frontend (PR 4 — Scanning tab)

12. **Project Settings → Scanning tab** (M)
    - Add `<DastScanningTab>` to `frontend/src/app/pages/ProjectSettingsContent.tsx`. Tab key `'scanning'`.
    - Inline: target URL input + Save, "Scan now" button (POST /scan), scan history table reusing `<RunRow>`.
    - Hook `useDastJobStatus(projectId)`: subscribes to `scan_jobs` filtered by `project_id AND type='dast'`, 5s polling fallback.
    - **Acceptance:** user configures URL, saves, clicks "Scan now", sees job appear in history with status updating live. Browser sign-off before PR 5.

### Frontend (PR 5 — Security tab)

13. **Security tab DAST chip + last-scan strip + empty state** (M)
    - Extend `<VulnerabilityExpandableTable>` (or its data hook) to include DAST findings.
    - Add `<DastChip>` to filter chips row.
    - Add inline last-scan strip at top of Security tab.
    - Add `<DastEmptyState>` when no DAST scan_jobs row exists.
    - **Acceptance:** project with DAST findings shows chip filter, last-run strip, findings in unified table. Project with no DAST run shows empty state. Browser sign-off before PR 6.

### Frontend (PR 6 — badge)

14. **Confirmed Exploitable badge** (S)
    - When a DAST finding row has `confirmed_exploitable: true`, render `<Badge variant="warning">Confirmed Exploitable</Badge>` inline. Show small "Linked: SCA · {osv_id}" chip with click-through to SCA finding.
    - **Acceptance:** in test project, DAST hit on `/api/users` linked to `mysql2` CVE shows the badge; standalone DAST findings don't.

### Tests + ship (PR 7)

15. **Backend tests** (M)
    - Routes: happy + RBAC + 409 + 422 hostile URL on POST /scan and PUT /config. Mock Supabase per `backend_test_mock_patterns`.
    - SSRF tests: 12+ hostile URLs against `validateExternalUrl()`.
    - Cross-tenant isolation: one targeted test on POST /scan and one on GET /findings. Foreign-org JWT returns 403/404.
    - RPC concurrency: real-DB (or PGLite) test for `claim_scan_job` race + `queue_scan_job` org-cap + project-cap (DAST type).
    - Cross-link unit test fixture matrix: (DAST-only, DAST+SCA), dynamic route normalization, negative cases, HTTP method mismatch, NULL handler resolution.
    - Suppression carry-forward: seed `status='risk_accepted'`, run second scan, assert `commit_dast_run` carries forward to new dast_run_id.
    - **Type-discriminator tests:** scan_jobs INSERT with type='dast' missing target_url is rejected by CHECK; claim_scan_job with `['extraction']` doesn't pick up DAST jobs and vice versa.
    - **Acceptance:** suite passes; cross-link logic + commit_dast_run carry-forward + type isolation all locked in.

16. **Frontend tests** (S)
    - Component tests for `<DastScanningTab>` and Security-tab DAST chip filter.
    - **Acceptance:** component tests pass; visual smoke against test project in Chrome.

17. **Manual e2e against built Docker image** (S)
    - Build depscanner Docker image (with ZAP); run full DAST scan from configured project against an instrumented target with known vulnerabilities.
    - Verify: scan completes within 30 minutes; ≥1 finding lands in Security tab; at least one has `confirmed_exploitable=true`.
    - Per `feedback_docker_vs_source_e2e`: test against built image, not source tree.

## Testing & Validation Strategy

| Layer | What | Where | Target |
|---|---|---|---|
| Backend unit | Route handlers, RBAC, SSRF rejection | `backend/src/routes/__tests__/dast.test.ts` | Happy + 422 + 409 + 403 |
| Backend integration | Cross-link join correctness | `backend/depscanner/src/dast/__tests__/cross-link.test.ts` | DAST-only + DAST+SCA; route normalization corpus |
| RPC concurrency | claim/queue race + caps + type filter | Real-DB / PGLite | Two parallel claims → exactly one row each; concurrent queue → second raises P0001; `claim_scan_job(['extraction'])` doesn't pick DAST rows |
| Atomic commit | commit_dast_run carry-forward | Cross-link test file | Suppressed/risk-accepted state survives second scan |
| Heartbeat | 25-min scan keeps heartbeat alive | Manual + scripted Fly smoke | `heartbeat_at` advances every 60s |
| SSRF | 12+ hostile URLs blocked | `backend/src/lib/__tests__/url-guard.test.ts` | All blocked classes return `{valid: false}` |
| Cross-tenant | Targeted test on POST /scan + GET /findings | Routes test file | Foreign-org JWT returns 403/404 |
| RLS | Realtime channel scopes by project | Manual against staging | Foreign-org subscription receives no events |
| E2E | Full scan against built Docker image | Manual + scripted smoke | Scan completes < 30min, ≥1 finding, badge fires |
| Regression | Existing extraction pipeline post-rename | Run extraction on test-npm | No regression after worker + table renames |

**Cut from v1**: 80% coverage targets (theater for solo pre-launch), k6 perf SLAs, Realtime <3s SLA.

## Risks & Open Questions

### Risks

- **PR 1 blast radius is the largest in the plan.** It bundles worker rename + table rename + RPC replacement + Phase 19 RPC update + every consumer migration. Mitigation: do PR 1 atomically with explicit rollback (env-var aliasing, dual-run cycle on Fly app, schema dump diff scrutinized). Gate with grep + parallel file-audit subagent + Docker e2e + recovery cron rerun + QStash dispatch smoke before stacking PR 2.
- **Image size.** Bundling ZAP brings depscanner image to ~3.5GB. Mitigation: multi-stage Dockerfile, prune ZAP non-essentials, monitor `image_size` on Fly. Cold-start uses cached image on stopped pool machines.
- **Cross-link false positives in route normalization.** Framework-aware regex compiler is the right shape; real-world repos have custom routers. Mitigation: `cross_link_metadata JSONB` records match method + confidence; tune post-launch. Confirmed Exploitable Badge (not Card) keeps individual findings visible if a link is wrong.
- **Heartbeat blocking.** Solved by mandating `spawn` over `execSync` in Task 8. Recovery threshold lifted to 32min for DAST type so legitimate slow scans don't trigger requeue.
- **Privacy of response evidence.** Regex-only redaction in v1; documented limitation. Mitigation: explicit redaction unit test corpus; deferred TruffleHog detector swap-in for phase 2.
- **Worker logs interleaving.** Bundling DAST into depscanner means DAST and extraction logs interleave. Mitigation: prefix log lines with `[ext-{job_id}]` or `[dast-{job_id}]` for filterability.
- **Phase 19 RPC consistency.** Renaming `extraction_jobs` requires updating Phase 19's `commit_extraction` and orphan reaper RPCs which reference the old name in their function bodies. Migration 2 handles this. Risk: existing RPC text contains references the migration misses. Mitigation: text-search the database/ folder for `extraction_jobs` after applying migration 1, fail-fast if any RPC body still references it.

### Open questions

- **Scan-on-extraction trigger plumbing (phase 2):** extraction worker dispatches a follow-up `scan_jobs` insert with `type='dast'` via QStash post-completion, OR the recovery/finalize step inline-inserts. Probably the former for clean job semantics. Defer.
- **Free-tier limits:** assume unlimited for solo pre-launch. Add when billing lands.
- **`scan_jobs.run_id` column:** existing column on `extraction_jobs` carries through the rename. DAST type uses it (= `'dast_' || id::text`). If phase 2 raises max_attempts for DAST, recovery RPC needs to regenerate `run_id` on requeue per existing extraction precedent.
- **Future scanner types:** `'malicious_pkg'`, `'iac'`, `'container'` are 1-line CHECK constraint additions plus per-type sparse columns. The shape established in v1 carries forward.

## Dependencies

- **Reused existing code:** `claim_extraction_job` pattern (replaced by `claim_scan_job`), `startFlyMachine`, `<RunRow>` from project-settings activity table, `<VulnerabilityExpandableTable>`, `useRealtimeStatus` hook pattern, `checkProjectManagePermission`, `project_entry_points` storage, `project_reachable_flows` join, Phase 19 atomic-commit pattern.
- **External dependencies:** OWASP ZAP Docker image (`ghcr.io/zaproxy/zaproxy:stable`).
- **Phase precedence:** none. This is the v1.

## Success Criteria

**Done means:**
- Worker renamed to `depscanner`; table renamed to `scan_jobs` with `type` discriminator; existing extraction pipeline ships findings end-to-end with no regressions.
- All migrations applied via MCP; schema dump refreshed; Phase 19 RPCs updated; RLS preserved on rename and added to new tables.
- API: 5 routes; RBAC enforced; SSRF rejected at PUT /config and POST /scan; concurrent caps enforced.
- Worker: ZAP runs via `spawn` async; heartbeat alive during 25min scan; recovery calls `stopFlyMachine` on failure.
- Cross-link: DAST↔SCA via reachable_flows produces `confirmed_exploitable=true` on at least one demo finding.
- Frontend: Project Settings Scanning tab functional; Security tab shows DAST chip, last-scan strip, empty state, Confirmed Exploitable badge on cross-linked rows.

**Quantitative pre-launch gates:**
- SSRF helper rejects 100% of 12+ hostile URL corpus.
- Route normalizer matches >80% on a 20-tuple test corpus across 8 frameworks.
- Cross-link false-positive rate <10% measured on a synthetic DAST+SCA fixture matrix.
- Redaction unit test confirms zero credentials leak in stored response evidence.

## Recommended Branching

Single worktree off `main`: `worktree-dast`. Stack as 7 PRs:

1. **PR 1** — Worker rename + table rename + type discriminator + RPC replacement + consumer migration. Largest PR. Validate end-to-end on existing extraction.
2. **PR 2** — DAST schema + worker dispatch hookup + URL guard + DAST routes.
3. **PR 3** — Worker DAST pipeline (Dockerfile + runner + cross-link + route matcher) + recovery extension.
4. **PR 4** — Project Settings Scanning tab. Browser sign-off.
5. **PR 5** — Security tab DAST chip + last-scan strip + empty state. Browser sign-off.
6. **PR 6** — Confirmed Exploitable badge.
7. **PR 7** — Tests + manual Docker e2e + ship.

Per `feedback_visual_redesign_iteration`: each frontend PR ships independently for browser sign-off before the next layers on. Per `feedback_audit_vs_grep`: PR 1 runs grep + parallel file-audit subagent for the worker AND table-name sweeps — two cross-cutting refactors in one PR; the audit:grep ratio matters more here than anywhere else.
