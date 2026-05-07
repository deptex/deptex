# DAST v2.1a Engine Foundation — Implementation Plan

## Overview

v2.1a is the **additive engine foundation** carved out of the original v2.1 plan after `/review-plan` returned REWORK 12/0/0. It ships the new multi-target schema, ZAP-only authenticated scanning (form/JWT/cookie), SPA auto-detection, scope rules, encrypted credential storage, and three-layer cross-tenant validation — **all behind a `DAST_RUNNER_MODE` feature flag whose default keeps v1's helper-script execution path live**. No destructive migration steps land in this phase: every old RPC, every old column, every old finding-table shape stays in place; new RPCs and new columns are added alongside via wrapper shims. This is the structural correction the unanimous REWORK verdict demanded — splitting one risky cutover into a safe additive landing + a destructive cleanup (v2.1b) gated on a ≥7-day shadow window.

What's deliberately **out of v2.1a**:

- **Nuclei (template-based scanning)** — moved to v2.1c. Locked 2026-05-02 as its own future `scan_jobs.type='dast_nuclei'` claimed sequentially after `dast_zap` on the same depscanner machine. v2.1a is ZAP-only; the `engine` column ships with CHECK widened to `'zap'|'nuclei'|'merged'` for forward-compat, but only `'zap'` ever inserts.
- **Recorded login (HAR replay)** — moved to v2.1d, ships after first customer SSO ask. v2.1a auth strategies: `form`, `jwt`, `cookie`.
- **Destructive migration steps** — moved to v2.1b: dropping `projects.active_dast_run_id`, flipping `findings.target_id` NOT NULL, dropping wrapper RPCs, dropping `DAST_RUNNER_MODE=helper_script` flag. v2.1b applies after Juice Shop e2e reproduces v1 anonymous-baseline finding counts within ±10% AND `pg_stat_user_functions` shows zero calls to old-signature RPCs in the last 24h.
- **`auto` profile = full active scan** — locked 2026-05-02 to passive-only. Explicit `profile='full'` is the sole path to active fuzzing and gates through the existing `ActiveScanOptInDialog`. Closes the consent hole structurally; no server-side `active_scan_consent_at` column needed.

The brief (`.cursor/plans/feature-brief-dast-v2.md`) is the source of truth for v2.1's locked scope; the review report (`.cursor/plans/review-dast-v2-1-engine.md`) is the source of truth for the patches this plan folds in.

## Competitive Research & Design Rationale

The brief's competitive landscape stays the source of truth (Burp, StackHawk, Invicti, Bright, Snyk, 42Crunch, Mayhem, ZAP AF). v2.1a-specific implications:

1. **ZAP Automation Framework as the long-term spine, behind a feature flag.** Rewriting the helper-script invocation to a generated YAML AF config (`automation.yaml` → `/zap/zap.sh -cmd -autorun`) unlocks `authentication`, `browserBased`, `replacer`, `script`, `alertFilter` jobs that the helper scripts can't reach. But cutting helper-script in one step is what gave architect-f2 + worker-pipeline-auditor-r2-f11 their P1 finding: "no rollback path if YAML build is wrong against v1 baseline." So v2.1a ships **both paths gated on `organizations.dast_runner_mode TEXT NULL CHECK ('helper_script','automation_framework')`** with global default env `DAST_RUNNER_MODE=helper_script`. Per-org override flips a tenant to AF for shadow comparison; phase24b drops the flag once the new path reproduces v1 finding count ±10% on Juice Shop.
2. **Auth modes mirror Burp + StackHawk taxonomy**, not ZAP's lower-level model. Strategy enum (`form` / `jwt` / `cookie`) maps to ZAP method per strategy: `form` → `formBasedAuthentication`, `jwt` → `httpAuthentication` Bearer + `replacer` rule, `cookie` → `replacer` rule on `Cookie` header. Burp-style `loggedInIndicator` / `loggedOutIndicator` regexes wired through ZAP's verification strategy ([ZAP auth methods](https://www.zaproxy.org/docs/desktop/start/features/authmethods/)).
3. **SPA detection by HTML markers, not user toggle.** Probe target HTML for runtime markers (`data-reactroot`, `id="__nuxt"`, `id="__next"`, `data-server-rendered`, `<app-root`, `id="svelte"`) ([SPA DAST guide](https://www.stackhawk.com/blog/scanning-your-spa-with-dast-youre-doing-it-wrong/)). Cache verdict on `project_dast_targets.detected_runtime` with `detected_runtime_ttl_at` (30 days). Per cluster-4 patch, **probe runs at `POST /dast/scan` route time (not worker time)** so machine-shape dispatch picks correct `DAST_CONFIG` size BEFORE Fly machine provisions — eliminates the SPA-OOM-on-`shared-cpu-4x` risk.
4. **Decryption stays at worker, not API route.** Architect originally proposed moving decryption to API; failure-mode-hunter dissented (QStash payload + scan_jobs.payload queryable JSONB + admin endpoints + worker stderr = strictly worse leak surface); architect withdrew. Worker-side decrypt + `Buffer.fill(0)` zero-out + `DAST_CREDENTIAL_KEY` confined to depscanner env is the resolved consensus.

## Codebase Analysis

### Existing patterns to reuse

- **AES-256-GCM encryption** — `backend/src/lib/ai/encryption.ts` already implements `encryptApiKey` / `decryptApiKey` with current+previous key fallback for rotation. v2.1a ships parallel `backend/src/lib/dast-encryption.ts` against `DAST_CREDENTIAL_KEY` env var with identical shape.
- **Job-claim and dispatch** — `backend/depscanner/src/index.ts` (`runWorker` + `processJob`) dispatches on `job.type`. v2.1a needs no changes here; the `processDastJob` branch loads the new YAML-AF path conditionally on `organizations.dast_runner_mode` resolved at job-claim time.
- **Atomic-commit + active-pointer** — `commit_dast_run(p_project_id UUID, p_dast_run_id TEXT)` in `phase23b_dast_schema.sql` flips `projects.active_dast_run_id`. v2.1a adds new `commit_dast_target_run(p_target_id UUID, p_dast_run_id TEXT)` ALONGSIDE; old wraps new via SECURITY DEFINER lookup of "first target row for project."
- **SSRF guard** — `backend/src/lib/url-guard.ts` (DNS-resolved IP block-list) reused unchanged at every new target URL ingress.
- **Spawn wrapper** — `backend/depscanner/src/dast/runner.ts:330` (`spawnZap`) is the basis for the new `spawnExternal` control plane (Task 8 patches subprocess kill chain + auth-loss abort).
- **Suppression carry-forward** — `commit_dast_run` joins prior-run findings on `(rule_id, handler_*, vulnerability_type)` for resolved + `(rule_id, endpoint_url, http_method, vulnerability_type)` for unresolved. New `commit_dast_target_run` extends both joins with `target_id`.
- **Realtime channel** — `frontend/src/components/dast/DastScanningTab.tsx` subscribes to `scan_jobs` per-project. v2.1a adds a second filter on `project_dast_targets` for direct target updates.
- **Confirmed Exploitable cross-link** — `backend/depscanner/src/dast/pipeline.ts:crossLinkFinding` unchanged; SAST cross-link is v2.3.

### Files this plan modifies

**Modified:**
- `backend/database/` (new migration: `phase24a_dast_v2_engine_additive.sql` — additive only, no DROP/destructive ops)
- `backend/database/schema.sql` (regenerated via `npm run schema:dump`)
- `backend/src/routes/dast.ts` (multi-target endpoints + cred CRUD + 3-layer cross-tenant guard)
- `backend/src/types/dast.ts` (DTO types for targets + credentials + scope_config)
- `backend/src/lib/fly-machines.ts` (DAST_CONFIG branched on detected_runtime)
- `backend/depscanner/src/dast/runner.ts` (gated by `DAST_RUNNER_MODE`; helper-script default; AF YAML opt-in)
- `backend/depscanner/src/dast/pipeline.ts` (load credentials + auth_state + cancellation + log scrub)
- `backend/depscanner/src/index.ts` (job-claim filter on `isDastEncryptionConfigured()`)
- `frontend/src/components/dast/DastScanningTab.tsx` (refactor to multi-target shell)
- `frontend/src/components/dast/DastFindingsSection.tsx` (target filter + auth_state badge)
- `frontend/src/lib/api.ts` (new endpoints + DTO types)

**New:**
- `backend/src/lib/dast-encryption.ts` (per-target credential encryption)
- `backend/src/lib/dast-tenant-guard.ts` (`loadTargetOrDeny` 3-layer enforcement helper)
- `backend/src/lib/dast-log-scrub.ts` (structured-log scrub regex over fixture; test-enforced)
- `backend/depscanner/src/dast/spa-detect.ts` (runtime-marker probe; called from API route + cached on target)
- `backend/depscanner/src/dast/auth-config.ts` (ZAP AF auth job builder per strategy — form/JWT/cookie only)
- `backend/depscanner/src/dast/yaml-builder.ts` (Automation Framework YAML composer; gated by flag)
- `backend/depscanner/src/dast/control-plane.ts` (`spawnExternal` + abort + stderr-watcher)
- `frontend/src/components/dast/DastTargetsList.tsx`
- `frontend/src/components/dast/DastTargetEditDialog.tsx`
- `frontend/src/components/dast/DastAuthPanel.tsx` (form + JWT + cookie only — no `RecordedLoginWizard`)
- `frontend/src/components/dast/DastScopePanel.tsx`
- `frontend/src/components/dast/ActiveScanOptInDialog.tsx`

**Deferred to v2.1b (destructive cleanup):**
- DROP `projects.active_dast_run_id` / `previous_dast_run_id`
- ALTER `findings.target_id NOT NULL`
- DROP wrapper `commit_dast_run(p_project_id, p_dast_run_id)`
- DROP wrapper `queue_scan_job` legacy signature
- DROP `DAST_RUNNER_MODE` + helper-script invocation path

**Deferred to v2.1c (Nuclei):**
- `backend/depscanner/src/dast/nuclei-runner.ts`
- `backend/depscanner/src/dast/dedup.ts`
- `backend/depscanner/Dockerfile` Nuclei binary + nuclei-templates layer
- New `scan_jobs.type='dast_nuclei'` enum value (CHECK widened in v2.1a, value never inserted)

**Deferred to v2.1d (recorded login HAR):**
- `backend/src/lib/dast-har.ts`
- `frontend/src/components/dast/RecordedLoginWizard.tsx`
- ZAP `sequence-import` job in YAML AF
- `auth_strategy='recorded'` enum value (CHECK widened in v2.1a, value never inserted)

### Patterns we will NOT invent

- No new dispatch path in worker — stay on `processJob` switch on `job.type`.
- No new RBAC permission — credential CRUD gated by **`manage_integrations`** per pragmatist-r2-f15 P1 patch (closer to "handles secrets" than `manage_projects`; minimizes effective-access expansion).
- No new Fly app — same `deptex-depscanner` app; SPA scans dispatched at `performance-4x` 16GB via `DAST_CONFIG` branched on `target.detected_runtime`.
- No new Realtime channel architecture — reuse existing pattern; add `project_dast_targets` to publication; cross-tenant test gate added to ensure RLS-aware filtering.

## Data Model

### Migration shape: additive only — no DROP, no NOT NULL flip, no signature destruction

Per `feedback_two_phase_migration_pattern`: this migration touches ≥3 signature-breaking surfaces (commit_dast_run signature, queue_scan_job signature, projects.active_dast_run_id removal, partial-index recomposition). v2.1a applies the **additive half**; v2.1b applies the destructive half after the ≥7-day shadow window proves the new path safe.

### New table: `project_dast_targets`

```sql
CREATE TABLE project_dast_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  target_url TEXT NOT NULL,
  label TEXT,
  enabled BOOLEAN NOT NULL DEFAULT true,

  detected_runtime TEXT NOT NULL DEFAULT 'unknown'
    CHECK (detected_runtime IN ('unknown', 'classic', 'spa')),
  detected_runtime_at TIMESTAMPTZ,
  detected_runtime_ttl_at TIMESTAMPTZ,

  active_dast_run_id  TEXT,
  previous_dast_run_id TEXT,
  last_scanned_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, target_url)
);

-- per data-model-auditor-f10 P2: prevent two targets in same project sharing a label
CREATE UNIQUE INDEX project_dast_targets_label_unique
  ON project_dast_targets(project_id, label)
  WHERE label IS NOT NULL;

CREATE INDEX idx_project_dast_targets_project ON project_dast_targets(project_id);
CREATE INDEX idx_project_dast_targets_org ON project_dast_targets(organization_id);
CREATE INDEX idx_project_dast_targets_active_run
  ON project_dast_targets(active_dast_run_id) WHERE active_dast_run_id IS NOT NULL;

ALTER TABLE project_dast_targets ENABLE ROW LEVEL SECURITY;

-- SELECT (existing pattern)
CREATE POLICY project_dast_targets_org_select
  ON project_dast_targets FOR SELECT
  USING (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));

-- INSERT/UPDATE/DELETE WITH CHECK — required for self-host RLS-as-enforcement-boundary
-- per multi-tenant-design-auditor cluster-3 patch
CREATE POLICY project_dast_targets_org_insert
  ON project_dast_targets FOR INSERT
  WITH CHECK (organization_id IN (
    SELECT om.organization_id FROM organization_members om
    WHERE om.user_id = auth.uid()
  ));

CREATE POLICY project_dast_targets_org_update
  ON project_dast_targets FOR UPDATE
  USING (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ))
  WITH CHECK (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));

CREATE POLICY project_dast_targets_org_delete
  ON project_dast_targets FOR DELETE
  USING (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));
```

### New table: `project_dast_credentials`

```sql
CREATE TABLE project_dast_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL UNIQUE REFERENCES project_dast_targets(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  -- v2.1a: form|jwt|cookie. CHECK widened for forward-compat with v2.1d 'recorded'.
  auth_strategy TEXT NOT NULL
    CHECK (auth_strategy IN ('form', 'jwt', 'cookie', 'recorded')),
  encrypted_payload TEXT NOT NULL,
  encryption_key_version INTEGER NOT NULL DEFAULT 1,

  logged_in_indicator  TEXT,
  logged_out_indicator TEXT,
  retry_login_on_lost  BOOLEAN NOT NULL DEFAULT false,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_project_dast_credentials_org ON project_dast_credentials(organization_id);

ALTER TABLE project_dast_credentials ENABLE ROW LEVEL SECURITY;

CREATE POLICY project_dast_credentials_org_select
  ON project_dast_credentials FOR SELECT
  USING (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));

CREATE POLICY project_dast_credentials_org_insert
  ON project_dast_credentials FOR INSERT
  WITH CHECK (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));

CREATE POLICY project_dast_credentials_org_update
  ON project_dast_credentials FOR UPDATE
  USING (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ))
  WITH CHECK (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));

CREATE POLICY project_dast_credentials_org_delete
  ON project_dast_credentials FOR DELETE
  USING (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));
```

### `project_dast_config` — additive scope_config only

**No DROP/RE-ADD on existing columns** (data-model-auditor-f8 P0: DROP+RE-ADD silently destroys customer settings). `target_url`, `scan_profile`, `scan_timeout_minutes` all kept; v2.1a reads from new `project_dast_targets` rows but writes also continue to land on legacy single-target column for the shadow window. Phase24b drops `target_url` after orphan sweep.

```sql
ALTER TABLE project_dast_config
  ADD COLUMN IF NOT EXISTS scope_config JSONB NOT NULL DEFAULT '{}'::jsonb;
```

`scope_config` shape:
```json
{
  "include_patterns": ["^/api/.*"],
  "exclude_patterns": ["^/admin/destroy.*", "/healthz$"],
  "header_rules": [
    { "name": "X-Test-User", "value": "scanner", "scope": "all" }
  ]
}
```

Per cluster scope-bypass P1 patch: route layer rejects sensitive header names (`Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-CSRF-Token`, regex `/token|secret|password|key/i`) at PUT time with 422 "use credential panel for sensitive headers." See Task 3 acceptance.

### `project_dast_findings` — additive columns only

```sql
-- target_id NULLABLE in v2.1a; phase24b flips to NOT NULL after orphan sweep
ALTER TABLE project_dast_findings
  ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES project_dast_targets(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS auth_state TEXT NOT NULL DEFAULT 'anonymous'
    CHECK (auth_state IN ('anonymous', 'authenticated', 'authentication_lost')),
  ADD COLUMN IF NOT EXISTS engine TEXT NOT NULL DEFAULT 'zap'
    CHECK (engine IN ('zap', 'nuclei', 'merged'));
```

Per opportunity-scout-f1 P3 forward-prep:
```sql
ALTER TABLE project_dast_findings
  ADD COLUMN IF NOT EXISTS linked_sast_finding_id UUID
    REFERENCES project_semgrep_findings(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS cross_link_methods TEXT[] DEFAULT ARRAY[]::TEXT[];
```

**Partial unique indexes — additive replacement, not DROP/recreate:**

Per migration-safety-auditor cluster-1 patch + drain runbook (Task 1.5): drain queue first → ACCESS EXCLUSIVE on existing partial indexes is ≤1s on sub-10K rows. We CAN drop+recreate WITHIN the migration once queue is drained, but for v2.1a additive-only safety, we **add new partial indexes alongside** keyed on `target_id`; phase24b drops the old indexes after shadow.

```sql
-- Existing indexes stay live in v2.1a:
--   project_dast_findings_resolved   (dast_run_id, rule_id, handler_*, vulnerability_type)
--   project_dast_findings_unresolved (dast_run_id, rule_id, endpoint_url, http_method, vulnerability_type)
-- Add NEW per-target indexes alongside:
CREATE UNIQUE INDEX project_dast_findings_target_resolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    handler_file_path, handler_function_name, vulnerability_type
  )
  WHERE handler_file_path IS NOT NULL AND target_id IS NOT NULL;

CREATE UNIQUE INDEX project_dast_findings_target_unresolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    endpoint_url, http_method, vulnerability_type
  )
  WHERE handler_file_path IS NULL AND target_id IS NOT NULL;
```

### `scan_jobs` additive columns

```sql
ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES project_dast_targets(id) ON DELETE SET NULL,
  -- per cluster-2 patch: per-scan credential audit replaces credential rotation history
  ADD COLUMN IF NOT EXISTS credential_id UUID
    REFERENCES project_dast_credentials(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS credential_payload_hash TEXT;
  -- credential_payload_hash = SHA-256 of encrypted_payload at job-claim snapshot time;
  -- worker captures and never re-reads. Eliminates TOCTOU + credential-replace-during-flight race.
```

Per opportunity-scout-f3 P3: widen `trigger_source` CHECK to reserve `'scheduled','on_deploy'` for v2.2 — avoid CHECK shuffle later.
```sql
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_trigger_source_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_source_check
  CHECK (trigger_source IS NULL OR trigger_source IN (
    'manual','webhook','recovery','scheduled','on_deploy'
  ));
```

### `projects` — no changes in v2.1a

`projects.active_dast_run_id` and `previous_dast_run_id` **stay live** for the shadow window. v2.1a writes to BOTH old (legacy column) AND new (target row) pointers via wrapper RPC. Phase24b drops the old columns.

### Wrapper RPC: `commit_dast_run` (legacy) wraps new `commit_dast_target_run`

```sql
-- New canonical RPC, target-scoped. Mirrors v1 semantics + carries target_id.
CREATE OR REPLACE FUNCTION commit_dast_target_run(
  p_target_id   UUID,
  p_dast_run_id TEXT
) RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE
  v_prior_run_id TEXT;
  v_project_id UUID;
BEGIN
  SELECT active_dast_run_id, project_id INTO v_prior_run_id, v_project_id
  FROM project_dast_targets WHERE id = p_target_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'commit_dast_target_run: target % not found', p_target_id;
  END IF;

  -- Suppression carry-forward, target-scoped.
  IF v_prior_run_id IS NOT NULL THEN
    UPDATE project_dast_findings new_f
    SET status = old_f.status,
        risk_accepted_by = old_f.risk_accepted_by,
        risk_accepted_at = old_f.risk_accepted_at,
        risk_accepted_reason = old_f.risk_accepted_reason
    FROM project_dast_findings old_f
    WHERE new_f.target_id = p_target_id
      AND new_f.dast_run_id = p_dast_run_id
      AND old_f.target_id = p_target_id
      AND old_f.dast_run_id = v_prior_run_id
      AND old_f.rule_id IS NOT DISTINCT FROM new_f.rule_id
      AND old_f.vulnerability_type = new_f.vulnerability_type
      AND old_f.status <> 'open'
      AND (
        (old_f.handler_file_path IS NOT NULL
          AND new_f.handler_file_path IS NOT NULL
          AND old_f.handler_file_path = new_f.handler_file_path
          AND old_f.handler_function_name IS NOT DISTINCT FROM new_f.handler_function_name)
        OR
        (old_f.handler_file_path IS NULL
          AND new_f.handler_file_path IS NULL
          AND old_f.endpoint_url = new_f.endpoint_url
          AND old_f.http_method = new_f.http_method)
      );
  END IF;

  UPDATE project_dast_targets
  SET previous_dast_run_id = active_dast_run_id,
      active_dast_run_id   = p_dast_run_id,
      last_scanned_at      = NOW()
  WHERE id = p_target_id;

  -- Shadow-window double-write to legacy projects column for v1 readers.
  -- v2.1b drops this UPDATE.
  UPDATE projects
  SET previous_dast_run_id = active_dast_run_id,
      active_dast_run_id   = p_dast_run_id
  WHERE id = v_project_id;
END;
$$;

-- Wrapper: legacy v1 signature DELEGATES to canonical via "first target row for project."
-- Existing callers (v1 worker baked at deploy-time, recovery cron, etc.) keep working.
CREATE OR REPLACE FUNCTION commit_dast_run(
  p_project_id  UUID,
  p_dast_run_id TEXT
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_target_id UUID;
BEGIN
  SELECT id INTO v_target_id
  FROM project_dast_targets
  WHERE project_id = p_project_id
  ORDER BY created_at
  LIMIT 1;

  IF v_target_id IS NULL THEN
    -- Backfill should have created one synthetic-legacy target per project; if missing,
    -- something is wrong. RAISE so we don't silently corrupt state.
    RAISE EXCEPTION 'commit_dast_run wrapper: no target found for project %', p_project_id;
  END IF;

  PERFORM commit_dast_target_run(v_target_id, p_dast_run_id);
END;
$$;
```

### Wrapper RPC: `queue_scan_job` — new optional target_id arg, legacy callers unaffected

```sql
-- v2.1a redefines queue_scan_job with new OPTIONAL p_target_id arg.
-- Legacy callers (v1 routes that don't yet pass target_id) work unchanged because
-- p_target_id defaults NULL; body resolves NULL to "first target row for project"
-- via same lookup as commit_dast_run wrapper. Per-org cap raises 3 → 5 for type='dast'.
DROP FUNCTION IF EXISTS queue_scan_job(UUID, UUID, TEXT, JSONB, TEXT, TEXT, INTEGER, TEXT, UUID);

CREATE OR REPLACE FUNCTION queue_scan_job(
  p_project_id      UUID,
  p_organization_id UUID,
  p_type            TEXT,
  p_payload         JSONB,
  p_target_id       UUID    DEFAULT NULL,
  p_target_url      TEXT    DEFAULT NULL,
  p_scan_profile    TEXT    DEFAULT NULL,
  p_timeout_minutes INTEGER DEFAULT NULL,
  p_trigger_source  TEXT    DEFAULT NULL,
  p_triggered_by    UUID    DEFAULT NULL
) RETURNS scan_jobs
LANGUAGE plpgsql AS $$
DECLARE
  v_resolved_target_id UUID;
  v_target_org_id UUID;
  v_target_project_id UUID;
  v_org_concurrent INT;
  v_proj_concurrent INT;
  v_inserted scan_jobs;
  v_credential_id UUID;
  v_credential_hash TEXT;
BEGIN
  -- Cluster-3 patch: RPC layer asserts (target.project_id, target.organization_id)
  -- match the args. RAISE on mismatch.
  IF p_type IN ('dast','dast_zap','dast_nuclei') THEN
    IF p_target_id IS NULL THEN
      SELECT id INTO v_resolved_target_id
      FROM project_dast_targets
      WHERE project_id = p_project_id
      ORDER BY created_at
      LIMIT 1;
    ELSE
      v_resolved_target_id := p_target_id;
    END IF;

    IF v_resolved_target_id IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: no DAST target found for project %', p_project_id;
    END IF;

    SELECT project_id, organization_id INTO v_target_project_id, v_target_org_id
    FROM project_dast_targets
    WHERE id = v_resolved_target_id;

    IF v_target_project_id <> p_project_id OR v_target_org_id <> p_organization_id THEN
      RAISE EXCEPTION
        'queue_scan_job: tenant drift — target % belongs to (project=%, org=%); caller passed (project=%, org=%)',
        v_resolved_target_id, v_target_project_id, v_target_org_id, p_project_id, p_organization_id;
    END IF;

    -- Cluster-2 patch: capture credential snapshot at queue time.
    SELECT id, encode(digest(encrypted_payload, 'sha256'), 'hex')
    INTO v_credential_id, v_credential_hash
    FROM project_dast_credentials
    WHERE target_id = v_resolved_target_id;
    -- v_credential_id may be NULL (anonymous scan); that's fine.
  END IF;

  -- Per-project cap: 1 active DAST scan_job (any dast_* type)
  SELECT COUNT(*) INTO v_proj_concurrent
  FROM scan_jobs
  WHERE project_id = p_project_id
    AND type IN ('dast','dast_zap','dast_nuclei')
    AND status IN ('queued','processing');

  IF v_proj_concurrent >= 1 THEN
    RAISE EXCEPTION 'project_concurrent_dast_blocked: project % already has DAST scan in flight', p_project_id;
  END IF;

  -- Per-org cap: 5 (raised from 3 per brief decision 10)
  SELECT COUNT(*) INTO v_org_concurrent
  FROM scan_jobs
  WHERE organization_id = p_organization_id
    AND type IN ('dast','dast_zap','dast_nuclei')
    AND status IN ('queued','processing');

  IF v_org_concurrent >= 5 THEN
    RAISE EXCEPTION 'org_concurrent_dast_blocked: organization % at 5/5 cap', p_organization_id;
  END IF;

  INSERT INTO scan_jobs (
    project_id, organization_id, type, status, payload,
    target_id, target_url,
    scan_profile, timeout_minutes,
    trigger_source, triggered_by,
    credential_id, credential_payload_hash
  ) VALUES (
    p_project_id, p_organization_id, p_type, 'queued', p_payload,
    v_resolved_target_id, p_target_url,
    p_scan_profile, p_timeout_minutes,
    p_trigger_source, p_triggered_by,
    v_credential_id, v_credential_hash
  )
  RETURNING * INTO v_inserted;

  RETURN v_inserted;
END;
$$;
```

### Migration file: `phase24a_dast_v2_engine_additive.sql`

Order of operations (additive only):

1. CREATE TABLE `project_dast_targets` + indexes + RLS policies (SELECT + INSERT + UPDATE + DELETE WITH CHECK)
2. CREATE TABLE `project_dast_credentials` + indexes + RLS policies
3. ALTER `project_dast_config` ADD COLUMN `scope_config JSONB`
4. ALTER `project_dast_findings` ADD COLUMNS `target_id`, `auth_state`, `engine`, `linked_sast_finding_id`, `cross_link_methods`
5. ALTER `scan_jobs` ADD COLUMNS `target_id`, `credential_id`, `credential_payload_hash`; widen `trigger_source` CHECK
6. CREATE UNIQUE INDEX (target-keyed partials) alongside existing partial indexes
7. CREATE FUNCTION `commit_dast_target_run` (canonical)
8. CREATE OR REPLACE FUNCTION `commit_dast_run` (wrapper delegating to canonical)
9. CREATE OR REPLACE FUNCTION `queue_scan_job` (with new optional `p_target_id` arg + tenant assertions + credential snapshot capture + 5/org cap)
10. ALTER PUBLICATION `supabase_realtime` ADD TABLE `project_dast_targets`, `project_dast_credentials`
11. **Two-pass backfill** (per cluster-1 patch):
    - **Pass 1 — synthetic-legacy targets:** `INSERT INTO project_dast_targets (project_id, organization_id, target_url, label, ...) SELECT project_id, organization_id, COALESCE(target_url, 'https://unknown.local'), 'legacy', NOW() FROM project_dast_config WHERE NOT EXISTS (SELECT 1 FROM project_dast_targets t WHERE t.project_id = project_dast_config.project_id);` — every project gets at least one row.
    - **Pass 2 — backfill `findings.target_id`:** UPDATE `project_dast_findings` SET `target_id = (SELECT id FROM project_dast_targets WHERE project_id = findings.project_id ORDER BY created_at LIMIT 1)`. Per cluster-1 patch: log orphan count via `RAISE NOTICE 'phase24a backfill: % findings remain target_id=NULL'` rather than ABORT — phase24b NOT NULL flip handles cleanup later.
12. **Verification SELECTs** logged to migration output:
    - `SELECT COUNT(*) FROM project_dast_targets` — assert ≥ count of distinct project_ids in `project_dast_config`
    - `SELECT COUNT(*) FROM project_dast_findings WHERE target_id IS NULL` — log orphan count (non-blocking)
    - `SELECT COUNT(*) FROM scan_jobs WHERE type IN ('dast','dast_zap','dast_nuclei') AND status IN ('queued','processing')` — must be 0 (drain runbook precondition)

### Schema dump

After Supabase MCP applies (per `feedback_apply_migrations_via_mcp`), regenerate `backend/database/schema.sql`:
```bash
cd backend/depscanner && npm run schema:dump
```
Per `feedback_schema_dump_rebase`: regenerate **on the feature branch**, not main, to avoid the silent rebase drop.

## API Design

All endpoints mounted at `/api/projects/:projectId/dast/...` via `app.use('/api/projects', dastRouter)` (v1 mount unchanged).

### Endpoints

| Method | Route | Auth | Permission | Description |
|--------|-------|------|------------|-------------|
| GET | `/api/projects/:projectId/dast/config` | authenticateUser | view (`checkProjectAccess`) | Returns `{ scan_profile, scan_timeout_minutes, scope_config, targets: DastTargetDTO[] }` |
| PUT | `/api/projects/:projectId/dast/config` | authenticateUser | `manage_projects` | Update profile / timeout / scope_config (excludes targets — use target endpoints for those). Validates scope_config: rejects sensitive header names + ReDoS-vulnerable patterns. |
| GET | `/api/projects/:projectId/dast/targets` | authenticateUser | view | List of `DastTargetDTO[]` |
| POST | `/api/projects/:projectId/dast/targets` | authenticateUser | `manage_projects` | Create target. Body: `{ target_url, label?, enabled? }`. SSRF-validates target_url. Synchronously runs SPA-detect probe and stores `detected_runtime` + `detected_runtime_at` + `detected_runtime_ttl_at` (NOW + 30d). |
| PATCH | `/api/projects/:projectId/dast/targets/:targetId` | authenticateUser | `manage_projects` | Update label / enabled. target_url immutable (delete+recreate to migrate). |
| POST | `/api/projects/:projectId/dast/targets/:targetId/recheck-runtime` | authenticateUser | `manage_projects` | Force re-probe SPA detection. Updates `detected_runtime` + TTL. Idempotent. |
| DELETE | `/api/projects/:projectId/dast/targets/:targetId` | authenticateUser | `manage_projects` | Cascade-deletes credentials + findings + scan_jobs. |
| GET | `/api/projects/:projectId/dast/targets/:targetId/credentials` | authenticateUser | `manage_integrations` | Returns redacted `DastCredentialSummaryDTO`. Per pragmatist-r2-f15: gated by `manage_integrations` (closer to "handles secrets" than `manage_projects`). |
| PUT | `/api/projects/:projectId/dast/targets/:targetId/credentials` | authenticateUser | `manage_integrations` | Set / replace credential. Body: `DastCredentialUpsertDTO`. Server runs validation: JWT exp claim ≥ 1.5× scan_timeout_minutes; one-shot login probe (form: POST username+password+check `logged_in_indicator` matches AND `logged_out_indicator` does not); 422 on failure BEFORE encrypt/store. |
| DELETE | `/api/projects/:projectId/dast/targets/:targetId/credentials` | authenticateUser | `manage_integrations` | Remove credential — target reverts to anonymous. |
| POST | `/api/projects/:projectId/dast/scan` | authenticateUser | `manage_projects` | Body: `{ target_id }`. Re-runs SSRF check on target's URL pre-flight. Re-runs SPA-detect if `detected_runtime_ttl_at < NOW()`. Routes via `queue_scan_job` with `p_target_id` set. Returns 503 when `INTERNAL_DAST_PAUSED=true` (drain runbook). |
| GET | `/api/projects/:projectId/dast/jobs` | authenticateUser | view | Existing — accepts `?target_id=...` filter. |
| GET | `/api/projects/:projectId/dast/findings` | authenticateUser | view | Existing — accepts `?target_id=...` filter. |

### Three-layer cross-tenant guard

Every targetId-bearing endpoint runs `loadTargetOrDeny` from `backend/src/lib/dast-tenant-guard.ts`:

```typescript
// backend/src/lib/dast-tenant-guard.ts
export interface LoadedTarget {
  id: string;
  project_id: string;
  organization_id: string;
  target_url: string;
  detected_runtime: 'unknown' | 'classic' | 'spa';
  detected_runtime_ttl_at: string | null;
}

/**
 * Returns 404 (not 403, not 422 — 404 prevents existence enumeration; same elapsed
 * time within 50ms whether target exists in another tenant or doesn't exist) when
 * (target.project_id, target.organization_id) ≠ (expected project, expected org).
 */
export async function loadTargetOrDeny(
  supabase: SupabaseClient,
  targetId: string,
  expectedProjectId: string,
  expectedOrganizationId: string
): Promise<{ target: LoadedTarget } | { status: 404; reason: 'target_not_found' }>;
```

Every route handler that takes `:targetId` calls this immediately after `resolveProjectAccess`. Worker-side, `pipeline.ts` SELECTs target + project + scan_jobs in a single query and asserts all three `organization_id`s match; on mismatch emits `error_category='tenant_drift_detected'` with the three observed org IDs in `error_payload`, does NOT decrypt.

### Types (in `backend/src/types/dast.ts`)

```typescript
export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';
// v2.1a: form|jwt|cookie. 'recorded' added in v2.1d.
export type DastAuthStrategy = 'form' | 'jwt' | 'cookie';
export type DastDetectedRuntime = 'unknown' | 'classic' | 'spa';
export type DastAuthState = 'anonymous' | 'authenticated' | 'authentication_lost';
// v2.1a inserts 'zap' only. 'nuclei' / 'merged' added in v2.1c.
export type DastEngine = 'zap';

export interface DastTargetDTO {
  id: string;
  target_url: string;
  label: string | null;
  enabled: boolean;
  detected_runtime: DastDetectedRuntime;
  detected_runtime_at: string | null;
  detected_runtime_ttl_at: string | null;
  has_credentials: boolean;
  auth_strategy: DastAuthStrategy | null;
  active_dast_run_id: string | null;
  last_scanned_at: string | null;
  created_at: string;
}

export interface DastScopeConfig {
  include_patterns?: string[];
  exclude_patterns?: string[];
  header_rules?: { name: string; value: string; scope: 'all' | 'requests' | 'responses' }[];
}

export interface DastConfigDTO {
  scan_profile: DastScanProfile;
  scan_timeout_minutes: number;
  scope_config: DastScopeConfig;
  targets: DastTargetDTO[];
}

// Per multi-tenant-design-auditor-f4/r2-f11 P1: locked redaction caps.
// token_prefix: first 8 chars + '…' (NOT 12 — JWT 'eyJhbGciOi' is 10 chars and reveals algorithm)
// username: masked first-char + '***@<domain>' truncated to 24 chars total
// cookie_names: capped at 10 items, each name truncated to 32 chars
// last_step_url: scheme + host only (NEVER path/query/fragment)
export interface DastCredentialSummaryDTO {
  auth_strategy: DastAuthStrategy;
  payload_summary:
    | { kind: 'form'; username_masked: string }
    | { kind: 'jwt'; token_prefix: string; token_length: number; expires_in_minutes: number }
    | { kind: 'cookie'; cookie_count: number; cookie_names: string[] };
  logged_in_indicator: string | null;
  logged_out_indicator: string | null;
  updated_at: string;
}

export interface DastCredentialUpsertDTO {
  auth_strategy: DastAuthStrategy;
  payload:
    | { kind: 'form'; login_url: string; username_field: string; password_field: string; username: string; password: string }
    | { kind: 'jwt'; token: string }
    | { kind: 'cookie'; cookies: { name: string; value: string; domain?: string; path?: string }[] };
  logged_in_indicator?: string;
  logged_out_indicator?: string;
}

// Existing DastFindingDTO gains target_id + auth_state + engine.
```

### Cred storage rules

`backend/src/lib/dast-encryption.ts` mirrors `ai/encryption.ts`:

```typescript
export function encryptCredential(plaintext: string, keyVersion?: number): { encrypted: string; version: number };
export function decryptCredential(encrypted: string, storedVersion: number): string;
export function isDastEncryptionConfigured(): boolean; // checks DAST_CREDENTIAL_KEY
```

**Architectural invariant (test-enforced — cluster-2 patch):**

Decrypted plaintext NEVER appears in:
1. `scan_jobs.payload`
2. `scan_jobs.error_details`
3. `extraction_logs` / `dast_logs` rows
4. Worker stderr / stdout
5. QStash payload
6. Crash trace dumps

Test gate: `backend/src/lib/dast-log-scrub.ts` runs a structured-log scrub regex over a fixture run; assertion `expect(scrubMatches).toEqual([])`. Fixture run feeds known plaintexts (synthetic password `s3cr3t-fixture`, synthetic JWT `eyJhbGciOiJIUzI1NiJ9.testpayload.testsig`) into the pipeline, asserts NONE appear in any captured log.

**Scope_config validation (P1 patch):**

- Rejects header names matching `/^(Authorization|Cookie|X-Api-Key|X-Auth-Token|X-CSRF-Token)$/i` OR `/(token|secret|password|key)/i` with 422 "use credential panel for sensitive headers."
- Each regex pattern length capped at 256 chars.
- Static check rejects nested unbounded quantifiers: `(.+)+`, `(a*)*`, etc.
- safe-regex2 (or equivalent) compile + 100ms-timeout test against synthetic 1000-char URL. If timeout: 422 "regex pattern too expensive."

**JWT validation at PUT time (P1 patch):**

- Decode (no signature verify): `JSON.parse(Buffer.from(token.split('.')[1],'base64').toString())`.
- Reject 422 if `exp` missing OR `(exp - nowSecs) < (1.5 * scan_timeout_minutes * 60)`.
- Document via UI hint: "Token expires in 12 minutes; scans take up to 30 — use a longer-lived token."

**Form login probe at PUT time (P1 patch):**

- One-shot HTTP POST to `payload.login_url` with `username_field=username&password_field=password`.
- Check response body: `logged_in_indicator` regex matches AND `logged_out_indicator` regex does not match on same response.
- If both fire on same response: 422 "logged_out_indicator matches the post-login page; fix your regex."
- "Test against URL" button (Burp Enterprise pattern) calls this same endpoint with `dry_run=true`.

## Frontend Design

### Pages & routes

No new top-level routes. Settings → Scanning tab continues at `/organizations/:orgId/projects/:projectId/settings/scanning`.

### Component tree

```
DastScanningTab (multi-target shell)
├── ProfileAndTimeoutCard           (project-wide: scan_profile + scan_timeout_minutes)
├── ScopeRulesCard                  (project-wide scope_config)
│   └── DastScopePanel
│       ├── IncludeExcludePatternList  (regex compile error tooltips)
│       └── HeaderRulesList            (sensitive-header rejection toast)
├── TargetsCard
│   └── DastTargetsList
│       └── DastTargetRow ×N
│           ├── TargetMetaSummary    (URL, label, runtime badge, last scan)
│           ├── AuthStatusChip       ("Anonymous" / "Form" / "JWT" / "Cookie")
│           ├── ScanNowButton        (per-target; opens ActiveScanOptInDialog when profile=full)
│           ├── EditButton           (opens DastTargetEditDialog)
│           └── DeleteButton         (confirmation per feedback_dialog_pattern)
├── HistoryCard                     (existing scan_jobs table; +target column)
└── DastTargetEditDialog            (slide-in from right per slide-in-sidebars pattern)
    ├── TargetUrlInput               (immutable on existing target — read-only)
    ├── LabelInput
    ├── DastAuthPanel
    │   ├── StrategySelect           (form | jwt | cookie — no 'recorded' in v2.1a)
    │   ├── (per-strategy form group)
    │   ├── LoggedInIndicatorInput
    │   ├── LoggedOutIndicatorInput
    │   └── TestAgainstUrlButton     (one-shot login probe)
    └── EnabledSwitch

ActiveScanOptInDialog               (matches feedback_dialog_pattern)
├── DestructiveWarningBlock
├── TargetUrlConfirm                 (must match by typing)
└── OutlineCancel + DestructiveConfirm
```

### Design specifications

Per `frontend-design` skill:

- **TargetsCard**: `rounded-lg border border-border bg-background-card`; header `px-4 py-3 border-b border-border` with title `text-sm font-semibold`. Each `DastTargetRow` is `flex px-4 py-3 hover:bg-table-hover transition-colors`.
- **AuthStatusChip**: outline variant for anonymous; subtle success for configured auth.
- **DastTargetEditDialog**: slide-in from right, `max-w-[640px] bg-background-card border-l`. Header `px-5 pt-5 pb-4 border-b`. Save button outline variant per `feedback_button_style`.
- **ActiveScanOptInDialog**: matches `feedback_dialog_pattern` exactly — two-tone popup, `hideClose`, outline Cancel + bordered destructive Confirm. Reference: `aegis/ThreadList.tsx`.
- **Detected-runtime badge**: outline pill — "Classic" (foreground-secondary), "SPA" (info), "Unknown" (foreground-muted with re-probe tooltip per ux-walker P1).
- **No `/30` or `/40` opacity** on body text/icons per `feedback_vercel_typography`.
- **Pixel-perfect** per `feedback_pixel_perfectionism`: 1-2px tweaks during browser sign-off, no restructures.

### State management

- `DastScanningTab` fetches `GET /api/projects/:projectId/dast/config` on mount → drives whole tab from single state object.
- Realtime: existing `scan_jobs` channel (`project_id=eq.:projectId`) + new channel on `project_dast_targets` (filter `project_id=eq.:projectId`).
- Per `feedback_react_stale_state`: track `editingTargetId` separately, clear on dialog close.
- ActiveScanOptInDialog confirmation memo'd per-target in `localStorage` keyed by `target_id`.

### Empty / loading / error states

- **Empty (no targets)**: TargetsCard centered prompt — "Add a target URL to start scanning. DAST runs against your deployed app, so use staging if you have one." + outline "Add target" CTA.
- **Empty (one target, never scanned)**: row shows "No scans yet" muted text + outline "Scan now" button.
- **Loading**: skeleton via `bg-muted animate-pulse rounded`.
- **Error**: toast via `useToast`. Per `feedback_no_raw_errors_to_users`: generic "Failed to save target" + push real error to `console.error`.
- **Tenant-drift error from worker**: row shows red "Scan failed: tenant verification" badge with deep-link to support.
- **Drain mode (503 from POST /scan)**: ScanNowButton disabled with tooltip "DAST queue is paused for maintenance" when `INTERNAL_DAST_PAUSED=true`.

### Auth-failure UI (P1 patch — auth_state as job-state, not finding)

Per architect-f9 + ux-walker-r2-f1 P1 patch: `authentication_lost` is **NOT** a finding row. Pipeline writes `scan_jobs.error_category='auth_failed'` + `scan_jobs.error_payload.consecutive_lost_count`. Findings collected before auth loss stay tagged `auth_state='authentication_lost'`.

`DastTargetRow` reads from `scan_jobs.error_category` for the most recent scan and shows banner: "Authentication lost during scan (3 consecutive `loggedOutIndicator` matches at /admin/users). [Edit indicators]" — deep-link opens `EditDialog` scrolled to `LoggedOutIndicatorInput`.

## Implementation Tasks

Each independently shippable. Sizes: S (≤4hr), M (4-12hr), L (1-3 days), XL (≥3 days).

### Task 1 — Schema migration phase24a (additive only) + wrapper RPCs (M)

**Files:** `backend/database/phase24a_dast_v2_engine_additive.sql` (new), `backend/database/schema.sql` (regenerated).

**Acceptance:**
- Migration applies cleanly via Supabase MCP against dev DB.
- Two-pass backfill seeds at least one `project_dast_targets` row per project that has any `project_dast_config` row; orphan count for `findings.target_id IS NULL` logged via RAISE NOTICE (non-blocking).
- New `commit_dast_target_run(p_target_id, p_dast_run_id)` exists; legacy `commit_dast_run(p_project_id, p_dast_run_id)` exists as a wrapper that delegates via "first target row for project."
- New `queue_scan_job` accepts optional `p_target_id` arg (NULL → resolves to first target); legacy callers pass NULL and get correct behavior. Tenant-drift assertion fires on cross-project / cross-org targetId. 5/org cap enforced for any `dast*` type.
- `project_dast_targets` and `project_dast_credentials` have SELECT + INSERT + UPDATE + DELETE RLS policies with WITH CHECK clauses.
- Verification SELECT: `SELECT COUNT(*) FROM scan_jobs WHERE type IN ('dast','dast_zap','dast_nuclei') AND status IN ('queued','processing')` returns 0 (drain runbook precondition).
- Schema dump regenerated **on the feature branch** (per `feedback_schema_dump_rebase`).
- PGLite e2e migration applies clean.

### Task 1.5 — Pre-migration drain runbook + deploy DAG (S)

**Files:** `docs/runbooks/dast-v2-1a-deploy.md` (new), `backend/src/index.ts` (drain-mode middleware).

**Acceptance:**
- Drain middleware: when `INTERNAL_DAST_PAUSED=true`, `POST /api/projects/:projectId/dast/scan` returns 503 `{ error: 'dast_queue_paused' }`. All other routes pass through.
- Runbook documents the deploy DAG:
  1. Set `INTERNAL_DAST_PAUSED=true` on backend API + Vercel env.
  2. Wait until `SELECT COUNT(*) FROM scan_jobs WHERE type IN ('dast','dast_zap','dast_nuclei') AND status IN ('queued','processing')` = 0 (poll, max 60min, kill stuck via existing `fail_exhausted_scan_jobs` cron).
  3. Roll out depscanner image with the dual-call shim — worker handles both old `commit_dast_run` and new `commit_dast_target_run` callbacks.
  4. Apply phase24a via Supabase MCP (per `feedback_apply_migrations_via_mcp`).
  5. Roll out backend API with new `queue_scan_job` call shape + new routes reading from `project_dast_targets`.
  6. Unset `INTERNAL_DAST_PAUSED`.
  7. Monitor ≥7 days (≥30 days for prod). Verify `pg_stat_user_functions` shows zero calls to legacy `commit_dast_run(uuid, text)` two-arg signature in last 24h before applying phase24b.
- Step 3→4 sequence non-negotiable (worker must speak both signatures before migration applies).

### Task 2 — Backend types + encryption + tenant guard + log scrub (M)

**Files:** `backend/src/types/dast.ts` (extended), `backend/src/lib/dast-encryption.ts` (new), `backend/src/lib/dast-tenant-guard.ts` (new), `backend/src/lib/dast-log-scrub.ts` (new).

**Acceptance:**
- `encryptCredential` + `decryptCredential` round-trip across `DAST_CREDENTIAL_KEY` rotation (current + previous key fallback).
- `isDastEncryptionConfigured()` returns false when env unset; routes refuse credential PUT with 503 `{ error: 'dast_encryption_not_configured' }`.
- `loadTargetOrDeny`: returns 404 (not 403/422) on cross-project / cross-org targetId mismatch. Test fixture: timing parity within 50ms regardless of target existence.
- `dast-log-scrub`: scrub regex catches synthetic password fixture + JWT fixture in any structured log row.
- Unit tests cover all 3 v2.1a strategies (form, jwt, cookie) payload shapes.
- New env var `DAST_CREDENTIAL_KEY` documented in `backend/.env.example` + `DEVELOPERS.md`.

### Task 3 — Backend routes: targets + form/JWT/cookie creds CRUD (L)

**Files:** `backend/src/routes/dast.ts` (rewrite), referenced from `backend/src/index.ts` (already mounted).

**Acceptance:**
- All 13 endpoints from API table return correct DTOs against freshly-migrated DB.
- Three-layer cross-tenant guard: every `:targetId` route runs `loadTargetOrDeny` immediately after `resolveProjectAccess`. Route returns 404 on cross-tenant targetId.
- SSRF guard at every target URL ingress (POST + PATCH + scan trigger).
- Credential PUT runs JWT exp validation + form login probe before encrypt/store. 422 on validation failure with structured `error_code` (`jwt_expired_too_soon`, `login_probe_failed_indicator_collision`, etc.).
- Credential summaries never leak encrypted_payload / password / token / cookie value. Locked redaction caps per multi-tenant-design-auditor-f4 (token_prefix 8 chars, username masked first-char, cookie_names capped at 10).
- 422 returned on invalid scope_config: regex compile-and-test, sensitive-header-name rejection, ReDoS pattern rejection.
- POST /scan returns 503 when `INTERNAL_DAST_PAUSED=true`.
- Concurrency: queueing a scan against `target_id=X` while another scan_job for same target is processing returns 409 `project_concurrent_dast_blocked`.
- POST /scan triggers SPA-detect probe synchronously when target's `detected_runtime_ttl_at < NOW()`; passes `detected_runtime` to `queue_scan_job` for machine-shape dispatch.
- All test cases use `setTableResponse` for first-call mocks, `pushTableResponse` for queue (per `backend_test_mock_patterns`); 403 paths use `/permission|access/i` regex; cross-tenant paths use parametrized cross-tenant test (Org A user + Org B targetId → 404, NOT 403).
- Per `feedback_no_raw_errors_to_users`: surface generic errors; real cause to `console.error`.
- Per `feedback_no_validation_on_autosave`: heavyweight validation (login probe, JWT decode) only on Test/Activate paths, not on every PUT.

### Task 4 — DAST_CONFIG branched on detected_runtime (S)

**Files:** `backend/src/lib/fly-machines.ts` (modified).

**Acceptance:**
- `getDastMachineConfig(detectedRuntime: 'unknown'|'classic'|'spa')` returns:
  - `'classic'` → `shared-cpu-4x` 8GB
  - `'unknown'` OR `'spa'` → `performance-4x` 16GB (first scan + SPA scans)
- `queue_scan_job` payload includes `detected_runtime`; Fly machine-start invocation reads from payload to pick config.
- POST /scan route resolves `detected_runtime` BEFORE queueing (route runs SPA-detect when TTL expired; otherwise uses cached value).
- After first scan classifies a target as `'classic'`, second scan provisions on `shared-cpu-4x` 8GB (downsize verified via Fly logs).

### Task 5 — Depscanner runner: YAML AF builder behind DAST_RUNNER_MODE flag (L)

**Files:** `backend/depscanner/src/dast/yaml-builder.ts` (new), `backend/depscanner/src/dast/runner.ts` (modified — DUAL path), `backend/depscanner/src/dast/auth-config.ts` (new).

**Acceptance:**
- Worker reads `organizations.dast_runner_mode` via `claim_scan_job` payload extension; falls back to env `DAST_RUNNER_MODE` (default `helper_script`).
- Helper-script path **stays live and is the default**. v1 anonymous baseline + api scan tests pass unchanged.
- `buildAutomationYaml(opts)` returns valid YAML with right job order: `addOns` → `passiveScan-config` → `replacer` (header rules + JWT auth) → `authentication` (form / cookie) → `spider` or `spiderAjax` → `browserBased` (when SPA) → `activeScan` (when profile=`full`) → `report`.
- Auth strategy → ZAP method: `form` → `formBasedAuthentication`; `jwt` → `replacer` Bearer header rule; `cookie` → `replacer` Cookie header rule. **`recorded` not handled in v2.1a; throws `dast_strategy_not_supported_in_v2_1a` if encountered.**
- `loggedInIndicator` / `loggedOutIndicator` regex emitted on the authentication job for form strategy.
- Scope: `context.includePaths` + `context.excludePaths` in YAML.
- `runZap()` invokes either `/zap/zap.sh -cmd -autorun /path/to/automation.yaml` (when AF mode) or existing helper script (default). Behavioral parity test: AF YAML against `auth_strategy=null + scope=empty + spa=false` produces v1 anonymous-baseline finding count ±10% on Juice Shop.
- v1 tests in `dast-runner.test.ts` still pass.

### Task 6 — SPA detection (S)

**Files:** `backend/depscanner/src/dast/spa-detect.ts` (new) — also imported by API route in Task 3.

**Acceptance:**
- `detectRuntime(targetUrl, opts)`: HTTP GET with 15s timeout, 3 redirect follow-cap, `User-Agent: Deptex-DAST-Probe/2.1`. Reads `Content-Type: text/html` body; matches against runtime-marker regex set: `data-reactroot`, `id="__nuxt"`, `id="__next"`, `data-server-rendered`, `<app-root`, `id="svelte"`, plus heuristic for empty-shell apps (`<script` count ≥4 + body innerHTML ≤500 chars).
- Returns `{ runtime: 'classic'|'spa'|'unknown', confidence: number, markers: string[] }`.
- On fetch failure / non-HTML / timeout → `{ runtime: 'unknown' }`.
- Caller (route OR worker) writes `{ detected_runtime, detected_runtime_at, detected_runtime_ttl_at }` back to `project_dast_targets`.
- TTL: `detected_runtime_ttl_at = NOW() + INTERVAL '30 days'` on every successful probe.
- Force-recheck endpoint hits this same function with `force=true`.

### Task 7 — Depscanner pipeline: cred load + auth_state + control plane (L)

**Files:** `backend/depscanner/src/dast/pipeline.ts` (rewrite), `backend/depscanner/src/dast/control-plane.ts` (new), `backend/depscanner/src/index.ts` (job-claim filter).

**Acceptance:**
- New flow: claim job → resolve `target_id` → SELECT target+project+scan_jobs in single query, assert all 3 `organization_id` match, abort with `error_category='tenant_drift_detected'` on mismatch (do NOT decrypt).
- Worker hard-fails on missing/stale `DAST_CREDENTIAL_KEY`:
  - `target.has_credentials=true` + `isDastEncryptionConfigured()=false` → abort with `error_category='dast_credential_key_missing'`.
  - `target.has_credentials=true` + `decryptCredential` throws after current+prev fallback → abort with `error_category='dast_credential_key_stale'`.
  - **Pipeline never runs anonymous scan when target.has_credentials=true** (this is the non-negotiable invariant).
- Job-claim-time filter: worker startup probes `isDastEncryptionConfigured()`; on false, `claim_scan_job` filters DAST jobs out (queue backpressure rather than per-job silent failure).
- Decrypt-just-before-spawn: plaintext exists only inside `buildAutomationYaml()` call frame; `Buffer.fill(0)` zero-out immediately after YAML emission.
- `auth_state` populated on every finding: `'authenticated'` when cred loaded + ZAP didn't trip `loggedOutIndicator` >3 times; `'authentication_lost'` when it did; `'anonymous'` otherwise.
- **`authentication_lost` as job-state, not finding** (P1 patch): pipeline writes `scan_jobs.error_category='auth_failed'` + `scan_jobs.error_payload={consecutive_lost_count, last_logged_out_url, last_logged_out_at}`. NO synthetic finding row inserted. Findings collected before loss stay tagged `auth_state='authentication_lost'`.
- `consecutive_lost_count` gates on response status (only 200/302/401; ignore 5xx + 4xx-other-than-401) + debounce window (4 trips in 5-min window AND no successful indicator-clear in between).
- **Subprocess control plane:** `spawnExternal` returns `{process, abort()}` handle. `abort()` does `process.kill(-pid, 'SIGTERM')` + 10s timer + `process.kill(-pid, 'SIGKILL')` for entire process group. Pipeline holds the handle and calls `abort()` on (a) cancellation poll between phases, (b) >3 `loggedOutIndicator` hits via stderr-watcher, (c) scan_timeout. Frontend ScanNowButton becomes Idle/Running/'Stop scan' stateful; PATCH scan_jobs SET cancellation_requested=true; max-time-to-stop ≤30s.
- Atomic-commit via NEW `commit_dast_target_run(target_id, dast_run_id)`.
- Heartbeat continues firing during scan (existing `processJob` interval timer).

### Task 8 — Frontend: targets list + auth panel (form/JWT/cookie) + scope panel (L)

**Files:** `frontend/src/components/dast/DastScanningTab.tsx` (rewrite), `DastTargetsList.tsx` (new), `DastTargetEditDialog.tsx` (new), `DastAuthPanel.tsx` (new), `DastScopePanel.tsx` (new), `frontend/src/lib/api.ts` (extended).

**Acceptance:**
- Component tree matches spec.
- StrategySelect shows form / jwt / cookie only (NO `recorded` option in v2.1a — this is the visible signal that recorded-login is v2.1d).
- Realtime: `scan_jobs` channel update → refresh `jobs[]` AND `targets[]`. Second channel on `project_dast_targets`.
- AuthPanel renders correct inputs per strategy; saving empty payload → 422 toast with structured error code.
- TestAgainstUrl button calls login-probe endpoint; surfaces validation success/failure inline.
- ScopePanel: invalid regex → red border + tooltip with compile error. Sensitive header name → red border + "Use credential panel for sensitive headers."
- Auth-failure banner reads from `scan_jobs.error_category='auth_failed'`; shows consecutive_lost_count + deep-link to LoggedOutIndicatorInput.
- ActiveScanOptInDialog blocks scan trigger ONLY when `scan_profile='full'` (auto is now passive-only — locked decision; no escalation path through auto). Per-target memo in `localStorage`.
- ActiveScanOptInDialog matches `feedback_dialog_pattern` exactly: two-tone popup, hideClose, outline Cancel + bordered destructive.
- Browser sign-off (per `feedback_visual_redesign_iteration`): ship targets list first → pixel feedback → then auth/scope panels.

### Task 9 — Tests + integration coverage (L)

**Files:** `backend/depscanner/src/__tests__/dast-spa-detect.test.ts`, `dast-yaml-builder.test.ts`, `backend/src/lib/__tests__/dast-encryption.test.ts`, `dast-tenant-guard.test.ts`, `dast-log-scrub.test.ts`, `backend/src/routes/__tests__/dast-targets.test.ts`, `dast-credentials.test.ts`, `backend/depscanner/src/__tests__/dast-pipeline-pglite.test.ts`.

**Acceptance:**
- **Cross-tenant tests** (cluster-3, P0): every `:targetId` route gets parametrized cross-tenant case (Org A user + Org B targetId → 404 with timing parity). Test pattern uses 404-not-403 assertion (the `/permission|access/i` regex from old plan is structurally insufficient).
- **Encryption rotation:** round-trip across current+previous keys; reject malformed ciphertexts; reject mismatched key versions.
- **Silent-anonymous-fallback prevention** (cluster-2, P0): test forces `target.has_credentials=true` + `DAST_CREDENTIAL_KEY` missing — assert pipeline aborts with `error_category='dast_credential_key_missing'`, NOT runs anonymous scan.
- **Log-scrub regression:** synthetic password + JWT fixture fed through pipeline; assert NONE of fixtures appear in scan_jobs.payload, scan_jobs.error_details, dast_logs, stderr capture, QStash payload.
- **Auth_state state machine:** parametrized: (anonymous, no cred) → 'anonymous'; (form cred + 0 logged_out hits) → 'authenticated'; (form cred + 4 logged_out hits in 5min window) → 'authentication_lost' + scan_jobs.error_category='auth_failed' + NO synthetic finding row.
- **Migration backfill PGLite:** seed 3 projects with mix of existing dast_config rows + findings; apply phase24a; assert 1 target row per project, findings.target_id backfilled where matchable, orphan count logged.
- **YAML AF builder snapshot** per (auth_strategy × scan_profile × spa_detected) combo.
- **SPA detect** against fixture set: React/Vue/Angular/Next/Nuxt/Svelte/classic SSR HTML samples.
- **Concurrency:** queueing scan against target X while scan_job for X is processing → 409 `project_concurrent_dast_blocked`.
- **Drain mode:** when `INTERNAL_DAST_PAUSED=true`, POST /scan returns 503.
- **Tenant-drift abort:** worker-side test forces target.organization_id ≠ project.organization_id; assert pipeline aborts with `error_category='tenant_drift_detected'` and credential never decrypted.
- All test mocks per `backend_test_mock_patterns`.

### Task 10 — Real-Docker e2e against Juice Shop with form auth (M)

**Files:** ad-hoc test script (not committed), updated `dast_v1_state.md` follow-up checklist.

**Acceptance:**
- Build new image: `docker build` on `backend/depscanner`.
- Run depscanner against Juice Shop on port 13000 (already running per v1 state memo).
- Configure form auth (`admin@juice-sh.op` / `admin123`); confirm `auth_state='authenticated'` on ≥50% of resulting findings.
- Confirm SPA detection fires (Juice Shop is Angular SPA): `detected_runtime='spa'` on target row after first scan; second scan provisions `performance-4x` 16GB.
- Run scan with `loggedOutIndicator=Login`; force session expiry mid-scan; confirm `scan_jobs.error_category='auth_failed'` set + NO synthetic `authentication_lost` finding row + findings collected before loss tagged `auth_state='authentication_lost'`.
- Behavioral parity: AF YAML mode against anonymous baseline produces finding count ±10% of helper-script mode against same target.
- Per `feedback_docker_vs_source_e2e`: real-Docker run scheduled before merge.

## Testing & Validation Strategy

### Backend

- **Routes:** every endpoint gets at least one happy-path + one 403 + one 422 + one cross-tenant 404 + one drain-mode 503 test. Mocks per `backend_test_mock_patterns`.
- **Encryption:** rotation; reject malformed; reject mismatched key versions; key-missing aborts.
- **Tenant guard:** parametrized cross-tenant matrix; timing-parity assertion (within 50ms); RLS WITH CHECK enforced via direct supabase-anon-key fixture.
- **Log scrub:** synthetic plaintexts NEVER appear in any captured log row.
- **YAML builder:** snapshot per (auth × profile × spa).
- **Concurrency:** in-flight scan + new POST /scan → 409.
- **JWT / login-probe validation:** at PUT time only (autosave skips per `feedback_no_validation_on_autosave`).

### Frontend

- Component tests for `DastTargetsList`, `DastAuthPanel`, `DastScopePanel`. Happy-path + error toasts.
- Realtime regression: scan_jobs row insert refreshes targets list within 2s.
- ActiveScanOptInDialog opens only on `profile='full'`; auto profile triggers scan WITHOUT dialog.

### End-to-end

- **PGLite local mode:** seed project + 2 targets + creds; queue scan; mock pipeline result; verify atomic-commit flips per-target pointer; verify findings filtered by target_id.
- **Real Docker (Task 10):** Juice Shop ground-truth signal. Per `feedback_docker_vs_source_e2e`: required before merge.
- **Browser walkthrough** per `feedback_visual_redesign_iteration`: targets list → pixel feedback → auth/scope panels.

### Performance targets

- Settings → Scanning load: ≤300ms p50 with ≤20 targets.
- POST /scan response: ≤500ms p50 (includes SSRF DNS + SPA-detect-when-stale + Fly machine-start dispatch).
- ZAP runtime: ≤45min for `scan_profile='full'` on 200-route SPA target.
- SPA-detect probe: ≤15s hard cap.
- Login probe: ≤8s hard cap.

### Regression guard

- v1 anonymous baseline + api scans must continue working — Task 5 helper-script default keeps v1 path live.
- Existing `commit_dast_run(p_project_id, p_dast_run_id)` callers (recovery cron, any backed-baked workers) keep working via wrapper.
- Schema dump regenerated on feature branch (per `feedback_schema_dump_rebase`).

## Risks & Open Questions

### Risks

- **R1 — Drain-and-deploy DAG complexity.** Task 1.5 requires API → drain → worker → migration → API order. Operator error skips a step. Mitigation: runbook is explicit; CI gate that asserts drain count = 0 before phase24a applies.
- **R2 — YAML AF parity gap.** When AF flag flips to `automation_framework`, AF must reproduce v1 anonymous-baseline finding count ±10%. If parity fails, helper-script stays default; phase24b drop blocked. Mitigation: behavioral-parity test in Task 10 is the gate for phase24b.
- **R3 — Login probe false-fail.** Form login probe at PUT time may fail against apps that require CSRF token or pre-login GET to set session cookie. Mitigation: probe runs as best-effort warning, not hard 422 reject — flag for `/implement` to refine after first user feedback.
- **R4 — SPA detect false negative.** Server-rendered Next.js apps with hydration markers but classic-spider-friendly URLs get classified `spa` and burn `performance-4x` budget. Mitigation: cache + 30-day TTL + force-recheck endpoint; revisit heuristic in v2.2 if cost shows.
- **R5 — Tenant-drift abort surface.** When `tenant_drift_detected` fires, the scan_job is in a terminal state but the user has no UI signal beyond a generic "scan failed" badge. Mitigation: structured error_payload includes the three observed org IDs; debug endpoint surfaces this for support; v2.2 finding-detail page exposes it more cleanly.
- **R6 — Wrapper RPC call-site discovery.** Phase24b can only drop legacy `commit_dast_run(uuid, text)` after `pg_stat_user_functions` shows zero calls. If a long-tail caller (recovery cron, manual ops query) keeps calling, phase24b stalls. Mitigation: Task 1.5 runbook step 7 explicitly enumerates expected call-sites; pg_stat poll-and-alert during shadow window.

### Open questions

- **Q1 (defer to /implement, low):** SPA detection probe — follow redirects up to 3? Default to follow-up-to-3.
- **Q2 (defer to /implement, low):** Login probe SSRF coverage — apply same `url-guard` rules as scan target ingress? Default yes.
- **Q3 (defer to /implement, low):** ScanNowButton 'Stop scan' state — hard-cap at 30s before showing "Force kill" tooltip? Empirical decision.
- **Q4 (defer to v2.1b plan):** Phase24b acceptance threshold — finding count parity ±10% on Juice Shop OR also ±5% on a second test target (DVWA)? Decide during v2.1b planning.
- **Q5 (informational, blocks nothing):** Per-org `dast_runner_mode` flag — should we expose UI for per-org override during the shadow window, or keep flag as ops-team-only env var? Lean toward env-only for v2.1a; revisit if shadow window reveals per-org variance.

## Dependencies

- **Existing v1 schema:** `project_dast_config`, `project_dast_findings`, `commit_dast_run`, `queue_scan_job`, `scan_jobs.type='dast'` all in place per `phase23b_dast_schema.sql`.
- **AES-256-GCM pattern:** `backend/src/lib/ai/encryption.ts` is the template for `dast-encryption.ts`.
- **SSRF guard:** `backend/src/lib/url-guard.ts` reused unchanged.
- **Worker dispatch:** `backend/depscanner/src/index.ts:processJob` already routes `type='dast'` to `runDastPipeline`.
- **Cross-link:** v1 logic in `pipeline.ts:crossLinkFinding` reused unchanged.
- **Fly machine sizing:** `DAST_CONFIG` in `backend/src/lib/fly-machines.ts` modified to branch on `detected_runtime` (Task 4).
- **Two-phase migration pattern:** see `feedback_two_phase_migration_pattern` memory; this plan is the first application of the formalized pattern.

## Success Criteria

- All 10 tasks land; PGLite e2e + real-Docker e2e (Juice Shop) both green.
- Authenticated form scan against Juice Shop produces ≥50% of findings with `auth_state='authenticated'`.
- SPA detection correctly classifies Juice Shop as `detected_runtime='spa'` on first scan; second scan provisions `performance-4x` 16GB; classic-runtime target downsizes to `shared-cpu-4x` 8GB.
- Multi-target: project with 2 targets shows independent active_dast_run_id pointers + independent finding lists.
- Scope rules: exclude pattern on `^/admin/` results in zero findings against URLs matching that pattern.
- `auth_failed` state surfaces in UI banner (NOT as a synthetic finding row); deep-link to LoggedOutIndicatorInput works.
- Cross-tenant test: Org A user passing Org B targetId → 404 across all 7 targetId-bearing endpoints.
- Worker hard-fails on missing/stale `DAST_CREDENTIAL_KEY`; never runs anonymous scan when `target.has_credentials=true`.
- Log scrub: zero plaintext password/token/cookie substrings in any captured log row across full Juice Shop scan.
- Drain-mode middleware returns 503 when `INTERNAL_DAST_PAUSED=true`.
- Helper-script mode (default) reproduces v1 anonymous-baseline finding count exactly. AF YAML mode reproduces it ±10%.
- All v2.1a features run inside self-host depscanner Docker image without cloud dependencies.
- Settings → Scanning page loads ≤300ms p50 with 20 targets.

---

## After this plan

Recommended next: **`/review-plan dast-v2-1a-engine`** — multi-agent debate covers scope creep, schema risk, missed edge cases, and architectural soundness. The previous v2.1 plan got REWORK 12/0/0; v2.1a folds in all 5 P0 cluster patches + the load-bearing P1 patches, so this iteration should land READY or REVISE. Catches issues before `/implement` burns a day.

If review passes: `/implement dast-v2-1a-engine` runs all 10 tasks back-to-back per `feedback_implement_no_milestone_pause`.

After v2.1a ships and ≥7-day shadow window passes with `pg_stat_user_functions` showing zero legacy `commit_dast_run(uuid, text)` calls + Juice Shop AF YAML parity within ±10%: kick off `/plan-feature dast-v2-1b-cleanup` for the destructive half (drop legacy columns, flip NOT NULL, drop wrapper RPCs, drop `DAST_RUNNER_MODE=helper_script` flag).
