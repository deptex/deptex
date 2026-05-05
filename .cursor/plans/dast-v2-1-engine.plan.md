# DAST v2.1 Engine — Implementation Plan

## Overview

v2.1 closes the table-stakes gap between Deptex DAST and the rest of the market. The current scanner is a thin wrapper around three ZAP helper scripts (`zap-baseline.py` / `zap-full-scan.py` / `zap-api-scan.py`) running anonymous scans against a single `target_url`. v2.1 ships:

- **Hybrid engine**: ZAP active scan + Nuclei templates running side-by-side inside the same depscanner Fly machine, with results dedup-merged before insert.
- **Authenticated scanning** in four modes — form login, JWT/Bearer header injection, recorded login sequence (HAR replay), cookie injection — with AES-256-GCM encrypted credential storage.
- **SPA support** via runtime-marker auto-detection that switches the scan from AJAX spider to ZAP's `browserBased` job (real headless Chromium) when the target needs it.
- **Multi-target per project** through a new `project_dast_targets` junction table; each target carries its own active/previous run pointers, credentials, and detected runtime.
- **Scope controls** — include/exclude regex/glob patterns and header injection rules — surfaced via ZAP's `replacer` job + context include/exclude paths.
- **Auth-failure observability**: hard-fail + emit a structured `authentication_lost` finding when `loggedOutIndicator` fires more than three times mid-scan.
- **Concurrency caps**: per-project stays at 1; per-org rises 3 → 5.

The scope is locked in `.cursor/plans/feature-brief-dast-v2.md` (v2.1 section). This plan converts those locked decisions into a concrete task list.

## Competitive Research & Design Rationale

The brief's competitive research stays the source of truth — see `feature-brief-dast-v2.md` "Competitive Landscape" and "Landscape Synthesis." Key implications baked into this plan:

1. **ZAP Automation Framework as the AF spine**, not the helper scripts. The current runner shells out to Python helper scripts and passes args; v2.1 generates a YAML AF config (`automation.yaml`) and invokes `/zap/zap.sh -cmd -autorun /path/to/automation.yaml`. The AF exposes `authentication`, `browserBased`, `replacer`, `sequence-import`, `graphql`, `postman`, `script`, `alertFilter` jobs we don't currently wire — they replace the script-arg interface in one cut. ([ZAP AF docs](https://www.zaproxy.org/docs/automate/automation-framework/))
2. **Nuclei is a pinned binary, not a library**. ProjectDiscovery ships single-binary Linux releases + a `nuclei-templates` git repo. We pin both to specific versions in the Dockerfile, ship templates inside the image (~50 MB layer), and spawn Nuclei via `child_process.spawn` mirroring the existing ZAP wrapper. No SDK; result format is JSONL on stdout.
3. **Auth modes mirror Burp + StackHawk taxonomy**, not ZAP's lower-level model. ZAP supports `formBasedAuthentication`, `jsonBasedAuthentication`, `httpAuthentication`, `manualAuthentication`, `scriptBasedAuthentication` ([ZAP auth methods](https://www.zaproxy.org/docs/desktop/start/features/authmethods/)). We wrap these in Deptex strategy enums (`form` / `jwt` / `recorded` / `cookie`) and pick the underlying ZAP method per strategy: `form` → `formBasedAuthentication`, `jwt` → `httpAuthentication` Bearer + `replacer` rule, `cookie` → `replacer` rule on `Cookie` header, `recorded` → ZAP `sequence-import` of a HAR file. Burp-style `loggedInIndicator` / `loggedOutIndicator` regexes wired through ZAP's verification strategy.
4. **SPA detection by HTML markers, not by user toggle**. Survey of the field (StackHawk SPA blog, Checkmarx 2026 DAST guide, GitLab DAST browser-based) is unanimous: real headless Chromium is required for Vue/React/Angular. Auto-detect probes the target's HTML body for runtime markers (`data-reactroot`, `id="__nuxt"`, `<app-root>`, `id="__next"`, `data-server-rendered`, `id="svelte"`); cache the verdict on `project_dast_targets.detected_runtime` so repeat scans skip the probe. ([SPA DAST guide](https://www.stackhawk.com/blog/scanning-your-spa-with-dast-youre-doing-it-wrong/))
5. **HAR is the recorded-login interchange format**. ZAP's native `sequence-import` accepts HAR; Burp uses a proprietary recorded-login JSON format; Selenium IDE outputs `.side` JSON. HAR is the lowest-common-denominator that any browser DevTools (Chrome / Firefox / Safari) exports out-of-the-box, so users can record once and paste. We accept HAR only in v2.1; future work can normalize Selenium IDE / Burp formats.

## Codebase Analysis

### Existing patterns to reuse

- **AES-256-GCM encryption pattern** — `backend/src/lib/ai/encryption.ts` already implements `encryptApiKey` / `decryptApiKey` with key versioning + previous-key fallback for rotation, against `AI_ENCRYPTION_KEY` env var. v2.1 ships a parallel module against `DAST_CREDENTIAL_KEY` env var with identical shape.
- **Job-claim and dispatch loop** — `backend/depscanner/src/index.ts:114` (`runWorker`) + `:77` (`processJob`) already dispatch on `job.type`. v2.1 needs no changes here; the new pipeline runs inside the existing `processDastJob` branch.
- **Atomic-commit + active-pointer pattern** — `commit_dast_run` RPC in `phase23b_dast_schema.sql` flips `projects.active_dast_run_id`. v2.1 moves the pointer off `projects` and onto `project_dast_targets` (per-target) but keeps the same flip semantics.
- **SSRF guard** — `backend/src/lib/url-guard.ts` (DNS-resolved IP block-list) is reused unchanged for every new target URL.
- **Spawn wrapper for long-running children** — `backend/depscanner/src/dast/runner.ts:330` (`spawnZap`) generalizes to Nuclei without modification; rename to `spawnExternal`.
- **Suppression carry-forward** — `commit_dast_run` already joins prior-run findings on `(rule_id, handler_*, vulnerability_type)` for resolved rows and `(rule_id, endpoint_url, http_method, vulnerability_type)` for unresolved. v2.1 extends both joins with `target_id`.
- **Realtime channel pattern** — `frontend/src/components/dast/DastScanningTab.tsx:148` subscribes to `scan_jobs` per-project. Multi-target reuses the same channel filter; per-target updates land via channel filter on `target_id`.
- **Confirmed Exploitable cross-link** — `backend/depscanner/src/dast/pipeline.ts:132` (`crossLinkFinding`) is unchanged in v2.1; SAST cross-link is v2.3.

### Files this plan modifies

Modified:
- `backend/database/` (new migration: `phase24a_dast_v2_engine.sql`)
- `backend/database/schema.sql` (regenerated via `npm run schema:dump`)
- `backend/src/routes/dast.ts` (multi-target + credentials CRUD + scan target_id arg)
- `backend/src/types/dast.ts` (DTO types for targets + credentials + scope_config)
- `backend/src/lib/url-guard.ts` (no changes; reused)
- `backend/depscanner/src/dast/runner.ts` (full rewrite — YAML AF config builder)
- `backend/depscanner/src/dast/pipeline.ts` (load credentials + SPA detect + Nuclei + dedup)
- `backend/depscanner/Dockerfile` (Nuclei binary + nuclei-templates layer)
- `backend/depscanner/src/job-db.ts` (no changes; ExtractionJobRow already has `type`)
- `frontend/src/components/dast/DastScanningTab.tsx` (refactor to multi-target shell)
- `frontend/src/components/dast/DastFindingsSection.tsx` (target filter + auth_state badge)
- `frontend/src/lib/api.ts` (new endpoints + DTO types)

New:
- `backend/src/lib/dast-encryption.ts` (per-target credential encryption)
- `backend/src/lib/dast-har.ts` (HAR validation + sensitive-data sanitizer)
- `backend/depscanner/src/dast/spa-detect.ts` (runtime-marker probe)
- `backend/depscanner/src/dast/auth-config.ts` (ZAP AF auth job builder per strategy)
- `backend/depscanner/src/dast/nuclei-runner.ts` (Nuclei spawn + JSONL parser)
- `backend/depscanner/src/dast/dedup.ts` (ZAP+Nuclei result merge)
- `backend/depscanner/src/dast/yaml-builder.ts` (Automation Framework YAML composer)
- `frontend/src/components/dast/DastTargetsList.tsx`
- `frontend/src/components/dast/DastTargetEditDialog.tsx`
- `frontend/src/components/dast/DastAuthPanel.tsx`
- `frontend/src/components/dast/DastScopePanel.tsx`
- `frontend/src/components/dast/RecordedLoginWizard.tsx`
- `frontend/src/components/dast/ActiveScanOptInDialog.tsx`

### Patterns we will NOT invent

- No new dispatch path in the worker — we stay on the `processJob` switch on `job.type`.
- No new finding storage shape — `project_dast_findings` keeps its existing columns plus two new ones (`target_id`, `auth_state`).
- No new RBAC permission — the brief flagged `manage_credentials` as an open question; this plan keeps credential CRUD gated by `manage_projects` (the existing permission) and revisits separation when there's a UX driver.
- No new Fly app — same `deptex-depscanner` app; SPA scans bump the per-machine guest config to `performance-4x` at machine-start time via the existing `DAST_CONFIG` (see `backend/src/lib/fly-machines.ts:34`).

## Data Model

### New table: `project_dast_targets`

Replaces the `target_url TEXT` column on `project_dast_config` and the `active_dast_run_id` / `previous_dast_run_id` columns on `projects`. One row per (project, target_url) tuple. Carries the active/previous run pointer, the detected runtime, and a back-pointer for credentials.

```sql
CREATE TABLE project_dast_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  target_url TEXT NOT NULL,
  label TEXT,                        -- 'staging', 'preview', 'prod' for UI display
  enabled BOOLEAN NOT NULL DEFAULT true,

  detected_runtime TEXT NOT NULL DEFAULT 'unknown'
    CHECK (detected_runtime IN ('unknown', 'classic', 'spa')),
  detected_runtime_at TIMESTAMPTZ,

  active_dast_run_id  TEXT,
  previous_dast_run_id TEXT,
  last_scanned_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, target_url)
);

CREATE INDEX idx_project_dast_targets_project ON project_dast_targets(project_id);
CREATE INDEX idx_project_dast_targets_org ON project_dast_targets(organization_id);
CREATE INDEX idx_project_dast_targets_active_run
  ON project_dast_targets(active_dast_run_id) WHERE active_dast_run_id IS NOT NULL;

ALTER TABLE project_dast_targets ENABLE ROW LEVEL SECURITY;
CREATE POLICY project_dast_targets_org_select
  ON project_dast_targets FOR SELECT
  USING (organization_id IN (
    SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()
  ));
```

### New table: `project_dast_credentials`

One credential row per target. The `encrypted_payload` is an opaque ciphertext blob whose plaintext shape varies by `auth_strategy` (see `backend/src/lib/dast-encryption.ts` types below). `logged_in_indicator` / `logged_out_indicator` are stored in plaintext (regex patterns are not secret).

```sql
CREATE TABLE project_dast_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL UNIQUE REFERENCES project_dast_targets(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  auth_strategy TEXT NOT NULL
    CHECK (auth_strategy IN ('form', 'jwt', 'recorded', 'cookie')),
  encrypted_payload TEXT NOT NULL,         -- nonce:ciphertext:authtag, base64-joined
  encryption_key_version INTEGER NOT NULL DEFAULT 1,

  logged_in_indicator  TEXT,               -- regex matched against post-login response
  logged_out_indicator TEXT,               -- regex; >3 consecutive matches mid-scan = abort
  retry_login_on_lost  BOOLEAN NOT NULL DEFAULT false,  -- v2.1 ships hard-fail; flag is forward-compat

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
```

### `project_dast_config` reshape

Drops the single-target columns; adds scope config. v2.2 adds schedule columns alongside.

```sql
ALTER TABLE project_dast_config DROP COLUMN target_url;
ALTER TABLE project_dast_config DROP COLUMN scan_profile;
ALTER TABLE project_dast_config DROP COLUMN scan_timeout_minutes;

-- Default profile + timeout move per-target into project_dast_targets? No — they
-- still apply project-wide because picking different profiles per target adds
-- UX surface without a clear user need. Keep them on config.
ALTER TABLE project_dast_config ADD COLUMN scan_profile TEXT NOT NULL DEFAULT 'auto'
  CHECK (scan_profile IN ('auto', 'quick', 'full', 'api'));
ALTER TABLE project_dast_config ADD COLUMN scan_timeout_minutes INTEGER NOT NULL DEFAULT 30
  CHECK (scan_timeout_minutes BETWEEN 5 AND 60);

-- New: scope rules JSONB. Shape:
-- {
--   "include_patterns": ["^/api/.*"],
--   "exclude_patterns": ["^/admin/destroy.*", "/healthz$"],
--   "header_rules": [
--     { "name": "X-Test-User", "value": "scanner", "scope": "all" },
--     { "name": "X-Tenant", "value": "deptex-staging", "scope": "all" }
--   ]
-- }
ALTER TABLE project_dast_config ADD COLUMN scope_config JSONB NOT NULL DEFAULT '{}'::jsonb;
```

### `project_dast_findings` shape changes

```sql
-- Per-target scoping. NOT NULL after backfill (one-time UPDATE in the migration).
ALTER TABLE project_dast_findings ADD COLUMN target_id UUID REFERENCES project_dast_targets(id) ON DELETE CASCADE;
ALTER TABLE project_dast_findings ADD COLUMN auth_state TEXT NOT NULL DEFAULT 'anonymous'
  CHECK (auth_state IN ('anonymous', 'authenticated', 'authentication_lost'));
ALTER TABLE project_dast_findings ADD COLUMN engine TEXT NOT NULL DEFAULT 'zap'
  CHECK (engine IN ('zap', 'nuclei', 'merged'));

-- Update partial unique indexes to include target_id (atomic-commit per-target).
DROP INDEX IF EXISTS project_dast_findings_resolved;
CREATE UNIQUE INDEX project_dast_findings_resolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    handler_file_path, handler_function_name, vulnerability_type
  )
  WHERE handler_file_path IS NOT NULL;

DROP INDEX IF EXISTS project_dast_findings_unresolved;
CREATE UNIQUE INDEX project_dast_findings_unresolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    endpoint_url, http_method, vulnerability_type
  )
  WHERE handler_file_path IS NULL;
```

### `projects.active_dast_run_id` removal

```sql
ALTER TABLE projects DROP COLUMN active_dast_run_id;
ALTER TABLE projects DROP COLUMN previous_dast_run_id;
DROP INDEX IF EXISTS idx_projects_active_dast_run;
```

The active-pointer is now per-target on `project_dast_targets`. Existing rows with `active_dast_run_id` are migrated to a `project_dast_targets` row with the original `target_url` from `project_dast_config` before the column drops.

### `commit_dast_run` RPC rewrite

```sql
DROP FUNCTION IF EXISTS commit_dast_run(UUID, TEXT);

CREATE OR REPLACE FUNCTION commit_dast_run(
  p_target_id UUID,
  p_dast_run_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE
  v_prior_run_id TEXT;
  v_project_id UUID;
BEGIN
  SELECT active_dast_run_id, project_id INTO v_prior_run_id, v_project_id
  FROM project_dast_targets WHERE id = p_target_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'commit_dast_run: target % not found', p_target_id;
  END IF;

  -- Carry forward suppression / risk-accepted state by stable identity.
  -- Now scoped to (target_id, prior_run_id) → (target_id, new_run_id).
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
END;
$$;
```

### `queue_scan_job` RPC update

```sql
-- Bump per-org cap 3 → 5; accept p_target_id and validate it belongs to the project.
DROP FUNCTION IF EXISTS queue_scan_job(UUID, UUID, TEXT, JSONB, TEXT, TEXT, INTEGER, TEXT, UUID);

CREATE OR REPLACE FUNCTION queue_scan_job(
  p_project_id      UUID,
  p_organization_id UUID,
  p_type            TEXT,
  p_payload         JSONB,
  p_target_id        UUID    DEFAULT NULL,        -- new
  p_target_url       TEXT    DEFAULT NULL,        -- denormalized for log clarity
  p_scan_profile     TEXT    DEFAULT NULL,
  p_timeout_minutes  INTEGER DEFAULT NULL,
  p_trigger_source   TEXT    DEFAULT NULL,
  p_triggered_by     UUID    DEFAULT NULL
) RETURNS scan_jobs ...

-- Body changes (DAST branch):
--   * Validate p_target_id belongs to p_project_id; raise if not.
--   * Skip the target_url SSRF check here — moved to route layer; DB only checks
--     the target row's URL (already validated at PUT /target time).
--   * Per-org cap raise: v_org_concurrent >= 5 (was 3).
--   * Per-project cap stays 1.

-- scan_jobs gains a target_id sparse column matching the dast_columns_match_type CHECK.
ALTER TABLE scan_jobs ADD COLUMN target_id UUID REFERENCES project_dast_targets(id) ON DELETE SET NULL;
-- Update the dast_columns_match_type CHECK to include target_id.
```

### Migration file: `phase24a_dast_v2_engine.sql`

Order of operations:
1. Create `project_dast_targets` + indexes + RLS.
2. Create `project_dast_credentials` + indexes + RLS.
3. Backfill: `INSERT INTO project_dast_targets (project_id, organization_id, target_url, ...) SELECT project_id, organization_id, target_url FROM project_dast_config WHERE target_url IS NOT NULL;`
4. Backfill `project_dast_findings.target_id` from the matching target row (join on `(project_id, target_url)` via `cross_link_metadata` is unreliable — use `projects.active_dast_run_id` to match findings to the seeded target).
5. Make `project_dast_findings.target_id NOT NULL` after backfill.
6. Drop `project_dast_config.target_url`, `scan_profile`, `scan_timeout_minutes` (re-added with new defaults).
7. Add `project_dast_config.scope_config`, recreate `scan_profile` + `scan_timeout_minutes` with the same constraints.
8. Drop `projects.active_dast_run_id`, `projects.previous_dast_run_id`.
9. Drop and recreate `project_dast_findings_resolved` / `_unresolved` partial unique indexes including `target_id`.
10. Drop `commit_dast_run(UUID, TEXT)`; create new `commit_dast_run(target_id UUID, dast_run_id TEXT)`.
11. Drop `queue_scan_job(...)`; recreate with `p_target_id` arg + 5/org cap.
12. Add `scan_jobs.target_id`; update `scan_jobs_dast_columns_match_type` CHECK to include `target_id`.
13. Update Realtime publication for `project_dast_targets`.

### Schema dump

After applying via Supabase MCP (per `feedback_apply_migrations_via_mcp`), regenerate `backend/database/schema.sql`:

```bash
cd backend/depscanner && npm run schema:dump
```

Per `feedback_schema_dump_rebase`: regenerate **on the feature branch**, not main, to avoid the silent rebase drop.

## API Design

### Endpoints

All endpoints mounted at `/api/projects/:projectId/dast/...` via `app.use('/api/projects', dastRouter)` in `backend/src/index.ts` (already mounted in v1).

| Method | Route | Auth | Permission | Description |
|--------|-------|------|------------|-------------|
| GET | `/api/projects/:projectId/dast/config` | authenticateUser | view (`checkProjectAccess`) | Returns `{ scan_profile, scan_timeout_minutes, scope_config, targets: DastTargetDTO[] }` |
| PUT | `/api/projects/:projectId/dast/config` | authenticateUser | `manage_projects` | Update profile / timeout / scope_config (excludes targets — use target endpoints for those) |
| GET | `/api/projects/:projectId/dast/targets` | authenticateUser | view | List of `DastTargetDTO[]` |
| POST | `/api/projects/:projectId/dast/targets` | authenticateUser | `manage_projects` | Create new target. Body: `{ target_url, label?, enabled? }`. SSRF-validates target_url. |
| PATCH | `/api/projects/:projectId/dast/targets/:targetId` | authenticateUser | `manage_projects` | Update label / enabled. Cannot change target_url (delete + recreate to migrate; preserves data integrity). |
| DELETE | `/api/projects/:projectId/dast/targets/:targetId` | authenticateUser | `manage_projects` | Cascade-deletes credentials + findings + scan_jobs. |
| GET | `/api/projects/:projectId/dast/targets/:targetId/credentials` | authenticateUser | `manage_projects` | Returns redacted `DastCredentialSummaryDTO` (auth_strategy, indicator regexes, masked metadata — never the encrypted_payload). |
| PUT | `/api/projects/:projectId/dast/targets/:targetId/credentials` | authenticateUser | `manage_projects` | Set / replace credential. Body: `{ auth_strategy, payload, logged_in_indicator?, logged_out_indicator? }`. Server encrypts. |
| DELETE | `/api/projects/:projectId/dast/targets/:targetId/credentials` | authenticateUser | `manage_projects` | Remove credential — target reverts to anonymous. |
| POST | `/api/projects/:projectId/dast/scan` | authenticateUser | `manage_projects` | Body: `{ target_id }`. Existing route — adds `target_id` arg. Re-runs SSRF check on the target's URL pre-flight. |
| GET | `/api/projects/:projectId/dast/jobs` | authenticateUser | view | Existing — accepts `?target_id=...` filter. |
| GET | `/api/projects/:projectId/dast/findings` | authenticateUser | view | Existing — accepts `?target_id=...` filter. Returns active-run findings for that target (or all targets if omitted). |

### Types (in `backend/src/types/dast.ts`)

```typescript
export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';
export type DastAuthStrategy = 'form' | 'jwt' | 'recorded' | 'cookie';
export type DastDetectedRuntime = 'unknown' | 'classic' | 'spa';
export type DastAuthState = 'anonymous' | 'authenticated' | 'authentication_lost';
export type DastEngine = 'zap' | 'nuclei' | 'merged';

export interface DastTargetDTO {
  id: string;
  target_url: string;
  label: string | null;
  enabled: boolean;
  detected_runtime: DastDetectedRuntime;
  detected_runtime_at: string | null;
  has_credentials: boolean;
  auth_strategy: DastAuthStrategy | null;  // mirror credential row, no payload
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

export interface DastCredentialSummaryDTO {
  auth_strategy: DastAuthStrategy;
  // For form: { username_redacted: 'henry@…' }
  // For jwt:  { token_prefix: 'eyJhbGc…', token_length: 312 }
  // For recorded: { har_request_count: 7, har_filename: 'login.har', last_step_url_redacted: 'https://…' }
  // For cookie: { cookie_count: 3, cookie_names: ['session','csrf','remember'] }
  payload_summary: Record<string, unknown>;
  logged_in_indicator: string | null;
  logged_out_indicator: string | null;
  updated_at: string;
}

export interface DastCredentialUpsertDTO {
  auth_strategy: DastAuthStrategy;
  payload:
    | { kind: 'form'; login_url: string; username_field: string; password_field: string; username: string; password: string }
    | { kind: 'jwt'; token: string }
    | { kind: 'recorded'; har_json: object }
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
export function isDastEncryptionConfigured(): boolean;  // checks DAST_CREDENTIAL_KEY env var
```

The `payload` field in `DastCredentialUpsertDTO` is `JSON.stringify`'d, then encrypted, then stored. Decryption returns the original JSON which the depscanner pipeline parses.

`backend/src/lib/dast-har.ts`:

```typescript
export interface HarValidationResult {
  valid: true;
  request_count: number;
  last_step_url: string;
  sanitized: object;  // HAR with passwords/auth-headers stripped
} | { valid: false; reason: string };

export function validateAndSanitizeHar(harJson: unknown): HarValidationResult;
```

The sanitizer strips `Authorization: Basic …`, `password=…` form fields, and any header matching a known sensitive-name list before storage. The original (with creds) **is** what we encrypt; sanitization runs on a copy used only for the redacted summary surface.

## Frontend Design

### Pages & routes

No new top-level routes. The Settings → Scanning tab continues at `/organizations/:orgId/projects/:projectId/settings/scanning`. The Security tab DAST section continues at `/organizations/:orgId/projects/:projectId/security` (DAST findings render below SCA findings as in v1).

### Component tree

```
DastScanningTab (multi-target shell)
├── ProfileAndTimeoutCard           (project-wide: scan_profile + scan_timeout_minutes)
├── ScopeRulesCard                  (project-wide scope_config)
│   └── DastScopePanel
│       ├── IncludeExcludePatternList
│       └── HeaderRulesList
├── TargetsCard                     (multi-target list + add)
│   └── DastTargetsList
│       └── DastTargetRow ×N
│           ├── TargetMetaSummary   (URL, label, runtime badge, last scan)
│           ├── AuthStatusChip      ("Anonymous" / "Form" / "JWT" / "Recorded" / "Cookie")
│           ├── ScanNowButton       (per-target; opens ActiveScanOptInDialog when profile=full)
│           ├── EditButton          (opens DastTargetEditDialog)
│           └── DeleteButton        (confirmation per feedback_dialog_pattern)
├── HistoryCard                     (existing scan_jobs table; +target column)
└── DastTargetEditDialog            (slide-in from right per slide-in-sidebars pattern)
    ├── TargetUrlInput              (immutable on existing target — show as read-only)
    ├── LabelInput
    ├── DastAuthPanel
    │   ├── StrategySelect          (form | jwt | recorded | cookie)
    │   ├── (per-strategy form group)
    │   ├── LoggedInIndicatorInput
    │   └── LoggedOutIndicatorInput
    └── EnabledSwitch

RecordedLoginWizard (modal, opens from DastAuthPanel when strategy=recorded)
├── HarFileDropzone
├── HarRequestList                  (preview parsed steps)
└── HarSanitizationSummary          ("Stripped 2 sensitive headers, 1 password field")

ActiveScanOptInDialog               (matches feedback_dialog_pattern)
├── DestructiveWarningBlock         ("Active scans send fuzz payloads…")
├── TargetUrlConfirm                (must match by typing)
└── OutlineCancel + DestructiveConfirm
```

### Design specifications

Per `frontend-design` skill:

- **TargetsCard**: `rounded-lg border border-border bg-background-card`; header `px-4 py-3 border-b border-border` with title `text-sm font-semibold`. Each `DastTargetRow` is a flex row with `px-4 py-3 hover:bg-table-hover transition-colors`.
- **AuthStatusChip**: small badge using existing variants — `outline` for anonymous, `success` (subtle) for configured auth.
- **DastTargetEditDialog**: slide-in from right per the slide-in sidebar pattern (`max-w-[640px] bg-background-card border-l`). Header `px-5 pt-5 pb-4 border-b`. Save button (outline variant per `feedback_button_style`) + Cancel.
- **ActiveScanOptInDialog**: matches `feedback_dialog_pattern` exactly — two-tone popup, `hideClose`, outline Cancel + bordered destructive Confirm. Reference template: `aegis/ThreadList.tsx` (per the memory).
- **HarFileDropzone**: dashed border drop area, `border-dashed border-border bg-background/50 rounded-lg p-6`; on hover `border-primary/50`.
- **Detected-runtime badge**: outline pill — "Classic" (foreground-secondary), "SPA" (info), "Unknown" (foreground-muted).
- **No `/30` or `/40` opacity on body text or icons** per `feedback_vercel_typography`.
- **Pixel-perfect** per `feedback_pixel_perfectionism`: 1-2px tweaks not restructures during browser sign-off.

### State management

- DastScanningTab fetches `GET /api/projects/:projectId/dast/config` once on mount → drives the whole tab from a single state object `{ scan_profile, scan_timeout_minutes, scope_config, targets[] }`.
- Realtime: existing `scan_jobs` Supabase channel filter on `project_id=eq.:projectId`. Channel-update triggers a refresh of `targets[]` (since active_dast_run_id and last_scanned_at live there). Plus a second channel filter on `project_dast_targets` for direct target updates.
- Per `feedback_react_stale_state`: track the currently-edited `targetId` in a separate `editingTargetId` state and clear it on dialog close to prevent stale data flash.

### Empty / loading / error states

- **Empty (no targets configured)**: `TargetsCard` body shows centered prompt — "Add a target URL to start scanning. DAST runs against your deployed app, so use staging if you have one." + CTA outline button "Add target".
- **Empty (one target, never scanned)**: per-target row shows "No scans yet" in muted text, big "Scan now" button outline.
- **Loading**: skeleton via `bg-muted animate-pulse rounded` (existing pattern from `DastScanningTab.tsx:468`).
- **Error**: toast via existing `useToast` hook. Per `feedback_no_raw_errors_to_users`, surface generic "Failed to save target" + push real error to `console.error`.

## Implementation Tasks

Ordered, each independently shippable. Sizes: S (≤4hr), M (4-12hr), L (1-3 days), XL (≥3 days).

### Task 1 — Schema migration + RLS + RPCs (M)
**Files**: `backend/database/phase24a_dast_v2_engine.sql` (new), `backend/database/schema.sql` (regenerated).
**Acceptance**:
- Migration applies cleanly via Supabase MCP against the dev DB.
- All seven schema changes from "Migration file" land: targets table, credentials table, config reshape, findings target_id+auth_state+engine, projects column drops, RPC rewrites, scan_jobs.target_id.
- Backfill UPDATE statements migrate any existing `project_dast_config.target_url` rows + matching `project_dast_findings` rows without data loss.
- Schema dump regenerated on feature branch (per `feedback_schema_dump_rebase`).
- PGLite e2e migration applies clean (Henry's local mode).

### Task 2 — Backend types + encryption + HAR sanitizer (M)
**Files**: `backend/src/types/dast.ts` (extended), `backend/src/lib/dast-encryption.ts` (new), `backend/src/lib/dast-har.ts` (new).
**Acceptance**:
- `encryptCredential` + `decryptCredential` round-trip across `DAST_CREDENTIAL_KEY` rotation (current + previous key fallback).
- `isDastEncryptionConfigured()` returns false when env var unset; routes refuse credential PUT with 503 in that case.
- `validateAndSanitizeHar` strips `Authorization` headers + password form fields from a sample HAR; rejects HARs missing `log.entries` array; caps at 100 entries.
- Unit tests cover all 4 strategies' payload shapes.
- New env var `DAST_CREDENTIAL_KEY` documented in `backend/.env.example`.

### Task 3 — Backend routes: targets + credentials CRUD (L)
**Files**: `backend/src/routes/dast.ts` (rewrite), referenced from `backend/src/index.ts` (already mounted).
**Acceptance**:
- All 11 endpoints from the API table return correct DTOs against a freshly-migrated DB.
- SSRF guard runs at every target URL ingress (POST + PATCH + scan trigger) per `feedback_no_raw_errors_to_users`.
- Credential PUT validates strategy-specific payload shape via Zod-style guard (no library — inline type check).
- Credential summaries never leak the encrypted payload, never echo back the password / token / cookie value.
- HAR uploads run through `validateAndSanitizeHar`; original (un-sanitized) gets encrypted + stored; sanitized version drives the redacted summary.
- 422 returned on invalid scope_config regex (try-compile each pattern in the route handler).
- Concurrency cap test: queueing a scan against `target_id=X` while another scan_job for `target_id=X` is processing returns 409 `project_concurrent_dast_blocked`.

### Task 4 — Depscanner Dockerfile: Nuclei + browser deps (S)
**Files**: `backend/depscanner/Dockerfile`.
**Acceptance**:
- Nuclei v3 binary pinned via release tarball (mirrors TruffleHog / Trivy install pattern in current Dockerfile).
- `nuclei-templates` repo cloned at a pinned tag into `/opt/nuclei-templates`.
- `nuclei -version` smoke check passes in image build.
- Existing X11 / Xvfb deps (already added in v1 bug-3 fix) confirmed sufficient for Chromium browserBased — Firefox stays the ZAP browser default for v2.1; we don't ship Chromium binaries (ZAP uses bundled Firefox via WebDriver).
- Image size delta documented (target: ≤200 MB increase).

### Task 5 — Depscanner runner: YAML AF config builder (L)
**Files**: `backend/depscanner/src/dast/yaml-builder.ts` (new), `backend/depscanner/src/dast/runner.ts` (rewrite), `backend/depscanner/src/dast/auth-config.ts` (new).
**Acceptance**:
- `buildAutomationYaml(opts)` returns a YAML string with the right job order: `addOns` → `passiveScan-config` → `replacer` (header rules + JWT auth) → `authentication` (form / jwt / cookie) → `sequence-import` (recorded HAR) → `spider` or `spiderAjax` → `browserBased` (when SPA detected) → `activeScan` (when profile=full or auto+detected) → `report`.
- Auth strategy → ZAP method mapping correct: `form` uses `formBasedAuthentication`; `jwt` uses `replacer` only (no ZAP auth method needed because Bearer doesn't refresh during scan); `cookie` uses `replacer`; `recorded` uses `sequence-import` + verification by indicator.
- `loggedInIndicator` / `loggedOutIndicator` regex emitted on the authentication job.
- Scope: `context.includePaths` + `context.excludePaths` in the YAML.
- `runZap` invokes `/zap/zap.sh -cmd -autorun /path/to/automation.yaml` instead of helper-script flags.
- v1 test fixtures still pass (existing `dast-runner.test.ts`).

### Task 6 — SPA detection (S)
**Files**: `backend/depscanner/src/dast/spa-detect.ts` (new).
**Acceptance**:
- `detectRuntime(targetUrl)` fetches the homepage with a 15s timeout; reads `Content-Type: text/html` body; matches against the runtime-marker regex set: `data-reactroot`, `id="__nuxt"`, `id="__next"`, `data-server-rendered`, `<app-root`, `id="svelte"`, plus generic SPA markers (`<script` count ≥4 + body innerHTML length ≤500 chars heuristic for empty-shell apps).
- Returns `{ runtime: 'classic' | 'spa', confidence: number, markers: string[] }`.
- On fetch failure or non-HTML response → `{ runtime: 'unknown' }` and the pipeline defaults to `classic` (preserves v1 behavior).
- Pipeline writes `{ detected_runtime, detected_runtime_at }` back to `project_dast_targets` on every scan.

### Task 7 — Nuclei runner + dedup (M)
**Files**: `backend/depscanner/src/dast/nuclei-runner.ts` (new), `backend/depscanner/src/dast/dedup.ts` (new).
**Acceptance**:
- `runNuclei(targetUrl, opts)` spawns `nuclei -u <url> -jsonl -silent -t /opt/nuclei-templates/http -severity critical,high,medium -rl 50 -timeout 5` (rate limit 50/sec; per-template timeout 5s) and parses JSONL line-by-line.
- Each Nuclei finding maps to `DastFindingRaw` shape (same as ZAP path) with `cwe_id` extracted from template `info.classification.cwe-id` and severity normalized to our enum.
- `mergeFindings(zapResults, nucleiResults)` dedups on `(cwe_id, endpoint_url, vulnerability_type)` — when both engines hit the same triple, ZAP wins (higher confidence on active scan); the merged row carries `engine='merged'` and `cross_link_metadata.engines = ['zap', 'nuclei']` for diagnostics.
- Total-run-time budget: ZAP + Nuclei must complete inside `scan_timeout_minutes`. Run them sequentially (not parallel) since ZAP active scan saturates the network and Nuclei adds noise; explicit decision documented in code comment.
- Heartbeat continues firing during Nuclei (uses the same `processJob` interval timer, no per-step changes).

### Task 8 — Pipeline orchestrator + auth-state finding (M)
**Files**: `backend/depscanner/src/dast/pipeline.ts` (rewrite).
**Acceptance**:
- New flow: claim job → resolve `target_id` → load credentials (if any) → SPA detect → write detected_runtime back → build YAML → run ZAP → run Nuclei → merge → cross-link → atomic-commit via `commit_dast_run(target_id, dast_run_id)`.
- `auth_state` populated on every finding: `'authenticated'` when a credential was loaded and ZAP didn't trip the `loggedOutIndicator` >3 times, `'authentication_lost'` when it did, `'anonymous'` otherwise.
- When auth fails mid-scan: pipeline aborts the active scan, emits a single `authentication_lost` finding with severity=`high`, `vulnerability_type='Authentication lost during scan'`, `endpoint_url=last_logged_out_url`, then completes the scan_job (status=`completed`) with a structured `error_category='auth_failed'`. Findings already collected before the loss are kept, all tagged `authentication_lost` so triage can decide.
- On Nuclei timeout but ZAP success: ZAP findings still ship; Nuclei timeout logged but not fatal.
- Concurrency cap test: when `commit_dast_run` runs against a target that already has another scan in flight, the FOR UPDATE row lock blocks the second; this is acceptable because per-project cap is 1.

### Task 9 — Frontend: targets list + auth panel + scope panel (L)
**Files**: `frontend/src/components/dast/DastScanningTab.tsx` (rewrite), `frontend/src/components/dast/DastTargetsList.tsx` (new), `frontend/src/components/dast/DastTargetEditDialog.tsx` (new), `frontend/src/components/dast/DastAuthPanel.tsx` (new), `frontend/src/components/dast/DastScopePanel.tsx` (new), `frontend/src/lib/api.ts` (extended).
**Acceptance**:
- Component tree matches the spec above.
- Realtime channel: scan_jobs change → refresh `jobs[]` AND `targets[]` (active_dast_run_id moved off projects, so per-target last_scanned_at lives on target rows).
- Auth panel renders correct inputs per strategy; saving an empty payload returns a 422 surfaced as toast.
- Scope panel: invalid regex shows red border on input + tooltip with the compile error message.
- Browser sign-off (per `feedback_visual_redesign_iteration`): ship targets list first, get pixel feedback, then ship auth/scope panels.

### Task 10 — Frontend: recorded login wizard + active-scan opt-in (M)
**Files**: `frontend/src/components/dast/RecordedLoginWizard.tsx` (new), `frontend/src/components/dast/ActiveScanOptInDialog.tsx` (new).
**Acceptance**:
- HAR file dropzone accepts `.har` and `.json`; shows parsed step count + last-step URL.
- Backend sanitization summary surfaces in the wizard ("Stripped 2 Authorization headers, 1 password field from request bodies before encryption").
- ActiveScanOptInDialog blocks scan trigger when `scan_profile = 'full'` AND user has not previously confirmed for this target. Per-target memo persisted in `localStorage` keyed by `target_id` (server-side memo not needed — re-confirmation costs nothing).
- Dialog matches `feedback_dialog_pattern` exactly: two-tone popup, hideClose, outline Cancel + bordered destructive.

### Task 11 — Tests + integration coverage (L)
**Files**: `backend/depscanner/src/__tests__/dast-spa-detect.test.ts`, `backend/depscanner/src/__tests__/dast-yaml-builder.test.ts`, `backend/depscanner/src/__tests__/dast-nuclei-runner.test.ts`, `backend/depscanner/src/__tests__/dast-dedup.test.ts`, `backend/src/lib/__tests__/dast-encryption.test.ts`, `backend/src/lib/__tests__/dast-har.test.ts`, `backend/src/routes/__tests__/dast-targets.test.ts`, `backend/src/routes/__tests__/dast-credentials.test.ts`, plus PGLite e2e for the full claim-→commit path.
**Acceptance**:
- Unit coverage: SPA detector against a fixture set of HTML samples (React/Vue/Angular/Next/Nuxt/Svelte/classic SSR); YAML builder against each combo of (auth_strategy × scan_profile × spa_detected); Nuclei JSONL parser against a real captured Nuclei output; dedup deterministic for ZAP+Nuclei collision cases; encryption round-trips across both keys.
- Route coverage per `backend_test_mock_patterns`: 403 paths use `/permission|access/i` regex; setTableResponse for first-call mocks, pushTableResponse for subsequent calls.
- PGLite e2e: insert one project + 2 targets; queue scan_job; mock pipeline result; verify atomic-commit flips per-target pointer; verify findings filtered correctly by target_id.

### Task 12 — Real-Docker e2e against Juice Shop with form auth + SPA mode (M)
**Files**: ad-hoc test script (not committed), updated `dast_v1_state.md` follow-up checklist.
**Acceptance**:
- Build the new image (`docker build` on `backend/depscanner`).
- Run depscanner against Juice Shop on port 13000 (already running per the v1 state memo).
- Configure form auth credentials (`admin@juice-sh.op` / `admin123`); confirm `auth_state='authenticated'` on at least 50% of resulting findings.
- Confirm SPA detection fires (Juice Shop is a classic Angular SPA); confirm `detected_runtime='spa'` on the target row after first scan.
- Confirm at least 5 Nuclei-sourced findings ship (templates pinned to current `nuclei-templates` v9.x baseline).
- Run a scan with the form `loggedOutIndicator` set to `Login` (regex matches the page title that returns when the session expires); confirm the pipeline emits an `authentication_lost` finding when auth is forced to drop.

## Testing & Validation Strategy

### Backend

- **Routes**: every new endpoint gets at least one happy-path + one 403 + one 422 test. Reuse `backend_test_mock_patterns`.
- **Encryption**: round-trip across rotation; reject malformed ciphertexts; reject mismatched key versions.
- **HAR sanitizer**: regression suite of HAR samples with known sensitive fields; expect each sensitive field stripped from the sanitized output but present in the encrypted-original.
- **YAML builder**: snapshot test the YAML output for the canonical (form auth + scope rules + SPA detected + active scan) case so future changes show in diff.
- **Concurrency**: integration test that POST /scan during an in-flight scan returns 409 with the right error tag.

### Frontend

- **Component tests** for `DastTargetsList`, `DastAuthPanel`, `DastScopePanel`, `RecordedLoginWizard`. Verify happy-path data flow + error toasts.
- **Realtime regression**: inserting a row in `scan_jobs` via the test client refreshes the targets list within 2s.

### End-to-end

- **PGLite local mode**: seed a project + targets + credentials; queue a scan; mock the depscanner pipeline; verify the route layer + commit RPC + finding filter all align.
- **Real Docker**: Task 12 above is the ground-truth signal. Per `feedback_docker_vs_source_e2e`, source-tree-only e2e doesn't catch container drift — schedule the Docker pass before merge.
- **Browser walkthrough**: per `feedback_visual_redesign_iteration`, ship targets list to browser first; iterate on pixel feedback; then add auth/scope panels.

### Performance targets

- Settings → Scanning load: ≤300 ms p50 for projects with ≤20 targets.
- POST /scan response: ≤500 ms p50 (includes SSRF DNS lookup + Fly machine-start dispatch).
- ZAP+Nuclei combined runtime: ≤45 min for `scan_profile='full'` against a 200-route SPA target.
- SPA-detect probe: ≤15 s timeout; hard-cap.

### Regression guard

- v1 anonymous baseline + api scans must continue to work — Task 5's YAML builder must produce a YAML that's behaviorally equivalent to the v1 helper-script invocation when `auth_strategy=null + scope=empty + spa=false`.
- Schema migration backfill: existing `active_dast_run_id` data must surface as `project_dast_targets` rows after migration; run a verification SELECT in the migration body that asserts target counts match config-row counts.

## Risks & Open Questions

### Risks

- **R1 — YAML AF migration is the largest single rewrite.** Replacing ZAP helper-script invocation with a generated AF YAML changes how every parameter flows. Mitigation: keep the helper-script code path behind a feature flag for one release so we can compare side-by-side.
- **R2 — Recorded login (HAR replay) fragility.** ZAP's `sequence-import` is opinionated about HAR shape (it expects `_resourceType` annotations Chrome-DevTools adds but Firefox doesn't). Mitigation: build the HAR sanitizer to emit a canonicalized HAR variant rather than passing user-supplied HAR through unchanged.
- **R3 — Nuclei rate-limit interactions with active scans.** Nuclei firing 50 req/s while ZAP active scan is also fuzzing the same target can saturate the staging server's CPU. Mitigation: run sequentially (Task 7 acceptance); revisit parallelization in v2.2 once we see real numbers.
- **R4 — Active-scan data corruption.** Brief decision 6 explicitly accepts the risk; v2.1 surfaces a destructive-action dialog (Task 10) but doesn't gate by infrastructure. Mitigation: clear UI warning + per-target-per-user opt-in in localStorage.
- **R5 — Schema migration backfill.** If existing `project_dast_findings` rows can't be matched to a target row (target_url drift between findings and config), the NOT NULL constraint on `target_id` will fail. Mitigation: backfill assigns a synthetic target row per (project_id, distinct findings.target-derived-from-cross-link-metadata.purl-or-endpoint_url-host); test in dev before applying to prod.
- **R6 — Nuclei template freshness.** Pinned templates go stale; releasing v2.1 without a template-update story leaves us shipping CVE detection for a known set of templates that won't grow. Mitigation: out-of-scope for v2.1 (templates pin to a known-good tag); v2.2 schedules a weekly template-bump PR via Aegis automation.

### Open questions

- **Q1 (defer to /implement, low risk):** HAR canonicalization — emit Chrome-DevTools-style `_resourceType` annotations on Firefox-sourced HAR? Decide based on real Firefox HAR drop test.
- **Q2 (defer to /implement, low risk):** SPA detection probe — should it follow redirects from `target_url` (e.g. `/` → `/login` → `/app`)? Default to follow-up-to-3.
- **Q3 (defer to /implement, low risk):** Nuclei concurrency — run sequentially (Task 7) or parallel-with-ZAP-paused-during-Nuclei? v2.1 ships sequential; revisit if total runtime exceeds 45min ceiling consistently.
- **Q4 (defer to /implement, very low risk):** `manage_credentials` permission separation — left folded into `manage_projects` per brief Q4. Reconsider if any user with `manage_projects` shouldn't see credential summaries.
- **Q5 (informational, blocks nothing):** v2.2 schedule cron container for self-host — captured here only as forward-context for the v2.2 plan.

## Dependencies

- **Existing v1 schema**: `project_dast_config`, `project_dast_findings`, `commit_dast_run`, `queue_scan_job`, `scan_jobs.type='dast'` all in place per `phase23b_dast_schema.sql`.
- **Existing AES-256-GCM pattern**: `backend/src/lib/ai/encryption.ts` is the template for `dast-encryption.ts`.
- **Existing SSRF guard**: `backend/src/lib/url-guard.ts` reused unchanged.
- **Existing dispatch**: `backend/depscanner/src/index.ts:processJob` already routes `type='dast'` to `runDastPipeline`.
- **Existing route-matcher + reachable-flow cross-link**: v1 cross-link logic in `pipeline.ts:crossLinkFinding` reused unchanged; just rewired into the new orchestrator.
- **Existing Fly machine sizing**: `DAST_CONFIG` in `backend/src/lib/fly-machines.ts:34` already targets `shared-cpu-4x` 8GB. v2.1 SPA scans need bumping — change to `performance-4x` 16GB or branch on payload (v2.1 keeps it simple: bump the default since ZAP browserBased is the more demanding path).

## Success Criteria

- All 12 tasks land; PGLite e2e + real-Docker e2e (Juice Shop) both green.
- Authenticated scan against Juice Shop produces ≥50% of findings with `auth_state='authenticated'` (proves credentials flowed through).
- Nuclei contributes ≥5 distinct findings on Juice Shop (proves the hybrid engine ships).
- SPA detection correctly classifies Juice Shop as `detected_runtime='spa'` on first scan.
- Multi-target: a project with 2 targets shows independent active_dast_run_id pointers + independent finding lists in the UI.
- Scope rules: an exclude pattern on `^/admin/` results in zero findings against URLs matching that pattern in a controlled test.
- `authentication_lost` finding is emitted when the loggedOutIndicator triggers >3 times in a controlled test.
- Settings → Scanning page loads in ≤300ms p50 with 20 targets.
- All v2.1 features run inside the self-host depscanner Docker image without cloud dependencies.

---

## After this plan

Recommended next: `/review-plan dast-v2-1-engine` — multi-agent debate covers scope creep, schema risk, missing edge cases, and architectural soundness. Catches issues before `/implement` burns a day on them.

If review passes: `/implement dast-v2-1-engine` runs all 12 milestones back-to-back per `feedback_implement_no_milestone_pause`.
