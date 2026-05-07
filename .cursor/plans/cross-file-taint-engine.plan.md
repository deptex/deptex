# Cross-File Taint Engine — Implementation Plan (Phase 6)

## Status (2026-04-30) — SHIPPED, MERGED as PR #19

Merge commit on main: `142b495`. 27 feature/test commits (`912e80e..231984b`) + critical-review fix (`e6a339b`) + main-merge (`d52ead1`). Scope expanded twice during build: TS/JS only → +Python/Java/Go → all 8 Phase 2 languages (Ruby, PHP, Rust, C#). 30 vuln/safe fixture pairs across the 7 non-JS languages (4 each); 11 vuln classes covered on Express; broader spec coverage for the rest.

**/critical-review (4 agents, 2026-04-30)** surfaced 3 P0 / 6 P1 / 10 P2 / 4 P3. All resolved before PR opened (3 fix-up migrations applied via MCP: `phase26_5_lock_down_rpc_grants`, `phase26_6_schema_dump_jsonb`, `phase26_7_drop_dead_column`). Two findings deliberately deferred: `manage_aegis` permission rename (locked at M6.8, P3) and engine flow PURL real resolver (M5+ work).

**Ships shadow-mode.** Engine writes to `project_reachable_flows` with `reachability_source='taint_engine'` alongside atom; atom keeps producing canonical reachability. Retirement is gated on 30-day shadow A/B + recall parity on the 88-CVE corpus + zero regressions on test-npm. Retirement-gates harness wired (M8) but not yet evaluated against real shadow data.

**Next phase**: Phase 6.5 — Cross-file CVE-targeted taint (~1 week of plumbing to bridge Phase 5's per-CVE rules into Phase 6's framework-generic engine + tag flows with osv_id so the classifier promotes to `confirmed`). See `.cursor/plans/reachability-analysis.plan.md` Phase 6.5 section. Prereqs (✅ Phase 5 merged, ✅ Phase 6 merged) now satisfied; only ~2 weeks of Phase 6 shadow data remains as a soft gate.

---

## Overview

A deterministic forward-propagation cross-file taint engine for JS/TS, built on the TypeScript Compiler API and wired into the extraction pipeline as a new `taint_engine` step that slots in **after** tree-sitter usage extraction and **before** the existing `scanning` step. Output flows are written to the existing `project_reachable_flows` table with a new `reachability_source = 'taint_engine'` value, so the existing `updateReachabilityLevels()` classifier picks them up unchanged. An IRIS-style AI augmentation layer (spec inference for long-tail frameworks + per-flow false-positive filter) runs on top of the deterministic engine; the deterministic core ships open-core, the AI layer is conditional on `getProviderForOrg()` returning a provider. Hard-fail policy + 5%-error-rate circuit breaker + shadow-mode rollout. Goal: replace `atom` as the canonical cross-file engine once recall parity + 30-day A/B + zero test-npm regressions all pass.

Locked decisions are documented in `feature-brief-cross-file-taint-engine.md`. Research evidence in `research-cross-file-stitching.md`.

## Competitive Research & Design Rationale

Already done in `.cursor/plans/research-cross-file-stitching.md`. Key takeaways shaping this plan:

1. **Joern took 30+ engineer-years** — we're not replicating Joern. We're building a forward-propagation engine on top of the TypeScript Compiler API (which gives us callgraph + symbols + type-aware edges essentially free). Tradeoff: we accept loss of context-sensitivity and aliasing precision in exchange for shippability.
2. **Snyk Code shipped in ~3 years** with a hybrid symbolic + ML approach from day 1 (per ETH Zurich source). We're explicitly cloning this hybrid shape — IRIS architecture (deterministic + LLM specs + LLM filter) is the published frontier.
3. **CodeQL has 28 MB of hand-curated QL standard library** — the engine is the smaller piece. We acknowledge framework-model curation IS the project. Hand-write top 5 JS frameworks (Express, Fastify, NestJS, Next.js, Hono); AI infers everything else.
4. **IRIS (ICLR 2025)** showed +103% recall on CWE-Bench-Java with LLM spec-inference + post-filter. We map this directly onto our existing Phase 5 AI infrastructure.
5. **Best-in-class JS static taint catches ~15-30% of real CVEs**. Our v1 target is "match atom on JS, then beat it on the cases atom misses (dynamic dispatch, framework indirection)" — not match CodeQL.

## Codebase Analysis

### Pipeline architecture (from `pipeline.ts` audit)

The extraction pipeline is a sequential function (`runPipeline`) at `backend/extraction-worker/src/pipeline.ts`. Key context:
- Each step calls `updateStep(supabase, projectId, stepName)` then `withTimeout(fn, timeoutMs, stepName)`.
- Soft failures call `logStepError(supabase, ...)` with `severity='warn'` and continue. Critical failures throw → `setError()` → pipeline exits.
- The active extraction is anchored by a `runId` (line 557: `job.jobId ?? Date.now().toString()`); all writes are scoped by `extraction_run_id`.
- **Phase 6 slots between `framework_detection` (~line 860) and `scanning` (~line 905).** This is correct because:
  - Tree-sitter has populated `project_usage_slices` with per-call-site data (filePath, lineNumber, containingMethod)
  - Framework entry points are persisted in `project_entry_points`
  - The `scanning` step runs dep-scan + atom + Phase 3 reachability rules + the classifier `updateReachabilityLevels()` at line 1363; that classifier reads from `project_reachable_flows`, so writing our flows there before the classifier runs is the cleanest integration

### Reachability classifier (from `reachability.ts`)

`updateReachabilityLevels()` at `reachability.ts:384` reads from `project_reachable_flows` and `project_usage_slices`, computes a reachability rank per PDV, and writes to `project_dependency_vulnerabilities.reachability_level`. Rank values: `confirmed` (4) > `data_flow` (3) > `function` (2) > `module` (1). The classifier is **source-agnostic** — it doesn't care whether a flow came from atom, Phase 3 reachability_rules, or Phase 6. This means our engine output requires zero classifier changes.

### Atom output shape (from `parseReachableFlows()`)

Atom writes to `project_reachable_flows` with this shape (per `phase6b_reachability_tables.sql` + later alters):
```sql
{
  project_id, extraction_run_id, purl, dependency_id,
  flow_nodes JSONB,                    -- the taint trace
  entry_point_file, entry_point_method, entry_point_line, entry_point_tag,
  sink_file, sink_method, sink_line, sink_is_external,
  flow_length, llm_prompt,
  reachability_source TEXT NOT NULL DEFAULT 'atom'  -- CHECK IN ('atom', 'semgrep_taint')
}
```
**Phase 6 reuses this exact table.** We extend the CHECK constraint to allow `'taint_engine'` and write our flows directly. No new flows table needed. Massive simplification — and means atom retirement is just "stop running atom" + the data shape is identical.

### Phase 5 AI rule-generator pattern (from `rule-generator/`)

Closest analogous feature. Layout:
- `rule-generator/index.ts` — entry point, retry loop, `MAX_GENERATION_ATTEMPTS=4`, exports `generateRuleForCve()`
- `rule-generator/generate.ts` — provider call shape, `callProviderAndParse()`, `withRateLimitRetry()`
- `rule-generator/validate.ts` — Semgrep validation gate
- Wired into pipeline.ts as a step inside the `scanning` block; cost tracked via `ai_usage_logs(feature='rule_generator', tier='platform')`

Phase 6 mirrors this layout under `taint-engine/`. We reuse `withRateLimitRetry`, the AI provider infra, and `ai_usage_logs` cost tracking.

### AI cost cap pattern (from `phase24_epd_org_settings`)

EPD has per-org cost cap stored in... actually the audit found this is currently NOT a per-org cost-cap table — it's logged to `ai_usage_logs` with `feature='epd_scoring'` and budget enforcement happens in code via `ai_usage_logs` aggregation. The AI Settings page displays cost cap as **read-only** (line 565-586 of `AIConfigurationSection.tsx`). Phase 6 will:
1. Add a per-org `taint_engine_settings.monthly_ai_cost_cap_usd` column
2. Build the **first editable cost cap form** in the AI Settings UI (precedent for retrofitting EPD later)
3. Log spec-inference + FP-filter calls to `ai_usage_logs` with `feature='taint_engine_spec_inference'` and `feature='taint_engine_fp_filter'`

### Frontend patterns to reuse

- **AI Settings page** at `frontend/src/components/settings/AIConfigurationSection.tsx` — extend the `usage` sub-tab with a new "Taint Engine" cost-cap card (clone the EPD card visually, add inline edit affordance)
- **Settings list table** at `frontend/src/components/StatusesSection.tsx` — the gold-standard pattern for an admin list page (table + add modal + row actions). Clone for the framework models management page.
- **Monaco JSON editor** — `PolicyCodeEditor.tsx` uses `@monaco-editor/react`. Adapt for editing AI-inferred framework spec JSON.
- **Reachability display** — `VulnerabilityOrgSidebarExpandedContent.tsx:153-159` shows `reachability_level` per vuln. No changes needed (silent UI fold per decision #10).
- **Quality warning banner** — no existing project-page banner pattern. New component, follows `AIConfigurationSection.tsx:523-532` alert-card pattern.

### Files modified vs new

**New files (engine):**
- `backend/extraction-worker/src/taint-engine/index.ts` — entry point
- `backend/extraction-worker/src/taint-engine/callgraph.ts` — TS Compiler API substrate
- `backend/extraction-worker/src/taint-engine/ir.ts` — normalized IR (callgraph + symbol info → propagator-friendly form)
- `backend/extraction-worker/src/taint-engine/propagator.ts` — worklist forward-propagation engine
- `backend/extraction-worker/src/taint-engine/spec-loader.ts` — load YAML framework models
- `backend/extraction-worker/src/taint-engine/spec-inference.ts` — AI spec inference for long-tail frameworks
- `backend/extraction-worker/src/taint-engine/fp-filter.ts` — AI per-flow false-positive filter
- `backend/extraction-worker/src/taint-engine/circuit-breaker.ts` — error-rate kill switch
- `backend/extraction-worker/src/taint-engine/storage.ts` — write flows to `project_reachable_flows`, run telemetry to `taint_engine_runs`
- `backend/extraction-worker/src/taint-engine/framework-models/express.yaml` — hand-written
- `backend/extraction-worker/src/taint-engine/framework-models/fastify.yaml` — hand-written
- `backend/extraction-worker/src/taint-engine/framework-models/nestjs.yaml` — hand-written
- `backend/extraction-worker/src/taint-engine/framework-models/nextjs.yaml` — hand-written
- `backend/extraction-worker/src/taint-engine/framework-models/hono.yaml` — hand-written
- `backend/extraction-worker/test/taint-engine/` — fixtures + unit tests

**New files (backend API):**
- `backend/src/routes/taint-engine.ts` — settings + framework models routes
- `backend/src/lib/taint-engine-cost.ts` — cost cap enforcement helper

**New files (frontend):**
- `frontend/src/app/pages/orgs/[orgId]/settings/taint-engine/index.tsx` — framework models management page
- `frontend/src/components/settings/TaintEngineCostCapCard.tsx` — new cost-cap card with editable input
- `frontend/src/components/settings/FrameworkModelEditor.tsx` — Monaco-based JSON editor modal
- `frontend/src/components/security/ReachabilityQualityBanner.tsx` — untyped-JS warning banner

**Modified files:**
- `backend/extraction-worker/src/pipeline.ts` — insert new `taint_engine` step
- `backend/extraction-worker/Dockerfile` — pin `typescript@5.x` and any tsc-Compiler-API peer deps
- `backend/database/phase23_taint_engine.sql` — schema migration
- `backend/database/schema.sql` — refresh via `npm run schema:dump`
- `backend/src/index.ts` — register new routes
- `frontend/src/components/settings/AIConfigurationSection.tsx` — add Taint Engine card
- `frontend/src/app/routes.tsx` — add new admin page route
- `frontend/src/app/pages/projects/[projectId]/security/SecurityPage.tsx` — render quality banner

## Data Model

### Migration: `backend/database/phase23_taint_engine.sql`

```sql
-- Phase 6: Cross-File Taint Engine
--
-- Adds three new tables (runs, framework_models, settings) plus extends the
-- existing project_reachable_flows.reachability_source CHECK constraint to
-- allow 'taint_engine' flow records. Uses the existing project_reachable_flows
-- table for the flow data itself — no new flows table needed.

-- 1. Extend reachability_source CHECK on project_reachable_flows
ALTER TABLE project_reachable_flows
  DROP CONSTRAINT IF EXISTS project_reachable_flows_reachability_source_check;
ALTER TABLE project_reachable_flows
  ADD CONSTRAINT project_reachable_flows_reachability_source_check
  CHECK (reachability_source IN ('atom', 'semgrep_taint', 'taint_engine'));

-- 2. taint_engine_runs — per-extraction telemetry, used by circuit breaker
CREATE TABLE IF NOT EXISTS taint_engine_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'aborted')),
  callgraph_build_ms INTEGER,
  taint_propagation_ms INTEGER,
  ai_spec_inference_ms INTEGER,
  ai_fp_filter_ms INTEGER,
  total_ms INTEGER,
  flows_emitted INTEGER DEFAULT 0,
  flows_after_ai_filter INTEGER DEFAULT 0,
  ai_cost_usd NUMERIC(10, 6) DEFAULT 0,
  frameworks_detected TEXT[] DEFAULT '{}',
  framework_models_used JSONB DEFAULT '{}',
  is_typed_js_project BOOLEAN,
  typed_files_pct NUMERIC(5, 2),
  vuln_classes_evaluated TEXT[] DEFAULT '{}',
  error_code TEXT,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  UNIQUE(project_id, extraction_run_id)
);

CREATE INDEX idx_ter_org_created ON taint_engine_runs(organization_id, created_at DESC);
CREATE INDEX idx_ter_project_extraction ON taint_engine_runs(project_id, extraction_run_id);
CREATE INDEX idx_ter_status_created ON taint_engine_runs(status, created_at DESC);
CREATE INDEX idx_ter_failed_recent ON taint_engine_runs(created_at DESC)
  WHERE status = 'failed';

-- 3. taint_engine_framework_models — AI-inferred specs cached per (org, framework, version)
CREATE TABLE IF NOT EXISTS taint_engine_framework_models (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  framework_name TEXT NOT NULL,
  framework_version TEXT NOT NULL DEFAULT '*',
  source_type TEXT NOT NULL CHECK (source_type IN ('hand_written', 'ai_inferred', 'user_edited')),
  spec JSONB NOT NULL,
  inferred_at TIMESTAMPTZ DEFAULT NOW(),
  inferred_by_model TEXT,
  inferred_cost_usd NUMERIC(10, 6),
  edited_by_user_id UUID REFERENCES auth.users(id),
  edited_at TIMESTAMPTZ,
  last_validated_at TIMESTAMPTZ,
  validation_score NUMERIC(5, 2),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, framework_name, framework_version)
);

CREATE INDEX idx_temf_org_active ON taint_engine_framework_models(organization_id, is_active);
CREATE INDEX idx_temf_framework ON taint_engine_framework_models(framework_name);

-- 4. taint_engine_settings — per-org config
CREATE TABLE IF NOT EXISTS taint_engine_settings (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  enabled BOOLEAN DEFAULT true,
  ai_layer_enabled BOOLEAN DEFAULT true,
  monthly_ai_cost_cap_usd NUMERIC(10, 2) DEFAULT 50.00,
  untyped_js_enabled BOOLEAN DEFAULT true,
  vuln_classes_enabled TEXT[] DEFAULT ARRAY[
    'sql_injection', 'ssrf', 'xss', 'path_traversal', 'command_injection',
    'prototype_pollution', 'deserialization', 'redos', 'file_upload',
    'open_redirect', 'log_injection'
  ],
  killswitch_active BOOLEAN DEFAULT false,
  killswitch_reason TEXT,
  killswitch_activated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- No RLS — backend service-role mediated, same as project_reachable_flows
-- per phase6b_reachability_tables.sql convention.

-- 5. Helper RPC: check circuit breaker state (called by worker before each run)
CREATE OR REPLACE FUNCTION check_taint_engine_circuit_breaker(
  p_organization_id UUID,
  p_window_minutes INTEGER DEFAULT 60,
  p_failure_threshold_pct NUMERIC DEFAULT 5.0
) RETURNS TABLE(should_run BOOLEAN, recent_runs INT, recent_failures INT, failure_pct NUMERIC, killswitch_active BOOLEAN) AS $$
DECLARE
  v_killswitch BOOLEAN;
  v_recent_runs INT;
  v_recent_failures INT;
  v_failure_pct NUMERIC;
BEGIN
  -- Manual killswitch
  SELECT killswitch_active INTO v_killswitch
  FROM taint_engine_settings
  WHERE organization_id = p_organization_id;
  v_killswitch := COALESCE(v_killswitch, false);

  -- Failure rate over window
  SELECT
    COUNT(*),
    COUNT(*) FILTER (WHERE status = 'failed')
  INTO v_recent_runs, v_recent_failures
  FROM taint_engine_runs
  WHERE organization_id = p_organization_id
    AND created_at > NOW() - (p_window_minutes || ' minutes')::INTERVAL;

  v_failure_pct := CASE
    WHEN v_recent_runs > 0 THEN (v_recent_failures::NUMERIC / v_recent_runs * 100)
    ELSE 0
  END;

  RETURN QUERY SELECT
    NOT v_killswitch AND (v_recent_runs < 5 OR v_failure_pct < p_failure_threshold_pct),
    v_recent_runs,
    v_recent_failures,
    v_failure_pct,
    v_killswitch;
END;
$$ LANGUAGE plpgsql;

-- 6. Auto-engage killswitch when failure threshold tripped (called from worker after each failure)
CREATE OR REPLACE FUNCTION engage_taint_engine_killswitch(
  p_organization_id UUID,
  p_reason TEXT
) RETURNS VOID AS $$
BEGIN
  INSERT INTO taint_engine_settings (organization_id, killswitch_active, killswitch_reason, killswitch_activated_at)
  VALUES (p_organization_id, true, p_reason, NOW())
  ON CONFLICT (organization_id) DO UPDATE
  SET killswitch_active = true,
      killswitch_reason = EXCLUDED.killswitch_reason,
      killswitch_activated_at = NOW();
END;
$$ LANGUAGE plpgsql;
```

After applying via Supabase MCP: run `cd backend/extraction-worker && npm run schema:dump` to refresh `backend/database/schema.sql` (CI fails otherwise per memory).

### Data volume estimates

- `taint_engine_runs`: 1 row per extraction. ~10k rows/month at scale.
- `taint_engine_framework_models`: ~5 hand-written + ~10-30 AI-inferred per org. ~20-50 rows per org. Capped naturally.
- `taint_engine_settings`: 1 row per org. Capped at total org count.
- `project_reachable_flows`: existing growth pattern + ~5-50 additional flows per extraction (similar to atom).

## API Design

### Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| GET | `/api/orgs/:orgId/taint-engine/settings` | authenticateUser | `view_ai_spending` | Returns settings row |
| PATCH | `/api/orgs/:orgId/taint-engine/settings` | authenticateUser | `manage_aegis` | Update settings (cost cap, AI layer toggle, untyped JS toggle, vuln classes) |
| POST | `/api/orgs/:orgId/taint-engine/killswitch/release` | authenticateUser | `manage_aegis` | Manually clear killswitch (admin recovery) |
| GET | `/api/orgs/:orgId/taint-engine/runs` | authenticateUser | `view_ai_spending` | Paginated list of recent runs (telemetry / debugging) |
| GET | `/api/orgs/:orgId/taint-engine/framework-models` | authenticateUser | `view_ai_spending` | List models with metadata (no spec body — separate fetch) |
| GET | `/api/orgs/:orgId/taint-engine/framework-models/:modelId` | authenticateUser | `view_ai_spending` | Get single model with full spec JSON |
| PATCH | `/api/orgs/:orgId/taint-engine/framework-models/:modelId` | authenticateUser | `manage_aegis` | Update spec JSON; sets `source_type='user_edited'` |
| POST | `/api/orgs/:orgId/taint-engine/framework-models/:modelId/refresh` | authenticateUser | `manage_aegis` | Re-run AI inference for this framework |
| DELETE | `/api/orgs/:orgId/taint-engine/framework-models/:modelId` | authenticateUser | `manage_aegis` | Mark model inactive (soft delete) |

### Internal worker endpoints

The worker authenticates with `INTERNAL_API_KEY` and uses these (rather than direct Supabase writes) only for the cost-cap check + circuit breaker, which need backend logic:

| Method | Route | Description |
|---|---|---|
| GET | `/api/internal/taint-engine/check-cost-cap?orgId=X` | Returns `{ allowed: bool, remaining_usd: number }` for an AI call |
| GET | `/api/internal/taint-engine/circuit-breaker?orgId=X` | Returns `should_run` from RPC |
| POST | `/api/internal/taint-engine/run-complete` | Worker reports completion; backend writes telemetry + auto-engages killswitch if threshold tripped |

All other writes (flows, framework models cache) the worker does directly via supabase-js with service role.

### Types

```typescript
// backend/src/routes/taint-engine.ts (mirror in frontend types file)

export interface TaintEngineSettings {
  organization_id: string;
  enabled: boolean;
  ai_layer_enabled: boolean;
  monthly_ai_cost_cap_usd: number;
  untyped_js_enabled: boolean;
  vuln_classes_enabled: string[];
  killswitch_active: boolean;
  killswitch_reason: string | null;
  killswitch_activated_at: string | null;
}

export interface TaintEngineRun {
  id: string;
  project_id: string;
  extraction_run_id: string;
  status: 'running' | 'completed' | 'failed' | 'aborted';
  callgraph_build_ms: number | null;
  taint_propagation_ms: number | null;
  ai_spec_inference_ms: number | null;
  ai_fp_filter_ms: number | null;
  total_ms: number | null;
  flows_emitted: number;
  flows_after_ai_filter: number;
  ai_cost_usd: number;
  frameworks_detected: string[];
  is_typed_js_project: boolean | null;
  typed_files_pct: number | null;
  vuln_classes_evaluated: string[];
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface FrameworkModel {
  id: string;
  organization_id: string;
  framework_name: string;
  framework_version: string;
  source_type: 'hand_written' | 'ai_inferred' | 'user_edited';
  spec: FrameworkSpec;
  inferred_at: string;
  inferred_by_model: string | null;
  inferred_cost_usd: number | null;
  edited_by_user_id: string | null;
  edited_at: string | null;
  last_validated_at: string | null;
  validation_score: number | null;
  is_active: boolean;
}

export interface FrameworkSpec {
  framework: string;
  version: string;
  sources: FrameworkSource[];
  sinks: FrameworkSink[];
  sanitizers: FrameworkSanitizer[];
}

export interface FrameworkSource {
  pattern: string;        // e.g. "req.body.*", "process.env.*"
  taint_kind: 'http_input' | 'env' | 'file' | 'cli' | 'rpc';
  description: string;
}

export interface FrameworkSink {
  pattern: string;        // e.g. "child_process.exec(*)", "_.template(*)"
  vuln_class: string;     // 'sql_injection' | 'ssrf' | ... (matches vuln_classes_enabled)
  argument_indices: number[];  // which positional args are tainted
  description: string;
}

export interface FrameworkSanitizer {
  pattern: string;        // e.g. "DOMPurify.sanitize(*)", "validator.escape(*)"
  vuln_classes: string[]; // which vuln classes this sanitizer breaks
  description: string;
}
```

## Frontend Design

### Pages & Routes

Add to `frontend/src/app/routes.tsx`:
```tsx
{
  path: '/organizations/:orgId/settings/taint-engine',
  element: <ProtectedRoute><TaintEngineSettingsPage /></ProtectedRoute>,
},
```

The Taint Engine cost-cap card lives inside the existing AI Settings page (`AIConfigurationSection.tsx`); no new route needed for that.

### Component Tree

**TaintEngineSettingsPage** (`frontend/src/app/pages/orgs/[orgId]/settings/taint-engine/index.tsx`):
```
TaintEngineSettingsPage
├── PageHeader ("Taint Engine — Framework Models")
├── HelpText (1-paragraph explainer + link to docs)
├── AddModelButton (opens modal)
└── FrameworkModelsTable
    ├── HeaderRow (Framework | Version | Source | Last Updated | Actions)
    └── ModelRow[] (one per framework model)
        ├── FrameworkBadge (icon + name)
        ├── SourceTypeBadge (hand-written | AI-inferred | user-edited)
        ├── ActionsMenu
        │   ├── Edit (opens FrameworkModelEditor modal)
        │   ├── Refresh AI inference (only for ai_inferred)
        │   └── Delete (soft delete, confirmation)
└── AddFrameworkModal
    ├── FrameworkNameInput
    ├── FrameworkVersionInput (default "*")
    └── InferButton (triggers AI spec inference)
└── FrameworkModelEditor (Monaco JSON editor in dialog)
    ├── Editor (Monaco JSON mode with schema validation)
    ├── ValidationStatus (shows JSON parse errors + spec schema validation)
    └── SaveButton
```

**TaintEngineCostCapCard** (`frontend/src/components/settings/TaintEngineCostCapCard.tsx`):
```
TaintEngineCostCapCard (rendered inside AIConfigurationSection)
├── CardHeader ("Taint Engine cost cap")
├── CapDisplay ($X.XX/mo)
├── EditButton → opens inline edit
│   ├── NumberInput (USD amount)
│   ├── CancelButton
│   └── SaveButton (PATCH /settings, toast on success)
├── UsageProgressBar (current month spend vs cap, color-coded)
├── KillswitchStatus (shows red banner if killswitch_active)
└── ReleaseKillswitchButton (admin only, requires confirmation)
```

**ReachabilityQualityBanner** (`frontend/src/components/security/ReachabilityQualityBanner.tsx`):
```
ReachabilityQualityBanner (only renders when latest taint_engine_run.is_typed_js_project === false)
├── Icon (Info-level, amber)
├── Heading ("Reachability quality reduced")
├── BodyText (typed files % + recommendation)
├── LearnMoreLink
└── DismissButton (per-project, stored in localStorage)
```

### Design Specifications

Per `frontend-design/SKILL.md` and the tokens captured in the codebase analysis:
- **Cards**: `rounded-xl border border-border bg-background-card/50 p-5` (matches existing AI Settings cards)
- **Tables**: `bg-background-card border border-border rounded-lg overflow-hidden` with header `bg-background-card-header` and rows `divide-y divide-border` and hover `hover:bg-table-hover` (matches StatusesSection)
- **Badges**: `inline-flex items-center justify-center font-mono text-[11px] font-bold` (matches JsLangBadge)
- **Buttons**: outline variant for actions (`border border-border bg-background-card text-foreground hover:bg-background-subtle`), primary for save (`bg-primary text-primary-foreground`)
- **Color tokens**: `text-foreground` (primary), `text-foreground-secondary` (labels), `text-foreground-muted` only for footnotes; never `text-foreground/30` per memory
- **Banner**: amber `bg-amber-500/10 border border-amber-500/20 text-amber-100` for info-level quality warning
- **Killswitch banner**: `bg-destructive/10 border border-destructive/40 text-destructive` for the kill-switch alert

ASCII layout sketches for the three new surfaces are in the codebase analysis report; the implementation should match them.

## Implementation Tasks

### M1 — TS Compiler API substrate (callgraph + symbols extractor)

**Goal:** Standalone CLI that takes a TS/JS project path, builds a whole-program callgraph using the TypeScript Compiler API, and emits JSON.

**Why first:** Highest-leverage unknown. If tsc Compiler API doesn't actually deliver the cross-file callgraph quality the research promises, every later milestone breaks. Validate before investing in the propagator.

**Effort:** 2-3 weeks (single engineer).

**Tasks:**
1. **M1.1** — Scaffold `backend/extraction-worker/src/taint-engine/` directory with `index.ts`, `callgraph.ts`, `ir.ts` empty exports. Add `typescript@5.x` dep to `extraction-worker/package.json` if not already a transitive. Verify `tsc --noEmit` passes. **(S, 1 day)**
2. **M1.2** — Implement `buildCallgraph(rootDir: string): Promise<Callgraph>` in `callgraph.ts`. Use `ts.createProgram` with `allowJs: true`, walk all source files, resolve every `CallExpression` via `ts.TypeChecker.getSymbolAtLocation()` + `getResolvedSignature()`. Output: `{ nodes: FunctionNode[], edges: CallEdge[] }`. Handle import aliases, re-exports, TS namespace aliases. **(L, 1 week)**
3. **M1.3** — Add `tsconfig.json` discovery + fallback. If project has tsconfig, use it; else synthesize a permissive one (`allowJs`, `noEmit`, `target: ES2020`). Track `is_typed_js_project` boolean for telemetry. **(S, 1 day)**
4. **M1.4** — Performance: profile callgraph build on (a) test-npm fixture, (b) the deptex-test-* repos, (c) 3 OSS Node.js projects (express itself, chalk, axios). Acceptable budget: <60s for medium project (50k LOC), <5min for large (500k LOC). Optimize hot paths if over budget. **(M, 3 days)**
5. **M1.5** — CLI wrapper: `npm run taint-engine:callgraph -- <path>` outputs JSON to stdout. Useful for debugging + benchmarking. **(S, 1 day)**
6. **M1.6** — Unit tests against synthetic fixtures (cross-file imports, type aliases, namespace re-exports, dynamic dispatch via interfaces). Coverage target: every callgraph edge type. **(M, 3 days)**

**Acceptance criteria:**
- Callgraph build completes within budget on 3 reference projects
- 95%+ of `.ts` call expressions resolve to a known callee on typed projects
- Untyped JS projects degrade gracefully (callgraph emits but is sparser; `is_typed_js_project=false` flag set)
- All tests pass

**Commit:** `feat(taint-engine): build whole-program callgraph via TypeScript Compiler API`

---

### M2 — Worklist forward-propagation taint engine + IR + spec format

**Goal:** Take the M1 callgraph + a YAML framework spec → produce a list of source→sink flow records.

**Effort:** 3-4 weeks.

**Tasks:**
1. **M2.1** — Define `FrameworkSpec` YAML schema (sources, sinks, sanitizers, vuln_class taxonomy). Write JSON schema validator. **(S, 1 day)**
2. **M2.2** — Implement `loadSpec(yamlPath): FrameworkSpec` with schema validation. **(S, 1 day)**
3. **M2.3** — Define normalized IR: `Function`, `BasicBlock`, `Statement` (assign | call | return | branch). Write `astToIr()` converter that takes a function's AST and produces IR. **(L, 1 week)**
4. **M2.4** — Implement worklist forward-propagation taint propagator in `propagator.ts`. Algorithm: BFS over callgraph from each source, propagate taint sets through IR statements within each function (intra-procedural flow-sensitive), at calls join taint into callee's parameter set, on returns propagate return taint to caller. Track origin-source-and-flow-path on each tainted variable. **(XL, 2 weeks)**
5. **M2.5** — Output flow records in the `project_reachable_flows`-compatible shape (purl, dependency_id resolution, flow_nodes JSONB, entry/sink locations). Set `reachability_source = 'taint_engine'`. **(M, 2 days)**
6. **M2.6** — Unit tests against synthetic taint scenarios: (a) direct source→sink in same function, (b) source→helper→sink across files, (c) source→sanitizer→sink (should NOT emit), (d) source through promise chain, (e) deep call chain (5+ hops). **(M, 3 days)**
7. **M2.7** — Performance: budget <2min taint propagation on medium project. Profile + optimize as needed. **(M, 2 days)**

**Acceptance criteria:**
- Engine emits flows for direct source→sink + cross-file source→helper→sink
- Engine correctly suppresses flows when sanitizer is in the path
- Output flow records match `project_reachable_flows` shape exactly
- Performance budget met

**Commit:** `feat(taint-engine): forward-propagation taint engine with framework spec loader`

---

### M3 — Hand-written framework models for Express + first 5 vuln classes

**Goal:** Write the first hand-curated framework spec (Express) covering SQLi, SSRF, XSS, path traversal, command injection. Validate against synthetic fixtures.

**Effort:** 2 weeks.

**Per-vuln-class effort:** ~2 days each. Express framework spec ~3 days. Validation harness ~3 days.

**Tasks:**
1. **M3.1** — Write `framework-models/express.yaml` with sources (`req.body.*`, `req.query.*`, `req.params.*`, `req.headers.*`, `req.cookies.*`), sinks per vuln class:
   - SQLi: `db.query(*)`, `pool.query(*)`, mongoose `Model.find({ where: * })`, sequelize `query(*)`, knex `raw(*)`
   - SSRF: `axios.get(*)`, `axios.post(*)`, `fetch(*)`, `node-fetch(*)`, `http.get(*)`, `request(*)`
   - XSS: `res.send(*)`, `res.write(*)`, `res.render(template, * /* unsanitized model */)`
   - Path traversal: `fs.readFile(*)`, `fs.createReadStream(*)`, `fs.readFileSync(*)`, `fs.writeFile(*)` etc.
   - Command injection: `child_process.exec(*)`, `child_process.execSync(*)`, `child_process.spawn(*)` (with shell:true)
   - Sanitizers: `DOMPurify.sanitize`, `validator.escape`, `path.normalize`, `path.resolve`, `escapeHtml`, `mysql.escape`, parameterized queries (positional `?` patterns)
   **(M, 3 days)**
2. **M3.2** — Build synthetic fixture suite under `test/taint-engine/fixtures/express-vulns/`. One mini-project per vuln class showing (a) a true-positive flow that should fire, (b) a sanitized version that should NOT fire. **(M, 3 days)**
3. **M3.3** — Validation harness: `npm run taint-engine:validate -- express` runs the engine on each fixture, asserts expected flow count per vuln class. **(S, 1 day)**
4. **M3.4** — Iterate Express spec until all fixture assertions pass. **(M, 3 days)**

**Acceptance criteria:**
- Express spec produces expected flows on all 10 fixture pairs (5 vuln classes × {vuln, safe})
- Validation harness reports 100% pass on Express fixtures
- Engine completes within 2min on each fixture project

**Commit:** `feat(taint-engine): Express framework spec with five core vulnerability classes`

---

### M4 — Pipeline integration in shadow mode + circuit breaker + 30min timeout + extraction failure logging

**Goal:** Wire the engine into the extraction pipeline as a real step. Output goes to `project_reachable_flows` with `reachability_source = 'taint_engine'` but is NOT yet surfaced to users (shadow mode). Hard-fail policy + circuit breaker + 30min timeout.

**Effort:** 1.5-2 weeks.

**Tasks:**
1. **M4.1** — Apply `phase23_taint_engine.sql` migration via Supabase MCP. Refresh schema.sql via `npm run schema:dump`. Verify tests still pass. **(S, half day)**
2. **M4.2** — Implement `circuit-breaker.ts` calling `check_taint_engine_circuit_breaker` RPC before each run. Returns `should_run: false` if killswitch active OR failure rate >5% in last hour. **(M, 2 days)**
3. **M4.3** — Implement `storage.ts` for writing telemetry to `taint_engine_runs` (upsert per extraction) and flows to `project_reachable_flows` (insert with `reachability_source='taint_engine'`). **(S, 1 day)**
4. **M4.4** — Modify `pipeline.ts`: add new step between `framework_detection` (~line 860) and `scanning` (~line 905):
   ```typescript
   await updateStep(supabase, projectId, 'taint_engine');
   try {
     await withTimeout(async (signal) => {
       // Check circuit breaker
       const cb = await checkCircuitBreaker(supabase, organizationId);
       if (!cb.should_run) {
         await logStepError(...severity='warn');
         return;
       }
       // Run engine
       const result = await runTaintEngine({ projectId, runId, repoPath, supabase, signal });
       await storage.writeFlows(supabase, projectId, runId, result.flows);
       await storage.writeRun(supabase, { projectId, runId, ...result.telemetry, status: 'completed' });
     }, 30 * 60_000, 'taint_engine');
   } catch (err) {
     // HARD-FAIL policy: log + set killswitch + throw
     await storage.writeRun(supabase, { projectId, runId, status: 'failed', error_code, error_message });
     // Auto-engage killswitch if recent failure rate exceeds threshold
     await maybeEngageKillswitch(supabase, organizationId);
     throw err;  // propagates to setError() which halts pipeline
   }
   ```
   **(L, 4 days)**
5. **M4.5** — Add `taint_engine` to the `updateStep` enum / valid step values list (if there is one). Add to `extraction_step_errors` recognized step names. **(S, half day)**
6. **M4.6** — Implement `maybeEngageKillswitch()`: if last 60min has >=5 runs and >5% failed, call `engage_taint_engine_killswitch` RPC. **(S, 1 day)**
7. **M4.7** — Staged rollout config: env var `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT` (0-100). Worker checks at job claim time and skips engine for `random() > pct/100`. Default 0 in production. **(S, half day)**
8. **M4.8** — End-to-end integration test: run pipeline on test-npm fixture, verify (a) `taint_engine_runs` row written, (b) flows present in `project_reachable_flows` with `reachability_source='taint_engine'`, (c) classifier picks them up + updates `reachability_level`. Inject synthetic engine crash, verify killswitch engages + extraction hard-fails. **(M, 2 days)**

**Acceptance criteria:**
- Pipeline runs end-to-end with engine enabled on test-npm
- Engine telemetry persisted to `taint_engine_runs`
- Engine flows persisted to `project_reachable_flows` and picked up by classifier
- Hard-fail correctly halts extraction
- Killswitch correctly engages after threshold
- Rollout pct env var works

**Commit:** `feat(taint-engine): pipeline integration with hard-fail circuit breaker`

---

### M5 — Hand-written models for Fastify, NestJS, Next.js, Hono + next 5-6 vuln classes

**Goal:** Expand framework coverage to top 5 JS frameworks AND vuln class coverage to 11.

**Effort:** 3-4 weeks. **Per-class: 2 days. Per-framework spec: 2-3 days.**

**Per-vuln-class effort breakdown:**
| Vuln class | Sink modeling complexity | Days |
|---|---|---|
| Prototype pollution | Sinks = `_.merge`, `_.set`, `Object.assign(*, untrusted)`, recursive merge functions. Source-to-sink less standard. | 3 |
| Deserialization | Sinks = `JSON.parse(untrusted)` only when JSON-shape validation absent + `node-serialize`, `eval`, `vm.runInNewContext`. | 2 |
| ReDoS | Sinks = `RegExp(*)`, `new RegExp(*)`, `*.match(*)`, `*.test(*)`, `*.replace(*, ...)` with user-controlled regex. Edge case: known-safe regexes from packages should be sanitized. | 2 |
| File upload | Sinks = `multer.single(*)` with no MIME validation, raw `fs.writeFile(*, untrusted_filename)`. Often overlaps path traversal. | 2 |
| Open redirect | Sinks = `res.redirect(*)`, `res.location(*)`. Sanitizer = URL parse + allowlist check. | 2 |
| Log injection | Sinks = `winston.log(*)`, `pino.info(*)`, `console.log(*)` with newline-containing user input. Lower-priority class — possibly defer. | 1 |

Total ~12 days for 5 new classes if log injection deferred to v1.1, else 13 days.

**Per-framework effort breakdown:**
| Framework | Sources/sinks complexity | Days |
|---|---|---|
| Fastify | Similar to Express; `request.body`, `request.query`. Fewer middleware patterns. | 2 |
| NestJS | Decorator-based: `@Body()`, `@Query()`, `@Param()`. Need to model decorator-extracted sources. | 3 |
| Next.js | App router (`request.json()`) + Pages router (`req.body`). Server components add complexity. | 3 |
| Hono | Modern, similar to Express. `c.req.json()`, `c.req.query()`. | 2 |

Total ~10 days for 4 frameworks. Plus ~3 days fixture authoring per framework = 12 days. **Total M5: ~25 days = 5 weeks.** Realistically: 3-4 weeks if focused.

**Tasks:**
1. **M5.1** — Fastify spec + fixtures **(M, 4 days)**
2. **M5.2** — NestJS spec + fixtures **(L, 5 days)**
3. **M5.3** — Next.js spec + fixtures **(L, 5 days)**
4. **M5.4** — Hono spec + fixtures **(M, 3 days)**
5. **M5.5** — Add prototype pollution sinks/sanitizers to all 5 framework specs + fixture pair per framework **(M, 3 days)**
6. **M5.6** — Add deserialization, ReDoS, file upload, open redirect sinks across all framework specs + fixtures **(L, 5 days)**
7. **M5.7** — Optional: log injection sinks (defer to v1.1 if M5 budget tight) **(S, 1 day)**

**Acceptance criteria:**
- All 5 framework specs validate against their fixture suites
- 10 vuln classes (or 11 if log injection landed) produce expected flows on synthetic fixtures
- Engine performance still within budget across all fixtures

**Commit:** `feat(taint-engine): expand framework coverage and vulnerability class library`

---

### M6 — AI spec inference layer for long-tail frameworks + framework models DB + AI Settings UI extension

**Goal:** When the engine encounters a framework not in the hand-written set, AI infers a draft spec from the framework's source code. Specs cached per (org, framework, version). Admin UI to review/edit.

**Effort:** 3 weeks.

**Tasks:**
1. **M6.1** — Implement `spec-inference.ts`. Inputs: framework name + version + a small sample of framework source code (route handlers, middleware exports). Output: `FrameworkSpec` JSON. Uses platform Gemini Flash via `getProviderForOrg()` (with platform fallback). Prompt template defines output schema. **(L, 5 days)**
2. **M6.2** — Cost cap enforcement: before each spec inference call, check `taint_engine_settings.monthly_ai_cost_cap_usd` vs aggregated `ai_usage_logs.estimated_cost` for current month. Skip if exceeded; log warning to `taint_engine_runs`. **(M, 2 days)**
3. **M6.3** — Cache inferred specs in `taint_engine_framework_models` with `source_type='ai_inferred'`. On hit (org + framework + version), reuse without re-inferring. **(S, 1 day)**
4. **M6.4** — Backend routes for framework models CRUD + refresh + delete (per API design table above). **(M, 3 days)**
5. **M6.5** — Backend routes for taint engine settings (GET + PATCH + killswitch release). **(S, 2 days)**
6. **M6.6** — Frontend: `TaintEngineSettingsPage` with framework models table + add modal + edit modal. **(L, 5 days)**
7. **M6.7** — Frontend: `TaintEngineCostCapCard` integrated into `AIConfigurationSection`. First editable cost-cap form in the codebase. **(M, 3 days)**
8. **M6.8** — Add route to `routes.tsx`. RBAC: `manage_aegis` for edits, `view_ai_spending` for views. **(S, 1 day)**

**Acceptance criteria:**
- Engine can ingest a previously-unseen framework (e.g., tRPC) and produce a usable spec via AI inference
- Inferred spec is cached and reused on subsequent runs
- Admin UI lists, edits, refreshes, and deletes specs
- Cost cap edits persist and are enforced server-side
- AI cost is tracked in `ai_usage_logs(feature='taint_engine_spec_inference')`

**Commit:** `feat(taint-engine): AI spec inference for long-tail frameworks with admin UI`

---

### M7 — AI FP filter layer + cost tracking

**Goal:** For each flow above a confidence threshold, run an LLM check ("is this genuinely exploitable, or did the engine over-approximate?") before persisting the flow. Per-flow cost tracked. Cost cap enforced.

**Effort:** 2 weeks.

**Tasks:**
1. **M7.1** — Implement `fp-filter.ts`. Input: a flow record with full source + sink + intermediate code snippets. Output: `{ verdict: 'kept' | 'rejected', reasoning: string, confidence: number }`. Uses platform Gemini Flash. **(L, 4 days)**
2. **M7.2** — Confidence threshold for invoking the filter (default 0.7 — flows the engine is unsure about). Threshold configurable via settings. **(S, 1 day)**
3. **M7.3** — Wire into propagator: after producing the flow list, batch-filter and discard rejected flows. Track `flows_emitted` (pre-filter) vs `flows_after_ai_filter` (post-filter) in telemetry. **(M, 3 days)**
4. **M7.4** — Cost tracking: log every FP filter call to `ai_usage_logs(feature='taint_engine_fp_filter')`. Aggregate cost into `taint_engine_runs.ai_cost_usd`. **(S, 1 day)**
5. **M7.5** — Cost cap enforcement at filter time: if cost cap remaining < per-flow estimate × pending flow count, skip filter for that run (degrade to deterministic-only output for that extraction). Log warning. **(M, 2 days)**
6. **M7.6** — Optional: surface `ai_filter_verdict` per flow in the `project_reachable_flows.flow_nodes` JSONB so admins can see the filter's reasoning when debugging. **(S, 1 day)**

**Acceptance criteria:**
- FP filter reduces false-positive rate by ≥30% on a hand-labeled 100-flow sample (proxy for the published 91% reduction; we target lower for v1)
- Cost cap correctly degrades to deterministic-only when exceeded
- Per-flow cost tracked + visible in admin UI

**Commit:** `feat(taint-engine): per-flow AI false-positive filter with cost tracking`

---

### M8 — Atom A/B benchmark harness + retirement gate measurement + go/no-go

**Goal:** Build the harness that measures recall parity vs atom on a benchmark corpus, run the 30-day shadow A/B, and gate the shadow→canonical cutover.

**Effort:** 2-3 weeks (engineering) + 30 days wall clock for the A/B period.

**Tasks:**
1. **M8.1** — Benchmark harness: `npm run taint-engine:benchmark -- --corpus=phase5-88cve` runs both engines on the same projects, computes per-CVE recall, emits HTML report. Reuse the Phase 5 88-CVE corpus from `backend/extraction-worker/test/iterate/candidates.ts`. **(L, 4 days)**
2. **M8.2** — Run benchmark on test-npm + deptex-test-npm + 5 OSS reference projects. Establish atom baseline + initial Phase 6 number. **(M, 2 days)**
3. **M8.3** — Iterate framework specs / engine bugs based on first benchmark. Goal: reach atom recall parity within ±5pp on the JS subset. **(L, 1 week)**
4. **M8.4** — Enable engine in production at `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT=100` (still shadow mode — flows written but `reachability_source='taint_engine'` so the classifier prefers the higher-rank flow per PDV; if both atom and engine fire, classifier picks the higher rank). **(S, 1 day)**
5. **M8.5** — 30-day A/B observation period: monitor `taint_engine_runs` failure rate, AI cost, recall delta vs atom on incremental new projects. Daily dashboard refresh. **(N/A — wall clock)**
6. **M8.6** — Final benchmark at end of 30 days. Apply retirement gates from feature brief:
   - (a) Recall parity OR better than atom on 88-CVE Phase 5 JS subset
   - (b) 30-day A/B passed with no critical incidents (failure rate <1% sustained)
   - (c) Zero new false negatives on test-npm + deptex-test-npm vs atom-only baseline
   **(M, 2 days)**
7. **M8.7** — Go/no-go decision. If go: retire atom (remove from pipeline; set `reachability_source` constraint to remove `'atom'` value in a future migration). If no-go: extend shadow period, document residual gaps, schedule v1.1. **(S, 1 day for the go path; iterative for no-go)**

**Acceptance criteria:**
- Benchmark harness produces reproducible per-CVE recall comparison
- 30-day A/B completes without critical incidents
- Retirement gate decision documented with evidence

**Commit:** `feat(taint-engine): atom retirement based on benchmark and A/B results`

---

## Testing & Validation Strategy

### Backend tests

- **Unit (taint-engine/)**:
  - `callgraph.test.ts` — synthetic fixtures for cross-file imports, type aliases, namespace re-exports, dynamic dispatch
  - `propagator.test.ts` — direct flow, cross-file flow, sanitizer-blocks-flow, deep call chain
  - `spec-loader.test.ts` — schema validation pass/fail
  - `circuit-breaker.test.ts` — RPC mocking; killswitch engages on threshold

- **Integration**:
  - End-to-end pipeline against test-npm fixture asserting flows persisted + classifier upgrades reachability_level
  - Synthetic crash injection asserting hard-fail + killswitch engagement
  - Cost cap exhaustion asserting graceful degradation to deterministic-only

- **Routes**:
  - GET/PATCH /settings — auth + permission boundary tests
  - GET/PATCH /framework-models/:id — happy path + 404 + 403
  - POST /killswitch/release — admin-only + idempotency

### Frontend tests

- `TaintEngineSettingsPage.test.tsx` — table renders, add modal opens, edit saves
- `TaintEngineCostCapCard.test.tsx` — number input validation, save handler called with correct payload
- `FrameworkModelEditor.test.tsx` — Monaco mount + JSON validation
- `ReachabilityQualityBanner.test.tsx` — only renders when condition met, dismiss persists to localStorage

### Performance targets

- Callgraph build: <60s on 50k LOC project, <5min on 500k LOC project
- Taint propagation: <2min on 50k LOC project
- AI FP filter: <30s for ≤100 flows (batched)
- AI spec inference: <60s per (framework, version), once per cache lifetime
- **Total per-extraction budget: 30min hard timeout** (per locked decision)

### Regression risks

- `project_reachable_flows` writes increase ~2x once Phase 6 is on. Watch DB write load.
- The `updateReachabilityLevels()` classifier is fuzzy-matching dependency names; verify Phase 6 flows don't cause false matches that would falsely promote an unrelated PDV.
- AI Settings page already crowded — verify EPD card UX isn't degraded by the new Taint Engine card placement.

## Risks & Open Questions

1. **TS Compiler API performance on large repos.** Mitigated by M1.4 profiling. If we hit a wall, fallback is per-package callgraph (analyze each workspace package independently and stitch at workspace root).

2. **Untyped JS recall is unmeasured.** M4 will surface the `is_typed_js_project` + `typed_files_pct` telemetry; we'll know after first 100 production extractions whether to gate untyped JS behind a hard tsconfig requirement.

3. **Hard-fail policy means engine bugs break extractions.** Mitigated by: staged rollout (M4.7), circuit breaker (M4.6), benchmark harness validating before enabling broadly (M8). Worst case during rollout: a percentage of extractions fail; we revert via `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT=0`.

4. **Vuln class scope is 10-13 days of pure source/sink modeling in M5.** If timeline slips, log injection is the easy defer.

5. **AI cost ceiling on platform tier.** Platform Gemini Flash for spec inference (~$0.05-0.50 per framework, cached) + FP filter (~$0.001 per flow). At 1000 weekly extractions × 50 flows × $0.001 = ~$50/wk. Manageable v1; revisit BYOK requirement at month 4 (per locked decision).

6. **Spec inference quality on JS frameworks unknown.** IRIS reports 87% recall on Java with GPT-4. Our Gemini Flash on JS might be worse. M6 acceptance criteria includes a hand-review of the first 5 AI-inferred specs before declaring v1 ready.

7. **`commit_extraction` RPC interaction.** The audit found that `commit_extraction` RPC (line 1769 of pipeline.ts) handles atomic writes. Phase 6 writes flows directly via supabase-js (NOT through commit_extraction) — this is asymmetric with how atom flows are written. Need to verify there's no race condition where the classifier runs before Phase 6 flows land. **Resolved in M4.4**: Phase 6 step runs strictly BEFORE the `scanning` step that calls the classifier, so flows are visible before classification.

## Dependencies

- Phase 2 (tree-sitter usage extraction) — Phase 6 reads `project_usage_slices` + `project_entry_points` as input
- Phase 3 (atom + reachability_rules + classifier) — Phase 6 writes to the same `project_reachable_flows` table the classifier already reads from
- Phase 4 (EPD AI BYOK + cost cap) — Phase 6 mirrors the AI provider integration pattern
- Phase 5 (AI rule generator) — Phase 6 reuses `withRateLimitRetry`, `getProviderForOrg`, `ai_usage_logs` cost tracking
- Phase 5 88-CVE corpus — Phase 6's M8 benchmark harness reuses it as the eval set

## Success Criteria

**v1 GA bar (post M7):**
- Engine completes within 30min on ≥99.5% of test-npm + deptex-test-* + 10 OSS-control projects
- Engine produces ≥80% of atom's recall on JS subset of 88-CVE Phase 5 corpus
- AI FP filter reduces flow false-positive rate by ≥30% on hand-labeled 100-flow sample
- Hard-fail circuit breaker engages on synthetic crash injection
- AI cost stays under $0.10 per typical extraction
- Backend + frontend test suites pass

**Atom retirement bar (post M8):**
- Recall parity OR better than atom on 88-CVE Phase 5 JS subset
- 30 days of shadow A/B in prod with no critical incidents (failure rate <1%)
- Zero new false negatives on test-npm + deptex-test-npm vs atom-only baseline

**Beyond v1:**
- Spec inference quality validated by hand-review of 50 AI-inferred framework models — ≥80% rated "usable as-is"
- Optional published OWASP-Benchmark-style F1 score for marketing — defer to v1.1 scoping

---

## Recommended Next Step

`/implement` against this plan. Recommended starting point: M1 (TS Compiler API substrate) — highest-leverage unknown to validate first. Spin up `worktree-cross-file-taint-engine` off main, copy backend/.env + frontend/.env, run npm install in both packages.
