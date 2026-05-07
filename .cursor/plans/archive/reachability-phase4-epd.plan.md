# Reachability Phase 4: EPD Wiring + Gap Closure — Implementation Plan

## Overview

Activate the existing `applyEpdScoringFallback()` in the extraction pipeline, close the two gaps Phase 3 created (Semgrep taint flows write `entry_point_tag=null`; rule packs don't declare an entry-point class), surface contextual scoring in the vulnerability UI via a small entry-point badge, and let org admins set their own per-extraction AI cost cap. Approach is **wire + close gaps**, not rebuild — `epd.ts` (~760 lines) already implements the full BYOK Anthropic verification, sanitization detection, source snippet extraction, and conservative `PUBLIC_UNAUTH` heuristic fallback. Total estimated scope: 4 milestones, ~5 days.

## Competitive Research & Design Rationale

**Pattern across the industry** (full breakdown in `feature-brief-reachability-phase4-epd.md`): vendors who do EPD-style contextual scoring also *name the entry point* in the UI. Endor Labs shows "reachable from public endpoint at `routes/api.ts:42`" inline on each vuln; Snyk's Priority Score lists contributing factors in a hover-card. Phase 4 adopts the **Endor pattern** — small entry-point badge per reachable vuln row, color-coded by risk weight — without (yet) the full Snyk-style factor breakdown panel. Factor breakdown is a candidate for a later UX pass once we have real adoption data; shipping the badge first keeps scope tight.

**Where we differentiate:** the per-org cost cap surfaced in `AIConfigurationSection` is unusual — most competitors hide AI cost as a black box. Surfacing it matches Deptex's BYOK transparency posture (the `monthly_cost_cap` field already exists per-provider; this adds a per-extraction cap for one specific AI feature).

**Key design correction from the brief:** the brief proposed deriving `entry_point_tag` by parsing Semgrep `pattern-sources`. After reading actual rule.yml files (`reachability-rules/CVE-2020-14343-pyyaml-unsafe-load/rule.yml`, `CVE-2021-44228-log4j-log4shell/rule.yml`), the patterns are too heterogeneous to map reliably — Flask `request.data` mixes with Python `os.environ`, Java `System.getenv` mixes with `$REQ.getParameter(...)`. The cleaner design is to **add an explicit `entry_point_class` metadata field to each rule.yml**. Defaults to `PUBLIC_UNAUTH` since all 20 current rules trace HTTP-request input or env-var-as-attacker-input; the field is opt-out, not opt-in, so we don't have to touch all 20 packs unless we want a different class.

## Codebase Analysis

**Files to modify:**

| File | Change | Lines |
|------|--------|-------|
| `backend/extraction-worker/src/pipeline.ts` | Uncomment EPD call at lines 1720–1729; wrap in structured try/catch with `extraction_step_errors` warn-level logging on failure (matches existing Semgrep step pattern at line 1742+). Modify Phase 3 taint flow row construction at lines 1530–1595: read `entry_point_class` from rule metadata, write `entry_point_tag: framework-input:<class>` instead of `null` at line 1586. | ~30 |
| `backend/extraction-worker/src/reachability-rules.ts` | Extend `RuleMetadata` interface (line 27–34) with optional `entryPointClass?: 'PUBLIC_UNAUTH' \| 'AUTH_INTERNAL' \| 'OFFLINE_WORKER'` (default `'PUBLIC_UNAUTH'`). `loadAllRulesWithSkipped` (line 105+) parses the new field from `metadata.entry_point_class` if present. | ~10 |
| `backend/extraction-worker/src/epd.ts` | Replace `getRunBudgetCapUsd()` (line 101–105) with org-aware lookup. New helper takes the project's `organization_id` (already fetched at line 421) and reads `organizations.epd_max_run_cost_usd`; falls back to env var when NULL. Read `epd_budget_exceeded_behavior` from same row to choose `fail_job` vs `continue_with_fallback` per Open Question #1. | ~25 |
| `backend/src/routes/organizations.ts` | Two new endpoints (~line 6229 area, alongside existing AI handlers): `GET /:id/ai-settings` and `PATCH /:id/ai-settings`. Both gated on `manage_organization_settings` (write) / `view_ai_spending` (read). Server-side clamp on `epd_max_run_cost_usd` to 0.10–20.00. | ~70 |
| `frontend/src/lib/api.ts` | Add `getOrgAISettings(orgId)` and `updateOrgAISettings(orgId, patch)` api methods + types. Existing `ProjectVulnerability` type already has `entry_point_classification` and `epd_status` from earlier UI work. | ~25 |
| `frontend/src/components/settings/AIConfigurationSection.tsx` | New "Reachability AI verification" panel between the Providers grid (line 348–431) and "Your providers" table (line 434–521). Number input for `epd_max_run_cost_usd` with default-placeholder showing the env-var fallback value, save-on-blur. Disabled state with a hint ("Configure Anthropic BYOK to enable") when no Anthropic provider connected. | ~80 |
| `frontend/src/components/security/EntryPointBadge.tsx` | NEW. Small color-coded pill component. Color mapping: `PUBLIC_UNAUTH` → red-400 (matches existing severity badges), `AUTH_INTERNAL` → amber-400, `OFFLINE_WORKER` → foreground-secondary. Tooltip via existing Radix Tooltip primitive (no new dep). | ~60 (new file) |
| `frontend/src/components/security/VulnerabilityExpandableTable.tsx` | Render `<EntryPointBadge />` next to depscore badge in each reachable vuln row (table cell adjacent to `rawDepscore` at line 42–45 area). | ~5 |
| `frontend/src/components/VersionSidebar.tsx` | Render `<EntryPointBadge />` next to `<VulnDepscoreBadge />` (line 41–55 area). | ~5 |

**No changes needed to:**
- `epd.ts` core scoring logic — it's correct, just unwired
- `project_reachable_flows` schema — `entry_point_tag TEXT` already exists, we just populate it
- `project_dependency_vulnerabilities` schema — all EPD columns already exist (verified via `phase18_epd_scoring.sql` reference in CLAUDE.md depscore section)
- Phase 3 reachability rules already on disk (20 packs in `reachability-rules/CVE-*/rule.yml`) — their default behavior stays `PUBLIC_UNAUTH` without any rule-pack edits

**Reusable code identified:**
- Existing `<Tooltip>` / `<TooltipContent>` Radix primitives (already used in `VulnerabilityExpandableTable.tsx:4266` for the depscore tooltip)
- Existing severity badge color tokens (`bg-red-500/10 text-red-400` pattern used throughout security/)
- `useToast` hook for save confirmations (already used in AIConfigurationSection)
- `withTimeout` helper (already wraps the EPD call site we're uncommenting wouldn't have wrapped)
- `extraction_step_errors` table + `logStepError` helper (matches Semgrep's existing failure path)
- Permission constants `manage_organization_settings`, `view_ai_spending` (already enforced in nearby AI provider routes)

**Integration points:**
- EPD call must run **after** `updateReachabilityLevels()` (so `reachability_level` is set) but **before** the SAST Semgrep step at line 1734 — same insertion point as the current commented block
- Frontend badge consumes existing `entry_point_classification` field already on the `ProjectVulnerability` type — no schema or API shape change needed
- Org settings API is a new sibling of the existing AI provider routes — same auth middleware, same permission style, same response shape conventions

**Conflicts / constraints to respect:**
- `monthly_cost_cap` on `organization_ai_providers` is **per-provider, all features** — different knob from EPD's per-extraction cap. Don't overload it.
- Soft-switch commit pattern (Phase 19): EPD writes scoped to current `extraction_run_id` via existing PipelineState helpers — no extra logic needed because we update `project_dependency_vulnerabilities` rows that were just inserted under this run's `extraction_run_id`.
- `feedback_select_error_destructure.md` — every new supabase `.select` must destructure `{ data, error }` and branch. EPD code already follows this; new org-settings endpoint must too.
- `feedback_apply_migrations_via_mcp.md` — apply the new migration via Supabase MCP, not manual SQL.
- `feedback_button_style.md` + `feedback_vercel_typography.md` — outline-style buttons, near-full-contrast text, no `/30` opacity on body content.

## Data Model

### Migration

**File:** `backend/database/phase24_epd_org_settings.sql` (next sequential after the highest current `phaseNN_*.sql` filename)

```sql
-- Phase 24: EPD per-org configuration
-- Adds organization-level knobs for the EPD (Exploitable Path Dominance)
-- contextual scoring pass that runs in the extraction worker's pipeline.
-- See backend/extraction-worker/src/epd.ts for the consumer.

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS epd_max_run_cost_usd NUMERIC(6, 2),
  ADD COLUMN IF NOT EXISTS epd_budget_exceeded_behavior TEXT
    CHECK (epd_budget_exceeded_behavior IN ('fail_job', 'continue_with_fallback'));

COMMENT ON COLUMN organizations.epd_max_run_cost_usd IS
  'Per-extraction EPD AI spend cap in USD (Anthropic BYOK). NULL falls back to EPD_MAX_RUN_COST_USD env (default $3.00). Server-side clamp: 0.10 to 20.00.';

COMMENT ON COLUMN organizations.epd_budget_exceeded_behavior IS
  'On EPD budget exhaustion mid-extraction: fail_job (throw, fail extraction) or continue_with_fallback (heuristic for remaining vulns). NULL falls back to EPD_BUDGET_EXCEEDED_BEHAVIOR env (default fail_job). Recommend continue_with_fallback for org-configured caps.';
```

**Apply via Supabase MCP** (per `feedback_apply_migrations_via_mcp.md`). Then run `cd backend/extraction-worker && npm run schema:dump` to refresh `backend/database/schema.sql` per CLAUDE.md.

**No new tables.** No new indexes (NULLable columns, no query patterns hit them in WHERE).

**Data volume:** N/A — adds two nullable columns on an existing low-cardinality table.

### Existing Schema Touched

| Table | Column | Change |
|---|---|---|
| `organizations` | `epd_max_run_cost_usd NUMERIC(6,2)` | NEW |
| `organizations` | `epd_budget_exceeded_behavior TEXT` | NEW (CHECK constraint) |
| `project_reachable_flows` | `entry_point_tag TEXT` | EXISTING — pipeline now populates for taint rows (was always `null`) |
| `project_dependency_vulnerabilities` | `contextual_depscore`, `entry_point_classification`, `epd_status`, `epd_factor`, `is_sanitized`, etc. | EXISTING — phase18 schema. Pipeline now writes them. |

## API Design

### Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| `GET` | `/api/organizations/:id/ai-settings` | `authenticateUser` | `view_ai_spending` | Returns `{ epd_max_run_cost_usd: number \| null, epd_budget_exceeded_behavior: 'fail_job' \| 'continue_with_fallback' \| null }`. NULL = using env-var fallback. |
| `PATCH` | `/api/organizations/:id/ai-settings` | `authenticateUser` | `manage_organization_settings` | Body: same shape as GET response (any subset of fields). Server-side clamp on `epd_max_run_cost_usd` (0.10–20.00). Validates `epd_budget_exceeded_behavior` enum. Returns updated row shape. |

Both routes mounted in `backend/src/routes/organizations.ts` adjacent to the existing AI provider handlers (~line 6229). Same `requireOrgPermission` helper used by neighbouring routes.

### Types

```typescript
// frontend/src/lib/api.ts

export interface OrgAISettings {
  epd_max_run_cost_usd: number | null;
  epd_budget_exceeded_behavior: 'fail_job' | 'continue_with_fallback' | null;
}

export const api = {
  // ...existing methods
  async getOrgAISettings(orgId: string): Promise<OrgAISettings> {
    const res = await fetch(`/api/organizations/${orgId}/ai-settings`, {
      headers: { Authorization: `Bearer ${await getToken()}` },
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
  async updateOrgAISettings(orgId: string, patch: Partial<OrgAISettings>): Promise<OrgAISettings> {
    const res = await fetch(`/api/organizations/${orgId}/ai-settings`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${await getToken()}` },
      body: JSON.stringify(patch),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
};
```

### Backend Handler Sketch

```typescript
// backend/src/routes/organizations.ts (new section near line 6229)

router.get('/:id/ai-settings', async (req: AuthRequest, res) => {
  const orgId = req.params.id;
  const userId = req.user!.id;
  const allowed = await hasOrgPermission(userId, orgId, 'view_ai_spending');
  if (!allowed) return res.status(403).json({ error: 'Permission denied' });

  const { data, error } = await supabase
    .from('organizations')
    .select('epd_max_run_cost_usd, epd_budget_exceeded_behavior')
    .eq('id', orgId)
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

router.patch('/:id/ai-settings', async (req: AuthRequest, res) => {
  const orgId = req.params.id;
  const userId = req.user!.id;
  const allowed = await hasOrgPermission(userId, orgId, 'manage_organization_settings');
  if (!allowed) return res.status(403).json({ error: 'Permission denied' });

  const updates: Record<string, unknown> = {};
  if (req.body.epd_max_run_cost_usd !== undefined) {
    const v = req.body.epd_max_run_cost_usd;
    if (v === null) updates.epd_max_run_cost_usd = null;
    else if (typeof v !== 'number' || !Number.isFinite(v)) return res.status(400).json({ error: 'epd_max_run_cost_usd must be a number or null' });
    else updates.epd_max_run_cost_usd = Math.min(20, Math.max(0.1, v));
  }
  if (req.body.epd_budget_exceeded_behavior !== undefined) {
    const v = req.body.epd_budget_exceeded_behavior;
    if (v !== null && v !== 'fail_job' && v !== 'continue_with_fallback') {
      return res.status(400).json({ error: 'epd_budget_exceeded_behavior must be fail_job | continue_with_fallback | null' });
    }
    updates.epd_budget_exceeded_behavior = v;
  }
  if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No valid fields to update' });

  const { data, error } = await supabase
    .from('organizations')
    .update(updates)
    .eq('id', orgId)
    .select('epd_max_run_cost_usd, epd_budget_exceeded_behavior')
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
```

## Frontend Design

### EntryPointBadge Component

```tsx
// frontend/src/components/security/EntryPointBadge.tsx
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';
import { cn } from '../../lib/utils';

type Classification = 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER' | 'UNKNOWN' | null;
type EpdStatus = 'ai_verified' | 'byok_missing' | 'fallback_no_ai' | 'ai_error_fallback' | 'budget_exceeded' | null;

const STYLES: Record<Exclude<Classification, null | 'UNKNOWN'>, { label: string; cls: string; emoji: string }> = {
  PUBLIC_UNAUTH:  { label: 'Public',         cls: 'bg-red-500/10 text-red-400 border-red-500/20',          emoji: '🔓' },
  AUTH_INTERNAL:  { label: 'Authenticated',  cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20',    emoji: '🔐' },
  OFFLINE_WORKER: { label: 'Background',     cls: 'bg-foreground-secondary/10 text-foreground-secondary border-border', emoji: '⚙️' },
};

const STATUS_HINT: Record<NonNullable<EpdStatus>, string> = {
  ai_verified:        'Verified by AI based on your repository code.',
  byok_missing:       'Heuristic classification — configure Anthropic BYOK in AI Configuration to enable AI verification.',
  fallback_no_ai:     'AI verification skipped this run.',
  ai_error_fallback:  'AI call failed; fell back to heuristic classification.',
  budget_exceeded:    'AI verification budget cap reached this extraction; heuristic fallback applied.',
};

export function EntryPointBadge({ classification, status }: { classification: Classification; status: EpdStatus }) {
  if (!classification || classification === 'UNKNOWN') return null;
  const { label, cls, emoji } = STYLES[classification];
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={cn('inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-medium', cls)}>
            <span aria-hidden>{emoji}</span>{label}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs text-xs space-y-1">
          <p className="font-medium">Entry point: {label}</p>
          {status && <p className="text-foreground-secondary">{STATUS_HINT[status]}</p>}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
```

### AIConfigurationSection Extension

Insert a new card between the "Add providers" grid (currently lines 348–431) and "Your providers" table (lines 434–521):

```tsx
{/* Reachability AI verification — new in Phase 4 */}
<div>
  <h3 className="text-lg font-semibold text-foreground mb-4">Reachability AI verification</h3>
  <p className="text-sm text-foreground-secondary mb-4">
    EPD (Exploitable Path Dominance) uses your Anthropic BYOK to classify how each
    reachable vulnerability is reached — public unauthenticated endpoint, authenticated route,
    or background worker — and adjust depscores accordingly.
  </p>
  <div className="rounded-xl border border-border bg-background-card/80 p-5 space-y-4">
    <div className="grid gap-2">
      <Label htmlFor="epd-cap">Per-extraction cost cap (USD)</Label>
      <Input
        id="epd-cap"
        type="number" step="0.1" min="0.1" max="20"
        value={epdCapInput}
        onChange={(e) => setEpdCapInput(e.target.value)}
        onBlur={handleEpdCapSave}
        placeholder={anthropicConnected ? 'Default $3.00' : 'Connect Anthropic BYOK'}
        disabled={!anthropicConnected}
        className="max-w-[200px]"
      />
      <p className="text-xs text-foreground-secondary">
        Maximum AI spend per repository scan. Range: $0.10–$20.00. Lower = cheaper but less precise.
      </p>
    </div>
    <div className="grid gap-2">
      <Label htmlFor="epd-budget-exceeded">When budget is exceeded mid-scan</Label>
      <select
        id="epd-budget-exceeded"
        value={epdBudgetBehavior ?? ''}
        onChange={(e) => handleEpdBehaviorChange(e.target.value)}
        disabled={!anthropicConnected}
        className="h-9 px-2 pr-6 bg-background border border-border rounded-md text-sm text-foreground focus:ring-2 focus:ring-primary/50 focus:border-primary outline-none max-w-[260px]"
      >
        <option value="">Default (continue with heuristic)</option>
        <option value="continue_with_fallback">Continue with heuristic fallback</option>
        <option value="fail_job">Fail the extraction</option>
      </select>
    </div>
  </div>
</div>
```

### Vulnerability Table Integration

```tsx
// VulnerabilityExpandableTable.tsx — adjacent to the existing depscore badge cell
import { EntryPointBadge } from './EntryPointBadge';
// ...
<EntryPointBadge
  classification={v.entry_point_classification}
  status={v.epd_status as EpdStatus}
/>
```

Same one-liner in `VersionSidebar.tsx` next to `<VulnDepscoreBadge />`.

### Loading / Empty / Error States

- AIConfigurationSection: existing pattern (loading skeleton on mount, toast on save error)
- EntryPointBadge: returns `null` when `classification` is null or UNKNOWN — no badge rendered, no broken UI for vulns that EPD didn't process (e.g., function/module-level reachable vulns that weren't AI-verified)
- Tooltip degrades to title attr if Tooltip primitive fails (Radix handles this internally)

### Design Tokens

Per `feedback_button_style.md` and `feedback_vercel_typography.md`:
- Badge text at full opacity (`text-red-400`, not `text-red-400/70`)
- Border + bg pair for the pill (matches existing severity badges pattern in `VulnerabilityExpandableTable.tsx`)
- Outline buttons on the settings panel, no ghost variants
- Form input uses existing `<Input>` and `<Label>` components

### Performance

- AIConfigurationSection adds one extra fetch on mount (`getOrgAISettings`) — paralleled with existing `loadProviders` / `loadUsage` / `loadLogs` via `Promise.all` if we want, but cheap enough to leave separate
- EntryPointBadge: pure component, no API calls, renders inline in existing virtual-scrolled table — zero perf impact

## Implementation Tasks

### M1: Backend wiring + entry-point tag derivation (1.5 days)

1. **[S]** Add `entry_point_class` to `RuleMetadata` interface in `reachability-rules.ts:27`. Update `loadAllRulesWithSkipped` to parse `metadata.entry_point_class` from rule.yml. Default `'PUBLIC_UNAUTH'` when absent.
   - Files: `backend/extraction-worker/src/reachability-rules.ts`
   - Acceptance: existing 20 rule packs load with `entryPointClass='PUBLIC_UNAUTH'` (default); a test rule.yml with `entry_point_class: OFFLINE_WORKER` parses to that value.

2. **[S]** Modify Phase 3 taint flow row construction at `pipeline.ts:1530–1595`. At line 1586 replace `entry_point_tag: null` with `entry_point_tag: \`framework-input:\${rule.metadata.entryPointClass ?? 'PUBLIC_UNAUTH'}\``. Verify EPD's `classifyFallbackEntryPoint` substring matching in `epd.ts:378–387` correctly routes `framework-input:PUBLIC_UNAUTH` → PUBLIC_UNAUTH (need to add `framework-input` to the http/route checks at line 383, OR rely on a new explicit prefix check).
   - Files: `backend/extraction-worker/src/pipeline.ts`, `backend/extraction-worker/src/epd.ts`
   - Acceptance: a Phase 3 taint flow row in `project_reachable_flows` has `entry_point_tag = 'framework-input:PUBLIC_UNAUTH'`. EPD's heuristic classifier returns `PUBLIC_UNAUTH` for that tag.

3. **[M]** Uncomment EPD call at `pipeline.ts:1720–1729`. Wrap in structured try/catch with `extraction_step_errors` warn-level logging on non-budget-exceeded errors. Re-throw `EpdBudgetExceededError` only when org's `epd_budget_exceeded_behavior = 'fail_job'`.
   - Files: `backend/extraction-worker/src/pipeline.ts`
   - Acceptance: EPD runs in a fresh extraction; `extraction_logs` shows the EPD step entries; vuln rows have non-null `contextual_depscore` for confirmed/data_flow vulns.

4. **[S]** Restrict EPD AI eligibility to `confirmed` and `data_flow` levels in `epd.ts`. Currently `aiEligible` at line 596 only requires `reachability_status === 'reachable'` — narrow further: `reachabilityLevel === 'confirmed' || reachabilityLevel === 'data_flow'`. Heuristic-only (no AI call) for function/module.
   - Files: `backend/extraction-worker/src/epd.ts`
   - Acceptance: with BYOK present and a project containing both confirmed and function-level reachable vulns, the function-level ones get `epd_status='fallback_no_ai'` and the confirmed ones get `epd_status='ai_verified'`.

### M2: Per-org cost cap (1 day)

5. **[S]** Write `backend/database/phase24_epd_org_settings.sql` (SQL above). **Apply via Supabase MCP**, then run `cd backend/extraction-worker && npm run schema:dump`.
   - Files: new migration + regenerated `schema.sql`
   - Acceptance: `organizations` table has both columns visible via `SELECT * FROM information_schema.columns WHERE table_name = 'organizations' AND column_name LIKE 'epd%'`.

6. **[M]** Add `GET /:id/ai-settings` and `PATCH /:id/ai-settings` to `backend/src/routes/organizations.ts` (handler sketches above). Server-side clamp on cost cap. Permission gating: `view_ai_spending` for GET, `manage_organization_settings` for PATCH.
   - Files: `backend/src/routes/organizations.ts`
   - Acceptance: `curl GET /api/organizations/<id>/ai-settings` returns `{epd_max_run_cost_usd: null, epd_budget_exceeded_behavior: null}` for an unconfigured org. `PATCH` with `{epd_max_run_cost_usd: 5}` persists and round-trips. `PATCH` with `{epd_max_run_cost_usd: 100}` clamps to 20.

7. **[M]** Replace `getRunBudgetCapUsd()` at `epd.ts:101` with org-aware lookup. Pass `organizationId` (already available at `epd.ts:430`) into a new helper `getOrgAISettings(supabase, organizationId)` that returns the row or `{ epd_max_run_cost_usd: null, epd_budget_exceeded_behavior: null }`. Apply to runtime cap selection (line 543 area) and to the budget-exceeded behavior at `epd.ts:757`.
   - Files: `backend/extraction-worker/src/epd.ts`
   - Acceptance: setting `epd_max_run_cost_usd = 0.50` on the org caps EPD AI spend at $0.50 in the next extraction (verifiable via the `run_spend_usd` field in extraction_logs `epd` summary metadata). Setting `epd_budget_exceeded_behavior = 'continue_with_fallback'` lets the extraction complete instead of throwing.

### M3: Frontend disclosure (1.5 days)

8. **[M]** Create `frontend/src/components/security/EntryPointBadge.tsx` (component above).
   - Files: new file
   - Acceptance: standalone import + render in any test page works; tooltip appears on hover; null classification renders nothing.

9. **[S]** Render `<EntryPointBadge />` in `VulnerabilityExpandableTable.tsx` next to depscore badge for each reachable vuln row (insert near the existing depscore-badge cell around line 4232–4280).
   - Files: `frontend/src/components/security/VulnerabilityExpandableTable.tsx`
   - Acceptance: a project with confirmed vulns shows red "Public" badges; an empty project shows no badges; manual smoke test in browser.

10. **[S]** Render `<EntryPointBadge />` in `VersionSidebar.tsx` next to `<VulnDepscoreBadge />` (line 41–55 area).
    - Files: `frontend/src/components/VersionSidebar.tsx`
    - Acceptance: opening a dependency version sidebar with reachable vulns shows the badge alongside the depscore.

11. **[L]** Extend `AIConfigurationSection.tsx` with the "Reachability AI verification" panel (sketch above). New state: `epdCapInput`, `epdBudgetBehavior`, `anthropicConnected` (derived from `providerMap.anthropic`). Save on input blur via `api.updateOrgAISettings`. Toast confirmation. Disabled state when no Anthropic provider connected.
    - Files: `frontend/src/components/settings/AIConfigurationSection.tsx`, `frontend/src/lib/api.ts` (add the two new methods + types)
    - Acceptance: org with no Anthropic BYOK shows disabled inputs with hint text. Org with Anthropic BYOK can save a value; reload page; value persists. Setting an out-of-range value clamps server-side and the saved value reflects the clamp.

### M4: Verification + tests (1 day)

12. **[M]** End-to-end verification on `deptex-test-npm` with Anthropic BYOK configured:
    - Trigger fresh extraction (manual sync button)
    - SQL: `SELECT osv_id, reachability_level, contextual_depscore, entry_point_classification, epd_status FROM project_dependency_vulnerabilities WHERE project_id = '<id>' AND reachability_level IN ('confirmed', 'data_flow');`
    - Expected: ≥80% have non-null `contextual_depscore`; ≥70% have `epd_status='ai_verified'`; entry_point_classification distribution shows realistic mix (not all PUBLIC_UNAUTH if AI is doing real work)
    - UI: open Security page, confirm badges render on confirmed vulns

13. **[M]** Same project, BYOK removed (delete the Anthropic provider in Settings → AI):
    - Trigger fresh extraction
    - Expected: 100% of confirmed/data_flow vulns have `epd_status='byok_missing'` AND non-null `entry_point_classification` (heuristic path works)
    - UI: badges still render but tooltip shows "Heuristic classification — configure BYOK..."

14. **[M]** Add unit test for org cost cap fallback in `backend/extraction-worker/src/__tests__/` (new file or extend existing): mock supabase, return org with `epd_max_run_cost_usd = null`, verify env-var fallback. Then return org with `epd_max_run_cost_usd = 5`, verify it's used. Then return org with `epd_max_run_cost_usd = 0.10`, verify behavior at the lower clamp boundary.
    - Files: new test file or extension to existing EPD test
    - Acceptance: `npm test` passes; new tests cover the three cases above.

15. **[S]** Manual UI walkthrough checklist:
    - AI Configuration → cost cap field saves (200 status), persists across reload
    - Cost cap field disabled state when no Anthropic BYOK
    - Out-of-range value (e.g. 100) gets clamped server-side
    - Vulnerability page badges render on confirmed vulns
    - Tooltip text accurate for each `epd_status`
    - VersionSidebar opens with badge visible
    - No badge when classification is null/UNKNOWN

## Testing & Validation Strategy

**Backend coverage:**
- New `getOrgAISettings(supabase, orgId)` helper unit-tested for env fallback + override + clamp boundary
- EPD `applyEpdScoringFallback` integration with mocked supabase + mock Anthropic response — already partially covered, extend if gaps surface
- Org-settings endpoints — happy path, permission denial (403), validation rejection (400), out-of-range clamp behavior

**Frontend coverage:**
- Manual: walk through M4 task #15 checklist in browser
- No automated React tests planned — Phase 4 components are simple enough that visual smoke is sufficient. (If we add component tests later, prioritise the clamp display logic in AIConfigurationSection.)

**Integration coverage:**
- M4 tasks #12 and #13 are the canonical end-to-end tests (BYOK present + BYOK absent paths against a real test project)
- Verify `extraction_step_errors` does NOT contain unrelated errors after EPD runs (regression check that the wrap-in-try/catch doesn't accidentally suppress other failures)

**Performance targets:**
- EPD adds ~60–90s wall time when BYOK present (≤30 AI calls × 2–3s each). Acceptable inside Fly's 90-min hard kill.
- Org-settings GET <50ms (single-row select on indexed PK)
- Frontend badge render: zero measurable impact (pure inline component)

**Regression checks:**
- Run existing reachability test suite: `cd backend/extraction-worker && npm test`. Phase 3's 18 tests must still pass.
- Existing `contextual_depscore` sort + tooltip logic in `VulnerabilityExpandableTable.tsx` must continue to work (already wired pre-Phase 4)

## Risks & Open Questions

**Risks:**
- **EPD wall-time blowup:** if a project has 100+ confirmed/data_flow vulns, AI cost cap kicks in mid-run and only the top 30 (sorted by base depscore) get verified. Verify this is the actual sort order, not random.
- **Anthropic API outage during EPD run:** per-vuln catch already handles individual failures; full outage marks all rows `ai_error_fallback`. Acceptable degradation.
- **Existing EPD code calls Anthropic SDK directly via `fetch`** — not through the centralized BYOK provider. If Anthropic deprecates the v1/messages endpoint or changes the structured-output schema, EPD breaks. Out-of-scope for Phase 4 but worth a memory entry.
- **`epd_max_run_cost_usd` decimal precision** — `NUMERIC(6,2)` allows 9999.99 but our clamp is 20.00. Sufficient overhead, no risk.

**Open Questions** (carried over from brief, resolved here):

1. **Per-org budget-exceeded behavior default** — RESOLVED in M2 task #6: schema column allows NULL, NULL falls back to env (default `fail_job`); UI default shown is `continue_with_fallback` to make the org-configured path graceful. Org admin can flip to `fail_job` if they want hard enforcement.
2. **`project_entry_points` join for atom-derived flows** — DEFERRED. Atom-derived flows (Java, Python via dep-scan) keep their existing `entry_point_tag` (set at `reachability.ts:125` from `firstNode.tags`). EPD's heuristic classifier handles those tags correctly already. Cross-table join is a future enhancement (logged in Open Questions of brief).
3. **Backfill** — RESOLVED: lazy. Next webhook push or daily sync triggers EPD on each project naturally. No deploy-time auto-re-extraction.

**Newly surfaced during planning:**

4. **`epd_status` typing on frontend** — currently typed loosely as `string` in `ProjectVulnerability`. M3 task #11 should narrow it to the literal union for type safety in `EntryPointBadge`. Add to `frontend/src/lib/api.ts`.
5. **Reactivity:** AI Configuration changes don't trigger re-extraction. New cost-cap value applies on next natural extraction trigger. Acceptable — admin-set and forget.

## Dependencies

**Built on:**
- Phase 19 (atomic commit / extraction_run_id) — EPD writes scoped to current run via existing PipelineState
- Phase 2 (tree-sitter framework detectors) — `project_entry_points` populated, but **not directly joined** by Phase 4 (consumed indirectly via Semgrep `entry_point_class` metadata)
- Phase 3 (reachability rules) — provides the taint flows EPD scores; Phase 4 adds the `entry_point_class` metadata field to existing rule.yml format
- Existing `epd.ts` (~760 lines) — reused as-is, modifications restricted to org-aware budget cap (M2 task #7) and AI-eligibility narrowing (M1 task #4)
- Existing `<Tooltip>` Radix primitive, severity badge color tokens, `useToast` hook

**Not yet built:**
- AI cost telemetry surfacing per EPD run — already covered by existing `epd_status_counts` metadata in extraction_logs (queryable), no UI surfacing this phase

## Success Criteria

- [ ] ≥80% of confirmed/data_flow vulns receive a non-null `contextual_depscore` after one extraction (proves EPD is running and producing data)
- [ ] For orgs with BYOK: ≥70% of confirmed vulns have `epd_status = 'ai_verified'` (proves AI path works end-to-end)
- [ ] For orgs without BYOK: 100% of confirmed vulns have `epd_status = 'byok_missing'` AND `entry_point_classification != null` (proves heuristic path doesn't silently fail)
- [ ] Median `contextual_depscore` < median base `depscore` across all reachable vulns (proves EPD actually narrows the noise)
- [ ] Zero EPD-related extraction failures in the first 50 extractions post-deploy
- [ ] Entry-point badge visible on ≥80% of reachable vuln rows in the UI
- [ ] Cost-cap setting saves and round-trips; clamped values reflect the clamp; out-of-range entries rejected with 400
- [ ] No regression in Phase 3 reachability tests (`npm test` in extraction-worker still passes 18/18)
