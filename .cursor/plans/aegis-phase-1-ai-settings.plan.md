# Aegis Phase 1 — AI Settings Page (Provider Default + Usage)

## Overview

Build a new top-level **"AI"** page in Org Settings (positioned just below Roles). The page replaces the orphaned `AIConfigurationSection` dead code with a far simpler model: orgs don't set up API keys — Deptex provides platform-paid OpenAI / Anthropic / Google. Each org just picks which one Aegis uses by default, and the same page surfaces token spend, cost, daily trend, per-feature breakdown, and per-Aegis-tool execution counts.

This unblocks the "No AI provider configured" error Henry hit on first chat send and ships the AI usage dashboard at the same time.

## Codebase Analysis

### What already exists (verified 2026-04-27)

- **Backend**
  - `backend/src/lib/aegis/llm-provider.ts` exposes `getLanguageModelForOrg(orgId)` — currently throws "No AI provider configured" if no row in `organization_ai_providers`. **This is the resolver to swap.**
  - `backend/src/lib/ai/models.ts` holds `DEFAULT_MODELS` map (openai/anthropic/google) — reuse.
  - `backend/src/lib/ai/encryption.ts` — AES-256-GCM helpers. Stays for future BYOK.
  - `backend/src/lib/ai/cost-cap.ts` — Redis-backed `checkMonthlyCostCap()` + `recordActualCost()`. Already wired into the chat path; works as-is.
  - `backend/src/lib/ai/logging.ts` — `logAIUsage()` writes `ai_usage_logs`. Already called from `aegis.ts:975, 1025` and `executor-v2.ts:214`.
  - **Read endpoints already exist** (`GET /api/organizations/:id/ai-usage`, `/ai-usage/logs`, `/api/aegis/spending/:orgId`, `/api/aegis/usage-stats/:orgId`). New page can reuse most; only daily-trend bucket and per-tool breakdown need new endpoints.
  - **BYOK routes still mounted** in `organizations.ts:6229–6463`. Leave dormant — no UI calls them.

- **Frontend**
  - `frontend/src/components/settings/AIConfigurationSection.tsx` (47KB) — **orphaned**. Not imported anywhere except itself + one test file. Delete.
  - `frontend/src/__tests__/ai-aegis.test.ts` — only tests orphaned code. Delete or refit.
  - `frontend/src/app/pages/OrganizationSettingsPage.tsx` line 151 — `VALID_SETTINGS_SECTIONS` set; insert `'ai'` after `'roles'`. Sidebar nav follows the same order.
  - `frontend/src/lib/api.ts` — `addAIProvider`, `setDefaultAIProvider`, `testAIProvider`, etc. unused. Delete.
  - `recharts@^2.15.4` already in `package.json`.

- **Database**
  - `organization_ai_providers` exists (BYOK rows). Stays untouched.
  - `ai_usage_logs` (phase6c) — feature/tier/provider/model/tokens/cost/created_at. Indexed by org_created and org_month.
  - `aegis_tool_executions` (phase7b) — tool_name/tokens_used/estimated_cost/created_at. Indexed by org + created.
  - `organizations` table — needs new `default_ai_provider` column.

### What's missing

- A column on `organizations` (or equivalent) holding the org's chosen default provider.
- A platform-key resolver (`getPlatformKeyForProvider`) reading env vars.
- Two read endpoints: daily-trend bucket and per-Aegis-tool breakdown.
- The new "AI" page itself.

### Reusable code identified

- `recharts` `LineChart` / `BarChart` for trend + breakdown viz.
- Existing settings sidebar pattern in `OrganizationSettingsPage.tsx`.
- Permission checks via `userRolePermissions` (`view_ai_spending`, `manage_organization_settings`).
- Cards + provider logos already used in (now-orphaned) `AIConfigurationSection` — port the visual treatment.

## Data Model

### New column on `organizations`

```sql
-- Migration: phase1_aegis_default_ai_provider.sql
ALTER TABLE organizations
  ADD COLUMN default_ai_provider TEXT NOT NULL DEFAULT 'anthropic'
    CHECK (default_ai_provider IN ('openai', 'anthropic', 'google'));

COMMENT ON COLUMN organizations.default_ai_provider IS
  'Platform-default AI provider for Aegis and other AI features. Resolves to a Deptex-paid API key via env vars (OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_AI_API_KEY).';
```

After applying via Supabase MCP: `cd backend/extraction-worker && npm run schema:dump`.

## API Design

### Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| GET | `/api/organizations/:id/ai-default-provider` | `authenticateUser` | org member | Returns `{provider, model}` (model resolved from `DEFAULT_MODELS[provider]`) |
| PATCH | `/api/organizations/:id/ai-default-provider` | `authenticateUser` | `manage_organization_settings` | Body `{provider}` ∈ openai/anthropic/google. Updates `organizations.default_ai_provider`. Returns new value. |
| GET | `/api/organizations/:id/ai-usage/daily?days=30` | `authenticateUser` | `view_ai_spending` OR `manage_integrations` | Returns `[{date: 'YYYY-MM-DD', tokens: int, cost_cents: int}]` for last N days |
| GET | `/api/organizations/:id/aegis-tools/breakdown?days=30&limit=10` | `authenticateUser` | `view_ai_spending` OR `manage_integrations` | Returns `[{tool_name, executions, total_tokens, total_cost_cents}]` top-N over period |

### Types (TypeScript)

```typescript
interface AIDefaultProviderResponse {
  provider: 'openai' | 'anthropic' | 'google';
  model: string;
}

interface DailyUsagePoint {
  date: string;          // YYYY-MM-DD
  tokens: number;
  cost_cents: number;
}

interface AegisToolBreakdownRow {
  tool_name: string;
  executions: number;
  total_tokens: number;
  total_cost_cents: number;
}
```

### `getLanguageModelForOrg` rewrite

```typescript
export async function getLanguageModelForOrg(orgId: string): Promise<LanguageModel> {
  const { data: org } = await supabase
    .from('organizations')
    .select('default_ai_provider')
    .eq('id', orgId)
    .single();

  const provider = org?.default_ai_provider ?? 'anthropic';
  const apiKey = getPlatformKeyForProvider(provider);
  if (!apiKey) {
    throw new Error(
      `Platform API key for ${provider} is not configured. Set ${envVarFor(provider)} on the backend.`
    );
  }
  const model = DEFAULT_MODELS[provider];
  return getLanguageModel({ provider, apiKey, model });
}

function getPlatformKeyForProvider(provider): string | undefined {
  switch (provider) {
    case 'openai':    return process.env.OPENAI_API_KEY;
    case 'anthropic': return process.env.ANTHROPIC_API_KEY;
    case 'google':    return process.env.GOOGLE_AI_API_KEY;
  }
}
```

BYOK helpers in `llm-provider.ts` (`getProviderInfoForOrg`, etc.) stay for now — dormant.

## Frontend Design

### Pages & Routes

- New section ID: `'ai'`. Add to `VALID_SETTINGS_SECTIONS` set + nav list in `OrganizationSettingsPage.tsx`. URL pattern stays `/organizations/:id/settings/ai`.
- New component: `frontend/src/components/settings/AISection.tsx`.

### Component Tree

```
AISection
├── ProviderPicker
│   └── ProviderCard (×3) — OpenAI / Anthropic / Google
└── UsagePanel
    ├── TopLineStats (tokens this month, est cost, cap progress bar)
    ├── DailyTrendChart (Recharts LineChart, last 30 days)
    ├── FeatureBreakdown (existing /ai-usage cost-by-feature, simple table)
    ├── AegisToolBreakdown (Recharts BarChart, top-10 tools by execution count)
    └── RecentActivity (table of last 25 ai_usage_logs rows, paginated)
```

### Design Specifications

Reference `.cursor/skills/frontend-design/SKILL.md`:

- **Provider cards**: `rounded-lg border border-border bg-background-card p-6`, hover `hover:border-foreground/20`, selected gets `border-foreground ring-1 ring-foreground/40`. Click anywhere on card to switch. Selected card shows a subtle "Default" pill (`text-xs text-foreground-secondary`).
- **Stats row**: 3 stat cards in a grid. `rounded-lg border border-border bg-background-card`. Label uses `text-foreground-secondary text-xs uppercase tracking-wide`, value uses `text-2xl font-semibold text-foreground`.
- **Cap progress bar**: thin (h-1.5), `bg-background-subtle`, fill `bg-foreground` (or amber at >75%, red at >90%).
- **Charts**: Recharts with theme-matched stroke `stroke="hsl(var(--foreground))"`, axis text `fill: hsl(var(--foreground) / 0.5)`, grid `stroke="hsl(var(--border))"`. No legend unless multi-series. Tooltip uses our card surface.
- **Tables**: header `bg-background-card-header`, rows `divide-y divide-border`, hover `hover:bg-table-hover`.
- **Empty states**: when no usage yet, centered icon + "No AI usage yet — start a chat with Aegis" + button.
- Buttons: `outline` variant per `feedback_button_style` memory.
- Text contrast: never below `/50` opacity per `feedback_vercel_typography` memory.

### Provider Card Visual Treatment

Each card shows: provider logo, provider name (e.g. "Anthropic"), default model label (e.g. "Claude Sonnet 4.6"), short blurb (e.g. "Best tool-calling, balanced cost"). Three blurbs Henry can tune later.

## Implementation Tasks

### M1 — Data model + platform-key resolution (S)

Files modified:
- New migration via Supabase MCP: `phase1_aegis_default_ai_provider.sql`
- `backend/database/schema.sql` (regenerated)
- `backend/src/lib/aegis/llm-provider.ts`
- `backend/src/lib/ai/models.ts` (verify defaults)

Acceptance: `getLanguageModelForOrg('<any-org-id>')` returns a working model from platform keys with no `organization_ai_providers` row required.

### M2 — Backend routes (S)

Files modified:
- `backend/src/routes/organizations.ts` (add 4 endpoints)

Acceptance: all 4 endpoints respond correctly with auth + permission checks. Manual curl shows expected shapes.

### M3 — Frontend "AI" page (M)

Files modified / created:
- `frontend/src/components/settings/AISection.tsx` (new)
- `frontend/src/app/pages/OrganizationSettingsPage.tsx` (sidebar + section dispatch)
- `frontend/src/lib/api.ts` (4 new client methods)

Acceptance: navigating to `/organizations/<id>/settings/ai` renders the page; provider selection persists across reload; charts render with real data; empty states render gracefully.

### M4 — Cleanup (S)

Files deleted:
- `frontend/src/components/settings/AIConfigurationSection.tsx`
- `frontend/src/__tests__/ai-aegis.test.ts` (or refit if it has reusable patterns)
- Unused BYOK methods in `frontend/src/lib/api.ts`

Backend `organization_ai_providers` routes stay mounted — dormant, no harm.

### M5 — Smoke test (S)

Acceptance: with `ANTHROPIC_API_KEY` set on backend, fresh chat in Aegis on Henry's org succeeds end-to-end with the v3 ToolLoopAgent flow. Switch default to `openai` (assuming `OPENAI_API_KEY` set), refresh, send another chat, confirm it routes to the new provider.

## Testing & Validation Strategy

- **Backend**:
  - Unit-test `getLanguageModelForOrg` happy path + missing-key path.
  - Light integration check via existing test scaffolding for the new endpoints (or manual curl since this is solo-pre-launch).
- **Frontend**:
  - Visual: render with seeded data; render empty state; verify cap bar color thresholds.
  - Switching provider triggers a single PATCH and updates the selected card without reload.
- **End-to-end**:
  - Aegis chat from a fresh org with no manual setup → tool loop executes through the chosen platform provider.
- **Performance**:
  - Daily-trend query touches `ai_usage_logs` filtered by `organization_id` and `created_at >= now() - 30d`; existing `idx_ai_usage_org_created` covers this.
  - Tool-breakdown query touches `aegis_tool_executions` with same filter; index covers it.

## Risks & Open Questions

- **Risk**: An org's `default_ai_provider` gets set to a provider whose platform key isn't on the backend. Mitigation: clear error message + frontend can surface a "this provider isn't available — pick another" hint by checking which keys are configured. Stretch goal — could add a `GET /api/ai/available-providers` endpoint that returns the subset of providers with keys live; for now the page lets you pick any of the 3 and surfaces the runtime error if it fails. Decision: defer; ship with all 3 always pickable.
- **Risk**: BYOK code in `llm-provider.ts` quietly bit-rots. Mitigation: noted in Phase 1 memory; revisit when BYOK comes back as advanced.
- **Open Q**: Do we want a per-feature provider override later (e.g. Aegis chat uses Anthropic, summarization uses Google)? Henry flagged this is **future work**.

## Dependencies

- `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` must be set on Fly.io backend before M5 succeeds for those providers. `GOOGLE_AI_API_KEY` already set.
- Supabase MCP (`mcp__claude_ai_Supabase__apply_migration`) for the schema change.

## Success Criteria

1. Henry can navigate to **Org Settings → AI**, see 3 provider cards, pick one, and have Aegis use that provider on the next chat — no API keys ever pasted.
2. The same page shows current-month token spend, est cost, cap progress, daily trend chart, per-feature breakdown, per-Aegis-tool execution counts, and recent activity log.
3. The orphaned `AIConfigurationSection.tsx` is gone.
4. CI green: typecheck + schema dump fresh.
