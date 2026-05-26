# Project Importance — Implementation Plan

## Overview

Replace the dual `asset_tier` enum + `organization_asset_tiers` custom-tier model with a single numeric `projects.importance` field. The number IS the multiplier — no enum, no lookup table, no per-org tier definition table, no per-tier SLA, no per-tier re-review settings. UI is a slider, 0.5–2.0, step 0.1, default 1.0.

Solo pre-launch: no compat shim. Direct rewrite.

## Locked decisions

1. **Field:** `projects.importance NUMERIC(3,2) NOT NULL DEFAULT 1.0 CHECK (importance >= 0.5 AND importance <= 2.0)`
2. **UI:** Radix Slider, step 0.1 (16 stops), default tick 1.0, labels `Low priority` / `Default` / `Critical`
3. **Backfill:** enum → multiplier (`CROWN_JEWELS=1.5 / EXTERNAL=1.0 / INTERNAL=0.8 / NON_PRODUCTION=0.6`); custom-tier rows use `environmental_multiplier` clamped to `[0.5, 2.0]`
4. **SLA:** drop `asset_tier_id` column, re-key UNIQUE on `(org, severity)`. One-row-per-severity. Settings page flattens.
5. **Rule-gen trigger filter:** dropped entirely. Fires on every project.
6. **Re-review settings:** dropped entirely. The whole `rereview_settings` JSONB goes away with the table.

## Migration (`phase41_drop_asset_tiers.sql`)

Single transactional migration. Order matters.

1. Add `projects.importance NUMERIC(3,2)` (nullable, no constraint yet)
2. Backfill from `asset_tier` + `asset_tier_id` join
3. `ALTER COLUMN importance SET NOT NULL`, `SET DEFAULT 1.0`, add CHECK
4. Drop dependent FKs / indexes / UNIQUEs that reference `asset_tier_id`
5. Drop `projects.asset_tier`, `projects.asset_tier_id`
6. Drop `organization_sla_policies.asset_tier_id` + recreate UNIQUE on `(organization_id, severity)`
7. Drop `organization_reachability_settings.trigger_asset_tier_max_rank`
8. Rewrite `get_effective_sla_policy(uuid, text)` — drops the tier param
9. Rewrite `commit_extraction` RPC — strip `LEFT JOIN organization_asset_tiers` + rereview inheritance
10. Rewrite `finalize_extraction` RPC — same
11. Rewrite/replace `update_sla_due_dates_for_org` (uses get_effective_sla_policy)
12. Drop `organization_asset_tiers` table
13. Drop `CREATE TYPE asset_tier`

## Code changes

### Depscanner (M1)

- `src/depscore.ts` — drop `AssetTier`, `TIER_WEIGHT`; replace `assetTier + tierMultiplier?` with `importance: number` across 5 context types (vuln, secret, semgrep, license, base). `tierWeight = ctx.importance`.
- `src/pipeline-steps/asset-tier.ts` → rename `importance.ts`, becomes 3-line read of `projects.importance`
- `src/pipeline.ts` — rename `ctx.assetTier` / `ctx.tierMultiplier` → `ctx.importance`
- `src/pipeline-types.ts` — field rename
- `src/cve-generation/coordinator.ts` — drop `fetchAssetTierRank` call + `applyTriggerPolicy` arg
- `src/cve-generation/trigger-filter.ts` — drop `fetchAssetTierRank`, drop `assetTierRank` param from `applyTriggerPolicy`, drop `asset_tier_filter` skip-reason
- `src/cve-generation/types.ts` — drop `trigger_asset_tier_max_rank` field
- `src/cli/seed.ts` — drop seeded asset tiers, drop `trigger_asset_tier_max_rank`
- `docs/framework-rule-pack-guide.md` — update formula

### Backend (M2)

- `src/routes/projects.ts` — `asset_tier` / `asset_tier_id` everywhere → `importance` (numeric). Validation: must be number in [0.5, 2.0]. ~25 sites. Drop `organization_asset_tiers` lookup + `tierById` map.
- `src/routes/integrations.ts:2248-2287` — drop the tier-name resolver, return `importance` numeric instead
- `src/routes/bitbucket-webhooks.ts:608` — same
- `src/routes/workers.ts` — if it touches asset_tier, drop
- `src/routes/organizations.ts` or wherever — delete asset-tier CRUD routes (4 endpoints: GET/POST/PATCH/DELETE)
- `src/routes/sla.ts` (or wherever) — drop the `asset_tier_id` param from policy CRUD
- `src/lib/aegis/tools/get-project-summary.ts` — drop `organization_asset_tiers` join, return `importance` numeric
- `src/lib/aegis/tools/list-projects.ts` — same
- Any Aegis system prompt mentions of "asset tier" → "importance"

### Frontend (M3)

- `src/lib/api.ts` — drop `OrganizationAssetTier` type, drop `AssetTier` type, drop 4 tier CRUD methods, drop `asset_tier`/`asset_tier_id`/`asset_tier_name`/`asset_tier_color` from `Project`, drop `asset_tier_id` from `SlaPolicy`, add `importance: number`
- `src/lib/scoring/depscore.ts` — same gut as worker depscore.ts
- `src/components/ImportanceSlider.tsx` NEW — reusable Radix Slider widget (0.5–2.0 / step 0.1 / label + value)
- `src/components/CreateProjectSidebar.tsx` — replace asset-tier picker (lines 909-967) with `<ImportanceSlider>`. Drop `orgAssetTiers` state + fetch + `getOrganizationAssetTiers` import (lines 57, 164-173).
- `src/app/pages/ProjectSettingsContent.tsx` — tier picker → ImportanceSlider
- `src/components/settings/SLAConfigurationSection.tsx` — drop per-tier tabs + `getOrganizationAssetTiers` fetch + `OrganizationAssetTier` type. One-flat-table layout.
- `src/components/vulnerabilities-graph/VulnProjectNode.tsx` — tier color/label → importance color (gradient by value)
- `src/components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout.ts` — same
- `src/components/supply-chain/useGraphLayout.ts` — same
- `src/app/pages/OrganizationOverviewPage.tsx` — tier filter/display
- `src/app/pages/SupplyChainContent.tsx` — tier badge
- `src/components/PolicyCodeEditor.tsx` — sandboxed code exposes `asset_tier`; expose `importance` instead
- `src/app/pages/NotificationRulesSection.tsx` — if tier-based triggers, drop them
- `src/components/StatusesSection.tsx` — verify references; clean
- Docs: `OrganizationsContent.tsx`, `ProjectsContent.tsx`, `PoliciesContent.tsx`, `NotificationRulesContent.tsx` — strip asset tier mentions

### Tests (M4)

- `depscanner/src/__tests__/depscore.test.ts` — rewrite all 14+ cases for new shape
- `depscanner/src/__tests__/pipeline-failures.test.ts` — fixture cleanup
- `depscanner/src/__tests__/rule-generation-step.test.ts` — drop 2 asset-tier-filter tests, drop tier seeding
- `depscanner/src/__tests__/rule-generation-step-persistence.test.ts` — drop tier seeding
- `depscanner/test/dast-v2-1c-migration-pglite.ts` — drop `seedAssetTier`, retire the 3 `asset_tier_id` test paths; one new "default importance" smoke
- `backend/src/__tests__/reachability-engine.test.ts` — `AssetTier` import gone
- `backend/src/__tests__/vulnerability-detail-suppressed.test.ts` — `asset_tier: 'tier-2'` fixture → `importance: 1.0`
- 5 `frontend/src/app/pages/__tests__/ProjectSettingsContent.*.test.tsx` — slider tests
- `frontend/src/components/__tests__/StatusesSection.test.tsx` — clean
- `frontend/src/app/pages/__tests__/SupplyChainContent.test.tsx` — clean

### CLAUDE.md (M5)

Update the Depscore paragraph — drop the "tierMultiplier from organization_asset_tiers" line, replace with "importance scalar 0.5–2.0".

## Risks

- The 6 RPCs (`commit_extraction`, `finalize_extraction`, etc.) are the heart of extraction. Rewriting needs PGLite test verification.
- Backfill order: importance populated **before** dropping `asset_tier`/`asset_tier_id`. Single migration, transactional.

## Commit milestones

1. Migration applied via MCP + schema dump
2. M1 — depscanner code + tests
3. M2 — backend code + tests
4. M3 — frontend code + slider component + tests
5. M4 — CLAUDE.md refresh + final preflight gate

No e2e harness needed beyond existing PGLite migration test + backend jest suite — this is a refactor, not a new feature.
