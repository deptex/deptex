# Billing Prepaid Rewrite — Implementation Plan (v3, second-round review patches)

**Status:** Pre-implementation. Output of `/plan-feature` 2026-05-22 + two rounds of `/review-plan` patches applied 2026-05-22.
**Feature brief:** `.cursor/plans/feature-brief-billing-prepaid-rewrite.md`
**Review reports:** `.cursor/plans/review-billing-prepaid-rewrite.md` (latest is v2 review; REVISE → patched to v3)
**Worktree:** `worktree-billing-prepaid-rewrite` at `.claude/worktrees/billing-prepaid-rewrite/`
**Base SHA:** `b8b3162` (origin/main, includes PR #54 logo refresh)
**Next migration phase:** `phase37`

**Patch log (v1 → v2 → v3):**
- **v2 patches** (from review v1): Group A (P0) A1-A10 + Group B (cuts) B1/B2/B3/B4/B6/B7/B8/B9/B10 + Group C (polish) C1-C10. B5 NOT applied (Decision 23 investor optics).
- **v3 patches** (from review v2): Group A2 (5 mandatory P0) + Group B2 (7 recommended P1):
  - **A2-1** Deleted broken §1 PRE-MIGRATION BACKFILL SQL (regression from v1's A2 patch — duplicate INSERT before CREATE TABLE)
  - **A2-2** Committed M11 to 10-min downtime window via direct `apply_migration` (dropped Supabase-branch language + phantom `BILLING_DOUBLE_WRITE` env var)
  - **A2-3** Clarified kill-switch: enforcement=off skips BOTH deduct AND ledger insert (no drift possible during soak; success metric = no Sentry billing errors)
  - **A2-4** Per-model `AEGIS_TURN_ESTIMATE_CENTS` (Haiku=50, Sonnet=200, Opus=800); fresh orgs default to Haiku until first top-up
  - **A2-5** Wired `assert_balance_matches_ledger()` to CI via `vitest.globalTeardown.ts`
  - **B2-1** Reverted C9 — dropped `billing_pending_payment_intents` table; use Stripe `metadata.purpose`
  - **B2-2** Converted M2.1 anti-test to CI-runnable mutation test
  - **B2-3** Expanded no-tier CI grep guard with 11 missing identifiers
  - **B2-4** Added webhook TOCTOU + cross-tenant PI mismatch tests
  - **B2-5** Added cross-column CHECK on event_type ↔ unit pairing in billing_transactions
  - **B2-6** Added `auto_recharge_in_progress` + `_started_at` pairing CHECK
  - **B2-7** Softened `credit_balance` no-billing-row case from RAISE to log+auto-create
- Group D (opportunity): deferred to v1.1 backlog

**Net effect (v1 → v3):** 14 milestones → **11**, ~80-110h → **~55-65h**, 4 tables → **3** (collapsed `billing_meter_events` into `billing_transactions`; dropped `billing_pending_payment_intents`), 9 frontend components → **4**, **direct apply_migration in 10-min downtime window** (Supabase-branch path removed), DB-enforced single-signup-grant invariant + concurrent-deduct race test with CI mutation anti-test + tenant-isolation suite + no-tier-grep CI guard + per-model AEGIS_TURN_ESTIMATE + ledger-invariant CI gate.

---

## Overview

Replace the 4-tier subscription model (Free / Pro / Team / Enterprise) with pure prepaid credit. Every org gets every feature. New users get $5 free credit, then pay 2x cost-of-goods on AI tokens + Fly worker minutes via prepaid balance. Optional auto-recharge. Optional billing email override. Alerts on low balance, zero balance, top-ups, auto-recharge events. **Single PR + 10-min planned downtime cutover via direct `apply_migration` to prod** — pre-launch, zero real customers, no Supabase branch needed.

The architectural spine is an **in-house Postgres ledger** with two main tables (collapsed from three per review patch B1): `organization_billing` (state + auto-recharge config) and `billing_transactions` (append-only event log carrying both transactions AND per-event metering metadata). Atomic `deduct_balance` RPC with `SELECT FOR UPDATE` race-safety. Stripe used only for PaymentIntents on top-up + auto-recharge; purpose discrimination via Stripe `metadata.purpose` (per B2-1, dropped the `billing_pending_payment_intents` denormalization).

A **`DEPTEX_BILLING_ENFORCEMENT=off`** kill-switch ships with the first deploy: per the clarified semantic (A2-3), `recordMeterEvent` console-logs and returns `{ deducted: false }` WITHOUT inserting any DB row. The 7-day soak metric is **no Sentry billing errors**, not ledger invariant — because no rows are written, no drift is possible. Flip to `on` after the clean soak.

---

## Competitive Research & Design Rationale

Full research lives in the feature brief. Top-level takeaways that shape the plan:

| Decision | Driven by |
|---|---|
| In-house ledger over Stripe Credit Grants | Credit Grants is preview API + requires $0/mo subscription wrapper + auto-recharge is non-native. ([Stripe docs](https://docs.stripe.com/billing/subscriptions/usage-based/billing-credits/implementation-guide)) |
| `meter_event` + `Customer Balance` not used in v1 | Stripe's pure-prepaid path (without subscription wrapper) is PaymentIntent-driven; we own the ledger. Meter Events API is GA but adds a second write surface for marginal value at our scale. ([Stripe Meter Events](https://docs.stripe.com/api/billing/meter-event)) |
| Auto-recharge defaults OFF | Matches OpenAI's default ("no surprise charges"). |
| $5 minimum top-up | Matches signup credit. ~11% Stripe-fee bite on small top-ups (effective markup 1.82x → 2x as top-up grows). |
| Pre-stream balance gate (C2) | Aegis Opus turn can burn $20; post-stream deduct alone risks mid-stream overdraft (`balance_cents CHECK >= 0` would abort, leaving orphan meter event). Pre-flight `can-charge` gate prevents the failure. |
| Kill-switch (C1) | Aegis is dogfooded daily; a deduction bug at cutover would brick chats. `DEPTEX_BILLING_ENFORCEMENT=off` lets the ledger soak for a week before enforcement flips on. |
| Single ledger table (B1, post-review) | `billing_meter_events` was redundant with `billing_transactions`; v1 deducts per-event inline anyway, so the rolled_up_* machinery served no consumer. |
| Itemized activity log without resolved labels (B3) | Server-side polymorphic-join for chat title/project name/fix-task target is v1.1 work. v1 shows feature + time + cost with click-through via `attribution_resource_type` + `attribution_resource_id`. |
| No spend chart in v1 (B3) | Pre-launch usage history will be empty for weeks. Big-number "Spend this period" + activity log proves billing correctness without recharts. |

---

## Codebase Analysis

### What gets DELETED whole-cloth

**Backend libs:**
- `backend/src/lib/plan-limits.ts` — `PLAN_LIMITS`, `PLAN_FEATURES`, `TIER_MAP`, `checkPlanLimit`, `checkPlanFeature`, `checkDowngradeAllowed`, `requirePlanLimit`, `requirePlanFeature`, `getOrgPlan`, `getUsageSummary`, `getFeatureAccess`, `invalidatePlanCache`, `TIER_DISPLAY_NAMES`. All gone.
- `backend/src/lib/stripe.ts` (`// @ts-nocheck` legacy) — full rewrite into typed `backend/src/lib/billing/stripe-billing.ts`.
- `backend/src/lib/ai/cost-cap.ts` — `checkMonthlyCostCap`, `recordActualCost` replaced by new `recordMeterEvent` lib. `checkSSEConcurrency` + `decrementSSECounter` moved to `backend/src/lib/ai/sse-concurrency.ts`.
- `backend/src/lib/ai/platform-cost-cap.ts` — kept (Deptex-own platform spend ceiling, not org-side). Optional rename for clarity.
- `backend/src/lib/taint-engine/cost-cap.ts` — callers migrated to `recordMeterEvent`.

**Backend route callsites (per architect-f8 — these `require()` lines die WITH the calls):**
- `backend/src/lib/extraction-jobs.ts:78` — `supabase.rpc('increment_sync_usage', ...)` callsite. Decision 13 (kill sync caps under prepaid) makes this semantically dead. **PATCH A1.**
- `backend/src/routes/projects.ts:1098` — `const { checkPlanLimit, TIER_DISPLAY_NAMES } = require('../lib/plan-limits');` + the call.
- `backend/src/routes/teams.ts:317` — same.
- `backend/src/routes/organizations.ts` — billing route group (`/:id/billing/plan`, `/:id/billing/usage`, `/:id/billing/checkout`, `/:id/billing/portal`, `/:id/billing/invoices`, `/:id/billing/check-downgrade`) + `checkPlanLimit` callsites in member add + notification-rule add. Also: the local `checkBillingPermission` function at `organizations.ts:7159` (gates on `role === 'admin'` — a non-existent role per `[[rbac_model]]`).
- `backend/src/routes/stripe-webhooks.ts` — replaced; actual current mount is `app.use('/api/stripe/webhooks', stripeWebhooksRouter)` at `index.ts:162` (architect-f2 corrected the plan typo).

**Backend env vars:** `STRIPE_PRO_MONTHLY_PRICE_ID`, `STRIPE_PRO_ANNUAL_PRICE_ID`, `STRIPE_TEAM_MONTHLY_PRICE_ID`, `STRIPE_TEAM_ANNUAL_PRICE_ID`.

**Frontend env vars:** the same four prefixed `VITE_*`.

**Frontend:**
- `frontend/src/contexts/PlanContext.tsx` — kept at original path per scope-cutter-f8 (cosmetic rename deferred to chore PR); file contents gutted and re-exported as `useBilling`. New BillingContext narrowed surface (no `usePlanGate`, `usePlanLimit`, `TIER_DISPLAY`, `FEATURE_REQUIRED_TIER`).
- `frontend/src/app/pages/PricingPage.tsx` — full rewrite (4-tier grid → single-card + calculator).
- `frontend/src/app/pages/OrganizationSettingsPage.tsx`:
  - `PlanBillingSectionContent` (~lines 5536-5837) — replaced with new single-file `PlanBillingSectionContent.tsx` (post-B9 collapse).
  - `UsageSectionContent` (~lines 5381-5529) — replaced with `UsageSectionContent.tsx` (activity log only post-B3; no chart).
  - `planTiers` const (lines 67-132) — deleted.
  - All `usePlanGate`/`usePlanLimit`/`TIER_DISPLAY` callsites — deleted.
- `frontend/src/lib/orgSettingsSections.tsx` — section IDs `'usage'` + `'plan'` stay valid.
- Tier-gating elsewhere: `CreateProjectSidebar.tsx` (`usePlanLimit('projects')` deleted), `SLAConfigurationSection.tsx` (tier-gate deleted), `AuditLogsSection.tsx` (tier-gate deleted).

**Stripe state (M11 cutover, NOT during dev):** the 4 existing Pro/Team monthly+annual products + their prices. Verify zero active subscriptions first.

### What gets MODIFIED in place

| File | Change |
|---|---|
| `backend/src/index.ts` | Mount `app.use('/api/organizations', billingRouter)` (NOT `/:id/billing` — architect-f1). Mount `app.use('/api/internal/billing', internalBillingRouter)` (the router calls `router.use(requireInternalKey)` per `internal.ts:10-22` — architect-f4). Mount `app.use('/api/stripe/webhooks', billingStripeWebhooksRouter)` (reuse existing path to keep Stripe Dashboard URL stable). Remove old `stripeWebhooksRouter` references. |
| `backend/src/lib/aegis-v3/agent.ts:178` | Replace `recordActualCost(...)` with ONE `recordMeterEvent({ ..., quantity: input_tokens, output_quantity: output_tokens, unit:'input_tokens', cost_cents_charged: 2*(input_cog+output_cog) })` per turn (single event, not split — B6). |
| `backend/src/routes/aegis-v3.ts` | (a) Other `recordActualCost` callsites → `recordMeterEvent`. (b) Pre-flight `can-charge` gate on stream-start (C2): `POST /api/internal/billing/can-charge { orgId, estimatedCents: MAX_AEGIS_TURN_ESTIMATE }`; reject 402 if `!allowed`. |
| `backend/src/lib/taint-engine/cost-cap.ts` callers | Migrate to `recordMeterEvent({ feature: 'taint-engine.<sub>' })`. |
| `frontend/src/contexts/PlanContext.tsx` | Gutted and replaced with `BillingContext` — narrower API surface (`useBilling()` only). File path kept per scope-cutter-f8. |
| `frontend/src/app/pages/OrganizationLayout.tsx:237` | `<PlanProvider>` → `<BillingProvider>` (architect-f14 corrected the v1 plan's wrong `main.tsx` reference). |

### What gets ADDED (net-new files)

**Backend:**
- `backend/database/phase37_billing_prepaid.sql` — the migration (full SQL below). Applied via Supabase branch at M11 cutover, not during dev (migration-safety-f2).
- `backend/src/lib/billing/types.ts` — TypeScript types.
- `backend/src/lib/billing/ledger.ts` — `recordMeterEvent`, `deductBalance` (calls RPC), `getBalance`, `listTransactions`, `listUsageActivity`. **Plus `canCharge(orgId, estimatedCents)` (C2) for pre-flight gates.**
- `backend/src/lib/billing/stripe-billing.ts` — Stripe client + helpers. **Stripe-issued payment-method lookup is lazy, NOT mirrored to Postgres** (B4 — eliminates sync bug class).
- `backend/src/lib/billing/auto-recharge.ts` — `maybeAutoRecharge`. **Includes stuck-flag recovery via `auto_recharge_in_progress_started_at` (test-strategy-f4): if flag is set but `_started_at > 30 minutes ago`, force-clear + alert.**
- `backend/src/lib/billing/alerts.ts` — `sendLowBalanceAlert`, `sendZeroBalanceAlert`, `sendCreditAddedEmail(orgId, amountCents, source)` (collapsed receipt template per scope-cutter-f10), `sendAutoRechargeFailed`. **Dispatch via QStash with idempotency-key = txn_id (C6).**
- `backend/src/lib/billing/pricing.ts` — Fly machine rates + 2x markup helper (`chargedCentsForWorker`).
- Extension to `backend/src/lib/ai/pricing.ts` — add `chargedCentsForAi(model, inputTokens, outputTokens) => { cogCents, chargedCents }`.
- `backend/src/lib/billing/enforcement.ts` (C1) — single export `isBillingEnforcementEnabled(): boolean` reading `process.env.DEPTEX_BILLING_ENFORCEMENT === 'on'`. When false, `recordMeterEvent` and `canCharge` log + insert ledger rows but skip the deduction/gate.
- `backend/src/routes/billing.ts` — the new org billing router.
- `backend/src/routes/internal-billing.ts` — internal endpoint for workers + Aegis pre-flight (local `requireInternalKey` per architect-f4).
- `backend/src/routes/billing-stripe-webhooks.ts` — new webhook handler (reuses `/api/stripe/webhooks` path; old handler deleted at M11).
- `backend/src/lib/billing/reconcile-script.ts` — manual reconciliation script (scope-cutter-f5; not a QStash cron in v1).
- **Tests (mandatory per review P0s):**
  - `backend/src/lib/billing/__tests__/ledger.test.ts`
  - `backend/src/lib/billing/__tests__/auto-recharge.test.ts`
  - `backend/src/lib/billing/__tests__/alerts.test.ts`
  - `backend/src/__tests__/billing-trigger.test.ts` (test-strategy-f3)
  - `backend/src/__tests__/billing-tenant-isolation.test.ts` (test-strategy-f8)
  - `backend/src/__tests__/no-plan-tier-references.test.ts` (test-strategy-f6 — CI grep guard)
  - `backend/src/__tests__/billing-reconcile.test.ts` (test-strategy-f13)
  - `backend/src/__tests__/e2e-billing-prepaid.ts` (full real-worker e2e — A5)
  - `backend/scripts/loadtest-deduct-balance.ts` (test-strategy-f11)

**depscanner worker:**
- `depscanner/src/lib/meter-event.ts` — POSTs `worker_minutes` event to `/api/internal/billing/meter-event`. Idempotency key: `depscanner:${scanJobId}:final` (migration-safety-f7 namespaced format).
- Hook into job-completion path (where `completed_at` + `duration_seconds` are set).

**fix-worker:**
- `fix-worker/src/lib/meter-event.ts` — same pattern. Key: `fix-worker:${taskId}:final`.

**Frontend:**
- `frontend/src/lib/stripe-client.ts` — `@stripe/stripe-js` loader.
- 4 components (post-B9 collapse from 9):
  - `frontend/src/components/billing/PlanBillingSectionContent.tsx` — balance + top-up + auto-recharge + spending-controls + payment-method in one file with `<section>` headings.
  - `frontend/src/components/billing/TransactionsTable.tsx` — paginated, cursor state.
  - `frontend/src/components/billing/UsageSectionContent.tsx` — "Spend this period" big number + activity log (no chart per B3).
  - `frontend/src/components/billing/PricingCalculator.tsx` — marketing page calculator.
- One frontend test file: `OrganizationSettingsPage.billing.test.tsx` covers balance/top-up/auto-recharge/transactions behaviors at the parent level (post-B9 component collapse).

### Patterns to follow

- **Migration shape:** `backend/database/phase13_billing.sql` — `IF NOT EXISTS`, `CREATE OR REPLACE FUNCTION`, RLS `Service role full access` policy, optional backfill at bottom.
- **Migration apply:** Use Supabase branch (`mcp__claude_ai_Supabase__create_branch`), apply migration there, run tests against the branch, merge at M11 cutover (migration-safety-f2).
- **Route shape:** `backend/src/routes/organizations.ts` — `Router()` → `authenticateUser` → `userHasOrgPermission(req.user.id, orgId, 'manage_billing')` from `backend/src/lib/permissions.ts` (architect-f3). Do NOT copy buggy `checkBillingPermission` admin-role check.
- **Internal route auth:** local `requireInternalKey` per `internal.ts:10-22` (architect-f4).
- **Webhook signature:** preserve `req.rawBody` + `constructWebhookEvent`. Lazy `require('../lib/billing/stripe-billing')` with try/catch 503 fallback per `stripe-webhooks.ts:20-25` (architect-f5).
- **Stripe lazy client:** `let stripeClient: Stripe | null = null; function getStripe() { ... }` pattern.
- **Email shape:** `sendEmail({ to, subject, html, text })` from `backend/src/lib/email.ts`. Templates mirror `sendInvitationEmail` HTML structure. Billing alerts bypass `destination-dispatchers.ts` / `user_notification_preferences` — they're transactional and not user-suppressible (architect-f9).
- **Frontend design tokens:** dark surfaces (`bg-background-card`), `border border-border`, `rounded-lg shadow-sm`. Buttons `variant="green"` for save/CTA. Per `.cursor/skills/frontend-design/SKILL.md`.

---

## Data Model

### `backend/database/phase37_billing_prepaid.sql`

```sql
-- Phase 37: Prepaid Billing Rewrite
-- Replaces the 4-tier subscription model with pure prepaid credit.
-- Applied at M11 cutover via Supabase branch (not during dev).
-- See: .cursor/plans/billing-prepaid-rewrite.plan.md
--
-- Patches applied (review v1):
--   A1: Explicit DROP FUNCTION before DROP TABLE
--   A2: Backfill stripe_customer_id before DROP organization_plans
--   A7: Trigger dedup + DB-enforced single-grant unique partial index
--   B1: Collapsed billing_meter_events INTO billing_transactions (single ledger table)
--   B2: Removed monthly-cap columns + current_month_usage_cents RPC + cap-alert columns
--   B4: Removed payment_method_brand/last4/expires_* (lazy Stripe fetch)
--   C5: Composite (organization_id, idempotency_key) UNIQUE; not full-table
--   C7: deduct_balance accepts NUMERIC(20,6) amount; rounds internally
--   C8: assert_balance_matches_ledger() function for reconciliation
--   B2-1: C9 billing_pending_payment_intents REVERTED — Stripe metadata.purpose is the source of truth
--   C10: COMMENT + CHECK on subscription_tier documenting Decision 23 contract

-- =============================================================================
-- 1. NEW TABLES
-- =============================================================================

-- 1:1 with organizations. Holds balance + auto-recharge config + spend controls.
CREATE TABLE IF NOT EXISTS organization_billing (
  organization_id            UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  balance_cents              BIGINT NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),

  -- Auto-recharge config
  auto_recharge_enabled              BOOLEAN     NOT NULL DEFAULT false,
  auto_recharge_threshold_cents      INTEGER,
  auto_recharge_amount_cents         INTEGER,
  auto_recharge_monthly_cap_cents    INTEGER,
  auto_recharge_in_progress          BOOLEAN     NOT NULL DEFAULT false,
  auto_recharge_in_progress_started_at TIMESTAMPTZ,   -- C7: stuck-flag recovery (force-clear after 30 min)
  auto_recharge_last_attempt_at      TIMESTAMPTZ,

  -- Spend controls (B2: monthly cap cluster REMOVED — no monthly_spending_cap_cents, no cap_alert_* columns)
  low_balance_alert_threshold_cents  INTEGER     NOT NULL DEFAULT 500,
  billing_email_override             TEXT,

  -- Stripe linkage (B4: card metadata NOT mirrored — fetched lazily from Stripe API)
  stripe_customer_id                 TEXT UNIQUE,
  stripe_default_payment_method_id   TEXT,

  -- Alert dedup (cleared on top-up via credit_balance RPC)
  low_balance_alert_sent_at          TIMESTAMPTZ,
  zero_balance_alert_sent_at         TIMESTAMPTZ,

  created_at                         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- B2-6: auto_recharge_in_progress + auto_recharge_in_progress_started_at must be set together.
  -- Prevents drift case where flag=false but started_at carries a stale timestamp (or vice versa)
  -- that would corrupt stuck-flag recovery logic in maybeAutoRecharge.
  CONSTRAINT chk_auto_recharge_in_progress_pairing CHECK (
    (auto_recharge_in_progress = false AND auto_recharge_in_progress_started_at IS NULL)
    OR
    (auto_recharge_in_progress = true  AND auto_recharge_in_progress_started_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_ob_stripe_customer       ON organization_billing(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ob_auto_recharge_enabled ON organization_billing(auto_recharge_enabled) WHERE auto_recharge_enabled = true;

-- B1 COLLAPSE: single ledger table carrying BOTH transaction + per-event metering metadata.
-- Replaces previous billing_transactions + billing_meter_events.
-- Append-only. Sum of signed amount_cents per org == organization_billing.balance_cents (invariant).
CREATE TABLE IF NOT EXISTS billing_transactions (
  id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind                       TEXT NOT NULL CHECK (kind IN (
    'signup_grant', 'topup', 'auto_recharge_topup', 'usage_deduction', 'refund', 'adjustment'
  )),
  amount_cents               BIGINT NOT NULL,                          -- signed: positive credit, negative deduction

  -- Per-metering-event metadata (only set for kind = 'usage_deduction')
  event_type                 TEXT CHECK (event_type IN ('ai_tokens', 'worker_minutes')),
  provider                   TEXT,                                     -- 'openai' | 'anthropic' | 'google' | 'deepinfra' | 'fly'
  feature                    TEXT,                                     -- 'aegis.chat' | 'depscanner.scan' | 'fix-worker.task' | …
  quantity                   NUMERIC(20, 6) CHECK (quantity IS NULL OR quantity > 0),
  output_quantity            NUMERIC(20, 6) CHECK (output_quantity IS NULL OR output_quantity > 0),  -- B6: for ai_tokens, output token count
  unit                       TEXT CHECK (unit IN ('input_tokens', 'output_tokens', 'seconds', 'mixed_tokens')),
  cost_cents_cog             NUMERIC(20, 6) CHECK (cost_cents_cog IS NULL OR cost_cents_cog >= 0),
  attribution_user_id        UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  attribution_resource_type  TEXT CHECK (attribution_resource_type IN ('aegis_chat', 'scan_job', 'fix_task', 'rule_generation', 'epd_scoring')),
  attribution_resource_id    UUID,
  model_id                   TEXT,
  machine_size               TEXT,
  idempotency_key            TEXT,                                     -- C5: composite UNIQUE below, not full-table

  -- Top-up / refund metadata
  description                TEXT NOT NULL,
  stripe_payment_intent_id   TEXT,
  created_by_user_id         UUID REFERENCES auth.users(id) ON DELETE SET NULL,

  created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- B2-5: cross-column CHECK pairing event_type with unit. Prevents 'worker_minutes' + unit='input_tokens' drift class.
  CONSTRAINT chk_event_type_unit_pairing CHECK (
    event_type IS NULL
    OR (event_type = 'ai_tokens'      AND unit IN ('input_tokens', 'output_tokens', 'mixed_tokens'))
    OR (event_type = 'worker_minutes' AND unit = 'seconds' AND output_quantity IS NULL)
  )
);

-- Per-org idempotency (C5; migration-safety-f7)
CREATE UNIQUE INDEX IF NOT EXISTS uq_billing_transactions_org_idemp
  ON billing_transactions(organization_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- DB-enforced single signup_grant per org (A7)
CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_transactions_one_signup_grant_per_org
  ON billing_transactions(organization_id)
  WHERE kind = 'signup_grant';

-- Stripe webhook dedup (data-model-f6: partial unique on credit-direction kinds prevents PI replay double-credit)
CREATE UNIQUE INDEX IF NOT EXISTS uq_billing_transactions_pi_credit
  ON billing_transactions(stripe_payment_intent_id)
  WHERE stripe_payment_intent_id IS NOT NULL AND kind IN ('topup', 'auto_recharge_topup');

CREATE INDEX IF NOT EXISTS idx_billing_transactions_org_created    ON billing_transactions(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_transactions_kind           ON billing_transactions(organization_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_transactions_attribution    ON billing_transactions(attribution_resource_type, attribution_resource_id) WHERE attribution_resource_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_billing_transactions_feature        ON billing_transactions(organization_id, feature, created_at DESC) WHERE feature IS NOT NULL;

-- Idempotency for Stripe webhook events (replaces stripe_webhook_events, dropped in §6).
CREATE TABLE IF NOT EXISTS billing_stripe_webhook_events (
  event_id       TEXT PRIMARY KEY,
  event_type     TEXT NOT NULL,
  processed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- B2-1: C9 billing_pending_payment_intents REVERTED.
-- PaymentIntent purpose persisted via Stripe metadata.purpose (set at PI creation; read in webhook).
-- Rationale: pre-launch Stripe metadata reliability + uq_billing_transactions_pi_credit partial unique
-- already prevents double-credit. The table added a lifecycle + unbounded-growth surface for zero benefit.

-- C10: Future-additive subscription_tier with documented contract (Decision 23 kept; B5 NOT applied)
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS subscription_tier TEXT;

COMMENT ON COLUMN organizations.subscription_tier IS
  'Decision 23 (phase37): NULL = pure prepaid (today''s only path). Future Pro/Enterprise SKUs will populate this. NEVER set a non-null DEFAULT in a backfill — that would silently reclassify existing prepaid orgs.';

ALTER TABLE organizations
  DROP CONSTRAINT IF EXISTS chk_organizations_subscription_tier;
ALTER TABLE organizations
  ADD CONSTRAINT chk_organizations_subscription_tier
    CHECK (subscription_tier IS NULL OR subscription_tier IN ('pro', 'enterprise'));

-- =============================================================================
-- 2. BACKFILL: preserve stripe_customer_id + seed signup_grant ledger entry
-- =============================================================================

-- A2: preserve stripe_customer_id from organization_plans before DROP
INSERT INTO organization_billing (organization_id, balance_cents, stripe_customer_id)
SELECT op.organization_id, 500, op.stripe_customer_id
FROM organization_plans op
ON CONFLICT (organization_id) DO UPDATE
  SET stripe_customer_id = COALESCE(organization_billing.stripe_customer_id, EXCLUDED.stripe_customer_id);

-- Seed organization_billing for any org without one (defensive; should be no-op after the join above)
INSERT INTO organization_billing (organization_id, balance_cents)
SELECT id, 500 FROM organizations
ON CONFLICT (organization_id) DO NOTHING;

-- Matching signup-grant ledger entry — partial unique index above makes this idempotent
INSERT INTO billing_transactions (organization_id, kind, amount_cents, description)
SELECT id, 'signup_grant', 500, 'Welcome credit ($5)' FROM organizations
ON CONFLICT DO NOTHING;

-- =============================================================================
-- 3. RPCs
-- =============================================================================

-- Atomic balance deduction. C7: takes NUMERIC(20,6) to preserve fractional cents precision.
-- Returns the new balance, or NULL if insufficient funds.
-- Pessimistic row lock via SELECT FOR UPDATE.
-- C1: caller checks DEPTEX_BILLING_ENFORCEMENT before calling this RPC.
CREATE OR REPLACE FUNCTION deduct_balance(
  p_organization_id  UUID,
  p_amount_cents     NUMERIC(20, 6),
  p_description      TEXT,
  p_event_metadata   JSONB                 -- {event_type, provider, feature, quantity, output_quantity, unit, cost_cents_cog, attribution_*, model_id, machine_size, idempotency_key}
) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE
  v_current_balance BIGINT;
  v_amount_rounded  BIGINT;
BEGIN
  v_amount_rounded := ROUND(p_amount_cents)::BIGINT;

  IF v_amount_rounded <= 0 THEN
    RAISE EXCEPTION 'deduct_balance: amount must round to positive int (got %)', p_amount_cents;
  END IF;

  SELECT balance_cents INTO v_current_balance
    FROM organization_billing
    WHERE organization_id = p_organization_id
    FOR UPDATE;

  IF v_current_balance IS NULL THEN
    RETURN NULL;
  END IF;

  IF v_current_balance < v_amount_rounded THEN
    RETURN NULL;
  END IF;

  UPDATE organization_billing
    SET balance_cents = balance_cents - v_amount_rounded,
        updated_at    = NOW()
    WHERE organization_id = p_organization_id;

  INSERT INTO billing_transactions (
    organization_id, kind, amount_cents, description,
    event_type, provider, feature, quantity, output_quantity, unit,
    cost_cents_cog, attribution_user_id, attribution_resource_type,
    attribution_resource_id, model_id, machine_size, idempotency_key
  ) VALUES (
    p_organization_id, 'usage_deduction', -v_amount_rounded, p_description,
    p_event_metadata->>'event_type',
    p_event_metadata->>'provider',
    p_event_metadata->>'feature',
    (p_event_metadata->>'quantity')::NUMERIC(20,6),
    (p_event_metadata->>'output_quantity')::NUMERIC(20,6),
    p_event_metadata->>'unit',
    (p_event_metadata->>'cost_cents_cog')::NUMERIC(20,6),
    (p_event_metadata->>'attribution_user_id')::UUID,
    p_event_metadata->>'attribution_resource_type',
    (p_event_metadata->>'attribution_resource_id')::UUID,
    p_event_metadata->>'model_id',
    p_event_metadata->>'machine_size',
    p_event_metadata->>'idempotency_key'
  );

  RETURN v_current_balance - v_amount_rounded;
END;
$$;

-- Atomic credit. Clears low/zero alert flags. Used by webhook + signup-grant trigger.
CREATE OR REPLACE FUNCTION credit_balance(
  p_organization_id          UUID,
  p_amount_cents             BIGINT,
  p_kind                     TEXT,
  p_description              TEXT,
  p_stripe_payment_intent_id TEXT,
  p_created_by_user_id       UUID
) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE
  v_new_balance BIGINT;
BEGIN
  IF p_amount_cents <= 0 THEN
    RAISE EXCEPTION 'credit_balance: amount must be positive';
  END IF;

  UPDATE organization_billing
    SET balance_cents              = balance_cents + p_amount_cents,
        low_balance_alert_sent_at  = NULL,
        zero_balance_alert_sent_at = NULL,
        updated_at                 = NOW()
    WHERE organization_id = p_organization_id
    RETURNING balance_cents INTO v_new_balance;

  IF v_new_balance IS NULL THEN
    -- B2-7: soften to log + auto-create (revert v2's over-correction per migration-safety-v2-f6).
    -- During the M11.3-M11.6 cutover window, a code-path racing the trigger creation could legitimately
    -- hit this branch. RAISE EXCEPTION would 500 user signups; log + auto-create degrades gracefully
    -- and surfaces the underlying bug via the RAISE NOTICE which routes to Postgres logs.
    RAISE NOTICE 'credit_balance: auto-creating missing organization_billing row for org % (likely trigger trg_organizations_after_insert_billing missed)', p_organization_id;
    INSERT INTO organization_billing (organization_id, balance_cents)
      VALUES (p_organization_id, p_amount_cents)
      RETURNING balance_cents INTO v_new_balance;
  END IF;

  INSERT INTO billing_transactions (
    organization_id, kind, amount_cents, description,
    stripe_payment_intent_id, created_by_user_id
  ) VALUES (
    p_organization_id, p_kind, p_amount_cents, p_description,
    p_stripe_payment_intent_id, p_created_by_user_id
  );

  RETURN v_new_balance;
END;
$$;

-- C8: reconciliation invariant check. Called from manual reconcile script (and any future cron).
-- Returns rows where sum-of-ledger != balance_cents. Empty result = healthy.
CREATE OR REPLACE FUNCTION assert_balance_matches_ledger()
RETURNS TABLE(organization_id UUID, balance_cents BIGINT, ledger_sum BIGINT, drift_cents BIGINT)
LANGUAGE sql STABLE AS $$
  SELECT ob.organization_id,
         ob.balance_cents,
         COALESCE(SUM(bt.amount_cents), 0)::BIGINT AS ledger_sum,
         (ob.balance_cents - COALESCE(SUM(bt.amount_cents), 0))::BIGINT AS drift_cents
    FROM organization_billing ob
    LEFT JOIN billing_transactions bt ON bt.organization_id = ob.organization_id
    GROUP BY ob.organization_id, ob.balance_cents
    HAVING ob.balance_cents != COALESCE(SUM(bt.amount_cents), 0);
$$;

-- =============================================================================
-- 4. TRIGGER: auto-create organization_billing + signup_grant on org INSERT
-- =============================================================================

-- A7: dedup guard via WHERE NOT EXISTS + partial unique index above (defense in depth)
CREATE OR REPLACE FUNCTION create_organization_billing_row()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO organization_billing (organization_id, balance_cents)
    VALUES (NEW.id, 500)
    ON CONFLICT (organization_id) DO NOTHING;

  INSERT INTO billing_transactions (organization_id, kind, amount_cents, description)
    SELECT NEW.id, 'signup_grant', 500, 'Welcome credit ($5)'
    WHERE NOT EXISTS (
      SELECT 1 FROM billing_transactions
      WHERE organization_id = NEW.id AND kind = 'signup_grant'
    );

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_organizations_after_insert_billing ON organizations;
CREATE TRIGGER trg_organizations_after_insert_billing
  AFTER INSERT ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION create_organization_billing_row();

-- =============================================================================
-- 5. DROP LEGACY TABLES + DEPENDENT FUNCTIONS
-- =============================================================================

-- A1: explicit DROP FUNCTION before DROP TABLE — visible in migration history
DROP FUNCTION IF EXISTS increment_sync_usage(UUID, INTEGER);
DROP FUNCTION IF EXISTS decrement_sync_usage(UUID);

-- Now drop tables. CASCADE is safe because dependent functions explicitly dropped above.
DROP TABLE IF EXISTS organization_plans CASCADE;
DROP TABLE IF EXISTS stripe_webhook_events CASCADE;

-- =============================================================================
-- 6. RLS
-- =============================================================================

ALTER TABLE organization_billing             ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_transactions             ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_stripe_webhook_events    ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on organization_billing"
  ON organization_billing FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access on billing_transactions"
  ON billing_transactions FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access on billing_stripe_webhook_events"
  ON billing_stripe_webhook_events FOR ALL USING (true) WITH CHECK (true);
```

### Schema notes

- **`balance_cents CHECK (balance_cents >= 0)`** — DB-level hard-cutoff invariant. Any code path that tries to overdraft aborts the transaction cleanly.
- **`uq_billing_transactions_org_idemp`** — per-org idempotency (C5). Cross-org collisions allowed; in-org are rejected.
- **`idx_billing_transactions_one_signup_grant_per_org`** — DB-enforced "$5 once per org" invariant (A7). Trigger replay can't double-grant.
- **`uq_billing_transactions_pi_credit`** — partial unique on PaymentIntent + credit-direction kinds. Webhook-secret rotation + Stripe replay won't double-credit.
- **`assert_balance_matches_ledger()`** — ledger invariant guard. Run from manual reconcile script + CI integration check.

### Stripe MCP cleanup (M11 cutover, NOT during dev)

```ts
// Run via Stripe MCP at M11 cutover, after the new code is live.
// 1. List products via mcp__claude_ai_Stripe__list_products. Capture old Pro/Team product IDs.
// 2. Verify zero active subscriptions: mcp__claude_ai_Stripe__list_subscriptions.
// 3. For each old product ID:
await mcp.stripe.stripe_api_execute({ method: 'DELETE', endpoint: `/v1/products/${productId}` });
```

---

## API Design

### New routes — `backend/src/routes/billing.ts`

All gated by `authenticateUser` + org membership check + `userHasOrgPermission(req.user.id, orgId, 'manage_billing')` (architect-f3). Mount: `app.use('/api/organizations', billingRouter)` (architect-f1 — bare prefix, `:id` is inside the router).

| Method | Route | Permission | Description |
|--------|-------|------------|-------------|
| GET    | `/:id/billing` | `manage_billing` OR `view_settings` | Full billing state. Card brand/last4/expires resolved lazily via Stripe API (B4); cached 60s in Redis if perf demands. |
| POST   | `/:id/billing/topup` | `manage_billing` | Creates Stripe PaymentIntent with `metadata: { organization_id, purpose: 'topup' }`. Returns `client_secret`. |
| PUT    | `/:id/billing/auto-recharge` | `manage_billing` | Updates `auto_recharge_enabled` + threshold/amount/monthly cap. Validates `amount_cents >= 500` if enabled. |
| PUT    | `/:id/billing/low-balance-threshold` | `manage_billing` | Updates `low_balance_alert_threshold_cents` |
| PUT    | `/:id/billing/billing-email` | `manage_billing` | Sets `billing_email_override` |
| DELETE | `/:id/billing/payment-method` | `manage_billing` | Detaches card; disables auto-recharge |
| GET    | `/:id/billing/transactions` | `manage_billing` OR `view_settings` | Paginated cursor-based. **Cursor derives org from URL param, not client-supplied (test-strategy-f8).** |
| GET    | `/:id/billing/usage` | `manage_billing` OR `view_settings` | Itemized activity log only (no time-series chart per B3). Cursor pagination. |

**Removed from v1 (per review patches):**
- `PUT /:id/billing/spending-cap` — B2 dropped monthly cap cluster
- `POST /:id/billing/setup-intent` — B8 dropped SetupIntent path
- `GET /:id/billing/plan` (legacy) — folded into `GET /:id/billing`
- `POST /:id/billing/checkout` (legacy) — replaced by topup endpoint
- `POST /:id/billing/portal` (legacy) — we own the UI
- `POST /:id/billing/check-downgrade` (legacy) — no tiers

### Webhook — `backend/src/routes/billing-stripe-webhooks.ts`

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST   | `/api/stripe/webhooks` | Stripe signature | Reuses existing path (no Stripe Dashboard URL change). Events: `payment_intent.succeeded`, `payment_intent.payment_failed`, `payment_method.detached`. |

**Removed event subscriptions (per scope-cutter-f6):**
- `charge.refunded` — no automated refund handling in v1; Henry issues `adjustment` manually if needed
- `charge.dispute.created` — Sentry-log only; no automated balance change
- `payment_method.attached` / `payment_method.updated` — B4 dropped Postgres mirroring of card metadata; Stripe is source of truth

### Internal — `backend/src/routes/internal-billing.ts`

Uses local `requireInternalKey` (architect-f4) per `internal.ts:10-22` pattern.

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST   | `/meter-event` | `INTERNAL_API_KEY` | Workers POST `worker_minutes` events |
| POST   | `/can-charge` | `INTERNAL_API_KEY` | **C2 pre-flight gate.** Body: `{ orgId, estimatedCents }`. Returns `{ allowed, balanceCents }`. When `DEPTEX_BILLING_ENFORCEMENT=off`, always returns `allowed:true` regardless of balance. |

### TypeScript types — `backend/src/lib/billing/types.ts`

```ts
export type MeterEventType = 'ai_tokens' | 'worker_minutes';
export type MeterProvider  = 'openai' | 'anthropic' | 'google' | 'deepinfra' | 'fly';
export type MeterUnit      = 'input_tokens' | 'output_tokens' | 'seconds' | 'mixed_tokens';
export type AttributionResourceType = 'aegis_chat' | 'scan_job' | 'fix_task' | 'rule_generation' | 'epd_scoring';

export type TransactionKind =
  | 'signup_grant' | 'topup' | 'auto_recharge_topup'
  | 'usage_deduction' | 'refund' | 'adjustment';

export interface RecordMeterEventInput {
  organizationId: string;
  eventType: MeterEventType;
  provider: MeterProvider;
  feature: string;
  quantity: number;          // input_tokens for ai_tokens; seconds for worker_minutes
  outputQuantity?: number;   // output_tokens (B6: single Aegis event carries both)
  unit: MeterUnit;
  modelId?: string;
  machineSize?: string;
  attribution?: {
    userId?: string;
    resourceType?: AttributionResourceType;
    resourceId?: string;
  };
  idempotencyKey: string;    // REQUIRED (was optional in v1; opportunity-scout-f8 + migration-safety-f7).
                             // Format: `<source>:<resource>:<phase>` (e.g. 'aegis:turn-uuid:tokens', 'depscanner:scan-uuid:final').
}

export interface BillingState {
  balanceCents: number;
  autoRecharge: {
    enabled: boolean;
    thresholdCents: number | null;
    amountCents: number | null;
    monthlyCapCents: number | null;
  };
  lowBalanceAlertThresholdCents: number;
  billingEmailOverride: string | null;
  paymentMethod: {           // lazy-fetched from Stripe (B4)
    brand: string;
    last4: string;
    expiresMonth: number;
    expiresYear: number;
  } | null;
  // B2: monthly_spending_cap_cents removed
}

export interface CanChargeResponse {
  allowed: boolean;
  balanceCents: number;
  reason?: 'insufficient_credit' | 'enforcement_off';
}

export interface TopUpResponse {
  clientSecret: string;
  paymentIntentId: string;
  amountCents: number;
}

export interface BillingTransaction {
  id: string;
  kind: TransactionKind;
  amountCents: number;
  description: string;
  createdAt: string;
  stripePaymentIntentId: string | null;
}

export interface UsageActivity {
  id: string;
  feature: string;
  eventType: MeterEventType;
  costCentsCharged: number;
  emittedAt: string;
  // B3: resolved labels DEFERRED to v1.1; v1 returns IDs only
  attribution: {
    userId: string | null;
    resourceType: AttributionResourceType | null;
    resourceId: string | null;
  };
  modelId: string | null;
  machineSize: string | null;
}

export interface UsageResponse {
  totalCents: number;        // "Spend this period" big number
  activity: UsageActivity[];
  nextCursor: string | null;
}
```

### Permission helper

Per architect-f3:
```ts
import { userHasOrgPermission } from '../lib/permissions';

const allowed = await userHasOrgPermission(req.user.id, orgId, 'manage_billing');
if (!allowed) return res.status(403).json({ error: 'Permission denied' });
```

Do NOT copy `checkBillingPermission` from `organizations.ts:7159` — it checks `role === 'admin'`, which is a non-existent role per `[[rbac_model]]`.

Per `[[feedback_no_raw_errors_to_users]]`: never return Stripe error messages directly. Catch + `console.error('[billing] topup', err)` → return generic `{ error: 'Top-up failed. Please try again.' }`.

---

## Frontend Design

### BillingContext — `frontend/src/contexts/PlanContext.tsx` (file path kept; contents gutted)

```tsx
interface BillingContextValue {
  billing: BillingState | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function BillingProvider({ organizationId, children }: ...) { ... }
export function useBilling() { ... }
```

Drops everything else (`isFeatureAllowed`, `getPlanGate`, `getPlanLimit`, `highestUsagePercent`, `TIER_DISPLAY`, `FEATURE_REQUIRED_TIER`, `PlanData`, `PlanTier`, `GatableFeature`, `LimitableResource`).

Wrap from `OrganizationLayout.tsx:237` (architect-f14 corrected).

### Pages & Routes

No new routes — `/organizations/:id/settings/usage` and `/.../settings/plan` keep their paths. Section IDs `'usage'` + `'plan'` stay valid. Content swaps.

Marketing `/pricing` route stays; content swaps.

### Plan & Billing — Component (post-B9 collapse)

```
PlanBillingSectionContent.tsx (single file with <section> headings)
├── <section: Balance>             // big $X.XX + last-updated
├── <section: Top up>              // chips $5/$10/$25/$50 + Custom + Stripe Elements card form
├── <section: Auto-recharge>       // toggle + threshold/amount/monthly cap
├── <section: Spending controls>   // low-balance threshold + billing email (B2: NO monthly cap input)
├── <section: Payment method>      // brand + last4 (lazy from Stripe API) + Remove
└── TransactionsTable.tsx          // separate file (paginated + cursor state)
```

### Usage — Component (post-B3 simplification)

```
UsageSectionContent.tsx (no chart per B3)
├── Big-number "Spend this period: $X.XX over last 30 days"
└── Activity log (infinite scroll)
    └── Each row: [icon] {feature} • {time ago} • ${cost}
                  Click → navigate via {resource_type}/{resource_id} (label resolution deferred to v1.1)
```

### Marketing — `PricingPage.tsx`

```
PricingPage
├── PageHero                     // "$5 free. Then pay as you go."
└── PricingCalculator            // sliders + computed monthly estimate
```

(FAQSection dropped per scope-cutter-f7.)

### Design specifications

Per `.cursor/skills/frontend-design/SKILL.md`. Card pattern, header, content patterns unchanged from v1.

Key UX rules:
- **Zero-balance state (B10 collapsed):** when `balanceCents === 0`, display a global banner with "Top up to continue" CTA. Don't pre-disable Aegis/scan send buttons — the backend returns 402 with `{ error: 'insufficient_credit' }` and a single global handler in `useBilling()` triggers the top-up modal. One handler, not three per-call-site.
- **Low-balance state:** balance card shows `<Badge variant="warning">Low</Badge>` when `balanceCents < lowBalanceAlertThresholdCents`.
- **Empty state on activity log:** "No usage yet. Try [Run a scan] / [Start an Aegis chat]" (opportunity-scout-f9 first-run wedge).
- **Top-up success polling:** after `stripe.confirmCardPayment` resolves, poll `GET /billing` every 1s up to 10s waiting for webhook to update balance.

---

## User Flows

(Unchanged from v1 except where noted.)

### Flow 1 — Org creation grants $5

```
1. POST /api/organizations → org row inserted
2. AFTER INSERT trigger fires create_organization_billing_row()
3. organization_billing row inserted (balance 500); signup_grant ledger row inserted (idempotent via WHERE NOT EXISTS + partial unique index)
4. Frontend toast: "Welcome — you have $5 of credit to explore."
```

### Flow 2 — Top up via Stripe

```
1. User clicks "Top up $25"
2. POST /billing/topup { amount_cents: 2500 }
3. Backend: ensureStripeCustomer + createPaymentIntent (off_session=false, setup_future_usage='off_session', metadata={ organization_id, purpose: 'topup' })  [B2-1: purpose lives in Stripe metadata]
4. Return client_secret
5. Stripe Elements confirm → on success, payment_intent.succeeded webhook fires
6. Webhook handler:
   a. dedup via billing_stripe_webhook_events.event_id PK
   b. validate pi.metadata.purpose IN ('topup', 'auto_recharge_topup') AND pi.metadata.organization_id present + matches pi.customer's org binding (cross-tenant guard per test-strategy-v2-f2)
   c. credit_balance(org, amount, kind=purpose, description, pi_id, NULL)  [uq_billing_transactions_pi_credit partial unique prevents double-credit on replay]
7. Frontend polls /billing for up to 10s; balance updates
8. QStash dispatch sendCreditAddedEmail(orgId, 2500, 'topup') with idempotency-key = txn_id (C6)
```

### Flow 3 — Aegis chat deducts (single event per turn, with pre-flight gate)

```
1. User sends Aegis message → POST /api/aegis/v3/stream
2. Backend pre-flight (C2 + A2-4): determine `estimatedCents` from selected model: `AEGIS_TURN_ESTIMATE_CENTS = { 'claude-haiku-*': 50, 'claude-sonnet-*': 200, 'claude-opus-*': 800, 'gemini-3-flash': 50, 'gemini-3.1-pro': 200, 'gpt-5-nano': 50, 'gpt-5.4': 200, 'gpt-5.5': 400, default: 200 }`. Fresh orgs with `subscription_tier IS NULL AND no successful topup` default to `claude-haiku-*` until first paid top-up. POST `/api/internal/billing/can-charge { orgId, estimatedCents }`
   - If !allowed AND DEPTEX_BILLING_ENFORCEMENT=on: return 402 with { error: 'insufficient_credit', balance_cents }
   - If DEPTEX_BILLING_ENFORCEMENT=off: allowed always true
3. streamText runs. On completion in onFinish:
   - Compute cogCents (input_cog + output_cog), chargedCents = 2 × cogCents
   - Build idempotencyKey = `aegis:${chatId}:${turnId}:tokens`
   - recordMeterEvent({ ..., quantity: input_tokens, outputQuantity: output_tokens, unit: 'mixed_tokens', cogCents, chargedCents, idempotencyKey, ... })
   - Inside ledger: if DEPTEX_BILLING_ENFORCEMENT=on, call deduct_balance RPC (atomic)
   - If deduct returns NULL (insufficient): turn already completed; user got one over-the-limit turn. Subsequent send returns 402.
4. Post-deduction: maybeAutoRecharge(orgId, newBalance) (fire-and-forget via QStash if AR enabled + below threshold)
5. Post-deduction: alert checks (low/zero balance — fire-and-forget via QStash with idempotency-key per C6)
```

(Note: pre-flight gate prevents the "$5 balance, $20 Opus turn" overdraft case from skeptic-f5. MAX_AEGIS_TURN_ESTIMATE is conservative — biggest plausible single turn at our default model.)

### Flow 4 — Worker minutes deduct from depscanner

```
1. scan_jobs row claimed by depscanner machine; started_at set
2. Job completes; completed_at + duration_seconds set
3. Worker POSTs /api/internal/billing/meter-event with:
   {
     event_type: 'worker_minutes', provider: 'fly', feature: 'depscanner.scan',
     quantity: duration_seconds, unit: 'seconds',
     machine_size: 'perf-2x', attribution: { resource_type: 'scan_job', resource_id: scanJobId },
     organization_id, idempotency_key: `depscanner:${scanJobId}:final`
   }
4. Backend: chargedCentsForWorker(machineSize, seconds) → { cogCents, chargedCents }
5. recordMeterEvent → if enforcement on, deduct_balance via RPC
6. If insufficient: scan results stay accessible; next scan blocked until top-up
```

### Flow 5 — Auto-recharge

```
1. Aegis deduction drops balance to $4.12 (< $5 threshold)
2. Post-deduction QStash job runs maybeAutoRecharge(orgId, balanceAfter)
3. Concurrency guard: SELECT FOR UPDATE; check auto_recharge_in_progress = false
4. Set in_progress=true + in_progress_started_at = NOW()
5. createPaymentIntent (off_session=true, customer=org's Stripe Customer, default PM, metadata={ organization_id, purpose: 'auto_recharge_topup' })  [B2-1]
6. Stripe processes → webhook → reads pi.metadata.purpose='auto_recharge_topup' → credit_balance (kind='auto_recharge_topup')
8. Webhook clears in_progress flag
9. QStash dispatch sendCreditAddedEmail(orgId, amount, 'auto_recharge')
10. Stuck-flag recovery: if next maybeAutoRecharge sees in_progress=true AND in_progress_started_at > 30 min ago, force-clear flag + dispatch sendAutoRechargeFailed alert
```

### Flow 6 — Zero balance

```
Same as v1. Hard cutoff on metered actions; non-metered pages keep working.
Global 402 handler in frontend opens top-up modal (B10 collapsed).
```

---

## Edge Cases & Failure-Mode Policy

(Same as v1; added rows per review findings.)

| Scenario | Behavior |
|---|---|
| Stripe webhook arrives twice (same event_id) | Idempotent via `billing_stripe_webhook_events.event_id` PK |
| Stripe webhook arrives twice (DIFFERENT event_id, same PaymentIntent) — e.g. after webhook secret rotation | `uq_billing_transactions_pi_credit` partial unique on (PI, kind) prevents double-credit (data-model-f6) |
| Webhook never arrives (Stripe outage) | Stripe retries 3 days. Manual reconciliation script (scope-cutter-f5) catches drift. |
| Two concurrent Aegis turns deduct simultaneously | `SELECT FOR UPDATE` in `deduct_balance` RPC serializes; tested with 2-pool race in M2.5 (A6) |
| Aegis turn completes but DB write fails | Provider already charged us; we eat the cost. Log to Sentry. Idempotency-key prevents retry double-bill. |
| AI provider returns 500 mid-stream | No meter event emitted (only emit on completed usage). User balance untouched. |
| Worker crashes mid-scan | Job ends without completion; manual reconcile script catches missing meter event. Idempotency-key prevents double-bill on resumption. |
| Card declined on auto-recharge | Auto-recharge disabled, email sent, no retry. User must re-enable. |
| Stuck `auto_recharge_in_progress=true` (3DS challenge, missing webhook) | Force-clear after 30 min via `in_progress_started_at` (test-strategy-f4); send sendAutoRechargeFailed alert |
| Refund request | ToS: no refunds. Support can issue manual `adjustment` transaction via internal endpoint. |
| Org deleted with non-zero balance | Balance forfeit per ToS. All rows cascade-delete via FK. |
| Stripe Test Mode vs Live Mode | Single `STRIPE_SECRET_KEY` env per environment; no mixing. |
| Stripe Tax / VAT | v1: pass through (markup absorbs VAT). v1.1: enable Stripe Tax. |
| Chargeback | Stripe sends `charge.dispute.created`. v1: Sentry-log only. v1.1: automated balance debit. |
| Currency | USD only. Multi-currency = v2+. |
| Aegis silent-loss (worker dies between LLM call and `recordMeterEvent`) | Acknowledged tradeoff per test-strategy-f13. No reconciliation surface in v1 (cost: write amplification we already worried about). Quantify in v1.1 telemetry. |
| Cold-boot machine time (Fly idle → first scan) | Platform-absorbed per Decision 14. Quantify in telemetry; raise worker markup in v1.1 if material. Acknowledged in unit-economics caveat. |

---

## Non-Functional Requirements

- **Deduction latency:** p99 < 50ms per `deduct_balance` RPC. **Validated by `backend/scripts/loadtest-deduct-balance.ts`** (test-strategy-f11; runs 50 conns × 10k calls, asserts p99 < 50ms). Gates merge.
- **Meter event throughput:** ~10/sec realistic; Stripe Meter API benchmarks 1000/sec — well below ceiling.
- **Webhook latency:** Stripe 5s timeout. Heavy work (alert dispatch, auto-recharge) pushed to QStash (C6).
- **Activity log query:** p95 < 500ms with 100k+ transactions per org. Seeded fixture in `backend/scripts/seed-billing-fixtures.ts`.
- **Top-up to balance-visible latency:** < 10s (Stripe webhook + Postgres + frontend poll).
- **Auto-recharge race-safety:** `auto_recharge_in_progress` row-lock + stuck-flag recovery.
- **Cost-of-goods table refresh:** AI provider pricing changes weekly to monthly; manual review at each addition. Documented in `backend/src/lib/ai/pricing.ts` + `backend/src/lib/billing/pricing.ts`.

---

## RBAC Requirements

- `manage_billing` permission (existing) gates Plan & Billing screen + Usage screen + all mutating routes.
- `view_settings` permission (existing) optionally allows view-only on Usage screen + transactions list.
- Owner role retains all permissions.
- Billing alert emails route to `billing_email_override` if set; else all org members with `manage_billing` (Decision 20).

---

## Implementation Tasks

11 milestones (down from 14). Complexity: **S** = <2h, **M** = 2-6h, **L** = 6-16h.

### M1. Backend types + ledger lib + RPCs

**1.1 phase37 migration draft** — M
- File: `backend/database/phase37_billing_prepaid.sql` (full SQL above)
- During development: apply via `mcp__claude_ai_Supabase__apply_migration` against the **local dev Supabase project** (NOT prod — prod cutover happens at M11.4 inside the maintenance window). Verify the migration applies cleanly to an empty schema BEFORE writing the M2-M10 code that depends on the tables.
- Run `cd depscanner && npm run schema:dump` against the local dev URL to refresh `backend/database/schema.sql`. CI's `schema-check.yml` will validate the committed schema.sql against the migration files.
- **Note (per A2-2):** Supabase branch path was removed in v3 patches. Prod cutover is direct `apply_migration` inside a 10-min maintenance window at M11 — no branch creation, no merge_branch drift surface.

**1.2 `backend/src/lib/billing/types.ts`** — S
- TS types from API Design section

**1.3 `backend/src/lib/billing/pricing.ts`** — M
- Fly machine rate table (`shared-cpu-1x`, `perf-2x`, `perf-4x`, etc.). Source: Fly pricing page (verify rates inline)
- `chargedCentsForWorker(machineSize: string, seconds: number) => { cogCents: number; chargedCents: number }` (2x markup)

**1.4 Extend `backend/src/lib/ai/pricing.ts`** — S
- Add `chargedCentsForAi(model, inputTokens, outputTokens) => { cogCents, chargedCents }`

**1.5 `backend/src/lib/billing/enforcement.ts`** — S (C1)
- Export `isBillingEnforcementEnabled()` reading `DEPTEX_BILLING_ENFORCEMENT`
- Tests: env var off → false; env var 'on' → true; missing → false

**1.6 `backend/src/lib/billing/ledger.ts`** — L
- `recordMeterEvent(input)` — builds `event_metadata` JSONB, calls `deduct_balance` RPC, returns `{ deducted, newBalance }`. **Enforcement-off semantic (A2-3):** when `DEPTEX_BILLING_ENFORCEMENT=off`, console-logs the would-be event via `console.info('[billing.enforcement_off]', { orgId, feature, cogCents, chargedCents })` and returns `{ deducted: false, newBalance: null }` **WITHOUT inserting any DB row**. This makes ledger drift structurally impossible during the 7-day soak; soak metric is Sentry billing errors, not ledger invariant.
- `canCharge(orgId, estimatedCents)` — returns `{ allowed, balanceCents, reason }`. Returns `allowed: true, reason: 'enforcement_off'` if `DEPTEX_BILLING_ENFORCEMENT !== 'on'`.
- `getBalance(orgId)` — reads `organization_billing`; lazy-fetches PaymentMethod from Stripe API
- `listTransactions(orgId, cursor?, limit=50)`
- `listUsageActivity(orgId, range, cursor?)` — v1: no resolved labels (B3 deferred)

**1.7 Unit tests for ledger.ts** — M
- `__tests__/ledger.test.ts`
- Tests: happy-path deduct; insufficient funds → null; **enforcement-off bypass writes NO ledger row AND returns `{ deducted: false }`** (A2-3); idempotency-key collision returns original event id; per-org idempotency collision rejected, cross-org allowed; rounding policy at 0.5-cent boundary (`deduct(0.5)` rounds via banker's rounding); `canCharge` returns `allowed:true reason:'enforcement_off'` when off, even with $0 balance

**Acceptance:** Migration applied to Supabase branch; types + lib exports clean; unit tests green.

### M2. Concurrent-race & invariant tests

**2.1 Concurrent deduct race test against real Postgres** — M (A6)
- File: `backend/src/__tests__/billing-concurrent-deduct.test.ts`
- Open 2 independent Supabase clients
- Add test-only wrapper RPC `deduct_balance_with_delay(p_org, p_amount_cents, p_desc, p_metadata, p_sleep_ms)` that calls `pg_sleep` after FOR UPDATE
- Fire both calls in parallel; assert exactly one succeeds when balance covers one, both succeed serially when balance covers both
- **CI-runnable mutation anti-test (B2-2):** new file `backend/src/__tests__/billing-foruupdate-mutation.test.ts`:
  - Creates a temporary RPC `deduct_balance_no_lock` in `beforeAll` — verbatim copy of `deduct_balance` minus the `FOR UPDATE` clause. Drops it in `afterAll`.
  - Runs the same 2-pool concurrent race against `deduct_balance_no_lock`; asserts that across N=20 trials at least one double-spend is observable (`expect(doubleSpends).toBeGreaterThan(0)`).
  - This proves CI catches FOR UPDATE regression: the canonical test (M2.1) proves "with-lock no race", the mutation test proves "without-lock race observable" — together they prove the lock is load-bearing.
- Skip on PGLite (`it.skipIf(process.env.PGLITE)`)

**2.2 Trigger test** — M (A7 / test-strategy-f3)
- File: `backend/src/__tests__/billing-trigger.test.ts`
- Tests: (1) happy-path insert → billing row + signup_grant; (2) transaction rolls back → no orphan; (3) insert same org twice (via raw SQL with conflict resolution) → exactly one signup_grant via partial unique index; (4) trigger error propagates and aborts insert

**2.3 Ledger invariant check + CI gate** — S (C8 + A2-5)
- File: `backend/src/__tests__/billing-invariant.test.ts` — insert random sequence of credits + debits; call `assert_balance_matches_ledger()` after each; expect empty result
- File: `backend/vitest.globalTeardown.ts` (NEW per A2-5) — after every test suite run, call `assert_balance_matches_ledger()` against the test DB; if it returns ANY rows, throw and fail CI. Wired in `vitest.config.ts` via `globalTeardown` option.
- File: `backend/scripts/reconcile-billing.ts` — supports `--assert` flag that exits non-zero if drift detected. Add CI step `npm run reconcile:billing -- --assert` in `.github/workflows/test.yml` so prod-shape ledger drift fails the build, not just the per-suite test DB.

**2.4 Loadtest harness** — M (test-strategy-f11)
- File: `backend/scripts/loadtest-deduct-balance.ts` + `backend/scripts/seed-billing-fixtures.ts`
- 50 connections × 10k deduct calls on one org; p50/p95/p99 reported; gate p99 < 50ms

**Acceptance:** All tests green; loadtest p99 < 50ms.

### M3. Stripe-billing lib + auto-recharge

**3.1 `backend/src/lib/billing/stripe-billing.ts`** — L
- Lazy `getStripe()`
- `ensureStripeCustomer(orgId)`
- `createPaymentIntent({ orgId, amountCents, purpose, offSession })` — sets `metadata: { organization_id: orgId, purpose }` on the Stripe PI (B2-1; no pending-row INSERT). Webhook reads purpose from `pi.metadata.purpose`.
- `detachPaymentMethod(orgId)` — clears stripe_default_payment_method_id + disables auto-recharge
- `getPaymentMethod(orgId)` — lazy lookup from Stripe API (B4); cache 60s in Redis
- `constructWebhookEvent(rawBody, signature)`
- `isEventProcessed(eventId)` / `markEventProcessed(eventId, eventType)`

**3.2 `backend/src/lib/billing/auto-recharge.ts`** — M
- `maybeAutoRecharge(orgId, balanceAfter)` — SELECT FOR UPDATE; check enabled + below threshold + monthly cap + in_progress; set in_progress + in_progress_started_at; createPaymentIntent off_session=true; webhook clears flag
- Stuck-flag recovery: at function entry, if in_progress=true AND started_at > 30 min ago, force-clear + sendAutoRechargeFailed alert

**3.3 Unit tests** — M (test-strategy-f4)
- `__tests__/auto-recharge.test.ts`
- Tests: enabled + below threshold → PI created; disabled → no PI; monthly cap exceeded → no PI; **2-client concurrent maybeAutoRecharge below threshold → exactly one PI fires** (mock paymentIntents.create assert count===1); stuck-flag-recovery test (set in_progress=true with old started_at; next call force-clears + sends alert)

**Acceptance:** Stripe lib + auto-recharge + tests green.

### M4. Alerts lib (QStash-dispatched)

**4.1 `backend/src/lib/billing/alerts.ts`** — M
- `resolveBillingRecipients(orgId)` — billing_email_override → [override]; else org members with manage_billing
- `sendLowBalanceAlert(orgId)` — dedup via `low_balance_alert_sent_at`
- `sendZeroBalanceAlert(orgId)` — dedup via `zero_balance_alert_sent_at`; content varies by `auto_recharge_enabled`
- `sendCreditAddedEmail(orgId, amountCents, source: 'topup' | 'auto_recharge_topup')` — single template (scope-cutter-f10)
- `sendAutoRechargeFailed(orgId, reason)`

**4.2 QStash dispatch wiring** — M (C6 — resolves the v1 plan contradiction)
- `recordMeterEvent` enqueues alert-check QStash job AFTER deduct succeeds, with idempotency-key = txn_id
- Dispatch handler does `SELECT FOR UPDATE org_billing` → read flag → if not set → send email via `sendEmail` → on success → set flag → COMMIT
- Dedup via QStash idempotency-key + row lock: double-fire blocked by both

**4.3 Unit tests** — S
- `__tests__/alerts.test.ts`: recipient resolution; dedup (email-succeed then flag set); dedup-on-email-failure (don't set flag); receipt collapse template renders for both sources

**Acceptance:** Alerts wired; emails verified in dev mailbox during M11 smoke.

### M5. Billing routes + webhook + internal route

**5.1 `backend/src/routes/billing.ts`** — L
- All 8 routes from API Design
- Permission check via `userHasOrgPermission` (architect-f3)
- Top-up: validate `amount_cents >= 500`; createPaymentIntent with `metadata: { organization_id, purpose: 'topup' }`; return client_secret (B2-1: no pending-row INSERT)
- Auto-recharge update: validate; require payment method (lazy Stripe fetch); persist; if user toggled ON with balance < threshold, fire `maybeAutoRecharge` immediately
- Cursor pagination derives org_id from URL param only (test-strategy-f8)
- All error responses generic per `[[feedback_no_raw_errors_to_users]]`

**5.2 `backend/src/routes/internal-billing.ts`** — M
- Local `requireInternalKey` per architect-f4
- `POST /meter-event` — body validated with zod (test-strategy-f9): quantity > 0, NaN/Infinity rejected, eventType↔unit pairing, quantity ceiling (1M tokens or 86400 seconds), unknown model_id rejected with clear error code
- `POST /can-charge` — returns `{ allowed, balanceCents, reason }` (C2)

**5.3 `backend/src/routes/billing-stripe-webhooks.ts`** — L
- Mount at `app.use('/api/stripe/webhooks', billingStripeWebhooksRouter)` — reuse existing path (no Stripe Dashboard URL change per architect-f2)
- Preserve CE-fallback try/catch 503 around `require('../lib/billing/stripe-billing')` per architect-f5
- Event handlers:
  - `payment_intent.succeeded` → read `pi.metadata.purpose` (validate IN ('topup','auto_recharge_topup'); reject if missing/unknown and Sentry-log); validate `pi.metadata.organization_id` matches `pi.customer`'s org binding (cross-tenant guard per test-strategy-v2-f2; reject + Sentry-log if mismatch); `credit_balance(org, amount, kind=metadata.purpose, ...)`. `uq_billing_transactions_pi_credit` partial unique prevents double-credit on replay.
  - `payment_intent.payment_failed` → if auto_recharge: disable + sendAutoRechargeFailed; mark pending resolved
  - `payment_method.detached` → clear stripe_default_payment_method_id + disable auto-recharge
- Webhook handler wraps `markEventProcessed` + credit work in SINGLE transaction (test-strategy-f7 — closes TOCTOU window)

**5.4 Wire routes in `backend/src/index.ts`** — S
- `app.use('/api/organizations', authenticateUser, billingRouter)` ← bare prefix per architect-f1
- `app.use('/api/internal/billing', internalBillingRouter)` ← router uses `requireInternalKey` internally
- `app.use('/api/stripe/webhooks', billingStripeWebhooksRouter)` ← reuse existing path (NOT a fresh path)
- Remove old route mounts AT M11 cutover (not yet — old code keeps running until cutover)

**5.5 Route tests** — M (test-strategy-f7 + f8 + f9)
- `__tests__/billing.test.ts`: each route happy/403/400; 500 generic-error contract
- `__tests__/billing-stripe-webhooks.test.ts` (B2-4 expanded coverage): each event type happy-path; **(1) duplicate event_id** in single-transaction (assert exactly one credit); **(2) TOCTOU concurrent webhook** — fire two `payment_intent.succeeded` handlers in `Promise.all` with same event_id; assert exactly one ledger row + one webhook_events row (proves the single-transaction wrap closes the TOCTOU window); **(3) missing pi.metadata.purpose** — Sentry-log + 400, no credit; **(4) unknown pi.metadata.purpose** value — same; **(5) cross-tenant PI/Customer mismatch** — pi.metadata.organization_id=orgA but pi.customer is bound to orgB → reject + Sentry-log + mark event processed; **(6) out-of-order** payment_method events; **(7) malformed PI payload** (missing amount, malformed customer field)
- `__tests__/internal-billing.test.ts`: INTERNAL_API_KEY gate; zod validation (negative quantity, NaN, eventType↔unit mismatch, ceiling); idempotency-key collision

**Acceptance:** Routes return correct shapes in dev curl tests; all route tests green.

### M6. Tenant isolation + no-tier-grep CI guards

**6.1 Tenant isolation test suite** — M (test-strategy-f8)
- File: `backend/src/__tests__/billing-tenant-isolation.test.ts`
- Tests: (1) user member of org A calls every billing route on org B → 403; (2) internal-billing receives POST with org-X body — must validate `attribution.resourceId` belongs to body's `organizationId` (if mismatch → reject); (3) cursor pagination ignores client-supplied org_id, derives from URL param; (4) `attribution.userId` validated as org member (if not, store NULL + Sentry)

**6.2 No-tier-references CI guard** — M (test-strategy-f6)
- Files: `backend/src/__tests__/no-plan-tier-references.test.ts` + `frontend/src/__tests__/no-plan-tier-references.test.ts`
- Greps post-rewrite tree for forbidden identifiers (expanded per B2-3):
  - **Tables / SQL:** `organization_plans`, `stripe_webhook_events`, `subscription_status`, `increment_sync_usage`, `decrement_sync_usage`
  - **Backend tier libs:** `PLAN_LIMITS`, `PLAN_FEATURES`, `TIER_MAP`, `TIER_DISPLAY_NAMES`, `checkPlanLimit`, `checkPlanFeature`, `checkDowngradeAllowed`, `requirePlanLimit`, `requirePlanFeature`, `getOrgPlan`, `getUsageSummary`, `getFeatureAccess`, `invalidatePlanCache`, `checkBillingPermission`
  - **AI cost-cap (replaced by recordMeterEvent):** `recordActualCost`, `checkMonthlyCostCap`
  - **Frontend tier hooks/consts:** `usePlanGate`, `usePlanLimit`, `planTiers`, `TIER_DISPLAY`, `FEATURE_REQUIRED_TIER`, `PlanData`, `PlanTier`, `GatableFeature`, `LimitableResource`
  - **Env vars:** `STRIPE_PRO_MONTHLY_PRICE_ID`, `STRIPE_PRO_ANNUAL_PRICE_ID`, `STRIPE_TEAM_MONTHLY_PRICE_ID`, `STRIPE_TEAM_ANNUAL_PRICE_ID`, `VITE_STRIPE_PRO_*`, `VITE_STRIPE_TEAM_*`
- Fails build if any match in `backend/src` or `frontend/src` (excluding the test files themselves + `.cursor/plans/` + `backend/database/` migration files + archive paths)

**Acceptance:** Both test suites green; CI gate enforced.

### M7. Aegis + taint-engine migration to ledger

**7.1 Update `backend/src/lib/aegis-v3/agent.ts:178`** — S (B6)
- Replace `recordActualCost` with ONE `recordMeterEvent({ ..., quantity: input_tokens, outputQuantity: output_tokens, unit:'mixed_tokens', chargedCents: 2*(input_cog+output_cog), idempotencyKey: `aegis:${chatId}:${turnId}:tokens`, attribution: { userId, resourceType:'aegis_chat', resourceId: chatId } })` per turn

**7.2 Pre-flight gate in `backend/src/routes/aegis-v3.ts`** — M (C2 + A2-4)
- On stream-start: derive `estimatedCents` from selected model via per-model table in `backend/src/lib/billing/aegis-estimate.ts`:
  ```ts
  export const AEGIS_TURN_ESTIMATE_CENTS: Record<string, number> = {
    // Haiku-family — cheap; default for fresh orgs
    'claude-haiku-4-5-20251001': 50,
    'gemini-3-flash': 50,
    'gpt-5-nano': 50,
    // Sonnet/mid-tier
    'claude-sonnet-4-6': 200,
    'gemini-3.1-pro': 200,
    'gpt-5.4': 200,
    // Premium
    'claude-opus-4-7': 800,
    'gpt-5.5': 400,
    'gpt-5.5-pro': 1500,
  };
  export const DEFAULT_AEGIS_ESTIMATE_CENTS = 200;
  ```
- Fresh-org rule: if `organization_billing.balance_cents = 500 AND no row in billing_transactions WHERE kind IN ('topup','auto_recharge_topup')`, force default model to `claude-haiku-4-5-20251001` regardless of org/user model preference. UI shows a "Try Haiku free; upgrade your top-up to unlock larger models" hint.
- `POST /api/internal/billing/can-charge { orgId, estimatedCents }` returns `{ allowed, balanceCents, reason }`.
- If !allowed → return 402 with `{ error: 'insufficient_credit', balanceCents }` before LLM call.
- **Rationale:** previous `MAX_AEGIS_TURN_ESTIMATE_CENTS=500` exactly equaled the $5 signup grant, blocking fresh users' first Aegis turn after any prior 1¢ scan deduction. Per-model estimates preserve wedge economics AND the gate's actual-overrun-prevention semantic.

**7.3 Migrate other recordActualCost callsites** — S
- Other Aegis callsites + `lib/taint-engine/cost-cap.ts` callers → `recordMeterEvent`
- `backend/src/__tests__/aegis-v3-stream.test.ts` — update mocks

**7.4 Move SSE concurrency cap** — S
- `backend/src/lib/ai/sse-concurrency.ts` ← `checkSSEConcurrency` + `decrementSSECounter` from old cost-cap.ts. Drop the cost-cap-specific exports.

**7.5 Delete legacy AI cost-cap** — S
- `backend/src/lib/ai/cost-cap.ts` deleted
- `backend/src/lib/taint-engine/cost-cap.ts` deleted (callsites migrated)
- `backend/src/lib/ai/platform-cost-cap.ts` KEPT (Deptex-side ceiling — not org billing)

**Acceptance:** No `recordActualCost` references left (CI guard from M6.2 catches). Aegis still streams. Meter events appear in `billing_transactions` for every turn.

### M8. Worker metering instrumentation + manual reconcile script

**8.1 `depscanner/src/lib/meter-event.ts`** — M
- `postWorkerMinutesEvent({ orgId, scanJobId, machineSize, seconds, feature })`
- Idempotency key: `depscanner:${scanJobId}:final` (migration-safety-f7 format)
- Retry on 5xx with backoff; treat 4xx as log+drop (test-strategy-f9 — broken request won't get unbroken)

**8.2 Hook into depscanner completion** — M
- After scan completes, call `postWorkerMinutesEvent` with `seconds = duration_seconds` (or computed from started_at/completed_at)
- Feature names per scan_jobs.type: `depscanner.scan`, `depscanner.dast`, `depscanner.malicious`, `depscanner.iac`

**8.3 Same for fix-worker** — M
- `fix-worker/src/lib/meter-event.ts` mirrors depscanner pattern
- Key format: `fix-worker:${taskId}:final`
- Feature: `fix-worker.task`

**8.4 Manual reconcile script** — M (scope-cutter-f5)
- File: `backend/scripts/reconcile-billing.ts`
- Two checks: (a) `assert_balance_matches_ledger()` — report any drift > $0.01; (b) scan_jobs LEFT JOIN billing_transactions on attribution_resource_id — for completed scans with no meter event, emit one with idempotency-key
- Runs via `npm run reconcile:billing` ad-hoc; NOT a QStash cron in v1
- v1.1 backlog item: wire to QStash after first real customer

**8.5 Reconcile script tests** — S (test-strategy-f13)
- `backend/src/__tests__/billing-reconcile.test.ts`: scan with no meter → script emits; scan with meter → script no-op (idempotency); ledger drift → script reports

**Acceptance:** Real depscanner scan locally → `worker_minutes` event in `billing_transactions` + balance deducted. Manual reconcile catches simulated drift.

### M9. Frontend — Plan & Billing + Usage screens

**9.1 Install `@stripe/stripe-js` + `@stripe/react-stripe-js`** — S
- `cd frontend && npm install @stripe/stripe-js @stripe/react-stripe-js`

**9.2 `frontend/src/lib/stripe-client.ts`** — S
- `export const stripePromise = loadStripe(import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY)`

**9.3 Gut `frontend/src/contexts/PlanContext.tsx`** — M (scope-cutter-f8)
- Same file path; gutted content; new `BillingContext` shape (BillingState + useBilling)

**9.4 `PlanBillingSectionContent.tsx`** — L (B9 collapse)
- Single file with `<section>` headings: Balance / Top up / Auto-recharge / Spending controls / Payment method
- Stripe Elements integration inline; PaymentElement + confirm flow
- On `paymentIntent.succeeded`, poll `/billing` every 1s up to 10s

**9.5 `TransactionsTable.tsx`** — M
- shadcn `<Table>`; cursor pagination

**9.6 `UsageSectionContent.tsx`** — M (B3 simplified)
- Big-number "Spend this period" + activity log
- NO recharts chart (B3 deferred to v1.1)
- Click row → navigate via `attribution_resource_type` + `attribution_resource_id` (raw ID navigation; label resolution v1.1)

**9.7 Replace sections in `OrganizationSettingsPage.tsx`** — M
- Drop `PlanBillingSectionContent` (lines 5536-5837) + `UsageSectionContent` (lines 5381-5529)
- Mount new components

**9.8 Frontend tests** — M (test-strategy-f15)
- `__tests__/OrganizationSettingsPage.billing.test.tsx`
- Tests: balance card empty/low/error states; top-up flow with mocked Stripe (confirmCardPayment resolved); polling timeout (mock slow webhook, assert polling stops at 10s); AutoRecharge validation (amount >= 500, payment-method-required gate); transaction pagination empty state

**Acceptance:** Plan & Billing + Usage screens render; top-up works in test mode.

### M10. Frontend — Zero-balance global handler + tier-gating deletion + PricingPage

**10.1 Global 402 handler** — M (B10 collapsed)
- In a fetch wrapper or top-level error boundary, intercept `402 { error: 'insufficient_credit' }` and open a top-up modal with a "Top up" button (deep-link to /settings/plan)
- No per-call-site disabled-state changes
- Backend gating per M5.1 is the actual enforcement

**10.2 Delete tier-gating callsites** — M
- `OrganizationSettingsPage.tsx`: delete `planTiers` const (lines 67-132) + all `usePlanGate` / `usePlanLimit` / `TIER_DISPLAY` callsites
- `CreateProjectSidebar.tsx`: delete `usePlanLimit('projects')` block
- `SLAConfigurationSection.tsx`: delete tier-gate
- `AuditLogsSection.tsx`: delete tier-gate
- Delete frontend env vars from `.env` + `.env.example`: `VITE_STRIPE_PRO_*`, `VITE_STRIPE_TEAM_*`

**10.3 `PricingPage.tsx` rewrite** — M
- Drop 4-tier grid
- Single-card hero "$5 free. Then pay as you go." + `<PricingCalculator>`
- No FAQSection (scope-cutter-f7 deferred)

**10.4 `PricingCalculator.tsx`** — M
- Three sliders (scans, Aegis chats, fixes per month)
- Placeholder rates documented inline ($0.10/scan, $0.40/chat, $1/fix)
- v1.1 backlog item: self-calibrating rates from real ledger telemetry (opportunity-scout-f4)

**Acceptance:** `/pricing` renders new design; no tier-gating elsewhere; calculator math correct.

### M11. Cutover (10-min downtime window + final cleanup)

> M11 is the **only** milestone that touches production state. **Cutover is a planned 10-minute downtime window** (Fly maintenance mode); pre-launch zero-user state makes this the simplest safe option. Direct `apply_migration` against prod, no Supabase branch.

**11.1 Pre-cutover Stripe audit** — S
- `mcp__claude_ai_Stripe__list_products` + `list_prices` + `list_subscriptions`
- Confirm zero active subscriptions; capture product IDs of `pro_*` + `team_*` for delete step
- Verify in Stripe Dashboard: no `pending` or `failed` webhook deliveries. If any pending, wait for them or manually re-fire before cutover.

**11.2 Final code review + push** — S
- `/criticalreview` if not already run
- Address P0+P1 inline
- Push branch + open PR (do NOT merge yet)

**11.3 Enable maintenance mode** — S
- `fly app maintenance-mode --on` on backend + worker apps (returns 503 to incoming requests)
- Vercel: optionally set maintenance page via env flag
- Wait ~30s for in-flight requests to drain

**11.4 Apply phase37 migration to PROD** — S
- `mcp__claude_ai_Supabase__apply_migration` directly against prod DB (NOT `merge_branch` — no Supabase branch in v3; direct apply avoids parallel-migration drift per migration-safety-v2-f3)
- Verify migration completed: SELECT exists check on `organization_billing`, `billing_transactions`, `billing_stripe_webhook_events`; verify trigger exists; verify `organization_plans` + `stripe_webhook_events` dropped; verify `increment_sync_usage` function dropped
- Re-dump schema via `cd depscanner && npm run schema:dump` (against prod URL); confirm diff is phase37-only (per `[[feedback_schema_dump_rebase]]`). If diff includes anything beyond phase37, BLOCK cutover and investigate — likely a parallel migration landed.
- Commit the refreshed `schema.sql` into the PR before merging.

**11.5 Merge PR → Vercel + Fly auto-deploy** — S
- Merge the PR; Vercel + Fly auto-deploy new code with `DEPTEX_BILLING_ENFORCEMENT=off` set
- Wait for deploys to complete (~2-3 min)
- New code now references the new tables, which exist; old code paths gone

**11.6 Drain maintenance mode + smoke test** — S
- `fly app maintenance-mode --off`
- Smoke test:
  - Create test org → verify `organization_billing` row + `signup_grant` ledger entry
  - Top up $5 with Stripe test card 4242 → verify balance updates within 10s
  - Send Aegis chat turn → verify NO `billing_transactions` deduction row appears (enforcement off — soft no-op per A2-3); Sentry shows no `[billing.error]` entries; `console.info` log of the would-be event present in Fly logs
  - Run scan → verify `worker_minutes` event in `billing_transactions`

**11.7 Delete legacy Stripe products** — S
- For each captured product ID from 11.1, call `mcp__claude_ai_Stripe__stripe_api_execute` DELETE
- Pre-delete: verify zero active subs (defensive)

**11.8 Delete legacy backend env vars** — S
- Remove `STRIPE_PRO_MONTHLY_PRICE_ID` + `STRIPE_PRO_ANNUAL_PRICE_ID` + `STRIPE_TEAM_MONTHLY_PRICE_ID` + `STRIPE_TEAM_ANNUAL_PRICE_ID` from Fly secrets + `.env`/`.env.example`
- Equivalent VITE_* env vars from Vercel + `frontend/.env`/`.env.example` were already deleted in M10.2

**11.9 7-day enforcement-off soak** — S
- `DEPTEX_BILLING_ENFORCEMENT` stays `off` for 7 days post-deploy
- Per kill-switch semantics (M1.6): `recordMeterEvent` logs to `console.info` + returns `{ deducted: false }` WITHOUT inserting any DB row. NO ledger drift possible because no rows are written.
- Soak metric: **no Sentry billing errors during the 7-day window**. If clean → flip enforcement on; if Sentry shows pricing-table bugs or mis-attribution, fix before flip.
- `fly secrets set DEPTEX_BILLING_ENFORCEMENT=on` to start real billing.

**Acceptance:** Maintenance window completes < 10 min; smoke tests pass; 7-day soak completes with zero Sentry billing errors; enforcement flipped to on.

### Total complexity estimate

Post-patches: **~55-70 hours** (down from 80-110h):
- M1: ~12h (smaller — single table, no rolled_up_* machinery)
- M2: ~6h (new mandatory race + trigger + invariant tests, loadtest)
- M3: ~10h
- M4: ~6h (collapsed receipt template; QStash dispatch wiring)
- M5: ~10h (fewer routes after B2/B8 cuts)
- M6: ~4h (CI guards; small new test surface)
- M7: ~5h (single Aegis event per turn — simpler than v1's input/output split)
- M8: ~6h (manual script instead of QStash cron)
- M9: ~10h (4 components instead of 9; no chart)
- M10: ~5h (global 402 handler; tier-gating deletes; PricingPage)
- M11: ~3h (cutover + soak)

---

## Testing & Validation Strategy

### Backend unit tests

| File | What's covered |
|---|---|
| `lib/billing/__tests__/ledger.test.ts` | recordMeterEvent happy/insufficient/enforcement-off/idempotency-collision/per-org-vs-cross-org/rounding |
| `lib/billing/__tests__/auto-recharge.test.ts` | Threshold trigger / monthly cap / in-progress flag / **2-client concurrent race** / **stuck-flag recovery** |
| `lib/billing/__tests__/alerts.test.ts` | Recipient resolution / dedup-set-only-on-send-success / collapsed receipt template |
| `__tests__/billing-concurrent-deduct.test.ts` | **Real-Postgres race** with `deduct_balance_with_delay` + 2 pools (A6) |
| `__tests__/billing-trigger.test.ts` | Happy / rollback / double-fire / error propagation (A7) |
| `__tests__/billing-invariant.test.ts` | Random credit+debit sequences; assert_balance_matches_ledger empty (C8) |
| `__tests__/billing-tenant-isolation.test.ts` | Cross-org access; internal-billing org/resource match; cursor org derivation; attribution user is org member |
| `__tests__/no-plan-tier-references.test.ts` | CI grep guard for forbidden identifiers |
| `__tests__/billing-reconcile.test.ts` | Reconcile catches missing meter events; idempotent on re-run |
| `routes/__tests__/billing.test.ts` | Each route happy/403/400/500 |
| `routes/__tests__/billing-stripe-webhooks.test.ts` | Each event; duplicate event_id; **TOCTOU concurrent (B2-4)**; missing/unknown metadata.purpose; **cross-tenant PI/Customer mismatch (B2-4)**; out-of-order; malformed payload |
| `routes/__tests__/internal-billing.test.ts` | INTERNAL_API_KEY gate; zod validation (negative/NaN/ceiling/eventType-unit mismatch); per-org idempotency collision |

### Frontend tests

| File | What's covered |
|---|---|
| `OrganizationSettingsPage.billing.test.tsx` | Balance card empty/low/error; top-up flow (mocked Stripe); polling timeout; AutoRecharge validation; TransactionsTable pagination empty |
| `__tests__/PricingPage.test.tsx` | Calculator math; CTA navigation |
| `__tests__/no-plan-tier-references.test.ts` (frontend) | Mirror of backend grep guard |

### E2E test (mandatory per `[[feedback_always_e2e]]`)

File: `backend/src/__tests__/e2e-billing-prepaid.ts`. Run via `npm run e2e:billing-prepaid`. Hits **real depscanner CLI** + **real Stripe test cards** (via `stripe listen --forward-to localhost:3001/api/stripe/webhooks`).

```
1. Create test org → assert balance_cents=500 + signup_grant row
2. POST /billing/topup amount=2500 with Stripe test card 4242 → confirm → assert balance=3000 within 10s
3. Send Aegis chat (3 turns) → assert 3 billing_transactions kind='usage_deduction' rows with feature='aegis.chat', balance drops accordingly
4. Run REAL depscanner scan (CLI in local mode against fixture repo, NOT mocked Fly) → on completion, assert `worker_minutes` row with `feature='depscanner.scan'` + `idempotency_key=depscanner:${scanJobId}:final` appears + matching deduction
5. Drain balance to $0 → next Aegis send returns 402 with `{ error: 'insufficient_credit' }`; scan history page still loads; settings still editable
6. Re-top-up $25 → balance restored; Aegis chat resumes
7. Enable auto-recharge ($5 threshold, $20 amount) → top up to $4.99 → run one Aegis turn → AR fires (mock Stripe paymentIntents.create OR use Stripe CLI to simulate) → balance back to ~$24 → receipt email
8. Cancel card via DELETE /billing/payment-method → next AR PI fails (use Stripe test card 4000 0000 0000 9995) → AR disabled, failure email
9. **Concurrent-deduct test:** spin up 10 simultaneous Aegis turns on $10 balance — assert exactly 10 successful deductions if balance covers all, no overdrafts via CHECK (balance >= 0)
10. **Webhook replay test:** send `payment_intent.succeeded` twice with same event_id — assert exactly one credit
11. **Ledger invariant test:** call `assert_balance_matches_ledger()` after each step — empty result throughout
12. **Tenant isolation:** member of org A calls /billing/topup on org B → 402
```

### Performance validation

| Target | Validation |
|---|---|
| `deduct_balance` p99 < 50ms | M2.4 loadtest: 50 conns × 10k calls; gates merge |
| `GET /billing/usage` p95 < 500ms with 100k events | M2.4 seed script + measured query |
| Top-up to balance-visible < 10s | E2E step 2 timing assertion |
| Webhook latency < 5s | Webhook handler enqueues to QStash for slow work |

### Regression validation

- **Aegis chat** still streams after `cost-cap.ts` deletion. Smoke: 10-turn chat.
- **Depscanner scan** completes correctly. Smoke: scan a small repo, check meter event.
- **Org creation** trigger fires. Smoke: create fresh org, check `organization_billing` + signup_grant.
- **Settings pages** load without PlanContext errors. Smoke: navigate every sidebar entry.
- **No-tier grep guard** green.
- **`extraction-jobs.ts`** still works without `increment_sync_usage` (callsite was deleted in M5/M7).

---

## Risks & Open Questions

### Known risks (updated post-patches)

| Risk | Mitigation |
|---|---|
| Worker meter-event POST fails silently → silent under-billing | Idempotency-key prevents double-bill on retry; manual reconcile script (M8.4) catches missing events |
| `deduct_balance` concurrency race | `SELECT FOR UPDATE` + `CHECK (balance_cents >= 0)`; tested in M2.1 with real-Postgres race + anti-test |
| Stripe webhook delay → stale balance | Frontend polls `/billing` 10s; manual refresh CTA if still stale |
| Auto-recharge double-fire | `auto_recharge_in_progress` row lock + stuck-flag recovery (M3.2); tested in M3.3 |
| Cutover code/migration interleave | Atomic via Supabase branch + DEPTEX_BILLING_ENFORCEMENT=off for 1 week (M11). Pre-launch downtime acceptable. |
| Aegis dogfood broken by deduction bug | DEPTEX_BILLING_ENFORCEMENT=off ships first; flip after 1 week soak |
| $5 free credit insufficient to evaluate | Acknowledged tradeoff; success criterion added: "fraction of signups that exhaust $5 before completing first Aegis investigation" tracked in v1.1 telemetry |
| Mid-stream Aegis turn overdraft | Pre-stream `can-charge` gate (C2) requires `balance >= MAX_AEGIS_TURN_ESTIMATE` before stream start |
| Worker cold-boot eats unbilled machine time | Acknowledged tradeoff; quantify in v1.1; consider raising worker markup if material |
| Chargeback on prepaid → AI cost already burned | v1 logs to Sentry; no fraud controls; v1.1: Stripe Radar rules + velocity limits + min-account-age before high-spend |
| Pricing tables drift from provider reality | Manual review at each model addition |
| Email send failure leaves alert dedup flag set | sendLowBalanceAlert sets flag ONLY after email succeeds; QStash retry handles transient |
| Ledger drift from non-RPC writes | `assert_balance_matches_ledger()` in M8.4 reconcile script; CI integration test |
| Per-turn write amplification (Aegis tool-call chains) | B6 single-event-per-turn halves write volume; loadtest M2.4 validates p99 |

### Open questions

(All non-blocking for `/implement`.)

1. **AI pricing refresh cadence.** Manual + monitored. Document table location.
2. **Stripe Tax for EU** — v1.1.
3. **Multi-currency** — v2+.
4. **Adjustment audit UI** — internal endpoint is enough for v1; UI when first refund/comp situation arises.
5. **PricingPage "Start free" target** — `/auth/sign-up` (existing). Confirm in M10.
6. **Marketing calculator rates** — placeholder ($0.10/$0.40/$1.00); revise once telemetry available. Self-calibrating rates is opportunity-scout-f4 v1.1.
7. **Aegis silent-loss reconciliation** — non-goal v1. Accepted tradeoff. Quantify in telemetry v1.1.

---

## Dependencies

**Already in place:**
- `backend/src/lib/email.ts` — `sendEmail` via nodemailer/Gmail
- `backend/src/lib/ai/pricing.ts` — extend with `chargedCentsForAi`
- `scan_jobs.organization_id`, `started_at`, `completed_at`, `duration_seconds` — worker-minute attribution columns exist
- `INTERNAL_API_KEY` env var
- `QSTASH_TOKEN` for alert dispatch + auto-recharge fire-and-forget
- Stripe MCP, Supabase MCP
- `frontend/src/components/ui/*` (shadcn): Button, Input, Switch, Table, Toast

**To add:**
- `STRIPE_PUBLISHABLE_KEY` (frontend) — verify exists, else add
- npm deps: `@stripe/stripe-js`, `@stripe/react-stripe-js` (frontend)
- env: `DEPTEX_BILLING_ENFORCEMENT` on backend + workers (C1)

---

## Success Criteria

The e2e harness in M13 (now M2.4 + M11.7 smoke) must pass against real services. Plus:

1. **No-tier grep CI guard green** (no callsites of forbidden identifiers).
2. **`assert_balance_matches_ledger()` returns empty** at the end of every test suite + every reconcile run.
3. **`deduct_balance` p99 < 50ms** per loadtest (M2.4).
4. **PricingPage renders new single-card design**; calculator math matches placeholder rates.
5. **`DEPTEX_BILLING_ENFORCEMENT=off`** for first week post-deploy; flip after clean soak.
6. **No `recordActualCost` references** in the codebase.
7. **`manage_billing` permission gates** both Plan & Billing and Usage screens.
8. **e2e harness exits 0** locally and in CI.

---

## Cross-references

- [[billing_prepaid_rewrite_direction]] — locked product direction
- [[org_settings_hardening]] — predecessor arc
- [[feedback_always_e2e]] — drives M2.4 loadtest + M11.7 e2e shape
- [[feedback_two_phase_migration_pattern]] — drives M11 atomic cutover via Supabase branch
- [[feedback_brief_grep_verify]] — drives M6.2 CI grep guard
- [[feedback_postgrest_partial_unique_inference]] — partial unique INDEX (not constraint) for signup_grant + PI uniqueness
- [[feedback_no_raw_errors_to_users]] — error-handling contract
- [[rbac_model]] — drives userHasOrgPermission usage in M5.1 (no admin-role gate)
- [[feedback_apply_migrations_via_mcp]] — Supabase branch via MCP, not psql
- [[feedback_schema_dump_rebase]] — re-dump schema.sql at every rebase
- Feature brief: `.cursor/plans/feature-brief-billing-prepaid-rewrite.md`
- Review report: `.cursor/plans/review-billing-prepaid-rewrite.md`
