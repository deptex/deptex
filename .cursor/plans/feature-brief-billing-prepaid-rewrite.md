# Billing Prepaid Rewrite — Feature Brief

**Status:** Pre-implementation. Output of `/brainstorm` on 2026-05-22.
**Predecessor arc:** [[org_settings_hardening]] (merged via PR #53).
**Worktree:** `worktree-billing-prepaid-rewrite` at `.claude/worktrees/billing-prepaid-rewrite/`.
**Base SHA:** `b8b3162` (origin/main, includes PR #54 logo refresh).

## Problem Statement

Deptex's current billing model (Free / Pro / Team / Enterprise) creates friction in three dimensions:

1. **User-facing friction:** Tiers force a "talk to sales" feeling on SSO/MFA/IP-allowlist + audit logs (anything `requiredTier === 'team'`). For a pre-launch product where the goal is "I want users, not money," that's the wrong wedge in a category where Snyk needs a sales call and Endor is enterprise-only.
2. **Engineering friction:** `usePlanGate`/`TIER_DISPLAY`/`planTiers` plus scattered `plan.tier === '*'` checks live in ~30 frontend callsites and 4 backend route surfaces. Every new feature requires a tier-gating decision.
3. **Margin friction:** The tier model bundles AI cost into a flat fee. A power Aegis user costs us many multiples of what they pay; a light user subsidizes them. The economics break under load.

Replace it with **pure prepaid credit**: type your email → $5 free → use every feature → top up when you want more. Markup is 2x cost-of-goods on AI tokens + worker minutes. No subscription. No seat fees. No feature tiers.

## Current State in Deptex

Mapped via Explore agent against `main` at `b8b3162`. Tier-gating is wired into 4 surfaces:

**Backend**
- `backend/database/phase13_billing.sql` — `organization_plans` table (1:1 with org): `plan_tier`, `subscription_status`, `stripe_customer_id`, `stripe_subscription_id`, `stripe_price_id`, `billing_cycle`, `current_period_*`, `syncs_used`, `custom_limits`. Plus `stripe_webhook_events` idempotency table.
- `backend/src/lib/plan-limits.ts` — owns `TIER_MAP` (free→enterprise = 0→3), `PLAN_LIMITS[tier]` (resource caps: projects, members, syncs, teams, notification_rules, integrations, automations, api_rpm), `PLAN_FEATURES[tier]` (feature gates: aegis_chat, ai_fixes, background_monitoring, sync_frequency, sso, mfa_enforcement, ip_allowlist, legal_docs, aegis_management, audit_logs, custom_sla, security_slas). 1-minute in-memory cache. Public surface: `getOrgPlan`, `getUsageSummary`, `checkPlanLimit`, `checkPlanFeature`, `checkDowngradeAllowed`, `requirePlanLimit`, `requirePlanFeature`.
- `backend/src/lib/stripe.ts` — `createCheckoutSession`, `createPortalSession`, `getInvoices`, 5 webhook handlers (`handleCheckoutCompleted`, `handleSubscriptionUpdated`, `handleSubscriptionDeleted`, `handlePaymentSucceeded`, `handlePaymentFailed`), `tierFromPriceId`, `getPriceIds` (reads `STRIPE_PRO_MONTHLY_PRICE_ID` etc.), `isEventProcessed`/`markEventProcessed` idempotency, `resetDueSyncCounters` cron.
- `backend/src/routes/organizations.ts` — billing routes: `GET /:id/billing/plan`, `GET /:id/billing/usage`, `POST /:id/billing/checkout`, `POST /:id/billing/portal`, `GET /:id/billing/invoices`, `POST /:id/billing/check-downgrade`. All gated on `manage_billing` permission.
- `backend/src/routes/stripe-webhooks.ts` — `POST /` for the 5 events above. Raw-body signature verification.
- `backend/src/lib/ai/cost-cap.ts` — Redis-backed monthly AI cost meter at `ai:cost:{orgId}:YYYY:M`. `checkMonthlyCostCap`, `recordActualCost`, `checkSSEConcurrency` (cap 5).
- `backend/src/lib/ai/platform-cost-cap.ts` — platform-wide AI budget gate (Gemini tier-1 features), keyed `ai:platform:cost:YYYY-MM` + `ai:platform:feature:{feature}:YYYY-MM-DD`.
- `checkPlanLimit` callsites: `POST /organizations` (members), `POST /organizations/:id/notification-rules` (rules), `POST /projects`, `POST /teams`.

**Frontend**
- `frontend/src/contexts/PlanContext.tsx` — exports `PlanProvider`, `usePlan`, `usePlanGate`, `usePlanLimit`, `TIER_DISPLAY`, `FEATURE_REQUIRED_TIER`.
- `frontend/src/app/pages/OrganizationSettingsPage.tsx` — 30 tier-gating references. `PlanBillingSectionContent` (~lines 5536–5837) holds the tier selector + Stripe Checkout + portal + invoices. `UsageSectionContent` (~lines 5381–5529) shows usage vs limits.
- `frontend/src/lib/orgSettingsSections.tsx` — `usage` + `plan` in `VALID_SETTINGS_SECTIONS`, gated on `manage_billing`.
- Tier-gating callsites outside settings: `CreateProjectSidebar.tsx` (`usePlanLimit('projects')`), `SLAConfigurationSection.tsx`, `AuditLogsSection.tsx`.
- `frontend/src/app/pages/PricingPage.tsx` — marketing page with hard-coded 4-tier cards using `VITE_STRIPE_PRO_MONTHLY_PRICE_ID` etc.

**Env vars in scope for removal:** `STRIPE_PRO_MONTHLY_PRICE_ID`, `STRIPE_PRO_ANNUAL_PRICE_ID`, `STRIPE_TEAM_MONTHLY_PRICE_ID`, `STRIPE_TEAM_ANNUAL_PRICE_ID` (plus `VITE_*` mirrors).

**Significant gap:** Worker compute minutes are NOT tracked anywhere today. `depscanner` and `fix-worker` Fly machines run with no per-org minute attribution. Building this is net-new instrumentation.

**Significant existing primitive that's reusable:** The Redis cost-cap meter already tracks per-org per-month AI spend, including per-model token pricing logic in `backend/src/lib/ai/pricing.ts`. The pricing tables move to the new ledger; the Redis layer goes.

## Competitive Landscape

### OpenAI API ([prepaid billing docs](https://help.openai.com/en/articles/8264644-what-is-prepaid-billing), inaccessible via WebFetch — search-result derived)

- Prepaid credit model with user-configurable auto-recharge.
- Min auto-recharge amount: **$5**. Max bounded by Trust Tier.
- Configurable: threshold (balance below which auto-recharge fires), recharge amount, optional monthly recharge limit.
- Switched from post-pay to pre-pay in 2024. No refund of unused balance under standard policy.

### Replicate ([pricing](https://replicate.com/pricing), [billing docs](https://replicate.com/docs/billing))

- Supports BOTH prepaid credit AND card-on-file pay-in-arrears.
- Time-based metering for most models; token/image/per-second for others.
- Sample rates: Claude 3.7 Sonnet $3/M input tokens, FLUX $0.04/output image, video models $0.09/sec of output.
- **No documented auto-recharge, no spending caps, no usage alerts.** Replicate is a cautionary tale — prepaid without spending controls leaves users exposed to runaway bills.

### Cursor ([pricing](https://www.cursor.com/pricing))

- Hobby (free, no card), Individual $20/mo, Teams $40/seat/mo, Enterprise custom.
- Included usage + on-demand overage billed in arrears.
- **No spending caps or budget alerts documented.** Subscription-first model — not what Deptex is targeting.

### Vercel Pro ([Pro plan docs](https://vercel.com/docs/accounts/plans/pro))

- $20/mo platform fee includes $20/mo usage credit + 1 deploying seat.
- Credit expires end of month, resets at start of next month.
- 75% notification, daily/weekly summary emails after exceeding monthly credit.
- Default $200/billing-cycle spend-management threshold for new customers (configurable via spend-management settings).
- Subscription + included credit + on-demand model — the alternative pattern Deptex is rejecting.

### Supabase ([billing FAQ](https://supabase.com/docs/guides/platform/billing-faq))

- Pro plan: spend cap default-on, users can disable for overage.
- Hourly compute billing.
- Prepaid credit balance supported ("top up your credit balance to cover multiple months").
- Notifications when exceeding Pro quota, thresholds not specified.

### Stripe primitives circa 2026

- **Stripe Meter Events API ([docs](https://docs.stripe.com/api/billing/meter-event))**: GA. 1,000 events/sec live mode (v1), 10,000 events/sec via streams (v2). Unique idempotency key per event, 24h enforcement window. Timestamps must be within past 35 calendar days or +5 min future. Async aggregation — `meter_event_summary` lags `meter_event`.
- **Stripe Credit Grants ([implementation guide](https://docs.stripe.com/billing/subscriptions/usage-based/billing-credits/implementation-guide), [API reference](https://docs.stripe.com/api/billing/credit-grant))**: ⚠️ **Preview API**. Constraint: Credit Grants ONLY apply to subscription line items linked to meter prices — pure-prepaid customers would need a $0/mo subscription wrapper. `category=paid` for purchased, `category=promotional` for grants. Manual top-up via PaymentIntent → listen for `invoice.paid` → call `POST /v1/billing/credit_grants`. **Auto-recharge is NOT native — Stripe doesn't trigger top-ups on low balance.** Built on top.
- **Snyk / Endor / Socket (the competitive set):** Snyk requires sales contact for SBOM / SSO. Endor Labs is enterprise-only with no self-serve. Socket has feature-capped free tier + paid tiers. **No category competitor offers "type email → $5 free → real Aegis + SSO + reachability."**

## Landscape Synthesis

**Table-stakes (2026):** Prepaid balance with per-event deduction. Spend cap toggle. Threshold-driven notifications. Auto-applied free credit on signup ($5 = standard).

**Frontier (1-2 vendors):** Auto-recharge with configurable threshold + amount + monthly ceiling — OpenAI is the canonical reference. Per-feature daily caps — only OpenAI ChatGPT Business has them.

**Whitespace in the security category:** Self-serve onboarding with full feature access. Snyk gates SSO behind sales, Endor is enterprise-only, Socket caps features. Deptex prepaid wedge: type email → $5 credit → run SSO + Aegis + reachability the same afternoon. THIS is the differentiation the rewrite buys.

**Feasibility verdict:** Tractable, ~2 weeks of engineering. Top risks:
1. **Worker-minute instrumentation is net-new** — `depscanner` and `fix-worker` don't emit machine-minute events today.
2. **Stripe Credit Grants is preview API** — not safe to depend on for v1 ledger. In-house Postgres ledger is the chosen path.
3. **Deduction concurrency** — two Aegis turns finishing simultaneously must not double-deduct or race the balance check. Pessimistic row-lock or optimistic-with-retry pattern needed.

## User Stories

- **As a new dev evaluating Deptex,** I want to sign up, get $5 of free credit, and run Aegis + a real scan within 10 minutes — without entering a card.
- **As a paid Deptex user,** I want to load $20 of credit and have it deducted as I use AI + scans, with full visibility into who consumed what.
- **As a growing team,** I want auto-recharge so my service doesn't break mid-Aegis-session because credit hit zero.
- **As a finance-conscious org owner,** I want to set an optional monthly cap and route billing alerts to a dedicated billing@company.com inbox.
- **As any user,** I want to see exactly which Aegis chats, scans, or fixes cost me $ and who triggered them.

## Locked Scope Decisions

Numbered in the order they were locked during interview. Each carries the rationale.

1. **In-house Postgres ledger for v1** — `organization_billing` (state) + `billing_transactions` (append-only ledger) + `billing_meter_events` (raw stream). **Reason:** Stripe Credit Grants is preview API + requires subscription wrapper + doesn't natively support auto-recharge. In-house ledger gives full control and zero preview-API exposure. Re-evaluate Stripe-native at Series-A scale.
2. **Marketing PricingPage + backend rewrite ship in the SAME PR.** **Reason:** Pre-launch, atomic flip is safe. Prevents marketing-vs-app contradiction window.
3. **Hard-delete the 4 existing Stripe products (Pro/Team monthly+annual)** via Stripe MCP during the rewrite PR. **Reason:** Henry overrode the archive recommendation — wants a clean Stripe-state slate. Verify zero active subscriptions before delete.
4. **$5 free signup credit, granted on org creation only.** Not refreshed. Not per-member. **Reason:** Cleanest accounting, prevents delete-and-recreate-org abuse. Matches OpenAI pattern.
5. **Credit never expires.** **Reason:** Once you load money, it sits forever. Removes "where did my credit go" support load. OpenAI does this.
6. **No refunds on unused balance.** Documented in checkout flow + ToS. **Reason:** Match OpenAI / Replicate / industry standard. Lowest ops overhead.
7. **Minimum top-up = $5.** **Reason:** Matches signup credit amount; lowest friction for trial users. **Caveat:** Stripe fees eat ~11% of a $5 top-up ($0.30 + 2.9% = $0.45 fee), reducing effective markup from 2x to ~1.82x on the smallest top-up. Henry accepted this; the "I want users" goal trumps the margin loss on the smallest tier.
8. **Auto-recharge defaults OFF** for new orgs. Opt-in. **Reason:** "No surprise charges" principle. Matches OpenAI default. Pre-launch users tolerate invisible churn if they don't enable it.
9. **No monthly spending cap by default.** Optional, user-configurable. **Reason:** Henry overrode the "$50 default hard block" recommendation — wants Vercel-style "adult mode" trust.
10. **No per-feature spending caps** in v1 or v2. **Reason:** Org-level cap (when user opts in) is sufficient. Per-feature ceiling matrix adds state × N features for marginal value.
11. **Alert system — two distinct streams:**
    - **Cap-threshold alerts (50/80/100%):** ONLY fire when user has SET an optional monthly cap.
    - **Balance-state alerts (everyone):** Low balance ($5 default, configurable) + zero balance.
    - **Zero-balance email content varies by auto-recharge state:**
      - If auto-recharge ON: "We charged your card $X.XX, balance reloaded" (receipt).
      - If auto-recharge OFF: "Your balance is empty, scans + AI rejected until you top up."
12. **Zero-balance behavior: hard cutoff on METERED actions only.** Dashboard browse, settings, viewing past findings continue to work. Aegis chat, scan kicks, fix-worker runs return a clear "top up to continue" error. **Reason:** Lowest surprise. Distinguishes "out of credit" from "account locked."
13. **Replace Redis `cost-cap.ts` + `platform-cost-cap.ts` entirely.** New Postgres ledger is single source of truth for AI cost. Eliminates double-write race. **Per-feature daily caps (5–50/day) become irrelevant under prepaid model.** Optionally retain `checkSSEConcurrency` (the 5-concurrent-SSE cap — that's about resource contention not money) as a thin Redis check or rebuild on Postgres.
14. **Worker minute metering scope (v1):** Both `depscanner` and `fix-worker`. Emit `worker_minutes` meter events on job completion. Charge at **2x the Fly machine rate** the job actually ran on (perf-2x / perf-4x / shared-cpu-1x, whichever the machine is). **Per-scan-job attribution**, not per-machine — multiple orgs' jobs interleaving on one machine is fine.
15. **Plan & Billing screen — 5 sections:** Balance card (big `$X.XX remaining`), Top-up section (preset chips $5/$10/$25/$50 + custom + Stripe Checkout), Auto-recharge toggle + threshold/amount, Payment method (card last4 from Stripe), Invoices/transactions table.
16. **Usage screen — itemized activity log + time-series chart.** Top: stacked bar chart of daily/weekly $ spent over last 30 days segmented by feature. Bottom: **itemized log of every Aegis chat (with participant attribution), every scan (with project), every fix run (with target), each line showing $ cost.** This is richer than the original "breakdown by feature" recommendation — Henry's refinement.
17. **No predicted cost in action flows.** Cost surfaces in the Usage screen as historical attribution. **Reason:** Most tasks have wildly variable cost; pre-action estimates would mislead.
18. **Marketing PricingPage: single "pay as you go" card + interactive calculator.** "$5 free credit. 2x our AI + worker cost. That's it." Below: `For X scans + Y Aegis sessions/mo → ~$Z`. Anti-tier-comparison-table; the no-tier model IS the feature.
19. **RBAC: keep existing `manage_billing` permission.** Owner role passes by default. Org admins can be granted. Delete tier-gating CALLSITES, keep the permission key. Zero `organization_roles` schema churn.
20. **Org-level configurable billing email** in v1 (Henry refined this from v1.1 → v1). New column on `organization_billing.billing_email_override`. If set, alerts route there instead of `manage_billing` members. Defaults to NULL → fall back to members-with-manage_billing.
21. **Rollout: instant cutover, single PR, no feature flag.** Pre-launch, zero real customers, atomic flip safe. Single migration drops `organization_plans.plan_tier`, drops `syncs_used`, adds new billing tables, deletes old Stripe SKUs via Stripe MCP.
22. **Done = full e2e test that does: top-up via real Stripe test card → run real Aegis chat that burns real Postgres credit → hit zero-balance cutoff with a real 402-equivalent error → trigger reload via real Stripe → resume successfully. Plus depscanner scan that burns real worker-minutes line items.** Per [[feedback_always_e2e]].
23. **Future-additive `organizations.subscription_tier` column kept nullable** so a future Pro/Enterprise SKU (flat fee + included credit) is additive, not a rewrite. **Reason:** Investor/acquirer optics on MRR. Today: column always NULL = pure prepaid path.

## Data Model

### New tables

```sql
-- 1:1 with organizations, holds state + auto-recharge config
organization_billing (
  organization_id           UUID PK FK organizations(id) ON DELETE CASCADE,
  balance_cents             BIGINT NOT NULL DEFAULT 0,        -- never goes negative under hard-cutoff policy
  auto_recharge_enabled     BOOLEAN NOT NULL DEFAULT false,
  auto_recharge_threshold_cents  INTEGER,                     -- e.g. 500 = trigger at $5
  auto_recharge_amount_cents     INTEGER,                     -- e.g. 2000 = add $20
  auto_recharge_monthly_cap_cents INTEGER,                    -- optional ceiling on auto-recharge spend per calendar month
  monthly_spending_cap_cents     INTEGER,                     -- NULL = no cap (per Decision 9)
  low_balance_alert_threshold_cents INTEGER NOT NULL DEFAULT 500,  -- $5 default per Decision 11
  billing_email_override    TEXT,                             -- per Decision 20, NULL = fall back to manage_billing members
  stripe_customer_id        TEXT,
  stripe_default_payment_method_id  TEXT,
  payment_method_brand      TEXT,
  payment_method_last4      TEXT,
  card_expires_month        SMALLINT,
  card_expires_year         SMALLINT,
  cap_alert_50_sent_at      TIMESTAMPTZ,                      -- dedup, reset monthly
  cap_alert_80_sent_at      TIMESTAMPTZ,
  cap_alert_100_sent_at     TIMESTAMPTZ,
  low_balance_alert_sent_at TIMESTAMPTZ,                      -- dedup, reset on top-up
  zero_balance_alert_sent_at TIMESTAMPTZ,                     -- dedup, reset on top-up
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only money-affecting events. Sum of (signed) amounts = current balance_cents.
billing_transactions (
  id                        UUID PK DEFAULT gen_random_uuid(),
  organization_id           UUID NOT NULL FK organizations(id) ON DELETE CASCADE,
  kind                      TEXT NOT NULL CHECK (kind IN (
    'signup_grant',         -- +$5 at org creation
    'topup',                -- +$X manual top-up
    'auto_recharge_topup',  -- +$X auto-recharge
    'usage_deduction',      -- -$X batched deduction from meter events
    'refund',               -- -$X (negative balance entry); reserved, ToS says no refunds
    'adjustment'            -- +/- manual support adjustment by Deptex staff
  )),
  amount_cents              BIGINT NOT NULL,                  -- signed: positive credits, negative deductions
  description               TEXT NOT NULL,                    -- human-readable: "Top-up via Stripe", "Aegis chat <chat_id>"
  stripe_payment_intent_id  TEXT,                             -- nullable; set on topup/auto_recharge_topup
  related_meter_event_ids   UUID[],                           -- for usage_deductions, the meter_events rolled up into this txn
  created_by_user_id        UUID FK users(id),                -- nullable; set for adjustments
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_billing_transactions_org_created ON billing_transactions(organization_id, created_at DESC);
CREATE INDEX idx_billing_transactions_pi ON billing_transactions(stripe_payment_intent_id) WHERE stripe_payment_intent_id IS NOT NULL;

-- Raw meter events, batched into billing_transactions by QStash cron.
billing_meter_events (
  id                        UUID PK DEFAULT gen_random_uuid(),
  organization_id           UUID NOT NULL FK organizations(id) ON DELETE CASCADE,
  event_type                TEXT NOT NULL CHECK (event_type IN ('ai_tokens', 'worker_minutes')),
  provider                  TEXT NOT NULL,                    -- 'openai' | 'anthropic' | 'google' | 'fly'
  feature                   TEXT NOT NULL,                    -- 'aegis.chat' | 'aegis.fix' | 'epd.scoring' | 'rule.generation' | 'depscanner.scan' | 'fix-worker.task' etc.
  quantity                  NUMERIC(20, 6) NOT NULL,          -- input_tokens, output_tokens, or machine_seconds (decide unit per event_type)
  unit                      TEXT NOT NULL,                    -- 'input_tokens' | 'output_tokens' | 'seconds'
  cost_cents_cog            NUMERIC(20, 6) NOT NULL,          -- cost-of-goods (what we pay)
  cost_cents_charged        NUMERIC(20, 6) NOT NULL,          -- 2x cog, what we deduct from balance
  attribution_user_id       UUID FK users(id),                -- who triggered (for Aegis chats); NULL for background scans
  attribution_resource_type TEXT,                             -- 'aegis_chat' | 'scan_job' | 'fix_task' | NULL
  attribution_resource_id   UUID,                             -- the chat_id / scan_job_id / fix_task_id
  model_id                  TEXT,                             -- nullable; for ai_tokens, the model name
  machine_size              TEXT,                             -- nullable; for worker_minutes, 'shared-cpu-1x' | 'perf-2x' etc.
  rolled_up_into_txn_id     UUID FK billing_transactions(id), -- NULL until batched; set when included in a usage_deduction
  emitted_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  rolled_up_at              TIMESTAMPTZ
);
CREATE INDEX idx_meter_events_unrolled ON billing_meter_events(organization_id, emitted_at) WHERE rolled_up_at IS NULL;
CREATE INDEX idx_meter_events_attribution ON billing_meter_events(attribution_resource_type, attribution_resource_id) WHERE attribution_resource_id IS NOT NULL;
```

### Modified tables

```sql
-- Drop the tier system from organization_plans, or migrate it to organization_billing wholesale.
-- Recommendation: drop organization_plans entirely after migrating stripe_customer_id / payment_method_* / created_at to organization_billing.

ALTER TABLE organizations
  ADD COLUMN subscription_tier TEXT;  -- nullable, future-additive per Decision 23. Today always NULL.

-- Drop:
DROP TABLE organization_plans;
DROP TABLE stripe_webhook_events;     -- replaced by new billing_stripe_webhook_events (same idempotency shape, different naming for clarity)

-- Keep but rename for clarity:
CREATE TABLE billing_stripe_webhook_events (
  event_id      TEXT PRIMARY KEY,
  event_type    TEXT NOT NULL,
  processed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Atomic deduction RPC

```sql
-- Decrements balance_cents atomically. Returns the new balance or NULL if insufficient funds (under hard-cutoff policy).
-- Pessimistic SELECT FOR UPDATE on organization_billing row.
CREATE OR REPLACE FUNCTION deduct_balance(p_organization_id UUID, p_amount_cents BIGINT, p_description TEXT, p_meter_event_ids UUID[])
RETURNS BIGINT  -- new balance, or NULL if insufficient
LANGUAGE plpgsql
AS $$ ... $$;
```

## API Endpoints

| Method | Route | Auth | Permission | Description |
|--------|-------|------|------------|-------------|
| GET    | `/api/organizations/:id/billing` | JWT | `manage_billing` OR `view_settings` | Returns balance, auto-recharge config, payment method, billing email |
| POST   | `/api/organizations/:id/billing/topup` | JWT | `manage_billing` | Creates Stripe PaymentIntent for amount. Returns `client_secret` for confirm. |
| POST   | `/api/organizations/:id/billing/auto-recharge` | JWT | `manage_billing` | Updates auto-recharge config (enabled, threshold, amount, monthly cap) |
| POST   | `/api/organizations/:id/billing/spending-cap` | JWT | `manage_billing` | Updates monthly spending cap (null = off) |
| POST   | `/api/organizations/:id/billing/low-balance-threshold` | JWT | `manage_billing` | Updates low-balance alert threshold |
| POST   | `/api/organizations/:id/billing/billing-email` | JWT | `manage_billing` | Updates org-level billing email override |
| DELETE | `/api/organizations/:id/billing/payment-method` | JWT | `manage_billing` | Detach card |
| GET    | `/api/organizations/:id/billing/transactions` | JWT | `manage_billing` OR `view_settings` | Paginated list of `billing_transactions` |
| GET    | `/api/organizations/:id/billing/usage` | JWT | `manage_billing` OR `view_settings` | Time-series chart data + itemized log of meter events with attribution |
| POST   | `/api/billing/stripe-webhooks` | Stripe signature | — | Replaces old stripe-webhooks. Events: `payment_intent.succeeded`, `payment_intent.payment_failed`, `payment_method.updated`, `payment_method.detached`, `charge.refunded` (for support-initiated refunds via Dashboard). |

**Removed routes:**
- `GET /:id/billing/plan` → folded into `GET /billing`
- `POST /:id/billing/checkout` → replaced by topup endpoint
- `POST /:id/billing/portal` → DELETE; we own the UI
- `POST /:id/billing/check-downgrade` → no tiers to downgrade between

**Internal endpoints:**
- `POST /api/internal/billing/meter-event` (`INTERNAL_API_KEY`-guarded) — workers POST `worker_minutes` events here
- AI call sites inside `backend/` write `ai_tokens` events directly via a `recordMeterEvent` lib

## Frontend Surface

### Plan & Billing screen (`OrganizationSettingsPage` section, replaces `PlanBillingSectionContent`)

```
┌─────────────────────────────────────────────────┐
│  Balance                                        │
│  $24.83 remaining                               │
│  Last updated: 2 minutes ago                    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Top up                                         │
│  [$5] [$10] [$25] [$50] [Custom]                │
│  Pay with: •••• 4242                            │
│  [Top up]                                       │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Auto-recharge          [Toggle: ON]            │
│  Recharge $20 when balance falls below $5       │
│  Monthly auto-recharge cap (optional): $200     │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Spending controls                              │
│  Monthly spending cap (optional): [—] [Set]     │
│  Low-balance alert at: $5 [Edit]                │
│  Billing email: billing@acme.com [Edit]         │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Payment method                                 │
│  Visa •••• 4242 — Expires 12/27                 │
│  [Replace card]    [Remove]                     │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Transactions                                   │
│  2026-05-22  Top-up        +$25.00              │
│  2026-05-22  Aegis chat    -$0.43               │
│  2026-05-21  Depscanner    -$0.12               │
│  …                              [Load more]     │
└─────────────────────────────────────────────────┘
```

### Usage screen (`UsageSectionContent` replacement)

```
┌─────────────────────────────────────────────────┐
│  Spend this period                              │
│  $14.27 over last 30 days                       │
│  [Bar chart: daily $ stacked by feature]        │
│  Legend: Aegis | Scans | Fixes | AI inferences  │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Activity                          [Filter ▾]   │
│  ─────────────────────────────────────          │
│  Aegis chat • thread-abc123                     │
│    Triggered by Henry • 2026-05-22 14:13        │
│    18 turns • $0.43                             │
│                                                 │
│  Depscanner scan • opensea/dragonfly            │
│    Triggered by GitHub webhook • 14:05          │
│    8m 22s • $0.31                               │
│                                                 │
│  Fix-worker • CVE-2025-12345 in dragonfly       │
│    Triggered by Henry • 13:48                   │
│    14m 03s • $1.07                              │
│                                                 │
│  …                              [Load more]     │
└─────────────────────────────────────────────────┘
```

### Marketing `PricingPage.tsx`

```
┌──────────────────────────────────────────────────┐
│                                                  │
│      $5 free. Then pay as you go.                │
│                                                  │
│      2x our AI + worker cost. That's it.         │
│      No subscription. No seats. No tiers.        │
│                                                  │
│      [Start free — no card needed]               │
│                                                  │
│ ─────────────────────────────────────────────── │
│                                                  │
│  Estimate your monthly spend                     │
│  Scans per month:        [50  ]                  │
│  Aegis chats per month:  [20  ]                  │
│  AI fixes per month:     [5   ]                  │
│  ─────────────────────────                       │
│  ~$8.40 / month                                  │
│                                                  │
└──────────────────────────────────────────────────┘
```

### Files to modify / create

**Modify:**
- `OrganizationSettingsPage.tsx` — replace `PlanBillingSectionContent` + `UsageSectionContent` whole-cloth
- `orgSettingsSections.tsx` — section labels (no logic change)
- `PlanContext.tsx` → rename to `BillingContext.tsx`; expose `useBilling()` returning `{ balanceCents, autoRecharge, isOverCap, refresh }`. Drop `usePlanGate`, `usePlanLimit`, `TIER_DISPLAY`, `FEATURE_REQUIRED_TIER` exports.
- `PricingPage.tsx` — rewrite per spec above
- Tier-gating callsites: `CreateProjectSidebar.tsx`, `SLAConfigurationSection.tsx`, `AuditLogsSection.tsx` — delete the gates (everyone gets the feature)

**Delete:**
- `frontend/src/components/PlanGateBlocker.tsx` (or equivalent component name) if it exists

**Create:**
- `BillingBalanceCard.tsx`, `TopUpSection.tsx`, `AutoRechargeSection.tsx`, `SpendingControlsSection.tsx`, `PaymentMethodSection.tsx`, `TransactionsTable.tsx`, `UsageSpendChart.tsx`, `UsageActivityLog.tsx`

## User Flows

### Flow 1 — Org creation grants $5

```
1. User completes Supabase OAuth → /organizations/new
2. POST /api/organizations → creates org row
3. Backend hook: insert organization_billing row with balance_cents = 500
4. Backend hook: insert billing_transactions row (kind=signup_grant, amount=+500, description="Welcome credit")
5. Redirect → /organizations/:id/projects with toast "Welcome — you have $5 of credit to explore."
```

### Flow 2 — Top up via Stripe

```
1. User clicks "Top up $25" on Plan & Billing screen
2. POST /api/organizations/:id/billing/topup { amount_cents: 2500 }
3. Backend: create Stripe Customer if missing, create PaymentIntent ($25, customer_id, off_session=false, setup_future_usage='off_session')
4. Return client_secret
5. Frontend: Stripe Elements confirm card → on success, PaymentIntent webhook fires
6. Webhook handler:
   a. dedup via billing_stripe_webhook_events
   b. SELECT FOR UPDATE organization_billing row
   c. INSERT billing_transactions (kind=topup, amount=+2500, stripe_payment_intent_id)
   d. UPDATE organization_billing.balance_cents += 2500
   e. Clear low_balance_alert_sent_at + zero_balance_alert_sent_at (allows re-firing if balance drops again)
   f. If auto_recharge was ON, store the payment_method_id as default
7. Frontend polls /billing or uses realtime → balance updates
8. Email "We charged your card $25.00, balance is now $X.XX" to billing email
```

### Flow 3 — Aegis chat deducts credit

```
1. User sends Aegis message → backend `streamText` runs
2. After provider returns each turn's usage{ input_tokens, output_tokens }:
   - Compute cost_cents_cog from pricing table; cost_cents_charged = 2 × cog
   - INSERT billing_meter_events row (event_type=ai_tokens, provider=openai, feature='aegis.chat', attribution_resource_type='aegis_chat', attribution_resource_id=chat_id, attribution_user_id=user_id)
   - Call deduct_balance RPC with cost_cents_charged
     - RPC: SELECT FOR UPDATE → check balance >= cost → UPDATE balance_cents -= cost → INSERT billing_transactions (kind=usage_deduction, amount=-cost, related_meter_event_ids=[row.id])
     - Returns new balance or NULL
   - If NULL (insufficient): cancel stream, return 402-equivalent error, do not consume more tokens
3. Frontend receives "Out of credit" error mid-stream → show "Top up to continue" CTA
```

(Note: this is the per-turn deduction path. We may batch deductions in v1.1 to reduce write amplification, but v1 keeps it simple — every turn = one deduction = one ledger row.)

### Flow 4 — Worker minutes deducted from depscanner scan

```
1. scan_jobs row claimed by depscanner machine, started_at timestamped
2. Job completes, completed_at timestamped
3. Worker POSTs /api/internal/billing/meter-event with:
   { event_type: 'worker_minutes', provider: 'fly', feature: 'depscanner.scan',
     quantity: seconds_elapsed, unit: 'seconds',
     machine_size: 'perf-2x', attribution_resource_type: 'scan_job',
     attribution_resource_id: scan_job_id, organization_id }
4. Backend: compute cost_cents_cog from Fly rate table (e.g. perf-2x = $0.0000022/sec → 480 sec = $0.001056), cost_cents_charged = 2 × cog
5. INSERT billing_meter_events
6. Call deduct_balance RPC
7. If insufficient: emit "scan-completed-but-credit-insufficient" notification; future scans blocked until top-up
```

(Note: a single scan completing into insufficient credit is allowed — we don't kill in-flight workers. The next scan is blocked.)

### Flow 5 — Auto-recharge fires

```
1. Aegis deduction drops balance to $4.12 (below $5 threshold)
2. Post-deduction check inside RPC: if auto_recharge_enabled AND new balance < threshold:
   a. Lock balance row to prevent concurrent auto-recharges
   b. Check auto_recharge_monthly_cap_cents not exceeded
   c. Create PaymentIntent off_session=true, amount=auto_recharge_amount_cents
   d. On success, INSERT billing_transactions (kind=auto_recharge_topup)
   e. Update balance += amount
   f. Email "We auto-recharged $X.XX" to billing email
3. If PaymentIntent fails (3DS challenge, expired card, etc.):
   a. Disable auto_recharge_enabled (force user action)
   b. Email "Auto-recharge failed, please update your card"
   c. Treat as no-credit going forward
```

### Flow 6 — Zero balance, no auto-recharge

```
1. Final deduction drops balance to $0 (or attempted deduction hits insufficient funds)
2. deduct_balance RPC returns NULL
3. Calling code returns metered-action error to client
4. Email "Your balance is empty. Top up to resume." (idempotent via zero_balance_alert_sent_at)
5. Frontend: balance widget turns red, banner across metered-action pages
6. Non-metered pages (dashboard, settings, history) continue to work
```

## Edge Cases & Failure-Mode Policy

| Scenario | Behavior |
|---|---|
| Stripe webhook arrives twice for same event | Idempotent via `billing_stripe_webhook_events.event_id` PK |
| Stripe webhook never arrives (Stripe outage) | Stripe retries 3 days; we also reconcile via daily cron pulling PaymentIntents created in last 24h |
| Two concurrent Aegis turns deduct simultaneously | `SELECT FOR UPDATE` in `deduct_balance` RPC serializes; second waits behind first |
| Aegis turn completes but DB write fails | Provider already charged us; we eat the cost. Log to Sentry; reconcile manually via support adjustment |
| AI provider returns 500 mid-stream | No meter event emitted (we only emit on completed usage). User's balance untouched. |
| Worker crashes mid-scan | Job ends without completion timestamp; reconciliation cron at hour boundary emits partial meter event from `started_at`→`updated_at`. Risk of over-charging on retries — mitigate with idempotency key per `scan_job_id` |
| Card declined on auto-recharge | Auto-recharge disabled, email sent, no retry. User must re-enable. |
| User downgrades plan (legacy) | N/A — no plans. Settings paths that referenced downgrade are removed. |
| Refund request | ToS: no refunds. Support can issue manual `adjustment` transaction via internal endpoint if Henry decides to comp someone. |
| Org deleted with non-zero balance | Balance is lost (forfeit per ToS). All rows cascade-delete via FK. |
| Stripe Test Mode vs Live Mode | Single `STRIPE_SECRET_KEY` env per environment; dev/local uses test, prod uses live. No mixing. |
| Stripe Tax / VAT | v1: pass through (Deptex absorbs VAT inside the 2x markup). v1.1: enable Stripe Tax on the Customer object. Note in marketing page: "prices include VAT where applicable." |
| Chargeback | Stripe notifies via `charge.dispute.created`. v1: log to Sentry, manual review. v1.1: automated balance debit if customer disputed and won. |
| User who set monthly spending cap hits cap mid-scan | Cap check happens AT deduction time. Mid-scan finishes (we don't kill workers); subsequent metered actions return 402. Cap-100% email fires. |
| Multiple orgs share machine; only one's job runs slow | Per-`scan_job_id` attribution; each org pays for its own job's elapsed time. Machine idle / boot time is platform-absorbed. |
| Currency | USD only in v1. Stripe Customer.currency hardcoded. Multi-currency = v2+. |

## Non-Functional Requirements

- **Deduction latency:** p99 < 50ms per `deduct_balance` RPC call (single row lock, single INSERT, single UPDATE).
- **Meter event throughput:** Backend should sustain 1000 events/sec org-wide (Stripe Meter API benchmark). Realistically << 10/sec at our scale, but design accordingly.
- **Webhook latency:** Stripe webhook handler must respond within 5 seconds (Stripe's timeout). Heavy work moves to QStash.
- **Activity log query (Usage screen):** Paginated, last 30 days default, p95 < 500ms with 100k+ meter events per org.
- **Top-up to balance-visible latency:** < 10 seconds (Stripe webhook + Postgres write + frontend refresh).
- **Auto-recharge race-safety:** No double-top-up if user simultaneously runs another deduction. Row lock + status flag (`auto_recharge_in_progress`).
- **Cost-of-goods table refresh:** AI provider pricing changes weekly to monthly; pricing tables in code, versioned with deployment. Document the table location.

## RBAC Requirements

- `manage_billing` permission (existing) gates:
  - View Plan & Billing screen (balance, top-up, auto-recharge, payment method, transactions)
  - View Usage screen
  - All POST routes that mutate billing state
- `view_settings` permission (existing) optionally allows view-only Usage screen access (TBD — confirm in implementation).
- Owner role retains all permissions by default.
- Billing alert emails route to **org-level configured billing email** if set, else all members with `manage_billing`.

## Dependencies

- **Stripe MCP** — for deleting old Pro/Team SKUs during the rewrite PR. Already loaded.
- **Supabase MCP** — for applying migrations + `apply_composition_results`-style RPC creation.
- **QStash** — for batched deduction worker (v1.1 if we batch; v1 keeps inline per-event).
- **Existing AI pricing table** (`backend/src/lib/ai/pricing.ts`) — preserve, extend if Fly machine pricing not yet listed.
- **No external service additions required for v1.**

## Success Criteria

**v1 ships when this end-to-end scenario passes locally:**

1. Fresh org created via UI → `organization_billing` row exists with `balance_cents = 500`, `billing_transactions` has signup_grant row.
2. User clicks "Top up $25" → real Stripe test card (4242 4242…) charged → webhook arrives → balance shows $30.
3. User runs Aegis chat (~3 turns) → `billing_meter_events` rows appear, `billing_transactions` rows for each turn's deduction, balance drops by real amount, Usage screen shows the chat with attribution.
4. User runs depscanner scan from UI → scan completes → `worker_minutes` meter event emitted → balance deducted, Usage screen shows the scan line item.
5. User keeps using Aegis until balance hits $0 → next chat attempt returns 402-equivalent error with clear UI ("Top up to continue") → existing scan history still loads fine → settings still editable.
6. User toggles auto-recharge ON ($5 threshold, $20 amount) → tops up to $4.99 → runs one more Aegis turn → balance dips below $5 → auto-recharge fires → new $20 charge → balance ~$24.
7. User cancels card → next auto-recharge fails → auto-recharge disabled, email sent → next metered action rejected with clear error.
8. Email alerts fire correctly at low-balance crossing and zero-balance crossing.

**Plus:** PricingPage.tsx renders the new single-card design, marketing calculator works, old `VITE_STRIPE_PRO_*` env vars deleted, old Stripe products archived in test mode + deleted in prod mode.

## Open Questions

Severity tags: **(blocks plan-feature)** / **(can defer to implement)** / **(informational)**

1. **Per-turn deduction vs batched deduction.** *(can defer to implement)* — Per Decision 14, v1 emits per-meter-event + per-deduction. At Aegis throughput this is fine (~10 deductions/min). If we hit write-amplification issues, batch into 60-second windows via QStash. Decide during implementation based on Postgres write metrics.
2. **AI pricing table refresh cadence.** *(can defer to implement)* — Pricing in `backend/src/lib/ai/pricing.ts` updates manually today. Should we keep that or wire to provider APIs? Provider APIs don't expose pricing endpoints reliably; manual + monitored is the pragmatic answer.
3. **Reconciliation cron — daily Stripe sync vs hourly?** *(can defer to implement)* — Run a daily cron pulling PaymentIntents from the last 36 hours and confirming each maps to a `billing_transactions` row. If missing, alert Henry.
4. **Stripe Tax for EU customers — v1 or v1.1?** *(informational)* — v1.1. Document VAT inclusion in marketing copy.
5. **Multi-currency support.** *(informational)* — Out of scope for v1. USD only.
6. **Adjustment audit trail — what does support tooling look like?** *(can defer to implement)* — Internal endpoint to issue `adjustment` transactions, gated by `INTERNAL_API_KEY`. UI deferred until first real refund/comp situation.
7. **What page does PricingPage redirect to for "Start free"?** *(can defer to implement)* — Existing `/auth/sign-up` flow probably. Confirm during implementation.
8. **`PlanContext.tsx` rename to `BillingContext.tsx`.** *(informational)* — Cosmetic, but worth doing in this PR to keep imports consistent post-rewrite.
9. **Marketing calculator's assumed cost rates.** *(can defer to implement)* — Need representative numbers for "average Aegis chat" ($0.40?), "average scan" ($0.10?), "average fix" ($1?). Derive from current production telemetry once available; ship calculator with documented placeholder estimates until then.

**None of the open questions block `/plan-feature`.**

## Recommended Next Step

`/plan-feature` from inside this worktree, using this brief as the locked scope.

Suggested milestone shape for the plan:

- **M1: Schema + migrations + Stripe MCP cleanup** — apply migrations via Supabase MCP, delete old Stripe products via Stripe MCP, drop old `organization_plans` + `stripe_webhook_events` tables.
- **M2: Backend ledger lib + RPC** — `deduct_balance` RPC, `recordMeterEvent` lib, `billing.ts` route, new Stripe webhook handler.
- **M3: AI metering instrumentation** — replace `cost-cap.ts` callsites with meter-event emission. Keep `checkSSEConcurrency`.
- **M4: Worker metering instrumentation** — `depscanner` + `fix-worker` emit `worker_minutes` events on completion. Include reconciliation cron.
- **M5: Frontend — Plan & Billing screen** — 5 sections, Stripe Elements confirm flow, BillingContext.
- **M6: Frontend — Usage screen** — spend chart + activity log.
- **M7: Marketing PricingPage rewrite** — single card + calculator.
- **M8: Delete tier-gating callsites** — remove `usePlanGate`/`usePlanLimit` callers; delete `TIER_DISPLAY`/`planTiers`/`FEATURE_REQUIRED_TIER`; delete frontend env vars `VITE_STRIPE_PRO_*`.
- **M9: Email alerts** — low-balance + zero-balance + cap-threshold + receipt emails via existing notification pipeline.
- **M10: E2E harness** — implement the 8-step Success Criteria scenario as `npm run e2e:billing-prepaid`.
- **M11: /criticalreview + cleanup** — multi-agent review pass, address P0+P1, push.

## Cross-references

- [[billing_prepaid_rewrite_direction]] — the originating direction memory (10 product decisions + 9 open questions Henry locked here).
- [[org_settings_hardening]] — predecessor arc that hardened the org settings screens this rewrite extends.
- [[security_compliance_ia_design]] — the settings IA pattern this rewrite follows.
- [[feedback_always_e2e]] — drives Decision 22 (full e2e).
- [[feedback_two_phase_migration_pattern]] — informs Decision 21 (instant cutover OK because pre-launch).
- [[feedback_no_uncommitted_work_in_main]] — informs the worktree-based development of this arc.
