---
name: Phase 13 - Plans, Billing & Stripe
overview: 4 tiers, Stripe integration, usage metering, plan limits.
todos:
  - id: phase-13-billing
    content: "Phase 13: Plans, Billing & Stripe - Define 4 tiers (Free/Pro $25/Team $300/Enterprise), Stripe Checkout + Billing + Customer Portal + Webhooks, sync-based usage metering, plan limit enforcement across all features (projects, members, syncs, Watchtower, AI), Usage & Plan & Billing page in Org Settings, invoices, legal docs (DPA, TIA, ToS, Privacy), sync frequency config per project"
    status: pending
isProject: false
---
## Phase 13: Plans, Billing & Stripe Integration

**Goal:** Implement a tiered pricing model with Stripe integration, usage metering, plan limits enforced throughout the app, and legal compliance documents. Transform the existing "Usage & Plan & Billing" placeholder in Org Settings into a fully functional billing dashboard.

**Timeline:** ~4-5 weeks. Stripe integration is well-documented; the bulk of work is plan-gating every feature across the app.

### 13A: Pricing Tiers


| Feature                          | Free        | Pro ($25/mo)                              | Team ($300/mo) | Enterprise (contact) |
| -------------------------------- | ----------- | ----------------------------------------- | -------------- | -------------------- |
| Projects                         | 3           | 15                                        | 50             | Unlimited            |
| Members                          | 5           | 20                                        | Unlimited      | Unlimited            |
| Syncs/month                      | 10          | 100                                       | 1000           | Unlimited            |
| Sync frequency                   | Manual only | Configurable (commit/daily/weekly/manual) | Configurable   | Configurable         |
| Watchtower packages              | 5           | 25                                        | 100            | Unlimited            |
| Deep reachability (atom)         | Yes         | Yes                                       | Yes            | Yes                  |
| Vulnerability scanning           | Yes         | Yes                                       | Yes            | Yes                  |
| Policy-as-code                   | Yes         | Yes                                       | Yes            | Yes                  |
| Platform AI (analyze, summaries) | Yes         | Yes                                       | Yes            | Yes                  |
| Aegis conversational AI (BYOK)   | No          | Yes                                       | Yes            | Yes                  |
| AI fixes / sprints (BYOK)        | No          | Yes                                       | Yes            | Yes                  |
| Background monitoring            | No          | Yes                                       | Yes            | Yes                  |
| Advanced filtering + sidebars    | Yes         | Yes                                       | Yes            | Yes                  |
| Watchtower forensics             | No          | Yes                                       | Yes            | Yes                  |
| SSO (SAML)                       | No          | No                                        | Yes            | Yes                  |
| MFA enforcement                  | No          | No                                        | Yes            | Yes                  |
| SOC 2 docs                       | No          | No                                        | Yes            | Yes                  |
| DPA + TIA                        | No          | No                                        | Yes            | Yes                  |
| Priority support                 | No          | No                                        | Yes            | Yes                  |
| BYO cloud / self-hosted          | No          | No                                        | No             | Yes                  |
| Private Slack + CSM              | No          | No                                        | No             | Yes                  |
| Custom SLA                       | No          | No                                        | No             | Yes                  |
| Audit logs (Phase 15)            | No          | No                                        | No             | Yes                  |


**Economics (does this keep us in the green?):**

Our cost per sync: ~$0.15 avg (performance-8x 64GB, 10-15 min).

- **Free**: 10 syncs x $0.15 = $1.50/month loss per org. Acceptable marketing/acquisition cost.
- **Pro**: At 60% utilization (typical SaaS), 60 syncs x $0.15 = $9 cost. $25 revenue = **$16 margin**.
- **Team**: At 60% utilization, 600 syncs x $0.15 = $90 cost. $300 revenue = **$210 margin**.
- **Enterprise**: Custom pricing ensures profitability.
- One Team customer covers ~230 free users. Standard SaaS pyramid economics.

**No overage model**: when an org reaches their sync/project/member limit, they see "You've reached your plan limit. Upgrade to [next tier] for more." No surprise charges. Clean and predictable for users.

### 13B: Database Schema

```sql
CREATE TABLE organization_plans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  plan_tier TEXT NOT NULL DEFAULT 'free', -- 'free', 'pro', 'team', 'enterprise'
  stripe_customer_id TEXT, -- Stripe customer ID
  stripe_subscription_id TEXT, -- Stripe subscription ID
  stripe_price_id TEXT, -- Stripe price ID for the current plan
  billing_email TEXT,
  billing_cycle TEXT DEFAULT 'monthly', -- 'monthly', 'annual'
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  cancel_at_period_end BOOLEAN DEFAULT false,
  -- Usage tracking for current billing period
  syncs_used INTEGER DEFAULT 0,
  syncs_limit INTEGER NOT NULL DEFAULT 10, -- from plan tier
  projects_limit INTEGER NOT NULL DEFAULT 3,
  members_limit INTEGER NOT NULL DEFAULT 5,
  watchtower_limit INTEGER NOT NULL DEFAULT 5,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id)
);

CREATE INDEX idx_op_stripe_customer ON organization_plans(stripe_customer_id);
CREATE INDEX idx_op_stripe_subscription ON organization_plans(stripe_subscription_id);
```

### 13C: Stripe Integration

**Stripe products and prices** (configured in Stripe Dashboard or via API):

- Product: "Deptex Pro" with monthly ($25) and annual ($250/yr, ~17% discount) prices
- Product: "Deptex Team" with monthly ($300) and annual ($3000/yr) prices
- Enterprise: handled manually (custom invoices via Stripe)

**Backend integration** (`ee/backend/lib/stripe.ts`):

```typescript
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

// Create Stripe Checkout session for plan upgrade
async function createCheckoutSession(orgId: string, priceId: string): Promise<string>;

// Handle Stripe webhooks: subscription lifecycle events
async function handleWebhookEvent(event: Stripe.Event): Promise<void>;

// Open Stripe Customer Portal for self-service billing management
async function createPortalSession(orgId: string): Promise<string>;

// Reset monthly usage counters (called by cron at billing period reset)
async function resetUsageCounters(orgId: string): Promise<void>;
```

**Stripe Webhooks** (`ee/backend/routes/stripe-webhooks.ts`):

Events to handle:

- `checkout.session.completed` -- plan purchased, update `organization_plans` with tier + Stripe IDs
- `customer.subscription.updated` -- plan changed (upgrade/downgrade), update tier + limits
- `customer.subscription.deleted` -- plan cancelled, downgrade to free at period end
- `invoice.payment_succeeded` -- record successful payment
- `invoice.payment_failed` -- notify org admin, show warning banner in UI
- `invoice.created` -- store invoice reference for the billing page

**Backend API endpoints:**

- `POST /api/organizations/:id/billing/checkout` -- create Stripe Checkout session for plan upgrade (requires `manage_integrations`)
- `POST /api/organizations/:id/billing/portal` -- create Stripe Customer Portal session for invoice/payment management
- `GET /api/organizations/:id/billing/usage` -- current usage vs limits (projects, syncs, members, watchtower)
- `GET /api/organizations/:id/billing/invoices` -- list past invoices from Stripe
- `POST /api/stripe/webhooks` -- Stripe webhook endpoint (verified with webhook secret)

**Stripe pricing note**: Stripe charges 2.9% + $0.30 per transaction. For Pro at $25/month, Stripe takes ~$1.03 (4.1%). For Team at $300/month, Stripe takes ~$9.00 (3.0%). Standard SaaS payment processing cost.

### 13D: Plan Limit Enforcement Across the App

**Every feature that has a plan limit must check before allowing the action.** Backend middleware `checkPlanLimit(orgId, resource)` that returns `{ allowed: boolean, current: number, limit: number, tier: string }`.

**Affected features (exhaustive list):**

1. **Project creation** ([CreateProjectSidebar.tsx](frontend/src/components/CreateProjectSidebar.tsx) + backend `POST /api/projects`):
  - Check `projects_limit` before allowing new project. If at limit: "You've reached the X project limit on your [tier] plan. Upgrade to [next tier] for Y projects."
  - Frontend: "New Project" button shows upgrade prompt when at limit.
2. **Member invites** (Org Settings Members page + backend `POST /api/organizations/:id/invite`):
  - Check `members_limit` before sending invite. If at limit: "Your [tier] plan supports up to X members."
  - Free: 5, Pro: 20, Team: unlimited.
3. **Extraction sync trigger** (manual trigger button + auto-sync webhook handler + background monitoring):
  - Check `syncs_used < syncs_limit` before starting any extraction. Increment `syncs_used` when job starts.
  - If at limit: "You've used all X syncs this month. Your syncs reset on [billing period end date]. Upgrade for more."
  - Background monitoring vuln-check jobs do NOT count as syncs (they're lightweight API calls, no extraction). Only full extraction runs count.
  - The extraction endpoint, webhook handler, and QStash cron all check this before queuing.
4. **Sync frequency configuration** (project repository settings):
  - Free tier: only "Manual" option available. Other options grayed out with "Pro feature" badge.
  - Pro+: all options available (on-commit, daily, weekly, manual).
  - Per-project setting stored in `project_repositories.sync_frequency` (new column): `'manual'`, `'on_commit'`, `'daily'`, `'weekly'`.
5. **Watchtower package add** (Watchtower settings):
  - Check `watchtower_limit` before adding a package to watch. If at limit: "Your [tier] plan supports up to X watched packages."
6. **Aegis conversational AI panel** (Security tab, Supply Chain tab):
  - Free tier: Aegis tab hidden entirely. The panel does not render.
  - Pro+: visible and functional (requires BYOK key separately).
7. **AI fix / sprint buttons** (Vulnerability Detail Sidebar, Project Security Sidebar):
  - Free tier: "Fix with AI" and "Run Security Sprint" buttons hidden entirely.
  - Pro+: visible (still requires BYOK key).
8. **Background monitoring toggle** (project settings):
  - Free tier: toggle disabled with "Pro feature" tooltip.
  - Pro+: enabled.
9. **Watchtower forensics** (Watchtower tab):
  - Free tier: tab shows "Upgrade to Pro to access Watchtower forensics."
  - Pro+: full access.
10. **SSO settings** (Org Settings):
  - Free/Pro: "SSO configuration" section shows "Available on Team plan" with upgrade button.
    - Team+: SSO configuration UI.
11. **MFA enforcement** (Org Settings Security):
  - Free/Pro: toggle disabled with "Team feature" badge.
    - Team+: enabled.
12. **Legal docs** (DPA, TIA):
  - Free/Pro: legal docs section hidden or shows "Available on Team plan."
    - Team+: downloadable DPA and TIA documents.

**Frontend approach**: a `usePlanGate(feature: string)` hook that returns `{ allowed: boolean, currentTier: string, requiredTier: string, upgradeUrl: string }`. Used throughout the app to conditionally render features or show upgrade prompts. Fetches plan data once and caches in React context.

**Backend approach**: `checkPlanLimit` middleware applied to relevant API endpoints. Returns 403 with `{ error: 'PLAN_LIMIT', resource: 'syncs', current: 100, limit: 100, tier: 'pro', upgradeTier: 'team' }` when limit is reached. Frontend catches this and shows the upgrade prompt.

### 13E: Usage & Plan & Billing Page

Replace the placeholder in [OrganizationSettingsPage.tsx](frontend/src/app/pages/OrganizationSettingsPage.tsx) "Usage & Plan & Billing" section:

**Current Plan Card:**

- Plan name badge (Free / Pro / Team / Enterprise) with tier color
- Status: Active / Cancelling / Past Due
- Billing cycle: Monthly / Annual
- Renewal date: "Renews on March 1, 2026"
- "Upgrade Plan" button (opens Stripe Checkout)
- "Manage Plan" button (opens Stripe Customer Portal -- change plan, update payment, cancel)

**Usage Card:**

- **Projects**: 8 / 15 used (progress bar)
- **Members**: 12 / 20 used (progress bar)
- **Syncs this month**: 67 / 100 used (progress bar, color changes to yellow >75%, red >90%)
- **Watchtower packages**: 18 / 25 used (progress bar)
- **Syncs reset on**: [next billing period start]
- If any resource is at limit: yellow warning badge

**Billing Card:**

- Payment method: Visa ending in 4242 (from Stripe)
- "Update Payment Method" button (Stripe Customer Portal)
- Next invoice: $25.00 on March 1, 2026

**Invoices Table:**

- Past invoices fetched from Stripe: date, amount, status (paid/failed/pending), PDF download link
- Paginated, most recent first

**AI Usage Section:**

- Link to the AI Usage Dashboard (from 6G): "View detailed AI usage and token spending"
- Quick summary: total AI calls this month, estimated BYOK spend

### 13F: Sync Frequency Configuration

New per-project setting in repository settings ([ProjectSettingsPage.tsx](frontend/src/app/pages/ProjectSettingsPage.tsx) or equivalent):

**New column:**

```sql
ALTER TABLE project_repositories ADD COLUMN sync_frequency TEXT DEFAULT 'manual';
-- Values: 'manual', 'on_commit', 'daily', 'weekly'
```

**UI in project repository settings:**

- Radio buttons: Manual / On every commit / Daily / Weekly
- Free tier: only "Manual" selectable, others grayed out with "Requires Pro" tooltip
- "On every commit" shows warning: "This will use 1 sync per commit pushed. High-traffic repos may use syncs quickly."
- Estimated monthly usage hint based on recent commit frequency (from webhook data if available)

**Backend changes:**

- Webhook push handler (`handlePushEvent`): check `sync_frequency`. If `'on_commit'`, queue extraction. If `'daily'` or `'weekly'`, skip (handled by cron). If `'manual'`, skip.
- Cron job (QStash scheduled task): runs daily, queries projects with `sync_frequency = 'daily'` or (weekly AND it's the configured day). Queues extractions respecting the org's sync limit.
- All paths check `syncs_used < syncs_limit` before queuing.

### 13G: Legal Documents

**DPA (Data Processing Addendum):**

- Standard GDPR-compliant document
- Available to Team+ orgs as a downloadable PDF from Org Settings > Legal
- Covers: data processing purposes, sub-processors (Supabase, Fly.io, Stripe), data retention, security measures
- Generated from a markdown template with org name and date fields

**Transfer Impact Assessment (TIA):**

- Standard document for EU data transfers (Schrems II compliance)
- Available alongside DPA for Team+ orgs
- Covers: data flow mapping, legal basis for transfers, supplementary measures

**Terms of Service + Privacy Policy:**

- Available to all tiers (required for any SaaS)
- Hosted at `/legal/terms` and `/legal/privacy` routes
- Static markdown pages rendered in the docs system
- Link in the footer of every page + during signup

### 13H: Phase 13 Test Suite

Tests 1-5 (Stripe Integration):

1. Checkout session creates correct Stripe session for Pro plan
2. Webhook `checkout.session.completed` updates org plan tier and limits
3. Webhook `customer.subscription.deleted` schedules downgrade to free at period end
4. Webhook `invoice.payment_failed` sets org plan status to past_due
5. Portal session returns valid Stripe Customer Portal URL

Tests 6-12 (Plan Limit Enforcement):
6. Project creation blocked at project limit (returns 403 with upgrade prompt)
7. Member invite blocked at member limit
8. Extraction blocked at sync limit (returns 403 with sync reset date)
9. Sync frequency options disabled on Free tier (only manual available)
10. Aegis panel hidden on Free tier
11. "Fix with AI" button hidden on Free tier
12. Watchtower add blocked at package limit

Tests 13-16 (Usage & Billing Page):
13. Usage card shows correct counts and progress bars
14. Plan card shows correct tier and renewal date
15. Invoices table fetches and displays Stripe invoices
16. "Upgrade" button creates Stripe Checkout session

Tests 17-18 (Sync Frequency):
17. On-commit sync respects sync_frequency setting
18. Daily cron only queues projects with sync_frequency = 'daily'
