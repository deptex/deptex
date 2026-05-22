-- Phase 37: Prepaid Billing Rewrite
-- Replaces the 4-tier subscription model with pure prepaid credit.
-- Applied at M11 cutover via Supabase MCP apply_migration (direct apply, NOT branch).
-- See: .cursor/plans/billing-prepaid-rewrite.plan.md
--
-- Patch log (review v1 + v2):
--   A1:  Explicit DROP FUNCTION before DROP TABLE
--   A2:  Backfill stripe_customer_id before DROP organization_plans
--   A7:  Trigger dedup + DB-enforced single-grant unique partial index
--   B1:  Collapsed billing_meter_events INTO billing_transactions (single ledger table)
--   B2:  Removed monthly-cap columns + current_month_usage_cents RPC + cap-alert columns
--   B4:  Removed payment_method_brand/last4/expires_* (lazy Stripe fetch)
--   C5:  Composite (organization_id, idempotency_key) UNIQUE; not full-table
--   C7:  deduct_balance accepts NUMERIC(20,6) amount; rounds internally
--   C8:  assert_balance_matches_ledger() function for reconciliation
--   C10: COMMENT + CHECK on subscription_tier documenting Decision 23 contract
--   B2-1: billing_pending_payment_intents NOT created — Stripe metadata.purpose is source of truth
--   B2-5: cross-column CHECK on event_type ↔ unit pairing
--   B2-6: cross-column CHECK on auto_recharge_in_progress ↔ _started_at pairing
--   B2-7: credit_balance soft-fail to log+auto-create instead of RAISE EXCEPTION

-- =============================================================================
-- 1. NEW TABLES
-- =============================================================================

CREATE TABLE IF NOT EXISTS organization_billing (
  organization_id            UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  balance_cents              BIGINT NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),

  auto_recharge_enabled                BOOLEAN     NOT NULL DEFAULT false,
  auto_recharge_threshold_cents        INTEGER,
  auto_recharge_amount_cents           INTEGER,
  auto_recharge_monthly_cap_cents      INTEGER,
  auto_recharge_in_progress            BOOLEAN     NOT NULL DEFAULT false,
  auto_recharge_in_progress_started_at TIMESTAMPTZ,
  auto_recharge_last_attempt_at        TIMESTAMPTZ,

  low_balance_alert_threshold_cents    INTEGER     NOT NULL DEFAULT 500,
  billing_email_override               TEXT,

  stripe_customer_id                   TEXT UNIQUE,
  stripe_default_payment_method_id     TEXT,

  low_balance_alert_sent_at            TIMESTAMPTZ,
  zero_balance_alert_sent_at           TIMESTAMPTZ,

  created_at                           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_auto_recharge_in_progress_pairing CHECK (
    (auto_recharge_in_progress = false AND auto_recharge_in_progress_started_at IS NULL)
    OR
    (auto_recharge_in_progress = true  AND auto_recharge_in_progress_started_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_ob_stripe_customer       ON organization_billing(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ob_auto_recharge_enabled ON organization_billing(auto_recharge_enabled) WHERE auto_recharge_enabled = true;

-- Single ledger table carrying BOTH transaction + per-event metering metadata.
-- Append-only. Sum of signed amount_cents per org == organization_billing.balance_cents (invariant).
CREATE TABLE IF NOT EXISTS billing_transactions (
  id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind                       TEXT NOT NULL CHECK (kind IN (
    'signup_grant', 'topup', 'auto_recharge_topup', 'usage_deduction', 'refund', 'adjustment'
  )),
  amount_cents               BIGINT NOT NULL,

  event_type                 TEXT CHECK (event_type IN ('ai_tokens', 'worker_minutes')),
  provider                   TEXT,
  feature                    TEXT,
  quantity                   NUMERIC(20, 6) CHECK (quantity IS NULL OR quantity > 0),
  output_quantity            NUMERIC(20, 6) CHECK (output_quantity IS NULL OR output_quantity > 0),
  unit                       TEXT CHECK (unit IN ('input_tokens', 'output_tokens', 'seconds', 'mixed_tokens')),
  cost_cents_cog             NUMERIC(20, 6) CHECK (cost_cents_cog IS NULL OR cost_cents_cog >= 0),
  attribution_user_id        UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  attribution_resource_type  TEXT CHECK (attribution_resource_type IN ('aegis_chat', 'scan_job', 'fix_task', 'rule_generation', 'epd_scoring')),
  attribution_resource_id    UUID,
  model_id                   TEXT,
  machine_size               TEXT,
  idempotency_key            TEXT,

  description                TEXT NOT NULL,
  stripe_payment_intent_id   TEXT,
  created_by_user_id         UUID REFERENCES auth.users(id) ON DELETE SET NULL,

  created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT chk_event_type_unit_pairing CHECK (
    event_type IS NULL
    OR (event_type = 'ai_tokens'      AND unit IN ('input_tokens', 'output_tokens', 'mixed_tokens'))
    OR (event_type = 'worker_minutes' AND unit = 'seconds' AND output_quantity IS NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_billing_transactions_org_idemp
  ON billing_transactions(organization_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_transactions_one_signup_grant_per_org
  ON billing_transactions(organization_id)
  WHERE kind = 'signup_grant';

CREATE UNIQUE INDEX IF NOT EXISTS uq_billing_transactions_pi_credit
  ON billing_transactions(stripe_payment_intent_id)
  WHERE stripe_payment_intent_id IS NOT NULL AND kind IN ('topup', 'auto_recharge_topup');

CREATE INDEX IF NOT EXISTS idx_billing_transactions_org_created    ON billing_transactions(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_transactions_kind           ON billing_transactions(organization_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_transactions_attribution    ON billing_transactions(attribution_resource_type, attribution_resource_id) WHERE attribution_resource_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_billing_transactions_feature        ON billing_transactions(organization_id, feature, created_at DESC) WHERE feature IS NOT NULL;

CREATE TABLE IF NOT EXISTS billing_stripe_webhook_events (
  event_id       TEXT PRIMARY KEY,
  event_type     TEXT NOT NULL,
  processed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- C10: Future-additive subscription_tier with documented contract (Decision 23 kept)
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

INSERT INTO organization_billing (organization_id, balance_cents, stripe_customer_id)
SELECT op.organization_id, 500, op.stripe_customer_id
FROM organization_plans op
ON CONFLICT (organization_id) DO UPDATE
  SET stripe_customer_id = COALESCE(organization_billing.stripe_customer_id, EXCLUDED.stripe_customer_id);

INSERT INTO organization_billing (organization_id, balance_cents)
SELECT id, 500 FROM organizations
ON CONFLICT (organization_id) DO NOTHING;

INSERT INTO billing_transactions (organization_id, kind, amount_cents, description)
SELECT id, 'signup_grant', 500, 'Welcome credit ($5)' FROM organizations
ON CONFLICT DO NOTHING;

-- =============================================================================
-- 3. RPCs
-- =============================================================================

CREATE OR REPLACE FUNCTION deduct_balance(
  p_organization_id  UUID,
  p_amount_cents     NUMERIC(20, 6),
  p_description      TEXT,
  p_event_metadata   JSONB
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

DROP FUNCTION IF EXISTS increment_sync_usage(UUID, INTEGER);
DROP FUNCTION IF EXISTS decrement_sync_usage(UUID);

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
