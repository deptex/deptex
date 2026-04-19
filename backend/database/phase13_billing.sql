-- Phase 13: Plans, Billing & Stripe
-- Prerequisites: organizations table must exist
-- Run after: phase9_notifications.sql, phase10_gin_index.sql

-- ─── Organization Plans ───
CREATE TABLE IF NOT EXISTS organization_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  plan_tier TEXT NOT NULL DEFAULT 'free',
  subscription_status TEXT NOT NULL DEFAULT 'active',
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  stripe_price_id TEXT,
  billing_email TEXT,
  billing_cycle TEXT DEFAULT 'monthly',
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  cancel_at_period_end BOOLEAN DEFAULT false,
  cancel_at TIMESTAMPTZ,
  syncs_used INTEGER DEFAULT 0,
  syncs_reset_at TIMESTAMPTZ DEFAULT NOW(),
  payment_method_brand TEXT,
  payment_method_last4 TEXT,
  custom_limits JSONB,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id)
);

CREATE INDEX IF NOT EXISTS idx_op_stripe_customer ON organization_plans(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_op_stripe_subscription ON organization_plans(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_op_status ON organization_plans(subscription_status);
CREATE INDEX IF NOT EXISTS idx_op_tier ON organization_plans(plan_tier);

-- ─── Stripe Webhook Idempotency ───
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  processed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_swe_event_id ON stripe_webhook_events(event_id);

-- ─── Atomic sync increment RPC ───
-- Returns the new count and whether the operation was allowed.
-- Uses FOR UPDATE to prevent race conditions on concurrent webhook pushes.
CREATE OR REPLACE FUNCTION increment_sync_usage(p_org_id UUID, p_sync_limit INTEGER)
RETURNS TABLE(new_count INTEGER, was_allowed BOOLEAN) AS $$
DECLARE
  v_current INTEGER;
BEGIN
  SELECT syncs_used INTO v_current
    FROM organization_plans
    WHERE organization_id = p_org_id
    FOR UPDATE;

  IF v_current IS NULL THEN
    RETURN QUERY SELECT 0, false;
    RETURN;
  END IF;

  IF p_sync_limit = -1 OR v_current < p_sync_limit THEN
    UPDATE organization_plans
      SET syncs_used = syncs_used + 1, updated_at = NOW()
      WHERE organization_id = p_org_id;
    RETURN QUERY SELECT v_current + 1, true;
  ELSE
    RETURN QUERY SELECT v_current, false;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- ─── Decrement sync usage (for cancelled syncs) ───
CREATE OR REPLACE FUNCTION decrement_sync_usage(p_org_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE organization_plans
    SET syncs_used = GREATEST(syncs_used - 1, 0), updated_at = NOW()
    WHERE organization_id = p_org_id;
END;
$$ LANGUAGE plpgsql;

-- ─── Backfill: create organization_plans row for every existing org ───
INSERT INTO organization_plans (organization_id, plan_tier)
SELECT id, COALESCE(plan, 'free') FROM organizations
ON CONFLICT (organization_id) DO NOTHING;

-- ─── RLS Policies ───
ALTER TABLE organization_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE stripe_webhook_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on organization_plans"
  ON organization_plans FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on stripe_webhook_events"
  ON stripe_webhook_events FOR ALL USING (true) WITH CHECK (true);
