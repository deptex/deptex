-- Phase 38: project_id on billing_transactions for the Vercel-style Usage UI.
-- Worker events (depscanner.*, fix-worker.task) carry a project_id; aegis_chat
-- + rule_generation + epd_scoring don't (NULL = cross-project).
--
-- The deduct_balance RPC now threads `project_id` out of the JSONB metadata
-- so existing callers keep working without code changes (project_id stays
-- NULL for any caller that doesn't include it).

ALTER TABLE billing_transactions
  ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_billing_transactions_org_project_created
  ON billing_transactions(organization_id, project_id, created_at DESC)
  WHERE project_id IS NOT NULL;

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
    attribution_resource_id, model_id, machine_size, idempotency_key,
    project_id
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
    p_event_metadata->>'idempotency_key',
    (p_event_metadata->>'project_id')::UUID
  );

  RETURN v_current_balance - v_amount_rounded;
END;
$$;
