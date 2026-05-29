-- Monthly cap-reached email dedup slot. NULL = never sent. Cleared at the start of each
-- UTC month by the alert helper (claim-on-update: see backend/src/lib/billing/alerts.ts).
ALTER TABLE organization_billing
  ADD COLUMN IF NOT EXISTS auto_recharge_cap_alert_sent_at TIMESTAMPTZ;
