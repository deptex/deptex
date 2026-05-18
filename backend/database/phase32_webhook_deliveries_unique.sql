-- Phase 32: enforce UNIQUE (delivery_id, provider) on webhook_deliveries.
--
-- Webhook dedup currently relies solely on a 1-hour Redis SETNX in
-- deduplicateWebhookDelivery (backend/src/routes/integrations.ts). If
-- Redis flaps, suffers an eviction at 99% memory, or the ex-3600 key
-- expires before a slow-redelivered webhook arrives, the audit table
-- accumulates duplicate rows for the same (delivery_id, provider). The
-- backing index on delivery_id alone is non-unique, so nothing in the
-- DB rejects the duplicate.
--
-- Add a UNIQUE index on (delivery_id, provider). Provider must be in
-- the key because GitHub / GitLab / Bitbucket all share this table and
-- can issue colliding delivery_id values across providers. The column
-- is already NOT NULL (phase8_webhook_deliveries.sql), so an
-- unconditional UNIQUE index is correct.
--
-- The matching application change (phase 32 of the recordWebhookDelivery
-- chain) rejects callers that omit a delivery_id rather than letting
-- them all collapse onto the literal 'unknown'. Without that the UNIQUE
-- constraint would start refusing legitimate inserts.
--
-- Idempotent: IF NOT EXISTS guards the index name. Safe to apply on a
-- live table only after duplicates have been reconciled — Henry will
-- run the dedup query (see commit body) before applying.

CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_deliveries_delivery_provider
  ON webhook_deliveries (delivery_id, provider);

-- The original non-unique index on delivery_id alone is now redundant
-- (the leading column of the UNIQUE composite covers single-column
-- delivery_id lookups). Drop it to free the dead row pointer overhead.
DROP INDEX IF EXISTS idx_webhook_deliveries_delivery_id;
