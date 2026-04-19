-- Phase 8F.8: Webhook Deliveries Audit Table
-- Persistent record of all webhook deliveries for debugging and audit trail.

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  delivery_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  event_type TEXT NOT NULL,
  action TEXT,
  repo_full_name TEXT,
  installation_id TEXT,
  processing_status TEXT NOT NULL DEFAULT 'received',
  error_message TEXT,
  processing_duration_ms INTEGER,
  payload_size_bytes INTEGER,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_delivery_id ON webhook_deliveries(delivery_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_repo ON webhook_deliveries(repo_full_name);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON webhook_deliveries(created_at);
