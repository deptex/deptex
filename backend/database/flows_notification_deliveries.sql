-- Wire notification_deliveries into the flow engine.
-- A delivery is now produced by either a legacy rule (rule_id) or a flow run (flow_run_id).
-- Once the legacy rule tables are dropped (end of flow builder rollout), rule_id can go too.

ALTER TABLE notification_deliveries
  ADD COLUMN IF NOT EXISTS flow_run_id UUID REFERENCES flow_runs(id) ON DELETE SET NULL;

ALTER TABLE notification_deliveries
  ALTER COLUMN rule_id DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_notif_deliveries_flow_run
  ON notification_deliveries (flow_run_id) WHERE flow_run_id IS NOT NULL;
