-- phase73_drop_flows.sql
-- Remove the automation "Flows" builder (parked pre-launch; cut for the open-source release).
--
-- NOT removed: the isolated-vm code sandbox it borrowed. That lives in the policy engine
-- (backend/src/lib/policy-engine.ts) and is still used by package/status/pr-check policy code.
-- Also NOT touched: the reachability "flows" (project_reachable_flows, code-flow / taint-engine
-- data-flow findings) — a different feature that merely shares the word "flow".
--
-- Idempotent (IF EXISTS everywhere): a no-op on fresh installs that never created these tables.

-- 1. Unwind the coupling onto the KEPT notification_deliveries table first (its flow_run_id
--    column carries an FK into flow_runs, so it must go before the flow tables).
DROP INDEX IF EXISTS idx_notif_deliveries_flow_run;
ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS flow_run_id;
-- notification_deliveries.rule_id stays nullable (it was loosened during the flow rollout;
-- restoring NOT NULL is unnecessary and would risk existing rows with a null rule_id).

-- 2. Drop the four flow tables, child -> parent.
DROP TABLE IF EXISTS flow_node_executions CASCADE;
DROP TABLE IF EXISTS flow_runs CASCADE;
DROP TABLE IF EXISTS flow_versions CASCADE;
DROP TABLE IF EXISTS flows CASCADE;
