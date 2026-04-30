-- The phase23 migration added project_reachable_flows_reachability_source_check
-- without dropping the older (Phase 6b) project_reachable_flows_source_chk
-- that constrained reachability_source to ('atom','semgrep_taint'). Both
-- constraints are evaluated on INSERT, so taint_engine inserts fail the
-- old one. Drop it; the newer constraint covers the same column with the
-- updated value list.
ALTER TABLE project_reachable_flows
  DROP CONSTRAINT IF EXISTS project_reachable_flows_source_chk;
