-- Unified flows: notification, PR check, policy, and status flows.
-- Each row is a complete graph; the engine walks it on a trigger.

CREATE TABLE IF NOT EXISTS flows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_type TEXT NOT NULL CHECK (flow_type IN ('notification', 'pr_check', 'policy', 'status')),
  scope TEXT NOT NULL CHECK (scope IN ('organization', 'team', 'project')),
  scope_id UUID NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  graph JSONB NOT NULL DEFAULT '{"version":1,"nodes":[],"edges":[]}'::jsonb,
  version INTEGER NOT NULL DEFAULT 1,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  dry_run BOOLEAN NOT NULL DEFAULT FALSE,
  snoozed_until TIMESTAMPTZ,
  created_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flows_org_type_active
  ON flows (organization_id, flow_type, active) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_flows_scope ON flows (scope, scope_id);

ALTER TABLE flows ENABLE ROW LEVEL SECURITY;

CREATE POLICY flows_select_org_members ON flows
  FOR SELECT USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );
-- Inserts/updates/deletes go through the service-role backend (RBAC-gated in route handlers).


-- Append-only version history. One row per save.
CREATE TABLE IF NOT EXISTS flow_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  graph JSONB NOT NULL,
  name TEXT NOT NULL,
  changed_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  change_summary TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (flow_id, version)
);

CREATE INDEX IF NOT EXISTS idx_flow_versions_flow ON flow_versions (flow_id, version DESC);

ALTER TABLE flow_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY flow_versions_select_org_members ON flow_versions
  FOR SELECT USING (
    flow_id IN (
      SELECT id FROM flows WHERE organization_id IN (
        SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
      )
    )
  );


-- Per-execution record. Powers the notification history page and per-flow run history.
CREATE TABLE IF NOT EXISTS flow_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  flow_version INTEGER NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  trigger_event_id UUID REFERENCES notification_events(id) ON DELETE SET NULL,
  trigger_payload JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'skipped', 'dry_run')),
  outcome JSONB,
  error TEXT,
  duration_ms INTEGER,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_flow_runs_flow_started ON flow_runs (flow_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_flow_runs_org_started ON flow_runs (organization_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_flow_runs_trigger_event
  ON flow_runs (trigger_event_id) WHERE trigger_event_id IS NOT NULL;

ALTER TABLE flow_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY flow_runs_select_org_members ON flow_runs
  FOR SELECT USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );


-- Per-node execution trace. Click a run, see which nodes fired and what flowed through.
CREATE TABLE IF NOT EXISTS flow_node_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_run_id UUID NOT NULL REFERENCES flow_runs(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL,
  node_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'skipped')),
  input JSONB,
  output JSONB,
  error TEXT,
  duration_ms INTEGER,
  executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flow_node_executions_run
  ON flow_node_executions (flow_run_id, executed_at);

ALTER TABLE flow_node_executions ENABLE ROW LEVEL SECURITY;
CREATE POLICY flow_node_executions_select_org_members ON flow_node_executions
  FOR SELECT USING (
    flow_run_id IN (
      SELECT id FROM flow_runs WHERE organization_id IN (
        SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
      )
    )
  );
