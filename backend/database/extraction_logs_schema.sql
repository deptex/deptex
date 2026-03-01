-- Phase 2F: extraction_logs table — Live extraction log streaming via Supabase Realtime

CREATE TABLE IF NOT EXISTS extraction_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id UUID NOT NULL,
  step TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info', 'success', 'warning', 'error')),
  message TEXT NOT NULL,
  duration_ms INTEGER,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_extraction_logs_project ON extraction_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_extraction_logs_run ON extraction_logs(run_id);

-- Enable Supabase Realtime on this table
ALTER PUBLICATION supabase_realtime ADD TABLE extraction_logs;

-- RLS
ALTER TABLE extraction_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access" ON extraction_logs
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Org members can read own project logs" ON extraction_logs
  FOR SELECT USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );
