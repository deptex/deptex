-- Aegis activity logs table
CREATE TABLE IF NOT EXISTS aegis_activity_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  request_text TEXT NOT NULL,
  action_performed TEXT,
  result_json JSONB DEFAULT '{}'
);

-- Enable Row Level Security
ALTER TABLE aegis_activity_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies for aegis_activity_logs
-- Users can view activity logs for organizations they are members of
CREATE POLICY "Users can view aegis activity logs for their orgs"
  ON aegis_activity_logs FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only authenticated users can create activity logs (typically done by backend)
CREATE POLICY "Authenticated users can create aegis activity logs"
  ON aegis_activity_logs FOR INSERT
  WITH CHECK (auth.uid() IS NOT NULL);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_aegis_activity_logs_organization_id ON aegis_activity_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_aegis_activity_logs_timestamp ON aegis_activity_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_aegis_activity_logs_action_performed ON aegis_activity_logs(action_performed);

