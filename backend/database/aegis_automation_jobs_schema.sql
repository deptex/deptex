-- Aegis automation jobs table (queue)
CREATE TABLE IF NOT EXISTS aegis_automation_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  automation_id UUID NOT NULL REFERENCES aegis_automations(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  scheduled_for TIMESTAMPTZ NOT NULL,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  result_json JSONB,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE aegis_automation_jobs ENABLE ROW LEVEL SECURITY;

-- RLS Policies for aegis_automation_jobs
-- Users can view jobs for organizations they are members of
CREATE POLICY "Users can view aegis automation jobs for their orgs"
  ON aegis_automation_jobs FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only authenticated users can create jobs (typically done by backend/queue system)
CREATE POLICY "Authenticated users can create aegis automation jobs"
  ON aegis_automation_jobs FOR INSERT
  WITH CHECK (auth.uid() IS NOT NULL);

-- Only authenticated users can update jobs (typically done by backend/queue system)
CREATE POLICY "Authenticated users can update aegis automation jobs"
  ON aegis_automation_jobs FOR UPDATE
  USING (auth.uid() IS NOT NULL);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_aegis_automation_jobs_automation_id ON aegis_automation_jobs(automation_id);
CREATE INDEX IF NOT EXISTS idx_aegis_automation_jobs_organization_id ON aegis_automation_jobs(organization_id);
CREATE INDEX IF NOT EXISTS idx_aegis_automation_jobs_status ON aegis_automation_jobs(status);
CREATE INDEX IF NOT EXISTS idx_aegis_automation_jobs_scheduled_for ON aegis_automation_jobs(scheduled_for) WHERE status = 'pending';

