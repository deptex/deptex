-- Phase 2A: extraction_jobs table — Supabase-based job persistence for Fly.io extraction workers
-- Replaces Redis queue for extraction jobs. Jobs survive machine crashes.

CREATE TABLE IF NOT EXISTS extraction_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'processing', 'completed', 'failed', 'cancelled')),
  run_id UUID NOT NULL DEFAULT gen_random_uuid(),
  machine_id TEXT,
  payload JSONB NOT NULL DEFAULT '{}',
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  error TEXT,
  started_at TIMESTAMPTZ,
  heartbeat_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_extraction_jobs_status_created ON extraction_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_extraction_jobs_project ON extraction_jobs(project_id);
CREATE INDEX IF NOT EXISTS idx_extraction_jobs_org ON extraction_jobs(organization_id);

-- RLS
ALTER TABLE extraction_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access" ON extraction_jobs
  FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Org members can read own jobs" ON extraction_jobs
  FOR SELECT USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

-- RPC: Atomic job claim (FOR UPDATE SKIP LOCKED prevents double-claim)
CREATE OR REPLACE FUNCTION claim_extraction_job(p_machine_id TEXT)
RETURNS SETOF extraction_jobs AS $$
  UPDATE extraction_jobs
  SET status = 'processing',
      started_at = NOW(),
      heartbeat_at = NOW(),
      machine_id = p_machine_id,
      attempts = attempts + 1
  WHERE id = (
    SELECT id FROM extraction_jobs
    WHERE status = 'queued'
    ORDER BY created_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED
  )
  RETURNING *;
$$ LANGUAGE sql;

-- RPC: Recover stuck jobs (processing with stale heartbeat, under max attempts)
CREATE OR REPLACE FUNCTION recover_stuck_extraction_jobs()
RETURNS SETOF extraction_jobs AS $$
  UPDATE extraction_jobs
  SET status = 'queued',
      machine_id = NULL,
      started_at = NULL,
      heartbeat_at = NULL,
      run_id = gen_random_uuid()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts < max_attempts
  RETURNING *;
$$ LANGUAGE sql;

-- RPC: Fail exhausted jobs (exceeded max attempts)
CREATE OR REPLACE FUNCTION fail_exhausted_extraction_jobs()
RETURNS SETOF extraction_jobs AS $$
  UPDATE extraction_jobs
  SET status = 'failed',
      error = 'Extraction failed after ' || attempts || ' attempts (machine crash or timeout)',
      completed_at = NOW()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts >= max_attempts
  RETURNING *;
$$ LANGUAGE sql;
