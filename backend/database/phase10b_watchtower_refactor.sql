-- Phase 10B: Watchtower Refactor — Per-Project Activation + Scale-to-Zero

-- 10B.O: Scale-to-zero job table
CREATE TABLE IF NOT EXISTS watchtower_jobs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'processing', 'completed', 'failed')),
  job_type TEXT NOT NULL CHECK (job_type IN ('full_analysis', 'new_version', 'batch_version_analysis', 'poll_sweep')),
  priority INTEGER NOT NULL DEFAULT 10,
  payload JSONB NOT NULL DEFAULT '{}',
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE,
  package_name TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  machine_id TEXT,
  heartbeat_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_watchtower_jobs_status ON watchtower_jobs(status) WHERE status IN ('queued', 'processing');
CREATE INDEX IF NOT EXISTS idx_watchtower_jobs_priority ON watchtower_jobs(priority, created_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_watchtower_jobs_heartbeat ON watchtower_jobs(heartbeat_at) WHERE status = 'processing';

-- Atomic claim: picks highest-priority queued job, locks it
CREATE OR REPLACE FUNCTION claim_watchtower_job(p_machine_id TEXT)
RETURNS SETOF watchtower_jobs AS $$
  UPDATE watchtower_jobs
  SET status = 'processing',
      machine_id = p_machine_id,
      started_at = NOW(),
      heartbeat_at = NOW(),
      attempt = attempt + 1,
      updated_at = NOW()
  WHERE id = (
    SELECT id FROM watchtower_jobs
    WHERE status = 'queued'
    ORDER BY priority ASC, created_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  )
  RETURNING *;
$$ LANGUAGE sql;

-- Recovery: requeue jobs stuck processing (no heartbeat in 5 min)
CREATE OR REPLACE FUNCTION recover_stuck_watchtower_jobs()
RETURNS INTEGER AS $$
DECLARE
  recovered INTEGER;
BEGIN
  UPDATE watchtower_jobs
  SET status = 'queued',
      machine_id = NULL,
      started_at = NULL,
      heartbeat_at = NULL,
      updated_at = NOW()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempt < max_attempts;
  GET DIAGNOSTICS recovered = ROW_COUNT;

  UPDATE watchtower_jobs
  SET status = 'failed',
      error_message = 'Exhausted max attempts',
      completed_at = NOW(),
      updated_at = NOW()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempt >= max_attempts;

  RETURN recovered;
END;
$$ LANGUAGE plpgsql;

-- 10B.C: Per-project activation columns
ALTER TABLE projects ADD COLUMN IF NOT EXISTS watchtower_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS watchtower_enabled_at TIMESTAMPTZ;

-- Junction table tracking which projects contributed which packages to the org watchlist
CREATE TABLE IF NOT EXISTS project_watchlist (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_watchlist_id UUID NOT NULL REFERENCES organization_watchlist(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, organization_watchlist_id)
);

CREATE INDEX IF NOT EXISTS idx_project_watchlist_project ON project_watchlist(project_id);
CREATE INDEX IF NOT EXISTS idx_project_watchlist_watchlist ON project_watchlist(organization_watchlist_id);

-- Automatically clean up orphaned organization_watchlist entries
CREATE OR REPLACE FUNCTION cleanup_orphaned_watchlist()
RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM organization_watchlist
  WHERE id = OLD.organization_watchlist_id
  AND NOT EXISTS (
    SELECT 1 FROM project_watchlist
    WHERE organization_watchlist_id = OLD.organization_watchlist_id
    AND id != OLD.id
  );
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cleanup_orphaned_watchlist ON project_watchlist;
CREATE TRIGGER trg_cleanup_orphaned_watchlist
AFTER DELETE ON project_watchlist
FOR EACH ROW EXECUTE FUNCTION cleanup_orphaned_watchlist();
