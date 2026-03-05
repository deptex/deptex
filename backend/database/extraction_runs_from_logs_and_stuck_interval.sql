-- Extraction runs from logs + increase stuck threshold to 10 minutes
-- 1) RPC: list run_ids that have logs (so UI can show previous attempts after recovery requeue)
-- 2) Recovery: 5 min -> 10 min so dep-scan (long-running) is not marked unresponsive

-- RPC: Get extraction run IDs for a project from logs (distinct run_id with first log time)
CREATE OR REPLACE FUNCTION get_extraction_runs_for_project(p_project_id UUID)
RETURNS TABLE(run_id UUID, started_at TIMESTAMPTZ) AS $$
  SELECT el.run_id, MIN(el.created_at) AS started_at
  FROM extraction_logs el
  WHERE el.project_id = p_project_id
  GROUP BY el.run_id
  ORDER BY started_at DESC
  LIMIT 20;
$$ LANGUAGE sql STABLE;

-- Recover stuck jobs: require 10 minutes without heartbeat (was 5) so dep-scan can run without being requeued
CREATE OR REPLACE FUNCTION recover_stuck_extraction_jobs()
RETURNS SETOF extraction_jobs AS $$
  UPDATE extraction_jobs
  SET status = 'queued',
      machine_id = NULL,
      started_at = NULL,
      heartbeat_at = NULL,
      run_id = gen_random_uuid()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '10 minutes'
    AND attempts < max_attempts
  RETURNING *;
$$ LANGUAGE sql;

-- Fail exhausted: same 10 minute threshold
CREATE OR REPLACE FUNCTION fail_exhausted_extraction_jobs()
RETURNS SETOF extraction_jobs AS $$
  UPDATE extraction_jobs
  SET status = 'failed',
      error = 'Extraction failed after ' || attempts || ' attempts (machine crash or timeout)',
      completed_at = NOW()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '10 minutes'
    AND attempts >= max_attempts
  RETURNING *;
$$ LANGUAGE sql;
