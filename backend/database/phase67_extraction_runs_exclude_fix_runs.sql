-- Exclude Aegis fix-agent runs from the project extraction-runs list.
--
-- The fix-worker (Aegis) writes its progress into extraction_logs (the shared logs
-- table) — a deliberate choice to reuse the same Realtime streaming as extraction —
-- and tags every fix log with metadata.job_type = 'fix' (see fix-worker/src/logger.ts)
-- precisely so consumers can tell fix runs from extraction runs. But
-- get_extraction_runs_for_project listed EVERY distinct run_id with no filter, so fix
-- runs showed up as phantom "extraction" runs in the project's Repository → Recent
-- Activity table (mislabeled "Manual sync / Error", since they have no extraction
-- scan_job). Honor the existing marker: drop any run that has a job_type='fix' log.
CREATE OR REPLACE FUNCTION public.get_extraction_runs_for_project(p_project_id uuid)
 RETURNS TABLE(run_id uuid, started_at timestamp with time zone)
 LANGUAGE sql
 STABLE
AS $function$
  SELECT el.run_id, MIN(el.created_at) AS started_at
  FROM extraction_logs el
  WHERE el.project_id = p_project_id
  GROUP BY el.run_id
  HAVING bool_or(el.metadata->>'job_type' = 'fix') IS NOT TRUE
  ORDER BY started_at DESC
  LIMIT 20;
$function$
;
