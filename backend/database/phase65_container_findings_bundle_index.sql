-- phase65 — container findings: index the Findings-tab (and bundle) hot query.
--
-- The Findings tab loads the open container findings as
--   WHERE project_id = ? AND extraction_run_id = ? AND status = 'open'
--   ORDER BY depscore DESC NULLS LAST, severity, created_at DESC
--   LIMIT 100
-- plus a count(*) over the same predicate. No existing index covers the sort:
--   idx_pcf_project_run        = (project_id, extraction_run_id)        -- no depscore
--   idx_pcf_org_status_depscore = (organization_id, status, depscore)   -- org-scoped, not project
-- so on a project with thousands of OS-CVE rows Postgres reads + sorts every
-- matching row to find the top 100 (measured ~5s on an ~11k-row project, the
-- single dominant slice of the findings bundle). This partial index matches the
-- predicate + sort order exactly, so the top-100 is an index scan (no full sort)
-- and the count is index-only. status='open' is the default the tab requests, so
-- the partial keeps the index compact (ignored/resolved rows stay out of it).

CREATE INDEX IF NOT EXISTS idx_pcf_project_run_open_depscore
  ON project_container_findings (
    project_id,
    extraction_run_id,
    depscore DESC NULLS LAST,
    severity,
    created_at DESC
  )
  WHERE status = 'open';
