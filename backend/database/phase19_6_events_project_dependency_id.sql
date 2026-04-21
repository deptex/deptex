-- Phase 19.6: project_vulnerability_events.project_dependency_id + per-PD uniqueness
--
-- Phase 19.4 added extraction_run_id + a partial unique index on
-- (project_id, osv_id, event_type, extraction_run_id). That correctly prevents
-- retry-duplicates, but inadvertently collapses the monorepo same-CVE-on-two-PDs
-- case to a single event — e.g. if lodash@4.17.20 is a direct dep and
-- lodash@4.17.21 is pulled in transitively, both vulnerable to CVE-X, both PDVs
-- in the same run would try to write a `detected` event with identical
-- (project_id, osv_id='CVE-X', event_type='detected', extraction_run_id=R)
-- tuples, and the second would ON CONFLICT DO NOTHING. We want one event per
-- affected PD (per Henry, "still two notifications please").
--
-- Fix: add project_dependency_id + swap the partial unique index to include it.
-- Per-(project_id, osv_id, event_type, extraction_run_id, pd_id) uniqueness
-- still blocks retry duplicates (same PD across retries has same pd_id) while
-- allowing distinct PDs under the same CVE to emit their own events.

ALTER TABLE project_vulnerability_events
  ADD COLUMN IF NOT EXISTS project_dependency_id UUID NULL
    REFERENCES project_dependencies(id) ON DELETE SET NULL;

DROP INDEX IF EXISTS idx_pve_unique_per_run;

CREATE UNIQUE INDEX IF NOT EXISTS idx_pve_unique_per_run
  ON project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id)
  WHERE extraction_run_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pve_project_dependency_id
  ON project_vulnerability_events (project_dependency_id)
  WHERE project_dependency_id IS NOT NULL;
