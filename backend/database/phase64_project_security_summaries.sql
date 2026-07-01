-- phase64: denormalized per-project security summary.
--
-- The org overview reads one indexed row per project from this table instead of
-- re-running the 10-LATERAL security_summary_counts aggregation across 7 finding
-- tables live on every page load. The row is recomputed at scan-finalize and after
-- every finding-state mutation by REUSING security_summary_counts for that one
-- project, so the stored row can never drift from the live computation. A daily
-- self-heal cron (recompute_all_project_summaries with a staleness cutoff) re-syncs
-- any row a hook missed, so the hand-hook set is not load-bearing for correctness.
--
-- No in-migration backfill: a DO-loop over every project inside this DDL transaction
-- is the phase62 statement-timeout class, and a timeout would roll back the CREATE
-- TABLE too. Initial population runs once post-deploy via recompute_all_project_summaries(NULL)
-- (the cron's backfill call); the read path lazily computes any not-yet-populated row.

CREATE TABLE IF NOT EXISTS project_security_summaries (
  project_id               uuid PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  -- organization_id is kept (in scope at recompute time; enables the cron's per-org batching
  -- and a future org-rollup) but intentionally UN-indexed: no query in this PR filters by it
  -- (the read uses the project_id PK). The deferred org-rollup/cache PR adds the index.
  organization_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  active_extraction_run_id text,
  vuln_count               bigint NOT NULL DEFAULT 0,
  critical_count           bigint NOT NULL DEFAULT 0,
  reachable_count          bigint NOT NULL DEFAULT 0,
  worst_depscore           numeric NOT NULL DEFAULT 0,
  band_critical            bigint NOT NULL DEFAULT 0,
  band_high                bigint NOT NULL DEFAULT 0,
  band_medium              bigint NOT NULL DEFAULT 0,
  band_low                 bigint NOT NULL DEFAULT 0,
  ignored_count            bigint NOT NULL DEFAULT 0,
  semgrep_count            bigint NOT NULL DEFAULT 0,
  secret_count             bigint NOT NULL DEFAULT 0,
  verified_secret_count    bigint NOT NULL DEFAULT 0,
  has_container            boolean NOT NULL DEFAULT false,
  has_dast                 boolean NOT NULL DEFAULT false,
  last_scan_at             timestamptz,
  summary_updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Recompute one project's summary by CALLING the live aggregation for that single project.
-- Defensive COALESCE on every numeric column: the table's NOT NULL contract must not depend
-- on security_summary_counts always COALESCE'ing internally (a future RPC edit could return NULL).
CREATE OR REPLACE FUNCTION recompute_project_summary(p_project_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  v_org_id uuid;
  v_run_id text;
BEGIN
  SELECT organization_id, active_extraction_run_id
    INTO v_org_id, v_run_id
    FROM projects WHERE id = p_project_id;
  IF v_org_id IS NULL THEN
    RETURN;  -- project deleted; ON DELETE CASCADE already removed any row
  END IF;

  INSERT INTO project_security_summaries AS pss (
    project_id, organization_id, active_extraction_run_id,
    vuln_count, critical_count, reachable_count, worst_depscore,
    band_critical, band_high, band_medium, band_low, ignored_count,
    semgrep_count, secret_count, verified_secret_count,
    has_container, has_dast, last_scan_at, summary_updated_at
  )
  SELECT
    p_project_id, v_org_id, v_run_id,
    COALESCE(s.vuln_count, 0), COALESCE(s.critical_count, 0), COALESCE(s.reachable_count, 0),
    COALESCE(s.worst_depscore, 0),
    COALESCE(s.band_critical, 0), COALESCE(s.band_high, 0), COALESCE(s.band_medium, 0),
    COALESCE(s.band_low, 0), COALESCE(s.ignored_count, 0),
    COALESCE(s.semgrep_count, 0), COALESCE(s.secret_count, 0), COALESCE(s.verified_secret_count, 0),
    COALESCE(s.has_container, false), COALESCE(s.has_dast, false), s.last_scan_at, now()
  FROM security_summary_counts(
         ARRAY[p_project_id]::uuid[],
         CASE WHEN v_run_id IS NULL THEN ARRAY[]::text[] ELSE ARRAY[v_run_id] END
       ) s
  ON CONFLICT (project_id) DO UPDATE SET
    organization_id          = EXCLUDED.organization_id,
    active_extraction_run_id = EXCLUDED.active_extraction_run_id,
    vuln_count               = EXCLUDED.vuln_count,
    critical_count           = EXCLUDED.critical_count,
    reachable_count          = EXCLUDED.reachable_count,
    worst_depscore           = EXCLUDED.worst_depscore,
    band_critical            = EXCLUDED.band_critical,
    band_high                = EXCLUDED.band_high,
    band_medium              = EXCLUDED.band_medium,
    band_low                 = EXCLUDED.band_low,
    ignored_count            = EXCLUDED.ignored_count,
    semgrep_count            = EXCLUDED.semgrep_count,
    secret_count             = EXCLUDED.secret_count,
    verified_secret_count    = EXCLUDED.verified_secret_count,
    has_container            = EXCLUDED.has_container,
    has_dast                 = EXCLUDED.has_dast,
    last_scan_at             = EXCLUDED.last_scan_at,
    summary_updated_at       = now();
END;
$$;

-- Bulk helper: used by the one-time post-deploy backfill AND the daily self-heal cron.
-- p_stale_before NULL = recompute ALL projects (backfill); a timestamp = only rows whose
-- summary_updated_at is older, plus any project with no row yet (cheap daily reconciliation).
-- Loops one project at a time so each call is a single bounded aggregation.
CREATE OR REPLACE FUNCTION recompute_all_project_summaries(p_stale_before timestamptz DEFAULT NULL)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE r record; n integer := 0;
BEGIN
  FOR r IN
    SELECT p.id
    FROM projects p
    LEFT JOIN project_security_summaries pss ON pss.project_id = p.id
    WHERE p_stale_before IS NULL
       OR pss.project_id IS NULL
       OR pss.summary_updated_at < p_stale_before
  LOOP
    PERFORM recompute_project_summary(r.id);
    n := n + 1;
  END LOOP;
  RETURN n;
END;
$$;
