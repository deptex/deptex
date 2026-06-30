-- phase66b_silence_cross_run_fn.sql
--
-- Workstream M (M2) — cross-run silence false-negative differ (read-only).
--
-- WHY: phase66's silence_events log records, per (run, pdv), the reachability
-- classifier's verdict + its inputs. The north-star metric is the silence
-- score: precision/recall of the auto-silence decision. The worst failure is a
-- silence FALSE-NEGATIVE — a vuln set to `unreachable`/`module` (auto-ignored,
-- depscore ~0) that is actually reachable. The cheapest ground-truth signal is
-- a run-over-run diff: a finding silenced in the prior run that gets PROMOTED
-- (level goes UP) in the current run proves the earlier silence was suspect.
--
-- This is a PURE SELECT — read-only, no writes. The M2 daily cron
-- (POST /api/internal/silence/check-cross-run-drift) calls it once and logs the
-- per-verdict breakdown; nothing here feeds back into reachability/depscore.
--
-- METHOD (mirrors assert_balance_matches_ledger(), which the billing drift cron
-- calls once): for EVERY project with a non-null previous_extraction_run_id,
-- read the two run ids straight off projects (active_extraction_run_id = current,
-- previous_extraction_run_id = prior), then run the canonical differ:
--   * prev = the prior run's SILENCED findings (reachability_level in
--            unreachable|module), bucketed by COALESCE(verdict, level).
--   * cur  = the current run's verdict for every finding.
--   * join on the STABLE cross-run key (project_id, project_dependency_id,
--     osv_id) — pdv_id is NOT stable across runs (PDVs are inserted fresh +
--     reaped each run); a version change forks a new project_dependency row,
--     which correctly excludes "vuln gone because upgraded" from the diff.
--   * keep only promotions (cur rank > prior rank) for upgraded_count.
--   * silence_fn_count = the SILENCE FALSE-NEGATIVE bucket: a finding whose prior
--     tier was SILENCED/auto-ignored (the `prev` CTE = unreachable|module, i.e.
--     rnk <= 1) and whose CURRENT tier is VISIBLE (function|data_flow|confirmed,
--     i.e. rnk >= 2). This is the worst failure: an auto-ignored vuln that is now
--     surfaced as reachable. NB: unreachable->module is NOT an FN (module is still
--     silenced — that's the healthy R1 floor correction), and module->function IS
--     an FN (a silenced vuln became visible). Silenced/visible split per phase48.
--
-- LOCAL MODE: hand-patched into backend/database/schema.sql alongside the
-- phase66 table so PGLite local mode (depscanner CLI + CI smoke tests) is
-- consistent with prod. Do NOT `npm run schema:dump` (it pulls prod drift).

CREATE OR REPLACE FUNCTION public.silence_cross_run_drift()
 RETURNS TABLE(project_id uuid, prior_verdict text, upgraded_count bigint, silence_fn_count bigint, to_levels text[])
 LANGUAGE sql
 STABLE
AS $function$
  WITH lvl(level, rnk) AS (
    VALUES ('unreachable', 0), ('module', 1), ('function', 2), ('data_flow', 3), ('confirmed', 4)
  ),
  runs AS (   -- every project with a prior run to diff against
    SELECT p.id                         AS project_id,
           p.previous_extraction_run_id AS prev_run,
           p.active_extraction_run_id   AS cur_run
    FROM public.projects p
    WHERE p.previous_extraction_run_id IS NOT NULL
      AND p.active_extraction_run_id IS NOT NULL
  ),
  prev AS (   -- the prior run's SILENCED findings (unreachable|module = rnk <= 1)
    SELECT r.project_id,
           se.project_dependency_id,
           se.osv_id,
           COALESCE(se.verdict, se.reachability_level) AS prior_verdict,
           pl.rnk                                      AS prior_rnk
    FROM runs r
    JOIN public.silence_events se
      ON se.project_id = r.project_id
     AND se.extraction_run_id = r.prev_run
    JOIN lvl pl ON pl.level = se.reachability_level
    WHERE se.reachability_level IN ('unreachable', 'module')
  ),
  cur AS (    -- the current run's verdict for every finding
    SELECT r.project_id,
           se.project_dependency_id,
           se.osv_id,
           se.reachability_level AS cur_level,
           cl.rnk                AS cur_rnk
    FROM runs r
    JOIN public.silence_events se
      ON se.project_id = r.project_id
     AND se.extraction_run_id = r.cur_run
    JOIN lvl cl ON cl.level = se.reachability_level
  )
  SELECT
    prev.project_id,
    prev.prior_verdict,
    count(*)                                                      AS upgraded_count,
    -- silence FN = prior tier SILENCED (prev CTE = unreachable|module) AND now
    -- VISIBLE (cur_rnk >= 2: function|data_flow|confirmed). unreachable->module
    -- stays silenced = a healthy R1 floor correction (fn=0); module->function is
    -- a real silence FN (an auto-ignored vuln became visible).
    count(*) FILTER (WHERE cur.cur_rnk >= 2)                      AS silence_fn_count,
    array_agg(DISTINCT cur.cur_level)                             AS to_levels
  FROM prev
  JOIN cur
    ON cur.project_id            = prev.project_id
   AND cur.project_dependency_id = prev.project_dependency_id
   AND cur.osv_id                = prev.osv_id
  WHERE cur.cur_rnk > prev.prior_rnk   -- any upward move from a silenced tier
  GROUP BY prev.project_id, prev.prior_verdict
  ORDER BY prev.project_id, upgraded_count DESC;
$function$
;

COMMENT ON FUNCTION public.silence_cross_run_drift() IS
  'M2 cross-run silence-FN differ (read-only). For every project with a non-null previous_extraction_run_id, diffs the prior run''s silenced findings (unreachable|module) against the current run via the stable (project_id, project_dependency_id, osv_id) key. Returns one row per (project, prior_verdict) bucket of PROMOTED findings: upgraded_count (any upward tier move), silence_fn_count (prior tier SILENCED and current tier VISIBLE = function|data_flow|confirmed, rnk>=2 — the worst failure: an auto-ignored vuln now reachable; unreachable->module is NOT counted, module->function IS), and the set of to-levels. Called daily by POST /api/internal/silence/check-cross-run-drift; log-only, no writes.';
