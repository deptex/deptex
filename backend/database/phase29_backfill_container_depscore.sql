-- ============================================================================
-- phase29_backfill_container_depscore.sql
--
-- One-time backfill for the Phase 2 close-out (worktree-iac-container-v2-
-- phase2-closeout): container findings written before depscanner/storage.ts's
-- containerDepscore() landed kept their severity-only depscore even when the
-- reachability classifier had already decided they were unreachable. The
-- security tab sorts container findings purely by `depscore`, so without
-- this UPDATE a fresh project's unreachable HIGH (28) sorts below a stale
-- project's unreachable HIGH (70) — Success Criterion 1 fails until every
-- project re-scans.
--
-- Idempotent by construction: the predicate restricts the UPDATE to rows
-- still carrying the severity-baseline value. Rows that have already been
-- downweighted (or freshly written by the post-PR worker) are skipped, so
-- re-running this migration is a no-op. The CASE table here MUST match
-- severityToDepscore() in depscanner/src/scanners/storage.ts; the multiplier
-- 0.4 MUST match CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER in the same file.
-- ============================================================================

UPDATE public.project_container_findings
   SET depscore = ROUND(depscore * 0.4)
 WHERE reachability_level = 'unreachable'
   AND depscore IS NOT NULL
   AND depscore = CASE severity
                    WHEN 'CRITICAL' THEN 90
                    WHEN 'HIGH'     THEN 70
                    WHEN 'MEDIUM'   THEN 50
                    WHEN 'LOW'      THEN 30
                    WHEN 'INFO'     THEN 10
                  END;
