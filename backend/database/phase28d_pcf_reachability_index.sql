-- ============================================================================
-- Phase 2 (Reachability Moat) — online build of the reachability index.
--
-- Split out of phase28c: CREATE INDEX CONCURRENTLY cannot run inside a
-- transaction, and project_container_findings is a hot write table that the
-- depscanner worker upserts container findings into continuously. A
-- non-CONCURRENT build takes a SHARE lock that blocks every running container
-- scan for the duration of the build. This must therefore be its own
-- migration so the migration runner does not wrap it in a transaction.
-- (Same rationale as phase27b_cve_targeted_taint_indexes.sql.)
--
-- A CONCURRENT build that fails leaves an INVALID index that keeps the name;
-- `CREATE INDEX CONCURRENTLY IF NOT EXISTS` would then skip by name and never
-- rebuild it. DROP IF EXISTS first so a re-run after a failed build starts
-- clean. DROP INDEX IF EXISTS is catalog-only and fast when nothing matches.
-- ============================================================================

DROP INDEX IF EXISTS public.idx_pcf_reachability;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pcf_reachability
  ON public.project_container_findings (project_id, reachability_level)
  WHERE reachability_level = 'module';
