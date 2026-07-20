-- Phase 76: Drop the deprecated Watchtower package-monitoring feature.
--
-- "Watchtower" (upstream package monitoring: watched-package commit polling,
-- anomaly detection, the org watchlist, quarantine, and the per-dependency
-- watch flag) was deprecated long ago. Its standalone workers (watchtower-worker,
-- watchtower-poller) were already removed; the open-source cleanup removes the
-- last remnants. The still-live daily-maintenance cron formerly named
-- "watchtower-daily-poll" was renamed to "dependency-daily-poll" (code only —
-- it never touched these tables).
--
-- Everything dropped here has zero live readers/writers (verified across the
-- backend, depscanner, and fix-worker sources).
--
-- KEPT (still live, despite adjacent names): dependency_prs + projects.auto_bump
-- (auto-bump PRs are now created inline on the ban/bump endpoints),
-- dependency_versions, package_capabilities / package_import_summaries (the
-- malicious-scan feature), banned_versions / team_banned_versions.
--
-- Safe to re-run (IF EXISTS + CASCADE on every drop).

-- Trigger + helper functions (all uncalled) -----------------------------------
DROP TRIGGER IF EXISTS trg_cleanup_orphaned_watchlist ON public.project_watchlist;
DROP FUNCTION IF EXISTS public.cleanup_orphaned_watchlist() CASCADE;
DROP FUNCTION IF EXISTS public.claim_watchtower_job(text) CASCADE;
DROP FUNCTION IF EXISTS public.recover_stuck_watchtower_jobs() CASCADE;
DROP FUNCTION IF EXISTS public.get_watchtower_commits_by_anomaly(uuid, timestamp with time zone, text[], integer, integer) CASCADE;

-- Monitoring tables (CASCADE clears the inter-table FKs + indexes) -------------
DROP TABLE IF EXISTS public.package_anomalies CASCADE;
DROP TABLE IF EXISTS public.package_commit_touched_functions CASCADE;
DROP TABLE IF EXISTS public.package_commits CASCADE;
DROP TABLE IF EXISTS public.package_contributors CASCADE;
DROP TABLE IF EXISTS public.project_watchlist CASCADE;
DROP TABLE IF EXISTS public.organization_watchlist_cleared_commits CASCADE;
DROP TABLE IF EXISTS public.organization_watchlist CASCADE;
DROP TABLE IF EXISTS public.watched_packages CASCADE;
DROP TABLE IF EXISTS public.watchtower_jobs CASCADE;

-- Vestigial columns on the live projects table --------------------------------
ALTER TABLE public.projects DROP COLUMN IF EXISTS watchtower_enabled;
ALTER TABLE public.projects DROP COLUMN IF EXISTS watchtower_enabled_at;
