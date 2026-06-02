-- Phase 45: degraded scan run state.
--
-- A scan can finalize to 'ready' while a security-critical step produced no /
-- partial signal (dep-scan crashed, SBOM empty because a dependency wouldn't
-- resolve, SAST/secret binary missing in a misbuilt image, malicious scan
-- failed, an IaC sub-scanner failed). Today that renders a misleading green
-- card. These columns record that a run was degraded and why, so the UI can
-- show a "Scan incomplete" badge.
--
-- project_repositories carries the current-run copy the project-list UI reads
-- (finalize overwrites it every run, so a clean re-scan self-clears the badge).
-- scan_jobs carries the per-run record, written THROUGH on each markDegraded
-- call so the reason survives a later hard-fail / cancel that never reaches
-- finalize (the disk-full/OOM crashes this feature exists to surface). It is a
-- permanent per-attempt record, not self-clearing.
--
-- scan_degraded_steps shape: [{ "step": "vuln_scan", "reason": "..." }, ...]

ALTER TABLE public.project_repositories
  ADD COLUMN IF NOT EXISTS scan_degraded boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS scan_degraded_steps jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE public.scan_jobs
  ADD COLUMN IF NOT EXISTS scan_degraded boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS scan_degraded_steps jsonb NOT NULL DEFAULT '[]'::jsonb;
