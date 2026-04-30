-- =============================================================================
-- Malicious Packages — soft-fail scan-status column
-- =============================================================================
-- Per the plan's Patch 3, the malicious-scan step computes a status of
-- 'complete', 'partial', or 'failed' instead of hard-failing the whole
-- extraction on isolated package errors. The frontend reads this column to
-- decide whether to render the "scanned with N% coverage gap" banner above
-- the project security tab.
--
-- 'complete' — every package scanned cleanly
-- 'partial'  — 1 ≤ failures < 100%; findings still surfaced but flagged
-- 'failed'   — every package errored (clear infrastructure outage); the
--              extraction job is marked failed by the worker
--
-- NULL is the initial / not-yet-run state for any job that predates this
-- column or skipped malicious-scan entirely.
-- =============================================================================

ALTER TABLE public.scan_jobs
  ADD COLUMN IF NOT EXISTS malicious_scan_status text
  CHECK (malicious_scan_status IS NULL OR malicious_scan_status IN ('complete', 'partial', 'failed'));
