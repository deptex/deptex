-- Phase 46 — capture source / sink code snippets on reachable flows.
--
-- The taint engine knows each flow's source (entry_point_file:line) and the
-- dangerous call it reaches (sink_file:line), but only stored the path + line +
-- symbol — so the vulnerability detail view could never show the actual code.
-- We now read a small window of lines off the clone at scan time (in
-- writeFlows) and persist it here, so the UI renders the real source/sink lines
-- without a live repo fetch (and the line numbers match the scanned commit).
--
-- Both columns are nullable: rows written before this migration stay NULL and
-- the UI falls back to the path/symbol-only view; a re-scan backfills them.

ALTER TABLE public.project_reachable_flows
  ADD COLUMN IF NOT EXISTS entry_point_code text,
  ADD COLUMN IF NOT EXISTS sink_code text;
