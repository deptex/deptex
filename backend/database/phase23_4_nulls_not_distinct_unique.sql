-- Phase 23.4: Single source-aware UNIQUE via NULLS NOT DISTINCT
-- ==========================================================================
-- The phase23 original UNIQUE (on 6 columns, no osv_id/rule_id) collapsed
-- distinct-CVE taint rows at the same sink coords — race-03 from the
-- Phase 3 critical review.
--
-- The fix needs to dedup independently per source while letting atom and
-- taint rows coexist:
--   - two atom rows at same coords                → dedup (atom-vs-atom)
--   - two taint rows same coords + same cve+rule  → dedup (exact dup)
--   - two taint rows same coords + different cve  → coexist
--   - atom row vs taint row at same coords        → coexist
--
-- Attempt 1 (phase23.1 + phase23.3): two partial UNIQUE indexes, one per
-- `reachability_source` value. Correct at the SQL layer, but PostgREST's
-- ON CONFLICT inference requires the partial's WHERE predicate to appear
-- in the INSERT statement — supabase-js's `onConflict` param doesn't
-- expose that. Upserts from the worker would hit the partial and fail to
-- infer, then raise a unique-violation instead of quietly skipping.
--
-- Attempt 2 (this migration): single non-partial UNIQUE keyed on all 8
-- columns, with NULLS NOT DISTINCT (Postgres 15+). Atom rows write
-- (coords, NULL, NULL); NULLS NOT DISTINCT treats two NULLs as equal so
-- atom-vs-atom collides on coords alone. Taint rows write (coords, cve,
-- rule); different cve/rule → distinct keys → coexist. Atom vs taint →
-- different NULL-vs-value → distinct keys → coexist.
--
-- Call-site impact:
--   - reachability.ts parseReachableFlows (atom upsert) must extend its
--     onConflict column list to include osv_id and rule_id so the 8-col
--     UNIQUE is the inferred arbiter.
--   - pipeline.ts reachability_rules step uses the same 8-col onConflict.
--
-- Requires Postgres 15+. Supabase is on Postgres 17 (verified via
-- list_projects), so NULLS NOT DISTINCT is supported.
-- ==========================================================================

DROP INDEX IF EXISTS public.idx_prf_atom_dedup;
DROP INDEX IF EXISTS public.idx_prf_taint_dedup;

ALTER TABLE public.project_reachable_flows
  ADD CONSTRAINT project_reachable_flows_source_dedup_key
  UNIQUE NULLS NOT DISTINCT
    (project_id, extraction_run_id, purl,
     entry_point_file, entry_point_line,
     sink_method, osv_id, rule_id);

COMMENT ON CONSTRAINT project_reachable_flows_source_dedup_key
  ON public.project_reachable_flows IS
  'Phase 23.4: single source-aware UNIQUE using NULLS NOT DISTINCT so atom rows (NULL osv_id/rule_id) dedup on coords alone and taint rows dedup on coords+cve+rule, with atom and taint coexisting at the same sink coords.';
