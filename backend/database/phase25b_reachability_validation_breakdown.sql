-- Phase 5b M3: per-stage validation funnel telemetry for AI rule generation.
--
-- Aggregated across all CVE candidates in a single extraction run. Counts how
-- many candidates passed each successive validation gate (schema → fixture pre
-- match → fixture safe clean → diff-targeted patch pre match → patch post
-- clean). Lets us iterate on the prompt + validation strategy with concrete
-- before/after metrics rather than the binary "any rule validated?" we had
-- before this column.
ALTER TABLE extraction_jobs
  ADD COLUMN IF NOT EXISTS reachability_validation_breakdown JSONB;

COMMENT ON COLUMN extraction_jobs.reachability_validation_breakdown IS
  'Phase 5b: per-stage validation funnel for AI rule generation. Shape: {candidates, schema_pass, fixture_pre_pass, fixture_safe_pass, patch_pre_pass, patch_post_pass}. Null when rule generation never ran for this scan.';
