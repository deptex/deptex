-- Persist the taint engine's vuln_class on each reachable flow.
--
-- The propagator already computes a `vuln_class` (sql_injection / xss / ssrf /
-- …) for every flow from the matched FrameworkSink, but writeFlows dropped it
-- on the way to the database. First-party taint flows (reachability_source =
-- 'taint_engine' AND osv_id IS NULL) are a source→sink path in the user's OWN
-- code — there is no CVE to borrow a title or severity from, so the vuln_class
-- is what makes the finding self-describing. Surfacing those flows as their own
-- finding type (the "Data-flow findings" surface) needs this column.
--
-- Plain nullable text rather than a CHECK-constrained enum: the VulnClass set
-- is extended over time (phase28b added code_injection, phase28c weak_crypto /
-- auth_bypass) and a CHECK here would have to be migrated in lockstep with the
-- worker's TypeScript union for no real safety gain — the writer is the only
-- producer. Existing rows stay NULL until their project is re-scanned; readers
-- fall back to a generic label when it is absent.

ALTER TABLE public.project_reachable_flows
  ADD COLUMN IF NOT EXISTS vuln_class text;

COMMENT ON COLUMN public.project_reachable_flows.vuln_class IS
  'Taint-engine vulnerability class (matches depscanner VulnClass: sql_injection, xss, ssrf, path_traversal, command_injection, prototype_pollution, deserialization, redos, file_upload, open_redirect, log_injection, code_injection, weak_crypto, auth_bypass). Drives the title + severity of first-party (osv_id IS NULL) data-flow findings. NULL for rows written before this column existed.';

-- Index the first-party-flow lookup the findings surface runs per project/run.
-- Partial on the exact predicate so it stays tiny (most flows are CVE-attributed).
CREATE INDEX IF NOT EXISTS idx_prf_first_party
  ON public.project_reachable_flows (project_id, extraction_run_id)
  WHERE osv_id IS NULL AND reachability_source = 'taint_engine';
