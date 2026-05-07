-- Phase 6.5 — Indexes split out for online build (msa-4 / G2). CREATE INDEX
-- CONCURRENTLY cannot run inside a transaction; must be its own migration so
-- Supabase MCP doesn't wrap it. project_reachable_flows is a hot write table —
-- a non-CONCURRENT index would pause every running extraction.
--
-- Patch 11: a CONCURRENT build that fails leaves the index in INVALID state.
-- `IF NOT EXISTS` skips by NAME — the INVALID index keeps the name, never
-- gets recreated, and silently never serves queries. Drop both target names
-- first so a re-run after a previous CONCURRENT failure starts clean. DROP
-- INDEX IF EXISTS is fast (catalog-only) when nothing matches.

DROP INDEX IF EXISTS public.idx_org_generated_rules_org_format_enabled;
DROP INDEX IF EXISTS public.idx_prf_project_signature_hash;
DROP INDEX IF EXISTS public.idx_prf_suppressions_org;
DROP INDEX IF EXISTS public.idx_prf_suppressions_suppressed_by;

-- Loader path: filter by org + spec_format + enabled + validation_status.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_org_generated_rules_org_format_enabled
  ON public.organization_generated_rules (organization_id, spec_format, enabled, validation_status)
  WHERE enabled = true;

-- Per-flow suppression lookup path (Option B / OD-4): join from
-- project_reachable_flows.flow_signature_hash → project_reachable_flow_suppressions
-- for classifier + EPD aggregator open-flow filtering. Hash column on the flows
-- table indexed for the join; suppressions table's UNIQUE (project_id, hash) is
-- the canonical lookup index.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_prf_project_signature_hash
  ON public.project_reachable_flows (project_id, flow_signature_hash)
  WHERE flow_signature_hash IS NOT NULL;

-- MSA-P1: suppression FK indexes. auth.users delete cascades a SET NULL on
-- suppressed_by → sequential scan if no covering index. Same concern on
-- organization_id for org-level cleanup queries.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_prf_suppressions_org
  ON public.project_reachable_flow_suppressions (organization_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_prf_suppressions_suppressed_by
  ON public.project_reachable_flow_suppressions (suppressed_by)
  WHERE suppressed_by IS NOT NULL;
