-- Phase 35 (v1.1): DAST OpenAPI / spec-driven scanning.
--
-- Additive only. v1.1 ships `synthesized`, `url`, `none` modes.
-- File-upload mode (`'upload'`) is NOT reserved here per Round 2 plan
-- review feedback; v1.2 will add its own migration with whatever shape
-- upload actually needs.
--
-- Existing targets are backfilled to `api_spec_source='none'` so deploy
-- doesn't silently flip every customer's scan shape on the next scan.
-- New targets created post-deploy default to `'synthesized'` per the
-- column DEFAULT.

BEGIN;

ALTER TABLE public.project_dast_targets
  ADD COLUMN IF NOT EXISTS api_spec_source TEXT NOT NULL DEFAULT 'synthesized',
  ADD COLUMN IF NOT EXISTS api_spec_url TEXT,
  ADD COLUMN IF NOT EXISTS last_synthesized_spec_path TEXT,
  ADD COLUMN IF NOT EXISTS last_synthesized_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_synthesis_endpoint_count INTEGER,
  ADD COLUMN IF NOT EXISTS last_synthesis_ok BOOLEAN;

-- Enum check (3 values). 'upload' is deferred to v1.2's own migration.
ALTER TABLE public.project_dast_targets
  ADD CONSTRAINT project_dast_targets_api_spec_source_check
  CHECK (api_spec_source IN ('synthesized', 'url', 'none'));

-- url source requires api_spec_url to be set. Enforced route-side too;
-- CHECK is defense-in-depth against direct SQL edits.
ALTER TABLE public.project_dast_targets
  ADD CONSTRAINT project_dast_targets_api_spec_url_required
  CHECK (
    api_spec_source <> 'url'
    OR (api_spec_url IS NOT NULL AND length(api_spec_url) > 0)
  );

-- Preserve existing behavior: existing targets stay on 'none' so they
-- don't silently change scan shape on next scan after deploy. The
-- DEFAULT applies to new rows only.
UPDATE public.project_dast_targets
   SET api_spec_source = 'none'
   WHERE api_spec_source = 'synthesized';

COMMIT;
