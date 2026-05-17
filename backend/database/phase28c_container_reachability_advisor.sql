-- ============================================================================
-- Phase 2 (Reachability Moat) — container reachability + base-image advisor.
--
-- Adds:
--   1. project_base_image_recommendations — one generated recommendation card
--      per Dockerfile per extraction run (base-image upgrade advisor, Item J).
--   2. reachability_level / reachability_details columns on
--      project_container_findings (static OS-package reachability, Item F).
--   3. cleanup_dismissed_base_image_recommendations() reaper RPC.
--
-- Additive only — no destructive operations. Safe to apply on a populated DB.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. project_base_image_recommendations
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.project_base_image_recommendations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  -- extraction_run_id is TEXT (not a FK) — matches project_container_findings;
  -- there is no extraction_runs table to reference.
  extraction_run_id TEXT NOT NULL,
  dockerfile_path TEXT NOT NULL,
  current_image TEXT NOT NULL,
  current_image_digest TEXT,                    -- joins inline finding pointers
  current_image_cve_count INTEGER,
  recommended_image TEXT,                       -- NULL = empty-state row (no catalog match)
  recommended_image_cve_count INTEGER,
  cve_delta INTEGER,                            -- current - recommended; positive = improvement
  alternatives JSONB NOT NULL DEFAULT '[]'::jsonb,  -- top-3 minus picked
  shell_compat_verdict TEXT NOT NULL CHECK (shell_compat_verdict IN
    ('shell_required', 'no_shell_required', 'unknown')),
  shell_compat_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  drop_in_score INTEGER NOT NULL DEFAULT 0
    CHECK (drop_in_score BETWEEN 0 AND 100),
  is_dismissed BOOLEAN NOT NULL DEFAULT FALSE,
  dismissed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  dismissed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT pbir_dockerfile_path_len CHECK (octet_length(dockerfile_path) <= 1024)
);

ALTER TABLE public.project_base_image_recommendations
  DROP CONSTRAINT IF EXISTS pbir_uniq;
ALTER TABLE public.project_base_image_recommendations
  ADD CONSTRAINT pbir_uniq UNIQUE (project_id, extraction_run_id, dockerfile_path);

CREATE INDEX IF NOT EXISTS idx_pbir_project_active
  ON public.project_base_image_recommendations (project_id)
  WHERE is_dismissed = FALSE;

CREATE INDEX IF NOT EXISTS idx_pbir_current_digest
  ON public.project_base_image_recommendations (current_image_digest)
  WHERE current_image_digest IS NOT NULL;

ALTER TABLE public.project_base_image_recommendations ENABLE ROW LEVEL SECURITY;

-- RLS: all access goes through the service-role backend, which filters by
-- organization_id / project_id explicitly. Direct anon/authenticated access denied.
DROP POLICY IF EXISTS "deny anon" ON public.project_base_image_recommendations;
CREATE POLICY "deny anon" ON public.project_base_image_recommendations
  FOR ALL TO anon USING (false);
DROP POLICY IF EXISTS "deny authenticated direct" ON public.project_base_image_recommendations;
CREATE POLICY "deny authenticated direct" ON public.project_base_image_recommendations
  FOR ALL TO authenticated USING (false);

-- Org-scope invariant: organization_id MUST match the project's org. The trigger
-- fires on INSERT and UPDATE — backfills NULL, raises on a mismatch — so a
-- mis-scoped row can never land regardless of what the caller supplies.
CREATE OR REPLACE FUNCTION public.enforce_pbir_org_scope() RETURNS TRIGGER AS $$
DECLARE
  proj_org UUID;
BEGIN
  SELECT organization_id INTO proj_org FROM public.projects WHERE id = NEW.project_id;
  IF proj_org IS NULL THEN
    RAISE EXCEPTION 'project % not found', NEW.project_id;
  END IF;
  IF NEW.organization_id IS NULL THEN
    NEW.organization_id := proj_org;
  ELSIF NEW.organization_id <> proj_org THEN
    RAISE EXCEPTION 'organization_id mismatch: row says %, project says %',
      NEW.organization_id, proj_org;
  END IF;
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS pbir_set_org_id ON public.project_base_image_recommendations;
CREATE TRIGGER pbir_set_org_id
  BEFORE INSERT OR UPDATE ON public.project_base_image_recommendations
  FOR EACH ROW EXECUTE FUNCTION public.enforce_pbir_org_scope();

-- ----------------------------------------------------------------------------
-- 2. Reachability columns on project_container_findings
-- ----------------------------------------------------------------------------
ALTER TABLE public.project_container_findings
  ADD COLUMN IF NOT EXISTS reachability_level TEXT
    CHECK (reachability_level IS NULL OR reachability_level IN ('module', 'unreachable')),
  ADD COLUMN IF NOT EXISTS reachability_details JSONB;

COMMENT ON COLUMN public.project_container_findings.reachability_level IS
  'Phase 2 ships module|unreachable only; widen the CHECK via ALTER when the cross-file taint engine reaches container findings (Phase 3+).';

CREATE INDEX IF NOT EXISTS idx_pcf_reachability
  ON public.project_container_findings (project_id, reachability_level)
  WHERE reachability_level = 'module';

-- ----------------------------------------------------------------------------
-- 3. Reaper RPC for dismissed recommendations (retention default 90 days)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.cleanup_dismissed_base_image_recommendations(
  retention_days INTEGER DEFAULT 90
)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE deleted INTEGER;
BEGIN
  DELETE FROM public.project_base_image_recommendations
  WHERE is_dismissed = TRUE
    AND dismissed_at < NOW() - (retention_days || ' days')::INTERVAL;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.cleanup_dismissed_base_image_recommendations(INTEGER)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cleanup_dismissed_base_image_recommendations(INTEGER)
  TO service_role;
