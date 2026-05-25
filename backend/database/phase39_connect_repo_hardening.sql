-- Connect-repo hardening
--
-- 1. Denormalize organization_id onto project_repositories so the
--    "repo already linked" dedup check can be scoped per-org instead of
--    globally. Today two different orgs can never connect the same public
--    repo because the global UNIQUE on (repo_full_name, package_json_path)
--    rejects the second attempt and leaks the existence of the first.
-- 2. Forward-compat trigger fills organization_id from projects.organization_id
--    for any INSERT that doesn't supply it, so the old two-step create+connect
--    code path keeps working between migration apply and backend deploy.
-- 3. Drop the global UNIQUE; replace with an org-scoped UNIQUE.
-- 4. Add a partial UNIQUE on scan_jobs(project_id, type) WHERE status IN
--    ('queued', 'processing') so a double-submit can't race two extraction
--    jobs into the queue for the same project at the same time.

BEGIN;

ALTER TABLE public.project_repositories
  ADD COLUMN IF NOT EXISTS organization_id uuid;

UPDATE public.project_repositories pr
SET organization_id = p.organization_id
FROM public.projects p
WHERE pr.project_id = p.id
  AND pr.organization_id IS NULL;

CREATE OR REPLACE FUNCTION public.fill_project_repositories_organization_id()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.organization_id IS NULL AND NEW.project_id IS NOT NULL THEN
    SELECT organization_id INTO NEW.organization_id
    FROM public.projects WHERE id = NEW.project_id;
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_project_repositories_fill_organization_id
  ON public.project_repositories;
CREATE TRIGGER trg_project_repositories_fill_organization_id
  BEFORE INSERT OR UPDATE ON public.project_repositories
  FOR EACH ROW
  EXECUTE FUNCTION public.fill_project_repositories_organization_id();

ALTER TABLE public.project_repositories
  DROP CONSTRAINT IF EXISTS project_repositories_organization_id_fkey;
ALTER TABLE public.project_repositories
  ADD CONSTRAINT project_repositories_organization_id_fkey
  FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

DROP INDEX IF EXISTS public.idx_project_repositories_repo_full_name_package_json_path;

CREATE UNIQUE INDEX IF NOT EXISTS idx_project_repositories_org_repo_path
  ON public.project_repositories (organization_id, repo_full_name, package_json_path);

CREATE INDEX IF NOT EXISTS idx_project_repositories_organization_id
  ON public.project_repositories (organization_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_one_active_per_project_type
  ON public.scan_jobs (project_id, type)
  WHERE status IN ('queued', 'processing');

COMMIT;
