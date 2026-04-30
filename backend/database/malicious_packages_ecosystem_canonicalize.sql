-- =============================================================================
-- Malicious Packages ecosystem-canonicalization fix
-- =============================================================================
-- Adds an internal SQL helper that mirrors backend/src/lib/malicious/ecosystem.ts
-- so the recompute_dependency_is_malicious RPC joins work when the internal
-- `dependencies.ecosystem` value differs from the canonical name stored in
-- `known_malicious_packages.ecosystem` (notably `gem` -> `rubygems`).
-- =============================================================================

CREATE OR REPLACE FUNCTION public.canonicalize_malicious_ecosystem(raw text)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE lower(coalesce(raw, ''))
    WHEN 'npm'              THEN 'npm'
    WHEN 'pypi'             THEN 'pypi'
    WHEN 'pip'              THEN 'pypi'
    WHEN 'maven'            THEN 'maven'
    WHEN 'golang'           THEN 'golang'
    WHEN 'go'               THEN 'golang'
    WHEN 'rubygems'         THEN 'rubygems'
    WHEN 'gem'              THEN 'rubygems'
    WHEN 'github-actions'   THEN 'github-actions'
    WHEN 'github-action'    THEN 'github-actions'
    WHEN 'github actions'   THEN 'github-actions'
    WHEN 'vscode'           THEN 'vscode'
    ELSE NULL
  END;
$$;

CREATE OR REPLACE FUNCTION public.recompute_dependency_is_malicious(p_dependency_ids uuid[])
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  -- Lock dependency rows to prevent cross-extraction race per FMH-07
  PERFORM 1 FROM public.dependencies WHERE id = ANY(p_dependency_ids) FOR UPDATE;

  UPDATE public.dependencies d
  SET is_malicious = (
    EXISTS (
      SELECT 1 FROM public.project_malicious_findings f
      WHERE f.dependency_id = d.id
        AND f.suppressed = false
        AND f.risk_accepted = false
    )
    OR EXISTS (
      SELECT 1 FROM public.known_malicious_packages k
      WHERE k.package_name = d.name
        AND k.ecosystem = public.canonicalize_malicious_ecosystem(d.ecosystem)
        AND k.withdrawn_at IS NULL
    )
  )
  WHERE d.id = ANY(p_dependency_ids);
END;
$$;
