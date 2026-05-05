-- =============================================================================
-- Malicious Packages v2: canonical ecosystem widening (composer/cargo/nuget)
-- =============================================================================
-- The 8-language capability detector lands in v2 covering js/py/java/go/ruby/
-- php/rust/csharp. v1's CHECK enum is scoped to 7 ecosystems
-- (npm/pypi/maven/golang/rubygems/github-actions/vscode); v2 widens to 10 by
-- adding composer (PHP), cargo (Rust), and nuget (C#/.NET) so capability
-- rows for those languages can land without violating the CHECK constraint.
--
-- The v1 ecosystem CHECKs were declared inline (anonymous), so their auto-
-- generated names are environment-dependent — PGLite vs Postgres can choose
-- different names. Use a dynamic `pg_constraint` lookup so DROP isn't a silent
-- no-op when running locally and we don't end up with two stacked CHECKs in
-- production.
--
-- Existing data is unaffected: no row uses the new values yet, and rows
-- using the old 7 values continue to satisfy the wider 10-value CHECK.
--
-- Apply order: this migration MUST land before
-- malicious_packages_v2_org_allowlist.sql and
-- malicious_packages_v2_capabilities.sql, both of which reference the wider
-- canonical set in their own CHECKs.
-- =============================================================================

-- ─── known_malicious_packages.ecosystem ────────────────────────────────────
DO $$
DECLARE
  v_constraint_name text;
BEGIN
  SELECT conname INTO v_constraint_name
  FROM pg_constraint c
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
  WHERE c.conrelid = 'public.known_malicious_packages'::regclass
    AND c.contype = 'c'
    AND a.attname = 'ecosystem'
  LIMIT 1;
  IF v_constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE public.known_malicious_packages DROP CONSTRAINT %I', v_constraint_name);
  END IF;
END $$;

ALTER TABLE public.known_malicious_packages
  ADD CONSTRAINT known_malicious_packages_ecosystem_chk
  CHECK (ecosystem IN ('npm','pypi','maven','golang','rubygems','composer','cargo','nuget','github-actions','vscode'));

-- ─── package_security_cache.ecosystem ──────────────────────────────────────
DO $$
DECLARE
  v_constraint_name text;
BEGIN
  SELECT conname INTO v_constraint_name
  FROM pg_constraint c
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
  WHERE c.conrelid = 'public.package_security_cache'::regclass
    AND c.contype = 'c'
    AND a.attname = 'ecosystem'
  LIMIT 1;
  IF v_constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE public.package_security_cache DROP CONSTRAINT %I', v_constraint_name);
  END IF;
END $$;

ALTER TABLE public.package_security_cache
  ADD CONSTRAINT package_security_cache_ecosystem_chk
  CHECK (ecosystem IN ('npm','pypi','maven','golang','rubygems','composer','cargo','nuget','github-actions','vscode'));

-- ─── canonicalize_malicious_ecosystem(): SQL mirror of ecosystem.ts ────────
-- The recompute_dependency_is_malicious RPC joins via this helper so dep
-- ecosystems like 'gem' / 'pip' / 'go' / 'php' / 'rust' / 'csharp' resolve
-- to the canonical name stored in known_malicious_packages.ecosystem.
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
    WHEN 'composer'         THEN 'composer'
    WHEN 'packagist'        THEN 'composer'
    WHEN 'php'              THEN 'composer'
    WHEN 'cargo'            THEN 'cargo'
    WHEN 'rust'             THEN 'cargo'
    WHEN 'crates.io'        THEN 'cargo'
    WHEN 'nuget'            THEN 'nuget'
    WHEN 'csharp'           THEN 'nuget'
    WHEN 'dotnet'           THEN 'nuget'
    WHEN '.net'             THEN 'nuget'
    WHEN 'github-actions'   THEN 'github-actions'
    WHEN 'github-action'    THEN 'github-actions'
    WHEN 'github actions'   THEN 'github-actions'
    WHEN 'vscode'           THEN 'vscode'
    ELSE NULL
  END;
$$;
