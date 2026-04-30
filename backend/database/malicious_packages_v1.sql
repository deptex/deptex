-- =============================================================================
-- Malicious Packages v1
-- =============================================================================
-- Adds:
--   1. known_malicious_packages           -- global, ingested from OSV + GHSA
--   2. package_security_cache             -- global, per-(package, version, scanner)
--   3. project_malicious_findings         -- per-project finding records
--   4. malicious_finding_id column on project_security_fixes
--   5. malicious_feed_sync_runs           -- per-source state for watchdog
--   6. RPC recompute_dependency_is_malicious
--   7. RPC insert_malicious_findings_with_recompute (atomic insert + recompute)
-- Also drops legacy dependencies UNIQUE(name) constraint that blocks
-- cross-ecosystem rows (lodash both npm AND pypi).
-- =============================================================================

-- 0. Drop legacy UNIQUE that blocks cross-ecosystem dep rows
ALTER TABLE public.dependencies DROP CONSTRAINT IF EXISTS dependencies_new_name_key;

-- 1. Global feed lookup table
CREATE TABLE IF NOT EXISTS public.known_malicious_packages (
  id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  package_name    text NOT NULL,
  version         text,                       -- null = all versions
  ecosystem       text NOT NULL,              -- canonical lowercase: npm, pypi, maven, golang, rubygems, github-actions, vscode
  source          text NOT NULL,              -- 'osv' | 'ghsa'
  source_id       text NOT NULL,
  severity        text,                       -- critical | high | medium | low | info
  description     text,
  first_seen_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),
  withdrawn_at    timestamptz,                -- non-null = withdrawn / FP
  CONSTRAINT known_malicious_packages_source_id_key UNIQUE (source, source_id),
  CONSTRAINT known_malicious_packages_ecosystem_chk CHECK
    (ecosystem IN ('npm','pypi','maven','golang','rubygems','github-actions','vscode')),
  CONSTRAINT known_malicious_packages_source_chk CHECK
    (source IN ('osv','ghsa'))
);
CREATE INDEX IF NOT EXISTS idx_known_malicious_packages_lookup
  ON public.known_malicious_packages (package_name, ecosystem)
  WHERE withdrawn_at IS NULL;

-- 2. Global per-(package, version, scanner) cache
-- scanner_version stored as plain telemetry column, NOT in UNIQUE -- UPSERT on
-- (package_name, version, ecosystem, scanner) replaces in place on scanner upgrade.
CREATE TABLE IF NOT EXISTS public.package_security_cache (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  package_name        text NOT NULL,
  version             text NOT NULL,
  ecosystem           text NOT NULL,
  scanner             text NOT NULL,                       -- 'guarddog' | 'ai_review'
  scanner_version     text NOT NULL,                       -- e.g. 'guarddog@2.9.0'
  prompt_version      text,                                -- non-null only for scanner='ai_review'
  model_version       text,                                -- non-null only for scanner='ai_review'
  prompt_input_sha256 text,                                -- non-null only for scanner='ai_review' (poisoning trace)
  findings            jsonb NOT NULL DEFAULT '[]'::jsonb,  -- [{rule_id, severity, message, evidence}]
  ai_narrative        text,                                -- non-null only for scanner='ai_review'
  risk_level          text,                                -- critical|high|medium|low|info|none
  scanned_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT package_security_cache_key UNIQUE
    (package_name, version, ecosystem, scanner),
  CONSTRAINT package_security_cache_ecosystem_chk CHECK
    (ecosystem IN ('npm','pypi','maven','golang','rubygems','github-actions','vscode')),
  CONSTRAINT package_security_cache_scanner_chk CHECK
    (scanner IN ('guarddog','ai_review'))
);
CREATE INDEX IF NOT EXISTS idx_package_security_cache_lookup
  ON public.package_security_cache (package_name, version, ecosystem, scanner);

-- NOTE: cache is global by design. If per-org GuardDog rules ever land
-- (e.g., Phase 5 reachability per-org rules pattern extends here), the
-- scanner='guarddog' rows MUST grow an organization_id column added to
-- the UNIQUE -- global cache breaks for org-derived inputs.
-- Cache rows MUST contain no org-derived data: file paths are tarball-rooted,
-- never project-rooted; ai_narrative does not name project or repo URL.

-- 3. Per-project finding records -- mirrors project_dependency_vulnerabilities
CREATE TABLE IF NOT EXISTS public.project_malicious_findings (
  id                    uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id            uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id       uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  extraction_run_id     text NOT NULL,
  project_dependency_id uuid NOT NULL REFERENCES public.project_dependencies(id) ON DELETE CASCADE,
  dependency_id         uuid NOT NULL REFERENCES public.dependencies(id),  -- denorm for recompute RPC
  rule_id               text NOT NULL,
  scanner               text NOT NULL CHECK (scanner IN ('feed','guarddog')),
  severity              text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  message               text,
  depscore              integer,
  suppressed            boolean NOT NULL DEFAULT false,
  suppressed_by         uuid REFERENCES auth.users(id),
  suppressed_at         timestamptz,
  suppressed_reason     text,
  risk_accepted         boolean NOT NULL DEFAULT false,
  risk_accepted_by      uuid REFERENCES auth.users(id),
  risk_accepted_at      timestamptz,
  risk_accepted_reason  text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pmf_dedup UNIQUE NULLS NOT DISTINCT
    (project_id, project_dependency_id, rule_id, scanner, extraction_run_id)
);
CREATE INDEX IF NOT EXISTS idx_pmf_project_run
  ON public.project_malicious_findings (project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_pmf_project_open
  ON public.project_malicious_findings (project_id, suppressed, risk_accepted);
CREATE INDEX IF NOT EXISTS idx_pmf_org
  ON public.project_malicious_findings (organization_id);
CREATE INDEX IF NOT EXISTS idx_pmf_dep
  ON public.project_malicious_findings (dependency_id);

-- Trigger: enforce organization_id consistency with projects.organization_id
CREATE OR REPLACE FUNCTION public.enforce_pmf_org_consistency()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  expected_org uuid;
BEGIN
  SELECT organization_id INTO expected_org FROM public.projects WHERE id = NEW.project_id;
  IF expected_org IS NULL THEN
    RAISE EXCEPTION 'project % does not exist', NEW.project_id;
  END IF;
  IF NEW.organization_id <> expected_org THEN
    RAISE EXCEPTION 'organization_id % does not match project organization_id %',
      NEW.organization_id, expected_org;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS pmf_enforce_org_consistency ON public.project_malicious_findings;
CREATE TRIGGER pmf_enforce_org_consistency
  BEFORE INSERT OR UPDATE OF organization_id, project_id ON public.project_malicious_findings
  FOR EACH ROW EXECUTE FUNCTION public.enforce_pmf_org_consistency();

-- 4. Add malicious_finding_id to fix tracking
ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS malicious_finding_id uuid
    REFERENCES public.project_malicious_findings(id) ON DELETE SET NULL;

-- 5. Per-source state for staleness watchdog
CREATE TABLE IF NOT EXISTS public.malicious_feed_sync_runs (
  id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  source              text NOT NULL,                       -- 'osv' | 'ghsa'
  state               text NOT NULL DEFAULT 'pending',     -- pending | running | completed | failed | dlq
  started_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),  -- heartbeat
  completed_at        timestamptz,
  entries_added       integer DEFAULT 0,
  entries_withdrawn   integer DEFAULT 0,
  error_message       text,
  CONSTRAINT mfsr_state_chk CHECK
    (state IN ('pending','running','completed','failed','dlq')),
  CONSTRAINT mfsr_source_chk CHECK
    (source IN ('osv','ghsa'))
);
CREATE INDEX IF NOT EXISTS idx_mfsr_source_state
  ON public.malicious_feed_sync_runs (source, state, completed_at DESC);

-- 6. Recompute dependencies.is_malicious for affected rows
-- Joins on canonical lowercase ecosystem; feed-sync.ts MUST canonicalize at ingest.
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
        AND k.ecosystem = lower(d.ecosystem)
        AND k.withdrawn_at IS NULL
    )
  )
  WHERE d.id = ANY(p_dependency_ids);
END;
$$;

-- 7. Atomic batch-insert findings + recompute is_malicious
-- Worker calls this once per scan with all findings; RPC handles dedup via UPSERT
-- and recompute in single transaction so partial failures don't leave is_malicious
-- inconsistent with project_malicious_findings.
CREATE OR REPLACE FUNCTION public.insert_malicious_findings_with_recompute(p_findings jsonb)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_inserted integer := 0;
  v_dep_ids uuid[];
BEGIN
  -- Insert findings (idempotent via UNIQUE)
  WITH inserted AS (
    INSERT INTO public.project_malicious_findings (
      project_id, organization_id, extraction_run_id, project_dependency_id,
      dependency_id, rule_id, scanner, severity, message, depscore
    )
    SELECT
      (f->>'project_id')::uuid,
      (f->>'organization_id')::uuid,
      f->>'extraction_run_id',
      (f->>'project_dependency_id')::uuid,
      (f->>'dependency_id')::uuid,
      f->>'rule_id',
      f->>'scanner',
      f->>'severity',
      f->>'message',
      (f->>'depscore')::integer
    FROM jsonb_array_elements(p_findings) AS f
    ON CONFLICT (project_id, project_dependency_id, rule_id, scanner, extraction_run_id)
      DO NOTHING
    RETURNING dependency_id
  )
  SELECT array_agg(DISTINCT dependency_id), count(*)::integer
    INTO v_dep_ids, v_inserted FROM inserted;

  IF v_dep_ids IS NOT NULL AND array_length(v_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_dep_ids);
  END IF;

  RETURN v_inserted;
END;
$$;
