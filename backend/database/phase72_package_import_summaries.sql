-- =============================================================================
-- Phase 72 — Arc 2 (dependency-source import graphs): per-dist import summaries
-- =============================================================================
-- Cross-org cache of question-relevant imports + question-token hits extracted
-- from a package's PUBLIC registry artifact (wheel-only for pypi — pip never
-- executes a build backend). Written and read only by the depscanner worker's
-- dep-import-graph step (pipeline-steps/dep-import-graph.ts); rows derive
-- solely from public registry artifacts, never from org code, so the cache is
-- safe to share across tenants (the package_capabilities precedent).
--
-- Notes:
--   - One row per (ecosystem, package_name, version). `package_name` is stored
--     PEP-503-normalized (lowercase, runs of -_. collapsed to -) — the same
--     normalization the evaluators use for owner exclusion.
--   - `extractor_version` is NOT in the unique key: an extractor / question-
--     registry change UPSERTs the row in place (no stale-row accumulation, no
--     reaper needed). Readers treat a version mismatch as a cache miss.
--   - `imported_modules` holds only the QUESTION-RELEVANT subset of the dist's
--     imports (prefixes of the models' transitive questions) — v1 is veto-only
--     and only ever asks those memberships; the subset keeps rows small.
--   - Failed / truncated extractions are never written — a partial result must
--     never be served to other orgs (the container_image_scan_cache rule).
--   - `artifact_sha256` is reserved for v2 integrity checks (absence claims);
--     the v1 writer leaves it null.
--   - Defense-in-depth RLS: the table is tenant-global and the worker
--     reads/writes via service role (which bypasses RLS). Without RLS the
--     public schema's default anon/authenticated grants make the PUBLIC anon
--     key a read+WRITE credential — and a poisoned row FORGES a transitive
--     absence proof (an emptied consumer row flips a Django veto false →
--     silences a genuinely-reachable CVE cross-org, breaking the fail-safe
--     doctrine). So we ENABLE RLS + deny-all for non-service roles, exactly
--     like phase27e did for container_image_scan_cache (the package_capabilities
--     precedent this table first copied is ITSELF unremediated).
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.package_import_summaries (
  id                 uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  ecosystem          text NOT NULL,
  package_name       text NOT NULL,                -- PEP-503-normalized
  version            text NOT NULL,
  extractor_version  text NOT NULL,                -- e.g. 'arc2-v1:<registry-hash>'

  imported_modules   jsonb NOT NULL DEFAULT '[]'::jsonb,  -- question-relevant subset only
  question_hits      jsonb NOT NULL DEFAULT '[]'::jsonb,  -- liberal token substring hits
  files_scanned      integer NOT NULL DEFAULT 0,
  artifact_sha256    text,                                 -- reserved (v2 integrity)

  created_at         timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT pis_natural_key UNIQUE (ecosystem, package_name, version),
  CONSTRAINT pis_ecosystem_chk CHECK (ecosystem IN ('npm','pypi','golang','rubygems','composer','cargo')),
  -- Serve-size guard: a summary is a few hundred bytes; anything bigger means
  -- the question registry exploded or the writer regressed — refuse the row.
  CONSTRAINT pis_size_chk CHECK (
    octet_length(imported_modules::text) <= 65536 AND octet_length(question_hits::text) <= 8192
  )
);

CREATE INDEX IF NOT EXISTS idx_pis_lookup
  ON public.package_import_summaries (ecosystem, package_name, version);

-- Defense-in-depth RLS (mirrors phase27e_cache_rls.sql). ENABLE alone already
-- denies non-service roles; the explicit deny-all policies make the intent
-- visible in the schema. The worker's service-role key bypasses RLS, so the
-- read/write path in dep-import-graph.ts is unaffected.
ALTER TABLE public.package_import_summaries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pis_deny_anon_select ON public.package_import_summaries;
CREATE POLICY pis_deny_anon_select ON public.package_import_summaries
  FOR SELECT TO anon, authenticated USING (false);

DROP POLICY IF EXISTS pis_deny_anon_write ON public.package_import_summaries;
CREATE POLICY pis_deny_anon_write ON public.package_import_summaries
  FOR ALL TO anon, authenticated USING (false) WITH CHECK (false);

COMMENT ON TABLE public.package_import_summaries IS
  'Arc 2: per-dist question-relevant import/token summaries from public registry artifacts. Global cache; never contains org-derived data. RLS deny-all for non-service roles (phase27e pattern) — a poisoned row forges a transitive absence proof.';
