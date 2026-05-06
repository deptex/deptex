-- =============================================================================
-- Malicious Packages v2: per-package capability tags
-- =============================================================================
-- Stores deterministic capability flags computed by the worker's tree-sitter
-- pass. Cache is global across all orgs/projects — file paths inside any
-- diagnostic detail are tarball-rooted, never project-rooted, so this row is
-- safe to share across tenants.
--
-- Notes:
--   - One row per (package, version, ecosystem). UPSERT on scanner upgrade
--     replaces in place; `scanner_version` is NOT in the unique key so we
--     don't accumulate stale rows when capability detectors evolve.
--   - `scan_error` non-null means the tree-sitter pass failed for this
--     package; capabilities all default false, scanner consumers render an
--     "unavailable" empty state.
--   - Boolean columns (vs JSONB) so future policy-composition queries can
--     index by capability — e.g. `WHERE eval_dynamic = true OR network_io = true`.
--
-- Apply order: requires malicious_packages_v2_ecosystem_widen.sql to have
-- landed first so the CHECK enum below is consistent with v1 tables.
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.package_capabilities (
  id                       uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  package_name             text NOT NULL,
  version                  text NOT NULL,
  ecosystem                text NOT NULL,
  scanner_version          text NOT NULL,                       -- e.g. 'capability@v2.0.0'

  -- Capability tags (Socket-style; 15 deterministic detectors locked in v2).
  -- Order grouped by signal weight; UI palette derives from the same grouping.
  spawns_processes         boolean NOT NULL DEFAULT false,
  network_io               boolean NOT NULL DEFAULT false,
  eval_dynamic             boolean NOT NULL DEFAULT false,
  native_addon_load        boolean NOT NULL DEFAULT false,
  filesystem_write         boolean NOT NULL DEFAULT false,
  crypto_operations        boolean NOT NULL DEFAULT false,
  serialization_deser      boolean NOT NULL DEFAULT false,
  install_script           boolean NOT NULL DEFAULT false,
  dns_query                boolean NOT NULL DEFAULT false,
  websocket                boolean NOT NULL DEFAULT false,
  process_signal           boolean NOT NULL DEFAULT false,
  encrypted_payload        boolean NOT NULL DEFAULT false,
  dynamic_import           boolean NOT NULL DEFAULT false,
  reads_env                boolean NOT NULL DEFAULT false,
  clipboard_access         boolean NOT NULL DEFAULT false,

  scanned_at               timestamptz NOT NULL DEFAULT now(),
  scan_error               text,                                 -- non-null = tree-sitter scan failed; capabilities all-false

  CONSTRAINT pc_natural_key UNIQUE (package_name, version, ecosystem),
  CONSTRAINT pc_ecosystem_chk CHECK
    (ecosystem IN ('npm','pypi','maven','golang','rubygems','composer','cargo','nuget','github-actions','vscode'))
);

CREATE INDEX IF NOT EXISTS idx_pc_lookup
  ON public.package_capabilities (package_name, version, ecosystem);

-- Composite index for future policy-composition queries — "any package with
-- a high-signal capability set". Cheap because the partial WHERE narrows to
-- the few-percent of packages that actually trip these flags.
CREATE INDEX IF NOT EXISTS idx_pc_high_signal
  ON public.package_capabilities (package_name, ecosystem)
  WHERE eval_dynamic = true OR network_io = true OR spawns_processes = true;

COMMENT ON TABLE public.package_capabilities IS
  'Malicious v2: per-package capability tags from tree-sitter pass. Global cache; never contains org-derived data.';
