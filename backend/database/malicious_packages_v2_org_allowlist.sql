-- =============================================================================
-- Malicious Packages v2: organization-wide allowlist
-- =============================================================================
-- Pre-approves specific (package, version, ecosystem) tuples so matching
-- malicious findings auto-suppress at scan time with an audit-trail reason
-- pointing to this row. Allowlist matching is performed by the
-- apply_malicious_allowlist() RPC (lands in malicious_packages_v2_rpcs.sql)
-- once the worker has inserted the run's findings.
--
-- Notes:
--   - `version` is exact-string match. Semver-range support deferred to v3.
--   - `version IS NULL` means "all versions of this package".
--   - `added_by` is nullable so user offboarding doesn't break the row;
--     `added_by_email` is frozen at write time as a permanent audit identity.
--   - Soft delete via `revoked_at`/`revoked_by`/`revoked_by_email` so the
--     audit trail outlives the entry's active lifetime.
--   - Allowlist is org-scoped; cache rows like package_capabilities stay
--     global and never reference this table.
--
-- Apply order: requires malicious_packages_v2_ecosystem_widen.sql to have
-- landed first so the CHECK enum below is consistent with v1 tables.
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.organization_malicious_allowlist (
  id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  package_name    text NOT NULL,
  version         text,                       -- null = all versions; specific = exact match
  ecosystem       text NOT NULL,
  reason          text NOT NULL,
  added_by        uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  added_by_email  text NOT NULL,
  added_at        timestamptz NOT NULL DEFAULT now(),
  revoked_at      timestamptz,
  revoked_by      uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  revoked_by_email text,
  CONSTRAINT oma_natural_key UNIQUE NULLS NOT DISTINCT
    (organization_id, package_name, version, ecosystem),
  CONSTRAINT oma_ecosystem_chk CHECK
    (ecosystem IN ('npm','pypi','maven','golang','rubygems','composer','cargo','nuget','github-actions','vscode'))
);

-- Active-only fast path (the most common query: "show me this org's
-- non-revoked allowlist entries").
CREATE INDEX IF NOT EXISTS idx_oma_org_active
  ON public.organization_malicious_allowlist (organization_id)
  WHERE revoked_at IS NULL;

-- Lookup index used by apply_malicious_allowlist() RPC's INNER JOIN —
-- (organization_id, package_name, ecosystem) is the equality scan key,
-- and `revoked_at IS NULL` is the partial-index predicate so revoked
-- entries don't need to be filtered out at runtime.
CREATE INDEX IF NOT EXISTS idx_oma_lookup
  ON public.organization_malicious_allowlist (organization_id, package_name, ecosystem)
  WHERE revoked_at IS NULL;

COMMENT ON TABLE public.organization_malicious_allowlist IS
  'Malicious v2: per-org allowlist of (package, version, ecosystem) tuples that auto-suppress matching findings.';
