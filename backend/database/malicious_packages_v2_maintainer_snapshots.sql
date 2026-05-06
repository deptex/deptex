-- =============================================================================
-- Malicious Packages v2: per-package historical maintainer snapshots
-- =============================================================================
-- Drives M1c maintainer-signal detection. Each successful sync run upserts a
-- snapshot keyed by (package, version, ecosystem, observed_at). Diffing the
-- current snapshot against `getLatestSnapshotBefore(now - 30d)` produces the
-- change-class signals (`email_changed_in_last_30d`,
-- `maintainer_changed_in_last_30d`, `signing_setup_changed`,
-- `new_postinstall_added`).
--
-- Cache is global — snapshot fields are pure registry data, never project /
-- org-derived. Retention pruner trims rows older than 90 days (long enough
-- for a 30-day diff plus a 60-day investigation window). When no baseline
-- exists yet (cold start or brand-new package), the registry-pull lib returns
-- `false` for every change signal; first sync run never fires false-positive
-- change alerts.
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.package_maintainer_snapshots (
  id                       uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  package_name             text NOT NULL,
  version                  text NOT NULL,
  ecosystem                text NOT NULL,
  observed_at              timestamptz NOT NULL DEFAULT now(),

  -- Snapshot fields (registry-derived; never project / org-specific).
  maintainer_handles       text[] NOT NULL DEFAULT '{}',           -- ordered usernames / handles
  primary_maintainer_email text,                                    -- npm: maintainer[0].email; PyPI: package owner email
  signing_config_hash      text,                                    -- sha256 of (provenance + signing-keys-fingerprints) JSON
  postinstall_hash         text,                                    -- sha256 of normalized install-script body, or null
  registry_metadata_raw    jsonb,                                   -- diagnostic; pruned at 90d alongside the row

  CONSTRAINT pms_natural_key UNIQUE NULLS NOT DISTINCT
    (package_name, version, ecosystem, observed_at),
  CONSTRAINT pms_ecosystem_chk CHECK
    (ecosystem IN ('npm','pypi','maven','golang','rubygems','composer','cargo','nuget','github-actions','vscode'))
);

-- Lookup pattern: "give me the latest snapshot ≥30d old for (pkg, version, eco)".
-- Composite index on the descending observed_at lets the registry-pull lib pull
-- the baseline with a single index range scan.
CREATE INDEX IF NOT EXISTS idx_pms_lookup
  ON public.package_maintainer_snapshots (package_name, ecosystem, version, observed_at DESC);

COMMENT ON TABLE public.package_maintainer_snapshots IS
  'Malicious v2: per-package historical maintainer state used for M1c change-signal detection. Global cache; never contains org-derived data. 90-day retention.';
