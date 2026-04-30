-- Phase 25c: covering index on organization_reachability_settings.updated_by.
--
-- Surfaced by the Phase 5 criticalreview migration-safety persona as a P3 —
-- every other FK in this schema has a covering index. The table is
-- one-row-per-org so the impact is negligible today, but the convention is
-- consistent indexes on every FK column so a future user-deletion sweep
-- doesn't seq-scan.

CREATE INDEX IF NOT EXISTS idx_org_reach_settings_updated_by
  ON organization_reachability_settings(updated_by);
