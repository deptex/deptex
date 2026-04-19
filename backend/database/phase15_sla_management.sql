-- Phase 15: Security SLA Management
-- Prerequisites: organization_asset_tiers, project_vulnerability_events, project_dependency_vulnerabilities
-- Creates: organization_sla_policies, sla_policy_changes, PDV SLA columns, org pause column, RPCs, backfill

-- =============================================================================
-- 1. Organization SLA policies (per-severity, optional per-asset-tier override)
-- =============================================================================
CREATE TABLE IF NOT EXISTS organization_sla_policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  asset_tier_id UUID REFERENCES organization_asset_tiers(id) ON DELETE CASCADE,
  max_hours INTEGER NOT NULL CHECK (max_hours > 0),
  warning_threshold_percent INTEGER DEFAULT 75 CHECK (warning_threshold_percent BETWEEN 1 AND 99),
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT uq_sla_policies_org_severity_tier UNIQUE NULLS NOT DISTINCT (organization_id, severity, asset_tier_id)
);

CREATE INDEX IF NOT EXISTS idx_sla_policies_org ON organization_sla_policies(organization_id);
CREATE INDEX IF NOT EXISTS idx_sla_policies_asset_tier ON organization_sla_policies(asset_tier_id) WHERE asset_tier_id IS NOT NULL;

COMMENT ON TABLE organization_sla_policies IS 'Per-severity remediation SLA thresholds. asset_tier_id NULL = org default; tier-specific rows override for projects in that tier.';

-- =============================================================================
-- 2. SLA policy change audit trail
-- =============================================================================
CREATE TABLE IF NOT EXISTS sla_policy_changes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  changed_by UUID NOT NULL,
  change_type TEXT NOT NULL,
  previous_values JSONB,
  new_values JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sla_policy_changes_org ON sla_policy_changes(organization_id);
CREATE INDEX IF NOT EXISTS idx_sla_policy_changes_created ON sla_policy_changes(created_at DESC);

COMMENT ON COLUMN sla_policy_changes.change_type IS 'created, updated, disabled, enabled, paused, resumed';

-- =============================================================================
-- 3. project_dependency_vulnerabilities: SLA tracking columns
-- =============================================================================
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_deadline_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_warning_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_status TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS sla_breached_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_met_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_exempt_reason TEXT,
  ADD COLUMN IF NOT EXISTS sla_warning_notified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS sla_breach_notified_at TIMESTAMPTZ;

ALTER TABLE project_dependency_vulnerabilities
  DROP CONSTRAINT IF EXISTS chk_pdv_sla_status;

ALTER TABLE project_dependency_vulnerabilities
  ADD CONSTRAINT chk_pdv_sla_status CHECK (
    sla_status IS NULL OR sla_status IN ('on_track', 'warning', 'breached', 'met', 'resolved_late', 'exempt')
  );

CREATE INDEX IF NOT EXISTS idx_pdv_sla_deadline ON project_dependency_vulnerabilities(sla_deadline_at)
  WHERE sla_status IN ('on_track', 'warning');
CREATE INDEX IF NOT EXISTS idx_pdv_sla_status ON project_dependency_vulnerabilities(sla_status)
  WHERE sla_status IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pdv_sla_warning_at ON project_dependency_vulnerabilities(sla_warning_at)
  WHERE sla_status = 'on_track' AND sla_warning_at IS NOT NULL;

COMMENT ON COLUMN project_dependency_vulnerabilities.detected_at IS 'When this vuln was first detected (from project_vulnerability_events or created_at fallback).';
COMMENT ON COLUMN project_dependency_vulnerabilities.sla_warning_at IS 'Pre-computed: when to transition to warning (detected_at + max_hours * warning_threshold_percent/100).';
COMMENT ON COLUMN project_dependency_vulnerabilities.sla_status IS 'on_track | warning | breached | met | resolved_late | exempt. NULL = SLAs not configured.';

-- =============================================================================
-- 4. organizations: SLA pause
-- =============================================================================
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS sla_paused_at TIMESTAMPTZ;

COMMENT ON COLUMN organizations.sla_paused_at IS 'When SLA timers were paused (NULL = not paused). On resume, open vuln deadlines are shifted by pause duration.';

-- =============================================================================
-- 5. RPC: Get vulns approaching warning (for cron)
-- =============================================================================
CREATE OR REPLACE FUNCTION get_sla_approaching_warning(p_batch_limit INTEGER DEFAULT 200)
RETURNS TABLE(
  id UUID,
  project_id UUID,
  organization_id UUID,
  osv_id TEXT,
  severity TEXT,
  sla_deadline_at TIMESTAMPTZ,
  hours_remaining NUMERIC
) AS $$
  SELECT pdv.id, pdv.project_id, p.organization_id, pdv.osv_id, pdv.severity,
         pdv.sla_deadline_at,
         EXTRACT(EPOCH FROM (pdv.sla_deadline_at - NOW())) / 3600 AS hours_remaining
  FROM project_dependency_vulnerabilities pdv
  JOIN projects p ON p.id = pdv.project_id
  JOIN organizations o ON o.id = p.organization_id
  WHERE pdv.sla_status = 'on_track'
    AND pdv.sla_deadline_at IS NOT NULL
    AND pdv.sla_warning_at IS NOT NULL
    AND pdv.sla_warning_notified_at IS NULL
    AND o.sla_paused_at IS NULL
    AND NOW() >= pdv.sla_warning_at
    AND NOW() < pdv.sla_deadline_at
  ORDER BY pdv.sla_deadline_at ASC
  LIMIT p_batch_limit;
$$ LANGUAGE sql STABLE;

-- =============================================================================
-- 6. RPC: Get vulns newly breached (for cron)
-- =============================================================================
CREATE OR REPLACE FUNCTION get_sla_newly_breached(p_batch_limit INTEGER DEFAULT 200)
RETURNS TABLE(
  id UUID,
  project_id UUID,
  organization_id UUID,
  osv_id TEXT,
  severity TEXT,
  sla_deadline_at TIMESTAMPTZ,
  hours_overdue NUMERIC
) AS $$
  SELECT pdv.id, pdv.project_id, p.organization_id, pdv.osv_id, pdv.severity,
         pdv.sla_deadline_at,
         EXTRACT(EPOCH FROM (NOW() - pdv.sla_deadline_at)) / 3600 AS hours_overdue
  FROM project_dependency_vulnerabilities pdv
  JOIN projects p ON p.id = pdv.project_id
  JOIN organizations o ON o.id = p.organization_id
  WHERE pdv.sla_status IN ('on_track', 'warning')
    AND pdv.sla_deadline_at IS NOT NULL
    AND pdv.sla_breach_notified_at IS NULL
    AND o.sla_paused_at IS NULL
    AND NOW() > pdv.sla_deadline_at
  ORDER BY pdv.sla_deadline_at ASC
  LIMIT p_batch_limit;
$$ LANGUAGE sql STABLE;

-- =============================================================================
-- 7. Backfill: Resolve effective SLA policy for (org, severity, asset_tier_id)
--    Returns max_hours and warning_threshold_percent. Tier-specific overrides org default.
-- =============================================================================
CREATE OR REPLACE FUNCTION get_effective_sla_policy(
  p_organization_id UUID,
  p_severity TEXT,
  p_asset_tier_id UUID
)
RETURNS TABLE(max_hours INTEGER, warning_threshold_percent INTEGER) AS $$
  SELECT osp.max_hours, osp.warning_threshold_percent
  FROM organization_sla_policies osp
  WHERE osp.organization_id = p_organization_id
    AND osp.severity = p_severity
    AND osp.enabled = true
    AND (
      (p_asset_tier_id IS NOT NULL AND osp.asset_tier_id = p_asset_tier_id)
      OR (osp.asset_tier_id IS NULL AND NOT EXISTS (
        SELECT 1 FROM organization_sla_policies osp2
        WHERE osp2.organization_id = p_organization_id
          AND osp2.severity = p_severity
          AND osp2.asset_tier_id = p_asset_tier_id
          AND osp2.enabled = true
      ))
    )
  ORDER BY osp.asset_tier_id IS NULL ASC
  LIMIT 1;
$$ LANGUAGE sql STABLE;

-- =============================================================================
-- 8. Backfill existing open vulns when org first enables SLAs (call from app)
--    Run after seeding default organization_sla_policies for the org.
--    Sets detected_at from project_vulnerability_events (detected) or created_at,
--    then computes sla_deadline_at and sla_warning_at from effective policy.
-- =============================================================================
CREATE OR REPLACE FUNCTION backfill_sla_for_organization(p_organization_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_updated INTEGER := 0;
  v_row RECORD;
  v_detected_at TIMESTAMPTZ;
  v_max_hours INTEGER;
  v_warning_pct INTEGER;
BEGIN
  FOR v_row IN
    SELECT pdv.id, pdv.project_id, pdv.osv_id, pdv.severity, pdv.created_at, p.asset_tier_id
    FROM project_dependency_vulnerabilities pdv
    JOIN projects p ON p.id = pdv.project_id
    WHERE p.organization_id = p_organization_id
      AND (pdv.suppressed = false OR pdv.suppressed IS NULL)
      AND (pdv.risk_accepted = false OR pdv.risk_accepted IS NULL)
      AND pdv.sla_status IS NULL
      AND pdv.severity IN ('critical', 'high', 'medium', 'low')
  LOOP
    -- Resolve detected_at: first 'detected' event for this (project_id, osv_id) or created_at
    SELECT MIN(pve.created_at) INTO v_detected_at
    FROM project_vulnerability_events pve
    WHERE pve.project_id = v_row.project_id
      AND pve.osv_id = v_row.osv_id
      AND pve.event_type = 'detected';

    IF v_detected_at IS NULL THEN
      v_detected_at := v_row.created_at;
    END IF;

    -- Get effective policy
    SELECT f.max_hours, f.warning_threshold_percent INTO v_max_hours, v_warning_pct
    FROM get_effective_sla_policy(p_organization_id, v_row.severity, v_row.asset_tier_id) f;

    IF v_max_hours IS NULL THEN
      CONTINUE;
    END IF;

    UPDATE project_dependency_vulnerabilities
    SET
      detected_at = v_detected_at,
      sla_deadline_at = v_detected_at + (v_max_hours || ' hours')::INTERVAL,
      sla_warning_at = v_detected_at + (v_max_hours * COALESCE(v_warning_pct, 75) / 100.0 || ' hours')::INTERVAL,
      sla_status = CASE
        WHEN NOW() > v_detected_at + (v_max_hours || ' hours')::INTERVAL THEN 'breached'
        WHEN NOW() >= v_detected_at + (v_max_hours * COALESCE(v_warning_pct, 75) / 100.0 || ' hours')::INTERVAL THEN 'warning'
        ELSE 'on_track'
      END,
      sla_breached_at = CASE
        WHEN NOW() > v_detected_at + (v_max_hours || ' hours')::INTERVAL THEN v_detected_at + (v_max_hours || ' hours')::INTERVAL
        ELSE NULL
      END
    WHERE project_dependency_vulnerabilities.id = v_row.id;

    v_updated := v_updated + 1;
  END LOOP;

  RETURN v_updated;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 9. Resume: shift open vuln deadlines by pause duration (call from app)
-- =============================================================================
CREATE OR REPLACE FUNCTION resume_sla_shift_deadlines(
  p_organization_id UUID,
  p_pause_duration_seconds INTEGER
)
RETURNS INTEGER AS $$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE project_dependency_vulnerabilities pdv
  SET
    sla_deadline_at = pdv.sla_deadline_at + (p_pause_duration_seconds || ' seconds')::INTERVAL,
    sla_warning_at = pdv.sla_warning_at + (p_pause_duration_seconds || ' seconds')::INTERVAL
  WHERE pdv.project_id IN (SELECT id FROM projects WHERE organization_id = p_organization_id)
    AND pdv.sla_status IN ('on_track', 'warning')
    AND pdv.sla_deadline_at IS NOT NULL;

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 12. Update get_project_vulnerabilities_from_pdv to return SLA fields (for list/graph)
-- =============================================================================
DROP FUNCTION IF EXISTS get_project_vulnerabilities_from_pdv(UUID);

CREATE OR REPLACE FUNCTION get_project_vulnerabilities_from_pdv(p_project_id UUID)
RETURNS TABLE (
  id UUID,
  dependency_id UUID,
  osv_id TEXT,
  severity TEXT,
  summary TEXT,
  details TEXT,
  aliases TEXT[],
  fixed_versions TEXT[],
  published_at TIMESTAMPTZ,
  modified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ,
  dependency_name TEXT,
  dependency_version TEXT,
  is_reachable BOOLEAN,
  epss_score NUMERIC,
  cvss_score NUMERIC,
  cisa_kev BOOLEAN,
  depscore INTEGER,
  sla_status TEXT,
  sla_deadline_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    pdv.id,
    pd.dependency_id,
    pdv.osv_id,
    pdv.severity,
    pdv.summary,
    NULL::TEXT AS details,
    pdv.aliases,
    pdv.fixed_versions,
    pdv.published_at,
    NULL::TIMESTAMPTZ AS modified_at,
    pdv.created_at,
    pd.name AS dependency_name,
    pd.version AS dependency_version,
    pdv.is_reachable,
    pdv.epss_score,
    pdv.cvss_score,
    pdv.cisa_kev,
    pdv.depscore,
    pdv.sla_status,
    pdv.sla_deadline_at
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  WHERE pdv.project_id = p_project_id;
$$;
