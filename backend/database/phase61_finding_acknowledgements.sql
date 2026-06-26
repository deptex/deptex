-- phase61: per-finding acknowledgement (the "Open" manual disposition)
--
-- The findings table lets a user set a finding to New / Open / Ignored.
--   * Ignored already lives in the per-type status columns (legacy
--     suppressed/risk_accepted mirror), the group-suppression table, and the
--     flow-suppression table.
--   * New vs Open is the missing bit: Open = the finding has been acknowledged
--     / is being worked.
--
-- We can't derive Open from the per-type `status` column — the scanners write
-- status='open' on insert, so a brand-new finding would already read as Open.
-- So acknowledgement lives here, keyed by the stable finding_key (survives
-- rescans): a row present = acknowledged (Open); absent = New. Ignored
-- supersedes both in the UI. (Filing a tracker ticket also reads as Open, via
-- finding_tracker_links — no row needed here for that case.)
--
-- Generic over every finding type, including taint_flow's flow_signature_hash
-- and the synthetic container_group / iac_group keys the UI already uses.

CREATE TABLE IF NOT EXISTS project_finding_acknowledgements (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_type text NOT NULL,
  finding_key text NOT NULL,
  acknowledged_by uuid,
  acknowledged_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, finding_type, finding_key)
);

CREATE INDEX IF NOT EXISTS idx_finding_acks_project
  ON project_finding_acknowledgements (project_id, finding_type, finding_key);
CREATE INDEX IF NOT EXISTS idx_finding_acks_org
  ON project_finding_acknowledgements (organization_id);
