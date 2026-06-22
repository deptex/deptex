-- Group-level suppression for the synthetic "collapsed" finding rows that have
-- no backing DB row of their own.
--
-- Two finding rows in the security table are presentation collapses over many
-- real findings, so the per-row status endpoint (which writes status onto a
-- backing store row keyed by finding_key) has nowhere to record their Ignore
-- disposition:
--   * container_group ("out-of-date base image") — key `cig:<project>|<image>`,
--     folds a base image's wall of OS-package CVEs into one row.
--   * iac_group ("container hardening")          — key `iacg:<project>`,
--     folds the k8s/Dockerfile hardening tail into one row.
--
-- Their Ignore lives here, keyed by the same stable synthetic group key the UI
-- already uses (which survives rescans like every other finding_key). The
-- underlying member findings are untouched — this only sets aside the aggregate
-- row. Removing the row (un-ignore) is a DELETE.
CREATE TABLE IF NOT EXISTS public.project_finding_group_suppressions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  group_type text NOT NULL CHECK (group_type IN ('container_group', 'iac_group')),
  group_key text NOT NULL,
  ignore_reason text CHECK (ignore_reason IN ('false_positive', 'wont_fix', 'accepted_risk')),
  ignore_note text,
  ignored_by uuid,
  ignored_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, group_type, group_key)
);

CREATE INDEX IF NOT EXISTS idx_finding_group_suppressions_org
  ON public.project_finding_group_suppressions (organization_id);
CREATE INDEX IF NOT EXISTS idx_finding_group_suppressions_project
  ON public.project_finding_group_suppressions (project_id);
