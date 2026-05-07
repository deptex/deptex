-- Phase 27c: hardening for IaC + Container v2 Phase 1.
--
-- Closes three findings from the post-implementation review:
--
--   1. Trigger ordering bug: pci_null_creds_on_org_move sorts alphabetically
--      BEFORE project_configured_images_enforce_org_id, so the null-creds
--      trigger runs while NEW.organization_id is still stale; reparenting a
--      configured image across orgs aborts with FK 23503 instead of soft-
--      detaching. Fix: drop both BEFORE triggers and replace with a single
--      merged trigger that derives the new org first, THEN nulls credentials_id
--      if the org changed.
--
--   2. Composite FK (credentials_id, organization_id) on
--      project_configured_images has no covering index, so cred deletion does
--      a Seq Scan to find children. Add a partial index.
--
--   3. project_configured_images cap (20 enabled images per project) was
--      enforced with a JS-only SELECT-then-INSERT, racy under parallel POSTs.
--      Replace with atomic plpgsql RPCs that count + write inside the same
--      transaction with row-level locking on a sentinel.

-- ============================================================
-- 1. Merged trigger
-- ============================================================
DROP TRIGGER IF EXISTS pci_null_creds_on_org_move ON project_configured_images;
DROP TRIGGER IF EXISTS project_configured_images_enforce_org_id ON project_configured_images;

CREATE OR REPLACE FUNCTION enforce_pci_org_id_and_null_creds() RETURNS TRIGGER AS $$
DECLARE
  derived_org UUID;
BEGIN
  derived_org := (SELECT organization_id FROM projects WHERE id = NEW.project_id);
  IF derived_org IS NULL THEN
    RAISE EXCEPTION 'enforce_pci_org_id_and_null_creds: project % not found', NEW.project_id;
  END IF;

  -- On UPDATE, check whether the derived org differs from the OLD row's org.
  -- If it does, soft-detach the cred (composite FK would otherwise reject
  -- the move with FK 23503, masking the legitimate reparent UX).
  IF TG_OP = 'UPDATE' AND derived_org IS DISTINCT FROM OLD.organization_id THEN
    NEW.credentials_id := NULL;
  END IF;

  NEW.organization_id := derived_org;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER project_configured_images_enforce_org_id
  BEFORE INSERT OR UPDATE ON project_configured_images
  FOR EACH ROW EXECUTE FUNCTION enforce_pci_org_id_and_null_creds();

-- ============================================================
-- 2. Covering index for composite FK
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_pci_credentials_id
  ON project_configured_images(credentials_id, organization_id)
  WHERE credentials_id IS NOT NULL;

-- ============================================================
-- 3. Atomic cap-and-insert / cap-and-update RPCs
-- ============================================================

-- Insert with atomic cap check. Locks the per-project enabled rows FOR UPDATE
-- so two parallel callers serialize and the second one sees the first's
-- inserted row in its count.
CREATE OR REPLACE FUNCTION insert_configured_image_with_cap(
  p_project_id UUID,
  p_organization_id UUID,
  p_image_reference TEXT,
  p_credentials_id UUID,
  p_enabled BOOLEAN,
  p_created_by UUID,
  p_cap INTEGER DEFAULT 20
) RETURNS SETOF project_configured_images AS $$
DECLARE
  current_count INTEGER;
BEGIN
  -- Lock all enabled rows for this project. Forces parallel POSTs to
  -- serialize. Disabled rows do not consume a slot.
  IF p_enabled THEN
    SELECT count(*) INTO current_count
      FROM project_configured_images
      WHERE project_id = p_project_id AND enabled = true
      FOR UPDATE;
    IF current_count >= p_cap THEN
      RAISE EXCEPTION 'image_cap_reached' USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  RETURN QUERY
    INSERT INTO project_configured_images
      (project_id, organization_id, image_reference, credentials_id, enabled, created_by)
    VALUES
      (p_project_id, p_organization_id, p_image_reference, p_credentials_id, p_enabled, p_created_by)
    RETURNING *;
END;
$$ LANGUAGE plpgsql;

-- Update with atomic cap check on enabled-flip. Same locking pattern as INSERT.
CREATE OR REPLACE FUNCTION update_configured_image_with_cap(
  p_image_id UUID,
  p_project_id UUID,
  p_organization_id UUID,
  p_enabled BOOLEAN,                  -- nullable: NULL means do not change
  p_credentials_id_set BOOLEAN,       -- whether to write credentials_id
  p_credentials_id UUID,
  p_cap INTEGER DEFAULT 20
) RETURNS SETOF project_configured_images AS $$
DECLARE
  current_count INTEGER;
BEGIN
  -- If the patch is flipping enabled to true, recheck the cap with the
  -- current row excluded.
  IF p_enabled IS TRUE THEN
    SELECT count(*) INTO current_count
      FROM project_configured_images
      WHERE project_id = p_project_id AND enabled = true AND id <> p_image_id
      FOR UPDATE;
    IF current_count >= p_cap THEN
      RAISE EXCEPTION 'image_cap_reached' USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  RETURN QUERY
    UPDATE project_configured_images SET
      enabled = COALESCE(p_enabled, enabled),
      credentials_id = CASE WHEN p_credentials_id_set THEN p_credentials_id ELSE credentials_id END,
      updated_at = NOW()
    WHERE id = p_image_id AND project_id = p_project_id AND organization_id = p_organization_id
    RETURNING *;
END;
$$ LANGUAGE plpgsql;
