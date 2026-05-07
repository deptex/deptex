-- Phase 27b rollback: drops registries + creds + cache + reverses image_source widening.
-- Atomic; populated-table-aware. Mirrors phase27a_iac_v2_formats_rollback.sql.

BEGIN;

-- Drop new triggers first so DROP TABLE doesn't trip them.
DROP TRIGGER IF EXISTS pci_null_creds_on_org_move ON project_configured_images;
DROP TRIGGER IF EXISTS project_configured_images_enforce_org_id ON project_configured_images;

-- FK-aware drop order. CASCADE absorbs any external references created by
-- future phases that we don't know about here.
DROP TABLE IF EXISTS container_image_scan_cache CASCADE;
DROP TABLE IF EXISTS project_configured_images CASCADE;
DROP TABLE IF EXISTS organization_registry_credentials CASCADE;

-- Reverse image_source CHECK widening — DELETE v2-only rows first or the
-- narrow CHECK fails. Documented behavior: rollback discards configured-image
-- container findings.
DELETE FROM project_container_findings WHERE image_source = 'configured_image';
ALTER TABLE project_container_findings DROP CONSTRAINT IF EXISTS project_container_findings_image_source_check;
ALTER TABLE project_container_findings ADD CONSTRAINT project_container_findings_image_source_check
  CHECK (image_source IN ('dockerfile_base'));

-- Drop helper functions (no remaining dependents after table drops).
DROP FUNCTION IF EXISTS cleanup_container_image_scan_cache(INTEGER);
DROP FUNCTION IF EXISTS pci_null_credentials_id_on_org_move();
-- enforce_project_scoped_org_id() left in place — could be used by future
-- phases. Drop it explicitly only if no other phase has adopted it.

COMMIT;
