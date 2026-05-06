-- Rollback for phase27c_iac_v2_hardening.sql.
--
-- Restores the original (broken-by-trigger-ordering) state from phase27b
-- and drops the atomic cap RPCs + covering index. Use only to revert the
-- hardening — the phase27b state is itself buggy (see phase27c header).

DROP FUNCTION IF EXISTS update_configured_image_with_cap(UUID, UUID, UUID, BOOLEAN, BOOLEAN, UUID, INTEGER);
DROP FUNCTION IF EXISTS insert_configured_image_with_cap(UUID, UUID, TEXT, UUID, BOOLEAN, UUID, INTEGER);

DROP INDEX IF EXISTS idx_pci_credentials_id;

-- Restore phase27b's two-trigger setup. enforce_project_scoped_org_id() and
-- pci_null_credentials_id_on_org_move() are still defined from phase27b.
DROP TRIGGER IF EXISTS project_configured_images_enforce_org_id ON project_configured_images;
DROP FUNCTION IF EXISTS enforce_pci_org_id_and_null_creds();

CREATE TRIGGER project_configured_images_enforce_org_id
  BEFORE INSERT OR UPDATE ON project_configured_images
  FOR EACH ROW EXECUTE FUNCTION enforce_project_scoped_org_id();

CREATE TRIGGER pci_null_creds_on_org_move
  BEFORE UPDATE ON project_configured_images
  FOR EACH ROW EXECUTE FUNCTION pci_null_credentials_id_on_org_move();
