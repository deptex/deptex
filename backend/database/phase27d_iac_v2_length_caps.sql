-- Phase 27d: defense-in-depth length caps mirroring the route-level limits
-- introduced in the post-implementation hardening pass.
--
-- All caps are sized for real-world values with comfortable headroom:
--   - registry credentials.display_name 200, registry_url 512
--   - project_configured_images.image_reference 512 (OCI refs cap ~256)
--   - project_iac_findings / project_container_findings.risk_accepted_reason 4096
--
-- Rows that already exceed these limits would fail the CHECK; phase27a/b only
-- shipped to dev so prod hasn't been seeded yet, but the constraints are
-- written so they fire only on subsequent INSERT/UPDATE — existing rows that
-- happen to be oversized via service-role direct insert would be detected on
-- the next mutation rather than blowing up the migration.

ALTER TABLE organization_registry_credentials
  ADD CONSTRAINT orc_display_name_length_check
    CHECK (length(display_name) <= 200),
  ADD CONSTRAINT orc_registry_url_length_check
    CHECK (registry_url IS NULL OR length(registry_url) <= 512);

ALTER TABLE project_configured_images
  ADD CONSTRAINT pci_image_reference_length_check
    CHECK (length(image_reference) <= 512);

ALTER TABLE project_iac_findings
  ADD CONSTRAINT piaf_risk_accepted_reason_length_check
    CHECK (risk_accepted_reason IS NULL OR length(risk_accepted_reason) <= 4096);

ALTER TABLE project_container_findings
  ADD CONSTRAINT pcf_risk_accepted_reason_length_check
    CHECK (risk_accepted_reason IS NULL OR length(risk_accepted_reason) <= 4096);
