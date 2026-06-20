-- phase55c: keep finding_key + auto_ignored in sync via triggers.
--
-- Rather than thread the stored-verdict computation through finalize_extraction
-- and commit_dast_target_run (large, load-bearing functions), a BEFORE INSERT OR
-- UPDATE trigger on each finding store stamps `finding_key` and the
-- `auto_ignored`/`auto_ignore_reason` verdict from the row's own columns. This
-- guarantees the stored verdict can NEVER drift from the row — a new scan's
-- inserts, finalize's carry-forward reachability update, and the reachability
-- classifier's updates all re-derive it automatically (so an auto-ignored finding
-- that later becomes reachable auto-reopens with no manual action).
--
-- finding_key is computed on INSERT only (the natural key is immutable after
-- insert); the auto-ignore verdict is recomputed on every write. The helpers
-- (compute_finding_key / compute_auto_ignore_reason) come from phase55.

BEGIN;

-- SCA / vulnerability
CREATE OR REPLACE FUNCTION trg_pdv_finding_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.finding_key := compute_finding_key(ARRAY[
      (SELECT pd.name FROM project_dependencies pd WHERE pd.id = NEW.project_dependency_id),
      NEW.osv_id]);
  END IF;
  NEW.auto_ignore_reason := compute_auto_ignore_reason('vulnerability', NEW.reachability_level, NEW.is_reachable, NULL, NULL, NULL, NULL);
  NEW.auto_ignored := NEW.auto_ignore_reason IS NOT NULL;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_pdv_finding_status ON project_dependency_vulnerabilities;
CREATE TRIGGER trg_pdv_finding_status BEFORE INSERT OR UPDATE ON project_dependency_vulnerabilities
  FOR EACH ROW EXECUTE FUNCTION trg_pdv_finding_status();

-- Secret (finding_key only; never auto-ignored)
CREATE OR REPLACE FUNCTION trg_secret_finding_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.finding_key := compute_finding_key(ARRAY[NEW.detector_type, NEW.file_path, NEW.redacted_value]);
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_secret_finding_status ON project_secret_findings;
CREATE TRIGGER trg_secret_finding_status BEFORE INSERT OR UPDATE ON project_secret_findings
  FOR EACH ROW EXECUTE FUNCTION trg_secret_finding_status();

-- Semgrep (finding_key only)
CREATE OR REPLACE FUNCTION trg_semgrep_finding_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.finding_key := compute_finding_key(ARRAY[
      coalesce(NEW.semgrep_fingerprint, concat_ws('|', NEW.rule_id, NEW.file_path, NEW.start_line::text))]);
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_semgrep_finding_status ON project_semgrep_findings;
CREATE TRIGGER trg_semgrep_finding_status BEFORE INSERT OR UPDATE ON project_semgrep_findings
  FOR EACH ROW EXECUTE FUNCTION trg_semgrep_finding_status();

-- DAST
CREATE OR REPLACE FUNCTION trg_dast_finding_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.finding_key := compute_finding_key(ARRAY[
      NEW.rule_id,
      NEW.vulnerability_type,
      CASE WHEN NEW.handler_file_path IS NOT NULL
           THEN concat_ws('|', NEW.handler_file_path, NEW.handler_function_name)
           ELSE concat_ws('|', NEW.endpoint_url, NEW.http_method) END]);
  END IF;
  NEW.auto_ignore_reason := compute_auto_ignore_reason('dast', NULL, NULL, NULL, NULL, NEW.severity, NEW.payload_redacted);
  NEW.auto_ignored := NEW.auto_ignore_reason IS NOT NULL;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_dast_finding_status ON project_dast_findings;
CREATE TRIGGER trg_dast_finding_status BEFORE INSERT OR UPDATE ON project_dast_findings
  FOR EACH ROW EXECUTE FUNCTION trg_dast_finding_status();

-- IaC
CREATE OR REPLACE FUNCTION trg_iac_finding_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.finding_key := compute_finding_key(ARRAY[
      coalesce(NEW.iac_fingerprint, concat_ws('|', NEW.scanner, NEW.rule_id, NEW.file_path, NEW.start_line_key::text))]);
  END IF;
  NEW.auto_ignore_reason := compute_auto_ignore_reason('iac', NULL, NULL, NULL, NEW.rule_id, NEW.severity, NULL);
  NEW.auto_ignored := NEW.auto_ignore_reason IS NOT NULL;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_iac_finding_status ON project_iac_findings;
CREATE TRIGGER trg_iac_finding_status BEFORE INSERT OR UPDATE ON project_iac_findings
  FOR EACH ROW EXECUTE FUNCTION trg_iac_finding_status();

-- Container
CREATE OR REPLACE FUNCTION trg_container_finding_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.finding_key := compute_finding_key(ARRAY[
      coalesce(NEW.container_fingerprint, concat_ws('|', NEW.image_reference, coalesce(NEW.osv_id, NEW.cve_id, NEW.os_package_name)))]);
  END IF;
  NEW.auto_ignore_reason := compute_auto_ignore_reason('container', NULL, NULL, NEW.is_kev, NULL, NULL, NULL);
  NEW.auto_ignored := NEW.auto_ignore_reason IS NOT NULL;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_container_finding_status ON project_container_findings;
CREATE TRIGGER trg_container_finding_status BEFORE INSERT OR UPDATE ON project_container_findings
  FOR EACH ROW EXECUTE FUNCTION trg_container_finding_status();

-- Malicious (finding_key only; never auto-ignored)
CREATE OR REPLACE FUNCTION trg_malicious_finding_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.finding_key := compute_finding_key(ARRAY[
      (SELECT pd.name FROM project_dependencies pd WHERE pd.id = NEW.project_dependency_id),
      NEW.rule_id, NEW.scanner]);
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_malicious_finding_status ON project_malicious_findings;
CREATE TRIGGER trg_malicious_finding_status BEFORE INSERT OR UPDATE ON project_malicious_findings
  FOR EACH ROW EXECUTE FUNCTION trg_malicious_finding_status();

COMMIT;
