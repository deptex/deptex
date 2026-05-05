import type { SupabaseClient } from '@supabase/supabase-js';
import type { ContainerFinding, IaCFinding } from './types';

const BATCH_SIZE = 100;

interface IaCRow extends Record<string, unknown> {
  project_id: string;
  extraction_run_id: string;
  scanner: 'trivy' | 'checkov';
  scanner_version: string | null;
  rule_id: string;
  framework: string;
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  severity: string | null;
  depscore: number | null;
  message: string | null;
  description: string | null;
  cwe_ids: string[];
  code_snippet: string | null;
  rule_doc_url: string | null;
  iac_fingerprint: string | null;
  compliance_refs: Record<string, string[]> | null;
  metadata: Record<string, unknown> | null;
}

interface ContainerRow extends Record<string, unknown> {
  project_id: string;
  extraction_run_id: string;
  scanner_version: string | null;
  image_reference: string;
  image_digest: string;
  image_source: 'dockerfile_base';
  os_package_name: string;
  os_package_version: string;
  os_package_ecosystem: string | null;
  osv_id: string | null;
  cve_id: string | null;
  // NOTE: vulnerability_id is intentionally absent — column is GENERATED ALWAYS.
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  fix_versions: string[];
  layer_digest: string | null;
  depscore: number | null;
  description: string | null;
  rule_doc_url: string | null;
  container_fingerprint: string | null;
}

export interface UpsertResult {
  inserted: number;
  staleDeleted: number;
}

function severityToDepscore(severity: string | null): number | null {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL': return 90;
    case 'HIGH': return 70;
    case 'MEDIUM': return 50;
    case 'LOW': return 30;
    case 'INFO': return 10;
    default: return null;
  }
}

/**
 * Bulk upsert IaC findings against the `(project_id, rule_id, file_path,
 * start_line_key, extraction_run_id)` UNIQUE index. Patch A: start_line_key is
 * GENERATED, never supplied in payload. Patch D: organization_id is set by
 * BEFORE INSERT trigger from projects.organization_id, so the worker never
 * passes organization_id either — preventing caller-side mis-attribution.
 */
export async function upsertIaCFindings(
  supabase: SupabaseClient,
  projectId: string,
  runId: string,
  findings: IaCFinding[]
): Promise<UpsertResult> {
  if (findings.length === 0) {
    return { inserted: 0, staleDeleted: 0 };
  }

  const rows: IaCRow[] = findings.map((f) => ({
    project_id: projectId,
    extraction_run_id: runId,
    scanner: f.scanner,
    scanner_version: f.scanner_version,
    rule_id: f.rule_id,
    framework: f.framework,
    file_path: f.file_path,
    start_line: f.start_line,
    end_line: f.end_line,
    severity: f.severity,
    depscore: severityToDepscore(f.severity),
    message: f.message,
    description: f.description,
    cwe_ids: f.cwe_ids ?? [],
    code_snippet: f.code_snippet,
    rule_doc_url: f.rule_doc_url,
    iac_fingerprint: f.iac_fingerprint,
    compliance_refs: f.compliance_refs,
    metadata: f.metadata,
  }));

  let inserted = 0;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error } = await supabase
      .from('project_iac_findings')
      .upsert(batch, {
        onConflict:
          'project_id,rule_id,file_path,start_line_key,extraction_run_id',
      });
    if (error) {
      throw new Error(`upsertIaCFindings batch ${i}: ${error.message}`);
    }
    inserted += batch.length;
  }
  return { inserted, staleDeleted: 0 };
}

/**
 * Bulk upsert container findings. Patch B: vulnerability_id is GENERATED
 * ALWAYS and MUST NOT appear in the payload. Patch D: same trigger semantics
 * as IaC.
 */
export async function upsertContainerFindings(
  supabase: SupabaseClient,
  projectId: string,
  runId: string,
  findings: ContainerFinding[]
): Promise<UpsertResult> {
  if (findings.length === 0) {
    return { inserted: 0, staleDeleted: 0 };
  }

  const rows: ContainerRow[] = findings.map((f) => ({
    project_id: projectId,
    extraction_run_id: runId,
    scanner_version: f.scanner_version,
    image_reference: f.image_reference,
    image_digest: f.image_digest,
    image_source: 'dockerfile_base',
    os_package_name: f.os_package_name,
    os_package_version: f.os_package_version,
    os_package_ecosystem: f.os_package_ecosystem,
    osv_id: f.osv_id,
    cve_id: f.cve_id,
    severity: f.severity,
    cvss_score: f.cvss_score,
    epss_score: f.epss_score,
    is_kev: f.is_kev,
    fix_versions: f.fix_versions ?? [],
    layer_digest: f.layer_digest,
    depscore: severityToDepscore(f.severity),
    description: f.description,
    rule_doc_url: f.rule_doc_url,
    container_fingerprint: f.container_fingerprint,
  }));

  let inserted = 0;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error } = await supabase
      .from('project_container_findings')
      .upsert(batch, {
        onConflict:
          'project_id,image_digest,os_package_name,os_package_version,vulnerability_id,extraction_run_id',
      });
    if (error) {
      throw new Error(`upsertContainerFindings batch ${i}: ${error.message}`);
    }
    inserted += batch.length;
  }
  return { inserted, staleDeleted: 0 };
}
