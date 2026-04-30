export type IaCFramework = 'terraform' | 'kubernetes' | 'dockerfile';

export type IaCScanner = 'trivy' | 'checkov';

export interface IaCFinding {
  scanner: IaCScanner;
  scanner_version: string;
  rule_id: string;
  framework: IaCFramework;
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  severity: string | null;
  message: string | null;
  description: string | null;
  cwe_ids: string[];
  code_snippet: string | null;
  rule_doc_url: string | null;
  /** Stable identifier for status carryover. NULL = decisions don't carry. */
  iac_fingerprint: string | null;
  metadata: Record<string, unknown> | null;
}

export interface ContainerFinding {
  scanner_version: string;
  image_reference: string;
  image_digest: string;
  os_package_name: string;
  os_package_version: string;
  os_package_ecosystem: string | null;
  osv_id: string | null;
  cve_id: string | null;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  fix_versions: string[];
  layer_digest: string | null;
  description: string | null;
  rule_doc_url: string | null;
  /** `${package_name}@${osv_id || cve_id}` — digest-independent. NULL when both
   *  osv_id and cve_id are missing. */
  container_fingerprint: string | null;
}

export interface SkippedImage {
  image: string;
  reason:
    | 'ghcr_namespace_mismatch'
    | 'private_registry_unsupported_at_v1'
    | 'no_dockerfile'
    | 'parse_failed';
}
