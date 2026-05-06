// Canonical IaC framework list — single source of truth. All readers
// (detect-infra, checkov, orchestrator, scanner-findings route, frontend api,
// vulnerability table chips) import from here. Adding a value? Add it ONCE.
// Note: kustomization.yaml surfaces as 'kubernetes' — no separate value.
export const IAC_FRAMEWORKS = [
  'terraform',
  'kubernetes',
  'dockerfile',
  'helm',
  'cloudformation',
  'arm',
  'bicep',
  'serverless',
  'github_actions',
] as const;

export type IaCFramework = (typeof IAC_FRAMEWORKS)[number];

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
  /** Compliance framework references extracted from Checkov metadata.benchmark
   *  (CIS / SOC2 / NIST / PCI-DSS / HIPAA → list of control IDs).
   *  NULL when no refs present. */
  compliance_refs: Record<string, string[]> | null;
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
    | 'parse_failed'
    // v2 — populated by container-scan substep failures (M8). Each maps 1:1
    // to a tag in classifyContainerScanError so the reason a row is skipped is
    // recoverable from extraction_step_errors alone, no log-grep required.
    | 'no_matching_cred'
    | 'cred_decrypt_failed'
    | 'auth_invalid'
    | 'auth_throttled'
    | 'auth_disabled'
    | 'auth_mint_failed'
    | 'registry_5xx'
    | 'manifest_not_found'
    | 'trivy_partial'
    | 'budget_exhausted'
    // SSRF defense: image_reference's registry host resolved to a
    // private / loopback / IMDS / Fly 6PN range at scan time.
    | 'image_host_blocked';
}

export type RegistryType =
  | 'ghcr'
  | 'ecr'
  | 'gcr'
  | 'acr'
  | 'dockerhub'
  | 'quay'
  | 'harbor'
  | 'jfrog'
  | 'custom';

export type CredentialShape =
  | 'username_password'
  | 'aws_keys'
  | 'gcp_service_account_key'
  | 'azure_service_principal'
  | 'token';

// Worker-side row shape for organization_registry_credentials. Includes
// encrypted_credentials + encryption_key_version because M5 (registry auth
// resolver) decrypts here. Never returned to clients — frontend mirror in
// frontend/src/lib/api.ts omits the encrypted blob.
export interface RegistryCredential {
  id: string;
  organization_id: string;
  registry_type: RegistryType;
  registry_url: string | null;
  display_name: string;
  credential_shape: CredentialShape;
  encrypted_credentials: string;
  encryption_key_version: number;
  last_used_at: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

// Discriminated union over credential_shape. The decrypted plaintext shape
// the worker passes to per-registry minters. The DecryptedCredential helper
// type lives in registry-auth.ts (M5) and never reaches route files.
export type CredentialPlaintext =
  | { shape: 'username_password'; username: string; password: string }
  | {
      shape: 'aws_keys';
      access_key_id: string;
      secret_access_key: string;
      session_token?: string;
      region: string;
    }
  | { shape: 'gcp_service_account_key'; service_account_json: string }
  | {
      shape: 'azure_service_principal';
      client_id: string;
      client_secret: string;
      tenant_id: string;
    }
  | { shape: 'token'; token: string };

// Worker-side row shape for project_configured_images. organization_id is
// re-derived by the BEFORE INSERT OR UPDATE trigger; readers MUST still chain
// .eq('project_id', projectId) per the tenancy invariants.
export interface ConfiguredImage {
  id: string;
  project_id: string;
  organization_id: string;
  image_reference: string;
  credentials_id: string | null;
  enabled: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}
