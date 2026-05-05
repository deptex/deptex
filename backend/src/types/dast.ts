// DAST DTOs shared between routes and (eventually) the frontend.
// Phase 23b shipped single-target DAST. Phase 24a (v2.1a) introduces
// multi-target scanning with per-target encrypted credentials.

export type ScanJobStatus = 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled';
// v2.1a widens trigger_source + adds dast_zap / dast_nuclei subtypes.
export type ScanJobType = 'extraction' | 'dast' | 'dast_zap' | 'dast_nuclei';

export type DastTriggerSource = 'manual' | 'webhook' | 'recovery' | 'scheduled' | 'on_deploy' | 'aegis';
export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';
export type DastSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DastFindingStatus = 'open' | 'suppressed' | 'risk_accepted' | 'fixed';
export type DastConfidence = 'confirmed' | 'high' | 'medium' | 'low';

// v2.1a inserts form|jwt|cookie. 'recorded' lands in v2.1d.
export type DastAuthStrategy = 'form' | 'jwt' | 'cookie';
export type DastDetectedRuntime = 'unknown' | 'classic' | 'spa';
export type DastAuthState = 'anonymous' | 'authenticated' | 'authentication_lost';
// v2.1a inserts 'zap' only. 'nuclei' / 'merged' added in v2.1c.
export type DastEngine = 'zap';

export interface DastTargetDTO {
  id: string;
  target_url: string;
  label: string | null;
  enabled: boolean;
  detected_runtime: DastDetectedRuntime;
  detected_runtime_at: string | null;
  detected_runtime_ttl_at: string | null;
  has_credentials: boolean;
  auth_strategy: DastAuthStrategy | null;
  active_dast_run_id: string | null;
  last_scanned_at: string | null;
  created_at: string;
}

export interface DastScopeHeaderRule {
  name: string;
  value: string;
  scope: 'all' | 'requests' | 'responses';
}

export interface DastScopeConfig {
  include_patterns?: string[];
  exclude_patterns?: string[];
  header_rules?: DastScopeHeaderRule[];
}

export interface DastConfigDTO {
  enabled: boolean;
  // Legacy v1 single-target field. Removed with phase24b once multi-target ships
  // and the frontend reads `targets[]` exclusively.
  target_url?: string | null;
  scan_profile: DastScanProfile;
  scan_timeout_minutes: number;
  // v2.1a additions; populated by the multi-target route in Task 3.
  scope_config?: DastScopeConfig;
  targets?: DastTargetDTO[];
}

// Redaction caps locked per multi-tenant-design-auditor-f4/r2-f11 P1:
//   token_prefix: first 8 chars + '…' (NOT 12 — JWT prefix 'eyJhbGciOi' is 10 and reveals algorithm)
//   username_masked: first char + '***@<domain>' truncated to 24 chars total
//   cookie_names: capped at 10 items, each name truncated to 32 chars
//   last_step_url: scheme + host only (NEVER path/query/fragment)
export type DastCredentialPayloadSummary =
  | { kind: 'form'; username_masked: string }
  | { kind: 'jwt'; token_prefix: string; token_length: number; expires_in_minutes: number }
  | { kind: 'cookie'; cookie_count: number; cookie_names: string[] };

export interface DastCredentialSummaryDTO {
  auth_strategy: DastAuthStrategy;
  payload_summary: DastCredentialPayloadSummary;
  logged_in_indicator: string | null;
  logged_out_indicator: string | null;
  updated_at: string;
}

export type DastCredentialUpsertPayload =
  | {
      kind: 'form';
      login_url: string;
      username_field: string;
      password_field: string;
      username: string;
      password: string;
    }
  | { kind: 'jwt'; token: string }
  | {
      kind: 'cookie';
      cookies: { name: string; value: string; domain?: string; path?: string }[];
    };

export interface DastCredentialUpsertDTO {
  auth_strategy: DastAuthStrategy;
  payload: DastCredentialUpsertPayload;
  logged_in_indicator?: string;
  logged_out_indicator?: string;
}

export interface DastJobDTO {
  id: string;
  status: ScanJobStatus;
  trigger_source: DastTriggerSource | null;
  target_id?: string | null;
  target_url: string | null;
  scan_profile: DastScanProfile | null;
  findings_count: number | null;
  duration_seconds: number | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  error_category: string | null;
  attempts: number;
  created_at: string;
}

export interface DastFindingDTO {
  id: string;
  target_id?: string | null;
  auth_state?: DastAuthState | null;
  engine?: DastEngine | null;
  endpoint_url: string;
  http_method: string;
  vulnerability_type: string;
  severity: DastSeverity;
  cwe_id: string | null;
  owasp_top10_ref: string | null;
  rule_id: string | null;
  message: string | null;
  payload_redacted: string | null;
  response_evidence_redacted: string | null;
  confidence: DastConfidence;
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  linked_sast_finding_id?: string | null;
  cross_link_methods?: string[] | null;
  confirmed_exploitable: boolean;
  status: DastFindingStatus;
  risk_accepted_reason: string | null;
  created_at: string;
}
