// Phase 23b: DAST DTOs shared between routes and (eventually) the frontend.

export type ScanJobStatus = 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled';
export type ScanJobType = 'extraction' | 'dast'; // extensible (malicious_pkg, iac, container)

export type DastTriggerSource = 'manual' | 'webhook' | 'scheduled' | 'aegis';
export type DastScanProfile = 'auto' | 'quick' | 'full' | 'api';
export type DastSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DastFindingStatus = 'open' | 'suppressed' | 'risk_accepted' | 'fixed';
export type DastConfidence = 'confirmed' | 'high' | 'medium' | 'low';

export interface DastConfigDTO {
  enabled: boolean;
  target_url: string | null;
  scan_profile: DastScanProfile;
  scan_timeout_minutes: number;
}

export interface DastJobDTO {
  id: string;
  status: ScanJobStatus;
  trigger_source: DastTriggerSource | null;
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
  confirmed_exploitable: boolean;
  status: DastFindingStatus;
  risk_accepted_reason: string | null;
  created_at: string;
}
