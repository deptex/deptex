/**
 * Shared types for the malicious-packages feature.
 * Mirrors the schema in `backend/database/malicious_packages_v1.sql`.
 */

export type MaliciousScanner = 'feed' | 'guarddog' | 'maintainer';
export type MaliciousSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type MaliciousFeedSource = 'osv' | 'ghsa';
export type MaliciousFeedSyncState = 'pending' | 'running' | 'completed' | 'failed' | 'dlq';

export interface MaliciousFinding {
  id: string;
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  project_dependency_id: string;
  dependency_id: string;
  rule_id: string;
  scanner: MaliciousScanner;
  severity: MaliciousSeverity;
  message: string | null;
  depscore: number | null;
  suppressed: boolean;
  suppressed_by: string | null;
  suppressed_at: string | null;
  suppressed_reason: string | null;
  risk_accepted: boolean;
  risk_accepted_by: string | null;
  risk_accepted_at: string | null;
  risk_accepted_reason: string | null;
  created_at: string;
  // Hydrated from package_security_cache on detail fetch:
  evidence?: MaliciousEvidence[];
  ai_narrative?: string | null;
  ai_narrative_cached_at?: string | null;
  // Hydrated from dependencies join:
  package_name?: string;
  ecosystem?: string;
  package_version?: string;
}

export interface MaliciousEvidence {
  file_path: string;
  lines: [number, number];
  snippet: string;
}

/**
 * Backwards-compatible shape: existing keys (`source`, `confidence`, `reason`)
 * are preserved; the malicious-packages feature adds `scanner`, `severity`,
 * and `top_finding_id` as additive fields.
 */
export interface MaliciousIndicator {
  source: 'deptex';
  confidence: 'high';
  reason: string;
  scanner?: MaliciousScanner;
  severity?: MaliciousSeverity;
  top_finding_id?: string | null;
}

export interface ExplainResult {
  narrative: string;
  risk_level: MaliciousSeverity | 'none';
  cached: boolean;
}

export interface KnownMaliciousPackage {
  id: string;
  package_name: string;
  version: string | null;
  ecosystem: string;
  source: MaliciousFeedSource;
  source_id: string;
  severity: MaliciousSeverity | null;
  description: string | null;
  first_seen_at: string;
  last_seen_at: string;
  withdrawn_at: string | null;
}

export interface PackageSecurityCacheRow {
  id: string;
  package_name: string;
  version: string;
  ecosystem: string;
  scanner: 'guarddog' | 'ai_review';
  scanner_version: string;
  prompt_version: string | null;
  model_version: string | null;
  prompt_input_sha256: string | null;
  findings: GuardDogRawFinding[];
  ai_narrative: string | null;
  risk_level: MaliciousSeverity | 'none' | null;
  scanned_at: string;
}

/** A single GuardDog rule hit, as stored inside `package_security_cache.findings`. */
export interface GuardDogRawFinding {
  rule_id: string;
  severity: 'ERROR' | 'WARNING' | string;
  message: string;
  evidence: MaliciousEvidence[];
}
