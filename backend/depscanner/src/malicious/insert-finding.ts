/**
 * Single insertion path for malicious-package findings.
 *
 * The pipeline batches all findings from a run and calls the
 * `insert_malicious_findings_with_recompute` RPC once; the RPC handles
 * idempotent upsert + dependencies.is_malicious recomputation in a single
 * transaction so partial failures can't leave is_malicious inconsistent
 * with project_malicious_findings.
 */
import type { Storage } from '../storage';
import type { GuardDogRule } from './guarddog';
import type { FeedHit } from './feeds';
import type { ReachabilityLevel, ReachabilityDetails } from './reachability';
import type { CanonicalEcosystem } from './ecosystem';
import { CAPABILITY_KEYS, type CapabilitySet } from './capabilities/types';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Scanner sources for malicious-package findings:
 *  - 'feed': OSV / GHSA / OSSF malware feed match (v1)
 *  - 'guarddog': GuardDog source-heuristic rules (v1)
 *  - 'maintainer': maintainer / account-takeover signals (M1c)
 */
export type MaliciousScanner = 'feed' | 'guarddog' | 'maintainer';

export interface PendingFinding {
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  project_dependency_id: string;
  dependency_id: string;
  rule_id: string;
  scanner: MaliciousScanner;
  severity: FindingSeverity;
  message: string | null;
  depscore: number | null;
  /**
   * v2: per-finding reachability classification computed by
   * `computeReachability()` against the workspace tree-sitter index.
   * Null when the finding's package isn't classifiable (e.g. compute
   * threw — soft-fail) or when the resolver hasn't run for this row.
   */
  reachability_level?: ReachabilityLevel | null;
  reachability_details?: ReachabilityDetails | { error: string; message?: string } | null;
}

export function severityForFeed(hit: FeedHit): FindingSeverity {
  // Feed match is, by construction, a confirmed advisory in OSSF /
  // OSV-Malicious / GHSA-MALWARE. Always critical regardless of the
  // upstream advisory's severity field (which is often null on these
  // since "malware" isn't a CVSS category).
  return 'critical';
}

export function severityForGuardDogRule(rule: GuardDogRule): FindingSeverity {
  switch ((rule.severity ?? '').toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'info';
    default:
      return 'info';
  }
}

export interface CachedScanRow {
  package_name: string;
  version: string;
  ecosystem: string;
  scanner: 'guarddog' | 'ai_review';
  scanner_version: string;
  findings: GuardDogRule[];
  risk_level: FindingSeverity | 'none' | null;
}

export async function upsertGuardDogCache(
  supabase: Storage,
  row: CachedScanRow,
): Promise<void> {
  await supabase
    .from('package_security_cache')
    .upsert(row as unknown as Record<string, unknown>, {
      onConflict: 'package_name,version,ecosystem,scanner',
    });
}

export interface CapabilityCacheRow {
  package_name: string;
  version: string;
  ecosystem: CanonicalEcosystem;
  scanner_version: string;
  capabilities: CapabilitySet;
  scan_error: string | null;
}

/**
 * Returns the capability row for (package, version, ecosystem) if one
 * exists, or null on miss / DB error. The row is global cache — same row
 * is reused across orgs and projects.
 */
export async function readCapabilityCache(
  supabase: Storage,
  packageName: string,
  version: string,
  ecosystem: string,
): Promise<CapabilityCacheRow | null> {
  const { data, error } = await supabase
    .from('package_capabilities')
    .select(
      [
        'package_name',
        'version',
        'ecosystem',
        'scanner_version',
        'scan_error',
        ...CAPABILITY_KEYS,
      ].join(', '),
    )
    .eq('package_name', packageName)
    .eq('version', version)
    .eq('ecosystem', ecosystem)
    .maybeSingle();
  if (error || !data) return null;
  const row = data as Record<string, unknown>;
  const caps = {} as CapabilitySet;
  for (const k of CAPABILITY_KEYS) caps[k] = row[k] === true;
  return {
    package_name: String(row.package_name),
    version: String(row.version),
    ecosystem: String(row.ecosystem) as CanonicalEcosystem,
    scanner_version: String(row.scanner_version),
    capabilities: caps,
    scan_error: row.scan_error == null ? null : String(row.scan_error),
  };
}

/**
 * Upsert the capability row for (package, version, ecosystem). Replaces
 * the existing row in place on scanner upgrade since `scanner_version` is
 * NOT in the unique key.
 */
export async function upsertCapabilityCache(
  supabase: Storage,
  row: CapabilityCacheRow,
): Promise<void> {
  const payload: Record<string, unknown> = {
    package_name: row.package_name,
    version: row.version,
    ecosystem: row.ecosystem,
    scanner_version: row.scanner_version,
    scan_error: row.scan_error,
    scanned_at: new Date().toISOString(),
  };
  for (const k of CAPABILITY_KEYS) payload[k] = row.capabilities[k];

  await supabase
    .from('package_capabilities')
    .upsert(payload, { onConflict: 'package_name,version,ecosystem' });
}

export async function insertFindingsBatch(
  supabase: Storage,
  findings: PendingFinding[],
): Promise<{ inserted: number; rpcError: string | null }> {
  if (findings.length === 0) return { inserted: 0, rpcError: null };

  const { data, error } = await supabase.rpc<number>(
    'insert_malicious_findings_with_recompute',
    { p_findings: findings as unknown as Record<string, unknown>[] },
  );
  if (error) return { inserted: 0, rpcError: error.message };
  return { inserted: typeof data === 'number' ? data : 0, rpcError: null };
}
