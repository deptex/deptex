import { createHash } from 'crypto';

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

type ContainerImageSource = 'dockerfile_base' | 'configured_image';

interface ContainerRow extends Record<string, unknown> {
  project_id: string;
  extraction_run_id: string;
  scanner_version: string | null;
  image_reference: string;
  image_digest: string;
  image_source: ContainerImageSource;
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
  findings: ContainerFinding[],
  imageSource: ContainerImageSource = 'dockerfile_base'
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
    image_source: imageSource,
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

// ============================================================================
// container_image_scan_cache — global digest-keyed result cache (M7)
//
// Lookup is read-only and gated by:
//   1. Composite-PK match: (image_digest, scanner, scanner_version,
//      trivy_db_version_day). All four columns are equality-filtered; PGLite's
//      Storage abstraction only supports eq/in, so freshness is checked in JS.
//   2. 7-day TTL on `scanned_at` (cache rows live up to 30d via the reaper, but
//      we only trust them for 7d so the Trivy CVE DB stays current).
//   3. SHA-256 integrity check on scan_results vs. the column's stored hash —
//      a mismatch logs `cache_integrity_mismatch` and surfaces as a miss so
//      DB-level corruption can never leak into a project's findings table.
//
// Upsert uses ON CONFLICT DO NOTHING (`ignoreDuplicates: true`) so concurrent
// orgs that simultaneously miss the cache and write the same key don't clobber
// each other — and so first_scanned_by_org_id / first_scanned_run_id keep the
// initial-writer attribution they were inserted with.
//
// Truncation: scan_results is bounded by a Postgres CHECK at 1 MB. If the
// findings array serializes larger, we sort by severity desc and drop tail
// findings until it fits, logging `cache_row_truncated`. The truncation is
// transparent to readers — the cached array is the canonical scan result.
// ============================================================================

export type ContainerCacheScanner = 'trivy';

export interface ContainerScanCacheKey {
  /** Bare 64-hex digest (no `sha256:` prefix, no `<repo>@` prefix) — produced
   *  by normalizeDigest() in trivy.ts. The CHECK constraint also accepts an
   *  optional `+linux/amd64` suffix for manifest-list resolution. */
  image_digest: string;
  scanner: ContainerCacheScanner;
  scanner_version: string;
  /** UTC YYYY-MM-DD; the Trivy CVE DB version-day captured at scan time. */
  trivy_db_version_day: string;
}

export interface ContainerScanCacheHit {
  findings: ContainerFinding[];
  scanner_version: string;
}

interface ContainerScanCacheRow extends Record<string, unknown> {
  image_digest: string;
  scanner: ContainerCacheScanner;
  scanner_version: string;
  trivy_db_version_day: string;
  scan_results: ContainerFinding[];
  scan_results_hash: string;
  first_scanned_by_org_id: string | null;
  first_scanned_run_id: string | null;
}

const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CACHE_BYTES = 1_048_576;
// Postgres's JSONB-to-text cast inserts `: ` after keys and `, ` between items,
// expanding the byte count vs. JSON.stringify. We budget 100 KB of headroom so
// that anything that fits the in-memory limit also fits the column's CHECK on
// octet_length(scan_results::text).
const EFFECTIVE_MAX_BYTES = MAX_CACHE_BYTES - 100_000;

/** Severity rank used for truncation ordering. Higher = kept first. */
function severityRank(severity: string | null | undefined): number {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 5;
    case 'HIGH':
      return 4;
    case 'MEDIUM':
      return 3;
    case 'LOW':
      return 2;
    case 'INFO':
      return 1;
    default:
      return 0;
  }
}

/** Recursive key-sort so JSON.stringify is byte-stable across runs. The hash
 *  has to round-trip Postgres → Node, so any property-order drift would manifest
 *  as a false `cache_integrity_mismatch`. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export function computeScanResultsHash(findings: ContainerFinding[]): string {
  return createHash('sha256').update(canonicalJson(findings), 'utf8').digest('hex');
}

/** Trims `findings` to fit within MAX_CACHE_BYTES of JSON.stringify output by
 *  dropping the lowest-severity tail first. Returns the (possibly identical)
 *  array plus a flag the caller can log against. */
export function truncateFindingsToFit(
  findings: ContainerFinding[]
): { findings: ContainerFinding[]; truncated: boolean } {
  const initial = JSON.stringify(findings);
  if (Buffer.byteLength(initial, 'utf8') <= EFFECTIVE_MAX_BYTES) {
    return { findings, truncated: false };
  }
  // Stable sort: severity desc, then index asc so equal-severity rows keep
  // their incoming order.
  const sorted = [...findings]
    .map((f, i) => ({ f, i }))
    .sort((a, b) => severityRank(b.f.severity) - severityRank(a.f.severity) || a.i - b.i)
    .map((x) => x.f);

  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    const candidate = JSON.stringify(sorted.slice(0, mid));
    if (Buffer.byteLength(candidate, 'utf8') <= EFFECTIVE_MAX_BYTES) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return { findings: sorted.slice(0, lo), truncated: true };
}

export async function lookupContainerScanCache(
  supabase: SupabaseClient,
  key: ContainerScanCacheKey
): Promise<ContainerScanCacheHit | null> {
  const { data, error } = await supabase
    .from('container_image_scan_cache')
    .select('image_digest, scanner, scanner_version, trivy_db_version_day, scan_results, scan_results_hash, scanned_at')
    .eq('image_digest', key.image_digest)
    .eq('scanner', key.scanner)
    .eq('scanner_version', key.scanner_version)
    .eq('trivy_db_version_day', key.trivy_db_version_day)
    .maybeSingle();

  if (error) {
    throw new Error(`lookupContainerScanCache: ${error.message}`);
  }
  if (!data) {
    return null;
  }

  const row = data as {
    scan_results: ContainerFinding[];
    scan_results_hash: string;
    scanner_version: string;
    scanned_at: string;
  };

  // 7-day TTL — checked here rather than via .gte() so PGLite (eq/in only) is
  // a drop-in for tests.
  const scannedAtMs = new Date(row.scanned_at).getTime();
  if (Number.isNaN(scannedAtMs) || Date.now() - scannedAtMs > CACHE_TTL_MS) {
    return null;
  }

  const expectedHash = computeScanResultsHash(row.scan_results);
  if (expectedHash !== row.scan_results_hash) {
    console.warn(
      `cache_integrity_mismatch digest=${key.image_digest} scanner=${key.scanner} ` +
        `version=${key.scanner_version} day=${key.trivy_db_version_day} ` +
        `expected=${expectedHash} stored=${row.scan_results_hash}`
    );
    return null;
  }

  return { findings: row.scan_results, scanner_version: row.scanner_version };
}

export async function upsertContainerScanCache(
  supabase: SupabaseClient,
  key: ContainerScanCacheKey,
  parsedFindings: ContainerFinding[],
  orgId: string,
  runId: string
): Promise<void> {
  const { findings, truncated } = truncateFindingsToFit(parsedFindings);
  if (truncated) {
    console.warn(
      `cache_row_truncated digest=${key.image_digest} ` +
        `original=${parsedFindings.length} kept=${findings.length}`
    );
  }

  const row: ContainerScanCacheRow = {
    image_digest: key.image_digest,
    scanner: key.scanner,
    scanner_version: key.scanner_version,
    trivy_db_version_day: key.trivy_db_version_day,
    scan_results: findings,
    scan_results_hash: computeScanResultsHash(findings),
    first_scanned_by_org_id: orgId,
    first_scanned_run_id: runId,
  };

  // ON CONFLICT DO NOTHING preserves first_scanned_* attribution and is safe
  // under concurrent cache-miss writes from different orgs.
  const { error } = await supabase
    .from('container_image_scan_cache')
    .upsert(row, {
      onConflict: 'image_digest,scanner,scanner_version,trivy_db_version_day',
      ignoreDuplicates: true,
    });
  if (error) {
    throw new Error(`upsertContainerScanCache: ${error.message}`);
  }
}
